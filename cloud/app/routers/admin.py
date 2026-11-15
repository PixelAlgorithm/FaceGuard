"""Admin endpoints (kiosk HMAC auth + X-Admin-Token): schedule edits, revocations (demo step "revoke Priya
during the outage"), control-panel access administration (users list, PUT access, staff code rotation, audit),
alerts / decision ledger for the dashboard, fake outbox for local OTP tests.

Errors: BundleRejected -> its API code, ScheduleConflict -> 409 INVALID_STATE, UnknownUser -> 404 (main.py)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Body, Path, Query
from fastapi.responses import JSONResponse

from ..clock import iso_z, parse_ts
from ..errors import ApiError
from ..schemas import (
    ADMIN_USER_ID,
    AccessUpdateRequest,
    AdminContactRequest,
    AdminRevokeRequest,
    CodesRotateRequest,
)
from ..services.enroll_service import PURPOSE, USER_ID_RE, mask_email
from .deps import AdminDep, KioskDep, SvcDep

router = APIRouter(prefix="/v1/admin", tags=["admin"])
# v1.4 (R-H): the access-administration routes take ^u_[0-9a-z]{4}$ only (422 VALIDATION_ERROR otherwise)
AdminUserId = Annotated[str, Path(pattern=ADMIN_USER_ID)]


@router.get("/schedule")
async def get_schedule(svc: SvcDep, _k: KioskDep, _a: AdminDep) -> dict:
    rec = svc.schedule.current()
    return {"version": rec["version"], "published_at": rec["published_at"], "doc": rec["doc"]}


@router.put("/schedule")
async def put_schedule(svc: SvcDep, kiosk_id: KioskDep, _a: AdminDep, doc: dict = Body(...)) -> dict:  # noqa: B008
    """Replace the master document. Validated (non-empty kiosks / zones / roles, the caller kiosk present, kiosk
    zones and user roles known) and never un-revokes (current revocations are carried over)."""
    version = await asyncio.to_thread(svc.schedule.replace, doc, caller_kiosk=kiosk_id)
    return {"bundle_version": version}


@router.put("/schedule/{kiosk_id}")
async def put_kiosk_bundle(kiosk_id: str, svc: SvcDep, _k: KioskDep, _a: AdminDep,
                           bundle: dict = Body(...)) -> dict:  # noqa: B008
    """Upload an operator-signed bundle (scripts/sign_bundle.py output, as-is). Verified: HMAC-SHA256 with the
    schedule bundle key (403), kiosk in kiosks{} and scope.kiosk_ids (403), bundle_version strictly greater than
    the stored one (409; identical re-upload -> 200 unchanged), not expired and no publicly documented override
    codes (422). Then served verbatim by GET /v1/schedule/{kiosk_id} with ETag "<bundle_version>"."""
    return await asyncio.to_thread(svc.schedule.accept_kiosk_bundle, kiosk_id, bundle)


@router.post("/revocations", status_code=201)
async def revoke(req: AdminRevokeRequest, svc: SvcDep, kiosk_id: KioskDep, _a: AdminDep) -> dict:
    """201 {seq, type, target_id, revoked_at, reason, bundle_version}. USER revocation of a user_id unknown to the
    schedule and the enrolment store -> 404 UNKNOWN_USER unless force=true; a user that already holds a
    non-ERASED USER revocation -> 409 ALREADY_REVOKED (no new seq); reason ERASED -> 422 (DELETE /v1/enroll)."""
    try:
        when = parse_ts(req.revoked_at) if req.revoked_at else None
    except ValueError as exc:
        raise ApiError("VALIDATION_ERROR", "revoked_at must be ISO-8601 with timezone") from exc
    ev = await asyncio.to_thread(svc.schedule.revoke, rtype=req.type, target_id=req.target_id,
                                 reason=req.reason, revoked_at=when, force=req.force, kiosk_id=kiosk_id,
                                 actor=req.actor)
    return {k: ev[k] for k in ("seq", "type", "target_id", "revoked_at", "reason", "bundle_version")}


# ---------------------------------------------------------------- control panel: users & access, staff codes
@router.get("/users")
async def list_users(svc: SvcDep, _k: KioskDep, _a: AdminDep) -> dict:
    """Schedule users (role, zones_add, extra_windows, validity, status ACTIVE / REVOKED / ERASED /
    NOT_IN_SCHEDULE) merged with cloud enrolment status (faces count), plus the master's roles / zones / kiosks /
    staff_ids so the panel can offer them (docs/API.md §4.9a)."""
    out = await asyncio.to_thread(svc.schedule.list_users)
    return {"as_of": iso_z(svc.clock.now()), **out}


@router.put("/users/{user_id}/access")
async def put_access(user_id: AdminUserId, req: AccessUpdateRequest, svc: SvcDep, kiosk_id: KioskDep,
                     _a: AdminDep) -> dict:
    """Create / edit / re-admit (R-B) / restore (R-C) a user's schedule entry (docs/API.md §3.18.2 state rules,
    §4.9a). Every change bumps bundle_version (re-signed on the next GET /v1/schedule, issued_at = now) and
    writes an audit entry (USER_CREATE / ACCESS_UPDATE / READMIT / RESTORE); an identical request changes
    nothing (unchanged=true, same version)."""
    sent = req.model_fields_set | {"role"}
    change = req.model_dump(include=sent - {"extra_windows"}, exclude={"actor"})
    if "extra_windows" in sent:
        change["extra_windows"] = (None if req.extra_windows is None else
                                   {z: [w.model_dump() for w in ws] for z, ws in req.extra_windows.items()})
    return await asyncio.to_thread(svc.schedule.update_access, user_id, change, kiosk_id=kiosk_id, actor=req.actor)


@router.post("/codes/rotate", status_code=201)
async def rotate_codes(req: CodesRotateRequest, svc: SvcDep, kiosk_id: KioskDep, _a: AdminDep) -> JSONResponse:
    """Mint fresh one-time staff override codes for `staff_id` (plaintext returned ONCE, never stored or
    logged; only PBKDF2 hashes enter the schedule). Drops documented fixture codes and, by default, the staff
    member's previous codes. Bumps bundle_version."""
    out = await asyncio.to_thread(svc.schedule.rotate_codes, req.staff_id, req.count,
                                  replace_existing=req.replace_existing, kiosk_id=kiosk_id, actor=req.actor)
    return JSONResponse(out, status_code=201, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@router.get("/audit")
async def audit(svc: SvcDep, _k: KioskDep, _a: AdminDep, limit: int = Query(100, ge=1, le=500),
                user_id: str | None = Query(None, pattern=ADMIN_USER_ID)) -> dict:
    """Access-administration ledger: who (kiosk_id + actor) changed what and when (no code values)."""
    items = await asyncio.to_thread(svc.schedule.audit_entries, limit, user_id)
    return {"as_of": iso_z(svc.clock.now()), "count": len(items), "items": items}


@router.get("/alerts")
async def alerts(svc: SvcDep, _k: KioskDep, _a: AdminDep, since: str | None = None,
                 limit: int = Query(100, ge=1, le=500), include_synthetic: bool = False) -> dict:
    items = [it for k, it in await asyncio.to_thread(svc.kv.list, "alerts")
             if (not since or k >= since) and (include_synthetic or not it.get("synthetic"))]
    for it in items:
        it.pop("_rev", None)
    return {"as_of": iso_z(datetime.now(UTC)), "items": items[-limit:]}


@router.get("/decisions")
async def decisions(svc: SvcDep, _k: KioskDep, _a: AdminDep, kiosk_id: str | None = None,
                    limit: int = Query(100, ge=1, le=500), include_synthetic: bool = False) -> dict:
    rows = [it for _, it in await asyncio.to_thread(svc.kv.list, "decisions")
            if (kiosk_id is None or it.get("kiosk_id") == kiosk_id)
            and (include_synthetic or not it.get("synthetic"))]
    rows.sort(key=lambda r: str(r.get("ts_utc") or r.get("decided_at") or ""))
    for r in rows:
        r.pop("_rev", None)
    return {"count": len(rows), "items": rows[-limit:]}


@router.get("/stats")
async def stats(svc: SvcDep, _k: KioskDep, _a: AdminDep, kiosk_id: str | None = None,
                include_synthetic: bool = False) -> dict:
    """Ledger aggregates for dashboards (synthetic test traffic excluded unless asked for)."""
    from collections import Counter

    rows = [it for _, it in await asyncio.to_thread(svc.kv.list, "decisions")
            if (kiosk_id is None or it.get("kiosk_id") == kiosk_id) and "#conflict#" not in str(it.get("sk", ""))]
    real = [r for r in rows if include_synthetic or not r.get("synthetic")]
    return {"as_of": iso_z(datetime.now(UTC)), "count": len(real), "synthetic_excluded": len(rows) - len(real),
            "by_decision": dict(Counter(r.get("decision") for r in real)),
            "by_mode": dict(Counter(r.get("mode") for r in real)),
            "by_verdict": dict(Counter(r.get("verdict") for r in real))}


@router.get("/fake/outbox")
async def fake_outbox(svc: SvcDep, _k: KioskDep, _a: AdminDep) -> dict:
    if svc.mailer.name != "fake":
        raise ApiError("NOT_FOUND", "only available with EMAIL_BACKEND=fake")
    return {"messages": [{"to": m.to, "subject": m.subject, "body": m.body} for m in svc.mailer.outbox[-20:]]}


@router.get("/metrics")
async def metrics(svc: SvcDep, _k: KioskDep, _a: AdminDep) -> dict:
    return {"sink": svc.metrics.sink, "records": svc.metrics.records[-500:] if svc.metrics.sink == "memory" else []}


@router.put("/users/{user_id}/contact")
async def put_contact(user_id: str, req: AdminContactRequest, svc: SvcDep, _k: KioskDep, _a: AdminDep) -> dict:
    """Upsert a consenting user's contact e-mail without any biometric data (OTP smoke before enrolment)."""
    if not USER_ID_RE.match(user_id):
        raise ApiError("VALIDATION_ERROR", "invalid user_id")
    now = iso_z(svc.clock.now())

    def _upsert() -> dict:
        row = svc.kv.get("users", user_id) or {"user_id": user_id, "groups": [], "status": "ACTIVE", "face_ids": [],
                                                 "rekognition_user_id": None, "template_version": 0,
                                                 "created_at": now}
        row = {k: v for k, v in row.items() if k != "_rev"}
        row.update({"display_name": req.display_name, "email": req.email, "updated_at": now,
                    "consent": {"given": True, "version": req.consent_version, "given_at": now, "purpose": PURPOSE}})
        svc.kv.put("users", user_id, row)
        return row

    row = await asyncio.to_thread(_upsert)
    return {"user_id": user_id, "destination_masked": mask_email(row["email"]), "faces_enrolled": len(row["face_ids"])}
