"""Admin endpoints (kiosk HMAC auth + an RBAC admin principal, cloud/app/rbac.py): schedule edits, revocations
(demo step "revoke Priya during the outage"), control-panel access administration (users list, PUT access, staff code
rotation, audit), alerts / decision ledger for the dashboard, fake outbox for local OTP tests.

Every route requires one permission (rbac.ROUTE_PERMISSIONS); credential failures are 403 FORBIDDEN with a reason.
The audited actor comes from the principal (edge_proxy keys may assert the human, recorded as edge_asserted).

Errors: BundleRejected -> its API code, ScheduleConflict -> 409 INVALID_STATE, UnknownUser -> 404 (main.py)."""

from __future__ import annotations

import asyncio
import copy
import re
from collections import Counter
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Body, Path, Query
from fastapi.responses import JSONResponse

from .. import rbac
from ..clock import iso_z, parse_ts
from ..errors import ApiError
from ..schemas import (
    ADMIN_USER_ID,
    REQUEST_ID,
    AccessUpdateRequest,
    AdminContactRequest,
    AdminRevokeRequest,
    CodesRotateRequest,
)
from ..services.enroll_service import USER_ID_RE, mask_email
from .deps import (
    AccessEdit,
    AccessRead,
    AlertsRead,
    AuditRead,
    CodesRotate,
    ContactEdit,
    DecisionsRead,
    KioskDep,
    MetricsRead,
    OutboxRead,
    RevocationsWrite,
    ScheduleRead,
    ScheduleWrite,
    StatsRead,
    SvcDep,
    actor_for,
    audit_meta,
)

router = APIRouter(prefix="/v1/admin", tags=["admin"])
# v1.4 (R-H): the access-administration routes take ^u_[0-9a-z]{4}$ only (422 VALIDATION_ERROR otherwise)
AdminUserId = Annotated[str, Path(pattern=ADMIN_USER_ID)]
_CODE_SECRETS = ("hash", "salt")


def _redact_codes(doc: dict) -> dict:
    """GET /v1/admin/schedule for a caller without schedule:write: override code hashes / salts are not needed to
    read the schedule and would allow an offline brute force of the 10-digit codes."""
    out = copy.deepcopy(doc)
    oc = out.get("override_codes")
    if isinstance(oc, dict) and isinstance(oc.get("codes"), list):
        oc["codes"] = [{k: v for k, v in c.items() if k not in _CODE_SECRETS} if isinstance(c, dict) else c
                       for c in oc["codes"]]
    return out


@router.get("/schedule")
async def get_schedule(svc: SvcDep, _k: KioskDep, p: ScheduleRead) -> dict:
    rec = await asyncio.to_thread(svc.schedule.current)
    doc = rec["doc"] if p.can(rbac.P.SCHEDULE_WRITE) else _redact_codes(rec["doc"])
    return {"version": rec["version"], "published_at": rec["published_at"], "doc": doc,
            "codes_redacted": not p.can(rbac.P.SCHEDULE_WRITE)}


@router.put("/schedule")
async def put_schedule(svc: SvcDep, kiosk_id: KioskDep, p: ScheduleWrite,
                       doc: dict = Body(...)) -> dict:  # noqa: B008
    """Replace the master document. Validated (non-empty kiosks / zones / roles, the caller kiosk present, kiosk
    zones and user roles known, element types, a dry-run bundle per kiosk) and never un-revokes."""
    ref = actor_for(p, doc.get("actor") if isinstance(doc, dict) else None, kiosk_id)
    request_id = doc.get("request_id") if isinstance(doc, dict) else None
    if request_id is not None and (not isinstance(request_id, str) or not re.fullmatch(REQUEST_ID, request_id)):
        raise ApiError("VALIDATION_ERROR", "request_id must match " + REQUEST_ID)
    body = {k: v for k, v in doc.items() if k not in ("actor", "request_id")} if isinstance(doc, dict) else doc
    version = await asyncio.to_thread(svc.schedule.replace, body, caller_kiosk=kiosk_id, actor=ref.actor,
                                      audit_meta=audit_meta(ref, request_id))
    return {"bundle_version": version}


@router.put("/schedule/{kiosk_id}")
async def put_kiosk_bundle(kiosk_id: str, svc: SvcDep, auth_kiosk: KioskDep, p: ScheduleWrite,
                           bundle: dict = Body(...)) -> dict:  # noqa: B008
    """Upload an operator-signed bundle (scripts/sign_bundle.py output, as-is). Verified: HMAC-SHA256 with the
    schedule bundle key (403), kiosk in kiosks{} and scope.kiosk_ids (403), bundle_version strictly greater than
    the stored one (409; identical re-upload -> 200 unchanged), not expired and no publicly documented override
    codes (422). Then served verbatim by GET /v1/schedule/{kiosk_id} with ETag "v<bundle_version>-<issued_at>".
    Audited (SCHEDULE_UPLOAD)."""
    ref = actor_for(p, None, auth_kiosk)
    return await asyncio.to_thread(svc.schedule.accept_kiosk_bundle, kiosk_id, bundle, actor=ref.actor,
                                   audit_meta={**audit_meta(ref), "uploaded_from": auth_kiosk})


@router.post("/revocations", status_code=201)
async def revoke(req: AdminRevokeRequest, svc: SvcDep, kiosk_id: KioskDep, p: RevocationsWrite) -> dict:
    """201 {seq, type, target_id, revoked_at, reason, bundle_version}. USER revocation of a user_id unknown to the
    schedule and the enrolment store -> 404 UNKNOWN_USER unless force=true; a user that already holds a
    non-ERASED USER revocation -> 409 ALREADY_REVOKED (no new seq); reason ERASED -> 422 (DELETE /v1/enroll)."""
    ref = actor_for(p, req.actor, kiosk_id)
    try:
        when = parse_ts(req.revoked_at) if req.revoked_at else None
    except ValueError as exc:
        raise ApiError("VALIDATION_ERROR", "revoked_at must be ISO-8601 with timezone") from exc
    ev = await asyncio.to_thread(svc.schedule.revoke, rtype=req.type, target_id=req.target_id,
                                 reason=req.reason, revoked_at=when, force=req.force, kiosk_id=kiosk_id,
                                 actor=ref.actor, audit_meta=audit_meta(ref, req.request_id))
    return {k: ev[k] for k in ("seq", "type", "target_id", "revoked_at", "reason", "bundle_version")}


# ---------------------------------------------------------------- control panel: users & access, staff codes
@router.get("/users")
async def list_users(svc: SvcDep, _k: KioskDep, _p: AccessRead) -> dict:
    """Schedule users (role, zones_add, extra_windows, validity, status ACTIVE / REVOKED / ERASED /
    NOT_IN_SCHEDULE) merged with cloud enrolment status (faces count), plus the master's roles / zones / kiosks /
    staff_ids so the panel can offer them (docs/API.md §4.9a)."""
    out = await asyncio.to_thread(svc.schedule.list_users)
    return {"as_of": iso_z(svc.clock.now()), **out}


@router.put("/users/{user_id}/access")
async def put_access(user_id: AdminUserId, req: AccessUpdateRequest, svc: SvcDep, kiosk_id: KioskDep,
                     p: AccessEdit) -> dict:
    """Create / edit / re-admit (R-B) / restore (R-C) a user's schedule entry (docs/API.md §3.18.2 state rules,
    §4.9a). Every change bumps bundle_version (re-signed on the next GET /v1/schedule, issued_at = now) and
    writes an audit entry (USER_CREATE / ACCESS_UPDATE / READMIT / RESTORE); an identical request changes
    nothing (unchanged=true, same version)."""
    ref = actor_for(p, req.actor, kiosk_id)
    sent = req.model_fields_set | {"role"}
    change = req.model_dump(include=sent - {"extra_windows"}, exclude={"actor", "request_id"})
    if "extra_windows" in sent:
        change["extra_windows"] = (None if req.extra_windows is None else
                                   {z: [w.model_dump() for w in ws] for z, ws in req.extra_windows.items()})
    return await asyncio.to_thread(svc.schedule.update_access, user_id, change, kiosk_id=kiosk_id, actor=ref.actor,
                                   audit_meta=audit_meta(ref, req.request_id))


@router.post("/codes/rotate", status_code=201)
async def rotate_codes(req: CodesRotateRequest, svc: SvcDep, kiosk_id: KioskDep, p: CodesRotate) -> JSONResponse:
    """Mint fresh one-time staff override codes for `staff_id` (plaintext returned ONCE, never stored or
    logged; only PBKDF2 hashes enter the schedule). Drops documented fixture codes and, by default, the staff
    member's previous codes. The staff_id is bound to the first kiosk that rotates it (409 STAFF_ID_TAKEN from
    another kiosk); at most 10 active codes per staff_id (422 TOO_MANY_ACTIVE_CODES). Bumps bundle_version."""
    ref = actor_for(p, req.actor, kiosk_id)
    out = await asyncio.to_thread(svc.schedule.rotate_codes, req.staff_id, req.count,
                                  replace_existing=req.replace_existing, kiosk_id=kiosk_id, actor=ref.actor,
                                  audit_meta=audit_meta(ref, req.request_id))
    return JSONResponse(out, status_code=201, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@router.get("/audit")
async def audit(svc: SvcDep, _k: KioskDep, _p: AuditRead, limit: int = Query(100, ge=1, le=500),
                user_id: str | None = Query(None, pattern=ADMIN_USER_ID)) -> dict:
    """Access-administration ledger: who (kiosk_id + actor + assurance) changed what and when (no code values)."""
    items = await asyncio.to_thread(svc.schedule.audit_entries, limit, user_id)
    return {"as_of": iso_z(svc.clock.now()), "count": len(items), "items": items}


@router.get("/alerts")
async def alerts(svc: SvcDep, _k: KioskDep, _p: AlertsRead, since: str | None = None,
                 limit: int = Query(100, ge=1, le=500), include_synthetic: bool = False) -> dict:
    rows = await asyncio.to_thread(svc.kv.list, "alerts", "", since or "")  # key-range read (keys start with ts)
    items = [it for _, it in rows if include_synthetic or not it.get("synthetic")]
    for it in items:
        it.pop("_rev", None)
    return {"as_of": iso_z(datetime.now(UTC)), "items": items[-limit:]}


def _decision_rows(rows: list[tuple[str, dict]], kiosk_id: str | None) -> list[dict]:
    prefix = f"{kiosk_id}|" if kiosk_id else ""
    return [it for k, it in rows if "#conflict#" not in k and k.startswith(prefix)
            and (kiosk_id is None or it.get("kiosk_id") == kiosk_id)]


@router.get("/decisions")
async def decisions(svc: SvcDep, _k: KioskDep, _p: DecisionsRead, kiosk_id: str | None = None,
                    limit: int = Query(100, ge=1, le=500), include_synthetic: bool = False) -> dict:
    raw = await asyncio.to_thread(svc.kv.list, "decisions", f"{kiosk_id}|" if kiosk_id else "")
    rows = [it for it in _decision_rows(raw, kiosk_id) if include_synthetic or not it.get("synthetic")]
    rows.sort(key=lambda r: str(r.get("ts_utc") or r.get("decided_at") or ""))
    for r in rows:
        r.pop("_rev", None)
    return {"count": len(rows), "items": rows[-limit:]}


@router.get("/stats")
async def stats(svc: SvcDep, _k: KioskDep, _p: StatsRead, kiosk_id: str | None = None,
                include_synthetic: bool = False) -> dict:
    """Ledger aggregates for dashboards (synthetic test traffic and conflict variants excluded)."""
    raw = await asyncio.to_thread(svc.kv.list, "decisions", f"{kiosk_id}|" if kiosk_id else "")
    rows = _decision_rows(raw, kiosk_id)
    real = [r for r in rows if include_synthetic or not r.get("synthetic")]
    return {"as_of": iso_z(datetime.now(UTC)), "count": len(real), "synthetic_excluded": len(rows) - len(real),
            "by_decision": dict(Counter(r.get("decision") for r in real)),
            "by_mode": dict(Counter(r.get("mode") for r in real)),
            "by_verdict": dict(Counter(r.get("verdict") for r in real))}


@router.get("/fake/outbox")
async def fake_outbox(svc: SvcDep, _k: KioskDep, _p: OutboxRead) -> dict:
    if svc.mailer.name != "fake":
        raise ApiError("NOT_FOUND", "only available with EMAIL_BACKEND=fake")
    return {"messages": [{"to": m.to, "subject": m.subject, "body": m.body} for m in svc.mailer.outbox[-20:]]}


@router.get("/metrics")
async def metrics(svc: SvcDep, _k: KioskDep, _p: MetricsRead) -> dict:
    return {"sink": svc.metrics.sink, "records": svc.metrics.records[-500:] if svc.metrics.sink == "memory" else []}


@router.put("/users/{user_id}/contact")
async def put_contact(user_id: str, req: AdminContactRequest, svc: SvcDep, kiosk_id: KioskDep,
                      p: ContactEdit) -> dict:
    """Upsert a consenting user's contact e-mail without any biometric data (OTP smoke before enrolment). CAS on the
    user row (a concurrent enrolment is never overwritten), audited as CONTACT_UPDATE with the actor."""
    if not USER_ID_RE.match(user_id):
        raise ApiError("VALIDATION_ERROR", "invalid user_id")
    ref = actor_for(p, req.actor, kiosk_id)
    row: dict[str, Any] = await asyncio.to_thread(
        svc.enroll.upsert_contact, user_id, display_name=req.display_name, email=req.email,
        consent_version=req.consent_version, kiosk_id=kiosk_id, actor=ref.actor,
        audit_meta=audit_meta(ref, req.request_id))
    return {"user_id": user_id, "destination_masked": mask_email(row["email"]),
            "faces_enrolled": len(row.get("face_ids") or [])}
