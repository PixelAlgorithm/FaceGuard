"""Users & Access admin proxies (operator Control Panel): docs/API.md v1.4 §3.18.

The SIGNED SCHEDULE is the single source of truth for a user's role, zones, hours, validity and revocation
(cloud master -> signed per-kiosk bundle -> edge). The edge never assigns a role itself. These helpers
  * read: merge the cloud master's users (GET /v1/admin/users), the verified installed bundle (what the policy
    enforces right now, plus the revocation-feed overlay) and the local enrolment state into AccessUser rows;
    offline the bundle alone is served, read-only,
  * write: forward an access change / revocation / staff-code rotation to the cloud (kiosk HMAC + admin token),
    then pull + verify + install the re-signed bundle (refresh_bundle_now(expect_version)) and the revocation
    feed, so the change applies to the very next attempt. A failed pull never turns a successful cloud write
    into an error (2xx, bundle.applied false + warning).
Models and field limits (R-H): edge/access_models.py. Error mapping of cloud calls: §3.18.6 (`cloud_admin`).
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from zoneinfo import ZoneInfo

from edge.access_models import (
    DAYS,
    USER_ID,
    AccessUpdate,
    CodesRotateRequest,
    RevokeRequest,
    Window,
    utc_z,
)
from edge.attempts import EdgeContext, _run, _safe_call
from edge.cloud_client import CloudRejected, CloudUnavailable
from edge.errors import STATUS, ApiError

__all__ = ["USER_ID", "AccessUpdate", "CodesRotateRequest", "RevokeRequest", "Window"]

log = logging.getLogger("edge.access")
IST = ZoneInfo("Asia/Kolkata")
ERASED = "ERASED"
STATUSES = ("ACTIVE", "REVOKED", "ERASED", "NOT_IN_SCHEDULE")
RISKS = ("low", "medium", "high")
_SCHEDULE_RESULTS = ("IN_WINDOW", "GRACE_WINDOW", "OUTSIDE_WINDOW", "NO_ENTITLEMENT", "ZONE_NOT_PERMITTED",
                     "HOLIDAY", "REVOKED")


# ---------------------------------------------------------------------------------- runtime / bundle helpers
def _lvb(ctx: EdgeContext) -> Mapping[str, Any] | None:
    lvb = getattr(getattr(ctx.runtime, "bundles", None), "lvb", None)
    return lvb if isinstance(lvb, Mapping) else None


def bundle_version(ctx: EdgeContext) -> int | None:
    v = getattr(getattr(ctx.runtime, "bundles", None), "version", None)
    return v if isinstance(v, int) else None


def _overlay_entries(ctx: EdgeContext) -> list[Mapping[str, Any]]:
    fn = getattr(getattr(ctx.runtime, "overlay", None), "entries", None)
    try:
        return [e for e in (fn() if callable(fn) else ()) if isinstance(e, Mapping)]
    except Exception:  # noqa: BLE001 - display data; decisions read the overlay themselves
        return []


def _overlay_reason(ctx: EdgeContext, user_id: str) -> str | None:
    fn = getattr(getattr(ctx.runtime, "overlay", None), "reason", None)
    try:
        r = fn(user_id) if callable(fn) else None
    except Exception:  # noqa: BLE001 - display data
        return None
    return r if isinstance(r, str) else None


def _merged_lvb(ctx: EdgeContext) -> Mapping[str, Any] | None:
    """The installed bundle with the revocation-feed overlay appended (what the policy enforces)."""
    lvb = _lvb(ctx)
    if lvb is None:
        return None
    return {**lvb, "revocations": [*(lvb.get("revocations") or []), *_overlay_entries(ctx)]}


def edge_now(ctx: EdgeContext) -> datetime:
    now = _safe_call(ctx.runtime, "now")
    return now if isinstance(now, datetime) and now.tzinfo else datetime.now(UTC)


def edge_mode(ctx: EdgeContext) -> str:
    return "ONLINE" if str(_safe_call(ctx.runtime, "mode") or "OFFLINE") == "ONLINE" else "OFFLINE"


def pending_cloud_erasures(ctx: EdgeContext) -> list[str]:
    """User ids whose cloud erasure is queued in edge/offline (R-J, PolicyRuntime.pending_cloud_erasures)."""
    items = _safe_call(ctx.runtime, "pending_cloud_erasures")
    out = []
    for it in items or []:
        uid = it.get("user_id") if isinstance(it, Mapping) else it
        if isinstance(uid, str):
            out.append(uid)
    return sorted(set(out))


def _windows_read(v: Any) -> list[dict[str, Any]]:
    """Mirrors edge/policy/schedule.py _applies_on: missing / null days = EVERY day; an explicit [] = no day."""
    out = []
    for w in v or []:
        if isinstance(w, Mapping) and isinstance(w.get("start"), str) and isinstance(w.get("end"), str):
            days = w.get("days")
            out.append({"days": list(DAYS) if days is None else [d for d in days if d in DAYS],
                        "start": w["start"], "end": w["end"]})
    return out


def _extra_windows(v: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(v, Mapping):
        return {}
    return {str(z): _windows_read(ws) for z, ws in v.items()}


def role_defaults(roles: Any) -> dict[str, dict[str, Any]]:
    """role -> {zones, windows} (the hours editor's "role default"; R-I). Notes and other keys dropped."""
    if not isinstance(roles, Mapping):
        return {}
    return {str(r): {"zones": [str(z) for z in ((v or {}).get("zones") or [])],
                     "windows": _extra_windows((v or {}).get("windows"))}
            for r, v in sorted(roles.items()) if isinstance(v, Mapping)}


def zones_view(zones: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(zones, Mapping):
        return {}
    out = {}
    for z, v in zones.items():
        v = v if isinstance(v, Mapping) else {}
        risk = str(v.get("risk") or "high").lower()
        out[str(z)] = {"risk": risk if risk in RISKS else "high",
                       "requires_explicit_grant": bool(v.get("requires_explicit_grant"))}
    return out


def bundle_staff_ids(lvb: Mapping[str, Any] | None) -> list[str]:
    codes = ((lvb or {}).get("override_codes") or {}).get("codes") or []
    return sorted({str(c["staff_id"]) for c in codes if isinstance(c, Mapping) and c.get("staff_id")})


def bundle_roles(lvb: Mapping[str, Any] | None) -> list[str]:
    return sorted((lvb or {}).get("roles") or {})


def check_role(update: AccessUpdate, lvb: Mapping[str, Any] | None) -> None:
    """Edge pre-check (§3.18 validation order): the role must be one of the installed bundle's role names
    (skipped without a bundle; the cloud validates again, authoritatively). Zones are checked by the cloud
    only: the per-kiosk bundle is filtered to this kiosk's zone."""
    roles = bundle_roles(lvb)
    if roles and update.role not in roles:
        raise ApiError("VALIDATION_ERROR", f"unknown role {update.role!r} (bundle roles: {', '.join(roles)})",
                       extra={"reason": "UNKNOWN_ROLE"})


# ---------------------------------------------------------------------------------- per-user views
def _revocations_of(merged: Mapping[str, Any] | None, user_id: str, now: datetime) -> list[tuple[str | None, str]]:
    """(revoked_at, reason) of the user's revocations effective at `now` (bundle list, overlay, users[].revoked)."""
    from edge.policy.schedule import parse_ts

    out: list[tuple[str | None, str]] = []
    if not merged:
        return out
    for r in merged.get("revocations") or []:
        if not (isinstance(r, Mapping) and (r.get("user_id") or r.get("target_id")) == user_id):
            continue
        if r.get("type") not in (None, "USER", "ERASE"):
            continue
        at = r.get("revoked_at")
        try:
            ts = parse_ts(at) if at else None
        except (TypeError, ValueError):
            ts = None
        if ts is None or ts <= now:  # unparseable time: counts (fail secure)
            out.append((utc_z(at), str(r.get("reason") or "REVOKED")))
    u = (merged.get("users") or {}).get(user_id)
    if isinstance(u, Mapping) and u.get("revoked"):
        out.append((utc_z(u.get("revoked_at")), str(u.get("revoked_reason") or "REVOKED")))
    return out


def bundle_status(merged: Mapping[str, Any] | None, user_id: str, now: datetime) -> tuple[str, str | None, str | None]:
    """(status, revoked_at, revoked_reason) from the installed bundle + overlay. REVOKED wins over ERASED."""
    revs = _revocations_of(merged, user_id, now)
    hard = [r for r in revs if r[1] != ERASED]
    if hard:
        return "REVOKED", hard[0][0], hard[0][1]
    if revs:
        return "ERASED", revs[0][0], ERASED
    in_bundle = isinstance(((merged or {}).get("users") or {}).get(user_id), Mapping)
    return ("ACTIVE" if in_bundle else "NOT_IN_SCHEDULE"), None, None


def today_view(merged: Mapping[str, Any] | None, user_id: str, zone: str | None, now: datetime) -> dict[str, Any] | None:
    """What the edge enforces TODAY at this kiosk's zone (verified bundle + feed, edge clock incl. the demo
    clock): permitted?, holiday?, the day's windows (role / pass / exception = "role", the user's extra windows =
    "extra") and the schedule result now. None when the user is not in the bundle or there is no zone."""
    if not merged or not zone:
        return None
    user = (merged.get("users") or {}).get(user_id)
    if not isinstance(user, Mapping):
        return None
    try:
        from edge.policy import schedule as sched

        local = now.astimezone(sched._tz(merged))
        role_name = str(user.get("role"))
        role = (merged.get("roles") or {}).get(role_name) or {}
        vp = sched.active_visitor_pass(merged, user_id, now)
        permitted = zone in sched.permitted_zones(merged, user, role, vp)
        holiday = bool(sched._holiday_applies(merged, role_name, zone, local.date()))
        entries = sched._window_entries(merged, user, role_name, role, zone, local.date(), vp) if permitted else []
        extra = {(w.get("start"), w.get("end")) for w in ((user.get("extra_windows") or {}).get(zone) or [])
                 if isinstance(w, Mapping)}
        windows = [{"start": str(w.get("start")), "end": str(w.get("end")),
                    "source": "extra" if (w.get("start"), w.get("end")) in extra else "role"}
                   for w in entries if isinstance(w, Mapping)]
        status = str(sched.evaluate_schedule(user_id, zone, now, merged, _schedule_cfg()))
        if status not in _SCHEDULE_RESULTS:
            status = "NO_ENTITLEMENT"
        return {"zone": zone, "date": local.date().isoformat(), "day": DAYS[local.weekday()],
                "now_local": local.strftime("%H:%M"), "permitted": bool(permitted), "holiday": holiday,
                "windows": windows, "status_now": status}
    except Exception as exc:  # noqa: BLE001 - a display helper must never break the admin view
        log.warning("today_view failed for a user: %s", type(exc).__name__)
        return None


_SCHED_CFG: dict[str, Any] | None = None


def _schedule_cfg() -> dict[str, Any]:
    """Grace minutes for evaluate_schedule (display only): config/thresholds.yaml `schedule`."""
    global _SCHED_CFG
    if _SCHED_CFG is None:
        from edge.config import PROJECT_ROOT, Thresholds

        try:
            sch = Thresholds.load(PROJECT_ROOT / "config" / "thresholds.yaml").get("schedule")
        except Exception:  # noqa: BLE001
            sch = {}
        _SCHED_CFG = {"grace_minutes": int((sch or {}).get("grace_minutes", 0)),
                      "grace_minutes_high_risk": int((sch or {}).get("grace_minutes_high_risk", 0))}
    return _SCHED_CFG


def has_local_totp(ctx: EdgeContext, user_id: str, template: Any = None) -> bool:
    """TOTP secrets live in the policy runtime's encrypted CredentialStore (provision_totp); the template's own
    totp_secret is only the no-runtime fallback. Never returns or logs the secret."""
    creds = getattr(ctx.runtime, "credentials", None)
    fn = getattr(creds, "totp_secret", None)
    if callable(fn):
        try:
            if fn(user_id):
                return True
        except Exception:  # noqa: BLE001
            log.warning("credential store lookup failed")
    return bool(getattr(template, "totp_secret", None))


def local_enrolment(ctx: EdgeContext, user_id: str) -> tuple[dict[str, Any], str | None]:
    """This edge's template-cache state (LocalEnrolment) + the stored display name (for rows without one)."""
    t = ctx.templates.get(user_id) if ctx.templates is not None else None
    return {"enrolled": t is not None, "templates": len(t.templates_b64) if t else 0,
            "template_version": t.template_version if t else None, "template_role": t.role if t else None,
            "totp_local": has_local_totp(ctx, user_id, t), "updated_at": t.updated_at if t else None}, \
        (t.display_name if t else None)


def _faces(u: Mapping[str, Any]) -> int | None:
    for k in ("faces", "enrolled_faces", "face_count", "faces_indexed"):
        v = u.get(k)
        if isinstance(v, bool):
            continue
        if isinstance(v, int):
            return v
        if isinstance(v, list):
            return len(v)
    return None


def _fallback(src: Mapping[str, Any] | None) -> dict[str, bool]:
    fb = (src or {}).get("fallback")
    fb = fb if isinstance(fb, Mapping) else {}
    return {"totp_enrolled": bool(fb.get("totp_enrolled")),
            "card": bool(fb.get("card")) or (isinstance(fb.get("card_id_hash"), str) and bool(fb.get("card_id_hash")))}


def _cloud_status(c: Mapping[str, Any]) -> str:
    s = str(c.get("status") or "").upper()
    if s in STATUSES:
        return s
    if c.get("erased"):
        return "ERASED"
    if c.get("revoked"):
        return "REVOKED"
    return "ACTIVE" if c.get("in_schedule", True) else "NOT_IN_SCHEDULE"


def access_row(ctx: EdgeContext, user_id: str, *, cloud: Mapping[str, Any] | None, cloud_listed: bool,
               merged: Mapping[str, Any] | None, zone: str | None, now: datetime) -> dict[str, Any]:
    """One AccessUser row. `cloud` = the master's record (list item or a write's `user`); `cloud_listed` = the
    master's full list was loaded (a user missing from it is NOT_IN_SCHEDULE)."""
    b = ((merged or {}).get("users") or {}).get(user_id)
    b = b if isinstance(b, Mapping) else None
    local, template_display = local_enrolment(ctx, user_id)
    bstat, bat, breason = bundle_status(merged, user_id, now)
    if bstat in ("ACTIVE", "NOT_IN_SCHEDULE") and _overlay_reason(ctx, user_id) == ERASED:
        bstat, bat, breason = "ERASED", None, ERASED  # feed erasure not lifted yet (no READMIT seen)
    if cloud is not None:
        src: Mapping[str, Any] = cloud
        status = _cloud_status(cloud)
        in_schedule = bool(cloud.get("in_schedule", status != "NOT_IN_SCHEDULE"))
        revoked_at, revoked_reason = utc_z(cloud.get("revoked_at")), cloud.get("revoked_reason")
    elif cloud_listed:
        src, status, in_schedule, revoked_at, revoked_reason = b or {}, "NOT_IN_SCHEDULE", False, None, None
    else:
        src, status, in_schedule, revoked_at, revoked_reason = b or {}, bstat, b is not None, bat, breason
    if status not in ("REVOKED", "ERASED"):
        revoked_at = revoked_reason = None
    stale = False
    if cloud is not None and b is not None:
        def zset(u: Mapping[str, Any], k: str) -> bool:
            return zone in (u.get(k) or [])

        stale = (cloud.get("role") != b.get("role") or status != bstat
                 or zset(cloud, "zones_add") != zset(b, "zones_add")
                 or zset(cloud, "zones_remove") != zset(b, "zones_remove")
                 or _windows_read((cloud.get("extra_windows") or {}).get(zone))
                 != _windows_read((b.get("extra_windows") or {}).get(zone)))
    return {
        "user_id": user_id,
        "display": str(src.get("display") or (b or {}).get("display") or template_display or user_id),
        "role": src.get("role"),
        "bundle_role": b.get("role") if b else None,
        "in_schedule": in_schedule,
        "in_bundle": b is not None,
        "status": status,
        "revoked_at": revoked_at,
        "revoked_reason": None if revoked_reason is None else str(revoked_reason),
        "bundle_stale": bool(stale),
        "zones_add": [str(z) for z in (src.get("zones_add") or [])],
        "zones_remove": [str(z) for z in (src.get("zones_remove") or [])],
        "extra_windows": _extra_windows(src.get("extra_windows")),
        "valid_from": utc_z(src.get("valid_from")),
        "valid_until": utc_z(src.get("valid_until")),
        "fallback": _fallback(src if src.get("fallback") is not None else b),
        "cloud_faces": _faces(cloud) if cloud is not None else None,
        "local": local,
        "today": today_view(merged, user_id, zone, now) if b is not None else None,
    }


def _cloud_users(payload: Any) -> dict[str, Mapping[str, Any]]:
    items = payload.get("users") if isinstance(payload, Mapping) else payload
    if isinstance(items, Mapping):  # {user_id: {...}}
        items = [{"user_id": k, **v} for k, v in items.items() if isinstance(v, Mapping)]
    return {str(u["user_id"]): u for u in items or [] if isinstance(u, Mapping) and u.get("user_id")}


def user_row(ctx: EdgeContext, user_id: str, cloud_user: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
    """The row after a write (cloud_faces null). Never raises: a display failure is a null row."""
    try:
        return access_row(ctx, user_id, cloud=cloud_user, cloud_listed=False, merged=_merged_lvb(ctx),
                          zone=_safe_call(ctx.runtime, "kiosk_zone"), now=edge_now(ctx))
    except Exception as exc:  # noqa: BLE001
        log.warning("access row failed for a user: %s", type(exc).__name__)
        return None


READ_ONLY_CODES = ("OFFLINE", "NOT_CONFIGURED", "CLOUD_ERROR", "ENDPOINT_NOT_DEPLOYED", "CLOUD_ADMIN_TOKEN")


def read_only_code(exc: ApiError) -> tuple[str, str | None]:
    """(read_only_code, read_only_cloud_reason). A cloud 403 is the CLOUD_ADMIN_TOKEN class (the edge's outbound
    credential was refused) and keeps the cloud's own reason unchanged (RBAC v2 D: ADMIN_KEY_INVALID,
    MISSING_PERMISSION, KIOSK_NOT_BOUND, LEGACY_DISABLED ...)."""
    reason = str(exc.extra.get("reason") or "")
    if exc.code == "FORBIDDEN":
        return "CLOUD_ADMIN_TOKEN", reason or None
    return (reason if reason in READ_ONLY_CODES else "CLOUD_ERROR"), None


async def list_view(ctx: EdgeContext) -> dict[str, Any]:
    """GET /v1/admin/access/users (§3.18.1). Only the edge's own auth errors (401 / 403 / 503 AUTH_*, raised by
    the route dependency) are errors: a cloud failure degrades to read-only (read_only_code says why)."""
    now = edge_now(ctx)
    cloud_payload: Mapping[str, Any] | None = None
    ro_code: str | None = None
    ro_reason: str | None = None
    ro_cloud_reason: str | None = None
    try:
        require_online(ctx)
        got = await cloud_admin(ctx, "GET", "/v1/admin/users", label="GET /v1/admin/users")
        if not isinstance(got, Mapping):
            raise ApiError("CLOUD_UNAVAILABLE", "cloud admin call failed: GET /v1/admin/users: unexpected body",
                           extra={"reason": "CLOUD_ERROR"})
        cloud_payload = got
    except ApiError as exc:
        ro_code, ro_cloud_reason = read_only_code(exc)
        ro_reason = exc.message
    lvb = _lvb(ctx)
    merged = _merged_lvb(ctx)
    zone = _safe_call(ctx.runtime, "kiosk_zone")
    cloud = _cloud_users(cloud_payload) if cloud_payload is not None else {}
    ids = set(cloud) | set((lvb or {}).get("users") or {})
    if ctx.templates is not None:
        ids |= set(ctx.templates.gallery.user_ids)
    users = [access_row(ctx, uid, cloud=cloud.get(uid), cloud_listed=cloud_payload is not None, merged=merged,
                        zone=zone, now=now) for uid in sorted(ids)]
    local = now.astimezone(IST)
    # online = the master's roles / zones (all zones); a cloud body without them (older build) or offline = bundle
    src = cloud_payload if cloud_payload is not None and isinstance(cloud_payload.get("roles"), Mapping) \
        and cloud_payload.get("roles") else lvb or {}
    zsrc = cloud_payload if cloud_payload is not None and isinstance(cloud_payload.get("zones"), Mapping) \
        and cloud_payload.get("zones") else lvb or {}
    cbv = cloud_payload.get("bundle_version") if cloud_payload is not None else None
    staff = cloud_payload.get("staff_ids") if cloud_payload is not None else None
    return {
        "source": "cloud+bundle" if cloud_payload is not None else "bundle",
        "read_only": cloud_payload is None,
        "read_only_code": ro_code,
        "read_only_cloud_reason": ro_cloud_reason,
        "read_only_reason": ro_reason,
        "mode": edge_mode(ctx),
        "kiosk_id": ctx.settings.kiosk_id,
        "zone": zone,
        "now_local": local.strftime("%H:%M"),
        "date_local": local.date().isoformat(),
        "day": DAYS[local.weekday()],
        "bundle": {"version": bundle_version(ctx), "issued_at": (lvb or {}).get("issued_at"),
                   "expires_at": (lvb or {}).get("expires_at")},
        "cloud_bundle_version": cbv if isinstance(cbv, int) else None,
        "roles": sorted(src.get("roles") or {}),
        "role_defaults": role_defaults(src.get("roles")),
        "zones": zones_view(zsrc.get("zones")),
        "staff_ids": sorted({str(s) for s in staff}) if isinstance(staff, list) else bundle_staff_ids(lvb),
        "pending_cloud_erasures": pending_cloud_erasures(ctx),
        "users": users,
    }


# ---------------------------------------------------------------------------------- cloud calls
def connectivity_up(ctx: EdgeContext) -> bool:
    """The cloud is reachable now: mode ONLINE, reason bundle_stale (a write is what refreshes the bundle) or the
    monitor is SYNCING (EAE-10: connectivity is back while the offline queue drains; decisions still use the
    offline rules, but an urgent revoke must not wait for that)."""
    if edge_mode(ctx) == "ONLINE":
        return True
    status = _safe_call(ctx.runtime, "mode_status") or {}
    if isinstance(status, Mapping) and status.get("reason") == "bundle_stale":
        return True
    return str(getattr(getattr(ctx.runtime, "monitor", None), "state", "")) == "SYNCING"


def require_online(ctx: EdgeContext) -> None:
    """ONLINE requirement of every write (§3.18): cloud configured (URL + outbound admin credential), not forced
    OFFLINE, and the cloud reachable now (connectivity_up)."""
    if not ctx.cloud.enabled:
        raise ApiError("CLOUD_UNAVAILABLE", "cloud not configured (CLOUD_API_URL empty)",
                       extra={"reason": "NOT_CONFIGURED"})
    if not ctx.settings.cloud_admin_configured:
        raise ApiError("CLOUD_UNAVAILABLE", "cloud not configured (no CLOUD_EDGE_PROXY_KEY / CLOUD_ADMIN_TOKEN for "
                                            "the cloud)", extra={"reason": "NOT_CONFIGURED"})
    forced = bool(getattr(getattr(ctx.runtime, "monitor", None), "forced", False))
    if forced or not connectivity_up(ctx):
        raise ApiError("CLOUD_UNAVAILABLE", "kiosk is OFFLINE" + (" (forced)" if forced else "")
                       + ": access changes need the cloud (the signed schedule is the source of truth)",
                       extra={"reason": "OFFLINE"})


async def cloud_admin(ctx: EdgeContext, method: str, path: str, body: dict[str, Any] | None = None, *,
                      label: str | None = None) -> Any:
    """ctx.cloud.admin with the §3.18.6 mapping. `label` = the route template shown in messages."""
    label = label or f"{method} {path.split('?')[0]}"
    try:
        return await ctx.cloud.admin(method, path, body)
    except CloudUnavailable as exc:
        if exc.connectivity_miss:
            _safe_call(ctx.runtime, "record_cloud_result", False)
        extra: dict[str, Any] = {"reason": "CLOUD_ERROR"}
        if exc.status is not None:
            extra["cloud_status"] = exc.status
        raise ApiError("CLOUD_UNAVAILABLE", f"cloud admin call failed: {exc}", extra=extra) from exc
    except CloudRejected as exc:
        cloud_code = exc.code if not exc.code.startswith("HTTP_") else None
        base: dict[str, Any] = {"cloud_status": exc.status}
        if cloud_code:
            base["cloud_code"] = cloud_code
        if (exc.status == 404 and not exc.reason) or exc.status == 405:
            raise ApiError("CLOUD_UNAVAILABLE", f"cloud endpoint {label} is not deployed on this cloud build "
                                                "(redeploy needed)",
                           extra={"reason": "ENDPOINT_NOT_DEPLOYED", **base}) from exc
        if exc.status == 403:  # RBAC v2 D: the cloud's reason (ADMIN_KEY_INVALID, MISSING_PERMISSION...) unchanged
            raise ApiError("FORBIDDEN", f"cloud refused the edge's admin credential: {exc.message}",
                           extra={**base, "reason": exc.reason or "CLOUD_ADMIN_TOKEN"}) from exc
        code = exc.code if exc.code in STATUS and STATUS[exc.code] == exc.status else {
            404: "NOT_FOUND", 409: "INVALID_STATE", 413: "PAYLOAD_TOO_LARGE", 422: "VALIDATION_ERROR",
            429: "RATE_LIMITED"}.get(exc.status, "VALIDATION_ERROR")
        extra = dict(base)
        if exc.reason:
            extra["reason"] = exc.reason
        if exc.retry_after_s is not None:
            extra["retry_after_s"] = exc.retry_after_s
        raise ApiError(code, f"cloud: {exc.message}", status=exc.status, extra=extra) from exc


def _refresh_out(prev: int | None, installed: int | None, result: str, error: str | None) -> dict[str, Any]:
    return {"previous_version": prev, "installed_version": installed, "changed": installed != prev,
            "result": result, "error": error}


async def pull_feed(ctx: EdgeContext) -> None:
    """Revocation feed now (revoke / re-admit / restore / erase apply to the very next attempt). Never raises."""
    rt = ctx.runtime
    fn = getattr(rt, "pull_revocations_now", None) or getattr(getattr(rt, "sync", None), "pull_revocations", None)
    if not callable(fn):
        return
    try:
        await _run(ctx, fn)
        await _run(ctx, lambda: _safe_call(rt, "apply_erasures"))
    except Exception as exc:  # noqa: BLE001 - the heartbeat pulls it again within seconds
        log.warning("revocation feed pull failed: %s", type(exc).__name__)


async def refresh_bundle(ctx: EdgeContext, expect_version: int | None = None) -> dict[str, Any]:
    """Pull + verify + install the newest cloud bundle (PolicyRuntime.refresh_bundle_now) and the feed.
    Returns a BundleRefresh dict; never raises (result "failed" + error instead)."""
    prev = bundle_version(ctx)
    fn = getattr(ctx.runtime, "refresh_bundle_now", None)
    if not callable(fn) or not ctx.cloud.enabled:
        return _refresh_out(prev, prev, "failed", "cloud not configured" if not ctx.cloud.enabled
                            else "policy runtime cannot refresh the bundle")
    try:
        await _run(ctx, lambda: fn(expect_version=expect_version))
    except Exception as exc:  # noqa: BLE001 - CloudUnavailableError or anything else: report, never 500
        await pull_feed(ctx)  # EAE-09: a revoke must apply to the next attempt even when the bundle pull failed
        return _refresh_out(prev, bundle_version(ctx), "failed", str(exc) or type(exc).__name__)
    await pull_feed(ctx)
    installed = bundle_version(ctx)
    return _refresh_out(prev, installed, "installed" if installed != prev else "not_modified", None)


async def refresh_after_write(ctx: EdgeContext, cloud_version: Any) -> dict[str, Any]:
    """refresh_bundle(expect_version=<cloud bundle_version>) + `applied`."""
    want = cloud_version if isinstance(cloud_version, int) and not isinstance(cloud_version, bool) else None
    out = await refresh_bundle(ctx, want)
    inst = out["installed_version"]
    out["applied"] = out["result"] != "failed" and (want is None or (isinstance(inst, int) and inst >= want))
    return out


def _pull_warning(cloud_version: Any, bundle: Mapping[str, Any], what: str, why: str = "before enrolling") -> str:
    v = f"v{cloud_version}" if cloud_version is not None else "a new version"
    return (f"the cloud saved the {what} ({v}) but this edge still runs v{bundle.get('installed_version')}: "
            f"POST /v1/admin/bundle/refresh {why}")


def _cloud_warnings(body: Any) -> list[str]:
    ws = body.get("warnings") if isinstance(body, Mapping) else None
    return [str(w) for w in ws] if isinstance(ws, list) else []


def _int_or_none(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


# ---------------------------------------------------------------------------------- write handlers
def with_actor(wire: dict[str, Any], actor: str) -> dict[str, Any]:
    """RBAC v2 D / EAE-04: the actor is ALWAYS the authenticated principal; a client `actor` field is ignored."""
    return {**{k: v for k, v in wire.items() if k != "actor"}, "actor": actor}


async def put_access(ctx: EdgeContext, user_id: str, body: AccessUpdate, actor: str) -> dict[str, Any]:
    """§3.18.2: validation order model 422 -> 503 -> UNKNOWN_ROLE -> cloud -> bundle + feed pull."""
    require_online(ctx)
    check_role(body, _lvb(ctx))
    cloud = await cloud_admin(ctx, "PUT", f"/v1/admin/users/{user_id}/access", with_actor(body.wire(), actor),
                              label="PUT /v1/admin/users/{user_id}/access")
    cloud = cloud if isinstance(cloud, Mapping) else {}
    cbv = _int_or_none(cloud.get("bundle_version"))
    bundle = await refresh_after_write(ctx, cbv)
    warnings = _cloud_warnings(cloud)
    cloud_user = cloud.get("user") if isinstance(cloud.get("user"), Mapping) else None
    row = None
    if bundle["applied"]:
        cu = {"user_id": user_id, "in_schedule": True, **cloud_user} if cloud_user is not None else None
        row = user_row(ctx, user_id, cu)
        if row is not None and not row["in_bundle"]:
            warnings.append(f"role {body.role} has no access to {_safe_call(ctx.runtime, 'kiosk_zone')}: the user "
                            "is not in this kiosk's bundle and cannot be enrolled or admitted here")
    else:
        warnings.append(_pull_warning(cbv, bundle, "change"))
    status = str((cloud_user or {}).get("status") or "")
    if status == "REVOKED" and not cloud.get("restored") and not any("revoked" in w for w in warnings):
        warnings.append("user is revoked: access changes do not lift a revocation (use Restore)")
    prev_role = cloud.get("previous_role")
    log.info("access_change user=%s role=%s fields=%s created=%s readmitted=%s restored=%s bundle=%s applied=%s",
             user_id, body.role, sorted(body.model_fields_set), bool(cloud.get("created")),
             bool(cloud.get("readmitted")), bool(cloud.get("restored")), bundle["installed_version"],
             bundle["applied"])
    return {"user_id": user_id, "created": bool(cloud.get("created")), "unchanged": bool(cloud.get("unchanged")),
            "readmitted": bool(cloud.get("readmitted")), "restored": bool(cloud.get("restored")),
            "previous_role": None if prev_role is None else str(prev_role),
            "role": str(cloud.get("role") or body.role), "cloud_bundle_version": cbv, "bundle": bundle,
            "user": row, "warnings": warnings}


async def revoke(ctx: EdgeContext, user_id: str, req: RevokeRequest, actor: str) -> dict[str, Any]:
    """§3.18.3: cloud USER revocation (never `force`), then bundle + feed pull (SCHEDULE_REVOKED at once)."""
    require_online(ctx)
    payload: dict[str, Any] = {"type": "USER", "target_id": user_id, "reason": req.reason, "actor": actor}
    cloud = await cloud_admin(ctx, "POST", "/v1/admin/revocations", payload, label="POST /v1/admin/revocations")
    cloud = cloud if isinstance(cloud, Mapping) else {}
    cbv = _int_or_none(cloud.get("bundle_version"))
    bundle = await refresh_after_write(ctx, cbv)
    warnings = _cloud_warnings(cloud)
    if not bundle["applied"]:
        warnings.append(_pull_warning(cbv, bundle, "revocation", "to apply it now"))
    log.info("access_revoke user=%s reason=%s bundle=%s applied=%s", user_id, req.reason,
             bundle["installed_version"], bundle["applied"])
    return {"user_id": user_id, "type": "USER", "reason": str(cloud.get("reason") or req.reason),
            "revoked_at": utc_z(cloud.get("revoked_at")), "seq": _int_or_none(cloud.get("seq")),
            "cloud_bundle_version": cbv, "bundle": bundle, "user": user_row(ctx, user_id), "warnings": warnings}


def _codes(v: Any) -> list[dict[str, Any]]:
    out = []
    for c in v or []:
        if isinstance(c, Mapping) and c.get("code"):
            out.append({"code_id": None if c.get("code_id") is None else str(c["code_id"]), "code": str(c["code"])})
        elif isinstance(c, str) and c:
            out.append({"code_id": None, "code": c})
    return out


ROTATE_WARNING = ("Shown once: store these codes safely (each works once, for this staff_id only). The cloud keeps "
                  "only hashes; kiosks get them with the next bundle refresh.")


async def rotate_codes(ctx: EdgeContext, req: CodesRotateRequest, actor: str) -> dict[str, Any]:
    """§3.18.4: the cloud mints; the edge returns the plaintext FLAT, once (never logged / stored). Once minted it
    is always 200, also when the bundle pull fails (a shown-once secret must never be lost)."""
    require_online(ctx)
    cloud = await cloud_admin(ctx, "POST", "/v1/admin/codes/rotate", with_actor(req.wire(), actor),
                              label="POST /v1/admin/codes/rotate")
    cloud = cloud if isinstance(cloud, Mapping) else {}
    cbv = _int_or_none(cloud.get("bundle_version"))
    try:
        bundle = await refresh_after_write(ctx, cbv)
    except Exception as exc:  # noqa: BLE001 - refresh never raises; belt and braces for the shown-once codes
        v = bundle_version(ctx)
        bundle = {**_refresh_out(v, v, "failed", type(exc).__name__), "applied": False}
    codes = _codes(cloud.get("codes"))
    warnings = _cloud_warnings(cloud)
    if not bundle["applied"]:
        target = f"bundle v{cbv}" if cbv is not None else "the new bundle"
        warnings.append(f"codes work on this kiosk only after it installs {target} (POST /v1/admin/bundle/refresh)")
    log.info("staff_codes_rotated staff_id=%s minted=%d bundle=%s applied=%s", req.staff_id, len(codes),
             bundle["installed_version"], bundle["applied"])  # never the codes themselves
    dropped = cloud.get("dropped_code_ids")
    return {"staff_id": str(cloud.get("staff_id") or req.staff_id), "codes": codes,
            "code_length": _int_or_none(cloud.get("code_length")),
            "valid_until": utc_z(cloud.get("valid_until")), "one_time": True,
            "dropped_code_ids": [str(d) for d in dropped] if isinstance(dropped, list) else [],
            "warning": str(cloud.get("warning") or ROTATE_WARNING), "cloud_bundle_version": cbv, "bundle": bundle,
            "warnings": warnings}


async def refresh_route(ctx: EdgeContext) -> dict[str, Any]:
    """§3.18.5 POST /v1/admin/bundle/refresh. Errors carry installed_version."""
    installed = bundle_version(ctx)
    if not ctx.cloud.enabled:
        raise ApiError("CLOUD_UNAVAILABLE", "cloud not configured (CLOUD_API_URL empty)",
                       extra={"reason": "NOT_CONFIGURED", "installed_version": installed})
    if bool(getattr(getattr(ctx.runtime, "monitor", None), "forced", False)):
        raise ApiError("CLOUD_UNAVAILABLE", "bundle refresh failed: forced OFFLINE",
                       extra={"reason": "OFFLINE", "installed_version": installed})
    fn = getattr(ctx.runtime, "refresh_bundle_now", None)
    if not callable(fn):
        raise ApiError("CLOUD_UNAVAILABLE", "bundle refresh failed: the policy runtime cannot refresh the bundle",
                       extra={"reason": "CLOUD_ERROR", "installed_version": installed})
    try:
        await _run(ctx, fn)
    except Exception as exc:
        await pull_feed(ctx)  # EAE-09: the revocation feed is independent of the bundle pull
        report = getattr(exc, "report", None) or {}
        status = str(report.get("bundle") or "")
        if status.startswith("rejected"):
            raise ApiError("INVALID_STATE", f"cloud bundle {status.replace(': ', ':')} (the last valid bundle is kept)",
                           extra={"reason": "BUNDLE_REJECTED", "installed_version": bundle_version(ctx)}) from exc
        reason = "OFFLINE" if "forced OFFLINE" in str(exc) else "CLOUD_ERROR"
        raise ApiError("CLOUD_UNAVAILABLE", f"bundle refresh failed: {exc or type(exc).__name__}",
                       extra={"reason": reason, "installed_version": bundle_version(ctx)}) from exc
    await pull_feed(ctx)
    now = bundle_version(ctx)
    return _refresh_out(installed, now, "installed" if now != installed else "not_modified", None)
