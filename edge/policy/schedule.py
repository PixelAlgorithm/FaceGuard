"""SC1 campus schedule evaluator + bundle cache state (DECISION_POLICY §5, SURPRISE_CHALLENGES §SC1).

Pure and dependency-free (stdlib + zoneinfo only): the cloud imports this exact module to
re-evaluate offline decisions at `ts_utc`, so keep it free of edge/policy imports.

Bundle format: config/schedule.example.json. `cfg` is any Mapping with `grace_minutes` and
`grace_minutes_high_risk` (cache_state: `bundle_max_staleness_hours`, `clock_rollback_tolerance_s`).
Unknown zone -> KeyError; naive datetimes -> ValueError. Unparsable bundle data fails secure.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

IN_WINDOW = "IN_WINDOW"
GRACE_WINDOW = "GRACE_WINDOW"
OUTSIDE_WINDOW = "OUTSIDE_WINDOW"
NO_ENTITLEMENT = "NO_ENTITLEMENT"
ZONE_NOT_PERMITTED = "ZONE_NOT_PERMITTED"
HOLIDAY = "HOLIDAY"
REVOKED = "REVOKED"

FRESH, EXPIRED, INVALID = "FRESH", "EXPIRED", "INVALID"

DAYS = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")
DEFAULT_TZ = "Asia/Kolkata"
RISKS = ("low", "medium", "high")

Interval = tuple[datetime, datetime]


# ---------------------------------------------------------------- parsing helpers
def parse_ts(value: Any) -> datetime | None:
    """ISO-8601 -> aware datetime; None for missing/naive/unparsable (callers fail secure)."""
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else None


def _require_aware(dt: datetime, name: str) -> None:
    if not isinstance(dt, datetime) or dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")


def _minutes(hhmm: str) -> int:
    hh, mm = hhmm.split(":")
    m = int(hh) * 60 + int(mm)
    if not 0 <= m <= 1440 or not 0 <= int(mm) < 60:
        raise ValueError(f"bad time {hhmm!r}")
    return m


def _parse_date(value: Any) -> date:
    if not isinstance(value, str):
        raise TypeError(f"bad date {value!r}")
    return date.fromisoformat(value)


def _tz(bundle: Mapping[str, Any]) -> ZoneInfo:
    return ZoneInfo(bundle.get("timezone") or DEFAULT_TZ)


# ---------------------------------------------------------------- lookups
def kiosk_zone(bundle: Mapping[str, Any] | None, kiosk_id: str) -> str | None:
    if not bundle:
        return None
    k = (bundle.get("kiosks") or {}).get(kiosk_id)
    return k.get("zone") if isinstance(k, Mapping) else None


def zone_risk(bundle: Mapping[str, Any], zone: str) -> str:
    risk = bundle["zones"][zone]["risk"]
    if risk not in RISKS:
        raise ValueError(f"zone {zone} has unknown risk {risk!r}")
    return risk


def revoked_at_or_before(bundle: Mapping[str, Any], user_id: str, user: Mapping[str, Any] | None,
                         at: datetime) -> bool:
    """Time-aware revocation: revoked iff a revocation effective at or before `at` exists.

    Undated revocation (flag without timestamp, or unparsable timestamp) counts as always revoked.
    """
    for r in bundle.get("revocations") or []:
        if isinstance(r, Mapping) and r.get("user_id") == user_id:
            ts = parse_ts(r.get("revoked_at"))
            if ts is None or ts <= at:
                return True
    if user and user.get("revoked"):
        ts = parse_ts(user.get("revoked_at"))
        if ts is None or ts <= at:
            return True
    return False


def revoked_any(bundle: Mapping[str, Any], user_id: str, user: Mapping[str, Any] | None) -> bool:
    """Deny-only, time-agnostic: ANY revocation for the user (any revoked_at, or the user's revoked flag). Used when
    the edge clock is untrusted (cache INVALID, audit F04) and before a step-up ALLOW (F11)."""
    if any(isinstance(r, Mapping) and r.get("user_id") == user_id for r in bundle.get("revocations") or []):
        return True
    return bool(user and user.get("revoked"))


def _within(valid_from: Any, valid_until: Any, t: datetime) -> bool:
    """Half-open validity [valid_from, valid_until); unparsable bound -> not within (fail secure)."""
    if valid_from is not None:
        f = parse_ts(valid_from)
        if f is None or t < f:
            return False
    if valid_until is not None:
        u = parse_ts(valid_until)
        if u is None or t >= u:
            return False
    return True


def active_visitor_pass(bundle: Mapping[str, Any], user_id: str, t0: datetime) -> Mapping[str, Any] | None:
    for vp in bundle.get("visitor_passes") or []:
        if (isinstance(vp, Mapping) and vp.get("user_id") == user_id
                and vp.get("valid_from") is not None and vp.get("valid_until") is not None
                and _within(vp.get("valid_from"), vp.get("valid_until"), t0)):
            return vp
    return None


def permitted_zones(bundle: Mapping[str, Any], user: Mapping[str, Any], role: Mapping[str, Any],
                    vp: Mapping[str, Any] | None) -> set[str]:
    zones_cfg = bundle.get("zones") or {}
    add = set(user.get("zones_add") or [])
    remove = set(user.get("zones_remove") or [])
    candidates = set(role.get("zones") or []) | add | set((vp or {}).get("zones") or [])
    out = set()
    for z in candidates - remove:
        if (zones_cfg.get(z) or {}).get("requires_explicit_grant") and z not in add:
            continue  # explicit-grant zones only via users[].zones_add
        out.add(z)
    return out


# ---------------------------------------------------------------- windows
def _applies_on(entry: Mapping[str, Any], d: date) -> bool:
    days = entry.get("days")
    return days is None or DAYS[d.weekday()] in days


def _to_interval(entry: Mapping[str, Any], d: date, tz: ZoneInfo) -> Interval | None:
    s, e = _minutes(entry["start"]), _minutes(entry["end"])
    if s == e:
        return None
    midnight = datetime.combine(d, time(0), tzinfo=tz)
    start = midnight + timedelta(minutes=s)
    end = midnight + timedelta(minutes=e) if e > s else midnight + timedelta(days=1, minutes=e)
    return start, end


def _crosses_midnight(entry: Mapping[str, Any]) -> bool:
    return _minutes(entry["end"]) < _minutes(entry["start"])


def _window_entries(bundle: Mapping[str, Any], user: Mapping[str, Any], role_name: str,
                    role: Mapping[str, Any], zone: str, d: date,
                    vp: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    """Window entries for (user, zone, local date d), before clipping (SC1.2 'Windows')."""
    if role_name == "visitor" and vp is not None and vp.get("windows") is not None:
        base_src: Iterable[Mapping[str, Any]] = vp["windows"]
    else:
        base_src = (role.get("windows") or {}).get(zone) or []
    entries = [w for w in base_src if _applies_on(w, d)]
    for exc in bundle.get("exceptions") or []:
        if not (_parse_date(exc["date_from"]) <= d <= _parse_date(exc["date_to"])):
            continue
        if role_name not in (exc.get("roles") or []) or zone not in (exc.get("zones") or []):
            continue
        mode = exc.get("mode")
        exc_windows = [w for w in exc.get("windows") or [] if _applies_on(w, d)]
        if mode == "add":
            entries = entries + exc_windows
        elif mode == "replace":
            entries = exc_windows
        elif mode == "close":
            entries = []
        else:
            raise ValueError(f"exception {exc.get('id')} has unknown mode {mode!r}")
    extra = (user.get("extra_windows") or {}).get(zone) or []
    return entries + [w for w in extra if _applies_on(w, d)]


def _intervals(bundle: Mapping[str, Any], user: Mapping[str, Any], role_name: str, role: Mapping[str, Any],
               zone: str, t: datetime, vp: Mapping[str, Any] | None) -> list[Interval]:
    tz = _tz(bundle)
    d = t.date()
    out: list[Interval] = []
    for entry in _window_entries(bundle, user, role_name, role, zone, d, vp):
        iv = _to_interval(entry, d, tz)
        if iv:
            out.append(iv)
    out += _crossing_from(bundle, user, role_name, role, zone, d - timedelta(days=1), vp, tz)
    if role_name == "visitor" and vp is not None:
        lo, hi = parse_ts(vp.get("valid_from")), parse_ts(vp.get("valid_until"))
        clipped = []
        for s, e in out:
            s2, e2 = max(s, lo) if lo else s, min(e, hi) if hi else e
            if s2 < e2:
                clipped.append((s2, e2))
        out = clipped
    return out


def _crossing_from(bundle: Mapping[str, Any], user: Mapping[str, Any], role_name: str, role: Mapping[str, Any],
                   zone: str, day: date, vp: Mapping[str, Any] | None, tz: ZoneInfo, *,
                   on_holiday: bool = False) -> list[Interval]:
    """Midnight-crossing windows that START on `day` (a crossing window belongs to the day it starts on). A holiday
    on `day` closes the whole window, its tail after midnight included (F02): such windows are returned only
    with on_holiday=True (to report HOLIDAY instead of OUTSIDE_WINDOW)."""
    if _holiday_applies(bundle, role_name, zone, day) != on_holiday:
        return []
    out: list[Interval] = []
    for entry in _window_entries(bundle, user, role_name, role, zone, day, vp):
        if _crosses_midnight(entry):
            iv = _to_interval(entry, day, tz)
            if iv:
                out.append(iv)
    return out


def _holiday_applies(bundle: Mapping[str, Any], role_name: str, zone: str, d: date) -> bool:
    for h in bundle.get("holidays") or []:
        if h.get("date") != d.isoformat():
            continue
        closed = h.get("closed_zones")
        if closed != "ALL" and zone not in (closed or []):
            continue
        if role_name in (h.get("exempt_roles") or []):
            continue
        for exc in bundle.get("exceptions") or []:
            if (exc.get("overrides_holiday")
                    and _parse_date(exc["date_from"]) <= d <= _parse_date(exc["date_to"])
                    and role_name in (exc.get("roles") or []) and zone in (exc.get("zones") or [])):
                break
        else:
            return True
    return False


# ---------------------------------------------------------------- public API
def evaluate_schedule(user_id: str, zone: str, t0: datetime, bundle: Mapping[str, Any],
                      cfg: Mapping[str, Any], *, revocation_slack_s: float = 0.0) -> str:
    """Schedule result for `user_id` entering `zone` at `t0` (precedence = most restrictive first).

    `revocation_slack_s` (live edge decisions only, audit F03): a revocation the edge already HOLDS counts when its
    revoked_at <= t0 + slack, so an edge clock running up to `slack` behind the cloud cannot ignore it. The cloud's
    re-evaluation at ts_utc keeps the strict default 0 (time-aware, SC2.6 rule 3). Only ever adds revocations."""
    _require_aware(t0, "t0")
    risk = zone_risk(bundle, zone)  # unknown zone -> KeyError (caller: SYSTEM_ERROR)
    t = t0.astimezone(_tz(bundle))
    user = (bundle.get("users") or {}).get(user_id)
    at = t0 + timedelta(seconds=max(0.0, float(revocation_slack_s)))
    if revoked_at_or_before(bundle, user_id, user if isinstance(user, Mapping) else None, at):
        return REVOKED  # DECISION_POLICY §5 precedence: REVOKED first (also for users absent from users{})
    if not isinstance(user, Mapping):
        return NO_ENTITLEMENT
    if not _within(user.get("valid_from"), user.get("valid_until"), t0):
        return NO_ENTITLEMENT
    role_name = user.get("role")
    role = (bundle.get("roles") or {}).get(role_name)
    if not isinstance(role, Mapping):
        return NO_ENTITLEMENT
    vp = active_visitor_pass(bundle, user_id, t0)
    if role_name == "visitor" and vp is None:
        return NO_ENTITLEMENT
    if zone not in permitted_zones(bundle, user, role, vp):
        return ZONE_NOT_PERMITTED
    if _holiday_applies(bundle, role_name, zone, t.date()):
        return HOLIDAY  # today's holiday also closes the tail of yesterday's crossing windows (most restrictive)
    intervals = _intervals(bundle, user, role_name, role, zone, t, vp)  # holiday-start tails already dropped
    if any(s <= t < e for s, e in intervals):
        return IN_WINDOW  # P5: a valid window of a non-holiday day wins
    closed = _crossing_from(bundle, user, role_name, role, zone, t.date() - timedelta(days=1), vp, _tz(bundle),
                            on_holiday=True)
    if any(s <= t < e for s, e in closed):
        return HOLIDAY  # F02: inside the post-midnight tail of a window whose start day is a holiday
    g = int(cfg["grace_minutes_high_risk"] if risk == "high" else cfg["grace_minutes"])
    if g > 0:
        gd = timedelta(minutes=g)
        if any(s - gd <= t < s or e <= t < e + gd for s, e in intervals):
            return GRACE_WINDOW
    return OUTSIDE_WINDOW


def day_windows(bundle: Mapping[str, Any], user_id: str, zone: str, d: date) -> list[dict[str, str]]:
    """Display view (control panel): the window entries that apply to `user_id` in `zone` on local date `d`
    (role or visitor-pass windows, exceptions, users[].extra_windows), sorted, as {"start", "end"} "HH:MM"
    (an end before the start crosses midnight). [] if the user / role / zone is unknown, the zone is not
    permitted or a holiday closes it. Validity and revocation are separate fields of the view; decisions
    always use evaluate_schedule()."""
    if zone not in (bundle.get("zones") or {}):
        return []
    user = (bundle.get("users") or {}).get(user_id)
    if not isinstance(user, Mapping):
        return []
    role_name = user.get("role")
    role = (bundle.get("roles") or {}).get(role_name)
    if not isinstance(role, Mapping):
        return []
    vps = [vp for vp in bundle.get("visitor_passes") or [] if isinstance(vp, Mapping) and vp.get("user_id") == user_id]
    vp = vps[0] if vps else None
    if zone not in permitted_zones(bundle, user, role, vp) or _holiday_applies(bundle, role_name, zone, d):
        return []
    seen, out = set(), []
    for w in _window_entries(bundle, user, role_name, role, zone, d, vp):
        key = (str(w["start"]), str(w["end"]))
        _minutes(key[0]), _minutes(key[1])  # malformed -> ValueError (caller decides)
        if key not in seen:
            seen.add(key)
            out.append({"start": key[0], "end": key[1]})
    return sorted(out, key=lambda x: (_minutes(x["start"]), _minutes(x["end"])))


def entitled_user_ids(bundle: Mapping[str, Any] | None, zone: str, at: datetime, *,
                      revocation_slack_s: float = 0.0) -> set[str]:
    """Users who may be permitted in `zone` at `at` (not revoked, valid, zone permitted)."""
    _require_aware(at, "at")
    if not bundle or zone not in (bundle.get("zones") or {}):
        return set()
    out = set()
    rev_at = at + timedelta(seconds=max(0.0, float(revocation_slack_s)))
    for uid, user in (bundle.get("users") or {}).items():
        if not isinstance(user, Mapping) or revoked_at_or_before(bundle, uid, user, rev_at):
            continue
        if not _within(user.get("valid_from"), user.get("valid_until"), at):
            continue
        role = (bundle.get("roles") or {}).get(user.get("role"))
        if not isinstance(role, Mapping):
            continue
        vp = active_visitor_pass(bundle, uid, at)
        if user.get("role") == "visitor" and vp is None:
            continue
        if zone in permitted_zones(bundle, user, role, vp):
            out.add(uid)
    return out


def effective_expiry(bundle: Mapping[str, Any], cfg: Mapping[str, Any]) -> datetime | None:
    issued, expires = parse_ts(bundle.get("issued_at")), parse_ts(bundle.get("expires_at"))
    if issued is None or expires is None:
        return None
    return min(expires, issued + timedelta(hours=float(cfg["bundle_max_staleness_hours"])))


def cache_state(bundle: Mapping[str, Any] | None, signature_valid: bool, now: datetime,
                cfg: Mapping[str, Any]) -> str:
    """FRESH | EXPIRED | INVALID (signature fails, bundle missing, clock < issued_at - tolerance)."""
    _require_aware(now, "now")
    if not bundle or not signature_valid:
        return INVALID
    issued = parse_ts(bundle.get("issued_at"))
    eff = effective_expiry(bundle, cfg)
    if issued is None or eff is None:
        return INVALID
    if now < issued - timedelta(seconds=float(cfg["clock_rollback_tolerance_s"])):
        return INVALID
    return EXPIRED if now > eff else FRESH
