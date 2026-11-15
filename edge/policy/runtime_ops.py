"""Small, I/O-free helpers of PolicyRuntime (edge/policy/runtime.py): policy alert log (F14), forced-mode timer
(RBAC v2 D), hook runner (EO-05 / EM-01 / SC2-D4) and the public sync summary (offline F6 / EO-13)."""

from __future__ import annotations

import logging
import threading
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

log = logging.getLogger("edge.policy.runtime")

EVENT_LOG_MAX = 500
ALERT_LIMIT_MAX = 200
# Security-relevant non-ALERT_* events also listed by recent_alerts() (operator console, GET /v1/admin/alerts).
SECURITY_EVENTS = frozenset({
    "REVOCATION_APPLIED", "USER_ERASED_LOCAL", "USER_REINSTATED_LOCAL", "CLOUD_ERASURE_QUEUED", "CLOUD_ERASURE_DONE",
    "FORCED_MODE_CHANGED", "FORCED_MODE_EXPIRED", "LEGACY_LOG_MIGRATED", "BUNDLE_INSTALLED",
    "FALLBACK_STATE_RESEEDED",
})
DEMO_REASON = "DEMO"
# GET /v1/mode is public: the sync summary it carries holds counts only (no user / attempt ids, offline F6).
PUBLIC_REPORT_KEYS = ("accepted", "duplicates", "rejected", "queue_depth", "ok", "error", "bundle", "sent",
                      "clock_drift_s", "revocations_state_lost")


class AlertLog:
    """Thread-safe bounded policy event log. Events carry pseudonymous ids only (never names / codes / images)."""

    def __init__(self, clock: Callable[[], datetime], iso: Callable[[datetime], str | None]) -> None:
        self._clock, self._iso = clock, iso
        self._events: deque[dict[str, Any]] = deque(maxlen=EVENT_LOG_MAX)
        self._next_id = 0
        self._lock = threading.Lock()

    def emit(self, kind: str, **data: Any) -> dict[str, Any]:
        with self._lock:
            self._next_id += 1
            ev = {"id": self._next_id, "type": kind, "at": self._iso(self._clock()), **data}
            self._events.append(ev)
        if kind.startswith("ALERT_"):
            log.warning("policy alert %s", kind)  # type only: ids stay in the authenticated alert view
        return ev

    def since(self, since_id: int = 0) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(e) for e in self._events if e["id"] > since_id]

    def recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        n = max(1, min(int(limit), ALERT_LIMIT_MAX))
        with self._lock:
            hits = [dict(e) for e in self._events if e["type"].startswith("ALERT_") or e["type"] in SECURITY_EVENTS]
        return hits[-n:]


@dataclass(frozen=True)
class ForcedState:
    forced: bool = False
    until: datetime | None = None  # real UTC; None while forced = unlimited (env FORCE_OFFLINE or DEMO)
    reason: str | None = None


def forced_state(force: str, reason: str | None, max_minutes: Any, *, demo_mode: bool, now: datetime,
                 default_min: float, max_min: float) -> ForcedState:
    """Validate POST /v1/admin/mode {force, reason?, max_minutes?} -> new state. ValueError (-> 422) on bad input.
    OFFLINE auto-reverts after max_minutes (default `default_min`, 1..max_min); only DEMO_MODE=1 with reason "DEMO"
    and no max_minutes stays forced without a deadline."""
    if force not in ("OFFLINE", "AUTO"):
        raise ValueError("forced mode must be OFFLINE or AUTO")
    if reason is not None and (not isinstance(reason, str) or len(reason) > 200):
        raise ValueError("reason must be a string of at most 200 characters")
    if force == "AUTO":
        return ForcedState()
    if max_minutes is None:
        if demo_mode and reason == DEMO_REASON:
            return ForcedState(True, None, reason)
        minutes = float(default_min)
    else:
        if isinstance(max_minutes, bool) or not isinstance(max_minutes, int | float):
            raise ValueError("max_minutes must be a number")
        minutes = float(max_minutes)
        if not 1 <= minutes <= float(max_min):
            raise ValueError(f"max_minutes must be within 1..{int(max_min)}")
    return ForcedState(True, now + timedelta(minutes=minutes), reason)


def run_hooks(hooks: Iterable[Callable[..., Any]], *args: Any, what: str) -> bool:
    """Run every hook (one failing hook never stops the others). True only if all succeeded."""
    ok = True
    for fn in hooks:
        try:
            fn(*args)
        except Exception as exc:  # noqa: BLE001 - isolated by design
            ok = False
            log.error("%s hook failed (%s)", what, type(exc).__name__)
    return ok


def public_report(report: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if report is None:
        return None
    out = {k: report.get(k) for k in PUBLIC_REPORT_KEYS if k in report}
    flags = report.get("flags")
    out["flags"] = len(flags) if isinstance(flags, list) else 0
    erasures = report.get("cloud_erasures")
    if isinstance(erasures, Mapping):
        out["cloud_erasures_pending"] = erasures.get("pending")
    return out
