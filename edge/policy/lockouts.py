"""Second-factor failure limits (SC2.4 / §7.2, audit F05 / F06 / SC2-D9 / EO-12). Pure logic over a state store.

A *scope* is one counter: `staff:<staff_id>` (STAFF_OVERRIDE, per named staff member), `device:staff_override`
(device backstop for every STAFF_OVERRIDE failure, incl. unknown / missing staff ids), `totp:<user_id>` and
`card:<user_id>` (per step-up candidate). The store (edge/offline/store.py SqliteFallbackState, or the in-memory
test double) persists the records, so a restart never resets a lockout. All times are REAL UTC (never the demo
clock). A lock that lies further ahead than its configured lockout (real clock stepped backwards) is clamped to
now + lockout: still locked, but never for longer than configured.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol

DEVICE_STAFF_SCOPE = "device:staff_override"


@dataclass(frozen=True)
class FailureRecord:
    failures: int = 0
    window_start: datetime | None = None
    locked_until: datetime | None = None
    times: tuple[datetime, ...] = ()  # windowed scopes: failure times inside the sliding window (<= max_failures)


@dataclass(frozen=True)
class Limit:
    """`max_failures` failures -> locked for `lockout_s`. `window_s` None = consecutive failures (a success or an
    expired lock resets); otherwise a SLIDING window: locked once `max_failures` failures fall within any `window_s`
    span (P6; a fixed window from the first failure would allow ~2x the stated rate around its boundary)."""

    max_failures: int
    lockout_s: float
    window_s: float | None = None

    @classmethod
    def from_cfg(cls, section: Any, prefix: str = "") -> Limit:
        window = section.get(f"{prefix}window_s") if prefix else section.get("window_s")
        return cls(max_failures=max(1, int(section[f"{prefix}max_failures"])),
                   lockout_s=float(section[f"{prefix}lockout_s"]),
                   window_s=float(window) if window is not None else None)


class FailureStore(Protocol):
    def failure_record(self, scope: str) -> FailureRecord | None: ...
    def set_failure_record(self, scope: str, record: FailureRecord | None) -> None: ...


def _current(store: FailureStore, scope: str, limit: Limit, now: datetime) -> FailureRecord:
    rec = store.failure_record(scope) or FailureRecord()
    if rec.locked_until is not None:
        if now >= rec.locked_until:
            return FailureRecord()  # lock served: start again
        cap = now + timedelta(seconds=limit.lockout_s)
        if rec.locked_until > cap:  # clock stepped backwards: bounded, still locked
            rec = FailureRecord(locked_until=cap)
            store.set_failure_record(scope, rec)
        return rec
    if limit.window_s is not None:  # sliding window: keep only the failures of the last window_s
        horizon = now - timedelta(seconds=limit.window_s)
        times = tuple(t for t in rec.times if t > horizon)
        return FailureRecord(failures=len(times), window_start=times[0] if times else None, times=times)
    return rec


def is_locked(store: FailureStore, scope: str, limit: Limit, now: datetime) -> bool:
    return _current(store, scope, limit, now).locked_until is not None


def locked_until(store: FailureStore, scope: str, limit: Limit, now: datetime) -> datetime | None:
    return _current(store, scope, limit, now).locked_until


def record_failure(store: FailureStore, scope: str, limit: Limit, now: datetime) -> bool:
    """Count one failure; True when this failure starts a lockout."""
    rec = _current(store, scope, limit, now)
    if rec.locked_until is not None:
        return False  # already locked: nothing more to count
    failures = rec.failures + 1
    if failures >= limit.max_failures:
        store.set_failure_record(scope, FailureRecord(locked_until=now + timedelta(seconds=limit.lockout_s)))
        return True
    times = (rec.times + (now,))[-limit.max_failures:] if limit.window_s is not None else ()
    store.set_failure_record(scope, FailureRecord(failures=failures, window_start=rec.window_start or now,
                                                  times=times))
    return False


def record_success(store: FailureStore, scope: str) -> None:
    store.set_failure_record(scope, None)
