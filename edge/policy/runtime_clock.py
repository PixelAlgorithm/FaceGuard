"""PolicyRuntime mixin (edge/policy/runtime.py): forced mode (RBAC v2 D, auto-revert), random liveness challenge
control and the DEMO_MODE=1 demo clock (docs/DECISION_POLICY.md §2: the wall clock = demo clock; the real clock
drives the forced-mode deadline)."""

from __future__ import annotations

import math
import re
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from edge.policy import runtime_ops as ops
from edge.policy import schedule as sched_mod
from edge.policy.runtime_common import IST
from edge.policy.runtime_common import iso as _iso

if TYPE_CHECKING:
    from edge.offline.bundle import BundleStore
    from edge.offline.connectivity import ConnectivityMonitor
    from edge.policy.thresholds import Thresholds

MAX_DEMO_OFFSET_S = 7 * 86400  # demo clock: +-7 days (larger offsets overflow datetime / brick the runtime)
_HHMM = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


class _FixedRng:
    """Forced random-challenge draw (FORCE / FORCE_NEXT): `forced` makes the engine bypass the rate (even 0.0)."""

    forced = True

    def __init__(self, value: float, on_use: Callable[[], None] | None = None) -> None:
        self.value, self.on_use = value, on_use

    def random(self) -> float:
        if self.on_use:
            self.on_use()
        return self.value


class ClockMixin:
    """Forced mode, random-challenge control and the demo clock. State is set by PolicyRuntime.__init__."""

    cfg: Thresholds
    bundles: BundleStore
    monitor: ConnectivityMonitor
    demo_mode: bool
    _lock: threading.RLock
    _real: Callable[[], datetime]
    _offset: timedelta
    _rng: Any
    _random_challenge: str
    _force_next: bool
    _forced: ops.ForcedState

    # methods of PolicyRuntime / other mixins (annotations only: never shadow the real methods in the MRO)
    now: Callable[[], datetime]
    _emit: Callable[..., None]
    mode_status: Callable[[], dict[str, Any]]

    def set_forced_mode(self, force: str, reason: str | None = None, max_minutes: Any = None) -> dict[str, Any]:
        """POST /v1/admin/mode (RBAC v2 D). OFFLINE auto-reverts to AUTO after max_minutes (default
        connectivity.forced_offline_default_min, 1..forced_offline_max_min); only DEMO_MODE=1 + reason "DEMO" + no
        max_minutes stays forced without a deadline. ValueError (-> 422) on bad input. The deny-only revocation feed
        keeps being pulled while forced OFFLINE."""
        C = self.cfg.connectivity
        state = ops.forced_state(force, reason, max_minutes, demo_mode=self.demo_mode, now=self._real(),
                                 default_min=float(C.forced_offline_default_min),
                                 max_min=float(C.forced_offline_max_min))
        with self._lock:
            self._forced = state
            self.monitor.set_forced(state.forced)
        self._emit("FORCED_MODE_CHANGED", force=force, until=_iso(state.until), reason=state.reason)
        return self.mode_status()

    def _expire_forced(self) -> None:
        st = self._forced
        if not (st.forced and st.until is not None and self._real() >= st.until):
            return
        with self._lock:
            swapped = self._forced is st  # a concurrent set_forced_mode / expiry wins: emit only once
            if swapped:
                self._forced = ops.ForcedState()
                self.monitor.set_forced(False)
        if swapped:
            self._emit("FORCED_MODE_EXPIRED", reason=st.reason)

    def set_random_challenge(self, mode: str) -> None:
        """Random liveness challenge control: AUTO (configured rate) | FORCE (every would-be ALLOW) |
        FORCE_NEXT (the next would-be ALLOW only) | OFF (never; eval/demo profile)."""
        if mode not in ("AUTO", "FORCE", "FORCE_NEXT", "OFF"):
            raise ValueError("random challenge mode must be AUTO, FORCE, FORCE_NEXT or OFF")
        self._random_challenge = mode
        self._force_next = mode == "FORCE_NEXT"

    def _attempt_rng(self) -> Any:
        if self._random_challenge == "OFF":
            return None
        if self._random_challenge == "FORCE":
            return _FixedRng(0.0)
        if self._force_next:
            def used() -> None:
                self._force_next = False
                self._random_challenge = "AUTO"
            return _FixedRng(0.0, on_use=used)
        return self._rng

    def set_demo_clock(self, *, set_local: str | None = None, offset_s: float | None = None,
                       reset: bool = False) -> dict[str, Any]:
        """POST /v1/admin/clock (DEMO_MODE=1 only, else PermissionError -> 403). Invalid input -> ValueError
        (-> 422) and the clock is left unchanged: "HH:MM" (today, IST) or an ISO datetime; the resulting offset
        must be finite and within +-MAX_DEMO_OFFSET_S (7 days) so now() can never overflow.
        "HH:MM" stays *today* (API.md 3.14, test X13): a time before the LVB issued_at - tolerance is a clock
        rollback (cache INVALID); the returned status flags it (`bundle_rollback`, `earliest_local`)."""
        if not self.demo_mode:
            raise PermissionError("demo clock requires DEMO_MODE=1")
        real = self._real()
        new = self._offset
        try:
            if reset:
                new = timedelta(0)
            elif set_local is not None:
                new = self._demo_target(str(set_local), real) - real
            elif offset_s is not None:
                off = float(offset_s)
                if not math.isfinite(off) or abs(off) > MAX_DEMO_OFFSET_S:
                    raise ValueError(f"offset_s must be finite and within +-{MAX_DEMO_OFFSET_S} s")
                new = timedelta(seconds=off)
            if abs(new.total_seconds()) > MAX_DEMO_OFFSET_S:
                raise ValueError(f"demo clock must stay within +-{MAX_DEMO_OFFSET_S // 86400} days of real time")
            _ = real + new  # must not overflow
        except (OverflowError, TypeError) as exc:
            raise ValueError(f"invalid demo clock value: {exc}") from exc
        with self._lock:
            self._offset = new
        return self._demo_clock_full()

    @staticmethod
    def _demo_target(set_local: str, real: datetime) -> datetime:
        m = _HHMM.match(set_local)
        if m:  # "HH:MM" today (IST)
            return real.astimezone(IST).replace(hour=int(m.group(1)), minute=int(m.group(2)), second=0,
                                                microsecond=0)
        if len(set_local) <= 5:
            raise ValueError("set_local must be HH:MM (00:00-23:59) or an ISO-8601 datetime")
        target = datetime.fromisoformat(set_local)  # ValueError on garbage
        return target.replace(tzinfo=IST) if target.tzinfo is None else target

    def _demo_clock_full(self) -> dict[str, Any]:
        now = self.now()
        out: dict[str, Any] = {"active": self._offset != timedelta(0),
                               "now_local": now.astimezone(IST).strftime("%H:%M"),
                               "now_utc": _iso(now), "offset_s": int(self._offset.total_seconds()),
                               "date_local": now.astimezone(IST).date().isoformat()}
        out.update(self._rollback_view(now))
        return out

    def _rollback_view(self, now: datetime) -> dict[str, Any]:
        """Control-panel warning (docs: the demo clock never re-signs): the earliest wall time the installed
        bundle accepts (issued_at - cache.clock_rollback_tolerance_s) and whether `now` is before it."""
        lvb = self.bundles.lvb
        issued = sched_mod.parse_ts(lvb.get("issued_at")) if lvb else None
        if issued is None:
            return {"bundle_issued_at": None, "earliest_utc": None, "earliest_local": None,
                    "earliest_date_local": None, "bundle_rollback": False, "cache_state": "INVALID"}
        earliest = issued - timedelta(seconds=float(self.cfg.cache.clock_rollback_tolerance_s))
        el = earliest.astimezone(IST)
        if el.second or el.microsecond:  # first whole minute a "HH:MM" demo time may use
            el = el.replace(second=0, microsecond=0) + timedelta(minutes=1)
        return {"bundle_issued_at": lvb.get("issued_at"), "earliest_utc": _iso(earliest),
                "earliest_local": el.strftime("%H:%M"), "earliest_date_local": el.date().isoformat(),
                "bundle_rollback": now < earliest,
                "cache_state": sched_mod.cache_state(lvb, True, now, self.cfg.cache)}

