"""Kiosk rate limiter (A1, DECISION_POLICY §9.7 / P11) on the monotonic clock.

Counted: a DENY whose codes contain a `rate_limit.counted_code_prefixes` (SPOOF_, MASK_CUE_, INJECTION_)
or `counted_codes` (CHALLENGE_FAILED, FALLBACK_FAILED) code -- except a DENY carrying any SCHEDULE_*
code (BIO_UNSURE + schedule DENYs). Never counted: schedule, identity, quality, SYSTEM_ERROR,
RATE_LIMITED. Sliding window: on a counted DENY at t drop events older than t - window_s (an event at
exactly t - window_s still counts), append t; count >= max_failures -> lockout_until = t + lockout_s.
Events stay after a lockout ends. `enabled: false` disables counting and blocking. Thread-safe.
"""

from __future__ import annotations

import math
import threading
from collections import deque
from collections.abc import Sequence
from typing import Any


def counts_toward_rate_limit(decision: str, codes: Sequence[str], RL: Any) -> bool:
    if decision != "DENY":
        return False
    if any(c.startswith("SCHEDULE_") for c in codes):
        return False  # N11 / F7 / E4: their MASK_CUE_* codes are unsure evidence, not attack evidence
    prefixes = tuple(RL.counted_code_prefixes)
    counted = set(RL.counted_codes)
    return any(c in counted or c.startswith(prefixes) for c in codes)


class RateLimiter:
    def __init__(self, cfg: Any) -> None:
        self.RL = cfg.rate_limit
        self.enabled = bool(self.RL.enabled)
        self.max_failures = int(self.RL.max_failures)
        self.window_s = float(self.RL.window_s)
        self.lockout_s = float(self.RL.lockout_s)
        self._events: deque[float] = deque()
        self._lockout_until: float | None = None
        self._lock = threading.Lock()

    def retry_after_s(self, t: float) -> float | None:
        """Seconds left of an active lockout at monotonic time t, else None."""
        with self._lock:
            if self.enabled and self._lockout_until is not None and t < self._lockout_until:
                return self._lockout_until - t
            return None

    def retry_after_int(self, t: float) -> int | None:
        left = self.retry_after_s(t)
        return None if left is None else max(1, math.ceil(left))

    def record(self, decision: str, codes: Sequence[str], t: float) -> bool:
        """Feed one decision. Returns True when this DENY starts a new lockout (-> ALERT_RATE_LIMIT_LOCKOUT)."""
        if not self.enabled or not counts_toward_rate_limit(decision, codes, self.RL):
            return False
        with self._lock:
            while self._events and self._events[0] < t - self.window_s:
                self._events.popleft()
            self._events.append(t)
            if len(self._events) >= self.max_failures:
                was_locked = self._lockout_until is not None and t < self._lockout_until
                self._lockout_until = t + self.lockout_s
                return not was_locked
            return False

    def reset(self) -> None:
        with self._lock:
            self._events.clear()
            self._lockout_until = None

    def state(self) -> dict[str, Any]:
        with self._lock:
            return {"events": list(self._events), "lockout_until": self._lockout_until}
