"""Login throttling and KDF admission (design v2 C).

- GlobalLimiter: all login attempts, every username, at most N per sliding window -> 429 RATE_LIMITED.
  There is NO per-IP limiter: every kiosk client is 127.0.0.1.
- LoginThrottle: per-key progressive delay in memory. After `threshold` failures every further attempt
  must wait 2^(n - threshold) s (capped). Unknown usernames are tracked exactly like real ones, so the
  response never reveals whether an account exists. It is a soft delay: nobody (not even the last admin)
  is ever hard-locked. The live delay runs on the sleep-inclusive monotonic clock (a wall-clock / NTP step
  can neither extend nor clear it) and retry_after_s is clamped to the cap; the wall-clock `next_allowed`
  in FailureState exists only for persistence (flush / seed) and display.
- KdfExecutor: a dedicated 2-thread pool ("auth-kdf") for scrypt; admission is non-blocking (2 in flight ->
  429 retry_after_s=1), so sign-ins can never queue up behind, or starve, the kiosk decision path.
"""

from __future__ import annotations

import asyncio
import functools
import math
import threading
from collections import OrderedDict, deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, TypeVar

from edge.auth.models import AuthError, Clock, auth_monotonic, utc_now

T = TypeVar("T")

MAX_TRACKED_USERNAMES = 10_000
KDF_WORKERS = 2
KDF_THREAD_PREFIX = "auth-kdf"
KDF_BUSY_RETRY_S = 1


def rate_limited(retry_after_s: float, message: str = "too many sign-in attempts, try again later") -> AuthError:
    retry = max(1, math.ceil(retry_after_s))
    return AuthError("RATE_LIMITED", message, extra={"retry_after_s": retry}, headers={"Retry-After": str(retry)})


class GlobalLimiter:
    def __init__(self, *, max_attempts: int, window_s: int, monotonic: Callable[[], float] = auth_monotonic) -> None:
        self._max = max_attempts
        self._window = float(window_s)
        self._mono = monotonic
        self._lock = threading.Lock()
        self._hits: deque[float] = deque()

    def hit(self) -> None:
        """Record one attempt; raises RATE_LIMITED (with retry_after_s) when the window is full."""
        now = self._mono()
        with self._lock:
            while self._hits and now - self._hits[0] >= self._window:
                self._hits.popleft()
            if len(self._hits) >= self._max:
                raise rate_limited(self._hits[0] + self._window - now)
            self._hits.append(now)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


@dataclass(frozen=True)
class FailureState:
    failed: int = 0
    next_allowed: datetime | None = None


@dataclass(frozen=True)
class _Entry:
    failed: int
    until_mono: float | None  # end of the live delay on the monotonic clock


class LoginThrottle:
    def __init__(self, *, threshold: int, cap_s: int, clock: Clock = utc_now,
                 monotonic: Callable[[], float] = auth_monotonic) -> None:
        self._threshold = threshold
        self._cap_s = cap_s
        self._cap = timedelta(seconds=cap_s)
        self._clock = clock
        self.monotonic = monotonic
        self._lock = threading.Lock()
        self._state: OrderedDict[str, _Entry] = OrderedDict()

    def rebind(self, *, monotonic: Callable[[], float]) -> LoginThrottle:
        """A new, EMPTY throttle with the same settings on another monotonic clock."""
        return LoginThrottle(threshold=self._threshold, cap_s=self._cap_s, clock=self._clock,
                             monotonic=monotonic)

    def delay_for(self, failed: int) -> timedelta:
        if failed < self._threshold:
            return timedelta(0)
        return min(timedelta(seconds=2 ** min(failed - self._threshold, 30)), self._cap)

    def _remaining(self, entry: _Entry | None, now_mono: float) -> float:
        if entry is None or entry.until_mono is None:
            return 0.0
        return min(float(self._cap_s), max(0.0, entry.until_mono - now_mono))

    def _public(self, entry: _Entry | None, now_mono: float) -> FailureState:
        if entry is None:
            return FailureState()
        remaining = self._remaining(entry, now_mono)
        return FailureState(entry.failed, self._clock() + timedelta(seconds=remaining) if remaining > 0 else None)

    def retry_after_s(self, username: str) -> float:
        """Seconds the caller must still wait before trying `username` again (0 = allowed now, <= cap)."""
        now = self.monotonic()
        with self._lock:
            entry = self._state.get(username)
        return self._remaining(entry, now)

    def fail(self, username: str) -> FailureState:
        now = self.monotonic()
        with self._lock:
            old = self._state.pop(username, _Entry(0, None))
            failed = old.failed + 1
            delay = self.delay_for(failed).total_seconds()
            entry = _Entry(failed, now + delay if delay else None)
            self._state[username] = entry
            while len(self._state) > MAX_TRACKED_USERNAMES:
                self._state.popitem(last=False)
        return self._public(entry, now)

    def succeed(self, username: str) -> None:
        with self._lock:
            self._state.pop(username, None)

    def state(self, username: str) -> FailureState:
        """Failure count + the wall-clock end of the live delay (None when no delay is running)."""
        now = self.monotonic()
        with self._lock:
            entry = self._state.get(username)
        return self._public(entry, now)

    def seed(self, username: str, failed: int, next_allowed: datetime | None) -> None:
        """Restore persisted volatile state (after a restart). A stored wait beyond the cap is ignored."""
        until: float | None = None
        if next_allowed is not None:
            remaining = (next_allowed - self._clock()).total_seconds()
            if 0 < remaining <= self._cap_s:
                until = self.monotonic() + remaining
        with self._lock:
            if username not in self._state and (failed or until is not None):
                self._state[username] = _Entry(failed, until)


class KdfExecutor:
    def __init__(self, workers: int = KDF_WORKERS) -> None:
        self._workers = workers
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix=KDF_THREAD_PREFIX)
        self._lock = threading.Lock()
        self._in_flight = 0

    @property
    def in_flight(self) -> int:
        return self._in_flight

    async def run(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Run blocking KDF work in the auth-kdf pool; 429 immediately when both workers are busy."""
        with self._lock:
            if self._in_flight >= self._workers:
                raise rate_limited(KDF_BUSY_RETRY_S, "sign-in is busy, try again in a moment")
            self._in_flight += 1
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(self._pool, functools.partial(fn, *args, **kwargs))
        finally:
            with self._lock:
                self._in_flight -= 1

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
