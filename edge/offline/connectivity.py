"""Connectivity monitor (SC2.1, DECISION_POLICY §8.1, API.md §3.10): ONLINE / OFFLINE / SYNCING.

ONLINE --misses_to_offline consecutive misses--> OFFLINE --successes_to_online--> SYNCING
SYNCING --queue acked + bundle refreshed--> ONLINE;  SYNCING --any miss--> OFFLINE.
mode() is ONLINE only in state ONLINE (SYNCING applies offline rules). A forced OFFLINE is immediate;
heartbeats keep being evaluated underneath, so AUTO goes straight to SYNCING if the last
successes_to_online heartbeats succeeded. CLOUD_API_URL empty => permanently OFFLINE (not_configured).
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

ONLINE, OFFLINE, SYNCING = "ONLINE", "OFFLINE", "SYNCING"
REASONS = ("heartbeat_timeout", "match_timeout", "forced", "not_configured")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z") if dt else None


class ConnectivityMonitor:
    def __init__(self, cfg: Any, *, configured: bool, forced_offline: bool = False, initial: str = OFFLINE,
                 clock: Callable[[], datetime] = _utcnow) -> None:
        C = cfg.connectivity
        self.misses_to_offline = int(C.misses_to_offline)
        self.successes_to_online = int(C.successes_to_online)
        self.require_sync = bool(C.require_sync_before_online)
        self.configured = configured
        self._clock = clock
        self._lock = threading.Lock()
        self.forced = bool(forced_offline)
        self.state = initial if (configured and not self.forced) else OFFLINE
        self.since = clock()
        self.reason: str | None = "forced" if self.forced else (None if configured else "not_configured")
        self.last_ok_at: datetime | None = None
        self.misses = 0
        self.successes = 0

    def mode(self) -> str:
        with self._lock:
            return ONLINE if self.state == ONLINE else OFFLINE

    def _set(self, state: str, reason: str | None) -> None:
        if state != self.state:
            self.state, self.since = state, self._clock()
        self.reason = reason

    def record(self, ok: bool, reason: str = "heartbeat_timeout") -> str:
        """Feed one heartbeat / cloud-call outcome. Returns the new state."""
        with self._lock:
            if not self.configured:
                self._set(OFFLINE, "not_configured")
                return self.state
            if ok:
                self.last_ok_at = self._clock()
                self.misses = 0
                self.successes += 1
            else:
                self.successes = 0
                self.misses += 1
            if self.forced:  # results are tracked, the state stays forced OFFLINE
                return self.state
            if ok:
                if self.state == OFFLINE and self.successes >= self.successes_to_online:
                    self._set(SYNCING if self.require_sync else ONLINE, None)
            elif self.state == SYNCING or (self.state == ONLINE and self.misses >= self.misses_to_offline):
                self._set(OFFLINE, reason if reason in REASONS else "heartbeat_timeout")
            return self.state

    def sync_complete(self) -> str:
        """Queue fully acked and a fresh bundle installed -> ONLINE (only from SYNCING)."""
        with self._lock:
            if self.state == SYNCING and not self.forced and self.configured:
                self._set(ONLINE, None)
            return self.state

    def set_forced(self, offline: bool) -> None:
        with self._lock:
            if offline:
                self.forced = True
                self._set(OFFLINE, "forced")
                return
            self.forced = False
            if not self.configured:
                self._set(OFFLINE, "not_configured")
            elif self.successes >= self.successes_to_online:
                self._set(SYNCING if self.require_sync else ONLINE, None)  # last N heartbeats were ok
            else:
                self._set(OFFLINE, "heartbeat_timeout" if self.misses else None)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "mode": ONLINE if self.state == ONLINE else OFFLINE,
                "state": self.state,
                "since": _iso(self.since),
                "forced": self.forced,
                "last_cloud_ok_at": _iso(self.last_ok_at),
                "reason": self.reason,
            }
