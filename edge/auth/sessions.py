"""In-memory staff sessions keyed by sha256(token): an edge restart signs everyone out.

Timers run on models.auth_monotonic() (sleep-inclusive, never jumps; injectable): idle timeout + absolute lifetime. Only explicit activity
(non-GET requests, X-FG-Activity: 1, POST /v1/auth/activity) refreshes last_seen; GET polls and SSE never
extend a session. Per-account cap (oldest evicted), revoke / revoke_all. Only token digests are held.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import timedelta

from edge.auth import tokens
from edge.auth.models import Clock, Session, auth_monotonic, utc_now

SESSION_ID_CHARS = 16  # public handle = first 16 hex chars of the token digest


class SessionManager:
    def __init__(self, *, idle_timeout_s: int, max_age_s: int, max_per_user: int, clock: Clock = utc_now,
                 monotonic: Callable[[], float] = auth_monotonic) -> None:
        self._idle = float(idle_timeout_s)
        self._max_age = float(max_age_s)
        self._max_per_user = max_per_user
        self._clock = clock
        self._mono = monotonic
        self._lock = threading.Lock()
        self._by_digest: dict[str, Session] = {}

    @property
    def idle_timeout_s(self) -> int:
        return int(self._idle)

    def create(self, staff_id: str, epoch: int, *, client_ip: str | None = None,
               user_agent: str | None = None) -> tuple[str, Session]:
        """(token shown once to the client, session). Evicts the account's oldest sessions over the cap."""
        token = tokens.new_session_token()
        token_sha = tokens.digest(token)
        mono, wall = self._mono(), self._clock()
        session = Session(
            session_id=token_sha[:SESSION_ID_CHARS], token_sha256=token_sha, staff_id=staff_id, epoch=epoch,
            created_mono=mono, last_seen_mono=mono, expires_mono=mono + self._max_age, created_at=wall,
            expires_at=wall + timedelta(seconds=self._max_age), client_ip=client_ip, user_agent=user_agent,
        )
        with self._lock:
            self._sweep(mono)
            mine = sorted((s for s in self._by_digest.values() if s.staff_id == staff_id),
                          key=lambda s: s.created_mono)
            for old in mine[: max(0, len(mine) - self._max_per_user + 1)]:
                self._by_digest.pop(old.token_sha256, None)
            self._by_digest[token_sha] = session
        return token, session

    def lookup(self, token: str, *, touch: bool = False) -> Session | None:
        """The live session for a token, or None (unknown, idle-expired, past its lifetime).
        touch=True records activity (extends the idle window, never the absolute lifetime)."""
        if not tokens.is_session_token(token):
            return None
        token_sha = tokens.digest(token)
        mono = self._mono()
        with self._lock:
            session = self._by_digest.get(token_sha)
            if session is None:
                return None
            if self._expired(session, mono):
                del self._by_digest[token_sha]
                return None
            if touch:
                session = replace(session, last_seen_mono=mono)
                self._by_digest[token_sha] = session
            return session

    def get(self, session_id: str) -> Session | None:
        """Live session by public id (no activity recorded)."""
        mono = self._mono()
        with self._lock:
            hit = next((s for s in self._by_digest.values() if s.session_id == session_id), None)
            return None if hit is None or self._expired(hit, mono) else hit

    def touch(self, session_id: str) -> bool:
        mono = self._mono()
        with self._lock:
            for token_sha, s in list(self._by_digest.items()):
                if s.session_id == session_id and not self._expired(s, mono):
                    self._by_digest[token_sha] = replace(s, last_seen_mono=mono)
                    return True
            return False

    def set_epoch(self, session_id: str, epoch: int) -> None:
        with self._lock:
            for token_sha, s in list(self._by_digest.items()):
                if s.session_id == session_id:
                    self._by_digest[token_sha] = replace(s, epoch=epoch)

    def revoke(self, session_id: str) -> bool:
        with self._lock:
            hit = [d for d, s in self._by_digest.items() if s.session_id == session_id]
            for d in hit:
                del self._by_digest[d]
            return bool(hit)

    def revoke_all(self, staff_id: str, *, except_session_id: str | None = None) -> int:
        with self._lock:
            hit = [d for d, s in self._by_digest.items()
                   if s.staff_id == staff_id and s.session_id != except_session_id]
            for d in hit:
                del self._by_digest[d]
            return len(hit)

    def for_staff(self, staff_id: str) -> list[Session]:
        mono = self._mono()
        with self._lock:
            return [s for s in self._by_digest.values() if s.staff_id == staff_id and not self._expired(s, mono)]

    def count(self) -> int:
        with self._lock:
            return len(self._by_digest)

    def _expired(self, session: Session, mono: float) -> bool:
        return mono >= session.expires_mono or mono - session.last_seen_mono >= self._idle

    def _sweep(self, mono: float) -> None:
        for d in [d for d, s in self._by_digest.items() if self._expired(s, mono)]:
            del self._by_digest[d]
