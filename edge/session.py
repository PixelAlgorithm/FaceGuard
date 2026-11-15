"""Attempt sessions: attempt ids (att_<ULID>), single-use nonces (TTL 10 s), random flash sequences.

All randomness comes from `secrets` (CSPRNG). Frames are never stored here; only per-attempt
metadata needed for the step-up path (candidate user, last decision) lives in RAM.
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from ulid import ULID

from edge.config import Thresholds
from edge.schemas import FlashStep

NONCE_TTL_S = 10  # contract: nonce single-use, TTL 10 s (docs/API.md 3.1)
ATTEMPT_RETENTION_S = 600  # in-RAM attempt metadata kept for step-up / GET, then dropped
MIN_SEGMENT_MS = 200
FLASH_COLOURS = 3  # lead decision (round 2, ratified): exactly 3 colours (~233 ms each over 700 ms)

# Off-primary tints (no saturated red, each colour at most once per sequence; photosensitivity).
FLASH_PALETTE: tuple[str, ...] = ("#FF4D4D", "#4DFF6A", "#4D6BFF", "#FFF04D", "#FF4DFF", "#4DFFFF")


class NonceError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class Attempt:
    attempt_id: str
    kiosk_id: str
    nonce: str
    created_at: datetime
    expires_at: datetime
    flash_enabled: bool
    flash_sequence: list[FlashStep]
    camera_label: str
    claimed_user_id: str | None = None
    recapture_of: str | None = None
    recapture_count: int = 0
    nonce_used: bool = False
    frames_received_at: datetime | None = None
    candidate_user_id: str | None = None
    last_response: dict[str, Any] | None = None
    eval_tags: dict[str, Any] | None = None  # copy of the admin eval context at session/start
    depth_requested: bool = False
    challenge_nonces: set[str] = field(default_factory=set)
    decided_challenge_nonces: set[str] = field(default_factory=set)  # the runtime produced a decision for these
    signals_debug: dict[str, Any] | None = None  # admin-only view; never images or embeddings
    face_lock_at_ms: int | None = None  # from FramesMeta; the rendered beacon must echo it
    rendered_client_ms: int | None = None  # first rendered beacon wins
    closed: bool = False  # superseded by a recapture
    # Early cloud probe (POST /v1/attempt/{id}/probe): one per attempt, between session/start and frames.
    probe_received: bool = False
    probe: Any = None  # edge.attempts.ProbeState (cloud task + start time + local embedding task)

    @property
    def eval_label(self) -> str | None:
        return (self.eval_tags or {}).get("label")

    @property
    def terminal(self) -> bool:
        return self.closed or bool(self.last_response and self.last_response.get("decision") in {"ALLOW", "DENY"})

    @property
    def pending_step(self) -> str | None:
        """CHALLENGE | SECOND_FACTOR | RECAPTURE while the latest decision is STEP_UP, else None."""
        r = self.last_response or {}
        if r.get("decision") != "STEP_UP":
            return None
        return str((r.get("next_action") or {}).get("type") or "") or None


def make_flash_sequence(th: Thresholds, rng: secrets.SystemRandom | None = None) -> list[FlashStep]:
    """Exactly 3 distinct random colours splitting liveness.flash.duration_ms (thresholds.yaml, shipped
    700 ms -> 233 + 233 + 234 ms; ratified lead decision). Photosensitivity: the 2 colour changes must fit
    liveness.flash.max_changes_per_s over that window and every segment must be >= MIN_SEGMENT_MS, else
    ValueError (the YAML is wrong; never silently shortened)."""
    rng = rng or secrets.SystemRandom()
    total = int(th.get("liveness.flash.duration_ms"))
    n = FLASH_COLOURS
    max_changes = float(th.get("liveness.flash.max_changes_per_s")) * total / 1000.0
    if n - 1 > max_changes or total // n < MIN_SEGMENT_MS:
        raise ValueError("flash sequence violates the photosensitivity limit in thresholds.yaml")
    colours = rng.sample(list(FLASH_PALETTE), n)
    durations = [total // n] * (n - 1) + [total - (total // n) * (n - 1)]
    steps, offset = [], 0
    for colour, dur in zip(colours, durations):
        steps.append(FlashStep(color=colour, offset_ms=offset, duration_ms=dur))
        offset += dur
    return steps


def new_nonce() -> str:
    return "n_" + secrets.token_urlsafe(18)


def secret_equal(expected: str | None, given: Any) -> bool:
    """Constant-time compare of a server-held secret (admin/depth token, attempt/depth nonce) with client
    input that never raises. hmac.compare_digest raises TypeError for a non-ASCII str (a latin-1-decoded
    header byte >= 0x80, a JSON "\\u00e9" nonce), which surfaced as HTTP 500: such input is simply unequal.
    An empty or non-ASCII configured secret never matches."""
    return (isinstance(expected, str) and isinstance(given, str) and bool(expected)
            and expected.isascii() and given.isascii() and secrets.compare_digest(expected, given))


class AttemptStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._attempts: dict[str, Attempt] = {}

    def create(
        self,
        *,
        kiosk_id: str,
        flash_enabled: bool,
        flash_sequence: list[FlashStep],
        camera_label: str,
        claimed_user_id: str | None,
        recapture_of: str | None,
        recapture_count: int,
        now: datetime | None = None,
    ) -> Attempt:
        now = now or datetime.now(UTC)
        att = Attempt(
            attempt_id=f"att_{ULID()}",
            kiosk_id=kiosk_id,
            nonce=new_nonce(),
            created_at=now,
            expires_at=now + timedelta(seconds=NONCE_TTL_S),
            flash_enabled=flash_enabled,
            flash_sequence=flash_sequence,
            camera_label=camera_label,
            claimed_user_id=claimed_user_id,
            recapture_of=recapture_of,
            recapture_count=recapture_count,
        )
        with self._lock:
            self._purge(now)
            self._attempts[att.attempt_id] = att
        return att

    def get(self, attempt_id: str) -> Attempt | None:
        with self._lock:
            return self._attempts.get(attempt_id)

    def consume_nonce(self, attempt_id: str, nonce: str, now: datetime | None = None) -> Attempt:
        """Atomically validate + burn the attempt nonce (single use, TTL, constant-time compare)."""
        now = now or datetime.now(UTC)
        with self._lock:
            att = self._attempts.get(attempt_id)
            if att is None:
                raise NonceError("ATTEMPT_NOT_FOUND", "unknown attempt")
            if att.terminal:
                raise NonceError("ATTEMPT_CLOSED", "attempt already decided")
            if att.nonce_used:
                raise NonceError("NONCE_REUSED", "nonce already used")
            if not secret_equal(att.nonce, nonce):
                raise NonceError("NONCE_INVALID", "nonce does not match this attempt")
            if now > att.expires_at:
                att.nonce_used = True
                raise NonceError("NONCE_EXPIRED", "nonce expired")
            att.nonce_used = True
            att.frames_received_at = now
            return att

    def _purge(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=ATTEMPT_RETENTION_S)
        for k in [k for k, a in self._attempts.items() if a.created_at < cutoff]:
            del self._attempts[k]

    def __len__(self) -> int:
        return len(self._attempts)
