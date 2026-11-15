"""iPhone TrueDepth bridge (DepthProbe app <-> edge). Gated by liveness.depth.enabled.

Flow: session/start queues a PASSIVE depth request; a STEP_UP CHALLENGE queues a CHALLENGE request
whose `delay_ms`/`interval_ms` aim the 3 captures at the deformation step (M1 needs the expression,
not the neutral face). The app long-polls GET /v1/depth/pending, captures, and POSTs
/v1/depth/frames echoing the single-use `depth_nonce`. Measurement is the depth agent's
`depth.protocol.process_upload` (D0-D4/M2; CHALLENGE also M1 vs this attempt's PASSIVE result using
face_box_norm_frames / landmarks_norm_frames). The frames handler waits at most
latency_budget_ms.depth_max_wait after the RGB frames (or the challenge submission).
Depth maps stay in RAM only and are dropped after DEPTH_TTL_S.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from edge.config import Thresholds
from edge.policy.signals import DepthSignal
from edge.session import secret_equal

log = logging.getLogger("edge.depth")
DEPTH_TTL_S = 180.0
STATUS_WINDOW_S = 30.0  # /v1/health depth_probe window + depth poll failure log rate limit
MAX_FRAMES = 3
DEFORMATION_ACTIONS = frozenset({"SMILE", "OPEN_MOUTH", "PUFF_CHEEKS"})
# Kiosk lead-in from receiving the STEP_UP to showing the first prompt (render + 200 ms neutral
# baseline). Capture scheduling estimate, not a decision threshold; DepthProbe caps delay at 3 s.
CHALLENGE_UI_LEAD_MS = 500
APP_MAX_DELAY_MS = 3000
CAPTURE_UPLOAD_MARGIN_MS = 2000


def challenge_capture_timing(actions: list[str], step_window_ms: int, min_reaction_ms: int) -> tuple[int, int]:
    """(delay_ms, interval_ms) so that 3 depth frames span the deformation step's response window."""
    k = next((i for i, a in enumerate(actions) if a in DEFORMATION_ACTIONS), 0)
    delay = min(APP_MAX_DELAY_MS, CHALLENGE_UI_LEAD_MS + k * int(step_window_ms) + int(min_reaction_ms))
    interval = max(100, (int(step_window_ms) - int(min_reaction_ms)) // MAX_FRAMES)
    return delay, interval


@dataclass
class DepthRequest:
    attempt_id: str
    phase: str
    frames: int
    deadline_ms: int
    delay_ms: int | None = None
    interval_ms: int | None = None
    claimed: bool = False
    depth_nonce: str = field(default_factory=lambda: "dn_" + secrets.token_urlsafe(16))
    nonce_used: bool = False

    def public(self) -> dict[str, Any]:
        out: dict[str, Any] = {"attempt_id": self.attempt_id, "phase": self.phase, "frames": self.frames,
                               "deadline_ms": self.deadline_ms, "depth_nonce": self.depth_nonce}
        if self.delay_ms is not None:
            out["delay_ms"] = self.delay_ms
        if self.interval_ms is not None:
            out["interval_ms"] = self.interval_ms
        return out


@dataclass
class _Stored:
    signal: DepthSignal
    result: Any  # depth.protocol.DepthResult (holds the fused depth map in RAM for M1)
    at: float = field(default_factory=time.monotonic)


class DepthBridge:
    def __init__(self, thresholds: Thresholds) -> None:
        self.th = thresholds
        self.enabled = bool(thresholds.get("liveness.depth.enabled", False))
        self.max_wait_ms = float(thresholds.get("latency_budget_ms.depth_max_wait"))
        self._pending: deque[DepthRequest] = deque()
        self._cond = asyncio.Condition()
        self._stored: dict[tuple[str, str], _Stored] = {}
        self._arrived: dict[tuple[str, str], asyncio.Event] = {}
        self._issued: dict[tuple[str, str], DepthRequest] = {}
        self.last_seen_device_at: float | None = None
        self.last_rejected_token_at: float | None = None  # last depth call refused for a bad X-Depth-Token
        self._poll_log_at: dict[int, float] = {}  # status -> monotonic time of the last logged failure
        self._poll_log_suppressed: dict[int, int] = {}

    def status(self) -> str:
        """`rejected_token` if the latest depth call within the last 30 s was refused for a bad X-Depth-Token
        (DepthProbe is polling with the wrong token), else `connected` if DepthProbe polled within the last
        30 s with a valid token, else `unavailable`."""
        now = time.monotonic()
        rej, seen = self.last_rejected_token_at, self.last_seen_device_at
        if rej is not None and now - rej < STATUS_WINDOW_S and (seen is None or rej >= seen):
            return "rejected_token"
        if seen and now - seen < STATUS_WINDOW_S:
            return "connected"
        return "unavailable"

    def note_rejected_token(self) -> None:
        self.last_rejected_token_at = time.monotonic()

    def note_poll_failure(self, status: int, client: str | None) -> bool:
        """Log a non-2xx GET /v1/depth/pending at most once per STATUS_WINDOW_S per status code (with the
        number of suppressed repeats). Never logs the token or any header. Returns True if it logged."""
        now = time.monotonic()
        last = self._poll_log_at.get(status)
        if last is not None and now - last < STATUS_WINDOW_S:
            self._poll_log_suppressed[status] = self._poll_log_suppressed.get(status, 0) + 1
            return False
        self._poll_log_at[status] = now
        repeats = self._poll_log_suppressed.pop(status, 0)
        hint = " (bad or missing X-Depth-Token: check DEPTH_DEVICE_TOKEN in the DepthProbe app)" if status == 401 else ""
        log.warning("depth poll GET /v1/depth/pending -> HTTP %d from %s%s; %d similar in the last %.0f s",
                    status, client or "?", hint, repeats, STATUS_WINDOW_S)
        return True

    def consume_nonce(self, attempt_id: str, phase: str, depth_nonce: str | None) -> bool:
        """Single-use depth nonce issued by /v1/depth/pending for exactly this attempt + phase."""
        req = self._issued.get((attempt_id, phase))
        if req is None or req.nonce_used or not secret_equal(req.depth_nonce, depth_nonce):
            return False
        req.nonce_used = True
        return True

    def _event(self, key: tuple[str, str]) -> asyncio.Event:
        if key not in self._arrived:
            self._arrived[key] = asyncio.Event()
        return self._arrived[key]

    def _gc(self) -> None:
        now = time.monotonic()
        for key in [k for k, v in self._stored.items() if now - v.at > DEPTH_TTL_S]:
            self._stored.pop(key, None)
            self._arrived.pop(key, None)
            self._issued.pop(key, None)
        now_ms = int(time.time() * 1000)
        while self._pending and self._pending[0].deadline_ms < now_ms - 5000:
            self._pending.popleft()

    async def request(self, attempt_id: str, phase: str, window_ms: int, frames: int = MAX_FRAMES, *,
                      delay_ms: int | None = None, interval_ms: int | None = None) -> bool:
        if not self.enabled:
            return False
        self._gc()
        n = max(1, min(frames, MAX_FRAMES))
        span = int(window_ms) + int(delay_ms or 0) + int(interval_ms or 0) * (n - 1)
        deadline = int(time.time() * 1000) + span + CAPTURE_UPLOAD_MARGIN_MS + int(self.max_wait_ms)
        key = (attempt_id, phase)
        if phase == "CHALLENGE":  # a (re-)issued challenge invalidates any earlier CHALLENGE capture
            self._stored.pop(key, None)
            self._arrived.pop(key, None)
            self._issued.pop(key, None)
            self._pending = deque(r for r in self._pending if (r.attempt_id, r.phase) != key)
        self._event(key)
        async with self._cond:
            self._pending.append(DepthRequest(attempt_id, phase, n, deadline, delay_ms, interval_ms))
            self._cond.notify_all()
        return True

    async def next_pending(self, wait_s: float) -> DepthRequest | None:
        self.last_seen_device_at = time.monotonic()
        end = time.monotonic() + max(0.0, min(wait_s, 30.0))
        async with self._cond:
            while True:
                now_ms = int(time.time() * 1000)
                for req in self._pending:
                    if not req.claimed and req.deadline_ms >= now_ms:
                        req.claimed = True
                        self._issued[(req.attempt_id, req.phase)] = req
                        return req
                remaining = end - time.monotonic()
                if remaining <= 0:
                    return None
                try:
                    await asyncio.wait_for(self._cond.wait(), timeout=remaining)
                except TimeoutError:
                    return None

    def submit(self, meta_raw: str | bytes, blobs: list[bytes], face_box_norm: list[float] | None,
               landmarks_norm: dict[str, list[float]] | None) -> DepthSignal:
        """Measure + store one upload (CPU work: call from a worker). Raises
        depth.protocol.DepthProtocolError for malformed input (-> 422)."""
        from depth.protocol import parse_meta, process_upload

        self.last_seen_device_at = time.monotonic()
        meta = parse_meta(meta_raw)
        if face_box_norm is not None and meta.get("face_box_norm") is None:
            meta["face_box_norm"] = face_box_norm  # located by the edge on rgb_0
        if landmarks_norm is not None and meta.get("landmarks_norm") is None:
            meta["landmarks_norm"] = landmarks_norm
        neutral = None
        if meta["phase"] == "CHALLENGE":
            stored = self._stored.get((meta["attempt_id"], "PASSIVE"))
            neutral = stored.result if stored else None
        res = process_upload(json.dumps(meta), blobs, self.th, neutral=neutral)
        sig = DepthSignal(**{k: res.signal.get(k) for k in DepthSignal.model_fields if k in res.signal})
        log.info("depth %s/%s: available=%s m1=%s reason=%s %.1f ms", res.attempt_id, res.phase, sig.available,
                 sig.m1_mouth_residual_mm, res.diag.get("reason"), res.compute_ms)
        self._stored[(res.attempt_id, res.phase)] = _Stored(signal=sig, result=res)
        return sig

    def mark_arrived(self, attempt_id: str, phase: str) -> None:
        self._event((attempt_id, phase)).set()

    async def wait_for(self, attempt_id: str, phase: str, timeout_s: float) -> DepthSignal | None:
        if not self.enabled:
            return None
        key = (attempt_id, phase)
        stored = self._stored.get(key)
        if stored is not None:
            return stored.signal
        try:
            await asyncio.wait_for(self._event(key).wait(), timeout=max(0.0, timeout_s))
        except TimeoutError:
            return None
        stored = self._stored.get(key)
        return stored.signal if stored else None

    def drop(self, attempt_id: str) -> None:
        for phase in ("PASSIVE", "CHALLENGE"):
            self._stored.pop((attempt_id, phase), None)
            self._arrived.pop((attempt_id, phase), None)
            self._issued.pop((attempt_id, phase), None)
