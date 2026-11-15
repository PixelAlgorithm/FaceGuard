"""§7.1 step-up challenge: issuance (random, single-use nonce) and verification (pure).

Exactly one deformation action (SMILE | OPEN_MOUTH | PUFF_CHEEKS, mandatory - eye-cut paper masks
can blink) + one of BLINK | TURN_LEFT | TURN_RIGHT, random order. Never blink-only.

KNOWN LIMITATION (audit F01, architectural, NOT fixed here): verification judges ActionEvidence that the kiosk
client measured and asserts (blendshape peaks, timings, landmark shift, same_track). The edge binds it to the
issued challenge_id / nonce / TTL and checks identity of the last challenge frame against the candidate, but it
does not itself measure the deformation or blink, nor run PAD / device / moire on the challenge frames. A modified
kiosk page or a local process on the kiosk host can therefore forge a passing challenge (the kiosk API binds
127.0.0.1 only; RBAC v2 A treats the kiosk OS account as trusted). Proper fix (RBAC v2 H, deferred): compute
landmarks / blendshapes server-side from the uploaded challenge frames bound to the nonce timing, run the
liveness stack on them, raise challenge.min_identity_cosine to the allow bar and authenticate the kiosk client.
Until then a passed CHALLENGE must not be described as server-verified liveness.
"""

from __future__ import annotations

import random
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from edge.policy.quality import finite
from edge.policy.signals import ActionEvidence, ChallengeEvidence

PASS, SOFT_FAIL, HARD_FAIL, M1_CONTRADICTION = "PASS", "SOFT_FAIL", "HARD_FAIL", "M1_CONTRADICTION"
_ABS_MIN_KEY = {"SMILE": "smile_abs_min", "OPEN_MOUTH": "jaw_open_abs_min", "PUFF_CHEEKS": "cheek_puff_abs_min"}


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    nonce: str
    actions: tuple[str, ...]
    step_window_ms: int
    min_reaction_ms: int
    issued_at: datetime
    expires_at: datetime

    def public(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "nonce": self.nonce,
            "actions": list(self.actions),
            "step_window_ms": self.step_window_ms,
            "min_reaction_ms": self.min_reaction_ms,
            "expires_at": self.expires_at.isoformat().replace("+00:00", "Z"),
        }


@dataclass(frozen=True)
class ChallengeOutcome:
    result: str
    reason: str = ""


def new_challenge(T: Any, now: datetime, rng: random.Random | None = None) -> Challenge:
    """Issue a challenge. `rng` injectable for reproducible tests; default = OS CSPRNG."""
    C = T.challenge
    r = rng or secrets.SystemRandom()
    deform = list(C.deformation_actions)
    second = list(C.secondary_actions)
    if not deform or any(a not in _ABS_MIN_KEY for a in deform):
        raise ValueError("challenge.deformation_actions must be non-empty mouth/cheek actions")
    actions = [r.choice(deform), r.choice(second)]
    r.shuffle(actions)
    if rng is None:
        nonce, cid = secrets.token_urlsafe(16), "chl_" + secrets.token_hex(6)
    else:
        nonce, cid = f"n_{rng.getrandbits(128):032x}", f"chl_{rng.getrandbits(48):012x}"
    return Challenge(
        challenge_id=cid,
        nonce=nonce,
        actions=tuple(actions),
        step_window_ms=int(C.step_window_ms),
        min_reaction_ms=int(C.min_reaction_ms),
        issued_at=now,
        expires_at=now + timedelta(seconds=float(C.session_ttl_s)),
    )


def _deformation_moved(a: ActionEvidence, C: Any, strict: bool) -> bool:
    abs_min = float(C[_ABS_MIN_KEY[a.action]])
    return finite(a.peak) and (a.peak > abs_min if strict else a.peak >= abs_min)


def _action_outcome(a: ActionEvidence, C: Any) -> tuple[str, str]:
    if a.tracking_lost:
        return HARD_FAIL, f"{a.action}: face track lost"
    if a.started_at_ms is not None and a.started_at_ms - a.prompted_at_ms < C.min_reaction_ms:
        return HARD_FAIL, f"{a.action}: response before min_reaction_ms (pre-recorded?)"
    if a.action in ("TURN_LEFT", "TURN_RIGHT") and finite(a.yaw_peak_deg):
        want = 1.0 if a.action == "TURN_LEFT" else -1.0
        delta = _yaw_delta(a)
        if delta * -want >= C.turn_yaw_min_deg:
            return HARD_FAIL, f"{a.action}: turned the wrong way (yaw delta {delta:+.1f} deg)"
    if a.started_at_ms is None or a.completed_at_ms is None:
        return SOFT_FAIL, f"{a.action}: no qualifying response"
    if a.completed_at_ms - a.prompted_at_ms > C.step_window_ms:
        return SOFT_FAIL, f"{a.action}: completed after the step window"
    if a.action in _ABS_MIN_KEY:
        rise_ok = finite(a.peak) and finite(a.baseline) and (a.peak - a.baseline) >= C.deformation_rise_min
        shift_ok = finite(a.landmark_shift) and a.landmark_shift > C.landmark_shift_min
        if not (rise_ok and _deformation_moved(a, C, strict=False) and shift_ok):
            return SOFT_FAIL, f"{a.action}: no qualifying deformation"
        return PASS, ""
    if a.action == "BLINK":
        if not (finite(a.peak) and a.peak >= C.blink_close_min):
            return SOFT_FAIL, "BLINK: eyes did not close"
        return PASS, ""  # completed_at_ms = re-open below blink_open_max (set by the client)
    want = 1.0 if a.action == "TURN_LEFT" else -1.0
    if not (finite(a.yaw_peak_deg) and _yaw_delta(a) * want >= C.turn_yaw_min_deg):
        return SOFT_FAIL, f"{a.action}: turn too small"
    return PASS, ""


def _yaw_delta(a: ActionEvidence) -> float:
    """Turn = signed peak yaw minus the yaw at the prompt (baseline); + = subject's left. Using the delta
    means a user whose neutral pose is already turned is judged on the movement, not the absolute pose."""
    return float(a.yaw_peak_deg) - (float(a.baseline) if finite(a.baseline) else 0.0)


def _m1_contradiction(ev: ChallengeEvidence, C: Any, K: Any) -> bool:
    d = ev.depth
    if d is None or not d.available or not finite(d.m1_mouth_residual_mm):
        return False
    if finite(d.m1_forehead_residual_mm) and d.m1_forehead_residual_mm > K.m1_forehead_residual_max_mm:
        return False  # rigid alignment unreliable (head moved) -> M1 not decisive
    moved = any(a.action in _ABS_MIN_KEY and _deformation_moved(a, C, strict=True) for a in ev.actions)
    return moved and d.m1_mouth_residual_mm < K.m1_mouth_residual_min_mm


def verify_challenge(challenge: Challenge, ev: ChallengeEvidence, T: Any, *, depth_enabled: bool) -> ChallengeOutcome:
    """PASS | SOFT_FAIL (no qualifying response -> retry) | HARD_FAIL | M1_CONTRADICTION (DENY MASK_CUE_RIGID)."""
    C, K = T.challenge, T.liveness.mask
    if depth_enabled and _m1_contradiction(ev, C, K):
        return ChallengeOutcome(M1_CONTRADICTION, "blendshape moved but depth stayed rigid")
    if ev.challenge_id != challenge.challenge_id or ev.nonce != challenge.nonce:
        return ChallengeOutcome(HARD_FAIL, "challenge id / nonce mismatch (replay?)")
    if [a.action for a in ev.actions] != list(challenge.actions):
        return ChallengeOutcome(HARD_FAIL, "reported actions differ from the issued challenge")
    if not ev.same_track:
        return ChallengeOutcome(HARD_FAIL, "face track changed during the challenge")
    if not finite(ev.last_frame_cosine) or ev.last_frame_cosine < C.min_identity_cosine:
        return ChallengeOutcome(HARD_FAIL, "last challenge frame does not match the candidate")
    soft = ""
    for a in ev.actions:
        result, why = _action_outcome(a, C)
        if result == HARD_FAIL:
            return ChallengeOutcome(HARD_FAIL, why)
        if result == SOFT_FAIL and not soft:
            soft = why
    return ChallengeOutcome(SOFT_FAIL, soft) if soft else ChallengeOutcome(PASS)
