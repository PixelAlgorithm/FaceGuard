"""Step-up session state machine + resolve_stepup (DECISION_POLICY §7, §9.6 rows R1-R10). Pure.

Sessions are immutable; every transition returns (new_session, Decision). The only loosening
operation in the whole policy is a STEP_UP that becomes ALLOW here after every required step passed
(P4). Schedule is never re-run; a DENY is terminal (no session is ever opened for it, P5/P8).
attempts_left = submissions still allowed for the pending step, including the next one (R15).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any

from edge.policy.challenge import HARD_FAIL, M1_CONTRADICTION, SOFT_FAIL, Challenge, verify_challenge
from edge.policy.codes import order_codes
from edge.policy.engine import (
    ALLOW,
    DENY,
    STEP_UP,
    Decision,
    NextAction,
    attempts_left_value,
    display_message,
)
from edge.policy.fallback import FallbackVerifier
from edge.policy.signals import ChallengeEvidence, FallbackSubmission

OPEN, ALLOWED, DENIED = "OPEN", "ALLOWED", "DENIED"
STEPS = ("CHALLENGE", "SECOND_FACTOR")
# DECISION_POLICY §6: trigger codes = original STEP_UP codes minus mode / retry codes.
NON_TRIGGER_CODES = frozenset({"OFFLINE_MODE", "OFFLINE_FALLBACK_REQUIRED", "CHALLENGE_FAILED", "FALLBACK_FAILED"})


class SessionClosed(Exception):
    """The attempt already reached a terminal ALLOW/DENY (API: 409 ATTEMPT_CLOSED)."""


@dataclass(frozen=True)
class StepUpSession:
    origin: Decision  # the STEP_UP decision that opened the session (its codes are the trigger codes)
    steps: tuple[str, ...]
    opened_at: datetime
    expires_at: datetime
    passed: tuple[str, ...] = ()
    challenge: Challenge | None = None
    challenge_soft_fails: int = 0
    factor_failures: int = 0
    status: str = OPEN
    fallback: Any = None
    last: Decision | None = None

    @property
    def attempt_id(self) -> str:
        return self.origin.attempt_id

    @property
    def mode(self) -> str:
        return self.origin.mode

    @property
    def trigger_codes(self) -> tuple[str, ...]:
        return self.origin.reason_codes

    @property
    def methods(self) -> tuple[str, ...]:
        return tuple(self.origin.next_action.methods or ())

    @property
    def pending_step(self) -> str | None:
        return next((s for s in self.steps if s not in self.passed), None)

    @property
    def remaining(self) -> tuple[str, ...]:
        return tuple(s for s in self.steps if s not in self.passed)


def open_session(decision: Decision, now: datetime, cfg: Any, challenge: Challenge | None) -> StepUpSession:
    T = cfg.for_mode(decision.mode)
    steps = tuple(decision.next_action.steps)
    if decision.decision != STEP_UP or not steps or any(s not in STEPS for s in steps):
        raise ValueError("a step-up session needs a STEP_UP decision with CHALLENGE/SECOND_FACTOR steps")
    if "CHALLENGE" in steps and challenge is None:
        raise ValueError("CHALLENGE step requires an issued challenge")
    s = StepUpSession(origin=decision, steps=steps, opened_at=now,
                      expires_at=now + timedelta(seconds=float(T.stepup.session_ttl_s)), challenge=challenge)
    return replace(s, last=current_decision(s, cfg))


def _left(s: StepUpSession, step: str, T: Any) -> int:
    used = s.challenge_soft_fails if step == "CHALLENGE" else s.factor_failures
    return attempts_left_value(step, used, T)


def current_decision(s: StepUpSession, cfg: Any, extra_codes: tuple[str, ...] = (), now: datetime | None = None
                     ) -> Decision:
    """STEP_UP for the pending step (R3 / R6 / R8): trigger codes (+ retry code), remaining steps."""
    T = cfg.for_mode(s.mode)
    pending = s.pending_step
    rem = s.remaining
    codes = tuple(order_codes(list(s.trigger_codes) + list(extra_codes)))
    nxt = NextAction(
        type=pending or "NONE",
        steps=rem,
        methods=s.methods if "SECOND_FACTOR" in rem else None,
        challenge=s.challenge.public() if pending == "CHALLENGE" and s.challenge else None,
        attempts_left=_left(s, pending, T) if pending else None,
    )
    stage = "challenge" if pending == "CHALLENGE" else "fallback"
    if not extra_codes and not s.passed:
        stage = s.origin.stage
    return replace(s.origin, decision=STEP_UP, reason_codes=codes, next_action=nxt, stage=stage,
                   decided_at=now or s.origin.decided_at,
                   display_message=display_message(STEP_UP, codes, s.origin.bio_result, nxt.type, s.mode))


def _terminal(s: StepUpSession, decision: str, codes: list[str], now: datetime, stage: str,
              fallback: Any = None, detail: str | None = None) -> tuple[StepUpSession, Decision]:
    if s.mode == "OFFLINE":
        codes = codes + ["OFFLINE_MODE"]
    ordered = tuple(order_codes(codes))
    nxt = NextAction("OPEN_DOOR") if decision == ALLOW else NextAction("NONE")
    d = replace(
        s.origin,
        decision=decision,
        reason_codes=ordered,
        resolved_codes=tuple(order_codes(c for c in s.trigger_codes if c not in NON_TRIGGER_CODES))
        if decision == ALLOW else (),
        next_action=nxt,
        stage=stage,
        decided_at=now,
        fallback=fallback if fallback is not None else s.fallback,
        display_message=display_message(decision, ordered, s.origin.bio_result, nxt.type, s.mode),
        detail=detail,
    )
    return replace(s, status=ALLOWED if decision == ALLOW else DENIED, last=d), d


def _check_open(s: StepUpSession, now: datetime, wall: datetime, step: str) -> tuple[StepUpSession, Decision] | None:
    """`now` = real clock (TTL is elapsed time, §2 Clocks); `wall` = edge wall clock (record stamps)."""
    if s.status != OPEN:
        raise SessionClosed(s.attempt_id)
    pending = s.pending_step
    expired = now > s.expires_at or (pending == "CHALLENGE" and s.challenge is not None
                                     and now > s.challenge.expires_at)
    if expired:  # R10: TTL counts from the STEP_UP, not from the last step
        code = "CHALLENGE_FAILED" if pending == "CHALLENGE" else "FALLBACK_FAILED"
        return _terminal(s, DENY, [code], wall, "challenge" if pending == "CHALLENGE" else "fallback")
    if pending != step:  # steps are processed strictly in order
        return _terminal(s, DENY, ["SYSTEM_ERROR"], wall, "system")
    return None


def _after_pass(s: StepUpSession, step: str, now: datetime, cfg: Any, fallback: Any = None
                ) -> tuple[StepUpSession, Decision]:
    s = replace(s, passed=s.passed + (step,), fallback=fallback if fallback is not None else s.fallback)
    if s.remaining:  # R3: next required step not yet submitted
        d = current_decision(s, cfg, now=now)
        return replace(s, last=d), d
    codes = ["ACCESS_OK"] + (["FALLBACK_OK"] if "SECOND_FACTOR" in s.passed else [])
    return _terminal(s, ALLOW, codes, now, "challenge" if step == "CHALLENGE" else "fallback")  # R1 / R2


def resolve_challenge(s: StepUpSession, ev: ChallengeEvidence, now: datetime, cfg: Any,
                      new_challenge_fn: Callable[[datetime], Challenge], wall_now: datetime | None = None
                      ) -> tuple[StepUpSession, Decision]:
    wall = wall_now or now
    early = _check_open(s, now, wall, "CHALLENGE")
    if early:
        return early
    T = cfg.for_mode(s.mode)
    challenge = s.challenge
    if challenge is None:
        return _terminal(s, DENY, ["SYSTEM_ERROR"], wall, "system")
    out = verify_challenge(challenge, ev, T, depth_enabled=bool(T.liveness.depth.enabled))
    if out.result == M1_CONTRADICTION:
        return _terminal(s, DENY, ["MASK_CUE_RIGID"], wall, "challenge", detail=out.reason)  # R5
    if out.result == HARD_FAIL:
        return _terminal(s, DENY, ["CHALLENGE_FAILED"], wall, "challenge", detail=out.reason)  # R4
    if out.result == SOFT_FAIL:
        if s.challenge_soft_fails < int(T.challenge.soft_fail_retries):  # R6: one retry, new nonce
            s = replace(s, challenge=new_challenge_fn(now), challenge_soft_fails=s.challenge_soft_fails + 1)
            d = replace(current_decision(s, cfg, extra_codes=("CHALLENGE_FAILED",), now=wall), detail=out.reason)
            return replace(s, last=d), d
        return _terminal(s, DENY, ["CHALLENGE_FAILED"], wall, "challenge", detail=out.reason)  # R7
    return _after_pass(replace(s, challenge=None), "CHALLENGE", wall, cfg)


def resolve_fallback(s: StepUpSession, sub: FallbackSubmission, now: datetime, cfg: Any,
                     verifier: FallbackVerifier, wall_now: datetime | None = None) -> tuple[StepUpSession, Decision]:
    wall = wall_now or now
    early = _check_open(s, now, wall, "SECOND_FACTOR")
    if early:
        return early
    T = cfg.for_mode(s.mode)
    ok, info = False, None
    if sub.method in s.methods:  # method not offered -> failure without verification (R8)
        res = verifier.verify(sub, s.origin.candidate_user_id, s.mode, now, wall_now=wall)
        ok, info = res.ok, res.fallback
    if not ok:
        s = replace(s, factor_failures=s.factor_failures + 1)
        if s.factor_failures < int(T.stepup.max_attempts_per_step):  # R8
            d = current_decision(s, cfg, extra_codes=("FALLBACK_FAILED",), now=wall)
            return replace(s, last=d), d
        return _terminal(s, DENY, ["FALLBACK_FAILED"], wall, "fallback")  # R9
    return _after_pass(s, "SECOND_FACTOR", wall, cfg, fallback=info)


def drop_method(s: StepUpSession, method: str, cfg: Any, now: datetime) -> tuple[StepUpSession, Decision]:
    """Stop offering `method` (e.g. EMAIL_OTP while the cloud verify is unavailable).

    Nothing is counted: failures / attempts_left are unchanged, the session TTL is untouched. The re-issued
    STEP_UP keeps the retry codes (FALLBACK_FAILED / CHALLENGE_FAILED) of the last response. Unknown method
    -> no-op; dropping the last remaining method is refused (ValueError) so a session never offers nothing."""
    if s.status != OPEN:
        raise SessionClosed(s.attempt_id)
    methods = tuple(m for m in s.methods if m != method)
    if not methods and s.methods:
        raise ValueError(f"cannot drop {method}: it is the last offered method")
    if methods != s.methods:
        s = replace(s, origin=replace(s.origin, next_action=replace(s.origin.next_action, methods=methods)))
    last = s.last or s.origin
    extra = tuple(c for c in last.reason_codes if c in ("FALLBACK_FAILED", "CHALLENGE_FAILED"))
    d = replace(current_decision(s, cfg, extra_codes=extra, now=now), stage=last.stage)
    return replace(s, last=d), d


def expire_if_due(s: StepUpSession, now: datetime) -> tuple[StepUpSession, Decision] | None:
    """Abandoned sessions: after expiry the attempt's final state is its last decision (no new DENY)."""
    if s.status == OPEN and now > s.expires_at:
        return replace(s, status=DENIED), s.last or s.origin
    return None
