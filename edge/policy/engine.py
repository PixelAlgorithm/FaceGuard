"""Policy engine: evaluate(signals, schedule_ctx, mode, now) -> Decision (docs/DECISION_POLICY.md .2).

Pure and deterministic: no I/O, no clock reads (`now` = edge wall clock, injected), randomness only via
the injected `rng` (consulted once, only for a would-be ALLOW -- P12). Any exception -> DENY +
SYSTEM_ERROR (P1). Order: M mode resolution -> 0 rate limit -> 1 quality (A2 / A3 / A6) -> 2 injection
-> (P7 cloud flip) -> 3 liveness + 4 identity -> 5 biometric result -> 6 schedule -> 7/8 combine ->
8b random challenge. Wire shape: docs/API.md v1.1 DecisionResponse.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

from edge.policy import identity as _identity
from edge.policy import liveness as _liveness
from edge.policy.codes import (
    CONTACT_DESK_CODES,
    DENY_TYPE,
    SCHED_CODE,
    SCHEDULE_RESULTS,
    dedupe,
    order_codes,
)
from edge.policy.injection import injection_check
from edge.policy.quality import quality_gate
from edge.policy.schedule import cache_state, evaluate_schedule, kiosk_zone, zone_risk
from edge.policy.signals import AttemptSignals
from edge.policy.thresholds import MODES, RISK_LEVELS

ALLOW, STEP_UP, DENY = "ALLOW", "STEP_UP", "DENY"
BIO_PASS, BIO_UNSURE, BIO_FAIL = "BIO_PASS", "BIO_UNSURE", "BIO_FAIL"
DECISION_RANK = {ALLOW: 0, STEP_UP: 1, DENY: 2}
UNKNOWN_ZONE = "UNKNOWN"

# Stage functions are looked up through the module so tests can inject failures (Q11 / P08).
liveness_fusion = _liveness.liveness_fusion
identity_match = _identity.identity_match

SCORE_KEYS = ("pad_mean", "pad_pass_frames", "flash_r", "flash_amp", "moire", "device_conf", "depth", "mask",
              "match_local", "match_margin", "rekognition", "rekognition_runner_up", "signals")
# scores.signals: per-signal status {pad, device, moire, flash, mask, depth, injection} -> PASS | PASS_AMBIENT |
# UNSURE | FAIL | NOT_AVAILABLE | ADVISORY_<zone> (lead 2026-11-14, operator view); null if liveness never ran.
LATENCY_KEYS = ("total", "liveness", "match", "schedule", "policy")
HINTS = {"MULTIPLE_FACES": "one_person", "QUALITY_LOW_LIGHT": "more_light", "QUALITY_BLUR": "hold_still",
         "QUALITY_POSE": "face_camera", "QUALITY_DEPTH_INVALID": "move_closer"}

GENERIC_DESK_MESSAGE = "Access not available - please contact the desk"
_MESSAGES = {
    "MULTIPLE_FACES": "One person at a time, please",
    "QUALITY_LOW_LIGHT": "More light needed - please face the light",
    "QUALITY_BLUR": "Please hold still",
    "QUALITY_POSE": "Please look straight at the camera",
    "QUALITY_DEPTH_INVALID": "Please step back slightly and try again",
    "INJECTION_VIRTUAL_CAMERA": "Camera not trusted",
    "SCHEDULE_OUTSIDE_WINDOW": "Outside your access hours",
    "SCHEDULE_HOLIDAY": "Campus closed today",
    "SYSTEM_ERROR": GENERIC_DESK_MESSAGE,
}


@dataclass(frozen=True)
class ScheduleCtx:
    """Schedule inputs: the newest VERIFIED bundle (the last valid bundle) and its refresh age.

    `refresh_age_s` = real elapsed seconds since the cloud last refreshed/confirmed the bundle
    (None = never) -- §5.1. Only a verified bundle is ever used (R6 / P5)."""

    kiosk_id: str
    bundle: Mapping[str, Any] | None
    signature_valid: bool
    extra_revocations: tuple[Mapping[str, Any], ...] = ()  # deny-only revocation feed overlay
    zone: str | None = None  # override; default = bundle.kiosks[kiosk_id].zone
    confirmed_at: datetime | None = None
    refresh_age_s: float | None = None

    @property
    def lvb(self) -> Mapping[str, Any] | None:
        return self.bundle if (self.bundle and self.signature_valid) else None


@dataclass(frozen=True)
class NextAction:
    type: str
    steps: tuple[str, ...] = ()
    methods: tuple[str, ...] | None = None
    challenge: Mapping[str, Any] | None = None
    attempts_left: int | None = None
    retry_after_s: int | None = None
    hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "steps": list(self.steps),
            "methods": list(self.methods) if self.methods is not None else None,
            "challenge": dict(self.challenge) if self.challenge is not None else None,
            "attempts_left": self.attempts_left,
            "retry_after_s": self.retry_after_s,
            "hint": self.hint,
        }


@dataclass(frozen=True)
class Combined:
    decision: str
    codes: list[str]
    steps: list[str]
    methods: list[str] | None


@dataclass(frozen=True)
class Decision:
    attempt_id: str
    kiosk_id: str
    zone: str | None
    decision: str
    reason_codes: tuple[str, ...]
    next_action: NextAction
    mode: str
    stage: str
    policy_version: str
    t0: datetime | None = None
    decided_at: datetime | None = None
    resolved_codes: tuple[str, ...] = ()
    bio_result: str | None = None
    schedule_result: str | None = None
    cache_state: str | None = None
    candidate_user_id: str | None = None
    candidate_display: str | None = None
    candidate_role: str | None = None
    causes: frozenset[str] = frozenset()
    scores: Mapping[str, Any] = field(default_factory=dict)
    bundle_version: int | None = None
    display_message: str = ""
    cloud_miss: bool = False
    rng_draws: int = 0
    fallback: Mapping[str, Any] | None = None  # log-only: method / staff_id / code_id (never code values)
    detail: str | None = None  # internal diagnostics (never shown / logged)

    @property
    def user_id(self) -> str | None:
        """Pseudonymous user for the log: the candidate unless biometrics failed / were skipped."""
        return self.candidate_user_id if self.bio_result in (BIO_PASS, BIO_UNSURE) else None

    def to_response(self, latency_ms: Mapping[str, int] | None = None) -> dict[str, Any]:
        show = self.bio_result in (BIO_PASS, BIO_UNSURE) and self.candidate_user_id
        lat = {k: 0 for k in LATENCY_KEYS}
        lat.update({k: int(v) for k, v in (latency_ms or {}).items() if k in LATENCY_KEYS})
        return {
            "attempt_id": self.attempt_id,
            "kiosk_id": self.kiosk_id,
            "zone": self.zone or UNKNOWN_ZONE,
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "resolved_codes": list(self.resolved_codes),
            "next_action": self.next_action.to_dict(),
            "bio_result": self.bio_result,
            "schedule_result": self.schedule_result,
            "mode": self.mode,
            "cache_state": self.cache_state,
            "candidate": {"user_id": self.candidate_user_id,
                          "display": self.candidate_display or self.candidate_user_id,
                          "role": self.candidate_role} if show else None,
            "scores": _round_scores(self.scores),
            "latency_ms": lat,
            "policy_version": self.policy_version,
            "bundle_version": self.bundle_version,
            "display_message": self.display_message,
            "stage": self.stage,
        }


def _round_scores(scores: Mapping[str, Any], nd: int = 3) -> dict[str, Any]:
    def r(v: Any) -> Any:
        if isinstance(v, bool) or v is None:
            return v
        if isinstance(v, float):
            return round(v, nd) if math.isfinite(v) else None
        if isinstance(v, Mapping):
            return {k: r(x) for k, x in v.items()}
        return v

    out: dict[str, Any] = {k: None for k in SCORE_KEYS}
    out["mask"] = {}
    out.update({k: r(v) for k, v in scores.items() if k in SCORE_KEYS})
    if out["mask"] is None:
        out["mask"] = {}
    return out


# ---------------------------------------------------------------- pure building blocks
def biometric_result(live: Any, ident: Any, strong_deny_count: int = 2) -> tuple[str, list[str], set[str]]:
    """§4. Returns (bio, codes, causes)."""
    strong_deny = len(live.strong_mask_codes) >= strong_deny_count
    if live.hard_codes or strong_deny:
        codes = list(live.hard_codes) + (list(live.strong_mask_codes) if strong_deny else [])
        if ident.status == "FAIL":
            codes.append("NOT_ENROLLED")
        return BIO_FAIL, dedupe(codes), set()
    if ident.status == "FAIL":
        return BIO_FAIL, ["NOT_ENROLLED"], set()
    causes: set[str] = set()
    codes: list[str] = []
    if live.status == "UNSURE" or live.mask_codes:
        causes.add("LIVENESS")
        codes += list(live.mask_codes) + list(live.unsure_codes)
    if ident.status == "UNSURE":
        causes.add("MATCH")
        codes += list(ident.codes)
    if causes:
        return BIO_UNSURE, dedupe(codes), causes
    return BIO_PASS, [], set()


def is_high(risk: str | None, mode: str, T: Any) -> bool:
    """§8.2 rules 4-5; unknown risk is treated as high."""
    r = risk if risk in RISK_LEVELS else "high"
    if mode == "OFFLINE":
        return r == "high" or RISK_LEVELS[r] > RISK_LEVELS[T.offline.auto_allow_max_risk]
    return r == "high"


def _methods(T: Any, key: str) -> list[str]:
    methods = list(T.stepup.methods[key])
    if not bool(T.fallback.email_otp.get("enabled", True)):
        methods = [m for m in methods if m != "EMAIL_OTP"]  # SES denied -> simply not offered
    return methods


def candidate_methods(methods: Sequence[str], bundle: Mapping[str, Any] | None, user_id: str | None) -> list[str]:
    """Second-factor methods the candidate can actually complete, per its VERIFIED bundle entry: TOTP only with
    `fallback.totp_enrolled`, CARD only with a `fallback.card_id_hash` (the verifier's own gates). Filtering only
    removes methods (order kept, never adds one); if it would leave nothing, the configured list stays so a
    step-up never offers [] (same rule as stepup.drop_method)."""
    users = (bundle or {}).get("users") if isinstance(bundle, Mapping) else None
    u = users.get(user_id) if isinstance(users, Mapping) and user_id else None
    fb = u.get("fallback") if isinstance(u, Mapping) else None
    fb = fb if isinstance(fb, Mapping) else {}
    card = fb.get("card_id_hash")
    drop = set()
    if not fb.get("totp_enrolled"):
        drop.add("TOTP")
    if not (isinstance(card, str) and card):
        drop.add("CARD")
    out = [m for m in methods if m not in drop]
    return out or list(methods)


def combine(bio: str, bio_codes: Sequence[str], causes: set[str], sched: str | None, cache: str,
            risk: str | None, mode: str, T: Any, *, lvb: bool = True) -> Combined:
    """Matrix §9.2-9.5 for bio in {BIO_PASS, BIO_UNSURE}. Pure; `T` = thresholds for `mode`.

    `lvb` = a last valid (verified) bundle exists; none -> DENY SCHEDULE_BUNDLE_INVALID (lead R6)."""
    if bio not in (BIO_PASS, BIO_UNSURE):
        raise ValueError(f"combine() needs BIO_PASS/BIO_UNSURE, got {bio!r}")
    off = mode == "OFFLINE"
    om = ["OFFLINE_MODE"] if off else []
    if not lvb:  # never use data from an unverified bundle; unknown zone = high risk
        return Combined(DENY, dedupe(list(bio_codes) + ["SCHEDULE_BUNDLE_INVALID"] + om), [], None)
    if off and cache == "INVALID":  # verified bundle but clock rolled back: no schedule, staff override only
        steps = (["CHALLENGE"] if "LIVENESS" in causes else []) + ["SECOND_FACTOR"]
        return Combined(STEP_UP, dedupe(list(bio_codes) + ["SCHEDULE_BUNDLE_INVALID"] + om +
                                        ["OFFLINE_FALLBACK_REQUIRED"]), steps, _methods(T, "cache_untrusted"))
    if sched not in SCHEDULE_RESULTS:
        raise ValueError(f"unknown schedule result {sched!r}")
    high = is_high(risk, mode, T) and (off or bool(T.schedule.high_risk_requires_stepup_online))
    exp = ["SCHEDULE_EXPIRED_CACHE"] if off and cache == "EXPIRED" else []
    s_code = [SCHED_CODE[sched]] if sched in SCHED_CODE else []
    if sched in DENY_TYPE:  # stale data may deny (P5)
        return Combined(DENY, dedupe(list(bio_codes) + s_code + exp + om), [], None)
    if bio == BIO_UNSURE and sched != "IN_WINDOW":  # two uncertainties -> DENY (SC1.4)
        return Combined(DENY, dedupe(list(bio_codes) + s_code + exp + om), [], None)
    if bio == BIO_PASS and sched == "IN_WINDOW" and not high:
        if not off:
            return Combined(ALLOW, ["ACCESS_OK"], [], None)  # N1
        if not exp:
            return Combined(ALLOW, ["ACCESS_OK"] + om, [], None)  # F1
    steps = ["CHALLENGE"] if "LIVENESS" in causes else []
    codes = list(bio_codes) + s_code
    if high:
        codes.append("OFFLINE_HIGH_RISK_ZONE" if off else "SCHEDULE_HIGH_RISK_ZONE")
    if "MATCH" in causes or sched == "GRACE_WINDOW" or high or off:
        steps.append("SECOND_FACTOR")
    codes += exp + om + (["OFFLINE_FALLBACK_REQUIRED"] if off and "SECOND_FACTOR" in steps else [])
    methods = None
    if "SECOND_FACTOR" in steps:
        if exp:
            key = "cache_untrusted"
        elif off:
            key = "offline_high_risk" if high else "offline_default"
        else:
            key = "online_high_risk" if high else "online_default"
        methods = _methods(T, key)
    if not steps:
        raise ValueError("STEP_UP without steps")
    return Combined(STEP_UP, dedupe(codes), steps, methods)


def contact_desk(codes: Sequence[str], bio: str | None) -> bool:
    """DENY for a probably-legitimate person -> human help; spoofs / OUTSIDE / HOLIDAY -> NONE."""
    return bio == BIO_UNSURE or any(c in CONTACT_DESK_CODES for c in codes)


def attempts_for(step: str, T: Any) -> int:
    """Total submissions allowed for a step: CHALLENGE 1 + soft_fail_retries, SECOND_FACTOR max_attempts."""
    if step == "CHALLENGE":
        return 1 + int(T.challenge.soft_fail_retries)
    return int(T.stepup.max_attempts_per_step)


def attempts_left_value(step: str, used: int, T: Any) -> int:
    """Lead R15 ("including_next"): submissions still allowed incl. the next one (2, then 1).
    DECISION_POLICY §7 / API.md ("retries_after"): further failures tolerated (1, then 0)."""
    left = attempts_for(step, T) - used
    if str(T.stepup.get("attempts_left_semantics", "retries_after")) == "retries_after":
        left -= 1
    return max(0, left)


def initial_attempts_left(steps: Sequence[str], T: Any) -> int | None:
    return attempts_left_value(steps[0], 0, T) if steps else None


def display_message(decision: str, codes: Sequence[str], bio: str | None, next_type: str, mode: str,
                    retry_after_s: int | None = None) -> str:
    if decision == DENY and bio == BIO_UNSURE:
        return GENERIC_DESK_MESSAGE  # no schedule detail for an unconfirmed identity (§10)
    if decision == ALLOW:
        return "Access granted" + (" (offline mode)" if mode == "OFFLINE" else "")
    if "RATE_LIMITED" in codes:
        return f"Too many attempts - please wait {retry_after_s} s" if retry_after_s else "Too many attempts"
    if next_type == "RECAPTURE":
        return _MESSAGES.get(next((c for c in codes if c in HINTS), ""), "Please try again")
    if next_type == "CHALLENGE":
        return "Please follow the on-screen check"
    if next_type == "SECOND_FACTOR":
        if any(c in HINTS for c in codes):
            return "Please see the desk staff for a manual check"
        return ("Offline: please verify with your code or a staff member" if mode == "OFFLINE"
                else "Please verify your identity")
    if next_type == "CONTACT_DESK":
        return GENERIC_DESK_MESSAGE
    return next((_MESSAGES[c] for c in codes if c in _MESSAGES), "Access denied")


def _stage_for(decision: str, codes: Sequence[str], bio: str | None, causes: set[str]) -> str:
    """API.md v1.1 Stage: precheck|quality|injection|liveness|match|schedule|mode|challenge|fallback|final|system."""
    if decision == ALLOW:
        return "final"
    cs = set(codes)
    if bio == BIO_FAIL:
        return "match" if cs <= {"NOT_ENROLLED", "OFFLINE_MODE"} else "liveness"
    if cs & {"SCHEDULE_BUNDLE_INVALID", "SCHEDULE_EXPIRED_CACHE", "OFFLINE_HIGH_RISK_ZONE"}:
        return "mode"
    if cs & (set(SCHED_CODE.values()) | {"SCHEDULE_HIGH_RISK_ZONE"}):
        return "schedule"
    if "LIVENESS" in causes or "RANDOM_CHALLENGE" in cs:
        return "liveness"
    if "MATCH" in causes:
        return "match"
    return "mode"


def online_bundle_ok(ctx: ScheduleCtx, now: datetime, T: Any) -> bool:
    """§5.1 / §9.0: ONLINE needs a verified bundle, cache FRESH, refresh age <= online_max_bundle_age_min."""
    lvb = ctx.lvb
    if not lvb or cache_state(lvb, True, now, T.cache) != "FRESH":
        return False
    age = ctx.refresh_age_s
    return age is not None and 0 <= age <= float(T.schedule.online_max_bundle_age_min) * 60.0


# ---------------------------------------------------------------- evaluate
def evaluate(signals: AttemptSignals, schedule_ctx: ScheduleCtx, mode: str, now: datetime, *, cfg: Any,
             rate_limit_retry_s: float | None = None, rng: Any = None) -> Decision:
    """The decision for one attempt. Never raises: any exception -> DENY + SYSTEM_ERROR (P1 / P08).

    `mode` = connectivity mode (SYNCING / forced -> pass OFFLINE). `rate_limit_retry_s` = seconds left of
    an active kiosk lockout (None = not locked). `rng.random()` is called at most once (8b)."""
    counter = _CountingRng(rng)
    try:
        d = _evaluate(signals, schedule_ctx, mode, now, cfg, rate_limit_retry_s, counter)
    except Exception as exc:  # noqa: BLE001 - fail-secure boundary
        d = system_error(signals, schedule_ctx, mode, now, cfg, detail=f"{type(exc).__name__}: {exc}")
    return replace(d, rng_draws=counter.calls)


class _CountingRng:
    def __init__(self, rng: Any) -> None:
        self.rng, self.calls = rng, 0
        self.forced = rng is not None and getattr(rng, "forced", False) is True

    def random(self) -> float:
        self.calls += 1
        if self.calls > 1:
            raise RuntimeError("random challenge RNG consulted more than once (P12)")
        return float(self.rng.random())


def _bundle_for_eval(ctx: ScheduleCtx) -> Mapping[str, Any]:
    b = ctx.lvb or {}
    if not ctx.extra_revocations:
        return b
    merged = dict(b)
    merged["revocations"] = list(b.get("revocations") or []) + list(ctx.extra_revocations)
    return merged


def user_meta(bundle: Mapping[str, Any] | None, user_id: str | None) -> tuple[str | None, str | None]:
    """(display, role) of a user from a VERIFIED bundle; (None, None) if unknown."""
    if not user_id or not bundle:
        return None, None
    u = (bundle.get("users") or {}).get(user_id)
    if not isinstance(u, Mapping):
        return None, None
    return u.get("display"), u.get("role")


def _display_name(ctx: ScheduleCtx, user_id: str | None) -> str | None:
    return user_meta(ctx.lvb, user_id)[0]


def _bundle_version(ctx: ScheduleCtx) -> int | None:
    v = (ctx.lvb or {}).get("bundle_version")
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _evaluate(signals: AttemptSignals, ctx: ScheduleCtx, mode: str, now: datetime, cfg: Any,
              retry_s: float | None, rng: _CountingRng) -> Decision:
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}")
    if now.tzinfo is None or signals.t0.tzinfo is None:
        raise ValueError("now and t0 must be timezone-aware")
    if signals.kiosk_id != ctx.kiosk_id:
        raise ValueError("attempt kiosk_id does not match the schedule context")
    lvb = ctx.lvb
    zone = ctx.zone or kiosk_zone(lvb, ctx.kiosk_id)  # zone / risk only ever from a verified bundle
    # M. mode resolution (§8.1 / §9.0): a stale or unusable online bundle makes the attempt OFFLINE (P7)
    if mode == "ONLINE" and not online_bundle_ok(ctx, now, cfg.for_mode("ONLINE")):
        mode = "OFFLINE"  # MO2 / MO3 -- not a heartbeat miss
    T = cfg.for_mode(mode)
    cache = cache_state(lvb, True, now, T.cache) if lvb else "INVALID"
    risk = zone_risk(lvb, zone) if (lvb and zone) else None
    base = {"attempt_id": signals.attempt_id, "kiosk_id": signals.kiosk_id, "zone": zone, "t0": signals.t0,
                "decided_at": now, "policy_version": cfg.policy_version, "bundle_version": _bundle_version(ctx)}

    def finish(decision: str, codes: Sequence[str], nxt: NextAction, *, mode_: str, stage: str,
               **kw: Any) -> Decision:
        codes = list(codes)
        if mode_ == "OFFLINE" and "OFFLINE_MODE" not in codes:
            codes.append("OFFLINE_MODE")
        ordered = tuple(order_codes(codes))
        if not ordered:  # P9 -- explicit check, never an assert (R14)
            raise ValueError("P9: empty reason codes")
        msg = display_message(decision, ordered, kw.get("bio_result"), nxt.type, mode_, nxt.retry_after_s)
        return Decision(decision=decision, reason_codes=ordered, next_action=nxt, mode=mode_, stage=stage,
                        display_message=msg, **base, **kw)

    # 0. rate limit (P11: only attack evidence arms it -- see edge/policy/ratelimit.py)
    if bool(T.rate_limit.enabled) and retry_s is not None and retry_s > 0:
        return finish(DENY, ["RATE_LIMITED"], NextAction("NONE", retry_after_s=max(1, math.ceil(retry_s))),
                      mode_=mode, stage="precheck")
    # 1. quality gate
    q = quality_gate(signals.frames, signals.depth, T)
    if q.codes:
        if signals.recapture_count < T.quality.max_recaptures:  # A2
            left = int(T.quality.max_recaptures) - signals.recapture_count
            if str(T.stepup.get("attempts_left_semantics", "retries_after")) == "retries_after":
                left -= 1  # 0 = this recapture is the last one (Q22)
            return finish(STEP_UP, q.codes, NextAction("RECAPTURE", attempts_left=left, hint=HINTS[q.codes[0]]),
                          mode_=mode, stage="quality")
        # quality exhausted: injection first (A4), then desk (A6, high risk) or manual review (A3)
        if injection_check(signals.camera, signals.frames, T) == "FAIL":
            return finish(DENY, ["INJECTION_VIRTUAL_CAMERA"], NextAction("NONE"), mode_=mode, stage="injection")
        if is_high(risk, mode, T):
            return finish(DENY, q.codes, NextAction("CONTACT_DESK"), mode_=mode, stage="quality", cache_state=cache)
        codes = list(q.codes) + (["OFFLINE_FALLBACK_REQUIRED"] if mode == "OFFLINE" else [])
        steps = ("SECOND_FACTOR",)
        return finish(STEP_UP, codes, NextAction("SECOND_FACTOR", steps=steps,
                                                 methods=tuple(_methods(T, "quality_exhausted")),
                                                 attempts_left=initial_attempts_left(steps, T)),
                      mode_=mode, stage="quality", cache_state=cache)
    # 2. injection (timing judged on all submitted frames)
    inj = injection_check(signals.camera, signals.frames, T)
    if inj == "FAIL":
        return finish(DENY, ["INJECTION_VIRTUAL_CAMERA"], NextAction("NONE"), mode_=mode, stage="injection")
    # P7: a failed / missing Rekognition call makes the whole attempt OFFLINE (and is a heartbeat miss)
    cloud_miss = False
    rek_enabled = bool(T.match.rekognition.enabled)
    cm = signals.cloud_match
    if mode == "ONLINE" and rek_enabled and (cm is None or not cm.ok):
        mode, cloud_miss = "OFFLINE", True
        T = cfg.for_mode(mode)
        cache = cache_state(lvb, True, now, T.cache) if lvb else "INVALID"
    # 3 + 4 -- pure, on the same raw scores with the effective mode's thresholds
    live = liveness_fusion(q.usable, signals, inj, T, mode)
    if mode == "ONLINE" and rek_enabled:
        ident = identity_match(q.usable, cm, T, "ONLINE", signals.template_cache_age_h)
    else:  # offline, or Rekognition disabled online: local matcher with the offline bars (§3.5)
        ident = identity_match(q.usable, None, cfg.for_mode("OFFLINE"), "OFFLINE", signals.template_cache_age_h)
    scores = {**live.scores, **ident.scores, "signals": dict(live.signals)}
    # 5. biometric result
    bio, bio_codes, causes = biometric_result(live, ident, int(T.liveness.mask.strong_cue_deny_count))
    common = {"scores": scores, "cloud_miss": cloud_miss, "candidate_user_id": ident.user_id, "bio_result": bio,
                  "causes": frozenset(causes)}
    if bio == BIO_FAIL:
        nxt = "CONTACT_DESK" if bio_codes == ["NOT_ENROLLED"] else "NONE"
        return finish(DENY, bio_codes, NextAction(nxt), mode_=mode,
                      stage=_stage_for(DENY, bio_codes, bio, causes), **common)
    user = ident.user_id
    if not user:
        raise ValueError("no candidate identity for a non-failing biometric result")
    # 6. schedule (SC1): same function, newest verified bundle, both modes; t0 in Asia/Kolkata
    sched: str | None = None
    if lvb and cache != "INVALID":
        if not zone:
            raise ValueError(f"kiosk {ctx.kiosk_id} has no zone in the bundle")
        sched = evaluate_schedule(user, zone, signals.t0, _bundle_for_eval(ctx), T.schedule)
    # 7 + 8. mode restrictions + final decision
    comb = combine(bio, bio_codes, causes, sched, cache, risk, mode, T, lvb=bool(lvb))
    # 8b. random deformation challenge: only a would-be ALLOW, exactly one draw (P12). A forced draw (runtime
    # FORCE / FORCE_NEXT demo control) bypasses the configured rate, including 0.0.
    if comb.decision == ALLOW and rng.rng is not None and (rng.random() < float(T.challenge.random_rate)
                                                           or rng.forced):
        comb = Combined(STEP_UP, ["RANDOM_CHALLENGE"] + (["OFFLINE_MODE"] if mode == "OFFLINE" else []),
                        ["CHALLENGE"], None)
    if comb.decision == STEP_UP:
        methods = candidate_methods(comb.methods, lvb, user) if comb.methods is not None else None
        nxt = NextAction(comb.steps[0], steps=tuple(comb.steps),
                         methods=tuple(methods) if methods is not None else None,
                         attempts_left=initial_attempts_left(comb.steps, T))
    elif comb.decision == ALLOW:
        nxt = NextAction("OPEN_DOOR")
    else:
        nxt = NextAction("CONTACT_DESK" if contact_desk(comb.codes, bio) else "NONE")
    return finish(comb.decision, comb.codes, nxt, mode_=mode, stage=_stage_for(comb.decision, comb.codes, bio, causes),
                  schedule_result=sched, cache_state=cache, candidate_display=_display_name(ctx, user),
                  candidate_role=user_meta(ctx.lvb, user)[1], **common)


def system_error(signals: Any, ctx: Any, mode: Any, now: Any, cfg: Any, detail: str | None = None) -> Decision:
    """DENY + SYSTEM_ERROR built defensively from whatever input survived (P1). Never raises."""
    def safe(fn: Any, default: Any) -> Any:
        try:
            return fn()
        except Exception:  # noqa: BLE001
            return default

    m = mode if mode in MODES else "OFFLINE"
    codes = ("SYSTEM_ERROR", "OFFLINE_MODE") if m == "OFFLINE" else ("SYSTEM_ERROR",)
    kiosk = safe(lambda: str(signals.kiosk_id), None) or safe(lambda: str(ctx.kiosk_id), "UNKNOWN")
    return Decision(
        attempt_id=safe(lambda: str(signals.attempt_id), "UNKNOWN"),
        kiosk_id=kiosk,
        zone=safe(lambda: ctx.zone or kiosk_zone(ctx.lvb, kiosk), None),
        decision=DENY,
        reason_codes=codes,
        next_action=NextAction("CONTACT_DESK"),
        mode=m,
        stage="system",
        policy_version=safe(lambda: cfg.policy_version, "unknown"),
        t0=safe(lambda: signals.t0 if signals.t0.tzinfo else None, None),
        decided_at=now if isinstance(now, datetime) and now.tzinfo else datetime.now(UTC),
        bundle_version=safe(lambda: _bundle_version(ctx), None),
        display_message=GENERIC_DESK_MESSAGE,
        detail=detail,
    )


def with_challenge(decision: Decision, challenge: Mapping[str, Any] | None) -> Decision:
    return replace(decision, next_action=replace(decision.next_action, challenge=challenge))
