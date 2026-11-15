"""Step-up continuations of docs/POLICY_TEST_CASES.md (matrix §9.6 rows R1-R10).

Rows: Q13 Q14 Q17 Q21 L21 C02-C10 RC04-RC07 RC09 S02 S03 S14 S45-S49 O05-O10 O12 O15 O20 O21 O29
O44-O47. attempts_left uses the DECISION_POLICY §7 / API.md semantics (lead final): retries left after this
submission -- 1 at first issue, 0 after one failure ("last try").
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pyotp
import pytest

import edge.policy.fallback as fallback_mod
from edge.policy.challenge import Challenge
from edge.policy.engine import evaluate
from edge.policy.fallback import FallbackVerifier, InMemoryFallbackState
from edge.policy.signals import DepthSignal, FallbackSubmission
from edge.policy.stepup import SessionClosed, open_session, resolve_challenge, resolve_fallback
from edge.policy.tests.builders import (
    L03_PAD,
    OB,
    TEST_CARD_PEPPER,
    TOTP_SECRETS,
    B,
    Scn,
    action,
    evidence_for,
    good_action,
    soft_fail_evidence,
    with_staff,
)

OM, OFR, HR = "OFFLINE_MODE", "OFFLINE_FALLBACK_REQUIRED", "OFFLINE_HIGH_RISK_ZONE"
ROWS_COVERED: set[str] = set()


def totp(user: str, at: datetime) -> str:
    return pyotp.TOTP(TOTP_SECRETS[user]).at(int(at.timestamp()))


class Flow:
    """Evaluate a scenario, open its step-up session, then resolve submissions at t0 + offsets."""

    def __init__(self, scn: Scn, *, actions=("SMILE", "TURN_LEFT"), state=None) -> None:
        signals, ctx, mode, now, T = scn.build()
        self.T, self.ctx, self.t = T, ctx, now
        self.first = evaluate(signals, ctx, mode, now, cfg=T, rng=scn.rng)
        self.state = state if state is not None else InMemoryFallbackState()
        self.verifier = FallbackVerifier(T, self.state, totp_secret=TOTP_SECRETS.get, card_pepper=TEST_CARD_PEPPER,
                                         bundle=lambda: ctx.lvb)
        self.actions, self.n = tuple(actions), 0
        self.session = None
        if self.first.decision == "STEP_UP" and self.first.next_action.steps:
            ch = self._challenge(now) if "CHALLENGE" in self.first.next_action.steps else None
            self.session = open_session(self.first, now, T, ch)
            self.first = self.session.last

    def _challenge(self, now: datetime) -> Challenge:
        self.n += 1
        return Challenge(challenge_id=f"chl_{self.n}", nonce=f"n_{self.n}", actions=self.actions, step_window_ms=1500,
                         min_reaction_ms=150, issued_at=now, expires_at=now + timedelta(seconds=120))

    def challenge(self, make_evidence=None, *, after_s: float = 5):
        ev = (make_evidence or evidence_for)(self.session.challenge)
        self.session, d = resolve_challenge(self.session, ev, self.t + timedelta(seconds=after_s), self.T,
                                            self._challenge)
        return d

    def fallback(self, *, after_s: float = 5, **sub):
        self.session, d = resolve_fallback(self.session, FallbackSubmission(**with_staff(sub)),
                                           self.t + timedelta(seconds=after_s), self.T, self.verifier)
        return d

    def at(self, after_s: float) -> datetime:
        return self.t + timedelta(seconds=after_s)


def expect(d, row, decision, codes, *, steps=None, type_=None, attempts_left=None, resolved=None):
    ROWS_COVERED.add(row)
    assert d.decision == decision, (d.decision, d.reason_codes)
    assert set(d.reason_codes) == set(codes)
    if steps is not None:
        assert list(d.next_action.steps) == steps
    if type_ is not None:
        assert d.next_action.type == type_
    if attempts_left is not None:
        assert d.next_action.attempts_left == attempts_left
    if resolved is not None:
        assert set(d.resolved_codes) == set(resolved)
    if decision == "ALLOW":
        assert d.next_action.type == "OPEN_DOOR"
    if decision == "DENY":
        assert d.resolved_codes == ()


def S01():
    return B().who("u_3c4d", "LIB", "2026-11-14T07:50")


def O04():
    return OB().who("u_7a8b", "SRV", "2026-11-14T10:00")


def O19():
    return OB().fixed().who("u_3c4d", "MAIN", "2026-11-14T21:00")


def Q05():
    return B().set(luma=[40.0] * 5, recapture_count=2)


# ---------------------------------------------------------------- §1 quality exhausted -> manual review (A3)
def test_Q13_manual_review_staff_override_allows_without_user():
    f = Flow(Q05())
    d = f.fallback(method="STAFF_OVERRIDE", code="48213907")
    expect(d, "R1", "ALLOW", {"ACCESS_OK", "FALLBACK_OK"}, resolved={"QUALITY_LOW_LIGHT"})
    assert d.user_id is None and d.candidate_user_id is None
    assert dict(d.fallback) == {"method": "STAFF_OVERRIDE", "staff_id": "s_guard01", "code_id": "OVR-001",
                                "totp_step": None}
    assert f.state.is_code_consumed("OVR-001")


def test_Q14_totp_not_offered_for_manual_review():
    d = Flow(Q05()).fallback(method="TOTP", code=totp("u_3c4d", B().t0))
    expect(d, "R8", "STEP_UP", {"QUALITY_LOW_LIGHT", "FALLBACK_FAILED"}, steps=["SECOND_FACTOR"], attempts_left=0)


def test_Q17_offline_manual_review():
    d = Flow(OB().set(luma=[40.0] * 5, recapture_count=2)).fallback(method="STAFF_OVERRIDE", code="48213907")
    expect(d, "R1", "ALLOW", {"ACCESS_OK", "FALLBACK_OK", OM}, resolved={"QUALITY_LOW_LIGHT"})
    assert d.user_id is None and d.fallback["staff_id"] == "s_guard01"


def test_Q17b_override_without_staff_id_never_allows():
    """Lead 2026-11-14 (security, R2): a valid code without staff_id matches nobody; a named retry passes."""
    f = Flow(OB().set(luma=[40.0] * 5, recapture_count=2))
    d = f.fallback(method="STAFF_OVERRIDE", code="48213907", staff_id=None)
    assert d.decision == "STEP_UP" and "FALLBACK_FAILED" in d.reason_codes and d.next_action.attempts_left == 0
    d = f.fallback(method="STAFF_OVERRIDE", code="48213907", staff_id="s_guard01", after_s=10)
    assert d.decision == "ALLOW" and d.fallback["staff_id"] == "s_guard01" and d.user_id is None


def test_Q21_wrong_override_twice():
    f = Flow(Q05())
    d = f.fallback(method="STAFF_OVERRIDE", code="00000000")
    expect(d, "R8", "STEP_UP", {"QUALITY_LOW_LIGHT", "FALLBACK_FAILED"}, attempts_left=0)
    d = f.fallback(method="STAFF_OVERRIDE", code="00000000", after_s=10)
    expect(d, "R9", "DENY", {"FALLBACK_FAILED"}, type_="NONE")


# ---------------------------------------------------------------- §2 / §3 challenge rows
def test_L21_non_flash_path_challenge_passed():
    f = Flow(B().set(flash_enabled=False))
    expect(f.challenge(), "R2", "ALLOW", {"ACCESS_OK"}, resolved={"LIVENESS_UNSURE"})


def test_M01_issued_challenge_has_one_mandatory_deformation():
    from edge.policy.challenge import new_challenge

    f = Flow(B().set(ring=[0.60] * 5))
    assert f.first.next_action.steps == ("CHALLENGE",)
    c = new_challenge(f.T, f.t)
    assert sum(a in {"SMILE", "OPEN_MOUTH", "PUFF_CHEEKS"} for a in c.actions) == 1


def test_C02_challenge_passed_allows():
    f = Flow(B().set(pad=list(L03_PAD)))
    d = f.challenge(lambda ch: evidence_for(ch, actions=[
        action("SMILE", prompt=10_000, start_after=400, complete_after=600, baseline=0.07, peak=0.62),
        action("TURN_LEFT", prompt=12_000, start_after=700, complete_after=900, baseline=0, peak=0, shift=None,
               yaw=20.0)]))
    expect(d, "R2", "ALLOW", {"ACCESS_OK"}, resolved={"LIVENESS_UNSURE"})


def test_C03_m1_rigid_mask_denies():
    f = Flow(B().set(ring=[0.60] * 5).cfg({"liveness": {"depth": {"enabled": True}}}))
    depth = DepthSignal(available=True, m1_mouth_residual_mm=1.2, m1_forehead_residual_mm=0.8)
    d = f.challenge(lambda ch: evidence_for(ch, actions=[action("SMILE", prompt=10_000, baseline=0.0, peak=0.60),
                                                         good_action("TURN_LEFT", 12_000)], depth=depth))
    expect(d, "R5", "DENY", {"MASK_CUE_RIGID"}, type_="NONE")


def test_C04_too_early_response_hard_fail():
    f = Flow(B().set(pad=list(L03_PAD)))
    d = f.challenge(lambda ch: evidence_for(ch, actions=[action("SMILE", prompt=10_000, start_after=80),
                                                         good_action("TURN_LEFT", 12_000)]))
    expect(d, "R4", "DENY", {"CHALLENGE_FAILED"}, type_="NONE")


def test_C05_wrong_turn_direction_hard_fail():
    f = Flow(B().set(pad=list(L03_PAD)))
    wrong = good_action("TURN_RIGHT", 12_000).model_copy(update={"action": "TURN_LEFT"})
    d = f.challenge(lambda ch: evidence_for(ch, actions=[good_action("SMILE", 10_000), wrong]))
    expect(d, "R4", "DENY", {"CHALLENGE_FAILED"}, type_="NONE")


def test_C06_C07_eye_cut_mask_soft_fails_twice():
    f = Flow(B().set(ring=[0.60] * 5), actions=("SMILE", "BLINK"))
    first_nonce = f.session.challenge.nonce
    d = f.challenge(soft_fail_evidence)
    expect(d, "R6", "STEP_UP", {"MASK_CUE_EDGE", "CHALLENGE_FAILED"}, steps=["CHALLENGE"], attempts_left=0)
    assert d.next_action.challenge["nonce"] != first_nonce  # new nonce
    d = f.challenge(soft_fail_evidence, after_s=10)
    expect(d, "R7", "DENY", {"CHALLENGE_FAILED"}, type_="NONE")


def test_C06_replaying_the_old_nonce_after_a_soft_fail_is_a_hard_fail():
    f = Flow(B().set(ring=[0.60] * 5), actions=("SMILE", "BLINK"))
    old = f.session.challenge
    f.challenge(soft_fail_evidence)
    d = f.challenge(lambda _ch: evidence_for(old), after_s=10)
    expect(d, "R4", "DENY", {"CHALLENGE_FAILED"})


def test_C08_challenge_after_ttl_denies():
    d = Flow(B().set(pad=list(L03_PAD))).challenge(after_s=130)
    expect(d, "R10", "DENY", {"CHALLENGE_FAILED"}, type_="NONE")


def test_C08_ttl_boundary_exactly_120s_is_still_open():
    d = Flow(B().set(pad=list(L03_PAD))).challenge(after_s=120)
    assert d.decision == "ALLOW"


def test_C09_second_factor_after_ttl_denies():
    f = Flow(S01())
    d = f.fallback(method="TOTP", code=totp("u_3c4d", f.at(130)), after_s=130)
    expect(d, "R10", "DENY", {"FALLBACK_FAILED"}, type_="NONE")


def test_C10_ttl_counts_from_the_original_step_up():
    f = Flow(B().set(pad=list(L03_PAD), cloud=dict(B().cloud, top1_similarity=92.0)))
    d = f.challenge(after_s=20)
    expect(d, "R3", "STEP_UP", {"LIVENESS_UNSURE", "MATCH_LOW"}, steps=["SECOND_FACTOR"])
    d = f.fallback(method="TOTP", code=totp("u_3c4d", f.at(125)), after_s=125)
    expect(d, "R10", "DENY", {"FALLBACK_FAILED"}, type_="NONE")


# ---------------------------------------------------------------- §3a random challenge
def test_RC04_random_challenge_passed():
    expect(Flow(B().r(0.05)).challenge(), "R2", "ALLOW", {"ACCESS_OK"}, resolved={"RANDOM_CHALLENGE"})


def test_RC05_RC06_random_challenge_soft_fails():
    f = Flow(B().r(0.05))
    d = f.challenge(soft_fail_evidence)
    expect(d, "R6", "STEP_UP", {"RANDOM_CHALLENGE", "CHALLENGE_FAILED"}, steps=["CHALLENGE"], attempts_left=0)
    expect(f.challenge(soft_fail_evidence, after_s=10), "R7", "DENY", {"CHALLENGE_FAILED"})


def test_RC07_rigid_3d_mask_caught_by_random_challenge_m1():
    f = Flow(B().depth_on().r(0.05), actions=("OPEN_MOUTH", "BLINK"))
    depth = DepthSignal(available=True, m1_mouth_residual_mm=1.0, m1_forehead_residual_mm=0.6)
    d = f.challenge(lambda ch: evidence_for(ch, actions=[action("OPEN_MOUTH", prompt=10_000, baseline=0.0, peak=0.55),
                                                         good_action("BLINK", 12_000)], depth=depth))
    expect(d, "R5", "DENY", {"MASK_CUE_RIGID"})


def test_RC09_offline_random_challenge_passed():
    expect(Flow(OB().r(0.20)).challenge(), "R2", "ALLOW", {"ACCESS_OK", OM}, resolved={"RANDOM_CHALLENGE"})


# ---------------------------------------------------------------- §5 schedule step-ups
def test_S02_totp_correct():
    f = Flow(S01())
    expect(f.fallback(method="TOTP", code=totp("u_3c4d", f.at(5))), "R1", "ALLOW", {"ACCESS_OK", "FALLBACK_OK"},
           resolved={"SCHEDULE_GRACE_WINDOW"})


def test_S03_wrong_users_totp_then_correct():
    f = Flow(S01())
    d = f.fallback(method="TOTP", code=totp("u_1a2b", f.at(5)))
    expect(d, "R8", "STEP_UP", {"SCHEDULE_GRACE_WINDOW", "FALLBACK_FAILED"}, attempts_left=0)
    d = f.fallback(method="TOTP", code=totp("u_3c4d", f.at(10)), after_s=10)
    expect(d, "R1", "ALLOW", {"ACCESS_OK", "FALLBACK_OK"})


def test_S14_staff_override_not_offered_online_high_risk():
    d = Flow(B().who("u_7a8b", "SRV", "2026-11-14T10:00")).fallback(method="STAFF_OVERRIDE", code="48213907")
    expect(d, "R8", "STEP_UP", {"SCHEDULE_HIGH_RISK_ZONE", "FALLBACK_FAILED"}, attempts_left=0)


def test_S45_email_otp_verified():
    d = Flow(S01()).fallback(method="EMAIL_OTP", otp_id="otp_1", email_otp_verified=True)
    expect(d, "R1", "ALLOW", {"ACCESS_OK", "FALLBACK_OK"})
    assert d.fallback["method"] == "EMAIL_OTP"


def test_S46_S47_email_otp_wrong_twice():
    f = Flow(S01())
    d = f.fallback(method="EMAIL_OTP", otp_id="otp_1", email_otp_verified=False)
    expect(d, "R8", "STEP_UP", {"SCHEDULE_GRACE_WINDOW", "FALLBACK_FAILED"}, steps=["SECOND_FACTOR"], attempts_left=0)
    expect(f.fallback(method="EMAIL_OTP", otp_id="otp_1", email_otp_verified=False, after_s=10), "R9", "DENY",
           {"FALLBACK_FAILED"})


def test_S48_email_otp_cloud_timeout_is_a_failed_submission_session_stays_online():
    """Engine-level fail-secure path (email_otp_verified=None reaching evaluate_fallback counts as a failed
    submission). Doc S48 / matrix R11 is the edge's drop_method path: test_drop_method_removes_it_..."""
    f = Flow(S01())
    d = f.fallback(method="EMAIL_OTP", otp_id="otp_1", email_otp_verified=None)
    expect(d, "R8", "STEP_UP", {"SCHEDULE_GRACE_WINDOW", "FALLBACK_FAILED"}, attempts_left=0)
    assert d.mode == "ONLINE" and f.session.mode == "ONLINE"


def test_S49_method_switch_within_the_remaining_attempt():
    f = Flow(S01())
    f.fallback(method="EMAIL_OTP", otp_id="otp_1", email_otp_verified=False)
    expect(f.fallback(method="TOTP", code=totp("u_3c4d", f.at(10)), after_s=10), "R1", "ALLOW",
           {"ACCESS_OK", "FALLBACK_OK"})


# ---------------------------------------------------------------- §6 offline step-ups
def test_O05_card_not_offered_offline_high_risk():
    d = Flow(O04()).fallback(method="CARD", card_id="HID-CARD-1004")
    expect(d, "R8", "STEP_UP", {OM, HR, OFR, "FALLBACK_FAILED"}, attempts_left=0)


def test_O06_totp_offline_high_risk():
    f = Flow(O04())
    d = f.fallback(method="TOTP", code=totp("u_7a8b", f.at(5)))
    expect(d, "R1", "ALLOW", {"ACCESS_OK", "FALLBACK_OK", OM})
    assert d.fallback["method"] == "TOTP"


def test_O07_wrong_totp_twice():
    f = Flow(O04())
    f.fallback(method="TOTP", code="000000")
    expect(f.fallback(method="TOTP", code="000001", after_s=10), "R9", "DENY", {"FALLBACK_FAILED", OM})


def test_O08_totp_step_replay_across_attempts():
    state = InMemoryFallbackState()
    f1 = Flow(O04(), state=state)
    code = totp("u_7a8b", f1.at(5))
    assert f1.fallback(method="TOTP", code=code).decision == "ALLOW"
    f2 = Flow(O04().set(attempt_id="att_TEST0002"), state=state)
    d = f2.fallback(method="TOTP", code=code)  # same time-step again
    expect(d, "R8", "STEP_UP", {OM, HR, OFR, "FALLBACK_FAILED"})
    expect(f2.fallback(method="TOTP", code=code, after_s=6), "R9", "DENY", {"FALLBACK_FAILED", OM})


def test_O09_O10_staff_override_is_single_use():
    state = InMemoryFallbackState()
    d = Flow(O04(), state=state).fallback(method="STAFF_OVERRIDE", code="48213907")
    expect(d, "R1", "ALLOW", {"ACCESS_OK", "FALLBACK_OK", OM})
    assert d.fallback["staff_id"] == "s_guard01" and d.fallback["code_id"] == "OVR-001"
    d = Flow(O04().set(attempt_id="att_TEST0002"), state=state).fallback(method="STAFF_OVERRIDE", code="48213907")
    expect(d, "R8", "STEP_UP", {OM, HR, OFR, "FALLBACK_FAILED"})


def test_O12_card_offline_grace():
    d = Flow(OB().who("u_3c4d", "LIB", "2026-11-14T07:50")).fallback(method="CARD", card_id="HID-CARD-1002")
    expect(d, "R1", "ALLOW", {"ACCESS_OK", "FALLBACK_OK", OM})


def test_O12_card_of_another_user_rejected():
    d = Flow(OB().who("u_3c4d", "LIB", "2026-11-14T07:50")).fallback(method="CARD", card_id="HID-CARD-1001")
    expect(d, "R8", "STEP_UP", {"SCHEDULE_GRACE_WINDOW", OM, OFR, "FALLBACK_FAILED"})


def test_O15_challenge_passed_second_factor_still_required():
    d = Flow(OB().set(pad=list(L03_PAD))).challenge()
    expect(d, "R3", "STEP_UP", {"LIVENESS_UNSURE", OM, OFR}, steps=["SECOND_FACTOR"], type_="SECOND_FACTOR")
    assert set(d.next_action.methods) == {"TOTP", "CARD", "STAFF_OVERRIDE"}


def test_O15_fallback_before_challenge_is_out_of_order():
    d = Flow(OB().set(pad=list(L03_PAD))).fallback(method="STAFF_OVERRIDE", code="48213907")
    assert d.decision == "DENY" and "SYSTEM_ERROR" in d.reason_codes


def test_O20_O21_expired_bundle_staff_override_only():
    f = Flow(O19())
    d = f.fallback(method="TOTP", code=totp("u_3c4d", f.at(5)))
    expect(d, "R8", "STEP_UP", {"SCHEDULE_EXPIRED_CACHE", OM, OFR, "FALLBACK_FAILED"})
    d = f.fallback(method="STAFF_OVERRIDE", code="75530182", after_s=10)
    expect(d, "R1", "ALLOW", {"ACCESS_OK", "FALLBACK_OK", OM})


def test_O29_staff_override_lockout_without_hash_check(monkeypatch):
    calls = {"n": 0}
    real = fallback_mod.override_hash

    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(fallback_mod, "override_hash", counting)
    state = InMemoryFallbackState()
    f1 = Flow(O04(), state=state)
    f1.fallback(method="STAFF_OVERRIDE", code="11111111")
    f1.fallback(method="STAFF_OVERRIDE", code="22222222", after_s=6)  # attempt 1 -> DENY (2 wrong)
    f2 = Flow(O04().set(attempt_id="att_TEST0002"), state=state)
    f2.fallback(method="STAFF_OVERRIDE", code="33333333", after_s=7)  # 3rd wrong in a row -> locked 300 s
    hashed = calls["n"]
    d = f2.fallback(method="STAFF_OVERRIDE", code="48213907", after_s=8)  # correct code, but locked
    ROWS_COVERED.add("R9")
    ROWS_COVERED.add("R12")
    # rejected without a hash check; KF-03: a locked method is not a factor failure -> FALLBACK_LOCKED + wait
    assert d.decision == "STEP_UP" and calls["n"] == hashed and "FALLBACK_LOCKED" in d.reason_codes
    assert d.next_action.retry_after_s == 299 and d.next_action.attempts_left == 0  # unchanged
    # lock started at 10:00:07 -> ends 10:05:07; a fresh attempt at 10:05:10 is accepted again
    f3 = Flow(OB().who("u_7a8b", "SRV", "2026-11-14T10:05:10").set(attempt_id="att_TEST0003"), state=state)
    assert f3.fallback(method="STAFF_OVERRIDE", code="48213907").decision == "ALLOW"


def test_O45_planted_override_hash_is_never_used():
    """Only the last VERIFIED bundle's override list counts; a tampered bundle cannot plant a code."""
    import hashlib

    from edge.policy.tests.test_cases import tampered_now

    planted = tampered_now()
    planted["override_codes"]["codes"].append({
        "code_id": "OVR-EVIL", "staff_id": "s_evil", "salt": "00" * 8, "valid_until": "2027-01-01T00:00:00Z",
        "hash": hashlib.pbkdf2_hmac("sha256", b"11112222", bytes(8), 100000).hex()})
    f = Flow(O04())  # LVB = the verified bundle
    verifier = FallbackVerifier(f.T, InMemoryFallbackState(), totp_secret=TOTP_SECRETS.get,
                                card_pepper=TEST_CARD_PEPPER, bundle=lambda: f.ctx.lvb)
    f.verifier = verifier
    d = f.fallback(method="STAFF_OVERRIDE", code="11112222", staff_id="s_evil")  # names the planted entry
    expect(d, "R8", "STEP_UP", {OM, HR, OFR, "FALLBACK_FAILED"}, attempts_left=0)


def test_O46_second_factor_after_ttl_offline():
    f = Flow(OB().set(pad=list(L03_PAD)))
    f.challenge(after_s=20)
    expect(f.fallback(method="TOTP", code=totp("u_3c4d", f.at(130)), after_s=130), "R10", "DENY",
           {"FALLBACK_FAILED", OM})


def test_O47_email_otp_not_offered_offline():
    d = Flow(OB().who("u_3c4d", "LIB", "2026-11-14T07:50")).fallback(method="EMAIL_OTP", email_otp_verified=True)
    expect(d, "R8", "STEP_UP", {"SCHEDULE_GRACE_WINDOW", OM, OFR, "FALLBACK_FAILED"}, attempts_left=0)


# ---------------------------------------------------------------- session mechanics
def test_closed_session_rejects_further_submissions():
    f = Flow(S01())
    f.fallback(method="TOTP", code=totp("u_3c4d", f.at(5)))
    with pytest.raises(SessionClosed):
        f.fallback(method="TOTP", code=totp("u_3c4d", f.at(6)), after_s=6)


def test_step_up_never_reruns_the_schedule():
    """P8: resolution re-uses the stored draft; a second factor cannot fix anything but a STEP_UP."""
    f = Flow(S01())
    d = f.fallback(method="TOTP", code=totp("u_3c4d", f.at(5)))
    assert d.schedule_result == "GRACE_WINDOW"


@pytest.mark.parametrize("build,submit", [(Q05, {"method": "TOTP", "code": "123456"}),
                                          (S01, {"method": "CARD", "card_id": "HID-CARD-1001"})])
def test_attempts_left_semantics(build, submit):
    f = Flow(build())
    assert f.first.next_action.attempts_left == 1  # doc: initial SECOND_FACTOR = max - 1
    assert f.fallback(**submit).next_action.attempts_left == 0  # last try
    f2 = Flow(build().cfg({"stepup": {"attempts_left_semantics": "including_next"}}))
    assert f2.first.next_action.attempts_left == 2 and f2.fallback(**submit).next_action.attempts_left == 1


def test_challenge_attempts_left_semantics():
    f = Flow(B().r(0.05))
    assert f.first.next_action.attempts_left == 1  # RC01
    assert f.challenge(soft_fail_evidence).next_action.attempts_left == 0  # RC05


# ---------------------------------------------------------------- drop_method (edge-ml: cloud OTP unavailable)
def test_drop_method_removes_it_without_counting_anything():
    """Matrix R11 / doc S48 (live path: edge/attempts.py drop_method on an EMAIL_OTP cloud-verify timeout):
    same STEP_UP, codes of the last response unchanged, EMAIL_OTP gone, attempts_left unchanged."""
    from edge.policy.stepup import drop_method

    f = Flow(S01())
    before = f.first.next_action
    assert "EMAIL_OTP" in before.methods
    s2, d = drop_method(f.session, "EMAIL_OTP", f.T, f.at(3))
    expect(d, "R11", "STEP_UP", {"SCHEDULE_GRACE_WINDOW"}, steps=list(before.steps),
           attempts_left=before.attempts_left)
    assert set(d.next_action.methods) == {"TOTP", "CARD", "STAFF_OVERRIDE"}
    assert s2.factor_failures == 0 and d.mode == "ONLINE"
    f.session = s2
    d = f.fallback(method="TOTP", code="000000")  # a later R8 re-issue no longer offers EMAIL_OTP
    assert "EMAIL_OTP" not in d.next_action.methods and "FALLBACK_FAILED" in d.reason_codes


def test_drop_method_keeps_the_retry_codes_of_the_last_response():
    from edge.policy.stepup import drop_method

    f = Flow(S01())
    f.fallback(method="TOTP", code="000000")  # R8: FALLBACK_FAILED, attempts_left 0
    _s2, d = drop_method(f.session, "EMAIL_OTP", f.T, f.at(6))
    assert "FALLBACK_FAILED" in d.reason_codes and d.next_action.attempts_left == 0


def test_drop_method_unknown_is_a_noop_and_last_method_cannot_be_dropped():
    from edge.policy.stepup import drop_method

    f = Flow(S01())
    s2, d = drop_method(f.session, "EMAIL_OTP", f.T, f.at(1))
    _s3, d3 = drop_method(s2, "EMAIL_OTP", f.T, f.at(2))
    assert set(d3.next_action.methods) == set(d.next_action.methods)
    q = Flow(Q05())  # A3 manual review: methods [STAFF_OVERRIDE] only
    with pytest.raises(ValueError):
        drop_method(q.session, "STAFF_OVERRIDE", q.T, q.at(1))


def test_drop_method_while_challenge_is_pending_updates_the_later_second_factor():
    from edge.policy.stepup import drop_method

    f = Flow(B().set(pad=list(L03_PAD), cloud={**B().cloud, "top1_similarity": 92.0}))  # CH -> SF{on}
    _s2, d = drop_method(f.session, "EMAIL_OTP", f.T, f.at(1))
    assert d.next_action.type == "CHALLENGE" and d.next_action.challenge is not None
    assert "EMAIL_OTP" not in d.next_action.methods
