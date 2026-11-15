"""docs/POLICY_TEST_CASES.md §6a RL01-RL16 + P10 (DECISION_POLICY §9.7): attack evidence only, monotonic t.

The lockout L and window W are read from config/thresholds.yaml (operator 2026-11-14: lockout_s 5; the doc's
literal retry_after values 59 / 50 / 30 / 1 are the L = 60 instances of the same expressions)."""

from __future__ import annotations

import math
import random

import pyotp

from edge.policy.engine import evaluate
from edge.policy.ratelimit import RateLimiter, counts_toward_rate_limit
from edge.policy.signals import DepthSignal
from edge.policy.tests.builders import (
    L03_PAD,
    OB,
    PHONE,
    TOTP_SECRETS,
    B,
    Scn,
    action,
    base_thresholds,
    evidence_for,
    good_action,
)
from edge.policy.tests.test_stepup import Flow

L = float(base_thresholds().rate_limit.lockout_s)
W = float(base_thresholds().rate_limit.window_s)
LAST = 40.0  # time of the 5th counted DENY in the RL05 sequence (t = 0, 10, 20, 30, 40)


class Kiosk:
    def __init__(self, cfg_patch: dict | None = None) -> None:
        self.T = B().cfg(cfg_patch or {}).thresholds()
        self.rl = RateLimiter(self.T)
        self.alerts = 0

    def attempt(self, scn: Scn, t: float):
        signals, ctx, mode, now, T = scn.build()  # the scenario's own thresholds; limiter config = kiosk's
        d = evaluate(signals, ctx, mode, now, cfg=T, rate_limit_retry_s=self.rl.retry_after_s(t), rng=scn.rng)
        self.record(d, t)
        return d

    def record(self, d, t: float) -> None:
        if self.rl.record(d.decision, d.reason_codes, t):
            self.alerts += 1


L05 = lambda: B().set(device=PHONE)
L01 = lambda: B().set(pad=[0.10, 0.20, 0.15, 0.90, 0.25])
S04 = lambda: B().who("u_3c4d", "LIB", "2026-11-14T07:40")
I03 = lambda: B().set(cloud={"ok": True, "top1_user": None, "top1_similarity": None},
                      local=[("u_3c4d", 0.22, 0.15)] * 5)
SYS = lambda: B().set(pad=[0.95, 0.93], luma=[120.0] * 2, lapvar=[150.0] * 2, yaw=[5.0] * 2,
                      secondary=[0.0] * 2, device=[(0, 0)] * 2, moire=[0.1] * 2, ring=[0.1] * 2,
                      local=[("u_3c4d", 0.72, 0.41)] * 2, ts=[1000, 1033], depth_valid=[None] * 2)


def test_RL01_schedule_denies_do_not_count():
    k = Kiosk()
    for t in (0, 10, 20, 30, 40):
        assert k.attempt(S04(), t).decision == "DENY"
    assert k.attempt(B(), 50).decision == "ALLOW"


def test_RL02_identity_and_system_error_denies_do_not_count():
    k = Kiosk()
    for i, t in enumerate(range(0, 100, 10)):
        d = k.attempt(I03() if i < 5 else SYS(), t)
        assert d.decision == "DENY" and (set(d.reason_codes) & {"NOT_ENROLLED", "SYSTEM_ERROR"})
    assert k.attempt(B(), 100).decision == "ALLOW"


def test_RL03_bio_unsure_plus_schedule_denies_never_count_even_with_mask_cues():
    k = Kiosk()
    for i, t in enumerate(range(0, 100, 10)):
        scn = B().who("u_3c4d", "LIB", "2026-11-14T07:50")
        scn = scn.set(pad=list(L03_PAD)) if i < 5 else scn.set(ring=[0.60] * 5)
        d = k.attempt(scn, t)
        assert d.decision == "DENY" and "SCHEDULE_GRACE_WINDOW" in d.reason_codes
    assert k.attempt(B(), 100).decision == "ALLOW"


def test_RL04_four_spoofs_do_not_lock():
    k = Kiosk()
    for t in (0, 10, 20, 30):
        k.attempt(L05(), t)
    assert k.attempt(B(), 40).decision == "ALLOW"


def rl05(k: Kiosk) -> None:
    for t in (0, 10, 20, 30, 40):
        d = k.attempt(L05(), t)
        assert d.decision == "DENY" and "SPOOF_DEVICE_DETECTED" in d.reason_codes  # the 5th is returned normally


def test_RL05_fifth_spoof_locks_the_kiosk():
    k = Kiosk()
    rl05(k)
    assert k.alerts == 1
    d = k.attempt(B(), LAST + 1)
    assert d.decision == "DENY" and set(d.reason_codes) == {"RATE_LIMITED"} and d.next_action.type == "NONE"
    assert d.next_action.retry_after_s == math.ceil(L - 1)  # doc (L = 60): 59


def test_RL06_RL07_rate_limited_denies_neither_extend_nor_rearm():
    k = Kiosk()
    rl05(k)
    until = LAST + L
    for t in (LAST + L / 6, LAST + L / 2, until - 0.5):  # doc (L = 60): t = 50, 70, 99
        assert k.attempt(B(), t).next_action.retry_after_s == math.ceil(until - t)
    assert k.attempt(B(), until).decision == "ALLOW"  # RL07: lockout ended; RATE_LIMITED did not re-arm
    # RL08: events stay in the window -> one more counted DENY locks again (second alert)
    d = k.attempt(L05(), until + 1)
    assert d.decision == "DENY" and "SPOOF_DEVICE_DETECTED" in d.reason_codes and k.alerts == 2
    assert k.attempt(B(), until + 2).next_action.retry_after_s == math.ceil(L - 1)


def test_RL09_admin_reset_clears_events_and_lockout():
    k = Kiosk()
    rl05(k)
    k.rl.reset()
    assert k.attempt(B(), 46).decision == "ALLOW"
    for t in (50, 60, 70, 80):
        k.attempt(L05(), t)
    assert k.attempt(B(), 90).decision == "ALLOW"


def test_RL10_event_exactly_window_old_still_counts():
    k = Kiosk()
    for t in (0, 10, 20, 30, W):
        k.attempt(L01(), t)
    d = k.attempt(B(), W + 1)
    assert set(d.reason_codes) == {"RATE_LIMITED"} and d.next_action.retry_after_s == math.ceil(L - 1)


def test_RL11_event_older_than_window_dropped():
    k = Kiosk()
    for t in (0, 10, 20, 30, W + 1):
        k.attempt(L01(), t)
    assert k.attempt(B(), W + 2).decision == "ALLOW"


def test_RL12_all_attack_evidence_kinds_count():
    k = Kiosk()
    k.attempt(B().set(label="OBS Virtual Camera"), 0)  # Q08 injection
    k.attempt(B().depth_on(m2_depth_step_mm=12.0, m3_template_rms_mm=9.0), 10)  # M02 strong-mask DENY
    f = Flow(B().set(pad=list(L03_PAD)))  # C04 CHALLENGE_FAILED after L03
    k.record(f.challenge(lambda ch: evidence_for(ch, actions=[action("SMILE", prompt=10_000, start_after=80),
                                                              good_action("TURN_LEFT", 12_000)])), 20)
    f = Flow(B().set(ring=[0.60] * 5).cfg({"liveness": {"depth": {"enabled": True}}}))  # C03 MASK_CUE_RIGID
    depth = DepthSignal(available=True, m1_mouth_residual_mm=1.2, m1_forehead_residual_mm=0.8)
    k.record(f.challenge(lambda ch: evidence_for(ch, actions=[action("SMILE", prompt=10_000, baseline=0.0, peak=0.6),
                                                              good_action("TURN_LEFT", 12_000)], depth=depth)), 30)
    f = Flow(B().who("u_3c4d", "LIB", "2026-11-14T07:50"))  # S47 FALLBACK_FAILED
    f.fallback(method="EMAIL_OTP", email_otp_verified=False)
    k.record(f.fallback(method="EMAIL_OTP", email_otp_verified=False, after_s=10), 40)
    t = LAST + min(10.0, L / 2)  # doc (L = 60): B at 50 -> retry_after 50
    d = k.attempt(B(), t)
    assert set(d.reason_codes) == {"RATE_LIMITED"} and d.next_action.retry_after_s == math.ceil(LAST + L - t)


def test_RL13_step_up_retries_are_not_denies():
    k = Kiosk()
    for i, t in enumerate((0, 10, 20, 30, 40)):
        f = Flow(B().who("u_3c4d", "LIB", "2026-11-14T07:50").set(attempt_id=f"att_rl13_{i}"))
        d = f.fallback(method="EMAIL_OTP", email_otp_verified=False)
        assert d.decision == "STEP_UP"
        k.record(d, t)
    assert k.attempt(B(), 50).decision == "ALLOW"


def test_RL14_disabled_profile_neither_counts_nor_blocks():
    k = Kiosk({"rate_limit": {"enabled": False}})
    for t in (0, 10, 20, 30, 40):
        k.attempt(L05().cfg({"rate_limit": {"enabled": False}}), t)
    assert k.attempt(B().cfg({"rate_limit": {"enabled": False}}), 41).decision == "ALLOW"
    assert k.alerts == 0 and k.rl.state() == {"events": [], "lockout_until": None}


def test_RL15_offline_lockout_carries_offline_mode():
    k = Kiosk()
    for t in (0, 10, 20, 30, 40):
        k.attempt(OB().set(device=PHONE), t)
    d = k.attempt(OB(), LAST + 1)
    assert set(d.reason_codes) == {"RATE_LIMITED", "OFFLINE_MODE"}
    assert d.next_action.retry_after_s == math.ceil(L - 1)


def test_RL16_open_step_up_sessions_are_not_blocked_by_a_lockout():
    k = Kiosk()
    f = Flow(B().who("u_3c4d", "LIB", "2026-11-14T07:50"))  # STEP_UP opened at t = 0
    for t in (1, 2, 3, 4, 5):
        k.attempt(L05(), t)
    assert k.rl.retry_after_s(5.5) is not None  # kiosk locked ...
    d = f.fallback(method="TOTP", code=pyotp.TOTP(TOTP_SECRETS["u_3c4d"]).at(int(f.at(5.5).timestamp())),
                   after_s=5.5)
    assert d.decision == "ALLOW" and set(d.reason_codes) == {"ACCESS_OK", "FALLBACK_OK"}  # ... session still resolves


# ---------------------------------------------------------------- P10 (fuzz)
CODES_POOL = ["ACCESS_OK", "OFFLINE_MODE", "SPOOF_PASSIVE", "SPOOF_DEVICE_DETECTED", "MASK_CUE_EDGE", "MASK_CUE_RIGID",
              "INJECTION_VIRTUAL_CAMERA", "CHALLENGE_FAILED", "FALLBACK_FAILED", "NOT_ENROLLED", "SYSTEM_ERROR",
              "RATE_LIMITED", "QUALITY_LOW_LIGHT", "LIVENESS_UNSURE", "SCHEDULE_OUTSIDE_WINDOW",
              "SCHEDULE_GRACE_WINDOW", "SCHEDULE_REVOKED", "MATCH_LOW"]


def test_P10_limiter_changes_only_on_attack_evidence_denies():
    T = B().thresholds()
    rng = random.Random(10)
    for _ in range(2000):
        decision = rng.choice(["ALLOW", "STEP_UP", "DENY"])
        codes = rng.sample(CODES_POOL, rng.randint(1, 4))
        rl = RateLimiter(T)
        rl.record(decision, codes, 1.0)
        changed = rl.state()["events"] != []
        expected = (decision == "DENY" and not any(c.startswith("SCHEDULE_") for c in codes)
                    and any(c.startswith(("SPOOF_", "MASK_CUE_", "INJECTION_")) or c in ("CHALLENGE_FAILED",
                                                                                           "FALLBACK_FAILED")
                            for c in codes))
        assert changed == expected == counts_toward_rate_limit(decision, codes, T.rate_limit), (decision, codes)
