"""§7.1 step-up challenge: issuance (C01) and verification rules."""

from __future__ import annotations

import random
from collections import Counter
from datetime import timedelta

import pytest

from edge.policy.challenge import Challenge, new_challenge, verify_challenge
from edge.policy.signals import DepthSignal
from edge.policy.tests.builders import B_T0, THRESHOLDS_PATH, action, evidence_for, good_action
from edge.policy.thresholds import Thresholds

T = Thresholds.load(THRESHOLDS_PATH)
DEFORM = {"SMILE", "OPEN_MOUTH", "PUFF_CHEEKS"}
SECOND = {"BLINK", "TURN_LEFT", "TURN_RIGHT"}


def ch(actions=("SMILE", "TURN_LEFT")):
    return Challenge(challenge_id="chl_t", nonce="n_t", actions=tuple(actions), step_window_ms=1500,
                     min_reaction_ms=150, issued_at=B_T0, expires_at=B_T0 + timedelta(seconds=120))


def verify(challenge, ev, depth_enabled=False):
    return verify_challenge(challenge, ev, T, depth_enabled=depth_enabled).result


# ---------------------------------------------------------------- C01 issuance property
def test_C01_every_issued_challenge_has_one_mandatory_deformation_and_unique_nonce():
    seen_nonces, orders, combos = set(), Counter(), Counter()
    for _ in range(1000):
        c = new_challenge(T, B_T0)
        assert len(c.actions) == 2
        assert sum(a in DEFORM for a in c.actions) == 1
        assert sum(a in SECOND for a in c.actions) == 1
        assert c.actions != ("BLINK",) and set(c.actions) != {"BLINK"}
        assert c.nonce not in seen_nonces and len(c.nonce) >= 16
        seen_nonces.add(c.nonce)
        orders[c.actions[0] in DEFORM] += 1
        combos[frozenset(c.actions)] += 1
        assert c.expires_at - c.issued_at == timedelta(seconds=120)
        assert c.step_window_ms == 1500
    assert orders[True] > 350 and orders[False] > 350  # random order, both positions used
    C = T.challenge  # shipped YAML: SMILE / OPEN_MOUTH x BLINK / TURN_LEFT / TURN_RIGHT (PUFF_CHEEKS removed)
    assert len(combos) == len(C.deformation_actions) * len(C.secondary_actions)  # every pairing occurs
    issued = {a for combo in combos for a in combo}
    assert issued == set(C.deformation_actions) | set(C.secondary_actions)  # only configured actions


def test_challenge_is_reproducible_with_injected_rng():
    a = new_challenge(T, B_T0, rng=random.Random(7))
    b = new_challenge(T, B_T0, rng=random.Random(7))
    assert a == b


def test_public_view_has_no_internal_fields():
    pub = new_challenge(T, B_T0).public()
    assert set(pub) == {"challenge_id", "nonce", "actions", "step_window_ms", "min_reaction_ms", "expires_at"}


# ---------------------------------------------------------------- verification
def test_all_good_passes():
    assert verify(ch(), evidence_for(ch())) == "PASS"


def test_C02_smile_rise_055_abs_062_then_turn_left_20():
    ev = evidence_for(ch(), actions=[
        action("SMILE", prompt=10_000, start_after=400, complete_after=600, baseline=0.07, peak=0.62),
        action("TURN_LEFT", prompt=12_000, start_after=700, complete_after=900, baseline=0, peak=0,
               shift=None, yaw=20.0),
    ])
    assert verify(ch(), ev) == "PASS"


def test_C04_response_before_min_reaction_is_hard_fail():
    ev = evidence_for(ch(), actions=[action("SMILE", prompt=10_000, start_after=80), good_action("TURN_LEFT", 12_000)])
    assert verify(ch(), ev) == "HARD_FAIL"


def test_C05_wrong_turn_direction_is_hard_fail():
    ev = evidence_for(ch(), actions=[good_action("SMILE", 10_000), good_action("TURN_RIGHT", 12_000)
                                     .model_copy(update={"action": "TURN_LEFT"})])
    assert verify(ch(), ev) == "HARD_FAIL"


def test_wrong_action_reported_is_hard_fail():
    ev = evidence_for(ch(), actions=[good_action("OPEN_MOUTH", 10_000), good_action("TURN_LEFT", 12_000)])
    assert verify(ch(), ev) == "HARD_FAIL"


def test_missing_action_is_hard_fail():
    ev = evidence_for(ch(), actions=[good_action("SMILE", 10_000)])
    assert verify(ch(), ev) == "HARD_FAIL"


def test_C06_no_deformation_is_soft_fail():
    c = ch(("SMILE", "BLINK"))
    ev = evidence_for(c, actions=[action("SMILE", prompt=10_000, baseline=0.07, peak=0.12),
                                  good_action("BLINK", 12_000)])
    assert verify(c, ev) == "SOFT_FAIL"


@pytest.mark.parametrize(
    "smile",
    [
        {"baseline": 0.20, "peak": 0.60},  # rise 0.40 < 0.45
        {"baseline": 0.00, "peak": 0.48},  # abs < 0.50
        {"shift": None},  # no correlated landmark shift
        {"shift": 0.0},
        {"start_after": None, "complete_after": None},  # no response at all
        {"complete_after": 1600},  # completed after the 1500 ms window
    ],
)
def test_deformation_soft_fail_variants(smile):
    params = {"prompt": 10_000, "baseline": 0.05, "peak": 0.62}
    params.update(smile)
    ev = evidence_for(ch(), actions=[action("SMILE", **params), good_action("TURN_LEFT", 12_000)])
    assert verify(ch(), ev) == "SOFT_FAIL"


@pytest.mark.parametrize("name,peak", [("OPEN_MOUTH", 0.39), ("PUFF_CHEEKS", 0.39)])
def test_jaw_and_puff_absolute_minimums(name, peak):
    c = ch((name, "BLINK"))
    ev = evidence_for(c, actions=[action(name, prompt=10_000, baseline=0.0, peak=peak), good_action("BLINK", 12_000)])
    assert verify(c, ev) == "SOFT_FAIL"
    ev_ok = evidence_for(c, actions=[action(name, prompt=10_000, baseline=0.0, peak=0.50),
                                     good_action("BLINK", 12_000)])
    assert verify(c, ev_ok) == "PASS"


def test_blink_needs_close_and_reopen():
    c = ch(("SMILE", "BLINK"))
    no_close = action("BLINK", prompt=12_000, baseline=0.05, peak=0.45, shift=None)
    no_reopen = action("BLINK", prompt=12_000, baseline=0.05, peak=0.9, shift=None, complete_after=None)
    assert verify(c, evidence_for(c, actions=[good_action("SMILE", 10_000), no_close])) == "SOFT_FAIL"
    assert verify(c, evidence_for(c, actions=[good_action("SMILE", 10_000), no_reopen])) == "SOFT_FAIL"


def test_small_turn_is_soft_fail():
    ev = evidence_for(ch(), actions=[good_action("SMILE", 10_000),
                                     action("TURN_LEFT", prompt=12_000, yaw=10.0, shift=None, peak=0, baseline=0)])
    assert verify(ch(), ev) == "SOFT_FAIL"


def test_tracking_lost_or_track_switch_is_hard_fail():
    lost = evidence_for(ch(), actions=[good_action("SMILE", 10_000).model_copy(update={"tracking_lost": True}),
                                       good_action("TURN_LEFT", 12_000)])
    assert verify(ch(), lost) == "HARD_FAIL"
    assert verify(ch(), evidence_for(ch(), same_track=False)) == "HARD_FAIL"


@pytest.mark.parametrize("cos,expected", [(0.30, "PASS"), (0.29, "HARD_FAIL"), (None, "HARD_FAIL")])
def test_last_frame_identity_cosine(cos, expected):
    assert verify(ch(), evidence_for(ch(), last_frame_cosine=cos)) == expected


def test_nonce_or_id_mismatch_is_hard_fail():
    ev = evidence_for(ch()).model_copy(update={"nonce": "n_replayed"})
    assert verify(ch(), ev) == "HARD_FAIL"
    ev = evidence_for(ch()).model_copy(update={"challenge_id": "chl_other"})
    assert verify(ch(), ev) == "HARD_FAIL"


def test_C03_m1_rigid_under_deformation_with_depth():
    depth = DepthSignal(available=True, m1_mouth_residual_mm=1.2, m1_forehead_residual_mm=0.8)
    ev = evidence_for(ch(), actions=[action("SMILE", prompt=10_000, baseline=0.0, peak=0.60),
                                     good_action("TURN_LEFT", 12_000)], depth=depth)
    assert verify(ch(), ev, depth_enabled=True) == "M1_CONTRADICTION"
    # depth disabled in config -> depth evidence is not used
    assert verify(ch(), ev, depth_enabled=False) == "PASS"


def test_m1_real_face_deforms():
    depth = DepthSignal(available=True, m1_mouth_residual_mm=6.5, m1_forehead_residual_mm=0.9)
    assert verify(ch(), evidence_for(ch(), depth=depth), depth_enabled=True) == "PASS"


def test_m1_ignored_when_alignment_unreliable():
    depth = DepthSignal(available=True, m1_mouth_residual_mm=1.0, m1_forehead_residual_mm=3.5)
    assert verify(ch(), evidence_for(ch(), depth=depth), depth_enabled=True) == "PASS"


def test_m1_beats_hard_fail():
    depth = DepthSignal(available=True, m1_mouth_residual_mm=1.0, m1_forehead_residual_mm=0.5)
    ev = evidence_for(ch(), same_track=False, depth=depth)
    assert verify(ch(), ev, depth_enabled=True) == "M1_CONTRADICTION"


# ---------------------------------------------------------------- turn = yaw delta vs baseline (kiosk bug report)
@pytest.mark.parametrize("ask,baseline,peak,expected", [
    ("TURN_LEFT", -20.0, -18.0, "SOFT_FAIL"),  # neutral already turned right; moved only +2 -> retry, not hard fail
    ("TURN_LEFT", -20.0, 0.0, "PASS"),  # moved +20 to the subject's left from a turned neutral pose
    ("TURN_RIGHT", 20.0, 2.0, "PASS"),  # moved -18
    ("TURN_RIGHT", 20.0, 18.0, "SOFT_FAIL"),
    ("TURN_LEFT", 0.0, -20.0, "HARD_FAIL"),  # really turned the wrong way
    ("TURN_LEFT", 10.0, -6.0, "HARD_FAIL"),  # delta -16 = wrong way even though |peak| < 15
    ("TURN_RIGHT", -18.0, -2.0, "HARD_FAIL"),  # delta +16 = wrong way
])
def test_turn_uses_yaw_delta_from_baseline(ask, baseline, peak, expected):
    c = ch(("SMILE", ask))
    turn = action(ask, prompt=12_000, start_after=700, complete_after=950, baseline=baseline, peak=0.0, shift=None,
                  yaw=peak)
    assert verify(c, evidence_for(c, actions=[good_action("SMILE", 10_000), turn])) == expected


# ---------------------------------------------------------------- smile bars vs real MediaPipe values (2026-11-14)
@pytest.mark.parametrize("baseline,peak,expected", [
    (0.05, 0.18, "SOFT_FAIL"),  # weak real smile: below smile_abs_min -> one retry (not a hard fail)
    (0.05, 0.56, "PASS"),
    (0.08, 0.63, "PASS"),
    (0.15, 0.56, "SOFT_FAIL"),  # rise 0.41 < deformation_rise_min 0.45 from a smiling neutral pose
])
def test_smile_bars_on_observed_values(baseline, peak, expected):
    c = ch(("SMILE", "BLINK"))
    ev = evidence_for(c, actions=[action("SMILE", prompt=10_000, baseline=baseline, peak=peak),
                                  good_action("BLINK", 12_000)])
    assert verify(c, ev) == expected
