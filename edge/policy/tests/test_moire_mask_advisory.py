"""Enforce switches `liveness.moire.enforce` and `liveness.mask.m2_rgb_enforce` (lead 2026-11-14).

false = ADVISORY: computed exactly as when enforced and reported (scores.moire / scores.mask.m2_ring, the
signals entry "ADVISORY_<zone>", LivenessResult.advisory_cues), with no decision effect: no UNSURE, no FAIL,
no mask code, never counted as a strong cue. Unchanged in both modes: PAD, device detector, injection, depth,
the depth-based M2 step, M1 (MASK_CUE_RIGID) and M3. A missing key means enforce. A *missing* moire value
stays UNSURE (pipeline fault, fail-secure), and the online ambient-flash exception still needs moire <
unsure (R12). Every test pins the switches explicitly, independent of the shipped YAML.
"""

from __future__ import annotations

import copy

import pytest

from edge.policy.liveness import liveness_fusion
from edge.policy.tests.builders import OB, B, base_thresholds
from edge.policy.thresholds import ConfigError, Thresholds

MOIRE_ADV = {"liveness": {"moire": {"enforce": False}}}
MOIRE_ENF = {"liveness": {"moire": {"enforce": True}}}
RGB_ADV = {"liveness": {"mask": {"m2_rgb_enforce": False}}}
RGB_ENF = {"liveness": {"mask": {"m2_rgb_enforce": True}}}
BOTH_ADV = {"liveness": {"moire": {"enforce": False}, "mask": {"m2_rgb_enforce": False}}}
PAD_UNSURE = [0.85, 0.82, 0.60, 0.50, 0.70]  # PAD UNSURE -> corroborates a moire FAIL


def fused(scn):
    s = scn.signals()
    return liveness_fusion(s.frames, s, "PASS", scn.thresholds(), scn.mode)


# ---------------------------------------------------------------- moire
@pytest.mark.parametrize("value,zone", [(0.45, "UNSURE"), (0.69, "UNSURE"), (0.80, "UNSURE")])  # 0.80 uncorroborated
def test_advisory_moire_has_no_decision_effect(value, zone):
    adv = B().cfg(MOIRE_ADV).set(moire=[value] * 5).evaluate()
    assert adv.decision == "ALLOW" and adv.reason_codes == ("ACCESS_OK",)
    assert adv.to_response()["scores"]["signals"]["moire"] == f"ADVISORY_{zone}"
    assert adv.to_response()["scores"]["moire"] == pytest.approx(value)
    enf = B().cfg(MOIRE_ENF).set(moire=[value] * 5).evaluate()
    assert enf.decision == "STEP_UP" and set(enf.reason_codes) == {"LIVENESS_UNSURE"}
    assert enf.to_response()["scores"]["signals"]["moire"] == zone


def test_advisory_moire_reports_the_score_and_band_it_would_have_had():
    res = fused(B().cfg(MOIRE_ADV).set(moire=[0.13, 0.30, 0.42, 0.79, 0.20]))
    assert res.signals["moire"] == "ADVISORY_UNSURE" and res.scores["moire"] == pytest.approx(0.79)
    assert res.status == "PASS" and res.unsure_codes == () and res.hard_codes == ()
    assert fused(B().cfg(MOIRE_ADV)).signals["moire"] == "ADVISORY_PASS"


def test_advisory_moire_never_denies_even_when_corroborated():
    enf = B().cfg(MOIRE_ENF).set(moire=[0.80] * 5, pad=list(PAD_UNSURE)).evaluate()
    assert enf.decision == "DENY" and "SPOOF_MOIRE" in enf.reason_codes
    adv = B().cfg(MOIRE_ADV).set(moire=[0.80] * 5, pad=list(PAD_UNSURE)).evaluate()
    assert adv.decision == "STEP_UP" and set(adv.reason_codes) == {"LIVENESS_UNSURE"}  # from PAD alone
    assert adv.to_response()["scores"]["signals"]["moire"] == "ADVISORY_FAIL"
    assert adv.to_response()["scores"]["signals"]["pad"] == "UNSURE"


def test_missing_moire_stays_unsure_when_advisory():
    for patch in (MOIRE_ADV, MOIRE_ENF):
        d = B().cfg(patch).set(moire=[None] * 5).evaluate()
        assert d.decision == "STEP_UP" and set(d.reason_codes) == {"LIVENESS_UNSURE"}
        assert d.to_response()["scores"]["signals"]["moire"] == "UNSURE"


def test_ambient_flash_exception_still_requires_low_moire_when_moire_is_advisory():
    """R12: WEAK flash online passes only with a clean device and moire < unsure, advisory or not."""
    weak = {**B().flash, "r": 0.9, "amplitude": 1.5}
    ok = B().cfg(MOIRE_ADV).set(flash=weak).evaluate()
    assert ok.decision == "ALLOW" and ok.to_response()["scores"]["signals"]["flash"] == "PASS_AMBIENT"
    blocked = B().cfg(MOIRE_ADV).set(flash=weak, moire=[0.45] * 5).evaluate()
    assert blocked.decision == "STEP_UP" and set(blocked.reason_codes) == {"LIVENESS_UNSURE"}
    assert blocked.to_response()["scores"]["signals"]["flash"] == "UNSURE"


# ---------------------------------------------------------------- RGB mask ring (M2)
@pytest.mark.parametrize("ring,level", [(0.60, "weak"), (0.80, "strong")])
def test_advisory_rgb_ring_has_no_decision_effect(ring, level):
    scn = B().cfg(RGB_ADV).set(ring=[ring] * 5)
    res = fused(scn)
    assert res.mask_codes == () and res.strong_mask_codes == () and res.status == "PASS"
    assert res.advisory_cues == {"MASK_CUE_EDGE": level} and res.signals["mask"] == "ADVISORY_UNSURE"
    d = scn.evaluate()
    assert d.decision == "ALLOW" and d.reason_codes == ("ACCESS_OK",)
    assert d.to_response()["scores"]["mask"] == {"m2_ring": pytest.approx(ring)}
    enf = B().cfg(RGB_ENF).set(ring=[ring] * 5).evaluate()
    assert enf.decision == "STEP_UP" and set(enf.reason_codes) == {"MASK_CUE_EDGE"}
    assert list(enf.next_action.steps) == ["CHALLENGE"]
    assert enf.to_response()["scores"]["signals"]["mask"] == "UNSURE"


def test_advisory_rgb_ring_never_counts_as_a_strong_cue():
    spectral = {"liveness": {"mask": {"spectral_enabled": True}}}
    flash = {**B().flash, "skin_score": 0.10}  # strong MASK_CUE_SPECTRAL
    enf = B().cfg(spectral).cfg(RGB_ENF).set(ring=[0.80] * 5, flash=flash).evaluate()
    assert enf.decision == "DENY" and {"MASK_CUE_EDGE", "MASK_CUE_SPECTRAL"} <= set(enf.reason_codes)
    adv = B().cfg(spectral).cfg(RGB_ADV).set(ring=[0.80] * 5, flash=flash).evaluate()
    assert adv.decision == "STEP_UP" and set(adv.reason_codes) == {"MASK_CUE_SPECTRAL"}
    assert adv.to_response()["scores"]["signals"]["mask"] == "UNSURE"


def test_depth_m2_step_and_m3_stay_enforced_when_rgb_is_advisory():
    d = B().cfg(RGB_ADV).depth_on(m2_depth_step_mm=12.0, m3_template_rms_mm=9.0).evaluate()  # matrix M02
    assert d.decision == "DENY" and {"MASK_CUE_EDGE", "MASK_CUE_SHAPE"} <= set(d.reason_codes)
    d = B().cfg(RGB_ADV).depth_on(m3_template_rms_mm=6.5).set(ring=[0.55] * 5).evaluate()  # matrix M04
    assert d.decision == "STEP_UP" and set(d.reason_codes) == {"MASK_CUE_SHAPE"}


# ---------------------------------------------------------------- both switches, both modes
def test_decisive_signals_still_deny_with_both_switches_advisory():
    d = B().cfg(BOTH_ADV).set(device=[(0.62, 1.0)] * 5, moire=[0.9] * 5, ring=[0.9] * 5).evaluate()
    assert d.decision == "DENY" and set(d.reason_codes) == {"SPOOF_DEVICE_DETECTED"}
    d = B().cfg(BOTH_ADV).set(pad=[0.10] * 5).evaluate()
    assert d.decision == "DENY" and set(d.reason_codes) == {"SPOOF_PASSIVE"}
    d = B().cfg(BOTH_ADV).set(pad=list(PAD_UNSURE)).evaluate()
    assert d.decision == "STEP_UP" and set(d.reason_codes) == {"LIVENESS_UNSURE"}


def test_switches_apply_offline_too():
    d = OB().cfg(BOTH_ADV).set(moire=[0.45] * 5, ring=[0.60] * 5).evaluate()
    assert d.decision == "ALLOW" and set(d.reason_codes) == {"ACCESS_OK", "OFFLINE_MODE"}
    d = OB().set(moire=[0.45] * 5).evaluate()  # doc baseline = enforced
    assert d.decision == "STEP_UP" and "LIVENESS_UNSURE" in d.reason_codes


def test_missing_switch_keys_mean_enforce():
    raw = base_thresholds().raw()
    raw["liveness"]["moire"].pop("enforce", None)
    raw["liveness"]["mask"].pop("m2_rgb_enforce", None)
    T = Thresholds(copy.deepcopy(raw))
    s = B().set(moire=[0.45] * 5, ring=[0.60] * 5).signals()
    res = liveness_fusion(s.frames, s, "PASS", T, "ONLINE")
    assert res.unsure_codes == ("LIVENESS_UNSURE",) and res.mask_codes == ("MASK_CUE_EDGE",)
    assert res.advisory_cues == {} and res.signals["moire"] == "UNSURE"


# ---------------------------------------------------------------- config validation
@pytest.mark.parametrize("dotted", ["liveness.flash.enforce", "liveness.moire.enforce",
                                    "liveness.mask.m2_rgb_enforce"])
def test_an_enforce_switch_must_be_a_boolean(dotted):
    raw = base_thresholds().raw()
    *path, key = dotted.split(".")
    sec = raw
    for p in path:
        sec = sec[p]
    for bad in ("false", 0, None):
        sec[key] = bad
        with pytest.raises(ConfigError, match="must be true or false"):
            Thresholds(copy.deepcopy(raw))


@pytest.mark.parametrize("section,key", [("moire", "enforce"), ("mask", "m2_rgb_enforce"), ("flash", "enforce")])
def test_offline_may_not_switch_an_enforced_signal_to_advisory(section, key):
    raw = base_thresholds().raw()
    raw["liveness"][section][key] = True
    raw["offline"].setdefault("overrides", {}).setdefault("liveness", {}).setdefault(section, {})[key] = False
    with pytest.raises(ConfigError, match="P6"):
        Thresholds(copy.deepcopy(raw))
    raw["liveness"][section][key] = False  # advisory online, enforced offline = tightening: allowed
    raw["offline"]["overrides"]["liveness"][section][key] = True
    T = Thresholds(copy.deepcopy(raw))
    assert T.for_mode("OFFLINE").liveness[section][key] is True
