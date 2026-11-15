"""liveness.flash.enforce: false = ADVISORY flash (lead/operator 2026-11-14, pending kiosk flash re-validation).

Advisory: a measured FAIL / UNSURE / WEAK / missing flash has no decision effect (reported as ADVISORY_*),
moire corroboration treats the advisory flash as PASS; the non-flash path (NOT_AVAILABLE) still needs a
CHALLENGE. A missing `enforce` key means enforce. Tests pin the key explicitly, independent of the YAML.
"""

from __future__ import annotations

import copy

import pytest

from edge.policy.liveness import liveness_fusion
from edge.policy.tests.builders import OB, B, base_thresholds
from edge.policy.thresholds import Thresholds

ADVISORY = {"liveness": {"flash": {"enforce": False}}}
ENFORCED = {"liveness": {"flash": {"enforce": True}}}


def flash(**kw):
    return {**B().flash, **kw}


@pytest.mark.parametrize("delta,status", [
    ({"r": 0.12}, "FAIL"),  # mismatch
    ({"lag_frames": 20.0}, "FAIL"),  # replay lag
    ({"order_ok": False}, "FAIL"),  # wrong colour order
    ({"r": 0.50}, "UNSURE"),
    ({"amplitude": 1.5, "r": 0.10}, "WEAK"),
])
def test_advisory_flash_result_has_no_decision_effect(delta, status):
    adv = B().cfg(ADVISORY).set(flash=flash(**delta)).evaluate()
    assert adv.decision == "ALLOW" and adv.reason_codes == ("ACCESS_OK",)
    enforced = B().cfg(ENFORCED).set(flash=flash(**delta)).evaluate()
    assert enforced.decision != "ALLOW" or status == "WEAK"  # WEAK may pass via the online ambient exception


@pytest.mark.parametrize("delta,status", [({"r": 0.12}, "FAIL"), ({"r": 0.50}, "UNSURE"),
                                          ({"amplitude": 1.5}, "WEAK")])
def test_advisory_flash_is_still_measured_and_reported(delta, status):
    s = B().set(flash=flash(**delta)).signals()
    T = base_thresholds().with_overrides(ADVISORY)
    res = liveness_fusion(s.frames, s, "PASS", T, "ONLINE")
    assert res.signals["flash"] == f"ADVISORY_{status}"
    assert res.scores["flash_r"] == pytest.approx(s.flash.r) and res.scores["flash_amp"] == pytest.approx(
        s.flash.amplitude)


def test_advisory_applies_offline_too():
    res = OB().cfg(ADVISORY).set(flash=flash(amplitude=1.5)).evaluate()
    assert res.decision == "ALLOW" and set(res.reason_codes) == {"ACCESS_OK", "OFFLINE_MODE"}


def test_advisory_missing_flash_measurement_does_not_step_up():
    assert B().cfg(ADVISORY).set(flash=None).evaluate().decision == "ALLOW"
    assert B().cfg(ENFORCED).set(flash=None).evaluate().decision == "STEP_UP"


def test_non_flash_path_still_requires_a_challenge_in_advisory_mode():
    res = B().cfg(ADVISORY).set(flash_enabled=False).evaluate()
    assert res.decision == "STEP_UP" and set(res.reason_codes) == {"LIVENESS_UNSURE"}
    assert list(res.next_action.steps) == ["CHALLENGE"]
    res = B().cfg({"liveness": {"flash": {"enforce": False, "enabled": False}}}).evaluate()
    assert res.decision == "STEP_UP" and list(res.next_action.steps) == ["CHALLENGE"]


def test_moire_corroboration_treats_advisory_flash_as_pass():
    """Advisory: moire >= 0.70 with PAD PASS and a measured-but-failing flash is not corroborated."""
    adv = B().cfg(ADVISORY).set(moire=[0.80] * 5, flash=flash(r=0.12)).evaluate()
    assert adv.decision == "STEP_UP" and set(adv.reason_codes) == {"LIVENESS_UNSURE"}
    enforced = B().cfg(ENFORCED).set(moire=[0.80] * 5, flash=flash(r=0.12)).evaluate()
    assert enforced.decision == "DENY" and {"SPOOF_MOIRE", "SPOOF_FLASH_MISMATCH"} <= set(enforced.reason_codes)
    pad_unsure = B().cfg(ADVISORY).set(moire=[0.80] * 5, pad=[0.85, 0.82, 0.60, 0.50, 0.70]).evaluate()
    assert pad_unsure.decision == "DENY" and "SPOOF_MOIRE" in pad_unsure.reason_codes  # PAD != PASS corroborates


def test_other_hard_evidence_still_denies_in_advisory_mode():
    res = B().cfg(ADVISORY).set(device=[(0.62, 1.0)] * 5, flash=flash(r=0.12)).evaluate()
    assert res.decision == "DENY" and set(res.reason_codes) == {"SPOOF_DEVICE_DETECTED"}


def test_missing_enforce_key_means_enforce():
    raw = base_thresholds().raw()
    del raw["liveness"]["flash"]["enforce"]
    T = Thresholds(copy.deepcopy(raw))
    s = B().set(flash=flash(r=0.12)).signals()
    assert liveness_fusion(s.frames, s, "PASS", T, "ONLINE").hard_codes == ("SPOOF_FLASH_MISMATCH",)
