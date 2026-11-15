"""Reason-code closed list and deterministic ordering (DECISION_POLICY §6)."""

import pytest

from edge.policy.codes import ALL_CODES, order_codes

REQUIRED = {
    "QUALITY_LOW_LIGHT", "QUALITY_BLUR", "MULTIPLE_FACES", "SPOOF_PASSIVE", "SPOOF_DEVICE_DETECTED",
    "SPOOF_MOIRE", "SPOOF_FLASH_MISMATCH", "SPOOF_FLAT_DEPTH", "MASK_CUE_RIGID", "MASK_CUE_EDGE",
    "INJECTION_VIRTUAL_CAMERA", "CHALLENGE_FAILED", "MATCH_LOW", "MATCH_AMBIGUOUS", "NOT_ENROLLED",
    "SCHEDULE_OUTSIDE_WINDOW", "SCHEDULE_GRACE_WINDOW", "SCHEDULE_NO_ENTITLEMENT",
    "SCHEDULE_ZONE_NOT_PERMITTED", "SCHEDULE_HOLIDAY", "SCHEDULE_REVOKED", "SCHEDULE_EXPIRED_CACHE",
    "OFFLINE_MODE", "OFFLINE_HIGH_RISK_ZONE", "OFFLINE_FALLBACK_REQUIRED", "FALLBACK_OK", "FALLBACK_FAILED",
}
ADDED = {
    "ACCESS_OK", "QUALITY_POSE", "QUALITY_DEPTH_INVALID", "LIVENESS_UNSURE", "SPOOF_DEPTH_SCALE",
    "MASK_CUE_SHAPE", "MASK_CUE_SPECTRAL", "SCHEDULE_HIGH_RISK_ZONE", "SCHEDULE_BUNDLE_INVALID",
    "RATE_LIMITED", "SYSTEM_ERROR",
    "RANDOM_CHALLENGE",  # round-2 lead decision R4
    "FALLBACK_LOCKED",  # KF-03 (policy-fixes): locked second-factor method, not a counted failure
}


def test_closed_list_is_exactly_required_plus_added():
    assert set(ALL_CODES) == REQUIRED | ADDED


def test_order_is_stage_order_and_dedupes():
    got = order_codes(["ACCESS_OK", "OFFLINE_MODE", "FALLBACK_OK", "OFFLINE_MODE"])
    assert got == ["OFFLINE_MODE", "FALLBACK_OK", "ACCESS_OK"]


def test_order_liveness_hard_before_mask_before_unsure_before_identity_before_schedule():
    got = order_codes(["SCHEDULE_OUTSIDE_WINDOW", "MATCH_LOW", "LIVENESS_UNSURE", "MASK_CUE_EDGE",
                       "SPOOF_MOIRE", "INJECTION_VIRTUAL_CAMERA", "QUALITY_BLUR", "RATE_LIMITED"])
    assert got == ["RATE_LIMITED", "QUALITY_BLUR", "INJECTION_VIRTUAL_CAMERA", "SPOOF_MOIRE",
                   "MASK_CUE_EDGE", "LIVENESS_UNSURE", "MATCH_LOW", "SCHEDULE_OUTSIDE_WINDOW"]


def test_unknown_code_rejected():
    with pytest.raises(ValueError):
        order_codes(["ACCESS_OK", "TOTALLY_FINE"])
