"""policy-fixes: offline overrides may only tighten (F08) + the shipped hardening knobs (F13, D9, F06, EO-11)."""

from __future__ import annotations

import copy

import pytest

from edge.policy.tests.builders import THRESHOLDS_PATH
from edge.policy.thresholds import ConfigError, Thresholds, deep_merge

T = Thresholds.load(THRESHOLDS_PATH)


def _with_offline(patch: dict) -> Thresholds:
    raw = copy.deepcopy(T.raw())
    raw["offline"]["overrides"] = deep_merge(raw["offline"].get("overrides") or {}, patch)
    return Thresholds(raw)


@pytest.mark.parametrize("patch", [
    {"liveness": {"device_detector": {"fail_conf": 0.99}}},           # phone in frame would pass offline
    {"liveness": {"moire": {"fail_score": 0.99}}},
    {"liveness": {"mask": {"strong_cue_deny_count": 9}}},
    {"liveness": {"depth": {"d1_plane_rms_fail_mm": 0.1}}},
    {"stepup": {"methods": {"offline_high_risk": ["CARD"]}}},
    {"stepup": {"methods": {"cache_untrusted": ["CARD", "TOTP"]}}},  # EXPIRED bundle -> TOTP (breaks P5)
    {"stepup": {"max_attempts_per_step": 9}},
    {"rate_limit": {"enabled": False}},
    {"match": {"local": {"require_same_identity_first_last_frame": False}}},
    {"schedule": {"high_risk_requires_stepup_online": False}},
    {"fallback": {"staff_override": {"max_failures": 99}}},
    {"injection": {"virtual_camera_label_patterns": []}},
])
def test_F08_loosening_or_unlisted_offline_overrides_are_config_errors(patch):
    with pytest.raises(ConfigError, match="offline override"):
        _with_offline(patch)


def test_F08_documented_tightening_overrides_still_load():
    off = _with_offline({"liveness": {"pad": {"pass_min": 0.9, "min_pass_frames": 4}},
                         "match": {"local": {"allow_min_cosine": 0.6}}}).for_mode("OFFLINE")
    assert off.liveness.pad.pass_min == 0.9 and off.match.local.allow_min_cosine == 0.6


def test_F13_public_kiosk_ships_without_detailed_reasons():
    assert T.ui.show_detailed_reasons is False


def test_hardening_knobs_are_shipped_and_never_looser_than_before():
    so = T.fallback.staff_override
    assert so.max_failures <= 3 and so.lockout_s >= 300
    assert so.device_max_failures <= 10 and so.device_window_s >= 300 and so.device_lockout_s >= 300
    assert so.code_length >= 10 and list(so.legacy_code_lengths) == [8]
    for m in ("totp", "card"):
        assert T.fallback[m].max_failures <= 5 and T.fallback[m].lockout_s >= 300
    c = T.connectivity
    assert 1 <= c.forced_offline_default_min <= c.forced_offline_max_min <= 240


@pytest.mark.parametrize("path,bad", [
    (("fallback", "staff_override", "legacy_code_lengths"), [8, "x"]),
    (("fallback", "staff_override", "device_max_failures"), 0),
    (("fallback", "totp", "max_failures"), -1),
    (("connectivity", "forced_offline_max_min"), 999),
    (("connectivity", "forced_offline_default_min"), 0),
])
def test_hardening_knobs_are_validated(path, bad):
    raw = copy.deepcopy(T.raw())
    cur = raw
    for p in path[:-1]:
        cur = cur[p]
    cur[path[-1]] = bad
    with pytest.raises(ConfigError):
        Thresholds(raw)


def test_DE05_non_physical_depth_geometry_is_unsure_not_pass():
    from edge.policy.tests.builders import DEPTH_PASS, B

    T_on = {"liveness": {"depth": {"enabled": True}}}
    ok = B().cfg(T_on).set(depth=dict(DEPTH_PASS)).evaluate()
    assert ok.to_response()["scores"]["signals"]["depth"] == "PASS"
    for key, bad in (("d1_plane_rms_mm", 251.0), ("d2_quad_rms_mm", 99.0), ("d3_nose_relief_mm", 156.0)):
        d = B().cfg(T_on).set(depth={**DEPTH_PASS, key: bad}).evaluate()
        assert d.to_response()["scores"]["signals"]["depth"] == "UNSURE", key
        assert d.decision != "ALLOW"


@pytest.mark.parametrize("path,bad", [
    (("fallback", "staff_override", "code_length"), 4),
    (("fallback", "staff_override", "legacy_code_lengths"), [6]),
    (("offline", "overrides"), [1]),
])
def test_review_code_length_floor_and_non_mapping_overrides(path, bad):
    raw = copy.deepcopy(T.raw())
    cur = raw
    for p in path[:-1]:
        cur = cur[p]
    cur[path[-1]] = bad
    with pytest.raises(ConfigError):
        Thresholds(raw)


def test_offline_cannot_narrow_the_challenge_action_pools():
    with pytest.raises(ConfigError, match="offline override"):
        _with_offline({"challenge": {"deformation_actions": ["SMILE"]}})
    with pytest.raises(ConfigError, match="offline override"):
        _with_offline({"challenge": {"secondary_actions": ["TURN_LEFT"]}})
