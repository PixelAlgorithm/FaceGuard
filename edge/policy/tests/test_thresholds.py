"""Thresholds loader: YAML base = ONLINE, OFFLINE = deep_merge(base, offline.overrides)."""

import re

import pytest

from edge.policy.tests.builders import PROJECT_ROOT, THRESHOLDS_PATH
from edge.policy.thresholds import ConfigError, Thresholds


@pytest.fixture(scope="module")
def T():
    return Thresholds.load(THRESHOLDS_PATH)


def test_policy_version_matches_decision_policy_header(T):
    header = (PROJECT_ROOT / "docs" / "DECISION_POLICY.md").read_text(encoding="utf-8")
    m = re.search(r"Policy version: `([^`]+)`", header)
    assert m and T.policy_version == m.group(1) == "2026-11-14.3"
    # every other policy_version string in the doc (e.g. the response example) carries the same version
    assert set(re.findall(r'"policy_version": "([^"]+)"', header)) == {T.policy_version}


# ---------------------------------------------------------------- early cloud probe budget (swarm 2026-11-14)
def test_probe_deadline_is_its_own_key_and_the_no_probe_timeout_is_kept(T):
    """The probe deadline is measured FROM PROBE START (face lock); the frames-only path keeps 700 ms."""
    assert T.latency_budget_ms.rekognition_probe_deadline == 1500
    assert T.latency_budget_ms.rekognition_timeout == 700
    assert T.for_mode("OFFLINE").latency_budget_ms.rekognition_probe_deadline == 1500


@pytest.mark.parametrize("key", ["rekognition_probe_deadline", "rekognition_timeout"])
@pytest.mark.parametrize("bad", [None, 0, -1, "1500", True, float("nan"), float("inf")])
def test_cloud_budgets_must_be_positive_finite_numbers(T, key, bad):
    with pytest.raises(ConfigError):
        T.with_overrides({"latency_budget_ms": {key: bad}})


def test_missing_probe_deadline_is_a_config_error_not_a_default(T):
    raw = T.raw()
    del raw["latency_budget_ms"]["rekognition_probe_deadline"]
    with pytest.raises(ConfigError):
        Thresholds(raw)


def test_online_values_are_base_values(T):
    on = T.for_mode("ONLINE")
    assert on.liveness.pad.pass_min == 0.80
    assert on.liveness.flash.pass_min_r == 0.70
    assert on.liveness.flash.ambient_exception_enabled is True
    assert on.match.local.allow_min_cosine == 0.50
    assert on.match.local.min_margin_top1_top2 == 0.10


def test_offline_deep_merges_overrides_without_dropping_siblings(T):
    off = T.for_mode("OFFLINE")
    assert off.mode == "OFFLINE"
    assert off.liveness.pad.pass_min == 0.85
    assert off.liveness.pad.fail_max == 0.30  # sibling kept, deny threshold unchanged
    assert off.liveness.pad.strong_live == 0.90
    assert off.liveness.flash.pass_min_r == 0.75
    assert off.liveness.flash.ambient_exception_enabled is False
    assert off.liveness.flash.min_amplitude == T.liveness.flash.min_amplitude  # sibling kept (YAML value)
    assert off.liveness.flash.lag_max_frames == T.liveness.flash.lag_max_frames
    assert off.match.local.allow_min_cosine == 0.55
    assert off.match.local.min_margin_top1_top2 == 0.15
    assert off.match.local.deny_below_cosine == 0.30
    assert off.offline.auto_allow_max_risk == "medium"


def test_for_mode_is_idempotent_and_reversible(T):
    off = T.for_mode("OFFLINE")
    assert off.for_mode("OFFLINE").liveness.pad.pass_min == 0.85
    assert off.for_mode("ONLINE").liveness.pad.pass_min == 0.80


def test_unknown_mode_rejected(T):
    with pytest.raises(ConfigError):
        T.for_mode("HALF_ONLINE")


def test_missing_key_raises_config_error(T):
    with pytest.raises(ConfigError):
        _ = T.liveness.pad.no_such_key


def test_with_overrides_patches_base_and_offline_view(T):
    patched = T.with_overrides({"schedule": {"high_risk_requires_stepup_online": False}})
    assert patched.schedule.high_risk_requires_stepup_online is False
    assert patched.for_mode("OFFLINE").schedule.high_risk_requires_stepup_online is False
    assert T.schedule.high_risk_requires_stepup_online is True  # original untouched


def test_offline_override_that_loosens_a_pass_bar_is_rejected(T):
    with pytest.raises(ConfigError):
        T.with_overrides({"offline": {"overrides": {"liveness": {"pad": {"pass_min": 0.70}}}}})


def test_offline_override_cannot_enable_ambient_exception(T):
    with pytest.raises(ConfigError):
        T.with_overrides({"offline": {"overrides": {"liveness": {"flash": {"ambient_exception_enabled": True}}}}})


def test_invalid_auto_allow_risk_rejected(T):
    with pytest.raises(ConfigError):
        T.with_overrides({"offline": {"auto_allow_max_risk": "extreme"}})


def test_unparsable_yaml_raises_config_error(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("quality: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        Thresholds.load(p)


def test_missing_section_raises_config_error(tmp_path):
    p = tmp_path / "partial.yaml"
    p.write_text('policy_version: "x"\nquality: {}\n', encoding="utf-8")
    with pytest.raises(ConfigError):
        Thresholds.load(p)


def test_cfg_is_a_mapping_usable_by_stdlib_only_code(T):
    sched = T.schedule
    assert sched["grace_minutes"] == 15
    assert dict(sched)["grace_minutes_high_risk"] == 0


# ---------------------------------------------------------------- challenge action lists (audit 2026-11-14)
@pytest.mark.parametrize("deform,second", [
    ([], ["BLINK"]),  # no deformation at all
    (["BLINK"], ["TURN_LEFT"]),  # blink-only: eye-cut paper masks let real eyes blink
    (["SMILE", "WINK"], ["BLINK"]),  # unknown action
    ("SMILE", ["BLINK"]),  # not a list
    (["SMILE"], ["SMILE"]),  # a deformation is not a secondary action
    (["SMILE"], []),  # steps 2 needs a secondary action
])
def test_challenge_action_lists_are_validated_at_load(deform, second):
    import copy as _copy

    from edge.policy.tests.builders import base_thresholds

    raw = base_thresholds().raw()
    raw["challenge"]["deformation_actions"], raw["challenge"]["secondary_actions"] = deform, second
    with pytest.raises(ConfigError, match="challenge"):
        Thresholds(_copy.deepcopy(raw))


def test_an_offline_override_cannot_make_the_challenge_blink_only():
    import copy as _copy

    from edge.policy.tests.builders import base_thresholds

    raw = base_thresholds().raw()
    raw["offline"].setdefault("overrides", {}).setdefault("challenge", {})["deformation_actions"] = ["BLINK"]
    with pytest.raises(ConfigError, match="deformation_actions"):
        Thresholds(_copy.deepcopy(raw))
