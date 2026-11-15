"""Unit semantics of quality / injection / liveness / identity edges (fail-secure on missing data)."""

from __future__ import annotations

import math

import pytest

from edge.policy.identity import identity_match
from edge.policy.injection import injection_check
from edge.policy.liveness import liveness_fusion
from edge.policy.quality import quality_gate
from edge.policy.signals import CameraMeta
from edge.policy.tests.builders import OB, THRESHOLDS_PATH, B
from edge.policy.thresholds import Thresholds

T = Thresholds.load(THRESHOLDS_PATH).with_overrides({"liveness": {"flash": {"enforce": True}},  # doc baseline
                                                     "injection": {"unknown_label_is_unsure": True}})
TOFF = T.for_mode("OFFLINE")
F = T.liveness.flash  # flash bars read from YAML (lead calibration 2026-11-14)
WEAK_AMP = float(F.min_amplitude) - 0.5


def live(scn, mode="ONLINE", t=None, inj="PASS"):
    s = scn.signals()
    tm = (t or scn.thresholds()).for_mode(mode)
    return liveness_fusion(s.frames, s, inj, tm, mode)


def set_(scn, **kw):
    for k, v in kw.items():
        setattr(scn, k, v)
    return scn


# ---------------------------------------------------------------- liveness
def test_ambient_exception_needs_clean_device_and_low_moire_r12():
    weak = dict(B().flash, amplitude=WEAK_AMP, r=0.10)
    assert live(set_(B(), flash=weak)).status == "PASS"
    assert live(set_(B(), flash=weak, device=[(0.26, 0.3)] * 5)).signals["flash"] == "UNSURE"
    assert live(set_(B(), flash=weak, moire=[0.45] * 5)).signals["flash"] == "UNSURE"


def test_ambient_exception_is_code_enforced_online_only():
    """P6: even if a thresholds object claimed the exception is enabled, OFFLINE never applies it."""
    scn = set_(B(), flash=dict(B().flash, amplitude=WEAK_AMP, r=0.10))
    s = scn.signals()
    online_cfg = T.for_mode("ONLINE")  # ambient_exception_enabled: true
    assert liveness_fusion(s.frames, s, "PASS", online_cfg, "ONLINE").status == "PASS"
    assert liveness_fusion(s.frames, s, "PASS", online_cfg, "OFFLINE").status == "UNSURE"


def test_missing_flash_is_unsure_not_pass():
    assert live(set_(B(), flash=None)).status == "UNSURE"


def test_non_flash_accessibility_path_requires_challenge():
    res = live(set_(B(), flash_enabled=False))
    assert res.status == "UNSURE" and res.unsure_codes == ("LIVENESS_UNSURE",)


def test_flash_disabled_globally_is_not_available_and_needs_a_challenge_L25():
    t = T.with_overrides({"liveness": {"flash": {"enabled": False}}})
    res = live(set_(B(), flash=None), t=t)
    assert res.status == "UNSURE" and res.unsure_codes == ("LIVENESS_UNSURE",)
    assert res.signals["flash"] == "NOT_AVAILABLE"
    assert live(set_(B(), flash=None, moire=[0.8] * 5), t=t).hard_codes == ("SPOOF_MOIRE",)  # flash != PASS


@pytest.mark.parametrize(
    "delta,expected",
    [
        ({"lag_std_frames": float(F.lag_max_std_frames) + 0.5}, "UNSURE"),
        ({"lag_std_frames": float(F.lag_max_std_frames)}, "PASS"),
        ({"lag_frames": float(F.lag_max_frames)}, "PASS"),
        ({"lag_frames": float(F.lag_max_frames) + 1}, "FAIL"),
        ({"amplitude": float(F.min_amplitude)}, "PASS"),
        ({"order_ok": False}, "FAIL"),
        ({"order_ok": None}, "UNSURE"),
        ({"lag_frames": None}, "UNSURE"),
        ({"r": None}, "UNSURE"),
        ({"amplitude": math.nan}, "UNSURE"),
        ({"r": 0.30}, "UNSURE"),  # 0.30 <= r < 0.70
        ({"r": 0.2999}, "FAIL"),
        ({"r": 0.70}, "PASS"),
        ({"lag_frames": 3.0}, "PASS"),
        ({"lag_frames": -1.0}, "FAIL"),
    ],
)
def test_flash_zones(delta, expected):
    res = live(set_(B(), flash=dict(B().flash, **delta)))
    assert res.signals["flash"] == expected


def test_offline_flash_bar_is_stricter():
    scn = set_(OB(), flash=dict(B().flash, r=0.72))
    assert live(scn, "OFFLINE").signals["flash"] == "UNSURE"
    assert live(set_(B(), flash=dict(B().flash, r=0.72))).signals["flash"] == "PASS"


def test_pad_missing_model_output_never_counts_as_pass():
    scn = B()
    s = scn.signals()
    for f in s.frames[:3]:
        object.__setattr__(f, "pad_v1se", None)
    res = liveness_fusion(s.frames, s, "PASS", T, "ONLINE")
    assert res.signals["pad"] == "UNSURE"


def test_pad_nan_and_out_of_range_are_missing():
    scn = set_(B(), pad=[math.nan, 1.7, 0.95, 0.93, 0.94])
    assert live(scn).signals["pad"] == "PASS"  # 3 valid passing frames remain
    scn = set_(B(), pad=[math.nan, 1.7, math.inf, 0.93, 0.94])
    assert live(scn).signals["pad"] == "UNSURE"


def test_pad_zones_round2_r11():
    assert live(set_(B(), pad=[0.1, 0.9, 0.9, 0.9, 0.9])).signals["pad"] == "PASS"  # <= 1 spoof-like frame
    assert live(set_(B(), pad=[0.1, 0.2, 0.9, 0.9, 0.9])).signals["pad"] == "UNSURE"  # 2 spoof-like frames
    assert live(set_(B(), pad=[0.1, 0.2, 0.3, 0.9, 0.9])).signals["pad"] == "FAIL"  # strict majority


def test_moire_missing_is_unsure():
    assert live(set_(B(), moire=[None] * 5)).signals["moire"] == "UNSURE"


def test_moire_uses_worst_frame():
    assert live(set_(B(), moire=[0.1, 0.1, 0.1, 0.1, 0.5])).signals["moire"] == "UNSURE"


def test_device_high_conf_without_containment_is_unsure():
    res = live(set_(B(), device=[(0.62, 0.5)] * 5))
    assert res.signals["device"] == "UNSURE" and not res.hard_codes


def test_device_single_frame_confident_containment_is_fail():
    res = live(set_(B(), device=[(0, 0)] * 4 + [(0.45, 0.85)]))
    assert res.hard_codes == ("SPOOF_DEVICE_DETECTED",)


@pytest.mark.parametrize(
    "delta,expected",
    [
        ({"d1_plane_rms_mm": 6.0}, "UNSURE"),  # PASS needs > 6
        ({"d1_plane_rms_mm": 3.0}, "UNSURE"),
        ({"d1_plane_rms_mm": 2.99}, "FAIL"),
        ({"d2_quad_rms_mm": 4.0}, "UNSURE"),
        ({"d2_quad_rms_mm": 1.9}, "FAIL"),
        ({"d3_nose_relief_mm": 15.0}, "PASS"),  # PASS is >= 15
        ({"d3_nose_relief_mm": 8.0}, "UNSURE"),
        ({"d3_nose_relief_mm": 7.9}, "FAIL"),
        ({"d0_valid_ratio": 0.5}, "UNSURE"),
        ({"d4_ipd_mm": 30.0, "absolute": False}, "PASS"),  # relative depth: D4 skipped
        ({"d4_ipd_mm": None}, "UNSURE"),
        ({"d1_plane_rms_mm": None}, "UNSURE"),
    ],
)
def test_depth_zones(delta, expected):
    assert live(B().depth_on(**delta)).signals["depth"] == expected


def test_depth_ignored_when_disabled_or_unavailable():
    scn = B()
    scn.depth = {"available": True, "d0_valid_ratio": 0.9, "d1_plane_rms_mm": 1.0}
    assert live(scn).signals["depth"] == "NOT_AVAILABLE"  # depth.enabled false in config
    scn = B().depth_on()
    scn.depth = {"available": False}
    assert live(scn).signals["depth"] == "NOT_AVAILABLE"


def test_spectral_cue_only_when_enabled():
    scn = set_(B(), flash=dict(B().flash, skin_score=0.1))
    assert live(scn).mask_codes == ()
    t = T.with_overrides({"liveness": {"mask": {"spectral_enabled": True}}})
    assert live(scn, t=t).strong_mask_codes == ("MASK_CUE_SPECTRAL",)


def test_injection_unsure_marks_liveness_unsure():
    assert live(B(), inj="UNSURE").unsure_codes == ("LIVENESS_UNSURE",)


# ---------------------------------------------------------------- quality
def test_quality_nan_luma_is_low_light():
    q = quality_gate(set_(B(), luma=[math.nan] * 5).signals().frames, None, T)
    assert q.codes == ("QUALITY_LOW_LIGHT",)


def test_quality_overexposed_backlight_is_low_light():
    s = B().signals()
    for f in s.frames:
        object.__setattr__(f.quality, "overexposed_frac", 0.4)
    assert quality_gate(s.frames, None, T).codes == ("QUALITY_LOW_LIGHT",)


def test_quality_no_face_is_pose():
    s = B().signals()
    for f in s.frames:
        object.__setattr__(f.quality, "face_count", 0)
    assert quality_gate(s.frames, None, T).codes == ("QUALITY_POSE",)


def test_quality_small_background_face_is_tolerated():
    q = quality_gate(set_(B(), secondary=[0.3] * 5).signals().frames, None, T)
    assert q.codes == ()


def test_quality_codes_deduplicated_and_ordered():
    q = quality_gate(set_(B(), luma=[40.0] * 5, lapvar=[30.0] * 5, yaw=[40.0] * 5).signals().frames, None, T)
    assert q.codes == ("QUALITY_LOW_LIGHT", "QUALITY_BLUR", "QUALITY_POSE")


def test_too_few_frames_is_invalid_input():
    s = B().signals()
    with pytest.raises(ValueError):
        quality_gate(s.frames[:2], None, T)
    with pytest.raises(ValueError):
        quality_gate([], None, T)


def test_too_few_frames_through_engine_is_system_error():
    from edge.policy.engine import evaluate

    scn = B()
    s, ctx, mode, now, t = scn.build()
    s2 = s.model_copy(update={"frames": s.frames[:2]})
    res = evaluate(s2, ctx, mode, now, cfg=t)
    assert res.decision == "DENY" and res.reason_codes == ("SYSTEM_ERROR",)


# ---------------------------------------------------------------- injection
def cam(label="FaceTime HD Camera", ts=(0, 33, 66, 99, 132), virtual=False):
    return CameraMeta(camera_label=label, frame_timestamps_ms=list(ts), virtual_camera_suspected=virtual)


@pytest.mark.parametrize(
    "camera,expected",
    [
        (cam(), "PASS"),
        (cam(label="ManyCam Video Source"), "FAIL"),
        (cam(label="Logitech USB Webcam"), "PASS"),
        (cam(label="Some Capture Device"), "UNSURE"),
        (cam(virtual=True), "FAIL"),
        (cam(ts=(0, 33, 33, 99, 132)), "FAIL"),  # non-monotonic
        (cam(ts=(0, 33, 66, 600, 633)), "FAIL"),  # interval > 400 ms
        (cam(ts=(0, 10, 20, 30, 40)), "FAIL"),  # interval < 15 ms
        (cam(ts=()), "PASS"),  # falls back to the frames' own ts_ms (33 ms apart)
    ],
)
def test_injection(camera, expected):
    assert injection_check(camera, B().signals().frames, T) == expected


def test_injection_unknown_label_pass_when_configured():
    t = T.with_overrides({"injection": {"unknown_label_is_unsure": False}})
    assert injection_check(cam(label=""), B().signals().frames, t) == "PASS"


# ---------------------------------------------------------------- identity
def ident(scn, mode="ONLINE"):
    s = scn.signals()
    return identity_match(s.frames, s.cloud_match, T.for_mode(mode), mode, s.template_cache_age_h)


def test_top2_none_means_no_competing_user():
    res = ident(set_(OB(), local=[("u_7a8b", 0.70, None)] * 5), "OFFLINE")
    assert res.status == "PASS"


def test_online_without_usable_local_matcher_never_passes():
    assert ident(set_(B(), cache_age_h=None)).codes == ("MATCH_AMBIGUOUS",)
    assert ident(set_(B(), local=[(None, None, None)] * 5)).codes == ("MATCH_AMBIGUOUS",)


def test_offline_unknown_cache_age_is_not_enrolled():
    assert ident(set_(OB(), cache_age_h=None), "OFFLINE").codes == ("NOT_ENROLLED",)


def test_offline_identity_switch_is_ambiguous():
    scn = set_(OB(), local=[("u_3c4d", 0.72, 0.41)] * 4 + [("u_1a2b", 0.66, 0.40)])
    assert ident(scn, "OFFLINE").codes == ("MATCH_AMBIGUOUS",)


def test_rekognition_is_authoritative_for_failure():
    res = ident(set_(B(), cloud={"ok": True, "top1_user": "u_3c4d", "top1_similarity": 79.9}))
    assert res.status == "FAIL" and res.user_id == "u_3c4d"


def test_rekognition_boundaries():
    assert ident(set_(B(), cloud={"ok": True, "top1_user": "u_3c4d", "top1_similarity": 99.0})).status == "PASS"
    assert ident(set_(B(), cloud={"ok": True, "top1_user": "u_3c4d", "top1_similarity": 98.99})).codes == ("MATCH_LOW",)
    assert ident(set_(B(), cloud={"ok": True, "top1_user": "u_3c4d", "top1_similarity": 80.0})).codes == ("MATCH_LOW",)
    amb = set_(B(), cloud={"ok": True, "top1_user": "u_3c4d", "top1_similarity": 99.5, "runner_up_similarity": 80.0})
    assert ident(amb).codes == ("MATCH_AMBIGUOUS",)


def test_local_boundaries_offline():
    assert ident(set_(OB(), local=[("u_3c4d", 0.55, 0.40)] * 5), "OFFLINE").status == "PASS"
    assert ident(set_(OB(), local=[("u_3c4d", 0.30, 0.10)] * 5), "OFFLINE").codes == ("MATCH_LOW",)
    assert ident(set_(OB(), local=[("u_3c4d", 0.2999, 0.10)] * 5), "OFFLINE").codes == ("NOT_ENROLLED",)


@pytest.mark.parametrize("n_div", [4, 5])  # 5 frames spread over the window: spacing = window/4 or window/5
def test_capture_window_spacing_passes_injection_bounds(n_div):
    """liveness.flash.duration_ms (700 ms, operator speed request) with quality.frames_per_attempt frames must
    stay inside injection.[min,max]_frame_interval_ms, and the flash must respect max_changes_per_s."""
    window, n = float(T.liveness.flash.duration_ms), int(T.quality.frames_per_attempt)
    spacing = window / n_div
    assert T.injection.min_frame_interval_ms <= spacing <= T.injection.max_frame_interval_ms
    ts = [1_000 + round(spacing * i) for i in range(n)]
    assert injection_check(cam(ts=ts), B().set(ts=ts).signals().frames, T) == "PASS"
    assert (int(T.liveness.flash.colours_max) - 1) / (window / 1000) <= T.liveness.flash.max_changes_per_s
