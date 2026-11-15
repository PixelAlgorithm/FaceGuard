"""D0-D4 / M1-M3 measurements on synthetic TrueDepth-like maps (geometry is known, so are the answers).

Zones are always read from config/thresholds.yaml through classify(); no threshold is hard-coded here.
"""

from __future__ import annotations

import time

import numpy as np
import pytest

from depth import synth
from depth.checks import (
    SIGNAL_KEYS,
    classify,
    compute_depth_checks,
    compute_m1,
    depth_score,
    make_template,
)
from depth.tests.conftest import noisy


def run(
    frame: synth.SynthFrame,
    cam: synth.SynthCamera,
    cfg: dict,
    *,
    accuracy: str = "absolute",
    depth=None,
    depth_type: str = "depth",
    template=None,
    diag: dict | None = None,
) -> dict:
    return compute_depth_checks(
        frame.depth_m if depth is None else depth,
        depth_type=depth_type,
        intrinsics=cam.intrinsics(
            640, 480
        ),  # intrinsics given at a larger reference size (as AVFoundation does)
        face_box_norm=frame.face_box_norm,
        landmarks_norm=frame.landmarks_norm,
        cfg=cfg,
        template=template,
        accuracy=accuracy,
        diagnostics=diag,
    )


# ------------------------------------------------------------------------------------------- contract
def test_signal_has_exactly_the_depthsignal_fields(cam, cfg, rng):
    sig = run(noisy(synth.scene_face(cam), rng), cam, cfg)
    assert tuple(sig) == SIGNAL_KEYS
    assert sig["d5_disagree"] is None and sig["m1_mouth_residual_mm"] is None
    signals = pytest.importorskip("edge.policy.signals")  # policy-engine model is extra="forbid"
    signals.DepthSignal(**sig)
    signals.DepthSignal(**run(synth.scene_print(cam), cam, cfg, accuracy="relative"))


# --------------------------------------------------------------------------------------------- prints
def test_flat_print_fails_d1_d2_d3(cam, cfg, rng):
    sig = run(noisy(synth.scene_print(cam), rng), cam, cfg)
    c = classify(sig, cfg)
    assert sig["d1_plane_rms_mm"] < 1.5  # ~sensor noise
    assert c["checks"]["d1"] == c["checks"]["d2"] == c["checks"]["d3"] == "FAIL"
    assert c["overall"] == "FAIL" and c["codes"] == ["SPOOF_FLAT_DEPTH"]
    assert c["checks"]["d4"] == "PASS"  # a life-size print has a plausible IPD: D4 alone cannot catch it


@pytest.mark.parametrize("yaw,pitch", [(35.0, 20.0), (-25.0, -10.0)])
def test_tilted_print_still_flat(cam, cfg, rng, yaw, pitch):
    sig = run(noisy(synth.scene_print(cam, pose=synth.Pose(yaw_deg=yaw, pitch_deg=pitch)), rng), cam, cfg)
    c = classify(sig, cfg)
    assert c["checks"]["d1"] == "FAIL" and c["checks"]["d3"] == "FAIL"  # tilt-invariant (plane frame)
    assert c["overall"] == "FAIL"


@pytest.mark.parametrize("radius,axis", [(50.0, "vertical"), (80.0, "horizontal")])
def test_bent_print_passes_d1_but_fails_d2(cam, cfg, rng, radius, axis):
    sig = run(noisy(synth.scene_print(cam, bend_radius_mm=radius, bend_axis=axis), rng), cam, cfg)
    c = classify(sig, cfg)
    assert c["checks"]["d1"] == "PASS"  # bending defeats the plane test ...
    assert c["checks"]["d2"] == "FAIL"  # ... but a cylinder is (almost) quadratic
    assert c["overall"] == "FAIL" and "SPOOF_FLAT_DEPTH" in c["codes"]


# ------------------------------------------------------------------------------------------ live face
def test_face_passes_d1_d2_d3_d4(cam, cfg, rng):
    sig = run(noisy(synth.scene_face(cam), rng), cam, cfg)
    c = classify(sig, cfg)
    assert c["checks"]["d0"] == c["checks"]["d1"] == c["checks"]["d2"] == c["checks"]["d3"] == "PASS", sig
    assert sig["d1_plane_rms_mm"] > 8.0  # research note: real faces ~8-15 mm
    assert 20.0 < sig["d3_nose_relief_mm"] < 35.0  # designed nose: ~27 mm above the cheeks
    assert sig["d4_ipd_mm"] == pytest.approx(63.0, abs=3.0)  # designed IPD 63 mm
    assert c["checks"]["d4"] == "PASS" and c["overall"] == "PASS" and c["codes"] == []
    assert depth_score(sig, cfg) == pytest.approx(1.0, abs=0.15)


@pytest.mark.parametrize(
    "pose,width,height",
    [
        (synth.Pose(yaw_deg=20.0), 320, 240),
        (synth.Pose(yaw_deg=-20.0, pitch_deg=10.0), 320, 240),
        (synth.Pose(distance_mm=300.0), 320, 240),
        (synth.Pose(distance_mm=500.0), 320, 240),
        (synth.Pose(roll_deg=15.0), 640, 480),
    ],
)
def test_face_robust_to_pose_distance_resolution(cfg, rng, pose, width, height):
    cam = synth.SynthCamera(width, height)
    sig = run(noisy(synth.scene_face(cam, pose=pose), rng), cam, cfg)
    c = classify(sig, cfg)
    assert c["checks"]["d1"] == "PASS" and c["checks"]["d3"] == "PASS", sig
    assert c["checks"]["d2"] != "FAIL" and c["checks"]["d4"] == "PASS"
    assert "SPOOF_FLAT_DEPTH" not in c["codes"]


def test_face_robust_to_holes_zeros_and_blobs(cam, cfg, rng):
    f = synth.scene_face(cam)
    f.depth_m = synth.add_sensor_noise(f.depth_m, rng, hole_fraction=0.25, zero_fraction=0.05)
    x, y, w, h = f.face_box_norm
    u, v = int((x + 0.25 * w) * cam.width), int((y + 0.6 * h) * cam.height)
    f.depth_m[v - 6 : v + 6, u - 6 : u + 6] = np.nan  # glasses/IR-dark blob on one cheek region
    sig = run(f, cam, cfg)
    c = classify(sig, cfg)
    assert 0.55 < sig["d0_valid_ratio"] < 0.75
    assert c["checks"]["d1"] == "PASS" and c["checks"]["d3"] == "PASS", sig
    assert "SPOOF_FLAT_DEPTH" not in c["codes"]


def test_multi_frame_median_beats_single_frame(cam, cfg, rng):
    clean = synth.scene_print(cam)
    stack = np.stack(
        [synth.add_sensor_noise(clean.depth_m, rng, sigma_mm=2.0, hole_fraction=0.30) for _ in range(3)]
    )
    single = run(clean, cam, cfg, depth=stack[0])
    fused = run(clean, cam, cfg, depth=stack)
    assert fused["d1_plane_rms_mm"] < single["d1_plane_rms_mm"]
    assert fused["d0_valid_ratio"] > single["d0_valid_ratio"]  # holes rarely coincide across frames
    assert classify(fused, cfg)["checks"]["d1"] == "FAIL"


def test_disparity_float16_matches_metric_depth(cam, cfg, rng):
    f = noisy(synth.scene_face(cam), rng)
    disp16 = np.frombuffer(synth.to_wire(f.depth_m, "disparity", "float16"), "<f2").reshape(f.depth_m.shape)
    a = run(f, cam, cfg, depth=f.depth_m, depth_type="depth")
    b = run(f, cam, cfg, depth=disp16, depth_type="disparity")
    for k in ("d1_plane_rms_mm", "d2_quad_rms_mm", "d3_nose_relief_mm", "d4_ipd_mm"):
        assert b[k] == pytest.approx(a[k], abs=0.5), k
    assert b["d0_valid_ratio"] == pytest.approx(a["d0_valid_ratio"], abs=0.01)


# -------------------------------------------------------------------------------------------- D4 scale
def test_small_scale_face_fails_d4(cam, cfg, rng):
    f = noisy(synth.scene_face(cam, pose=synth.Pose(scale=0.35, distance_mm=300.0)), rng)
    sig = run(f, cam, cfg)
    c = classify(sig, cfg)
    assert sig["d4_ipd_mm"] == pytest.approx(63.0 * 0.35, abs=3.0)
    assert c["checks"]["d4"] == "FAIL" and "SPOOF_DEPTH_SCALE" in c["codes"] and c["overall"] == "FAIL"


def test_d4_needs_absolute_depth(cam, cfg, cfg_copy, rng):
    f = noisy(synth.scene_face(cam, pose=synth.Pose(scale=0.35, distance_mm=300.0)), rng)
    diag: dict = {}
    rel = run(f, cam, cfg, accuracy="relative", diag=diag)
    assert rel["absolute"] is False and rel["d4_ipd_mm"] is None
    assert diag["d4_ipd_mm_raw"] == pytest.approx(22.0, abs=3.0)  # still logged for calibration
    assert classify(rel, cfg)["checks"]["d4"] == "NA"
    unknown = run(f, cam, cfg, accuracy=None)
    assert unknown["absolute"] is False and unknown["d4_ipd_mm"] is None  # unknown accuracy = relative
    cfg_copy["liveness"]["depth"]["require_absolute_depth_for_d4"] = False
    assert run(f, cam, cfg_copy, accuracy="relative")["d4_ipd_mm"] is not None


def test_d4_skipped_without_real_intrinsics(cam, cfg, rng):
    f = noisy(synth.scene_face(cam), rng)
    diag: dict = {}
    sig = compute_depth_checks(
        f.depth_m,
        depth_type="depth",
        intrinsics=None,
        face_box_norm=f.face_box_norm,
        landmarks_norm=f.landmarks_norm,
        cfg=cfg,
        accuracy="absolute",
        diagnostics=diag,
    )
    assert diag["intrinsics_source"] == "default_fov" and sig["d4_ipd_mm"] is None
    assert classify(sig, cfg)["checks"]["d1"] == "PASS"  # D1-D3 barely depend on the focal length


# ------------------------------------------------------------------------------- D0 / missing inputs
def test_low_valid_ratio_asks_for_recapture(cam, cfg, rng):
    f = noisy(synth.scene_face(cam), rng, hole_fraction=0.75)
    sig = run(f, cam, cfg)
    c = classify(sig, cfg)
    assert sig["d0_valid_ratio"] < cfg["liveness"]["depth"]["d0_valid_fail_below"]
    assert c["overall"] == "RECAPTURE" and c["codes"] == ["QUALITY_DEPTH_INVALID"]


def test_mid_valid_ratio_is_unsure(cam, cfg, rng):
    f = noisy(synth.scene_face(cam), rng, hole_fraction=0.50)
    sig = run(f, cam, cfg)
    c = classify(sig, cfg)
    assert c["checks"]["d0"] == "UNSURE" and "LIVENESS_UNSURE" in c["codes"] and c["overall"] == "UNSURE"


@pytest.mark.parametrize(
    "depth,depth_type,box",
    [
        (np.zeros((240, 320), np.float32), "depth", None),  # no face box from Vision
        (np.ones((240, 320), np.float32) * 0.4, "depth", [0.4, 0.4, 0.0, 0.2]),  # degenerate box
        (np.ones((5,), np.float32), "depth", [0.3, 0.3, 0.3, 0.3]),  # wrong ndim
        (np.ones((240, 320), np.float32), "kinect", [0.3, 0.3, 0.3, 0.3]),  # unknown depth_type
        (None, "depth", [0.3, 0.3, 0.3, 0.3]),
    ],
)
def test_bad_or_missing_input_is_unavailable_never_raises(cfg, depth, depth_type, box):
    diag: dict = {}
    sig = compute_depth_checks(
        depth,
        depth_type=depth_type,
        intrinsics=None,
        face_box_norm=box,
        landmarks_norm=None,
        cfg=cfg,
        diagnostics=diag,
    )
    assert sig["available"] is False and all(
        sig[k] is None for k in SIGNAL_KEYS if k not in ("available", "absolute")
    )
    assert classify(sig, cfg)["overall"] == "NOT_AVAILABLE"


def test_all_invalid_depth_inside_face_box(cam, cfg):
    f = synth.scene_face(cam)
    sig = run(f, cam, cfg, depth=np.full_like(f.depth_m, np.nan))
    assert sig["available"] is True and sig["d0_valid_ratio"] == 0.0 and sig["d1_plane_rms_mm"] is None
    assert classify(sig, cfg)["overall"] == "RECAPTURE"


def test_box_only_never_counts_missing_checks_as_pass(cam, cfg, rng):
    f = noisy(synth.scene_face(cam, with_landmarks=False), rng)
    sig = run(f, cam, cfg)
    assert (
        sig["d1_plane_rms_mm"] is not None and sig["d3_nose_relief_mm"] is None and sig["d4_ipd_mm"] is None
    )
    c = classify(sig, cfg)
    assert c["checks"]["d3"] == "NA" and c["overall"] == "UNSURE" and "LIVENESS_UNSURE" in c["codes"]


# ---------------------------------------------------------------------------------------------- masks
def _m1(cam, cfg, neutral, challenge, diag=None):
    return compute_m1(
        neutral.depth_m,
        challenge.depth_m,
        neutral.face_box_norm,
        neutral.landmarks_norm,
        depth_type="depth",
        intrinsics=cam.intrinsics(),
        cfg=cfg,
        face_box_norm_challenge=challenge.face_box_norm,
        landmarks_norm_challenge=challenge.landmarks_norm,
        diagnostics=diag,
    )


def _face(cam, rng, **kw):
    return noisy(synth.scene_face(cam, rng=rng, landmark_jitter=0.0015, **kw), rng)


def test_m1_rigid_mask_is_rigid(cam, cfg, rng):
    neutral = _face(cam, rng)
    moved = _face(cam, rng, pose=synth.Pose(yaw_deg=3.0, tx_mm=2.0, ty_mm=-1.0, distance_mm=405.0))
    m1 = _m1(cam, cfg, neutral, moved)
    sig = {
        "available": True,
        "d0_valid_ratio": 0.9,
        "d1_plane_rms_mm": 10.0,
        "d2_quad_rms_mm": 5.0,
        "d3_nose_relief_mm": 25.0,
        **m1,
    }
    c = classify(sig, cfg, blendshape_moved=True)
    assert m1["m1_forehead_residual_mm"] < cfg["liveness"]["mask"]["m1_forehead_residual_max_mm"]
    assert c["checks"]["m1"] == "RIGID" and c["overall"] == "FAIL" and c["codes"] == ["MASK_CUE_RIGID"]
    assert classify(sig, cfg, blendshape_moved=False)["overall"] == "PASS"  # no movement asked: not a cue


@pytest.mark.parametrize("deform", [synth.open_mouth(), synth.smile()])
def test_m1_real_face_deforms(cam, cfg, rng, deform):
    diag: dict = {}
    m1 = _m1(cam, cfg, _face(cam, rng), _face(cam, rng, deform=deform), diag)
    mask_cfg = cfg["liveness"]["mask"]
    assert m1["m1_forehead_residual_mm"] < mask_cfg["m1_forehead_residual_max_mm"], diag
    assert m1["m1_mouth_residual_mm"] > mask_cfg["m1_mouth_residual_min_mm"], diag
    assert classify({"available": True, "d0_valid_ratio": 0.9, **m1}, cfg)["checks"]["m1"] == "DEFORMED"


def test_m1_unavailable_without_landmarks(cam, cfg, rng):
    a = noisy(synth.scene_face(cam, with_landmarks=False), rng)
    diag: dict = {}
    assert _m1(cam, cfg, a, a, diag) == {"m1_mouth_residual_mm": None, "m1_forehead_residual_mm": None}
    assert "NO_LANDMARKS" in diag["reason"]


def test_m2_eyehole_mask_step_vs_real_eyes(cam, cfg, rng):
    strong = cfg["liveness"]["mask"]["m2_depth_step_strong_mm"]
    mask = run(noisy(synth.scene_eyehole_mask(cam), rng), cam, cfg)
    face = run(noisy(synth.scene_face(cam), rng), cam, cfg)
    assert mask["m2_depth_step_mm"] >= strong > face["m2_depth_step_mm"]
    c = classify(mask, cfg)
    assert c["checks"]["m2"] == "STRONG" and c["overall"] == "UNSURE" and c["codes"] == ["MASK_CUE_EDGE"]


def test_m3_template_same_vs_other_face(cam, cfg, rng):
    enrol = noisy(synth.scene_face(cam), rng)
    tpl = make_template(
        enrol.depth_m,
        depth_type="depth",
        intrinsics=cam.intrinsics(),
        face_box_norm=enrol.face_box_norm,
        landmarks_norm=enrol.landmarks_norm,
        cfg=cfg,
    )
    assert tpl.shape == (64, 64) and np.isfinite(tpl).mean() > 0.8
    same = run(
        noisy(synth.scene_face(cam, pose=synth.Pose(yaw_deg=3.0, tx_mm=2.0)), rng), cam, cfg, template=tpl
    )
    other = run(noisy(synth.scene_face(cam, shape=synth.OTHER_FACE), rng), cam, cfg, template=tpl)
    assert same["m3_template_rms_mm"] < 3.0 < other["m3_template_rms_mm"]
    assert classify(same, cfg)["checks"]["m3"] == "NONE"
    assert run(enrol, cam, cfg)["m3_template_rms_mm"] is None  # no template -> not measured


def test_two_strong_mask_cues_deny(cfg):
    m = cfg["liveness"]["mask"]
    sig = {
        "available": True,
        "d0_valid_ratio": 0.9,
        "d1_plane_rms_mm": 10.0,
        "d2_quad_rms_mm": 5.0,
        "d3_nose_relief_mm": 25.0,
        "m2_depth_step_mm": m["m2_depth_step_strong_mm"] + 2,
        "m3_template_rms_mm": m["m3_template_rms_strong_mm"] + 1,
    }
    c = classify(sig, cfg)
    assert c["overall"] == "FAIL" and c["codes"] == ["MASK_CUE_EDGE", "MASK_CUE_SHAPE"]  # DECISION_POLICY M02


# ------------------------------------------------------------------------------------ config + speed
def test_zones_follow_config_not_code(cam, cfg, cfg_copy, rng):
    sig = run(noisy(synth.scene_face(cam), rng), cam, cfg)
    assert classify(sig, cfg)["checks"]["d1"] == "PASS"
    cfg_copy["liveness"]["depth"]["d1_plane_rms_fail_mm"] = sig["d1_plane_rms_mm"] + 1.0
    cfg_copy["liveness"]["depth"]["d1_plane_rms_pass_mm"] = sig["d1_plane_rms_mm"] + 5.0
    assert classify(sig, cfg_copy)["checks"]["d1"] == "FAIL"


def test_algo_override_via_config(cam, cfg_copy, rng):
    f = noisy(synth.scene_face(cam), rng)
    cfg_copy["liveness"]["depth"]["algo"] = {"z_max_m": 0.30}  # face at 0.40 m -> out of range
    sig = run(f, cam, cfg_copy)
    assert sig["d0_valid_ratio"] == 0.0


def test_latency_well_inside_depth_budget(cfg, rng):
    cam = synth.SynthCamera(640, 480)
    clean = synth.scene_face(cam)
    stack = np.stack([synth.add_sensor_noise(clean.depth_m, rng) for _ in range(3)])
    run(clean, cam, cfg, depth=stack)  # warm-up
    t0 = time.perf_counter()
    for _ in range(3):
        run(clean, cam, cfg, depth=stack)
    ms = (time.perf_counter() - t0) * 1000.0 / 3
    budget = cfg["latency_budget_ms"]["depth_max_wait"]
    assert ms < budget, f"{ms:.1f} ms per 640x480x3 attempt vs depth_max_wait {budget} ms"


def test_m1_uses_the_most_deformed_challenge_frame(cam, cfg, rng):
    """Capture timing: the challenge stack may straddle the expression (neutral, open, neutral)."""
    neutral = _face(cam, rng)
    frames = [_face(cam, rng), _face(cam, rng, deform=synth.open_mouth()), _face(cam, rng)]
    stack = np.stack([f.depth_m for f in frames])
    kw = {"depth_type": "depth", "intrinsics": cam.intrinsics(), "cfg": cfg}
    diag: dict = {}
    m1 = compute_m1(
        neutral.depth_m,
        stack,
        neutral.face_box_norm,
        neutral.landmarks_norm,
        face_box_norm_challenge=[f.face_box_norm for f in frames],
        landmarks_norm_challenge=[f.landmarks_norm for f in frames],
        diagnostics=diag,
        **kw,
    )
    assert diag["m1_frames"] == 3 and diag["m1_frame_index"] == 1, diag
    assert m1["m1_mouth_residual_mm"] > cfg["liveness"]["mask"]["m1_mouth_residual_min_mm"]

    one: dict = {}  # a single landmark set describes frame 0 only -> only frame 0 is measured
    compute_m1(
        neutral.depth_m,
        stack,
        neutral.face_box_norm,
        neutral.landmarks_norm,
        landmarks_norm_challenge=frames[0].landmarks_norm,
        diagnostics=one,
        **kw,
    )
    assert one["m1_frames"] == 1

    rigid_frames = [_face(cam, rng, pose=synth.Pose(yaw_deg=2.0 * k, tx_mm=float(k))) for k in range(3)]
    m1r = compute_m1(
        neutral.depth_m,
        np.stack([f.depth_m for f in rigid_frames]),
        neutral.face_box_norm,
        neutral.landmarks_norm,
        face_box_norm_challenge=[f.face_box_norm for f in rigid_frames],
        landmarks_norm_challenge=[f.landmarks_norm for f in rigid_frames],
        **kw,
    )
    assert classify({"available": True, "d0_valid_ratio": 0.9, **m1r}, cfg)["checks"]["m1"] == "RIGID", m1r


def test_m1_skips_challenge_frames_without_their_own_landmarks(cam, cfg, rng):
    """Per-frame mode: a frame Vision missed (null landmarks) is not measured with the stale neutral
    set, so a rigid mask cannot look deformed through missing landmarks; none at all -> M1 unavailable."""
    neutral = _face(cam, rng)
    rigid = [_face(cam, rng, pose=synth.Pose(yaw_deg=2.0 * k, tx_mm=float(k))) for k in range(3)]
    stack = np.stack([f.depth_m for f in rigid])
    kw = {"depth_type": "depth", "intrinsics": cam.intrinsics(), "cfg": cfg}
    some: dict = {}
    m1 = compute_m1(
        neutral.depth_m,
        stack,
        neutral.face_box_norm,
        neutral.landmarks_norm,
        face_box_norm_challenge=[f.face_box_norm for f in rigid],
        landmarks_norm_challenge=[rigid[0].landmarks_norm, None, None],
        diagnostics=some,
        **kw,
    )
    assert len(some["m1_per_frame"]) == 1 and some["m1_frame_index"] == 0, some
    assert classify({"available": True, "d0_valid_ratio": 0.9, **m1}, cfg)["checks"]["m1"] != "DEFORMED", m1
    none: dict = {}
    m1n = compute_m1(
        neutral.depth_m,
        stack,
        neutral.face_box_norm,
        neutral.landmarks_norm,
        face_box_norm_challenge=[f.face_box_norm for f in rigid],
        landmarks_norm_challenge=[None, None, None],
        diagnostics=none,
        **kw,
    )
    assert m1n["m1_mouth_residual_mm"] is None and none["reason"] == "CHALLENGE_FRAME_NO_LANDMARKS", none


def test_m1_lip_corner_swap_is_not_motion(cam, cfg, rng):
    """Vision's orientation can flip between frames and swap left/right lip corners: not deformation."""
    neutral = _face(cam, rng)
    same = _face(cam, rng)
    swapped = dict(same.landmarks_norm)
    lm = same.landmarks_norm
    swapped["mouth_left"], swapped["mouth_right"] = lm["mouth_right"], lm["mouth_left"]
    kw = {"depth_type": "depth", "intrinsics": cam.intrinsics(), "cfg": cfg}
    ref: dict = {}
    args = (neutral.depth_m, same.depth_m, neutral.face_box_norm, neutral.landmarks_norm)
    m1_ref = compute_m1(*args, face_box_norm_challenge=same.face_box_norm, landmarks_norm_challenge=lm,
                        diagnostics=ref, **kw)
    sw: dict = {}
    m1_sw = compute_m1(*args, face_box_norm_challenge=same.face_box_norm, landmarks_norm_challenge=swapped,
                       diagnostics=sw, **kw)
    ref_mm = m1_ref["m1_mouth_residual_mm"]
    assert m1_sw["m1_mouth_residual_mm"] == pytest.approx(ref_mm, abs=0.05), (ref, sw)
    checks = classify({"available": True, "d0_valid_ratio": 0.9, **m1_sw}, cfg)["checks"]
    assert checks["m1"] == "RIGID", m1_sw
