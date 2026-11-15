"""Audit findings DE-03 / DE-05 / DE-10 / DE-13: implausible intrinsics never reach the geometry (no CPU
spin, no fake PASS), FOV-guessed intrinsics never drive D4, and classify() mirrors the policy for a
missing D4."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

from depth import synth
from depth.checks import classify, compute_depth_checks, intrinsics_plausible
from depth.protocol import DepthProtocolError, parse_meta, process_upload
from depth.tests.conftest import noisy

ROOT = Path(__file__).resolve().parents[2]
SPIN_TIMEOUT_S = 30


def _meta(cam: synth.SynthCamera, frame: synth.SynthFrame, **over) -> dict:
    meta = {"attempt_id": "att_01HARD", "phase": "PASSIVE", "depth_type": "disparity", "dtype": "float16",
            "width": cam.width, "height": cam.height, "intrinsics": cam.intrinsics(640, 480),
            "face_box_norm": frame.face_box_norm, "landmarks_norm": frame.landmarks_norm,
            "depth_accuracy": "absolute"}
    meta.update(over)
    return meta


BAD_INTRINSICS = [
    {"fx": 500.0, "fy": 500.0, "cx": 1e305, "cy": 120.0},  # DE-03: back-projection overflows -> svd spin
    {"fx": 1e-250, "fy": 1e-250, "cx": 160.0, "cy": 120.0},  # DE-05: flat print measured as a face
    {"fx": 1e300, "fy": 1e300, "cx": 160.0, "cy": 120.0},
    {"fx": 280.0, "fy": 280.0, "cx": -50.0, "cy": 120.0},
    {"fx": 280.0, "fy": 280.0, "cx": 160.0, "cy": 120.0, "ref_width": 1e9, "ref_height": 240.0},
]


@pytest.mark.parametrize("intr", BAD_INTRINSICS)
def test_parse_meta_rejects_non_physical_intrinsics(cam, intr):
    with pytest.raises(DepthProtocolError):
        parse_meta(_meta(cam, synth.scene_face(cam), intrinsics=intr))


def test_shipped_and_reference_scaled_intrinsics_stay_plausible(cam):
    for ref in ((None, None), (640, 480), (4032, 3024)):
        i = cam.intrinsics(*ref)
        assert intrinsics_plausible(i["fx"], i["fy"], i["cx"], i["cy"], i["ref_width"], i["ref_height"])
    assert parse_meta(_meta(cam, synth.scene_face(cam)))["intrinsics"]["fx"] > 0


def test_extreme_cx_does_not_spin_the_worker(cam, cfg):
    """DE-03 repro, isolated in a child process so a regression cannot hang the suite."""
    code = (
        "import json,sys,numpy as np\n"
        "from depth import synth\nfrom depth.checks import compute_depth_checks, load_thresholds\n"
        "cam=synth.SynthCamera(320,240); f=synth.scene_print(cam)\n"
        "sig=compute_depth_checks(f.depth_m, depth_type='depth', intrinsics={'fx':500.0,'fy':500.0,"
        "'cx':1e305,'cy':120.0}, face_box_norm=f.face_box_norm, landmarks_norm=f.landmarks_norm,"
        " cfg=load_thresholds(), accuracy='absolute')\n"
        "print(json.dumps({'d1': sig['d1_plane_rms_mm'], 'd4': sig['d4_ipd_mm']}))\n"
    )
    r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True,
                       timeout=SPIN_TIMEOUT_S, check=True)
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["d4"] is None  # implausible intrinsics are ignored (default FOV), never trusted for D4


@pytest.mark.parametrize("seed", [0, 1, 2])
@pytest.mark.parametrize("fx", [1e-200, 1e-250, 1e-300])
def test_tiny_focal_flat_print_never_passes(cam, cfg, seed, fx):
    """DE-05 (verifier repro: make_scene 'flat', relative accuracy -> PASS before the fix)."""
    rng = np.random.default_rng(seed)
    f = synth.make_scene("flat", cam, rng, phase="PASSIVE", sigma_mm=0.0, hole_fraction=0.0)
    sig = compute_depth_checks(synth.add_sensor_noise(f.depth_m, rng), depth_type="depth",
                               intrinsics={"fx": fx, "fy": fx, "cx": 160.0, "cy": 120.0},
                               face_box_norm=f.face_box_norm, landmarks_norm=f.landmarks_norm, cfg=cfg,
                               accuracy="relative")
    assert classify(sig, cfg)["overall"] != "PASS"


def test_fov_guessed_intrinsics_never_drive_d4(cam, cfg, rng):
    """DE-10: intrinsics_source 'fov' (no calibration data on the phone) -> D4 not reported."""
    f = noisy(synth.scene_face(cam), rng)
    blobs = [synth.to_wire(f.depth_m, "disparity", "float16")]
    calibrated = process_upload(json.dumps(_meta(cam, f, intrinsics_source="calibration")), blobs, cfg)
    guessed = process_upload(json.dumps(_meta(cam, f, intrinsics_source="fov")), blobs, cfg)
    assert calibrated.signal["d4_ipd_mm"] is not None
    assert guessed.signal["d4_ipd_mm"] is None
    assert guessed.signal["d1_plane_rms_mm"] is not None  # D1-D3 still measured
    assert guessed.diag["intrinsics_source"] == "estimated_fov"


def test_classify_absolute_without_d4_is_unsure_like_the_policy(cam, cfg, rng):
    """DE-13: edge/policy/liveness.py appends UNSURE when D4 is required (absolute) but missing."""
    sig = dict(compute_depth_checks(noisy(synth.scene_face(cam), rng).depth_m, depth_type="depth",
                                    intrinsics=None, face_box_norm=synth.scene_face(cam).face_box_norm,
                                    landmarks_norm=synth.scene_face(cam).landmarks_norm, cfg=cfg,
                                    accuracy="absolute"))
    assert sig["d4_ipd_mm"] is None and sig["absolute"] is True
    out = classify(sig, cfg)
    assert out["checks"]["d4"] == "UNSURE" and out["overall"] == "UNSURE"
    relative = classify(sig | {"absolute": False}, cfg)
    assert relative["checks"]["d4"] == "NA"  # relative depth: D4 legitimately not required


@pytest.mark.parametrize("key,cap", [("d1_plane_rms_mm", "d1_plane_rms_max_mm"),
                                     ("d2_quad_rms_mm", "d2_quad_rms_max_mm"),
                                     ("d3_nose_relief_mm", "d3_nose_relief_max_mm")])
def test_classify_mirrors_policy_ceilings(cfg, key, cap):
    """DE-05 policy side (edge/policy/liveness.py): a value above its plausibility ceiling is UNSURE."""
    d = cfg["liveness"]["depth"]
    sig = {"available": True, "absolute": False, "d0_valid_ratio": 0.95, "d1_plane_rms_mm": 10.0,
           "d2_quad_rms_mm": 6.0, "d3_nose_relief_mm": 25.0}
    assert classify(sig, cfg)["overall"] == "PASS"
    out = classify(sig | {key: d[cap] + 1.0}, cfg)
    assert out["checks"][key[:2]] == "UNSURE" and out["overall"] == "UNSURE"
