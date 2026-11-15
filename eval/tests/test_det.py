"""DET generation, EER, threshold calibration, PNG output."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from evallib import det, style


def test_det_points_exact_counts():
    g = np.array([0.6, 0.7, 0.8, 0.9])
    i = np.array([0.1, 0.2, 0.3, 0.65])
    ts, fmr, fnmr = det.det_points(g, i)
    # at t = 0.65: impostors >= 0.65 -> 1/4 ; genuine < 0.65 -> 1/4
    j = int(np.where(np.isclose(ts, 0.65))[0][0])
    assert fmr[j] == pytest.approx(0.25) and fnmr[j] == pytest.approx(0.25)
    # monotone: FMR non-increasing, FNMR non-decreasing in t
    assert np.all(np.diff(fmr) <= 1e-12) and np.all(np.diff(fnmr) >= -1e-12)
    # +inf threshold endpoint: nothing accepted
    assert fmr[-1] == 0.0 and fnmr[-1] == 1.0


def test_counts_at_uses_accept_ge_threshold():
    g = np.array([0.5, 0.49])
    i = np.array([0.5, 0.2])
    kfm, ni, kfnm, ng = det.counts_at(g, i, 0.5)
    assert (kfm, ni, kfnm, ng) == (1, 2, 1, 2)  # 0.5 >= 0.5 accepted; 0.49 rejected


def test_eer_symmetric_case():
    g = np.array([0.6, 0.7, 0.8, 0.9])
    i = np.array([0.1, 0.2, 0.3, 0.65])
    e = det.eer(g, i)
    assert e["eer"] == pytest.approx(0.25)


def test_calibration_percentile_and_resolution_flag():
    rng = np.random.default_rng(1)
    imp = rng.normal(0.1, 0.07, 2000)
    c = det.calibrate_threshold(imp, 99.8)
    assert c["threshold"] == pytest.approx(np.percentile(imp, 99.8))
    assert c["resolution_ok"] and c["n_needed_for_resolution"] == 500
    small = det.calibrate_threshold(imp[:100], 99.8)
    assert not small["resolution_ok"]
    assert small["threshold"] <= small["impostor_max"]


def test_det_png_light_and_dark(tmp_path):
    rng = np.random.default_rng(3)
    g, i = rng.normal(0.7, 0.08, 120), rng.normal(0.1, 0.08, 900)
    files = style.plot_det_matcher(tmp_path / "det_arcface.png", (g, i), (g[:40], i[:300]),
                                   [("t=0.5", 0.0, 0.01)], "DUMMY DET", "DUMMY")
    assert [p.split("/")[-1] for p in files] == ["det_arcface.png", "det_arcface_dark.png"]
    for p in files:
        assert Path(p).read_bytes()[:8].startswith(b"\x89PNG")


def test_pad_det_small_multiples(tmp_path):
    rng = np.random.default_rng(4)
    bona = rng.normal(0.9, 0.05, 60)
    per = {"print": (bona, rng.normal(0.1, 0.05, 30)), "phone_video": (bona, rng.normal(0.3, 0.1, 30))}
    files = style.plot_det_pad(tmp_path / "det_pad.png", per, "DUMMY PAD DET")
    assert len(files) == 2 and all(Path(p).read_bytes()[:4] == b"\x89PNG" for p in files)
