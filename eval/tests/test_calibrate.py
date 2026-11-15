"""calibrate.py on DUMMY fixtures: row selection, distributions, bar side counts with bounds, labels, guard."""

from __future__ import annotations

import json

import pytest

import calibrate as CB
from evallib import RESULTS_DIR


def test_side_counts_direction_and_bounds():
    g = CB.side_counts([0.9, 0.85, 0.7], 0.8, "live", "bona_fide")
    assert (g["k"], g["n"]) == (1, 3) and "attack side" in g["what"]
    a = CB.side_counts([0.1, 0.2], 0.8, "live", "print")
    assert (a["k"], a["n"]) == (0, 2) and a["ub95"] > 0  # zero errors still carry an upper bound
    m = CB.side_counts([0.6, 0.3], 0.5, "attack", "print_eyecut")  # higher = attack: live side is < bar
    assert (m["k"], m["n"]) == (1, 2)


def test_readout_on_dummy(tmp_path, fixtures):
    out = tmp_path / "calib"
    assert CB.main(["--attempts", str(fixtures / "attempts_DUMMY.csv"), "--exclusions",
                    str(fixtures / "exclusions_DUMMY.csv"), "--split", "test", "--out-dir", str(out)]) == 0
    doc = json.loads((out / "calibration_test.json").read_text())
    meta = doc["meta"]
    assert meta["dummy"] is True and "do not tune" in meta["label"]
    assert meta["dropped"]["NO_RESPONSE"] >= 1 and meta["dropped"]["RATE_LIMITED / SYSTEM_ERROR"] == 2
    assert meta["dropped"]["injection (not PAD)"] == 6 and meta["dropped"]["scenario rows"] == 2
    pad = doc["signals"]["s_pad"]
    assert pad["distribution"]["bona_fide"]["n"] > 0 and pad["distribution"]["print"]["n"] > 0
    assert pad["distribution"]["bona_fide"]["p50"] > pad["distribution"]["print"]["p50"]
    bar = pad["bars"]["pad.pass_min"]
    assert bar["path"] == "liveness.pad.pass_min" and bar["print"]["n"] == pad["distribution"]["print"]["n"]
    assert "s_mask_ring" in doc["signals"] and doc["signals"]["s_moire"]["status"] == "NO_DATA"
    assert doc["signal_status"]["flash"]["bona_fide"].get("ADVISORY_PASS", 0) > 0
    md = (out / "CALIBRATION_test.md").read_text()
    assert "DUMMY DATA" in md and "do not tune" in md and "Not APCER/BPCER" in md and "95% UB" in md


def test_refuses_dummy_into_results(fixtures):
    with pytest.raises(SystemExit):
        CB.main(["--attempts", str(fixtures / "attempts_DUMMY.csv"), "--split", "dev",
                 "--out-dir", str(RESULTS_DIR / "calibration")])
