"""summary.py on DUMMY metrics: sections, banner, source links, dashboard shape, results/ guard."""

from __future__ import annotations

import json

import pytest

import metrics as M
import summary as SM
from evallib import RESULTS_DIR


@pytest.fixture
def dummy_metrics(dummy_args, tmp_path):
    assert M.main(dummy_args) == 0
    return tmp_path / "out" / "metrics.json"


def test_summary_sections_and_dashboard(dummy_metrics):
    out = dummy_metrics.parent
    assert SM.main(["--metrics", str(dummy_metrics)]) == 0
    txt = (out / "SUMMARY.md").read_text()
    assert "DUMMY DATA" in txt and "iBeta Level 1-**style**" in txt and "not certified" in txt
    for section in ("## 1. HID targets vs measured", "## 2. Attack presentations", "## 3. Bona fide",
                    "## 4. Face matcher", "## 5. Decision time", "## 6. Decision mix", "## 7. SC1 / SC2 gate",
                    "## 8. Trials needed", "## 9. Honesty notes", "## 10. Dashboard JSON"):
        assert section in txt, section
    assert "(runs/DUMMY-R1.json)" in txt  # every table row links its source run
    assert "0/33 -> < 3/33" in txt  # zero-error cells shown as rule-of-3 upper bounds
    assert "100% liveness" not in txt and "certified protocol" not in txt
    assert "Configuration under test" in txt and "moire: enforce" in txt
    flash_advisory = json.loads(dummy_metrics.read_text())["RUN_INFO"]["switches"]["flash"]["enforce"] is False
    assert ("measured with PAD + device detector + moire **without** the flash" in txt) is flash_advisory
    for png in ("apcer_by_species.png", "bpcer_by_lighting.png", "latency_stages.png", "latency_hist.png"):
        assert (out / png).exists() and png in txt
    dash = json.loads((out / "dashboard.json").read_text())
    for key in ("attempts", "decisions", "by_mode", "reason_codes", "latency_ms", "by_label", "hid_targets"):
        assert key in dash
    assert dash["dummy_data"] is True
    assert dash["by_label"]["print"]["apcer_upper_95"] > 0
    assert dash["by_label"]["bona_fide"]["step_up"] >= 1
    assert set(dash["latency_ms"]) >= {"client", "total", "liveness", "match"}


def test_summary_refuses_dummy_into_results(dummy_metrics):
    before = sorted(p.name for p in RESULTS_DIR.iterdir())
    with pytest.raises(SystemExit):
        SM.main(["--metrics", str(dummy_metrics), "--out-dir", str(RESULTS_DIR)])
    assert sorted(p.name for p in RESULTS_DIR.iterdir()) == before


def test_missing_metrics_returns_3(tmp_path):
    assert SM.main(["--metrics", str(tmp_path / "nope.json")]) == 3
