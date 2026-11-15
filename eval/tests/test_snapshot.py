"""snapshot_metrics.py: dry run on the DUMMY fixture, CSV cross-check, privacy filter, results/ guard."""

from __future__ import annotations

import json

import pytest

import snapshot_metrics as SN
from evallib import RESULTS_DIR


def _run(tmp_path, fixtures, *extra):
    root = tmp_path / "snap"
    rc = SN.main(["--fixture", str(fixtures / "edge_snapshot_DUMMY.json"), "--attempts",
                  str(fixtures / "attempts_DUMMY.csv"), "--run-id", "DUMMY-R1", "--max-attempts", "3",
                  "--out-root", str(root), *extra])
    (out,) = list(root.iterdir())
    return rc, out


def test_dry_run_writes_snapshot(tmp_path, fixtures):
    rc, out = _run(tmp_path, fixtures)
    assert rc == 0 and out.name.startswith("DUMMY-snapshot_")
    for f in ("edge_metrics.json", "edge_mode.json", "edge_health.json", "attempts.json", "SNAPSHOT.md"):
        assert (out / f).exists(), f
    doc = json.loads((out / "attempts.json").read_text())
    assert doc["meta"]["n_requested"] == 3 and doc["meta"]["n_found"] == 2 and doc["meta"]["dummy"] is True
    assert set(doc["attempts"]) == {"att_DUMMY0001", "att_DUMMY0002"}
    md = (out / "SNAPSHOT.md").read_text()
    assert "not an eval result" in md and "DUMMY fixture" in md and "colour flash:" in md
    assert "| `att_DUMMY0001` | ALLOW | ALLOW | yes |" in md
    raw = (out / "attempts.json").read_text()
    assert "DUMMY NAME" not in raw  # names / display strings never persisted (whitelist)


def test_privacy_scan_flags_blobs_and_forbidden_keys():
    found = SN.privacy_scan({"a": {"embedding": [0.1]}, "b": "QUJD" * 100, "c": [{"ok": 1}]}, "m")
    assert any("embedding" in f for f in found) and any("blob" in f for f in found) and len(found) == 2


def test_refuses_dummy_into_results(fixtures):
    with pytest.raises(SystemExit):
        SN.main(["--fixture", str(fixtures / "edge_snapshot_DUMMY.json"), "--out-root", str(RESULTS_DIR / "runs")])


def test_ids_from_csv_includes_chain_members(tmp_path):
    p = tmp_path / "a.csv"
    p.write_text("run_id,attempt_id,notes\nR1,att_A,chain:att_A>att_B\nR1,noresp_x,\nR2,att_C,\n")
    assert SN.ids_from_csv(p, "R1") == ["att_A", "att_B"]


def test_redact_keeps_document_but_drops_flagged_values():
    doc = {"policy_version": "p1", "template_cache": {"count": 3}, "x": [{"embedding": [0.1]}, "QUJD" * 100],
           "policy_bars": {"pad_pass_min": 0.7}}
    out = SN.redact(doc)
    assert out["policy_version"] == "p1" and out["policy_bars"] == {"pad_pass_min": 0.7}
    assert out["template_cache"] == SN.REDACTED and out["x"] == [{"embedding": SN.REDACTED}, SN.REDACTED]
    left = SN.privacy_scan(out, "m")  # only the (now empty) key names remain flagged; no value survives
    assert left and all(f.endswith("forbidden key") for f in left) and "QUJD" not in json.dumps(out)
