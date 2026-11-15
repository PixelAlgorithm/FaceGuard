"""compare.py pairing logic on synthetic DUMMY embeddings (the embedding itself runs in the edge venv)."""

from __future__ import annotations

import numpy as np
import pytest

import compare as CP
from evallib import io as eio
from evallib import schema as S


def unit(v):
    v = np.asarray(v, dtype=np.float32)
    return v / np.linalg.norm(v)


def items():
    e = np.eye(4, dtype=np.float32)
    return [
        CP.Item("e1", "A", "dev", "enrol", "office", "live", unit(e[0])),
        CP.Item("e2", "A", "dev", "enrol", "office", "live", unit(e[0] + 0.5 * e[3])),
        CP.Item("p1", "A", "dev", "probe", "dim", "live", unit(e[0] + 0.2 * e[3])),
        CP.Item("e3", "B", "test", "enrol", "office", "live", unit(e[1])),
        CP.Item("p2", "B", "test", "probe", "office", "live", unit(e[1] + 0.1 * e[0])),
        CP.Item("e4", "C", "test", "enrol", "office", "live", unit(e[2])),
        CP.Item("lf1", "lfw:X", "test", "enrol", "", "lfw", unit(e[3])),
        CP.Item("lf2", "lfw:X", "test", "probe", "", "lfw", unit(e[3] + 0.1 * e[2])),
        CP.Item("lf3", "lfw:Y", "test", "enrol", "", "lfw", unit(e[2] + e[1])),
        CP.Item("nf", "C", "test", "probe", "office", "live", None),  # no face found -> skipped
    ]


def test_pairs_flags_splits_and_max_rule():
    rows = CP.comparisons(items(), "arcface", "DUMMY-model", "DUMMY-C")
    by = {(r["probe_attempt_id"], r["gallery_subject"]): r for r in rows}
    # team probes vs team galleries only (3 galleries x 2 probes), LFW probe vs LFW galleries only (2)
    assert len(rows) == 3 * 2 + 2
    assert by[("p1", "A")]["genuine"] == 1 and by[("p1", "A")]["split"] == "dev"
    assert by[("p1", "B")]["genuine"] == 0 and by[("p1", "B")]["split"] == "cross"
    assert by[("p2", "C")]["split"] == "test" and by[("p2", "C")]["genuine"] == 0
    assert ("lf2", "A") not in by and by[("lf2", "lfw:Y")]["source"] == "lfw"
    # max over A's two templates
    q = unit(np.eye(4)[0] + 0.2 * np.eye(4)[3])
    best = max(float(unit(np.eye(4)[0]) @ q), float(unit(np.eye(4)[0] + 0.5 * np.eye(4)[3]) @ q))
    assert by[("p1", "A")]["score"] == pytest.approx(best, abs=1e-5)
    assert by[("p1", "A")]["gallery_template"] == "max_of_2"
    assert all(r["matcher"] == "arcface" and r["model"] == "DUMMY-model" for r in rows)


def test_rows_validate_against_schema():
    rows = [{k: str(v) for k, v in r.items()} for r in CP.comparisons(items(), "arcface", "m", "DUMMY-C")]
    errors, _ = S.validate_comparisons(rows, S.COMPARISON_COLUMNS, results_file=False)
    assert errors == []
    assert "embedding" not in str(rows) and "emb" not in rows[0]


def test_duplicate_manifest_images_rejected(tmp_path):
    caps = tmp_path / "captures"
    caps.mkdir()
    subj = tmp_path / "subjects.csv"
    eio.write_csv(subj, ["subject_id", "split", "enrolled_user_id", "consent", "consent_version", "notes"],
                  [{"subject_id": "A", "split": "dev", "consent": "yes"}])
    row = {"image_id": "img_x", "subject_id": "A", "split": "dev", "role": "probe", "lighting": "office",
           "distance": "mid", "source": "live", "captured_at_utc": "2026-11-14T00:00:00.000Z", "file": "A/x.jpg"}
    eio.write_csv(caps / "manifest.csv", list(row), [row, row])
    with pytest.raises(SystemExit):
        CP.load_team(caps, subj, 3)


def test_enrol_selection_prefers_flagged_then_first_office(tmp_path):
    caps = tmp_path / "captures"
    caps.mkdir()
    subj = tmp_path / "subjects.csv"
    eio.write_csv(subj, ["subject_id", "split", "enrolled_user_id", "consent", "consent_version", "notes"],
                  [{"subject_id": "A", "split": "test", "consent": "yes"}])
    cols = ["image_id", "subject_id", "split", "role", "lighting", "distance", "source", "captured_at_utc", "file"]
    rows = [{"image_id": f"i{k}", "subject_id": "A", "split": "test", "role": "probe",
             "lighting": "dim" if k == 0 else "office", "distance": "mid", "source": "live",
             "captured_at_utc": f"2026-11-14T00:00:0{k}.000Z", "file": f"A/{k}.jpg"} for k in range(5)]
    eio.write_csv(caps / "manifest.csv", cols, rows)
    its = CP.load_team(caps, subj, 2)
    assert [i.image_id for i in its if i.role == "enrol"] == ["i1", "i2"]  # first 2 office images
