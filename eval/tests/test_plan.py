"""Subject-disjoint split assignment and interleaved shuffled plans."""

from __future__ import annotations

import itertools
from collections import Counter

import plan as P
from evallib import io as eio


def test_assign_splits_deterministic_and_disjoint():
    ids = [f"S{i:02d}" for i in range(1, 11)]
    a = P.assign_splits(ids, 0.4, 7)
    assert a == P.assign_splits(ids, 0.4, 7)
    assert Counter(a.values()) == {"dev": 4, "test": 6}
    assert P.assign_splits(["S1", "S2"], 0.4, 1).values().__len__() == 2
    assert Counter(P.assign_splits(["S1", "S2"], 0.4, 1).values()) == {"dev": 1, "test": 1}


def test_schedule_volumes_and_interleaving(tmp_path, fixtures):
    out = tmp_path / "plan.csv"
    assert P.main(["schedule", "--subjects", str(fixtures / "subjects_DUMMY.csv"), "--split", "test",
                   "--out", str(out), "--extra", "mask_3d:4,zero_effort:3"]) == 0
    _, rows = eio.read_csv(out)
    c = Counter(r["species"] for r in rows)
    # 4 test subjects: genuine/cell = ceil(120 / (4*3*1)) = 10 -> 120; attacks/species = ceil(30/4)=8 -> 32
    assert c["bona_fide"] == 120 + 3 and c["print"] == 32 and c["mask_3d"] == 4
    assert all(r["split"] == "test" for r in rows)
    assert [int(r["plan_seq"]) for r in rows] == list(range(1, len(rows) + 1))
    # lighting blocks are contiguous and runs of one class never exceed MAX_RUN
    blocks = [r["block"] for r in rows]
    assert blocks == sorted(blocks, key=["office", "backlit", "dim"].index)
    run, worst = 1, 1
    for prev, cur in itertools.pairwise(rows):
        same = (prev["attempt_class"] in ("genuine", "zero_effort")) == (cur["attempt_class"] in ("genuine", "zero_effort"))
        run = run + 1 if same and prev["block"] == cur["block"] else 1
        worst = max(worst, run)
    assert worst <= P.MAX_RUN


def test_subjects_registry_refuses_overwrite(tmp_path):
    out = tmp_path / "subjects.csv"
    assert P.main(["subjects", "--ids", "S01,S02,S03", "--out", str(out)]) == 0
    try:
        P.main(["subjects", "--ids", "S01,S02,S03", "--out", str(out)])
        raise AssertionError("expected SystemExit")
    except SystemExit:
        pass


def test_reduced_plan_volumes_targets_and_bounds(tmp_path, capsys):
    subj, out = tmp_path / "subjects.csv", tmp_path / "reduced.csv"
    assert P.main(["reduced", "--subjects", str(subj), "--write-subjects", "--out", str(out)]) == 0
    _, reg = eio.read_csv(subj)
    assert {r["subject_id"]: r["enrolled_user_id"] for r in reg} == P.REDUCED_SUBJECTS
    assert all(r["split"] == "test" and r["consent"] == "" for r in reg)  # consent is the operator's step
    _, rows = eio.read_csv(out)
    c = Counter(r["species"] for r in rows)
    assert c == {"bona_fide": 40, "print": 15, "phone_photo": 15, "phone_video": 15, "print_eyecut": 10}
    assert Counter(r["subject_id"] for r in rows if r["species"] == "print_eyecut") == {"S01": 4, "S02": 3, "S03": 3}
    assert Counter(r["block"] for r in rows) == {"office": 83, "dim": 12}
    assert all(r["species"] == "bona_fide" for r in rows if r["block"] == "dim")
    assert all(r["zone"] == "MAIN_GATE" and r["split"] == "test" for r in rows)
    run, worst = 1, 1
    office = [r for r in rows if r["block"] == "office"]  # the dim block is bona fide only
    for prev, cur in itertools.pairwise(office):
        same = (prev["attempt_class"] == "genuine") == (cur["attempt_class"] == "genuine")
        run = run + 1 if same and prev["block"] == cur["block"] else 1
        worst = max(worst, run)
    assert worst <= P.MAX_RUN
    txt = capsys.readouterr().out
    assert "| APCER print | 15 | < 20.00% | < 18.11% |" in txt and "1497 impostor comparisons" in txt
    # registry is never overwritten (split fixed before capture)
    import pytest
    with pytest.raises(SystemExit):
        P.main(["reduced", "--subjects", str(subj), "--write-subjects", "--out", str(out)])


def test_reduced_plan_attack_targets_subset(tmp_path):
    subj, out = tmp_path / "subjects.csv", tmp_path / "reduced.csv"
    assert P.main(["reduced", "--subjects", str(subj), "--write-subjects", "--attack-targets", "S01",
                   "--out", str(out)]) == 0
    _, rows = eio.read_csv(out)
    assert {r["subject_id"] for r in rows if r["attempt_class"] == "attack"} == {"S01"}
    assert {r["subject_id"] for r in rows if r["attempt_class"] == "genuine"} == {"S01", "S02", "S03"}
