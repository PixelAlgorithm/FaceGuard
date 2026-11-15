"""CSV schema validation (attempts / comparisons / scenarios) incl. privacy and DUMMY guards."""

from __future__ import annotations

import copy

from evallib import io as eio
from evallib import schema as S


def _rows(fixtures):
    header, rows = eio.read_csv(fixtures / "attempts_DUMMY.csv")
    return header, rows


def test_dummy_fixture_is_valid_when_not_a_results_file(fixtures):
    header, rows = _rows(fixtures)
    errors, _ = S.validate_attempts(rows, header, results_file=False)
    assert errors == []


def test_dummy_rows_rejected_in_results_file(fixtures):
    header, rows = _rows(fixtures)
    errors, _ = S.validate_attempts(rows, header, results_file=True)
    assert any("DUMMY row in a results file" in e for e in errors)


def test_header_matches_schema_order(fixtures):
    header, _ = _rows(fixtures)
    assert header == S.ATTEMPT_COLUMNS


def test_missing_column_is_an_error(fixtures):
    header, rows = _rows(fixtures)
    h = [c for c in header if c != "species"]
    errors, _ = S.validate_attempts(rows, h, results_file=False)
    assert errors and "missing columns" in errors[0]


def _one(fixtures, **delta):
    header, rows = _rows(fixtures)
    r = copy.deepcopy(rows[0])
    r.update(delta)
    return S.validate_attempts([r], header, results_file=False)[0]


def test_label_species_consistency(fixtures):
    assert any("inconsistent with species" in e for e in _one(fixtures, species="print", label="video"))


def test_bad_enums(fixtures):
    assert any("unknown species" in e for e in _one(fixtures, species="selfie"))
    assert any("decision" in e for e in _one(fixtures, decision="MAYBE"))
    assert any("lighting" in e for e in _one(fixtures, lighting="sunny"))
    assert any("split" in e for e in _one(fixtures, split="train"))


def test_terminal_first_decision_cannot_change(fixtures):
    errs = _one(fixtures, first_decision="DENY", decision="ALLOW", stepup_outcome="none")
    assert any("terminal first decision" in e for e in errs)


def test_stepup_outcome_consistency(fixtures):
    errs = _one(fixtures, first_decision="STEP_UP", decision="ALLOW", stepup_outcome="failed")
    assert any("stepup_outcome" in e for e in errs)


def test_privacy_guard_blocks_blobs_and_embedding_keys(fixtures):
    blob = "A" * 300
    assert any("blob" in e for e in _one(fixtures, notes=blob))
    assert any("not allowed" in e for e in _one(fixtures, scores='{"embedding": [0.1, 0.2]}'))
    header, rows = _rows(fixtures)
    errs, _ = S.validate_attempts(rows[:1], header + ["face_image"], results_file=False)
    assert any("forbidden column" in e for e in errs)


def test_subject_disjoint_split_enforced(fixtures):
    header, rows = _rows(fixtures)
    a, b = copy.deepcopy(rows[0]), copy.deepcopy(rows[1])
    b["subject_id"] = a["subject_id"]
    b["split"] = "test" if a["split"] == "dev" else "dev"
    b["attempt_id"] = "att_other"
    errs, _ = S.validate_attempts([a, b], header, results_file=False)
    assert any("both splits" in e for e in errs)


def test_duplicate_attempt_id(fixtures):
    header, rows = _rows(fixtures)
    errs, _ = S.validate_attempts([rows[0], rows[0]], header, results_file=False)
    assert any("duplicate attempt_id" in e for e in errs)


def test_noncanonical_reason_code_is_warning(fixtures):
    header, rows = _rows(fixtures)
    r = copy.deepcopy(rows[0])
    r["reason_codes"] = "SCHEDULE_OK"
    errs, warns = S.validate_attempts([r], header, results_file=False)
    assert not errs and any("non-canonical" in w for w in warns)


def test_comparisons_fixture_valid_and_genuine_flag_checked(fixtures):
    header, rows = eio.read_csv(fixtures / "comparisons_DUMMY.csv")
    assert S.validate_comparisons(rows, header, results_file=False)[0] == []
    bad = dict(rows[0])
    bad["genuine"] = "1" if bad["probe_subject"] != bad["gallery_subject"] else "0"
    assert S.validate_comparisons([bad], header, results_file=False)[0]


def test_scenarios_fixture_valid(fixtures):
    header, rows = eio.read_csv(fixtures / "scenarios_DUMMY.csv")
    assert S.validate_scenarios(rows, header, results_file=False)[0] == []
    assert S.validate_scenarios(rows, header, results_file=True)[0]


def test_derive_liveness_result():
    d = S.derive_liveness_result
    assert d("ALLOW", "final", ["ACCESS_OK"]) == "PASS"
    assert d("DENY", "liveness", ["SPOOF_DEVICE_DETECTED"]) == "FAIL"
    assert d("STEP_UP", "liveness", ["LIVENESS_UNSURE"]) == "UNSURE"
    assert d("STEP_UP", "liveness", ["MASK_CUE_EDGE"]) == "UNSURE"
    assert d("STEP_UP", "quality", ["QUALITY_LOW_LIGHT"]) == "NOT_EVALUATED"
    assert d("DENY", "injection", ["INJECTION_VIRTUAL_CAMERA"]) == "NOT_EVALUATED"
    assert d("DENY", "final", ["RATE_LIMITED"]) == "NOT_EVALUATED"
    assert d("DENY", "match", ["NOT_ENROLLED"]) == "UNKNOWN"
    assert d("DENY", "schedule", ["LIVENESS_UNSURE", "SCHEDULE_OUTSIDE_WINDOW"]) == "UNSURE"
    assert d("DENY", "schedule", ["SCHEDULE_OUTSIDE_WINDOW"]) == "PASS"


def test_deny_cause_priority():
    c = S.deny_cause
    assert c(["RATE_LIMITED"]) == "system"
    assert c(["SCHEDULE_OUTSIDE_WINDOW", "LIVENESS_UNSURE"]) == "schedule"
    assert c(["CHALLENGE_FAILED"]) == "pad"
    assert c(["QUALITY_BLUR"]) == "quality"
    assert c(["NOT_ENROLLED"]) == "match"
    assert c(["FALLBACK_FAILED", "OFFLINE_MODE"]) == "fallback"


def test_protocol_documents_every_column():
    """PROTOCOL.md section 7 must name every attempts.csv / comparisons.csv / scenarios.csv column (no drift)."""
    from evallib import EVAL_DIR

    txt = (EVAL_DIR / "PROTOCOL.md").read_text()
    for c in S.ATTEMPT_COLUMNS + S.COMPARISON_COLUMNS + S.SCENARIO_COLUMNS + S.EXCLUSION_COLUMNS:
        assert f"`{c}`" in txt or f"{c}," in txt or f", {c}" in txt, c
    assert "iBeta Level 1-**style**" in txt and "not a certification" in txt
