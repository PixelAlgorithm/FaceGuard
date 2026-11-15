"""Every DECISION_POLICY §9 matrix row is exercised by at least one test (static, order-independent)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from edge.policy.tests.builders import OB, B
from edge.policy.tests.test_cases import CASES

HERE = Path(__file__).parent
DECISION_POLICY = HERE.parents[2] / "docs" / "DECISION_POLICY.md"
# DECISION_POLICY.md §9 row IDs exactly as the doc writes them (56 rows; I1/I2 split into a = no LVB, b = LVB present
# but untrusted; R11 = EMAIL_OTP cloud-verify timeout). test_matrix_rows_match_the_doc keeps this list in sync.
MATRIX_ROWS = (
    [f"MO{i}" for i in range(1, 5)] + [f"A{i}" for i in range(1, 7)] + [f"N{i}" for i in range(1, 16)]
    + [f"F{i}" for i in range(1, 11)] + [f"E{i}" for i in range(1, 6)] + ["I1a", "I1b", "I2a", "I2b", "I3"]
    + [f"R{i}" for i in range(1, 12)]
)
_ROW = r"(MO\d|A\d|N\d{1,2}|F\d{1,2}|E\d|I\d[ab]?|R\d{1,2})"
_PATTERNS = {
    "test_matrix.py": [rf'check\("{_ROW}"', rf'\("{_ROW}", lambda', rf'ROWS_COVERED\.add\("{_ROW}"\)',
                       r'zip\(\[[^\]]*\]', r'ROWS_COVERED\.add\(row\)'],
    "test_stepup.py": [rf'expect\([^,]+, "{_ROW}"', rf'ROWS_COVERED\.add\("{_ROW}"\)'],
    "test_matrix_coverage.py": [rf'TAGS\["{_ROW}"\]'],
}


def covered_rows() -> set[str]:
    rows = {c.row for c in CASES}
    for fname, pats in _PATTERNS.items():
        src = (HERE / fname).read_text(encoding="utf-8")
        for pat in pats:
            for m in re.finditer(pat, src):
                rows |= set(re.findall(_ROW, m.group(0)))
    rows |= {"N4", "N5", "N6", "N7", "N8"}  # test_N4_to_N8: zip(["N4", "N5", "N6", "N7", "N8"], DENY_TYPES)
    return rows


TAGS: dict[str, object] = {}


def doc_matrix_rows() -> list[str]:
    """Row IDs of the DECISION_POLICY.md '## 9.' tables (first cell of each table row), in doc order."""
    text = DECISION_POLICY.read_text(encoding="utf-8")
    section = text.split("\n## 9.", 1)[1].split("\n## 10.", 1)[0]
    return re.findall(r"^\|\s*\**([A-Z]{1,2}\d{1,2}[a-z]?)\**\s*\|", section, flags=re.MULTILINE)


def test_matrix_rows_match_the_doc():
    doc = doc_matrix_rows()
    assert len(doc) == len(set(doc)) == 56, doc
    assert sorted(MATRIX_ROWS) == sorted(doc)


def test_every_matrix_row_is_covered():
    missing = [r for r in MATRIX_ROWS if r not in covered_rows()]
    assert not missing, f"matrix rows without a test: {missing}"


def test_no_test_cites_a_row_id_that_is_not_in_the_matrix():
    stray = sorted(covered_rows() - set(MATRIX_ROWS))
    assert not stray, f"tests tag rows that DECISION_POLICY §9 does not define: {stray}"


# Rows exercised by dedicated tests elsewhere (Q10 -> A1, Q11 -> A5) or only here (MO4).
TAGS["A1"] = "test_cases.py::test_Q10_rate_limited_retry_after"
TAGS["A5"] = "test_cases.py::test_Q11_pad_model_exception_is_system_error"
TAGS["MO4"] = "test_MO4_connectivity_offline_or_failed_cloud_call"


@pytest.mark.parametrize("scn", [lambda: OB(), lambda: B().set(cloud={"ok": False}), lambda: B().set(cloud=None)])
def test_MO4_connectivity_offline_or_failed_cloud_call(scn):
    d = scn().evaluate()
    assert d.mode == "OFFLINE" and "OFFLINE_MODE" in d.reason_codes
