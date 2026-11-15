"""Parse docs/POLICY_TEST_CASES.md (normative policy vectors) into {ID: case}.

The SC1/SC2 gate (H5) is keyed by these IDs (lead decision, round 2): section 5 = SC1 (schedule), sections 6 and 7 =
SC2 (offline; connectivity, storage, sync). Sections 1-4 and 8 are core biometric policy (reported, not gate).
Expected values are read from the doc at run time, never hand-copied.
"""

from __future__ import annotations

import re
from pathlib import Path

from evallib import PROJECT_DIR
from evallib import schema as S

DOC = PROJECT_DIR / "docs" / "POLICY_TEST_CASES.md"
SECTION_CHALLENGE = {"1": "CORE", "2": "CORE", "3": "CORE", "4": "CORE", "5": "SC1", "6": "SC2", "7": "SC2",
                     "8": "CORE"}
GATE_SECTIONS = {"5", "6", "7"}
ID_RE = re.compile(r"^[A-Z]\d{2}$")
CODE_RE = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b")
DECISIONS = ("ALLOW", "STEP_UP", "DENY")


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def parse(path: Path = DOC) -> dict[str, dict]:
    cases: dict[str, dict] = {}
    section, title, header = None, "", None
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^##\s+(\d+)\.\s*(.*)", line)
        if m:
            section, title, header = m.group(1), m.group(2).strip(), None
            continue
        if not line.startswith("|") or section is None:
            continue
        cells = _cells(line)
        if cells and cells[0] == "ID":
            header = [c.lower() for c in cells]
            continue
        if header is None or not cells or not ID_RE.match(cells[0]) or set(cells[0]) <= {"-"}:
            continue
        row = dict(zip(header, cells, strict=False))
        dec_txt = row.get("decision", "") or row.get("expected", "")
        decisions = [d for d in re.findall(r"STEP_UP|ALLOW|DENY", dec_txt)]
        codes_txt = row.get("reason_codes", "")
        codes = [c for c in CODE_RE.findall(codes_txt) if c in S.ALL_CODES]
        setup = row.get("base + deltas") or row.get("who / kiosk / local time") or row.get("setup") or \
            row.get("property") or ""
        cases[cells[0]] = {
            "id": cells[0],
            "section": section,
            "section_title": title,
            "challenge": SECTION_CHALLENGE.get(section, "CORE"),
            "gate": section in GATE_SECTIONS,
            "setup": setup,
            "decision_text": dec_txt,
            "decision": decisions[0] if decisions else None,
            "final_decision": decisions[-1] if decisions else None,
            "reason_codes_text": codes_txt,
            "reason_codes": codes,
            "next_action": row.get("next_action", ""),
            "expected_text": row.get("expected", ""),
            "matrix_row": row.get("row", ""),
        }
    return cases


def expected_text(c: dict) -> str:
    if c.get("decision_text") and c.get("decision"):
        codes = c.get("reason_codes_text") or ""
        return f"{c['decision_text']} [{codes}]" if codes else c["decision_text"]
    return c.get("expected_text") or c.get("decision_text") or ""


def gate_ids(cases: dict[str, dict]) -> list[str]:
    return [k for k, v in cases.items() if v["gate"]]
