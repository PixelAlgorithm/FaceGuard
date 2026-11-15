"""Scenario gate: POLICY_TEST_CASES parsing, JUnit -> ID mapping, store inspection (DUMMY inputs only)."""

from __future__ import annotations

import json
import sqlite3

from scenarios import cases as C
from scenarios import run_scenarios as R

JUNIT = """<?xml version="1.0"?><testsuites><testsuite name="pytest">
<testcase classname="policy.tests.test_cases" name="test_policy_case[S01]"/>
<testcase classname="policy.tests.test_cases" name="test_S02_totp_after_grace"><failure message="x"/></testcase>
<testcase classname="policy.tests.test_cases" name="test_policy_case[S02]"/>
<testcase classname="offline.tests" name="test_O01_offline_allow"><skipped/></testcase>
<testcase classname="t" name="test_sha256_D5_not_an_id_A256"/>
</testsuite></testsuites>"""


def test_policy_cases_parsed_from_doc():
    cases = C.parse()
    gate = C.gate_ids(cases)
    assert "S01" in gate and "O01" in gate and "Y01" in gate and "Q01" not in gate
    assert cases["S01"]["challenge"] == "SC1" and cases["O04"]["challenge"] == "SC2"
    assert cases["S01"]["decision"] == "STEP_UP" and "SCHEDULE_GRACE_WINDOW" in cases["S01"]["reason_codes"]
    assert cases["Q01"]["decision"] == "ALLOW" and cases["Q01"]["gate"] is False
    assert all(code in cases["O04"]["reason_codes"] for code in ("OFFLINE_MODE", "OFFLINE_HIGH_RISK_ZONE"))


def test_junit_mapping_and_status(tmp_path):
    xml = tmp_path / "j.xml"
    xml.write_text(JUNIT)
    by = R.map_outcomes(R.parse_junit(xml), "edge")
    assert R.status_for(by["S01"])[0] == "PASS"
    assert R.status_for(by["S02"])[0] == "FAIL"  # one failing test is enough
    assert R.status_for(by["O01"])[0] == "NOT_RUN"  # skipped only
    assert R.status_for(by.get("S03", []))[0] == "NOT_RUN"
    assert "D5" not in by and "A25" not in by


def _db(path, payload):
    con = sqlite3.connect(path)
    con.execute("create table decision_log (seq integer primary key, attempt_id text, payload blob)")
    con.execute("insert into decision_log (attempt_id, payload) values (?, ?)", ("att_DUMMY", payload))
    con.commit()
    con.close()


def test_store_inspection_flags_plaintext(tmp_path):
    bad = tmp_path / "bad.sqlite"
    _db(bad, json.dumps({"user_id": "u_3c4d", "decision": "ALLOW"}))
    st, detail = R.inspect_store([bad])
    assert st == "FAIL" and ("plaintext" in detail)
    good = tmp_path / "good.sqlite"
    _db(good, bytes(range(256)) * 2)  # opaque ciphertext-like bytes
    st, _ = R.inspect_store([good])
    assert st == "PASS"
    assert R.inspect_store([])[0] == "NOT_RUN"
