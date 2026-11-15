"""Scenario gate: POLICY_TEST_CASES parsing, JUnit -> ID mapping, store inspection (DUMMY inputs only)."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

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


# ------------------------------------------------------------------ admin backends against a local fake edge

KEY = "fgk_dummy003." + "O" * 43


class _Edge(BaseHTTPRequestHandler):
    log: ClassVar[list] = []
    mode: ClassVar[str] = "ONLINE"
    deny: ClassVar[int] = 0
    broken_mode: ClassVar[bool] = False  # GET /v1/mode returns non-JSON while forced OFFLINE
    stall_s: ClassVar[float] = 0.0  # POST force OFFLINE is applied, then the reply stalls this long  # 0 = allow the Bearer key; else forced status for admin routes

    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _admin_ok(self):
        authed = self.headers.get("Authorization") == f"Bearer {KEY}" and not self.headers.get("X-Admin-Token")
        if not authed:
            self._send({"error": {"code": "UNAUTHORIZED"}}, 401)
            return False
        if _Edge.deny:
            self._send({"error": {"code": "FORBIDDEN", "reason": "MISSING_PERMISSION",
                                  "required": ["mode:switch"]}}, _Edge.deny)
            return False
        return True

    def do_GET(self):
        if self.path == "/v1/mode":
            if _Edge.broken_mode and _Edge.mode == "OFFLINE":
                return self._send("<html>proxy error</html>")  # JSON string, not an object
            return self._send({"mode": _Edge.mode, "sync_queue_depth": 0, "forced": _Edge.mode == "OFFLINE"})
        if self.path == "/v1/admin/store" and self._admin_ok():
            return self._send({"records": [{"attempt_id": "att_DUMMY", "decision": "ALLOW",
                                            "scores": {"pad": 0.91}}]})
        return None

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        _Edge.log.append((self.path, body))
        if self.path == "/v1/admin/mode" and self._admin_ok():
            _Edge.mode = "OFFLINE" if body.get("force") == "OFFLINE" else "ONLINE"
            if _Edge.mode == "OFFLINE" and _Edge.stall_s:
                time.sleep(_Edge.stall_s)  # force applied, reply late: the client times out
            return self._send({"ok": True})
        return None


@pytest.fixture
def edge(monkeypatch):
    for k in ("FG_OPS_API_KEY", "FG_ALLOW_LEGACY_ADMIN_TOKEN", "ADMIN_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    _Edge.log, _Edge.mode, _Edge.deny, _Edge.broken_mode, _Edge.stall_s = [], "ONLINE", 0, False, 0.0
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Edge)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _api(tmp_path, edge, *extra):
    return R.main(["--backend", "api", "--yes-toggle-mode", "--edge", edge, "--run-id", "DUMMY-SC",
                   "--out", str(tmp_path / "scen.csv"), "--env-file", str(tmp_path / "no.env"), *extra])


def test_api_backend_uses_ops_key_and_restores_auto(tmp_path, edge, monkeypatch, capsys):
    monkeypatch.setenv("FG_OPS_API_KEY", KEY)
    assert _api(tmp_path, edge) == 0
    forces = [b for p, b in _Edge.log if p == "/v1/admin/mode"]
    assert [b["force"] for b in forces] == ["OFFLINE", "AUTO"]
    assert forces[0]["max_minutes"] == R.FORCE_OFFLINE_MAX_MINUTES and forces[0]["reason"]
    rows = (tmp_path / "scen.csv").read_text()
    assert ",X06," in rows
    assert KEY not in rows + capsys.readouterr().out


def _rows(tmp_path):
    import csv

    with (tmp_path / "scen.csv").open() as fh:
        return {r["scenario_id"]: r for r in csv.DictReader(fh)}


def test_x06_badge_only_is_never_a_pass(tmp_path, edge, monkeypatch):
    """T-04: X06 also expects OFFLINE_MODE on the very next attempt and heartbeats in the background; this
    backend observes only the GET /v1/mode badge, so a correct badge is NOT_RUN (partial), never PASS."""
    monkeypatch.setenv("FG_OPS_API_KEY", KEY)
    assert _api(tmp_path, edge) == 0
    x06 = _rows(tmp_path)["X06"]
    assert x06["status"] == "NOT_RUN"
    assert "badge" in x06["detail"] and "OFFLINE_MODE" in x06["detail"] and "not exercised" in x06["detail"]
    assert "mode OFFLINE" in x06["detail"] and "forced True" in x06["detail"]


def test_x06_wrong_badge_is_a_fail(tmp_path, edge, monkeypatch):
    """T-04: the badge part is still checked: a force that never shows as OFFLINE/forced is FAIL."""
    monkeypatch.setenv("FG_OPS_API_KEY", KEY)
    monkeypatch.setattr(R, "MODE_OFFLINE_WAIT_S", 0.5)
    orig = _Edge.do_POST

    def ignore_force(self):
        orig(self)
        _Edge.mode = "ONLINE"  # edge accepted the POST but never went OFFLINE

    monkeypatch.setattr(_Edge, "do_POST", ignore_force)
    assert _api(tmp_path, edge) == 0
    assert _rows(tmp_path)["X06"]["status"] == "FAIL"


def test_operator_forced_offline_is_left_alone(tmp_path, edge, monkeypatch, capsys):
    """T-06: an operator's existing forced OFFLINE is never replaced or ended by the runner."""
    monkeypatch.setenv("FG_OPS_API_KEY", KEY)
    _Edge.mode = "OFFLINE"  # GET /v1/mode reports forced true before the run
    assert _api(tmp_path, edge) == 0
    assert not [p for p, _ in _Edge.log if p == "/v1/admin/mode"] and _Edge.mode == "OFFLINE"
    rows = _rows(tmp_path)
    for cid in ("X06", "X07"):
        assert rows[cid]["status"] == "NOT_RUN"
        assert "edge already forced OFFLINE by an operator; not toggled" in rows[cid]["detail"]
    assert "already forced" in capsys.readouterr().err


def test_auto_restored_when_offline_post_times_out_after_applying(tmp_path, edge, monkeypatch):
    """T-05: the edge applies the force but the reply times out: AUTO must still be posted."""
    monkeypatch.setenv("FG_OPS_API_KEY", KEY)
    monkeypatch.setattr(R, "ADMIN_TIMEOUT_S", 0.3, raising=False)
    _Edge.stall_s = 1.0
    assert _api(tmp_path, edge) == 0
    forces = [b["force"] for p, b in _Edge.log if p == "/v1/admin/mode"]
    assert forces[0] == "OFFLINE" and forces[-1] == "AUTO" and _Edge.mode == "ONLINE"
    assert _rows(tmp_path)["X06"]["status"] == "ERROR"


def test_forced_toggle_never_recorded_as_heartbeat_or_sync_cases(tmp_path, edge, monkeypatch):
    """DE-06: a forced OFFLINE is X06; X02 (3 heartbeat misses) and X04 (sync drains N>0, new bundle) are
    not exercised by this backend, and X07 needs queued records (queue empty here)."""
    monkeypatch.setenv("FG_OPS_API_KEY", KEY)
    assert _api(tmp_path, edge) == 0
    ids = [line.split(",")[2] for line in (tmp_path / "scen.csv").read_text().splitlines()[1:]]
    assert "X06" in ids and "X02" not in ids and "X04" not in ids
    assert "X07" not in ids or "NOT_RUN" in (tmp_path / "scen.csv").read_text()


def test_auto_restored_when_the_run_errors_after_forcing_offline(tmp_path, edge, monkeypatch):
    """DE-09: any exception after the force must still POST force AUTO."""
    monkeypatch.setenv("FG_OPS_API_KEY", KEY)
    _Edge.broken_mode = True
    assert _api(tmp_path, edge) == 0
    forces = [b["force"] for p, b in _Edge.log if p == "/v1/admin/mode"]
    assert forces[0] == "OFFLINE" and forces[-1] == "AUTO" and _Edge.mode == "ONLINE"
    assert "ERROR" in (tmp_path / "scen.csv").read_text()


def test_missing_case_id_never_toggles_the_kiosk(tmp_path, edge, monkeypatch):
    monkeypatch.setenv("FG_OPS_API_KEY", KEY)
    cred = R.A.load_credential(R.A.OPS_KEY_ENV, tmp_path / "no.env")
    with pytest.raises(KeyError):
        R.run_api({}, "DUMMY-SC", edge, cred)
    assert not _Edge.log


@pytest.mark.parametrize("status", [401, 403])
def test_api_backend_auth_failure_exits_5_no_rows(tmp_path, edge, monkeypatch, capsys, status):
    monkeypatch.setenv("FG_OPS_API_KEY", KEY if status == 403 else "fgk_wrong003." + "W" * 43)
    _Edge.deny = 403 if status == 403 else 0
    assert _api(tmp_path, edge) == 5
    assert not (tmp_path / "scen.csv").exists()
    err = capsys.readouterr().err
    assert f"HTTP {status}" in err and KEY not in err


def test_api_backend_without_credential_exits_5(tmp_path, edge, monkeypatch, capsys):
    monkeypatch.setenv("ADMIN_TOKEN", "DUMMY-ADMIN-TOKEN-xyz")  # ignored without FG_ALLOW_LEGACY_ADMIN_TOKEN
    assert _api(tmp_path, edge) == 5 and not _Edge.log
    assert "FG_OPS_API_KEY" in capsys.readouterr().err


def test_store_backend_reads_admin_store_with_bearer(tmp_path, edge, monkeypatch):
    monkeypatch.setenv("FG_OPS_API_KEY", KEY)
    rc = R.main(["--backend", "store", "--edge", edge, "--run-id", "DUMMY-ST", "--out", str(tmp_path / "s.csv"),
                 "--store-glob", str(tmp_path / "none" / "*.sqlite"),
                 "--env-file", str(tmp_path / "no.env")])
    rows = (tmp_path / "s.csv").read_text()
    assert rc == 0 and "D01" in rows and "keys within the D01 whitelist" in rows
