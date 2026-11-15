"""Capture logger: SSE parsing, event classification/normalisation/whitelisting, attempt association state machine,
kiosk 'rendered' join, eval-tag cross-checks, schema-valid rows, and end-to-end runs against a local fake edge
(SSE + poll fallback, admin eval context + rate-limit reset, token never echoed). DUMMY data only."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

import capture as C
from evallib import io as eio
from evallib import schema as S

TAGS = {"run_id": "DUMMY-CAP", "subject_id": "DUMMY_S03", "label": "bona_fide", "condition": "normal", "split": "test"}
ALLOW_EV = {"attempt_id": "att_01JCX4Q8Z7", "decision": "ALLOW", "stage": "final", "reason_codes": ["ACCESS_OK"],
            "bio_result": "BIO_PASS", "schedule_result": "IN_WINDOW", "mode": "ONLINE", "cache_state": "FRESH",
            "candidate": {"user_id": "u_dummy3", "display": "DUMMY NAME"},
            "scores": {"pad_mean": 0.94, "pad_pass_frames": 5, "flash_r": 0.82, "moire": 0.12, "device_conf": 0.0,
                       "match_local": 0.72, "match_margin": 0.31, "rekognition": 99.6, "mask": {}},
            "latency_ms": {"total": 512, "liveness": 118, "match": 431, "schedule": 18, "policy": 4},
            "policy_version": "2026-11-14.2", "bundle_version": 42, "eval": TAGS,
            # fields that must never reach the CSV:
            "embedding": [0.1] * 512, "frame_b64": "QUJD" * 200, "display_message": "Welcome DUMMY NAME"}
STEPUP_EV = {"attempt_id": "att_STEP", "decision": "STEP_UP", "stage": "liveness", "reason_codes": ["LIVENESS_UNSURE"],
             "mode": "ONLINE", "bio_result": "BIO_UNSURE", "candidate": {"user_id": "u_dummy3"}, "eval": TAGS,
             "scores": {"liveness": 0.71}, "latency_ms": {"total": 547, "liveness": 133, "match": 455, "policy": 3},
             "next_action": {"type": "CHALLENGE", "steps": ["CHALLENGE"]}}
CHAL_ALLOW = {"attempt_id": "att_STEP", "decision": "ALLOW", "stage": "challenge", "reason_codes": ["ACCESS_OK"],
              "resolved_codes": ["LIVENESS_UNSURE"], "mode": "ONLINE", "latency_ms": {"total": 9}, "eval": TAGS}
CHAL_DENY = CHAL_ALLOW | {"decision": "DENY", "reason_codes": ["CHALLENGE_FAILED"], "resolved_codes": []}


def rendered(aid, lat=1430.0):
    return {"attempt_id": aid, "face_lock_at_ms": 1_000_000.0, "rendered_at_ms": 1_000_000.0 + lat,
            "client_latency_ms": lat}


def lab(**kw):
    base = {"run_id": "DUMMY-CAP", "subject_id": "DUMMY_S03", "split": "test", "species": "bona_fide",
            "lighting": "office", "distance": "mid", "target_user_id": "u_dummy3", "plan_seq": 1}
    return C.Label(**(base | kw))


def n(ev):
    out = C.normalize(ev)
    assert out is not None
    return out


def test_iter_sse_parses_multiline_comments_and_ids():
    lines = [": heartbeat", "event: decision", "id: 7", 'data: {"a":', "data: 1}", "", "data: x", "", "data: tail"]
    evs = list(C.iter_sse(iter(lines)))
    assert evs[0] == ("decision", '{"a":\n1}', "7")
    assert evs[1] == ("message", "x", "7")
    assert evs[2] == ("message", "tail", "7")


def test_classify_by_event_name_type_field_or_shape():
    assert C.classify("decision", {"attempt_id": "a"}) == "decision"
    assert C.classify("rendered", {"attempt_id": "a"}) == "rendered"
    assert C.classify("message", {"type": "rendered", "attempt_id": "a"}) == "rendered"
    assert C.classify("message", ALLOW_EV) == "decision"
    assert C.classify("message", rendered("a")) == "rendered"
    assert C.classify("message", {"mode": "OFFLINE"}) == "other"
    assert C.normalize_rendered({"attempt_id": "a", "face_lock_at_ms": 10, "rendered_at_ms": 1510})[
        "client_latency_ms"] == 1500


def test_normalize_whitelists_and_maps_aliases():
    e = n(ALLOW_EV)
    assert e["scores"]["s_pad"] == 0.94 and e["scores"]["s_match"] == 0.72 and e["scores"]["s_rekognition"] == 99.6
    assert e["scores"]["s_depth"] is None  # dict-valued / absent -> None, never copied
    assert e["candidate_user_id"] == "u_dummy3" and e["eval_tags"] == TAGS
    flat = json.dumps(e)
    assert "embedding" not in flat and "QUJD" not in flat and "DUMMY NAME" not in flat
    assert C.normalize({"type": "mode", "mode": "OFFLINE"}) is None
    assert n(STEPUP_EV)["next_action_type"] == "CHALLENGE"
    assert n(STEPUP_EV)["scores"]["s_pad"] == 0.71  # API.md scores.liveness alias


def test_terminal_decision_waits_for_render_then_joins_client_latency():
    tr = C.Tracker(set(), render_wait_ms=2500)
    tr.arm(lab(), 1000)
    assert tr.feed(1100, n(ALLOW_EV)) is None and tr.state == "AWAIT_RENDER"
    row = tr.feed_rendered(1200, C.normalize_rendered(rendered("att_01JCX4Q8Z7", 1430)))
    assert row["decision"] == "ALLOW" and row["first_decision"] == "ALLOW" and row["stepup_outcome"] == "none"
    assert row["latency_ms"] == "1430" and row["latency_source"] == "kiosk_render"
    assert row["lat_server_total_ms"] == "512" and row["s_pad"] == "0.94" and row["condition"] == "normal"
    assert row["liveness_result"] == "PASS" and row["liveness_result_source"] == "derived"
    assert json.loads(row["scores"])["pad_label"] == "live"
    assert "EVAL_TAG" not in row["notes"]
    assert "embedding" not in json.dumps(row) and "DUMMY NAME" not in json.dumps(row)


def test_render_timeout_finishes_without_decision_time():
    tr = C.Tracker(set(), render_wait_ms=2500)
    tr.arm(lab(), 0)
    tr.feed(10, n(ALLOW_EV))
    assert tr.tick(2000) is None
    row = tr.tick(2600)
    assert row["latency_ms"] == "" and row["latency_source"] == "none" and "no_render_event" in row["notes"]


@pytest.mark.parametrize("final,outcome", [(CHAL_ALLOW, "passed"), (CHAL_DENY, "failed")])
def test_stepup_followed_to_terminal_with_first_render(final, outcome):
    tr = C.Tracker(set())
    tr.arm(lab(), 0)
    assert tr.feed(10, n(STEPUP_EV)) is None and tr.state == "FOLLOWING"
    tr.feed_rendered(50, C.normalize_rendered(rendered("att_STEP", 980)))  # the STEP_UP prompt was rendered
    row = tr.feed(4010, n(final))  # render already known -> finishes at once
    assert row["first_decision"] == "STEP_UP" and row["decision"] == final["decision"]
    assert row["stepup_outcome"] == outcome and row["stepup_rounds"] == 1 and row["stepup_ms"] == "4000"
    assert row["next_action_type"] == "CHALLENGE" and row["liveness_result"] == "UNSURE"
    assert row["s_pad"] == "0.71" and row["latency_ms"] == "980"


def test_recapture_chain_with_new_attempt_id():
    tr = C.Tracker(set(), render_wait_ms=0)
    tr.arm(lab(), 0)
    rec = {"attempt_id": "att_A", "decision": "STEP_UP", "stage": "quality", "reason_codes": ["QUALITY_LOW_LIGHT"],
           "mode": "ONLINE", "next_action": {"type": "RECAPTURE"}, "eval": TAGS}
    assert tr.feed(5, n(rec)) is None
    row = tr.feed(2000, n(ALLOW_EV | {"attempt_id": "att_B"}))
    assert row["attempt_id"] == "att_A" and "chain:att_A>att_B" in row["notes"]
    assert row["recaptures"] == 1 and row["first_decision"] == "STEP_UP" and row["decision"] == "ALLOW"
    assert row["liveness_result"] == "PASS" and row["s_pad"] == "0.94"


def test_no_response_after_transaction_cap():
    tr = C.Tracker(set(), first_timeout_ms=30_000)
    tr.arm(lab(), 0)
    assert tr.tick(29_000) is None
    row = tr.tick(30_001)
    assert row["decision"] == "NO_RESPONSE" and row["attempt_id"].startswith("noresp_DUMMY-CAP_1_")
    assert row["first_decision"] == "" and row["stepup_outcome"] == "none" and row["condition"] == "normal"


def test_unresolved_stepup_after_timeout():
    tr = C.Tracker(set(), stepup_timeout_ms=130_000)
    tr.arm(lab(), 0)
    tr.feed(10, n(STEPUP_EV))
    row = tr.tick(130_011)
    assert row["decision"] == "STEP_UP" and row["stepup_outcome"] == "unresolved"
    assert "stepup_unresolved" in row["notes"]


def test_unarmed_and_already_seen_attempts_ignored():
    tr = C.Tracker({"att_OLD"}, render_wait_ms=0)
    tr.feed(0, n(STEPUP_EV))  # IDLE -> unarmed, marked seen
    tr.arm(lab(), 100)
    assert tr.feed(200, n(CHAL_ALLOW)) is None  # resolution of the unarmed attempt is not a new attempt
    assert tr.feed(210, n(ALLOW_EV | {"attempt_id": "att_OLD"})) is None
    assert tr.state == "ARMED" and tr.counts["ignored_unarmed"] == 1
    row = tr.feed(300, n(ALLOW_EV))
    assert row["attempt_id"] == "att_01JCX4Q8Z7"


def test_new_attempt_during_stepup_closes_current_as_unresolved():
    tr = C.Tracker(set())
    tr.arm(lab(), 0)
    tr.feed(10, n(STEPUP_EV))
    row = tr.feed(20, n(ALLOW_EV))
    assert row["attempt_id"] == "att_STEP" and row["stepup_outcome"] == "unresolved"
    assert "stepup_abandoned" in row["notes"] and tr.counts["ignored_started_during_stepup"] == 1


@pytest.mark.parametrize("tags,expect", [
    (TAGS, None),
    (TAGS | {"label": "print"}, "EVAL_TAG_MISMATCH(label=print)"),
    (None, "EVAL_TAGS_MISSING"),
])
def test_eval_tags_cross_checked(tags, expect):
    tr = C.Tracker(set(), render_wait_ms=0)
    tr.arm(lab(), 0)
    row = tr.feed(5, n(ALLOW_EV | {"eval": tags}))
    if expect:
        assert expect in row["notes"]
    else:
        assert "EVAL_TAG" not in row["notes"]


def test_rate_limited_flagged():
    tr = C.Tracker(set(), render_wait_ms=0)
    tr.arm(lab(species="print"), 0)
    row = tr.feed(5, n({"attempt_id": "att_RL", "decision": "DENY", "stage": "final", "reason_codes": ["RATE_LIMITED"],
                        "mode": "ONLINE", "eval": TAGS | {"label": "print"}}))
    assert "RATE_LIMITED" in row["notes"] and row["liveness_result"] == "NOT_EVALUATED"


def test_edge_condition_mapping():
    assert C.edge_condition("office", "mid") == "normal"
    assert C.edge_condition("office", "far") == "far"
    assert C.edge_condition("dim", "far") == "dim"
    assert C.edge_condition("backlit", "near") == "backlit"


def test_rows_pass_schema_validation():
    rows = []
    for i, ev in enumerate([ALLOW_EV, STEPUP_EV]):
        tr = C.Tracker(set(), render_wait_ms=0)
        tr.arm(lab(plan_seq=i), 0)
        r = tr.feed(1, n(ev | {"attempt_id": f"att_{i}"}))
        rows.append(r or tr.feed(2, n(CHAL_ALLOW | {"attempt_id": f"att_{i}"})))
    tr = C.Tracker(set())
    tr.arm(lab(plan_seq=9), 0)
    rows.append(tr.tick(10**9))
    errors, _ = S.validate_attempts(rows, S.ATTEMPT_COLUMNS, results_file=False)
    assert errors == []


def test_sanitize_removes_blobs():
    row = C.sanitize({"notes": "x" * 1000, "reason_codes": "ACCESS_OK"})
    assert row["notes"].startswith("[REMOVED") and row["reason_codes"] == "ACCESS_OK"
    assert set(row) == set(S.ATTEMPT_COLUMNS)




# ------------------------------------------------------------------ end-to-end against a fake edge

TOKEN = "DUMMY-ADMIN-TOKEN-xyz"  # legacy X-Admin-Token (only with FG_ALLOW_LEGACY_ADMIN_TOKEN=1)
KEY = "fgk_dummy001." + "K" * 43  # evaluator API key (Authorization: Bearer)


class FakeEdge(BaseHTTPRequestHandler):
    events: ClassVar[list] = []
    admin_log: ClassVar[list] = []
    poll_log: ClassVar[list] = []
    auth_log: ClassVar[list] = []
    admin_status: ClassVar[int] = 0  # forced status for admin routes (e.g. 403); 0 = normal

    def log_message(self, *a):  # quiet
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        FakeEdge.auth_log.append((self.path, self.headers.get("Authorization"), self.headers.get("X-Admin-Token")))
        return (self.headers.get("Authorization") == f"Bearer {KEY}"
                or self.headers.get("X-Admin-Token") == TOKEN)

    def _admin(self, method):
        ok = self._authed()
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else None
        FakeEdge.admin_log.append((method, self.path, ok, body))
        if ok and FakeEdge.admin_status:
            return self._json({"error": {"code": "FORBIDDEN", "reason": "MISSING_PERMISSION",
                                         "required": ["eval:admin"]}}, FakeEdge.admin_status)
        return self._json({"ok": ok} if ok else {"error": {"code": "UNAUTHORIZED"}}, 200 if ok else 401)

    def do_POST(self):
        return self._admin("POST")

    def do_DELETE(self):
        return self._admin("DELETE")

    def do_GET(self):
        if self.path.startswith("/v1/health"):
            return self._json({"status": "ok", "version": "DUMMY"})
        if self.path.startswith("/v1/mode"):
            return self._json({"mode": "ONLINE", "sync_queue_depth": 0})
        if self.path.startswith("/v1/attempt/"):  # GET /v1/attempt/{id}: LATEST DecisionResponse, no eval key
            FakeEdge.poll_log.append(self.path)
            aid = self.path.rsplit("/", 1)[1]
            t = time.time() - self.server.t0
            hits = [ev for delay, typ, ev in self.events if delay <= t and typ == "decision"
                    and ev["attempt_id"] == aid]
            if not hits:
                return self._json({"error": {"code": "INVALID_STATE"}}, 409)
            return self._json({k: v for k, v in hits[-1].items() if k != "eval"})
        if self.path.startswith("/v1/events"):
            if getattr(self.server, "no_sse", False):
                return self._json({"error": "not found"}, 404)
            if not self._authed():
                return self._json({"error": {"code": "UNAUTHORIZED", "reason": "CREDENTIAL_INVALID"}}, 401)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            start = time.time()
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            for delay, typ, ev in self.events:
                time.sleep(max(0.0, delay - (time.time() - start)))
                self.wfile.write(f"event: {typ}\ndata: ".encode() + json.dumps(ev).encode() + b"\n\n")
                self.wfile.flush()
            time.sleep(1.0)
            return None
        return self._json({}, 404)


def _serve(events, no_sse=False):
    FakeEdge.events = events
    FakeEdge.admin_log = []
    FakeEdge.poll_log = []
    FakeEdge.auth_log = []
    FakeEdge.admin_status = 0
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeEdge)
    srv.t0 = time.time()
    srv.no_sse = no_sse
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


TAGS_DIM = TAGS | {"condition": "dim"}
EVENTS = [(0.8, "decision", ALLOW_EV | {"attempt_id": "att_E1", "eval": TAGS_DIM}),
          (0.9, "rendered", rendered("att_E1", 1390.0)),
          (1.3, "decision", STEPUP_EV | {"attempt_id": "att_E2", "eval": TAGS_DIM}),
          (1.4, "rendered", rendered("att_E2", 1012.0)),
          (1.7, "decision", CHAL_ALLOW | {"attempt_id": "att_E2", "eval": TAGS_DIM}),
          (1.8, "rendered", rendered("att_E2", 5100.0))]


@pytest.mark.parametrize("transport,no_sse", [("sse", False), ("auto", True)])
def test_end_to_end_capture(tmp_path, fixtures, transport, no_sse, monkeypatch, capsys):
    monkeypatch.setenv("FG_EVAL_API_KEY", KEY)
    monkeypatch.setenv("ADMIN_TOKEN", TOKEN)  # present but ignored: no FG_ALLOW_LEGACY_ADMIN_TOKEN
    monkeypatch.delenv("FG_ALLOW_LEGACY_ADMIN_TOKEN", raising=False)
    typed = iter(["att_E1", "att_E2"])  # poll-only mode: the operator types the ids from the admin live feed
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(typed))
    srv = _serve(EVENTS, no_sse=no_sse)
    try:
        out = tmp_path / "attempts.csv"
        rc = C.main(["--edge", f"http://127.0.0.1:{srv.server_port}", "--transport", transport,
                     "--out", str(out), "--subjects", str(fixtures / "subjects_DUMMY.csv"),
                     "--subject", "DUMMY_S03", "--species", "bona_fide", "--lighting", "dim", "--count", "2",
                     "--no-prompt", "--run-id", "DUMMY-CAP", "--first-timeout", "8", "--operator", "DUMMY"])
        assert rc == 0
        header, rows = eio.read_csv(out)
        assert header == S.ATTEMPT_COLUMNS and len(rows) == 2
        assert [r["attempt_id"] for r in rows] == ["att_E1", "att_E2"]
        assert rows[0]["decision"] == "ALLOW" and rows[0]["split"] == "test" and rows[0]["target_user_id"] == "u_dummy3"
        assert rows[1]["decision"] == "ALLOW"
        if transport == "sse":  # poll fallback has no 'rendered' join guarantee
            assert rows[1]["first_decision"] == "STEP_UP" and rows[1]["stepup_outcome"] == "passed"
            assert rows[0]["latency_ms"] == "1390" and rows[0]["latency_source"] == "kiosk_render"
            assert rows[1]["latency_ms"] == "1012"  # FIRST render of the attempt = decision time of the 2 s path
            assert rows[0]["face_lock_at_ms"] == "1000000"
            assert not FakeEdge.poll_log
        else:  # GET /v1/attempt/{id} only: latest response, no eval tags, no render; a missed STEP_UP is flagged
            assert FakeEdge.poll_log and all(p.startswith("/v1/attempt/att_E") for p in FakeEdge.poll_log)
            assert all("eval_tags_not_in_poll_response" in r["notes"] for r in rows)
            assert all(r["latency_source"] == "none" and "no_render_event" in r["notes"] for r in rows)
            assert (rows[1]["first_decision"] == "STEP_UP" and rows[1]["stepup_outcome"] == "passed") or (
                rows[1]["first_decision"] == "ALLOW" and "POLL_MISSED_STEPUP" in rows[1]["notes"])
        assert all("EVAL_TAG" not in r["notes"] for r in rows)
        assert S.validate_attempts(rows, header, results_file=False)[0] == []
        man = json.loads((tmp_path / "runs" / "DUMMY-CAP.json").read_text())
        assert man["kind"] == "capture" and man["counts"]["ALLOW"] == 2 and man["edge_credential"].startswith("API key key:dummy001")
        assert man["transport_used"] == ("sse" if transport == "sse" else "poll")
        assert man["edge_health_at_start"]["status"] == "ok" and len(man["thresholds_sha256"]) == 64
        assert man["shipped_switches"]["flash"]["state"] in ("ADVISORY", "ENFORCED")
        assert man["rate_limit_handling"]["reset_rate_limit"] == "attempt" and man["duplicates_dropped"] == 0
        # eval context set for each attempt with the edge enum, cleared after; limiter reset at start
        posts = [b for m, p, ok, b in FakeEdge.admin_log if m == "POST" and p == "/v1/admin/eval/context"]
        assert posts and all(ok for _, _, ok, _ in FakeEdge.admin_log)
        assert posts[0] == {"run_id": "DUMMY-CAP", "subject_id": "DUMMY_S03", "label": "bona_fide",
                            "condition": "dim", "split": "test"}
        assert any(m == "DELETE" for m, *_ in FakeEdge.admin_log)
        assert any(p == "/v1/admin/rate-limit/reset" for _, p, *_ in FakeEdge.admin_log)
        # every authenticated call used the Bearer key, never the legacy header
        assert FakeEdge.auth_log and all(a == f"Bearer {KEY}" and x is None for _, a, x in FakeEdge.auth_log)
        # neither secret leaks into output, manifest or CSV
        cap = capsys.readouterr()
        for blob in (cap.out, cap.err, out.read_text(), (tmp_path / "runs" / "DUMMY-CAP.json").read_text()):
            assert TOKEN not in blob and KEY not in blob
        raw = out.read_text()
        assert "embedding" not in raw and "QUJD" not in raw and "DUMMY NAME" not in raw
    finally:
        srv.shutdown()


def test_no_response_when_edge_silent(tmp_path, fixtures, monkeypatch):
    monkeypatch.setenv("FG_EVAL_API_KEY", KEY)
    srv = _serve([])
    try:
        out = tmp_path / "attempts.csv"
        assert C.main(["--edge", f"http://127.0.0.1:{srv.server_port}", "--out", str(out),
                       "--subjects", str(fixtures / "subjects_DUMMY.csv"), "--subject", "DUMMY_S04",
                       "--species", "print", "--count", "1", "--no-prompt", "--run-id", "DUMMY-NR",
                       "--first-timeout", "1", "--env-file", str(tmp_path / "no.env")]) == 0
        _, rows = eio.read_csv(out)
        assert len(rows) == 1 and rows[0]["decision"] == "NO_RESPONSE" and rows[0]["attempt_class"] == "attack"
    finally:
        srv.shutdown()


def _flags_run(tmp_path, fixtures, port, run_id="DUMMY-AUTH"):
    return C.main(["--edge", f"http://127.0.0.1:{port}", "--transport", "sse", "--out", str(tmp_path / "a.csv"),
                   "--subjects", str(fixtures / "subjects_DUMMY.csv"), "--subject", "DUMMY_S03",
                   "--species", "print", "--count", "1", "--no-prompt", "--run-id", run_id,
                   "--first-timeout", "3", "--env-file", str(tmp_path / "no.env")])


def _clear_cred_env(monkeypatch):
    for k in ("FG_EVAL_API_KEY", "FG_ALLOW_LEGACY_ADMIN_TOKEN", "ADMIN_TOKEN"):
        monkeypatch.delenv(k, raising=False)


def test_no_credential_exits_before_any_call(tmp_path, fixtures, monkeypatch, capsys):
    _clear_cred_env(monkeypatch)
    monkeypatch.setenv("ADMIN_TOKEN", TOKEN)  # legacy token without the opt-in flag is not used
    srv = _serve([])
    try:
        assert _flags_run(tmp_path, fixtures, srv.server_port) == 5
        assert not FakeEdge.admin_log and not FakeEdge.auth_log
        err = capsys.readouterr().err
        assert "FG_EVAL_API_KEY" in err and TOKEN not in err
    finally:
        srv.shutdown()


def test_legacy_token_only_with_opt_in_flag(tmp_path, fixtures, monkeypatch):
    _clear_cred_env(monkeypatch)
    monkeypatch.setenv("ADMIN_TOKEN", TOKEN)
    monkeypatch.setenv("FG_ALLOW_LEGACY_ADMIN_TOKEN", "1")
    srv = _serve([])
    try:
        assert _flags_run(tmp_path, fixtures, srv.server_port, "DUMMY-LEG") == 0
        assert FakeEdge.auth_log and all(x == TOKEN and a is None for _, a, x in FakeEdge.auth_log)
    finally:
        srv.shutdown()


def test_wrong_key_on_sse_or_admin_exits_with_clear_error(tmp_path, fixtures, monkeypatch, capsys):
    _clear_cred_env(monkeypatch)
    bad = "fgk_wrong001." + "W" * 43
    monkeypatch.setenv("FG_EVAL_API_KEY", bad)
    srv = _serve([])
    try:
        assert _flags_run(tmp_path, fixtures, srv.server_port) == 5
        err = capsys.readouterr().err
        assert "HTTP 401" in err and "key:wrong001" in err and bad not in err
        assert not (tmp_path / "a.csv").exists() or "DUMMY" not in (tmp_path / "a.csv").read_text()
    finally:
        srv.shutdown()


def test_admin_403_stops_the_run(tmp_path, fixtures, monkeypatch, capsys):
    _clear_cred_env(monkeypatch)
    monkeypatch.setenv("FG_EVAL_API_KEY", KEY)
    srv = _serve([])
    FakeEdge.admin_status = 403
    try:
        assert _flags_run(tmp_path, fixtures, srv.server_port) == 5
        err = capsys.readouterr().err
        assert "HTTP 403" in err and "MISSING_PERMISSION" in err and "eval:admin" in err
        man = json.loads((tmp_path / "runs" / "DUMMY-AUTH.json").read_text())
        assert man["auth_failed"] is True
    finally:
        srv.shutdown()


def test_sse_401_mid_run_stops_without_silent_retry(tmp_path, fixtures, monkeypatch, capsys):
    """Admin calls pass but the stream is refused: the run must stop, not poll/retry silently."""
    _clear_cred_env(monkeypatch)
    monkeypatch.setenv("FG_EVAL_API_KEY", KEY)
    srv = _serve([])
    orig = FakeEdge._authed
    monkeypatch.setattr(FakeEdge, "_authed", lambda self: orig(self) and not self.path.startswith("/v1/events"))
    try:
        t0 = time.time()
        assert _flags_run(tmp_path, fixtures, srv.server_port) == 5
        assert time.time() - t0 < 3.0  # stopped on the 401, did not wait for the first-decision timeout
        assert "GET /v1/events: HTTP 401" in capsys.readouterr().err
    finally:
        srv.shutdown()


AUTH_END_EVENTS = [(0.1, "decision", ALLOW_EV | {"attempt_id": "att_PRE"}),  # before arming: ignored
                   (0.3, "auth", {"reason": "SESSION_ENDED"})]
AUTH_END_FIRST_TIMEOUT_S = 20  # generous: the test must not depend on machine load


def test_sse_auth_event_mid_stream_stops_the_run(tmp_path, fixtures, monkeypatch, capsys):
    """T-07: the edge ends the stream with `event: auth` (key expired / revoked / lost events:read):
    the run stops with exit 5 at once, never reconnects or waits for the first-decision timeout."""
    _clear_cred_env(monkeypatch)
    monkeypatch.setenv("FG_EVAL_API_KEY", KEY)
    monkeypatch.setenv("ADMIN_TOKEN", TOKEN)  # present but unused (no legacy opt-in)
    srv = _serve(AUTH_END_EVENTS)
    try:
        t0 = time.time()
        rc = C.main(["--edge", f"http://127.0.0.1:{srv.server_port}", "--transport", "sse",
                     "--out", str(tmp_path / "a.csv"), "--subjects", str(fixtures / "subjects_DUMMY.csv"),
                     "--subject", "DUMMY_S03", "--species", "print", "--count", "1", "--no-prompt",
                     "--run-id", "DUMMY-AEV", "--first-timeout", str(AUTH_END_FIRST_TIMEOUT_S),
                     "--env-file", str(tmp_path / "no.env")])
        assert rc == 5
        # stopped on the auth event, well before the first-decision timeout (NO_RESPONSE row, rc 0)
        assert time.time() - t0 < AUTH_END_FIRST_TIMEOUT_S / 2
        assert not (tmp_path / "a.csv").exists()
        cap = capsys.readouterr()
        assert "event: auth" in cap.err and "key:dummy001" in cap.err
        for blob in (cap.out, cap.err):
            assert KEY not in blob and TOKEN not in blob
        man = json.loads((tmp_path / "runs" / "DUMMY-AEV.json").read_text())
        assert man["auth_failed"] is True
    finally:
        srv.shutdown()


def test_refuses_dummy_run_into_results(fixtures):
    with pytest.raises(SystemExit):
        C.main(["--subjects", str(fixtures / "subjects_DUMMY.csv"), "--subject", "DUMMY_S03", "--species", "print",
                "--run-id", "DUMMY-X", "--no-prompt", "--count", "1"])


def test_resume_refuses_mismatched_header(tmp_path, fixtures):
    out = tmp_path / "attempts.csv"
    out.write_text("a,b\n1,2\n")
    with pytest.raises(SystemExit):
        C.main(["--out", str(out), "--subjects", str(fixtures / "subjects_DUMMY.csv"), "--subject", "DUMMY_S03",
                "--species", "print", "--run-id", "DUMMY-H", "--no-prompt", "--count", "1"])


# ------------------------------------------------------------------ duplicate presentations (two capture clients)

def _dup(aid, fl_server, **scores):
    ev = ALLOW_EV | {"attempt_id": aid, "latency_ms": ALLOW_EV["latency_ms"] | {"face_lock_to_decision_server": fl_server}}
    if scores:
        ev["scores"] = ALLOW_EV["scores"] | scores
    return n(ev)


def test_duplicate_same_face_lock_and_scores_dropped_and_counted():
    tr = C.Tracker(set(), render_wait_ms=2500)
    tr.arm(lab(), 0)
    assert tr.feed(1000, _dup("att_K1", 900)) is None  # face lock = 1000 - 900 = 100
    assert tr.feed(1030, _dup("att_K2", 900)) is None  # face lock 130: |dt| = 30 ms <= 50 ms, same scores
    assert tr.counts["dropped_duplicate"] == 1 and tr.dups == {"att_K2": "att_K1"}
    assert tr.duplicates[0]["dropped"] == "att_K2" and tr.duplicates[0]["face_lock_dt_ms"] == 30.0
    row = tr.feed_rendered(1100, C.normalize_rendered(rendered("att_K1", 1400)))
    assert row["attempt_id"] == "att_K1" and "dup_dropped:att_K2(ALLOW)" in row["notes"]
    assert tr.feed(1200, _dup("att_K2", 900)) is None  # later events of the dropped twin are swallowed
    assert tr.state == "IDLE"


@pytest.mark.parametrize("dt_server,scores", [(840, {}), (900, {"pad_mean": 0.95})])
def test_not_a_duplicate_when_face_lock_apart_or_scores_differ(dt_server, scores):
    tr = C.Tracker(set(), render_wait_ms=0)
    tr.arm(lab(), 0)
    row1 = tr.feed(1000, _dup("att_K1", 900))  # face lock 100
    tr.arm(lab(plan_seq=2), 1010)
    row2 = tr.feed(1030, _dup("att_K2", dt_server, **scores))  # face lock 190 (dt 90 ms) or different pad
    assert row1["attempt_id"] == "att_K1" and row2["attempt_id"] == "att_K2"
    assert tr.counts["dropped_duplicate"] == 0


def test_no_scores_never_treated_as_duplicate():
    ev = {"attempt_id": "att_Q1", "decision": "DENY", "stage": "quality", "reason_codes": ["QUALITY_BLUR"],
          "mode": "ONLINE", "latency_ms": {"face_lock_to_decision_server": 900}}
    tr = C.Tracker(set(), render_wait_ms=0)
    tr.arm(lab(), 0)
    assert tr.feed(1000, n(ev))["attempt_id"] == "att_Q1"
    tr.arm(lab(plan_seq=2), 1001)
    assert tr.feed(1010, n(ev | {"attempt_id": "att_Q2"}))["attempt_id"] == "att_Q2"
    assert tr.counts["dropped_duplicate"] == 0


def test_poll_response_after_stepup_flags_missed_stepup():
    tr = C.Tracker(set(), render_wait_ms=0)
    tr.arm(lab(), 0)
    ev = n(CHAL_ALLOW | {"eval": None})
    ev["via"] = "poll"
    row = tr.feed(10, ev)
    assert "POLL_MISSED_STEPUP(first_seen_stage=challenge)" in row["notes"]
    assert "eval_tags_not_in_poll_response" in row["notes"]


def test_event_source_polls_followed_ids_only(monkeypatch):
    calls = []

    class R:
        def __init__(self, code, obj=None):
            self.status_code, self._obj = code, obj

        def json(self):
            return self._obj

    def fake_get(url, timeout):
        calls.append(url)
        return R(200, ALLOW_EV | {"attempt_id": "att_P1"}) if url.endswith("att_P1") else R(409)

    monkeypatch.setattr(C.httpx, "get", fake_get)
    import queue as _q
    q = _q.Queue()
    src = C.EventSource("http://127.0.0.1:1", q, transport="poll")
    src.follow({"att_P1", "att_P2"})
    assert src.poll_followed() == 1 and src.poll_followed() == 0  # unchanged response is not pushed twice
    assert set(calls) == {"http://127.0.0.1:1/v1/attempt/att_P1", "http://127.0.0.1:1/v1/attempt/att_P2"}
    kind, _, ev = q.get_nowait()
    assert kind == "decision" and ev["attempt_id"] == "att_P1" and ev["via"] == "poll"
    assert src.poll_calls["200"] == 2 and src.poll_calls["409"] == 2


def test_credential_never_sent_to_a_remote_http_edge(tmp_path, fixtures, monkeypatch, capsys):
    """DE-11: EDGE_URL / --edge pointing at a LAN host over http is refused before any request."""
    _clear_cred_env(monkeypatch)
    monkeypatch.setenv("FG_EVAL_API_KEY", KEY)
    rc = C.main(["--edge", "http://192.0.2.10:8000", "--out", str(tmp_path / "a.csv"),
                 "--subjects", str(fixtures / "subjects_DUMMY.csv"), "--subject", "DUMMY_S03",
                 "--species", "print", "--count", "1", "--no-prompt", "--run-id", "DUMMY-RM"])
    assert rc == 5 and "loopback" in capsys.readouterr().err
