"""HTTP contract end to end: fake_probe (the phone) <-> calibration server (the LAN listener stand-in).

Exercises long-poll, X-Depth-Token, depth_nonce echo, multipart upload, measurement and CSV logging.
"""

from __future__ import annotations

import csv
import json
import threading
import time
import urllib.error
import urllib.request

import numpy as np
import pytest

from depth import fake_probe, synth
from depth.calibrate import CalibrationServer, read_rows, summarise
from depth.protocol import encode_multipart

TOKEN = "test-token-not-a-secret"


@pytest.fixture
def server(cfg, tmp_path):
    srv = CalibrationServer(
        cfg,
        tmp_path / "cal.csv",
        token=TOKEN,
        host="127.0.0.1",
        port=0,
        frames=3,
        deadline_s=10.0,
        log=lambda _m: None,
    )
    srv.start()
    yield srv
    srv.stop()


def _edge(srv: CalibrationServer) -> str:
    return f"http://127.0.0.1:{srv.port}"


def _probe(srv: CalibrationServer, scene: str, n: int = 1) -> list[dict]:
    out: list[dict] = []
    t = threading.Thread(
        target=lambda: out.extend(
            fake_probe.run(_edge(srv), scene=scene, count=n, wait_s=2.0, token=TOKEN, seed=7)
        )
    )
    t.start()
    t.join(timeout=30)
    assert not t.is_alive(), "fake probe hung"
    return out


@pytest.mark.parametrize(
    "scene,label,d1,overall", [("flat", "print", "FAIL", "FAIL"), ("face", "live", "PASS", "PASS")]
)
def test_probe_to_server_passive(server, scene, label, d1, overall):
    server.enqueue(label=label, subject="s01")
    replies = _probe(server, scene)
    assert replies[0]["_http_status"] == 200 and replies[0]["overall"] == overall
    rows = read_rows(server.csv_path)
    assert len(rows) == 1 and rows[0]["label"] == label and rows[0]["cls_d1"] == d1
    assert (
        rows[0]["frames"] == "3"
        and rows[0]["depth_type"] == "disparity"
        and rows[0]["accuracy"] == "absolute"
    )
    assert TOKEN not in server.csv_path.read_text()  # the secret never reaches the CSV


def test_probe_challenge_measures_m1(server):
    job = server.enqueue(label="live", subject="s01")
    _probe(server, "face")
    server.enqueue(phase="CHALLENGE", label="live", subject="s01", attempt_id=job.attempt_id)
    reply = _probe(server, "face")[0]  # CHALLENGE on a live face = open mouth
    assert reply["signal"]["m1_mouth_residual_mm"] > 4.0
    rows = read_rows(server.csv_path)
    assert [r["phase"] for r in rows] == ["PASSIVE", "CHALLENGE"] and rows[1]["cls_m1"] == "DEFORMED"


def test_pending_requires_token_and_long_polls(server):
    req = urllib.request.Request(f"{_edge(server)}/v1/depth/pending?wait_s=0.2")
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=5)
    assert exc.value.code == 401
    req.add_header("X-Depth-Token", TOKEN)
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 204  # nothing queued
    server.enqueue(label="live")
    with urllib.request.urlopen(req, timeout=5) as resp:
        job = json.loads(resp.read())
    assert set(job) >= {"attempt_id", "phase", "frames", "deadline_ms", "depth_nonce"}


def test_upload_with_wrong_nonce_is_forbidden(server, cam):
    server.enqueue(label="print")
    job = fake_probe.poll_pending(_edge(server), 2.0, TOKEN)
    body, ctype, meta = fake_probe.build_upload(job, scene="flat", rng=np.random.default_rng(0))
    meta["depth_nonce"] = "forged"
    frame = synth.scene_print(cam)
    body, ctype = encode_multipart(meta, [synth.to_wire(frame.depth_m)])
    req = urllib.request.Request(
        f"{_edge(server)}/v1/depth/frames",
        data=body,
        method="POST",
        headers={"Content-Type": ctype, "X-Depth-Token": TOKEN},
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=5)
    assert exc.value.code == 403 and read_rows(server.csv_path) == []


def test_summary_verdicts():
    def rows(label, cls, n):
        return [
            {"label": label, "phase": "PASSIVE", "cls_d1": cls, "d1_plane_rms_mm": "1.0", "overall": "X"}
        ] * n

    assert "INSUFFICIENT DATA" in summarise(rows("live", "PASS", 3) + rows("print", "FAIL", 3))[1]
    assert "GO" in summarise(rows("live", "PASS", 10) + rows("print", "FAIL", 10))[1]
    assert (
        "NO-GO"
        in summarise(rows("live", "PASS", 10) + rows("print", "FAIL", 9) + rows("print", "UNSURE", 1))[1]
    )


def test_csv_header_is_stable(server):
    server.enqueue(label="live")
    _probe(server, "face")
    with server.csv_path.open() as fh:
        header = next(csv.reader(fh))
    assert header[:4] == ["ts_utc", "attempt_id", "phase", "label"] and "d1_plane_rms_mm" in header


def test_listener_matches_edge_for_depthprobe_v03(server):
    """DepthProbe 0.3.0 compatibility: Find Mac recognises a listener by the edge's exact 401 text, and the
    app's first poll is a quick wait_s=0 that must return at once (204 when nothing is queued)."""
    url = f"{_edge(server)}/v1/depth/pending?wait_s=0"
    with pytest.raises(urllib.error.HTTPError) as no_token:
        urllib.request.urlopen(urllib.request.Request(url), timeout=5)
    body = json.loads(no_token.value.read())
    assert no_token.value.code == 401 and body["error"]["message"] == "depth device token required"
    req = urllib.request.Request(url, headers={"X-Depth-Token": TOKEN})
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 204


# ------------------------------------------------------------------ DE-12: calibration server hardening

def test_concurrent_duplicate_uploads_are_measured_once(server, monkeypatch):
    """Two uploads with the same nonce race: exactly one is processed and logged, the other gets 409."""
    from depth import calibrate

    server.enqueue(label="print")
    job = fake_probe.poll_pending(_edge(server), 2.0, TOKEN)
    body, ctype, _ = fake_probe.build_upload(job, scene="flat", rng=np.random.default_rng(0))
    real = calibrate.process_upload

    def slow(*a, **kw):  # keep the first upload in flight while the second one is checked
        time.sleep(0.3)
        return real(*a, **kw)

    monkeypatch.setattr(calibrate, "process_upload", slow)
    codes: list[int] = []

    def post():
        codes.append(server.handle_frames(ctype, body)[0])

    threads = [threading.Thread(target=post) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert sorted(codes) == [200, 409]
    assert len(read_rows(server.csv_path)) == 1


def test_csv_cells_cannot_inject_spreadsheet_formulas(tmp_path):
    from depth.calibrate import CSV_FIELDS, append_row

    path = tmp_path / "c.csv"
    append_row(path, {"device": '=HYPERLINK("http://x","y")', "notes": "+cmd", "subject": "@x",
                      "label": "-1+1", "d1_plane_rms_mm": -1.5})
    row = next(csv.DictReader(path.open()))
    assert row["device"].startswith("'=") and row["notes"] == "'+cmd" and row["subject"] == "'@x"
    assert row["label"] == "'-1+1" and row["d1_plane_rms_mm"] == "-1.5"  # numbers untouched
    assert set(row) == set(CSV_FIELDS)


def test_non_integer_content_length_is_a_422(server):
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
    conn.putrequest("POST", "/v1/depth/frames")
    conn.putheader("X-Depth-Token", TOKEN)
    conn.putheader("Content-Length", "abc")
    conn.endheaders()
    resp = conn.getresponse()
    assert resp.status == 422 and b"VALIDATION_ERROR" in resp.read()
