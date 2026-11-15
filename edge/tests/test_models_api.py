"""Model-backed tests (real ONNX weights) + API contract tests. Skipped if models/ is empty."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import numpy as np
import pytest

from edge import synth
from edge.events import EventBus
from edge.tests.conftest import requires_models

pytestmark = [pytest.mark.models, requires_models]


# ------------------------------------------------------------------ models
def test_pad_self_test_index_and_scale(engine):
    st = engine.health.pad_self_test
    assert st is not None and st.ok, st.message
    assert st.real_class_index == 1 and st.input_scale == 1.0
    assert st.live_min > st.attack_max
    separating = [(a["real_index"], a["input_scale"]) for a in st.alternatives if a["separates"]]
    assert separating == [(1, "raw 0-255")], "only index 1 with raw 0-255 input may separate live vs attack"


def test_detector_alignment_and_embedding(engine):
    frame = synth.base_frame()
    fa = engine.analyze_frame(0, 0, frame)
    assert fa.quality.face_count == 1 and fa.aligned is not None and fa.aligned.shape == (112, 112, 3)
    assert fa.quality.face_width_px >= 112
    e1 = engine.embed(fa)
    e2 = engine.embed(engine.analyze_frame(1, 0, synth.base_frame(shift_px=6)))
    assert e1.shape == (512,) and abs(float(np.linalg.norm(e1)) - 1.0) < 1e-3
    assert float(e1 @ e2) > 0.9


def test_device_detector_runs_on_every_frame(engine):
    fa = engine.analyze_frame(0, 0, synth.base_frame())
    sig = engine.device_score(fa)
    assert sig is not None and sig.device_conf < 0.25  # no phone/laptop/tv in the synthetic frame


# ------------------------------------------------------------------ API helpers
def start(client, kiosk="KIOSK_MAIN_01"):
    r = client.post("/v1/session/start", json={"kiosk_id": kiosk, "client": {
        "camera_label": "FaceTime HD Camera", "user_agent": "pytest", "screen": {}}, "flash_enabled": True})
    return r


def send_frames(client, sess, **kw):
    frames, meta = synth.make_attempt(sess, **kw)
    files, data = synth.multipart_files(frames, meta)
    return client.post(f"/v1/attempt/{sess['attempt_id']}/frames", files=files, data=data), meta


# ------------------------------------------------------------------ API
def test_health_shape(client):
    r = client.get("/v1/health")
    assert r.status_code == 200 and "x-latency-ms" in r.headers
    h = r.json()
    assert set(h) >= {"status", "version", "models_loaded", "self_test", "depth_probe", "uptime_s"}
    assert set(h["models_loaded"]) == {"minifasnet_v2", "minifasnet_v1se", "face_detector", "device_detector", "arcface"}
    assert all(h["models_loaded"].values())
    assert h["self_test"] == {"minifasnet_real_index": 1, "input_scale": "0-255 BGR", "passed": True}
    assert h["depth_probe"] in {"connected", "unavailable"}


def test_session_start_contract(client, thresholds):
    r = start(client)
    assert r.status_code == 201
    s = r.json()
    assert s["attempt_id"].startswith("att_") and s["nonce"].startswith("n_")
    seq = s["flash_sequence"]
    total = int(thresholds.get("liveness.flash.duration_ms"))  # derived: the YAML value is tuned live
    third = total // 3
    assert len(seq) == 3 and len({x["color"] for x in seq}) == 3
    assert [x["duration_ms"] for x in seq] == [third, third, total - 2 * third] and seq[0]["offset_ms"] == 0
    assert s["capture"] == {"frames": int(thresholds.get("quality.frames_per_attempt")), "window_ms": total,
                            "max_width_px": 1280, "jpeg_quality": 0.85}
    assert s["mode"] in {"ONLINE", "OFFLINE"}
    exp = datetime.fromisoformat(s["expires_at"])
    assert timedelta(seconds=8) < exp - datetime.now(UTC) <= timedelta(seconds=10)


def test_unknown_kiosk_forbidden(client):
    """DEMO_MODE=0: another kiosk is 403 FORBIDDEN. DEMO_MODE=1 (kiosk switch): a kiosk outside the verified
    bundle / the runtime's kiosk is 409 INVALID_STATE (edge/tests/test_round4.py has the full matrix)."""
    import dataclasses

    ctx = client.app.state.ctx
    real = ctx.settings
    try:
        for demo, status, code in ((False, 403, "FORBIDDEN"), (True, 409, "INVALID_STATE")):
            ctx.settings = dataclasses.replace(real, demo_mode=demo)
            r = start(client, kiosk="KIOSK_NOT_IN_BUNDLE")
            assert r.status_code == status and r.json()["error"]["code"] == code
    finally:
        ctx.settings = real


def test_frames_decision_contract_and_nonce_single_use(client):
    s = start(client).json()
    r, _ = send_frames(client, s)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["attempt_id"] == s["attempt_id"] and d["decision"] in {"ALLOW", "STEP_UP", "DENY"}
    assert isinstance(d["reason_codes"], list) and d["reason_codes"]
    assert d["mode"] in {"ONLINE", "OFFLINE"} and "stage" in d
    for k in ("liveness", "match", "quality", "total", "policy"):
        assert isinstance(d["latency_ms"][k], int) and d["latency_ms"][k] >= 0
    assert float(r.headers["x-latency-ms"]) > 0
    again, _ = send_frames(client, s)
    assert again.status_code == 409 and again.json()["error"]["code"] in {"NONCE_REUSED", "ATTEMPT_CLOSED"}


def test_signals_are_real(client, admin_headers):
    s = start(client).json()
    send_frames(client, s)
    dbg = client.get(f"/v1/admin/attempt/{s['attempt_id']}/signals", headers=admin_headers).json()
    frames = dbg["signals"]["frames"]
    assert len(frames) == 5
    assert all(f["pad_v2"] is not None and f["pad_v1se"] is not None for f in frames)
    assert all(f["moire"] is not None and f["mask_edge_ring"] is not None for f in frames)
    fl = dbg["signals"]["flash"]
    assert fl["r"] is not None and fl["r"] > 0.7 and fl["order_ok"] is True  # simulated reflection
    assert dbg["signals"]["camera"]["camera_label"] == "FaceTime HD Camera"


def test_nonce_mismatch_and_expiry(client):
    s = start(client).json()
    frames, meta = synth.make_attempt(s)
    meta["nonce"] = "n_forged"
    files, data = synth.multipart_files(frames, meta)
    r = client.post(f"/v1/attempt/{s['attempt_id']}/frames", files=files, data=data)
    assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN"
    s2 = start(client).json()
    client.app.state.ctx.sessions.get(s2["attempt_id"]).expires_at = datetime.now(UTC) - timedelta(seconds=1)
    r2, _ = send_frames(client, s2)
    assert r2.status_code == 410 and r2.json()["error"]["code"] == "NONCE_EXPIRED"


def test_frames_validation(client):
    s = start(client).json()
    frames, meta = synth.make_attempt(s)
    files, data = synth.multipart_files(frames[:2], {**meta, "frame_timestamps_ms": meta["frame_timestamps_ms"][:2]})
    r = client.post(f"/v1/attempt/{s['attempt_id']}/frames", files=files, data=data)
    assert r.status_code == 422 and r.json()["error"]["code"] == "VALIDATION_ERROR"
    assert client.post("/v1/attempt/att_nope/frames", files=files, data=data).status_code == 404


def test_admin_requires_token(client):
    assert client.get("/v1/admin/users").status_code == 401
    assert client.post("/v1/admin/mode", json={"force": "OFFLINE"}, headers={"X-Admin-Token": "x"}).status_code == 401


def test_enroll_list_match_delete(client, admin_headers, example_bundle):
    frames = [synth.jpeg(synth.base_frame(shift_px=s)) for s in (-8, -4, 0, 4, 8)]
    files = {f"frame_{i}": (f"f{i}.jpg", b, "image/jpeg") for i, b in enumerate(frames)}
    meta = {"user_id": "u_3c4d", "display_name": "Synthetic", "role": "student", "consent": True,
            "consent_version": "2026-11-14.v1", "card_id": "CARD-1", "provision_totp": True}
    r = client.post("/v1/enroll", files=files, data={"meta": json.dumps(meta)}, headers=admin_headers)
    assert r.status_code == 201, r.text
    e = r.json()
    assert e["user_id"] == "u_3c4d" and e["local_cache_updated"] and e["frames_used"] >= 3
    assert e["totp_provisioning_uri"].startswith("otpauth://totp/")
    users = client.get("/v1/admin/users", headers=admin_headers).json()["users"]
    assert any(u["user_id"] == "u_3c4d" and u["card"] for u in users)
    s = start(client).json()
    send_frames(client, s)
    dbg = client.get(f"/v1/admin/attempt/{s['attempt_id']}/signals", headers=admin_headers).json()
    tops = [f["match_top1"] for f in dbg["signals"]["frames"] if f["match_top1"] is not None]
    assert tops and max(tops) > 0.8
    assert {f["match_top1_user"] for f in dbg["signals"]["frames"] if f["match_top1_user"]} == {"u_3c4d"}
    no_consent = {**meta, "consent": False}
    assert client.post("/v1/enroll", files=files, data={"meta": json.dumps(no_consent)},
                       headers=admin_headers).status_code == 422
    d = client.delete("/v1/enroll/u_3c4d", headers=admin_headers)
    assert d.status_code == 200 and d.json()["local_removed"] is True


def test_reenrol_appends_and_keeps_the_totp_secret_unless_asked(client, admin_headers, example_bundle):
    """Adding a look (glasses on / off) appends templates and must not silently rotate the user's TOTP."""
    frames = [synth.jpeg(synth.base_frame(shift_px=s)) for s in (-8, -4, 0, 4, 8)]
    files = {f"frame_{i}": (f"f{i}.jpg", b, "image/jpeg") for i, b in enumerate(frames)}
    meta = {"user_id": "u_3c4d", "display_name": "Synthetic", "role": "student", "consent": True,
            "consent_version": "2026-11-14.v1", "provision_totp": True}

    def enrol(m):
        return client.post("/v1/enroll", files=files, data={"meta": json.dumps(m)}, headers=admin_headers)

    first = enrol(meta)
    assert first.status_code == 201, first.text
    assert first.json()["totp_provisioning_uri"].startswith("otpauth://totp/")
    again = enrol({k: v for k, v in meta.items() if k != "provision_totp"})  # default, not explicit
    assert again.status_code == 201, again.text
    body = again.json()
    assert body["template_version"] == first.json()["template_version"] + 1
    assert body["totp_provisioning_uri"] is None  # existing user: secret kept
    rotated = enrol(meta)  # explicit provision_totp=true still rotates on purpose
    assert rotated.status_code == 201 and rotated.json()["totp_provisioning_uri"].startswith("otpauth://totp/")
    assert client.delete("/v1/enroll/u_3c4d", headers=admin_headers).status_code == 200


def test_rendered_eval_context_and_metrics(client, admin_headers):
    ctx = {"run_id": "run_t1", "subject_id": "S01", "label": "bona_fide", "condition": "normal", "split": "dev"}
    r0 = client.post("/v1/admin/eval/context", json=ctx, headers=admin_headers)
    assert r0.status_code == 200 and r0.json()["active"] is True and r0.json()["context"] == ctx
    bad_ctx = {**ctx, "condition": "lab"}
    assert client.post("/v1/admin/eval/context", json=bad_ctx, headers=admin_headers).status_code == 422
    s = start(client).json()
    _, meta = send_frames(client, s)
    assert client.app.state.ctx.sessions.get(s["attempt_id"]).eval_tags == ctx
    r = client.post(f"/v1/attempt/{s['attempt_id']}/rendered",
                    json={"face_lock_at_ms": meta["face_lock_at_ms"], "rendered_at_ms": meta["face_lock_at_ms"] + 1400})
    assert r.status_code == 204
    again = client.post(f"/v1/attempt/{s['attempt_id']}/rendered",
                        json={"face_lock_at_ms": meta["face_lock_at_ms"], "rendered_at_ms": meta["face_lock_at_ms"] + 9})
    assert again.status_code == 204  # first beacon wins; repeats ignored
    m = client.get("/v1/metrics", params={"label": "bona_fide"}, headers=admin_headers).json()
    assert m["latency_ms"]["client"]["n"] == 1 and m["latency_ms"]["client"]["p50"] == 1400.0
    assert m["by_label"]["bona_fide"]["n"] >= 1 and m["by_label"]["bona_fide"]["latency_ms"]["client"]["n"] == 1
    assert client.delete("/v1/admin/eval/context", headers=admin_headers).status_code == 204
    s2 = start(client).json()
    _, meta2 = send_frames(client, s2)
    mismatch = client.post(f"/v1/attempt/{s2['attempt_id']}/rendered",
                           json={"face_lock_at_ms": meta2["face_lock_at_ms"] + 1, "rendered_at_ms": meta2["face_lock_at_ms"] + 900})
    assert mismatch.status_code == 422
    early = client.post(f"/v1/attempt/{s2['attempt_id']}/rendered",
                        json={"face_lock_at_ms": meta2["face_lock_at_ms"], "rendered_at_ms": meta2["face_lock_at_ms"] - 5})
    assert early.status_code == 422


def test_admin_misc(client, admin_headers):
    assert client.post("/v1/admin/rate-limit/reset", headers=admin_headers).status_code == 204
    r = client.post("/v1/admin/clock", json={"set_local": "09:30", "offset_s": 5}, headers=admin_headers)
    assert r.status_code in {403, 422}
    m = client.get("/v1/mode").json()
    assert "mode" in m and "demo_clock" in m


def test_cors_preflight(client):
    r = client.options("/v1/session/start", headers={"Origin": "http://localhost:5173",
                                                     "Access-Control-Request-Method": "POST"})
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"
    r2 = client.options("/v1/session/start", headers={"Origin": "http://evil.example",
                                                      "Access-Control-Request-Method": "POST"})
    assert r2.headers.get("access-control-allow-origin") is None


def test_depth_endpoints_need_device_token(client, settings):
    assert client.get("/v1/depth/pending", params={"wait_s": 0}).status_code == 401
    if not settings.depth_device_token:
        pytest.skip("DEPTH_DEVICE_TOKEN not set")
    from edge.tests.conftest import SecretHeaders

    hdr = SecretHeaders({"X-Depth-Token": settings.depth_device_token})
    assert client.get("/v1/depth/pending", params={"wait_s": 0}, headers=hdr).status_code == 204
    meta = {"attempt_id": "att_x", "depth_nonce": "dn_x", "depth_type": "depth", "dtype": "float32",
            "width": 4, "height": 4}
    files = {"depth_0": ("d0.bin", np.zeros(16, "<f4").tobytes(), "application/octet-stream")}
    r = client.post("/v1/depth/frames", files=files, data={"meta": json.dumps(meta)}, headers=hdr)
    assert r.status_code in {403, 409}


def test_sse_event_format():
    async def run():
        bus = EventBus()
        gen = bus.stream(lambda: asyncio.sleep(0, result=False), heartbeat_s=0.05)
        assert (await gen.__anext__()).startswith(": connected")
        bus.publish("decision", {"attempt_id": "att_1", "decision": "DENY", "eval": None})
        msg = await gen.__anext__()
        assert msg.startswith("event: decision\ndata: ") and msg.endswith("\n\n")
        assert json.loads(msg.split("data: ", 1)[1])["attempt_id"] == "att_1"
        bus.publish("rendered", {"attempt_id": "att_1", "client_latency_ms": 900})
        assert (await gen.__anext__()).startswith("event: rendered\n")
        with pytest.raises(ValueError):
            bus.publish("other", {})
        await gen.aclose()

    asyncio.run(run())


def _free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_lan_listener_serves_only_depth_with_token(engine, settings):
    import dataclasses

    import httpx
    from fastapi.testclient import TestClient

    from edge.app import build_context, create_app

    if not settings.depth_device_token:
        pytest.skip("DEPTH_DEVICE_TOKEN not set")
    port = _free_port()
    lan_settings = dataclasses.replace(settings, lan_port=port)
    app = create_app(lambda: build_context(lan_settings, engine))
    with TestClient(app) as c:
        assert c.app.state.ctx.lan_status == f"listening 0.0.0.0:{port}"
        base = f"http://127.0.0.1:{port}"
        from edge.tests.conftest import SecretHeaders

        hdr = SecretHeaders({"X-Depth-Token": settings.depth_device_token})
        assert httpx.get(f"{base}/v1/depth/pending", params={"wait_s": 0}, timeout=5).status_code == 401
        assert httpx.get(f"{base}/v1/depth/pending", params={"wait_s": 0}, headers=hdr, timeout=5).status_code == 204
        assert httpx.get(f"{base}/v1/health", timeout=5).status_code == 404
        assert httpx.post(f"{base}/v1/session/start", json={}, timeout=5).status_code == 404


def test_busy_lan_port_does_not_kill_the_api(engine, settings):
    import dataclasses
    import socket

    from fastapi.testclient import TestClient

    from edge.app import build_context, create_app

    blocker = socket.socket()
    blocker.bind(("0.0.0.0", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    try:
        app = create_app(lambda: build_context(dataclasses.replace(settings, lan_port=port), engine))
        with TestClient(app) as c:
            assert c.app.state.ctx.lan_status.startswith("bind_failed")
            assert c.get("/v1/health").status_code == 200
    finally:
        blocker.close()


def test_step_prechecks_are_protocol_errors(client):
    s = start(client).json()
    aid = s["attempt_id"]
    assert client.get(f"/v1/attempt/{aid}").status_code == 409  # frames not yet submitted
    ch = {"challenge_id": "chl_x", "nonce": "n_x", "same_track": True, "actions": [
        {"action": "SMILE", "prompted_at_ms": 1, "baseline": 0.0, "peak": 0.9}]}
    r = client.post(f"/v1/attempt/{aid}/challenge", content=json.dumps(ch), headers={"Content-Type": "application/json"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "INVALID_STATE"
    f = client.post(f"/v1/attempt/{aid}/fallback", json={"method": "TOTP", "code": "123456"})
    assert f.status_code == 409 and f.json()["error"]["code"] == "INVALID_STATE"
    assert client.post(f"/v1/attempt/{aid}/otp/send").status_code == 409
    rc = client.post("/v1/session/start", json={"kiosk_id": "KIOSK_MAIN_01", "recapture_of": aid, "client": {
        "camera_label": "FaceTime HD Camera", "user_agent": "pytest", "screen": {}}, "flash_enabled": True})
    assert rc.status_code == 409 and rc.json()["error"]["code"] == "INVALID_STATE"
    send_frames(client, s)
    got = client.get(f"/v1/attempt/{aid}")
    assert got.status_code == 200 and got.json()["attempt_id"] == aid


def test_admin_sync_offline_is_503(client, admin_headers):
    r = client.post("/v1/admin/sync", headers=admin_headers)
    assert r.status_code == 503 and r.json()["error"]["code"] == "CLOUD_UNAVAILABLE"
