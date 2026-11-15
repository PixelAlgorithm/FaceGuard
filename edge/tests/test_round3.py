"""Round-3 contract tests (lead decisions, 2026-11-14): flash ms/fps fields, challenge evidence
pass-through, template-cache status, offline cloud skip, demo controls, depth M1 timing, EMAIL_OTP
R11 re-issue, protocol consistency, cloud signing with server-corrected time."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import httpx
import numpy as np
import pytest

from edge import synth
from edge.tests.conftest import SecretHeaders, requires_models
from edge.tests.test_flash import FRAME_MS, SEQ, frames, run, series


# ------------------------------------------------------------------ 1. flash ms + fps fields
def test_flash_reports_lag_ms_lag_std_ms_and_fps():
    s = run().signal
    assert s.fps == pytest.approx(30.0, abs=0.1)
    assert s.lag_ms is not None and s.lag_ms == pytest.approx(s.lag_frames * FRAME_MS, abs=0.6)
    assert s.lag_std_ms is not None and s.lag_std_ms == pytest.approx(s.lag_std_frames * FRAME_MS, abs=0.6)
    assert 0.0 <= s.lag_ms <= 3 * FRAME_MS  # simulated 50 ms display->camera lag


def test_flash_lag_is_bounded_by_the_frames_not_the_client_series():
    """Frames show a 200 ms replay loop; a forged client series claims 50 ms."""
    a = run(fr=frames(SEQ, lag_ms=200.0), cl=series(SEQ, lag_ms=50.0))
    assert a.signal.lag_ms is not None and a.signal.lag_ms >= 150.0
    assert a.signal.lag_frames > 3.0


def test_flash_without_client_series_still_reports_ms_fields():
    s = run(cl=[]).signal
    assert s.lag_ms is not None and s.fps == pytest.approx(30.0, abs=0.1)
    assert 0.0 <= s.lag_ms <= 3 * FRAME_MS
    assert s.lag_std_ms is None  # needs the dense series


# ------------------------------------------------------------------ 2. challenge evidence pass-through
def test_challenge_actions_pass_through_unchanged():
    from edge.schemas import ChallengeMeta

    actions = [
        {"action": "TURN_LEFT", "prompted_at_ms": 1794630914000, "started_at_ms": 1794630914260,
         "completed_at_ms": 1794630914410, "baseline": -3.5, "peak": 22.5, "landmark_shift": None,
         "yaw_peak_deg": 22.5, "tracking_lost": False},
        {"action": "OPEN_MOUTH", "prompted_at_ms": 1794630915100, "started_at_ms": 1794630915320,
         "completed_at_ms": 1794630915560, "baseline": 0.02, "peak": 0.61, "landmark_shift": 0.18,
         "yaw_peak_deg": None, "tracking_lost": False},
    ]
    meta = ChallengeMeta.model_validate({"challenge_id": "chl_1", "nonce": "n_1", "same_track": True,
                                         "actions": actions})
    assert [a.model_dump() for a in meta.actions] == actions  # baseline = yaw at prompt kept as sent
    with pytest.raises(ValueError):
        ChallengeMeta.model_validate({"challenge_id": "c", "nonce": "n", "same_track": True,
                                      "actions": [{**actions[0], "unknown_field": 1}]})


# ------------------------------------------------------------------ fakes for unit-level tests
class FakeRuntime:
    def __init__(self, mode="OFFLINE", demo=True):
        self._mode = mode
        self.calls: list[tuple] = []
        self.demo_mode = demo

    def mode(self):
        return self._mode

    def record_cloud_result(self, ok):
        self.calls.append(("record_cloud_result", ok))

    def resolve_fallback(self, attempt_id, sub):
        self.calls.append(("resolve_fallback", sub.method))
        raise AssertionError("R11: an unavailable cloud verify must not reach the policy")

    def set_template_cache_status(self, **kw):
        self.calls.append(("set_template_cache_status", kw))

    def entitled_user_ids(self):
        return None


class FakeCloud:
    enabled = True

    def __init__(self, verify_result=None):
        self.verify_result = verify_result
        self.match_calls = 0

    async def otp_verify(self, attempt_id, otp_id, code):
        return self.verify_result

    async def match(self, attempt_id, jpeg, claimed):
        self.match_calls += 1
        from edge.policy.signals import CloudMatch

        return CloudMatch(ok=True, top1_user="u_3c4d", top1_similarity=99.5, runner_up_similarity=None)


def fake_ctx(settings, thresholds, runtime, cloud, engine=None):
    from edge.attempts import EdgeContext
    from edge.depth_bridge import DepthBridge
    from edge.events import EventBus
    from edge.metrics import MetricsStore
    from edge.session import AttemptStore

    return EdgeContext(settings=settings, thresholds=thresholds, engine=engine, runtime=runtime,
                       runtime_kind="fake", sessions=AttemptStore(), events=EventBus(), metrics=MetricsStore(),
                       cloud=cloud, depth=DepthBridge(thresholds), templates=None,
                       pool=ThreadPoolExecutor(max_workers=2), started_monotonic=time.monotonic())


def _attempt(ctx):
    att = ctx.sessions.create(kiosk_id="KIOSK_MAIN_01", flash_enabled=True, flash_sequence=[], camera_label="cam",
                              claimed_user_id=None, recapture_of=None, recapture_count=0)
    att.nonce_used = True
    return att


# ------------------------------------------------------------------ 7. EMAIL_OTP R11 via rt.drop_method
def _pending_second_factor(att, methods):
    att.last_response = {
        "attempt_id": att.attempt_id, "decision": "STEP_UP", "reason_codes": ["MATCH_LOW"], "mode": "ONLINE",
        "next_action": {"type": "SECOND_FACTOR", "steps": ["SECOND_FACTOR"], "methods": list(methods),
                        "challenge": None, "attempts_left": 1, "retry_after_s": None},
        "latency_ms": {"total": 300},
    }


class DropRuntime(FakeRuntime):
    def drop_method(self, attempt_id, method):
        self.calls.append(("drop_method", method))
        if method == "EMAIL_OTP" and self.only_email:
            raise ValueError("cannot drop the last remaining method")
        return {"attempt_id": attempt_id, "decision": "STEP_UP", "reason_codes": ["MATCH_LOW"], "mode": "ONLINE",
                "next_action": {"type": "SECOND_FACTOR", "steps": ["SECOND_FACTOR"], "methods": ["TOTP"],
                                "challenge": None, "attempts_left": 1, "retry_after_s": None},
                "latency_ms": {"total": 0, "policy": 1}}


def test_email_otp_cloud_unavailable_uses_runtime_drop_method(settings, thresholds):
    from edge.attempts import process_fallback
    from edge.schemas import FallbackRequest

    rt = DropRuntime(mode="ONLINE")
    rt.only_email = False
    ctx = fake_ctx(settings, thresholds, rt, FakeCloud(verify_result=None))
    att = _attempt(ctx)
    _pending_second_factor(att, ["TOTP", "EMAIL_OTP"])
    resp = asyncio.run(process_fallback(ctx, att, FallbackRequest(method="EMAIL_OTP", otp_id="otp_1", code="123456")))
    assert ("drop_method", "EMAIL_OTP") in rt.calls and ("record_cloud_result", False) in rt.calls
    assert not any(c[0] == "resolve_fallback" for c in rt.calls)  # R11: nothing counted
    assert resp["decision"] == "STEP_UP" and resp["reason_codes"] == ["MATCH_LOW"]
    assert resp["next_action"]["methods"] == ["TOTP"] and resp["next_action"]["attempts_left"] == 1
    assert att.last_response is resp  # the served response is the runtime's re-issue


def test_email_otp_only_method_unavailable_is_503_and_step_up_stays_open(settings, thresholds):
    from edge.attempts import process_fallback
    from edge.errors import ApiError
    from edge.schemas import FallbackRequest

    rt = DropRuntime(mode="ONLINE")
    rt.only_email = True
    ctx = fake_ctx(settings, thresholds, rt, FakeCloud(verify_result=None))
    att = _attempt(ctx)
    _pending_second_factor(att, ["EMAIL_OTP"])
    before = att.last_response
    with pytest.raises(ApiError) as e:
        asyncio.run(process_fallback(ctx, att, FallbackRequest(method="EMAIL_OTP", otp_id="otp_1", code="1")))
    assert e.value.code == "CLOUD_UNAVAILABLE" and e.value.status == 503
    assert att.last_response is before and att.pending_step == "SECOND_FACTOR"  # left open, nothing counted
    assert not any(c[0] in {"resolve_fallback", "decide_error"} for c in rt.calls)


def test_email_otp_verified_false_goes_to_the_policy(settings, thresholds):
    """A wrong code (cloud answered verified=false) is a counted failure: the policy decides."""
    from edge.attempts import process_fallback
    from edge.schemas import FallbackRequest

    class Counting(DropRuntime):
        def resolve_fallback(self, attempt_id, sub):
            self.calls.append(("resolve_fallback", sub.email_otp_verified))
            return {"attempt_id": attempt_id, "decision": "STEP_UP", "reason_codes": ["MATCH_LOW", "FALLBACK_FAILED"],
                    "next_action": {"type": "SECOND_FACTOR", "methods": ["TOTP", "EMAIL_OTP"], "attempts_left": 0},
                    "latency_ms": {}}

    rt = Counting(mode="ONLINE")
    rt.only_email = False
    ctx = fake_ctx(settings, thresholds, rt, FakeCloud(verify_result=False))
    att = _attempt(ctx)
    _pending_second_factor(att, ["TOTP", "EMAIL_OTP"])
    resp = asyncio.run(process_fallback(ctx, att, FallbackRequest(method="EMAIL_OTP", otp_id="otp_1", code="000000")))
    assert ("resolve_fallback", False) in rt.calls and not any(c[0] == "drop_method" for c in rt.calls)
    assert "FALLBACK_FAILED" in resp["reason_codes"]


# ------------------------------------------------------------------ 4. cloud match skipped offline
@requires_models
def test_cloud_match_skipped_when_next_attempt_is_offline(settings, thresholds, engine):
    from edge.attempts import match_branch

    frame = engine.analyze_frame(0, 0, synth.base_frame())
    jpegs = [synth.jpeg(synth.base_frame())]
    for mode, expect_calls in (("OFFLINE", 0), ("ONLINE", 1)):
        cloud = FakeCloud()
        ctx = fake_ctx(settings, thresholds, FakeRuntime(mode=mode), cloud, engine=engine)
        _, cloud_match, _ = asyncio.run(match_branch(ctx, _attempt(ctx), [frame], jpegs))
        assert cloud.match_calls == expect_calls
        assert (cloud_match is None) == (mode == "OFFLINE")


# ------------------------------------------------------------------ 6. depth CHALLENGE timing + M1 path
def _depth_enabled(thresholds):
    from edge.config import Thresholds

    raw = json.loads(json.dumps(thresholds.raw))
    raw["liveness"]["depth"]["enabled"] = True
    return Thresholds(raw)


def test_challenge_depth_request_is_timed_to_the_deformation_step(thresholds):
    from edge.depth_bridge import DepthBridge, challenge_capture_timing

    w = int(thresholds.get("challenge.step_window_ms"))
    react = int(thresholds.get("challenge.min_reaction_ms"))
    d0, i0 = challenge_capture_timing(["OPEN_MOUTH", "BLINK"], w, react)
    d1, i1 = challenge_capture_timing(["TURN_LEFT", "SMILE"], w, react)
    assert d1 - d0 == w and i0 == i1 and 100 <= i0 <= w // 2
    assert d1 <= 3000  # DepthProbe caps delay at 3 s

    async def go():
        bridge = DepthBridge(_depth_enabled(thresholds))
        await bridge.request("att_1", "CHALLENGE", 0, delay_ms=d1, interval_ms=i1)
        req = await bridge.next_pending(0.1)
        assert req.phase == "CHALLENGE" and req.delay_ms == d1 and req.interval_ms == i1 and req.frames == 3
        assert req.depth_nonce.startswith("dn_")

    asyncio.run(go())


def test_depth_challenge_upload_computes_m1_against_passive(thresholds):
    from depth import fake_probe

    from edge.depth_bridge import DepthBridge

    th = _depth_enabled(thresholds)
    rng = np.random.default_rng(3)

    async def go():
        bridge = DepthBridge(th)
        out = {}
        for phase in ("PASSIVE", "CHALLENGE"):
            await bridge.request("att_m1", phase, 1000)
            job = await bridge.next_pending(0.1)
            body, ctype, _meta = fake_probe.build_upload({"attempt_id": "att_m1", "phase": phase, "frames": 3,
                                                         "depth_nonce": job.depth_nonce}, scene="face", rng=rng)
            from depth.protocol import parse_multipart

            parts = parse_multipart(body, ctype)
            blobs = [parts[f"depth_{i}"][1] for i in range(3) if f"depth_{i}" in parts]
            assert bridge.consume_nonce("att_m1", phase, job.depth_nonce)
            out[phase] = bridge.submit(parts["meta"][1].decode(), blobs, None, None)
        return out

    out = asyncio.run(go())
    assert out["PASSIVE"].available and out["PASSIVE"].d1_plane_rms_mm is not None
    assert out["CHALLENGE"].m1_mouth_residual_mm is not None  # M1 measured vs the PASSIVE depth


# ------------------------------------------------------------------ 3/5/8 via the real app
@requires_models
def test_template_cache_status_and_age_always_reported(client, admin_headers, example_bundle):
    ctx = client.app.state.ctx
    m = client.get("/v1/mode").json()
    assert m["template_cache"]["model"].startswith("arcface") and m["template_cache"]["age_h"] is not None
    before = m["template_cache"]["count"]
    frames_ = [synth.jpeg(synth.base_frame(shift_px=s)) for s in (-8, -4, 0, 4, 8)]
    files = {f"frame_{i}": (f"f{i}.jpg", b, "image/jpeg") for i, b in enumerate(frames_)}
    meta = {"user_id": "u_9c0d", "display_name": "Synthetic", "role": "student", "consent": True,
            "consent_version": "v1", "provision_totp": False}
    assert client.post("/v1/enroll", files=files, data={"meta": json.dumps(meta)}, headers=admin_headers).status_code == 201
    assert ctx.runtime.mode_status()["template_cache"]["count"] == before + 1
    s = client.post("/v1/session/start", json={"kiosk_id": "KIOSK_MAIN_01", "client": {
        "camera_label": "FaceTime HD Camera", "user_agent": "t", "screen": {}}, "flash_enabled": True}).json()
    fr, mt = synth.make_attempt(s)
    f2, d2 = synth.multipart_files(fr, mt)
    client.post(f"/v1/attempt/{s['attempt_id']}/frames", files=f2, data=d2)
    sig = client.get(f"/v1/admin/attempt/{s['attempt_id']}/signals", headers=admin_headers).json()["signals"]
    assert sig["template_cache_age_h"] is not None
    assert client.delete("/v1/enroll/u_9c0d", headers=admin_headers).status_code == 200
    assert ctx.runtime.mode_status()["template_cache"]["count"] == before


@requires_models
def test_random_challenge_admin_route(client, admin_headers):
    ctx = client.app.state.ctx
    r = client.post("/v1/admin/random-challenge", json={"mode": "FORCE_NEXT"}, headers=admin_headers)
    assert r.status_code == 200 and ctx.runtime._random_challenge == "FORCE_NEXT"
    assert client.post("/v1/admin/random-challenge", json={"mode": "OFF"}, headers=admin_headers).status_code == 200
    assert client.post("/v1/admin/random-challenge", json={"mode": "BOGUS"}, headers=admin_headers).status_code == 422
    assert client.post("/v1/admin/random-challenge", json={"mode": "AUTO"}).status_code == 401
    real = ctx.settings
    ctx.settings = dataclasses.replace(real, demo_mode=False)
    try:
        r = client.post("/v1/admin/random-challenge", json={"mode": "AUTO"}, headers=admin_headers)
        assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN"
    finally:
        ctx.settings = real
    client.post("/v1/admin/random-challenge", json={"mode": "AUTO"}, headers=admin_headers)


@requires_models
def test_protocol_consistency(client):
    h = client.get("/v1/health").json()
    assert "self_test" in h and "depth_probe" in h and h["pad_self_test"]["ok"] is True  # alias kept
    pre = client.options("/v1/attempt/x/frames", headers={"Origin": "http://localhost:5173",
                                                          "Access-Control-Request-Method": "POST",
                                                          "Access-Control-Request-Headers": "X-Eval-Label"})
    assert pre.status_code == 400  # X-Eval-Label is gone (eval context replaces it)


@requires_models
def test_runtime_errors_map_to_protocol_codes(client, admin_headers):
    from edge.policy.runtime import CloudUnavailableError

    ctx = client.app.state.ctx

    class Boom:
        def __init__(self, exc):
            self.exc = exc

        def __call__(self, *a, **k):
            raise self.exc

    real_sync, real_clock = ctx.runtime.sync_now, ctx.runtime.set_demo_clock
    real_settings = ctx.settings
    try:
        ctx.settings = dataclasses.replace(real_settings, cloud_api_url="https://cloud.invalid")
        ctx.runtime.sync_now = Boom(CloudUnavailableError("forced OFFLINE"))
        r = client.post("/v1/admin/sync", headers=admin_headers)
        assert r.status_code == 503 and r.json()["error"]["code"] == "CLOUD_UNAVAILABLE"
        ctx.runtime.set_demo_clock = Boom(PermissionError("demo clock requires DEMO_MODE=1"))
        r = client.post("/v1/admin/clock", json={"offset_s": 60}, headers=admin_headers)
        assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN"
    finally:
        ctx.runtime.sync_now, ctx.runtime.set_demo_clock = real_sync, real_clock
        ctx.settings = real_settings


# ------------------------------------------------------------------ 9. cloud signing
def test_cloud_signing_utf8_key_and_server_corrected_time(settings, thresholds):
    from edge.cloud_client import CloudClient
    from edge.offline.signing import verify_request

    skew = 120  # cloud clock is 2 min ahead of the kiosk
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        server_now = int(time.time()) + skew
        ok = verify_request(req.method, req.url.path, req.content, req.headers,
                            kiosk_key=settings_.kiosk_hmac_key.encode("utf-8"), now_s=server_now)
        status = 200 if ok else 401
        return httpx.Response(status, json={"verified": ok}, headers={"X-Server-Time": str(server_now)})

    settings_ = dataclasses.replace(settings, cloud_api_url="https://cloud.test", kiosk_hmac_key="k-ünï-utf8",
                                    cloud_api_key="api")

    async def go():
        c = CloudClient(settings_, thresholds, transport=httpx.MockTransport(handler))
        await c.start()
        try:
            first = await c.otp_verify("att_1", "otp_1", "123456")  # 401 -> learns the skew -> retried once
            second = await c.otp_verify("att_1", "otp_1", "123456")
        finally:
            await c.stop()
        return first, second, c

    first, second, c = asyncio.run(go())
    assert first is True and second is True
    assert abs(c.clock_offset_s - skew) <= 2
    assert int(seen[-1].headers["X-Timestamp"]) == pytest.approx(time.time() + skew, abs=3)
    assert datetime.fromtimestamp(int(seen[-1].headers["X-Timestamp"]), UTC).year >= 2026


def test_depth_token_header_object_is_masked():
    assert "***" in repr(SecretHeaders({"X-Depth-Token": "secret"}))


@requires_models
def test_drop_method_against_the_real_runtime_maps_errors(client):
    """Real PolicyRuntime: no open step-up -> AttemptNotFoundError -> 409 INVALID_STATE (never a DENY)."""
    from edge.attempts import drop_method
    from edge.errors import ApiError

    ctx = client.app.state.ctx
    s = client.post("/v1/session/start", json={"kiosk_id": "KIOSK_MAIN_01", "client": {
        "camera_label": "FaceTime HD Camera", "user_agent": "t", "screen": {}}, "flash_enabled": True}).json()
    att = ctx.sessions.get(s["attempt_id"])

    async def go():
        return await drop_method(ctx, att, "EMAIL_OTP")

    with pytest.raises(ApiError) as e:
        asyncio.run(go())
    assert e.value.code == "INVALID_STATE" and e.value.status == 409
