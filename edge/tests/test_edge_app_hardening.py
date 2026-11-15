"""Edge-app hardening (swarm 2026-11-15): one regression test per audit finding, written before the fix.

Finding ids: /tmp/fg_audit_results/audit_edge-core-api.json (F*), audit_edge-access-enroll.json (EAE-*),
audit_edge-ml.json (EM-07), runtime_offline-e2e.json (SC2-D4, SC2-D7). Model-free fakes, dummy secrets,
never the live :8000 edge and never the real cloud.
"""

from __future__ import annotations

import asyncio
import dataclasses
import math
import time
import types

import pytest

from edge.tests.test_round4 import StubRuntime, lite_client, lite_ctx
from edge.tests.test_round5 import (
    EMB_A,
    EMB_B,
    LEVEL_B,
    FakeCloud,
    FakeEngine,
    frames_of,
    make_templates,
    new_attempt,
)

ALL_USERS = frozenset({"u_a", "u_b"})


# ------------------------------------------------------------------ F1: full-gallery ranking
class EntitledOnlyARuntime(StubRuntime):
    """u_b is revoked / unentitled (not in entitled_user_ids) but its templates are still cached."""

    def __init__(self, mode: str = "OFFLINE", excluded: set[str] | None = None, fail: bool = False) -> None:
        super().__init__(mode)
        self._excluded = excluded or set()
        self._fail = fail

    def entitled_user_ids(self) -> set[str]:
        return {"u_a"}

    def excluded_user_ids(self) -> set[str]:
        if self._fail:
            raise RuntimeError("store unreadable")
        return set(self._excluded)


def _f1_ctx(lite_settings, thresholds, tmp_path, runtime):
    ctx = lite_ctx(lite_settings, thresholds, runtime, cloud=FakeCloud(enabled=False))
    ctx.engine = FakeEngine()
    ctx.templates = make_templates(tmp_path)
    return ctx


def _local_match(ctx, level: int):
    from edge.attempts import match_branch

    frames, jpegs = frames_of(ctx, level)
    local, _, _ = asyncio.run(match_branch(ctx, new_attempt(ctx), frames, jpegs))
    return local


@pytest.fixture
def lite_settings(settings, tmp_path):
    return dataclasses.replace(settings, kiosk_id="KIOSK_MAIN_01", cloud_api_url="", demo_mode=True, lan_port=0,
                               data_dir=tmp_path)


def test_f1_revoked_lookalike_is_the_top1_not_hidden(lite_settings, thresholds, tmp_path):
    """B (unentitled, still cached) shows up: B must be the top-1 (the schedule then DENYs B), never A."""
    ctx = _f1_ctx(lite_settings, thresholds, tmp_path, EntitledOnlyARuntime())
    local = _local_match(ctx, LEVEL_B)
    assert local and {m.top1_user for m in local.values()} == {"u_b"}
    m = next(iter(local.values()))
    assert m.top1 == pytest.approx(1.0, abs=1e-3) and m.top2 == pytest.approx(float(EMB_A @ EMB_B), abs=1e-3)
    assert m.n_users == 2  # the margin is measured against every cached user


def test_f1_erased_users_are_never_candidates(lite_settings, thresholds, tmp_path):
    ctx = _f1_ctx(lite_settings, thresholds, tmp_path, EntitledOnlyARuntime(excluded={"u_b"}))
    local = _local_match(ctx, LEVEL_B)
    assert {m.top1_user for m in local.values()} == {"u_a"} and all(m.n_users == 1 for m in local.values())


@pytest.mark.parametrize("runtime", [EntitledOnlyARuntime(fail=True), StubRuntime("OFFLINE")])
def test_f1_runtime_that_cannot_answer_gives_no_candidate(lite_settings, thresholds, tmp_path, runtime):
    ctx = _f1_ctx(lite_settings, thresholds, tmp_path, runtime)
    assert all(m.top1_user is None for m in _local_match(ctx, LEVEL_B).values())


def test_f1_matcher_exclude_and_allowed(tmp_path):
    from edge.ml.matcher import search

    g = make_templates(tmp_path).gallery
    assert search(EMB_B, g).top1_user == "u_b"
    assert search(EMB_B, g, exclude={"u_b"}).top1_user == "u_a"
    assert search(EMB_B, g, exclude=ALL_USERS).top1_user is None


# ------------------------------------------------------------------ F6: metrics bound never overflows
def test_f6_clopper_pearson_large_n_is_finite_and_fast():
    from edge.metrics import clopper_pearson_upper, error_upper_95

    t = time.perf_counter()
    ub = clopper_pearson_upper(200, 5000)
    assert 200 / 5000 < ub < 0.05 and time.perf_counter() - t < 0.5
    assert clopper_pearson_upper(1, 10) == pytest.approx(0.3942, abs=1e-3)  # textbook one-sided 95 %
    assert clopper_pearson_upper(420, 1100) < 1.0 and math.isfinite(clopper_pearson_upper(4999, 5000))
    assert error_upper_95(0, 100) == 0.03


def test_f6_summary_with_many_errors_is_a_200(lite_settings, thresholds):
    ctx = lite_ctx(lite_settings, thresholds, StubRuntime("ONLINE"))
    for i in range(5000):
        ctx.metrics.record({"attempt_id": f"a{i}", "decision": "DENY" if i % 25 == 0 else "ALLOW",
                            "mode": "ONLINE", "reason_codes": [], "latency_ms": {"total": 10}}, "bona_fide")
    out = ctx.metrics.summary()
    assert out["by_label"]["bona_fide"]["n"] == 5000 and out["by_label"]["bona_fide"]["bpcer_upper_95"] < 0.05


def test_f10_metrics_record_survives_absurd_latency(lite_settings, thresholds):
    ctx = lite_ctx(lite_settings, thresholds, StubRuntime("ONLINE"))
    ctx.metrics.record({"attempt_id": "x", "decision": "DENY", "mode": "ONLINE", "reason_codes": [],
                        "latency_ms": {"total": 10 ** 400, "nan": float("nan")}}, None)
    assert ctx.metrics.summary()["attempts"] == 1


# ------------------------------------------------------------------ F10: client fields to contract patterns
@pytest.mark.parametrize("body", [
    {"kiosk_id": "KIOSK_MAIN_01", "claimed_user_id": "!"},
    {"kiosk_id": "KIOSK_MAIN_01", "client": {"camera_label": "x" * 5000}},
    {"kiosk_id": "KIOSK_MAIN_01", "recapture_of": "../../etc"},
    {"kiosk_id": "k" * 500},
])
def test_f10_session_start_rejects_out_of_contract_fields(lite_settings, thresholds, body):
    with lite_client(lite_ctx(lite_settings, thresholds, StubRuntime("ONLINE"))) as c:
        r = c.post("/v1/session/start", json=body)
    assert r.status_code == 422, r.text


@pytest.mark.parametrize("field", ["face_lock_at_ms", "capture_started_at_ms"])
def test_f10_frames_meta_bounds_epoch_ms(field):
    from pydantic import ValidationError

    from edge.schemas import FramesMeta

    ok = {"nonce": "n", "face_lock_at_ms": 1_700_000_000_000, "capture_started_at_ms": 1_700_000_000_000,
          "frame_timestamps_ms": [1, 2, 3]}
    FramesMeta.model_validate(ok)
    for bad in (-(10 ** 400), -1, 10 ** 15):
        with pytest.raises(ValidationError):
            FramesMeta.model_validate({**ok, field: bad})


def test_f10_finish_never_fails_after_the_decision(lite_settings, thresholds):
    from edge.attempts import finish

    ctx = lite_ctx(lite_settings, thresholds, StubRuntime("ONLINE"))
    att = new_attempt(ctx)
    ctx.metrics = types.SimpleNamespace(record=lambda *a, **k: (_ for _ in ()).throw(OverflowError("boom")))
    resp = {"attempt_id": att.attempt_id, "decision": "DENY", "mode": "ONLINE", "reason_codes": [],
            "latency_ms": {"total": 1}}
    assert finish(ctx, att, dict(resp), kind="frames")["decision"] == "DENY"
    assert att.last_response["decision"] == "DENY"



# ------------------------------------------------------------------ F9: EMAIL_OTP follows the step, not the mode now
class FallbackRuntime(StubRuntime):
    def __init__(self, mode: str) -> None:
        super().__init__(mode)
        self.calls: list[tuple] = []

    def record_cloud_result(self, ok):
        self.calls.append(("record_cloud_result", ok))

    def resolve_fallback(self, attempt_id, sub):
        self.calls.append(("resolve_fallback", sub.method, sub.email_otp_verified))
        return {"attempt_id": attempt_id, "decision": "ALLOW", "mode": "ONLINE", "reason_codes": [],
                "latency_ms": {}}

    def drop_method(self, attempt_id, method):
        self.calls.append(("drop_method", method))
        return {"attempt_id": attempt_id, "decision": "STEP_UP", "mode": "OFFLINE", "reason_codes": [],
                "latency_ms": {}, "next_action": {"type": "SECOND_FACTOR", "methods": ["TOTP"]}}


class OtpCloud:
    def __init__(self, enabled: bool, verdict):
        self.enabled, self.verdict, self.verify_calls = enabled, verdict, 0

    async def otp_verify(self, attempt_id, otp_id, code):
        self.verify_calls += 1
        return self.verdict


def _offered_step(ctx, methods=("EMAIL_OTP", "TOTP")):
    att = new_attempt(ctx)
    att.last_response = {"decision": "STEP_UP", "mode": "ONLINE",
                         "next_action": {"type": "SECOND_FACTOR", "methods": list(methods)}}
    return att


@pytest.mark.parametrize(("cloud_on", "verdict", "expect"), [
    (True, True, ("resolve_fallback", "EMAIL_OTP", True)),  # flipped OFFLINE after the offer: still verified
    (True, None, ("drop_method", "EMAIL_OTP")),  # cloud cannot judge it now: R11 drop, nothing counted
    (False, None, ("drop_method", "EMAIL_OTP")),  # no cloud client at all: R11 drop
])
def test_f9_email_otp_after_mode_flip(lite_settings, thresholds, cloud_on, verdict, expect):
    from edge.attempts import process_fallback
    from edge.schemas import FallbackRequest

    rt = FallbackRuntime("OFFLINE")
    ctx = lite_ctx(lite_settings, thresholds, rt)
    ctx.cloud = OtpCloud(cloud_on, verdict)
    att = _offered_step(ctx)
    asyncio.run(process_fallback(ctx, att, FallbackRequest(method="EMAIL_OTP", otp_id="otp_1", code="123456")))
    assert expect in rt.calls
    assert not any(c[0] == "resolve_fallback" and c[2] is None for c in rt.calls)  # never an unverified submit


def test_f9_email_otp_not_offered_is_never_sent_to_the_cloud(lite_settings, thresholds):
    from edge.attempts import process_fallback
    from edge.schemas import FallbackRequest

    rt = FallbackRuntime("ONLINE")
    ctx = lite_ctx(lite_settings, thresholds, rt)
    ctx.cloud = OtpCloud(True, True)
    att = _offered_step(ctx, methods=("TOTP",))
    asyncio.run(process_fallback(ctx, att, FallbackRequest(method="EMAIL_OTP", otp_id="otp_1", code="123456")))
    assert ctx.cloud.verify_calls == 0 and ("resolve_fallback", "EMAIL_OTP", None) in rt.calls


# ------------------------------------------------------------------ F3: Host / Origin / docs
def _app_client(lite_settings, thresholds, monkeypatch, *, demo: bool = True):
    from fastapi.testclient import TestClient

    from edge.app import create_app

    monkeypatch.setenv("DEMO_MODE", "1" if demo else "0")
    ctx = lite_ctx(dataclasses.replace(lite_settings, demo_mode=demo), thresholds, StubRuntime("ONLINE"))
    return TestClient(create_app(lambda: ctx))


START_BODY = {"kiosk_id": "KIOSK_MAIN_01", "client": {"camera_label": "cam"}}


def test_f3_foreign_host_header_is_refused(lite_settings, thresholds, monkeypatch):
    with _app_client(lite_settings, thresholds, monkeypatch) as c:
        assert c.get("/v1/health", headers={"Host": "rebind.attacker.example:8000"}).status_code == 400
        assert c.post("/v1/session/start", json=START_BODY,
                      headers={"Host": "rebind.attacker.example"}).status_code == 400
        assert c.get("/v1/health", headers={"Host": "127.0.0.1:8000"}).status_code == 200
        assert c.get("/v1/health", headers={"Host": "localhost:8000"}).status_code == 200


@pytest.mark.parametrize(("origin", "status"), [
    ("http://evil.example", 403), ("null", 403), ("http://localhost:5173", 201), (None, 201)])
def test_f3_foreign_origin_on_state_changing_requests(lite_settings, thresholds, monkeypatch, origin, status):
    headers = {"Origin": origin} if origin else {}
    with _app_client(lite_settings, thresholds, monkeypatch) as c:
        r = c.post("/v1/session/start", json=START_BODY, headers=headers)
        assert r.status_code == status, r.text
        if status == 403:
            assert r.json()["error"]["code"] == "FORBIDDEN" and r.json()["error"]["reason"] == "ORIGIN_NOT_ALLOWED"
        assert c.get("/v1/health", headers=headers).status_code == 200  # GETs are not origin-gated


@pytest.mark.parametrize(("demo", "status"), [(False, 404), (True, 200)])
def test_f3_docs_only_in_demo_mode(lite_settings, thresholds, monkeypatch, demo, status):
    with _app_client(lite_settings, thresholds, monkeypatch, demo=demo) as c:
        assert c.get("/openapi.json").status_code == status
        assert c.get("/docs").status_code == status


# ------------------------------------------------------------------ F5: body limits before spooling
def test_f5_oversized_json_body_is_413_before_parsing(lite_settings, thresholds, monkeypatch):
    big = b'{"kiosk_id":"KIOSK_MAIN_01","pad":"' + b"x" * (200 * 1024) + b'"}'
    with _app_client(lite_settings, thresholds, monkeypatch) as c:
        r = c.post("/v1/session/start", content=big, headers={"Content-Type": "application/json"})
        assert r.status_code == 413 and r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_f5_streamed_body_without_length_is_cut_off(lite_settings, thresholds, monkeypatch):
    def chunks():
        for _ in range(64):
            yield b"x" * (512 * 1024)  # 32 MB, no Content-Length

    with _app_client(lite_settings, thresholds, monkeypatch) as c:
        att = c.post("/v1/session/start", json=START_BODY).json()["attempt_id"]
        r = c.post(f"/v1/attempt/{att}/probe", content=chunks(),
                   headers={"Content-Type": "multipart/form-data; boundary=xyz"})
        assert r.status_code == 413, r.text


def test_f5_multipart_over_the_route_cap_is_413(lite_settings, thresholds, monkeypatch):
    with _app_client(lite_settings, thresholds, monkeypatch) as c:
        att = c.post("/v1/session/start", json=START_BODY).json()["attempt_id"]
        r = c.post(f"/v1/attempt/{att}/probe", files={"probe": ("p.jpg", b"\xff" * (30 * 1024 * 1024))})
        assert r.status_code == 413


def test_f5_sse_subscriber_cap():
    from edge.events import EventBus

    async def run() -> tuple[bool, bool]:
        bus = EventBus(max_subscribers=2)

        async def never() -> bool:
            return False

        streams = [bus.stream(never) for _ in range(2)]
        for st in streams:
            assert await anext(st) == ": connected\n\n"
        full = not bus.has_capacity()
        await streams[0].aclose()
        return full, bus.has_capacity()

    assert asyncio.run(run()) == (True, True)


# ------------------------------------------------------------------ F7: DEMO_MODE is never silently on
def test_f7_demo_mode_degrades_health(lite_settings, thresholds, monkeypatch):
    with _app_client(lite_settings, thresholds, monkeypatch, demo=True) as c:
        h = c.get("/v1/health").json()
        assert "demo_mode" in h["degraded_reasons"] and h["status"] == "degraded"
    with _app_client(lite_settings, thresholds, monkeypatch, demo=False) as c:
        assert "demo_mode" not in c.get("/v1/health").json()["degraded_reasons"]


def test_f7_demo_mode_logs_a_loud_warning(lite_settings, thresholds, monkeypatch, caplog):
    caplog.set_level("WARNING", logger="edge.app")
    with _app_client(lite_settings, thresholds, monkeypatch, demo=True):
        pass
    assert any("DEMO_MODE=1" in r.getMessage() and r.levelname in ("WARNING", "ERROR") for r in caplog.records)


# ------------------------------------------------------------------ EAE-02 / EAE-07 / EAE-17: outbound cloud credential + TLS
def _cloud_settings(settings, **kw):
    base = {"cloud_api_url": "https://cloud.test", "cloud_api_key": "dummy-api-key", "kiosk_hmac_key": "dummy-kiosk",
            "cloud_admin_token": "", "cloud_edge_proxy_key": ""}
    return dataclasses.replace(settings, **{**base, **kw})


def _recording_client(settings, thresholds, status=200, body=None):
    import httpx

    from edge.cloud_client import CloudClient

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json=body if body is not None else {"ok": True})

    return CloudClient(settings, thresholds, transport=httpx.MockTransport(handler)), seen


@pytest.mark.parametrize(("kw", "want"), [
    ({"cloud_edge_proxy_key": "fgk_abcd1234.secret", "cloud_admin_token": "legacy"}, ("authorization", "Bearer fgk_abcd1234.secret")),
    ({"cloud_admin_token": "legacy-cloud-token"}, ("x-admin-token", "legacy-cloud-token")),
])
def test_eae02_outbound_admin_credential(settings, thresholds, kw, want):
    client, seen = _recording_client(_cloud_settings(settings, **kw), thresholds)

    async def run():
        await client.start()
        try:
            await client.admin("GET", "/v1/admin/users")
        finally:
            await client.stop()

    asyncio.run(run())
    hdrs = {k.lower(): v for k, v in seen[0].headers.items()}
    assert hdrs[want[0]] == want[1]
    other = "x-admin-token" if want[0] == "authorization" else "authorization"
    assert other not in hdrs


def test_eae02_never_falls_back_to_the_inbound_admin_token(settings, thresholds, monkeypatch):
    from edge.cloud_client import CloudUnavailable
    from edge.config import Settings

    monkeypatch.setenv("ADMIN_TOKEN", "inbound-only-token")
    monkeypatch.delenv("CLOUD_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("CLOUD_EDGE_PROXY_KEY", raising=False)
    s = Settings.from_env()
    assert s.cloud_admin_token == "" and not s.cloud_admin_configured
    client, seen = _recording_client(_cloud_settings(s), thresholds)

    async def run():
        await client.start()
        try:
            await client.admin("GET", "/v1/admin/users")
        finally:
            await client.stop()

    with pytest.raises(CloudUnavailable):
        asyncio.run(run())
    assert seen == []


def test_eae17_cloud_secrets_not_in_repr(settings):
    s = _cloud_settings(settings, cloud_edge_proxy_key="fgk_abcd1234.topsecret", cloud_api_key="api-topsecret")
    assert "topsecret" not in repr(s)


@pytest.mark.parametrize(("url", "demo", "ok"), [
    ("https://cloud.example", False, True), ("http://127.0.0.1:8240", False, True), ("http://localhost", False, True),
    ("http://cloud.example", True, True), ("http://cloud.example", False, False), ("ftp://cloud.example", True, False),
    ("", False, True)])
def test_eae07_cloud_url_must_be_https(url, demo, ok):
    from edge.config import ConfigError, validate_cloud_url

    if ok:
        validate_cloud_url(url, demo_mode=demo)
    else:
        with pytest.raises(ConfigError):
            validate_cloud_url(url, demo_mode=demo)


def test_eae07_tls_ca_file_pins_the_cloud_certificate(tmp_path):
    import ssl

    from edge.config import ConfigError, cloud_tls_verify

    assert cloud_tls_verify("") is True
    with pytest.raises(ConfigError):
        cloud_tls_verify(tmp_path / "missing.pem")
    bad = tmp_path / "bad.pem"
    bad.write_text("not a pem")
    with pytest.raises(ConfigError):
        cloud_tls_verify(bad)
    pem = tmp_path / "ca.pem"
    pem.write_bytes(_self_signed_pem())
    ctx = cloud_tls_verify(pem)
    assert isinstance(ctx, ssl.SSLContext) and ctx.verify_mode == ssl.CERT_REQUIRED
    assert len(ctx.get_ca_certs()) == 1  # ONLY the pinned certificate, not the system store


def test_eae07_cloud_client_uses_the_pinned_context(settings, thresholds, tmp_path):
    from edge.cloud_client import CloudClient

    pem = tmp_path / "ca.pem"
    pem.write_bytes(_self_signed_pem())
    client = CloudClient(_cloud_settings(settings, cloud_tls_ca_file=str(pem)), thresholds)
    assert client.tls_verify is not True


def _self_signed_pem() -> bytes:
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cloud.test")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


# ------------------------------------------------------------------ EAE-03/04: actor sent signed
def test_eae04_erasure_delete_carries_signed_actor(settings, thresholds):
    from edge.offline.signing import verify_request

    s = _cloud_settings(settings)
    client, seen = _recording_client(s, thresholds)

    async def run():
        await client.start()
        try:
            await client.delete_user("u_ab12", actor="staff:s_guard01")
        finally:
            await client.stop()

    asyncio.run(run())
    req = seen[0]
    assert req.url.params["actor"] == "staff:s_guard01"
    signed_path = req.url.raw_path.decode()
    assert signed_path.startswith("/v1/enroll/u_ab12?actor=")
    assert verify_request("DELETE", signed_path, b"", dict(req.headers), kiosk_key=s.kiosk_hmac_key.encode())


def test_eae04_enrol_body_carries_actor(settings, thresholds):
    import json as _json

    client, seen = _recording_client(_cloud_settings(settings), thresholds, status=201)

    async def run():
        await client.start()
        try:
            await client.enroll({"user_id": "u_ab12", "actor": "key:abcd1234"}, [b"\xff\xd8x"])
        finally:
            await client.stop()

    asyncio.run(run())
    assert _json.loads(seen[0].content)["actor"] == "key:abcd1234"


# ------------------------------------------------------------------ access writes (EAE-04, EAE-09, EAE-10, cloud 403)
from edge.tests.contract_cloud import ADMIN


def test_eae09_revocation_feed_is_pulled_even_when_the_bundle_pull_fails(make_env):
    env = make_env()
    assert "u_3c4d" in env.ctx.runtime.entitled_user_ids()
    env.cloud.fail[("GET", "/v1/schedule/")] = (503, {"error": {"code": "INTERNAL", "message": "down"}}, {})
    r = env.c.post("/v1/admin/access/users/u_3c4d/revoke", json={"reason": "ADMIN"}, headers=ADMIN)
    assert r.status_code == 200, r.text
    assert r.json()["bundle"]["applied"] is False
    assert "u_3c4d" in env.ctx.runtime.revoked_user_ids()  # the feed applied the revoke to the next attempt
    assert "u_3c4d" not in env.ctx.runtime.entitled_user_ids()


def test_eae09_bundle_refresh_route_pulls_the_feed_on_failure(make_env):
    env = make_env()
    env.cloud._revoke("u_3c4d", "ADMIN")
    env.cloud.fail[("GET", "/v1/schedule/")] = (503, {"error": {"code": "INTERNAL", "message": "down"}}, {})
    r = env.c.post("/v1/admin/bundle/refresh", headers=ADMIN)
    assert r.status_code == 503
    assert "u_3c4d" in env.ctx.runtime.revoked_user_ids()


def test_eae10_urgent_revoke_allowed_while_syncing(make_env):
    env = make_env()
    env.ctx.runtime.monitor.state = "SYNCING"  # connectivity is back, the queue is still draining
    assert env.ctx.runtime.mode() == "OFFLINE"
    r = env.c.post("/v1/admin/access/users/u_3c4d/revoke", json={"reason": "ADMIN"}, headers=ADMIN)
    assert r.status_code == 200, r.text


def test_eae04_client_actor_is_ignored_and_the_principal_actor_is_sent(make_env):
    env = make_env()
    env.put("u_3c4d", {"role": "faculty", "actor": "someone-else"})
    r = env.c.post("/v1/admin/access/users/u_3c4d/revoke", json={"reason": "ADMIN", "actor": "forged"},
                   headers=ADMIN)
    assert r.status_code == 200, r.text
    put = env.cloud.calls("PUT", "/v1/admin/users/")[-1]
    rev = env.cloud.calls("POST", "/v1/admin/revocations")[-1]
    assert put["json"]["actor"] == rev["json"]["actor"] == "legacy:admin_token"
    assert put["request_id"] and rev["request_id"] and put["request_id"] != rev["request_id"]


def test_cloud_403_reason_is_surfaced_unchanged(make_env):
    env = make_env()
    env.cloud.fail[("PUT", "/v1/admin/users/")] = (
        403, {"error": {"code": "FORBIDDEN", "message": "no", "reason": "MISSING_PERMISSION"}}, {})
    r = env.c.put("/v1/admin/access/users/u_3c4d", json={"role": "faculty"}, headers=ADMIN)
    assert r.status_code == 403 and r.json()["error"]["reason"] == "MISSING_PERMISSION"


# ------------------------------------------------------------------ F11 / EAE-12 / EM-02: erasure robustness
def test_f11_erasure_without_template_cache_still_erases_totp_and_cloud(make_env):
    env = make_env()
    env.ctx.runtime.provision_totp("u_3c4d")
    env.ctx.templates = None
    r = env.c.delete("/v1/enroll/u_3c4d", headers=ADMIN)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["local_removed"] is False and out["cloud"] == "deleted"
    assert "template cache" in (out["message"] or "")
    assert not env.ctx.runtime.credentials.totp_secret("u_3c4d")
    assert env.cloud.calls("DELETE", "/v1/enroll/u_3c4d")


def test_em02_template_store_write_failure_is_503_and_nothing_else_changes(make_env, monkeypatch):
    from edge.ml.templates import TemplateStoreError

    env = make_env()
    env.seed_template("u_3c4d")
    env.ctx.runtime.provision_totp("u_3c4d")

    def broken(_uid):
        raise TemplateStoreError("disk full: change NOT applied")

    monkeypatch.setattr(env.ctx.templates, "delete", broken)
    r = env.c.delete("/v1/enroll/u_3c4d", headers=ADMIN)
    assert r.status_code == 503 and "NOT applied" in r.json()["error"]["message"]
    assert env.ctx.runtime.credentials.totp_secret("u_3c4d")  # nothing claimed, nothing removed
    assert not env.cloud.calls("DELETE", "/v1/enroll/")


@pytest.mark.parametrize(("body", "cloud"), [
    ({"error": {"code": "NOT_FOUND", "message": "Not Found"}}, "queued"),  # route not deployed: retry later
    ({"error": {"code": "NOT_FOUND", "message": "no", "reason": "UNKNOWN_KIOSK"}}, "queued"),  # another 404
    ({"error": {"code": "NOT_FOUND", "message": "no", "reason": "NOT_ENROLLED"}}, "deleted"),
])
def test_eae12_only_an_explicit_not_enrolled_404_counts_as_erased(make_env, body, cloud):
    env = make_env()
    env.seed_template("u_3c4d")
    env.cloud.fail[("DELETE", "/v1/enroll/")] = (404, body, {})
    r = env.c.delete("/v1/enroll/u_3c4d", headers=ADMIN)
    assert r.status_code == 200 and r.json()["cloud"] == cloud, r.text


def test_eae04_erasure_sends_actor_and_queues_it(make_env):
    env = make_env()
    env.seed_template("u_3c4d")
    r = env.c.delete("/v1/enroll/u_3c4d", headers=ADMIN)
    assert r.status_code == 200
    assert env.cloud.calls("DELETE", "/v1/enroll/u_3c4d")[-1]["query"] == {"actor": "legacy:admin_token"}
    seen: list[tuple] = []
    env.ctx.runtime.queue_cloud_erasure = lambda uid, actor=None: seen.append((uid, actor))
    env.seed_template("u_5e6f")
    env.force_offline()
    r = env.c.delete("/v1/enroll/u_5e6f", headers=ADMIN)
    assert r.json()["cloud"] == "queued" and seen == [("u_5e6f", "legacy:admin_token")]


# ------------------------------------------------------------------ enrolment (EAE-05/06/11/13/14/16, EM-07, SC2-D4)
import json as _json

from edge.tests.conftest import requires_models
from edge.tests.contract_cloud import _face_frames

ENROL_META = {"consent": True, "consent_version": "2026-11-14.v1"}


def _enrol(env, uid: str, display: str = "Synthetic", frames=None, **extra):
    frames = frames or _face_frames()
    files = {f"frame_{i}": (f"f{i}.jpg", b, "image/jpeg") for i, b in enumerate(frames)}
    meta = {"user_id": uid, "display_name": display, **ENROL_META, **extra}
    return env.c.post("/v1/enroll", files=files, data={"meta": _json.dumps(meta)}, headers=ADMIN)


@requires_models
def test_eae05_online_reenrolment_commits_locally_only_after_the_cloud_accepts(make_env):
    env = make_env(models=True)
    assert _enrol(env, "u_3c4d", "Priya N.").status_code == 201
    before = len(env.ctx.templates.get("u_3c4d").templates_b64)
    env.cloud.fail[("POST", "/v1/enroll")] = (409, {"error": {"code": "INVALID_STATE", "message": "face belongs to "
                                                              "another user", "reason": "FACE_MISMATCH"}}, {})
    r = _enrol(env, "u_3c4d", "Priya N.")
    assert r.status_code == 409 and r.json()["error"]["reason"] == "CLOUD_REFUSED_REENROLMENT", r.text
    assert len(env.ctx.templates.get("u_3c4d").templates_b64) == before  # nothing appended


@requires_models
def test_eae05_offline_reenrolment_needs_the_stricter_bar(make_env, monkeypatch):
    env = make_env(models=True)
    assert _enrol(env, "u_3c4d", "Priya N.").status_code == 201
    env.force_offline()
    monkeypatch.setattr("edge.enroll.resemblance_to_stored", lambda *_a, **_k: 0.52)  # >= online bar 0.50 only
    r = _enrol(env, "u_3c4d", "Priya N.")
    assert r.status_code == 409 and r.json()["error"]["reason"] == "LOOK_MISMATCH", r.text


@requires_models
def test_eae06_totp_enrolled_is_never_sent_as_false(make_env):
    env = make_env(models=True)
    assert _enrol(env, "u_3c4d", "Priya N.", provision_totp=False).status_code == 201
    body = env.cloud.calls("POST", "/v1/enroll")[-1]["json"]
    assert "totp_enrolled" not in body and "provision_totp" not in body
    assert body["actor"] == "legacy:admin_token"  # EAE-03/04: signed actor in the enrol body


@requires_models
def test_eae11_unlifted_erase_blocks_reenrolment_until_readmitted(make_env):
    env = make_env(models=True)
    rt = env.ctx.runtime
    issued = rt.bundles.lvb["issued_at"]
    rt.overlay.apply({"items": [{"type": "USER", "target_id": "u_3c4d", "reason": "ERASED",
                                 "revoked_at": "2099-01-01T00:00:00Z"}], "revocation_seq": 99})
    r = _enrol(env, "u_3c4d", "Priya N.")
    assert r.status_code == 409 and r.json()["error"]["reason"] == "ERASED_PENDING_READMIT", r.text
    assert rt.overlay.reason("u_3c4d") == "ERASED"  # never silently cleared
    assert issued  # the bundle predates that erasure


@requires_models
def test_eae13_totp_is_not_rotated_when_the_template_write_fails(make_env, monkeypatch):
    from edge.ml.templates import TemplateStoreError

    env = make_env(models=True)
    rt = env.ctx.runtime
    rt.provision_totp("u_3c4d")
    old = rt.credentials.totp_secret("u_3c4d")

    def broken(**_kw):
        raise TemplateStoreError("disk full: change NOT applied")

    monkeypatch.setattr(env.ctx.templates, "upsert", broken)
    r = _enrol(env, "u_3c4d", "Priya N.", provision_totp=True)
    assert r.status_code == 503
    assert rt.credentials.totp_secret("u_3c4d") == old


def test_eae14_enrolment_refused_without_a_policy_runtime(lite_settings, thresholds):
    ctx = lite_ctx(lite_settings, thresholds, StubRuntime("ONLINE"))  # no user_info: fail-secure runtime
    ctx.runtime_kind = "fail_secure"
    with lite_client(ctx) as c:
        files = {f"frame_{i}": (f"f{i}.jpg", b, "image/jpeg") for i, b in enumerate(_face_frames())}
        meta = {"user_id": "u_3c4d", "display_name": "X", **ENROL_META}
        r = c.post("/v1/enroll", files=files, data={"meta": _json.dumps(meta)},
                   headers={"X-Admin-Token": lite_settings.admin_token})
    assert r.status_code == 503 and r.json()["error"]["reason"] == "POLICY_RUNTIME_UNAVAILABLE", r.text


def test_eae16_cloud_payload_stays_under_the_cloud_body_cap():
    from edge.enroll import CLOUD_ENROL_MAX_B64_BYTES, fit_cloud_images

    big = [b"\xff" * (2 * 1024 * 1024) for _ in range(5)]
    assert fit_cloud_images(big, []) is None  # cannot be fitted (no faces to crop): refused before any commit
    small = [b"\xff" * 1000 for _ in range(5)]
    assert fit_cloud_images(small, []) == small
    assert CLOUD_ENROL_MAX_B64_BYTES < 6 * 1024 * 1024


@requires_models
def test_em07_frames_matching_another_user_above_the_bar_are_refused(make_env, monkeypatch):
    from edge.ml.matcher import MatchScore

    env = make_env(models=True)
    assert _enrol(env, "u_3c4d", "Priya N.").status_code == 201
    env.seed_template("u_5e6f")
    real = __import__("edge.enroll", fromlist=["search"]).search

    def other_close(e, gallery, allowed=None, exclude=None):
        if exclude and "u_3c4d" in exclude:  # the guard searches everyone EXCEPT the user being enrolled
            return MatchScore(top1_user="u_5e6f", top1=0.62, top2=None, n_users=1)
        return real(e, gallery, allowed, exclude)

    monkeypatch.setattr("edge.enroll.search", other_close)
    r = _enrol(env, "u_3c4d", "Priya N.")  # top-1 overall is still u_3c4d, but u_5e6f is >= the allow bar
    assert r.status_code == 409 and r.json()["error"]["reason"] == "FACE_ENROLLED_OTHER", r.text


@requires_models
def test_sc2d4_offline_enrolment_is_queued_and_replayed_to_the_cloud(make_env):
    from edge.enroll import replay_offline_enrolments

    env = make_env(models=True)
    if not callable(getattr(env.ctx.runtime, "pending_enrolments", None)):
        pytest.skip("policy runtime without the pending-enrolment queue (policy-fixes API not landed)")
    env.force_offline()
    r = _enrol(env, "u_3c4d", "Priya N.")
    assert r.status_code == 201 and r.json()["cloud_state"] == "skipped_offline"
    pending = env.ctx.runtime.pending_enrolments()
    assert [p["user_id"] for p in pending] == ["u_3c4d"]
    rec = pending[0]
    assert rec["actor"] == "legacy:admin_token" and rec["kiosk_id"] == env.ctx.settings.kiosk_id
    assert not {"images", "images_b64", "embeddings", "frames"} & set(rec)
    assert env.c.post("/v1/admin/mode", json={"force": "AUTO"}, headers=ADMIN).status_code == 200
    env.cloud.fail[("POST", "/v1/enroll/offline-record")] = (201, {"recorded": True, "duplicate": False}, {})
    asyncio.run(replay_offline_enrolments(env.ctx))
    sent = env.cloud.calls("POST", "/v1/enroll/offline-record")
    assert sent and sent[-1]["json"]["user_id"] == "u_3c4d" and "images_b64" not in sent[-1]["json"]
    assert env.ctx.runtime.pending_enrolments() == []


# ------------------------------------------------------------------ EAE-15: depth bridge state is bounded
def _depth_on(thresholds):
    from edge.tests.test_round4 import with_overrides

    return with_overrides(thresholds, liveness__depth__enabled=True)


def test_eae15_depth_state_without_upload_is_reaped(thresholds, monkeypatch):
    import edge.depth_bridge as db

    bridge = db.DepthBridge(_depth_on(thresholds))
    assert bridge.enabled

    async def run():
        for i in range(50):
            await bridge.request(f"att_{i}", "PASSIVE", 700)
        assert len(bridge._arrived) == 50
        t0 = time.monotonic()
        monkeypatch.setattr(db.time, "monotonic", lambda: t0 + db.DEPTH_TTL_S + 1)
        await bridge.request("att_new", "PASSIVE", 700)  # request() runs the GC

    asyncio.run(run())
    assert set(bridge._arrived) == {("att_new", "PASSIVE")} and not bridge._issued


def test_eae15_terminal_decision_drops_the_attempts_depth_state(lite_settings, thresholds):
    from edge.attempts import finish
    from edge.depth_bridge import DepthBridge

    ctx = lite_ctx(lite_settings, thresholds, StubRuntime("ONLINE"))
    ctx.depth = DepthBridge(_depth_on(thresholds))
    att = new_attempt(ctx)
    asyncio.run(ctx.depth.request(att.attempt_id, "PASSIVE", 700))
    finish(ctx, att, {"attempt_id": att.attempt_id, "decision": "STEP_UP", "mode": "ONLINE", "reason_codes": [],
                      "latency_ms": {}}, kind="frames")
    assert (att.attempt_id, "PASSIVE") in ctx.depth._arrived  # still pending a step-up: kept
    finish(ctx, att, {"attempt_id": att.attempt_id, "decision": "DENY", "mode": "ONLINE", "reason_codes": [],
                      "latency_ms": {}}, kind="challenge")
    assert (att.attempt_id, "PASSIVE") not in ctx.depth._arrived


# ------------------------------------------------------------------ offline F7: mailer outage is R11, not a miss
class MailerDownCloud(OtpCloud):
    def __init__(self):
        super().__init__(True, None)

    async def start(self): ...

    async def stop(self): ...

    def warm_up(self):
        return False

    async def otp_send(self, attempt_id, user_id):
        from edge.cloud_client import CloudUnavailable

        raise CloudUnavailable("otp/send HTTP 503", 503, "EMAIL_UNAVAILABLE")


def test_offline_f7_mailer_outage_drops_email_otp_without_a_heartbeat_miss(lite_settings, thresholds):
    rt = FallbackRuntime("ONLINE")
    ctx = lite_ctx(lite_settings, thresholds, rt)
    ctx.cloud = MailerDownCloud()
    att = _offered_step(ctx)
    att.candidate_user_id = "u_3c4d"
    with lite_client(ctx) as c:
        r = c.post(f"/v1/attempt/{att.attempt_id}/otp/send")
    assert r.status_code == 503 and r.json()["error"]["reason"] == "EMAIL_UNAVAILABLE", r.text
    assert r.json()["error"]["methods"] == ["TOTP"]
    assert ("drop_method", "EMAIL_OTP") in rt.calls and ("record_cloud_result", False) not in rt.calls


def test_depth_upload_reply_has_no_check_oracle():
    import inspect

    from edge import app as app_mod

    assert '"checks"' not in inspect.getsource(app_mod.depth_frames)


# ------------------------------------------------------------------ the real PolicyRuntime provides every capability
# edge-app looks these up with getattr(...)/_safe_call so the FailSecureRuntime and test stubs degrade safely; for the
# REAL runtime a rename must fail here, not silently turn e.g. a DPDP erasure into cloud "failed".
REQUIRED_RUNTIME_CAPABILITIES = (
    "add_erase_hook", "add_reconcile_hook", "add_sync_hook", "apply_erasures", "bundle_kiosk_ids", "bundles",
    "clear_pending_enrolment", "credentials", "decide", "decide_error", "drop_method", "excluded_user_ids",
    "get_attempt", "kiosk_id", "kiosk_zone", "mode", "mode_status", "monitor", "now", "overlay",
    "pending_cloud_erasures", "pending_enrolments", "provision_totp", "queue_cloud_erasure", "queue_pending_enrolment",
    "recent_alerts", "record_cloud_result", "refresh_bundle_now", "reinstate_user", "reset_rate_limit",
    "resolve_challenge", "resolve_fallback", "revoked_user_ids", "set_demo_clock", "set_forced_mode",
    "set_random_challenge", "set_template_cache_status", "start", "stop", "store_view", "sync_detail", "sync_now",
    "totp_status", "user_info", "access_users",
)


def test_real_policy_runtime_has_every_capability_the_app_uses(tmp_path):
    import inspect

    from edge.tests.test_round4 import scratch_runtime

    rt = scratch_runtime(tmp_path)
    missing = [n for n in REQUIRED_RUNTIME_CAPABILITIES if not hasattr(rt, n)]
    assert missing == []
    assert callable(getattr(rt, "pull_revocations_now", None) or getattr(rt.sync, "pull_revocations", None))
    params = inspect.signature(rt.queue_cloud_erasure).parameters
    assert "actor" in params  # the erasure queue persists who asked (RBAC v2 D)
    assert {"reason", "max_minutes"} <= set(inspect.signature(rt.set_forced_mode).parameters)


def test_fail_secure_runtime_still_degrades_safely(settings, thresholds):
    from edge.policy_facade import FailSecureRuntime

    rt = FailSecureRuntime(settings, thresholds, "boom")
    assert rt.excluded_user_ids() == set() and rt.mode() == "OFFLINE"


# ------------------------------------------------------------------ POST /v1/admin/mode passes the expiry, never drops it
def test_admin_mode_forwards_reason_and_max_minutes(make_env):
    env = make_env()
    seen: list[tuple] = []
    real = env.ctx.runtime.set_forced_mode

    def spy(force, reason=None, max_minutes=None):
        seen.append((force, reason, max_minutes))
        return real(force, reason=reason, max_minutes=max_minutes)

    env.ctx.runtime.set_forced_mode = spy
    r = env.c.post("/v1/admin/mode", json={"force": "OFFLINE", "reason": "network work", "max_minutes": 30},
                   headers=ADMIN)
    assert r.status_code == 200 and seen == [("OFFLINE", "network work", 30)], r.text
    assert r.json().get("forced_until")
    assert env.c.post("/v1/admin/mode", json={"force": "OFFLINE", "max_minutes": 241}, headers=ADMIN).status_code == 422
    assert env.c.post("/v1/admin/mode", json={"force": "OFFLINE", "reason": "x" * 201},
                      headers=ADMIN).status_code == 422


def test_actor_of_fails_closed_without_a_principal():
    from starlette.requests import Request

    from edge.app import actor_of
    from edge.errors import ApiError

    req = Request({"type": "http", "method": "POST", "path": "/", "headers": [], "state": {}})
    with pytest.raises(ApiError) as exc:
        actor_of(req)
    assert exc.value.status == 401


# ------------------------------------------------------------------ final review EA-1..EA-4, probe 10b
@requires_models
def test_ea1_erasure_waits_for_an_in_flight_enrolment(make_env):
    """POST /v1/enroll is blocked in the cloud call; an erasure started meanwhile must run only after it, so the
    cloud erasure comes after the cloud enrolment and the local cache ends empty."""
    from edge.app import erase_user
    from edge.enroll import enroll, user_lock
    from edge.schemas import EnrollMeta

    env = make_env(models=True)
    ctx = env.ctx
    order: list[str] = []

    async def run() -> dict:
        gate = asyncio.Event()

        async def slow_enroll(meta, jpegs):
            order.append("cloud_enrol_start")
            await gate.wait()
            order.append("cloud_enrol_done")
            return {"status": 201, "body": {"user_id": meta["user_id"], "faces_indexed": len(jpegs)}}

        async def cloud_delete(user_id, *, actor):
            order.append("cloud_delete")
            return {"status": 200, "body": {"erased": True}}

        ctx.cloud.enroll = slow_enroll
        ctx.cloud.delete_user = cloud_delete
        meta = EnrollMeta(user_id="u_3c4d", display_name="Priya N.", **ENROL_META)
        enrol_task = asyncio.ensure_future(enroll(ctx, meta, _face_frames(), "staff:s_a"))
        while "cloud_enrol_start" not in order:
            await asyncio.sleep(0.01)

        async def erase():
            async with user_lock(ctx, "u_3c4d"):
                return await erase_user(ctx, "u_3c4d", "staff:s_b")

        erase_task = asyncio.ensure_future(erase())
        await asyncio.sleep(0.2)
        assert not erase_task.done()  # blocked behind the enrolment
        gate.set()
        await enrol_task
        return await erase_task

    out = asyncio.run(run())
    assert order == ["cloud_enrol_start", "cloud_enrol_done", "cloud_delete"]
    assert out["local_removed"] is True and out["cloud"] == "deleted"
    assert ctx.templates.get("u_3c4d") is None


@requires_models
def test_ea2_erasure_clears_the_queued_offline_enrolment(make_env):
    env = make_env(models=True)
    env.force_offline()
    assert _enrol(env, "u_3c4d", "Priya N.").status_code == 201
    assert [p["user_id"] for p in env.ctx.runtime.pending_enrolments()] == ["u_3c4d"]
    r = env.c.delete("/v1/enroll/u_3c4d", headers=ADMIN)
    assert r.status_code == 200, r.text
    assert env.ctx.runtime.pending_enrolments() == []


def test_ea3_mistyped_staff_id_is_not_a_422():
    from pydantic import ValidationError

    from edge.schemas import FallbackRequest

    for sid in ("S_GUARD01", "guard01", "s_g"):
        assert FallbackRequest(method="STAFF_OVERRIDE", code="12345678", staff_id=sid).staff_id == sid
    with pytest.raises(ValidationError):
        FallbackRequest(method="STAFF_OVERRIDE", code="1", staff_id="x" * 500)


def test_ea4_guard_errors_carry_cors_headers(lite_settings, thresholds, monkeypatch):
    origin = {"Origin": "http://localhost:5173"}
    big = b'{"kiosk_id":"KIOSK_MAIN_01","pad":"' + b"x" * (200 * 1024) + b'"}'
    with _app_client(lite_settings, thresholds, monkeypatch) as c:
        r = c.post("/v1/session/start", content=big, headers={**origin, "Content-Type": "application/json"})
        assert r.status_code == 413 and r.headers.get("access-control-allow-origin") == origin["Origin"]


def test_probe10b_identical_admin_calls_get_distinct_signatures(settings, thresholds):
    import json as _j

    client, seen = _recording_client(_cloud_settings(settings, cloud_admin_token="t"), thresholds)

    async def run():
        await client.start()
        try:
            for _ in range(2):
                await client.admin("POST", "/v1/admin/codes/rotate", {"staff_id": "s_guard01", "count": 1})
            await client.delete_user("u_ab12", actor="staff:s_a")
        finally:
            await client.stop()

    asyncio.run(run())
    a, b = (_j.loads(r.content) for r in seen[:2])
    assert a["request_id"] != b["request_id"] and len(a["request_id"]) >= 8
    assert seen[0].headers["x-signature"] != seen[1].headers["x-signature"]
    assert seen[2].url.params["request_id"]


@requires_models
def test_probe_f2_offline_record_is_replayed_before_the_decision_batch(make_env):
    """The pre-sync hook delivers the offline-enrolment record before POST /v1/sync."""
    from edge.app import register_offline_enrolment_replay

    env = make_env(models=True)
    rt = env.ctx.runtime
    if not callable(getattr(rt, "add_pre_sync_hook", None)):
        pytest.skip("policy runtime without add_pre_sync_hook")
    env.force_offline()
    assert _enrol(env, "u_3c4d", "Priya N.").status_code == 201
    env.cloud.fail[("POST", "/v1/enroll/offline-record")] = (201, {"recorded": True, "duplicate": False}, {})
    assert register_offline_enrolment_replay(env.ctx, None) == "pre_sync"
    assert env.c.post("/v1/admin/mode", json={"force": "AUTO"}, headers=ADMIN).status_code == 200
    rt.sync_now()
    paths = [r["path"] for r in env.cloud.requests if r["method"] == "POST"]
    assert "/v1/enroll/offline-record" in paths  # delivered by the pre-sync hook of this sync cycle
    if "/v1/sync" in paths:  # a decision batch (if any was queued) follows the record; the hook-before-batch
        assert paths.index("/v1/enroll/offline-record") < paths.index("/v1/sync")  # order is pinned by policy-fixes
    assert env.cloud.calls("POST", "/v1/enroll/offline-record")[-1]["request_id"]
    assert rt.pending_enrolments() == []


# ------------------------------------------------------------------ EM-12: enrolment gates fail closed on NaN / inf
NONFINITE = (float("nan"), float("inf"), float("-inf"))


def _good_quality():
    from edge.policy.signals import FrameQuality

    return FrameQuality(face_count=1, secondary_face_rel_size=0.0, luma_mean=120.0, overexposed_frac=0.0,
                        laplacian_var=500.0, face_width_px=220.0, iod_px=90.0, yaw_deg=0.0, pitch_deg=0.0,
                        roll_deg=0.0)


def _pad(v2=0.99, v1se=0.99):
    from edge.ml.pad import PadFrameScore

    return PadFrameScore(pad_v2=v2, pad_v1se=v1se)


def _dev(conf=0.0, containment=0.0):
    return types.SimpleNamespace(device_conf=conf, device_face_containment=containment)


def test_em12_control_a_clean_frame_passes(thresholds):
    from edge.enroll import frame_reasons

    assert frame_reasons(_good_quality(), _pad(), _dev(), thresholds)[0] == []


@pytest.mark.parametrize("bad", NONFINITE)
@pytest.mark.parametrize("field", ["secondary_face_rel_size", "luma_mean", "overexposed_frac", "laplacian_var",
                                   "face_width_px", "iod_px", "yaw_deg", "pitch_deg", "roll_deg"])
def test_em12_nonfinite_quality_metric_rejects_the_frame(thresholds, field, bad):
    from edge.enroll import frame_reasons

    q = _good_quality().model_copy(update={field: bad})
    assert frame_reasons(q, _pad(), _dev(), thresholds)[0], field


@pytest.mark.parametrize("bad", NONFINITE)
def test_em12_nonfinite_pad_or_device_rejects_the_frame(thresholds, bad):
    from edge.enroll import frame_reasons

    assert "PAD_BELOW_PASS" in frame_reasons(_good_quality(), _pad(v2=bad), _dev(), thresholds)[0]
    assert "PAD_BELOW_PASS" in frame_reasons(_good_quality(), _pad(v1se=bad), _dev(), thresholds)[0]
    assert "DEVICE_NEAR_FACE" in frame_reasons(_good_quality(), _pad(), _dev(conf=bad), thresholds)[0]
    assert "DEVICE_NEAR_FACE" in frame_reasons(_good_quality(), _pad(), _dev(containment=bad), thresholds)[0]


@pytest.mark.parametrize("bad", NONFINITE)
def test_em12_nonfinite_cosine_to_another_user_is_refused(tmp_path, monkeypatch, bad):
    from edge.enroll import guard_other_users
    from edge.errors import ApiError
    from edge.ml.matcher import MatchScore

    ctx = types.SimpleNamespace(templates=make_templates(tmp_path))
    monkeypatch.setattr("edge.enroll.search", lambda *a, **k: MatchScore(top1_user="u_b", top1=bad, top2=None,
                                                                          n_users=1))
    with pytest.raises(ApiError) as exc:
        guard_other_users(ctx, "u_a", EMB_A[None], 0.5)
    assert exc.value.extra["reason"] == "FACE_ENROLLED_OTHER"
