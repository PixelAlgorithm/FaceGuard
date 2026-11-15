"""Round 6 (control panel + role bugs, 2026-11-14 ~23:15 IST):

1. Users & Access edge proxies against a FAKE cloud (httpx.MockTransport; never the real cloud / live :8000):
   GET /v1/admin/access/users (cloud + bundle + local merge; offline -> bundle-only read_only),
   PUT /v1/admin/access/users/{id} (validated, forwarded with kiosk HMAC + admin token, bundle refreshed so the
   new role applies at once), POST .../revoke, POST /v1/admin/access/codes/rotate (no-store, never logged),
   POST /v1/admin/bundle/refresh; cloud 404-route / 403 / 422 mapping.
2. Enrolment never sets a role: bundle membership (409 NOT_IN_SCHEDULE), schedule_role + warning, template
   stores the bundle role; /v1/admin/users reports the bundle role + runtime TOTP.
3. ERASED revocations do not block re-enrolment (and are cleared on it); ADMIN revocations still 403.
4. otp/send: 404 / 429 / 422 are not outages (no connectivity miss); 5xx / transport are.
5. DELETE /v1/enroll: a failed cloud erasure is reported as "failed", never "queued".
6. Post-enrolment bundle refresh; cloud TOTP URI stripped; offline / failed cloud enrolment warns.
7. Challenge nonce released on a 422; perception crash -> DENY SYSTEM_ERROR; rejected probe frees the slot.
"""

from __future__ import annotations

import base64
import copy
import dataclasses
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from fastapi.testclient import TestClient

from edge.config import PROJECT_ROOT
from edge.tests.conftest import requires_models
from edge.tests.contract_cloud import staff_headers

KIOSK = "KIOSK_MAIN_01"
BUNDLE_KEY = "round6-bundle-key"
EDGE_ADMIN = "round6-edge-admin"
CLOUD_ADMIN = "round6-cloud-admin"
ADMIN = {"X-Admin-Token": EDGE_ADMIN}
CLOUD_URL = "https://fake-cloud.test"  # EAE-07: plain http is refused unless DEMO_MODE=1
PLAINTEXT_CODES = ["OVR-7Q2K-91XZ", "OVR-M4P8-0TRA"]


class FakeCloudServer:
    """Just enough cloud for the edge proxies + runtime sync. Records every request (method, path, headers,
    json). `fail` = {(method, path_prefix): (status, body, headers)} overrides; `down` = transport error."""

    def __init__(self) -> None:
        from edge.offline.bundle import sign_bundle

        self._sign = sign_bundle
        self.doc = json.loads((PROJECT_ROOT / "config" / "schedule.example.json").read_text(encoding="utf-8"))
        self.version = int(self.doc["bundle_version"])
        self.requests: list[dict] = []
        self.fail: dict[tuple[str, str], tuple[int, dict | None, dict]] = {}
        self.down = False
        self.faces: dict[str, int] = {"u_3c4d": 5}

    def signed(self) -> dict:
        return self._sign({**self.doc, "bundle_version": self.version}, BUNDLE_KEY.encode())

    def publish(self) -> int:
        self.version += 1
        return self.version

    def calls(self, method: str, prefix: str) -> list[dict]:
        return [r for r in self.requests if r["method"] == method and r["path"].startswith(prefix)]

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("fake cloud down", request=request)
        m, path = request.method, request.url.path
        body = json.loads(request.content) if request.content else None
        rid = body.pop("request_id", None) if isinstance(body, dict) else None  # probe 10b per-call nonce
        self.requests.append({"method": m, "path": path, "headers": dict(request.headers), "json": body,
                              "request_id": rid})
        for (fm, fp), (status, fbody, fh) in self.fail.items():
            if fm == m and path.startswith(fp):
                return httpx.Response(status, json=fbody, headers=fh)
        users = self.doc["users"]
        if path == "/v1/health":
            return httpx.Response(200, json={"status": "ok"})
        if path == "/v1/revocations":
            return httpx.Response(200, json={"items": [], "revocation_seq": 0})
        if path == f"/v1/schedule/{KIOSK}":
            if request.headers.get("If-None-Match") == f'"{self.version}"':
                return httpx.Response(304)
            return httpx.Response(200, json=self.signed())
        if path == "/v1/match":
            return httpx.Response(200, json={"user_id": None, "similarity": None})
        if path == "/v1/admin/users" and m == "GET":
            return httpx.Response(200, json={"bundle_version": self.version, "users": [
                {"user_id": uid, "display": u.get("display"), "role": u.get("role"),
                 "zones_add": u.get("zones_add"), "extra_windows": u.get("extra_windows"),
                 "valid_from": u.get("valid_from"), "valid_until": u.get("valid_until"),
                 "revoked": bool(u.get("revoked")), "enrolled_faces": self.faces.get(uid, 0)}
                for uid, u in users.items()]})
        if path.startswith("/v1/admin/users/") and path.endswith("/access") and m == "PUT":
            uid = path.split("/")[4]
            u = users.setdefault(uid, {"display": uid, "role": body["role"], "zones_add": [], "zones_remove": [],
                                       "extra_windows": {}, "valid_from": None, "valid_until": None,
                                       "revoked": False, "revoked_at": None, "fallback": {}})
            u.update({k: v for k, v in body.items()})
            return httpx.Response(200, json={"user_id": uid, "user": u, "bundle_version": self.publish()})
        if path == "/v1/admin/codes/rotate" and m == "POST":
            return httpx.Response(200, json={"staff_id": body["staff_id"], "codes": PLAINTEXT_CODES[: body["count"]],
                                             "bundle_version": self.publish()})
        if path == "/v1/admin/revocations" and m == "POST":
            users[body["target_id"]]["revoked"] = True
            return httpx.Response(201, json={"seq": 1, "bundle_version": self.publish()})
        if path == "/v1/otp/send":
            return httpx.Response(201, json={"otp_id": "otp_1", "destination_masked": "p***@x.in", "ttl_s": 300})
        if path == "/v1/enroll" and m == "POST":
            uid = body["user_id"]
            self.faces[uid] = len(body["images_b64"])
            return httpx.Response(201, json={"user_id": uid, "faces_indexed": len(body["images_b64"]),
                                             "bundle_version": self.publish(),
                                             "totp_provisioning_uri": "otpauth://totp/cloud-secret-must-not-leak"})
        if path.startswith("/v1/enroll/") and m == "DELETE":
            return httpx.Response(200, json={"erased": True, "bundle_version": self.publish()})
        return httpx.Response(404, json={"error": {"code": "NOT_FOUND", "message": "Not Found"}})


def _runtime(tmp_path, fake: FakeCloudServer, *, cloud: bool = True):
    from edge.policy.runtime import PolicyRuntime

    path = tmp_path / "bundle.signed.json"
    path.write_text(json.dumps(fake.signed()), encoding="utf-8")
    env = {"KIOSK_ID": KIOSK, "EDGE_DATA_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode(),
           "EDGE_DATA_DIR": str(tmp_path), "SCHEDULE_BUNDLE_HMAC_KEY": BUNDLE_KEY, "BUNDLE_PATH": str(path),
           "CLOUD_API_URL": CLOUD_URL if cloud else "", "DEMO_MODE": "1", "CARD_ID_PEPPER": "round6-pepper",
           "KIOSK_HMAC_KEY": "round6-kiosk-key", "CLOUD_API_KEY": "round6-api-key"}
    rt = PolicyRuntime.from_env(PROJECT_ROOT, env=env, transport=httpx.MockTransport(fake.handler))
    rt.start = lambda: None  # no background loop: every cloud call in these tests is explicit
    rt.stop = lambda: None
    return rt


def _go_online(rt) -> None:
    for _ in range(int(rt.cfg.connectivity.successes_to_online)):
        assert rt.heartbeat()
    rt.sync_now()
    assert rt.mode() == "ONLINE", rt.mode_status()


@pytest.fixture
def fake_cloud() -> FakeCloudServer:
    return FakeCloudServer()


def _make_ctx(tmp_path, settings, thresholds, fake, engine=None, *, online: bool = True):
    from edge.attempts import EdgeContext
    from edge.cloud_client import CloudClient
    from edge.depth_bridge import DepthBridge
    from edge.events import EventBus
    from edge.metrics import MetricsStore
    from edge.ml.templates import TemplateStore
    from edge.perception import EngineHealth
    from edge.session import AttemptStore

    s = dataclasses.replace(settings, kiosk_id=KIOSK, cloud_api_url=CLOUD_URL, cloud_api_key="round6-api-key",
                            kiosk_hmac_key="round6-kiosk-key", admin_token=EDGE_ADMIN,
                            cloud_admin_token=CLOUD_ADMIN, data_dir=tmp_path, lan_port=0, demo_mode=True,
                            card_id_pepper="round6-pepper")
    rt = _runtime(tmp_path, fake)
    if online:
        _go_online(rt)
    if engine is None:
        import types

        engine = types.SimpleNamespace(health=EngineHealth(), ready=False, detector=None, embedder=None)
    model_id = engine.embedder.model_id if engine.embedder else "fake_arcface"
    store = TemplateStore(tmp_path / "templates.fernet", s.edge_data_key, model_id)
    store.load()
    return EdgeContext(settings=s, thresholds=thresholds, engine=engine, runtime=rt, runtime_kind="policy",
                       sessions=AttemptStore(), events=EventBus(), metrics=MetricsStore(),
                       cloud=CloudClient(s, thresholds, transport=httpx.MockTransport(fake.handler)),
                       depth=DepthBridge(thresholds), templates=store, pool=ThreadPoolExecutor(max_workers=4),
                       started_monotonic=time.monotonic())


@pytest.fixture
def online(tmp_path, settings, thresholds, fake_cloud):
    from edge.app import create_app

    ctx = _make_ctx(tmp_path, settings, thresholds, fake_cloud)
    with TestClient(create_app(lambda: ctx)) as c:
        yield c, ctx, fake_cloud


@pytest.fixture
def online_models(tmp_path, settings, thresholds, fake_cloud, engine):
    from edge.app import create_app

    ctx = _make_ctx(tmp_path, settings, thresholds, fake_cloud, engine)
    with TestClient(create_app(lambda: ctx)) as c:
        yield c, ctx, fake_cloud


# ================================================================== 1. Users & Access proxies
def test_access_users_online_merges_cloud_bundle_and_local(online):
    c, _ctx, fake = online
    assert c.get("/v1/admin/access/users").status_code == 401  # admin-gated
    r = c.get("/v1/admin/access/users", headers=ADMIN)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["source"] == "cloud+bundle" and body["read_only"] is False and body["mode"] == "ONLINE"
    assert body["zone"] == "MAIN_GATE" and {"student", "faculty", "staff"} <= set(body["roles"])  # v1.4: top level
    assert "MAIN_GATE" in body["role_defaults"]["student"]["windows"] and body["read_only_code"] is None
    priya = next(u for u in body["users"] if u["user_id"] == "u_3c4d")
    assert priya["role"] == "student" and priya["in_bundle"] and priya["bundle_role"] == "student"
    assert priya["cloud_faces"] == 5 and priya["status"] == "ACTIVE"
    assert priya["local"]["enrolled"] is False and priya["bundle_stale"] is False
    assert priya["today"]["zone"] == "MAIN_GATE" and priya["today"]["windows"], priya["today"]
    sent = fake.calls("GET", "/v1/admin/users")[-1]["headers"]
    assert sent["x-admin-token"] == CLOUD_ADMIN and sent["x-signature"] and sent["x-kiosk-id"] == KIOSK


def test_access_put_applies_role_and_hours_within_the_request(online):
    c, ctx, fake = online
    v0 = ctx.runtime.bundles.version
    upd = {"role": "faculty", "extra_windows": {"MAIN_GATE": [{"days": ["SAT"], "start": "22:00", "end": "23:30"}]}}
    r = c.put("/v1/admin/access/users/u_3c4d", json=upd, headers=ADMIN)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["bundle"]["installed_version"] == v0 + 1 and out["bundle"]["applied"] is True
    assert ctx.runtime.user_info("u_3c4d")["role"] == "faculty"  # the next decision uses the new role
    assert out["user"]["extra_windows"]["MAIN_GATE"][0]["end"] == "23:30" and out["user"]["bundle_role"] == "faculty"
    sent = fake.calls("PUT", "/v1/admin/users/u_3c4d/access")[-1]
    assert sent["json"] == {**upd, "actor": "legacy:admin_token"} and sent["headers"]["x-admin-token"] == CLOUD_ADMIN
    # "Add user": a new user_id is forwarded the same way (the cloud creates it)
    r2 = c.put("/v1/admin/access/users/u_n3w1", json={"role": "staff", "display": "New Staff", "consent": True},
               headers=ADMIN)
    assert r2.status_code == 200 and ctx.runtime.user_info("u_n3w1")["role"] == "staff"


@pytest.mark.parametrize("bad", [
    {"role": "dean"},  # not a bundle role (edge pre-check, reason UNKNOWN_ROLE); zones are checked by the cloud
    {"role": "Student"},  # role pattern ^[a-z_]{1,32}$
    {"role": "student", "zones_add": ["moon base"]},  # zone pattern ^[A-Z0-9_]{1,32}$
    {"role": "student", "extra_windows": {"MAIN_GATE": [{"days": ["SUN"], "start": "20:00", "end": "24:00"}]}},
    {"role": "student", "extra_windows": {"MAIN_GATE": [{"days": ["MON", "MON"], "start": "09:00", "end": "10:00"}]}},
    {"role": "student", "display": "x" * 81},
    {"role": "student", "restore": True},  # restore needs consent: true
    {"role": "student", "actor": "bad actor!"},
    {"role": "student", "extra_windows": {"MAIN_GATE": [{"days": ["MON"], "start": "10:00", "end": "09:00"}]}},
    {"role": "student", "extra_windows": {"MAIN_GATE": [{"days": ["MON"], "start": "9:00", "end": "10:00"}]}},
    {"role": "student", "extra_windows": {"MAIN_GATE": [{"days": ["FUNDAY"], "start": "09:00", "end": "10:00"}]}},
    {"role": "student", "extra_windows": {"MAIN_GATE": [{"days": [], "start": "09:00", "end": "10:00"}]}},
    {"role": "student", "valid_from": "2026-11-15T00:00:00Z", "valid_until": "2026-11-14T00:00:00Z"},
    {"role": "student", "valid_from": "2026-11-15T00:00:00"},  # naive time
    {"role": "student", "bogus": 1},
])
def test_access_put_validation_is_422_without_a_cloud_call(online, bad):
    c, _, fake = online
    r = c.put("/v1/admin/access/users/u_3c4d", json=bad, headers=ADMIN)
    assert r.status_code == 422 and r.json()["error"]["code"] == "VALIDATION_ERROR", r.text
    assert not fake.calls("PUT", "/v1/admin/users/")


def test_access_put_bad_user_id_and_zone_check_left_to_the_cloud(online):
    c, _, fake = online
    assert c.put("/v1/admin/access/users/priya", json={"role": "student"}, headers=ADMIN).status_code == 422
    # R-H: the edge bundle is filtered to MAIN_GATE, so a LIBRARY window is forwarded (the cloud validates zones)
    ok = {"role": "student", "extra_windows": {"LIBRARY": [{"days": ["SUN"], "start": "20:00", "end": "23:59"}]}}
    assert c.put("/v1/admin/access/users/u_3c4d", json=ok, headers=ADMIN).status_code == 200
    assert fake.calls("PUT", "/v1/admin/users/u_3c4d/access")[-1]["json"] == {**ok, "actor": "legacy:admin_token"}


def test_access_changes_offline_are_503_and_the_view_is_bundle_only(online):
    c, _ctx, fake = online
    assert c.post("/v1/admin/mode", json={"force": "OFFLINE"}, headers=ADMIN).status_code == 200
    r = c.put("/v1/admin/access/users/u_3c4d", json={"role": "faculty"}, headers=ADMIN)
    assert r.status_code == 503 and r.json()["error"]["code"] == "CLOUD_UNAVAILABLE"
    assert r.json()["error"]["reason"] == "OFFLINE"
    guard = staff_headers(_ctx, "guard01", ["security_officer"])  # RBAC v2 D: codes need a staff session
    assert c.post("/v1/admin/access/codes/rotate", json={"staff_id": "s_guard01"}, headers=guard).status_code == 503
    assert c.post("/v1/admin/access/users/u_3c4d/revoke", headers=ADMIN).status_code == 503
    view = c.get("/v1/admin/access/users", headers=ADMIN).json()
    assert view["source"] == "bundle" and view["read_only"] is True and view["read_only_code"] == "OFFLINE"
    assert "OFFLINE" in view["read_only_reason"] and view["cloud_bundle_version"] is None
    assert any(u["user_id"] == "u_3c4d" and u["role"] == "student" and u["cloud_faces"] is None
               for u in view["users"])
    assert not fake.calls("PUT", "/v1/admin/users/") and not fake.calls("GET", "/v1/admin/users")


def test_codes_rotate_returns_plaintext_once_no_store_never_logged(online, caplog):
    c, _ctx, fake = online
    with caplog.at_level(logging.DEBUG):
        r = c.post("/v1/admin/access/codes/rotate", json={"staff_id": "s_guard01", "count": 2},
                   headers=staff_headers(_ctx, "guard01", ["security_officer"]))
    assert r.status_code == 200, r.text
    assert r.headers["cache-control"] == "no-store"
    # R-D: FLAT codes (an old cloud's plain strings are wrapped with code_id null), applied once installed
    assert [x["code"] for x in r.json()["codes"]] == PLAINTEXT_CODES and r.json()["bundle"]["applied"] is True
    assert "cloud" not in r.json() and r.json()["one_time"] is True
    assert fake.calls("POST", "/v1/admin/codes/rotate")[-1]["json"] == {"staff_id": "s_guard01", "count": 2,
                                                                        "replace_existing": True,
                                                                        "actor": "staff:s_guard01"}
    assert not any(code in caplog.text for code in PLAINTEXT_CODES)
    for bad in ({"staff_id": "guard"}, {"staff_id": "s_g"}, {"staff_id": "s_Guard01"}, {"staff_id": "s_guard01",
                                                                                         "count": 11}):
        assert c.post("/v1/admin/access/codes/rotate", json=bad, headers=ADMIN).status_code == 422, bad


def test_revoke_forwards_admin_reason_and_refuses_erased(online):
    c, _ctx, fake = online
    r = c.post("/v1/admin/access/users/u_3c4d/revoke", headers=ADMIN)
    assert r.status_code == 200, r.text
    assert fake.calls("POST", "/v1/admin/revocations")[-1]["json"] == {"type": "USER", "target_id": "u_3c4d",
                                                                       "reason": "ADMIN",
                                                                       "actor": "legacy:admin_token"}  # never `force`
    assert r.json()["type"] == "USER" and r.json()["reason"] == "ADMIN"
    assert c.post("/v1/admin/access/users/u_3c4d/revoke", json={"reason": "ERASED"}, headers=ADMIN).status_code == 422


def test_bundle_refresh_installs_newest_and_maps_failures(online):
    c, ctx, fake = online
    v0 = ctx.runtime.bundles.version
    fake.publish()  # e.g. someone edited the schedule from another kiosk
    r = c.post("/v1/admin/bundle/refresh", headers=ADMIN)
    assert r.status_code == 200 and r.json()["installed_version"] == v0 + 1 and r.json()["previous_version"] == v0
    fake.down = True
    r = c.post("/v1/admin/bundle/refresh", headers=ADMIN)
    assert r.status_code == 503 and r.json()["error"]["code"] == "CLOUD_UNAVAILABLE"
    assert r.json()["error"]["installed_version"] == v0 + 1  # the last valid bundle is kept


@pytest.mark.parametrize(("status", "body", "code", "http"), [
    (404, {"error": {"code": "NOT_FOUND", "message": "Not Found"}}, "CLOUD_UNAVAILABLE", 503),  # route missing
    (403, {"error": {"code": "FORBIDDEN", "message": "admin token required (X-Admin-Token)"}}, "FORBIDDEN", 403),
    (422, {"error": {"code": "VALIDATION_ERROR", "message": "role: unknown role"}}, "VALIDATION_ERROR", 422),
    (409, {"error": {"code": "INVALID_STATE", "message": "user revoked"}}, "INVALID_STATE", 409),
    (500, {"error": {"code": "INTERNAL", "message": "internal error"}}, "CLOUD_UNAVAILABLE", 503),
])
def test_cloud_admin_errors_keep_their_meaning(online, status, body, code, http):
    c, ctx, fake = online
    fake.fail[("PUT", "/v1/admin/users/")] = (status, body, {})
    r = c.put("/v1/admin/access/users/u_3c4d", json={"role": "faculty"}, headers=ADMIN)
    assert r.status_code == http and r.json()["error"]["code"] == code, r.text
    if status == 404:
        assert r.json()["error"]["reason"] == "ENDPOINT_NOT_DEPLOYED"
    if status == 403:
        assert r.json()["error"]["reason"] == "CLOUD_ADMIN_TOKEN"
    if status == 500:
        assert r.json()["error"]["reason"] == "CLOUD_ERROR" and r.json()["error"]["cloud_status"] == 500
    assert ctx.runtime.user_info("u_3c4d")["role"] == "student"  # nothing changed


# ================================================================== 4. otp/send error mapping
def _second_factor_attempt(ctx, methods=("EMAIL_OTP", "TOTP")):
    att = ctx.sessions.create(kiosk_id=KIOSK, flash_enabled=False, flash_sequence=[], camera_label="cam",
                              claimed_user_id=None, recapture_of=None, recapture_count=0)
    att.candidate_user_id = "u_3c4d"
    att.last_response = {"attempt_id": att.attempt_id, "decision": "STEP_UP",
                         "next_action": {"type": "SECOND_FACTOR", "methods": list(methods)}}
    return att


@pytest.mark.parametrize(("status", "headers", "code", "http", "miss"), [
    (404, {}, "NOT_FOUND", 404, False),
    (429, {"Retry-After": "30"}, "RATE_LIMITED", 429, False),
    (422, {}, "VALIDATION_ERROR", 422, False),
    (401, {}, "CLOUD_UNAVAILABLE", 503, False),  # our key was rejected: configuration, not an outage
    (503, {}, "CLOUD_UNAVAILABLE", 503, True),
    (None, {}, "CLOUD_UNAVAILABLE", 503, True),  # transport error
])
def test_otp_send_rejections_are_not_connectivity_misses(online, monkeypatch, status, headers, code, http, miss):
    c, ctx, fake = online
    rt = ctx.runtime
    misses: list[bool] = []
    monkeypatch.setattr(rt, "record_cloud_result", lambda ok: misses.append(ok))
    dropped = {"attempt_id": "x", "decision": "STEP_UP", "reason_codes": ["SECOND_FACTOR_REQUIRED"],
               "next_action": {"type": "SECOND_FACTOR", "methods": ["TOTP"]}}
    monkeypatch.setattr(rt, "drop_method", lambda aid, method: {**dropped, "attempt_id": aid})
    att = _second_factor_attempt(ctx)
    if status is None:
        fake.down = True
    else:
        fake.fail[("POST", "/v1/otp/send")] = (status, {"error": {"code": "X", "message": "m"}}, headers)
    r = c.post(f"/v1/attempt/{att.attempt_id}/otp/send")
    assert r.status_code == http and r.json()["error"]["code"] == code, r.text
    assert (False in misses) is miss
    err = r.json()["error"]
    if status == 404:
        assert err["reason"] == "NO_EMAIL_ON_FILE" and err["methods"] == ["TOTP"]
        assert att.last_response["next_action"]["methods"] == ["TOTP"]  # GET /v1/attempt shows the re-issue
    if status == 429:
        assert err["retry_after_s"] == 30 and r.headers["retry-after"] == "30"


def test_otp_send_ok_passes_the_cloud_body(online):
    c, ctx, _ = online
    att = _second_factor_attempt(ctx)
    r = c.post(f"/v1/attempt/{att.attempt_id}/otp/send")
    assert r.status_code == 201 and r.json()["otp_id"] == "otp_1"


# ================================================================== 7. challenge nonce / probe slot
def _challenge_attempt(ctx):
    att = ctx.sessions.create(kiosk_id=KIOSK, flash_enabled=False, flash_sequence=[], camera_label="cam",
                              claimed_user_id=None, recapture_of=None, recapture_count=0)
    att.candidate_user_id = "u_3c4d"
    att.last_response = {"attempt_id": att.attempt_id, "decision": "STEP_UP",
                         "next_action": {"type": "CHALLENGE", "challenge": {"challenge_id": "chl_0123456789ab"}}}
    return att


def _challenge_post(c, att, jpeg: bytes, nonce: str = "nonce-abcdefghijklmnop"):
    meta = {"challenge_id": "chl_0123456789ab", "nonce": nonce, "same_track": True,
            "actions": [{"action": "SMILE", "prompted_at_ms": 1, "baseline": 0.1, "peak": 0.8}]}
    return c.post(f"/v1/attempt/{att.attempt_id}/challenge", data={"meta": json.dumps(meta)},
                  files={"frame_0": ("f.jpg", jpeg, "image/jpeg")})


@requires_models
def test_challenge_422_releases_the_nonce_for_the_retry(online_models, monkeypatch):
    from edge import synth

    c, ctx, _ = online_models
    att = _challenge_attempt(ctx)
    seen = []

    def resolve(aid, ev):
        seen.append(ev.nonce)
        return {"attempt_id": aid, "decision": "DENY", "reason_codes": ["CHALLENGE_FAILED"], "mode": "ONLINE"}

    monkeypatch.setattr(ctx.runtime, "resolve_challenge", resolve)
    bad = _challenge_post(c, att, b"\xff\xd8 not a jpeg")
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "VALIDATION_ERROR"
    ok = _challenge_post(c, att, synth.jpeg(synth.base_frame()))
    assert ok.status_code == 200 and ok.json()["decision"] == "DENY" and seen == ["nonce-abcdefghijklmnop"]
    again = _challenge_post(c, att, synth.jpeg(synth.base_frame()))
    assert again.status_code == 409  # decided: the nonce stays used / attempt closed


@requires_models
def test_challenge_perception_crash_is_deny_system_error_not_500(online_models, monkeypatch):
    from edge import synth

    c, ctx, _ = online_models
    att = _challenge_attempt(ctx)

    def boom(*a, **k):
        raise RuntimeError("detector exploded")

    monkeypatch.setattr(ctx.engine, "analyze_frame", boom)
    r = _challenge_post(c, att, synth.jpeg(synth.base_frame()))
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "DENY" and "SYSTEM_ERROR" in r.json()["reason_codes"]


@requires_models
def test_rejected_probe_does_not_use_up_the_probe_slot(online_models):
    from edge import synth

    c, _ctx, _ = online_models
    s = c.post("/v1/session/start", json={"kiosk_id": KIOSK, "flash_enabled": True}).json()
    bad = c.post(f"/v1/attempt/{s['attempt_id']}/probe", files={"probe": ("p.jpg", b"\xff\xd8 junk", "image/jpeg")})
    assert bad.status_code == 422
    ok = c.post(f"/v1/attempt/{s['attempt_id']}/probe",
                files={"probe": ("p.jpg", synth.jpeg(synth.base_frame()), "image/jpeg")})
    assert ok.status_code == 202, ok.text
    dup = c.post(f"/v1/attempt/{s['attempt_id']}/probe",
                 files={"probe": ("p.jpg", synth.jpeg(synth.base_frame()), "image/jpeg")})
    assert dup.status_code == 409


# ================================================================== 2/3/5/6. enrolment + erasure
def _enrol(c, user_id="u_3c4d", role="student", **extra):
    from edge import synth

    frames = [synth.jpeg(synth.base_frame(shift_px=s)) for s in (-8, -4, 0, 4, 8)]
    files = {f"frame_{i}": (f"f{i}.jpg", b, "image/jpeg") for i, b in enumerate(frames)}
    meta = {"user_id": user_id, "display_name": "Synthetic", "role": role, "consent": True,
            "consent_version": "2026-11-14.v1", **extra}
    return c.post("/v1/enroll", files=files, data={"meta": json.dumps(meta)}, headers=ADMIN)


@requires_models
def test_enrolment_outside_the_schedule_is_409_and_stores_nothing(online_models):
    c, ctx, fake = online_models
    r = _enrol(c, user_id="u_zz99")
    assert r.status_code == 409 and r.json()["error"]["reason"] == "NOT_IN_SCHEDULE", r.text
    assert ctx.templates.get("u_zz99") is None and not fake.calls("POST", "/v1/enroll")


@requires_models
def test_enrolment_never_sets_the_role_and_reports_the_schedule_role(online_models):
    c, ctx, fake = online_models
    v0 = ctx.runtime.bundles.version
    r = _enrol(c, role="faculty")  # Priya is a student in the schedule
    assert r.status_code == 201, r.text
    e = r.json()
    assert e["schedule_role"] == "student" and e["role_requested"] == "faculty" and e["role_applied"] is False
    assert any("NOT applied" in w for w in e["warnings"])
    assert ctx.templates.get("u_3c4d").role == "student"  # the template stores the bundle role
    # cloud: indexed, re-signed bundle installed in the same request, one TOTP secret only (the edge's)
    assert e["cloud_state"] == "indexed" and e["cloud_indexed"] and e["bundle_version"] == v0 + 1
    assert ctx.runtime.bundles.version == v0 + 1
    assert e["totp_provisioning_uri"].startswith("otpauth://totp/") and "totp_provisioning_uri" not in e["cloud"]["body"]
    sent = fake.calls("POST", "/v1/enroll")[-1]["json"]
    assert "role" not in sent and sent["provision_totp"] is True and sent["totp_enrolled"] is True
    users = c.get("/v1/admin/users", headers=ADMIN).json()
    u = next(x for x in users["users"] if x["user_id"] == "u_3c4d")
    assert u["role"] == "student" and u["bundle_role"] == "student" and u["template_role"] == "student"
    assert u["totp_local"] is True  # secret lives in the runtime CredentialStore, not the template
    # re-enrolment with the default provision_totp keeps the secret and does not ask the cloud for one
    again = _enrol(c)
    assert again.status_code == 201 and again.json()["totp_provisioning_uri"] is None
    assert fake.calls("POST", "/v1/enroll")[-1]["json"]["provision_totp"] is True  # edge still holds a secret


@requires_models
def test_enrolment_cloud_failure_and_offline_warn_clearly(online_models):
    c, _ctx, fake = online_models
    fake.fail[("POST", "/v1/enroll")] = (500, {"error": {"code": "INTERNAL", "message": "x"}}, {})
    r = _enrol(c)
    assert r.status_code == 201 and r.json()["cloud_state"] == "failed" and not r.json()["cloud_indexed"]
    assert any("NOT_ENROLLED online" in w for w in r.json()["warnings"])
    assert c.post("/v1/admin/mode", json={"force": "OFFLINE"}, headers=ADMIN).status_code == 200
    r2 = _enrol(c)
    assert r2.status_code == 201 and r2.json()["cloud_state"] == "skipped_offline"
    assert any("OFFLINE" in w for w in r2.json()["warnings"])


@requires_models
def test_erased_user_can_re_enrol_and_the_erasure_entry_is_cleared(online_models):
    from edge.enroll import is_revoked

    c, ctx, _ = online_models
    rt = ctx.runtime
    # EAE-11: the erasure predates the installed bundle (issued 02:30Z), which no longer carries it = re-admitted
    rt.overlay.apply({"items": [{"type": "USER", "target_id": "u_3c4d", "reason": "ERASED",
                                 "revoked_at": "2026-11-14T02:00:00Z"}], "revocation_seq": 7})
    rt._erased.add("u_3c4d")
    assert is_revoked(ctx, "u_3c4d") is False
    r = _enrol(c)
    assert r.status_code == 201, r.text
    assert r.json()["reinstated_after_erasure"] is True
    assert rt.overlay.reason("u_3c4d") is None and "u_3c4d" not in rt._erased
    assert "u_3c4d" in rt.entitled_user_ids()  # the gallery admits them again


@requires_models
def test_admin_revocation_still_blocks_enrolment(online_models):
    c, ctx, _ = online_models
    ctx.runtime.overlay.apply({"items": [{"type": "USER", "target_id": "u_3c4d", "reason": "ADMIN",
                                          "revoked_at": "2026-11-14T04:00:00Z"}], "revocation_seq": 8})
    r = _enrol(c)
    assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN"
    assert ctx.templates.get("u_3c4d") is None


@requires_models
def test_erasure_still_in_the_bundle_is_409(online_models):
    c, ctx, _ = online_models
    lvb = copy.deepcopy(ctx.runtime.bundles.lvb)
    lvb["revocations"].append({"user_id": "u_3c4d", "revoked_at": "2026-11-14T04:00:00Z", "reason": "ERASED"})
    ctx.runtime.bundles._lvb = lvb
    r = _enrol(c)
    assert r.status_code == 409 and r.json()["error"]["reason"] == "ERASED_IN_BUNDLE", r.text


@pytest.mark.parametrize(("status", "down", "expect"), [(200, False, "deleted"), (204, False, "deleted"),
                                                        (500, False, "queued"), (None, True, "queued")])
def test_delete_queues_a_failed_cloud_erasure(online, status, down, expect):
    """R-J: a failed cloud erasure is persisted (PolicyRuntime.queue_cloud_erasure) and replayed at sync."""
    c, ctx, fake = online
    if status not in (200, None):
        fake.fail[("DELETE", "/v1/enroll/")] = (status, None if status == 204 else {"error": {}}, {})
    fake.down = down
    r = c.delete("/v1/enroll/u_3c4d", headers=ADMIN)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["cloud"] == expect and set(body) == {"user_id", "local_removed", "cloud", "cloud_status", "message",
                                                     "bundle"}
    if expect == "queued":
        assert "queued" in body["message"] and body["bundle"] is None
        assert [e["user_id"] for e in ctx.runtime.pending_cloud_erasures()] == ["u_3c4d"]
    else:
        assert body["bundle"]["error"] is None and body["message"] is None


def test_delete_without_a_queue_in_the_runtime_says_failed_never_queued(online, monkeypatch):
    c, ctx, fake = online
    monkeypatch.delattr(type(ctx.runtime), "queue_cloud_erasure")
    fake.down = True
    body = c.delete("/v1/enroll/u_3c4d", headers=ADMIN).json()
    assert body["cloud"] == "failed" and "retry" in body["message"]
    assert c.delete("/v1/enroll/prj1", headers=ADMIN).status_code == 422  # R-H path pattern
