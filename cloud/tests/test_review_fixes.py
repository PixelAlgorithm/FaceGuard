"""Regression tests for the cloud/app code review findings F1-F20 (each reproduced first, then fixed)."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import time

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from cloud.app.auth import signed_headers
from cloud.app.config import ConfigError, settings_from_env
from cloud.app.container import build_services
from cloud.app.main import create_app
from cloud.app.services.faces import RekognitionFaces
from cloud.app.services.kv import DynamoKV, SqliteKV
from cloud.tools.fakeimg import make_fake_jpeg

from .conftest import ADMIN, API_KEY, KIOSK_KEY, Signed, batch, make_record

ADMIN_H = {"X-Admin-Token": ADMIN}
BASE_ENV = {"KIOSK_HMAC_KEY": KIOSK_KEY, "SCHEDULE_BUNDLE_HMAC_KEY": "b" * 64, "CLOUD_API_KEY": API_KEY,
            "ADMIN_TOKEN": ADMIN, "OTP_PEPPER": "otp-pepper"}


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def enrol(c: Signed, uid: str = "u_3c4d", salt: str = "rf"):
    body = {"user_id": uid, "display_name": "Priya N.", "email": "priya@example.org", "consent": True,
            "consent_version": "2026-11-14.v1", "images_b64": [b64(make_fake_jpeg(uid, salt=f"{salt}{i}"))
                                                                for i in range(3)]}
    r = c.post("/v1/enroll", body)
    assert r.status_code == 201, r.text
    return r.json()


@pytest.fixture
def main(client) -> Signed:
    return Signed(client, kiosk="KIOSK_MAIN_01")


@pytest.fixture
def lenient(services):
    """A client that returns 500s instead of raising them (what a kiosk sees)."""
    with TestClient(create_app(services=services), raise_server_exceptions=False) as c:
        yield Signed(c)


# ------------------------------------------------------------------ F1 revocation feed watermark
def test_F1_feed_seq_never_jumps_over_an_unwritten_event(services, clock):
    sch = services.schedule
    sch.ensure_seeded()
    base = sch.revocation_seq()
    sch._next_seq()  # allocated by an in-flight writer whose feed event is not visible yet
    ev = sch.revoke(rtype="USER", target_id="u_3c4d", reason="ADMIN")
    seq, items = sch.revocations_since(base)
    assert seq < ev["seq"], "the kiosk would set since=<counter> and never see the in-flight event"
    assert all(int(it["seq"]) <= seq for it in items)
    clock.advance(minutes=5)  # the gap is now old: a burnt seq, not an in-flight write
    seq2, items2 = sch.revocations_since(base)
    assert seq2 == ev["seq"] and [it["seq"] for it in items2] == [ev["seq"]]


# ------------------------------------------------------------------ F2 erasure
def test_F2_erase_is_retryable_when_publishing_the_erasure_fails(signed, services, monkeypatch):
    enrol(signed)
    real = services.schedule.erase_user
    calls = {"n": 0}

    def flaky(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("store hiccup while publishing ERASED")
        return real(*a, **kw)

    monkeypatch.setattr(services.schedule, "erase_user", flaky)
    with pytest.raises(RuntimeError):
        services.enroll.erase("u_3c4d", kiosk_id="KIOSK_LIB_01")
    out = services.enroll.erase("u_3c4d", kiosk_id="KIOSK_LIB_01")  # retry must still find the enrolment
    assert out["erased"] is True
    doc = services.schedule.current()["doc"]
    assert any(r.get("user_id") == "u_3c4d" and r.get("reason") == "ERASED" for r in doc["revocations"])
    assert services.kv.get("users", "u_3c4d") is None


def test_F2_erase_fails_loud_when_faces_could_not_be_deleted(signed, services, monkeypatch):
    enrol(signed)
    monkeypatch.setattr(services.faces, "delete_user", lambda uid, tok: True)  # user NOT really deleted
    r = signed.delete("/v1/enroll/u_3c4d")
    assert r.status_code == 503, r.text  # faces still associated: not erased, retry
    assert services.kv.get("users", "u_3c4d") is not None  # row kept so the retry can finish the job
    assert services.faces.list_user_faces("u_3c4d")


def test_F2_delete_faces_is_chunked_not_truncated():
    seen: list[int] = []

    class Stub:
        def delete_faces(self, **kw):
            seen.append(len(kw["FaceIds"]))
            return {"DeletedFaces": list(kw["FaceIds"])}

    faces = RekognitionFaces(Stub(), "c")
    ids = [f"f{i}" for i in range(5000)]
    assert len(faces.delete_faces(ids)) == 5000 and sum(seen) == 5000


def test_F2_unknown_user_erase_is_404_with_reason(signed):
    r = signed.delete("/v1/enroll/u_zzzz")
    assert r.status_code == 404 and r.json()["error"].get("reason") == "NOT_ENROLLED"


# ------------------------------------------------------------------ F4 shared kiosk key
def test_F4_shared_kiosk_key_needs_explicit_opt_in():
    with pytest.raises(ConfigError):
        settings_from_env(BASE_ENV, load_env_file=False)
    s = settings_from_env({**BASE_ENV, "KIOSK_KEYS_JSON": json.dumps({"KIOSK_LIB_01": "l" * 64})},
                          load_env_file=False)
    assert s.key_for_kiosk("KIOSK_LIB_01", {"KIOSK_LIB_01", "KIOSK_MAIN_01"}) == "l" * 64
    assert s.key_for_kiosk("KIOSK_MAIN_01", {"KIOSK_LIB_01", "KIOSK_MAIN_01"}) is None
    shared = settings_from_env({**BASE_ENV, "ALLOW_SHARED_KIOSK_KEY": "1"}, load_env_file=False)
    assert shared.key_for_kiosk("KIOSK_MAIN_01", {"KIOSK_MAIN_01"}) == KIOSK_KEY


# ------------------------------------------------------------------ F5 bare-path signature with a query
def test_F5_bare_path_signature_does_not_cover_the_query(client):
    h = signed_headers(kiosk_id="KIOSK_LIB_01", key=KIOSK_KEY, api_key=API_KEY, method="GET",
                       path="/v1/revocations")
    assert client.get("/v1/revocations?since=0", headers=h).status_code == 401
    ok = signed_headers(kiosk_id="KIOSK_LIB_01", key=KIOSK_KEY, api_key=API_KEY, method="GET",
                        path="/v1/revocations?since=0")
    assert client.get("/v1/revocations?since=0", headers=ok).status_code == 200


# ------------------------------------------------------------------ F6 replay cache shared by every worker
def test_F6_replay_is_refused_by_another_worker_sharing_the_store(services, settings, clock):
    other = build_services(settings, clock=clock, kv=services.kv)
    body = json.dumps({"otp_id": "otp_x", "attempt_id": "att_rf6", "code": "123456"}).encode()
    h = signed_headers(kiosk_id="KIOSK_LIB_01", key=KIOSK_KEY, api_key=API_KEY, method="POST",
                       path="/v1/otp/verify", body=body)
    h["Content-Type"] = "application/json"
    with TestClient(create_app(services=services)) as a, TestClient(create_app(services=other)) as b:
        assert a.post("/v1/otp/verify", content=body, headers=h).status_code == 200
        r = b.post("/v1/otp/verify", content=body, headers=h)
    assert r.status_code == 401 and "replay" in r.json()["error"]["message"]


# ------------------------------------------------------------------ F7 Content-Length checked before reading
async def test_F7_oversized_content_length_is_refused_before_reading(services):
    from cloud.app.middleware import HidMiddleware

    async def app(scope, receive, send):  # pragma: no cover - must never be reached
        raise AssertionError("app reached")

    reads = {"n": 0}

    async def receive():
        reads["n"] += 1
        return {"type": "http.request", "body": b"x" * 10, "more_body": False}

    sent: list[dict] = []

    async def send(msg):
        sent.append(msg)

    mw = HidMiddleware(app, get_services=lambda: services)
    scope = {"type": "http", "method": "POST", "path": "/v1/sync", "query_string": b"",
             "headers": [(b"content-length", str(services.settings.max_body_bytes + 1).encode())]}
    await mw(scope, receive, send)
    assert sent[0]["status"] == 413 and reads["n"] == 0


# ------------------------------------------------------------------ F8 schedule element types + dry run
@pytest.mark.parametrize("field,value", [
    ("holidays", ["2026-11-14"]),
    ("exceptions", [{"zones": "LIBRARY", "date": "2026-11-14"}]),
    ("visitor_passes", [42]),
    ("override_codes", {"codes": "OVR-1"}),
])
def test_F8_bad_element_types_are_refused_and_bundles_keep_working(main, services, field, value):
    doc = services.schedule.doc()
    doc[field] = value
    r = main.request("PUT", "/v1/admin/schedule", json_body=doc, headers=ADMIN_H)
    assert r.status_code == 422, r.text
    assert main.get("/v1/schedule/KIOSK_MAIN_01").status_code == 200


# ------------------------------------------------------------------ F9 sync: one bad item never wedges a batch
def test_F9_bad_item_is_rejected_and_the_rest_of_the_batch_is_ingested(lenient):
    bad = make_record("att_rf9_bad", seq=1, prev_hash="00" * 32)
    bad["prev_hash"] = ["not", "a", "string"]  # record_hash present, prev_hash of the wrong type
    good = make_record("att_rf9_good", ts="2026-11-14T04:36:00Z")
    r = lenient.post("/v1/sync", batch("KIOSK_LIB_01", [bad, good]))
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["accepted"] == ["att_rf9_good"]
    assert [x["idempotency_key"] for x in out["rejected"]] == ["att_rf9_bad"]


def test_F9_deeply_nested_body_is_400_not_500(lenient):
    raw = b'{"kiosk_id":"KIOSK_LIB_01","items":' + b"[" * 50000 + b"]" * 50000 + b"}"
    r = lenient.request("POST", "/v1/sync", content=raw, content_type="application/json")
    assert r.status_code == 400, r.text
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"


# ------------------------------------------------------------------ F10 idempotent READMIT / RESTORE re-emit
def test_F10_missing_restore_event_is_re_emitted_on_retry(services, clock, monkeypatch):
    sch = services.schedule
    sch.revoke(rtype="USER", target_id="u_3c4d", reason="ADMIN")
    change = {"role": "student", "consent": True, "restore": True}
    real_put = services.kv.put
    state = {"fail": True}

    def put(ns, key, item, ttl=None):
        if ns == "revocations" and item.get("type") == "READMIT" and state["fail"]:
            state["fail"] = False
            raise RuntimeError("store hiccup writing the feed event")
        return real_put(ns, key, item, ttl)

    monkeypatch.setattr(services.kv, "put", put)
    with pytest.raises(RuntimeError):
        sch.update_access("u_3c4d", dict(change), kiosk_id="KIOSK_MAIN_01")
    sch.update_access("u_3c4d", dict(change), kiosk_id="KIOSK_MAIN_01")  # operator retries: unchanged doc
    clock.advance(minutes=5)  # the lost event's seq is now a burnt gap the feed steps over
    _, items = sch.revocations_since(0)
    mine = [it for it in items if it["target_id"] == "u_3c4d"]
    assert mine[-1]["type"] == "READMIT" and mine[-1]["reason"] == "RESTORE"


# ------------------------------------------------------------------ F11 OTP
def _otp_user(services, uid: str = "u_3c4d") -> None:
    services.kv.put("users", uid, {"user_id": uid, "email": "priya@example.org", "face_ids": []})


def test_F11_per_user_send_cap(signed, services):
    _otp_user(services)
    codes = [signed.post("/v1/otp/send", {"attempt_id": f"att_cap{i}", "user_id": "u_3c4d", "channel": "email"})
             .status_code for i in range(services.thresholds.otp_max_sends_per_user + 1)]
    assert codes[:-1] == [201] * services.thresholds.otp_max_sends_per_user and codes[-1] == 429


def test_F11_resend_invalidates_the_previous_code(signed, services, clock):
    _otp_user(services)
    first = signed.post("/v1/otp/send", {"attempt_id": "att_inv", "user_id": "u_3c4d", "channel": "email"}).json()
    code1 = services.mailer.outbox[-1].body.split("code is ")[1][:services.thresholds.otp_digits]
    clock.advance(seconds=services.settings.otp_resend_after_s + 1)
    assert signed.post("/v1/otp/send", {"attempt_id": "att_inv", "user_id": "u_3c4d", "channel": "email"},
                       now=time.time() + 1).status_code == 201  # fresh signature (replay guard)
    r = signed.post("/v1/otp/verify", {"otp_id": first["otp_id"], "attempt_id": "att_inv", "code": code1})
    assert r.json()["verified"] is False


def test_F11_otp_is_stored_before_the_mail_is_sent(services, monkeypatch):
    _otp_user(services)
    real_put = services.kv.put

    def put(ns, key, item, ttl=None):
        if ns == "otp":
            raise RuntimeError("store down")
        return real_put(ns, key, item, ttl)

    monkeypatch.setattr(services.kv, "put", put)
    monkeypatch.setattr(services.kv, "cas", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("store down")))
    with pytest.raises(RuntimeError):
        services.otp.send(attempt_id="att_store", user_id="u_3c4d", channel="email")
    assert services.mailer.outbox == []  # nobody received a code that can never verify


# ------------------------------------------------------------------ F12 OTP pepper
def test_F12_otp_pepper_required_for_persistent_stores():
    env = {**BASE_ENV, "ALLOW_SHARED_KIOSK_KEY": "1", "STORE_BACKEND": "sqlite"}
    env.pop("OTP_PEPPER")
    with pytest.raises(ConfigError):
        settings_from_env(env, load_env_file=False)
    mem = {**BASE_ENV, "ALLOW_SHARED_KIOSK_KEY": "1"}
    mem.pop("OTP_PEPPER")
    assert settings_from_env(mem, load_env_file=False).otp_pepper == ""


# ------------------------------------------------------------------ F13 store down -> 503, not 401
def test_F13_store_outage_is_503_not_401(signed, services, monkeypatch):
    services.schedule._cache = None
    services.schedule._last_kiosks = None

    def boom(*a, **k):
        raise RuntimeError("dynamodb unreachable")

    monkeypatch.setattr(services.kv, "get", boom)
    r = signed.get("/v1/revocations?since=0")
    assert r.status_code == 503 and r.json()["error"]["code"] == "CLOUD_UNAVAILABLE"
    assert "x-server-time" in r.headers


# ------------------------------------------------------------------ F14 KV backends
def test_F14_sqlite_prefix_is_case_sensitive(tmp_path):
    kv = SqliteKV(str(tmp_path / "kv.sqlite"))
    kv.put("users", "u_Ab", {"x": 1})
    kv.put("users", "u_ab", {"x": 2})
    assert [k for k, _ in kv.list("users", prefix="u_A")] == ["u_Ab"]


@pytest.fixture
def ddb(monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(k, "testing")
    with mock_aws():
        c = boto3.client("dynamodb", region_name="us-east-1")
        c.create_table(TableName="t_state", BillingMode="PAY_PER_REQUEST",
                       AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                                             {"AttributeName": "sk", "AttributeType": "S"}],
                       KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                                  {"AttributeName": "sk", "KeyType": "RANGE"}])
        yield c


def test_F14_dynamo_cas_refuses_an_expired_item(ddb):
    now = {"t": 1_000_000.0}
    kv = DynamoKV(ddb, users_table="t_state", decisions_table="t_state", state_table="t_state",
                  now_fn=lambda: now["t"])
    kv.put("otp", "o1", {"v": 1}, ttl=1_000_100)
    now["t"] = 1_000_200.0  # expired, not yet reaped by DynamoDB
    assert kv.get("otp", "o1") is None
    assert kv.cas("otp", "o1", {"v": 2}, expected_rev=1) is False


def test_F14_dynamo_put_never_reuses_a_rev(ddb, monkeypatch):
    kv = DynamoKV(ddb, users_table="t_state", decisions_table="t_state", state_table="t_state")
    kv.put("state", "k", {"v": 1})
    stale = kv.get("state", "k")
    kv.put("state", "k", {"v": 2})  # a concurrent writer
    real_get = kv.get
    first = {"done": False}

    def get(ns, key):
        if not first["done"]:
            first["done"] = True
            return copy.deepcopy(stale)
        return real_get(ns, key)

    monkeypatch.setattr(kv, "get", get)
    kv.put("state", "k", {"v": 3})
    got = real_get("state", "k")
    assert got["v"] == 3 and got["_rev"] == 3


# ------------------------------------------------------------------ F15 sync reconcile / duplicates
def test_F15_lost_race_duplicate_raises_no_second_alert(signed, services, monkeypatch):
    fb = {"method": "STAFF_OVERRIDE", "staff_id": "s_guard01", "code_id": "OVR-RF15"}
    body = batch("KIOSK_LIB_01", [make_record("att_rf15", fallback=fb, codes=["FALLBACK_OK"])])
    assert signed.post("/v1/sync", body).json()["accepted"] == ["att_rf15"]
    n_alerts = len(services.kv.list("alerts"))
    real_get = services.kv.get
    hidden = {"once": True}

    def get(ns, key):  # the concurrent replay is not visible yet to a plain read
        if ns == "decisions" and hidden["once"]:
            hidden["once"] = False
            return None
        return real_get(ns, key)

    monkeypatch.setattr(services.kv, "get", get)
    again = signed.post("/v1/sync", {**body, "batch_id": "b_retry"}).json()
    assert again["duplicates"] == ["att_rf15"]
    assert len(services.kv.list("alerts")) == n_alerts


def test_F15_duplicate_rebuilds_the_flags_of_the_first_delivery(signed, services):
    from datetime import UTC, datetime

    services.schedule.revoke(rtype="USER", target_id="u_3c4d", reason="ADMIN",
                             revoked_at=datetime(2026, 11, 14, 3, 30, tzinfo=UTC))
    body = batch("KIOSK_LIB_01", [make_record("att_rf15b")])
    first = signed.post("/v1/sync", body).json()
    assert first["flags"] == [{"attempt_id": "att_rf15b", "type": "POST_HOC_REVOKED"}]
    again = signed.post("/v1/sync", body).json()  # ack lost: the kiosk resends
    assert again["duplicates"] == ["att_rf15b"] and again["flags"] == first["flags"]


def test_F15_decision_keys_are_kiosk_scoped(signed, client):
    main = Signed(client, kiosk="KIOSK_MAIN_01")
    a = main.post("/v1/sync", batch("KIOSK_MAIN_01", [make_record("att_same", kiosk="KIOSK_MAIN_01",
                                                                  zone="MAIN_GATE")])).json()
    b = signed.post("/v1/sync", batch("KIOSK_LIB_01", [make_record("att_same")])).json()
    assert a["accepted"] == ["att_same"] and b["accepted"] == ["att_same"] and b["duplicates"] == []


# ------------------------------------------------------------------ F17 error envelope
def test_F17_unhandled_500_carries_server_time(lenient, services, monkeypatch):
    def boom(_since):
        raise RuntimeError("bug")

    monkeypatch.setattr(services.schedule, "revocations_since", boom)
    r = lenient.get("/v1/revocations?since=0")
    assert r.status_code == 500 and r.json()["error"]["code"] == "INTERNAL"
    assert "x-server-time" in r.headers and "x-latency-ms" in r.headers


def test_F17_client_errors_are_not_reported_as_internal(signed):
    r = signed.request("POST", "/v1/enroll", content=b"--x\r\n", content_type="multipart/form-data")
    assert 400 <= r.status_code < 500 and r.json()["error"]["code"] == "VALIDATION_ERROR", r.text


# ------------------------------------------------------------------ F18 match user_status
def test_F18_match_status_comes_from_user_state(signed, services):
    enrol(signed)

    def _erase_suspend(doc):
        doc["revocations"].append({"user_id": "u_3c4d", "revoked_at": "2026-11-14T04:00:00Z", "reason": "ERASED"})

    services.schedule.publish(_erase_suspend, "test:erased-suspension")
    r = signed.post("/v1/match", {"attempt_id": "att_rf18", "kiosk_id": "KIOSK_LIB_01",
                                  "image_b64": b64(make_fake_jpeg("u_3c4d", salt="q"))})
    assert r.status_code == 200 and r.json()["user_id"] == "u_3c4d"
    assert r.json()["user_status"] == "SUSPENDED"


# ------------------------------------------------------------------ F19 rotate drops + memoised PBKDF2
def test_F19_rebased_codes_are_reported_and_audited(main, services):
    salt = "ab" * 8
    legacy = {"code_id": "OVR-OLD-01", "staff_id": "s_guard02", "salt": salt, "valid_until": "2026-11-16T00:00:00Z",
              "hash": hashlib.pbkdf2_hmac("sha256", b"12345678", bytes.fromhex(salt), 1000).hex()}

    def _m(doc):
        doc["override_codes"] = {"kdf": "PBKDF2-HMAC-SHA256", "iterations": 1000, "codes": [legacy]}

    services.schedule.publish(_m, "test:legacy-iterations")
    out = main.post("/v1/admin/codes/rotate", {"staff_id": "s_guard01", "count": 1}, headers=ADMIN_H).json()
    assert "OVR-OLD-01" in out["dropped_code_ids"]
    audit = [it for it in services.schedule.audit_entries(50) if it["action"] == "CODES_ROTATE"]
    assert "OVR-OLD-01" in audit[-1]["dropped_code_ids"]


def test_F19_documented_code_check_is_memoised(main, services, monkeypatch):
    from cloud.app.services import code_hygiene

    assert main.post("/v1/admin/codes/rotate", {"staff_id": "s_guard01", "count": 5}, headers=ADMIN_H).status_code \
        == 201
    calls = {"n": 0}
    real = code_hygiene.hashlib.pbkdf2_hmac

    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(code_hygiene.hashlib, "pbkdf2_hmac", counting)
    assert main.post("/v1/admin/codes/rotate", {"staff_id": "s_guard02", "count": 1}, headers=ADMIN_H).status_code \
        == 201
    assert calls["n"] <= 8, calls  # only the new code is checked; the 5 existing ones come from the memo


# ------------------------------------------------------------------ F20 contact edit
def test_F20_contact_edit_is_audited_with_the_actor(main, services):
    r = main.request("PUT", "/v1/admin/users/u_3c4d/contact", headers=ADMIN_H,
                     json_body={"display_name": "Priya", "email": "priya@example.org", "consent": True,
                                "consent_version": "2026-11-14.v1", "actor": "staff:s_guard01"})
    assert r.status_code == 200, r.text
    entry = [it for it in services.schedule.audit_entries(50) if it["action"] == "CONTACT_UPDATE"]
    assert entry and entry[-1]["user_id"] == "u_3c4d" and entry[-1]["kiosk_id"] == "KIOSK_MAIN_01"
    assert entry[-1]["actor"] == "legacy:admin_token"  # legacy credential: the client value is ignored
    assert "priya@example.org" not in json.dumps(entry[-1])  # no PII in the ledger


def test_F20_contact_upsert_uses_cas(main, services, monkeypatch):
    real_get = services.kv.get

    def racing_get(ns, key):  # a concurrent enrolment lands between our read and our write
        item = real_get(ns, key)
        if ns == "users" and key == "u_3c4d" and item is None:
            services.kv.put("users", "u_3c4d", {"user_id": "u_3c4d", "face_ids": ["f1", "f2"]})
        return item

    monkeypatch.setattr(services.kv, "get", racing_get)
    r = main.request("PUT", "/v1/admin/users/u_3c4d/contact", headers=ADMIN_H,
                     json_body={"display_name": "Priya", "email": "priya@example.org", "consent": True,
                                "consent_version": "2026-11-14.v1"})
    assert r.status_code == 200, r.text
    assert real_get("users", "u_3c4d")["face_ids"] == ["f1", "f2"]  # the enrolment's faces were not clobbered


# ------------------------------------------------------------------ accept_kiosk_bundle audit
def test_uploaded_bundle_acceptance_is_audited(main, services):
    from .test_bundle_upload import operator_bundle

    r = main.request("PUT", "/v1/admin/schedule/KIOSK_MAIN_01", json_body=operator_bundle(46), headers=ADMIN_H)
    assert r.status_code == 200, r.text
    entry = [it for it in services.schedule.audit_entries(50) if it["action"] == "SCHEDULE_UPLOAD"]
    assert entry and entry[-1]["bundle_version"] == 46 and entry[-1]["kiosk_id"] == "KIOSK_MAIN_01"


def test_F11_resend_window_still_enforced(signed, services, clock):
    _otp_user(services)
    assert signed.post("/v1/otp/send", {"attempt_id": "att_w", "user_id": "u_3c4d",
                                        "channel": "email"}).status_code == 201
    clock.advance(seconds=1)
    assert signed.post("/v1/otp/send", {"attempt_id": "att_w", "user_id": "u_3c4d", "channel": "email"},
                       now=time.time() + 1).status_code == 429


# ------------------------------------------------------------------ offline-verification audit (cloud side)
def _hashed_chain(n: int, *, kiosk: str = "KIOSK_LIB_01", drop: tuple[int, ...] = (), **kw) -> list[dict]:
    from .conftest import genesis

    prev = genesis(kiosk)
    out = []
    for seq in range(1, n + 1):
        it = make_record(f"att_ch{seq}", seq=seq, prev_hash=prev, ts=f"2026-11-14T04:{10 + seq:02d}:00Z", **kw)
        prev = it["record_hash"]
        if seq not in drop:
            out.append(it)
    return out


def test_OF3_deleted_record_seq_gap_raises_chain_gap_alert(signed):
    items = _hashed_chain(5, drop=(3,))
    out = signed.post("/v1/sync?verbose=true", batch("KIOSK_LIB_01", items)).json()
    assert sorted(out["accepted"]) == ["att_ch1", "att_ch2", "att_ch4", "att_ch5"]  # later records still ingested
    gaps = [a for a in out["alerts"] if a["alert"] == "ALERT_CHAIN_GAP"]
    assert gaps and gaps[0]["detail"]["missing_first_seq"] == 3 and gaps[0]["detail"]["missing_last_seq"] == 3


def test_OF3_tombstoned_gap_is_not_a_chain_gap(signed):
    items = _hashed_chain(5, drop=(3,))
    tomb = {"type": "TOMBSTONE", "kiosk_id": "KIOSK_LIB_01", "count": 1, "first_seq": 3, "last_seq": 3,
            "chain_head": items[-1]["record_hash"], "tombstone_id": "t3"}
    out = signed.post("/v1/sync?verbose=true", batch("KIOSK_LIB_01", [*items, tomb])).json()
    assert "ALERT_CHAIN_GAP" not in {a["alert"] for a in out["alerts"]}


def test_OF5_offline_manual_review_override_is_not_a_schedule_mismatch(signed):
    fb = {"method": "STAFF_OVERRIDE", "staff_id": "s_guard01", "code_id": "OVR-RF-A3"}
    rec = make_record("att_a3", user=None, fallback=fb, codes=["FALLBACK_OK", "OFFLINE_MODE"])
    out = signed.post("/v1/sync?verbose=true", batch("KIOSK_LIB_01", [rec])).json()
    assert "ALERT_SCHEDULE_MISMATCH" not in {a["alert"] for a in out["alerts"]}
    assert out["flags"] == [] and out["acks"][0]["verdict"] == "MANUAL_REVIEW"
    assert "ALERT_OVERRIDE_USED" in {a["alert"] for a in out["alerts"]}


def test_M2_unhashed_record_from_a_chained_kiosk_is_tamper(signed):
    first = _hashed_chain(2)
    signed.post("/v1/sync", batch("KIOSK_LIB_01", first))
    bare = make_record("att_nohash", seq=3, ts="2026-11-14T04:20:00Z")  # record_hash / prev_hash stripped
    out = signed.post("/v1/sync?verbose=true", batch("KIOSK_LIB_01", [bare], batch_id="b2")).json()
    assert out["accepted"] == ["att_nohash"]
    assert any(a["alert"] == "ALERT_LOG_TAMPER" and a["detail"].get("reason") == "record_hash missing"
               for a in out["alerts"])


# ------------------------------------------------------------------ F16 key-range reads
@pytest.mark.parametrize("backend", ["memory", "sqlite", "dynamodb"])
def test_F16_list_supports_a_key_range(backend, tmp_path, request):
    from cloud.app.services.kv import MemoryKV

    if backend == "dynamodb":
        c = request.getfixturevalue("ddb")
        kv = DynamoKV(c, users_table="t_state", decisions_table="t_state", state_table="t_state")
    else:
        kv = MemoryKV() if backend == "memory" else SqliteKV(str(tmp_path / "r.sqlite"))
    for i in range(1, 6):
        kv.put("revocations", f"{i:012d}", {"seq": i})
    kv.put("revocationsX", f"{9:012d}", {"seq": 9})  # another namespace never leaks in
    assert [it["seq"] for _, it in kv.list("revocations", start=f"{3:012d}")] == [3, 4, 5]
    kv.put("decisions", "K1|a", {"v": 1})
    kv.put("decisions", "K1|b", {"v": 2})
    kv.put("decisions", "K2|a", {"v": 3})
    assert [k for k, _ in kv.list("decisions", prefix="K1|", start="K1|b")] == ["K1|b"]
    assert [k for k, _ in kv.list("decisions", prefix="K1|")] == ["K1|a", "K1|b"]


# ------------------------------------------------------------------ SC2-D4 offline enrolment record (edge-app)
def test_offline_enrolment_record_flags_offline_allows_until_cloud_enrolment(signed, services):
    rec = {"user_id": "u_3c4d", "kiosk_id": "KIOSK_LIB_01", "at": "2026-11-14T04:00:00Z", "template_count": 3,
           "model": "arcface_w600k_r50@1", "actor": "staff:s_enroller01"}
    r = signed.post("/v1/enroll/offline-record", rec)
    assert r.status_code == 201 and r.json() == {"recorded": True, "duplicate": False}
    again = signed.post("/v1/enroll/offline-record", rec, now=time.time() + 1)
    assert again.status_code == 200 and again.json()["duplicate"] is True
    entry = [e for e in services.schedule.audit_entries(20) if e["action"] == "OFFLINE_ENROLMENT"]
    assert len(entry) == 1 and entry[0]["actor"] == "staff:s_enroller01"
    assert entry[0]["actor_assurance"] == "edge_asserted" and entry[0]["via"] == "kiosk:KIOSK_LIB_01"
    out = signed.post("/v1/sync", batch("KIOSK_LIB_01", [make_record("att_off1")])).json()
    assert {"attempt_id": "att_off1", "type": "OFFLINE_TEMPLATE_UNCONFIRMED"} in out["flags"]
    enrol(signed)  # a cloud enrolment indexes a face: the mark is cleared
    out2 = signed.post("/v1/sync", batch("KIOSK_LIB_01", [make_record("att_off2")])).json()
    assert out2["flags"] == []


@pytest.mark.parametrize("bad", [{"kiosk_id": "KIOSK_MAIN_01"}, {"at": "yesterday"}, {"template_count": 0},
                                 {"images_b64": ["x"]}, {"actor": "bob"}])
def test_offline_enrolment_record_validation(signed, bad):
    rec = {"user_id": "u_3c4d", "kiosk_id": "KIOSK_LIB_01", "at": "2026-11-14T04:00:00Z", "template_count": 3,
           "model": "m", **bad}
    r = signed.post("/v1/enroll/offline-record", rec)
    assert r.status_code in (403, 422), r.text
