"""/v1/enroll, /v1/match (1:N, 1:1, runner-up, no face, throttling/retry/503), DELETE /v1/enroll (erasure)."""

from __future__ import annotations

import base64

import pytest

from cloud.app.services.faces import FaceError
from cloud.tools.fakeimg import make_fake_jpeg

from .conftest import PEPPER


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def enroll_json(user="u_3c4d", **kw) -> dict:
    body = {"user_id": user, "display_name": "Priya N.", "email": "priya@example.org", "groups": ["student"],
            "consent": True, "consent_version": "2026-11-14.v1", "card_id": "HID-CARD-1002", "provision_totp": True,
            "images_b64": [b64(make_fake_jpeg(user, salt=f"f{i}")) for i in range(3)]}
    body.update(kw)
    return body


def match_body(img: bytes, **kw) -> dict:
    return {"attempt_id": "att_m1", "kiosk_id": "KIOSK_LIB_01", "image_b64": b64(img), **kw}


@pytest.fixture
def enrolled(signed):
    r = signed.post("/v1/enroll", enroll_json())
    assert r.status_code == 201, r.text
    r2 = signed.post("/v1/enroll", enroll_json("u_1a2b", display_name="Aarav S.", email="aarav@example.org",
                                               card_id="HID-CARD-1001"))
    assert r2.status_code == 201, r2.text
    return r.json()


def test_enroll_json_contract(enrolled, services):
    assert enrolled["faces_indexed"] == 3 and len(enrolled["face_ids"]) == 3
    # the cloud never mints a TOTP seed (the edge owns TOTP secrets): provision_totp only sets the bundle flag
    assert enrolled["totp_provisioning_uri"] is None and enrolled["totp_seed_persisted"] is False
    assert enrolled["schedule_entitlement"] is True and enrolled["destination_masked"] == "p****@example.org"
    assert enrolled["schedule_role"] == "student" and enrolled["requested_role"] is None
    row = services.kv.get("users", "u_3c4d")
    assert row["consent"]["version"] == "2026-11-14.v1" and row["status"] == "ACTIVE"
    # card hash scheme of config/schedule.example.json (demo pepper) -> identical to the seeded value
    assert row["card_id_hash"] == "d321eef09d98d6f2d2be42376fe89fbbaefb6d942235f329687bd674b22f9cdd"
    assert services.settings.card_id_pepper == PEPPER
    assert row["totp_seed_enc"] is None and row["totp_enrolled"] is True and "secret=" not in str(row)
    assert services.faces.calls.count("IndexFaces") == 6


def test_enroll_multipart_like_api_md(signed):
    import json

    import httpx

    meta = {k: v for k, v in enroll_json("u_7a8b", display_name="Rahul V.", email="rahul@example.org").items()
            if k != "images_b64"}
    files = {f"frame_{i}": (f"f{i}.jpg", make_fake_jpeg("u_7a8b", salt=str(i)), "image/jpeg") for i in range(2)}
    req = httpx.Request("POST", "http://x/v1/enroll", data={"meta": json.dumps(meta)}, files=files)
    body = req.read()
    r = signed.request("POST", "/v1/enroll", content=body, content_type=req.headers["content-type"])
    assert r.status_code == 201, r.text
    assert r.json()["faces_indexed"] == 2


@pytest.mark.parametrize("patch,code", [
    ({"consent": False}, "VALIDATION_ERROR"),
    ({"email": "not-an-email"}, "VALIDATION_ERROR"),
    ({"user_id": "bad id!"}, "VALIDATION_ERROR"),
    ({"images_b64": [b64(make_fake_jpeg("NOFACE"))]}, "VALIDATION_ERROR"),
    ({"images_b64": [b64(b"GIF89a....")]}, "VALIDATION_ERROR"),
])
def test_enroll_rejections(signed, patch, code):
    r = signed.post("/v1/enroll", enroll_json(**patch))
    assert r.status_code == 422 and r.json()["error"]["code"] == code


def test_match_1n_top1_and_contract(signed, enrolled):
    r = signed.post("/v1/match", match_body(make_fake_jpeg("u_3c4d")))
    assert r.status_code == 200, r.text
    m = r.json()
    assert m["matched"] is True and m["user_id"] == "u_3c4d" and m["similarity"] == 99.9
    assert m["runner_up_user_id"] is None and m["face_detected"] is True and m["user_status"] == "ACTIVE"
    assert m["source"] == "fake" and isinstance(m["latency_ms"], int) and "x-latency-ms" in r.headers


def test_match_runner_up_reported_raw_0_100(signed, enrolled):
    m = signed.post("/v1/match", match_body(make_fake_jpeg("u_3c4d=97.5;u_1a2b=85.0"))).json()
    assert (m["user_id"], m["similarity"], m["runner_up_user_id"], m["runner_up_similarity"]) == \
        ("u_3c4d", 97.5, "u_1a2b", 85.0)


def test_match_below_threshold_and_not_enrolled(signed, enrolled):
    assert signed.post("/v1/match", match_body(make_fake_jpeg("u_3c4d=70.0"))).json()["matched"] is False
    m = signed.post("/v1/match", match_body(make_fake_jpeg("u_unknown"))).json()
    assert m["matched"] is False and m["user_id"] is None and m["face_detected"] is True


def test_match_no_face(signed, enrolled):
    m = signed.post("/v1/match", match_body(make_fake_jpeg("NOFACE"))).json()
    assert m["face_detected"] is False and m["matched"] is False


def test_match_revoked_user_status(signed, enrolled, services):
    services.schedule.revoke(rtype="USER", target_id="u_3c4d", reason="ADMIN")
    assert signed.post("/v1/match", match_body(make_fake_jpeg("u_3c4d"))).json()["user_status"] == "REVOKED"


def test_match_1to1_claimed_user(signed, enrolled):
    ok = signed.post("/v1/match", match_body(make_fake_jpeg("u_3c4d"), mode="1:1", claimed_user_id="u_3c4d")).json()
    assert ok["matched"] is True and ok["user_id"] == "u_3c4d"
    other = signed.post("/v1/match", match_body(make_fake_jpeg("u_1a2b"), mode="1:1",
                                                claimed_user_id="u_3c4d")).json()
    assert other["matched"] is False and other["runner_up_user_id"] == "u_1a2b"
    nobody = signed.post("/v1/match", match_body(make_fake_jpeg("u_3c4d"), mode="1:1",
                                                 claimed_user_id="u_never")).json()
    assert nobody["matched"] is False


def test_match_throttle_one_retry_then_success(signed, enrolled, services):
    services.faces.throttle_next = 1
    r = signed.post("/v1/match", match_body(make_fake_jpeg("u_3c4d")))
    assert r.status_code == 200 and r.json()["matched"] is True
    assert any(rec["name"] == "RekognitionThrottled" for rec in services.metrics.records)


def test_match_throttle_twice_is_503_upstream_throttled(signed, enrolled, services):
    services.faces.throttle_next = 2
    r = signed.post("/v1/match", match_body(make_fake_jpeg("u_3c4d")))
    assert r.status_code == 503 and r.json()["error"]["code"] == "UPSTREAM_THROTTLED"
    assert r.json()["error"]["attempt_id"] == "att_m1"


def test_match_budget_timeout_is_503(signed, enrolled, services):
    services.match.budget_ms = 150
    services.faces.delay_s = 0.4
    r = signed.post("/v1/match", match_body(make_fake_jpeg("u_3c4d")))
    assert r.status_code == 503 and r.json()["error"]["code"] == "CLOUD_UNAVAILABLE"


def test_match_client_side_token_bucket(signed, enrolled, services):
    from cloud.app.services.adapters import TokenBucket

    services.match.search_bucket = TokenBucket(0.01, burst=1)  # one call per 100 s
    assert signed.post("/v1/match", match_body(make_fake_jpeg("u_3c4d"))).status_code == 200
    r = signed.post("/v1/match", {**match_body(make_fake_jpeg("u_3c4d")), "attempt_id": "att_m2"})
    assert r.status_code == 503 and r.json()["error"]["code"] == "UPSTREAM_THROTTLED"


def test_match_bad_inputs(signed, enrolled):
    assert signed.post("/v1/match", {"attempt_id": "a", "kiosk_id": "KIOSK_LIB_01",
                                     "image_b64": "!!!notbase64!!!"}).status_code == 422
    assert signed.post("/v1/match", match_body(b"GIF89a-not-jpeg")).status_code == 422
    r = signed.post("/v1/match", {**match_body(make_fake_jpeg("u_3c4d")), "kiosk_id": "KIOSK_MAIN_01"})
    assert r.status_code == 403


def test_disabled_face_backend_returns_503(clock):
    from fastapi.testclient import TestClient

    from cloud.app.container import build_services
    from cloud.app.main import create_app

    from .conftest import Signed, make_settings

    svc = build_services(make_settings(face_backend="disabled"), clock=clock)
    with TestClient(create_app(services=svc)) as c:
        s = Signed(c)
        r = s.post("/v1/match", match_body(make_fake_jpeg("u_3c4d")))
        assert r.status_code == 503 and r.json()["error"]["code"] == "CLOUD_UNAVAILABLE"
        assert s.post("/v1/enroll", enroll_json()).status_code == 503
        assert c.get("/v1/health").json()["rekognition"] == "disabled"


def test_reenroll_appends_faces(signed, enrolled, services):
    """Re-enrolment appends (edge parity, glasses on / off); details in test_enroll_append.py."""
    before = services.faces.face_count()
    r = signed.post("/v1/enroll", enroll_json(images_b64=[b64(make_fake_jpeg("u_3c4d", salt="new"))]))
    assert r.status_code == 201 and r.json()["template_version"] == 2
    assert services.faces.face_count() == before + 1
    assert set(enrolled["face_ids"]) < set(r.json()["face_ids"]) and len(r.json()["face_ids"]) == 4


def test_erasure_deletes_everything_and_emits_revocation(signed, enrolled, services):
    seq0, _ = services.schedule.revocations_since(0)
    r = signed.delete("/v1/enroll/u_3c4d")
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["erased"] and out["rekognition_user_deleted"] and out["faces_deleted"] == 3
    assert services.kv.get("users", "u_3c4d") is None
    assert "u_3c4d" not in services.faces.user_ids()
    # biometric erasure keeps the campus entitlement, suspended by an ERASED revocation (edge purges on it)
    doc = services.schedule.current()["doc"]
    assert doc["users"]["u_3c4d"]["role"] == "student" and doc["users"]["u_3c4d"]["fallback"]["totp_enrolled"] is False
    assert {"user_id": "u_3c4d", "reason": "ERASED"}.items() <= next(
        r for r in doc["revocations"] if r["user_id"] == "u_3c4d").items()
    assert out["revocation_seq"] > seq0
    seq, items = services.schedule.revocations_since(seq0)
    # non-deny feed event: the edge's deny-only overlay must not turn an erasure into a permanent ban
    assert [(i["type"], i["target_id"], i["reason"]) for i in items] == [("ERASE", "u_3c4d", "ERASED")]
    assert signed.post("/v1/match", match_body(make_fake_jpeg("u_3c4d"))).json()["matched"] is False
    assert signed.delete("/v1/enroll/u_never_enrolled").status_code == 404


def test_rekognition_failures_map_to_protocol_errors(signed, services):
    def boom(*a, **k):
        raise FaceError("CREDS_EXPIRED", "AWS session credentials expired")

    services.faces.search_users_by_image = boom
    r = signed.post("/v1/match", match_body(make_fake_jpeg("u_3c4d")))
    assert r.status_code == 503 and "expired" in r.json()["error"]["message"]
