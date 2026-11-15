"""API.md §0 auth (HMAC request signing) + X-Latency-Ms everywhere + fast public /v1/health."""

from __future__ import annotations

import dataclasses
import time

import pytest

from cloud.app.auth import signed_headers

from .conftest import API_KEY, KIOSK_KEY, make_settings


def test_health_is_public_fast_and_has_contract_fields(client):
    t = time.perf_counter()
    r = client.get("/v1/health")
    elapsed_ms = (time.perf_counter() - t) * 1000
    assert r.status_code == 200
    body = r.json()
    assert {"status", "rekognition", "dynamodb", "region"} <= set(body)
    assert body["region"] == "us-east-1" and body["status"] == "ok" and body["policy"] == "ok"
    assert int(r.headers["x-latency-ms"]) < 50 and elapsed_ms < 200
    assert client.get("/health").status_code == 200  # thresholds.yaml connectivity.health_path alias


def test_unsigned_request_rejected_with_latency_header(client):
    r = client.get("/v1/revocations")
    assert r.status_code == 401 and r.json()["error"]["code"] == "UNAUTHORIZED"
    assert "x-latency-ms" in r.headers and "x-server-time" in r.headers


def test_signed_request_accepted(signed):
    r = signed.get("/v1/revocations?since=0")
    assert r.status_code == 200 and "x-latency-ms" in r.headers


def test_signature_over_bare_path_is_refused_unless_transition_switch(client, services):
    """F5: a signature over the bare path leaves the query unauthenticated (?since=, ?actor=)."""
    h = signed_headers(kiosk_id="KIOSK_LIB_01", key=KIOSK_KEY, api_key=API_KEY, method="GET", path="/v1/revocations")
    assert client.get("/v1/revocations?since=0", headers=h).status_code == 401
    services.settings = dataclasses.replace(services.settings, accept_bare_path_sig=True)
    assert client.get("/v1/revocations?since=0", headers=h).status_code == 200


@pytest.mark.parametrize("change,msg", [
    ({"X-Api-Key": "nope"}, "invalid api key"),
    ({"X-Signature": "0" * 64}, "bad signature"),
    ({"X-Kiosk-Id": "KIOSK_UNKNOWN"}, "unknown kiosk"),
    ({"X-Timestamp": str(int(time.time()) - 120)}, "timestamp outside"),
    ({"X-Timestamp": "yesterday"}, "epoch seconds"),
])
def test_auth_failures(client, change, msg):
    h = signed_headers(kiosk_id="KIOSK_LIB_01", key=KIOSK_KEY, api_key=API_KEY, method="GET",
                       path="/v1/revocations")
    h.update(change)
    r = client.get("/v1/revocations", headers=h)
    assert r.status_code == 401 and msg in r.json()["error"]["message"]


def test_body_is_covered_by_signature(client):
    body = b'{"attempt_id":"att_1","user_id":"u_3c4d","channel":"email"}'
    h = signed_headers(kiosk_id="KIOSK_LIB_01", key=KIOSK_KEY, api_key=API_KEY, method="POST",
                       path="/v1/otp/send", body=body)
    h["Content-Type"] = "application/json"
    r = client.post("/v1/otp/send", content=body.replace(b"u_3c4d", b"u_1a2b"), headers=h)
    assert r.status_code == 401 and "bad signature" in r.json()["error"]["message"]


def test_non_idempotent_post_is_single_use(client):
    body = b'{"attempt_id":"att_r1","user_id":"u_nobody","channel":"email"}'
    h = signed_headers(kiosk_id="KIOSK_LIB_01", key=KIOSK_KEY, api_key=API_KEY, method="POST",
                       path="/v1/otp/send", body=body)
    h["Content-Type"] = "application/json"
    assert client.post("/v1/otp/send", content=body, headers=h).status_code == 404  # no e-mail on file
    r = client.post("/v1/otp/send", content=body, headers=h)
    assert r.status_code == 401 and "replayed" in r.json()["error"]["message"]


def test_unknown_route_has_error_envelope_and_latency(signed):
    r = signed.get("/v1/nope")
    assert r.status_code == 404 and r.json()["error"]["code"] == "NOT_FOUND" and "x-latency-ms" in r.headers


def test_body_too_large(client):
    big = b"x" * (make_settings().max_body_bytes + 1)
    r = client.post("/v1/match", content=big)
    assert r.status_code == 413 and r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_per_kiosk_keys_override_shared_key(clock):
    from fastapi.testclient import TestClient

    from cloud.app.container import build_services
    from cloud.app.main import create_app

    svc = build_services(make_settings(kiosk_keys={"KIOSK_SRV_01": "s" * 64}), clock=clock)
    with TestClient(create_app(services=svc)) as c:
        ok = signed_headers(kiosk_id="KIOSK_SRV_01", key="s" * 64, api_key=API_KEY, method="GET",
                            path="/v1/revocations")
        shared = signed_headers(kiosk_id="KIOSK_SRV_01", key=KIOSK_KEY, api_key=API_KEY, method="GET",
                                path="/v1/revocations")
        assert c.get("/v1/revocations", headers=ok).status_code == 200
        assert c.get("/v1/revocations", headers=shared).status_code == 401


def test_validation_error_never_echoes_input(signed):
    secret_looking = "A" * 64
    r = signed.post("/v1/match", {"attempt_id": "att_v", "kiosk_id": "KIOSK_LIB_01", "image_b64": secret_looking,
                                  "max_users": 99})
    assert r.status_code == 422 and secret_looking not in r.text
