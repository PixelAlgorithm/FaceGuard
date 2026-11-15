"""Cloud request signing (docs/API.md §0), reusable by edge-ml and the cloud verifier."""

from __future__ import annotations

import hashlib
import hmac

import httpx

from edge.offline.signing import KioskAuth, sign_request, string_to_sign, verify_request

KEY = b"test-kiosk-hmac-key"


def test_signature_is_hmac_of_the_documented_string():
    body = b'{"a":1}'
    h = sign_request("POST", "/v1/sync", body, kiosk_id="KIOSK_LIB_01", kiosk_key=KEY, api_key="k", now_s=1700000000)
    expected_msg = f"POST\n/v1/sync\n1700000000\n{hashlib.sha256(body).hexdigest()}".encode()
    assert string_to_sign("post", "/v1/sync", 1700000000, body) == expected_msg
    assert h["X-Signature"] == hmac.new(KEY, expected_msg, hashlib.sha256).hexdigest()
    assert h["X-Kiosk-Id"] == "KIOSK_LIB_01" and h["X-Timestamp"] == "1700000000" and h["X-Api-Key"] == "k"


def test_verify_roundtrip_and_tamper():
    body = b'{"items":[]}'
    h = sign_request("POST", "/v1/sync", body, kiosk_id="K", kiosk_key=KEY, now_s=1000)
    assert verify_request("POST", "/v1/sync", body, h, kiosk_key=KEY, now_s=1030)
    assert not verify_request("POST", "/v1/sync", body + b" ", h, kiosk_key=KEY, now_s=1030)
    assert not verify_request("POST", "/v1/other", body, h, kiosk_key=KEY, now_s=1030)
    assert not verify_request("POST", "/v1/sync", body, h, kiosk_key=b"wrong", now_s=1030)
    assert not verify_request("POST", "/v1/sync", body, h, kiosk_key=KEY, now_s=1061)  # > 60 s skew
    assert not verify_request("POST", "/v1/sync", body, {}, kiosk_key=KEY, now_s=1030)


def test_httpx_auth_signs_every_request():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["ok"] = verify_request(request.method, request.url.raw_path.decode(), request.content, request.headers,
                                    kiosk_key=KEY)
        seen["bare"] = verify_request(request.method, request.url.path, request.content, request.headers,
                                      kiosk_key=KEY)
        return httpx.Response(200)

    with httpx.Client(base_url="https://c", transport=httpx.MockTransport(handler),
                      auth=KioskAuth("KIOSK_LIB_01", KEY, "api")) as c:
        c.post("/v1/sync?x=1", content=b"{}")
    assert seen["ok"] is True and seen["bare"] is False  # F5: "?query" is part of the signed PATH
