from __future__ import annotations

import hashlib
import json
import warnings
from datetime import UTC, datetime

import pytest

warnings.filterwarnings("ignore", message=".*httpx.*starlette.testclient.*")

from fastapi.testclient import TestClient  # noqa: E402

from cloud.app.auth import signed_headers  # noqa: E402
from cloud.app.canonical import canonical_json, item_hmac  # noqa: E402
from cloud.app.clock import FixedClock  # noqa: E402
from cloud.app.config import Settings  # noqa: E402
from cloud.app.container import build_services  # noqa: E402
from cloud.app.main import create_app  # noqa: E402

KIOSK_KEY = "k" * 64
BUNDLE_KEY = "b" * 64
API_KEY = "test-api-key"
ADMIN = "test-admin-token"
PEPPER = "hidhack-demo-pepper"
# POLICY_TEST_CASES baseline B: Sat 14 Nov 2026 10:05 IST = 04:35Z
T0 = datetime(2026, 11, 14, 4, 35, tzinfo=UTC)


def etag(version: int, issued: datetime = T0) -> str:
    """Bundle ETag (V2 §E): "v<bundle_version>-<issued_at epoch>"; the FixedClock issues at T0."""
    return f'"v{version}-{int(issued.timestamp())}"'


def make_settings(**kw) -> Settings:
    """Test settings. Existing tests use the shared kiosk key and the legacy X-Admin-Token, so both opt-ins are ON
    here; tests of the production default (both OFF) pass auth_legacy_admin_token=False etc. explicitly."""
    base = dict(auth_legacy_admin_token=True, allow_shared_kiosk_key=True,
                kiosk_hmac_key=KIOSK_KEY, schedule_bundle_hmac_key=BUNDLE_KEY, cloud_api_key=API_KEY,
                admin_token=ADMIN, card_id_pepper=PEPPER, otp_pepper="otp-pepper", face_backend="fake",
                liveness_backend="fake", store_backend="memory", email_backend="fake", blob_backend="memory",
                metrics_sink="memory", health_refresh_s=3600.0)
    base.update(kw)
    return Settings(**base)


class Signed:
    """TestClient wrapper that signs every request like the edge does (API.md §0)."""

    def __init__(self, client: TestClient, kiosk: str = "KIOSK_LIB_01", key: str = KIOSK_KEY,
                 api_key: str = API_KEY) -> None:
        self.c = client
        self.kiosk = kiosk
        self.key = key
        self.api_key = api_key

    def request(self, method: str, path: str, *, json_body=None, content: bytes | None = None,
                headers: dict | None = None, kiosk: str | None = None, content_type: str | None = None,
                now: float | None = None):
        body = content if content is not None else (json.dumps(json_body).encode() if json_body is not None else b"")
        h = signed_headers(kiosk_id=kiosk or self.kiosk, key=self.key, api_key=self.api_key, method=method,
                           path=path, body=body, now=now)
        if json_body is not None:
            h["Content-Type"] = "application/json"
        if content_type:
            h["Content-Type"] = content_type
        h.update(headers or {})
        return self.c.request(method, path, content=body, headers=h)

    def get(self, path: str, **kw):
        return self.request("GET", path, **kw)

    def post(self, path: str, json_body=None, **kw):
        return self.request("POST", path, json_body=json_body, **kw)

    def delete(self, path: str, **kw):
        return self.request("DELETE", path, **kw)


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(T0)


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def services(settings, clock):
    return build_services(settings, clock=clock)


@pytest.fixture
def client(services):
    app = create_app(services=services)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def signed(client) -> Signed:
    return Signed(client)


# ------------------------------------------------------------------ sync record helpers (SC2.5)
def genesis(kiosk: str) -> str:
    return hashlib.sha256(f"genesis:{kiosk}".encode()).hexdigest()


RECORD_FIELDS = ("attempt_id", "seq", "kiosk_id", "zone", "ts_utc", "user_id", "candidate_user_id", "decision",
                 "reason_codes", "resolved_codes", "scores", "fallback", "schedule_version", "cache_state", "mode")


def record_hash(prev_hash: str, record: dict) -> str:
    """Same formula as edge/offline/store.py compute_record_hash."""
    body = {k: v for k, v in record.items() if k not in ("prev_hash", "record_hash")}
    return hashlib.sha256(prev_hash.encode("ascii") + canonical_json(body)).hexdigest()


def make_record(att: str, *, kiosk: str = "KIOSK_LIB_01", zone: str = "LIBRARY", user: str | None = "u_3c4d",
                decision: str = "ALLOW", mode: str = "OFFLINE", ts: str = "2026-11-14T04:35:00Z",
                seq: int | None = None, codes: list[str] | None = None, fallback: dict | None = None,
                candidate: str | None = None, prev_hash: str | None = None, **extra) -> dict:
    """SC2.5 record as the edge stores it, wrapped as a sync item (type + idempotency_key, no hmac yet)."""
    if codes is None:
        codes = ["ACCESS_OK"] + (["OFFLINE_MODE"] if mode == "OFFLINE" else []) if decision == "ALLOW" else []
    rec = {"attempt_id": att, "seq": seq, "kiosk_id": kiosk, "zone": zone, "ts_utc": ts, "user_id": user,
           "candidate_user_id": candidate, "decision": decision, "reason_codes": codes, "resolved_codes": [],
           "scores": {"pad": 0.93, "flash": 0.81, "match": 0.72, "margin": 0.31}, "fallback": fallback,
           "schedule_version": 42, "cache_state": "FRESH", "mode": mode, **extra}
    if prev_hash is not None:
        rec["prev_hash"] = prev_hash
        rec["record_hash"] = record_hash(prev_hash, rec)
    return {"type": "DECISION", "idempotency_key": att, **rec}


def signed_item(item: dict, key: str = KIOSK_KEY) -> dict:
    body = {k: v for k, v in item.items() if k != "hmac"}
    return {**body, "hmac": item_hmac(key, body)}


def batch(kiosk: str, items: list[dict], batch_id: str = "b_test", **extra) -> dict:
    return {"kiosk_id": kiosk, "batch_id": batch_id, "items": [signed_item(i) for i in items], **extra}
