"""Shared fixtures for edge/offline tests: a fake cloud enforcing the docs/API.md v1.1 sync contract and an
in-process PolicyRuntime on a temp data dir (never the live :8000 edge)."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta
from typing import Literal

import httpx
import pytest
from pydantic import BaseModel, ConfigDict, Field

from edge.offline.bundle import canonical_json, sign_bundle
from edge.offline.signing import verify_request
from edge.policy.runtime import PolicyRuntime
from edge.policy.tests.builders import (
    PROJECT_ROOT,
    RT_CLOCK,
    TEST_BUNDLE_KEY,
    TEST_CARD_PEPPER,
    TEST_DATA_KEY,
    TEST_KIOSK_KEY,
    TOTP_SECRETS,
    load_example_bundle,
)
from edge.policy.tests.wallclock import fake_wall_clock  # noqa: F401  (autouse; POLICY_TEST_WALL_CLOCK)


@pytest.fixture(autouse=True)
def _anchor_runtime_clock() -> None:
    """RT_CLOCK starts at the baseline instant in every test (no dependence on the run order / elapsed time)."""
    RT_CLOCK.reset()


# ---------------------------------------------------------------- API.md v1.1 §4.4 server-side models (oracle)
class FallbackUsed(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: Literal["TOTP", "CARD", "EMAIL_OTP", "STAFF_OVERRIDE"]
    staff_id: str | None = None
    code_id: str | None = None
    totp_step: int | None = None  # lead decision: added for Y07 (API.md round-2 pass)


class SyncItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attempt_id: str
    seq: int
    kiosk_id: str
    zone: str
    ts_utc: datetime
    user_id: str | None
    candidate_user_id: str | None
    decision: Literal["ALLOW", "STEP_UP", "DENY"]
    reason_codes: list[str]
    resolved_codes: list[str]
    scores: dict[str, float | None]
    fallback: FallbackUsed | None
    schedule_version: int | None
    cache_state: Literal["FRESH", "EXPIRED", "INVALID"] | None
    mode: Literal["ONLINE", "OFFLINE"]
    prev_hash: str
    record_hash: str
    idempotency_key: str
    hmac: str


class TombstoneItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["TOMBSTONE"]
    count: int
    first_seq: int
    last_seq: int
    chain_head: str
    hmac: str


class SyncRequest(BaseModel):
    kiosk_id: str
    batch_id: str
    chain_head: str
    chain_head_hmac: str
    items: list[TombstoneItem | SyncItem] = Field(max_length=50)


def signed_now(now: datetime, version: int = 42) -> dict:
    b = load_example_bundle()
    b["bundle_version"] = version
    b["issued_at"] = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    b["expires_at"] = (now + timedelta(hours=11, minutes=55)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for c in b["override_codes"]["codes"]:
        c["valid_until"] = (now + timedelta(hours=36)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return sign_bundle(b, TEST_BUNDLE_KEY)


class FakeCloud:
    def __init__(self) -> None:
        self.up = True
        self.stored: dict[str, dict] = {}
        self.tombstones: list[dict] = []
        self.calls: list[tuple[str, str]] = []
        self.sync_batches: list[list[dict]] = []
        self.flags: list[dict] = []
        self.alerts: list[dict] = []  # server-side alerts (ALERT_SYNC_CONFLICT); not in the non-verbose response
        self.conflict_variants: list[dict] = []
        self.revocations: list[dict] = []
        self.bundle: dict | None = None
        self.lose_next_sync_response = False
        self.bundle_status = 200
        self.etag_304 = False  # True: answer If-None-Match for the current version with 304

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        if not self.up:
            raise httpx.ConnectError("cloud down", request=request)
        if path != "/v1/health":
            assert verify_request(request.method, path, request.content or b"", request.headers,
                                  kiosk_key=TEST_KIOSK_KEY), "bad request signature"
        if path == "/v1/health":
            return httpx.Response(200, json={"status": "ok"})
        if path == "/v1/revocations":
            return httpx.Response(200, json={"as_of": "2026-11-14T04:58:00Z", "revocation_seq": len(self.revocations),
                                             "items": self.revocations})
        if path.startswith("/v1/schedule/"):
            if self.bundle_status != 200 or self.bundle is None:
                return httpx.Response(self.bundle_status if self.bundle_status != 200 else 404)
            if self.etag_304 and request.headers.get("If-None-Match") == f'"{self.bundle.get("bundle_version")}"':
                return httpx.Response(304)  # API.md 4.2: unchanged bundle
            return httpx.Response(200, json=self.bundle)
        if path == "/v1/sync":
            return self._sync(request)
        return httpx.Response(404)

    def _sync(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        req = SyncRequest.model_validate(body)  # contract: extra="forbid" items, <= 50
        mac = hmac.new(TEST_KIOSK_KEY, req.chain_head.encode(), hashlib.sha256).hexdigest()
        assert hmac.compare_digest(mac, req.chain_head_hmac)
        acc, dup, rej = [], [], []
        self.sync_batches.append(body["items"])
        for it in body["items"]:
            expected = hmac.new(TEST_KIOSK_KEY, canonical_json({k: v for k, v in it.items() if k != "hmac"}),
                                hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, it["hmac"]):
                rej.append({"idempotency_key": it.get("idempotency_key"), "error": "HMAC_INVALID"})
                continue
            if it.get("type") == "TOMBSTONE":
                self.tombstones.append(it)
                continue
            k = it["idempotency_key"]
            if k in self.stored:
                if self.stored[k]["record_hash"] == it["record_hash"]:
                    dup.append(k)
                else:  # API.md 4.4 / deployed cloud: keep both versions, alert, ack as a duplicate
                    if all(v["record_hash"] != it["record_hash"] for v in self.conflict_variants):
                        self.conflict_variants.append(it)
                        self.alerts.append({"alert": "ALERT_SYNC_CONFLICT", "attempt_id": k})
                    dup.append(k)
            else:
                self.stored[k] = it
                acc.append(k)
        if self.lose_next_sync_response:
            self.lose_next_sync_response = False
            raise httpx.ReadTimeout("response lost", request=request)
        return httpx.Response(200, json={"accepted": acc, "duplicates": dup, "rejected": rej, "flags": self.flags,
                                         "server_time": "2026-11-14T04:58:41Z"})


@pytest.fixture
def cloud() -> FakeCloud:
    return FakeCloud()


@pytest.fixture
def make_rt(tmp_path):
    made = []

    def make(cloud: FakeCloud | None = None, kiosk: str = "KIOSK_LIB_01", **extra_env) -> PolicyRuntime:
        now = RT_CLOCK()
        bundle = signed_now(now)
        (tmp_path / "bundle.signed.json").write_text(json.dumps(bundle), encoding="utf-8")
        if cloud is not None and cloud.bundle is None:
            cloud.bundle = bundle
        env = {"KIOSK_ID": kiosk, "EDGE_DATA_KEY": TEST_DATA_KEY, "SCHEDULE_BUNDLE_HMAC_KEY": TEST_BUNDLE_KEY.decode(),
               "CARD_ID_PEPPER": TEST_CARD_PEPPER.decode(), "KIOSK_HMAC_KEY": TEST_KIOSK_KEY.decode(),
               "EDGE_DATA_DIR": str(tmp_path), "CLOUD_API_URL": "https://cloud.test" if cloud else ""}
        env.update(extra_env)
        rt = PolicyRuntime.from_env(PROJECT_ROOT, env=env, transport=httpx.MockTransport(cloud) if cloud else None,
                                    clock=RT_CLOCK)
        rt.set_random_challenge("OFF")
        for uid, secret in TOTP_SECRETS.items():
            rt.set_totp_secret(uid, secret)
        made.append(rt)
        return rt

    yield make
    for rt in made:
        rt.stop()


def attempt(aid: str, **deltas):
    from edge.policy.tests.builders import B

    return B().set(attempt_id=aid, **deltas).signals().model_copy(update={"t0": RT_CLOCK()})


def bring_online(rt: PolicyRuntime) -> None:
    for _ in range(3):
        rt.heartbeat()
    assert rt.monitor.state == "SYNCING"
    rt.sync_now()
    assert rt.monitor.state == "ONLINE"
