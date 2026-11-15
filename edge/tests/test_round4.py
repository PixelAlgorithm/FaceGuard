"""Round-4 fixes (lead brief, 2026-11-14 evening), one regression test group per item:

1. cloud /v1/match client: 60 s keep-alive + fire-and-forget warm-up GET at session/start (same client,
   skipped if the client was used < 20 s ago; never blocks or fails an attempt)
2. POST /v1/admin/random-challenge accepts FORCE
3. DEMO_MODE kiosk switch: only kiosks the VERIFIED bundle covers and the policy runtime evaluates, else 409
4. /v1/metrics sync.last_sync_at == /v1/mode last_sync.at
5. non-ASCII admin/depth tokens and attempt/depth nonces -> 401/403, never an HTTP 500
6. device box choice: (fail-grade containment, conf); a faint box around the face never masks a phone
7. size limits before reading: oversized part -> 413 before read; rgb_0 through _files; JPEG > 4096 px
   refused before decode

Model-free "lite" app (no ONNX weights), scratch EDGE_DATA_DIR, dummy secrets; never the live :8000 edge.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import io
import json
import os
import threading
import time
import types
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import cv2
import httpx
import numpy as np
import pytest
from fastapi.testclient import TestClient

from edge.config import PROJECT_ROOT, Thresholds
from edge.tests.conftest import SecretHeaders

ADMIN_TOKEN = "round4-admin-token"  # dummy secrets: the real .env values are never used here
DEPTH_TOKEN = "round4-depth-token"
BUNDLE_KEY = "round4-bundle-hmac-key"
KIOSK = "KIOSK_MAIN_01"
START = {"kiosk_id": KIOSK, "client": {"camera_label": "FaceTime HD Camera", "user_agent": "pytest", "screen": {}},
         "flash_enabled": True}
ADMIN = SecretHeaders({"X-Admin-Token": ADMIN_TOKEN})
DEPTH = SecretHeaders({"X-Depth-Token": DEPTH_TOKEN})


# ------------------------------------------------------------------ lite app (no models)
@pytest.fixture
def lite_settings(settings, tmp_path):
    return dataclasses.replace(settings, kiosk_id=KIOSK, admin_token=ADMIN_TOKEN, depth_device_token=DEPTH_TOKEN,
                               kiosk_hmac_key="round4-kiosk-key", cloud_api_key="round4-api-key",
                               cloud_api_url="", demo_mode=True, lan_port=0, data_dir=tmp_path)


class StubRuntime:
    """Just enough runtime for session/start; these tests never reach a policy decision."""

    kiosk_id = KIOSK

    def __init__(self, mode: str = "ONLINE") -> None:
        self._mode = mode

    def mode(self) -> str:
        return self._mode


def scratch_runtime(tmp_path, *, demo: bool = True, bundle: str | None = "signed"):
    """Real PolicyRuntime on a temp dir: example bundle signed with a dummy key ("signed"), the shipped
    example whose signature does not verify ("unsigned"), or no bundle file (None)."""
    from edge.offline.bundle import sign_bundle
    from edge.policy.runtime import PolicyRuntime

    example = json.loads((PROJECT_ROOT / "config" / "schedule.example.json").read_text(encoding="utf-8"))
    path = tmp_path / "bundle.signed.json"
    if bundle == "signed":
        path.write_text(json.dumps(sign_bundle(example, BUNDLE_KEY.encode())), encoding="utf-8")
    elif bundle == "unsigned":
        path.write_text(json.dumps(example), encoding="utf-8")
    env = {"KIOSK_ID": KIOSK, "EDGE_DATA_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode(),
           "EDGE_DATA_DIR": str(tmp_path), "SCHEDULE_BUNDLE_HMAC_KEY": BUNDLE_KEY, "BUNDLE_PATH": str(path),
           "CLOUD_API_URL": "", "DEMO_MODE": "1" if demo else "0", "CARD_ID_PEPPER": "round4-pepper",
           "KIOSK_HMAC_KEY": "round4-kiosk-key"}
    return PolicyRuntime.from_env(PROJECT_ROOT, env=env)


def lite_ctx(settings, thresholds, runtime, *, cloud=None):
    from edge.attempts import EdgeContext
    from edge.cloud_client import CloudClient
    from edge.depth_bridge import DepthBridge
    from edge.events import EventBus
    from edge.metrics import MetricsStore
    from edge.perception import EngineHealth
    from edge.session import AttemptStore

    engine = types.SimpleNamespace(health=EngineHealth(), ready=False, detector=None, embedder=None)
    return EdgeContext(settings=settings, thresholds=thresholds, engine=engine, runtime=runtime,
                       runtime_kind="test", sessions=AttemptStore(), events=EventBus(), metrics=MetricsStore(),
                       cloud=cloud or CloudClient(settings, thresholds), depth=DepthBridge(thresholds),
                       templates=None, pool=ThreadPoolExecutor(max_workers=2), started_monotonic=time.monotonic())


@contextlib.contextmanager
def lite_client(ctx):
    from edge.app import create_app

    with TestClient(create_app(lambda: ctx)) as c:
        yield c


def with_overrides(thresholds: Thresholds, **dotted) -> Thresholds:
    raw = json.loads(json.dumps(thresholds.raw))
    for key, value in dotted.items():
        node = raw
        *parents, leaf = key.split("__")
        for p in parents:
            node = node[p]
        node[leaf] = value
    return Thresholds(raw)


def wait_until(pred, timeout_s: float = 3.0) -> bool:
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.005)
    return pred()


# ------------------------------------------------------------------ 1. cloud keep-alive + warm-up
class CountingHTTPServer:
    """Minimal HTTP/1.1 keep-alive server (asyncio, 127.0.0.1) that counts TCP connections."""

    def __init__(self) -> None:
        self.connections = 0
        self.requests: list[tuple[str, str]] = []

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            while True:
                head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1").split("\r\n")
                method, path, _ = head[0].split(" ", 2)
                length = next((int(h.split(":", 1)[1]) for h in head[1:] if h.lower().startswith("content-length:")), 0)
                if length:
                    await reader.readexactly(length)
                self.requests.append((method, path))
                body = json.dumps({"user_id": "u_3c4d", "similarity": 99.1, "status": "ok"}).encode()
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s"
                             % (len(body), body))
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()


def test_match_client_reuses_one_connection_across_attempt_gaps(settings, thresholds, monkeypatch):
    """Root cause: httpx's default 5 s keep-alive vs attempts 7-21 s apart -> every match paid a cold TLS
    connection (~0.7 s to us-east-1 > the 700 ms budget -> OFFLINE). httpcore's idle clock is faked."""
    import httpcore._async.http11 as h11mod

    from edge.cloud_client import CloudClient

    clock = {"t": 1000.0}
    monkeypatch.setattr(h11mod, "time", types.SimpleNamespace(monotonic=lambda: clock["t"]))

    async def go():
        srv = CountingHTTPServer()
        server = await asyncio.start_server(srv.handle, "127.0.0.1", 0)
        url = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        cfg = dataclasses.replace(settings, cloud_api_url=url, kiosk_hmac_key="k", cloud_api_key="a")
        cloud = CloudClient(cfg, thresholds)
        await cloud.start()
        try:
            assert cloud.warm_up() is True  # session/start warm-up: same client as the match
            await cloud._warm_task
            for _ in range(3):
                assert (await cloud.match("att_1", b"jpeg", None)).ok
                clock["t"] += 15.0  # next attempt 15 s later
            ours = srv.connections
            srv.connections = 0
            async with httpx.AsyncClient(base_url=url) as default_client:  # control: httpx defaults
                for _ in range(3):
                    await default_client.get("/v1/health")
                    clock["t"] += 15.0
            return ours, srv.connections, list(srv.requests)
        finally:
            await cloud.stop()
            server.close()
            await server.wait_closed()

    ours, control, requests = asyncio.run(go())
    assert requests[0] == ("GET", str(thresholds.get("connectivity.health_path")))
    assert [r for r in requests[1:4]] == [("POST", "/v1/match")] * 3
    assert ours == 1, "warm-up + 3 matches 15 s apart must share one keep-alive connection"
    assert control == 3, "control: the 5 s httpx default reconnects after every gap (the bug)"


def _blocking_cloud(thresholds, settings, release: threading.Event, seen: list, fail: bool = False):
    from edge.cloud_client import CloudClient

    health = str(thresholds.get("connectivity.health_path"))

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.url.path == health:
            while not release.is_set():  # a slow cloud: loop-agnostic wait (TestClient runs its own loop)
                await asyncio.sleep(0.005)
            if fail:
                raise httpx.ConnectError("cloud unreachable")
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(404)

    return CloudClient(settings, thresholds, transport=httpx.MockTransport(handler)), health


def test_session_start_fires_the_warm_up_without_awaiting_it(lite_settings, thresholds):
    release, seen = threading.Event(), []
    cfg = dataclasses.replace(lite_settings, cloud_api_url="https://cloud.test")
    cloud, health = _blocking_cloud(thresholds, cfg, release, seen)
    with lite_client(lite_ctx(cfg, thresholds, StubRuntime("ONLINE"), cloud=cloud)) as c:
        try:
            r = c.post("/v1/session/start", json=START)
            assert r.status_code == 201, r.text  # answered while the warm-up GET is still blocked
            assert wait_until(lambda: ("GET", health) in seen)
            assert cloud.warmups_started == 1 and not cloud._warm_task.done() and cloud._last_used is None
        finally:
            release.set()
        assert wait_until(lambda: cloud._last_used is not None)
        r2 = c.post("/v1/session/start", json=START)  # client used < 20 s ago -> no second warm-up
        assert r2.status_code == 201 and cloud.warmups_started == 1 and seen.count(("GET", health)) == 1


def test_warm_up_failure_offline_or_rekognition_off_never_touch_the_attempt(lite_settings, thresholds):
    release, seen = threading.Event(), []
    release.set()
    cfg = dataclasses.replace(lite_settings, cloud_api_url="https://cloud.test")
    cloud, _ = _blocking_cloud(thresholds, cfg, release, seen, fail=True)
    with lite_client(lite_ctx(cfg, thresholds, StubRuntime("ONLINE"), cloud=cloud)) as c:
        assert c.post("/v1/session/start", json=START).status_code == 201
        assert wait_until(lambda: cloud._warm_task is not None and cloud._warm_task.done())
        assert cloud._warm_task.exception() is None and cloud._last_used is None  # failure swallowed
    for runtime, th in ((StubRuntime("OFFLINE"), thresholds),
                        (StubRuntime("ONLINE"), with_overrides(thresholds, match__rekognition__enabled=False))):
        seen.clear()
        cloud2, _ = _blocking_cloud(th, cfg, release, seen)
        with lite_client(lite_ctx(cfg, th, runtime, cloud=cloud2)) as c:
            assert c.post("/v1/session/start", json=START).status_code == 201
        assert cloud2.warmups_started == 0 and seen == []  # no match will be made -> no warm-up


def test_warm_up_skip_window_and_single_flight(settings, thresholds):
    from edge.cloud_client import CloudClient

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(200, json={"user_id": "u_3c4d", "similarity": 99.0, "status": "ok"})

    cfg = dataclasses.replace(settings, cloud_api_url="https://cloud.test", kiosk_hmac_key="k", cloud_api_key="a")

    async def go():
        cloud = CloudClient(cfg, thresholds, transport=httpx.MockTransport(handler))
        assert cloud.warm_up() is False  # not started: nothing to warm
        await cloud.start()
        try:
            assert (await cloud.match("att_1", b"x", None)).ok
            assert cloud.warm_up() is False  # used just now
            cloud._last_used -= 25.0  # idle 25 s (> 20 s skip window)
            assert cloud.warm_up() is True
            assert cloud.warm_up() is False  # one warm-up in flight at a time
            await cloud._warm_task
        finally:
            await cloud.stop()

    asyncio.run(go())
    assert calls == ["/v1/match", str(thresholds.get("connectivity.health_path"))]


def test_match_pool_keepalive_is_configured(settings, thresholds):
    from edge.cloud_client import KEEPALIVE_EXPIRY_S, CloudClient

    cfg = dataclasses.replace(settings, cloud_api_url="https://cloud.test")

    async def go():
        cloud = CloudClient(cfg, thresholds)
        await cloud.start()
        try:
            return cloud._client._transport._pool._keepalive_expiry
        finally:
            await cloud.stop()

    assert KEEPALIVE_EXPIRY_S >= 60 and asyncio.run(go()) == KEEPALIVE_EXPIRY_S


# ------------------------------------------------------------------ 2. FORCE random challenge
def test_random_challenge_force_mode(lite_settings, thresholds, tmp_path):
    from pydantic import ValidationError

    from edge.schemas import RandomChallengeRequest

    assert RandomChallengeRequest(mode="FORCE").mode == "FORCE"
    with pytest.raises(ValidationError):
        RandomChallengeRequest(mode="ALWAYS")
    with lite_client(lite_ctx(lite_settings, thresholds, scratch_runtime(tmp_path))) as c:
        r = c.post("/v1/admin/random-challenge", json={"mode": "FORCE"}, headers=ADMIN)
        assert r.status_code == 200 and r.json() == {"random_challenge": "FORCE"}
        assert c.get("/v1/admin/mode/detail", headers=ADMIN).json()["random_challenge"] == "FORCE"
        assert "random_challenge" not in c.get("/v1/mode").json()  # offline-verification F6: badge subset only
        assert c.post("/v1/admin/random-challenge", json={"mode": "AUTO"}, headers=ADMIN).status_code == 200


# ------------------------------------------------------------------ 3. kiosk switch
def _start(c, kiosk):
    return c.post("/v1/session/start", json={**START, "kiosk_id": kiosk})


def test_kiosk_switch_needs_the_verified_bundle_and_the_runtime(lite_settings, thresholds, tmp_path):
    rt = scratch_runtime(tmp_path)  # signed bundle covering all 5 demo kiosks; runtime = KIOSK_MAIN_01
    assert "KIOSK_LIB_01" in rt.bundles.lvb["kiosks"]
    ctx = lite_ctx(lite_settings, thresholds, rt)
    with lite_client(ctx) as c:
        assert _start(c, KIOSK).status_code == 201
        covered = _start(c, "KIOSK_LIB_01")  # in the bundle, but decide() would be SYSTEM_ERROR (other kiosk)
        assert covered.status_code == 409 and covered.json()["error"]["code"] == "INVALID_STATE"
        assert "KIOSK_MAIN_01" in covered.json()["error"]["message"]
        unknown = _start(c, "KIOSK_NOT_IN_BUNDLE")
        assert unknown.status_code == 409 and "not covered by the verified schedule bundle" in \
            unknown.json()["error"]["message"]
        ctx.settings = dataclasses.replace(lite_settings, demo_mode=False)
        r = _start(c, "KIOSK_LIB_01")
        assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN"  # unchanged outside demo mode


def test_kiosk_switch_never_uses_the_unsigned_example(lite_settings, thresholds, tmp_path):
    """Regression: a missing runtime method made the edge accept every kiosk of the UNSIGNED
    config/schedule.example.json; their attempts then ended in DENY SYSTEM_ERROR (engine kiosk check)."""
    rt = scratch_runtime(tmp_path, bundle="unsigned")
    assert rt.bundles.lvb is None
    with lite_client(lite_ctx(lite_settings, thresholds, rt)) as c:
        r = _start(c, "KIOSK_LIB_01")
        assert r.status_code == 409 and "no verified schedule bundle" in r.json()["error"]["message"]
        assert _start(c, KIOSK).status_code == 201  # own kiosk still served (policy handles INVALID bundle)


# ------------------------------------------------------------------ 4. /v1/metrics last_sync_at
def test_metrics_last_sync_at_matches_mode(lite_settings, thresholds, tmp_path):
    rt = scratch_runtime(tmp_path)
    with lite_client(lite_ctx(lite_settings, thresholds, rt)) as c:
        assert c.get("/v1/metrics", headers=ADMIN).json()["sync"]["last_sync_at"] is None  # never synced
        rt.sync.last_sync_at = datetime(2026, 11, 14, 8, 30, tzinfo=UTC)
        at = c.get("/v1/admin/mode/detail", headers=ADMIN).json()["last_sync"]["at"]
        sync = c.get("/v1/metrics", headers=ADMIN).json()["sync"]
        assert at is not None and sync["last_sync_at"] == at and sync["queue_depth"] == 0


# ------------------------------------------------------------------ 5. non-ASCII tokens / nonces
def test_secret_equal_never_raises():
    from edge.session import secret_equal

    assert secret_equal("n_abc", "n_abc")
    for given in ("n_abd", "n_ébc", "\udc80", "", None, b"n_abc", 123):
        assert secret_equal("n_abc", given) is False
    assert secret_equal("", "") is False and secret_equal(None, "x") is False
    assert secret_equal("töken", "töken") is False  # a non-ASCII configured secret never matches


def test_non_ascii_nonces_are_rejected_not_raised(thresholds):
    from edge.depth_bridge import DepthBridge
    from edge.session import AttemptStore, NonceError

    store = AttemptStore()
    att = store.create(kiosk_id=KIOSK, flash_enabled=False, flash_sequence=[], camera_label="cam",
                       claimed_user_id=None, recapture_of=None, recapture_count=0)
    with pytest.raises(NonceError) as e:
        store.consume_nonce(att.attempt_id, att.nonce + "é")
    assert e.value.code == "NONCE_INVALID" and not att.nonce_used

    async def go():
        bridge = DepthBridge(with_overrides(thresholds, liveness__depth__enabled=True))
        await bridge.request("att_d", "PASSIVE", 700)
        job = await bridge.next_pending(0.1)
        bad = bridge.consume_nonce("att_d", "PASSIVE", job.depth_nonce + "ü")
        return bad, bridge.consume_nonce("att_d", "PASSIVE", job.depth_nonce)

    assert asyncio.run(go()) == (False, True)


def test_non_ascii_tokens_and_nonces_over_http(lite_settings, thresholds):
    th = with_overrides(thresholds, liveness__depth__enabled=True)
    with lite_client(lite_ctx(lite_settings, th, StubRuntime("OFFLINE"))) as c:
        weird = "töken".encode()  # header bytes >= 0x80 -> latin-1 decoded non-ASCII str
        r = c.post("/v1/admin/random-challenge", json={"mode": "AUTO"}, headers={"X-Admin-Token": weird})
        assert r.status_code == 401 and r.json()["error"]["code"] == "UNAUTHORIZED"
        r = c.get("/v1/depth/pending", params={"wait_s": 0}, headers={"X-Depth-Token": weird})
        assert r.status_code == 401
        s = c.post("/v1/session/start", json=START).json()
        assert s["depth_requested"] is True
        meta = {"nonce": s["nonce"] + "é", "face_lock_at_ms": 1, "capture_started_at_ms": 2,
                "frame_timestamps_ms": [10, 20, 30]}
        files = {f"frame_{i}": (f"f{i}.jpg", b"\xff\xd8\xff", "image/jpeg") for i in range(3)}
        r = c.post(f"/v1/attempt/{s['attempt_id']}/frames", files=files, data={"meta": json.dumps(meta)})
        assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN"
        job = c.get("/v1/depth/pending", params={"wait_s": 0}, headers=DEPTH).json()
        dmeta = {"attempt_id": s["attempt_id"], "depth_nonce": job["depth_nonce"] + "é", "depth_type": "depth",
                 "dtype": "float32", "width": 4, "height": 4}
        dfiles = {"depth_0": ("d0.bin", np.zeros(16, "<f4").tobytes(), "application/octet-stream")}
        r = c.post("/v1/depth/frames", files=dfiles, data={"meta": json.dumps(dmeta)}, headers=DEPTH)
        assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN"


# ------------------------------------------------------------------ 6. device box choice
def _face():
    from edge.ml.detect import FaceBox

    return FaceBox(100, 100, 200, 200, 0.99, np.zeros((5, 2), np.float32))


def _policy_zone(sig, D) -> str:
    """DECISION_POLICY §3 device rule (as in edge/policy/liveness.py), from thresholds.yaml values."""
    if sig.device_conf >= D["fail_conf"] and sig.device_face_containment >= D["face_containment"]:
        return "FAIL"
    return "UNSURE" if sig.device_conf >= D["unsure_conf"] else "PASS"


def test_faint_tv_box_around_the_face_no_longer_masks_a_phone(thresholds):
    from edge.ml.device import DeviceBox, containment, device_signal

    D = thresholds.get("liveness.device_detector")
    face = _face()
    phone = DeviceBox(cls=67, label="cell phone", conf=0.90, x1=125, y1=100, x2=230, y2=210)  # 75 % of the face
    tv = DeviceBox(cls=62, label="tv", conf=0.12, x1=0, y1=0, x2=640, y2=480)  # contains the face
    assert containment(face, phone) == pytest.approx(0.75) and containment(face, tv) == 1.0
    alone = device_signal(face, [phone], D["face_containment"], D["fail_conf"])
    both = device_signal(face, [phone, tv], D["face_containment"], D["fail_conf"])
    assert _policy_zone(alone, D) == "UNSURE"
    assert (both.label, both.device_conf, both.device_face_containment) == ("cell phone", 0.9, 0.75)
    assert _policy_zone(both, D) == "UNSURE" and both.n_device_boxes == 2  # was PASS (tv 0.12 picked)
    screen = DeviceBox(cls=67, label="cell phone", conf=0.5, x1=80, y1=80, x2=230, y2=260)  # fail-grade
    laptop = DeviceBox(cls=63, label="laptop", conf=0.95, x1=150, y1=150, x2=400, y2=400)  # 25 % overlap
    worst = device_signal(face, [laptop, screen, tv], D["face_containment"], D["fail_conf"])
    assert (worst.label, worst.device_conf) == ("cell phone", 0.5) and _policy_zone(worst, D) == "FAIL"


def test_perception_passes_fail_conf_to_the_device_rule(settings, thresholds):
    from edge.ml.device import DeviceBox
    from edge.perception import PerceptionEngine

    eng = PerceptionEngine(settings, thresholds)  # no models loaded: only the device rule is exercised
    boxes = [DeviceBox(cls=67, label="cell phone", conf=0.90, x1=125, y1=100, x2=230, y2=210),
             DeviceBox(cls=62, label="tv", conf=0.12, x1=0, y1=0, x2=640, y2=480)]
    eng.device = types.SimpleNamespace(detect_all=lambda bgr: boxes)
    sig = eng.device_score(types.SimpleNamespace(bgr=np.zeros((480, 640, 3), np.uint8), main=_face()))
    assert sig.label == "cell phone" and sig.device_conf == 0.9


# ------------------------------------------------------------------ 7. size limits
def _jpeg(w: int, h: int, progressive: bool = False) -> bytes:
    params = [int(cv2.IMWRITE_JPEG_QUALITY), 80, int(cv2.IMWRITE_JPEG_PROGRESSIVE), int(progressive)]
    ok, buf = cv2.imencode(".jpg", np.full((h, w, 3), 128, np.uint8), params)
    assert ok
    return buf.tobytes()


def _with_sof(data: bytes, w: int, h: int) -> bytes:
    """Same tiny file, SOF header claiming w x h (a decompression bomb header)."""
    b, i = bytearray(data), 2
    while True:
        marker, seg = b[i + 1], (b[i + 2] << 8) | b[i + 3]
        if marker in (0xC0, 0xC2):
            b[i + 5:i + 7], b[i + 7:i + 9] = h.to_bytes(2, "big"), w.to_bytes(2, "big")
            return bytes(b)
        i += 2 + seg


def test_decode_jpeg_refuses_oversized_or_non_jpeg_before_decoding(monkeypatch):
    from edge import perception
    from edge.perception import MAX_JPEG_SIDE_PX, decode_jpeg, jpeg_size

    assert MAX_JPEG_SIDE_PX == 4096
    edge_ok = _jpeg(4096, 8)
    assert jpeg_size(edge_ok) == (4096, 8) and decode_jpeg(edge_ok).shape == (8, 4096, 3)
    assert jpeg_size(_jpeg(64, 48, progressive=True)) == (64, 48)  # SOF2
    bomb = _with_sof(_jpeg(16, 16), 5000, 5000)
    assert jpeg_size(bomb) == (5000, 5000)
    _, png = cv2.imencode(".png", np.zeros((8, 8, 3), np.uint8))
    real_imdecode = cv2.imdecode

    def guarded(buf, flags):
        raise AssertionError("cv2.imdecode called on an input that must be refused first")

    monkeypatch.setattr(perception.cv2, "imdecode", guarded)
    for bad in (_jpeg(4097, 8), _jpeg(8, 4097), bomb, png.tobytes(), b"", b"\xff\xd8", b"\xff\xd8\xff\xd9",
                b"\xff\xd8" + os.urandom(64), b"GIF89a" + bytes(32)):
        assert decode_jpeg(bad) is None
    monkeypatch.setattr(perception.cv2, "imdecode", real_imdecode)
    assert decode_jpeg(_jpeg(32, 24)).shape == (24, 32, 3)


class _CountingUpload:
    """Starlette UploadFile stand-in that records reads."""

    def __init__(self, data: bytes, size: int | None) -> None:
        from starlette.datastructures import UploadFile

        self.reads = 0
        self.upload = UploadFile(file=io.BytesIO(data), size=size, filename="f.jpg")
        real = self.upload.read

        async def read(n: int = -1) -> bytes:
            self.reads += 1
            return await real(n)

        self.upload.read = read


def test_files_checks_every_size_before_reading_any_part():
    from starlette.datastructures import FormData

    from edge.app import MAX_FRAME_BYTES, _files
    from edge.errors import ApiError

    small = _CountingUpload(b"abc", 3)
    huge = _CountingUpload(b"", MAX_FRAME_BYTES + 1)  # declared size only: reading it would be the bug
    form = FormData([("frame_0", small.upload), ("frame_1", huge.upload)])
    with pytest.raises(ApiError) as e:
        asyncio.run(_files(form, "frame_", 5, MAX_FRAME_BYTES))
    assert (e.value.code, e.value.status) == ("PAYLOAD_TOO_LARGE", 413) and small.reads == huge.reads == 0
    unsized = _CountingUpload(b"x" * (MAX_FRAME_BYTES + 10), None)  # no size from the parser: bounded read
    with pytest.raises(ApiError) as e:
        asyncio.run(_files(FormData([("frame_0", unsized.upload)]), "frame_", 5, MAX_FRAME_BYTES))
    assert e.value.status == 413
    empty = _CountingUpload(b"", 0)
    with pytest.raises(ApiError) as e:
        asyncio.run(_files(FormData([("frame_0", empty.upload)]), "frame_", 5, MAX_FRAME_BYTES))
    assert (e.value.code, e.value.status) == ("VALIDATION_ERROR", 422)
    ok = _CountingUpload(b"abc", 3)
    assert asyncio.run(_files(FormData([("frame_0", ok.upload)]), "frame_", 5, MAX_FRAME_BYTES)) == [b"abc"]


def test_oversized_parts_are_413_over_http(lite_settings, thresholds):
    from edge.app import MAX_FRAME_BYTES

    th = with_overrides(thresholds, liveness__depth__enabled=True)
    ctx = lite_ctx(lite_settings, th, StubRuntime("OFFLINE"))
    with lite_client(ctx) as c:
        s = c.post("/v1/session/start", json=START).json()
        meta = {"nonce": s["nonce"], "face_lock_at_ms": 1, "capture_started_at_ms": 2,
                "frame_timestamps_ms": [10, 20, 30]}
        files = {f"frame_{i}": (f"f{i}.jpg", _jpeg(16, 16), "image/jpeg") for i in range(3)}
        files["frame_1"] = ("f1.jpg", b"\xff" * (MAX_FRAME_BYTES + 1), "image/jpeg")
        r = c.post(f"/v1/attempt/{s['attempt_id']}/frames", files=files, data={"meta": json.dumps(meta)})
        assert r.status_code == 413 and r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
        assert ctx.sessions.get(s["attempt_id"]).nonce_used is False  # refused before the nonce was burnt
        bombs = {f"frame_{i}": (f"f{i}.jpg", _with_sof(_jpeg(16, 16), 5000, 5000), "image/jpeg") for i in range(3)}
        r = c.post(f"/v1/attempt/{s['attempt_id']}/frames", files=bombs, data={"meta": json.dumps(meta)})
        assert r.status_code == 422 and "4096" in r.json()["error"]["message"]
        s2 = c.post("/v1/session/start", json=START).json()
        job = c.get("/v1/depth/pending", params={"wait_s": 0}, headers=DEPTH).json()
        assert job["attempt_id"] in {s["attempt_id"], s2["attempt_id"]}
        dmeta = {"attempt_id": job["attempt_id"], "depth_nonce": job["depth_nonce"], "depth_type": "depth",
                 "dtype": "float32", "width": 4, "height": 4}
        dfiles = {"depth_0": ("d0.bin", np.zeros(16, "<f4").tobytes(), "application/octet-stream"),
                  "rgb_0": ("rgb_0.jpg", b"\xff" * (MAX_FRAME_BYTES + 1), "image/jpeg")}
        r = c.post("/v1/depth/frames", files=dfiles, data={"meta": json.dumps(dmeta)}, headers=DEPTH)
        assert r.status_code == 413 and r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
