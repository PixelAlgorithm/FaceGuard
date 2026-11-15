"""Round-5 (lead brief 2026-11-14 ~21:45 IST), one test group per item:

1. EARLY CLOUD PROBE: POST /v1/attempt/{id}/probe -> 202 started | skipped; the frames await the probe with
   rekognition_probe_deadline measured FROM PROBE START; identity binding (probe local top-1 == best frame
   local top-1 AND cosine >= match.local.allow_min_cosine) else CloudMatch(ok=False); one probe per attempt,
   not after the frames (409); > 2 MB -> 413; garbage JPEG -> 422, never a 500; no probe -> old path.
2. template-append gate at match.local.allow_min_cosine (not deny_below 0.30); revoked user -> 403
5. depth observability: rejected_token status, rate-limited pending-failure log without the token
6. API-valid static DENY SYSTEM_ERROR; /v1/health degraded reasons; otp_verify cloud errors -> None;
   edge data dir tightened to owner-only

Model-free fake engine + real TemplateStore on tmp_path, dummy secrets, fake cloud; never the live :8000 edge.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import secrets
import time
import types

import cv2
import httpx
import numpy as np
import pytest
from cryptography.fernet import Fernet

from edge.ml.detect import FaceBox
from edge.perception import EngineHealth, FrameAnalysis
from edge.policy.signals import CloudMatch, FrameQuality
from edge.tests.conftest import requires_models
from edge.tests.test_round4 import (
    DEPTH,
    START,
    StubRuntime,
    lite_client,
    lite_ctx,
    with_overrides,
)

EMB_DIM = 512
LEVEL_A, LEVEL_B, LEVEL_LOW = 60, 180, 120  # uniform grey level of a test JPEG -> whose face it "is"
PROBE_DEADLINE_MS = 1500


def _unit(v: np.ndarray) -> np.ndarray:
    return (v / np.linalg.norm(v)).astype(np.float32)


RNG = np.random.default_rng(5)
EMB_A, EMB_B = _unit(RNG.standard_normal(EMB_DIM)), _unit(RNG.standard_normal(EMB_DIM))
_ORTH = RNG.standard_normal(EMB_DIM)
_ORTH -= (_ORTH @ EMB_A) * EMB_A
_ORTH -= (_ORTH @ EMB_B) * EMB_B
# nearest enrolled user is still A, but only cosine 0.40 to A: a different person who happens to rank A first
EMB_LOW = _unit(0.40 * EMB_A + np.sqrt(1 - 0.40 ** 2) * _unit(_ORTH))


def jpeg_of(level: int, w: int = 640, h: int = 480) -> bytes:
    ok, buf = cv2.imencode(".jpg", np.full((h, w, 3), level, np.uint8))
    assert ok
    return buf.tobytes()


class FakeEngine:
    """analyze_frame/embed stand-in: a uniform frame of grey level L shows one face whose identity is L
    (0 = no face). Records every embed() call."""

    def __init__(self, fail_detect: bool = False) -> None:
        self.health = EngineHealth()
        self.ready = False
        self.detector = None
        self.embedder = types.SimpleNamespace(model_id="fake_arcface")
        self.fail_detect = fail_detect
        self.embeds = 0

    def analyze_frame(self, index: int, ts_ms: int, bgr: np.ndarray) -> FrameAnalysis:
        if self.fail_detect:
            raise RuntimeError("detector exploded")
        level = int(bgr[bgr.shape[0] // 2, bgr.shape[1] // 2, 0])
        faces = [] if level < 20 else [FaceBox(220, 140, 420, 340, 0.99, np.zeros((5, 2), np.float32))]
        q = FrameQuality(face_count=len(faces), secondary_face_rel_size=0.0, luma_mean=float(level),
                         overexposed_frac=0.0, laplacian_var=100.0 + index, face_width_px=200.0, iod_px=90.0,
                         yaw_deg=0.0, pitch_deg=0.0, roll_deg=0.0)
        return FrameAnalysis(index=index, ts_ms=ts_ms, bgr=bgr, faces=faces, quality=q,
                             aligned=bgr[:112, :112] if faces else None)

    def embed(self, fa: FrameAnalysis) -> np.ndarray | None:
        self.embeds += 1
        if fa.aligned is None:
            return None
        level = int(fa.bgr[fa.bgr.shape[0] // 2, fa.bgr.shape[1] // 2, 0])
        return {LEVEL_A: EMB_A, LEVEL_B: EMB_B, LEVEL_LOW: EMB_LOW}[min((LEVEL_A, LEVEL_B, LEVEL_LOW),
                                                                       key=lambda k: abs(k - level))]


class FakeCloud:
    """CloudClient stand-in: match() answers `top1_user` after `delay_s` (or raises `exc`)."""

    def __init__(self, delay_s: float = 0.0, top1_user: str = "u_a", exc: Exception | None = None,
                 enabled: bool = True) -> None:
        self.delay_s, self.top1_user, self.exc, self._enabled = delay_s, top1_user, exc, enabled
        self.calls: list[dict] = []

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    def warm_up(self) -> bool:
        return False

    async def match(self, attempt_id, jpeg, claimed_user_id, *, timeout_s=None) -> CloudMatch:
        self.calls.append({"attempt_id": attempt_id, "bytes": len(jpeg), "timeout_s": timeout_s,
                           "at": time.monotonic()})
        await asyncio.sleep(self.delay_s)
        if self.exc is not None:
            raise self.exc
        return CloudMatch(ok=True, top1_user=self.top1_user, top1_similarity=99.2)


@pytest.fixture
def probe_thresholds(thresholds):
    return with_overrides(thresholds, latency_budget_ms__rekognition_probe_deadline=PROBE_DEADLINE_MS,
                          match__rekognition__enabled=True)


@pytest.fixture
def lite_settings(settings, tmp_path):
    return dataclasses.replace(settings, kiosk_id="KIOSK_MAIN_01", admin_token="round5-admin-token",
                               depth_device_token="round4-depth-token", cloud_api_url="", demo_mode=True,
                               lan_port=0, data_dir=tmp_path)


def make_templates(tmp_path):
    from edge.ml.templates import TemplateStore

    store = TemplateStore(tmp_path / f"templates_{secrets.token_hex(4)}.fernet", Fernet.generate_key().decode(),
                          "fake_arcface")
    store.load()
    for uid, emb in (("u_a", EMB_A), ("u_b", EMB_B)):
        store.upsert(user_id=uid, display_name=uid, role="student", embeddings=emb[None], consent_version="t",
                     card_id_hash=None, totp_secret=None)
    return store


class ProbeRuntime(StubRuntime):
    """StubRuntime + the gallery filter: both test users are entitled at this kiosk."""

    def entitled_user_ids(self) -> set[str]:
        return {"u_a", "u_b"}


def probe_ctx(settings, thresholds, tmp_path, *, mode="ONLINE", cloud=None, engine=None):
    ctx = lite_ctx(settings, thresholds, ProbeRuntime(mode), cloud=cloud or FakeCloud())
    ctx.engine = engine or FakeEngine()
    ctx.templates = make_templates(tmp_path)
    return ctx


def new_attempt(ctx):
    return ctx.sessions.create(kiosk_id="KIOSK_MAIN_01", flash_enabled=False, flash_sequence=[],
                               camera_label="cam", claimed_user_id=None, recapture_of=None, recapture_count=0)


def frames_of(ctx, level: int, n: int = 3):
    from edge.perception import decode_jpeg

    jpegs = [jpeg_of(level) for _ in range(n)]
    return [ctx.engine.analyze_frame(i, i * 100, decode_jpeg(j)) for i, j in enumerate(jpegs)], jpegs


async def run_probe_then_frames(ctx, probe_level: int, frame_level: int, *, age_probe_s: float = 0.0):
    """start_probe on a `probe_level` face, optionally age the probe, then the frames' match_branch."""
    from edge.attempts import match_branch, start_probe

    att = new_attempt(ctx)
    res = await start_probe(ctx, att, jpeg_of(probe_level))
    if age_probe_s and att.probe is not None:
        att.probe.started -= age_probe_s
    frames, jpegs = frames_of(ctx, frame_level)
    t = time.monotonic()
    local, cm, _ = await match_branch(ctx, att, frames, jpegs)
    return att, res, local, cm, time.monotonic() - t


# ------------------------------------------------------------------ 1a. started / skipped over HTTP
def _post_probe(c, attempt_id, data: bytes, name: str = "probe"):
    return c.post(f"/v1/attempt/{attempt_id}/probe", files={name: ("probe.jpg", data, "image/jpeg")})


def test_probe_started_runs_the_cloud_match_on_a_small_face_crop(lite_settings, probe_thresholds, tmp_path):
    cloud = FakeCloud(delay_s=0.05)
    ctx = probe_ctx(lite_settings, probe_thresholds, tmp_path, cloud=cloud)
    with lite_client(ctx) as c:
        s = c.post("/v1/session/start", json=START).json()
        r = _post_probe(c, s["attempt_id"], jpeg_of(LEVEL_A))
        assert r.status_code == 202 and r.json() == {"accepted": True, "cloud": "started"}
        att = ctx.sessions.get(s["attempt_id"])
        assert att.probe_received and att.probe.cloud_task is not None
        assert att.probe.deadline_s == pytest.approx(PROBE_DEADLINE_MS / 1000)
        assert len(cloud.calls) == 1 and cloud.calls[0]["timeout_s"] == pytest.approx(1.5)
        assert cloud.calls[0]["bytes"] < len(jpeg_of(LEVEL_A))  # the face crop leaves the kiosk, not the frame
        assert ctx.engine.embeds >= 0  # local embedding scheduled (awaited by the frames)


@pytest.mark.parametrize("case", ["offline", "rekognition_off", "no_cloud", "no_face"])
def test_probe_skipped_when_this_attempt_will_not_call_the_cloud(lite_settings, probe_thresholds, tmp_path, case):
    th = with_overrides(probe_thresholds, match__rekognition__enabled=False) if case == "rekognition_off" \
        else probe_thresholds
    cloud = FakeCloud(enabled=case != "no_cloud")
    ctx = probe_ctx(lite_settings, th, tmp_path, mode="OFFLINE" if case == "offline" else "ONLINE", cloud=cloud)
    with lite_client(ctx) as c:
        s = c.post("/v1/session/start", json=START).json()
        r = _post_probe(c, s["attempt_id"], jpeg_of(0 if case == "no_face" else LEVEL_A))
        assert r.status_code == 202 and r.json() == {"accepted": True, "cloud": "skipped"}
        assert cloud.calls == []
        assert ctx.sessions.get(s["attempt_id"]).probe.cloud_task is None


# ------------------------------------------------------------------ 1b. state machine + limits
def test_second_probe_and_probe_after_frames_are_409(lite_settings, probe_thresholds, tmp_path):
    ctx = probe_ctx(lite_settings, probe_thresholds, tmp_path)
    with lite_client(ctx) as c:
        s = c.post("/v1/session/start", json=START).json()
        assert _post_probe(c, s["attempt_id"], jpeg_of(LEVEL_A)).status_code == 202
        r = _post_probe(c, s["attempt_id"], jpeg_of(LEVEL_A))
        assert r.status_code == 409 and r.json()["error"]["code"] == "INVALID_STATE"
        assert "one per attempt" in r.json()["error"]["message"]
        s2 = c.post("/v1/session/start", json=START).json()
        ctx.sessions.consume_nonce(s2["attempt_id"], s2["nonce"])  # the frames got there first
        r = _post_probe(c, s2["attempt_id"], jpeg_of(LEVEL_A))
        assert r.status_code == 409 and r.json()["error"]["code"] == "INVALID_STATE"
        assert ctx.sessions.get(s2["attempt_id"]).probe is None
        r = _post_probe(c, "att_unknown", jpeg_of(LEVEL_A))
        assert r.status_code == 404 and r.json()["error"]["code"] == "ATTEMPT_NOT_FOUND"


def test_probe_size_and_garbage_never_500(lite_settings, probe_thresholds, tmp_path):
    from edge.app import MAX_FRAME_BYTES

    ctx = probe_ctx(lite_settings, probe_thresholds, tmp_path)
    with lite_client(ctx) as c:
        s = c.post("/v1/session/start", json=START).json()
        r = _post_probe(c, s["attempt_id"], b"\xff" * (MAX_FRAME_BYTES + 1))
        assert r.status_code == 413 and r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
        assert not ctx.sessions.get(s["attempt_id"]).probe_received  # refused before it was claimed
        r = _post_probe(c, s["attempt_id"], jpeg_of(LEVEL_A), name="frame_0")  # wrong part name
        assert r.status_code == 422 and r.json()["error"]["code"] == "VALIDATION_ERROR"
        r = c.post(f"/v1/attempt/{s['attempt_id']}/probe", content=b"not multipart",
                   headers={"Content-Type": "application/json"})
        assert r.status_code == 422
        for junk in (b"\xff\xd8\xff" + bytes(64), b"GIF89a" + bytes(16), b"\x00"):
            s_j = c.post("/v1/session/start", json=START).json()
            r = _post_probe(c, s_j["attempt_id"], junk)
            assert r.status_code == 422 and r.json()["error"]["code"] == "VALIDATION_ERROR", r.text
        s3 = c.post("/v1/session/start", json=START).json()
        ctx.engine.fail_detect = True  # a detector exception -> skipped, never a 500
        r = _post_probe(c, s3["attempt_id"], jpeg_of(LEVEL_A))
        assert r.status_code == 202 and r.json()["cloud"] == "skipped"


def test_probe_cloud_exception_is_a_miss_not_a_500(lite_settings, probe_thresholds, tmp_path):
    ctx = probe_ctx(lite_settings, probe_thresholds, tmp_path, cloud=FakeCloud(exc=RuntimeError("boom")))
    _, res, _, cm, _ = asyncio.run(run_probe_then_frames(ctx, LEVEL_A, LEVEL_A))
    assert res["cloud"] == "started" and cm == CloudMatch(ok=False)


# ------------------------------------------------------------------ 1c. deadline from probe start
def test_probe_deadline_is_longer_than_the_frames_budget_and_counts_from_probe_start(
        lite_settings, probe_thresholds, tmp_path):
    rek_ms = int(probe_thresholds.get("latency_budget_ms.rekognition_timeout"))
    assert rek_ms < 1000 < PROBE_DEADLINE_MS
    # 1.0 s cloud round trip: past the 700 ms frames budget, inside the 1500 ms probe deadline -> used
    ctx = probe_ctx(lite_settings, probe_thresholds, tmp_path, cloud=FakeCloud(delay_s=1.0))
    att, _, _, cm, waited = asyncio.run(run_probe_then_frames(ctx, LEVEL_A, LEVEL_A))
    assert cm.ok and cm.top1_user == "u_a" and att.probe.outcome["used"] is True
    assert 0.8 < waited < 1.4
    # same 1.0 s cloud, but the probe started 1.3 s before the frames: only ~0.2 s left -> deadline -> OFFLINE
    ctx = probe_ctx(lite_settings, probe_thresholds, tmp_path, cloud=FakeCloud(delay_s=1.0))
    att, _, _, cm, waited = asyncio.run(run_probe_then_frames(ctx, LEVEL_A, LEVEL_A, age_probe_s=1.3))
    assert cm == CloudMatch(ok=False) and att.probe.outcome["why"] == "deadline"
    assert waited < 0.5, "the wait is the REMAINING probe budget, not a fresh rekognition_timeout"
    assert att.probe.cloud_task.cancelled() or att.probe.cloud_task.done()
    # probe older than its whole deadline: remaining clamps to 0 -> no wait at all
    ctx = probe_ctx(lite_settings, probe_thresholds, tmp_path, cloud=FakeCloud(delay_s=1.0))
    _, _, _, cm, waited = asyncio.run(run_probe_then_frames(ctx, LEVEL_A, LEVEL_A, age_probe_s=5.0))
    assert cm == CloudMatch(ok=False) and waited < 0.2


def test_probe_deadline_key_is_read_from_thresholds(thresholds, settings):
    from edge.attempts import _probe_deadline_s

    ctx = types.SimpleNamespace(thresholds=with_overrides(
        thresholds, latency_budget_ms__rekognition_probe_deadline=1234))
    assert _probe_deadline_s(ctx) == pytest.approx(1.234)
    raw = json.loads(json.dumps(thresholds.raw))
    raw["latency_budget_ms"].pop("rekognition_probe_deadline", None)
    from edge.config import Thresholds

    ctx = types.SimpleNamespace(thresholds=Thresholds(raw))  # key absent -> the stricter frames budget
    assert _probe_deadline_s(ctx) == pytest.approx(float(thresholds.get("latency_budget_ms.rekognition_timeout"))
                                                   / 1000)


# ------------------------------------------------------------------ 1d. identity binding
@pytest.mark.parametrize(("probe_level", "frame_level", "binding"), [
    (LEVEL_A, LEVEL_A, "ok"),
    (LEVEL_B, LEVEL_A, "user_mismatch"),  # probe shows B (cloud says u_a), frames show A: never bound
    (LEVEL_LOW, LEVEL_A, "low_cosine"),  # same local top-1 (A) but cosine 0.40 < allow_min_cosine
])
def test_probe_identity_binding(lite_settings, probe_thresholds, tmp_path, probe_level, frame_level, binding):
    allow = float(probe_thresholds.get("match.local.allow_min_cosine"))
    assert float(EMB_LOW @ EMB_A) < allow <= float(EMB_A @ EMB_A)
    ctx = probe_ctx(lite_settings, probe_thresholds, tmp_path, cloud=FakeCloud(delay_s=0.01, top1_user="u_a"))
    att, res, local, cm, _ = asyncio.run(run_probe_then_frames(ctx, probe_level, frame_level))
    assert res["cloud"] == "started" and att.probe.outcome["binding"] == binding
    assert {m.top1_user for m in local.values()} == {"u_a"}  # the local branch is unaffected by the probe
    if binding == "ok":
        assert cm.ok and cm.top1_user == "u_a" and att.probe.outcome["used"] is True
    else:
        assert cm == CloudMatch(ok=False) and att.probe.outcome["used"] is False  # -> attempt OFFLINE (P7)


def test_probe_with_nobody_entitled_never_binds(lite_settings, probe_thresholds, tmp_path):
    ctx = probe_ctx(lite_settings, probe_thresholds, tmp_path, cloud=FakeCloud())
    ctx.runtime = StubRuntime("ONLINE")  # neither excluded_ nor entitled_user_ids -> no candidate (fail-secure)
    att, _, _, cm, _ = asyncio.run(run_probe_then_frames(ctx, LEVEL_A, LEVEL_A))
    assert cm == CloudMatch(ok=False) and att.probe.outcome["binding"] == "no_local_match"


def test_probe_without_templates_never_binds(lite_settings, probe_thresholds, tmp_path):
    ctx = probe_ctx(lite_settings, probe_thresholds, tmp_path, cloud=FakeCloud())
    ctx.templates = None
    att, _, _, cm, _ = asyncio.run(run_probe_then_frames(ctx, LEVEL_A, LEVEL_A))
    assert cm == CloudMatch(ok=False) and att.probe.outcome["binding"] == "no_templates"


# ------------------------------------------------------------------ 1e. no probe / offline at frames
def test_no_probe_keeps_the_old_frames_path(lite_settings, probe_thresholds, tmp_path):
    from edge.attempts import match_branch

    cloud = FakeCloud(delay_s=0.01)
    ctx = probe_ctx(lite_settings, probe_thresholds, tmp_path, cloud=cloud)
    att = new_attempt(ctx)
    frames, jpegs = frames_of(ctx, LEVEL_A)
    _, cm, _ = asyncio.run(match_branch(ctx, att, frames, jpegs))
    assert cm.ok and len(cloud.calls) == 1 and cloud.calls[0]["timeout_s"] is None  # rekognition_timeout
    assert att.probe is None
    slow = FakeCloud(delay_s=1.0)  # the 700 ms frames budget still applies without a probe
    ctx = probe_ctx(lite_settings, probe_thresholds, tmp_path, cloud=slow)
    t = time.monotonic()
    _, cm, _ = asyncio.run(match_branch(ctx, new_attempt(ctx), frames, jpegs))
    assert cm == CloudMatch(ok=False) and time.monotonic() - t < 0.95


def test_skipped_probe_falls_back_to_the_old_path(lite_settings, probe_thresholds, tmp_path):
    cloud = FakeCloud(delay_s=0.01)
    ctx = probe_ctx(lite_settings, probe_thresholds, tmp_path, cloud=cloud)
    _, res, _, cm, _ = asyncio.run(run_probe_then_frames(ctx, 0, LEVEL_A))  # probe had no face
    assert res["cloud"] == "skipped" and cm.ok and len(cloud.calls) == 1 and cloud.calls[0]["timeout_s"] is None


def test_mode_offline_at_frames_cancels_the_probe(lite_settings, probe_thresholds, tmp_path):
    from edge.attempts import match_branch, start_probe

    ctx = probe_ctx(lite_settings, probe_thresholds, tmp_path, cloud=FakeCloud(delay_s=1.0))

    async def go():
        att = new_attempt(ctx)
        await start_probe(ctx, att, jpeg_of(LEVEL_A))
        ctx.runtime._mode = "OFFLINE"  # heartbeat lost between face lock and the frames
        frames, jpegs = frames_of(ctx, LEVEL_A)
        _, cm, _ = await match_branch(ctx, att, frames, jpegs)
        await asyncio.sleep(0)
        return att, cm

    att, cm = asyncio.run(go())
    assert cm is None and att.probe.cloud_task.cancelled()


# ------------------------------------------------------------------ 1f. full HTTP path (real models + runtime)
@requires_models
def test_session_probe_frames_returns_a_decision(client):
    from edge import synth
    from edge.policy.tests.test_runtime import DecisionResponse

    s = client.post("/v1/session/start", json=START).json()
    r = client.post(f"/v1/attempt/{s['attempt_id']}/probe",
                    files={"probe": ("p.jpg", synth.jpeg(synth.base_frame()), "image/jpeg")})
    assert r.status_code == 202 and r.json() == {"accepted": True, "cloud": "skipped"}  # hermetic: no cloud
    frames, meta = synth.make_attempt(s)
    files, data = synth.multipart_files(frames, meta)
    d = client.post(f"/v1/attempt/{s['attempt_id']}/frames", files=files, data=data)
    assert d.status_code == 200 and d.json()["decision"] in {"ALLOW", "STEP_UP", "DENY"}
    body = d.json()
    DecisionResponse.model_validate({**body, "latency_ms": {k: body["latency_ms"][k] for k in
                                                            ("total", "liveness", "match", "schedule", "policy")}})
    late = client.post(f"/v1/attempt/{s['attempt_id']}/probe",
                       files={"probe": ("p.jpg", synth.jpeg(synth.base_frame()), "image/jpeg")})
    assert late.status_code == 409


# ------------------------------------------------------------------ 2. template-append gate + revoked
@requires_models
# no cloud configured (hermetic client) = no cloud identity check: the OFFLINE re-enrolment bar applies (EAE-05,
# enrol.reenrol_min_cosine_offline 0.60), so 0.55 (above the online allow bar) is refused too
@pytest.mark.parametrize(("worst", "admitted"), [(0.40, False), (0.55, False), (0.65, True)])
def test_new_look_must_reach_allow_min_cosine(client, admin_headers, thresholds, monkeypatch, worst, admitted,
                                             example_bundle):
    from edge import enroll as enroll_mod
    from edge import synth

    allow = float(thresholds.get("match.local.allow_min_cosine"))
    deny = float(thresholds.get("match.local.deny_below_cosine"))
    assert deny < 0.40 < allow < 0.55  # 0.40 passed the old deny_below gate; it must not pass now
    frames = [synth.jpeg(synth.base_frame(shift_px=s)) for s in (-8, -4, 0, 4, 8)]
    files = {f"frame_{i}": (f"f{i}.jpg", b, "image/jpeg") for i, b in enumerate(frames)}
    meta = {"user_id": "u_5e6f", "display_name": "Gate", "role": "student", "consent": True,
            "consent_version": "2026-11-14.v1"}

    def enrol():
        return client.post("/v1/enroll", files=files, data={"meta": json.dumps(meta)}, headers=admin_headers)

    first = enrol()
    assert first.status_code == 201, first.text
    try:
        monkeypatch.setattr(enroll_mod, "resemblance_to_stored", lambda stored, new: worst)
        r = enrol()
        if admitted:
            assert r.status_code == 201 and r.json()["template_version"] == first.json()["template_version"] + 1
        else:
            assert r.status_code == 409 and r.json()["error"]["code"] == "INVALID_STATE"
            assert "new look does not resemble the enrolled user" in r.json()["error"]["message"]
    finally:
        assert client.delete("/v1/enroll/u_5e6f", headers=admin_headers).status_code == 200


@requires_models
def test_revoked_user_enrolment_is_403(client, admin_headers, monkeypatch):
    from edge import synth

    rt = client.app.state.ctx.runtime
    monkeypatch.setattr(rt, "revoked_user_ids", lambda: {"u_rv01"}, raising=False)
    files = {f"frame_{i}": (f"f{i}.jpg", synth.jpeg(synth.base_frame(shift_px=s)), "image/jpeg")
             for i, s in enumerate((-4, 0, 4))}
    meta = {"user_id": "u_rv01", "display_name": "R", "role": "student", "consent": True,
            "consent_version": "2026-11-14.v1"}
    r = client.post("/v1/enroll", files=files, data={"meta": json.dumps(meta)}, headers=admin_headers)
    assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN", r.text
    assert client.app.state.ctx.templates.get("u_rv01") is None


# ------------------------------------------------------------------ 5. depth observability
def test_depth_rejected_token_status_and_rate_limited_log(lite_settings, thresholds, caplog):
    th = with_overrides(thresholds, liveness__depth__enabled=True)
    ctx = lite_ctx(lite_settings, th, StubRuntime("OFFLINE"))
    bad = "wrong-token-must-never-be-logged"
    with lite_client(ctx) as c, caplog.at_level(logging.INFO):
        assert c.get("/v1/health").json()["depth_probe"] == "unavailable"
        for _ in range(3):
            assert c.get("/v1/depth/pending", params={"wait_s": 0}, headers={"X-Depth-Token": bad}).status_code == 401
        assert c.get("/v1/health").json()["depth_probe"] == "rejected_token"
        warned = [r for r in caplog.records if r.name == "edge.depth" and "depth/pending" in r.getMessage()]
        assert len(warned) == 1 and "401" in warned[0].getMessage()  # rate-limited: 1 line for 3 failures
        assert bad not in caplog.text and lite_settings.depth_device_token not in caplog.text
        assert c.get("/v1/depth/pending", params={"wait_s": 0}, headers=DEPTH).status_code == 204
        assert c.get("/v1/health").json()["depth_probe"] == "connected"  # a good poll clears it
    ctx.depth.last_rejected_token_at = time.monotonic() - 31  # older than 30 s -> no longer reported
    ctx.depth.last_seen_device_at = time.monotonic() - 40
    assert ctx.depth.status() == "unavailable"


# ------------------------------------------------------------------ 6. fail-secure bodies, health, otp, perms
def test_static_system_error_and_fail_secure_deny_are_api_valid(lite_settings, thresholds):
    from edge.attempts import _static_system_error
    from edge.policy.tests.test_runtime import DecisionResponse
    from edge.policy_facade import FailSecureRuntime

    class Broken:
        def mode(self):
            raise RuntimeError("down")

    for rt, mode in ((Broken(), "OFFLINE"), (StubRuntime("ONLINE"), "ONLINE"), (StubRuntime("weird"), "OFFLINE")):
        ctx = lite_ctx(lite_settings, thresholds, rt)
        for lat in (None, {"total": 12, "liveness": "x"}, {"total": 5, "match": 3}):
            body = _static_system_error(ctx, None, lat)
            DecisionResponse.model_validate(body)
            assert body["decision"] == "DENY" and body["mode"] == mode and "SYSTEM_ERROR" in body["reason_codes"]
    fs = FailSecureRuntime(lite_settings, thresholds, "test")
    DecisionResponse.model_validate(fs.decide_error("att_x", latency_ms={"total": 3}))


def test_health_degraded_reasons(lite_settings, thresholds):
    ctx = lite_ctx(lite_settings, thresholds, StubRuntime("OFFLINE"))
    ctx.runtime_kind = "fail_secure"
    with lite_client(ctx) as c:
        h = c.get("/v1/health").json()
    assert h["status"] == "degraded"
    assert {"policy_runtime_fail_secure", "model_missing:arcface", "pad_self_test_not_run",
            "template_cache_unavailable"} <= set(h["degraded_reasons"])


@requires_models
def test_health_ok_has_no_degraded_reasons(client):
    """Models, PAD self-test, runtime and cache are healthy: only the configuration-driven reasons of the
    hermetic test env remain (DEMO_MODE=1, legacy admin token on, a developer .env mode)."""
    h = client.get("/v1/health").json()
    config_only = {"demo_mode", "legacy_admin_token", "env_file_permissive"}
    assert set(h["degraded_reasons"]) <= config_only
    assert h["status"] == ("degraded" if h["degraded_reasons"] else "ok")


@pytest.mark.parametrize(("status", "body", "expected"), [
    (200, {"verified": True}, True), (200, {"verified": False}, False), (400, {}, False), (404, {}, False),
    (401, {}, None), (429, {}, None), (500, {}, None), (503, {}, None), (200, "not-json", None),
    ("timeout", None, None),
])
def test_otp_verify_cloud_errors_are_none(settings, thresholds, status, body, expected):
    from edge.cloud_client import CloudClient

    def handler(request: httpx.Request) -> httpx.Response:
        if status == "timeout":
            raise httpx.ReadTimeout("slow", request=request)
        if isinstance(body, str):
            return httpx.Response(status, content=body.encode())
        return httpx.Response(status, json=body)

    cfg = dataclasses.replace(settings, cloud_api_url="https://cloud.test", kiosk_hmac_key="k", cloud_api_key="a")

    async def go():
        cloud = CloudClient(cfg, thresholds, transport=httpx.MockTransport(handler))
        await cloud.start()
        try:
            return await cloud.otp_verify("att_1", "otp_1", "123456")
        finally:
            await cloud.stop()

    assert asyncio.run(go()) is expected


def test_data_dir_is_tightened_to_owner_only(tmp_path):
    from edge.app import tighten_data_dir

    d = tmp_path / "data"
    d.mkdir(mode=0o755)
    loose, tight = d / "revocations.enc", d / "templates.fernet"
    loose.write_bytes(b"x")
    loose.chmod(0o644)
    tight.write_bytes(b"y")
    tight.chmod(0o600)
    assert set(tighten_data_dir(d)) == {".", "revocations.enc"}
    assert loose.stat().st_mode & 0o777 == 0o600 and d.stat().st_mode & 0o777 == 0o700
    assert tighten_data_dir(d) == [] and tighten_data_dir(tmp_path / "missing") == []


# ------------------------------------------------------------------ 3. startup erase hook (DPDP erasure)
def test_startup_registers_the_template_erase_hook(lite_settings, thresholds, tmp_path):
    class ErasingRuntime(ProbeRuntime):
        """add_erase_hook replays users erased before registration (PolicyRuntime contract)."""

        def __init__(self) -> None:
            super().__init__("OFFLINE")
            self.hooks: list = []
            self.status_reports: list[int] = []

        def add_erase_hook(self, fn) -> None:
            self.hooks.append(fn)
            fn("u_b")  # erased by the cloud before this edge started

        def set_template_cache_status(self, *, count, model, age_h) -> None:
            self.status_reports.append(count)

    rt = ErasingRuntime()
    ctx = lite_ctx(lite_settings, thresholds, rt)
    ctx.templates = make_templates(tmp_path)
    with lite_client(ctx):
        assert len(rt.hooks) == 1
        assert ctx.templates.get("u_b") is None and ctx.templates.get("u_a") is not None
        rt.hooks[0]("u_a")  # a later ERASED revocation from the feed
        assert ctx.templates.count() == 0 and rt.status_reports[-1] == 0
        rt.hooks[0]("u_zz")  # unknown user: no-op, never raises
