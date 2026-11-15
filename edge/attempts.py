"""Attempt orchestration: frames -> perception signals (liveness || match || cloud || depth) ->
AttemptSignals -> PolicyRuntime.decide. The policy decides; this module only measures + times.
"""

from __future__ import annotations

import asyncio
import json
import logging
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import numpy as np

from edge.cloud_client import CloudClient
from edge.config import Settings, Thresholds
from edge.depth_bridge import DepthBridge, challenge_capture_timing
from edge.errors import ApiError
from edge.events import EventBus
from edge.metrics import MetricsStore
from edge.ml.device import DeviceSignal
from edge.ml.flash import Event, FlashAnalysis, Step, flash_signal
from edge.ml.mask import MaskRingSignal
from edge.ml.matcher import MatchScore, best_cosine, search
from edge.ml.moire import MoireSignal
from edge.ml.pad import PadFrameScore
from edge.ml.templates import TemplateStore
from edge.perception import MAX_JPEG_SIDE_PX, FrameAnalysis, PerceptionEngine, decode_jpeg
from edge.policy.signals import (
    AttemptSignals,
    CameraMeta,
    ChallengeEvidence,
    CloudMatch,
    DepthSignal,
    FallbackSubmission,
    FrameSignals,
)
from edge.policy_facade import EMPTY_SCORES, LATENCY_KEYS, AttemptClosedError, AttemptNotFoundError
from edge.schemas import ChallengeMeta, FallbackRequest, FramesMeta
from edge.session import Attempt, AttemptStore

log = logging.getLogger("edge.attempts")
T0_PAST_TOLERANCE_S = 30.0  # face lock may precede session/start; older/future t0 -> server time
T0_FUTURE_TOLERANCE_S = 2.0


@dataclass
class EdgeContext:
    settings: Settings
    thresholds: Thresholds
    engine: PerceptionEngine
    runtime: Any
    runtime_kind: str
    sessions: AttemptStore
    events: EventBus
    metrics: MetricsStore
    cloud: CloudClient
    depth: DepthBridge
    templates: TemplateStore | None
    pool: ThreadPoolExecutor
    started_monotonic: float
    eval_context: dict[str, Any] | None = None  # POST/DELETE /v1/admin/eval/context
    eval_context_since: str | None = None
    lan_server: Any = None
    lan_status: str = "disabled"


def _ms(t: float) -> int:
    return round((time.perf_counter() - t) * 1000)


def now_epoch_ms() -> int:
    return int(time.time() * 1000)


def resolve_t0(att: Attempt, face_lock_at_ms: int, now: datetime) -> datetime:
    """Face-lock time from the kiosk clock (same host), bounded by server time (fail-secure)."""
    try:
        t = datetime.fromtimestamp(face_lock_at_ms / 1000.0, tz=UTC)
    except (OverflowError, OSError, ValueError):  # absurd client clock (verifier FAIL 1): never a 500
        return att.created_at
    if att.created_at - timedelta(seconds=T0_PAST_TOLERANCE_S) <= t <= now + timedelta(seconds=T0_FUTURE_TOLERANCE_S):
        return t
    return att.created_at


def _frame_interval_ms(meta: FramesMeta) -> float:
    fps = meta.client_signals.fps_measured
    if fps and 5.0 <= fps <= 120.0:
        return 1000.0 / fps
    ts = sorted(c.t_ms for c in meta.chroma_series)
    if len(ts) >= 3:
        d = float(np.median(np.diff(ts)))
        if 5.0 <= d <= 200.0:
            return d
    return 1000.0 / 30.0


def compute_flash(att: Attempt, meta: FramesMeta, frames: list[FrameAnalysis], th: Thresholds) -> FlashAnalysis:
    steps = [Step(s.color, float(s.offset_ms), float(s.duration_ms)) for s in att.flash_sequence]
    events = [Event(e.step_index, e.color, float(e.shown_at_ms)) for e in meta.flash_events]
    frame_series = [(float(f.ts_ms), *f.skin_rgb) for f in frames if f.skin_rgb is not None]
    client_series = [(c.t_ms, c.r, c.g, c.b) for c in meta.chroma_series]
    return flash_signal(
        steps, events, float(meta.capture_started_at_ms), frame_series, client_series,
        _frame_interval_ms(meta), float(th.get("liveness.flash.min_amplitude")),
        float(th.get("liveness.flash.lag_max_frames")),
    )


def select_match_frames(frames: list[FrameAnalysis]) -> list[int]:
    """First + last frame with a face (identity consistency) + the sharpest one (best score)."""
    with_face = [f.index for f in frames if f.main is not None]
    if not with_face:
        return []
    sharpest = max(with_face, key=lambda i: frames[i].quality.laplacian_var)
    return sorted({with_face[0], with_face[-1], sharpest})


async def _run(ctx: EdgeContext, fn, *args):
    return await asyncio.get_running_loop().run_in_executor(ctx.pool, fn, *args)


async def analyze_jpegs(ctx: EdgeContext, jpegs: list[bytes], ts: list[int]) -> list[FrameAnalysis]:
    def one(i: int) -> FrameAnalysis:
        img = decode_jpeg(jpegs[i])
        if img is None:
            raise ApiError("VALIDATION_ERROR", f"frame_{i} is not a decodable JPEG of at most "
                                               f"{MAX_JPEG_SIDE_PX}x{MAX_JPEG_SIDE_PX} px")
        return ctx.engine.analyze_frame(i, ts[i], img)

    return list(await asyncio.gather(*(_run(ctx, one, i) for i in range(len(jpegs)))))


async def liveness_branch(ctx: EdgeContext, att: Attempt, meta: FramesMeta, frames: list[FrameAnalysis]):
    t = time.perf_counter()
    eng = ctx.engine
    pad_f = _run(ctx, eng.pad_scores, frames)
    dev_f = asyncio.gather(*(_run(ctx, eng.device_score, f) for f in frames))
    tex_f = asyncio.gather(*(_run(ctx, eng.texture_scores, f) for f in frames))
    flash_f = _run(ctx, compute_flash, att, meta, frames, ctx.thresholds) if att.flash_enabled else None
    pads: list[PadFrameScore] = await pad_f
    try:
        devs: list[DeviceSignal | None] = list(await dev_f)
    except Exception:  # a dead device detector must not read as "no device"
        log.exception("device detector failed")
        devs = [None] * len(frames)
    tex: list[tuple[MoireSignal, MaskRingSignal]] = list(await tex_f)
    flash: FlashAnalysis | None = await flash_f if flash_f is not None else None
    if any(d is None for d, f in zip(devs, frames) if f.main is not None):
        # FrameSignals.device_conf defaults to 0.0 ("no device"); without a detector result we
        # null PAD instead so the attempt can never be auto-allowed (fail-secure).
        pads = [PadFrameScore(pad_v2=None, pad_v1se=None) for _ in frames]
    return pads, devs, tex, flash, _ms(t)


async def match_branch(ctx: EdgeContext, att: Attempt, frames: list[FrameAnalysis], jpegs: list[bytes]):
    t = time.perf_counter()
    sel = select_match_frames(frames)
    best = max(sel, key=lambda i: frames[i].quality.laplacian_var) if sel else None
    allowed = _entitled(ctx) if ctx.templates is not None else None

    async def embed_selected() -> dict[int, np.ndarray | None]:
        if ctx.templates is None:
            return {}
        embs = await asyncio.gather(*(_run(ctx, ctx.engine.embed, frames[i]) for i in sel))
        return dict(zip(sel, embs))

    emb_task = asyncio.ensure_future(embed_selected())

    async def local() -> dict[int, MatchScore]:
        embs = await asyncio.shield(emb_task)
        if ctx.templates is None:
            return {}
        gallery = ctx.templates.gallery
        return {i: search(e, gallery, allowed) for i, e in embs.items()}

    async def cloud() -> CloudMatch | None:
        # Ask the runtime first: if the next attempt is OFFLINE (heartbeat down, forced, stale bundle) or
        # Rekognition is disabled, the cloud is skipped entirely (online identity = local matcher).
        if not cloud_wanted(ctx):
            cancel_probe(att)
            return None
        if att.probe is not None and att.probe.cloud_task is not None:
            return await bind_probe(ctx, att, att.probe, emb_task, best, allowed)
        if best is None:
            return CloudMatch(ok=False)
        # Upload a small face crop (~10-25 KB), not the full 1280 px frame: over the venue/hotspot
        # uplink the full JPEG hit httpx WriteTimeout on every attempt (2026-11-14, ~1.35 s wasted).
        probe = _face_crop_jpeg(frames[best]) or jpegs[best]
        # Hard TOTAL deadline (latency_budget_ms.rekognition_timeout): httpx timeouts are per phase
        # (connect/write/read), so without this the call could exceed the budget several times over.
        try:
            cm = await asyncio.wait_for(ctx.cloud.match(att.attempt_id, probe, att.claimed_user_id),
                                        timeout=_match_deadline_s(ctx))
        except TimeoutError:
            log.info("cloud match exceeded the %.0f ms budget -> attempt OFFLINE (P7)",
                     _match_deadline_s(ctx) * 1000)
            cm = CloudMatch(ok=False)
        # No record_cloud_result here: runtime.decide() records the miss/success itself (P7);
        # recording it here too double-counted every miss and flipped the kiosk OFFLINE early.
        return cm

    try:
        local_scores, cloud_match = await asyncio.gather(local(), cloud())
    finally:
        if not emb_task.done():
            emb_task.cancel()
    return local_scores, cloud_match, _ms(t)


def cloud_wanted(ctx: EdgeContext) -> bool:
    """True when this attempt will call Rekognition: cloud configured, the runtime's NEXT attempt mode is
    ONLINE and match.rekognition.enabled. Never raises (a broken runtime -> False -> no cloud call)."""
    try:
        return (ctx.cloud.enabled and str(_safe_call(ctx.runtime, "mode")) == "ONLINE"
                and bool(ctx.thresholds.get("match.rekognition.enabled")))
    except Exception:
        log.exception("cloud_wanted check failed")
        return False


# ---------------------------------------------------------------------------------- early cloud probe
@dataclass
class ProbeState:
    """The face-lock probe of one attempt (POST /v1/attempt/{id}/probe). Never holds image bytes after the
    upload; the embedding stays in RAM until the attempt is decided and is never exported."""

    started: float  # time.monotonic() when the cloud match was started (the deadline counts from here)
    deadline_s: float  # latency_budget_ms.rekognition_probe_deadline
    cloud_task: asyncio.Task | None  # -> CloudMatch; never raises (see _probe_cloud)
    local_task: asyncio.Future | None  # -> np.ndarray | None (probe ArcFace embedding)
    outcome: dict[str, Any]  # admin debug record (no embeddings)


def _probe_deadline_s(ctx: EdgeContext) -> float:
    """latency_budget_ms.rekognition_probe_deadline (measured FROM PROBE START). Until that YAML key exists
    the probe falls back to latency_budget_ms.rekognition_timeout (stricter, still YAML-sourced)."""
    v = ctx.thresholds.get("latency_budget_ms.rekognition_probe_deadline", None)
    if v is None:
        v = ctx.thresholds.get("latency_budget_ms.rekognition_timeout")
    return float(v) / 1000.0


async def _probe_cloud(ctx: EdgeContext, att: Attempt, crop: bytes, deadline_s: float) -> CloudMatch:
    """The probe's cloud match with its own TOTAL deadline, so an unused probe never outlives its budget.
    Never raises: any failure is CloudMatch(ok=False)."""
    t = time.perf_counter()
    status = "ok"
    try:
        cm = await asyncio.wait_for(
            ctx.cloud.match(att.attempt_id, crop, att.claimed_user_id, timeout_s=deadline_s), timeout=deadline_s)
    except TimeoutError:
        status, cm = "deadline", CloudMatch(ok=False)
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("cloud probe failed for %s", att.attempt_id)
        status, cm = "error", CloudMatch(ok=False)
    if status == "ok" and not cm.ok:
        status = "cloud_failed"
    log.info(json.dumps({"event": "cloud_probe", "attempt_id": att.attempt_id, "status": status,
                         "latency_ms": _ms(t)}))
    return cm


def cancel_probe(att: Attempt) -> None:
    probe = att.probe
    if probe is not None and probe.cloud_task is not None and not probe.cloud_task.done():
        probe.cloud_task.cancel()


async def start_probe(ctx: EdgeContext, att: Attempt, jpeg: bytes) -> dict[str, Any]:
    """POST /v1/attempt/{id}/probe: start the cloud match on the face-lock frame, in parallel with the
    kiosk's flash capture. Returns {"accepted": True, "cloud": "started" | "skipped"}.

    Skipped (nothing started, the frames use the normal path): the attempt will not call the cloud, the probe
    shows no face, or the frames arrived meanwhile. Not a JPEG / > 4096 px -> 422. Never an HTTP 500."""
    t = time.perf_counter()

    def skipped(why: str) -> dict[str, Any]:
        att.probe = ProbeState(started=time.monotonic(), deadline_s=0.0, cloud_task=None, local_task=None,
                               outcome={"cloud": "skipped", "why": why})
        log.info(json.dumps({"event": "probe", "attempt_id": att.attempt_id, "cloud": "skipped", "why": why,
                             "latency_ms": _ms(t)}))
        return {"accepted": True, "cloud": "skipped"}

    if not cloud_wanted(ctx):
        return skipped("no_cloud_this_attempt")

    def prepare() -> tuple[FrameAnalysis, bytes | None] | None:
        img = decode_jpeg(jpeg)
        if img is None:
            return None
        fa = ctx.engine.analyze_frame(0, now_epoch_ms(), img)
        return fa, _face_crop_jpeg(fa)

    try:
        prepared = await _run(ctx, prepare)
    except Exception:
        log.exception("probe face detection failed for %s", att.attempt_id)
        return skipped("detector_error")
    if prepared is None:
        raise ApiError("VALIDATION_ERROR", f"probe is not a decodable JPEG of at most "
                                           f"{MAX_JPEG_SIDE_PX}x{MAX_JPEG_SIDE_PX} px", att.attempt_id)
    fa, crop = prepared
    if crop is None:
        return skipped("no_face")
    if att.nonce_used:  # the frames overtook the probe: their own cloud call is already running
        return skipped("frames_first")
    deadline = _probe_deadline_s(ctx)
    started = time.monotonic()
    cloud_task = asyncio.create_task(_probe_cloud(ctx, att, crop, deadline), name=f"probe-{att.attempt_id}")
    local_task = asyncio.ensure_future(_run(ctx, ctx.engine.embed, fa))
    att.probe = ProbeState(started=started, deadline_s=deadline, cloud_task=cloud_task, local_task=local_task,
                           outcome={"cloud": "started", "crop_bytes": len(crop), "deadline_ms": round(deadline * 1000)})
    log.info(json.dumps({"event": "probe", "attempt_id": att.attempt_id, "cloud": "started",
                         "crop_bytes": len(crop), "latency_ms": _ms(t)}))
    return {"accepted": True, "cloud": "started"}


async def bind_probe(ctx: EdgeContext, att: Attempt, probe: ProbeState, frame_embs: asyncio.Future,
                     best: int | None, allowed: set[str] | None) -> CloudMatch:
    """Use the probe's cloud result only if it is provably the same person as the uploaded frames:
    probe local top-1 user == best frame local top-1 user AND cosine(probe, best frame) >=
    match.local.allow_min_cosine. Deadline = rekognition_probe_deadline - time since probe start (>= 0).
    Anything else -> CloudMatch(ok=False): the attempt is decided OFFLINE (P7, fail-secure)."""
    t = time.perf_counter()
    remaining = max(0.0, probe.deadline_s - (time.monotonic() - probe.started))
    task = probe.cloud_task

    async def cloud_result() -> CloudMatch | None:
        try:
            return await asyncio.wait_for(asyncio.shield(task), timeout=remaining)
        except TimeoutError:
            task.cancel()
            return None
        except Exception:  # noqa: BLE001 - _probe_cloud never raises; belt and braces
            return None

    async def probe_emb() -> np.ndarray | None:
        try:
            return await probe.local_task if probe.local_task is not None else None
        except Exception:
            log.exception("probe embedding failed for %s", att.attempt_id)
            return None

    async def best_emb() -> np.ndarray | None:
        try:
            return (await asyncio.shield(frame_embs)).get(best) if best is not None else None
        except Exception:  # noqa: BLE001 - the local branch reports the same failure itself
            return None

    cm, p_emb, f_emb = await asyncio.gather(cloud_result(), probe_emb(), best_emb())
    out = probe.outcome
    out.update({"waited_ms": _ms(t), "remaining_ms_at_frames": round(remaining * 1000)})
    binding, cos = identity_binding(ctx, p_emb, f_emb, allowed)
    out.update({"binding": binding, "cosine": cos})
    if cm is None:
        out["used"], result = False, CloudMatch(ok=False)
        out["why"] = "deadline"
    elif not cm.ok:
        out["used"], result = False, cm
        out["why"] = "cloud_failed"
    elif binding != "ok":
        out["used"], result = False, CloudMatch(ok=False)
        out["why"] = f"identity_binding_{binding}"
    else:
        out["used"], result = True, cm
    log.info(json.dumps({"event": "probe_bind", "attempt_id": att.attempt_id, "used": out["used"],
                         "binding": binding, "cosine": cos, "why": out.get("why"),
                         "remaining_ms": round(remaining * 1000), "latency_ms": out["waited_ms"]}))
    return result


def identity_binding(ctx: EdgeContext, p_emb: np.ndarray | None, f_emb: np.ndarray | None,
                     allowed: set[str] | None) -> tuple[str, float | None]:
    """("ok" | "no_templates" | "no_embedding" | "no_local_match" | "user_mismatch" | "low_cosine", cosine)."""
    if ctx.templates is None:
        return "no_templates", None
    if p_emb is None or f_emb is None:
        return "no_embedding", None
    pn = p_emb / (np.linalg.norm(p_emb) + 1e-9)
    fn = f_emb / (np.linalg.norm(f_emb) + 1e-9)
    cos = round(float(pn.astype(np.float32) @ fn.astype(np.float32)), 4)
    gallery = ctx.templates.gallery
    p_top, f_top = search(p_emb, gallery, allowed).top1_user, search(f_emb, gallery, allowed).top1_user
    if p_top is None or f_top is None:
        return "no_local_match", cos
    if p_top != f_top:
        return "user_mismatch", cos
    if not cos >= float(ctx.thresholds.get("match.local.allow_min_cosine")):  # NaN -> not bound
        return "low_cosine", cos
    return "ok", cos


def warm_cloud_match(ctx: EdgeContext, mode: str) -> bool:
    """session/start: pre-open the match client's keep-alive connection when this attempt will call
    Rekognition (same conditions as match_branch.cloud). Fire-and-forget: never awaited, never raises."""
    try:
        if mode != "ONLINE" or not ctx.cloud.enabled or not bool(ctx.thresholds.get("match.rekognition.enabled")):
            return False  # same conditions as cloud_wanted(), with the mode already read by session/start
        warm = getattr(ctx.cloud, "warm_up", None)
        return bool(warm()) if callable(warm) else False
    except Exception:  # the warm-up must never fail an attempt
        log.exception("cloud warm-up not started")
        return False


def register_erase_hook(ctx: EdgeContext) -> bool:
    """DPDP erasure: an ERASED revocation (bundle or feed) also deletes the user's local face templates.
    The runtime replays erasures applied before registration. No-op for the fail-secure runtime."""
    add = getattr(ctx.runtime, "add_erase_hook", None)
    templates = ctx.templates
    if not callable(add) or templates is None:
        return False

    def erase(user_id: str) -> None:
        if templates.delete(user_id):
            log.info("ERASED revocation: local face templates deleted (%d users left)", templates.count())
            report_template_cache(ctx)

    add(erase)
    return True


def _match_deadline_s(ctx: EdgeContext) -> float:
    """Total budget for the cloud match = latency_budget_ms.rekognition_timeout (YAML)."""
    v = getattr(ctx.cloud, "match_timeout_s", None)
    return float(v) if v else float(ctx.thresholds.get("latency_budget_ms.rekognition_timeout")) / 1000.0


def _face_crop_jpeg(fa: FrameAnalysis, *, margin: float = 0.6, max_side: int = 320,
                    quality: int = 85) -> bytes | None:
    """JPEG of the main face with `margin` x box padding, longest side <= max_side px (None if no face).

    Rekognition needs >= 40 px faces; a 320 px crop keeps the face at ~200 px. Only this crop leaves
    the kiosk for the cloud match (data minimisation), never the full frame.
    """
    import cv2  # local import: cv2 is already loaded by perception; keeps module import light

    face = fa.main
    if face is None or fa.bgr is None:
        return None
    h, w = fa.bgr.shape[:2]
    bw, bh = face.x2 - face.x1, face.y2 - face.y1
    x1 = int(max(0, face.x1 - margin * bw)); y1 = int(max(0, face.y1 - margin * bh))
    x2 = int(min(w, face.x2 + margin * bw)); y2 = int(min(h, face.y2 + margin * bh))
    if x2 - x1 < 40 or y2 - y1 < 40:
        return None
    crop = fa.bgr[y1:y2, x1:x2]
    scale = min(1.0, max_side / max(crop.shape[:2]))
    if scale < 1.0:
        crop = cv2.resize(crop, (int(crop.shape[1] * scale), int(crop.shape[0] * scale)),
                          interpolation=cv2.INTER_AREA)
    ok, buf = cv2.imencode(".jpg", crop, [int(cv2.IMWRITE_JPEG_QUALITY), quality])
    return buf.tobytes() if ok else None


def _entitled(ctx: EdgeContext) -> set[str] | None:
    """Gallery filter = users entitled at this kiosk's zone (runtime.entitled_user_ids(): verified bundle
    + revocation feed). Revoked / unentitled users are never a match candidate.

    No last valid bundle (LVB) at all: the cache is searched unfiltered, only so the identity result
    is honest; DECISION_POLICY §9.5 I1a/I2a then DENY SCHEDULE_BUNDLE_INVALID + CONTACT_DESK anyway (no
    zone, no verified override list). LVB present (incl. the clock-rollback case I1b/I2b, STEP_UP staff
    override only): filtered as usual. A runtime that cannot answer -> empty set (no candidate, fail-secure).
    """
    bundles = getattr(ctx.runtime, "bundles", None)
    if bundles is not None and getattr(bundles, "lvb", None) is None:
        return None
    ids = _safe_call(ctx.runtime, "entitled_user_ids")
    return set(ids) if ids is not None else set()


def _safe_call(obj: Any, name: str, *args, **kw):
    fn = getattr(obj, name, None)
    if not callable(fn):
        return None
    try:
        return fn(*args, **kw)
    except Exception:  # optional facade calls must not break an attempt
        log.exception("runtime.%s failed", name)
        return None


def report_template_cache(ctx: EdgeContext) -> None:
    """PolicyRuntime.set_template_cache_status (GET /v1/mode TemplateCacheStatus): at startup and
    after every enrolment / erasure."""
    if ctx.templates is None:
        _safe_call(ctx.runtime, "set_template_cache_status", count=0, model="unavailable", age_h=None)
        return
    s = ctx.templates.summary()
    _safe_call(ctx.runtime, "set_template_cache_status", count=s["count"], model=s["model"], age_h=s["age_h"])


async def depth_branch(ctx: EdgeContext, att: Attempt) -> DepthSignal | None:
    if not ctx.depth.enabled:
        return None
    received = att.frames_received_at or datetime.now(UTC)
    elapsed_ms = (datetime.now(UTC) - received).total_seconds() * 1000.0
    return await ctx.depth.wait_for(att.attempt_id, "PASSIVE", (ctx.depth.max_wait_ms - elapsed_ms) / 1000.0)


def build_frame_signals(frames, pads, devs, tex, matches) -> list[FrameSignals]:
    out = []
    for f, p, d, (mo, mk) in zip(frames, pads, devs, tex):
        m = matches.get(f.index)
        out.append(
            FrameSignals(
                index=f.index, ts_ms=f.ts_ms, quality=f.quality, pad_v2=p.pad_v2, pad_v1se=p.pad_v1se,
                device_conf=d.device_conf if d else 0.0,
                device_face_containment=d.device_face_containment if d else 0.0,
                moire=mo.moire, mask_edge_ring=mk.mask_edge_ring,
                match_top1_user=m.top1_user if m else None, match_top1=m.top1 if m else None,
                match_top2=m.top2 if m else None,
            )
        )
    return out


def merge_latency(resp: dict[str, Any], measured: dict[str, int]) -> dict[str, Any]:
    """Keep the runtime's own `policy`/`schedule`; `total` = the larger (never under-report)."""
    lat = dict(resp.get("latency_ms") or {})
    for k, v in measured.items():
        if k in {"policy", "schedule"} and k in lat:
            continue
        lat[k] = max(int(lat.get(k, 0) or 0), int(v)) if k == "total" else v
    resp["latency_ms"] = lat
    return resp


def finish(ctx: EdgeContext, att: Attempt, resp: dict[str, Any], *, kind: str) -> dict[str, Any]:
    att.last_response = resp
    cand = (resp.get("candidate") or {}).get("user_id") if isinstance(resp.get("candidate"), dict) else None
    if cand:
        att.candidate_user_id = cand
    ctx.metrics.record(resp, att.eval_label, kind=kind)
    ctx.events.publish("decision", {**resp, "eval": att.eval_tags})
    log.info(json.dumps({
        "ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"), "event": f"decision_{kind}",
        "attempt_id": att.attempt_id, "decision": resp.get("decision"), "mode": resp.get("mode"),
        "reason_codes": resp.get("reason_codes"), "latency_ms": resp.get("latency_ms"),
        "policy_version": resp.get("policy_version"), "policy_runtime": ctx.runtime_kind,
        "eval": att.eval_tags,
    }))
    return resp


def _policy_version(ctx: EdgeContext) -> str:
    pv = getattr(ctx.thresholds, "policy_version", "unknown")
    return str(pv() if callable(pv) else pv)


def _static_system_error(ctx: EdgeContext, attempt_id: str | None, latency_ms: dict[str, Any] | None) -> dict[str, Any]:
    """Last-resort DENY SYSTEM_ERROR (P1) when the policy runtime itself raised. Never ALLOW.
    API.md v1.1 DecisionResponse-valid: every latency key an int, every scores key present (null)."""
    try:
        mode = str(ctx.runtime.mode())
    except Exception:  # noqa: BLE001 - runtime is already broken; assume the stricter mode
        mode = "OFFLINE"
    mode = mode if mode in {"ONLINE", "OFFLINE"} else "OFFLINE"
    codes = ["SYSTEM_ERROR"] + (["OFFLINE_MODE"] if mode == "OFFLINE" else [])
    lat_in = latency_ms or {}
    lat = {}
    for k in LATENCY_KEYS:
        try:
            lat[k] = int(lat_in.get(k, 0) or 0)
        except (TypeError, ValueError):
            lat[k] = 0
    return {
        "attempt_id": attempt_id or "", "kiosk_id": ctx.settings.kiosk_id, "zone": "UNKNOWN",
        "decision": "DENY", "reason_codes": codes, "resolved_codes": [],
        "next_action": {"type": "CONTACT_DESK", "steps": [], "methods": None, "challenge": None,
                        "attempts_left": None, "retry_after_s": None, "hint": None},
        "bio_result": None, "schedule_result": None, "mode": mode, "cache_state": None, "candidate": None,
        "scores": dict(EMPTY_SCORES), "latency_ms": lat,
        "policy_version": _policy_version(ctx), "bundle_version": None,
        "display_message": "Access check unavailable - please contact the desk", "stage": "system",
    }


async def _decide(ctx: EdgeContext, fn, *args, **kw) -> dict[str, Any]:
    """Runtime call with the HTTP mapping of its contract exceptions.

    Fail-secure (DECISION_POLICY P1): any other exception raised by the policy runtime becomes
    DENY SYSTEM_ERROR via runtime.decide_error (which logs the minimal record), or a static
    DENY if that fails too -- never an HTTP 500 and never a fall-through ALLOW.
    """
    try:
        return await _run(ctx, lambda: fn(*args, **kw))
    except AttemptClosedError as exc:
        raise ApiError("ATTEMPT_CLOSED", "attempt already reached a terminal decision", str(exc)) from exc
    except AttemptNotFoundError as exc:  # the edge knows the attempt; the runtime has no open step-up
        raise ApiError("INVALID_STATE", "no step-up pending for this attempt", str(exc)) from exc
    except ApiError:
        raise
    except Exception as exc:
        first = args[0] if args else None
        attempt_id = first if isinstance(first, str) else getattr(first, "attempt_id", None)
        log.exception("policy runtime %s failed for %s", getattr(fn, "__name__", fn), attempt_id)
        detail = f"policy: {type(exc).__name__}"
        if getattr(fn, "__name__", "") != "decide_error":
            try:
                return await _run(ctx, lambda: ctx.runtime.decide_error(
                    attempt_id, detail=detail, latency_ms=kw.get("latency_ms")))
            except Exception:
                log.exception("runtime.decide_error also failed for %s", attempt_id)
        return _static_system_error(ctx, attempt_id, kw.get("latency_ms"))


async def process_frames(ctx: EdgeContext, att: Attempt, jpegs: list[bytes], meta: FramesMeta) -> dict[str, Any]:
    t_total = time.perf_counter()
    now = att.frames_received_at or datetime.now(UTC)
    att.face_lock_at_ms = meta.face_lock_at_ms
    try:
        frames = await analyze_jpegs(ctx, jpegs, meta.frame_timestamps_ms)
        q_ms = _ms(t_total)
        (pads, devs, tex, flash, live_ms), (matches, cloud_match, match_ms), depth = await asyncio.gather(
            liveness_branch(ctx, att, meta, frames), match_branch(ctx, att, frames, jpegs), depth_branch(ctx, att)
        )
    except ApiError:
        raise
    except Exception as exc:
        log.exception("perception failed for %s", att.attempt_id)
        resp = await _decide(ctx, ctx.runtime.decide_error, att.attempt_id, detail=f"perception: {type(exc).__name__}",
                             latency_ms={"total": _ms(t_total)})
        return finish(ctx, att, resp, kind="frames")
    label_now = meta.client_signals.camera_label or att.camera_label
    signals = AttemptSignals(
        attempt_id=att.attempt_id,
        kiosk_id=att.kiosk_id,
        t0=resolve_t0(att, meta.face_lock_at_ms, now),
        recapture_count=att.recapture_count,
        frames=build_frame_signals(frames, pads, devs, tex, matches),
        camera=CameraMeta(
            camera_label=label_now,
            frame_timestamps_ms=list(meta.frame_timestamps_ms),
            virtual_camera_suspected=bool(meta.client_signals.virtual_camera_suspected)
            or (bool(att.camera_label) and bool(label_now) and label_now != att.camera_label),
        ),
        flash=flash.signal if flash else None,
        flash_enabled=att.flash_enabled,
        depth=depth,
        cloud_match=cloud_match,
        template_cache_age_h=ctx.templates.age_hours() if ctx.templates else None,
    )
    t_pol = time.perf_counter()
    pre = {"quality": q_ms, "liveness": live_ms, "match": match_ms, "total": _ms(t_total)}
    resp = await _decide(ctx, ctx.runtime.decide, signals, latency_ms=pre)
    pol_ms = _ms(t_pol)
    if not resp.get("candidate"):
        best = [m for m in matches.values() if m.top1_user]
        if best:
            att.candidate_user_id = max(best, key=lambda m: m.top1 or -1).top1_user
    resp = merge_latency(resp, {
        "quality": q_ms, "liveness": live_ms, "match": match_ms, "policy": pol_ms,
        "total": _ms(t_total), "face_lock_to_decision_server": max(0, now_epoch_ms() - meta.face_lock_at_ms),
    })
    att.signals_debug = {"signals": signals.model_dump(mode="json"),
                         "raw": {**_debug(frames, pads, devs, tex, flash, matches, cloud_match, depth),
                                 "probe": att.probe.outcome if att.probe is not None else None}}
    finish(ctx, att, resp, kind="frames")
    await queue_challenge_depth(ctx, att, resp)
    return resp


async def queue_challenge_depth(ctx: EdgeContext, att: Attempt, resp: dict[str, Any]) -> None:
    """When a CHALLENGE is (re-)issued, ask DepthProbe for 3 frames aimed at the deformation step."""
    nxt = resp.get("next_action") or {}
    ch = nxt.get("challenge") or {}
    if not ctx.depth.enabled or str(nxt.get("type", "")).upper() != "CHALLENGE" or not ch:
        return
    window = int(ch.get("step_window_ms") or ctx.thresholds.get("challenge.step_window_ms"))
    react = int(ch.get("min_reaction_ms") or ctx.thresholds.get("challenge.min_reaction_ms"))
    delay, interval = challenge_capture_timing(list(ch.get("actions") or []), window, react)
    await ctx.depth.request(att.attempt_id, "CHALLENGE", 0, delay_ms=delay, interval_ms=interval)


def _debug(frames, pads, devs, tex, flash, matches, cloud_match, depth) -> dict[str, Any]:
    """Admin/demo view of raw signals (no images, no embeddings)."""
    pl = [statistics.fmean([p.pad_v2, p.pad_v1se]) for p in pads if p.pad_v2 is not None and p.pad_v1se is not None]
    return {
        "faces_per_frame": [len(f.faces) for f in frames],
        "p_live": [round(v, 3) for v in pl],
        "device": [d.model_dump() if d else None for d in devs],
        "moire": [m.model_dump() for m, _ in tex],
        "mask_ring": [k.model_dump() for _, k in tex],
        "flash": flash.model_dump() if flash else None,
        "match": {str(i): m.model_dump() for i, m in matches.items()},
        "cloud_match": cloud_match.model_dump() if cloud_match else None,
        "depth": depth.model_dump() if depth else None,
    }


async def process_challenge(ctx: EdgeContext, att: Attempt, meta: ChallengeMeta, jpeg: bytes | None) -> dict:
    t = time.perf_counter()
    last_cos = None
    cand = att.candidate_user_id
    if cand is None:
        prev = _safe_call(ctx.runtime, "get_attempt", att.attempt_id) or {}
        cand = (prev.get("candidate") or {}).get("user_id") if isinstance(prev.get("candidate"), dict) else None
    if jpeg is not None and cand and ctx.templates is not None:
        try:
            frames = await analyze_jpegs(ctx, [jpeg], [now_epoch_ms()])
            emb = await _run(ctx, ctx.engine.embed, frames[0])
            last_cos = best_cosine(emb, ctx.templates.gallery, cand)
        except ApiError:
            raise  # 422 undecodable frame: nothing decided (the route releases the nonce for a retry, R-G)
        except Exception as exc:  # a perception-stage crash is DENY SYSTEM_ERROR (P1), never an HTTP 500
            log.exception("challenge perception failed for %s", att.attempt_id)
            resp = await _decide(ctx, ctx.runtime.decide_error, att.attempt_id,
                                 detail=f"challenge perception: {type(exc).__name__}")
            att.decided_challenge_nonces.add(meta.nonce)  # decided (DENY SYSTEM_ERROR): the nonce stays used
            return finish(ctx, att, merge_latency(dict(resp), {"challenge_edge": _ms(t)}), kind="challenge")
    depth = None
    if ctx.depth.enabled:
        depth = await ctx.depth.wait_for(att.attempt_id, "CHALLENGE", ctx.depth.max_wait_ms / 1000.0)
    ev = ChallengeEvidence(
        challenge_id=meta.challenge_id, nonce=meta.nonce,
        actions=list(meta.actions),
        same_track=meta.same_track, last_frame_cosine=last_cos, depth=depth,
    )
    resp = await _decide(ctx, ctx.runtime.resolve_challenge, att.attempt_id, ev)
    att.decided_challenge_nonces.add(meta.nonce)  # a decision exists from here on (R-G: no release after this)
    resp = merge_latency(dict(resp), {"challenge_edge": _ms(t)})
    att.signals_debug = {**(att.signals_debug or {}), "challenge": ev.model_dump(mode="json")}
    finish(ctx, att, resp, kind="challenge")
    await queue_challenge_depth(ctx, att, resp)  # R6 soft fail re-issues a new challenge
    return resp


async def process_fallback(ctx: EdgeContext, att: Attempt, req: FallbackRequest) -> dict:
    t = time.perf_counter()
    verified = None
    if req.method == "EMAIL_OTP" and ctx.cloud.enabled and str(_safe_call(ctx.runtime, "mode")) == "ONLINE":
        if not (req.otp_id and req.code):
            raise ApiError("VALIDATION_ERROR", "EMAIL_OTP needs otp_id and code", att.attempt_id)
        verified = await ctx.cloud.otp_verify(att.attempt_id, req.otp_id, req.code)
        if verified is None:  # R11: cloud verify timeout/error is not attack evidence
            _safe_call(ctx.runtime, "record_cloud_result", False)
            resp = await drop_method(ctx, att, "EMAIL_OTP")
            return finish(ctx, att, merge_latency(dict(resp), {"fallback_edge": _ms(t)}), kind="fallback")
    sub = FallbackSubmission(method=req.method, code=req.code, card_id=req.card_id, staff_id=req.staff_id,
                             otp_id=req.otp_id, email_otp_verified=verified)
    resp = await _decide(ctx, ctx.runtime.resolve_fallback, att.attempt_id, sub)
    resp = merge_latency(dict(resp), {"fallback_edge": _ms(t)})
    return finish(ctx, att, resp, kind="fallback")


async def drop_method(ctx: EdgeContext, att: Attempt, method: str) -> dict[str, Any]:
    """DECISION_POLICY R11 via PolicyRuntime.drop_method: the same STEP_UP without `method`, nothing
    counted, attempts_left unchanged. If `method` was the only one left (ValueError) the step-up is
    left open untouched and the kiosk gets 503 CLOUD_UNAVAILABLE (retry later or call staff)."""
    fn = getattr(ctx.runtime, "drop_method", None)
    if not callable(fn):
        raise ApiError("CLOUD_UNAVAILABLE", f"{method} unavailable and the policy runtime cannot drop it",
                       att.attempt_id)
    try:
        return await _run(ctx, lambda: fn(att.attempt_id, method))
    except ValueError as exc:
        raise ApiError("CLOUD_UNAVAILABLE", f"{method} verification unavailable and it is the only method left",
                       att.attempt_id) from exc
    except AttemptClosedError as exc:
        raise ApiError("ATTEMPT_CLOSED", "attempt already reached a terminal decision", att.attempt_id) from exc
    except AttemptNotFoundError as exc:
        raise ApiError("INVALID_STATE", "no step-up pending for this attempt", att.attempt_id) from exc
