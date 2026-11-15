"""HID kiosk local edge service (FastAPI). Run from the project root:

    edge/.venv/bin/python -m uvicorn edge.app:app --host 127.0.0.1 --port 8000

Lifespan loads + warms every model once, runs the mandatory MiniFASNet self-test, loads the
encrypted template cache and starts the policy runtime. If EDGE_LAN_PORT is set, a second listener
on 0.0.0.0:EDGE_LAN_PORT serves ONLY /v1/depth/* for the DepthProbe iPhone app (X-Depth-Token).
Every response carries X-Latency-Ms.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Annotated, Any
from zoneinfo import ZoneInfo

import uvicorn
from fastapi import APIRouter, Depends, FastAPI, Header, Path, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from pydantic import ValidationError
from starlette.datastructures import UploadFile

from edge import access
from edge import attempts as svc
from edge.attempts import EdgeContext
from edge.cloud_client import CloudClient, CloudRejected, CloudUnavailable
from edge.config import EDGE_VERSION, Settings, Thresholds
from edge.depth_bridge import DepthBridge
from edge.enroll import enroll
from edge.errors import ApiError, install_error_handlers
from edge.events import EventBus
from edge.metrics import MetricsStore
from edge.ml.templates import TemplateStore, TemplateStoreError
from edge.perception import PerceptionEngine, decode_jpeg
from edge.policy_facade import load_runtime
from edge.schemas import (
    AdminModeRequest,
    CaptureSpec,
    ChallengeMeta,
    ClockRequest,
    DepthFramesMeta,
    EnrollMeta,
    EnrollResponse,
    EvalContext,
    FallbackRequest,
    FramesMeta,
    ProbeResponse,
    RandomChallengeRequest,
    RenderedRequest,
    SessionStartRequest,
    SessionStartResponse,
)
from edge.session import AttemptStore, NonceError, make_flash_sequence, secret_equal

log = logging.getLogger("edge.app")
MAX_FRAME_BYTES = 2 * 1024 * 1024
MAX_DEPTH_BYTES = 8 * 1024 * 1024
POOL_WORKERS = 8
MAX_CLIENT_LATENCY_MS = 60_000
IST = ZoneInfo("Asia/Kolkata")


def build_context(settings: Settings | None = None, engine: PerceptionEngine | None = None) -> EdgeContext:
    settings = settings or Settings.from_env()
    th = Thresholds.load(settings.thresholds_path)
    if engine is None:
        engine = PerceptionEngine(settings, th)
        engine.load()
    templates: TemplateStore | None = None
    model_id = engine.embedder.model_id if engine.embedder else "arcface_unavailable"
    try:
        templates = TemplateStore(settings.data_dir / "templates.fernet", settings.edge_data_key, model_id)
        templates.load()
    except TemplateStoreError as exc:
        log.error("template cache unavailable: %s", exc)
        templates = None
    runtime, kind = load_runtime(settings, th)
    return EdgeContext(
        settings=settings, thresholds=th, engine=engine, runtime=runtime, runtime_kind=kind,
        sessions=AttemptStore(), events=EventBus(), metrics=MetricsStore(), cloud=CloudClient(settings, th),
        depth=DepthBridge(th), templates=templates, pool=ThreadPoolExecutor(max_workers=POOL_WORKERS),
        started_monotonic=time.monotonic(),
    )


class _QuietServer(uvicorn.Server):
    """Embedded uvicorn server: leaves signal handling to the main server."""

    @contextlib.contextmanager
    def capture_signals(self):
        yield


def _add_latency_middleware(app: FastAPI) -> None:
    @app.middleware("http")
    async def latency_header(request: Request, call_next):
        t = time.perf_counter()
        response = await call_next(request)
        ms = (time.perf_counter() - t) * 1000.0
        response.headers["X-Latency-Ms"] = f"{ms:.1f}"
        if request.url.path != "/v1/depth/pending":
            log.info(json.dumps({"event": "http", "method": request.method, "path": request.url.path,
                                 "status": response.status_code, "latency_ms": round(ms, 1)}))
        elif not 200 <= response.status_code < 300:  # long-poll successes stay quiet; failures rate-limited
            ctx = getattr(request.app.state, "ctx", None)
            if ctx is not None:
                ctx.depth.note_poll_failure(response.status_code, request.client.host if request.client else None)
        return response


def create_lan_app(ctx: EdgeContext) -> FastAPI:
    """0.0.0.0 listener for the iPhone: ONLY GET /v1/depth/pending + POST /v1/depth/frames."""
    lan = FastAPI(title="HID edge depth LAN", version=EDGE_VERSION, docs_url=None, redoc_url=None,
                  openapi_url=None)
    lan.state.ctx = ctx
    _add_latency_middleware(lan)
    install_error_handlers(lan)
    lan.include_router(depth_router)
    return lan


def start_lan_listener(ctx: EdgeContext) -> asyncio.Task | None:
    """Bind 0.0.0.0:EDGE_LAN_PORT ourselves (a busy port must not take the kiosk API down)."""
    port = ctx.settings.lan_port
    if not port:
        ctx.lan_status = "disabled"
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
    except OSError as exc:
        sock.close()
        ctx.lan_status = f"bind_failed: {exc.strerror or exc}"
        log.error("depth LAN listener NOT started on 0.0.0.0:%s (%s)", port, exc)
        return None
    server = _QuietServer(uvicorn.Config(create_lan_app(ctx), lifespan="off", log_level="warning",
                                         access_log=False))
    ctx.lan_server = server
    ctx.lan_status = f"listening 0.0.0.0:{port}"

    async def run() -> None:
        try:
            await server.serve(sockets=[sock])
        except (Exception, SystemExit) as exc:  # noqa: BLE001 - uvicorn exits via SystemExit
            ctx.lan_status = f"failed: {exc}"
            log.error("depth LAN listener stopped: %s", exc)
        finally:
            sock.close()

    return asyncio.create_task(run())


def tighten_data_dir(data_dir) -> list[str]:
    """edge/data holds encrypted templates, the decision store and fallback state: owner-only (dir 0700,
    files 0600). Run at startup; returns the names it had to tighten. Never raises."""
    fixed: list[str] = []
    try:
        if data_dir.is_dir() and data_dir.stat().st_mode & 0o077:
            data_dir.chmod(0o700)
            fixed.append(".")
        for f in data_dir.iterdir() if data_dir.is_dir() else []:
            if f.is_file() and not f.is_symlink() and f.stat().st_mode & 0o077:
                f.chmod(0o600)
                fixed.append(f.name)
    except OSError as exc:
        log.warning("could not tighten %s permissions: %s", data_dir, exc)
    if fixed:
        log.warning("edge data permissions tightened to owner-only: %s", ", ".join(fixed))
    return fixed


def create_app(context_factory=build_context) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        ctx: EdgeContext = await asyncio.to_thread(context_factory)
        app.state.ctx = ctx
        tighten_data_dir(ctx.settings.data_dir)
        await ctx.cloud.start()
        svc.register_erase_hook(ctx)  # before start(): the first tick's ERASED revocations delete templates too
        svc._safe_call(ctx.runtime, "start")
        svc.report_template_cache(ctx)
        lan_task = start_lan_listener(ctx)
        log.info("edge ready: models=%s pad_self_test=%s runtime=%s templates=%s lan_port=%s",
                 ctx.engine.health.models_loaded,
                 ctx.engine.health.pad_self_test.ok if ctx.engine.health.pad_self_test else None,
                 ctx.runtime_kind, ctx.templates.count() if ctx.templates else None, ctx.settings.lan_port or None)
        try:
            yield
        finally:
            if lan_task is not None:
                ctx.lan_server.should_exit = True
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(lan_task, timeout=3)
            svc._safe_call(ctx.runtime, "stop")
            await ctx.cloud.stop()
            ctx.pool.shutdown(wait=False, cancel_futures=True)

    app = FastAPI(title="HID kiosk edge", version=EDGE_VERSION, lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware, allow_origins=list(Settings.from_env().cors_origins), allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-Admin-Token"], expose_headers=["X-Latency-Ms"],
    )
    _add_latency_middleware(app)
    install_error_handlers(app)
    app.include_router(router)
    app.include_router(depth_router)
    return app


# ---------------------------------------------------------------------------------- dependencies
def get_ctx(request: Request) -> EdgeContext:
    return request.app.state.ctx


Ctx = Annotated[EdgeContext, Depends(get_ctx)]


def require_admin(ctx: Ctx, x_admin_token: Annotated[str | None, Header()] = None) -> None:
    if not secret_equal(ctx.settings.admin_token, x_admin_token):  # non-ASCII header -> 401, not 500
        raise ApiError("UNAUTHORIZED", "admin token required")


def require_depth_device(ctx: Ctx, x_depth_token: Annotated[str | None, Header()] = None) -> None:
    if not secret_equal(ctx.settings.depth_device_token, x_depth_token):
        ctx.depth.note_rejected_token()  # /v1/health depth_probe -> "rejected_token" (never the token itself)
        raise ApiError("UNAUTHORIZED", "depth device token required")


Admin = Annotated[None, Depends(require_admin)]
DepthDevice = Annotated[None, Depends(require_depth_device)]
router = APIRouter(prefix="/v1")
depth_router = APIRouter(prefix="/v1")


def _attempt(ctx: EdgeContext, attempt_id: str):
    att = ctx.sessions.get(attempt_id)
    if att is None:
        raise ApiError("ATTEMPT_NOT_FOUND", "unknown attempt", attempt_id)
    return att


async def _form(request: Request):
    try:
        return await request.form(max_files=16, max_fields=32, max_part_size=4 * 1024 * 1024)
    except Exception as exc:  # malformed multipart
        raise ApiError("VALIDATION_ERROR", f"invalid multipart body: {exc}") from exc


def _meta(form, model):
    raw = form.get("meta")
    if raw is None:
        raise ApiError("VALIDATION_ERROR", "missing 'meta' part")
    if isinstance(raw, UploadFile):
        raise ApiError("VALIDATION_ERROR", "'meta' must be a JSON string field")
    try:
        return model.model_validate_json(raw)
    except ValidationError as exc:
        details = [{"loc": ["meta", *e.get("loc", ())], "msg": e.get("msg", "")} for e in exc.errors()][:10]
        first = details[0] if details else {"loc": ["meta"], "msg": "invalid"}
        raise ApiError("VALIDATION_ERROR", f"invalid meta: {'.'.join(map(str, first['loc'][1:])) or 'meta'}: "
                                           f"{first['msg']}", extra={"details": details}) from exc


async def _files(form, prefix: str, max_n: int, max_bytes: int) -> list[bytes]:
    """File parts {prefix}0..{prefix}{n-1} (contiguous, n <= max_n). Every limit is checked BEFORE any part
    is read: Starlette spools parts to temp files, and reading an oversized one would pull it into RAM.
    Oversized -> 413 PAYLOAD_TOO_LARGE; empty / not a file / extra parts -> 422 VALIDATION_ERROR."""
    parts: list[UploadFile] = []
    for i in range(max_n):
        part = form.get(f"{prefix}{i}")
        if part is None:
            break
        if not isinstance(part, UploadFile):
            raise ApiError("VALIDATION_ERROR", f"{prefix}{i} must be a file part")
        if part.size is not None and part.size > max_bytes:
            raise ApiError("PAYLOAD_TOO_LARGE", f"{prefix}{i} is {part.size} bytes (max {max_bytes})")
        parts.append(part)
    expected = {f"{prefix}{i}" for i in range(len(parts))}
    extra = [k for k in form if k.startswith(prefix) and k not in expected]
    if extra:
        raise ApiError("VALIDATION_ERROR", f"unexpected/non-contiguous parts {extra[:3]} (max {max_n} {prefix}*)")
    out = []
    for i, part in enumerate(parts):
        data = await part.read(max_bytes + 1)  # bounded even if the parser reported no size
        if len(data) > max_bytes:
            raise ApiError("PAYLOAD_TOO_LARGE", f"{prefix}{i} larger than {max_bytes} bytes")
        if not data:
            raise ApiError("VALIDATION_ERROR", f"{prefix}{i} is empty")
        out.append(data)
    return out


async def _named_file(form, name: str, max_bytes: int) -> bytes:
    """One required file part `name`, with the _files limits (size checked before reading)."""
    part = form.get(name)
    if part is None:
        raise ApiError("VALIDATION_ERROR", f"missing '{name}' file part")
    if not isinstance(part, UploadFile):
        raise ApiError("VALIDATION_ERROR", f"{name} must be a file part")
    if part.size is not None and part.size > max_bytes:
        raise ApiError("PAYLOAD_TOO_LARGE", f"{name} is {part.size} bytes (max {max_bytes})")
    data = await part.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ApiError("PAYLOAD_TOO_LARGE", f"{name} larger than {max_bytes} bytes")
    if not data:
        raise ApiError("VALIDATION_ERROR", f"{name} is empty")
    return data


try:
    from edge.policy.runtime import CloudUnavailableError
except ImportError:  # pragma: no cover

    class CloudUnavailableError(Exception):  # type: ignore[no-redef]
        pass


async def _call_runtime(ctx: EdgeContext, fn, *args, **kw) -> Any:
    """Admin/runtime call with the contract mapping: CloudUnavailableError -> 503,
    PermissionError -> 403, ValueError -> 422."""
    try:
        return await svc._run(ctx, lambda: fn(*args, **kw))
    except CloudUnavailableError as exc:
        raise ApiError("CLOUD_UNAVAILABLE", str(exc) or "cloud unavailable") from exc
    except PermissionError as exc:
        raise ApiError("FORBIDDEN", str(exc) or "forbidden") from exc
    except ValueError as exc:
        raise ApiError("VALIDATION_ERROR", str(exc)) from exc


def _require_step(att, step: str) -> None:
    """API 3.3/3.4: a submission for a step that is not pending is a protocol error, not a DENY."""
    if att.terminal:
        raise ApiError("ATTEMPT_CLOSED", "attempt already reached a terminal decision", att.attempt_id)
    if att.pending_step != step:
        raise ApiError("INVALID_STATE", f"no {step} step pending (pending: {att.pending_step})", att.attempt_id)


def _bundle_kiosks(ctx: EdgeContext) -> set[str]:
    """Kiosks the runtime's VERIFIED bundle covers (runtime.bundle_kiosk_ids()); empty without one."""
    ids = svc._safe_call(ctx.runtime, "bundle_kiosk_ids")
    return {str(k) for k in ids} if isinstance(ids, set | frozenset | list | tuple) else set()


def allowed_kiosks(ctx: EdgeContext) -> set[str]:
    """Kiosks session/start serves: KIOSK_ID; with DEMO_MODE=1 (demo kiosk switch) also a kiosk that the
    VERIFIED bundle covers AND the policy runtime evaluates. decide() is bound to runtime.kiosk_id (its
    ScheduleCtx), so an attempt for any other kiosk ends in DENY SYSTEM_ERROR at the engine's kiosk check:
    such a switch is refused up front. Never derived from the unsigned config/schedule.example.json."""
    own = {ctx.settings.kiosk_id}
    if not ctx.settings.demo_mode:
        return own
    return own | (_bundle_kiosks(ctx) & {getattr(ctx.runtime, "kiosk_id", None)})


def _kiosk_refusal(ctx: EdgeContext, kiosk_id: str) -> ApiError:
    own = ctx.settings.kiosk_id
    if not ctx.settings.demo_mode:
        return ApiError("FORBIDDEN", f"kiosk_id not served by this edge ({own}; DEMO_MODE=0)")
    covered = _bundle_kiosks(ctx)
    if kiosk_id not in covered:
        where = f"it covers {', '.join(sorted(covered))}" if covered else "no verified schedule bundle installed"
        return ApiError("INVALID_STATE", f"kiosk switch to {kiosk_id} refused: not covered by the verified "
                                         f"schedule bundle ({where})")
    runtime_kiosk = getattr(ctx.runtime, "kiosk_id", None) or own
    return ApiError("INVALID_STATE", f"kiosk switch to {kiosk_id} refused: the policy runtime evaluates attempts "
                                     f"only for {runtime_kiosk} (restart the edge with KIOSK_ID={kiosk_id})")


# ---------------------------------------------------------------------------------- system
def health_problems(ctx: EdgeContext) -> list[str]:
    """Why /v1/health is `degraded` (empty = ok): fail-secure policy runtime (every attempt DENY
    SYSTEM_ERROR), a required model missing, the MiniFASNet self-test failed (PAD disabled), or no
    template cache."""
    h = ctx.engine.health
    out = []
    if ctx.runtime_kind == "fail_secure":
        out.append("policy_runtime_fail_secure")
    out += [f"model_missing:{k}" for k in ("face_detector", "minifasnet_v2", "minifasnet_v1se", "coco_detector",
                                           "arcface") if not h.models_loaded.get(k, False)]
    if not (h.pad_self_test and h.pad_self_test.ok):
        out.append("pad_self_test_failed" if h.pad_self_test else "pad_self_test_not_run")
    if ctx.templates is None:
        out.append("template_cache_unavailable")
    return out


@router.get("/health")
async def health(ctx: Ctx) -> dict[str, Any]:
    h = ctx.engine.health
    loaded = h.models_loaded
    st = h.pad_self_test
    reasons = health_problems(ctx)
    return {
        "status": "degraded" if reasons else "ok",
        "degraded_reasons": reasons,
        "version": EDGE_VERSION,
        "models_loaded": {
            "minifasnet_v2": loaded.get("minifasnet_v2", False),
            "minifasnet_v1se": loaded.get("minifasnet_v1se", False),
            "face_detector": loaded.get("face_detector", False),
            "device_detector": loaded.get("coco_detector", False),
            "arcface": loaded.get("arcface", False),
        },
        "self_test": {
            "minifasnet_real_index": st.real_class_index if st else None,
            "input_scale": (("0-255 BGR" if st.input_scale == 1.0 else f"x{st.input_scale:g} BGR") if st else None),
            "passed": bool(st and st.ok),
        },
        "depth_probe": ctx.depth.status(),
        "uptime_s": round(time.monotonic() - ctx.started_monotonic),
        # deprecated alias (first-round shape) kept for existing dashboards; prefer `self_test`
        "pad_self_test": st.model_dump(exclude={"detail", "alternatives"}) if st else None,
        "detail": {
            "kiosk_id": ctx.settings.kiosk_id, "policy_runtime": ctx.runtime_kind,
            "policy_version": ctx.thresholds.policy_version, "cloud_configured": ctx.cloud.enabled,
            "arcface_provider": h.arcface_provider, "model_errors": h.errors,
            "self_test": st.model_dump(exclude={"detail", "alternatives"}) if st else None,
            "template_cache": ctx.templates.summary() if ctx.templates else None,
            "depth_enabled": ctx.depth.enabled, "lan_listener": ctx.lan_status,
            "demo_mode": ctx.settings.demo_mode,
        },
    }


def _demo_clock_view(dc: Any) -> dict[str, Any] | None:
    """API 3.10/3.14 shape: now_local as "HH:MM" Asia/Kolkata (+ now_utc, offset_s)."""
    if not isinstance(dc, dict):
        return None
    out = {"earliest_date_local": None, "earliest_local": None, "earliest_utc": None, "bundle_issued_at": None,
           **dc}
    try:
        local = datetime.fromisoformat(str(dc.get("now_local")))
        local = local if local.tzinfo else local.replace(tzinfo=IST)
        out["now_local"] = local.astimezone(IST).strftime("%H:%M")
        out["now_utc"] = local.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    except (TypeError, ValueError):
        now_utc = out.get("now_utc")
        if isinstance(now_utc, str) and "." in now_utc:  # whole seconds on the wire
            out["now_utc"] = now_utc.split(".")[0] + "Z"
    return out


@router.get("/mode")
async def mode(ctx: Ctx) -> dict[str, Any]:
    status = dict(svc._safe_call(ctx.runtime, "mode_status") or {"mode": svc._safe_call(ctx.runtime, "mode")})
    dc = status.get("demo_clock")  # v1.4 (R-E): present whenever DEMO_MODE=1 (with `active`), else null
    status["demo_clock"] = _demo_clock_view(dc) if ctx.settings.demo_mode and isinstance(dc, dict) else None
    tc = dict(status.get("template_cache") or {})
    if ctx.templates is not None:
        s_ = ctx.templates.summary()
        tc.update({"count": s_["count"], "model": s_["model"], "age_h": s_["age_h"]})
    status["template_cache"] = tc or None
    return status


@router.get("/events")
async def events(request: Request, ctx: Ctx) -> StreamingResponse:
    return StreamingResponse(ctx.events.stream(request.is_disconnected), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/metrics")
async def metrics(ctx: Ctx, since: str | None = None, label: str | None = None) -> dict[str, Any]:
    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
        except ValueError as exc:
            raise ApiError("VALIDATION_ERROR", "since must be ISO-8601") from exc
        if since_dt.tzinfo is None:
            since_dt = since_dt.replace(tzinfo=UTC)
    ms = svc._safe_call(ctx.runtime, "mode_status") or {}
    last = ms.get("last_sync")  # PolicyRuntime: {"at": ..., "report": ...} (same value as GET /v1/mode)
    sync = {"queue_depth": ms.get("sync_queue_depth"),
            "last_sync_at": last.get("at") if isinstance(last, dict) else ms.get("last_sync_at")}
    return ctx.metrics.summary(since_dt, label, sync)


# ---------------------------------------------------------------------------------- attempts
@router.post("/session/start", status_code=201, response_model=SessionStartResponse)
async def session_start(body: SessionStartRequest, ctx: Ctx) -> SessionStartResponse:
    if body.kiosk_id not in allowed_kiosks(ctx):
        raise _kiosk_refusal(ctx, body.kiosk_id)
    th = ctx.thresholds
    recapture_count = 0
    if body.recapture_of:
        prev = _attempt(ctx, body.recapture_of)
        if prev.kiosk_id != body.kiosk_id or prev.terminal or prev.pending_step != "RECAPTURE":
            raise ApiError("INVALID_STATE", "recapture_of must be this kiosk's attempt pending RECAPTURE",
                           body.recapture_of)
        recapture_count = prev.recapture_count + 1
        prev.closed = True  # the old attempt is closed; the new one carries the count
    mode = str(svc._safe_call(ctx.runtime, "mode") or "OFFLINE")
    svc.warm_cloud_match(ctx, mode)  # fire-and-forget: the /v1/match ~1 s later reuses a warm connection
    flash_on = bool(body.flash_enabled and th.get("liveness.flash.enabled"))
    seq = make_flash_sequence(th) if flash_on else []
    att = ctx.sessions.create(
        kiosk_id=body.kiosk_id, flash_enabled=flash_on, flash_sequence=seq,
        camera_label=body.client.camera_label, claimed_user_id=body.claimed_user_id,
        recapture_of=body.recapture_of, recapture_count=recapture_count,
    )
    att.eval_tags = dict(ctx.eval_context) if ctx.eval_context else None
    window = int(th.get("liveness.flash.duration_ms"))
    att.depth_requested = await ctx.depth.request(att.attempt_id, "PASSIVE", window)
    return SessionStartResponse(
        attempt_id=att.attempt_id, nonce=att.nonce, flash_sequence=seq,
        capture=CaptureSpec(frames=int(th.get("quality.frames_per_attempt")), window_ms=window),
        mode=mode, expires_at=att.expires_at,
        recapture_count=recapture_count, depth_requested=att.depth_requested,
    )


_NONCE_HTTP = {"NONCE_INVALID": "FORBIDDEN"}


@router.post("/attempt/{attempt_id}/frames")
async def attempt_frames(attempt_id: str, request: Request, ctx: Ctx) -> dict[str, Any]:
    _attempt(ctx, attempt_id)
    form = await _form(request)
    meta: FramesMeta = _meta(form, FramesMeta)
    th = ctx.thresholds
    jpegs = await _files(form, "frame_", int(th.get("quality.frames_per_attempt")), MAX_FRAME_BYTES)
    if len(jpegs) < int(th.get("quality.min_usable_frames")):
        raise ApiError("VALIDATION_ERROR", f"need >= {th.get('quality.min_usable_frames')} frames", attempt_id)
    if len(meta.frame_timestamps_ms) != len(jpegs):
        raise ApiError("VALIDATION_ERROR", "frame_timestamps_ms must have one entry per frame part", attempt_id)
    try:
        att = ctx.sessions.consume_nonce(attempt_id, meta.nonce)
    except NonceError as exc:
        raise ApiError(_NONCE_HTTP.get(exc.code, exc.code), str(exc), attempt_id) from exc
    return await svc.process_frames(ctx, att, jpegs, meta)


def _probe_window(att) -> None:
    """A probe is valid after session/start and before the frames, once per attempt (else 409)."""
    if att.terminal or att.nonce_used or att.frames_received_at is not None:
        raise ApiError("INVALID_STATE", "probe only between session/start and the frames upload", att.attempt_id)
    if att.probe_received:
        raise ApiError("INVALID_STATE", "probe already received for this attempt (one per attempt)",
                       att.attempt_id)


@router.post("/attempt/{attempt_id}/probe", status_code=202, response_model=ProbeResponse)
async def attempt_probe(attempt_id: str, request: Request, ctx: Ctx) -> ProbeResponse:
    """Early cloud probe: the kiosk's face-lock frame (multipart part `probe`, JPEG <= 2 MB) starts the
    Rekognition match while the flash capture runs. Fire-and-forget for the kiosk; never an HTTP 500."""
    att = _attempt(ctx, attempt_id)
    _probe_window(att)
    form = await _form(request)
    jpeg = await _named_file(form, "probe", MAX_FRAME_BYTES)
    _probe_window(att)  # re-checked after the upload; no await between this check and the claim
    att.probe_received = True
    try:
        return ProbeResponse(**await svc.start_probe(ctx, att, jpeg))
    except ApiError as exc:
        if exc.code == "VALIDATION_ERROR":  # a rejected (undecodable) probe must not use up the probe slot
            att.probe_received = False
            att.probe = None
        raise


@router.post("/attempt/{attempt_id}/rendered", status_code=204)
async def attempt_rendered(attempt_id: str, body: RenderedRequest, ctx: Ctx) -> Response:
    att = _attempt(ctx, attempt_id)
    if att.last_response is None or att.face_lock_at_ms is None:
        raise ApiError("INVALID_STATE", "no decision has been returned for this attempt", attempt_id)
    if att.rendered_client_ms is not None:  # first beacon per attempt wins
        return Response(status_code=204)
    if body.face_lock_at_ms != att.face_lock_at_ms:
        raise ApiError("VALIDATION_ERROR", "face_lock_at_ms differs from the value sent in FramesMeta", attempt_id)
    client_ms = body.rendered_at_ms - body.face_lock_at_ms
    if not 0 <= client_ms <= MAX_CLIENT_LATENCY_MS:
        raise ApiError("VALIDATION_ERROR", "rendered_at_ms must be within 60 s after face_lock_at_ms", attempt_id)
    att.rendered_client_ms = client_ms
    ctx.metrics.record_client(attempt_id, client_ms, att.eval_label)
    ctx.events.publish("rendered", {
        "attempt_id": attempt_id, "client_latency_ms": client_ms, "face_lock_at_ms": body.face_lock_at_ms,
        "rendered_at_ms": body.rendered_at_ms, "decision": att.last_response.get("decision"),
        "eval": att.eval_tags,
    })
    log.info(json.dumps({"event": "rendered", "attempt_id": attempt_id, "client_latency_ms": client_ms}))
    return Response(status_code=204)


@router.post("/attempt/{attempt_id}/challenge")
async def attempt_challenge(attempt_id: str, request: Request, ctx: Ctx) -> dict[str, Any]:
    att = _attempt(ctx, attempt_id)
    jpeg = None
    if request.headers.get("content-type", "").startswith("multipart/"):
        form = await _form(request)
        meta: ChallengeMeta = _meta(form, ChallengeMeta)
        frames = await _files(form, "frame_", 3, MAX_FRAME_BYTES)
        jpeg = frames[-1] if frames else None
    else:
        try:
            meta = ChallengeMeta.model_validate_json(await request.body())
        except ValidationError as exc:
            raise ApiError("VALIDATION_ERROR", f"invalid challenge body: {exc.errors()[:3]}", attempt_id) from exc
    _require_step(att, "CHALLENGE")
    issued = ((att.last_response or {}).get("next_action") or {}).get("challenge") or {}
    if issued.get("challenge_id") and meta.challenge_id != issued["challenge_id"]:
        raise ApiError("VALIDATION_ERROR", "challenge_id does not match the pending challenge", attempt_id)
    if meta.nonce in att.challenge_nonces:
        raise ApiError("NONCE_REUSED", "challenge nonce already used", attempt_id)
    att.challenge_nonces.add(meta.nonce)  # claimed before any await: a concurrent replay gets 409
    try:
        return await svc.process_challenge(ctx, att, meta, jpeg)
    except BaseException:
        # R-G: ANY failure before a decision was produced (422 frame, runtime error, cancellation) releases the
        # nonce so the retry may reuse it; once the runtime decided, the nonce stays used.
        if meta.nonce not in att.decided_challenge_nonces:
            att.challenge_nonces.discard(meta.nonce)
        raise


@router.post("/attempt/{attempt_id}/fallback")
async def attempt_fallback(attempt_id: str, body: FallbackRequest, ctx: Ctx) -> dict[str, Any]:
    att = _attempt(ctx, attempt_id)
    _require_step(att, "SECOND_FACTOR")
    return await svc.process_fallback(ctx, att, body)


@router.post("/attempt/{attempt_id}/otp/send", status_code=201)
async def attempt_otp_send(attempt_id: str, ctx: Ctx) -> dict[str, Any]:
    att = _attempt(ctx, attempt_id)
    _require_step(att, "SECOND_FACTOR")
    methods = ((att.last_response or {}).get("next_action") or {}).get("methods") or []
    if "EMAIL_OTP" not in methods:
        raise ApiError("INVALID_STATE", "EMAIL_OTP is not an offered method for this step", attempt_id)
    if not ctx.cloud.enabled or str(svc._safe_call(ctx.runtime, "mode")) != "ONLINE":
        raise ApiError("CLOUD_UNAVAILABLE", "email OTP needs the cloud (offline: use TOTP/card/staff)", attempt_id)
    if not att.candidate_user_id:
        raise ApiError("INVALID_STATE", "no candidate user for this attempt", attempt_id)
    try:
        return await ctx.cloud.otp_send(attempt_id, att.candidate_user_id)
    except CloudUnavailable as exc:
        if exc.connectivity_miss:  # transport error / 5xx only: a 401 is a key problem, not an outage
            svc._safe_call(ctx.runtime, "record_cloud_result", False)
        raise ApiError("CLOUD_UNAVAILABLE", str(exc), attempt_id) from exc
    except CloudRejected as exc:  # the cloud answered: never a connectivity miss
        raise await _otp_send_rejected(ctx, att, exc) from exc


async def _otp_send_rejected(ctx: EdgeContext, att, exc: CloudRejected) -> ApiError:
    """404 = no e-mail on file: drop EMAIL_OTP from this step (R11 path, nothing counted; the re-issued STEP_UP
    is GET /v1/attempt/{id} and `methods` below). 429 = resend throttle. Anything else = 422."""
    aid = att.attempt_id
    if exc.status == 404:
        methods = None
        try:
            resp = await svc.drop_method(ctx, att, "EMAIL_OTP")
            svc.finish(ctx, att, dict(resp), kind="fallback")
            methods = (resp.get("next_action") or {}).get("methods")
        except ApiError:  # EMAIL_OTP was the only method left: the step stays open unchanged
            methods = ((att.last_response or {}).get("next_action") or {}).get("methods")
        return ApiError("NOT_FOUND", "no e-mail on file for this user: use TOTP, card or a staff code", aid,
                        extra={"reason": "NO_EMAIL_ON_FILE", "methods": methods})
    if exc.status == 429:
        retry = exc.retry_after_s
        return ApiError("RATE_LIMITED", "an e-mail code was sent recently; wait before asking again"
                        + (f" ({retry} s)" if retry is not None else ""), aid,
                        extra={"retry_after_s": retry},
                        headers={"Retry-After": str(retry)} if retry is not None else None)
    return ApiError("VALIDATION_ERROR", f"cloud refused the e-mail code request: {exc.message}", aid,
                    extra={"cloud_status": exc.status, "cloud_code": exc.code})


@router.get("/attempt/{attempt_id}")
async def attempt_get(attempt_id: str, ctx: Ctx) -> dict[str, Any]:
    att = ctx.sessions.get(attempt_id)
    if att is not None and att.last_response is not None:
        return att.last_response  # the edge's latest response (includes R11 re-issues)
    if att is None:
        view = svc._safe_call(ctx.runtime, "get_attempt", attempt_id)
        if view:
            return view
        raise ApiError("ATTEMPT_NOT_FOUND", "unknown attempt", attempt_id)
    raise ApiError("INVALID_STATE", "frames not yet submitted", attempt_id)


# ---------------------------------------------------------------------------------- admin
@router.post("/admin/mode")
async def admin_mode(body: AdminModeRequest, ctx: Ctx, _: Admin) -> dict[str, Any]:
    fn = getattr(ctx.runtime, "set_forced_mode", None)
    if not callable(fn):
        raise ApiError("INVALID_STATE", f"policy runtime ({ctx.runtime_kind}) cannot force a mode")
    await _call_runtime(ctx, fn, body.force)
    return await mode(ctx)


@router.get("/admin/store")
async def admin_store(ctx: Ctx, _: Admin) -> dict[str, Any]:
    return await svc._run(ctx, lambda: svc._safe_call(ctx.runtime, "store_view") or {})


@router.post("/admin/sync")
async def admin_sync(ctx: Ctx, _: Admin) -> dict[str, Any]:
    fn = getattr(ctx.runtime, "sync_now", None)
    if not callable(fn) or not ctx.settings.cloud_enabled:
        raise ApiError("CLOUD_UNAVAILABLE", "cloud not configured / unreachable (offline)")
    rep = await _call_runtime(ctx, fn)
    if not isinstance(rep, dict) or rep.get("error"):
        raise ApiError("CLOUD_UNAVAILABLE", f"sync failed: {(rep or {}).get('error') if isinstance(rep, dict) else rep}")

    def n(v: Any) -> int:
        return len(v) if isinstance(v, list | tuple) else int(v or 0)

    ms = svc._safe_call(ctx.runtime, "mode_status") or {}
    return {"accepted": n(rep.get("accepted")), "duplicates": n(rep.get("duplicates")),
            "rejected": n(rep.get("rejected")), "flags": rep.get("flags") or [],
            "queue_depth": ms.get("sync_queue_depth"), "report": rep}


@router.post("/admin/eval/context")
async def admin_eval_context_set(body: EvalContext, ctx: Ctx, _: Admin) -> dict[str, Any]:
    ctx.eval_context = body.model_dump()
    ctx.eval_context_since = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    return {"active": True, "context": ctx.eval_context, "since": ctx.eval_context_since}


@router.delete("/admin/eval/context", status_code=204)
async def admin_eval_context_clear(ctx: Ctx, _: Admin) -> Response:
    ctx.eval_context = None
    ctx.eval_context_since = None
    return Response(status_code=204)


@router.post("/admin/rate-limit/reset", status_code=204)
async def admin_rate_limit_reset(ctx: Ctx, _: Admin) -> Response:
    svc._safe_call(ctx.runtime, "reset_rate_limit")
    return Response(status_code=204)


@router.post("/admin/clock")
async def admin_clock(body: ClockRequest, ctx: Ctx, _: Admin) -> dict[str, Any]:
    if not ctx.settings.demo_mode:
        raise ApiError("FORBIDDEN", "demo clock requires DEMO_MODE=1", extra={"reason": "NOT_DEMO_MODE"})
    if sum([body.set_local is not None, body.offset_s is not None, bool(body.reset)]) != 1:
        raise ApiError("VALIDATION_ERROR", "send exactly one of set_local | offset_s | reset")
    fn = getattr(ctx.runtime, "set_demo_clock", None)
    if not callable(fn):
        raise ApiError("INVALID_STATE", f"policy runtime ({ctx.runtime_kind}) has no demo clock")
    res = await _call_runtime(ctx, fn, set_local=body.set_local, offset_s=body.offset_s, reset=body.reset)
    return _demo_clock_view(res) or {"active": False}


@router.post("/admin/random-challenge")
async def admin_random_challenge(body: RandomChallengeRequest, ctx: Ctx, _: Admin) -> dict[str, Any]:
    """Demo control for the random liveness challenge (mask contingency). DEMO_MODE=1 only."""
    if not ctx.settings.demo_mode:
        raise ApiError("FORBIDDEN", "random-challenge control requires DEMO_MODE=1")
    fn = getattr(ctx.runtime, "set_random_challenge", None)
    if not callable(fn):
        raise ApiError("INVALID_STATE", f"policy runtime ({ctx.runtime_kind}) has no random challenge")
    await _call_runtime(ctx, fn, body.mode)
    return {"random_challenge": body.mode}


@router.get("/admin/attempt/{attempt_id}/signals")
async def admin_attempt_signals(attempt_id: str, ctx: Ctx, _: Admin) -> dict[str, Any]:
    att = _attempt(ctx, attempt_id)
    return {"attempt_id": attempt_id, "eval": att.eval_tags, **(att.signals_debug or {})}


@router.get("/admin/users")
async def admin_users(ctx: Ctx, _: Admin) -> dict[str, Any]:
    """Locally enrolled users. `role` / `display_name` are the VERIFIED BUNDLE's (what every decision uses);
    the label stored with the template is `template_role` / `template_display_name`. `in_schedule` false =
    the user is not in the bundle (DENY NOT_ENROLLED / NO_ENTITLEMENT until added)."""
    if ctx.templates is None:
        raise ApiError("INVALID_STATE", "template cache unavailable")
    users = [ctx.templates.get(uid) for uid in sorted({*ctx.templates.gallery.user_ids})]
    out = []
    for u in users:
        if not u:
            continue
        info = svc._safe_call(ctx.runtime, "user_info", u.user_id) or {}
        out.append({"user_id": u.user_id, "display_name": info.get("display") or u.display_name,
                    "role": info.get("role"), "bundle_role": info.get("role"),
                    "bundle_display": info.get("display"), "in_schedule": bool(info),
                    "template_role": u.role, "template_display_name": u.display_name,
                    "template_version": u.template_version, "templates": len(u.templates_b64),
                    "totp_local": access.has_local_totp(ctx, u.user_id, u), "card": bool(u.card_id_hash),
                    "updated_at": u.updated_at})
    return {"users": out, "bundle_version": getattr(getattr(ctx.runtime, "bundles", None), "version", None),
            **ctx.templates.summary()}


# ---------------------------------------------------------------------------------- users & access (control panel)
UserIdPath = Annotated[str, Path(pattern=access.USER_ID)]


@router.get("/admin/access/users")
async def admin_access_users(ctx: Ctx, _: Admin) -> dict[str, Any]:
    """API 3.18.1: cloud master (ONLINE) merged with the verified bundle + feed and the local enrolment.
    OFFLINE / cloud error -> bundle-only, read_only (read_only_code says why). Only 401 is an error."""
    return await access.list_view(ctx)


@router.put("/admin/access/users/{user_id}")
async def admin_access_put(user_id: UserIdPath, body: access.AccessUpdate, ctx: Ctx, _: Admin) -> dict[str, Any]:
    """API 3.18.2: create / update / re-admit (R-B) / restore (R-C) a schedule entry in the cloud master, then
    pull + install the re-signed bundle and the feed in the same call. Needs ONLINE (503 otherwise)."""
    return await access.put_access(ctx, user_id, body)


@router.post("/admin/access/users/{user_id}/revoke")
async def admin_access_revoke(user_id: UserIdPath, ctx: Ctx, _: Admin,
                              body: access.RevokeRequest | None = None) -> dict[str, Any]:
    """API 3.18.3 (R-C): cloud USER revocation (SCHEDULE_REVOKED online and offline), then bundle + feed pull."""
    return await access.revoke(ctx, user_id, body or access.RevokeRequest())


@router.post("/admin/access/codes/rotate")
async def admin_codes_rotate(body: access.CodesRotateRequest, ctx: Ctx, _: Admin) -> Response:
    """API 3.18.4 (R-D): fresh one-time staff override codes, returned FLAT and ONCE: never logged, never stored
    on the edge, Cache-Control: no-store. Always 200 once the cloud minted them."""
    payload = await access.rotate_codes(ctx, body)
    return Response(json.dumps(payload), media_type="application/json",
                    headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@router.post("/admin/bundle/refresh")
async def admin_bundle_refresh(ctx: Ctx, _: Admin) -> dict[str, Any]:
    """API 3.18.5: pull + verify + install the newest cloud bundle now (body {} or none)."""
    return await access.refresh_route(ctx)


@router.post("/enroll", status_code=201, response_model=EnrollResponse)
async def enroll_user(request: Request, ctx: Ctx, _: Admin) -> EnrollResponse:
    form = await _form(request)
    meta: EnrollMeta = _meta(form, EnrollMeta)
    jpegs = await _files(form, "frame_", int(ctx.thresholds.get("quality.frames_per_attempt")), MAX_FRAME_BYTES)
    if not jpegs:
        raise ApiError("VALIDATION_ERROR", "no frame_* parts")
    return await enroll(ctx, meta, jpegs)


ERASE_QUEUED_MSG = ("local data erased; the cloud erasure (Rekognition faces + cloud record) is queued and retried at "
                    "the next sync")


async def _queue_cloud_erasure(ctx: EdgeContext, user_id: str) -> bool:
    """R-J: persist the pending cloud erasure in edge/offline (PolicyRuntime.queue_cloud_erasure, replayed at
    every sync until the cloud answers 200/204/404). False when the runtime cannot queue it."""
    fn = getattr(ctx.runtime, "queue_cloud_erasure", None) or getattr(ctx.runtime, "enqueue_cloud_erasure", None)
    if not callable(fn):
        return False
    try:
        await svc._run(ctx, fn, user_id)
    except Exception as exc:  # noqa: BLE001 - reported honestly as not queued
        log.error("queueing the cloud erasure failed: %s", type(exc).__name__)
        return False
    return True


@router.delete("/enroll/{user_id}")
async def enroll_delete(user_id: UserIdPath, ctx: Ctx, _: Admin) -> dict[str, Any]:
    """API 3.15 DPDP erasure: local template + TOTP secret now; the cloud erasure now when ONLINE, else (or when
    the cloud call fails) queued in edge/offline and replayed at sync (R-J). `cloud` is one of deleted | queued |
    not_configured | failed (M1: the local erasure queue could not be written, e.g. disk error; the local
    template IS erased and the operator must retry while ONLINE)."""
    if ctx.templates is None:
        raise ApiError("INVALID_STATE", "template cache unavailable")
    removed = await svc._run(ctx, ctx.templates.delete, user_id)
    svc.report_template_cache(ctx)
    creds = getattr(ctx.runtime, "credentials", None)  # TOTP secret lives in the runtime's encrypted store
    if creds is not None and callable(getattr(creds, "remove", None)):
        await svc._run(ctx, creds.remove, user_id)
    if not removed and not ctx.cloud.enabled:
        raise ApiError("NOT_FOUND", f"user {user_id} not enrolled on this edge", extra={"reason": "NOT_ENROLLED"})
    out: dict[str, Any] = {"user_id": user_id, "local_removed": bool(removed), "cloud": "not_configured",
                           "cloud_status": None, "message": None, "bundle": None}
    if not ctx.cloud.enabled:
        return out
    forced = bool(getattr(getattr(ctx.runtime, "monitor", None), "forced", False))
    error = "kiosk OFFLINE"
    if not forced and access.edge_mode(ctx) == "ONLINE":
        try:
            res = await ctx.cloud.delete_user(user_id)
            out["cloud_status"] = res.get("status")
            if res.get("status") in (200, 204, 404):  # 404 = nothing left in the cloud (idempotent)
                out["cloud"] = "deleted"
                body = res.get("body")
                want = body.get("bundle_version") if isinstance(body, dict) else None
                refreshed = await access.refresh_bundle(ctx, want if isinstance(want, int) else None)
                out["bundle"] = refreshed  # the erasure re-signs the bundle: install it now
                return out
            error = f"cloud HTTP {res.get('status')}"
            if isinstance(res.get("status"), int) and res["status"] >= 500:
                svc._safe_call(ctx.runtime, "record_cloud_result", False)
        except CloudUnavailable as exc:
            error = str(exc)
            if exc.connectivity_miss:
                svc._safe_call(ctx.runtime, "record_cloud_result", False)
    if await _queue_cloud_erasure(ctx, user_id):
        out["cloud"], out["message"] = "queued", ERASE_QUEUED_MSG
    else:  # no persisted queue in this runtime: say so honestly (DPDP), never claim "queued"
        out["cloud"] = "failed"
        out["message"] = (f"local data erased, but the CLOUD erasure did not happen ({error}) and could not be "
                          f"queued: retry DELETE /v1/enroll/{user_id} while the kiosk is ONLINE")
    log.info("erasure user=%s local_removed=%s cloud=%s", user_id, removed, out["cloud"])
    return out


# ---------------------------------------------------------------------------------- depth (DepthProbe)
@depth_router.get("/depth/pending", response_model=None)
async def depth_pending(ctx: Ctx, _: DepthDevice, wait_s: Annotated[float, Query(ge=0, le=30)] = 20.0) -> Any:
    req = await ctx.depth.next_pending(wait_s)
    if req is None:
        return Response(status_code=204)
    return req.public()


@depth_router.post("/depth/frames")
async def depth_frames(request: Request, ctx: Ctx, _: DepthDevice) -> dict[str, Any]:
    if not ctx.depth.enabled:
        raise ApiError("INVALID_STATE", "depth disabled (liveness.depth.enabled = false)")
    form = await _form(request)
    meta: DepthFramesMeta = _meta(form, DepthFramesMeta)
    att = _attempt(ctx, meta.attempt_id)
    if att.terminal:
        raise ApiError("INVALID_STATE", "attempt already closed", meta.attempt_id)
    if not ctx.depth.consume_nonce(meta.attempt_id, meta.phase, meta.depth_nonce):
        raise ApiError("FORBIDDEN", "depth_nonce invalid or already used for this attempt/phase", meta.attempt_id)
    raw = await _files(form, "depth_", 3, MAX_DEPTH_BYTES)
    if not raw:
        raise ApiError("VALIDATION_ERROR", "no depth_* parts", meta.attempt_id)
    rgb_jpegs = await _files(form, "rgb_", 1, MAX_FRAME_BYTES)  # optional face-locator JPEG (2 MB like frames)
    box, lms = meta.face_box_norm, meta.landmarks_norm
    if (box is None or lms is None) and rgb_jpegs:
        img = await svc._run(ctx, decode_jpeg, rgb_jpegs[0])
        if img is not None and ctx.engine.detector is not None:
            faces = await svc._run(ctx, ctx.engine.detector.detect, img)
            if faces:
                h, w = img.shape[:2]
                f = faces[0]
                k = f.kps
                box = box or [f.x1 / w, f.y1 / h, f.width / w, f.height / h]
                lms = lms or {"left_eye": [float(k[0][0] / w), float(k[0][1] / h)],
                              "right_eye": [float(k[1][0] / w), float(k[1][1] / h)],
                              "nose": [float(k[2][0] / w), float(k[2][1] / h)],
                              "mouth": [float((k[3][0] + k[4][0]) / 2 / w), float((k[3][1] + k[4][1]) / 2 / h)]}
    from depth.protocol import DepthProtocolError

    try:
        sig = await svc._run(ctx, ctx.depth.submit, form.get("meta"), raw,
                             None if box is meta.face_box_norm else box,
                             None if lms is meta.landmarks_norm else lms)
    except DepthProtocolError as exc:
        raise ApiError("VALIDATION_ERROR", str(exc), meta.attempt_id) from exc
    ctx.depth.mark_arrived(meta.attempt_id, meta.phase)
    return {"accepted": True, "attempt_id": meta.attempt_id, "phase": meta.phase, "checks": sig.model_dump()}


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
app = create_app()
