"""Cloud endpoints (docs/API.md §4): health, match, enroll/erase, schedule bundle, revocations, sync, OTP,
Face Liveness. Thin handlers; logic lives in services."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from ..clock import iso_z, parse_ts
from ..config import APP_VERSION
from ..errors import ApiError
from ..schemas import (
    EnrollJson,
    EnrollMeta,
    EnrollResponse,
    EraseResponse,
    HealthResponse,
    LivenessResultResponse,
    LivenessSessionRequest,
    LivenessSessionResponse,
    MatchRequest,
    MatchResponse,
    OtpSendRequest,
    OtpSendResponse,
    OtpVerifyRequest,
    OtpVerifyResponse,
    RevocationsResponse,
    ScheduleCheckRequest,
    ScheduleCheckResponse,
)
from ..services.match_service import decode_image
from ..services.schedule_service import UnknownKiosk
from ..services.sync_service import ItemRejected
from .deps import KioskDep, SvcDep

router = APIRouter()
STARTED = time.time()


def _validation(exc: ValidationError) -> ApiError:
    parts = [f"{'.'.join(str(p) for p in e.get('loc', ()))}: {e.get('msg')}" for e in exc.errors()[:5]]
    return ApiError("VALIDATION_ERROR", "; ".join(parts))


# ---------------------------------------------------------------- health (public, cached, fast)
@router.get("/health", response_model=HealthResponse, include_in_schema=False)
@router.get("/v1/health", response_model=HealthResponse)
async def health(svc: SvcDep) -> HealthResponse:
    snap = svc.health.snapshot
    bad = {"error", "creds_expired", "timeout"}
    degraded = snap.get("rekognition") in bad or snap.get("store") in bad
    return HealthResponse(
        status="degraded" if degraded else "ok",
        rekognition=snap.get("rekognition", "unknown"),
        dynamodb=snap.get("dynamodb", "unknown"),
        region=svc.settings.region,
        store=f"{svc.settings.store_backend}:{snap.get('store', 'unknown')}",
        face_backend=svc.settings.face_backend,
        email_backend=svc.settings.email_backend,
        policy="ok" if svc.policy.available else "unavailable",
        version=APP_VERSION,
        uptime_s=int(time.time() - STARTED),
        server_time=iso_z(datetime.now(UTC)),
        checked_at=iso_z(datetime.fromtimestamp(svc.health.checked_at, UTC)) if svc.health.checked_at else None,
    )


# ---------------------------------------------------------------- match
@router.post("/v1/match", response_model=MatchResponse)
async def match(req: MatchRequest, svc: SvcDep, kiosk_id: KioskDep) -> MatchResponse:
    t0 = time.perf_counter()
    if req.kiosk_id != kiosk_id:
        raise ApiError("FORBIDDEN", "kiosk_id must match X-Kiosk-Id", attempt_id=req.attempt_id)
    image = decode_image(req.image_b64)
    out = await svc.match.match(attempt_id=req.attempt_id, image=image, mode=req.mode,
                                claimed_user_id=req.claimed_user_id, max_users=req.max_users)
    status = None
    if out.user_id:
        rec = await asyncio.to_thread(svc.schedule.current)
        u = (rec["doc"].get("users") or {}).get(out.user_id) or {}
        row = await asyncio.to_thread(svc.kv.get, "users", out.user_id) or {}
        status = "REVOKED" if u.get("revoked") else (row.get("status") or ("ACTIVE" if u else None))
    return MatchResponse(attempt_id=req.attempt_id, matched=out.matched, user_id=out.user_id,
                         similarity=out.similarity, runner_up_user_id=out.runner_up_user_id,
                         runner_up_similarity=out.runner_up_similarity, face_detected=out.face_detected,
                         source="fake" if svc.faces.name == "fake" else "rekognition", user_status=status,
                         latency_ms=int((time.perf_counter() - t0) * 1000))


# ---------------------------------------------------------------- enrolment / erasure
async def _enroll_inputs(request: Request) -> tuple[EnrollMeta, list[bytes]]:
    ctype = request.headers.get("content-type", "")
    try:
        if ctype.startswith("multipart/form-data"):
            form = await request.form()
            if "meta" not in form:
                raise ApiError("VALIDATION_ERROR", "multipart part 'meta' (JSON) required")
            meta = EnrollMeta.model_validate(json.loads(str(form["meta"])))
            frames = []
            for name in sorted((k for k in form if k.startswith("frame_")), key=lambda k: int(k[6:] or 0)):
                part = form[name]
                frames.append(await part.read() if hasattr(part, "read") else bytes(str(part), "latin-1"))
            if not frames:
                raise ApiError("VALIDATION_ERROR", "at least one frame_N part required")
            return meta, frames
        body = EnrollJson.model_validate_json(await request.body())
        return EnrollMeta.model_validate(body.model_dump(exclude={"images_b64"})), \
            [decode_image(b) for b in body.images_b64]
    except ValidationError as exc:
        raise _validation(exc) from exc
    except (json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, ApiError):
            raise
        raise ApiError("VALIDATION_ERROR", "invalid enrolment body") from exc


@router.post("/v1/enroll", response_model=EnrollResponse, status_code=201)
async def enroll(request: Request, svc: SvcDep, kiosk_id: KioskDep) -> EnrollResponse:
    meta, frames = await _enroll_inputs(request)
    if meta.liveness_session_id:
        await svc.liveness.verify_for_enrolment(meta.liveness_session_id, kiosk_id, meta.user_id, frames, svc.blobs)
    out = await asyncio.to_thread(svc.enroll.enroll, meta.model_dump(), frames, kiosk_id=kiosk_id)
    return EnrollResponse(**out)


@router.delete("/v1/enroll/{user_id}", response_model=EraseResponse)
async def erase(user_id: str, svc: SvcDep, kiosk_id: KioskDep) -> EraseResponse:
    out = await asyncio.to_thread(svc.enroll.erase, user_id, kiosk_id=kiosk_id)
    return EraseResponse(**out)


# ---------------------------------------------------------------- schedule + revocations
@router.get("/v1/schedule/{kiosk_id}")
async def schedule_bundle(kiosk_id: str, request: Request, svc: SvcDep, auth_kiosk: KioskDep) -> Response:
    if kiosk_id != auth_kiosk:
        raise ApiError("FORBIDDEN", "a kiosk may only fetch its own bundle")
    try:
        bundle, etag = await asyncio.to_thread(svc.schedule.signed_bundle, kiosk_id)
    except UnknownKiosk as exc:
        raise ApiError("NOT_FOUND", "unknown kiosk_id in schedule") from exc
    inm = request.headers.get("if-none-match", "")
    tags = {t.strip().removeprefix("W/").strip() for t in inm.split(",") if t.strip()}
    version = str(bundle["bundle_version"])
    if etag in tags or version in tags or f'"{version}"' in tags:
        return Response(status_code=304, headers={"ETag": etag, "X-Bundle-Version": version})
    return JSONResponse(bundle, headers={"ETag": etag, "X-Bundle-Version": version, "Cache-Control": "no-store"})


@router.post("/v1/schedule/check", response_model=ScheduleCheckResponse)
async def schedule_check(req: ScheduleCheckRequest, svc: SvcDep, kiosk_id: KioskDep) -> ScheduleCheckResponse:
    """Online authoritative SC1 check (DECISION_POLICY §11 ctx.cloud.schedule_check): same evaluator."""
    zone = req.zone or await asyncio.to_thread(svc.schedule.kiosk_zone, kiosk_id)
    if not zone:
        raise ApiError("NOT_FOUND", "kiosk has no zone in schedule")
    try:
        t0 = parse_ts(req.t0) if req.t0 else datetime.now(UTC)
    except ValueError as exc:
        raise ApiError("VALIDATION_ERROR", "t0 must be ISO-8601 with timezone") from exc
    if not svc.policy.available:
        raise ApiError("CLOUD_UNAVAILABLE", "schedule evaluator unavailable")
    rec = await asyncio.to_thread(svc.schedule.current)
    try:
        result = svc.schedule.evaluate(req.user_id, zone, t0, rec["doc"])
    except KeyError as exc:
        raise ApiError("NOT_FOUND", f"unknown zone {zone}") from exc
    return ScheduleCheckResponse(user_id=req.user_id, zone=zone, result=result,
                                 bundle_version=int(rec["version"]),
                                 revocations_version=int(rec["doc"].get("revocations_version", 0)),
                                 evaluated_at=iso_z(t0), evaluator=svc.policy.source)


@router.get("/v1/revocations", response_model=RevocationsResponse)
async def revocations(svc: SvcDep, kiosk_id: KioskDep, since: int = Query(0, ge=0)) -> RevocationsResponse:
    seq, items = await asyncio.to_thread(svc.schedule.revocations_since, since)
    return RevocationsResponse(as_of=iso_z(datetime.now(UTC)), revocation_seq=seq, items=items)


# ---------------------------------------------------------------- sync
@router.post("/v1/sync")
async def sync(request: Request, svc: SvcDep, kiosk_id: KioskDep,
               verbose: bool = Query(False, description="add alerts/acks/conflicts (dashboard/debug)")) -> JSONResponse:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ApiError("VALIDATION_ERROR", "body must be JSON") from exc
    if not isinstance(body, dict):
        raise ApiError("VALIDATION_ERROR", "body must be a JSON object")
    try:
        out = await asyncio.to_thread(svc.sync.ingest, body, kiosk_id, request.headers.get("idempotency-key"),
                                      verbose)
    except ItemRejected as rej:
        raise ApiError("FORBIDDEN" if rej.error == "FORBIDDEN" else "VALIDATION_ERROR", rej.detail) from rej
    return JSONResponse(out)


# ---------------------------------------------------------------- OTP (SES e-mail)
@router.post("/v1/otp/send", response_model=OtpSendResponse, status_code=201)
async def otp_send(req: OtpSendRequest, svc: SvcDep, kiosk_id: KioskDep) -> OtpSendResponse:
    out = await asyncio.to_thread(svc.otp.send, attempt_id=req.attempt_id, user_id=req.user_id, channel=req.channel)
    return OtpSendResponse(**out)


@router.post("/v1/otp/verify", response_model=OtpVerifyResponse)
async def otp_verify(req: OtpVerifyRequest, svc: SvcDep, kiosk_id: KioskDep) -> OtpVerifyResponse:
    out = await asyncio.to_thread(svc.otp.verify, otp_id=req.otp_id, attempt_id=req.attempt_id, code=req.code)
    return OtpVerifyResponse(**out)


# ---------------------------------------------------------------- Face Liveness (optional step-up)
@router.post("/v1/liveness/session", response_model=LivenessSessionResponse, status_code=201)
async def liveness_session(req: LivenessSessionRequest, svc: SvcDep, kiosk_id: KioskDep) -> LivenessSessionResponse:
    if req.kiosk_id != kiosk_id:
        raise ApiError("FORBIDDEN", "kiosk_id must match X-Kiosk-Id", attempt_id=req.attempt_id)
    out = await asyncio.to_thread(svc.liveness.create, attempt_id=req.attempt_id, kiosk_id=kiosk_id,
                                  user_id=req.user_id, challenge=req.challenge)
    return LivenessSessionResponse(**out)


@router.get("/v1/liveness/session/{session_id}/result", response_model=LivenessResultResponse)
async def liveness_result(session_id: str, svc: SvcDep, kiosk_id: KioskDep) -> LivenessResultResponse:
    return LivenessResultResponse(**await svc.liveness.result(session_id, kiosk_id, svc.blobs))
