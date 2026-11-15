"""Optional Rekognition Face Liveness step-up (never on the 2 s path).

POST /v1/liveness/session -> CreateFaceLivenessSession (single use, expires after 3 min).
GET  /v1/liveness/session/{id}/result -> GetFaceLivenessSessionResults, then a 1:1 check of the reference
image against the claimed user. verified = SUCCEEDED and confidence >= challenge.face_liveness_min_confidence
(80) and similarity >= match.rekognition.allow_min_similarity (99). Quotas: 5 TPS and 15 concurrent
sessions (ap-south-1 defaults; us-east-1 allows 25 / 75) enforced client-side. The confidence goes to
the edge only; the kiosk screen must show pass/fail only (AWS guidance).
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

from ..clock import Clock, epoch_s, iso_z
from ..errors import ApiError
from ..thresholds import CloudThresholds
from .adapters import ConcurrencyGauge, TokenBucket
from .faces import FaceError
from .kv import KV
from .match_service import MatchService

NS_LIVE = "liveness"
CHALLENGES = {"FaceMovementAndLightChallenge", "FaceMovementChallenge"}


class LivenessService:
    def __init__(self, faces, kv: KV, match: MatchService, thresholds: CloudThresholds, clock: Clock, *,
                 tps: float, max_concurrent: int, region: str, s3_bucket: str | None, kms_key_id: str | None,
                 backend: str) -> None:
        self.faces = faces
        self.kv = kv
        self.match = match
        self.t = thresholds
        self.clock = clock
        self.bucket = TokenBucket(tps)
        self.gauge = ConcurrencyGauge(max_concurrent)
        self.region = region
        self.s3_bucket = s3_bucket
        self.kms = kms_key_id
        self.backend = backend

    def _check(self) -> None:
        if self.backend == "disabled" or getattr(self.faces, "name", "") == "disabled":
            raise ApiError("CLOUD_UNAVAILABLE", "Face Liveness disabled; use challenge + TOTP/staff/card")
        if self.bucket.try_acquire(max_wait_s=0.5) is None:
            raise ApiError("RATE_LIMITED", "Face Liveness TPS quota")

    def create(self, *, attempt_id: str, kiosk_id: str, user_id: str, challenge: str) -> dict:
        if challenge not in CHALLENGES:
            raise ApiError("VALIDATION_ERROR", f"challenge must be one of {sorted(CHALLENGES)}")
        self._check()
        if not self.gauge.try_open(attempt_id):
            raise ApiError("RATE_LIMITED", "too many concurrent Face Liveness sessions (quota 15)")
        try:
            sid = self.faces.create_liveness_session(
                token=attempt_id, challenge=challenge, s3_bucket=self.s3_bucket,
                s3_prefix=f"liveness/{attempt_id}/", kms_key_id=self.kms, user_hint=user_id)
        except FaceError as e:
            self.gauge.close(attempt_id)
            raise ApiError("CLOUD_UNAVAILABLE", e.message, attempt_id=attempt_id) from e
        now = self.clock.now()
        expires = now + timedelta(minutes=3)
        self.kv.put(NS_LIVE, sid, {"session_id": sid, "attempt_id": attempt_id, "kiosk_id": kiosk_id,
                                   "user_id": user_id, "created_at": iso_z(now)}, ttl=epoch_s(expires) + 600)
        return {"session_id": sid, "region": self.region, "expires_at": iso_z(expires)}

    async def result(self, session_id: str, kiosk_id: str, blobs) -> dict:
        sess = await asyncio.to_thread(self.kv.get, NS_LIVE, session_id)  # blocking store call: off the event loop
        if sess is None or sess.get("kiosk_id") != kiosk_id:
            raise ApiError("NOT_FOUND", "unknown liveness session")
        self._check()
        try:
            r = await asyncio.to_thread(self.faces.get_liveness_results, session_id)
        except FaceError as e:
            raise ApiError("CLOUD_UNAVAILABLE", e.message) from e
        if r.status in {"SUCCEEDED", "FAILED", "EXPIRED"}:
            self.gauge.close(sess["attempt_id"])
        conf = r.confidence
        live = r.status == "SUCCEEDED" and conf is not None and conf >= self.t.face_liveness_min_confidence
        sim = None
        ref = r.reference_bytes
        if ref is None and r.reference_s3 is not None:
            ref = await asyncio.to_thread(blobs.get, r.reference_s3[1], r.reference_s3[0])
        if live and ref:
            out = await self.match.match(attempt_id=sess["attempt_id"], image=ref, mode="1:1",
                                         claimed_user_id=sess["user_id"], max_users=1)
            sim = out.similarity if out.user_id == sess["user_id"] else None
        verified = bool(live and sim is not None and sim >= self.t.allow_min_similarity)
        return {"session_id": session_id, "status": r.status, "confidence": conf, "live": live,
                "compare_similarity": sim, "verified": verified}

    async def verify_for_enrolment(self, session_id: str, kiosk_id: str, user_id: str, frames: list[bytes],
                                   blobs) -> float:
        """Optional enrolment gate (POST /v1/enroll liveness_session_id). The session must belong to this kiosk
        AND this user_id, is single-use (consumed by a CAS before evaluation, pass or fail), must be live, and
        its reference image must match the first enrolment frame (CompareFaces >= allow_min_similarity). A 1:1
        search against the user's gallery cannot work here: a first-time user has no faces yet."""
        sess = await asyncio.to_thread(self.kv.get, NS_LIVE, session_id)
        if sess is None or sess.get("kiosk_id") != kiosk_id:
            raise ApiError("NOT_FOUND", "unknown liveness session")
        if sess.get("user_id") != user_id:
            raise ApiError("FORBIDDEN", "liveness session was created for another user_id")
        if sess.get("consumed_at"):
            raise ApiError("FORBIDDEN", "liveness session already used")
        now = self.clock.now()
        rev = sess.pop("_rev", None)
        if not await asyncio.to_thread(self.kv.cas, NS_LIVE, session_id, {**sess, "consumed_at": iso_z(now)}, rev,
                                       epoch_s(now) + 600):
            raise ApiError("FORBIDDEN", "liveness session already used")
        self._check()
        try:
            r = await asyncio.to_thread(self.faces.get_liveness_results, session_id)
        except FaceError as e:
            raise ApiError("CLOUD_UNAVAILABLE", e.message) from e
        if r.status in {"SUCCEEDED", "FAILED", "EXPIRED"}:
            self.gauge.close(sess["attempt_id"])
        live = r.status == "SUCCEEDED" and r.confidence is not None and \
            r.confidence >= self.t.face_liveness_min_confidence
        ref = r.reference_bytes
        if ref is None and r.reference_s3 is not None:
            ref = await asyncio.to_thread(blobs.get, r.reference_s3[1], r.reference_s3[0])
        if not live or not ref or not frames:
            raise ApiError("FORBIDDEN", "enrolment liveness session not verified")
        try:
            sim = await asyncio.to_thread(self.faces.compare_faces, ref, frames[0], self.t.allow_min_similarity,
                                          self.t.quality_filter)
        except FaceError as e:
            raise ApiError("CLOUD_UNAVAILABLE", e.message) from e
        if sim is None or sim < self.t.allow_min_similarity:
            raise ApiError("FORBIDDEN", "enrolment frames do not match the liveness session face")
        return float(sim)
