"""POST /v1/match - Rekognition 1:N (SearchUsersByImage) or 1:1 (claimed_user_id).

Budget: the whole server-side match must finish within MATCH_BUDGET_MS (default 900 ms; the edge has
its own timeout and falls back to its local matcher, which stays primary). Quotas: a token bucket caps
SearchUsersByImage at REKOGNITION_SEARCH_TPS (5 = ap-south-1 default; us-east-1 allows 50) and
CompareFaces at 25 TPS. Throttling -> ONE jittered retry if the remaining budget allows, else
503 UPSTREAM_THROTTLED. Thresholds (UserMatchThreshold 80, QualityFilter AUTO) come from
config/thresholds.yaml `match.rekognition`.
1:1: CompareFaces against the stored enrolment reference when ENROLL_STORE_REFERENCE=true (off by
default: no face images stored); otherwise SearchUsersByImage and read the claimed user's similarity.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import random
import time
from dataclasses import dataclass

from ..errors import ApiError
from ..metrics import Metrics
from ..thresholds import CloudThresholds
from .adapters import TokenBucket
from .faces import FaceError, SearchResult
from .kv import KV

log = logging.getLogger("hid.cloud.match")


@dataclass
class MatchOutcome:
    matched: bool
    user_id: str | None
    similarity: float | None
    runner_up_user_id: str | None
    runner_up_similarity: float | None
    face_detected: bool


def decode_image(image_b64: str) -> bytes:
    s = image_b64.strip()
    if s.startswith("data:") and "," in s:
        s = s.split(",", 1)[1]
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ApiError("VALIDATION_ERROR", "image_b64 is not valid base64") from exc


class MatchService:
    def __init__(self, faces, kv: KV, thresholds: CloudThresholds, metrics: Metrics, *, budget_ms: int,
                 search_tps: float, compare_tps: float, blobs=None, store_reference: bool = False,
                 user_status_fn=None) -> None:
        self.faces = faces
        self.kv = kv
        self.t = thresholds
        self.metrics = metrics
        self.budget_ms = budget_ms
        self.search_bucket = TokenBucket(search_tps)
        self.compare_bucket = TokenBucket(compare_tps)
        self.blobs = blobs
        self.store_reference = store_reference
        self.user_status_fn = user_status_fn

    async def _call(self, bucket: TokenBucket, fn, deadline: float, attempt_id: str):
        """Run a blocking Rekognition call within the deadline; one jittered retry on throttling."""
        for attempt in (1, 2):
            remaining = deadline - time.monotonic()
            wait = bucket.try_acquire(max_wait_s=min(0.15, max(0.0, remaining - 0.25)))
            if wait is None:
                self.metrics.count("RekognitionThrottled", Where="client")
                raise ApiError("UPSTREAM_THROTTLED", "rekognition quota (client-side token bucket)",
                               attempt_id=attempt_id)
            if wait:
                await asyncio.sleep(wait)
            remaining = deadline - time.monotonic()
            if remaining <= 0.05:
                raise ApiError("CLOUD_UNAVAILABLE", "match budget exhausted", attempt_id=attempt_id)
            try:
                return await asyncio.wait_for(asyncio.to_thread(fn), timeout=remaining)
            except TimeoutError as exc:
                raise ApiError("CLOUD_UNAVAILABLE", "rekognition timeout (match budget)",
                               attempt_id=attempt_id) from exc
            except FaceError as e:
                if e.kind == "THROTTLED":
                    self.metrics.count("RekognitionThrottled", Where="service")
                    jitter = random.uniform(0.05, 0.15)
                    if attempt == 1 and deadline - time.monotonic() > jitter + 0.25:
                        await asyncio.sleep(jitter)
                        continue
                    raise ApiError("UPSTREAM_THROTTLED", "rekognition throttled", attempt_id=attempt_id) from e
                if e.kind in {"INVALID_IMAGE", "INVALID_PARAMETER"}:
                    raise ApiError("VALIDATION_ERROR", f"image rejected: {e.message}", attempt_id=attempt_id) from e
                raise ApiError("CLOUD_UNAVAILABLE", e.message, attempt_id=attempt_id) from e
        raise ApiError("UPSTREAM_THROTTLED", "rekognition throttled", attempt_id=attempt_id)

    async def match(self, *, attempt_id: str, image: bytes, mode: str, claimed_user_id: str | None,
                    max_users: int) -> MatchOutcome:
        if getattr(self.faces, "name", "") == "disabled":
            raise ApiError("CLOUD_UNAVAILABLE", "face matching disabled in this deployment (FACE_BACKEND=disabled)",
                           attempt_id=attempt_id)
        t0 = time.monotonic()
        deadline = t0 + self.budget_ms / 1000.0
        thr = self.t.user_match_threshold
        qf = self.t.quality_filter
        one_to_one = mode == "1:1" or claimed_user_id is not None
        try:
            if one_to_one:
                if not claimed_user_id:
                    raise ApiError("VALIDATION_ERROR", "claimed_user_id required for mode 1:1", attempt_id=attempt_id)
                out = await self._one_to_one(attempt_id, image, claimed_user_id, thr, qf, deadline)
            else:
                res: SearchResult = await self._call(
                    self.search_bucket,
                    lambda: self.faces.search_users_by_image(image, thr, max_users, qf),
                    deadline, attempt_id)
                top = res.matches[0] if res.matches else None
                ru = res.matches[1] if len(res.matches) > 1 else None
                out = MatchOutcome(matched=top is not None and top.similarity >= thr,
                                   user_id=top.user_id if top else None,
                                   similarity=round(top.similarity, 3) if top else None,
                                   runner_up_user_id=ru.user_id if ru else None,
                                   runner_up_similarity=round(ru.similarity, 3) if ru else None,
                                   face_detected=res.face_detected)
            self.metrics.count("MatchCalls", Result="matched" if out.matched else "no_match",
                               Mode="1:1" if one_to_one else "1:N")
            return out
        finally:
            self.metrics.put("MatchLatencyMs", (time.monotonic() - t0) * 1000.0, Mode="1:1" if one_to_one else "1:N")

    async def _one_to_one(self, attempt_id: str, image: bytes, claimed: str, thr: float, qf: str,
                          deadline: float) -> MatchOutcome:
        user = await asyncio.to_thread(self.kv.get, "users", claimed)
        if user is None or not user.get("face_ids"):
            return MatchOutcome(False, None, None, None, None, face_detected=True)
        ref = None
        if self.store_reference and self.blobs is not None and user.get("reference_key"):
            ref = await asyncio.to_thread(self.blobs.get, user["reference_key"])
        if ref:
            sim = await self._call(self.compare_bucket,
                                   lambda: self.faces.compare_faces(image, ref, thr, qf), deadline, attempt_id)
            return MatchOutcome(sim is not None and sim >= thr, claimed if sim is not None else None,
                                round(sim, 3) if sim is not None else None, None, None, face_detected=True)
        res: SearchResult = await self._call(
            self.search_bucket, lambda: self.faces.search_users_by_image(image, thr, 5, qf), deadline, attempt_id)
        mine = next((m for m in res.matches if m.user_id == claimed), None)
        other = next((m for m in res.matches if m.user_id != claimed), None)
        return MatchOutcome(
            matched=mine is not None and mine.similarity >= thr,
            user_id=claimed if mine else None,
            similarity=round(mine.similarity, 3) if mine else None,
            runner_up_user_id=other.user_id if other else None,
            runner_up_similarity=round(other.similarity, 3) if other else None,
            face_detected=res.face_detected,
        )
