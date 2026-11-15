"""POST /v1/enroll and DELETE /v1/enroll/{user_id} (consenting team members only; DPDP erasure).

Enrol APPENDS, like the edge template cache (edge/ml/templates.py; glasses on / off both match):
IndexFaces per frame (MaxFaces 1, QualityFilter AUTO, ExternalImageId=user_id) -> validate -> CreateUser
(idempotent) -> AssociateFaces(new faces only). The user's existing faces are never touched before the new
ones are associated, so a failed (re-)enrolment changes nothing: faces indexed by the failed call are
disassociated / deleted again. A user that already has faces only accepts new faces Rekognition matches to
it (AssociateFaces UserMatchThreshold = match.rekognition.user_match_threshold), so a different face cannot
be appended (409). Cap per user ENROLL_MAX_FACES_PER_USER (24; Rekognition allows 100): the first
ENROLL_PINNED_FACES (5, the original enrolment) always stay, the newest of the rest are kept, evicted faces
are disassociated + deleted (best effort). There is no replace path: DELETE (erase), then enrol.
No face image is stored unless ENROLL_STORE_REFERENCE=true (then one reference JPEG goes to S3 SSE-KMS,
lifecycle <= 7 days, for 1:1 CompareFaces). The user row keeps e-mail (for SES OTP), consent record, face ids
(oldest first), the card hash (the edge sends card_id_hash; a raw card_id is hashed here) and the edge's
"TOTP provisioned" flag. The cloud never mints a TOTP seed (the edge owns TOTP secrets).
Role: the request's role is echoed (requested_role) but never applied; the signed schedule decides
(PUT /v1/admin/users/{user_id}/access). A successful enrolment updates the schedule user's fallback flags and
lifts an ERASED suspension (consent re-recorded), publishing only when something changes.
Erase: row face ids + ListFaces(user) -> DeleteUser + DeleteFaces + row + reference image; the schedule entry
stays, suspended by an ERASED revocation until the user enrols again (ScheduleService.erase_user).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import uuid
from typing import Any

from ..clock import Clock, iso_z
from ..errors import ApiError
from .faces import Association, FaceError
from .kv import KV
from .schedule_service import ScheduleService

log = logging.getLogger("hid.cloud.enroll")

USER_ID_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}\.[A-Za-z]{2,}$")
PURPOSE = "campus access control at HID kiosk (hackathon demo)"


def card_hash(pepper: str, card_id: str) -> str:
    """config/schedule.example.json card_id_hash_scheme: HMAC-SHA256(key=CARD_ID_PEPPER, msg=card_id).hex()"""
    return hmac.new(pepper.encode("utf-8"), card_id.encode("utf-8"), hashlib.sha256).hexdigest()


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    return (local[:1] + "*" * max(1, len(local) - 1)) + "@" + domain


def _face_error(e: FaceError) -> ApiError:
    if e.kind in {"INVALID_IMAGE", "INVALID_PARAMETER"}:  # e.g. image < 80 px, no usable face: client error
        return ApiError("VALIDATION_ERROR", f"frame rejected: {e.message}")
    if e.kind == "THROTTLED":
        return ApiError("UPSTREAM_THROTTLED", "rekognition throttled during enrolment; retry")
    return ApiError("CLOUD_UNAVAILABLE", e.message)


def _refused(uid: str, assoc: Association, n_new: int) -> ApiError:
    reasons = sorted({r for rs in assoc.unsuccessful.values() for r in rs})
    if "LOW_MATCH_CONFIDENCE" in reasons:
        return ApiError("INVALID_STATE", f"new enrolment frames do not match the enrolled {uid} "
                                         f"({len(assoc.unsuccessful)} of {n_new} faces LOW_MATCH_CONFIDENCE); "
                                         "existing faces kept, erase the user to replace")
    return ApiError("CLOUD_UNAVAILABLE", f"rekognition associated too few new faces "
                                         f"({', '.join(reasons) or 'no reason given'}); nothing changed, retry")


def plan_eviction(face_ids: list[str], cap: int, pinned: int) -> tuple[list[str], list[str]]:
    """(keep, evict) for an oldest-first face list; same rule as edge/ml/templates.py: the first `pinned`
    (the original enrolment) always stay, the newest of the rest fill the cap."""
    if len(face_ids) <= cap:
        return list(face_ids), []
    head, rest = face_ids[:pinned], face_ids[pinned:]
    cut = len(rest) - max(0, cap - len(head))
    return head + rest[cut:], rest[:cut]


class EnrollService:
    def __init__(self, faces, kv: KV, schedule: ScheduleService, secretbox, blobs, clock: Clock, *,
                 card_pepper: str, quality_filter: str, min_faces: int, store_reference: bool,
                 search_bucket=None, match_threshold: float | None = None, max_faces: int = 24,
                 pinned_faces: int = 5) -> None:
        self.faces = faces
        self.kv = kv
        self.schedule = schedule
        self.box = secretbox
        self.blobs = blobs
        self.clock = clock
        self.card_pepper = card_pepper
        self.qf = quality_filter
        self.min_faces = min_faces
        self.store_reference = store_reference
        self.bucket = search_bucket
        self.match_threshold = match_threshold
        self.max_faces = max_faces
        self.pinned_faces = pinned_faces

    def _throttle(self) -> None:
        if self.bucket is not None:
            import time

            wait = self.bucket.try_acquire(max_wait_s=2.0)
            if wait is None:
                raise ApiError("UPSTREAM_THROTTLED", "enrolment rate limit")
            if wait:
                time.sleep(wait)

    def _current_faces(self, uid: str, old: dict | None) -> list[str]:
        """The user's faces in Rekognition (authoritative), oldest first: the row's order (pinning) for faces
        that still exist, then any the row does not know (e.g. a concurrent enrolment)."""
        try:
            listed = self.faces.list_user_faces(uid)
        except FaceError as e:
            if e.kind != "NOT_FOUND":
                raise
            listed = []
        present = set(listed)
        known = [f for f in (old or {}).get("face_ids") or [] if f in present]
        return known + [f for f in listed if f not in set(known)]

    def _delete_quiet(self, uid: str, face_ids: list[str]) -> None:
        """Delete unassociated faces; best effort, never raises (cleanup must not mask the original error)."""
        if not face_ids:
            return
        try:
            deleted = set(self.faces.delete_faces(face_ids))
        except Exception as e:  # cleanup must never mask the original error
            log.warning("enroll %s: DeleteFaces failed (%s)", uid, getattr(e, "kind", type(e).__name__))
            deleted = set()
        left = [f for f in face_ids if f not in deleted]
        if left:
            log.warning("enroll %s: %d face(s) not deleted, remove manually (teardown deletes the collection): %s",
                        uid, len(left), ",".join(left))

    def _discard(self, uid: str, new_ids: list[str], added: list[str], token: str) -> None:
        """Undo THIS call's faces: disassociate the ones already on the user, then delete them all. The user's
        older faces are never touched. Best effort, never raises."""
        if added:
            try:
                self.faces.disassociate_faces(uid, added, token + "u")
            except Exception as e:  # cleanup must never mask the original error
                log.warning("enroll %s: DisassociateFaces (undo) failed (%s)", uid,
                            getattr(e, "kind", type(e).__name__))
        self._delete_quiet(uid, new_ids)

    def _evict(self, uid: str, evict: list[str], token: str) -> list[str]:
        """Faces beyond the cap: disassociate + delete. Best effort: on failure the user stays above the cap
        until the next enrolment retries. Returns the faces no longer on the user."""
        try:
            gone = self.faces.disassociate_faces(uid, evict, token + "x")
        except Exception as e:  # housekeeping only: the enrolment already succeeded
            log.warning("enroll %s: evicting %d face(s) failed (%s); retried at the next enrolment",
                        uid, len(evict), getattr(e, "kind", type(e).__name__))
            return []
        self._delete_quiet(uid, gone)
        log.info("enroll %s: evicted %d face(s) beyond the cap of %d", uid, len(gone), self.max_faces)
        return gone

    @staticmethod
    def totp_flag(meta: dict[str, Any]) -> bool | None:
        """The edge's explicit totp_enrolled wins; else provision_totp=true means the enrolling kiosk provisioned
        a TOTP secret (edge/enroll.py). None = unknown -> the schedule flag is left as it is."""
        if meta.get("totp_enrolled") is not None:
            return bool(meta["totp_enrolled"])
        return True if meta.get("provision_totp") else None

    def _build_row(self, uid: str, meta: dict[str, Any], old: dict | None, face_ids: list[str],
                   best: bytes) -> tuple[dict, str | None]:
        """(user row, card hash of this request). No TOTP seed is minted: the edge owns TOTP secrets."""
        now = iso_z(self.clock.now())
        seed_enc = old.get("totp_seed_enc") if old else None  # legacy rows only; never read
        chash = meta.get("card_id_hash") or (
            card_hash(self.card_pepper, meta["card_id"]) if meta.get("card_id") and self.card_pepper else None)
        totp = self.totp_flag(meta)
        ref_key = None
        if self.store_reference:
            ref_key = f"enroll/{uid}/reference.jpg"
            try:
                self.blobs.put(ref_key, best, "image/jpeg")
            except Exception:
                ref_key = None
        row = {
            "user_id": uid,
            "display_name": meta["display_name"],
            # optional; a re-enrolment without one keeps the e-mail already on file
            "email": meta.get("email") or (old.get("email") if old else None),
            "groups": list(meta.get("groups") or []),
            "status": "ACTIVE",
            "rekognition_user_id": uid,
            "face_ids": face_ids,  # every face on the user, oldest first (the first pinned_faces are never evicted)
            "consent": {"given": True, "version": meta["consent_version"], "given_at": now, "purpose": PURPOSE},
            "card_id_hash": chash or (old.get("card_id_hash") if old else None),
            "totp_enrolled": totp if totp is not None else bool(old.get("totp_enrolled")) if old else False,
            "totp_seed_enc": seed_enc,
            "reference_key": ref_key,
            "template_version": int(old.get("template_version", 0)) + 1 if old else 1,
            "created_at": old.get("created_at", now) if old else now,
            "updated_at": now,
        }
        return row, chash

    def enroll(self, meta: dict[str, Any], frames: list[bytes], *, kiosk_id: str | None = None) -> dict:
        if getattr(self.faces, "name", "") == "disabled":
            raise ApiError("CLOUD_UNAVAILABLE", "enrolment needs Rekognition (FACE_BACKEND=disabled)")
        uid = meta["user_id"]
        token = uuid.uuid4().hex
        old = self.kv.get("users", uid)
        new_ids: list[str] = []  # faces indexed by THIS call: the only ones a failure may remove
        added: list[str] = []  # ... of which Rekognition associated with the user
        image_of: dict[str, bytes] = {}
        rejected = 0
        try:
            existing = self._current_faces(uid, old)
            for i, img in enumerate(frames):
                self._throttle()
                fid = self.faces.index_face(img, uid, self.qf)
                if fid:
                    new_ids.append(fid)
                    image_of[fid] = img
                else:
                    rejected += 1
                log.info("enroll %s frame %d -> %s", uid, i, "indexed" if fid else "no usable face")
            need = max(1, self.min_faces)
            if len(new_ids) < need:
                raise ApiError("VALIDATION_ERROR", f"no usable face in frames ({len(new_ids)} < {need}, "
                                                   f"{rejected} rejected by QualityFilter); nothing changed")
            self.faces.create_user(uid, token + "c")  # idempotent (ConflictException = exists)
            assoc = self.faces.associate_faces(uid, new_ids, token + "a", match_threshold=self.match_threshold)
            accepted = set(assoc.associated)
            added = [f for f in new_ids if f in accepted]
            if len(added) < need:
                raise _refused(uid, assoc, len(new_ids))
            row, chash = self._build_row(uid, meta, old, existing + added, image_of[added[0]])
            self.kv.put("users", uid, row)
        except Exception as exc:  # undo THIS call's faces whatever failed; the user's older faces stay
            self._discard(uid, new_ids, added, token)
            if isinstance(exc, FaceError):
                raise _face_error(exc) from exc
            raise
        # Enrolled: the row lists every face on the user. Best-effort housekeeping from here on.
        refused = [f for f in new_ids if f not in set(added)]
        if refused:
            log.info("enroll %s: %d new face(s) not associated: %s", uid, len(refused),
                     sorted({r for f in refused for r in assoc.unsuccessful.get(f, [])}))
            self._delete_quiet(uid, refused)
        _, evict = plan_eviction(row["face_ids"], self.max_faces, self.pinned_faces)
        gone = set(self._evict(uid, evict, token)) if evict else set()
        if gone:
            row["face_ids"] = [f for f in row["face_ids"] if f not in gone]
            try:
                self.kv.put("users", uid, row)
            except Exception:
                log.warning("enroll %s: face list not updated after eviction (reconciled at the next enrolment)", uid)
        sched = self.schedule.record_enrolment(uid, totp_enrolled=self.totp_flag(meta), card_id_hash=chash,
                                               kiosk_id=kiosk_id)
        requested = meta.get("role")
        out = {
            "user_id": uid,
            "rekognition_user_id": uid,
            "face_ids": row["face_ids"],
            "faces_indexed": len(added),  # new faces added by this call
            "frames_rejected": rejected + len(refused),
            "template_version": row["template_version"],
            "local_cache_updated": False,
            "schedule_entitlement": bool(sched["in_schedule"]),
            "bundle_version": sched["bundle_version"],
            "totp_seed_persisted": row["totp_seed_enc"] is not None,
            "destination_masked": mask_email(row["email"]) if row.get("email") else None,
            "schedule_role": sched["role"],
            "requested_role": requested,
            "role_applied": bool(requested) and requested == sched["role"],
            "readmitted": bool(sched["readmitted"]),
        }
        return out

    def erase(self, user_id: str, *, kiosk_id: str | None = None) -> dict:
        """DPDP erasure of an ENROLLED user: Rekognition user + faces, user row and reference image; the schedule
        entry stays, suspended by an ERASED revocation (feed: non-deny ERASE item). A user without an enrolment
        row (e.g. a schedule-only demo user) -> 404 and nothing changes (no schedule edit, no revocation)."""
        row = self.kv.get("users", user_id)
        if row is None:
            raise ApiError("NOT_FOUND", "user not enrolled (no enrolment record); nothing erased")
        face_ids = list(row.get("face_ids") or [])
        rek_deleted = False
        deleted_faces: list[str] = []
        if getattr(self.faces, "name", "") != "disabled":
            # Rekognition is authoritative: faces the row does not list (e.g. concurrent appends) go too. Listed
            # BEFORE DeleteUser, which only disassociates them.
            try:
                face_ids = list(dict.fromkeys(face_ids + self._current_faces(user_id, row)))
            except FaceError as e:
                if e.kind != "INVALID_PARAMETER":
                    raise _face_error(e) from e
            try:
                rek_deleted = self.faces.delete_user(user_id, uuid.uuid4().hex[:32])
                deleted_faces = self.faces.delete_faces(face_ids)
            except FaceError as e:
                if e.kind not in {"NOT_FOUND", "INVALID_PARAMETER"}:
                    raise _face_error(e) from e
        if row.get("reference_key"):
            try:
                self.blobs.delete(row["reference_key"])
            except Exception:
                log.warning("reference image delete failed for %s", user_id)
        self.kv.delete("users", user_id)
        event = self.schedule.erase_user(user_id, kiosk_id=kiosk_id)
        return {"user_id": user_id, "erased": True, "rekognition_user_deleted": rek_deleted,
                "faces_deleted": len(deleted_faces), "revocation_seq": event["seq"],
                "bundle_version": event["bundle_version"]}
