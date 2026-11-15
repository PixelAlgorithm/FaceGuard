"""Face matching backends: Amazon Rekognition user vectors, a deterministic fake, and 'disabled'.

The fake never pretends to do biometrics. An image's identity comes from an ASCII marker embedded in
the bytes (e.g. a JPEG COM segment), produced by `cloud.tools.fakeimg`:
    HIDFAKE:u_3c4d            -> face of u_3c4d (similarity 99.9 vs that user)
    HIDFAKE:u_3c4d=97.5;u_1a2b=85.0  -> top-1 u_3c4d 97.5, runner-up u_1a2b 85.0
    HIDFAKE:NOFACE            -> no face detected
Unmarked images only match byte-identical enrolment images. This lets the edge integration-test the
whole HTTP contract (auth, timeouts, throttling, 1:N / 1:1, runner-up) before AWS exists.
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
import uuid
from dataclasses import dataclass, field

MAX_IMAGE_BYTES = 5 * 1024 * 1024  # Rekognition limit for Image.Bytes
DELETE_FACES_BATCH = 4096  # Rekognition DeleteFaces FaceIds limit per call (larger lists are chunked, never cut)
FACE_GONE = "FACE_NOT_FOUND"  # UnsuccessfulFaceDeletions reason that still means "not in the collection"
_MARKER_RE = re.compile(rb"HIDFAKE:([A-Za-z0-9_.:;=\-]+)")


class FaceError(Exception):
    """kind: THROTTLED | INVALID_IMAGE | INVALID_PARAMETER | UNAVAILABLE | CREDS_EXPIRED | NOT_FOUND | CONFLICT"""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


@dataclass
class UserMatch:
    user_id: str
    similarity: float
    status: str | None = None


@dataclass
class SearchResult:
    face_detected: bool
    matches: list[UserMatch] = field(default_factory=list)


@dataclass
class Association:
    """AssociateFaces outcome: faces now on the user, and the refused ones (face_id -> Rekognition reasons:
    FACE_NOT_FOUND | ASSOCIATED_TO_A_DIFFERENT_USER | LOW_MATCH_CONFIDENCE)."""

    associated: list[str]
    unsuccessful: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class LivenessResult:
    status: str  # CREATED | IN_PROGRESS | SUCCEEDED | FAILED | EXPIRED
    confidence: float | None
    reference_bytes: bytes | None = None
    reference_s3: tuple[str, str] | None = None


def check_image(image: bytes) -> None:
    if not image:
        raise FaceError("INVALID_IMAGE", "empty image")
    if len(image) > MAX_IMAGE_BYTES:
        raise FaceError("INVALID_IMAGE", "image larger than 5 MB")
    if not (image.startswith(b"\xff\xd8\xff") or image.startswith(b"\x89PNG\r\n\x1a\n")):
        raise FaceError("INVALID_IMAGE", "image must be JPEG or PNG")


# ----------------------------------------------------------------------------- error mapping
_THROTTLE = {"ThrottlingException", "ProvisionedThroughputExceededException", "LimitExceededException",
             "TooManyRequestsException"}
_EXPIRED = {"ExpiredTokenException", "ExpiredToken", "RequestExpired", "TokenRefreshRequired"}
_DENIED = {"AccessDeniedException", "AccessDenied", "UnrecognizedClientException", "InvalidClientTokenId",
           "UnauthorizedOperation"}


def map_aws_error(exc: Exception) -> FaceError:
    from botocore.exceptions import (
        ClientError,
        ConnectionClosedError,
        ConnectTimeoutError,
        EndpointConnectionError,
        NoCredentialsError,
        ProfileNotFound,
        ReadTimeoutError,
    )

    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        code, msg = err.get("Code", ""), err.get("Message", "")
        if code in _THROTTLE:
            return FaceError("THROTTLED", code)
        if code in _EXPIRED:
            return FaceError("CREDS_EXPIRED", "AWS session credentials expired")
        if code in _DENIED:
            return FaceError("UNAVAILABLE", f"rekognition access denied ({code})")
        if code in {"ResourceNotFoundException", "SessionNotFoundException"}:
            return FaceError("NOT_FOUND", msg or code)
        if code in {"InvalidImageFormatException", "ImageTooLargeException", "InvalidS3ObjectException"}:
            return FaceError("INVALID_IMAGE", code)
        if code == "InvalidParameterException":
            return FaceError("INVALID_PARAMETER", msg or code)
        if code == "ConflictException":
            return FaceError("CONFLICT", msg or code)
        return FaceError("UNAVAILABLE", code or "rekognition error")
    if isinstance(exc, ReadTimeoutError | ConnectTimeoutError | EndpointConnectionError | ConnectionClosedError):
        return FaceError("UNAVAILABLE", f"rekognition network error ({type(exc).__name__})")
    if isinstance(exc, NoCredentialsError | ProfileNotFound):
        return FaceError("UNAVAILABLE", "no AWS credentials available")
    if type(exc).__name__ in {"TokenRetrievalError", "UnauthorizedSSOTokenError"}:
        return FaceError("CREDS_EXPIRED", "AWS session credentials expired")
    return FaceError("UNAVAILABLE", f"rekognition error ({type(exc).__name__})")


# ----------------------------------------------------------------------------- rekognition
class RekognitionFaces:
    name = "rekognition"

    def __init__(self, client, collection_id: str) -> None:
        self._c = client
        self.collection_id = collection_id

    def _call(self, fn, **kw):
        try:
            return fn(**kw)
        except Exception as exc:  # mapped to a small closed set of kinds
            raise map_aws_error(exc) from exc

    def search_users_by_image(self, image: bytes, threshold: float, max_users: int,
                              quality_filter: str) -> SearchResult:
        check_image(image)
        try:
            r = self._call(self._c.search_users_by_image, CollectionId=self.collection_id, Image={"Bytes": image},
                           UserMatchThreshold=float(threshold), MaxUsers=int(max_users),
                           QualityFilter=quality_filter)
        except FaceError as e:
            if e.kind == "INVALID_PARAMETER" and "face" in e.message.lower():
                return SearchResult(face_detected=False)
            raise
        matches = [
            UserMatch(m["User"]["UserId"], float(m["Similarity"]), m["User"].get("UserStatus"))
            for m in r.get("UserMatches", [])
        ]
        matches.sort(key=lambda m: m.similarity, reverse=True)
        detected = bool(r.get("SearchedFace")) or bool(matches)
        return SearchResult(face_detected=detected, matches=matches)

    def compare_faces(self, source: bytes, target: bytes, threshold: float, quality_filter: str) -> float | None:
        check_image(source)
        check_image(target)
        try:
            r = self._call(self._c.compare_faces, SourceImage={"Bytes": source}, TargetImage={"Bytes": target},
                           SimilarityThreshold=float(threshold), QualityFilter=quality_filter)
        except FaceError as e:
            if e.kind == "INVALID_PARAMETER" and "face" in e.message.lower():
                return None
            raise
        sims = [float(m["Similarity"]) for m in r.get("FaceMatches", [])]
        return max(sims) if sims else None

    def index_face(self, image: bytes, external_id: str, quality_filter: str) -> str | None:
        check_image(image)
        r = self._call(self._c.index_faces, CollectionId=self.collection_id, Image={"Bytes": image},
                       ExternalImageId=external_id, MaxFaces=1, QualityFilter=quality_filter,
                       DetectionAttributes=["DEFAULT"])
        recs = r.get("FaceRecords", [])
        return recs[0]["Face"]["FaceId"] if recs else None

    def create_user(self, user_id: str, token: str) -> None:
        try:
            self._call(self._c.create_user, CollectionId=self.collection_id, UserId=user_id,
                       ClientRequestToken=token)
        except FaceError as e:
            if e.kind != "CONFLICT":
                raise

    def associate_faces(self, user_id: str, face_ids: list[str], token: str,
                        match_threshold: float | None = None) -> Association:
        """For a user that already has faces, Rekognition only associates a face that matches the user with
        >= UserMatchThreshold (AWS default 75); refused faces come back in UnsuccessfulFaceAssociations."""
        kw: dict = {"CollectionId": self.collection_id, "UserId": user_id, "FaceIds": face_ids[:100],
                    "ClientRequestToken": token}
        if match_threshold is not None:
            kw["UserMatchThreshold"] = float(match_threshold)
        r = self._call(self._c.associate_faces, **kw)
        return Association(
            associated=[f["FaceId"] for f in r.get("AssociatedFaces", [])],
            unsuccessful={u["FaceId"]: list(u.get("Reasons") or []) for u in r.get("UnsuccessfulFaceAssociations", [])
                          if u.get("FaceId")})

    def disassociate_faces(self, user_id: str, face_ids: list[str], token: str) -> list[str]:
        if not face_ids:
            return []
        r = self._call(self._c.disassociate_faces, CollectionId=self.collection_id, UserId=user_id,
                       FaceIds=face_ids[:100], ClientRequestToken=token)
        return [f["FaceId"] for f in r.get("DisassociatedFaces", [])]

    def delete_user(self, user_id: str, token: str) -> bool:
        try:
            self._call(self._c.delete_user, CollectionId=self.collection_id, UserId=user_id,
                       ClientRequestToken=token)
            return True
        except FaceError as e:
            if e.kind == "NOT_FOUND":
                return False
            raise

    def delete_faces(self, face_ids: list[str]) -> list[str]:
        """Faces still associated with a user are NOT deleted (UnsuccessfulFaceDeletions reason
        ASSOCIATED_TO_AN_EXISTING_USER): DisassociateFaces or DeleteUser first."""
        return self.delete_faces_detailed(face_ids)[0]

    def delete_faces_detailed(self, face_ids: list[str]) -> tuple[list[str], dict[str, list[str]]]:
        """(deleted, refused face_id -> reasons) over every id, in chunks of DELETE_FACES_BATCH."""
        deleted: list[str] = []
        refused: dict[str, list[str]] = {}
        for i in range(0, len(face_ids), DELETE_FACES_BATCH):
            r = self._call(self._c.delete_faces, CollectionId=self.collection_id,
                           FaceIds=face_ids[i:i + DELETE_FACES_BATCH])
            deleted += list(r.get("DeletedFaces", []))
            for u in r.get("UnsuccessfulFaceDeletions", []) or []:
                if u.get("FaceId"):
                    refused[u["FaceId"]] = list(u.get("Reasons") or [])
        return deleted, refused

    def list_user_faces(self, user_id: str) -> list[str]:
        out: list[str] = []
        kw = {"CollectionId": self.collection_id, "UserId": user_id, "MaxResults": 100}
        while True:
            r = self._call(self._c.list_faces, **kw)
            out += [f["FaceId"] for f in r.get("Faces", [])]
            if not r.get("NextToken"):
                return out
            kw["NextToken"] = r["NextToken"]

    def ping(self) -> None:
        self._call(self._c.describe_collection, CollectionId=self.collection_id)

    # --- Face Liveness (step-up only) ---
    def create_liveness_session(self, *, token: str, challenge: str, s3_bucket: str | None,
                                s3_prefix: str, kms_key_id: str | None, user_hint: str | None = None) -> str:
        settings: dict = {"AuditImagesLimit": 0, "ChallengePreferences": [{"Type": challenge}]}
        if s3_bucket:
            settings["OutputConfig"] = {"S3Bucket": s3_bucket, "S3KeyPrefix": s3_prefix}
        kw: dict = {"Settings": settings, "ClientRequestToken": token[:64]}
        if kms_key_id:
            kw["KmsKeyId"] = kms_key_id
        r = self._call(self._c.create_face_liveness_session, **kw)
        return r["SessionId"]

    def get_liveness_results(self, session_id: str) -> LivenessResult:
        r = self._call(self._c.get_face_liveness_session_results, SessionId=session_id)
        ref = r.get("ReferenceImage") or {}
        s3 = ref.get("S3Object")
        return LivenessResult(
            status=r.get("Status", "FAILED"),
            confidence=float(r["Confidence"]) if r.get("Confidence") is not None else None,
            reference_bytes=ref.get("Bytes"),
            reference_s3=(s3["Bucket"], s3["Name"]) if s3 else None,
        )


# ----------------------------------------------------------------------------- fake
def parse_marker(image: bytes) -> list[tuple[str, float | None]] | None:
    """None = no marker; [] = NOFACE; else [(user_id, similarity|None), ...]."""
    m = _MARKER_RE.search(image)
    if not m:
        return None
    spec = m.group(1).decode("ascii")
    if spec.upper() == "NOFACE":
        return []
    out: list[tuple[str, float | None]] = []
    for part in spec.split(";"):
        if not part:
            continue
        if "=" in part:
            uid, sim = part.split("=", 1)
            out.append((uid, float(sim)))
        else:
            out.append((part, None))
    return out


class FakeFaces:
    """In-memory stand-in for Rekognition with the same method surface and error kinds."""

    name = "fake"

    def __init__(self, collection_id: str = "fake-collection") -> None:
        self.collection_id = collection_id
        self._faces: dict[str, tuple[str, str]] = {}  # face_id -> (identity, external_id)
        self._users: dict[str, set[str]] = {}  # user_id -> face_ids
        self._lock = threading.Lock()
        self._liveness: dict[str, dict] = {}
        self.throttle_next = 0  # tests: raise THROTTLED this many times
        self.delay_s = 0.0  # tests: simulate service latency
        self.liveness_confidence = 95.0
        self.calls: list[str] = []

    def _maybe_fail(self, op: str) -> None:
        self.calls.append(op)
        if self.delay_s:
            time.sleep(self.delay_s)
        if self.throttle_next > 0:
            self.throttle_next -= 1
            raise FaceError("THROTTLED", "ThrottlingException")

    @staticmethod
    def _identity(image: bytes) -> str | None:
        marker = parse_marker(image)
        if marker is None:
            return "sha:" + hashlib.sha256(image).hexdigest()
        if not marker:
            return None
        return "usr:" + marker[0][0]

    def search_users_by_image(self, image: bytes, threshold: float, max_users: int,
                              quality_filter: str) -> SearchResult:
        check_image(image)
        self._maybe_fail("SearchUsersByImage")
        marker = parse_marker(image)
        with self._lock:
            if marker == []:
                return SearchResult(face_detected=False)
            if marker is None:
                ident = self._identity(image)
                hits = [UserMatch(u, 99.9, "ACTIVE") for u, fids in self._users.items()
                        if any(self._faces[f][0] == ident for f in fids)]
            else:
                hits = []
                for i, (uid, sim) in enumerate(marker):
                    if uid in self._users and self._users[uid]:
                        hits.append(UserMatch(uid, sim if sim is not None else (99.9 if i == 0 else 85.0),
                                              "ACTIVE"))
        hits = [h for h in hits if h.similarity >= threshold]
        hits.sort(key=lambda m: m.similarity, reverse=True)
        return SearchResult(face_detected=True, matches=hits[:max_users])

    def compare_faces(self, source: bytes, target: bytes, threshold: float, quality_filter: str) -> float | None:
        check_image(source)
        check_image(target)
        self._maybe_fail("CompareFaces")
        a, b = self._identity(source), self._identity(target)
        if a is None or b is None or a != b:
            return None
        marker = parse_marker(source)
        sim = marker[0][1] if marker and marker[0][1] is not None else 99.9
        return sim if sim >= threshold else None

    def index_face(self, image: bytes, external_id: str, quality_filter: str) -> str | None:
        check_image(image)
        self._maybe_fail("IndexFaces")
        ident = self._identity(image)
        if ident is None:
            return None
        fid = str(uuid.uuid4())
        with self._lock:
            self._faces[fid] = (ident, external_id)
        return fid

    def create_user(self, user_id: str, token: str) -> None:
        self._maybe_fail("CreateUser")
        with self._lock:
            self._users.setdefault(user_id, set())

    def associate_faces(self, user_id: str, face_ids: list[str], token: str,
                        match_threshold: float | None = None) -> Association:
        """Rekognition semantics: a user that already has faces only accepts a face of the same identity
        (else LOW_MATCH_CONFIDENCE); a face already on another user is refused; one already on this user is
        ignored (in neither list)."""
        self._maybe_fail("AssociateFaces")
        with self._lock:
            if user_id not in self._users:
                raise FaceError("NOT_FOUND", "user not found")
            mine = self._users[user_id]
            known = {self._faces[f][0] for f in mine if f in self._faces}
            owner = {f: u for u, fids in self._users.items() for f in fids}
            ok: list[str] = []
            bad: dict[str, list[str]] = {}
            for f in face_ids:
                if f not in self._faces:
                    bad[f] = ["FACE_NOT_FOUND"]
                elif f in mine:
                    continue
                elif f in owner:
                    bad[f] = ["ASSOCIATED_TO_A_DIFFERENT_USER"]
                elif known and self._faces[f][0] not in known:
                    bad[f] = ["LOW_MATCH_CONFIDENCE"]
                else:
                    ok.append(f)
            mine.update(ok)
            return Association(associated=ok, unsuccessful=bad)

    def disassociate_faces(self, user_id: str, face_ids: list[str], token: str) -> list[str]:
        self._maybe_fail("DisassociateFaces")
        with self._lock:
            if user_id not in self._users:
                raise FaceError("NOT_FOUND", "user not found")
            gone = [f for f in face_ids if f in self._users[user_id]]
            self._users[user_id].difference_update(gone)
            return gone

    def delete_user(self, user_id: str, token: str) -> bool:
        self._maybe_fail("DeleteUser")
        with self._lock:
            return self._users.pop(user_id, None) is not None

    def delete_faces(self, face_ids: list[str]) -> list[str]:
        """Like Rekognition: a face still associated with a user is not deleted (ASSOCIATED_TO_AN_EXISTING_USER)."""
        return self.delete_faces_detailed(face_ids)[0]

    def delete_faces_detailed(self, face_ids: list[str]) -> tuple[list[str], dict[str, list[str]]]:
        self._maybe_fail("DeleteFaces")
        with self._lock:
            owned = {f for fids in self._users.values() for f in fids}
            deleted, refused = [], {}
            for f in face_ids:
                if f in owned:
                    refused[f] = ["ASSOCIATED_TO_AN_EXISTING_USER"]
                elif self._faces.pop(f, None) is not None:
                    deleted.append(f)
                else:
                    refused[f] = [FACE_GONE]
            return deleted, refused

    def list_user_faces(self, user_id: str) -> list[str]:
        self._maybe_fail("ListFaces")
        with self._lock:
            return sorted(self._users.get(user_id, set()))

    def ping(self) -> None:
        return None

    def user_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._users)

    def face_count(self) -> int:
        with self._lock:
            return len(self._faces)

    def create_liveness_session(self, *, token: str, challenge: str, s3_bucket: str | None,
                                s3_prefix: str, kms_key_id: str | None, user_hint: str | None = None) -> str:
        self._maybe_fail("CreateFaceLivenessSession")
        sid = str(uuid.uuid4())
        self._liveness[sid] = {"user_hint": user_hint, "created": time.time()}
        return sid

    def get_liveness_results(self, session_id: str) -> LivenessResult:
        self._maybe_fail("GetFaceLivenessSessionResults")
        s = self._liveness.get(session_id)
        if s is None:
            raise FaceError("NOT_FOUND", "SessionNotFoundException")
        from cloud.tools.fakeimg import make_fake_jpeg

        ref = make_fake_jpeg(s["user_hint"]) if s.get("user_hint") else None
        return LivenessResult(status="SUCCEEDED", confidence=self.liveness_confidence, reference_bytes=ref)


class DisabledFaces:
    """FACE_BACKEND=disabled: every call is 'unavailable' (sandbox denies Rekognition)."""

    name = "disabled"
    collection_id = ""

    def __getattr__(self, item: str):
        def _unavailable(*_a, **_kw):
            raise FaceError("UNAVAILABLE", "face backend disabled (FACE_BACKEND=disabled)")

        return _unavailable
