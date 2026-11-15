"""Request/response models for the cloud API (docs/API.md §4). Responses are typed to avoid leaks."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

ID = r"^[A-Za-z0-9_.:\-]{1,128}$"
USER_ID = r"^[A-Za-z0-9_.\-]{1,64}$"


class MatchRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    attempt_id: str = Field(pattern=ID)
    kiosk_id: str = Field(pattern=ID)
    image_b64: str = Field(min_length=8, max_length=7_200_000)
    mode: Literal["1:N", "1:1"] = "1:N"
    claimed_user_id: str | None = Field(default=None, pattern=USER_ID)
    max_users: int = Field(default=2, ge=1, le=5)


class MatchResponse(BaseModel):
    attempt_id: str
    matched: bool
    user_id: str | None
    similarity: float | None
    runner_up_user_id: str | None
    runner_up_similarity: float | None
    face_detected: bool
    source: Literal["rekognition", "arcface", "fake"]
    user_status: Literal["ACTIVE", "SUSPENDED", "REVOKED"] | None
    latency_ms: int


class EnrollMeta(BaseModel):
    """Enrolment metadata as the edge sends it (edge/enroll.py: meta without card_id, plus card_id_hash).
    `role` is accepted and echoed (`requested_role`) but never applied here: the signed schedule is the only
    source of a user's role; the operator applies it with PUT /v1/admin/users/{user_id}/access (admin token).
    Strings are stripped first (R-H: display_name is 1-80 characters after trimming, as on the edge)."""
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)
    user_id: str = Field(pattern=USER_ID)
    display_name: str = Field(min_length=1, max_length=80)  # same bound as edge/schemas.py EnrollMeta
    # optional: without an e-mail the face is still indexed; email OTP is then simply unavailable for the user
    email: str | None = Field(default=None, pattern=r"^[^@\s]{1,64}@[^@\s]{1,253}\.[A-Za-z]{2,}$", max_length=254)
    groups: list[str] = Field(default_factory=list, max_length=10)
    role: str | None = Field(default=None, pattern=r"^[a-z_]{1,32}$")  # optional, echoed, never applied
    consent: Literal[True]
    consent_version: str = Field(min_length=1, max_length=40)
    card_id: str | None = Field(default=None, max_length=64)
    # the edge hashes the card itself (HMAC-SHA256 with CARD_ID_PEPPER) and never sends the raw id
    card_id_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    # "the enrolling kiosk provisioned a TOTP secret" (the secret lives on the edge only). The cloud never
    # mints a seed: it only records fallback.totp_enrolled in the schedule. totp_enrolled wins when sent.
    provision_totp: bool = False
    totp_enrolled: bool | None = None
    liveness_session_id: str | None = Field(default=None, max_length=128)

    @field_validator("email", mode="before")
    @classmethod
    def _blank_email_is_none(cls, v: object) -> object:
        return None if v is None or (isinstance(v, str) and not v.strip()) else (v.strip() if isinstance(v, str) else v)

    @field_validator("card_id_hash", "card_id", mode="before")
    @classmethod
    def _blank_is_none(cls, v: object) -> object:
        return None if isinstance(v, str) and not v.strip() else v


class EnrollJson(EnrollMeta):
    images_b64: list[str] = Field(min_length=1, max_length=10)


class EnrollResponse(BaseModel):
    user_id: str
    rekognition_user_id: str
    face_ids: list[str]
    faces_indexed: int
    frames_rejected: int
    template_version: int
    local_cache_updated: bool
    schedule_entitlement: bool
    bundle_version: int | None
    totp_seed_persisted: bool  # legacy: a seed minted by an older cloud build is still on file (never read)
    destination_masked: str | None = None  # None = no e-mail on file -> email OTP unavailable for this user
    totp_provisioning_uri: str | None = None  # always None: the edge owns TOTP secrets
    # the signed schedule (not this request) decides the role; None = user not in the schedule yet
    schedule_role: str | None = None
    requested_role: str | None = None
    role_applied: bool = False  # True only when the schedule role already equals the requested role
    readmitted: bool = False  # an ERASED suspension was lifted by this (consented) enrolment


class EraseResponse(BaseModel):
    user_id: str
    erased: bool
    rekognition_user_deleted: bool
    faces_deleted: int
    revocation_seq: int
    bundle_version: int


class RevocationItem(BaseModel):
    seq: int
    # ERASE = biometric data erased (non-deny; the bundle's ERASED revocation suspends + purges templates);
    # READMIT = an ERASED suspension was lifted (consent re-recorded / access re-applied by an admin)
    type: Literal["USER", "CARD", "RULE", "ERASE", "READMIT"]
    target_id: str | None
    revoked_at: str | None
    reason: str | None


class RevocationsResponse(BaseModel):
    as_of: str
    revocation_seq: int
    items: list[RevocationItem]


class ScheduleCheckRequest(BaseModel):
    user_id: str = Field(pattern=USER_ID)
    zone: str | None = Field(default=None, pattern=ID)
    t0: str | None = None


class ScheduleCheckResponse(BaseModel):
    user_id: str
    zone: str
    result: str
    bundle_version: int
    revocations_version: int
    evaluated_at: str
    evaluator: str


class OtpSendRequest(BaseModel):
    attempt_id: str = Field(pattern=ID)
    user_id: str = Field(pattern=USER_ID)
    channel: Literal["email"] = "email"


class OtpSendResponse(BaseModel):
    otp_id: str
    channel: Literal["email"]
    destination_masked: str
    expires_at: str
    resend_after_s: int
    code_length: int


class OtpVerifyRequest(BaseModel):
    otp_id: str = Field(pattern=ID)
    attempt_id: str = Field(pattern=ID)
    code: str = Field(pattern=r"^\s*\d{4,10}\s*$")


class OtpVerifyResponse(BaseModel):
    otp_id: str
    verified: bool
    attempts_remaining: int
    reason: str | None = None


class LivenessSessionRequest(BaseModel):
    attempt_id: str = Field(pattern=ID)
    kiosk_id: str = Field(pattern=ID)
    user_id: str = Field(pattern=USER_ID)
    challenge: Literal["FaceMovementAndLightChallenge", "FaceMovementChallenge"] = "FaceMovementAndLightChallenge"


class LivenessSessionResponse(BaseModel):
    session_id: str
    region: str
    expires_at: str


class LivenessResultResponse(BaseModel):
    session_id: str
    status: str
    confidence: float | None
    live: bool
    compare_similarity: float | None
    verified: bool


# ---------------------------------------------------------------- v1.4 admin-access contract (R-H field limits)
# One set of limits on all three sides (docs/API.md §3.18 / §4.9a, docs/contracts/admin_access.examples.json).
ADMIN_USER_ID = r"^u_[0-9a-z]{4}$"
STAFF_ID = r"^s_[0-9a-z_]{2,32}$"
ACTOR = r"^[A-Za-z0-9_.:@-]{1,64}$"
REVOKE_REASON = r"^[A-Z][A-Z_]{1,31}$"
ROLE = r"^[a-z_]{1,32}$"
ZONE = r"^[A-Z0-9_]{1,32}$"
HHMM = r"^([01]\d|2[0-3]):[0-5]\d$"  # written times: 00:00-23:59 (24:00 only appears in read data)
DISPLAY_MAX = 80
# Collection limits (= edge/access_models.py ZONES_ADD_MAX / EXTRA_WINDOW_ZONES_MAX / WINDOWS_PER_ZONE_MAX)
ZONES_ADD_MAX = 16
EXTRA_WINDOW_ZONES_MAX = 16
WINDOWS_PER_ZONE_MAX = 14
ROTATE_COUNT_MIN, ROTATE_COUNT_MAX, ROTATE_COUNT_DEFAULT = 1, 10, 4
DAY = Literal["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]
DAY_ORDER = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")


def _iso_with_offset(v: str | None, field: str) -> str | None:
    from datetime import datetime

    if v is None:
        return v
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be ISO-8601 with a UTC offset") from exc
    if dt.tzinfo is None:
        raise ValueError(f"{field} must be ISO-8601 with a UTC offset")
    return v


class AdminRevokeRequest(BaseModel):
    """POST /v1/admin/revocations. USER target_id = ^u_[0-9a-z]{4}$; reason ERASED is reserved for the DPDP
    erasure (DELETE /v1/enroll/{user_id}). No whitespace stripping (edge RevokeRequest parity): ' ADMIN ' is a 422."""
    model_config = ConfigDict(extra="forbid")
    type: Literal["USER", "CARD"] = "USER"
    target_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:\-]{1,128}$")
    reason: str = Field(default="ADMIN", pattern=REVOKE_REASON)
    revoked_at: str | None = None
    force: StrictBool = False  # USER revocation of a user_id unknown to the schedule and the enrolment store
    actor: str | None = Field(default=None, pattern=ACTOR)

    @field_validator("reason")
    @classmethod
    def _not_erased(cls, v: str) -> str:
        if v == "ERASED":
            raise ValueError("ERASED is the DPDP erasure: use DELETE /v1/enroll/{user_id}")
        return v

    @model_validator(mode="after")
    def _user_target(self) -> AdminRevokeRequest:
        import re

        if self.type == "USER" and not re.match(ADMIN_USER_ID, self.target_id):
            raise ValueError(f"USER target_id must match {ADMIN_USER_ID}")
        return self


class AccessWindow(BaseModel):
    """A written window (R-H): days 1-7 unique, HH:MM 00:00-23:59, end > start (same day)."""
    model_config = ConfigDict(extra="forbid")
    days: list[DAY] = Field(min_length=1, max_length=7)
    start: str = Field(pattern=HHMM)
    end: str = Field(pattern=HHMM)

    @field_validator("days")
    @classmethod
    def _unique_days(cls, v: list[str]) -> list[str]:
        if len(set(v)) != len(v):
            raise ValueError("days must be unique")
        return sorted(v, key=DAY_ORDER.index)

    @model_validator(mode="after")
    def _end_after_start(self) -> AccessWindow:
        def minutes(t: str) -> int:
            h, m = t.split(":")
            return int(h) * 60 + int(m)

        if minutes(self.end) <= minutes(self.start):
            raise ValueError(f"window end {self.end} must be after start {self.start} (same day)")
        return self


class AccessUpdateRequest(BaseModel):
    """PUT /v1/admin/users/{user_id}/access (= edge §3.18.2 AccessUpdate, forwarded as sent). Omitted fields keep
    their value; zones_add / extra_windows REPLACE; for valid_from / valid_until an explicit null clears.
    consent: true is required to create, to re-admit an ERASED user and with restore (R-B / R-C)."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    role: str = Field(pattern=ROLE)
    display: str | None = Field(default=None, min_length=1, max_length=DISPLAY_MAX)
    # StrictBool (R-H parity with edge/access_models.py AccessUpdate): "true" / 1 are refused, never coerced
    consent: StrictBool | None = None
    restore: StrictBool | None = None
    zones_add: list[str] | None = Field(default=None, max_length=ZONES_ADD_MAX)
    extra_windows: dict[str, list[AccessWindow]] | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    actor: str | None = Field(default=None, pattern=ACTOR)  # who made the change (audit); kiosk id is added

    @field_validator("zones_add")
    @classmethod
    def _zone_names(cls, v: list[str] | None) -> list[str] | None:
        import re

        if v is None:
            return v
        bad = [z for z in v if not re.match(ZONE, z)]
        if bad:
            raise ValueError("zone names must match ^[A-Z0-9_]{1,32}$")
        return list(dict.fromkeys(v))

    @field_validator("extra_windows")
    @classmethod
    def _window_zones(cls, v: dict | None) -> dict | None:
        import re

        if v is None:
            return v
        if len(v) > EXTRA_WINDOW_ZONES_MAX or any(not re.match(ZONE, z) for z in v):
            raise ValueError(f"extra_windows keys must be zone names (^[A-Z0-9_]{{1,32}}$, at most "
                             f"{EXTRA_WINDOW_ZONES_MAX})")
        if any(len(ws) > WINDOWS_PER_ZONE_MAX for ws in v.values()):
            raise ValueError(f"at most {WINDOWS_PER_ZONE_MAX} windows per zone")
        return v

    @field_validator("valid_from", "valid_until")
    @classmethod
    def _iso(cls, v: str | None, info) -> str | None:  # noqa: ANN001 - pydantic ValidationInfo
        return _iso_with_offset(v, info.field_name)

    @model_validator(mode="after")
    def _restore_needs_consent(self) -> AccessUpdateRequest:
        from datetime import datetime

        if self.restore and self.consent is not True:
            raise ValueError("restore requires consent: true")
        if self.valid_from and self.valid_until:
            f = datetime.fromisoformat(self.valid_from.replace("Z", "+00:00"))
            u = datetime.fromisoformat(self.valid_until.replace("Z", "+00:00"))
            if u <= f:
                raise ValueError("valid_until must be after valid_from")
        return self


class CodesRotateRequest(BaseModel):
    """No whitespace stripping (edge CodesRotateRequest parity): ' s_guard01 ' is a 422, never trimmed."""
    model_config = ConfigDict(extra="forbid")
    staff_id: str = Field(pattern=STAFF_ID)
    count: int = Field(default=ROTATE_COUNT_DEFAULT, ge=ROTATE_COUNT_MIN, le=ROTATE_COUNT_MAX)
    replace_existing: StrictBool = True  # drop this staff member's previous codes (rotation); edge parity
    actor: str | None = Field(default=None, pattern=ACTOR)


# ---------------------------------------------------------------- v1.4 admin-access response shapes
# Strict (extra="forbid") so the contract test catches a field that is lost or invented on either side.
class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReadWindow(_Strict):
    """= edge WindowRead: days required (a master window without days is read back as all seven), start
    00:00-23:59, end may be 24:00 (end of day)."""
    days: list[DAY]
    start: str = Field(pattern=HHMM)
    end: str = Field(pattern=r"^(([01]\d|2[0-3]):[0-5]\d|24:00)$")


class FallbackFlags(_Strict):
    totp_enrolled: bool
    card: bool


UserStatus = Literal["ACTIVE", "REVOKED", "ERASED", "NOT_IN_SCHEDULE"]


class AccessUserPublic(_Strict):
    """`user` of the PUT access response: the schedule entry after the change (never a card hash)."""
    display: str | None
    role: str | None
    zones_add: list[str]
    zones_remove: list[str]
    extra_windows: dict[str, list[ReadWindow]]
    valid_from: str | None
    valid_until: str | None
    status: UserStatus
    revoked_at: str | None
    revoked_reason: str | None
    fallback: FallbackFlags


class AccessPutResponse(_Strict):
    user_id: str
    bundle_version: int
    created: bool
    unchanged: bool
    readmitted: bool
    restored: bool
    previous_role: str | None
    role: str
    user: AccessUserPublic
    changed_at: str | None
    warnings: list[str]


class AdminUserRow(_Strict):
    user_id: str
    display: str | None
    role: str | None
    in_schedule: bool
    status: UserStatus
    revoked_at: str | None
    revoked_reason: str | None
    zones_add: list[str]
    zones_remove: list[str]
    extra_windows: dict[str, list[ReadWindow]]
    valid_from: str | None
    valid_until: str | None
    fallback: FallbackFlags
    enrolled: bool
    faces: int
    consent_version: str | None


class RoleDefaults(_Strict):
    zones: list[str]
    windows: dict[str, list[ReadWindow]]


class ZoneInfo(_Strict):
    risk: Literal["low", "medium", "high"]
    requires_explicit_grant: bool


class KioskInfo(_Strict):
    zone: str
    label: str | None


class AdminUsersResponse(_Strict):
    as_of: str
    bundle_version: int
    published_at: str | None
    timezone: str
    roles: dict[str, RoleDefaults]
    zones: dict[str, ZoneInfo]
    kiosks: dict[str, KioskInfo]
    staff_ids: list[str]
    users: list[AdminUserRow]


class AdminRevokeResponse(_Strict):
    seq: int
    type: Literal["USER", "CARD"]
    target_id: str
    revoked_at: str
    reason: str
    bundle_version: int


class MintedCode(_Strict):
    code_id: str
    code: str


class CodesRotateResponse(_Strict):
    staff_id: str
    bundle_version: int
    codes: list[MintedCode]
    dropped_code_ids: list[str]
    code_length: int
    valid_until: str
    one_time: Literal[True]
    warning: str


class AuditItem(BaseModel):
    model_config = ConfigDict(extra="allow")  # action-specific detail (never code values)
    ts_utc: str
    action: str
    kiosk_id: str | None
    actor: str | None


class AuditResponse(_Strict):
    as_of: str
    count: int
    items: list[AuditItem]


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    rekognition: str
    dynamodb: str
    region: str
    store: str
    face_backend: str
    email_backend: str
    policy: str
    version: str
    uptime_s: int
    server_time: str
    checked_at: str | None


class AdminContactRequest(BaseModel):
    """Contact-only user record (no faces): lets e-mail OTP be tested before face enrolment."""
    model_config = ConfigDict(str_strip_whitespace=True)  # R-H: 1-80 characters after trimming
    display_name: str = Field(min_length=1, max_length=80)  # R-H: 1-80 like every other display field
    email: str = Field(pattern=r"^[^@\s]{1,64}@[^@\s]{1,253}\.[A-Za-z]{2,}$", max_length=254)
    consent: Literal[True]
    consent_version: str = Field(min_length=1, max_length=40)  # = EnrollMeta / edge schemas.py
