"""Users & Access (Control Panel) wire models: docs/API.md v1.4 §3.18 + docs/contracts/admin_access.examples.json.

Request models are what the edge accepts (FastAPI validates them: 422 VALIDATION_ERROR with details[]). Response
models are the canonical shapes the handlers emit (extra="forbid": a field the contract does not name is a bug);
edge/tests/test_contract_admin_access.py validates every contract example and every handler response
against them. Field limits are the single set of lead ruling R-H, shared with the cloud and the kiosk.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StringConstraints,
    field_validator,
    model_validator,
)

# ---------------------------------------------------------------------------------- R-H field limits
USER_ID = r"^u_[0-9a-z]{4}$"
STAFF_ID = r"^s_[0-9a-z_]{2,32}$"
ROLE = r"^[a-z_]{1,32}$"
ZONE = r"^[A-Z0-9_]{1,32}$"
ACTOR = r"^[A-Za-z0-9_.:@-]{1,64}$"
REVOKE_REASON = r"^[A-Z][A-Z_]{1,31}$"
HHMM = r"^([01]\d|2[0-3]):[0-5]\d$"  # written times: 00:00-23:59
HHMM_READ_END = r"^(([01]\d|2[0-3]):[0-5]\d|24:00)$"  # read data only (role defaults may end at 24:00)
DISPLAY_MAX = 80
ZONES_ADD_MAX = 16
EXTRA_WINDOW_ZONES_MAX = 16
WINDOWS_PER_ZONE_MAX = 14
ROTATE_COUNT_DEFAULT = 4

DAYS = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")
Day = Literal["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]
ZoneName = Annotated[str, StringConstraints(pattern=ZONE)]
UserStatus = Literal["ACTIVE", "REVOKED", "ERASED", "NOT_IN_SCHEDULE"]
ReadOnlyCode = Literal["OFFLINE", "NOT_CONFIGURED", "CLOUD_ERROR", "ENDPOINT_NOT_DEPLOYED", "CLOUD_ADMIN_TOKEN"]
ScheduleResult = Literal["IN_WINDOW", "GRACE_WINDOW", "OUTSIDE_WINDOW", "NO_ENTITLEMENT", "ZONE_NOT_PERMITTED",
                         "HOLIDAY", "REVOKED"]


def minutes(hhmm: str) -> int:
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------------- request models
class Window(_Strict):
    """A written window (R-H): HH:MM 00:00-23:59, end after start on the same day, unique days."""

    days: list[Day] = Field(min_length=1, max_length=7)
    start: str = Field(pattern=HHMM)
    end: str = Field(pattern=HHMM)

    @model_validator(mode="after")
    def _end_after_start(self) -> Window:
        if minutes(self.end) <= minutes(self.start):
            raise ValueError(f"window end {self.end} must be after start {self.start} (same day)")
        if len(set(self.days)) != len(self.days):
            raise ValueError("days must be unique within a window")
        return self


class AccessUpdate(BaseModel):
    """PUT /v1/admin/access/users/{user_id} (§3.18.2). Absent = unchanged (forwarded with exclude_unset);
    zones_add / extra_windows REPLACE the stored values ({} clears); an explicit null clears valid_*."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    role: str = Field(pattern=ROLE)
    display: str | None = Field(default=None, min_length=1, max_length=DISPLAY_MAX)
    consent: StrictBool | None = None
    restore: StrictBool | None = None
    zones_add: list[ZoneName] | None = Field(default=None, max_length=ZONES_ADD_MAX)
    extra_windows: dict[ZoneName, Annotated[list[Window], Field(max_length=WINDOWS_PER_ZONE_MAX)]] | None = Field(
        default=None, max_length=EXTRA_WINDOW_ZONES_MAX)
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    actor: str | None = Field(default=None, pattern=ACTOR)

    @field_validator("valid_from", "valid_until")
    @classmethod
    def _aware(cls, v: datetime | None) -> datetime | None:
        if v is not None and v.tzinfo is None:
            raise ValueError("valid_from / valid_until need a UTC offset (e.g. 2026-11-14T18:30:00+05:30)")
        return v

    @model_validator(mode="after")
    def _rules(self) -> AccessUpdate:
        if self.restore and self.consent is not True:
            raise ValueError("restore requires consent: true")
        if self.valid_from and self.valid_until and self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self

    def wire(self) -> dict[str, Any]:
        """The cloud body: only the fields the client sent; timestamps normalised to UTC "Z"."""
        out = self.model_dump(mode="json", exclude_unset=True)
        for k in ("valid_from", "valid_until"):
            v = getattr(self, k)
            if k in out and v is not None:
                out[k] = utc_z(v)
        return out


class RevokeRequest(_Strict):
    """POST /v1/admin/access/users/{user_id}/revoke (§3.18.3). The DPDP erasure is DELETE /v1/enroll/{user_id}."""

    reason: str = Field(default="ADMIN", pattern=REVOKE_REASON)
    actor: str | None = Field(default=None, pattern=ACTOR)

    @field_validator("reason")
    @classmethod
    def _not_erased(cls, v: str) -> str:
        if v == "ERASED":
            raise ValueError("ERASED is the DPDP erasure: use DELETE /v1/enroll/{user_id}")
        return v


class CodesRotateRequest(_Strict):
    """POST /v1/admin/access/codes/rotate (§3.18.4); every field is forwarded to the cloud."""

    staff_id: str = Field(pattern=STAFF_ID)
    count: int = Field(default=ROTATE_COUNT_DEFAULT, ge=1, le=10)
    replace_existing: StrictBool = True
    actor: str | None = Field(default=None, pattern=ACTOR)

    def wire(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True)


# ---------------------------------------------------------------------------------- shared response shapes
class WindowRead(_Strict):
    days: list[Day]
    start: str = Field(pattern=HHMM)
    end: str = Field(pattern=HHMM_READ_END)


class BundleRefresh(_Strict):
    previous_version: int | None
    installed_version: int | None
    changed: bool
    result: Literal["installed", "not_modified", "failed"]
    error: str | None
    applied: bool | None = None  # write responses only: installed_version >= cloud_bundle_version


class Fallback(_Strict):
    totp_enrolled: bool
    card: bool


class LocalEnrolment(_Strict):
    enrolled: bool
    templates: int
    template_version: int | None
    template_role: str | None
    totp_local: bool
    updated_at: str | None


class TodayWindow(_Strict):
    start: str
    end: str
    source: Literal["role", "extra"]


class Today(_Strict):
    zone: str
    date: str
    day: Day
    now_local: str
    permitted: bool
    holiday: bool
    windows: list[TodayWindow]
    status_now: ScheduleResult


class AccessUser(_Strict):
    user_id: str
    display: str
    role: str | None
    bundle_role: str | None
    in_schedule: bool
    in_bundle: bool
    status: UserStatus
    revoked_at: str | None
    revoked_reason: str | None
    bundle_stale: bool
    zones_add: list[str]
    zones_remove: list[str]
    extra_windows: dict[str, list[WindowRead]]
    valid_from: str | None
    valid_until: str | None
    fallback: Fallback
    cloud_faces: int | None
    local: LocalEnrolment
    today: Today | None


class BundleInfo(_Strict):
    version: int | None
    issued_at: str | None
    expires_at: str | None


class RoleDefault(_Strict):
    zones: list[str]
    windows: dict[str, list[WindowRead]]


class ZoneRisk(_Strict):
    risk: Literal["low", "medium", "high"]
    requires_explicit_grant: bool


class AccessUsersResponse(_Strict):
    source: Literal["cloud+bundle", "bundle"]
    read_only: bool
    read_only_code: ReadOnlyCode | None
    read_only_reason: str | None
    read_only_cloud_reason: str | None = None  # cloud 403 reason, unchanged (RBAC v2 D)
    mode: Literal["ONLINE", "OFFLINE"]
    kiosk_id: str
    zone: str | None
    now_local: str
    date_local: str
    day: Day
    bundle: BundleInfo
    cloud_bundle_version: int | None
    roles: list[str]
    role_defaults: dict[str, RoleDefault]
    zones: dict[str, ZoneRisk]
    staff_ids: list[str]
    pending_cloud_erasures: list[str]
    users: list[AccessUser]


# Write responses (API v1.4 M2): cloud_bundle_version / revoked_at / seq are null when the cloud reply omitted them
# or the follow-up bundle pull failed (bundle.applied false + a warning); clients show "pending refresh".
class AccessUpdateResult(_Strict):
    user_id: str
    created: bool
    unchanged: bool
    readmitted: bool
    restored: bool
    previous_role: str | None
    role: str
    cloud_bundle_version: int | None
    bundle: BundleRefresh
    user: AccessUser | None
    warnings: list[str]


class RevokeResult(_Strict):
    user_id: str
    type: Literal["USER"]
    reason: str
    revoked_at: str | None
    seq: int | None
    cloud_bundle_version: int | None
    bundle: BundleRefresh
    user: AccessUser | None
    warnings: list[str]


class Code(_Strict):
    code_id: str | None
    code: str


class RotateCodesResult(_Strict):
    staff_id: str
    codes: list[Code]
    code_length: int | None
    valid_until: str | None
    one_time: Literal[True]
    dropped_code_ids: list[str]
    warning: str
    cloud_bundle_version: int | None
    bundle: BundleRefresh
    warnings: list[str]


class EraseResponse(_Strict):
    user_id: str
    local_removed: bool
    # "failed" (API v1.4 M1): the local template IS erased, but the cloud erasure neither happened nor could be
    # written to the local erasure queue (e.g. disk error) -> the operator must retry while ONLINE
    cloud: Literal["deleted", "queued", "not_configured", "failed"]
    cloud_status: int | None
    message: str | None
    bundle: BundleRefresh | None


class AdminUserRow(_Strict):
    user_id: str
    display_name: str | None
    role: str | None
    bundle_role: str | None
    bundle_display: str | None
    in_schedule: bool
    template_role: str | None
    template_display_name: str | None
    template_version: int
    templates: int
    totp_local: bool
    card: bool
    updated_at: str | None


class AdminUsersResponse(_Strict):
    users: list[AdminUserRow]
    bundle_version: int | None
    count: int
    model: str
    age_h: float | None
    skipped_model_mismatch: int


class DemoClock(_Strict):
    active: bool
    now_local: str
    now_utc: str
    offset_s: int
    date_local: str
    bundle_issued_at: str | None
    earliest_utc: str | None
    earliest_local: str | None
    earliest_date_local: str | None
    bundle_rollback: bool
    cache_state: Literal["FRESH", "EXPIRED", "INVALID"]


def utc_z(v: Any) -> str | None:
    """ISO-8601 -> UTC "...Z" (seconds). Unparseable strings are returned unchanged (display data only)."""
    if v is None:
        return None
    dt = v
    if not isinstance(dt, datetime):
        try:
            dt = datetime.fromisoformat(str(v))
        except ValueError:
            return str(v)
    if dt.tzinfo is None:
        return str(v)
    return dt.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
