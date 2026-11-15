"""Wire-format request/response models for the edge API (lead's v1.1 contract; docs/API.md)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from edge.policy.signals import ActionEvidence

Mode = Literal["ONLINE", "OFFLINE"]


class _In(BaseModel):
    model_config = ConfigDict(extra="ignore")


# F10 / F5: every client field the edge stores or forwards is bounded to the contract (docs/API.md) so a bad value
# is a 422 here, never a cloud 422 counted as a heartbeat miss, an unbounded string held for 600 s, or a 500.
USER_ID_PATTERN = r"^u_[0-9a-z]{4}$"
ATTEMPT_ID_PATTERN = r"^att_[0-9A-HJKMNP-TV-Z]{26}$"  # att_<ULID> (edge/session.py)
KIOSK_ID_PATTERN = r"^[A-Z0-9_]{1,64}$"
STAFF_ID_PATTERN = r"^s_[0-9a-z_]{2,32}$"
LABEL_MAX = 256  # camera labels / user agents
SHORT_TEXT_MAX = 128
SECRET_TEXT_MAX = 64  # TOTP / e-mail OTP / staff codes / card ids
EPOCH_MS_MAX = 10 ** 14  # year ~5138: any real client clock is far below; bounds latency arithmetic
SCREEN_KEYS_MAX = 16
EpochMs = Annotated[int, Field(ge=0, lt=EPOCH_MS_MAX)]


# ---------------------------------------------------------------- session/start
class ClientInfo(_In):
    camera_label: str = Field(default="", max_length=LABEL_MAX)
    user_agent: str = Field(default="", max_length=LABEL_MAX)
    screen: dict[str, Any] = Field(default_factory=dict, max_length=SCREEN_KEYS_MAX)


class SessionStartRequest(_In):
    kiosk_id: str = Field(pattern=KIOSK_ID_PATTERN)
    claimed_user_id: str | None = Field(default=None, pattern=USER_ID_PATTERN)
    client: ClientInfo = Field(default_factory=ClientInfo)
    flash_enabled: bool = True
    recapture_of: str | None = Field(default=None, pattern=ATTEMPT_ID_PATTERN)


class FlashStep(BaseModel):
    color: str
    offset_ms: int
    duration_ms: int


class CaptureSpec(BaseModel):
    frames: int
    window_ms: int
    max_width_px: int = 1280  # 640 px left the face at ~50 px IOD at kiosk distance (< quality.min_interocular_px 60)
    jpeg_quality: float = 0.85


class SessionStartResponse(BaseModel):
    attempt_id: str
    nonce: str
    flash_sequence: list[FlashStep]
    capture: CaptureSpec
    mode: Mode
    expires_at: datetime
    recapture_count: int = 0
    depth_requested: bool = False



class ProbeResponse(BaseModel):
    """POST /v1/attempt/{id}/probe (202): the face-lock frame was accepted. `cloud` = "started" when the
    early Rekognition match is in flight, "skipped" when this attempt will not call the cloud (OFFLINE,
    no cloud configured, match.rekognition.enabled false) or the probe frame shows no usable face."""

    accepted: Literal[True] = True
    cloud: Literal["started", "skipped"]


# ---------------------------------------------------------------- frames
class FlashEventIn(_In):
    step_index: int
    color: str
    shown_at_ms: float


class ChromaSampleIn(_In):
    t_ms: float
    r: float
    g: float
    b: float


class ClientQuality(_In):
    face_count: int | None = None
    iod_px: float | None = None
    yaw_deg: float | None = None
    pitch_deg: float | None = None
    roll_deg: float | None = None
    blur_var: float | None = None
    luma_mean: float | None = None
    face_box: list[float] | None = None


class ClientSignals(_In):
    camera_label: str = Field(default="", max_length=LABEL_MAX)
    virtual_camera_suspected: bool = False
    device_count: int | None = None
    track_settings: dict[str, Any] = Field(default_factory=dict)
    fps_measured: float | None = None
    frame_interval_jitter_ms: float | None = None
    exposure_locked: bool | None = None


class FramesMeta(_In):
    nonce: str = Field(max_length=SHORT_TEXT_MAX)
    face_lock_at_ms: EpochMs
    capture_started_at_ms: EpochMs
    frame_timestamps_ms: list[EpochMs] = Field(max_length=32)
    flash_events: list[FlashEventIn] = Field(default_factory=list)
    chroma_series: list[ChromaSampleIn] = Field(default_factory=list)
    quality: ClientQuality = Field(default_factory=ClientQuality)
    client_signals: ClientSignals = Field(default_factory=ClientSignals)
    blendshapes: dict[str, float] = Field(default_factory=dict)
    landmarks_hash: str | None = Field(default=None, max_length=SHORT_TEXT_MAX)


# ---------------------------------------------------------------- challenge / fallback
_ACTION_ALIASES = {
    "smile": "SMILE", "jaw_open": "OPEN_MOUTH", "open_mouth": "OPEN_MOUTH", "cheek_puff": "PUFF_CHEEKS",
    "puff_cheeks": "PUFF_CHEEKS", "blink": "BLINK", "turn_left": "TURN_LEFT", "turn_right": "TURN_RIGHT",
}


class ChallengeMeta(BaseModel):
    """API 3.3. `actions` ARE the policy's ActionEvidence (extra="forbid"), passed through unchanged
    (for TURN_* `baseline` is the signed yaw at the prompt; the policy evaluates the delta)."""

    model_config = ConfigDict(extra="forbid")
    challenge_id: str = Field(max_length=SHORT_TEXT_MAX)
    nonce: str = Field(max_length=SHORT_TEXT_MAX)
    actions: list[ActionEvidence] = Field(max_length=8)
    same_track: bool

    @field_validator("actions", mode="before")
    @classmethod
    def _canonical_action_names(cls, v: Any) -> Any:
        if not isinstance(v, list):
            return v
        out = []
        for a in v:
            if isinstance(a, dict) and isinstance(a.get("action"), str):
                a = {**a, "action": _ACTION_ALIASES.get(a["action"].lower(), a["action"])}
            out.append(a)
        return out


FallbackMethodIn = Literal["TOTP", "CARD", "EMAIL_OTP", "STAFF_OVERRIDE"]
_FALLBACK_ALIASES = {
    "totp": "TOTP", "card": "CARD", "card_id": "CARD", "otp": "EMAIL_OTP", "email_otp": "EMAIL_OTP",
    "staff": "STAFF_OVERRIDE", "staff_code": "STAFF_OVERRIDE", "staff_override": "STAFF_OVERRIDE",
}


class FallbackRequest(_In):
    method: FallbackMethodIn
    code: str | None = Field(default=None, max_length=SECRET_TEXT_MAX)
    card_id: str | None = Field(default=None, max_length=SECRET_TEXT_MAX)
    # EA-3: any short string; a mistyped staff id is a normal wrong code for the verifier (counted toward the
    # device backstop), never a 422 in the middle of a step-up
    staff_id: str | None = Field(default=None, max_length=SHORT_TEXT_MAX)
    otp_id: str | None = Field(default=None, max_length=SHORT_TEXT_MAX)

    @field_validator("method", mode="before")
    @classmethod
    def _alias(cls, v: Any) -> Any:
        return _FALLBACK_ALIASES.get(str(v).lower(), v) if isinstance(v, str) else v


# ---------------------------------------------------------------- enrolment / admin
class EnrollMeta(_In):
    """API 3.15 (v1.4, R-A / R-H). extra="ignore"; strings stripped."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)
    user_id: str = Field(pattern=r"^u_[0-9a-z]{4}$")  # must be in the verified schedule bundle (else 409)
    display_name: str = Field(min_length=1, max_length=80)
    email: str | None = Field(default=None, max_length=254)
    # optional, NEVER applied: the role comes from the signed schedule (EnrollResponse.schedule_role; change it
    # with PUT /v1/admin/access/users/{user_id}); a value that differs from the schedule adds a warning
    role: str | None = Field(default=None, max_length=32)
    consent: Literal[True]
    consent_version: str = Field(min_length=1, max_length=40)
    card_id: str | None = Field(default=None, max_length=SECRET_TEXT_MAX)
    provision_totp: bool = True


class EnrollResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")  # docs/contracts/admin_access.examples.json edge.enroll.post
    user_id: str
    template_version: int
    local_cache_updated: bool
    cloud_indexed: bool = False  # False when offline / not configured / Rekognition denied
    totp_provisioning_uri: str | None = None
    frames_used: int
    frames_rejected: list[dict[str, Any]] = Field(default_factory=list)
    min_pairwise_cosine: float | None = None
    cloud: dict[str, Any] | None = None  # {status, body} (secret-bearing keys removed) or {status: null, error}
    # "indexed" | "failed" (cloud refused / unreachable) | "skipped_offline" | "not_configured"
    cloud_state: Literal["indexed", "failed", "skipped_offline", "not_configured"] = "not_configured"
    # a local TOTP secret exists AND the installed bundle marks the user fallback.totp_enrolled (only then is TOTP
    # offered at the kiosk; the UI shows the QR as "Scan now" only when true)
    totp_active: bool = False
    schedule_role: str | None = None  # the role decisions use (verified bundle), never meta.role
    schedule_display: str | None = None
    role_requested: str | None = None
    role_applied: bool = False  # always False: enrolment never sets a role
    bundle_version: int | None = None  # installed after the post-enrolment refresh
    reinstated_after_erasure: bool = False
    warnings: list[str] = Field(default_factory=list)


FORCED_MODE_MAX_MINUTES = 240
FORCED_REASON_MAX_CHARS = 200  # = the policy runtime's set_forced_mode reason limit (edge/policy/runtime_ops.py)


class AdminModeRequest(_In):
    """POST /v1/admin/mode (RBAC v2 D): forced OFFLINE auto-reverts to AUTO after max_minutes (runtime default
    60); `reason` is recorded with the actor."""

    force: Literal["OFFLINE", "AUTO"]
    reason: str | None = Field(default=None, max_length=FORCED_REASON_MAX_CHARS)
    max_minutes: int | None = Field(default=None, ge=1, le=FORCED_MODE_MAX_MINUTES)


class RandomChallengeRequest(_In):
    # FORCE = every would-be ALLOW gets the challenge (PolicyRuntime.set_random_challenge); FORCE_NEXT = once
    mode: Literal["AUTO", "FORCE", "FORCE_NEXT", "OFF"]


class RenderedRequest(_In):
    face_lock_at_ms: EpochMs
    rendered_at_ms: EpochMs


class EvalContext(_In):
    run_id: str = Field(min_length=1, max_length=64)
    subject_id: str = Field(min_length=1, max_length=64)  # pseudonymous (S01..), never a name
    label: Literal["bona_fide", "print", "screen_photo", "video", "mask_paper", "mask_3d", "injection"]
    condition: Literal["normal", "dim", "backlit", "far"]
    split: Literal["dev", "test"]


class ClockRequest(_In):
    set_local: str | None = Field(default=None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    offset_s: float | None = Field(default=None, allow_inf_nan=False)
    reset: bool = False


class DepthFramesMeta(_In):
    attempt_id: str = Field(pattern=ATTEMPT_ID_PATTERN)
    depth_nonce: str = Field(max_length=SHORT_TEXT_MAX)
    phase: Literal["PASSIVE", "CHALLENGE"] = "PASSIVE"
    depth_type: Literal["disparity", "depth"]
    dtype: Literal["float16", "float32"]
    width: int = Field(gt=0, le=4096)
    height: int = Field(gt=0, le=4096)
    intrinsics: dict[str, float] | None = None
    face_box_norm: list[float] | None = None
    landmarks_norm: dict[str, list[float]] | None = None
    timestamps_ms: list[float] = Field(default_factory=list)
    device: dict[str, Any] | str | None = None
    accuracy: Literal["absolute", "relative"] | None = None
