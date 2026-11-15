"""Signal contract between the perception layer (edge-ml, producer) and the policy engine (consumer).

Field names are binding (agreed with edge-ml). All `X | None` fields default to None; the policy
treats None / NaN / inf as a *missing* signal, and a missing signal can never produce ALLOW
(DECISION_POLICY.md P1/P3). Extra (unknown) fields are rejected so typos surface immediately.

Units: probabilities/scores 0-1 unless noted; pixels; degrees; milliseconds; depth in millimetres.
"""

from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

ActionName = Literal["SMILE", "OPEN_MOUTH", "PUFF_CHEEKS", "BLINK", "TURN_LEFT", "TURN_RIGHT"]
FallbackMethod = Literal["TOTP", "CARD", "EMAIL_OTP", "STAFF_OVERRIDE"]

DEFORMATION_ACTIONS: frozenset[str] = frozenset({"SMILE", "OPEN_MOUTH", "PUFF_CHEEKS"})
SECONDARY_ACTIONS: frozenset[str] = frozenset({"BLINK", "TURN_LEFT", "TURN_RIGHT"})


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FrameQuality(_Model):
    face_count: int
    secondary_face_rel_size: float = Field(
        description="largest secondary face area / main face area; 0 if none"
    )
    luma_mean: float = Field(description="face ROI mean luma, 0-255")
    overexposed_frac: float = Field(description="fraction of face ROI pixels over-exposed, 0-1")
    laplacian_var: float = Field(description="Laplacian variance of the 112x112 gray face crop")
    face_width_px: float
    iod_px: float = Field(description="inter-ocular distance in pixels")
    yaw_deg: float
    pitch_deg: float
    roll_deg: float
    depth_valid_ratio: float | None = Field(
        default=None, description="D0 valid-depth ratio for this frame, if depth is enabled"
    )


class FrameSignals(_Model):
    index: int
    ts_ms: int
    quality: FrameQuality
    pad_v2: float | None = Field(default=None, description="P_live of MiniFASNetV2")
    pad_v1se: float | None = Field(default=None, description="P_live of MiniFASNetV1SE")
    device_conf: float = Field(
        default=0.0, description="max conf of a COCO cell phone/laptop/tv box overlapping the face"
    )
    device_face_containment: float = Field(
        default=0.0, description="fraction of the face box inside that device box"
    )
    moire: float | None = Field(default=None, description="moire FFT score of face ROI, 0-1")
    mask_edge_ring: float | None = Field(default=None, description="M2 RGB ring score, 0-1")
    match_top1_user: str | None = None
    match_top1: float | None = Field(default=None, description="local ArcFace cosine of top-1 user")
    match_top2: float | None = Field(
        default=None,
        description="local ArcFace cosine of the best *different* user; None ONLY if the gallery has no other user",
    )


class FlashSignal(_Model):
    r: float | None = Field(default=None, description="chroma response vs nonce correlation")
    lag_frames: float | None = Field(default=None, description="response lag in frames (or give lag_ms + fps)")
    lag_std_frames: float | None = None
    lag_ms: float | None = Field(default=None, description="lag in ms: flash_events vs frame timestamps")
    lag_std_ms: float | None = None
    fps: float | None = Field(default=None, description="measured capture fps, converts *_ms to frames")
    amplitude: float | None = None
    order_ok: bool | None = Field(default=None, description="colour order matched the nonce")
    skin_score: float | None = Field(default=None, description="spectral skin-likeness, 0-1")


class DepthSignal(_Model):
    available: bool
    absolute: bool = Field(default=False, description="True if depth is metric (mm)")
    d0_valid_ratio: float | None = None
    d1_plane_rms_mm: float | None = None
    d2_quad_rms_mm: float | None = None
    d3_nose_relief_mm: float | None = None
    d4_ipd_mm: float | None = None
    m2_depth_step_mm: float | None = None
    m3_template_rms_mm: float | None = None
    d5_disagree: float | None = None
    m1_mouth_residual_mm: float | None = None
    m1_forehead_residual_mm: float | None = None


class CloudMatch(_Model):
    ok: bool = Field(
        description="False = timeout/error/not configured -> the attempt is OFFLINE (P7)"
    )
    top1_user: str | None = None
    top1_similarity: float | None = Field(default=None, description="Rekognition similarity 0-100")
    runner_up_similarity: float | None = None


class CameraMeta(_Model):
    camera_label: str
    frame_timestamps_ms: list[int]
    virtual_camera_suspected: bool = False


class AttemptSignals(_Model):
    attempt_id: str
    kiosk_id: str
    t0: AwareDatetime = Field(description="face-lock time, timezone-aware")
    recapture_count: int = 0
    frames: list[FrameSignals]
    camera: CameraMeta
    flash: FlashSignal | None = None
    flash_enabled: bool = True
    depth: DepthSignal | None = None
    cloud_match: CloudMatch | None = None
    template_cache_age_h: float | None = None


class ActionEvidence(_Model):
    action: ActionName
    prompted_at_ms: int
    started_at_ms: int | None = None
    completed_at_ms: int | None = None
    baseline: float = Field(description="neutral blendshape baseline (first 200 ms after lock); for TURN_* the "
                                        "signed yaw at the prompt (deg, + = subject's left)")
    peak: float = Field(description="peak blendshape value (deformation/blink) during the window")
    landmark_shift: float | None = Field(
        default=None, description="correlated cheek/nasolabial landmark shift, 0-1 normalised"
    )
    yaw_peak_deg: float | None = Field(
        default=None, description="signed peak yaw for TURN_* (positive = subject's left)"
    )
    tracking_lost: bool = False


class ChallengeEvidence(_Model):
    challenge_id: str
    nonce: str
    actions: list[ActionEvidence]
    same_track: bool
    last_frame_cosine: float | None = Field(
        default=None, description="local ArcFace cosine of last challenge frame to the candidate"
    )
    depth: DepthSignal | None = None


class FallbackSubmission(_Model):
    method: FallbackMethod
    code: str | None = None
    card_id: str | None = None
    staff_id: str | None = None
    otp_id: str | None = None
    email_otp_verified: bool | None = Field(
        default=None, description="set by edge-ml after the cloud verified the email OTP"
    )


__all__ = [
    "DEFORMATION_ACTIONS",
    "SECONDARY_ACTIONS",
    "ActionEvidence",
    "ActionName",
    "AttemptSignals",
    "CameraMeta",
    "ChallengeEvidence",
    "CloudMatch",
    "DepthSignal",
    "FallbackMethod",
    "FallbackSubmission",
    "FlashSignal",
    "FrameQuality",
    "FrameSignals",
]
