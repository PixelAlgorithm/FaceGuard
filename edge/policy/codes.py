"""Reason codes: closed list + deterministic ordering (docs/DECISION_POLICY.md §6)."""

from __future__ import annotations

from collections.abc import Iterable

# Stage order (pre-check, quality, injection, liveness hard, mask, liveness unsure, identity, schedule,
# mode, step-up, final); within a stage the table order of DECISION_POLICY §6 (quality: §3.1 order).
CODE_ORDER: tuple[str, ...] = (
    "SYSTEM_ERROR",
    # pre-check
    "RATE_LIMITED",
    # quality (§3.1 table order)
    "MULTIPLE_FACES",
    "QUALITY_LOW_LIGHT",
    "QUALITY_BLUR",
    "QUALITY_POSE",
    "QUALITY_DEPTH_INVALID",
    # injection
    "INJECTION_VIRTUAL_CAMERA",
    # liveness hard
    "SPOOF_PASSIVE",
    "SPOOF_DEVICE_DETECTED",
    "SPOOF_MOIRE",
    "SPOOF_FLASH_MISMATCH",
    "SPOOF_FLAT_DEPTH",
    "SPOOF_DEPTH_SCALE",
    # mask
    "MASK_CUE_RIGID",
    "MASK_CUE_EDGE",
    "MASK_CUE_SHAPE",
    "MASK_CUE_SPECTRAL",
    # liveness unsure
    "LIVENESS_UNSURE",
    "RANDOM_CHALLENGE",  # round-2 R4: random liveness challenge on a would-be ALLOW
    # identity
    "MATCH_LOW",
    "MATCH_AMBIGUOUS",
    "NOT_ENROLLED",
    # schedule
    "SCHEDULE_OUTSIDE_WINDOW",
    "SCHEDULE_GRACE_WINDOW",
    "SCHEDULE_NO_ENTITLEMENT",
    "SCHEDULE_ZONE_NOT_PERMITTED",
    "SCHEDULE_HOLIDAY",
    "SCHEDULE_REVOKED",
    "SCHEDULE_HIGH_RISK_ZONE",
    # mode
    "SCHEDULE_EXPIRED_CACHE",
    "SCHEDULE_BUNDLE_INVALID",
    "OFFLINE_MODE",
    "OFFLINE_HIGH_RISK_ZONE",
    "OFFLINE_FALLBACK_REQUIRED",
    # step-up
    "CHALLENGE_FAILED",
    "FALLBACK_OK",
    "FALLBACK_FAILED",
    "FALLBACK_LOCKED",  # KF-03: the submitted method is locked (failure limit); retry_after_s says how long
    # final
    "ACCESS_OK",
)
ALL_CODES: frozenset[str] = frozenset(CODE_ORDER)
_RANK = {c: i for i, c in enumerate(CODE_ORDER)}

QUALITY_CODES = ("MULTIPLE_FACES", "QUALITY_LOW_LIGHT", "QUALITY_BLUR", "QUALITY_POSE", "QUALITY_DEPTH_INVALID")
HARD_LIVENESS_CODES = frozenset(
    {"SPOOF_PASSIVE", "SPOOF_DEVICE_DETECTED", "SPOOF_MOIRE", "SPOOF_FLASH_MISMATCH", "SPOOF_FLAT_DEPTH",
     "SPOOF_DEPTH_SCALE"}
)
MASK_CODES = frozenset({"MASK_CUE_RIGID", "MASK_CUE_EDGE", "MASK_CUE_SHAPE", "MASK_CUE_SPECTRAL"})
# Codes that make a DENY final (P2): nothing may upgrade a decision carrying them.
HARD_SPOOF_CODES = HARD_LIVENESS_CODES | {"INJECTION_VIRTUAL_CAMERA", "MASK_CUE_RIGID", "CHALLENGE_FAILED"}

SCHED_CODE = {
    "GRACE_WINDOW": "SCHEDULE_GRACE_WINDOW",
    "OUTSIDE_WINDOW": "SCHEDULE_OUTSIDE_WINDOW",
    "NO_ENTITLEMENT": "SCHEDULE_NO_ENTITLEMENT",
    "ZONE_NOT_PERMITTED": "SCHEDULE_ZONE_NOT_PERMITTED",
    "HOLIDAY": "SCHEDULE_HOLIDAY",
    "REVOKED": "SCHEDULE_REVOKED",
}
DENY_TYPE = frozenset({"OUTSIDE_WINDOW", "NO_ENTITLEMENT", "ZONE_NOT_PERMITTED", "HOLIDAY", "REVOKED"})
SCHEDULE_RESULTS = frozenset(DENY_TYPE | {"IN_WINDOW", "GRACE_WINDOW"})
CONTACT_DESK_CODES = frozenset(
    {"NOT_ENROLLED", "SCHEDULE_NO_ENTITLEMENT", "SCHEDULE_ZONE_NOT_PERMITTED", "SCHEDULE_REVOKED", "SYSTEM_ERROR",
     "SCHEDULE_BUNDLE_INVALID"}  # R6: no last-valid bundle -> human help
)
# Round-2 R1: only attack-evidence DENYs feed the kiosk rate limiter.
RATE_LIMIT_CODES = HARD_LIVENESS_CODES | {"INJECTION_VIRTUAL_CAMERA", "MASK_CUE_RIGID", "CHALLENGE_FAILED",
                                          "FALLBACK_FAILED"}


def order_codes(codes: Iterable[str]) -> list[str]:
    """Deduplicate and sort by stage order. Unknown codes raise (P1: unknown value -> SYSTEM_ERROR)."""
    unique = set(codes)
    unknown = unique - ALL_CODES
    if unknown:
        raise ValueError(f"unknown reason code(s): {sorted(unknown)}")
    return sorted(unique, key=_RANK.__getitem__)


def dedupe(codes: Iterable[str]) -> list[str]:
    """Order-preserving de-duplication."""
    seen: set[str] = set()
    out = []
    for c in codes:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out
