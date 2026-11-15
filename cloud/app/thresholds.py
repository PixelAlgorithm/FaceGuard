"""Cloud-side view of config/thresholds.yaml (all numeric thresholds live there, CLAUDE.md §7).

Keys the cloud needs but the YAML does not (yet) define fall back to the documented defaults from
docs/API.md and are listed in `missing` (surfaced in /v1/health and the startup log) so they can be
added to the YAML by the config owner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_SPEC: dict[str, tuple[tuple[str, ...], Any]] = {
    "policy_version": (("policy_version",), "unknown"),
    "user_match_threshold": (("match", "rekognition", "user_match_threshold"), 80.0),
    "quality_filter": (("match", "rekognition", "quality_filter"), "AUTO"),
    "allow_min_similarity": (("match", "rekognition", "allow_min_similarity"), 99.0),
    "face_liveness_min_confidence": (("challenge", "face_liveness_min_confidence"), 80.0),
    "otp_digits": (("fallback", "email_otp", "digits"), 6),
    "otp_ttl_s": (("fallback", "email_otp", "ttl_s"), 300),
    "otp_max_attempts": (("fallback", "email_otp", "max_attempts"), 3),  # API.md §4.6: 3 attempts
    "clock_skew_alert_s": (("sync", "clock_skew_alert_s"), 120),
    "spoof_burst_count": (("sync", "spoof_burst_count"), 3),
    "spoof_burst_window_min": (("sync", "spoof_burst_window_min"), 10),
    "bundle_max_staleness_hours": (("cache", "bundle_max_staleness_hours"), 12),
    # one source of truth with scripts/sign_bundle.py: per-code valid_until = bundle expires_at + N h (R7)
    "override_valid_after_expiry_h": (("fallback", "staff_override", "valid_after_expiry_h"), 24),
    # POST /v1/admin/codes/rotate mints codes the edge accepts (edge/policy/fallback.py _match_override)
    "override_code_length": (("fallback", "staff_override", "code_length"), 8),
    "override_pbkdf2_iterations": (("fallback", "staff_override", "pbkdf2_iterations"), 100000),
}


def _dig(d: dict, path: tuple[str, ...]) -> Any:
    cur: Any = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            raise KeyError(".".join(path))
        cur = cur[p]
    return cur


@dataclass(frozen=True)
class CloudThresholds:
    raw: dict
    policy_version: str
    user_match_threshold: float
    quality_filter: str
    allow_min_similarity: float
    face_liveness_min_confidence: float
    otp_digits: int
    otp_ttl_s: int
    otp_max_attempts: int
    clock_skew_alert_s: int
    spoof_burst_count: int
    spoof_burst_window_min: int
    bundle_max_staleness_hours: int
    override_valid_after_expiry_h: float = 24.0
    override_code_length: int = 8
    override_pbkdf2_iterations: int = 100000
    missing: list[str] = field(default_factory=list)


def load_thresholds(path: str | Path) -> CloudThresholds:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    values: dict[str, Any] = {}
    missing: list[str] = []
    for name, (keypath, default) in _SPEC.items():
        try:
            values[name] = _dig(raw, keypath)
        except KeyError:
            values[name] = default
            missing.append(".".join(keypath))
    return CloudThresholds(
        raw=raw,
        policy_version=str(values["policy_version"]),
        user_match_threshold=float(values["user_match_threshold"]),
        quality_filter=str(values["quality_filter"]),
        allow_min_similarity=float(values["allow_min_similarity"]),
        face_liveness_min_confidence=float(values["face_liveness_min_confidence"]),
        otp_digits=int(values["otp_digits"]),
        otp_ttl_s=int(values["otp_ttl_s"]),
        otp_max_attempts=int(values["otp_max_attempts"]),
        clock_skew_alert_s=int(values["clock_skew_alert_s"]),
        spoof_burst_count=int(values["spoof_burst_count"]),
        spoof_burst_window_min=int(values["spoof_burst_window_min"]),
        bundle_max_staleness_hours=int(values["bundle_max_staleness_hours"]),
        override_valid_after_expiry_h=float(values["override_valid_after_expiry_h"]),
        override_code_length=int(values["override_code_length"]),
        override_pbkdf2_iterations=int(values["override_pbkdf2_iterations"]),
        missing=missing,
    )
