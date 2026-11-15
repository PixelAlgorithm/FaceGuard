"""Stage 1 quality gate (DECISION_POLICY §3.1). Pure."""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from edge.policy.codes import QUALITY_CODES
from edge.policy.signals import DepthSignal, FrameSignals


def finite(x: Any) -> bool:
    return isinstance(x, int | float) and not isinstance(x, bool) and math.isfinite(x)


def depth_active(depth: DepthSignal | None, T: Any) -> bool:
    """Depth is used only when enabled in config and a depth result for this attempt arrived."""
    return bool(T.liveness.depth.enabled) and depth is not None and bool(depth.available)


@dataclass(frozen=True)
class QualityResult:
    usable: tuple[FrameSignals, ...]
    codes: tuple[str, ...]  # empty -> quality pass
    dropped: tuple[tuple[int, tuple[str, ...]], ...]


def frame_quality_codes(f: FrameSignals, T: Any, use_depth: bool) -> list[str]:
    Q, q = T.quality, f.quality
    codes: list[str] = []
    rel = q.secondary_face_rel_size
    if (finite(rel) and rel >= Q.secondary_face_min_rel_size) or (q.face_count > 1 and not finite(rel)):
        codes.append("MULTIPLE_FACES")
    luma_ok = finite(q.luma_mean) and Q.min_luma_mean <= q.luma_mean <= Q.max_luma_mean
    exposure_ok = finite(q.overexposed_frac) and q.overexposed_frac <= Q.max_overexposed_fraction
    if not (luma_ok and exposure_ok):
        codes.append("QUALITY_LOW_LIGHT")
    if not (finite(q.laplacian_var) and q.laplacian_var >= Q.min_laplacian_var):
        codes.append("QUALITY_BLUR")
    pose_ok = (
        q.face_count >= 1
        and finite(q.face_width_px) and q.face_width_px >= Q.min_face_width_px
        and finite(q.iod_px) and q.iod_px >= Q.min_interocular_px
        and finite(q.yaw_deg) and abs(q.yaw_deg) <= Q.max_abs_yaw_deg
        and finite(q.pitch_deg) and abs(q.pitch_deg) <= Q.max_abs_pitch_deg
        and finite(q.roll_deg) and abs(q.roll_deg) <= Q.max_abs_roll_deg
    )
    if not pose_ok:
        codes.append("QUALITY_POSE")
    if use_depth and q.depth_valid_ratio is not None:
        r = q.depth_valid_ratio
        if not finite(r) or r < T.liveness.depth.d0_valid_fail_below:
            codes.append("QUALITY_DEPTH_INVALID")
    return codes


def quality_gate(frames: Sequence[FrameSignals], depth: DepthSignal | None, T: Any) -> QualityResult:
    """Drop failing frames; the attempt fails if < min_usable_frames remain, any frame has
    MULTIPLE_FACES, or (depth active) the attempt-level D0 ratio is below the fail line.
    Raises ValueError for structurally invalid input (no frames / too few frames) -> SYSTEM_ERROR."""
    Q = T.quality
    if not frames:
        raise ValueError("attempt has no frames")
    use_depth = depth_active(depth, T)
    usable: list[FrameSignals] = []
    dropped: list[tuple[int, tuple[str, ...]]] = []
    for f in frames:
        c = frame_quality_codes(f, T, use_depth)
        if c:
            dropped.append((f.index, tuple(c)))
        else:
            usable.append(f)
    failing: set[str] = set()
    multi = any("MULTIPLE_FACES" in c for _, c in dropped)
    if multi or len(usable) < Q.min_usable_frames:
        failing.update(code for _, c in dropped for code in c)
    if use_depth and depth is not None and depth.d0_valid_ratio is not None:
        d0 = depth.d0_valid_ratio
        if not finite(d0) or d0 < T.liveness.depth.d0_valid_fail_below:
            failing.add("QUALITY_DEPTH_INVALID")
    if not failing and len(usable) < Q.min_usable_frames:
        raise ValueError(f"only {len(frames)} frames submitted; need >= {Q.min_usable_frames}")
    codes = tuple(c for c in QUALITY_CODES if c in failing)
    return QualityResult(usable=tuple(usable), codes=codes, dropped=tuple(dropped))
