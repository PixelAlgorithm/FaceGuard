"""Stage 3 liveness fusion (DECISION_POLICY §3.3-3.4). Pure; re-runnable on the same raw scores
with another mode's thresholds (P7 flip, no re-inference).

Every signal is three-zone. A missing / non-finite signal is never a PASS (it is UNSURE), except
optional *soft* cues (mask ring, spectral) whose absence is simply "no cue".

Enforce switches (YAML, a missing key means enforce): `liveness.flash.enforce`, `liveness.moire.enforce`,
`liveness.mask.m2_rgb_enforce`. A switched-off signal is ADVISORY: computed exactly as when enforced and
reported (`signals[...] = "ADVISORY_<zone>"`, `advisory_cues`), with no decision effect. A *missing* moire
measurement stays UNSURE even when advisory (pipeline fault, not a calibration question; fail-secure).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from statistics import fmean
from typing import Any

from edge.policy.codes import order_codes
from edge.policy.quality import depth_active, finite
from edge.policy.signals import AttemptSignals, FrameSignals

PASS, UNSURE, FAIL, WEAK, NOT_AVAILABLE = "PASS", "UNSURE", "FAIL", "WEAK", "NOT_AVAILABLE"


@dataclass(frozen=True)
class LivenessResult:
    status: str
    hard_codes: tuple[str, ...]
    unsure_codes: tuple[str, ...]
    mask_codes: tuple[str, ...]  # all cues (weak or strong)
    strong_mask_codes: tuple[str, ...]
    signals: dict[str, str] = field(default_factory=dict)
    scores: dict[str, Any] = field(default_factory=dict)
    advisory_cues: dict[str, str] = field(default_factory=dict)  # cue -> weak|strong, measured, no effect


def enforced(section: Any, key: str = "enforce") -> bool:
    """Optional enforce switch of a YAML section; a missing key means enforce (type-checked at load)."""
    return bool(dict(section).get(key, True))


def frame_p_live(f: FrameSignals) -> float | None:
    """Per-frame P_live = mean(MiniFASNetV2, MiniFASNetV1SE); None unless both are valid probabilities."""
    a, b = f.pad_v2, f.pad_v1se
    if not (finite(a) and finite(b)) or not (0.0 <= a <= 1.0 and 0.0 <= b <= 1.0):
        return None
    return (a + b) / 2.0


def _pad(frames: Sequence[FrameSignals], P: Any) -> tuple[str, float | None, int]:
    plive = [frame_p_live(f) for f in frames]
    n = len(frames)
    pass_n = sum(1 for p in plive if p is not None and p >= P.pass_min)
    fail_n = sum(1 for p in plive if p is not None and p <= P.fail_max)
    valid = [p for p in plive if p is not None]
    mean = fmean(valid) if valid else None
    if n and fail_n * 2 > n:
        return FAIL, mean, pass_n
    if pass_n >= P.min_pass_frames and fail_n <= 1:  # R11: PASS also needs at most 1 spoof-like frame
        return PASS, mean, pass_n
    return UNSURE, mean, pass_n


def _device(frames: Sequence[FrameSignals], D: Any) -> tuple[str, float]:
    status, top = PASS, 0.0
    for f in frames:
        c, cont = f.device_conf, f.device_face_containment
        if not (finite(c) and finite(cont)):
            status = UNSURE if status != FAIL else FAIL
            continue
        top = max(top, c)
        if c >= D.fail_conf and cont >= D.face_containment:
            status = FAIL
        elif c >= D.unsure_conf and status != FAIL:
            status = UNSURE
    return status, top


def flash_lag_frames(s: Any) -> tuple[float | None, float | None]:
    """Lag (and its std) in frames. Prefers lag_ms / lag_std_ms converted with the measured fps (robust to
    the webcam pipeline delay); falls back to the producer's lag_frames / lag_std_frames."""
    fps_ok = finite(s.fps) and s.fps > 0
    lag = s.lag_ms * s.fps / 1000.0 if fps_ok and finite(s.lag_ms) else s.lag_frames
    std = s.lag_std_ms * s.fps / 1000.0 if fps_ok and finite(s.lag_std_ms) else s.lag_std_frames
    return lag, std


def _flash(att: AttemptSignals, F: Any) -> str:
    if not F.enabled or not att.flash_enabled:
        return NOT_AVAILABLE  # non-flash path (§3.3): adds LIVENESS_UNSURE -> a CHALLENGE is always required
    if att.flash is None:
        return UNSURE  # flash enabled but no measurement
    s = att.flash
    lag, lag_std = flash_lag_frames(s)
    if not finite(s.amplitude):
        return UNSURE
    if s.amplitude < F.min_amplitude:
        return WEAK  # low amplitude is never FAIL
    if not finite(s.r):
        return UNSURE
    lag_outside = finite(lag) and not (F.lag_min_frames <= lag <= F.lag_max_frames)
    if s.r < F.fail_max_r or lag_outside or s.order_ok is False:
        return FAIL
    if (s.r >= F.pass_min_r and finite(lag) and finite(lag_std) and lag_std <= F.lag_max_std_frames
            and s.order_ok is True):
        return PASS
    return UNSURE


def _three_zone(value: Any, fail_below: float, pass_above: float, *, pass_inclusive: bool) -> str:
    if not finite(value):
        return UNSURE
    if value < fail_below:
        return FAIL
    if value > pass_above or (pass_inclusive and value >= pass_above):
        return PASS
    return UNSURE


def _capped(status: str, value: Any, ceiling: float) -> str:
    """Plausibility ceiling (tighten-only): a PASS above `ceiling` is downgraded to UNSURE."""
    return UNSURE if status == PASS and finite(value) and value > float(ceiling) else status


def liveness_fusion(frames: Sequence[FrameSignals], att: AttemptSignals, inj_status: str, T: Any,
                    mode: str) -> LivenessResult:
    L = T.liveness
    hard: list[str] = []
    unsure = inj_status == UNSURE
    sig: dict[str, str] = {"injection": inj_status}

    pad, pad_mean, pad_pass = _pad(frames, L.pad)
    sig["pad"] = pad
    if pad == FAIL:
        hard.append("SPOOF_PASSIVE")

    dev, dev_top = _device(frames, L.device_detector)
    sig["device"] = dev
    if dev == FAIL:
        hard.append("SPOOF_DEVICE_DETECTED")

    M = L.moire
    m_vals = [f.moire for f in frames if finite(f.moire)]
    moire_score = max(m_vals) if m_vals else None

    flash = _flash(att, L.flash)
    ambient = (  # online only (P6, code-enforced); R12: also needs a clean device detector and moire < unsure
        flash == WEAK and mode == "ONLINE" and bool(L.flash.ambient_exception_enabled)
        and pad == PASS and pad_mean is not None and pad_mean >= L.pad.strong_live
        and dev == PASS and moire_score is not None and moire_score < M.unsure_score
    )
    if not enforced(L.flash) and flash != NOT_AVAILABLE:
        # Advisory mode (lead/operator decision 2026-11-14): the kiosk's real-camera flash timing is
        # not yet validated (genuine users got false SPOOF_FLASH_MISMATCH / step-ups). The flash is
        # still measured and reported in signals/scores, but cannot FAIL or step up an attempt until
        # liveness.flash.enforce is set back to true after calibration. The non-flash accessibility
        # path (NOT_AVAILABLE) is unchanged and still requires a CHALLENGE.
        flash_eff = PASS
        sig["flash"] = "ADVISORY_" + flash
    else:
        flash_eff = PASS if ambient else (UNSURE if flash == WEAK else flash)
        sig["flash"] = flash_eff if not ambient else "PASS_AMBIENT"
    if flash_eff == FAIL:
        hard.append("SPOOF_FLASH_MISMATCH")
    if moire_score is None:
        moire = UNSURE
    elif moire_score >= M.fail_score:
        corroborated = not (pad == PASS and flash_eff == PASS) if M.require_corroboration else True
        moire = FAIL if corroborated else UNSURE
    elif moire_score >= M.unsure_score:
        moire = UNSURE
    else:
        moire = PASS
    if enforced(M) or moire_score is None:
        moire_eff = moire
        sig["moire"] = moire
    else:
        # Advisory (liveness.moire.enforce: false, lead 2026-11-14): the flash-lit frames of genuine users
        # score 0.42-0.79 and there are no phone-replay captures to calibrate the bands on. Measured and
        # reported, no UNSURE / FAIL. The ambient-flash exception above still requires moire < unsure (R12).
        moire_eff = PASS
        sig["moire"] = "ADVISORY_" + moire
    if moire_eff == FAIL:
        hard.append("SPOOF_MOIRE")

    depth_scores: dict[str, Any] | None = None
    depth_statuses: list[str] = []
    use_depth = depth_active(att.depth, T)
    if use_depth and att.depth is not None:
        D, dp = L.depth, att.depth
        d0 = dp.d0_valid_ratio
        depth_statuses.append(UNSURE if not finite(d0) or d0 < D.d0_valid_pass_min else PASS)
        flat = [  # DE-05: a value above the physical ceiling is non-physical geometry -> UNSURE, never PASS
            _capped(_three_zone(dp.d1_plane_rms_mm, D.d1_plane_rms_fail_mm, D.d1_plane_rms_pass_mm,
                                pass_inclusive=False), dp.d1_plane_rms_mm, D.d1_plane_rms_max_mm),
            _capped(_three_zone(dp.d2_quad_rms_mm, D.d2_quad_rms_fail_mm, D.d2_quad_rms_pass_mm,
                                pass_inclusive=False), dp.d2_quad_rms_mm, D.d2_quad_rms_max_mm),
            _capped(_three_zone(dp.d3_nose_relief_mm, D.d3_nose_relief_fail_mm, D.d3_nose_relief_pass_mm,
                                pass_inclusive=True), dp.d3_nose_relief_mm, D.d3_nose_relief_max_mm),
        ]
        depth_statuses += flat
        if FAIL in flat:
            hard.append("SPOOF_FLAT_DEPTH")
        if dp.absolute or not D.require_absolute_depth_for_d4:
            if not finite(dp.d4_ipd_mm):
                depth_statuses.append(UNSURE)
            elif not (D.d4_ipd_min_mm <= dp.d4_ipd_mm <= D.d4_ipd_max_mm):
                depth_statuses.append(FAIL)
                hard.append("SPOOF_DEPTH_SCALE")
            else:
                depth_statuses.append(PASS)
        depth_scores = {k: getattr(dp, k) for k in (
            "d0_valid_ratio", "d1_plane_rms_mm", "d2_quad_rms_mm", "d3_nose_relief_mm", "d4_ipd_mm",
            "d5_disagree", "m2_depth_step_mm", "m3_template_rms_mm")}
        sig["depth"] = FAIL if FAIL in depth_statuses else (UNSURE if UNSURE in depth_statuses else PASS)
    else:
        sig["depth"] = NOT_AVAILABLE

    # ---- mask cues (soft evidence)
    K = L.mask
    cues: dict[str, str] = {}
    advisory: dict[str, str] = {}
    mask_scores: dict[str, float] = {}
    rings = [f.mask_edge_ring for f in frames if finite(f.mask_edge_ring)]
    ring = max(rings) if rings else None
    m2 = None
    if ring is not None:
        mask_scores["m2_ring"] = ring
        m2_rgb = "strong" if ring >= K.m2_ring_score_strong else ("weak" if ring >= K.m2_ring_score_weak else None)
        if enforced(K, "m2_rgb_enforce"):
            m2 = m2_rgb
        elif m2_rgb:
            # Advisory (liveness.mask.m2_rgb_enforce: false, lead 2026-11-14): spectacle frames score 0.35-0.80
            # on genuine users. Listed in advisory_cues; never a mask code, never counted as a strong cue.
            # The depth-based M2 step below (and M1 / M3) stay enforced.
            advisory["MASK_CUE_EDGE"] = m2_rgb
    if use_depth and att.depth is not None and finite(att.depth.m2_depth_step_mm):
        mask_scores["m2_depth_step_mm"] = att.depth.m2_depth_step_mm
        if att.depth.m2_depth_step_mm >= K.m2_depth_step_strong_mm:
            m2 = "strong"
    if m2:
        cues["MASK_CUE_EDGE"] = m2
    if use_depth and att.depth is not None and finite(att.depth.m3_template_rms_mm):
        m3v = att.depth.m3_template_rms_mm
        mask_scores["m3_template_rms_mm"] = m3v
        m3 = "strong" if m3v >= K.m3_template_rms_strong_mm else ("weak" if m3v >= K.m3_template_rms_weak_mm else None)
        if m3:
            cues["MASK_CUE_SHAPE"] = m3
    if K.spectral_enabled and att.flash is not None and finite(att.flash.skin_score):
        sk = att.flash.skin_score
        mask_scores["spectral_skin"] = sk
        sp = "strong" if sk <= K.spectral_skin_strong_max else ("weak" if sk <= K.spectral_skin_weak_max else None)
        if sp:
            cues["MASK_CUE_SPECTRAL"] = sp
    mask_codes = tuple(order_codes(cues))
    strong = tuple(order_codes(c for c, s in cues.items() if s == "strong"))
    sig["mask"] = _mask_zone(cues, advisory, int(K.strong_cue_deny_count))

    unsure = (unsure or UNSURE in (pad, dev, flash_eff, moire_eff) or flash_eff == NOT_AVAILABLE
              or UNSURE in depth_statuses)
    hard_t = tuple(order_codes(hard))
    if hard_t or len(strong) >= K.strong_cue_deny_count:
        status = FAIL
    elif unsure or mask_codes:
        status = UNSURE
    else:
        status = PASS
    flash_sig = att.flash
    scores = {
        "pad_mean": pad_mean,
        "pad_pass_frames": pad_pass,
        "flash_r": flash_sig.r if flash_sig is not None and finite(flash_sig.r) else None,
        "flash_amp": flash_sig.amplitude if flash_sig is not None and finite(flash_sig.amplitude) else None,
        "moire": moire_score,
        "device_conf": dev_top,
        "depth": depth_scores,
        "mask": mask_scores,
    }
    return LivenessResult(
        status=status,
        hard_codes=hard_t,
        unsure_codes=("LIVENESS_UNSURE",) if unsure else (),
        mask_codes=mask_codes,
        strong_mask_codes=strong,
        signals=sig,
        scores=scores,
        advisory_cues=advisory,
    )


def _mask_zone(cues: dict[str, str], advisory: dict[str, str], deny_count: int) -> str:
    """Per-signal mask status: FAIL (>= deny_count strong cues), UNSURE (any cue), PASS; when only advisory
    cues would change it, ADVISORY_<zone> of enforced + advisory cues together (reporting only)."""
    def zone(c: dict[str, str]) -> str:
        if sum(1 for v in c.values() if v == "strong") >= deny_count:
            return FAIL
        return UNSURE if c else PASS

    z = zone(cues)
    if z == PASS and advisory:
        return "ADVISORY_" + zone({**advisory, **cues})
    return z
