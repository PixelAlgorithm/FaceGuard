"""Colour-flash reflection signal (original implementation; no third-party code).

The kiosk paints the server-issued colour sequence full-screen; skin reflects it with a short
display->camera lag. We compare the *chromaticity* (r,g,b)/(r+g+b) of the face ROI (cancels most
auto-exposure gain) with the chromaticity of the colour that was on screen `lag` ms earlier.

Sources:
  * frame series  - ROI means the server measured itself on the uploaded JPEG frames (trusted);
  * client series - dense ROI means reported by the browser (~30 fps; untrusted, used for timing).
r = r_frames ONLY (ratified): the edge-measured frame correlation. The client series is untrusted and
noisy, so it never raises or lowers r; it only picks the lag inside the frame-feasible range and stays
in the debug record (r_client). If the frames do not cover >= 2 colour segments the server cannot
verify anything and r is None (FLASH_FRAMES_INSUFFICIENT).

Outputs (FlashSignal): r, lag_frames, lag_std_frames, amplitude (mean |dRGB| 0-255 between
consecutive colour plateaus), order_ok, skin_score. Decisions are the policy's job.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass

import numpy as np
from pydantic import BaseModel

from edge.policy.signals import FlashSignal

LAG_SEARCH_MIN_FRAMES = -2.0  # search window for the best lag (wider than the policy window so
LAG_SEARCH_EXTRA_FRAMES = 4.0  # out-of-window lags are *reported*, not hidden)
EVENT_TOL_MS = 40.0  # + 2 frame intervals: allowed paint-time jitter vs the issued offsets
MIN_CLIENT_SAMPLES = 6


@dataclass(frozen=True)
class Step:
    color: str
    offset_ms: float
    duration_ms: float


@dataclass(frozen=True)
class Event:
    step_index: int
    color: str
    shown_at_ms: float


class FlashAnalysis(BaseModel):
    signal: FlashSignal
    r_frames: float | None = None
    r_client: float | None = None
    lag_ms: float | None = None
    events_consistent: bool | None = None
    response_order_ok: bool | None = None
    n_frame_samples: int = 0
    n_client_samples: int = 0
    reason_candidates: list[str] = []


def hex_to_rgb(color: str) -> np.ndarray:
    c = color.lstrip("#")
    return np.array([int(c[i : i + 2], 16) for i in (0, 2, 4)], dtype=np.float64)


def chroma(rgb: np.ndarray) -> np.ndarray:
    rgb = np.atleast_2d(np.asarray(rgb, dtype=np.float64))
    return rgb / np.maximum(rgb.sum(axis=1, keepdims=True), 1e-6)


def _pearson(obs: np.ndarray, exp: np.ndarray) -> float | None:
    """Pooled per-channel Pearson. A flat observation against a varying stimulus scores 0.0 (it
    provably does not follow the flash); an undefined stimulus (one colour only) gives None."""
    a = obs - obs.mean(axis=0)
    b = exp - exp.mean(axis=0)
    va, vb = float((a * a).sum()), float((b * b).sum())
    if vb <= 1e-12:
        return None
    if va <= 1e-12:
        return 0.0
    return float((a * b).sum() / np.sqrt(va * vb))


def check_events(steps: list[Step], events: list[Event], frame_ms: float) -> bool | None:
    """Client paint log must reproduce the issued sequence (colours, order, relative timing)."""
    if not events:
        return None
    ev = sorted(events, key=lambda e: e.step_index)
    if [e.step_index for e in ev] != list(range(len(steps))):
        return False
    if any(e.color.lower() != s.color.lower() for e, s in zip(ev, steps)):
        return False
    t0 = ev[0].shown_at_ms
    tol = EVENT_TOL_MS + 2.0 * frame_ms
    for e, s in zip(ev, steps):
        if abs((e.shown_at_ms - t0) - (s.offset_ms - steps[0].offset_ms)) > tol:
            return False
    return all(b.shown_at_ms > a.shown_at_ms for a, b in itertools.pairwise(ev))


def segment_bounds(steps: list[Step], events: list[Event], capture_started_at_ms: float,
                   use_events: bool) -> tuple[np.ndarray, np.ndarray]:
    """Start/end epoch-ms of each colour segment (client paint times if consistent)."""
    if use_events:
        ev = sorted(events, key=lambda e: e.step_index)
        starts = np.array([e.shown_at_ms for e in ev], dtype=np.float64)
    else:
        starts = np.array([capture_started_at_ms + s.offset_ms for s in steps], dtype=np.float64)
    ends = np.append(starts[1:], starts[-1] + steps[-1].duration_ms)
    return starts, ends


def _segment_index(t: np.ndarray, starts: np.ndarray, ends: np.ndarray, settle_ms: float) -> np.ndarray:
    idx = np.full(t.shape, -1, dtype=int)
    for k, (s, e) in enumerate(zip(starts, ends)):
        idx[(t >= s + settle_ms) & (t < e)] = k
    return idx


def _best_lag(t: np.ndarray, obs_c: np.ndarray, starts: np.ndarray, ends: np.ndarray,
              exp_c: np.ndarray, lags: np.ndarray, settle_ms: float
              ) -> tuple[float | None, float | None, float | None]:
    """Best pooled chroma correlation and the [min, max] range of lags (ms) that attain it."""
    rs: list[float] = []
    for lag in lags:
        seg = _segment_index(t - lag, starts, ends, settle_ms)
        ok = seg >= 0
        if ok.sum() < 3 or len(set(seg[ok].tolist())) < 2:
            rs.append(-np.inf)
            continue
        r = _pearson(obs_c[ok], exp_c[seg[ok]])
        rs.append(-np.inf if r is None else r)
    arr = np.array(rs)
    if not np.isfinite(arr).any():
        return None, None, None
    best = float(arr.max())
    tied = lags[np.isclose(arr, best, atol=1e-9)]
    return best, float(tied.min()), float(tied.max())


def _plateaus(t: np.ndarray, rgb: np.ndarray, starts: np.ndarray, ends: np.ndarray,
              lag: float, settle_ms: float) -> list[np.ndarray | None]:
    seg = _segment_index(t - lag, starts, ends, settle_ms)
    return [np.median(rgb[seg == k], axis=0) if np.any(seg == k) else None for k in range(len(starts))]


def _amplitude(plateaus: list[np.ndarray | None]) -> float | None:
    vals = [p for p in plateaus if p is not None]
    if len(vals) < 2:
        return None
    return float(np.mean([np.abs(b - a).mean() for a, b in itertools.pairwise(vals)]))


def _response_order(plateaus: list[np.ndarray | None], exp_c: np.ndarray) -> bool | None:
    """True if the issued colour order explains the observed plateaus at least as well as every
    other permutation of the same colours (pooled chroma correlation)."""
    ks = [k for k, p in enumerate(plateaus) if p is not None]
    if len(ks) < 2:
        return None
    obs = chroma(np.array([plateaus[k] for k in ks]))
    r_issued = _pearson(obs, exp_c[ks])
    if r_issued is None:
        return None
    for perm in itertools.permutations(ks):
        if list(perm) == ks:
            continue
        r = _pearson(obs, exp_c[list(perm)])
        if r is not None and r > r_issued + 1e-9:
            return False
    return True


def _transition_lags(t: np.ndarray, obs_c: np.ndarray, starts: np.ndarray, ends: np.ndarray,
                     lag: float, settle_ms: float) -> list[float]:
    plate = _plateaus(t, obs_c, starts, ends, lag, settle_ms)
    lags: list[float] = []
    for k in range(1, len(starts)):
        a, b = plate[k - 1], plate[k]
        if a is None or b is None:
            continue
        d = b - a
        span = float(np.linalg.norm(d))
        if span < 1e-4:
            continue
        s = (obs_c - a) @ (d / span) / span
        win = (t >= starts[k] - settle_ms) & (t < ends[k] + lag)
        tt, ss = t[win], s[win]
        for i in range(1, len(tt)):
            if ss[i - 1] < 0.5 <= ss[i]:
                tc = tt[i - 1] + (0.5 - ss[i - 1]) * (tt[i] - tt[i - 1]) / max(ss[i] - ss[i - 1], 1e-9)
                lags.append(tc - starts[k])
                break
    return lags


def _skin_score(steps: list[Step], plateaus: list[np.ndarray | None]) -> float | None:
    """Spectral cue: skin reflects blue light much less than red light; paper/screens ~equally.

    ratio = (B-channel rise under the bluest colour) / (R-channel rise under the reddest colour),
    rises measured against the mean plateau. Skin ~0.3-0.7, flat white media ~1. [cal]
    """
    cols = np.array([hex_to_rgb(s.color) for s in steps])
    have = [k for k, p in enumerate(plateaus) if p is not None]
    if len(have) < 3:
        return None
    red_k = max(have, key=lambda k: cols[k, 0] - cols[k, 1:].mean())
    blue_k = max(have, key=lambda k: cols[k, 2] - cols[k, :2].mean())
    if red_k == blue_k:
        return None
    base = np.mean([plateaus[k] for k in have], axis=0)
    rise_r = float(plateaus[red_k][0] - base[0])
    rise_b = float(plateaus[blue_k][2] - base[2])
    if rise_r <= 0.5:
        return None
    ratio = rise_b / rise_r
    return float(np.clip(1.0 - abs(ratio - 0.5) / 0.6, 0.0, 1.0))


def flash_signal(
    steps: list[Step],
    events: list[Event],
    capture_started_at_ms: float,
    frame_series: list[tuple[float, float, float, float]],
    client_series: list[tuple[float, float, float, float]],
    frame_interval_ms: float,
    min_amplitude: float,
    lag_max_frames: float,
) -> FlashAnalysis:
    """Pure: issued sequence + client paint log + ROI colour series -> FlashSignal (+ debug)."""
    frame_ms = float(frame_interval_ms) if frame_interval_ms and frame_interval_ms > 1 else 33.3
    if len(steps) < 2:
        return FlashAnalysis(signal=FlashSignal(), reason_candidates=["FLASH_NOT_ISSUED"])
    events_ok = check_events(steps, events, frame_ms)
    starts, ends = segment_bounds(steps, events, capture_started_at_ms, use_events=bool(events_ok))
    exp_c = chroma(np.array([hex_to_rgb(s.color) for s in steps]))
    settle = 0.0
    lags = np.arange(LAG_SEARCH_MIN_FRAMES * frame_ms,
                     (lag_max_frames + LAG_SEARCH_EXTRA_FRAMES) * frame_ms + 1e-6, frame_ms / 2.0)

    def prep(series: list[tuple[float, float, float, float]]) -> tuple[np.ndarray, np.ndarray]:
        if not series:
            return np.zeros(0), np.zeros((0, 3))
        arr = np.array(sorted(series), dtype=np.float64)
        return arr[:, 0], arr[:, 1:4]

    tf, rgbf = prep(frame_series)
    tc, rgbc = prep(client_series)
    r_f, f_lo, f_hi = (_best_lag(tf, chroma(rgbf), starts, ends, exp_c, lags, settle) if len(tf) >= 3
                       else (None, None, None))
    r_c, lag_c = None, None
    if len(tc) >= MIN_CLIENT_SAMPLES:
        r_c, c_lo, c_hi = _best_lag(tc, chroma(rgbc), starts, ends, exp_c, lags, frame_ms)
        lag_c = None if c_lo is None else (c_lo + c_hi) / 2.0

    reasons: list[str] = []
    if r_f is None:
        reasons.append("FLASH_FRAMES_INSUFFICIENT")
        r = None
    else:
        # Decide on the edge-measured frame correlation only. The client chroma series is untrusted
        # (forgeable by an injection attacker) AND measured noisily in the browser: on the operator's
        # real webcam (n=14 genuine, 2026-11-14) r_frames was 0.86-0.99 while r_client swung 0.33-0.98,
        # so min(r_f, r_c) produced false SPOOF_FLASH_MISMATCH DENYs. Ignoring r_c entirely also means a
        # forged client series can neither raise nor lower r. r_c stays in the debug record only.
        r = r_f
    # Lag (flash_events vs frame timestamps): the trusted frames define the feasible lag range
    # [f_lo, f_hi] (every lag that explains them equally well); the dense client series only picks a
    # point inside it, so a forged series can never hide a replay loop. Without a client series the
    # smallest non-negative feasible lag is reported (frames are ~200 ms apart, the range is wide).
    lag_ms: float | None = None
    if f_lo is not None and f_hi is not None:
        lag_ms = float(np.clip(lag_c if lag_c is not None else 0.0, f_lo, f_hi))
    elif lag_c is not None:
        lag_ms = lag_c

    # amplitude + order + skin from the trusted frame plateaus (client plateaus only as fallback),
    # segmented at the best lag clipped to the plausible display->camera window: a response that
    # follows the wrong sequence must not shrink its own amplitude by picking a spurious lag.
    lag_seg = float(np.clip(lag_ms if lag_ms is not None else 0.0, 0.0, lag_max_frames * frame_ms))
    plate = _plateaus(tf, rgbf, starts, ends, lag_seg, settle) if len(tf) else []
    amp = _amplitude(plate) if plate else None
    if amp is None and len(tc) >= MIN_CLIENT_SAMPLES:
        plate = _plateaus(tc, rgbc, starts, ends, lag_seg, frame_ms)
        amp = _amplitude(plate)
    resp_ok = _response_order(plate, exp_c) if plate and amp is not None and amp >= min_amplitude else None
    if events_ok is False or resp_ok is False:
        order_ok: bool | None = False
    elif events_ok is None:
        order_ok = None
    else:
        order_ok = True

    lag_std = None
    if len(tc) >= MIN_CLIENT_SAMPLES and lag_ms is not None:
        tl = _transition_lags(tc, chroma(rgbc), starts, ends, lag_seg, frame_ms)
        if len(tl) >= 2:
            lag_std = float(np.std(tl)) / frame_ms
    if amp is not None and amp < min_amplitude:
        reasons.append("FLASH_WEAK_SIGNAL")
    if events_ok is False:
        reasons.append("FLASH_EVENTS_MISMATCH")
    if r_c is not None and r_f is not None and r_c - r_f > 0.3:
        reasons.append("FLASH_SERIES_MISMATCH")

    sig = FlashSignal(
        r=None if r is None else round(float(r), 4),
        lag_frames=None if lag_ms is None else round(lag_ms / frame_ms, 3),
        lag_std_frames=None if lag_std is None else round(lag_std, 3),
        lag_ms=None if lag_ms is None else round(lag_ms, 1),
        lag_std_ms=None if lag_std is None else round(lag_std * frame_ms, 1),
        fps=round(1000.0 / frame_ms, 2),
        amplitude=None if amp is None else round(float(amp), 3),
        order_ok=order_ok,
        skin_score=None if not plate or amp is None else _round(_skin_score(steps, plate)),
    )
    return FlashAnalysis(
        signal=sig, r_frames=_round(r_f), r_client=_round(r_c), lag_ms=_round(lag_ms),
        events_consistent=events_ok, response_order_ok=resp_ok, n_frame_samples=len(tf),
        n_client_samples=len(tc), reason_candidates=reasons,
    )


def _round(v: float | None, nd: int = 4) -> float | None:
    return None if v is None else round(float(v), nd)


def skin_roi_rgb(bgr: np.ndarray, kps: np.ndarray) -> tuple[float, float, float] | None:
    """Mean (R, G, B) over forehead + both cheeks (eyes, brows and mouth excluded), from 5 kps."""
    k = np.asarray(kps, dtype=np.float64)
    le, re, _nose, lm, rm = k
    iod = float(np.hypot(*(re - le)))
    if iod < 10:
        return None
    eye_y = (le[1] + re[1]) / 2.0
    mouth_y = (lm[1] + rm[1]) / 2.0
    h, w = bgr.shape[:2]
    half = 0.16 * iod
    cheek_y = (eye_y + mouth_y) / 2.0 + 0.05 * iod
    rects = [
        (min(le[0], re[0]), eye_y - 0.62 * iod, max(le[0], re[0]), eye_y - 0.30 * iod),  # forehead
        (le[0] - half, cheek_y - half, le[0] + half, cheek_y + half),  # image-left cheek
        (re[0] - half, cheek_y - half, re[0] + half, cheek_y + half),  # image-right cheek
    ]
    acc, n = np.zeros(3), 0
    for x1, y1, x2, y2 in rects:
        xa, ya = int(np.clip(x1, 0, w - 1)), int(np.clip(y1, 0, h - 1))
        xb, yb = int(np.clip(x2, xa + 1, w)), int(np.clip(y2, ya + 1, h))
        patch = bgr[ya:yb, xa:xb].reshape(-1, 3)
        acc += patch.sum(axis=0)
        n += patch.shape[0]
    if n == 0:
        return None
    b, g, r = acc / n
    return float(r), float(g), float(b)
