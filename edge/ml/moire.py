"""Moire / screen-pattern signal: FFT peak prominence on the grey face ROI (pure, own code).

Method: grey face crop -> 128x128 (INTER_AREA) -> zero mean -> 2-D Hann window -> log power
spectrum -> subtract the radial median profile (removes the natural 1/f fall-off) -> take the
strongest residual peak in the band r in [R_LO, R_HI] of Nyquist, ignoring a narrow cross on the
u=0 / v=0 axes (JPEG 8x8 block artefacts and frame edges are axis-aligned; screen moire is usually
rotated). Natural skin gives residual peaks ~2-3.5 (max of ~5k chi-square bins); recaptured screens
show isolated peaks well above that.

The 0-1 score is a fixed linear map of the peak (Z0 -> 0, Z1 -> 1). Z0/Z1 are feature-normalisation
constants, not decision thresholds; decisions use liveness.moire.unsure_score / fail_score.
[cal] Both the map and the YAML bands must be calibrated on demo-webcam live vs phone-replay
captures at the kiosk JPEG quality.
"""

from __future__ import annotations

import cv2
import numpy as np
from pydantic import BaseModel

from edge.ml.detect import FaceBox

N = 128
R_LO, R_HI = 0.25, 0.95
AXIS_HALF_WIDTH = 2  # bins
Z0, Z1 = 3.0, 7.0

_win = np.outer(np.hanning(N), np.hanning(N)).astype(np.float32)
_yy, _xx = np.mgrid[-N // 2 : N // 2, -N // 2 : N // 2]
_R = np.hypot(_xx, _yy) / (N / 2)
_RBIN = np.clip((_R * (N / 2)).astype(int), 0, N)
_BAND = (_R >= R_LO) & (_R <= R_HI) & (np.abs(_xx) > AXIS_HALF_WIDTH) & (np.abs(_yy) > AXIS_HALF_WIDTH)
_BIN_IDX = {int(rb): np.flatnonzero((_RBIN == rb) & _BAND) for rb in np.unique(_RBIN[_BAND])}
_BAND_FLAT = np.flatnonzero(_BAND)
_HF = (_R >= R_LO) & (_R <= 1.0)
_ALL = (_R > 0.02) & (_R <= 1.0)


class MoireSignal(BaseModel):
    moire: float | None
    peak_z: float | None = None
    hf_ratio: float | None = None


def moire_from_gray(gray: np.ndarray) -> MoireSignal:
    """Score a grey face crop (any size >= 32 px)."""
    if gray.size == 0 or min(gray.shape[:2]) < 32:
        return MoireSignal(moire=None)
    g = cv2.resize(gray, (N, N), interpolation=cv2.INTER_AREA).astype(np.float32)
    g -= g.mean()
    power = np.abs(np.fft.fftshift(np.fft.fft2(g * _win))) ** 2
    logp = np.log(power + 1e-6).ravel()
    profile = np.zeros(N + 1, dtype=np.float64)
    for rb, idx in _BIN_IDX.items():
        profile[rb] = np.median(logp[idx])
    resid = logp - profile[_RBIN.ravel()]
    peak = float(resid[_BAND_FLAT].max())
    total = float(power[_ALL].sum()) + 1e-9
    hf = float(power[_HF].sum()) / total
    score = float(np.clip((peak - Z0) / (Z1 - Z0), 0.0, 1.0))
    return MoireSignal(moire=round(score, 4), peak_z=round(peak, 3), hf_ratio=round(hf, 5))


def moire_signal(bgr: np.ndarray, face: FaceBox | None) -> MoireSignal:
    if face is None:
        return MoireSignal(moire=None)
    h, w = bgr.shape[:2]
    x1, y1, x2, y2 = face.clipped(w, h)
    gray = cv2.cvtColor(bgr[y1:y2, x1:x2], cv2.COLOR_BGR2GRAY)
    return moire_from_gray(gray)
