"""M2 RGB mask cue: closed edge ring around the eyes (paper/latex mask eye holes). Pure, own code.

For each eye keypoint we sample the *radial* image gradient on an annulus r in [R0, R1] x IOD
around the eye centre (ANGLES directions). A cut-out eye hole produces a strong radial edge at a
consistent radius in (almost) every direction; a real eye region has strong edges mainly at the
brow and eyelids (a few directions, varying radius). Per eye:
    coverage = fraction of directions whose max radial gradient >= K x (median face gradient)
               AND whose edge radius is within RADIUS_TOL x IOD of the median edge radius
Score = mean over both eyes of clip((coverage - C0) / (C1 - C0), 0, 1).
R0/R1/K/RADIUS_TOL/C0/C1 are feature-definition constants; the cue bands are
liveness.mask.m2_ring_score_weak / _strong in thresholds.yaml. [cal] uncalibrated: soft evidence.

Gradients are computed on a region of interest only: the face box plus both eye annuli plus
ROI_MARGIN_PX (blur + Sobel support + bilinear tap), clamped to the frame. Every sampled gradient is
far enough from an interior ROI edge that it equals the full-frame value, and the frame borders stay
where they were, so the signal is unchanged while a 4096 x 4096 frame no longer costs ~281 MB of
float32 temporaries per call (audit EM-08).
"""

from __future__ import annotations

import cv2
import numpy as np
from pydantic import BaseModel

from edge.ml.detect import FaceBox

ANGLES = 24
R0, R1, N_R = 0.22, 0.50, 15
K = 3.0
RADIUS_TOL = 0.08
C0, C1 = 0.35, 0.90
MIN_IOD_PX = 30.0
# GaussianBlur(sigma 1.0) on float32 uses a 9-tap kernel (radius 4) + Sobel 3x3 (radius 1) + the
# bilinear remap's second tap (1) = 6 px of support; 8 px leaves slack. Geometry, not a threshold.
ROI_MARGIN_PX = 8

_theta = np.linspace(0.0, 2 * np.pi, ANGLES, endpoint=False)
_rad = np.linspace(R0, R1, N_R)


class MaskRingSignal(BaseModel):
    mask_edge_ring: float | None
    coverage: list[float] = []


def _eye_coverage(gx: np.ndarray, gy: np.ndarray, centre: np.ndarray, iod: float, norm: float) -> float:
    cos_t, sin_t = np.cos(_theta)[:, None], np.sin(_theta)[:, None]
    r = (_rad * iod)[None, :]
    map_x = (centre[0] + r * cos_t).astype(np.float32)
    map_y = (centre[1] + r * sin_t).astype(np.float32)
    sx = cv2.remap(gx, map_x, map_y, cv2.INTER_LINEAR, borderMode=cv2.BORDER_CONSTANT, borderValue=0)
    sy = cv2.remap(gy, map_x, map_y, cv2.INTER_LINEAR, borderMode=cv2.BORDER_CONSTANT, borderValue=0)
    radial = np.abs(sx * cos_t + sy * sin_t) / norm  # (ANGLES, N_R)
    peak = radial.max(axis=1)
    peak_r = _rad[radial.argmax(axis=1)]
    strong = peak >= K
    if not np.any(strong):
        return 0.0
    med_r = float(np.median(peak_r[strong]))
    consistent = strong & (np.abs(peak_r - med_r) <= RADIUS_TOL)
    return float(consistent.mean())


def _roi(kps: np.ndarray, iod: float, box: tuple[int, int, int, int], w: int, h: int) -> tuple[int, int, int, int]:
    """Frame-clamped bounds covering the face box and both eye annuli plus ROI_MARGIN_PX."""
    reach = R1 * iod
    eyes = kps[:2]
    lo_x = min(float(box[0]), float(eyes[:, 0].min()) - reach) - ROI_MARGIN_PX
    lo_y = min(float(box[1]), float(eyes[:, 1].min()) - reach) - ROI_MARGIN_PX
    hi_x = max(float(box[2]), float(eyes[:, 0].max()) + reach) + ROI_MARGIN_PX
    hi_y = max(float(box[3]), float(eyes[:, 1].max()) + reach) + ROI_MARGIN_PX
    rx1, ry1 = int(np.clip(np.floor(lo_x), 0, box[0])), int(np.clip(np.floor(lo_y), 0, box[1]))
    rx2, ry2 = int(np.clip(np.ceil(hi_x), box[2], w)), int(np.clip(np.ceil(hi_y), box[3], h))
    return rx1, ry1, rx2, ry2


def mask_ring_signal(bgr: np.ndarray, face: FaceBox | None) -> MaskRingSignal:
    if face is None:
        return MaskRingSignal(mask_edge_ring=None)
    kps = np.asarray(face.kps, dtype=np.float32)
    iod = float(np.hypot(*(kps[1] - kps[0])))
    if iod < MIN_IOD_PX:
        return MaskRingSignal(mask_edge_ring=None)
    h, w = bgr.shape[:2]
    x1, y1, x2, y2 = face.clipped(w, h)
    rx1, ry1, rx2, ry2 = _roi(kps, iod, (x1, y1, x2, y2), w, h)
    roi = bgr[ry1:ry2, rx1:rx2]
    gray = cv2.GaussianBlur(cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY).astype(np.float32), (0, 0), 1.0)
    gx = cv2.Sobel(gray, cv2.CV_32F, 1, 0, ksize=3)
    gy = cv2.Sobel(gray, cv2.CV_32F, 0, 1, ksize=3)
    mag = np.hypot(gx[y1 - ry1:y2 - ry1, x1 - rx1:x2 - rx1], gy[y1 - ry1:y2 - ry1, x1 - rx1:x2 - rx1])
    norm = float(np.median(mag)) + 1.0
    offset = np.array([rx1, ry1], dtype=np.float32)
    cov = [_eye_coverage(gx, gy, kps[i] - offset, iod, norm) for i in (0, 1)]
    score = float(np.mean([np.clip((c - C0) / (C1 - C0), 0.0, 1.0) for c in cov]))
    return MaskRingSignal(mask_edge_ring=round(score, 4), coverage=[round(c, 3) for c in cov])
