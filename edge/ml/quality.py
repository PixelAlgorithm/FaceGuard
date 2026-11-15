"""Per-frame quality measurements (pure). Produces the policy's FrameQuality; never decides.

Pose is a 5-keypoint geometric *proxy* (no head-pose network):
  roll  = eye-line angle;
  yaw   = atan(2 * (nose_x - eye_mid_x) / IOD)      (nose tip ~0.5 IOD in front of the eye plane);
  pitch = asin(v / R) - beta, v = (nose_y - eye_mid_y) / IOD, solved for the same rigid model with
          the frontal offset 0.571 taken from the ArcFace 112x112 reference template.
All three are measured in the de-rolled face frame. They are coarse (+-5-10 deg) and uncalibrated.
"""

from __future__ import annotations

import math

import cv2
import numpy as np

from edge.ml.detect import FaceBox
from edge.policy.signals import FrameQuality

OVEREXPOSED_Y = 250  # thresholds.yaml: "fraction of ROI pixels Y>=250 (backlight)"
_NOSE_DEPTH_IOD = 0.5  # rigid-face model constant for the yaw/pitch proxies
_FRONTAL_V = 0.571  # (nose_y - eye_y) / IOD on the ArcFace reference template
_R = math.hypot(_FRONTAL_V, _NOSE_DEPTH_IOD)
_BETA = math.asin(_FRONTAL_V / _R)


def luma_stats(bgr: np.ndarray, face: FaceBox) -> tuple[float, float]:
    """Mean luma (0-255) and over-exposed fraction (Y >= 250) inside the face box."""
    h, w = bgr.shape[:2]
    x1, y1, x2, y2 = face.clipped(w, h)
    roi = cv2.cvtColor(bgr[y1:y2, x1:x2], cv2.COLOR_BGR2GRAY)
    if roi.size == 0:
        return 0.0, 0.0
    return float(roi.mean()), float((roi >= OVEREXPOSED_Y).mean())


def laplacian_var(aligned112_bgr: np.ndarray) -> float:
    gray = cv2.cvtColor(aligned112_bgr, cv2.COLOR_BGR2GRAY)
    return float(cv2.Laplacian(gray, cv2.CV_64F).var())


def pose_from_kps(kps: np.ndarray) -> tuple[float, float, float, float]:
    """Return (iod_px, yaw_deg, pitch_deg, roll_deg) from 5 keypoints (proxy, see module doc)."""
    le, re, nose = (np.asarray(kps[i], dtype=np.float64) for i in range(3))
    d = re - le
    iod = float(np.hypot(d[0], d[1]))
    if iod < 1e-6:
        return 0.0, 0.0, 0.0, 0.0
    roll = math.atan2(d[1], d[0])
    c, s = math.cos(-roll), math.sin(-roll)
    mid = (le + re) / 2.0
    rel = nose - mid
    nx, ny = c * rel[0] - s * rel[1], s * rel[0] + c * rel[1]  # de-rolled nose offset
    yaw = math.degrees(math.atan(nx / iod / _NOSE_DEPTH_IOD))
    v = float(np.clip(ny / iod / _R, -1.0, 1.0))
    pitch = math.degrees(math.asin(v) - _BETA)
    return iod, yaw, pitch, math.degrees(roll)


def frame_quality(
    bgr: np.ndarray, faces: list[FaceBox], aligned112: np.ndarray | None
) -> FrameQuality:
    """Quality measurements for one frame. `faces` sorted by area desc; main face = faces[0]."""
    if not faces:
        gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
        return FrameQuality(
            face_count=0,
            secondary_face_rel_size=0.0,
            luma_mean=float(gray.mean()),
            overexposed_frac=float((gray >= OVEREXPOSED_Y).mean()),
            laplacian_var=0.0,
            face_width_px=0.0,
            iod_px=0.0,
            yaw_deg=0.0,
            pitch_deg=0.0,
            roll_deg=0.0,
        )
    main = faces[0]
    secondary = (faces[1].area / main.area) if len(faces) > 1 and main.area > 0 else 0.0
    luma, over = luma_stats(bgr, main)
    iod, yaw, pitch, roll = pose_from_kps(main.kps)
    return FrameQuality(
        face_count=len(faces),
        secondary_face_rel_size=round(float(secondary), 4),
        luma_mean=round(luma, 2),
        overexposed_frac=round(over, 4),
        laplacian_var=round(laplacian_var(aligned112), 2) if aligned112 is not None else 0.0,
        face_width_px=round(main.width, 1),
        iod_px=round(iod, 1),
        yaw_deg=round(yaw, 1),
        pitch_deg=round(pitch, 1),
        roll_deg=round(roll, 1),
    )
