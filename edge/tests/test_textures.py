"""Moire FFT score, M2 eye-hole ring score, device rule, quality pose proxies (pure functions)."""

from __future__ import annotations

import cv2
import numpy as np
from skimage import data as skdata

from edge.ml.detect import FaceBox
from edge.ml.device import DeviceBox, containment, device_signal
from edge.ml.mask import mask_ring_signal
from edge.ml.moire import moire_from_gray
from edge.ml.quality import frame_quality, pose_from_kps

ARC = np.array([[38.2946, 51.6963], [73.5318, 51.5014], [56.0252, 71.7366],
                [41.5493, 92.3655], [70.7299, 92.2041]], np.float32)


def astronaut_face_gray() -> np.ndarray:
    img = cv2.cvtColor(skdata.astronaut(), cv2.COLOR_RGB2GRAY)
    return img[62:178, 181:268]  # face box of the public-domain NASA portrait


def test_moire_natural_face_low_grating_high():
    face = astronaut_face_gray()
    natural = moire_from_gray(face)
    h, w = face.shape
    yy, xx = np.mgrid[0:h, 0:w]
    th = np.deg2rad(17)
    grating = np.clip(face + 20 * np.sin(2 * np.pi * (xx * np.cos(th) + yy * np.sin(th)) / 3.1), 0, 255)
    screen = moire_from_gray(grating.astype(np.uint8))
    assert natural.moire is not None and natural.moire < 0.4
    assert screen.moire is not None and screen.moire > natural.moire + 0.3


def test_moire_too_small_is_missing():
    assert moire_from_gray(np.zeros((10, 10), np.uint8)).moire is None


def _face_box(kps: np.ndarray, pad: float = 60) -> FaceBox:
    x1, y1 = kps.min(axis=0) - pad
    x2, y2 = kps.max(axis=0) + pad
    return FaceBox(float(x1), float(y1), float(x2), float(y2), 0.99, kps.astype(np.float32))


def test_mask_ring_detects_eye_holes():
    rng = np.random.default_rng(0)
    skin = np.clip(rng.normal(150, 6, (400, 400, 3)), 0, 255).astype(np.uint8)
    kps = np.array([[150, 170], [250, 170], [200, 230], [160, 290], [240, 290]], np.float32)
    face = _face_box(kps)
    real = mask_ring_signal(cv2.GaussianBlur(skin, (0, 0), 2), face)
    paper = skin.copy()
    for e in kps[:2]:
        cv2.circle(paper, (int(e[0]), int(e[1])), 33, (40, 30, 30), -1)  # dark hole, sharp rim
    masked = mask_ring_signal(paper, face)
    assert real.mask_edge_ring is not None and real.mask_edge_ring < 0.5
    assert masked.mask_edge_ring is not None and masked.mask_edge_ring >= 0.75


def test_mask_ring_missing_face():
    assert mask_ring_signal(np.zeros((100, 100, 3), np.uint8), None).mask_edge_ring is None


def test_device_rule_containment_and_severity():
    face = FaceBox(100, 100, 200, 200, 0.99, np.zeros((5, 2), np.float32))
    holding = DeviceBox(cls=67, label="cell phone", conf=0.9, x1=190, y1=150, x2=300, y2=400)  # overlaps a bit
    screen = DeviceBox(cls=67, label="cell phone", conf=0.5, x1=80, y1=80, x2=230, y2=260)  # contains the face
    far = DeviceBox(cls=63, label="laptop", conf=0.95, x1=400, y1=0, x2=600, y2=200)
    assert containment(face, screen) == 1.0
    sig = device_signal(face, [holding, screen, far], face_containment_min=0.8, fail_conf=0.4)
    assert sig.device_conf == 0.5 and sig.device_face_containment == 1.0 and sig.n_device_boxes == 3
    only_hand = device_signal(face, [holding, far], face_containment_min=0.8, fail_conf=0.4)
    assert only_hand.device_conf == 0.9 and only_hand.device_face_containment < 0.8
    assert device_signal(face, [far], 0.8, 0.4).device_conf == 0.0
    assert device_signal(None, [screen], 0.8, 0.4).device_conf == 0.0


def test_pose_proxy_frontal_template_is_zero():
    iod, yaw, pitch, roll = pose_from_kps(ARC * 4)
    assert abs(yaw) < 1.0 and abs(pitch) < 1.0 and abs(roll) < 1.0
    assert abs(iod - 4 * 35.24) < 1.0


def test_pose_proxy_roll_and_yaw_signs():
    ang = np.deg2rad(10)
    rot = np.array([[np.cos(ang), -np.sin(ang)], [np.sin(ang), np.cos(ang)]])
    _, _, _, roll = pose_from_kps((ARC - ARC.mean(0)) @ rot.T + 200)
    assert 9.0 < roll < 11.0
    turned = ARC.copy()
    turned[2, 0] += 10  # nose towards image right
    assert pose_from_kps(turned)[1] > 10


def test_frame_quality_no_face_and_luma():
    img = np.full((480, 640, 3), 30, np.uint8)
    q = frame_quality(img, [], None)
    assert q.face_count == 0 and q.face_width_px == 0 and abs(q.luma_mean - 30) < 1
    face = FaceBox(100, 100, 300, 300, 0.99, (ARC * 2 + 120).astype(np.float32))
    bright = img.copy()
    bright[100:300, 100:300] = 255
    q2 = frame_quality(bright, [face], np.full((112, 112, 3), 128, np.uint8))
    assert q2.face_count == 1 and q2.overexposed_frac > 0.9 and q2.luma_mean > 250
    assert q2.laplacian_var == 0.0
