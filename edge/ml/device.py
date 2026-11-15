"""Device-in-frame signal: YOLOX-Tiny (Megvii, Apache-2.0) COCO detector, 416x416 letterbox.

Preprocessing follows the YOLOX 0.1.1rc0 ONNXRuntime demo: BGR uint8 letterboxed onto a 114-grey
canvas, no normalisation, then grid/stride decoding of the raw head output. COCO-80 contiguous ids
(cell phone 67, laptop 63, tv 62) come from thresholds.yaml `liveness.device_detector.classes`.

Signal = (device_conf, device_face_containment) per frame: the most severe device box overlapping
the face (prefers a box that is fail-grade: contains >= `face_containment` of the face box with
conf >= `fail_conf`; else the most confident one). No decision here.
"""

from __future__ import annotations

from pathlib import Path

import cv2
import numpy as np
from pydantic import BaseModel

from edge.ml.detect import FaceBox
from edge.ml.onnx import make_session

INPUT = 416
CANDIDATE_MIN_CONF = 0.10  # pre-NMS floor; policy bands start at liveness.device_detector.unsure_conf
NMS_IOU = 0.45
COCO_NAMES = {62: "tv", 63: "laptop", 67: "cell phone"}


class DeviceBox(BaseModel):
    cls: int
    label: str
    conf: float
    x1: float
    y1: float
    x2: float
    y2: float


class DeviceSignal(BaseModel):
    device_conf: float
    device_face_containment: float
    label: str | None = None
    n_device_boxes: int = 0


def _grids() -> tuple[np.ndarray, np.ndarray]:
    grids, strides = [], []
    for stride in (8, 16, 32):
        size = INPUT // stride
        xv, yv = np.meshgrid(np.arange(size), np.arange(size))
        grids.append(np.stack((xv, yv), 2).reshape(-1, 2))
        strides.append(np.full((size * size, 1), stride))
    return np.concatenate(grids).astype(np.float32), np.concatenate(strides).astype(np.float32)


_GRID, _STRIDE = _grids()


def _nms(boxes: np.ndarray, scores: np.ndarray, iou: float) -> list[int]:
    order = scores.argsort()[::-1]
    keep: list[int] = []
    areas = (boxes[:, 2] - boxes[:, 0]) * (boxes[:, 3] - boxes[:, 1])
    while order.size:
        i = int(order[0])
        keep.append(i)
        xx1 = np.maximum(boxes[i, 0], boxes[order[1:], 0])
        yy1 = np.maximum(boxes[i, 1], boxes[order[1:], 1])
        xx2 = np.minimum(boxes[i, 2], boxes[order[1:], 2])
        yy2 = np.minimum(boxes[i, 3], boxes[order[1:], 3])
        inter = np.maximum(0.0, xx2 - xx1) * np.maximum(0.0, yy2 - yy1)
        ovr = inter / (areas[i] + areas[order[1:]] - inter + 1e-9)
        order = order[1:][ovr <= iou]
    return keep


class DeviceDetector:
    def __init__(self, model_path: Path, classes: list[int], *, threads: int = 2) -> None:
        self.session = make_session(model_path, threads=threads)
        self.input_name = self.session.get_inputs()[0].name
        self.classes = [int(c) for c in classes]

    def preprocess(self, bgr: np.ndarray) -> tuple[np.ndarray, float]:
        h, w = bgr.shape[:2]
        r = min(INPUT / h, INPUT / w)
        resized = cv2.resize(bgr, (int(w * r), int(h * r)), interpolation=cv2.INTER_LINEAR)
        canvas = np.full((INPUT, INPUT, 3), 114, dtype=np.uint8)
        canvas[: resized.shape[0], : resized.shape[1]] = resized
        return np.ascontiguousarray(canvas.transpose(2, 0, 1)[None], dtype=np.float32), r

    def detect_all(self, bgr: np.ndarray, classes: list[int] | None = None) -> list[DeviceBox]:
        """COCO boxes for `classes` (default: device classes) in full-frame pixels."""
        x, r = self.preprocess(bgr)
        out = self.session.run(None, {self.input_name: x})[0][0].copy()
        out[:, :2] = (out[:, :2] + _GRID) * _STRIDE
        out[:, 2:4] = np.exp(out[:, 2:4]) * _STRIDE
        wanted = self.classes if classes is None else classes
        cls_scores = out[:, 5:][:, wanted] * out[:, 4:5]
        best = cls_scores.argmax(axis=1)
        conf = cls_scores[np.arange(len(best)), best]
        keep = conf >= CANDIDATE_MIN_CONF
        if not np.any(keep):
            return []
        cxcywh, conf, best = out[keep, :4], conf[keep], best[keep]
        boxes = np.stack(
            [
                cxcywh[:, 0] - cxcywh[:, 2] / 2,
                cxcywh[:, 1] - cxcywh[:, 3] / 2,
                cxcywh[:, 0] + cxcywh[:, 2] / 2,
                cxcywh[:, 1] + cxcywh[:, 3] / 2,
            ],
            axis=1,
        ) / r
        result = []
        for c in sorted(set(best.tolist())):
            m = np.where(best == c)[0]
            for i in _nms(boxes[m], conf[m], NMS_IOU):
                j = m[i]
                cls = wanted[c]
                result.append(
                    DeviceBox(
                        cls=cls, label=COCO_NAMES.get(cls, str(cls)), conf=round(float(conf[j]), 4),
                        x1=float(boxes[j, 0]), y1=float(boxes[j, 1]),
                        x2=float(boxes[j, 2]), y2=float(boxes[j, 3]),
                    )
                )
        return result

    def warmup(self) -> None:
        self.detect_all(np.zeros((480, 640, 3), np.uint8))


def containment(face: FaceBox, box: DeviceBox) -> float:
    """Fraction of the face box area that lies inside the device box."""
    ix = max(0.0, min(face.x2, box.x2) - max(face.x1, box.x1))
    iy = max(0.0, min(face.y2, box.y2) - max(face.y1, box.y1))
    return float(ix * iy / face.area) if face.area > 0 else 0.0


def device_signal(face: FaceBox | None, boxes: list[DeviceBox], face_containment_min: float,
                  fail_conf: float) -> DeviceSignal:
    """Pure rule: the most severe device box overlapping the face.

    Severity order: (fail-grade = containment >= face_containment_min AND conf >= fail_conf, conf). A
    fail-grade box wins; otherwise the most confident overlapping box. (Ranking containment alone first let
    a faint 0.12 tv box around the face hide a 0.90 phone covering 75 % of it: UNSURE became PASS.)
    Boxes that do not overlap the face at all are counted (n_device_boxes) but do not set device_conf
    (a phone in a hand is not a spoof).
    """
    if face is None or not boxes:
        return DeviceSignal(device_conf=0.0, device_face_containment=0.0, n_device_boxes=len(boxes))
    best: tuple[bool, float, float, str] | None = None
    for b in boxes:
        c = containment(face, b)
        if c <= 0.0:
            continue
        key = (c >= face_containment_min and b.conf >= fail_conf, b.conf, c, b.label)
        if best is None or key[:2] > best[:2]:
            best = key
    if best is None:
        return DeviceSignal(device_conf=0.0, device_face_containment=0.0, n_device_boxes=len(boxes))
    return DeviceSignal(
        device_conf=round(best[1], 4), device_face_containment=round(best[2], 4),
        label=best[3], n_device_boxes=len(boxes),
    )
