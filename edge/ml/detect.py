"""Face detection (RetinaFace MobileNetV2, yakhyo/uniface ONNX) + 5-point alignment helpers.

The detector runs on a frame downscaled so its longer side is DETECT_MAX_SIDE px (kiosk faces are
>= 112 px wide at 640 px, i.e. >= 56 px at 320 px). Boxes/keypoints are returned in full-frame
pixels. Upstream minivision also derives the MiniFASNet box from a RetinaFace run on a ~192 px
downscaled image, so box precision is comparable.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import cv2
import numpy as np
from uniface.common import decode_boxes, decode_landmarks, generate_anchors, non_max_suppression
from uniface.face_utils import face_alignment

from edge.ml.onnx import make_session

DETECT_MAX_SIDE = 320  # model hyper-parameter (speed), not a decision threshold
DET_CONFIDENCE = 0.5  # uniface default face-confidence cut-off for candidate boxes
NMS_IOU = 0.4  # uniface default
_MEAN_BGR = np.array([104.0, 117.0, 123.0], dtype=np.float32)


@dataclass(frozen=True)
class FaceBox:
    """One detected face in full-frame pixel coordinates."""

    x1: float
    y1: float
    x2: float
    y2: float
    score: float
    kps: np.ndarray  # (5, 2): image-left eye, image-right eye, nose tip, left mouth, right mouth

    @property
    def width(self) -> float:
        return max(0.0, self.x2 - self.x1)

    @property
    def height(self) -> float:
        return max(0.0, self.y2 - self.y1)

    @property
    def area(self) -> float:
        return self.width * self.height

    def upstream_xywh(self) -> tuple[int, int, int, int]:
        """Box in minivision `get_bbox` convention: [left, top, right-left+1, bottom-top+1] ints."""
        return (int(self.x1), int(self.y1), int(self.x2 - self.x1 + 1), int(self.y2 - self.y1 + 1))

    def clipped(self, width: int, height: int) -> tuple[int, int, int, int]:
        x1 = int(np.clip(np.floor(self.x1), 0, width - 1))
        y1 = int(np.clip(np.floor(self.y1), 0, height - 1))
        x2 = int(np.clip(np.ceil(self.x2), x1 + 1, width))
        y2 = int(np.clip(np.ceil(self.y2), y1 + 1, height))
        return x1, y1, x2, y2


class FaceDetector:
    def __init__(self, model_path: Path, *, threads: int = 2) -> None:
        self.session = make_session(model_path, threads=threads)
        self.input_name = self.session.get_inputs()[0].name
        self._anchors: dict[tuple[int, int], np.ndarray] = {}

    def _priors(self, h: int, w: int) -> np.ndarray:
        key = (h, w)
        if key not in self._anchors:
            self._anchors[key] = generate_anchors(image_size=(h, w))  # uniface: (height, width)
        return self._anchors[key]

    def detect(self, bgr: np.ndarray) -> list[FaceBox]:
        """Return faces sorted by box area (largest = main face first)."""
        h0, w0 = bgr.shape[:2]
        scale = min(1.0, DETECT_MAX_SIDE / float(max(h0, w0)))
        img = bgr
        if scale < 1.0:
            img = cv2.resize(bgr, (round(w0 * scale), round(h0 * scale)), interpolation=cv2.INTER_AREA)
        h, w = img.shape[:2]
        x = (img.astype(np.float32) - _MEAN_BGR).transpose(2, 0, 1)[None]
        loc, conf, lms = self.session.run(None, {self.input_name: x})
        priors = self._priors(h, w)
        boxes = decode_boxes(loc[0], priors) * np.array([w, h, w, h], dtype=np.float32)
        kps = decode_landmarks(lms[0], priors) * np.array([w, h] * 5, dtype=np.float32)
        scores = conf[0][:, 1]
        keep = scores > DET_CONFIDENCE
        boxes, kps, scores = boxes[keep], kps[keep], scores[keep]
        if len(scores) == 0:
            return []
        order = scores.argsort()[::-1]
        boxes, kps, scores = boxes[order], kps[order], scores[order]
        dets = np.hstack([boxes, scores[:, None]]).astype(np.float32)
        idx = non_max_suppression(dets, NMS_IOU)
        inv = 1.0 / scale
        faces = [
            FaceBox(
                x1=float(dets[i, 0] * inv),
                y1=float(dets[i, 1] * inv),
                x2=float(dets[i, 2] * inv),
                y2=float(dets[i, 3] * inv),
                score=float(dets[i, 4]),
                kps=(kps[i].reshape(5, 2) * inv).astype(np.float32),
            )
            for i in idx
        ]
        faces.sort(key=lambda f: f.area, reverse=True)
        return faces


def align112(bgr: np.ndarray, kps: np.ndarray) -> np.ndarray:
    """ArcFace 5-point similarity alignment to 112x112 (BGR). Used for matching + blur metric only."""
    warped, _ = face_alignment(bgr, np.asarray(kps, dtype=np.float32), image_size=112)
    return warped
