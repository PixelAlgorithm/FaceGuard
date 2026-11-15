"""Passive PAD: MiniFASNetV2 (2.7x crop) + MiniFASNetV1SE (4.0x crop), 80x80 BGR, raw 0-255.

Preprocessing reproduces minivision `CropImage` exactly (enlarge around the box centre, clamp the
scale to the image, then SHIFT - not shrink - the window back inside the image). Output index of
"real" and the input scale are verified at startup by `run_self_test` (evidence in edge/README.md):
on the yakhyo ONNX exports, index 1 = real with raw 0-255 input; with /255 the network output
collapses to a constant for every image.

Signal = per-frame P_live of each model (softmax[real_index]); fusion/voting is the policy's job.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import cv2
import numpy as np
from pydantic import BaseModel

from edge.ml.detect import FaceBox, FaceDetector
from edge.ml.onnx import make_session

CROP_SCALES = {"minifasnet_v2": 2.7, "minifasnet_v1se": 4.0}
INPUT_SIZE = 80


def upstream_crop(bgr: np.ndarray, box_xywh: tuple[int, int, int, int], scale: float) -> np.ndarray:
    """minivision CropImage.crop (src/generate_patches.py) for one scale, output 80x80 BGR uint8."""
    src_h, src_w = bgr.shape[:2]
    x, y, box_w, box_h = box_xywh
    box_w, box_h = max(box_w, 1), max(box_h, 1)
    scale = min((src_h - 1) / box_h, min((src_w - 1) / box_w, scale))
    new_w, new_h = box_w * scale, box_h * scale
    cx, cy = box_w / 2 + x, box_h / 2 + y
    left, top = cx - new_w / 2, cy - new_h / 2
    right, bottom = cx + new_w / 2, cy + new_h / 2
    if left < 0:
        right -= left
        left = 0
    if top < 0:
        bottom -= top
        top = 0
    if right > src_w - 1:
        left -= right - src_w + 1
        right = src_w - 1
    if bottom > src_h - 1:
        top -= bottom - src_h + 1
        bottom = src_h - 1
    l, t, r, b = int(left), int(top), int(right), int(bottom)
    patch = bgr[t : b + 1, l : r + 1]
    return cv2.resize(patch, (INPUT_SIZE, INPUT_SIZE))


def _softmax(z: np.ndarray) -> np.ndarray:
    e = np.exp(z - z.max(axis=1, keepdims=True))
    return e / e.sum(axis=1, keepdims=True)


class PadFrameScore(BaseModel):
    """Per-frame passive PAD signal (P_live per model). None = model unavailable/self-test failed."""

    pad_v2: float | None
    pad_v1se: float | None


class PadSelfTestResult(BaseModel):
    ok: bool
    real_class_index: int
    input_scale: float
    live_min: float | None = None
    attack_max: float | None = None
    live_mean: float | None = None
    attack_mean: float | None = None
    detail: list[dict] = []
    alternatives: list[dict] = []
    message: str = ""


@dataclass
class PadModel:
    """Two MiniFASNet sessions; `enabled` is False until the startup self-test passes."""

    v2_path: Path
    v1se_path: Path
    real_index: int
    input_scale: float = 1.0
    threads: int = 2
    enabled: bool = False

    def __post_init__(self) -> None:
        self.sessions = {
            "minifasnet_v2": make_session(self.v2_path, threads=self.threads),
            "minifasnet_v1se": make_session(self.v1se_path, threads=self.threads),
        }

    def probabilities(
        self, crops_by_model: dict[str, np.ndarray], input_scale: float | None = None
    ) -> dict[str, np.ndarray]:
        """Full softmax vectors (N, 3) per model for pre-cropped batches (N, 80, 80, 3) uint8."""
        k = self.input_scale if input_scale is None else input_scale
        out: dict[str, np.ndarray] = {}
        for key, sess in self.sessions.items():
            batch = crops_by_model[key].astype(np.float32) * np.float32(k)
            x = np.ascontiguousarray(batch.transpose(0, 3, 1, 2))
            logits = sess.run(None, {sess.get_inputs()[0].name: x})[0]
            out[key] = _softmax(logits.astype(np.float64))
        return out

    @staticmethod
    def crops(frames: list[np.ndarray], faces: list[FaceBox]) -> dict[str, np.ndarray]:
        return {
            key: np.stack([upstream_crop(f, b.upstream_xywh(), s) for f, b in zip(frames, faces)])
            for key, s in CROP_SCALES.items()
        }

    def score_frames(self, frames: list[np.ndarray], faces: list[FaceBox | None]) -> list[PadFrameScore]:
        """P_live per model for each frame (None where no face or PAD disabled)."""
        result = [PadFrameScore(pad_v2=None, pad_v1se=None) for _ in frames]
        idx = [i for i, b in enumerate(faces) if b is not None]
        if not self.enabled or not idx:
            return result
        probs = self.probabilities(self.crops([frames[i] for i in idx], [faces[i] for i in idx]))
        for j, i in enumerate(idx):
            result[i] = PadFrameScore(
                pad_v2=round(float(probs["minifasnet_v2"][j, self.real_index]), 4),
                pad_v1se=round(float(probs["minifasnet_v1se"][j, self.real_index]), 4),
            )
        return result

    def warmup(self) -> None:
        dummy = np.zeros((1, INPUT_SIZE, INPUT_SIZE, 3), np.uint8)
        self.probabilities({k: dummy for k in CROP_SCALES})


def run_self_test(
    pad: PadModel,
    detector: FaceDetector,
    live: dict[str, np.ndarray],
    attack: dict[str, np.ndarray],
) -> PadSelfTestResult:
    """Verify `real_index` + `input_scale` on bona-fide vs attack fixtures (fails loudly).

    Pass condition (no tunable numbers): every bona-fide fixture's fused P_live is strictly higher
    than every attack fixture's, for the configured index and scale. Alternatives (other indices,
    /255 input) are computed as evidence only.
    """
    names = list(live) + list(attack)
    images = {**live, **attack}
    faces: dict[str, FaceBox] = {}
    for name in names:
        dets = detector.detect(images[name])
        if not dets:
            return PadSelfTestResult(
                ok=False, real_class_index=pad.real_index, input_scale=pad.input_scale,
                message=f"no face detected in fixture {name}",
            )
        faces[name] = dets[0]
    crops = pad.crops([images[n] for n in names], [faces[n] for n in names])
    scales = sorted({1.0, 1.0 / 255.0, float(pad.input_scale)}, reverse=True)
    probs_by_scale = {s: pad.probabilities(crops, input_scale=s) for s in scales}
    results: dict[tuple[int, float], dict] = {}
    for scale, probs in probs_by_scale.items():
        fused = (probs["minifasnet_v2"] + probs["minifasnet_v1se"]) / 2.0
        for idx in range(fused.shape[1]):
            vals = {n: float(fused[i, idx]) for i, n in enumerate(names)}
            lv = [vals[n] for n in live]
            av = [vals[n] for n in attack]
            results[(idx, scale)] = {
                "real_index": idx,
                "input_scale": "raw 0-255" if scale == 1.0 else f"x{scale:.6f}",
                "live_min": round(min(lv), 4),
                "attack_max": round(max(av), 4),
                "separates": min(lv) > max(av),
                "per_fixture": {n: round(v, 4) for n, v in vals.items()},
            }
    chosen_probs = probs_by_scale[float(pad.input_scale)]
    chosen = results[(pad.real_index, float(pad.input_scale))]
    detail = []
    for i, n in enumerate(names):
        detail.append(
            {
                "fixture": n,
                "kind": "bona_fide" if n in live else "attack",
                "v2": [round(float(p), 4) for p in chosen_probs["minifasnet_v2"][i]],
                "v1se": [round(float(p), 4) for p in chosen_probs["minifasnet_v1se"][i]],
                "p_live": chosen["per_fixture"][n],
            }
        )
    lv = [chosen["per_fixture"][n] for n in live]
    av = [chosen["per_fixture"][n] for n in attack]
    ok = bool(chosen["separates"])
    return PadSelfTestResult(
        ok=ok,
        real_class_index=pad.real_index,
        input_scale=pad.input_scale,
        live_min=round(min(lv), 4),
        attack_max=round(max(av), 4),
        live_mean=round(float(np.mean(lv)), 4),
        attack_mean=round(float(np.mean(av)), 4),
        detail=detail,
        alternatives=list(results.values()),
        message="ok" if ok else "configured real_class_index/input_scale do NOT separate live vs attack",
    )
