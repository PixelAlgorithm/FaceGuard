"""Perception engine: owns the ONNX models (loaded + warmed once) and the per-frame signal functions.

Nothing here decides ALLOW/STEP_UP/DENY. Each component degrades independently; a missing or
failed component yields None signals (the policy treats None as missing => never ALLOW).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import cv2
import numpy as np

from edge.config import Settings, Thresholds
from edge.ml.detect import FaceBox, FaceDetector, align112
from edge.ml.device import DeviceDetector, DeviceSignal, device_signal
from edge.ml.flash import skin_roi_rgb
from edge.ml.mask import MaskRingSignal, mask_ring_signal
from edge.ml.matcher import ArcFaceEmbedder
from edge.ml.moire import MoireSignal, moire_signal
from edge.ml.pad import PadFrameScore, PadModel, PadSelfTestResult, run_self_test
from edge.ml.quality import frame_quality
from edge.ml.registry import FIXTURE_FILES, MODEL_FILES, sha256_file, verified_path
from edge.policy.signals import FrameQuality

log = logging.getLogger("edge.perception")


@dataclass
class FrameAnalysis:
    """Detection + quality for one uploaded frame (kept in RAM for the attempt only)."""

    index: int
    ts_ms: int
    bgr: np.ndarray
    faces: list[FaceBox]
    quality: FrameQuality
    aligned: np.ndarray | None = None
    skin_rgb: tuple[float, float, float] | None = None

    @property
    def main(self) -> FaceBox | None:
        return self.faces[0] if self.faces else None


@dataclass
class EngineHealth:
    models_loaded: dict[str, bool] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    pad_self_test: PadSelfTestResult | None = None
    load_ms: dict[str, float] = field(default_factory=dict)
    arcface_provider: str | None = None


MAX_JPEG_SIDE_PX = 4096  # decode guard: a 2 MB JPEG can declare 65535 x 65535 px (~12 GB decoded)
# Start-of-frame markers (baseline, extended, progressive, lossless, arithmetic); C4/C8/CC are not SOFs.
_SOF_MARKERS = frozenset({0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF})


def jpeg_size(data: bytes) -> tuple[int, int] | None:
    """(width, height) from the first SOF segment, read from the header without decoding.

    Strict walk SOI -> marker segments -> SOF: anything else before the SOF (no SOI, stray bytes, SOS or
    EOI first, truncation) gives None, so a header this parser accepts is the one libjpeg will use.
    """
    n = len(data)
    if n < 4 or data[0] != 0xFF or data[1] != 0xD8:
        return None
    i = 2
    while i < n:
        if data[i] != 0xFF:
            return None
        while i < n and data[i] == 0xFF:  # fill bytes before a marker
            i += 1
        if i >= n:
            return None
        marker = data[i]
        i += 1
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:  # TEM / RSTn: no length field
            continue
        if marker in (0x00, 0xD8, 0xD9, 0xDA) or i + 2 > n:  # stuffed byte, SOI, EOI, SOS before SOF
            return None
        seg_len = (data[i] << 8) | data[i + 1]
        if seg_len < 2:
            return None
        if marker in _SOF_MARKERS:
            if seg_len < 8 or i + 7 > n:
                return None
            return (data[i + 5] << 8) | data[i + 6], (data[i + 3] << 8) | data[i + 4]
        i += seg_len
    return None


def decode_jpeg(data: bytes) -> np.ndarray | None:
    """BGR image, or None if `data` is not a JPEG, declares a side > MAX_JPEG_SIDE_PX (checked before
    decoding, so a decompression-bomb header never reaches cv2.imdecode) or does not decode."""
    size = jpeg_size(data)
    if size is None or not (0 < size[0] <= MAX_JPEG_SIDE_PX and 0 < size[1] <= MAX_JPEG_SIDE_PX):
        return None
    arr = np.frombuffer(data, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    return img if img is not None and img.ndim == 3 else None


def load_fixture_images(settings: Settings) -> tuple[dict[str, np.ndarray], dict[str, np.ndarray]]:
    """Bona-fide + attack fixtures for the PAD self-test.

    Bona fide: scikit-image `astronaut` (NASA portrait of Eileen Collins, public domain) and
    minivision `image_T1.jpg`; attacks: minivision `image_F1/F2.jpg` (Apache-2.0, pinned commit).
    Kiosk-camera captures placed in eval/fixtures/{live,print,phone,screen}_*.jpg are added.
    """
    from skimage import data as skdata

    live: dict[str, np.ndarray] = {
        "skimage_astronaut(public-domain)": cv2.cvtColor(skdata.astronaut(), cv2.COLOR_RGB2BGR)
    }
    attack: dict[str, np.ndarray] = {}
    fx = settings.models_dir / "fixtures"
    for name, sha in FIXTURE_FILES.items():
        path = fx / name
        if not path.is_file() or sha256_file(path) != sha:
            raise FileNotFoundError(f"fixture {path} missing or modified - run scripts/fetch_models.sh")
        img = cv2.imread(str(path), cv2.IMREAD_COLOR)
        (live if "_T" in name else attack)[name] = img
    eval_fx = settings.project_root / "eval" / "fixtures"
    if eval_fx.is_dir():
        for path in sorted(eval_fx.glob("*.jpg")):
            img = cv2.imread(str(path), cv2.IMREAD_COLOR)
            if img is None:
                continue
            if path.name.startswith("live_"):
                live[f"eval/{path.name}"] = img
            elif path.name.split("_", 1)[0] in {"print", "phone", "screen", "replay", "mask"}:
                attack[f"eval/{path.name}"] = img
    return live, attack


class PerceptionEngine:
    def __init__(self, settings: Settings, thresholds: Thresholds) -> None:
        self.settings = settings
        self.thresholds = thresholds
        self.detector: FaceDetector | None = None
        self.pad: PadModel | None = None
        self.device: DeviceDetector | None = None
        self.embedder: ArcFaceEmbedder | None = None
        self.health = EngineHealth()

    # ------------------------------------------------------------------ lifecycle
    def _try(self, key: str, fn) -> Any:
        t = time.perf_counter()
        try:
            obj = fn()
            self.health.models_loaded[key] = True
            return obj
        except Exception as exc:  # noqa: BLE001 - every component degrades independently
            log.error("model %s failed to load: %s", key, exc)
            self.health.models_loaded[key] = False
            self.health.errors[key] = f"{type(exc).__name__}: {exc}"
            return None
        finally:
            self.health.load_ms[key] = round((time.perf_counter() - t) * 1000, 1)

    def load(self) -> None:
        md = self.settings.models_dir
        th = self.thresholds
        self.detector = self._try("face_detector", lambda: FaceDetector(verified_path(md, "face_detector")))

        def _pad() -> PadModel:
            return PadModel(
                v2_path=verified_path(md, "minifasnet_v2"),
                v1se_path=verified_path(md, "minifasnet_v1se"),
                real_index=int(th.get("liveness.pad.real_class_index")),
                input_scale=float(th.get("liveness.pad.input_scale", 1.0)),
            )

        self.pad = self._try("minifasnet", _pad)
        self.health.models_loaded["minifasnet_v2"] = self.health.models_loaded.pop("minifasnet", False)
        self.health.models_loaded["minifasnet_v1se"] = self.health.models_loaded["minifasnet_v2"]
        self.device = self._try(
            "coco_detector",
            lambda: DeviceDetector(
                verified_path(md, "coco_detector"), list(th.get("liveness.device_detector.classes"))
            ),
        )
        self.embedder = self._try(
            "arcface",
            lambda: ArcFaceEmbedder(
                verified_path(md, "arcface"), MODEL_FILES["arcface"].sha256, provider=self.settings.ort_provider
            ),
        )
        if self.embedder:
            self.health.arcface_provider = self.embedder.provider
        self.warmup()
        self.self_test()

    def warmup(self) -> None:
        dummy = np.zeros((480, 640, 3), np.uint8)
        for comp, fn in (
            ("face_detector", lambda: self.detector and self.detector.detect(dummy)),
            ("minifasnet_v2", lambda: self.pad and self.pad.warmup()),
            ("coco_detector", lambda: self.device and self.device.warmup()),
            ("arcface", lambda: self.embedder and self.embedder.warmup()),
        ):
            try:
                for _ in range(2):
                    fn()
            except Exception as exc:  # noqa: BLE001 - a failed warm-up marks the model unavailable
                self.health.models_loaded[comp] = False
                self.health.errors[comp] = f"warmup failed: {exc}"

    def self_test(self) -> PadSelfTestResult | None:
        """MANDATORY MiniFASNet self-test; PAD stays disabled (signals None) unless it passes."""
        if self.pad is None or self.detector is None:
            self.health.pad_self_test = PadSelfTestResult(
                ok=False, real_class_index=-1, input_scale=0.0, message="PAD or detector not loaded"
            )
            return self.health.pad_self_test
        try:
            live, attack = load_fixture_images(self.settings)
            res = run_self_test(self.pad, self.detector, live, attack)
        except Exception as exc:  # noqa: BLE001 - self-test errors disable PAD (fail-secure)
            res = PadSelfTestResult(
                ok=False, real_class_index=self.pad.real_index, input_scale=self.pad.input_scale,
                message=f"self-test error: {exc}",
            )
        self.pad.enabled = res.ok
        self.health.pad_self_test = res
        if res.ok:
            log.info("PAD self-test PASSED live_min=%.3f attack_max=%.3f", res.live_min, res.attack_max)
        else:
            log.error("PAD self-test FAILED (%s) - PAD signals disabled", res.message)
        return res

    @property
    def ready(self) -> bool:
        return all(
            self.health.models_loaded.get(k, False)
            for k in ("face_detector", "minifasnet_v2", "coco_detector", "arcface")
        ) and bool(self.health.pad_self_test and self.health.pad_self_test.ok)

    # ------------------------------------------------------------------ per-frame signal functions
    def analyze_frame(self, index: int, ts_ms: int, bgr: np.ndarray) -> FrameAnalysis:
        faces = self.detector.detect(bgr) if self.detector else []
        aligned = align112(bgr, faces[0].kps) if faces else None
        quality = frame_quality(bgr, faces, aligned)
        skin = skin_roi_rgb(bgr, faces[0].kps) if faces else None
        return FrameAnalysis(index=index, ts_ms=ts_ms, bgr=bgr, faces=faces, quality=quality,
                             aligned=aligned, skin_rgb=skin)

    def pad_scores(self, frames: list[FrameAnalysis]) -> list[PadFrameScore]:
        if self.pad is None:
            return [PadFrameScore(pad_v2=None, pad_v1se=None) for _ in frames]
        return self.pad.score_frames([f.bgr for f in frames], [f.main for f in frames])

    def device_score(self, frame: FrameAnalysis) -> DeviceSignal | None:
        if self.device is None:
            return None
        boxes = self.device.detect_all(frame.bgr)
        return device_signal(frame.main, boxes,
                             float(self.thresholds.get("liveness.device_detector.face_containment")),
                             float(self.thresholds.get("liveness.device_detector.fail_conf")))

    @staticmethod
    def texture_scores(frame: FrameAnalysis) -> tuple[MoireSignal, MaskRingSignal]:
        return moire_signal(frame.bgr, frame.main), mask_ring_signal(frame.bgr, frame.main)

    def embed(self, frame: FrameAnalysis) -> np.ndarray | None:
        if self.embedder is None or frame.aligned is None:
            return None
        return self.embedder.embed(frame.aligned)

    def health_dict(self) -> dict[str, Any]:
        st = self.health.pad_self_test
        return {
            "models_loaded": dict(self.health.models_loaded),
            "errors": dict(self.health.errors),
            "load_ms": dict(self.health.load_ms),
            "arcface_provider": self.health.arcface_provider,
            "pad_self_test": st.model_dump(exclude={"detail", "alternatives"}) if st else None,
        }


def model_files_dir(settings: Settings) -> Path:
    return settings.models_dir
