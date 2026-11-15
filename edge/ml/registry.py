"""Pinned model files (same pins as scripts/fetch_models.sh; provenance in edge/ml/MODELS.md).

`verified_path` checks a file at startup; `verified_bytes` reads a pinned file ONCE and checks the
SHA-256 of exactly those bytes, which `edge.ml.onnx.make_session` then hands to ONNX Runtime, so the
model that runs is the model that was hashed (no swap between check and load, audit EM-13).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ModelFile:
    key: str
    filename: str
    sha256: str
    url: str
    licence: str


MODEL_FILES: dict[str, ModelFile] = {
    m.key: m
    for m in (
        ModelFile(
            "minifasnet_v2",
            "MiniFASNetV2.onnx",
            "b32929adc2d9c34b9486f8c4c7bc97c1b69bc0ea9befefc380e4faae4e463907",
            "https://github.com/yakhyo/face-anti-spoofing/releases/download/weights/MiniFASNetV2.onnx",
            "Apache-2.0",
        ),
        ModelFile(
            "minifasnet_v1se",
            "MiniFASNetV1SE.onnx",
            "ebab7f90c7833fbccd46d3a555410e78d969db5438e169b6524be444862b3676",
            "https://github.com/yakhyo/face-anti-spoofing/releases/download/weights/MiniFASNetV1SE.onnx",
            "Apache-2.0",
        ),
        ModelFile(
            "face_detector",
            "retinaface_mv2.onnx",
            "3ca44c045651cabeed1193a1fae8946ad1f3a55da8fa74b341feab5a8319f757",
            "https://github.com/yakhyo/uniface/releases/download/weights/retinaface_mv2.onnx",
            "MIT code (yakhyo/retinaface-pytorch); trained on WIDER FACE (research dataset)",
        ),
        ModelFile(
            "arcface",
            "w600k_r50.onnx",
            "4c06341c33c2ca1f86781dab0e829f88ad5b64be9fba56e56bc9ebdefc619e43",
            "https://github.com/yakhyo/uniface/releases/download/weights/w600k_r50.onnx",
            "InsightFace buffalo_l recognition weights: NON-COMMERCIAL research only",
        ),
        ModelFile(
            "coco_detector",
            "yolox_tiny.onnx",
            "427cc366d34e27ff7a03e2899b5e3671425c262ea2291f88bb942bc1cc70b0f7",
            "https://github.com/Megvii-BaseDetection/YOLOX/releases/download/0.1.1rc0/yolox_tiny.onnx",
            "Apache-2.0 (Megvii YOLOX); COCO-trained",
        ),
    )
}

FIXTURE_FILES = {
    "minivision_image_T1.jpg": "f4455149f488f76205fdee5499ec5261d08ef6279a1cff7b778ea85405331e94",
    "minivision_image_F1.jpg": "4b11b5d7a8a8e4a88f5f16a5426a0a7692e39e5bb45bb03b4ebe5e1606336860",
    "minivision_image_F2.jpg": "fbbea73450ae9d9bb555c8ccac77bf39d234261fe3be4190e3ed2999690c485f",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pin_for(path: Path) -> ModelFile | None:
    """The pin whose filename matches `path` (pinned files are identified by name), else None."""
    return next((m for m in MODEL_FILES.values() if m.filename == path.name), None)


def verified_bytes(path: Path) -> bytes:
    """Read `path` once; if it is a pinned model, raise ValueError unless sha256(bytes) == pin."""
    data = path.read_bytes()
    spec = pin_for(path)
    if spec is not None:
        digest = hashlib.sha256(data).hexdigest()
        if digest != spec.sha256:
            raise ValueError(f"{path} sha256 {digest} != pinned {spec.sha256}")
    return data


def verified_path(models_dir: Path, key: str) -> Path:
    """Return the model path if present and its SHA-256 matches the pin, else raise."""
    spec = MODEL_FILES[key]
    path = models_dir / spec.filename
    if not path.is_file():
        raise FileNotFoundError(f"{path} missing - run scripts/fetch_models.sh")
    digest = sha256_file(path)
    if digest != spec.sha256:
        raise ValueError(f"{path} sha256 {digest} != pinned {spec.sha256}")
    return path
