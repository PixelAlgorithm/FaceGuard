"""Local face matcher: ArcFace (InsightFace w600k_r50 = buffalo_l recogniser) + 1:N cosine search.

Embedding: 5-point aligned 112x112 crop -> RGB -> (x - 127.5) / 127.5 -> NCHW -> 512-d, L2-normalised.
Search is a pure function over an immutable gallery snapshot: per-user score = max over that user's
templates; top2 = best *different* user. Gallery = this kiosk's entitled users only (caller filters).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from pydantic import BaseModel

from edge.ml.onnx import active_provider, make_session

log = logging.getLogger("edge.ml.matcher")
EMB_DIM = 512
COREML_PARITY_MIN_COS = 0.9999  # CoreML embeddings must equal CPU ones, else fall back to CPU


class MatchScore(BaseModel):
    top1_user: str | None
    top1: float | None
    top2: float | None
    n_users: int = 0


@dataclass(frozen=True)
class Gallery:
    user_ids: tuple[str, ...] = ()
    matrix: np.ndarray = field(default_factory=lambda: np.zeros((0, EMB_DIM), np.float32))

    @property
    def users(self) -> set[str]:
        return set(self.user_ids)


def search(q: np.ndarray | None, gallery: Gallery, allowed: set[str] | None = None) -> MatchScore:
    """1:N search. `allowed` restricts the gallery (None = no restriction)."""
    if q is None or gallery.matrix.shape[0] == 0:
        return MatchScore(top1_user=None, top1=None, top2=None, n_users=0)
    qn = q / (np.linalg.norm(q) + 1e-9)
    sims = gallery.matrix @ qn.astype(np.float32)
    best: dict[str, float] = {}
    for uid, s in zip(gallery.user_ids, sims):
        if allowed is not None and uid not in allowed:
            continue
        if s > best.get(uid, -2.0):
            best[uid] = float(s)
    if not best:
        return MatchScore(top1_user=None, top1=None, top2=None, n_users=0)
    ranked = sorted(best.items(), key=lambda kv: kv[1], reverse=True)
    top2 = round(ranked[1][1], 4) if len(ranked) > 1 else None
    return MatchScore(top1_user=ranked[0][0], top1=round(ranked[0][1], 4), top2=top2, n_users=len(ranked))


def best_cosine(q: np.ndarray | None, gallery: Gallery, user_id: str) -> float | None:
    """Max cosine of `q` against one user's templates (identity continuity checks)."""
    if q is None:
        return None
    rows = [i for i, u in enumerate(gallery.user_ids) if u == user_id]
    if not rows:
        return None
    qn = q / (np.linalg.norm(q) + 1e-9)
    return round(float(np.max(gallery.matrix[rows] @ qn.astype(np.float32))), 4)


class ArcFaceEmbedder:
    def __init__(self, model_path: Path, sha256: str, *, provider: str = "auto", threads: int = 2) -> None:
        self.model_id = f"arcface_w600k_r50@{sha256[:12]}"
        self.cpu = make_session(model_path, threads=threads)
        self.session = self.cpu
        self.input_name = self.cpu.get_inputs()[0].name
        if provider in {"auto", "coreml"}:
            try:
                cm = make_session(model_path, threads=threads, coreml=True)
                if active_provider(cm) == "CoreMLExecutionProvider" and self._parity(cm):
                    self.session = cm
            except Exception:  # CoreML is an optional accelerator
                log.warning("CoreML session unavailable for ArcFace; using CPU", exc_info=True)
        self.provider = active_provider(self.session)

    def _parity(self, other) -> bool:
        x = np.random.default_rng(7).uniform(-1, 1, (1, 3, 112, 112)).astype(np.float32)
        a = self.cpu.run(None, {self.input_name: x})[0][0]
        b = other.run(None, {self.input_name: x})[0][0]
        cos = float(a @ b / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-9))
        log.info("ArcFace CoreML/CPU parity cosine=%.6f", cos)
        return cos >= COREML_PARITY_MIN_COS

    @staticmethod
    def preprocess(aligned_bgr: np.ndarray) -> np.ndarray:
        rgb = aligned_bgr[:, :, ::-1].astype(np.float32)
        return np.ascontiguousarray(((rgb - 127.5) / 127.5).transpose(2, 0, 1)[None])

    def embed(self, aligned_bgr: np.ndarray) -> np.ndarray:
        out = self.session.run(None, {self.input_name: self.preprocess(aligned_bgr)})[0][0]
        return (out / (np.linalg.norm(out) + 1e-9)).astype(np.float32)

    def warmup(self) -> None:
        self.embed(np.zeros((112, 112, 3), np.uint8))
