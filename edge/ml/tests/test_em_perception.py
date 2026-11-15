"""edge-ml hardening: perception helpers (audit EM-08, EM-09, EM-10, EM-13).

Model-free unless marked `models` (those need the pinned ONNX weights in models/).
"""

from __future__ import annotations

import hashlib

import cv2
import numpy as np
import pytest
from uniface.common import generate_anchors

import edge.ml.mask as mask_mod
import edge.ml.onnx as onnx_mod
from edge.ml.detect import ANCHOR_CACHE_MAX, FaceBox, FaceDetector, PriorCache
from edge.ml.device import INPUT as DEVICE_INPUT
from edge.ml.device import DeviceDetector
from edge.ml.mask import MIN_IOD_PX, mask_ring_signal
from edge.ml.registry import MODEL_FILES, verified_bytes, verified_path
from edge.tests.conftest import MODELS_DIR, requires_models


# ---------------------------------------------------------------- EM-08: mask ring on the face ROI only
def _reference_mask_ring(bgr: np.ndarray, face: FaceBox) -> tuple[float | None, list[float]]:
    """The pre-fix full-frame implementation (verbatim maths), used as the equivalence oracle."""
    kps = np.asarray(face.kps, dtype=np.float32)
    iod = float(np.hypot(*(kps[1] - kps[0])))
    if iod < MIN_IOD_PX:
        return None, []
    h, w = bgr.shape[:2]
    x1, y1, x2, y2 = face.clipped(w, h)
    gray = cv2.GaussianBlur(cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY).astype(np.float32), (0, 0), 1.0)
    gx = cv2.Sobel(gray, cv2.CV_32F, 1, 0, ksize=3)
    gy = cv2.Sobel(gray, cv2.CV_32F, 0, 1, ksize=3)
    mag = np.hypot(gx[y1:y2, x1:x2], gy[y1:y2, x1:x2])
    norm = float(np.median(mag)) + 1.0
    cov = [mask_mod._eye_coverage(gx, gy, kps[i], iod, norm) for i in (0, 1)]
    score = float(np.mean([np.clip((c - mask_mod.C0) / (mask_mod.C1 - mask_mod.C0), 0.0, 1.0) for c in cov]))
    return round(score, 4), [round(c, 3) for c in cov]


def _scene(rng: np.random.Generator, h: int, w: int, holes: bool) -> np.ndarray:
    img = cv2.GaussianBlur(rng.integers(0, 255, (h, w, 3), dtype=np.uint8), (0, 0), 3)
    if holes:
        for _ in range(4):
            c = (int(rng.integers(0, w)), int(rng.integers(0, h)))
            cv2.circle(img, c, int(rng.integers(8, 30)), (0, 0, 0), -1)
    return img


def _face(x1: float, y1: float, size: float, eyes: tuple[tuple[float, float], tuple[float, float]]) -> FaceBox:
    kps = np.array([eyes[0], eyes[1], (x1 + size / 2, y1 + size * 0.6), (x1 + size * 0.35, y1 + size * 0.8),
                    (x1 + size * 0.65, y1 + size * 0.8)], np.float32)
    return FaceBox(x1=x1, y1=y1, x2=x1 + size, y2=y1 + size, score=0.99, kps=kps)


CASES = [
    # (h, w, face x1, y1, size, left eye, right eye)
    (480, 640, 220, 140, 200, (285, 215), (355, 215)),  # centred
    (480, 640, -40, -30, 220, (20, 40), (95, 42)),  # face clipped at the top-left corner
    (480, 640, 500, 330, 200, (560, 400), (625, 402)),  # bottom-right, eye ring leaves the frame
    (300, 300, 0, 0, 300, (-5, 80), (120, 80)),  # an eye keypoint outside the frame
    (720, 1280, 400, 100, 420, (530, 260), (690, 250)),  # large face, rotated eyes
    (200, 900, 380, 10, 180, (430, 70), (500, 75)),  # extreme aspect frame
]


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("holes", [False, True])
def test_em08_roi_mask_ring_matches_full_frame_reference(case, holes):
    h, w, x1, y1, size, le, re = case
    rng = np.random.default_rng(h * 7 + w + int(holes))
    img = _scene(rng, h, w, holes)
    face = _face(x1, y1, size, (le, re))
    out = mask_ring_signal(img, face)
    ref_score, ref_cov = _reference_mask_ring(img, face)
    assert out.mask_edge_ring == pytest.approx(ref_score, abs=1e-4)
    assert out.coverage == pytest.approx(ref_cov, abs=1e-3)


def test_em08_blur_and_sobel_run_on_the_roi_not_the_frame(monkeypatch):
    shapes: list[tuple[int, ...]] = []
    real_blur = cv2.GaussianBlur

    def spy(src, *a, **k):
        shapes.append(src.shape)
        return real_blur(src, *a, **k)

    monkeypatch.setattr(mask_mod.cv2, "GaussianBlur", spy)
    img = np.full((4096, 4096, 3), 128, np.uint8)
    face = _face(1000, 1000, 200, ((1060, 1070), (1140, 1070)))
    mask_ring_signal(img, face)
    assert shapes and all(s[0] * s[1] < 400 * 400 for s in shapes)  # was 4096 x 4096 (~281 MB transient)


# ---------------------------------------------------------------- EM-09: bounded prior cache
def test_em09_prior_cache_is_bounded_and_returns_uniface_anchors():
    cache = PriorCache()
    for h in range(1, 200):
        cache.get(h, 320)
    assert len(cache) <= ANCHOR_CACHE_MAX
    np.testing.assert_array_equal(cache.get(240, 320), generate_anchors(image_size=(240, 320)))
    first = cache.get(240, 320)
    assert cache.get(240, 320) is first  # hits are cached


def test_mlr2_prior_cache_is_thread_safe_under_eviction(monkeypatch):
    import sys
    import threading

    import edge.ml.detect as detect_mod

    monkeypatch.setattr(detect_mod, "generate_anchors", lambda image_size: np.zeros((1, 4), np.float32))
    old_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    cache = PriorCache(2)
    errors: list[str] = []

    def work(seed: int) -> None:
        rng = np.random.default_rng(seed)
        for _ in range(20_000):
            try:
                cache.get(int(rng.integers(0, 3)), 1)
            except Exception as exc:  # noqa: BLE001 - the test records any failure
                errors.append(type(exc).__name__)
                return

    try:
        threads = [threading.Thread(target=work, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(old_interval)
    assert errors == [] and len(cache) <= 2


def test_em13_uniface_anchor_layout_is_height_width():
    """Golden pin of uniface 4.3.0 behaviour detect.py relies on: image_size = (height, width), despite the
    upstream docstring. If a uniface upgrade "fixes" this, every non-square frame's boxes shift."""
    a = generate_anchors(image_size=(240, 320))
    assert a.shape == (3160, 4)
    np.testing.assert_allclose(a[0], [0.5 * 8 / 320, 0.5 * 8 / 240, 16 / 320, 16 / 240], rtol=1e-6)
    np.testing.assert_allclose(a[2], [1.5 * 8 / 320, 0.5 * 8 / 240, 16 / 320, 16 / 240], rtol=1e-6)


# ---------------------------------------------------------------- EM-10: degenerate frames
class _NoRunSession:
    def run(self, *_a, **_k):
        raise AssertionError("the detector must not run on a degenerate frame")


DEGENERATE = [(4, 4096), (4096, 4), (1, 1), (2, 5000), (15, 15)]


@pytest.mark.parametrize("shape", DEGENERATE)
def test_em10_face_detector_rejects_degenerate_frames_cleanly(shape):
    det = FaceDetector.__new__(FaceDetector)
    det.session, det.input_name, det._anchors = _NoRunSession(), "input", PriorCache()
    assert det.detect(np.zeros((*shape, 3), np.uint8)) == []


@pytest.mark.parametrize("shape", DEGENERATE)
def test_em10_device_preprocess_never_builds_a_zero_sized_resize(shape):
    dev = DeviceDetector.__new__(DeviceDetector)
    x, r = dev.preprocess(np.full((*shape, 3), 77, np.uint8))
    assert x.shape == (1, 3, DEVICE_INPUT, DEVICE_INPUT) and r > 0


# ---------------------------------------------------------------- EM-13: ORT loads exactly the hashed bytes
def test_em13_tampered_pinned_file_is_refused_before_ort(tmp_path, monkeypatch):
    bad = tmp_path / MODEL_FILES["face_detector"].filename
    bad.write_bytes(b"not the pinned model")

    def never(*_a, **_k):
        raise AssertionError("ORT must not open an unverified pinned model")

    monkeypatch.setattr(onnx_mod.ort, "InferenceSession", never)
    with pytest.raises(ValueError, match="sha256"):
        onnx_mod.make_session(bad)
    with pytest.raises(ValueError, match="sha256"):
        verified_bytes(bad)


def test_em13_session_is_built_from_the_verified_bytes(tmp_path, monkeypatch):
    spec = MODEL_FILES["face_detector"]
    payload = b"fake-model-bytes"
    monkeypatch.setitem(MODEL_FILES, "face_detector", spec.__class__(
        spec.key, spec.filename, hashlib.sha256(payload).hexdigest(), spec.url, spec.licence))
    path = tmp_path / spec.filename
    path.write_bytes(payload)
    seen: list[object] = []

    class Fake:
        def __init__(self, model, *_a, **_k):
            seen.append(model)

    monkeypatch.setattr(onnx_mod.ort, "InferenceSession", Fake)
    onnx_mod.make_session(path)
    assert seen == [payload]  # bytes, not a path ORT would re-open later (TOCTOU)


# ---------------------------------------------------------------- model-backed regressions
@pytest.mark.models
@requires_models
def test_em10_real_models_survive_degenerate_frames():
    det = FaceDetector(verified_path(MODELS_DIR, "face_detector"))
    dev = DeviceDetector(verified_path(MODELS_DIR, "coco_detector"), [62, 63, 67])
    for shape in [*DEGENERATE, (17, 33), (100, 3), (2000, 9)]:
        img = np.full((*shape, 3), 128, np.uint8)
        assert isinstance(det.detect(img), list)
        assert isinstance(dev.detect_all(img), list)


@pytest.mark.models
@requires_models
def test_em09_real_detector_cache_stays_bounded_and_detects_the_same():
    from skimage import data

    det = FaceDetector(verified_path(MODELS_DIR, "face_detector"))
    face = cv2.cvtColor(data.astronaut(), cv2.COLOR_RGB2BGR)
    first = det.detect(face)
    for side in range(40, 40 + 3 * ANCHOR_CACHE_MAX):
        det.detect(np.zeros((side, side + 1, 3), np.uint8))
    assert len(det._anchors) <= ANCHOR_CACHE_MAX
    again = det.detect(face)  # evicted + rebuilt priors give the identical detection
    assert first and len(first) == len(again)
    assert (first[0].x1, first[0].y1, first[0].x2, first[0].y2) == (again[0].x1, again[0].y1, again[0].x2, again[0].y2)


@pytest.mark.models
@requires_models
def test_em13_all_pinned_models_load_from_verified_bytes():
    from edge.ml.matcher import ArcFaceEmbedder

    for key in ("face_detector", "coco_detector", "minifasnet_v2", "minifasnet_v1se"):
        assert onnx_mod.make_session(verified_path(MODELS_DIR, key)).get_inputs()
    emb = ArcFaceEmbedder(verified_path(MODELS_DIR, "arcface"), MODEL_FILES["arcface"].sha256)
    v = emb.embed(np.full((112, 112, 3), 128, np.uint8))
    assert v.shape == (512,) and np.isfinite(v).all()
