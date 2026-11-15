"""Depth liveness measurements D0-D4 and mask cues M1-M3 on iPhone front TrueDepth frames.

Numbers only. This module *measures*; the policy engine (edge/policy) applies the pass/fail
thresholds from config/thresholds.yaml (liveness.depth / liveness.mask) as defined in
docs/DECISION_POLICY.md §3.3-3.4. `classify()` mirrors those rules for the calibration CLI only.

Public API (import root = project root):
    compute_depth_checks(depth, *, depth_type, intrinsics, face_box_norm, landmarks_norm, cfg,
                         template=None, accuracy=None, diagnostics=None) -> DepthSignal dict
    compute_m1(depth_neutral, depth_challenge, face_box_norm, landmarks_norm, *, ...) -> M1 dict
    make_template(depth, *, ...) -> 64x64 float32 depth template (for M3) or None
    classify(signal, cfg, *, blendshape_moved=None) -> per-check zones + codes (CLI / calibration)
    depth_score(signal, cfg) -> 0..1 display score or None

Conventions
- Image coordinates are normalised [0, 1], top-left origin, x right, y down, in the depth map's own
  buffer orientation (DepthProbe maps Vision results into buffer coordinates before sending).
  Depth is aligned to the RGB frame (same field of view and aspect), so normalised coords are shared.
- Camera frame: x right, y down, z forward (away from the camera), millimetres.
- Input depth: metres (depth_type="depth") or 1/m (depth_type="disparity"), one frame (H, W) or a
  stack (N, H, W) that is fused with a per-pixel median. NaN, inf, <= 0 and out-of-range = invalid.
- Returned values are millimetres (ratios for D0). None means "not measured" and must never be
  treated as a pass by the consumer.
"""

from __future__ import annotations

import logging
import math
import time
import warnings
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import numpy as np

log = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_THRESHOLDS_PATH = PROJECT_ROOT / "config" / "thresholds.yaml"

# Exactly the fields of edge/policy/signals.py::DepthSignal (extra="forbid" there).
SIGNAL_KEYS: tuple[str, ...] = (
    "available",
    "absolute",
    "d0_valid_ratio",
    "d1_plane_rms_mm",
    "d2_quad_rms_mm",
    "d3_nose_relief_mm",
    "d4_ipd_mm",
    "m2_depth_step_mm",
    "m3_template_rms_mm",
    "d5_disagree",
    "m1_mouth_residual_mm",
    "m1_forehead_residual_mm",
)
M1_KEYS: tuple[str, str] = ("m1_mouth_residual_mm", "m1_forehead_residual_mm")

# Measurement (algorithm) parameters, NOT decision thresholds. Decision thresholds live only in
# config/thresholds.yaml. Any key can be overridden via a `liveness.depth.algo` mapping in the config.
DEFAULT_ALGO: dict[str, float] = {
    "z_min_m": 0.15,  # TrueDepth is tuned for faces at 25-50 cm; outside [0.15, 1.0] m = invalid
    "z_max_m": 1.00,
    "roi_shrink_x": 0.15,  # inner face ROI: fraction of the face box trimmed from each side
    "roi_shrink_y": 0.10,
    "min_roi_px": 8,
    "band_mm": 150.0,  # fit points must lie within +-band of the ROI median depth (drops background)
    "min_points": 150,  # minimum valid ROI points for D1/D2 (and everything that needs the plane)
    "max_points": 40000,
    "fit_iters": 3,  # trimmed refits for the plane / quadric
    "fit_keep": 0.90,
    "rms_trim": 0.03,  # D1/M3: RMS over the 97 % smallest |residuals| (fingers, hair, flying pixels)
    "d2_rms_trim": 0.01,  # D2: lighter trim - the nose is the D2 signal
    "nose_radius_ipd": 0.40,  # D3 nose-tip search radius (fraction of the inter-pupil distance)
    "nose_top_fraction": 0.05,
    "cheek_radius_ipd": 0.12,
    "min_patch_px": 5,
    "eye_radius_ipd": 0.12,  # D4 eye depth patch
    "m2_r_in_ipd": 0.12,  # M2 radial profiles around each eye
    "m2_r_out_ipd": 0.50,
    "m2_rays": 24,
    "m2_baseline_mm": 3.5,
    "m2_max_gap_ipd": 0.20,
    "m2_min_ray_fraction": 0.5,
    "m1_grid": 40,
    "m1_icp_iters": 6,
    "m1_mouth_quantile": 0.90,
    "m1_min_points": 30,
    "template_size": 64,
    "m3_min_overlap": 0.30,
    "frame_x_half": 0.95,  # face frame extent in IPD units (origin = eye midpoint, +y to the mouth)
    "frame_y_min": -0.75,
    "frame_y_max": 1.60,
    "default_hfov_deg": 70.0,  # only when intrinsics are missing (then D4 is not reported)
}


class DepthInputError(ValueError):
    """Depth array / depth_type cannot be interpreted."""


# ------------------------------------------------------------------------------------------- config
def _raw(cfg: Any) -> Mapping[str, Any]:
    if cfg is None:
        return {}
    raw = getattr(cfg, "raw", cfg)  # accepts edge.config.Thresholds or a plain dict
    return raw if isinstance(raw, Mapping) else {}


def depth_section(cfg: Any) -> Mapping[str, Any]:
    """`liveness.depth` from a full thresholds dict, or the dict itself if already the section."""
    raw = _raw(cfg)
    live = raw.get("liveness")
    if isinstance(live, Mapping) and isinstance(live.get("depth"), Mapping):
        return live["depth"]
    if isinstance(raw.get("depth"), Mapping) and "d1_plane_rms_fail_mm" in raw["depth"]:
        return raw["depth"]
    return raw


def mask_section(cfg: Any) -> Mapping[str, Any]:
    raw = _raw(cfg)
    live = raw.get("liveness")
    if isinstance(live, Mapping) and isinstance(live.get("mask"), Mapping):
        return live["mask"]
    if isinstance(raw.get("mask"), Mapping):
        return raw["mask"]
    return {}


def algo_params(cfg: Any) -> dict[str, float]:
    params = dict(DEFAULT_ALGO)
    override = depth_section(cfg).get("algo")
    if isinstance(override, Mapping):
        params.update({k: v for k, v in override.items() if k in DEFAULT_ALGO})
    return params


def load_thresholds(path: str | Path | None = None) -> dict[str, Any]:
    import yaml  # local import: only needed by CLIs / tests

    with Path(path or DEFAULT_THRESHOLDS_PATH).open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a YAML mapping")
    return data


def empty_signal(*, absolute: bool = False) -> dict[str, Any]:
    sig: dict[str, Any] = dict.fromkeys(SIGNAL_KEYS)
    sig["available"] = False
    sig["absolute"] = bool(absolute)
    return sig


# ------------------------------------------------------------------------------------- input fusion
def fuse_depth_mm(depth: Any, depth_type: str, algo: Mapping[str, float] | None = None) -> np.ndarray:
    """(H,W) or (N,H,W) depth/disparity -> fused (H,W) float64 depth in mm, NaN = invalid."""
    algo = algo or DEFAULT_ALGO
    if depth is None:
        raise DepthInputError("no depth array")
    arr = np.asarray(depth)
    if arr.ndim == 2:
        arr = arr[None]
    if arr.ndim != 3 or arr.shape[0] < 1 or arr.shape[1] < 2 or arr.shape[2] < 2:
        raise DepthInputError(f"depth must be (H,W) or (N,H,W), got shape {arr.shape}")
    a = arr.astype(np.float64)
    if depth_type == "disparity":
        with np.errstate(divide="ignore", invalid="ignore"):
            z_m = np.where(a > 0, 1.0 / a, np.nan)
    elif depth_type == "depth":
        z_m = a
    else:
        raise DepthInputError(f"depth_type must be 'depth' or 'disparity', got {depth_type!r}")
    z = z_m * 1000.0
    with np.errstate(invalid="ignore"):
        bad = ~np.isfinite(z) | (z < algo["z_min_m"] * 1000.0) | (z > algo["z_max_m"] * 1000.0)
    z[bad] = np.nan
    if z.shape[0] == 1:
        return z[0]
    return _median_stack(z)


def _median_stack(z: np.ndarray) -> np.ndarray:
    """Per-pixel median over axis 0 ignoring NaN; NaN where no frame is valid.

    np.nanmedian is ~10x slower here (per-pixel warnings + masked-array fallback)."""
    n = z.shape[0]
    s = np.sort(z, axis=0)  # NaN sorts last, so the k valid values come first
    k = np.isfinite(z).sum(axis=0)
    lo = np.clip((k - 1) // 2, 0, n - 1)[None]
    hi = np.clip(k // 2, 0, n - 1)[None]
    med = 0.5 * (np.take_along_axis(s, lo, axis=0)[0] + np.take_along_axis(s, hi, axis=0)[0])
    return np.where(k > 0, med, np.nan)


# ---------------------------------------------------------------------------------- geometry helpers
@dataclass(frozen=True)
class _Cam:
    fx: float
    fy: float
    cx: float
    cy: float
    source: str  # "intrinsics" | "default_fov"

    def backproject(self, u: Any, v: Any, z: Any) -> np.ndarray:
        u, v, z = (np.asarray(t, dtype=np.float64) for t in (u, v, z))
        return np.stack([(u - self.cx) * z / self.fx, (v - self.cy) * z / self.fy, z], axis=-1)

    def project(self, p: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        with np.errstate(divide="ignore", invalid="ignore"):
            return self.fx * p[..., 0] / p[..., 2] + self.cx, self.fy * p[..., 1] / p[..., 2] + self.cy


def _camera(intrinsics: Any, width: int, height: int, algo: Mapping[str, float]) -> _Cam:
    if isinstance(intrinsics, Mapping):
        try:
            fx, fy, cx, cy = (float(intrinsics[k]) for k in ("fx", "fy", "cx", "cy"))
            rw = float(intrinsics.get("ref_width") or width)
            rh = float(intrinsics.get("ref_height") or height)
            vals = (fx, fy, cx, cy, rw, rh)
            if all(math.isfinite(t) for t in vals) and fx > 0 and fy > 0 and rw > 0 and rh > 0:
                sx, sy = width / rw, height / rh
                return _Cam(fx * sx, fy * sy, cx * sx, cy * sy, "intrinsics")
        except (KeyError, TypeError, ValueError):
            pass
    f = (width / 2.0) / math.tan(math.radians(float(algo["default_hfov_deg"])) / 2.0)
    return _Cam(f, f, (width - 1) / 2.0, (height - 1) / 2.0, "default_fov")


@dataclass
class _Face:
    inner: tuple[int, int, int, int]  # y0, y1, x0, x1 (pixel slice bounds of the inner ROI)
    has_landmarks: bool = False
    left_eye: np.ndarray | None = None  # pixel coords (u, v)
    right_eye: np.ndarray | None = None
    nose: np.ndarray | None = None
    mouth: np.ndarray | None = None
    mid: np.ndarray | None = None
    ipd_px: float = 0.0
    ex: np.ndarray | None = None  # face-frame unit axes in the image (ex right-handed w.r.t. ey)
    ey: np.ndarray | None = None  # from the eye line towards the nose / mouth

    def to_px(self, gx: np.ndarray, gy: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Face-frame grid (IPD units) -> pixel coords."""
        assert self.mid is not None and self.ex is not None and self.ey is not None
        u = self.mid[0] + self.ipd_px * (gx * self.ex[0] + gy * self.ey[0])
        v = self.mid[1] + self.ipd_px * (gx * self.ex[1] + gy * self.ey[1])
        return u, v


def _norm_point(p: Any, width: int, height: int) -> np.ndarray | None:
    try:
        x, y = float(p[0]), float(p[1])
    except (TypeError, ValueError, IndexError, KeyError):
        return None
    if not (math.isfinite(x) and math.isfinite(y)) or not (-0.5 <= x <= 1.5 and -0.5 <= y <= 1.5):
        return None
    return np.array([x * width - 0.5, y * height - 0.5])


def _face_geometry(
    face_box_norm: Any, landmarks_norm: Any, width: int, height: int, algo: Mapping[str, float]
) -> _Face | None:
    if face_box_norm is None:
        return None
    try:
        x, y, w, h = (float(t) for t in face_box_norm)
    except (TypeError, ValueError):
        return None
    if not all(math.isfinite(t) for t in (x, y, w, h)) or w <= 0 or h <= 0:
        return None
    bx0, by0, bx1, by1 = max(x, 0.0), max(y, 0.0), min(x + w, 1.0), min(y + h, 1.0)
    if bx1 <= bx0 or by1 <= by0:
        return None
    sx, sy = float(algo["roi_shrink_x"]), float(algo["roi_shrink_y"])
    ix0 = max(int(math.floor((bx0 + sx * (bx1 - bx0)) * width)), 0)
    ix1 = min(int(math.ceil((bx1 - sx * (bx1 - bx0)) * width)), width)
    iy0 = max(int(math.floor((by0 + sy * (by1 - by0)) * height)), 0)
    iy1 = min(int(math.ceil((by1 - sy * (by1 - by0)) * height)), height)
    if ix1 - ix0 < algo["min_roi_px"] or iy1 - iy0 < algo["min_roi_px"]:
        return None
    face = _Face(inner=(iy0, iy1, ix0, ix1))
    if not isinstance(landmarks_norm, Mapping):
        return face
    le = _norm_point(landmarks_norm.get("left_eye"), width, height)
    re = _norm_point(landmarks_norm.get("right_eye"), width, height)
    nose = _norm_point(landmarks_norm.get("nose"), width, height)
    if le is None or re is None or nose is None:
        return face
    ipd = float(np.linalg.norm(re - le))
    if ipd < 3.0:
        return face
    e_lr = (re - le) / ipd
    mid = (le + re) / 2.0
    v = nose - mid
    v_perp = v - float(v[0] * e_lr[0] + v[1] * e_lr[1]) * e_lr
    if float(np.linalg.norm(v_perp)) < 0.1 * ipd:
        return face
    ey = v_perp / np.linalg.norm(v_perp)
    face.has_landmarks = True
    face.left_eye, face.right_eye, face.nose, face.mid = le, re, nose, mid
    face.mouth = _norm_point(landmarks_norm.get("mouth"), width, height)
    face.ipd_px = ipd
    face.ey = ey
    face.ex = np.array([ey[1], -ey[0]])
    return face


def _disc_values(img: np.ndarray, center: np.ndarray, radius: float) -> np.ndarray:
    """Finite values of img inside a disc (pixel coords)."""
    h, w = img.shape
    u, v = float(center[0]), float(center[1])
    r = max(float(radius), 1.0)
    x0, x1 = max(int(math.floor(u - r)), 0), min(int(math.ceil(u + r)) + 1, w)
    y0, y1 = max(int(math.floor(v - r)), 0), min(int(math.ceil(v + r)) + 1, h)
    if x1 <= x0 or y1 <= y0:
        return np.empty(0)
    yy, xx = np.mgrid[y0:y1, x0:x1]
    vals = img[y0:y1, x0:x1][(xx - u) ** 2 + (yy - v) ** 2 <= r * r]
    return vals[np.isfinite(vals)]


def _sample_nearest(img: np.ndarray, u: np.ndarray, v: np.ndarray) -> np.ndarray:
    h, w = img.shape
    iu = np.rint(np.nan_to_num(u, nan=-1.0)).astype(np.int64)
    iv = np.rint(np.nan_to_num(v, nan=-1.0)).astype(np.int64)
    ok = (iu >= 0) & (iu < w) & (iv >= 0) & (iv < h)
    out = np.full(np.shape(u), np.nan)
    out[ok] = img[iv[ok], iu[ok]]
    return out


def _sample_bilinear(img: np.ndarray, u: np.ndarray, v: np.ndarray) -> np.ndarray:
    """Bilinear lookup; falls back to the nearest pixel where a neighbour is invalid (NaN)."""
    h, w = img.shape
    u, v = np.asarray(u, dtype=np.float64), np.asarray(v, dtype=np.float64)
    out = _sample_nearest(img, u, v)
    if h < 2 or w < 2:
        return out
    ok = np.isfinite(u) & np.isfinite(v) & (u >= 0) & (u <= w - 1) & (v >= 0) & (v <= h - 1)
    uu, vv = u[ok], v[ok]
    x0 = np.clip(np.floor(uu).astype(np.int64), 0, w - 2)
    y0 = np.clip(np.floor(vv).astype(np.int64), 0, h - 2)
    fx, fy = uu - x0, vv - y0
    val = (
        img[y0, x0] * (1 - fx) * (1 - fy)
        + img[y0, x0 + 1] * fx * (1 - fy)
        + img[y0 + 1, x0] * (1 - fx) * fy
        + img[y0 + 1, x0 + 1] * fx * fy
    )
    out[ok] = np.where(np.isfinite(val), val, out[ok])
    return out


def _trimmed_rms(r: np.ndarray, trim: float) -> float:
    a = np.abs(np.asarray(r, dtype=np.float64))
    a = a[np.isfinite(a)]
    if a.size == 0:
        return float("nan")
    if trim > 0:
        a = np.sort(a)[: max(1, int(math.ceil(a.size * (1.0 - trim))))]
    return float(np.sqrt(np.mean(a * a)))


@dataclass(frozen=True)
class _Plane:
    c: np.ndarray
    n: np.ndarray  # unit normal pointing towards the camera
    u1: np.ndarray
    u2: np.ndarray


def _fit_plane(p: np.ndarray, iters: int, keep: float) -> _Plane:
    mask = np.ones(len(p), dtype=bool)
    c = p.mean(axis=0)
    vt = np.eye(3)
    for i in range(max(int(iters), 1)):
        c = p[mask].mean(axis=0)
        _, _, vt = np.linalg.svd(p[mask] - c, full_matrices=False)
        if i + 1 < iters:
            h = np.abs(_dot3(p - c, vt[2]))
            mask = h <= np.quantile(h, keep)
    n = vt[2]
    if float(np.dot(-c, n)) < 0:  # camera at the origin
        n = -n
    u1 = vt[0]
    return _Plane(c=c, n=n, u1=u1, u2=np.cross(n, u1))


def _quad_residuals(p: np.ndarray, plane: _Plane, iters: int, keep: float) -> np.ndarray:
    """Residual of h = q(a, b) (full quadratic) in the plane-aligned frame."""
    d = p - plane.c
    a, b, h = _dot3(d, plane.u1), _dot3(d, plane.u2), _dot3(d, plane.n)
    s = max(float(np.std(a)), float(np.std(b)), 1e-6)
    a, b = a / s, b / s
    design = np.column_stack([np.ones_like(a), a, b, a * a, a * b, b * b])
    mask = np.ones(len(p), dtype=bool)
    resid = h
    for _ in range(max(int(iters), 1)):
        coef, *_ = np.linalg.lstsq(design[mask], h[mask], rcond=None)
        resid = h - np.einsum("ij,j->i", design, coef)
        mask = np.abs(resid) <= np.quantile(np.abs(resid), keep)
    return resid


def _kabsch(src: np.ndarray, dst: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """R, t minimising ||R src + t - dst||."""
    cs, cd = src.mean(axis=0), dst.mean(axis=0)
    u, _, vt = np.linalg.svd(np.einsum("ni,nj->ij", src - cs, dst - cd))
    v, ut = vt.T, u.T
    d = float(np.sign(np.linalg.det(np.einsum("ij,jk->ik", v, ut)))) or 1.0
    rot = np.einsum("ij,jk->ik", v * np.array([1.0, 1.0, d]), ut)
    return rot, cd - np.einsum("ij,j->i", rot, cs)


def _dot3(p: np.ndarray, n: np.ndarray) -> np.ndarray:
    """p[..., :3] . n without BLAS (Accelerate raises spurious FP warnings on macOS)."""
    return p[..., 0] * n[0] + p[..., 1] * n[1] + p[..., 2] * n[2]


def _rotate(p: np.ndarray, rot: np.ndarray) -> np.ndarray:
    """(N,3) points times rot.T, BLAS-free."""
    return np.stack([_dot3(p, rot[i]) for i in range(3)], axis=-1)


def _nanmedian3(img: np.ndarray) -> np.ndarray:
    pad = np.pad(img, 1, constant_values=np.nan)
    h, w = img.shape
    stack = np.stack([pad[dy : dy + h, dx : dx + w] for dy in range(3) for dx in range(3)])
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        return np.nanmedian(stack, axis=0)


# --------------------------------------------------------------------------------------- preparation
@dataclass
class _Prep:
    z: np.ndarray  # fused depth, mm, NaN invalid
    cam: _Cam
    face: _Face | None = None
    d0: float | None = None
    median_mm: float | None = None
    n_points: int = 0
    plane: _Plane | None = None
    d1: float | None = None
    d2: float | None = None
    h_map: np.ndarray | None = None  # signed height above the face plane (mm), band-limited
    z_band: np.ndarray | None = None  # depth (mm) with out-of-band pixels removed
    reason: str | None = None


def _prepare(
    depth: Any,
    depth_type: str,
    intrinsics: Any,
    face_box_norm: Any,
    landmarks_norm: Any,
    algo: Mapping[str, float],
) -> _Prep:
    z = fuse_depth_mm(depth, depth_type, algo)
    height, width = z.shape
    prep = _Prep(z=z, cam=_camera(intrinsics, width, height, algo))
    prep.face = _face_geometry(face_box_norm, landmarks_norm, width, height, algo)
    if prep.face is None:
        prep.reason = "NO_FACE_BOX"
        return prep
    y0, y1, x0, x1 = prep.face.inner
    roi = z[y0:y1, x0:x1]
    valid = np.isfinite(roi)
    prep.d0 = float(valid.mean())
    vv, uu = np.nonzero(valid)
    zz = roi[vv, uu]
    if zz.size == 0:
        prep.reason = "NO_VALID_DEPTH"
        return prep
    med = float(np.median(zz))
    prep.median_mm = med
    keep = np.abs(zz - med) <= algo["band_mm"]
    uu, vv, zz = uu[keep] + x0, vv[keep] + y0, zz[keep]
    if zz.size > algo["max_points"]:
        idx = np.linspace(0, zz.size - 1, int(algo["max_points"])).astype(np.int64)
        uu, vv, zz = uu[idx], vv[idx], zz[idx]
    prep.n_points = int(zz.size)
    if zz.size < algo["min_points"]:
        prep.reason = "TOO_FEW_POINTS"
        return prep
    pts = prep.cam.backproject(uu, vv, zz)
    plane = _fit_plane(pts, int(algo["fit_iters"]), float(algo["fit_keep"]))
    prep.plane = plane
    prep.d1 = _trimmed_rms(_dot3(pts - plane.c, plane.n), float(algo["rms_trim"]))
    prep.d2 = _trimmed_rms(
        _quad_residuals(pts, plane, int(algo["fit_iters"]), float(algo["fit_keep"])),
        float(algo["d2_rms_trim"]),
    )
    with np.errstate(invalid="ignore"):
        z_band = np.where(np.abs(z - med) <= algo["band_mm"], z, np.nan)
    vg, ug = np.mgrid[0:height, 0:width]
    p_all = prep.cam.backproject(ug, vg, z_band)
    prep.h_map = _dot3(p_all - plane.c, plane.n)
    prep.z_band = z_band
    return prep


# ------------------------------------------------------------------------------------------ D3 / D4
def _nose_relief(prep: _Prep, algo: Mapping[str, float]) -> float | None:
    f, h = prep.face, prep.h_map
    if f is None or h is None or not f.has_landmarks:
        return None
    assert f.nose is not None and f.left_eye is not None and f.right_eye is not None and f.mid is not None
    nose_vals = _disc_values(h, f.nose, algo["nose_radius_ipd"] * f.ipd_px)
    offset = f.nose - f.mid
    cl = _disc_values(h, f.left_eye + offset, algo["cheek_radius_ipd"] * f.ipd_px)
    cr = _disc_values(h, f.right_eye + offset, algo["cheek_radius_ipd"] * f.ipd_px)
    mp = int(algo["min_patch_px"])
    if nose_vals.size < 3 or cl.size < mp or cr.size < mp:
        return None
    k = max(3, int(math.ceil(algo["nose_top_fraction"] * nose_vals.size)))
    nose_top = float(np.mean(np.sort(nose_vals)[-k:]))
    return nose_top - 0.5 * (float(np.median(cl)) + float(np.median(cr)))


def _ipd_mm(prep: _Prep, algo: Mapping[str, float]) -> float | None:
    f, zb = prep.face, prep.z_band
    if f is None or zb is None or not f.has_landmarks or prep.median_mm is None:
        return None
    assert f.left_eye is not None and f.right_eye is not None
    pts = []
    for eye in (f.left_eye, f.right_eye):
        vals = _disc_values(zb, eye, algo["eye_radius_ipd"] * f.ipd_px)
        ze = float(np.median(vals)) if vals.size >= 3 else prep.median_mm
        pts.append(prep.cam.backproject(eye[0], eye[1], ze))
    return float(np.linalg.norm(pts[0] - pts[1]))


# ----------------------------------------------------------------------------------------------- M2
def _eye_step(
    z: np.ndarray, eye: np.ndarray, ipd: float, med: float, cam: _Cam, algo: Mapping[str, float]
) -> float | None:
    r_in, r_out = algo["m2_r_in_ipd"] * ipd, algo["m2_r_out_ipd"] * ipd
    radii = np.arange(r_in, r_out + 1e-9, 1.0)
    if radii.size < 4:
        return None
    h, w = z.shape
    pad = int(math.ceil(r_out)) + 2
    x0, x1 = max(int(eye[0]) - pad, 0), min(int(eye[0]) + pad + 1, w)
    y0, y1 = max(int(eye[1]) - pad, 0), min(int(eye[1]) + pad + 1, h)
    if x1 - x0 < 3 or y1 - y0 < 3:
        return None
    sm = _nanmedian3(z[y0:y1, x0:x1])
    ang = np.linspace(0.0, 2.0 * math.pi, int(algo["m2_rays"]), endpoint=False)
    uu = eye[0] + np.cos(ang)[:, None] * radii[None, :] - x0
    vv = eye[1] + np.sin(ang)[:, None] * radii[None, :] - y0
    prof = _sample_nearest(sm, uu, vv)
    base = max(1, int(round(algo["m2_baseline_mm"] * cam.fx / med)))
    max_gap = max(2, int(round(algo["m2_max_gap_ipd"] * ipd)))
    steps = np.full(len(prof), np.nan)
    for i, row in enumerate(prof):
        idx = np.flatnonzero(np.isfinite(row))
        if idx.size < 3:
            continue
        j = np.searchsorted(idx, idx + base)  # first valid sample >= base px further out
        ok = j < idx.size
        if not ok.any():
            continue
        a, b = idx[ok], idx[j[ok]]
        span_ok = (b - a) <= base + max_gap
        if span_ok.any():
            steps[i] = float(np.max(np.abs(row[b[span_ok]] - row[a[span_ok]])))
    good = np.isfinite(steps)
    if good.mean() < algo["m2_min_ray_fraction"]:
        return None
    return float(np.median(steps[good]))


def _depth_step(prep: _Prep, algo: Mapping[str, float]) -> float | None:
    f, zb = prep.face, prep.z_band
    if f is None or zb is None or not f.has_landmarks or prep.median_mm is None:
        return None
    assert f.left_eye is not None and f.right_eye is not None
    vals = [_eye_step(zb, e, f.ipd_px, prep.median_mm, prep.cam, algo) for e in (f.left_eye, f.right_eye)]
    vals = [v for v in vals if v is not None]
    return max(vals) if vals else None


# ----------------------------------------------------------------------------------------------- M3
def _template_from(prep: _Prep, algo: Mapping[str, float]) -> np.ndarray | None:
    f, h = prep.face, prep.h_map
    if f is None or h is None or not f.has_landmarks:
        return None
    n = int(algo["template_size"])
    gx, gy = np.meshgrid(
        np.linspace(-algo["frame_x_half"], algo["frame_x_half"], n),
        np.linspace(algo["frame_y_min"], algo["frame_y_max"], n),
    )
    u, v = f.to_px(gx, gy)
    return _sample_nearest(h, u, v).astype(np.float32)


def _template_rms(now: np.ndarray, ref: np.ndarray, algo: Mapping[str, float]) -> float | None:
    if now.shape != ref.shape:
        return None
    ok = np.isfinite(now) & np.isfinite(ref)
    if ok.mean() < algo["m3_min_overlap"]:
        return None
    n = now.shape[0]
    gx, gy = np.meshgrid(np.linspace(-1, 1, now.shape[1]), np.linspace(-1, 1, n))
    diff = (now - ref).astype(np.float64)[ok]
    design = np.column_stack([np.ones(diff.size), gx[ok], gy[ok]])  # remove offset + small tilt
    coef, *_ = np.linalg.lstsq(design, diff, rcond=None)
    return _trimmed_rms(diff - np.einsum("ij,j->i", design, coef), float(algo["rms_trim"]))


# ------------------------------------------------------------------------------------------ public
def _r(v: float | None, nd: int = 2) -> float | None:
    if v is None or not math.isfinite(v):
        return None
    return round(float(v), nd)


def compute_depth_checks(
    depth: Any,
    *,
    depth_type: str,
    intrinsics: Mapping[str, Any] | None,
    face_box_norm: list[float] | None,
    landmarks_norm: Mapping[str, Any] | None,
    cfg: Any,
    template: np.ndarray | None = None,
    accuracy: str | None = None,
    diagnostics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Measure D0-D4, M2, M3 for one attempt (PASSIVE phase). Returns exactly SIGNAL_KEYS.

    `accuracy`: AVDepthData.depthDataAccuracy as sent by the app ("absolute" | "relative");
    unknown -> treated as relative (D4 not reported when require_absolute_depth_for_d4).
    `diagnostics`: optional dict filled with non-biometric debug values (reason, timings, raw IPD).
    """
    t0 = time.perf_counter()
    absolute = accuracy == "absolute"
    diag = diagnostics if diagnostics is not None else {}
    sig = empty_signal(absolute=absolute)
    try:
        dcfg = depth_section(cfg)
        algo = algo_params(cfg)
        prep = _prepare(depth, depth_type, intrinsics, face_box_norm, landmarks_norm, algo)
        diag.update(
            reason=prep.reason,
            intrinsics_source=prep.cam.source,
            landmarks=bool(prep.face and prep.face.has_landmarks),
            median_face_depth_mm=_r(prep.median_mm, 1),
            n_points=prep.n_points,
        )
        if prep.face is None:
            return sig
        sig["available"] = True
        sig["d0_valid_ratio"] = _r(prep.d0, 4)
        if prep.plane is None:
            return sig
        sig["d1_plane_rms_mm"] = _r(prep.d1)
        sig["d2_quad_rms_mm"] = _r(prep.d2)
        sig["d3_nose_relief_mm"] = _r(_nose_relief(prep, algo))
        ipd = _ipd_mm(prep, algo)
        diag["d4_ipd_mm_raw"] = _r(ipd)
        need_abs = bool(dcfg.get("require_absolute_depth_for_d4", True))
        if prep.cam.source == "intrinsics" and (absolute or not need_abs):
            sig["d4_ipd_mm"] = _r(ipd)
        sig["m2_depth_step_mm"] = _r(_depth_step(prep, algo))
        if template is not None:
            now = _template_from(prep, algo)
            if now is not None:
                sig["m3_template_rms_mm"] = _r(_template_rms(now, np.asarray(template), algo))
        return sig
    except Exception as exc:  # optional signal: never take the attempt down, report unavailable
        log.exception("depth checks failed")
        diag["error"] = f"{type(exc).__name__}: {exc}"
        return empty_signal(absolute=absolute)
    finally:
        diag["compute_ms"] = round((time.perf_counter() - t0) * 1000.0, 2)


def make_template(
    depth: Any,
    *,
    depth_type: str,
    intrinsics: Mapping[str, Any] | None,
    face_box_norm: list[float] | None,
    landmarks_norm: Mapping[str, Any] | None,
    cfg: Any = None,
) -> np.ndarray | None:
    """Enrolment: landmark-aligned 64x64 height map (mm above the face plane, NaN = no data).

    Biometric template: store encrypted only, never log it.
    """
    algo = algo_params(cfg)
    try:
        prep = _prepare(depth, depth_type, intrinsics, face_box_norm, landmarks_norm, algo)
    except DepthInputError:
        return None
    return _template_from(prep, algo)


def _face_cloud(prep: _Prep, face: _Face, gx: np.ndarray, gy: np.ndarray) -> np.ndarray:
    """3D points (mm) of prep's depth sampled on a face-frame grid (sub-pixel, bilinear)."""
    assert prep.z_band is not None
    u, v = face.to_px(gx, gy)
    return prep.cam.backproject(u, v, _sample_bilinear(prep.z_band, u, v))


def _surface_residuals(
    pts: np.ndarray, rot: np.ndarray, t: np.ndarray, target: _Prep
) -> tuple[np.ndarray, np.ndarray]:
    """Move pts (challenge frame) into the neutral frame and compare with the neutral surface
    along the viewing ray. Returns (residual mm, matched neutral points)."""
    assert target.z_band is not None
    y = _rotate(pts, rot) + t
    u, v = target.cam.project(y)
    q = target.cam.backproject(u, v, _sample_bilinear(target.z_band, u, v))
    return np.linalg.norm(y - q, axis=-1), q


def _lower_face_px(lm: Any, width: int, height: int) -> dict[str, np.ndarray]:
    """Mouth centroid, lip corners and an inner-chin point (60 % from the mouth to Vision's chin
    contour point, which itself sits on the jaw silhouette where depth is unstable)."""
    if not isinstance(lm, Mapping):
        return {}
    pts = {k: _norm_point(lm.get(k), width, height) for k in ("mouth", "mouth_left", "mouth_right", "chin")}
    mouth, chin = pts["mouth"], pts["chin"]
    pts["chin"] = None if mouth is None or chin is None else mouth + 0.6 * (chin - mouth)
    return {k: p for k, p in pts.items() if p is not None}


def _pair_lip_corners(a: dict[str, np.ndarray], b: dict[str, np.ndarray]) -> dict[str, np.ndarray]:
    """Pair the lip corners order-invariantly: DepthProbe's Vision pass may use a different image
    orientation per frame, which swaps "left" and "right"; the cheaper assignment is the real one, so a
    swap is never read as a mouth-width of motion."""
    keys = ("mouth_left", "mouth_right")
    if not all(k in a for k in keys) or not all(k in b for k in keys):
        return b
    al, ar, bl, br = a["mouth_left"], a["mouth_right"], b["mouth_left"], b["mouth_right"]
    straight = float(np.linalg.norm(al - bl) + np.linalg.norm(ar - br))
    crossed = float(np.linalg.norm(al - br) + np.linalg.norm(ar - bl))
    return {**b, "mouth_left": br, "mouth_right": bl} if crossed < straight else b


def _landmark_displacement(
    pn: _Prep,
    pc: _Prep,
    lm_n: Any,
    lm_c: Any,
    rot: np.ndarray,
    t: np.ndarray,
    algo: Mapping[str, float],
) -> float | None:
    """In-plane motion (mm) of lower-face landmarks after the rigid alignment.

    Catches deformation that slides along the surface (jaw drop, lip corners pulled out), which the
    along-ray surface residual cannot see; the along-ray part is dropped here because it is dominated by
    depth noise on steep slopes. Robust statistic: 2nd largest displacement when >= 3 landmarks (one
    jittery landmark on a rigid mask cannot fake motion), else the smallest."""
    if pn.face is None or pn.z_band is None or pc.z_band is None:
        return None
    h, w = pn.z_band.shape
    a_pts, b_pts = _lower_face_px(lm_n, w, h), _lower_face_px(lm_c, w, h)
    b_pts = _pair_lip_corners(a_pts, b_pts)
    radius = float(algo["cheek_radius_ipd"]) * 0.5 * pn.face.ipd_px
    disp = []
    for key, a in a_pts.items():
        b = b_pts.get(key)
        if b is None:
            continue
        za, zb = _disc_values(pn.z_band, a, radius), _disc_values(pc.z_band, b, radius)
        if za.size < 3 or zb.size < 3:
            continue
        pa = pn.cam.backproject(a[0], a[1], float(np.median(za)))
        pb = _rotate(pc.cam.backproject(b[0], b[1], float(np.median(zb)))[None], rot)[0] + t
        d = pb - pa
        ray = pa / np.linalg.norm(pa)
        disp.append(float(np.linalg.norm(d - _dot3(d, ray) * ray)))
    if not disp:
        return None
    disp.sort(reverse=True)
    return disp[1] if len(disp) >= 3 else disp[-1]


def compute_m1(
    depth_neutral: Any,
    depth_challenge: Any,
    face_box_norm: list[float] | None,
    landmarks_norm: Mapping[str, Any] | None,
    *,
    depth_type: str = "depth",
    intrinsics: Mapping[str, Any] | None = None,
    cfg: Any = None,
    face_box_norm_challenge: Any = None,
    landmarks_norm_challenge: Any = None,
    depth_type_challenge: str | None = None,
    diagnostics: dict[str, Any] | None = None,
) -> dict[str, float | None]:
    """M1: rigidly align forehead + nose bridge between the neutral and challenge frames, then
    measure how far the mouth/cheek region moved off the neutral surface (+ in-plane motion of the
    lower-face landmarks).

    Real face (smile / open mouth): mouth residual > 4 mm, forehead < 2 mm. Rigid mask: both small.
    The forehead residual is the alignment quality; the consumer should not trust M1 when it is high.

    `depth_challenge` may be one frame or a stack (N, H, W) captured across the challenge window; each
    frame is measured on its own and the most deformed, reliably aligned frame is reported.
    `face_box_norm_challenge` / `landmarks_norm_challenge`: one value for all frames, or a per-frame
    list (DepthProbe sends `*_frames` lists in CHALLENGE meta). With per-frame landmarks every frame is
    measured; with a single set (or None) only frame 0 is, because stale landmarks on later frames make
    head motion look like deformation.
    """
    t0 = time.perf_counter()
    diag = diagnostics if diagnostics is not None else {}
    out: dict[str, float | None] = dict.fromkeys(M1_KEYS)
    try:
        algo = algo_params(cfg)
        pn = _prepare(depth_neutral, depth_type, intrinsics, face_box_norm, landmarks_norm, algo)
        if pn.face is None or not pn.face.has_landmarks or pn.z_band is None:
            diag["reason"] = f"NEUTRAL_{pn.reason or 'NO_LANDMARKS'}"
            return out
        if depth_challenge is None:
            diag["reason"] = "NO_CHALLENGE_DEPTH"
            return out
        chal = np.asarray(depth_challenge)
        frames = list(chal) if chal.ndim == 3 else [chal]  # each challenge frame is measured on its own
        boxes = _per_frame(face_box_norm_challenge, len(frames), is_box=True)
        lms = _per_frame(landmarks_norm_challenge, len(frames), is_box=False)
        per_frame_lms = isinstance(landmarks_norm_challenge, (list, tuple))
        if not per_frame_lms:
            # One landmark set describes frame 0 only; measuring later frames with it lets head motion
            # look like deformation (rigid masks escape), so only frame 0 is measured.
            frames, boxes, lms = frames[:1], boxes[:1], lms[:1]
        results: list[dict[str, float]] = []
        reasons: list[str] = []
        for k, frame in enumerate(frames):
            box_k, (lm_k, own) = boxes[k][0], lms[k]
            if per_frame_lms and not own:
                # Vision missed this frame: measuring it with the neutral (stale) landmarks makes head motion
                # look like deformation, and the most deformed frame wins, so a rigid mask could pass M1.
                reasons.append("CHALLENGE_FRAME_NO_LANDMARKS")
                continue
            pc = _prepare(
                frame,
                depth_type_challenge or depth_type,
                intrinsics,
                box_k if box_k is not None else face_box_norm,
                lm_k if lm_k is not None else landmarks_norm,
                algo,
            )
            r = _m1_frame(pn, pc, landmarks_norm, lm_k if own else None, algo)
            if isinstance(r, str):
                reasons.append(r)
            else:
                results.append(r)
        if not results:
            diag["reason"] = reasons[0] if reasons else "NO_CHALLENGE_FRAMES"
            return out
        # Challenge frames may straddle the expression (capture timing): report the most deformed frame
        # among the reliably aligned ones (forehead residual within the policy bound), else the best-aligned.
        fh_max = _num(mask_section(cfg).get("m1_forehead_residual_max_mm"))
        reliable = [r for r in results if fh_max is None or r["forehead"] <= fh_max]
        pick = (
            max(reliable, key=lambda r: r["mouth"]) if reliable else min(results, key=lambda r: r["forehead"])
        )
        out["m1_forehead_residual_mm"] = _r(pick["forehead"])
        out["m1_mouth_residual_mm"] = _r(pick["mouth"])
        diag.update(
            m1_surface_mm=_r(pick["surface"]),
            m1_landmark_mm=_r(pick["landmark"]) if pick["landmark"] >= 0 else None,
            m1_frames=len(frames),
            m1_frame_index=results.index(pick),
            m1_per_frame=[(_r(r["mouth"]), _r(r["forehead"])) for r in results],
        )
        return out
    except Exception as exc:
        log.exception("M1 failed")
        diag["error"] = f"{type(exc).__name__}: {exc}"
        return dict.fromkeys(M1_KEYS)
    finally:
        diag["compute_ms"] = round((time.perf_counter() - t0) * 1000.0, 2)


def _per_frame(value: Any, n: int, *, is_box: bool) -> list[tuple[Any, bool]]:
    """Normalise a challenge box/landmarks argument to n (value, measured_on_this_frame) pairs."""
    if is_box:
        per = (
            isinstance(value, (list, tuple))
            and len(value) > 0
            and (value[0] is None or isinstance(value[0], (list, tuple)))
        )
    else:
        per = isinstance(value, (list, tuple))
    if per:
        vals = list(value)[:n] + [None] * max(0, n - len(value))
        return [(v, v is not None) for v in vals]
    return [(value, k == 0 and value is not None) for k in range(n)]


def _m1_frame(
    pn: _Prep, pc: _Prep, lm_n: Any, lm_c: Any, algo: Mapping[str, float]
) -> dict[str, float] | str:
    """M1 for one challenge frame -> {mouth, forehead, surface, landmark} or a reason string."""
    if pc.face is None or not pc.face.has_landmarks or pc.z_band is None:
        return f"CHALLENGE_{pc.reason or 'NO_LANDMARKS'}"
    assert pn.face is not None
    n = int(algo["m1_grid"])
    gx, gy = np.meshgrid(
        np.linspace(-algo["frame_x_half"], algo["frame_x_half"], n),
        np.linspace(algo["frame_y_min"], algo["frame_y_max"], n),
    )
    ax = np.abs(gx)
    rigid = ((gy >= -0.75) & (gy <= -0.20) & (ax <= 0.80)) | ((gy > -0.20) & (gy <= 0.35) & (ax <= 0.15))
    mouth = ((gy >= 0.85) & (gy <= 1.55) & (ax <= 0.75)) | (
        (gy >= 0.45) & (gy < 0.85) & (ax >= 0.30) & (ax <= 0.85)
    )
    # Sample the challenge on the *neutral* face frame, shifted by the eye-midpoint motion: eye
    # landmarks jitter (and squint during a smile), so only their mean position is trusted.
    frame_c = replace(pn.face, mid=pc.face.mid)
    cn, cc = _face_cloud(pn, pn.face, gx, gy), _face_cloud(pc, frame_c, gx, gy)
    ok_n, ok_c = np.isfinite(cn).all(axis=-1), np.isfinite(cc).all(axis=-1)
    pair = rigid & ok_n & ok_c
    min_pts = int(algo["m1_min_points"])
    if pair.sum() < min_pts:
        return "TOO_FEW_RIGID_POINTS"
    rot, t = _kabsch(cc[pair], cn[pair])  # landmark-grid correspondences: initial alignment
    src = cc[rigid & ok_c]
    for _ in range(int(algo["m1_icp_iters"])):  # projective ICP on the rigid region
        res, q = _surface_residuals(src, rot, t, pn)
        good = np.isfinite(res)
        if good.sum() < min_pts:
            break
        good &= res <= max(3.0 * float(np.median(res[good])), 1.0)
        if good.sum() < min_pts:
            break
        rot, t = _kabsch(src[good], q[good])
    res_rigid, _ = _surface_residuals(src, rot, t, pn)
    res_mouth, _ = _surface_residuals(cc[mouth & ok_c], rot, t, pn)
    res_mouth = res_mouth[np.isfinite(res_mouth)]
    if np.isfinite(res_rigid).sum() < min_pts or res_mouth.size < min_pts:
        return "TOO_FEW_MATCHED_POINTS"
    surface = float(np.quantile(res_mouth, float(algo["m1_mouth_quantile"])))
    lm_disp = _landmark_displacement(pn, pc, lm_n, lm_c, rot, t, algo) if lm_c is not None else None
    return {
        "mouth": max(surface, lm_disp) if lm_disp is not None else surface,
        "forehead": _trimmed_rms(res_rigid, 0.10),
        "surface": surface,
        "landmark": lm_disp if lm_disp is not None else -1.0,
    }


# ----------------------------------------------------------------------------- classification (CLI)
def _num(v: Any) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _zone_gt(v: float | None, fail_below: float, pass_above: float) -> str:
    """FAIL if v < fail; PASS if v > pass; else UNSURE (D1, D2)."""
    if v is None:
        return "NA"
    return "FAIL" if v < fail_below else "PASS" if v > pass_above else "UNSURE"


def classify(signal: Mapping[str, Any], cfg: Any, *, blendshape_moved: bool | None = None) -> dict[str, Any]:
    """Depth-only view of DECISION_POLICY.md §3.1/§3.3/§3.4 for calibration output.

    The policy engine (edge/policy) is authoritative; this helper exists so the depth CLI can show
    PASS / UNSURE / FAIL per check with the configured thresholds. NA (not measured) is never a pass:
    a missing D1-D3 while depth is available yields LIVENESS_UNSURE.
    """
    d, m = depth_section(cfg), mask_section(cfg)
    checks = dict.fromkeys(("d0", "d1", "d2", "d3", "d4", "m1", "m2", "m3"), "NA")
    if not signal.get("available"):
        return {"checks": checks, "overall": "NOT_AVAILABLE", "codes": []}
    d0 = _num(signal.get("d0_valid_ratio"))
    if d0 is not None:
        checks["d0"] = (
            "FAIL" if d0 < d["d0_valid_fail_below"] else "UNSURE" if d0 < d["d0_valid_pass_min"] else "PASS"
        )
    checks["d1"] = _zone_gt(
        _num(signal.get("d1_plane_rms_mm")), d["d1_plane_rms_fail_mm"], d["d1_plane_rms_pass_mm"]
    )
    checks["d2"] = _zone_gt(
        _num(signal.get("d2_quad_rms_mm")), d["d2_quad_rms_fail_mm"], d["d2_quad_rms_pass_mm"]
    )
    d3 = _num(signal.get("d3_nose_relief_mm"))
    if d3 is not None:
        checks["d3"] = (
            "FAIL"
            if d3 < d["d3_nose_relief_fail_mm"]
            else "PASS"
            if d3 >= d["d3_nose_relief_pass_mm"]
            else "UNSURE"
        )
    d4 = _num(signal.get("d4_ipd_mm"))
    if d4 is not None and (signal.get("absolute") or not d.get("require_absolute_depth_for_d4", True)):
        checks["d4"] = "FAIL" if (d4 < d["d4_ipd_min_mm"] or d4 > d["d4_ipd_max_mm"]) else "PASS"
    mouth, forehead = _num(signal.get("m1_mouth_residual_mm")), _num(signal.get("m1_forehead_residual_mm"))
    if mouth is not None and m:
        if forehead is None or forehead > m["m1_forehead_residual_max_mm"]:
            checks["m1"] = "UNRELIABLE"
        elif mouth < m["m1_mouth_residual_min_mm"]:
            checks["m1"] = "RIGID"
        else:
            checks["m1"] = "DEFORMED"
    m2 = _num(signal.get("m2_depth_step_mm"))
    if m2 is not None and m:
        checks["m2"] = "STRONG" if m2 >= m["m2_depth_step_strong_mm"] else "NONE"
    m3 = _num(signal.get("m3_template_rms_mm"))
    if m3 is not None and m:
        checks["m3"] = (
            "STRONG"
            if m3 >= m["m3_template_rms_strong_mm"]
            else "WEAK"
            if m3 >= m["m3_template_rms_weak_mm"]
            else "NONE"
        )

    if checks["d0"] in ("FAIL", "NA"):
        return {"checks": checks, "overall": "RECAPTURE", "codes": ["QUALITY_DEPTH_INVALID"]}
    hard: list[str] = []
    if "FAIL" in (checks["d1"], checks["d2"], checks["d3"]):
        hard.append("SPOOF_FLAT_DEPTH")
    if checks["d4"] == "FAIL":
        hard.append("SPOOF_DEPTH_SCALE")
    rigid = checks["m1"] == "RIGID" and blendshape_moved is not False
    strong = [c for c, k in (("MASK_CUE_EDGE", "m2"), ("MASK_CUE_SHAPE", "m3")) if checks[k] == "STRONG"]
    cues = ["MASK_CUE_RIGID"] if rigid else []
    cues += [
        c for c, k in (("MASK_CUE_EDGE", "m2"), ("MASK_CUE_SHAPE", "m3")) if checks[k] in ("STRONG", "WEAK")
    ]
    unsure = checks["d0"] == "UNSURE" or any(checks[k] in ("UNSURE", "NA") for k in ("d1", "d2", "d3"))
    deny_count = int(m.get("strong_cue_deny_count", 2)) if m else 2
    if hard or rigid or len(strong) >= deny_count:
        codes = hard + (["MASK_CUE_RIGID"] if rigid else []) + (strong if len(strong) >= deny_count else [])
        return {"checks": checks, "overall": "FAIL", "codes": codes}
    if cues or unsure:
        return {
            "checks": checks,
            "overall": "UNSURE",
            "codes": cues + (["LIVENESS_UNSURE"] if unsure else []),
        }
    return {"checks": checks, "overall": "PASS", "codes": []}


def depth_score(signal: Mapping[str, Any], cfg: Any) -> float | None:
    """0..1 display score (`scores.depth` in docs/API.md): weakest normalised margin of D1-D3.

    0 at the FAIL threshold, 1 at the PASS threshold. Display only; decisions use the raw values.
    """
    if not signal.get("available"):
        return None
    d = depth_section(cfg)
    parts = []
    for key, lo, hi in (
        ("d1_plane_rms_mm", "d1_plane_rms_fail_mm", "d1_plane_rms_pass_mm"),
        ("d2_quad_rms_mm", "d2_quad_rms_fail_mm", "d2_quad_rms_pass_mm"),
        ("d3_nose_relief_mm", "d3_nose_relief_fail_mm", "d3_nose_relief_pass_mm"),
    ):
        v = _num(signal.get(key))
        if v is None:
            return None
        parts.append(min(max((v - d[lo]) / (d[hi] - d[lo]), 0.0), 1.0))
    return round(min(parts), 3)


__all__ = [
    "DEFAULT_ALGO",
    "M1_KEYS",
    "SIGNAL_KEYS",
    "DepthInputError",
    "algo_params",
    "classify",
    "compute_depth_checks",
    "compute_m1",
    "depth_score",
    "depth_section",
    "empty_signal",
    "fuse_depth_mm",
    "load_thresholds",
    "make_template",
    "mask_section",
]
