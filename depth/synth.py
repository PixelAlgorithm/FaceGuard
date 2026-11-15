"""Synthetic TrueDepth-like depth maps for unit tests, the fake probe and pipeline smoke runs.

Geometry: pinhole camera, x right, y down, z forward (millimetres). Surfaces are sampled as dense 3D
points and splatted into the depth image with a z-buffer, so perspective and occlusion are exact up to
the sampling step. Output depth maps are in metres with NaN = no return (like unfiltered TrueDepth).

NEVER use these numbers for calibration claims: thresholds must be tuned on real captures
(depth/calibrate.py). The face model is a coarse anthropometric shape (ellipsoid head + Gaussian
features), good enough to exercise the algorithms, not to estimate error rates.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass, field, replace

import numpy as np

Deform = Callable[[np.ndarray, np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray, np.ndarray]]


# --------------------------------------------------------------------------------------------- camera
@dataclass(frozen=True)
class SynthCamera:
    width: int = 320
    height: int = 240
    hfov_deg: float = 70.0

    @property
    def fx(self) -> float:
        return (self.width / 2.0) / math.tan(math.radians(self.hfov_deg) / 2.0)

    @property
    def fy(self) -> float:
        return self.fx

    @property
    def cx(self) -> float:
        return (self.width - 1) / 2.0

    @property
    def cy(self) -> float:
        return (self.height - 1) / 2.0

    def intrinsics(self, ref_width: int | None = None, ref_height: int | None = None) -> dict:
        """Intrinsics dict as the app sends it (optionally expressed at a larger reference size)."""
        rw = ref_width or self.width
        rh = ref_height or self.height
        sx, sy = rw / self.width, rh / self.height
        return {
            "fx": self.fx * sx,
            "fy": self.fy * sy,
            "cx": self.cx * sx,
            "cy": self.cy * sy,
            "ref_width": rw,
            "ref_height": rh,
        }

    def project_norm(self, pts: np.ndarray) -> np.ndarray:
        """3D points (N,3) mm -> normalised image coords (N,2), top-left origin."""
        p = np.atleast_2d(np.asarray(pts, dtype=np.float64))
        u = self.fx * p[:, 0] / p[:, 2] + self.cx
        v = self.fy * p[:, 1] / p[:, 2] + self.cy
        return np.column_stack([(u + 0.5) / self.width, (v + 0.5) / self.height])


# ------------------------------------------------------------------------------------------ face model
@dataclass(frozen=True)
class Feature:
    amp_mm: float  # > 0 protrudes towards the camera, < 0 recessed
    x_mm: float
    y_mm: float
    sx_mm: float
    sy_mm: float
    mirror_x: bool = False  # also add the feature at -x


@dataclass(frozen=True)
class FaceShape:
    """Face frame: origin at the eye midpoint, x right, y down (towards the mouth), z away from camera."""

    half_width_mm: float = 72.0
    half_height_mm: float = 105.0
    depth_mm: float = 60.0
    center_y_mm: float = 30.0
    ipd_mm: float = 63.0
    nose_y_mm: float = 32.0
    lips_y_mm: float = 70.0
    chin_y_mm: float = 112.0
    features: tuple[Feature, ...] = (
        Feature(24.0, 0.0, 32.0, 9.0, 15.0),  # nose
        Feature(10.0, 0.0, 5.0, 7.0, 14.0),  # nose bridge
        Feature(-9.0, 31.5, 0.0, 13.0, 9.0, mirror_x=True),  # eye sockets
        Feature(4.0, 28.0, -16.0, 18.0, 6.0, mirror_x=True),  # brow ridges
        Feature(4.0, 40.0, 28.0, 14.0, 12.0, mirror_x=True),  # cheekbones
        Feature(6.0, 0.0, 70.0, 20.0, 7.0),  # lips
        Feature(6.0, 0.0, 108.0, 16.0, 12.0),  # chin
    )

    def surface(self, x: np.ndarray, y: np.ndarray) -> np.ndarray:
        """Relative depth (mm, 0 = ellipsoid apex, positive = farther); NaN outside the head ellipse."""
        q = 1.0 - (x / self.half_width_mm) ** 2 - ((y - self.center_y_mm) / self.half_height_mm) ** 2
        z = np.where(q > 0.0, self.depth_mm * (1.0 - np.sqrt(np.clip(q, 0.0, None))), np.nan)
        for f in self.features:
            xs = (f.x_mm, -f.x_mm) if f.mirror_x else (f.x_mm,)
            for fx in xs:
                g = np.exp(-0.5 * (((x - fx) / f.sx_mm) ** 2 + ((y - f.y_mm) / f.sy_mm) ** 2))
                z = z - f.amp_mm * g
        return z


OTHER_FACE = FaceShape(
    half_width_mm=80.0,
    depth_mm=45.0,
    features=(
        Feature(14.0, 0.0, 36.0, 11.0, 12.0),
        Feature(4.0, 0.0, 8.0, 9.0, 12.0),
        Feature(-4.0, 31.5, 0.0, 15.0, 10.0, mirror_x=True),
        Feature(2.0, 30.0, -18.0, 20.0, 7.0, mirror_x=True),
        Feature(8.0, 42.0, 36.0, 16.0, 14.0, mirror_x=True),
        Feature(3.0, 0.0, 74.0, 22.0, 8.0),
        Feature(10.0, 0.0, 112.0, 20.0, 14.0),
    ),
)


@dataclass(frozen=True)
class Pose:
    distance_mm: float = 400.0  # camera -> ellipsoid apex (front of the face)
    yaw_deg: float = 0.0
    pitch_deg: float = 0.0
    roll_deg: float = 0.0
    tx_mm: float = 0.0
    ty_mm: float = 0.0
    scale: float = 1.0
    pivot_back_mm: float = 90.0  # head rotates about a point this far behind the face front


def _rotation(yaw_deg: float, pitch_deg: float, roll_deg: float) -> np.ndarray:
    y, p, r = (math.radians(a) for a in (yaw_deg, pitch_deg, roll_deg))
    ry = np.array([[math.cos(y), 0, math.sin(y)], [0, 1, 0], [-math.sin(y), 0, math.cos(y)]])
    rx = np.array([[1, 0, 0], [0, math.cos(p), -math.sin(p)], [0, math.sin(p), math.cos(p)]])
    rz = np.array([[math.cos(r), -math.sin(r), 0], [math.sin(r), math.cos(r), 0], [0, 0, 1]])
    return rz @ rx @ ry


def _apply_pose(p_face: np.ndarray, pose: Pose, center_y: float) -> np.ndarray:
    """Face-frame points (mm) -> camera frame."""
    s = pose.scale
    p = p_face * s
    pivot = np.array([0.0, center_y * s, pose.pivot_back_mm * s])
    rot = _rotation(pose.yaw_deg, pose.pitch_deg, pose.roll_deg)
    p = np.einsum("nj,ij->ni", p - pivot, rot) + pivot
    return p + np.array([pose.tx_mm, pose.ty_mm - center_y * s, pose.distance_mm])


@dataclass
class SynthFrame:
    depth_m: np.ndarray  # (H, W) float32 metres, NaN = no return
    face_box_norm: list[float] | None
    landmarks_norm: dict[str, list[float]] | None
    meta: dict = field(default_factory=dict)


def _grid(x0: float, x1: float, y0: float, y1: float, step: float) -> tuple[np.ndarray, np.ndarray]:
    xs = np.arange(x0, x1 + step * 0.5, step)
    ys = np.arange(y0, y1 + step * 0.5, step)
    gx, gy = np.meshgrid(xs, ys)
    return gx.ravel(), gy.ravel()


def face_points(
    shape: FaceShape, pose: Pose, *, step_mm: float = 0.5, deform: Deform | None = None
) -> tuple[np.ndarray, dict[str, np.ndarray]]:
    """Dense 3D points of the face surface in camera coords + 3D landmarks (camera coords)."""
    a, b, yc = shape.half_width_mm, shape.half_height_mm, shape.center_y_mm
    step = step_mm / max(pose.scale, 1e-3)
    x, y = _grid(-a, a, yc - b, yc + b, step)
    z = shape.surface(x, y)
    ok = np.isfinite(z)
    x, y, z = x[ok], y[ok], z[ok]
    if deform is not None:
        x, y, z = deform(x, y, z)
    pts = _apply_pose(np.column_stack([x, y, z]), pose, yc)
    ly_ = shape.lips_y_mm
    lm_xy = {
        "left_eye": [(-shape.ipd_mm / 2, 0.0)],
        "right_eye": [(shape.ipd_mm / 2, 0.0)],
        "nose": [(0.0, shape.nose_y_mm)],
        "mouth": [(0.0, ly_ - 4.0), (0.0, ly_ + 4.0)],  # outer-lips centroid = mean of both lips
        "mouth_left": [(-24.0, ly_)],
        "mouth_right": [(24.0, ly_)],
        "chin": [(0.0, shape.chin_y_mm)],
        "box_tl": [(-0.95 * a, -35.0)],
        "box_br": [(0.95 * a, shape.chin_y_mm + 8.0)],
    }
    lms: dict[str, np.ndarray] = {}
    for k, pts_xy in lm_xy.items():
        lx = np.array([q[0] for q in pts_xy])
        ly = np.array([q[1] for q in pts_xy])
        lz = shape.surface(lx, ly)
        lz = np.where(np.isfinite(lz), lz, 0.0)
        if deform is not None and not k.startswith("box"):
            n = lx.size
            dx, dy, dz = deform(lx, ly, lz)
            lx, ly, lz = dx[:n], dy[:n], dz[:n]
        lms[k] = _apply_pose(np.column_stack([lx, ly, lz]), pose, yc).mean(axis=0)
    return pts, lms


def print_points(
    pose: Pose,
    *,
    bend_radius_mm: float | None = None,
    bend_axis: str = "vertical",
    width_mm: float = 150.0,
    top_mm: float = -80.0,
    bottom_mm: float = 130.0,
    step_mm: float = 0.5,
    shape: FaceShape | None = None,
) -> tuple[np.ndarray, dict[str, np.ndarray]]:
    """A printed life-size face photo: flat sheet, or bent into a convex cylinder whose axis is
    vertical (curvature across the face) or horizontal (curvature top-to-bottom)."""
    shape = shape or FaceShape()
    x, y = _grid(-width_mm / 2, width_mm / 2, top_mm, bottom_mm, step_mm / max(pose.scale, 1e-3))
    y_mid = (top_mm + bottom_mm) / 2.0

    def coord(xx: np.ndarray, yy: np.ndarray) -> np.ndarray:
        return xx if bend_axis == "vertical" else yy - y_mid

    def sheet(xx: np.ndarray, yy: np.ndarray) -> np.ndarray:
        if bend_radius_mm is None:
            return np.zeros_like(xx)
        r, c = bend_radius_mm, coord(xx, yy)
        return r - np.sqrt(np.clip(r * r - c * c, 0.0, None))

    ok = np.abs(coord(x, y)) < (bend_radius_mm or 1e9) * 0.98
    x, y = x[ok], y[ok]
    pts = _apply_pose(np.column_stack([x, y, sheet(x, y)]), pose, shape.center_y_mm)
    a = shape.half_width_mm
    lm_xy = {
        "left_eye": (-shape.ipd_mm / 2, 0.0),
        "right_eye": (shape.ipd_mm / 2, 0.0),
        "nose": (0.0, shape.nose_y_mm),
        "mouth": (0.0, shape.lips_y_mm),
        "mouth_left": (-24.0, shape.lips_y_mm),
        "mouth_right": (24.0, shape.lips_y_mm),
        "chin": (0.0, shape.chin_y_mm),
        "box_tl": (-0.95 * a, -35.0),
        "box_br": (0.95 * a, shape.chin_y_mm + 8.0),
    }
    lms = {
        k: _apply_pose(
            np.array([[lx, ly, sheet(np.array([lx]), np.array([ly]))[0]]]), pose, shape.center_y_mm
        )[0]
        for k, (lx, ly) in lm_xy.items()
    }
    return pts, lms


def render(
    cam: SynthCamera, point_sets: list[np.ndarray], background_mm: float | None = 1500.0
) -> np.ndarray:
    """Z-buffer splat of 3D point sets (mm) into a depth map in metres (float32, NaN = no return)."""
    w, h = cam.width, cam.height
    zbuf = np.full(w * h, np.inf)
    for pts in point_sets:
        p = np.asarray(pts, dtype=np.float64)
        p = p[p[:, 2] > 1.0]
        u = np.floor(cam.fx * p[:, 0] / p[:, 2] + cam.cx + 0.5).astype(np.int64)
        v = np.floor(cam.fy * p[:, 1] / p[:, 2] + cam.cy + 0.5).astype(np.int64)
        inb = (u >= 0) & (u < w) & (v >= 0) & (v < h)
        np.minimum.at(zbuf, v[inb] * w + u[inb], p[inb, 2])
    empty = ~np.isfinite(zbuf)
    zbuf[empty] = background_mm if background_mm is not None else np.nan
    return (zbuf.reshape(h, w) / 1000.0).astype(np.float32)


def add_sensor_noise(
    depth_m: np.ndarray,
    rng: np.random.Generator,
    *,
    sigma_mm: float = 0.7,
    hole_fraction: float = 0.05,
    zero_fraction: float = 0.0,
) -> np.ndarray:
    """Gaussian depth noise + random holes (NaN) + optional zero-valued holes."""
    d = depth_m.astype(np.float64) + rng.normal(0.0, sigma_mm / 1000.0, depth_m.shape)
    if hole_fraction > 0:
        d[rng.random(d.shape) < hole_fraction] = np.nan
    if zero_fraction > 0:
        d[rng.random(d.shape) < zero_fraction] = 0.0
    return d.astype(np.float32)


def to_wire(depth_m: np.ndarray, depth_type: str = "disparity", dtype: str = "float16") -> bytes:
    """Encode a metre depth map the way DepthProbe sends it: little-endian, row-major."""
    d = np.asarray(depth_m, dtype=np.float64)
    if depth_type == "disparity":
        with np.errstate(divide="ignore", invalid="ignore"):
            d = np.where(np.isfinite(d) & (d > 0), 1.0 / d, np.nan)
    elif depth_type != "depth":
        raise ValueError(f"unknown depth_type {depth_type!r}")
    np_dtype = {"float16": "<f2", "float32": "<f4"}[dtype]
    return np.ascontiguousarray(d.astype(np_dtype)).tobytes()


LANDMARK_KEYS = ("left_eye", "right_eye", "nose", "mouth", "mouth_left", "mouth_right", "chin")


def _frame_from(
    cam: SynthCamera,
    sets: list[np.ndarray],
    lms: dict[str, np.ndarray],
    *,
    with_landmarks: bool = True,
    rng: np.random.Generator | None = None,
    landmark_jitter: float = 0.0,
) -> SynthFrame:
    """`landmark_jitter`: Gaussian sigma in normalised units (Vision jitter is ~1 px at 640 wide)."""
    depth = render(cam, sets)
    corners = cam.project_norm(np.vstack([lms["box_tl"], lms["box_br"]]))
    x0, y0 = np.clip(corners.min(axis=0), 0.0, 1.0)
    x1, y1 = np.clip(corners.max(axis=0), 0.0, 1.0)
    box = [float(x0), float(y0), float(x1 - x0), float(y1 - y0)]
    landmarks = None
    if with_landmarks:
        landmarks = {}
        for k in LANDMARK_KEYS:
            xy = cam.project_norm(lms[k])[0]
            if rng is not None and landmark_jitter > 0:
                xy = xy + rng.normal(0.0, landmark_jitter, 2)
            landmarks[k] = [float(c) for c in xy]
    return SynthFrame(depth_m=depth, face_box_norm=box, landmarks_norm=landmarks)


# --------------------------------------------------------------------------------------- deformations
def open_mouth(drop_mm: float = 14.0, back_mm: float = 6.0, lips_y_mm: float = 70.0) -> Deform:
    """Jaw drop: the lips part at the mouth line, everything below moves down and back, and the
    mouth cavity (interior ~30 mm behind the lips) shows through the opening."""

    def _d(x: np.ndarray, y: np.ndarray, z: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        low = y > lips_y_mm
        y2, z2 = y + drop_mm * low, z + back_mm * low
        cav = (np.abs(x) < 22.0) & (y >= lips_y_mm - 1.0) & (y <= lips_y_mm + 1.0)
        cx_ = np.repeat(x[cav], 30)
        cy_ = np.repeat(y[cav], 30) + np.tile(np.linspace(0.0, drop_mm, 30), int(cav.sum()))
        cz_ = np.repeat(z[cav], 30) + 30.0
        return np.concatenate([x, cx_]), np.concatenate([y2, cy_]), np.concatenate([z2, cz_])

    return _d


def smile(
    bulge_mm: float = 6.0, corner_out_mm: float = 6.0, corner_up_mm: float = 4.0, corner_back_mm: float = 3.0
) -> Deform:
    """Smile: cheeks bulge forward and rise; mouth corners move outwards, up and back
    (a full smile widens the mouth by ~10-15 mm in total)."""

    def _d(x: np.ndarray, y: np.ndarray, z: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        cheek = np.exp(-0.5 * (((np.abs(x) - 32.0) / 13.0) ** 2 + ((y - 52.0) / 13.0) ** 2))
        corner = np.exp(-0.5 * (((np.abs(x) - 22.0) / 9.0) ** 2 + ((y - 70.0) / 8.0) ** 2))
        x2 = x + np.sign(x) * corner_out_mm * corner
        y2 = y - 4.0 * cheek - corner_up_mm * corner
        z2 = z - bulge_mm * cheek + corner_back_mm * corner
        return x2, y2, z2

    return _d


# --------------------------------------------------------------------------------------------- scenes
def scene_face(
    cam: SynthCamera,
    *,
    shape: FaceShape | None = None,
    pose: Pose | None = None,
    deform: Deform | None = None,
    with_landmarks: bool = True,
    rng: np.random.Generator | None = None,
    landmark_jitter: float = 0.0,
) -> SynthFrame:
    shape = shape or FaceShape()
    pts, lms = face_points(shape, pose or Pose(), deform=deform)
    return _frame_from(
        cam, [pts], lms, with_landmarks=with_landmarks, rng=rng, landmark_jitter=landmark_jitter
    )


def scene_print(
    cam: SynthCamera,
    *,
    pose: Pose | None = None,
    bend_radius_mm: float | None = None,
    bend_axis: str = "vertical",
) -> SynthFrame:
    pts, lms = print_points(pose or Pose(), bend_radius_mm=bend_radius_mm, bend_axis=bend_axis)
    return _frame_from(cam, [pts], lms)


def scene_eyehole_mask(
    cam: SynthCamera,
    *,
    pose: Pose | None = None,
    standoff_mm: float = 12.0,
    hole_radius_mm: float = 14.0,
) -> SynthFrame:
    """A rigid mask shell standing `standoff_mm` in front of a real face, with eye holes."""
    shape = FaceShape()
    pose = pose or Pose()
    face, lms = face_points(shape, pose)
    a, b, yc = shape.half_width_mm, shape.half_height_mm, shape.center_y_mm
    x, y = _grid(-a, a, yc - b, yc + b, 0.5)
    z = shape.surface(x, y) - standoff_mm
    eye = shape.ipd_mm / 2
    holes = (
        (np.hypot(x - eye, y) < hole_radius_mm) | (np.hypot(x + eye, y) < hole_radius_mm)
    ) | ~np.isfinite(z)
    shell = _apply_pose(np.column_stack([x[~holes], y[~holes], z[~holes]]), pose, yc)
    return _frame_from(cam, [face, shell], lms)


SCENES = ("face", "flat", "flat_tilted", "bent", "small_face", "mask_rigid", "eyehole_mask", "other_face")


def make_scene(
    name: str,
    cam: SynthCamera,
    rng: np.random.Generator,
    *,
    phase: str = "PASSIVE",
    sigma_mm: float = 0.7,
    hole_fraction: float = 0.05,
    jitter_mm: float = 1.5,
) -> SynthFrame:
    """Named scenes for the fake probe / smoke runs. CHALLENGE on a live face opens the mouth;
    CHALLENGE on mask_rigid only moves the head rigidly (what a rigid mask does)."""
    base = Pose(
        tx_mm=float(rng.normal(0, jitter_mm)),
        ty_mm=float(rng.normal(0, jitter_mm)),
        yaw_deg=float(rng.normal(0, 2.0)),
        pitch_deg=float(rng.normal(0, 2.0)),
    )
    challenge = phase.upper() == "CHALLENGE"
    jit = {"rng": rng, "landmark_jitter": 0.0015}
    if name == "face":
        frame = scene_face(cam, pose=base, deform=open_mouth() if challenge else None, **jit)
    elif name == "other_face":
        frame = scene_face(cam, shape=OTHER_FACE, pose=base, **jit)
    elif name == "mask_rigid":
        moved = replace(base, yaw_deg=base.yaw_deg + 3.0, tx_mm=base.tx_mm + 2.0) if challenge else base
        frame = scene_face(cam, pose=moved, **jit)
    elif name == "flat":
        frame = scene_print(cam, pose=base)
    elif name == "flat_tilted":
        frame = scene_print(cam, pose=replace(base, yaw_deg=30.0, pitch_deg=15.0))
    elif name == "bent":
        frame = scene_print(cam, pose=base, bend_radius_mm=50.0)
    elif name == "small_face":
        frame = scene_face(cam, pose=replace(base, scale=0.35, distance_mm=300.0))
    elif name == "eyehole_mask":
        frame = scene_eyehole_mask(cam, pose=base)
    else:
        raise ValueError(f"unknown scene {name!r}; choose from {SCENES}")
    frame.depth_m = add_sensor_noise(frame.depth_m, rng, sigma_mm=sigma_mm, hole_fraction=hole_fraction)
    frame.meta["scene"] = name
    return frame
