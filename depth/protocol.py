"""Wire format of `POST /v1/depth/frames` (DepthProbe -> edge) and a one-call processing helper.

The edge HTTP endpoints (edge-ml) parse the multipart request and hand the pieces to this module:

    from depth.protocol import DepthProtocolError, process_upload
    res = process_upload(meta_text, [depth_0_bytes, ...], thresholds, neutral=passive_result_or_None)
    DepthSignal(**res.signal)   # exactly the edge/policy/signals.py::DepthSignal fields

Multipart parts: `meta` (JSON text field), `depth_0`..`depth_2` (raw little-endian row-major float16 or
float32, depth in metres or disparity in 1/m, NaN/0 = invalid), optional `rgb_0` (JPEG, unused here).

meta (required): attempt_id, phase "PASSIVE"|"CHALLENGE", depth_type "disparity"|"depth",
dtype "float16"|"float32", width, height, intrinsics {fx, fy, cx, cy, ref_width, ref_height},
face_box_norm [x, y, w, h] | null, landmarks_norm {left_eye, right_eye, nose: [x, y]} | null
(+ optional mouth, mouth_left, mouth_right, chin), timestamps_ms [], device (string).
CHALLENGE meta may add face_box_norm_frames / landmarks_norm_frames: one entry per depth_i (Vision run on
every challenge frame), so M1 can use the frame that caught the expression.
meta (optional, sent by DepthProbe): accuracy (alias depth_accuracy) "absolute"|"relative", depth_filtered,
depth_quality, intrinsics_source, capture_ms, received_ms, valid_ratio_device, app_version, ...
Unknown fields are ignored (forward compatible).

Privacy: depth maps are biometric data. Keep `DepthResult.depth_m` in memory only (for M1 in the
CHALLENGE phase of the same attempt) and drop it when the attempt closes; never log or persist it.
"""

from __future__ import annotations

import json
import math
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from depth.checks import (
    M1_KEYS,
    SIGNAL_KEYS,
    algo_params,
    compute_depth_checks,
    compute_m1,
    empty_signal,
    fuse_depth_mm,
)

PHASES = ("PASSIVE", "CHALLENGE")
DEPTH_TYPES = ("depth", "disparity")
DTYPES = {"float16": "<f2", "float32": "<f4"}
MAX_FRAMES = 3
MAX_PIXELS = 1280 * 960
LANDMARK_KEYS = ("left_eye", "right_eye", "nose", "mouth", "mouth_left", "mouth_right", "chin")


class DepthProtocolError(ValueError):
    """Malformed upload -> the edge should answer 422 VALIDATION_ERROR (never a decision)."""


def _box(v: Any) -> list[float] | None:
    if v is None:
        return None
    if not isinstance(v, (list, tuple)) or len(v) != 4:
        raise DepthProtocolError("face_box_norm must be [x, y, w, h] or null")
    try:
        box = [float(t) for t in v]
    except (TypeError, ValueError) as exc:
        raise DepthProtocolError("face_box_norm must contain numbers") from exc
    if not all(math.isfinite(t) for t in box) or box[2] <= 0 or box[3] <= 0:
        raise DepthProtocolError("face_box_norm must be finite with w, h > 0")
    return box


def _landmarks(v: Any) -> dict[str, list[float]] | None:
    if v is None:
        return None
    if not isinstance(v, Mapping):
        raise DepthProtocolError("landmarks_norm must be an object or null")
    out: dict[str, list[float]] = {}
    for key in LANDMARK_KEYS:
        p = v.get(key)
        if p is None:
            continue
        if not isinstance(p, (list, tuple)) or len(p) != 2:
            raise DepthProtocolError(f"landmarks_norm.{key} must be [x, y]")
        try:
            xy = [float(p[0]), float(p[1])]
        except (TypeError, ValueError) as exc:
            raise DepthProtocolError(f"landmarks_norm.{key} must contain numbers") from exc
        if all(math.isfinite(t) for t in xy):
            out[key] = xy
    if not all(k in out for k in ("left_eye", "right_eye", "nose")):
        return None  # incomplete landmarks: treated as "box only"
    return out


def _per_frame_list(v: Any, parse: Any) -> list[Any] | None:
    """Optional per-depth-frame list (CHALLENGE): face_box_norm_frames / landmarks_norm_frames."""
    if v is None:
        return None
    if not isinstance(v, list) or len(v) > MAX_FRAMES:
        raise DepthProtocolError(f"per-frame lists must have at most {MAX_FRAMES} entries")
    return [parse(item) for item in v]


def _intrinsics(v: Any) -> dict[str, float] | None:
    if v is None:
        return None
    if not isinstance(v, Mapping):
        raise DepthProtocolError("intrinsics must be an object")
    try:
        out = {k: float(v[k]) for k in ("fx", "fy", "cx", "cy")}
        for k in ("ref_width", "ref_height"):
            if v.get(k) is not None:
                out[k] = float(v[k])
    except (KeyError, TypeError, ValueError) as exc:
        raise DepthProtocolError("intrinsics needs numeric fx, fy, cx, cy") from exc
    return out


def parse_meta(raw: str | bytes | Mapping[str, Any]) -> dict[str, Any]:
    """Validate + normalise the `meta` part. Raises DepthProtocolError."""
    if isinstance(raw, (str, bytes, bytearray)):
        try:
            meta = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise DepthProtocolError(f"meta is not valid JSON: {exc}") from exc
    else:
        meta = dict(raw)
    if not isinstance(meta, dict):
        raise DepthProtocolError("meta must be a JSON object")
    attempt_id = meta.get("attempt_id")
    if not isinstance(attempt_id, str) or not attempt_id or len(attempt_id) > 128:
        raise DepthProtocolError("attempt_id must be a non-empty string")
    phase = str(meta.get("phase", "")).upper()
    if phase not in PHASES:
        raise DepthProtocolError(f"phase must be one of {PHASES}")
    depth_type = meta.get("depth_type")
    if depth_type not in DEPTH_TYPES:
        raise DepthProtocolError(f"depth_type must be one of {DEPTH_TYPES}")
    dtype = meta.get("dtype")
    if dtype not in DTYPES:
        raise DepthProtocolError(f"dtype must be one of {tuple(DTYPES)}")
    try:
        width, height = int(meta["width"]), int(meta["height"])
    except (KeyError, TypeError, ValueError) as exc:
        raise DepthProtocolError("width and height must be integers") from exc
    if width < 8 or height < 8 or width * height > MAX_PIXELS:
        raise DepthProtocolError(f"unsupported depth size {width}x{height}")
    accuracy = meta.get("accuracy", meta.get("depth_accuracy"))  # edge schema name / app alias
    if accuracy is None and isinstance(meta.get("device"), Mapping):
        accuracy = meta["device"].get("depth_accuracy")
    ts = meta.get("timestamps_ms") or []
    if not isinstance(ts, list):
        raise DepthProtocolError("timestamps_ms must be a list")
    norm = dict(meta)
    norm.update(
        attempt_id=attempt_id,
        phase=phase,
        depth_type=depth_type,
        dtype=dtype,
        width=width,
        height=height,
        intrinsics=_intrinsics(meta.get("intrinsics")),
        face_box_norm=_box(meta.get("face_box_norm")),
        landmarks_norm=_landmarks(meta.get("landmarks_norm")),
        face_box_norm_frames=_per_frame_list(meta.get("face_box_norm_frames"), _box),
        landmarks_norm_frames=_per_frame_list(meta.get("landmarks_norm_frames"), _landmarks),
        timestamps_ms=ts,
        depth_accuracy=accuracy if accuracy in ("absolute", "relative") else None,
    )
    return norm


def decode_frames(meta: Mapping[str, Any], blobs: Sequence[bytes]) -> np.ndarray:
    """Raw depth parts -> (N, H, W) float32 array (values as sent: metres or 1/m)."""
    if not blobs:
        raise DepthProtocolError("no depth_0 part")
    if len(blobs) > MAX_FRAMES:
        raise DepthProtocolError(f"at most {MAX_FRAMES} depth frames per upload")
    w, h, np_dtype = int(meta["width"]), int(meta["height"]), DTYPES[str(meta["dtype"])]
    expected = w * h * np.dtype(np_dtype).itemsize
    frames = []
    for i, blob in enumerate(blobs):
        if len(blob) != expected:
            raise DepthProtocolError(
                f"depth_{i} has {len(blob)} bytes, expected {expected} ({w}x{h} {meta['dtype']})"
            )
        frames.append(np.frombuffer(blob, dtype=np_dtype).reshape(h, w).astype(np.float32))
    return np.stack(frames)


@dataclass
class DepthResult:
    attempt_id: str
    phase: str
    signal: dict[str, Any]  # exactly SIGNAL_KEYS
    depth_m: np.ndarray | None = field(default=None, repr=False)  # fused metres, NaN invalid (memory only)
    face_box_norm: list[float] | None = None
    landmarks_norm: dict[str, list[float]] | None = None
    intrinsics: dict[str, float] | None = None
    accuracy: str | None = None
    n_frames: int = 0
    diag: dict[str, Any] = field(default_factory=dict)
    compute_ms: float = 0.0


def process_upload(
    meta_raw: str | bytes | Mapping[str, Any],
    blobs: Sequence[bytes],
    cfg: Any,
    *,
    template: np.ndarray | None = None,
    neutral: DepthResult | None = None,
) -> DepthResult:
    """Validate, decode and measure one upload.

    PASSIVE: D0-D4, M2 (+ M3 when `template` is given).
    CHALLENGE: the same measurements on the challenge frames, plus M1 against `neutral` (the PASSIVE
    DepthResult of the same attempt) when available; M1 fields stay None otherwise.
    Raises DepthProtocolError for malformed input; numeric failures yield available=False.
    """
    t0 = time.perf_counter()
    meta = parse_meta(meta_raw)
    stack = decode_frames(meta, blobs)
    algo = algo_params(cfg)
    diag: dict[str, Any] = {}
    try:  # fuse once (median of frames, metres); the checks then see one fused depth map
        depth_m: np.ndarray | None = (fuse_depth_mm(stack, meta["depth_type"], algo) / 1000.0).astype(
            np.float32
        )
    except ValueError:
        depth_m = None
    signal = compute_depth_checks(
        depth_m if depth_m is not None else stack,
        depth_type="depth" if depth_m is not None else meta["depth_type"],
        intrinsics=meta["intrinsics"],
        face_box_norm=meta["face_box_norm"],
        landmarks_norm=meta["landmarks_norm"],
        cfg=cfg,
        template=template,
        accuracy=meta["depth_accuracy"],
        diagnostics=diag,
    )
    if (
        meta["phase"] == "CHALLENGE"
        and neutral is not None
        and neutral.depth_m is not None
        and depth_m is not None
    ):
        m1_diag: dict[str, Any] = {}
        m1 = compute_m1(
            neutral.depth_m,
            stack,  # per frame, not fused: the expression may be in one frame only
            neutral.face_box_norm,
            neutral.landmarks_norm,
            depth_type="depth",
            depth_type_challenge=meta["depth_type"],
            intrinsics=neutral.intrinsics or meta["intrinsics"],
            cfg=cfg,
            face_box_norm_challenge=meta["face_box_norm_frames"] or meta["face_box_norm"],
            landmarks_norm_challenge=meta["landmarks_norm_frames"] or meta["landmarks_norm"],
            diagnostics=m1_diag,
        )
        signal.update({k: m1[k] for k in M1_KEYS})
        diag["m1"] = m1_diag
    if set(signal) != set(SIGNAL_KEYS):  # contract guard (DepthSignal is extra="forbid")
        signal = empty_signal(absolute=meta["depth_accuracy"] == "absolute")
    return DepthResult(
        attempt_id=meta["attempt_id"],
        phase=meta["phase"],
        signal=signal,
        depth_m=depth_m,
        face_box_norm=meta["face_box_norm"],
        landmarks_norm=meta["landmarks_norm"],
        intrinsics=meta["intrinsics"],
        accuracy=meta["depth_accuracy"],
        n_frames=int(stack.shape[0]),
        diag=diag,
        compute_ms=round((time.perf_counter() - t0) * 1000.0, 2),
    )


def parse_multipart(body: bytes, content_type: str) -> dict[str, tuple[dict[str, str], bytes]]:
    """Minimal multipart/form-data parser (stdlib only) for the calibration server / tests.

    Returns {part name: (headers incl. 'filename' if any, payload bytes)}.
    """
    marker = "boundary="
    idx = content_type.find(marker)
    if idx < 0:
        raise DepthProtocolError("multipart boundary missing")
    boundary = content_type[idx + len(marker) :].split(";")[0].strip().strip('"').encode()
    parts: dict[str, tuple[dict[str, str], bytes]] = {}
    for chunk in body.split(b"--" + boundary)[1:]:
        if chunk.startswith(b"--"):
            break
        chunk = chunk[2:] if chunk.startswith(b"\r\n") else chunk
        head, sep, payload = chunk.partition(b"\r\n\r\n")
        if not sep:
            continue
        payload = payload[:-2] if payload.endswith(b"\r\n") else payload
        headers: dict[str, str] = {}
        for line in head.decode("utf-8", "replace").split("\r\n"):
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
        name = None
        for item in headers.get("content-disposition", "").split(";"):
            k, _, v = item.strip().partition("=")
            if k in ("name", "filename"):
                headers[k] = v.strip('"')
                if k == "name":
                    name = v.strip('"')
        if name:
            parts[name] = (headers, payload)
    return parts


def encode_multipart(
    meta: Mapping[str, Any], depth_blobs: Sequence[bytes], rgb_jpeg: bytes | None = None
) -> tuple[bytes, str]:
    """Build the same multipart body DepthProbe sends. Returns (body, content_type)."""
    boundary = f"DepthProbe-{time.time_ns():x}"
    out = bytearray()

    def add(s: str) -> None:
        out.extend(s.encode())

    add(
        f'--{boundary}\r\nContent-Disposition: form-data; name="meta"\r\n'
        "Content-Type: application/json\r\n\r\n"
    )
    out.extend(json.dumps(meta, sort_keys=True).encode())
    add("\r\n")
    for i, blob in enumerate(depth_blobs):
        add(f'--{boundary}\r\nContent-Disposition: form-data; name="depth_{i}"; filename="depth_{i}.bin"\r\n')
        add("Content-Type: application/octet-stream\r\n\r\n")
        out.extend(blob)
        add("\r\n")
    if rgb_jpeg is not None:
        add(f'--{boundary}\r\nContent-Disposition: form-data; name="rgb_0"; filename="rgb_0.jpg"\r\n')
        add("Content-Type: image/jpeg\r\n\r\n")
        out.extend(rgb_jpeg)
        add("\r\n")
    add(f"--{boundary}--\r\n")
    return bytes(out), f"multipart/form-data; boundary={boundary}"


__all__ = [
    "DTYPES",
    "MAX_FRAMES",
    "PHASES",
    "DepthProtocolError",
    "DepthResult",
    "decode_frames",
    "encode_multipart",
    "parse_meta",
    "parse_multipart",
    "process_upload",
]
