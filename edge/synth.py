"""Synthetic kiosk attempts for tests + the latency benchmark (NOT evaluation data).

Face: scikit-image `astronaut` (NASA portrait of Eileen Collins, public domain) placed on a 640x480
canvas. A colour flash is simulated as a multiplicative tint of the face (reflection model
I' = I * (1 + gain * (c - mean(c)))) applied with a display->camera lag. Frames are JPEG q=85.
"""

from __future__ import annotations

import json
import time
from typing import Any

import cv2
import numpy as np


def base_frame(shift_px: int = 0, size: tuple[int, int] = (640, 480)) -> np.ndarray:
    from skimage import data as skdata

    w, h = size
    src = cv2.cvtColor(skdata.astronaut(), cv2.COLOR_RGB2BGR)[0:300, 100:350]  # head + shoulders
    face = cv2.resize(src, (int(250 * h / 300), h), interpolation=cv2.INTER_CUBIC)  # face ~140 px wide
    canvas = np.full((h, w, 3), (96, 92, 88), np.uint8)
    fw = face.shape[1]
    x0 = int(np.clip((w - fw) // 2 + shift_px, 0, w - fw))
    canvas[:, x0 : x0 + fw] = face
    return canvas


def hex_bgr01(color: str) -> np.ndarray:
    c = color.lstrip("#")
    r, g, b = (int(c[i : i + 2], 16) / 255.0 for i in (0, 2, 4))
    return np.array([b, g, r])


def colour_at(seq: list[dict[str, Any]], t_rel_ms: float) -> str | None:
    for s in seq:
        if s["offset_ms"] <= t_rel_ms < s["offset_ms"] + s["duration_ms"]:
            return s["color"]
    return None


def tint(img: np.ndarray, color: str | None, gain: float) -> np.ndarray:
    if color is None:
        return img
    c = hex_bgr01(color)
    mult = 1.0 + gain * (c - c.mean())
    return np.clip(img.astype(np.float32) * mult[None, None, :], 0, 255).astype(np.uint8)


def jpeg(img: np.ndarray, quality: int = 85) -> bytes:
    ok, buf = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, quality])
    assert ok
    return buf.tobytes()


def make_attempt(
    session: dict[str, Any],
    *,
    n_frames: int = 5,
    lag_ms: float = 50.0,
    gain: float = 0.12,
    respond: bool = True,
    camera_label: str = "FaceTime HD Camera",
    now_ms: int | None = None,
) -> tuple[list[bytes], dict[str, Any]]:
    """Frames + FramesMeta for a /frames call answering `session` (session/start response)."""
    seq = session.get("flash_sequence") or []
    window = float(session.get("capture", {}).get("window_ms", 1000))
    start = int(now_ms if now_ms is not None else time.time() * 1000) - int(window) - 60
    face_lock = start - 120
    frame_t = [start + window * (i + 0.6) / n_frames for i in range(n_frames)]
    frames = []
    base = [base_frame(shift_px=(i % 3) - 1) for i in range(n_frames)]
    for i, t in enumerate(frame_t):
        col = colour_at(seq, t - start - lag_ms) if respond else None
        frames.append(jpeg(tint(base[i], col, gain)))
    # dense client ROI series at ~30 fps from the same reflection model (forehead/cheek mean colour)
    roi = base[0][110:250, 260:380].reshape(-1, 3).mean(axis=0)  # BGR, mid-face
    series = []
    for k in range(int(window / 33.3) + 1):
        t = start + k * 33.3
        col = colour_at(seq, t - start - lag_ms) if respond else None
        v = roi if col is None else np.clip(roi * (1.0 + gain * (hex_bgr01(col) - hex_bgr01(col).mean())), 0, 255)
        series.append({"t_ms": round(t, 1), "r": float(v[2]), "g": float(v[1]), "b": float(v[0])})
    meta = {
        "nonce": session["nonce"],
        "face_lock_at_ms": int(face_lock),
        "capture_started_at_ms": int(start),
        "frame_timestamps_ms": [int(t) for t in frame_t],
        "flash_events": [{"step_index": i, "color": s["color"], "shown_at_ms": start + s["offset_ms"]}
                         for i, s in enumerate(seq)],
        "chroma_series": series,
        "quality": {"face_count": 1, "iod_px": 90.0, "yaw_deg": 0.0, "pitch_deg": 0.0, "roll_deg": 0.0,
                    "blur_var": 200.0, "luma_mean": 120.0, "face_box": [0.3, 0.2, 0.4, 0.5]},
        "client_signals": {"camera_label": camera_label, "virtual_camera_suspected": False,
                           "device_count": 1, "track_settings": {"width": 640, "height": 480, "frameRate": 30},
                           "fps_measured": 30.0, "frame_interval_jitter_ms": 2.0, "exposure_locked": False},
        "blendshapes": {"mouthSmileLeft": 0.03, "mouthSmileRight": 0.03, "jawOpen": 0.02, "cheekPuff": 0.01},
    }
    return frames, meta


def multipart_files(frames: list[bytes], meta: dict[str, Any]) -> tuple[dict, dict]:
    files = {f"frame_{i}": (f"frame_{i}.jpg", b, "image/jpeg") for i, b in enumerate(frames)}
    return files, {"meta": json.dumps(meta)}


def main() -> None:
    """CLI for curl smoke tests: session/start JSON on stdin -> frame_*.jpg + meta.json in OUT_DIR."""
    import sys
    from pathlib import Path

    out = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/edge_attempt")
    out.mkdir(parents=True, exist_ok=True)
    session = json.loads(sys.stdin.read())
    frames, meta = make_attempt(session)
    for i, b in enumerate(frames):
        (out / f"frame_{i}.jpg").write_bytes(b)
    (out / "meta.json").write_text(json.dumps(meta))
    print(str(out))


if __name__ == "__main__":
    main()
