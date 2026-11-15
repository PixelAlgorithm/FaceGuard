"""Fake DepthProbe: long-polls the edge like the iPhone app and uploads synthetic depth frames.

Lets the edge integration (GET /v1/depth/pending + POST /v1/depth/frames on the LAN listener,
EDGE_LAN_PORT, default 8001) be tested without the phone. Same wire format as depth/ios/DepthProbe
(see depth/protocol.py): X-Depth-Token header (DEPTH_DEVICE_TOKEN from the env / project .env, never
printed) and the per-attempt depth_nonce from /pending echoed in the upload meta.

    edge/.venv/bin/python -m depth.fake_probe --scene face --count 1          # http://127.0.0.1:8001
    edge/.venv/bin/python -m depth.fake_probe --scene flat --forever          # printed photo
Scenes: face, flat, flat_tilted, bent, small_face, mask_rigid, eyehole_mask, other_face
(CHALLENGE on "face" opens the mouth; on "mask_rigid" the head only moves rigidly).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any

import numpy as np

from depth import synth
from depth.protocol import encode_multipart
from depth.settings import device_token, lan_port

APP_VERSION = "fake-0.1.0"


def _request(
    url: str, *, data: bytes | None = None, headers: dict[str, str] | None = None, timeout: float = 30.0
):
    req = urllib.request.Request(
        url, data=data, headers=headers or {}, method="POST" if data is not None else "GET"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def poll_pending(edge: str, wait_s: float, token: str | None = None) -> dict[str, Any] | None:
    headers = {"X-Depth-Token": token} if token else {}
    status, body = _request(
        f"{edge}/v1/depth/pending?wait_s={wait_s:g}", headers=headers, timeout=wait_s + 10
    )
    if status == 204:
        return None
    if status != 200:
        raise RuntimeError(f"pending: HTTP {status}: {body[:200]!r}")
    return json.loads(body)


def build_upload(
    job: dict[str, Any],
    *,
    scene: str,
    rng: np.random.Generator,
    width: int = 320,
    height: int = 240,
    depth_type: str = "disparity",
    dtype: str = "float16",
    accuracy: str = "absolute",
) -> tuple[bytes, str, dict[str, Any]]:
    """Render 1-3 frames of `scene` for the job's phase -> (multipart body, content type, meta)."""
    cam = synth.SynthCamera(width, height)
    phase = str(job.get("phase", "PASSIVE")).upper()
    n = max(1, min(int(job.get("frames") or 1), 3))
    t0 = time.perf_counter()
    clean = synth.make_scene(scene, cam, rng, phase=phase, sigma_mm=0.0, hole_fraction=0.0)
    blobs = [synth.to_wire(synth.add_sensor_noise(clean.depth_m, rng), depth_type, dtype) for _ in range(n)]
    first = clean
    now = time.time() * 1000.0
    meta = {
        "attempt_id": job["attempt_id"],
        "phase": phase,
        "depth_type": depth_type,
        "dtype": dtype,
        "width": width,
        "height": height,
        "intrinsics": cam.intrinsics(640, 480),
        "face_box_norm": first.face_box_norm,
        "landmarks_norm": first.landmarks_norm,
        "timestamps_ms": [round(now - 33.3 * (n - 1 - i)) for i in range(n)],
        "device": "fake_probe",
        "accuracy": accuracy,
        "depth_accuracy": accuracy,
        "depth_filtered": False,
        "intrinsics_source": "synthetic",
        "capture_ms": round((time.perf_counter() - t0) * 1000.0),
        "app_version": APP_VERSION,
        "scene": scene,
    }
    if job.get("depth_nonce") is not None:
        meta["depth_nonce"] = job["depth_nonce"]
    if phase == "CHALLENGE":  # like DepthProbe: Vision result per challenge frame
        meta["face_box_norm_frames"] = [first.face_box_norm] * n
        meta["landmarks_norm_frames"] = [first.landmarks_norm] * n
    body, ctype = encode_multipart(meta, blobs)
    return body, ctype, meta


def run(
    edge: str,
    *,
    scene: str = "face",
    count: int | None = 1,
    wait_s: float = 20.0,
    token: str | None = None,
    seed: int | None = None,
    **upload_kw: Any,
) -> list[dict[str, Any]]:
    """Serve `count` attempts (None = forever). Returns the edge replies."""
    edge = edge.rstrip("/")
    rng = np.random.default_rng(seed)
    replies: list[dict[str, Any]] = []
    while count is None or len(replies) < count:
        try:
            job = poll_pending(edge, wait_s, token)
        except (OSError, RuntimeError) as exc:
            print(f"[fake_probe] edge unreachable: {exc}", file=sys.stderr)
            time.sleep(2.0)
            continue
        if job is None:
            continue
        body, ctype, meta = build_upload(job, scene=scene, rng=rng, **upload_kw)
        headers = {"Content-Type": ctype}
        if token:
            headers["X-Depth-Token"] = token
        t0 = time.perf_counter()
        status, reply = _request(f"{edge}/v1/depth/frames", data=body, headers=headers, timeout=15)
        ms = (time.perf_counter() - t0) * 1000.0
        try:
            parsed = json.loads(reply) if reply else {}
        except json.JSONDecodeError:
            parsed = {"raw": reply[:200].decode("utf-8", "replace")}
        parsed["_http_status"] = status
        replies.append(parsed)
        print(
            f"[fake_probe] {meta['attempt_id']} {meta['phase']} scene={scene} bytes={len(body)} "
            f"HTTP {status} {ms:.0f} ms -> {json.dumps(parsed.get('signal', parsed))[:300]}"
        )
    return replies


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--edge", default=f"http://127.0.0.1:{lan_port()}")
    ap.add_argument("--scene", default="face", choices=synth.SCENES)
    ap.add_argument("--count", type=int, default=1, help="attempts to serve (default 1)")
    ap.add_argument("--forever", action="store_true")
    ap.add_argument("--wait-s", type=float, default=20.0)
    ap.add_argument(
        "--token", default=None, help="default: DEPTH_DEVICE_TOKEN from env / .env (never printed)"
    )
    ap.add_argument("--width", type=int, default=320)
    ap.add_argument("--height", type=int, default=240)
    ap.add_argument("--depth-type", default="disparity", choices=("disparity", "depth"))
    ap.add_argument("--dtype", default="float16", choices=("float16", "float32"))
    ap.add_argument("--accuracy", default="absolute", choices=("absolute", "relative"))
    ap.add_argument("--seed", type=int, default=None)
    a = ap.parse_args(argv)
    token = a.token or device_token()
    if not token:
        print("[fake_probe] warning: no DEPTH_DEVICE_TOKEN; requests carry no X-Depth-Token", file=sys.stderr)
    run(
        a.edge,
        scene=a.scene,
        count=None if a.forever else a.count,
        wait_s=a.wait_s,
        token=token,
        seed=a.seed,
        width=a.width,
        height=a.height,
        depth_type=a.depth_type,
        dtype=a.dtype,
        accuracy=a.accuracy,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
