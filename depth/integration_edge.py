"""Integration smoke test: depth/fake_probe.py -> edge-ml's real LAN listener -> depth/checks.py.

Runs edge-ml's FastAPI app in-process (temp data dir, liveness.depth.enabled=true in a temp copy of
config/thresholds.yaml, LAN listener on a free port), starts kiosk sessions and lets the fake phone
answer them over real HTTP. Not collected by pytest (it loads the edge models). Never prints the token.

    cd <project root> && PYTHONPATH=$PWD edge/.venv/bin/python depth/integration_edge.py
"""

from __future__ import annotations

import dataclasses
import os
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import numpy as np
import yaml

from depth import fake_probe
from depth.checks import classify

SCENES = ("flat", "bent", "face", "small_face")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _probe_async(base: str, scene: str, token: str, out: list[Any]) -> threading.Thread:
    def work() -> None:
        out.extend(fake_probe.run(base, scene=scene, count=1, wait_s=5, token=token, seed=3))

    t = threading.Thread(target=work)
    t.start()
    return t


def main() -> int:
    from fastapi.testclient import TestClient

    from edge.app import build_context, create_app
    from edge.config import PROJECT_ROOT, Settings, load_dotenv

    load_dotenv(PROJECT_ROOT / ".env")
    os.environ["EDGE_DATA_DIR"] = tempfile.mkdtemp(prefix="depth_it_data_")
    os.environ["EDGE_LAN_PORT"] = "0"
    th = yaml.safe_load((PROJECT_ROOT / "config" / "thresholds.yaml").read_text())
    th["liveness"]["depth"]["enabled"] = True
    cfg_path = Path(tempfile.mkdtemp(prefix="depth_it_cfg_")) / "thresholds.yaml"
    cfg_path.write_text(yaml.safe_dump(th))
    port = _free_port()
    settings = dataclasses.replace(Settings.from_env(), thresholds_path=cfg_path, lan_port=port)
    token = settings.depth_device_token
    if not token:
        print("DEPTH_DEVICE_TOKEN missing in .env")
        return 2
    base = f"http://127.0.0.1:{port}"
    start = {"kiosk_id": settings.kiosk_id, "client": {"camera_label": "FaceTime HD Camera"}}
    failures = 0
    with TestClient(create_app(lambda: build_context(settings))) as client:
        print("lan_status:", client.app.state.ctx.lan_status)
        for scene in SCENES:
            out: list[Any] = []
            t = _probe_async(base, scene, token, out)
            time.sleep(0.3)
            t0 = time.perf_counter()
            r = client.post("/v1/session/start", json=start)
            assert r.status_code == 201 and r.json()["depth_requested"] is True, r.text
            t.join(20)
            reply = out[0] if out else {}
            chk = reply.get("checks") or {}
            cls = classify(chk, th) if chk else {"overall": None, "codes": []}
            ms = 1000 * (time.perf_counter() - t0)
            print(
                f"{scene:10s} HTTP {reply.get('_http_status')} start->reply {ms:.0f} ms "
                f"d0={chk.get('d0_valid_ratio')} d1={chk.get('d1_plane_rms_mm')} "
                f"d2={chk.get('d2_quad_rms_mm')} "
                f"d3={chk.get('d3_nose_relief_mm')} d4={chk.get('d4_ipd_mm')} abs={chk.get('absolute')} "
                f"-> {cls['overall']} {cls['codes']}"
            )
            failures += (cls["overall"] == "PASS") != (scene == "face")
        jobs: list[Any] = []
        t = threading.Thread(target=lambda: jobs.append(fake_probe.poll_pending(base, 5, token)))
        t.start()
        time.sleep(0.3)
        client.post("/v1/session/start", json=start)
        t.join(10)
        body, ctype, meta = fake_probe.build_upload(jobs[0], scene="flat", rng=np.random.default_rng(0))
        body = body.replace(meta["depth_nonce"].encode(), b"dn_forged_forged_forged")
        req = urllib.request.Request(
            f"{base}/v1/depth/frames",
            data=body,
            method="POST",
            headers={"Content-Type": ctype, "X-Depth-Token": token},
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            print("forged nonce: ACCEPTED (bad)")
            failures += 1
        except urllib.error.HTTPError as exc:
            print("forged nonce: HTTP", exc.code)
            failures += exc.code != 403
    print("INTEGRATION", "OK" if failures == 0 else f"FAILED ({failures})")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
