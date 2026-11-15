"""Measure client-side latency from this machine to the cloud API (keep-alive connection, like the edge).

    cloud/.venv/bin/python -m cloud.tools.latency --live --base https://<api> --n 20 --image /tmp/noface.jpg

GET /v1/health (public) and POST /v1/match with a NON-FACE JPEG (Rekognition answers "no face"). Reports
n, p50, p95 (nearest rank; with n=20 p95 is the 19th-smallest sample), min, max of client wall time, and
the server-side X-Latency-Ms. The first request (TCP + TLS setup) is reported separately. A non-local --base
needs --live (CIT-12).
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import statistics
import sys
import time
import uuid

from cloud.tools import targets
from cloud.tools.cloudclient import CloudClient


def pct(values: list[float], p: float) -> float:
    s = sorted(values)
    k = max(1, math.ceil(p / 100 * len(s)))
    return s[k - 1]


def summarize(name: str, wall: list[float], server: list[float]) -> dict:
    out = {"endpoint": name, "n": len(wall), "p50_ms": round(pct(wall, 50), 1), "p95_ms": round(pct(wall, 95), 1),
           "min_ms": round(min(wall), 1), "max_ms": round(max(wall), 1), "mean_ms": round(statistics.mean(wall), 1)}
    if server:
        out.update({"server_p50_ms": round(pct(server, 50), 1), "server_p95_ms": round(pct(server, 95), 1)})
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--image", required=True, help="non-face JPEG")
    ap.add_argument("--kiosk", default="KIOSK_MAIN_01")
    targets.add_live_flag(ap)
    a = ap.parse_args(argv)
    targets.require_target(a.base, live=a.live)
    c = CloudClient(a.base, a.kiosk)
    base = a.base.rstrip("/")
    img_b64 = base64.b64encode(open(a.image, "rb").read()).decode()

    t = time.perf_counter()
    first = c.http.get(base + "/v1/health")
    cold = (time.perf_counter() - t) * 1000
    hw, hs = [], []
    for _ in range(a.n):
        t = time.perf_counter()
        r = c.http.get(base + "/v1/health")
        hw.append((time.perf_counter() - t) * 1000)
        hs.append(float(r.headers.get("x-latency-ms", "nan")))
    mw, ms, statuses = [], [], []
    for _ in range(a.n):
        body = {"attempt_id": f"att_lat_{uuid.uuid4().hex[:10]}", "kiosk_id": a.kiosk, "image_b64": img_b64,
                "max_users": 2}
        t = time.perf_counter()
        r, _curl = c.request("POST", "/v1/match", json_body=body)
        mw.append((time.perf_counter() - t) * 1000)
        ms.append(float(r.headers.get("x-latency-ms", "nan")))
        try:
            j = r.json()
        except ValueError:
            j = {}
        statuses.append(f"{r.status_code}:{j.get('face_detected', j.get('error', {}).get('code'))}")
    print(json.dumps({
        "first_request_incl_tls_ms": round(cold, 1), "first_status": first.status_code,
        "image_bytes": len(base64.b64decode(img_b64)),
        "health": summarize("GET /v1/health", hw, hs),
        "match": summarize("POST /v1/match (non-face JPEG)", mw, ms),
        "match_status_counts": {s: statuses.count(s) for s in sorted(set(statuses))},
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
