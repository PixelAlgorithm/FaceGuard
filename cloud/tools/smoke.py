"""Done-criteria smoke test against a running cloud API (local or deployed):

  1. GET  /v1/health answers (public, fast)
  2. POST /v1/enroll a test user, then POST /v1/match finds that user
  3. POST /v1/sync accepts a batch, and the SAME batch replayed is reported as duplicates (idempotent)
  4. (optional --cleanup) DELETE /v1/enroll/<user> erasure

Local (FACE_BACKEND=fake):  cloud/.venv/bin/python -m cloud.tools.smoke
Deployed (Rekognition):     cloud/.venv/bin/python -m cloud.tools.smoke --live --base https://<api> \\
                              --user u_smoke_<name> --images ~/consented/frames/ --probe ~/consented/probe.jpg --cleanup
Real faces only of consenting team members; --cleanup deletes the Rekognition user + faces afterwards.
Every request is echoed as a curl command (secrets as $ENV placeholders). A non-local --base needs --live
(CIT-12: a CLOUD_API_URL left in the shell must never turn a local smoke into live traffic).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from cloud.tools import redact, targets
from cloud.tools.cloudclient import CloudClient, load_keys, sign_items
from cloud.tools.fakeimg import make_fake_jpeg


def show(title: str, resp, curl: str, *, body_note: str | None = None) -> dict:
    print(f"\n### {title}")
    print("$ " + curl if len(curl) < 900 else "$ " + curl[:900] + " ...(body elided)")
    if body_note:
        print(f"  ({body_note})")
    try:
        data = resp.json()
    except ValueError:
        data = {"raw": resp.text}
    print(f"HTTP {resp.status_code}  X-Latency-Ms: {resp.headers.get('x-latency-ms')}")
    print(json.dumps(redact.redact_json(data), indent=2)[:3000])
    return data


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default=os.environ.get("CLOUD_API_URL") or "http://127.0.0.1:9000")
    ap.add_argument("--kiosk", default="KIOSK_LIB_01")
    ap.add_argument("--user", default="u_smoke")
    ap.add_argument("--email", default="smoke@example.org")
    ap.add_argument("--images", help="dir of JPEG enrolment frames (real faces, consenting member)")
    ap.add_argument("--probe", help="JPEG probe for /v1/match (real face)")
    ap.add_argument("--cleanup", action="store_true")
    ap.add_argument("--cafile")
    targets.add_live_flag(ap)
    a = ap.parse_args(argv)
    targets.require_target(a.base, live=a.live)
    keys = load_keys(a.kiosk)
    c = CloudClient(a.base, a.kiosk, keys, verify=a.cafile or True)
    ok = True

    t = time.perf_counter()
    r, curl = c.request("GET", "/v1/health")
    h = show("1. health", r, curl, body_note=f"client round trip {int((time.perf_counter() - t) * 1000)} ms")
    ok &= r.status_code == 200 and h.get("status") in {"ok", "degraded"}

    if a.images:
        frames = [p.read_bytes() for p in sorted(Path(a.images).glob("*.jp*g"))][:5]
        probe = Path(a.probe).read_bytes() if a.probe else frames[-1]
    else:
        frames = [make_fake_jpeg(a.user, salt=f"f{i}") for i in range(3)]
        probe = make_fake_jpeg(a.user, salt="probe")
    enroll = {"user_id": a.user, "display_name": "Smoke Test", "email": a.email, "groups": ["student"],
              "consent": True, "consent_version": "2026-11-14.v1", "provision_totp": False,
              "images_b64": [base64.b64encode(f).decode() for f in frames]}
    r, curl = c.request("POST", "/v1/enroll", json_body=enroll)
    e = show("2a. enroll", r, curl, body_note=f"{len(frames)} frames, base64 elided in output")
    ok &= r.status_code == 201

    att = f"att_smoke_{uuid.uuid4().hex[:8]}"
    r, curl = c.request("POST", "/v1/match", json_body={
        "attempt_id": att, "kiosk_id": a.kiosk, "image_b64": base64.b64encode(probe).decode(), "max_users": 2})
    m = show("2b. match", r, curl)
    ok &= r.status_code == 200 and m.get("user_id") == a.user and m.get("matched") is True

    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    items = []
    for i, (dec, codes) in enumerate([("ALLOW", ["ACCESS_OK", "OFFLINE_MODE"]),
                                      ("DENY", ["SPOOF_DEVICE_DETECTED", "OFFLINE_MODE"])]):
        items.append({"attempt_id": f"{att}_{i}", "idempotency_key": f"{att}_{i}", "seq": i + 1,
                      "kiosk_id": a.kiosk, "ts_utc": now, "user_id": "u_3c4d" if dec == "ALLOW" else None,
                      "candidate_user_id": None if dec == "ALLOW" else "u_3c4d", "decision": dec,
                      "reason_codes": codes, "resolved_codes": [], "scores": {"pad": 0.93, "match": 0.72},
                      "fallback": None, "schedule_version": e.get("bundle_version") or 42,
                      "cache_state": "FRESH", "mode": "OFFLINE", "synthetic": True})
    body = {"kiosk_id": a.kiosk, "batch_id": f"b_{att}", "items": sign_items(items, keys["kiosk_key"])}
    fd, batch_file = tempfile.mkstemp(prefix="hid_smoke_batch_", suffix=".json")
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(body, separators=(",", ":")))
    r, curl = c.request("POST", "/v1/sync", json_body=body, data_file=batch_file)
    s1 = show("3a. sync batch", r, curl)
    r, curl = c.request("POST", "/v1/sync", json_body=body, data_file=batch_file)
    s2 = show("3b. sync SAME batch replayed", r, curl)
    ok &= len(s1.get("accepted", [])) == 2 and sorted(s2.get("duplicates", [])) == sorted(s1.get("accepted", []))
    ok &= s2.get("accepted") == []

    if a.cleanup:
        r, curl = c.request("DELETE", f"/v1/enroll/{a.user}")
        show("4. erase test user", r, curl)
        ok &= r.status_code == 200
    print("\nSMOKE", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
