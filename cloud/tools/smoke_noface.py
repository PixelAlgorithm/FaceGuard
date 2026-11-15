"""Deployed smoke test WITHOUT any face image (lead instruction: third-party faces are personal data).

  1. GET /v1/health (public) answers
  2. GET /v1/schedule/<kiosk> -> signature verified with the EDGE's verifier (edge.offline.bundle.verify_bundle),
     demo user entitled (u_prj1), demo card hashes recomputed (no placeholders), ETag/If-None-Match -> 304
  3. POST /v1/sync accepts a 2-item batch; the SAME batch replayed -> duplicates (idempotent)
  4. (only with --otp-email, after the SES identity is Verified) PUT contact for --otp-user + POST /v1/otp/send

    cloud/.venv/bin/python -m cloud.tools.smoke_noface --base https://<api>.execute-api.us-east-1.amazonaws.com
    ... --otp-user u_prj1 --otp-email studies.prajwalm@gmail.com     # step 4, after the verification click
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import UTC, datetime

from cloud.app.config import PROJECT_ROOT, load_dotenv
from cloud.tools.cloudclient import CloudClient, load_keys, sign_items


def show(title: str, resp, curl: str | None = None, body: dict | None = None) -> dict:
    print(f"\n### {title}")
    if curl:
        print("$ " + (curl if len(curl) < 700 else curl[:700] + " ...(body elided)"))
    data = body
    if data is None:
        try:
            data = resp.json()
        except ValueError:
            data = {"raw": resp.text[:300]}
    print(f"HTTP {resp.status_code}  X-Latency-Ms: {resp.headers.get('x-latency-ms')}  "
          f"ETag: {resp.headers.get('etag')}")
    print(json.dumps(data, indent=2)[:2500])
    return data


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", required=True)
    ap.add_argument("--kiosk", default="KIOSK_MAIN_01")
    ap.add_argument("--demo-user", default="u_prj1")
    ap.add_argument("--otp-user")
    ap.add_argument("--otp-email")
    ap.add_argument("--otp-only", action="store_true",
                    help="only the OTP step (writes no sync records to the live ledger)")
    a = ap.parse_args(argv)
    keys = load_keys()
    env = dict(os.environ)
    load_dotenv(PROJECT_ROOT / ".env", env)
    bundle_key = env["SCHEDULE_BUNDLE_HMAC_KEY"].encode("utf-8")
    c = CloudClient(a.base, a.kiosk, keys)
    ok = True

    if a.otp_only:
        return otp_step(c, a)
    r = c.http.get(a.base.rstrip("/") + "/v1/health")
    h = show("1. GET /v1/health (public)", r, f"curl -sS -i {a.base.rstrip('/')}/v1/health")
    ok &= r.status_code == 200 and h.get("rekognition") == "ok" and h.get("dynamodb") == "ok"

    from edge.offline.bundle import verify_bundle  # the kiosk's own verifier (policy-engine)

    r, curl = c.request("GET", f"/v1/schedule/{a.kiosk}")
    b = r.json()
    users = b.get("users") or {}
    summary = {"bundle_version": b.get("bundle_version"), "issued_at": b.get("issued_at"),
               "expires_at": b.get("expires_at"), "kiosks": list(b.get("kiosks") or {}),
               "zones": list(b.get("zones") or {}), "users": sorted(users),
               "signature": {k: v for k, v in (b.get("signature") or {}).items() if k != "canonicalization"},
               "edge_verify_bundle": verify_bundle(b, bundle_key),
               "demo_user_entitled": a.demo_user in users,
               "placeholder_card_hashes": sorted(u for u, v in users.items()
                                                 if "RECOMPUTED" in str((v.get("fallback") or {}).get("card_id_hash")))}
    show(f"2a. GET /v1/schedule/{a.kiosk} (signed bundle, summary)", r, curl, body=summary)
    ok &= r.status_code == 200 and summary["edge_verify_bundle"] and summary["demo_user_entitled"]
    ok &= not summary["placeholder_card_hashes"]
    r, curl = c.request("GET", f"/v1/schedule/{a.kiosk}", headers={"If-None-Match": f'"{b.get("bundle_version")}"'})
    print(f"\n### 2b. If-None-Match \"{b.get('bundle_version')}\" -> HTTP {r.status_code} (expect 304)")
    ok &= r.status_code == 304

    att = f"att_smoke_{uuid.uuid4().hex[:10]}"
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    items = [{"attempt_id": f"{att}_{i}", "idempotency_key": f"{att}_{i}", "seq": None, "kiosk_id": a.kiosk,
              "zone": None, "ts_utc": now, "user_id": a.demo_user if dec == "ALLOW" else None,
              "candidate_user_id": None if dec == "ALLOW" else a.demo_user, "decision": dec, "reason_codes": codes,
              "resolved_codes": [], "scores": {"pad": 0.93, "match": 0.72}, "fallback": None,
              "schedule_version": b.get("bundle_version"), "cache_state": "FRESH", "mode": "ONLINE",
              "synthetic": True}
             for i, (dec, codes) in enumerate([("ALLOW", ["ACCESS_OK"]), ("DENY", ["SPOOF_DEVICE_DETECTED"])])]
    body = {"kiosk_id": a.kiosk, "batch_id": f"b_{att}", "items": sign_items(items, keys["kiosk_key"])}
    r, curl = c.request("POST", "/v1/sync", json_body=body)
    s1 = show("3a. POST /v1/sync (2 items)", r, curl)
    r, curl = c.request("POST", "/v1/sync", json_body=body)
    s2 = show("3b. POST /v1/sync SAME batch replayed", r, curl)
    ok &= sorted(s1.get("accepted", [])) == sorted(i["attempt_id"] for i in items)
    ok &= s2.get("accepted") == [] and sorted(s2.get("duplicates", [])) == sorted(s1.get("accepted", []))

    if a.otp_email and a.otp_user:
        ok &= otp_step(c, a) == 0
    print("\nSMOKE (no faces)", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def otp_step(c: CloudClient, a) -> int:
    if not (a.otp_user and a.otp_email):
        print("--otp-user and --otp-email required")
        return 2
    r, curl = c.request("PUT", f"/v1/admin/users/{a.otp_user}/contact", admin=True, json_body={
        "display_name": "Operator", "email": a.otp_email, "consent": True, "consent_version": "2026-11-14.v1"})
    show(f"4a. PUT /v1/admin/users/{a.otp_user}/contact (no biometric data)", r, curl)
    ok = r.status_code == 200
    r, curl = c.request("POST", "/v1/otp/send", json_body={"attempt_id": f"att_smoke_otp_{uuid.uuid4().hex[:8]}",
                                                           "user_id": a.otp_user, "channel": "email"})
    o = show("4b. POST /v1/otp/send (SES e-mail)", r, curl)
    ok &= r.status_code == 201 and bool(o.get("otp_id"))
    print("\nOTP SMOKE", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
