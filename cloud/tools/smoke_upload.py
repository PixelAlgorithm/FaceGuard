"""No-face smoke for PUT /v1/admin/schedule/{kiosk_id}: only REFUSALS are exercised, so nothing is stored.

  1. GET /v1/schedule/<kiosk> (current authoritative bundle, version V)
  2. same content re-signed with the bundle key, one field tampered AFTER signing -> expect 403 FORBIDDEN
  3. same content correctly re-signed as version V-1 (lower) -> expect 409 INVALID_STATE
  4. GET /v1/schedule/<kiosk> again -> ETag still "V"

    cloud/.venv/bin/python -m cloud.tools.smoke_upload --base https://<api>.execute-api.us-east-1.amazonaws.com

Keys come from env / project .env and are never printed (curl lines use $CLOUD_API_KEY / $ADMIN_TOKEN).
"""

from __future__ import annotations

import argparse
import copy
import os
import sys

from cloud.app.config import PROJECT_ROOT, load_dotenv
from cloud.tools.cloudclient import CloudClient, load_keys


def _resign(doc: dict, key: bytes, key_id: str) -> dict:
    from edge.offline.bundle import sign_bundle  # the operator's signer (same as scripts/sign_bundle.py)

    return sign_bundle({k: v for k, v in doc.items() if k != "signature"}, key, key_id=key_id)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", required=True)
    ap.add_argument("--kiosk", default="KIOSK_MAIN_01")
    a = ap.parse_args(argv)
    env = dict(os.environ)
    load_dotenv(PROJECT_ROOT / ".env", env)
    bundle_key = env["SCHEDULE_BUNDLE_HMAC_KEY"].encode("utf-8")
    c = CloudClient(a.base, a.kiosk, load_keys())
    path = f"/v1/admin/schedule/{a.kiosk}"
    ok = True

    r, _ = c.request("GET", f"/v1/schedule/{a.kiosk}")
    cur = r.json()
    v = int(cur["bundle_version"])
    key_id = (cur.get("signature") or {}).get("key_id") or "demo-k1"
    print(f"1. GET /v1/schedule/{a.kiosk} -> HTTP {r.status_code} ETag {r.headers.get('etag')}")
    ok &= r.status_code == 200

    tampered = _resign(cur, bundle_key, key_id)
    tampered["bundle_version"] = v + 100  # changed after signing -> HMAC no longer verifies
    r, curl = c.request("PUT", path, json_body=tampered, admin=True)
    err = (r.json().get("error") or {}) if r.headers.get("content-type", "").startswith("application/json") else {}
    print(f"2. PUT {path} tampered-after-signing -> HTTP {r.status_code} {err.get('code')}: {err.get('message')}")
    ok &= r.status_code == 403 and err.get("code") == "FORBIDDEN"

    lower = copy.deepcopy(cur)
    lower["bundle_version"] = v - 1
    lower = _resign(lower, bundle_key, key_id)
    r, curl = c.request("PUT", path, json_body=lower, admin=True)
    err = (r.json().get("error") or {}) if r.headers.get("content-type", "").startswith("application/json") else {}
    print(f"3. PUT {path} correctly signed v{v - 1} -> HTTP {r.status_code} {err.get('code')}: {err.get('message')}")
    ok &= r.status_code == 409 and err.get("code") == "INVALID_STATE"

    r, _ = c.request("GET", f"/v1/schedule/{a.kiosk}")
    print(f"4. GET /v1/schedule/{a.kiosk} -> HTTP {r.status_code} ETag {r.headers.get('etag')} (expect \"{v}\")")
    ok &= r.status_code == 200 and r.headers.get("etag") == f'"{v}"'
    print("\nSMOKE (upload refusals)", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
