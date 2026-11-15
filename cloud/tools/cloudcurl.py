"""Signed request to the cloud API; prints the equivalent curl command and the response.

    cloud/.venv/bin/python -m cloud.tools.cloudcurl GET /v1/health
    cloud/.venv/bin/python -m cloud.tools.cloudcurl --kiosk KIOSK_LIB_01 GET "/v1/revocations?since=0"
    cloud/.venv/bin/python -m cloud.tools.cloudcurl POST /v1/sync --data @/tmp/batch.json
    cloud/.venv/bin/python -m cloud.tools.cloudcurl --admin POST /v1/admin/revocations --data '{"target_id":"u_3c4d"}'

Base URL: --base or $CLOUD_API_URL or http://127.0.0.1:9000. Keys from env/.env (never printed: the
curl line uses $CLOUD_API_KEY / $ADMIN_TOKEN placeholders).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from cloud.tools.cloudclient import CloudClient


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("method")
    ap.add_argument("path")
    ap.add_argument("--base", default=os.environ.get("CLOUD_API_URL") or "http://127.0.0.1:9000")
    ap.add_argument("--kiosk", default=os.environ.get("KIOSK_ID") or "KIOSK_MAIN_01")
    ap.add_argument("--data", help="JSON string or @file")
    ap.add_argument("--admin", action="store_true", help="add X-Admin-Token")
    ap.add_argument("--header", action="append", default=[], help="extra 'Name: value'")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (self-signed fallback only)")
    ap.add_argument("--cafile", help="pinned CA/cert file for the self-signed fallback")
    a = ap.parse_args(argv)
    data_file = None
    body = None
    if a.data:
        if a.data.startswith("@"):
            data_file = a.data[1:]
            with open(data_file, "rb") as fh:
                body = fh.read()
        else:
            body = a.data.encode()
    extra = dict(h.split(": ", 1) for h in a.header)
    verify: bool | str = a.cafile or (not a.insecure)
    c = CloudClient(a.base, a.kiosk, verify=verify)
    resp, curl = c.request(a.method.upper(), a.path, content=body,
                           content_type="application/json" if body else None, admin=a.admin, headers=extra,
                           data_file=data_file)
    print("$ " + curl)
    print(f"HTTP {resp.status_code}  X-Latency-Ms: {resp.headers.get('x-latency-ms')}  "
          f"ETag: {resp.headers.get('etag')}")
    try:
        txt = json.dumps(resp.json(), indent=2)
    except ValueError:
        txt = resp.text
    print(txt if len(txt) < 6000 else txt[:6000] + "\n... (truncated)")
    return 0 if resp.status_code < 400 or resp.status_code == 304 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
