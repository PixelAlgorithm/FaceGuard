"""Signed request to the cloud API; prints the equivalent curl command and the (redacted) response.

    cloud/.venv/bin/python -m cloud.tools.cloudcurl GET /v1/health
    cloud/.venv/bin/python -m cloud.tools.cloudcurl --kiosk KIOSK_LIB_01 GET "/v1/revocations?since=0"
    cloud/.venv/bin/python -m cloud.tools.cloudcurl POST /v1/sync --data @/tmp/batch.json
    cloud/.venv/bin/python -m cloud.tools.cloudcurl --admin POST /v1/admin/revocations --data '{"target_id":"u_3c4d"}'
    cloud/.venv/bin/python -m cloud.tools.cloudcurl --live --base https://<api> --admin POST /v1/admin/codes/rotate \
        --data '{"staff_id":"s_guard01"}' --reveal-secrets /tmp/codes.json     # codes -> 0600 file, not stdout

Base URL: --base or $CLOUD_API_URL or http://127.0.0.1:9000; a non-local base needs --live. Keys from env/.env
(never printed: the curl line uses $CLOUD_API_KEY / $FG_CLOUD_ADMIN_KEY / $ADMIN_TOKEN placeholders). --admin
sends `Authorization: Bearer $FG_CLOUD_ADMIN_KEY` (legacy X-Admin-Token only with FG_ALLOW_LEGACY_ADMIN_TOKEN=1).
Response secrets (override codes, OTPs, outbox bodies, tokens) are masked; --reveal-secrets PATH writes the
full response to a NEW mode-0600 file instead.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from cloud.tools import redact, targets
from cloud.tools.cloudclient import CloudClient

MAX_PRINT = 6000


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("method")
    ap.add_argument("path")
    ap.add_argument("--base", default=os.environ.get("CLOUD_API_URL") or "http://127.0.0.1:9000")
    ap.add_argument("--kiosk", default=os.environ.get("KIOSK_ID") or "KIOSK_MAIN_01")
    ap.add_argument("--data", help="JSON string or @file")
    ap.add_argument("--admin", action="store_true", help="add the admin credential (Bearer FG_CLOUD_ADMIN_KEY)")
    ap.add_argument("--header", action="append", default=[], help="extra 'Name: value'")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (self-signed fallback only)")
    ap.add_argument("--cafile", help="pinned CA/cert file for the self-signed fallback")
    ap.add_argument("--reveal-secrets", metavar="PATH", help="write the unredacted response to a new 0600 file")
    targets.add_live_flag(ap)
    return ap


def _body(data: str | None) -> tuple[bytes | None, str | None]:
    if not data:
        return None, None
    if data.startswith("@"):
        with open(data[1:], "rb") as fh:
            return fh.read(), data[1:]
    return data.encode(), None


def main(argv: list[str]) -> int:
    a = _parser().parse_args(argv)
    targets.require_target(a.base, live=a.live)
    body, data_file = _body(a.data)
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
        raw = json.dumps(resp.json(), indent=2)
    except ValueError:
        raw = resp.text
    if a.reveal_secrets:
        path = redact.reveal_to_file(a.reveal_secrets, raw)
        print(f"(full response written to {path}, mode 0600; delete it after use)")
    txt = redact.redact_text(raw)
    print(txt if len(txt) < MAX_PRINT else txt[:MAX_PRINT] + "\n... (truncated)")
    return 0 if resp.status_code < 400 or resp.status_code == 304 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
