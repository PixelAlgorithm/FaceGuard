"""Target guard for the operator tools (CIT-12): scratch (loopback) targets by default, live needs --live.

Smoke / latency / cloudcurl runs against a deployed cloud write real ledger rows, reach Rekognition and SES and
count in the dashboards, so a remote base URL (e.g. a CLOUD_API_URL left in the shell) is refused unless the
operator passes --live explicitly.
"""

from __future__ import annotations

import argparse
import ipaddress
from urllib.parse import urlsplit

LOOPBACK_NAMES = frozenset({"localhost"})


def is_loopback(base: str) -> bool:
    host = (urlsplit(base).hostname or "").strip("[]").lower()
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def require_target(base: str, *, live: bool) -> str:
    """`base` when it is loopback or `live` is set; otherwise SystemExit with a clear message."""
    parts = urlsplit(base)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise SystemExit(f"bad base URL {base!r} (need http(s)://host[:port])")
    if not live and not is_loopback(base):
        raise SystemExit(f"refusing non-local target {parts.scheme}://{parts.hostname}: this writes to a live "
                         "cloud (ledger, Rekognition, SES, dashboards). Pass --live if that is intended, or use a "
                         "local cloud (uvicorn cloud.app.main:app on 127.0.0.1).")
    return base


def add_live_flag(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--live", action="store_true",
                    help="allow a non-local (deployed) target; writes real ledger rows / AWS calls")
