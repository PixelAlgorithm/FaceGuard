"""Mint a cloud API key (RBAC design v2 §E). Prints the key ONCE plus the JSON entry for CLOUD_API_KEYS_JSON.

    cloud/.venv/bin/python -m cloud.tools.apikey --name "ops laptop" --roles auditor --expires-days 30
    cloud/.venv/bin/python -m cloud.tools.apikey --name "edge main" --roles edge_proxy --kiosk-id KIOSK_MAIN_01
    ... --key-file /path/key.txt     # write the key to a NEW 0600 file instead of printing it

Key format: `fgk_<key_id>.<secret>` (edge/auth/tokens.py). The cloud stores only key_id + SHA-256(secret), so
the key cannot be recovered later: store it now (FG_CLOUD_ADMIN_KEY for the operator tools, CLOUD_EDGE_PROXY_KEY
on the edge for an edge_proxy key). Append the printed entry to the JSON list in CLOUD_API_KEYS_JSON (project
.env -> make_app_env -> SSM) and redeploy; revoke by removing the entry. Roles come from
edge/auth/rbac.py CLOUD_ROLES; an edge_proxy key must be bound to exactly one kiosk id.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime, timedelta

from edge.auth.rbac import CLOUD_ROLES, validate_roles
from edge.auth.tokens import new_api_key

EXIT_USAGE = 2
MAX_EXPIRES_DAYS = 365
KIOSK_ID_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")  # cloud/app/schemas.py ID


def _name_max() -> int:
    """cloud/app/rbac.py MAX_KEY_NAME (the cloud refuses longer names at startup); same constant as fallback."""
    try:
        from cloud.app.rbac import MAX_KEY_NAME
    except Exception:  # noqa: BLE001 - the operator tool also runs where the cloud app is not importable
        return 64
    return int(MAX_KEY_NAME)


NAME_MAX = _name_max()


def build_entry(name: str, roles: tuple[str, ...], kiosk_ids: list[str], expires_days: int | None,
                now: datetime) -> tuple[str, dict]:
    """(full key, CLOUD_API_KEYS_JSON entry). Raises ValueError on an invalid request."""
    if not name.strip() or len(name.strip()) > NAME_MAX:
        raise ValueError(f"--name must be 1-{NAME_MAX} chars (after trimming spaces)")
    roles = validate_roles(roles, CLOUD_ROLES)
    bad = [k for k in kiosk_ids if not KIOSK_ID_RE.fullmatch(k)]
    if bad:
        raise ValueError(f"invalid kiosk id(s): {', '.join(bad)}")
    if "edge_proxy" in roles and len(kiosk_ids) != 1:
        raise ValueError("an edge_proxy key must be bound to exactly one --kiosk-id")
    if expires_days is not None and not 1 <= expires_days <= MAX_EXPIRES_DAYS:
        raise ValueError(f"--expires-days must be 1..{MAX_EXPIRES_DAYS}")
    key_id, full, sha = new_api_key()
    entry: dict = {"key_id": key_id, "sha256": sha, "roles": list(roles), "name": name.strip()}
    if kiosk_ids:
        entry["kiosk_ids"] = list(kiosk_ids)
    if expires_days is not None:
        entry["expires_at"] = (now + timedelta(days=expires_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return full, entry


def _write_key_file(path: str, key: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(key + "\n")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True, help="who/what holds the key (shown in the audit)")
    ap.add_argument("--roles", action="append", required=True,
                    help=f"cloud role, repeatable or comma-separated: {', '.join(sorted(CLOUD_ROLES))}")
    ap.add_argument("--kiosk-id", action="append", default=[], help="bind to a kiosk (edge_proxy: exactly one)")
    ap.add_argument("--expires-days", type=int)
    ap.add_argument("--key-file", help="write the key to this NEW 0600 file instead of stdout")
    a = ap.parse_args(argv)
    roles = tuple(r.strip() for group in a.roles for r in group.split(",") if r.strip())
    try:
        key, entry = build_entry(a.name, roles, a.kiosk_id, a.expires_days, datetime.now(UTC))
    except ValueError as exc:
        print(f"apikey: {exc}", file=sys.stderr)
        return EXIT_USAGE
    holder = "CLOUD_EDGE_PROXY_KEY (edge .env)" if "edge_proxy" in entry["roles"] else "FG_CLOUD_ADMIN_KEY"
    if a.key_file:
        try:
            _write_key_file(a.key_file, key)
        except FileExistsError:
            print(f"apikey: {a.key_file} exists; refusing to overwrite", file=sys.stderr)
            return EXIT_USAGE
        print(f"key written to {a.key_file} (mode 0600) -> use it as {holder}")
    else:
        print(f"API key (shown ONCE; store it now as {holder}):")
        print(f"  {key}")
    print("CLOUD_API_KEYS_JSON entry (append to the JSON list in the cloud secret store, then redeploy):")
    print(json.dumps(entry, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
