"""Ensure the project-root .env has the secrets the cloud API needs. Never prints values.

    cloud/.venv/bin/python -m cloud.tools.ensure_env          # fill missing/empty keys only
    cloud/.venv/bin/python -m cloud.tools.ensure_env --check  # report present/missing, change nothing

Generated: CLOUD_API_KEY (hex 32 B), OTP_PEPPER (hex 32 B), CLOUD_DATA_KEY (Fernet key for TOTP seeds when
no KMS key is configured). Also pins CLOUD_AWS_REGION=us-east-1 (sandbox region). Existing non-empty
values are never touched. File mode is kept at 0600.
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENV = ROOT / ".env"


def _fernet_key() -> str:
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode()


GENERATORS = {
    "CLOUD_API_KEY": lambda: secrets.token_hex(32),
    "OTP_PEPPER": lambda: secrets.token_hex(32),
    "CLOUD_DATA_KEY": _fernet_key,
}
PLAIN = {"CLOUD_AWS_REGION": "us-east-1"}
REQUIRED_EXISTING = ("KIOSK_HMAC_KEY", "SCHEDULE_BUNDLE_HMAC_KEY", "ADMIN_TOKEN", "CARD_ID_PEPPER")


def _parse(lines: list[str]) -> dict[str, tuple[int, str]]:
    out = {}
    for i, raw in enumerate(lines):
        s = raw.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        out[k.strip()] = (i, v.split(" #", 1)[0].strip())
    return out


def main(argv: list[str]) -> int:
    check = "--check" in argv
    lines = ENV.read_text(encoding="utf-8").splitlines() if ENV.exists() else []
    kv = _parse(lines)
    changed = []
    for name in REQUIRED_EXISTING:
        state = "present" if kv.get(name, (0, ""))[1] else "MISSING (owned by lead/edge; not generated here)"
        print(f"{name}: {state}")
    for name, gen in {**GENERATORS, **{k: (lambda v=v: v) for k, v in PLAIN.items()}}.items():
        cur = kv.get(name)
        if cur and cur[1]:
            print(f"{name}: present")
            continue
        if check:
            print(f"{name}: missing")
            continue
        value = gen()
        if cur:
            lines[cur[0]] = f"{name}={value}"
        else:
            lines.append(f"{name}={value}")
        changed.append(name)
        print(f"{name}: generated")
    if changed and not check:
        ENV.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.chmod(ENV, 0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
