"""Ensure the project-root .env has the secrets the cloud API needs. Never prints values.

    cloud/.venv/bin/python -m cloud.tools.ensure_env          # fill missing/empty keys only
    cloud/.venv/bin/python -m cloud.tools.ensure_env --check  # report present/missing, change nothing else
    ... --env-file PATH                                        # another file (tests, a second stack)

Generated: CLOUD_API_KEY (hex 32 B), OTP_PEPPER (hex 32 B), CLOUD_DATA_KEY (Fernet key for TOTP seeds when
no KMS key is configured). Also pins CLOUD_AWS_REGION=us-east-1 (sandbox region). Existing non-empty
values are never touched. Reported, never generated: KIOSK_HMAC_KEY / KIOSK_KEYS_JSON, SCHEDULE_BUNDLE_HMAC_KEY,
CARD_ID_PEPPER, ADMIN_TOKEN (only needed with AUTH_LEGACY_ADMIN_TOKEN=1) and CLOUD_API_KEYS_JSON (mint keys with
`python -m cloud.tools.apikey`).

The file is parsed exactly like the edge/cloud loaders (cloud/tools/envfile.py); duplicate keys are refused.
Its mode is forced to 0600 on every run (also --check) and changes are written atomically (temp file in the
same directory, fsync, os.replace), so an interrupted run never truncates keys this tool cannot regenerate.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from collections.abc import Callable
from pathlib import Path

from cloud.tools import envfile

ROOT = Path(__file__).resolve().parents[2]
ENV = ROOT / ".env"
EXIT_CONFIG = 2


def _fernet_key() -> str:
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode()


GENERATORS: dict[str, Callable[[], str]] = {
    "CLOUD_API_KEY": lambda: secrets.token_hex(32),
    "OTP_PEPPER": lambda: secrets.token_hex(32),
    "CLOUD_DATA_KEY": _fernet_key,
}
PLAIN = {"CLOUD_AWS_REGION": "us-east-1"}
REPORTED = ("SCHEDULE_BUNDLE_HMAC_KEY", "CARD_ID_PEPPER")


DEFAULT_STORE_BACKEND = "memory"  # cloud/app/config.py settings_from_env default (pinned by a test)


def store_backend(env: dict[str, str]) -> str:
    """STORE_BACKEND as the cloud app reads it (strip + lower, app default when unset/empty)."""
    return (env.get("STORE_BACKEND") or DEFAULT_STORE_BACKEND).strip().lower()


def _report_existing(env: dict[str, str]) -> list[str]:
    lines = []
    store = store_backend(env)
    required = set(envfile.required_cloud_secrets(env, store))
    for name in (*REPORTED, "KIOSK_HMAC_KEY", "ADMIN_TOKEN"):
        if env.get(name):
            lines.append(f"{name}: present")
        elif name in required or name in REPORTED:
            lines.append(f"{name}: MISSING (owned by lead/edge; not generated here)")
        else:
            lines.append(f"{name}: absent (not required: "
                         + ("AUTH_LEGACY_ADMIN_TOKEN is off)" if name == "ADMIN_TOKEN"
                            else "ALLOW_SHARED_KIOSK_KEY is off)"))
    lines += [f"kiosk keys: MISSING - {p}" for p in envfile.kiosk_rule_problems(env)]
    lines.append(_api_keys_line(env))
    if env.get("KIOSK_KEYS_JSON"):
        probs = envfile.kiosk_keys_problems(env["KIOSK_KEYS_JSON"])
        lines.append("KIOSK_KEYS_JSON: " + ("; ".join(probs) if probs else "present"))
    return lines


def _api_keys_line(env: dict[str, str]) -> str:
    raw = env.get("CLOUD_API_KEYS_JSON", "")
    if not raw:
        return ("CLOUD_API_KEYS_JSON: absent (admin routes need it, or AUTH_LEGACY_ADMIN_TOKEN=1; "
                "mint with: python -m cloud.tools.apikey)")
    probs = envfile.api_key_entries_problems(raw)
    if probs:
        return "CLOUD_API_KEYS_JSON: INVALID - " + "; ".join(probs)
    return f"CLOUD_API_KEYS_JSON: present ({len(json.loads(raw))} key(s))"


def _fill(parsed: envfile.EnvFile, check: bool) -> tuple[list[str], list[str]]:
    lines = list(parsed.lines)
    changed: list[str] = []
    report: list[str] = []
    gens: dict[str, Callable[[], str]] = {**GENERATORS, **{k: (lambda v=v: v) for k, v in PLAIN.items()}}
    for name, gen in gens.items():
        if parsed.values.get(name):
            report.append(f"{name}: present")
            continue
        if check:
            report.append(f"{name}: missing")
            continue
        value = gen()
        idx = parsed.first_line.get(name)
        if idx is None:
            lines.append(f"{name}={value}")
        else:
            lines[idx] = f"{name}={value}"
        changed.append(name)
        report.append(f"{name}: generated")
    return (lines if changed else []), report


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--env-file", default=str(ENV))
    a = ap.parse_args(argv)
    path = Path(a.env_file)
    if envfile.enforce_private_mode(path):
        print(f"{path.name}: mode was group/other-readable -> fixed to 0600", file=sys.stderr)
    parsed = envfile.read_env_file(path)
    if parsed.duplicates:
        print(f"duplicate keys in {path.name} (first wins at runtime; remove the extra lines): "
              f"{', '.join(parsed.duplicates)}", file=sys.stderr)
        return EXIT_CONFIG
    for line in _report_existing(parsed.values):
        print(line)
    new_lines, report = _fill(parsed, a.check)
    for line in report:
        print(line)
    if new_lines:
        envfile.write_atomic(path, "\n".join(new_lines) + "\n")
    print(f"{path.name}: mode 0600")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
