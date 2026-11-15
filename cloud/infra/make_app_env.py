#!/usr/bin/env python3
"""Render the cloud app environment for EC2 (env file) or Lambda (--environment JSON). Stdlib only.

Secrets are read from the project-root .env and written ONLY to --out (mode 0600); nothing is printed
except key NAMES. Usage (called by deploy_ec2.sh / deploy_lambda.sh):
  make_app_env.py --out FILE --format env|lambda --face rekognition|disabled --store dynamodb|sqlite
                  --email ses|disabled --blob s3|disabled --metrics put_metric_data|emf_stdout --bucket NAME
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECRETS = ("KIOSK_HMAC_KEY", "SCHEDULE_BUNDLE_HMAC_KEY", "CLOUD_API_KEY", "ADMIN_TOKEN", "CARD_ID_PEPPER",
           "OTP_PEPPER", "CLOUD_DATA_KEY")
OPTIONAL = ("KIOSK_KEYS_JSON", "CLOUD_ADMIN_TOKEN", "KMS_KEY_ID")


def read_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        out[k.strip()] = v.split(" #", 1)[0].strip()
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--format", choices=["env", "lambda"], default="env")
    ap.add_argument("--face", default="rekognition")
    ap.add_argument("--store", default="dynamodb")
    ap.add_argument("--email", default="ses")
    ap.add_argument("--blob", default="s3")
    ap.add_argument("--metrics", default="put_metric_data")
    ap.add_argument("--bucket", default="")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--collection", default="hid-kiosk-users")
    ap.add_argument("--match-budget-ms", default="900")
    ap.add_argument("--seed-schedule", default="", help="e.g. config/schedule.demo.json (relative to the app root)")
    ap.add_argument("--ses-sender", default="", help="verified SES sender (overrides .env SES_SENDER)")
    a = ap.parse_args(argv)
    env = read_env(ROOT / ".env")
    missing = [k for k in SECRETS if not env.get(k)]
    if missing:
        print(f"missing in .env: {', '.join(missing)} (run cloud/.venv/bin/python -m cloud.tools.ensure_env)",
              file=sys.stderr)
        return 2
    sender = a.ses_sender or env.get("SES_SENDER", "")
    email = a.email
    if email == "ses" and (not sender or sender.endswith("@example.com")):
        print("SES_SENDER not set to a verified address -> EMAIL_BACKEND=disabled", file=sys.stderr)
        email = "disabled"
    blob = a.blob if a.bucket else "disabled"
    values = {k: env[k] for k in SECRETS}
    values.update({k: env[k] for k in OPTIONAL if env.get(k)})
    values.update({
        "CLOUD_AWS_REGION": a.region, "FACE_BACKEND": a.face,
        "LIVENESS_BACKEND": "rekognition" if a.face == "rekognition" else "disabled",
        "STORE_BACKEND": a.store, "EMAIL_BACKEND": email, "BLOB_BACKEND": blob, "METRICS_SINK": a.metrics,
        "REKOGNITION_COLLECTION_ID": a.collection, "DDB_TABLE_USERS": "hid_users",
        "DDB_TABLE_DECISIONS": "hid_decisions", "DDB_TABLE_STATE": "hid_state",
        "SQLITE_PATH": "/opt/hid/data/cloud.sqlite" if a.format == "env" else "/tmp/cloud.sqlite",  # noqa: S108
        "MATCH_BUDGET_MS": a.match_budget_ms, "CLOUD_LOAD_DOTENV": "0",
    })
    if a.bucket:
        values["S3_AUDIT_BUCKET"] = a.bucket
    if a.seed_schedule:
        values["SEED_SCHEDULE_PATH"] = a.seed_schedule
    if email == "ses":
        values["SES_SENDER"] = sender
    fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        if a.format == "env":
            fh.write("".join(f"{k}={v}\n" for k, v in values.items()))
        else:
            json.dump({"Variables": values}, fh)
    print("app env keys: " + ", ".join(sorted(values)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
