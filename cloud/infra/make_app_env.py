#!/usr/bin/env python3
"""Render the cloud app environment for EC2 (env file) or Lambda (--environment JSON).

Secrets are read from the project-root .env (or --env-file) and written ONLY to --out (mode 0600); nothing is
printed except key NAMES. Usage (called by deploy_ec2.sh / deploy_lambda.sh):
  make_app_env.py --out FILE --format env|lambda --face rekognition|disabled --store dynamodb|sqlite
                  --email ses|disabled --blob s3|disabled --metrics put_metric_data|emf_stdout --bucket NAME
                  --seed-schedule config/<file>.json [--demo] [--ddb-users T --ddb-decisions T --ddb-state T]
  make_app_env.py --resolve-sender [--ses-sender ADDR]     # prints the effective SES sender (or nothing)
  make_app_env.py --health-event FILE                      # API Gateway v2 event for GET /v1/health
  make_app_env.py --check-health-response FILE             # exit 0 iff a Lambda response has statusCode 200

Rules (CIT-05/14, RBAC design v2 §E):
- the .env is parsed with the edge's semantics (cloud/tools/envfile.py); duplicate keys and values the cloud
  loader would read differently are refused, so the deployed cloud never gets a different secret than the edge;
- test backends (fake / memory) cannot be deployed; table names are arguments (per stack);
- the seed schedule is mandatory; demo content (placeholder card hashes, demo-card users) needs --demo;
- ADMIN_TOKEN is shipped only with AUTH_LEGACY_ADMIN_TOKEN=1; CLOUD_API_KEYS_JSON / KIOSK_KEYS_JSON are
  validated before they are shipped; OTP_PEPPER is required (deployed stores are persistent);
- EC2 env lines are single-quoted (systemd EnvironmentFile keeps JSON values verbatim that way);
- the rendered values are validated by the cloud's own startup check (cloud/app/config.py settings_from_env,
  which also runs cloud/app/rbac.py parse_api_keys) when cloud.app is importable, so a deploy the cloud would
  refuse to start is refused here (CI-02/05); the structural checks above remain the fallback;
- --format lambda refuses a Variables JSON over Lambda's 4 KB environment limit.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cloud.tools import envfile  # noqa: E402

ALWAYS = ("CARD_ID_PEPPER", "CLOUD_DATA_KEY")
FORWARDED_IF_SET = ("KIOSK_HMAC_KEY", "KIOSK_KEYS_JSON", "ALLOW_SHARED_KIOSK_KEY", "CLOUD_API_KEYS_JSON",
                    "AUTH_LEGACY_ADMIN_TOKEN", "SCHEDULE_BUNDLE_KEY_ID", "SYNTHETIC_KIOSKS",
                    "CLOUD_ACCEPT_BARE_PATH_SIG")  # transition flag, default off in the app
LEGACY_ONLY = ("ADMIN_TOKEN", "CLOUD_ADMIN_TOKEN")
EXIT_CONFIG = 2
DEMO_PLACEHOLDER = "RECOMPUTED"
LAMBDA_ENV_MAX_BYTES = 4096  # AWS Lambda: total size of all environment variables
HEALTH_PATH = "/v1/health"


def _cloud_settings_check():  # noqa: ANN202 - Callable[[dict[str, str]], object] | None
    """cloud.app.config.settings_from_env bound to load_env_file=False, or None when the app (or the edge.auth
    modules rbac needs) is not importable under this interpreter."""
    try:
        from cloud.app import config as cloud_config
        from cloud.app import rbac  # noqa: F401 - settings_from_env imports it lazily; fail here instead
    except (ImportError, RuntimeError):
        return None
    return lambda values: cloud_config.settings_from_env(values, load_env_file=False)


def _cloud_api_key_problems(raw: str) -> list[str]:
    """cloud/app/rbac.py parse_api_keys verdict (the parser the cloud runs at startup), when importable."""
    try:
        from cloud.app.config import ConfigError
        from cloud.app.rbac import parse_api_keys
    except (ImportError, RuntimeError):
        return []
    try:
        parse_api_keys(raw)
    except ConfigError as exc:
        return [f"cloud rbac: {exc}"]
    return []


def _settings_problems(values: dict[str, str]) -> list[str]:
    """Why the cloud would refuse to start with `values` (messages never contain values)."""
    check = _cloud_settings_check()
    if check is None:
        print("note: cloud.app not importable under this interpreter -> structural checks only "
              "(run with cloud/.venv/bin/python for the full startup check)", file=sys.stderr)
        return []
    if "<" in values.get("S3_AUDIT_BUCKET", ""):  # PLAN mode: bucket name holds <ACCOUNT_ID>; config drops it
        values = {**values, "S3_AUDIT_BUCKET": "plan-placeholder-bucket"}
    try:
        check(values)
    except Exception as exc:  # noqa: BLE001 - every startup failure blocks the deploy
        from cloud.app.config import ConfigError

        if isinstance(exc, ConfigError):
            return [f"the cloud would refuse to start: {exc}"]
        return [f"the cloud would refuse to start: {type(exc).__name__} while parsing settings "
                "(check numeric / boolean values)"]
    return []


def health_event() -> dict:
    """API Gateway HTTP API (payload 2.0) event for GET /v1/health, as Mangum expects it."""
    return {
        "version": "2.0", "routeKey": "$default", "rawPath": HEALTH_PATH, "rawQueryString": "",
        "headers": {"host": "deploy-check.invalid", "user-agent": "hid-deploy-check", "accept": "application/json"},
        "requestContext": {
            "accountId": "anonymous", "apiId": "deploycheck", "domainName": "deploy-check.invalid",
            "domainPrefix": "deploy-check", "requestId": "hid-deploy-check", "routeKey": "$default",
            "stage": "$default", "time": "01/Jan/2026:00:00:00 +0000", "timeEpoch": 1767225600000,
            "http": {"method": "GET", "path": HEALTH_PATH, "protocol": "HTTP/1.1", "sourceIp": "127.0.0.1",
                     "userAgent": "hid-deploy-check"},
        },
        "isBase64Encoded": False,
    }


def health_response_ok(path: Path) -> bool:
    """True iff the Lambda invoke output is an HTTP response with statusCode 200 (body never printed)."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(doc, dict) and type(doc.get("statusCode")) is int and doc["statusCode"] == 200


def _cloud_roles() -> frozenset[str] | None:
    try:
        from edge.auth.rbac import CLOUD_ROLES
    except Exception:  # noqa: BLE001 - stdlib-only fallback: structural checks still run
        return None
    return frozenset(CLOUD_ROLES)


def _demo_card_users() -> set[str]:
    path = ROOT / "scripts" / "sign_bundle.py"
    spec = importlib.util.spec_from_file_location("hid_sign_bundle_check", path)
    if spec is None or spec.loader is None:
        return set()
    try:
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except Exception:  # noqa: BLE001 - placeholder check below still refuses demo seeds
        return set()
    return set(getattr(mod, "DEMO_CARDS", {}).values())


def seed_problems(doc: dict, *, demo_ok: bool) -> list[str]:
    """Why a seed schedule must not be deployed without --demo (empty list = acceptable)."""
    if demo_ok:
        return []
    users = doc.get("users") or {}
    out = []
    placeholders = sorted(u for u, v in users.items()
                          if DEMO_PLACEHOLDER in str(((v or {}).get("fallback") or {}).get("card_id_hash", "")))
    if placeholders:
        out.append(f"placeholder demo card hashes for {', '.join(placeholders)}")
    demo_users = sorted(set(users) & _demo_card_users())
    if demo_users:
        out.append(f"users with publicly documented demo cards: {', '.join(demo_users)}")
    return out


def _check_seed(rel: str, demo_ok: bool) -> list[str]:
    p = Path(rel)
    if p.is_absolute() or p.parts[:1] != ("config",) or ".." in p.parts:
        return [f"--seed-schedule must be a file under config/ (shipped in the artifact), got {rel}"]
    full = ROOT / p
    if not full.is_file():
        return [f"--seed-schedule {rel} does not exist"]
    try:
        doc = json.loads(full.read_text(encoding="utf-8"))
    except ValueError:
        return [f"--seed-schedule {rel} is not valid JSON"]
    probs = seed_problems(doc, demo_ok=demo_ok)
    return [f"seed {rel} contains demo data ({'; '.join(probs)}): pass --demo to deploy it"] if probs else []


def _env_problems(parsed: envfile.EnvFile, store: str) -> list[str]:
    env = parsed.values
    out = []
    if parsed.duplicates:
        out.append(f"duplicate keys in .env (first wins at runtime; remove the extra lines): "
                   f"{', '.join(parsed.duplicates)}")
    if parsed.ambiguous:
        out.append(f".env values the edge and cloud loaders read differently (unquote them / drop inline "
                   f"comments / drop 'export'): {', '.join(parsed.ambiguous)}")
    missing = [k for k in (*envfile.required_cloud_secrets(env, store), *ALWAYS) if not env.get(k)]
    if missing:
        out.append(f"missing in .env: {', '.join(missing)} (run cloud/.venv/bin/python -m cloud.tools.ensure_env)")
    if env.get("CLOUD_API_KEYS_JSON"):
        out += envfile.api_key_entries_problems(env["CLOUD_API_KEYS_JSON"], known_roles=_cloud_roles())
        out += _cloud_api_key_problems(env["CLOUD_API_KEYS_JSON"])
    if env.get("KIOSK_KEYS_JSON"):
        out += envfile.kiosk_keys_problems(env["KIOSK_KEYS_JSON"])
    out += envfile.kiosk_rule_problems(env)
    return out


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--env-file", default=os.environ.get("HID_ENV_FILE") or str(ROOT / ".env"))
    ap.add_argument("--format", choices=["env", "lambda"], default="env")
    ap.add_argument("--face", choices=["rekognition", "disabled"], default="rekognition")
    ap.add_argument("--store", choices=["dynamodb", "sqlite"], default="dynamodb")
    ap.add_argument("--email", choices=["ses", "disabled"], default="ses")
    ap.add_argument("--blob", choices=["s3", "disabled"], default="s3")
    ap.add_argument("--metrics", choices=["put_metric_data", "emf_stdout"], default="put_metric_data")
    ap.add_argument("--bucket", default="")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--collection", default="hid-kiosk-users")
    ap.add_argument("--ddb-users", default="hid_users")
    ap.add_argument("--ddb-decisions", default="hid_decisions")
    ap.add_argument("--ddb-state", default="hid_state")
    ap.add_argument("--kms-key-id", default="", help="CMK from data_plane.sh --with-cmk (state KMS_KEY_ID)")
    ap.add_argument("--deploy-stamp", default="", help="echoed by /v1/health as deploy_stamp (cutover check)")
    ap.add_argument("--match-budget-ms", default="900")
    ap.add_argument("--seed-schedule", default="", help="config/<file>.json (relative to the app root)")
    ap.add_argument("--demo", action="store_true", help="allow demo seed content (documented demo cards)")
    ap.add_argument("--ses-sender", default="", help="verified SES sender (overrides .env SES_SENDER)")
    ap.add_argument("--resolve-sender", action="store_true", help="print the effective SES sender and exit")
    ap.add_argument("--health-event", help="write the GET /v1/health API Gateway v2 test event to this file")
    ap.add_argument("--check-health-response", help="exit 0 iff this Lambda invoke output has statusCode 200")
    return ap


def _sender(a: argparse.Namespace, env: dict[str, str]) -> str:
    sender = a.ses_sender or env.get("SES_SENDER", "")
    return "" if not sender or sender.endswith("@example.com") else sender


def _values(a: argparse.Namespace, env: dict[str, str], email: str, sender: str) -> dict[str, str]:
    store = a.store
    values = {k: env[k] for k in (*envfile.required_cloud_secrets(env, store), *ALWAYS) if env.get(k)}
    values.update({k: env[k] for k in FORWARDED_IF_SET if env.get(k)})
    if envfile.flag_on(env, "AUTH_LEGACY_ADMIN_TOKEN"):
        values.update({k: env[k] for k in LEGACY_ONLY if env.get(k)})
    blob = a.blob if a.bucket else "disabled"
    values.update({
        "CLOUD_AWS_REGION": a.region, "FACE_BACKEND": a.face,
        "LIVENESS_BACKEND": "rekognition" if a.face == "rekognition" else "disabled",
        "STORE_BACKEND": store, "EMAIL_BACKEND": email, "BLOB_BACKEND": blob, "METRICS_SINK": a.metrics,
        "REKOGNITION_COLLECTION_ID": a.collection, "DDB_TABLE_USERS": a.ddb_users,
        "DDB_TABLE_DECISIONS": a.ddb_decisions, "DDB_TABLE_STATE": a.ddb_state,
        "SQLITE_PATH": "/opt/hid/data/cloud.sqlite" if a.format == "env" else "/tmp/cloud.sqlite",  # noqa: S108
        "MATCH_BUDGET_MS": a.match_budget_ms, "CLOUD_LOAD_DOTENV": "0",
        "SEED_SCHEDULE_PATH": a.seed_schedule,
    })
    if a.bucket:
        values["S3_AUDIT_BUCKET"] = a.bucket
    if a.kms_key_id:
        values["KMS_KEY_ID"] = a.kms_key_id
    if a.deploy_stamp:
        values["HID_DEPLOY_STAMP"] = a.deploy_stamp
    if email == "ses":
        values["SES_SENDER"] = sender
    return values


def _render(values: dict[str, str], fmt: str) -> str:
    if fmt == "lambda":
        text = json.dumps({"Variables": values}, separators=(",", ":"))
        size = len(json.dumps(values, separators=(",", ":")).encode("utf-8"))
        if size > LAMBDA_ENV_MAX_BYTES:
            raise ValueError(f"Lambda environment would be {size} bytes, over the {LAMBDA_ENV_MAX_BYTES}-byte "
                             "(4 KB) limit: ship fewer CLOUD_API_KEYS_JSON / KIOSK_KEYS_JSON entries, move the "
                             "secrets to Secrets Manager / SSM, or deploy on EC2 (deploy_ec2.sh)")
        return text
    bad = [k for k, v in values.items() if "'" in v or "\n" in v or "\r" in v]
    if bad:
        raise ValueError(f"values with quotes/newlines cannot be shipped safely: {', '.join(bad)}")
    return "".join(f"{k}='{v}'\n" for k, v in values.items())


def main(argv: list[str]) -> int:
    a = _parser().parse_args(argv)
    if a.health_event:
        fd = os.open(a.health_event, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(health_event(), fh)
        return 0
    if a.check_health_response:
        return 0 if health_response_ok(Path(a.check_health_response)) else 1
    parsed = envfile.read_env_file(Path(a.env_file))
    env = parsed.values
    sender = _sender(a, env)
    if a.resolve_sender:
        print(sender)
        return 0
    if not a.out:
        print("--out is required", file=sys.stderr)
        return EXIT_CONFIG
    problems = _env_problems(parsed, a.store)
    problems += ([] if a.seed_schedule else ["--seed-schedule config/<file>.json is required (or --demo in the "
                                               "deploy script)"])
    if a.seed_schedule:
        problems += _check_seed(a.seed_schedule, a.demo)
    if problems:
        print("\n".join(f"make_app_env: {p}" for p in problems), file=sys.stderr)
        return EXIT_CONFIG
    email = a.email
    if email == "ses" and not sender:
        print("SES_SENDER not set to a verified address -> EMAIL_BACKEND=disabled", file=sys.stderr)
        email = "disabled"
    if not env.get("CLOUD_API_KEYS_JSON") and not envfile.flag_on(env, "AUTH_LEGACY_ADMIN_TOKEN"):
        print("note: no CLOUD_API_KEYS_JSON and AUTH_LEGACY_ADMIN_TOKEN off -> admin routes refuse every caller "
              "(mint keys with: cloud/.venv/bin/python -m cloud.tools.apikey)", file=sys.stderr)
    values = _values(a, env, email, sender)
    problems = _settings_problems(values)
    if problems:
        print("\n".join(f"make_app_env: {p}" for p in problems), file=sys.stderr)
        return EXIT_CONFIG
    try:
        text = _render(values, a.format)
    except ValueError as exc:
        print(f"make_app_env: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    print("app env keys: " + ", ".join(sorted(values)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
