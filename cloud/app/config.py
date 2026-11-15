"""Cloud API settings, loaded from environment variables (12-factor).

Local runs also read the project-root `.env` (never overriding variables that are already set).
Secrets are validated for presence at startup and are never logged or echoed.

Region: the hackathon sandbox only allows us-east-1 (production target: ap-south-1). The app reads
`CLOUD_AWS_REGION` and deliberately ignores `AWS_REGION`, which other tools on the laptop may set.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
APP_VERSION = "0.1.0"

_REQUIRED_SECRETS = ("SCHEDULE_BUNDLE_HMAC_KEY", "CLOUD_API_KEY")


class ConfigError(RuntimeError):
    """Raised when the environment is incomplete or inconsistent (fail fast at startup)."""


def load_dotenv(path: Path, environ: dict[str, str] | None = None) -> list[str]:
    """Minimal .env reader: KEY=VALUE lines, '#' comments; returns names it set (never values)."""
    env = os.environ if environ is None else environ
    if not path.is_file():
        return []
    set_names: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.split(" #", 1)[0].split("\t#", 1)[0].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in env:
            env[key] = value
            set_names.append(key)
    return set_names


def _bool(v: str | None, default: bool) -> bool:
    if v is None or v == "":
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _int(v: str | None, default: int) -> int:
    return default if v in (None, "") else int(v)


def _float(v: str | None, default: float) -> float:
    return default if v in (None, "") else float(v)


def _choice(name: str, v: str | None, default: str, allowed: set[str]) -> str:
    val = (v or default).strip().lower()
    if val not in allowed:
        raise ConfigError(f"{name}={val!r} not in {sorted(allowed)}")
    return val


@dataclass(frozen=True)
class Settings:
    # --- secrets (never logged) ---
    kiosk_hmac_key: str = field(repr=False)
    schedule_bundle_hmac_key: str = field(repr=False)
    cloud_api_key: str = field(repr=False)
    admin_token: str = field(repr=False)
    kiosk_keys: dict[str, str] = field(default_factory=dict, repr=False)
    card_id_pepper: str = field(default="", repr=False)
    otp_pepper: str = field(default="", repr=False)
    cloud_data_key: str = field(default="", repr=False)
    cloud_api_keys: tuple = field(default=(), repr=False)  # rbac.ApiKeyEntry entries (CLOUD_API_KEYS_JSON)
    # --- auth switches (design v2 §E; both default OFF in production) ---
    auth_legacy_admin_token: bool = False  # AUTH_LEGACY_ADMIN_TOKEN=1: accept X-Admin-Token (role admin)
    allow_shared_kiosk_key: bool = False  # ALLOW_SHARED_KIOSK_KEY=1: KIOSK_HMAC_KEY for kiosks not in KIOSK_KEYS_JSON
    accept_bare_path_sig: bool = False  # CLOUD_ACCEPT_BARE_PATH_SIG=1: transition only (signature without ?query)
    # --- environment ---
    region: str = "us-east-1"
    face_backend: str = "fake"  # rekognition | fake | disabled
    liveness_backend: str = "fake"  # rekognition | fake | disabled
    store_backend: str = "memory"  # dynamodb | sqlite | memory
    email_backend: str = "fake"  # ses | fake | disabled
    blob_backend: str = "memory"  # s3 | memory | disabled
    metrics_sink: str = "memory"  # emf_stdout | put_metric_data | memory | none
    secretbox: str = "auto"  # kms | fernet | none | auto
    # --- resource names ---
    collection_id: str = "hid-kiosk-users"
    ddb_table_users: str = "hid_users"
    ddb_table_decisions: str = "hid_decisions"
    ddb_table_state: str = "hid_state"
    s3_bucket: str = ""
    kms_key_id: str = ""
    ses_sender: str = ""
    sqlite_path: str = str(PROJECT_ROOT / "cloud" / "data" / "cloud.sqlite")
    metrics_namespace: str = "HIDKiosk"
    # --- behaviour ---
    thresholds_path: str = str(PROJECT_ROOT / "config" / "thresholds.yaml")
    seed_schedule_path: str = str(PROJECT_ROOT / "config" / "schedule.example.json")
    bundle_key_id: str = "demo-k1"
    bundle_ttl_hours: int = 12
    auth_skew_s: int = 60
    match_budget_ms: int = 900
    rekognition_search_tps: float = 5.0
    rekognition_compare_tps: float = 25.0
    liveness_tps: float = 5.0
    liveness_max_concurrent: int = 15
    max_body_bytes: int = 6 * 1024 * 1024
    decisions_ttl_days: int = 7
    alerts_ttl_days: int = 7
    enroll_store_reference: bool = False
    enroll_min_faces: int = 1
    enroll_max_faces_per_user: int = 24  # append cap (edge keeps 24 templates); Rekognition allows 100 per user
    enroll_pinned_faces: int = 5  # first faces (original enrolment) never evicted by the cap
    sync_require_item_hmac: bool = True
    sync_max_items: int = 50
    health_refresh_s: float = 15.0
    enable_docs: bool = False
    otp_resend_after_s: int = 30
    synthetic_attempt_prefixes: tuple[str, ...] = ("att_smoke_", "att_test_", "att_lat_")
    synthetic_kiosks: tuple[str, ...] = ()

    def key_for_kiosk(self, kiosk_id: str, known_kiosks: set[str]) -> str | None:
        """Per-kiosk HMAC key: explicit KIOSK_KEYS_JSON entry; the shared KIOSK_HMAC_KEY only for known kiosks and
        only with ALLOW_SHARED_KIOSK_KEY=1 (one leaked kiosk key would otherwise impersonate every kiosk)."""
        if kiosk_id in self.kiosk_keys:
            return self.kiosk_keys[kiosk_id]
        if self.allow_shared_kiosk_key and self.kiosk_hmac_key and kiosk_id in known_kiosks:
            return self.kiosk_hmac_key
        return None

    def public_summary(self) -> dict[str, object]:
        """Non-secret configuration for logs / health."""
        return {
            "region": self.region,
            "face_backend": self.face_backend,
            "liveness_backend": self.liveness_backend,
            "store_backend": self.store_backend,
            "email_backend": self.email_backend,
            "blob_backend": self.blob_backend,
            "metrics_sink": self.metrics_sink,
            "collection_id": self.collection_id,
        }


def _path(value: str | None, default: Path) -> str:
    """Relative paths (e.g. SEED_SCHEDULE_PATH=config/schedule.demo.json) resolve against the project root."""
    if not value:
        return str(default)
    p = Path(value)
    return str(p if p.is_absolute() else PROJECT_ROOT / p)


def settings_from_env(environ: dict[str, str] | None = None, *, load_env_file: bool = True) -> Settings:
    env = dict(os.environ) if environ is None else dict(environ)
    if load_env_file and _bool(env.get("CLOUD_LOAD_DOTENV"), True):
        load_dotenv(PROJECT_ROOT / ".env", env)

    legacy = _bool(env.get("AUTH_LEGACY_ADMIN_TOKEN"), False)
    shared = _bool(env.get("ALLOW_SHARED_KIOSK_KEY"), False)
    store_backend = _choice("STORE_BACKEND", env.get("STORE_BACKEND"), "memory", {"dynamodb", "sqlite", "memory"})
    missing = [k for k in _REQUIRED_SECRETS if not env.get(k)]
    if legacy and not (env.get("CLOUD_ADMIN_TOKEN") or env.get("ADMIN_TOKEN")):
        missing.append("ADMIN_TOKEN (required with AUTH_LEGACY_ADMIN_TOKEN=1)")
    if shared and not env.get("KIOSK_HMAC_KEY"):
        missing.append("KIOSK_HMAC_KEY (required with ALLOW_SHARED_KIOSK_KEY=1)")
    if store_backend != "memory" and not env.get("OTP_PEPPER"):
        # a per-process pepper on a persistent store: every OTP dies on restart / differs between workers
        missing.append("OTP_PEPPER (required unless STORE_BACKEND=memory)")
    if missing:
        raise ConfigError(f"missing required secrets (set in env or .env): {', '.join(missing)}")

    kiosk_keys: dict[str, str] = {}
    if env.get("KIOSK_KEYS_JSON"):
        try:
            parsed = json.loads(env["KIOSK_KEYS_JSON"])
        except json.JSONDecodeError as exc:
            raise ConfigError("KIOSK_KEYS_JSON is not valid JSON") from exc
        if not isinstance(parsed, dict) or not all(isinstance(v, str) and v for v in parsed.values()):
            raise ConfigError("KIOSK_KEYS_JSON must map kiosk_id -> non-empty key string")
        kiosk_keys = parsed
    if not kiosk_keys and not shared:
        raise ConfigError("no kiosk keys: set KIOSK_KEYS_JSON ({kiosk_id: key}) or ALLOW_SHARED_KIOSK_KEY=1 with "
                          "KIOSK_HMAC_KEY")
    from .rbac import parse_api_keys  # rbac imports this module

    api_keys = parse_api_keys(env.get("CLOUD_API_KEYS_JSON"))

    s = Settings(
        kiosk_hmac_key=env.get("KIOSK_HMAC_KEY", ""),
        schedule_bundle_hmac_key=env["SCHEDULE_BUNDLE_HMAC_KEY"],
        cloud_api_key=env["CLOUD_API_KEY"],
        admin_token=(env.get("CLOUD_ADMIN_TOKEN") or env.get("ADMIN_TOKEN") or "") if legacy else "",
        kiosk_keys=kiosk_keys,
        cloud_api_keys=api_keys,
        auth_legacy_admin_token=legacy,
        allow_shared_kiosk_key=shared,
        accept_bare_path_sig=_bool(env.get("CLOUD_ACCEPT_BARE_PATH_SIG"), False),
        card_id_pepper=env.get("CARD_ID_PEPPER", ""),
        otp_pepper=env.get("OTP_PEPPER", ""),
        cloud_data_key=env.get("CLOUD_DATA_KEY", ""),
        region=env.get("CLOUD_AWS_REGION") or "us-east-1",
        face_backend=_choice("FACE_BACKEND", env.get("FACE_BACKEND"), "fake", {"rekognition", "fake", "disabled"}),
        liveness_backend=_choice(
            "LIVENESS_BACKEND", env.get("LIVENESS_BACKEND"), "fake", {"rekognition", "fake", "disabled"}
        ),
        store_backend=store_backend,
        email_backend=_choice("EMAIL_BACKEND", env.get("EMAIL_BACKEND"), "fake", {"ses", "fake", "disabled"}),
        blob_backend=_choice("BLOB_BACKEND", env.get("BLOB_BACKEND"), "memory", {"s3", "memory", "disabled"}),
        metrics_sink=_choice(
            "METRICS_SINK", env.get("METRICS_SINK"), "memory", {"emf_stdout", "put_metric_data", "memory", "none"}
        ),
        secretbox=_choice("SECRETBOX", env.get("SECRETBOX"), "auto", {"kms", "fernet", "none", "auto"}),
        collection_id=env.get("REKOGNITION_COLLECTION_ID") or "hid-kiosk-users",
        ddb_table_users=env.get("DDB_TABLE_USERS") or "hid_users",
        ddb_table_decisions=env.get("DDB_TABLE_DECISIONS") or "hid_decisions",
        ddb_table_state=env.get("DDB_TABLE_STATE") or "hid_state",
        s3_bucket=env.get("S3_AUDIT_BUCKET", "") if "<" not in env.get("S3_AUDIT_BUCKET", "") else "",
        kms_key_id=env.get("KMS_KEY_ID", ""),
        ses_sender=env.get("SES_SENDER", ""),
        sqlite_path=env.get("SQLITE_PATH") or str(PROJECT_ROOT / "cloud" / "data" / "cloud.sqlite"),
        metrics_namespace=env.get("METRICS_NAMESPACE") or "HIDKiosk",
        thresholds_path=_path(env.get("THRESHOLDS_PATH"), PROJECT_ROOT / "config" / "thresholds.yaml"),
        seed_schedule_path=_path(env.get("SEED_SCHEDULE_PATH"), PROJECT_ROOT / "config" / "schedule.example.json"),
        bundle_key_id=env.get("SCHEDULE_BUNDLE_KEY_ID") or "demo-k1",
        bundle_ttl_hours=_int(env.get("BUNDLE_TTL_HOURS"), 12),
        auth_skew_s=_int(env.get("AUTH_SKEW_S"), 60),
        match_budget_ms=_int(env.get("MATCH_BUDGET_MS"), 900),
        rekognition_search_tps=_float(env.get("REKOGNITION_SEARCH_TPS"), 5.0),
        rekognition_compare_tps=_float(env.get("REKOGNITION_COMPARE_TPS"), 25.0),
        liveness_tps=_float(env.get("LIVENESS_TPS"), 5.0),
        liveness_max_concurrent=_int(env.get("LIVENESS_MAX_CONCURRENT"), 15),
        max_body_bytes=_int(env.get("MAX_BODY_BYTES"), 6 * 1024 * 1024),
        decisions_ttl_days=_int(env.get("DECISIONS_TTL_DAYS"), 7),
        alerts_ttl_days=_int(env.get("ALERTS_TTL_DAYS"), 7),
        enroll_store_reference=_bool(env.get("ENROLL_STORE_REFERENCE"), False),
        enroll_min_faces=_int(env.get("ENROLL_MIN_FACES"), 1),
        enroll_max_faces_per_user=_int(env.get("ENROLL_MAX_FACES_PER_USER"), 24),
        enroll_pinned_faces=_int(env.get("ENROLL_PINNED_FACES"), 5),
        sync_require_item_hmac=_bool(env.get("SYNC_REQUIRE_ITEM_HMAC"), True),
        sync_max_items=_int(env.get("SYNC_MAX_ITEMS"), 50),
        health_refresh_s=_float(env.get("HEALTH_REFRESH_S"), 15.0),
        enable_docs=_bool(env.get("CLOUD_ENABLE_DOCS"), False),
        otp_resend_after_s=_int(env.get("OTP_RESEND_AFTER_S"), 30),
        synthetic_attempt_prefixes=tuple(x for x in (env.get("SYNTHETIC_ATTEMPT_PREFIXES")
                                                     or "att_smoke_,att_test_,att_lat_").split(",") if x),
        synthetic_kiosks=tuple(x for x in (env.get("SYNTHETIC_KIOSKS") or "").split(",") if x),
    )
    if not (s.enroll_min_faces >= 1 and 0 <= s.enroll_pinned_faces < s.enroll_max_faces_per_user <= 100):
        raise ConfigError("need ENROLL_MIN_FACES >= 1 and 0 <= ENROLL_PINNED_FACES < ENROLL_MAX_FACES_PER_USER <= 100")
    if s.decisions_ttl_days > 7 or s.alerts_ttl_days > 7:
        raise ConfigError("retention must be <= 7 days (DECISIONS_TTL_DAYS / ALERTS_TTL_DAYS)")
    if s.blob_backend == "s3" and not s.s3_bucket:
        raise ConfigError("BLOB_BACKEND=s3 requires S3_AUDIT_BUCKET")
    if s.email_backend == "ses" and (not s.ses_sender or s.ses_sender.endswith("@example.com")):
        raise ConfigError("EMAIL_BACKEND=ses requires a verified SES_SENDER")
    return s
