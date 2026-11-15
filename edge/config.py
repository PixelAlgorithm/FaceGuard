"""Edge configuration: thresholds from config/thresholds.yaml (the only source of numbers) + .env.

Secrets are read from the environment / project `.env` and are never logged or returned.
"""

from __future__ import annotations

import ipaddress
import os
import re
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EDGE_VERSION = "0.1.0"
_REQUIRED = object()


_INLINE_COMMENT = re.compile(r"\s+#.*$")


def parse_env_value(value: str) -> str:
    """Quoted values keep everything inside the quotes; unquoted values drop ' # comment' tails."""
    v = value.strip()
    if len(v) >= 2 and v[0] in "\"'":
        end = v.find(v[0], 1)
        return v[1:end] if end > 0 else v[1:]
    if v.startswith("#"):
        return ""
    return _INLINE_COMMENT.sub("", v).strip()


def load_dotenv(path: Path, *, override: bool = False) -> None:
    """Minimal .env loader (KEY=VALUE, '#' comments incl. inline). Existing env vars win."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        if key and (override or key not in os.environ):
            os.environ[key] = parse_env_value(value)


class ConfigError(ValueError):
    """A setting that must stop the edge from starting (named in the message; never a secret value)."""


TRUTHY = frozenset({"1", "true", "yes"})
# F3: the main API answers only these Host headers (DNS rebinding). EDGE_EXTRA_ALLOWED_HOSTS may add exact host
# names (tests: "testserver"); a wildcard is refused.
LOOPBACK_HOSTS: tuple[str, ...] = ("127.0.0.1", "localhost", "[::1]")
_HOSTNAME = re.compile(r"^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]{1,253})$")


def _flag(env: Any, name: str, default: str = "0") -> bool:
    return str(env.get(name, default)).strip().lower() in TRUTHY


def is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    h = host.strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def validate_cloud_url(url: str, *, demo_mode: bool) -> str:
    """EAE-07: the cloud URL must be https://, except a loopback host or DEMO_MODE=1 (scratch / demo stacks).
    Empty = cloud not configured. Raises ConfigError otherwise. Shared with the policy runtime's client."""
    url = url.strip().rstrip("/")
    if not url:
        return ""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError("CLOUD_API_URL must be an http(s) URL with a host")
    if parts.scheme == "http" and not (demo_mode or is_loopback_host(parts.hostname)):
        raise ConfigError("CLOUD_API_URL must use https:// (plain http only for a loopback host or DEMO_MODE=1): "
                          "the kiosk HMAC, API key, admin credential and OTP codes would travel in cleartext")
    return url


def cloud_tls_verify(ca_file: str | Path | None) -> ssl.SSLContext | bool:
    """EAE-07 TLS trust for every edge -> cloud client: CLOUD_TLS_CA_FILE set -> an SSLContext that trusts ONLY
    that PEM (the self-signed instance certificate is pinned); unset -> True (system trust store). A missing or
    unreadable file raises ConfigError (fail closed, never silently unverified)."""
    if not ca_file:
        return True
    path = Path(ca_file)
    if not path.is_file():
        raise ConfigError(f"CLOUD_TLS_CA_FILE does not exist: {path}")
    try:
        return ssl.create_default_context(cafile=str(path))
    except (OSError, ssl.SSLError) as exc:
        raise ConfigError(f"CLOUD_TLS_CA_FILE is not a readable PEM CA bundle: {path}") from exc


DEFAULT_CORS_ORIGINS: tuple[str, ...] = ("http://localhost:5173", "http://127.0.0.1:5173")
_ORIGIN = re.compile(r"^https?://(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]{1,253})(:\d{1,5})?$")


def cors_origins_from(raw: str) -> tuple[str, ...]:
    """KF-07: EDGE_CORS_ORIGINS = comma list of exact kiosk origins (scheme://host[:port], no path, no wildcard);
    empty = the Vite dev origins. Also the allow-list of the foreign-Origin 403 guard."""
    origins = tuple(o.strip().rstrip("/") for o in raw.split(",") if o.strip())
    if not origins:
        return DEFAULT_CORS_ORIGINS
    bad = [o for o in origins if not _ORIGIN.match(o)]
    if bad:
        raise ConfigError("EDGE_CORS_ORIGINS takes exact origins like http://127.0.0.1:4173 (no paths, no '*')")
    return origins


def extra_allowed_hosts(raw: str) -> tuple[str, ...]:
    hosts = tuple(h.strip() for h in raw.split(",") if h.strip())
    bad = [h for h in hosts if "*" in h or not _HOSTNAME.match(h)]
    if bad:
        raise ConfigError("EDGE_EXTRA_ALLOWED_HOSTS takes exact host names only (no wildcards)")
    return hosts


class Thresholds:
    """Read-only accessor over config/thresholds.yaml (base = ONLINE values)."""

    def __init__(self, data: dict[str, Any], path: Path | None = None) -> None:
        self._data = data
        self.path = path

    @classmethod
    def load(cls, path: Path) -> Thresholds:
        with path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            raise TypeError(f"{path} is not a YAML mapping")
        return cls(data, path)

    @property
    def raw(self) -> dict[str, Any]:
        return self._data

    @property
    def policy_version(self) -> str:
        return str(self._data.get("policy_version", "unknown"))

    def get(self, dotted: str, default: Any = _REQUIRED) -> Any:
        node: Any = self._data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                if default is _REQUIRED:
                    raise KeyError(f"thresholds.yaml is missing '{dotted}'")
                return default
            node = node[part]
        return node


@dataclass(frozen=True)
class Settings:
    project_root: Path
    kiosk_id: str
    cloud_api_url: str
    cloud_api_key: str = field(repr=False)  # EAE-17: a cloud secret like the others
    kiosk_hmac_key: str = field(repr=False)
    edge_data_key: str = field(repr=False)
    admin_token: str = field(repr=False)
    card_id_pepper: str = field(repr=False)
    force_offline: bool
    models_dir: Path
    data_dir: Path
    thresholds_path: Path
    ort_provider: str  # "auto" | "cpu" | "coreml" (applies to the ArcFace embedder only)
    depth_device_token: str = field(default="", repr=False)
    lan_port: int = 0  # 0 = no LAN listener for the DepthProbe iPhone app
    demo_mode: bool = False
    cors_origins: tuple[str, ...] = DEFAULT_CORS_ORIGINS
    # Outbound edge -> cloud admin credential (RBAC v2 D, EAE-02), never coupled to the inbound ADMIN_TOKEN:
    # CLOUD_EDGE_PROXY_KEY (an edge_proxy API key, sent as Authorization: Bearer) wins; else the legacy
    # CLOUD_ADMIN_TOKEN (sent as X-Admin-Token). Never falls back to ADMIN_TOKEN.
    cloud_admin_token: str = field(default="", repr=False)
    cloud_edge_proxy_key: str = field(default="", repr=False)
    cloud_tls_ca_file: str = ""  # EAE-07: PEM that the cloud certificate must chain to (pinning); "" = system store
    allowed_hosts: tuple[str, ...] = LOOPBACK_HOSTS

    @property
    def cloud_admin_configured(self) -> bool:
        return bool(self.cloud_edge_proxy_key or self.cloud_admin_token)

    @property
    def cloud_enabled(self) -> bool:
        return bool(self.cloud_api_url)

    @classmethod
    def from_env(cls, project_root: Path = PROJECT_ROOT) -> Settings:
        load_dotenv(project_root / ".env")
        env = os.environ
        return cls(
            project_root=project_root,
            kiosk_id=env.get("KIOSK_ID", "KIOSK_MAIN_01"),
            cloud_api_url=validate_cloud_url(env.get("CLOUD_API_URL", ""), demo_mode=_flag(env, "DEMO_MODE")),
            cloud_api_key=env.get("CLOUD_API_KEY", ""),
            kiosk_hmac_key=env.get("KIOSK_HMAC_KEY", ""),
            edge_data_key=env.get("EDGE_DATA_KEY", ""),
            admin_token=env.get("ADMIN_TOKEN", ""),
            card_id_pepper=env.get("CARD_ID_PEPPER", ""),
            force_offline=_flag(env, "FORCE_OFFLINE"),
            models_dir=Path(env.get("EDGE_MODELS_DIR", str(project_root / "models"))),
            data_dir=Path(env.get("EDGE_DATA_DIR", str(project_root / "edge" / "data"))),
            thresholds_path=Path(
                env.get("EDGE_THRESHOLDS", str(project_root / "config" / "thresholds.yaml"))
            ),
            ort_provider=env.get("EDGE_ORT_PROVIDER", "auto").strip().lower(),
            depth_device_token=env.get("DEPTH_DEVICE_TOKEN", ""),
            lan_port=int(env.get("EDGE_LAN_PORT", "0") or 0),
            demo_mode=_flag(env, "DEMO_MODE"),
            cloud_admin_token=env.get("CLOUD_ADMIN_TOKEN", ""),
            cloud_edge_proxy_key=env.get("CLOUD_EDGE_PROXY_KEY", ""),
            cloud_tls_ca_file=env.get("CLOUD_TLS_CA_FILE", "").strip(),
            allowed_hosts=LOOPBACK_HOSTS + extra_allowed_hosts(env.get("EDGE_EXTRA_ALLOWED_HOSTS", "")),
            cors_origins=cors_origins_from(env.get("EDGE_CORS_ORIGINS", "")),
        )
