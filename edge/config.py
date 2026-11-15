"""Edge configuration: thresholds from config/thresholds.yaml (the only source of numbers) + .env.

Secrets are read from the environment / project `.env` and are never logged or returned.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
    cloud_api_key: str
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
    cors_origins: tuple[str, ...] = ("http://localhost:5173", "http://127.0.0.1:5173")
    # X-Admin-Token the edge sends to the CLOUD admin routes (API.md 4.9): CLOUD_ADMIN_TOKEN, else ADMIN_TOKEN
    # (the cloud also falls back from CLOUD_ADMIN_TOKEN to ADMIN_TOKEN, cloud/app/config.py)
    cloud_admin_token: str = field(default="", repr=False)

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
            cloud_api_url=env.get("CLOUD_API_URL", "").strip().rstrip("/"),
            cloud_api_key=env.get("CLOUD_API_KEY", ""),
            kiosk_hmac_key=env.get("KIOSK_HMAC_KEY", ""),
            edge_data_key=env.get("EDGE_DATA_KEY", ""),
            admin_token=env.get("ADMIN_TOKEN", ""),
            card_id_pepper=env.get("CARD_ID_PEPPER", ""),
            force_offline=env.get("FORCE_OFFLINE", "0").strip().lower() in {"1", "true", "yes"},
            models_dir=Path(env.get("EDGE_MODELS_DIR", str(project_root / "models"))),
            data_dir=Path(env.get("EDGE_DATA_DIR", str(project_root / "edge" / "data"))),
            thresholds_path=Path(
                env.get("EDGE_THRESHOLDS", str(project_root / "config" / "thresholds.yaml"))
            ),
            ort_provider=env.get("EDGE_ORT_PROVIDER", "auto").strip().lower(),
            depth_device_token=env.get("DEPTH_DEVICE_TOKEN", ""),
            lan_port=int(env.get("EDGE_LAN_PORT", "0") or 0),
            demo_mode=env.get("DEMO_MODE", "0").strip().lower() in {"1", "true", "yes"},
            cloud_admin_token=env.get("CLOUD_ADMIN_TOKEN") or env.get("ADMIN_TOKEN", ""),
        )
