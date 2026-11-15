"""Depth-bridge settings from the environment / project .env (same rules as edge/config.py).

DEPTH_DEVICE_TOKEN is a secret shared with the phone (X-Depth-Token header): never print or log it.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LAN_PORT = 8001
_INLINE_COMMENT = re.compile(r"\s+#.*$")


def _parse(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and v[0] in "\"'":
        end = v.find(v[0], 1)
        return v[1:end] if end > 0 else v[1:]
    if v.startswith("#"):
        return ""
    return _INLINE_COMMENT.sub("", v).strip()


def env_value(key: str, default: str | None = None, *, dotenv: Path | None = None) -> str | None:
    """os.environ wins; else the project .env; else default."""
    if os.environ.get(key):
        return os.environ[key]
    path = dotenv or (PROJECT_ROOT / ".env")
    if path.is_file():
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            if k.strip().removeprefix("export ").strip() == key:
                return _parse(v) or default
    return default


def lan_port() -> int:
    try:
        return int(env_value("EDGE_LAN_PORT", str(DEFAULT_LAN_PORT)) or DEFAULT_LAN_PORT)
    except ValueError:
        return DEFAULT_LAN_PORT


def device_token() -> str | None:
    return env_value("DEPTH_DEVICE_TOKEN") or None
