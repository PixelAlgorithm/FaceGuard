"""Edge credentials for the eval tooling (RBAC v2 section G).

Every authenticated edge call (SSE `GET /v1/events`, `GET /v1/metrics`, `/v1/admin/*`) sends
`Authorization: Bearer <key>`:

- `FG_EVAL_API_KEY` (role evaluator) for capture.py and snapshot_metrics.py;
- `FG_OPS_API_KEY` (roles security_officer + evaluator) for scenarios/run_scenarios.py.

The legacy shared `ADMIN_TOKEN` (`X-Admin-Token`) is used only when no key is set AND
`FG_ALLOW_LEGACY_ADMIN_TOKEN=1`. Values (keys, the legacy flag and ADMIN_TOKEN) come from the process
environment first, then the project `.env`.
A 401/403 from the edge raises `AuthFailure`; the tools turn it into a clear message and a non-zero exit
(never a silent fallback to unauthenticated or legacy calls). Secret values are never printed, logged or
written: `describe()` names the source and, for API keys, only the public key id.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from evallib import PROJECT_DIR

EVAL_KEY_ENV = "FG_EVAL_API_KEY"
OPS_KEY_ENV = "FG_OPS_API_KEY"
LEGACY_FLAG_ENV = "FG_ALLOW_LEGACY_ADMIN_TOKEN"
LEGACY_TOKEN_ENV = "ADMIN_TOKEN"
DEFAULT_ENV_FILE = PROJECT_DIR / ".env"

EXIT_AUTH = 5
MODE_DETAIL_PATH = "/v1/admin/mode/detail"  # store:read: policy_version, policy_bars, rate_limit, bundle, zone
PUBLIC_MODE_PATH = "/v1/mode"  # badge subset only (older edges served everything here)  # credential missing, malformed, or refused by the edge (401/403)

API_KEY_RE = re.compile(r"^fgk_(?P<key_id>[a-z0-9]{8})\.[A-Za-z0-9_-]{32,128}$")
LEGACY_TOKEN_RE = re.compile(r"^[\x21-\x7e]{8,512}$")  # printable, no whitespace (header-safe)
AUTH_FAILURE_CODES = (401, 403)
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class AuthFailure(Exception):
    """The edge refused the credential, or no usable credential is configured. Message never holds secrets."""


@dataclass(frozen=True)
class EdgeCredential:
    kind: str  # "api_key" | "legacy_admin_token"
    source: str  # e.g. "env FG_EVAL_API_KEY", ".env FG_OPS_API_KEY"
    key_id: str = ""
    secret: str = field(default="", repr=False)

    def headers(self) -> dict[str, str]:
        if self.kind == "api_key":
            return {"Authorization": f"Bearer {self.secret}"}
        return {"X-Admin-Token": self.secret}

    def describe(self) -> str:
        if self.kind == "api_key":
            return f"API key key:{self.key_id} ({self.source})"
        return f"legacy ADMIN_TOKEN ({self.source}; {LEGACY_FLAG_ENV}=1)"


def read_env_value(name: str, env_file: Path | None = DEFAULT_ENV_FILE) -> tuple[str, str] | None:
    """(value, source) from the process environment, else the .env file. None when unset or empty."""
    if os.environ.get(name):
        return os.environ[name].strip(), f"env {name}"
    if env_file is None:
        return None
    try:
        lines = env_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        k, sep, v = line.partition("=")
        if sep and k.strip().removeprefix("export ").strip() == name:
            v = v.split(" #")[0].strip().strip('"').strip("'")
            return (v, f".env {name}") if v else None
    return None


def legacy_allowed(env_file: Path | None = DEFAULT_ENV_FILE) -> bool:
    """FG_ALLOW_LEGACY_ADMIN_TOKEN=1 in the process environment, else in the project .env (same order as keys)."""
    found = read_env_value(LEGACY_FLAG_ENV, env_file)
    return bool(found) and found[0].strip() == "1"


def load_credential(key_env: str = EVAL_KEY_ENV, env_file: Path | None = DEFAULT_ENV_FILE) -> EdgeCredential:
    """The API key named by `key_env`, else the legacy token when allowed. Raises AuthFailure otherwise."""
    found = read_env_value(key_env, env_file)
    if found:
        value, source = found
        m = API_KEY_RE.match(value)
        if not m:
            raise AuthFailure(f"{key_env} ({source}) is not an edge API key (expected fgk_<key_id>.<secret>); "
                              "mint one with `python -m edge.auth create-api-key ... --print-key-only`")
        return EdgeCredential("api_key", source, m["key_id"], value)
    if legacy_allowed(env_file):
        legacy = read_env_value(LEGACY_TOKEN_ENV, env_file)
        if legacy and LEGACY_TOKEN_RE.match(legacy[0]):
            return EdgeCredential("legacy_admin_token", legacy[1], "", legacy[0])
        raise AuthFailure(f"{LEGACY_FLAG_ENV}=1 but no usable {LEGACY_TOKEN_ENV} in the environment or .env")
    raise AuthFailure(f"no edge credential: set {key_env} (edge API key, `Authorization: Bearer`); the legacy "
                      f"{LEGACY_TOKEN_ENV} is used only with {LEGACY_FLAG_ENV}=1")


def check_edge_url(url: str, allow_remote: bool = False) -> None:
    """Credentials only go to a loopback edge, or (with allow_remote) to an https one (DE-11).

    Raises AuthFailure (no request is made) for any other scheme/host, e.g. a stale EDGE_URL pointing at a
    LAN host over plain http, which would receive the key in cleartext."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https") or not host:
        raise AuthFailure(f"edge URL {url!r} is not an http(s) URL")
    if host in LOOPBACK_HOSTS:
        return
    if parts.scheme == "https" and allow_remote:
        return
    raise AuthFailure(f"refusing to send edge credentials to {parts.scheme}://{host}: only a loopback edge "
                      "(127.0.0.1 / localhost / [::1]) or https with --allow-remote-edge")


def error_reason(body: object) -> str:
    """`error.reason` / `error.code` (+ `required`) from an edge error envelope, for messages. Never secrets."""
    err = body.get("error") if isinstance(body, dict) else None
    if not isinstance(err, dict):
        return ""
    parts = [str(err.get(k)) for k in ("code", "reason") if isinstance(err.get(k), str)]
    req = err.get("required")
    if isinstance(req, list) and all(isinstance(p, str) for p in req):
        parts.append("required " + ",".join(req))
    return " ".join(parts)[:200]


def failure_message(status: int, method: str, path: str, cred: EdgeCredential | None, body: object = None) -> str:
    who = cred.describe() if cred else "no credential"
    reason = error_reason(body)
    hint = ("credential invalid, revoked or expired" if status == 401
            else "credential lacks the permission for this route")
    return f"edge refused {method} {path}: HTTP {status}{' ' + reason if reason else ''} ({hint}; {who})"


def raise_for_auth(status: int, method: str, path: str, cred: EdgeCredential | None, body: object = None) -> None:
    """AuthFailure on 401/403; any other status returns (the caller handles it)."""
    if status in AUTH_FAILURE_CODES:
        raise AuthFailure(failure_message(status, method, path, cred, body))
