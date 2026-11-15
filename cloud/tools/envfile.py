"""One `.env` reader for the deploy tooling, matching the runtime loaders (CIT-14). Stdlib only.

Semantics (identical to `edge/config.py`, which also matches `cloud/app/config.py` for well-formed lines):
- `KEY=VALUE` lines; blank lines and `#` comment lines are skipped; an `export ` prefix on the key is dropped.
- A quoted value keeps everything inside the quotes; an unquoted value loses a whitespace-led ` # comment`
  (space or tab) tail and surrounding whitespace.
- The FIRST occurrence of a key wins (both runtime loaders never override a key already set).

`read_env_file` also reports keys whose value the cloud loader would read differently (`ambiguous`) and keys
that occur more than once (`duplicates`), so the tools can refuse them instead of deploying a different
secret than the edge reads. Values are never printed by this module.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

_INLINE_COMMENT = re.compile(r"\s+#.*$")
_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ENV_FILE_MODE = 0o600
NO_KIOSK_KEYS = "no kiosk keys: set KIOSK_KEYS_JSON or ALLOW_SHARED_KIOSK_KEY=1 (+KIOSK_HMAC_KEY)"


def _max_key_name() -> int:
    """cloud/app/rbac.py MAX_KEY_NAME when importable (single source), else the same constant."""
    try:
        from cloud.app.rbac import MAX_KEY_NAME
    except Exception:  # noqa: BLE001 - stdlib-only callers without the app / edge.auth on the path
        return 64
    return int(MAX_KEY_NAME)


MAX_KEY_NAME = _max_key_name()
_PERMISSIVE_BITS = 0o077


@dataclass(frozen=True)
class EnvFile:
    values: dict[str, str]
    duplicates: tuple[str, ...]
    ambiguous: tuple[str, ...]
    lines: tuple[str, ...]
    first_line: dict[str, int]


def parse_value(raw: str) -> str:
    """Edge semantics (edge/config.py parse_env_value)."""
    v = raw.strip()
    if len(v) >= 2 and v[0] in "\"'":
        end = v.find(v[0], 1)
        return v[1:end] if end > 0 else v[1:]
    if v.startswith("#"):
        return ""
    return _INLINE_COMMENT.sub("", v).strip()


def cloud_value(raw: str) -> str:
    """Cloud semantics (cloud/app/config.py load_dotenv), used only to detect disagreements."""
    v = raw.split(" #", 1)[0].split("\t#", 1)[0].strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v


def split_line(raw: str) -> tuple[str, str, bool] | None:
    """(key, raw value, had_export_prefix) for an assignment line, else None."""
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        return None
    key, _, value = line.partition("=")
    key = key.strip()
    exported = key.startswith("export ")
    key = key.removeprefix("export ").strip()
    if not _KEY.match(key):
        return None
    return key, value, exported


def parse_lines(lines: list[str]) -> EnvFile:
    values: dict[str, str] = {}
    first: dict[str, int] = {}
    dups: list[str] = []
    ambiguous: list[str] = []
    for i, raw in enumerate(lines):
        parts = split_line(raw)
        if parts is None:
            continue
        key, rawval, exported = parts
        if key in values:
            if key not in dups:
                dups.append(key)
            continue
        values[key] = parse_value(rawval)
        first[key] = i
        if exported or cloud_value(rawval) != values[key]:
            ambiguous.append(key)
    return EnvFile(values=values, duplicates=tuple(sorted(dups)), ambiguous=tuple(sorted(ambiguous)),
                   lines=tuple(lines), first_line=first)


def read_env_file(path: Path) -> EnvFile:
    lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    return parse_lines(lines)


def enforce_private_mode(path: Path) -> bool:
    """chmod 0600 when group/other bits are set; True when the mode was changed."""
    if not path.exists():
        return False
    mode = path.stat().st_mode & 0o777
    if mode & _PERMISSIVE_BITS:
        os.chmod(path, ENV_FILE_MODE)
        return True
    return False


def write_atomic(path: Path, text: str) -> None:
    """Write `text` to a 0600 temp file in the same directory, fsync, then os.replace it over `path` (CIT-17)."""
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        os.fchmod(fd, ENV_FILE_MODE)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


# --------------------------------------------------------------------------- cloud secret rules (RBAC v2 E)
def flag_on(env: Mapping[str, str], name: str) -> bool:
    return env.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def required_cloud_secrets(env: Mapping[str, str], store_backend: str) -> tuple[str, ...]:
    """Names the cloud app needs for this environment (mirrors cloud/app/config.py, RBAC design v2 §E).

    KIOSK_HMAC_KEY is required only with ALLOW_SHARED_KIOSK_KEY=1 (as in config.py); whether ANY kiosk key
    source exists is `kiosk_rule_problems`."""
    req = ["SCHEDULE_BUNDLE_HMAC_KEY", "CLOUD_API_KEY"]
    if flag_on(env, "ALLOW_SHARED_KIOSK_KEY"):
        req.append("KIOSK_HMAC_KEY")
    if store_backend != "memory":
        req.append("OTP_PEPPER")
    if flag_on(env, "AUTH_LEGACY_ADMIN_TOKEN") and not env.get("CLOUD_ADMIN_TOKEN"):
        req.append("ADMIN_TOKEN")
    return tuple(req)


def kiosk_rule_problems(env: Mapping[str, str]) -> list[str]:
    """config.py refuses to start without a kiosk key source: a non-empty KIOSK_KEYS_JSON map, or
    ALLOW_SHARED_KIOSK_KEY=1 (+KIOSK_HMAC_KEY, reported by required_cloud_secrets). A KIOSK_KEYS_JSON that is
    not a valid map is reported by kiosk_keys_problems instead (not twice)."""
    if flag_on(env, "ALLOW_SHARED_KIOSK_KEY"):
        return []
    raw = env.get("KIOSK_KEYS_JSON", "")
    if raw:
        if kiosk_keys_problems(raw):
            return []
        if json.loads(raw):
            return []
    return [NO_KIOSK_KEYS]


def api_key_entries_problems(raw: str, kiosk_id_re: str = r"^[A-Za-z0-9_.:\-]{1,128}$",
                             known_roles: frozenset[str] | None = None) -> list[str]:
    """Structural problems of a CLOUD_API_KEYS_JSON value (empty list = valid). Never echoes secrets."""
    try:
        doc = json.loads(raw)
    except ValueError:
        return ["CLOUD_API_KEYS_JSON is not valid JSON"]
    if not isinstance(doc, list):
        return ["CLOUD_API_KEYS_JSON must be a JSON list"]
    problems: list[str] = []
    seen: set[str] = set()
    for i, e in enumerate(doc):
        problems += _entry_problems(i, e, seen, kiosk_id_re, known_roles)
    return problems


def _entry_problems(i: int, e: object, seen: set[str], kiosk_id_re: str,
                    known_roles: frozenset[str] | None) -> list[str]:
    where = f"CLOUD_API_KEYS_JSON[{i}]"
    if not isinstance(e, dict):
        return [f"{where} is not an object"]
    out: list[str] = []
    key_id = e.get("key_id")
    if not isinstance(key_id, str) or not re.fullmatch(r"[a-z0-9]{8}", key_id):
        out.append(f"{where}.key_id must be 8 chars [a-z0-9]")
    elif key_id in seen:
        out.append(f"{where}.key_id {key_id} is duplicated")
    else:
        seen.add(key_id)
    if not isinstance(e.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", e["sha256"]):
        out.append(f"{where}.sha256 must be 64 lowercase hex chars")
    roles = e.get("roles")
    if not isinstance(roles, list) or not roles or len(roles) > 3 or not all(isinstance(r, str) for r in roles):
        out.append(f"{where}.roles must be a list of 1-3 role names")
    elif known_roles is not None and set(roles) - known_roles:
        out.append(f"{where}.roles has unknown cloud role(s): {', '.join(sorted(set(roles) - known_roles))}")
    if not isinstance(e.get("name"), str) or not e["name"].strip():
        out.append(f"{where}.name is required")
    elif len(e["name"]) > MAX_KEY_NAME:
        out.append(f"{where}.name must be at most {MAX_KEY_NAME} chars (cloud/app/rbac.py MAX_KEY_NAME)")
    kiosks = e.get("kiosk_ids")
    if kiosks is not None and (not isinstance(kiosks, list) or
                               not all(isinstance(k, str) and re.fullmatch(kiosk_id_re, k) for k in kiosks)):
        out.append(f"{where}.kiosk_ids must be a list of kiosk ids")
    if isinstance(roles, list) and "edge_proxy" in roles and (not isinstance(kiosks, list) or len(kiosks) != 1):
        out.append(f"{where}: an edge_proxy key must list exactly one kiosk_id")
    exp = e.get("expires_at")
    if exp is not None and (not isinstance(exp, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", exp)):
        out.append(f"{where}.expires_at must be YYYY-MM-DDTHH:MM:SSZ (UTC)")
    return out


def kiosk_keys_problems(raw: str) -> list[str]:
    try:
        doc = json.loads(raw)
    except ValueError:
        return ["KIOSK_KEYS_JSON is not valid JSON"]
    if not isinstance(doc, dict) or not all(isinstance(k, str) and isinstance(v, str) and v for k, v in doc.items()):
        return ["KIOSK_KEYS_JSON must map kiosk_id -> non-empty key string"]
    return []
