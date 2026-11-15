"""Minimal signed client for the cloud API (used by cloudcurl / smoke; the edge may copy it).

Keys are read from the environment or the project-root .env (never printed). `curl_command()` renders the
equivalent curl line with the API key / admin credential as $ENV placeholders and the per-request signature
(valid for 60 s; single-use except /v1/sync).

Admin routes (RBAC design v2 §E): `Authorization: Bearer $FG_CLOUD_ADMIN_KEY` (a cloud API key minted with
`python -m cloud.tools.apikey`). The legacy shared `X-Admin-Token` (CLOUD_ADMIN_TOKEN / ADMIN_TOKEN) is sent
only when FG_ALLOW_LEGACY_ADMIN_TOKEN=1; there is no silent fallback. The kiosk signing key is the kiosk's own
KIOSK_KEYS_JSON entry when present, else the shared KIOSK_HMAC_KEY.
"""

from __future__ import annotations

import json
import os
import shlex
from collections.abc import Mapping
from typing import Any

import httpx
from edge.auth.tokens import parse_api_key

from cloud.app.auth import signed_headers
from cloud.app.canonical import item_hmac
from cloud.app.config import PROJECT_ROOT, load_dotenv

ADMIN_KEY_ENV = "FG_CLOUD_ADMIN_KEY"
LEGACY_FLAG_ENV = "FG_ALLOW_LEGACY_ADMIN_TOKEN"
_PLACEHOLDERS = {"X-Api-Key": '"X-Api-Key: $CLOUD_API_KEY"', "X-Admin-Token": '"X-Admin-Token: $ADMIN_TOKEN"',
                 "Authorization": f'"Authorization: Bearer ${ADMIN_KEY_ENV}"'}


def _env(environ: Mapping[str, str] | None) -> dict[str, str]:
    env = dict(os.environ if environ is None else environ)
    if environ is None:
        load_dotenv(PROJECT_ROOT / ".env", env)
    return env


def _kiosk_key(env: Mapping[str, str], kiosk_id: str | None) -> str:
    raw = env.get("KIOSK_KEYS_JSON") or ""
    if raw and kiosk_id:
        try:
            per = json.loads(raw)
        except ValueError as exc:
            raise SystemExit("KIOSK_KEYS_JSON is not valid JSON") from exc
        if isinstance(per, dict) and isinstance(per.get(kiosk_id), str) and per[kiosk_id]:
            return per[kiosk_id]
    return env.get("KIOSK_HMAC_KEY", "")


def admin_credential(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """{"admin_key": ...} or {"admin_token": ...} (legacy, flag only) or {} when nothing is configured."""
    env = _env(environ)
    key = env.get(ADMIN_KEY_ENV, "").strip()
    if key:
        if parse_api_key(key) is None:
            raise SystemExit(f"{ADMIN_KEY_ENV} is not a cloud API key (fgk_<key_id>.<secret>)")
        return {"admin_key": key}
    if env.get(LEGACY_FLAG_ENV, "").strip() == "1":
        token = env.get("CLOUD_ADMIN_TOKEN") or env.get("ADMIN_TOKEN") or ""
        return {"admin_token": token} if token else {}
    return {}


def load_keys(kiosk_id: str | None = None, environ: Mapping[str, str] | None = None) -> dict[str, str]:
    env = _env(environ)
    keys = {"kiosk_key": _kiosk_key(env, kiosk_id), "api_key": env.get("CLOUD_API_KEY", "")}
    missing = [n for n, k in (("KIOSK_HMAC_KEY or KIOSK_KEYS_JSON entry", "kiosk_key"), ("CLOUD_API_KEY", "api_key"))
               if not keys[k]]
    if missing:
        raise SystemExit(f"missing in env/.env: {', '.join(missing)} (run: python -m cloud.tools.ensure_env)")
    return {**keys, **admin_credential(env)}


class CloudClient:
    def __init__(self, base_url: str, kiosk_id: str, keys: dict[str, str] | None = None, timeout: float = 15.0,
                 verify: bool | str = True) -> None:
        self.base = base_url.rstrip("/")
        self.kiosk_id = kiosk_id
        self.keys = keys or load_keys(kiosk_id)
        self.http = httpx.Client(timeout=timeout, verify=verify)

    def _admin_headers(self) -> dict[str, str]:
        if self.keys.get("admin_key"):
            return {"Authorization": f"Bearer {self.keys['admin_key']}"}
        if self.keys.get("admin_token"):
            return {"X-Admin-Token": self.keys["admin_token"]}
        raise SystemExit(f"admin route needs {ADMIN_KEY_ENV} (mint one: python -m cloud.tools.apikey --roles admin "
                         f"...); the legacy X-Admin-Token is sent only with {LEGACY_FLAG_ENV}=1")

    def _headers(self, method: str, path: str, body: bytes, admin: bool, content_type: str | None) -> dict:
        h = signed_headers(kiosk_id=self.kiosk_id, key=self.keys["kiosk_key"], api_key=self.keys["api_key"],
                           method=method, path=path, body=body)
        if content_type:
            h["Content-Type"] = content_type
        if admin:
            h.update(self._admin_headers())
        return h

    def curl_command(self, method: str, path: str, body: bytes, headers: dict, data_file: str | None = None) -> str:
        parts = ["curl", "-sS", "-i", "-X", method, shlex.quote(self.base + path)]
        for k, v in headers.items():
            parts += ["-H", _PLACEHOLDERS.get(k, shlex.quote(f"{k}: {v}"))]
        if body:
            parts += ["--data-binary", f"@{data_file}" if data_file else shlex.quote(body.decode("utf-8", "replace"))]
        return " ".join(parts)

    def request(self, method: str, path: str, *, json_body: Any = None, content: bytes | None = None,
                content_type: str | None = None, admin: bool = False, headers: dict | None = None,
                data_file: str | None = None) -> tuple[httpx.Response, str]:
        if json_body is not None:
            content = json.dumps(json_body, separators=(",", ":")).encode()
            content_type = content_type or "application/json"
        body = content or b""
        h = self._headers(method, path, body, admin, content_type)
        h.update(headers or {})
        curl = self.curl_command(method, path, body, h, data_file)
        resp = self.http.request(method, self.base + path, content=body, headers=h)
        return resp, curl


def sign_items(items: list[dict], kiosk_key: str) -> list[dict]:
    out = []
    for it in items:
        body = {k: v for k, v in it.items() if k != "hmac"}
        out.append({**body, "hmac": item_hmac(kiosk_key, body)})
    return out
