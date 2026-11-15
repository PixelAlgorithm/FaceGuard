"""Minimal signed client for the cloud API (used by cloudcurl / smoke; the edge may copy it).

Keys are read from the environment or the project-root .env (never printed). `curl_command()` renders the
equivalent curl line with the API key / admin token as $ENV placeholders and the per-request signature
(valid for 60 s; single-use except /v1/sync)."""

from __future__ import annotations

import json
import os
import shlex
from typing import Any

import httpx

from cloud.app.auth import signed_headers
from cloud.app.canonical import item_hmac
from cloud.app.config import PROJECT_ROOT, load_dotenv


def load_keys() -> dict[str, str]:
    env = dict(os.environ)
    load_dotenv(PROJECT_ROOT / ".env", env)
    missing = [k for k in ("KIOSK_HMAC_KEY", "CLOUD_API_KEY") if not env.get(k)]
    if missing:
        raise SystemExit(f"missing in env/.env: {', '.join(missing)} (run: python -m cloud.tools.ensure_env)")
    return {"kiosk_key": env["KIOSK_HMAC_KEY"], "api_key": env["CLOUD_API_KEY"],
            "admin_token": env.get("CLOUD_ADMIN_TOKEN") or env.get("ADMIN_TOKEN", "")}


class CloudClient:
    def __init__(self, base_url: str, kiosk_id: str, keys: dict[str, str] | None = None, timeout: float = 15.0,
                 verify: bool | str = True) -> None:
        self.base = base_url.rstrip("/")
        self.kiosk_id = kiosk_id
        self.keys = keys or load_keys()
        self.http = httpx.Client(timeout=timeout, verify=verify)

    def _headers(self, method: str, path: str, body: bytes, admin: bool, content_type: str | None) -> dict:
        h = signed_headers(kiosk_id=self.kiosk_id, key=self.keys["kiosk_key"], api_key=self.keys["api_key"],
                           method=method, path=path, body=body)
        if content_type:
            h["Content-Type"] = content_type
        if admin:
            h["X-Admin-Token"] = self.keys["admin_token"]
        return h

    def curl_command(self, method: str, path: str, body: bytes, headers: dict, data_file: str | None = None) -> str:
        parts = ["curl", "-sS", "-i", "-X", method, shlex.quote(self.base + path)]
        for k, v in headers.items():
            if k == "X-Api-Key":
                parts += ["-H", '"X-Api-Key: $CLOUD_API_KEY"']
            elif k == "X-Admin-Token":
                parts += ["-H", '"X-Admin-Token: $ADMIN_TOKEN"']
            else:
                parts += ["-H", shlex.quote(f"{k}: {v}")]
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
