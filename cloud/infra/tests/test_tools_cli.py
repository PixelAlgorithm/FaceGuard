"""V2 apikey.py + admin credential headers; CIT-12 (scratch targets by default); CIT-13 (cloudcurl redaction);
CIT-19 (no personal e-mail / live ids in tool docs)."""

# ruff: noqa: S603, S607, S105, S106, S108

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cloud.tools import cloudclient, cloudcurl, redact, targets
from edge.auth import tokens

from .conftest import ROOT

KEYS = {"kiosk_key": "k" * 40, "api_key": "a" * 40}


def _apikey(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "cloud.tools.apikey", *args], cwd=ROOT, capture_output=True,
                          text=True, timeout=60)


# --------------------------------------------------------------------------- apikey.py
def test_apikey_mints_key_and_matching_entry():
    r = _apikey("--name", "ops laptop", "--roles", "auditor", "--expires-days", "7")
    assert r.returncode == 0, r.stderr
    key = next(line.strip() for line in r.stdout.splitlines() if line.strip().startswith("fgk_"))
    entry = json.loads(next(line for line in r.stdout.splitlines() if line.strip().startswith("{")))
    key_id, secret = tokens.parse_api_key(key)
    assert entry["key_id"] == key_id and entry["sha256"] == tokens.digest(secret)
    assert entry["roles"] == ["auditor"] and entry["name"] == "ops laptop"
    exp = datetime.strptime(entry["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    assert timedelta(days=6) < exp - datetime.now(UTC) <= timedelta(days=7)
    assert r.stdout.count(key) == 1  # printed once


def test_apikey_edge_proxy_needs_exactly_one_kiosk():
    assert _apikey("--name", "e", "--roles", "edge_proxy").returncode == 2
    assert _apikey("--name", "e", "--roles", "edge_proxy", "--kiosk-id", "A", "--kiosk-id", "B").returncode == 2
    r = _apikey("--name", "e", "--roles", "edge_proxy", "--kiosk-id", "KIOSK_MAIN_01")
    assert r.returncode == 0, r.stderr
    entry = json.loads(next(line for line in r.stdout.splitlines() if line.strip().startswith("{")))
    assert entry["kiosk_ids"] == ["KIOSK_MAIN_01"] and "expires_at" not in entry
    assert "CLOUD_EDGE_PROXY_KEY" in r.stdout


def test_apikey_rejects_unknown_role_and_bad_days():
    assert _apikey("--name", "x", "--roles", "security_officer").returncode == 2  # edge role, not a cloud role
    assert _apikey("--name", "x", "--roles", "auditor", "--expires-days", "0").returncode == 2


def test_apikey_key_file_is_0600_and_key_not_on_stdout(tmp_path: Path):
    kf = tmp_path / "k.txt"
    r = _apikey("--name", "x", "--roles", "auditor", "--key-file", str(kf))
    assert r.returncode == 0, r.stderr
    key = kf.read_text().strip()
    assert tokens.parse_api_key(key) and key not in r.stdout
    assert stat.S_IMODE(kf.stat().st_mode) == 0o600


# --------------------------------------------------------------------------- admin credential headers
def _headers(env: dict[str, str]) -> dict:
    c = cloudclient.CloudClient("http://127.0.0.1:1", "KIOSK_MAIN_01", {**KEYS, **cloudclient.admin_credential(env)})
    return c._headers("GET", "/v1/admin/stats", b"", True, None)


def test_admin_bearer_key_preferred():
    key = tokens.new_api_key()[1]
    h = _headers({"FG_CLOUD_ADMIN_KEY": key, "ADMIN_TOKEN": "legacy"})
    assert h["Authorization"] == f"Bearer {key}" and "X-Admin-Token" not in h


def test_legacy_token_only_with_flag():
    with pytest.raises(SystemExit):
        _headers({"ADMIN_TOKEN": "legacy"})
    h = _headers({"ADMIN_TOKEN": "legacy", "FG_ALLOW_LEGACY_ADMIN_TOKEN": "1"})
    assert h["X-Admin-Token"] == "legacy" and "Authorization" not in h


def test_malformed_admin_key_refused():
    with pytest.raises(SystemExit):
        _headers({"FG_CLOUD_ADMIN_KEY": "not-a-key"})


def test_curl_line_uses_placeholders():
    key = tokens.new_api_key()[1]
    c = cloudclient.CloudClient("http://127.0.0.1:1", "K", {**KEYS, **cloudclient.admin_credential(
        {"FG_CLOUD_ADMIN_KEY": key})})
    h = c._headers("GET", "/v1/admin/stats", b"", True, None)
    line = c.curl_command("GET", "/v1/admin/stats", b"", h)
    assert key not in line and "$FG_CLOUD_ADMIN_KEY" in line and KEYS["api_key"] not in line


def test_per_kiosk_key_used_for_signing():
    env = {"KIOSK_KEYS_JSON": json.dumps({"KIOSK_A": "per-kiosk"}), "KIOSK_HMAC_KEY": "shared",
           "CLOUD_API_KEY": "api"}
    assert cloudclient.load_keys("KIOSK_A", env)["kiosk_key"] == "per-kiosk"
    assert cloudclient.load_keys("KIOSK_B", env)["kiosk_key"] == "shared"


# --------------------------------------------------------------------------- CIT-12 scratch targets
@pytest.mark.parametrize("base", ["http://127.0.0.1:9000", "http://localhost:8250", "http://[::1]:8251"])
def test_loopback_targets_allowed(base):
    assert targets.require_target(base, live=False) == base


def test_remote_target_needs_live_flag():
    with pytest.raises(SystemExit) as e:
        targets.require_target("https://abc.execute-api.us-east-1.amazonaws.com", live=False)
    assert "--live" in str(e.value)
    assert targets.require_target("https://abc.execute-api.us-east-1.amazonaws.com", live=True)


def test_cloudcurl_refuses_remote_without_live(monkeypatch):
    monkeypatch.setenv("CLOUD_API_URL", "https://live.example.org")
    with pytest.raises(SystemExit):
        cloudcurl.main(["GET", "/v1/health"])


@pytest.mark.parametrize("mod", ["smoke", "smoke_noface", "smoke_upload", "latency"])
def test_smoke_tools_refuse_remote_without_live(mod):
    r = subprocess.run([sys.executable, "-m", f"cloud.tools.{mod}", "--base", "https://live.example.org",
                        *(["--image", "x.jpg"] if mod == "latency" else [])],
                       cwd=ROOT, capture_output=True, text=True, timeout=60,
                       env={**os.environ, "KIOSK_HMAC_KEY": "k", "CLOUD_API_KEY": "a"})
    assert r.returncode != 0 and "--live" in (r.stdout + r.stderr)


# --------------------------------------------------------------------------- CIT-13 redaction
ROTATE = {"staff_id": "s_guard01", "bundle_version": 50, "codes": [{"code_id": "OVR-R1-01", "code": "48213907"}],
          "valid_until": "2026-11-16T00:00:00Z"}
OUTBOX = {"messages": [{"to": "a@example.org", "subject": "Your code", "body": "Your code is 123456"}]}


def test_redact_codes_and_outbox():
    red = redact.redact_json(ROTATE)
    assert "48213907" not in json.dumps(red) and red["codes"][0]["code_id"] == "OVR-R1-01"
    assert "123456" not in json.dumps(redact.redact_json(OUTBOX))
    tok = tokens.new_api_key()[1]
    assert tok not in json.dumps(redact.redact_json({"note": f"key {tok}"}))


def _serve(monkeypatch, payload: dict) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json=payload)

    real = httpx.Client

    def fake_client(*a, **kw):
        kw.pop("verify", None)
        return real(transport=httpx.MockTransport(handler), **kw)

    monkeypatch.setattr(cloudclient.httpx, "Client", fake_client)
    monkeypatch.setenv("KIOSK_HMAC_KEY", "k" * 40)
    monkeypatch.setenv("CLOUD_API_KEY", "a" * 40)
    monkeypatch.setenv("FG_CLOUD_ADMIN_KEY", tokens.new_api_key()[1])


def test_cloudcurl_redacts_by_default(monkeypatch, capsys):
    _serve(monkeypatch, ROTATE)
    rc = cloudcurl.main(["--base", "http://127.0.0.1:9", "--admin", "POST", "/v1/admin/codes/rotate",
                         "--data", '{"staff_id":"s_guard01"}'])
    out = capsys.readouterr().out
    assert rc == 0 and "48213907" not in out and "OVR-R1-01" in out


def test_cloudcurl_reveal_writes_0600_file(monkeypatch, capsys, tmp_path: Path):
    _serve(monkeypatch, ROTATE)
    dest = tmp_path / "codes.json"
    rc = cloudcurl.main(["--base", "http://127.0.0.1:9", "--admin", "--reveal-secrets", str(dest), "POST",
                         "/v1/admin/codes/rotate", "--data", "{}"])
    out = capsys.readouterr().out
    assert rc == 0 and "48213907" not in out
    assert "48213907" in dest.read_text() and stat.S_IMODE(dest.stat().st_mode) == 0o600


# --------------------------------------------------------------------------- CIT-19
OWNED_DOCS = ["cloud/tools", "cloud/infra", "cloud/SANDBOX.md", "scripts/fetch_models.sh"]


def test_no_personal_email_or_live_ids_in_owned_files():
    import re

    bad = re.compile(r"[A-Za-z0-9._%+-]+@gmail\.com|\b8c1yi8fjgj\b|\bi-0[0-9a-f]{16}\b")
    hits = []
    for rel in OWNED_DOCS:
        p = ROOT / rel
        files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file() and f.suffix in
                                         {".py", ".sh", ".md", ".tmpl", ".json"} and "tests" not in f.parts
                                         and "build" not in f.parts]
        hits += [f"{f}:{m.group(0)}" for f in files for m in bad.finditer(f.read_text(errors="ignore"))]
    assert hits == []
