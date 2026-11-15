"""CIT-14 (one .env parser, edge semantics), CIT-17 (0600 + atomic), V2 env names (make_app_env / ensure_env)."""

# ruff: noqa: S603, S607, S105, S106, S108

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from cloud.tools import envfile
from edge.auth import tokens

from .conftest import DUMMY_ENV, DUMMY_SECRETS, INFRA, ROOT

LEGACY_FREE = {k: v for k, v in DUMMY_ENV.items() if k != "ADMIN_TOKEN"}


def _key_entry(roles=("auditor",), kiosk_ids=None) -> dict:
    key_id, _full, sha = tokens.new_api_key()
    e = {"key_id": key_id, "sha256": sha, "roles": list(roles), "name": "t"}
    if kiosk_ids:
        e["kiosk_ids"] = list(kiosk_ids)
    return e


# --------------------------------------------------------------------------- parser (CIT-14)
@pytest.mark.parametrize("raw", ["abc\t# note", '"abc"', "abc # c", "'abc'", "abc"])
def test_value_semantics_match_edge(raw):
    from edge.config import parse_env_value

    assert envfile.parse_value(raw) == parse_env_value(raw)


def test_first_value_wins_export_prefix_and_duplicates_reported(tmp_path: Path):
    p = tmp_path / ".env"
    p.write_text("export A=1\nB=\nB=2\nA=3\n# c\n")
    parsed = envfile.read_env_file(p)
    assert parsed.values == {"A": "1", "B": ""}
    assert parsed.duplicates == ("A", "B")


def test_ambiguous_value_detected(tmp_path: Path):
    p = tmp_path / ".env"
    p.write_text('K="a #b"\nOK=plain\n')
    parsed = envfile.read_env_file(p)
    assert "K" in parsed.ambiguous and "OK" not in parsed.ambiguous


# --------------------------------------------------------------------------- make_app_env
def _make(tmp_path: Path, env_lines: dict[str, str], *args: str) -> subprocess.CompletedProcess:
    envf = tmp_path / "dot.env"
    envf.write_text("".join(f"{k}={v}\n" for k, v in env_lines.items()))
    out = tmp_path / "app.env"
    return subprocess.run([sys.executable, str(INFRA / "make_app_env.py"), "--env-file", str(envf), "--out", str(out),
                           "--seed-schedule", "config/schedule.demo.json", "--demo", *args],
                          capture_output=True, text=True, timeout=60)


def _app_env(tmp_path: Path) -> dict[str, str]:
    out = {}
    for line in (tmp_path / "app.env").read_text().splitlines():
        k, v = line.split("=", 1)
        assert v.startswith("'") and v.endswith("'"), "systemd EnvironmentFile values are single-quoted"
        out[k] = v[1:-1]
    return out


def test_make_app_env_needs_no_admin_token_without_legacy(tmp_path: Path):
    r = _make(tmp_path, LEGACY_FREE)
    assert r.returncode == 0, r.stderr
    vals = _app_env(tmp_path)
    assert "ADMIN_TOKEN" not in vals
    assert stat.S_IMODE((tmp_path / "app.env").stat().st_mode) == 0o600
    for v in DUMMY_SECRETS.values():
        assert v not in r.stdout + r.stderr


def test_make_app_env_requires_admin_token_with_legacy(tmp_path: Path):
    r = _make(tmp_path, {**LEGACY_FREE, "AUTH_LEGACY_ADMIN_TOKEN": "1"})
    assert r.returncode == 2 and "ADMIN_TOKEN" in r.stderr
    r = _make(tmp_path, {**DUMMY_ENV, "AUTH_LEGACY_ADMIN_TOKEN": "1"})
    assert r.returncode == 0, r.stderr
    vals = _app_env(tmp_path)
    assert vals["AUTH_LEGACY_ADMIN_TOKEN"] == "1" and vals["ADMIN_TOKEN"] == DUMMY_SECRETS["ADMIN_TOKEN"]


def test_make_app_env_requires_otp_pepper(tmp_path: Path):
    env = {k: v for k, v in LEGACY_FREE.items() if k != "OTP_PEPPER"}
    r = _make(tmp_path, env)
    assert r.returncode == 2 and "OTP_PEPPER" in r.stderr


def test_make_app_env_forwards_and_validates_api_keys(tmp_path: Path):
    keys = [_key_entry(("auditor",)), _key_entry(("edge_proxy",), ["KIOSK_MAIN_01"])]
    r = _make(tmp_path, {**LEGACY_FREE, "CLOUD_API_KEYS_JSON": json.dumps(keys)})
    assert r.returncode == 0, r.stderr
    assert json.loads(_app_env(tmp_path)["CLOUD_API_KEYS_JSON"]) == keys
    bad = [_key_entry(("edge_proxy",))]  # edge_proxy without exactly one kiosk_id
    r = _make(tmp_path, {**LEGACY_FREE, "CLOUD_API_KEYS_JSON": json.dumps(bad)})
    assert r.returncode == 2 and "kiosk_id" in r.stderr
    r = _make(tmp_path, {**LEGACY_FREE, "CLOUD_API_KEYS_JSON": "[{not json"})
    assert r.returncode == 2 and "CLOUD_API_KEYS_JSON" in r.stderr


def test_make_app_env_kiosk_keys(tmp_path: Path):
    env = {k: v for k, v in LEGACY_FREE.items() if k != "KIOSK_HMAC_KEY"}
    r = _make(tmp_path, env)
    assert r.returncode == 2 and "KIOSK_HMAC_KEY" in r.stderr  # ALLOW_SHARED_KIOSK_KEY=1 -> shared key needed
    env = {k: v for k, v in env.items() if k != "ALLOW_SHARED_KIOSK_KEY"}
    r = _make(tmp_path, env)
    assert r.returncode == 2 and "no kiosk keys" in r.stderr  # neither source: config.py would refuse
    r = _make(tmp_path, {**env, "KIOSK_KEYS_JSON": json.dumps({"KIOSK_MAIN_01": "per-kiosk-key-0123456789"})})
    assert r.returncode == 0, r.stderr
    assert "KIOSK_HMAC_KEY" not in _app_env(tmp_path)


def test_make_app_env_refuses_duplicates_and_ambiguous_secrets(tmp_path: Path):
    envf = tmp_path / "dot.env"
    lines = "".join(f"{k}={v}\n" for k, v in LEGACY_FREE.items()) + "CLOUD_API_KEY=second\n"
    envf.write_text(lines)
    r = subprocess.run([sys.executable, str(INFRA / "make_app_env.py"), "--env-file", str(envf), "--out",
                        str(tmp_path / "o"), "--seed-schedule", "config/schedule.demo.json", "--demo"],
                       capture_output=True, text=True)
    assert r.returncode == 2 and "duplicate" in r.stderr.lower() and "CLOUD_API_KEY" in r.stderr


@pytest.mark.parametrize("flag,val", [("--face", "fake"), ("--store", "memory"), ("--email", "fake"),
                                      ("--blob", "memory"), ("--metrics", "memory")])
def test_make_app_env_rejects_test_backends(tmp_path: Path, flag: str, val: str):
    r = _make(tmp_path, LEGACY_FREE, flag, val)
    assert r.returncode == 2


def test_make_app_env_table_names_are_arguments(tmp_path: Path):
    r = _make(tmp_path, LEGACY_FREE, "--ddb-users", "x_users", "--ddb-decisions", "x_dec", "--ddb-state", "x_st")
    assert r.returncode == 0, r.stderr
    v = _app_env(tmp_path)
    assert (v["DDB_TABLE_USERS"], v["DDB_TABLE_DECISIONS"], v["DDB_TABLE_STATE"]) == ("x_users", "x_dec", "x_st")


def test_seed_check(tmp_path: Path):
    sys.path.insert(0, str(INFRA))
    import make_app_env  # type: ignore[import-not-found]

    demo = json.loads((ROOT / "config" / "schedule.demo.json").read_text())
    assert make_app_env.seed_problems(demo, demo_ok=False)
    assert make_app_env.seed_problems(demo, demo_ok=True) == []
    clean = {"bundle_version": 1, "users": {"u_zz01": {"fallback": {"card_id_hash": "ab" * 32}}}}
    assert make_app_env.seed_problems(clean, demo_ok=False) == []


# --------------------------------------------------------------------------- ensure_env (CIT-17)
def _ensure(env_file: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "cloud.tools.ensure_env", "--env-file", str(env_file), *args],
                          cwd=ROOT, capture_output=True, text=True, timeout=60)


def test_ensure_env_fixes_permissive_mode_even_on_check(tmp_path: Path):
    p = tmp_path / ".env"
    p.write_text("".join(f"{k}={v}\n" for k, v in DUMMY_ENV.items()))
    os.chmod(p, 0o644)
    r = _ensure(p, "--check")
    assert r.returncode == 0, r.stderr
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert "0600" in r.stdout + r.stderr
    for v in DUMMY_SECRETS.values():
        assert v not in r.stdout + r.stderr


def test_ensure_env_generates_atomically_and_keeps_existing(tmp_path: Path):
    p = tmp_path / ".env"
    p.write_text("KIOSK_HMAC_KEY=keep-me\n# comment kept\n")
    os.chmod(p, 0o644)
    ino_before = p.stat().st_ino
    r = _ensure(p)
    assert r.returncode == 0, r.stderr
    text = p.read_text()
    assert "KIOSK_HMAC_KEY=keep-me" in text and "# comment kept" in text
    assert "OTP_PEPPER=" in text and "CLOUD_API_KEY=" in text
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert p.stat().st_ino != ino_before  # replaced via os.replace, not rewritten in place
    assert not list(tmp_path.glob(".env.*"))  # no temp file left behind


def test_ensure_env_reports_new_auth_names(tmp_path: Path):
    p = tmp_path / ".env"
    p.write_text("".join(f"{k}={v}\n" for k, v in LEGACY_FREE.items()))
    r = _ensure(p, "--check")
    out = r.stdout
    assert "ADMIN_TOKEN" in out and "not required" in out
    assert "CLOUD_API_KEYS_JSON" in out
    p.write_text(p.read_text() + "AUTH_LEGACY_ADMIN_TOKEN=1\n")
    r = _ensure(p, "--check")
    assert "ADMIN_TOKEN: MISSING" in r.stdout


def test_ensure_env_refuses_duplicates(tmp_path: Path):
    p = tmp_path / ".env"
    p.write_text("CLOUD_API_KEY=a\nCLOUD_API_KEY=b\n")
    r = _ensure(p)
    assert r.returncode == 2 and "duplicate" in r.stderr.lower()


def test_ensure_env_store_default_matches_cloud_app():
    # the required-secret rules must see the same STORE_BACKEND the app would use when .env does not set it
    from cloud.app.config import settings_from_env
    from cloud.tools import ensure_env

    from .conftest import DUMMY_ENV

    app_default = settings_from_env(dict(DUMMY_ENV), load_env_file=False).store_backend
    assert ensure_env.store_backend({}) == app_default
    assert ensure_env.store_backend({"STORE_BACKEND": " DynamoDB "}) == "dynamodb"
