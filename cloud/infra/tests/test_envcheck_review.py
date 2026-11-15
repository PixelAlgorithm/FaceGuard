"""CI-02 / CI-05 / CI-10: deploy preflight mirrors what cloud/app/config.py + cloud/app/rbac.py accept.

Every rendered Lambda environment is fed to the real `settings_from_env` (the cloud's startup check), so the
tooling cannot drift from the app again. Dummy values only.
"""

# ruff: noqa: S603, S607, S105, S106, S108

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cloud.app.config import ConfigError, settings_from_env
from cloud.app.rbac import MAX_KEY_NAME
from cloud.tools import apikey, envfile

from .conftest import DUMMY_ENV, DUMMY_SECRETS, INFRA

NOW = datetime(2026, 11, 15, tzinfo=UTC)
BASE = {k: v for k, v in DUMMY_SECRETS.items() if k not in ("ADMIN_TOKEN", "ALLOW_SHARED_KIOSK_KEY", "KIOSK_HMAC_KEY")}
SHARED = {"ALLOW_SHARED_KIOSK_KEY": "1", "KIOSK_HMAC_KEY": DUMMY_SECRETS["KIOSK_HMAC_KEY"]}
PER_KIOSK = {"KIOSK_KEYS_JSON": json.dumps({"KIOSK_MAIN_01": "dummy-per-kiosk-key-0123456789"})}
LEGACY = {"AUTH_LEGACY_ADMIN_TOKEN": "1", "ADMIN_TOKEN": DUMMY_SECRETS["ADMIN_TOKEN"]}


def _minted_keys() -> str:
    entries = [
        apikey.build_entry("ops laptop", ("auditor",), [], 30, NOW)[1],
        apikey.build_entry("break glass", ("admin",), [], None, NOW)[1],
        apikey.build_entry("edge main", ("edge_proxy",), ["KIOSK_MAIN_01"], None, NOW)[1],
    ]
    return json.dumps(entries)


def _make(tmp_path: Path, env_lines: dict[str, str], *args: str, fmt: str = "lambda") -> subprocess.CompletedProcess:
    envf = tmp_path / "dot.env"
    envf.write_text("".join(f"{k}={v}\n" for k, v in env_lines.items()))
    return subprocess.run([sys.executable, str(INFRA / "make_app_env.py"), "--env-file", str(envf),
                           "--out", str(tmp_path / "out.json"), "--format", fmt,
                           "--seed-schedule", "config/schedule.demo.json", "--demo", *args],
                          capture_output=True, text=True, timeout=60)


def _no_secret(text: str) -> None:
    for name, value in DUMMY_SECRETS.items():
        assert value not in text, f"{name} leaked"


# --------------------------------------------------------------------------- CI-10 positive combinations
COMBOS = {
    "shared": {**BASE, **SHARED},
    "shared+legacy": {**BASE, **SHARED, **LEGACY},
    "per-kiosk": {**BASE, **PER_KIOSK},
    "per-kiosk+legacy": {**BASE, **PER_KIOSK, **LEGACY},
    "per-kiosk+minted-keys": {**BASE, **PER_KIOSK, "CLOUD_API_KEYS_JSON": "MINT"},
    "shared+per-kiosk+minted-keys+legacy": {**BASE, **SHARED, **PER_KIOSK, **LEGACY, "CLOUD_API_KEYS_JSON": "MINT"},
}


@pytest.mark.parametrize("combo", sorted(COMBOS))
def test_rendered_lambda_env_is_accepted_by_cloud_settings(tmp_path: Path, combo: str):
    env = {k: (_minted_keys() if v == "MINT" else v) for k, v in COMBOS[combo].items()}
    r = _make(tmp_path, env)
    assert r.returncode == 0, r.stderr
    _no_secret(r.stdout + r.stderr)
    variables = json.loads((tmp_path / "out.json").read_text())["Variables"]
    s = settings_from_env(variables, load_env_file=False)  # raises ConfigError if the cloud would refuse it
    assert s.auth_legacy_admin_token == ("AUTH_LEGACY_ADMIN_TOKEN" in env)
    if "CLOUD_API_KEYS_JSON" in env:
        assert {e.name for e in s.cloud_api_keys} == {"ops laptop", "break glass", "edge main"}


def test_dummy_secrets_fixture_is_a_config_the_cloud_accepts():
    settings_from_env({**DUMMY_ENV, "STORE_BACKEND": "dynamodb"}, load_env_file=False)


# --------------------------------------------------------------------------- CI-02 kiosk-key rule
def test_no_kiosk_keys_is_refused_like_the_cloud(tmp_path: Path):
    env = {**BASE, "KIOSK_HMAC_KEY": DUMMY_SECRETS["KIOSK_HMAC_KEY"]}  # shared key present, flag off
    with pytest.raises(ConfigError, match="no kiosk keys"):
        settings_from_env({**env, "STORE_BACKEND": "dynamodb"}, load_env_file=False)
    r = _make(tmp_path, env)
    assert r.returncode == 2
    assert "no kiosk keys" in r.stderr and "ALLOW_SHARED_KIOSK_KEY=1" in r.stderr
    _no_secret(r.stdout + r.stderr)
    assert not (tmp_path / "out.json").exists()


def test_empty_kiosk_keys_json_counts_as_no_kiosk_keys(tmp_path: Path):
    r = _make(tmp_path, {**BASE, "KIOSK_KEYS_JSON": "{}"})
    assert r.returncode == 2 and "no kiosk keys" in r.stderr


def test_envfile_kiosk_rule_mirrors_config():
    assert envfile.kiosk_rule_problems({}) == [envfile.NO_KIOSK_KEYS]
    assert envfile.kiosk_rule_problems({"KIOSK_HMAC_KEY": "x"}) == [envfile.NO_KIOSK_KEYS]
    assert envfile.kiosk_rule_problems({"KIOSK_KEYS_JSON": "{}"}) == [envfile.NO_KIOSK_KEYS]
    assert envfile.kiosk_rule_problems({"ALLOW_SHARED_KIOSK_KEY": "1", "KIOSK_HMAC_KEY": "x"}) == []
    assert envfile.kiosk_rule_problems(PER_KIOSK) == []
    # shared flag without the key: reported as a missing secret, like config.py
    assert "KIOSK_HMAC_KEY" in envfile.required_cloud_secrets({"ALLOW_SHARED_KIOSK_KEY": "1"}, "dynamodb")
    assert "KIOSK_HMAC_KEY" not in envfile.required_cloud_secrets(PER_KIOSK, "dynamodb")


def test_ensure_env_reports_no_kiosk_keys(tmp_path: Path):
    p = tmp_path / ".env"
    p.write_text("".join(f"{k}={v}\n" for k, v in {**BASE, "KIOSK_HMAC_KEY": "dummy-k"}.items()))
    r = subprocess.run([sys.executable, "-m", "cloud.tools.ensure_env", "--env-file", str(p), "--check"],
                       cwd=INFRA.parents[1], capture_output=True, text=True, timeout=60)
    assert "no kiosk keys" in r.stdout
    _no_secret(r.stdout + r.stderr)


def test_make_app_env_refuses_on_cloud_config_error(tmp_path: Path, monkeypatch, capsys):
    sys.path.insert(0, str(INFRA))
    import make_app_env  # type: ignore[import-not-found]

    def boom(values):
        raise ConfigError("synthetic refusal from settings_from_env")

    monkeypatch.setattr(make_app_env, "_cloud_settings_check", lambda: boom)
    envf = tmp_path / "dot.env"
    envf.write_text("".join(f"{k}={v}\n" for k, v in {**BASE, **SHARED}.items()))
    out = tmp_path / "o.json"
    rc = make_app_env.main(["--env-file", str(envf), "--out", str(out), "--format", "lambda",
                            "--seed-schedule", "config/schedule.demo.json", "--demo"])
    err = capsys.readouterr().err
    assert rc == 2 and "synthetic refusal" in err and not out.exists()
    _no_secret(err)


def test_make_app_env_falls_back_when_cloud_app_not_importable(tmp_path: Path, monkeypatch, capsys):
    sys.path.insert(0, str(INFRA))
    import make_app_env  # type: ignore[import-not-found]

    monkeypatch.setattr(make_app_env, "_cloud_settings_check", lambda: None)
    envf = tmp_path / "dot.env"
    envf.write_text("".join(f"{k}={v}\n" for k, v in {**BASE, **SHARED}.items()))
    rc = make_app_env.main(["--env-file", str(envf), "--out", str(tmp_path / "o.json"), "--format", "lambda",
                            "--seed-schedule", "config/schedule.demo.json", "--demo"])
    assert rc == 0
    assert "structural checks only" in capsys.readouterr().err


def test_make_app_env_hides_non_config_exception_text(tmp_path: Path, monkeypatch, capsys):
    sys.path.insert(0, str(INFRA))
    import make_app_env  # type: ignore[import-not-found]

    def boom(values):
        raise ValueError("invalid literal for int() with base 10: 'dummy-secret-looking-value'")

    monkeypatch.setattr(make_app_env, "_cloud_settings_check", lambda: boom)
    envf = tmp_path / "dot.env"
    envf.write_text("".join(f"{k}={v}\n" for k, v in {**BASE, **SHARED}.items()))
    rc = make_app_env.main(["--env-file", str(envf), "--out", str(tmp_path / "o.json"), "--format", "lambda",
                            "--seed-schedule", "config/schedule.demo.json", "--demo"])
    err = capsys.readouterr().err
    assert rc == 2 and "ValueError" in err and "dummy-secret-looking-value" not in err


# --------------------------------------------------------------------------- Lambda 4 KB limit
def test_lambda_env_over_4kb_is_refused(tmp_path: Path):
    many = json.dumps({f"KIOSK_{i:03d}": "k" * 40 for i in range(80)})
    r = _make(tmp_path, {**BASE, "KIOSK_KEYS_JSON": many})
    assert r.returncode == 2
    assert "4096" in r.stderr and "Secrets Manager" in r.stderr
    assert not (tmp_path / "out.json").exists()
    r = _make(tmp_path, {**BASE, "KIOSK_KEYS_JSON": many}, fmt="env")  # EC2 env file has no such limit
    assert r.returncode == 0, r.stderr


# --------------------------------------------------------------------------- CI-05 key name length
def test_apikey_name_limit_matches_rbac():
    assert apikey.NAME_MAX == MAX_KEY_NAME
    apikey.build_entry("n" * MAX_KEY_NAME, ("auditor",), [], None, NOW)
    apikey.build_entry("  " + "n" * MAX_KEY_NAME + "  ", ("auditor",), [], None, NOW)  # stripped length counts
    with pytest.raises(ValueError, match=str(MAX_KEY_NAME)):
        apikey.build_entry("n" * 70, ("auditor",), [], None, NOW)


def test_apikey_cli_refuses_long_name():
    r = subprocess.run([sys.executable, "-m", "cloud.tools.apikey", "--name", "n" * 70, "--roles", "auditor"],
                       cwd=INFRA.parents[1], capture_output=True, text=True, timeout=60)
    assert r.returncode == 2 and "fgk_" not in r.stdout


def test_long_key_name_is_refused_by_preflight(tmp_path: Path):
    _key, entry = apikey.build_entry("short", ("auditor",), [], None, NOW)
    entry["name"] = "n" * 70
    raw = json.dumps([entry])
    with pytest.raises(ConfigError):
        settings_from_env({**BASE, **SHARED, "CLOUD_API_KEYS_JSON": raw}, load_env_file=False)
    assert any("name" in p for p in envfile.api_key_entries_problems(raw))
    r = _make(tmp_path, {**BASE, **SHARED, "CLOUD_API_KEYS_JSON": raw})
    assert r.returncode == 2 and "name" in r.stderr
    assert not (tmp_path / "out.json").exists()


# --------------------------------------------------------------------------- deploy_lambda: health before alias
def _lambda_apply_rules(h, health_body: str | None = '{"statusCode": 200, "body": "{}"}', invoke_rc: int = 0):
    """Front-loaded rules (first match wins) so they override the fixture's default healthy invoke."""
    front = []
    if health_body is not None or invoke_rc:
        front.append({"tool": "aws", "match": ["lambda invoke"], "rc": invoke_rc,
                      "stdout": '{"StatusCode": 200}' if not invoke_rc else "",
                      "stderr": "An error occurred (ServiceException)" if invoke_rc else "",
                      "write_last": health_body if not invoke_rc else None, "once": False})
    h.rules[:0] = front
    h.rules_file.write_text(json.dumps(h.rules))
    h.not_found("iam", "get-role", code="NoSuchEntity")
    h.not_found("lambda", "get-function")
    h.rule("publish-version", stdout="7\n")
    h.rule("get-alias", stdout="{}")
    h.rule("get-apis", stdout="api123\n")


def test_deploy_lambda_checks_new_version_health_before_alias(h):
    _lambda_apply_rules(h)
    r = h.run("deploy_lambda.sh", "--apply", "--skip-build", "--demo")
    assert r.returncode == 0, r.stdout + r.stderr
    calls = h.joined_calls()
    i_inv = next(i for i, c in enumerate(calls) if "lambda invoke" in c)
    i_alias = next(i for i, c in enumerate(calls) if "update-alias" in c)
    assert i_inv < i_alias
    inv = calls[i_inv]
    assert "--qualifier 7" in inv and "--cli-binary-format raw-in-base64-out" in inv and "--payload file://" in inv
    assert "--function-version 7" in calls[i_alias]
    _no_secret(r.stdout + r.stderr)


@pytest.mark.parametrize("body,rc", [('{"statusCode": 503, "body": "{}"}', 0), ('{"errorMessage": "boom"}', 0),
                                     ("", 0), (None, 254)])
def test_deploy_lambda_unhealthy_version_never_gets_the_alias(h, body, rc):
    _lambda_apply_rules(h, health_body=body, invoke_rc=rc)
    r = h.run("deploy_lambda.sh", "--apply", "--skip-build", "--demo")
    assert r.returncode != 0
    assert "/v1/health" in r.stderr and "alias" in r.stderr
    calls = h.joined_calls()
    assert not any("update-alias" in c or "create-alias" in c for c in calls)
    assert not any("create-api" in c for c in calls)
    _no_secret(r.stdout + r.stderr)


def test_deploy_lambda_plan_prints_health_invoke(h):
    r = h.run("deploy_lambda.sh", "--skip-build", "--demo")
    assert r.returncode == 0, r.stdout + r.stderr
    out = r.stdout
    assert "lambda invoke" in out and "--qualifier" in out and "raw-in-base64-out" in out
    assert out.index("lambda invoke") < out.index("create-alias")
    assert not h.calls()  # PLAN makes no AWS call


def test_health_event_is_an_http_api_v2_get_health(tmp_path: Path):
    out = tmp_path / "ev.json"
    r = subprocess.run([sys.executable, str(INFRA / "make_app_env.py"), "--health-event", str(out)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    ev = json.loads(out.read_text())
    assert ev["version"] == "2.0" and ev["rawPath"] == "/v1/health" and ev["rawQueryString"] == ""
    assert ev["requestContext"]["http"]["method"] == "GET" and ev["requestContext"]["http"]["path"] == "/v1/health"
    assert ev["isBase64Encoded"] is False


def test_health_check_parser(tmp_path: Path):
    sys.path.insert(0, str(INFRA))
    import make_app_env  # type: ignore[import-not-found]

    p = tmp_path / "resp.json"
    for body, ok in (('{"statusCode": 200}', True), ('{"statusCode": "200"}', False), ('{"statusCode": 500}', False),
                     ('{"errorMessage": "x"}', False), ("", False), ("[1]", False)):
        p.write_text(body)
        assert make_app_env.main(["--check-health-response", str(p)]) == (0 if ok else 1), body
