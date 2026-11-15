"""Edge credentials for the eval tooling: API key first, legacy ADMIN_TOKEN only with the opt-in flag,
clear AuthFailure on 401/403, secrets never in messages. DUMMY values only."""

from __future__ import annotations

import pytest

from evallib import auth as A

KEY = "fgk_dummy001." + "D" * 43
LEGACY = "DUMMY-ADMIN-TOKEN-xyz"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (A.EVAL_KEY_ENV, A.OPS_KEY_ENV, A.LEGACY_FLAG_ENV, A.LEGACY_TOKEN_ENV):
        monkeypatch.delenv(name, raising=False)


def test_api_key_from_env_is_bearer(monkeypatch, tmp_path):
    monkeypatch.setenv(A.EVAL_KEY_ENV, KEY)
    cred = A.load_credential(A.EVAL_KEY_ENV, tmp_path / "none.env")
    assert cred.kind == "api_key" and cred.key_id == "dummy001"
    assert cred.headers() == {"Authorization": f"Bearer {KEY}"}
    assert KEY not in cred.describe() and KEY not in repr(cred)


def test_api_key_from_env_file(tmp_path):
    f = tmp_path / ".env"
    f.write_text(f"FOO=1\nexport {A.OPS_KEY_ENV}={KEY}   # ops key\n")
    cred = A.load_credential(A.OPS_KEY_ENV, f)
    assert cred.kind == "api_key" and cred.source == f".env {A.OPS_KEY_ENV}"


def test_malformed_key_refused_without_echo(monkeypatch, tmp_path):
    monkeypatch.setenv(A.EVAL_KEY_ENV, "not-a-key-SECRETVALUE")
    with pytest.raises(A.AuthFailure) as e:
        A.load_credential(A.EVAL_KEY_ENV, tmp_path / "none.env")
    assert "SECRETVALUE" not in str(e.value)


def test_legacy_token_ignored_without_flag(monkeypatch, tmp_path):
    monkeypatch.setenv(A.LEGACY_TOKEN_ENV, LEGACY)
    with pytest.raises(A.AuthFailure) as e:
        A.load_credential(A.EVAL_KEY_ENV, tmp_path / "none.env")
    assert A.LEGACY_FLAG_ENV in str(e.value) and LEGACY not in str(e.value)


def test_legacy_token_with_flag(monkeypatch, tmp_path):
    f = tmp_path / ".env"
    f.write_text(f"{A.LEGACY_TOKEN_ENV}={LEGACY}\n")
    monkeypatch.setenv(A.LEGACY_FLAG_ENV, "1")
    cred = A.load_credential(A.EVAL_KEY_ENV, f)
    assert cred.kind == "legacy_admin_token" and cred.headers() == {"X-Admin-Token": LEGACY}
    assert LEGACY not in cred.describe()


def test_key_wins_over_legacy(monkeypatch, tmp_path):
    monkeypatch.setenv(A.LEGACY_FLAG_ENV, "1")
    monkeypatch.setenv(A.LEGACY_TOKEN_ENV, LEGACY)
    monkeypatch.setenv(A.EVAL_KEY_ENV, KEY)
    assert A.load_credential(A.EVAL_KEY_ENV, tmp_path / "none.env").kind == "api_key"


@pytest.mark.parametrize("status", [401, 403])
def test_raise_for_auth_names_reason_not_secret(monkeypatch, tmp_path, status):
    monkeypatch.setenv(A.EVAL_KEY_ENV, KEY)
    cred = A.load_credential(A.EVAL_KEY_ENV, tmp_path / "none.env")
    body = {"error": {"code": "FORBIDDEN", "reason": "MISSING_PERMISSION", "required": ["metrics:read"]}}
    with pytest.raises(A.AuthFailure) as e:
        A.raise_for_auth(status, "GET", "/v1/metrics", cred, body)
    msg = str(e.value)
    assert f"HTTP {status}" in msg and "key:dummy001" in msg and KEY not in msg
    if status == 403:
        assert "MISSING_PERMISSION" in msg and "metrics:read" in msg


@pytest.mark.parametrize("status", [200, 204, 404, 409, 500])
def test_raise_for_auth_passes_other_statuses(status):
    A.raise_for_auth(status, "GET", "/v1/x", None)


@pytest.mark.parametrize("url", ["http://127.0.0.1:8000", "http://localhost:8280/", "http://[::1]:8000"])
def test_loopback_edges_accepted(url):
    A.check_edge_url(url)


@pytest.mark.parametrize("url,allow", [("http://192.168.1.20:8000", False), ("http://192.168.1.20:8000", True),
                                       ("https://edge.example", False), ("ftp://127.0.0.1", False),
                                       ("127.0.0.1:8000", False), ("http://127.0.0.1.evil.example", False)])
def test_remote_or_cleartext_edges_refused(url, allow):
    """DE-11: a stale EDGE_URL / typo must not receive the key (cleartext http to a LAN host)."""
    with pytest.raises(A.AuthFailure):
        A.check_edge_url(url, allow)


def test_https_remote_needs_explicit_opt_in():
    A.check_edge_url("https://edge.example:8443", allow_remote=True)


def test_legacy_flag_read_from_env_file_like_the_keys(tmp_path):
    """FG_ALLOW_LEGACY_ADMIN_TOKEN: process env first, then the project .env (same order as the keys)."""
    f = tmp_path / ".env"
    f.write_text(f"{A.LEGACY_FLAG_ENV}=1\n{A.LEGACY_TOKEN_ENV}={LEGACY}\n")
    cred = A.load_credential(A.EVAL_KEY_ENV, f)
    assert cred.kind == "legacy_admin_token"


def test_env_legacy_flag_wins_over_env_file(monkeypatch, tmp_path):
    f = tmp_path / ".env"
    f.write_text(f"{A.LEGACY_FLAG_ENV}=1\n{A.LEGACY_TOKEN_ENV}={LEGACY}\n")
    monkeypatch.setenv(A.LEGACY_FLAG_ENV, "0")
    with pytest.raises(A.AuthFailure):
        A.load_credential(A.EVAL_KEY_ENV, f)
