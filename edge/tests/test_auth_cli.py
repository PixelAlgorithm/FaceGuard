"""`python -m edge.auth` CLI: create-user via stdin then login works, API keys for scripts, MFA enrolment,
exit codes (0 / 2 usage / 75 busy / 1 other), no secrets in listings."""

from __future__ import annotations

import fcntl
import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from edge.auth import cli, mfa
from edge.auth.models import AuthError, utc_now
from edge.auth.service import build_auth_service
from edge.config import PROJECT_ROOT
from edge.tests import test_auth_support as support
from edge.tests.test_auth_support import DATA_KEY, OTHER_KEY, USER_PW

fast_scrypt = support.fast_scrypt


def run(env: dict[str, str], *argv: str, stdin: str | io.StringIO = "") -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    source = stdin if isinstance(stdin, io.StringIO) else io.StringIO(stdin)
    code = cli.main(list(argv), env=env, stdin=source, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def env(tmp_path: Path, fast_scrypt: None) -> dict[str, str]:
    return {"EDGE_DATA_DIR": str(tmp_path), "EDGE_DATA_KEY": DATA_KEY, "AUTH_MFA_REQUIRED_ROLES": "none"}


def create(env: dict[str, str], username: str = "guard01", *roles: str) -> tuple[int, str, str]:
    role_args = [a for r in (roles or ("security_officer",)) for a in ("--role", r)]
    return run(env, "create-user", "--username", username, "--display-name", "Guard One", *role_args,
               "--password-stdin", stdin=USER_PW + "\n")


def test_create_user_then_login_works(env: dict[str, str]) -> None:
    code, out, _ = create(env)
    assert code == 0 and "s_guard01" in out and USER_PW not in out
    auth = build_auth_service(Path(env["EDGE_DATA_DIR"]), env)
    _, _, principal = auth.login_sync("guard01", USER_PW)
    assert principal.roles == ("security_officer",) and principal.pending_action is None
    entries, _ = auth.audit.read()
    create_entry = next(e for e in entries if e["action"] == "staff.create")
    assert create_entry["actor"]["kind"] == "cli" and create_entry["actor"]["id"].startswith("cli:")
    auth.close()


def test_temporary_password_forces_a_change(env: dict[str, str]) -> None:
    run(env, "create-user", "--username", "temp01", "--display-name", "T", "--role", "auditor",
        "--password-stdin", "--temporary", stdin=USER_PW + "\n")
    auth = build_auth_service(Path(env["EDGE_DATA_DIR"]), env)
    assert auth.login_sync("temp01", USER_PW)[2].pending_action == "PASSWORD_CHANGE_REQUIRED"
    auth.close()


def test_create_api_key_print_key_only_is_one_line(env: dict[str, str]) -> None:
    code, out, err = run(env, "create-api-key", "--name", "bench", "--role", "evaluator", "--role", "enroller",
                         "--expires-days", "1", "--print-key-only")
    assert code == 0 and re.fullmatch(r"fgk_[a-z0-9]{8}\.[A-Za-z0-9_-]{43}\n", out)
    assert "created API key" in err and out.strip() not in err
    auth = build_auth_service(Path(env["EDGE_DATA_DIR"]), env)
    principal = auth.authenticate(out.strip())
    assert principal.kind == "api_key" and "eval:admin" in principal.permissions
    assert "enrol:erase" not in principal.permissions
    auth.close()


def test_list_json_has_no_secrets(env: dict[str, str]) -> None:
    create(env)
    _, key, _ = run(env, "create-api-key", "--name", "bench", "--role", "auditor", "--print-key-only")
    code, out, _ = run(env, "list", "--json")
    doc = json.loads(out)
    assert code == 0 and doc["store"] == "OK" and doc["staff"][0]["staff_id"] == "s_guard01"
    for secret in (USER_PW, "scrypt", key.strip(), key.strip().split(".")[1], "secret_sha256", "password_hash"):
        assert secret not in out


def test_enable_mfa_reads_the_code_and_login_then_needs_it(env: dict[str, str]) -> None:
    create(env)

    class CodeFromSecret(io.StringIO):
        def __init__(self, out: io.StringIO) -> None:
            super().__init__()
            self.out = out

        def readline(self, *_: object) -> str:
            secret = re.search(r"secret: ([A-Z2-7]+)", self.out.getvalue()).group(1)  # type: ignore[union-attr]
            return mfa.code_at(secret, mfa.current_step(utc_now())) + "\n"

    out, err = io.StringIO(), io.StringIO()
    code = cli.main(["enable-mfa", "--username", "guard01"], env=env, stdin=CodeFromSecret(out), stdout=out,
                    stderr=err)
    assert code == 0 and "MFA enabled" in out.getvalue() and "otpauth://" in out.getvalue()
    auth = build_auth_service(Path(env["EDGE_DATA_DIR"]), env)
    with pytest.raises(AuthError) as need:
        auth.login_sync("guard01", USER_PW)
    assert need.value.reason == "MFA_REQUIRED"
    auth.close()
    assert run(env, "disable-mfa", "--username", "guard01")[0] == 0


def test_exit_codes(env: dict[str, str], tmp_path: Path) -> None:
    assert run(env, "no-such-command")[0] == cli.EXIT_USAGE
    assert create(env, "admin", "auditor")[0] == cli.EXIT_USAGE  # reserved username
    assert run(env, "disable", "--username", "ghost01")[0] == cli.EXIT_USAGE
    weak = run(env, "create-user", "--username", "weak01", "--display-name", "W", "--role", "auditor",
               "--password-stdin", stdin="short\n")
    assert weak[0] == cli.EXIT_USAGE and "PASSWORD" not in weak[1] and "policy" in weak[2]
    create(env, "boss01", "admin")
    code, _, err = run(env, "disable", "--username", "boss01")
    assert code == cli.EXIT_USAGE and "LAST_ADMIN" in err
    assert run({**env, "EDGE_DATA_KEY": OTHER_KEY}, "list")[0] == cli.EXIT_ERROR  # store unreadable
    assert run({**env, "AUTH_SESSION_IDLE_MIN": "zero"}, "list")[0] == cli.EXIT_USAGE


def test_busy_store_exits_75(env: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from edge.auth import store as store_mod

    fd = os.open(tmp_path / "staff.lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        original = store_mod.StaffStore.__init__

        def short_timeout(self: store_mod.StaffStore, *a: object, **kw: object) -> None:
            kw["lock_timeout_s"] = 0.2
            original(self, *a, **kw)  # type: ignore[arg-type]

        monkeypatch.setattr(store_mod.StaffStore, "__init__", short_timeout)
        assert create(env)[0] == cli.EXIT_BUSY
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def test_module_entry_point_runs(env: dict[str, str]) -> None:
    child_env = {**os.environ, **env, "PYTHONPATH": str(PROJECT_ROOT)}
    proc = subprocess.run([sys.executable, "-m", "edge.auth", "list"], env=child_env, capture_output=True, check=False,
                          text=True, timeout=120)
    assert proc.returncode == 0 and "store: EMPTY" in proc.stdout


def test_rekey_needs_force_because_a_running_edge_loses_staff_auth(env: dict[str, str]) -> None:
    create(env)
    new_key = Fernet.generate_key().decode()  # dummy, test-only
    code, out, err = run(env, "rekey", stdin=new_key + "\n")
    assert code == cli.EXIT_USAGE and out == ""
    for words in ("--force", "503 AUTH_UNAVAILABLE", "STAFF_STORE_KEY", "stop the edge"):
        assert words in err
    assert new_key not in err
    assert run(env, "list")[0] == cli.EXIT_OK  # nothing was re-encrypted

    code, out, err = run(env, "rekey", "--force", stdin=new_key + "\n")
    assert code == cli.EXIT_OK and "re-encrypted" in out
    assert "503 AUTH_UNAVAILABLE" in err and new_key not in out + err
    assert run(env, "list")[0] == cli.EXIT_ERROR  # the old key no longer opens it
    code, out, _ = run({**env, "STAFF_STORE_KEY": new_key}, "list")
    assert code == cli.EXIT_OK and "s_guard01" in out
