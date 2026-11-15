"""SessionManager (monotonic timers), AuditLog (HMAC chain, rotation, scrubbing, aggregation), AuthConfig."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from edge.auth import tokens
from edge.auth.audit import AuditLog
from edge.auth.config import DEFAULT_MFA_REQUIRED_ROLES, AuthConfig
from edge.auth.keys import audit_mac_key
from edge.auth.sessions import SessionManager
from edge.tests import test_auth_support as support
from edge.tests.test_auth_support import DATA_KEY, OTHER_KEY, FakeClock

clock = support.clock


def manager(clock: FakeClock, **kw: int) -> SessionManager:
    opts = {"idle_timeout_s": 1800, "max_age_s": 12 * 3600, "max_per_user": 5, **kw}
    return SessionManager(clock=clock, monotonic=clock.mono, **opts)


# ------------------------------------------------------------------ sessions
def test_session_token_format_and_only_digest_is_kept(clock: FakeClock) -> None:
    sm = manager(clock)
    token, session = sm.create("s_guard01", 0)
    assert tokens.is_session_token(token) and session.token_sha256 == tokens.digest(token)
    assert token not in repr(session) and session.session_id == session.token_sha256[:16]
    assert sm.lookup(token) == session


def test_idle_expiry_without_activity_and_polls_never_extend(clock: FakeClock) -> None:
    sm = manager(clock)
    token, _ = sm.create("s_guard01", 0)
    clock.advance(1700)
    assert sm.lookup(token) is not None  # a GET poll: no touch
    clock.advance(101)
    assert sm.lookup(token) is None


def test_activity_extends_idle_but_never_the_absolute_lifetime(clock: FakeClock) -> None:
    sm = manager(clock, idle_timeout_s=600, max_age_s=3600)
    token, _ = sm.create("s_guard01", 0)
    for _ in range(5):
        clock.advance(590)
        assert sm.lookup(token, touch=True) is not None
    clock.advance(660)  # 3610 s after creation
    assert sm.lookup(token, touch=True) is None


def test_wall_clock_jumps_do_not_move_session_timers(clock: FakeClock) -> None:
    sm = manager(clock, idle_timeout_s=600)
    token, _ = sm.create("s_guard01", 0)
    clock.now = clock.now.replace(year=2030)  # demo/runtime clock games must not expire or extend sessions
    assert sm.lookup(token) is not None


def test_oldest_sessions_are_evicted_over_the_cap(clock: FakeClock) -> None:
    sm = manager(clock, max_per_user=2)
    first, _ = sm.create("s_guard01", 0)
    clock.advance(1)
    second, _ = sm.create("s_guard01", 0)
    clock.advance(1)
    third, _ = sm.create("s_guard01", 0)
    other, _ = sm.create("s_guard02", 0)
    assert sm.lookup(first) is None and sm.lookup(second) and sm.lookup(third) and sm.lookup(other)


def test_revoke_and_revoke_all_except_current(clock: FakeClock) -> None:
    sm = manager(clock)
    a, sa = sm.create("s_guard01", 0)
    b, _ = sm.create("s_guard01", 0)
    c, sc = sm.create("s_guard02", 0)
    assert sm.revoke_all("s_guard01", except_session_id=sa.session_id) == 1
    assert sm.lookup(a) and sm.lookup(b) is None
    assert sm.revoke(sc.session_id) and sm.lookup(c) is None


# ------------------------------------------------------------------ audit
def audit_log(tmp_path: Path, clock: FakeClock, **kw: int) -> AuditLog:
    opts = {"max_bytes": 1024 * 1024, "keep": 3, **kw}
    return AuditLog(tmp_path, mac_key=audit_mac_key(DATA_KEY), clock=clock, **opts)


def test_chain_verifies_and_detects_tampering(tmp_path: Path, clock: FakeClock) -> None:
    log = audit_log(tmp_path, clock)
    for i in range(5):
        log.append("staff.update", actor={"kind": "staff", "id": "s_admin01", "username": "admin01"},
                   target=f"s_u{i}")
    assert log.verify()
    assert stat.S_IMODE(log.path.stat().st_mode) == 0o600
    lines = log.path.read_text().splitlines()
    forged = json.loads(lines[2])
    forged["target"] = "s_someone_else"
    lines[2] = json.dumps(forged, sort_keys=True, separators=(",", ":"))
    log.path.write_text("\n".join(lines) + "\n")
    assert not log.verify()


def test_mac_needs_the_key(tmp_path: Path, clock: FakeClock) -> None:
    audit_log(tmp_path, clock).append("auth.login")
    assert not AuditLog(tmp_path, mac_key=audit_mac_key(OTHER_KEY), max_bytes=10**6, keep=3).verify()


def test_rotation_keeps_n_files_and_chains_across_them(tmp_path: Path, clock: FakeClock) -> None:
    log = audit_log(tmp_path, clock, max_bytes=64 * 1024, keep=2)
    for i in range(700):
        log.append("auth.login", detail={"i": i, "pad": "x" * 150})
    files = log.files()
    assert len(files) == 3 and not (tmp_path / "audit.jsonl.3").exists()
    first_of_current = json.loads(files[0].read_text().splitlines()[0])
    last_of_previous = json.loads(files[1].read_text().splitlines()[-1])
    assert first_of_current["prev_mac"] == last_of_previous["mac"]
    assert first_of_current["seq"] == last_of_previous["seq"] + 1
    assert log.verify()


def test_entries_never_contain_secrets(tmp_path: Path, clock: FakeClock) -> None:
    log = audit_log(tmp_path, clock)
    token = tokens.new_session_token()
    _, api_key, _ = tokens.new_api_key()
    log.append("auth.password_change", detail={
        "password": "hunter2-hunter2", "new_password": "x", "totp_code": "123456", "token": token,
        "note": f"Bearer {api_key}", "uri": "otpauth://totp/FaceGuard:x?secret=ABC", "nested": {"secret": "s"},
        "key_id": "abcd1234", "hash": "scrypt$15$8$3$AAAA$BBBB"})
    text = log.path.read_text()
    for secret in ("hunter2", "123456", token, api_key, "otpauth", "ABC", "scrypt$"):
        assert secret not in text
    assert "abcd1234" in text


def test_read_pages_newest_first(tmp_path: Path, clock: FakeClock) -> None:
    log = audit_log(tmp_path, clock)
    for i in range(7):
        log.append("auth.login", detail={"i": i})
    page, cursor = log.read(limit=3)
    assert [e["seq"] for e in page] == [7, 6, 5] and cursor == 5
    page, cursor = log.read(limit=3, before_seq=cursor)
    assert [e["seq"] for e in page] == [4, 3, 2]
    page, cursor = log.read(limit=3, before_seq=cursor)
    assert [e["seq"] for e in page] == [1] and cursor is None


def test_denials_are_aggregated_per_actor_route_reason_minute(tmp_path: Path, clock: FakeClock) -> None:
    log = audit_log(tmp_path, clock)
    actor = {"kind": "staff", "id": "s_guard01", "username": "guard01"}
    for _ in range(4):
        log.record_denial(actor=actor, route="/v1/admin/mode", reason="MISSING_PERMISSION",
                          required=["mode:switch"])
    log.record_denial(actor=actor, route="/v1/admin/sync", reason="MISSING_PERMISSION", required=["sync:run"])
    assert not log.path.exists()  # the minute is still open
    clock.advance(60)
    entries, _ = log.read()
    counts = {e["target"]: e["count"] for e in entries if e["action"] == "auth.denied"}
    assert counts == {"/v1/admin/mode": 4, "/v1/admin/sync": 1}
    assert log.verify()


# ------------------------------------------------------------------ config
def test_config_defaults_match_the_design() -> None:
    cfg = AuthConfig.from_env({})
    assert (cfg.session_idle_min, cfg.session_max_hours, cfg.max_sessions_per_user) == (30, 12, 5)
    assert (cfg.lockout_threshold, cfg.lockout_min, cfg.login_global_max, cfg.login_global_window_min) == \
        (5, 15, 60, 5)
    assert not cfg.legacy_admin_token_enabled and cfg.legacy_admin_token == ""
    assert cfg.mfa_required_roles == DEFAULT_MFA_REQUIRED_ROLES == {"admin", "security_officer"}
    assert (cfg.audit_max_bytes, cfg.audit_keep) == (5 * 1024 * 1024, 5)


def test_config_legacy_token_only_kept_when_flag_on() -> None:
    assert AuthConfig.from_env({}, legacy_admin_token="tok").legacy_admin_token == ""
    on = AuthConfig.from_env({"AUTH_LEGACY_ADMIN_TOKEN": "1"}, legacy_admin_token="zz-dummy-legacy-zz")
    assert on.legacy_admin_token_enabled and "zz-dummy-legacy-zz" not in repr(on)
    assert AuthConfig.from_env({"AUTH_MFA_REQUIRED_ROLES": "none"}).mfa_required_roles == frozenset()


@pytest.mark.parametrize(("env", "name"), [
    ({"AUTH_SESSION_IDLE_MIN": "0"}, "AUTH_SESSION_IDLE_MIN"),
    ({"AUTH_SESSION_MAX_HOURS": "abc"}, "AUTH_SESSION_MAX_HOURS"),
    ({"AUTH_LOCKOUT_THRESHOLD": "1000"}, "AUTH_LOCKOUT_THRESHOLD"),
    ({"AUTH_LEGACY_ADMIN_TOKEN": "maybe"}, "AUTH_LEGACY_ADMIN_TOKEN"),
    ({"AUTH_LEGACY_ADMIN_TOKEN": "1"}, "ADMIN_TOKEN"),
    ({"AUTH_MFA_REQUIRED_ROLES": "admin,root"}, "AUTH_MFA_REQUIRED_ROLES"),
    ({"AUTH_SESSION_IDLE_MIN": "600", "AUTH_SESSION_MAX_HOURS": "2"}, "AUTH_SESSION_IDLE_MIN"),
])
def test_config_errors_name_the_variable(env: dict[str, str], name: str) -> None:
    with pytest.raises(ValueError, match=name):
        AuthConfig.from_env(env)


@pytest.mark.parametrize("raw", ["", "   ", " , "])
def test_empty_mfa_roles_keep_the_default_only_none_disables(raw: str) -> None:
    # a copied .env line `AUTH_MFA_REQUIRED_ROLES=` must not silently turn MFA off for admins
    assert AuthConfig.from_env({"AUTH_MFA_REQUIRED_ROLES": raw}).mfa_required_roles == DEFAULT_MFA_REQUIRED_ROLES
    assert AuthConfig.from_env({"AUTH_MFA_REQUIRED_ROLES": "NONE"}).mfa_required_roles == frozenset()


@pytest.mark.parametrize(("raw", "expected"), [(None, False), ("", False), ("0", False), ("1", True),
                                               ("true", True), (" YES ", True), ("off", False)])
def test_legacy_token_enabled_matches_auth_config(raw: str | None, expected: bool) -> None:
    from edge.auth.config import legacy_token_enabled

    env = {} if raw is None else {"AUTH_LEGACY_ADMIN_TOKEN": raw}
    assert legacy_token_enabled(env) is expected
    assert AuthConfig.from_env(env, legacy_admin_token="zz-dummy-zz").legacy_admin_token_enabled is expected
    with pytest.raises(ValueError, match="AUTH_LEGACY_ADMIN_TOKEN"):
        legacy_token_enabled({"AUTH_LEGACY_ADMIN_TOKEN": "maybe"})
