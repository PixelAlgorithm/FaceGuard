"""AuthService hardening (review 2): audit key without EDGE_DATA_KEY (EAC-08), the actor re-check inside the
store lock (F9), change_password never signs out its own session (F10), MFA enrolment needs re-auth and runs
off the event loop (F6, EAC-02/F3), throttle clearing on unlock (EAC-06), monotonic defaults (EAC-05) and
legacy-token auditing."""

from __future__ import annotations

import asyncio
import inspect
import threading
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from edge.auth import keys, service
from edge.auth.audit import AuditLog
from edge.auth.models import AuthError, Principal, auth_monotonic
from edge.auth.routes import build_router
from edge.auth.service import AuthService, build_auth_service
from edge.errors import install_error_handlers
from edge.tests import test_auth_support as support
from edge.tests.test_auth_support import (
    ADMIN_PW,
    CONSOLE,
    NEW_PW,
    USER_PW,
    FakeClock,
    add_user,
    login,
    make_config,
    make_service,
)

clock = support.clock
fast_scrypt = support.fast_scrypt
OLD_PUBLIC_AUDIT_KEY = b"faceguard-audit-without-edge-data-key"
STORE_KEY = Fernet.generate_key().decode()  # dummy, test-only
FRESH_PW = "zebra-quartz-6612"
LEGACY_TOKEN = "zz-dummy-legacy-admin-token-zz"


def audit_log(data_dir: Path, mac_key: bytes) -> AuditLog:
    return AuditLog(data_dir, mac_key=mac_key, max_bytes=10_000_000, keep=3)


# ------------------------------------------------------------------ EAC-08: no public audit key
def test_audit_key_comes_from_staff_store_key_without_edge_data_key(tmp_path: Path, clock: FakeClock,
                                                                    fast_scrypt: None) -> None:
    auth = AuthService.open(tmp_path, "", make_config(), store_key=STORE_KEY, clock=clock, monotonic=clock.mono)
    add_user(auth, "guard01", ["auditor"])
    auth.close()
    assert audit_log(tmp_path, keys.audit_mac_key("", STORE_KEY)).verify()
    assert not audit_log(tmp_path, OLD_PUBLIC_AUDIT_KEY).verify()


def test_no_key_material_means_a_random_audit_key_and_auth_unavailable(tmp_path: Path, clock: FakeClock) -> None:
    first = AuthService.open(tmp_path, "", make_config(), clock=clock, monotonic=clock.mono)
    second = AuthService.open(tmp_path, "", make_config(), clock=clock, monotonic=clock.mono)
    assert "auth_unavailable" in first.degraded_reasons()
    macs = {first.audit._mac_key, second.audit._mac_key}
    assert OLD_PUBLIC_AUDIT_KEY not in macs and len(macs) == 2
    assert all(len(k) >= 32 for k in macs)
    assert not hasattr(service, "_NO_AUDIT_KEY")


# ------------------------------------------------------------------ F9: actor re-checked inside the store lock
@pytest.fixture
def admins(tmp_path: Path, clock: FakeClock, fast_scrypt: None) -> SimpleNamespace:
    auth = make_service(tmp_path, clock)
    add_user(auth, "boss01", ["admin"], ADMIN_PW)
    add_user(auth, "boss02", ["admin"])
    add_user(auth, "guard01", ["security_officer"])
    key, _ = auth.create_api_key(CONSOLE, "bench", ["auditor"])
    _, actor = login(auth, "boss02")
    return SimpleNamespace(auth=auth, actor=actor, key_id=key.key_id, dir=tmp_path, clock=clock)


MUTATIONS: dict[str, Callable[[AuthService, Principal, str], Any]] = {
    "create_staff": lambda a, p, _k: a.create_staff(p, "evil01", "Evil", ["admin"], FRESH_PW,
                                                    confirm_password=USER_PW),
    "update_staff": lambda a, p, _k: a.update_staff(p, "s_guard01", roles=["admin"], confirm_password=USER_PW),
    "delete_staff": lambda a, p, _k: a.delete_staff(p, "s_guard01", confirm_password=USER_PW),
    "reset_password": lambda a, p, _k: a.reset_password(p, "s_guard01", FRESH_PW, confirm_password=USER_PW),
    "unlock": lambda a, p, _k: a.unlock(p, "s_guard01", confirm_password=USER_PW),
    "create_api_key": lambda a, p, _k: a.create_api_key(p, "evil", ["auditor"], confirm_password=USER_PW),
    "revoke_api_key": lambda a, p, k: a.revoke_api_key(p, k, confirm_password=USER_PW),
    "reset_mfa": lambda a, p, _k: a.reset_mfa(p, "s_guard01", confirm_password=USER_PW),
}

INTERFERENCE: dict[str, tuple[Callable[[AuthService], Any], str, str]] = {
    "demoted": (lambda other: other.update_staff(CONSOLE, "s_boss02", roles=["auditor"]),
                "FORBIDDEN", "MISSING_PERMISSION"),
    "disabled": (lambda other: other.update_staff(CONSOLE, "s_boss02", status="disabled"),
                 "FORBIDDEN", "MISSING_PERMISSION"),
    "deleted": (lambda other: other.delete_staff(CONSOLE, "s_boss02"), "FORBIDDEN", "MISSING_PERMISSION"),
    "epoch_bumped": (lambda other: other.reset_mfa(CONSOLE, "s_boss02"), "UNAUTHORIZED", "SESSION_EXPIRED"),
}


def generation(data_dir: Path, clock: FakeClock) -> int:
    fresh = make_service(data_dir, clock)
    try:
        return fresh.store.snapshot().generation
    finally:
        fresh.close()


@pytest.mark.parametrize("what", sorted(INTERFERENCE))
@pytest.mark.parametrize("op", sorted(MUTATIONS))
def test_actor_lost_rights_during_reauth_commits_nothing(admins: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
                                                         op: str, what: str) -> None:
    auth: AuthService = admins.auth
    other = make_service(admins.dir, admins.clock)  # a second process (or the console) changes B meanwhile
    interfere, code, reason = INTERFERENCE[what]
    real = auth._check_reauth
    seen: dict[str, int] = {}

    def reauth_then_interfere(actor: Principal, password: str | None) -> None:
        real(actor, password)
        interfere(other)
        seen["generation"] = generation(admins.dir, admins.clock)

    monkeypatch.setattr(auth, "_check_reauth", reauth_then_interfere)
    with pytest.raises(AuthError) as err:
        MUTATIONS[op](auth, admins.actor, admins.key_id)
    assert (err.value.code, err.value.reason) == (code, reason)
    assert generation(admins.dir, admins.clock) == seen["generation"]  # nothing written after the change
    data = other.store.snapshot()
    assert "s_evil01" not in data.accounts
    assert data.accounts["s_guard01"].roles == ("security_officer",)
    assert sum(1 for k in data.api_keys.values() if k.created_by == "staff:s_boss02") == 0
    other.close()


def test_unchanged_actor_still_commits_and_console_is_exempt(admins: SimpleNamespace) -> None:
    auth: AuthService = admins.auth
    assert auth.create_staff(admins.actor, "fresh01", "Fresh", ["auditor"], FRESH_PW,
                             confirm_password=USER_PW).staff_id == "s_fresh01"
    assert auth.update_staff(CONSOLE, "s_fresh01", roles=["evaluator"]).roles == ("evaluator",)


def test_signed_out_actor_cannot_manage(admins: SimpleNamespace) -> None:
    auth: AuthService = admins.auth
    auth.logout(admins.actor)
    with pytest.raises(AuthError) as err:
        auth.unlock(admins.actor, "s_guard01", confirm_password=USER_PW)
    assert err.value.reason == "SESSION_EXPIRED"


# ------------------------------------------------------------------ F10: change_password keeps this session
def test_concurrent_authenticate_during_the_password_write_keeps_the_session(
        tmp_path: Path, clock: FakeClock, fast_scrypt: None, monkeypatch: pytest.MonkeyPatch) -> None:
    auth = make_service(tmp_path, clock)
    add_user(auth, "guard01", ["security_officer"])
    token, principal = login(auth, "guard01")
    other_token, _ = login(auth, "guard01")
    real_write = auth.store._write
    seen: list[str] = []

    def write_with_a_concurrent_request(data: Any) -> None:
        real_write(data)
        seen.append(auth.authenticate(token).id)  # e.g. GET /v1/auth/me landing during the commit

    monkeypatch.setattr(auth.store, "_write", write_with_a_concurrent_request)
    real_revoke_all = auth.sessions.revoke_all

    def revoke_all_then_request(*a: Any, **kw: Any) -> int:
        n = real_revoke_all(*a, **kw)
        seen.append(auth.authenticate(token).id)
        return n

    monkeypatch.setattr(auth.sessions, "revoke_all", revoke_all_then_request)
    auth.change_password(principal, USER_PW, NEW_PW)
    assert seen == ["s_guard01", "s_guard01"]
    assert auth.authenticate(token).id == "s_guard01"
    with pytest.raises(AuthError):
        auth.authenticate(other_token)
    assert auth.sessions.get(principal.session_id or "").epoch == auth.store.snapshot().accounts[
        "s_guard01"].session_epoch


def test_failed_password_write_leaves_the_session_and_old_password(
        tmp_path: Path, clock: FakeClock, fast_scrypt: None, monkeypatch: pytest.MonkeyPatch) -> None:
    auth = make_service(tmp_path, clock)
    add_user(auth, "guard01", ["security_officer"])
    token, principal = login(auth, "guard01")

    def broken_write(_: Any) -> None:
        raise AuthError("AUTH_UNAVAILABLE", "disk full")

    monkeypatch.setattr(auth.store, "_write", broken_write)
    with pytest.raises(AuthError):
        auth.change_password(principal, USER_PW, NEW_PW)
    monkeypatch.undo()
    assert auth.authenticate(token).id == "s_guard01"
    assert not auth._pending_epochs
    login(auth, "guard01", USER_PW)


def test_password_change_after_a_concurrent_epoch_bump_fails(
        tmp_path: Path, clock: FakeClock, fast_scrypt: None, monkeypatch: pytest.MonkeyPatch) -> None:
    auth = make_service(tmp_path, clock)
    add_user(auth, "boss01", ["admin"], ADMIN_PW)
    add_user(auth, "guard01", ["security_officer"])
    token, principal = login(auth, "guard01")
    other = make_service(tmp_path, clock)
    real = auth._check_reauth

    def reauth_then_role_change(actor: Principal, password: str | None) -> None:
        real(actor, password)
        other.update_staff(CONSOLE, "s_guard01", roles=["auditor"])

    monkeypatch.setattr(auth, "_check_reauth", reauth_then_role_change)
    with pytest.raises(AuthError) as err:
        auth.change_password(principal, USER_PW, NEW_PW)
    assert err.value.reason == "SESSION_EXPIRED"
    with pytest.raises(AuthError):
        auth.authenticate(token)
    other.close()


# ------------------------------------------------------------------ F6 + EAC-02/F3: MFA enrolment
def test_enroll_own_mfa_always_needs_the_current_password(tmp_path: Path, clock: FakeClock,
                                                           fast_scrypt: None) -> None:
    auth = make_service(tmp_path, clock)
    add_user(auth, "guard01", ["security_officer"])
    _, principal = login(auth, "guard01")
    for password in (None, "", "wrong-password-123"):
        with pytest.raises(AuthError) as err:
            auth.enroll_own_mfa(principal, password)
        assert err.value.reason == "REAUTH_REQUIRED"
    assert auth.store.snapshot().accounts["s_guard01"].mfa_pending_secret is None
    assert auth.enroll_own_mfa(principal, USER_PW).secret


def mini_app(auth: AuthService) -> FastAPI:
    app = FastAPI()
    install_error_handlers(app)

    def get_auth(_: Request) -> AuthService:
        return auth

    app.include_router(build_router(get_auth))
    return app


def test_mfa_enroll_route_runs_store_and_audit_writes_off_the_event_loop(
        tmp_path: Path, clock: FakeClock, fast_scrypt: None, monkeypatch: pytest.MonkeyPatch) -> None:
    auth = make_service(tmp_path, clock)
    add_user(auth, "guard01", ["security_officer"])
    token, _ = login(auth, "guard01")
    on_loop: list[bool] = []

    def running_loop() -> bool:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return False
        return True

    real_update, real_append = auth.store.update, auth.audit.append

    def update(*a: Any, **kw: Any) -> Any:
        on_loop.append(running_loop())
        return real_update(*a, **kw)

    def append(*a: Any, **kw: Any) -> Any:
        on_loop.append(running_loop())
        return real_append(*a, **kw)

    monkeypatch.setattr(auth.store, "update", update)
    monkeypatch.setattr(auth.audit, "append", append)
    c = TestClient(mini_app(auth))
    headers = {"Authorization": f"Bearer {token}"}
    assert c.post("/v1/auth/mfa/enroll", headers=headers).status_code == 422
    assert c.post("/v1/auth/mfa/enroll", headers=headers, json={}).status_code == 422
    r = c.post("/v1/auth/mfa/enroll", headers=headers, json={"current_password": "wrong-password-123"})
    assert r.status_code == 403 and r.json()["error"]["reason"] == "REAUTH_REQUIRED"
    r = c.post("/v1/auth/mfa/enroll", headers=headers, json={"current_password": USER_PW})
    assert r.status_code == 200 and r.json()["secret"]
    assert on_loop and not any(on_loop)
    assert threading.current_thread() is threading.main_thread()


# ------------------------------------------------------------------ EAC-06 / F2: unlock clears the throttle
def test_unlock_and_reset_clear_the_throttle_through_clear_throttle(
        tmp_path: Path, clock: FakeClock, fast_scrypt: None, monkeypatch: pytest.MonkeyPatch) -> None:
    auth = make_service(tmp_path, clock)
    add_user(auth, "guard01", ["security_officer"])
    cleared: list[str] = []
    monkeypatch.setattr(auth, "clear_throttle", cleared.append)
    auth.unlock(CONSOLE, "s_guard01")
    auth.reset_password(CONSOLE, "s_guard01", FRESH_PW)
    assert cleared == ["guard01", "guard01"]


# ------------------------------------------------------------------ EAC-05 + LoginThrottle(monotonic=...)
def test_monotonic_defaults_are_the_sleep_inclusive_auth_clock() -> None:
    for fn in (AuthService.__init__, AuthService.open, build_auth_service):
        assert inspect.signature(fn).parameters["monotonic"].default is auth_monotonic


def test_login_throttle_gets_the_injected_monotonic_when_it_accepts_one(
        tmp_path: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch) -> None:
    received: dict[str, Any] = {}
    real = service.LoginThrottle

    class ThrottleWithMonotonic(real):  # type: ignore[misc, valid-type]
        def __init__(self, *, monotonic: Callable[[], float], **kw: Any) -> None:
            received["monotonic"] = monotonic
            super().__init__(**kw)

    monkeypatch.setattr(service, "LoginThrottle", ThrottleWithMonotonic)
    make_service(tmp_path, clock)
    assert received["monotonic"] == clock.mono


# ------------------------------------------------------------------ legacy token use is aggregated
def test_legacy_token_use_goes_to_record_legacy_use(tmp_path: Path, clock: FakeClock) -> None:
    auth = make_service(tmp_path, clock, legacy_admin_token_enabled=True, legacy_admin_token=LEGACY_TOKEN)
    calls: list[dict[str, Any]] = []
    auth.audit = SimpleNamespace(record_legacy_use=lambda **kw: calls.append(kw))  # type: ignore[assignment]
    auth.authenticate(None, admin_token=LEGACY_TOKEN, client_ip="127.0.0.1", path="/v1/admin/mode")
    assert len(calls) == 1 and calls[0]["actor"]["kind"] == "legacy"
    assert (calls[0]["route"], calls[0]["client_ip"]) == ("/v1/admin/mode", "127.0.0.1")


