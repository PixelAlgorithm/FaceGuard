"""Login flow: indistinguishable failures, progressive throttle, global cap, MFA + tickets + replay, KDF
admission, session invalidation by epoch (also across processes), volatile-field persistence."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

import pytest

from edge.auth import passwords
from edge.auth.models import AuthError
from edge.auth.service import AuthService
from edge.auth.store import STORE_FILE
from edge.tests import test_auth_support as support
from edge.tests.test_auth_support import (
    CONSOLE,
    NEW_PW,
    USER_PW,
    FakeClock,
    add_user,
    code_now,
    enable_mfa,
    login,
    make_service,
)

clock = support.clock
fast_scrypt = support.fast_scrypt
WRONG = "definitely-wrong-pw"


@pytest.fixture
def auth(tmp_path: Path, clock: FakeClock, fast_scrypt: None) -> AuthService:
    service = make_service(tmp_path, clock)
    add_user(service, "guard01", ["security_officer"])
    add_user(service, "boss01", ["admin"])
    return service


def fail(auth: AuthService, username: str, password: str = WRONG, **kw: object) -> AuthError:
    with pytest.raises(AuthError) as err:
        auth.login_sync(username, password, **kw)  # type: ignore[arg-type]
    return err.value


def test_success_returns_token_session_and_principal(auth: AuthService) -> None:
    token, session, principal = auth.login_sync("Guard01 ", USER_PW, client_ip="127.0.0.1")
    assert token.startswith("fgs_") and session.staff_id == "s_guard01"
    assert principal.kind == "staff" and principal.staff_id == "s_guard01"
    assert principal.actor_id == "staff:s_guard01" and "mode:switch" in principal.permissions
    assert auth.authenticate(token).id == "s_guard01"


def test_unknown_user_and_wrong_password_are_indistinguishable(auth: AuthService) -> None:
    wrong, unknown = fail(auth, "guard01"), fail(auth, "nobody99")
    assert (wrong.status, wrong.code, wrong.message, wrong.extra) == \
        (unknown.status, unknown.code, unknown.message, unknown.extra) == \
        (401, "UNAUTHORIZED", "invalid username or password", {"reason": "INVALID_CREDENTIALS"})


def test_unknown_user_still_spends_a_kdf(auth: AuthService, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(passwords, "dummy_verify", lambda pw: calls.append("dummy"))
    fail(auth, "nobody99")
    assert calls == ["dummy"]


@pytest.mark.parametrize("username", ["guard01", "nobody99"])
def test_progressive_delay_after_threshold_for_known_and_unknown(auth: AuthService, clock: FakeClock,
                                                                 username: str) -> None:
    for _ in range(5):
        assert fail(auth, username).reason == "INVALID_CREDENTIALS"
    limited = fail(auth, username)
    assert limited.status == 429 and limited.code == "RATE_LIMITED" and limited.extra["retry_after_s"] == 1
    assert limited.headers == {"Retry-After": "1"}
    clock.advance(1.1)
    assert fail(auth, username).reason == "INVALID_CREDENTIALS"  # 6th failure -> wait 2 s
    clock.advance(1.1)
    assert fail(auth, username).code == "RATE_LIMITED"


def test_delay_never_reveals_a_correct_password_and_is_capped(auth: AuthService, clock: FakeClock) -> None:
    for _ in range(5):
        fail(auth, "guard01")
    assert fail(auth, "guard01", USER_PW).code == "RATE_LIMITED"  # no oracle during the delay
    for _ in range(25):  # keep failing: the wait is capped at AUTH_LOCKOUT_MIN
        clock.advance(15 * 60 + 1)
        fail(auth, "guard01")
    assert auth.throttle.retry_after_s("guard01") <= 15 * 60
    clock.advance(15 * 60 + 1)
    assert login(auth, "guard01")[1].staff_id == "s_guard01"  # soft delay, never a hard lock
    assert auth.throttle.retry_after_s("guard01") == 0


def test_last_admin_is_throttled_never_hard_locked(auth: AuthService, clock: FakeClock) -> None:
    for _ in range(12):
        clock.advance(15 * 60 + 1)
        fail(auth, "boss01")
    clock.advance(15 * 60 + 1)
    assert login(auth, "boss01", support.USER_PW)[1].roles == ("admin",)


def test_global_cap_counts_every_attempt(tmp_path: Path, clock: FakeClock, fast_scrypt: None) -> None:
    auth = make_service(tmp_path, clock, login_global_max=3)
    add_user(auth, "guard01", ["auditor"])
    login(auth, "guard01")
    fail(auth, "a_user")
    fail(auth, "b_user")
    err = fail(auth, "guard01", USER_PW)
    assert err.code == "RATE_LIMITED" and err.extra["retry_after_s"] >= 1
    clock.advance(5 * 60)
    login(auth, "guard01")


def test_disabled_account_revealed_only_after_correct_password(auth: AuthService) -> None:
    auth.update_staff(CONSOLE, "s_guard01", status="disabled")
    assert fail(auth, "guard01").reason == "INVALID_CREDENTIALS"
    assert fail(auth, "guard01", USER_PW).reason == "ACCOUNT_DISABLED"


def test_mfa_ticket_flow_single_use_and_expiry(auth: AuthService, clock: FakeClock) -> None:
    secret = enable_mfa(auth, clock, "guard01")
    need = fail(auth, "guard01", USER_PW)
    assert need.status == 401 and need.reason == "MFA_REQUIRED" and need.extra["mfa_ticket"]
    ticket = need.extra["mfa_ticket"]
    token, _, principal = auth.login_sync(None, None, code_now(secret, clock), mfa_ticket=ticket)
    assert principal.mfa_enabled and token
    assert fail(auth, None, None, totp_code=code_now(secret, clock), mfa_ticket=ticket).reason == "MFA_INVALID"
    clock.advance(30)
    stale = fail(auth, "guard01", USER_PW).extra["mfa_ticket"]
    clock.advance(121)
    assert fail(auth, None, None, totp_code=code_now(secret, clock), mfa_ticket=stale).reason == "MFA_INVALID"


def test_mfa_invalid_and_replayed_codes_are_rejected(auth: AuthService, clock: FakeClock) -> None:
    secret = enable_mfa(auth, clock, "guard01")
    assert fail(auth, "guard01", USER_PW, totp_code="000000").reason in ("MFA_INVALID",)
    code = code_now(secret, clock)
    login(auth, "guard01", totp_code=code)
    assert fail(auth, "guard01", USER_PW, totp_code=code).reason == "MFA_INVALID"  # same step = replay
    clock.advance(30)
    login(auth, "guard01", totp_code=code_now(secret, clock))


def test_valid_totp_bypasses_the_soft_delay_for_mfa_accounts(auth: AuthService, clock: FakeClock) -> None:
    secret = enable_mfa(auth, clock, "guard01")
    for _ in range(5):
        fail(auth, "guard01", totp_code=code_now(secret, clock))
    assert fail(auth, "guard01", USER_PW).code == "RATE_LIMITED"
    assert fail(auth, "guard01", USER_PW, totp_code="000000").code == "RATE_LIMITED"
    assert login(auth, "guard01", totp_code=code_now(secret, clock))[1].staff_id == "s_guard01"


def test_kdf_admission_is_non_blocking(auth: AuthService, monkeypatch: pytest.MonkeyPatch) -> None:
    release, started = threading.Event(), threading.Semaphore(0)
    real = passwords.verify_password

    def slow(password: str, encoded: str) -> bool:
        started.release()
        release.wait(10)
        return real(password, encoded)

    monkeypatch.setattr(passwords, "verify_password", slow)

    async def scenario() -> list[object]:
        first = asyncio.create_task(auth.login("guard01", USER_PW))
        second = asyncio.create_task(auth.login("boss01", USER_PW))
        await asyncio.to_thread(started.acquire)
        await asyncio.to_thread(started.acquire)
        with pytest.raises(AuthError) as busy:
            await auth.login("guard01", USER_PW)
        release.set()
        return [busy.value, *(await asyncio.gather(first, second))]

    busy, *done = asyncio.run(scenario())
    assert busy.code == "RATE_LIMITED" and busy.extra["retry_after_s"] == 1  # type: ignore[attr-defined]
    assert len(done) == 2 and auth.kdf.in_flight == 0


def test_kdf_runs_on_the_dedicated_pool(auth: AuthService, monkeypatch: pytest.MonkeyPatch) -> None:
    names: list[str] = []
    real = passwords.verify_password
    monkeypatch.setattr(passwords, "verify_password",
                        lambda p, e: names.append(threading.current_thread().name) or real(p, e))
    asyncio.run(auth.login("guard01", USER_PW))
    assert names and names[0].startswith("auth-kdf")


def test_reserved_usernames_are_refused(auth: AuthService) -> None:
    for name in ("admin", "root", "kiosk", "demo"):
        with pytest.raises(AuthError) as err:
            add_user(auth, name, ["auditor"])
        assert err.value.reason == "RESERVED_USERNAME" and err.value.status == 422


def test_pending_actions_on_the_principal(tmp_path: Path, clock: FakeClock, fast_scrypt: None) -> None:
    auth = make_service(tmp_path, clock, mfa_required_roles=frozenset({"admin"}))
    add_user(auth, "temp01", ["auditor"], must_change=True)
    add_user(auth, "boss01", ["admin"])
    assert login(auth, "temp01")[1].pending_action == "PASSWORD_CHANGE_REQUIRED"
    assert login(auth, "boss01")[1].pending_action == "MFA_ENROLMENT_REQUIRED"


def test_password_change_keeps_this_session_and_ends_the_others(auth: AuthService) -> None:
    keep, me = login(auth, "guard01")
    other, _ = login(auth, "guard01")
    auth.change_password(me, USER_PW, NEW_PW)
    assert auth.authenticate(keep).id == "s_guard01"
    with pytest.raises(AuthError) as err:
        auth.authenticate(other)
    assert err.value.reason == "SESSION_EXPIRED"
    login(auth, "guard01", NEW_PW)


def test_wrong_current_password_is_reauth_required_not_401(auth: AuthService) -> None:
    _, me = login(auth, "guard01")
    with pytest.raises(AuthError) as err:
        auth.change_password(me, WRONG, NEW_PW)
    assert (err.value.status, err.value.reason) == (403, "REAUTH_REQUIRED")
    with pytest.raises(AuthError) as weak:
        auth.change_password(me, USER_PW, "short")
    assert weak.value.reason == "PASSWORD_POLICY" and weak.value.extra["problems"]


@pytest.mark.parametrize("change", ["disable", "roles", "reset", "mfa_reset"])
def test_privilege_changes_end_sessions(auth: AuthService, change: str) -> None:
    token, _ = login(auth, "guard01")
    if change == "disable":
        auth.update_staff(CONSOLE, "s_guard01", status="disabled")
    elif change == "roles":
        auth.update_staff(CONSOLE, "s_guard01", roles=["auditor"])
    elif change == "reset":
        auth.reset_password(CONSOLE, "s_guard01", NEW_PW)
    else:
        auth.reset_mfa(CONSOLE, "s_guard01")
    with pytest.raises(AuthError):
        auth.authenticate(token)


def test_changes_made_by_another_process_end_sessions_here(tmp_path: Path, clock: FakeClock,
                                                           auth: AuthService) -> None:
    token, _ = login(auth, "guard01")
    console = make_service(tmp_path, FakeClock())  # e.g. the CLI while the edge runs
    console.update_staff(CONSOLE, "s_guard01", roles=["auditor"])
    clock.advance(1.5)  # the edge re-stats the store at most once per second
    with pytest.raises(AuthError) as err:
        auth.authenticate(token)
    assert err.value.reason == "SESSION_EXPIRED"


def test_store_unavailable_fails_closed(auth: AuthService, tmp_path: Path, clock: FakeClock) -> None:
    token, _ = login(auth, "guard01")
    (tmp_path / STORE_FILE).write_bytes(b"corrupted")
    clock.advance(2)
    for call in (lambda: auth.authenticate(token), lambda: auth.login_sync("guard01", USER_PW)):
        with pytest.raises(AuthError) as err:
            call()
        assert err.value.code == "AUTH_UNAVAILABLE" and err.value.status == 503
    assert "auth_unavailable" in auth.degraded_reasons()


def test_volatile_fields_flush_at_most_once_a_minute_and_survive_restart(
        auth: AuthService, tmp_path: Path, clock: FakeClock) -> None:
    generation = auth.store.generation
    login(auth, "guard01")
    for _ in range(5):
        fail(auth, "boss01")
    assert auth.store.generation == generation  # nothing written yet
    clock.advance(61)
    fail(auth, "nobody99")
    stored = auth.store.snapshot().accounts
    assert stored["s_guard01"].last_login_at is not None and stored["s_boss01"].failed_logins == 5
    restarted = make_service(tmp_path, clock)
    assert restarted.throttle.state("boss01").failed == 5


def test_is_authorized_rechecks_without_extending(auth: AuthService, clock: FakeClock) -> None:
    _, principal = login(auth, "guard01")
    assert auth.is_authorized(principal, "events:read")
    assert not auth.is_authorized(principal, "staff:manage")
    clock.advance(29 * 60)
    assert auth.is_authorized(principal, "events:read")
    clock.advance(2 * 60)  # idle timeout passed: SSE checks never extended it
    assert not auth.is_authorized(principal, "events:read")


def test_bruteforce_health_signal(auth: AuthService, clock: FakeClock) -> None:
    for i in range(20):
        fail(auth, f"user{i:02d}")
    assert "auth_bruteforce" in auth.degraded_reasons()
    clock.advance(601)
    assert "auth_bruteforce" not in auth.degraded_reasons()
