"""Login hardening (review round 2): MFA guess throttle, monotonic delays, reset races, ticket binding,
no unknown usernames in the audit log, no store I/O on the event loop, cross-process unlock, dummy hash."""

from __future__ import annotations

import asyncio
import inspect
import json
import threading
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from edge.auth import mfa, passwords
from edge.auth.models import AuthError, auth_monotonic
from edge.auth.ratelimit import GlobalLimiter, LoginThrottle
from edge.auth.service import AuthService
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
THRESHOLD = 5


@pytest.fixture
def auth(tmp_path: Path, clock: FakeClock, fast_scrypt: None) -> AuthService:
    service = make_service(tmp_path, clock)
    add_user(service, "guard01", ["security_officer"])
    add_user(service, "boss01", ["admin"])
    return service


def fail(auth: AuthService, username: str | None, password: str | None = WRONG, **kw: Any) -> AuthError:
    with pytest.raises(AuthError) as err:
        auth.login_sync(username, password, **kw)
    return err.value


def wrong_code(secret: str, clock: FakeClock, offset: int = 0) -> str:
    """A 6-digit code outside the accepted +-1 step window."""
    step = mfa.current_step(clock())
    valid = {mfa.code_at(secret, step + d) for d in (-1, 0, 1)}
    n = offset
    while f"{n % 1_000_000:06d}" in valid:
        n += 1
    return f"{n % 1_000_000:06d}"


def count_calls(monkeypatch: pytest.MonkeyPatch, module: Any, name: str) -> list[int]:
    calls: list[int] = []
    real = getattr(module, name)

    def counting(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(module, name, counting)
    return calls


# ---------------------------------------------------------------- EAC-01 / F4: MFA guess throttle
def test_bad_totp_guesses_during_the_delay_get_429_without_any_evaluation(
        auth: AuthService, clock: FakeClock, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = enable_mfa(auth, clock, "guard01")
    for i in range(THRESHOLD):
        assert fail(auth, "guard01", USER_PW, totp_code=wrong_code(secret, clock, i)).reason == "MFA_INVALID"
    totp = count_calls(monkeypatch, mfa, "accept_code")
    kdf = count_calls(monkeypatch, passwords, "verify_password")
    for i in range(20):
        err = fail(auth, "guard01", USER_PW, totp_code=wrong_code(secret, clock, 100 + i))
        assert err.code == "RATE_LIMITED" and err.extra["retry_after_s"] >= 1
    # a valid code cannot bypass the MFA throttle either
    assert fail(auth, "guard01", USER_PW, totp_code=code_now(secret, clock)).code == "RATE_LIMITED"
    assert totp == [] and kdf == []
    clock.advance(auth.mfa_throttle.retry_after_s("s_guard01") + 0.1)
    assert login(auth, "guard01", totp_code=code_now(secret, clock))[1].staff_id == "s_guard01"
    assert auth.mfa_throttle.retry_after_s("s_guard01") == 0
    assert auth.mfa_throttle.state("s_guard01").failed == 0  # reset on success


def test_throttled_bad_totp_counts_as_an_mfa_failure(auth: AuthService, clock: FakeClock) -> None:
    secret = enable_mfa(auth, clock, "guard01")
    for _ in range(THRESHOLD):
        fail(auth, "guard01")  # password throttle only
    assert auth.mfa_throttle.state("s_guard01").failed == 0
    assert fail(auth, "guard01", USER_PW, totp_code=wrong_code(secret, clock)).code == "RATE_LIMITED"
    assert auth.mfa_throttle.state("s_guard01").failed == 1
    # design rule kept: correct password + valid TOTP still bypasses the password delay
    assert login(auth, "guard01", totp_code=code_now(secret, clock))[1].staff_id == "s_guard01"


def test_ticket_path_checks_the_mfa_throttle_before_the_totp(
        auth: AuthService, clock: FakeClock, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = enable_mfa(auth, clock, "guard01")
    tickets = [fail(auth, "guard01", USER_PW).extra["mfa_ticket"] for _ in range(THRESHOLD + 1)]
    for i, ticket in enumerate(tickets[:THRESHOLD]):
        assert fail(auth, None, None, totp_code=wrong_code(secret, clock, i), mfa_ticket=ticket).reason == \
            "MFA_INVALID"
    totp = count_calls(monkeypatch, mfa, "accept_code")
    err = fail(auth, None, None, totp_code=code_now(secret, clock), mfa_ticket=tickets[-1])
    assert err.code == "RATE_LIMITED" and totp == []
    clock.advance(auth.mfa_throttle.retry_after_s("s_guard01") + 0.1)
    token, _, principal = auth.login_sync(None, None, code_now(secret, clock), mfa_ticket=tickets[-1])
    assert token and principal.staff_id == "s_guard01"


# ---------------------------------------------------------------- EAC-07: monotonic delay, clamped
class Wall:
    def __init__(self) -> None:
        self.now = support.START

    def __call__(self) -> Any:
        return self.now


class Mono:
    def __init__(self) -> None:
        self.t = 500.0

    def __call__(self) -> float:
        return self.t


def test_live_delay_ignores_wall_clock_steps_and_is_capped() -> None:
    wall, mono = Wall(), Mono()
    throttle = LoginThrottle(threshold=THRESHOLD, cap_s=900, clock=wall, monotonic=mono)
    for _ in range(THRESHOLD + 1):
        throttle.fail("guard01")  # 6th failure -> 2 s
    assert throttle.retry_after_s("guard01") == pytest.approx(2.0)
    wall.now -= timedelta(hours=2)  # NTP step backwards
    assert throttle.retry_after_s("guard01") == pytest.approx(2.0)
    wall.now += timedelta(hours=4)  # forward step does not clear the delay either
    assert throttle.retry_after_s("guard01") == pytest.approx(2.0)
    mono.t += 2.1
    assert throttle.retry_after_s("guard01") == 0
    for _ in range(40):
        throttle.fail("guard01")
    assert 0 < throttle.retry_after_s("guard01") <= 900


def test_state_reports_wall_next_allowed_and_seed_uses_monotonic() -> None:
    wall, mono = Wall(), Mono()
    throttle = LoginThrottle(threshold=THRESHOLD, cap_s=900, clock=wall, monotonic=mono)
    for _ in range(THRESHOLD):
        throttle.fail("guard01")
    state = throttle.state("guard01")
    assert state.failed == THRESHOLD and state.next_allowed == wall.now + timedelta(seconds=1)
    restored = LoginThrottle(threshold=THRESHOLD, cap_s=900, clock=wall, monotonic=mono)
    restored.seed("guard01", 8, wall.now + timedelta(seconds=30))
    restored.seed("boss01", 8, wall.now + timedelta(hours=3))  # beyond the cap: ignored
    assert restored.retry_after_s("guard01") == pytest.approx(30.0)
    assert restored.retry_after_s("boss01") == 0 and restored.state("boss01").failed == 8
    wall.now -= timedelta(hours=1)
    assert restored.retry_after_s("guard01") == pytest.approx(30.0)


def test_limiters_default_to_the_sleep_inclusive_clock() -> None:
    assert inspect.signature(LoginThrottle).parameters["monotonic"].default is auth_monotonic
    assert inspect.signature(GlobalLimiter).parameters["monotonic"].default is auth_monotonic


def test_service_throttles_follow_the_service_monotonic_clock(auth: AuthService, clock: FakeClock) -> None:
    for _ in range(THRESHOLD):
        fail(auth, "guard01")
    clock.now -= timedelta(hours=2)  # wall step only
    assert auth.throttle.retry_after_s("guard01") <= 1
    clock.mono_s += 1.1
    assert auth.throttle.retry_after_s("guard01") == 0
    assert auth.mfa_throttle.retry_after_s("s_guard01") == 0


# ---------------------------------------------------------------- F1: reset racing a login
def _reset_during_verify(monkeypatch: pytest.MonkeyPatch, cli: AuthService) -> None:
    real = passwords.verify_password
    fired: list[int] = []

    def racing(password: str, encoded: str) -> bool:
        ok = real(password, encoded)
        if not fired:
            fired.append(1)
            cli.reset_password(CONSOLE, "s_guard01", NEW_PW, must_change_password=False)
        return ok

    monkeypatch.setattr(passwords, "verify_password", racing)


def _stored(auth: AuthService) -> Any:
    auth.store.refresh(force=True)
    return auth.store.snapshot().accounts["s_guard01"]


def test_rehash_never_overwrites_a_concurrent_reset(tmp_path: Path, auth: AuthService, clock: FakeClock,
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(passwords, "SCRYPT_LOG2_N", 11)  # parameters upgraded: the login wants a rehash
    cli = make_service(tmp_path, clock)
    _reset_during_verify(monkeypatch, cli)
    err = fail(auth, "guard01", USER_PW)
    assert (err.status, err.reason) == (401, "INVALID_CREDENTIALS")
    stored = _stored(auth)
    assert passwords.verify_password(NEW_PW, stored.password_hash)
    assert not passwords.verify_password(USER_PW, stored.password_hash)
    assert auth.sessions.for_staff("s_guard01") == []


def test_mfa_login_racing_a_reset_creates_no_session(tmp_path: Path, auth: AuthService, clock: FakeClock,
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    secret = enable_mfa(auth, clock, "guard01")
    last_step = _stored(auth).mfa_last_step
    cli = make_service(tmp_path, clock)
    _reset_during_verify(monkeypatch, cli)
    err = fail(auth, "guard01", USER_PW, totp_code=code_now(secret, clock))
    assert (err.status, err.reason) == (401, "INVALID_CREDENTIALS")
    stored = _stored(auth)
    assert stored.mfa_last_step == last_step  # nothing written
    assert passwords.verify_password(NEW_PW, stored.password_hash)
    assert auth.sessions.for_staff("s_guard01") == []


def test_session_uses_the_verified_epoch(auth: AuthService, clock: FakeClock) -> None:
    secret = enable_mfa(auth, clock, "guard01")
    epoch = auth.store.snapshot().accounts["s_guard01"].session_epoch
    _, session, _ = auth.login_sync("guard01", USER_PW, code_now(secret, clock))
    assert session.epoch == epoch


# ---------------------------------------------------------------- F5: ticket bound to the account instance
@pytest.mark.parametrize("with_mfa", [False, True])
def test_ticket_is_dead_after_delete_and_recreate(auth: AuthService, clock: FakeClock, with_mfa: bool) -> None:
    enable_mfa(auth, clock, "guard01")
    ticket = fail(auth, "guard01", USER_PW).extra["mfa_ticket"]
    auth.delete_staff(CONSOLE, "s_guard01")
    add_user(auth, "guard01", ["security_officer"], password=NEW_PW)
    code = "123456"
    if with_mfa:
        code = code_now(enable_mfa(auth, clock, "guard01"), clock)
    err = fail(auth, None, None, totp_code=code, mfa_ticket=ticket)
    assert (err.status, err.code, err.reason) == (401, "UNAUTHORIZED", "MFA_INVALID")
    assert auth.sessions.for_staff("s_guard01") == []


@pytest.mark.parametrize("change", ["disable", "mfa_reset", "password_reset"])
def test_ticket_is_dead_after_account_changes(auth: AuthService, clock: FakeClock, change: str) -> None:
    secret = enable_mfa(auth, clock, "guard01")
    ticket = fail(auth, "guard01", USER_PW).extra["mfa_ticket"]
    if change == "disable":
        auth.update_staff(CONSOLE, "s_guard01", status="disabled")
    elif change == "mfa_reset":
        auth.reset_mfa(CONSOLE, "s_guard01")
    else:
        auth.reset_password(CONSOLE, "s_guard01", NEW_PW)
    err = fail(auth, None, None, totp_code=code_now(secret, clock), mfa_ticket=ticket)
    assert (err.status, err.reason) == (401, "MFA_INVALID")


# ---------------------------------------------------------------- F8: unknown usernames never audited
def test_unknown_username_is_never_written_to_the_audit_log(auth: AuthService, tmp_path: Path) -> None:
    typed = "correcthorsebatterystaple"
    assert fail(auth, typed, "x").reason == "INVALID_CREDENTIALS"
    auth.audit.flush_denials()
    files = list(tmp_path.glob("audit.jsonl*"))
    assert files and all(typed.encode() not in p.read_bytes() for p in files)
    lines = [json.loads(line) for p in files for line in p.read_text().splitlines() if line.strip()]
    denied = [x for x in lines if x.get("action") == "auth.login" and x.get("outcome") == "denied"]
    assert denied and denied[-1]["actor"]["username"] is None and denied[-1]["detail"]["known"] is False


# ---------------------------------------------------------------- EAC-02 / F3: no store I/O on the loop
def _record_threads(monkeypatch: pytest.MonkeyPatch, obj: Any, names: list[str]) -> list[int]:
    seen: list[int] = []
    for name in names:
        real = getattr(obj, name)

        def wrapper(*args: Any, _real: Any = real, **kwargs: Any) -> Any:
            seen.append(threading.get_ident())
            return _real(*args, **kwargs)

        monkeypatch.setattr(obj, name, wrapper)
    return seen


def test_ticket_login_runs_store_and_audit_io_off_the_event_loop(
        auth: AuthService, clock: FakeClock, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = enable_mfa(auth, clock, "guard01")
    ticket = fail(auth, "guard01", USER_PW).extra["mfa_ticket"]
    io = _record_threads(monkeypatch, auth.store, ["update", "snapshot"])
    io += _record_threads(monkeypatch, auth.audit, ["append"])

    async def scenario() -> int:
        await auth.login(None, None, code_now(secret, clock), mfa_ticket=ticket)
        return threading.get_ident()

    loop_thread = asyncio.run(scenario())
    assert io and loop_thread not in io


def test_bad_ticket_and_password_login_do_no_io_on_the_event_loop(
        auth: AuthService, clock: FakeClock, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = enable_mfa(auth, clock, "guard01")
    ticket = fail(auth, "guard01", USER_PW).extra["mfa_ticket"]
    io = _record_threads(monkeypatch, auth.store, ["update", "snapshot", "refresh"])
    io += _record_threads(monkeypatch, auth.audit, ["append"])

    async def scenario() -> int:
        with pytest.raises(AuthError):
            await auth.login(None, None, wrong_code(secret, clock), mfa_ticket=ticket)
        with pytest.raises(AuthError):
            await auth.login("guard01", WRONG)
        return threading.get_ident()

    loop_thread = asyncio.run(scenario())
    assert io and loop_thread not in io


# ---------------------------------------------------------------- EAC-06 / F2: unlock from another process
def _delay_edge(edge: AuthService, clock: FakeClock, extra: int = 3) -> None:
    for _ in range(THRESHOLD):
        fail(edge, "guard01")
    for _ in range(extra):
        clock.advance(edge.throttle.retry_after_s("guard01") + 0.1)
        fail(edge, "guard01")
    assert edge.throttle.retry_after_s("guard01") > 2
    assert fail(edge, "guard01", USER_PW).code == "RATE_LIMITED"


def test_cli_unlock_clears_the_running_edge_throttle(tmp_path: Path, auth: AuthService,
                                                     clock: FakeClock) -> None:
    _delay_edge(auth, clock)
    cli = make_service(tmp_path, clock)
    cli.unlock(CONSOLE, "s_guard01")
    clock.advance(1.5)  # the edge re-stats the store at most once per second
    assert login(auth, "guard01")[1].staff_id == "s_guard01"
    auth.flush_volatile()
    stored = _stored(cli)
    assert (stored.failed_logins, stored.locked_until) == (0, None)


def test_edge_flush_never_resurrects_counters_cleared_elsewhere(tmp_path: Path, auth: AuthService,
                                                                 clock: FakeClock) -> None:
    _delay_edge(auth, clock)
    cli = make_service(tmp_path, clock)
    cli.unlock(CONSOLE, "s_guard01")
    clock.advance(1.5)
    auth.flush_volatile()  # before any edge login reconciles
    stored = _stored(cli)
    assert (stored.failed_logins, stored.locked_until) == (0, None)
    assert login(auth, "guard01")[1].staff_id == "s_guard01"
    clock.advance(61)
    auth.flush_volatile()
    stored = _stored(cli)
    assert (stored.failed_logins, stored.locked_until) == (0, None)


def test_unrelated_store_writes_do_not_clear_the_edge_throttle(tmp_path: Path, auth: AuthService,
                                                               clock: FakeClock) -> None:
    _delay_edge(auth, clock)
    cli = make_service(tmp_path, clock)
    cli.update_staff(CONSOLE, "s_boss01", display_name="Boss")
    clock.advance(1.5)
    assert fail(auth, "guard01", USER_PW).code == "RATE_LIMITED"


def test_edge_own_admin_edit_of_a_delayed_account_keeps_its_throttle(auth: AuthService,
                                                                     clock: FakeClock) -> None:
    _delay_edge(auth, clock)
    auth.update_staff(CONSOLE, "s_guard01", display_name="Guard Renamed")  # this process, not an unlock
    clock.advance(1.5)
    assert fail(auth, "guard01", USER_PW).code == "RATE_LIMITED"


def test_cli_password_reset_clears_the_edge_throttle(tmp_path: Path, auth: AuthService,
                                                     clock: FakeClock) -> None:
    _delay_edge(auth, clock)
    cli = make_service(tmp_path, clock)
    cli.reset_password(CONSOLE, "s_guard01", NEW_PW, must_change_password=False)
    clock.advance(1.5)
    assert login(auth, "guard01", NEW_PW)[1].staff_id == "s_guard01"


# ---------------------------------------------------------------- F11: dummy hash parameters
def _params(encoded: str) -> tuple[int, int, int, int]:
    parsed = passwords._parse(encoded)
    assert parsed is not None
    log2_n, r, p, _salt, dk = parsed
    return log2_n, r, p, len(dk)


def test_dummy_hash_uses_the_hash_password_parameters_fast(fast_scrypt: None) -> None:
    passwords.dummy_verify("anything-at-all")
    assert _params(passwords._DUMMY_HASH) == _params(passwords.hash_password("copper-lantern-482"))


def test_dummy_hash_uses_the_hash_password_parameters_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(passwords, "_DUMMY_HASH", "")
    # skip the real full-cost scrypt: only the encoded parameters matter here
    monkeypatch.setattr(passwords, "_derive", lambda pw, salt, n, r, p, dklen: b"\1" * dklen)
    passwords.dummy_verify("anything-at-all")
    assert _params(passwords._DUMMY_HASH) == _params(passwords.hash_password("copper-lantern-482")) == \
        (passwords.SCRYPT_LOG2_N, passwords.SCRYPT_R, passwords.SCRYPT_P, passwords.DKLEN)
