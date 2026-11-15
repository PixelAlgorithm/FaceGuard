"""Shared helpers for the edge/auth tests (fixtures are imported by the test_auth_* modules).

Dummy keys only. scrypt cost is lowered so the suite stays fast; time is controlled by FakeClock.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet

from edge.auth import mfa, passwords
from edge.auth.config import AuthConfig
from edge.auth.models import Principal
from edge.auth.service import AuthService
from edge.auth.staff_ops import cli_principal

DATA_KEY = Fernet.generate_key().decode()   # dummy, test-only
OTHER_KEY = Fernet.generate_key().decode()  # dummy, test-only
ADMIN_PW = "orbit-tangerine-971"
USER_PW = "copper-lantern-482"
NEW_PW = "silver-meadow-305"
START = datetime(2026, 11, 14, 5, 30, tzinfo=UTC)


@dataclass
class FakeClock:
    """Wall clock (aware UTC) + monotonic seconds, advanced together by the test."""
    now: datetime = START
    mono_s: float = 1_000.0
    calls: list[str] = field(default_factory=list)

    def __call__(self) -> datetime:
        return self.now

    def mono(self) -> float:
        return self.mono_s

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)
        self.mono_s += seconds


@pytest.fixture
def fast_scrypt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(passwords, "SCRYPT_LOG2_N", 10)
    monkeypatch.setattr(passwords, "SCRYPT_P", 1)
    monkeypatch.setattr(passwords, "_DUMMY_HASH", "")


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


def make_config(**overrides: Any) -> AuthConfig:
    base: dict[str, Any] = {"mfa_required_roles": frozenset(), "demo_mode": True}
    return AuthConfig(**{**base, **overrides})


def make_service(data_dir: Path, clock: FakeClock, *, key: str = DATA_KEY, **overrides: Any) -> AuthService:
    return AuthService.open(data_dir, key, make_config(**overrides), clock=clock, monotonic=clock.mono)


CONSOLE = cli_principal("tester")


def add_user(auth: AuthService, username: str, roles: list[str], password: str = USER_PW, *,
             must_change: bool = False) -> None:
    auth.create_staff(CONSOLE, username, username.title(), roles, password, must_change_password=must_change)


def login(auth: AuthService, username: str, password: str = USER_PW, **kwargs: Any) -> tuple[str, Principal]:
    token, _, principal = auth.login_sync(username, password, **kwargs)
    return token, principal


def enable_mfa(auth: AuthService, clock: FakeClock, username: str) -> str:
    """Enrol TOTP from the console; returns the secret (test-only)."""
    setup = auth.begin_mfa(CONSOLE, f"s_{username}")
    auth.confirm_mfa(CONSOLE, f"s_{username}", mfa.code_at(setup.secret, mfa.current_step(clock())))
    clock.advance(mfa.TOTP_STEP_S)  # the enrolment code's step is spent
    return setup.secret


def code_now(secret: str, clock: FakeClock) -> str:
    return mfa.code_at(secret, mfa.current_step(clock()))
