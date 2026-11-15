"""Opt-in faked WALL clock for the policy/offline suites (clock-independence proof, swarm 2026-11-14).

    POLICY_TEST_WALL_CLOCK=2026-11-14T23:30:00+05:30 edge/.venv/bin/python -m pytest edge/policy edge/offline -q

When the env var is set, every test runs with the host wall clock shifted so that "now" starts at that
instant (and keeps advancing in real time): `time.time()` and `datetime.now()` / `datetime.utcnow()` as seen
by every loaded `edge.*` / `scripts.*` module (code AND tests) are shifted by the same offset. Monotonic
clocks are untouched (they carry no time of day). No freezegun dependency.

A suite that passes under a late-evening and an early-morning fake clock does not depend on the time of
day it happens to be run at (the live demo runs until late at night).
"""

from __future__ import annotations

import datetime as _dt
import os
import sys
import time as _time
from collections.abc import Iterator

import pytest

ENV = "POLICY_TEST_WALL_CLOCK"
_REAL_DATETIME = _dt.datetime
_REAL_TIME = _time.time
_PREFIXES = ("edge.", "scripts.", "sign_bundle")


class _Meta(type):
    def __instancecheck__(cls, obj: object) -> bool:  # real datetimes stay `isinstance(x, datetime)`
        return isinstance(obj, _REAL_DATETIME)

    def __subclasscheck__(cls, sub: type) -> bool:
        return issubclass(sub, _REAL_DATETIME)


def make_fake_datetime(offset: _dt.timedelta) -> type:
    class FakeDatetime(_REAL_DATETIME, metaclass=_Meta):
        _wallclock_fake = True

        @classmethod
        def now(cls, tz: _dt.tzinfo | None = None) -> _dt.datetime:  # type: ignore[override]
            return _REAL_DATETIME.now(tz) + offset

        @classmethod
        def utcnow(cls) -> _dt.datetime:  # type: ignore[override]
            return _REAL_DATETIME.now(_dt.UTC).replace(tzinfo=None) + offset

        @classmethod
        def today(cls) -> _dt.datetime:  # type: ignore[override]
            return cls.now()

    return FakeDatetime


def parse_target(value: str) -> _dt.datetime:
    t = _REAL_DATETIME.fromisoformat(value)
    if t.tzinfo is None:
        raise ValueError(f"{ENV} must carry a UTC offset, e.g. 2026-11-14T23:30:00+05:30")
    return t


def install(monkeypatch: pytest.MonkeyPatch, target: _dt.datetime) -> _dt.timedelta:
    """Shift the wall clock so that now == target (then advancing). Returns the applied offset."""
    offset = target - _REAL_DATETIME.now(_dt.UTC)
    fake = make_fake_datetime(offset)
    secs = offset.total_seconds()
    monkeypatch.setattr(_time, "time", lambda: _REAL_TIME() + secs)
    for name, mod in list(sys.modules.items()):
        if mod is None or not name.startswith(_PREFIXES):
            continue
        cur = getattr(mod, "datetime", None)
        if cur is _REAL_DATETIME or getattr(cur, "_wallclock_fake", False):  # re-install replaces a fake
            monkeypatch.setattr(mod, "datetime", fake)
    return offset


@pytest.fixture(autouse=True)
def fake_wall_clock(monkeypatch: pytest.MonkeyPatch) -> Iterator[_dt.timedelta | None]:
    value = os.environ.get(ENV, "").strip()
    if not value:
        yield None
        return
    yield install(monkeypatch, parse_target(value))
