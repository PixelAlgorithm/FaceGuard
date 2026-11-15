"""Injectable clock + time helpers. Stored timestamps are UTC ISO-8601 with a trailing 'Z'."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


class Clock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class FixedClock(Clock):
    """Test clock; advance() moves it forward."""

    def __init__(self, t: datetime) -> None:
        self._t = t if t.tzinfo else t.replace(tzinfo=UTC)

    def now(self) -> datetime:
        return self._t

    def set(self, t: datetime) -> None:
        self._t = t if t.tzinfo else t.replace(tzinfo=UTC)

    def advance(self, **kw: float) -> None:
        self._t = self._t + timedelta(**kw)


def iso_z(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_z_ms(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.astimezone(UTC).microsecond // 1000:03d}Z"


def parse_ts(value: str) -> datetime:
    """Parse ISO-8601 (with 'Z' or offset). Naive values are rejected (ambiguous)."""
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    t = datetime.fromisoformat(v)
    if t.tzinfo is None:
        raise ValueError("timestamp must carry a timezone (use Z for UTC)")
    return t.astimezone(UTC)


def epoch_s(t: datetime) -> int:
    return int(t.timestamp())
