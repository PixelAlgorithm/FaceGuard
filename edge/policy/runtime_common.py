"""Names shared by PolicyRuntime (edge/policy/runtime.py) and its mixins (runtime_*.py): the IST zone, the UTC ISO
formatter and the facade's exceptions. Re-exported by edge.policy.runtime (import them from there)."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Kolkata")


class AttemptClosedError(Exception):
    """Attempt already reached a terminal ALLOW/DENY (HTTP 409 ATTEMPT_CLOSED)."""


class AttemptNotFoundError(Exception):
    """No step-up session for this attempt (HTTP 404 ATTEMPT_NOT_FOUND)."""


class CloudUnavailableError(Exception):
    """Cloud not configured / forced offline / unreachable (HTTP 503 CLOUD_UNAVAILABLE)."""

    def __init__(self, message: str, report: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.report = dict(report or {})


def iso(dt: datetime | None) -> str | None:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z") if dt else None


__all__ = ["IST", "AttemptClosedError", "AttemptNotFoundError", "CloudUnavailableError", "iso"]
