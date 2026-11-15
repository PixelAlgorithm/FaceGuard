"""Staff TOTP (RFC 6238 via pyotp): +-1 step tolerance and replay protection by last accepted step."""

from __future__ import annotations

import hmac
import re
from datetime import datetime

import pyotp

TOTP_ISSUER = "FaceGuard"
TOTP_STEP_S = 30
TOTP_DIGITS = 6
TOTP_WINDOW_STEPS = 1
CODE_RE = re.compile(r"^\d{6}$")


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_STEP_S).provisioning_uri(
        name=username, issuer_name=TOTP_ISSUER)


def current_step(now: datetime) -> int:
    return int(now.timestamp()) // TOTP_STEP_S


def code_at(secret: str, step: int) -> str:
    return pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_STEP_S).at(step * TOTP_STEP_S)


def accept_code(secret: str, code: str | None, now: datetime, last_step: int | None) -> int | None:
    """The accepted time step for `code`, or None (bad format, wrong code, or a replayed/older step)."""
    if not isinstance(code, str) or not CODE_RE.fullmatch(code):
        return None
    base = current_step(now)
    accepted: int | None = None
    for step in range(base - TOTP_WINDOW_STEPS, base + TOTP_WINDOW_STEPS + 1):
        # evaluate every candidate (constant work), keep the match
        if hmac.compare_digest(code_at(secret, step), code) and (last_step is None or step > last_step):
            accepted = step
    return accepted
