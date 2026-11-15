"""§7.2 second factor / fallback verifiers (TOTP, CARD, EMAIL_OTP, STAFF_OVERRIDE).

TOTP: RFC 6238 (HMAC-SHA1, 6 digits, 30 s, +-1 step), replay-protected per user (last accepted step).
CARD: HMAC-SHA256(CARD_ID_PEPPER, card_id) == users[u].fallback.card_id_hash (from the verified bundle).
STAFF_OVERRIDE: PBKDF2-HMAC-SHA256(code, per-code salt, iterations) vs unused, unexpired codes of the
last valid bundle; consumed locally; 3 consecutive wrong codes -> 300 s lockout (no hash check while
locked). EMAIL_OTP: online only; trusts `email_otp_verified` set by edge-ml after the cloud verify.
Code values are never stored or logged.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol

from edge.policy.schedule import parse_ts
from edge.policy.signals import FallbackSubmission

BundleProvider = Callable[[], Mapping[str, Any] | None]  # last VALID bundle (verified) or None


def _fb(method: str, *, staff_id: str | None = None, code_id: str | None = None,
        totp_step: int | None = None) -> dict[str, Any]:
    """Log projection of a verified factor (API.md FallbackUsed + totp_step); never code values."""
    return {"method": method, "staff_id": staff_id, "code_id": code_id, "totp_step": totp_step}


# ---------------------------------------------------------------- primitives
def _b32decode(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(secret_b32: str, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    digest = hmac.new(_b32decode(secret_b32), struct.pack(">Q", counter), getattr(hashlib, algorithm.lower())).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_matching_step(secret_b32: str, code: str, now: datetime, *, period_s: int = 30, window_steps: int = 1,
                       digits: int = 6, algorithm: str = "SHA1") -> int | None:
    """Time-step counter the code is valid for (now +- window), or None."""
    if not (isinstance(code, str) and code.isascii() and code.isdigit() and len(code) == digits):
        return None
    step = int(now.timestamp()) // period_s
    match = None
    for s in range(step - window_steps, step + window_steps + 1):
        if hmac.compare_digest(hotp(secret_b32, s, digits, algorithm).encode(), code.encode()):
            match = s  # keep scanning: constant work regardless of which step matched
    return match


def card_hash(pepper: bytes, card_id: str) -> str:
    return hmac.new(pepper, card_id.strip().encode("utf-8"), hashlib.sha256).hexdigest()


def override_hash(code: str, salt_hex: str, iterations: int) -> str:
    return hashlib.pbkdf2_hmac("sha256", code.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)).hex()


# ---------------------------------------------------------------- state (replay, consumption, lockout)
class FallbackState(Protocol):
    def totp_last_step(self, user_id: str) -> int | None: ...
    def set_totp_last_step(self, user_id: str, step: int) -> None: ...
    def is_code_consumed(self, code_id: str) -> bool: ...
    def consume_code(self, code_id: str, at: datetime) -> None: ...
    def override_lock(self) -> tuple[int, datetime | None]: ...
    def set_override_lock(self, failures: int, locked_until: datetime | None) -> None: ...
    def purge_totp_before(self, step: int) -> int: ...


class InMemoryFallbackState:
    def __init__(self) -> None:
        self._totp: dict[str, int] = {}
        self._consumed: dict[str, datetime] = {}
        self._failures = 0
        self._locked_until: datetime | None = None

    def totp_last_step(self, user_id: str) -> int | None:
        return self._totp.get(user_id)

    def set_totp_last_step(self, user_id: str, step: int) -> None:
        self._totp[user_id] = step

    def is_code_consumed(self, code_id: str) -> bool:
        return code_id in self._consumed

    def consume_code(self, code_id: str, at: datetime) -> None:
        self._consumed[code_id] = at

    def override_lock(self) -> tuple[int, datetime | None]:
        return self._failures, self._locked_until

    def set_override_lock(self, failures: int, locked_until: datetime | None) -> None:
        self._failures, self._locked_until = failures, locked_until

    def purge_totp_before(self, step: int) -> int:
        old = [u for u, s in self._totp.items() if s < step]
        for u in old:
            del self._totp[u]
        return len(old)


@dataclass(frozen=True)
class FactorResult:
    ok: bool
    reason: str
    fallback: Mapping[str, Any] | None = None  # log info: method, staff_id, code_id, totp_step (never values)


def _ct_equal(a: Any, b: Any) -> bool:
    """Constant-time string equality that never raises (non-ASCII -> compared as UTF-8 bytes)."""
    if not (isinstance(a, str) and isinstance(b, str)):
        return False
    return hmac.compare_digest(a.encode("utf-8", "surrogatepass"), b.encode("utf-8", "surrogatepass"))


def _bundle_revoked_cards(bundle: Mapping[str, Any]) -> set[str]:
    """CARD revocations carried in the bundle itself (API.md 4.3 item shape: type CARD, target_id = hash)."""
    out = set()
    for r in bundle.get("revocations") or []:
        if isinstance(r, Mapping) and r.get("type") == "CARD" and isinstance(r.get("target_id"), str):
            out.add(r["target_id"])
    return out


class FallbackVerifier:
    """Verifies one second-factor submission for the step-up candidate. Thread-safe."""

    def __init__(self, cfg: Any, state: FallbackState, *, totp_secret: Callable[[str], str | None],
                 card_pepper: bytes | None, bundle: BundleProvider,
                 card_revoked: Callable[[str], bool] | None = None) -> None:
        self._F = cfg.fallback
        self._state = state
        self._totp_secret = totp_secret
        self._pepper = card_pepper
        self._bundle = bundle
        self._card_revoked = card_revoked or (lambda _h: False)  # revocation-feed overlay (card-ID hashes)
        self._lock = threading.Lock()

    def verify(self, sub: FallbackSubmission, candidate_user_id: str | None, mode: str, now: datetime,
               wall_now: datetime | None = None) -> FactorResult:
        """`now` = real time (TOTP, lockout); `wall_now` = edge wall clock (override valid_until, §2 Clocks)."""
        with self._lock:
            method = sub.method
            if method == "TOTP":
                return self._totp(sub, candidate_user_id, now)
            if method == "CARD":
                return self._card(sub, candidate_user_id)
            if method == "EMAIL_OTP":
                if mode != "ONLINE":
                    return FactorResult(False, "email OTP is online only")
                ok = sub.email_otp_verified is True and bool(candidate_user_id)
                return FactorResult(ok, "" if ok else "email OTP not verified",
                                    _fb("EMAIL_OTP") if ok else None)
            if method == "STAFF_OVERRIDE":
                return self._staff(sub, now, wall_now or now)
            return FactorResult(False, f"unknown method {method!r}")

    # -- TOTP
    def _totp(self, sub: FallbackSubmission, user: str | None, now: datetime) -> FactorResult:
        if not user or not sub.code:
            return FactorResult(False, "missing candidate or code")
        bundle = self._bundle()
        if bundle is not None:
            u = (bundle.get("users") or {}).get(user) or {}
            if not (u.get("fallback") or {}).get("totp_enrolled"):
                return FactorResult(False, "user has no TOTP enrolment")
        secret = self._totp_secret(user)
        if not secret:
            return FactorResult(False, "no TOTP secret cached for user")
        t = self._F.totp
        step = totp_matching_step(secret, sub.code, now, period_s=int(t.period_s), window_steps=int(t.window_steps),
                                  digits=int(t.digits), algorithm=str(t.algorithm))
        if step is None:
            return FactorResult(False, "wrong TOTP code")
        last = self._state.totp_last_step(user)
        if last is not None and step <= last:
            return FactorResult(False, "TOTP time-step already used (replay)")
        self._state.set_totp_last_step(user, step)
        return FactorResult(True, "", _fb("TOTP", totp_step=step))

    # -- CARD
    def _card(self, sub: FallbackSubmission, user: str | None) -> FactorResult:
        bundle = self._bundle()
        if not user or not sub.card_id or not self._pepper or bundle is None:
            return FactorResult(False, "card cannot be verified")
        expected = ((bundle.get("users") or {}).get(user) or {}).get("fallback", {}).get("card_id_hash")
        presented = card_hash(self._pepper, sub.card_id)
        if not _ct_equal(presented, expected):
            return FactorResult(False, "card does not belong to the candidate")
        if presented in _bundle_revoked_cards(bundle) or self._card_revoked(presented):
            return FactorResult(False, "card revoked")  # revocation feed / bundle: deny-only, immediate
        return FactorResult(True, "", _fb("CARD"))

    # -- STAFF_OVERRIDE
    def _staff(self, sub: FallbackSubmission, now: datetime, wall: datetime) -> FactorResult:
        S = self._F.staff_override
        failures, locked_until = self._state.override_lock()
        if locked_until is not None and now < locked_until:
            return FactorResult(False, "staff override locked")  # no hash check while locked
        if locked_until is not None:
            failures, locked_until = 0, None
        has_staff = bool((sub.staff_id or "").strip())
        match = self._match_override(sub, wall) if has_staff else None
        if match is None:  # a missing staff_id counts like a wrong code (no hash is checked for it)
            failures += 1
            if failures >= int(S.max_failures):
                self._state.set_override_lock(0, now + timedelta(seconds=float(S.lockout_s)))
            else:
                self._state.set_override_lock(failures, None)
            return FactorResult(False, "override code rejected" if has_staff else "staff_id required")
        self._state.set_override_lock(0, None)
        self._state.consume_code(match["code_id"], now)
        return FactorResult(True, "", _fb("STAFF_OVERRIDE", staff_id=match.get("staff_id"), code_id=match["code_id"]))

    def _match_override(self, sub: FallbackSubmission, now: datetime) -> Mapping[str, Any] | None:
        S = self._F.staff_override
        code = sub.code or ""
        staff = (sub.staff_id or "").strip()
        bundle = self._bundle()
        if not staff or bundle is None or not (code.isdigit() and len(code) == int(S.code_length)):
            return None  # R2: an override binds to the named staff member, never to any guard's code
        oc = bundle.get("override_codes") or {}
        iterations = max(int(oc.get("iterations") or 0), int(S.pbkdf2_iterations))
        grace = timedelta(hours=float(S.valid_after_expiry_h))
        bundle_expiry = parse_ts(bundle.get("expires_at"))
        found = None
        for c in oc.get("codes") or []:
            cid = c.get("code_id")
            if not cid or self._state.is_code_consumed(cid):
                continue
            valid_until = parse_ts(c.get("valid_until")) or (bundle_expiry + grace if bundle_expiry else None)
            if valid_until is None or now >= valid_until:
                continue
            if staff != c.get("staff_id"):
                continue
            try:
                h = override_hash(code, str(c.get("salt", "")), iterations)
            except ValueError:  # malformed salt in a (signed) bundle entry: that entry never matches
                continue
            if _ct_equal(h, c.get("hash")):
                found = c
        return found
