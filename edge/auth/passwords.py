"""Staff password hashing (scrypt, stdlib only) and password policy.

Encoded form: ``scrypt$<log2 n>$<r>$<p>$<salt b64>$<hash b64>`` (unpadded url-safe base64). Parameters
follow OWASP's scrypt guidance (n=2**15, r=8, p=3 => 32 MiB, ~0.1 s on the kiosk laptop). Passwords are
NFKC-normalised before hashing (NIST SP 800-63B). Verification is constant-time and never raises for a
malformed hash (it simply fails). Stdlib only, so it stays vendorable (the cloud artifact currently ships only __init__, rbac, tokens).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import unicodedata

SCHEME = "scrypt"
SCRYPT_LOG2_N = 15
SCRYPT_R = 8
SCRYPT_P = 3
DKLEN = 32
SALT_BYTES = 16
MAXMEM = 64 * 1024 * 1024  # > 128 * r * n (32 MiB) so hashlib never refuses the parameters
MIN_LENGTH = 12
MAX_LENGTH = 128
MIN_DISTINCT_CHARS = 5
_MAX_ACCEPTED_LOG2_N = 20  # refuse absurd stored parameters (CPU/memory DoS via a tampered store)

# Tiny built-in deny list (lowercase); the length rule already removes most common passwords.
_DENY = frozenset({
    "password1234", "password12345", "passw0rd1234", "123456789012", "1234567890123", "qwertyuiop12",
    "qwerty123456", "letmein12345", "welcome12345", "changeme1234", "administrator", "admin1234567",
    "faceguard123", "faceguard1234", "iloveyou1234", "abc123456789", "trustno11234",
})

_DUMMY_HASH = ""  # built lazily (one real scrypt) so importing this module stays cheap


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _normalise(password: str) -> bytes:
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def _derive(password: str, salt: bytes, log2_n: int, r: int, p: int, dklen: int) -> bytes:
    return hashlib.scrypt(_normalise(password), salt=salt, n=1 << log2_n, r=r, p=p, dklen=dklen, maxmem=MAXMEM)


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    """Encoded scrypt hash of `password` (a fresh random salt unless one is given, for tests)."""
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    salt = salt if salt is not None else secrets.token_bytes(SALT_BYTES)
    dk = _derive(password, salt, SCRYPT_LOG2_N, SCRYPT_R, SCRYPT_P, DKLEN)
    return f"{SCHEME}${SCRYPT_LOG2_N}${SCRYPT_R}${SCRYPT_P}${_b64e(salt)}${_b64e(dk)}"


def _parse(encoded: str) -> tuple[int, int, int, bytes, bytes] | None:
    try:
        scheme, log2_n, r, p, salt_b64, dk_b64 = encoded.split("$")
        if scheme != SCHEME:
            return None
        n_log, r_, p_ = int(log2_n), int(r), int(p)
        salt, dk = _b64d(salt_b64), _b64d(dk_b64)
    except (AttributeError, ValueError, binascii.Error):
        return None
    if not (1 <= n_log <= _MAX_ACCEPTED_LOG2_N and 1 <= r_ <= 32 and 1 <= p_ <= 16) or not salt or len(dk) < 16:
        return None
    if 128 * r_ * (1 << n_log) >= MAXMEM:
        return None
    return n_log, r_, p_, salt, dk


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time check of `password` against an encoded hash. Malformed input -> False, never raises."""
    if not isinstance(password, str) or not password or len(password) > MAX_LENGTH * 4:
        return False
    parsed = _parse(encoded) if isinstance(encoded, str) else None
    if parsed is None:
        dummy_verify(password)
        return False
    log2_n, r, p, salt, dk = parsed
    try:
        candidate = _derive(password, salt, log2_n, r, p, len(dk))
    except (ValueError, MemoryError):
        return False
    return hmac.compare_digest(candidate, dk)


def needs_rehash(encoded: str) -> bool:
    """True when the stored hash uses older/weaker parameters than the current ones."""
    parsed = _parse(encoded) if isinstance(encoded, str) else None
    if parsed is None:
        return True
    log2_n, r, p, salt, dk = parsed
    return (log2_n, r, p, len(dk)) != (SCRYPT_LOG2_N, SCRYPT_R, SCRYPT_P, DKLEN) or len(salt) < SALT_BYTES


def dummy_verify(password: str) -> None:
    """Spend the same work as a real verification (unknown user / malformed hash) to blunt timing probes."""
    global _DUMMY_HASH
    if not _DUMMY_HASH:
        _DUMMY_HASH = hash_password("dummy-password-for-timing", salt=b"\0" * SALT_BYTES)
    parsed = _parse(_DUMMY_HASH)
    if parsed is None or not isinstance(password, str) or not password:
        return
    log2_n, r, p, salt, dk = parsed
    hmac.compare_digest(_derive(password[: MAX_LENGTH * 4], salt, log2_n, r, p, len(dk)), dk)


def check_policy(password: str, username: str = "") -> list[str]:
    """Policy violations for a NEW password (empty list = acceptable). Messages are user-facing."""
    if not isinstance(password, str):
        return ["password must be text"]
    problems: list[str] = []
    norm = unicodedata.normalize("NFKC", password)
    if len(norm) < MIN_LENGTH:
        problems.append(f"use at least {MIN_LENGTH} characters")
    if len(norm) > MAX_LENGTH:
        problems.append(f"use at most {MAX_LENGTH} characters")
    if len(set(norm)) < MIN_DISTINCT_CHARS:
        problems.append(f"use at least {MIN_DISTINCT_CHARS} different characters")
    lowered = norm.casefold()
    user = (username or "").strip().casefold()
    if user and len(user) >= 3 and user in lowered:
        problems.append("do not include the username")
    if lowered in _DENY:
        problems.append("this password is too common")
    return problems
