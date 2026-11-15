"""Bearer credential formats for staff sessions and API keys (stdlib only; the cloud may vendor it).

- Session token: ``fgs_`` + 43 url-safe chars (32 random bytes). The server keeps only its SHA-256.
- API key:       ``fgk_<key_id>.<secret>``: key_id = 8 chars [a-z0-9] (lookup), secret = 43 url-safe chars.
                 The server keeps key_id + SHA-256(secret) and compares digests in constant time.

Parsers reject anything that is not exactly one of these shapes before any hashing, so an oversized or
malformed Authorization header costs nothing. Credentials are never accepted in a query string.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import string

SESSION_PREFIX = "fgs_"
API_KEY_PREFIX = "fgk_"
KEY_ID_LEN = 8
_KEY_ID_ALPHABET = string.ascii_lowercase + string.digits
_SESSION_RE = re.compile(r"^fgs_[A-Za-z0-9_-]{43}$")
_API_KEY_RE = re.compile(r"^fgk_([a-z0-9]{8})\.([A-Za-z0-9_-]{43})$")
_MAX_HEADER = 256


def digest(secret: str) -> str:
    """Hex SHA-256 of a high-entropy secret (tokens and API-key secrets; never used for passwords)."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def digests_equal(a: str, b: str) -> bool:
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def new_session_token() -> str:
    return SESSION_PREFIX + secrets.token_urlsafe(32)


def is_session_token(raw: str | None) -> bool:
    return isinstance(raw, str) and bool(_SESSION_RE.fullmatch(raw))


def new_api_key() -> tuple[str, str, str]:
    """(key_id, full key shown ONCE to the operator, SHA-256 of the secret part to store)."""
    key_id = "".join(secrets.choice(_KEY_ID_ALPHABET) for _ in range(KEY_ID_LEN))
    secret = secrets.token_urlsafe(32)
    return key_id, f"{API_KEY_PREFIX}{key_id}.{secret}", digest(secret)


def parse_api_key(raw: str | None) -> tuple[str, str] | None:
    """(key_id, secret) for a well-formed API key, else None."""
    if not isinstance(raw, str):
        return None
    m = _API_KEY_RE.fullmatch(raw)
    return (m.group(1), m.group(2)) if m else None


def parse_bearer(authorization: str | None) -> str | None:
    """Credential from an ``Authorization: Bearer <credential>`` header, else None (scheme is case-insensitive)."""
    if not isinstance(authorization, str) or len(authorization) > _MAX_HEADER:
        return None
    scheme, _, value = authorization.strip().partition(" ")
    if scheme.lower() != "bearer":
        return None
    value = value.strip()
    return value if value and " " not in value else None
