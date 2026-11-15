"""Key derivation for the staff store and the audit chain (HKDF-SHA256 over EDGE_DATA_KEY).

Separate info labels give independent keys, so the template cache, the staff store and the audit MAC
never share key material even though they all come from EDGE_DATA_KEY. STAFF_STORE_KEY (a Fernet key),
when set, replaces the derived staff-store key (CLI `rekey` moves a store between keys).
"""

from __future__ import annotations

import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

STORE_KEY_INFO = b"faceguard staff-store v1"
AUDIT_KEY_INFO = b"faceguard audit-chain v1"
AUDIT_FROM_STORE_KEY_INFO = b"faceguard audit-chain from staff-store key v1"
MARKER_KEY_INFO = b"faceguard staff-store marker v1"
DERIVED_KEY_BYTES = 32


class KeyMaterialError(ValueError):
    """Unusable key material (the message never contains the key)."""


def derive(secret: str, info: bytes) -> bytes:
    if not secret:
        raise KeyMaterialError("EDGE_DATA_KEY is not set")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=DERIVED_KEY_BYTES, salt=None, info=info)
    return hkdf.derive(secret.encode("utf-8"))


def store_fernet(data_key: str, store_key: str = "") -> Fernet:
    """Fernet for staff.fernet: STAFF_STORE_KEY when given, else HKDF(EDGE_DATA_KEY, STORE_KEY_INFO)."""
    if store_key:
        try:
            return Fernet(store_key.encode("ascii"))
        except (ValueError, TypeError, UnicodeEncodeError):
            raise KeyMaterialError("STAFF_STORE_KEY is not a valid Fernet key") from None
    return Fernet(base64.urlsafe_b64encode(derive(data_key, STORE_KEY_INFO)))


def audit_mac_key(data_key: str, store_key: str = "") -> bytes:
    """HKDF(EDGE_DATA_KEY, audit info); without EDGE_DATA_KEY, HKDF(STAFF_STORE_KEY, a separate info).
    Raises KeyMaterialError when neither is set (never a public fallback key)."""
    if data_key:
        return derive(data_key, AUDIT_KEY_INFO)
    if store_key:
        return derive(store_key, AUDIT_FROM_STORE_KEY_INFO)
    raise KeyMaterialError("EDGE_DATA_KEY is not set")


def marker_mac_key(data_key: str, store_key: str = "") -> bytes:
    """Key for the store's durable sidecar (existence marker + generation high-water mark)."""
    secret = store_key or data_key
    if not secret:
        raise KeyMaterialError("EDGE_DATA_KEY is not set")
    return derive(secret, MARKER_KEY_INFO)
