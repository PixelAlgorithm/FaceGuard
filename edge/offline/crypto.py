"""At-rest encryption for edge data (AES-256-GCM). Key material = EDGE_DATA_KEY (a Fernet key).

Purpose-specific subkeys are derived with HKDF-SHA256 so the decision log, credential cache and
pseudonymous lookup keys never share a key. Ciphertext layout: 12-byte nonce || AES-GCM(ct+tag).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _derive(raw: bytes, label: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=f"hid-edge:{label}".encode()).derive(raw)


def decode_data_key(key: str | bytes) -> bytes:
    raw = base64.urlsafe_b64decode(key if isinstance(key, bytes) else key.encode("ascii"))
    if len(raw) != 32:
        raise ValueError("EDGE_DATA_KEY must be a 32-byte urlsafe-base64 (Fernet) key")
    return raw


class DataCipher:
    def __init__(self, data_key: str | bytes, purpose: str) -> None:
        raw = decode_data_key(data_key)
        self._aead = AESGCM(_derive(raw, purpose))
        self._mac = _derive(raw, purpose + ":pseudonym")

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, plaintext, aad)

    def decrypt(self, blob: bytes, aad: bytes = b"") -> bytes:
        return self._aead.decrypt(blob[:12], blob[12:], aad)

    def pseudonym(self, value: str) -> str:
        """Keyed, non-reversible lookup key (so user ids never appear in plaintext on disk)."""
        return hmac.new(self._mac, value.encode("utf-8"), hashlib.sha256).hexdigest()
