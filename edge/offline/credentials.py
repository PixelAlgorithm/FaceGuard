"""Encrypted credential cache (per-user TOTP secrets). Never logged; AES-GCM with EDGE_DATA_KEY.

Writes are owner-only, fsync'd and atomic. A 0-byte / truncated / foreign-key file (power loss, wrong key) is
quarantined as *.corrupt-<ts> and the cache starts empty with `corrupt` set (EO-08): TOTP is then simply not
offered (fail-secure), the edge still starts, syncs and purges."""

from __future__ import annotations

import base64
import json
import secrets
import threading
from pathlib import Path
from urllib.parse import quote

from edge.offline.crypto import DataCipher, read_encrypted, write_private_atomic

_AAD = b"credentials"


class CredentialStore:
    def __init__(self, path: Path | str, data_key: str | bytes) -> None:
        self.path = Path(path)
        self._c = DataCipher(data_key, "credentials")
        self._lock = threading.Lock()
        self._totp: dict[str, str] = {}
        self._sig: tuple[int, int] | None = None
        self.corrupt: Path | None = None
        self._reload()

    def _reload(self) -> None:
        """Pick up secrets provisioned by another process (e.g. scripts/sign_bundle.py --provision-totp)."""
        try:
            st = self.path.stat()
        except OSError:
            return
        sig = (st.st_mtime_ns, st.st_size)
        if sig == self._sig:
            return
        plain, moved = read_encrypted(self.path, self._c, _AAD)
        if moved is not None:  # quarantined: no TOTP until re-provisioned (never a crash)
            self._totp, self._sig, self.corrupt = {}, None, moved
            return
        data = json.loads(plain) if plain else {}
        totp = data.get("totp") if isinstance(data, dict) else None
        self._totp = {str(k): str(v) for k, v in totp.items()} if isinstance(totp, dict) else {}
        self._sig = sig

    def totp_secret(self, user_id: str) -> str | None:
        with self._lock:
            self._reload()
            return self._totp.get(user_id)

    def set_totp_secret(self, user_id: str, secret_b32: str) -> None:
        base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))  # validate
        with self._lock:
            self._reload()  # never clobber secrets written by another process
            self._totp[user_id] = secret_b32.upper()
            self._save()

    def remove(self, user_id: str) -> None:
        with self._lock:
            self._reload()  # never clobber secrets written by another process
            if self._totp.pop(user_id, None) is not None:
                self._save()

    def provision_totp(self, user_id: str, issuer: str = "HID-Kiosk") -> str:
        """Create a secret for `user_id`; returns the otpauth:// URI (show once as a QR, never log)."""
        secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
        self.set_totp_secret(user_id, secret)
        label = quote(f"{issuer}:{user_id}")
        return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&digits=6&period=30"

    def count(self) -> int:
        with self._lock:
            return len(self._totp)

    def _save(self) -> None:
        blob = self._c.encrypt(json.dumps({"totp": self._totp}).encode(), _AAD)
        write_private_atomic(self.path, blob, prefix=".cred-")
        st = self.path.stat()
        self._sig = (st.st_mtime_ns, st.st_size)
