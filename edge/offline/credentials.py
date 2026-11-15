"""Encrypted credential cache (per-user TOTP secrets). Never logged; AES-GCM with EDGE_DATA_KEY."""

from __future__ import annotations

import base64
import json
import os
import secrets
import tempfile
import threading
from pathlib import Path
from urllib.parse import quote

from edge.offline.crypto import DataCipher


class CredentialStore:
    def __init__(self, path: Path | str, data_key: str | bytes) -> None:
        self.path = Path(path)
        self._c = DataCipher(data_key, "credentials")
        self._lock = threading.Lock()
        self._totp: dict[str, str] = {}
        self._sig: tuple[int, int] | None = None
        self._reload()

    def _reload(self) -> None:
        """Pick up secrets provisioned by another process (e.g. scripts/sign_bundle.py --provision-totp)."""
        try:
            st = self.path.stat()
        except OSError:
            return
        sig = (st.st_mtime_ns, st.st_size)
        if sig != self._sig:
            self._totp = json.loads(self._c.decrypt(self.path.read_bytes(), b"credentials")).get("totp", {})
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
        self.path.parent.mkdir(parents=True, exist_ok=True)
        blob = self._c.encrypt(json.dumps({"totp": self._totp}).encode(), b"credentials")
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".cred-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(blob)
            os.replace(tmp, self.path)
            st = self.path.stat()
            self._sig = (st.st_mtime_ns, st.st_size)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
