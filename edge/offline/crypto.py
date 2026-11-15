"""At-rest encryption for edge data (AES-256-GCM). Key material = EDGE_DATA_KEY (a Fernet key).

Purpose-specific subkeys are derived with HKDF-SHA256 so the decision log, credential cache and
pseudonymous lookup keys never share a key. Ciphertext layout: 12-byte nonce || AES-GCM(ct+tag).

Also the shared durable-file helpers: `write_private_atomic` (0600 + fsync + atomic replace) and
`read_encrypted` / `quarantine` (a 0-byte or undecryptable state file is moved aside as *.corrupt-<ts>
instead of crashing the constructor; the caller decides the fail-safe state).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_log = logging.getLogger("edge.offline.crypto")


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


# ---------------------------------------------------------------- durable private files (EO-08 / EO-M2)
CORRUPT_SUFFIX = ".corrupt-"


def write_private_atomic(path: Path | str, data: bytes, *, prefix: str = ".tmp-") -> None:
    """Owner-only (0600) atomic replace that survives a power loss: mkstemp (0600, never world-readable) ->
    write -> fsync(file) -> os.replace -> fsync(directory). A reader sees the old or the new file, never a
    0-byte / partial one."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=prefix)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _fsync_dir(directory: Path) -> None:
    try:
        dfd = os.open(directory, os.O_RDONLY)
    except OSError:
        return  # platform without directory fds: the file itself is already fsynced
    try:
        os.fsync(dfd)
    except OSError:
        pass  # some filesystems refuse fsync on a directory; the rename is still atomic
    finally:
        os.close(dfd)


def quarantine(path: Path | str, now: datetime | None = None) -> Path:
    """Move an unreadable / undecryptable state file aside as `<name>.corrupt-<UTC stamp>` (kept 0600 for the
    operator, never deleted) and return the new path. The caller then starts from a fail-safe empty state."""
    path = Path(path)
    stamp = (now or datetime.now(UTC)).astimezone(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    dst = path.with_name(f"{path.name}{CORRUPT_SUFFIX}{stamp}")
    os.replace(path, dst)
    try:
        os.chmod(dst, 0o600)
    except OSError:
        pass
    _log.error("encrypted state file %s is unreadable or fails authentication: quarantined as %s",
               path.name, dst.name)
    return dst


def read_encrypted(path: Path | str, cipher: DataCipher, aad: bytes,
                   now: datetime | None = None) -> tuple[bytes | None, Path | None]:
    """(plaintext, None) for a readable file; (None, None) when it does not exist; (None, quarantined_path)
    when it is empty, truncated, tampered or written with another key (never raises for those)."""
    path = Path(path)
    try:
        blob = path.read_bytes()
    except FileNotFoundError:
        return None, None
    try:
        return cipher.decrypt(blob, aad), None
    except Exception:  # noqa: BLE001 - InvalidTag / short nonce: corrupt state, handled fail-safe by the caller
        return None, quarantine(path, now)
