"""Encrypted staff store: accounts + API keys in <data_dir>/staff.fernet.

Key: HKDF(EDGE_DATA_KEY, "faceguard staff-store v1") or STAFF_STORE_KEY (edge/auth/keys.py).
Every mutation (edge and CLI) = flock(staff.lock, 5 s timeout -> AUTH_BUSY) -> re-read + decrypt -> apply
a pure function StoreData -> (StoreData, result) -> atomic write (unique tmp, fsync, os.replace, fsync dir,
0600) with generation + 1 -> marker write -> unlock. The in-process RLock is taken only AFTER the flock, so
readers (snapshot() on the event loop) never wait behind a writer that is polling the flock.
Readers stat the files at most once per second and reload on change.

Marker: <data_dir>/staff.marker (0600, JSON {"generation": N, "mac": hex}), HMAC-SHA256 under
keys.marker_mac_key(EDGE_DATA_KEY, STAFF_STORE_KEY). Written after every store write (store file first, so a
crash in between leaves file generation > marker generation, which is fine). It is the durable proof that a
store existed and the persisted generation high-water mark (rollback detection survives restarts and works in
every CLI process). rekey() rewrites it under the new key. Restoring an older staff.fernet together with its
own older staff.marker, or deleting the marker, is not detectable here (old deployments have no marker).

States: OK | EMPTY (no file, no marker and no store history in the audit log: bootstrap) | MISSING (no file,
but the marker or the audit log shows a store existed) | UNAVAILABLE (wrong key, corrupt file, invalid marker,
a generation lower than the marker's or one already seen = rollback, or any OSError while reading the store,
the marker, the audit history or the lock). MISSING / UNAVAILABLE fail closed: reads raise AUTH_UNAVAILABLE,
the file is never overwritten or wiped. OSErrors never escape: update()/rekey() raise AUTH_UNAVAILABLE.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import json
import logging
import os
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, TypeVar

from cryptography.fernet import Fernet, InvalidToken

from edge.auth.keys import KeyMaterialError, marker_mac_key, store_fernet
from edge.auth.models import ApiKey, AuthError, StaffAccount, StoreData, auth_monotonic

log = logging.getLogger("edge.auth")
T = TypeVar("T")
StoreState = Literal["OK", "EMPTY", "MISSING", "UNAVAILABLE"]

STORE_FILE = "staff.fernet"
LOCK_FILE = "staff.lock"
MARKER_FILE = "staff.marker"
MARKER_MAX_BYTES = 4096
_MARKER_MAC_LABEL = b"faceguard staff.marker generation="
_FINGERPRINT_LABEL = b"faceguard staff-store fingerprint v1"
FINGERPRINT_HEX_CHARS = 16
AUDIT_FILE_PREFIX = "audit.jsonl"
STORE_FORMAT = 1
PRIVATE_FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o700
LOCK_TIMEOUT_S = 5.0
LOCK_POLL_S = 0.05
REFRESH_INTERVAL_S = 1.0
_HISTORY_MARKERS = (b'"action":"staff.', b'"action":"store.')
_ABSENT = ("absent",)
FileStamp = tuple[Any, ...]


class _Unreadable(Exception):
    """Internal: a file needed to decide the store state could not be read (an OSError)."""


def unavailable_error() -> AuthError:
    return AuthError("AUTH_UNAVAILABLE", "staff authentication is unavailable on this kiosk")


def busy_error() -> AuthError:
    return AuthError("AUTH_BUSY", "the staff store is busy, try again", extra={"retry_after_s": 1},
                     headers={"Retry-After": "1"})


class StaffStore:
    def __init__(self, data_dir: Path, data_key: str, *, store_key: str = "",
                 lock_timeout_s: float = LOCK_TIMEOUT_S, refresh_interval_s: float = REFRESH_INTERVAL_S,
                 monotonic: Callable[[], float] = auth_monotonic) -> None:
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / STORE_FILE
        self.lock_path = self.data_dir / LOCK_FILE
        self.marker_path = self.data_dir / MARKER_FILE
        self._lock = threading.RLock()
        self._lock_timeout = lock_timeout_s
        self._refresh_interval = refresh_interval_s
        self._mono = monotonic
        self._data = StoreData()
        self._stamp: tuple[FileStamp, FileStamp] | None = None
        self._checked_at: float | None = None
        self._state: StoreState = "EMPTY"
        self._error: str | None = None
        self._highest_generation = 0
        self._history_cache: tuple[tuple[Any, ...], bool] | None = None
        self._fernet: Fernet | None = None
        self._marker_key = b""
        try:
            self._fernet = store_fernet(data_key, store_key)
            self._marker_key = marker_mac_key(data_key, store_key)
        except KeyMaterialError as exc:
            self._fernet = None
            self._set_unavailable(str(exc))
        self.refresh(force=True)

    # ------------------------------------------------------------------ state
    @property
    def state(self) -> StoreState:
        self.refresh()
        return self._state

    @property
    def available(self) -> bool:
        return self.state in ("OK", "EMPTY")

    @property
    def error(self) -> str | None:
        """Why the store is unavailable (never contains key material), else None."""
        return self._error

    @property
    def generation(self) -> int:
        return self._data.generation

    @property
    def fernet_fingerprint(self) -> str | None:
        """Short one-way id of the effective store key (same key -> same value), or None without a usable
        key. Lets the CLI tell whether a key change happened; it reveals nothing about the key itself."""
        if self._fernet is None:
            return None
        digest = hmac.new(self._marker_key, _FINGERPRINT_LABEL, hashlib.sha256).hexdigest()
        return digest[:FINGERPRINT_HEX_CHARS]

    def snapshot(self) -> StoreData:
        """Current data (reloaded if the file changed). Raises AUTH_UNAVAILABLE when MISSING/UNAVAILABLE."""
        with self._lock:
            self.refresh()
            if self._state not in ("OK", "EMPTY"):
                raise unavailable_error()
            return self._data

    def refresh(self, *, force: bool = False) -> None:
        """Re-stat the file (at most once per REFRESH_INTERVAL_S unless forced) and reload on change."""
        if self._fernet is None:
            return
        with self._lock:
            now = self._mono()
            if not force and self._checked_at is not None and now - self._checked_at < self._refresh_interval:
                return
            self._checked_at = now
            stamp = self._current_stamp()
            if force or stamp is None or stamp != self._stamp or stamp[0] == _ABSENT:
                self._load()

    def update(self, fn: Callable[[StoreData], tuple[StoreData, T]], *, allow_missing: bool = False) -> T:
        """Apply `fn` to the latest on-disk data under the cross-process lock and persist the result.
        allow_missing=True lets the console re-create a store that the audit log says existed (MISSING)."""
        if self._fernet is None:
            raise unavailable_error()
        # flock first (may poll for up to lock_timeout_s), RLock only around re-read/apply/write: snapshot()
        # readers never block behind the poll. Threads stay serialised by the flock itself (each _file_lock
        # opens its own descriptor, and flock locks per open file description).
        with self._file_lock(), self._lock:
            self._load()
            if self._state == "UNAVAILABLE" or (self._state == "MISSING" and not allow_missing):
                raise unavailable_error()
            new, result = fn(self._data)
            if new is not self._data:
                self._write(new)
            return result

    def rekey(self, new_store_key: str) -> None:
        """Re-encrypt the store under a new Fernet key (then set STAFF_STORE_KEY to it). The marker is
        rewritten under marker_mac_key("", new_store_key), the key a process opened with STAFF_STORE_KEY set to
        the new key derives. A process still on the old key then sees the store as UNAVAILABLE."""
        new_fernet = store_fernet("", new_store_key)
        new_marker_key = marker_mac_key("", new_store_key)
        with self._file_lock(), self._lock:
            self._load()
            if self._state != "OK":
                raise unavailable_error()
            old = (self._fernet, self._marker_key)
            self._fernet, self._marker_key = new_fernet, new_marker_key
            try:
                self._write(self._data)
            except BaseException:
                self._fernet, self._marker_key = old
                raise

    # ------------------------------------------------------------------ internals
    def _set_unavailable(self, reason: str) -> None:
        changed = (self._state, self._error) != ("UNAVAILABLE", reason)
        self._data, self._state, self._error = StoreData(), "UNAVAILABLE", reason
        if changed:  # refresh() retries unreadable files every interval; log each new reason once
            log.error("auth store unavailable, failing closed: %s (%s)", reason, self.path)

    def _current_stamp(self) -> tuple[FileStamp, FileStamp] | None:
        """(store, marker) stat identity; None when a stat fails (the next refresh reloads and reports it)."""
        try:
            return _stat_stamp(self.path), _stat_stamp(self.marker_path)
        except OSError:
            return None

    def _load(self) -> None:
        assert self._fernet is not None
        self._stamp = self._current_stamp()
        try:
            marker_ok, marker_gen = self._read_marker()
            blob = self._read_store()
            if blob is None:
                self._load_missing(marker_ok, marker_gen)
                return
        except _Unreadable as exc:
            self._stamp = None  # retry on the next refresh (permissions may be fixed)
            self._set_unavailable(str(exc))
            return
        if not marker_ok:
            self._set_unavailable("staff store marker is invalid (tampered, corrupt or another key)")
            return
        if marker_gen is not None:
            self._highest_generation = max(self._highest_generation, marker_gen)
        try:
            data = _decode(json.loads(self._fernet.decrypt(blob)))
        except InvalidToken:
            self._set_unavailable("staff store cannot be decrypted (wrong key or corrupt file)")
            return
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            self._set_unavailable(f"staff store is malformed ({type(exc).__name__})")
            return
        if data.generation < self._highest_generation:
            self._set_unavailable("staff store generation went backwards (rollback)")
            return
        self._highest_generation = data.generation
        self._data, self._state, self._error = data, "OK", None

    def _load_missing(self, marker_ok: bool, marker_gen: int | None) -> None:
        """No staff.fernet: MISSING when the marker (valid or not) or the audit history proves a store
        existed, else EMPTY. A valid marker's generation is kept so a console re-create continues above it."""
        if marker_gen is not None:
            self._highest_generation = max(self._highest_generation, marker_gen)
        existed = not marker_ok or marker_gen is not None or self._store_history_exists()
        self._data, self._error = StoreData(), None
        self._state = "MISSING" if existed else "EMPTY"
        if existed:
            log.error("staff store file is missing but a store existed (marker/audit log); failing closed")

    def _read_store(self) -> bytes | None:
        try:
            with open(self.path, "rb") as fh:
                return fh.read()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise _Unreadable(f"staff store unreadable ({type(exc).__name__})") from exc

    def _read_marker(self) -> tuple[bool, int | None]:
        """(valid, generation): (True, None) = no marker, (False, None) = present but invalid."""
        try:
            with open(self.marker_path, "rb") as fh:
                raw = fh.read(MARKER_MAX_BYTES + 1)
        except FileNotFoundError:
            return True, None
        except OSError as exc:
            raise _Unreadable(f"staff store marker unreadable ({type(exc).__name__})") from exc
        generation = _parse_marker(raw, self._marker_key)
        return generation is not None, generation

    def _store_history_exists(self) -> bool:
        try:
            files = sorted(p for p in self.data_dir.glob(AUDIT_FILE_PREFIX + "*") if p.is_file())
            stamp = tuple(_audit_stamp(p) for p in files)
            if self._history_cache is not None and self._history_cache[0] == stamp:
                return self._history_cache[1]
            found = any(marker in blob for blob in map(_read_if_present, files) for marker in _HISTORY_MARKERS)
        except OSError as exc:
            raise _Unreadable(f"audit history unreadable ({type(exc).__name__})") from exc
        self._history_cache = (stamp, found)
        return found

    def _write(self, data: StoreData) -> None:
        assert self._fernet is not None
        new = StoreData(data.accounts, data.api_keys, max(data.generation, self._highest_generation) + 1)
        token = self._fernet.encrypt(json.dumps(_encode(new), separators=(",", ":")).encode("utf-8"))
        try:
            write_private_atomic(self.path, token)
        except OSError as exc:
            log.error("staff store write failed (%s); nothing changed", type(exc).__name__)
            raise unavailable_error() from exc
        self._highest_generation = new.generation
        self._data, self._state, self._error = new, "OK", None
        self._write_marker(new.generation)
        self._stamp = self._current_stamp()

    def _write_marker(self, generation: int) -> None:
        payload = {"generation": generation, "mac": _marker_mac(self._marker_key, generation)}
        try:
            write_private_atomic(self.marker_path, json.dumps(payload, separators=(",", ":")).encode("ascii"))
        except OSError as exc:
            # The store write already succeeded; a stale marker (generation below the file's) still loads.
            log.error("staff store marker write failed (%s); rollback high-water mark is stale",
                      type(exc).__name__)

    @contextlib.contextmanager
    def _file_lock(self) -> Iterator[None]:
        try:
            self.data_dir.mkdir(mode=PRIVATE_DIR_MODE, parents=True, exist_ok=True)
            fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, PRIVATE_FILE_MODE)
        except OSError as exc:
            log.error("staff store lock unusable (%s): %s", type(exc).__name__, self.lock_path)
            raise unavailable_error() from exc
        try:
            self._acquire(fd)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _acquire(self, fd: int) -> None:
        deadline = self._mono() + self._lock_timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                if self._mono() >= deadline:
                    raise busy_error() from None
                time.sleep(LOCK_POLL_S)
            except OSError as exc:
                log.error("staff store lock failed (%s): %s", type(exc).__name__, self.lock_path)
                raise unavailable_error() from exc


def _stat_stamp(path: Path) -> FileStamp:
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return _ABSENT
    return (st.st_ino, st.st_mtime_ns, st.st_size)


def _audit_stamp(path: Path) -> tuple[Any, ...]:
    try:
        st = path.stat()
    except FileNotFoundError:  # rotated away between glob and stat
        return (path.name, None)
    return (path.name, st.st_size, st.st_mtime_ns)


def _read_if_present(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return b""


def _marker_mac(key: bytes, generation: int) -> str:
    return hmac.new(key, _MARKER_MAC_LABEL + str(generation).encode("ascii"), hashlib.sha256).hexdigest()


def _parse_marker(raw: bytes, key: bytes) -> int | None:
    """The marker's generation when it parses and its MAC verifies, else None."""
    if len(raw) > MARKER_MAX_BYTES:
        return None
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    generation, mac = payload.get("generation"), payload.get("mac")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 0:
        return None
    if not isinstance(mac, str) or not hmac.compare_digest(mac, _marker_mac(key, generation)):
        return None
    return generation


def write_private_atomic(path: Path, data: bytes) -> None:
    """Owner-only atomic write: a unique tmp file (created 0600) in the same dir, fsync, os.replace."""
    path.parent.mkdir(mode=PRIVATE_DIR_MODE, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        os.fchmod(fd, PRIVATE_FILE_MODE)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    _fsync_dir(path.parent)


def _fsync_dir(directory: Path) -> None:
    with contextlib.suppress(OSError):
        dfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def _encode(data: StoreData) -> dict[str, Any]:
    return {
        "format": STORE_FORMAT, "generation": data.generation,
        "accounts": [a.to_record() for _, a in sorted(data.accounts.items())],
        "api_keys": [k.to_record() for _, k in sorted(data.api_keys.items())],
    }


def _decode(payload: Any) -> StoreData:
    if not isinstance(payload, dict) or payload.get("format") != STORE_FORMAT:
        raise ValueError("unsupported staff store format")
    generation = payload.get("generation")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 0:
        raise ValueError("bad generation")
    accounts = [StaffAccount.from_record(r) for r in payload.get("accounts", [])]
    keys = [ApiKey.from_record(r) for r in payload.get("api_keys", [])]
    by_id = {a.staff_id: a for a in accounts}
    keys_by_id = {k.key_id: k for k in keys}
    if len(by_id) != len(accounts) or len(keys_by_id) != len(keys):
        raise ValueError("duplicate ids in staff store")
    return StoreData(MappingProxyType(by_id), MappingProxyType(keys_by_id), generation)
