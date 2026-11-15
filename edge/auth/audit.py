"""Append-only, MAC-chained staff audit log: <data_dir>/audit.jsonl (0600), rotated to audit.jsonl.1..N.

Each line: {ts_utc, seq, prev_mac, mac, actor:{kind,id,username}, action, target, outcome, client_ip,
detail[, count]}. mac = HMAC-SHA256(HKDF(EDGE_DATA_KEY, "faceguard audit-chain v1"), canonical line without
mac); prev_mac is the previous line's mac, so the first line of a new file carries the previous file's last
mac and the chain continues across rotation. Writers in several processes (edge + CLI) serialise on an
fcntl lock. Permission denials are aggregated: one line per (actor, route, reason, minute) with a count;
legacy-token use likewise per (route, minute). At most MAX_DENIAL_SLOTS slots are pending; beyond that,
events go to one overflow bucket per (action, minute) with route "<other>" and reason "OVERFLOW", so the
counts are kept but memory and line count stay bounded.
Details are scrubbed: keys that name a secret and values that look like a credential never reach the file.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import json
import logging
import os
import re
import threading
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from edge.auth.models import Clock, iso, utc_now

log = logging.getLogger("edge.auth")

AUDIT_FILE = "audit.jsonl"
AUDIT_LOCK = "audit.lock"
GENESIS_MAC = "0" * 64
MINUTE_FORMAT = "%Y-%m-%dT%H:%MZ"
FILE_MODE = 0o600
DIR_MODE = 0o700
READ_MAX = 500
TAIL_BYTES = 64 * 1024
MAX_DETAIL_DEPTH = 4
MAX_STR = 200
REDACTED = "[redacted]"
Outcome = Literal["ok", "denied", "error"]

_SECRET_KEY_PARTS = ("password", "secret", "token", "totp", "otp", "provisioning", "credential")
_SECRET_KEYS = frozenset({"code", "codes", "key", "api_key", "authorization", "uri"})
_SECRET_VALUE = re.compile(r"(fgs_|fgk_|otpauth://|scrypt\$)", re.IGNORECASE)


def _is_secret_key(key: str) -> bool:
    k = key.lower()
    return k in _SECRET_KEYS or any(part in k for part in _SECRET_KEY_PARTS)


def scrub(value: Any, depth: int = 0) -> Any:
    """JSON-safe copy of `value` without secret-named keys or credential-looking strings."""
    if depth > MAX_DETAIL_DEPTH:
        return REDACTED
    if isinstance(value, Mapping):
        return {str(k): (REDACTED if _is_secret_key(str(k)) else scrub(v, depth + 1)) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value, key=str) if isinstance(value, (set, frozenset)) else value
        return [scrub(v, depth + 1) for v in items]
    if isinstance(value, str):
        return REDACTED if _SECRET_VALUE.search(value) else value[:MAX_STR]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:MAX_STR]


def canonical(entry: Mapping[str, Any]) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def entry_mac(key: bytes, entry: Mapping[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "mac"}
    return hmac.new(key, canonical(body).encode("ascii"), hashlib.sha256).hexdigest()


DENIED_ACTION = "auth.denied"
LEGACY_ACTION = "auth.legacy_token"
MAX_DENIAL_SLOTS = 1000  # pending aggregation slots (all actions, all open minutes) before overflow
OVERFLOW_ROUTE = "<other>"
OVERFLOW_REASON = "OVERFLOW"
_ANONYMOUS_ACTOR: dict[str, Any] = {"kind": "anonymous", "id": None, "username": None}
_OVERFLOW_ACTOR: dict[str, Any] = {"kind": "aggregate", "id": None, "username": None}
SlotKey = tuple[str, str, str, str]  # (action, actor json, route, reason); slots are grouped per minute


@dataclass
class _Slot:
    """One pending aggregated line: `count` events of `action` by `actor` on `route` within `minute`."""
    action: str
    actor: dict[str, Any]
    route: str
    reason: str
    minute: str
    client_ip: str | None
    required: list[str]
    count: int = 0

    def detail(self) -> dict[str, Any]:
        if self.action == DENIED_ACTION:
            return {"reason": self.reason, "required": self.required, "minute": self.minute}
        return {"route": self.route, "minute": self.minute}


class AuditLog:
    def __init__(self, data_dir: Path, *, mac_key: bytes, max_bytes: int, keep: int,
                 clock: Clock = utc_now) -> None:
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / AUDIT_FILE
        self._lock_path = self.data_dir / AUDIT_LOCK
        self._mac_key = mac_key
        self._max_bytes = max_bytes
        self._keep = keep
        self._clock = clock
        self._lock = threading.Lock()
        self._agg_lock = threading.Lock()
        self._pending: dict[str, dict[SlotKey, _Slot]] = {}  # minute -> slots
        self._slot_count = 0

    def append(self, action: str, *, actor: Mapping[str, Any] | None = None, target: str | None = None,
               outcome: Outcome = "ok", client_ip: str | None = None,
               detail: Mapping[str, Any] | None = None, count: int | None = None) -> dict[str, Any]:
        """Append one entry (thread- and process-safe). Returns the entry as written."""
        with self._lock, self._file_lock():
            seq, prev = self._tail()
            entry: dict[str, Any] = {
                "ts_utc": iso(self._clock()), "seq": seq + 1, "prev_mac": prev,
                "actor": scrub(dict(actor)) if actor else {"kind": "system", "id": None, "username": None},
                "action": action, "target": scrub(target), "outcome": outcome,
                "client_ip": scrub(client_ip), "detail": scrub(dict(detail or {})),
            }
            if count is not None:
                entry["count"] = count
            entry["mac"] = entry_mac(self._mac_key, entry)
            line = canonical(entry)
            self._rotate_if_needed(len(line) + 1)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, FILE_MODE)
            try:
                os.fchmod(fd, FILE_MODE)
                os.write(fd, (line + "\n").encode("utf-8"))
            finally:
                os.close(fd)
            return entry

    def safe_append(self, action: str, **kwargs: Any) -> None:
        """append() that logs instead of raising: an audit failure never breaks the request path."""
        try:
            self.append(action, **kwargs)
        except Exception:  # audit must not take the kiosk down
            log.exception("audit append failed for action %s", action)

    def record_denial(self, *, actor: Mapping[str, Any] | None, route: str, reason: str,
                      required: list[str] | None = None, client_ip: str | None = None) -> None:
        """Count a permission denial; written as one aggregated line per (actor, route, reason, minute)."""
        self._aggregate(DENIED_ACTION, actor=actor, route=route, reason=reason, required=required,
                        client_ip=client_ip)

    def record_legacy_use(self, *, actor: Mapping[str, Any], route: str, client_ip: str | None) -> None:
        """Count one use of the legacy X-Admin-Token; written as one aggregated "auth.legacy_token" line per
        (route, minute) with a count, so every use is audited without a line per request."""
        self._aggregate(LEGACY_ACTION, actor=actor, route=route, reason="", required=None, client_ip=client_ip)

    def pending_slots(self) -> int:
        """Aggregation slots waiting to be written (bounded by MAX_DENIAL_SLOTS plus the overflow buckets)."""
        with self._agg_lock:
            return self._slot_count

    def flush_denials(self, *, complete_only: bool = False) -> None:
        """Write aggregated lines (denials and legacy-token use); only finished minutes when complete_only."""
        current = self._clock().strftime(MINUTE_FORMAT)
        with self._agg_lock:
            ready = self._take_ready(current, complete_only)
        self._write_slots(ready)

    def _aggregate(self, action: str, *, actor: Mapping[str, Any] | None, route: str, reason: str,
                   required: list[str] | None, client_ip: str | None) -> None:
        minute = self._clock().strftime(MINUTE_FORMAT)
        actor_doc = scrub(dict(actor)) if actor else dict(_ANONYMOUS_ACTOR)
        key: SlotKey = (action, canonical(actor_doc), route, reason)
        with self._agg_lock:
            ready = self._take_ready(minute, complete_only=True)  # frees finished minutes before the cap check
            bucket = self._pending.setdefault(minute, {})
            slot = bucket.get(key)
            if slot is None and self._slot_count >= MAX_DENIAL_SLOTS:
                key = (action, canonical(_OVERFLOW_ACTOR), OVERFLOW_ROUTE, OVERFLOW_REASON)
                slot = bucket.get(key)
                if slot is None:
                    slot = _Slot(action, dict(_OVERFLOW_ACTOR), OVERFLOW_ROUTE, OVERFLOW_REASON, minute, None, [])
            elif slot is None:
                slot = _Slot(action, actor_doc, route, reason, minute, client_ip, sorted(required or []))
            if key not in bucket:
                bucket[key] = slot
                self._slot_count += 1
            slot.count += 1
        self._write_slots(ready)

    def _take_ready(self, current: str, complete_only: bool) -> list[_Slot]:
        """Pop every slot of a finished minute (all of them unless complete_only). Caller holds _agg_lock."""
        minutes = sorted(m for m in self._pending if not complete_only or m < current)
        ready: list[_Slot] = []
        for minute in minutes:
            bucket = self._pending.pop(minute)
            ready += [bucket[k] for k in sorted(bucket)]
        self._slot_count -= len(ready)
        return ready

    def _write_slots(self, slots: list[_Slot]) -> None:
        for slot in slots:
            outcome: Outcome = "denied" if slot.action == DENIED_ACTION else "ok"
            try:
                self.append(slot.action, actor=slot.actor, target=slot.route, outcome=outcome,
                            client_ip=slot.client_ip, count=slot.count, detail=slot.detail())
            except Exception:  # audit must not take the kiosk down
                log.exception("audit append failed for %d aggregated %s event(s)", slot.count, slot.action)

    def read(self, limit: int = 100, before_seq: int | None = None) -> tuple[list[dict[str, Any]], int | None]:
        """Newest-first entries with seq < before_seq, and the next before_seq cursor (None = no more)."""
        self.flush_denials(complete_only=True)
        limit = max(1, min(int(limit), READ_MAX))
        out: list[dict[str, Any]] = []
        for entry in self._iter_newest_first():
            if before_seq is not None and entry.get("seq", 0) >= before_seq:
                continue
            if len(out) == limit:
                return out, out[-1]["seq"]
            out.append(entry)
        return out, None

    def verify(self) -> bool:
        """True when every kept line has a valid MAC and chains to its predecessor (the oldest kept line's
        prev_mac is the anchor: its predecessor may have been rotated away)."""
        prev_mac: str | None = None
        prev_seq = 0
        for path in reversed(self.files()):
            for line in _read_lines(path):
                try:
                    entry = json.loads(line)
                    ok = hmac.compare_digest(str(entry["mac"]), entry_mac(self._mac_key, entry)) and (
                        prev_mac is None or (entry["prev_mac"] == prev_mac and entry["seq"] == prev_seq + 1))
                    prev_mac, prev_seq = str(entry["mac"]), int(entry["seq"])
                except (ValueError, KeyError, TypeError):
                    return False
                if not ok:
                    return False
        return True

    def files(self) -> list[Path]:
        """Current file first, then audit.jsonl.1 .. .N (newest to oldest)."""
        rotated = [self._rotated(i) for i in range(1, self._keep + 1)]
        return [p for p in (self.path, *rotated) if p.is_file()]

    # ------------------------------------------------------------------ internals
    def _rotated(self, index: int) -> Path:
        return self.path.with_name(f"{AUDIT_FILE}.{index}")

    def _tail(self) -> tuple[int, str]:
        for path in self.files():
            last = _last_line(path)
            if last is None:
                continue
            try:
                tail = json.loads(last)
                return int(tail["seq"]), str(tail["mac"])
            except (ValueError, KeyError, TypeError):
                log.warning("audit log tail is unreadable; chaining to a digest of its raw bytes")
                return 0, hashlib.sha256(last.encode("utf-8")).hexdigest()
        return 0, GENESIS_MAC

    def _rotate_if_needed(self, incoming: int) -> None:
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return
        if size == 0 or size + incoming <= self._max_bytes:
            return
        with contextlib.suppress(FileNotFoundError):
            self._rotated(self._keep).unlink()
        for i in range(self._keep - 1, 0, -1):
            if self._rotated(i).is_file():
                os.replace(self._rotated(i), self._rotated(i + 1))
        os.replace(self.path, self._rotated(1))

    def _iter_newest_first(self) -> Iterator[dict[str, Any]]:
        for path in self.files():
            for line in reversed(_read_lines(path)):
                try:
                    yield json.loads(line)
                except ValueError:
                    continue

    @contextlib.contextmanager
    def _file_lock(self) -> Iterator[None]:
        self.data_dir.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
        fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, FILE_MODE)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def _read_lines(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    return [ln for ln in text.splitlines() if ln.strip()]


def _last_line(path: Path) -> str | None:
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - TAIL_BYTES))
            chunk = fh.read().decode("utf-8", errors="replace")
    except FileNotFoundError:
        return None
    lines = [ln for ln in chunk.splitlines() if ln.strip()]
    return lines[-1] if lines else None
