"""Minimal, encrypted, hash-chained decision log + sync queue (docs/SURPRISE_CHALLENGES.md §SC2.5).

Stored per decision: exactly the SC2.5 whitelist (no images, crops, embeddings, display names, TOTP /
override code values, raw card IDs). Payload = AES-256-GCM(JSON) with a key derived from EDGE_DATA_KEY,
bound (AAD) to kiosk_id|seq|attempt_id. Hash chain:
    genesis      = sha256("genesis:" + kiosk_id)
    record_hash  = sha256(prev_hash_hex_ascii || canonical_json(record minus prev_hash/record_hash))
One record per attempt_id: STEP_UP decisions wait in `pending` (also encrypted) and enter the chain
once the attempt is final (ALLOW / DENY, or abandoned -> its last STEP_UP), so the server never sees
two different records for one attempt (no false SYNC_CONFLICT).
Retention: deleted on server ack; unsynced records older than max_retention_hours are purged and a
tombstone {count, first_seq, last_seq, chain_head} is queued instead.
Deletion evidence (EO-06): every seq that leaves the table legitimately (server ack or retention tombstone) is
recorded in an authenticated (AES-GCM) range set; verify_chain() reports the first seq below next_seq that is
neither present nor covered, so `DELETE FROM decision_log WHERE seq=3` (no key needed) is detected locally.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import threading
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from edge.offline.bundle import canonical_json
from edge.offline.crypto import DataCipher
from edge.policy.lockouts import FailureRecord

RECORD_FIELDS = (
    "attempt_id", "seq", "kiosk_id", "zone", "ts_utc", "user_id", "candidate_user_id", "decision",
    "reason_codes", "resolved_codes", "scores", "fallback", "schedule_version", "cache_state", "mode",
    "prev_hash", "record_hash",
)
LOG_SCORES = {  # response score key -> log key (float scalars only, 2 dp, no per-frame data; API.md 4.4)
    "pad_mean": "pad", "flash_r": "flash", "flash_amp": "flash_amp", "moire": "moire", "device_conf": "device",
    "match_local": "match", "match_margin": "margin", "rekognition": "rek", "rekognition_runner_up": "rek_runner_up",
}
FALLBACK_FIELDS = ("method", "staff_id", "code_id", "totp_step")  # API.md FallbackUsed + totp_step (lead:
# a time-step counter, not a secret -> lets the cloud detect cross-kiosk TOTP replay, Y07); never code values

_SCHEMA = """
CREATE TABLE IF NOT EXISTS decision_log(
  seq INTEGER PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL, ts_utc TEXT NOT NULL, payload BLOB NOT NULL,
  prev_hash TEXT NOT NULL, record_hash TEXT NOT NULL, synced_at TEXT);
CREATE TABLE IF NOT EXISTS pending(attempt_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, payload BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS tombstones(id TEXT PRIMARY KEY, created_at TEXT NOT NULL, payload BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""


def _owner_only(path: str) -> None:
    """chmod 600 for an on-disk SQLite file (created with the process umask, typically 644)."""
    if path != ":memory:" and os.path.exists(path):
        os.chmod(path, 0o600)


def iso_utc(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def genesis_hash(kiosk_id: str) -> str:
    return hashlib.sha256(("genesis:" + kiosk_id).encode("utf-8")).hexdigest()


def compute_record_hash(prev_hash: str, record: Mapping[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k not in ("prev_hash", "record_hash")}
    return hashlib.sha256(prev_hash.encode("ascii") + canonical_json(body)).hexdigest()


def _round(v: Any, nd: int) -> float | None:
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, int | float) and math.isfinite(v):
        return round(float(v), nd)
    return None  # nested / unknown / non-finite values are not logged


def minimal_record(decision: Any, decimals: int = 2) -> dict[str, Any]:
    """SC2.5 whitelist from a policy Decision (seq / prev_hash / record_hash added by the log)."""
    scores = {LOG_SCORES[k]: _round(v, decimals) for k, v in (decision.scores or {}).items() if k in LOG_SCORES}
    fb = decision.fallback
    fallback = {k: fb.get(k) for k in FALLBACK_FIELDS} if fb and fb.get("method") else None
    t = decision.t0 or decision.decided_at
    return {
        "attempt_id": decision.attempt_id,
        "kiosk_id": decision.kiosk_id,
        "zone": decision.zone or "UNKNOWN",
        "ts_utc": iso_utc(t) if t else None,
        "user_id": decision.user_id,
        "candidate_user_id": decision.candidate_user_id if decision.bio_result == "BIO_FAIL" else None,
        "decision": decision.decision,
        "reason_codes": list(decision.reason_codes),
        "resolved_codes": list(decision.resolved_codes),
        "scores": scores,
        "fallback": fallback,
        "schedule_version": decision.bundle_version,
        "cache_state": decision.cache_state,
        "mode": decision.mode,
    }


class ChainError(Exception):
    pass


class DecisionLog:
    def __init__(self, path: Path | str, data_key: str | bytes, kiosk_id: str, *, retention_hours: float = 24) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.kiosk_id = kiosk_id
        self.retention = timedelta(hours=float(retention_hours))
        self._c = DataCipher(data_key, "decision-log")
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        _owner_only(self.path)
        self._db.execute("PRAGMA secure_delete = ON")  # purged rows are overwritten, not left in free pages
        self._db.execute("PRAGMA journal_mode = DELETE")
        self._db.executescript(_SCHEMA)
        cols = {r[1] for r in self._db.execute("PRAGMA table_info(decision_log)")}
        if "created_real" not in cols:  # migration: real-clock creation time drives the retention purge
            self._db.execute("ALTER TABLE decision_log ADD COLUMN created_real TEXT")
        self.evidence_rebased = False  # True = the removal evidence had to be re-baselined (runtime alert)
        with self._lock:
            if self._evidence() is None:
                self._baseline_evidence()

    def _baseline_evidence(self) -> None:
        """First open of a fresh log, or a log whose evidence is missing / unauthenticated (pre-upgrade file OR
        tampering -- indistinguishable locally): every currently absent seq is taken as removed, and a non-fresh
        log raises `evidence_rebased` so the runtime alerts (the cloud's gap check stays authoritative)."""
        present = {r[0] for r in self._db.execute("SELECT seq FROM decision_log")}
        next_seq = int(self._meta("next_seq", "1") or 1)
        self.evidence_rebased = next_seq > 1 or self._meta(_RANGES_KEY) is not None
        ranges = _add_seqs([], [q for q in range(1, next_seq) if q not in present])
        self._save_evidence(ranges, next_seq, self._meta("chain_head") or genesis_hash(self.kiosk_id))

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ------------------------------------------------------------ meta helpers
    def _meta(self, k: str, default: str | None = None) -> str | None:
        row = self._db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return row[0] if row else default

    def _set_meta(self, k: str, v: str) -> None:
        self._db.execute("INSERT INTO meta(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))

    def chain_head(self) -> str:
        with self._lock:
            return self._meta("chain_head") or genesis_hash(self.kiosk_id)

    def fallback_epoch(self) -> str | None:
        """Epoch of the fallback-state file this log last ran with (EO-12 reset detection)."""
        with self._lock:
            return self._meta("fallback_epoch")

    def set_fallback_epoch(self, epoch: str) -> None:
        with self._lock:
            self._set_meta("fallback_epoch", str(epoch))

    # ------------------------------------------------------------ deletion evidence (EO-06)
    def _evidence(self) -> dict[str, Any] | None:
        """Authenticated {ranges, next_seq, chain_head}: removed seqs + the authentic chain tip (detects tail
        deletion with a rewritten plain next_seq / chain_head, EO-06). None = missing or tampered."""
        raw = self._meta(_RANGES_KEY)
        if raw is None:
            return None
        try:
            data = json.loads(self._c.decrypt(bytes.fromhex(raw), _RANGES_AAD + self.kiosk_id.encode()))
            return {"ranges": [[int(a), int(b)] for a, b in data["ranges"]], "next_seq": int(data["next_seq"]),
                    "chain_head": str(data["chain_head"])}
        except Exception:  # noqa: BLE001 - tag failure / garbage / old format = unauthenticated
            return None

    def _save_evidence(self, ranges: list[list[int]], next_seq: int, chain_head: str) -> None:
        body = {"ranges": ranges, "next_seq": int(next_seq), "chain_head": chain_head}
        blob = self._c.encrypt(json.dumps(body).encode(), _RANGES_AAD + self.kiosk_id.encode())
        self._set_meta(_RANGES_KEY, blob.hex())

    def _cover(self, seqs: Iterable[int]) -> None:
        ev = self._evidence() or {"ranges": [], "next_seq": int(self._meta("next_seq", "1") or 1),
                                  "chain_head": self.chain_head()}
        self._save_evidence(_add_seqs(ev["ranges"], seqs), ev["next_seq"], ev["chain_head"])

    def _aad(self, seq: int | str, attempt_id: str) -> bytes:
        return f"{self.kiosk_id}|{seq}|{attempt_id}".encode()

    def _enc(self, obj: Mapping[str, Any], aad: bytes) -> bytes:
        return self._c.encrypt(canonical_json(obj), aad)

    def _dec(self, blob: bytes, aad: bytes) -> dict[str, Any]:
        return json.loads(self._c.decrypt(blob, aad))

    def _dec_rows(self, rows: Iterable[tuple[Any, str, bytes]], kind: str) -> list[dict[str, Any]]:
        """Decrypt rows; an unauthenticated row (tampered / foreign key) is reported, never fatal."""
        out = []
        for key, attempt_id, blob in rows:
            try:
                out.append(self._dec(blob, self._aad(key if kind == "log" else kind, attempt_id)))
            except Exception:  # noqa: BLE001 - AES-GCM tag failure
                out.append({"attempt_id": attempt_id, "seq": key if kind == "log" else None,
                            "error": "UNDECRYPTABLE (tampered or written with another key/kiosk)"})
        return out

    # ------------------------------------------------------------ writes
    def has_final(self, attempt_id: str) -> bool:
        with self._lock:
            return self._db.execute("SELECT 1 FROM decision_log WHERE attempt_id=?", (attempt_id,)).fetchone() is not None

    def put_pending(self, record: Mapping[str, Any], now: datetime) -> None:
        rec = {k: record.get(k) for k in RECORD_FIELDS if k not in ("seq", "prev_hash", "record_hash")}
        with self._lock:
            self._db.execute(
                "INSERT INTO pending(attempt_id, created_at, payload) VALUES(?,?,?) "
                "ON CONFLICT(attempt_id) DO UPDATE SET payload=excluded.payload",
                (rec["attempt_id"], iso_utc(now), self._enc(rec, self._aad("pending", rec["attempt_id"]))),
            )

    def append_final(self, record: Mapping[str, Any], *, created_real: datetime | None = None) -> dict[str, Any]:
        """Append a final record to the chain (removes any pending row for the attempt). `created_real` = real
        wall time of the write (the runtime passes it; the retention purge uses it, never the demo clock)."""
        rec = {k: record.get(k) for k in RECORD_FIELDS if k not in ("seq", "prev_hash", "record_hash")}
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                if self._db.execute("SELECT 1 FROM decision_log WHERE attempt_id=?", (rec["attempt_id"],)).fetchone():
                    raise ChainError(f"attempt {rec['attempt_id']} already has a final record")
                seq = int(self._meta("next_seq", "1"))
                prev = self._meta("chain_head") or genesis_hash(self.kiosk_id)
                rec["seq"] = seq
                rec["prev_hash"] = prev
                rec["record_hash"] = compute_record_hash(prev, rec)
                self._db.execute(
                    "INSERT INTO decision_log(seq, attempt_id, ts_utc, payload, prev_hash, record_hash, created_real) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (seq, rec["attempt_id"], rec["ts_utc"] or "", self._enc(rec, self._aad(seq, rec["attempt_id"])),
                     prev, rec["record_hash"], iso_utc(created_real) if created_real else None),
                )
                self._db.execute("DELETE FROM pending WHERE attempt_id=?", (rec["attempt_id"],))
                self._set_meta("next_seq", str(seq + 1))
                self._set_meta("chain_head", rec["record_hash"])
                ev = self._evidence()
                self._save_evidence(ev["ranges"] if ev else [], seq + 1, rec["record_hash"])
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return rec

    # ------------------------------------------------------------ reads
    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute("SELECT seq, attempt_id, payload FROM decision_log ORDER BY seq").fetchall()
            return self._dec_rows(rows, "log")

    def pending(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute("SELECT attempt_id, attempt_id, payload FROM pending ORDER BY created_at").fetchall()
            return self._dec_rows(rows, "pending")

    def unsynced(self, limit: int) -> list[dict[str, Any]]:
        """Next records to sync (undecryptable rows are skipped; the retention purge tombstones them)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT seq, attempt_id, payload FROM decision_log WHERE synced_at IS NULL ORDER BY seq LIMIT ?",
                (int(limit),)).fetchall()
            return [r for r in self._dec_rows(rows, "log") if "error" not in r]

    def queue_depth(self) -> int:
        with self._lock:
            n = self._db.execute("SELECT COUNT(*) FROM decision_log WHERE synced_at IS NULL").fetchone()[0]
            return int(n) + len(self.tombstones())

    def tombstones(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute("SELECT id, id, payload FROM tombstones ORDER BY created_at").fetchall()
            return [r for r in self._dec_rows(rows, "tombstone") if "error" not in r]

    # ------------------------------------------------------------ sync acks / retention
    def ack(self, attempt_ids: Iterable[str]) -> int:
        """Server acknowledged (accepted or duplicate): purge those records now."""
        ids = list(attempt_ids)
        with self._lock:
            n, seqs = 0, []
            self._db.execute("BEGIN IMMEDIATE")  # delete + evidence in one transaction (no false tamper on a crash)
            try:
                for a in ids:
                    row = self._db.execute("SELECT seq FROM decision_log WHERE attempt_id=?", (a,)).fetchone()
                    if row is None:
                        continue
                    n += self._db.execute("DELETE FROM decision_log WHERE seq=?", (row[0],)).rowcount
                    seqs.append(int(row[0]))
                if seqs:
                    self._cover(seqs)
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            return n

    def ack_tombstones(self, ids: Iterable[str]) -> int:
        with self._lock:
            return sum(self._db.execute("DELETE FROM tombstones WHERE id=?", (i,)).rowcount for i in ids)

    def purge_expired(self, now: datetime) -> dict[str, Any] | None:
        """Unsynced records older than the retention window -> deleted + one tombstone queued. Age = real
        creation time when recorded (`created_real`), else the record timestamp; `now` = real wall time."""
        cutoff = iso_utc(now - self.retention)
        with self._lock:
            rows = self._db.execute(
                "SELECT seq FROM decision_log WHERE synced_at IS NULL AND COALESCE(created_real, ts_utc) < ? "
                "ORDER BY seq", (cutoff,)
            ).fetchall()
            if not rows:
                return None
            seqs = [r[0] for r in rows]
            tomb = {"type": "TOMBSTONE", "kiosk_id": self.kiosk_id, "count": len(seqs), "first_seq": seqs[0],
                    "last_seq": seqs[-1], "chain_head": self.chain_head(), "purged_at": iso_utc(now)}
            tid = f"tomb_{self.kiosk_id}_{seqs[0]}_{seqs[-1]}"
            tomb["tombstone_id"] = tid
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.executemany("DELETE FROM decision_log WHERE seq=?", [(s,) for s in seqs])
                self._db.execute("INSERT OR REPLACE INTO tombstones(id, created_at, payload) VALUES(?,?,?)",
                                 (tid, iso_utc(now), self._enc(tomb, self._aad("tombstone", tid))))
                self._cover(seqs)
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            return tomb

    def stale_pending(self, older_than: datetime) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute("SELECT attempt_id, attempt_id, payload FROM pending WHERE created_at < ?",
                                    (iso_utc(older_than),)).fetchall()
            return [r for r in self._dec_rows(rows, "pending") if "error" not in r]

    # ------------------------------------------------------------ tamper evidence
    def verify_chain(self) -> tuple[bool, int | None]:
        """Recompute every remaining record's hash and the links between consecutive records.

        Returns (True, None) or (False, first_bad_seq). Acked / tombstoned records leave gaps that only the server
        (which holds them) can bridge; any OTHER missing seq below next_seq is reported as the first bad seq
        (EO-06: a deleted unsynced record)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT seq, attempt_id, payload, prev_hash, record_hash FROM decision_log ORDER BY seq").fetchall()
            ev = self._evidence()
            meta_next = int(self._meta("next_seq", "1") or 1)
            meta_head = self._meta("chain_head") or genesis_hash(self.kiosk_id)
        if ev is None:  # evidence missing / tampered since open
            return False, (rows[0][0] if rows else max(1, meta_next - 1))
        if ev["next_seq"] != meta_next or ev["chain_head"] != meta_head:  # rewritten tip (tail deletion)
            return False, max(1, min(ev["next_seq"], meta_next) - 1)
        missing = _first_uncovered(ev["next_seq"], {r[0] for r in rows}, ev["ranges"])
        if missing is not None:
            return False, missing
        prev_seq, prev_hash = None, None
        for seq, attempt_id, payload, row_prev, row_hash in rows:
            try:
                rec = self._dec(payload, self._aad(seq, attempt_id))
            except Exception:  # noqa: BLE001 - authentication failure = tampering
                return False, seq
            if (rec.get("seq") != seq or rec.get("prev_hash") != row_prev or rec.get("record_hash") != row_hash
                    or compute_record_hash(row_prev, rec) != row_hash):
                return False, seq
            if seq == 1 and row_prev != genesis_hash(self.kiosk_id):
                return False, seq
            if prev_seq is not None and seq == prev_seq + 1 and row_prev != prev_hash:
                return False, seq
            prev_seq, prev_hash = seq, row_hash
        return True, None


_RANGES_KEY = "removal_evidence_v2"
_RANGES_AAD = b"removed-ranges|"


def _add_seqs(ranges: list[list[int]], seqs: Iterable[int]) -> list[list[int]]:
    """Merge seqs into a sorted list of inclusive [lo, hi] ranges (new list; inputs untouched)."""
    points = sorted({int(q) for q in seqs})
    merged = sorted([list(r) for r in ranges] + [[q, q] for q in points])
    out: list[list[int]] = []
    for lo, hi in merged:
        if out and lo <= out[-1][1] + 1:
            out[-1] = [out[-1][0], max(out[-1][1], hi)]
        else:
            out.append([lo, hi])
    return out


def _first_uncovered(next_seq: int, present: set[int], ranges: list[list[int]] | None) -> int | None:
    """Smallest seq in [1, next_seq) that is neither present nor legitimately removed (None = complete)."""
    if ranges is None:
        return 1 if next_seq > 1 else None  # evidence missing or tampered: the whole history is unproven
    expected = 1
    for lo, hi in ranges:
        for q in range(expected, min(lo, next_seq)):
            if q not in present:
                return q
        expected = max(expected, hi + 1)
    for q in range(expected, next_seq):
        if q not in present:
            return q
    return None


_LOCKED_FOREVER = datetime(9999, 1, 1, tzinfo=UTC)  # undecryptable failure row -> locked (lockouts.py clamps it)


class SqliteFallbackState:
    """Device-wide fallback state (TOTP last accepted step per user, consumed override codes, second-factor
    failure counters / lockouts).

    One file per edge device (not per KIOSK_ID) so a consumed one-time code, a used TOTP step or a lockout can
    never be replayed / reset after a kiosk switch or a restart (SC2-D9, EO-12). User ids, staff ids and code ids
    are stored only as keyed pseudonyms; failure records are AES-GCM encrypted (a tampered row reads as locked).
    `epoch` = random id written once at creation: the runtime compares it with the decision log to detect a
    deleted / replaced state file (EO-12) and re-seeds consumed codes and TOTP steps from the log."""

    def __init__(self, path: Path | str, data_key: str | bytes) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._c = DataCipher(data_key, "fallback-state")
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        _owner_only(self.path)
        self._db.execute("PRAGMA secure_delete = ON")
        self._db.executescript(
            "CREATE TABLE IF NOT EXISTS fb_totp(user_key TEXT PRIMARY KEY, step INTEGER NOT NULL);"
            "CREATE TABLE IF NOT EXISTS fb_consumed(code_key TEXT PRIMARY KEY, consumed_at TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS fb_fail(scope_key TEXT PRIMARY KEY, payload BLOB NOT NULL);"
            "CREATE TABLE IF NOT EXISTS fb_meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);")
        row = self._db.execute("SELECT v FROM fb_meta WHERE k='epoch'").fetchone()
        self.created_new = row is None
        if row is None:
            self.epoch = os.urandom(16).hex()
            self._db.execute("INSERT INTO fb_meta(k, v) VALUES('epoch', ?)", (self.epoch,))
        else:
            self.epoch = str(row[0])

    def _key(self, value: str) -> str:
        return self._c.pseudonym(value)

    def totp_last_step(self, user_id: str) -> int | None:
        with self._lock:
            row = self._db.execute("SELECT step FROM fb_totp WHERE user_key=?", (self._key(user_id),)).fetchone()
            return int(row[0]) if row else None

    def set_totp_last_step(self, user_id: str, step: int) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO fb_totp(user_key, step) VALUES(?,?) ON CONFLICT(user_key) DO UPDATE SET step=excluded.step",
                (self._key(user_id), int(step)))

    def is_code_consumed(self, code_id: str) -> bool:
        with self._lock:
            return self._db.execute("SELECT 1 FROM fb_consumed WHERE code_key=?",
                                    (self._key(code_id),)).fetchone() is not None

    def consume_code(self, code_id: str, at: datetime) -> None:
        with self._lock:
            self._db.execute("INSERT OR IGNORE INTO fb_consumed(code_key, consumed_at) VALUES(?,?)",
                             (self._key(code_id), iso_utc(at)))

    def failure_record(self, scope: str) -> FailureRecord | None:
        key = self._key("fail:" + scope)
        with self._lock:
            row = self._db.execute("SELECT payload FROM fb_fail WHERE scope_key=?", (key,)).fetchone()
        if row is None:
            return None
        try:
            d = json.loads(self._c.decrypt(row[0], key.encode()))
            times = tuple(t for t in (_parse_iso(x) for x in d.get("times") or []) if t is not None)
            return FailureRecord(failures=int(d.get("failures") or 0), window_start=_parse_iso(d.get("window_start")),
                                 locked_until=_parse_iso(d.get("locked_until")), times=times)
        except Exception:  # noqa: BLE001 - tampered / foreign-key row: fail secure = locked
            return FailureRecord(locked_until=_LOCKED_FOREVER)

    def set_failure_record(self, scope: str, record: FailureRecord | None) -> None:
        key = self._key("fail:" + scope)
        with self._lock:
            if record is None:
                self._db.execute("DELETE FROM fb_fail WHERE scope_key=?", (key,))
                return
            body = {"failures": int(record.failures),
                    "window_start": iso_utc(record.window_start) if record.window_start else None,
                    "locked_until": iso_utc(record.locked_until) if record.locked_until else None,
                    "times": [record_time(t) for t in record.times]}
            self._db.execute(
                "INSERT INTO fb_fail(scope_key, payload) VALUES(?,?) "
                "ON CONFLICT(scope_key) DO UPDATE SET payload=excluded.payload",
                (key, self._c.encrypt(json.dumps(body).encode(), key.encode())))

    def purge_totp_before(self, step: int) -> int:
        """Replay protection only matters inside the +-window: older last-steps can never collide again."""
        with self._lock:
            return self._db.execute("DELETE FROM fb_totp WHERE step < ?", (int(step),)).rowcount

    def close(self) -> None:
        with self._lock:
            self._db.close()


def record_time(t: datetime) -> str:
    """Failure-time stamp with microseconds (sliding windows need sub-second order)."""
    return t.astimezone(UTC).isoformat()


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    return datetime.fromisoformat(value)  # 3.11 parses a trailing Z


def reseed_fallback_state(state: Any, log: DecisionLog, at: datetime) -> dict[str, int]:
    """EO-12 recovery: re-mark every override code and TOTP step recorded in the (unsynced) decision log as used,
    so deleting fallback_state.sqlite cannot make a consumed code / used step valid again. Synced records are gone
    locally; the cloud retires their codes through the signed bundle's consumed_code_ids (SC2-D8). Tighten-only."""
    codes = steps = 0
    for rec in log.records() + log.pending():
        fb = rec.get("fallback") if isinstance(rec, Mapping) else None
        if not isinstance(fb, Mapping) or rec.get("decision") != "ALLOW":
            continue
        cid, step, uid = fb.get("code_id"), fb.get("totp_step"), rec.get("user_id")
        if isinstance(cid, str) and cid and not state.is_code_consumed(cid):
            state.consume_code(cid, at)
            codes += 1
        if isinstance(step, int) and isinstance(uid, str) and uid:
            last = state.totp_last_step(uid)
            if last is None or step > last:
                state.set_totp_last_step(uid, step)
                steps += 1
    return {"codes": codes, "totp_steps": steps}
