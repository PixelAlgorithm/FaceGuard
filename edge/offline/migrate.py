"""One-time, replay-safe migration of the pre-per-kiosk decision log (`<data_dir>/decisions.sqlite`).

Before the log became per kiosk (`decisions_<KIOSK_ID>.sqlite`) one file held the chain, the pending STEP_UPs,
the tombstones and the fallback replay state. Its unsynced records were orphaned (never synced, never purged).
At startup (edge/policy/runtime.py from_env) this module:

1. deletes archives of earlier migrations that are older than the retention window (no copy outlives the TTL);
2. identifies the writing kiosk: the AES-GCM AAD binds kiosk_id|seq|attempt_id, so only the right kiosk id +
   data key decrypt (candidates: this kiosk + every existing `decisions_<K>.sqlite`); unknown -> left in place;
3. verifies each unsynced row (decrypts, seq / attempt / kiosk / record_hash recomputed) and re-appends it to
   that kiosk's per-kiosk chain with its ORIGINAL creation time (the 24 h purge is never extended); content is
   unchanged, only seq / prev_hash / record_hash are re-chained; rows already synced are dropped;
4. finalizes legacy pending STEP_UPs like abandoned attempts (runtime `_sweep`: last STEP_UP becomes final);
5. merges the fallback replay state (consumed codes, TOTP last steps) into fallback_state.sqlite, tighten-only;
6. deletes each moved row from the source (secure_delete), so an interrupted run never duplicates a record;
7. when nothing is left: renames the file to `decisions.sqlite.migrated-<UTC stamp>` (mode 0600).

`purge_foreign_logs` (EO-07) keeps the 24 h retention on the per-kiosk logs of other kiosk ids, which this
process never syncs, and reports what is still queued there (ALERT_ORPHANED_QUEUE).

Anything it cannot move unambiguously (undecryptable / tampered rows, legacy tombstones whose seqs would clash
with the per-kiosk chain, unknown kiosk or key) stays in the source file, which is then NOT archived, and the
report carries an `error` for the operator. Never raises into startup: the caller gets a report.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from edge.offline.crypto import DataCipher
from edge.offline.store import DecisionLog, SqliteFallbackState, compute_record_hash

LEGACY_NAME = "decisions.sqlite"
ARCHIVE_PREFIX = LEGACY_NAME + ".migrated-"
LOG_PREFIX, LOG_SUFFIX = "decisions_", ".sqlite"  # per-kiosk logs: decisions_<KIOSK_ID>.sqlite
_STAMP = "%Y%m%dT%H%M%SZ"


def _tables(db: sqlite3.Connection) -> set[str]:
    return {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _parse_utc(s: Any) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(s))  # py3.11 parses a trailing "Z"
    except (TypeError, ValueError):
        return None
    return t.astimezone(UTC) if t.tzinfo else None


def purge_old_archives(data_dir: Path, now: datetime, retention: timedelta) -> int:
    n = 0
    for p in data_dir.glob(ARCHIVE_PREFIX + "*"):
        try:
            made = datetime.strptime(p.name[len(ARCHIVE_PREFIX):], _STAMP).replace(tzinfo=UTC)
        except ValueError:
            continue  # not ours
        if made < now - retention:
            p.unlink(missing_ok=True)
            n += 1
    return n


def _identify_kiosk(db: sqlite3.Connection, cipher: DataCipher, candidates: list[str]) -> str | None:
    """The kiosk whose AAD authenticates a legacy row (AES-GCM: wrong kiosk id or key -> tag failure)."""
    probes: list[tuple[str, bytes]] = []
    tables = _tables(db)
    if "decision_log" in tables:
        probes += [(f"{seq}|{aid}", blob) for seq, aid, blob in
                   db.execute("SELECT seq, attempt_id, payload FROM decision_log ORDER BY seq LIMIT 5")]
    if "pending" in tables:
        probes += [(f"pending|{aid}", blob) for aid, blob in
                   db.execute("SELECT attempt_id, payload FROM pending LIMIT 5")]
    for k in candidates:
        for suffix, blob in probes:
            try:
                cipher.decrypt(blob, f"{k}|{suffix}".encode())
                return k
            except Exception:  # noqa: BLE001, S112 - tag failure: not this kiosk / key (expected, not logged)
                continue
    return None


def _decrypt_record(cipher: DataCipher, kiosk: str, seq: int, aid: str, blob: bytes, prev: str,
                    rhash: str) -> dict[str, Any] | None:
    try:
        rec = json.loads(cipher.decrypt(blob, f"{kiosk}|{seq}|{aid}".encode()))
    except Exception:  # noqa: BLE001
        return None
    if (not isinstance(rec, dict) or rec.get("seq") != seq or rec.get("attempt_id") != aid
            or rec.get("kiosk_id") != kiosk or rec.get("prev_hash") != prev or rec.get("record_hash") != rhash
            or compute_record_hash(prev, rec) != rhash):
        return None
    return rec


def _normalise(rec: dict[str, Any]) -> dict[str, Any]:
    out = dict(rec)
    if not out.get("zone"):
        out["zone"] = "UNKNOWN"  # same rule as store.minimal_record (an older writer could leave it null)
    return out


def migrate_legacy_log(data_dir: Path | str, data_key: str | bytes, log: DecisionLog,
                       fb_state: SqliteFallbackState | None = None, *, now: datetime,
                       retention_hours: float = 24.0) -> dict[str, Any] | None:
    """Migrate `<data_dir>/decisions.sqlite` into the per-kiosk log(s). Returns a report, or None when there
    was nothing to do. `now` = real wall time (UTC-aware)."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    data_dir = Path(data_dir)
    rep: dict[str, Any] = {"source": LEGACY_NAME, "kiosk_id": None, "migrated": 0, "skipped_synced": 0,
                           "already_present": 0, "pending_finalized": 0, "undecryptable": 0, "tombstones_left": 0,
                           "fallback_rows": 0, "archived_to": None, "archives_purged": 0, "error": None}
    try:
        rep["archives_purged"] = purge_old_archives(data_dir, now, timedelta(hours=float(retention_hours)))
        src = data_dir / LEGACY_NAME
        if not src.is_file() or src.resolve() == Path(log.path).resolve():
            return rep if rep["archives_purged"] else None
        _migrate(src, data_dir, data_key, log, fb_state, now, float(retention_hours), rep)
    except Exception as exc:  # noqa: BLE001 - never break startup; the report carries the error
        rep["error"] = f"{type(exc).__name__}: {exc}"
    return rep


def _migrate(src: Path, data_dir: Path, data_key: str | bytes, log: DecisionLog,
             fb_state: SqliteFallbackState | None, now: datetime, retention_hours: float,
             rep: dict[str, Any]) -> None:
    cipher = DataCipher(data_key, "decision-log")
    db = sqlite3.connect(src, isolation_level=None)
    try:
        db.execute("PRAGMA secure_delete = ON")  # moved payloads are overwritten in the source file
        tables = _tables(db)
        has_rows = any(db.execute(f"SELECT 1 FROM {t} LIMIT 1").fetchone()  # fixed table names
                       for t in ("decision_log", "pending") if t in tables)
        target = log
        if has_rows:
            others = sorted(p.name[len(LOG_PREFIX):-len(LOG_SUFFIX)] for p in data_dir.glob(f"{LOG_PREFIX}*{LOG_SUFFIX}"))
            kiosk = _identify_kiosk(db, cipher, [log.kiosk_id] + [k for k in others if k != log.kiosk_id])
            if kiosk is None:
                rep["error"] = "UNKNOWN_KIOSK_OR_KEY: no known kiosk id / data key decrypts the legacy log; left in place"
                return
            rep["kiosk_id"] = kiosk
            if kiosk != log.kiosk_id:
                target = DecisionLog(data_dir / f"decisions_{kiosk}.sqlite", data_key, kiosk,
                                     retention_hours=retention_hours)
        else:
            rep["kiosk_id"] = log.kiosk_id
        try:
            cols = {r[1] for r in db.execute("PRAGMA table_info(decision_log)")} if "decision_log" in tables else set()
            created_col = "created_real" if "created_real" in cols else "NULL"
            if "decision_log" in tables:
                rows = db.execute(f"SELECT seq, attempt_id, ts_utc, payload, prev_hash, record_hash, synced_at, "
                                  f"{created_col} FROM decision_log ORDER BY seq").fetchall()
                for seq, aid, ts, blob, prev, rhash, synced_at, created in rows:
                    if synced_at:  # already on the server (purge on ack)
                        db.execute("DELETE FROM decision_log WHERE seq=?", (seq,))
                        rep["skipped_synced"] += 1
                        continue
                    rec = _decrypt_record(cipher, rep["kiosk_id"], seq, aid, blob, prev, rhash)
                    if rec is None:
                        rep["undecryptable"] += 1
                        continue
                    if target.has_final(aid):
                        rep["already_present"] += 1
                    else:
                        target.append_final(_normalise(rec), created_real=_parse_utc(created) or _parse_utc(ts))
                        rep["migrated"] += 1
                    db.execute("DELETE FROM decision_log WHERE seq=?", (seq,))
            if "pending" in tables:
                for aid, created, blob in db.execute("SELECT attempt_id, created_at, payload FROM pending").fetchall():
                    try:
                        rec = json.loads(cipher.decrypt(blob, f"{rep['kiosk_id']}|pending|{aid}".encode()))
                    except Exception:  # noqa: BLE001
                        rep["undecryptable"] += 1
                        continue
                    if not isinstance(rec, dict) or rec.get("attempt_id") != aid:
                        rep["undecryptable"] += 1
                        continue
                    if target.has_final(aid):
                        rep["already_present"] += 1
                    else:  # abandoned attempt -> its last STEP_UP becomes final (runtime _sweep rule)
                        target.append_final(_normalise(rec), created_real=_parse_utc(created) or _parse_utc(
                            rec.get("ts_utc")))
                        rep["pending_finalized"] += 1
                    db.execute("DELETE FROM pending WHERE attempt_id=?", (aid,))
            if "tombstones" in tables:
                rep["tombstones_left"] = int(db.execute("SELECT COUNT(*) FROM tombstones").fetchone()[0])
            _merge_fallback(db, tables, fb_state, rep)
        finally:
            if target is not log:
                target.close()
    finally:
        db.close()
    left = rep["undecryptable"] + rep["tombstones_left"]
    if left:
        rep["error"] = (f"{rep['undecryptable']} undecryptable/tampered row(s), {rep['tombstones_left']} legacy "
                        f"tombstone(s): left in place for operator review (file not archived)")
        return
    dst = data_dir / f"{ARCHIVE_PREFIX}{now.astimezone(UTC).strftime(_STAMP)}"
    os.chmod(src, 0o600)
    os.replace(src, dst)
    os.chmod(dst, 0o600)
    rep["archived_to"] = dst.name


def _merge_fallback(db: sqlite3.Connection, tables: set[str], fb: SqliteFallbackState | None,
                    rep: dict[str, Any]) -> None:
    """Legacy fallback replay state -> device-wide store. Same pseudonym label ("fallback-state"), merged
    tighten-only (a consumed code stays consumed; a TOTP last step is never lowered)."""
    if fb is None:
        return
    with fb._lock:  # same package: the raw keyed pseudonyms are copied as-is
        if "fb_consumed" in tables:
            for key, at in db.execute("SELECT code_key, consumed_at FROM fb_consumed").fetchall():
                fb._db.execute("INSERT OR IGNORE INTO fb_consumed(code_key, consumed_at) VALUES(?,?)", (key, at))
                db.execute("DELETE FROM fb_consumed WHERE code_key=?", (key,))
                rep["fallback_rows"] += 1
        if "fb_totp" in tables:
            for key, step in db.execute("SELECT user_key, step FROM fb_totp").fetchall():
                fb._db.execute("INSERT INTO fb_totp(user_key, step) VALUES(?,?) ON CONFLICT(user_key) DO UPDATE "
                               "SET step=MAX(step, excluded.step)", (key, int(step)))
                db.execute("DELETE FROM fb_totp WHERE user_key=?", (key,))
                rep["fallback_rows"] += 1


def _foreign_kiosk(path: Path, active_kiosk: str) -> str | None:
    name = path.name
    if not (name.startswith(LOG_PREFIX) and name.endswith(LOG_SUFFIX)):
        return None
    kiosk = name[len(LOG_PREFIX):-len(LOG_SUFFIX)]
    return kiosk if kiosk and kiosk != active_kiosk else None


def purge_foreign_logs(data_dir: Path | str, data_key: str | bytes, active_kiosk: str, *, now: datetime,
                       retention_hours: float = 24.0) -> list[dict[str, Any]]:
    """EO-07: per-kiosk logs of OTHER kiosk ids (`decisions_<K>.sqlite`, e.g. after a KIOSK_ID switch or a legacy
    migration) are never synced by this process. Apply the same SC2.5 24 h retention to them (unsynced rows
    older than the window -> deleted + tombstone, real clock) and report what is still queued there, so the
    caller raises ALERT_ORPHANED_QUEUE. Call at startup and on every tick. Never raises: a log that cannot be
    opened is reported with an `error`. Returns one entry per foreign log that still holds anything."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    out: list[dict[str, Any]] = []
    for path in sorted(Path(data_dir).glob(f"{LOG_PREFIX}*{LOG_SUFFIX}")):
        kiosk = _foreign_kiosk(path, active_kiosk)
        if kiosk is None:
            continue
        entry: dict[str, Any] = {"kiosk_id": kiosk, "file": path.name, "purged": 0, "queued": 0,
                                 "tombstones": 0, "error": None}
        try:
            log = DecisionLog(path, data_key, kiosk, retention_hours=retention_hours)
            try:
                tomb = log.purge_expired(now)
                entry["purged"] = int(tomb["count"]) if tomb else 0
                entry["tombstones"] = len(log.tombstones())
                entry["queued"] = log.queue_depth() - entry["tombstones"]
            finally:
                log.close()
        except Exception as exc:  # noqa: BLE001 - one bad file must not stop the sweep (or startup)
            entry["error"] = f"{type(exc).__name__}: {exc}"
        if entry["purged"] or entry["queued"] or entry["tombstones"] or entry["error"]:
            out.append(entry)
    return out


__all__ = ["ARCHIVE_PREFIX", "LEGACY_NAME", "migrate_legacy_log", "purge_foreign_logs", "purge_old_archives"]
