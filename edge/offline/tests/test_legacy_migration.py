"""One-time migration of the orphaned pre-per-kiosk decision log (`<data_dir>/decisions.sqlite`) into the
per-kiosk log / sync queue at startup, then archive (rename, mode 0600). Fixtures only (tmp data dirs): never
run against the live edge/data directory."""

from __future__ import annotations

import os
import sqlite3
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from edge.offline.bundle import canonical_json
from edge.offline.crypto import DataCipher
from edge.offline.migrate import ARCHIVE_PREFIX, LEGACY_NAME, migrate_legacy_log
from edge.offline.store import DecisionLog, SqliteFallbackState, compute_record_hash, genesis_hash, iso_utc
from edge.offline.tests.conftest import SyncItem, bring_online
from edge.policy.tests.builders import RT_CLOCK, TEST_DATA_KEY

KIOSK = "KIOSK_LIB_01"  # make_rt's default kiosk
OTHER_KEY = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU="  # a different (valid) data key
# Exact schema of the orphaned file (no created_real column; fallback tables in the same file).
LEGACY_SCHEMA = """
CREATE TABLE decision_log(
  seq INTEGER PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL, ts_utc TEXT NOT NULL, payload BLOB NOT NULL,
  prev_hash TEXT NOT NULL, record_hash TEXT NOT NULL, synced_at TEXT);
CREATE TABLE pending(attempt_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, payload BLOB NOT NULL);
CREATE TABLE tombstones(id TEXT PRIMARY KEY, created_at TEXT NOT NULL, payload BLOB NOT NULL);
CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE fb_totp(user_key TEXT PRIMARY KEY, step INTEGER NOT NULL);
CREATE TABLE fb_consumed(code_key TEXT PRIMARY KEY, consumed_at TEXT NOT NULL);
"""


def rec(aid: str, ts: datetime, kiosk: str = KIOSK, **over) -> dict:
    r = {"attempt_id": aid, "kiosk_id": kiosk, "zone": "LIBRARY", "ts_utc": iso_utc(ts), "user_id": "u_3c4d",
         "candidate_user_id": None, "decision": "ALLOW", "reason_codes": ["ACCESS_OK", "OFFLINE_MODE"],
         "resolved_codes": [], "scores": {"pad": 0.95, "match": 0.72}, "fallback": None, "schedule_version": 42,
         "cache_state": "FRESH", "mode": "OFFLINE"}
    r.update(over)
    return r


def make_legacy(path: Path, records: list[dict], *, kiosk: str = KIOSK, key: str = TEST_DATA_KEY,
                synced: set[str] = frozenset(), pending: list[dict] = (), tombstone: bool = False,
                consumed: list[str] = (), totp: dict[str, int] | None = None) -> None:
    """Write a legacy decisions.sqlite exactly like the pre-per-kiosk DecisionLog did."""
    c = DataCipher(key, "decision-log")
    db = sqlite3.connect(path, isolation_level=None)
    db.executescript(LEGACY_SCHEMA)
    prev = genesis_hash(kiosk)
    for seq, r in enumerate(records, start=1):
        r = {**r, "seq": seq, "prev_hash": prev}
        r["record_hash"] = compute_record_hash(prev, r)
        blob = c.encrypt(canonical_json(r), f"{kiosk}|{seq}|{r['attempt_id']}".encode())
        db.execute("INSERT INTO decision_log VALUES(?,?,?,?,?,?,?)",
                   (seq, r["attempt_id"], r["ts_utc"], blob, prev, r["record_hash"],
                    "2026-11-14T08:30:00Z" if r["attempt_id"] in synced else None))
        prev = r["record_hash"]
    db.execute("INSERT INTO meta VALUES('chain_head', ?)", (prev,))
    db.execute("INSERT INTO meta VALUES('next_seq', ?)", (str(len(records) + 1),))
    for p in pending:
        blob = c.encrypt(canonical_json(p), f"{kiosk}|pending|{p['attempt_id']}".encode())
        db.execute("INSERT INTO pending VALUES(?,?,?)", (p["attempt_id"], p["ts_utc"], blob))
    if tombstone:
        t = {"type": "TOMBSTONE", "kiosk_id": kiosk, "count": 2, "first_seq": 1, "last_seq": 2, "chain_head": prev}
        db.execute("INSERT INTO tombstones VALUES(?,?,?)", ("tomb_x", "2026-11-14T08:00:00Z",
                   c.encrypt(canonical_json(t), f"{kiosk}|tombstone|tomb_x".encode())))
    fb = DataCipher(key, "fallback-state")
    for code_id in consumed:
        db.execute("INSERT INTO fb_consumed VALUES(?,?)", (fb.pseudonym(code_id), "2026-11-14T08:00:00Z"))
    for uid, step in (totp or {}).items():
        db.execute("INSERT INTO fb_totp VALUES(?,?)", (fb.pseudonym(uid), step))
    db.close()
    os.chmod(path, 0o644)  # the orphan on the live box is 0644


def archives(d: Path) -> list[Path]:
    return sorted(d.glob(ARCHIVE_PREFIX + "*"))


NOW = RT_CLOCK()


# ---------------------------------------------------------------- through the runtime (startup)
def test_startup_moves_unsynced_legacy_records_into_the_per_kiosk_queue_and_archives_0600(tmp_path, make_rt):
    t1, t2, t3 = NOW - timedelta(hours=8), NOW - timedelta(hours=7, minutes=57), NOW - timedelta(hours=7)
    make_legacy(tmp_path / LEGACY_NAME, [rec("att_leg1", t1), rec("att_leg_synced", t2), rec("att_leg3", t3)],
                synced={"att_leg_synced"})
    rt = make_rt()
    q = rt.log.unsynced(50)
    assert [r["attempt_id"] for r in q] == ["att_leg1", "att_leg3"]  # the already-synced row is not re-sent
    for r, t in zip(q, (t1, t3), strict=True):
        assert r["ts_utc"] == iso_utc(t) and r["kiosk_id"] == KIOSK and r["decision"] == "ALLOW"
        assert {k: v for k, v in r.items() if k not in ("seq", "prev_hash", "record_hash")} == rec(
            r["attempt_id"], t)  # content unchanged, only re-chained
    assert rt.log.verify_chain() == (True, None)
    assert not (tmp_path / LEGACY_NAME).exists()
    [arc] = archives(tmp_path)
    assert stat.S_IMODE(os.stat(arc).st_mode) == 0o600
    assert rt.legacy_migration["migrated"] == 2 and rt.legacy_migration["skipped_synced"] == 1
    assert rt.legacy_migration["archived_to"] == arc.name and rt.legacy_migration["error"] is None
    [ev] = [e for e in rt.events() if e["type"] == "LEGACY_LOG_MIGRATED"]
    assert ev["migrated"] == 2 and ev["kiosk_id"] == KIOSK


def test_archive_holds_no_decision_payloads(tmp_path, make_rt):
    make_legacy(tmp_path / LEGACY_NAME, [rec("att_leg1", NOW - timedelta(hours=1))])
    make_rt()
    [arc] = archives(tmp_path)
    db = sqlite3.connect(f"file:{arc}?mode=ro", uri=True)
    assert db.execute("SELECT COUNT(*) FROM decision_log").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM pending").fetchone()[0] == 0
    db.close()


def test_migrated_records_sync_under_the_api_contract(tmp_path, make_rt, cloud):
    make_legacy(tmp_path / LEGACY_NAME, [rec("att_leg1", NOW - timedelta(hours=2)),
                                         rec("att_leg2", NOW - timedelta(hours=1))])
    rt = make_rt(cloud)
    bring_online(rt)  # FakeCloud validates SyncItem (extra="forbid") + every HMAC + the chain head HMAC
    assert {"att_leg1", "att_leg2"} <= cloud.stored.keys() and rt.log.queue_depth() == 0
    for aid in ("att_leg1", "att_leg2"):
        SyncItem.model_validate(cloud.stored[aid])


def test_migrated_records_keep_their_original_age_for_the_24h_purge(tmp_path, make_rt):
    make_legacy(tmp_path / LEGACY_NAME, [rec("att_old", NOW - timedelta(hours=25)),
                                         rec("att_new", NOW - timedelta(hours=2))])
    rt = make_rt()
    tomb = rt.log.purge_expired(NOW)
    assert tomb and tomb["count"] == 1  # migration does not extend retention
    assert [r["attempt_id"] for r in rt.log.unsynced(50)] == ["att_new"]


def test_no_legacy_file_is_a_no_op(tmp_path, make_rt):
    rt = make_rt()
    assert rt.legacy_migration is None and not archives(tmp_path)


def test_unknown_key_leaves_the_file_in_place_and_never_breaks_startup(tmp_path, make_rt):
    make_legacy(tmp_path / LEGACY_NAME, [rec("att_leg1", NOW - timedelta(hours=1))], key=OTHER_KEY)
    rt = make_rt()
    assert (tmp_path / LEGACY_NAME).exists() and not archives(tmp_path)
    assert rt.legacy_migration["migrated"] == 0 and "UNKNOWN_KIOSK_OR_KEY" in rt.legacy_migration["error"]
    assert [e["type"] for e in rt.events()].count("ALERT_LEGACY_LOG_MIGRATION") == 1
    assert rt.log.queue_depth() == 0
    from edge.offline.tests.conftest import attempt

    assert rt.decide(attempt("att_after"))["decision"] == "ALLOW"  # runtime fully usable


def test_a_crashing_migration_never_breaks_startup(tmp_path, make_rt, monkeypatch):
    import edge.offline.migrate as mig

    make_legacy(tmp_path / LEGACY_NAME, [rec("att_leg1", NOW - timedelta(hours=1))])
    monkeypatch.setattr(mig, "_identify_kiosk", lambda *a, **k: 1 / 0)
    rt = make_rt()
    assert "ZeroDivisionError" in rt.legacy_migration["error"] and (tmp_path / LEGACY_NAME).exists()


# ---------------------------------------------------------------- function level
def _log(tmp_path: Path, kiosk: str = KIOSK) -> DecisionLog:
    return DecisionLog(tmp_path / f"decisions_{kiosk}.sqlite", TEST_DATA_KEY, kiosk)


def test_interrupted_migration_is_replay_safe(tmp_path, monkeypatch):
    make_legacy(tmp_path / LEGACY_NAME, [rec("att_a", NOW - timedelta(hours=1)), rec("att_b", NOW)])
    log = _log(tmp_path)
    real_replace = os.replace
    monkeypatch.setattr(os, "replace", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    rep = migrate_legacy_log(tmp_path, TEST_DATA_KEY, log, now=NOW)
    assert rep["migrated"] == 2 and "disk full" in rep["error"] and (tmp_path / LEGACY_NAME).exists()
    monkeypatch.setattr(os, "replace", real_replace)
    rep2 = migrate_legacy_log(tmp_path, TEST_DATA_KEY, log, now=NOW)
    assert rep2["migrated"] == 0 and rep2["error"] is None and archives(tmp_path)
    assert [r["attempt_id"] for r in log.unsynced(50)] == ["att_a", "att_b"]  # never duplicated


def test_already_present_attempt_is_not_appended_twice(tmp_path):
    log = _log(tmp_path)
    log.append_final(rec("att_dup", NOW))
    make_legacy(tmp_path / LEGACY_NAME, [rec("att_dup", NOW), rec("att_new", NOW)])
    rep = migrate_legacy_log(tmp_path, TEST_DATA_KEY, log, now=NOW)
    assert rep["migrated"] == 1 and rep["already_present"] == 1
    assert [r["attempt_id"] for r in log.unsynced(50)] == ["att_dup", "att_new"]


def test_tampered_row_is_not_migrated_and_the_file_stays_for_review(tmp_path):
    p = tmp_path / LEGACY_NAME
    make_legacy(p, [rec("att_ok", NOW), rec("att_bad", NOW)])
    db = sqlite3.connect(p, isolation_level=None)
    db.execute("UPDATE decision_log SET record_hash='00' WHERE attempt_id='att_bad'")
    db.close()
    log = _log(tmp_path)
    rep = migrate_legacy_log(tmp_path, TEST_DATA_KEY, log, now=NOW)
    assert rep["migrated"] == 1 and rep["undecryptable"] == 1 and "left in place" in rep["error"]
    assert p.exists() and not archives(tmp_path)
    assert [r["attempt_id"] for r in log.unsynced(50)] == ["att_ok"]


def test_legacy_tombstones_are_not_guessed_the_file_stays_for_review(tmp_path):
    p = tmp_path / LEGACY_NAME
    make_legacy(p, [rec("att_ok", NOW)], tombstone=True)
    rep = migrate_legacy_log(tmp_path, TEST_DATA_KEY, _log(tmp_path), now=NOW)
    assert rep["migrated"] == 1 and rep["tombstones_left"] == 1 and p.exists() and not archives(tmp_path)


def test_legacy_pending_step_up_is_finalized_like_an_abandoned_attempt(tmp_path):
    p = rec("att_pend", NOW - timedelta(hours=3), decision="STEP_UP", reason_codes=["LIVENESS_UNSURE"])
    make_legacy(tmp_path / LEGACY_NAME, [rec("att_a", NOW - timedelta(hours=4))], pending=[p])
    log = _log(tmp_path)
    rep = migrate_legacy_log(tmp_path, TEST_DATA_KEY, log, now=NOW)
    assert rep["pending_finalized"] == 1 and rep["error"] is None
    q = log.unsynced(50)
    assert [r["attempt_id"] for r in q] == ["att_a", "att_pend"] and q[1]["decision"] == "STEP_UP"


def test_legacy_fallback_replay_state_is_merged_tighten_only(tmp_path):
    fb = SqliteFallbackState(tmp_path / "fallback_state.sqlite", TEST_DATA_KEY)
    fb.set_totp_last_step("u_3c4d", 900)
    make_legacy(tmp_path / LEGACY_NAME, [], consumed=["OVR-D11140800-01"], totp={"u_3c4d": 800, "u_1a2b": 950})
    rep = migrate_legacy_log(tmp_path, TEST_DATA_KEY, _log(tmp_path), fb_state=fb, now=NOW)
    assert rep["fallback_rows"] == 3 and rep["error"] is None and archives(tmp_path)
    assert fb.is_code_consumed("OVR-D11140800-01")
    assert fb.totp_last_step("u_3c4d") == 900 and fb.totp_last_step("u_1a2b") == 950  # never lowered


def test_records_of_another_known_kiosk_go_to_that_kiosks_log(tmp_path):
    _log(tmp_path, "KIOSK_LAB_01").close()  # the device ran as KIOSK_LAB_01 before
    make_legacy(tmp_path / LEGACY_NAME, [rec("att_lab", NOW, kiosk="KIOSK_LAB_01")], kiosk="KIOSK_LAB_01")
    log = _log(tmp_path)
    rep = migrate_legacy_log(tmp_path, TEST_DATA_KEY, log, now=NOW)
    assert rep["kiosk_id"] == "KIOSK_LAB_01" and rep["migrated"] == 1 and log.queue_depth() == 0
    lab = _log(tmp_path, "KIOSK_LAB_01")
    assert [r["attempt_id"] for r in lab.unsynced(50)] == ["att_lab"] and lab.verify_chain() == (True, None)


def test_archives_older_than_the_retention_window_are_deleted(tmp_path):
    old = tmp_path / f"{ARCHIVE_PREFIX}{(NOW - timedelta(hours=30)).strftime('%Y%m%dT%H%M%SZ')}"
    fresh = tmp_path / f"{ARCHIVE_PREFIX}{(NOW - timedelta(hours=2)).strftime('%Y%m%dT%H%M%SZ')}"
    old.write_bytes(b"x")
    fresh.write_bytes(b"x")
    rep = migrate_legacy_log(tmp_path, TEST_DATA_KEY, _log(tmp_path), now=NOW, retention_hours=24)
    assert not old.exists() and fresh.exists() and rep["archives_purged"] == 1


def test_never_touches_the_live_data_dir_by_default(tmp_path):
    with pytest.raises(TypeError):
        migrate_legacy_log(tmp_path, TEST_DATA_KEY)  # data_dir + log are explicit; no implicit edge/data path


def test_now_must_be_timezone_aware(tmp_path):
    with pytest.raises(ValueError):
        migrate_legacy_log(tmp_path, TEST_DATA_KEY, _log(tmp_path), now=datetime(2026, 11, 14, 10))
    assert NOW.tzinfo is not None and NOW.astimezone(UTC)
