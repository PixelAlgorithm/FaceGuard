"""SC2.5 minimal, encrypted, hash-chained decision log -- POLICY_TEST_CASES D01-D08."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from edge.offline.bundle import canonical_json
from edge.offline.store import (
    RECORD_FIELDS,
    ChainError,
    DecisionLog,
    SqliteFallbackState,
    compute_record_hash,
    genesis_hash,
    minimal_record,
)
from edge.policy.tests.builders import L03_PAD, OB, PHONE, TEST_DATA_KEY, B
from edge.policy.tests.test_stepup import Flow

KIOSK = "KIOSK_LIB_01"
NOW = datetime(2026, 11, 14, 4, 35, tzinfo=UTC)
WHITELIST = {"attempt_id", "seq", "kiosk_id", "zone", "ts_utc", "user_id", "candidate_user_id", "decision",
             "reason_codes", "resolved_codes", "scores", "fallback", "schedule_version", "cache_state", "mode",
             "prev_hash", "record_hash"}


@pytest.fixture
def log(tmp_path):
    lg = DecisionLog(tmp_path / f"decisions_{KIOSK}.sqlite", TEST_DATA_KEY, KIOSK)
    yield lg
    lg.close()


def decisions():
    """A representative mix: ALLOW, spoof DENY, STEP_UP, A3 manual review ALLOW, TOTP ALLOW, random challenge."""
    out = [B().set(attempt_id="att_d_allow").evaluate(),
           B().set(attempt_id="att_d_spoof", device=PHONE).evaluate(),
           OB().set(attempt_id="att_d_unsure", pad=list(L03_PAD)).evaluate()]
    f = Flow(OB().set(attempt_id="att_d_q17", luma=[40.0] * 5, recapture_count=2))
    out.append(f.fallback(method="STAFF_OVERRIDE", code="48213907"))  # Q17 -> D07
    f = Flow(B().set(attempt_id="att_d_rc04").r(0.05))
    out.append(f.challenge())  # RC04 -> D08
    return out


def test_D01_only_whitelisted_fields_and_no_biometric_or_secret_data(log):
    for d in decisions():
        rec = minimal_record(d)
        (log.put_pending if d.decision == "STEP_UP" else log.append_final)(rec, NOW) if d.decision == "STEP_UP" \
            else log.append_final(rec)
    for rec in log.records() + log.pending():
        assert set(rec) <= WHITELIST, set(rec) - WHITELIST
        blob = json.dumps(rec)
        assert not re.search(r"[A-Za-z0-9+/=]{257,}", blob)  # no base64 blobs / image bytes
        for needle in ("Priya", "Aarav", "48213907", "75530182", "HID-CARD", "embedding", "display"):
            assert needle not in blob
        assert not any(isinstance(v, list) and len(v) > 16 and all(isinstance(x, float) for x in v)
                       for v in rec.values())  # no embedding-like arrays


def test_D02_scores_rounded_to_2dp_no_per_frame_data(log):
    rec = minimal_record(B().set(pad=[0.951234, 0.93, 0.94, 0.92, 0.96]).evaluate())
    assert rec["scores"] and all(isinstance(v, float) and round(v, 2) == v for v in rec["scores"].values()
                                 if v is not None)
    assert all(not isinstance(v, list | dict) for v in rec["scores"].values())


def test_D03_db_file_holds_ciphertext_only(tmp_path, log):
    for d in decisions():
        rec = minimal_record(d)
        if d.decision == "STEP_UP":
            log.put_pending(rec, NOW)
        else:
            log.append_final(rec)
    raw = b"".join(p.read_bytes() for p in tmp_path.iterdir() if p.is_file())
    for needle in (b"u_3c4d", b"u_7a8b", b"ACCESS_OK", b"SPOOF_DEVICE", b"s_guard01", b"OVR-001"):
        assert needle not in raw, needle
    con = sqlite3.connect(log.path)
    for (payload,) in con.execute("SELECT payload FROM decision_log"):
        with pytest.raises(ValueError):
            json.loads(payload)
    con.close()


def test_D03_fallback_state_db_has_no_plaintext_ids(tmp_path):
    st = SqliteFallbackState(tmp_path / "fallback_state.sqlite", TEST_DATA_KEY)
    st.set_totp_last_step("u_3c4d", 59000000)
    st.consume_code("OVR-001", NOW)
    assert st.totp_last_step("u_3c4d") == 59000000 and st.is_code_consumed("OVR-001")
    raw = (tmp_path / "fallback_state.sqlite").read_bytes()
    assert b"u_3c4d" not in raw and b"OVR-001" not in raw


def _append(log, n, *, ts=NOW):
    recs = []
    for i in range(n):
        d = B().set(attempt_id=f"att_{i:04d}").evaluate()
        rec = minimal_record(d)
        rec["ts_utc"] = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        recs.append(log.append_final(rec))
    return recs


def test_hash_chain_is_independently_recomputable(log):
    recs = _append(log, 3)
    assert recs[0]["prev_hash"] == hashlib.sha256(f"genesis:{KIOSK}".encode()).hexdigest() == genesis_hash(KIOSK)
    for prev, rec in zip([None] + recs, recs, strict=False):
        body = {k: v for k, v in rec.items() if k not in ("prev_hash", "record_hash")}
        expected = hashlib.sha256(rec["prev_hash"].encode() + canonical_json(body)).hexdigest()
        assert rec["record_hash"] == expected == compute_record_hash(rec["prev_hash"], rec)
        if prev:
            assert rec["prev_hash"] == prev["record_hash"]
    assert [r["seq"] for r in recs] == [1, 2, 3] and log.chain_head() == recs[-1]["record_hash"]
    assert log.verify_chain() == (True, None)


def test_D04_ack_purges_only_acknowledged_rows(log):
    _append(log, 3)
    assert log.ack(["att_0000", "att_0002"]) == 2
    assert [r["attempt_id"] for r in log.records()] == ["att_0001"] and log.queue_depth() == 1
    assert log.verify_chain() == (True, None)


def test_D05_unsynced_record_older_than_24h_becomes_a_tombstone(log):
    _append(log, 1, ts=NOW)
    head = log.chain_head()
    assert log.purge_expired(NOW + timedelta(hours=24) - timedelta(seconds=1)) is None
    tomb = log.purge_expired(NOW + timedelta(hours=24, minutes=1))
    assert {k: tomb[k] for k in ("count", "first_seq", "last_seq", "chain_head")} == {
        "count": 1, "first_seq": 1, "last_seq": 1, "chain_head": head}
    assert log.records() == [] and log.tombstones()[0]["count"] == 1 and log.queue_depth() == 1


def test_D06_tampered_payload_detected_at_its_seq(log):
    _append(log, 5)
    con = sqlite3.connect(log.path)
    blob = con.execute("SELECT payload FROM decision_log WHERE seq=3").fetchone()[0]
    con.execute("UPDATE decision_log SET payload=? WHERE seq=3", (blob[:-1] + bytes([blob[-1] ^ 1]),))
    con.commit()
    con.close()
    assert log.verify_chain() == (False, 3)
    assert any(r.get("error") for r in log.records())  # reported, not fatal


def test_D06_reencrypted_modified_record_detected(log):
    _append(log, 5)
    rec = next(r for r in log.records() if r["seq"] == 3)
    rec["decision"] = "DENY"
    con = sqlite3.connect(log.path)
    con.execute("UPDATE decision_log SET payload=? WHERE seq=3", (log._enc(rec, log._aad(3, rec["attempt_id"])),))
    con.commit()
    con.close()
    assert log.verify_chain() == (False, 3)


def test_D07_manual_review_record(log):
    d = decisions()[3]
    rec = log.append_final(minimal_record(d))
    assert rec["user_id"] is None and rec["candidate_user_id"] is None
    assert rec["resolved_codes"] == ["QUALITY_LOW_LIGHT"] and rec["decision"] == "ALLOW"
    assert rec["fallback"] == {"method": "STAFF_OVERRIDE", "staff_id": "s_guard01", "code_id": "OVR-001",
                               "totp_step": None}
    assert "48213907" not in json.dumps(rec)


def test_D08_random_challenge_record(log):
    rec = log.append_final(minimal_record(decisions()[4]))
    assert rec["reason_codes"] == ["ACCESS_OK"] and rec["resolved_codes"] == ["RANDOM_CHALLENGE"]
    assert all(round(v, 2) == v for v in rec["scores"].values() if v is not None)


def test_bio_fail_record_keeps_candidate_but_no_user():
    rec = minimal_record(B().who("u_a3b4", "LIB", "2026-11-14T10:05").set(device=PHONE).evaluate())
    assert rec["user_id"] is None and rec["candidate_user_id"] == "u_a3b4"  # targeted-spoof alerts


def test_one_record_per_attempt_pending_then_final(log):
    d = OB().set(attempt_id="att_pf", pad=list(L03_PAD)).evaluate()
    log.put_pending(minimal_record(d), NOW)
    log.put_pending(minimal_record(d), NOW)  # upsert, not a second row
    assert len(log.pending()) == 1 and log.records() == []
    final = B().set(attempt_id="att_pf").evaluate()
    log.append_final(minimal_record(final))
    assert log.pending() == [] and len(log.records()) == 1 and log.has_final("att_pf")
    with pytest.raises(ChainError):
        log.append_final(minimal_record(final))


def test_record_fields_constant_matches_sc25():
    assert set(RECORD_FIELDS) == WHITELIST


def test_wrong_key_cannot_read(tmp_path, log):
    _append(log, 1)
    other = DecisionLog(log.path, base64.urlsafe_b64encode(b"\x01" * 32).decode(), KIOSK)
    assert other.records()[0].get("error")  # AES-GCM authentication fails, reported per row
