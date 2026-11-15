"""policy-fixes: EO-06 deletion evidence in the decision log (a deleted unsynced record is detected locally) and the
fallback-state reseed (EO-12)."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

from edge.offline.store import DecisionLog, SqliteFallbackState, minimal_record, reseed_fallback_state
from edge.policy.tests.builders import TEST_DATA_KEY, B

KIOSK = "KIOSK_LIB_01"
NOW = datetime(2026, 11, 14, 4, 35, tzinfo=UTC)


def _log(tmp_path) -> DecisionLog:
    return DecisionLog(tmp_path / f"decisions_{KIOSK}.sqlite", TEST_DATA_KEY, KIOSK)


def _fill(lg: DecisionLog, n: int) -> None:
    for i in range(n):
        lg.append_final(minimal_record(B().set(attempt_id=f"att_g{i}").evaluate()), created_real=NOW)


def test_EO06_deleting_an_unsynced_middle_record_is_detected(tmp_path):
    lg = _log(tmp_path)
    _fill(lg, 5)
    assert lg.verify_chain() == (True, None)
    raw = sqlite3.connect(lg.path)
    raw.execute("DELETE FROM decision_log WHERE seq=3")  # no key needed
    raw.commit()
    assert lg.verify_chain() == (False, 3)


def test_EO06_deleting_the_newest_record_is_detected(tmp_path):
    lg = _log(tmp_path)
    _fill(lg, 3)
    raw = sqlite3.connect(lg.path)
    raw.execute("DELETE FROM decision_log WHERE seq=3")
    raw.commit()
    assert lg.verify_chain() == (False, 3)


def test_EO06_acked_and_tombstoned_records_are_legitimate_gaps(tmp_path):
    lg = _log(tmp_path)
    _fill(lg, 6)
    assert lg.ack(["att_g1", "att_g3"]) == 2
    assert lg.verify_chain() == (True, None)
    assert lg.purge_expired(NOW + timedelta(hours=25)) is not None  # the rest -> tombstone
    assert lg.records() == [] and lg.verify_chain() == (True, None)
    lg.close()
    assert _log(tmp_path).verify_chain() == (True, None)  # evidence persists across reopen


def test_EO06_forged_removal_evidence_is_tampering(tmp_path):
    lg = _log(tmp_path)
    _fill(lg, 3)
    raw = sqlite3.connect(lg.path)
    raw.execute("UPDATE meta SET v='00' WHERE k='removal_evidence_v2'")
    raw.execute("DELETE FROM decision_log WHERE seq=2")
    raw.commit()
    assert lg.verify_chain()[0] is False


def test_EO06_log_without_evidence_is_rebaselined_and_flagged(tmp_path):
    """A pre-upgrade file and an attacker who deleted the evidence row look the same locally: the log re-baselines
    (no permanent false alarm) but raises evidence_rebased so the runtime alerts; a fresh log never does."""
    lg = _log(tmp_path)
    assert lg.evidence_rebased is False
    _fill(lg, 4)
    lg.ack(["att_g0"])
    raw = sqlite3.connect(lg.path)
    raw.execute("DELETE FROM meta WHERE k='removal_evidence_v2'")
    raw.commit()
    lg.close()
    again = _log(tmp_path)
    assert again.verify_chain() == (True, None) and again.evidence_rebased is True
    again.close()
    assert _log(tmp_path).evidence_rebased is False  # baselined once


def test_EO06_tail_deletion_with_a_rewritten_tip_is_detected(tmp_path):
    lg = _log(tmp_path)
    _fill(lg, 5)
    raw = sqlite3.connect(lg.path)
    head3 = raw.execute("SELECT record_hash FROM decision_log WHERE seq=3").fetchone()[0]
    raw.execute("DELETE FROM decision_log WHERE seq IN (4, 5)")
    raw.execute("UPDATE meta SET v='4' WHERE k='next_seq'")
    raw.execute("UPDATE meta SET v=? WHERE k='chain_head'", (head3,))
    raw.commit()
    assert lg.verify_chain()[0] is False


def test_EO06_ack_is_atomic_with_its_evidence(tmp_path, monkeypatch):
    import pytest

    lg = _log(tmp_path)
    _fill(lg, 3)

    def boom(_seqs):
        raise RuntimeError("crash between delete and evidence")

    monkeypatch.setattr(lg, "_cover", boom)
    with pytest.raises(RuntimeError):
        lg.ack(["att_g1"])
    monkeypatch.undo()
    assert len(lg.records()) == 3 and lg.verify_chain() == (True, None)  # nothing deleted, no false alarm


def test_EO12_reseed_marks_logged_codes_and_totp_steps_as_used(tmp_path):
    lg = _log(tmp_path)
    rec = minimal_record(B().set(attempt_id="att_fb").evaluate())
    rec = {**rec, "decision": "ALLOW", "user_id": "u_3c4d",
           "fallback": {"method": "STAFF_OVERRIDE", "staff_id": "s_guard01", "code_id": "OVR-002", "totp_step": None}}
    lg.append_final(rec, created_real=NOW)
    rec2 = {**rec, "attempt_id": "att_fb2", "fallback": {"method": "TOTP", "staff_id": None, "code_id": None,
                                                         "totp_step": 59000000}}
    lg.append_final(rec2, created_real=NOW)
    st = SqliteFallbackState(tmp_path / "fallback_state.sqlite", TEST_DATA_KEY)
    assert reseed_fallback_state(st, lg, NOW) == {"codes": 1, "totp_steps": 1}
    assert st.is_code_consumed("OVR-002") and st.totp_last_step("u_3c4d") == 59000000
    assert reseed_fallback_state(st, lg, NOW) == {"codes": 0, "totp_steps": 0}  # idempotent


def test_EO08_corrupt_credentials_file_is_quarantined_not_fatal(tmp_path):
    import os
    import stat

    from edge.offline.credentials import CredentialStore

    path = tmp_path / "credentials.enc"
    path.write_bytes(b"\x00garbage")
    cs = CredentialStore(path, TEST_DATA_KEY)
    assert cs.corrupt is not None and cs.totp_secret("u_3c4d") is None
    cs.set_totp_secret("u_3c4d", "JBSWY3DPEHPK3PXP")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert CredentialStore(path, TEST_DATA_KEY).totp_secret("u_3c4d") == "JBSWY3DPEHPK3PXP"
