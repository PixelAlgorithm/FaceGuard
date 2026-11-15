"""offline-sync hardening: foreign per-kiosk logs keep the 24 h retention (EO-07) and scripts/sign_bundle.py
mints 10-digit codes (EO-11), writes the bundle 0600 (SC2-D8), hashes the documented demo cards only with
--demo-cards (SC2-D6) and refuses --allow-doc-codes for the live bundle path (EO-10). In-process main() with a
patched ROOT, so the live edge/data is never touched."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
import re
import stat
from datetime import UTC, datetime, timedelta

import pytest

from edge.offline.migrate import purge_foreign_logs
from edge.offline.store import DecisionLog
from edge.policy.tests.builders import PROJECT_ROOT, TEST_BUNDLE_KEY, TEST_CARD_PEPPER, TEST_DATA_KEY

NOW = datetime(2026, 11, 17, 4, 30, tzinfo=UTC)
EXAMPLE = PROJECT_ROOT / "config" / "schedule.example.json"


def _rec(aid: str, kiosk: str) -> dict:
    return {"attempt_id": aid, "kiosk_id": kiosk, "zone": "LAB", "ts_utc": "2026-11-14T04:30:00Z",
            "user_id": "u_3c4d", "candidate_user_id": "u_3c4d", "decision": "ALLOW", "reason_codes": ["ACCESS_OK"],
            "resolved_codes": [], "scores": {}, "fallback": None, "schedule_version": 42, "cache_state": "FRESH",
            "mode": "OFFLINE"}


# ---------------------------------------------------------------- EO-07
def test_EO07_foreign_kiosk_logs_are_purged_after_24h_and_reported(tmp_path):
    lab = DecisionLog(tmp_path / "decisions_KIOSK_LAB_01.sqlite", TEST_DATA_KEY, "KIOSK_LAB_01")
    lab.append_final(_rec("att_lab_old", "KIOSK_LAB_01"), created_real=NOW - timedelta(hours=72))
    lab.append_final(_rec("att_lab_new", "KIOSK_LAB_01"), created_real=NOW - timedelta(hours=1))
    lab.close()
    own = DecisionLog(tmp_path / "decisions_KIOSK_LIB_01.sqlite", TEST_DATA_KEY, "KIOSK_LIB_01")
    own.append_final(_rec("att_own_old", "KIOSK_LIB_01"), created_real=NOW - timedelta(hours=72))
    out = purge_foreign_logs(tmp_path, TEST_DATA_KEY, "KIOSK_LIB_01", now=NOW)
    assert out == [{"kiosk_id": "KIOSK_LAB_01", "file": "decisions_KIOSK_LAB_01.sqlite", "purged": 1, "queued": 1,
                    "tombstones": 1, "error": None}]
    again = DecisionLog(tmp_path / "decisions_KIOSK_LAB_01.sqlite", TEST_DATA_KEY, "KIOSK_LAB_01")
    assert [r["attempt_id"] for r in again.records()] == ["att_lab_new"]  # the 72 h old user_id is gone
    assert own.queue_depth() == 1  # the active kiosk's log is the runtime's job, untouched here


def test_EO07_unreadable_foreign_log_is_reported_never_raised(tmp_path):
    (tmp_path / "decisions_KIOSK_X.sqlite").write_bytes(b"not a database" * 10)
    out = purge_foreign_logs(tmp_path, TEST_DATA_KEY, "KIOSK_LIB_01", now=NOW)
    assert len(out) == 1 and out[0]["kiosk_id"] == "KIOSK_X" and out[0]["error"]
    with pytest.raises(ValueError):
        purge_foreign_logs(tmp_path, TEST_DATA_KEY, "KIOSK_LIB_01", now=NOW.replace(tzinfo=None))


# ---------------------------------------------------------------- scripts/sign_bundle.py
@pytest.fixture
def signer(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("os_sign_bundle", PROJECT_ROOT / "scripts" / "sign_bundle.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "thresholds.yaml").write_text(
        (PROJECT_ROOT / "config" / "thresholds.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(mod, "ROOT", tmp_path)  # .env / thresholds / live path all inside tmp
    monkeypatch.setenv("SCHEDULE_BUNDLE_HMAC_KEY", TEST_BUNDLE_KEY.decode())
    monkeypatch.setenv("CARD_ID_PEPPER", TEST_CARD_PEPPER.decode())

    def run(*args: str) -> tuple[dict, str]:
        out, codes = tmp_path / "out" / "bundle.signed.json", tmp_path / "out" / "DEMO_CODES.txt"
        assert mod.main(["--src", str(EXAMPLE), "--out", str(out), "--codes-file", str(codes), *args]) == 0
        return json.loads(out.read_text(encoding="utf-8")), codes.read_text(encoding="utf-8")

    return mod, run, tmp_path


def _pbkdf2(code: str, c: dict) -> str:
    return hashlib.pbkdf2_hmac("sha256", code.encode(), bytes.fromhex(c["salt"]), 100000).hex()


def test_EO11_new_codes_have_10_digits_and_verify(signer):
    _mod, run, _tmp = signer
    b, text = run("--min-codes", "4")
    listed = re.findall(r"^\s+(OVR-\S+)\s+(s_guard\d+)\s+(\d+)$", text, re.MULTILINE)
    assert len(listed) == 4 and all(len(code) == 10 for _c, _s, code in listed)
    by_id = {c["code_id"]: c for c in b["override_codes"]["codes"]}
    assert all(_pbkdf2(code, by_id[cid]) == by_id[cid]["hash"] for cid, _s, code in listed)


def test_SC2D8_signed_bundle_is_owner_only_regardless_of_umask(signer):
    _mod, run, tmp = signer
    old = os.umask(0o022)
    try:
        run()
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(tmp / "out" / "bundle.signed.json").st_mode) == 0o600
    assert not list((tmp / "out").glob(".bundle-*")) and not list((tmp / "out").glob("*.tmp"))


def test_SC2D6_documented_demo_cards_only_with_the_explicit_flag(signer):
    mod, run, _tmp = signer
    documented = {hmac.new(TEST_CARD_PEPPER, c.encode(), hashlib.sha256).hexdigest() for c in mod.DEMO_CARDS}

    def card_hashes(b: dict) -> set[str]:
        return {u.get("fallback", {}).get("card_id_hash") for u in b["users"].values()} - {None}

    plain, text = run()
    assert not card_hashes(plain) & documented and "HID-CARD" not in text and "HID-DEMO" not in text
    demo, text = run("--demo-cards")
    assert card_hashes(demo) & documented and "HID-CARD-1002" in text


def test_EO10_allow_doc_codes_is_refused_for_the_live_bundle_path(signer):
    mod, _run, tmp = signer
    live = tmp / "edge" / "data" / "bundle.signed.json"
    with pytest.raises(SystemExit, match="refusing"):
        mod.main(["--src", str(EXAMPLE), "--out", str(live), "--codes-file", str(tmp / "c.txt"), "--allow-doc-codes"])
    assert not live.exists()


def test_signer_reexports_the_documented_values_the_cloud_reads(signer):
    mod, _run, _tmp = signer
    assert set(mod.DOC_OVERRIDE_CODES) == {"OVR-001", "OVR-002", "OVR-003"}  # cloud/app/policy_bridge.py
    assert callable(mod.recompute_card_hashes)


def test_OS4_key_id_defaults_to_SCHEDULE_BUNDLE_KEY_ID_and_explicit_flag_wins(signer, monkeypatch):
    from edge.offline.bundle import verify_bundle

    _mod, run, _tmp = signer
    monkeypatch.delenv("SCHEDULE_BUNDLE_KEY_ID", raising=False)
    b, _text = run()
    assert b["signature"]["key_id"] == "demo-k1"  # DEFAULT_KEY_ID without configuration
    monkeypatch.setenv("SCHEDULE_BUNDLE_KEY_ID", "prod-k2")
    b, _text = run()
    assert b["signature"]["key_id"] == "prod-k2" and verify_bundle(b, TEST_BUNDLE_KEY, "prod-k2")
    b, _text = run("--key-id", "ops-k3")
    assert b["signature"]["key_id"] == "ops-k3"  # an explicit --key-id still wins
