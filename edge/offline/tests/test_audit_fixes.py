"""Audit-swarm findings 2026-11-14 (policy-engine triage): crash-safety of digest comparisons, CARD revocation,
local erasure on ERASED revocations, P7 cloud-match visibility, real-clock retention, file permissions,
TOTP replay-table purge, and the 304 bundle branch. Fixture keys only; temp data dirs."""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime, timedelta

import pytest

from edge.offline.bundle import BundleStore, ct_equal, verify_bundle
from edge.offline.signing import verify_request
from edge.offline.store import DecisionLog, SqliteFallbackState, iso_utc
from edge.offline.tests.conftest import attempt, bring_online, signed_now
from edge.policy.fallback import card_hash
from edge.policy.signals import FallbackSubmission
from edge.policy.tests.builders import (
    RT_CLOCK,
    TEST_BUNDLE_KEY,
    TEST_CARD_PEPPER,
    TEST_DATA_KEY,
    TEST_KIOSK_KEY,
)


# ---------------------------------------------------------------- 1. never raise on hostile strings
@pytest.mark.parametrize("value", ["é" * 64, "\ud800" * 64, "", "0" * 64])
def test_verify_bundle_never_raises_on_non_ascii_or_bogus_signatures(value):
    b = signed_now(RT_CLOCK())
    b["signature"]["value"] = value
    assert verify_bundle(b, TEST_BUNDLE_KEY) is False


def test_ct_equal_handles_non_strings_and_unicode():
    assert ct_equal("abc", "abc") and not ct_equal("abc", "abd") and not ct_equal("é", "e")
    assert not ct_equal(None, "x") and not ct_equal("x", 5)


def test_bundle_store_boots_on_a_non_ascii_signature_file(tmp_path):
    b = signed_now(RT_CLOCK())
    b["signature"]["value"] = "é" * 64
    (tmp_path / "bundle.signed.json").write_text(json.dumps(b), encoding="utf-8")
    store = BundleStore(tmp_path / "bundle.signed.json", TEST_BUNDLE_KEY, "KIOSK_LIB_01")  # must not raise
    assert store.lvb is None


def test_sync_reports_a_non_ascii_signature_bundle_as_rejected_without_raising(make_rt, cloud):
    rt = make_rt(cloud)
    bad = signed_now(RT_CLOCK(), version=43)
    bad["signature"]["value"] = "é" * 64
    cloud.bundle = bad
    rep = rt.sync.run_once()  # must not raise
    assert str(rep["bundle"]).startswith("rejected") and rt.bundles.version == 42


def test_verify_request_never_raises_on_a_non_ascii_signature_header():
    assert verify_request("POST", "/v1/sync", b"{}", {"X-Timestamp": str(int(datetime.now(UTC).timestamp())),
                                                      "X-Signature": "é" * 64}, kiosk_key=TEST_KIOSK_KEY) is False


# ---------------------------------------------------------------- 2. CARD revocation (feed overlay)
def test_a_card_revoked_through_the_feed_no_longer_verifies(make_rt, cloud):
    rt = make_rt(cloud)
    sub = FallbackSubmission(method="CARD", card_id="HID-CARD-1002")  # Priya u_3c4d (fixture pepper)
    now = RT_CLOCK()
    assert rt.verifier.verify(sub, "u_3c4d", "OFFLINE", now).ok is True
    cloud.revocations = [{"seq": 1, "type": "CARD", "target_id": card_hash(TEST_CARD_PEPPER, "HID-CARD-1002"),
                          "revoked_at": iso_utc(now), "reason": "LOST"}]
    bring_online(rt)
    res = rt.verifier.verify(sub, "u_3c4d", "OFFLINE", now)
    assert res.ok is False and res.reason == "card revoked"


# ---------------------------------------------------------------- 3. ERASED revocation -> local erase
def test_erased_revocation_removes_totp_and_runs_erase_hooks_once(make_rt, cloud):
    rt = make_rt(cloud)
    early: list[str] = []
    rt.add_erase_hook(early.append)
    assert rt.credentials.totp_secret("u_3c4d") is not None
    cloud.revocations = [{"seq": 1, "type": "USER", "target_id": "u_3c4d", "revoked_at": iso_utc(RT_CLOCK()),
                          "reason": "ERASED"},
                         {"seq": 2, "type": "USER", "target_id": "u_1a2b", "revoked_at": iso_utc(RT_CLOCK()),
                          "reason": "ADMIN"}]
    bring_online(rt)
    rt.tick()
    rt.tick()  # idempotent
    assert early == ["u_3c4d"] and rt.credentials.totp_secret("u_3c4d") is None
    assert rt.credentials.totp_secret("u_1a2b") is not None  # an ordinary revocation keeps the secret
    late: list[str] = []
    rt.add_erase_hook(late.append)  # registered later -> replayed
    assert late == ["u_3c4d"]
    assert any(e["type"] == "USER_ERASED_LOCAL" and e["user_id"] == "u_3c4d" for e in rt.events())


# ---------------------------------------------------------------- 4. P7 visibility in GET /v1/mode
def test_cloud_match_misses_are_visible_while_the_kiosk_stays_online(make_rt, cloud):
    rt = make_rt(cloud)
    cloud.bundle = rt.bundles.lvb
    bring_online(rt)
    rt.sync_now()
    rt.decide(attempt("att_cm_miss", cloud={"ok": False, "top1_user": None}))
    cm = rt.mode_status()["cloud_match"]
    assert cm["degraded"] is True and cm["misses"] == 1 and cm["last_miss_at"] is not None
    rt.decide(attempt("att_cm_ok"))
    cm = rt.mode_status()["cloud_match"]
    assert cm["degraded"] is False and cm["recent"] == 2 and cm["last_ok_at"] is not None


# ---------------------------------------------------------------- 7. retention on the real clock, 0600 files
def _rec(aid: str, ts: str) -> dict:
    return {"attempt_id": aid, "kiosk_id": "KIOSK_LIB_01", "zone": "LIBRARY", "ts_utc": ts, "user_id": "u_3c4d",
            "candidate_user_id": "u_3c4d", "decision": "ALLOW", "reason_codes": ["ACCESS_OK"], "resolved_codes": [],
            "scores": {}, "fallback": None, "schedule_version": 42, "cache_state": "FRESH", "mode": "OFFLINE"}


def test_retention_purge_uses_real_creation_time_not_the_demo_stamp(tmp_path):
    log = DecisionLog(tmp_path / "d.sqlite", TEST_DATA_KEY, "KIOSK_LIB_01")
    real = datetime.now(UTC)
    log.append_final(_rec("att_demo_past", iso_utc(real - timedelta(days=5))), created_real=real)  # demo clock -5 d
    log.append_final(_rec("att_old", iso_utc(real)), created_real=real - timedelta(hours=25))
    log.append_final(_rec("att_legacy", iso_utc(real - timedelta(hours=25))))  # no created_real: ts_utc
    tomb = log.purge_expired(real)
    left = {r["attempt_id"] for r in log.records()}
    assert left == {"att_demo_past"} and tomb["count"] == 2


def test_runtime_demo_clock_jump_does_not_purge_fresh_unsynced_records(make_rt):
    rt = make_rt(DEMO_MODE="1")
    rt.decide(attempt("att_keep"))
    rt.set_demo_clock(offset_s=3 * 24 * 3600)  # +3 days on the wall (demo) clock
    rt.tick()
    assert [r["attempt_id"] for r in rt.store_view()["records"]] == ["att_keep"]


def test_sqlite_files_are_owner_only(tmp_path):
    DecisionLog(tmp_path / "d.sqlite", TEST_DATA_KEY, "K").close()
    SqliteFallbackState(tmp_path / "f.sqlite", TEST_DATA_KEY)
    for f in ("d.sqlite", "f.sqlite"):
        assert stat.S_IMODE(os.stat(tmp_path / f).st_mode) == 0o600


def test_totp_replay_table_is_purged_outside_the_window_only(tmp_path):
    st = SqliteFallbackState(tmp_path / "f.sqlite", TEST_DATA_KEY)
    st.set_totp_last_step("u_old", 100)
    st.set_totp_last_step("u_new", 200)
    assert st.purge_totp_before(150) == 1
    assert st.totp_last_step("u_old") is None and st.totp_last_step("u_new") == 200


# ---------------------------------------------------------------- 11. 304 bundle branch
def test_bundle_304_confirms_the_installed_bundle(make_rt, cloud):
    rt = make_rt(cloud)
    cloud.bundle = rt.bundles.lvb
    cloud.etag_304 = True
    rep = rt.sync.run_once()
    assert rep["bundle"] == "not_modified" and rt.bundles.refresh_age_s() is not None
    assert rt.bundles.refresh_age_s() < 5 and cloud.calls[-1] == ("GET", "/v1/schedule/KIOSK_LIB_01")


# ---------------------------------------------------------------- POLICY_TEST_CASES Y12
def test_Y12_120_queued_records_go_in_three_ordered_batches(make_rt, cloud):
    rt = make_rt(cloud)  # cloud configured but not ONLINE: decisions queue locally
    for i in range(120):
        rt.decide(attempt(f"att_y12_{i:03d}"))
    rt.sync.run_once()
    assert [len(b) for b in cloud.sync_batches] == [50, 50, 20]
    items = [it for b in cloud.sync_batches for it in b]
    seqs = [it["seq"] for it in items]
    assert seqs == sorted(seqs) and len(set(seqs)) == 120
    assert all(it["idempotency_key"] == it["attempt_id"] and it["hmac"] for it in items)


def test_bundle_kiosk_ids_come_from_the_verified_bundle_only(make_rt):
    rt = make_rt()
    lvb = rt.bundles.lvb
    assert rt.bundle_kiosk_ids() == set(lvb["kiosks"]) & set(lvb["scope"]["kiosk_ids"]) and "KIOSK_LIB_01" in \
        rt.bundle_kiosk_ids()
    rt.bundles._lvb = None  # no verified bundle -> nothing (fail-secure)
    assert rt.bundle_kiosk_ids() == set()


def test_revocation_overlay_file_is_owner_only_and_atomic(tmp_path):
    """revocations.enc (deny-only overlay, encrypted) is created 0600 regardless of umask, like the other
    edge/data files; a rewrite keeps 0600, leaves no temp file behind, and round-trips."""
    from edge.offline.sync import RevocationOverlay

    old = os.umask(0o022)
    try:
        path = tmp_path / "data" / "revocations.enc"
        ov = RevocationOverlay(path, TEST_DATA_KEY)
        ov.apply({"revocation_seq": 3, "items": [{"type": "USER", "target_id": "u_x", "reason": "LOST"}]})
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        ov.apply({"revocation_seq": 4, "items": [{"type": "CARD", "target_id": "c_hash"}]})
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert sorted(p.name for p in path.parent.iterdir()) == ["revocations.enc"]
        again = RevocationOverlay(path, TEST_DATA_KEY)
        assert again.seq == 4 and again.reason("u_x") == "LOST" and again.card_revoked("c_hash")
    finally:
        os.umask(old)
