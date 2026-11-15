"""offline-sync hardening: bundle key-id pinning (EO-02), one anti-rollback rule for install and reload (EO-09),
documented override codes refused unless DEMO_MODE (EO-10), durable 0600 writes with a .bak (EO-M2), and the
signed `consumed_code_ids` array kept intact (RBAC v2 E / D8). Temp paths and fixture keys only."""

from __future__ import annotations

import copy
import json
import os
import stat
import time
from datetime import UTC, datetime, timedelta

from edge.offline.bundle import (
    BACKUP_SUFFIX,
    BundleStore,
    is_documented_code,
    sign_bundle,
    verify_bundle,
    without_documented_codes,
)
from edge.policy.tests.builders import TEST_BUNDLE_KEY, load_example_bundle

KIOSK = "KIOSK_LIB_01"
T0 = datetime(2026, 11, 14, 4, 30, tzinfo=UTC)
DOC_IDS = {"OVR-001", "OVR-002", "OVR-003"}


def _z(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def signed(issued: datetime = T0, version: int = 42, key_id: str = "demo-k1", **extra) -> dict:
    b = load_example_bundle()
    b["bundle_version"] = version
    b["issued_at"], b["expires_at"] = _z(issued), _z(issued + timedelta(hours=12))
    b.update(extra)
    return sign_bundle(b, TEST_BUNDLE_KEY, key_id=key_id)


def store(tmp_path, bundle: dict | None = None, **kw) -> BundleStore:
    p = tmp_path / "bundle.signed.json"
    if bundle is not None:
        p.write_text(json.dumps(bundle), encoding="utf-8")
    return BundleStore(p, TEST_BUNDLE_KEY, KIOSK, **kw)


def rewrite(s: BundleStore, bundle: dict) -> None:
    time.sleep(0.01)  # a new mtime
    s.path.write_text(json.dumps(bundle), encoding="utf-8")
    s._last_check = 0.0  # skip the 1 s reload throttle


# ---------------------------------------------------------------- EO-02 key id
def test_EO02_key_id_must_equal_the_configured_one():
    b = signed(key_id="rotated-out")
    assert verify_bundle(b, TEST_BUNDLE_KEY)  # the HMAC itself is fine ...
    assert not verify_bundle(b, TEST_BUNDLE_KEY, "demo-k1")  # ... but the key id is not the configured one
    assert verify_bundle(signed(), TEST_BUNDLE_KEY, "demo-k1")
    nokid = copy.deepcopy(signed())
    del nokid["signature"]["key_id"]
    assert not verify_bundle(nokid, TEST_BUNDLE_KEY, "demo-k1")


def test_EO02_store_pins_demo_k1_by_default_and_rejects_another_key_id(tmp_path):
    s = store(tmp_path, signed())
    assert s.lvb is not None and s.key_id == "demo-k1"
    ok, reason = s.install(signed(T0 + timedelta(minutes=5), version=43, key_id="k2"), T0)
    assert not ok and "signature" in reason and s.version == 42
    s2 = store(tmp_path / "b", None, key_id="k2")
    assert s2.install(signed(version=43, key_id="k2"), T0)[0]


# ---------------------------------------------------------------- EO-09 one ordering rule
def test_EO09_reload_rejects_an_older_issued_at_at_the_same_version_like_install(tmp_path):
    later = signed(T0 + timedelta(hours=1))
    s = store(tmp_path, later)
    assert s.install(signed(T0), T0) == (False, "older issued_at for the same version")
    rewrite(s, signed(T0))  # an earlier copy of v42 restored over the later re-sign
    assert s.lvb["issued_at"] == later["issued_at"]
    assert any("older issued_at" in a.get("reason", "") for a in s.alerts)


def test_EO09_touching_the_file_is_not_a_refresh(tmp_path):
    s = store(tmp_path, signed())
    assert s.refresh_age_s() is None  # boot load is not a refresh
    os.utime(s.path, None)  # `touch`
    time.sleep(0.01)
    os.utime(s.path, None)
    s._last_check = 0.0
    assert s.lvb is not None and s.refresh_age_s() is None


def test_EO09_a_newer_operator_resign_on_disk_still_counts_as_refresh(tmp_path):
    s = store(tmp_path, signed())
    rewrite(s, signed(T0 + timedelta(minutes=30), version=43))
    assert s.version == 43 and s.refresh_age_s() is not None


def test_EO09_same_stamps_but_different_content_is_rejected(tmp_path):
    s = store(tmp_path, signed())
    other = load_example_bundle()
    other["issued_at"], other["expires_at"] = _z(T0), _z(T0 + timedelta(hours=12))
    other["roles"]["student"]["windows"]["LIBRARY"][0]["end"] = "23:59"
    ok, reason = s.install(sign_bundle(other, TEST_BUNDLE_KEY), T0)
    assert not ok and "different content" in reason


def test_EO09_mixed_timestamp_formats_compare_as_instants(tmp_path):
    s = store(tmp_path, signed(T0 + timedelta(hours=1)))
    b = load_example_bundle()
    b["issued_at"] = (T0 + timedelta(minutes=30)).isoformat()  # "+00:00" form, earlier instant
    b["expires_at"] = _z(T0 + timedelta(hours=12))
    assert s.install(sign_bundle(b, TEST_BUNDLE_KEY), T0)[0] is False


# ---------------------------------------------------------------- EO-10 documented codes
def test_EO10_documented_codes_never_reach_the_decision_bundle_without_demo_mode(tmp_path):
    s = store(tmp_path, signed())
    codes = {c["code_id"] for c in s.decision_bundle["override_codes"]["codes"]}
    assert not codes & DOC_IDS and set(s.dropped_codes) == DOC_IDS
    assert verify_bundle(s.lvb, TEST_BUNDLE_KEY, "demo-k1")  # the LVB itself stays the verbatim signed document
    assert {c["code_id"] for c in s.lvb["override_codes"]["codes"]} >= DOC_IDS
    assert any(a["type"] == "BUNDLE_DOCUMENTED_CODES_DROPPED" for a in s.alerts)


def test_EO10_demo_mode_keeps_them(tmp_path):
    s = store(tmp_path, signed(), allow_documented_codes=True)
    assert {c["code_id"] for c in s.decision_bundle["override_codes"]["codes"]} >= DOC_IDS


def test_EO10_a_renamed_documented_value_is_still_dropped_and_fresh_codes_kept():
    b = load_example_bundle()
    oc = b["override_codes"]
    renamed = {**oc["codes"][0], "code_id": "OVR-R1115120000-01"}  # documented value, new id
    fresh = {**oc["codes"][0], "code_id": "OVR-R1115120000-02", "hash": "00" * 32}
    oc["codes"] = [renamed, fresh]
    out, dropped = without_documented_codes(b)
    assert dropped == ["OVR-R1115120000-01"] and [c["code_id"] for c in out["override_codes"]["codes"]] == [
        "OVR-R1115120000-02"]
    assert b["override_codes"]["codes"] == [renamed, fresh]  # input not mutated
    assert is_documented_code("not a dict", 100000) and is_documented_code({"salt": "zz"}, 100000)


# ---------------------------------------------------------------- consumed_code_ids (RBAC v2 E / D8)
def test_consumed_code_ids_survive_verify_install_reload_and_the_decision_view(tmp_path):
    consumed = ["OVR-R1115090000-03", "OVR-R1115090000-07"]
    b = signed(version=43, consumed_code_ids=consumed)
    assert verify_bundle(b, TEST_BUNDLE_KEY, "demo-k1")
    tampered = copy.deepcopy(b)
    tampered["consumed_code_ids"] = []
    assert not verify_bundle(tampered, TEST_BUNDLE_KEY)  # part of the signed body
    s = store(tmp_path, signed())
    assert s.install(b, T0)[0]
    assert s.lvb["consumed_code_ids"] == consumed and s.decision_bundle["consumed_code_ids"] == consumed
    again = BundleStore(s.path, TEST_BUNDLE_KEY, KIOSK)  # reload from disk
    assert again.lvb["consumed_code_ids"] == consumed and again.decision_bundle["consumed_code_ids"] == consumed


# ---------------------------------------------------------------- EO-M2 durability
def test_EOM2_install_writes_0600_with_a_backup_and_boot_falls_back_to_it(tmp_path):
    old = os.umask(0o022)
    try:
        s = store(tmp_path, None)
        assert s.install(signed(), T0)[0]
    finally:
        os.umask(old)
    bak = s.path.with_name(s.path.name + BACKUP_SUFFIX)
    assert stat.S_IMODE(os.stat(s.path).st_mode) == 0o600 and stat.S_IMODE(os.stat(bak).st_mode) == 0o600
    assert not list(tmp_path.glob(".bundle-*"))  # no temp file left behind
    s.path.write_bytes(b"")  # power loss leaves a 0-byte main file
    booted = BundleStore(s.path, TEST_BUNDLE_KEY, KIOSK)
    assert booted.version == 42 and any(a["type"] == "BUNDLE_BACKUP_LOADED" for a in booted.alerts)


def test_EOM2_a_tampered_backup_is_never_loaded(tmp_path):
    s = store(tmp_path, None)
    s.install(signed(), T0)
    bak = s.path.with_name(s.path.name + BACKUP_SUFFIX)
    b = json.loads(bak.read_text(encoding="utf-8"))
    b["roles"]["student"]["windows"]["LIBRARY"][0]["end"] = "23:59"
    bak.write_text(json.dumps(b), encoding="utf-8")
    s.path.unlink()
    assert BundleStore(s.path, TEST_BUNDLE_KEY, KIOSK).lvb is None


# ---------------------------------------------------------------- OS-5 boot keeps the newer of main / .bak
def _plant(tmp_path, main: dict | None, bak: dict | None):
    p = tmp_path / "bundle.signed.json"
    if main is not None:
        p.write_text(json.dumps(main), encoding="utf-8")
    if bak is not None:
        p.with_name(p.name + BACKUP_SUFFIX).write_text(json.dumps(bak), encoding="utf-8")
    return p


def test_OS5_boot_prefers_a_newer_verified_backup_over_a_readable_older_main(tmp_path):
    """Power loss between the .bak write and the main replace: main v45, .bak v46 -> v46 + alert."""
    p = _plant(tmp_path, signed(version=45), signed(T0 + timedelta(minutes=5), version=46))
    s = BundleStore(p, TEST_BUNDLE_KEY, KIOSK)
    assert s.version == 46
    alert = next(a for a in s.alerts if a["type"] == "BUNDLE_ROLLBACK_SUSPECTED")
    assert alert["main_version"] == 45 and alert["backup_version"] == 46
    assert s.refresh_age_s() is None  # the boot load is never a refresh


def test_OS5_an_old_main_restored_at_boot_does_not_roll_back_below_the_backup(tmp_path):
    p = _plant(tmp_path, signed(version=42), signed(version=45))
    assert BundleStore(p, TEST_BUNDLE_KEY, KIOSK).version == 45


def test_OS5_a_tampered_backup_never_wins(tmp_path):
    bak = signed(version=46)
    bak["roles"]["student"]["windows"]["LIBRARY"][0]["end"] = "23:59"
    p = _plant(tmp_path, signed(version=45), bak)
    s = BundleStore(p, TEST_BUNDLE_KEY, KIOSK)
    assert s.version == 45 and not any(a["type"] == "BUNDLE_ROLLBACK_SUSPECTED" for a in s.alerts)


def test_OS5_an_equal_or_older_backup_keeps_the_main_file_silently(tmp_path):
    p = _plant(tmp_path, signed(T0 + timedelta(minutes=5), version=46), signed(version=45))
    s = BundleStore(p, TEST_BUNDLE_KEY, KIOSK)
    assert s.version == 46 and not any(a["type"] == "BUNDLE_ROLLBACK_SUSPECTED" for a in s.alerts)


# ---------------------------------------------------------------- OS-8 no PBKDF2 on the decision path
def test_OS8_documented_code_view_is_computed_at_install_never_on_read(tmp_path, monkeypatch):
    import edge.offline.bundle as bundle_mod

    s = store(tmp_path, None)
    assert s.install(signed(), T0)[0]

    def boom(*_a, **_k):
        raise AssertionError("PBKDF2 on the decision path")

    monkeypatch.setattr(bundle_mod, "is_documented_code", boom)
    monkeypatch.setattr(bundle_mod.hashlib, "pbkdf2_hmac", boom)
    view = s.decision_bundle
    assert not {c["code_id"] for c in view["override_codes"]["codes"]} & DOC_IDS
    assert set(s.dropped_codes) == DOC_IDS


def test_OS8_view_is_ready_after_boot_and_file_reload_too(tmp_path, monkeypatch):
    import edge.offline.bundle as bundle_mod

    s = store(tmp_path, signed())
    rewrite(s, signed(T0 + timedelta(minutes=30), version=43))
    _ = s.lvb  # the reload (sync thread / admin path) computes the view
    monkeypatch.setattr(bundle_mod, "is_documented_code",
                        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("lazy scan")))
    assert s.version == 43 and not {c["code_id"] for c in s.decision_bundle["override_codes"]["codes"]} & DOC_IDS
    assert any(a["type"] == "BUNDLE_DOCUMENTED_CODES_DROPPED" for a in s.alerts)
