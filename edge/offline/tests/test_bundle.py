"""Signed schedule bundle: canonical HMAC signature, last-valid-bundle store (lead R6), hot reload."""

from __future__ import annotations

import copy
import json
import time
from datetime import UTC, datetime, timedelta

from edge.offline.bundle import BundleStore, bundle_signature, canonical_json, sign_bundle, verify_bundle
from edge.policy.tests.builders import (
    TEST_BUNDLE_KEY,
    bundle_signed_at,
    load_example_bundle,
    sign_fixture_bundle,
    tampered,
)

NOW = datetime(2026, 11, 14, 4, 35, tzinfo=UTC)
# key_id=None: fixtures mix sign_bundle (demo-k1) and builders.sign_fixture_bundle (test-k1); pinning is tested in test_os_bundle.py


def test_canonical_form_matches_the_documented_one():
    b = {"b": 1, "a": {"y": "é", "x": [1, 2]}}
    assert canonical_json(b) == '{"a":{"x":[1,2],"y":"é"},"b":1}'.encode()


def test_signature_matches_an_independent_implementation():
    ours = sign_bundle(load_example_bundle(), TEST_BUNDLE_KEY, key_id="test-k1")
    theirs = sign_fixture_bundle(load_example_bundle())
    assert ours["signature"]["value"] == theirs["signature"]["value"]
    assert verify_bundle(ours, TEST_BUNDLE_KEY)


def test_verification_rejects_tamper_unsigned_wrong_key_and_alg():
    good = sign_bundle(load_example_bundle(), TEST_BUNDLE_KEY)
    assert not verify_bundle(tampered(good), TEST_BUNDLE_KEY)
    assert not verify_bundle(load_example_bundle(), TEST_BUNDLE_KEY)  # O25: unsigned example
    assert not verify_bundle(good, b"other-key")
    bad_alg = copy.deepcopy(good)
    bad_alg["signature"]["alg"] = "none"
    assert not verify_bundle(bad_alg, TEST_BUNDLE_KEY)
    assert not verify_bundle(good, None)
    assert bundle_signature(good, TEST_BUNDLE_KEY) == good["signature"]["value"]


def store(tmp_path, bundle=None, kiosk="KIOSK_LIB_01"):
    p = tmp_path / "bundle.signed.json"
    if bundle is not None:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(bundle), encoding="utf-8")
    return BundleStore(p, TEST_BUNDLE_KEY, kiosk, key_id=None)


def test_boot_with_valid_file_has_lvb_but_no_refresh(tmp_path):
    s = store(tmp_path, bundle_signed_at(NOW))
    assert s.lvb is not None and s.version == 42 and s.refresh_age_s() is None


def test_boot_with_tampered_or_unsigned_file_has_no_lvb(tmp_path):
    s = store(tmp_path, tampered(bundle_signed_at(NOW)))
    assert s.lvb is None and s.alerts and s.alerts[-1]["type"] == "BUNDLE_REJECTED"
    s2 = store(tmp_path / "x", load_example_bundle())
    assert s2.lvb is None


def test_received_bundle_failing_verification_never_replaces_lvb_r6(tmp_path):
    s = store(tmp_path, bundle_signed_at(NOW))
    ok, _why = s.install(tampered(bundle_signed_at(NOW)), NOW)
    assert not ok and s.lvb is not None and verify_bundle(s.lvb, TEST_BUNDLE_KEY)
    assert json.loads((tmp_path / "bundle.signed.json").read_text())["signature"] == s.lvb["signature"]


def test_install_rules(tmp_path):
    s = store(tmp_path, bundle_signed_at(NOW))
    newer = load_example_bundle()
    newer["bundle_version"] = 43
    assert s.install(sign_bundle(newer, TEST_BUNDLE_KEY), NOW)[0] and s.version == 43
    assert s.refresh_age_s() is not None and s.refresh_age_s() < 1
    older = load_example_bundle()
    older["bundle_version"] = 41
    assert not s.install(sign_bundle(older, TEST_BUNDLE_KEY), NOW)[0] and s.version == 43
    same_older_stamp = copy.deepcopy(s.lvb)
    same_older_stamp.pop("signature")
    same_older_stamp["issued_at"] = "2026-11-13T00:00:00Z"
    assert not s.install(sign_bundle(same_older_stamp, TEST_BUNDLE_KEY), NOW)[0]  # API.md 4.2
    resign = copy.deepcopy(s.lvb)
    resign.pop("signature")
    resign["issued_at"] = "2026-11-14T09:00:00Z"
    assert s.install(sign_bundle(resign, TEST_BUNDLE_KEY), NOW)[0]  # equal version, newer issued_at


def test_bundle_outside_kiosk_scope_rejected(tmp_path):
    b = load_example_bundle()
    b["scope"]["kiosk_ids"] = ["KIOSK_MAIN_01"]
    s = store(tmp_path, None)
    assert not s.install(sign_bundle(b, TEST_BUNDLE_KEY), NOW)[0]


def test_mark_confirmed_resets_refresh_age(tmp_path):
    s = store(tmp_path, bundle_signed_at(NOW))
    assert s.refresh_age_s() is None
    s.mark_confirmed(NOW)
    assert s.refresh_age_s() is not None and s.schedule_ctx().refresh_age_s < 1


def test_hot_reload_of_a_resigned_file_counts_as_refresh(tmp_path):
    s = store(tmp_path, bundle_signed_at(NOW))
    b = load_example_bundle()
    b["issued_at"], b["expires_at"] = "2026-11-14T05:00:00Z", "2026-11-14T17:00:00Z"
    time.sleep(0.01)
    (tmp_path / "bundle.signed.json").write_text(json.dumps(sign_bundle(b, TEST_BUNDLE_KEY)), encoding="utf-8")
    s._last_check = 0.0  # skip the 1 s rate limit of the mtime check
    assert s.lvb["issued_at"] == "2026-11-14T05:00:00Z"
    assert s.refresh_age_s() is not None


def test_hot_reload_of_a_tampered_file_keeps_lvb(tmp_path):
    s = store(tmp_path, bundle_signed_at(NOW))
    before = s.lvb["signature"]["value"]
    time.sleep(0.01)
    (tmp_path / "bundle.signed.json").write_text(json.dumps(tampered(bundle_signed_at(NOW))), encoding="utf-8")
    s._last_check = 0.0
    assert s.lvb["signature"]["value"] == before and s.alerts[-1]["type"] == "BUNDLE_REJECTED"


def test_schedule_ctx_only_exposes_verified_data(tmp_path):
    ctx = store(tmp_path, tampered(bundle_signed_at(NOW))).schedule_ctx()
    assert ctx.lvb is None and ctx.bundle is None
    ctx = store(tmp_path / "ok", bundle_signed_at(NOW)).schedule_ctx(({"user_id": "u_x", "revoked_at": None},))
    assert ctx.lvb is not None and ctx.extra_revocations


def test_store_written_atomically_and_reloadable(tmp_path):
    s = store(tmp_path, None)
    b = sign_bundle(load_example_bundle(), TEST_BUNDLE_KEY)
    assert s.install(b, NOW)[0]
    s2 = BundleStore(tmp_path / "bundle.signed.json", TEST_BUNDLE_KEY, "KIOSK_LIB_01", key_id=None)
    assert s2.lvb == b and not list(tmp_path.glob(".bundle-*"))


def test_effective_window_uses_relative_stamps():
    b = bundle_signed_at(NOW)
    issued = datetime.fromisoformat(b["issued_at"])
    assert NOW - issued == timedelta(minutes=5)
