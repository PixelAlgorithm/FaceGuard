"""policy-fixes: persisted second-factor failure limits (SC2-D9, F05, F06, EO-12, KF-03), consumed_code_ids
(SC2-D8), 10-digit codes with legacy 8 (EO-11) and per-code scope (F09)."""

from __future__ import annotations

import copy
from datetime import timedelta

import pyotp

from edge.offline.store import SqliteFallbackState
from edge.policy.fallback import FallbackVerifier, InMemoryFallbackState, override_hash
from edge.policy.signals import FallbackSubmission
from edge.policy.tests.builders import (
    SIGNED_BUNDLE,
    TEST_CARD_PEPPER,
    TEST_DATA_KEY,
    THRESHOLDS_PATH,
    TOTP_SECRETS,
    utc,
)
from edge.policy.thresholds import Thresholds

T = Thresholds.load(THRESHOLDS_PATH)
NOW = utc("2026-11-14T04:35:00")
GOOD = ("48213907", "s_guard01")  # fixture code (config/schedule.example.json)
DATA_KEY = TEST_DATA_KEY


def verifier(state, bundle=SIGNED_BUNDLE, alerts=None):
    return FallbackVerifier(T, state, totp_secret=TOTP_SECRETS.get, card_pepper=TEST_CARD_PEPPER,
                            bundle=lambda: bundle,
                            on_lockout=(lambda k, s: alerts.append((k, s))) if alerts is not None else None)


def staff(code, staff_id):
    return FallbackSubmission(method="STAFF_OVERRIDE", code=code, staff_id=staff_id)


def test_D9_override_lockout_survives_a_restart(tmp_path):
    path = tmp_path / "fallback_state.sqlite"
    v = verifier(SqliteFallbackState(path, DATA_KEY))
    for i in range(3):
        assert v.verify(staff("1111111" + str(i), "s_guard01"), None, "OFFLINE", NOW).ok is False
    v2 = verifier(SqliteFallbackState(path, DATA_KEY))  # "restart": new process, same file
    res = v2.verify(staff(*GOOD), None, "OFFLINE", NOW + timedelta(seconds=30))
    assert res.ok is False and res.reason == "staff override locked" and res.locked_until is not None
    assert v2.verify(staff(*GOOD), None, "OFFLINE", NOW + timedelta(seconds=301)).ok is True


def test_F05_anonymous_guesses_do_not_lock_out_a_named_guard():
    v = verifier(InMemoryFallbackState())
    for i in range(3):  # unknown staff id and missing staff id: backstop only
        v.verify(staff(f"2222222{i}", "s_nobody"), None, "OFFLINE", NOW)
        v.verify(staff(f"3333333{i}", None), None, "OFFLINE", NOW)
    assert v.verify(staff(*GOOD), None, "OFFLINE", NOW + timedelta(seconds=1)).ok is True


def test_F05_device_backstop_locks_every_override_after_10_failures_in_5_min():
    alerts: list = []
    v = verifier(InMemoryFallbackState(), alerts=alerts)
    for i in range(10):
        v.verify(staff(f"4444444{i % 10}", "s_unknown" if i % 2 else None), None, "OFFLINE", NOW)
    res = v.verify(staff(*GOOD), None, "OFFLINE", NOW + timedelta(seconds=2))
    assert res.ok is False and res.reason == "staff override locked"
    assert ("STAFF_OVERRIDE_DEVICE", None) in alerts
    assert v.verify(staff(*GOOD), None, "OFFLINE", NOW + timedelta(seconds=302)).ok is True


def test_backstop_window_expires_slow_failures_do_not_lock():
    v = verifier(InMemoryFallbackState())
    for i in range(10):
        v.verify(staff(f"5555555{i}", None), None, "OFFLINE", NOW + timedelta(seconds=40 * i))  # 10 over 6 min
    assert v.verify(staff(*GOOD), None, "OFFLINE", NOW + timedelta(seconds=401)).ok is True


def test_lock_is_clamped_when_the_real_clock_steps_backwards():
    st = InMemoryFallbackState()
    v = verifier(st)
    for i in range(3):
        v.verify(staff(f"6666666{i}", "s_guard01"), None, "OFFLINE", NOW + timedelta(days=1))
    back = NOW  # clock jumped back one day: still locked, but at most lockout_s from now
    assert v.verify(staff(*GOOD), None, "OFFLINE", back).ok is False
    assert v.verify(staff(*GOOD), None, "OFFLINE", back + timedelta(seconds=301)).ok is True


def test_tampered_failure_row_reads_as_locked(tmp_path):
    path = tmp_path / "fb.sqlite"
    st = SqliteFallbackState(path, DATA_KEY)
    v = verifier(st)
    v.verify(staff("77777770", "s_guard01"), None, "OFFLINE", NOW)
    st._db.execute("UPDATE fb_fail SET payload=?", (b"\x00" * 40,))
    assert v.verify(staff(*GOOD), None, "OFFLINE", NOW + timedelta(seconds=1)).ok is False


def test_F06_totp_per_user_failure_limit_persists_and_locks_unchecked(tmp_path):
    path = tmp_path / "fb.sqlite"
    secret = TOTP_SECRETS["u_3c4d"]
    v = verifier(SqliteFallbackState(path, DATA_KEY))
    for i in range(5):
        res = v.verify(FallbackSubmission(method="TOTP", code=f"00000{i}"), "u_3c4d", "OFFLINE", NOW)
        assert res.ok is False
    good = pyotp.TOTP(secret).at(int(NOW.timestamp()))
    res = verifier(SqliteFallbackState(path, DATA_KEY)).verify(
        FallbackSubmission(method="TOTP", code=good), "u_3c4d", "OFFLINE", NOW)
    assert res.ok is False and res.locked_until is not None
    other = verifier(SqliteFallbackState(path, DATA_KEY))  # another user is unaffected
    assert other.verify(FallbackSubmission(method="TOTP", code="000000"), "u_5e6f", "OFFLINE", NOW).locked_until is None


def test_F06_card_per_user_failure_limit():
    v = verifier(InMemoryFallbackState())
    for i in range(5):
        assert v.verify(FallbackSubmission(method="CARD", card_id=f"HID-CARD-99{i}"), "u_3c4d", "OFFLINE", NOW).ok is False
    res = v.verify(FallbackSubmission(method="CARD", card_id="HID-CARD-1002"), "u_3c4d", "OFFLINE", NOW)
    assert res.ok is False and res.locked_until is not None
    later = v.verify(FallbackSubmission(method="CARD", card_id="HID-CARD-1002"), "u_3c4d", "OFFLINE",
                     NOW + timedelta(seconds=301))
    assert later.ok is True


def test_D8_code_listed_in_consumed_code_ids_is_rejected_and_counted():
    b = copy.deepcopy(SIGNED_BUNDLE)
    b["consumed_code_ids"] = ["OVR-001"]
    res = verifier(InMemoryFallbackState(), bundle=b).verify(staff(*GOOD), None, "OFFLINE", NOW)
    assert res.ok is False and res.counted is True


def _bundle_with_code(code: str, **extra) -> dict:
    b = copy.deepcopy(SIGNED_BUNDLE)
    c = {"code_id": "OVR-NEW", "staff_id": "s_guard09", "salt": "00112233445566778899aabbccddeeff",
         "valid_until": "2026-11-15T14:30:00Z", **extra}
    c["hash"] = override_hash(code, c["salt"], 100000)
    b["override_codes"]["codes"].append(c)
    return b


def test_EO11_ten_digit_codes_and_legacy_eight_digit_codes_are_accepted():
    b = _bundle_with_code("0123456789")
    assert verifier(InMemoryFallbackState(), bundle=b).verify(staff("0123456789", "s_guard09"), None, "OFFLINE",
                                                              NOW).ok is True
    assert verifier(InMemoryFallbackState()).verify(staff(*GOOD), None, "OFFLINE", NOW).ok is True
    assert verifier(InMemoryFallbackState()).verify(staff("482139071", "s_guard01"), None, "OFFLINE", NOW).ok is False


def test_F09_code_scope_restricts_zones_and_kiosks():
    b = _bundle_with_code("0123456789", zones=["LIBRARY"], kiosk_ids=["KIOSK_LIB_01"])
    v = verifier(InMemoryFallbackState(), bundle=b)
    sub = staff("0123456789", "s_guard09")
    assert v.verify(sub, None, "OFFLINE", NOW, zone="SERVER_ROOM", kiosk_id="KIOSK_LIB_01").ok is False
    assert v.verify(sub, None, "OFFLINE", NOW, zone="LIBRARY", kiosk_id="KIOSK_SRV_01").ok is False
    assert v.verify(sub, None, "OFFLINE", NOW, zone="LIBRARY", kiosk_id="KIOSK_LIB_01").ok is True
