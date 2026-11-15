"""§7.2 fallback primitives: TOTP (RFC 6238), card hash, staff override PBKDF2, validity, replay."""

from __future__ import annotations

import base64
import copy
from datetime import UTC, datetime, timedelta

import pyotp
import pytest

from edge.policy.fallback import (
    FallbackVerifier,
    InMemoryFallbackState,
    card_hash,
    hotp,
    override_hash,
    totp_matching_step,
)
from edge.policy.signals import FallbackSubmission
from edge.policy.tests.builders import (
    FIXTURE_STAFF,
    SIGNED_BUNDLE,
    TEST_CARD_PEPPER,
    THRESHOLDS_PATH,
    TOTP_SECRETS,
    utc,
)
from edge.policy.thresholds import Thresholds

T = Thresholds.load(THRESHOLDS_PATH)
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()  # RFC 6238 Appendix B (SHA1)


def test_totp_matches_rfc6238_appendix_b_vectors():
    # (unix time, 8-digit SHA1 value from the RFC) -> our 6-digit HOTP is its last 6 digits
    for t, v8 in [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                  (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]:
        assert hotp(RFC_SECRET, t // 30, digits=8) == v8
        assert hotp(RFC_SECRET, t // 30, digits=6) == v8[-6:]


def test_totp_agrees_with_pyotp_and_accepts_plus_minus_one_step():
    secret = TOTP_SECRETS["u_3c4d"]
    now = utc("2026-11-14T04:35:00")
    step = int(now.timestamp()) // 30
    for d in (-1, 0, 1):
        code = pyotp.TOTP(secret).at(int(now.timestamp()) + 30 * d)
        assert totp_matching_step(secret, code, now) == step + d
    assert totp_matching_step(secret, pyotp.TOTP(secret).at(int(now.timestamp()) + 90), now) is None
    assert totp_matching_step(secret, "12345", now) is None and totp_matching_step(secret, "abcdef", now) is None


def test_card_hash_matches_the_example_bundle():
    assert card_hash(TEST_CARD_PEPPER, "HID-CARD-1002") == SIGNED_BUNDLE["users"]["u_3c4d"]["fallback"]["card_id_hash"]


def test_override_hash_matches_the_example_bundle():
    c = SIGNED_BUNDLE["override_codes"]["codes"][0]
    assert override_hash("48213907", c["salt"], 100000) == c["hash"]


def verifier(bundle=SIGNED_BUNDLE, state=None):
    return FallbackVerifier(T, state or InMemoryFallbackState(), totp_secret=TOTP_SECRETS.get,
                            card_pepper=TEST_CARD_PEPPER, bundle=lambda: bundle)


def staff(code, **kw):
    kw.setdefault("staff_id", FIXTURE_STAFF.get(code, "s_guard01"))  # R2: always named unless a test says so
    return FallbackSubmission(method="STAFF_OVERRIDE", code=code, **kw)


NOW = utc("2026-11-14T04:35:00")


def test_staff_override_respects_valid_until_on_the_wall_clock():
    b = copy.deepcopy(SIGNED_BUNDLE)
    for c in b["override_codes"]["codes"]:
        c["valid_until"] = "2026-11-14T05:00:00Z"
    v = verifier(b)
    assert v.verify(staff("48213907"), None, "OFFLINE", NOW, wall_now=utc("2026-11-14T05:00:00")).ok is False
    assert v.verify(staff("48213907"), None, "OFFLINE", NOW, wall_now=utc("2026-11-14T04:59:59")).ok is True


def test_staff_override_missing_valid_until_defaults_to_expiry_plus_grace():
    b = copy.deepcopy(SIGNED_BUNDLE)
    for c in b["override_codes"]["codes"]:
        c.pop("valid_until")
    v = verifier(b)  # expires_at 14:30Z + 24 h
    assert v.verify(staff("48213907"), None, "OFFLINE", NOW, wall_now=utc("2026-11-15T14:29:00")).ok is True


def test_staff_override_staff_id_must_match():
    assert verifier().verify(staff("48213907", staff_id="s_guard02"), None, "OFFLINE", NOW).ok is False
    assert verifier().verify(staff("48213907", staff_id="s_guard01"), None, "OFFLINE", NOW).ok is True


@pytest.mark.parametrize("missing", [None, "", "   "])
def test_staff_override_requires_the_staff_id(missing):
    """R2 / lead 2026-11-14 (security): without staff_id an override must not match ANY guard's code."""
    for code in ("48213907", "75530182", "19064425"):  # every valid fixture code, of both guards
        res = verifier().verify(staff(code, staff_id=missing), None, "OFFLINE", NOW)
        assert res.ok is False and res.reason == "staff_id required" and res.fallback is None
    res = verifier().verify(staff("19064425"), None, "OFFLINE", NOW)  # the same code, named -> accepted
    assert res.ok is True and res.fallback["staff_id"] == "s_guard02"


def test_missing_staff_id_counts_only_towards_the_device_backstop():
    """F05: anonymous submissions cannot lock a named guard with max_failures guesses; only the device backstop
    (device_max_failures in device_window_s) locks every override."""
    st = InMemoryFallbackState()
    v = verifier(state=st)
    for _ in range(int(T.fallback.staff_override.max_failures)):
        assert v.verify(staff("48213907", staff_id=None), None, "OFFLINE", NOW).ok is False
    assert v.verify(staff("75530182"), None, "OFFLINE", NOW + timedelta(seconds=1)).ok is True
    for _ in range(int(T.fallback.staff_override.device_max_failures)):
        v.verify(staff("48213907", staff_id=None), None, "OFFLINE", NOW + timedelta(seconds=2))
    res = v.verify(staff("48213907"), None, "OFFLINE", NOW + timedelta(seconds=3))
    assert res.ok is False and res.reason == "staff override locked"


def test_staff_override_without_verified_bundle_never_verifies():
    assert verifier(bundle=None).verify(staff("48213907"), None, "OFFLINE", NOW).ok is False


def test_staff_override_wrong_length_rejected():
    assert verifier().verify(staff("4821390"), None, "OFFLINE", NOW).ok is False


def test_totp_requires_enrolment_and_secret():
    b = copy.deepcopy(SIGNED_BUNDLE)
    b["users"]["u_3c4d"]["fallback"]["totp_enrolled"] = False
    code = pyotp.TOTP(TOTP_SECRETS["u_3c4d"]).at(int(NOW.timestamp()))
    sub = FallbackSubmission(method="TOTP", code=code)
    assert verifier(b).verify(sub, "u_3c4d", "OFFLINE", NOW).ok is False
    assert verifier().verify(sub, "u_9c0d", "OFFLINE", NOW).ok is False  # no secret cached
    assert verifier().verify(sub, "u_3c4d", "OFFLINE", NOW).ok is True


def test_totp_older_step_rejected_after_newer_accepted():
    v = verifier()
    later = NOW + timedelta(seconds=30)
    assert v.verify(FallbackSubmission(method="TOTP", code=pyotp.TOTP(TOTP_SECRETS["u_3c4d"]).at(
        int(later.timestamp()))), "u_3c4d", "OFFLINE", later).ok
    older = pyotp.TOTP(TOTP_SECRETS["u_3c4d"]).at(int(NOW.timestamp()))
    assert v.verify(FallbackSubmission(method="TOTP", code=older), "u_3c4d", "OFFLINE", later).ok is False


def test_email_otp_offline_never_verifies():
    sub = FallbackSubmission(method="EMAIL_OTP", email_otp_verified=True)
    assert verifier().verify(sub, "u_3c4d", "OFFLINE", NOW).ok is False
    assert verifier().verify(sub, "u_3c4d", "ONLINE", NOW).ok is True


def test_fallback_log_info_never_contains_code_values():
    res = verifier().verify(staff("48213907"), None, "OFFLINE", NOW)
    assert "48213907" not in repr(res.fallback)
    assert res.fallback == {"method": "STAFF_OVERRIDE", "staff_id": "s_guard01", "code_id": "OVR-001", "totp_step": None}
    code = pyotp.TOTP(TOTP_SECRETS["u_3c4d"]).at(int(NOW.timestamp()))
    res = verifier().verify(FallbackSubmission(method="TOTP", code=code), "u_3c4d", "OFFLINE", NOW)
    assert code not in repr(res.fallback)
    assert res.fallback["totp_step"] == int(NOW.timestamp()) // 30  # time-step counter for Y07, not a secret


def test_naive_wall_clock_not_used():
    assert isinstance(NOW, datetime) and NOW.tzinfo is UTC


# ---------------------------------------------------------------- hostile input never raises (audit 2026-11-14)
@pytest.mark.parametrize("code", ["١٢٣٤٥٦", "１２３４５６", "12345é", "²³⁴⁵⁶⁷"])
def test_totp_with_non_ascii_digits_is_rejected_not_raised(code):
    res = verifier().verify(FallbackSubmission(method="TOTP", code=code), "u_3c4d", "OFFLINE", NOW)
    assert res.ok is False


def test_override_entry_with_a_malformed_salt_is_skipped_not_raised():
    b = copy.deepcopy(SIGNED_BUNDLE)
    b["override_codes"]["codes"][0]["salt"] = "zz-not-hex"
    v = verifier(b)
    assert v.verify(staff("48213907"), None, "OFFLINE", NOW).ok is False  # the broken entry never matches
    assert verifier(b).verify(staff("75530182"), None, "OFFLINE", NOW).ok is True  # others still work


def test_card_revoked_in_the_bundle_or_the_feed_is_rejected():
    b = copy.deepcopy(SIGNED_BUNDLE)
    h = card_hash(TEST_CARD_PEPPER, "HID-CARD-1002")
    sub = FallbackSubmission(method="CARD", card_id="HID-CARD-1002")
    assert verifier(b).verify(sub, "u_3c4d", "OFFLINE", NOW).ok is True
    b["revocations"] = [*b.get("revocations", []), {"type": "CARD", "target_id": h, "reason": "LOST"}]
    res = verifier(b).verify(sub, "u_3c4d", "OFFLINE", NOW)
    assert res.ok is False and res.reason == "card revoked"
    feed = FallbackVerifier(T, InMemoryFallbackState(), totp_secret=TOTP_SECRETS.get, card_pepper=TEST_CARD_PEPPER,
                            bundle=lambda: SIGNED_BUNDLE, card_revoked=lambda x: x == h)
    assert feed.verify(sub, "u_3c4d", "OFFLINE", NOW).reason == "card revoked"
