"""Control-panel round (2026-11-14 late): what the edge admin proxies need from the policy runtime.

- PolicyRuntime.refresh_bundle_now(): pull + verify + install the newest cloud bundle now (fail-secure).
- SECOND_FACTOR methods filtered by the candidate's VERIFIED bundle entry (and the local TOTP secret):
  filtering only ever removes methods, never adds one, and never leaves a step-up with nothing to offer.
- TOTP usability status for the enrolment UI (bundle flag + locally cached secret).
- Demo clock: bounded offsets (no OverflowError bricking the runtime) and a rollback warning in the status.
- Schedule: user extra_windows / zones_add (all-day windows, several windows a day, midnight edges).
All in-process with a mocked cloud -- never the live :8000 edge.
"""

from __future__ import annotations

import copy
import json
import math

import httpx
import pyotp
import pytest

from edge.offline.bundle import sign_bundle
from edge.policy import schedule as S
from edge.policy.runtime import CloudUnavailableError
from edge.policy.signals import FallbackSubmission
from edge.policy.tests.builders import (
    OB,
    TEST_BUNDLE_KEY,
    TOTP_SECRETS,
    B,
    bundle_signed_at,
    ist,
    sign_fixture_bundle,
)
from edge.policy.tests.test_runtime import FakeCloud, attempt, bring_online, ok
from edge.policy.tests.test_runtime import make_rt as _make_rt_fixture

make_rt = _make_rt_fixture  # same fixture as test_runtime.py (temp data dir, mocked cloud)

ON_ALL = ["TOTP", "CARD", "EMAIL_OTP", "STAFF_OVERRIDE"]


# ================================================================ methods filtered by the bundle entry
def _with_user(scn, user: str, **fallback):
    b = bundle_signed_at(scn.eff_now)
    b.pop("signature")
    fb = b["users"][user].setdefault("fallback", {})
    for k, v in fallback.items():
        if v is None:
            fb.pop(k, None)
        else:
            fb[k] = v
    scn.bundle = sign_fixture_bundle(b)
    return scn


def test_grace_step_up_offers_every_method_for_a_fully_enrolled_user():
    d = B().who("u_3c4d", "LIB", "2026-11-14 07:50").evaluate()
    assert d.decision == "STEP_UP" and list(d.next_action.methods) == ON_ALL


def test_totp_not_offered_without_a_bundle_totp_enrolment():
    d = _with_user(B().who("u_3c4d", "LIB", "2026-11-14 07:50"), "u_3c4d", totp_enrolled=False).evaluate()
    assert d.decision == "STEP_UP" and list(d.next_action.methods) == ["CARD", "EMAIL_OTP", "STAFF_OVERRIDE"]


def test_card_not_offered_without_a_card_hash():
    d = _with_user(B().who("u_3c4d", "LIB", "2026-11-14 07:50"), "u_3c4d", card_id_hash=None).evaluate()
    assert list(d.next_action.methods) == ["TOTP", "EMAIL_OTP", "STAFF_OVERRIDE"]


def test_offline_filter_keeps_staff_override_and_order():
    d = _with_user(OB().who("u_3c4d", "LIB", "2026-11-14 07:50"), "u_3c4d",
                   totp_enrolled=False, card_id_hash=None).evaluate()
    assert d.decision == "STEP_UP" and list(d.next_action.methods) == ["STAFF_OVERRIDE"]
    assert "OFFLINE_FALLBACK_REQUIRED" in d.reason_codes


def test_filter_never_empties_the_method_list():
    """online_high_risk = [TOTP, CARD, EMAIL_OTP]; with EMAIL_OTP disabled and neither TOTP nor a card the
    filter would leave nothing -> the configured list stays (nothing can be added, the session never offers [])."""
    scn = B().who("u_7a8b", "SRV", "2026-11-14 10:00").cfg({"fallback": {"email_otp": {"enabled": False}}})
    d = _with_user(scn, "u_7a8b", totp_enrolled=False, card_id_hash=None).evaluate()
    assert d.decision == "STEP_UP" and "SCHEDULE_HIGH_RISK_ZONE" in d.reason_codes
    assert list(d.next_action.methods) == ["TOTP", "CARD"]


def test_filter_never_adds_a_method():
    scn = OB().who("u_7a8b", "SRV", "2026-11-14 10:00")  # offline_high_risk = [TOTP, STAFF_OVERRIDE]
    d = scn.evaluate()
    assert list(d.next_action.methods) == ["TOTP", "STAFF_OVERRIDE"]  # card hash present, CARD still not added


# ================================================================ runtime: local TOTP secret + status
def test_runtime_drops_totp_when_no_local_secret(make_rt):
    rt = make_rt()
    rt.credentials.remove("u_3c4d")
    rt.demo_mode = True
    rt.set_demo_clock(set_local="2026-11-14T10:05:00")  # stays inside the bundle (issued 10:00 IST)
    body = ok(rt.decide(attempt("att_aa_nosecret", pad=[0.85, 0.82, 0.60, 0.50, 0.70])))
    assert body["mode"] == "OFFLINE" and "TOTP" not in body["next_action"]["methods"]
    assert body["next_action"]["methods"] == ["CARD", "STAFF_OVERRIDE"]


def test_runtime_methods_follow_local_secret(make_rt):
    rt = make_rt()
    body = ok(rt.decide(attempt("att_aa_secret", pad=[0.85, 0.82, 0.60, 0.50, 0.70])))
    assert body["next_action"]["steps"] == ["CHALLENGE", "SECOND_FACTOR"]
    assert body["next_action"]["methods"] == ["TOTP", "CARD", "STAFF_OVERRIDE"]
    rt.credentials.remove("u_3c4d")
    body = ok(rt.decide(attempt("att_aa_nosecret2", pad=[0.85, 0.82, 0.60, 0.50, 0.70])))
    assert body["next_action"]["methods"] == ["CARD", "STAFF_OVERRIDE"]
    assert rt.sessions["att_aa_nosecret2"].methods == ("CARD", "STAFF_OVERRIDE")


def test_totp_status(make_rt):
    rt = make_rt()
    assert rt.totp_status("u_3c4d") == {"user_id": "u_3c4d", "bundle_enrolled": True, "secret_cached": True,
                                        "usable": True}
    st = rt.totp_status("u_9c0d")  # contractor: totp_enrolled false in the bundle, no secret
    assert st["bundle_enrolled"] is False and st["usable"] is False
    rt.provision_totp("u_9c0d")
    st = rt.totp_status("u_9c0d")
    assert st["secret_cached"] is True and st["usable"] is False  # the bundle stays the gate
    st = rt.totp_status("u_nobody")
    assert st == {"user_id": "u_nobody", "bundle_enrolled": None, "secret_cached": False, "usable": False}


def test_totp_flag_false_user_never_burns_an_attempt_on_totp(make_rt):
    """The MAJOR: a TOTP-provisioned user without the bundle flag is not offered TOTP; submitting it anyway is
    still FALLBACK_FAILED (method not offered, R8) -- the bundle remains the gate."""
    rt = make_rt()
    b = copy.deepcopy(rt.bundles.lvb)
    b.pop("signature")
    b["users"]["u_3c4d"]["fallback"]["totp_enrolled"] = False
    b["bundle_version"] = int(b["bundle_version"]) + 1
    assert rt.bundles.install(sign_bundle(b, TEST_BUNDLE_KEY), rt.now())[0]
    body = ok(rt.decide(attempt("att_aa_flag", pad=[0.85, 0.82, 0.60, 0.50, 0.70])))
    assert "TOTP" not in body["next_action"]["methods"]


# ================================================================ refresh_bundle_now
def _newer(rt, **user_changes) -> dict:
    b = copy.deepcopy(rt.bundles.lvb)
    b.pop("signature")
    b["bundle_version"] = int(b["bundle_version"]) + 1
    for uid, change in user_changes.items():
        b["users"][uid].update(change)
    return sign_bundle(b, TEST_BUNDLE_KEY)


def test_refresh_bundle_now_installs_the_newer_bundle_and_role_follows(make_rt):
    cloud = FakeCloud(None)
    rt = make_rt(cloud=cloud)
    cloud.bundle = rt.bundles.lvb
    bring_online(rt)
    v0 = rt.bundles.version
    cloud.bundle = _newer(rt, u_3c4d={"role": "faculty"})
    assert rt.refresh_bundle_now() == v0 + 1
    assert rt.bundles.version == v0 + 1
    assert rt.user_info("u_3c4d")["role"] == "faculty"
    assert any(e["type"] == "BUNDLE_INSTALLED" for e in rt.events())
    assert rt.refresh_bundle_now(expect_version=v0 + 1) == v0 + 1  # 304/same version -> current version


def test_refresh_bundle_now_wrapped_payload(make_rt):
    cloud = FakeCloud(None)
    rt = make_rt(cloud=cloud)
    cloud.bundle = rt.bundles.lvb
    nb = _newer(rt)
    sig = nb.pop("signature")
    cloud.bundle = {"bundle": nb, "signature": sig}
    assert rt.refresh_bundle_now() == nb["bundle_version"]


def test_refresh_bundle_now_expect_version_not_yet_served(make_rt):
    cloud = FakeCloud(None)
    rt = make_rt(cloud=cloud)
    cloud.bundle = rt.bundles.lvb
    with pytest.raises(CloudUnavailableError):
        rt.refresh_bundle_now(expect_version=rt.bundles.version + 1)


def test_refresh_bundle_now_rejects_an_unverified_bundle_and_keeps_the_lvb(make_rt):
    cloud = FakeCloud(None)
    rt = make_rt(cloud=cloud)
    v0 = rt.bundles.version
    bad = _newer(rt, u_3c4d={"role": "staff"})
    bad["users"]["u_3c4d"]["role"] = "faculty"  # edited after signing
    cloud.bundle = bad
    with pytest.raises(CloudUnavailableError) as ei:
        rt.refresh_bundle_now()
    assert "rejected" in str(ei.value)
    assert rt.bundles.version == v0 and rt.user_info("u_3c4d")["role"] == "student"


def test_refresh_bundle_now_without_cloud_forced_or_down(make_rt):
    rt = make_rt()
    with pytest.raises(CloudUnavailableError):
        rt.refresh_bundle_now()
    cloud = FakeCloud(None)
    rt = make_rt(cloud=cloud)
    cloud.bundle = rt.bundles.lvb
    rt.set_forced_mode("OFFLINE")
    with pytest.raises(CloudUnavailableError):
        rt.refresh_bundle_now()
    rt.set_forced_mode("AUTO")
    cloud.up = False
    with pytest.raises(CloudUnavailableError):
        rt.refresh_bundle_now()


def test_refresh_bundle_now_server_error_is_cloud_unavailable(make_rt):
    def boom(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "x"})

    rt = make_rt(cloud=boom)
    with pytest.raises(CloudUnavailableError):
        rt.refresh_bundle_now()


# ================================================================ demo clock
@pytest.mark.parametrize("bad", [3e11, -3e11, 1e20, math.inf, -math.inf, math.nan, 7 * 86400 + 1])
def test_demo_clock_offset_out_of_range_is_a_value_error_and_keeps_the_clock(make_rt, bad):
    rt = make_rt(DEMO_MODE="1")
    rt.set_demo_clock(offset_s=600)
    with pytest.raises(ValueError):
        rt.set_demo_clock(offset_s=bad)
    assert rt.set_demo_clock()["offset_s"] == 600
    rt.now()  # never raises afterwards
    assert rt.mode_status()["demo_clock"]["offset_s"] == 600


def test_demo_clock_bounds_are_inclusive(make_rt):
    rt = make_rt(DEMO_MODE="1")
    assert rt.set_demo_clock(offset_s=7 * 86400)["offset_s"] == 7 * 86400
    assert rt.set_demo_clock(offset_s=-7 * 86400)["offset_s"] == -7 * 86400


@pytest.mark.parametrize("bad", ["25:00", "12:61", "ab:cd", "9999-12-31T23:59:00", "2026-11-30T10:00:00"])
def test_demo_clock_bad_set_local_is_a_value_error(make_rt, bad):
    rt = make_rt(DEMO_MODE="1")
    with pytest.raises(ValueError):
        rt.set_demo_clock(set_local=bad)
    assert rt.set_demo_clock()["offset_s"] == 0


def test_demo_clock_status_warns_about_bundle_rollback(make_rt):
    """X13 stays: HH:MM = today, a time before issued_at - 300 s is a rollback (cache INVALID). The status now
    says so explicitly so the Control Panel can warn instead of failing silently."""
    rt = make_rt(DEMO_MODE="1")  # real now Sat 10:05 IST (RT_CLOCK re-anchored per test), bundle issued 10:00 IST
    issued = S.parse_ts(rt.bundles.lvb["issued_at"])
    assert issued.second == 0  # whole-minute stamp whatever ran before (the flaky 09:56 of the gate run)
    st = rt.set_demo_clock(set_local="07:50")
    assert st["date_local"] == "2026-11-14" and st["now_local"] == "07:50"
    assert st["bundle_rollback"] is True and st["cache_state"] == "INVALID"
    assert st["earliest_local"] == "09:55" and st["earliest_utc"] == "2026-11-14T04:25:00Z"
    assert st["earliest_date_local"] == "2026-11-14" and st["bundle_issued_at"] == "2026-11-14T04:30:00Z"
    st = rt.set_demo_clock(set_local="21:10")
    assert st["bundle_rollback"] is False and st["cache_state"] == "FRESH"
    st = rt.set_demo_clock(reset=True)
    assert st["active"] is False and st["bundle_rollback"] is False


DEMO_CLOCK_FIELDS = {"active", "now_local", "now_utc", "offset_s", "date_local", "bundle_issued_at", "earliest_utc",
                     "earliest_local", "earliest_date_local", "bundle_rollback", "cache_state"}


def test_demo_clock_status_shape_matches_the_contract(make_rt):
    """API v1.4 route 9: GET /v1/mode demo_clock (DEMO_MODE=1) == the POST /v1/admin/clock response shape."""
    rt = make_rt(DEMO_MODE="1")
    st = rt.mode_status()["demo_clock"]
    assert set(st) == DEMO_CLOCK_FIELDS
    again = rt.set_demo_clock()  # same view from both routes (now_utc carries the advancing seconds)
    assert {k: v for k, v in st.items() if k != "now_utc"} == {k: v for k, v in again.items() if k != "now_utc"}
    assert set(rt.set_demo_clock(set_local="21:30")) == DEMO_CLOCK_FIELDS


def test_demo_clock_absent_without_demo_mode_and_403_input(make_rt):
    rt = make_rt()
    assert rt.mode_status()["demo_clock"] is None
    with pytest.raises(PermissionError):
        rt.set_demo_clock(set_local="21:30")


def test_demo_clock_status_without_a_bundle_is_invalid_not_rollback(make_rt):
    rt = make_rt(DEMO_MODE="1")
    rt.bundles._lvb = None
    rt.bundles._last_check = float("inf")
    st = rt.set_demo_clock(set_local="21:30")
    assert set(st) == DEMO_CLOCK_FIELDS
    assert st["cache_state"] == "INVALID" and st["bundle_rollback"] is False
    assert st["earliest_local"] is None and st["earliest_date_local"] is None and st["bundle_issued_at"] is None


def test_rollback_time_steps_up_with_staff_override_never_denies(make_rt):
    """R-E: a demo time before issued_at - 300 s makes the bundle INVALID -> STEP_UP SCHEDULE_BUNDLE_INVALID with a
    staff override (not DENY); the override code then ALLOWs. The Control Panel wording must say STEP_UP."""
    rt = make_rt(DEMO_MODE="1")
    st = rt.set_demo_clock(set_local="07:50")
    assert st["bundle_rollback"] is True
    body = ok(rt.decide(attempt("att_rollback_su")))
    assert body["decision"] == "STEP_UP" and "SCHEDULE_BUNDLE_INVALID" in body["reason_codes"]
    assert "STAFF_OVERRIDE" in body["next_action"]["methods"]
    res = ok(rt.resolve_fallback("att_rollback_su", {"method": "STAFF_OVERRIDE", "code": "48213907",
                                                     "staff_id": "s_guard01"}))
    assert res["decision"] == "ALLOW"


# ================================================================ schedule: extra windows / zones_add
CFG = {"grace_minutes": 15, "grace_minutes_high_risk": 0}
ALL_DAYS = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]


def _bundle_with(user: str, *, role: str = "student", zones_add=(), extra=None) -> dict:
    b = json.loads(json.dumps(bundle_signed_at(ist("2026-11-14 10:00"))))
    b["users"][user].update({"role": role, "zones_add": list(zones_add), "extra_windows": extra or {}})
    return b


def _ev(b, user, zone, local):
    return S.evaluate_schedule(user, zone, ist(local), b, CFG)


def test_extra_all_day_window_00_00_to_23_59():
    b = _bundle_with("u_3c4d", zones_add=["LAB_BLOCK"],
                     extra={"LAB_BLOCK": [{"days": ALL_DAYS, "start": "00:00", "end": "23:59"}]})
    for t in ("2026-11-15 00:00", "2026-11-15 03:00", "2026-11-15 12:00", "2026-11-15 23:58"):
        assert _ev(b, "u_3c4d", "LAB_BLOCK", t) == S.IN_WINDOW, t
    # half-open [00:00, 23:59): the last minute is the grace band of the end edge (and of the next start)
    assert _ev(b, "u_3c4d", "LAB_BLOCK", "2026-11-15 23:59") == S.GRACE_WINDOW


def test_extra_all_day_window_00_00_to_24_00_covers_every_minute():
    b = _bundle_with("u_3c4d", zones_add=["LAB_BLOCK"],
                     extra={"LAB_BLOCK": [{"days": ALL_DAYS, "start": "00:00", "end": "24:00"}]})
    for t in ("2026-11-15 00:00", "2026-11-15 23:59", "2026-11-16 00:00"):
        assert _ev(b, "u_3c4d", "LAB_BLOCK", t) == S.IN_WINDOW, t


def test_extra_all_day_window_high_risk_last_minute_is_outside():
    b = _bundle_with("u_7a8b", role="staff", zones_add=["SERVER_ROOM"],
                     extra={"SERVER_ROOM": [{"days": ALL_DAYS, "start": "00:00", "end": "23:59"}]})
    assert _ev(b, "u_7a8b", "SERVER_ROOM", "2026-11-17 23:58") == S.IN_WINDOW
    assert _ev(b, "u_7a8b", "SERVER_ROOM", "2026-11-17 23:59") == S.OUTSIDE_WINDOW  # grace 0 high risk


def test_multiple_extra_windows_per_day():
    b = _bundle_with("u_3c4d", zones_add=["LAB_BLOCK"], extra={"LAB_BLOCK": [
        {"days": ["SUN"], "start": "06:00", "end": "08:00"},
        {"days": ["SUN"], "start": "12:00", "end": "13:00"},
        {"days": ["SUN"], "start": "20:00", "end": "21:00"}]})
    assert _ev(b, "u_3c4d", "LAB_BLOCK", "2026-11-15 07:00") == S.IN_WINDOW
    assert _ev(b, "u_3c4d", "LAB_BLOCK", "2026-11-15 12:30") == S.IN_WINDOW
    assert _ev(b, "u_3c4d", "LAB_BLOCK", "2026-11-15 20:59") == S.IN_WINDOW
    assert _ev(b, "u_3c4d", "LAB_BLOCK", "2026-11-15 10:00") == S.OUTSIDE_WINDOW
    assert _ev(b, "u_3c4d", "LAB_BLOCK", "2026-11-15 11:50") == S.GRACE_WINDOW
    assert _ev(b, "u_3c4d", "LAB_BLOCK", "2026-11-15 21:00") == S.GRACE_WINDOW  # end exclusive
    assert _ev(b, "u_3c4d", "LAB_BLOCK", "2026-11-16 07:00") != S.IN_WINDOW  # Monday: not listed


def test_extra_window_crossing_midnight_belongs_to_its_start_day():
    b = _bundle_with("u_3c4d", zones_add=["LAB_BLOCK"],
                     extra={"LAB_BLOCK": [{"days": ["SAT"], "start": "22:00", "end": "02:00"}]})
    assert _ev(b, "u_3c4d", "LAB_BLOCK", "2026-11-14 23:30") == S.IN_WINDOW  # Sat
    assert _ev(b, "u_3c4d", "LAB_BLOCK", "2026-11-15 00:00") == S.IN_WINDOW  # Sun, from Sat's window
    assert _ev(b, "u_3c4d", "LAB_BLOCK", "2026-11-15 01:59") == S.IN_WINDOW
    assert _ev(b, "u_3c4d", "LAB_BLOCK", "2026-11-15 02:00") == S.GRACE_WINDOW
    assert _ev(b, "u_3c4d", "LAB_BLOCK", "2026-11-15 23:30") == S.OUTSIDE_WINDOW  # Sun night: no window


def test_extra_window_extends_a_role_zone_beyond_role_hours():
    b = _bundle_with("u_3c4d")
    base = _ev(b, "u_3c4d", "MAIN_GATE", "2026-11-14 23:30")
    assert base == S.OUTSIDE_WINDOW
    b = _bundle_with("u_3c4d", extra={"MAIN_GATE": [{"days": ["SAT"], "start": "22:00", "end": "24:00"}]})
    assert _ev(b, "u_3c4d", "MAIN_GATE", "2026-11-14 23:30") == S.IN_WINDOW


def test_extra_windows_without_zone_permission_grant_nothing():
    b = _bundle_with("u_3c4d", extra={"SERVER_ROOM": [{"days": ALL_DAYS, "start": "00:00", "end": "24:00"}]})
    assert _ev(b, "u_3c4d", "SERVER_ROOM", "2026-11-14 10:00") == S.ZONE_NOT_PERMITTED


def test_zones_add_without_windows_is_outside():
    b = _bundle_with("u_3c4d", zones_add=["SERVER_ROOM"])
    assert _ev(b, "u_3c4d", "SERVER_ROOM", "2026-11-14 10:00") == S.OUTSIDE_WINDOW


def test_role_change_changes_windows():
    b = _bundle_with("u_3c4d", role="faculty")
    assert b["users"]["u_3c4d"]["role"] == "faculty"
    fac = [w for w in b["roles"]["faculty"]["windows"].get("MAIN_GATE", []) if S._applies_on(w, ist("2026-11-14 10:00").date())]
    assert _ev(b, "u_3c4d", "MAIN_GATE", "2026-11-14 10:00") == (S.IN_WINDOW if fac else S.OUTSIDE_WINDOW)


def test_day_windows_view():
    b = _bundle_with("u_3c4d", zones_add=["LAB_BLOCK"], extra={"LAB_BLOCK": [
        {"days": ["SUN"], "start": "20:00", "end": "21:00"}, {"days": ["SUN"], "start": "06:00", "end": "08:00"}]})
    d = ist("2026-11-15 10:00").date()
    assert S.day_windows(b, "u_3c4d", "LAB_BLOCK", d) == [{"start": "06:00", "end": "08:00"},
                                                           {"start": "20:00", "end": "21:00"}]
    assert S.day_windows(b, "u_3c4d", "SERVER_ROOM", d) == []  # zone not permitted
    assert S.day_windows(b, "u_nobody", "LAB_BLOCK", d) == []


def test_access_users_view_from_the_verified_bundle(make_rt):
    rt = make_rt()
    view = rt.access_users()
    assert view["bundle_version"] == rt.bundles.version and view["zone"] == "LIBRARY"
    assert set(view["roles"]) >= {"student", "faculty", "staff", "contractor", "visitor"}
    users = {u["user_id"]: u for u in view["users"]}
    p = users["u_3c4d"]
    assert p["role"] == "student" and p["display"] == "Priya N." and p["revoked"] is False
    assert p["totp_enrolled"] is True and p["card_enrolled"] is True and "card_id_hash" not in json.dumps(p)
    assert isinstance(p["windows_today"], list)
    assert users["u_c5d6"]["extra_windows"] == {"LIBRARY": [{"days": ["SUN"], "start": "07:00", "end": "21:00"}]}


def test_access_users_view_without_bundle_is_empty(make_rt, tmp_path):
    rt = make_rt()
    rt.bundles._lvb = None
    rt.bundles._last_check = float("inf")
    view = rt.access_users()
    assert view["users"] == [] and view["bundle_version"] is None


def test_totp_code_still_works_for_flagged_user(make_rt):
    rt = make_rt()
    body = ok(rt.decide(attempt("att_aa_totp", pad=[0.85, 0.82, 0.60, 0.50, 0.70])))
    from edge.policy.tests.builders import evidence_for
    body = ok(rt.resolve_challenge("att_aa_totp", evidence_for(rt.sessions["att_aa_totp"].challenge)))
    code = pyotp.TOTP(TOTP_SECRETS["u_3c4d"]).at(int(rt.real_now().timestamp()))
    body = ok(rt.resolve_fallback("att_aa_totp", FallbackSubmission(method="TOTP", code=code)))
    assert body["decision"] == "ALLOW"
