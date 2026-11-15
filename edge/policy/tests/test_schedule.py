"""SC1 schedule evaluator (pure, stdlib + zoneinfo) and bundle cache state (§5)."""

import copy
from datetime import timedelta

import pytest

from edge.policy.schedule import (
    cache_state,
    entitled_user_ids,
    evaluate_schedule,
    kiosk_zone,
    zone_risk,
)
from edge.policy.tests.builders import SIGNED_BUNDLE, ist, utc

CFG = {"grace_minutes": 15, "grace_minutes_high_risk": 0}
CACHE_CFG = {"bundle_max_staleness_hours": 12, "clock_rollback_tolerance_s": 300}


def sched(user, zone, local):
    return evaluate_schedule(user, zone, ist(local), SIGNED_BUNDLE, CFG)


# Schedule result for every SC1 row of POLICY_TEST_CASES §5 (decision mapping tested in test_cases.py).
@pytest.mark.parametrize(
    "case,user,zone,local,expected",
    [
        ("S01", "u_3c4d", "LIBRARY", "2026-11-14T07:50", "GRACE_WINDOW"),
        ("S04", "u_3c4d", "LIBRARY", "2026-11-14T07:40", "OUTSIDE_WINDOW"),
        ("S05", "u_3c4d", "LAB_BLOCK", "2026-11-14T20:30", "IN_WINDOW"),
        ("S06", "u_3c4d", "LAB_BLOCK", "2026-11-15T11:00", "OUTSIDE_WINDOW"),
        ("S07", "u_3c4d", "LAB_BLOCK", "2026-11-16T10:00", "OUTSIDE_WINDOW"),
        ("S08", "u_3c4d", "LIBRARY", "2026-11-18T23:30", "IN_WINDOW"),
        ("S09", "u_3c4d", "HOSTEL", "2026-11-14T21:00", "ZONE_NOT_PERMITTED"),
        ("S10", "u_1a2b", "HOSTEL", "2026-11-14T23:10", "GRACE_WINDOW"),
        ("S11", "u_1a2b", "HOSTEL", "2026-11-14T23:20", "OUTSIDE_WINDOW"),
        ("S12", "u_1a2b", "HOSTEL", "2026-11-15T00:30", "OUTSIDE_WINDOW"),
        ("S13", "u_7a8b", "SERVER_ROOM", "2026-11-14T10:00", "IN_WINDOW"),
        ("S15", "u_7a8b", "SERVER_ROOM", "2026-11-14T08:55", "OUTSIDE_WINDOW"),
        ("S16", "u_5e6f", "SERVER_ROOM", "2026-11-16T11:00", "ZONE_NOT_PERMITTED"),
        ("S17", "u_a3b4", "MAIN_GATE", "2026-11-14T09:00", "REVOKED"),
        ("S18", "u_e1f2", "LAB_BLOCK", "2026-11-14T15:00", "IN_WINDOW"),
        ("S19", "u_e1f2", "LAB_BLOCK", "2026-11-14T18:10", "NO_ENTITLEMENT"),
        ("S20", "u_e1f2", "LIBRARY", "2026-11-14T11:00", "ZONE_NOT_PERMITTED"),
        ("S21", "u_9c0d", "LAB_BLOCK", "2026-11-20T10:00", "HOLIDAY"),
        ("S22", "u_7a8b", "LAB_BLOCK", "2026-11-20T10:00", "IN_WINDOW"),
        ("S23", "u_9c0d", "LAB_BLOCK", "2026-12-01T10:00", "NO_ENTITLEMENT"),
        ("S24", "u_c5d6", "LIBRARY", "2026-11-15T08:00", "IN_WINDOW"),
        ("S25", "u_7a8b", "LIBRARY", "2026-11-15T08:00", "OUTSIDE_WINDOW"),
        ("S26", "u_c5d6", "LAB_BLOCK", "2026-11-16T10:00", "ZONE_NOT_PERMITTED"),
        ("S27", "u_zz99", "LIBRARY", "2026-11-14T10:05", "NO_ENTITLEMENT"),
        ("SC1.6#12b", "u_e1f2", "LAB_BLOCK", "2026-11-15T10:00", "NO_ENTITLEMENT"),
        ("O02", "u_3c4d", "LAB_BLOCK", "2026-11-14T11:00", "IN_WINDOW"),
        ("O19", "u_3c4d", "MAIN_GATE", "2026-11-14T21:00", "IN_WINDOW"),
        ("O23", "u_7a8b", "SERVER_ROOM", "2026-11-14T20:45", "IN_WINDOW"),
    ],
)
def test_schedule_rows(case, user, zone, local, expected):
    assert sched(user, zone, local) == expected


@pytest.mark.parametrize(
    "local,expected",
    [
        ("2026-11-14T07:44:59", "OUTSIDE_WINDOW"),
        ("2026-11-14T07:45", "GRACE_WINDOW"),  # start - 15 min is inside grace
        ("2026-11-14T07:59:59", "GRACE_WINDOW"),
        ("2026-11-14T08:00", "IN_WINDOW"),  # start inclusive
        ("2026-11-14T20:59:59", "IN_WINDOW"),
        ("2026-11-14T21:00", "GRACE_WINDOW"),  # end exclusive -> after-end grace
        ("2026-11-14T21:14:59", "GRACE_WINDOW"),
        ("2026-11-14T21:15", "OUTSIDE_WINDOW"),
    ],
)
def test_window_edges_library_saturday(local, expected):
    assert sched("u_3c4d", "LIBRARY", local) == expected


def test_window_ending_24_00_contains_last_minute():
    assert sched("u_3c4d", "LIBRARY", "2026-11-18T23:59:59") == "IN_WINDOW"


def test_t0_in_utc_is_converted_to_ist():
    t0 = utc("2026-11-14T02:20:00")  # = 07:50 IST
    assert evaluate_schedule("u_3c4d", "LIBRARY", t0, SIGNED_BUNDLE, CFG) == "GRACE_WINDOW"


def _with_window(bundle, user, zone, days, start, end):
    b = copy.deepcopy(bundle)
    b["users"][user]["extra_windows"] = {zone: [{"days": days, "start": start, "end": end}]}
    return b


def test_cross_midnight_window_belongs_to_start_day():
    b = _with_window(SIGNED_BUNDLE, "u_1a2b", "HOSTEL", ["SAT"], "22:00", "02:00")
    t_sun_0130 = ist("2026-11-15T01:30")
    t_sun_0210 = ist("2026-11-15T02:10")
    t_sun_0220 = ist("2026-11-15T02:20")
    assert evaluate_schedule("u_1a2b", "HOSTEL", t_sun_0130, b, CFG) == "IN_WINDOW"
    assert evaluate_schedule("u_1a2b", "HOSTEL", t_sun_0210, b, CFG) == "GRACE_WINDOW"
    assert evaluate_schedule("u_1a2b", "HOSTEL", t_sun_0220, b, CFG) == "OUTSIDE_WINDOW"
    # Friday-night->Saturday is not covered: the window belongs to SAT only.
    assert evaluate_schedule("u_1a2b", "HOSTEL", ist("2026-11-14T01:30"), b, CFG) == "OUTSIDE_WINDOW"


def test_no_grace_for_high_risk_zone_even_after_end():
    assert sched("u_7a8b", "SERVER_ROOM", "2026-11-14T21:05") == "OUTSIDE_WINDOW"


def test_grace_zero_config_disables_grace():
    t = ist("2026-11-14T07:50")
    assert evaluate_schedule("u_3c4d", "LIBRARY", t, SIGNED_BUNDLE, dict(CFG, grace_minutes=0)) == "OUTSIDE_WINDOW"


def test_revocations_list_entry_revokes_even_if_user_flag_false():
    b = copy.deepcopy(SIGNED_BUNDLE)
    b["revocations"].append({"user_id": "u_3c4d", "revoked_at": "2026-11-14T03:30:00Z", "reason": "ADMIN"})
    assert evaluate_schedule("u_3c4d", "LIBRARY", utc("2026-11-14T04:35:00"), b, CFG) == "REVOKED"


def test_revocation_effective_after_t0_is_not_applied_retroactively():
    """Server re-evaluation at ts_utc (SC2.6 rule 3 / Y04): revocation after the attempt != REVOKED."""
    b = copy.deepcopy(SIGNED_BUNDLE)
    b["users"]["u_3c4d"]["revoked"] = True
    b["users"]["u_3c4d"]["revoked_at"] = "2026-11-14T05:30:00Z"
    b["revocations"].append({"user_id": "u_3c4d", "revoked_at": "2026-11-14T05:30:00Z", "reason": "ADMIN"})
    assert evaluate_schedule("u_3c4d", "LIBRARY", utc("2026-11-14T04:35:00"), b, CFG) == "IN_WINDOW"
    assert evaluate_schedule("u_3c4d", "LIBRARY", utc("2026-11-14T05:30:00"), b, CFG) == "REVOKED"


def test_revoked_flag_without_timestamp_revokes():
    b = copy.deepcopy(SIGNED_BUNDLE)
    b["users"]["u_3c4d"]["revoked"] = True
    assert evaluate_schedule("u_3c4d", "LIBRARY", ist("2026-11-14T10:05"), b, CFG) == "REVOKED"


def test_revocation_precedes_validity_and_zone_checks():
    b = copy.deepcopy(SIGNED_BUNDLE)
    b["users"]["u_9c0d"]["revoked"] = True
    assert evaluate_schedule("u_9c0d", "SERVER_ROOM", ist("2026-12-05T10:00"), b, CFG) == "REVOKED"


def test_holiday_override_exception_reopens_zone():
    b = copy.deepcopy(SIGNED_BUNDLE)
    b["exceptions"].append(
        {"id": "EXC-T", "name": "t", "date_from": "2026-11-20", "date_to": "2026-11-20",
         "roles": ["contractor"], "zones": ["LAB_BLOCK"], "mode": "add",
         "windows": [{"start": "09:00", "end": "12:00"}], "overrides_holiday": True}
    )
    assert evaluate_schedule("u_9c0d", "LAB_BLOCK", ist("2026-11-20T10:00"), b, CFG) == "IN_WINDOW"


def test_explicit_grant_zone_requires_zones_add_not_role_membership():
    b = copy.deepcopy(SIGNED_BUNDLE)
    b["roles"]["staff"]["zones"].append("SERVER_ROOM")  # even if the role lists the zone ...
    # ... Neha (staff, no zones_add grant) is not permitted; Rahul (zones_add) is.
    assert evaluate_schedule("u_c5d6", "SERVER_ROOM", ist("2026-11-16T10:00"), b, CFG) == "ZONE_NOT_PERMITTED"
    assert evaluate_schedule("u_7a8b", "SERVER_ROOM", ist("2026-11-16T10:00"), b, CFG) == "IN_WINDOW"


def test_visitor_pass_windows_replace_role_windows():
    b = copy.deepcopy(SIGNED_BUNDLE)
    b["visitor_passes"][0]["windows"] = [{"days": ["SAT"], "start": "14:00", "end": "16:00"}]
    assert evaluate_schedule("u_e1f2", "LAB_BLOCK", ist("2026-11-14T15:00"), b, CFG) == "IN_WINDOW"
    assert evaluate_schedule("u_e1f2", "LAB_BLOCK", ist("2026-11-14T11:00"), b, CFG) == "OUTSIDE_WINDOW"


def test_unknown_zone_raises():
    with pytest.raises(KeyError):
        sched("u_3c4d", "NO_SUCH_ZONE", "2026-11-14T10:05")


def test_naive_t0_rejected():
    from datetime import datetime

    with pytest.raises(ValueError):
        evaluate_schedule("u_3c4d", "LIBRARY", datetime(2026, 11, 14, 10, 5), SIGNED_BUNDLE, CFG)


def test_helpers_zone_and_risk():
    assert kiosk_zone(SIGNED_BUNDLE, "KIOSK_SRV_01") == "SERVER_ROOM"
    assert kiosk_zone(SIGNED_BUNDLE, "KIOSK_NOPE") is None
    assert zone_risk(SIGNED_BUNDLE, "SERVER_ROOM") == "high"
    assert zone_risk(SIGNED_BUNDLE, "LAB_BLOCK") == "medium"


def test_entitled_users_for_zone():
    at = ist("2026-11-14T10:05")
    assert entitled_user_ids(SIGNED_BUNDLE, "SERVER_ROOM", at) == {"u_7a8b"}
    lib = entitled_user_ids(SIGNED_BUNDLE, "LIBRARY", at)
    assert {"u_3c4d", "u_1a2b", "u_5e6f", "u_7a8b", "u_c5d6"} <= lib
    assert "u_a3b4" not in lib  # revoked
    assert "u_e1f2" not in lib  # visitor pass excludes LIBRARY
    assert "u_9c0d" not in lib  # contractor role has no LIBRARY


# ---------------------------------------------------------------- cache state (§5)
@pytest.mark.parametrize(
    "now,valid,expected",
    [
        ("2026-11-14T04:35:00", True, "FRESH"),
        ("2026-11-14T14:30:00", True, "FRESH"),  # == effective expiry (fixed stamps 02:30Z / 14:30Z)
        ("2026-11-14T14:30:01", True, "EXPIRED"),
        ("2026-11-14T15:30:00", True, "EXPIRED"),  # O19
        ("2026-11-14T04:35:00", False, "INVALID"),  # O24/O25
        ("2026-11-13T20:00:00", True, "INVALID"),  # O26 clock rollback
        ("2026-11-14T02:25:00", True, "FRESH"),  # exactly issued_at - 300 s is tolerated
        ("2026-11-14T02:24:59", True, "INVALID"),
        ("2026-11-14T02:20:00", True, "INVALID"),  # 07:50 IST with fixed stamps: rollback (X13 trap)
    ],
)
def test_cache_state(now, valid, expected):
    assert cache_state(SIGNED_BUNDLE, valid, utc(now), CACHE_CFG) == expected


def test_cache_state_missing_bundle_is_invalid():
    assert cache_state(None, True, utc("2026-11-14T04:35:00"), CACHE_CFG) == "INVALID"


def test_cache_effective_expiry_is_min_of_expires_at_and_issued_plus_12h():
    b = copy.deepcopy(SIGNED_BUNDLE)
    b["expires_at"] = "2026-11-15T23:00:00Z"  # longer than issued_at + 12 h
    assert cache_state(b, True, utc("2026-11-14T14:30:00"), CACHE_CFG) == "FRESH"
    assert cache_state(b, True, utc("2026-11-14T14:30:00") + timedelta(seconds=1), CACHE_CFG) == "EXPIRED"


def test_cache_state_unparsable_timestamps_invalid():
    b = copy.deepcopy(SIGNED_BUNDLE)
    b["issued_at"] = "yesterday"
    assert cache_state(b, True, utc("2026-11-14T04:35:00"), CACHE_CFG) == "INVALID"
