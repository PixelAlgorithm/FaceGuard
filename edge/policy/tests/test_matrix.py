"""DECISION_POLICY §9 decision matrix, row by row, on the pure combine() + BIO_FAIL rows via evaluate()."""

from __future__ import annotations

import itertools

import pytest

from edge.policy.engine import BIO_PASS, BIO_UNSURE, combine
from edge.policy.tests.builders import OB, THRESHOLDS_PATH, B
from edge.policy.thresholds import Thresholds

T = Thresholds.load(THRESHOLDS_PATH)
ON = ["TOTP", "CARD", "EMAIL_OTP", "STAFF_OVERRIDE"]
ONH = ["TOTP", "CARD", "EMAIL_OTP"]
OFF = ["TOTP", "CARD", "STAFF_OVERRIDE"]
OFFH = ["TOTP", "STAFF_OVERRIDE"]
STF = ["STAFF_OVERRIDE"]
OM, OFR, EXP = "OFFLINE_MODE", "OFFLINE_FALLBACK_REQUIRED", "SCHEDULE_EXPIRED_CACHE"
DENY_TYPES = ["OUTSIDE_WINDOW", "NO_ENTITLEMENT", "ZONE_NOT_PERMITTED", "HOLIDAY", "REVOKED"]
SCODE = {"GRACE_WINDOW": "SCHEDULE_GRACE_WINDOW", "OUTSIDE_WINDOW": "SCHEDULE_OUTSIDE_WINDOW",
         "NO_ENTITLEMENT": "SCHEDULE_NO_ENTITLEMENT", "ZONE_NOT_PERMITTED": "SCHEDULE_ZONE_NOT_PERMITTED",
         "HOLIDAY": "SCHEDULE_HOLIDAY", "REVOKED": "SCHEDULE_REVOKED"}
# BIO_UNSURE variants: (codes, causes, CHALLENGE present, MATCH cause present)
UNSURE = [
    (["LIVENESS_UNSURE"], {"LIVENESS"}),
    (["MASK_CUE_EDGE"], {"LIVENESS"}),
    (["MATCH_LOW"], {"MATCH"}),
    (["MATCH_AMBIGUOUS"], {"MATCH"}),
    (["LIVENESS_UNSURE", "MATCH_LOW"], {"LIVENESS", "MATCH"}),
]

MATRIX_ROWS_COVERED: set[str] = set()


def C(bio, codes, causes, sched, cache, risk, mode, t=T):
    tm = t.for_mode(mode)
    return combine(bio, list(codes), set(causes), sched, cache, risk, mode, tm)


def check(row, res, decision, codes, steps, methods):
    MATRIX_ROWS_COVERED.add(row)
    assert res.decision == decision, row
    assert set(res.codes) == set(codes), row
    assert list(res.steps) == steps, row
    assert (sorted(res.methods) if res.methods is not None else None) == (sorted(methods) if methods else None), row


# ---------------------------------------------------------------- §9.2 ONLINE
@pytest.mark.parametrize("risk", ["low", "medium"])
def test_N1(risk):
    check("N1", C(BIO_PASS, [], set(), "IN_WINDOW", "FRESH", risk, "ONLINE"), "ALLOW", ["ACCESS_OK"], [], None)


def test_N2():
    check("N2", C(BIO_PASS, [], set(), "IN_WINDOW", "FRESH", "high", "ONLINE"),
          "STEP_UP", ["SCHEDULE_HIGH_RISK_ZONE"], ["SECOND_FACTOR"], ONH)


@pytest.mark.parametrize("risk", ["low", "medium"])
def test_N3(risk):
    check("N3", C(BIO_PASS, [], set(), "GRACE_WINDOW", "FRESH", risk, "ONLINE"),
          "STEP_UP", ["SCHEDULE_GRACE_WINDOW"], ["SECOND_FACTOR"], ON)


@pytest.mark.parametrize("row,sched", list(zip(["N4", "N5", "N6", "N7", "N8"], DENY_TYPES)))
@pytest.mark.parametrize("risk", ["low", "medium", "high"])
def test_N4_to_N8(row, sched, risk):
    check(row, C(BIO_PASS, [], set(), sched, "FRESH", risk, "ONLINE"), "DENY", [SCODE[sched]], [], None)


@pytest.mark.parametrize("codes,causes", UNSURE)
@pytest.mark.parametrize("risk", ["low", "medium"])
def test_N9(codes, causes, risk):
    steps = (["CHALLENGE"] if "LIVENESS" in causes else []) + (["SECOND_FACTOR"] if "MATCH" in causes else [])
    check("N9", C(BIO_UNSURE, codes, causes, "IN_WINDOW", "FRESH", risk, "ONLINE"),
          "STEP_UP", codes, steps, ON if "SECOND_FACTOR" in steps else None)


@pytest.mark.parametrize("codes,causes", UNSURE)
def test_N10(codes, causes):
    steps = (["CHALLENGE"] if "LIVENESS" in causes else []) + ["SECOND_FACTOR"]
    check("N10", C(BIO_UNSURE, codes, causes, "IN_WINDOW", "FRESH", "high", "ONLINE"),
          "STEP_UP", codes + ["SCHEDULE_HIGH_RISK_ZONE"], steps, ONH)


@pytest.mark.parametrize("codes,causes", UNSURE)
@pytest.mark.parametrize("sched", ["GRACE_WINDOW"] + DENY_TYPES)
@pytest.mark.parametrize("risk", ["low", "medium", "high"])
def test_N11(codes, causes, sched, risk):
    check("N11", C(BIO_UNSURE, codes, causes, sched, "FRESH", risk, "ONLINE"),
          "DENY", codes + [SCODE[sched]], [], None)


def test_online_ignores_cache_state():
    for cache in ("FRESH", "EXPIRED", "INVALID"):
        res = C(BIO_PASS, [], set(), "IN_WINDOW", cache, "low", "ONLINE")
        assert res.decision == "ALLOW" and res.codes == ["ACCESS_OK"]


# ---------------------------------------------------------------- §9.3 OFFLINE, FRESH
@pytest.mark.parametrize("risk", ["low", "medium"])
def test_F1(risk):
    check("F1", C(BIO_PASS, [], set(), "IN_WINDOW", "FRESH", risk, "OFFLINE"), "ALLOW", ["ACCESS_OK", OM], [], None)


def test_F2():
    check("F2", C(BIO_PASS, [], set(), "IN_WINDOW", "FRESH", "high", "OFFLINE"),
          "STEP_UP", [OM, "OFFLINE_HIGH_RISK_ZONE", OFR], ["SECOND_FACTOR"], OFFH)


def test_F2_risk_above_auto_allow_max_is_treated_as_high():
    t = T.with_overrides({"offline": {"auto_allow_max_risk": "low"}})
    check("F2", C(BIO_PASS, [], set(), "IN_WINDOW", "FRESH", "medium", "OFFLINE", t),
          "STEP_UP", [OM, "OFFLINE_HIGH_RISK_ZONE", OFR], ["SECOND_FACTOR"], OFFH)


def test_F2_high_risk_never_auto_allows_offline_even_if_configured_permissive():
    t = T.with_overrides({"offline": {"auto_allow_max_risk": "high"},
                          "schedule": {"high_risk_requires_stepup_online": False}})
    res = C(BIO_PASS, [], set(), "IN_WINDOW", "FRESH", "high", "OFFLINE", t)
    assert res.decision == "STEP_UP" and "OFFLINE_HIGH_RISK_ZONE" in res.codes


@pytest.mark.parametrize("risk", ["low", "medium"])
def test_F3(risk):
    check("F3", C(BIO_PASS, [], set(), "GRACE_WINDOW", "FRESH", risk, "OFFLINE"),
          "STEP_UP", ["SCHEDULE_GRACE_WINDOW", OM, OFR], ["SECOND_FACTOR"], OFF)


@pytest.mark.parametrize("sched", DENY_TYPES)
@pytest.mark.parametrize("risk", ["low", "medium", "high"])
def test_F4(sched, risk):
    check("F4", C(BIO_PASS, [], set(), sched, "FRESH", risk, "OFFLINE"), "DENY", [SCODE[sched], OM], [], None)


@pytest.mark.parametrize("codes,causes", UNSURE)
@pytest.mark.parametrize("risk", ["low", "medium"])
def test_F5(codes, causes, risk):
    steps = (["CHALLENGE"] if "LIVENESS" in causes else []) + ["SECOND_FACTOR"]
    check("F5", C(BIO_UNSURE, codes, causes, "IN_WINDOW", "FRESH", risk, "OFFLINE"),
          "STEP_UP", codes + [OM, OFR], steps, OFF)


@pytest.mark.parametrize("codes,causes", UNSURE)
def test_F6(codes, causes):
    steps = (["CHALLENGE"] if "LIVENESS" in causes else []) + ["SECOND_FACTOR"]
    check("F6", C(BIO_UNSURE, codes, causes, "IN_WINDOW", "FRESH", "high", "OFFLINE"),
          "STEP_UP", codes + [OM, "OFFLINE_HIGH_RISK_ZONE", OFR], steps, OFFH)


@pytest.mark.parametrize("codes,causes", UNSURE)
@pytest.mark.parametrize("sched", ["GRACE_WINDOW"] + DENY_TYPES)
def test_F7(codes, causes, sched):
    check("F7", C(BIO_UNSURE, codes, causes, sched, "FRESH", "low", "OFFLINE"),
          "DENY", codes + [SCODE[sched], OM], [], None)


# ---------------------------------------------------------------- §9.4 OFFLINE, EXPIRED
@pytest.mark.parametrize("sched", ["IN_WINDOW", "GRACE_WINDOW"])
@pytest.mark.parametrize("risk", ["low", "medium", "high"])
def test_E1(sched, risk):
    codes = ([SCODE[sched]] if sched in SCODE else []) + [EXP, OM, OFR]
    if risk == "high":
        codes.append("OFFLINE_HIGH_RISK_ZONE")
    check("E1", C(BIO_PASS, [], set(), sched, "EXPIRED", risk, "OFFLINE"), "STEP_UP", codes, ["SECOND_FACTOR"], STF)


@pytest.mark.parametrize("sched", DENY_TYPES)
def test_E2(sched):
    check("E2", C(BIO_PASS, [], set(), sched, "EXPIRED", "low", "OFFLINE"), "DENY", [SCODE[sched], EXP, OM], [], None)


@pytest.mark.parametrize("codes,causes", UNSURE)
@pytest.mark.parametrize("risk", ["low", "high"])
def test_E3(codes, causes, risk):
    steps = (["CHALLENGE"] if "LIVENESS" in causes else []) + ["SECOND_FACTOR"]
    exp_codes = codes + [EXP, OM, OFR] + (["OFFLINE_HIGH_RISK_ZONE"] if risk == "high" else [])
    check("E3", C(BIO_UNSURE, codes, causes, "IN_WINDOW", "EXPIRED", risk, "OFFLINE"), "STEP_UP", exp_codes, steps,
          STF)


@pytest.mark.parametrize("codes,causes", UNSURE)
@pytest.mark.parametrize("sched", ["GRACE_WINDOW"] + DENY_TYPES)
def test_E4(codes, causes, sched):
    check("E4", C(BIO_UNSURE, codes, causes, sched, "EXPIRED", "low", "OFFLINE"),
          "DENY", codes + [SCODE[sched], EXP, OM], [], None)


# ---------------------------------------------------------------- §9.5 OFFLINE, INVALID
# I1b / I2b: LVB present but untrusted (clock rolled back) -> STEP_UP; I1a / I2a (no LVB) -> DENY, see below.
@pytest.mark.parametrize("risk", ["low", "medium", "high"])
def test_I1b(risk):
    check("I1b", C(BIO_PASS, [], set(), None, "INVALID", risk, "OFFLINE"),
          "STEP_UP", ["SCHEDULE_BUNDLE_INVALID", OM, OFR], ["SECOND_FACTOR"], STF)


@pytest.mark.parametrize("codes,causes", UNSURE)
def test_I2b(codes, causes):
    steps = (["CHALLENGE"] if "LIVENESS" in causes else []) + ["SECOND_FACTOR"]
    check("I2b", C(BIO_UNSURE, codes, causes, None, "INVALID", "low", "OFFLINE"),
          "STEP_UP", codes + ["SCHEDULE_BUNDLE_INVALID", OM, OFR], steps, STF)


def test_no_last_valid_bundle_denies_contact_desk_r6():
    """Round-2 R6 = matrix rows I1a (PASS) / I2a (UNSURE): no verified bundle -> DENY SCHEDULE_BUNDLE_INVALID."""
    MATRIX_ROWS_COVERED.add("I1a")
    MATRIX_ROWS_COVERED.add("I2a")
    for bio, codes, causes in [(BIO_PASS, [], set()), (BIO_UNSURE, ["LIVENESS_UNSURE"], {"LIVENESS"})]:
        for mode in ("ONLINE", "OFFLINE"):
            res = combine(bio, codes, causes, None, "INVALID", None, mode, T.for_mode(mode), lvb=False)
            assert res.decision == "DENY"
            assert set(res.codes) == set(codes) | {"SCHEDULE_BUNDLE_INVALID"} | ({OM} if mode == "OFFLINE" else set())


# ---------------------------------------------------------------- BIO_FAIL rows via evaluate()
PHONE = [(0.62, 1.0)] * 5


@pytest.mark.parametrize(
    "row,build,codes,nxt",
    [
        ("N12", lambda: _set(B(), device=PHONE), {"SPOOF_DEVICE_DETECTED"}, "NONE"),
        ("N13", lambda: _set(B(), cloud={"ok": True, "top1_user": None, "top1_similarity": None},
                             local=[("u_3c4d", 0.22, 0.1)] * 5), {"NOT_ENROLLED"}, "CONTACT_DESK"),
        ("F8", lambda: _set(OB(), device=PHONE), {"SPOOF_DEVICE_DETECTED", OM}, "NONE"),
        ("F8", lambda: _set(OB(), local=[("u_3c4d", 0.2, 0.1)] * 5), {"NOT_ENROLLED", OM}, "CONTACT_DESK"),
        ("E5", lambda: _set(OB().fixed().who("u_3c4d", "MAIN", "2026-11-14T21:00"), device=PHONE),
         {"SPOOF_DEVICE_DETECTED", OM}, "NONE"),
        ("E5", lambda: _set(OB().fixed().who("u_3c4d", "MAIN", "2026-11-14T21:00"),
                            local=[("u_3c4d", 0.2, 0.1)] * 5), {"NOT_ENROLLED", OM}, "CONTACT_DESK"),
        ("I3", lambda: _set(OB(), signature_valid=False, pad=[0.1] * 5), {"SPOOF_PASSIVE", OM}, "NONE"),
    ],
)
def test_bio_fail_rows(row, build, codes, nxt):
    MATRIX_ROWS_COVERED.add(row)
    res = build().evaluate()
    assert res.decision == "DENY"
    assert set(res.reason_codes) == codes
    assert res.next_action.type == nxt
    assert res.schedule_result is None


def _set(scn, **kw):
    for k, v in kw.items():
        setattr(scn, k, v)
    return scn


# ---------------------------------------------------------------- exhaustive sweep (no row missing)
def test_combine_total_over_input_space():
    """Every (bio, sched, cache, risk, mode) combination yields exactly one valid outcome, no exception."""
    scheds = [None, "IN_WINDOW", "GRACE_WINDOW"] + DENY_TYPES
    for bio, (codes, causes), sched, cache, risk, mode in itertools.product(
        [BIO_PASS, BIO_UNSURE], UNSURE, scheds, ["FRESH", "EXPIRED", "INVALID"], ["low", "medium", "high"],
        ["ONLINE", "OFFLINE"],
    ):
        if bio == BIO_PASS:
            codes, causes = [], set()
        if sched is None and not (mode == "OFFLINE" and cache == "INVALID"):
            continue  # schedule is only skipped for an untrusted bundle
        res = C(bio, codes, causes, sched, cache, risk, mode)
        assert res.decision in {"ALLOW", "STEP_UP", "DENY"}
        assert res.codes
        if res.decision == "ALLOW":
            assert bio == BIO_PASS and sched == "IN_WINDOW"
            assert mode == "ONLINE" or (cache == "FRESH" and risk != "high")
        if res.decision == "STEP_UP":
            assert res.steps
        if mode == "OFFLINE":
            assert OM in res.codes
