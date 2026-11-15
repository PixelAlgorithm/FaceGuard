"""docs/POLICY_TEST_CASES.md rows that had no test reference (policy-engine triage 2026-11-14).

Covered here: Q25, L06b, L26, L27, LA01-LA11, C11, C13, C14, S50, S51, S52 (+ the holiday "ALL" path),
O48, O49, RL17, RL19, Y12.
Not here, by design: Q23 / RL18 are withdrawn; Q24, Y03, Y05, Y06, Y08, Y09, Y10 are cloud-side (cloud/tests);
C12 and RC19 are HTTP-layer contracts (edge/tests: INVALID_STATE / 422 / 401 / 403); X15 is a manual rehearsal;
RC18 (shipped YAML random_rate 0.15 online / 0.30 offline, docs/POLICY_TEST_CASES.md §3a) is implemented as
test_cases.test_shipped_yaml_random_challenge_restored, the test name the doc row cites.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta

import pytest

from edge.policy.liveness import liveness_fusion
from edge.policy.ratelimit import counts_toward_rate_limit
from edge.policy.runtime import AttemptClosedError, AttemptNotFoundError
from edge.policy.schedule import evaluate_schedule
from edge.policy.stepup import drop_method
from edge.policy.tests.builders import (
    L03_PAD,
    OB,
    PHONE,
    SIGNED_BUNDLE,
    B,
    base_thresholds,
    evidence_for,
    ist,
    load_example_bundle,
    sign_fixture_bundle,
)
from edge.policy.tests.test_cases import ON, tampered_now
from edge.policy.tests.test_ratelimit import Kiosk
from edge.policy.tests.test_runtime import FakeCloud, attempt, bring_online, make_rt, ok  # noqa: F401 (fixture)
from edge.policy.tests.test_stepup import Flow
from edge.policy.thresholds import Thresholds

FLASH_ADV = {"liveness": {"flash": {"enforce": False}}}
WEAK = 1.5  # below liveness.flash.min_amplitude


def flash(**kw):
    return {**B().flash, **kw}


def shipped(scn):
    scn.cfg_patch = {}  # config/thresholds.yaml exactly as shipped (no fixture pins)
    return scn


# ---------------------------------------------------------------- Q25 shipped YAML: unknown label alone passes
@pytest.mark.parametrize("label,decision,codes", [
    ("MacBook Pro Camera", "ALLOW", {"ACCESS_OK"}),
    ("", "ALLOW", {"ACCESS_OK"}),
    ("OBS Virtual Camera", "DENY", {"INJECTION_VIRTUAL_CAMERA"}),
])
def test_Q25_shipped_yaml_camera_labels(label, decision, codes):
    d = shipped(B()).set(label=label).evaluate()
    assert d.decision == decision and set(d.reason_codes) == codes


# ---------------------------------------------------------------- L06b, L26, L27
def test_L06b_device_box_without_containment_is_unsure():
    d = B().set(device=[(0.62, 0.5)] * 5).evaluate()
    assert d.decision == "STEP_UP" and set(d.reason_codes) == {"LIVENESS_UNSURE"}
    assert list(d.next_action.steps) == ["CHALLENGE"]


@pytest.mark.parametrize("row,delta", [("L26", {"moire": [0.45] * 5}), ("L27", {"device": [(0.30, 0.9)] * 5})])
def test_L26_L27_ambient_exception_needs_low_moire_and_clean_device(row, delta):
    assert B().set(flash=flash(amplitude=WEAK, r=0.10)).evaluate().decision == "ALLOW"  # L10 baseline
    d = B().set(flash=flash(amplitude=WEAK, r=0.10), **delta).evaluate()
    assert d.decision == "STEP_UP" and set(d.reason_codes) == {"LIVENESS_UNSURE"}, row
    assert list(d.next_action.steps) == ["CHALLENGE"]


# ---------------------------------------------------------------- LA01-LA11 flash advisory (§3 C3)
LA = [
    ("LA01", lambda: B().cfg(FLASH_ADV).set(flash=flash(r=0.12)), "ALLOW", {"ACCESS_OK"}, "ADVISORY_FAIL"),
    ("LA02", lambda: B().cfg(FLASH_ADV).set(flash=flash(lag_frames=20.0)), "ALLOW", {"ACCESS_OK"}, "ADVISORY_FAIL"),
    ("LA02", lambda: B().cfg(FLASH_ADV).set(flash=flash(order_ok=False)), "ALLOW", {"ACCESS_OK"}, "ADVISORY_FAIL"),
    ("LA03", lambda: B().cfg(FLASH_ADV).set(flash=flash(r=0.50)), "ALLOW", {"ACCESS_OK"}, "ADVISORY_UNSURE"),
    ("LA04", lambda: B().cfg(FLASH_ADV).set(flash=flash(amplitude=WEAK, r=0.10)), "ALLOW", {"ACCESS_OK"},
     "ADVISORY_WEAK"),
    ("LA05", lambda: OB().cfg(FLASH_ADV).set(flash=flash(amplitude=WEAK)), "ALLOW", {"ACCESS_OK", "OFFLINE_MODE"},
     "ADVISORY_WEAK"),
    ("LA06", lambda: B().cfg(FLASH_ADV).set(flash=None), "ALLOW", {"ACCESS_OK"}, "ADVISORY_UNSURE"),
    ("LA07", lambda: B().cfg(FLASH_ADV).set(flash_enabled=False), "STEP_UP", {"LIVENESS_UNSURE"}, "NOT_AVAILABLE"),
    ("LA07", lambda: B().cfg({"liveness": {"flash": {"enforce": False, "enabled": False}}}), "STEP_UP",
     {"LIVENESS_UNSURE"}, "NOT_AVAILABLE"),
    ("LA08", lambda: B().cfg(FLASH_ADV).set(moire=[0.80] * 5, flash=flash(r=0.12)), "STEP_UP", {"LIVENESS_UNSURE"},
     "ADVISORY_FAIL"),
    ("LA09", lambda: B().cfg(FLASH_ADV).set(moire=[0.80] * 5, pad=list(L03_PAD)), "DENY", {"SPOOF_MOIRE"}, None),
    ("LA10", lambda: B().cfg(FLASH_ADV).set(device=PHONE, flash=flash(r=0.12)), "DENY", {"SPOOF_DEVICE_DETECTED"},
     None),
]


@pytest.mark.parametrize("row,build,decision,codes,flash_sig", LA, ids=[f"{c[0]}-{i}" for i, c in enumerate(LA)])
def test_LA_flash_advisory_rows(row, build, decision, codes, flash_sig):
    d = build().evaluate()
    assert d.decision == decision and set(d.reason_codes) == codes, (row, d.reason_codes)
    if decision == "STEP_UP":
        assert list(d.next_action.steps) == ["CHALLENGE"]
    if flash_sig:
        assert d.to_response()["scores"]["signals"]["flash"] == flash_sig


def test_LA11_missing_enforce_key_means_enforce():
    raw = base_thresholds().raw()
    raw["liveness"]["flash"].pop("enforce", None)
    s = B().set(flash=flash(r=0.12)).signals()
    res = liveness_fusion(s.frames, s, "PASS", Thresholds(copy.deepcopy(raw)), "ONLINE")
    assert res.hard_codes == ("SPOOF_FLASH_MISMATCH",)


# ---------------------------------------------------------------- C11, C13, C14 (runtime side of §9.6)
def test_C11_unknown_attempt_is_not_found_and_touches_nothing(make_rt):  # noqa: F811 (pytest fixture imported from test_runtime)
    rt = make_rt()
    before = rt.limiter.state()
    with pytest.raises(AttemptNotFoundError):
        rt.resolve_fallback("att_UNKNOWN", {"method": "TOTP", "code": "123456"})
    assert rt.store_view()["records"] == [] and rt.limiter.state() == before


def test_C13_closed_attempt_rejects_further_steps(make_rt):  # noqa: F811 (pytest fixture imported from test_runtime)
    rt = make_rt()
    assert ok(rt.decide(attempt("att_c13")))["decision"] == "ALLOW"
    with pytest.raises(AttemptClosedError):
        rt.resolve_fallback("att_c13", {"method": "TOTP", "code": "123456"})
    assert [r["attempt_id"] for r in rt.store_view()["records"]] == ["att_c13"]


def test_C14_session_ttl_ignores_the_demo_clock(make_rt):  # noqa: F811 (pytest fixture imported from test_runtime)
    cloud = FakeCloud(None)
    rt = make_rt(cloud=cloud, DEMO_MODE="1")
    cloud.bundle = rt.bundles.lvb
    bring_online(rt)
    body = ok(rt.decide(attempt("att_c14", pad=list(L03_PAD))))
    assert body["decision"] == "STEP_UP" and body["next_action"]["steps"] == ["CHALLENGE"]
    ch = rt.sessions["att_c14"].challenge
    rt.set_demo_clock(offset_s=3 * 3600)  # +3 h wall (demo) clock; the TTL is real elapsed time
    body = ok(rt.resolve_challenge("att_c14", evidence_for(ch)))
    assert body["decision"] == "ALLOW" and body["reason_codes"] == ["ACCESS_OK"]


# ---------------------------------------------------------------- S50-S52 + holiday ALL
def test_S50_email_otp_not_offered_when_ses_is_denied():
    d = B().who("u_3c4d", "LIB", "2026-11-14T07:50").cfg({"fallback": {"email_otp": {"enabled": False}}}).evaluate()
    assert d.decision == "STEP_UP" and set(d.reason_codes) == {"SCHEDULE_GRACE_WINDOW"}
    assert list(d.next_action.steps) == ["SECOND_FACTOR"]
    assert set(d.next_action.methods) == {"TOTP", "CARD", "STAFF_OVERRIDE"}


def test_S51_grace_does_not_cross_midnight():
    d = B().who("u_3c4d", "LIB", "2026-11-19T00:05").evaluate()
    assert d.decision == "DENY" and set(d.reason_codes) == {"SCHEDULE_OUTSIDE_WINDOW"}
    assert d.next_action.type == "NONE"


def test_S52_start_grace_of_a_window_ending_at_midnight():
    d = B().who("u_3c4d", "LIB", "2026-11-19T05:50").evaluate()
    assert d.decision == "STEP_UP" and set(d.reason_codes) == {"SCHEDULE_GRACE_WINDOW"}
    assert list(d.next_action.steps) == ["SECOND_FACTOR"] and set(d.next_action.methods) == ON


def test_holiday_closing_ALL_zones_exempts_listed_roles_only():
    b = copy.deepcopy(SIGNED_BUNDLE)
    b["holidays"] = [*b.get("holidays", []), {"date": "2026-11-14", "name": "test closure", "closed_zones": "ALL",
                                               "exempt_roles": ["staff"]}]
    cfg = {"grace_minutes": 15, "grace_minutes_high_risk": 0}
    assert evaluate_schedule("u_3c4d", "LIBRARY", ist("2026-11-14T10:05"), b, cfg) == "HOLIDAY"  # student
    assert evaluate_schedule("u_3c4d", "LAB_BLOCK", ist("2026-11-14T10:05"), b, cfg) == "HOLIDAY"
    assert evaluate_schedule("u_7a8b", "SERVER_ROOM", ist("2026-11-14T10:00"), b, cfg) != "HOLIDAY"  # staff


# ---------------------------------------------------------------- O48, O49
def _expired_bundle(now: datetime, *, codes_until: datetime | None = None) -> dict:
    b = load_example_bundle()
    b["issued_at"] = (now - timedelta(hours=12, minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    b["expires_at"] = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    until = codes_until or (now - timedelta(minutes=5) + timedelta(hours=24))
    for c in b["override_codes"]["codes"]:
        c["valid_until"] = until.strftime("%Y-%m-%dT%H:%M:%SZ")
    return sign_fixture_bundle({k: v for k, v in b.items() if k != "signature"})


def test_O48_expired_bundle_override_codes_stay_valid_until_valid_until():
    scn = OB().who("u_3c4d", "MAIN", "2026-11-14T10:05")
    now = scn.eff_now.astimezone(UTC)
    f = Flow(scn.set(bundle=_expired_bundle(now)))
    assert f.first.decision == "STEP_UP"
    assert set(f.first.reason_codes) == {"SCHEDULE_EXPIRED_CACHE", "OFFLINE_MODE", "OFFLINE_FALLBACK_REQUIRED"}
    assert list(f.first.next_action.methods) == ["STAFF_OVERRIDE"]
    d = f.fallback(method="STAFF_OVERRIDE", code="75530182")
    assert d.decision == "ALLOW" and set(d.reason_codes) == {"ACCESS_OK", "FALLBACK_OK", "OFFLINE_MODE"}
    late = Flow(OB().who("u_3c4d", "MAIN", "2026-11-14T10:05").set(bundle=_expired_bundle(now, codes_until=now)))
    d = late.fallback(method="STAFF_OVERRIDE", code="75530182")  # now + 5 s >= valid_until
    assert d.decision == "STEP_UP" and "FALLBACK_FAILED" in d.reason_codes and d.next_action.attempts_left == 0


def test_O49_revoked_user_excluded_from_the_template_cache_is_not_enrolled():
    d = OB().who("u_a3b4", "MAIN", "2026-11-14T09:00").set(local=[("u_1a2b", 0.25, 0.20)] * 5).evaluate()
    assert d.decision == "DENY" and set(d.reason_codes) == {"NOT_ENROLLED", "OFFLINE_MODE"}
    assert d.next_action.type == "CONTACT_DESK" and d.schedule_result is None


# ---------------------------------------------------------------- RL17, RL19
def test_RL17_protocol_errors_and_method_reissues_never_count(make_rt):  # noqa: F811 (pytest fixture imported from test_runtime)
    rt = make_rt()
    for i in range(5):  # 5 x C11 at the runtime: no decision, no limiter event
        with pytest.raises(AttemptNotFoundError):
            rt.resolve_fallback(f"att_unknown_{i}", {"method": "TOTP", "code": "123456"})
    k = Kiosk()
    for i in range(5):  # 5 x S48: EMAIL_OTP dropped while the cloud verify is down (R11 re-issue)
        f = Flow(B().who("u_3c4d", "LIB", "2026-11-14T07:50").set(attempt_id=f"att_s48_{i}"))
        _s, d = drop_method(f.session, "EMAIL_OTP", f.T, f.t + timedelta(seconds=5))
        assert d.decision == "STEP_UP" and not counts_toward_rate_limit(d.decision, d.reason_codes, f.T.rate_limit)
        k.record(d, 10.0 * i + 50)
    assert k.attempt(B(), 100.0).decision == "ALLOW" and k.alerts == 0
    assert ok(rt.decide(attempt("att_rl17")))["decision"] == "ALLOW"


def test_RL19_no_lvb_denies_are_never_counted():
    k = Kiosk()
    for t in (0.0, 10.0, 20.0, 30.0, 40.0):
        d = k.attempt(OB().set(bundle=tampered_now(), pad=list(L03_PAD)), t)  # O42-style, schedule code only
        assert d.decision == "DENY" and "SCHEDULE_BUNDLE_INVALID" in d.reason_codes
    assert k.attempt(B(), 41.0).decision == "ALLOW" and k.alerts == 0
