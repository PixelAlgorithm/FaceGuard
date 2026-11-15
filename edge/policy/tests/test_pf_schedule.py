"""policy-fixes: schedule fail-opens F02 (holiday vs midnight-crossing window), F03 (clock-skewed revocation),
F04 (clock rollback skips the revocation check)."""

from __future__ import annotations

import copy
from datetime import UTC, timedelta

from edge.policy.engine import ScheduleCtx, evaluate
from edge.policy.schedule import HOLIDAY, IN_WINDOW, REVOKED, evaluate_schedule
from edge.policy.tests.builders import OB, SIGNED_BUNDLE, bundle_signed_at, ist, utc

CFG = {"grace_minutes": 15, "grace_minutes_high_risk": 0}


def _crossing_bundle() -> dict:
    b = copy.deepcopy(SIGNED_BUNDLE)  # 2026-11-20 (Fri) is a LAB_BLOCK holiday, contractors not exempt
    b["users"]["u_9c0d"]["extra_windows"] = {"LAB_BLOCK": [{"days": ["FRI"], "start": "22:00", "end": "02:00"}]}
    return b


def test_F02_holiday_on_the_start_day_closes_the_tail_after_midnight():
    b = _crossing_bundle()
    assert evaluate_schedule("u_9c0d", "LAB_BLOCK", ist("2026-11-20T23:00"), b, CFG) == HOLIDAY
    assert evaluate_schedule("u_9c0d", "LAB_BLOCK", ist("2026-11-21T01:00"), b, CFG) == HOLIDAY  # was IN_WINDOW


def test_F02_same_window_on_a_normal_friday_still_crosses_midnight():
    b = _crossing_bundle()
    assert evaluate_schedule("u_9c0d", "LAB_BLOCK", ist("2026-11-28T01:00"), b, CFG) == IN_WINDOW


def test_F03_received_revocation_counts_although_the_edge_clock_is_behind():
    b = copy.deepcopy(SIGNED_BUNDLE)
    revoked_at = utc("2026-11-14T04:35:00")
    b["revocations"] = list(b["revocations"]) + [{"user_id": "u_3c4d", "revoked_at": "2026-11-14T04:35:00Z",
                                                  "reason": "ADMIN"}]
    behind = revoked_at - timedelta(seconds=120)
    assert evaluate_schedule("u_3c4d", "LIBRARY", behind, b, CFG) != REVOKED  # strict (cloud re-evaluation)
    assert evaluate_schedule("u_3c4d", "LIBRARY", behind, b, CFG, revocation_slack_s=300) == REVOKED  # live edge


def test_F03_live_engine_applies_the_revocation_slack():
    s = OB().who("u_3c4d", "LIB", "2026-11-14T10:00")
    sig, ctx, mode, now, T = s.build()
    ahead = (sig.t0 + timedelta(seconds=120)).astimezone(UTC)  # cloud clock 120 s ahead of the edge
    rev = ({"user_id": "u_3c4d", "revoked_at": ahead.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "reason": "ADMIN"},)
    ctx2 = ScheduleCtx(kiosk_id=ctx.kiosk_id, bundle=ctx.bundle, signature_valid=True, extra_revocations=rev,
                       refresh_age_s=ctx.refresh_age_s)
    d = evaluate(sig, ctx2, mode, now, cfg=T, rng=None)
    assert d.decision == "DENY" and "SCHEDULE_REVOKED" in d.reason_codes


def test_F04_clock_rollback_still_denies_a_revoked_candidate():
    s = OB()
    s.bundle = bundle_signed_at(s.eff_now + timedelta(hours=2))  # issued "in the future": cache INVALID
    s.signature_valid = True
    sig, ctx, mode, now, T = s.build()
    dated_later = {"user_id": "u_3c4d", "revoked_at": "2026-12-31T00:00:00Z", "reason": "ADMIN"}
    for extra in ((), (dated_later,), ({"user_id": "u_3c4d", "revoked_at": None, "reason": "ADMIN"},)):
        ctx2 = ScheduleCtx(kiosk_id=ctx.kiosk_id, bundle=ctx.bundle, signature_valid=True, extra_revocations=extra,
                           refresh_age_s=ctx.refresh_age_s)
        d = evaluate(sig, ctx2, mode, now, cfg=T, rng=None)
        assert d.cache_state == "INVALID"
        if extra:
            assert d.decision == "DENY" and "SCHEDULE_REVOKED" in d.reason_codes, d.reason_codes
            assert d.next_action.type == "CONTACT_DESK"
        else:
            assert d.decision == "STEP_UP" and d.next_action.methods == ("STAFF_OVERRIDE",)
