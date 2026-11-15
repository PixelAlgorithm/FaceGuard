"""SC2.1 connectivity + demo clock: POLICY_TEST_CASES X01-X14."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta

import pytest

from edge.offline.bundle import sign_bundle
from edge.offline.connectivity import OFFLINE, ONLINE, SYNCING, ConnectivityMonitor
from edge.offline.tests.conftest import attempt, bring_online
from edge.policy.tests.builders import (
    IST,
    O14_PAD,
    RT_CLOCK,
    TEST_BUNDLE_KEY,
    base_thresholds,
    load_example_bundle,
)

T = base_thresholds()


def mon(state=ONLINE, **kw) -> ConnectivityMonitor:
    return ConnectivityMonitor(T, configured=True, initial=state, **kw)


def test_X01_two_misses_stay_online():
    m = mon()
    for ok in (True, False, False):
        m.record(ok)
    assert m.state == ONLINE and m.mode() == ONLINE


def test_X02_third_consecutive_miss_goes_offline():
    m = mon()
    for ok in (True, False, False, False):
        m.record(ok)
    assert m.state == OFFLINE and m.status()["reason"] == "heartbeat_timeout"


def test_X02_attempt_after_three_misses_is_offline(make_rt, cloud):
    rt = make_rt(cloud)
    bring_online(rt)
    cloud.up = False
    for _ in range(3):
        rt.heartbeat()
    assert rt.mode_status()["mode"] == OFFLINE
    assert "OFFLINE_MODE" in rt.decide(attempt("att_x02"))["reason_codes"]


def test_X03_three_successes_from_offline_enter_syncing_with_offline_rules(make_rt, cloud):
    rt = make_rt(cloud)
    for i in range(4):
        rt.decide(attempt(f"att_x03_{i}"))
    for _ in range(3):
        rt.heartbeat()
    assert rt.monitor.state == SYNCING and rt.mode() == OFFLINE
    body = rt.decide(attempt("att_x03_o14", pad=list(O14_PAD)))
    assert body["decision"] == "STEP_UP" and "OFFLINE_MODE" in body["reason_codes"]  # O14 still STEP_UP


def test_X05_miss_while_syncing_goes_offline():
    m = mon(OFFLINE)
    for _ in range(3):
        m.record(True)
    assert m.state == SYNCING
    m.record(False)
    assert m.state == OFFLINE


def test_X06_forced_offline_is_immediate_and_heartbeats_keep_running(make_rt, cloud):
    rt = make_rt(cloud)
    bring_online(rt)
    st = rt.set_forced_mode("OFFLINE")
    assert st["mode"] == OFFLINE and st["forced"] is True and st["reason"] == "forced"
    assert "OFFLINE_MODE" in rt.decide(attempt("att_x06"))["reason_codes"]
    n = len(cloud.calls)
    rt.heartbeat()
    # probing continues underneath; RBAC v2 D: the deny-only revocation feed is still pulled while forced
    assert [c[1] for c in cloud.calls[n:]] == ["/v1/health", "/v1/revocations"] and rt.monitor.successes >= 1


def test_X06_force_offline_env_at_startup(make_rt, cloud):
    rt = make_rt(cloud, FORCE_OFFLINE="1")
    assert rt.mode_status()["forced"] is True and rt.mode() == OFFLINE


def test_X07_auto_after_three_good_heartbeats_goes_straight_to_syncing(make_rt, cloud):
    rt = make_rt(cloud)
    bring_online(rt)
    rt.set_forced_mode("OFFLINE")
    rt.decide(attempt("att_x07_a"))
    rt.decide(attempt("att_x07_b"))
    for _ in range(3):
        rt.heartbeat()
    st = rt.set_forced_mode("AUTO")
    assert st["state"] == SYNCING and st["forced"] is False and st["sync_queue_depth"] == 2
    rt.sync_now()
    assert rt.monitor.state == ONLINE and rt.log.queue_depth() == 0


def test_X08_auto_while_unreachable_stays_offline_until_three_successes(make_rt, cloud):
    rt = make_rt(cloud)
    bring_online(rt)
    rt.set_forced_mode("OFFLINE")
    cloud.up = False
    rt.heartbeat()
    assert rt.set_forced_mode("AUTO")["state"] == OFFLINE
    cloud.up = True
    rt.heartbeat()
    rt.heartbeat()
    assert rt.monitor.state == OFFLINE
    rt.heartbeat()
    assert rt.monitor.state == SYNCING


def test_X09_offline_only_after_the_third_miss_never_before():
    m = mon()
    m.record(True)
    for i in range(1, 4):
        m.record(False)
        assert m.state == (ONLINE if i < 3 else OFFLINE)


def test_X09_heartbeat_timeout_from_yaml():
    assert T.connectivity.heartbeat_timeout_ms == 2000 and T.connectivity.heartbeat_interval_s == 5
    assert T.connectivity.health_path == "/v1/health"


def test_X10_revocation_feed_at_heartbeat_applies_online(make_rt, cloud):
    rt = make_rt(cloud)
    bring_online(rt)
    cloud.revocations = [{"seq": 8, "type": "USER", "target_id": "u_3c4d",
                          "revoked_at": (RT_CLOCK() - timedelta(seconds=5)).isoformat(),
                          "reason": "ADMIN"}]
    rt.heartbeat()
    body = rt.decide(attempt("att_x10"))
    assert body["decision"] == "DENY" and "SCHEDULE_REVOKED" in body["reason_codes"]
    assert body["mode"] == ONLINE and body["next_action"]["type"] == "CONTACT_DESK"


def test_X11_stale_online_bundle_attempt_goes_offline_without_a_miss(make_rt, cloud):
    rt = make_rt(cloud)
    bring_online(rt)
    rt.bundles._refreshed_mono = time.monotonic() - 29 * 60
    assert rt.decide(attempt("att_x11_29"))["mode"] == ONLINE
    rt.bundles._refreshed_mono = time.monotonic() - 31 * 60
    misses = rt.monitor.misses
    body = rt.decide(attempt("att_x11_31"))
    assert body["mode"] == OFFLINE and set(body["reason_codes"]) == {"ACCESS_OK", "OFFLINE_MODE"}  # O30
    st = rt.mode_status()
    assert st["mode"] == OFFLINE and st["reason"] == "bundle_stale" and rt.monitor.misses == misses


def test_X12_demo_clock_rejected_without_demo_mode(make_rt):
    rt = make_rt(None, DEMO_MODE="0")
    before = rt.now()
    with pytest.raises(PermissionError):
        rt.set_demo_clock(set_local="07:50")
    assert abs((rt.now() - before).total_seconds()) < 5 and rt.mode_status()["demo_clock"] is None


def _fixed_real(rt, local: str) -> datetime:
    real = datetime.fromisoformat(local).replace(tzinfo=IST).astimezone(UTC)
    rt._real = lambda: real
    return real


def test_X13_X14_demo_clock_trap_and_resign(make_rt, cloud, tmp_path):
    rt = make_rt(cloud, DEMO_MODE="1")
    real = _fixed_real(rt, "2026-11-14T10:05:00")
    b = load_example_bundle()
    b["issued_at"], b["expires_at"] = "2026-11-14T04:30:00Z", "2026-11-14T16:30:00Z"  # signed at 10:00 IST
    path = rt.bundles.path
    path.write_text(json.dumps(sign_bundle(b, TEST_BUNDLE_KEY)), encoding="utf-8")
    rt.bundles._last_check = 0.0
    bring_online(rt)  # cloud serves the same bundle
    cloud.bundle = rt.bundles.lvb
    clock = rt.set_demo_clock(set_local="07:50")
    assert clock["active"] is True and clock["now_local"] == "07:50"
    # X13: 07:50 IST < issued_at - 300 s -> INVALID -> MO3 -> I1
    s = attempt("att_x13").model_copy(update={"t0": real})
    body = rt.decide(s)
    assert body["decision"] == "STEP_UP" and set(body["reason_codes"]) == {
        "SCHEDULE_BUNDLE_INVALID", "OFFLINE_MODE", "OFFLINE_FALLBACK_REQUIRED"}
    assert body["next_action"]["methods"] == ["STAFF_OVERRIDE"]
    # X14: re-sign at demo now (07:50 IST) and install -> S01 result online
    b2 = load_example_bundle()
    b2["issued_at"], b2["expires_at"] = "2026-11-14T02:20:00Z", "2026-11-14T14:20:00Z"
    # EO-09: an older issued_at at the SAME version is a rollback on reload too; scripts/sign_bundle.py bumps the
    # version (installed + 1) by default, which is the documented X14 recovery
    b2["bundle_version"] = int(b.get("bundle_version") or 0) + 1
    time.sleep(0.01)
    path.write_text(json.dumps(sign_bundle(b2, TEST_BUNDLE_KEY)), encoding="utf-8")
    rt.bundles._last_check = 0.0
    body = rt.decide(attempt("att_x14").model_copy(update={"t0": real}))
    assert body["mode"] == ONLINE and body["decision"] == "STEP_UP"
    assert body["reason_codes"] == ["SCHEDULE_GRACE_WINDOW"] and set(body["next_action"]["methods"]) == {
        "TOTP", "CARD", "EMAIL_OTP", "STAFF_OVERRIDE"}
    assert rt.mode_status()["demo_clock"]["active"] is True
    rt.set_demo_clock(reset=True)
    assert rt.now() == real and rt.mode_status()["demo_clock"]["active"] is False


def test_not_configured_is_permanently_offline(make_rt):
    rt = make_rt(None)
    for _ in range(5):
        rt.heartbeat()
    st = rt.mode_status()
    assert st["mode"] == OFFLINE and st["reason"] == "not_configured" and st["state"] == OFFLINE
