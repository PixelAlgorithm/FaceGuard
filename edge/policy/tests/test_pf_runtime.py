"""policy-fixes: PolicyRuntime hardening -- forced-mode expiry (RBAC v2 D), loop / tick isolation (F07), EMAIL_OTP
R11 drop (F10), revocation re-check before a step-up ALLOW (F11), full-gallery entitlement (F12), alerts (F14),
public-safe /v1/mode (offline F6), persisted lockouts through the runtime (SC2-D9), fallback-state reset (EO-12),
consumed_code_ids (SC2-D8), lost revocation overlay (EO-08) and the sync / reconcile hooks (SC2-D4, EM-01)."""

# ruff: noqa: F811  (the shared `make_rt` fixture is imported from test_runtime and requested by name)
from __future__ import annotations

from datetime import timedelta

import httpx
import pyotp
import pytest

from edge.offline.store import SqliteFallbackState
from edge.policy.signals import FallbackSubmission
from edge.policy.tests.builders import RT_CLOCK, TEST_DATA_KEY, TOTP_SECRETS
from edge.policy.tests.test_runtime import FakeCloud, attempt, bring_online, make_rt, ok  # noqa: F401 (fixture)

LOW = {"local": [("u_3c4d", 0.45, 0.20)] * 5}  # offline MATCH_LOW -> STEP_UP SECOND_FACTOR for u_3c4d


def _online(make_rt):
    cloud = FakeCloud(None)
    rt = make_rt(cloud=cloud)
    cloud.bundle = rt.bundles.lvb
    bring_online(rt)
    assert rt.mode() == "ONLINE"
    return rt, cloud


# ---------------------------------------------------------------- forced mode (V2 D)
def test_forced_offline_auto_reverts_after_max_minutes(make_rt):
    rt, _ = _online(make_rt)
    st = rt.set_forced_mode("OFFLINE", reason="maintenance", max_minutes=5)
    assert st["mode"] == "OFFLINE" and st["forced"] is True and st["forced_reason"] == "operator"  # public view
    assert rt.sync_detail()["forced"]["reason"] == "maintenance"  # free text only in the authenticated view
    assert st["forced_until"] is not None
    RT_CLOCK.advance(timedelta(minutes=5, seconds=1))
    rt.tick()
    assert rt.mode_status()["forced"] is False and rt.mode_status()["forced_until"] is None
    assert "FORCED_MODE_EXPIRED" in [e["type"] for e in rt.recent_alerts()]


def test_forced_offline_defaults_to_60_minutes_and_validates_input(make_rt):
    rt = make_rt()
    rt.set_forced_mode("OFFLINE")
    RT_CLOCK.advance(timedelta(minutes=59))
    assert rt.mode_status()["forced"] is True
    RT_CLOCK.advance(timedelta(minutes=2))
    assert rt.mode_status()["forced"] is True or rt.mode() == "OFFLINE"  # status reflects expiry on next read
    rt.mode()
    assert rt.mode_status()["forced"] is False
    for bad in (0, 241, -1, "10", True):
        with pytest.raises(ValueError):
            rt.set_forced_mode("OFFLINE", max_minutes=bad)
    with pytest.raises(ValueError):
        rt.set_forced_mode("ONLINE")


def test_unlimited_forced_offline_only_for_demo_reason_in_demo_mode(make_rt):
    rt = make_rt()
    assert rt.set_forced_mode("OFFLINE", reason="DEMO")["forced_until"] is not None  # DEMO_MODE=0: still 60 min
    demo = make_rt(DEMO_MODE="1")
    st = demo.set_forced_mode("OFFLINE", reason="DEMO")
    assert st["forced"] is True and st["forced_until"] is None
    RT_CLOCK.advance(timedelta(hours=10))
    demo.tick()
    assert demo.mode_status()["forced"] is True


def test_revocation_feed_is_still_pulled_while_forced_offline(make_rt):
    rt, cloud = _online(make_rt)
    rt.set_forced_mode("OFFLINE", max_minutes=30)
    cloud.revocations = [{"type": "USER", "target_id": "u_3c4d", "revoked_at": "2026-11-14T04:30:00Z",
                          "reason": "ADMIN", "seq": 1}]
    rt.heartbeat()
    assert "u_3c4d" in rt.revoked_user_ids()


# ---------------------------------------------------------------- F07 isolation
def test_F07_a_failing_erasure_stage_does_not_block_the_retention_purge(make_rt):
    rt = make_rt()
    rt.decide(attempt("att_pf_old"))
    rt.add_erase_hook(lambda uid: (_ for _ in ()).throw(OSError("disk full")))
    rt.overlay.apply({"items": [{"type": "ERASE", "target_id": "u_1a2b", "revoked_at": "2026-11-14T04:00:00Z",
                                 "reason": "ERASED", "seq": 1}], "revocation_seq": 1})
    rt.credentials.remove = lambda uid: (_ for _ in ()).throw(OSError("bad key"))  # also fails
    RT_CLOCK.advance(timedelta(hours=25))
    rt.tick()
    view = rt.store_view()
    assert view["records"] == [] and view["tombstones"], "retention purge must still run"


def test_F07_malformed_feed_body_never_raises_out_of_the_heartbeat(make_rt):
    def transport(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/health":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(200, json=[1, 2, 3])  # a list where a dict is expected

    rt = make_rt(cloud=transport)
    assert rt.heartbeat() is True


# ---------------------------------------------------------------- F10 / F11 / F12
def test_F10_email_otp_after_a_mid_step_flip_is_dropped_not_counted(make_rt):
    rt, _ = _online(make_rt)
    sig = attempt("att_pf_email", cloud={"ok": True, "top1_user": "u_3c4d", "top1_similarity": 90.0,
                                               "runner_up_similarity": None})
    body = ok(rt.decide(sig))
    assert body["decision"] == "STEP_UP" and "EMAIL_OTP" in body["next_action"]["methods"]
    left = body["next_action"]["attempts_left"]
    rt.set_forced_mode("OFFLINE", max_minutes=10)
    body = ok(rt.resolve_fallback("att_pf_email", FallbackSubmission(method="EMAIL_OTP", otp_id="otp_1")))
    assert body["decision"] == "STEP_UP" and "EMAIL_OTP" not in body["next_action"]["methods"]
    assert body["next_action"]["attempts_left"] == left and "FALLBACK_FAILED" not in body["reason_codes"]


def test_F11_user_revoked_while_the_step_up_is_open_is_denied(make_rt):
    rt = make_rt()
    body = ok(rt.decide(attempt("att_pf_f11", **LOW)))
    assert body["decision"] == "STEP_UP" and body["candidate"]["user_id"] == "u_3c4d"
    rt.overlay.apply({"items": [{"type": "USER", "target_id": "u_3c4d",
                                 "revoked_at": (RT_CLOCK() + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                 "reason": "ADMIN", "seq": 1}], "revocation_seq": 1})
    code = pyotp.TOTP(TOTP_SECRETS["u_3c4d"]).at(int(rt.real_now().timestamp()))
    body = ok(rt.resolve_fallback("att_pf_f11", FallbackSubmission(method="TOTP", code=code)))
    assert body["decision"] == "DENY" and "SCHEDULE_REVOKED" in body["reason_codes"]
    assert body["next_action"]["type"] == "CONTACT_DESK"
    assert rt.store_view()["records"][-1]["decision"] == "DENY"


@pytest.mark.parametrize("mode", ["OFFLINE", "ONLINE"])
@pytest.mark.parametrize("who", ["u_a3b4", "u_zz99"])  # revoked in the bundle / not in the bundle at all
def test_F12_full_gallery_top1_that_is_not_entitled_never_allows(make_rt, mode, who):
    rt, _ = _online(make_rt) if mode == "ONLINE" else (make_rt(), None)
    cm = {"ok": True, "top1_user": who, "top1_similarity": 99.6, "runner_up_similarity": None}
    for i, local in enumerate(([(who, 0.80, 0.58)] * 5, [(who, 0.45, 0.20)] * 5)):
        body = ok(rt.decide(attempt(f"att_pf_f12_{mode}_{who}_{i}", local=local, cloud=cm)))
        assert body["decision"] == "DENY", body["reason_codes"]


def test_excluded_user_ids_lists_erase_pending_users(make_rt):
    rt = make_rt()
    rt.overlay.apply({"items": [{"type": "ERASE", "target_id": "u_1a2b", "revoked_at": "2026-11-14T04:00:00Z",
                                 "reason": "ERASED", "seq": 1}], "revocation_seq": 1})
    assert "u_1a2b" in rt.excluded_user_ids()


# ---------------------------------------------------------------- alerts / mode privacy
def test_F14_lockout_alert_is_listed_by_recent_alerts(make_rt):
    rt = make_rt(DEMO_MODE="1")
    for i in range(3):
        body = ok(rt.decide(attempt(f"att_pf_lock{i}", **LOW)))
        rt.resolve_fallback(body["attempt_id"], FallbackSubmission(method="STAFF_OVERRIDE", code=f"9999999{i}",
                                                                   staff_id="s_guard01"))
    kinds = [(e["type"], e.get("lock")) for e in rt.recent_alerts(10)]
    assert ("ALERT_FALLBACK_LOCKOUT", "STAFF_OVERRIDE_STAFF") in kinds
    assert len(rt.recent_alerts(1)) == 1


def test_offline_F6_public_mode_status_holds_counts_only(make_rt):
    rt, cloud = _online(make_rt)
    cloud.revocations = [{"type": "USER", "target_id": "u_3c4d", "revoked_at": "2026-11-14T04:30:00Z",
                          "reason": "ADMIN", "seq": 1}]
    rt.sync_now()
    st = rt.mode_status()
    assert "server_flags" not in st and isinstance(st["server_flags_count"], int)
    assert "u_3c4d" not in repr(st["last_sync"])
    assert rt.sync_detail()["last_sync"]["report"]["revoked_users"] == ["u_3c4d"]


# ---------------------------------------------------------------- persisted state through the runtime
def test_D9_lockout_survives_a_runtime_restart(make_rt):
    rt = make_rt(DEMO_MODE="1")
    for i in range(3):
        body = ok(rt.decide(attempt(f"att_pf_r{i}", **LOW)))
        rt.resolve_fallback(body["attempt_id"], FallbackSubmission(method="STAFF_OVERRIDE", code=f"1212121{i}",
                                                                   staff_id="s_guard01"))
    rt.stop()
    rt2 = make_rt(DEMO_MODE="1")
    body = ok(rt2.decide(attempt("att_pf_after", **LOW)))
    body = ok(rt2.resolve_fallback("att_pf_after", FallbackSubmission(method="STAFF_OVERRIDE", code="48213907",
                                                                       staff_id="s_guard01")))
    assert body["decision"] == "STEP_UP" and "FALLBACK_LOCKED" in body["reason_codes"]
    assert body["next_action"]["retry_after_s"] > 0


def test_EO12_deleted_fallback_state_is_detected_and_consumed_codes_reseeded(make_rt, tmp_path):
    rt = make_rt(DEMO_MODE="1")
    body = ok(rt.decide(attempt("att_pf_used", **LOW)))
    body = ok(rt.resolve_fallback("att_pf_used", FallbackSubmission(method="STAFF_OVERRIDE", code="48213907",
                                                                     staff_id="s_guard01")))
    assert body["decision"] == "ALLOW"
    rt.stop()
    rt.fallback_state.close()
    (tmp_path / "fallback_state.sqlite").unlink()  # attacker deletes the replay state (no key needed)
    rt2 = make_rt(DEMO_MODE="1")
    assert "ALERT_FALLBACK_STATE_RESET" in [e["type"] for e in rt2.recent_alerts()]
    ok(rt2.decide(attempt("att_pf_replay", **LOW)))
    body = ok(rt2.resolve_fallback("att_pf_replay", FallbackSubmission(method="STAFF_OVERRIDE", code="48213907",
                                                                        staff_id="s_guard01")))
    assert body["decision"] != "ALLOW"


def test_D8_tick_persists_consumed_code_ids_from_the_bundle(make_rt):
    rt = make_rt()
    lvb = dict(rt.bundles.lvb)
    lvb["consumed_code_ids"] = ["OVR-002"]
    rt.bundles._lvb = lvb  # simulate a verified bundle that lists a code used at another kiosk
    rt.tick()
    assert rt.fallback_state.is_code_consumed("OVR-002") and not rt.fallback_state.is_code_consumed("OVR-001")


def test_EO08_lost_revocation_overlay_never_auto_allows(make_rt):
    rt = make_rt()
    rt.overlay.state_lost = True
    body = ok(rt.decide(attempt("att_pf_lost")))
    assert body["decision"] == "STEP_UP" and body["next_action"]["type"] == "SECOND_FACTOR"
    assert rt.mode_status()["revocations_state_lost"] is True


def test_sync_and_reconcile_hooks_run_after_a_successful_sync(make_rt):
    rt, cloud = _online(make_rt)
    seen: list = []
    rt.add_sync_hook(lambda: seen.append("sync"))
    rt.add_reconcile_hook(lambda now: seen.append(("reconcile", now.tzinfo is not None)))
    rt.add_sync_hook(lambda: (_ for _ in ()).throw(RuntimeError("isolated")))
    rt.sync_now()
    assert seen == ["sync", ("reconcile", True)]
    cloud.up = False
    with pytest.raises(Exception):  # noqa: B017 - CloudUnavailableError
        rt.sync_now()
    assert seen == ["sync", ("reconcile", True)]


def test_pending_enrolment_queue_round_trip(make_rt):
    rt = make_rt()
    rec = {"user_id": "u_3c4d", "actor": "staff:s_admin01", "at": "2026-11-14T04:35:00Z", "template_count": 3,
           "model": "buffalo_l", "kiosk_id": "KIOSK_LIB_01"}
    rt.queue_pending_enrolment(rec)
    assert rt.pending_enrolments() == [rec]
    assert rt.clear_pending_enrolment("u_3c4d") is True and rt.pending_enrolments() == []
    with pytest.raises(ValueError):
        rt.queue_pending_enrolment({**rec, "images": ["x"]})


def test_sqlite_state_epoch_is_stable_across_reopen(tmp_path):
    a = SqliteFallbackState(tmp_path / "f.sqlite", TEST_DATA_KEY)
    assert a.created_new is True
    b = SqliteFallbackState(tmp_path / "f.sqlite", TEST_DATA_KEY)
    assert b.created_new is False and b.epoch == a.epoch
