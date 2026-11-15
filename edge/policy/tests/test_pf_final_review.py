# ruff: noqa: F811  (the shared `make_rt` fixture is imported from test_runtime and requested by name)
"""policy-fixes: final-review findings P1 (repeat ERASE never acked), P2 (orphaned-queue alert flood), P4 (EO-08
challenge-only step-up), P5 (holiday tail vs today's own window), P6 (sliding device backstop)."""

from __future__ import annotations

import copy
from datetime import timedelta

from edge.policy.fallback import InMemoryFallbackState
from edge.policy.lockouts import Limit, is_locked, record_failure
from edge.policy.schedule import HOLIDAY, IN_WINDOW, evaluate_schedule
from edge.policy.tests.builders import L03_PAD, SIGNED_BUNDLE, B, ist, utc
from edge.policy.tests.test_runtime import attempt, make_rt, ok  # noqa: F401 (fixture)

CFG = {"grace_minutes": 15, "grace_minutes_high_risk": 0}


def _erase_event(seq: int) -> dict:
    return {"items": [{"type": "ERASE", "target_id": "u_1a2b", "revoked_at": "2026-11-14T04:00:00Z",
                       "reason": "ERASED", "seq": seq}], "revocation_seq": seq}


# ---------------------------------------------------------------- P1
def test_P1_a_repeated_erase_event_is_purged_again_and_acked(make_rt):
    rt = make_rt()
    calls: list[str] = []
    rt.add_erase_hook(calls.append)
    rt.overlay.apply(_erase_event(1))
    rt.apply_erasures()
    assert rt.overlay.pending_purge() == [] and rt.erasures_complete()
    rt.overlay.apply(_erase_event(2))  # cloud writes a new ERASE event on every erase call
    rt.apply_erasures()
    assert rt.overlay.pending_purge() == [] and rt.erasures_complete()
    assert calls == ["u_1a2b", "u_1a2b"]  # each ERASE event purges once (idempotent)


def test_P1_bundle_erasure_before_the_feed_event_is_acked(make_rt, monkeypatch):
    rt = make_rt()
    calls: list[str] = []
    rt.add_erase_hook(calls.append)
    orig = rt.erased_user_ids
    monkeypatch.setattr(rt, "erased_user_ids", lambda: orig() | {"u_1a2b"})  # bundle ERASED revocation
    rt.apply_erasures()
    rt.overlay.apply(_erase_event(1))
    rt.apply_erasures()
    assert rt.overlay.pending_purge() == [] and rt.erasures_complete()


# ---------------------------------------------------------------- P2
def test_P2_orphaned_queue_alert_is_emitted_once_per_state(make_rt, monkeypatch):
    import edge.policy.runtime as rt_mod

    rt = make_rt()
    report = [{"kiosk_id": "KIOSK_OLD_01", "file": "decisions_KIOSK_OLD_01.sqlite", "purged": 0, "queued": 0,
               "tombstones": 1, "error": None}]
    monkeypatch.setattr(rt_mod, "purge_foreign_logs", lambda *a, **k: [dict(e) for e in report])
    for _ in range(20):
        rt.tick()
    assert [e["type"] for e in rt.events()].count("ALERT_ORPHANED_QUEUE") == 1
    report[0]["queued"] = 3  # state changed -> one new alert
    rt.tick()
    rt.tick()
    assert [e["type"] for e in rt.events()].count("ALERT_ORPHANED_QUEUE") == 2


# ---------------------------------------------------------------- P4
def test_P4_lost_overlay_adds_a_second_factor_to_a_challenge_only_step_up():
    s = B().set(pad=list(L03_PAD))  # ONLINE, liveness UNSURE, IN_WINDOW, low risk -> CHALLENGE only
    base = s.evaluate()
    assert base.decision == "STEP_UP" and base.next_action.steps == ("CHALLENGE",)
    sig, ctx, mode, now, T = s.build()
    from dataclasses import replace

    from edge.policy.engine import evaluate

    d = evaluate(sig, replace(ctx, revocations_incomplete=True), mode, now, cfg=T, rng=None)
    assert d.decision == "STEP_UP" and d.next_action.steps == ("CHALLENGE", "SECOND_FACTOR")
    assert d.next_action.methods and "OFFLINE_FALLBACK_REQUIRED" in d.reason_codes


# ---------------------------------------------------------------- P5
def test_P5_todays_own_window_wins_over_a_closed_holiday_tail():
    b = copy.deepcopy(SIGNED_BUNDLE)  # 2026-11-20 (Fri) is a LAB_BLOCK holiday
    b["users"]["u_9c0d"]["extra_windows"] = {"LAB_BLOCK": [{"days": ["FRI"], "start": "22:00", "end": "02:00"},
                                                           {"days": ["SAT"], "start": "00:30", "end": "06:00"}]}
    assert evaluate_schedule("u_9c0d", "LAB_BLOCK", ist("2026-11-21T01:00"), b, CFG) == IN_WINDOW
    assert evaluate_schedule("u_9c0d", "LAB_BLOCK", ist("2026-11-21T00:15"), b, CFG) == HOLIDAY


# ---------------------------------------------------------------- P6
def test_P6_device_backstop_is_a_sliding_window():
    st, lim, t0 = InMemoryFallbackState(), Limit(10, 300, 300), utc("2026-11-14T04:35:00")
    record_failure(st, "device:x", lim, t0)
    for i in range(8):
        record_failure(st, "device:x", lim, t0 + timedelta(seconds=299))
    locked = False
    for i in range(9):  # 9 more just after the first failure aged out: 17 within 3 s -> must lock
        locked = record_failure(st, "device:x", lim, t0 + timedelta(seconds=301 + i * 0.1)) or locked
    assert locked and is_locked(st, "device:x", lim, t0 + timedelta(seconds=303))


def test_P6_slow_failures_still_never_lock():
    st, lim, t0 = InMemoryFallbackState(), Limit(10, 300, 300), utc("2026-11-14T04:35:00")
    for i in range(30):
        assert record_failure(st, "device:x", lim, t0 + timedelta(seconds=40 * i)) is False


def test_P6_sliding_window_times_persist_in_sqlite(tmp_path):
    from edge.offline.store import SqliteFallbackState
    from edge.policy.tests.builders import TEST_DATA_KEY

    lim, t0 = Limit(10, 300, 300), utc("2026-11-14T04:35:00")
    st = SqliteFallbackState(tmp_path / "fb.sqlite", TEST_DATA_KEY)
    for i in range(9):
        record_failure(st, "device:x", lim, t0 + timedelta(seconds=i * 0.5))
    st2 = SqliteFallbackState(tmp_path / "fb.sqlite", TEST_DATA_KEY)  # restart
    assert record_failure(st2, "device:x", lim, t0 + timedelta(seconds=10)) is True


def test_pre_sync_hook_runs_before_the_decision_batch(make_rt):
    from edge.policy.tests.test_runtime import FakeCloud

    cloud = FakeCloud(None)
    rt = make_rt(cloud=cloud)
    cloud.bundle = rt.bundles.lvb
    order: list[str] = []
    orig = rt.sync.run_once
    rt.sync.run_once = lambda: (order.append("sync"), orig())[1]
    rt.add_pre_sync_hook(lambda: order.append("pre"))
    rt.add_pre_sync_hook(lambda: (_ for _ in ()).throw(RuntimeError("isolated")))
    rt.sync_now()
    assert order == ["pre", "sync"]
