"""SC2.6 sync: idempotent replay (Y01), conflicts (Y02), surfaced discrepancies, revocations first, X04, Y11."""

from __future__ import annotations

import pytest

from edge.offline.tests.conftest import attempt, bring_online, signed_now
from edge.policy.runtime import CloudUnavailableError
from edge.policy.tests.builders import L03_PAD, PHONE, RT_CLOCK


def queue(rt, n: int, prefix: str = "att_q") -> None:
    for i in range(n):
        rt.decide(attempt(f"{prefix}{i:03d}"))


def test_items_match_the_api_contract_and_queue_drains(make_rt, cloud):
    rt = make_rt(cloud)
    rt.decide(attempt("att_s_allow"))
    rt.decide(attempt("att_s_spoof", device=PHONE))
    rep = rt.sync_now()  # FakeCloud validates SyncRequest / SyncItem (extra="forbid") and every HMAC
    assert rep["accepted"] == 2 and rep["rejected"] == 0 and rep["queue_depth"] == 0
    assert set(cloud.stored) == {"att_s_allow", "att_s_spoof"}
    item = cloud.stored["att_s_allow"]
    assert item["idempotency_key"] == item["attempt_id"] and "type" not in item


def test_Y01_replay_after_a_lost_response_is_idempotent(make_rt, cloud):
    rt = make_rt(cloud)
    queue(rt, 3)
    cloud.lose_next_sync_response = True
    with pytest.raises(CloudUnavailableError):
        rt.sync_now()
    assert rt.log.queue_depth() == 3 and len(cloud.stored) == 3  # server stored, edge never got the ack
    rep = rt.sync_now()  # replay: all duplicates -> safe to purge
    assert rep["duplicates"] == 3 and rep["accepted"] == 0 and rep["queue_depth"] == 0
    assert len(cloud.stored) == 3  # server record count unchanged


def test_sync_twice_sends_nothing_new(make_rt, cloud):
    rt = make_rt(cloud)
    queue(rt, 2)
    rt.sync_now()
    n = len(cloud.sync_batches)
    rep = rt.sync_now()
    assert rep["accepted"] == rep["duplicates"] == 0 and len(cloud.sync_batches) == n


def test_Y02_conflict_is_acked_as_duplicate_both_versions_kept_and_alerted(make_rt, cloud):
    """docs/API.md 4.4 + deployed cloud (sync_service._existing): same attempt_id, different content ->
    acknowledged in `duplicates` (never `rejected`), the server keeps both versions and raises
    ALERT_SYNC_CONFLICT; the edge purges its copy (purge on ack)."""
    rt = make_rt(cloud)
    rt.decide(attempt("att_conflict"))
    original = {"record_hash": "different"}
    cloud.stored["att_conflict"] = original
    rep = rt.sync.run_once()
    assert rep["rejected"] == 0 and rep["duplicates"] == 1 and rep["accepted"] == 0
    assert rt.log.queue_depth() == 0  # acked -> purged locally
    assert cloud.stored["att_conflict"] is original  # kiosk records immutable: the first version is not replaced
    assert [v["idempotency_key"] for v in cloud.conflict_variants] == ["att_conflict"]  # both versions stored
    assert [(a["alert"], a["attempt_id"]) for a in cloud.alerts] == [("ALERT_SYNC_CONFLICT", "att_conflict")]
    again = rt.sync.run_once()  # nothing left to replay -> no second alert
    assert again["sent"] == 0 and len(cloud.alerts) == 1


def test_Y02_verbose_acks_shape_surfaces_the_conflict_as_ALERT_SYNC_CONFLICT():
    from edge.offline.sync import _parse_sync_response

    acc, dup, rej, flags = _parse_sync_response({"acks": [
        {"attempt_id": "att_c", "status": "CONFLICT", "verdict": None},
        {"attempt_id": "att_d", "status": "DUPLICATE", "verdict": None},
        {"attempt_id": "att_a", "status": "ACCEPTED", "verdict": None}], "alerts": []})
    assert acc == ["att_a"] and dup == ["att_c", "att_d"] and rej == []
    assert flags == [{"attempt_id": "att_c", "type": "ALERT_SYNC_CONFLICT"}]


def test_server_flags_are_surfaced(make_rt, cloud):
    rt = make_rt(cloud)
    rt.decide(attempt("att_flagged"))
    cloud.flags = [{"attempt_id": "att_flagged", "type": "POST_HOC_REVOKED"}]
    rep = rt.sync_now()
    assert rep["flags"] == cloud.flags
    # EO-13 / offline F6: the public mode_status carries counts only; the detail is authenticated (sync_detail)
    assert rt.sync_detail()["server_flags"][-1]["type"] == "POST_HOC_REVOKED"
    assert rt.mode_status()["server_flags_count"] >= 1


def test_revocations_are_pulled_before_the_queue_is_replayed(make_rt, cloud):
    rt = make_rt(cloud)
    queue(rt, 1)
    rt.sync_now()
    paths = [p for _, p in cloud.calls]
    assert paths.index("/v1/revocations") < paths.index("/v1/sync")


def test_tombstones_are_sent_and_acked(make_rt, cloud):
    from datetime import timedelta

    rt = make_rt(cloud)
    queue(rt, 2)
    rt.log.purge_expired(rt.now() + timedelta(hours=25))
    assert rt.log.queue_depth() == 1 and rt.log.tombstones()
    rt.sync_now()
    assert cloud.tombstones and cloud.tombstones[0]["count"] == 2 and rt.log.tombstones() == []


def test_batches_are_at_most_50_items(make_rt, cloud):
    rt = make_rt(cloud)
    queue(rt, 120)
    rep = rt.sync_now()
    assert [len(b) for b in cloud.sync_batches] == [50, 50, 20] and rep["accepted"] == 120


def test_X04_syncing_becomes_online_after_ack_and_bundle_refresh(make_rt, cloud):
    rt = make_rt(cloud)
    queue(rt, 4)
    for _ in range(3):
        rt.heartbeat()
    assert rt.monitor.state == "SYNCING" and rt.mode() == "OFFLINE"  # X03: offline rules while syncing
    cloud.bundle = signed_now(RT_CLOCK(), version=43)
    rt.sync_now()
    st = rt.mode_status()
    assert st["state"] == "ONLINE" and st["sync_queue_depth"] == 0 and st["schedule_bundle"]["version"] == 43


def test_sync_failure_keeps_syncing_from_going_online(make_rt, cloud):
    rt = make_rt(cloud)
    queue(rt, 1)
    for _ in range(3):
        rt.heartbeat()
    cloud.up = False
    with pytest.raises(CloudUnavailableError):
        rt.sync_now()
    assert rt.monitor.state == "OFFLINE" and rt.log.queue_depth() == 1  # X05: a miss while SYNCING


def test_Y11_revocation_pulled_at_sync_applies_to_the_next_attempt(make_rt, cloud):
    rt = make_rt(cloud)
    bring_online(rt)
    assert "u_3c4d" in rt.entitled_user_ids()
    cloud.revocations = [{"seq": 8, "type": "USER", "target_id": "u_3c4d", "revoked_at": "2026-11-01T00:00:00Z",
                          "reason": "ADMIN"}]
    rt.sync_now()
    assert "u_3c4d" not in rt.entitled_user_ids() and "u_3c4d" in rt.revoked_user_ids()
    body = rt.decide(attempt("att_y11"))
    assert body["decision"] == "DENY" and "SCHEDULE_REVOKED" in body["reason_codes"]
    assert body["next_action"]["type"] == "CONTACT_DESK"


def test_rejected_bundle_from_the_cloud_keeps_the_lvb(make_rt, cloud):
    from edge.policy.tests.builders import tampered

    rt = make_rt(cloud)
    v = rt.bundles.lvb["signature"]["value"]
    cloud.bundle = tampered(rt.bundles.lvb)
    rep = rt.sync.run_once()
    assert str(rep["bundle"]).startswith("rejected") and rt.bundles.lvb["signature"]["value"] == v


def test_offline_or_unconfigured_sync_is_cloud_unavailable(make_rt, cloud):
    with pytest.raises(CloudUnavailableError):
        make_rt(None).sync_now()
    rt = make_rt(cloud)
    rt.set_forced_mode("OFFLINE")
    with pytest.raises(CloudUnavailableError):
        rt.sync_now()


def test_step_up_attempt_is_synced_once_as_its_final_decision(make_rt, cloud):
    rt = make_rt(cloud)
    bring_online(rt)  # online: L03 needs the CHALLENGE only
    body = rt.decide(attempt("att_su_sync", pad=list(L03_PAD)))
    assert body["mode"] == "ONLINE" and body["next_action"]["steps"] == ["CHALLENGE"]
    rt.sync_now()
    assert "att_su_sync" not in cloud.stored  # still pending: not final yet
    from edge.policy.tests.builders import evidence_for

    rt.resolve_challenge("att_su_sync", evidence_for(rt.sessions["att_su_sync"].challenge))
    rt.sync_now()
    assert cloud.stored["att_su_sync"]["decision"] == "ALLOW"
    assert cloud.stored["att_su_sync"]["resolved_codes"] == ["LIVENESS_UNSURE"]
