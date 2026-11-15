"""POST /v1/sync - docs/POLICY_TEST_CASES.md §7 rows Y01-Y11 (+ D06 tamper, guards, contract shape)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cloud.app.canonical import hmac_hex
from cloud.app.services.schedule_service import verify_bundle

from .conftest import BUNDLE_KEY, KIOSK_KEY, Signed, batch, genesis, make_record, signed_item

SPEC_KEYS = {"accepted", "duplicates", "rejected", "flags", "server_time"}


def _sync(signed: Signed, body: dict, kiosk: str | None = None, verbose: bool = False):
    path = "/v1/sync" + ("?verbose=true" if verbose else "")
    r = signed.post(path, body, kiosk=kiosk or body["kiosk_id"])
    assert r.status_code == 200, r.text
    assert "x-latency-ms" in r.headers
    return r.json()


def _alerts(out: dict) -> set[str]:
    return {a["alert"] for a in out["alerts"]}


def test_response_shape_is_exactly_the_lead_contract(signed):
    out = _sync(signed, batch("KIOSK_LIB_01", [make_record("att_shape1")]))
    assert set(out) == SPEC_KEYS
    assert out["accepted"] == ["att_shape1"] and out["duplicates"] == [] and out["rejected"] == []


def test_Y01_replay_same_batch_is_idempotent(signed, services):
    items = [make_record(f"att_y01_{i}", ts=f"2026-11-14T04:3{i}:00Z") for i in range(3)]
    body = batch("KIOSK_LIB_01", items, batch_id="b_y01")
    first = _sync(signed, body)
    assert sorted(first["accepted"]) == sorted(i["attempt_id"] for i in items)
    n = len(services.kv.list("decisions"))
    second = signed.post("/v1/sync", body, headers={"Idempotency-Key": "b_y01"}).json()
    assert second["accepted"] == [] and sorted(second["duplicates"]) == sorted(first["accepted"])
    assert second["flags"] == [] and second["rejected"] == []
    assert len(services.kv.list("decisions")) == n  # server record count unchanged


def test_Y02_same_attempt_different_content_is_conflict(signed, services):
    _sync(signed, batch("KIOSK_LIB_01", [make_record("att_y02", decision="DENY", mode="ONLINE",
                                                     codes=["SPOOF_PASSIVE"])]))
    out = _sync(signed, batch("KIOSK_LIB_01", [make_record("att_y02", decision="ALLOW")]), verbose=True)
    assert out["acks"][0]["status"] == "CONFLICT"
    assert "att_y02" in out["duplicates"] and "att_y02" in out["conflicts"]  # stored -> safe to purge
    assert "ALERT_SYNC_CONFLICT" in _alerts(out)
    keys = [k for k, _ in services.kv.list("decisions", prefix="KIOSK_LIB_01|att_y02")]
    assert len(keys) == 2  # both versions stored
    again = _sync(signed, batch("KIOSK_LIB_01", [make_record("att_y02", decision="ALLOW")]), verbose=True)
    assert "ALERT_SYNC_CONFLICT" not in _alerts(again)  # conflict variant itself is idempotent


def test_Y03_revocation_effective_before_offline_allow_is_flagged(signed, services):
    services.schedule.revoke(rtype="USER", target_id="u_3c4d", reason="ADMIN",
                             revoked_at=datetime(2026, 11, 14, 3, 30, tzinfo=UTC))
    out = _sync(signed, batch("KIOSK_LIB_01", [make_record("att_y03", ts="2026-11-14T04:35:00Z")]), verbose=True)
    assert {"attempt_id": "att_y03", "type": "POST_HOC_REVOKED"} in [
        {"attempt_id": f["attempt_id"], "type": f["type"]} for f in out["flags"]]
    assert out["acks"][0]["verdict"] == "DISCREPANCY"
    a = next(a for a in out["alerts"] if a["alert"] == "ALERT_REVOKED_USER_ADMITTED")
    assert a["severity"] == "high"


def test_Y04_revocation_after_offline_allow_is_confirmed(signed, services):
    services.schedule.revoke(rtype="USER", target_id="u_3c4d", reason="ADMIN",
                             revoked_at=datetime(2026, 11, 14, 5, 30, tzinfo=UTC))
    out = _sync(signed, batch("KIOSK_LIB_01", [make_record("att_y04", ts="2026-11-14T04:35:00Z")]), verbose=True)
    assert out["flags"] == []
    assert out["acks"][0]["verdict"] == "CONFIRMED"
    assert "ALERT_REVOKED_USER_ADMITTED" not in _alerts(out)


def test_Y05_closure_published_while_offline_is_schedule_mismatch(signed, services):
    def close_library(doc):
        doc["holidays"].append({"date": "2026-11-14", "name": "Emergency closure", "closed_zones": ["LIBRARY"],
                                "exempt_roles": ["staff"]})
    services.schedule.publish(close_library, "test:closure")
    out = _sync(signed, batch("KIOSK_LIB_01", [make_record("att_y05")]), verbose=True)
    assert [f["type"] for f in out["flags"]] == ["SCHEDULE_CHANGED"]
    assert "ALERT_SCHEDULE_MISMATCH" in _alerts(out)
    assert out["flags"][0]["detail"]["authoritative_result"] == "HOLIDAY"


def test_Y06_override_code_reuse_across_kiosks(signed):
    fb = {"method": "STAFF_OVERRIDE", "staff_id": "s_guard01", "code_id": "OVR-001"}
    first = _sync(signed, batch("KIOSK_LIB_01", [make_record("att_y06a", ts="2026-11-14T04:40:00Z", fallback=fb,
                                                             codes=["ACCESS_OK", "FALLBACK_OK", "OFFLINE_MODE"])]),
                  verbose=True)
    assert first["acks"][0]["verdict"] == "CONFIRMED"
    # OVR-001 is a publicly documented demo code the cloud never minted (stripped from every bundle): an edge that
    # honoured it is flagged (CA-04 "unknown override code"); nothing is published for it
    assert _alerts(first) == {"ALERT_OVERRIDE_USED", "ALERT_OFFLINE_POLICY_VIOLATION"}
    second = _sync(signed, batch("KIOSK_MAIN_01", [make_record(
        "att_y06b", kiosk="KIOSK_MAIN_01", zone="MAIN_GATE", ts="2026-11-14T05:10:00Z", fallback=fb,
        codes=["ACCESS_OK", "FALLBACK_OK", "OFFLINE_MODE"])]), verbose=True)
    reuse = next(a for a in second["alerts"] if a["alert"] == "ALERT_OVERRIDE_REUSE")
    assert reuse["detail"]["reused_by"] == "att_y06b" and reuse["detail"]["other_kiosk"] == "KIOSK_LIB_01"
    assert reuse["severity"] == "high"


def test_Y07_totp_step_replay_across_kiosks(signed):
    fb = {"method": "TOTP", "totp_step": 59109456}
    _sync(signed, batch("KIOSK_LIB_01", [make_record("att_y07a", fallback=fb,
                                                     codes=["ACCESS_OK", "FALLBACK_OK", "OFFLINE_MODE"])]))
    out = _sync(signed, batch("KIOSK_MAIN_01", [make_record("att_y07b", kiosk="KIOSK_MAIN_01", zone="MAIN_GATE",
                                                            fallback=fb,
                                                            codes=["ACCESS_OK", "FALLBACK_OK", "OFFLINE_MODE"])]),
                verbose=True)
    assert "ALERT_TOTP_REPLAY" in _alerts(out)


def test_Y08_spoof_burst_offline(signed):
    items = [make_record(f"att_y08_{i}", decision="DENY", user=None, candidate="u_3c4d",
                         codes=["SPOOF_DEVICE_DETECTED", "OFFLINE_MODE"], ts=f"2026-11-14T04:3{i}:00Z")
             for i in range(3)]
    out = _sync(signed, batch("KIOSK_LIB_01", items), verbose=True)
    assert [a["alert"] for a in out["alerts"]].count("ALERT_SPOOF_BURST") == 1
    assert "ALERT_TARGETED_SPOOF" in _alerts(out)  # candidate_user_id logged on BIO_FAIL (DECISION_POLICY §4)


def test_Y08_two_spoofs_do_not_burst(signed):
    items = [make_record(f"att_y08n_{i}", decision="DENY", user=None, codes=["SPOOF_MOIRE", "OFFLINE_MODE"],
                         ts=f"2026-11-14T04:3{i}:00Z") for i in range(2)]
    out = _sync(signed, batch("KIOSK_LIB_01", items), verbose=True)
    assert "ALERT_SPOOF_BURST" not in _alerts(out)


def test_Y09_clock_skew_alert_and_corrected_reevaluation(signed, services, clock):
    # server 04:45Z, kiosk clock 5 min behind (04:40Z). Revocation effective 04:37Z (server time).
    clock.set(datetime(2026, 11, 14, 4, 45, tzinfo=UTC))
    services.schedule.revoke(rtype="USER", target_id="u_3c4d", reason="ADMIN",
                             revoked_at=datetime(2026, 11, 14, 4, 37, tzinfo=UTC))
    rec = make_record("att_y09", ts="2026-11-14T04:35:00Z")  # kiosk clock -> really 04:40Z
    out = _sync(signed, batch("KIOSK_LIB_01", [rec], kiosk_now_utc="2026-11-14T04:40:00Z"), verbose=True)
    assert "ALERT_CLOCK_SKEW" in _alerts(out)
    assert [f["type"] for f in out["flags"]] == ["POST_HOC_REVOKED"]  # uncorrected 04:35Z would be CONFIRMED


def test_Y10_tombstone_raises_purged_unsynced(signed):
    tomb = {"type": "TOMBSTONE", "count": 4, "first_seq": 10, "last_seq": 13, "chain_head": "ab" * 32}
    out = _sync(signed, batch("KIOSK_LIB_01", [tomb]))
    assert out["accepted"] == ["TOMBSTONE:10-13"]
    assert out["flags"] == [{"attempt_id": "TOMBSTONE:10-13", "type": "RECORDS_PURGED_UNSYNCED"}]
    again = _sync(signed, batch("KIOSK_LIB_01", [tomb]))
    # a resend after a lost ack gets the same flag again (F15), without a second alert
    assert again["duplicates"] == ["TOMBSTONE:10-13"] and again["flags"] == out["flags"]


def test_Y11_revocation_reaches_kiosk_via_feed_and_signed_bundle(signed, services):
    _seq0, _ = services.schedule.revocations_since(0)
    services.schedule.revoke(rtype="USER", target_id="u_3c4d", reason="SUSPENDED")
    feed = signed.get(f"/v1/revocations?since={_seq0}").json()
    assert [i["target_id"] for i in feed["items"]] == ["u_3c4d"] and feed["revocation_seq"] == _seq0 + 1
    r = signed.get("/v1/schedule/KIOSK_LIB_01")
    bundle = r.json()
    assert verify_bundle(bundle, BUNDLE_KEY)
    assert bundle["users"]["u_3c4d"]["revoked"] is True
    from edge.policy.schedule import evaluate_schedule

    assert evaluate_schedule("u_3c4d", "LIBRARY", services.clock.now(), bundle,
                             services.thresholds.raw["schedule"]) == "REVOKED"


def test_online_allow_not_reevaluated_and_deny_has_no_flags(signed):
    out = _sync(signed, batch("KIOSK_LIB_01", [
        make_record("att_on1", mode="ONLINE"),
        make_record("att_off_deny", decision="DENY", codes=["SCHEDULE_OUTSIDE_WINDOW", "OFFLINE_MODE"])]),
        verbose=True)
    verdicts = {a["attempt_id"]: a["verdict"] for a in out["acks"]}
    assert verdicts == {"att_on1": "CONFIRMED", "att_off_deny": "NOT_REQUIRED"}
    assert out["flags"] == []


def test_offline_auto_allow_in_high_risk_zone_is_policy_violation(signed):
    out = _sync(signed, batch("KIOSK_SRV_01", [make_record("att_srv", kiosk="KIOSK_SRV_01", zone="SERVER_ROOM",
                                                           user="u_7a8b", ts="2026-11-14T04:35:00Z")]),
                verbose=True)
    assert "ALERT_OFFLINE_POLICY_VIOLATION" in _alerts(out)


def test_D06_modified_payload_breaks_chain(signed):
    k = "KIOSK_LIB_01"
    prev = genesis(k)
    items = []
    for i in range(1, 6):
        r = make_record(f"att_d06_{i}", seq=i, ts=f"2026-11-14T04:3{i}:00Z", prev_hash=prev)
        items.append(r)
        prev = r["record_hash"]
    clean = _sync(signed, batch(k, items[:2]), verbose=True)
    assert "ALERT_LOG_TAMPER" not in _alerts(clean)
    items[2]["scores"] = {"pad": 0.99}  # attacker edits record 3 on disk; kiosk re-signs at sync
    out = _sync(signed, batch(k, items[2:], chain_head=prev, chain_head_hmac=hmac_hex(KIOSK_KEY, prev.encode())),
                verbose=True)
    tamper = [a for a in out["alerts"] if a["alert"] == "ALERT_LOG_TAMPER"]
    assert tamper and tamper[0]["detail"]["seq"] == 3
    assert set(out["accepted"]) == {"att_d06_3", "att_d06_4", "att_d06_5"}  # ingested, flagged


def test_bad_chain_head_hmac_alerts(signed):
    out = _sync(signed, batch("KIOSK_LIB_01", [make_record("att_head")], chain_head="aa" * 32,
                              chain_head_hmac="00" * 32), verbose=True)
    assert "ALERT_LOG_TAMPER" in _alerts(out)


def test_hmac_invalid_item_rejected_not_stored(signed, services):
    bad = signed_item(make_record("att_badmac"))
    bad["decision"] = "ALLOW" if bad["decision"] == "DENY" else "DENY"  # tampered after signing
    body = {"kiosk_id": "KIOSK_LIB_01", "batch_id": "b_bad", "items": [bad]}
    out = _sync(signed, body)
    assert out["rejected"] == [{"idempotency_key": "att_badmac", "error": "HMAC_INVALID"}]
    assert services.kv.get("decisions", "att_badmac") is None


def test_images_or_embeddings_cannot_enter_the_ledger(signed):
    out = _sync(signed, batch("KIOSK_LIB_01", [make_record("att_img", frame_b64="A" * 2000),
                                               make_record("att_emb", embedding=[0.01] * 512)]))
    assert {r["idempotency_key"] for r in out["rejected"]} == {"att_img", "att_emb"}
    assert {r["error"] for r in out["rejected"]} == {"VALIDATION_ERROR"}


@pytest.mark.parametrize("mutate,status", [
    (lambda b: b.update(kiosk_id="KIOSK_MAIN_01"), 403),
    (lambda b: b.update(items=[signed_item(make_record(f"att_x{i}")) for i in range(51)]), 422),
    (lambda b: b.pop("items"), 422),
])
def test_envelope_validation(signed, mutate, status):
    body = batch("KIOSK_LIB_01", [make_record("att_env")])
    mutate(body)
    r = signed.post("/v1/sync", body, kiosk="KIOSK_LIB_01")
    assert r.status_code == status, r.text
    assert "error" in r.json()


def test_item_kiosk_mismatch_and_bad_fields_rejected(signed):
    out = _sync(signed, batch("KIOSK_LIB_01", [
        make_record("att_km", kiosk="KIOSK_MAIN_01"),
        {**make_record("att_dec"), "decision": "MAYBE"},
        {**make_record("att_ts"), "ts_utc": "2026-11-14T10:05:00"},  # naive -> ambiguous
    ]))
    assert {(r["idempotency_key"], r["error"]) for r in out["rejected"]} == {
        ("att_km", "KIOSK_MISMATCH"), ("att_dec", "VALIDATION_ERROR"), ("att_ts", "VALIDATION_ERROR")}
