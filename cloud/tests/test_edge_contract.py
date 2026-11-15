"""Contract tests that drive the cloud API with the policy-engine's REAL edge code (edge/offline/*), so the
two sides cannot drift: request signing, bundle verification, sync items + hash chain, response parsing.
Key convention: HMAC keys are the .env strings encoded as UTF-8 (not hex-decoded)."""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime

import pytest

from .conftest import API_KEY, BUNDLE_KEY, KIOSK_KEY

signing = pytest.importorskip("edge.offline.signing")
bundle_mod = pytest.importorskip("edge.offline.bundle")
store = pytest.importorskip("edge.offline.store")
sync_mod = pytest.importorskip("edge.offline.sync")

KEY = KIOSK_KEY.encode("utf-8")


def _edge_request(client, method: str, path: str, body: bytes = b"", query: str = "", headers: dict | None = None):
    h = signing.sign_request(method, path, body, kiosk_id="KIOSK_LIB_01", kiosk_key=KEY, api_key=API_KEY)
    h.update(headers or {})
    if body:
        h["Content-Type"] = "application/json"
    return client.request(method, path + (f"?{query}" if query else ""), content=body, headers=h)


def _chain(n: int, kiosk: str = "KIOSK_LIB_01", start_ts: int = 30) -> list[dict]:
    """Records exactly as DecisionLog.append_final builds them (RECORD_FIELDS + seq/prev/record hash)."""
    prev = store.genesis_hash(kiosk)
    out = []
    for seq in range(1, n + 1):
        rec = {"attempt_id": f"att_edge_{seq}", "kiosk_id": kiosk, "zone": "LIBRARY",
               "ts_utc": f"2026-11-14T04:{start_ts + seq:02d}:00Z", "user_id": "u_3c4d", "candidate_user_id": None,
               "decision": "ALLOW", "reason_codes": ["ACCESS_OK", "OFFLINE_MODE"], "resolved_codes": [],
               "scores": {"pad": 0.93, "match": 0.72}, "fallback": None, "schedule_version": 42,
               "cache_state": "FRESH", "mode": "OFFLINE"}
        rec["seq"], rec["prev_hash"] = seq, prev
        rec["record_hash"] = store.compute_record_hash(prev, rec)
        prev = rec["record_hash"]
        out.append(rec)
    return out


def _body(items: list[dict], head: str) -> bytes:
    body = {"kiosk_id": "KIOSK_LIB_01", "batch_id": "b_edge", "kiosk_now_utc": "2026-11-14T04:35:00Z",
            "chain_head": head, "chain_head_hmac": hmac.new(KEY, head.encode(), hashlib.sha256).hexdigest(),
            "items": items}
    return bundle_mod.canonical_json(body)


def test_edge_request_signer_is_accepted(client):
    r = _edge_request(client, "GET", "/v1/revocations?since=0")  # KioskAuth signs raw_path (path + "?query")
    assert r.status_code == 200, r.text


def test_cloud_bundle_verifies_with_edge_verifier(client):
    r = _edge_request(client, "GET", "/v1/schedule/KIOSK_LIB_01")
    b = r.json()
    assert bundle_mod.verify_bundle(b, BUNDLE_KEY.encode("utf-8")) is True
    assert "KIOSK_LIB_01" in b["kiosks"] and "KIOSK_LIB_01" in b["scope"]["kiosk_ids"]  # BundleStore._acceptable
    inm = {"If-None-Match": r.headers["etag"]}  # the edge stores and resends the full ETag it received
    r2 = _edge_request(client, "GET", "/v1/schedule/KIOSK_LIB_01", headers=inm)
    assert r2.status_code == 304
    derived = getattr(sync_mod, "derived_etag", None)
    if derived is not None:  # after a restart the edge derives it from the installed bundle: same value
        assert derived(b) == r.headers["etag"]


def test_edge_sync_items_accepted_idempotent_and_chain_clean(client):
    recs = _chain(4)
    tomb = {"type": "TOMBSTONE", "kiosk_id": "KIOSK_LIB_01", "count": 2, "first_seq": 5, "last_seq": 6,
            "chain_head": recs[-1]["record_hash"], "purged_at": "2026-11-15T05:00:00Z", "tombstone_id": "tomb_5_6"}
    items = sync_mod.build_items(recs, [tomb], KEY)
    body = _body(items, recs[-1]["record_hash"])
    r = _edge_request(client, "POST", "/v1/sync", body)
    assert r.status_code == 200, r.text
    accepted, duplicates, rejected, flags = sync_mod._parse_sync_response(r.json())
    # edge tombstone item = {type, count, first_seq, last_seq, chain_head, hmac} (no key) -> server key
    # "TOMBSTONE:<first>-<last>"; the edge acks its tombstones unless a rejected entry has idempotency_key null
    assert sorted(accepted) == sorted([x["attempt_id"] for x in recs] + ["TOMBSTONE:5-6"]) and rejected == []
    assert flags == [{"attempt_id": "TOMBSTONE:5-6", "type": "RECORDS_PURGED_UNSYNCED"}]
    verbose = _edge_request(client, "POST", "/v1/sync?verbose=true", body).json()
    assert "ALERT_LOG_TAMPER" not in {a["alert"] for a in verbose["alerts"]}
    again = _edge_request(client, "POST", "/v1/sync", body).json()
    assert again["accepted"] == [] and sorted(again["duplicates"]) == sorted(accepted)


def test_edge_rejected_tombstone_has_null_key_so_edge_keeps_it(client):
    tomb = {"tombstone_id": "t1", "count": 1, "first_seq": 9, "last_seq": 9, "chain_head": "ab" * 32}
    items = sync_mod.build_items([], [tomb], b"wrong-key")  # bad HMAC
    r = _edge_request(client, "POST", "/v1/sync", _body(items, "ab" * 32))
    assert r.json()["rejected"] == [{"idempotency_key": None, "error": "HMAC_INVALID"}]


def test_edge_tampered_record_raises_log_tamper(client):
    recs = _chain(3, start_ts=40)
    recs[1]["scores"] = {"pad": 0.99, "match": 0.99}  # edited on disk after hashing; kiosk re-signs at sync
    items = sync_mod.build_items(recs, [], KEY)
    r = _edge_request(client, "POST", "/v1/sync?verbose=true", _body(items, recs[-1]["record_hash"]))
    tamper = [a for a in r.json()["alerts"] if a["alert"] == "ALERT_LOG_TAMPER"]
    assert tamper and tamper[0]["detail"]["seq"] == 2


def test_edge_post_hoc_revocation_flag_reaches_parser(client, services):
    services.schedule.revoke(rtype="USER", target_id="u_3c4d", reason="ADMIN",
                             revoked_at=datetime(2026, 11, 14, 3, 30, tzinfo=UTC))
    recs = _chain(1, start_ts=50)
    r = _edge_request(client, "POST", "/v1/sync", _body(sync_mod.build_items(recs, [], KEY), recs[-1]["record_hash"]))
    _a, _d, _r, flags = sync_mod._parse_sync_response(r.json())
    assert flags == [{"attempt_id": "att_edge_1", "type": "POST_HOC_REVOKED"}]
