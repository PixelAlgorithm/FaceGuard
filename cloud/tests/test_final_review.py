"""Final-review findings CA-01..CA-04 (cloud/app) and the request_id replay fix (probe rbac-e2e 10b)."""

from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from cloud.app.main import create_app
from cloud.app.services.kv import KVError
from cloud.app.services.schedule_service import CONSUMED_CODES, ScheduleConflict

from .conftest import ADMIN, Signed, batch, make_record

ADMIN_H = {"X-Admin-Token": ADMIN}


@pytest.fixture
def lenient(services):
    with TestClient(create_app(services=services), raise_server_exceptions=False) as c:
        yield Signed(c)


def _fail_once(monkeypatch, kv, method: str, ns: str) -> dict:
    real = getattr(kv, method)
    state = {"armed": True}

    def flaky(n, *a, **k):
        if n == ns and state["armed"]:
            state["armed"] = False
            raise KVError(f"injected {method} failure on {ns}")
        return real(n, *a, **k)

    monkeypatch.setattr(kv, method, flaky)
    return state


def _alerts(services) -> list[str]:
    return [it["alert"] for _, it in services.kv.list("alerts")]


# ------------------------------------------------------------------ CA-01 recoverable claim
def test_CA01_store_error_mid_reconcile_is_reconciled_on_the_resend(lenient, services, monkeypatch):
    services.schedule.revoke(rtype="USER", target_id="u_3c4d", reason="ADMIN",
                             revoked_at=datetime(2026, 11, 14, 3, 30, tzinfo=UTC))
    body = batch("KIOSK_LIB_01", [make_record("att_ca01")])
    _fail_once(monkeypatch, services.kv, "put", "alerts")
    assert lenient.post("/v1/sync", body).status_code >= 500
    again = lenient.post("/v1/sync", body).json()  # the kiosk resends the batch
    assert again["flags"] == [{"attempt_id": "att_ca01", "type": "POST_HOC_REVOKED"}], again
    assert "ALERT_REVOKED_USER_ADMITTED" in _alerts(services)
    assert services.kv.get("decisions", "KIOSK_LIB_01|att_ca01")["verdict"] == "DISCREPANCY"


def test_CA01_stale_pending_claim_is_taken_over(lenient, services, monkeypatch, clock):
    services.schedule.revoke(rtype="USER", target_id="u_3c4d", reason="ADMIN",
                             revoked_at=datetime(2026, 11, 14, 3, 30, tzinfo=UTC))
    body = batch("KIOSK_LIB_01", [make_record("att_ca01b")])
    _fail_once(monkeypatch, services.kv, "put", "alerts")
    _fail_once(monkeypatch, services.kv, "delete", "decisions")  # the roll-back fails too: PENDING stays
    assert lenient.post("/v1/sync", body).status_code >= 500
    assert services.kv.get("decisions", "KIOSK_LIB_01|att_ca01b")["verdict"] == "PENDING"
    clock.advance(minutes=5)
    again = lenient.post("/v1/sync", body).json()
    assert again["flags"] == [{"attempt_id": "att_ca01b", "type": "POST_HOC_REVOKED"}], again
    assert services.kv.get("decisions", "KIOSK_LIB_01|att_ca01b")["verdict"] == "DISCREPANCY"


# ------------------------------------------------------------------ CA-02 consumption is retried
def _rotate(c: Signed, staff: str = "s_guard01", dt: float = 3) -> str:
    r = c.post("/v1/admin/codes/rotate", {"staff_id": staff, "count": 1}, headers=ADMIN_H, now=time.time() + dt)
    assert r.status_code == 201, r.text
    return r.json()["codes"][0]["code_id"]


def _override(att: str, code_id: str, staff: str = "s_guard01") -> dict:
    return make_record(att, kiosk="KIOSK_MAIN_01", zone="MAIN_GATE", codes=["FALLBACK_OK"],
                       fallback={"method": "STAFF_OVERRIDE", "staff_id": staff, "code_id": code_id})


def test_CA02_failed_consumption_is_retried_on_the_next_sync(client, services, monkeypatch):
    main = Signed(client, kiosk="KIOSK_MAIN_01")
    code_id = _rotate(main)
    real = services.schedule.consume_code
    state = {"armed": True}

    def flaky(*a, **k):
        if state["armed"]:
            state["armed"] = False
            raise ScheduleConflict("lost 5 CAS rounds")
        return real(*a, **k)

    monkeypatch.setattr(services.schedule, "consume_code", flaky)
    assert main.post("/v1/sync", batch("KIOSK_MAIN_01", [_override("att_ca02", code_id)])).json()["accepted"]
    assert code_id not in [c["code_id"] for c in services.schedule.current()["doc"].get(CONSUMED_CODES) or []]
    main.post("/v1/sync", batch("KIOSK_MAIN_01", [], batch_id="b_next"), now=time.time() + 1)  # next sync
    assert code_id in [c["code_id"] for c in services.schedule.current()["doc"][CONSUMED_CODES]]


# ------------------------------------------------------------------ CA-03 upload cannot resurrect a consumed code
def test_CA03_upload_with_a_consumed_code_is_refused(client, services):
    from .test_bundle_upload import fresh_code, operator_bundle

    main = Signed(client, kiosk="KIOSK_MAIN_01")
    code_id = _rotate(main)
    main.post("/v1/sync", batch("KIOSK_MAIN_01", [_override("att_ca03", code_id)]))
    stale = {**fresh_code(1), "code_id": code_id}
    v = services.schedule.current()["version"] + 1
    r = main.request("PUT", "/v1/admin/schedule/KIOSK_MAIN_01", json_body=operator_bundle(v, codes=[stale]),
                     headers=ADMIN_H)
    assert r.status_code == 422 and r.json()["error"]["reason"] == "CODE_CONSUMED", r.text


# ------------------------------------------------------------------ CA-04 unknown code ids are never published
def test_CA04_unknown_code_id_is_alerted_not_published(client, services):
    main = Signed(client, kiosk="KIOSK_MAIN_01")
    v0 = services.schedule.current()["version"]
    out = main.post("/v1/sync?verbose=true", batch("KIOSK_MAIN_01", [_override("att_ca04", "OVR-NEVER-MINTED")])).json()
    assert out["accepted"] == ["att_ca04"]
    assert services.schedule.current()["version"] == v0
    assert not services.schedule.current()["doc"].get(CONSUMED_CODES)
    assert any(a["alert"] == "ALERT_OFFLINE_POLICY_VIOLATION" and a["detail"].get("reason") == "unknown override code"
               for a in out["alerts"])


def test_CA04_rotated_out_code_is_still_known_and_consumed(client, services):
    main = Signed(client, kiosk="KIOSK_MAIN_01")
    old = _rotate(main)
    _rotate(main, dt=5)  # replace_existing drops `old` from the master; offline kiosks may still hold it
    main.post("/v1/sync", batch("KIOSK_MAIN_01", [_override("att_ca04b", old)]))
    assert old in [c["code_id"] for c in services.schedule.current()["doc"][CONSUMED_CODES]]


@pytest.mark.parametrize("fb", [{"method": "STAFF_OVERRIDE", "staff_id": "s_guard01", "code_id": "x" * 65},
                                {"method": "STAFF_OVERRIDE", "staff_id": "S GUARD", "code_id": "OVR-1"},
                                {"method": ["STAFF_OVERRIDE"]}])
def test_CA04_fallback_fields_are_validated(signed, fb):
    rec = make_record("att_ca04c", fallback=fb, codes=["FALLBACK_OK"])
    out = signed.post("/v1/sync", batch("KIOSK_LIB_01", [rec])).json()
    assert out["accepted"] == [] and out["rejected"][0]["error"] == "VALIDATION_ERROR"


# ------------------------------------------------------------------ probe 10b: request_id makes retries distinct
def test_request_id_lets_two_identical_admin_calls_in_one_second_succeed(client, services):
    main = Signed(client, kiosk="KIOSK_MAIN_01")
    ts = time.time()
    a = main.post("/v1/admin/codes/rotate", {"staff_id": "s_guard01", "count": 1, "request_id": "req_aaaaaaaa"},
                  headers=ADMIN_H, now=ts)
    b = main.post("/v1/admin/codes/rotate", {"staff_id": "s_guard01", "count": 1, "request_id": "req_bbbbbbbb"},
                  headers=ADMIN_H, now=ts)
    assert a.status_code == 201 and b.status_code == 201, b.text
    rot = [e for e in services.schedule.audit_entries(20) if e["action"] == "CODES_ROTATE"]
    assert [e.get("request_id") for e in rot[-2:]] == ["req_aaaaaaaa", "req_bbbbbbbb"]


@pytest.mark.parametrize("path,method,body", [
    ("/v1/admin/codes/rotate", "POST", {"staff_id": "s_guard01"}),
    ("/v1/admin/revocations", "POST", {"type": "USER", "target_id": "u_1a2b"}),
    ("/v1/admin/users/u_3c4d/access", "PUT", {"role": "student"}),
    ("/v1/enroll/offline-record", "POST", {"user_id": "u_3c4d", "kiosk_id": "KIOSK_MAIN_01",
                                           "at": "2026-11-14T04:00:00Z", "template_count": 3, "model": "m"}),
])
def test_request_id_is_accepted_and_validated(client, path, method, body):
    main = Signed(client, kiosk="KIOSK_MAIN_01")
    ok = main.request(method, path, json_body={**body, "request_id": "abcDEF_-12"}, headers=ADMIN_H)
    assert ok.status_code < 400, ok.text
    bad = main.request(method, path, json_body={**body, "request_id": "no spaces!"}, headers=ADMIN_H,
                       now=time.time() + 1)
    assert bad.status_code == 422, bad.text
