"""SC2 cloud fixes (design v2 §E): staff_id owner kiosk, active-code cap, fleet-wide consumption of synced override
codes (signed consumed_code_ids), per-kiosk code scoping and bundle ETag freshness (re-issue after ttl/2)."""

from __future__ import annotations

import time
from datetime import timedelta

import pytest

from cloud.app.services.schedule_service import CONSUMED_CODES, STAFF_REGISTRY, verify_bundle

from .conftest import ADMIN, BUNDLE_KEY, Signed, batch, etag, make_record

ADMIN_H = {"X-Admin-Token": ADMIN}


@pytest.fixture
def main(client) -> Signed:
    return Signed(client, kiosk="KIOSK_MAIN_01")


@pytest.fixture
def lib(client) -> Signed:
    return Signed(client, kiosk="KIOSK_LIB_01")


def rotate(c: Signed, staff: str = "s_guard01", count: int = 2, _dt: float = 0, **kw):
    """_dt shifts the signing time: identical requests within one second would be refused as replays."""
    return c.post("/v1/admin/codes/rotate", {"staff_id": staff, "count": count, **kw}, headers=ADMIN_H,
                  now=time.time() + _dt)


def bundle_of(c: Signed, **headers) -> tuple[dict, str, int]:
    r = c.get(f"/v1/schedule/{c.kiosk}", headers=headers or None)
    return (r.json() if r.status_code == 200 else {}), r.headers.get("etag", ""), r.status_code


# ------------------------------------------------------------------ staff_id owner kiosk + cap
def test_staff_id_belongs_to_the_first_rotating_kiosk(main, lib, services):
    assert rotate(main).status_code == 201
    r = rotate(lib)
    assert r.status_code == 409 and r.json()["error"]["reason"] == "STAFF_ID_TAKEN", r.text
    assert services.schedule.current()["doc"][STAFF_REGISTRY]["s_guard01"]["owner_kiosk_id"] == "KIOSK_MAIN_01"
    assert rotate(main, _dt=1).status_code == 201  # the owner may rotate again
    assert rotate(lib, "s_guard02").status_code == 201  # another staff id is free


def test_codes_reach_only_the_owner_kiosk_bundle(main, lib):
    minted = rotate(main).json()["codes"]
    ids = {c["code_id"] for c in minted}
    main_codes = {c["code_id"] for c in bundle_of(main)[0]["override_codes"]["codes"]}
    lib_codes = {c["code_id"] for c in bundle_of(lib)[0]["override_codes"]["codes"]}
    assert ids <= main_codes and not ids & lib_codes
    entries = [c for c in bundle_of(main)[0]["override_codes"]["codes"] if c["code_id"] in ids]
    assert all(c["kiosk_ids"] == ["KIOSK_MAIN_01"] for c in entries)  # signed per-code scope (edge F09)


def test_at_most_ten_active_codes_per_staff_id(main):
    assert rotate(main, count=6, replace_existing=False).status_code == 201
    r = rotate(main, count=5, replace_existing=False, _dt=1)
    assert r.status_code == 422 and r.json()["error"]["reason"] == "TOO_MANY_ACTIVE_CODES", r.text
    assert rotate(main, count=4, replace_existing=False, _dt=2).status_code == 201  # exactly 10
    assert rotate(main, count=10, _dt=3).status_code == 201  # replace_existing drops the previous ones first


def test_replace_keeps_the_staff_registry(main, services):
    rotate(main)
    doc = services.schedule.doc()
    doc.pop(STAFF_REGISTRY)
    assert main.request("PUT", "/v1/admin/schedule", json_body=doc, headers=ADMIN_H).status_code == 200
    assert services.schedule.current()["doc"][STAFF_REGISTRY]["s_guard01"]["owner_kiosk_id"] == "KIOSK_MAIN_01"


# ------------------------------------------------------------------ consumed codes
def test_synced_override_consumes_the_code_fleet_wide(main, services, clock):
    code_id = rotate(main).json()["codes"][0]["code_id"]
    v0 = services.schedule.current()["version"]
    fb = {"method": "STAFF_OVERRIDE", "staff_id": "s_guard01", "code_id": code_id}
    rec = make_record("att_ovr1", kiosk="KIOSK_MAIN_01", zone="MAIN_GATE", fallback=fb, codes=["FALLBACK_OK"])
    assert main.post("/v1/sync", batch("KIOSK_MAIN_01", [rec])).json()["accepted"] == ["att_ovr1"]
    doc = services.schedule.current()["doc"]
    assert services.schedule.current()["version"] == v0 + 1
    assert code_id not in {c["code_id"] for c in doc["override_codes"]["codes"]}
    assert [c["code_id"] for c in doc[CONSUMED_CODES]] == [code_id]
    b, _, _ = bundle_of(main)
    assert verify_bundle(b, BUNDLE_KEY) and b["consumed_code_ids"] == [code_id]  # signed array
    lib_b, _, _ = bundle_of(Signed(main.c, kiosk="KIOSK_LIB_01"))
    assert lib_b["consumed_code_ids"] == [code_id]  # every kiosk refuses it, not only the owner
    # a resend of the same record publishes nothing new
    main.post("/v1/sync", batch("KIOSK_MAIN_01", [rec]), now=time.time() + 1)
    assert services.schedule.current()["version"] == v0 + 1
    clock.advance(hours=48)  # past the code's latest possible valid_until: no longer listed
    b2, _, _ = bundle_of(main)
    assert "consumed_code_ids" not in b2


def test_override_used_under_another_staff_id_is_a_violation(main):
    code_id = rotate(main).json()["codes"][0]["code_id"]
    fb = {"method": "STAFF_OVERRIDE", "staff_id": "s_guard02", "code_id": code_id}
    rec = make_record("att_ovr2", kiosk="KIOSK_MAIN_01", zone="MAIN_GATE", fallback=fb, codes=["FALLBACK_OK"])
    out = main.post("/v1/sync?verbose=true", batch("KIOSK_MAIN_01", [rec])).json()
    assert out["acks"][0]["verdict"] == "DISCREPANCY"
    assert any(a["alert"] == "ALERT_OFFLINE_POLICY_VIOLATION" for a in out["alerts"])


# ------------------------------------------------------------------ ETag freshness (EO-01)
def test_etag_is_version_and_issue_and_reissued_after_half_ttl(main, services, clock):
    b1, tag1, _ = bundle_of(main)
    assert tag1 == etag(42)
    assert bundle_of(main, **{"If-None-Match": tag1})[2] == 304
    clock.advance(hours=1)  # same version, issue still young: stable stamps, same ETag
    b2, tag2, _ = bundle_of(main)
    assert tag2 == tag1 and b2["issued_at"] == b1["issued_at"] and b2["signature"] == b1["signature"]
    ttl = min(services.settings.bundle_ttl_hours, services.thresholds.bundle_max_staleness_hours)
    clock.advance(hours=ttl / 2)  # older than ttl/2: a kiosk holding it gets a fresh issue, not a 304
    b3, tag3, status = bundle_of(main, **{"If-None-Match": tag1})
    assert status == 200 and tag3 != tag1 and b3["bundle_version"] == 42 and verify_bundle(b3, BUNDLE_KEY)
    assert b3["issued_at"] > b1["issued_at"]


def test_bare_version_tag_is_not_a_match(main):
    assert bundle_of(main, **{"If-None-Match": '"42"'})[2] == 200


def test_uploaded_bundle_etag_uses_its_own_issue(main):
    from .test_bundle_upload import operator_bundle

    up = operator_bundle(46, issued=main_t0() - timedelta(minutes=5))
    assert main.request("PUT", "/v1/admin/schedule/KIOSK_MAIN_01", json_body=up, headers=ADMIN_H).status_code == 200
    _, tag, _ = bundle_of(main)
    assert tag == etag(46, main_t0() - timedelta(minutes=5))


def main_t0():
    from .conftest import T0

    return T0


def test_code_of_another_kiosk_is_flagged_and_not_consumed(main, services):
    code_id = rotate(main).json()["codes"][0]["code_id"]
    fb = {"method": "STAFF_OVERRIDE", "staff_id": "s_guard01", "code_id": code_id}
    rec = make_record("att_ovr3", fallback=fb, codes=["FALLBACK_OK"])  # synced by KIOSK_LIB_01
    out = Signed(main.c).post("/v1/sync?verbose=true", batch("KIOSK_LIB_01", [rec])).json()
    assert out["acks"][0]["verdict"] == "DISCREPANCY"
    assert any(a["detail"].get("reason") == "override code bound to another kiosk" for a in out["alerts"])
    assert code_id in {c["code_id"] for c in services.schedule.current()["doc"]["override_codes"]["codes"]}
