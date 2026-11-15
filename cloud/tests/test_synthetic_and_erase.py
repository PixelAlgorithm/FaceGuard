"""Round-4 hygiene fixes: (a) synthetic flag on ledger items + metric dimension + admin aggregates exclude it,
(b) erase only enrolled users (schedule-only user -> 404, no revocation), (c) Rekognition InvalidParameter -> 4xx."""

from __future__ import annotations

import base64

from cloud.app.services.faces import FaceError
from cloud.tools.backfill_metrics import datums, plan, publish
from cloud.tools.fakeimg import make_fake_jpeg

from .conftest import ADMIN, Signed, batch, make_record

ADM = {"X-Admin-Token": ADMIN}


def _sync(signed: Signed, items: list[dict], kiosk: str = "KIOSK_LIB_01"):
    r = signed.post("/v1/sync", batch(kiosk, items), kiosk=kiosk)
    assert r.status_code == 200, r.text
    return r.json()


def test_synthetic_flag_explicit_and_prefix(signed, services):
    _sync(signed, [make_record("att_real_1"),
                   make_record("att_flagged_1", synthetic=True),
                   make_record("att_smoke_abc_0")])
    rows = {k.split("|", 1)[1]: v for k, v in services.kv.list("decisions")}  # keys are <kiosk_id>|<attempt_id>
    assert rows["att_real_1"]["synthetic"] is False
    assert rows["att_flagged_1"]["synthetic"] is True and rows["att_smoke_abc_0"]["synthetic"] is True
    dims = [(r["name"], r["dims"].get("Synthetic")) for r in services.metrics.records
            if r["name"] in {"Decisions", "SyncItems"}]
    assert ("Decisions", "false") in dims and dims.count(("Decisions", "true")) == 2
    assert all(s in {"true", "false"} for _, s in dims)  # every decision/sync metric carries the dimension


def test_admin_aggregates_exclude_synthetic_by_default(signed):
    _sync(signed, [make_record("att_real_2"), make_record("att_test_x", synthetic=True)])
    r = signed.get("/v1/admin/decisions", headers=ADM).json()
    assert [i["attempt_id"] for i in r["items"]] == ["att_real_2"]
    r_all = signed.get("/v1/admin/decisions?include_synthetic=true", headers=ADM).json()
    assert {i["attempt_id"] for i in r_all["items"]} == {"att_real_2", "att_test_x"}
    st = signed.get("/v1/admin/stats", headers=ADM).json()
    assert st["count"] == 1 and st["synthetic_excluded"] == 1 and st["by_decision"] == {"ALLOW": 1}


def test_synthetic_alerts_tagged_and_hidden_and_never_feed_burst(signed, services):
    spoof = [make_record(f"att_test_s{i}", decision="DENY", user=None, candidate="u_3c4d",
                         codes=["SPOOF_DEVICE_DETECTED", "OFFLINE_MODE"], ts=f"2026-11-14T04:3{i}:00Z")
             for i in range(3)]
    out = signed.post("/v1/sync?verbose=true", batch("KIOSK_LIB_01", spoof)).json()
    assert {a["alert"] for a in out["alerts"]} == {"ALERT_TARGETED_SPOOF"}  # no ALERT_SPOOF_BURST from tests
    assert all(a["synthetic"] for a in out["alerts"])
    assert services.kv.list("spoof") == []
    assert signed.get("/v1/admin/alerts", headers=ADM).json()["items"] == []
    assert len(signed.get("/v1/admin/alerts?include_synthetic=true", headers=ADM).json()["items"]) == 3


def test_erase_schedule_only_user_is_404_and_changes_nothing(signed, services):
    seq0, _ = services.schedule.revocations_since(0)
    v0 = services.schedule.current()["version"]
    r = signed.delete("/v1/enroll/u_3c4d")  # in the schedule, never enrolled (the test-fixture incident)
    assert r.status_code == 404 and r.json()["error"]["code"] == "NOT_FOUND"
    assert services.schedule.revocations_since(0)[0] == seq0  # no revocation broadcast
    assert services.schedule.current()["version"] == v0 and "u_3c4d" in services.schedule.doc()["users"]


def test_erase_enrolled_user_still_works(signed, services):
    img = base64.b64encode(make_fake_jpeg("u_3c4d")).decode()
    body = {"user_id": "u_3c4d", "display_name": "Priya N.", "email": "p@example.org", "groups": ["student"],
            "consent": True, "consent_version": "v1", "images_b64": [img]}
    assert signed.post("/v1/enroll", body).status_code == 201
    r = signed.delete("/v1/enroll/u_3c4d")
    assert r.status_code == 200 and r.json()["erased"] is True


def test_enroll_invalid_parameter_is_422_not_503(signed, services):
    def bad(*_a, **_k):
        raise FaceError("INVALID_PARAMETER", "Requested image should have a minimum width of 80")

    services.faces.index_face = bad
    body = {"user_id": "u_x", "display_name": "X", "email": "x@example.org", "consent": True, "consent_version": "v1",
            "images_b64": [base64.b64encode(make_fake_jpeg("u_x")).decode()]}
    r = signed.post("/v1/enroll", body)
    assert r.status_code == 422 and r.json()["error"]["code"] == "VALIDATION_ERROR"


def test_backfill_plan_skips_synthetic_and_is_once_only(signed, services):
    _sync(signed, [make_record("att_real_9"), make_record("att_smoke_q_0")])
    dec, items, alerts = plan(services.kv, "2099-01-01T00:00:00Z")
    assert sum(dec.values()) == 1 and sum(items.values()) == 1
    data = datums(dec, items, alerts)
    assert all({"Name": "Synthetic", "Value": "false"} in d["Dimensions"] for d in data)

    class CW:
        calls = 0

        def put_metric_data(self, **kw):
            CW.calls += 1

    assert publish(CW(), services.kv, data) == len(data) and CW.calls == 1
    try:
        publish(CW(), services.kv, data)
        raise AssertionError("second backfill must refuse")
    except SystemExit:
        pass
