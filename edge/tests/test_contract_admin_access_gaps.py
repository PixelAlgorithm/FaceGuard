"""Audit gap tests for the Users & Access admin routes (API v1.4 §3.18, docs/contracts/admin_access.examples.json).

1. R-L strict booleans: consent / restore must be JSON true/false ("true", 1, 0 -> 422, the cloud is never called).
2. L3: POST /v1/admin/bundle/refresh with connectivity OFFLINE but NOT forced and the cloud down is attempted and
   fails as 503 CLOUD_UNAVAILABLE reason CLOUD_ERROR (not OFFLINE, which is only the forced case).
3. R-K: rotate codes[].code_id / code_length / valid_until are nullable (the replay is the contract example
   minted_fields_unknown in test_contract_admin_access.py; here: the strict model accepts the nulls).
4. R-M: staff_id (rotate) and reason (revoke) are matched as sent: leading / trailing whitespace is a 422, never
   stripped and forwarded.
Scratch app + contract-shaped fake cloud (edge/tests/contract_cloud.py); never the live :8000 edge.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from edge.access_models import AccessUpdate, CodesRotateRequest, RevokeRequest, RotateCodesResult
from edge.tests.contract_cloud import ADMIN

PUT = "/v1/admin/access/users/u_3c4d"


def _assert_422(r, field: str) -> None:
    assert r.status_code == 422, r.text
    err = r.json()["error"]
    assert err["code"] == "VALIDATION_ERROR" and err["attempt_id"] is None
    assert any(list(d["loc"])[-1] == field for d in err["details"]), err["details"]


# ================================================================== 1. R-L StrictBool on the edge
@pytest.mark.parametrize("body", [
    pytest.param({"role": "student", "consent": "true"}, id="consent-string-true"),
    pytest.param({"role": "student", "consent": "false"}, id="consent-string-false"),
    pytest.param({"role": "student", "consent": 1}, id="consent-int-1"),
    pytest.param({"role": "student", "consent": 0}, id="consent-int-0"),
    pytest.param({"role": "student", "consent": True, "restore": "true"}, id="restore-string-true"),
    pytest.param({"role": "student", "consent": True, "restore": 1}, id="restore-int-1"),
])
def test_put_access_rejects_non_json_booleans(make_env, body):
    env = make_env()
    r = env.c.put(PUT, json=body, headers=ADMIN)
    field = "restore" if "restore" in body else "consent"
    _assert_422(r, field)
    assert env.cloud.calls("PUT", "/v1/admin/users/") == []  # rejected before any cloud write


def test_put_access_accepts_json_booleans(make_env):
    """Control for the rejections above: real JSON booleans pass the same handler."""
    env = make_env()
    r = env.c.put(PUT, json={"role": "student", "consent": True}, headers=ADMIN)
    assert r.status_code == 200, r.text
    assert len(env.cloud.calls("PUT", "/v1/admin/users/")) == 1


@pytest.mark.parametrize("value", ["true", "false", 1, 0, "yes", "on"])
def test_access_update_model_is_strict_for_consent_and_restore(value):
    with pytest.raises(ValidationError):
        AccessUpdate.model_validate({"role": "student", "consent": value})
    with pytest.raises(ValidationError):
        AccessUpdate.model_validate({"role": "student", "consent": True, "restore": value})


# ================================================================== 2. refresh, OFFLINE not forced, cloud down
def test_refresh_offline_not_forced_with_cloud_down_is_cloud_error(make_env):
    env = make_env()
    rt = env.ctx.runtime
    installed = rt.bundles.version
    env.cloud.down = True
    for _ in range(50):  # natural connectivity loss: heartbeats miss until the monitor says OFFLINE
        assert rt.heartbeat() is False
        if rt.mode() == "OFFLINE":
            break
    assert rt.mode() == "OFFLINE", rt.mode_status()
    assert rt.monitor.forced is False and rt.mode_status().get("reason") != "forced"  # natural, not forced
    r = env.c.post("/v1/admin/bundle/refresh", json={}, headers=ADMIN)
    assert r.status_code == 503, r.text
    err = r.json()["error"]
    assert (err["code"], err["reason"]) == ("CLOUD_UNAVAILABLE", "CLOUD_ERROR"), err
    assert err["attempt_id"] is None and err["installed_version"] == installed
    assert rt.bundles.version == installed  # the last valid bundle is kept


# ================================================================== 3. R-K nullable minted fields (model level)
def test_rotate_result_model_accepts_null_code_id_length_and_validity():
    RotateCodesResult.model_validate({
        "staff_id": "s_guard01", "codes": [{"code_id": None, "code": "40718325"}], "code_length": None,
        "valid_until": None, "one_time": True, "dropped_code_ids": [], "warning": "shown once",
        "cloud_bundle_version": None,
        "bundle": {"previous_version": 49, "installed_version": 49, "changed": False, "result": "failed",
                   "error": "x", "applied": False},
        "warnings": []})


# ================================================================== 4. R-M whitespace is rejected, not stripped
PADDED_STAFF = [" s_guard01", "s_guard01 ", "\ts_guard01", "s_guard01\n", " s_guard01 "]
PADDED_REASON = [" ADMIN", "ADMIN ", "ADMIN\n", "\tADMIN", " ADMIN "]


@pytest.mark.parametrize("staff_id", PADDED_STAFF)
def test_rotate_rejects_padded_staff_id(make_env, staff_id):
    with pytest.raises(ValidationError):
        CodesRotateRequest.model_validate({"staff_id": staff_id})
    env = make_env()
    r = env.c.post("/v1/admin/access/codes/rotate", json={"staff_id": staff_id, "count": 2}, headers=ADMIN)
    _assert_422(r, "staff_id")
    assert env.cloud.calls("POST", "/v1/admin/codes/rotate") == []  # nothing minted for a stripped id


@pytest.mark.parametrize("reason", PADDED_REASON)
def test_revoke_rejects_padded_reason(make_env, reason):
    with pytest.raises(ValidationError):
        RevokeRequest.model_validate({"reason": reason})
    env = make_env()
    r = env.c.post("/v1/admin/access/users/u_3c4d/revoke", json={"reason": reason}, headers=ADMIN)
    _assert_422(r, "reason")
    assert env.cloud.calls("POST", "/v1/admin/revocations") == []
    assert env.cloud.status("u_3c4d") == "ACTIVE"


def test_unpadded_staff_id_and_reason_are_accepted(make_env):
    """Control: the same values without padding go through (so the 422s above are the whitespace)."""
    env = make_env()
    r = env.c.post("/v1/admin/access/codes/rotate", json={"staff_id": "s_guard01", "count": 2}, headers=ADMIN)
    assert r.status_code == 200, r.text
    assert env.cloud.calls("POST", "/v1/admin/codes/rotate")[0]["json"]["staff_id"] == "s_guard01"
    r = env.c.post("/v1/admin/access/users/u_3c4d/revoke", json={"reason": "ADMIN"}, headers=ADMIN)
    assert r.status_code == 200, r.text
    assert env.cloud.calls("POST", "/v1/admin/revocations")[0]["json"]["reason"] == "ADMIN"


# ================================================================== 5. read windows mirror the schedule evaluator
@pytest.mark.parametrize("window", [
    pytest.param({"start": "08:00", "end": "18:00"}, id="days-missing"),
    pytest.param({"days": None, "start": "08:00", "end": "18:00"}, id="days-null"),
    pytest.param({"days": [], "start": "08:00", "end": "18:00"}, id="days-empty"),
    pytest.param({"days": ["MON", "FRI"], "start": "08:00", "end": "18:00"}, id="days-listed"),
])
def test_windows_read_days_match_what_the_policy_evaluates(window):
    """The admin view must show the days on which edge/policy/schedule.py applies the window: missing / null
    days = every day (shown as all seven), explicit [] = no day (kept empty)."""
    from datetime import date, timedelta

    from edge.access import _windows_read, role_defaults
    from edge.access_models import DAYS, WindowRead
    from edge.policy.schedule import _applies_on

    (shown,) = _windows_read([window])
    WindowRead.model_validate(shown)
    monday = date(2026, 11, 16)
    applies = [DAYS[(monday + timedelta(days=i)).weekday()] for i in range(7)
               if _applies_on(window, monday + timedelta(days=i))]
    assert shown["days"] == applies
    if window.get("days") is None:
        assert shown["days"] == ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]
    rd = role_defaults({"staff": {"zones": ["MAIN_GATE"], "windows": {"MAIN_GATE": [window]}}})
    assert rd["staff"]["windows"]["MAIN_GATE"][0]["days"] == applies
