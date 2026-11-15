"""Cloud side of the canonical admin-access contract (docs/API.md v1.4 §4.9a / §4.3,
docs/contracts/admin_access.examples.json, routes `cloud.*`).

How the file is used (its own `how_to_test`):
- valid examples: request.body validates against the cloud request model; response.body parses into the cloud
  response model (extra="forbid": no field lost or invented). Then the example is replayed against the app in the
  example's state and the real response must parse into the same model and carry the same keys.
- error examples: request_invalid=true -> the request model (body / path / query) rejects it and the app answers
  422 VALIDATION_ERROR without a reason; request_invalid=false -> the state named in `state` is set up and the
  app's status, error.code and error.reason must match (message is informative text only).

Hermetic: in-memory store, fake face backend, FixedClock; the signature window uses real time on both sides.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from urllib.parse import urlencode

import pytest
from pydantic import BaseModel, ValidationError

from cloud.app import schemas as S
from cloud.app.services import schedule_service as sched_mod
from cloud.tools.fakeimg import make_fake_jpeg

from .conftest import ADMIN, Signed

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads((ROOT / "docs" / "contracts" / "admin_access.examples.json").read_text(encoding="utf-8"))
ROUTES = {r["id"]: r for r in CONTRACT["routes"] if r["side"] == "cloud"}
KIOSK = "KIOSK_MAIN_01"

REQUEST_MODELS: dict[str, type[BaseModel] | None] = {
    "cloud.admin.users.list": None,
    "cloud.admin.access.put": S.AccessUpdateRequest,
    "cloud.admin.revocations.post": S.AdminRevokeRequest,
    "cloud.admin.codes.rotate": S.CodesRotateRequest,
    "cloud.revocations.feed": None,
    "cloud.admin.audit": None,
}
RESPONSE_MODELS: dict[str, type[BaseModel]] = {
    "cloud.admin.users.list": S.AdminUsersResponse,
    "cloud.admin.access.put": S.AccessPutResponse,
    "cloud.admin.revocations.post": S.AdminRevokeResponse,
    "cloud.admin.codes.rotate": S.CodesRotateResponse,
    "cloud.revocations.feed": S.RevocationsResponse,
    "cloud.admin.audit": S.AuditResponse,
}
PATH_PATTERNS = {"user_id": S.ADMIN_USER_ID}
QUERY_LIMITS = {"cloud.admin.audit": {"limit": (1, 500)}}


def _valid(route_id: str):
    return [pytest.param(route_id, ex, id=f"{route_id}:{ex['name']}") for ex in ROUTES[route_id]["examples"]]


def _errors(route_id: str, invalid: bool):
    return [pytest.param(route_id, er, id=f"{route_id}:{er['name']}") for er in ROUTES[route_id]["errors"]
            if bool(er["request_invalid"]) is invalid]


ALL_VALID = [p for rid in ROUTES for p in _valid(rid)]
ALL_INVALID = [p for rid in ROUTES for p in _errors(rid, True)]
ALL_STATE_ERRORS = [p for rid in ROUTES for p in _errors(rid, False)]


# ------------------------------------------------------------------ static: the file vs the cloud models
def test_contract_covers_exactly_the_cloud_routes():
    assert CONTRACT["api_version"] == "v1.4"
    assert set(ROUTES) == set(REQUEST_MODELS) == set(RESPONSE_MODELS)


def test_field_limits_are_the_cloud_limits():
    fl = CONTRACT["field_limits"]
    assert fl["user_id"] == S.ADMIN_USER_ID and fl["staff_id"] == S.STAFF_ID
    assert fl["actor"]["pattern"] == S.ACTOR and fl["revoke_reason"]["pattern"] == S.REVOKE_REASON
    assert fl["role"]["pattern"] == S.ROLE and fl["zone"]["pattern"] == S.ZONE
    assert fl["time_write"] == S.HHMM and fl["display"]["max_length"] == S.DISPLAY_MAX
    assert fl["revoke_reason"]["default"] == S.AdminRevokeRequest.model_fields["reason"].default
    assert fl["revoke_reason"]["forbidden"] == ["ERASED"]
    count = S.CodesRotateRequest.model_fields["count"]
    lo = next(m.ge for m in count.metadata if getattr(m, "ge", None) is not None)
    hi = next(m.le for m in count.metadata if getattr(m, "le", None) is not None)
    assert (fl["rotate_count"]["min"], fl["rotate_count"]["max"], fl["rotate_count"]["default"]) == (lo, hi,
                                                                                                    count.default)
    assert S.AccessUpdateRequest.model_fields["zones_add"].metadata[0].max_length == fl["zones_add_max"]
    assert CONTRACT["enums"]["user_status"] == list(S.UserStatus.__args__)
    assert (fl["zones_add_max"], fl["extra_windows_zones_max"], fl["windows_per_zone_max"]) == (
        S.ZONES_ADD_MAX, S.EXTRA_WINDOW_ZONES_MAX, S.WINDOWS_PER_ZONE_MAX)
    assert (lo, hi, count.default) == (S.ROTATE_COUNT_MIN, S.ROTATE_COUNT_MAX, S.ROTATE_COUNT_DEFAULT)


def test_strict_bool_restore_example_is_replayed():
    """restore_int_rejected (restore: 1 -> 422) must stay in the replayed invalid set: StrictBool, never coerced."""
    ids = {p.id for p in ALL_INVALID}
    assert "cloud.admin.access.put:restore_int_rejected" in ids
    er = next(e for e in ROUTES["cloud.admin.access.put"]["errors"] if e["name"] == "restore_int_rejected")
    body = er["request"]["body"]
    assert body["restore"] == 1 and body["consent"] is True  # only the int restore makes it invalid
    with pytest.raises(ValidationError) as exc:
        S.AccessUpdateRequest.model_validate(body)
    assert [e["loc"] for e in exc.value.errors()] == [("restore",)]


@pytest.mark.parametrize("route_id,ex", ALL_VALID)
def test_valid_example_parses_into_the_cloud_models(route_id, ex):
    req = ex["request"]
    for name, value in (req.get("path_params") or {}).items():
        assert re.match(PATH_PATTERNS[name], value), (name, value)
    model = REQUEST_MODELS[route_id]
    if model is not None:
        model.model_validate(req["body"])
    else:
        assert req.get("body") is None
    RESPONSE_MODELS[route_id].model_validate(ex["response"]["body"])


@pytest.mark.parametrize("route_id,er", ALL_INVALID)
def test_invalid_request_is_rejected_by_the_model(route_id, er):
    req = er["request"]
    bad_path = [n for n, v in (req.get("path_params") or {}).items() if not re.match(PATH_PATTERNS[n], v)]
    bad_query = [k for k, (lo, hi) in QUERY_LIMITS.get(route_id, {}).items()
                 if k in (req.get("query") or {}) and not lo <= int(req["query"][k]) <= hi]
    if bad_path or bad_query:
        return
    with pytest.raises(ValidationError):
        REQUEST_MODELS[route_id].model_validate(req["body"])


# ------------------------------------------------------------------ live: replay against the app
@pytest.fixture
def main(client) -> Signed:
    return Signed(client, kiosk=KIOSK)


def call(c: Signed, route_id: str, req: dict, *, admin: bool | None = None, key: str | None = None):
    route = ROUTES[route_id]
    path = route["path"].format(**(req.get("path_params") or {}))
    if req.get("query"):
        path += "?" + urlencode(req["query"])
    want_admin = route["auth"] == "cloud_kiosk_hmac_admin" if admin is None else admin
    headers = {"X-Admin-Token": ADMIN} if want_admin else {}
    signer = c if key is None else Signed(c.c, kiosk=c.kiosk, key=key)
    return signer.request(route["method"], path, json_body=req.get("body"), headers=headers)


def put_access(c: Signed, uid: str, body: dict):
    return call(c, "cloud.admin.access.put", {"path_params": {"user_id": uid}, "body": body})


def erase_state(c: Signed) -> None:
    """u_prj1: scheduled (student), cloud-enrolled with consent, then DPDP-erased -> status ERASED."""
    r = put_access(c, "u_prj1", {"display": "Prajwal M.", "role": "student", "consent": True})
    assert r.status_code == 200, r.text
    imgs = [base64.b64encode(make_fake_jpeg("u_prj1", salt=f"c{i}")).decode() for i in range(3)]
    r = c.post("/v1/enroll", {"user_id": "u_prj1", "display_name": "Prajwal M.", "consent": True,
                              "consent_version": "2026-11-14.v1", "images_b64": imgs})
    assert r.status_code == 201, r.text
    assert c.delete("/v1/enroll/u_prj1").status_code == 200


def status_of(c: Signed, uid: str) -> str:
    users = {u["user_id"]: u for u in c.get("/v1/admin/users", headers={"X-Admin-Token": ADMIN}).json()["users"]}
    return users[uid]["status"] if uid in users else "ABSENT"


def keys_match(actual: dict, expected: dict, where: str) -> None:
    assert set(actual) == set(expected), f"{where}: {sorted(set(actual) ^ set(expected))}"


@pytest.mark.parametrize("route_id,er", ALL_INVALID)
def test_invalid_request_is_a_422_without_reason(main, services, route_id, er):
    v0 = services.schedule.current()["version"]
    r = call(main, route_id, er["request"])
    err = r.json()["error"]
    assert (r.status_code, err["code"]) == (422, "VALIDATION_ERROR"), r.text
    assert "reason" not in err and "attempt_id" not in err
    assert services.schedule.current()["version"] == v0


@pytest.mark.parametrize("route_id,er", ALL_STATE_ERRORS)
def test_state_error_status_code_and_reason(main, services, monkeypatch, route_id, er):
    name = er["name"]
    kw: dict = {}
    if name == "admin_token_wrong":
        kw["admin"] = False
    elif name == "hmac_invalid":
        kw["key"] = "x" * 64
    elif name == "schedule_conflict":
        def contention(*_a, **_k):  # every CAS attempt lost to another writer (publish gave up after 5 tries)
            raise sched_mod.ScheduleConflict("concurrent schedule updates")

        monkeypatch.setattr(services.schedule, "publish", contention)
    elif name == "codes_unavailable":
        monkeypatch.setattr(sched_mod, "load_documented_override_values", lambda: None)
    elif name == "erased_without_consent":
        erase_state(main)
        assert status_of(main, "u_prj1") == "ERASED"
    elif name in {"revoked_consent_without_restore", "already_revoked"}:
        assert status_of(main, "u_a3b4") == "REVOKED"
    elif name in {"unknown_role", "unknown_zone", "create_without_consent", "create_without_display",
                  "unknown_user"}:
        pass  # baseline seed state (u_kv02 / u_zz99 absent, u_3c4d ACTIVE)
    else:
        pytest.fail(f"contract error example {route_id}:{name} has no state set-up in this test: add one")
    seq0, _ = services.schedule.revocations_since(0)
    v0 = services.schedule.current()["version"]
    r = call(main, route_id, er["request"], **kw)
    want = er["response"]["body"]["error"]
    got = r.json()["error"]
    assert r.status_code == er["response"]["status"], r.text
    assert got["code"] == want["code"] and got.get("reason") == want.get("reason"), r.text
    assert "attempt_id" not in got  # cloud errors carry no attempt_id
    assert services.schedule.current()["version"] == v0  # a refused write publishes nothing
    assert services.schedule.revocations_since(0)[0] == seq0 or route_id == "cloud.admin.revocations.post"


def test_users_list_example(main, services):
    ex = ROUTES["cloud.admin.users.list"]["examples"][0]
    erase_state(main)
    r = call(main, "cloud.admin.users.list", ex["request"])
    assert r.status_code == ex["response"]["status"], r.text
    body = r.json()
    S.AdminUsersResponse.model_validate(body)
    exp = ex["response"]["body"]
    keys_match(body, exp, "top")
    for row in body["users"]:
        keys_match(row, exp["users"][0], f"users[{row['user_id']}]")
    assert set(body["roles"]) == set(exp["roles"]) and set(body["zones"]) == set(exp["zones"])
    assert set(body["kiosks"]) == set(exp["kiosks"])
    for name, rd in body["roles"].items():
        keys_match(rd, exp["roles"][name], f"roles.{name}")
        assert rd["zones"] == exp["roles"][name]["zones"]  # generated from the master values
    users = {u["user_id"]: u for u in body["users"]}
    assert users["u_a3b4"]["status"] == "REVOKED" and users["u_a3b4"]["revoked_reason"] == "ADMIN"
    assert users["u_prj1"]["status"] == "ERASED" and users["u_prj1"]["revoked_reason"] == "ERASED"
    assert users["u_3c4d"]["status"] == "ACTIVE" and users["u_3c4d"]["revoked_at"] is None
    dump = json.dumps(body)
    assert "card_id_hash" not in dump and "salt" not in dump and '"hash"' not in dump


@pytest.mark.parametrize("route_id,ex", _valid("cloud.admin.access.put"))
def test_put_access_example(main, services, route_id, ex):
    uid = ex["request"]["path_params"]["user_id"]
    if ex["name"] == "readmit_erased":
        erase_state(main)
        assert status_of(main, uid) == "ERASED"
    elif ex["name"] == "create":
        assert status_of(main, uid) == "ABSENT"
    v0 = services.schedule.current()["version"]
    seq0, _ = services.schedule.revocations_since(0)
    r = call(main, route_id, ex["request"])
    assert r.status_code == ex["response"]["status"], r.text
    body = r.json()
    S.AccessPutResponse.model_validate(body)
    exp = ex["response"]["body"]
    keys_match(body, exp, "top")
    keys_match(body["user"], exp["user"], "user")
    for k in ("created", "unchanged", "readmitted", "restored", "previous_role", "role", "warnings"):
        assert body[k] == exp[k], (k, body[k], exp[k])
    for k in ("display", "role", "status", "revoked_at", "revoked_reason", "zones_add", "extra_windows"):
        assert body["user"][k] == exp["user"][k], (k, body["user"][k], exp["user"][k])
    assert (body["changed_at"] is None) is (exp["changed_at"] is None)
    assert body["bundle_version"] == (v0 if exp["unchanged"] else v0 + 1)
    _, feed = services.schedule.revocations_since(seq0)
    want_feed = {"readmit_erased": [("READMIT", uid, "READMIT")],
                 "restore_revoked": [("READMIT", uid, "RESTORE")]}.get(ex["name"], [])
    assert [(i["type"], i["target_id"], i["reason"]) for i in feed] == want_feed
    if ex["name"] in {"readmit_erased", "restore_revoked"}:
        b = Signed(main.c, kiosk="KIOSK_LIB_01").get("/v1/schedule/KIOSK_LIB_01").json()
        assert not any(x["user_id"] == uid for x in b["revocations"])  # suspension really lifted in the bundle


def test_revocation_example(main, services):
    ex = ROUTES["cloud.admin.revocations.post"]["examples"][0]
    r = call(main, "cloud.admin.revocations.post", ex["request"])
    assert r.status_code == ex["response"]["status"], r.text
    S.AdminRevokeResponse.model_validate(r.json())
    keys_match(r.json(), ex["response"]["body"], "top")
    assert (r.json()["type"], r.json()["target_id"], r.json()["reason"]) == ("USER", "u_3c4d", "ADMIN")
    assert status_of(main, "u_3c4d") == "REVOKED"
    seq1, _ = services.schedule.revocations_since(0)
    again = call(main, "cloud.admin.revocations.post",  # a fresh signature (the replay cache refuses a resend)
                 {"body": {**ex["request"]["body"], "actor": "again"}})
    assert again.status_code == 409 and again.json()["error"]["reason"] == "ALREADY_REVOKED"
    assert services.schedule.revocations_since(0)[0] == seq1  # no new seq


def test_rotate_example(main, services):
    ex = ROUTES["cloud.admin.codes.rotate"]["examples"][0]
    r = call(main, "cloud.admin.codes.rotate", ex["request"])
    assert r.status_code == ex["response"]["status"], r.text
    for h, v in ex["response"]["headers"].items():
        assert r.headers[h].lower() == v.lower()
    body = r.json()
    S.CodesRotateResponse.model_validate(body)
    keys_match(body, ex["response"]["body"], "top")
    assert len(body["codes"]) == ex["request"]["body"]["count"]
    assert all(len(c["code"]) == body["code_length"] and c["code"].isdigit() for c in body["codes"])
    assert body["one_time"] is True and "Shown once" in body["warning"]
    assert body["staff_id"] in call(main, "cloud.admin.users.list", {"body": None}).json()["staff_ids"]


def test_feed_example_erase_readmit_revoke_restore(main, services):
    ex = ROUTES["cloud.revocations.feed"]["examples"][0]
    since, _ = services.schedule.revocations_since(0)
    erase_state(main)
    assert put_access(main, "u_prj1", {"display": "Prajwal M.", "role": "student", "consent": True,
                                       "actor": "register"}).json()["readmitted"] is True
    assert call(main, "cloud.admin.revocations.post",
                {"body": {"type": "USER", "target_id": "u_3c4d", "reason": "ADMIN"}}).status_code == 201
    assert put_access(main, "u_a3b4", {"role": "student", "consent": True, "restore": True}).json()["restored"]
    r = call(main, "cloud.revocations.feed", {"query": {"since": since}})
    assert r.status_code == 200, r.text
    S.RevocationsResponse.model_validate(r.json())
    got = [(i["type"], i["target_id"], i["reason"]) for i in r.json()["items"]]
    want = [(i["type"], i["target_id"], i["reason"]) for i in ex["response"]["body"]["items"]]
    assert got == want
    for item in r.json()["items"]:
        keys_match(item, ex["response"]["body"]["items"][0], "feed item")


def test_audit_example(main, services):
    ex = ROUTES["cloud.admin.audit"]["examples"][0]
    assert put_access(main, "u_kv02", {"display": "Prof. Arjun T.", "role": "faculty", "consent": True,
                                       "actor": "register"}).status_code == 200
    rot = call(main, "cloud.admin.codes.rotate", {"body": {"staff_id": "s_guard01", "count": 4,
                                                           "actor": "control-panel"}}).json()
    r = call(main, "cloud.admin.audit", ex["request"])
    assert r.status_code == 200, r.text
    body = r.json()
    S.AuditResponse.model_validate(body)
    keys_match(body, ex["response"]["body"], "top")
    assert body["count"] == len(body["items"]) == ex["request"]["query"]["limit"]
    for got, want in zip(body["items"], ex["response"]["body"]["items"], strict=True):
        assert got["action"] == want["action"] and got["actor"] == want["actor"] and got["kiosk_id"] == KIOSK
        assert set(want) <= set(got), sorted(set(want) - set(got))
    assert body["items"][0]["changes"] == ex["response"]["body"]["items"][0]["changes"]
    assert not any(c["code"] in json.dumps(body) for c in rot["codes"])  # never code values
