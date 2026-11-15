"""HTTP layer: deps (401/403/503, pending gates, legacy flag, activity), routes (auth, staff, API keys, audit,
roles, status), privilege rules and the no-store / never-echo-secrets contract."""


from pathlib import Path
from typing import Annotated, Any

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from edge.auth import mfa, rbac
from edge.auth.deps import AuthDependencies
from edge.auth.models import AuthError, Principal
from edge.auth.routes import build_router
from edge.auth.service import AuthService
from edge.auth.staff_ops import check_ceiling
from edge.auth.store import STORE_FILE
from edge.errors import install_error_handlers
from edge.tests import test_auth_support as support
from edge.tests.test_auth_support import (
    ADMIN_PW,
    CONSOLE,
    NEW_PW,
    USER_PW,
    FakeClock,
    add_user,
    enable_mfa,
    make_service,
)

clock = support.clock
fast_scrypt = support.fast_scrypt
LEGACY_TOKEN = "zz-dummy-legacy-admin-token-zz"


def make_app(holder: dict[str, AuthService | None]) -> FastAPI:
    app = FastAPI()
    install_error_handlers(app)

    def get_auth(_: Request) -> AuthService | None:
        return holder["auth"]

    deps = AuthDependencies(get_auth)
    app.include_router(build_router(get_auth))

    @app.get("/v1/admin/store")
    def store(p: Annotated[Principal, Depends(deps.for_route("GET", "/v1/admin/store"))]) -> dict[str, Any]:
        return {"actor": p.actor_id}

    @app.post("/v1/admin/mode")
    def mode(p: Annotated[Principal, Depends(deps.for_route("POST", "/v1/admin/mode"))]) -> dict[str, Any]:
        return {"actor": p.actor_id}

    @app.post("/v1/admin/clock")
    def demo_clock(p: Annotated[Principal, Depends(deps.for_route("POST", "/v1/admin/clock"))]) -> dict[str, Any]:
        return {"actor": p.actor_id}

    return app


@pytest.fixture
def env(tmp_path: Path, clock: FakeClock, fast_scrypt: None) -> dict[str, Any]:
    auth = make_service(tmp_path, clock)
    add_user(auth, "boss01", ["admin"], ADMIN_PW)
    add_user(auth, "guard01", ["security_officer"])
    add_user(auth, "viewer01", ["auditor"])
    holder: dict[str, AuthService | None] = {"auth": auth}
    return {"auth": auth, "holder": holder, "client": TestClient(make_app(holder)), "dir": tmp_path}


def bearer(token: str, **extra: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", **extra}


def sign_in(client: TestClient, username: str, password: str = USER_PW) -> str:
    r = client.post("/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    assert r.headers["cache-control"] == "no-store" and r.headers["pragma"] == "no-cache"
    body = r.json()
    assert body["token_type"] == "Bearer" and body["idle_timeout_s"] == 1800 and password not in r.text
    return body["token"]


def error(r: Any) -> dict[str, Any]:
    return r.json()["error"]


# ------------------------------------------------------------------ authentication
def test_public_status_never_lists_usernames(env: dict[str, Any]) -> None:
    r = env["client"].get("/v1/auth/status")
    assert r.status_code == 200 and r.json() == {"store": "OK", "accounts_exist": True,
                                                 "legacy_token_enabled": False, "mfa_required_roles": []}
    assert "boss01" not in r.text


def test_me_logout_and_no_store(env: dict[str, Any]) -> None:
    c = env["client"]
    token = sign_in(c, "guard01")
    me = c.get("/v1/auth/me", headers=bearer(token))
    assert me.status_code == 200 and me.headers["cache-control"] == "no-store"
    body = me.json()
    assert body["principal"]["actor_id"] == "staff:s_guard01" and body["session"]["idle_timeout_s"] == 1800
    assert c.post("/v1/auth/logout", headers=bearer(token)).status_code == 204
    assert error(c.get("/v1/auth/me", headers=bearer(token)))["reason"] == "SESSION_EXPIRED"


@pytest.mark.parametrize(("headers", "reason"), [
    ({}, "CREDENTIAL_INVALID"),
    ({"Authorization": "Basic abc"}, "CREDENTIAL_INVALID"),
    ({"Authorization": "Bearer fgs_" + "A" * 43}, "SESSION_EXPIRED"),
    ({"Authorization": "Bearer fgk_abcd1234." + "A" * 43}, "CREDENTIAL_INVALID"),
    ({"Authorization": "Bearer something-else"}, "CREDENTIAL_INVALID"),
    ({"X-Admin-Token": LEGACY_TOKEN}, "CREDENTIAL_INVALID"),  # legacy flag is OFF by default
])
def test_401_for_missing_or_bad_credentials(env: dict[str, Any], headers: dict[str, str], reason: str) -> None:
    r = env["client"].get("/v1/admin/store", headers=headers)
    assert r.status_code == 401 and error(r)["code"] == "UNAUTHORIZED" and error(r)["reason"] == reason


def test_missing_permission_is_403_with_required_and_is_audited(env: dict[str, Any], clock: FakeClock) -> None:
    c = env["client"]
    token = sign_in(c, "viewer01")
    r = c.post("/v1/admin/mode", headers=bearer(token))
    assert r.status_code == 403 and error(r)["reason"] == "MISSING_PERMISSION"
    assert error(r)["required"] == ["mode:switch"]
    assert c.get("/v1/admin/store", headers=bearer(token)).json() == {"actor": "staff:s_viewer01"}
    clock.advance(60)
    denials = [e for e in env["auth"].audit.read()[0] if e["action"] == "auth.denied"]
    assert denials and denials[0]["target"] == "/v1/admin/mode" and denials[0]["count"] == 1


def test_demo_permissions_vanish_when_demo_mode_is_off(tmp_path: Path, clock: FakeClock, fast_scrypt: None) -> None:
    auth = make_service(tmp_path, clock, demo_mode=False)
    add_user(auth, "boss01", ["admin"], ADMIN_PW)
    c = TestClient(make_app({"auth": auth}))
    token = sign_in(c, "boss01", ADMIN_PW)
    perms = c.get("/v1/auth/me", headers=bearer(token)).json()["principal"]["permissions"]
    assert "demo:clock" not in perms and "challenge:control" not in perms and "staff:manage" in perms
    assert c.post("/v1/admin/clock", headers=bearer(token)).status_code == 403


def test_auth_unavailable_without_service_or_with_corrupt_store(env: dict[str, Any], clock: FakeClock) -> None:
    c = env["client"]
    token = sign_in(c, "guard01")
    (env["dir"] / STORE_FILE).write_bytes(b"corrupt")
    clock.advance(2)
    r = c.get("/v1/admin/store", headers=bearer(token))
    assert r.status_code == 503 and error(r)["code"] == "AUTH_UNAVAILABLE"
    assert c.get("/v1/auth/status").json()["store"] == "UNAVAILABLE"
    env["holder"]["auth"] = None
    assert c.get("/v1/admin/store", headers=bearer(token)).status_code == 503


def test_legacy_token_when_enabled_is_admin_minus_staff_manage(tmp_path: Path, clock: FakeClock,
                                                              fast_scrypt: None) -> None:
    auth = make_service(tmp_path, clock, legacy_admin_token_enabled=True, legacy_admin_token=LEGACY_TOKEN)
    c = TestClient(make_app({"auth": auth}))
    legacy = {"X-Admin-Token": LEGACY_TOKEN}
    assert c.post("/v1/admin/mode", headers=legacy).json() == {"actor": "legacy:admin_token"}
    assert c.get("/v1/admin/staff", headers=legacy).status_code == 403
    assert c.get("/v1/admin/store", headers={"X-Admin-Token": "wrong"}).status_code == 401
    assert "legacy_admin_token" in auth.degraded_reasons()
    auth.audit.flush_denials()  # legacy use is aggregated per (route, minute)
    assert any(e["action"] == "auth.legacy_token" for e in auth.audit.read()[0])
    add_user(auth, "guard01", ["auditor"])
    (tmp_path / STORE_FILE).unlink()  # store deleted: MISSING; the legacy token does not bypass it
    clock.advance(2)
    assert c.post("/v1/admin/mode", headers=legacy).status_code == 503


def test_password_change_gate(env: dict[str, Any]) -> None:
    c, auth = env["client"], env["auth"]
    add_user(auth, "temp01", ["auditor"], must_change=True)
    token = sign_in(c, "temp01")
    r = c.get("/v1/admin/store", headers=bearer(token))
    assert r.status_code == 403 and error(r)["reason"] == "PASSWORD_CHANGE_REQUIRED"
    assert c.get("/v1/auth/me", headers=bearer(token)).json()["principal"]["must_change_password"]
    r = c.post("/v1/auth/password", headers=bearer(token),
               json={"current_password": USER_PW, "new_password": NEW_PW})
    assert r.status_code == 204
    assert c.get("/v1/admin/store", headers=bearer(token)).status_code == 200


def test_mfa_enrolment_gate_and_self_enrolment(tmp_path: Path, clock: FakeClock, fast_scrypt: None) -> None:
    auth = make_service(tmp_path, clock, mfa_required_roles=frozenset({"admin"}))
    add_user(auth, "boss01", ["admin"], ADMIN_PW)
    c = TestClient(make_app({"auth": auth}))
    token = sign_in(c, "boss01", ADMIN_PW)
    assert error(c.get("/v1/admin/staff", headers=bearer(token)))["reason"] == "MFA_ENROLMENT_REQUIRED"
    assert c.post("/v1/auth/mfa/enroll", headers=bearer(token)).status_code == 422  # body is required
    wrong = c.post("/v1/auth/mfa/enroll", headers=bearer(token), json={"current_password": USER_PW})
    assert wrong.status_code == 403 and error(wrong)["reason"] == "REAUTH_REQUIRED"
    r = c.post("/v1/auth/mfa/enroll", headers=bearer(token), json={"current_password": ADMIN_PW})
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    secret = r.json()["secret"]
    assert r.json()["otpauth_uri"].startswith("otpauth://totp/")
    code = mfa.code_at(secret, mfa.current_step(clock()))
    assert c.post("/v1/auth/mfa/confirm", headers=bearer(token), json={"totp_code": code}).status_code == 204
    assert c.get("/v1/admin/staff", headers=bearer(token)).status_code == 200
    assert secret not in (tmp_path / "audit.jsonl").read_text()


def test_mfa_login_over_http_with_ticket(env: dict[str, Any], clock: FakeClock) -> None:
    c, auth = env["client"], env["auth"]
    secret = enable_mfa(auth, clock, "guard01")
    r = c.post("/v1/auth/login", json={"username": "guard01", "password": USER_PW})
    assert r.status_code == 401 and error(r)["reason"] == "MFA_REQUIRED"
    ticket = error(r)["mfa_ticket"]
    r = c.post("/v1/auth/login", json={"mfa_ticket": ticket, "totp_code": support.code_now(secret, clock)})
    assert r.status_code == 200 and r.json()["principal"]["mfa_enabled"]
    bad = c.post("/v1/auth/login", json={"mfa_ticket": ticket, "username": "guard01", "totp_code": "123456"})
    assert bad.status_code == 422


def test_rate_limited_has_retry_after_header(env: dict[str, Any]) -> None:
    c = env["client"]
    for _ in range(5):
        c.post("/v1/auth/login", json={"username": "guard01", "password": "nope-nope-nope"})
    r = c.post("/v1/auth/login", json={"username": "guard01", "password": "nope-nope-nope"})
    assert r.status_code == 429 and r.headers["retry-after"] == "1" and error(r)["retry_after_s"] == 1


def test_only_activity_extends_the_idle_timer(env: dict[str, Any], clock: FakeClock) -> None:
    c = env["client"]
    token = sign_in(c, "viewer01")
    clock.advance(25 * 60)
    c.get("/v1/admin/store", headers=bearer(token))  # a poll
    clock.advance(6 * 60)
    assert c.get("/v1/admin/store", headers=bearer(token)).status_code == 401
    token = sign_in(c, "viewer01")
    for headers in ({"X-FG-Activity": "1"}, {}):
        clock.advance(25 * 60)
        if headers:
            assert c.get("/v1/admin/store", headers=bearer(token, **headers)).status_code == 200
        else:
            assert c.post("/v1/auth/activity", headers=bearer(token)).status_code == 204
    clock.advance(25 * 60)
    assert c.get("/v1/admin/store", headers=bearer(token)).status_code == 200


# ------------------------------------------------------------------ staff administration
def test_staff_crud_requires_reauth_and_never_leaks_secrets(env: dict[str, Any]) -> None:
    c = env["client"]
    admin = bearer(sign_in(c, "boss01", ADMIN_PW))
    body = {"username": "enrol01", "display_name": "Enroller", "roles": ["enroller"],
            "temporary_password": "fresh-start-pw-77"}
    r = c.post("/v1/admin/staff", headers=admin, json={**body, "confirm_password": "wrong-password-x"})
    assert r.status_code == 403 and error(r)["reason"] == "REAUTH_REQUIRED"
    r = c.post("/v1/admin/staff", headers=admin, json={**body, "confirm_password": ADMIN_PW})
    assert r.status_code == 201 and r.json()["item"]["must_change_password"] is True
    assert c.post("/v1/admin/staff", headers=admin, json={**body, "confirm_password": ADMIN_PW}).status_code == 409
    listing = c.get("/v1/admin/staff", headers=admin)
    assert {i["staff_id"] for i in listing.json()["items"]} >= {"s_enrol01", "s_boss01"}
    for secret in ("fresh-start-pw-77", ADMIN_PW, "scrypt", "password_hash", "mfa_secret"):
        assert secret not in listing.text and secret not in r.text
    r = c.patch("/v1/admin/staff/s_enrol01", headers=admin,
                json={"display_name": "Enroller Two", "confirm_password": ADMIN_PW})
    assert r.json()["item"]["display_name"] == "Enroller Two"
    assert c.request("DELETE", "/v1/admin/staff/s_enrol01", headers=admin,
                     json={"confirm_password": ADMIN_PW}).status_code == 204
    assert c.get("/v1/admin/staff/s_enrol01", headers=admin).status_code == 404


def test_staff_routes_need_staff_manage(env: dict[str, Any]) -> None:
    c = env["client"]
    officer = bearer(sign_in(c, "guard01"))
    assert c.get("/v1/admin/staff", headers=officer).status_code == 403
    assert c.post("/v1/admin/api-keys", headers=officer,
                  json={"name": "x", "roles": ["auditor"], "confirm_password": USER_PW}).status_code == 403


def test_no_self_modification_and_last_admin(env: dict[str, Any]) -> None:
    c, auth = env["client"], env["auth"]
    admin = bearer(sign_in(c, "boss01", ADMIN_PW))
    for change in ({"status": "disabled"}, {"roles": ["auditor"]}):
        r = c.patch("/v1/admin/staff/s_boss01", headers=admin, json={**change, "confirm_password": ADMIN_PW})
        assert r.status_code == 403 and error(r)["reason"] == "SELF_MODIFICATION"
    with pytest.raises(AuthError) as err:  # the console is not "self", but the last admin stays
        auth.update_staff(CONSOLE, "s_boss01", status="disabled")
    assert err.value.reason == "LAST_ADMIN" and err.value.status == 403
    add_user(auth, "boss02", ["admin"])
    auth.update_staff(CONSOLE, "s_boss01", roles=["auditor"])  # another active admin exists now


def test_role_ceiling() -> None:
    officer = Principal(kind="staff", id="s_guard01", username="guard01", display_name="g",
                        roles=("security_officer",), permissions=rbac.permissions_for(["security_officer"]))
    with pytest.raises(AuthError) as err:
        check_ceiling(officer, rbac.permissions_for(["admin"]))
    assert err.value.reason == "ROLE_CEILING"
    check_ceiling(officer, rbac.permissions_for(["auditor"]) - {"enrol:read"})


def test_admin_password_reset_and_unlock(env: dict[str, Any]) -> None:
    c = env["client"]
    admin = bearer(sign_in(c, "boss01", ADMIN_PW))
    victim = sign_in(c, "guard01")
    r = c.post("/v1/admin/staff/s_guard01/password", headers=admin,
               json={"temporary_password": NEW_PW, "confirm_password": ADMIN_PW})
    assert r.status_code == 204 and NEW_PW not in r.text
    assert c.get("/v1/auth/me", headers=bearer(victim)).status_code == 401
    token = sign_in(c, "guard01", NEW_PW)
    assert error(c.get("/v1/admin/store", headers=bearer(token)))["reason"] == "PASSWORD_CHANGE_REQUIRED"
    for _ in range(6):
        c.post("/v1/auth/login", json={"username": "viewer01", "password": "nope-nope-nope"})
    assert c.post("/v1/auth/login", json={"username": "viewer01", "password": USER_PW}).status_code == 429
    assert c.post("/v1/admin/staff/s_viewer01/unlock", headers=admin,
                  json={"confirm_password": ADMIN_PW}).status_code == 204
    sign_in(c, "viewer01")


# ------------------------------------------------------------------ API keys
def create_key(c: TestClient, admin: dict[str, str], **body: Any) -> Any:
    return c.post("/v1/admin/api-keys", headers=admin,
                  json={"name": "bench", "roles": ["evaluator", "enroller"], "confirm_password": ADMIN_PW, **body})


def test_api_key_shown_once_scoped_and_revocable(env: dict[str, Any]) -> None:
    c = env["client"]
    admin = bearer(sign_in(c, "boss01", ADMIN_PW))
    r = create_key(c, admin)
    assert r.status_code == 201 and r.headers["cache-control"] == "no-store"
    key, item = r.json()["key"], r.json()["item"]
    assert key.startswith(f"fgk_{item['key_id']}.") and item["status"] == "active"
    assert "enrol:erase" not in item["permissions"] and "mode:switch" in item["permissions"]
    listing = c.get("/v1/admin/api-keys", headers=admin)
    assert key.split(".")[1] not in listing.text and "secret_sha256" not in listing.text
    assert c.post("/v1/admin/mode", headers=bearer(key)).json() == {"actor": f"key:{item['key_id']}"}
    assert c.get("/v1/admin/staff", headers=bearer(key)).status_code == 403
    r = c.post("/v1/auth/password", headers=bearer(key), json={"current_password": "x", "new_password": NEW_PW})
    assert r.status_code == 403 and error(r)["reason"] == "NO_STAFF_IDENTITY"
    assert c.request("DELETE", f"/v1/admin/api-keys/{item['key_id']}", headers=admin,
                     json={"confirm_password": ADMIN_PW}).status_code == 204
    assert c.post("/v1/admin/mode", headers=bearer(key)).status_code == 401


def test_api_key_expiry_and_limits(env: dict[str, Any], clock: FakeClock) -> None:
    c = env["client"]
    admin = bearer(sign_in(c, "boss01", ADMIN_PW))
    assert create_key(c, admin, roles=["admin"]).status_code == 422
    assert create_key(c, admin, expires_days=91).status_code == 422
    key = create_key(c, admin, expires_days=1).json()["key"]
    assert c.get("/v1/admin/store", headers=bearer(key)).status_code == 200
    clock.advance(86_401)
    assert c.get("/v1/admin/store", headers=bearer(key)).status_code == 401


def test_disabling_a_creator_revokes_their_keys(env: dict[str, Any]) -> None:
    c, auth = env["client"], env["auth"]
    add_user(auth, "boss02", ["admin"], ADMIN_PW)
    other = bearer(sign_in(c, "boss02", ADMIN_PW))
    key = create_key(c, other).json()["key"]
    admin = bearer(sign_in(c, "boss01", ADMIN_PW))
    assert c.patch("/v1/admin/staff/s_boss02", headers=admin,
                   json={"status": "disabled", "confirm_password": ADMIN_PW}).status_code == 200
    assert c.get("/v1/admin/store", headers=bearer(key)).status_code == 401
    assert c.get("/v1/auth/me", headers=other).status_code == 401


# ------------------------------------------------------------------ audit + roles
def test_audit_route_and_no_secrets_in_any_line(env: dict[str, Any], clock: FakeClock) -> None:
    c = env["client"]
    viewer = bearer(sign_in(c, "viewer01"))
    admin = bearer(sign_in(c, "boss01", ADMIN_PW))
    key = create_key(c, admin).json()["key"]
    c.post("/v1/auth/login", json={"username": "guard01", "password": "wrong-pass-1234"})
    c.post("/v1/admin/mode", headers=viewer)
    clock.advance(60)
    r = c.get("/v1/admin/auth/audit?limit=50", headers=viewer)
    assert r.status_code == 200
    body = r.json()
    assert {"as_of", "count", "items", "next_before_seq"} <= set(body) and body["count"] == len(body["items"])
    actions = {e["action"] for e in body["items"]}
    assert {"auth.login", "apikey.create", "auth.denied", "staff.create"} <= actions
    text = (env["dir"] / "audit.jsonl").read_text()
    for secret in (ADMIN_PW, USER_PW, "wrong-pass-1234", key, key.split(".")[1], viewer["Authorization"][7:]):
        assert secret not in text
    assert env["auth"].audit.verify()
    officer = bearer(sign_in(c, "guard01"))
    assert c.get("/v1/admin/auth/audit", headers=officer).status_code == 200  # security_officer has audit:read
    assert c.get("/v1/admin/auth/audit", headers=bearer(key)).status_code == 403


def test_roles_catalog_for_the_ui(env: dict[str, Any]) -> None:
    c = env["client"]
    r = c.get("/v1/admin/roles", headers=bearer(sign_in(c, "viewer01")))
    roles = {x["name"]: x for x in r.json()["roles"]}
    assert set(roles) == set(rbac.EDGE_ROLES) and roles["admin"]["key_allowed"] is False
    assert roles["enroller"]["description"] and "enrol:erase" in roles["enroller"]["permissions"]
    assert c.get("/v1/admin/roles").status_code == 401


def test_login_body_is_strict(env: dict[str, Any]) -> None:
    c = env["client"]
    assert c.post("/v1/auth/login", json={"username": "guard01", "password": USER_PW, "x": 1}).status_code == 422
    assert c.post("/v1/auth/login", json={"username": "guard01"}).status_code == 422
    assert c.post("/v1/auth/login", json={"password": USER_PW}).status_code == 422
