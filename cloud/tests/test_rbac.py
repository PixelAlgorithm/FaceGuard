"""Cloud admin RBAC (design v2 §E): production default, credential precedence and 403 reasons, kiosk binding,
the full route -> permission matrix, outbox gating, schedule redaction and actor attribution."""

from __future__ import annotations

import dataclasses
import json
import secrets
import time
from datetime import timedelta

import pytest
from edge.auth import tokens
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from cloud.app import rbac
from cloud.app.config import ConfigError, settings_from_env
from cloud.app.container import build_services
from cloud.app.main import create_app

from .conftest import ADMIN, API_KEY, KIOSK_KEY, T0, Signed, make_settings

AUTH_REASONS = {"ADMIN_KEY_INVALID", "ADMIN_KEY_EXPIRED", "MISSING_PERMISSION", "KIOSK_NOT_BOUND", "LEGACY_DISABLED"}
PATH_VALUES = {"kiosk_id": "KIOSK_MAIN_01", "user_id": "u_3c4d"}


def mint(key_id: str) -> tuple[str, str]:
    """(full key shown once, sha256 of the secret) - the shape cloud/tools/apikey.py prints."""
    secret = secrets.token_urlsafe(32)
    return f"fgk_{key_id}.{secret}", tokens.digest(secret)


KEYS = {name: mint(kid) for name, kid in (("admin", "adminkk1"), ("edge_proxy", "edgeprx1"), ("auditor", "auditrr1"),
                                          ("proxy_lib", "edgelib1"), ("expired", "expired1"))}


def key_entries() -> list[dict]:
    return [
        {"key_id": "adminkk1", "sha256": KEYS["admin"][1], "roles": ["admin"], "name": "ops"},
        {"key_id": "edgeprx1", "sha256": KEYS["edge_proxy"][1], "roles": ["edge_proxy"], "name": "main-edge",
         "kiosk_ids": ["KIOSK_MAIN_01"]},
        {"key_id": "auditrr1", "sha256": KEYS["auditor"][1], "roles": ["auditor"], "name": "audit"},
        {"key_id": "edgelib1", "sha256": KEYS["proxy_lib"][1], "roles": ["edge_proxy"], "name": "lib-edge",
         "kiosk_ids": ["KIOSK_LIB_01"]},
        {"key_id": "expired1", "sha256": KEYS["expired"][1], "roles": ["admin"], "name": "old",
         "expires_at": (T0 - timedelta(hours=1)).isoformat()},
    ]


def bearer(name: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {KEYS[name][0]}"}


def make_client(clock, **kw):
    s = make_settings(**{"auth_legacy_admin_token": False,
                         "cloud_api_keys": rbac.parse_api_keys(json.dumps(key_entries())), **kw})
    svc = build_services(s, clock=clock)
    return svc, TestClient(create_app(services=svc))


@pytest.fixture
def prod(clock):
    """Production default: legacy X-Admin-Token OFF, admin access only through API keys."""
    svc, c = make_client(clock)
    with c:
        yield svc, Signed(c, kiosk="KIOSK_MAIN_01")


def reason(r) -> str | None:
    return (r.json().get("error") or {}).get("reason")


# ------------------------------------------------------------------ production default + 403 reasons
def test_production_default_refuses_the_legacy_token_with_403(prod):
    _, main = prod
    r = main.get("/v1/admin/users", headers={"X-Admin-Token": ADMIN})
    assert r.status_code == 403 and reason(r) == "LEGACY_DISABLED"
    r = main.get("/v1/admin/users")
    assert r.status_code == 403 and reason(r) == "ADMIN_KEY_INVALID"
    assert "x-server-time" in r.headers


@pytest.mark.parametrize("header", [
    "Bearer", "Bearer fgk_short", "Basic abc", "Bearer fgs_" + "a" * 43,  # session token: not a cloud credential
    f"Bearer fgk_unknown1.{'a' * 43}", f"Bearer fgk_adminkk1.{'b' * 43}",  # unknown key / wrong secret
])
def test_bad_bearer_credentials_are_403_admin_key_invalid(prod, header):
    _, main = prod
    r = main.get("/v1/admin/users", headers={"Authorization": header})
    assert r.status_code == 403 and reason(r) == "ADMIN_KEY_INVALID"


def test_expired_key_and_unbound_kiosk(prod):
    _, main = prod
    r = main.get("/v1/admin/users", headers=bearer("expired"))
    assert r.status_code == 403 and reason(r) == "ADMIN_KEY_EXPIRED"
    r = main.get("/v1/admin/users", headers=bearer("proxy_lib"))  # LIB key from the MAIN kiosk
    assert r.status_code == 403 and reason(r) == "KIOSK_NOT_BOUND"
    lib = Signed(main.c, kiosk="KIOSK_LIB_01")
    assert lib.get("/v1/admin/users", headers=bearer("proxy_lib")).status_code == 200


def test_kiosk_hmac_still_mandatory_with_a_valid_key(prod):
    _, main = prod
    r = main.c.get("/v1/admin/users", headers=bearer("admin"))  # no kiosk signature
    assert r.status_code == 401


def test_bearer_alone_decides_even_with_a_valid_legacy_token(clock):
    svc, c = make_client(clock, auth_legacy_admin_token=True)
    with c:
        main = Signed(c, kiosk="KIOSK_MAIN_01")
        assert main.get("/v1/admin/users", headers={"X-Admin-Token": ADMIN}).status_code == 200  # legacy flag on
        r = main.get("/v1/admin/users", headers={"X-Admin-Token": ADMIN, "Authorization": "Bearer nope"})
        assert r.status_code == 403 and reason(r) == "ADMIN_KEY_INVALID"
        r = main.get("/v1/admin/users", headers={"X-Admin-Token": "wrong"})
        assert r.status_code == 403 and reason(r) == "ADMIN_KEY_INVALID"


# ------------------------------------------------------------------ route -> permission matrix
def admin_routes(router) -> list[tuple[str, str, APIRoute]]:
    out = []
    for route in router.routes:
        if isinstance(route, APIRoute) and route.path.startswith("/v1/admin"):
            out.extend((m, route.path, route) for m in sorted(route.methods))
    return out


def required_of(route: APIRoute) -> set[str]:
    return {getattr(d.call, "required_permission", None) for d in route.dependant.dependencies} - {None}


def test_every_admin_route_is_in_the_permission_table():
    from cloud.app.routers import admin, core

    routes = admin_routes(admin.router)
    assert not admin_routes(core.router)  # every admin route lives in the RBAC-guarded router
    assert {(m, p) for m, p, _ in routes} == set(rbac.ROUTE_PERMISSIONS)
    for m, p, route in routes:
        assert required_of(route) == {str(rbac.ROUTE_PERMISSIONS[(m, p)])}, (m, p)


def _role_perms(role: str, email_backend: str = "fake") -> frozenset[str]:
    return rbac.effective_permissions((role,), email_backend=email_backend)


@pytest.mark.parametrize("method,path", sorted(rbac.ROUTE_PERMISSIONS))
def test_route_permission_matrix(prod, method, path):
    _, main = prod
    perm = str(rbac.ROUTE_PERMISSIONS[(method, path)])
    url = path.format(**PATH_VALUES)
    body = {} if method in {"PUT", "POST"} else None
    lacking = [r for r in ("auditor", "edge_proxy", "admin") if perm not in _role_perms(r)]
    granted = [r for r in ("admin", "edge_proxy", "auditor") if perm in _role_perms(r)]
    for i, role in enumerate(lacking):  # distinct timestamps: the kiosk signature does not cover the bearer
        r = main.request(method, url, json_body=body, headers=bearer(role), now=time.time() + i + 1)
        assert r.status_code == 403 and reason(r) == "MISSING_PERMISSION", (role, r.text)
        assert r.json()["error"]["required"] == [perm]
    assert granted, f"no role grants {perm}"
    r = main.request(method, url, json_body=body, headers=bearer(granted[0]), now=time.time() + 10)
    assert r.status_code != 401 and not (r.status_code == 403 and reason(r) in AUTH_REASONS), r.text


def test_edge_proxy_role_matches_design_v2(prod):
    perms = _role_perms("edge_proxy")
    assert perms == {"schedule:read", "access:read", "access:edit", "revocations:write", "codes:rotate"}


# ------------------------------------------------------------------ outbox only with the fake mailer
def test_outbox_needs_fake_email_backend(clock):
    svc, c = make_client(clock)
    with c:
        assert Signed(c, kiosk="KIOSK_MAIN_01").get("/v1/admin/fake/outbox", headers=bearer("admin")).status_code \
            == 200
    svc, c = make_client(clock, email_backend="disabled")
    with c:
        r = Signed(c, kiosk="KIOSK_MAIN_01").get("/v1/admin/fake/outbox", headers=bearer("admin"))
        assert r.status_code == 403 and reason(r) == "MISSING_PERMISSION"


# ------------------------------------------------------------------ schedule redaction
def test_schedule_read_redacts_code_secrets_without_schedule_write(prod):
    _, main = prod
    assert main.post("/v1/admin/codes/rotate", {"staff_id": "s_guard01", "count": 2},
                     headers=bearer("edge_proxy")).status_code == 201
    proxy = main.get("/v1/admin/schedule", headers=bearer("edge_proxy")).json()
    codes = proxy["doc"]["override_codes"]["codes"]
    assert proxy["codes_redacted"] is True and codes and all("hash" not in c and "salt" not in c for c in codes)
    full = main.get("/v1/admin/schedule", headers=bearer("admin")).json()
    assert full["codes_redacted"] is False and all("hash" in c for c in full["doc"]["override_codes"]["codes"])


# ------------------------------------------------------------------ actor attribution
def test_edge_proxy_actor_is_recorded_as_edge_asserted(prod):
    svc, main = prod
    r = main.request("PUT", "/v1/admin/users/u_3c4d/access", json_body={"role": "faculty",
                                                                        "actor": "staff:s_guard01"},
                     headers=bearer("edge_proxy"))
    assert r.status_code == 200, r.text
    entry = svc.schedule.audit_entries(5, "u_3c4d")[-1]
    assert entry["actor"] == "staff:s_guard01" and entry["actor_assurance"] == "edge_asserted"
    assert entry["via"] == "key:edgeprx1" and entry["kiosk_id"] == "KIOSK_MAIN_01"


@pytest.mark.parametrize("actor", ["register", "staff:Admin", "key:short", "legacy:other"])
def test_edge_proxy_invalid_actor_is_422(prod, actor):
    _, main = prod
    r = main.request("PUT", "/v1/admin/users/u_3c4d/access", json_body={"role": "faculty", "actor": actor},
                     headers=bearer("edge_proxy"))
    assert r.status_code == 422 and reason(r) == "ACTOR_INVALID", r.text


def test_other_keys_cannot_assert_an_actor(prod):
    svc, main = prod
    r = main.request("POST", "/v1/admin/revocations", json_body={"type": "USER", "target_id": "u_1a2b",
                                                                 "actor": "staff:s_someone"},
                     headers=bearer("admin"))
    assert r.status_code == 201, r.text
    entry = [e for e in svc.schedule.audit_entries(10) if e["action"] == "REVOKE"][-1]
    assert entry["actor"] == "key:adminkk1" and entry["actor_assurance"] == "authenticated"


def test_device_routes_record_the_signed_actor(prod):
    svc, main = prod
    r = main.request("DELETE", "/v1/enroll/u_zzzz?actor=staff%3As_guard01")
    assert r.status_code == 404 and reason(r) == "NOT_ENROLLED"
    r = main.request("DELETE", "/v1/enroll/u_zzzz?actor=bogus")
    assert r.status_code == 422 and reason(r) == "ACTOR_INVALID"


# ------------------------------------------------------------------ configuration
BASE_ENV = {"KIOSK_HMAC_KEY": KIOSK_KEY, "SCHEDULE_BUNDLE_HMAC_KEY": "b" * 64, "CLOUD_API_KEY": API_KEY,
            "ALLOW_SHARED_KIOSK_KEY": "1"}


@pytest.mark.parametrize("entry", [
    {"key_id": "edgeprx1", "sha256": "a" * 64, "roles": ["edge_proxy"]},  # no kiosk
    {"key_id": "edgeprx1", "sha256": "a" * 64, "roles": ["edge_proxy"], "kiosk_ids": ["A", "B"]},
    {"key_id": "adminkk1", "sha256": "a" * 64, "roles": ["root"]},
    {"key_id": "edgeprx1", "sha256": "a" * 64, "roles": ["edge_proxy", "admin"], "kiosk_ids": ["A"]},
    {"key_id": "ADMIN", "sha256": "a" * 64, "roles": ["admin"]},
    {"key_id": "adminkk1", "sha256": "xyz", "roles": ["admin"]},
    {"key_id": "adminkk1", "sha256": "a" * 64, "roles": ["admin"], "expires_at": "2026-11-14"},  # naive
])
def test_bad_key_entries_fail_fast(entry):
    with pytest.raises(ConfigError):
        settings_from_env({**BASE_ENV, "CLOUD_API_KEYS_JSON": json.dumps([entry])}, load_env_file=False)


def test_admin_token_required_only_with_the_legacy_flag():
    s = settings_from_env(BASE_ENV, load_env_file=False)
    assert s.auth_legacy_admin_token is False and s.admin_token == ""
    with pytest.raises(ConfigError):
        settings_from_env({**BASE_ENV, "AUTH_LEGACY_ADMIN_TOKEN": "1"}, load_env_file=False)
    legacy = settings_from_env({**BASE_ENV, "AUTH_LEGACY_ADMIN_TOKEN": "1", "ADMIN_TOKEN": "t"}, load_env_file=False)
    assert legacy.admin_token == "t"
    keys = settings_from_env({**BASE_ENV, "CLOUD_API_KEYS_JSON": json.dumps(key_entries())}, load_env_file=False)
    assert [k.key_id for k in keys.cloud_api_keys][:2] == ["adminkk1", "edgeprx1"]
    assert KEYS["admin"][1] not in repr(keys)  # digests never in repr / logs


def test_legacy_principal_is_admin(clock):
    svc, c = make_client(clock, auth_legacy_admin_token=True)
    with c:
        main = Signed(c, kiosk="KIOSK_MAIN_01")
        r = main.request("PUT", "/v1/admin/users/u_3c4d/access", json_body={"role": "faculty", "actor": "x"},
                         headers={"X-Admin-Token": ADMIN})
        assert r.status_code == 200
        assert svc.schedule.audit_entries(5, "u_3c4d")[-1]["actor"] == "legacy:admin_token"


def test_settings_are_frozen_copies():
    s = make_settings(auth_legacy_admin_token=False)
    assert dataclasses.replace(s, auth_legacy_admin_token=True).auth_legacy_admin_token is True


def test_repeated_credential_headers_are_refused(prod):
    _, main = prod
    h = [("Authorization", f"Bearer {KEYS['auditor'][0]}"), ("Authorization", f"Bearer {KEYS['admin'][0]}")]
    from cloud.app.auth import signed_headers

    from .conftest import API_KEY as _API
    from .conftest import KIOSK_KEY as _KEY

    sig = signed_headers(kiosk_id="KIOSK_MAIN_01", key=_KEY, api_key=_API, method="GET", path="/v1/admin/fake/outbox")
    r = main.c.get("/v1/admin/fake/outbox", headers=[*sig.items(), *h])
    assert r.status_code == 403 and reason(r) == "ADMIN_KEY_INVALID"
    r = main.c.get("/v1/admin/fake/outbox", headers=[*sig.items(), ("X-Kiosk-Id", "KIOSK_LIB_01")])
    assert r.status_code == 401
