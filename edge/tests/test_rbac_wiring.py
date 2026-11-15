"""RBAC v2 wiring of the edge HTTP surface (/tmp/fg_design/RBAC_DESIGN_V2.md sections B, C, D).

1. Production default (AUTH_LEGACY_ADMIN_TOKEN off, MFA default roles): X-Admin-Token -> 401, CORS never
   allows X-Admin-Token, staff sessions work, MFA-required roles must enrol first.
2. Route matrix: every (METHOD, path) of create_app() is in exactly one of ROUTE_PERMISSIONS / PUBLIC_ROUTES /
   DEPTH_DEVICE_ROUTES, and every mapped route answers 401 without a credential, 403 MISSING_PERMISSION for a
   principal (staff session or API key) lacking the permission, and neither for one holding it. The holder /
   lacker sets are computed from rbac.EDGE_ROLES; an injected principal holding EXACTLY the mapped permissions
   proves the edge/app.py routes ask for nothing more.
3. The LAN app exposes only the two depth routes.
4. GET /v1/events ends with `event: auth` after logout (before the next event and at the heartbeat).
5. POST /v1/admin/access/codes/rotate identity rules. 6. The cloud actor is derived from the principal.

Scratch edge (contract_cloud.make_env, fake cloud over httpx.MockTransport), TestClient only, dummy secrets.
Fixtures that need the production default set the env BEFORE make_env() builds the app: the lifespan then
builds a fresh AuthService from it.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import queue
import threading
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from edge.auth import mfa, rbac
from edge.auth.models import AuthError, Principal
from edge.auth.staff_ops import cli_principal
from edge.events import AUTH_CLOSED_EVENT, EventBus
from edge.tests.contract_cloud import ADMIN, STAFF_PW, Env, staff_headers
from edge.tests.test_auth_support import fast_scrypt  # noqa: F401 - fixture, applied module-wide below

pytestmark = pytest.mark.usefixtures("fast_scrypt")  # cheap scrypt for every staff account / login here

ORIGIN = "http://localhost:5173"
PASSIVE = frozenset({"HEAD", "OPTIONS"})
PATH_PARAMS = {"attempt_id": "att_missing00", "user_id": "u_3c4d", "staff_id": "s_nobody01", "key_id": "abcd1234"}
EXACT_TOKEN = "fgs_" + "e" * 43  # well-formed, never issued: answered by the injected exact-permission principal
STREAM_PATH = "/v1/events"
DEMO_ROUTES = frozenset({("POST", "/v1/admin/clock"), ("POST", "/v1/admin/random-challenge")})
WAIT_S = 2.0
SAFETY_HEARTBEAT_S = 5.0  # > WAIT_S + margin: an `event: auth` within WAIT_S of a publish is not the heartbeat's
CONSOLE = cli_principal("pytest")


# ------------------------------------------------------------------ helpers
def api_routes(routes: Any, prefix: str = "") -> Iterator[tuple[str, APIRoute]]:
    """(full path, APIRoute) for every API route, descending into included routers (FastAPI >= 0.16x keeps an
    included router as one wrapper route with `original_router` + `include_context`)."""
    for route in routes:
        if isinstance(route, APIRoute):
            yield prefix + route.path, route
        inner = getattr(route, "original_router", None)
        if inner is not None:
            context = getattr(route, "include_context", None)
            yield from api_routes(inner.routes, prefix + str(getattr(context, "prefix", "") or ""))


def route_keys(app: Any, module: str | None = None) -> set[tuple[str, str]]:
    """Every (METHOD, path template) the app serves (HEAD / OPTIONS aside); `module` = endpoints defined there."""
    return {(m, path) for path, r in api_routes(app.routes)
            if module is None or r.endpoint.__module__ == module for m in r.methods if m not in PASSIVE}


def app_py_routes(app: Any) -> set[tuple[str, str]]:
    """Routes defined in edge/app.py (not the edge/auth router)."""
    return route_keys(app, "edge.app")


def concrete(path: str) -> str:
    return path.format(**PATH_PARAMS)


def call(c: TestClient, method: str, path: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    """(status, error object) for a minimal request; the SSE route is opened and closed at once."""
    url, hdrs = concrete(path), dict(headers or {})
    if path == STREAM_PATH:
        with c.stream("GET", url, headers=hdrs) as r:
            body = r.read() if r.status_code != 200 else b""
            return r.status_code, _error(r.status_code, body)
    if path == "/v1/depth/pending":
        url += "?wait_s=0"
    kwargs: dict[str, Any] = {} if method == "GET" else {"json": {}}
    r = c.request(method, url, headers=hdrs, **kwargs)
    return r.status_code, _error(r.status_code, r.content)


def _error(status: int, body: bytes) -> dict[str, Any]:
    if status < 400 or not body:
        return {}
    try:
        return json.loads(body).get("error") or {}
    except ValueError:
        return {}


def holder_roles(needed: tuple[str, ...]) -> list[str]:
    return sorted(r for r, perms in rbac.EDGE_ROLES.items() if rbac.has_permissions(perms, needed))


def lacking_roles(needed: tuple[str, ...]) -> list[str]:
    return sorted(r for r, perms in rbac.EDGE_ROLES.items() if not rbac.has_permissions(perms, needed))


def minimal_holder(needed: tuple[str, ...]) -> str:
    """The holder role with the fewest permissions (closest to 'exactly the needed ones')."""
    return min(holder_roles(needed), key=lambda r: (len(rbac.EDGE_ROLES[r]), r))


def role_user(role: str) -> str:
    return "u" + role.replace("_", "")[:20]


class Principals:
    """One cached staff session per role and one API key per key-eligible role, on the scratch edge's AuthService."""

    def __init__(self, env: Env) -> None:
        self.env = env
        self._sessions: dict[str, dict[str, str]] = {}
        self._keys: dict[str, dict[str, str]] = {}

    def session(self, role: str) -> dict[str, str]:
        if role not in self._sessions:
            self._sessions[role] = staff_headers(self.env.ctx, role_user(role), [role])
        return self._sessions[role]

    def fresh_session(self, role: str) -> dict[str, str]:
        staff_headers(self.env.ctx, role_user(role), [role])  # make sure the account exists
        token = self.env.ctx.auth.login_sync(role_user(role), STAFF_PW)[0]
        return {"Authorization": f"Bearer {token}"}

    def key(self, role: str) -> dict[str, str]:
        if role not in self._keys:
            _, full = self.env.ctx.auth.create_api_key(CONSOLE, f"pytest {role}", [role], expires_days=1)
            self._keys[role] = {"Authorization": f"Bearer {full}"}
        return self._keys[role]


def key_roles() -> list[str]:
    return sorted(set(rbac.EDGE_ROLES) - rbac.KEY_FORBIDDEN_ROLES)


def install_exact_principal(monkeypatch: pytest.MonkeyPatch, auth: Any) -> Callable[[tuple[str, ...]], dict[str, str]]:
    """EXACT_TOKEN authenticates as a staff principal (s_guard01) holding exactly the given permissions."""
    holder: dict[str, Principal] = {}
    original = auth.authenticate

    def authenticate(credential: str | None, **kwargs: Any) -> Principal:
        if credential == EXACT_TOKEN:
            return holder["principal"]
        return original(credential, **kwargs)

    monkeypatch.setattr(auth, "authenticate", authenticate)

    def use(permissions: tuple[str, ...]) -> dict[str, str]:
        holder["principal"] = Principal(kind="staff", id="s_guard01", username="guard01", display_name="Exact",
                                        roles=(), permissions=frozenset(permissions))
        return {"Authorization": f"Bearer {EXACT_TOKEN}"}

    return use


@pytest.fixture
def production_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Production defaults for the auth layer: no legacy token, MFA for admin + security_officer, DEMO_MODE=0."""
    monkeypatch.delenv("AUTH_LEGACY_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("AUTH_MFA_REQUIRED_ROLES", raising=False)
    monkeypatch.setenv("DEMO_MODE", "0")


@pytest.fixture
def matrix_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Legacy token off; MFA off so every role's session reaches the permission check (MFA gating: test 1)."""
    monkeypatch.delenv("AUTH_LEGACY_ADMIN_TOKEN", raising=False)
    monkeypatch.setenv("AUTH_MFA_REQUIRED_ROLES", "none")


# ================================================================== 1. production default
def test_production_default_rejects_the_legacy_token(production_env, make_env):
    env = make_env(demo=False)
    assert env.c.get("/v1/auth/status").json()["legacy_token_enabled"] is False
    for method, path in (("GET", "/v1/admin/store"), ("POST", "/v1/admin/mode")):
        for headers in (ADMIN, {}):
            status, err = call(env.c, method, path, headers)
            assert status == 401 and err.get("code") == "UNAUTHORIZED", (method, path, headers.keys(), err)
    evaluator = staff_headers(env.ctx, "evalone", ["evaluator"])  # store:read + mode:switch, not MFA-required
    assert env.c.get("/v1/admin/store", headers=evaluator).status_code == 200
    r = env.c.post("/v1/admin/mode", json={"force": "AUTO"}, headers=evaluator)
    assert r.status_code == 200, r.text


def test_production_default_cors_never_allows_the_legacy_header(production_env, make_env):
    env = make_env(demo=False)
    pre = {"Origin": ORIGIN, "Access-Control-Request-Method": "GET"}
    bad = env.c.options("/v1/admin/store", headers={**pre, "Access-Control-Request-Headers": "X-Admin-Token"})
    assert bad.status_code == 400
    assert "x-admin-token" not in bad.headers.get("access-control-allow-headers", "").lower()
    good = env.c.options("/v1/admin/store", headers={**pre, "Access-Control-Request-Headers": "Authorization"})
    assert good.status_code == 200 and "authorization" in good.headers["access-control-allow-headers"].lower()


def test_legacy_flag_on_allows_the_legacy_header_in_cors(make_env):
    env = make_env()  # conftest HERMETIC_ENV: AUTH_LEGACY_ADMIN_TOKEN=1
    r = env.c.options("/v1/admin/store", headers={"Origin": ORIGIN, "Access-Control-Request-Method": "GET",
                                                  "Access-Control-Request-Headers": "X-Admin-Token"})
    assert r.status_code == 200 and "x-admin-token" in r.headers["access-control-allow-headers"].lower()


def test_production_default_mfa_role_must_enrol_then_signs_in_with_totp(production_env, make_env):
    env = make_env(demo=False)
    auth = env.ctx.auth
    no_mfa = staff_headers(env.ctx, "guard01", ["security_officer"])
    status, err = call(env.c, "GET", "/v1/admin/store", no_mfa)
    assert status == 403 and err.get("reason") == "MFA_ENROLMENT_REQUIRED", err
    assert env.c.get("/v1/auth/me", headers=no_mfa).status_code == 200  # allowed while pending
    setup = auth.begin_mfa(CONSOLE, "s_guard01")
    step = mfa.current_step(auth.clock())
    auth.confirm_mfa(CONSOLE, "s_guard01", mfa.code_at(setup.secret, step))
    with pytest.raises(AuthError) as exc:
        auth.login_sync("guard01", STAFF_PW)
    assert exc.value.status == 401 and exc.value.reason == "MFA_REQUIRED"
    token = auth.login_sync("guard01", STAFF_PW, mfa.code_at(setup.secret, step + 1))[0]  # next step: no replay
    assert env.c.get("/v1/admin/store", headers={"Authorization": f"Bearer {token}"}).status_code == 200


# ================================================================== 2. route matrix
def test_every_route_is_mapped_exactly_once(make_env):
    env = make_env()
    routes = route_keys(env.c.app)
    tables = {"ROUTE_PERMISSIONS": set(rbac.ROUTE_PERMISSIONS), "PUBLIC_ROUTES": set(rbac.PUBLIC_ROUTES),
              "DEPTH_DEVICE_ROUTES": set(rbac.DEPTH_DEVICE_ROUTES)}
    unmapped = sorted(r for r in routes if not any(r in t for t in tables.values()))
    doubly = sorted(r for r in routes if sum(r in t for t in tables.values()) > 1)
    stale = {name: sorted(t - routes) for name, t in tables.items() if t - routes}
    assert not unmapped, f"routes in no RBAC table: {unmapped}"
    assert not doubly, f"routes in more than one RBAC table: {doubly}"
    assert not stale, f"RBAC table entries with no route: {stale}"


def test_every_privileged_route_needs_a_credential(matrix_env, make_env):
    env = make_env()
    for method, path in sorted(rbac.ROUTE_PERMISSIONS):
        status, err = call(env.c, method, path)
        assert status == 401 and err.get("code") == "UNAUTHORIZED", (method, path, status, err)
        status, err = call(env.c, method, path, ADMIN)  # legacy flag off: the shared token is no credential
        assert status == 401, (method, path, status, err)


def test_principal_lacking_the_permission_gets_403_missing_permission(matrix_env, make_env):
    env = make_env()
    who = Principals(env)
    checked = 0
    for (method, path), needed in sorted(rbac.ROUTE_PERMISSIONS.items()):
        if not needed:
            continue
        for role in lacking_roles(needed):
            status, err = call(env.c, method, path, who.session(role))
            assert status == 403 and err.get("reason") == "MISSING_PERMISSION", (method, path, role, err)
            assert sorted(err.get("required") or []) == sorted(needed), (method, path, err)
            checked += 1
        for role in key_roles():
            if rbac.has_permissions(rbac.key_permissions([role]), needed):
                continue
            status, err = call(env.c, method, path, who.key(role))
            assert status == 403 and err.get("reason") == "MISSING_PERMISSION", (method, path, f"key:{role}", err)
            checked += 1
    assert checked > len(rbac.ROUTE_PERMISSIONS)


def test_principal_holding_the_permission_passes_the_check(matrix_env, make_env):
    env = make_env()
    who = Principals(env)
    for (method, path), needed in sorted(rbac.ROUTE_PERMISSIONS.items()):
        if not needed:
            continue
        status, err = call(env.c, method, path, who.session(minimal_holder(needed)))
        assert status != 401 and err.get("reason") != "MISSING_PERMISSION", (method, path, status, err)
        assert status != 403, (method, path, minimal_holder(needed), err)
        for role in key_roles():
            if rbac.has_permissions(rbac.key_permissions([role]), needed):
                status, err = call(env.c, method, path, who.key(role))
                assert status not in (401, 403), (method, path, f"key:{role}", status, err)


def test_api_keys_never_pass_key_forbidden_permissions(matrix_env, make_env):
    env = make_env()
    who = Principals(env)
    for (method, path), needed in sorted(rbac.ROUTE_PERMISSIONS.items()):
        if not set(needed) & rbac.KEY_FORBIDDEN_PERMISSIONS:
            continue
        for role in key_roles():
            status, err = call(env.c, method, path, who.key(role))
            assert status == 403 and err.get("reason") == "MISSING_PERMISSION", (method, path, role, err)


def test_app_routes_need_nothing_beyond_their_mapped_permissions(matrix_env, make_env, monkeypatch):
    env = make_env()
    exact = install_exact_principal(monkeypatch, env.ctx.auth)
    covered = 0
    for method, path in sorted(app_py_routes(env.c.app)):
        needed = rbac.ROUTE_PERMISSIONS.get((method, path))
        if not needed:
            continue
        status, err = call(env.c, method, path, exact(needed))
        assert status not in (401, 403), (method, path, needed, status, err)
        covered += 1
    assert covered == len([k for k in app_py_routes(env.c.app) if rbac.ROUTE_PERMISSIONS.get(k)])


def test_any_principal_routes_accept_every_session(matrix_env, make_env):
    env = make_env()
    who = Principals(env)
    for (method, path), needed in sorted(rbac.ROUTE_PERMISSIONS.items()):
        if needed:
            continue
        status, err = call(env.c, method, path, who.fresh_session("auditor"))  # logout ends a session: fresh one
        assert status not in (401, 403), (method, path, status, err)


KEY_REFUSED = (  # (method, path, a VALID body): the identity check must refuse an API key, not body validation
    ("POST", "/v1/auth/password", {"current_password": "x" * 12, "new_password": "fresh-cobalt-heron-77"}),
    ("POST", "/v1/auth/mfa/enroll", {"current_password": "x" * 12}),
    ("POST", "/v1/auth/mfa/confirm", {"totp_code": "123456"}),
    ("GET", "/v1/admin/staff", None),
    ("GET", "/v1/admin/api-keys", None),
    ("POST", "/v1/admin/api-keys", {"name": "k", "roles": ["evaluator"], "confirm_password": "x" * 12}),
)


def test_api_keys_cannot_use_self_service_or_staff_routes(matrix_env, make_env):
    env = make_env()
    key = Principals(env).key("evaluator")
    for method, path, body in KEY_REFUSED:
        r = env.c.request(method, path, headers=key, **({} if body is None else {"json": body}))
        assert r.status_code == 403, (method, path, r.status_code, r.text)
    assert env.c.get("/v1/auth/me", headers=key).status_code == 200


def test_public_routes_need_no_credential(matrix_env, make_env):
    env = make_env()
    for method, path in sorted(rbac.PUBLIC_ROUTES):
        status, err = call(env.c, method, path)
        assert status not in (401, 403), (method, path, status, err)


def test_depth_routes_need_the_depth_token_not_staff_credentials(matrix_env, make_env):
    env = make_env()
    admin = Principals(env).session("admin")
    depth = {"X-Depth-Token": env.ctx.settings.depth_device_token}
    for method, path in sorted(rbac.DEPTH_DEVICE_ROUTES):
        for headers in ({}, admin, ADMIN):
            status, _ = call(env.c, method, path, headers)
            assert status == 401, (method, path, headers.keys())
    status, _ = call(env.c, "GET", "/v1/depth/pending", depth)
    assert status in (200, 204)


def test_demo_routes_answer_not_demo_mode_when_demo_is_off(matrix_env, make_env):
    env = make_env(demo=False)
    who = Principals(env)
    for method, path in sorted(DEMO_ROUTES):
        assert call(env.c, method, path)[0] == 401
        for role in sorted(rbac.EDGE_ROLES):
            status, err = call(env.c, method, path, who.session(role))
            assert status == 403 and err.get("reason") == "NOT_DEMO_MODE", (method, path, role, err)
    perms = set(env.c.get("/v1/auth/me", headers=who.session("admin")).json()["principal"]["permissions"])
    assert not perms & rbac.DEMO_ONLY_PERMISSIONS


# ================================================================== 3. LAN app
def test_lan_app_exposes_only_the_depth_routes(make_env):
    from edge.app import create_lan_app

    env = make_env()
    lan = create_lan_app(env.ctx)
    assert route_keys(lan) == set(rbac.DEPTH_DEVICE_ROUTES)
    with TestClient(lan) as c:
        assert c.get("/v1/auth/status").status_code == 404
        assert c.post("/v1/auth/login", json={"username": "x", "password": "y"}).status_code == 404
        assert c.get("/v1/health").status_code == 404
        assert c.get("/v1/admin/store", headers=ADMIN).status_code == 404
        depth = {"X-Depth-Token": env.ctx.settings.depth_device_token}
        assert c.get("/v1/depth/pending", params={"wait_s": 0}, headers=depth).status_code in (200, 204)


# ================================================================== 4. SSE closes after logout
@contextlib.contextmanager
def patched_stream(monkeypatch: pytest.MonkeyPatch, bus: EventBus, heartbeat_s: float) -> Iterator[threading.Event]:
    """Short heartbeat for the route's stream; setting the yielded Event makes the stream end at the next heartbeat
    (a safety net so a broken re-check can never hang the suite)."""
    abort = threading.Event()
    original = bus.stream

    def stream(is_disconnected: Callable[[], Any], authorized: Callable[[], bool] | None = None, **_: Any):
        async def disconnected() -> bool:
            return abort.is_set() or await is_disconnected()

        args = (disconnected,) if authorized is None else (disconnected, authorized)
        return original(*args, heartbeat_s=heartbeat_s)

    monkeypatch.setattr(bus, "stream", stream)
    try:
        yield abort
    finally:
        abort.set()


def _reader(resp, out: queue.Queue) -> None:
    try:
        for line in resp.iter_lines():
            out.put(line)
    except Exception as exc:  # noqa: BLE001 - surfaced to the test
        out.put(exc)
    finally:
        out.put(None)


def _next_line(out: queue.Queue, timeout_s: float = WAIT_S) -> str | None:
    """Next non-blank SSE line (None = the stream ended); queue.Empty after timeout_s."""
    while True:
        item = out.get(timeout=timeout_s)
        if isinstance(item, Exception):
            raise item
        if item != "":
            return item


def _lines_until_end(out: queue.Queue, timeout_s: float = WAIT_S) -> list[str]:
    lines: list[str] = []
    while (line := _next_line(out, timeout_s)) is not None:
        lines.append(line)
    return lines


@pytest.mark.parametrize("trigger", ["event", "heartbeat"])
def test_sse_stream_ends_with_auth_event_after_logout(matrix_env, make_env, monkeypatch, trigger):
    env = make_env()
    headers = Principals(env).fresh_session("auditor")
    heartbeat = SAFETY_HEARTBEAT_S if trigger == "event" else 0.05
    with patched_stream(monkeypatch, env.ctx.events, heartbeat), \
            env.c.stream("GET", STREAM_PATH, headers=headers) as resp:
        assert resp.status_code == 200
        out: queue.Queue = queue.Queue()
        threading.Thread(target=_reader, args=(resp, out), daemon=True).start()
        assert _next_line(out) == ": connected"
        assert env.c.post("/v1/auth/logout", headers=headers).status_code == 204
        if trigger == "event":
            env.c.portal.call(env.ctx.events.publish, "decision", {"attempt_id": "att_after", "decision": "DENY"})
        lines = _lines_until_end(out)
    assert "event: auth" in lines, lines
    assert lines[-2:] == AUTH_CLOSED_EVENT.strip("\n").split("\n"), lines
    assert not any("att_after" in ln for ln in lines)  # the event after logout was never delivered
    assert env.ctx.events.subscribers == 0


def test_sse_still_delivers_events_to_a_valid_session(matrix_env, make_env, monkeypatch):
    env = make_env()
    headers = Principals(env).fresh_session("auditor")
    with patched_stream(monkeypatch, env.ctx.events, SAFETY_HEARTBEAT_S) as abort, \
            env.c.stream("GET", STREAM_PATH, headers=headers) as resp:
        out: queue.Queue = queue.Queue()
        threading.Thread(target=_reader, args=(resp, out), daemon=True).start()
        assert _next_line(out) == ": connected"
        env.c.portal.call(env.ctx.events.publish, "decision", {"attempt_id": "att_live", "decision": "DENY"})
        assert _next_line(out) == "event: decision"
        assert "att_live" in (_next_line(out) or "")
        abort.set()
        _lines_until_end(out, SAFETY_HEARTBEAT_S + WAIT_S)  # ends at the next heartbeat


def _run(coro_fn: Callable[[], Any]) -> None:
    asyncio.run(asyncio.wait_for(coro_fn(), timeout=WAIT_S * 2))


async def _never_disconnected() -> bool:
    return False


def test_event_bus_closes_at_heartbeat_when_authorization_ends():
    async def run() -> None:
        bus, state = EventBus(), {"ok": True}
        gen = bus.stream(_never_disconnected, lambda: state["ok"], heartbeat_s=0.05)
        assert await gen.__anext__() == ": connected\n\n"
        assert await gen.__anext__() == ": ping\n\n"
        state["ok"] = False
        assert await gen.__anext__() == AUTH_CLOSED_EVENT
        with pytest.raises(StopAsyncIteration):
            await gen.__anext__()
        assert bus.subscribers == 0

    _run(run)


def test_event_bus_rechecks_before_every_event():
    async def run() -> None:
        bus, state = EventBus(), {"ok": True}
        gen = bus.stream(_never_disconnected, lambda: state["ok"], heartbeat_s=30)
        assert await gen.__anext__() == ": connected\n\n"
        bus.publish("decision", {"attempt_id": "att_1"})
        assert (await gen.__anext__()).startswith("event: decision\n")
        state["ok"] = False
        bus.publish("decision", {"attempt_id": "att_2"})
        assert await gen.__anext__() == AUTH_CLOSED_EVENT
        with pytest.raises(StopAsyncIteration):
            await gen.__anext__()

    _run(run)


def test_event_bus_refuses_an_unauthorized_stream_at_once():
    async def run() -> None:
        bus = EventBus()
        items = [m async for m in bus.stream(_never_disconnected, lambda: False, heartbeat_s=30)]
        assert items == [AUTH_CLOSED_EVENT] and bus.subscribers == 0

    _run(run)


# ================================================================== 5. codes rotate identity rules
ROTATE = "/v1/admin/access/codes/rotate"


def _rotate(env: Env, headers: dict[str, str], staff_id: str, count: int):
    return env.c.post(ROTATE, json={"staff_id": staff_id, "count": count}, headers=headers)


def test_codes_rotate_needs_a_staff_identity(make_env):
    env = make_env()  # legacy flag on (conftest): the legacy principal holds codes:rotate
    r = _rotate(env, ADMIN, "s_guard01", 2)
    assert r.status_code == 403 and r.json()["error"]["reason"] == "NO_STAFF_IDENTITY", r.text
    key = Principals(env).key("security_officer")  # codes:rotate is key-forbidden: refused at the permission
    r = _rotate(env, key, "s_guard01", 2)
    assert r.status_code == 403 and r.json()["error"]["reason"] == "MISSING_PERMISSION", r.text
    assert env.cloud.calls("POST", "/v1/admin/codes/rotate") == []


def test_check_codes_rotate_refuses_a_key_even_holding_the_permission():
    from edge.access_models import CodesRotateRequest
    from edge.app import check_codes_rotate

    key = Principal(kind="api_key", id="key:abcd1234", username=None, display_name="k", roles=("security_officer",),
                    permissions=frozenset({"codes:rotate"}), key_id="abcd1234")
    with pytest.raises(AuthError) as exc:
        check_codes_rotate(key, CodesRotateRequest(staff_id="s_guard01", count=2))
    assert exc.value.reason == "NO_STAFF_IDENTITY"


def test_codes_rotate_own_staff_id_only(make_env):
    env = make_env()
    guard = env.staff("guard01", ("security_officer",))
    r = _rotate(env, guard, "s_guard02", 2)
    assert r.status_code == 403 and r.json()["error"]["reason"] == "STAFF_ID_NOT_OWN", r.text
    assert _rotate(env, guard, "s_guard01", 5).status_code == 422
    assert env.cloud.calls("POST", "/v1/admin/codes/rotate") == []
    r = _rotate(env, guard, "s_guard01", 2)
    assert r.status_code == 200, r.text
    assert "no-store" in r.headers.get("cache-control", "")
    sent = env.cloud.calls("POST", "/v1/admin/codes/rotate")[-1]["json"]
    assert sent["actor"] == "staff:s_guard01" and sent["staff_id"] == "s_guard01"


def test_codes_rotate_any_lets_an_admin_rotate_another_staff_id(make_env):
    env = make_env()
    boss = env.staff("boss", ("admin",))
    r = _rotate(env, boss, "s_guard02", 2)
    assert r.status_code == 200, r.text
    assert env.cloud.calls("POST", "/v1/admin/codes/rotate")[-1]["json"]["actor"] == "staff:s_boss"


# ================================================================== 6. actor derivation
def test_revoke_sends_the_staff_actor(make_env):
    env = make_env()
    guard = env.staff("guard01", ("security_officer",))
    r = env.c.post("/v1/admin/access/users/u_3c4d/revoke", json={"reason": "ADMIN", "actor": "forged"},
                   headers=guard)
    assert r.status_code == 200, r.text
    assert env.cloud.calls("POST", "/v1/admin/revocations")[-1]["json"]["actor"] == "staff:s_guard01"


def test_erasure_sends_the_staff_actor_in_the_query(make_env):
    env = make_env()
    env.seed_template("u_3c4d")
    boss = env.staff("boss", ("admin",))
    r = env.c.delete("/v1/enroll/u_3c4d", headers=boss)
    assert r.status_code == 200, r.text
    assert env.cloud.calls("DELETE", "/v1/enroll/u_3c4d")[-1]["query"] == {"actor": "staff:s_boss"}

