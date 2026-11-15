"""Role-based access control catalog: the single source of truth for SYSTEM-user permissions.

Two different kinds of "role" exist in FaceGuard and must never be mixed:
- SYSTEM roles (this module) decide who may operate the kiosk system: admin, security_officer, enroller,
  auditor, evaluator on the edge; admin, edge_proxy, auditor on the cloud.
- ENTRANT roles (student, faculty, staff, contractor, visitor) live in the signed SC1 schedule bundle and
  decide campus access. They are unrelated to this module.

Stdlib only: the cloud deploy artifact vendor-copies this file (cloud/infra/build_artifact.sh).
Unknown roles grant nothing (fail-closed); the catalogs are immutable at runtime.
ROUTE_PERMISSIONS / PUBLIC_ROUTES / DEPTH_DEVICE_ROUTES cover every edge route (a test walks app.routes).
Bump RBAC_VERSION whenever a role, a permission or a route mapping changes.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import StrEnum
from types import MappingProxyType

RBAC_VERSION = 2
MAX_ROLES_PER_ACCOUNT = 3


class EdgePermission(StrEnum):
    EVENTS_READ = "events:read"          # GET /v1/events (SSE live decision feed)
    METRICS_READ = "metrics:read"        # GET /v1/metrics
    STORE_READ = "store:read"            # GET /v1/admin/store (minimal offline decision log)
    ATTEMPT_SIGNALS = "attempt:signals"  # GET /v1/admin/attempt/{id}/signals
    MODE_SWITCH = "mode:switch"          # POST /v1/admin/mode
    SYNC_RUN = "sync:run"                # POST /v1/admin/sync
    RATELIMIT_RESET = "ratelimit:reset"  # POST /v1/admin/rate-limit/reset
    EVAL_ADMIN = "eval:admin"            # POST / DELETE /v1/admin/eval/context
    DEMO_CLOCK = "demo:clock"            # POST /v1/admin/clock (DEMO_MODE=1 only; admin only)
    CHALLENGE_CONTROL = "challenge:control"  # POST /v1/admin/random-challenge (DEMO_MODE=1 only)
    ENROL_READ = "enrol:read"            # GET /v1/admin/users
    ENROL_WRITE = "enrol:write"          # POST /v1/enroll
    ENROL_ERASE = "enrol:erase"          # DELETE /v1/enroll/{user_id}
    ACCESS_READ = "access:read"          # GET /v1/admin/access/users
    ACCESS_EDIT = "access:edit"          # PUT /v1/admin/access/users/{user_id}
    ACCESS_REVOKE = "access:revoke"      # POST /v1/admin/access/users/{user_id}/revoke
    CODES_ROTATE = "codes:rotate"        # POST /v1/admin/access/codes/rotate for the caller's own staff_id
    CODES_ROTATE_ANY = "codes:rotate_any"  # same route for any staff_id
    BUNDLE_REFRESH = "bundle:refresh"    # POST /v1/admin/bundle/refresh
    STAFF_MANAGE = "staff:manage"        # /v1/admin/staff*, /v1/admin/api-keys*
    AUDIT_READ = "audit:read"            # GET /v1/admin/auth/audit, /v1/admin/alerts, /v1/admin/sync/last


class CloudPermission(StrEnum):
    SCHEDULE_READ = "schedule:read"
    SCHEDULE_WRITE = "schedule:write"
    REVOCATIONS_WRITE = "revocations:write"
    ACCESS_READ = "access:read"
    ACCESS_EDIT = "access:edit"
    CODES_ROTATE = "codes:rotate"
    CONTACT_EDIT = "contact:edit"
    AUDIT_READ = "audit:read"
    ALERTS_READ = "alerts:read"
    DECISIONS_READ = "decisions:read"
    STATS_READ = "stats:read"
    METRICS_READ = "metrics:read"
    OUTBOX_READ = "outbox:read"


E = EdgePermission
C = CloudPermission

EDGE_ROLES: Mapping[str, frozenset[str]] = MappingProxyType({
    "admin": frozenset(E),
    "security_officer": frozenset({
        E.EVENTS_READ, E.METRICS_READ, E.STORE_READ, E.ATTEMPT_SIGNALS, E.MODE_SWITCH, E.SYNC_RUN,
        E.RATELIMIT_RESET, E.ENROL_READ, E.ACCESS_READ, E.ACCESS_REVOKE, E.CODES_ROTATE, E.BUNDLE_REFRESH,
        E.AUDIT_READ,
    }),
    "enroller": frozenset({E.ENROL_READ, E.ENROL_WRITE, E.ENROL_ERASE, E.ACCESS_READ, E.BUNDLE_REFRESH}),
    "auditor": frozenset({E.EVENTS_READ, E.METRICS_READ, E.STORE_READ, E.ENROL_READ, E.ACCESS_READ, E.AUDIT_READ}),
    "evaluator": frozenset({
        E.EVENTS_READ, E.METRICS_READ, E.ATTEMPT_SIGNALS, E.EVAL_ADMIN, E.RATELIMIT_RESET, E.CHALLENGE_CONTROL,
        E.MODE_SWITCH, E.STORE_READ,
    }),
})

CLOUD_ROLES: Mapping[str, frozenset[str]] = MappingProxyType({
    "admin": frozenset(C) - {C.OUTBOX_READ},
    # Key held by an edge: the edge authorises the human first (edge permissions), then proxies.
    "edge_proxy": frozenset({
        C.SCHEDULE_READ, C.ACCESS_READ, C.ACCESS_EDIT, C.REVOCATIONS_WRITE, C.CODES_ROTATE,
    }),
    "auditor": frozenset({
        C.SCHEDULE_READ, C.ACCESS_READ, C.AUDIT_READ, C.ALERTS_READ, C.DECISIONS_READ, C.STATS_READ,
        C.METRICS_READ,
    }),
})

# API keys (automation) can never hold these, whatever their roles; role admin is refused for keys.
KEY_FORBIDDEN_PERMISSIONS: frozenset[str] = frozenset(str(p) for p in (
    E.STAFF_MANAGE, E.CODES_ROTATE, E.CODES_ROTATE_ANY, E.ACCESS_EDIT, E.ACCESS_REVOKE, E.ENROL_ERASE, E.DEMO_CLOCK,
))
KEY_FORBIDDEN_ROLES: frozenset[str] = frozenset({"admin"})
# The deprecated shared X-Admin-Token (AUTH_LEGACY_ADMIN_TOKEN=1): admin minus staff management / any-id codes.
LEGACY_PERMISSIONS: frozenset[str] = frozenset(str(p) for p in E) - {str(E.STAFF_MANAGE), str(E.CODES_ROTATE_ANY)}
# Granted only while DEMO_MODE=1 (removed from every principal otherwise).
DEMO_ONLY_PERMISSIONS: frozenset[str] = frozenset({str(E.DEMO_CLOCK), str(E.CHALLENGE_CONTROL)})

_V1 = "/v1"
# Every edge HTTP route -> permissions it needs (ALL of them). An empty tuple = any authenticated principal.
ROUTE_PERMISSIONS: Mapping[tuple[str, str], tuple[str, ...]] = MappingProxyType({
    ("GET", f"{_V1}/events"): (E.EVENTS_READ,),
    ("GET", f"{_V1}/metrics"): (E.METRICS_READ,),
    ("POST", f"{_V1}/admin/mode"): (E.MODE_SWITCH,),
    ("GET", f"{_V1}/admin/store"): (E.STORE_READ,),
    ("GET", f"{_V1}/admin/mode/detail"): (E.STORE_READ,),
    ("POST", f"{_V1}/admin/sync"): (E.SYNC_RUN,),
    ("POST", f"{_V1}/admin/eval/context"): (E.EVAL_ADMIN,),
    ("DELETE", f"{_V1}/admin/eval/context"): (E.EVAL_ADMIN,),
    ("POST", f"{_V1}/admin/rate-limit/reset"): (E.RATELIMIT_RESET,),
    ("POST", f"{_V1}/admin/clock"): (E.DEMO_CLOCK,),
    ("POST", f"{_V1}/admin/random-challenge"): (E.CHALLENGE_CONTROL,),
    ("GET", f"{_V1}/admin/attempt/{{attempt_id}}/signals"): (E.ATTEMPT_SIGNALS,),
    ("GET", f"{_V1}/admin/users"): (E.ENROL_READ,),
    ("GET", f"{_V1}/admin/access/users"): (E.ACCESS_READ,),
    ("PUT", f"{_V1}/admin/access/users/{{user_id}}"): (E.ACCESS_EDIT,),
    ("POST", f"{_V1}/admin/access/users/{{user_id}}/revoke"): (E.ACCESS_REVOKE,),
    ("POST", f"{_V1}/admin/access/codes/rotate"): (E.CODES_ROTATE,),  # other staff ids: + codes:rotate_any
    ("POST", f"{_V1}/admin/bundle/refresh"): (E.BUNDLE_REFRESH,),
    ("GET", f"{_V1}/admin/alerts"): (E.AUDIT_READ,),
    ("GET", f"{_V1}/admin/sync/last"): (E.AUDIT_READ,),
    ("POST", f"{_V1}/enroll"): (E.ENROL_WRITE,),
    ("DELETE", f"{_V1}/enroll/{{user_id}}"): (E.ENROL_ERASE,),
    # staff auth (edge/auth/routes.py)
    ("GET", f"{_V1}/auth/me"): (),
    ("POST", f"{_V1}/auth/logout"): (),
    ("POST", f"{_V1}/auth/activity"): (),
    ("POST", f"{_V1}/auth/password"): (),
    ("POST", f"{_V1}/auth/mfa/enroll"): (),
    ("POST", f"{_V1}/auth/mfa/confirm"): (),
    ("GET", f"{_V1}/admin/roles"): (),
    ("GET", f"{_V1}/admin/staff"): (E.STAFF_MANAGE,),
    ("POST", f"{_V1}/admin/staff"): (E.STAFF_MANAGE,),
    ("GET", f"{_V1}/admin/staff/{{staff_id}}"): (E.STAFF_MANAGE,),
    ("PATCH", f"{_V1}/admin/staff/{{staff_id}}"): (E.STAFF_MANAGE,),
    ("DELETE", f"{_V1}/admin/staff/{{staff_id}}"): (E.STAFF_MANAGE,),
    ("POST", f"{_V1}/admin/staff/{{staff_id}}/password"): (E.STAFF_MANAGE,),
    ("POST", f"{_V1}/admin/staff/{{staff_id}}/unlock"): (E.STAFF_MANAGE,),
    ("POST", f"{_V1}/admin/staff/{{staff_id}}/mfa/reset"): (E.STAFF_MANAGE,),
    ("GET", f"{_V1}/admin/api-keys"): (E.STAFF_MANAGE,),
    ("POST", f"{_V1}/admin/api-keys"): (E.STAFF_MANAGE,),
    ("DELETE", f"{_V1}/admin/api-keys/{{key_id}}"): (E.STAFF_MANAGE,),
    ("GET", f"{_V1}/admin/auth/audit"): (E.AUDIT_READ,),
})
ROUTE_PERMISSIONS = MappingProxyType({k: tuple(str(p) for p in v) for k, v in ROUTE_PERMISSIONS.items()})

# No staff authentication, ever (the kiosk entrant flow, health and the login itself).
PUBLIC_ROUTES: frozenset[tuple[str, str]] = frozenset({
    ("GET", f"{_V1}/health"), ("GET", f"{_V1}/mode"), ("GET", f"{_V1}/auth/status"), ("POST", f"{_V1}/auth/login"),
    ("POST", f"{_V1}/session/start"), ("GET", f"{_V1}/attempt/{{attempt_id}}"),
    *(("POST", f"{_V1}/attempt/{{attempt_id}}/{leaf}")
      for leaf in ("frames", "probe", "rendered", "challenge", "fallback", "otp/send")),
})
# X-Depth-Token (the DepthProbe iPhone) only; the LAN app exposes nothing else.
DEPTH_DEVICE_ROUTES: frozenset[tuple[str, str]] = frozenset({
    ("GET", f"{_V1}/depth/pending"), ("POST", f"{_V1}/depth/frames"),
})

ROLE_DESCRIPTIONS: Mapping[str, str] = MappingProxyType({
    "admin": "Full control, including staff accounts, API keys and every kiosk setting.",
    "security_officer": "Live monitoring, offline/sync control, revocations, own staff override codes.",
    "enroller": "Registers and erases faces of people already in the signed schedule; refreshes the bundle.",
    "auditor": "Read-only: live feed, metrics, minimal decision log, audit log.",
    "evaluator": "Runs evaluation sessions: eval context, mode switch, rate-limit reset, random challenge (DEMO_MODE).",
    "edge_proxy": "Cloud key held by a kiosk edge; the edge authorises each human before proxying.",
})


def validate_roles(roles: Iterable[str], catalog: Mapping[str, frozenset[str]] = EDGE_ROLES) -> tuple[str, ...]:
    """Normalised (sorted, de-duplicated) roles, or ValueError for an empty, oversized or unknown set."""
    out = tuple(sorted({str(r).strip() for r in roles}))
    if not out:
        raise ValueError("at least one role is required")
    if len(out) > MAX_ROLES_PER_ACCOUNT:
        raise ValueError(f"at most {MAX_ROLES_PER_ACCOUNT} roles per account")
    unknown = [r for r in out if r not in catalog]
    if unknown:
        raise ValueError(f"unknown role(s): {', '.join(unknown)}")
    return out


def permissions_for(roles: Iterable[str], catalog: Mapping[str, frozenset[str]] = EDGE_ROLES) -> frozenset[str]:
    """Union of the roles' permissions. Unknown roles contribute nothing (fail-closed)."""
    granted: set[str] = set()
    for role in roles:
        granted |= catalog.get(role, frozenset())
    return frozenset(str(p) for p in granted)


def has_permissions(granted: Iterable[str], required: Iterable[str]) -> bool:
    """True when every required permission is granted (an empty requirement is never satisfied implicitly)."""
    need = {str(p) for p in required}
    return bool(need) and need <= {str(p) for p in granted}


def validate_key_roles(roles: Iterable[str]) -> tuple[str, ...]:
    """validate_roles for API keys: 1..3 edge roles, never admin."""
    out = validate_roles(roles)
    refused = sorted(set(out) & KEY_FORBIDDEN_ROLES)
    if refused:
        raise ValueError(f"API keys cannot hold role(s): {', '.join(refused)}")
    return out


def key_permissions(roles: Iterable[str]) -> frozenset[str]:
    """Effective API-key permissions: the roles' union minus KEY_FORBIDDEN_PERMISSIONS."""
    return permissions_for(roles) - KEY_FORBIDDEN_PERMISSIONS
