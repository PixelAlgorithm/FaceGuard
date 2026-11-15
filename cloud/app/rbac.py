"""Cloud admin RBAC (design v2 §E): API-key principals, per-route permissions, actor attribution.

Credentials on `/v1/admin/*` (the kiosk HMAC stays mandatory on every route; this is checked on top of it):
- `Authorization: Bearer fgk_<key_id>.<secret>`: looked up in CLOUD_API_KEYS_JSON (list of {key_id, sha256 of
  the secret part, roles, name, kiosk_ids?, expires_at?}). If an Authorization header is present it alone decides.
- `X-Admin-Token`: legacy shared token, accepted only when AUTH_LEGACY_ADMIN_TOKEN=1 (principal = role admin).
Every admin-credential failure is 403 FORBIDDEN (never 401; 401 means the kiosk HMAC failed) with reason
ADMIN_KEY_INVALID | ADMIN_KEY_EXPIRED | MISSING_PERMISSION | KIOSK_NOT_BOUND | LEGACY_DISABLED.

An `edge_proxy` key is bound to exactly one kiosk, which must be the HMAC-authenticated kiosk. Its requests may
assert the human actor (set by the edge from the staff session, integrity-protected by the kiosk HMAC body
hash); asserted actors are recorded (actor_assurance="edge_asserted") but never used for authorisation.

The permission catalog is the edge's (edge/auth/rbac.py, vendored into the cloud artifact): imported, never
copied. The cloud refuses to start when it is missing.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .config import PROJECT_ROOT, ConfigError

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:  # stdlib-only modules, vendored by cloud/infra/build_artifact.sh
    from edge.auth import rbac as _edge_rbac
    from edge.auth import tokens as _tokens
except ImportError as _exc:  # pragma: no cover - exercised only by a broken artifact
    raise RuntimeError("edge.auth.rbac / edge.auth.tokens are missing from this build: the cloud refuses to "
                       "start without the RBAC catalog (cloud/infra/build_artifact.sh must ship them)") from _exc

CloudPermission = _edge_rbac.CloudPermission
CLOUD_ROLES: Mapping[str, frozenset[str]] = _edge_rbac.CLOUD_ROLES
P = CloudPermission

EDGE_PROXY_ROLE = "edge_proxy"
ADMIN_ROLE = "admin"
LEGACY_ACTOR = "legacy:admin_token"
KEY_ID_RE = re.compile(r"^[a-z0-9]{8}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# Actors an edge_proxy key may assert (the edge derives them from its principal, V2 §D)
ASSERTED_ACTOR_RE = re.compile(r"^(staff:s_[0-9a-z_]{2,32}|key:[a-z0-9]{8}|legacy:admin_token)$")
MAX_KEY_NAME = 64

# reasons (error.reason of the 403 FORBIDDEN envelope)
ADMIN_KEY_INVALID = "ADMIN_KEY_INVALID"
ADMIN_KEY_EXPIRED = "ADMIN_KEY_EXPIRED"
MISSING_PERMISSION = "MISSING_PERMISSION"
KIOSK_NOT_BOUND = "KIOSK_NOT_BOUND"
LEGACY_DISABLED = "LEGACY_DISABLED"

# (METHOD, path template) -> required permission, for every /v1/admin/* route (tests walk app.routes)
ROUTE_PERMISSIONS: Mapping[tuple[str, str], str] = {
    ("GET", "/v1/admin/schedule"): P.SCHEDULE_READ,
    ("PUT", "/v1/admin/schedule"): P.SCHEDULE_WRITE,
    ("PUT", "/v1/admin/schedule/{kiosk_id}"): P.SCHEDULE_WRITE,
    ("POST", "/v1/admin/revocations"): P.REVOCATIONS_WRITE,
    ("GET", "/v1/admin/users"): P.ACCESS_READ,
    ("PUT", "/v1/admin/users/{user_id}/access"): P.ACCESS_EDIT,
    ("POST", "/v1/admin/codes/rotate"): P.CODES_ROTATE,
    ("GET", "/v1/admin/audit"): P.AUDIT_READ,
    ("GET", "/v1/admin/alerts"): P.ALERTS_READ,
    ("GET", "/v1/admin/decisions"): P.DECISIONS_READ,
    ("GET", "/v1/admin/stats"): P.STATS_READ,
    ("GET", "/v1/admin/metrics"): P.METRICS_READ,
    ("PUT", "/v1/admin/users/{user_id}/contact"): P.CONTACT_EDIT,
    ("GET", "/v1/admin/fake/outbox"): P.OUTBOX_READ,
}


class AdminAuthError(Exception):
    """403 FORBIDDEN with a machine-readable reason (mapped to the error envelope by the router)."""

    def __init__(self, reason: str, message: str, required: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.required = required


@dataclass(frozen=True)
class ApiKeyEntry:
    key_id: str
    sha256: str
    roles: tuple[str, ...]
    name: str
    kiosk_ids: tuple[str, ...] = ()
    expires_at: datetime | None = None

    def __repr__(self) -> str:  # never print the digest
        return f"ApiKeyEntry(key_id={self.key_id!r}, roles={self.roles!r}, name={self.name!r})"


@dataclass(frozen=True)
class Principal:
    kind: str  # "key" | "legacy"
    id: str  # key_id, or "admin_token" for the legacy principal
    roles: tuple[str, ...]
    permissions: frozenset[str]
    kiosk_ids: tuple[str, ...] = ()

    @property
    def is_edge_proxy(self) -> bool:
        return self.kind == "key" and EDGE_PROXY_ROLE in self.roles

    @property
    def credential(self) -> str:
        return LEGACY_ACTOR if self.kind == "legacy" else f"key:{self.id}"

    def can(self, perm: str) -> bool:
        return str(perm) in self.permissions


@dataclass(frozen=True)
class ActorRef:
    """Who did it: `actor` (stored / audited), how sure we are, and the credential it came through."""
    actor: str | None
    assurance: str  # edge_asserted | authenticated | legacy | device
    via: str

    def audit_fields(self) -> dict[str, Any]:
        return {"actor_assurance": self.assurance, "via": self.via}


# ----------------------------------------------------------------------------- key configuration
def _parse_expiry(value: Any, where: str) -> datetime | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ConfigError(f"{where}.expires_at must be an ISO-8601 string")
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ConfigError(f"{where}.expires_at is not ISO-8601") from exc
    if ts.tzinfo is None:
        raise ConfigError(f"{where}.expires_at must carry a timezone")
    return ts.astimezone(UTC)


def _parse_entry(raw: Any, i: int) -> ApiKeyEntry:
    where = f"CLOUD_API_KEYS_JSON[{i}]"
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} must be an object")
    key_id, digest = raw.get("key_id"), raw.get("sha256")
    if not isinstance(key_id, str) or not KEY_ID_RE.fullmatch(key_id):
        raise ConfigError(f"{where}.key_id must match [a-z0-9]{{8}}")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ConfigError(f"{where}.sha256 must be 64 lower-case hex chars (sha256 of the secret part)")
    roles_raw = raw.get("roles")
    if not isinstance(roles_raw, list) or not all(isinstance(r, str) for r in roles_raw):
        raise ConfigError(f"{where}.roles must be a list of role names")
    try:
        roles = _edge_rbac.validate_roles(roles_raw, CLOUD_ROLES)
    except ValueError as exc:
        raise ConfigError(f"{where}.roles: {exc}") from exc
    name = raw.get("name") or key_id
    if not isinstance(name, str) or len(name) > MAX_KEY_NAME:
        raise ConfigError(f"{where}.name must be a string of at most {MAX_KEY_NAME} chars")
    kiosks_raw = raw.get("kiosk_ids") or []
    if not isinstance(kiosks_raw, list) or not all(isinstance(k, str) and k for k in kiosks_raw):
        raise ConfigError(f"{where}.kiosk_ids must be a list of kiosk ids")
    kiosk_ids = tuple(dict.fromkeys(kiosks_raw))
    if EDGE_PROXY_ROLE in roles and len(roles) != 1:  # asserted actors are trusted only from a pure proxy key
        raise ConfigError(f"{where}: the edge_proxy role cannot be combined with other roles")
    if EDGE_PROXY_ROLE in roles and len(kiosk_ids) != 1:
        raise ConfigError(f"{where}: an edge_proxy key must list exactly one kiosk_id")
    return ApiKeyEntry(key_id=key_id, sha256=digest, roles=roles, name=name, kiosk_ids=kiosk_ids,
                       expires_at=_parse_expiry(raw.get("expires_at"), where))


def parse_api_keys(raw: str | None) -> tuple[ApiKeyEntry, ...]:
    """CLOUD_API_KEYS_JSON -> entries (ConfigError on anything malformed: fail fast at startup)."""
    if raw is None or not raw.strip():
        return ()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError("CLOUD_API_KEYS_JSON is not valid JSON") from exc
    if not isinstance(data, list):
        raise ConfigError("CLOUD_API_KEYS_JSON must be a JSON list")
    entries = tuple(_parse_entry(item, i) for i, item in enumerate(data))
    ids = [e.key_id for e in entries]
    if len(set(ids)) != len(ids):
        raise ConfigError("CLOUD_API_KEYS_JSON has duplicate key_id values")
    return entries


# ----------------------------------------------------------------------------- authentication
def effective_permissions(roles: Iterable[str], *, email_backend: str) -> frozenset[str]:
    """Role permissions; admin additionally gets outbox:read only while EMAIL_BACKEND=fake (non-prod)."""
    roles = tuple(roles)
    perms = _edge_rbac.permissions_for(roles, CLOUD_ROLES)
    if ADMIN_ROLE in roles and email_backend == "fake":
        perms = perms | {str(P.OUTBOX_READ)}
    return frozenset(perms)


def _key_principal(credential: str, kiosk_id: str, keys: tuple[ApiKeyEntry, ...], now: datetime,
                   email_backend: str) -> Principal:
    parsed = _tokens.parse_api_key(credential)
    if parsed is None:
        raise AdminAuthError(ADMIN_KEY_INVALID, "Authorization must be 'Bearer fgk_<key_id>.<secret>'")
    key_id, secret = parsed
    entry = next((e for e in keys if e.key_id == key_id), None)
    presented = _tokens.digest(secret)
    if entry is None or not _tokens.digests_equal(presented, entry.sha256):
        raise AdminAuthError(ADMIN_KEY_INVALID, "unknown or invalid admin API key")
    if entry.expires_at is not None and now >= entry.expires_at:
        raise AdminAuthError(ADMIN_KEY_EXPIRED, "admin API key expired; mint a new one (cloud/tools/apikey.py)")
    if entry.kiosk_ids and kiosk_id not in entry.kiosk_ids:
        raise AdminAuthError(KIOSK_NOT_BOUND, "this API key is not bound to the calling kiosk")
    return Principal(kind="key", id=key_id, roles=entry.roles, kiosk_ids=entry.kiosk_ids,
                     permissions=effective_permissions(entry.roles, email_backend=email_backend))


def authenticate(headers: Mapping[str, str | list[str]], *, kiosk_id: str, keys: tuple[ApiKeyEntry, ...],
                 legacy_enabled: bool, legacy_token: str, email_backend: str, now: datetime,
                 token_equal: Callable[[str, str], bool]) -> Principal:
    """The admin principal of a request (headers lower-case; a list value = the header was repeated, which is
    refused: a front proxy and the app could otherwise pick different values). Raises AdminAuthError (403)."""
    for name in ("authorization", "x-admin-token"):
        if isinstance(headers.get(name), list):
            raise AdminAuthError(ADMIN_KEY_INVALID, f"{name} header sent more than once")
    authorization = headers.get("authorization")
    if authorization is not None:  # Bearer present: it alone decides (X-Admin-Token is ignored)
        credential = _tokens.parse_bearer(authorization)
        if credential is None:
            raise AdminAuthError(ADMIN_KEY_INVALID, "Authorization must be 'Bearer fgk_<key_id>.<secret>'")
        return _key_principal(credential, kiosk_id, keys, now, email_backend)
    legacy = headers.get("x-admin-token")
    if legacy is None:
        raise AdminAuthError(ADMIN_KEY_INVALID, "admin credential required (Authorization: Bearer fgk_...)")
    if not legacy_enabled:
        raise AdminAuthError(LEGACY_DISABLED, "X-Admin-Token is disabled; use an admin API key (Bearer fgk_...)")
    if not legacy or not legacy_token or not token_equal(legacy, legacy_token):
        raise AdminAuthError(ADMIN_KEY_INVALID, "invalid X-Admin-Token")
    return Principal(kind="legacy", id="admin_token", roles=(ADMIN_ROLE,),
                     permissions=effective_permissions((ADMIN_ROLE,), email_backend=email_backend))


def require_permission(principal: Principal, perm: str) -> None:
    if not principal.can(perm):
        raise AdminAuthError(MISSING_PERMISSION, f"missing permission {perm}", required=(str(perm),))


# ----------------------------------------------------------------------------- actor attribution
class ActorInvalid(ValueError):
    pass


def resolve_actor(principal: Principal, client_actor: str | None, *, kiosk_id: str) -> ActorRef:
    """edge_proxy: the asserted actor (validated pattern; None allowed); other keys: key:<key_id> (client value
    ignored); legacy: legacy:admin_token."""
    if principal.kind == "legacy":
        return ActorRef(actor=LEGACY_ACTOR, assurance="legacy", via=f"kiosk:{kiosk_id}")
    if principal.is_edge_proxy:
        return ActorRef(actor=validate_asserted_actor(client_actor), assurance="edge_asserted",
                        via=principal.credential)
    return ActorRef(actor=principal.credential, assurance="authenticated", via=principal.credential)


def validate_asserted_actor(actor: Any) -> str | None:
    if actor is None:
        return None
    if not isinstance(actor, str) or not ASSERTED_ACTOR_RE.fullmatch(actor):
        raise ActorInvalid("actor must match staff:s_<id> | key:<key_id> | legacy:admin_token")
    return actor


def device_actor(client_actor: Any, *, kiosk_id: str) -> ActorRef:
    """Device-scoped routes (POST/DELETE /v1/enroll, offline-record): the kiosk HMAC is the only credential;
    the actor the edge asserts is recorded, never trusted."""
    return ActorRef(actor=validate_asserted_actor(client_actor), assurance="edge_asserted", via=f"kiosk:{kiosk_id}")
