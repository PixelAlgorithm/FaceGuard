"""FastAPI dependencies: resolve the caller's Principal and enforce permissions.

    deps = AuthDependencies(get_auth)            # get_auth(request) -> AuthService | None (app.state...)
    P = Annotated[Principal, Depends(deps.for_route("POST", "/v1/admin/mode"))]

- 401 UNAUTHORIZED: no / malformed / invalid / expired credential (X-Admin-Token only with the legacy flag).
- 403 FORBIDDEN reason MISSING_PERMISSION (+ required) when the principal lacks a permission.
- 403 FORBIDDEN reason PASSWORD_CHANGE_REQUIRED / MFA_ENROLMENT_REQUIRED for a staff principal that must
  act first, on every route except those built with allow_pending=True (/auth/me|logout|activity|password,
  /auth/mfa/*).
- 503 AUTH_UNAVAILABLE when there is no auth service or the staff store is MISSING / UNAVAILABLE.
Only non-GET requests and requests with `X-FG-Activity: 1` refresh a session's idle timer. Denials are
audited (aggregated on the matched route template, never the raw path: see route_template). The principal
is also left on request.state.principal.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

from edge.auth import rbac, tokens
from edge.auth.login import unauthorized
from edge.auth.models import AuthError, Principal
from edge.auth.service import AuthService
from edge.auth.store import unavailable_error

GetAuth = Callable[[Request], AuthService | None]
PrincipalDependency = Callable[[Request], Principal]
LEGACY_HEADER = "x-admin-token"
ACTIVITY_HEADER = "x-fg-activity"
PASSIVE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
UNMATCHED_ROUTE = "<unmatched>"
NO_STORE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}
_EDGE_PERMISSIONS = frozenset(str(p) for p in rbac.EdgePermission)
_PENDING_MESSAGES = {
    "PASSWORD_CHANGE_REQUIRED": "change your password first",
    "MFA_ENROLMENT_REQUIRED": "set up two-factor authentication first",
}


def client_ip(request: Request) -> str | None:
    """Peer address of the TCP connection (proxy headers are never trusted on the edge)."""
    return request.client.host if request.client else None


def route_template(request: Request) -> str:
    """Path template of the matched route ("/v1/admin/staff/{staff_id}"), or "<unmatched>". Audit lines key on
    this, never on the raw path, so a caller cannot mint one aggregation slot per distinct URL."""
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    return path if isinstance(path, str) and path else UNMATCHED_ROUTE


def secret_json(content: Any, status_code: int = 200) -> JSONResponse:
    """JSON response for anything carrying a secret (token, API key, TOTP secret, codes): never cached."""
    return JSONResponse(content, status_code=status_code, headers=dict(NO_STORE_HEADERS))


def is_activity(request: Request) -> bool:
    return request.method not in PASSIVE_METHODS or request.headers.get(ACTIVITY_HEADER) == "1"


class AuthDependencies:
    def __init__(self, get_auth: GetAuth) -> None:
        self._get_auth = get_auth

    def service(self, request: Request) -> AuthService:
        auth = self._get_auth(request)
        if auth is None:
            raise unavailable_error()
        return auth

    def resolve(self, request: Request, *, allow_pending: bool = False) -> Principal:
        auth = self.service(request)
        header = request.headers.get("authorization")
        credential = tokens.parse_bearer(header) if header is not None else None
        if header is not None and credential is None:
            raise unauthorized("malformed Authorization header")
        legacy = None if credential else request.headers.get(LEGACY_HEADER)
        ip, path = client_ip(request), route_template(request)
        principal = auth.authenticate(credential, admin_token=legacy, client_ip=ip, path=path,
                                      touch=is_activity(request))
        pending = principal.pending_action
        if pending and not allow_pending:
            auth.audit_denied(principal, path=path, required=[], reason=pending, client_ip=ip)
            raise AuthError("FORBIDDEN", _PENDING_MESSAGES.get(pending, "action required"), reason=pending)
        request.state.principal = principal
        return principal

    def principal(self, *, allow_pending: bool = False) -> PrincipalDependency:
        """Any authenticated principal (no permission requirement)."""

        def dependency(request: Request) -> Principal:
            return self.resolve(request, allow_pending=allow_pending)

        return dependency

    def require(self, *permissions: str) -> PrincipalDependency:
        """Principal holding EVERY listed permission."""
        needed = tuple(sorted({str(p) for p in permissions}))
        if not needed:
            raise ValueError("require() needs at least one permission")
        unknown = [p for p in needed if p not in _EDGE_PERMISSIONS]
        if unknown:
            raise ValueError(f"unknown edge permission(s): {', '.join(unknown)}")

        def dependency(request: Request) -> Principal:
            principal = self.resolve(request)
            if not rbac.has_permissions(principal.permissions, needed):
                self.service(request).audit_denied(principal, path=route_template(request),
                                                   required=list(needed), reason="MISSING_PERMISSION",
                                                   client_ip=client_ip(request))
                raise AuthError("FORBIDDEN", "missing permission", reason="MISSING_PERMISSION",
                                extra={"required": list(needed)})
            return principal

        return dependency

    def for_route(self, method: str, path_template: str, *, allow_pending: bool = False) -> PrincipalDependency:
        """The dependency rbac.ROUTE_PERMISSIONS prescribes for a route (KeyError when unmapped)."""
        needed = rbac.ROUTE_PERMISSIONS[(method.upper(), path_template)]
        return self.require(*needed) if needed else self.principal(allow_pending=allow_pending)


def require(*permissions: str, get_auth: GetAuth) -> PrincipalDependency:
    """Shorthand for AuthDependencies(get_auth).require(*permissions)."""
    return AuthDependencies(get_auth).require(*permissions)
