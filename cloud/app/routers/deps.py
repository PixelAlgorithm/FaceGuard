"""FastAPI dependencies: services, the HMAC-authenticated kiosk, and the RBAC admin principal (cloud/app/rbac.py)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any

from fastapi import Depends, Request

from .. import rbac
from ..auth import constant_time_eq
from ..container import Services
from ..errors import ApiError


def get_services(request: Request) -> Services:
    return request.app.state.services


def get_kiosk_id(request: Request) -> str:
    k = request.scope.get("hid.kiosk_id")
    if not k:
        raise ApiError("UNAUTHORIZED", "kiosk authentication required")
    return k


def forbidden(err: rbac.AdminAuthError) -> ApiError:
    extra = {"required": list(err.required)} if err.required else None
    return ApiError("FORBIDDEN", err.message, reason=err.reason, extra=extra)


def get_principal(request: Request, svc: Annotated[Services, Depends(get_services)],
                  kiosk_id: Annotated[str, Depends(get_kiosk_id)]) -> rbac.Principal:
    s = svc.settings
    headers: dict[str, str | list[str]] = {}
    for k, v in request.headers.items():  # repeated credential headers stay visible (refused by authenticate)
        key = k.lower()
        headers[key] = [*(headers[key] if isinstance(headers[key], list) else [headers[key]]), v] \
            if key in headers else v
    try:
        principal = rbac.authenticate(headers, kiosk_id=kiosk_id, keys=s.cloud_api_keys,
                                      legacy_enabled=s.auth_legacy_admin_token, legacy_token=s.admin_token,
                                      email_backend=s.email_backend, now=svc.clock.now(),
                                      token_equal=constant_time_eq)
    except rbac.AdminAuthError as err:
        svc.metrics.count("AdminAuthFailures", Reason=err.reason)
        raise forbidden(err) from err
    request.scope["hid.principal"] = principal
    return principal


def require(perm: str) -> Callable[..., rbac.Principal]:
    """Dependency: the admin principal, which must hold `perm` (403 FORBIDDEN reason MISSING_PERMISSION)."""

    def _dep(principal: Annotated[rbac.Principal, Depends(get_principal)],
             svc: Annotated[Services, Depends(get_services)]) -> rbac.Principal:
        try:
            rbac.require_permission(principal, perm)
        except rbac.AdminAuthError as err:
            svc.metrics.count("AdminAuthFailures", Reason=err.reason)
            raise forbidden(err) from err
        return principal

    _dep.required_permission = str(perm)  # type: ignore[attr-defined] - read by the route-matrix test
    return _dep


def actor_for(principal: rbac.Principal, client_actor: Any, kiosk_id: str) -> rbac.ActorRef:
    try:
        return rbac.resolve_actor(principal, client_actor, kiosk_id=kiosk_id)
    except rbac.ActorInvalid as exc:
        raise ApiError("VALIDATION_ERROR", str(exc), reason="ACTOR_INVALID") from exc


def device_actor_for(client_actor: Any, kiosk_id: str) -> rbac.ActorRef:
    try:
        return rbac.device_actor(client_actor, kiosk_id=kiosk_id)
    except rbac.ActorInvalid as exc:
        raise ApiError("VALIDATION_ERROR", str(exc), reason="ACTOR_INVALID") from exc


def audit_meta(ref: rbac.ActorRef, request_id: str | None = None) -> dict[str, Any]:
    """Actor assurance / via (+ the edge's per-call request_id, if any) for the audit entry."""
    return {**ref.audit_fields(), **({"request_id": request_id} if request_id else {})}


SvcDep = Annotated[Services, Depends(get_services)]
KioskDep = Annotated[str, Depends(get_kiosk_id)]
PrincipalDep = Annotated[rbac.Principal, Depends(get_principal)]

P = rbac.P
ScheduleRead = Annotated[rbac.Principal, Depends(require(P.SCHEDULE_READ))]
ScheduleWrite = Annotated[rbac.Principal, Depends(require(P.SCHEDULE_WRITE))]
RevocationsWrite = Annotated[rbac.Principal, Depends(require(P.REVOCATIONS_WRITE))]
AccessRead = Annotated[rbac.Principal, Depends(require(P.ACCESS_READ))]
AccessEdit = Annotated[rbac.Principal, Depends(require(P.ACCESS_EDIT))]
CodesRotate = Annotated[rbac.Principal, Depends(require(P.CODES_ROTATE))]
AuditRead = Annotated[rbac.Principal, Depends(require(P.AUDIT_READ))]
AlertsRead = Annotated[rbac.Principal, Depends(require(P.ALERTS_READ))]
DecisionsRead = Annotated[rbac.Principal, Depends(require(P.DECISIONS_READ))]
StatsRead = Annotated[rbac.Principal, Depends(require(P.STATS_READ))]
MetricsRead = Annotated[rbac.Principal, Depends(require(P.METRICS_READ))]
ContactEdit = Annotated[rbac.Principal, Depends(require(P.CONTACT_EDIT))]
OutboxRead = Annotated[rbac.Principal, Depends(require(P.OUTBOX_READ))]
