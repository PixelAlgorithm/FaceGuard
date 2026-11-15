from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request

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


def require_admin(request: Request, svc: Annotated[Services, Depends(get_services)]) -> None:
    tok = request.headers.get("x-admin-token", "")
    if not tok or not constant_time_eq(tok, svc.settings.admin_token):
        raise ApiError("FORBIDDEN", "admin token required (X-Admin-Token)")


SvcDep = Annotated[Services, Depends(get_services)]
KioskDep = Annotated[str, Depends(get_kiosk_id)]
AdminDep = Annotated[None, Depends(require_admin)]
