"""HTTP contract for staff auth (design v2): /v1/auth/*, /v1/admin/staff*, /v1/admin/api-keys*,
/v1/admin/auth/audit, /v1/admin/roles. Every response carries Cache-Control: no-store; secret-bearing ones
use secret_json(); passwords are never echoed; the session token and a new API key are returned once.
Calls that hash or verify a password run on the dedicated auth-kdf executor (auth.kdf.run). No async route
does blocking store or audit I/O on the event loop: every async handler hands its whole service call to
auth.kdf.run (login's ticket path is handled inside AuthService.login); plain `def` routes run in FastAPI's
threadpool.

No `from __future__ import annotations` here: the Annotated dependency aliases are closure-local and FastAPI
must see real objects, not strings.
"""

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Query, Request, Response
from fastapi import Path as PathParam
from pydantic import BaseModel, ConfigDict, Field, model_validator

from edge.auth import rbac
from edge.auth.deps import NO_STORE_HEADERS, AuthDependencies, GetAuth, client_ip, secret_json
from edge.auth.models import Principal, iso
from edge.auth.passwords import MAX_LENGTH, MIN_LENGTH
from edge.auth.service import AuthService
from edge.auth.staff_ops import DEFAULT_API_KEY_DAYS, MAX_API_KEY_DAYS

USERNAME_PATTERN = r"^[a-z][a-z0-9_]{1,30}$"
STAFF_ID_PATTERN = r"^s_[a-z][a-z0-9_]{1,30}$"
KEY_ID_PATTERN = r"^[a-z0-9]{8}$"
CODE_PATTERN = r"^\d{6}$"
ROLE_PATTERN = r"^[a-z_]{1,32}$"
MAX_GIVEN_PASSWORD = MAX_LENGTH * 4  # verify_password's own bound; the policy applies to NEW passwords only
MAX_TICKET = 64
AUDIT_DEFAULT_LIMIT = 100
AUDIT_MAX_LIMIT = 500
STAFF_MANAGE = str(rbac.EdgePermission.STAFF_MANAGE)
AUDIT_READ = str(rbac.EdgePermission.AUDIT_READ)

GivenPassword = Annotated[str, Field(min_length=1, max_length=MAX_GIVEN_PASSWORD)]
NewPassword = Annotated[str, Field(min_length=MIN_LENGTH, max_length=MAX_LENGTH)]
TotpCode = Annotated[str, Field(pattern=CODE_PATTERN)]
RoleList = Annotated[list[Annotated[str, Field(pattern=ROLE_PATTERN)]],
                     Field(min_length=1, max_length=rbac.MAX_ROLES_PER_ACCOUNT)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(_Strict):
    username: str | None = Field(default=None, min_length=1, max_length=64)
    password: GivenPassword | None = None
    totp_code: TotpCode | None = None
    mfa_ticket: str | None = Field(default=None, min_length=1, max_length=MAX_TICKET)

    @model_validator(mode="after")
    def _one_form(self) -> "LoginRequest":
        if self.mfa_ticket is not None:
            if self.totp_code is None or self.username is not None or self.password is not None:
                raise ValueError("send {mfa_ticket, totp_code} only")
        elif self.username is None or self.password is None:
            raise ValueError("username and password are required")
        return self


class PasswordChangeRequest(_Strict):
    current_password: GivenPassword
    new_password: NewPassword


class MfaEnrollRequest(_Strict):
    current_password: GivenPassword  # re-authentication is required to bind an authenticator


class MfaConfirmRequest(_Strict):
    totp_code: TotpCode


class ConfirmRequest(_Strict):
    confirm_password: GivenPassword


class CreateStaffRequest(_Strict):
    username: str = Field(pattern=USERNAME_PATTERN)
    display_name: str = Field(min_length=1, max_length=80)
    roles: RoleList
    temporary_password: NewPassword
    confirm_password: GivenPassword


class UpdateStaffRequest(_Strict):
    display_name: str | None = Field(default=None, min_length=1, max_length=80)
    roles: RoleList | None = None
    status: str | None = Field(default=None, pattern=r"^(active|disabled)$")
    confirm_password: GivenPassword


class ResetPasswordRequest(_Strict):
    temporary_password: NewPassword
    confirm_password: GivenPassword


class CreateApiKeyRequest(_Strict):
    name: str = Field(min_length=1, max_length=64)
    roles: RoleList
    expires_days: int = Field(default=DEFAULT_API_KEY_DAYS, ge=1, le=MAX_API_KEY_DAYS, strict=True)
    confirm_password: GivenPassword


def _no_store(response: Response) -> None:
    response.headers.update(NO_STORE_HEADERS)


def _no_content() -> Response:
    return Response(status_code=204, headers=dict(NO_STORE_HEADERS))


def role_catalog() -> dict[str, Any]:
    roles = [{"name": name, "description": rbac.ROLE_DESCRIPTIONS.get(name, ""), "permissions": sorted(perms),
              "key_allowed": name not in rbac.KEY_FORBIDDEN_ROLES}
             for name, perms in ((n, rbac.permissions_for([n])) for n in rbac.EDGE_ROLES)]
    return {"roles": roles, "permissions": sorted(str(p) for p in rbac.EdgePermission),
            "key_forbidden_permissions": sorted(rbac.KEY_FORBIDDEN_PERMISSIONS),
            "max_roles_per_account": rbac.MAX_ROLES_PER_ACCOUNT, "rbac_version": rbac.RBAC_VERSION}


def build_router(get_auth: GetAuth) -> APIRouter:
    deps = AuthDependencies(get_auth)
    router = APIRouter(prefix="/v1", dependencies=[Depends(_no_store)])
    Auth = Annotated[AuthService, Depends(deps.service)]
    Pending = Annotated[Principal, Depends(deps.principal(allow_pending=True))]
    Authed = Annotated[Principal, Depends(deps.principal())]
    Manage = Annotated[Principal, Depends(deps.require(STAFF_MANAGE))]
    AuditReader = Annotated[Principal, Depends(deps.require(AUDIT_READ))]
    StaffId = Annotated[str, PathParam(pattern=STAFF_ID_PATTERN)]
    KeyId = Annotated[str, PathParam(pattern=KEY_ID_PATTERN)]

    # ---------------------------------------------------------------- /auth (public)
    @router.get("/auth/status")
    def status(auth: Auth) -> dict[str, Any]:
        return auth.status()

    @router.post("/auth/login")
    async def login(body: LoginRequest, request: Request, auth: Auth) -> Response:
        token, session, principal = await auth.login(
            body.username, body.password, body.totp_code, client_ip(request), request.headers.get("user-agent"),
            mfa_ticket=body.mfa_ticket)
        return secret_json({"token": token, "token_type": "Bearer", "expires_at": iso(session.expires_at),
                            "idle_timeout_s": auth.sessions.idle_timeout_s, "principal": principal.to_public()})

    # ---------------------------------------------------------------- /auth (signed in)
    @router.post("/auth/logout", status_code=204)
    def logout(request: Request, principal: Pending, auth: Auth) -> Response:
        auth.logout(principal, client_ip=client_ip(request))
        return _no_content()

    @router.post("/auth/activity", status_code=204)
    def activity(principal: Pending, auth: Auth) -> Response:
        auth.activity(principal)
        return _no_content()

    @router.get("/auth/me")
    def me(principal: Pending, auth: Auth) -> dict[str, Any]:
        return auth.me(principal)

    @router.post("/auth/password", status_code=204)
    async def change_password(body: PasswordChangeRequest, request: Request, principal: Pending,
                              auth: Auth) -> Response:
        await auth.kdf.run(auth.change_password, principal, body.current_password, body.new_password,
                           client_ip=client_ip(request))
        return _no_content()

    @router.post("/auth/mfa/enroll")
    async def mfa_enroll(body: MfaEnrollRequest, request: Request, principal: Pending, auth: Auth) -> Response:
        setup = await auth.kdf.run(auth.enroll_own_mfa, principal, body.current_password,
                                   client_ip=client_ip(request))
        return secret_json({"secret": setup.secret, "otpauth_uri": setup.otpauth_uri})

    @router.post("/auth/mfa/confirm", status_code=204)
    def mfa_confirm(body: MfaConfirmRequest, request: Request, principal: Pending, auth: Auth) -> Response:
        auth.confirm_own_mfa(principal, body.totp_code, client_ip=client_ip(request))
        return _no_content()

    # ---------------------------------------------------------------- /admin/roles, /admin/staff
    @router.get("/admin/roles")
    def roles(_: Authed) -> dict[str, Any]:
        return role_catalog()

    @router.get("/admin/staff")
    def list_staff(principal: Manage, auth: Auth) -> dict[str, Any]:
        now = auth.clock()
        return {"items": [a.to_public(now) for a in auth.list_staff(principal)]}

    @router.post("/admin/staff", status_code=201)
    async def create_staff(body: CreateStaffRequest, request: Request, principal: Manage,
                           auth: Auth) -> dict[str, Any]:
        account = await auth.kdf.run(auth.create_staff, principal, body.username, body.display_name, body.roles,
                                     body.temporary_password, confirm_password=body.confirm_password,
                                     must_change_password=True, client_ip=client_ip(request))
        return {"item": account.to_public(auth.clock())}

    @router.get("/admin/staff/{staff_id}")
    def get_staff(staff_id: StaffId, principal: Manage, auth: Auth) -> dict[str, Any]:
        return {"item": auth.get_staff(principal, staff_id).to_public(auth.clock())}

    @router.patch("/admin/staff/{staff_id}")
    async def update_staff(staff_id: StaffId, body: UpdateStaffRequest, request: Request, principal: Manage,
                           auth: Auth) -> dict[str, Any]:
        account = await auth.kdf.run(auth.update_staff, principal, staff_id, display_name=body.display_name,
                                     roles=body.roles, status=body.status, confirm_password=body.confirm_password,
                                     client_ip=client_ip(request))
        return {"item": account.to_public(auth.clock())}

    @router.delete("/admin/staff/{staff_id}", status_code=204)
    async def delete_staff(staff_id: StaffId, body: Annotated[ConfirmRequest, Body()], request: Request,
                           principal: Manage, auth: Auth) -> Response:
        await auth.kdf.run(auth.delete_staff, principal, staff_id, confirm_password=body.confirm_password,
                           client_ip=client_ip(request))
        return _no_content()

    @router.post("/admin/staff/{staff_id}/password", status_code=204)
    async def reset_password(staff_id: StaffId, body: ResetPasswordRequest, request: Request,
                             principal: Manage, auth: Auth) -> Response:
        await auth.kdf.run(auth.reset_password, principal, staff_id, body.temporary_password,
                           confirm_password=body.confirm_password, must_change_password=True,
                           client_ip=client_ip(request))
        return _no_content()

    @router.post("/admin/staff/{staff_id}/unlock", status_code=204)
    async def unlock(staff_id: StaffId, body: ConfirmRequest, request: Request, principal: Manage,
                     auth: Auth) -> Response:
        await auth.kdf.run(auth.unlock, principal, staff_id, confirm_password=body.confirm_password,
                           client_ip=client_ip(request))
        return _no_content()

    @router.post("/admin/staff/{staff_id}/mfa/reset", status_code=204)
    async def mfa_reset(staff_id: StaffId, body: ConfirmRequest, request: Request, principal: Manage,
                        auth: Auth) -> Response:
        await auth.kdf.run(auth.reset_mfa, principal, staff_id, confirm_password=body.confirm_password,
                           client_ip=client_ip(request))
        return _no_content()

    # ---------------------------------------------------------------- /admin/api-keys
    @router.get("/admin/api-keys")
    def list_keys(principal: Manage, auth: Auth) -> dict[str, Any]:
        now = auth.clock()
        return {"items": [k.to_public(now, rbac.key_permissions(k.roles)) for k in auth.list_api_keys(principal)]}

    @router.post("/admin/api-keys", status_code=201)
    async def create_key(body: CreateApiKeyRequest, request: Request, principal: Manage, auth: Auth) -> Response:
        key, full = await auth.kdf.run(auth.create_api_key, principal, body.name, body.roles,
                                       expires_days=body.expires_days, confirm_password=body.confirm_password,
                                       client_ip=client_ip(request))
        item = key.to_public(auth.clock(), rbac.key_permissions(key.roles))
        return secret_json({"key": full, "item": item}, status_code=201)

    @router.delete("/admin/api-keys/{key_id}", status_code=204)
    async def revoke_key(key_id: KeyId, body: Annotated[ConfirmRequest, Body()], request: Request,
                         principal: Manage, auth: Auth) -> Response:
        await auth.kdf.run(auth.revoke_api_key, principal, key_id, confirm_password=body.confirm_password,
                           client_ip=client_ip(request))
        return _no_content()

    # ---------------------------------------------------------------- /admin/auth/audit
    @router.get("/admin/auth/audit")
    def audit(_: AuditReader, auth: Auth,
              limit: Annotated[int, Query(ge=1, le=AUDIT_MAX_LIMIT)] = AUDIT_DEFAULT_LIMIT,
              before_seq: Annotated[int | None, Query(ge=1)] = None) -> dict[str, Any]:
        items, next_before = auth.audit.read(limit, before_seq)
        return {"as_of": iso(datetime.now(UTC)), "count": len(items), "items": items,
                "next_before_seq": next_before}

    return router
