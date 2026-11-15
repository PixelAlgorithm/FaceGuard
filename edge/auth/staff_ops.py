"""Staff account, API key and MFA administration (mixed into AuthService).

Privilege rules (design v2 C): every staff:manage mutation and API-key creation needs `confirm_password`
(re-auth, 403 REAUTH_REQUIRED); nobody changes their own roles or status (403 SELF_MODIFICATION); an actor
may only grant roles whose permissions are a subset of its own (403 ROLE_CEILING); the last active admin
cannot be disabled, demoted or deleted (403 LAST_ADMIN, checked inside the store lock). Disabling an account
revokes its sessions and the API keys it created. The actor itself is re-checked INSIDE the store lock, on the
same data the change is applied to (ActorCheck): a staff actor whose account was deleted, disabled, demoted or
had its session_epoch bumped after _manage (e.g. during the re-auth KDF) commits nothing (403
MISSING_PERMISSION / 401 SESSION_EXPIRED). The console is exempt. Disable, role change, password reset and MFA reset bump
the account's session_epoch, which invalidates its sessions in every process.
Callers on the event loop run these through the auth-kdf executor (they may hash a password).
"""

from __future__ import annotations

import getpass
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from edge.auth import mfa, passwords, rbac, tokens
from edge.auth.models import (
    ADMIN_ROLE,
    MAX_DISPLAY_NAME,
    MAX_KEY_NAME,
    RESERVED_USERNAMES,
    STAFF_ACTOR_PREFIX,
    USERNAME_RE,
    ApiKey,
    AuthError,
    Principal,
    StaffAccount,
    StoreData,
    staff_id_for,
)

if TYPE_CHECKING:
    from edge.auth.audit import AuditLog
    from edge.auth.config import AuthConfig
    from edge.auth.models import Clock
    from edge.auth.sessions import SessionManager
    from edge.auth.store import StaffStore

DEFAULT_API_KEY_DAYS = 30
MAX_API_KEY_DAYS = 90
KEY_ID_ATTEMPTS = 8
STAFF_MANAGE = str(rbac.EdgePermission.STAFF_MANAGE)
CLI_ACTOR_PREFIX = "cli:"
Change = Callable[[StoreData, StaffAccount, datetime], StaffAccount | None]
ActorCheck = Callable[[StoreData], None]  # raises when the actor may no longer do this (run inside the lock)


def no_actor_check(_: StoreData) -> None:
    """ActorCheck of the console (local file + key access) and of self-service changes."""


@dataclass(frozen=True)
class MfaSetup:
    """Shown ONCE to the person enrolling: never logged, audited or stored outside the encrypted store."""
    secret: str = field(repr=False)
    otpauth_uri: str = field(repr=False)


def cli_principal(os_user: str | None = None) -> Principal:
    """The console operator (python -m edge.auth): local file + key access, so full admin rights."""
    user = os_user or _os_user()
    return Principal(kind="cli", id=CLI_ACTOR_PREFIX + user, username=user, display_name="console",
                     roles=(ADMIN_ROLE,), permissions=rbac.permissions_for([ADMIN_ROLE]))


def _os_user() -> str:
    try:
        return getpass.getuser()
    except (KeyError, OSError):
        return "unknown"


def invalid(message: str, reason: str, **extra: Any) -> AuthError:
    return AuthError("VALIDATION_ERROR", message, reason=reason, extra=extra or None)


def forbidden(message: str, reason: str, **extra: Any) -> AuthError:
    return AuthError("FORBIDDEN", message, reason=reason, extra=extra or None)


def not_found(what: str) -> AuthError:
    return AuthError("NOT_FOUND", f"{what} not found")


def check_username(username: str) -> str:
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        raise invalid("username must match ^[a-z][a-z0-9_]{1,30}$", "INVALID_USERNAME")
    if username in RESERVED_USERNAMES:
        raise invalid("this username is reserved; choose a personal one", "RESERVED_USERNAME")
    return username


def check_label(text: str, max_len: int, what: str) -> str:
    value = unicodedata.normalize("NFKC", text if isinstance(text, str) else "").strip()
    if not 1 <= len(value) <= max_len or any(unicodedata.category(c).startswith("C") for c in value):
        raise invalid(f"{what} must be 1..{max_len} printable characters", "INVALID_" + what.upper())
    return value


def check_roles(roles: Any, *, for_key: bool = False) -> tuple[str, ...]:
    seq = roles if isinstance(roles, (list, tuple, set, frozenset)) else []
    try:
        return rbac.validate_key_roles(seq) if for_key else rbac.validate_roles(seq)
    except ValueError as exc:
        raise invalid(str(exc), "INVALID_ROLES") from None


def check_password(password: str, username: str) -> str:
    problems = passwords.check_policy(password, username)
    if problems:
        raise invalid("password does not meet the policy", "PASSWORD_POLICY", problems=problems)
    return password


def check_ceiling(actor: Principal, granted: frozenset[str]) -> None:
    """403 ROLE_CEILING when `granted` exceeds the actor's own permissions (demo-only permissions are
    ignored: they are switched off for everyone when DEMO_MODE=0, not a privilege the actor lacks)."""
    beyond = sorted(granted - actor.permissions - rbac.DEMO_ONLY_PERMISSIONS)
    if actor.kind != "cli" and beyond:
        raise forbidden("you cannot grant permissions you do not hold", "ROLE_CEILING", beyond=beyond)


def _is_active_admin(account: StaffAccount | None) -> bool:
    return account is not None and account.active and ADMIN_ROLE in account.roles


def guard_last_admin(data: StoreData, old: StaffAccount, new: StaffAccount | None) -> None:
    """Refuse a change that would leave no active admin."""
    if not _is_active_admin(old) or _is_active_admin(new):
        return
    if not any(a.staff_id != old.staff_id and _is_active_admin(a) for a in data.accounts.values()):
        raise forbidden("the last active admin cannot be disabled, demoted or deleted", "LAST_ADMIN")


def _revoke_keys_by(data: StoreData, creator: str, now: datetime) -> StoreData:
    for key in data.api_keys.values():
        if key.created_by == creator and key.revoked_at is None:
            data = data.with_api_key(replace(key, revoked_at=now))
    return data


class StaffOpsMixin:
    config: AuthConfig
    store: StaffStore
    audit: AuditLog
    sessions: SessionManager
    clock: Clock

    def _check_reauth(self, actor: Principal, password: str | None) -> None:  # implemented by AuthService
        raise NotImplementedError

    def _actor_check(self, actor: Principal, permission: str = STAFF_MANAGE) -> ActorCheck:  # AuthService
        raise NotImplementedError

    # ------------------------------------------------------------------ helpers
    def _require(self, actor: Principal, permission: str = STAFF_MANAGE) -> None:
        if actor.kind != "cli" and permission not in actor.permissions:
            raise forbidden("missing permission", "MISSING_PERMISSION", required=[permission])

    def _manage(self, actor: Principal, confirm_password: str | None) -> ActorCheck:
        """Permission + re-auth before the lock; the returned check re-validates the actor inside it (it
        captures the session epoch BEFORE the re-auth KDF)."""
        self._require(actor)
        check = self._actor_check(actor)
        self._check_reauth(actor, confirm_password)
        return check

    def _record(self, actor: Principal, action: str, target: str, client_ip: str | None, **detail: Any) -> None:
        self.audit.safe_append(action, actor=actor.actor(), target=target, client_ip=client_ip, detail=detail)

    def _mutate(self, staff_id: str, change: Change, *,
                also: Callable[[StoreData, StaffAccount, datetime], StoreData] | None = None,
                check: ActorCheck = no_actor_check) -> tuple[StaffAccount, StaffAccount | None]:
        """(old, new) after applying `change` to the latest copy inside the store lock; new None = delete."""
        now = self.clock()

        def apply(data: StoreData) -> tuple[StoreData, tuple[StaffAccount, StaffAccount | None]]:
            check(data)
            old = data.accounts.get(staff_id)
            if old is None:
                raise not_found("staff account")
            new = change(data, old, now)
            guard_last_admin(data, old, new)
            out = data.without_account(staff_id) if new is None else data.with_account(new)
            return (also(out, old, now) if also else out), (old, new)

        old, new = self.store.update(apply)
        if new is not None:
            self._note_own_write(new)
        return old, new

    def _note_own_write(self, account: StaffAccount) -> None:  # LoginMixin records it for its reconcile
        return None

    def staff_exists(self, staff_id: str) -> bool:
        return staff_id in self.store.snapshot().accounts

    # ------------------------------------------------------------------ staff
    def list_staff(self, actor: Principal) -> list[StaffAccount]:
        self._require(actor)
        return sorted(self.store.snapshot().accounts.values(), key=lambda a: a.username)

    def get_staff(self, actor: Principal, staff_id: str) -> StaffAccount:
        self._require(actor)
        account = self.store.snapshot().accounts.get(staff_id)
        if account is None:
            raise not_found("staff account")
        return account

    def create_staff(self, actor: Principal, username: str, display_name: str, roles: Any, password: str, *,
                     confirm_password: str | None = None, must_change_password: bool = True,
                     client_ip: str | None = None, allow_missing_store: bool = False) -> StaffAccount:
        username = check_username(username)
        name, role_set = check_label(display_name, MAX_DISPLAY_NAME, "display_name"), check_roles(roles)
        check_password(password, username)
        actor_check = self._manage(actor, confirm_password)
        check_ceiling(actor, rbac.permissions_for(role_set))
        password_hash = passwords.hash_password(password)
        now = self.clock()
        account = StaffAccount(
            staff_id=staff_id_for(username), username=username, display_name=name, roles=role_set,
            password_hash=password_hash, must_change_password=must_change_password, created_at=now,
            updated_at=now, password_changed_at=now,
        )

        def apply(data: StoreData) -> tuple[StoreData, StaffAccount]:
            actor_check(data)
            if account.staff_id in data.accounts:
                raise AuthError("INVALID_STATE", "username already exists", reason="USERNAME_TAKEN")
            return data.with_account(account), account

        created = self.store.update(apply, allow_missing=allow_missing_store)
        self._record(actor, "staff.create", created.staff_id, client_ip, roles=list(role_set),
                     must_change_password=must_change_password)
        return created

    def update_staff(self, actor: Principal, staff_id: str, *, display_name: str | None = None,
                     roles: Any = None, status: str | None = None, confirm_password: str | None = None,
                     client_ip: str | None = None) -> StaffAccount:
        if display_name is None and roles is None and status is None:
            raise invalid("nothing to update", "EMPTY_UPDATE")
        if status is not None and status not in ("active", "disabled"):
            raise invalid("status must be active or disabled", "INVALID_STATUS")
        name = check_label(display_name, MAX_DISPLAY_NAME, "display_name") if display_name is not None else None
        role_set = check_roles(roles) if roles is not None else None
        if actor.staff_id == staff_id and (role_set is not None or status is not None):
            raise forbidden("you cannot change your own roles or status", "SELF_MODIFICATION")
        actor_check = self._manage(actor, confirm_password)
        if role_set is not None:
            check_ceiling(actor, rbac.permissions_for(role_set))

        def change(_: StoreData, old: StaffAccount, now: datetime) -> StaffAccount:
            new = replace(old, display_name=name or old.display_name, roles=role_set or old.roles,
                          status=status or old.status, updated_at=now)  # type: ignore[arg-type]
            revoke = new.roles != old.roles or (old.active and not new.active)
            return replace(new, session_epoch=old.session_epoch + 1) if revoke else new

        def revoke_keys(data: StoreData, old: StaffAccount, now: datetime) -> StoreData:
            disabling = old.active and status == "disabled"
            return _revoke_keys_by(data, STAFF_ACTOR_PREFIX + staff_id, now) if disabling else data

        old, new = self._mutate(staff_id, change, also=revoke_keys, check=actor_check)
        assert new is not None
        if new.session_epoch != old.session_epoch:
            self.sessions.revoke_all(staff_id)
        changed = sorted(k for k, v in (("display_name", name), ("roles", role_set), ("status", status))
                         if v is not None)
        self._record(actor, "staff.update", staff_id, client_ip, changed=changed, roles=list(new.roles),
                     status=new.status)
        return new

    def delete_staff(self, actor: Principal, staff_id: str, *, confirm_password: str | None = None,
                     client_ip: str | None = None) -> None:
        if actor.staff_id == staff_id:
            raise forbidden("you cannot delete your own account", "SELF_MODIFICATION")
        actor_check = self._manage(actor, confirm_password)
        self._mutate(staff_id, lambda _d, _old, _now: None,
                     also=lambda data, _old, now: _revoke_keys_by(data, STAFF_ACTOR_PREFIX + staff_id, now),
                     check=actor_check)
        self.sessions.revoke_all(staff_id)
        self._record(actor, "staff.delete", staff_id, client_ip)

    def reset_password(self, actor: Principal, staff_id: str, password: str, *,
                       confirm_password: str | None = None, must_change_password: bool = True,
                       client_ip: str | None = None) -> StaffAccount:
        if actor.staff_id == staff_id:
            raise forbidden("use POST /v1/auth/password for your own password", "SELF_MODIFICATION")
        account = self.store.snapshot().accounts.get(staff_id)
        if account is None:
            raise not_found("staff account")
        check_password(password, account.username)
        actor_check = self._manage(actor, confirm_password)
        password_hash = passwords.hash_password(password)

        def change(_: StoreData, old: StaffAccount, now: datetime) -> StaffAccount:
            return replace(old, password_hash=password_hash, must_change_password=must_change_password,
                           password_changed_at=now, updated_at=now, failed_logins=0, locked_until=None,
                           session_epoch=old.session_epoch + 1)

        _, new = self._mutate(staff_id, change, check=actor_check)
        assert new is not None
        self.sessions.revoke_all(staff_id)
        self._after_unlock(new.username)
        self._record(actor, "staff.password_reset", staff_id, client_ip, must_change_password=must_change_password)
        return new

    def unlock(self, actor: Principal, staff_id: str, *, confirm_password: str | None = None,
               client_ip: str | None = None) -> StaffAccount:
        actor_check = self._manage(actor, confirm_password)
        _, new = self._mutate(staff_id, lambda _d, old, now: replace(
            old, failed_logins=0, locked_until=None, updated_at=now), check=actor_check)
        assert new is not None
        self._after_unlock(new.username)
        self._record(actor, "staff.unlock", staff_id, client_ip)
        return new

    def _after_unlock(self, username: str) -> None:  # AuthService: LoginMixin.clear_throttle (login + MFA)
        return None

    # ------------------------------------------------------------------ API keys
    def list_api_keys(self, actor: Principal) -> list[ApiKey]:
        self._require(actor)
        return sorted(self.store.snapshot().api_keys.values(),
                      key=lambda k: (k.created_at is None, k.created_at, k.key_id))

    def create_api_key(self, actor: Principal, name: str, roles: Any, *,
                       expires_days: int | None = DEFAULT_API_KEY_DAYS, confirm_password: str | None = None,
                       client_ip: str | None = None) -> tuple[ApiKey, str]:
        """(stored key, the full `fgk_...` credential: returned ONCE, never stored or logged)."""
        label = check_label(name, MAX_KEY_NAME, "name")
        role_set = check_roles(roles, for_key=True)
        days = DEFAULT_API_KEY_DAYS if expires_days is None else expires_days
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_API_KEY_DAYS:
            raise invalid(f"expires_days must be 1..{MAX_API_KEY_DAYS}", "INVALID_EXPIRY")
        actor_check = self._manage(actor, confirm_password)
        check_ceiling(actor, rbac.key_permissions(role_set))
        now = self.clock()

        def apply(data: StoreData) -> tuple[StoreData, tuple[ApiKey, str]]:
            actor_check(data)
            for _ in range(KEY_ID_ATTEMPTS):
                key_id, full, secret_sha = tokens.new_api_key()
                if key_id not in data.api_keys:
                    key = ApiKey(key_id=key_id, name=label, roles=role_set, secret_sha256=secret_sha,
                                 created_at=now, created_by=actor.actor_id, expires_at=now + timedelta(days=days))
                    return data.with_api_key(key), (key, full)
            raise AuthError("INTERNAL", "could not allocate an API key id")

        key, full = self.store.update(apply)
        self._record(actor, "apikey.create", key.key_id, client_ip, roles=list(role_set), name=label,
                     expires_days=days)
        return key, full

    def revoke_api_key(self, actor: Principal, key_id: str, *, confirm_password: str | None = None,
                       client_ip: str | None = None) -> ApiKey:
        actor_check = self._manage(actor, confirm_password)
        now = self.clock()

        def apply(data: StoreData) -> tuple[StoreData, ApiKey]:
            actor_check(data)
            key = data.api_keys.get(key_id)
            if key is None:
                raise not_found("API key")
            if key.revoked_at is not None:
                return data, key
            revoked = replace(key, revoked_at=now)
            return data.with_api_key(revoked), revoked

        key = self.store.update(apply)
        self._record(actor, "apikey.revoke", key_id, client_ip)
        return key

    # ------------------------------------------------------------------ MFA
    def begin_mfa(self, actor: Principal, staff_id: str, *, client_ip: str | None = None) -> MfaSetup:
        """Start TOTP enrolment for yourself (or any account from the console): a pending secret that
        becomes active only after confirm_mfa."""
        if actor.kind != "cli" and actor.staff_id != staff_id:
            raise forbidden("you can only enrol MFA for your own account", "NO_STAFF_IDENTITY")
        secret = mfa.new_secret()

        def change(_: StoreData, old: StaffAccount, now: datetime) -> StaffAccount:
            if old.mfa_enabled:
                raise AuthError("INVALID_STATE", "MFA is already enabled", reason="MFA_ALREADY_ENABLED")
            return replace(old, mfa_pending_secret=secret, updated_at=now)

        old, _ = self._mutate(staff_id, change)
        self._record(actor, "staff.mfa_begin", staff_id, client_ip)
        return MfaSetup(secret=secret, otpauth_uri=mfa.provisioning_uri(secret, old.username))

    def confirm_mfa(self, actor: Principal, staff_id: str, code: str, *, client_ip: str | None = None) -> None:
        if actor.kind != "cli" and actor.staff_id != staff_id:
            raise forbidden("you can only enrol MFA for your own account", "NO_STAFF_IDENTITY")

        def change(_: StoreData, old: StaffAccount, now: datetime) -> StaffAccount:
            if old.mfa_pending_secret is None:
                raise AuthError("INVALID_STATE", "no MFA enrolment in progress", reason="MFA_NOT_PENDING")
            step = mfa.accept_code(old.mfa_pending_secret, code, now, None)
            if step is None:
                raise invalid("the authenticator code is not valid", "MFA_INVALID")
            return replace(old, mfa_secret=old.mfa_pending_secret, mfa_pending_secret=None,
                           mfa_last_step=step, updated_at=now)

        self._mutate(staff_id, change)
        self._record(actor, "staff.mfa_enable", staff_id, client_ip)

    def reset_mfa(self, actor: Principal, staff_id: str, *, confirm_password: str | None = None,
                  client_ip: str | None = None) -> None:
        """Remove an account's TOTP (lost phone). Bumps session_epoch: its sessions end."""
        actor_check = self._manage(actor, confirm_password)
        self._mutate(staff_id, lambda _d, old, now: replace(
            old, mfa_secret=None, mfa_pending_secret=None, mfa_last_step=None, updated_at=now,
            session_epoch=old.session_epoch + 1), check=actor_check)
        self.sessions.revoke_all(staff_id)
        self._record(actor, "staff.mfa_reset", staff_id, client_ip)
