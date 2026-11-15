"""Immutable data model of the staff store, sessions and principals, plus the auth error type.

Every update returns a NEW frozen dataclass (dataclasses.replace); nothing here is mutated in place.
"""

from __future__ import annotations

import hmac
import re
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Literal

from edge.errors import ApiError

Clock = Callable[[], datetime]
PrincipalKind = Literal["staff", "api_key", "legacy", "cli"]
AccountStatus = Literal["active", "disabled"]

USERNAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,30}$")
STAFF_ID_RE = re.compile(r"^s_[a-z][a-z0-9_]{1,30}$")
KEY_ID_RE = re.compile(r"^[a-z0-9]{8}$")
STAFF_ID_PREFIX = "s_"
ACCOUNT_STATUSES: frozenset[str] = frozenset({"active", "disabled"})
ADMIN_ROLE = "admin"
LEGACY_ACTOR_ID = "legacy:admin_token"
STAFF_ACTOR_PREFIX = "staff:"
KEY_ACTOR_PREFIX = "key:"
RESERVED_USERNAMES: frozenset[str] = frozenset(
    {"admin", "root", "administrator", "sa", "test", "demo", "system", "kiosk"})
MAX_DISPLAY_NAME = 80
MAX_KEY_NAME = 64


def _sleep_inclusive_clock_id() -> int | None:
    """darwin CLOCK_MONOTONIC keeps counting while the laptop sleeps (time.monotonic = mach_absolute_time
    does not); Linux needs CLOCK_BOOTTIME for the same property."""
    if sys.platform == "darwin" and hasattr(time, "CLOCK_MONOTONIC"):
        return time.CLOCK_MONOTONIC
    return getattr(time, "CLOCK_BOOTTIME", None)


_AUTH_CLOCK_ID = _sleep_inclusive_clock_id()


def auth_monotonic() -> float:
    """Seconds on a clock that never jumps with wall-clock changes and KEEPS running during system sleep
    (a closed lid must not freeze session idle/absolute timers, MFA tickets or login windows)."""
    if _AUTH_CLOCK_ID is not None:
        return time.clock_gettime(_AUTH_CLOCK_ID)
    return time.monotonic()


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso(ts: datetime | None) -> str | None:
    return None if ts is None else ts.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_iso(text: Any) -> datetime | None:
    if text is None:
        return None
    if not isinstance(text, str):
        raise TypeError("timestamp must be a string")
    ts = datetime.fromisoformat(text)
    if ts.tzinfo is None:
        raise ValueError("timestamp must carry a timezone")
    return ts.astimezone(UTC)


def staff_id_for(username: str) -> str:
    return STAFF_ID_PREFIX + username


def secret_equal(expected: str | None, given: Any) -> bool:
    """Constant-time compare that never raises (non-ASCII / non-str input is simply unequal)."""
    return (isinstance(expected, str) and isinstance(given, str) and bool(expected)
            and expected.isascii() and given.isascii()
            and hmac.compare_digest(expected.encode("ascii"), given.encode("ascii")))


class AuthError(ApiError):
    """ApiError raised by the auth layer; `reason` (when given) lands in the error envelope's extra."""

    def __init__(self, code: str, message: str, *, reason: str | None = None, extra: dict | None = None,
                 headers: dict[str, str] | None = None) -> None:
        merged = {**(extra or {}), **({"reason": reason} if reason else {})}
        super().__init__(code, message, extra=merged, headers=headers)
        self.reason = reason


@dataclass(frozen=True)
class StaffAccount:
    staff_id: str
    username: str
    display_name: str
    roles: tuple[str, ...]
    password_hash: str = field(repr=False)
    status: AccountStatus = "active"
    failed_logins: int = 0
    locked_until: datetime | None = None
    mfa_secret: str | None = field(default=None, repr=False)
    mfa_pending_secret: str | None = field(default=None, repr=False)
    mfa_last_step: int | None = None
    must_change_password: bool = False
    session_epoch: int = 0  # bumping it invalidates every session of the account, in every process
    created_at: datetime | None = None
    updated_at: datetime | None = None
    password_changed_at: datetime | None = None
    last_login_at: datetime | None = None

    @property
    def mfa_enabled(self) -> bool:
        return self.mfa_secret is not None

    @property
    def active(self) -> bool:
        return self.status == "active"

    def is_locked(self, now: datetime) -> bool:
        return self.locked_until is not None and now < self.locked_until

    def to_public(self, now: datetime) -> dict[str, Any]:
        """Shape returned by the admin API and the CLI: never the hash or any MFA secret."""
        locked = self.is_locked(now)
        return {
            "staff_id": self.staff_id, "username": self.username, "display_name": self.display_name,
            "roles": list(self.roles), "status": self.status, "locked": locked,
            "locked_until": iso(self.locked_until) if locked else None,
            "failed_logins": self.failed_logins, "mfa_enabled": self.mfa_enabled,
            "must_change_password": self.must_change_password, "created_at": iso(self.created_at),
            "updated_at": iso(self.updated_at), "password_changed_at": iso(self.password_changed_at),
            "last_login_at": iso(self.last_login_at),
        }

    def to_record(self) -> dict[str, Any]:
        return {
            "staff_id": self.staff_id, "username": self.username, "display_name": self.display_name,
            "roles": list(self.roles), "password_hash": self.password_hash, "status": self.status,
            "failed_logins": self.failed_logins, "locked_until": iso(self.locked_until),
            "mfa_secret": self.mfa_secret, "mfa_pending_secret": self.mfa_pending_secret,
            "mfa_last_step": self.mfa_last_step, "must_change_password": self.must_change_password,
            "session_epoch": self.session_epoch, "created_at": iso(self.created_at),
            "updated_at": iso(self.updated_at), "password_changed_at": iso(self.password_changed_at),
            "last_login_at": iso(self.last_login_at),
        }

    @classmethod
    def from_record(cls, raw: Mapping[str, Any]) -> StaffAccount:
        username = _req_str(raw, "username")
        staff_id = _req_str(raw, "staff_id")
        if not USERNAME_RE.fullmatch(username) or staff_id != staff_id_for(username):
            raise ValueError("bad username / staff_id")
        status = _req_str(raw, "status")
        if status not in ACCOUNT_STATUSES:
            raise ValueError("bad status")
        roles = raw.get("roles")
        if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
            raise ValueError("bad roles")
        return cls(
            staff_id=staff_id, username=username, display_name=_req_str(raw, "display_name"),
            roles=tuple(roles), password_hash=_req_str(raw, "password_hash"),
            status=status,  # type: ignore[arg-type]
            failed_logins=_int(raw, "failed_logins"), locked_until=parse_iso(raw.get("locked_until")),
            mfa_secret=_opt_str(raw, "mfa_secret"), mfa_pending_secret=_opt_str(raw, "mfa_pending_secret"),
            mfa_last_step=_opt_int(raw, "mfa_last_step"),
            must_change_password=bool(raw.get("must_change_password", False)),
            session_epoch=_int(raw, "session_epoch"), created_at=parse_iso(raw.get("created_at")),
            updated_at=parse_iso(raw.get("updated_at")),
            password_changed_at=parse_iso(raw.get("password_changed_at")),
            last_login_at=parse_iso(raw.get("last_login_at")),
        )


@dataclass(frozen=True)
class ApiKey:
    key_id: str
    name: str
    roles: tuple[str, ...]
    secret_sha256: str = field(repr=False)
    created_at: datetime | None = None
    created_by: str | None = None
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None

    def usable(self, now: datetime) -> bool:
        return self.revoked_at is None and (self.expires_at is None or now < self.expires_at)

    def to_public(self, now: datetime, permissions: frozenset[str] = frozenset()) -> dict[str, Any]:
        state = "revoked" if self.revoked_at else ("active" if self.usable(now) else "expired")
        return {
            "key_id": self.key_id, "name": self.name, "roles": list(self.roles),
            "permissions": sorted(permissions), "status": state,
            "created_at": iso(self.created_at), "created_by": self.created_by,
            "expires_at": iso(self.expires_at), "last_used_at": iso(self.last_used_at),
            "revoked_at": iso(self.revoked_at),
        }

    def to_record(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id, "name": self.name, "roles": list(self.roles),
            "secret_sha256": self.secret_sha256,
            "created_at": iso(self.created_at), "created_by": self.created_by,
            "expires_at": iso(self.expires_at), "last_used_at": iso(self.last_used_at),
            "revoked_at": iso(self.revoked_at),
        }

    @classmethod
    def from_record(cls, raw: Mapping[str, Any]) -> ApiKey:
        key_id = _req_str(raw, "key_id")
        if not KEY_ID_RE.fullmatch(key_id):
            raise ValueError("bad key_id")
        roles = raw.get("roles")
        if not isinstance(roles, list) or not roles or not all(isinstance(r, str) for r in roles):
            raise ValueError("bad api key roles")
        return cls(
            key_id=key_id, name=_req_str(raw, "name"), roles=tuple(roles),
            secret_sha256=_req_str(raw, "secret_sha256"), created_at=parse_iso(raw.get("created_at")),
            created_by=_opt_str(raw, "created_by"), expires_at=parse_iso(raw.get("expires_at")),
            last_used_at=parse_iso(raw.get("last_used_at")), revoked_at=parse_iso(raw.get("revoked_at")),
        )


def _empty() -> Mapping[str, Any]:
    return MappingProxyType({})


@dataclass(frozen=True)
class StoreData:
    accounts: Mapping[str, StaffAccount] = field(default_factory=_empty)
    api_keys: Mapping[str, ApiKey] = field(default_factory=_empty)
    generation: int = 0  # bumped by the store on every write; a lower one on disk = rollback

    def with_account(self, account: StaffAccount) -> StoreData:
        return replace(self, accounts=MappingProxyType({**self.accounts, account.staff_id: account}))

    def without_account(self, staff_id: str) -> StoreData:
        return replace(self, accounts=MappingProxyType({k: v for k, v in self.accounts.items() if k != staff_id}))

    def with_api_key(self, key: ApiKey) -> StoreData:
        return replace(self, api_keys=MappingProxyType({**self.api_keys, key.key_id: key}))

    def by_username(self, username: str) -> StaffAccount | None:
        return self.accounts.get(staff_id_for(username))


@dataclass(frozen=True)
class Session:
    """Timers run on time.monotonic() (wall-clock jumps and the demo clock never move them); the wall-clock
    created_at / expires_at are for display only."""
    session_id: str          # public handle (prefix of the token digest), safe for logs and audit
    token_sha256: str = field(repr=False)
    staff_id: str = ""
    epoch: int = 0
    created_mono: float = 0.0
    last_seen_mono: float = 0.0
    expires_mono: float = 0.0
    created_at: datetime | None = None
    expires_at: datetime | None = None
    client_ip: str | None = None
    user_agent: str | None = None


@dataclass(frozen=True)
class Principal:
    """kind staff: id = staff_id (s_...); api_key: id = key:<key_id>; legacy: id = legacy:admin_token;
    cli: id = cli:<os user> (console operator, never reachable over HTTP)."""
    kind: PrincipalKind
    id: str
    username: str | None
    display_name: str
    roles: tuple[str, ...]
    permissions: frozenset[str]
    session_id: str | None = None
    key_id: str | None = None
    must_change_password: bool = False
    mfa_enrolment_required: bool = False
    mfa_enabled: bool = False

    @property
    def staff_id(self) -> str | None:
        return self.id if self.kind == "staff" else None

    @property
    def actor_id(self) -> str:
        """The actor string sent to the cloud and written to logs: staff:<id> | key:<id> | legacy:admin_token."""
        if self.kind == "staff":
            return STAFF_ACTOR_PREFIX + self.id
        return self.id

    @property
    def pending_action(self) -> str | None:
        """Reason a staff principal is confined to /auth/me|logout|activity|password|mfa/* until it acts."""
        if self.must_change_password:
            return "PASSWORD_CHANGE_REQUIRED"
        if self.mfa_enrolment_required:
            return "MFA_ENROLMENT_REQUIRED"
        return None

    def actor(self) -> dict[str, Any]:
        return {"kind": self.kind, "id": self.id, "username": self.username}

    def to_public(self) -> dict[str, Any]:
        return {
            "kind": self.kind, "id": self.id, "staff_id": self.staff_id, "actor_id": self.actor_id,
            "username": self.username, "display_name": self.display_name, "roles": list(self.roles),
            "permissions": sorted(self.permissions), "must_change_password": self.must_change_password,
            "mfa_enrolment_required": self.mfa_enrolment_required, "mfa_enabled": self.mfa_enabled,
        }


def _req_str(raw: Mapping[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _opt_str(raw: Mapping[str, Any], key: str) -> str | None:
    value = raw.get(key)
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    return value


def _int(raw: Mapping[str, Any], key: str) -> int:
    value = raw.get(key, 0)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{key} must be a non-negative integer")
    return value


def _opt_int(raw: Mapping[str, Any], key: str) -> int | None:
    return None if raw.get(key) is None else _int(raw, key)
