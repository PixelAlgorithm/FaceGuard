"""AuthService: the facade the edge app, the HTTP routes and the CLI use.

    auth = build_auth_service(settings.data_dir, os.environ)   # never raises for a bad key / corrupt store
    principal = auth.authenticate(credential, admin_token=..., touch=...)
    auth.is_authorized(principal, "events:read")               # SSE re-check, never extends a session

Blocking scrypt work goes through `await auth.kdf.run(fn, ...)` (dedicated 2-thread pool, non-blocking
admission). Login lives in login.py, staff/key/MFA administration in staff_ops.py.

Without any key material (no EDGE_DATA_KEY and no STAFF_STORE_KEY) the store is UNAVAILABLE and the audit log
uses a random per-process MAC key: nothing written then can be forged, and degraded_reasons() reports
auth_unavailable. Every staff:manage mutation re-checks its staff actor (exists, active, still holds
staff:manage, same session_epoch as its session) inside the store lock (staff_ops.ActorCheck).
"""

from __future__ import annotations

import logging
import secrets
import threading
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any

from edge.auth import mfa, passwords, rbac, tokens
from edge.auth.audit import AuditLog
from edge.auth.config import AuthConfig
from edge.auth.keys import KeyMaterialError, audit_mac_key
from edge.auth.login import LoginMixin, unauthorized
from edge.auth.models import (
    LEGACY_ACTOR_ID,
    AuthError,
    Clock,
    Principal,
    Session,
    StaffAccount,
    StoreData,
    auth_monotonic,
    iso,
    secret_equal,
    utc_now,
)
from edge.auth.ratelimit import GlobalLimiter, KdfExecutor, LoginThrottle, rate_limited
from edge.auth.sessions import SessionManager
from edge.auth.staff_ops import (
    STAFF_MANAGE,
    ActorCheck,
    MfaSetup,
    StaffOpsMixin,
    check_password,
    forbidden,
    no_actor_check,
)
from edge.auth.store import StaffStore, StoreState

log = logging.getLogger("edge.auth")

LEGACY_DISPLAY_NAME = "legacy admin token"
EPHEMERAL_AUDIT_KEY_BYTES = 32


def session_expired() -> AuthError:
    return unauthorized("session expired, sign in again", "SESSION_EXPIRED")


def _login_throttle(config: AuthConfig, clock: Clock, monotonic: Callable[[], float]) -> LoginThrottle:
    return LoginThrottle(threshold=config.lockout_threshold, cap_s=config.lockout_cap_s, clock=clock,
                         monotonic=monotonic)


class AuthService(LoginMixin, StaffOpsMixin):
    def __init__(self, config: AuthConfig, store: StaffStore, audit: AuditLog, *, clock: Clock = utc_now,
                 monotonic: Callable[[], float] = auth_monotonic, sessions: SessionManager | None = None,
                 kdf: KdfExecutor | None = None) -> None:
        self.config = config
        self.store = store
        self.audit = audit
        self.clock = clock
        self.monotonic = monotonic
        self.sessions = sessions or SessionManager(
            idle_timeout_s=config.idle_timeout_s, max_age_s=config.max_session_s,
            max_per_user=config.max_sessions_per_user, clock=clock, monotonic=monotonic)
        self.global_limiter = GlobalLimiter(max_attempts=config.login_global_max,
                                            window_s=config.login_global_window_s, monotonic=monotonic)
        self.throttle = _login_throttle(config, clock, monotonic)
        self.kdf = kdf or KdfExecutor()
        self.unauthenticated_count = 0
        self._key_material_missing = False
        self._pending_epochs: dict[str, int] = {}  # session_id -> epoch its own password change is moving to
        self._pending_lock = threading.Lock()
        self._init_login_state()

    @classmethod
    def open(cls, data_dir: Path, data_key: str, config: AuthConfig, *, store_key: str = "",
             clock: Clock = utc_now, monotonic: Callable[[], float] = auth_monotonic) -> AuthService:
        """Service over <data_dir>/staff.fernet + audit.jsonl. Never raises for a missing/bad key or a corrupt
        store: the store is then UNAVAILABLE and every authenticated call fails closed (AUTH_UNAVAILABLE)."""
        try:
            mac_key, missing = audit_mac_key(data_key, store_key), False
        except KeyMaterialError:
            # No key at all: the store is UNAVAILABLE too. A random per-process key keeps every line written
            # now unforgeable (never a constant from the source); such lines do not verify after a restart.
            log.error("no EDGE_DATA_KEY or STAFF_STORE_KEY: staff auth unavailable, audit MAC key is ephemeral")
            mac_key, missing = secrets.token_bytes(EPHEMERAL_AUDIT_KEY_BYTES), True
        audit = AuditLog(data_dir, mac_key=mac_key, max_bytes=config.audit_max_bytes, keep=config.audit_keep,
                         clock=clock)
        store = StaffStore(data_dir, data_key, store_key=store_key, monotonic=monotonic)
        service = cls(config, store, audit, clock=clock, monotonic=monotonic)
        service._key_material_missing = missing
        return service

    # ------------------------------------------------------------------ state / health
    @property
    def store_state(self) -> StoreState:
        return self.store.state

    @property
    def available(self) -> bool:
        return self.store.available

    def status(self) -> dict[str, Any]:
        """Public GET /v1/auth/status (never usernames)."""
        state = self.store_state
        accounts = bool(self.store.snapshot().accounts) if state in ("OK", "EMPTY") else False
        return {"store": state, "accounts_exist": accounts,
                "legacy_token_enabled": self.config.legacy_admin_token_enabled,
                "mfa_required_roles": sorted(self.config.mfa_required_roles)}

    def degraded_reasons(self) -> list[str]:
        reasons = []
        if self.config.legacy_admin_token_enabled:
            reasons.append("legacy_admin_token")
        if self._key_material_missing or self.store_state in ("MISSING", "UNAVAILABLE"):
            reasons.append("auth_unavailable")
        if self.bruteforce_suspected():
            reasons.append("auth_bruteforce")
        return reasons

    def close(self) -> None:
        self.flush_volatile()
        self.audit.flush_denials()
        self.kdf.shutdown()

    # ------------------------------------------------------------------ authentication
    def authenticate(self, credential: str | None, *, admin_token: str | None = None,
                     client_ip: str | None = None, path: str | None = None, touch: bool = False) -> Principal:
        """Principal for a bearer credential (fgs_ session / fgk_ API key) or, only with the legacy flag, the
        shared X-Admin-Token. touch=True records session activity. Raises UNAUTHORIZED / AUTH_UNAVAILABLE."""
        if not credential and not admin_token:
            self.unauthenticated_count += 1
            raise unauthorized()
        self.store.snapshot()  # fail closed (MISSING / UNAVAILABLE) before looking at any credential
        if credential and tokens.is_session_token(credential):
            return self._session_principal(credential, touch)
        if credential and tokens.parse_api_key(credential) is not None:
            return self._api_key_principal(credential)
        if credential:
            raise unauthorized("invalid credential")
        assert admin_token is not None
        return self._legacy_principal(admin_token, client_ip, path)

    def _session_principal(self, token: str, touch: bool) -> Principal:
        session = self.sessions.lookup(token, touch=touch)
        if session is None:
            raise session_expired()
        account = self._live_account(session)
        if account is None:
            self.sessions.revoke(session.session_id)
            raise session_expired()
        return self._principal_for(account, session)

    def _live_account(self, session: Session) -> StaffAccount | None:
        account = self.store.snapshot().accounts.get(session.staff_id)
        if account is None or not account.active:
            return None
        if account.session_epoch != session.epoch and not self._epoch_moving_to(session, account.session_epoch):
            return None
        return account

    def _epoch_moving_to(self, session: Session, epoch: int) -> bool:
        """Is this session being moved to `epoch` by its own password change (F10)? The pending mark is set
        inside the store lock before the write, and set_epoch() runs before the mark is cleared, so a request
        that read the session before the move still sees one of the two."""
        with self._pending_lock:
            if self._pending_epochs.get(session.session_id) == epoch:
                return True
        current = self.sessions.get(session.session_id)
        return current is not None and current.epoch == epoch

    def _session_epoch(self, actor: Principal) -> int:
        """The epoch of a staff actor's live session (captured before a KDF; compared inside the store lock)."""
        session = self.sessions.get(actor.session_id or "")
        if session is None or session.staff_id != actor.id:
            raise session_expired()
        return session.epoch

    def _actor_check(self, actor: Principal, permission: str = STAFF_MANAGE) -> ActorCheck:
        """A check of the actor's CURRENT account, run on the store's `data` inside the lock (F9). The console
        is exempt; other non-staff actors never hold staff:manage (_require refused them already)."""
        if actor.kind != "staff":
            return no_actor_check
        epoch = self._session_epoch(actor)

        def check(data: StoreData) -> None:
            account = data.accounts.get(actor.id)
            if account is None or not account.active or \
                    permission not in self._principal_for(account, None).permissions:
                raise forbidden("missing permission", "MISSING_PERMISSION", required=[permission])
            if account.session_epoch != epoch:
                raise session_expired()

        return check

    def _effective(self, permissions: frozenset[str]) -> frozenset[str]:
        return permissions if self.config.demo_mode else permissions - rbac.DEMO_ONLY_PERMISSIONS

    def _principal_for(self, account: StaffAccount, session: Session | None) -> Principal:
        roles = tuple(r for r in account.roles if r in rbac.EDGE_ROLES)
        needs_mfa = bool(set(roles) & self.config.mfa_required_roles) and not account.mfa_enabled
        return Principal(
            kind="staff", id=account.staff_id, username=account.username, display_name=account.display_name,
            roles=roles, permissions=self._effective(rbac.permissions_for(roles)),
            session_id=session.session_id if session else None,
            must_change_password=account.must_change_password, mfa_enrolment_required=needs_mfa,
            mfa_enabled=account.mfa_enabled,
        )

    def _api_key_principal(self, credential: str) -> Principal:
        parsed = tokens.parse_api_key(credential)
        assert parsed is not None
        key_id, secret = parsed
        key = self.store.snapshot().api_keys.get(key_id)
        ok = key is not None and tokens.digests_equal(tokens.digest(secret), key.secret_sha256)
        if key is None or not ok or not key.usable(self.clock()):
            raise unauthorized("invalid, revoked or expired API key")
        self.note_key_use(key_id)
        return Principal(kind="api_key", id=f"key:{key_id}", username=None, display_name=key.name,
                         roles=key.roles, permissions=self._effective(rbac.key_permissions(key.roles)),
                         key_id=key_id)

    def _legacy_principal(self, admin_token: str, client_ip: str | None, path: str | None) -> Principal:
        cfg = self.config
        if not cfg.legacy_admin_token_enabled or not secret_equal(cfg.legacy_admin_token, admin_token):
            raise unauthorized()
        log.warning("deprecated X-Admin-Token used (AUTH_LEGACY_ADMIN_TOKEN=1) path=%s; "
                    "migrate to staff accounts or API keys", path)
        principal = Principal(kind="legacy", id=LEGACY_ACTOR_ID, username=None, display_name=LEGACY_DISPLAY_NAME,
                              roles=("admin",), permissions=self._effective(rbac.LEGACY_PERMISSIONS))
        self._audit_legacy_use(principal, client_ip, path)
        return principal

    def _audit_legacy_use(self, principal: Principal, client_ip: str | None, path: str | None) -> None:
        try:
            self.audit.record_legacy_use(actor=principal.actor(), route=path or "", client_ip=client_ip)
        except Exception:  # audit bookkeeping must never fail the request
            log.exception("could not record legacy admin token use (path=%s)", path)

    def is_authorized(self, principal: Principal, *permissions: str) -> bool:
        """Is this principal STILL valid and allowed (SSE re-check)? Never extends a session."""
        try:
            if principal.kind == "staff":
                session = self.sessions.get(principal.session_id or "")
                current = self._live_account(session) if session else None
                perms = self._principal_for(current, session).permissions if current else frozenset()
            elif principal.kind == "api_key":
                key = self.store.snapshot().api_keys.get(principal.key_id or "")
                usable = key is not None and key.usable(self.clock())
                perms = self._effective(rbac.key_permissions(key.roles)) if key and usable else frozenset()
            elif principal.kind == "legacy":
                self.store.snapshot()
                perms = self._effective(rbac.LEGACY_PERMISSIONS) if self.config.legacy_admin_token_enabled \
                    else frozenset()
            else:
                return False
        except AuthError:
            return False
        return bool(perms) and set(permissions) <= perms

    def audit_denied(self, principal: Principal | None, *, path: str, required: list[str], reason: str,
                     client_ip: str | None = None) -> None:
        self.audit.record_denial(actor=principal.actor() if principal else None, route=path, reason=reason,
                                 required=required, client_ip=client_ip)

    # ------------------------------------------------------------------ self-service
    def logout(self, principal: Principal, *, client_ip: str | None = None) -> None:
        if principal.kind == "staff" and principal.session_id:
            self.sessions.revoke(principal.session_id)
            self.audit.safe_append("auth.logout", actor=principal.actor(), client_ip=client_ip,
                                   detail={"session_id": principal.session_id})

    def activity(self, principal: Principal) -> None:
        if principal.session_id:
            self.sessions.touch(principal.session_id)

    def me(self, principal: Principal) -> dict[str, Any]:
        session = self.sessions.get(principal.session_id) if principal.session_id else None
        info = None if session is None else {"session_id": session.session_id, "expires_at": iso(session.expires_at),
                                             "idle_timeout_s": self.sessions.idle_timeout_s}
        return {"principal": principal.to_public(), "session": info}

    def _own_account(self, principal: Principal) -> StaffAccount:
        if principal.kind != "staff":
            raise forbidden("only a signed-in staff account can do this", "NO_STAFF_IDENTITY")
        account = self.store.snapshot().accounts.get(principal.id)
        if account is None:
            raise session_expired()
        return account

    def _check_reauth(self, actor: Principal, password: str | None) -> None:
        """Re-authentication for sensitive actions (console operators are exempt). Runs one KDF."""
        if actor.kind == "cli":
            return
        account = self._own_account(actor)
        wait = self.throttle.retry_after_s(account.username)
        if wait > 0:
            raise rate_limited(wait)
        if not password or not passwords.verify_password(password, account.password_hash):
            self._login_failed(account.username, account, None, "REAUTH_FAILED")
            raise forbidden("confirm with your current password", "REAUTH_REQUIRED")

    def _after_unlock(self, username: str) -> None:
        self.clear_throttle(username)

    def change_password(self, principal: Principal, current_password: str, new_password: str, *,
                        client_ip: str | None = None) -> None:
        """Change your own password (2 KDFs: run via kdf.run); every OTHER session of the account ends.
        The current session is marked as moving to the new epoch inside the store lock, before the write, so
        a concurrent request never sees an epoch mismatch for it and signs it out (F10)."""
        account = self._own_account(principal)
        check_password(new_password, account.username)
        if new_password == current_password:
            raise AuthError("VALIDATION_ERROR", "choose a new password", reason="PASSWORD_POLICY",
                            extra={"problems": ["the new password must differ from the current one"]})
        session_id = principal.session_id
        epoch = self._session_epoch(principal) if session_id else None  # captured before the KDF
        self._check_reauth(principal, current_password)
        new_hash = passwords.hash_password(new_password)

        def change(_: StoreData, old: StaffAccount, at: datetime) -> StaffAccount:
            if not old.active or (epoch is not None and old.session_epoch != epoch):
                raise session_expired()  # disabled, demoted or reset meanwhile: this session is already over
            new_epoch = old.session_epoch + 1
            if session_id:
                with self._pending_lock:
                    self._pending_epochs[session_id] = new_epoch
            return replace(old, password_hash=new_hash, must_change_password=False, password_changed_at=at,
                           updated_at=at, failed_logins=0, locked_until=None, session_epoch=new_epoch)

        try:
            _, new = self._mutate(account.staff_id, change)
            assert new is not None
            self.sessions.revoke_all(account.staff_id, except_session_id=session_id)
            if session_id:
                self.sessions.set_epoch(session_id, new.session_epoch)
        finally:
            if session_id:
                with self._pending_lock:
                    self._pending_epochs.pop(session_id, None)
        self.audit.safe_append("auth.password_change", actor=principal.actor(), target=account.staff_id,
                               client_ip=client_ip)

    def enroll_own_mfa(self, principal: Principal, current_password: str | None, *,
                       client_ip: str | None = None) -> MfaSetup:
        """Start TOTP enrolment for yourself. Always re-authenticates (403 REAUTH_REQUIRED for a wrong or
        missing password): one KDF plus a store write, so callers on the event loop use kdf.run."""
        self._own_account(principal)
        self._check_reauth(principal, current_password)
        return self.begin_mfa(principal, principal.id, client_ip=client_ip)

    def confirm_own_mfa(self, principal: Principal, code: str, *, client_ip: str | None = None) -> None:
        self._own_account(principal)
        self.confirm_mfa(principal, principal.id, code, client_ip=client_ip)

    def verify_own_totp(self, principal: Principal, code: str) -> bool:
        account = self._own_account(principal)
        return bool(account.mfa_secret) and mfa.accept_code(
            account.mfa_secret or "", code, self.clock(), account.mfa_last_step) is not None


def build_auth_service(data_dir: Path, env: Mapping[str, str], *, clock: Clock = utc_now,
                       monotonic: Callable[[], float] = auth_monotonic) -> AuthService:
    """The edge's AuthService from its environment (EDGE_DATA_KEY, STAFF_STORE_KEY, ADMIN_TOKEN, AUTH_*,
    DEMO_MODE). Raises ValueError (naming the variable) only for invalid AUTH_* settings."""
    config = AuthConfig.from_env(env, legacy_admin_token=env.get("ADMIN_TOKEN", ""))
    return AuthService.open(Path(data_dir), env.get("EDGE_DATA_KEY", ""), config,
                            store_key=env.get("STAFF_STORE_KEY", ""), clock=clock, monotonic=monotonic)
