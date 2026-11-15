"""Staff sign-in (mixed into AuthService): throttle -> KDF admission -> verify -> MFA -> session.

- The global cap and the per-username progressive delay are checked BEFORE any scrypt work; during a delay
  only "correct password + valid TOTP" on an MFA account gets through (the soft delay never hard-locks).
- A SEPARATE per-account MFA throttle (keyed by staff_id, same threshold/cap) counts bad TOTP codes. A
  totp_code can NOT bypass it, and it is checked before any KDF or TOTP work (password and ticket paths),
  so a known password does not give unlimited second-factor guesses. Reset on a successful login.
- Unknown usernames run a dummy scrypt and are throttled exactly like real ones (no existence leak).
- ACCOUNT_DISABLED is only revealed after a correct password.
- MFA accounts without totp_code get 401 MFA_REQUIRED + an opaque single-use `mfa_ticket` (2 min), so the
  client re-posts {mfa_ticket, totp_code} without a second KDF. A ticket is bound to the account instance
  (staff_id, epoch, created_at, password_changed_at, password hash): anything else -> 401 MFA_INVALID.
- The durable write of a login (TOTP step, rehash) re-checks inside the store lock that the verified hash
  and epoch are unchanged (a concurrent reset wins), and the session uses the VERIFIED epoch.
- Unknown usernames are never written to the audit log (username null, known=false).
- The async path does no store / audit I/O on the event loop (precheck + ticket step run in a thread).
- Volatile fields (failure counters, last_login_at, API-key last_used_at) live in memory and are flushed to
  the store at most once per minute. Changes made by another process (CLI unlock / reset) are reconciled
  on the next store reload: the in-memory throttle is cleared and a later flush never writes the old
  counters back.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import threading
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime
from typing import TYPE_CHECKING, Any

from edge.auth import mfa, passwords, tokens
from edge.auth.models import (
    USERNAME_RE,
    AuthError,
    Principal,
    Session,
    StaffAccount,
    StoreData,
    iso,
    staff_id_for,
)
from edge.auth.ratelimit import FailureState, LoginThrottle, rate_limited

if TYPE_CHECKING:
    from edge.auth.audit import AuditLog
    from edge.auth.config import AuthConfig
    from edge.auth.models import Clock
    from edge.auth.ratelimit import GlobalLimiter, KdfExecutor
    from edge.auth.sessions import SessionManager
    from edge.auth.store import StaffStore

log = logging.getLogger("edge.auth")

MAX_USER_AGENT = 200
MAX_LOGIN_USERNAME = 64
TICKET_TTL_S = 120.0
MAX_TICKETS = 1_000
VOLATILE_FLUSH_INTERVAL_S = 60.0
BRUTEFORCE_WINDOW_S = 600.0
BRUTEFORCE_THRESHOLD = 20
INVALID_USERNAME_KEY = "\0invalid"
LOGIN_FAILED = "invalid username or password"
MFA_FAILED = "authenticator code is not valid"
TICKET_EXPIRED = "sign-in step expired, enter your password again"
_UNSEEN = object()
LoginResult = tuple[str, Session, Principal]


def unauthorized(message: str = "authentication required", reason: str | None = "CREDENTIAL_INVALID",
                 **extra: Any) -> AuthError:
    return AuthError("UNAUTHORIZED", message, reason=reason, extra=extra or None)


def normalise_username(username: Any) -> str | None:
    if not isinstance(username, str) or len(username) > MAX_LOGIN_USERNAME:
        return None
    value = username.strip().lower()
    return value if USERNAME_RE.fullmatch(value) else None


def account_binding(account: StaffAccount) -> str:
    """Identifies one account INSTANCE: changes on delete + re-create (same staff_id) and on any password
    change. In memory only (MFA tickets), never logged."""
    raw = "\0".join((account.staff_id, iso(account.created_at) or "", iso(account.password_changed_at) or "",
                     account.password_hash))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _same_credentials(current: StaffAccount, verified: StaffAccount) -> bool:
    return (current.password_hash == verified.password_hash and current.session_epoch == verified.session_epoch
            and current.created_at == verified.created_at)


@dataclass(frozen=True)
class MfaTicket:
    staff_id: str
    username: str
    epoch: int
    binding: str
    expires_mono: float


class LoginMixin:
    config: AuthConfig
    store: StaffStore
    audit: AuditLog
    sessions: SessionManager
    clock: Clock
    monotonic: Callable[[], float]
    throttle: LoginThrottle
    mfa_throttle: LoginThrottle
    global_limiter: GlobalLimiter
    kdf: KdfExecutor

    def _init_login_state(self) -> None:
        # The live delays must run on the service's monotonic clock. service.py should construct
        # LoginThrottle(..., clock=clock, monotonic=monotonic); until it does, rebind here (still empty).
        if self.throttle.monotonic != self.monotonic:
            self.throttle = self.throttle.rebind(monotonic=self.monotonic)
        self.mfa_throttle = LoginThrottle(threshold=self.config.lockout_threshold,
                                          cap_s=self.config.lockout_cap_s, clock=self.clock,
                                          monotonic=self.monotonic)
        self._reconcile_lock = threading.Lock()
        self._reconciled_generation = -1
        self._seen_updated_at: dict[str, datetime | None] = {}
        self._tickets: OrderedDict[str, MfaTicket] = OrderedDict()
        self._tickets_lock = threading.Lock()
        self._volatile_lock = threading.Lock()
        self._volatile_logins: dict[str, datetime] = {}
        self._volatile_keys: dict[str, datetime] = {}
        self._dirty_failures: set[str] = set()
        self._last_flush = self.monotonic()
        self._failures: deque[float] = deque()
        self._seed_throttle()

    def _principal_for(self, account: StaffAccount, session: Session | None) -> Principal:  # AuthService
        raise NotImplementedError

    # ------------------------------------------------------------------ entry points
    async def login(self, username: str | None, password: str | None, totp_code: str | None = None,
                    client_ip: str | None = None, user_agent: str | None = None, *,
                    mfa_ticket: str | None = None) -> LoginResult:
        self.global_limiter.hit()  # memory only
        if mfa_ticket is not None:  # store + audit I/O: off the loop, but not in a KDF slot
            return await asyncio.to_thread(self._login_with_ticket, mfa_ticket, totp_code, client_ip, user_agent)
        uname, throttled = await asyncio.to_thread(self._precheck, username, totp_code)  # store re-stat
        return await self.kdf.run(self._login_kdf, uname, password or "", totp_code, client_ip, user_agent,
                                  throttled)

    def login_sync(self, username: str | None, password: str | None, totp_code: str | None = None,
                   client_ip: str | None = None, user_agent: str | None = None, *,
                   mfa_ticket: str | None = None) -> LoginResult:
        """Same as login() on the calling thread (tests, tools)."""
        self.global_limiter.hit()
        if mfa_ticket is not None:
            return self._login_with_ticket(mfa_ticket, totp_code, client_ip, user_agent)
        uname, throttled = self._precheck(username, totp_code)
        return self._login_kdf(uname, password or "", totp_code, client_ip, user_agent, throttled)

    def _precheck(self, username: str | None, totp_code: str | None) -> tuple[str | None, bool]:
        """Throttle checks before any KDF: an MFA-throttled account gets 429 whatever it sends; a delayed
        username without a TOTP code gets 429 at once."""
        uname = normalise_username(username)
        self._reconcile_throttle()
        if uname:
            mfa_wait = self.mfa_throttle.retry_after_s(staff_id_for(uname))
            if mfa_wait > 0:
                raise rate_limited(mfa_wait)
        wait = self.throttle.retry_after_s(uname or INVALID_USERNAME_KEY)
        if wait > 0 and not totp_code:
            raise rate_limited(wait)
        return uname, wait > 0

    # ------------------------------------------------------------------ password step
    def _login_kdf(self, uname: str | None, password: str, totp_code: str | None, client_ip: str | None,
                   user_agent: str | None, throttled: bool) -> LoginResult:
        data = self.store.snapshot()  # AUTH_UNAVAILABLE when MISSING / UNAVAILABLE
        account = data.by_username(uname) if uname else None
        key = uname or INVALID_USERNAME_KEY
        if account is None:
            passwords.dummy_verify(password)
            ok = False
        else:
            ok = passwords.verify_password(password, account.password_hash)
        if not ok:
            self._login_failed(key, account, client_ip, "INVALID_CREDENTIALS")
            if throttled:
                raise rate_limited(self.throttle.retry_after_s(key))
            raise unauthorized(LOGIN_FAILED, "INVALID_CREDENTIALS")
        assert account is not None
        if throttled:
            return self._throttled_mfa_bypass(account, password, totp_code, client_ip, user_agent)
        if not account.active:
            self._audit_login(account, "denied", client_ip, "ACCOUNT_DISABLED")
            raise unauthorized("account disabled", "ACCOUNT_DISABLED")
        if not account.mfa_enabled:
            return self._complete_login(account, None, client_ip, user_agent, password)
        if not totp_code:
            ticket = self._issue_ticket(account)
            self._audit_login(account, "denied", client_ip, "MFA_REQUIRED")
            raise AuthError("UNAUTHORIZED", "authenticator code required", reason="MFA_REQUIRED",
                            extra={"mfa_ticket": ticket}, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
        return self._mfa_step(account, totp_code, client_ip, user_agent, password)

    def _throttled_mfa_bypass(self, account: StaffAccount, password: str, totp_code: str | None,
                              client_ip: str | None, user_agent: str | None) -> LoginResult:
        """During a delay only a correct password AND a valid TOTP on an MFA account gets through."""
        step = (mfa.accept_code(account.mfa_secret, totp_code, self.clock(), account.mfa_last_step)
                if account.mfa_secret else None)
        if step is None:
            mfa_state = self.mfa_throttle.fail(account.staff_id) if account.mfa_secret else None
            self._login_failed(account.username, account, client_ip, "THROTTLED", mfa_state=mfa_state)
            raise rate_limited(self.throttle.retry_after_s(account.username))
        if not account.active:
            self._audit_login(account, "denied", client_ip, "ACCOUNT_DISABLED")
            raise unauthorized("account disabled", "ACCOUNT_DISABLED")
        return self._complete_login(account, step, client_ip, user_agent, password)

    def _mfa_step(self, account: StaffAccount, code: str | None, client_ip: str | None,
                  user_agent: str | None, password: str | None) -> LoginResult:
        if account.mfa_secret is None:
            raise unauthorized(MFA_FAILED, "MFA_INVALID")
        step = mfa.accept_code(account.mfa_secret, code, self.clock(), account.mfa_last_step)
        if step is None:
            mfa_state = self.mfa_throttle.fail(account.staff_id)
            self._login_failed(account.username, account, client_ip, "MFA_INVALID", mfa_state=mfa_state)
            raise unauthorized(MFA_FAILED, "MFA_INVALID")
        return self._complete_login(account, step, client_ip, user_agent, password)

    # ------------------------------------------------------------------ MFA tickets
    def _issue_ticket(self, account: StaffAccount) -> str:
        ticket = secrets.token_urlsafe(32)
        now = self.monotonic()
        with self._tickets_lock:
            for k in [k for k, t in self._tickets.items() if t.expires_mono <= now]:
                del self._tickets[k]
            self._tickets[tokens.digest(ticket)] = MfaTicket(account.staff_id, account.username,
                                                             account.session_epoch, account_binding(account),
                                                             now + TICKET_TTL_S)
            while len(self._tickets) > MAX_TICKETS:
                self._tickets.popitem(last=False)
        return ticket

    def _login_with_ticket(self, ticket: str, code: str | None, client_ip: str | None,
                           user_agent: str | None) -> LoginResult:
        """Second step. The MFA throttle is checked before the ticket is spent or any code evaluated (a
        throttled ticket stays usable until it expires); any change to the account instance -> MFA_INVALID."""
        digest = tokens.digest(ticket) if isinstance(ticket, str) else None
        entry = self._peek_ticket(digest)
        self._reconcile_throttle()
        wait = self.mfa_throttle.retry_after_s(entry.staff_id)
        if wait > 0:
            raise rate_limited(wait)
        with self._tickets_lock:
            if self._tickets.pop(digest, None) is None:  # spent concurrently
                raise unauthorized(TICKET_EXPIRED, "MFA_INVALID")
        account = self.store.snapshot().accounts.get(entry.staff_id)
        if (account is None or not account.active or not account.mfa_enabled
                or account.session_epoch != entry.epoch or account_binding(account) != entry.binding):
            raise unauthorized(TICKET_EXPIRED, "MFA_INVALID")
        return self._mfa_step(account, code, client_ip, user_agent, None)

    def _peek_ticket(self, digest: str | None) -> MfaTicket:
        now = self.monotonic()
        with self._tickets_lock:
            entry = self._tickets.get(digest) if digest else None
            if entry is not None and entry.expires_mono <= now:
                del self._tickets[digest]  # type: ignore[arg-type]
                entry = None
        if entry is None:
            raise unauthorized(TICKET_EXPIRED, "MFA_INVALID")
        return entry

    # ------------------------------------------------------------------ outcomes
    def _complete_login(self, account: StaffAccount, step: int | None, client_ip: str | None,
                        user_agent: str | None, password: str | None) -> LoginResult:
        """`account` is the VERIFIED snapshot: the session always carries its epoch."""
        new_hash = (passwords.hash_password(password)
                    if password and passwords.needs_rehash(account.password_hash) else None)
        current = account
        if step is not None or new_hash:
            try:
                current = self._persist_login(account, step, new_hash)
            except AuthError as exc:
                self._audit_login(account, "denied", client_ip, exc.reason)
                raise
        self.throttle.succeed(account.username)
        self.mfa_throttle.succeed(account.staff_id)
        with self._volatile_lock:
            self._volatile_logins[account.staff_id] = self.clock()
        token, session = self.sessions.create(account.staff_id, account.session_epoch, client_ip=client_ip,
                                              user_agent=(user_agent or "")[:MAX_USER_AGENT] or None)
        self._audit_login(current, "ok", client_ip, None, session_id=session.session_id)
        self.maybe_flush_volatile()
        return token, session, self._principal_for(current, session)

    def _persist_login(self, verified: StaffAccount, step: int | None, new_hash: str | None) -> StaffAccount:
        """TOTP step (replay protection) and a parameter upgrade are durable; checked inside the lock. If the
        password hash, epoch or account instance changed since verification (a concurrent reset / MFA reset
        / re-create), nothing is written and the login fails: a rehash never overwrites a reset."""
        def apply(data: StoreData) -> tuple[StoreData, StaffAccount]:
            acc = data.accounts.get(verified.staff_id)
            if acc is None or not acc.active or not _same_credentials(acc, verified):
                raise unauthorized(LOGIN_FAILED, "INVALID_CREDENTIALS")
            if step is not None and acc.mfa_last_step is not None and step <= acc.mfa_last_step:
                raise unauthorized(MFA_FAILED, "MFA_INVALID")  # concurrent replay
            new = replace(acc, mfa_last_step=step if step is not None else acc.mfa_last_step,
                          password_hash=new_hash or acc.password_hash)
            return data.with_account(new), new

        return self.store.update(apply)

    def _login_failed(self, key: str, account: StaffAccount | None, client_ip: str | None, reason: str, *,
                      mfa_state: FailureState | None = None) -> None:
        state = self.throttle.fail(key)
        now = self.monotonic()
        with self._volatile_lock:
            self._failures.append(now)
            while self._failures and now - self._failures[0] > BRUTEFORCE_WINDOW_S:
                self._failures.popleft()
            if account is not None:
                self._dirty_failures.add(account.staff_id)
        # An unknown "username" may be a passphrase typed into the wrong box: it is never written anywhere.
        actor = ({"kind": "staff", "id": account.staff_id, "username": account.username} if account
                 else {"kind": "anonymous", "id": None, "username": None})
        detail: dict[str, Any] = {"reason": reason, "known": account is not None, "failures": state.failed,
                                  "retry_after": iso(state.next_allowed)}
        if mfa_state is not None:
            detail["mfa_failures"] = mfa_state.failed
            detail["mfa_retry_after"] = iso(mfa_state.next_allowed)
        self.audit.safe_append("auth.login", actor=actor, outcome="denied", client_ip=client_ip, detail=detail)
        self.maybe_flush_volatile()

    def _audit_login(self, account: StaffAccount, outcome: str, client_ip: str | None, reason: str | None,
                     **detail: Any) -> None:
        self.audit.safe_append("auth.login", actor={"kind": "staff", "id": account.staff_id,
                                                    "username": account.username},
                               outcome=outcome, client_ip=client_ip,  # type: ignore[arg-type]
                               detail={**({"reason": reason} if reason else {}), **detail})

    def recent_failed_logins(self) -> int:
        now = self.monotonic()
        with self._volatile_lock:
            return sum(1 for t in self._failures if now - t <= BRUTEFORCE_WINDOW_S)

    def bruteforce_suspected(self) -> bool:
        return self.recent_failed_logins() >= BRUTEFORCE_THRESHOLD

    # ------------------------------------------------------------------ volatile fields
    def note_key_use(self, key_id: str) -> None:
        with self._volatile_lock:
            self._volatile_keys[key_id] = self.clock()
        self.maybe_flush_volatile()

    def maybe_flush_volatile(self) -> None:
        if self.monotonic() - self._last_flush >= VOLATILE_FLUSH_INTERVAL_S:
            self.flush_volatile()

    def flush_volatile(self) -> None:
        """Write last_login_at / last_used_at / failure counters to the store (best effort)."""
        with self._volatile_lock:
            logins, keys, dirty = dict(self._volatile_logins), dict(self._volatile_keys), set(self._dirty_failures)
            self._volatile_logins.clear()
            self._volatile_keys.clear()
            self._dirty_failures.clear()
            self._last_flush = self.monotonic()
        if not (logins or keys or dirty):
            return

        skipped: set[str] = set()

        def apply(data: StoreData) -> tuple[StoreData, None]:
            for staff_id in set(logins) | dirty:
                acc = data.accounts.get(staff_id)
                if acc is None:
                    continue
                if self._changed_elsewhere(acc):
                    # Another process changed the account since we last looked (e.g. CLI unlock): never write
                    # our counters over it; the next reconcile decides, then a later flush writes them.
                    skipped.add(staff_id)
                    if staff_id in logins:
                        data = data.with_account(replace(acc, last_login_at=logins[staff_id]))
                    continue
                state = self.throttle.state(acc.username)
                data = data.with_account(replace(acc, last_login_at=logins.get(staff_id, acc.last_login_at),
                                                 failed_logins=state.failed, locked_until=state.next_allowed))
            for key_id, used in keys.items():
                key = data.api_keys.get(key_id)
                if key is not None:
                    data = data.with_api_key(replace(key, last_used_at=used))
            return data, None

        try:
            self.store.update(apply)
        except Exception:  # bookkeeping must never fail a request
            log.exception("could not flush volatile auth fields (these values are dropped)")
            return
        if skipped:
            with self._volatile_lock:
                self._dirty_failures |= skipped

    def _changed_elsewhere(self, account: StaffAccount) -> bool:
        with self._reconcile_lock:
            seen = self._seen_updated_at.get(account.staff_id, _UNSEEN)
        return seen is not _UNSEEN and seen != account.updated_at

    def _reconcile_throttle(self) -> None:
        """At most once per store reload: clear the in-memory throttles of every account that another
        process (or an admin) reset, i.e. whose updated_at moved since we last looked while its stored
        failed_logins is 0 and locked_until is None (CLI unlock / set-password)."""
        try:
            data = self.store.snapshot()
        except AuthError:
            return  # the KDF step reports AUTH_UNAVAILABLE
        with self._reconcile_lock:
            if data.generation == self._reconciled_generation:
                return
            self._reconciled_generation = data.generation
            for acc in data.accounts.values():
                seen = self._seen_updated_at.get(acc.staff_id, _UNSEEN)
                self._seen_updated_at[acc.staff_id] = acc.updated_at
                if seen is _UNSEEN or seen == acc.updated_at:
                    continue
                if acc.failed_logins == 0 and acc.locked_until is None:
                    self.throttle.succeed(acc.username)
                    self.mfa_throttle.succeed(acc.staff_id)
            for staff_id in [s for s in self._seen_updated_at if s not in data.accounts]:
                del self._seen_updated_at[staff_id]

    def _seed_throttle(self) -> None:
        try:
            data = self.store.snapshot()
        except AuthError:
            return
        with self._reconcile_lock:
            self._reconciled_generation = data.generation
            for acc in data.accounts.values():
                self._seen_updated_at[acc.staff_id] = acc.updated_at
                self.throttle.seed(acc.username, acc.failed_logins, acc.locked_until)

    def _note_own_write(self, account: StaffAccount) -> None:
        """This process wrote `account` (admin edit, unlock, reset...): its new updated_at is not a sign that
        ANOTHER process reset it, so the next reconcile must not clear its throttle because of it.
        Unlock / reset clear the throttle explicitly (clear_throttle)."""
        with self._reconcile_lock:
            self._seen_updated_at[account.staff_id] = account.updated_at

    def clear_throttle(self, username: str) -> None:
        """Clear the password AND the MFA throttle of `username` (unlock / reset in this process)."""
        self.throttle.succeed(username)
        self.mfa_throttle.succeed(staff_id_for(username))
