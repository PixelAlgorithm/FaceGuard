/**
 * In-browser SIMULATED edge auth (dev builds / VITE_ALLOW_MOCK=1 only; see config.ts DEV_TOOLS_ALLOWED).
 * Mirrors the edge contract (design v2 §B/§C) closely enough to exercise every UI path: login with MFA
 * ticket, MFA enrolment, forced password change, throttle (429), staff + API key admin with re-auth,
 * permission denials and the audit log. State is per tab (sessionStorage `hid.mock.auth`).
 *
 * Demo accounts accept ANY non-empty password until their password is set (create / reset / change);
 * the literal password "wrong" is always rejected so the error paths can be shown. MFA code: 123456.
 * Nothing here protects anything: it is a demo safety net, clearly marked SIMULATED in the UI.
 */
import type {
  ApiKeyCreate,
  ApiKeyCreated,
  ApiKeyInfo,
  AuditQuery,
  AuthAuditEntry,
  AuthAuditPage,
  AuthMe,
  AuthStatus,
  LoginRequest,
  LoginResult,
  MfaEnrolment,
  PasswordChange,
  Principal,
  Reauth,
  RolesCatalog,
  StaffAccount,
  StaffCreate,
  StaffPasswordReset,
  StaffUpdate,
} from './authTypes'
import { AUTH_LIMITS } from './authTypes'
import { isUserInitiated, notifyUnauthorized, shouldSignOutOn401 } from './credentials'
import { passwordPolicyProblems } from '../shared/auth/passwordPolicy'
import { ApiError } from './types'

export const MOCK_TOTP_CODE = '123456'
const STORAGE_KEY = 'hid.mock.auth'
const MFA_REQUIRED_ROLES = ['admin', 'security_officer']
const IDLE_MS = 30 * 60_000
const MAX_SESSION_MS = 12 * 3_600_000
const TICKET_MS = 2 * 60_000
const FREE_FAILURES = 5
const MAX_DELAY_S = 15 * 60
const MOCK_SECRET = 'JBSWY3DPEHPK3PXP'
const REJECTED_PASSWORD = 'wrong'

const ALL_PERMS = [
  'events:read', 'metrics:read', 'store:read', 'attempt:signals', 'mode:switch', 'sync:run', 'ratelimit:reset',
  'eval:admin', 'demo:clock', 'challenge:control', 'enrol:read', 'enrol:write', 'enrol:erase', 'access:read',
  'access:edit', 'access:revoke', 'codes:rotate', 'codes:rotate_any', 'bundle:refresh', 'staff:manage', 'audit:read',
]
const KEY_FORBIDDEN = ['staff:manage', 'codes:rotate', 'codes:rotate_any', 'access:edit', 'access:revoke', 'enrol:erase', 'demo:clock']

/** Mirror of edge/auth/rbac.py EDGE_ROLES (design v2 §B), DEMO_MODE=1. */
const ROLES: Record<string, { description: string; permissions: string[] }> = {
  admin: { description: 'Full control, including staff accounts, API keys and every kiosk setting.', permissions: ALL_PERMS },
  security_officer: {
    description: 'Live monitoring, offline/sync control, revocations, own staff override codes.',
    permissions: ['events:read', 'metrics:read', 'store:read', 'attempt:signals', 'mode:switch', 'sync:run', 'ratelimit:reset', 'enrol:read', 'access:read', 'access:revoke', 'codes:rotate', 'bundle:refresh', 'audit:read'],
  },
  enroller: { description: 'Registers (enrols) faces of people already in the signed schedule.', permissions: ['enrol:read', 'enrol:write', 'enrol:erase', 'access:read', 'bundle:refresh'] },
  auditor: { description: 'Read-only: live feed, metrics, minimal decision log, audit log.', permissions: ['events:read', 'metrics:read', 'store:read', 'enrol:read', 'access:read', 'audit:read'] },
  evaluator: {
    description: 'Runs evaluation sessions: eval context, rate-limit reset, demo controls (DEMO_MODE only).',
    permissions: ['events:read', 'metrics:read', 'attempt:signals', 'eval:admin', 'ratelimit:reset', 'challenge:control', 'mode:switch', 'store:read'],
  },
}

interface MockAccount extends StaffAccount {
  /** null = demo account: any non-empty password except "wrong" */
  password: string | null
  pending_secret: string | null
  session_epoch: number
}
interface MockSession { token: string; staff_id: string; epoch: number; created: number; last_seen: number }
interface MockKey { info: ApiKeyInfo; token: string }
interface Throttle { failures: number; until: number }
interface MockState {
  accounts: MockAccount[]
  sessions: MockSession[]
  keys: MockKey[]
  audit: AuthAuditEntry[]
  seq: number
  /** epoch = account session_epoch when issued (edge: a later disable / password reset voids the ticket) */
  tickets: Array<{ ticket: string; staff_id: string; exp: number; epoch?: number }>
  throttle: Record<string, Throttle>
}

const nowIso = () => new Date().toISOString()
const permsFor = (roles: readonly string[]) => [...new Set(roles.flatMap((r) => ROLES[r]?.permissions ?? []))].sort()

function randomToken(bytes = 24): string {
  const a = new Uint8Array(bytes)
  crypto.getRandomValues(a)
  return btoa(String.fromCharCode(...a)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function demoAccount(username: string, display: string, roles: string[], extra: Partial<MockAccount> = {}): MockAccount {
  const at = nowIso()
  return {
    staff_id: `s_${username}`, username, display_name: display, roles, status: 'active', locked: false, locked_until: null,
    failed_logins: 0, mfa_enabled: false, must_change_password: false, created_at: at, updated_at: at,
    password_changed_at: at, last_login_at: null, password: null, pending_secret: null, session_epoch: 0, ...extra,
  }
}

function freshState(): MockState {
  return {
    accounts: [
      demoAccount('ada', 'Ada Admin', ['admin'], { mfa_enabled: true }),
      demoAccount('olivia', 'Olivia Officer', ['security_officer']),
      demoAccount('emma', 'Emma Enroller', ['enroller']),
      demoAccount('audra', 'Audra Auditor', ['auditor']),
      demoAccount('evan', 'Evan Evaluator', ['evaluator']),
      demoAccount('nina', 'Nina New', ['enroller'], { must_change_password: true }),
    ],
    sessions: [], keys: [], audit: [], seq: 0, tickets: [], throttle: {},
  }
}

/** Demo usernames for the SIMULATED login hint. */
export const MOCK_DEMO_USERS: ReadonlyArray<{ username: string; roles: string }> = [
  { username: 'ada', roles: 'admin (MFA 123456)' },
  { username: 'olivia', roles: 'security_officer (MFA enrolment)' },
  { username: 'emma', roles: 'enroller' },
  { username: 'audra', roles: 'auditor' },
  { username: 'evan', roles: 'evaluator' },
  { username: 'nina', roles: 'enroller (must change password)' },
]

const err = (status: number, code: string, message: string, extra: Record<string, unknown> = {}) =>
  new ApiError(code, status, message, null, { reason: (extra.reason as string | undefined) ?? null, ...extra })

function publicAccount(a: MockAccount): StaffAccount {
  const rest: Partial<MockAccount> = { ...a }
  delete rest.password
  delete rest.pending_secret
  delete rest.session_epoch
  return rest as StaffAccount
}

export class MockAuth {
  private load(): MockState {
    try {
      const raw = window.sessionStorage.getItem(STORAGE_KEY)
      if (raw) return JSON.parse(raw) as MockState
    } catch {
      /* corrupt / unavailable: start fresh */
    }
    return freshState()
  }

  private save(s: MockState): void {
    try {
      window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(s))
    } catch {
      /* ignore */
    }
  }

  /** Apply fn to a copy of the state, persist it, return fn's result. */
  private update<T>(fn: (s: MockState) => T): T {
    const s = this.load()
    const out = fn(s)
    this.save(s)
    return out
  }

  private audit(s: MockState, actor: Principal | null, action: string, target: string | null, outcome: string, detail: Record<string, unknown> | null = null): void {
    s.seq += 1
    const entry: AuthAuditEntry = {
      seq: s.seq, ts_utc: nowIso(),
      actor: actor ? { kind: actor.kind, id: actor.id, username: actor.username } : { kind: 'anonymous', id: null, username: null },
      action, target, outcome, client_ip: '127.0.0.1', detail, count: null,
    }
    s.audit = [entry, ...s.audit].slice(0, 500)
  }

  private principalOf(a: MockAccount): Principal {
    return {
      kind: 'staff', id: a.staff_id, staff_id: a.staff_id, actor_id: `staff:${a.staff_id}`, username: a.username,
      display_name: a.display_name, roles: [...a.roles], permissions: permsFor(a.roles),
      must_change_password: a.must_change_password,
      mfa_enrolment_required: !a.mfa_enabled && a.roles.some((r) => MFA_REQUIRED_ROLES.includes(r)),
      mfa_enabled: a.mfa_enabled,
    }
  }

  private keyPrincipal(k: MockKey): Principal {
    const permissions = permsFor(k.info.roles).filter((p) => !KEY_FORBIDDEN.includes(p))
    return {
      kind: 'api_key', id: k.info.key_id, staff_id: null, actor_id: `key:${k.info.key_id}`, username: null,
      display_name: `API key ${k.info.name}`, roles: [...k.info.roles], permissions,
      must_change_password: false, mfa_enrolment_required: false, mfa_enabled: false,
    }
  }

  private fail401(path: string, token: string, reason: string): never {
    const e = err(401, 'UNAUTHORIZED', 'authentication required', { reason })
    // token: lets the auth layer ignore a 401 that belongs to an older, already replaced session
    const info = { path, reason, token }
    if (shouldSignOutOn401(path, token)) notifyUnauthorized(info)
    throw e
  }

  /**
   * Resolve the credential like edge/auth/deps.py. `perm` null = any signed-in principal. `confined` routes
   * (me / logout / activity / password / mfa) stay reachable while a password change or MFA enrolment is pending.
   */
  authenticate(token: string, path: string, perm: string | null, opts: { write?: boolean; confined?: boolean; staffOnly?: boolean } = {}): Principal {
    return this.update((s) => {
      const now = Date.now()
      if (!token) this.fail401(path, token, 'CREDENTIAL_INVALID')
      let principal: Principal
      if (token.startsWith('fgk_')) {
        const k = s.keys.find((x) => x.token === token)
        const expired = k?.info.expires_at ? Date.parse(k.info.expires_at) <= now : false
        if (!k || k.info.status === 'revoked' || expired) this.fail401(path, token, 'CREDENTIAL_INVALID')
        if (opts.staffOnly) throw err(403, 'FORBIDDEN', 'API keys cannot use this route', { reason: 'MISSING_PERMISSION', required: perm ? [perm] : [] })
        k.info.last_used_at = nowIso()
        principal = this.keyPrincipal(k)
      } else {
        const sess = s.sessions.find((x) => x.token === token)
        if (!sess) this.fail401(path, token, token.startsWith('fgs_') ? 'SESSION_EXPIRED' : 'CREDENTIAL_INVALID')
        const acct = s.accounts.find((a) => a.staff_id === sess.staff_id)
        const idle = now - sess.last_seen > IDLE_MS
        const tooOld = now - sess.created > MAX_SESSION_MS
        if (!acct || acct.status !== 'active' || acct.session_epoch !== sess.epoch || idle || tooOld) {
          s.sessions = s.sessions.filter((x) => x.token !== token)
          this.save(s)
          this.fail401(path, token, 'SESSION_EXPIRED')
        }
        if (opts.write || isUserInitiated(now)) sess.last_seen = now
        principal = this.principalOf(acct)
        if (!opts.confined) {
          if (principal.must_change_password) throw err(403, 'FORBIDDEN', 'change your password first', { reason: 'PASSWORD_CHANGE_REQUIRED' })
          if (principal.mfa_enrolment_required) throw err(403, 'FORBIDDEN', 'set up MFA first', { reason: 'MFA_ENROLMENT_REQUIRED' })
        }
      }
      if (perm && !principal.permissions.includes(perm)) {
        this.audit(s, principal, 'auth.denied', path, 'denied', { reason: 'MISSING_PERMISSION', required: [perm] })
        this.save(s)
        throw err(403, 'FORBIDDEN', `missing permission ${perm}`, { reason: 'MISSING_PERMISSION', required: [perm] })
      }
      return principal
    })
  }

  status(): AuthStatus {
    return { store: 'OK', accounts_exist: true, legacy_token_enabled: false, mfa_required_roles: [...MFA_REQUIRED_ROLES] }
  }

  login(req: LoginRequest): LoginResult {
    return this.update((s) => {
      const now = Date.now()
      let acct: MockAccount | undefined
      if ('mfa_ticket' in req) {
        const t = s.tickets.find((x) => x.ticket === req.mfa_ticket && x.exp > now)
        s.tickets = s.tickets.filter((x) => x.ticket !== req.mfa_ticket) // single use, even when the code is wrong
        if (!t) {
          this.save(s)
          throw err(401, 'UNAUTHORIZED', 'sign-in step expired, enter your password again', { reason: 'MFA_INVALID' })
        }
        acct = s.accounts.find((a) => a.staff_id === t.staff_id)
        // edge login.py _login_with_ticket: disabled / epoch bumped since the password step -> INVALID_CREDENTIALS
        if (!acct || acct.status !== 'active' || acct.session_epoch !== (t.epoch ?? -1)) {
          this.save(s)
          throw err(401, 'UNAUTHORIZED', 'invalid username or password', { reason: 'INVALID_CREDENTIALS' })
        }
        if (req.totp_code !== MOCK_TOTP_CODE) {
          this.audit(s, null, 'auth.login', acct.staff_id, 'denied', { reason: 'MFA_INVALID' })
          this.save(s)
          throw err(401, 'UNAUTHORIZED', 'authenticator code is not valid', { reason: 'MFA_INVALID' })
        }
      } else {
        const uname = req.username.trim().toLowerCase()
        const th = s.throttle[uname] ?? { failures: 0, until: 0 }
        acct = s.accounts.find((a) => a.username === uname)
        const okPassword = !!acct && !!req.password && req.password !== REJECTED_PASSWORD && (acct.password === null || acct.password === req.password)
        // edge: a correct password + a valid TOTP bypasses the soft delay for MFA accounts
        const mfaBypass = okPassword && !!acct?.mfa_enabled && req.totp_code === MOCK_TOTP_CODE
        if (th.until > now && !mfaBypass) {
          const retry = Math.max(1, Math.ceil((th.until - now) / 1000))
          throw err(429, 'RATE_LIMITED', 'too many sign-in attempts, try again later', { retry_after_s: retry })
        }
        if (!acct || !okPassword) {
          const failures = th.failures + 1
          const delay = failures > FREE_FAILURES ? Math.min(2 ** (failures - FREE_FAILURES), MAX_DELAY_S) : 0
          s.throttle[uname] = { failures, until: delay ? now + delay * 1000 : 0 }
          this.audit(s, null, 'auth.login', acct?.staff_id ?? null, 'denied', { reason: 'INVALID_CREDENTIALS' })
          this.save(s)
          throw err(401, 'UNAUTHORIZED', 'invalid username or password', { reason: 'INVALID_CREDENTIALS' })
        }
        s.throttle[uname] = { failures: 0, until: 0 }
        if (acct.status !== 'active') throw err(401, 'UNAUTHORIZED', 'account disabled', { reason: 'ACCOUNT_DISABLED' })
        if (acct.mfa_enabled && req.totp_code !== MOCK_TOTP_CODE) {
          if (req.totp_code) throw err(401, 'UNAUTHORIZED', 'authenticator code is not valid', { reason: 'MFA_INVALID' })
          const ticket = `mt_${randomToken(12)}`
          s.tickets = [...s.tickets.filter((x) => x.exp > now), { ticket, staff_id: acct.staff_id, exp: now + TICKET_MS, epoch: acct.session_epoch }]
          this.save(s)
          throw err(401, 'UNAUTHORIZED', 'authenticator code required', { reason: 'MFA_REQUIRED', mfa_ticket: ticket })
        }
      }
      const token = `fgs_${randomToken(32)}`
      s.sessions = [...s.sessions, { token, staff_id: acct.staff_id, epoch: acct.session_epoch, created: now, last_seen: now }]
      acct.last_login_at = nowIso()
      const principal = this.principalOf(acct)
      this.audit(s, principal, 'auth.login', acct.staff_id, 'ok')
      return { token, token_type: 'Bearer', expires_at: new Date(now + MAX_SESSION_MS).toISOString(), idle_timeout_s: IDLE_MS / 1000, principal }
    })
  }

  logout(token: string): void {
    this.update((s) => {
      const sess = s.sessions.find((x) => x.token === token)
      s.sessions = s.sessions.filter((x) => x.token !== token)
      if (sess) this.audit(s, null, 'auth.logout', sess.staff_id, 'ok')
    })
  }

  me(token: string): AuthMe {
    const principal = this.authenticate(token, '/v1/auth/me', null, { confined: true })
    const sess = this.load().sessions.find((x) => x.token === token)
    return {
      principal,
      session: sess ? { session_id: sess.token.slice(4, 12), expires_at: new Date(sess.created + MAX_SESSION_MS).toISOString(), idle_timeout_s: IDLE_MS / 1000 } : null,
    }
  }

  activity(token: string): void {
    this.authenticate(token, '/v1/auth/activity', null, { write: true, confined: true })
  }

  private checkReauth(s: MockState, actor: Principal, password: string): MockAccount {
    const me = s.accounts.find((a) => a.staff_id === actor.staff_id)
    const ok = !!me && !!password && password !== REJECTED_PASSWORD && (me.password === null || me.password === password)
    if (!me || !ok) throw err(403, 'FORBIDDEN', 'password not accepted', { reason: 'REAUTH_REQUIRED' })
    return me
  }

  /** edge/auth/passwords.py check_policy (without the deny list) -> 422 PASSWORD_POLICY with `problems`. */
  private checkPolicy(password: string, username: string): void {
    const problems = passwordPolicyProblems(password, username)
    if (problems.length) throw err(422, 'VALIDATION_ERROR', 'the password does not meet the policy', { reason: 'PASSWORD_POLICY', problems })
  }

  changePassword(token: string, req: PasswordChange): void {
    const actor = this.authenticate(token, '/v1/auth/password', null, { write: true, confined: true, staffOnly: true })
    this.update((s) => {
      // same order as edge service.change_password: policy, must differ, then re-auth
      const username = s.accounts.find((a) => a.staff_id === actor.staff_id)?.username ?? ''
      this.checkPolicy(req.new_password, username)
      if (req.new_password === req.current_password) throw err(422, 'VALIDATION_ERROR', 'choose a new password', { reason: 'PASSWORD_POLICY', problems: ['the new password must differ from the current one'] })
      const me = this.checkReauth(s, actor, req.current_password)
      me.password = req.new_password
      me.must_change_password = false
      me.password_changed_at = nowIso()
      me.session_epoch += 1
      // keep THIS session, drop the others (edge: revokes other sessions)
      s.sessions = s.sessions.filter((x) => x.staff_id !== me.staff_id || x.token === token).map((x) => (x.token === token ? { ...x, epoch: me.session_epoch } : x))
      this.audit(s, actor, 'auth.password_change', me.staff_id, 'ok')
    })
  }

  mfaEnroll(token: string, currentPassword: string): MfaEnrolment {
    const actor = this.authenticate(token, '/v1/auth/mfa/enroll', null, { write: true, confined: true, staffOnly: true })
    // like the edge (review F6): current_password is required; missing -> 422, wrong -> 403 REAUTH_REQUIRED
    if (typeof currentPassword !== 'string' || !currentPassword) throw err(422, 'VALIDATION_ERROR', 'current_password is required')
    return this.update((s) => {
      const me = this.checkReauth(s, actor, currentPassword)
      if (me.mfa_enabled) throw err(409, 'INVALID_STATE', 'MFA already enabled', { reason: 'MFA_ALREADY_ENABLED' })
      me.pending_secret = MOCK_SECRET
      return { secret: MOCK_SECRET, otpauth_uri: `otpauth://totp/FaceGuard%20(SIMULATED):${me.username}?secret=${MOCK_SECRET}&issuer=FaceGuard` }
    })
  }

  mfaConfirm(token: string, code: string): void {
    const actor = this.authenticate(token, '/v1/auth/mfa/confirm', null, { write: true, confined: true, staffOnly: true })
    this.update((s) => {
      const me = s.accounts.find((a) => a.staff_id === actor.staff_id)
      if (!me?.pending_secret) throw err(409, 'INVALID_STATE', 'no MFA enrolment in progress', { reason: 'MFA_NOT_PENDING' })
      if (code !== MOCK_TOTP_CODE) throw err(422, 'VALIDATION_ERROR', 'the authenticator code is not valid', { reason: 'MFA_INVALID' })
      me.mfa_enabled = true
      me.pending_secret = null
      this.audit(s, actor, 'staff.mfa_enable', me.staff_id, 'ok')
    })
  }

  listStaff(token: string): StaffAccount[] {
    this.authenticate(token, '/v1/admin/staff', 'staff:manage', { staffOnly: true })
    return this.load().accounts.map(publicAccount)
  }

  /** Role ceiling + validation shared by create / update (edge: ROLE_CEILING, INVALID_ROLES). */
  private checkRoles(actor: Principal, roles: string[]): void {
    if (!roles.length || roles.length > AUTH_LIMITS.maxRoles || roles.some((r) => !ROLES[r])) throw err(422, 'VALIDATION_ERROR', 'invalid roles', { reason: 'INVALID_ROLES' })
    if (permsFor(roles).some((p) => !actor.permissions.includes(p))) throw err(403, 'FORBIDDEN', 'you cannot grant more than you hold', { reason: 'ROLE_CEILING' })
  }

  createStaff(token: string, req: StaffCreate): StaffAccount {
    const actor = this.authenticate(token, '/v1/admin/staff', 'staff:manage', { write: true, staffOnly: true })
    return this.update((s) => {
      this.checkReauth(s, actor, req.confirm_password)
      const username = req.username.trim()
      if (!AUTH_LIMITS.usernamePattern.test(username)) throw err(422, 'VALIDATION_ERROR', 'invalid username', { reason: 'INVALID_USERNAME' })
      if ((AUTH_LIMITS.reservedUsernames as readonly string[]).includes(username)) throw err(422, 'VALIDATION_ERROR', 'reserved username', { reason: 'RESERVED_USERNAME' })
      if (s.accounts.some((a) => a.username === username)) throw err(409, 'CONFLICT', 'username taken', { reason: 'USERNAME_TAKEN' })
      this.checkRoles(actor, req.roles)
      this.checkPolicy(req.temporary_password, username)
      const acct = demoAccount(username, req.display_name.trim() || username, [...req.roles].sort(), { password: req.temporary_password, must_change_password: true })
      s.accounts = [...s.accounts, acct]
      this.audit(s, actor, 'staff.create', acct.staff_id, 'ok', { roles: acct.roles })
      return publicAccount(acct)
    })
  }

  updateStaff(token: string, staffId: string, req: StaffUpdate): StaffAccount {
    const actor = this.authenticate(token, `/v1/admin/staff/${staffId}`, 'staff:manage', { write: true, staffOnly: true })
    return this.update((s) => {
      this.checkReauth(s, actor, req.confirm_password)
      const acct = s.accounts.find((a) => a.staff_id === staffId)
      if (!acct) throw err(404, 'NOT_FOUND', 'staff account not found')
      if (staffId === actor.staff_id && (req.roles || req.status)) throw err(403, 'FORBIDDEN', 'you cannot change your own roles or status', { reason: 'SELF_MODIFICATION' })
      if (req.roles) this.checkRoles(actor, req.roles)
      const nextRoles = req.roles ? [...req.roles].sort() : acct.roles
      const nextStatus = req.status ?? acct.status
      const otherAdmins = s.accounts.filter((a) => a.staff_id !== staffId && a.status === 'active' && a.roles.includes('admin'))
      if (acct.roles.includes('admin') && (!nextRoles.includes('admin') || nextStatus !== 'active') && otherAdmins.length === 0) {
        throw err(403, 'FORBIDDEN', 'the last active admin cannot be removed', { reason: 'LAST_ADMIN' })
      }
      const securityChange = !!req.roles || (req.status !== undefined && req.status !== acct.status)
      acct.roles = nextRoles
      acct.status = nextStatus
      if (req.display_name !== undefined) acct.display_name = req.display_name.trim() || acct.display_name
      acct.updated_at = nowIso()
      if (securityChange) acct.session_epoch += 1
      if (nextStatus === 'disabled') {
        s.sessions = s.sessions.filter((x) => x.staff_id !== staffId)
        s.keys = s.keys.map((k) => (k.info.created_by === `staff:${staffId}` && k.info.status === 'active' ? { ...k, info: { ...k.info, status: 'revoked', revoked_at: nowIso() } } : k))
      }
      this.audit(s, actor, 'staff.update', staffId, 'ok', { roles: req.roles ?? null, status: req.status ?? null })
      return publicAccount(acct)
    })
  }

  resetPassword(token: string, staffId: string, req: StaffPasswordReset): void {
    const actor = this.authenticate(token, `/v1/admin/staff/${staffId}/password`, 'staff:manage', { write: true, staffOnly: true })
    this.update((s) => {
      this.checkReauth(s, actor, req.confirm_password)
      const acct = s.accounts.find((a) => a.staff_id === staffId)
      if (!acct) throw err(404, 'NOT_FOUND', 'staff account not found')
      this.checkPolicy(req.temporary_password, acct.username)
      acct.password = req.temporary_password
      acct.must_change_password = true
      acct.session_epoch += 1
      s.sessions = s.sessions.filter((x) => x.staff_id !== staffId)
      this.audit(s, actor, 'staff.password_reset', staffId, 'ok')
    })
  }

  unlock(token: string, staffId: string, req: Reauth): void {
    const actor = this.authenticate(token, `/v1/admin/staff/${staffId}/unlock`, 'staff:manage', { write: true, staffOnly: true })
    this.update((s) => {
      this.checkReauth(s, actor, req.confirm_password)
      const acct = s.accounts.find((a) => a.staff_id === staffId)
      if (!acct) throw err(404, 'NOT_FOUND', 'staff account not found')
      s.throttle[acct.username] = { failures: 0, until: 0 }
      acct.locked = false
      acct.locked_until = null
      acct.failed_logins = 0
      this.audit(s, actor, 'staff.unlock', staffId, 'ok')
    })
  }

  listApiKeys(token: string): ApiKeyInfo[] {
    this.authenticate(token, '/v1/admin/api-keys', 'staff:manage', { staffOnly: true })
    const now = Date.now()
    return this.load().keys.map((k) => ({ ...k.info, status: k.info.status === 'active' && k.info.expires_at && Date.parse(k.info.expires_at) <= now ? 'expired' : k.info.status }))
  }

  createApiKey(token: string, req: ApiKeyCreate): ApiKeyCreated {
    const actor = this.authenticate(token, '/v1/admin/api-keys', 'staff:manage', { write: true, staffOnly: true })
    return this.update((s) => {
      this.checkReauth(s, actor, req.confirm_password)
      if (req.roles.includes('admin')) throw err(422, 'VALIDATION_ERROR', 'role admin cannot be held by an API key', { reason: 'INVALID_ROLES' })
      this.checkRoles(actor, req.roles)
      const days = req.expires_days
      if (!Number.isInteger(days) || days < AUTH_LIMITS.keyExpiresDaysMin || days > AUTH_LIMITS.keyExpiresDaysMax) throw err(422, 'VALIDATION_ERROR', 'expires_days must be 1..90', { reason: 'INVALID_EXPIRY' })
      const keyId = Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) => 'abcdefghijklmnopqrstuvwxyz0123456789'[b % 36]).join('')
      const key = `fgk_${keyId}.${randomToken(32)}`
      const roles = [...req.roles].sort()
      const info: ApiKeyInfo = {
        key_id: keyId, name: req.name.trim(), roles, permissions: permsFor(roles).filter((p) => !KEY_FORBIDDEN.includes(p)), status: 'active',
        created_at: nowIso(), created_by: actor.actor_id, expires_at: new Date(Date.now() + days * 86_400_000).toISOString(), last_used_at: null, revoked_at: null,
      }
      s.keys = [...s.keys, { info, token: key }]
      this.audit(s, actor, 'api_key.create', keyId, 'ok', { roles })
      return { key, item: info }
    })
  }

  revokeApiKey(token: string, keyId: string, req: Reauth): void {
    const actor = this.authenticate(token, `/v1/admin/api-keys/${keyId}`, 'staff:manage', { write: true, staffOnly: true })
    this.update((s) => {
      this.checkReauth(s, actor, req.confirm_password)
      const k = s.keys.find((x) => x.info.key_id === keyId)
      if (!k) throw err(404, 'NOT_FOUND', 'API key not found')
      k.info = { ...k.info, status: 'revoked', revoked_at: nowIso() }
      this.audit(s, actor, 'api_key.revoke', keyId, 'ok')
    })
  }

  roles(token: string): RolesCatalog {
    this.authenticate(token, '/v1/admin/roles', null) // edge: any authenticated principal
    return {
      roles: Object.entries(ROLES).map(([name, r]) => ({ name, description: r.description, permissions: [...r.permissions].sort(), key_allowed: name !== 'admin' })),
      permissions: [...ALL_PERMS].sort(),
      key_forbidden_permissions: [...KEY_FORBIDDEN].sort(),
      max_roles_per_account: AUTH_LIMITS.maxRoles,
    }
  }

  auditPage(token: string, q: AuditQuery = {}): AuthAuditPage {
    this.authenticate(token, '/v1/admin/auth/audit', 'audit:read')
    const limit = Math.min(Math.max(q.limit ?? 100, 1), 500)
    const all = this.load().audit.filter((e) => q.before_seq == null || e.seq < q.before_seq)
    const page = all.slice(0, limit)
    const last = page[page.length - 1]
    return { as_of: nowIso(), count: page.length, items: page, next_before_seq: all.length > limit && last ? last.seq : null }
  }
}
