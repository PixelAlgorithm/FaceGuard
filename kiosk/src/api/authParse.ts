/**
 * Parsers for the edge auth / staff routes (types in authTypes.ts). Fields that drive security decisions
 * in the UI (token, principal.permissions, roles) are strict: missing or mistyped -> ApiError BAD_RESPONSE.
 * Informational fields (timestamps, descriptions) default to null / ''. Permissions are never invented:
 * an unknown principal shape yields NO permissions (fail-closed).
 *
 * Imports carry explicit `.ts` extensions so Node can run this module directly (contract test).
 */
import type {
  ApiKeyCreated,
  ApiKeyInfo,
  ApiKeyStatus,
  AuthAuditEntry,
  AuthAuditPage,
  AuthMe,
  AuthStatus,
  AuthStoreState,
  LoginResult,
  MfaEnrolment,
  Principal,
  PrincipalKind,
  RoleInfo,
  RolesCatalog,
  SessionInfo,
  StaffAccount,
} from './authTypes.ts'
import { ApiError } from './types.ts'

type Obj = Record<string, unknown>

const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v)

function bad(where: string, what: string): never {
  throw new ApiError('BAD_RESPONSE', 200, `${where}: ${what}`)
}

function obj(v: unknown, where: string): Obj {
  return isObj(v) ? v : bad(where, 'expected an object')
}

function str(o: Obj, k: string, where: string): string {
  const v = o[k]
  return typeof v === 'string' && v.length > 0 ? v : bad(`${where}.${k}`, 'expected a non-empty string')
}

const strN = (o: Obj, k: string): string | null => (typeof o[k] === 'string' ? (o[k] as string) : null)
const numN = (o: Obj, k: string): number | null => (typeof o[k] === 'number' && Number.isFinite(o[k]) ? (o[k] as number) : null)
const bool = (o: Obj, k: string): boolean => o[k] === true

function strList(o: Obj, k: string, where: string): string[] {
  const v = o[k]
  if (!Array.isArray(v) || !v.every((x) => typeof x === 'string')) bad(`${where}.${k}`, 'expected a string array')
  return [...(v as string[])]
}

/** Items of a list response: {items:[...]} (contract), or a bare array / {staff} / {accounts} (tolerated). */
function items(raw: unknown, where: string, alt: string[] = []): unknown[] {
  if (Array.isArray(raw)) return raw
  const o = obj(raw, where)
  for (const k of ['items', ...alt]) if (Array.isArray(o[k])) return o[k] as unknown[]
  return bad(`${where}.items`, 'expected an array')
}

const STORE_STATES: readonly AuthStoreState[] = ['OK', 'EMPTY', 'MISSING', 'UNAVAILABLE']
const KINDS: readonly PrincipalKind[] = ['staff', 'api_key', 'legacy', 'cli']
const KEY_STATUSES: readonly ApiKeyStatus[] = ['active', 'expired', 'revoked']

export function parseAuthStatus(raw: unknown): AuthStatus {
  const o = obj(raw, 'auth.status')
  const store = strN(o, 'store')
  return {
    // An unknown store state is shown as UNAVAILABLE (fail-closed: no "create the first admin" hint).
    store: store && (STORE_STATES as readonly string[]).includes(store) ? (store as AuthStoreState) : 'UNAVAILABLE',
    accounts_exist: bool(o, 'accounts_exist'),
    legacy_token_enabled: bool(o, 'legacy_token_enabled'),
    mfa_required_roles: Array.isArray(o.mfa_required_roles) ? o.mfa_required_roles.filter((x): x is string => typeof x === 'string') : [],
  }
}

export function parsePrincipal(raw: unknown, where = 'principal'): Principal {
  const o = obj(raw, where)
  const kind = strN(o, 'kind')
  if (!kind || !(KINDS as readonly string[]).includes(kind)) bad(`${where}.kind`, `unknown principal kind ${String(kind)}`)
  const id = str(o, 'id', where)
  const username = strN(o, 'username')
  return {
    kind: kind as PrincipalKind,
    id,
    staff_id: strN(o, 'staff_id') ?? (kind === 'staff' ? id : null),
    actor_id: strN(o, 'actor_id'),
    username,
    display_name: strN(o, 'display_name') || username || id,
    roles: strList(o, 'roles', where),
    permissions: strList(o, 'permissions', where),
    must_change_password: bool(o, 'must_change_password'),
    // older edge builds called it mfa_setup_required
    mfa_enrolment_required: bool(o, 'mfa_enrolment_required') || bool(o, 'mfa_setup_required'),
    mfa_enabled: bool(o, 'mfa_enabled'),
  }
}

function parseSession(raw: unknown): SessionInfo | null {
  if (!isObj(raw)) return null
  return { session_id: strN(raw, 'session_id'), expires_at: strN(raw, 'expires_at'), idle_timeout_s: numN(raw, 'idle_timeout_s') }
}

export function parseAuthMe(raw: unknown): AuthMe {
  const o = obj(raw, 'auth.me')
  return { principal: parsePrincipal(o.principal, 'auth.me.principal'), session: parseSession(o.session) }
}

export function parseLoginResult(raw: unknown): LoginResult {
  const o = obj(raw, 'auth.login')
  const token = str(o, 'token', 'auth.login')
  if (!token.startsWith('fgs_')) bad('auth.login.token', 'expected an fgs_ session token')
  return {
    token,
    token_type: 'Bearer',
    expires_at: strN(o, 'expires_at'),
    idle_timeout_s: numN(o, 'idle_timeout_s'),
    principal: parsePrincipal(o.principal, 'auth.login.principal'),
  }
}

export function parseMfaEnrolment(raw: unknown): MfaEnrolment {
  const o = obj(raw, 'auth.mfa.enroll')
  const uri = str(o, 'otpauth_uri', 'auth.mfa.enroll')
  if (!uri.startsWith('otpauth://')) bad('auth.mfa.enroll.otpauth_uri', 'expected an otpauth:// URI')
  return { secret: str(o, 'secret', 'auth.mfa.enroll'), otpauth_uri: uri }
}

export function parseStaffAccount(raw: unknown, where = 'staff'): StaffAccount {
  const o = obj(raw, where)
  const status = strN(o, 'status')
  if (status !== 'active' && status !== 'disabled') bad(`${where}.status`, `unknown status ${String(status)}`)
  return {
    staff_id: str(o, 'staff_id', where),
    username: str(o, 'username', where),
    display_name: strN(o, 'display_name') ?? '',
    roles: strList(o, 'roles', where),
    status,
    locked: bool(o, 'locked'),
    locked_until: strN(o, 'locked_until'),
    failed_logins: numN(o, 'failed_logins') ?? 0,
    mfa_enabled: bool(o, 'mfa_enabled'),
    must_change_password: bool(o, 'must_change_password'),
    created_at: strN(o, 'created_at'),
    updated_at: strN(o, 'updated_at'),
    password_changed_at: strN(o, 'password_changed_at'),
    last_login_at: strN(o, 'last_login_at'),
  }
}

export function parseStaffList(raw: unknown): StaffAccount[] {
  return items(raw, 'admin.staff', ['staff', 'accounts']).map((x, i) => parseStaffAccount(x, `admin.staff[${i}]`))
}

/** POST 201 {item} / PATCH 200 {item}; 204 (null body) -> null. */
export function parseStaffItem(raw: unknown): StaffAccount | null {
  if (raw === null || raw === undefined) return null
  const o = obj(raw, 'admin.staff.item')
  return parseStaffAccount(isObj(o.item) ? o.item : o, 'admin.staff.item')
}

export function parseApiKey(raw: unknown, where = 'api_key'): ApiKeyInfo {
  const o = obj(raw, where)
  const status = strN(o, 'status')
  // a single `role` (early edge builds) is accepted as a one-element list
  const roles = Array.isArray(o.roles) ? strList(o, 'roles', where) : typeof o.role === 'string' ? [o.role] : bad(`${where}.roles`, 'expected a string array')
  return {
    key_id: str(o, 'key_id', where),
    name: strN(o, 'name') ?? '',
    roles,
    permissions: Array.isArray(o.permissions) ? strList(o, 'permissions', where) : [],
    // unknown status -> revoked (never show an unknown key as usable)
    status: status && (KEY_STATUSES as readonly string[]).includes(status) ? (status as ApiKeyStatus) : 'revoked',
    created_at: strN(o, 'created_at'),
    created_by: strN(o, 'created_by'),
    expires_at: strN(o, 'expires_at'),
    last_used_at: strN(o, 'last_used_at'),
    revoked_at: strN(o, 'revoked_at'),
  }
}

export function parseApiKeyList(raw: unknown): ApiKeyInfo[] {
  return items(raw, 'admin.api_keys', ['api_keys', 'keys']).map((x, i) => parseApiKey(x, `admin.api_keys[${i}]`))
}

export function parseApiKeyCreated(raw: unknown): ApiKeyCreated {
  const o = obj(raw, 'admin.api_keys.create')
  const key = str(o, 'key', 'admin.api_keys.create')
  if (!key.startsWith('fgk_')) bad('admin.api_keys.create.key', 'expected an fgk_ key')
  const item = o.item ?? o.api_key
  return { key, item: parseApiKey(item, 'admin.api_keys.create.item') }
}

function parseRole(raw: unknown, where: string): RoleInfo {
  const o = obj(raw, where)
  return {
    name: str(o, 'name', where),
    description: strN(o, 'description') ?? '',
    permissions: strList(o, 'permissions', where),
    key_allowed: bool(o, 'key_allowed'),
  }
}

export function parseRolesCatalog(raw: unknown): RolesCatalog {
  const o = Array.isArray(raw) ? { roles: raw } : obj(raw, 'admin.roles')
  if (!Array.isArray(o.roles)) bad('admin.roles.roles', 'expected an array')
  const roles = (o.roles as unknown[]).map((r, i) => parseRole(r, `admin.roles.roles[${i}]`))
  return {
    roles,
    permissions: Array.isArray(o.permissions) ? strList(o, 'permissions', 'admin.roles') : [...new Set(roles.flatMap((r) => r.permissions))].sort(),
    key_forbidden_permissions: Array.isArray(o.key_forbidden_permissions) ? strList(o, 'key_forbidden_permissions', 'admin.roles') : [],
    max_roles_per_account: numN(o, 'max_roles_per_account') ?? 3,
  }
}

function parseAuditEntry(raw: unknown, where: string): AuthAuditEntry {
  const o = obj(raw, where)
  const seq = numN(o, 'seq')
  if (seq === null) bad(`${where}.seq`, 'expected a number')
  const actor = isObj(o.actor) ? o.actor : {}
  return {
    seq,
    ts_utc: strN(o, 'ts_utc'),
    actor: { kind: strN(actor, 'kind') ?? 'unknown', id: strN(actor, 'id'), username: strN(actor, 'username') },
    action: strN(o, 'action') ?? '(unknown)',
    target: strN(o, 'target'),
    outcome: strN(o, 'outcome') ?? 'unknown',
    client_ip: strN(o, 'client_ip'),
    detail: isObj(o.detail) ? o.detail : null,
    count: numN(o, 'count'),
  }
}

export function parseAuthAuditPage(raw: unknown): AuthAuditPage {
  const o = obj(raw, 'admin.auth.audit')
  const list = Array.isArray(o.items) ? o.items : Array.isArray(o.entries) ? o.entries : bad('admin.auth.audit.items', 'expected an array')
  const parsed = (list as unknown[]).map((x, i) => parseAuditEntry(x, `admin.auth.audit.items[${i}]`))
  return { as_of: strN(o, 'as_of'), count: numN(o, 'count') ?? parsed.length, items: parsed, next_before_seq: numN(o, 'next_before_seq') }
}
