/**
 * Unit tests for api/authParse.ts (design v2 §C/§F): strict, fail-closed parsing of /v1/auth/* and
 * /v1/admin/{staff,api-keys,roles,auth/audit}. Fixtures are trimmed copies of
 * docs/contracts/admin_access.examples.json `auth_routes` (inlined: the tests import no node: modules).
 */
import { done, eq, ok, test } from '../shared/testkit.ts'
import {
  parseApiKey,
  parseApiKeyCreated,
  parseApiKeyList,
  parseAuthAuditPage,
  parseAuthMe,
  parseAuthStatus,
  parseLoginResult,
  parseMfaEnrolment,
  parsePrincipal,
  parseRolesCatalog,
  parseStaffItem,
  parseStaffList,
} from './authParse.ts'
import { ApiError } from './types.ts'

/** Asserts fn throws ApiError BAD_RESPONSE (the caller then shows an error, never a signed-in UI). */
function rejects(fn: () => unknown, what: string): void {
  try {
    fn()
  } catch (e) {
    ok(e instanceof ApiError, `${what}: expected ApiError, got ${String(e)}`)
    eq((e as ApiError).code, 'BAD_RESPONSE', `${what}: code`)
    return
  }
  throw new Error(`${what}: expected BAD_RESPONSE, parsed instead`)
}

const PERMS = ['access:read', 'audit:read', 'events:read', 'store:read']
const principal = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  kind: 'staff',
  id: 's_guard01',
  staff_id: 's_guard01',
  actor_id: 'staff:s_guard01',
  username: 'guard01',
  display_name: 'Guard One',
  roles: ['security_officer'],
  permissions: PERMS,
  must_change_password: false,
  mfa_enrolment_required: false,
  mfa_enabled: true,
  ...over,
})
const login = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  token: 'fgs_SESSION',
  token_type: 'Bearer',
  expires_at: '2026-11-15T21:00:00Z',
  idle_timeout_s: 1800,
  principal: principal(),
  ...over,
})
const staff = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  staff_id: 's_enrol02',
  username: 'enrol02',
  display_name: 'Desk Two',
  roles: ['enroller'],
  status: 'active',
  locked: false,
  locked_until: null,
  failed_logins: 0,
  mfa_enabled: false,
  must_change_password: true,
  created_at: '2026-11-15T09:00:00Z',
  updated_at: '2026-11-15T09:00:00Z',
  password_changed_at: '2026-11-15T09:00:00Z',
  last_login_at: null,
  ...over,
})
const apiKey = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  key_id: 'k7q2m9x1',
  name: 'eval capture',
  roles: ['evaluator'],
  permissions: ['events:read', 'metrics:read'],
  status: 'active',
  created_at: '2026-11-15T09:05:00Z',
  created_by: 'staff:s_admin01',
  expires_at: '2026-12-15T09:05:00Z',
  last_used_at: null,
  revoked_at: null,
  ...over,
})

// ---------------------------------------------------------------- /v1/auth/status

test('status: contract fixtures parse as-is', () => {
  eq(
    parseAuthStatus({ store: 'EMPTY', accounts_exist: false, legacy_token_enabled: false, mfa_required_roles: ['admin', 'security_officer'] }),
    { store: 'EMPTY', accounts_exist: false, legacy_token_enabled: false, mfa_required_roles: ['admin', 'security_officer'] },
    'bootstrap_empty',
  )
  eq(parseAuthStatus({ store: 'OK', accounts_exist: true }).store, 'OK', 'ok')
  eq(parseAuthStatus({ store: 'MISSING' }).store, 'MISSING', 'missing')
})
test('status: an unknown or missing store state is UNAVAILABLE (no bootstrap hint)', () => {
  eq(parseAuthStatus({ store: 'BOOTSTRAP' }).store, 'UNAVAILABLE', 'unknown')
  eq(parseAuthStatus({ store: 'empty' }).store, 'UNAVAILABLE', 'wrong case')
  eq(parseAuthStatus({}).store, 'UNAVAILABLE', 'missing')
  eq(parseAuthStatus({ store: 3 }).store, 'UNAVAILABLE', 'number')
})
test('status: booleans are true only when literally true; junk roles dropped', () => {
  const s = parseAuthStatus({ store: 'OK', accounts_exist: 'yes', legacy_token_enabled: 1, mfa_required_roles: ['admin', 7, null] })
  eq(s.accounts_exist, false, 'accounts_exist')
  eq(s.legacy_token_enabled, false, 'legacy_token_enabled')
  eq(s.mfa_required_roles, ['admin'], 'mfa_required_roles')
})
test('status: a non-object body is rejected', () => {
  rejects(() => parseAuthStatus(null), 'null')
  rejects(() => parseAuthStatus([]), 'array')
  rejects(() => parseAuthStatus('OK'), 'string')
})

// ---------------------------------------------------------------- principal / me

test('principal: the contract fixture parses with exactly its permissions', () => {
  const p = parsePrincipal(principal())
  eq(p.kind, 'staff', 'kind')
  eq(p.permissions, PERMS, 'permissions')
  eq(p.roles, ['security_officer'], 'roles')
  eq(p.mfa_enabled, true, 'mfa_enabled')
})
test('principal: permissions are never invented from roles (missing list rejected)', () => {
  const { permissions: _drop, ...noPerms } = principal({ roles: ['admin'] })
  rejects(() => parsePrincipal(noPerms), 'missing permissions')
  rejects(() => parsePrincipal(principal({ permissions: 'staff:manage' })), 'string instead of list')
  rejects(() => parsePrincipal(principal({ permissions: ['access:read', 1] })), 'mixed list')
  rejects(() => parsePrincipal(principal({ permissions: null })), 'null')
})
test('principal: an empty permission list stays empty even for an admin role', () => {
  eq(parsePrincipal(principal({ roles: ['admin'], permissions: [] })).permissions, [], 'empty')
})
test('principal: unknown kind, missing id or missing roles is rejected', () => {
  rejects(() => parsePrincipal(principal({ kind: 'superuser' })), 'unknown kind')
  rejects(() => parsePrincipal(principal({ kind: undefined })), 'missing kind')
  rejects(() => parsePrincipal(principal({ id: '' })), 'empty id')
  rejects(() => parsePrincipal(principal({ roles: undefined })), 'missing roles')
})
test('principal: returned lists are copies (mutating the body cannot grant permissions later)', () => {
  const body = principal({ permissions: ['access:read'] })
  const p = parsePrincipal(body)
  ;(body.permissions as string[]).push('staff:manage')
  eq(p.permissions, ['access:read'], 'permissions')
})
test('principal: staff_id falls back to id only for staff; display name falls back to username, then id', () => {
  eq(parsePrincipal(principal({ staff_id: undefined })).staff_id, 's_guard01', 'staff')
  eq(parsePrincipal(principal({ kind: 'api_key', id: 'k1', staff_id: undefined })).staff_id, null, 'api_key')
  eq(parsePrincipal(principal({ display_name: '' })).display_name, 'guard01', 'username')
  eq(parsePrincipal(principal({ display_name: null, username: null })).display_name, 's_guard01', 'id')
})
test('principal: `mfa_setup_required` (older edge builds) is accepted as mfa_enrolment_required', () => {
  eq(parsePrincipal(principal({ mfa_enrolment_required: undefined, mfa_setup_required: true })).mfa_enrolment_required, true, 'alias')
  eq(parsePrincipal(principal({ mfa_enrolment_required: undefined })).mfa_enrolment_required, false, 'absent')
  eq(parsePrincipal(principal({ must_change_password: 'true' })).must_change_password, false, 'string is not true')
})
test('me: principal + session; a missing session is null, a missing principal is rejected', () => {
  const me = parseAuthMe({ principal: principal(), session: { session_id: 'x1', expires_at: '2026-11-15T21:00:00Z', idle_timeout_s: 1800 } })
  eq(me.session, { session_id: 'x1', expires_at: '2026-11-15T21:00:00Z', idle_timeout_s: 1800 }, 'session')
  eq(parseAuthMe({ principal: principal() }).session, null, 'no session')
  rejects(() => parseAuthMe({ session: {} }), 'no principal')
})

// ---------------------------------------------------------------- login

test('login: contract fixture parses; token_type is always Bearer', () => {
  const r = parseLoginResult(login({ token_type: 'Basic' }))
  eq(r.token, 'fgs_SESSION', 'token')
  eq(r.token_type, 'Bearer', 'token_type')
  eq(r.idle_timeout_s, 1800, 'idle')
  eq(r.principal.permissions, PERMS, 'permissions')
})
test('login: a non-fgs_ token is rejected (an API key or legacy token is never a session)', () => {
  rejects(() => parseLoginResult(login({ token: 'fgk_k7q2m9x1.secret' })), 'fgk_ key')
  rejects(() => parseLoginResult(login({ token: 'legacy-token' })), 'legacy')
  rejects(() => parseLoginResult(login({ token: 'FGS_upper' })), 'wrong case')
  rejects(() => parseLoginResult(login({ token: '' })), 'empty')
  rejects(() => parseLoginResult(login({ token: undefined })), 'missing')
})
test('login: a bad principal rejects the whole login', () => {
  rejects(() => parseLoginResult(login({ principal: undefined })), 'missing principal')
  rejects(() => parseLoginResult(login({ principal: principal({ permissions: undefined }) })), 'no permissions')
})
test('login: non-finite numbers become null', () => {
  eq(parseLoginResult(login({ idle_timeout_s: Number.NaN })).idle_timeout_s, null, 'NaN')
  eq(parseLoginResult(login({ idle_timeout_s: '1800' })).idle_timeout_s, null, 'string')
})

// ---------------------------------------------------------------- MFA enrolment

test('mfa enroll: contract fixture parses', () => {
  const uri = 'otpauth://totp/FaceGuard:guard01?secret=JBSWY3DPEHPK3PXP&issuer=FaceGuard'
  eq(parseMfaEnrolment({ secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: uri }), { secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: uri }, 'enrolment')
})
test('mfa enroll: a non-otpauth URI is rejected (no javascript:/https: links shown as the secret)', () => {
  rejects(() => parseMfaEnrolment({ secret: 'S', otpauth_uri: 'javascript:alert(1)' }), 'javascript:')
  rejects(() => parseMfaEnrolment({ secret: 'S', otpauth_uri: 'https://evil.example/otpauth://' }), 'https:')
  rejects(() => parseMfaEnrolment({ secret: 'S', otpauth_uri: 'OTPAUTH://totp/x' }), 'wrong case')
  rejects(() => parseMfaEnrolment({ secret: '', otpauth_uri: 'otpauth://totp/x' }), 'empty secret')
  rejects(() => parseMfaEnrolment({ secret: 'S' }), 'missing uri')
})

// ---------------------------------------------------------------- staff

test('staff list: {items} contract, bare array, {staff} and {accounts} variants', () => {
  const expected = parseStaffList({ items: [staff()] })
  eq(expected.length, 1, 'items length')
  eq(expected[0]?.username, 'enrol02', 'username')
  eq(parseStaffList([staff()]), expected, 'bare array')
  eq(parseStaffList({ staff: [staff()] }), expected, '{staff}')
  eq(parseStaffList({ accounts: [staff()] }), expected, '{accounts}')
  eq(parseStaffList({ items: [] }), [], 'empty')
})
test('staff list: no array, or one bad row, rejects the whole list', () => {
  rejects(() => parseStaffList({}), 'no array')
  rejects(() => parseStaffList({ items: 'x' }), 'string')
  rejects(() => parseStaffList({ items: [staff(), staff({ status: 'superuser' })] }), 'bad second row')
})
test('staff: an unknown status is rejected (never shown as active)', () => {
  rejects(() => parseStaffList([staff({ status: 'enabled' })]), 'enabled')
  rejects(() => parseStaffList([staff({ status: undefined })]), 'missing')
  eq(parseStaffList([staff({ status: 'disabled' })])[0]?.status, 'disabled', 'disabled ok')
})
test('staff: roles must be a string list; locked only when literally true', () => {
  rejects(() => parseStaffList([staff({ roles: 'admin' })]), 'roles string')
  eq(parseStaffList([staff({ locked: 'yes' })])[0]?.locked, false, 'locked')
  eq(parseStaffList([staff({ failed_logins: undefined })])[0]?.failed_logins, 0, 'failed_logins default')
})
test('staff item: {item}, bare object, and 204 null', () => {
  eq(parseStaffItem({ item: staff() })?.staff_id, 's_enrol02', '{item}')
  eq(parseStaffItem(staff())?.staff_id, 's_enrol02', 'bare')
  eq(parseStaffItem(null), null, 'null')
  eq(parseStaffItem(undefined), null, 'undefined')
  rejects(() => parseStaffItem({ item: staff({ username: '' }) }), 'bad item')
})

// ---------------------------------------------------------------- API keys

test('api keys: contract list parses; {api_keys}/{keys}/bare array variants', () => {
  const expected = parseApiKeyList({ items: [apiKey()] })
  eq(expected[0]?.status, 'active', 'status')
  eq(expected[0]?.permissions, ['events:read', 'metrics:read'], 'permissions')
  eq(parseApiKeyList([apiKey()]), expected, 'bare')
  eq(parseApiKeyList({ api_keys: [apiKey()] }), expected, '{api_keys}')
  eq(parseApiKeyList({ keys: [apiKey()] }), expected, '{keys}')
})
test('api key: an unknown status becomes revoked (never shown as usable)', () => {
  for (const s of ['enabled', 'ACTIVE', '', undefined, 1]) eq(parseApiKey(apiKey({ status: s })).status, 'revoked', `status ${String(s)}`)
  eq(parseApiKey(apiKey({ status: 'expired' })).status, 'expired', 'expired kept')
})
test('api key: a single `role` (early edge builds) becomes a one-element roles list', () => {
  eq(parseApiKey(apiKey({ roles: undefined, role: 'evaluator' })).roles, ['evaluator'], 'role')
  rejects(() => parseApiKey(apiKey({ roles: undefined })), 'neither roles nor role')
  rejects(() => parseApiKey(apiKey({ roles: ['ok', 2] })), 'mixed roles')
})
test('api key: missing permissions are an empty list, never derived from roles', () => {
  eq(parseApiKey(apiKey({ roles: ['admin'], permissions: undefined })).permissions, [], 'empty')
  rejects(() => parseApiKey(apiKey({ permissions: ['a', null] })), 'mixed permissions')
})
test('api key create: fgk_ key + item (also `api_key`) parses', () => {
  const r = parseApiKeyCreated({ key: 'fgk_k7q2m9x1.SECRET', item: apiKey() })
  eq(r.key, 'fgk_k7q2m9x1.SECRET', 'key')
  eq(r.item.key_id, 'k7q2m9x1', 'item')
  eq(parseApiKeyCreated({ key: 'fgk_x', api_key: apiKey() }).item.key_id, 'k7q2m9x1', 'api_key alias')
})
test('api key create: a non-fgk_ key is rejected (a session token is never shown as a key)', () => {
  rejects(() => parseApiKeyCreated({ key: 'fgs_SESSION', item: apiKey() }), 'fgs_')
  rejects(() => parseApiKeyCreated({ key: 'k7q2m9x1.SECRET', item: apiKey() }), 'no prefix')
  rejects(() => parseApiKeyCreated({ key: '', item: apiKey() }), 'empty')
  rejects(() => parseApiKeyCreated({ key: 'fgk_x' }), 'missing item')
})

// ---------------------------------------------------------------- roles catalog

const roleRow = { name: 'enroller', description: 'Registers faces.', permissions: ['access:read', 'enrol:write'], key_allowed: true }

test('roles: contract catalog parses', () => {
  const c = parseRolesCatalog({ roles: [roleRow], permissions: ['access:read', 'enrol:write'], key_forbidden_permissions: ['staff:manage'], max_roles_per_account: 3 })
  eq(c.roles, [roleRow], 'roles')
  eq(c.key_forbidden_permissions, ['staff:manage'], 'key forbidden')
  eq(c.max_roles_per_account, 3, 'max')
})
test('roles: a bare array is accepted; the permission list is the sorted union of role permissions', () => {
  const c = parseRolesCatalog([roleRow, { name: 'viewer', permissions: ['metrics:read', 'access:read'] }])
  eq(c.permissions, ['access:read', 'enrol:write', 'metrics:read'], 'union')
  eq(c.roles[1]?.key_allowed, false, 'key_allowed defaults to false')
  eq(c.key_forbidden_permissions, [], 'no forbidden list')
  eq(c.max_roles_per_account, 3, 'default max')
})
test('roles: a role without a permission list, or without a name, is rejected', () => {
  rejects(() => parseRolesCatalog({ roles: [{ name: 'admin' }] }), 'no permissions')
  rejects(() => parseRolesCatalog({ roles: [{ permissions: [] }] }), 'no name')
  rejects(() => parseRolesCatalog({}), 'no roles')
})

// ---------------------------------------------------------------- auth audit

test('audit: contract page parses, including the aggregated denial line', () => {
  const page = parseAuthAuditPage({
    as_of: '2026-11-15T10:00:00Z',
    count: 2,
    items: [
      { seq: 42, ts_utc: '2026-11-15T09:59:00Z', actor: { kind: 'staff', id: 's_admin01', username: 'admin01' }, action: 'staff.create', target: 's_enrol02', outcome: 'ok', client_ip: '127.0.0.1', detail: null, count: null },
      { seq: 41, ts_utc: '2026-11-15T09:58:00Z', actor: { kind: 'staff', id: 's_enrol02', username: 'enrol02' }, action: 'auth.denied', target: 'POST /v1/admin/access/users/{user_id}/revoke', outcome: 'denied', client_ip: '127.0.0.1', detail: { reason: 'MISSING_PERMISSION', required: ['access:revoke'] }, count: 3 },
    ],
    next_before_seq: 41,
  })
  eq(page.count, 2, 'count')
  eq(page.next_before_seq, 41, 'cursor')
  eq(page.items[1]?.count, 3, 'aggregated count')
  eq(page.items[1]?.detail, { reason: 'MISSING_PERMISSION', required: ['access:revoke'] }, 'detail')
})
test('audit: `entries` alias; missing actor/action/outcome get explicit unknown placeholders', () => {
  const page = parseAuthAuditPage({ entries: [{ seq: 1 }] })
  eq(page.count, 1, 'count defaults to item count')
  eq(page.items[0]?.actor, { kind: 'unknown', id: null, username: null }, 'actor')
  eq(page.items[0]?.action, '(unknown)', 'action')
  eq(page.items[0]?.outcome, 'unknown', 'outcome')
  eq(page.next_before_seq, null, 'no cursor')
})
test('audit: a line without a numeric seq, or no item list, is rejected', () => {
  rejects(() => parseAuthAuditPage({ items: [{ action: 'x' }] }), 'no seq')
  rejects(() => parseAuthAuditPage({ items: [{ seq: '42' }] }), 'string seq')
  rejects(() => parseAuthAuditPage({ as_of: 'x' }), 'no items')
})

done('authParse.test.ts')
