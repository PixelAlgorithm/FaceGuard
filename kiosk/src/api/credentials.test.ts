/** Unit tests for api/credentials.ts (design v2 §F: Bearer vs legacy header, X-FG-Activity, 401 sign-out, SSE auth). */
import { done, eq, ok, test } from '../shared/testkit.ts'
import {
  ACTIVITY_HEADER,
  USER_INTENT_WINDOW_MS,
  activityHeaders,
  authHeaders,
  credentialError,
  handleSseAuthEvent,
  isUserInitiated,
  noteUserInput,
  notifyUnauthorized,
  setAuthRecheckHandler,
  setUnauthorizedHandler,
  shouldSignOutOn401,
  type UnauthorizedInfo,
} from './credentials.ts'

const SESSION = 'fgs_abc123'
const API_KEY = 'fgk_k7q2m9x1.secret'
const LEGACY = 'legacy-shared-token'

/** Registers recording handlers, runs fn, then unregisters both (module state is shared across tests). */
function withHandlers(fn: () => void): { signedOut: UnauthorizedInfo[]; rechecks: UnauthorizedInfo[] } {
  const signedOut: UnauthorizedInfo[] = []
  const rechecks: UnauthorizedInfo[] = []
  const offA = setUnauthorizedHandler((i) => signedOut.push(i))
  const offB = setAuthRecheckHandler((i) => rechecks.push(i))
  try {
    fn()
  } finally {
    offA()
    offB()
  }
  return { signedOut, rechecks }
}

// ---------------------------------------------------------------- authHeaders

test('a session token goes in Authorization: Bearer, never in X-Admin-Token', () => {
  eq(authHeaders(SESSION), { Authorization: `Bearer ${SESSION}` }, 'headers')
})
test('an API key goes in Authorization: Bearer', () => {
  eq(authHeaders(API_KEY), { Authorization: `Bearer ${API_KEY}` }, 'headers')
})
test('anything else is the legacy shared token in X-Admin-Token (never Bearer)', () => {
  eq(authHeaders(LEGACY), { 'X-Admin-Token': LEGACY }, 'headers')
  eq(authHeaders('FGS_upper'), { 'X-Admin-Token': 'FGS_upper' }, 'prefix is case-sensitive')
})
test('no token sends no auth header at all', () => {
  eq(authHeaders(''), {}, 'headers')
})

// ---------------------------------------------------------------- credentialError (KAO-12)

test('a clean credential has no error; empty is not an error (signed out)', () => {
  eq(credentialError(SESSION), null, 'session')
  eq(credentialError(API_KEY), null, 'api key')
  eq(credentialError(''), null, 'empty')
})
test('a space, a smart quote or a newline is refused before fetch() can throw', () => {
  ok(credentialError('fgs_abc 123') !== null, 'space')
  ok(credentialError('“fgs_abc”') !== null, 'smart quotes')
  ok(credentialError('fgs_abc\n') !== null, 'trailing newline')
  ok(credentialError('fgs_abé') !== null, 'non-ASCII')
})
test('an over-long credential is refused (512 is the limit)', () => {
  eq(credentialError(`fgs_${'a'.repeat(508)}`), null, '512 chars ok')
  ok(credentialError(`fgs_${'a'.repeat(509)}`) !== null, '513 chars refused')
})

// ---------------------------------------------------------------- activity header

test('every non-GET request carries X-FG-Activity: 1 (any case of the method)', () => {
  noteUserInput(Number.NEGATIVE_INFINITY)
  for (const m of ['POST', 'put', 'Patch', 'DELETE']) eq(activityHeaders(m, 1_000_000), { [ACTIVITY_HEADER]: '1' }, m)
  eq(ACTIVITY_HEADER, 'X-FG-Activity', 'header name')
})
test('a GET poll with no recent input never extends the idle timer', () => {
  noteUserInput(1_000_000)
  eq(activityHeaders('GET', 1_000_000 + USER_INTENT_WINDOW_MS + 1), {}, 'stale input')
  eq(activityHeaders('get', 5_000_000), {}, 'lower-case get')
})
test('a GET right after pointerdown / keydown is user-initiated', () => {
  noteUserInput(2_000_000)
  ok(isUserInitiated(2_000_000), 'same instant')
  ok(isUserInitiated(2_000_000 + USER_INTENT_WINDOW_MS), 'window edge is inclusive')
  ok(!isUserInitiated(2_000_000 + USER_INTENT_WINDOW_MS + 1), 'just outside the window')
  eq(activityHeaders('GET', 2_000_500), { [ACTIVITY_HEADER]: '1' }, 'header')
})
test('before any input, nothing is user-initiated', () => {
  noteUserInput(Number.NEGATIVE_INFINITY)
  ok(!isUserInitiated(0), 'at t=0')
  eq(activityHeaders('GET', Date.now()), {}, 'now')
})

// ---------------------------------------------------------------- 401 sign-out rule

test('a 401 on a session-token request signs the user out', () => {
  ok(shouldSignOutOn401('/v1/admin/staff', SESSION), 'admin route')
  ok(shouldSignOutOn401('/v1/auth/me', SESSION), '/v1/auth/me')
  ok(shouldSignOutOn401('/v1/events', SESSION), 'SSE')
})
test('a 401 on login / logout / status never triggers "session expired"', () => {
  ok(!shouldSignOutOn401('/v1/auth/login', SESSION), 'login')
  ok(!shouldSignOutOn401('/v1/auth/logout', SESSION), 'logout')
  ok(!shouldSignOutOn401('/v1/auth/status', SESSION), 'status')
})
test('a 401 sent with an API key, a legacy token or no token is not a session expiry', () => {
  ok(!shouldSignOutOn401('/v1/admin/staff', API_KEY), 'api key')
  ok(!shouldSignOutOn401('/v1/admin/staff', LEGACY), 'legacy')
  ok(!shouldSignOutOn401('/v1/admin/staff', ''), 'none')
})

// ---------------------------------------------------------------- handlers

test('notifyUnauthorized reaches the registered handler with path and reason', () => {
  const r = withHandlers(() => notifyUnauthorized({ path: '/v1/admin/staff', reason: 'SESSION_EXPIRED' }))
  eq(r.signedOut, [{ path: '/v1/admin/staff', reason: 'SESSION_EXPIRED' }], 'signed out')
  eq(r.rechecks, [], 'no recheck')
})
test('notifyUnauthorized with no handler is a no-op (does not throw)', () => {
  setUnauthorizedHandler(null)
  notifyUnauthorized()
})
test('unregistering a stale handler does not remove the current one', () => {
  const seen: string[] = []
  const offOld = setUnauthorizedHandler(() => seen.push('old'))
  const offNew = setUnauthorizedHandler(() => seen.push('new'))
  offOld()
  notifyUnauthorized()
  offNew()
  notifyUnauthorized()
  eq(seen, ['new'], 'only the current handler fires, and nothing after it unregisters')
})
test('unregistering a stale recheck handler does not remove the current one', () => {
  const seen: string[] = []
  const offOld = setAuthRecheckHandler(() => seen.push('old'))
  const offNew = setAuthRecheckHandler(() => seen.push('new'))
  offOld()
  handleSseAuthEvent('/v1/events', SESSION, 'MISSING_PERMISSION')
  offNew()
  eq(seen, ['new'], 'recheck')
})

// ---------------------------------------------------------------- SSE `event: auth`

test('SSE auth event with a session-gone reason signs the session out (and names the token)', () => {
  for (const reason of ['SESSION_EXPIRED', 'CREDENTIAL_INVALID', 'ACCOUNT_DISABLED', 'UNAUTHORIZED', 'REVOKED']) {
    const r = withHandlers(() => handleSseAuthEvent('/v1/events', SESSION, reason))
    eq(r.signedOut, [{ path: '/v1/events', reason, token: SESSION }], reason)
    eq(r.rechecks, [], `${reason} no recheck`)
  }
})
test('SSE auth event without a reason is treated as session gone (fail-closed)', () => {
  const r = withHandlers(() => handleSseAuthEvent('/v1/events', SESSION, null))
  eq(r.signedOut, [{ path: '/v1/events', reason: null, token: SESSION }], 'signed out')
  eq(r.rechecks, [], 'no recheck')
})
test('SSE auth event for a lost permission re-reads /v1/auth/me instead of signing out', () => {
  const r = withHandlers(() => handleSseAuthEvent('/v1/events', SESSION, 'MISSING_PERMISSION'))
  eq(r.signedOut, [], 'not signed out')
  eq(r.rechecks, [{ path: '/v1/events', reason: 'MISSING_PERMISSION', token: SESSION }], 'recheck')
})
test('SSE auth event on an API-key or legacy stream rechecks, never clears a session', () => {
  const r = withHandlers(() => {
    handleSseAuthEvent('/v1/events', API_KEY, 'SESSION_EXPIRED')
    handleSseAuthEvent('/v1/events', LEGACY, null)
  })
  eq(r.signedOut, [], 'no sign-out')
  eq(r.rechecks.length, 2, 'two rechecks')
})

done('credentials.test.ts')
