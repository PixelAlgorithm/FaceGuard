/** Unit tests for shared/auth/lifecycle.ts (session lifecycle rules of design v2 §F). */
import { done, eq, ok, test } from '../testkit.ts'
import {
  ACTIVITY_POST_MIN_MS,
  CLIENT_IDLE_SIGNOUT_MS,
  RECHECK_MIN_MS,
  activityPostDue,
  isIdleExpired,
  planRecheck,
  publicPageNeedsWipe,
  restoredLastInput,
  secondsLeft,
  unauthorizedMatches,
} from './lifecycle.ts'

const T0 = 1_000_000

test('idle sign-out happens only after more than 10 minutes without input', () => {
  eq(CLIENT_IDLE_SIGNOUT_MS, 600_000, 'limit')
  ok(!isIdleExpired(T0, T0 + CLIENT_IDLE_SIGNOUT_MS), 'exactly 10 min is not idle yet')
  ok(isIdleExpired(T0, T0 + CLIENT_IDLE_SIGNOUT_MS + 1), 'past 10 min is idle')
})

test('activity POST is throttled to at most once per 60 s', () => {
  eq(ACTIVITY_POST_MIN_MS, 60_000, 'interval')
  ok(activityPostDue(0, T0), 'never posted -> due')
  ok(!activityPostDue(T0, T0 + 59_999), 'inside the window -> not due')
  ok(activityPostDue(T0, T0 + 60_000), 'window over -> due')
})

test('recheck runs immediately outside the window', () => {
  eq(planRecheck(0, T0), { runNow: true, delayMs: 0 }, 'first recheck')
  eq(planRecheck(T0, T0 + RECHECK_MIN_MS), { runNow: true, delayMs: 0 }, 'window just over')
})

test('a recheck inside the window is deferred to the window end (never dropped)', () => {
  eq(planRecheck(T0, T0 + 1_000), { runNow: false, delayMs: RECHECK_MIN_MS - 1_000 }, 'deferred')
})

test('countdown seconds round up and never go negative', () => {
  eq(secondsLeft(T0 + 4_001, T0), 5, 'rounds up')
  eq(secondsLeft(T0 + 5_000, T0), 5, 'exact')
  eq(secondsLeft(T0 - 1, T0), 0, 'past')
  eq(secondsLeft(0, T0), 0, 'unset')
})

test('a 401 for an older token never signs out the current session', () => {
  ok(unauthorizedMatches({ path: '/v1/x', reason: null, token: 'fgs_old' }, 'fgs_new') === false, 'old token')
  ok(unauthorizedMatches({ path: '/v1/x', reason: null, token: 'fgs_new' }, 'fgs_new'), 'same token')
  ok(unauthorizedMatches({ path: '/v1/x', reason: null }, 'fgs_new'), 'no token info -> current session (fail closed)')
  ok(!unauthorizedMatches({ path: '/v1/x', reason: null }, ''), 'already signed out -> nothing to do')
})

test('KAUTH-02 a reload keeps the idle clock: the stored last input decides', () => {
  eq(restoredLastInput(String(T0 - 60_000), T0), { lastInputAt: T0 - 60_000, expired: false }, 'recent input survives the reload')
  ok(restoredLastInput(String(T0 - CLIENT_IDLE_SIGNOUT_MS - 1), T0).expired, 'idle > 10 min before the reload -> signed out')
  ok(restoredLastInput(null, T0).expired, 'no stored input time -> fail closed')
  ok(restoredLastInput('garbage', T0).expired, 'unparseable -> fail closed')
  ok(restoredLastInput(String(T0 + 5 * 60_000), T0).expired, 'far-future time (tampered / clock jump) -> fail closed')
  ok(!restoredLastInput(String(T0 + 1_000), T0).expired, 'small clock skew is tolerated')
})

test('KAUTH-01 a back/forward-cache restore of the public kiosk wipes credentials', () => {
  ok(publicPageNeedsWipe({ type: 'pageshow', persisted: true }), 'bfcache restore')
  ok(!publicPageNeedsWipe({ type: 'pageshow', persisted: false }), 'normal load is handled by mount')
  ok(publicPageNeedsWipe({ type: 'visibilitychange', visible: true }), 'tab shown again')
  ok(!publicPageNeedsWipe({ type: 'visibilitychange', visible: false }), 'tab hidden')
})

done('lifecycle.test.ts')
