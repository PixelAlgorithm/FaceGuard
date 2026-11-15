/**
 * Unit tests for api/normalize.ts normalizeMode (audit KAO-09): only an explicit ONLINE is ONLINE; a missing
 * or unknown mode is OFFLINE with reason `mode_unknown`; an unreported sync queue depth is null (never 0);
 * forced_until passes through.
 */
import { done, eq, ok, test } from '../shared/testkit.ts'
import { normalizeMode } from './normalize.ts'

test('an explicit ONLINE stays ONLINE with the edge reason', () => {
  const m = normalizeMode({ mode: 'ONLINE', state: 'ONLINE', reason: 'cloud_ok', sync_queue_depth: 0 })
  eq(m.mode, 'ONLINE', 'mode')
  eq(m.state, 'ONLINE', 'state')
  eq(m.reason, 'cloud_ok', 'reason')
  eq(m.sync_queue_depth, 0, 'a reported 0 stays 0')
})
test('an explicit OFFLINE keeps its own reason (not mode_unknown)', () => {
  const m = normalizeMode({ mode: 'OFFLINE', reason: 'cloud_unreachable' })
  eq(m.mode, 'OFFLINE', 'mode')
  eq(m.reason, 'cloud_unreachable', 'reason')
  eq(m.state, 'OFFLINE', 'state defaults to mode')
})
test('an unknown, mis-cased or missing mode is OFFLINE with reason mode_unknown', () => {
  for (const mode of ['online', 'Online', 'AUTO', 'SYNCING', '', 1, true, null, undefined]) {
    const m = normalizeMode({ mode, reason: 'cloud_ok' })
    eq(m.mode, 'OFFLINE', `mode ${String(mode)}`)
    eq(m.reason, 'mode_unknown', `reason for ${String(mode)} (edge reason is not trusted)`)
  }
})
test('a non-object body is OFFLINE / mode_unknown and does not throw', () => {
  for (const body of [null, undefined, 'ONLINE', 42, [], [{ mode: 'ONLINE' }]]) {
    const m = normalizeMode(body)
    eq(m.mode, 'OFFLINE', `mode for ${JSON.stringify(body)}`)
    eq(m.reason, 'mode_unknown', `reason for ${JSON.stringify(body)}`)
    eq(m.forced, false, 'forced')
  }
})
test('a missing or non-numeric sync_queue_depth is null, never 0', () => {
  eq(normalizeMode({ mode: 'OFFLINE' }).sync_queue_depth, null, 'missing')
  eq(normalizeMode({ mode: 'OFFLINE', sync_queue_depth: '3' }).sync_queue_depth, null, 'string')
  eq(normalizeMode({ mode: 'OFFLINE', sync_queue_depth: Number.NaN }).sync_queue_depth, null, 'NaN')
  eq(normalizeMode({ mode: 'OFFLINE', sync_queue_depth: 12 }).sync_queue_depth, 12, 'number')
})
test('forced_until passes through; forced is true only when literally true', () => {
  const m = normalizeMode({ mode: 'OFFLINE', forced: true, forced_until: '2026-11-15T11:00:00Z' })
  eq(m.forced, true, 'forced')
  eq(m.forced_until, '2026-11-15T11:00:00Z', 'forced_until')
  eq(normalizeMode({ mode: 'OFFLINE', forced: 'true', forced_until: 5 }).forced, false, 'string forced')
  eq(normalizeMode({ mode: 'OFFLINE', forced_until: 5 }).forced_until, null, 'non-string forced_until')
  eq(normalizeMode({ mode: 'OFFLINE' }).forced_until, null, 'missing forced_until')
})
test('only ONLINE/OFFLINE/SYNCING are valid states; anything else follows mode', () => {
  eq(normalizeMode({ mode: 'OFFLINE', state: 'SYNCING' }).state, 'SYNCING', 'syncing')
  eq(normalizeMode({ mode: 'ONLINE', state: 'weird' }).state, 'ONLINE', 'unknown state -> mode')
  eq(normalizeMode({ mode: 'OFFLINE', state: 'ONLINE_ISH' }).state, 'OFFLINE', 'unknown state -> OFFLINE')
})
test('a signature_valid that is not a boolean is null (unknown), never true', () => {
  eq(normalizeMode({ mode: 'OFFLINE', schedule_bundle: { version: 3, signature_valid: 'true' } }).schedule_bundle?.signature_valid, null, 'string')
  eq(normalizeMode({ mode: 'OFFLINE', schedule_bundle: { version: 3, signature_valid: false } }).schedule_bundle?.signature_valid, false, 'false')
  eq(normalizeMode({ mode: 'OFFLINE', schedule_bundle: 'x' }).schedule_bundle, null, 'non-object bundle')
})
test('rate_limit.locked only when literally true; unknown random_challenge is null', () => {
  eq(normalizeMode({ mode: 'ONLINE', rate_limit: { locked: 'yes' } }).rate_limit?.locked, false, 'locked string')
  eq(normalizeMode({ mode: 'ONLINE', random_challenge: 'force' }).random_challenge, 'FORCE', 'case-insensitive known value')
  eq(normalizeMode({ mode: 'ONLINE', random_challenge: 'ALWAYS' }).random_challenge, null, 'unknown value')
  ok(Array.isArray(normalizeMode({ mode: 'ONLINE', server_flags: [1, 'a'] }).server_flags), 'server_flags list')
  eq(normalizeMode({ mode: 'ONLINE', server_flags: [1, 'a'] }).server_flags, ['a'], 'non-strings dropped')
})

test('cache_state: top-level wins, else schedule_bundle.cache_state, else null (never assumed FRESH)', () => {
  eq(normalizeMode({ mode: 'ONLINE', cache_state: 'EXPIRED', schedule_bundle: { cache_state: 'FRESH' } }).cache_state, 'EXPIRED', 'top-level')
  eq(normalizeMode({ mode: 'ONLINE', schedule_bundle: { cache_state: 'INVALID' } }).cache_state, 'INVALID', 'bundle fallback')
  eq(normalizeMode({ mode: 'ONLINE' }).cache_state, null, 'missing')
  eq(normalizeMode({ mode: 'ONLINE', cache_state: 7 }).cache_state, null, 'non-string')
  eq(normalizeMode({ mode: 'ONLINE', cache_state: 'fresh' }).cache_state, null, 'unknown value is not FRESH')
})

done('normalize.test.ts')
