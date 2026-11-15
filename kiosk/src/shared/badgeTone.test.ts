/** Unit tests for shared/badgeTone.ts: the ONLINE/OFFLINE badge never claims ONLINE when it does not know. */
import { done, eq, test } from './testkit.ts'
import { badgeTone, bundleText, type BadgeMode } from './badgeTone.ts'

const m = (p: Partial<BadgeMode>): BadgeMode => ({ mode: 'ONLINE', state: 'ONLINE', forced: false, reason: null, degraded: false, ...p })

test('edge down beats everything', () => eq(badgeTone(m({}), false), 'down', 'tone'))
test('no answer yet -> connecting', () => eq(badgeTone(null, true), 'unknown', 'tone'))
test('unknown mode from the edge (KAO-09) -> its own amber state, never ONLINE', () =>
  eq(badgeTone(m({ mode: 'OFFLINE', state: 'OFFLINE', reason: 'mode_unknown' }), true), 'modeUnknown', 'tone'))
test('forced OFFLINE shows as forced even while the heartbeat is syncing', () =>
  eq(badgeTone(m({ mode: 'OFFLINE', state: 'SYNCING', forced: true }), true), 'forced', 'tone'))
test('syncing', () => eq(badgeTone(m({ mode: 'OFFLINE', state: 'SYNCING' }), true), 'syncing', 'tone'))
test('offline by state or by attempt mode', () => {
  eq(badgeTone(m({ state: 'OFFLINE' }), true), 'offline', 'state')
  eq(badgeTone(m({ mode: 'OFFLINE', reason: 'bundle_stale' }), true), 'offline', 'mode')
})
test('degraded cloud', () => eq(badgeTone(m({ degraded: true }), true), 'degraded', 'tone'))
test('online', () => eq(badgeTone(m({}), true), 'online', 'tone'))

// Review KA-03: schedule_bundle moved off the public /v1/mode; the version comes from an authenticated
// source (access list / mode detail) when the page has one, else the public cache_state is shown.
test('bundle text: version when known, else the public cache state, else nothing', () => {
  eq(bundleText(46, 'FRESH'), 'bundle v46', 'version wins')
  eq(bundleText(null, 'EXPIRED'), 'bundle EXPIRED', 'public cache state')
  eq(bundleText(null, null), null, 'nothing known')
})

done('badgeTone.test.ts')
