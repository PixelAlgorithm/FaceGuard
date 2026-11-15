/** Unit tests for kiosk/viewRules.ts (audit KF-10: no user cancel while the edge is deciding). */
import { done, eq, test } from '../shared/testkit.ts'
import { userCancelAllowed } from './viewRules.ts'

test('cancel is refused while a fallback code is being verified', () => {
  eq(userCancelAllowed({ kind: 'fallback', busy: true }), false, 'fallback busy')
  eq(userCancelAllowed({ kind: 'fallback', busy: false }), true, 'fallback idle')
})
test('cancel is refused while frames or challenge evidence are with the edge', () => {
  eq(userCancelAllowed({ kind: 'deciding' }), false, 'deciding')
  eq(userCancelAllowed({ kind: 'challenge', phase: 'submitting' }), false, 'challenge submitting')
  eq(userCancelAllowed({ kind: 'challenge', phase: 'prompt' }), true, 'challenge prompt')
})
test('cancel is allowed on idle screens', () => {
  for (const kind of ['scanning', 'decision', 'service-error', 'capturing'] as const) eq(userCancelAllowed({ kind }), true, kind)
})

done('viewRules.test.ts')
