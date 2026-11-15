/** Unit tests for the RBAC gate on the registration plan (design v2 §B: enroller lacks access:edit). */
import { done, eq, ok, test } from './testkit.ts'
import { askAdminText, gatePlan, registerPlan } from './accessRules.ts'

const row = { status: 'ACTIVE' as const, role: 'student', bundle_role: 'student', display: 'Priya N.', in_bundle: true }

test('a new person needs a schedule write: blocked NEEDS_ACCESS_EDIT without access:edit', () => {
  eq(gatePlan(registerPlan(null, true, 'student', 'New P.'), false), { kind: 'blocked', why: 'NEEDS_ACCESS_EDIT' }, 'plan')
})
test('the same plan passes with access:edit', () => {
  eq(gatePlan(registerPlan(null, true, 'student', 'New P.'), true).kind, 'put-then-enrol', 'kind')
})
test('enrolling someone already in the bundle never needs access:edit', () => {
  eq(gatePlan(registerPlan(row, true, null, 'Priya N.'), false), { kind: 'enrol', role: 'student' }, 'plan')
})
test('other blocks are unchanged (OFFLINE stays OFFLINE)', () => {
  eq(gatePlan(registerPlan(null, false, 'student', 'New P.'), false), { kind: 'blocked', why: 'OFFLINE' }, 'plan')
})
test('the enroller sees the exact ask-an-admin sentence', () => {
  eq(askAdminText('u_ab12'), 'Ask an admin to add u_ab12 to the schedule.', 'text')
  ok(askAdminText('').includes('this person'), 'empty id')
})

done('accessRules.test.ts')
