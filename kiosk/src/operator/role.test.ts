/** Unit tests for operator/role.ts (audit KAO-11: never prefer the build-time demo file over the live bundle). */
import { done, eq, test } from '../shared/testkit.ts'
import { resolveRole } from './role.ts'

const demo = [{ user_id: 'u_prj1', role: 'student' }]
const users = [{ user_id: 'u_prj1', role: 'visitor', bundle_role: 'visitor', template_role: 'student' }]

test('edge response role wins', () => {
  eq(resolveRole('u_prj1', 'faculty', users, demo), { role: 'faculty', source: 'edge response' }, 'role')
})
test('live installed-bundle role beats the build-time demo file', () => {
  eq(resolveRole('u_prj1', null, users, demo), { role: 'visitor', source: 'installed bundle' }, 'role')
})
test('the template role is never shown as the access role', () => {
  eq(resolveRole('u_prj1', null, [{ user_id: 'u_prj1', role: null, bundle_role: null, template_role: 'student' }], []), { role: null, source: null }, 'role')
})
test('demo file only as a last resort, labelled as possibly stale', () => {
  eq(resolveRole('u_prj1', null, null, demo), { role: 'student', source: 'demo file (may be stale)' }, 'role')
})
test('no candidate -> no role', () => {
  eq(resolveRole(null, null, users, demo), { role: null, source: null }, 'role')
})

done('role.test.ts')
