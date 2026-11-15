/**
 * Edge permission names (design v2 §B, edge/auth/rbac.py) and the permission each edge route needs.
 * The UI NEVER derives permissions from roles: it only checks the `permissions` list the edge returns in
 * /v1/auth/me. These constants exist so a typo is a compile error, and so scripts/contract-test.ts can
 * prove the gates match docs/contracts/admin_access.examples.json (`route.permission`).
 */

export const PERM = {
  eventsRead: 'events:read',
  metricsRead: 'metrics:read',
  storeRead: 'store:read',
  attemptSignals: 'attempt:signals',
  modeSwitch: 'mode:switch',
  syncRun: 'sync:run',
  rateLimitReset: 'ratelimit:reset',
  evalAdmin: 'eval:admin',
  demoClock: 'demo:clock',
  challengeControl: 'challenge:control',
  enrolRead: 'enrol:read',
  enrolWrite: 'enrol:write',
  enrolErase: 'enrol:erase',
  accessRead: 'access:read',
  accessEdit: 'access:edit',
  accessRevoke: 'access:revoke',
  codesRotate: 'codes:rotate',
  codesRotateAny: 'codes:rotate_any',
  bundleRefresh: 'bundle:refresh',
  staffManage: 'staff:manage',
  auditRead: 'audit:read',
} as const

export type Permission = (typeof PERM)[keyof typeof PERM]

/** Contract route id -> permission (null = no permission: public or any signed-in principal). */
export const EDGE_ROUTE_PERMISSION: Readonly<Record<string, Permission | null>> = {
  'edge.access.users.list': PERM.accessRead,
  'edge.access.users.put': PERM.accessEdit,
  'edge.access.users.revoke': PERM.accessRevoke,
  'edge.access.codes.rotate': PERM.codesRotate,
  'edge.bundle.refresh': PERM.bundleRefresh,
  'edge.enroll.post': PERM.enrolWrite,
  'edge.enroll.delete': PERM.enrolErase,
  'edge.admin.users.list': PERM.enrolRead,
  'edge.mode.get': null,
  'edge.admin.clock.post': PERM.demoClock,
  'edge.auth.status': null,
  'edge.auth.login': null,
  'edge.auth.me': null,
  'edge.auth.mfa.enroll': null,
  'edge.auth.password': null,
  'edge.admin.staff.list': PERM.staffManage,
  'edge.admin.staff.create': PERM.staffManage,
  'edge.admin.staff.patch': PERM.staffManage,
  'edge.admin.api_keys.list': PERM.staffManage,
  'edge.admin.api_keys.create': PERM.staffManage,
  // edge/auth/rbac.py ROUTE_PERMISSIONS: any authenticated principal (the role catalog is not secret)
  'edge.admin.roles': null,
  'edge.admin.auth.audit': PERM.auditRead,
}

/** The hint shown on a disabled control. */
export function needsText(perm: string): string {
  return `Needs ${perm}`
}
