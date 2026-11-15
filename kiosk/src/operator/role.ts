/**
 * The role shown next to an operator verdict (display only: the signed schedule decides access on the edge).
 * Audit KAO-11: the build-time demo schedule file must never outrank the live, signature-verified bundle role
 * from GET /v1/admin/users, and the role stored with the template is informational only (never shown as the
 * access role). Pure module (unit-tested with plain Node).
 */
export type RoleSource = 'edge response' | 'installed bundle' | 'demo file (may be stale)'

export interface RoleUser {
  user_id: string
  /** schedule role in the installed (verified) bundle */
  role: string | null
  bundle_role: string | null
  template_role: string | null
}

export interface DemoRole {
  user_id: string
  role: string
}

/** candidate.role (edge) > installed-bundle role (enrolled users list) > demo file (labelled stale) > unknown. */
export function resolveRole(
  userId: string | null,
  rawRole: string | null,
  users: readonly RoleUser[] | null,
  demo: readonly DemoRole[],
): { role: string | null; source: RoleSource | null } {
  if (rawRole) return { role: rawRole, source: 'edge response' }
  if (!userId) return { role: null, source: null }
  const u = users?.find((x) => x.user_id === userId)
  const live = u?.bundle_role ?? u?.role ?? null
  if (live) return { role: live, source: 'installed bundle' }
  if (users === null) {
    const d = demo.find((x) => x.user_id === userId)?.role
    if (d) return { role: d, source: 'demo file (may be stale)' }
  }
  return { role: null, source: null }
}
