/**
 * Local mirror of edge/auth/passwords.py check_policy (NEW passwords only), so the change-password form can show
 * problems before the request. The edge stays authoritative: it also rejects common passwords (deny list) and
 * answers 422 reason PASSWORD_POLICY with `problems`. Messages match the edge's wording.
 * Pure module (no imports): used by the login screen, the SIMULATED edge (api/mockAuth.ts) and the Node unit tests.
 */

export const PASSWORD_MIN = 12
export const PASSWORD_MAX = 128
export const PASSWORD_MIN_DISTINCT = 5
/** The username rule applies only to usernames at least this long (edge: len(user) >= 3). */
const USERNAME_RULE_MIN = 3
/**
 * Longest password the sign-in / re-auth fields accept (edge MAX_GIVEN_PASSWORD = MAX_LENGTH * 4). Must stay above
 * PASSWORD_MAX: an input maxLength counts UTF-16 code units, so 128 code points of emoji would be truncated.
 */
export const GIVEN_PASSWORD_MAX = PASSWORD_MAX * 4

/** Code points after NFKC: what Python's len(unicodedata.normalize("NFKC", p)) counts. */
function codePoints(text: string): string[] {
  return [...text.normalize('NFKC')]
}

/** Edge policy problems for a new password (empty = acceptable locally). */
export function passwordPolicyProblems(password: string, username: string): string[] {
  const chars = codePoints(password)
  const problems: string[] = []
  if (chars.length < PASSWORD_MIN) problems.push(`use at least ${PASSWORD_MIN} characters`)
  if (chars.length > PASSWORD_MAX) problems.push(`use at most ${PASSWORD_MAX} characters`)
  if (new Set(chars).size < PASSWORD_MIN_DISTINCT) problems.push(`use at least ${PASSWORD_MIN_DISTINCT} different characters`)
  const user = username.trim().toLowerCase()
  if (user.length >= USERNAME_RULE_MIN && chars.join('').toLowerCase().includes(user)) problems.push('do not include the username')
  return problems
}

export interface NewPasswordContext {
  username: string
  /** the current (temporary) password being replaced */
  current: string
  /** the "new password again" field ('' = not typed yet) */
  again: string
}

/** Policy problems plus the change-password form's own checks (differs from current, repeat matches). */
export function newPasswordProblems(next: string, ctx: NewPasswordContext): string[] {
  const problems = passwordPolicyProblems(next, ctx.username)
  if (next && next === ctx.current) problems.push('the new password must differ from the current one')
  if (ctx.again && next !== ctx.again) problems.push('the two new passwords differ')
  return problems
}
