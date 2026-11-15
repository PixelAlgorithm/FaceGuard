/** Plain-language text for a failed auth / staff call. The edge `reason` decides, never the message text. */
import { asApiError } from '../../api/types'

const REASON_TEXT: Record<string, string> = {
  INVALID_CREDENTIALS: 'Wrong username or password.',
  MFA_INVALID: 'The authenticator code was not accepted.',
  ACCOUNT_DISABLED: 'This account is disabled. Ask an admin.',
  ACCOUNT_LOCKED: 'This account is temporarily locked. Wait, or ask an admin to unlock it.',
  REAUTH_REQUIRED: 'Your password was not accepted.',
  SESSION_EXPIRED: 'Session expired, sign in again.',
  AUTH_UNAVAILABLE: 'Staff sign-in is unavailable on this edge (staff store unreadable). Check the edge logs.',
  AUTH_BUSY: 'The staff store is busy. Try again in a moment.',
  SELF_MODIFICATION: 'You cannot change your own roles or status.',
  LAST_ADMIN: 'This would leave no active admin. Promote another admin first.',
  ROLE_CEILING: 'You can only grant roles whose permissions you hold yourself.',
  RESERVED_USERNAME: 'That username is reserved. Pick another one.',
  USERNAME_TAKEN: 'That username already exists.',
  INVALID_ROLES: 'That role combination is not allowed (API keys can never hold admin).',
  STAFF_ID_NOT_OWN: 'You may only rotate codes for your own staff id.',
  NO_STAFF_IDENTITY: 'Staff codes need a signed-in staff account (not an API key or the legacy token).',
  PASSWORD_CHANGE_REQUIRED: 'Change your password first.',
  MFA_ENROLMENT_REQUIRED: 'Set up two-factor sign-in first.',
}

export function authErrorText(e: unknown): string {
  const err = asApiError(e)
  if (!err) return e instanceof Error ? e.message : String(e)
  if (err.isUnreachable) return 'The edge is not reachable. Check that the edge service is running.'
  if (err.status === 429) return `Too many attempts. Try again in ${err.extra.retry_after_s ?? 'a few'} s.`
  if (err.reason === 'PASSWORD_POLICY') return `The new password does not meet the policy: ${(err.extra.problems ?? []).join('; ') || err.message}`
  if (err.reason === 'MISSING_PERMISSION') return `Not allowed: needs ${(err.extra.required ?? []).join(', ') || 'a permission you do not hold'}.`
  const key = err.reason ?? err.code
  return REASON_TEXT[key] ?? (err.message || err.code)
}
