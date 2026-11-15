/** Auth context + useAuth() (kept apart from the provider component so fast refresh works). */
import { createContext, useContext } from 'react'
import type { LoginResult, Principal, SessionInfo } from '../../api/authTypes'

/**
 * loading    - checking a stored session with GET /v1/auth/me
 * signed_out - show the login screen
 * pending    - signed in, but the edge confines the session until a password change / MFA enrolment
 * signed_in  - permissions from /v1/auth/me apply
 * error      - the edge could not be reached to check the stored session (token kept; retry)
 */
export type AuthStatusKind = 'loading' | 'signed_out' | 'pending' | 'signed_in' | 'error'
export type PendingAction = 'PASSWORD_CHANGE_REQUIRED' | 'MFA_ENROLMENT_REQUIRED'

export interface AuthContextValue {
  status: AuthStatusKind
  /** the credential to pass as `token` to every EdgeApi call ('' when signed out) */
  token: string
  principal: Principal | null
  session: SessionInfo | null
  pending: PendingAction | null
  /** why the user is on the login screen ("Session expired, sign in again", …) */
  notice: string | null
  error: string | null
  /** permission granted by the edge (never derived from role names); false while pending */
  can: (perm: string) => boolean
  canAny: (perms: readonly string[]) => boolean
  signOut: (notice?: string | null) => Promise<void>
  /** mark user activity now (keeps the client idle timer and the edge session alive) */
  noteActivity: () => void
  /** login screen: a successful POST /v1/auth/login */
  acceptLogin: (result: LoginResult) => void
  /** login screen: use a legacy admin token (only when the edge enables it) */
  signInWithToken: (token: string) => Promise<void>
  /** re-read /v1/auth/me (after a password change, MFA enrolment, a 403) */
  refresh: () => Promise<void>
}

const SIGNED_OUT: AuthContextValue = {
  status: 'signed_out',
  token: '',
  principal: null,
  session: null,
  pending: null,
  notice: null,
  error: null,
  can: () => false,
  canAny: () => false,
  signOut: async () => undefined,
  noteActivity: () => undefined,
  acceptLogin: () => undefined,
  signInWithToken: async () => undefined,
  refresh: async () => undefined,
}

export const AuthContext = createContext<AuthContextValue>(SIGNED_OUT)

/** Auth state of the page. Outside an <AuthProvider> everything is signed out (fail-closed). */
export function useAuth(): AuthContextValue {
  return useContext(AuthContext)
}

export function pendingOf(p: Principal | null): PendingAction | null {
  if (!p) return null
  if (p.must_change_password) return 'PASSWORD_CHANGE_REQUIRED'
  if (p.mfa_enrolment_required) return 'MFA_ENROLMENT_REQUIRED'
  return null
}
