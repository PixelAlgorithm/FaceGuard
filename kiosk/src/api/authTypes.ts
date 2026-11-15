/**
 * Wire types of the edge authentication + staff administration routes (design v2 §C/§F; shapes confirmed
 * with edge/auth/routes.py). Parsed by src/api/authParse.ts; nothing here is trusted for authorisation:
 * the edge enforces every permission, the UI only hides / disables what would be refused.
 */

export type AuthStoreState = 'OK' | 'EMPTY' | 'MISSING' | 'UNAVAILABLE'

/** GET /v1/auth/status (public; never lists usernames). */
export interface AuthStatus {
  store: AuthStoreState
  accounts_exist: boolean
  legacy_token_enabled: boolean
  mfa_required_roles: string[]
}

export type PrincipalKind = 'staff' | 'api_key' | 'legacy' | 'cli'

export interface Principal {
  kind: PrincipalKind
  id: string
  staff_id: string | null
  /** what the edge writes as `actor` (staff:<id> | key:<id> | legacy:admin_token) */
  actor_id: string | null
  username: string | null
  display_name: string
  roles: string[]
  permissions: string[]
  must_change_password: boolean
  mfa_enrolment_required: boolean
  mfa_enabled: boolean
}

export interface SessionInfo {
  session_id: string | null
  expires_at: string | null
  idle_timeout_s: number | null
}

/** GET /v1/auth/me (session null for API keys and the legacy token). */
export interface AuthMe {
  principal: Principal
  session: SessionInfo | null
}

/** POST /v1/auth/login: password form, or the MFA second leg with the opaque ticket. */
export type LoginRequest =
  | { username: string; password: string; totp_code?: string }
  | { mfa_ticket: string; totp_code: string }

export interface LoginResult {
  token: string
  token_type: 'Bearer'
  expires_at: string | null
  idle_timeout_s: number | null
  principal: Principal
}

export interface PasswordChange {
  current_password: string
  new_password: string
}

/** POST /v1/auth/mfa/enroll -> shown once (no-store). */
export interface MfaEnrolment {
  secret: string
  otpauth_uri: string
}

export type StaffStatus = 'active' | 'disabled'

export interface StaffAccount {
  staff_id: string
  username: string
  display_name: string
  roles: string[]
  status: StaffStatus
  locked: boolean
  locked_until: string | null
  failed_logins: number
  mfa_enabled: boolean
  must_change_password: boolean
  created_at: string | null
  updated_at: string | null
  password_changed_at: string | null
  last_login_at: string | null
}

/** Every staff:manage mutation and API key creation re-authenticates the actor (403 REAUTH_REQUIRED). */
export interface Reauth {
  confirm_password: string
}

export interface StaffCreate extends Reauth {
  username: string
  display_name: string
  roles: string[]
  temporary_password: string
}

export interface StaffUpdate extends Reauth {
  display_name?: string
  roles?: string[]
  status?: StaffStatus
}

export interface StaffPasswordReset extends Reauth {
  temporary_password: string
}

export type ApiKeyStatus = 'active' | 'expired' | 'revoked'

export interface ApiKeyInfo {
  key_id: string
  name: string
  roles: string[]
  permissions: string[]
  status: ApiKeyStatus
  created_at: string | null
  created_by: string | null
  expires_at: string | null
  last_used_at: string | null
  revoked_at: string | null
}

export interface ApiKeyCreate extends Reauth {
  name: string
  roles: string[]
  expires_days: number
}

/** POST /v1/admin/api-keys -> the plaintext key exactly once. */
export interface ApiKeyCreated {
  key: string
  item: ApiKeyInfo
}

export interface RoleInfo {
  name: string
  description: string
  permissions: string[]
  /** API keys may hold this role (admin never) */
  key_allowed: boolean
}

/** GET /v1/admin/roles */
export interface RolesCatalog {
  roles: RoleInfo[]
  permissions: string[]
  key_forbidden_permissions: string[]
  max_roles_per_account: number
}

export interface AuditActor {
  kind: string
  id: string | null
  username: string | null
}

export interface AuthAuditEntry {
  seq: number
  ts_utc: string | null
  actor: AuditActor
  action: string
  target: string | null
  outcome: string
  client_ip: string | null
  detail: Record<string, unknown> | null
  /** aggregated `auth.denied` lines only */
  count: number | null
}

/** GET /v1/admin/auth/audit (newest first). */
export interface AuthAuditPage {
  as_of: string | null
  count: number
  items: AuthAuditEntry[]
  next_before_seq: number | null
}

export interface AuditQuery {
  limit?: number
  before_seq?: number | null
}

/** Field limits shared by the login / staff forms (mirror edge/auth/models.py + passwords.py). */
export const AUTH_LIMITS = {
  usernamePattern: /^[a-z][a-z0-9_]{1,30}$/,
  reservedUsernames: ['admin', 'root', 'administrator', 'sa', 'test', 'demo', 'system', 'kiosk'],
  passwordMin: 12,
  passwordMax: 128,
  displayNameMax: 80,
  keyNameMax: 64,
  keyExpiresDaysMin: 1,
  keyExpiresDaysMax: 90,
  keyExpiresDaysDefault: 30,
  maxRoles: 3,
  totpPattern: /^\d{6}$/,
} as const
