/**
 * Edge credential plumbing shared by the real client (http.ts), the mock (mock.ts) and raw fetch readers
 * (operator/edgeRaw.ts). RBAC contract: design v2 §F, docs/API.md "Authentication and roles".
 *
 * - `fgs_…` (staff session) and `fgk_…` (API key) go in `Authorization: Bearer`; anything else is the
 *   deprecated shared token and goes in `X-Admin-Token` (accepted by the edge only with AUTH_LEGACY_ADMIN_TOKEN=1).
 * - Requests triggered by user input carry `X-FG-Activity: 1` (the only GETs that extend the idle timer).
 * - A 401 on a request that sent a SESSION token (never the login call itself) calls the registered
 *   unauthorized handler: the auth layer clears the session and shows "Session expired, sign in again".
 *
 * Pure module (no React, no window access at import time) so the Node contract test can import it.
 */

export const SESSION_PREFIX = 'fgs_'
export const API_KEY_PREFIX = 'fgk_'
export const ACTIVITY_HEADER = 'X-FG-Activity'
/** A GET issued this soon after a pointerdown / keydown counts as user-initiated. */
export const USER_INTENT_WINDOW_MS = 1000
const MAX_CREDENTIAL_LENGTH = 512
/** Printable ASCII without spaces: anything else cannot be sent in an HTTP header (fetch throws). */
const CREDENTIAL_RE = /^[\x21-\x7e]+$/

/** Login / logout / status calls never trigger the "session expired" flow (a wrong password is not an expiry). */
const NO_SIGNOUT_PATHS = ['/v1/auth/login', '/v1/auth/logout', '/v1/auth/status']

export function isSessionToken(token: string): boolean {
  return token.startsWith(SESSION_PREFIX)
}

export function isBearerCredential(token: string): boolean {
  return token.startsWith(SESSION_PREFIX) || token.startsWith(API_KEY_PREFIX)
}

/** Why a credential cannot be sent (null = fine). Catches pasted smart quotes / spaces (audit KAO-12). */
export function credentialError(token: string): string | null {
  if (!token) return null
  if (token.length > MAX_CREDENTIAL_LENGTH) return 'The credential is too long.'
  if (!CREDENTIAL_RE.test(token)) return 'The credential contains a space or a non-ASCII character (a pasted smart quote?).'
  return null
}

/** Auth headers for one request: Bearer for fgs_/fgk_, legacy X-Admin-Token otherwise, none when empty. */
export function authHeaders(token: string): Record<string, string> {
  if (!token) return {}
  return isBearerCredential(token) ? { Authorization: `Bearer ${token}` } : { 'X-Admin-Token': token }
}

// ---------------------------------------------------------------- user-intent tracking

let lastInputAt = Number.NEGATIVE_INFINITY

/** Called by the auth provider on every pointerdown / keydown (capture phase). */
export function noteUserInput(now: number = Date.now()): void {
  lastInputAt = now
}

/** True when a request issued now was (very likely) caused by the user's own input. */
export function isUserInitiated(now: number = Date.now()): boolean {
  return now - lastInputAt <= USER_INTENT_WINDOW_MS
}

/** `X-FG-Activity: 1` for writes and for user-initiated reads; polls and SSE never send it. */
export function activityHeaders(method: string, now: number = Date.now()): Record<string, string> {
  return method.toUpperCase() !== 'GET' || isUserInitiated(now) ? { [ACTIVITY_HEADER]: '1' } : {}
}

// ---------------------------------------------------------------- 401 / auth-recheck handlers

export interface UnauthorizedInfo {
  path: string
  /** edge error.reason (SESSION_EXPIRED, CREDENTIAL_INVALID, …) or the SSE `event: auth` reason */
  reason: string | null
  /** the credential that got the 401 / auth event (lets the auth layer ignore stale in-flight requests) */
  token?: string
}

type Listener = (info: UnauthorizedInfo) => void

let unauthorizedListener: Listener | null = null
let recheckListener: Listener | null = null

/** Registers THE unauthorized handler (one auth provider per page). Returns an unregister function. */
export function setUnauthorizedHandler(fn: Listener | null): () => void {
  unauthorizedListener = fn
  return () => {
    if (unauthorizedListener === fn) unauthorizedListener = null
  }
}

/** Registers the "permissions may have changed, reload /v1/auth/me" handler. */
export function setAuthRecheckHandler(fn: Listener | null): () => void {
  recheckListener = fn
  return () => {
    if (recheckListener === fn) recheckListener = null
  }
}

/** Should a 401 on `path`, sent with `token`, end the signed-in session in the UI? */
export function shouldSignOutOn401(path: string, token: string): boolean {
  return isSessionToken(token) && !NO_SIGNOUT_PATHS.some((p) => path.startsWith(p))
}

/** Tell the auth layer the session is gone (call only after shouldSignOutOn401 / an `event: auth`). */
export function notifyUnauthorized(info: UnauthorizedInfo = { path: '', reason: null }): void {
  unauthorizedListener?.(info)
}

/** Tell the auth layer to re-read /v1/auth/me (a 403 may mean the roles changed under us). */
export function requestAuthRecheck(info: UnauthorizedInfo = { path: '', reason: null }): void {
  recheckListener?.(info)
}

/** SSE `event: auth` reasons that mean the session itself is no longer valid. */
const SESSION_GONE_REASONS = new Set(['SESSION_EXPIRED', 'CREDENTIAL_INVALID', 'ACCOUNT_DISABLED', 'UNAUTHORIZED', 'REVOKED'])

/**
 * The edge closed an SSE stream with `event: auth` (session invalid/expired/revoked or events:read lost).
 * Session gone -> sign out; anything else -> re-read the permissions.
 */
export function handleSseAuthEvent(path: string, token: string, reason: string | null): void {
  if (isSessionToken(token) && (reason === null || SESSION_GONE_REASONS.has(reason))) notifyUnauthorized({ path, reason, token })
  else requestAuthRecheck({ path, reason, token })
}
