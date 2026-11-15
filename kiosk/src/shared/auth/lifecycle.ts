/**
 * Pure session-lifecycle rules for the staff consoles (design v2 §F), kept free of React and the DOM so the
 * Node unit tests can import them. AuthProvider.tsx wires them to timers and input events.
 */

/** Client-side sign-out after this long without pointer / keyboard input (the edge's own idle limit is 30 min). */
export const CLIENT_IDLE_SIGNOUT_MS = 10 * 60_000
/** How often the idle timer looks at the last input. */
export const IDLE_CHECK_MS = 15_000
/** POST /v1/auth/activity at most once per this interval. */
export const ACTIVITY_POST_MIN_MS = 60_000
/** Re-read /v1/auth/me at most once per this interval (403 MISSING_PERMISSION / SSE `event: auth` bursts). */
export const RECHECK_MIN_MS = 5_000

/** True when the last input is more than CLIENT_IDLE_SIGNOUT_MS ago. */
export function isIdleExpired(lastInputAt: number, now: number, limitMs: number = CLIENT_IDLE_SIGNOUT_MS): boolean {
  return now - lastInputAt > limitMs
}

/** True when a debounced POST /v1/auth/activity may be sent now. */
export function activityPostDue(lastPostAt: number, now: number, minMs: number = ACTIVITY_POST_MIN_MS): boolean {
  return now - lastPostAt >= minMs
}

export interface RecheckPlan {
  runNow: boolean
  /** when !runNow: run once after this delay (trailing edge), so a late role change is never missed */
  delayMs: number
}

/** Leading + trailing throttle for /v1/auth/me rechecks. */
export function planRecheck(lastRunAt: number, now: number, minMs: number = RECHECK_MIN_MS): RecheckPlan {
  const since = now - lastRunAt
  return since >= minMs ? { runNow: true, delayMs: 0 } : { runNow: false, delayMs: minMs - since }
}

/** Whole seconds left until `until` (ms epoch), rounded up, never negative. */
export function secondsLeft(until: number, now: number): number {
  return Math.max(0, Math.ceil((until - now) / 1000))
}

/** Shape of credentials.ts UnauthorizedInfo; `token` (when the reporter sends it) is the credential that got the 401. */
export interface UnauthorizedReport {
  path: string
  reason: string | null
  token?: string
}

/**
 * Should a reported 401 end the CURRENT session? Not when nobody is signed in, and not when the 401 belongs to an
 * older token (a request that was in flight across a sign-out / sign-in). Reports without a token are treated as
 * the current session (fail closed).
 */
export function unauthorizedMatches(info: UnauthorizedReport, currentToken: string): boolean {
  if (!currentToken) return false
  return info.token === undefined || info.token === currentToken
}

/** Lifetime of the opaque login `mfa_ticket` (edge TICKET_TTL_S = 120). */
export const MFA_TICKET_TTL_MS = 2 * 60_000

/** A stored last-input time this far in the future is not trusted (tampering / clock jump); small skew is fine. */
export const MAX_FUTURE_SKEW_MS = 60_000

/**
 * KAUTH-02: the client idle clock survives a reload. `stored` is the persisted last-input time (ms epoch, as a
 * string). Missing, unparseable or far-future values fail closed (expired), so a reload never restarts the clock.
 */
export function restoredLastInput(stored: string | null, now: number): { lastInputAt: number; expired: boolean } {
  const at = stored === null ? Number.NaN : Number(stored)
  if (!Number.isFinite(at) || at > now + MAX_FUTURE_SKEW_MS) return { lastInputAt: 0, expired: true }
  return { lastInputAt: at, expired: isIdleExpired(at, now) }
}

export type PublicPageEvent = { type: 'pageshow'; persisted: boolean } | { type: 'visibilitychange'; visible: boolean }

/**
 * KAUTH-01: page events after which the public kiosk route wipes staff credentials again. A back/forward-cache
 * restore (pageshow persisted) re-shows "/" without remounting anything; the tab becoming visible is a cheap
 * extra check. The wipe is idempotent.
 */
export function publicPageNeedsWipe(e: PublicPageEvent): boolean {
  return e.type === 'pageshow' ? e.persisted : e.visible
}
