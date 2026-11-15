/**
 * Pure classification of a failed kiosk request -> what the controller does next (no DOM, no runtime imports),
 * unit-tested with plain Node. The order mirrors KioskController.handleError:
 *   rate limit > nonce restart (primary attempt only) > kiosk refusal > step-up lost > transient > service error.
 *
 * KF-M2: during a challenge or fallback step the edge holds an open step-up (its own TTL and counted tries).
 * A nonce / transient error there must NOT silently send the person back to scanning (that hides the failure
 * and resets counted progress); it is shown as a terminal "please try again" screen instead.
 * KF-06: session/start with recapture_of closes the parent attempt on the edge, so a recapture start must be
 * sent exactly once; prefetching it (and re-prefetching when stale) breaks the chain with 409 INVALID_STATE.
 */

export const TRANSIENT_CODES: ReadonlySet<string> = new Set([
  'NONCE_EXPIRED',
  'NONCE_REUSED',
  'ATTEMPT_CLOSED',
  'ATTEMPT_NOT_FOUND',
  'VALIDATION_ERROR',
  'INVALID_STATE',
])

/** Silent nonce restarts allowed in a row on the primary attempt. */
export const MAX_NONCE_RESTARTS = 3
/** Transient errors in a row before the service-error screen. */
export const MAX_TRANSIENT_ERRORS = 3

export interface ErrorInput {
  code: string
  status: number
  message: string
  unreachable: boolean
  nonceRestarts: number
  /** service errors counted so far, BEFORE this one */
  serviceErrors: number
  /** the error happened while a challenge or fallback step was on screen */
  inStepUp: boolean
}

export type ErrorAction =
  | { kind: 'rate-limited' }
  | { kind: 'nonce-restart' }
  | { kind: 'kiosk-refusal' }
  | { kind: 'step-up-lost' }
  | { kind: 'transient' }
  | { kind: 'service-error'; unreachable: boolean }

/**
 * session/start for a kiosk_id this edge does not serve (edge/app.py _kiosk_refusal): 409 INVALID_STATE
 * "kiosk switch to X refused ..." (DEMO_MODE=1) or 403 FORBIDDEN "kiosk_id not served by this edge".
 * A configuration error, never a transient one: retrying loops forever on every face.
 */
export function isKioskRefusal(code: string, message: string): boolean {
  return (code === 'INVALID_STATE' && /kiosk switch/i.test(message)) || (code === 'FORBIDDEN' && /kiosk_id not served/i.test(message))
}

export function errorAction(e: ErrorInput): ErrorAction {
  if (e.code === 'RATE_LIMITED' || e.status === 429) return { kind: 'rate-limited' }
  const nonce = e.code === 'NONCE_EXPIRED' || e.code === 'NONCE_REUSED'
  if (nonce && !e.inStepUp && e.nonceRestarts < MAX_NONCE_RESTARTS) return { kind: 'nonce-restart' }
  if (isKioskRefusal(e.code, e.message)) return { kind: 'kiosk-refusal' }
  if (e.inStepUp && (nonce || TRANSIENT_CODES.has(e.code))) return { kind: 'step-up-lost' }
  if (TRANSIENT_CODES.has(e.code) && e.serviceErrors + 1 < MAX_TRANSIENT_ERRORS) return { kind: 'transient' }
  return { kind: 'service-error', unreachable: e.unreachable }
}

/** KF-06: never prefetch a session while a recapture chain is open (recapture_of must be sent once). */
export function prefetchAllowed(recaptureOf: string | null): boolean {
  return recaptureOf === null
}
