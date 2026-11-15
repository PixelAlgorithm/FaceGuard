/**
 * Pure SECOND_FACTOR view-model rules (no React, no DOM, no runtime imports beyond ./reasons.ts), so they can
 * be unit-tested with plain Node (`node --test`). Used by KioskController.
 *
 *  - reconcileFallback: a new STEP_UP SECOND_FACTOR response for the attempt already on the fallback screen.
 *    Two edge behaviours share that shape (docs/API.md R8 / R11):
 *      R8  a code was rejected and counted: attempts_left went down, FALLBACK_FAILED is present;
 *      R11 the EMAIL_OTP cloud verify was unavailable: the same step is re-issued WITHOUT EMAIL_OTP and
 *          nothing is counted (attempts_left unchanged).
 *    The selected method must always be one the edge still offers, otherwise the next submission is a
 *    counted "method not offered" failure (audit KF-02 / F2).
 *    FALLBACK_LOCKED (+ retry_after_s): the submitted method is locked for a while; nothing counted (KF-03).
 *  - fallbackErrorPatch: a /fallback request that failed (no decision) -> what the screen shows next.
 *  - codeLengths: allowed code lengths per method (staff codes: code_length + legacy lengths, EO-11).
 */
import type { ApiError, DecisionResponse, FallbackMethod } from '../api/types'
import type { FallbackViewModel } from './controller'
import { reasonText, triesLeftText } from './reasons.ts'

export const METHOD_UNAVAILABLE_TEXT = 'That method is not available right now. Please choose another method.'
export const EMAIL_UNAVAILABLE_TEXT = 'Email codes are not available right now. Please choose another method.'
export const ASK_DESK_TEXT = 'Verification is not available right now. Please ask the desk for help.'
export const NOT_RESPONDING_TEXT = 'Kiosk service not responding. Please try again or ask the desk.'
export const GENERIC_FAILED_TEXT = 'Verification could not be completed. Please try again or ask the desk.'

/** The method to keep selected when the offered set changes: kept if still offered, the only one, or none. */
export function keepSelected(selected: FallbackMethod | null, methods: readonly FallbackMethod[]): FallbackMethod | null {
  if (selected !== null && methods.includes(selected)) return selected
  return methods.length === 1 ? methods[0] : null
}

/** A failure was counted by the edge for this response (R8), as opposed to a plain re-issue (R11). */
export function failureCounted(prevLeft: number | null, resp: DecisionResponse): boolean {
  const left = resp.next_action.attempts_left
  if (prevLeft !== null && left !== null) return left < prevLeft
  return resp.reason_codes.includes('FALLBACK_FAILED')
}

/**
 * FALLBACK_LOCKED (KF-03): the method just submitted is temporarily locked on the edge (wrong-code backstop);
 * nothing was counted and retry_after_s says how long. The person is offered the other methods.
 */
export function lockedText(method: FallbackMethod | null, waitS: number | null): string {
  const wait = waitS !== null && waitS > 0 ? ` (${Math.ceil(waitS)} s)` : ''
  return method === 'STAFF_OVERRIDE'
    ? `Staff override temporarily locked – ask the desk or use another method${wait}`
    : `This method is locked for a few minutes – please use another method or ask the desk${wait}`
}

/** Same-attempt SECOND_FACTOR response -> next fallback view model (never mutates `vm`). */
export function reconcileFallback(vm: FallbackViewModel, resp: DecisionResponse): FallbackViewModel {
  const methods = resp.next_action.methods ?? vm.methods
  const left = resp.next_action.attempts_left
  if (resp.reason_codes.includes('FALLBACK_LOCKED')) {
    return {
      ...vm,
      decision: resp,
      methods,
      // back to the picker so another offered method can be chosen (the only method stays selected)
      selected: keepSelected(null, methods),
      otp: null,
      busy: false,
      error: lockedText(vm.selected, resp.next_action.retry_after_s),
      attemptsLeft: left,
    }
  }
  const selected = keepSelected(vm.selected, methods)
  const methodDropped = vm.selected !== null && !methods.includes(vm.selected)
  const counted = failureCounted(vm.attemptsLeft, resp)
  const error = counted
    ? `${reasonText('FALLBACK_FAILED', 'STEP_UP')}${left !== null ? ` (${triesLeftText(left)})` : ''}`
    : methodDropped
      ? vm.selected === 'EMAIL_OTP'
        ? EMAIL_UNAVAILABLE_TEXT
        : METHOD_UNAVAILABLE_TEXT
      : null
  return {
    ...vm,
    decision: resp,
    methods,
    selected,
    // an e-mail code belongs to EMAIL_OTP only; drop it as soon as that method is gone
    otp: methods.includes('EMAIL_OTP') && selected === 'EMAIL_OTP' ? vm.otp : null,
    busy: false,
    error,
    attemptsLeft: left,
  }
}

/** Failed /fallback request (no decision received) -> patch for the fallback view model. */
export function fallbackErrorPatch(vm: FallbackViewModel, method: FallbackMethod, err: ApiError | null): Partial<FallbackViewModel> {
  if (!err) return { busy: false, error: GENERIC_FAILED_TEXT }
  if (err.isUnreachable) return { busy: false, error: NOT_RESPONDING_TEXT }
  if (method === 'EMAIL_OTP' && (err.code === 'CLOUD_UNAVAILABLE' || err.status === 503)) {
    // the cloud cannot verify e-mail codes now: never leave the person on a code screen that cannot succeed
    const methods = vm.methods.filter((m) => m !== 'EMAIL_OTP')
    if (!methods.length) return { busy: false, otp: null, error: `${EMAIL_UNAVAILABLE_TEXT.split('.')[0]}. ${ASK_DESK_TEXT}` }
    return { busy: false, otp: null, methods, selected: keepSelected(null, methods), error: EMAIL_UNAVAILABLE_TEXT }
  }
  if (err.code === 'RATE_LIMITED' || err.status === 429) {
    const wait = err.extra.retry_after_s
    return { busy: false, error: `Too many tries – please wait${wait ? ` ${Math.ceil(wait)} s` : ' a moment'} and try again.` }
  }
  // the edge's message is an internal string: show a user-facing sentence (the code helps the desk)
  return { busy: false, error: `${GENERIC_FAILED_TEXT} (${err.code})` }
}

/** Allowed code lengths for a method (sorted, unique, positive integers). */
export function codeLengths(main: number, legacy: readonly number[] = []): number[] {
  return [...new Set([main, ...legacy])].filter((n) => Number.isInteger(n) && n > 0).sort((a, b) => a - b)
}

/** A complete code: digits only, and its length is one of the allowed lengths. */
export function codeComplete(code: string, lengths: readonly number[]): boolean {
  return /^\d+$/.test(code) && lengths.includes(code.length)
}

const KNOWN_METHODS: ReadonlySet<string> = new Set(['TOTP', 'CARD', 'EMAIL_OTP', 'STAFF_OVERRIDE'])

/** `error.methods` of an edge error body (otp/send EMAIL_UNAVAILABLE / NO_EMAIL_ON_FILE), else null. */
export function edgeMethodsOf(err: ApiError | null): FallbackMethod[] | null {
  if (!err) return null
  const extra: Record<string, unknown> = { ...err.extra }
  const raw = extra.methods
  if (!Array.isArray(raw)) return null
  return raw.filter((m): m is FallbackMethod => typeof m === 'string' && KNOWN_METHODS.has(m))
}

/**
 * Failed POST /v1/attempt/{id}/otp/send -> patch for the fallback view model. NO_EMAIL_ON_FILE and (edge-app)
 * 503 EMAIL_UNAVAILABLE: the edge already dropped EMAIL_OTP; its `error.methods` list wins when present.
 * 429 OTP_SEND_CAP: no more e-mail codes for this attempt. Other 429: a code was just sent.
 */
export function otpErrorPatch(vm: FallbackViewModel, err: ApiError | null, edgeMethods: FallbackMethod[] | null): Partial<FallbackViewModel> {
  if (!err) return { busy: false, error: 'Could not send the email code. Choose another method.' }
  const dropped = err.reason === 'NO_EMAIL_ON_FILE' || err.reason === 'EMAIL_UNAVAILABLE'
  if (dropped) {
    const methods = (edgeMethods ?? vm.methods).filter((m) => m !== 'EMAIL_OTP')
    const why = err.reason === 'NO_EMAIL_ON_FILE' ? 'No e-mail address on file.' : 'Email codes are not available right now.'
    if (!methods.length) return { busy: false, otp: null, error: `${why} Please ask the desk for help.` }
    return { busy: false, otp: null, methods, selected: keepSelected(null, methods), error: `${why} Please choose another method.` }
  }
  if (err.code === 'RATE_LIMITED' || err.status === 429) {
    if (err.reason === 'OTP_SEND_CAP') return { busy: false, error: 'No more email codes can be sent for this check. Please choose another method.' }
    const wait = err.extra.retry_after_s
    return { busy: false, error: `A code was sent a moment ago. Please check your e-mail${wait ? ` or ask again in ${Math.ceil(wait)} s` : ''}.` }
  }
  if (err.isUnreachable) return { busy: false, error: NOT_RESPONDING_TEXT }
  return { busy: false, error: `Could not send the email code (${err.code}). Choose another method.` }
}

/**
 * Staff code keypad (EO-11, review KA-05): the configured code_length is the only length that Verify / Enter
 * submit; a legacy length (8-digit codes still in signed bundles) is submitted only through an explicit
 * "legacy code" action, so a 10-digit code can never go out early as an 8-digit prefix (which would count
 * as a wrong code and feed the override lockout).
 */
export function staffCodeAction(code: string, mainLength: number, legacyLengths: readonly number[]): 'submit' | 'legacy' | null {
  if (!/^\d+$/.test(code)) return null
  if (code.length === mainLength) return 'submit'
  return legacyLengths.includes(code.length) ? 'legacy' : null
}
