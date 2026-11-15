/** Unit tests for kiosk/fallbackState.ts (audit KF-02 / F2, EO-11). Run: node --test "src/**\/*.test.ts". */
import type { ApiError, DecisionResponse, FallbackMethod, OtpSendResponse } from '../api/types'
import { done, eq, ok, test } from '../shared/testkit.ts'
import type { FallbackViewModel } from './controller'
import {
  EMAIL_UNAVAILABLE_TEXT,
  otpErrorPatch,
  staffCodeAction,
  codeComplete,
  codeLengths,
  fallbackErrorPatch,
  failureCounted,
  keepSelected,
  reconcileFallback,
} from './fallbackState.ts'

function stepUp(methods: FallbackMethod[], attemptsLeft: number | null, codes: string[] = ['OFFLINE_FALLBACK_REQUIRED']): DecisionResponse {
  return {
    attempt_id: 'att_1',
    kiosk_id: 'KIOSK_01',
    zone: 'MAIN_GATE',
    decision: 'STEP_UP',
    reason_codes: codes,
    resolved_codes: [],
    next_action: { type: 'SECOND_FACTOR', steps: ['SECOND_FACTOR'], methods, challenge: null, attempts_left: attemptsLeft, retry_after_s: null },
    bio_result: 'BIO_UNSURE',
    schedule_result: 'IN_WINDOW',
    mode: 'ONLINE',
    cache_state: 'FRESH',
    candidate: null,
    scores: {},
    latency_ms: { total: 10 },
    policy_version: null,
    bundle_version: null,
    display_message: null,
    stage: null,
  }
}

const OTP: OtpSendResponse = { otp_id: 'otp_1', destination_masked: 'a***@x.org', expires_at: '2026-11-15T12:00:00Z' } as OtpSendResponse

function vm(selected: FallbackMethod | null, methods: FallbackMethod[], attemptsLeft: number | null): FallbackViewModel {
  return { decision: stepUp(methods, attemptsLeft), methods, selected, otp: selected === 'EMAIL_OTP' ? OTP : null, busy: true, error: null, attemptsLeft }
}

function apiErr(code: string, status: number, extra: Record<string, unknown> = {}): ApiError {
  return { code, status, message: 'x', attemptId: null, reason: null, extra, isUnreachable: code === 'NETWORK' || code === 'TIMEOUT', name: 'ApiError' } as unknown as ApiError
}

// KF-02 / F2: R11 re-issue drops EMAIL_OTP without counting a failure.
test('R11 drop of the selected EMAIL_OTP leaves the only remaining method selected', () => {
  const next = reconcileFallback(vm('EMAIL_OTP', ['TOTP', 'EMAIL_OTP'], 1), stepUp(['TOTP'], 1))
  eq(next.selected, 'TOTP', 'selected')
  eq(next.otp, null, 'otp')
  eq(next.methods, ['TOTP'], 'methods')
  eq(next.error, EMAIL_UNAVAILABLE_TEXT, 'error')
  eq(next.busy, false, 'busy')
})

test('R11 drop with several methods left returns to the picker', () => {
  const next = reconcileFallback(vm('EMAIL_OTP', ['TOTP', 'CARD', 'EMAIL_OTP'], 1), stepUp(['TOTP', 'CARD'], 1))
  eq(next.selected, null, 'selected')
  ok(!/not accepted/i.test(next.error ?? ''), `no false "code not accepted" text: ${next.error}`)
})

test('R8 counted failure keeps the method and says the code was not accepted', () => {
  const next = reconcileFallback(vm('TOTP', ['TOTP', 'CARD'], 1), stepUp(['TOTP', 'CARD'], 0, ['FALLBACK_FAILED']))
  eq(next.selected, 'TOTP', 'selected')
  ok(/not accepted/i.test(next.error ?? ''), `error mentions not accepted: ${next.error}`)
  eq(next.attemptsLeft, 0, 'attemptsLeft')
})

test('failureCounted uses attempts_left when both are known, else FALLBACK_FAILED', () => {
  eq(failureCounted(1, stepUp(['TOTP'], 1, ['FALLBACK_FAILED'])), false, 'unchanged left')
  eq(failureCounted(1, stepUp(['TOTP'], 0)), true, 'left decreased')
  eq(failureCounted(null, stepUp(['TOTP'], null, ['FALLBACK_FAILED'])), true, 'no counts, code present')
})

test('keepSelected never returns a method that is not offered', () => {
  eq(keepSelected('CARD', ['TOTP']), 'TOTP', 'single')
  eq(keepSelected('CARD', ['TOTP', 'STAFF_OVERRIDE']), null, 'several')
  eq(keepSelected('TOTP', ['TOTP', 'CARD']), 'TOTP', 'kept')
})

test('reconcileFallback does not mutate its input', () => {
  const before = vm('EMAIL_OTP', ['TOTP', 'EMAIL_OTP'], 1)
  const copy = JSON.parse(JSON.stringify(before)) as FallbackViewModel
  reconcileFallback(before, stepUp(['TOTP'], 1))
  eq(before, copy, 'input')
})

// KF-02: CLOUD_UNAVAILABLE on an EMAIL_OTP submit must not leave the person stuck on the e-mail screen.
test('CLOUD_UNAVAILABLE on EMAIL_OTP offers the other methods', () => {
  const p = fallbackErrorPatch(vm('EMAIL_OTP', ['TOTP', 'EMAIL_OTP'], 1), 'EMAIL_OTP', apiErr('CLOUD_UNAVAILABLE', 503))
  eq(p.methods, ['TOTP'], 'methods')
  eq(p.selected, 'TOTP', 'selected')
  eq(p.otp, null, 'otp')
})

test('CLOUD_UNAVAILABLE with EMAIL_OTP as the only method sends the person to the desk', () => {
  const p = fallbackErrorPatch(vm('EMAIL_OTP', ['EMAIL_OTP'], 1), 'EMAIL_OTP', apiErr('CLOUD_UNAVAILABLE', 503))
  ok(/desk/i.test(p.error ?? ''), `desk text: ${p.error}`)
  eq(p.methods, undefined, 'methods unchanged')
})

test('other errors show a user-facing sentence, never the raw edge message', () => {
  const p = fallbackErrorPatch(vm('TOTP', ['TOTP'], 1), 'TOTP', apiErr('VALIDATION_ERROR', 422))
  ok(/try again or ask the desk/i.test(p.error ?? ''), `generic text: ${p.error}`)
  ok(!(p.error ?? '').includes(' x'), 'no raw message')
})

// EO-11: staff codes 10 digits, legacy 8 still accepted.
test('codeLengths merges main + legacy lengths', () => {
  eq(codeLengths(10, [8]), [8, 10], 'lengths')
  eq(codeLengths(8, [8]), [8], 'dedup')
})

test('codeComplete accepts only allowed lengths of digits', () => {
  eq(codeComplete('12345678', [8, 10]), true, '8')
  eq(codeComplete('1234567890', [8, 10]), true, '10')
  eq(codeComplete('123456789', [8, 10]), false, '9')
  eq(codeComplete('1234abcd', [8, 10]), false, 'non-digits')
})

// KF-03 (edge signal from policy-fixes): FALLBACK_LOCKED + next_action.retry_after_s, nothing counted.
function locked(methods: FallbackMethod[], left: number, wait: number): DecisionResponse {
  const r = stepUp(methods, left, ['OFFLINE_FALLBACK_REQUIRED', 'FALLBACK_LOCKED'])
  return { ...r, next_action: { ...r.next_action, retry_after_s: wait } }
}

test('locked staff override: say so with the wait, send the person back to the other methods', () => {
  const next = reconcileFallback(vm('STAFF_OVERRIDE', ['TOTP', 'STAFF_OVERRIDE'], 1), locked(['TOTP', 'STAFF_OVERRIDE'], 1, 287))
  eq(next.selected, null, 'selected')
  ok(/Staff override temporarily locked/.test(next.error ?? '') && /287 s/.test(next.error ?? ''), `error: ${next.error}`)
  ok(!/not accepted/i.test(next.error ?? ''), 'not the counted-failure text')
})

test('locked TOTP with the only method: stays, explains the lock', () => {
  const next = reconcileFallback(vm('TOTP', ['TOTP'], 1), locked(['TOTP'], 1, 60))
  eq(next.selected, 'TOTP', 'selected')
  ok(/locked/i.test(next.error ?? '') && /desk/i.test(next.error ?? ''), `error: ${next.error}`)
})

// edge-app item 5: otp/send 503 EMAIL_UNAVAILABLE carries error.methods (EMAIL_OTP already dropped).
test('EMAIL_UNAVAILABLE on otp/send uses the edge methods and leaves the e-mail screen', () => {
  const e = apiErr('CLOUD_UNAVAILABLE', 503, { reason: 'EMAIL_UNAVAILABLE', details: { methods: ['TOTP'] } })
  const p = otpErrorPatch(vm('EMAIL_OTP', ['TOTP', 'EMAIL_OTP'], 1), { ...e, reason: 'EMAIL_UNAVAILABLE', methods: ['TOTP'] } as unknown as ApiError, ['TOTP'])
  eq(p.methods, ['TOTP'], 'methods')
  eq(p.selected, 'TOTP', 'selected')
})
test('OTP_SEND_CAP is not "a code was sent a moment ago"', () => {
  const e = { ...apiErr('RATE_LIMITED', 429), reason: 'OTP_SEND_CAP' } as unknown as ApiError
  const p = otpErrorPatch(vm('EMAIL_OTP', ['TOTP', 'EMAIL_OTP'], 1), e, null)
  ok(/another method/i.test(p.error ?? '') && !/moment ago/.test(p.error ?? ''), `error: ${p.error}`)
})
test('NO_EMAIL_ON_FILE with no edge list falls back to dropping EMAIL_OTP locally', () => {
  const e = { ...apiErr('INVALID_STATE', 409), reason: 'NO_EMAIL_ON_FILE' } as unknown as ApiError
  const p = otpErrorPatch(vm('EMAIL_OTP', ['CARD', 'TOTP', 'EMAIL_OTP'], 1), e, null)
  eq(p.methods, ['CARD', 'TOTP'], 'methods')
  eq(p.selected, null, 'selected')
})

// Review KA-05: with code_length 10 + legacy [8], an 8-digit prefix of a 10-digit code must never go out
// through Verify / Enter; an 8-digit legacy code needs its own explicit action.
test('staff code: Verify only at the configured length; legacy length is a separate explicit action', () => {
  eq(staffCodeAction('1234567890', 10, [8]), 'submit', '10 digits')
  eq(staffCodeAction('12345678', 10, [8]), 'legacy', '8 digits = explicit legacy only')
  eq(staffCodeAction('123456789', 10, [8]), null, '9 digits')
  eq(staffCodeAction('12345678', 8, [8]), 'submit', 'legacy == configured length')
  eq(staffCodeAction('1234abcd', 10, [8]), null, 'non-digits')
})

done('fallbackState.test.ts')
