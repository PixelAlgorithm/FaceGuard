/** Unit tests for kiosk/errorPolicy.ts (audit KF-M2, KF-06). Run: node --test "src/**\/*.test.ts". */
import { done, eq, test } from '../shared/testkit.ts'
import { errorAction, prefetchAllowed, type ErrorInput } from './errorPolicy.ts'

const base: ErrorInput = { code: 'NONCE_EXPIRED', status: 409, message: '', unreachable: false, nonceRestarts: 0, serviceErrors: 0, inStepUp: false }

// Primary attempt: unchanged behaviour.
test('nonce error on the primary attempt restarts silently', () => {
  eq(errorAction(base).kind, 'nonce-restart', 'kind')
})
test('nonce restarts are capped at 3', () => {
  eq(errorAction({ ...base, nonceRestarts: 3 }).kind, 'transient', 'kind')
})
test('rate limit wins over everything', () => {
  eq(errorAction({ ...base, code: 'RATE_LIMITED', status: 429, inStepUp: true }).kind, 'rate-limited', 'kind')
})
test('kiosk refusal is a configuration error', () => {
  eq(errorAction({ ...base, code: 'FORBIDDEN', status: 403, message: 'kiosk_id not served by this edge' }).kind, 'kiosk-refusal', 'kind')
})
test('unreachable edge -> service error', () => {
  eq(errorAction({ ...base, code: 'NETWORK', status: 0, unreachable: true }).kind, 'service-error', 'kind')
})

// KF-M2: during a challenge / fallback step the open step-up must never be silently abandoned.
test('nonce error during a step-up is shown, not a silent rescan', () => {
  eq(errorAction({ ...base, inStepUp: true }).kind, 'step-up-lost', 'kind')
})
test('transient codes during a step-up are shown, not a silent rescan', () => {
  for (const code of ['ATTEMPT_CLOSED', 'VALIDATION_ERROR', 'INVALID_STATE', 'NONCE_REUSED']) {
    eq(errorAction({ ...base, code, inStepUp: true }).kind, 'step-up-lost', code)
  }
})

// KF-06: session/start with recapture_of closes the parent attempt, so it must be sent exactly once.
test('no session prefetch while a recapture chain is open', () => {
  eq(prefetchAllowed('att_parent'), false, 'recapture')
  eq(prefetchAllowed(null), true, 'fresh')
})

done('errorPolicy.test.ts')
