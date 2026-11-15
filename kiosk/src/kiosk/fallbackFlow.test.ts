/**
 * Integration-level test of the SECOND_FACTOR flow (kiosk/fallbackFlow.ts, driven by KioskController) with a
 * scripted edge: select -> e-mail code -> R11 re-issue -> TOTP -> ALLOW; plus FALLBACK_LOCKED, CLOUD_UNAVAILABLE
 * and a reset while a request is in flight (review KA-04). No camera, no DOM.
 */
import { ApiError, type DecisionResponse, type FallbackMethod, type FallbackRequest, type OtpSendResponse } from '../api/types.ts'
import { done, eq, ok, test } from '../shared/testkit.ts'
import type { FallbackViewModel } from './controller'
import { FallbackFlow, type FallbackHost, type FallbackPorts } from './fallbackFlow.ts'

function resp(decision: DecisionResponse['decision'], methods: FallbackMethod[] | null, left: number | null, codes: string[] = []): DecisionResponse {
  return {
    attempt_id: 'att_1', kiosk_id: 'KIOSK_01', zone: 'MAIN_GATE', decision, reason_codes: codes, resolved_codes: [],
    next_action: {
      type: decision === 'ALLOW' ? 'OPEN_DOOR' : 'SECOND_FACTOR', steps: [], methods, challenge: null, attempts_left: left,
      retry_after_s: codes.includes('FALLBACK_LOCKED') ? 120 : null,
    },
    bio_result: 'BIO_PASS', schedule_result: 'IN_WINDOW', mode: 'ONLINE', cache_state: 'FRESH', candidate: null, scores: {},
    latency_ms: { total: 5 }, policy_version: null, bundle_version: null, display_message: null, stage: null,
  }
}

/** A host like KioskController: same-attempt SECOND_FACTOR responses go back into the flow. */
function harness(edge: Array<(req: FallbackRequest) => DecisionResponse | ApiError>) {
  const state = { vm: null as FallbackViewModel | null, terminal: [] as DecisionResponse[], fatal: [] as string[], gen: 0, submitted: [] as FallbackRequest[] }
  const ports: FallbackPorts = {
    sendOtp: async (): Promise<OtpSendResponse> => ({ otp_id: 'otp_1', destination_masked: 'a***@x.org' }) as OtpSendResponse,
    submitFallback: async (_id, req) => {
      state.submitted.push(req)
      const step = edge.shift()
      if (!step) throw new Error('unscripted submit')
      const out = step(req)
      if (out instanceof ApiError) throw out
      return out
    },
  }
  const host: FallbackHost = {
    current: () => state.vm,
    show: (vm) => {
      state.vm = vm
    },
    decided: (r) => {
      if (r.decision === 'STEP_UP' && flow.sameAttempt(r)) return
      state.vm = null
      state.terminal.push(r)
    },
    fatal: (e) => state.fatal.push(e.code),
    touch: () => undefined,
    gen: () => state.gen,
  }
  const flow = new FallbackFlow(ports, host)
  return { flow, state }
}

async function main(): Promise<void> {
  // select EMAIL_OTP -> code sent -> cloud verify unavailable (R11: EMAIL_OTP dropped, nothing counted)
  // -> TOTP is the only method left and is preselected -> ALLOW
  const h = harness([() => resp('STEP_UP', ['TOTP'], 1, []), () => resp('ALLOW', null, null, ['FALLBACK_OK'])])
  h.flow.enter(resp('STEP_UP', ['TOTP', 'EMAIL_OTP'], 1))
  h.flow.select('EMAIL_OTP')
  await h.flow.requestOtp()
  const sentOtp = h.state.vm?.otp?.otp_id
  await h.flow.submit({ method: 'EMAIL_OTP', code: '123456', otp_id: 'otp_1' })
  const afterR11 = h.state.vm
  await h.flow.submit({ method: 'TOTP', code: '654321' })
  test('full flow: e-mail -> R11 re-issue -> TOTP -> ALLOW', () => {
    eq(sentOtp, 'otp_1', 'otp shown after send')
    eq(afterR11?.selected, 'TOTP', 'only remaining method preselected')
    eq(afterR11?.otp, null, 'stale e-mail code dropped')
    ok(!/not accepted/i.test(afterR11?.error ?? ''), `no false rejection: ${afterR11?.error}`)
    eq(h.state.submitted.map((r) => r.method), ['EMAIL_OTP', 'TOTP'], 'never resubmits a dropped method')
    eq(h.state.terminal.map((r) => r.decision), ['ALLOW'], 'terminal decision handed to the host')
  })

  const l = harness([() => resp('STEP_UP', ['TOTP', 'STAFF_OVERRIDE'], 1, ['FALLBACK_LOCKED'])])
  l.flow.enter(resp('STEP_UP', ['TOTP', 'STAFF_OVERRIDE'], 1))
  l.flow.select('STAFF_OVERRIDE')
  await l.flow.submit({ method: 'STAFF_OVERRIDE', staff_id: 's_guard01', code: '1234567890' })
  test('FALLBACK_LOCKED: back to the picker with the lock text, nothing terminal', () => {
    eq(l.state.vm?.selected, null, 'picker')
    ok(/temporarily locked/.test(l.state.vm?.error ?? ''), `lock text: ${l.state.vm?.error}`)
    eq(l.state.terminal, [], 'no terminal decision')
  })

  const c = harness([() => new ApiError('CLOUD_UNAVAILABLE', 503, 'cloud verify down')])
  c.flow.enter(resp('STEP_UP', ['CARD', 'EMAIL_OTP'], 1))
  c.flow.select('EMAIL_OTP')
  await c.flow.submit({ method: 'EMAIL_OTP', code: '111111', otp_id: 'otp_1' })
  test('CLOUD_UNAVAILABLE on EMAIL_OTP submit offers the other method', () => {
    eq(c.state.vm?.methods, ['CARD'], 'methods')
    eq(c.state.vm?.selected, 'CARD', 'selected')
    eq(c.state.vm?.busy, false, 'not busy')
  })

  const x = harness([() => new ApiError('ATTEMPT_CLOSED', 409, 'closed')])
  x.flow.enter(resp('STEP_UP', ['TOTP'], 1))
  await x.flow.submit({ method: 'TOTP', code: '000000' })
  test('ATTEMPT_CLOSED goes to the host as fatal', () => eq(x.state.fatal, ['ATTEMPT_CLOSED'], 'fatal'))

  test('busy fallback refuses a second submit and a user cancel', () => {
    const b = harness([() => resp('ALLOW', null, null)])
    b.flow.enter(resp('STEP_UP', ['STAFF_OVERRIDE'], 1))
    void b.flow.submit({ method: 'STAFF_OVERRIDE', staff_id: 's_guard01', code: '1234567890' })
    eq(b.state.vm?.busy, true, 'busy while the edge decides')
    eq(b.flow.cancelAllowed(), false, 'cancel refused')
    void b.flow.submit({ method: 'STAFF_OVERRIDE', staff_id: 's_guard01', code: '1234567890' })
    eq(b.state.submitted.length, 1, 'single submission')
  })

  const r = harness([() => resp('ALLOW', null, null)])
  r.flow.enter(resp('STEP_UP', ['TOTP'], 1))
  const pending = r.flow.submit({ method: 'TOTP', code: '123456' })
  r.state.gen += 1 // the controller reset meanwhile (idle timeout)
  await pending
  test('a response after a reset is dropped (never shown on the next person)', () => eq(r.state.terminal, [], 'terminal'))

  done('fallbackFlow.test.ts')
}

await main()
