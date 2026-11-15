/**
 * The SECOND_FACTOR (fallback) step of the kiosk flow, extracted from KioskController so the whole sequence
 * can be tested under plain Node with a scripted edge (kiosk/fallbackFlow.test.ts, review KA-04). The
 * controller is the host: it owns the view, the idle timer, the generation counter and decision routing.
 *
 * Rules (unchanged from the controller): one request at a time (busy), a response that arrives after a reset
 * (generation changed) is dropped, a same-attempt SECOND_FACTOR response is reconciled in place
 * (fallbackState.reconcileFallback: R8 / R11 / FALLBACK_LOCKED), ATTEMPT_CLOSED / ATTEMPT_NOT_FOUND are fatal,
 * other failures become a user-facing message (fallbackErrorPatch / otpErrorPatch).
 */
import { asApiError, type ApiError, type DecisionResponse, type FallbackMethod, type FallbackRequest, type OtpSendResponse } from '../api/types.ts'
import type { FallbackViewModel } from './controller'
import { edgeMethodsOf, fallbackErrorPatch, keepSelected, otpErrorPatch, reconcileFallback } from './fallbackState.ts'
import { userCancelAllowed } from './viewRules.ts'

/** The two edge calls of this step. */
export interface FallbackPorts {
  sendOtp(attemptId: string): Promise<OtpSendResponse>
  submitFallback(attemptId: string, req: FallbackRequest): Promise<DecisionResponse>
}

/** What the flow needs from the controller. */
export interface FallbackHost {
  /** the fallback view model on screen, or null when another view is shown */
  current(): FallbackViewModel | null
  show(vm: FallbackViewModel): void
  /** a decision for this attempt arrived (the host routes it like any other response) */
  decided(resp: DecisionResponse): void
  /** the attempt is gone on the edge (ATTEMPT_CLOSED / ATTEMPT_NOT_FOUND) */
  fatal(err: ApiError): void
  /** user activity: keeps the fallback screen alive */
  touch(): void
  /** bumped on every reset; work started under an older value is dropped */
  gen(): number
}

const FATAL_CODES: ReadonlySet<string> = new Set(['ATTEMPT_CLOSED', 'ATTEMPT_NOT_FOUND'])

export class FallbackFlow {
  private readonly ports: FallbackPorts
  private readonly host: FallbackHost

  constructor(ports: FallbackPorts, host: FallbackHost) {
    this.ports = ports
    this.host = host
  }

  /** First SECOND_FACTOR response of an attempt: show the method picker (the only method preselected). */
  enter(resp: DecisionResponse): void {
    const methods = resp.next_action.methods ?? []
    this.host.show({
      decision: resp,
      methods,
      selected: keepSelected(null, methods),
      otp: null,
      busy: false,
      error: null,
      attemptsLeft: resp.next_action.attempts_left,
    })
    this.host.touch()
  }

  /** Same-attempt SECOND_FACTOR response (R8 / R11 / FALLBACK_LOCKED): reconcile in place. */
  sameAttempt(resp: DecisionResponse): boolean {
    const vm = this.host.current()
    if (!vm || vm.decision.attempt_id !== resp.attempt_id || resp.next_action.type !== 'SECOND_FACTOR') return false
    this.host.show(reconcileFallback(vm, resp))
    this.host.touch()
    return true
  }

  /** KF-10: no user cancel while the edge is checking a code. */
  cancelAllowed(): boolean {
    const vm = this.host.current()
    return vm === null || userCancelAllowed({ kind: 'fallback', busy: vm.busy })
  }

  select(method: FallbackMethod | null): void {
    this.patch({ selected: method, error: null })
    this.host.touch()
  }

  async requestOtp(): Promise<void> {
    const vm = this.host.current()
    if (!vm || vm.busy) return
    const gen = this.host.gen()
    this.patch({ busy: true, error: null })
    this.host.touch()
    try {
      const otp = await this.ports.sendOtp(vm.decision.attempt_id)
      if (gen === this.host.gen()) this.patch({ otp, busy: false })
    } catch (e) {
      if (gen !== this.host.gen()) return
      const err = asApiError(e)
      this.patch(otpErrorPatch(vm, err, edgeMethodsOf(err)))
    }
  }

  async submit(req: FallbackRequest): Promise<void> {
    const vm = this.host.current()
    if (!vm || vm.busy) return
    const gen = this.host.gen()
    this.patch({ busy: true, error: null })
    this.host.touch()
    try {
      const resp = await this.ports.submitFallback(vm.decision.attempt_id, req)
      if (gen !== this.host.gen()) return
      this.host.decided(resp)
    } catch (e) {
      if (gen !== this.host.gen()) return
      const err = asApiError(e)
      if (err && FATAL_CODES.has(err.code)) {
        this.host.fatal(err)
        return
      }
      this.patch(fallbackErrorPatch(vm, req.method, err))
    }
  }

  private patch(p: Partial<FallbackViewModel>): void {
    const vm = this.host.current()
    if (vm) this.host.show({ ...vm, ...p })
  }
}
