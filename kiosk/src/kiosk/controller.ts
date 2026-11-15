/**
 * KioskController - the kiosk flow as an explicit state machine, independent of React.
 *
 * scanning --face lock--> capturing (session/start + colour flash + 5 frames) --> deciding (frames POST)
 *   --> decision screen; the UI then follows next_action.type of EVERY response:
 *       OPEN_DOOR / NONE / CONTACT_DESK -> auto reset    RECAPTURE -> scanning with recapture_of
 *       CHALLENGE -> challenge prompts -> POST challenge  SECOND_FACTOR -> method picker -> POST fallback
 * Steps are therefore processed strictly in the order of next_action.steps (the edge sends steps[0]).
 * Fail-secure: any error shows "contact the desk"; nothing on the client can open the door.
 */
import { getApi } from '../api'
import {
  asApiError,
  type ChallengeActionResult,
  type ChallengeAction,
  type ChallengeMeta,
  type ChallengeSpec,
  type DecisionResponse,
  type FallbackMethod,
  type FallbackRequest,
  type FramesMeta,
  type OtpSendResponse,
  type SessionStartRequest,
  type SessionStartResponse,
} from '../api/types'
import { THRESHOLDS, UI, clearKioskOverride, getKioskId, kioskIdSource } from '../config'
import { CaptureCancelled, runFlashCapture, type CaptureOutput } from '../capture/attemptCapture'
import { CameraError, NO_LOCK, lockExposure, restoreExposure, trackSettingsSummary, type ExposureLock } from '../capture/camera'
import {
  ActionTracker,
  EMPTY_BASELINE,
  TrackContinuity,
  blendBaselineMeta,
  computeBaseline,
  type NeutralBaseline,
} from '../capture/challenge'
import { getEngine, type BlendSubset, type FrameAnalysis, type VisionEngine } from '../capture/engine'
import { checkFlashSafety } from '../capture/flash'
import { grabProbeFrame, sendProbe, type ProbeOutcome } from '../capture/probe'
import { assessQuality, type Guidance } from '../capture/quality'
import { epochNow, sleep } from '../capture/time'
import { CaptureLock } from '../shared/captureLock'
import { describeDecision, reasonText, triesLeftText, type DecisionCopy } from './reasons'

export interface ClientTiming {
  sessionStartMs: number | null
  captureWindowMs: number | null
  encodeMs: number | null
  uploadAndEdgeMs: number | null
  /** spans measured from t0 (capture time of the face-lock frame), ms */
  lockProcessedMs?: number | null // camera + detect latency of the lock frame
  sessionReadyMs?: number | null
  firstColourMs?: number | null // colour 0 on screen
  framesReadyMs?: number | null // last JPEG encoded
  responseMs?: number | null // decision received
  sessionPrefetched?: boolean
  /** early cloud probe result (arrives asynchronously; shown in the operator detail line) */
  probe?: ProbeOutcome | 'pending' | 'off'
}

export interface DecisionTiming {
  label: 'Decision time' | 'Verification time'
  /** Start of the measured span (epoch ms): face lock, or the first STEP_UP for verification time. */
  baseAtMs: number | null
  /** Set once the decision screen is PAINTED: rendered_at_ms - baseAtMs. */
  clientMs: number | null
  renderedAtMs: number | null
  /** Edge latency_ms.total */
  serverMs: number | null
  breakdown: ClientTiming | null
}

export interface DecisionViewModel {
  response: DecisionResponse
  copy: DecisionCopy
  timing: DecisionTiming
  autoAdvanceMs: number | null
  shownAt: number
  canContinue: boolean
}

export type ChallengePhase = 'ready' | 'prompt' | 'done' | 'submitting'

export interface ChallengeViewModel {
  decision: DecisionResponse
  phase: ChallengePhase
  index: number
  total: number
  action: ChallengeAction | null
  actions: ChallengeAction[]
  windowMs: number
  retry: boolean
}

export interface FallbackViewModel {
  decision: DecisionResponse
  methods: FallbackMethod[]
  selected: FallbackMethod | null
  otp: OtpSendResponse | null
  busy: boolean
  error: string | null
  attemptsLeft: number | null
}

export type KioskView =
  | { kind: 'boot'; stage: 'camera' | 'model' | 'ready' }
  | { kind: 'fatal'; title: string; message: string; hint: string | null }
  | { kind: 'scanning'; guidance: Guidance; lockProgress: number; rateLimitedUntil: number | null; note: string | null }
  | { kind: 'capturing' }
  | { kind: 'deciding' }
  | { kind: 'decision'; vm: DecisionViewModel }
  | { kind: 'challenge'; vm: ChallengeViewModel }
  | { kind: 'fallback'; vm: FallbackViewModel }
  | { kind: 'service-error'; title: string; message: string; retryAt: number }

export interface CameraSummary {
  label: string
  virtualMatch: string | null
  delegate: string
  deviceCount: number
  knownGood: boolean
  controls: string
}

export interface KioskSnapshot {
  view: KioskView
  flashEnabled: boolean
  kioskId: string
  camera: CameraSummary | null
  lastZone: string | null
  engineReady: boolean
}

/**
 * session/start for a kiosk_id this edge does not serve (edge/app.py _kiosk_refusal): 409 INVALID_STATE
 * "kiosk switch to X refused ..." (DEMO_MODE=1) or 403 FORBIDDEN "kiosk_id not served by this edge".
 * A configuration error, never a transient one: retrying loops forever on every face.
 */
export function isKioskRefusal(code: string, message: string): boolean {
  return (code === 'INVALID_STATE' && /kiosk switch/i.test(message)) || (code === 'FORBIDDEN' && /kiosk_id not served/i.test(message))
}

const TRANSIENT_CODES = new Set([
  'NONCE_EXPIRED',
  'NONCE_REUSED',
  'ATTEMPT_CLOSED',
  'ATTEMPT_NOT_FOUND',
  'VALIDATION_ERROR',
  'INVALID_STATE',
])

/** Shown while another tab (the /operator console) holds the one-capturing-tab lock. */
export const CAPTURE_PAUSED_NOTE = 'The operator console is capturing on this computer. Operator: press T here to take over.'
/** The lock is granted within a few ms at boot; only show the pause note if waiting lasts longer. */
const PAUSE_NOTE_AFTER_MS = 400

const r2 = (x: number) => Math.round(x * 100) / 100
const r4 = (x: number) => Math.round(x * 10000) / 10000
const finite = (x: number | undefined): number | null => (typeof x === 'number' && Number.isFinite(x) ? x : null)

function roundBlend(b: BlendSubset): BlendSubset {
  return {
    mouthSmileLeft: r4(b.mouthSmileLeft),
    mouthSmileRight: r4(b.mouthSmileRight),
    jawOpen: r4(b.jawOpen),
    cheekPuff: r4(b.cheekPuff),
    eyeBlinkLeft: r4(b.eyeBlinkLeft),
    eyeBlinkRight: r4(b.eyeBlinkRight),
  }
}

export class KioskController {
  private snap: KioskSnapshot = {
    view: { kind: 'boot', stage: 'camera' },
    flashEnabled: true,
    kioskId: getKioskId(),
    camera: null,
    lastZone: null,
    engineReady: false,
  }
  private readonly listeners = new Set<() => void>()
  private readonly api = getApi()
  private engine: VisionEngine | null = null
  private booting = false
  /** Generation counter: bumped on every attempt start and reset; stale async work bails out. */
  private gen = 0
  private readonly timers = new Set<number>()
  private pendingContinue: (() => void) | null = null
  private abort: AbortController | null = null
  private tintSink: ((color: string | null) => void) | null = null
  // scanning
  private prevFrame: FrameAnalysis | null = null
  private okSince: number | null = null
  private armedAt = 0
  private shownGuidance: Guidance = 'NO_FACE'
  private candidate: { g: Guidance; since: number } | null = null
  private recaptureOf: string | null = null
  private rateLimitedUntil = 0
  private serviceErrors = 0
  // step-up
  private faceLockAtMs = 0
  private stepUpStartedAt: number | null = null
  private pendingPrompt: { index: number; arm: () => void } | null = null
  private idleTimer = 0
  /** attempt_id whose primary decision render has not been reported yet (POST /rendered). */
  private renderPending: string | null = null
  private nonceRestarts = 0
  private debugTracker: ActionTracker | null = null
  /** capture.max_width_px from the latest session/start (drives "Move closer" + challenge frame size). */
  private uploadMaxWidth: number = UI.defaultUploadMaxWidth
  private uploadJpegQuality = 0.85
  /** session/start fired while the face is still stabilising, so it is ready at face lock. */
  private prefetched: { promise: Promise<SessionStartResponse>; key: string; at: number } | null = null
  /** One capturing tab at a time (fixes duplicate attempts with /operator capturing too). */
  private readonly captureLock = new CaptureLock('kiosk')
  private lockWaitSince = performance.now()
  /** Note passed to enterScanning (error / rate-limit text); the pause note overrides it while paused. */
  private scanNote: string | null = null

  // ------------------------------------------------ external store API

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  getSnapshot = (): KioskSnapshot => this.snap

  private set(patch: Partial<KioskSnapshot>): void {
    this.snap = { ...this.snap, ...patch }
    this.listeners.forEach((l) => l())
  }

  private setView(view: KioskView): void {
    // Face-crop statistics are needed every frame only while flashing (chroma), every other frame while
    // scanning (advisory gate) and never during the challenge (keeps the tracker at full frame rate).
    this.engine?.setCropMode(view.kind === 'capturing' ? 'all' : view.kind === 'scanning' ? 'half' : 'off')
    this.set({ view })
  }

  /** Live challenge tracker state for the ?debug=1 overlay. */
  getDebugChallenge(): { action: string; armed: boolean; frames: number; baseline: number; peak: number | null; complete: boolean } | null {
    const t = this.debugTracker
    if (!t) return null
    return { action: t.action, armed: t.armed, frames: t.framesSeen, baseline: t.baselineValue, peak: t.currentPeak, complete: t.complete }
  }

  /** Direct DOM sink for the flash tint (timestamps must be taken in the same rAF as the paint). */
  setTintSink(fn: ((color: string | null) => void) | null): void {
    this.tintSink = fn
  }

  getEngine(): VisionEngine | null {
    return this.engine
  }

  // ------------------------------------------------ boot

  async boot(): Promise<void> {
    if (this.engine || this.booting) return
    this.booting = true
    try {
      const engine = await getEngine((stage) => this.setView({ kind: 'boot', stage }))
      this.engine = engine
      this.set({
        engineReady: true,
        camera: {
          label: engine.camera.label,
          virtualMatch: engine.camera.virtualMatch,
          delegate: engine.delegate,
          deviceCount: engine.camera.deviceCount,
          knownGood: engine.camera.knownGood,
          controls: engine.camera.controls,
        },
      })
      console.info(`[camera] "${engine.camera.label}" · ${engine.camera.deviceCount} device(s) · controls: ${engine.camera.controls}`)
      this.captureLock.subscribe(this.onLockChange)
      if (document.visibilityState !== 'hidden') this.captureLock.enable()
      document.addEventListener('visibilitychange', this.onVisibility)
      engine.onFrame(this.onFrame)
      this.enterScanning(0)
    } catch (e) {
      console.error('[kiosk] boot failed', e)
      if (e instanceof CameraError) {
        const copy: Record<CameraError['kind'], [string, string]> = {
          denied: ['Camera access blocked', 'Operator: allow camera access for this page in the browser, then reload.'],
          not_found: ['No camera found', 'Operator: connect the kiosk camera, then reload.'],
          busy: ['Camera is busy', 'Operator: close other apps using the camera (Zoom, FaceTime, OBS...), then reload.'],
          insecure: ['Camera unavailable', 'Open the kiosk on http://localhost:5173 (camera needs a secure origin).'],
          other: ['Camera failed to start', e.message],
        }
        const [title, hint] = copy[e.kind]
        this.setView({ kind: 'fatal', title, message: 'This kiosk cannot check access right now.', hint })
      } else {
        this.setView({
          kind: 'fatal',
          title: 'Face model failed to load',
          message: e instanceof Error ? e.message : String(e),
          hint: 'Operator: run "npm run assets" in kiosk/ (offline model + wasm), then reload.',
        })
      }
    } finally {
      this.booting = false
    }
  }

  // ------------------------------------------------ timers

  private after(ms: number, fn: () => void): void {
    const gen = this.gen
    const run = () => {
      this.timers.delete(id)
      this.pendingContinue = null
      if (gen === this.gen) fn()
    }
    const id = window.setTimeout(run, ms)
    this.timers.add(id)
    this.pendingContinue = () => {
      window.clearTimeout(id)
      run()
    }
  }

  private clearTimers(): void {
    this.timers.forEach((id) => window.clearTimeout(id))
    this.timers.clear()
    this.pendingContinue = null
  }

  /** "Continue" button on the amber STEP_UP screen: skip the intro wait. */
  continueNow = (): void => {
    this.pendingContinue?.()
  }

  // ------------------------------------------------ one-capturing-tab lock

  /** A hidden kiosk tab gets no camera frames anyway: release the lock so /operator can capture. */
  private onVisibility = (): void => {
    if (document.visibilityState === 'hidden') this.captureLock.disable()
    else this.captureLock.enable()
  }

  private onLockChange = (): void => {
    if (!this.captureLock.isHeld()) this.lockWaitSince = performance.now()
    const view = this.snap.view
    if (view.kind === 'scanning') this.setView({ ...view, lockProgress: 0, note: this.currentNote() })
  }

  private currentNote(): string | null {
    const paused = !this.captureLock.isHeld() && performance.now() - this.lockWaitSince >= PAUSE_NOTE_AFTER_MS
    return paused ? CAPTURE_PAUSED_NOTE : this.scanNote
  }

  /** Operator key T on the kiosk: take the capture lock back from the /operator console. */
  takeOverCapture = (): void => {
    if (document.visibilityState !== 'hidden') this.captureLock.enable(true)
  }

  // ------------------------------------------------ scanning / face lock

  private enterScanning(rearmMs: number, note: string | null = null): void {
    this.clearTimers()
    window.clearTimeout(this.idleTimer)
    this.pendingPrompt = null
    this.okSince = null
    this.candidate = null
    this.shownGuidance = 'NO_FACE'
    this.armedAt = performance.now() + rearmMs
    this.tintSink?.(null)
    this.scanNote = note
    this.setView({
      kind: 'scanning',
      guidance: 'NO_FACE',
      lockProgress: 0,
      rateLimitedUntil: Date.now() < this.rateLimitedUntil ? this.rateLimitedUntil : null,
      note: this.currentNote(),
    })
  }

  private onFrame = (f: FrameAnalysis): void => {
    const view = this.snap.view
    if (view.kind !== 'scanning') {
      this.prevFrame = f
      this.okSince = null
      return
    }
    const now = performance.now()
    const limited = Date.now() < this.rateLimitedUntil
    const a = assessQuality(f, this.prevFrame, this.uploadMaxWidth)
    this.prevFrame = f
    let progress = 0
    // Only the tab holding the capture lock may prefetch a session or lock a face.
    const held = this.captureLock.isHeld()
    if (a.ok && now >= this.armedAt && !limited && held) {
      if (this.okSince === null) {
        this.okSince = f.perfMs
        this.prefetchSession()
      }
      const held = f.perfMs - this.okSince
      progress = Math.min(1, held / UI.lockStableMs)
      if (held >= UI.lockStableMs) {
        this.okSince = null
        void this.runAttempt(f)
        return
      }
    } else {
      this.okSince = null
    }
    // One instruction at a time, debounced so it does not flicker (OK shows immediately).
    if (a.guidance === 'OK') {
      this.shownGuidance = 'OK'
      this.candidate = null
    } else if (a.guidance !== this.shownGuidance) {
      if (!this.candidate || this.candidate.g !== a.guidance) this.candidate = { g: a.guidance, since: now }
      else if (now - this.candidate.since >= UI.guidanceDebounceMs) {
        this.shownGuidance = a.guidance
        this.candidate = null
      }
    } else {
      this.candidate = null
    }
    const q = Math.round(progress * 10) / 10
    const rl = limited ? this.rateLimitedUntil : null
    const note = this.currentNote()
    if (this.shownGuidance !== view.guidance || q !== view.lockProgress || rl !== view.rateLimitedUntil || note !== view.note) {
      this.setView({ ...view, guidance: this.shownGuidance, lockProgress: q, rateLimitedUntil: rl, note })
    }
  }

  // ------------------------------------------------ session prefetch

  private sessionRequest(): SessionStartRequest {
    const engine = this.engine
    return {
      kiosk_id: getKioskId(),
      claimed_user_id: null,
      client: {
        camera_label: engine?.camera.label ?? '',
        user_agent: navigator.userAgent,
        screen: { width: window.screen.width, height: window.screen.height, refresh_hz: engine?.refreshHz ?? 60 },
      },
      flash_enabled: this.snap.flashEnabled && THRESHOLDS.flash.enabled,
      ...(this.recaptureOf ? { recapture_of: this.recaptureOf } : {}),
    }
  }

  private sessionKey(req: SessionStartRequest): string {
    return `${req.kiosk_id}|${req.flash_enabled}|${req.recapture_of ?? ''}`
  }

  /** Fire session/start while the quality gate is still dwelling (removes the round trip after t0). */
  private prefetchSession(): void {
    const req = this.sessionRequest()
    const key = this.sessionKey(req)
    const p = this.prefetched
    if (p && p.key === key && Date.now() - p.at < UI.sessionPrefetchMaxAgeMs) return
    const promise = this.api.sessionStart(req)
    promise.catch(() => {
      if (this.prefetched?.promise === promise) this.prefetched = null
    })
    this.prefetched = { promise, key, at: Date.now() }
  }

  /** Use the prefetched session if it matches and has >= 3 s of nonce life left, else start one now. */
  private async takeSession(req: SessionStartRequest): Promise<{ session: SessionStartResponse; prefetched: boolean }> {
    const p = this.prefetched
    this.prefetched = null
    if (p && p.key === this.sessionKey(req) && Date.now() - p.at < UI.sessionPrefetchMaxAgeMs) {
      try {
        const session = await p.promise
        const left = Date.parse(session.expires_at) - Date.now()
        if (!Number.isFinite(left) || left > 3000) return { session, prefetched: true }
      } catch {
        /* fall through to a fresh request */
      }
    }
    return { session: await this.api.sessionStart(req), prefetched: false }
  }

  // ------------------------------------------------ main attempt (t0 = face lock)

  private async runAttempt(lockFrame: FrameAnalysis): Promise<void> {
    const engine = this.engine
    if (!engine || !lockFrame.face) return
    const gen = ++this.gen
    const alive = () => gen === this.gen
    const abort = new AbortController()
    this.abort = abort
    // t0 = capture time of the frame that completed the face lock (conservative: earliest timestamp).
    this.faceLockAtMs = lockFrame.epochMs
    // Early cloud probe: copy the face-lock frame NOW (one drawImage); it is encoded + posted after
    // session/start without being awaited, so it never delays the flash or the capture.
    const probeCanvas = UI.earlyProbe ? grabProbeFrame(engine, this.uploadMaxWidth) : null
    this.stepUpStartedAt = null
    const kioskId = getKioskId()
    this.set({ kioskId })
    this.setView({ kind: 'capturing' })

    const baselineFrames: FrameAnalysis[] = [lockFrame]
    const stopBaseline = engine.onFrame((f) => {
      if (f.face && f.perfMs <= lockFrame.perfMs + THRESHOLDS.challenge.baselineMs) baselineFrames.push(f)
    })
    const timing: ClientTiming = { sessionStartMs: null, captureWindowMs: null, encodeMs: null, uploadAndEdgeMs: null }
    const exposurePromise = UI.lockExposure ? lockExposure(engine.track) : Promise.resolve(NO_LOCK)
    const exposure = Promise.race([exposurePromise, sleep(250).then(() => NO_LOCK)])
    let lock: ExposureLock = NO_LOCK
    // Whatever happens (even a late lock), restore the camera's previous modes after this attempt.
    const restore = () => void exposurePromise.then((l) => restoreExposure(engine.track, l))
    timing.lockProcessedMs = Math.round(epochNow() - this.faceLockAtMs)
    try {
      const req: SessionStartRequest = { ...this.sessionRequest(), kiosk_id: kioskId }
      const t1 = performance.now()
      const taken = await this.takeSession(req)
      let session: SessionStartResponse = taken.session
      timing.sessionPrefetched = taken.prefetched
      if (!alive()) return
      const safety = checkFlashSafety(session.flash_sequence, THRESHOLDS.flash.maxChangesPerS)
      if (!safety.ok) {
        // Photosensitivity guard: never paint it - restart on the accessible non-flash path.
        console.warn(`[kiosk] refusing flash sequence (${safety.reason}); using flash_enabled=false`)
        session = await this.api.sessionStart({ ...req, flash_enabled: false })
        if (!alive()) return
      }
      timing.sessionStartMs = Math.round(performance.now() - t1)
      timing.sessionReadyMs = Math.round(epochNow() - this.faceLockAtMs)
      if (probeCanvas && session.mode === 'ONLINE') {
        timing.probe = 'pending'
        sendProbe(this.api, session.attempt_id, probeCanvas, session.capture.jpeg_quality || 0.85, (o) => {
          timing.probe = o
        })
      } else {
        timing.probe = 'off'
      }
      if (session.capture.max_width_px > 0) this.uploadMaxWidth = session.capture.max_width_px
      if (session.capture.jpeg_quality > 0) this.uploadJpegQuality = session.capture.jpeg_quality
      lock = await exposure
      if (!alive()) {
        restore()
        return
      }
      const capture = await runFlashCapture(
        engine,
        session.capture,
        session.flash_sequence,
        (c) => this.tintSink?.(c),
        abort.signal,
        UI.flashSaturate,
        UI.flashCameraLagMs,
      )
      stopBaseline()
      restore()
      if (!alive()) return
      timing.captureWindowMs = capture.windowMs
      timing.encodeMs = capture.encodeMs
      timing.firstColourMs = capture.captureStartedAtMs - this.faceLockAtMs
      timing.framesReadyMs = Math.round(epochNow() - this.faceLockAtMs)
      // POST first, render "Checking..." afterwards (keeps React work off the critical path).
      const meta = this.buildFramesMeta(engine, session, lockFrame, baselineFrames, capture, lock.locked)
      const t2 = performance.now()
      const pending = this.api.submitFrames(session.attempt_id, capture.frames, meta)
      this.setView({ kind: 'deciding' })
      const resp = await pending
      if (!alive()) return
      timing.uploadAndEdgeMs = Math.round(performance.now() - t2)
      timing.responseMs = Math.round(epochNow() - this.faceLockAtMs)
      this.recaptureOf = null
      this.nonceRestarts = 0
      this.renderPending = resp.attempt_id
      this.handleDecision(resp, {
        label: 'Decision time',
        baseAtMs: this.faceLockAtMs,
        clientMs: null,
        renderedAtMs: null,
        serverMs: finite(resp.latency_ms.total),
        breakdown: timing,
      })
    } catch (e) {
      stopBaseline()
      restore()
      if (e instanceof CaptureCancelled || !alive()) return
      this.handleError(e)
    } finally {
      if (this.abort === abort) this.abort = null
    }
  }

  private buildFramesMeta(
    engine: VisionEngine,
    session: SessionStartResponse,
    lock: FrameAnalysis,
    baselineFrames: FrameAnalysis[],
    capture: CaptureOutput,
    exposureLocked: boolean,
  ): FramesMeta {
    const face = lock.face
    const scale = Math.min(1, session.capture.max_width_px / lock.width)
    const { fps, jitterMs } = engine.timingStats()
    return {
      nonce: session.nonce,
      face_lock_at_ms: this.faceLockAtMs,
      capture_started_at_ms: capture.captureStartedAtMs,
      frame_timestamps_ms: capture.frameTimestampsMs,
      flash_events: capture.flashEvents,
      chroma_series: capture.chromaSeries,
      quality: {
        face_count: lock.faceCount,
        iod_px: r2((face?.iodPx ?? 0) * scale),
        yaw_deg: r2(face?.yawDeg ?? 0),
        pitch_deg: r2(face?.pitchDeg ?? 0),
        roll_deg: r2(face?.rollDeg ?? 0),
        blur_var: r2(face?.crop?.blurVar ?? 0),
        luma_mean: r2(face?.crop?.luma ?? 0),
        face_box: (face?.box ?? [0, 0, 0, 0]).map(r4) as [number, number, number, number],
      },
      client_signals: {
        camera_label: engine.camera.label,
        virtual_camera_suspected: engine.camera.virtualSuspected,
        device_count: engine.camera.deviceCount,
        track_settings: trackSettingsSummary(engine.camera, engine.track),
        fps_measured: r2(fps),
        frame_interval_jitter_ms: r2(jitterMs),
        exposure_locked: exposureLocked,
      },
      blendshapes: roundBlend(blendBaselineMeta(baselineFrames)),
    }
  }

  // ------------------------------------------------ decisions

  private stepUpTiming(resp: DecisionResponse): DecisionTiming {
    return {
      label: 'Verification time',
      baseAtMs: this.stepUpStartedAt,
      clientMs: null,
      renderedAtMs: null,
      serverMs: finite(resp.latency_ms.total),
      breakdown: null,
    }
  }

  /**
   * Called by the decision screen once it has been PAINTED. Displayed time = rendered - face lock.
   * The first decision of each attempt is reported (fire-and-forget) to POST /v1/attempt/{id}/rendered.
   */
  onDecisionRendered = (shownAt: number, renderedAtMs: number): void => {
    const v = this.snap.view
    if (v.kind !== 'decision' || v.vm.shownAt !== shownAt || v.vm.timing.renderedAtMs !== null) return
    const base = v.vm.timing.baseAtMs
    this.setView({
      kind: 'decision',
      vm: { ...v.vm, timing: { ...v.vm.timing, renderedAtMs, clientMs: base !== null ? renderedAtMs - base : null } },
    })
    const b = v.vm.timing.breakdown
    if (b && base !== null) {
      console.info(
        `[timing] face lock -> rendered ${renderedAtMs - base} ms | lock processed +${b.lockProcessedMs} | session ready +${b.sessionReadyMs}` +
          ` (${b.sessionPrefetched ? 'prefetched' : `round trip ${b.sessionStartMs} ms`}) | colour 0 on screen +${b.firstColourMs}` +
          ` | frames ready +${b.framesReadyMs} | decision received +${b.responseMs} (upload+edge ${b.uploadAndEdgeMs}, edge ${v.vm.timing.serverMs})`,
      )
    }
    const id = v.vm.response.attempt_id
    if (this.renderPending === id) {
      this.renderPending = null
      this.api
        .markRendered(id, { face_lock_at_ms: this.faceLockAtMs, rendered_at_ms: renderedAtMs })
        .catch((e) => console.warn('[kiosk] POST rendered failed (non-blocking)', e))
    }
  }

  private handleDecision(resp: DecisionResponse, timing: DecisionTiming): void {
    this.serviceErrors = 0
    if (resp.zone) this.set({ lastZone: resp.zone })
    const type = resp.next_action.type
    const show = (autoMs: number | null, canContinue = false) =>
      this.setView({
        kind: 'decision',
        vm: { response: resp, copy: describeDecision(resp), timing, autoAdvanceMs: autoMs, shownAt: Date.now(), canContinue },
      })
    this.clearTimers()
    window.clearTimeout(this.idleTimer)

    if (resp.decision !== 'STEP_UP') {
      const retry = resp.next_action.retry_after_s
      if (retry) this.rateLimitedUntil = Date.now() + retry * 1000
      show(UI.resultResetMs)
      this.after(UI.resultResetMs, () => this.reset())
      return
    }
    if (this.stepUpStartedAt === null) this.stepUpStartedAt = epochNow()

    if (type === 'RECAPTURE') {
      show(UI.recaptureIntroMs)
      this.after(UI.recaptureIntroMs, () => {
        this.recaptureOf = resp.attempt_id
        this.enterScanning(300)
      })
      return
    }
    if (type === 'CHALLENGE' && resp.next_action.challenge) {
      show(UI.stepUpIntroMs, true)
      this.after(UI.stepUpIntroMs, () => void this.runChallenge(resp))
      return
    }
    if (type === 'SECOND_FACTOR' && (resp.next_action.methods?.length ?? 0) > 0) {
      const v = this.snap.view
      if (v.kind === 'fallback' && v.vm.decision.attempt_id === resp.attempt_id) {
        // R8: code rejected but attempts remain -> stay on the code screen with an explanation.
        const left = resp.next_action.attempts_left
        this.setView({
          kind: 'fallback',
          vm: {
            ...v.vm,
            decision: resp,
            methods: resp.next_action.methods ?? v.vm.methods,
            busy: false,
            error: `${reasonText('FALLBACK_FAILED', 'STEP_UP')}${left !== null ? ` (${triesLeftText(left)})` : ''}`,
            attemptsLeft: left,
          },
        })
        this.touch()
        return
      }
      show(UI.stepUpIntroMs, true)
      this.after(UI.stepUpIntroMs, () => this.enterFallback(resp))
      return
    }
    // STEP_UP with no automatic path (CONTACT_DESK / NONE / malformed): fail secure, ask for help.
    show(UI.resultResetMs + 2000)
    this.after(UI.resultResetMs + 2000, () => this.reset())
  }

  private handleError(e: unknown): void {
    this.tintSink?.(null)
    const err = asApiError(e)
    console.error('[kiosk] request failed', e)
    if (err && (err.code === 'RATE_LIMITED' || err.status === 429)) {
      this.rateLimitedUntil = Date.now() + 60_000
      this.enterScanning(0, 'Too many attempts – please wait')
      return
    }
    // Stale / replayed nonce: silently start a fresh session (no message to the user).
    if (err && (err.code === 'NONCE_EXPIRED' || err.code === 'NONCE_REUSED') && this.nonceRestarts < 3) {
      this.nonceRestarts += 1
      this.recaptureOf = null
      this.stepUpStartedAt = null
      this.enterScanning(0)
      return
    }
    if (err && isKioskRefusal(err.code, err.message)) {
      // Operator error: the selected kiosk id is not served by this edge. Drop the override (admin selector
      // or ?kiosk=) so the kiosk returns to its own id instead of failing on every face.
      const refused = getKioskId()
      const source = kioskIdSource()
      clearKioskOverride()
      const retryMs = 8000
      this.prefetched = null
      this.clearTimers()
      this.setView({
        kind: 'service-error',
        title: 'Kiosk not configured for this gate',
        message: `This edge does not serve kiosk “${refused}”${source === 'query' ? ' (from ?kiosk= in the address)' : source === 'admin' ? ' (picked in the control panel)' : ''}. Switched back to ${getKioskId()}. Please contact the desk.`,
        retryAt: Date.now() + retryMs,
      })
      this.after(retryMs, () => this.reset())
      return
    }
    this.serviceErrors += 1
    if (err && TRANSIENT_CODES.has(err.code) && this.serviceErrors < 3) {
      this.recaptureOf = null
      this.stepUpStartedAt = null
      this.enterScanning(800, 'Let’s try that again')
      return
    }
    const unreachable = err?.isUnreachable ?? false
    const retryMs = 5000
    this.clearTimers()
    this.setView({
      kind: 'service-error',
      title: unreachable ? 'Access check unavailable' : 'Something went wrong',
      message: unreachable
        ? 'The kiosk service is not responding, so no access can be granted. Please contact the desk.'
        : `Please contact the desk.${err ? ` (${err.code})` : ''}`,
      retryAt: Date.now() + retryMs,
    })
    this.after(retryMs, () => this.reset())
  }

  // ------------------------------------------------ step-up: challenge

  /** Called by the prompt component in a layout effect, i.e. right before the prompt is painted. */
  markPrompted = (index: number): void => {
    if (this.pendingPrompt?.index === index) this.pendingPrompt.arm()
  }

  private async runChallenge(resp: DecisionResponse): Promise<void> {
    const engine = this.engine
    const spec = resp.next_action.challenge
    if (!engine || !spec) return
    const gen = this.gen
    const alive = () => gen === this.gen
    const base: ChallengeViewModel = {
      decision: resp,
      phase: 'ready',
      index: 0,
      total: spec.actions.length,
      action: null,
      actions: spec.actions,
      windowMs: spec.step_window_ms,
      retry: resp.reason_codes.includes('CHALLENGE_FAILED'),
    }
    this.setView({ kind: 'challenge', vm: base })

    // Recent frames: each action's baseline = MEDIAN of the face frames in the baseline_ms right before its
    // prompt appears (neutral face, robust to a blink), falling back to the whole ready period.
    const recent: FrameAnalysis[] = []
    const stopRecent = engine.onFrame((f) => {
      recent.push(f)
      if (recent.length > 90) recent.shift()
    })
    const baselineBeforePrompt = (): NeutralBaseline => {
      const last = recent[recent.length - 1]?.perfMs ?? 0
      const pre = recent.filter((f) => f.face && f.perfMs >= last - THRESHOLDS.challenge.baselineMs)
      return computeBaseline(pre.length >= 2 ? pre : recent, 'median') ?? EMPTY_BASELINE
    }
    await sleep(UI.challengeReadyMs)
    if (!alive()) {
      stopRecent()
      return
    }

    const continuity = new TrackContinuity()
    const stopContinuity = engine.onFrame((f) => continuity.update(f))
    const results: ChallengeActionResult[] = []
    const framesPerAction: number[] = []
    try {
      for (let i = 0; i < spec.actions.length; i++) {
        const step = await this.runChallengeStep(engine, spec, i, baselineBeforePrompt(), base)
        if (!alive()) return
        results.push(step.result)
        framesPerAction.push(step.frames)
        if (i < spec.actions.length - 1) {
          await sleep(UI.challengeBetweenStepsMs)
          if (!alive()) return
        }
      }
    } finally {
      stopContinuity()
      stopRecent()
      this.debugTracker = null
    }
    console.info(
      '[challenge]',
      results
        .map(
          (r, i) =>
            `${r.action}: frames=${framesPerAction[i]} baseline=${r.baseline} peak=${r.peak} started=${r.started_at_ms !== null}` +
            ` completed=${r.completed_at_ms !== null} lost=${r.tracking_lost}` +
            (r.started_at_ms !== null ? ` reaction=${r.started_at_ms - r.prompted_at_ms}ms` : '') +
            (r.yaw_peak_deg !== null ? ` yaw_peak=${r.yaw_peak_deg}` : '') +
            (r.landmark_shift !== null ? ` shift=${r.landmark_shift}` : ''),
        )
        .join(' | '),
      `same_track=${continuity.sameTrack()} (${continuity.describe()}) engine_fps=${engine.processedFps().toFixed(1)}`,
    )
    for (const [i, r] of results.entries()) {
      const deform = r.action === 'SMILE' || r.action === 'OPEN_MOUTH' || r.action === 'PUFF_CHEEKS'
      if (deform && (r.landmark_shift ?? 0) > 0.1 && r.peak - r.baseline < 0.05) {
        console.warn(
          `[challenge] ${r.action}: landmarks moved (shift ${r.landmark_shift}) but the blendshape stayed flat - check ?debug=1; if the bars do not move, try ?delegate=cpu`,
        )
      }
      if (framesPerAction[i] < 10) console.warn(`[challenge] ${r.action}: only ${framesPerAction[i]} camera frames analysed in the step window`)
    }
    this.setView({ kind: 'challenge', vm: { ...base, phase: 'submitting', index: spec.actions.length - 1 } })
    try {
      const frame = await engine.grabJpeg(this.uploadMaxWidth, this.uploadJpegQuality).catch(() => null)
      const meta: ChallengeMeta = {
        challenge_id: spec.challenge_id,
        nonce: spec.nonce,
        actions: results,
        same_track: continuity.sameTrack(),
      }
      const next = await this.api.submitChallenge(resp.attempt_id, meta, frame)
      if (!alive()) return
      this.handleDecision(next, this.stepUpTiming(next))
    } catch (e) {
      if (alive()) this.handleError(e)
    }
  }

  private runChallengeStep(
    engine: VisionEngine,
    spec: ChallengeSpec,
    index: number,
    baseline: NeutralBaseline,
    base: ChallengeViewModel,
  ): Promise<{ result: ChallengeActionResult; frames: number }> {
    return new Promise((resolve) => {
      const action = spec.actions[index]
      const tracker = new ActionTracker(action, baseline)
      this.debugTracker = tracker
      let done = false
      let windowTimer = 0
      let holdTimer = 0
      const finish = () => {
        if (done) return
        done = true
        stop()
        window.clearTimeout(windowTimer)
        window.clearTimeout(holdTimer)
        window.clearTimeout(armTimer)
        if (this.pendingPrompt?.index === index) this.pendingPrompt = null
        resolve({ result: tracker.result(), frames: tracker.framesSeen })
      }
      const arm = () => {
        if (tracker.armed) return
        tracker.arm(performance.now())
        windowTimer = window.setTimeout(finish, spec.step_window_ms)
      }
      this.pendingPrompt = { index, arm }
      // Safety net if the prompt component never mounts (should not happen).
      const armTimer = window.setTimeout(arm, 500)
      const stop = engine.onFrame((f) => {
        tracker.update(f)
        if (tracker.complete && !holdTimer) {
          const v = this.snap.view
          if (v.kind === 'challenge' && v.vm.index === index) this.setView({ kind: 'challenge', vm: { ...v.vm, phase: 'done' } })
          holdTimer = window.setTimeout(finish, UI.challengeHoldAfterCompleteMs)
        }
      })
      this.setView({ kind: 'challenge', vm: { ...base, phase: 'prompt', index, action } })
    })
  }

  // ------------------------------------------------ step-up: second factor / fallback

  private enterFallback(resp: DecisionResponse): void {
    const methods = resp.next_action.methods ?? []
    this.setView({
      kind: 'fallback',
      vm: {
        decision: resp,
        methods,
        selected: methods.length === 1 ? methods[0] : null,
        otp: null,
        busy: false,
        error: null,
        attemptsLeft: resp.next_action.attempts_left,
      },
    })
    this.touch()
  }

  /** Any interaction on the fallback screen keeps it alive; inactivity abandons the attempt. */
  touch = (): void => {
    window.clearTimeout(this.idleTimer)
    const gen = this.gen
    this.idleTimer = window.setTimeout(() => {
      if (gen === this.gen && this.snap.view.kind === 'fallback') this.reset()
    }, UI.fallbackIdleMs)
  }

  private patchFallback(patch: Partial<FallbackViewModel>): void {
    const v = this.snap.view
    if (v.kind === 'fallback') this.setView({ kind: 'fallback', vm: { ...v.vm, ...patch } })
  }

  selectMethod = (method: FallbackMethod | null): void => {
    this.patchFallback({ selected: method, error: null })
    this.touch()
  }

  requestOtp = async (): Promise<void> => {
    const v = this.snap.view
    if (v.kind !== 'fallback' || v.vm.busy) return
    const gen = this.gen
    this.patchFallback({ busy: true, error: null })
    this.touch()
    try {
      const otp = await this.api.sendOtp(v.vm.decision.attempt_id)
      if (gen === this.gen) this.patchFallback({ otp, busy: false })
    } catch (e) {
      if (gen !== this.gen) return
      const err = asApiError(e)
      if (err?.reason === 'NO_EMAIL_ON_FILE') {
        // the edge dropped EMAIL_OTP from this step (API.md §3.5): offer the remaining methods only
        const methods = v.vm.methods.filter((m) => m !== 'EMAIL_OTP')
        if (!methods.length) {
          this.patchFallback({ busy: false, error: 'No e-mail address on file. Please ask the desk for help.' })
          return
        }
        this.patchFallback({ busy: false, methods, selected: methods.length === 1 ? methods[0] : null, error: 'No e-mail address on file. Please choose another method.' })
        return
      }
      if (err && (err.code === 'RATE_LIMITED' || err.status === 429)) {
        const wait = err.extra.retry_after_s
        this.patchFallback({ busy: false, error: `A code was sent a moment ago. Please check your e-mail${wait ? ` or ask again in ${Math.ceil(wait)} s` : ''}.` })
        return
      }
      this.patchFallback({
        busy: false,
        error: err ? `Could not send the email code (${err.code}). Choose another method.` : 'Could not send the email code.',
      })
    }
  }

  submitFallback = async (req: FallbackRequest): Promise<void> => {
    const v = this.snap.view
    if (v.kind !== 'fallback' || v.vm.busy) return
    const gen = this.gen
    this.patchFallback({ busy: true, error: null })
    this.touch()
    try {
      const resp = await this.api.submitFallback(v.vm.decision.attempt_id, req)
      if (gen !== this.gen) return
      this.handleDecision(resp, this.stepUpTiming(resp))
    } catch (e) {
      if (gen !== this.gen) return
      const err = asApiError(e)
      if (err && (err.code === 'ATTEMPT_CLOSED' || err.code === 'ATTEMPT_NOT_FOUND')) {
        this.handleError(err)
        return
      }
      this.patchFallback({
        busy: false,
        error: err ? (err.isUnreachable ? 'Kiosk service not responding.' : err.message) : 'Verification failed.',
      })
    }
  }

  // ------------------------------------------------ operator / user controls

  reset = (): void => {
    this.gen++
    this.abort?.abort()
    this.abort = null
    this.tintSink?.(null)
    this.recaptureOf = null
    this.stepUpStartedAt = null
    this.set({ flashEnabled: true, kioskId: getKioskId() })
    if (this.engine) this.enterScanning(UI.rearmDelayMs)
  }

  /** Accessibility: no-flash path for the current person (resets to flash on after their attempt). */
  toggleFlash = (): void => {
    this.set({ flashEnabled: !this.snap.flashEnabled })
  }

  refreshKioskId = (): void => {
    this.set({ kioskId: getKioskId() })
  }
}

let controller: KioskController | null = null

export function getKioskController(): KioskController {
  if (!controller) {
    controller = new KioskController()
    // Dev-only debug handle for automated browser tests (never present in production builds).
    if (import.meta.env.DEV) (window as unknown as Record<string, unknown>).__hidKiosk = controller
  }
  return controller
}
