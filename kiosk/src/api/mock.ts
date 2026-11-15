/**
 * In-browser MOCK edge implementing the same contract as the real edge (VITE_MOCK=1 or ?mock=1).
 * Demo safety net: emulates the DECISION_POLICY §9 matrix for the selected scenario, the step-up
 * resolution rules (§9.6), mode/sync-queue behaviour (SC2) and a minimal hash-chained store.
 * Shared state lives in localStorage + BroadcastChannel so /admin in another tab sees kiosk decisions.
 * All latencies here are SIMULATED - never put mock numbers on a slide.
 */
import { DEFAULT_KIOSK_ID, STORAGE_KEYS, THRESHOLDS, getKioskId } from '../config'
import {
  parseAccessUpdate,
  parseAccessUsers,
  parseDemoClock,
  parseEnroll,
  parseEnrolledUsers,
  parseErase,
  parseRefresh,
  parseRevoke,
  parseRotate,
} from './access'
import {
  mockBundleIssuedAt,
  mockBundleVersion,
  mockEarliestUtcMs,
  mockEnroll,
  mockErase,
  mockListAccess,
  mockListEnrolled,
  mockPutAccess,
  mockRefreshBundle,
  mockRevoke,
  mockRotateCodes,
  mockScheduleRole,
} from './mockAccess'
import { DEFAULT_MOCK_SCENARIO, MOCK_CREDENTIALS, findScenario, type MockScenario } from './mockScenarios'
import { orderCodes } from './reasonOrder'
import {
  ApiError,
  DEFORMATION_ACTIONS,
  type AccessUpdate,
  type AccessUpdateResult,
  type AccessUsersResponse,
  type BundleRefresh,
  type DemoClockStatus,
  type EnrolledUsersResponse,
  type EraseResponse,
  type ModeDemoClock,
  type RevokeRequest,
  type RevokeResult,
  type RotateCodesRequest,
  type RotateCodesResult,
  type BioResult,
  type Candidate,
  type ChallengeAction,
  type ChallengeMeta,
  type ChallengeSpec,
  type Decision,
  type DecisionResponse,
  type DemoClockRequest,
  type EdgeApi,
  type EnrollMeta,
  type EnrollResponse,
  type EdgeEventsHandlers,
  type EvalContext,
  type FallbackMethod,
  type FallbackRequest,
  type FlashStep,
  type ForceMode,
  type FramesMeta,
  type HealthResponse,
  type LatencyMs,
  type MetricsResponse,
  type Mode,
  type ModeResponse,
  type ModeState,
  type NextAction,
  type OtpSendResponse,
  type ProbeResponse,
  type RandomChallengeMode,
  type RenderedEvent,
  type RenderedReport,
  type SessionStartRequest,
  type SessionStartResponse,
} from './types'

const CHANNEL = 'hid-mock-events'

/** Test knobs (URL only, not persisted): ?mocklat=<ms> fixes the simulated edge latency, ?mockwin=<ms> the flash window. */
const MOCK_PARAMS = new URLSearchParams(window.location.search)
const MOCK_LATENCY_MS = Number(MOCK_PARAMS.get('mocklat')) || null
const MOCK_WINDOW_MS = Number(MOCK_PARAMS.get('mockwin')) || null
/** ?mockslowcloud=1: report cloud_match.degraded and decide ONLINE scenarios locally (OFFLINE, P7). */
const MOCK_SLOW_CLOUD = MOCK_PARAMS.get('mockslowcloud') === '1'
const CANDIDATE: Candidate = { user_id: 'u_3c4d', display: 'Priya N.', role: 'student' }
/** Edge probe part limit (API.md v1.3 §3.1a: > 2 MB -> 413). */
const PROBE_MAX_BYTES = 2 * 1024 * 1024

// ---------------------------------------------------------------- helpers

function rand(): number {
  const a = new Uint32Array(1)
  crypto.getRandomValues(a)
  return a[0] / 2 ** 32
}
const randInt = (lo: number, hi: number) => lo + Math.floor(rand() * (hi - lo + 1))
const pickOne = <T,>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)]
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
const isoNow = () => new Date().toISOString()
const round2 = (x: number) => Math.round(x * 100) / 100

function randomId(prefix: string): string {
  const a = new Uint8Array(10)
  crypto.getRandomValues(a)
  return prefix + Array.from(a, (b) => b.toString(36).padStart(2, '0')).join('').slice(0, 16).toUpperCase()
}

/** scores.signals as the edge reports them (edge/policy/engine.py SCORE_KEYS): one status per signal. */
function mockSignals(bio: MockScenario['bio'], codes: string[], flash: boolean, injection: boolean): Record<string, string> {
  const spoof = bio === 'FAIL_SPOOF'
  const has = (c: string) => codes.includes(c)
  return {
    pad: spoof && !has('SPOOF_MOIRE') && !has('SPOOF_DEVICE_DETECTED') ? 'FAIL' : bio === 'UNSURE_LIVENESS' && !has('RANDOM_CHALLENGE') ? 'UNSURE' : 'PASS',
    device: has('SPOOF_DEVICE_DETECTED') ? 'FAIL' : 'PASS',
    moire: has('SPOOF_MOIRE') ? 'FAIL' : 'PASS',
    // flash is advisory on the live edge (liveness.flash.enforce: false)
    flash: flash ? (spoof ? 'ADVISORY_FAIL' : 'ADVISORY_PASS') : 'NOT_AVAILABLE',
    mask: codes.some((c) => c.startsWith('SPOOF_MASK')) ? 'FAIL' : codes.some((c) => c.startsWith('MASK_')) ? 'UNSURE' : 'PASS',
    depth: 'NOT_AVAILABLE',
    injection: injection ? 'FAIL' : 'PASS',
  }
}

async function sha256Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('')
}

function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return '[' + v.map(canonicalJson).join(',') + ']'
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>
    return '{' + Object.keys(o).sort().map((k) => JSON.stringify(k) + ':' + canonicalJson(o[k])).join(',') + '}'
  }
  return JSON.stringify(v ?? null)
}

function percentile(values: number[], p: number): number | null {
  if (values.length === 0) return null
  const s = [...values].sort((a, b) => a - b)
  const rank = Math.max(1, Math.ceil((p / 100) * s.length)) // nearest-rank
  return s[rank - 1]
}

/** Wilson upper bound (95 %), or rule of 3 when there are zero errors. Mock metrics only. */
function upperBound95(errors: number, n: number): number | null {
  if (n === 0) return null
  if (errors === 0) return Math.min(1, 3 / n)
  const z = 1.96
  const p = errors / n
  const denom = 1 + (z * z) / n
  const centre = p + (z * z) / (2 * n)
  const margin = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))
  return Math.min(1, (centre + margin) / denom)
}

const IST = 'Asia/Kolkata'

function istMinutes(epochMs: number): number {
  const parts = new Intl.DateTimeFormat('en-GB', { timeZone: IST, hour: '2-digit', minute: '2-digit', hourCycle: 'h23' })
    .formatToParts(new Date(epochMs))
  const h = Number(parts.find((p) => p.type === 'hour')?.value ?? 0)
  const m = Number(parts.find((p) => p.type === 'minute')?.value ?? 0)
  return h * 60 + m
}

function fmtHHMM(minutes: number): string {
  const m = ((Math.round(minutes) % 1440) + 1440) % 1440
  return `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`
}

/** POST /v1/admin/clock / GET /v1/mode demo_clock (contract shape) for the mock's offset. */
function mockDemoClock(offsetMs: number | null): DemoClockStatus {
  const nowMs = Date.now() + (offsetMs ?? 0)
  const earliest = mockEarliestUtcMs()
  const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z')
  const istDate = (ms: number) => new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Kolkata', year: 'numeric', month: '2-digit', day: '2-digit' }).format(ms)
  const rollback = offsetMs !== null && nowMs < earliest
  return {
    active: offsetMs !== null,
    now_local: fmtHHMM(istMinutes(nowMs)),
    now_utc: iso(nowMs),
    offset_s: Math.round((offsetMs ?? 0) / 1000),
    date_local: istDate(nowMs),
    bundle_issued_at: mockBundleIssuedAt(),
    earliest_utc: iso(earliest),
    earliest_local: fmtHHMM(istMinutes(earliest)),
    earliest_date_local: istDate(earliest),
    bundle_rollback: rollback,
    cache_state: rollback ? 'INVALID' : 'FRESH',
  }
}

/** Mock campus schedule for the demo user (SC1): 08:00-20:00 IST, 15 min grace (0 for high-risk zones). */
const MOCK_WINDOW = { start: 8 * 60, end: 20 * 60, grace: 15 }

function scheduleAt(minutes: number, highRisk: boolean): 'IN_WINDOW' | 'GRACE_WINDOW' | 'OUTSIDE_WINDOW' {
  if (minutes >= MOCK_WINDOW.start && minutes < MOCK_WINDOW.end) return 'IN_WINDOW'
  const grace = highRisk ? 0 : MOCK_WINDOW.grace
  if ((minutes >= MOCK_WINDOW.start - grace && minutes < MOCK_WINDOW.start) || (minutes >= MOCK_WINDOW.end && minutes < MOCK_WINDOW.end + grace)) {
    return 'GRACE_WINDOW'
  }
  return 'OUTSIDE_WINDOW'
}

// ---------------------------------------------------------------- shared (cross-tab) state

interface StoreRecord {
  attempt_id: string
  seq: number
  kiosk_id: string
  zone: string
  ts_utc: string
  user_id: string | null
  candidate_user_id: string | null
  decision: Decision
  reason_codes: string[]
  resolved_codes: string[]
  scores: Record<string, number>
  fallback: { method: FallbackMethod; staff_id?: string } | null
  schedule_version: number
  cache_state: 'FRESH'
  mode: Mode
  prev_hash: string
  record_hash: string
}

interface HistoryItem {
  at: number
  attemptId: string
  decision: Decision
  mode: Mode
  codes: string[]
  latency: LatencyMs
  /** face lock -> decision RENDERED (from POST rendered), primary decision only */
  lockToDecision: number | null
  primary: boolean
  label: string | null
}

type MockChannelMsg =
  | { kind: 'decision'; decision: DecisionResponse; eval: EvalContext | null }
  | { kind: 'rendered'; event: RenderedEvent }

interface MockShared {
  scenario: string
  forced: ForceMode
  state: ModeState
  since: string
  lastCloudOkAt: string | null
  syncStartedAt: number | null
  queue: StoreRecord[]
  seq: number
  headHash: string | null
  lastSyncAt: string | null
  history: HistoryItem[]
  /** demo clock: offset (ms) added to real time; null = real time */
  clockOffsetMs: number | null
  denyTimes: number[]
  lockedUntil: number
  evalContext: EvalContext | null
  /** §3.14a random-challenge control (AUTO in the mock = scenario-driven only, no random draw). */
  randomChallenge: RandomChallengeMode
}

function freshShared(): MockShared {
  return {
    scenario: DEFAULT_MOCK_SCENARIO,
    forced: 'AUTO',
    state: 'ONLINE',
    since: isoNow(),
    lastCloudOkAt: isoNow(),
    syncStartedAt: null,
    queue: [],
    seq: 0,
    headHash: null,
    lastSyncAt: null,
    history: [],
    clockOffsetMs: null,
    denyTimes: [],
    lockedUntil: 0,
    evalContext: null,
    randomChallenge: 'AUTO',
  }
}

export function loadMockShared(): MockShared {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEYS.mockState)
    if (raw) return { ...freshShared(), ...(JSON.parse(raw) as Partial<MockShared>) }
  } catch {
    /* corrupted -> fresh */
  }
  return freshShared()
}

function saveShared(s: MockShared): void {
  try {
    window.localStorage.setItem(STORAGE_KEYS.mockState, JSON.stringify(s))
  } catch {
    /* ignore */
  }
}

function updateShared(fn: (s: MockShared) => void): MockShared {
  const s = loadMockShared()
  fn(s)
  saveShared(s)
  return s
}

export function getMockScenarioId(): string {
  return loadMockShared().scenario
}

export function setMockScenarioId(id: string): void {
  updateShared((s) => {
    s.scenario = findScenario(id).id
  })
}

export function resetMockState(): void {
  saveShared(freshShared())
}

/** Effective connectivity: forced OFFLINE, or an offline scenario simulating "cloud down". */
function computeMode(s: MockShared): { mode: Mode; state: ModeState; reason: string | null } {
  const scen = findScenario(s.scenario)
  if (s.forced === 'OFFLINE') return { mode: 'OFFLINE', state: 'OFFLINE', reason: 'forced' }
  if (scen.offline) return { mode: 'OFFLINE', state: 'OFFLINE', reason: 'heartbeat_timeout' }
  if (s.queue.length > 0) return { mode: 'OFFLINE', state: 'SYNCING', reason: 'syncing' }
  return { mode: 'ONLINE', state: 'ONLINE', reason: null }
}

/** Drain the sync queue while SYNCING: one record acked every 700 ms (simulated cloud /v1/sync). */
function tickSync(s: MockShared): void {
  const { state } = computeMode(s)
  if (state === 'SYNCING') {
    const started = s.syncStartedAt ?? Date.now()
    s.syncStartedAt = started
    const acked = Math.floor((Date.now() - started) / 700)
    if (acked > 0) {
      s.queue.splice(0, acked)
      s.syncStartedAt = started + acked * 700
      s.lastSyncAt = isoNow()
    }
    if (s.queue.length === 0) s.syncStartedAt = null
  } else if (state === 'OFFLINE') {
    s.syncStartedAt = null
  }
  const next = computeMode(s)
  if (next.state !== s.state) {
    s.state = next.state
    s.since = isoNow()
  }
  if (next.mode === 'ONLINE') s.lastCloudOkAt = isoNow()
}

// ---------------------------------------------------------------- per-attempt state (kiosk tab)

type Step = 'CHALLENGE' | 'SECOND_FACTOR'

interface MockAttempt {
  attemptId: string
  kioskId: string
  zone: string
  highRisk: boolean
  nonce: string
  mode: Mode
  scenario: MockScenario
  recaptureCount: number
  closed: boolean
  steps: Step[]
  triggerCodes: string[]
  methods: FallbackMethod[] | null
  challenge: ChallengeSpec | null
  challengeRetries: number
  factorAttempts: number
  passedFactor: FallbackMethod | null
  staffId: string | null
  bio: BioResult | null
  sched: string | null
  otp: { otp_id: string; code: string; expires: number } | null
  label: string | null
  faceLockAt: number | null
  createdAt: number
  scores: Record<string, number | null>
  /** scores.signals (per-signal status, API.md v1.3 §1) of the frames decision */
  signals: Record<string, string> | null
  rendered: boolean
  /** early cloud probe received (one per attempt, before frames) */
  probed: boolean
  framesIn: boolean
}

function zoneFor(kioskId: string): { zone: string; highRisk: boolean } {
  const id = kioskId.toUpperCase()
  if (id.includes('SRV') || id.includes('SERVER')) return { zone: 'SERVER_ROOM', highRisk: true }
  if (id.includes('LIB')) return { zone: 'LIBRARY', highRisk: false }
  if (id.includes('LAB')) return { zone: 'LAB_A', highRisk: false }
  return { zone: 'MAIN_GATE', highRisk: false }
}

const SCHED_CODE: Record<string, string> = {
  GRACE_WINDOW: 'SCHEDULE_GRACE_WINDOW',
  OUTSIDE_WINDOW: 'SCHEDULE_OUTSIDE_WINDOW',
  NO_ENTITLEMENT: 'SCHEDULE_NO_ENTITLEMENT',
  ZONE_NOT_PERMITTED: 'SCHEDULE_ZONE_NOT_PERMITTED',
  HOLIDAY: 'SCHEDULE_HOLIDAY',
  REVOKED: 'SCHEDULE_REVOKED',
}
const DENY_TYPE = new Set(['OUTSIDE_WINDOW', 'NO_ENTITLEMENT', 'ZONE_NOT_PERMITTED', 'HOLIDAY', 'REVOKED'])
const SCHED_CONTACT_DESK = new Set(['NO_ENTITLEMENT', 'ZONE_NOT_PERMITTED', 'REVOKED'])

function action(type: NextAction['type'], extra: Partial<NextAction> = {}): NextAction {
  return { type, steps: [], methods: null, challenge: null, attempts_left: null, retry_after_s: null, ...extra }
}

function methodsFor(att: MockAttempt): FallbackMethod[] {
  const m = THRESHOLDS.stepup.methods
  const list =
    att.mode === 'OFFLINE'
      ? att.highRisk
        ? m.offlineHighRisk
        : m.offlineDefault
      : att.highRisk
        ? m.onlineHighRisk
        : m.onlineDefault
  return list.filter((x): x is FallbackMethod => ['TOTP', 'CARD', 'EMAIL_OTP', 'STAFF_OVERRIDE'].includes(x))
}

function newChallenge(): ChallengeSpec {
  const deformation = pickOne(DEFORMATION_ACTIONS)
  const secondary = pickOne<ChallengeAction>(['BLINK', 'TURN_LEFT', 'TURN_RIGHT'])
  const actions: ChallengeAction[] = rand() < 0.5 ? [deformation, secondary] : [secondary, deformation]
  return {
    challenge_id: randomId('chl_'),
    nonce: randomId('n_'),
    actions,
    step_window_ms: THRESHOLDS.challenge.stepWindowMs,
    min_reaction_ms: THRESHOLDS.challenge.minReactionMs,
    expires_at: new Date(Date.now() + THRESHOLDS.challenge.sessionTtlS * 1000).toISOString(),
  }
}

function newFlashSequence(windowMs: number): FlashStep[] {
  // Off-primary palette; no two consecutive colours equal; saturated red at most once (photosensitivity).
  const palette = ['#FF3333', '#33FF33', '#3333FF', '#FFFFFF', '#FFFF33']
  const count = 3 // matches the edge: exactly 3 colours x ~233 ms in the 700 ms window (API.md v1.2)
  const steps: FlashStep[] = []
  let offset = 0
  let prev = ''
  let redUsed = false
  for (let i = 0; i < count; i++) {
    const last = i === count - 1
    // Equal split like the edge (233/233/234). The old 250 ms floor + jitter left the last step < 200 ms
    // in a 700 ms window, so the kiosk's photosensitivity guard refused it (no-flash path) at random.
    const duration = last ? windowMs - offset : Math.floor(windowMs / count)
    let color = pickOne(palette)
    while (color === prev || (redUsed && color === '#FF3333')) color = pickOne(palette)
    if (color === '#FF3333') redUsed = true
    prev = color
    steps.push({ color, offset_ms: offset, duration_ms: duration })
    offset += duration
  }
  return steps
}

function simulatedLatency(mode: Mode): LatencyMs {
  if (MOCK_LATENCY_MS) {
    const total = MOCK_LATENCY_MS
    return { total, liveness: Math.round(total * 0.6), match: Math.round(total * 0.8), schedule: 1, policy: 1 }
  }
  const liveness = randInt(95, 160)
  const match = mode === 'ONLINE' ? randInt(280, 460) : randInt(35, 70)
  const schedule = mode === 'ONLINE' ? randInt(3, 18) : randInt(1, 3)
  const policy = randInt(1, 4)
  return { total: Math.max(liveness, match) + schedule + policy + 6, liveness, match, schedule, policy }
}

// ---------------------------------------------------------------- the mock API

export class MockEdgeApi implements EdgeApi {
  readonly kind = 'mock' as const
  readonly baseUrl = 'mock://edge'
  private attempts = new Map<string, MockAttempt>()
  private channel: BroadcastChannel | null =
    typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel(CHANNEL) : null
  private localListeners = new Set<(m: MockChannelMsg) => void>()
  private decidedOnce = new Set<string>()

  private broadcast(msg: MockChannelMsg): void {
    try {
      this.channel?.postMessage(msg)
    } catch {
      /* ignore */
    }
    for (const l of this.localListeners) l(msg)
  }

  async markRendered(attemptId: string, report: RenderedReport): Promise<void> {
    const att = this.attempts.get(attemptId)
    if (!att || att.rendered) return
    att.rendered = true
    updateShared((s) => {
      const item = s.history.find((h) => h.attemptId === attemptId && h.primary)
      if (item) item.lockToDecision = report.rendered_at_ms - report.face_lock_at_ms
    })
    this.broadcast({ kind: 'rendered', event: { attempt_id: attemptId, ...report, decision_ms: report.rendered_at_ms - report.face_lock_at_ms } })
  }

  // ------------------------------------------------ kiosk endpoints

  async sessionStart(req: SessionStartRequest): Promise<SessionStartResponse> {
    await sleep(randInt(6, 18))
    const shared = updateShared(tickSync)
    const scenario = findScenario(shared.scenario)
    const { mode } = computeMode(shared)
    const kioskId = req.kiosk_id || getKioskId()
    if (kioskId !== DEFAULT_KIOSK_ID) {
      // Same refusal as the real edge: it serves only its runtime kiosk_id.
      throw new ApiError(
        'INVALID_STATE',
        409,
        `kiosk switch to ${kioskId} refused: the policy runtime evaluates attempts only for ${DEFAULT_KIOSK_ID} (mock edge)`,
      )
    }
    const z = zoneFor(kioskId)
    const prior = req.recapture_of ? this.attempts.get(req.recapture_of) : undefined
    const attemptId = randomId('att_')
    const nonce = randomId('n_')
    const windowMs = MOCK_WINDOW_MS ?? THRESHOLDS.flash.durationMs
    this.attempts.set(attemptId, {
      attemptId,
      kioskId,
      zone: z.zone,
      highRisk: z.highRisk || scenario.highRisk === true,
      nonce,
      mode,
      scenario,
      recaptureCount: prior ? prior.recaptureCount + 1 : 0,
      closed: false,
      steps: [],
      triggerCodes: [],
      methods: null,
      challenge: null,
      challengeRetries: 0,
      factorAttempts: 0,
      passedFactor: null,
      staffId: null,
      bio: null,
      sched: null,
      otp: null,
      label: null,
      faceLockAt: null,
      createdAt: Date.now(),
      scores: {},
      signals: null,
      rendered: false,
      probed: false,
      framesIn: false,
    })
    return {
      attempt_id: attemptId,
      nonce,
      flash_sequence: req.flash_enabled ? newFlashSequence(windowMs) : [],
      capture: { frames: THRESHOLDS.quality.framesPerAttempt, window_ms: windowMs, max_width_px: 1280, jpeg_quality: 0.85 },
      mode,
      expires_at: new Date(Date.now() + 10_000).toISOString(),
    }
  }

  private requireAttempt(attemptId: string): MockAttempt {
    const att = this.attempts.get(attemptId)
    if (!att) throw new ApiError('ATTEMPT_NOT_FOUND', 404, `Unknown attempt ${attemptId}`, attemptId)
    if (att.closed) throw new ApiError('ATTEMPT_CLOSED', 409, 'Attempt already decided', attemptId)
    return att
  }

  async submitProbe(attemptId: string, probe: Blob): Promise<ProbeResponse> {
    const att = this.requireAttempt(attemptId)
    if (att.framesIn) throw new ApiError('INVALID_STATE', 409, 'probe after frames', attemptId)
    if (att.probed) throw new ApiError('INVALID_STATE', 409, 'probe already received for this attempt', attemptId)
    if (probe.size > PROBE_MAX_BYTES) throw new ApiError('PAYLOAD_TOO_LARGE', 413, `probe is ${probe.size} bytes (max ${PROBE_MAX_BYTES})`, attemptId)
    if (probe.size === 0) throw new ApiError('VALIDATION_ERROR', 422, 'probe is empty', attemptId)
    att.probed = true
    await sleep(randInt(3, 10))
    return { accepted: true, cloud: att.mode === 'OFFLINE' ? 'skipped' : 'started' }
  }

  async submitFrames(attemptId: string, frames: Blob[], meta: FramesMeta): Promise<DecisionResponse> {
    const att = this.requireAttempt(attemptId)
    if (att.framesIn) throw new ApiError('INVALID_STATE', 409, 'frames already received', attemptId)
    att.framesIn = true
    // Slow cloud: the match misses its budget -> this attempt is decided locally (OFFLINE, P7).
    if (MOCK_SLOW_CLOUD && att.mode === 'ONLINE') att.mode = 'OFFLINE'
    if (meta.nonce !== att.nonce) throw new ApiError('NONCE_REUSED', 409, 'Nonce mismatch', attemptId)
    if (frames.length !== meta.frame_timestamps_ms.length) {
      throw new ApiError('VALIDATION_ERROR', 422, 'frame count / timestamp mismatch', attemptId)
    }
    att.label = loadMockShared().evalContext?.label ?? null
    att.faceLockAt = meta.face_lock_at_ms
    const latency = simulatedLatency(att.mode)
    await sleep(latency.total)
    return this.emit(att, this.evaluateFrames(att, meta), latency)
  }

  private evaluateFrames(att: MockAttempt, meta: FramesMeta): Omit<DecisionResponse, 'latency_ms'> {
    const sc = att.scenario
    const off = att.mode === 'OFFLINE'
    const om = off ? ['OFFLINE_MODE'] : []
    const live = sc.bio === 'FAIL_SPOOF' ? 0.12 : sc.bio === 'UNSURE_LIVENESS' ? 0.71 : 0.94
    att.scores = {
      pad_mean: live,
      flash_r: sc.bio === 'FAIL_SPOOF' ? 0.08 : meta.flash_events.length ? 0.81 : null,
      moire: sc.bioCodes.includes('SPOOF_MOIRE') ? 0.83 : 0.12,
      device_conf: sc.bioCodes.includes('SPOOF_DEVICE_DETECTED') ? 0.77 : 0,
      match_local: sc.bio === 'FAIL_NOT_ENROLLED' ? 0.18 : sc.bio === 'UNSURE_MATCH' ? 0.47 : 0.72,
      match_margin: sc.bio === 'UNSURE_MATCH' ? 0.04 : 0.31,
      rekognition: off ? null : sc.bio === 'FAIL_NOT_ENROLLED' ? null : sc.bio === 'UNSURE_MATCH' ? 93.1 : 99.6,
      depth: null,
    }
    att.signals = mockSignals(sc.bio, sc.bioCodes, meta.flash_events.length > 0, meta.client_signals.virtual_camera_suspected)
    const done = (decision: Decision, codes: string[], next: NextAction, extra: Partial<DecisionResponse> = {}) => {
      if (decision !== 'STEP_UP') att.closed = true
      return this.base(att, decision, codes, next, extra)
    }

    // A1 rate limit (scenario, or >= 5 DENY in 180 s on this kiosk -> 60 s lockout)
    const shared = loadMockShared()
    if (sc.rateLimited || Date.now() < shared.lockedUntil) {
      const left = sc.rateLimited ? 60 : Math.ceil((shared.lockedUntil - Date.now()) / 1000)
      return done('DENY', ['RATE_LIMITED', ...om], action('NONE', { retry_after_s: left }), { stage: 'quality' })
    }
    // A4 injection (client flag) / A2 quality
    if (meta.client_signals.virtual_camera_suspected) {
      return done('DENY', ['INJECTION_VIRTUAL_CAMERA', ...om], action('NONE'), { bio_result: null, stage: 'injection' })
    }
    if (sc.qualityFirst && att.recaptureCount === 0) {
      const left = THRESHOLDS.quality.maxRecaptures - att.recaptureCount
      return left > 0
        ? done('STEP_UP', [...sc.qualityFirst, ...om], action('RECAPTURE', { steps: ['RECAPTURE'], attempts_left: left - 1 }), { stage: 'quality' })
        : done('DENY', [...sc.qualityFirst, ...om], action('CONTACT_DESK'), { stage: 'quality' })
    }

    // Biometric result
    if (sc.bio === 'FAIL_SPOOF' || sc.bio === 'FAIL_NOT_ENROLLED') {
      att.bio = 'BIO_FAIL'
      return done('DENY', [...sc.bioCodes, ...om], action(sc.bio === 'FAIL_NOT_ENROLLED' ? 'CONTACT_DESK' : 'NONE'), {
        bio_result: 'BIO_FAIL',
        candidate: null,
        stage: sc.bio === 'FAIL_NOT_ENROLLED' ? 'match' : 'liveness',
      })
    }
    const unsure = sc.bio === 'UNSURE_LIVENESS' || sc.bio === 'UNSURE_MATCH'
    att.bio = unsure ? 'BIO_UNSURE' : 'BIO_PASS'
    // With the demo clock active, scenarios that are "in window" follow the mock 08:00-20:00 schedule.
    const sched: string =
      shared.clockOffsetMs !== null && sc.sched === 'IN_WINDOW'
        ? scheduleAt(istMinutes(Date.now() + shared.clockOffsetMs), att.highRisk)
        : sc.sched
    att.sched = sched
    const sCode = SCHED_CODE[sched] ? [SCHED_CODE[sched]] : []
    const outsideMsg =
      sched === 'OUTSIDE_WINDOW' && sc.bio === 'PASS'
        ? `Live and recognised, but outside your access hours (${fmtHHMM(MOCK_WINDOW.start)}–${fmtHHMM(MOCK_WINDOW.end)})`
        : null
    const common = { bio_result: att.bio, schedule_result: sched, display_message: sc.displayMessage ?? outsideMsg }

    // Schedule (SC1): deny-type always DENY; BIO_UNSURE only proceeds IN_WINDOW
    if (DENY_TYPE.has(sched) || (unsure && sched !== 'IN_WINDOW')) {
      const next = unsure || SCHED_CONTACT_DESK.has(sched) ? 'CONTACT_DESK' : 'NONE'
      return done('DENY', [...sc.bioCodes, ...sCode, ...om], action(next), { ...common, stage: 'schedule' })
    }

    // Combine (N1/F1 ALLOW; otherwise STEP_UP with ordered steps)
    // §3.14a: a forced random challenge converts only a would-be ALLOW (never loosens a decision).
    const wouldAllow = !unsure && sched === 'IN_WINDOW' && !att.highRisk
    const rc = shared.randomChallenge
    const forcedChallenge = wouldAllow && (rc === 'FORCE' || rc === 'FORCE_NEXT')
    if (forcedChallenge && rc === 'FORCE_NEXT') {
      updateShared((s) => {
        s.randomChallenge = 'AUTO'
      })
    }
    if (wouldAllow && !forcedChallenge) {
      return done('ALLOW', ['ACCESS_OK', ...om], action('OPEN_DOOR'), { ...common, stage: 'final' })
    }
    const steps: Step[] = []
    const codes = forcedChallenge ? ['RANDOM_CHALLENGE'] : [...sc.bioCodes, ...sCode]
    if (sc.bio === 'UNSURE_LIVENESS' || forcedChallenge) steps.push('CHALLENGE')
    const needSf = sc.bio === 'UNSURE_MATCH' || sched === 'GRACE_WINDOW' || att.highRisk || off
    if (att.highRisk) codes.push(off ? 'OFFLINE_HIGH_RISK_ZONE' : 'SCHEDULE_HIGH_RISK_ZONE')
    if (needSf) steps.push('SECOND_FACTOR')
    codes.push(...om)
    if (off && needSf) codes.push('OFFLINE_FALLBACK_REQUIRED')
    att.steps = steps
    att.triggerCodes = orderCodes(codes)
    att.methods = needSf ? methodsFor(att) : null
    att.challenge = steps[0] === 'CHALLENGE' ? newChallenge() : null
    return done('STEP_UP', att.triggerCodes, this.pendingAction(att), {
      ...common,
      stage: steps[0] === 'CHALLENGE' ? 'liveness' : sc.bio === 'UNSURE_MATCH' ? 'match' : off ? 'offline' : 'schedule',
      display_message: steps[0] === 'CHALLENGE' ? 'Please follow the on-screen check' : 'Please verify your identity',
    })
  }

  private pendingAction(att: MockAttempt, attemptsLeft?: number): NextAction {
    const type = att.steps[0]
    return action(type, {
      steps: [...att.steps],
      methods: att.steps.includes('SECOND_FACTOR') ? att.methods : null,
      challenge: type === 'CHALLENGE' ? att.challenge : null,
      attempts_left:
        attemptsLeft ??
        (type === 'CHALLENGE'
          ? THRESHOLDS.challenge.softFailRetries - att.challengeRetries
          : THRESHOLDS.stepup.maxAttemptsPerStep - att.factorAttempts - 1),
    })
  }

  async submitChallenge(attemptId: string, meta: ChallengeMeta, frame: Blob | null): Promise<DecisionResponse> {
    void frame
    const att = this.requireAttempt(attemptId)
    if (att.steps[0] !== 'CHALLENGE' || !att.challenge) throw new ApiError('INVALID_STATE', 409, 'No challenge pending', attemptId)
    if (meta.challenge_id !== att.challenge.challenge_id || meta.nonce !== att.challenge.nonce) {
      throw new ApiError('NONCE_REUSED', 409, 'Challenge nonce mismatch', attemptId)
    }
    const latency: LatencyMs = { total: randInt(20, 45), liveness: randInt(12, 30), match: randInt(8, 20), schedule: 0, policy: 1 }
    await sleep(latency.total)
    const om = att.mode === 'OFFLINE' ? ['OFFLINE_MODE'] : []
    const deny = (codes: string[], msg: string) => {
      att.closed = true
      return this.emit(att, this.base(att, 'DENY', [...codes, ...om], action('NONE'), { stage: 'challenge', display_message: msg }), latency)
    }
    const C = THRESHOLDS.challenge
    let hard = !meta.same_track
    let soft = false
    let flatDeformation = false
    for (const [i, expected] of att.challenge.actions.entries()) {
      const r = meta.actions[i]
      if (!r || r.action !== expected || r.tracking_lost) {
        hard = true
        continue
      }
      if (r.started_at_ms !== null && r.started_at_ms - r.prompted_at_ms < C.minReactionMs) hard = true
      let passed: boolean
      if (r.action === 'SMILE' || r.action === 'OPEN_MOUTH' || r.action === 'PUFF_CHEEKS') {
        const abs = r.action === 'SMILE' ? C.smileAbsMin : r.action === 'OPEN_MOUTH' ? C.jawOpenAbsMin : C.cheekPuffAbsMin
        passed = r.peak >= abs && r.peak - r.baseline >= C.deformationRiseMin
        if (!passed) flatDeformation = true
      } else if (r.action === 'BLINK') {
        passed = r.completed_at_ms !== null && r.peak >= C.blinkCloseMin
      } else {
        // Mirrors the edge: turn = DELTA of yaw_peak_deg vs the neutral baseline yaw (+ = subject's left).
        const want = r.action === 'TURN_LEFT' ? 1 : -1
        const delta = r.yaw_peak_deg !== null ? r.yaw_peak_deg - r.baseline : 0
        if (delta * -want >= C.turnYawMinDeg) hard = true // clearly turned the wrong way
        passed = r.started_at_ms !== null && r.completed_at_ms !== null && delta * want >= C.turnYawMinDeg
      }
      if (!passed) soft = true
    }
    if (hard) return deny(['CHALLENGE_FAILED'], 'Challenge failed')
    if (soft) {
      if (att.challengeRetries < C.softFailRetries) {
        att.challengeRetries += 1
        att.challenge = newChallenge()
        return this.emit(
          att,
          this.base(att, 'STEP_UP', orderCodes([...att.triggerCodes, 'CHALLENGE_FAILED']), this.pendingAction(att, 0), {
            stage: 'challenge',
            display_message: 'Let’s try that once more',
          }),
          latency,
        )
      }
      return deny(
        flatDeformation ? ['CHALLENGE_FAILED', 'MASK_CUE_RIGID'] : ['CHALLENGE_FAILED'],
        flatDeformation ? 'Challenge failed: no facial movement detected' : 'Challenge failed',
      )
    }
    att.steps.shift()
    att.challenge = null
    return this.emit(att, this.afterStepPassed(att), latency)
  }

  private afterStepPassed(att: MockAttempt): Omit<DecisionResponse, 'latency_ms'> {
    if (att.steps.length > 0) {
      return this.base(att, 'STEP_UP', att.triggerCodes, this.pendingAction(att), {
        stage: 'challenge',
        display_message: 'Please verify your identity',
      })
    }
    att.closed = true
    const codes = ['ACCESS_OK', ...(att.passedFactor ? ['FALLBACK_OK'] : []), ...(att.mode === 'OFFLINE' ? ['OFFLINE_MODE'] : [])]
    return this.base(att, 'ALLOW', codes, action('OPEN_DOOR'), {
      resolved_codes: att.triggerCodes,
      stage: att.passedFactor ? 'fallback' : 'challenge',
      display_message: null,
    })
  }

  async sendOtp(attemptId: string): Promise<OtpSendResponse> {
    const att = this.requireAttempt(attemptId)
    await sleep(randInt(120, 260))
    if (att.mode === 'OFFLINE') throw new ApiError('INVALID_STATE', 409, 'Email OTP is not available offline', attemptId)
    if (att.steps[0] !== 'SECOND_FACTOR' || !att.methods?.includes('EMAIL_OTP')) {
      throw new ApiError('INVALID_STATE', 409, 'Email OTP not permitted for this attempt', attemptId)
    }
    att.otp = { otp_id: randomId('otp_'), code: MOCK_CREDENTIALS.EMAIL_OTP, expires: Date.now() + 300_000 }
    return { otp_id: att.otp.otp_id, destination_masked: 'p*****@pes.edu', expires_at: new Date(att.otp.expires).toISOString() }
  }

  async submitFallback(attemptId: string, req: FallbackRequest): Promise<DecisionResponse> {
    const att = this.requireAttempt(attemptId)
    if (att.steps[0] !== 'SECOND_FACTOR') throw new ApiError('INVALID_STATE', 409, 'No second factor pending', attemptId)
    const latency: LatencyMs = { total: randInt(8, 24), liveness: 0, match: 0, schedule: 0, policy: randInt(1, 3) }
    await sleep(latency.total)
    const allowed = att.methods?.includes(req.method) ?? false
    let ok = false
    if (allowed) {
      if (req.method === 'TOTP') ok = req.code === MOCK_CREDENTIALS.TOTP
      else if (req.method === 'STAFF_OVERRIDE') ok = !!req.staff_id?.trim() && req.code === MOCK_CREDENTIALS.STAFF_OVERRIDE
      else if (req.method === 'CARD') ok = (req.card_id ?? '').trim().toUpperCase() === MOCK_CREDENTIALS.CARD
      else if (req.method === 'EMAIL_OTP') {
        ok = !!att.otp && req.otp_id === att.otp.otp_id && req.code === att.otp.code && Date.now() < att.otp.expires
      }
    }
    if (ok) {
      att.passedFactor = req.method
      att.staffId = req.method === 'STAFF_OVERRIDE' ? (req.staff_id ?? null) : null
      att.steps.shift()
      return this.emit(att, this.afterStepPassed(att), latency)
    }
    att.factorAttempts += 1
    if (att.factorAttempts < THRESHOLDS.stepup.maxAttemptsPerStep) {
      return this.emit(
        att,
        this.base(att, 'STEP_UP', orderCodes([...att.triggerCodes, 'FALLBACK_FAILED']), this.pendingAction(att), {
          stage: 'fallback',
          display_message: 'Verification failed – please try again',
        }),
        latency,
      )
    }
    att.closed = true
    const om = att.mode === 'OFFLINE' ? ['OFFLINE_MODE'] : []
    return this.emit(
      att,
      this.base(att, 'DENY', ['FALLBACK_FAILED', ...om], action('NONE'), { stage: 'fallback', display_message: 'Verification failed' }),
      latency,
    )
  }

  // ------------------------------------------------ response assembly + side effects

  private base(
    att: MockAttempt,
    decision: Decision,
    codes: string[],
    next: NextAction,
    extra: Partial<DecisionResponse> = {},
  ): Omit<DecisionResponse, 'latency_ms'> {
    return {
      attempt_id: att.attemptId,
      kiosk_id: att.kioskId,
      zone: att.zone,
      decision,
      reason_codes: decision === 'ALLOW' ? codes : orderCodes(codes),
      resolved_codes: [],
      next_action: next,
      bio_result: att.bio,
      schedule_result: att.sched,
      mode: att.mode,
      cache_state: att.mode === 'OFFLINE' ? 'FRESH' : null,
      candidate: att.bio === 'BIO_FAIL' || att.bio === null ? null : { ...CANDIDATE, role: mockScheduleRole(CANDIDATE.user_id) ?? CANDIDATE.role },
      scores: { ...att.scores, ...(att.signals ? { signals: { ...att.signals } } : {}) },
      policy_version: THRESHOLDS.policyVersion,
      bundle_version: mockBundleVersion(),
      display_message: null,
      stage: 'final',
      ...extra,
    }
  }

  private async emit(att: MockAttempt, body: Omit<DecisionResponse, 'latency_ms'>, latency: LatencyMs): Promise<DecisionResponse> {
    const resp: DecisionResponse = { ...body, latency_ms: latency }
    const decidedAt = Date.now()
    await this.appendRecord(att, resp)
    const primary = !att.rendered && !this.decidedOnce.has(att.attemptId)
    this.decidedOnce.add(att.attemptId)
    const shared = updateShared((s) => {
      s.history.push({
        at: decidedAt,
        attemptId: att.attemptId,
        decision: resp.decision,
        mode: resp.mode,
        codes: resp.reason_codes,
        latency,
        lockToDecision: null,
        primary,
        label: att.label,
      })
      if (s.history.length > 500) s.history.splice(0, s.history.length - 500)
      if (resp.decision === 'DENY' && !resp.reason_codes.includes('RATE_LIMITED')) {
        s.denyTimes = [...s.denyTimes.filter((t) => decidedAt - t < 180_000), decidedAt]
        if (s.denyTimes.length >= 5) {
          s.lockedUntil = decidedAt + 60_000
          s.denyTimes = []
        }
      }
    })
    this.broadcast({ kind: 'decision', decision: resp, eval: shared.evalContext })
    return resp
  }

  /** Minimal record (SURPRISE_CHALLENGES §SC2.5): no images, no embeddings, scores rounded to 2 dp. */
  private async appendRecord(att: MockAttempt, resp: DecisionResponse): Promise<void> {
    const shared = loadMockShared()
    const prev = shared.headHash ?? (await sha256Hex('genesis:' + att.kioskId))
    const scores: Record<string, number> = {}
    for (const [k, v] of Object.entries(att.scores)) if (typeof v === 'number') scores[k] = round2(v)
    const record: Omit<StoreRecord, 'record_hash'> = {
      attempt_id: att.attemptId,
      seq: shared.seq + 1,
      kiosk_id: att.kioskId,
      zone: att.zone,
      ts_utc: isoNow(),
      user_id: resp.candidate?.user_id ?? null,
      candidate_user_id: resp.bio_result === 'BIO_FAIL' && att.scenario.bio === 'FAIL_SPOOF' ? CANDIDATE.user_id : null,
      decision: resp.decision,
      reason_codes: resp.reason_codes,
      resolved_codes: resp.resolved_codes,
      scores,
      fallback: att.passedFactor ? { method: att.passedFactor, ...(att.staffId ? { staff_id: att.staffId } : {}) } : null,
      schedule_version: mockBundleVersion(),
      cache_state: 'FRESH',
      mode: resp.mode,
      prev_hash: prev,
    }
    const recordHash = await sha256Hex(prev + canonicalJson(record))
    updateShared((s) => {
      s.seq = record.seq
      s.headHash = recordHash
      // Online decisions are synced immediately (ack -> purge). Offline ones wait in the queue.
      if (resp.mode === 'OFFLINE') s.queue.push({ ...record, record_hash: recordHash })
      else s.lastSyncAt = isoNow()
    })
  }

  // ------------------------------------------------ mode / health

  async getMode(): Promise<ModeResponse> {
    await sleep(randInt(2, 8))
    const s = updateShared(tickSync)
    const m = computeMode(s)
    return {
      mode: m.mode,
      state: m.state,
      since: s.since,
      forced: s.forced === 'OFFLINE',
      last_cloud_ok_at: s.lastCloudOkAt,
      reason: m.reason,
      schedule_bundle: {
        version: mockBundleVersion(),
        issued_at: mockBundleIssuedAt(),
        expires_at: new Date(Date.now() + 8 * 3600_000).toISOString(),
        signature_valid: true,
        cache_state: 'FRESH',
      },
      revocation_seq: 17,
      template_cache: { count: 6, model: 'arcface_r50 (mock)' },
      sync_queue_depth: s.queue.length,
      // the mock emulates DEMO_MODE=1: demo_clock is always present (R-E)
      demo_clock: { contract: true, ...mockDemoClock(s.clockOffsetMs) } satisfies ModeDemoClock,
      // The mock's cloud is never slow; the degraded badge is shown with ?mockslowcloud=1.
      cloud_match: { enabled: true, degraded: MOCK_SLOW_CLOUD && m.mode === 'ONLINE', recent: 10, misses: MOCK_SLOW_CLOUD ? 7 : 0, last_miss_at: null, last_ok_at: s.lastCloudOkAt },
      random_challenge: s.randomChallenge,
      kiosk_id: DEFAULT_KIOSK_ID,
      zone: zoneFor(DEFAULT_KIOSK_ID).zone,
      policy_version: THRESHOLDS.policyVersion,
      rate_limit: { enabled: true, locked: s.lockedUntil > Date.now(), retry_after_s: s.lockedUntil > Date.now() ? Math.ceil((s.lockedUntil - Date.now()) / 1000) : null },
      last_sync: s.lastSyncAt ? { at: s.lastSyncAt, report: { ok: true, accepted: 0, duplicates: 0, rejected: 0, bundle: 'not_modified', mock: true } } : null,
      server_flags: [],
      policy_bars: { pad_pass: 0.8, flash_enforce: false, moire_enforce: true, m2_rgb_enforce: true, rekognition: true, random_rate: 0.15, mock: true },
    }
  }

  async setRandomChallenge(token: string, mode: RandomChallengeMode): Promise<unknown> {
    this.requireToken(token)
    updateShared((s) => {
      s.randomChallenge = mode
    })
    return { random_challenge: mode }
  }

  async getHealth(): Promise<HealthResponse> {
    return { status: 'ok', version: 'mock', models_loaded: { mock: true }, depth_bridge: 'unavailable' }
  }

  // ------------------------------------------------ admin

  private requireToken(token: string): void {
    if (!token.trim()) throw new ApiError('UNAUTHORIZED', 401, 'X-Admin-Token required (mock accepts any non-empty token)')
  }

  async getMetrics(token: string): Promise<MetricsResponse> {
    this.requireToken(token)
    const s = updateShared(tickSync)
    const h = s.history
    // Like the edge: latency from each attempt's FIRST (frames) decision; counts/labels from its FINAL decision.
    const prim = h.filter((x) => x.primary)
    const finalBy = new Map<string, HistoryItem>()
    for (const x of h) finalBy.set(x.attemptId, x)
    const fin = [...finalBy.values()]
    const tally = (xs: string[]) => xs.reduce<Record<string, number>>((acc, k) => ({ ...acc, [k]: (acc[k] ?? 0) + 1 }), {})
    const reason: Record<string, number> = {}
    for (const x of fin) for (const c of x.codes) reason[c] = (reason[c] ?? 0) + 1
    const stat = (vals: number[]) => ({ p50: percentile(vals, 50), p95: percentile(vals, 95), n: vals.length })
    const byLabel: MetricsResponse['by_label'] = {}
    for (const label of [...new Set(fin.map((x) => x.label).filter((x): x is string => !!x))]) {
      const items = fin.filter((x) => x.label === label)
      const n = items.length
      if (label === 'bona_fide') {
        const rejected = items.filter((x) => x.decision === 'DENY').length
        byLabel[label] = {
          n,
          rejected,
          step_up: items.filter((x) => x.decision === 'STEP_UP').length,
          bpcer: n ? rejected / n : null,
          bpcer_upper_95: upperBound95(rejected, n),
        }
      } else {
        const accepted = items.filter((x) => x.decision === 'ALLOW').length
        byLabel[label] = { n, accepted, apcer: n ? accepted / n : null, apcer_upper_95: upperBound95(accepted, n) }
      }
    }
    return {
      window: { since: h.length ? new Date(h[0].at).toISOString() : null, until: isoNow() },
      attempts: fin.length,
      decisions: tally(fin.map((x) => x.decision)),
      by_mode: tally(fin.map((x) => x.mode)),
      reason_codes: reason,
      latency_ms: {
        total: stat(prim.map((x) => x.latency.total)),
        liveness: stat(prim.map((x) => x.latency.liveness ?? 0)),
        match: stat(prim.map((x) => x.latency.match ?? 0)),
        client: stat(prim.map((x) => x.lockToDecision).filter((x): x is number => x !== null)),
      },
      by_label: byLabel,
      sync: { queue_depth: s.queue.length, last_sync_at: s.lastSyncAt },
      note: 'MOCK EDGE - simulated latencies, not measurements',
    }
  }

  async setMode(token: string, force: ForceMode): Promise<unknown> {
    this.requireToken(token)
    updateShared((s) => {
      s.forced = force
      if (force === 'AUTO' && s.queue.length > 0) s.syncStartedAt = Date.now()
      tickSync(s)
    })
    return this.getMode()
  }

  async getStore(token: string): Promise<unknown> {
    this.requireToken(token)
    const s = updateShared(tickSync)
    return {
      table: 'decision_log',
      storage: 'mock: localStorage (real edge: SQLite, AES-GCM payload)',
      retention: 'purged on sync ack; unsynced max 24 h',
      chain_head: s.headHash,
      records: s.queue,
    }
  }

  async triggerSync(token: string): Promise<unknown> {
    this.requireToken(token)
    const before = loadMockShared()
    if (computeMode({ ...before, queue: [] }).mode === 'OFFLINE') {
      throw new ApiError('CLOUD_UNAVAILABLE', 503, 'Cloud unreachable – cannot sync while offline')
    }
    const accepted = before.queue.map((r) => r.attempt_id)
    updateShared((s) => {
      s.queue = []
      s.syncStartedAt = null
      s.lastSyncAt = isoNow()
      tickSync(s)
    })
    return { accepted, duplicates: [], rejected: [], flags: [], server_time: isoNow() }
  }

  async setEvalContext(token: string, ctx: EvalContext): Promise<unknown> {
    this.requireToken(token)
    updateShared((s) => {
      s.evalContext = ctx
    })
    return { ok: true, eval_context: ctx }
  }

  async clearEvalContext(token: string): Promise<unknown> {
    this.requireToken(token)
    updateShared((s) => {
      s.evalContext = null
    })
    return { ok: true, eval_context: null }
  }

  async resetRateLimit(token: string): Promise<unknown> {
    this.requireToken(token)
    updateShared((s) => {
      s.denyTimes = []
      s.lockedUntil = 0
    })
    return { ok: true }
  }

  async setDemoClock(token: string, req: DemoClockRequest): Promise<DemoClockStatus> {
    this.requireToken(token)
    if ('reset' in req) {
      updateShared((s) => {
        s.clockOffsetMs = null
      })
      return parseDemoClock(mockDemoClock(null))
    }
    const m = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(req.set_local)
    if (!m) throw new ApiError('VALIDATION_ERROR', 422, 'set_local must be HH:MM (00:00-23:59)')
    const target = Number(m[1]) * 60 + Number(m[2])
    const now = Date.now()
    const offset = (target - istMinutes(now)) * 60_000
    updateShared((s) => {
      s.clockOffsetMs = offset
    })
    return parseDemoClock(mockDemoClock(offset))
  }

  async getAttemptSignals(token: string, attemptId: string): Promise<unknown> {
    this.requireToken(token)
    const att = this.attempts.get(attemptId)
    if (!att) throw new ApiError('ATTEMPT_NOT_FOUND', 404, 'unknown attempt (mock keeps attempts per tab)', attemptId)
    return { attempt_id: attemptId, mock: true, signals: { flash: { amplitude: null, r: att.scores.flash_r ?? null, note: 'mock' }, scores: att.scores } }
  }

  async enroll(token: string, frames: Blob[], meta: EnrollMeta): Promise<EnrollResponse> {
    this.requireToken(token)
    await sleep(randInt(400, 900))
    return parseEnroll(mockEnroll(this.offlineNow(), meta, frames.length))
  }

  async deleteEnrollment(token: string, userId: string): Promise<EraseResponse> {
    this.requireToken(token)
    await sleep(randInt(50, 200))
    return parseErase(mockErase(this.offlineNow(), userId))
  }

  // ------------------------------------------------ access control (mock cloud master schedule)

  private offlineNow(): boolean {
    return computeMode(updateShared(tickSync)).mode === 'OFFLINE'
  }

  // Every mock result goes through the same strict contract parsers as the real edge's responses.
  async listEnrolledUsers(token: string): Promise<EnrolledUsersResponse> {
    this.requireToken(token)
    await sleep(randInt(5, 20))
    return parseEnrolledUsers(mockListEnrolled())
  }

  async listAccessUsers(token: string): Promise<AccessUsersResponse> {
    this.requireToken(token)
    await sleep(randInt(30, 120))
    const s = loadMockShared()
    return parseAccessUsers(mockListAccess(this.offlineNow(), Date.now() + (s.clockOffsetMs ?? 0)))
  }

  async putAccessUser(token: string, userId: string, req: AccessUpdate): Promise<AccessUpdateResult> {
    this.requireToken(token)
    await sleep(randInt(150, 400))
    return parseAccessUpdate(mockPutAccess(this.offlineNow(), userId, req))
  }

  async revokeAccessUser(token: string, userId: string, req: RevokeRequest): Promise<RevokeResult> {
    this.requireToken(token)
    await sleep(randInt(150, 400))
    return parseRevoke(mockRevoke(this.offlineNow(), userId, req))
  }

  async rotateStaffCodes(token: string, req: RotateCodesRequest): Promise<RotateCodesResult> {
    this.requireToken(token)
    await sleep(randInt(150, 400))
    return parseRotate(mockRotateCodes(this.offlineNow(), req))
  }

  async refreshBundle(token: string): Promise<BundleRefresh> {
    this.requireToken(token)
    await sleep(randInt(50, 150))
    return parseRefresh(mockRefreshBundle(this.offlineNow()))
  }

  subscribeEvents(token: string, handlers: EdgeEventsHandlers): () => void {
    if (!token.trim()) {
      handlers.onStatus?.('error')
      return () => undefined
    }
    handlers.onStatus?.('open')
    const deliver = (m: MockChannelMsg) => {
      if (m.kind === 'decision') handlers.onDecision(m.decision, m.eval as Record<string, unknown> | null)
      else handlers.onRendered?.(m.event)
    }
    this.localListeners.add(deliver)
    const ch = typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel(CHANNEL) : null
    if (ch) ch.onmessage = (ev: MessageEvent) => deliver(ev.data as MockChannelMsg)
    return () => {
      this.localListeners.delete(deliver)
      ch?.close()
    }
  }
}
