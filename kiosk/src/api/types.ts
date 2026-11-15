/**
 * Wire contract between the kiosk and the edge service.
 * Source: lead's API contract (docs/API.md v1.1) + docs/DECISION_POLICY.md §7 / §10.
 * Field names are snake_case exactly as on the wire.
 */
import type {
  ApiKeyCreate,
  ApiKeyCreated,
  ApiKeyInfo,
  AuditQuery,
  AuthAuditPage,
  AuthMe,
  AuthStatus,
  LoginRequest,
  LoginResult,
  MfaEnrolment,
  PasswordChange,
  Reauth,
  RolesCatalog,
  StaffAccount,
  StaffCreate,
  StaffPasswordReset,
  StaffUpdate,
} from './authTypes.ts'

export type Decision = 'ALLOW' | 'STEP_UP' | 'DENY'
export type Mode = 'ONLINE' | 'OFFLINE'
export type ModeState = 'ONLINE' | 'OFFLINE' | 'SYNCING'
export type NextActionType = 'OPEN_DOOR' | 'RECAPTURE' | 'CHALLENGE' | 'SECOND_FACTOR' | 'CONTACT_DESK' | 'NONE'
export type FallbackMethod = 'TOTP' | 'CARD' | 'EMAIL_OTP' | 'STAFF_OVERRIDE'
export type ChallengeAction = 'SMILE' | 'OPEN_MOUTH' | 'PUFF_CHEEKS' | 'BLINK' | 'TURN_LEFT' | 'TURN_RIGHT'
export type BioResult = 'BIO_PASS' | 'BIO_UNSURE' | 'BIO_FAIL'
export type CacheState = 'FRESH' | 'EXPIRED' | 'INVALID'

export const FALLBACK_METHODS: readonly FallbackMethod[] = ['TOTP', 'CARD', 'EMAIL_OTP', 'STAFF_OVERRIDE']
export const CHALLENGE_ACTIONS: readonly ChallengeAction[] = [
  'SMILE',
  'OPEN_MOUTH',
  'PUFF_CHEEKS',
  'BLINK',
  'TURN_LEFT',
  'TURN_RIGHT',
]
export const DEFORMATION_ACTIONS: readonly ChallengeAction[] = ['SMILE', 'OPEN_MOUTH', 'PUFF_CHEEKS']

// ---------------------------------------------------------------- session/start

export interface ClientInfo {
  camera_label: string
  user_agent: string
  screen: { width: number; height: number; refresh_hz: number }
}

export interface SessionStartRequest {
  kiosk_id: string
  claimed_user_id: string | null
  client: ClientInfo
  flash_enabled: boolean
  recapture_of?: string
}

export interface FlashStep {
  color: string // "#RRGGBB"
  offset_ms: number // from capture start
  duration_ms: number
}

export interface CaptureSpec {
  frames: number
  window_ms: number
  max_width_px: number
  jpeg_quality: number
}

export interface SessionStartResponse {
  attempt_id: string
  nonce: string
  flash_sequence: FlashStep[]
  capture: CaptureSpec
  mode: Mode
  expires_at: string
}

// ---------------------------------------------------------------- frames

export interface FlashEvent {
  step_index: number
  /**
   * colour as ISSUED by the edge. The kiosk paints its max-saturation variant (each channel >= 128 -> 255,
   * else 0: #FF4D4D -> #FF0000 ...) - a fixed mapping the edge can apply itself; not sent as an extra field.
   */
  color: string
  shown_at_ms: number // epoch ms (performance.timeOrigin + performance.now()) when the fill was painted
}

export interface ChromaSample {
  t_ms: number
  r: number
  g: number
  b: number
}

export interface QualityMeta {
  face_count: number
  iod_px: number // inter-ocular distance in uploaded-frame pixels
  yaw_deg: number // + = subject turned to their LEFT
  pitch_deg: number
  roll_deg: number
  blur_var: number // client Laplacian-variance estimate on a 112x112 face crop
  luma_mean: number // 0-255 on face ROI
  face_box: [number, number, number, number] // x, y, w, h normalised 0-1 (unmirrored frame)
}

export interface ClientSignals {
  camera_label: string
  virtual_camera_suspected: boolean
  device_count: number
  track_settings: Record<string, string | number | boolean>
  fps_measured: number
  frame_interval_jitter_ms: number
  exposure_locked: boolean
}

export interface BlendshapeBaseline {
  mouthSmileLeft: number
  mouthSmileRight: number
  jawOpen: number
  cheekPuff: number
  eyeBlinkLeft: number
  eyeBlinkRight: number
}

export interface FramesMeta {
  nonce: string
  face_lock_at_ms: number
  capture_started_at_ms: number
  frame_timestamps_ms: number[]
  flash_events: FlashEvent[]
  chroma_series: ChromaSample[]
  quality: QualityMeta
  client_signals: ClientSignals
  blendshapes: BlendshapeBaseline
}

// ---------------------------------------------------------------- decision

export interface ChallengeSpec {
  challenge_id: string
  nonce: string
  actions: ChallengeAction[]
  step_window_ms: number
  min_reaction_ms: number
  expires_at: string
}

export interface NextAction {
  type: NextActionType
  steps: string[]
  methods: FallbackMethod[] | null
  challenge: ChallengeSpec | null
  attempts_left: number | null
  retry_after_s: number | null
}

export interface LatencyMs {
  total: number
  liveness?: number
  match?: number
  schedule?: number
  policy?: number
  [stage: string]: number | undefined
}

export interface Candidate {
  user_id: string
  display: string
  /** From the verified schedule bundle (e.g. student, faculty); null if unknown. */
  role?: string | null
}

export interface DecisionResponse {
  attempt_id: string
  kiosk_id: string
  zone: string | null
  decision: Decision
  reason_codes: string[]
  resolved_codes: string[]
  next_action: NextAction
  bio_result: BioResult | null
  schedule_result: string | null
  mode: Mode
  cache_state: CacheState | null
  candidate: Candidate | null
  scores: Record<string, unknown>
  latency_ms: LatencyMs
  policy_version: string | null
  bundle_version: string | number | null
  display_message: string | null
  stage: string | null
}

// ---------------------------------------------------------------- challenge / fallback

export interface ChallengeActionResult {
  action: ChallengeAction
  prompted_at_ms: number
  started_at_ms: number | null
  completed_at_ms: number | null
  /** Neutral value. Blendshape actions: blendshape score. Turns: neutral signed yaw (deg, + = subject's left). */
  baseline: number
  /** Blendshape actions: max score in window. Turns: = yaw_peak_deg (signed). */
  peak: number
  /** Deformation actions only: max normalised cheek/nasolabial landmark displacement (units of IOD). */
  landmark_shift: number | null
  /** Turn actions only: absolute signed yaw (deg, + = subject's left) - extreme in the commanded direction
   *  (or the wrong-way extreme if the head clearly moved the wrong way). */
  yaw_peak_deg: number | null
  tracking_lost: boolean
}

export interface ChallengeMeta {
  challenge_id: string
  nonce: string
  actions: ChallengeActionResult[]
  same_track: boolean
}

export interface FallbackRequest {
  method: FallbackMethod
  code?: string
  card_id?: string
  staff_id?: string
  otp_id?: string
}

export interface OtpSendResponse {
  otp_id: string
  destination_masked: string
  expires_at: string
}

// ---------------------------------------------------------------- mode / health / admin

export interface ModeResponse {
  mode: Mode
  state: ModeState
  since: string | null
  forced: boolean
  /** a forced OFFLINE auto-reverts to AUTO at this time (POST /v1/admin/mode max_minutes, default 60) */
  forced_until: string | null
  /** schedule bundle cache state (public /v1/mode top-level; else schedule_bundle.cache_state); null = unknown, never FRESH */
  cache_state: CacheState | null
  last_cloud_ok_at: string | null
  reason: string | null
  schedule_bundle: {
    version: number | string | null
    expires_at: string | null
    signature_valid: boolean | null
    issued_at?: string | null
    cache_state?: string | null
  } | null
  revocation_seq: number | null
  template_cache: { count: number | null; model: string | null } | null
  /** null = the edge did not report it (never shown as 0; audit KAO-09) */
  sync_queue_depth: number | null
  /**
   * Demo clock (API.md v1.4 §3.10/§3.14): present whenever DEMO_MODE=1 (else null). `contract` = the edge sent
   * the full v1.4 shape; an older edge sends only {active, now_local}, the other fields are then null.
   */
  demo_clock: ModeDemoClock | null
  /**
   * API.md v1.3 §3.10 `cloud_match`: degraded = recent cloud /v1/match calls missed the budget, so attempts
   * are decided locally (OFFLINE, P7) although connectivity is ONLINE.
   */
  cloud_match?: CloudMatchStatus | null
  /** §3.14a random-challenge control as reported by the edge (AUTO | FORCE_NEXT | FORCE | OFF). */
  random_challenge?: RandomChallengeMode | null
  /** the only kiosk_id this edge serves in session/start (runtime.kiosk_id) */
  kiosk_id?: string | null
  zone?: string | null
  policy_version?: string | null
  rate_limit?: { enabled: boolean | null; locked: boolean; retry_after_s: number | null } | null
  last_sync?: { at: string | null; report: Record<string, unknown> | null } | null
  server_flags?: string[]
  /** enforcement switches and bars (edge/policy/runtime.py mode_status) */
  policy_bars?: Record<string, number | boolean | string | null> | null
}

/** GET /v1/mode demo_clock as used by the UI (DemoClockStatus when `contract` is true). */
export interface ModeDemoClock {
  contract: boolean
  active: boolean
  now_local: string | null
  now_utc: string | null
  offset_s: number | null
  date_local: string | null
  bundle_issued_at: string | null
  earliest_utc: string | null
  earliest_local: string | null
  earliest_date_local: string | null
  bundle_rollback: boolean
  cache_state: CacheState | null
}

export interface CloudMatchStatus {
  enabled: boolean | null
  degraded: boolean
  recent: number | null
  misses: number | null
  last_miss_at: string | null
  last_ok_at: string | null
}

/** POST /v1/admin/random-challenge {mode} (DEMO_MODE=1). FORCE = every would-be ALLOW; FORCE_NEXT = once. */
export type RandomChallengeMode = 'AUTO' | 'FORCE_NEXT' | 'FORCE' | 'OFF'
export const RANDOM_CHALLENGE_MODES: readonly RandomChallengeMode[] = ['AUTO', 'FORCE_NEXT', 'FORCE', 'OFF']

/** POST /v1/attempt/{id}/probe -> 202 (API.md v1.3 §3.1a, early cloud probe). */
export interface ProbeResponse {
  accepted: boolean
  cloud: 'started' | 'skipped'
}

export interface HealthResponse {
  status: string
  version?: string
  [key: string]: unknown
}

export interface LatencyStat {
  p50?: number | null
  p95?: number | null
  n?: number | null
}

export interface LabelStat {
  n?: number
  accepted?: number
  rejected?: number
  apcer?: number | null
  apcer_upper_95?: number | null
  bpcer?: number | null
  bpcer_upper_95?: number | null
  [key: string]: unknown
}

export interface MetricsResponse {
  window?: { since?: string | null; until?: string | null }
  attempts?: number
  decisions?: Partial<Record<Decision, number>>
  by_mode?: Partial<Record<Mode, number>>
  reason_codes?: Record<string, number>
  latency_ms?: Record<string, LatencyStat>
  by_label?: Record<string, LabelStat>
  sync?: { queue_depth?: number; last_sync_at?: string | null }
  [key: string]: unknown
}

export type ForceMode = 'OFFLINE' | 'AUTO'

/** POST /v1/attempt/{id}/rendered - decision screen painted (decision time = rendered - face lock). */
export interface RenderedReport {
  face_lock_at_ms: number
  rendered_at_ms: number
}

/** SSE `event: rendered` payload (edge-defined; only attempt_id is relied upon). */
export interface RenderedEvent {
  attempt_id: string
  face_lock_at_ms?: number | null
  rendered_at_ms?: number | null
  [key: string]: unknown
}

// Literal unions mirroring edge/schemas.py (EnrollMeta.role, EvalContext.label / condition / split).
export type Role = 'student' | 'faculty' | 'staff' | 'contractor' | 'visitor'
export const ROLES: readonly Role[] = ['student', 'faculty', 'staff', 'contractor', 'visitor']
export const isRole = (v: unknown): v is Role => typeof v === 'string' && (ROLES as readonly string[]).includes(v)
export type EvalLabel = 'bona_fide' | 'print' | 'screen_photo' | 'video' | 'mask_paper' | 'mask_3d' | 'injection'
export const EVAL_LABELS: readonly EvalLabel[] = ['bona_fide', 'print', 'screen_photo', 'video', 'mask_paper', 'mask_3d', 'injection']
export type EvalCondition = 'normal' | 'dim' | 'backlit' | 'far'
export const EVAL_CONDITIONS: readonly EvalCondition[] = ['normal', 'dim', 'backlit', 'far']
export type Split = 'dev' | 'test'
export const SPLITS: readonly Split[] = ['dev', 'test']

/** POST/DELETE /v1/admin/eval/context - tags subsequent attempts for the eval harness. */
export interface EvalContext {
  run_id: string
  subject_id: string
  label: EvalLabel
  condition: EvalCondition
  split: Split
}

export type DemoClockRequest = { set_local: string } | { reset: true }

// ---------------------------------------------------------------- enrolment + access control (API.md v1.4)
// Wire shapes EXACTLY as in docs/API.md v1.4 §3.15 / §3.18 and docs/contracts/admin_access.examples.json.
// Parsed by src/api/access.ts (strict: a missing or mistyped field is a contract error, never guessed).

export type DayCode = 'MON' | 'TUE' | 'WED' | 'THU' | 'FRI' | 'SAT' | 'SUN'
export const DAY_CODES: readonly DayCode[] = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN']

/** POST /v1/enroll meta (multipart part `meta`). `role` is optional and never applied (API.md v1.4). */
export interface EnrollMeta {
  user_id: string
  display_name: string
  email: string | null
  consent: true
  consent_version: string
  card_id: string | null
  provision_totp: boolean
  role?: string
}

export type CloudState = 'indexed' | 'failed' | 'skipped_offline' | 'not_configured'
export const CLOUD_STATES: readonly CloudState[] = ['indexed', 'failed', 'skipped_offline', 'not_configured']

/** POST /v1/enroll -> 201 */
export type EnrollCloudCall = { status: number; body: unknown } | { status: null; error: string }

export interface EnrollResponse {
  user_id: string
  template_version: number
  local_cache_updated: boolean
  cloud_indexed: boolean
  cloud_state: CloudState
  totp_provisioning_uri: string | null
  /** the policy can offer TOTP for this person now (only then show "Scan now") */
  totp_active: boolean
  frames_used: number
  frames_rejected: Array<Record<string, unknown>>
  min_pairwise_cosine: number | null
  /**
   * the cloud enrol call (informational), null when not called: {status, body} when the cloud answered,
   * {status: null, error} on a transport failure (edge/enroll.py CloudUnavailable; audit KAO-04)
   */
  cloud: EnrollCloudCall | null
  schedule_role: string | null
  schedule_display: string | null
  role_requested: string | null
  role_applied: boolean
  bundle_version: number | null
  reinstated_after_erasure: boolean
  warnings: string[]
}

/**
 * DELETE /v1/enroll `cloud` (v1.4 M1): deleted | queued (persisted, replayed at every sync) | not_configured |
 * failed = the edge could not even write its local erasure queue (e.g. disk error): the LOCAL data IS erased,
 * but nothing will retry the cloud erasure, so the operator must run the erasure again.
 */
export type EraseCloud = 'deleted' | 'queued' | 'not_configured' | 'failed'
export const ERASE_CLOUD: readonly EraseCloud[] = ['deleted', 'queued', 'not_configured', 'failed']

/** A schedule window: Asia/Kolkata wall time. Written times are 00:00-23:59; "24:00" appears only in read data. */
export interface AccessWindow {
  days: DayCode[]
  start: string
  end: string
}
export type ZoneWindows = Record<string, AccessWindow[]>

export type BundleResult = 'installed' | 'not_modified' | 'failed'
export const BUNDLE_RESULTS: readonly BundleResult[] = ['installed', 'not_modified', 'failed']

/** Outcome of the edge's bundle pull (POST /v1/admin/bundle/refresh body; `bundle` of every write). */
export interface BundleRefresh {
  previous_version: number | null
  installed_version: number | null
  changed: boolean
  result: BundleResult
  error: string | null
  /** write responses only: installed_version >= cloud_bundle_version */
  applied?: boolean | null
}

/** DELETE /v1/enroll/{user_id} -> 200 */
export interface EraseResponse {
  user_id: string
  local_removed: boolean
  /** queued = persisted on the edge and replayed at the next sync (R-J) */
  cloud: EraseCloud
  cloud_status: number | null
  message: string | null
  bundle: BundleRefresh | null
}

export interface RoleDefaults {
  zones: string[]
  windows: ZoneWindows
}

export type ZoneRisk = 'low' | 'medium' | 'high'
export interface ZoneDef {
  risk: ZoneRisk
  requires_explicit_grant: boolean
}

export type AccessStatus = 'ACTIVE' | 'REVOKED' | 'ERASED' | 'NOT_IN_SCHEDULE'
export const ACCESS_STATUSES: readonly AccessStatus[] = ['ACTIVE', 'REVOKED', 'ERASED', 'NOT_IN_SCHEDULE']

export type ScheduleStatusNow =
  | 'IN_WINDOW'
  | 'GRACE_WINDOW'
  | 'OUTSIDE_WINDOW'
  | 'NO_ENTITLEMENT'
  | 'ZONE_NOT_PERMITTED'
  | 'HOLIDAY'
  | 'REVOKED'
export const SCHEDULE_STATUSES_NOW: readonly ScheduleStatusNow[] = [
  'IN_WINDOW',
  'GRACE_WINDOW',
  'OUTSIDE_WINDOW',
  'NO_ENTITLEMENT',
  'ZONE_NOT_PERMITTED',
  'HOLIDAY',
  'REVOKED',
]

export interface TodayWindow {
  start: string
  end: string
  source: 'role' | 'extra'
}

/** What the edge enforces today at this kiosk's zone (edge clock incl. demo clock). */
export interface AccessToday {
  zone: string
  date: string
  day: DayCode
  now_local: string
  permitted: boolean
  holiday: boolean
  windows: TodayWindow[]
  status_now: ScheduleStatusNow
}

export interface AccessFallback {
  totp_enrolled: boolean
  card: boolean
}

export interface LocalEnrolment {
  enrolled: boolean
  templates: number
  template_version: number | null
  template_role: string | null
  totp_local: boolean
  updated_at: string | null
}

/** One row of the Users & Access table (GET /v1/admin/access/users users[]). */
export interface AccessUser {
  user_id: string
  display: string
  /** authoritative role (cloud master online, installed bundle offline); null = not in the schedule */
  role: string | null
  /** role in the INSTALLED bundle (what decisions use now); null = not in it */
  bundle_role: string | null
  in_schedule: boolean
  /** in this kiosk's installed bundle (filtered to its zone); false = no access here, do not enrol here */
  in_bundle: boolean
  status: AccessStatus
  revoked_at: string | null
  revoked_reason: string | null
  bundle_stale: boolean
  zones_add: string[]
  zones_remove: string[]
  extra_windows: ZoneWindows
  valid_from: string | null
  valid_until: string | null
  fallback: AccessFallback
  cloud_faces: number | null
  local: LocalEnrolment
  today: AccessToday | null
}

export type ReadOnlyCode = 'OFFLINE' | 'NOT_CONFIGURED' | 'CLOUD_ERROR' | 'ENDPOINT_NOT_DEPLOYED' | 'CLOUD_ADMIN_TOKEN'
export const READ_ONLY_CODES: readonly ReadOnlyCode[] = ['OFFLINE', 'NOT_CONFIGURED', 'CLOUD_ERROR', 'ENDPOINT_NOT_DEPLOYED', 'CLOUD_ADMIN_TOKEN']

/** GET /v1/admin/access/users -> 200 */
export interface AccessUsersResponse {
  source: 'cloud+bundle' | 'bundle'
  read_only: boolean
  read_only_code: ReadOnlyCode | null
  read_only_reason: string | null
  mode: Mode
  kiosk_id: string
  zone: string | null
  now_local: string
  date_local: string
  day: DayCode
  bundle: { version: number | null; issued_at: string | null; expires_at: string | null }
  cloud_bundle_version: number | null
  roles: string[]
  role_defaults: Record<string, RoleDefaults>
  zones: Record<string, ZoneDef>
  staff_ids: string[]
  pending_cloud_erasures: string[]
  users: AccessUser[]
}

/**
 * PUT /v1/admin/access/users/{user_id} body (extra fields are rejected). Absent = unchanged; zones_add and
 * extra_windows REPLACE the stored values; null clears valid_from / valid_until.
 */
export interface AccessUpdate {
  role: string
  display?: string
  /** the person consented: required to create, to re-admit an ERASED user and with restore */
  consent?: boolean
  /** lift this user's revocation (R-C Restore); requires consent: true */
  restore?: boolean
  zones_add?: string[]
  extra_windows?: ZoneWindows
  valid_from?: string | null
  valid_until?: string | null
  actor?: string
}

/** PUT /v1/admin/access/users/{user_id} -> 200 */
export interface AccessUpdateResult {
  user_id: string
  created: boolean
  unchanged: boolean
  readmitted: boolean
  restored: boolean
  previous_role: string | null
  role: string
  /** the master version after the change; null when the edge's follow-up pull failed (M2: show "pending refresh") */
  cloud_bundle_version: number | null
  bundle: BundleRefresh
  user: AccessUser | null
  warnings: string[]
}

/** POST /v1/admin/access/users/{user_id}/revoke body (optional). */
export interface RevokeRequest {
  reason?: string
  actor?: string
}

/** POST /v1/admin/access/users/{user_id}/revoke -> 200 */
export interface RevokeResult {
  user_id: string
  type: 'USER'
  reason: string
  /** M2: revoked_at / seq / cloud_bundle_version are null when the edge's follow-up pull failed (applied:false) */
  revoked_at: string | null
  seq: number | null
  cloud_bundle_version: number | null
  bundle: BundleRefresh
  user: AccessUser | null
  warnings: string[]
}

/** POST /v1/admin/access/codes/rotate body. */
export interface RotateCodesRequest {
  staff_id: string
  count?: number
  replace_existing?: boolean
  actor?: string
}

/** POST /v1/admin/access/codes/rotate -> 200 (no-store). Plaintext codes: shown ONCE, never persisted. */
export interface RotateCodesResult {
  staff_id: string
  /** code_id may be null (R-K): the plaintext code is still shown once */
  codes: Array<{ code_id: string | null; code: string }>
  /** null (R-K) = the edge could not read it back: shown as "unknown" */
  code_length: number | null
  /** null (R-K) = unknown validity: shown as "unknown" */
  valid_until: string | null
  one_time: true
  dropped_code_ids: string[]
  warning: string
  /** null when the edge's follow-up pull failed (M2: "pending refresh") */
  cloud_bundle_version: number | null
  bundle: BundleRefresh
  warnings: string[]
}

/** GET /v1/admin/users users[] (enrolled on this edge; no templates, no secrets). */
export interface EnrolledUser {
  user_id: string
  display_name: string
  /** schedule role in the installed bundle (null = not in it) */
  role: string | null
  bundle_role: string | null
  bundle_display: string | null
  in_schedule: boolean
  /** role stored with the template (informational only) */
  template_role: string | null
  template_display_name: string | null
  template_version: number | null
  templates: number | null
  totp_local: boolean
  card: boolean
  updated_at: string | null
}

/** GET /v1/admin/users -> 200 */
export interface EnrolledUsersResponse {
  users: EnrolledUser[]
  bundle_version: number | null
  count: number
  model: string | null
  age_h: number | null
  skipped_model_mismatch: number
}

/** GET /v1/mode demo_clock = POST /v1/admin/clock response (DEMO_MODE=1). */
export interface DemoClockStatus {
  active: boolean
  now_local: string
  now_utc: string
  offset_s: number
  date_local: string
  bundle_issued_at: string | null
  earliest_utc: string | null
  earliest_local: string | null
  earliest_date_local: string | null
  /** the demo time is before bundle issued_at - 300 s: bundle INVALID -> STEP_UP SCHEDULE_BUNDLE_INVALID */
  bundle_rollback: boolean
  cache_state: CacheState | null
}

/** Extra machine-readable fields of an edge error body (API.md v1.4 §0 / §3.18.6). */
export interface ApiErrorExtra {
  /** machine-readable cause (e.g. OFFLINE, NOT_IN_SCHEDULE, ERASED_IN_BUNDLE); the kiosk maps THIS, not the message */
  reason?: string | null
  cloud_status?: number | null
  cloud_code?: string | null
  retry_after_s?: number | null
  installed_version?: number | null
  bundle_version?: number | null
  details?: unknown
  /** 401 MFA_REQUIRED: opaque 2-minute single-use ticket for the second login leg (POST {mfa_ticket, totp_code}) */
  mfa_ticket?: string | null
  /** 403 MISSING_PERMISSION: the permissions the route needs */
  required?: string[] | null
  /** 422 PASSWORD_POLICY: what is wrong with the new password */
  problems?: string[] | null
  /** otp/send 503 EMAIL_UNAVAILABLE / NO_EMAIL_ON_FILE: the second-factor methods still on offer */
  methods?: string[] | null
}

/** Protocol / transport error (distinct from decision reason codes). */
export class ApiError extends Error {
  readonly code: string
  readonly status: number
  readonly attemptId: string | null
  readonly reason: string | null
  readonly extra: ApiErrorExtra

  constructor(code: string, status: number, message: string, attemptId: string | null = null, extra: ApiErrorExtra = {}) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.status = status
    this.attemptId = attemptId
    this.reason = extra.reason ?? null
    this.extra = extra
  }

  /** Network failure / timeout / edge down — the kiosk must fail secure (no access). */
  get isUnreachable(): boolean {
    return this.code === 'NETWORK' || this.code === 'TIMEOUT'
  }
}

/** ApiError check that also survives duplicated module instances (duck-typed on code + status). */
export function asApiError(e: unknown): ApiError | null {
  if (e instanceof ApiError) return e
  if (e && typeof e === 'object' && typeof (e as ApiError).code === 'string' && typeof (e as ApiError).status === 'number') {
    const x = e as ApiError
    const extra: ApiErrorExtra = x.extra && typeof x.extra === 'object' ? x.extra : { reason: typeof x.reason === 'string' ? x.reason : null }
    return new ApiError(x.code, x.status, String(x.message ?? x.code), x.attemptId ?? null, extra)
  }
  return null
}

export interface EdgeEventsHandlers {
  /** `event: decision` - DecisionResponse plus the edge's `eval` context (if any). */
  onDecision: (d: DecisionResponse, evalContext: Record<string, unknown> | null) => void
  /** `event: rendered` */
  onRendered?: (e: RenderedEvent) => void
  onStatus?: (status: 'connecting' | 'open' | 'error') => void
  /**
   * The stream ended for an auth reason and will NOT reconnect: HTTP 401/403 or the edge's final
   * `event: auth` (session expired / revoked / events:read lost). 401 / session-gone also signs the UI out.
   */
  onAuthClosed?: (info: { status: number | null; reason: string | null }) => void
}

export interface SetModeOptions {
  reason?: string
  /** 1..240 minutes */
  max_minutes?: number
}

/** The kiosk talks to the edge only through this interface (real HTTP or in-browser mock). */
export interface EdgeApi {
  readonly kind: 'http' | 'mock'
  readonly baseUrl: string
  sessionStart(req: SessionStartRequest): Promise<SessionStartResponse>
  submitFrames(attemptId: string, frames: Blob[], meta: FramesMeta): Promise<DecisionResponse>
  /** Early cloud probe: face-lock frame, after session/start and before frames (fire-and-forget). */
  submitProbe(attemptId: string, probe: Blob): Promise<ProbeResponse>
  /** Fire-and-forget once the decision screen is painted. */
  markRendered(attemptId: string, report: RenderedReport): Promise<void>
  submitChallenge(attemptId: string, meta: ChallengeMeta, frame: Blob | null): Promise<DecisionResponse>
  sendOtp(attemptId: string): Promise<OtpSendResponse>
  submitFallback(attemptId: string, req: FallbackRequest): Promise<DecisionResponse>
  getMode(): Promise<ModeResponse>
  getHealth(): Promise<HealthResponse>
  // admin (X-Admin-Token)
  getMetrics(token: string): Promise<MetricsResponse>
  /** POST /v1/admin/mode (mode:switch): a forced OFFLINE auto-reverts after max_minutes (1..240, default 60) */
  setMode(token: string, force: ForceMode, opts?: SetModeOptions): Promise<unknown>
  /**
   * GET /v1/admin/mode/detail (store:read): the full mode status. Public GET /v1/mode carries only mode, state,
   * reason, forced, forced_until, kiosk_id, sync_queue_depth, cache_state, template_cache.count, demo_clock.
   */
  getModeDetail(token: string): Promise<ModeResponse>
  getStore(token: string): Promise<unknown>
  triggerSync(token: string): Promise<unknown>
  setEvalContext(token: string, ctx: EvalContext): Promise<unknown>
  clearEvalContext(token: string): Promise<unknown>
  resetRateLimit(token: string): Promise<unknown>
  /** POST /v1/admin/clock (DEMO_MODE=1) -> the demo clock status (R-E). */
  setDemoClock(token: string, req: DemoClockRequest): Promise<DemoClockStatus>
  /** POST /v1/admin/random-challenge (DEMO_MODE=1, §3.14a). */
  setRandomChallenge(token: string, mode: RandomChallengeMode): Promise<unknown>
  /** GET /v1/admin/attempt/{id}/signals - per-signal evidence (e.g. signals.flash.amplitude). */
  getAttemptSignals(token: string, attemptId: string): Promise<unknown>
  enroll(token: string, frames: Blob[], meta: EnrollMeta): Promise<EnrollResponse>
  /** DELETE /v1/enroll/{user_id} - DPDP erasure (cloud deleted | queued | not_configured | failed). */
  deleteEnrollment(token: string, userId: string): Promise<EraseResponse>
  /** GET /v1/admin/users - users enrolled (face templates) on this edge. */
  listEnrolledUsers(token: string): Promise<EnrolledUsersResponse>
  /** GET /v1/admin/access/users - signed-schedule users + roles/windows + local enrolment (offline: read-only). */
  listAccessUsers(token: string): Promise<AccessUsersResponse>
  /** PUT /v1/admin/access/users/{id} - cloud upsert (ONLINE only, else 503 CLOUD_UNAVAILABLE). */
  putAccessUser(token: string, userId: string, req: AccessUpdate): Promise<AccessUpdateResult>
  /** POST /v1/admin/access/users/{id}/revoke - cloud USER revocation (R-C), ONLINE only. */
  revokeAccessUser(token: string, userId: string, req: RevokeRequest): Promise<RevokeResult>
  /** POST /v1/admin/access/codes/rotate - ONLINE only; codes shown once (R-D). */
  rotateStaffCodes(token: string, req: RotateCodesRequest): Promise<RotateCodesResult>
  /** POST /v1/admin/bundle/refresh - pull + verify + install the newest cloud bundle now. */
  refreshBundle(token: string): Promise<BundleRefresh>
  subscribeEvents(token: string, handlers: EdgeEventsHandlers): () => void
  // ---- authentication (design v2 §C/§F). `token` = the fgs_ session token (or an fgk_ key / legacy token).
  /** GET /v1/auth/status (public) */
  authStatus(): Promise<AuthStatus>
  /** POST /v1/auth/login - 401 reason MFA_REQUIRED carries extra.mfa_ticket; 429 extra.retry_after_s */
  login(req: LoginRequest): Promise<LoginResult>
  /** POST /v1/auth/logout (204) */
  logout(token: string): Promise<void>
  /** GET /v1/auth/me */
  me(token: string): Promise<AuthMe>
  /** POST /v1/auth/password (204); 422 reason PASSWORD_POLICY extra.problems */
  changePassword(token: string, req: PasswordChange): Promise<void>
  /** POST /v1/auth/mfa/enroll {current_password} (required; 403 REAUTH_REQUIRED) -> secret + otpauth URI, shown once */
  mfaEnroll(token: string, currentPassword: string): Promise<MfaEnrolment>
  /** POST /v1/auth/mfa/confirm (204) */
  mfaConfirm(token: string, totpCode: string): Promise<void>
  /** POST /v1/auth/activity (204): the user is active (debounced by the auth layer) */
  noteActivity(token: string): Promise<void>
  // ---- staff:manage
  listStaff(token: string): Promise<StaffAccount[]>
  createStaff(token: string, req: StaffCreate): Promise<StaffAccount | null>
  updateStaff(token: string, staffId: string, req: StaffUpdate): Promise<StaffAccount | null>
  resetStaffPassword(token: string, staffId: string, req: StaffPasswordReset): Promise<void>
  unlockStaff(token: string, staffId: string, req: Reauth): Promise<void>
  listApiKeys(token: string): Promise<ApiKeyInfo[]>
  createApiKey(token: string, req: ApiKeyCreate): Promise<ApiKeyCreated>
  revokeApiKey(token: string, keyId: string, req: Reauth): Promise<void>
  /** GET /v1/admin/roles (staff:manage) */
  listRoles(token: string): Promise<RolesCatalog>
  /** GET /v1/admin/auth/audit (audit:read), newest first */
  listAuthAudit(token: string, q?: AuditQuery): Promise<AuthAuditPage>
}
