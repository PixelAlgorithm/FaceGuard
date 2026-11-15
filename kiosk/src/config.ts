/**
 * Kiosk configuration.
 *
 * 1. THRESHOLDS: read from config/thresholds.yaml at BUILD time (virtual:thresholds). The kiosk uses them
 *    only as advisory client-side gates (face lock guidance, challenge pacing). The edge re-checks
 *    everything authoritatively; nothing here can produce ALLOW.
 * 2. UI: kiosk presentation timings / client-estimate tuning. These are NOT policy thresholds.
 * 3. Runtime settings (edge URL, kiosk id, mock flag, eval label) with operator overrides in localStorage.
 */
import rawThresholds, { THRESHOLDS_SOURCE } from 'virtual:thresholds'

type Json = Record<string, unknown>

const missingKeys: string[] = []

function pick(path: string): unknown {
  return path.split('.').reduce<unknown>(
    (obj, key) => (obj && typeof obj === 'object' ? (obj as Json)[key] : undefined),
    rawThresholds,
  )
}

function num(path: string, fallback: number): number {
  const v = pick(path)
  if (typeof v === 'number' && Number.isFinite(v)) return v
  missingKeys.push(path)
  return fallback
}

function bool(path: string, fallback: boolean): boolean {
  const v = pick(path)
  if (typeof v === 'boolean') return v
  missingKeys.push(path)
  return fallback
}

function str(path: string, fallback: string): string {
  const v = pick(path)
  if (typeof v === 'string') return v
  missingKeys.push(path)
  return fallback
}

function strList(path: string, fallback: string[]): string[] {
  const v = pick(path)
  if (Array.isArray(v) && v.every((x) => typeof x === 'string')) return v as string[]
  missingKeys.push(path)
  return fallback
}

export const THRESHOLDS = {
  source: THRESHOLDS_SOURCE,
  policyVersion: str('policy_version', 'unknown'),
  quality: {
    minFaceWidthPx: num('quality.min_face_width_px', 112),
    minInterocularPx: num('quality.min_interocular_px', 60),
    maxAbsYawDeg: num('quality.max_abs_yaw_deg', 25),
    maxAbsPitchDeg: num('quality.max_abs_pitch_deg', 20),
    maxAbsRollDeg: num('quality.max_abs_roll_deg', 20),
    minLumaMean: num('quality.min_luma_mean', 60),
    maxLumaMean: num('quality.max_luma_mean', 210),
    maxOverexposedFraction: num('quality.max_overexposed_fraction', 0.15),
    minLaplacianVar: num('quality.min_laplacian_var', 80),
    maxRecaptures: num('quality.max_recaptures', 2),
    framesPerAttempt: num('quality.frames_per_attempt', 5),
  },
  injection: {
    virtualCameraLabelPatterns: strList('injection.virtual_camera_label_patterns', [
      'obs',
      'virtual',
      'manycam',
      'snap camera',
      'xsplit',
      'droidcam',
    ]),
    knownGoodLabelPatterns: strList('injection.known_good_label_patterns', []),
  },
  flash: {
    enabled: bool('liveness.flash.enabled', true),
    maxChangesPerS: num('liveness.flash.max_changes_per_s', 3),
    durationMs: num('liveness.flash.duration_ms', 1000),
  },
  challenge: {
    baselineMs: num('challenge.baseline_ms', 200),
    minReactionMs: num('challenge.min_reaction_ms', 150),
    stepWindowMs: num('challenge.step_window_ms', 1500),
    deformationRiseMin: num('challenge.deformation_rise_min', 0.45),
    smileAbsMin: num('challenge.smile_abs_min', 0.5),
    jawOpenAbsMin: num('challenge.jaw_open_abs_min', 0.4),
    cheekPuffAbsMin: num('challenge.cheek_puff_abs_min', 0.4),
    blinkCloseMin: num('challenge.blink_close_min', 0.5),
    blinkOpenMax: num('challenge.blink_open_max', 0.2),
    turnYawMinDeg: num('challenge.turn_yaw_min_deg', 15),
    softFailRetries: num('challenge.soft_fail_retries', 1),
    sessionTtlS: num('challenge.session_ttl_s', 120),
  },
  stepup: {
    maxAttemptsPerStep: num('stepup.max_attempts_per_step', 2),
    sessionTtlS: num('stepup.session_ttl_s', 120),
    methods: {
      onlineDefault: strList('stepup.methods.online_default', ['TOTP', 'CARD', 'EMAIL_OTP', 'STAFF_OVERRIDE']),
      onlineHighRisk: strList('stepup.methods.online_high_risk', ['TOTP', 'CARD', 'EMAIL_OTP']),
      offlineDefault: strList('stepup.methods.offline_default', ['TOTP', 'CARD', 'STAFF_OVERRIDE']),
      offlineHighRisk: strList('stepup.methods.offline_high_risk', ['TOTP', 'STAFF_OVERRIDE']),
      cacheUntrusted: strList('stepup.methods.cache_untrusted', ['STAFF_OVERRIDE']),
    },
  },
  fallback: {
    totpDigits: num('fallback.totp.digits', 6),
    emailOtpDigits: num('fallback.email_otp.digits', 6),
    staffCodeLength: num('fallback.staff_override.code_length', 8),
  },
  connectivity: {
    statusPollMs: num('connectivity.status_poll_ms', 2000),
  },
  ui: {
    showDetailedReasons: bool('ui.show_detailed_reasons', false),
  },
  latency: {
    totalDecisionMs: num('latency_budget_ms.total_decision', 2000),
  },
} as const

/** Threshold keys the kiosk expected but did not find in thresholds.yaml (shown on /admin). */
export const THRESHOLDS_MISSING: readonly string[] = missingKeys

/** Kiosk presentation timings and client-estimate tuning (UI only, not policy). */
export const UI = {
  /** Terminal ALLOW/DENY screen stays up this long, then the kiosk resets. */
  resultResetMs: 4000,
  /** Amber STEP_UP screen shown before the challenge / second-factor screen. */
  stepUpIntroMs: 1800,
  /** Amber RECAPTURE screen before scanning again. */
  recaptureIntroMs: 2200,
  /** Quality gate must hold continuously for this long to declare face lock (t0). */
  lockStableMs: 150,
  /** A prefetched session/start is reused for at most this long (edge nonce TTL is 10 s). */
  sessionPrefetchMaxAgeMs: 6000,
  /** Ignore faces for this long after a reset so the same person does not instantly re-trigger. */
  rearmDelayMs: 1500,
  /** Guidance text must be stable this long before it replaces the current text (anti-flicker). */
  guidanceDebounceMs: 220,
  /** Abandon the second-factor screen after this much inactivity. */
  fallbackIdleMs: 60000,
  /** Client blur estimate is not on the aligned crop; gate at this fraction of quality.min_laplacian_var. */
  clientBlurFactor: 0.5,
  /** Face centre may move at most this much (fraction of frame width) between frames when locking. */
  maxCenterJitter: 0.015,
  /** Face centre must be within this distance of the frame centre (normalised). */
  maxCenterOffset: 0.2,
  /** Face box wider than this fraction of the frame -> "Move back a little". */
  maxFaceWidthFraction: 0.75,
  /**
   * Upload width assumed for pre-lock size checks until the first session/start; afterwards the kiosk uses
   * the edge's capture.max_width_px (1280: at 640 px a face at kiosk distance has IOD < 60 px).
   */
  defaultUploadMaxWidth: 1280,
  /** Challenge: "get ready" period before the first prompt; baseline is taken from its first baseline_ms. */
  challengeReadyMs: 1100,
  /** Challenge: keep tracking the peak this long after the step completes. */
  challengeHoldAfterCompleteMs: 300,
  /** Challenge: pause between steps (shows a check mark). */
  challengeBetweenStepsMs: 450,
  /** Face absent longer than this inside a challenge step => tracking_lost. */
  trackingLostMs: 300,
  /** Paint each issued flash colour at max saturation (pure primaries/secondaries) as an opaque fill. */
  flashSaturate: true,
  /** Camera pipeline delay used to place the 5 frames on each colour plateau (measured webcam 4-7 frames). */
  flashCameraLagMs: 150,
  /**
   * Lock exposure / white balance during the flash. OFF: on real webcams the lock caused clipping and
   * amplitude swings (0.7 -> 20.7) and camera reconfiguration hiccups inside the 1 s window.
   */
  lockExposure: false,
  /**
   * Early cloud probe (API.md v1.3 §3.1a): POST the face-lock frame right after session/start so the cloud
   * match overlaps the capture. Fire-and-forget; `?probe=0` disables it (A/B timing runs).
   */
  earlyProbe: new URLSearchParams(window.location.search).get('probe') !== '0',
  /** Network timeouts (ms). */
  timeouts: { sessionStart: 3000, frames: 8000, challenge: 8000, fallback: 8000, mode: 1500, admin: 4000, accessAdmin: 15000 },
} as const

// ---------------------------------------------------------------- runtime settings

export const STORAGE_KEYS = {
  mock: 'hid.mock',
  debug: 'hid.debug',
  camflip: 'hid.camflip',
  delegate: 'hid.delegate',
  kioskId: 'hid.kioskId',
  evalContext: 'hid.evalContext',
  adminToken: 'hid.adminToken', // sessionStorage
  mockScenario: 'hid.mock.scenario',
  mockState: 'hid.mock.state',
} as const

/** VITE_EDGE_URL > same origin when the edge itself serves the built kiosk (port 8000) > http://127.0.0.1:8000. */
export const EDGE_URL = (
  import.meta.env.VITE_EDGE_URL || (window.location.port === '8000' ? window.location.origin : 'http://127.0.0.1:8000')
).replace(/\/+$/, '')
export const DEFAULT_KIOSK_ID = import.meta.env.VITE_KIOSK_ID || 'KIOSK_MAIN_01'

function readLocal(key: string): string | null {
  try {
    return window.localStorage.getItem(key)
  } catch {
    return null
  }
}

export function writeLocal(key: string, value: string | null): void {
  try {
    if (value === null) window.localStorage.removeItem(key)
    else window.localStorage.setItem(key, value)
  } catch {
    /* storage unavailable (private mode) - settings simply do not persist */
  }
}

function readSession(key: string): string | null {
  try {
    return window.sessionStorage.getItem(key)
  } catch {
    return null
  }
}

function writeSession(key: string, value: string | null): void {
  try {
    if (value === null) window.sessionStorage.removeItem(key)
    else window.sessionStorage.setItem(key, value)
  } catch {
    /* ignore */
  }
}

/**
 * Mock edge on/off: ?mock=1|0 > this TAB's sessionStorage > VITE_MOCK. Evaluated once per page load.
 * Deliberately per tab (sessionStorage), never localStorage: one ?mock=1 visit must not leave the live
 * kiosk / admin tabs on the simulated edge (fake decisions and latencies in a live demo). A value left in
 * localStorage by older builds is removed.
 */
export const MOCK_ENABLED: boolean = (() => {
  writeLocal(STORAGE_KEYS.mock, null)
  const q = new URLSearchParams(window.location.search).get('mock')
  if (q === '1' || q === '0') {
    writeSession(STORAGE_KEYS.mock, q === '1' ? '1' : null)
    return q === '1'
  }
  if (readSession(STORAGE_KEYS.mock) === '1') return true
  return import.meta.env.VITE_MOCK === '1'
})()

/** URL that leaves the simulated edge in this tab (?mock=0 clears the per-tab flag). */
export function exitMockHref(): string {
  const p = new URLSearchParams(window.location.search)
  p.set('mock', '0')
  return `${window.location.pathname}?${p.toString()}${window.location.hash}`
}

function persistedFlag(param: string, key: string): string | null {
  const q = new URLSearchParams(window.location.search).get(param)
  if (q !== null) {
    writeLocal(key, q === '' ? null : q)
    return q || null
  }
  return readLocal(key)
}

/** ?debug=1 shows the live sensor overlay (blendshapes, yaw, fps); ?debug=0 hides it. Persisted. */
export const DEBUG_ENABLED: boolean = persistedFlag('debug', STORAGE_KEYS.debug) === '1'

/**
 * ?camflip=1 if the camera stream itself arrives MIRRORED (some camera apps / OS settings): inverts the
 * yaw sign so that + stays = the subject's left. Check it on the ?debug=1 overlay. Persisted; ?camflip=0 resets.
 */
export const CAMERA_FLIPPED: boolean = persistedFlag('camflip', STORAGE_KEYS.camflip) === '1'

/** ?delegate=cpu|gpu forces the MediaPipe delegate (default GPU with CPU fallback). Persisted. */
export const DELEGATE_OVERRIDE: 'CPU' | 'GPU' | null = (() => {
  const v = (persistedFlag('delegate', STORAGE_KEYS.delegate) ?? '').toUpperCase()
  return v === 'CPU' || v === 'GPU' ? v : null
})()

/** ?kiosk= applies to this page load only (not persisted: a stale override used to survive reloads). */
let kioskQueryOverride: string | null = new URLSearchParams(window.location.search).get('kiosk') || null

/** Kiosk id: ?kiosk= (this page load) > localStorage (set from /admin) > VITE_KIOSK_ID. */
export function getKioskId(): string {
  return kioskQueryOverride || readLocal(STORAGE_KEYS.kioskId) || DEFAULT_KIOSK_ID
}

/** Where the current kiosk id comes from (for operator messages). */
export function kioskIdSource(): 'query' | 'admin' | 'default' {
  if (kioskQueryOverride) return 'query'
  return readLocal(STORAGE_KEYS.kioskId) ? 'admin' : 'default'
}

/** Drop every kiosk-id override (after the edge refused it) so the next attempt uses the default kiosk. */
export function clearKioskOverride(): void {
  kioskQueryOverride = null
  writeLocal(STORAGE_KEYS.kioskId, null)
  window.dispatchEvent(new Event('hid-kiosk-id'))
}

/**
 * Demo kiosks known to the demo schedule. The edge serves ONLY its own runtime kiosk_id (GET /v1/mode
 * `kiosk_id`); session/start for any other id is refused (409 INVALID_STATE "kiosk switch ... refused").
 */
export const KIOSK_IDS = ['KIOSK_MAIN_01', 'KIOSK_LIB_01', 'KIOSK_LAB_01', 'KIOSK_HOSTEL_01', 'KIOSK_SRV_01'] as const

/**
 * Last eval context set from /admin in this browser (POST /v1/admin/eval/context). The edge holds the
 * authoritative copy; this local copy only drives the "EVAL" tag on the kiosk screen.
 */
export function getEvalContextLocal(): string | null {
  return readLocal(STORAGE_KEYS.evalContext)
}

export function getAdminToken(): string {
  try {
    return window.sessionStorage.getItem(STORAGE_KEYS.adminToken) ?? ''
  } catch {
    return ''
  }
}

export function setAdminToken(token: string): void {
  try {
    if (token) window.sessionStorage.setItem(STORAGE_KEYS.adminToken, token)
    else window.sessionStorage.removeItem(STORAGE_KEYS.adminToken)
  } catch {
    /* ignore */
  }
}
