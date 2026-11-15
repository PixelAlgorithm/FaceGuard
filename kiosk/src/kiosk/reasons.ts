/**
 * Human text for every reason code in docs/DECISION_POLICY.md §6 (required + added codes).
 * Kiosk shows display_message + the first (non-informational) reason code; demo mode shows all codes.
 */
import type { Decision, DecisionResponse } from '../api/types'

interface ReasonCopy {
  text: string
  deny?: string // wording when the decision is DENY
  stepUp?: string // wording when the decision is STEP_UP
}

export const REASON_TEXT: Record<string, ReasonCopy> = {
  // required set
  QUALITY_LOW_LIGHT: { text: 'More light needed – please face the light' },
  QUALITY_BLUR: { text: 'Please hold still' },
  MULTIPLE_FACES: { text: 'One person at a time' },
  SPOOF_PASSIVE: { text: 'Liveness check failed', stepUp: 'Extra check needed' },
  SPOOF_DEVICE_DETECTED: { text: 'Screen detected around face' },
  SPOOF_MOIRE: { text: 'Screen pattern detected', stepUp: 'Extra check needed' },
  SPOOF_FLASH_MISMATCH: { text: 'Light check failed – colours not reflected', stepUp: 'Extra check needed' },
  SPOOF_FLAT_DEPTH: { text: '3D check failed – flat surface' },
  MASK_CUE_RIGID: { text: 'Extra check needed', deny: 'Challenge failed: no facial movement' },
  MASK_CUE_EDGE: { text: 'Extra check needed', deny: 'Mask detected' },
  INJECTION_VIRTUAL_CAMERA: { text: 'Camera not trusted' },
  CHALLENGE_FAILED: { text: 'Challenge failed', stepUp: 'Check not completed – let’s try once more' },
  MATCH_LOW: { text: 'Please verify your identity', deny: 'Not recognised' },
  MATCH_AMBIGUOUS: { text: 'Please verify your identity', deny: 'Identity could not be confirmed' },
  NOT_ENROLLED: { text: 'Not recognised' },
  SCHEDULE_OUTSIDE_WINDOW: { text: 'Outside your access hours' },
  SCHEDULE_GRACE_WINDOW: { text: 'Just outside your access hours – extra check needed' },
  SCHEDULE_NO_ENTITLEMENT: { text: 'No access entitlement for this entrance' },
  SCHEDULE_ZONE_NOT_PERMITTED: { text: 'This area is not permitted for you' },
  SCHEDULE_HOLIDAY: { text: 'Campus closed today' },
  SCHEDULE_REVOKED: { text: 'Access revoked' },
  SCHEDULE_EXPIRED_CACHE: { text: 'Offline: verification needed' },
  OFFLINE_MODE: { text: 'Offline mode' },
  OFFLINE_HIGH_RISK_ZONE: { text: 'Offline: high-security area needs extra verification' },
  OFFLINE_FALLBACK_REQUIRED: { text: 'Offline: enter a code or tap your card' },
  FALLBACK_OK: { text: 'Verified' },
  FALLBACK_FAILED: { text: 'Verification failed', stepUp: 'Code not accepted – please try again' },
  FALLBACK_LOCKED: { text: 'This method is temporarily locked – please use another method or ask the desk' },
  // added codes (closed list)
  ACCESS_OK: { text: 'Identity and access verified' },
  QUALITY_POSE: { text: 'Please face the camera' },
  QUALITY_DEPTH_INVALID: { text: 'Depth check could not read your face – please try again' },
  LIVENESS_UNSURE: { text: 'Extra check needed', deny: 'Liveness could not be confirmed' },
  SPOOF_DEPTH_SCALE: { text: '3D check failed – face size not plausible' },
  MASK_CUE_SHAPE: { text: 'Extra check needed', deny: 'Face shape does not match' },
  MASK_CUE_SPECTRAL: { text: 'Extra check needed', deny: 'Skin response not detected' },
  SCHEDULE_HIGH_RISK_ZONE: { text: 'High-security area – second factor required' },
  SCHEDULE_BUNDLE_INVALID: { text: 'Offline: staff verification needed' },
  RATE_LIMITED: { text: 'Too many attempts – please wait' },
  SYSTEM_ERROR: { text: 'System error' },
  // round 2
  RANDOM_CHALLENGE: { text: 'Quick check: follow the prompts' },
}

/** Codes that never explain the decision on their own (mode is shown by the badge). */
const INFORMATIONAL = new Set(['OFFLINE_MODE'])

export function reasonText(code: string, decision: Decision): string {
  const c = REASON_TEXT[code]
  if (!c) return code.replace(/_/g, ' ').toLowerCase().replace(/^\w/, (m) => m.toUpperCase())
  if (decision === 'DENY' && c.deny) return c.deny
  if (decision === 'STEP_UP' && c.stepUp) return c.stepUp
  return c.text
}

export function primaryCode(codes: string[]): string | null {
  return codes.find((c) => !INFORMATIONAL.has(c)) ?? codes[0] ?? null
}

export type Tone = 'allow' | 'stepup' | 'deny'

export interface DecisionCopy {
  tone: Tone
  /** The brief's three outcomes, verbatim: ALLOW / REQUEST VERIFICATION / DENY (API enum STEP_UP). */
  label: 'ALLOW' | 'REQUEST VERIFICATION' | 'DENY'
  /** "step-up" under REQUEST VERIFICATION */
  subtitle: string | null
  headline: string
  reason: string
  detail: string | null
  welcome: string | null
  nextHint: string | null
  /** true when the generic BIO_UNSURE + schedule-deny text replaced the specific reason (§10). */
  generic: boolean
}

const GENERIC_UNAVAILABLE = 'Access not available – please contact the desk'

/** Schedule results that, combined with BIO_UNSURE, DENY (matrix N11/F7/E4). */
const SCHEDULE_DENY_CODES = new Set([
  'SCHEDULE_OUTSIDE_WINDOW',
  'SCHEDULE_GRACE_WINDOW',
  'SCHEDULE_NO_ENTITLEMENT',
  'SCHEDULE_ZONE_NOT_PERMITTED',
  'SCHEDULE_HOLIDAY',
  'SCHEDULE_REVOKED',
])

/** Human text for "N tries remaining": attempts_left counts retries AFTER the next try (policy §9.6 R8). */
export function triesLeftText(attemptsLeft: number | null): string {
  if (attemptsLeft === null) return ''
  return attemptsLeft <= 0 ? 'last try' : `${attemptsLeft + 1} tries left`
}

export function describeDecision(d: DecisionResponse): DecisionCopy {
  const codes = d.reason_codes
  const code = primaryCode(codes)
  const tone: Tone = d.decision === 'ALLOW' ? 'allow' : d.decision === 'STEP_UP' ? 'stepup' : 'deny'
  const type = d.next_action.type

  if (d.decision === 'ALLOW') {
    return {
      tone,
      label: 'ALLOW',
      subtitle: null,
      headline: 'Access granted',
      reason: codes.includes('FALLBACK_OK') ? 'Verified with a second factor' : reasonText('ACCESS_OK', 'ALLOW'),
      detail: d.mode === 'OFFLINE' ? 'Offline decision – will sync when the connection returns' : null,
      welcome: d.candidate?.display
        ? `Welcome, ${d.candidate.display}${d.candidate.role ? ` · ${d.candidate.role}` : ''}`
        : null,
      nextHint: null,
      generic: false,
    }
  }

  if (d.decision === 'DENY') {
    // DECISION_POLICY §10: identity unconfirmed + schedule deny -> no schedule detail to that person.
    const generic = d.bio_result === 'BIO_UNSURE' && codes.some((c) => SCHEDULE_DENY_CODES.has(c))
    const retry = d.next_action.retry_after_s
    return {
      tone,
      label: 'DENY',
      subtitle: null,
      headline: 'Access denied',
      reason: generic
        ? GENERIC_UNAVAILABLE
        : code === 'RATE_LIMITED' && retry
          ? `Too many attempts – please wait ${Math.ceil(retry)} s`
          : code
            ? reasonText(code, 'DENY')
            : 'Access denied',
      detail: generic ? null : type === 'CONTACT_DESK' ? 'Please contact the desk' : null,
      welcome: null,
      nextHint: null,
      generic,
    }
  }

  // STEP_UP
  const nextHint =
    type === 'CHALLENGE'
      ? 'Next: a quick face check'
      : type === 'SECOND_FACTOR'
        ? 'Next: verify with a code or your card'
        : type === 'RECAPTURE'
          ? 'Let’s take that again'
          : type === 'CONTACT_DESK'
            ? 'Please contact the desk'
            : null
  const special = codes.includes('CHALLENGE_FAILED')
    ? 'CHALLENGE_FAILED'
    : codes.includes('FALLBACK_FAILED')
      ? 'FALLBACK_FAILED'
      : code
  return {
    tone,
    label: 'REQUEST VERIFICATION',
    subtitle: 'step-up',
    headline: type === 'RECAPTURE' ? 'Let’s try again' : 'Verification needed',
    reason: special ? reasonText(special, 'STEP_UP') : 'Extra check needed',
    detail: null,
    welcome: null,
    nextHint,
    generic: false,
  }
}

export interface OperatorDetail {
  /** reason codes safe to list on the public screen's operator strip */
  codes: string[]
  /** schedule_result, or null when it must not be shown */
  scheduleResult: string | null
}

/**
 * What the public screen's operator strip (ui.show_detailed_reasons) may show. DECISION_POLICY §10 / audit
 * KF-05 / policy F13: no schedule detail to a person whose identity is unconfirmed (BIO_UNSURE, or the generic
 * message), even with the demo flag on; otherwise the public kiosk becomes an entitlement oracle.
 */
export function operatorDetail(d: DecisionResponse): OperatorDetail {
  const unconfirmed = d.bio_result === 'BIO_UNSURE' || describeDecision(d).generic
  if (!unconfirmed) return { codes: d.reason_codes, scheduleResult: d.schedule_result }
  return { codes: d.reason_codes.filter((c) => !c.startsWith('SCHEDULE_')), scheduleResult: null }
}
