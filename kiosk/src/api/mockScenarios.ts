/** Mock edge scenarios (demo safety net). Each one drives the mini policy matrix in mock.ts. */

export type MockBio = 'PASS' | 'UNSURE_LIVENESS' | 'UNSURE_MATCH' | 'FAIL_SPOOF' | 'FAIL_NOT_ENROLLED'
export type MockSched =
  | 'IN_WINDOW'
  | 'GRACE_WINDOW'
  | 'OUTSIDE_WINDOW'
  | 'NO_ENTITLEMENT'
  | 'ZONE_NOT_PERMITTED'
  | 'HOLIDAY'
  | 'REVOKED'

export interface MockScenario {
  id: string
  label: string
  /** What the operator should expect / demo with it. */
  hint: string
  bio: MockBio
  bioCodes: string[]
  sched: MockSched
  /** Simulate cloud down: attempt evaluated with OFFLINE rules and the badge shows OFFLINE. */
  offline?: boolean
  /** Treat this kiosk's zone as high-risk regardless of kiosk id. */
  highRisk?: boolean
  /** Quality codes returned on the first attempt (RECAPTURE), then the attempt proceeds. */
  qualityFirst?: string[]
  rateLimited?: boolean
  displayMessage?: string
}

export const MOCK_SCENARIOS: readonly MockScenario[] = [
  {
    id: 'ALLOW',
    label: 'ALLOW (online)',
    hint: 'Enrolled live user inside schedule -> green, OPEN_DOOR.',
    bio: 'PASS',
    bioCodes: [],
    sched: 'IN_WINDOW',
  },
  {
    id: 'STEP_UP_CHALLENGE',
    label: 'STEP_UP -> CHALLENGE (mask cue)',
    hint: 'Amber, then smile/open-mouth/puff + blink/turn. Pass -> ALLOW; no deformation -> retry -> DENY.',
    bio: 'UNSURE_LIVENESS',
    bioCodes: ['MASK_CUE_EDGE'],
    sched: 'IN_WINDOW',
  },
  {
    id: 'STEP_UP_SECOND_FACTOR',
    label: 'STEP_UP -> SECOND_FACTOR (match ambiguous)',
    hint: 'Amber, then method picker (TOTP 123456 / card HID-0001 / email 654321 / staff 12345678).',
    bio: 'UNSURE_MATCH',
    bioCodes: ['MATCH_AMBIGUOUS'],
    sched: 'IN_WINDOW',
  },
  {
    id: 'DENY_SPOOF',
    label: 'DENY spoof (screen replay)',
    hint: 'Phone/screen held up -> red, "Screen detected around face".',
    bio: 'FAIL_SPOOF',
    bioCodes: ['SPOOF_DEVICE_DETECTED', 'SPOOF_MOIRE'],
    sched: 'IN_WINDOW',
  },
  {
    id: 'DENY_SCHEDULE',
    label: 'DENY schedule (outside hours, SC1)',
    hint: 'Live + recognised but outside access hours -> red, no step-up can fix it.',
    bio: 'PASS',
    bioCodes: [],
    sched: 'OUTSIDE_WINDOW',
    displayMessage: 'Live and recognised, but outside your access hours',
  },
  {
    id: 'OFFLINE_ALLOW',
    label: 'OFFLINE ALLOW (local decision, SC2)',
    hint: 'Cloud unreachable: badge OFFLINE, local ALLOW, sync queue +1.',
    bio: 'PASS',
    bioCodes: [],
    sched: 'IN_WINDOW',
    offline: true,
  },
  {
    id: 'OFFLINE_HIGH_RISK',
    label: 'OFFLINE high-risk zone STEP_UP (SC2)',
    hint: 'Offline + server room: never auto-ALLOW -> TOTP 123456 or staff 12345678.',
    bio: 'PASS',
    bioCodes: [],
    sched: 'IN_WINDOW',
    offline: true,
    highRisk: true,
  },
  {
    id: 'RECAPTURE',
    label: 'STEP_UP -> RECAPTURE (low light), then ALLOW',
    hint: 'First attempt: "More light needed" + automatic retake; second attempt ALLOW.',
    bio: 'PASS',
    bioCodes: [],
    sched: 'IN_WINDOW',
    qualityFirst: ['QUALITY_LOW_LIGHT'],
  },
  {
    id: 'GRACE',
    label: 'STEP_UP -> SECOND_FACTOR (schedule grace, SC1)',
    hint: 'Within 15 min grace of the window -> second factor -> ALLOW.',
    bio: 'PASS',
    bioCodes: [],
    sched: 'GRACE_WINDOW',
  },
  {
    id: 'DENY_PRINT',
    label: 'DENY spoof (printed photo)',
    hint: 'Printed photo -> red, passive PAD fail + flash colours not reflected.',
    bio: 'FAIL_SPOOF',
    bioCodes: ['SPOOF_PASSIVE', 'SPOOF_FLASH_MISMATCH'],
    sched: 'IN_WINDOW',
  },
  {
    id: 'DENY_UNSURE_SCHEDULE',
    label: 'DENY bio-unsure + schedule (generic text)',
    hint: 'Identity not confirmed + outside hours -> generic "contact the desk" (no schedule detail shown).',
    bio: 'UNSURE_LIVENESS',
    bioCodes: ['LIVENESS_UNSURE'],
    sched: 'OUTSIDE_WINDOW',
  },
  {
    id: 'NOT_ENROLLED',
    label: 'DENY not enrolled',
    hint: 'Unknown face -> red, contact the desk.',
    bio: 'FAIL_NOT_ENROLLED',
    bioCodes: ['NOT_ENROLLED'],
    sched: 'IN_WINDOW',
  },
  {
    id: 'RANDOM_CHALLENGE',
    label: 'STEP_UP -> random deformation challenge',
    hint: 'Random audit challenge even for a clean pass: "Quick check: follow the prompts".',
    bio: 'UNSURE_LIVENESS',
    bioCodes: ['RANDOM_CHALLENGE'],
    sched: 'IN_WINDOW',
  },
  {
    id: 'RATE_LIMITED',
    label: 'DENY rate limited',
    hint: 'Too many failures -> red with a 60 s lockout countdown.',
    bio: 'PASS',
    bioCodes: [],
    sched: 'IN_WINDOW',
    rateLimited: true,
  },
]

export const DEFAULT_MOCK_SCENARIO = 'ALLOW'

export function findScenario(id: string | null | undefined): MockScenario {
  return MOCK_SCENARIOS.find((s) => s.id === id) ?? MOCK_SCENARIOS[0]
}

/** Codes accepted by the mock second-factor verifier (shown on the mock panels). */
export const MOCK_CREDENTIALS = {
  TOTP: '123456',
  EMAIL_OTP: '654321',
  STAFF_OVERRIDE: '12345678',
  CARD: 'HID-0001',
} as const
