/** Canonical reason-code order (docs/DECISION_POLICY.md §6: stage order, then table order). */
export const CANONICAL_CODE_ORDER: readonly string[] = [
  // pre-check
  'RATE_LIMITED',
  // quality
  'QUALITY_LOW_LIGHT',
  'QUALITY_BLUR',
  'MULTIPLE_FACES',
  'QUALITY_POSE',
  'QUALITY_DEPTH_INVALID',
  // injection
  'INJECTION_VIRTUAL_CAMERA',
  // liveness hard
  'SPOOF_PASSIVE',
  'SPOOF_DEVICE_DETECTED',
  'SPOOF_MOIRE',
  'SPOOF_FLASH_MISMATCH',
  'SPOOF_FLAT_DEPTH',
  'SPOOF_DEPTH_SCALE',
  // mask
  'MASK_CUE_RIGID',
  'MASK_CUE_EDGE',
  'MASK_CUE_SHAPE',
  'MASK_CUE_SPECTRAL',
  // liveness unsure
  'LIVENESS_UNSURE',
  'RANDOM_CHALLENGE',
  // identity
  'MATCH_LOW',
  'MATCH_AMBIGUOUS',
  'NOT_ENROLLED',
  // schedule
  'SCHEDULE_OUTSIDE_WINDOW',
  'SCHEDULE_GRACE_WINDOW',
  'SCHEDULE_NO_ENTITLEMENT',
  'SCHEDULE_ZONE_NOT_PERMITTED',
  'SCHEDULE_HOLIDAY',
  'SCHEDULE_REVOKED',
  'SCHEDULE_HIGH_RISK_ZONE',
  // mode
  'SCHEDULE_EXPIRED_CACHE',
  'SCHEDULE_BUNDLE_INVALID',
  'OFFLINE_MODE',
  'OFFLINE_HIGH_RISK_ZONE',
  'OFFLINE_FALLBACK_REQUIRED',
  // step-up
  'CHALLENGE_FAILED',
  'FALLBACK_OK',
  'FALLBACK_FAILED',
  'FALLBACK_LOCKED',
  // final / any
  'ACCESS_OK',
  'SYSTEM_ERROR',
]

export function orderCodes(codes: string[]): string[] {
  const rank = (c: string) => {
    const i = CANONICAL_CODE_ORDER.indexOf(c)
    return i < 0 ? CANONICAL_CODE_ORDER.length : i
  }
  return [...new Set(codes)].sort((a, b) => rank(a) - rank(b))
}
