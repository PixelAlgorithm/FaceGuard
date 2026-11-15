/**
 * Who may mint STAFF_OVERRIDE codes for whom (design v2 §D, edge/app.py check_codes_rotate): only a signed-in
 * staff session (an API key / the legacy token gets 403 NO_STAFF_IDENTITY, even with codes:rotate_any);
 * codes:rotate = the caller's own staff_id and at most OWN_CODES_MAX codes; codes:rotate_any = any staff id.
 */
import { LIMITS } from '../shared/accessRules.ts'

/** Mirrors edge/app.py OWN_CODES_MAX. */
export const OWN_CODES_MAX = 4

export interface CodesGate {
  /** the rotate form may be submitted */
  mayRotate: boolean
  /** the principal holds a codes permission but is no staff session */
  noIdentity: boolean
  /** only the caller's own staff id is allowed */
  ownOnly: boolean
  maxCount: number
}

export function codesGate(perms: { rotate: boolean; rotateAny: boolean }, ownStaffId: string | null): CodesGate {
  const holds = perms.rotate || perms.rotateAny
  const ownOnly = !perms.rotateAny
  return {
    mayRotate: holds && !!ownStaffId,
    noIdentity: holds && !ownStaffId,
    ownOnly,
    maxCount: ownOnly ? Math.min(OWN_CODES_MAX, LIMITS.rotateCountMax) : LIMITS.rotateCountMax,
  }
}
