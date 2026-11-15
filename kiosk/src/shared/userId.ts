/** user_id limits (R-H): one definition, in accessRules.ts (identical to docs/API.md v1.4 field_limits). */
import { USER_ID_HINT, USER_ID_RE } from './accessRules'

export { USER_ID_HINT, USER_ID_RE }

export const isUserId = (v: string): boolean => USER_ID_RE.test(v)
