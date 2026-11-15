/**
 * Field limits (R-H, docs/API.md v1.4 / admin_access.examples.json `field_limits`), request validators that
 * mirror the edge's request models exactly, and the R-I hours display. Pure functions: the contract test
 * (scripts/contract-test.ts) runs them in Node against every example. Imports carry `.ts` extensions so Node
 * can load this module directly.
 */
import { DAY_CODES, type AccessUser, type AccessUsersResponse, type DayCode } from '../api/types.ts'

export const USER_ID_RE = /^u_[0-9a-z]{4}$/
export const STAFF_ID_RE = /^s_[0-9a-z_]{2,32}$/
export const ROLE_RE = /^[a-z_]{1,32}$/
export const ZONE_RE = /^[A-Z0-9_]{1,32}$/
/** written times (R-H): 00:00-23:59; "24:00" appears only in read data */
export const HHMM_WRITE = /^([01]\d|2[0-3]):[0-5]\d$/
export const REVOKE_REASON_RE = /^[A-Z][A-Z_]{1,31}$/
export const ACTOR_RE = /^[A-Za-z0-9_.:@-]{1,64}$/
const ISO_OFFSET = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:\d{2})$/

export const LIMITS = {
  displayMax: 80,
  zonesAddMax: 16,
  extraZonesMax: 16,
  windowsPerZoneMax: 14,
  rotateCountMin: 1,
  rotateCountMax: 10,
  rotateCountDefault: 4,
  consentVersionMax: 40,
} as const

export const USER_ID_HINT = 'u_ followed by 4 characters a-z / 0-9, e.g. u_prj1'
export const STAFF_ID_HINT = 's_ followed by 2-32 characters a-z / 0-9 / _, e.g. s_guard01'

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v)

export const toMinutes = (t: string): number => {
  if (t === '24:00') return 1440
  const m = /^(\d{2}):(\d{2})$/.exec(t)
  return m ? Number(m[1]) * 60 + Number(m[2]) : NaN
}

function extraKeys(o: Obj, allowed: readonly string[], p: string, out: string[]): void {
  for (const k of Object.keys(o)) if (!allowed.includes(k)) out.push(`${p}${k}: unknown field (not allowed)`)
}

/** display / display_name: stripped, then 1-80 characters. */
export function displayError(v: unknown, label = 'display name'): string | null {
  if (typeof v !== 'string') return `${label}: required`
  const t = v.trim()
  if (!t.length) return `${label}: 1-${LIMITS.displayMax} characters`
  if (t.length > LIMITS.displayMax) return `${label}: at most ${LIMITS.displayMax} characters`
  return null
}

export function userIdError(v: unknown): string | null {
  return typeof v === 'string' && USER_ID_RE.test(v) ? null : `user id: ${USER_ID_HINT}`
}

export function staffIdError(v: unknown): string | null {
  return typeof v === 'string' && STAFF_ID_RE.test(v) ? null : `staff id: ${STAFF_ID_HINT}`
}

/** One written window {days, start, end}: days 1-7 unique MON..SUN, HH:MM 00:00-23:59, end > start. */
export function windowError(w: unknown): string | null {
  if (!isObj(w)) return 'window must be an object'
  const extra: string[] = []
  extraKeys(w, ['days', 'start', 'end'], '', extra)
  if (extra.length) return extra[0]
  const days = w.days
  if (!Array.isArray(days) || days.length < 1 || days.length > 7) return 'pick 1-7 days'
  if (days.some((d) => typeof d !== 'string' || !(DAY_CODES as readonly string[]).includes(d))) return 'days must be MON..SUN'
  if (new Set(days).size !== days.length) return 'each day only once'
  if (typeof w.start !== 'string' || !HHMM_WRITE.test(w.start)) return 'start must be HH:MM (00:00-23:59)'
  if (typeof w.end !== 'string' || !HHMM_WRITE.test(w.end)) return 'end must be HH:MM (00:00-23:59; 24:00 is not writable)'
  if (toMinutes(w.end) <= toMinutes(w.start)) return `end ${w.end} must be after start ${w.start} (same day)`
  return null
}

function isoError(v: unknown, label: string): string | null {
  if (v === null) return null
  return typeof v === 'string' && ISO_OFFSET.test(v) && Number.isFinite(Date.parse(v)) ? null : `${label}: ISO-8601 date-time with an offset`
}

function actorError(v: unknown): string | null {
  return v === undefined || v === null || (typeof v === 'string' && ACTOR_RE.test(v)) ? null : 'actor: 1-64 characters A-Z a-z 0-9 _ . : @ -'
}

/**
 * PUT /v1/admin/access/users/{user_id}: path + body exactly as the edge's AccessUpdate model (request-model
 * 422s only; role membership / zone existence are state checks done by the edge / cloud).
 */
export function accessUpdateErrors(userId: unknown, body: unknown): string[] {
  const out: string[] = []
  const id = userIdError(userId)
  if (id) out.push(id)
  if (!isObj(body)) return [...out, 'body must be an object']
  extraKeys(body, ['role', 'display', 'consent', 'restore', 'zones_add', 'extra_windows', 'valid_from', 'valid_until', 'actor'], '', out)
  if (typeof body.role !== 'string' || !ROLE_RE.test(body.role)) out.push('role: required, a-z and _ only')
  if (body.display !== undefined && body.display !== null) {
    const d = displayError(body.display)
    if (d) out.push(d)
  }
  for (const k of ['consent', 'restore'] as const) {
    if (body[k] !== undefined && body[k] !== null && typeof body[k] !== 'boolean') out.push(`${k}: true or false`)
  }
  if (body.restore === true && body.consent !== true) out.push('restore requires consent: true')
  if (body.zones_add !== undefined && body.zones_add !== null) {
    const z = body.zones_add
    if (!Array.isArray(z)) out.push('zones_add: a list of zones')
    else {
      if (z.length > LIMITS.zonesAddMax) out.push(`zones_add: at most ${LIMITS.zonesAddMax} zones`)
      if (z.some((x) => typeof x !== 'string' || !ZONE_RE.test(x))) out.push('zones_add: zone names are A-Z 0-9 _')
    }
  }
  if (body.extra_windows !== undefined && body.extra_windows !== null) {
    const ew = body.extra_windows
    if (!isObj(ew)) out.push('extra_windows: an object zone -> windows')
    else {
      const zones = Object.keys(ew)
      if (zones.length > LIMITS.extraZonesMax) out.push(`extra_windows: at most ${LIMITS.extraZonesMax} zones`)
      for (const z of zones) {
        if (!ZONE_RE.test(z)) out.push(`extra_windows: zone ${z} must be A-Z 0-9 _`)
        const ws = ew[z]
        if (!Array.isArray(ws)) {
          out.push(`${z}: a list of windows`)
          continue
        }
        if (ws.length > LIMITS.windowsPerZoneMax) out.push(`${z}: at most ${LIMITS.windowsPerZoneMax} windows`)
        ws.forEach((w, i) => {
          const e = windowError(w)
          if (e) out.push(`${z} window ${i + 1}: ${e}`)
        })
      }
    }
  }
  const vf = body.valid_from
  const vu = body.valid_until
  if (vf !== undefined) {
    const e = isoError(vf, 'valid from')
    if (e) out.push(e)
  }
  if (vu !== undefined) {
    const e = isoError(vu, 'valid until')
    if (e) out.push(e)
  }
  if (typeof vf === 'string' && typeof vu === 'string' && Date.parse(vu) <= Date.parse(vf)) out.push('valid until must be after valid from')
  const a = actorError(body.actor)
  if (a) out.push(a)
  return out
}

/** POST /v1/admin/access/users/{user_id}/revoke (body optional). */
export function revokeErrors(userId: unknown, body: unknown): string[] {
  const out: string[] = []
  const id = userIdError(userId)
  if (id) out.push(id)
  if (body === null || body === undefined) return out
  if (!isObj(body)) return [...out, 'body must be an object']
  extraKeys(body, ['reason', 'actor'], '', out)
  if (body.reason !== undefined) {
    if (typeof body.reason !== 'string' || !REVOKE_REASON_RE.test(body.reason)) out.push('reason: A-Z and _, starting with a letter (e.g. ADMIN, LOST_BADGE)')
    else if (body.reason === 'ERASED') out.push('reason ERASED is the DPDP erasure: use Erase (DELETE /v1/enroll/{user_id})')
  }
  const a = actorError(body.actor)
  if (a) out.push(a)
  return out
}

/** POST /v1/admin/access/codes/rotate */
export function rotateErrors(body: unknown): string[] {
  if (!isObj(body)) return ['body must be an object']
  const out: string[] = []
  extraKeys(body, ['staff_id', 'count', 'replace_existing', 'actor'], '', out)
  const s = staffIdError(body.staff_id)
  if (s) out.push(s)
  if (body.count !== undefined) {
    const c = body.count
    if (typeof c !== 'number' || !Number.isInteger(c) || c < LIMITS.rotateCountMin || c > LIMITS.rotateCountMax) {
      out.push(`count: a whole number ${LIMITS.rotateCountMin}-${LIMITS.rotateCountMax}`)
    }
  }
  if (body.replace_existing !== undefined && typeof body.replace_existing !== 'boolean') out.push('replace_existing: true or false')
  const a = actorError(body.actor)
  if (a) out.push(a)
  return out
}

/** POST /v1/enroll meta (the JSON `meta` part). */
export function enrollMetaErrors(meta: unknown): string[] {
  if (!isObj(meta)) return ['meta must be an object']
  const out: string[] = []
  extraKeys(meta, ['user_id', 'display_name', 'email', 'role', 'consent', 'consent_version', 'card_id', 'provision_totp'], 'meta.', out)
  const id = userIdError(meta.user_id)
  if (id) out.push(id)
  const d = displayError(meta.display_name, 'display name')
  if (d) out.push(d)
  if (meta.consent !== true) out.push('consent: the person must agree (consent: true)')
  if (typeof meta.consent_version !== 'string' || !meta.consent_version.length || meta.consent_version.length > LIMITS.consentVersionMax) {
    out.push('consent_version: required')
  }
  for (const k of ['email', 'card_id'] as const) if (meta[k] !== undefined && meta[k] !== null && typeof meta[k] !== 'string') out.push(`${k}: text or empty`)
  if (meta.provision_totp !== undefined && typeof meta.provision_totp !== 'boolean') out.push('provision_totp: true or false')
  if (meta.role !== undefined && meta.role !== null && (typeof meta.role !== 'string' || !ROLE_RE.test(meta.role))) out.push('role: a-z and _ only')
  return out
}

/** POST /v1/admin/clock {set_local: "HH:MM"} | {reset: true} */
export function clockErrors(body: unknown): string[] {
  if (!isObj(body)) return ['body must be an object']
  const out: string[] = []
  extraKeys(body, ['set_local', 'offset_s', 'reset'], '', out)
  if (body.set_local !== undefined && body.set_local !== null && (typeof body.set_local !== 'string' || !HHMM_WRITE.test(body.set_local))) {
    out.push('time must be HH:MM (00:00-23:59)')
  }
  if (body.reset !== undefined && typeof body.reset !== 'boolean') out.push('reset: true or false')
  return out
}

// ------------------------------------------------------------------ R-I hours display

export interface HoursRow {
  start: string
  end: string
  source: 'role' | 'extra'
}

export type HoursResult =
  | { kind: 'windows'; windows: HoursRow[] }
  | { kind: 'none'; reason: string }

/**
 * R-I (API.md v1.4 §3.18): hours for `zone` on `day` = role_defaults[role].windows[zone] when the zone is
 * permitted (role zones + zones_add - zones_remove; explicit-grant zones only via zones_add) plus
 * extra_windows[zone], filtered by day. Exceptions / holidays / visitor passes are not shipped to the kiosk:
 * `user.today` is the edge's authoritative view for its own zone and is shown next to this.
 */
export function hoursFor(
  user: Pick<AccessUser, 'role' | 'status' | 'zones_add' | 'zones_remove' | 'extra_windows'>,
  zone: string,
  day: DayCode,
  access: Pick<AccessUsersResponse, 'role_defaults' | 'zones'>,
): HoursResult {
  if (user.status === 'NOT_IN_SCHEDULE' || !user.role) return { kind: 'none', reason: 'not in schedule' }
  if (user.status === 'REVOKED') return { kind: 'none', reason: 'revoked' }
  if (user.status === 'ERASED') return { kind: 'none', reason: 'erased (re-admit to restore)' }
  const role = access.role_defaults[user.role]
  if (!role) return { kind: 'none', reason: `role ${user.role} has no defaults` }
  const explicit = access.zones[zone]?.requires_explicit_grant === true
  const permitted = !user.zones_remove.includes(zone) && (user.zones_add.includes(zone) || (!explicit && role.zones.includes(zone)))
  const rows: HoursRow[] = []
  if (permitted) {
    for (const w of role.windows[zone] ?? []) if (w.days.includes(day)) rows.push({ start: w.start, end: w.end, source: 'role' })
  }
  for (const w of user.extra_windows[zone] ?? []) if (w.days.includes(day)) rows.push({ start: w.start, end: w.end, source: 'extra' })
  if (!rows.length) return { kind: 'none', reason: permitted ? 'no window this day' : 'zone not permitted' }
  rows.sort((a, b) => toMinutes(a.start) - toMinutes(b.start) || (a.source === b.source ? 0 : a.source === 'role' ? -1 : 1))
  return { kind: 'windows', windows: rows }
}

export function hoursText(r: HoursResult): string {
  return r.kind === 'windows' ? r.windows.map((w) => `${w.start}–${w.end}${w.source === 'extra' ? ' (extra)' : ''}`).join(', ') : r.reason
}

// ------------------------------------------------------------------ R-E demo clock default

/**
 * Default demo-clock time (R-E): max(now_local, earliest_local) when the earliest accepted time is today;
 * now_local when the limit lies on an earlier day. "23:59" when it lies on a later day (any time today rolls back).
 */
export function defaultDemoTime(clock: { now_local: string | null; date_local: string | null; earliest_local: string | null; earliest_date_local: string | null }): string | null {
  const now = clock.now_local
  if (!now) return clock.earliest_local
  if (!clock.earliest_local || !clock.earliest_date_local || !clock.date_local) return now
  if (clock.earliest_date_local < clock.date_local) return now
  if (clock.earliest_date_local > clock.date_local) return '23:59'
  return toMinutes(clock.earliest_local) > toMinutes(now) ? clock.earliest_local : now
}

/** The chosen HH:MM (today, edge date) is before the bundle's earliest accepted time -> rollback (bundle INVALID). */
export function isRollbackTime(t: string, clock: { date_local: string | null; earliest_local: string | null; earliest_date_local: string | null }): boolean {
  if (!HHMM_WRITE.test(t) || !clock.earliest_local || !clock.earliest_date_local || !clock.date_local) return false
  if (clock.earliest_date_local < clock.date_local) return false
  if (clock.earliest_date_local > clock.date_local) return true
  return toMinutes(t) < toMinutes(clock.earliest_local)
}

// ------------------------------------------------------------------ R-A / R-B registration plan

export type RegisterPlan =
  /** in this kiosk's bundle with ACTIVE status: enrol directly (works offline too) */
  | { kind: 'enrol'; role: string }
  /** must PUT access first (new person, role / name change, or ERASED re-admission), then enrol */
  | { kind: 'put-then-enrol'; readmit: boolean; create: boolean }
  /** cannot proceed: explain why */
  | { kind: 'blocked'; why: 'OFFLINE' | 'REVOKED' | 'NOT_AT_THIS_KIOSK' | 'NO_ROLE' | 'NEEDS_ACCESS_EDIT' }

/**
 * What registering `userId` needs (R-A / R-B). `user` is the Users & Access row (null = unknown everywhere).
 * `online` = writes possible now (not read-only, ONLINE). `wantRole` / `wantDisplay` = the form values.
 */
export function registerPlan(
  user: Pick<AccessUser, 'status' | 'role' | 'bundle_role' | 'display' | 'in_bundle'> | null,
  online: boolean,
  wantRole: string | null,
  wantDisplay: string,
): RegisterPlan {
  if (user?.status === 'REVOKED') return { kind: 'blocked', why: 'REVOKED' }
  const known = user !== null && user.status !== 'NOT_IN_SCHEDULE'
  const erased = user?.status === 'ERASED'
  const changes = known && !erased && ((wantRole !== null && wantRole !== user.role) || wantDisplay.trim() !== user.display)
  if (known && !erased && !changes) {
    if (user.in_bundle && user.bundle_role) return { kind: 'enrol', role: user.bundle_role }
    if (!online) return { kind: 'blocked', why: 'NOT_AT_THIS_KIOSK' }
    // in the master but not (yet) in this kiosk's bundle: a write + refresh tells whether it can be admitted here
    return { kind: 'put-then-enrol', readmit: false, create: false }
  }
  if (!online) return { kind: 'blocked', why: 'OFFLINE' }
  if (!wantRole) return { kind: 'blocked', why: 'NO_ROLE' }
  return { kind: 'put-then-enrol', readmit: erased, create: !known }
}

/**
 * RBAC gate on a registration plan (design v2 §B): a schedule write (put-then-enrol) needs access:edit, which
 * the enroller role does not hold. Without it the plan is blocked NEEDS_ACCESS_EDIT, so /register asks for an
 * admin instead of sending a PUT the edge would refuse with 403. Other plans pass through unchanged.
 */
export function gatePlan(plan: RegisterPlan, canEditAccess: boolean): RegisterPlan {
  return plan.kind === 'put-then-enrol' && !canEditAccess ? { kind: 'blocked', why: 'NEEDS_ACCESS_EDIT' } : plan
}

/** The sentence /register shows to a user without access:edit. */
export function askAdminText(userId: string): string {
  return `Ask an admin to add ${userId || 'this person'} to the schedule.`
}

/**
 * "v50", or "pending refresh" when the write response carries no version (M2: the edge's follow-up pull failed,
 * so cloud_bundle_version / seq / revoked_at are null). Never an error: the change is saved in the cloud.
 */
export function versionText(v: number | null | undefined): string {
  return typeof v === 'number' ? `v${v}` : 'pending refresh'
}

/** Same rule as the edge's refresh_after_write: a successful pull, and at least the written version when known. */
export function bundleApplied(b: { result: string; installed_version: number | null }, want: number | null): boolean {
  if (b.result === 'failed') return false
  return want === null || (b.installed_version !== null && b.installed_version >= want)
}

/** R-K: code_length / valid_until may be null in the rotate response; never crash, never hide the codes. */
export const codeLengthText = (n: number | null): string => (n === null ? 'length unknown' : `${String(n)} digits`)
export function validUntilText(iso: string | null): string {
  if (iso === null) return 'unknown'
  const t = Date.parse(iso)
  return Number.isNaN(t) ? `unknown (${iso})` : new Date(t).toLocaleString([], { hour12: false })
}
