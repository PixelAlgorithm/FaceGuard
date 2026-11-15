/**
 * STRICT parsers for the admin-access / enrolment responses of the edge (docs/API.md v1.4 §3.15, §3.18,
 * §3.10 demo_clock; examples: docs/contracts/admin_access.examples.json). Every field is read under its
 * contract name only: a missing or mistyped field throws ApiError BAD_RESPONSE naming the field, so a
 * contract drift is visible at once instead of silently blanking a column or inventing a value.
 * The output keeps exactly the contract keys (scripts/contract-test.ts checks parse(body) deep-equals body).
 *
 * Imports carry explicit `.ts` extensions so Node can run this module directly (contract test).
 */
import {
  ACCESS_STATUSES,
  ApiError,
  BUNDLE_RESULTS,
  CLOUD_STATES,
  DAY_CODES,
  ERASE_CLOUD,
  READ_ONLY_CODES,
  SCHEDULE_STATUSES_NOW,
  type AccessToday,
  type AccessUpdateResult,
  type AccessUser,
  type AccessUsersResponse,
  type AccessWindow,
  type ApiErrorExtra,
  type BundleRefresh,
  type CacheState,
  type DayCode,
  type DemoClockStatus,
  type EnrolledUser,
  type EnrolledUsersResponse,
  type EnrollCloudCall,
  type EnrollResponse,
  type EraseResponse,
  type RevokeResult,
  type RoleDefaults,
  type RotateCodesResult,
  type ZoneDef,
  type ZoneWindows,
} from './types.ts'

type Obj = Record<string, unknown>

const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v)

function describe(v: unknown): string {
  if (v === undefined) return 'missing'
  if (v === null) return 'null'
  if (Array.isArray(v)) return 'an array'
  if (typeof v === 'string') return `"${v.slice(0, 40)}"`
  return typeof v === 'object' ? 'an object' : `${typeof v} ${String(v)}`
}

function fail(path: string, want: string, got: unknown): never {
  throw new ApiError('BAD_RESPONSE', 200, `edge response does not match the API contract: ${path} must be ${want} (got ${describe(got)})`)
}

function recordOf<T>(v: unknown, p: string, item: (v: unknown, p: string) => T): Record<string, T> {
  if (!isObj(v)) return fail(p, 'an object', v)
  const out: Record<string, T> = {}
  for (const [key, x] of Object.entries(v)) out[key] = item(x, `${p}.${key}`)
  return out
}

/** Field reader bound to one object + its path (for error messages). */
class R {
  readonly o: Obj
  readonly p: string
  constructor(v: unknown, p: string) {
    this.o = isObj(v) ? v : fail(p, 'an object', v)
    this.p = p
  }
  private v(k: string): unknown {
    return k in this.o ? this.o[k] : fail(`${this.p}.${k}`, 'present', undefined)
  }
  has(k: string): boolean {
    return k in this.o
  }
  str(k: string): string {
    const v = this.v(k)
    return typeof v === 'string' ? v : fail(`${this.p}.${k}`, 'a string', v)
  }
  strN(k: string): string | null {
    const v = this.v(k)
    return v === null ? null : typeof v === 'string' ? v : fail(`${this.p}.${k}`, 'a string or null', v)
  }
  bool(k: string): boolean {
    const v = this.v(k)
    return typeof v === 'boolean' ? v : fail(`${this.p}.${k}`, 'a boolean', v)
  }
  boolN(k: string): boolean | null {
    const v = this.v(k)
    return v === null ? null : typeof v === 'boolean' ? v : fail(`${this.p}.${k}`, 'a boolean or null', v)
  }
  int(k: string): number {
    const v = this.v(k)
    return typeof v === 'number' && Number.isInteger(v) ? v : fail(`${this.p}.${k}`, 'an integer', v)
  }
  intN(k: string): number | null {
    const v = this.v(k)
    return v === null ? null : typeof v === 'number' && Number.isInteger(v) ? v : fail(`${this.p}.${k}`, 'an integer or null', v)
  }
  num(k: string): number {
    const v = this.v(k)
    return typeof v === 'number' && Number.isFinite(v) ? v : fail(`${this.p}.${k}`, 'a number', v)
  }
  numN(k: string): number | null {
    return this.v(k) === null ? null : this.num(k)
  }
  oneOf<T extends string>(k: string, values: readonly T[]): T {
    const v = this.v(k)
    return typeof v === 'string' && (values as readonly string[]).includes(v) ? (v as T) : fail(`${this.p}.${k}`, `one of ${values.join('|')}`, v)
  }
  oneOfN<T extends string>(k: string, values: readonly T[]): T | null {
    return this.v(k) === null ? null : this.oneOf(k, values)
  }
  hhmm(k: string): string {
    return hhmm(this.v(k), `${this.p}.${k}`)
  }
  day(k: string): DayCode {
    return day(this.v(k), `${this.p}.${k}`)
  }
  list<T>(k: string, item: (v: unknown, p: string) => T): T[] {
    const v = this.v(k)
    if (!Array.isArray(v)) return fail(`${this.p}.${k}`, 'an array', v)
    return v.map((x, i) => item(x, `${this.p}.${k}[${i}]`))
  }
  strs(k: string): string[] {
    return this.list(k, (x, p) => (typeof x === 'string' ? x : fail(p, 'a string', x)))
  }
  record<T>(k: string, item: (v: unknown, p: string) => T): Record<string, T> {
    return recordOf(this.v(k), `${this.p}.${k}`, item)
  }
  obj(k: string): R {
    return new R(this.v(k), `${this.p}.${k}`)
  }
  objN(k: string): R | null {
    const v = this.v(k)
    return v === null ? null : new R(v, `${this.p}.${k}`)
  }
}

const HHMM_READ = /^(([01]\d|2[0-3]):[0-5]\d|24:00)$/

function hhmm(v: unknown, p: string): string {
  return typeof v === 'string' && HHMM_READ.test(v) ? v : fail(p, 'HH:MM', v)
}

function day(v: unknown, p: string): DayCode {
  return typeof v === 'string' && (DAY_CODES as readonly string[]).includes(v) ? (v as DayCode) : fail(p, 'a day code MON..SUN', v)
}

export function parseWindow(v: unknown, p: string): AccessWindow {
  const r = new R(v, p)
  return { days: r.list('days', day), start: r.hhmm('start'), end: r.hhmm('end') }
}

const zoneWindows = (v: unknown, p: string): ZoneWindows =>
  recordOf(v, p, (ws, wp) => (Array.isArray(ws) ? ws.map((w, i) => parseWindow(w, `${wp}[${i}]`)) : fail(wp, 'an array', ws)))

/** BundleRefresh (`applied` only when the edge sent it: write responses). */
export function parseBundleRefresh(v: unknown, p = 'bundle'): BundleRefresh {
  const r = new R(v, p)
  const out: BundleRefresh = {
    previous_version: r.intN('previous_version'),
    installed_version: r.intN('installed_version'),
    changed: r.bool('changed'),
    result: r.oneOf('result', BUNDLE_RESULTS),
    error: r.strN('error'),
  }
  if (r.has('applied')) out.applied = r.boolN('applied')
  return out
}

function parseToday(r: R): AccessToday {
  return {
    zone: r.str('zone'),
    date: r.str('date'),
    day: r.day('day'),
    now_local: r.hhmm('now_local'),
    permitted: r.bool('permitted'),
    holiday: r.bool('holiday'),
    windows: r.list('windows', (w, wp) => {
      const x = new R(w, wp)
      return { start: x.hhmm('start'), end: x.hhmm('end'), source: x.oneOf('source', ['role', 'extra'] as const) }
    }),
    status_now: r.oneOf('status_now', SCHEDULE_STATUSES_NOW),
  }
}

export function parseAccessUser(v: unknown, p: string): AccessUser {
  const r = new R(v, p)
  const fb = r.obj('fallback')
  const local = r.obj('local')
  const today = r.objN('today')
  return {
    user_id: r.str('user_id'),
    display: r.str('display'),
    role: r.strN('role'),
    bundle_role: r.strN('bundle_role'),
    in_schedule: r.bool('in_schedule'),
    in_bundle: r.bool('in_bundle'),
    status: r.oneOf('status', ACCESS_STATUSES),
    revoked_at: r.strN('revoked_at'),
    revoked_reason: r.strN('revoked_reason'),
    bundle_stale: r.bool('bundle_stale'),
    zones_add: r.strs('zones_add'),
    zones_remove: r.strs('zones_remove'),
    extra_windows: r.record('extra_windows', (ws, wp) => (Array.isArray(ws) ? ws.map((w, i) => parseWindow(w, `${wp}[${i}]`)) : fail(wp, 'an array', ws))),
    valid_from: r.strN('valid_from'),
    valid_until: r.strN('valid_until'),
    fallback: { totp_enrolled: fb.bool('totp_enrolled'), card: fb.bool('card') },
    cloud_faces: r.intN('cloud_faces'),
    local: {
      enrolled: local.bool('enrolled'),
      templates: local.int('templates'),
      template_version: local.intN('template_version'),
      template_role: local.strN('template_role'),
      totp_local: local.bool('totp_local'),
      updated_at: local.strN('updated_at'),
    },
    today: today ? parseToday(today) : null,
  }
}

function roleDefaults(v: unknown, p: string): RoleDefaults {
  const r = new R(v, p)
  return { zones: r.strs('zones'), windows: zoneWindows(r.o.windows, `${p}.windows`) }
}

function zoneDef(v: unknown, p: string): ZoneDef {
  const r = new R(v, p)
  return { risk: r.oneOf('risk', ['low', 'medium', 'high'] as const), requires_explicit_grant: r.bool('requires_explicit_grant') }
}

/** GET /v1/admin/access/users */
export function parseAccessUsers(raw: unknown): AccessUsersResponse {
  const r = new R(raw, 'access.users')
  const b = r.obj('bundle')
  return {
    source: r.oneOf('source', ['cloud+bundle', 'bundle'] as const),
    read_only: r.bool('read_only'),
    read_only_code: r.oneOfN('read_only_code', READ_ONLY_CODES),
    read_only_reason: r.strN('read_only_reason'),
    mode: r.oneOf('mode', ['ONLINE', 'OFFLINE'] as const),
    kiosk_id: r.str('kiosk_id'),
    zone: r.strN('zone'),
    now_local: r.hhmm('now_local'),
    date_local: r.str('date_local'),
    day: r.day('day'),
    bundle: { version: b.intN('version'), issued_at: b.strN('issued_at'), expires_at: b.strN('expires_at') },
    cloud_bundle_version: r.intN('cloud_bundle_version'),
    roles: r.strs('roles'),
    role_defaults: r.record('role_defaults', roleDefaults),
    zones: r.record('zones', zoneDef),
    staff_ids: r.strs('staff_ids'),
    pending_cloud_erasures: r.strs('pending_cloud_erasures'),
    users: r.list('users', parseAccessUser),
  }
}

function userOrNull(r: R): AccessUser | null {
  if (!r.has('user')) fail(`${r.p}.user`, 'present', undefined)
  return r.o.user === null ? null : parseAccessUser(r.o.user, `${r.p}.user`)
}

/** PUT /v1/admin/access/users/{user_id} */
export function parseAccessUpdate(raw: unknown): AccessUpdateResult {
  const r = new R(raw, 'access.put')
  return {
    user_id: r.str('user_id'),
    created: r.bool('created'),
    unchanged: r.bool('unchanged'),
    readmitted: r.bool('readmitted'),
    restored: r.bool('restored'),
    previous_role: r.strN('previous_role'),
    role: r.str('role'),
    cloud_bundle_version: r.intN('cloud_bundle_version'),
    bundle: parseBundleRefresh(r.o.bundle, 'access.put.bundle'),
    user: userOrNull(r),
    warnings: r.strs('warnings'),
  }
}

/** POST /v1/admin/access/users/{user_id}/revoke */
export function parseRevoke(raw: unknown): RevokeResult {
  const r = new R(raw, 'access.revoke')
  return {
    user_id: r.str('user_id'),
    type: r.oneOf('type', ['USER'] as const),
    reason: r.str('reason'),
    revoked_at: r.strN('revoked_at'),
    seq: r.intN('seq'),
    cloud_bundle_version: r.intN('cloud_bundle_version'),
    bundle: parseBundleRefresh(r.o.bundle, 'access.revoke.bundle'),
    user: userOrNull(r),
    warnings: r.strs('warnings'),
  }
}

/** POST /v1/admin/access/codes/rotate (flat; the plaintext codes are shown once and never stored). */
export function parseRotate(raw: unknown): RotateCodesResult {
  const r = new R(raw, 'codes.rotate')
  if (r.bool('one_time') !== true) fail('codes.rotate.one_time', 'true', r.o.one_time)
  return {
    staff_id: r.str('staff_id'),
    codes: r.list('codes', (c, p) => {
      const x = new R(c, p)
      return { code_id: x.strN('code_id'), code: x.str('code') }
    }),
    code_length: r.intN('code_length'),
    valid_until: r.strN('valid_until'),
    one_time: true,
    dropped_code_ids: r.strs('dropped_code_ids'),
    warning: r.str('warning'),
    cloud_bundle_version: r.intN('cloud_bundle_version'),
    bundle: parseBundleRefresh(r.o.bundle, 'codes.rotate.bundle'),
    warnings: r.strs('warnings'),
  }
}

/** POST /v1/admin/bundle/refresh */
export const parseRefresh = (raw: unknown): BundleRefresh => parseBundleRefresh(raw, 'bundle.refresh')

/** POST /v1/enroll -> 201 */
export function parseEnroll(raw: unknown): EnrollResponse {
  const r = new R(raw, 'enroll')
  const cloud = r.objN('cloud')
  return {
    user_id: r.str('user_id'),
    template_version: r.int('template_version'),
    local_cache_updated: r.bool('local_cache_updated'),
    cloud_indexed: r.bool('cloud_indexed'),
    cloud_state: r.oneOf('cloud_state', CLOUD_STATES),
    totp_provisioning_uri: r.strN('totp_provisioning_uri'),
    totp_active: r.bool('totp_active'),
    frames_used: r.int('frames_used'),
    frames_rejected: r.list('frames_rejected', (x, p) => (isObj(x) ? x : fail(p, 'an object', x))),
    min_pairwise_cosine: r.numN('min_pairwise_cosine'),
    cloud: cloud ? parseEnrollCloud(cloud) : null,
    schedule_role: r.strN('schedule_role'),
    schedule_display: r.strN('schedule_display'),
    role_requested: r.strN('role_requested'),
    role_applied: r.bool('role_applied'),
    bundle_version: r.intN('bundle_version'),
    reinstated_after_erasure: r.bool('reinstated_after_erasure'),
    warnings: r.strs('warnings'),
  }
}

/**
 * enroll.cloud: {status, body} when the cloud answered; {status: null, error} on a transport failure
 * (audit KAO-04: the local enrolment IS committed and the shown-once TOTP URI must not be lost).
 */
function parseEnrollCloud(cloud: R): EnrollCloudCall {
  if (cloud.o.status === null) return { status: null, error: cloud.str('error') }
  if (!cloud.has('body')) fail('enroll.cloud.body', 'present', undefined)
  return { status: cloud.int('status'), body: cloud.o.body }
}

/** DELETE /v1/enroll/{user_id} */
export function parseErase(raw: unknown): EraseResponse {
  const r = new R(raw, 'erase')
  const bundle = r.objN('bundle')
  return {
    user_id: r.str('user_id'),
    local_removed: r.bool('local_removed'),
    cloud: r.oneOf('cloud', ERASE_CLOUD),
    cloud_status: r.intN('cloud_status'),
    message: r.strN('message'),
    bundle: bundle ? parseBundleRefresh(bundle.o, 'erase.bundle') : null,
  }
}

function enrolledUser(v: unknown, p: string): EnrolledUser {
  const r = new R(v, p)
  return {
    user_id: r.str('user_id'),
    display_name: r.str('display_name'),
    role: r.strN('role'),
    bundle_role: r.strN('bundle_role'),
    bundle_display: r.strN('bundle_display'),
    in_schedule: r.bool('in_schedule'),
    template_role: r.strN('template_role'),
    template_display_name: r.strN('template_display_name'),
    template_version: r.intN('template_version'),
    templates: r.intN('templates'),
    totp_local: r.bool('totp_local'),
    card: r.bool('card'),
    updated_at: r.strN('updated_at'),
  }
}

/** GET /v1/admin/users */
export function parseEnrolledUsers(raw: unknown): EnrolledUsersResponse {
  const r = new R(raw, 'admin.users')
  return {
    users: r.list('users', enrolledUser),
    bundle_version: r.intN('bundle_version'),
    count: r.int('count'),
    model: r.strN('model'),
    age_h: r.numN('age_h'),
    skipped_model_mismatch: r.int('skipped_model_mismatch'),
  }
}

const CACHE_STATES: readonly CacheState[] = ['FRESH', 'EXPIRED', 'INVALID']

/** GET /v1/mode demo_clock (non-null) = POST /v1/admin/clock response. */
export function parseDemoClock(raw: unknown, p = 'demo_clock'): DemoClockStatus {
  const r = new R(raw, p)
  return {
    active: r.bool('active'),
    now_local: r.hhmm('now_local'),
    now_utc: r.str('now_utc'),
    offset_s: r.num('offset_s'),
    date_local: r.str('date_local'),
    bundle_issued_at: r.strN('bundle_issued_at'),
    earliest_utc: r.strN('earliest_utc'),
    earliest_local: r.o.earliest_local === null ? null : r.hhmm('earliest_local'),
    earliest_date_local: r.strN('earliest_date_local'),
    bundle_rollback: r.bool('bundle_rollback'),
    cache_state: r.oneOfN('cache_state', CACHE_STATES),
  }
}

/**
 * Edge error body {error:{code, message, attempt_id, reason?, cloud_status?, cloud_code?, retry_after_s?,
 * installed_version?, bundle_version?, details?}} -> ApiError. FastAPI's default {detail} shape is mapped too.
 */
const strArr = (v: unknown): string[] | null => (Array.isArray(v) && v.every((x) => typeof x === 'string') ? [...(v as string[])] : null)

export function apiErrorFromBody(status: number, body: unknown): ApiError {
  const err = isObj(body) && isObj(body.error) ? body.error : null
  if (err) {
    const s = (k: string) => (typeof err[k] === 'string' ? (err[k] as string) : null)
    const n = (k: string) => (typeof err[k] === 'number' && Number.isFinite(err[k]) ? (err[k] as number) : null)
    const extra: ApiErrorExtra = {
      reason: s('reason'),
      cloud_status: n('cloud_status'),
      cloud_code: s('cloud_code'),
      retry_after_s: n('retry_after_s'),
      installed_version: n('installed_version'),
      bundle_version: n('bundle_version'),
      details: err.details,
      mfa_ticket: s('mfa_ticket'),
      required: strArr(err.required),
      problems: strArr(err.problems),
      methods: strArr(err.methods),
    }
    return new ApiError(s('code') ?? `HTTP_${status}`, status, s('message') ?? `HTTP ${status}`, s('attempt_id'), extra)
  }
  const detail = isObj(body) && 'detail' in body ? body.detail : null
  const code =
    status === 422
      ? 'VALIDATION_ERROR'
      : status === 401
        ? 'UNAUTHORIZED'
        : status === 403
          ? 'FORBIDDEN'
          : status === 404
            ? 'NOT_FOUND'
            : status === 503
              ? 'CLOUD_UNAVAILABLE'
              : `HTTP_${status}`
  return new ApiError(code, status, detail ? JSON.stringify(detail).slice(0, 300) : `HTTP ${status}`, null, { details: detail })
}
