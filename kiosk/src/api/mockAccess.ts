/**
 * MOCK cloud master schedule + edge proxies for the in-browser mock edge (?mock=1), emitting EXACTLY the
 * v1.4 contract shapes (mock.ts passes every result through the strict parsers of ./access) and the same
 * state rules: R-A create needs display + consent, R-B ERASED -> re-admit with consent, R-C revoke /
 * restore (consent + restore), enrolment refused when not in the kiosk bundle (409 NOT_IN_SCHEDULE),
 * ERASED (409 ERASED_IN_BUNDLE) or REVOKED (403 USER_REVOKED), offline writes 503 OFFLINE, queued erasures.
 * Role definitions mirror config/schedule.demo.json (MOCK ONLY). Shared across tabs via localStorage.
 */
import { DEMO_USERS } from '../shared/demoUsers'
import { accessUpdateErrors, enrollMetaErrors, hoursFor, revokeErrors, rotateErrors, toMinutes } from '../shared/accessRules'
import {
  ApiError,
  DAY_CODES,
  type AccessStatus,
  type AccessUpdate,
  type AccessUpdateResult,
  type AccessUser,
  type AccessUsersResponse,
  type BundleRefresh,
  type DayCode,
  type EnrolledUsersResponse,
  type EnrollMeta,
  type EnrollResponse,
  type EraseResponse,
  type RevokeRequest,
  type RevokeResult,
  type RoleDefaults,
  type RotateCodesRequest,
  type RotateCodesResult,
  type ZoneDef,
  type ZoneWindows,
} from './types'

const KEY = 'hid.mock.access.v14'
const KIOSK_ID = 'KIOSK_MAIN_01'
const KIOSK_ZONE = 'MAIN_GATE'
const ALL: DayCode[] = [...DAY_CODES]
const WEEK6: DayCode[] = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT']
const WEEK5: DayCode[] = ['MON', 'TUE', 'WED', 'THU', 'FRI']

export const MOCK_ROLE_DEFAULTS: Record<string, RoleDefaults> = {
  contractor: {
    zones: ['MAIN_GATE', 'LAB_BLOCK'],
    windows: { MAIN_GATE: [{ days: WEEK6, start: '08:00', end: '18:00' }], LAB_BLOCK: [{ days: WEEK5, start: '09:00', end: '17:00' }] },
  },
  faculty: {
    zones: ['MAIN_GATE', 'LIBRARY', 'LAB_BLOCK'],
    windows: {
      MAIN_GATE: [{ days: ALL, start: '06:00', end: '23:00' }],
      LIBRARY: [{ days: WEEK6, start: '07:00', end: '22:00' }],
      LAB_BLOCK: [{ days: WEEK6, start: '07:00', end: '22:00' }],
    },
  },
  staff: {
    zones: ['MAIN_GATE', 'LIBRARY', 'LAB_BLOCK'],
    windows: {
      MAIN_GATE: [{ days: ALL, start: '00:00', end: '24:00' }],
      LIBRARY: [{ days: WEEK6, start: '07:00', end: '21:00' }],
      LAB_BLOCK: [{ days: WEEK6, start: '07:00', end: '21:00' }],
      SERVER_ROOM: [{ days: WEEK5, start: '09:00', end: '18:00' }],
    },
  },
  student: {
    zones: ['MAIN_GATE', 'LIBRARY', 'LAB_BLOCK'],
    windows: {
      MAIN_GATE: [
        { days: WEEK6, start: '06:00', end: '22:00' },
        { days: ['SUN'], start: '08:00', end: '20:00' },
      ],
      LIBRARY: [
        { days: WEEK6, start: '08:00', end: '21:00' },
        { days: ['SUN'], start: '10:00', end: '17:00' },
      ],
      LAB_BLOCK: [
        { days: WEEK5, start: '08:00', end: '18:00' },
        { days: ['SAT'], start: '09:00', end: '13:00' },
      ],
      HOSTEL: [{ days: ALL, start: '05:00', end: '23:00' }],
    },
  },
  visitor: {
    zones: [],
    windows: {
      MAIN_GATE: [{ days: ALL, start: '09:00', end: '18:00' }],
      LIBRARY: [{ days: ALL, start: '10:00', end: '17:00' }],
      LAB_BLOCK: [{ days: ALL, start: '09:00', end: '18:00' }],
    },
  },
}

const MOCK_ZONES: Record<string, ZoneDef> = {
  MAIN_GATE: { risk: 'low', requires_explicit_grant: false },
  LIBRARY: { risk: 'low', requires_explicit_grant: false },
  LAB_BLOCK: { risk: 'medium', requires_explicit_grant: false },
  HOSTEL: { risk: 'medium', requires_explicit_grant: false },
  SERVER_ROOM: { risk: 'high', requires_explicit_grant: true },
}

interface MockUser {
  display: string
  role: string
  zones_add: string[]
  zones_remove: string[]
  extra_windows: ZoneWindows
  valid_from: string | null
  valid_until: string | null
  status: Exclude<AccessStatus, 'NOT_IN_SCHEDULE'>
  revoked_at: string | null
  revoked_reason: string | null
  totp_enrolled: boolean
  card: boolean
}

interface MockEnrolment {
  display_name: string
  role: string | null
  templates: number
  template_version: number
  totp: boolean
  card: boolean
  updated_at: string
}

interface MockAccessState {
  /** master version */
  version: number
  issuedAt: string
  /** version the (mock) edge has installed */
  installed: number
  /** users as of the installed bundle (snapshot at install time) */
  bundleUsers: Record<string, MockUser>
  users: Record<string, MockUser>
  enrolled: Record<string, MockEnrolment>
  pendingErasures: string[]
  seq: number
  staffIds: string[]
}

const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v)) as T
const isoAt = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z')
const isoNow = () => isoAt(Date.now())

function fresh(): MockAccessState {
  const users: Record<string, MockUser> = {}
  for (const u of DEMO_USERS) {
    users[u.user_id] = {
      display: u.display,
      role: u.role in MOCK_ROLE_DEFAULTS ? u.role : 'student',
      zones_add: [],
      zones_remove: [],
      extra_windows: {},
      valid_from: null,
      valid_until: null,
      status: 'ACTIVE',
      revoked_at: null,
      revoked_reason: null,
      totp_enrolled: false,
      card: false,
    }
  }
  const issuedAt = isoAt(Math.floor((Date.now() - 3600_000) / 60_000) * 60_000)
  return { version: 42, issuedAt, installed: 42, bundleUsers: clone(users), users, enrolled: {}, pendingErasures: [], seq: 10, staffIds: ['s_guard01', 's_guard02'] }
}

function load(): MockAccessState {
  try {
    const raw = window.localStorage.getItem(KEY)
    if (raw) return { ...fresh(), ...(JSON.parse(raw) as Partial<MockAccessState>) }
  } catch {
    /* corrupted -> fresh */
  }
  return fresh()
}

function save(s: MockAccessState): void {
  try {
    window.localStorage.setItem(KEY, JSON.stringify(s))
  } catch {
    /* ignore */
  }
}

/** publish a new master version (issued now) */
function publish(s: MockAccessState): void {
  s.version += 1
  s.issuedAt = isoNow()
}

/** the mock edge pulls + installs the master (bundle = master snapshot) */
function install(s: MockAccessState): BundleRefresh {
  const prev = s.installed
  s.installed = s.version
  s.bundleUsers = clone(s.users)
  return { previous_version: prev, installed_version: s.installed, changed: prev !== s.installed, result: prev !== s.installed ? 'installed' : 'not_modified', error: null }
}

/**
 * Test knobs (URL only): ?mockpull=fail = the edge's follow-up pull after a write fails (M2: applied:false,
 * cloud_bundle_version / seq / revoked_at null, the master still changes); ?mockerase=fail = the erasure queue
 * cannot be written (M1: cloud "failed", local data erased).
 */
const KNOBS = typeof window === 'undefined' ? new URLSearchParams() : new URLSearchParams(window.location.search)
const PULL_FAILS = KNOBS.get('mockpull') === 'fail'
const ERASE_QUEUE_FAILS = KNOBS.get('mockerase') === 'fail'

/** the write's follow-up pull: installs, or (?mockpull=fail) fails and leaves the old bundle installed */
function pullAfterWrite(s: MockAccessState): BundleRefresh {
  if (!PULL_FAILS) return { ...install(s), applied: true }
  return { previous_version: s.installed, installed_version: s.installed, changed: false, result: 'failed', error: 'CLOUD_UNAVAILABLE: ReadTimeout: timed out (mock)', applied: false }
}

function offlineError(): ApiError {
  return new ApiError('CLOUD_UNAVAILABLE', 503, 'kiosk is OFFLINE: access changes need the cloud (the signed schedule is the source of truth)', null, { reason: 'OFFLINE' })
}

function validation(errors: string[]): ApiError {
  return new ApiError('VALIDATION_ERROR', 422, `invalid request: ${errors.join('; ')}`, null, { details: errors })
}

export function mockBundleVersion(): number {
  return load().installed
}

export function mockBundleIssuedAt(): string {
  return load().issuedAt
}

function permittedAt(u: Pick<MockUser, 'role' | 'zones_add' | 'zones_remove'>, zone: string): boolean {
  const role = MOCK_ROLE_DEFAULTS[u.role]
  const explicit = MOCK_ZONES[zone]?.requires_explicit_grant === true
  return !u.zones_remove.includes(zone) && (u.zones_add.includes(zone) || (!explicit && !!role?.zones.includes(zone)))
}

/** the per-kiosk bundle is filtered to the kiosk zone (users without access there are not in it) */
const inKioskBundle = (u: MockUser) => permittedAt(u, KIOSK_ZONE)

/** Role of a user in the installed mock bundle (for the mock's ALLOW screen); null if unknown. */
export function mockScheduleRole(userId: string): string | null {
  const u = load().bundleUsers[userId]
  return u && inKioskBundle(u) ? u.role : null
}

function istParts(at: number): { date: string; day: DayCode; hhmm: string } {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Kolkata',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    weekday: 'short',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(at)
  const g = (t: string) => parts.find((p) => p.type === t)?.value ?? ''
  const wd = g('weekday').slice(0, 3).toUpperCase() as DayCode
  return { date: `${g('year')}-${g('month')}-${g('day')}`, day: DAY_CODES.includes(wd) ? wd : 'MON', hhmm: `${g('hour')}:${g('minute')}` }
}

function row(s: MockAccessState, id: string, offline: boolean, nowMs: number): AccessUser {
  const master = offline ? undefined : s.users[id]
  const b = s.bundleUsers[id]
  const bundleUser = b && inKioskBundle(b) ? b : undefined
  const u = master ?? bundleUser
  const e = s.enrolled[id]
  const t = istParts(nowMs)
  const status: AccessStatus = u ? u.status : 'NOT_IN_SCHEDULE'
  let today: AccessUser['today'] = null
  if (bundleUser) {
    const h = hoursFor(bundleUser, KIOSK_ZONE, t.day, { role_defaults: MOCK_ROLE_DEFAULTS, zones: MOCK_ZONES })
    const windows = h.kind === 'windows' ? h.windows : []
    const now = toMinutes(t.hhmm)
    const inside = windows.some((w) => toMinutes(w.start) <= now && now < toMinutes(w.end))
    today = {
      zone: KIOSK_ZONE,
      date: t.date,
      day: t.day,
      now_local: t.hhmm,
      permitted: permittedAt(bundleUser, KIOSK_ZONE),
      holiday: false,
      windows,
      status_now: bundleUser.status !== 'ACTIVE' ? 'REVOKED' : inside ? 'IN_WINDOW' : windows.length ? 'OUTSIDE_WINDOW' : 'NO_ENTITLEMENT',
    }
  }
  const same = (a: unknown, c: unknown) => JSON.stringify(a) === JSON.stringify(c)
  const stale =
    !!master &&
    inKioskBundle(master) &&
    (!bundleUser || master.role !== bundleUser.role || master.status !== bundleUser.status || !same(master.extra_windows, bundleUser.extra_windows) || !same(master.zones_add, bundleUser.zones_add))
  return {
    user_id: id,
    display: u?.display ?? e?.display_name ?? id,
    role: u?.role ?? null,
    bundle_role: bundleUser?.role ?? null,
    in_schedule: !!u,
    in_bundle: !!bundleUser,
    status,
    revoked_at: u?.revoked_at ?? null,
    revoked_reason: u?.revoked_reason ?? null,
    bundle_stale: stale,
    zones_add: u?.zones_add ?? [],
    zones_remove: u?.zones_remove ?? [],
    extra_windows: offline ? Object.fromEntries(Object.entries(u?.extra_windows ?? {}).filter(([z]) => z === KIOSK_ZONE)) : (u?.extra_windows ?? {}),
    valid_from: u?.valid_from ?? null,
    valid_until: u?.valid_until ?? null,
    fallback: { totp_enrolled: u?.totp_enrolled ?? false, card: u?.card ?? false },
    cloud_faces: offline ? null : e && u ? e.templates : 0,
    local: {
      enrolled: !!e,
      templates: e?.templates ?? 0,
      template_version: e?.template_version ?? null,
      template_role: e?.role ?? null,
      totp_local: e?.totp ?? false,
      updated_at: e?.updated_at ?? null,
    },
    today,
  }
}

function eraseInMaster(s: MockAccessState, id: string): void {
  const u = s.users[id]
  if (u && u.status !== 'REVOKED') {
    u.status = 'ERASED'
    u.revoked_at = isoNow()
    u.revoked_reason = 'ERASED'
    u.totp_enrolled = false
  }
}

/** pending (offline) cloud erasures are replayed when the mock is online again (R-J) */
function replayErasures(s: MockAccessState, offline: boolean): void {
  if (offline || !s.pendingErasures.length) return
  for (const id of s.pendingErasures) eraseInMaster(s, id)
  s.pendingErasures = []
  publish(s)
  install(s)
  save(s)
}

export function mockListAccess(offline: boolean, nowMs = Date.now()): AccessUsersResponse {
  const s = load()
  replayErasures(s, offline)
  const ids = new Set<string>([
    ...(offline ? [] : Object.keys(s.users)),
    ...Object.keys(s.bundleUsers).filter((id) => inKioskBundle(s.bundleUsers[id])),
    ...Object.keys(s.enrolled),
  ])
  const t = istParts(nowMs)
  const kioskOnly = (rd: RoleDefaults): RoleDefaults => ({
    zones: rd.zones.filter((z) => z === KIOSK_ZONE),
    windows: Object.fromEntries(Object.entries(rd.windows).filter(([z]) => z === KIOSK_ZONE)),
  })
  return {
    source: offline ? 'bundle' : 'cloud+bundle',
    read_only: offline,
    read_only_code: offline ? 'OFFLINE' : null,
    read_only_reason: offline ? 'kiosk is OFFLINE: showing the installed signed bundle; access changes need the cloud master schedule' : null,
    mode: offline ? 'OFFLINE' : 'ONLINE',
    kiosk_id: KIOSK_ID,
    zone: KIOSK_ZONE,
    now_local: t.hhmm,
    date_local: t.date,
    day: t.day,
    bundle: { version: s.installed, issued_at: s.issuedAt, expires_at: isoAt(Date.parse(s.issuedAt) + 12 * 3600_000) },
    cloud_bundle_version: offline ? null : s.version,
    roles: Object.keys(MOCK_ROLE_DEFAULTS).sort(),
    role_defaults: offline ? Object.fromEntries(Object.entries(MOCK_ROLE_DEFAULTS).map(([k, v]) => [k, kioskOnly(v)])) : clone(MOCK_ROLE_DEFAULTS),
    zones: offline ? { [KIOSK_ZONE]: MOCK_ZONES[KIOSK_ZONE] } : clone(MOCK_ZONES),
    staff_ids: [...s.staffIds],
    pending_cloud_erasures: [...s.pendingErasures],
    users: [...ids].sort().map((id) => row(s, id, offline, nowMs)),
  }
}

const toUtc = (v: string | null | undefined): string | null => (v ? isoAt(Date.parse(v)) : null)

export function mockPutAccess(offline: boolean, userId: string, req: AccessUpdate): AccessUpdateResult {
  const errs = accessUpdateErrors(userId, req)
  if (errs.length) throw validation(errs)
  if (offline) throw offlineError()
  const s = load()
  if (!(req.role in MOCK_ROLE_DEFAULTS)) {
    throw new ApiError('VALIDATION_ERROR', 422, `unknown role '${req.role}' (bundle roles: ${Object.keys(MOCK_ROLE_DEFAULTS).sort().join(', ')})`, null, { reason: 'UNKNOWN_ROLE' })
  }
  const unknownZones = [...(req.zones_add ?? []), ...Object.keys(req.extra_windows ?? {})].filter((z) => !(z in MOCK_ZONES))
  if (unknownZones.length) throw new ApiError('VALIDATION_ERROR', 422, `cloud: unknown zones ${JSON.stringify(unknownZones)}`, null, { reason: 'UNKNOWN_ZONE' })
  const prev = s.users[userId]
  const warnings: string[] = []
  let created = false
  let readmitted = false
  let restored = false
  if (!prev) {
    if (!req.display?.trim()) throw new ApiError('VALIDATION_ERROR', 422, 'cloud: display is required to add a new user', null, { reason: 'DISPLAY_REQUIRED' })
    if (req.consent !== true) throw new ApiError('VALIDATION_ERROR', 422, 'cloud: consent: true is required to add a new user', null, { reason: 'CONSENT_REQUIRED' })
    created = true
  } else if (prev.status === 'ERASED') {
    if (req.consent !== true) throw new ApiError('INVALID_STATE', 409, `cloud: user ${userId} was erased (DPDP): re-admit with consent: true`, null, { reason: 'ERASED_IN_BUNDLE' })
    readmitted = true
  } else if (prev.status === 'REVOKED') {
    if (req.consent === true && req.restore === true) restored = true
    else if (req.consent === true) throw new ApiError('INVALID_STATE', 409, `cloud: user ${userId} is revoked: use Restore (restore: true) first`, null, { reason: 'USER_REVOKED' })
    else warnings.push('user is revoked: access changes do not lift a revocation (use Restore)')
  }
  const lifted = readmitted || restored
  const next: MockUser = {
    display: req.display?.trim() || prev?.display || userId,
    role: req.role,
    zones_add: req.zones_add ?? prev?.zones_add ?? [],
    zones_remove: prev?.zones_remove ?? [],
    extra_windows: req.extra_windows ?? prev?.extra_windows ?? {},
    valid_from: req.valid_from !== undefined ? toUtc(req.valid_from) : (prev?.valid_from ?? null),
    valid_until: req.valid_until !== undefined ? toUtc(req.valid_until) : (prev?.valid_until ?? null),
    status: lifted ? 'ACTIVE' : (prev?.status ?? 'ACTIVE'),
    revoked_at: lifted ? null : (prev?.revoked_at ?? null),
    revoked_reason: lifted ? null : (prev?.revoked_reason ?? null),
    totp_enrolled: prev?.totp_enrolled ?? false,
    card: prev?.card ?? false,
  }
  const unchanged = !!prev && JSON.stringify(prev) === JSON.stringify(next)
  s.users[userId] = next
  if (!unchanged) publish(s)
  const bundle: BundleRefresh = pullAfterWrite(s)
  save(s)
  const user = row(s, userId, false, Date.now())
  if (!user.in_bundle) warnings.push(`role ${next.role} has no access to ${KIOSK_ZONE}: the user is not in this kiosk's bundle and cannot be enrolled or admitted here`)
  return {
    user_id: userId,
    created,
    unchanged,
    readmitted,
    restored,
    previous_role: prev?.role ?? null,
    role: next.role,
    cloud_bundle_version: PULL_FAILS ? null : s.version,
    bundle,
    user: bundle.applied ? { ...user, cloud_faces: null } : null,
    warnings: bundle.applied ? warnings : [...warnings, `the cloud saved the change (a new version) but this edge still runs v${s.installed}: POST /v1/admin/bundle/refresh before enrolling`],
  }
}

export function mockRevoke(offline: boolean, userId: string, req: RevokeRequest): RevokeResult {
  const errs = revokeErrors(userId, req)
  if (errs.length) throw validation(errs)
  if (offline) throw offlineError()
  const s = load()
  const u = s.users[userId]
  if (!u) throw new ApiError('NOT_FOUND', 404, `cloud: unknown user_id ${userId} (not in the schedule or the enrolment store)`, null, { reason: 'UNKNOWN_USER' })
  if (u.status === 'REVOKED') throw new ApiError('INVALID_STATE', 409, `cloud: user ${userId} is already revoked`, null, { reason: 'ALREADY_REVOKED' })
  const reason = req.reason ?? 'ADMIN'
  const at = isoNow()
  u.status = 'REVOKED'
  u.revoked_at = at
  u.revoked_reason = reason
  s.seq += 1
  publish(s)
  const bundle: BundleRefresh = pullAfterWrite(s)
  save(s)
  const pulled = bundle.applied === true
  return {
    user_id: userId,
    type: 'USER',
    reason,
    revoked_at: pulled ? at : null,
    seq: pulled ? s.seq : null,
    cloud_bundle_version: pulled ? s.version : null,
    bundle,
    user: { ...row(s, userId, false, Date.now()), cloud_faces: null },
    warnings: pulled ? [] : [`the cloud saved the revocation (a new version) but this edge still runs v${s.installed}: POST /v1/admin/bundle/refresh to apply it now`],
  }
}

export function mockRotateCodes(offline: boolean, req: RotateCodesRequest): RotateCodesResult {
  const errs = rotateErrors(req)
  if (errs.length) throw validation(errs)
  if (offline) throw offlineError()
  const n = req.count ?? 4
  const stamp = istParts(Date.now())
  const tag = `OVR-R${stamp.date.slice(5).replace('-', '')}${stamp.hhmm.replace(':', '')}00`
  const codes = Array.from({ length: n }, (_, i) => {
    const b = new Uint32Array(1)
    crypto.getRandomValues(b)
    return { code_id: `${tag}-${String(i + 1).padStart(2, '0')}`, code: String(b[0] % 100_000_000).padStart(8, '0') }
  })
  const s = load()
  if (!s.staffIds.includes(req.staff_id)) s.staffIds = [...s.staffIds, req.staff_id].sort()
  publish(s)
  const bundle: BundleRefresh = pullAfterWrite(s)
  save(s)
  return {
    staff_id: req.staff_id,
    codes,
    code_length: 8,
    valid_until: isoAt(Date.parse(s.issuedAt) + 36 * 3600_000),
    one_time: true,
    dropped_code_ids: req.replace_existing === false ? [] : [`OVR-PREV-${req.staff_id}`],
    warning: 'Shown once: store these codes safely (each works once, for this staff_id only). The cloud keeps only PBKDF2 hashes; kiosks get them with the next bundle refresh.',
    cloud_bundle_version: PULL_FAILS ? null : s.version,
    bundle,
    warnings: PULL_FAILS ? ['codes work on this kiosk only after it installs the new bundle (POST /v1/admin/bundle/refresh)'] : [],
  }
}

export function mockRefreshBundle(offline: boolean): BundleRefresh {
  const s = load()
  if (offline) throw new ApiError('CLOUD_UNAVAILABLE', 503, 'bundle refresh failed: forced OFFLINE', null, { reason: 'OFFLINE', installed_version: s.installed })
  const r = install(s)
  save(s)
  return r
}

/** POST /v1/enroll state rules + bookkeeping (frames / liveness are simulated by mock.ts). */
export function mockEnroll(offline: boolean, meta: EnrollMeta, frames: number): EnrollResponse {
  const errs = enrollMetaErrors(meta)
  if (errs.length) throw validation(errs)
  const s = load()
  const b = s.bundleUsers[meta.user_id]
  if (!b || !inKioskBundle(b)) {
    throw new ApiError(
      'INVALID_STATE',
      409,
      `user ${meta.user_id} is not in the campus schedule (bundle v${s.installed}): add the user in the control panel (Users & Access -> Add user), then enrol`,
      null,
      { reason: 'NOT_IN_SCHEDULE', bundle_version: s.installed },
    )
  }
  if (b.status === 'REVOKED') throw new ApiError('FORBIDDEN', 403, `user ${meta.user_id} is revoked; enrolment refused`, null, { reason: 'USER_REVOKED' })
  if (b.status === 'ERASED') {
    throw new ApiError(
      'INVALID_STATE',
      409,
      `user ${meta.user_id} was erased (DPDP) and the installed schedule bundle still carries that erasure: re-admit the user in the control panel (Users & Access), then enrol`,
      null,
      { reason: 'ERASED_IN_BUNDLE' },
    )
  }
  if (frames < 3) throw new ApiError('VALIDATION_ERROR', 422, `only ${frames} enrolment frames passed quality+liveness (need 3)`, null, { reason: 'FRAMES_REJECTED' })
  const prev = s.enrolled[meta.user_id]
  const newSecret = meta.provision_totp
  s.enrolled[meta.user_id] = {
    display_name: meta.display_name.trim(),
    role: b.role,
    templates: Math.min(24, (prev?.templates ?? 0) + frames),
    template_version: (prev?.template_version ?? 0) + 1,
    totp: newSecret || (prev?.totp ?? false),
    card: !!meta.card_id || (prev?.card ?? false),
    updated_at: isoNow(),
  }
  const warnings: string[] = []
  if (!offline) {
    const m = s.users[meta.user_id]
    if (m && newSecret) m.totp_enrolled = true
    if (m && meta.card_id) m.card = true
    publish(s)
    install(s)
  } else {
    warnings.push('kiosk is OFFLINE: enrolled on this edge only. Once ONLINE, Rekognition is authoritative and this user is NOT_ENROLLED until re-enrolled while ONLINE')
    if (newSecret) warnings.push('TOTP is not active yet: the campus schedule does not mark this user TOTP-enrolled (re-enrol while ONLINE)')
  }
  if (meta.role && meta.role !== b.role) warnings.push(`requested role '${meta.role}' was NOT applied: the campus schedule says '${b.role}'`)
  save(s)
  const entry = s.enrolled[meta.user_id]
  const totpActive = offline ? b.totp_enrolled && !newSecret && entry.totp : (s.users[meta.user_id]?.totp_enrolled ?? false) && entry.totp
  return {
    user_id: meta.user_id,
    template_version: entry.template_version,
    local_cache_updated: true,
    cloud_indexed: !offline,
    cloud_state: offline ? 'skipped_offline' : 'indexed',
    totp_provisioning_uri: newSecret ? `otpauth://totp/HID-Kiosk:${encodeURIComponent(meta.user_id)}?secret=JBSWY3DPEHPK3PXP&issuer=HID-Kiosk&digits=6&period=30` : null,
    totp_active: totpActive,
    frames_used: frames,
    frames_rejected: [],
    min_pairwise_cosine: 0.71,
    cloud: offline ? null : { status: 201, body: { user_id: meta.user_id, faces_indexed: frames, bundle_version: s.version } },
    schedule_role: b.role,
    schedule_display: b.display,
    role_requested: meta.role ?? null,
    role_applied: false,
    bundle_version: s.installed,
    reinstated_after_erasure: false,
    warnings,
  }
}

export function mockErase(offline: boolean, userId: string): EraseResponse {
  const s = load()
  const had = !!s.enrolled[userId]
  const inMaster = !!s.users[userId]
  if (!had && (offline || !inMaster)) throw new ApiError('NOT_FOUND', 404, `user ${userId} not enrolled on this edge`, null, { reason: 'NOT_ENROLLED' })
  delete s.enrolled[userId]
  if (offline && ERASE_QUEUE_FAILS) {
    save(s)
    return {
      user_id: userId,
      local_removed: had,
      cloud: 'failed',
      cloud_status: null,
      message: `local data erased, but the CLOUD erasure did not happen (kiosk OFFLINE) and could not be queued: retry DELETE /v1/enroll/${userId} while the kiosk is ONLINE`,
      bundle: null,
    }
  }
  if (offline) {
    if (inMaster && !s.pendingErasures.includes(userId)) s.pendingErasures.push(userId)
    save(s)
    return {
      user_id: userId,
      local_removed: had,
      cloud: 'queued',
      cloud_status: null,
      message: 'local data erased; the cloud erasure (Rekognition faces + cloud record) is queued and retried at the next sync',
      bundle: null,
    }
  }
  eraseInMaster(s, userId)
  publish(s)
  const bundle = install(s)
  save(s)
  return { user_id: userId, local_removed: had, cloud: 'deleted', cloud_status: 200, message: null, bundle }
}

export function mockIsEnrolled(userId: string): boolean {
  return !!load().enrolled[userId]
}

export function mockListEnrolled(): EnrolledUsersResponse {
  const s = load()
  const users = Object.entries(s.enrolled)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([id, e]) => {
      const b = s.bundleUsers[id]
      const inB = !!b && inKioskBundle(b)
      return {
        user_id: id,
        display_name: inB ? b.display : e.display_name,
        role: inB ? b.role : null,
        bundle_role: inB ? b.role : null,
        bundle_display: inB ? b.display : null,
        in_schedule: inB,
        template_role: e.role,
        template_display_name: e.display_name,
        template_version: e.template_version,
        templates: e.templates,
        totp_local: e.totp,
        card: e.card,
        updated_at: e.updated_at,
      }
    })
  return { users, bundle_version: s.installed, count: users.length, model: 'arcface_r50 (mock)', age_h: 0.1, skipped_model_mismatch: 0 }
}

/** Demo-clock rollback limit of the installed mock bundle: issued_at - 300 s, rounded up to the minute. */
export function mockEarliestUtcMs(): number {
  return Math.ceil((Date.parse(load().issuedAt) - 300_000) / 60_000) * 60_000
}

export function resetMockAccess(): void {
  save(fresh())
}
