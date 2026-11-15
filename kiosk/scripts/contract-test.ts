/**
 * Kiosk contract test (docs/API.md v1.4; docs/contracts/admin_access.examples.json). Run with plain Node
 * (native type stripping): `node scripts/contract-test.ts` (also part of `npm run build` / `npm test`).
 *
 * For every EDGE route the kiosk calls:
 *  - valid examples: the kiosk request validator accepts request.body / path / meta, and the strict parser
 *    turns response.body into exactly the same object (no field lost, none invented);
 *  - error examples: the kiosk's error mapping yields the same status, error.code and error.reason; and the
 *    request validator rejects the request iff request_invalid is true.
 * Plus: field limits / enums identical to the contract, R-I hours vs the edge's `today`, R-E demo-clock
 * default, and the R-A / R-B registration plan.
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { isDeepStrictEqual } from 'node:util'
import {
  apiErrorFromBody,
  parseAccessUpdate,
  parseAccessUsers,
  parseDemoClock,
  parseEnroll,
  parseEnrolledUsers,
  parseErase,
  parseRefresh,
  parseRevoke,
  parseRotate,
} from '../src/api/access.ts'
import {
  ACCESS_STATUSES,
  BUNDLE_RESULTS,
  CLOUD_STATES,
  ERASE_CLOUD,
  READ_ONLY_CODES,
  SCHEDULE_STATUSES_NOW,
  type AccessUser,
  type AccessUsersResponse,
} from '../src/api/types.ts'
import {
  ACTOR_RE,
  HHMM_WRITE,
  LIMITS,
  REVOKE_REASON_RE,
  ROLE_RE,
  STAFF_ID_RE,
  USER_ID_RE,
  ZONE_RE,
  accessUpdateErrors,
  bundleApplied,
  clockErrors,
  codeLengthText,
  defaultDemoTime,
  enrollMetaErrors,
  hoursFor,
  isRollbackTime,
  registerPlan,
  revokeErrors,
  rotateErrors,
  userIdError,
  validUntilText,
  versionText,
} from '../src/shared/accessRules.ts'

type Obj = Record<string, unknown>
interface Example {
  name: string
  state?: string
  request_invalid?: boolean
  request: { path_params?: Obj; query?: Obj; body?: unknown; meta?: unknown; frames?: number }
  response: { status: number; body: unknown; fragment?: boolean }
}
interface Route {
  id: string
  side: string
  examples: Example[]
  errors: Example[]
}

const here = path.dirname(fileURLToPath(import.meta.url))
const file = path.resolve(here, process.env.HID_CONTRACT_JSON ?? '../../docs/contracts/admin_access.examples.json')
const doc = JSON.parse(readFileSync(file, 'utf8')) as { api_version: string; field_limits: Obj; enums: Record<string, string[]>; routes: Route[] }

let passed = 0
const failures: string[] = []
function check(name: string, ok: boolean, detail = ''): void {
  if (ok) passed++
  else failures.push(`${name}${detail ? `: ${detail}` : ''}`)
}
function attempt<T>(name: string, fn: () => T): T | undefined {
  try {
    return fn()
  } catch (e) {
    failures.push(`${name}: threw ${e instanceof Error ? e.message : String(e)}`)
    return undefined
  }
}

type Validator = (ex: Example) => string[]
const pathId = (ex: Example) => ex.request.path_params?.user_id

const ROUTES: Record<string, { parse: (b: unknown) => unknown; validate?: Validator; fragmentKey?: string }> = {
  'edge.access.users.list': { parse: parseAccessUsers },
  'edge.access.users.put': { parse: parseAccessUpdate, validate: (ex) => accessUpdateErrors(pathId(ex), ex.request.body) },
  'edge.access.users.revoke': { parse: parseRevoke, validate: (ex) => revokeErrors(pathId(ex), ex.request.body) },
  'edge.access.codes.rotate': { parse: parseRotate, validate: (ex) => rotateErrors(ex.request.body) },
  'edge.bundle.refresh': { parse: parseRefresh },
  'edge.enroll.post': { parse: parseEnroll, validate: (ex) => enrollMetaErrors(ex.request.meta) },
  'edge.enroll.delete': { parse: parseErase, validate: (ex) => [userIdError(pathId(ex))].filter((x): x is string => x !== null) },
  'edge.admin.users.list': { parse: parseEnrolledUsers },
  'edge.mode.get': { parse: (b) => (b === null ? null : parseDemoClock(b)), fragmentKey: 'demo_clock' },
  'edge.admin.clock.post': { parse: (b) => parseDemoClock(b), validate: (ex) => clockErrors(ex.request.body) },
}

check('api_version is v1.4', doc.api_version === 'v1.4', doc.api_version)

// ---------------------------------------------------------------- per-route examples
const seen = new Set<string>()
for (const route of doc.routes) {
  if (route.side !== 'edge') continue // the kiosk talks to the edge only
  const spec = ROUTES[route.id]
  check(`route ${route.id} has a kiosk parser`, !!spec)
  if (!spec) continue
  seen.add(route.id)
  for (const ex of route.examples) {
    const tag = `${route.id} / ${ex.name}`
    if (spec.validate) {
      const errs = spec.validate(ex)
      check(`${tag}: request accepted by the kiosk validator`, errs.length === 0, errs.join('; '))
    }
    const body = spec.fragmentKey ? (ex.response.body as Obj)[spec.fragmentKey] : ex.response.body
    const parsed = attempt(`${tag}: parse`, () => spec.parse(body))
    if (parsed !== undefined) check(`${tag}: parse(body) deep-equals body`, isDeepStrictEqual(parsed, body), diff(parsed, body))
  }
  for (const ex of route.errors) {
    const tag = `${route.id} / error ${ex.name}`
    const b = ex.response.body as { error?: { code?: string; reason?: string } }
    const err = apiErrorFromBody(ex.response.status, ex.response.body)
    check(`${tag}: status`, err.status === ex.response.status)
    check(`${tag}: error.code`, err.code === b.error?.code, `${err.code} vs ${String(b.error?.code)}`)
    check(`${tag}: error.reason`, err.reason === (b.error?.reason ?? null), `${String(err.reason)} vs ${String(b.error?.reason)}`)
    if (spec.validate) {
      const errs = spec.validate(ex)
      if (ex.request_invalid) check(`${tag}: kiosk validator rejects the request (request_invalid)`, errs.length > 0)
      else check(`${tag}: kiosk validator accepts the model-valid request`, errs.length === 0, errs.join('; '))
    }
  }
}
for (const id of Object.keys(ROUTES)) check(`contract has route ${id}`, seen.has(id))

// ---------------------------------------------------------------- field limits + enums identical to the contract
const fl = doc.field_limits as Record<string, unknown>
const pat = (k: string) => {
  const v = fl[k]
  return typeof v === 'string' ? v : (v as { pattern?: string } | undefined)?.pattern
}
check('user_id pattern', USER_ID_RE.source === pat('user_id'), `${USER_ID_RE.source} vs ${String(pat('user_id'))}`)
check('staff_id pattern', STAFF_ID_RE.source === pat('staff_id'))
check('role pattern', ROLE_RE.source === pat('role'))
check('zone pattern', ZONE_RE.source === pat('zone'))
check('time_write pattern', HHMM_WRITE.source === pat('time_write'))
check('set_local pattern', HHMM_WRITE.source === pat('set_local'))
check('revoke reason pattern', REVOKE_REASON_RE.source === pat('revoke_reason'))
check('actor pattern', ACTOR_RE.source === pat('actor'))
check('display max', (fl.display as { max_length: number }).max_length === LIMITS.displayMax)
check('display_name max', (fl.display_name as { max_length: number }).max_length === LIMITS.displayMax)
check('zones_add max', fl.zones_add_max === LIMITS.zonesAddMax)
check('extra_windows zones max', fl.extra_windows_zones_max === LIMITS.extraZonesMax)
check('windows per zone max', fl.windows_per_zone_max === LIMITS.windowsPerZoneMax)
const rc = fl.rotate_count as { min: number; max: number; default: number }
check('rotate count limits', rc.min === LIMITS.rotateCountMin && rc.max === LIMITS.rotateCountMax && rc.default === LIMITS.rotateCountDefault)
const sameSet = (a: readonly string[], b: readonly string[] | undefined) => !!b && a.length === b.length && a.every((x) => b.includes(x))
check('enum user_status', sameSet(ACCESS_STATUSES, doc.enums.user_status))
check('enum read_only_code', sameSet(READ_ONLY_CODES, doc.enums.read_only_code))
check('enum bundle_result', sameSet(BUNDLE_RESULTS, doc.enums.bundle_result))
check('enum cloud_state', sameSet(CLOUD_STATES, doc.enums.cloud_state))
check('enum erase_cloud', sameSet(ERASE_CLOUD, doc.enums.erase_cloud))
check('enum schedule_result', sameSet(SCHEDULE_STATUSES_NOW, doc.enums.schedule_result))

// ---------------------------------------------------------------- R-I hours vs the edge's `today`
const listRoute = doc.routes.find((r) => r.id === 'edge.access.users.list')
for (const ex of listRoute?.examples ?? []) {
  const access = attempt(`R-I ${ex.name}: parse`, () => parseAccessUsers(ex.response.body)) as AccessUsersResponse | undefined
  if (!access || !access.zone) continue
  for (const u of access.users) {
    if (!u.today || u.today.zone !== access.zone || u.status !== 'ACTIVE') continue
    const h = hoursFor(u, access.zone, u.today.day, access)
    const got = h.kind === 'windows' ? h.windows : []
    const want = [...u.today.windows].sort((a, b) => a.start.localeCompare(b.start))
    check(`R-I ${ex.name} ${u.user_id}: role_defaults + extra_windows match the edge's today`, isDeepStrictEqual(got, want), `${JSON.stringify(got)} vs ${JSON.stringify(want)}`)
  }
}
const permitted: Pick<AccessUsersResponse, 'role_defaults' | 'zones'> = {
  role_defaults: { staff: { zones: ['MAIN_GATE'], windows: { MAIN_GATE: [{ days: ['MON'], start: '09:00', end: '18:00' }], SERVER_ROOM: [{ days: ['MON'], start: '09:00', end: '18:00' }] } } },
  zones: { MAIN_GATE: { risk: 'low', requires_explicit_grant: false }, SERVER_ROOM: { risk: 'high', requires_explicit_grant: true } },
}
const base = { role: 'staff', status: 'ACTIVE' as const, zones_add: [] as string[], zones_remove: [] as string[], extra_windows: {} }
check('R-I explicit-grant zone needs zones_add', hoursFor(base, 'SERVER_ROOM', 'MON', permitted).kind === 'none')
check('R-I zones_add grants the role window', hoursFor({ ...base, zones_add: ['SERVER_ROOM'] }, 'SERVER_ROOM', 'MON', permitted).kind === 'windows')
check('R-I zones_remove removes the role window', hoursFor({ ...base, zones_remove: ['MAIN_GATE'] }, 'MAIN_GATE', 'MON', permitted).kind === 'none')
const withExtra = hoursFor({ ...base, extra_windows: { MAIN_GATE: [{ days: ['MON', 'SUN'], start: '18:00', end: '21:00' }] } }, 'MAIN_GATE', 'MON', permitted)
check(
  'R-I extra windows are added, filtered by day',
  isDeepStrictEqual(withExtra, { kind: 'windows', windows: [{ start: '09:00', end: '18:00', source: 'role' }, { start: '18:00', end: '21:00', source: 'extra' }] }),
  JSON.stringify(withExtra),
)
check('R-I revoked shows no hours', hoursFor({ ...base, status: 'REVOKED' }, 'MAIN_GATE', 'MON', permitted).kind === 'none')

// ---------------------------------------------------------------- R-E demo clock default + rollback warning
const modeRoute = doc.routes.find((r) => r.id === 'edge.mode.get')
for (const ex of modeRoute?.examples ?? []) {
  const c = (ex.response.body as { demo_clock: unknown }).demo_clock
  if (c === null) continue
  const dc = parseDemoClock(c)
  const def = defaultDemoTime(dc)
  check(`R-E ${ex.name}: default time is not a rollback`, def !== null && !isRollbackTime(def, dc), String(def))
  check(`R-E ${ex.name}: current time rollback flag matches the edge`, isRollbackTime(dc.now_local, dc) === dc.bundle_rollback)
}
const clk = { now_local: '09:00', date_local: '2026-11-14', earliest_local: '18:05', earliest_date_local: '2026-11-14' }
check('R-E default = max(now, earliest)', defaultDemoTime(clk) === '18:05')
check('R-E default = now when later', defaultDemoTime({ ...clk, now_local: '21:30' }) === '21:30')
check('R-E earliest on an earlier day: any time is safe', !isRollbackTime('00:10', { ...clk, earliest_date_local: '2026-11-13' }))
check('R-E earliest on a later day: every time rolls back', isRollbackTime('23:00', { ...clk, earliest_date_local: '2026-11-15' }))

// ---------------------------------------------------------------- R-A / R-B registration plan
const row = (status: AccessUser['status'], extra: Partial<AccessUser> = {}) => ({ status, role: 'student', bundle_role: 'student', display: 'Priya N.', in_bundle: true, ...extra })
check('R-A new person online: PUT then enrol', isDeepStrictEqual(registerPlan(null, true, 'faculty', 'Prof. X'), { kind: 'put-then-enrol', readmit: false, create: true }))
check('R-A new person offline: blocked OFFLINE', isDeepStrictEqual(registerPlan(null, false, 'faculty', 'Prof. X'), { kind: 'blocked', why: 'OFFLINE' }))
check('R-A not-in-schedule row online: PUT then enrol', registerPlan(row('NOT_IN_SCHEDULE', { role: null, bundle_role: null, in_bundle: false }), true, 'staff', 'N').kind === 'put-then-enrol')
check('R-A bundle user offline: enrol directly', isDeepStrictEqual(registerPlan(row('ACTIVE'), false, 'student', 'Priya N.'), { kind: 'enrol', role: 'student' }))
check('R-A bundle user, role change offline: blocked', isDeepStrictEqual(registerPlan(row('ACTIVE'), false, 'faculty', 'Priya N.'), { kind: 'blocked', why: 'OFFLINE' }))
check('R-A role change online: PUT then enrol', registerPlan(row('ACTIVE'), true, 'faculty', 'Priya N.').kind === 'put-then-enrol')
check('R-B erased online: re-admit then enrol', isDeepStrictEqual(registerPlan(row('ERASED'), true, 'student', 'Priya N.'), { kind: 'put-then-enrol', readmit: true, create: false }))
check('R-B erased offline: blocked', registerPlan(row('ERASED'), false, 'student', 'Priya N.').kind === 'blocked')
check('R-C revoked: blocked (Restore first)', isDeepStrictEqual(registerPlan(row('REVOKED'), true, 'student', 'Priya N.'), { kind: 'blocked', why: 'REVOKED' }))
check('R-A in master but not at this kiosk, offline: blocked', isDeepStrictEqual(registerPlan(row('ACTIVE', { in_bundle: false, bundle_role: null }), false, 'student', 'Priya N.'), { kind: 'blocked', why: 'NOT_AT_THIS_KIOSK' }))

// ---------------------------------------------------------------- strictness: drift is an error, not a guess
const nested = { staff_id: 's_guard01', cloud: { codes: [{ code_id: 'x', code: '1' }] }, bundle: {} }
check('rotate: nested cloud.codes (old edge shape) is rejected', attempt('strict rotate', () => { try { parseRotate(nested); return false } catch { return true } }) === true)
check('refresh: missing result is rejected', attempt('strict refresh', () => { try { parseRefresh({ previous_version: 1, installed_version: 2, changed: true }); return false } catch { return true } }) === true)

// ---------------------------------------------------------------- M1 / M2 (lead rulings): failed erasure + null versions
const exBody = (id: string, name: string) => doc.routes.find((r) => r.id === id)?.examples.find((e) => e.name === name)?.response.body as Obj | undefined
const failedErase = exBody('edge.enroll.delete', 'cloud_erasure_failed')
check('M1 contract has cloud_erasure_failed', failedErase?.cloud === 'failed', JSON.stringify(failedErase?.cloud))
for (const [id, name, keys] of [
  ['edge.access.users.put', 'saved_version_unknown', ['cloud_bundle_version']],
  ['edge.access.users.revoke', 'revoked_but_not_installed', ['revoked_at', 'seq', 'cloud_bundle_version']],
  ['edge.access.codes.rotate', 'minted_version_unknown', ['cloud_bundle_version']],
] as const) {
  const b = exBody(id, name)
  check(`M2 contract has ${id} / ${name} with null ${keys.join(', ')}`, !!b && keys.every((k) => b[k] === null) && (b.bundle as Obj).applied === false)
}
const rotNull = exBody('edge.access.codes.rotate', 'minted_version_unknown')
check('M2 rotate with null version still carries the codes (shown once)', Array.isArray(rotNull?.codes) && (rotNull.codes as unknown[]).length > 0)
// R-K: rotate codes[].code_id, code_length, valid_until are nullable; the codes are still shown once
const rotUnknown = exBody('edge.access.codes.rotate', 'minted_fields_unknown')
check(
  'R-K contract has edge.access.codes.rotate / minted_fields_unknown with null code_id, code_length, valid_until',
  !!rotUnknown &&
    rotUnknown.code_length === null &&
    rotUnknown.valid_until === null &&
    Array.isArray(rotUnknown.codes) &&
    (rotUnknown.codes as Obj[]).length > 0 &&
    (rotUnknown.codes as Obj[]).every((c) => c.code_id === null && typeof c.code === 'string'),
)
const rkParsed = attempt('R-K parse minted_fields_unknown', () => parseRotate(rotUnknown))
check(
  'R-K parseRotate keeps every plaintext code when the metadata is null',
  !!rkParsed && rkParsed.codes.length === (rotUnknown?.codes as unknown[] | undefined)?.length && rkParsed.codes.every((c) => c.code.length > 0 && c.code_id === null),
)
check('R-K parseRotate: null code_length / valid_until stay null', !!rkParsed && rkParsed.code_length === null && rkParsed.valid_until === null)
check('R-K codeLengthText(null) = length unknown', codeLengthText(null) === 'length unknown' && codeLengthText(8) === '8 digits')
check('R-K validUntilText(null) = unknown (no Invalid Date)', validUntilText(null) === 'unknown' && validUntilText('garbage').startsWith('unknown') && !validUntilText('2026-11-15T10:00:00Z').includes('Invalid'))
check(
  'R-K rotate: a non-null code_id must still be a string',
  attempt('strict rotate code_id', () => { try { parseRotate({ ...rotUnknown, codes: [{ code_id: 7, code: '1' }] }); return false } catch { return true } }) === true,
)
check('M2 versionText(null) = pending refresh', versionText(null) === 'pending refresh' && versionText(50) === 'v50')
check('M2 bundleApplied: failed pull is never applied', !bundleApplied({ result: 'failed', installed_version: 99 }, null))
check('M2 bundleApplied: unknown version + successful pull = applied (edge rule)', bundleApplied({ result: 'not_modified', installed_version: 49 }, null))
check('M2 bundleApplied: known version must be installed', !bundleApplied({ result: 'installed', installed_version: 49 }, 50) && bundleApplied({ result: 'installed', installed_version: 50 }, 50))

function diff(a: unknown, b: unknown, p = ''): string {
  if (isDeepStrictEqual(a, b)) return ''
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    for (const k of new Set([...Object.keys(a as Obj), ...Object.keys(b as Obj)])) {
      const d = diff((a as Obj)[k], (b as Obj)[k], `${p}.${k}`)
      if (d) return d
    }
  }
  return `${p || '(root)'}: parsed ${JSON.stringify(a)?.slice(0, 120)} vs contract ${JSON.stringify(b)?.slice(0, 120)}`
}

console.log(`kiosk contract test (${path.relative(process.cwd(), file)}, ${doc.api_version}): ${passed} passed, ${failures.length} failed`)
for (const f of failures) console.log(`  FAIL ${f}`)
process.exit(failures.length ? 1 : 0)
