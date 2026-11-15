/**
 * Who is who, for /register, the /admin enrol card and the Users & Access tab (docs/API.md v1.4 §3.18). The
 * SIGNED SCHEDULE is the single source of truth for a person's role (cloud master -> signed bundle -> edge):
 * the role stored with a face template is informational only. Roles / hours / revocations change only through
 * the edge's access routes (ONLINE; the edge installs the re-signed bundle in the same call).
 */
import { useEffect, useMemo } from 'react'
import { usePoll } from '../admin/usePoll'
import { getApi } from '../api'
import {
  asApiError,
  type AccessStatus,
  type AccessUpdate,
  type AccessUpdateResult,
  type AccessUser,
  type AccessUsersResponse,
  type ApiError,
  type EnrolledUser,
  type EnrolledUsersResponse,
  type EraseCloud,
  type ReadOnlyCode,
} from '../api/types'
import { bundleApplied, versionText } from './accessRules'
import { DEMO_USERS, DEMO_USERS_SOURCE } from './demoUsers'

export { bundleApplied, versionText }
import { useModeStatus } from './modeStore'

export interface Identity {
  user_id: string
  display: string
  /** authoritative schedule role (cloud master online, bundle offline); null = not in the schedule */
  role: string | null
  /** role in this kiosk's installed bundle (what decisions use now) */
  bundle_role: string | null
  status: AccessStatus
  /** in this kiosk's installed bundle (can be enrolled + admitted here) */
  in_bundle: boolean
  in_schedule: boolean
  /** role stored with the local template (informational only) */
  template_role: string | null
  enrolled: boolean
  totp: boolean
  /** the Users & Access row (null when the access list is not loaded) */
  row: AccessUser | null
  /** where `role` comes from */
  source: 'schedule' | 'enrolments' | 'demo-file'
}

export interface AccessDirectory {
  access: AccessUsersResponse | null
  accessError: string | null
  enrolled: EnrolledUsersResponse | null
  enrolledError: string | null
  identities: Identity[]
  /** roles of the schedule (master online, bundle offline); [] until the list loads */
  roles: string[]
  bundleVersion: number | string | null
  /** schedule writes are possible right now (admin token, edge reachable, ONLINE, list not read-only) */
  canEdit: boolean
  /** why not, for the UI */
  editBlockedReason: string | null
  /**
   * POST /v1/admin/bundle/refresh may be tried (admin token, edge reachable, mode not forced). Deliberately NOT
   * gated on ONLINE or read_only: the edge answers NOT_CONFIGURED / CLOUD_ERROR / OFFLINE itself, and that
   * answer is shown as-is.
   */
  canRefreshBundle: boolean
  refreshBlockedReason: string | null
  /** the kiosk is offline / read-only: only people already in the installed bundle can be enrolled */
  offline: boolean
  loading: boolean
  refresh: () => void
}

export function buildIdentities(access: AccessUsersResponse | null, enrolled: EnrolledUser[]): Identity[] {
  const map = new Map<string, Identity>()
  if (access) {
    for (const u of access.users) {
      map.set(u.user_id, {
        user_id: u.user_id,
        display: u.display,
        role: u.role,
        bundle_role: u.bundle_role,
        status: u.status,
        in_bundle: u.in_bundle,
        in_schedule: u.in_schedule,
        template_role: u.local.template_role,
        enrolled: u.local.enrolled,
        totp: u.local.totp_local,
        row: u,
        source: 'schedule',
      })
    }
  } else {
    // No schedule list (no token / edge without the access routes): the demo schedule source file, display only.
    for (const u of DEMO_USERS) {
      map.set(u.user_id, {
        user_id: u.user_id,
        display: u.display,
        role: u.role,
        bundle_role: null,
        status: 'ACTIVE',
        in_bundle: false,
        in_schedule: true,
        template_role: null,
        enrolled: false,
        totp: false,
        row: null,
        source: 'demo-file',
      })
    }
  }
  for (const e of enrolled) {
    const prev = map.get(e.user_id)
    if (prev?.row) {
      map.set(e.user_id, { ...prev, enrolled: true, totp: prev.totp || e.totp_local })
      continue
    }
    map.set(e.user_id, {
      user_id: e.user_id,
      display: e.bundle_display ?? prev?.display ?? e.display_name,
      role: e.bundle_role ?? prev?.role ?? null,
      bundle_role: e.bundle_role,
      status: e.in_schedule ? 'ACTIVE' : (prev?.status ?? 'NOT_IN_SCHEDULE'),
      in_bundle: e.in_schedule,
      in_schedule: e.in_schedule || (prev?.in_schedule ?? false),
      template_role: e.template_role,
      enrolled: true,
      totp: e.totp_local,
      row: null,
      source: prev?.source === 'demo-file' ? 'demo-file' : 'enrolments',
    })
  }
  return [...map.values()].sort((a, b) => a.user_id.localeCompare(b.user_id))
}

export const ROLE_SOURCE_TEXT = (src: Identity['source'], version: number | string | null): string =>
  src === 'schedule'
    ? `signed campus schedule${version !== null ? ` v${String(version)}` : ''}`
    : src === 'enrolments'
      ? `installed bundle${version !== null ? ` v${String(version)}` : ''} (via this edge's enrolments)`
      : `${DEMO_USERS_SOURCE} (schedule list not loaded)`

const READ_ONLY_TEXT: Record<ReadOnlyCode, string> = {
  OFFLINE:
    'The kiosk is OFFLINE. The signed schedule changes only while the cloud is reachable: new people cannot be registered and roles / hours cannot change. People already in the installed bundle can still enrol (local template only).',
  NOT_CONFIGURED: 'This edge has no cloud configured (CLOUD_API_URL / cloud admin token): the schedule is read-only here.',
  CLOUD_ERROR: 'The cloud did not answer: the schedule is read-only until it does (try Reload).',
  ENDPOINT_NOT_DEPLOYED: 'The live cloud build does not have the access routes yet (cloud redeploy pending): the schedule is read-only.',
  CLOUD_ADMIN_TOKEN: "The cloud refused this edge's admin token (CLOUD_ADMIN_TOKEN in the edge .env, not the token you typed): read-only.",
}

export function readOnlyText(access: AccessUsersResponse): string {
  const base = access.read_only_code ? READ_ONLY_TEXT[access.read_only_code] : 'The edge reports the schedule as read-only.'
  return access.read_only_reason ? `${base} (${access.read_only_reason})` : base
}

export function useAccessDirectory(token: string, key = 'dir'): AccessDirectory {
  const api = getApi()
  const { mode, reachable } = useModeStatus()
  const access = usePoll(() => api.listAccessUsers(token), 15000, Boolean(token), `${key}-access:${token}`)
  const enrolled = usePoll(() => api.listEnrolledUsers(token), 15000, Boolean(token), `${key}-enrolled:${token}`)
  const enrolledUsers = enrolled.data?.users
  const identities = useMemo(() => buildIdentities(access.data, enrolledUsers ?? []), [access.data, enrolledUsers])
  const roles = useMemo(() => access.data?.roles ?? [], [access.data])
  // ONLINE requirement of the edge (§3.18): mode ONLINE, or connectivity up with a stale bundle.
  const online = reachable && !!mode && !mode.forced && (mode.mode === 'ONLINE' || mode.reason === 'bundle_stale')
  const editBlockedReason = !token
    ? 'Enter the admin token first.'
    : !reachable
      ? 'The edge is not reachable.'
      : access.error && !access.data
        ? `The access list did not load: ${access.error}`
        : access.data?.read_only
          ? readOnlyText(access.data)
          : !online
            ? READ_ONLY_TEXT.OFFLINE
            : !access.data
              ? 'Loading the schedule…'
              : null
  const refreshBlockedReason = !token
    ? 'Enter the admin token first.'
    : !reachable
      ? 'The edge is not reachable.'
      : mode?.forced
        ? 'The kiosk is forced OFFLINE (demo toggle): set the mode back to AUTO to pull a bundle.'
        : null
  const refreshAccess = access.refresh
  const refreshEnrolled = enrolled.refresh
  // Any access change / enrolment anywhere on the page refreshes every directory instance.
  useEffect(() => {
    const on = () => {
      refreshAccess()
      refreshEnrolled()
    }
    window.addEventListener(ACCESS_CHANGED, on)
    return () => window.removeEventListener(ACCESS_CHANGED, on)
  }, [refreshAccess, refreshEnrolled])
  return {
    access: access.data,
    accessError: access.error,
    enrolled: enrolled.data,
    enrolledError: enrolled.error,
    identities,
    roles,
    bundleVersion: access.data?.bundle.version ?? mode?.schedule_bundle?.version ?? null,
    canEdit: editBlockedReason === null,
    editBlockedReason,
    canRefreshBundle: refreshBlockedReason === null,
    refreshBlockedReason,
    offline: !online || access.data?.read_only === true,
    loading: access.loading || enrolled.loading,
    refresh: notifyAccessChanged,
  }
}

/** DELETE /v1/enroll `cloud` (M1) in plain words. `failed` = local erase done, cloud erasure could NOT be queued. */
export const ERASE_CLOUD_TEXT: Record<EraseCloud, string> = {
  deleted: 'cloud data deleted',
  queued: 'cloud erasure QUEUED: retried automatically at the next sync',
  not_configured: 'no cloud configured on this edge',
  failed:
    'local erase done, but the cloud erasure could NOT be queued (the edge could not write its erasure queue): nothing will retry it, so run Erase again while the kiosk is ONLINE',
}

/** Window event fired after a successful access change or enrolment (all directories reload). */
export const ACCESS_CHANGED = 'hid-access-changed'

export function notifyAccessChanged(): void {
  window.dispatchEvent(new Event(ACCESS_CHANGED))
}

export interface ApplyOutcome {
  ok: boolean
  result: AccessUpdateResult | null
  /** this edge installed the re-signed bundle (installed_version >= cloud_bundle_version) */
  applied: boolean
  /** the person's row after the change (null if it could not be read back) */
  user: AccessUser | null
  installedVersion: number | null
  /** cloud + edge warnings, plus our own notes */
  warnings: string[]
  message: string
  error: ApiError | null
}

/** Pull attempts after a write that reported applied:false (API.md §3.15 / R-A: "up to 3 tries, 1 s apart"). */
export const REFRESH_TRIES = 3
export const REFRESH_GAP_MS = 1000

const sleep = (ms: number) => new Promise<void>((res) => setTimeout(res, ms))

/**
 * PUT the user's access through the edge (cloud master -> re-signed bundle), then make sure THIS edge runs
 * it: when the write reports `bundle.applied: false`, POST /v1/admin/bundle/refresh up to 3 times, 1 s apart.
 * The row is read back (GET /v1/admin/access/users) when the write did not include it, so `user.in_bundle` is
 * known. `cloud_bundle_version` may be null (M2): shown as "pending refresh", never treated as an error.
 */
export async function applyAccess(token: string, userId: string, req: AccessUpdate): Promise<ApplyOutcome> {
  const api = getApi()
  let r: AccessUpdateResult
  try {
    r = await api.putAccessUser(token, userId, req)
  } catch (e) {
    const err = asApiError(e)
    return { ok: false, result: null, applied: false, user: null, installedVersion: null, warnings: [], message: errorText(e), error: err }
  }
  const warnings = [...r.warnings]
  let applied = r.bundle.applied === true
  let installed = r.bundle.installed_version
  for (let i = 0; !applied && i < REFRESH_TRIES; i++) {
    if (i > 0) await sleep(REFRESH_GAP_MS)
    try {
      const b = await api.refreshBundle(token)
      installed = b.installed_version
      applied = bundleApplied(b, r.cloud_bundle_version)
    } catch (e) {
      if (i === REFRESH_TRIES - 1) warnings.push(`the edge could not install the new bundle (${versionText(r.cloud_bundle_version)}) yet: ${errorText(e)}`)
    }
  }
  let user = applied ? r.user : null
  if (applied && !user) {
    try {
      user = (await api.listAccessUsers(token)).users.find((u) => u.user_id === userId) ?? null
    } catch {
      user = null
    }
  }
  notifyAccessChanged()
  const what = r.created ? 'added' : r.readmitted ? 're-admitted' : r.restored ? 'restored' : r.unchanged ? 'unchanged' : 'updated'
  const roleText = r.previous_role && r.previous_role !== r.role ? `${r.previous_role} → ${r.role}` : r.role
  return {
    ok: true,
    result: r,
    applied,
    user,
    installedVersion: installed,
    warnings,
    message: `${userId} ${what} · ${roleText} · signed schedule ${versionText(r.cloud_bundle_version)}${applied ? ' installed on this kiosk' : ' NOT yet installed on this kiosk'}.`,
    error: null,
  }
}

/** Human hint per machine-readable error.reason (§3.18.6): the kiosk maps the reason, never the message. */
export const REASON_HINT: Record<string, string> = {
  OFFLINE: 'The kiosk is OFFLINE: new people can only be registered, and access changed, while ONLINE.',
  NOT_CONFIGURED: 'This edge has no cloud configured (CLOUD_API_URL / cloud admin token).',
  CLOUD_ERROR: 'The cloud did not answer. Try again in a moment.',
  ENDPOINT_NOT_DEPLOYED: 'The live cloud does not have this route yet: cloud redeploy pending.',
  CLOUD_ADMIN_TOKEN: "The cloud refused this edge's admin token (CLOUD_ADMIN_TOKEN in the edge .env), not the token you typed.",
  UNKNOWN_ROLE: 'That role is not in the campus schedule.',
  UNKNOWN_ZONE: 'A zone is not in the campus schedule.',
  DISPLAY_REQUIRED: 'A display name is needed to add a new person.',
  CONSENT_REQUIRED: "The person's consent is needed to add them to the schedule.",
  ERASED_IN_BUNDLE: 'This person was erased (DPDP). Use “Re-admit and enrol” (with fresh consent).',
  USER_REVOKED: 'This person is revoked. Restore them first (Control panel → Users & access).',
  SCHEDULE_CONFLICT: 'The schedule changed at the same moment. Try again.',
  ALREADY_REVOKED: 'This person is already revoked.',
  UNKNOWN_USER: 'This id is neither in the schedule nor in the cloud enrolment store.',
  BUNDLE_REJECTED: 'The cloud bundle was rejected (signature, version or expiry); the last valid bundle stays installed.',
  NOT_IN_SCHEDULE: "This id is not in this kiosk's campus schedule. Add the person first (Register does this automatically while ONLINE).",
  NO_BUNDLE: 'No verified schedule bundle is installed on this edge: refresh the bundle first.',
  FACE_ENROLLED_OTHER: 'This face is already enrolled as someone else.',
  LOOK_MISMATCH: "The new photos do not resemble this person's enrolment. To replace it, erase the person first (fresh consent).",
  FRAMES_REJECTED: 'Too few photos passed quality + liveness: retake in good front light with no phone or screen in view.',
  NOT_ENROLLED: 'This person is not enrolled on this edge.',
  NOT_DEMO_MODE: 'The demo clock needs DEMO_MODE=1 on the edge.',
  CODES_UNAVAILABLE: 'The cloud cannot mint codes right now.',
}

const CODE_HINT: Record<string, string> = {
  CLOUD_UNAVAILABLE: 'The cloud is not reachable; this needs ONLINE.',
  UNAUTHORIZED: 'Admin token missing or wrong (ADMIN_TOKEN in the project .env).',
  FORBIDDEN: 'Not allowed with this admin token.',
  NOT_FOUND: 'This edge does not have that route (edge restart pending?).',
  VALIDATION_ERROR: 'The edge rejected the values.',
  MODELS_UNAVAILABLE: 'The edge models / PAD self-test are not ready, so enrolment is refused.',
  BAD_RESPONSE: 'The edge answered in a shape that does not match the API contract (edge restart pending?).',
}

/** Human-readable admin error: hint first (by reason, else by code), then code / reason / edge message. */
export function errorText(e: unknown): string {
  const err = asApiError(e)
  if (!err) return e instanceof Error ? e.message : String(e)
  if (err.isUnreachable) return `The edge is not reachable (${err.code}).`
  const hint = (err.reason && REASON_HINT[err.reason]) || CODE_HINT[err.code] || ''
  return `${hint ? `${hint} ` : ''}[${err.code}${err.reason ? ` ${err.reason}` : ''}] ${err.message}`
}
