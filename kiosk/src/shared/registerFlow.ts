/**
 * The registration flow shared by /register and the admin enrol card (R-A / R-B / R-F, docs/API.md v1.4):
 *  1. new person, role / name change, or an ERASED person (re-admission): PUT /v1/admin/access/users/{id}
 *     {display, role, consent: true, actor} FIRST (ONLINE only); the edge installs the re-signed bundle
 *     (POST /v1/admin/bundle/refresh up to 3x when it reports applied:false); the person must then be in this
 *     kiosk's bundle (user.in_bundle), else enrolment here is pointless and is not attempted;
 *  2. POST /v1/enroll (meta without a role: the role always comes from the signed schedule);
 *  3. cloud_state / warnings[] are turned into notes (failed = blocking-style, skipped_offline = offline note).
 * Offline, people already in the installed bundle can still enrol; new people cannot be registered.
 */
import { getApi } from '../api'
import { asApiError, type EnrollMeta, type EnrollResponse } from '../api/types'
import { applyAccess, errorText, versionText, notifyAccessChanged, type ApplyOutcome, type Identity } from './accessDirectory'
import { registerPlan, type RegisterPlan } from './accessRules'

export const CONSENT_VERSION = '2026-11-14.v1'

export interface RegisterInput {
  userId: string
  display: string
  /** role wanted in the schedule; null = keep the schedule role */
  role: string | null
  email: string
  cardId: string
  provisionTotp: boolean
  frames: Blob[]
  actor: 'register' | 'control-panel'
  /** re-admit (consent:true PUT) even if the list did not show ERASED yet (after a 409 ERASED_IN_BUNDLE) */
  forceReadmit?: boolean
}

export interface Note {
  tone: 'ok' | 'warn' | 'block'
  text: string
}

export interface RegisterOutcome {
  ok: boolean
  /** the step that failed (or 'done') */
  stage: 'plan' | 'schedule' | 'enrol' | 'done'
  plan: RegisterPlan
  apply: ApplyOutcome | null
  enrol: EnrollResponse | null
  error: string | null
  /** machine-readable error.reason of the failure (drives "Re-admit and enrol" / "Restore first") */
  reason: string | null
  /** role the signed schedule gives the person after this registration (from the edge, never the form) */
  scheduleRole: string | null
  notes: Note[]
}

const BLOCKED_TEXT: Record<'OFFLINE' | 'REVOKED' | 'NOT_AT_THIS_KIOSK' | 'NO_ROLE', string> = {
  OFFLINE:
    'The kiosk is OFFLINE: new people can only be registered (and roles changed) while ONLINE, because the cloud-signed schedule is the source of truth. People already in the installed bundle can still enrol offline.',
  REVOKED: 'This person is revoked: restore them first (Control panel → Users & access → Restore), then register.',
  NOT_AT_THIS_KIOSK: "This person is in the campus schedule but has no access at this kiosk's zone, so they cannot be enrolled here.",
  NO_ROLE: 'Pick a role from the campus schedule first.',
}

/** cloud_state + warnings[] -> notes (R-F). */
export function enrolNotes(r: EnrollResponse): Note[] {
  const notes: Note[] = []
  if (r.cloud_state === 'failed') {
    notes.push({
      tone: 'block',
      text: 'NOT indexed in the cloud. While ONLINE the cloud (Rekognition) is authoritative, so this person is NOT recognised online until they are registered again with the cloud reachable.',
    })
  } else if (r.cloud_state === 'skipped_offline') {
    notes.push({ tone: 'warn', text: 'Registered OFFLINE: face template on this kiosk only. Register again once ONLINE so the cloud recognises this person too.' })
  } else if (r.cloud_state === 'not_configured') {
    notes.push({ tone: 'warn', text: 'This edge has no cloud configured: face template on this kiosk only.' })
  }
  if (r.totp_provisioning_uri && !r.totp_active && !r.warnings.some((w) => /TOTP/i.test(w))) {
    notes.push({ tone: 'warn', text: 'The authenticator (TOTP) secret is not active yet: the campus schedule does not mark this person TOTP-enrolled. Do not hand out the QR; register again while ONLINE.' })
  }
  for (const w of r.warnings) notes.push({ tone: r.cloud_state === 'failed' ? 'block' : 'warn', text: w })
  return notes
}

/**
 * Run the R-A flow for one person. `who` is the person's directory entry (null = unknown everywhere);
 * `online` = schedule writes possible now (AccessDirectory.canEdit); `listLoaded` = the Users & Access list
 * is loaded (without it the kiosk cannot know the schedule state and lets the edge decide at enrolment).
 */
export async function registerPerson(
  token: string,
  who: Identity | null,
  ctx: { online: boolean; listLoaded: boolean },
  input: RegisterInput,
): Promise<RegisterOutcome> {
  const api = getApi()
  const online = ctx.online
  const row = who?.row ?? null
  const base = { apply: null, enrol: null, scheduleRole: row?.bundle_role ?? null, notes: [] as Note[] }
  let plan: RegisterPlan = ctx.listLoaded
    ? registerPlan(
        row ?? (who && who.source === 'enrolments' ? { status: who.status, role: who.role, bundle_role: who.bundle_role, display: who.display, in_bundle: who.in_bundle } : null),
        online,
        input.role,
        input.display,
      )
    : { kind: 'enrol', role: who?.bundle_role ?? who?.role ?? '' }
  if (input.forceReadmit && online && plan.kind !== 'blocked') plan = { kind: 'put-then-enrol', readmit: true, create: false }
  if (plan.kind === 'blocked') {
    return { ...base, ok: false, stage: 'plan', plan, error: BLOCKED_TEXT[plan.why], reason: plan.why === 'REVOKED' ? 'USER_REVOKED' : plan.why === 'OFFLINE' ? 'OFFLINE' : null }
  }

  let apply: ApplyOutcome | null = null
  let scheduleRole = base.scheduleRole
  const notes: Note[] = []
  if (plan.kind === 'put-then-enrol') {
    const role = input.role ?? row?.role ?? null
    if (!role) return { ...base, ok: false, stage: 'plan', plan, error: BLOCKED_TEXT.NO_ROLE, reason: null }
    apply = await applyAccess(token, input.userId, { display: input.display.trim(), role, consent: true, actor: input.actor })
    if (!apply.ok) return { ...base, ok: false, stage: 'schedule', plan, apply, error: apply.message, reason: apply.error?.reason ?? null }
    for (const w of apply.warnings) notes.push({ tone: 'warn', text: w })
    if (!apply.applied) {
      return {
        ...base,
        ok: false,
        stage: 'schedule',
        plan,
        apply,
        notes,
        error: `The cloud saved ${input.userId} as ${apply.result?.role ?? role} (${versionText(apply.result?.cloud_bundle_version)}), but this kiosk could not install the new bundle yet, so enrolment would be refused. Try “Refresh edge bundle” in the Control panel, then register again.`,
        reason: null,
      }
    }
    if (apply.user && !apply.user.in_bundle) {
      return {
        ...base,
        ok: false,
        stage: 'schedule',
        plan,
        apply,
        notes,
        error: `${input.userId} is in the campus schedule as ${apply.result?.role ?? role}, but that gives no access at this kiosk's zone, so they are not enrolled here (pick another role or grant this zone in Users & access).`,
        reason: 'NOT_AT_THIS_KIOSK',
      }
    }
    scheduleRole = apply.user?.bundle_role ?? apply.result?.role ?? role
  } else if (online && row?.bundle_stale) {
    // the master changed since this kiosk's bundle: install it first (best effort) so the right role is used
    try {
      await api.refreshBundle(token)
    } catch {
      /* the enrolment still uses the installed bundle */
    }
  }

  const meta: EnrollMeta = {
    user_id: input.userId,
    display_name: input.display.trim(),
    email: input.email.trim() || null,
    consent: true,
    consent_version: CONSENT_VERSION,
    card_id: input.cardId.trim() || null,
    provision_totp: input.provisionTotp,
  }
  try {
    const r = await api.enroll(token, input.frames, meta)
    notifyAccessChanged()
    return { ok: true, stage: 'done', plan, apply, enrol: r, error: null, reason: null, scheduleRole: r.schedule_role ?? scheduleRole, notes: [...notes, ...enrolNotes(r)] }
  } catch (e) {
    const err = asApiError(e)
    notifyAccessChanged()
    const error =
      err?.code === 'BAD_RESPONSE'
        ? `The edge answered the enrolment in a shape this kiosk does not expect (edge restart pending?). The face may have been stored: check “Enrolled on this edge” before retrying. ${err.message}`
        : errorText(e)
    return { ok: false, stage: 'enrol', plan, apply, enrol: null, error, reason: err?.reason ?? null, scheduleRole, notes }
  }
}
