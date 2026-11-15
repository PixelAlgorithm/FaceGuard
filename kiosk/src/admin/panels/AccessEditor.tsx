/**
 * Edit / add one person's access in the signed campus schedule (API.md v1.4 §3.18.2-3): display name, role
 * (schedule roles), extra zones, per-zone extended hours, validity; Revoke (R-C, dedicated route), Restore
 * (consent + restore) and Re-admit an ERASED person (R-B, consent). Every write goes PUT / POST through the
 * edge to the cloud master, which re-signs the bundle; the edge installs it in the same call.
 * Field limits (R-H) come from accessRules.ts, identical to the contract; written times are 00:00-23:59.
 */
import { useMemo, useState } from 'react'
import { getApi } from '../../api'
import { DAY_CODES, type AccessUpdate, type AccessUser, type AccessUsersResponse, type AccessWindow, type DayCode } from '../../api/types'
import { windowsText } from '../../shared/accessHours'
import { applyAccess, errorText, notifyAccessChanged, versionText, type ApplyOutcome } from '../../shared/accessDirectory'
import { REVOKE_REASON_RE, accessUpdateErrors, hoursFor, hoursText, windowError } from '../../shared/accessRules'
import { useAuth } from '../../shared/auth/context'
import { PERM, needsText } from '../../shared/auth/permissions'
import { toast } from '../../shared/toast'

type Preset = 'default' | 'allday' | 'custom'

interface ZoneState {
  preset: Preset
  rows: AccessWindow[]
}

const field = 'rounded-lg border border-black/20 bg-white px-2 py-1 text-sm disabled:bg-[#f0efec]'
const ALL_DAYS: DayCode[] = [...DAY_CODES]
const WEEKDAYS: DayCode[] = ['MON', 'TUE', 'WED', 'THU', 'FRI']
/** "all day" as a WRITTEN window (R-H: 24:00 is not writable) */
const ALL_DAY: AccessWindow = { days: [...ALL_DAYS], start: '00:00', end: '23:59' }
const REVOKE_REASONS = ['ADMIN', 'LOST_BADGE', 'LEFT_CAMPUS', 'SECURITY'] as const

function initZone(ws: AccessWindow[] | undefined): ZoneState {
  if (!ws || !ws.length) return { preset: 'default', rows: [{ days: [...WEEKDAYS], start: '18:00', end: '23:00' }] }
  const allDay = ws.length === 1 && ws[0].days.length === 7 && ws[0].start === '00:00' && (ws[0].end === '23:59' || ws[0].end === '24:00')
  return { preset: allDay ? 'allday' : 'custom', rows: ws.map((w) => ({ days: [...w.days], start: w.start, end: w.end === '24:00' ? '23:59' : w.end })) }
}

/** ISO instant -> "YYYY-MM-DDTHH:MM" in Asia/Kolkata (for <input type="datetime-local">). */
function toLocalInput(iso: string | null): string {
  if (!iso) return ''
  const t = Date.parse(iso)
  if (!Number.isFinite(t)) return ''
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Kolkata',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(t)
  const g = (k: string) => parts.find((p) => p.type === k)?.value ?? '00'
  return `${g('year')}-${g('month')}-${g('day')}T${g('hour')}:${g('minute')}`
}

/** "YYYY-MM-DDTHH:MM" (Asia/Kolkata wall time) -> ISO with +05:30; "" -> null. */
function fromLocalInput(v: string): string | null {
  return v ? `${v}:00+05:30` : null
}

const sameJson = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b)

export function AccessEditor({
  user,
  access,
  token,
  canEdit,
  blockedReason,
  onApplied,
  onClose,
}: {
  /** null = add a new person */
  user: AccessUser | null
  access: AccessUsersResponse
  token: string
  canEdit: boolean
  blockedReason: string | null
  onApplied: () => void
  onClose: () => void
}) {
  const api = getApi()
  const { can, principal } = useAuth()
  // the edge derives the real actor from the session; this value is informational (design v2 §D)
  const actor = principal?.actor_id ?? 'control-panel'
  // `canEdit` = the schedule is writable here (online, list loaded); each action also needs its own permission
  const mayEdit = can(PERM.accessEdit)
  const mayRevoke = can(PERM.accessRevoke)
  const adding = user === null
  const kioskZone = access.zone ?? ''
  const zones = useMemo(() => Object.keys(access.zones).sort((a, b) => (a === kioskZone ? -1 : b === kioskZone ? 1 : a.localeCompare(b))), [access, kioskZone])
  const [userId, setUserId] = useState(user?.user_id ?? '')
  const [display, setDisplay] = useState(user?.display ?? '')
  const [role, setRole] = useState<string>(() => (user?.role && access.roles.includes(user.role) ? user.role : (access.roles.find((r) => r === 'student') ?? access.roles[0] ?? '')))
  const [zonesAdd, setZonesAdd] = useState<string[]>(user?.zones_add ?? [])
  const [ew, setEw] = useState<Record<string, ZoneState>>(() => Object.fromEntries(zones.map((z) => [z, initZone(user?.extra_windows[z])])))
  const [validFrom, setValidFrom] = useState(toLocalInput(user?.valid_from ?? null))
  const [validUntil, setValidUntil] = useState(toLocalInput(user?.valid_until ?? null))
  const [consent, setConsent] = useState(false)
  const [revokeReason, setRevokeReason] = useState<string>('ADMIN')
  const [busy, setBusy] = useState(false)
  const [outcome, setOutcome] = useState<{ ok: boolean; text: string; warnings: string[] } | null>(null)
  const [previewZone, setPreviewZone] = useState(kioskZone || zones[0] || '')
  const [previewDay, setPreviewDay] = useState<DayCode>(access.day)

  const status = user?.status ?? 'NOT_IN_SCHEDULE'
  const erased = status === 'ERASED'
  const revoked = status === 'REVOKED'
  const creating = adding || status === 'NOT_IN_SCHEDULE'
  const roleDef = access.role_defaults[role]

  const extraWindows = useMemo(() => {
    const out: Record<string, AccessWindow[]> = {}
    for (const z of zones) {
      const st = ew[z]
      if (!st || st.preset === 'default') continue
      out[z] = st.preset === 'allday' ? [{ ...ALL_DAY, days: [...ALL_DAY.days] }] : st.rows.map((r) => ({ ...r, days: [...r.days] }))
    }
    return out
  }, [ew, zones])

  const vf = fromLocalInput(validFrom)
  const vu = fromLocalInput(validUntil)
  const id = adding ? userId : (user?.user_id ?? '')

  /** body with only the changed fields (absent = unchanged); role is always sent (contract) */
  const body: AccessUpdate = { role, actor }
  if (creating || display.trim() !== (user?.display ?? '')) body.display = display.trim()
  if (creating || !sameJson(zonesAdd, user?.zones_add ?? [])) body.zones_add = zonesAdd
  if (creating ? Object.keys(extraWindows).length > 0 : !sameJson(extraWindows, user?.extra_windows ?? {})) body.extra_windows = extraWindows
  if (vf !== (user?.valid_from ? fromLocalInput(toLocalInput(user.valid_from)) : null)) body.valid_from = vf
  if (vu !== (user?.valid_until ? fromLocalInput(toLocalInput(user.valid_until)) : null)) body.valid_until = vu
  if (creating) body.consent = consent

  const errors = accessUpdateErrors(id, body)
  if (!access.roles.includes(role)) errors.push('role: pick one of the schedule roles')
  if (adding && access.users.some((u) => u.user_id === userId && u.in_schedule)) errors.push(`${userId} is already in the schedule: edit it instead`)
  if (creating && !consent) errors.push('tick the consent box: adding a person needs their consent (DPDP)')
  if (creating && !display.trim()) errors.push('display name: required for a new person')

  const draft = { role, status: 'ACTIVE' as const, zones_add: zonesAdd, zones_remove: user?.zones_remove ?? [], extra_windows: extraWindows }
  const preview = hoursFor(draft, previewZone, previewDay, access)
  const notPermittedExtras = Object.keys(extraWindows).filter((z) => {
    const explicit = access.zones[z]?.requires_explicit_grant === true
    return !(!draft.zones_remove.includes(z) && (zonesAdd.includes(z) || (!explicit && (roleDef?.zones ?? []).includes(z))))
  })

  const setZone = (z: string, next: Partial<ZoneState>) => setEw((cur) => ({ ...cur, [z]: { ...(cur[z] ?? initZone(undefined)), ...next } }))
  const setRow = (z: string, i: number, next: Partial<AccessWindow>) =>
    setEw((cur) => {
      const st = cur[z] ?? initZone(undefined)
      return { ...cur, [z]: { ...st, rows: st.rows.map((r, j) => (j === i ? { ...r, ...next } : r)) } }
    })

  const show = (o: ApplyOutcome, label: string) => {
    const text = o.ok ? (o.applied ? o.message : `${o.message} Use “Refresh edge bundle” to install it here.`) : o.message
    setOutcome({ ok: o.ok, text, warnings: o.warnings })
    if (o.ok) toast.success(`${label}: ${o.message}`)
    else toast.error(`${label} failed: ${o.message}`)
    if (o.ok) onApplied()
  }

  const put = async (req: AccessUpdate, label: string) => {
    setBusy(true)
    setOutcome(null)
    const o = await applyAccess(token, id, req)
    setBusy(false)
    show(o, label)
  }

  const submit = () => {
    if (errors.length || !canEdit || !mayEdit || busy) return
    if (user?.role && user.role !== role && !window.confirm(`Change ${id} from ${user.role} to ${role}? Their access hours change on every kiosk that installs the new bundle.`)) return
    void put(body, creating ? `Added ${id}` : `Updated ${id}`)
  }

  const revoke = async () => {
    if (!user || !canEdit || !mayRevoke || busy) return
    if (!REVOKE_REASON_RE.test(revokeReason) || revokeReason === 'ERASED') return
    if (!window.confirm(`Revoke ${user.user_id} (${user.display}) now, reason ${revokeReason}? Every kiosk then DENIES them (SCHEDULE_REVOKED), online and offline. “Restore” undoes it.`)) return
    setBusy(true)
    setOutcome(null)
    try {
      const r = await api.revokeAccessUser(token, user.user_id, { reason: revokeReason, actor })
      const applied = r.bundle.applied === true
      const at = r.revoked_at ? ` at ${new Date(r.revoked_at).toLocaleString([], { hour12: false })}` : ''
      const text = applied
        ? `${r.user_id} revoked (${r.reason})${at} · bundle ${versionText(r.cloud_bundle_version)} installed on this kiosk.`
        : `${r.user_id} revocation (${r.reason}) sent to the cloud${at} · bundle ${versionText(r.cloud_bundle_version)}: the new bundle is NOT installed here yet. The revocation itself reaches this kiosk with the next revocation-feed pull (edge heartbeat, a few seconds); use “Refresh edge bundle” to install the bundle now.`
      setOutcome({ ok: true, text, warnings: r.warnings })
      if (applied) toast.success(text)
      else toast.error(text)
      notifyAccessChanged()
      onApplied()
    } catch (e) {
      const text = errorText(e)
      setOutcome({ ok: false, text, warnings: [] })
      toast.error(`Revoke failed: ${text}`)
    } finally {
      setBusy(false)
    }
  }

  const restore = () => {
    if (!user || !canEdit || !mayEdit || busy || !consent) return
    void put({ role, consent: true, restore: true, actor }, `Restored ${user.user_id}`)
  }

  const readmit = () => {
    if (!user || !canEdit || !mayEdit || busy || !consent || errors.some((e) => e.startsWith('display'))) return
    void put({ role, display: display.trim(), consent: true, actor }, `Re-admitted ${user.user_id}`)
  }

  const disabled = !canEdit || !mayEdit || busy
  const revokeDisabled = !canEdit || !mayRevoke || busy

  return (
    <section className="rounded-xl border-2 border-[#2a78d6]/40 bg-white p-4" aria-label={adding ? 'Add person' : `Edit ${user?.user_id}`}>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <h3 className="text-base font-bold">{adding ? 'Add a person to the campus schedule' : `Access · ${user?.display} (${user?.user_id})`}</h3>
        {!adding ? (
          <span
            className={`rounded-full px-2 py-0.5 text-xs font-bold ${status === 'ACTIVE' ? 'bg-[#e3f4e3] text-[#0f5132]' : status === 'NOT_IN_SCHEDULE' ? 'bg-[#f0efec] text-[#52514e]' : 'bg-[#fde2e1] text-[#8f1d1d]'}`}
          >
            {status}
            {user?.revoked_reason && status !== 'ACTIVE' ? ` · ${user.revoked_reason}` : ''}
          </span>
        ) : null}
        <button type="button" onClick={onClose} className="ml-auto rounded-lg px-3 py-1 text-sm ring-1 ring-black/15 hover:bg-[#f0efec]">
          Close
        </button>
      </div>
      {!canEdit ? <p className="mb-3 rounded-lg bg-[#fff4d6] px-3 py-2 text-sm text-[#5c4300]">Read-only: {blockedReason}</p> : null}
      {erased ? (
        <p className="mb-3 rounded-lg bg-[#fde2e1] px-3 py-2 text-sm text-[#8f1d1d]">
          {user?.user_id} was <b>erased</b> (DPDP){user?.revoked_at ? ` on ${new Date(user.revoked_at).toLocaleString([], { hour12: false })}` : ''}: no face data, no
          access. With the person’s fresh consent you can <b>re-admit</b> them, then enrol their face again (Quick enrol or /register: “Re-admit and enrol”).
        </p>
      ) : null}
      {revoked ? (
        <p className="mb-3 rounded-lg bg-[#fde2e1] px-3 py-2 text-sm text-[#8f1d1d]">
          {user?.user_id} is <b>revoked</b> ({user?.revoked_reason ?? 'ADMIN'}): every kiosk denies them (SCHEDULE_REVOKED). Edits are saved but do not lift the
          revocation; use <b>Restore</b>.
        </p>
      ) : null}
      {user?.bundle_stale ? (
        <p className="mb-3 rounded-lg bg-[#fff4d6] px-3 py-2 text-xs text-[#5c4300]">
          The cloud master differs from this kiosk’s installed bundle (decisions here still use role {user.bundle_role ?? 'none'}): refresh the edge bundle.
        </p>
      ) : null}

      <div className="grid gap-3 md:grid-cols-3">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-xs text-[#52514e]">User id</span>
          <input
            className={`${field} font-mono`}
            value={userId}
            disabled={!adding || disabled}
            placeholder="u_ab12"
            onChange={(e) => setUserId(e.target.value.trim().toLowerCase())}
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-xs text-[#52514e]">Display name (shown on ALLOW, 1–80)</span>
          <input className={field} value={display} maxLength={80} disabled={disabled} onChange={(e) => setDisplay(e.target.value)} />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-xs text-[#52514e]">Role (campus schedule)</span>
          <select className={field} value={role} disabled={disabled} onChange={(e) => setRole(e.target.value)}>
            {access.roles.map((r) => (
              <option key={r} value={r}>
                {r}
                {r === user?.role ? ' (current)' : ''}
              </option>
            ))}
          </select>
          {user?.local.template_role && user.local.template_role !== role ? (
            <span className="text-xs text-[#898781]">face template stored as {user.local.template_role} (informational; the schedule role decides)</span>
          ) : null}
        </label>
      </div>

      <div className="mt-3 text-sm">
        <p className="text-xs text-[#52514e]">
          {role} default zones: {roleDef?.zones.length ? roleDef.zones.join(', ') : 'none (visitor pass / explicit grants only)'}. Extra zones (explicit grants):
        </p>
        <div className="mt-1 flex flex-wrap gap-3">
          {zones.map((z) => (
            <label key={z} className="flex items-center gap-1.5">
              <input
                type="checkbox"
                disabled={disabled}
                checked={zonesAdd.includes(z)}
                onChange={(e) => setZonesAdd((cur) => (e.target.checked ? [...cur, z] : cur.filter((x) => x !== z)))}
              />
              <span className="font-mono text-xs">{z}</span>
              {access.zones[z]?.requires_explicit_grant ? <span className="text-[10px] text-[#d03b3b]">grant required</span> : null}
            </label>
          ))}
        </div>
        {user?.zones_remove.length ? <p className="mt-1 text-xs text-[#898781]">Removed zones (set in the master): {user.zones_remove.join(', ')}</p> : null}
      </div>

      <div className="mt-4">
        <p className="mb-1 text-xs font-bold tracking-wide text-[#52514e] uppercase">Extended hours (added to the role's windows)</p>
        <div className="flex flex-col gap-2">
          {zones.map((z) => {
            const st = ew[z] ?? initZone(undefined)
            const def = roleDef?.windows[z] ?? []
            return (
              <div key={z} className="rounded-lg border border-[#e1e0d9] p-2">
                <div className="flex flex-wrap items-center gap-3 text-sm">
                  <span className="w-28 font-mono text-xs font-bold">{z}</span>
                  {(['default', 'allday', 'custom'] as const).map((p) => (
                    <label key={p} className="flex items-center gap-1">
                      <input type="radio" name={`preset-${z}`} disabled={disabled} checked={st.preset === p} onChange={() => setZone(z, { preset: p })} />
                      {p === 'default' ? 'Role default only' : p === 'allday' ? 'All day (00:00–23:59)' : 'Custom'}
                    </label>
                  ))}
                  <span className="text-xs text-[#898781]">role: {def.length ? windowsText(def) : 'no windows'}</span>
                </div>
                {st.preset === 'custom' ? (
                  <div className="mt-2 flex flex-col gap-2">
                    {st.rows.map((r, i) => {
                      const err = windowError(r)
                      return (
                        <div key={i} className="flex flex-wrap items-center gap-2 text-xs">
                          {DAY_CODES.map((d) => (
                            <label key={d} className="flex items-center gap-0.5">
                              <input
                                type="checkbox"
                                disabled={disabled}
                                checked={r.days.includes(d)}
                                onChange={(e) => setRow(z, i, { days: e.target.checked ? DAY_CODES.filter((x) => x === d || r.days.includes(x)) : r.days.filter((x) => x !== d) })}
                              />
                              {d}
                            </label>
                          ))}
                          <input
                            className={`${field} w-20 font-mono`}
                            value={r.start}
                            disabled={disabled}
                            aria-label={`${z} window ${i + 1} start (HH:MM)`}
                            onChange={(e) => setRow(z, i, { start: e.target.value.trim() })}
                          />
                          –
                          <input
                            className={`${field} w-20 font-mono`}
                            value={r.end}
                            disabled={disabled}
                            aria-label={`${z} window ${i + 1} end (HH:MM, up to 23:59)`}
                            onChange={(e) => setRow(z, i, { end: e.target.value.trim() })}
                          />
                          <button
                            type="button"
                            disabled={disabled || st.rows.length <= 1}
                            className="rounded px-2 py-0.5 ring-1 ring-black/15 disabled:opacity-40"
                            onClick={() => setZone(z, { rows: st.rows.filter((_, j) => j !== i) })}
                          >
                            remove
                          </button>
                          {err ? <span className="text-[#d03b3b]">{err}</span> : null}
                        </div>
                      )
                    })}
                    <button
                      type="button"
                      disabled={disabled || st.rows.length >= 14}
                      className="self-start rounded px-2 py-0.5 text-xs ring-1 ring-black/15 disabled:opacity-40"
                      onClick={() => setZone(z, { rows: [...st.rows, { days: [...ALL_DAYS], start: '08:00', end: '20:00' }] })}
                    >
                      + add window
                    </button>
                  </div>
                ) : null}
              </div>
            )
          })}
        </div>
        {notPermittedExtras.length ? (
          <p className="mt-2 text-xs text-[#8f1d1d]">
            Extended hours in {notPermittedExtras.join(', ')} have no effect unless the zone is permitted: a {role} needs an explicit grant there (tick it
            above).
          </p>
        ) : null}
      </div>

      <div className="mt-4 grid gap-3 md:grid-cols-2">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-xs text-[#52514e]">Valid from (Asia/Kolkata, empty = no limit)</span>
          <input type="datetime-local" className={field} value={validFrom} disabled={disabled} onChange={(e) => setValidFrom(e.target.value)} />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-xs text-[#52514e]">Valid until (Asia/Kolkata, empty = no limit)</span>
          <input type="datetime-local" className={field} value={validUntil} disabled={disabled} onChange={(e) => setValidUntil(e.target.value)} />
        </label>
      </div>

      <div className="mt-3 rounded-lg bg-[#f0efec] px-3 py-2 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <span>Hours with these settings in</span>
          <select className={`${field} py-0.5 font-mono text-xs`} value={previewZone} onChange={(e) => setPreviewZone(e.target.value)} aria-label="Preview zone">
            {zones.map((z) => (
              <option key={z} value={z}>
                {z}
              </option>
            ))}
          </select>
          <span>on</span>
          <select className={`${field} py-0.5 text-xs`} value={previewDay} onChange={(e) => setPreviewDay(e.target.value as DayCode)} aria-label="Preview day">
            {DAY_CODES.map((d) => (
              <option key={d} value={d}>
                {d}
                {d === access.day ? ' (today)' : ''}
              </option>
            ))}
          </select>
          <b className="font-mono text-xs">{hoursText(preview)}</b>
        </div>
        {user?.today && previewZone === user.today.zone && previewDay === user.today.day ? (
          <p className="mt-1 text-xs text-[#52514e]">
            Enforced today by this kiosk (installed bundle, incl. exceptions / holidays):{' '}
            <b className="font-mono">{user.today.windows.length ? user.today.windows.map((w) => `${w.start}–${w.end}`).join(', ') : 'none'}</b> · now{' '}
            {user.today.now_local}: {user.today.status_now}
          </p>
        ) : null}
        <p className="mt-1 text-xs text-[#898781]">
          Role defaults + extended hours for the chosen zone and day. Exceptions, holidays and visitor passes are applied by the edge only.
        </p>
      </div>

      {creating || revoked || erased ? (
        <label className="mt-3 flex items-start gap-2 rounded-lg bg-[#fff8f0] p-2 text-xs ring-1 ring-[#f2a900]/50">
          <input type="checkbox" checked={consent} disabled={disabled} onChange={(e) => setConsent(e.target.checked)} className="mt-0.5" />
          <span>
            The person has given (fresh) consent to campus face access control (India DPDP Act 2023). Required to{' '}
            {creating ? 'add them' : erased ? 're-admit them after an erasure' : 'restore their access'}.
          </span>
        </label>
      ) : null}

      {errors.length && !erased ? (
        <ul className="mt-2 list-disc pl-5 text-xs text-[#d03b3b]">
          {errors.map((e) => (
            <li key={e}>{e}</li>
          ))}
        </ul>
      ) : null}
      {outcome ? (
        <div className={`mt-2 rounded-lg px-3 py-2 text-sm ${outcome.ok ? 'bg-[#e3f4e3] text-[#0f5132]' : 'bg-[#fde2e1] text-[#8f1d1d]'}`}>
          <p>
            {outcome.ok ? 'Done: ' : 'Not applied: '}
            {outcome.text}
          </p>
          {outcome.warnings.length ? (
            <ul className="mt-1 list-disc pl-5 text-xs text-[#5c4300]">
              {outcome.warnings.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}

      <div className="mt-3 flex flex-wrap items-center gap-2">
        {erased ? (
          <button
            type="button"
            disabled={disabled || !consent || !display.trim()}
            onClick={readmit}
            className="rounded-lg bg-[#2a78d6] px-4 py-1.5 text-sm font-semibold text-white hover:bg-[#256abf] disabled:opacity-50"
          >
            {busy ? 'Re-admitting…' : `Re-admit as ${role}`}
          </button>
        ) : (
          <button
            type="button"
            disabled={disabled || errors.length > 0}
            onClick={submit}
            className="rounded-lg bg-[#2a78d6] px-4 py-1.5 text-sm font-semibold text-white hover:bg-[#256abf] disabled:opacity-50"
          >
            {busy ? 'Applying…' : creating ? 'Add person' : 'Apply changes'}
          </button>
        )}
        {revoked ? (
          <button
            type="button"
            disabled={disabled || !consent}
            onClick={restore}
            title={consent ? undefined : 'Tick the consent box first'}
            className="rounded-lg px-3 py-1.5 text-sm font-semibold ring-1 ring-black/20 hover:bg-[#f0efec] disabled:opacity-50"
          >
            Restore access
          </button>
        ) : null}
        {status === 'ACTIVE' ? (
          <span className="inline-flex items-center gap-1">
            <select className={`${field} py-1 text-xs`} value={revokeReason} disabled={revokeDisabled} onChange={(e) => setRevokeReason(e.target.value)} aria-label="Revoke reason">
              {REVOKE_REASONS.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
            <button
              type="button"
              disabled={revokeDisabled}
              title={mayRevoke ? undefined : needsText(PERM.accessRevoke)}
              onClick={() => void revoke()}
              className="rounded-lg bg-[#d03b3b] px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-50"
            >
              Revoke now
            </button>
            {!mayRevoke ? <span className="text-xs text-[#8a6d00]">{needsText(PERM.accessRevoke)}</span> : null}
          </span>
        ) : null}
        {!mayEdit ? <span className="text-xs text-[#8a6d00]">{needsText(PERM.accessEdit)} to change roles, hours or validity</span> : null}
        <span className="text-xs text-[#898781]">Writes go to the cloud master schedule → re-signed bundle → installed on this edge.</span>
      </div>
    </section>
  )
}
