/**
 * Users & Access (API.md v1.4 §3.18.1): the signed campus schedule (role, status, extra zones, extended hours,
 * validity) merged with this edge's enrolment state. Hours (R-I) = role_defaults[role].windows[zone] (when the
 * zone is permitted) + extra_windows[zone] for the selected zone / day; next to it the edge's own `today` for
 * its zone ("enforced today"). Edits / revoke / restore / re-admit go through AccessEditor (ONLINE only);
 * offline the list is the installed bundle, read-only.
 */
import { useMemo, useState } from 'react'
import { DAY_CODES, getApi, type AccessUser, type DayCode } from '../../api'
import { refreshMode } from '../../shared/modeStore'
import { extraWindowsText } from '../../shared/accessHours'
import { hoursFor, hoursText } from '../../shared/accessRules'
import { errorText, useAccessDirectory } from '../../shared/accessDirectory'
import { toast } from '../../shared/toast'
import { Card } from '../ui'
import { AccessEditor } from './AccessEditor'

function statusOf(u: AccessUser, nowMs: number): { text: string; tone: 'ok' | 'warn' | 'bad' } {
  switch (u.status) {
    case 'NOT_IN_SCHEDULE':
      return { text: 'not in schedule', tone: 'bad' }
    case 'REVOKED':
      return { text: `revoked${u.revoked_reason ? ` (${u.revoked_reason})` : ''}`, tone: 'bad' }
    case 'ERASED':
      return { text: 'erased (DPDP)', tone: 'bad' }
    case 'ACTIVE':
      break
  }
  if (!u.in_bundle) return { text: 'no access at this kiosk', tone: 'warn' }
  if (u.valid_until && Date.parse(u.valid_until) <= nowMs) return { text: 'validity ended', tone: 'bad' }
  if (u.valid_from && Date.parse(u.valid_from) > nowMs) return { text: `from ${new Date(u.valid_from).toLocaleString([], { hour12: false })}`, tone: 'warn' }
  if (u.valid_until) return { text: `until ${new Date(u.valid_until).toLocaleString([], { hour12: false })}`, tone: 'warn' }
  return { text: 'active', tone: 'ok' }
}

const TONE = { ok: 'text-[#006300]', warn: 'text-[#8a5a00]', bad: 'text-[#d03b3b]' }
const NOW_TEXT: Record<string, string> = {
  IN_WINDOW: 'in window',
  GRACE_WINDOW: 'grace window',
  OUTSIDE_WINDOW: 'outside hours',
  NO_ENTITLEMENT: 'no entitlement',
  ZONE_NOT_PERMITTED: 'zone not permitted',
  HOLIDAY: 'holiday',
  REVOKED: 'revoked',
}

export function UsersAccessPanel({ token }: { token: string }) {
  const api = getApi()
  const dir = useAccessDirectory(token, 'users-tab')
  const [editing, setEditing] = useState<{ user: AccessUser | null } | null>(null)
  const [filter, setFilter] = useState('')
  const [refreshing, setRefreshing] = useState(false)
  const access = dir.access
  const [zoneSel, setZoneSel] = useState<string | null>(null)
  const [daySel, setDaySel] = useState<DayCode | null>(null)
  const zone = zoneSel ?? access?.zone ?? ''
  const day = daySel ?? access?.day ?? 'MON'
  const [nowMs] = useState(() => Date.now())

  const rows = useMemo(() => {
    const q = filter.trim().toLowerCase()
    const list = access?.users ?? []
    return q ? list.filter((u) => `${u.user_id} ${u.display} ${u.role ?? ''} ${u.status}`.toLowerCase().includes(q)) : list
  }, [access, filter])

  const pullBundle = async () => {
    setRefreshing(true)
    try {
      const r = await api.refreshBundle(token)
      if (r.result === 'failed') {
        toast.error(`Bundle refresh failed: ${r.error ?? 'the edge reported result "failed" without a reason'} (edge still runs v${String(r.installed_version ?? '?')})`)
        dir.refresh()
        refreshMode()
        return
      }
      toast.success(
        r.result === 'installed'
          ? `Edge bundle v${String(r.installed_version)} installed (was v${String(r.previous_version ?? '?')})`
          : `Edge bundle v${String(r.installed_version ?? '?')} is already the newest`,
      )
      dir.refresh()
      refreshMode()
    } catch (e) {
      toast.error(`Bundle refresh failed: ${errorText(e)}`)
    } finally {
      setRefreshing(false)
    }
  }

  if (!token) {
    return (
      <Card title="Users & access">
        <p className="text-sm text-[#8f1d1d]">Enter the admin token (top right) to load the campus schedule.</p>
      </Card>
    )
  }

  const zones = access ? Object.keys(access.zones).sort() : []
  const enrolledCount = access?.users.filter((u) => u.local.enrolled).length ?? 0

  return (
    <Card
      title="Users & access (signed campus schedule)"
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-[#52514e]">
            {access
              ? `${access.source === 'cloud+bundle' ? `cloud master v${String(access.cloud_bundle_version ?? '?')}` : 'installed bundle only'} · kiosk runs v${String(access.bundle.version ?? '?')}`
              : dir.loading
                ? 'loading…'
                : ''}
          </span>
          <button type="button" onClick={() => dir.refresh()} className="rounded-lg px-3 py-1 text-sm ring-1 ring-black/15 hover:bg-[#f0efec]">
            {dir.loading ? 'Loading…' : 'Reload'}
          </button>
          <button
            type="button"
            disabled={!dir.canRefreshBundle || refreshing}
            title={dir.refreshBlockedReason ?? 'Pull, verify and install the newest cloud bundle now (the edge reports its own error if the cloud is not available)'}
            onClick={() => void pullBundle()}
            className="rounded-lg px-3 py-1 text-sm ring-1 ring-black/15 hover:bg-[#f0efec] disabled:opacity-50"
          >
            {refreshing ? 'Refreshing…' : 'Refresh edge bundle'}
          </button>
          <button
            type="button"
            disabled={!dir.canEdit || !access}
            title={dir.editBlockedReason ?? undefined}
            onClick={() => setEditing({ user: null })}
            className="rounded-lg bg-[#2a78d6] px-3 py-1 text-sm font-semibold text-white hover:bg-[#256abf] disabled:opacity-50"
          >
            Add person
          </button>
        </div>
      }
    >
      <p className="mb-3 text-sm text-[#52514e]">
        The signed schedule is the only source of a person’s role and hours. Registering a face never changes them; changes here go to the cloud,
        which re-signs the bundle, and this kiosk installs it straight away.
      </p>
      {dir.editBlockedReason ? (
        <p className="mb-3 rounded-lg bg-[#fff4d6] px-3 py-2 text-sm text-[#5c4300]">
          <b>Read-only.</b> {dir.editBlockedReason}
        </p>
      ) : null}
      {dir.accessError && !access ? <p className="mb-3 rounded-lg bg-[#fde2e1] px-3 py-2 text-sm text-[#8f1d1d]">{errorText(dir.accessError)}</p> : null}
      {dir.accessError && access ? <p className="mb-2 text-xs text-[#d03b3b]">Last reload failed: {dir.accessError} (showing the previous list)</p> : null}
      {access?.pending_cloud_erasures.length ? (
        <p className="mb-3 rounded-lg bg-[#fff4d6] px-3 py-2 text-sm text-[#5c4300]">
          Cloud erasure queued (retried at the next sync): <span className="font-mono">{access.pending_cloud_erasures.join(', ')}</span>. Their local data is
          already gone.
        </p>
      ) : null}

      {editing && access ? (
        <div className="mb-4">
          <AccessEditor
            key={editing.user?.user_id ?? 'new'}
            user={editing.user}
            access={access}
            token={token}
            canEdit={dir.canEdit}
            blockedReason={dir.editBlockedReason}
            onApplied={() => {
              dir.refresh()
              refreshMode()
            }}
            onClose={() => setEditing(null)}
          />
        </div>
      ) : null}

      <div className="mb-2 flex flex-wrap items-center gap-2">
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter by name, id, role or status"
          className="w-64 rounded-lg border border-black/20 bg-white px-2 py-1 text-sm"
          aria-label="Filter users"
        />
        <label className="flex items-center gap-1 text-xs text-[#52514e]">
          Hours for
          <select className="rounded-lg border border-black/20 bg-white px-1 py-0.5 font-mono text-xs" value={zone} onChange={(e) => setZoneSel(e.target.value)}>
            {zones.map((z) => (
              <option key={z} value={z}>
                {z}
                {z === access?.zone ? ' (this kiosk)' : ''}
              </option>
            ))}
          </select>
          on
          <select className="rounded-lg border border-black/20 bg-white px-1 py-0.5 text-xs" value={day} onChange={(e) => setDaySel(e.target.value as DayCode)}>
            {DAY_CODES.map((d) => (
              <option key={d} value={d}>
                {d}
                {d === access?.day ? ' (today)' : ''}
              </option>
            ))}
          </select>
        </label>
        <span className="text-xs text-[#898781]">
          {rows.length} of {access?.users.length ?? 0} · enrolled on this edge: {access ? enrolledCount : '–'}
          {access ? ` · edge time ${access.now_local} ${access.day} ${access.date_local}` : ''}
        </span>
      </div>

      {access ? (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[60rem] text-left text-sm">
            <thead className="border-b border-black/15 text-xs text-[#52514e] uppercase">
              <tr>
                <th className="py-1.5 pr-3">Name</th>
                <th className="py-1.5 pr-3">User id</th>
                <th className="py-1.5 pr-3">Role (schedule)</th>
                <th className="py-1.5 pr-3">
                  Hours · {zone.replace(/_/g, ' ')} · {day}
                </th>
                <th className="py-1.5 pr-3">Enforced now here</th>
                <th className="py-1.5 pr-3">Extended hours</th>
                <th className="py-1.5 pr-3">Enrolled here</th>
                <th className="py-1.5 pr-3">Cloud faces</th>
                <th className="py-1.5 pr-3">Status</th>
                <th className="py-1.5" />
              </tr>
            </thead>
            <tbody>
              {rows.map((u) => {
                const st = statusOf(u, nowMs)
                const hours = hoursFor(u, zone, day, access)
                return (
                  <tr key={u.user_id} className="border-b border-[#e1e0d9] align-top last:border-0">
                    <td className="py-1.5 pr-3 font-medium">{u.display}</td>
                    <td className="py-1.5 pr-3 font-mono text-xs">{u.user_id}</td>
                    <td className="py-1.5 pr-3">
                      {u.role ? <b>{u.role}</b> : <span className="text-[#d03b3b]">none</span>}
                      {u.bundle_stale || (u.role && u.bundle_role !== u.role && u.in_bundle) ? (
                        <span className="block text-xs text-[#8a5a00]">kiosk bundle: {u.bundle_role ?? 'none'} (refresh pending)</span>
                      ) : null}
                      {u.local.template_role && u.local.template_role !== u.role ? (
                        <span className="block text-xs text-[#898781]">template stored as {u.local.template_role}</span>
                      ) : null}
                      {u.zones_add.length ? <span className="block text-xs text-[#52514e]">+ {u.zones_add.join(', ')}</span> : null}
                      {u.zones_remove.length ? <span className="block text-xs text-[#52514e]">− {u.zones_remove.join(', ')}</span> : null}
                    </td>
                    <td className={`py-1.5 pr-3 font-mono text-xs ${hours.kind === 'windows' ? '' : 'text-[#d03b3b]'}`}>{hoursText(hours)}</td>
                    <td className="py-1.5 pr-3 text-xs">
                      {u.today ? (
                        <>
                          <span className="font-mono">{u.today.windows.length ? u.today.windows.map((w) => `${w.start}–${w.end}`).join(', ') : 'none'}</span>
                          <span className={`block ${u.today.status_now === 'IN_WINDOW' ? 'text-[#006300]' : u.today.status_now === 'GRACE_WINDOW' ? 'text-[#8a5a00]' : 'text-[#d03b3b]'}`}>
                            {u.today.now_local}: {NOW_TEXT[u.today.status_now] ?? u.today.status_now}
                            {u.today.holiday ? ' · holiday' : ''}
                          </span>
                        </>
                      ) : (
                        <span className="text-[#898781]">not in this kiosk’s bundle</span>
                      )}
                    </td>
                    <td className="py-1.5 pr-3 text-xs">{extraWindowsText(u.extra_windows) || <span className="text-[#898781]">role default</span>}</td>
                    <td className="py-1.5 pr-3">
                      {u.local.enrolled ? `yes · ${u.local.templates}` : <span className="text-[#898781]">no</span>}
                      {u.local.totp_local ? <span className="block text-xs text-[#52514e]">TOTP{u.fallback.totp_enrolled ? '' : ' (not active)'}</span> : null}
                    </td>
                    <td className="py-1.5 pr-3">
                      {u.cloud_faces === null ? <span className="text-[#898781]">–</span> : u.cloud_faces > 0 ? u.cloud_faces : <span className="text-[#8a5a00]">0</span>}
                    </td>
                    <td className={`py-1.5 pr-3 text-xs font-semibold ${TONE[st.tone]}`}>
                      {st.text}
                      {access.pending_cloud_erasures.includes(u.user_id) ? <span className="block font-normal text-[#8a5a00]">cloud erasure queued</span> : null}
                    </td>
                    <td className="py-1.5 text-right">
                      <button
                        type="button"
                        onClick={() => setEditing({ user: u })}
                        className="rounded-lg px-3 py-1 text-sm font-semibold whitespace-nowrap ring-1 ring-black/15 hover:bg-[#f0efec]"
                      >
                        {!dir.canEdit
                          ? 'View'
                          : u.status === 'ERASED'
                            ? 'Re-admit'
                            : u.status === 'REVOKED'
                              ? 'Restore…'
                              : u.status === 'NOT_IN_SCHEDULE'
                                ? 'Add to schedule'
                                : 'Edit'}
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      ) : dir.loading ? (
        <p className="text-sm text-[#52514e]">Loading the schedule…</p>
      ) : null}
      {access ? (
        <p className="mt-2 text-xs text-[#898781]">
          “Hours” = the role’s default windows (when the zone is permitted) plus extended hours, for the chosen zone and day. “Enforced now here” is
          the edge’s own evaluation for this kiosk’s zone, including exceptions, holidays and the demo clock.
          {access.source === 'bundle' ? ' Offline: role defaults and zones are those of this kiosk’s bundle only.' : ''}
        </p>
      ) : null}
    </Card>
  )
}
