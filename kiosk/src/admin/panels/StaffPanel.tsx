/**
 * Staff & roles (staff:manage; design v2 §C/§F): list staff accounts, create one with a temporary password
 * (must be changed at first sign-in), change roles, disable / enable, reset the password, unlock. Every
 * mutation asks for the actor's own password (confirm_password; 403 REAUTH_REQUIRED when wrong).
 * Roles come from GET /v1/admin/roles; the edge refuses self-modification, the last admin and role ceilings.
 */
import { useState, type FormEvent } from 'react'
import { getApi } from '../../api'
import { AUTH_LIMITS, type RolesCatalog, type StaffAccount } from '../../api/authTypes'
import { authErrorText } from '../../shared/auth/authErrorText'
import { useAuth } from '../../shared/auth/context'
import { PERM, needsText } from '../../shared/auth/permissions'
import { toast } from '../../shared/toast'
import { RolePicker, ShownOnce } from '../staffShared'
import { fmtWhen, generateTempPassword } from '../staffUtil'
import { Card } from '../ui'
import { useReauth } from '../useReauth'
import { usePoll } from '../usePoll'
import { ApiKeysPanel } from './ApiKeysPanel'

const STAFF_POLL_MS = 15_000
const ROLES_POLL_MS = 300_000
const field = 'rounded-lg border border-black/20 bg-white px-2 py-1 text-sm'
const btn = 'rounded-lg px-2.5 py-1 text-xs font-semibold ring-1 ring-black/15 hover:bg-[#f0efec] disabled:opacity-50'

function usernameProblem(u: string): string | null {
  if (!u) return null
  if (!AUTH_LIMITS.usernamePattern.test(u)) return 'lowercase letter first, then 1–30 of a-z 0-9 _'
  if ((AUTH_LIMITS.reservedUsernames as readonly string[]).includes(u)) return 'reserved username'
  return null
}

interface Secret {
  label: string
  value: string
  note: string
}

function CreateStaffForm({ catalog, onCreated, ask }: { catalog: RolesCatalog; onCreated: (s: Secret) => void; ask: (a: string) => Promise<string | null> }) {
  const api = getApi()
  const { token } = useAuth()
  const [username, setUsername] = useState('')
  const [display, setDisplay] = useState('')
  const [roles, setRoles] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const problem = usernameProblem(username)
  const ok = !!username && !problem && !!display.trim() && display.length <= AUTH_LIMITS.displayNameMax && roles.length > 0
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!ok || busy) return
    const confirm = await ask(`Create staff account ${username} (${roles.join(', ')}).`)
    if (!confirm) return
    const temp = generateTempPassword()
    setBusy(true)
    try {
      await api.createStaff(token, { username, display_name: display.trim(), roles, temporary_password: temp, confirm_password: confirm })
      toast.success(`Created ${username}`)
      onCreated({ label: `Temporary password for ${username}`, value: temp, note: `Give it to ${display.trim()} in person; it must be changed at the first sign-in.` })
      setUsername('')
      setDisplay('')
      setRoles([])
    } catch (err) {
      toast.error(`Create failed: ${authErrorText(err)}`)
    } finally {
      setBusy(false)
    }
  }
  return (
    <form onSubmit={submit} className="flex flex-col gap-2 rounded-lg bg-[#f0efec] p-3">
      <p className="text-xs font-bold tracking-wide text-[#52514e] uppercase">New staff account</p>
      <div className="flex flex-wrap gap-2">
        <label className="flex flex-col text-xs text-[#52514e]">
          Username
          <input className={`${field} font-mono ${problem ? 'border-[#d03b3b]' : ''}`} value={username} onChange={(e) => setUsername(e.target.value.trim().toLowerCase())} autoComplete="off" />
        </label>
        <label className="flex flex-col text-xs text-[#52514e]">
          Display name
          <input className={field} value={display} maxLength={AUTH_LIMITS.displayNameMax} onChange={(e) => setDisplay(e.target.value)} autoComplete="off" />
        </label>
      </div>
      {problem ? <span className="text-xs text-[#d03b3b]">username: {problem}</span> : null}
      <RolePicker roles={catalog.roles} value={roles} onChange={setRoles} max={catalog.max_roles_per_account} idPrefix="new-staff" />
      <p className="text-xs text-[#52514e]">A random temporary password is generated and shown once; the person must change it at the first sign-in.</p>
      <div>
        <button type="submit" disabled={!ok || busy} className="rounded-lg bg-[#2a78d6] px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-50">
          {busy ? 'Creating…' : 'Create account'}
        </button>
      </div>
    </form>
  )
}

function StaffRow({
  s,
  catalog,
  self,
  ask,
  onChanged,
  onSecret,
}: {
  s: StaffAccount
  catalog: RolesCatalog
  self: boolean
  ask: (a: string) => Promise<string | null>
  onChanged: () => void
  onSecret: (x: Secret) => void
}) {
  const api = getApi()
  const { token } = useAuth()
  const [editRoles, setEditRoles] = useState<string[] | null>(null)
  const [busy, setBusy] = useState(false)
  const act = async (label: string, fn: (confirm: string) => Promise<unknown>, done?: () => void) => {
    const confirm = await ask(label)
    if (!confirm) return
    setBusy(true)
    try {
      await fn(confirm)
      toast.success(label)
      done?.()
      onChanged()
    } catch (err) {
      toast.error(`${label}: ${authErrorText(err)}`)
    } finally {
      setBusy(false)
    }
  }
  const selfHint = self ? 'You cannot change your own roles or status.' : undefined
  const selfPasswordHint = self ? 'Your own password is changed with your current password, not reset here.' : undefined
  return (
    <tr className="border-t border-[#e1e0d9] align-top">
      <td className="px-2 py-1.5">
        <span className="font-semibold">{s.display_name}</span>
        <span className="block font-mono text-[11px] text-[#52514e]">
          {s.username} · {s.staff_id}
          {self ? ' · you' : ''}
        </span>
      </td>
      <td className="px-2 py-1.5">
        {editRoles ? (
          <div className="flex flex-col gap-1">
            <RolePicker roles={catalog.roles} value={editRoles} onChange={setEditRoles} max={catalog.max_roles_per_account} idPrefix={`roles-${s.staff_id}`} />
            <span className="flex gap-1">
              <button
                type="button"
                className={btn}
                disabled={busy || editRoles.length === 0}
                onClick={() =>
                  void act(`Set roles of ${s.username} to ${editRoles.join(', ')}`, (c) => api.updateStaff(token, s.staff_id, { roles: editRoles, confirm_password: c }), () => setEditRoles(null))
                }
              >
                Save roles
              </button>
              <button type="button" className={btn} disabled={busy} onClick={() => setEditRoles(null)}>
                Cancel
              </button>
            </span>
          </div>
        ) : (
          <span className="text-xs">{s.roles.join(', ')}</span>
        )}
      </td>
      <td className="px-2 py-1.5 text-xs">
        <span className={s.status === 'active' ? 'text-[#006300]' : 'font-semibold text-[#8f1d1d]'}>{s.status}</span>
        {s.locked ? <span className="block font-semibold text-[#8f1d1d]">locked until {fmtWhen(s.locked_until)}</span> : null}
        {s.failed_logins ? <span className="block text-[#5c4300]">{s.failed_logins} failed sign-ins</span> : null}
        {s.must_change_password ? <span className="block text-[#5c4300]">must change password</span> : null}
        <span className="block text-[#52514e]">MFA {s.mfa_enabled ? 'on' : 'off'}</span>
      </td>
      <td className="px-2 py-1.5 text-[11px] text-[#52514e]">{fmtWhen(s.last_login_at)}</td>
      <td className="px-2 py-1.5">
        <span className="flex flex-wrap gap-1">
          <button type="button" className={btn} disabled={busy || self || editRoles !== null} title={selfHint} onClick={() => setEditRoles([...s.roles])}>
            Edit roles
          </button>
          <button
            type="button"
            className={btn}
            disabled={busy || self}
            title={selfHint}
            onClick={() =>
              void act(`${s.status === 'active' ? 'Disable' : 'Enable'} ${s.username}${s.status === 'active' ? ' (ends their sessions and revokes the API keys they created)' : ''}`, (c) =>
                api.updateStaff(token, s.staff_id, { status: s.status === 'active' ? 'disabled' : 'active', confirm_password: c }),
              )
            }
          >
            {s.status === 'active' ? 'Disable' : 'Enable'}
          </button>
          <button
            type="button"
            className={btn}
            disabled={busy || self}
            title={selfPasswordHint}
            onClick={() => {
              const temp = generateTempPassword()
              void act(`Reset the password of ${s.username} (ends their sessions)`, (c) => api.resetStaffPassword(token, s.staff_id, { temporary_password: temp, confirm_password: c }), () =>
                onSecret({ label: `Temporary password for ${s.username}`, value: temp, note: `Give it to ${s.display_name} in person; it must be changed at the next sign-in.` }),
              )
            }}
          >
            Reset password
          </button>
          {s.locked || s.failed_logins > 0 ? (
            <button type="button" className={btn} disabled={busy} onClick={() => void act(`Unlock ${s.username}`, (c) => api.unlockStaff(token, s.staff_id, { confirm_password: c }))}>
              Unlock
            </button>
          ) : null}
        </span>
      </td>
    </tr>
  )
}

export function StaffPanel() {
  const api = getApi()
  const { token, can, principal } = useAuth()
  const allowed = can(PERM.staffManage)
  const live = !!token && allowed
  const staff = usePoll(() => api.listStaff(token), STAFF_POLL_MS, live, `staff:${token}`, authErrorText)
  const roles = usePoll(() => api.listRoles(token), ROLES_POLL_MS, live, `roles:${token}`, authErrorText)
  const { ask, dialog } = useReauth()
  const [secret, setSecret] = useState<Secret | null>(null)

  if (!allowed) {
    return (
      <Card title="Staff & roles">
        <p className="text-sm text-[#8a6d00]">{needsText(PERM.staffManage)}</p>
      </Card>
    )
  }
  const catalog = roles.data
  return (
    <div className="flex flex-col gap-4">
      {dialog}
      <Card
        title="Staff & roles"
        actions={
          <button type="button" className={btn} onClick={staff.refresh}>
            Refresh
          </button>
        }
      >
        <p className="mb-3 text-sm text-[#52514e]">
          Individual staff accounts replace the shared admin token. Every change here is audited with your account and needs your password.
        </p>
        {staff.error ? <p className="mb-2 text-sm text-[#d03b3b]">{staff.error}</p> : null}
        {roles.error ? <p className="mb-2 text-sm text-[#d03b3b]">roles: {roles.error}</p> : null}
        {secret ? <ShownOnce key={secret.value} label={secret.label} secret={secret.value} note={secret.note} onHide={() => setSecret(null)} /> : null}
        {catalog ? <CreateStaffForm catalog={catalog} ask={ask} onCreated={(s) => {
          setSecret(s)
          staff.refresh()
        }} /> : <p className="text-sm text-[#898781]">Loading roles…</p>}
        <div className="mt-3 overflow-auto rounded border border-black/10">
          <table className="w-full text-left text-sm">
            <thead className="bg-[#f0efec] text-xs text-[#52514e]">
              <tr>
                <th className="px-2 py-1">Account</th>
                <th className="px-2 py-1">Roles</th>
                <th className="px-2 py-1">State</th>
                <th className="px-2 py-1">Last sign-in</th>
                <th className="px-2 py-1">Actions</th>
              </tr>
            </thead>
            <tbody>
              {(staff.data ?? []).map((s) =>
                catalog ? (
                  <StaffRow key={s.staff_id} s={s} catalog={catalog} self={s.staff_id === principal?.staff_id} ask={ask} onChanged={staff.refresh} onSecret={setSecret} />
                ) : null,
              )}
            </tbody>
          </table>
          {staff.data && staff.data.length === 0 ? <p className="p-2 text-sm text-[#898781]">No staff accounts.</p> : null}
        </div>
        {catalog ? (
          <details className="mt-3 text-xs text-[#52514e]">
            <summary className="cursor-pointer">What each role can do</summary>
            <ul className="mt-2 flex flex-col gap-1">
              {catalog.roles.map((r) => (
                <li key={r.name}>
                  <b>{r.name}</b>: {r.description} <span className="font-mono">{r.permissions.join(' ')}</span>
                </li>
              ))}
            </ul>
          </details>
        ) : null}
      </Card>
      {catalog ? <ApiKeysPanel catalog={catalog} ask={ask} /> : null}
    </div>
  )
}
