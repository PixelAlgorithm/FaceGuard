/**
 * API keys for automation (staff:manage; design v2 §B): 1..3 roles (never admin), expiry 1..90 days, the key
 * is shown ONCE. Keys can never hold KEY_FORBIDDEN_PERMISSIONS (edge: effective = roles - forbidden).
 */
import { useState, type FormEvent } from 'react'
import { getApi } from '../../api'
import { AUTH_LIMITS, type RolesCatalog } from '../../api/authTypes'
import { authErrorText } from '../../shared/auth/authErrorText'
import { useAuth } from '../../shared/auth/context'
import { PERM } from '../../shared/auth/permissions'
import { toast } from '../../shared/toast'
import { RolePicker, ShownOnce } from '../staffShared'
import { fmtWhen } from '../staffUtil'
import { Card } from '../ui'
import { usePoll } from '../usePoll'

const KEYS_POLL_MS = 30_000
const field = 'rounded-lg border border-black/20 bg-white px-2 py-1 text-sm'
const btn = 'rounded-lg px-2.5 py-1 text-xs font-semibold ring-1 ring-black/15 hover:bg-[#f0efec] disabled:opacity-50'

export function ApiKeysPanel({ catalog, ask }: { catalog: RolesCatalog; ask: (a: string) => Promise<string | null> }) {
  const api = getApi()
  const { token, can } = useAuth()
  const keys = usePoll(() => api.listApiKeys(token), KEYS_POLL_MS, !!token && can(PERM.staffManage), `keys:${token}`, authErrorText)
  const keyRoles = catalog.roles.filter((r) => r.key_allowed)
  const [name, setName] = useState('')
  const [roles, setRoles] = useState<string[]>([])
  const [days, setDays] = useState<number>(AUTH_LIMITS.keyExpiresDaysDefault)
  const [busy, setBusy] = useState(false)
  const [shown, setShown] = useState<{ key: string; name: string } | null>(null)
  const [revoking, setRevoking] = useState<string | null>(null)
  const daysOk = Number.isInteger(days) && days >= AUTH_LIMITS.keyExpiresDaysMin && days <= AUTH_LIMITS.keyExpiresDaysMax
  const ok = !!name.trim() && name.length <= AUTH_LIMITS.keyNameMax && roles.length > 0 && daysOk

  const create = async (e: FormEvent) => {
    e.preventDefault()
    if (!ok || busy) return
    const confirm = await ask(`Create API key "${name.trim()}" (${roles.join(', ')}, ${days} days).`)
    if (!confirm) return
    setBusy(true)
    try {
      const r = await api.createApiKey(token, { name: name.trim(), roles, expires_days: days, confirm_password: confirm })
      setShown({ key: r.key, name: r.item.name })
      toast.success(`API key ${r.item.key_id} created`)
      setName('')
      setRoles([])
      keys.refresh()
    } catch (err) {
      toast.error(`Create key failed: ${authErrorText(err)}`)
    } finally {
      setBusy(false)
    }
  }

  const revoke = async (keyId: string, keyName: string) => {
    if (revoking) return
    const confirm = await ask(`Revoke API key ${keyId} ("${keyName}"). Automation using it stops at once.`)
    if (!confirm) return
    setRevoking(keyId)
    try {
      await api.revokeApiKey(token, keyId, { confirm_password: confirm })
      toast.success(`Revoked ${keyId}`)
      keys.refresh()
    } catch (err) {
      toast.error(`Revoke failed: ${authErrorText(err)}`)
    } finally {
      setRevoking(null)
    }
  }

  return (
    <Card title="API keys (automation)">
      <p className="mb-2 text-xs text-[#52514e]">
        For eval capture, bench and ops scripts (Authorization: Bearer fgk_…). Keys never get: {catalog.key_forbidden_permissions.join(', ') || '–'}.
      </p>
      {shown ? (
        <ShownOnce key={shown.key} label={`API key "${shown.name}"`} secret={shown.key} note="Put it in the tool's environment (e.g. FG_EVAL_API_KEY); it cannot be shown again." onHide={() => setShown(null)} />
      ) : null}
      <form onSubmit={create} className="mt-2 flex flex-col gap-2 rounded-lg bg-[#f0efec] p-3">
        <div className="flex flex-wrap gap-2">
          <label className="flex flex-col text-xs text-[#52514e]">
            Name
            <input className={field} value={name} maxLength={AUTH_LIMITS.keyNameMax} onChange={(e) => setName(e.target.value)} autoComplete="off" />
          </label>
          <label className="flex flex-col text-xs text-[#52514e]">
            Expires after (days, {AUTH_LIMITS.keyExpiresDaysMin}–{AUTH_LIMITS.keyExpiresDaysMax})
            <input
              type="number"
              className={`${field} w-28 ${daysOk ? '' : 'border-[#d03b3b]'}`}
              min={AUTH_LIMITS.keyExpiresDaysMin}
              max={AUTH_LIMITS.keyExpiresDaysMax}
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
            />
          </label>
        </div>
        <RolePicker roles={keyRoles} value={roles} onChange={setRoles} max={catalog.max_roles_per_account} idPrefix="new-key" />
        <div>
          <button type="submit" disabled={!ok || busy} className="rounded-lg bg-[#2a78d6] px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-50">
            {busy ? 'Creating…' : 'Create key'}
          </button>
        </div>
      </form>
      {keys.error ? <p className="mt-2 text-sm text-[#d03b3b]">{keys.error}</p> : null}
      <div className="mt-3 overflow-auto rounded border border-black/10">
        <table className="w-full text-left text-xs">
          <thead className="bg-[#f0efec] text-[#52514e]">
            <tr>
              <th className="px-2 py-1">Key</th>
              <th className="px-2 py-1">Roles</th>
              <th className="px-2 py-1">Status</th>
              <th className="px-2 py-1">Expires</th>
              <th className="px-2 py-1">Last used</th>
              <th className="px-2 py-1">Created by</th>
              <th className="px-2 py-1" />
            </tr>
          </thead>
          <tbody>
            {(keys.data ?? []).map((k) => (
              <tr key={k.key_id} className="border-t border-[#e1e0d9]">
                <td className="px-2 py-1">
                  <span className="font-semibold">{k.name}</span>
                  <span className="block font-mono text-[#52514e]">{k.key_id}</span>
                </td>
                <td className="px-2 py-1">{k.roles.join(', ')}</td>
                <td className={`px-2 py-1 font-semibold ${k.status === 'active' ? 'text-[#006300]' : 'text-[#8f1d1d]'}`}>{k.status}</td>
                <td className="px-2 py-1">{fmtWhen(k.expires_at)}</td>
                <td className="px-2 py-1">{fmtWhen(k.last_used_at)}</td>
                <td className="px-2 py-1 font-mono">{k.created_by ?? '–'}</td>
                <td className="px-2 py-1">
                  {k.status === 'active' ? (
                    <button type="button" className={btn} disabled={revoking !== null} onClick={() => void revoke(k.key_id, k.name)}>
                      {revoking === k.key_id ? 'Revoking…' : 'Revoke'}
                    </button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {keys.data && keys.data.length === 0 ? <p className="p-2 text-xs text-[#898781]">No API keys.</p> : null}
      </div>
    </Card>
  )
}
