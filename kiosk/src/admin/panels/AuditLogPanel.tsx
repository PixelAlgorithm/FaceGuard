/**
 * Auth audit log (audit:read, GET /v1/admin/auth/audit, newest first, hash-chained on the edge). The head page
 * is polled; every page ever received is merged by seq (auditPages.ts), so new entries never open a gap between
 * the head and the pages loaded with "Load older".
 */
import { useState } from 'react'
import { getApi } from '../../api'
import type { AuthAuditEntry } from '../../api/authTypes'
import { authErrorText } from '../../shared/auth/authErrorText'
import { useAuth } from '../../shared/auth/context'
import { PERM, needsText } from '../../shared/auth/permissions'
import { mergeAudit, olderCursor } from '../auditPages'
import { fmtWhen } from '../staffUtil'
import { Card } from '../ui'
import { usePoll } from '../usePoll'

const PAGE = 100
const HEAD_POLL_MS = 10_000
const btn = 'rounded-lg px-2.5 py-1 text-xs font-semibold ring-1 ring-black/15 hover:bg-[#f0efec] disabled:opacity-50'

function detailText(d: Record<string, unknown> | null): string {
  if (!d) return ''
  const s = JSON.stringify(d)
  return s.length > 140 ? `${s.slice(0, 137)}…` : s
}

export function AuditLogPanel() {
  const api = getApi()
  const { token, can } = useAuth()
  const allowed = can(PERM.auditRead)
  const [held, setHeld] = useState<AuthAuditEntry[]>([])
  const [firstHeadNext, setFirstHeadNext] = useState<number | null | undefined>(undefined)
  // every head page is merged into `held` as it arrives (the panel is keyed by token, so held never mixes principals)
  const fetchHead = async () => {
    const page = await api.listAuthAudit(token, { limit: PAGE })
    setHeld((h) => mergeAudit(h, page.items))
    setFirstHeadNext((n) => (n === undefined ? page.next_before_seq : n))
    return page
  }
  const head = usePoll(fetchHead, HEAD_POLL_MS, !!token && allowed, `audit:${token}`, authErrorText)
  const [cursor, setCursor] = useState<number | null | undefined>(undefined)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState('')

  if (!allowed) {
    return (
      <Card title="Audit log">
        <p className="text-sm text-[#8a6d00]">{needsText(PERM.auditRead)}</p>
      </Card>
    )
  }
  const next = olderCursor(cursor, firstHeadNext ?? null)
  const rows = held
  const q = filter.trim().toLowerCase()
  const shown = q
    ? rows.filter((e) => `${e.seq} ${e.action} ${e.actor.kind} ${e.actor.id ?? ''} ${e.actor.username ?? ''} ${e.target ?? ''} ${e.outcome} ${e.client_ip ?? ''}`.toLowerCase().includes(q))
    : rows

  const loadOlder = async () => {
    if (next === null || busy) return
    setBusy(true)
    setError(null)
    try {
      const older = await api.listAuthAudit(token, { limit: PAGE, before_seq: next })
      setHeld((h) => mergeAudit(h, older.items))
      setCursor(older.next_before_seq)
    } catch (e) {
      setError(authErrorText(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card
      title="Audit log (sign-ins, staff, keys, denials)"
      actions={
        <span className="flex items-center gap-2">
          <input className="rounded-lg border border-black/20 px-2 py-0.5 text-xs" placeholder="filter" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter audit log" />
          <button type="button" className={btn} onClick={head.refresh}>
            Refresh
          </button>
        </span>
      }
    >
      {head.error ? <p className="mb-2 text-sm text-[#d03b3b]">{head.error}</p> : null}
      <p className="mb-2 text-xs text-[#52514e]" aria-live="polite">
        as of {fmtWhen(head.data?.as_of ?? null)} · {rows.length} entries loaded{q ? ` · ${shown.length} match the filter` : ''}
      </p>
      <div className="max-h-[36rem] overflow-auto rounded border border-black/10">
        <table className="w-full text-left text-xs">
          <thead className="sticky top-0 bg-[#f0efec] text-[#52514e]">
            <tr>
              <th className="px-2 py-1">#</th>
              <th className="px-2 py-1">Time</th>
              <th className="px-2 py-1">Actor</th>
              <th className="px-2 py-1">Action</th>
              <th className="px-2 py-1">Target</th>
              <th className="px-2 py-1">Outcome</th>
              <th className="px-2 py-1">Detail</th>
            </tr>
          </thead>
          <tbody className="font-mono">
            {shown.map((e) => (
              <tr key={e.seq} className="border-t border-[#e1e0d9] align-top">
                <td className="px-2 py-1 text-[#898781]">{e.seq}</td>
                <td className="px-2 py-1 whitespace-nowrap">{fmtWhen(e.ts_utc)}</td>
                <td className="px-2 py-1">
                  {e.actor.kind}:{e.actor.username ?? e.actor.id ?? '–'}
                </td>
                <td className="px-2 py-1">{e.action}</td>
                <td className="px-2 py-1 break-all">{e.target ?? '–'}</td>
                <td className={`px-2 py-1 font-semibold ${e.outcome === 'ok' ? 'text-[#006300]' : 'text-[#8f1d1d]'}`}>
                  {e.outcome}
                  {e.count && e.count > 1 ? ` ×${e.count}` : ''}
                </td>
                <td className="px-2 py-1 break-all text-[#52514e]" title={e.detail ? JSON.stringify(e.detail) : undefined}>
                  {detailText(e.detail)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {head.data && shown.length === 0 ? <p className="p-2 text-xs text-[#898781]">{q ? 'No loaded entry matches the filter.' : 'No audit entries.'}</p> : null}
      </div>
      {error ? <p className="mt-2 text-sm text-[#d03b3b]">{error}</p> : null}
      <div className="mt-2">
        <button type="button" className={btn} disabled={busy || next === null} onClick={() => void loadOlder()}>
          {busy ? 'Loading…' : next === null ? 'No older entries' : 'Load older'}
        </button>
      </div>
    </Card>
  )
}
