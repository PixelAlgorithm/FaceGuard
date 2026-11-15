/** Live decision feed from GET /v1/events (SSE): every reason code, scores, latency, kiosk decision time. */
import { useEffect, useState } from 'react'
import { getApi, type DecisionResponse, type RenderedEvent } from '../../api'
import { DecisionChip } from '../DecisionChip'
import { Card } from '../ui'

interface Row {
  key: string
  at: number
  d: DecisionResponse
  evalCtx: Record<string, unknown> | null
  clientMs: number | null
}

const MAX_ROWS = 100

function pickNum(o: unknown, path: string[]): number | null {
  let cur: unknown = o
  for (const k of path) cur = cur && typeof cur === 'object' ? (cur as Record<string, unknown>)[k] : undefined
  return typeof cur === 'number' && Number.isFinite(cur) ? cur : null
}

/** GET /v1/admin/attempt/{id}/signals: flash amplitude / correlation / lag for this attempt (target amplitude >= 5). */
function SignalsButton({ token, attemptId }: { token: string; attemptId: string }) {
  const [state, setState] = useState<{ busy: boolean; body: unknown; error: string | null; open: boolean }>({
    busy: false,
    body: null,
    error: null,
    open: false,
  })
  const load = async () => {
    setState((s) => ({ ...s, busy: true, error: null }))
    try {
      const body = await getApi().getAttemptSignals(token, attemptId)
      setState({ busy: false, body, error: null, open: true })
    } catch (e) {
      setState({ busy: false, body: null, error: e instanceof Error ? e.message : String(e), open: true })
    }
  }
  const b = state.body
  const amp = pickNum(b, ['signals', 'flash', 'amplitude']) ?? pickNum(b, ['flash', 'amplitude'])
  const r = pickNum(b, ['signals', 'flash', 'r']) ?? pickNum(b, ['signals', 'flash', 'ncc']) ?? pickNum(b, ['flash', 'r'])
  const lag = pickNum(b, ['signals', 'flash', 'lag_frames']) ?? pickNum(b, ['signals', 'flash', 'lag_ms'])
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <button type="button" onClick={load} disabled={state.busy} className="rounded px-1.5 py-0.5 text-[11px] ring-1 ring-black/15">
        {state.busy ? '…' : 'signals'}
      </button>
      {state.open && !state.error ? (
        <span className="font-mono text-[11px]">
          flash amplitude{' '}
          <b style={{ color: amp === null ? '#52514e' : amp >= 5 ? '#006300' : '#d03b3b' }}>{amp === null ? '–' : amp.toFixed(2)}</b>
          {r !== null ? ` · r ${r.toFixed(2)}` : ''}
          {lag !== null ? ` · lag ${lag}` : ''}
        </span>
      ) : null}
      {state.error ? <span className="text-[11px] text-[#d03b3b]">{state.error}</span> : null}
      {state.open && b ? (
        <details className="w-full">
          <summary className="cursor-pointer text-[11px] text-[#52514e]">raw signals</summary>
          <pre className="max-h-48 overflow-auto rounded bg-[#f0efec] p-1 text-[10px]">{JSON.stringify(b, null, 1)}</pre>
        </details>
      ) : null}
    </span>
  )
}

function fmtScore(v: unknown): string {
  if (typeof v === 'number') return Number.isInteger(v) ? String(v) : v.toFixed(v < 2 ? 2 : 1)
  if (v === null || v === undefined) return '–'
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

export function LiveFeed({ token }: { token: string }) {
  const [rows, setRows] = useState<Row[]>([])
  const [status, setStatus] = useState<'connecting' | 'open' | 'error'>('connecting')

  useEffect(() => {
    let seq = 0
    const unsubscribe = getApi().subscribeEvents(token, {
      onStatus: setStatus,
      onDecision: (d, evalCtx) => {
        seq += 1
        const row: Row = { key: `${d.attempt_id}-${seq}-${Date.now()}`, at: Date.now(), d, evalCtx, clientMs: null }
        setRows((rs) => [row, ...rs].slice(0, MAX_ROWS))
      },
      onRendered: (e: RenderedEvent) => {
        const ms =
          typeof e.client_latency_ms === 'number'
            ? e.client_latency_ms
            : typeof e.rendered_at_ms === 'number' && typeof e.face_lock_at_ms === 'number'
              ? e.rendered_at_ms - e.face_lock_at_ms
              : null
        if (ms === null) return
        setRows((rs) => {
          // Attach to the OLDEST row of that attempt (its first decision = the 2 s path).
          const idx = rs.map((r) => r.d.attempt_id).lastIndexOf(e.attempt_id)
          if (idx < 0) return rs
          const next = [...rs]
          next[idx] = { ...next[idx], clientMs: ms }
          return next
        })
      },
    })
    return unsubscribe
  }, [token])

  return (
    <Card
      title="Live decision feed (GET /v1/events)"
      actions={
        <span className="flex items-center gap-3 text-xs">
          <span className={status === 'open' ? 'text-[#006300]' : status === 'error' ? 'text-[#d03b3b]' : 'text-[#898781]'}>
            ● {status === 'open' ? 'live' : status === 'error' ? 'disconnected – retrying' : 'connecting'}
          </span>
          <button type="button" onClick={() => setRows([])} className="rounded px-2 py-0.5 ring-1 ring-black/15">
            Clear
          </button>
        </span>
      }
    >
      {rows.length === 0 ? (
        <p className="text-sm text-[#898781]">Waiting for decisions… (each kiosk attempt appears here instantly)</p>
      ) : (
        <ol className="flex max-h-[34rem] flex-col gap-2 overflow-auto pr-1">
          {rows.map(({ key, at, d, evalCtx, clientMs }) => (
            <li key={key} className="rounded-lg border border-black/10 bg-white p-2 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-[#898781]">{new Date(at).toLocaleTimeString([], { hour12: false })}</span>
                <DecisionChip decision={d.decision} />
                <span className="rounded bg-[#f0efec] px-1.5 py-0.5 font-semibold">{d.mode}</span>
                <span className="text-[#52514e]">
                  {d.kiosk_id || '–'}
                  {d.zone ? ` · ${d.zone}` : ''}
                </span>
                {d.candidate?.display ? <span className="font-semibold">{d.candidate.display}</span> : null}
                <span className="text-[#52514e]">next {d.next_action.type}</span>
                {evalCtx && typeof evalCtx.label === 'string' ? (
                  <span className="rounded bg-[#cde2fb] px-1.5 py-0.5 font-mono">eval {String(evalCtx.label)}</span>
                ) : null}
                <span className="ml-auto font-mono text-[#898781]">{d.attempt_id}</span>
                <SignalsButton token={token} attemptId={d.attempt_id} />
              </div>
              <div className="mt-1 flex flex-wrap gap-1">
                {d.reason_codes.map((c) => (
                  <span key={c} className="rounded bg-[#0b0b0b] px-1.5 py-0.5 font-mono text-[11px] text-white">
                    {c}
                  </span>
                ))}
                {d.resolved_codes.map((c) => (
                  <span key={`r-${c}`} className="rounded bg-[#e1e0d9] px-1.5 py-0.5 font-mono text-[11px] line-through">
                    {c}
                  </span>
                ))}
              </div>
              <div className="mt-1 grid gap-0.5 font-mono text-[11px] text-[#52514e]">
                <span>
                  scores{' '}
                  {Object.entries(d.scores)
                    .map(([k, v]) => `${k}=${fmtScore(v)}`)
                    .join('  ') || '–'}
                </span>
                <span>
                  edge latency{' '}
                  {Object.entries(d.latency_ms)
                    .map(([k, v]) => `${k}=${v}`)
                    .join(' ')}
                  {clientMs !== null ? (
                    <span className="font-bold text-[#0b0b0b]"> · kiosk face-lock→rendered {Math.round(clientMs)} ms</span>
                  ) : null}
                </span>
                <span>
                  stage {d.stage ?? '–'} · {d.bio_result ?? '–'} · schedule {d.schedule_result ?? '–'} · cache{' '}
                  {d.cache_state ?? '–'} · policy {d.policy_version ?? '–'} · bundle {String(d.bundle_version ?? '–')}
                  {d.display_message ? ` · "${d.display_message}"` : ''}
                </span>
              </div>
            </li>
          ))}
        </ol>
      )}
    </Card>
  )
}
