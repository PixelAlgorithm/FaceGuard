/**
 * Fast verdict: PASS (ALLOW, green) / SUSPICIOUS — verification needed (STEP_UP, amber) / DENIED (red),
 * edge decision time (latency_ms.total), name + role on PASS, the six key scores against the policy bars
 * with pass/fail marks, and every reason code with its plain-language meaning.
 */
import { useLayoutEffect } from 'react'
import type { Decision, DecisionResponse } from '../api/types'
import { epochNow } from '../capture/time'
import { AlertIcon, CheckIcon, CrossIcon } from '../kiosk/components/Icons'
import { reasonText } from '../kiosk/reasons'
import type { OperatorAttempt, OperatorTiming } from './attempt'
import type { EdgeUser } from './edgeRaw'
import { rawCandidateRole } from './edgeRaw'
import { CHIP_STYLE, rawSignalLines, signalChips } from './signals'
import {
  VERDICT_STYLE,
  nextActionText,
  otherScores,
  resolveRole,
  scoreRows,
  verdictOf,
  type PolicyBars,
  type ScoreRow,
} from './verdict'

export interface VerdictEntry {
  attemptId: string
  /** 'console' = scanned on this page · 'kiosk' = decision seen on the live feed (GET /v1/events) */
  source: 'console' | 'kiosk'
  decision: DecisionResponse
  /** every decision seen for this attempt, oldest first (e.g. STEP_UP then ALLOW after the challenge) */
  history: Decision[]
  raw: Record<string, unknown> | null
  receivedAt: number
  faceLockAtMs: number | null
  /** face lock -> verdict painted (console: measured here; kiosk: the kiosk's rendered beacon) */
  clientMs: number | null
  forced: boolean
  flash: OperatorAttempt['flash'] | null
  timing: OperatorTiming | null
  bars: PolicyBars
  /** GET /v1/admin/attempt/{id}/signals body (observer view; needs the admin token) */
  signals?: unknown
  signalsError?: string | null
}

const ICON = { PASS: CheckIcon, SUSPICIOUS: AlertIcon, DENIED: CrossIcon } as const

const fmt3 = (v: number | null) => (v === null ? '—' : v.toFixed(3))
const ms = (v: number | null | undefined) => (typeof v === 'number' && Number.isFinite(v) ? `${Math.round(v).toLocaleString()} ms` : '—')

function ScoreTrack({ row }: { row: ScoreRow }) {
  const clamp = (x: number) => Math.max(0, Math.min(1, x))
  const fill = row.value === null ? 0 : clamp(row.value)
  const tone = row.pass === null ? 'bg-white/30' : row.pass ? 'bg-emerald-400' : 'bg-red-400'
  return (
    <div className="relative h-2.5 w-full min-w-24 rounded-full bg-white/10" aria-hidden>
      <div className={`absolute inset-y-0 left-0 rounded-full ${tone}`} style={{ width: `${fill * 100}%` }} />
      <div className="absolute -inset-y-1 w-0.5 bg-white" style={{ left: `calc(${clamp(row.bar) * 100}% - 1px)` }} />
    </div>
  )
}

function SignalChips({ scores }: { scores: Record<string, unknown> }) {
  const chips = signalChips(scores)
  if (!chips) return <p className="text-sm text-white/50">This edge sent no per-signal status (scores.signals).</p>
  return (
    <ul className="flex flex-wrap gap-2" aria-label="Per-signal result">
      {chips.map((c) => {
        const st = CHIP_STYLE[c.verdict]
        return (
          <li
            key={c.key}
            title={`${c.key}: ${c.status}`}
            className={`flex flex-col rounded-lg px-2.5 py-1 leading-tight ${c.advisory ? 'bg-white/5 ring-1 ring-white/25' : st.cls}`}
          >
            <span className={`text-[11px] font-semibold ${c.advisory ? 'text-white/60' : 'opacity-80'}`}>{c.label}</span>
            <span className="text-sm font-black tracking-wide">
              {c.advisory ? <span className="text-white/85">{st.text}</span> : st.text}
              {c.ambient ? <span className="ml-1 text-[11px] font-bold opacity-80">ambient</span> : null}
              {c.advisory ? <span className="ml-1 text-[11px] font-semibold text-white/55">advisory · no effect</span> : null}
            </span>
          </li>
        )
      })}
    </ul>
  )
}

function RawSignals({ entry }: { entry: VerdictEntry }) {
  const lines = rawSignalLines(entry.signals)
  if (!lines.length && !entry.signalsError) return null
  return (
    <details className="rounded-lg bg-white/5 px-3 py-2 text-sm">
      <summary className="cursor-pointer text-xs font-semibold tracking-wide text-white/60 uppercase">
        Raw signals (GET /v1/admin/attempt/…/signals)
      </summary>
      {entry.signalsError ? <p className="mt-1 text-xs text-amber-200">{entry.signalsError}</p> : null}
      <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5">
        {lines.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-white/50">{k}</dt>
            <dd className="font-mono text-xs break-all">{v}</dd>
          </div>
        ))}
      </dl>
    </details>
  )
}

function ScoreTable({ rows, bars }: { rows: ScoreRow[]; bars: PolicyBars }) {
  return (
    <div>
      <table className="w-full border-collapse text-left">
        <caption className="mb-1 text-left text-xs text-white/60">
          Bars: {bars.source === 'edge' ? `GET /v1/mode policy_bars${bars.mode ? ` (${bars.mode})` : ''}` : 'config/thresholds.yaml (edge sent no policy_bars)'}. White
          tick = bar. The chips above are the edge&apos;s own per-signal verdicts.
        </caption>
        <thead>
          <tr className="text-xs tracking-wide text-white/50 uppercase">
            <th className="py-1 pr-2 font-semibold">Signal</th>
            <th className="py-1 pr-2 font-semibold">Value</th>
            <th className="w-[32%] py-1 pr-2 font-semibold">vs bar</th>
            <th className="py-1 font-semibold">Result</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.key} className="border-t border-white/10">
              <td className="py-1.5 pr-2">
                <span className="block text-sm font-semibold">{r.label}</span>
                <span className="font-mono text-[11px] text-white/45">{r.key}</span>
              </td>
              <td className="py-1.5 pr-2 font-mono text-base tabular-nums">{fmt3(r.value)}</td>
              <td className="py-1.5 pr-2">
                <ScoreTrack row={r} />
                <span className="mt-1 block font-mono text-[11px] text-white/55">
                  {r.rule === 'min' ? '≥' : '<'} {r.bar.toFixed(2)}
                </span>
              </td>
              <td className="py-1.5 text-sm font-bold whitespace-nowrap">
                {r.pass === null ? (
                  <span className="text-white/45">not measured</span>
                ) : r.pass ? (
                  <span className="text-emerald-300">✓ pass</span>
                ) : (
                  <span className="text-red-300">✗ fail</span>
                )}
                {r.advisory ? <span className="block text-[11px] font-normal text-white/50">advisory (no effect)</span> : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function VerdictPanel({
  entry,
  users,
  onPainted,
}: {
  entry: VerdictEntry
  users: EdgeUser[] | null
  /** called once the verdict is on screen (two rAFs after commit) -> POST /rendered for console attempts */
  onPainted: (attemptId: string, renderedAtMs: number) => void
}) {
  const d = entry.decision
  const verdict = verdictOf(d.decision)
  const style = VERDICT_STYLE[verdict]
  const Icon = ICON[verdict]
  const role = resolveRole(d.candidate?.user_id ?? null, d.candidate?.role || rawCandidateRole(entry.raw), users)
  const rows = scoreRows(d.scores, entry.bars)
  const extra = otherScores(d.scores)
  const needsBeacon = entry.source === 'console' && !entry.forced && entry.clientMs === null

  useLayoutEffect(() => {
    if (!needsBeacon) return
    let inner = 0
    const outer = requestAnimationFrame(() => {
      inner = requestAnimationFrame(() => onPainted(entry.attemptId, epochNow()))
    })
    return () => {
      cancelAnimationFrame(outer)
      cancelAnimationFrame(inner)
    }
  }, [needsBeacon, entry.attemptId, onPainted])

  const latencyStages = Object.entries(d.latency_ms).filter(
    (e): e is [string, number] => e[0] !== 'total' && typeof e[1] === 'number' && Number.isFinite(e[1]),
  )

  return (
    <section
      aria-live="polite"
      aria-label={`Verdict ${style.title}${style.tail ? ` ${style.tail}` : ''}`}
      className="overflow-hidden rounded-2xl ring-1 ring-white/15"
    >
      <div className={`${style.cls} px-5 py-4`}>
        <div className="flex flex-wrap items-center gap-4">
          <Icon className="h-14 w-14 shrink-0" />
          <div className="min-w-0">
            <p className="text-[clamp(1.8rem,4.2vw,3.6rem)] leading-none font-black tracking-tight">
              {style.title}
              {style.tail ? ' ' : null}
              {style.tail ? <span className="text-[0.5em] font-extrabold tracking-normal whitespace-nowrap">{style.tail}</span> : null}
            </p>
            <p className="mt-1 text-base font-semibold opacity-85">{style.sub}</p>
          </div>
          <div className="ml-auto text-right">
            <p className="text-[clamp(1.6rem,3vw,2.6rem)] leading-none font-black tabular-nums">{ms(d.latency_ms.total)}</p>
            <p className="text-xs font-semibold opacity-80">edge decision time (latency_ms.total)</p>
            {entry.clientMs !== null ? (
              <p className="mt-1 text-sm font-bold tabular-nums">face lock → on screen {ms(entry.clientMs)}</p>
            ) : null}
          </div>
        </div>
        {d.candidate ? (
          <p className={`mt-3 flex flex-wrap items-baseline gap-x-3 ${verdict === 'PASS' ? 'text-[clamp(1.4rem,2.6vw,2.2rem)] font-bold' : 'text-lg font-semibold'}`}>
            <span>{verdict === 'PASS' ? '' : 'Recognised: '}{d.candidate.display || d.candidate.user_id}</span>
            {role.role ? (
              <span className="rounded-lg bg-black/25 px-2 py-0.5 text-[0.7em] font-bold tracking-wide uppercase">{role.role}</span>
            ) : null}
            <span className="font-mono text-sm font-normal opacity-75">{d.candidate.user_id}</span>
            {role.source && role.source !== 'edge response' ? (
              <span className="text-xs font-normal opacity-70">(role from {role.source})</span>
            ) : null}
          </p>
        ) : (
          <p className="mt-2 text-base font-semibold opacity-85">No identity shown{d.bio_result === 'BIO_FAIL' ? ' (biometric fail)' : ''}</p>
        )}
        {entry.history.length > 1 ? (
          <p className="mt-1 text-sm font-semibold opacity-85">Sequence: {entry.history.map((h) => (h === 'STEP_UP' ? 'REQUEST VERIFICATION' : h)).join(' → ')}</p>
        ) : null}
      </div>

      <div className="flex flex-col gap-2 bg-zinc-950 px-4 pt-4">
        <h3 className="text-xs font-semibold tracking-wide text-white/50 uppercase">Signals</h3>
        <SignalChips scores={d.scores} />
        <RawSignals entry={entry} />
      </div>
      <div className="grid gap-4 bg-zinc-950 p-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <ScoreTable rows={rows} bars={entry.bars} />
        <div className="flex flex-col gap-3">
          <div>
            <h3 className="text-xs font-semibold tracking-wide text-white/50 uppercase">Reason codes</h3>
            {d.reason_codes.length ? (
              <ul className="mt-1 flex flex-col gap-1.5">
                {d.reason_codes.map((c) => (
                  <li key={c} className="rounded-lg bg-white/5 px-2 py-1.5">
                    <span className="font-mono text-sm font-bold">{c}</span>
                    <span className="block text-sm text-white/75">{reasonText(c, d.decision)}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-white/50">none</p>
            )}
            {d.resolved_codes.length ? (
              <p className="mt-1 text-xs text-white/55">resolved: {d.resolved_codes.join(', ')}</p>
            ) : null}
          </div>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-sm">
            <dt className="text-white/50">next</dt>
            <dd>{nextActionText(d)}</dd>
            <dt className="text-white/50">kiosk · zone</dt>
            <dd>
              {d.kiosk_id || '—'} · {d.zone ?? '—'}
            </dd>
            <dt className="text-white/50">mode</dt>
            <dd>
              {d.mode}
              {d.cache_state ? ` · cache ${d.cache_state}` : ''}
            </dd>
            <dt className="text-white/50">bio · schedule</dt>
            <dd>
              {d.bio_result ?? '—'} · {d.schedule_result ?? '—'}
            </dd>
            <dt className="text-white/50">source</dt>
            <dd>
              {entry.source === 'console' ? `this console${entry.forced ? ' (forced scan, no face lock)' : ''}` : 'kiosk (live feed)'}
              {entry.flash ? ` · flash ${entry.flash}` : ''}
            </dd>
            <dt className="text-white/50">attempt</dt>
            <dd className="font-mono text-xs">
              <span className="break-all">{entry.attemptId}</span>{' '}
              <span className="whitespace-nowrap">· {new Date(entry.receivedAt).toLocaleTimeString([], { hour12: false })}</span>
            </dd>
            {latencyStages.length ? (
              <>
                <dt className="text-white/50">edge stages</dt>
                <dd className="font-mono text-xs">{latencyStages.map(([k, v]) => `${k} ${Math.round(v)}`).join(' · ')}</dd>
              </>
            ) : null}
            {entry.timing ? (
              <>
                <dt className="text-white/50">client</dt>
                <dd className="font-mono text-xs">
                  session {entry.timing.sessionStartMs} · capture {entry.timing.captureWindowMs} · encode {entry.timing.encodeMs} · upload+edge{' '}
                  {entry.timing.uploadAndEdgeMs}
                </dd>
              </>
            ) : null}
            {extra.length ? (
              <>
                <dt className="text-white/50">other scores</dt>
                <dd className="font-mono text-xs">{extra.map(([k, v]) => `${k} ${v.toFixed(3)}`).join(' · ')}</dd>
              </>
            ) : null}
          </dl>
        </div>
      </div>
    </section>
  )
}

export function VerdictChip({ decision }: { decision: Decision }) {
  const s = VERDICT_STYLE[verdictOf(decision)]
  return <span className={`inline-flex rounded-md px-2 py-0.5 text-xs font-bold whitespace-nowrap ${s.chip}`}>{s.title}</span>
}
