/**
 * GET /v1/metrics -> KPI tiles, decision split (tall segmented bar), reason codes (ranked bars, one hue),
 * decision-time meter vs the 2 s budget, per-label APCER/BPCER table with the edge's 95 % upper bounds.
 * Charts follow the dataviz skill: status colours only for decision state (with icon + label), one hue for
 * ranked magnitudes, text in ink tokens, thin marks, values labelled at the bar tip, table views present.
 */
import type { ReactNode } from 'react'
import type { Decision, LabelStat, LatencyStat, MetricsResponse } from '../../api/types'
import { THRESHOLDS } from '../../config'
import { STATUS } from '../decisionStatus'
import { fmtMs, fmtPct } from '../format'
import { Card } from '../ui'

const INK = { primary: '#0b0b0b', secondary: '#52514e', muted: '#898781', grid: '#e1e0d9', series: '#2a78d6' }
const DECISIONS: Decision[] = ['ALLOW', 'STEP_UP', 'DENY']

function Tile({ label, value, sub, mark }: { label: string; value: string; sub?: string; mark?: ReactNode }) {
  return (
    <div className="rounded-lg border border-black/10 bg-white px-3 py-2">
      <div className="flex items-center gap-1.5 text-xs text-[#52514e]">
        {mark}
        {label}
      </div>
      <div className="text-2xl font-semibold text-[#0b0b0b]">{value}</div>
      {sub ? <div className="text-xs text-[#898781]">{sub}</div> : null}
    </div>
  )
}

function DecisionSplit({ counts }: { counts: Record<Decision, number> }) {
  const total = DECISIONS.reduce((a, d) => a + counts[d], 0)
  if (total === 0) return <p className="text-sm text-[#898781]">No decisions yet.</p>
  return (
    <div>
      <div className="flex h-7 w-full gap-[2px]" role="img" aria-label={DECISIONS.map((d) => `${STATUS[d].label} ${counts[d]}`).join(', ')}>
        {DECISIONS.filter((d) => counts[d] > 0).map((d) => {
          const share = counts[d] / total
          return (
            <div
              key={d}
              title={`${STATUS[d].label}: ${counts[d]} (${(share * 100).toFixed(0)} %)`}
              className="flex h-full items-center overflow-visible rounded-[4px] px-1.5 text-xs font-semibold"
              style={{ width: `${share * 100}%`, background: STATUS[d].fill, color: STATUS[d].ink }}
            >
              {share >= 0.12 ? `${(share * 100).toFixed(0)}%` : ''}
            </div>
          )
        })}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-[#52514e]">
        {DECISIONS.map((d) => {
          const S = STATUS[d]
          return (
            <span key={d} className="inline-flex items-center gap-1">
              <span className="inline-flex h-3.5 w-3.5 items-center justify-center rounded-sm" style={{ background: S.fill, color: S.ink }}>
                <S.Icon className="h-3 w-3" />
              </span>
              {S.label}
              {S.sub ? ` (${S.sub})` : ''} <span className="font-semibold text-[#0b0b0b] tabular-nums">{counts[d]}</span>
            </span>
          )
        })}
      </div>
    </div>
  )
}

function ReasonBars({ reasons }: { reasons: Record<string, number> }) {
  const rows = Object.entries(reasons).sort((a, b) => b[1] - a[1])
  if (rows.length === 0) return <p className="text-sm text-[#898781]">No reason codes yet.</p>
  const top = rows.slice(0, 12)
  const rest = rows.slice(12).reduce((a, [, n]) => a + n, 0)
  if (rest > 0) top.push(['Other', rest])
  const max = Math.max(...top.map(([, n]) => n))
  return (
    <div className="flex flex-col gap-1.5" role="list">
      {top.map(([code, n]) => (
        <div key={code} role="listitem" className="grid grid-cols-[13rem_1fr] items-center gap-2" title={`${code}: ${n}`}>
          <span className="truncate font-mono text-xs text-[#52514e]">{code}</span>
          <span className="flex items-center gap-1.5">
            <span className="h-4 rounded-r-[4px]" style={{ width: `${Math.max(2, (n / max) * 85)}%`, background: INK.series }} />
            <span className="text-xs font-semibold text-[#0b0b0b] tabular-nums">{n}</span>
          </span>
        </div>
      ))}
    </div>
  )
}

function LatencyMeter({ stat, budget }: { stat: LatencyStat | undefined; budget: number }) {
  const p95 = stat?.p95 ?? null
  if (p95 === null || p95 === undefined) return <p className="text-sm text-[#898781]">No kiosk-measured decisions yet.</p>
  const ok = p95 <= budget
  const scaleMax = Math.max(budget * 1.25, p95)
  const status = ok ? { fill: '#0ca30c', label: 'within budget' } : { fill: '#d03b3b', label: 'over budget' }
  return (
    <div>
      <div className="relative h-3 w-full rounded-full bg-[#cde2fb]" role="img" aria-label={`p95 ${Math.round(p95)} ms of ${budget} ms budget, ${status.label}`}>
        <div className="h-3 rounded-full" style={{ width: `${(p95 / scaleMax) * 100}%`, background: status.fill }} />
        <div className="absolute top-[-4px] h-5 w-[2px] bg-[#0b0b0b]" style={{ left: `${(budget / scaleMax) * 100}%` }} title={`budget ${budget} ms`} />
      </div>
      <p className="mt-1 text-xs text-[#52514e]">
        p95 <span className="font-semibold text-[#0b0b0b]">{fmtMs(p95)}</span> vs {budget.toLocaleString()} ms budget ·{' '}
        <span style={{ color: ok ? '#006300' : '#d03b3b' }} className="font-semibold">
          {ok ? '✓' : '✕'} {status.label}
        </span>{' '}
        · n = {stat?.n ?? 0}
      </p>
    </div>
  )
}

function LabelTable({ byLabel }: { byLabel: Record<string, LabelStat> }) {
  const rows = Object.entries(byLabel)
  if (rows.length === 0) return <p className="text-sm text-[#898781]">No labelled attempts (set an eval context).</p>
  return (
    <table className="w-full text-left text-xs">
      <thead className="text-[#52514e]">
        <tr className="border-b border-[#c3c2b7]">
          <th className="py-1 font-semibold">label</th>
          <th className="py-1 text-right font-semibold">n</th>
          <th className="py-1 text-right font-semibold">errors</th>
          <th className="py-1 text-right font-semibold">metric</th>
          <th className="py-1 text-right font-semibold">rate</th>
          <th className="py-1 text-right font-semibold">95 % upper</th>
        </tr>
      </thead>
      <tbody className="tabular-nums">
        {rows.map(([label, s]) => {
          const bona = label === 'bona_fide'
          const errors = bona ? s.rejected : s.accepted
          return (
            <tr key={label} className="border-b border-[#e1e0d9] last:border-0">
              <td className="py-1 font-mono">{label}</td>
              <td className="py-1 text-right">{s.n ?? '–'}</td>
              <td className="py-1 text-right" title={bona ? 'bona fide rejected (DENY)' : 'attack accepted (ALLOW)'}>
                {errors ?? '–'}
              </td>
              <td className="py-1 text-right">{bona ? 'BPCER' : 'APCER'}</td>
              <td className="py-1 text-right font-semibold">{fmtPct(bona ? s.bpcer : s.apcer)}</td>
              <td className="py-1 text-right">{fmtPct(bona ? s.bpcer_upper_95 : s.apcer_upper_95)}</td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

export function MetricsPanel({ metrics, error }: { metrics: MetricsResponse | null; error: string | null }) {
  const m = metrics ?? {}
  const decisions = m.decisions ?? {}
  const counts: Record<Decision, number> = {
    ALLOW: decisions.ALLOW ?? 0,
    STEP_UP: decisions.STEP_UP ?? 0,
    DENY: decisions.DENY ?? 0,
  }
  const lat = m.latency_ms ?? {}
  const client = lat.client ?? lat.face_lock_to_decision
  const budget = THRESHOLDS.latency.totalDecisionMs
  const note = typeof m.note === 'string' ? m.note : null
  return (
    <Card
      title="Metrics (GET /v1/metrics)"
      actions={error ? <span className="text-xs text-[#d03b3b]">metrics error: {error}</span> : null}
    >
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4 xl:grid-cols-7">
        <Tile label="Attempts" value={String(m.attempts ?? 0)} sub="final decision per attempt" />
        {DECISIONS.map((d) => {
          const S = STATUS[d]
          return (
            <Tile
              key={d}
              label={S.sub ? `${S.label} (${S.sub})` : S.label}
              value={String(counts[d])}
              mark={<span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: S.fill }} />}
            />
          )
        })}
        <Tile label="Decision time p50 (kiosk)" value={fmtMs(client?.p50)} sub={`p95 ${fmtMs(client?.p95)} · n=${client?.n ?? 0}`} />
        <Tile label="Edge total p50" value={fmtMs(lat.total?.p50)} sub={`p95 ${fmtMs(lat.total?.p95)}`} />
        <Tile
          label="Online / offline"
          value={`${m.by_mode?.ONLINE ?? 0} / ${m.by_mode?.OFFLINE ?? 0}`}
          sub={`sync queue ${m.sync?.queue_depth ?? '–'}`}
        />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div>
          <h3 className="mb-1.5 text-xs font-semibold text-[#52514e]">Decision split</h3>
          <DecisionSplit counts={counts} />
          <h3 className="mt-4 mb-1.5 text-xs font-semibold text-[#52514e]">
            Face lock → decision rendered (kiosk-measured) vs {budget} ms
          </h3>
          <LatencyMeter stat={client} budget={budget} />
          <h3 className="mt-4 mb-1.5 text-xs font-semibold text-[#52514e]">Latency by stage (ms)</h3>
          <table className="w-full text-left text-xs tabular-nums">
            <thead className="text-[#52514e]">
              <tr className="border-b border-[#c3c2b7]">
                <th className="py-1 font-semibold">stage</th>
                <th className="py-1 text-right font-semibold">p50</th>
                <th className="py-1 text-right font-semibold">p95</th>
                <th className="py-1 text-right font-semibold">n</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(lat).map(([k, v]) => (
                <tr key={k} className="border-b border-[#e1e0d9] last:border-0">
                  <td className="py-1 font-mono">{k}</td>
                  <td className="py-1 text-right">{fmtMs(v?.p50)}</td>
                  <td className="py-1 text-right">{fmtMs(v?.p95)}</td>
                  <td className="py-1 text-right">{v?.n ?? '–'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div>
          <h3 className="mb-1.5 text-xs font-semibold text-[#52514e]">Reason codes (final decisions)</h3>
          <ReasonBars reasons={m.reason_codes ?? {}} />
          <h3 className="mt-4 mb-1.5 text-xs font-semibold text-[#52514e]">ISO/IEC 30107-3 by label</h3>
          <LabelTable byLabel={m.by_label ?? {}} />
          <p className="mt-1 text-[11px] text-[#898781]">
            Upper bounds as computed by the edge (rule of 3 for zero errors). Live counts – the official numbers come from eval/.
          </p>
        </div>
      </div>
      {note ? <p className="mt-3 text-[11px] text-[#898781]">{note}</p> : null}
    </Card>
  )
}
