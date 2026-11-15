/** Full-screen ALLOW (green) / REQUEST VERIFICATION (amber, API STEP_UP) / DENY (red) with reason + measured time. */
import { useLayoutEffect } from 'react'
import { THRESHOLDS } from '../../config'
import { epochNow } from '../../capture/time'
import { useModeStatus } from '../../shared/modeStore'
import type { DecisionViewModel } from '../controller'
import { AlertIcon, CheckIcon, CrossIcon } from '../components/Icons'
import { reasonText } from '../reasons'

const TONE = {
  allow: { bg: 'bg-allow', ink: 'text-allow-ink', sub: 'text-white/90', chip: 'bg-black/25', Icon: CheckIcon },
  stepup: { bg: 'bg-stepup', ink: 'text-stepup-ink', sub: 'text-black/80', chip: 'bg-black/10', Icon: AlertIcon },
  deny: { bg: 'bg-deny', ink: 'text-deny-ink', sub: 'text-white/90', chip: 'bg-black/25', Icon: CrossIcon },
} as const

function fmtSeconds(ms: number): string {
  return `${(ms / 1000).toFixed(2)} s`
}

export function DecisionScreen({
  vm,
  onContinue,
  onRendered,
}: {
  vm: DecisionViewModel
  onContinue: () => void
  onRendered: (shownAt: number, renderedAtMs: number) => void
}) {
  const { response: r, copy, timing } = vm
  const { shownAt } = vm

  // rendered_at = first animation frame AFTER the frame that painted this screen (double rAF).
  useLayoutEffect(() => {
    let inner = 0
    const outer = requestAnimationFrame(() => {
      inner = requestAnimationFrame(() => onRendered(shownAt, epochNow()))
    })
    return () => {
      cancelAnimationFrame(outer)
      cancelAnimationFrame(inner)
    }
  }, [shownAt, onRendered])
  // Connectivity ONLINE but this attempt was decided locally (cloud match missed its budget, P7): say so
  // instead of the confusing "Offline decision" while the badge shows ONLINE.
  const { mode: badge } = useModeStatus()
  const cloudSlow = r.mode === 'OFFLINE' && badge?.mode === 'ONLINE' && badge.state === 'ONLINE'
  const t = TONE[copy.tone]
  const showDetail = THRESHOLDS.ui.showDetailedReasons
  // Prefer the edge's display_message when it adds information beyond the mapped reason text.
  const dm = r.display_message?.trim() ?? ''
  const same = (a: string, b: string) => a.toLowerCase().includes(b.toLowerCase()) || b.toLowerCase().includes(a.toLowerCase())
  const message = dm && !copy.generic && !same(dm, copy.reason) && !same(dm, copy.headline) ? dm : null
  const baseDetail = cloudSlow && copy.tone === 'allow' ? 'Cloud slow – decided locally on this kiosk · will sync' : copy.detail
  const detail = baseDetail && !(message && same(message, baseDetail)) ? baseDetail : null
  return (
    <section
      role="alert"
      aria-live="assertive"
      className={`absolute inset-0 z-50 flex flex-col items-center justify-center ${t.bg} ${t.ink} px-[5vw] text-center`}
    >
      <t.Icon className="settle-in h-[14vh] w-[14vh]" title={copy.label} />
      <h1 className="mt-[1.4vh] text-[clamp(40px,9.5vh,124px)] leading-none font-black tracking-tight">{copy.label}</h1>
      {copy.subtitle ? (
        <p className={`mt-[0.6vh] text-[clamp(18px,3.2vh,38px)] font-bold tracking-widest uppercase ${t.sub}`}>{copy.subtitle}</p>
      ) : null}
      <p className="mt-[1.6vh] text-[clamp(26px,5vh,60px)] leading-tight font-extrabold">
        {copy.welcome ?? copy.headline}
      </p>
      <p className="mt-[2vh] max-w-[85vw] text-[clamp(24px,4.6vh,54px)] leading-tight font-semibold">{copy.reason}</p>
      {message ? <p className={`mt-[1.2vh] text-[clamp(18px,3vh,36px)] ${t.sub}`}>{message}</p> : null}
      {detail ? <p className={`mt-[1.2vh] text-[clamp(18px,3.2vh,38px)] font-semibold ${t.sub}`}>{detail}</p> : null}
      {copy.nextHint ? (
        <p className={`mt-[2.4vh] text-[clamp(20px,3.6vh,42px)] font-bold ${t.sub}`}>{copy.nextHint}</p>
      ) : null}

      {timing.baseAtMs !== null || timing.serverMs !== null ? (
        <p className={`mt-[3vh] text-[clamp(16px,2.6vh,30px)] tabular-nums ${t.sub}`}>
          {timing.label}{' '}
          <span className="font-bold">{timing.clientMs !== null ? fmtSeconds(timing.clientMs) : '…'}</span>
          {timing.clientMs !== null ? ` (${Math.round(timing.clientMs)} ms)` : ''}
          {timing.serverMs !== null ? ` · edge ${Math.round(timing.serverMs)} ms` : ''}
        </p>
      ) : null}

      {vm.canContinue ? (
        <button
          type="button"
          onClick={onContinue}
          className="mt-[2.4vh] min-h-14 rounded-2xl bg-black/85 px-10 py-3 text-[clamp(20px,3.2vh,38px)] font-bold text-white"
        >
          Continue
        </button>
      ) : null}

      {showDetail ? (
        <div className={`absolute inset-x-[3vw] bottom-[2.4vh] rounded-xl ${t.chip} px-4 py-2 text-left text-[clamp(11px,1.5vh,17px)]`}>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-bold uppercase opacity-80">Operator detail</span>
            {r.reason_codes.map((c) => (
              <span key={c} title={reasonText(c, r.decision)} className="rounded bg-black/30 px-2 py-0.5 font-mono font-semibold text-white">
                {c}
              </span>
            ))}
            {r.resolved_codes.length ? <span className="opacity-80">resolved:</span> : null}
            {r.resolved_codes.map((c) => (
              <span key={`res-${c}`} className="rounded bg-black/15 px-2 py-0.5 font-mono line-through decoration-2">
                {c}
              </span>
            ))}
          </div>
          <div className="mt-1 font-mono opacity-85">
            {r.mode} · stage {r.stage ?? '–'} · {r.bio_result ?? '–'} · schedule {r.schedule_result ?? '–'} · next{' '}
            {r.next_action.type}
            {r.next_action.steps.length ? ` [${r.next_action.steps.join(' → ')}]` : ''} · {r.attempt_id}
          </div>
          <div className="mt-0.5 font-mono opacity-85">
            edge latency {Object.entries(r.latency_ms).map(([k, v]) => `${k}=${v}`).join(' ')}
            {timing.breakdown
              ? ` · from face lock: session +${timing.breakdown.sessionReadyMs}${timing.breakdown.sessionPrefetched ? ' (prefetched)' : ''}` +
                ` · colour0 +${timing.breakdown.firstColourMs} · frames +${timing.breakdown.framesReadyMs}` +
                ` · decision +${timing.breakdown.responseMs} (upload+edge ${timing.breakdown.uploadAndEdgeMs})` +
                (timing.breakdown.probe ? ` · probe ${timing.breakdown.probe}` : '')
              : ''}
          </div>
        </div>
      ) : null}

      {vm.autoAdvanceMs ? (
        <div className="absolute inset-x-0 bottom-0 h-[1.2vh] bg-black/15">
          <div
            key={vm.shownAt}
            className="countdown-bar h-full bg-black/45"
            style={{ animationDuration: `${vm.autoAdvanceMs}ms` }}
          />
        </div>
      ) : null}
    </section>
  )
}
