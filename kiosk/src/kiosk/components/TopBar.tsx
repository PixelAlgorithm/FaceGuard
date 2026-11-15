import { useSyncExternalStore } from 'react'
import { MOCK_ENABLED, getEvalContextLocal } from '../../config'
import { ModeBadge } from '../../shared/ModeBadge'
import { useModeStatus } from '../../shared/modeStore'

function subscribeStorage(cb: () => void) {
  window.addEventListener('storage', cb)
  return () => window.removeEventListener('storage', cb)
}

function evalTag(raw: string | null): string | null {
  if (!raw) return null
  try {
    const c = JSON.parse(raw) as { label?: string; run_id?: string; subject_id?: string }
    return [c.label, c.subject_id, c.run_id].filter(Boolean).join(' · ') || null
  } catch {
    return null
  }
}

export function TopBar({ kioskId, zone }: { kioskId: string; zone: string | null }) {
  const evalRaw = useSyncExternalStore(subscribeStorage, getEvalContextLocal)
  const { mode } = useModeStatus()
  const clock = mode?.demo_clock?.active ? mode.demo_clock.now_local : null
  const tag = evalTag(evalRaw)
  return (
    <header className="pointer-events-none absolute inset-x-0 top-0 z-[55] flex items-start justify-between gap-4 p-[2.2vh]">
      <div className="rounded-2xl bg-black/70 px-5 py-2.5 backdrop-blur">
        <div className="text-[clamp(16px,2.6vh,30px)] font-bold tracking-tight">FaceGuard</div>
        <div className="text-[clamp(12px,1.6vh,18px)] text-white/75">
          {zone ? `${zone.replace(/_/g, ' ')} · ` : ''}
          {kioskId}
        </div>
      </div>
      <div className="flex flex-col items-end gap-2">
        <ModeBadge size="lg" />
        {clock ? (
          <span className="rounded-full bg-violet-700 px-4 py-1.5 text-[clamp(14px,2.2vh,24px)] font-bold tracking-wide ring-2 ring-violet-300">
            DEMO CLOCK {clock}
          </span>
        ) : null}
        {tag ? (
          <span className="rounded-full bg-sky-700/90 px-3 py-1 text-[clamp(11px,1.5vh,16px)] font-semibold">EVAL: {tag}</span>
        ) : null}
        {MOCK_ENABLED ? (
          <span className="rounded-full bg-black/70 px-3 py-1 text-[clamp(11px,1.4vh,15px)] text-fuchsia-300">
            simulated edge – latencies are not measurements
          </span>
        ) : null}
      </div>
    </header>
  )
}
