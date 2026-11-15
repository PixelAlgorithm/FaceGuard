/** Persistent ONLINE / OFFLINE / SYNCING badge + sync-queue depth from GET /v1/mode. */
import { MOCK_ENABLED } from '../config'
import { useModeStatus } from './modeStore'

type BadgeTone = 'online' | 'degraded' | 'offline' | 'syncing' | 'down' | 'unknown'

const TONE: Record<BadgeTone, { dot: string; label: string; ring: string }> = {
  online: { dot: 'bg-emerald-400', label: 'ONLINE', ring: 'ring-emerald-400/40' },
  // GET /v1/mode cloud_match.degraded: connectivity is up but cloud matches miss their budget, so attempts
  // are decided locally (OFFLINE rules, P7) and synced later.
  degraded: { dot: 'bg-amber-400', label: 'ONLINE · cloud slow – deciding locally', ring: 'ring-amber-400/50' },
  offline: { dot: 'bg-red-500', label: 'OFFLINE', ring: 'ring-red-500/50' },
  syncing: { dot: 'bg-amber-400 soft-pulse', label: 'SYNCING', ring: 'ring-amber-400/50' },
  down: { dot: 'bg-zinc-400', label: 'EDGE UNREACHABLE', ring: 'ring-zinc-400/50' },
  unknown: { dot: 'bg-zinc-500 soft-pulse', label: 'CONNECTING', ring: 'ring-zinc-500/40' },
}

export function ModeBadge({ size = 'lg', showBundle = false }: { size?: 'lg' | 'sm'; showBundle?: boolean }) {
  const { mode, reachable } = useModeStatus()
  const tone: BadgeTone = !reachable
    ? 'down'
    : !mode
      ? 'unknown'
      : mode.state === 'SYNCING'
        ? 'syncing'
        : mode.state === 'OFFLINE' || mode.mode === 'OFFLINE'
          ? 'offline'
          : mode.cloud_match?.degraded
            ? 'degraded'
            : 'online'
  const t = TONE[tone]
  const big = size === 'lg'
  const queue = mode?.sync_queue_depth ?? null
  return (
    <div
      role="status"
      aria-live="polite"
      aria-label={`Connection ${t.label}${queue !== null ? `, sync queue ${queue}` : ''}`}
      className={`inline-flex items-center gap-3 rounded-full bg-black/75 ring-2 ${t.ring} ${
        big ? 'px-5 py-2.5 text-[clamp(14px,2.2vh,24px)]' : 'px-3 py-1 text-sm'
      } font-semibold text-white backdrop-blur`}
    >
      <span className={`inline-block rounded-full ${t.dot} ${big ? 'h-4 w-4' : 'h-2.5 w-2.5'}`} />
      <span className="tracking-wide">{t.label}</span>
      {queue !== null && reachable ? (
        <span className="font-normal text-white/80">
          · queue <span className="font-semibold tabular-nums text-white">{queue}</span>
        </span>
      ) : null}
      {showBundle && mode?.schedule_bundle?.version !== undefined && mode?.schedule_bundle?.version !== null ? (
        <span className="font-normal text-white/70">· bundle v{String(mode.schedule_bundle.version)}</span>
      ) : null}
      {MOCK_ENABLED ? (
        <span className="rounded bg-fuchsia-600 px-2 py-0.5 text-[0.75em] font-bold tracking-wider">MOCK</span>
      ) : null}
    </div>
  )
}
