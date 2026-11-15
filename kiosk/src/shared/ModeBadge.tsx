/** Persistent ONLINE / OFFLINE / SYNCING badge + sync-queue depth from GET /v1/mode. */
import { MOCK_ENABLED } from '../config'
import { badgeTone, bundleText, type BadgeTone } from './badgeTone'
import { useModeStatus } from './modeStore'

const TONE: Record<BadgeTone, { dot: string; label: string; ring: string }> = {
  online: { dot: 'bg-emerald-400', label: 'ONLINE', ring: 'ring-emerald-400/40' },
  // GET /v1/mode cloud_match.degraded: connectivity is up but cloud matches miss their budget, so attempts
  // are decided locally (OFFLINE rules, P7) and synced later.
  degraded: { dot: 'bg-amber-400', label: 'ONLINE · cloud slow – deciding locally', ring: 'ring-amber-400/50' },
  offline: { dot: 'bg-red-500', label: 'OFFLINE', ring: 'ring-red-500/50' },
  forced: { dot: 'bg-red-500', label: 'OFFLINE (forced)', ring: 'ring-red-500/50' },
  // the edge answered but its mode could not be read: treated as OFFLINE (normalizeMode, audit KAO-09)
  modeUnknown: { dot: 'bg-amber-400', label: 'MODE UNKNOWN – treated as OFFLINE', ring: 'ring-amber-400/50' },
  syncing: { dot: 'bg-amber-400 soft-pulse', label: 'SYNCING', ring: 'ring-amber-400/50' },
  down: { dot: 'bg-zinc-400', label: 'EDGE UNREACHABLE', ring: 'ring-zinc-400/50' },
  unknown: { dot: 'bg-zinc-500 soft-pulse', label: 'CONNECTING', ring: 'ring-zinc-500/40' },
}

/**
 * `bundleVersion`: the installed bundle version from an authenticated source (access list / mode detail);
 * the public /v1/mode no longer carries it (KA-03), so without it the badge shows the public cache state.
 */
export function ModeBadge({
  size = 'lg',
  showBundle = false,
  bundleVersion = null,
}: {
  size?: 'lg' | 'sm'
  showBundle?: boolean
  bundleVersion?: number | string | null
}) {
  const { mode, reachable } = useModeStatus()
  const tone: BadgeTone = badgeTone(
    mode
      ? { mode: mode.mode, state: mode.state, forced: mode.forced, reason: mode.reason, degraded: mode.cloud_match?.degraded === true }
      : null,
    reachable,
  )
  const t = TONE[tone]
  const bundle = bundleText(bundleVersion ?? mode?.schedule_bundle?.version ?? null, mode?.cache_state ?? null)
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
      {showBundle && bundle ? <span className="font-normal text-white/70">· {bundle}</span> : null}
      {MOCK_ENABLED ? (
        <span className="rounded bg-fuchsia-600 px-2 py-0.5 text-[0.75em] font-bold tracking-wider">MOCK</span>
      ) : null}
    </div>
  )
}
