/**
 * Which ONLINE / OFFLINE badge to show (pure, unit-tested with plain Node). Fail-safe order: edge down >
 * no answer > unknown mode (normalizeMode reason `mode_unknown`, audit KAO-09) > forced OFFLINE > SYNCING >
 * OFFLINE > cloud degraded > ONLINE. The badge never says ONLINE unless the edge reported it.
 */
export type BadgeTone = 'online' | 'degraded' | 'offline' | 'forced' | 'syncing' | 'down' | 'unknown' | 'modeUnknown'

export interface BadgeMode {
  mode: string
  state: string
  forced: boolean
  reason: string | null
  degraded: boolean
}

export function badgeTone(m: BadgeMode | null, reachable: boolean): BadgeTone {
  if (!reachable) return 'down'
  if (!m) return 'unknown'
  if (m.reason === 'mode_unknown') return 'modeUnknown'
  if (m.forced && m.mode === 'OFFLINE') return 'forced'
  if (m.state === 'SYNCING') return 'syncing'
  if (m.state === 'OFFLINE' || m.mode === 'OFFLINE') return 'offline'
  if (m.degraded) return 'degraded'
  return 'online'
}

/**
 * Bundle part of the badge (review KA-03). The public GET /v1/mode carries only cache_state (schedule_bundle
 * moved to the authenticated /v1/admin/mode/detail): the version is shown when the page passes one from an
 * authenticated source, else the cache state, else nothing.
 */
export function bundleText(version: number | string | null, cacheState: string | null): string | null {
  if (version !== null && version !== '') return `bundle v${String(version)}`
  return cacheState ? `bundle ${cacheState}` : null
}
