/**
 * Per-signal chips for /operator from `scores.signals` (API.md v1.3 §1; edge/policy/engine.py SCORE_KEYS):
 * {pad, device, moire, flash, mask, depth, injection} -> PASS | PASS_AMBIENT | UNSURE | FAIL | NOT_AVAILABLE |
 * ADVISORY_<zone>. Shown in the operator's words: PASS / SUSPICIOUS / DENIED (+ "not measured", and an
 * "advisory" tag when the signal is measured but has no decision effect, e.g. the colour flash).
 * Plus a compact summary of GET /v1/admin/attempt/{id}/signals (raw per-frame values, no images).
 */
type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v)

export type SignalVerdict = 'PASS' | 'SUSPICIOUS' | 'DENIED' | 'NOT_MEASURED'

export interface SignalChip {
  key: string
  label: string
  /** status exactly as the edge sent it */
  status: string
  verdict: SignalVerdict
  /** ADVISORY_<zone>: measured and reported, no decision effect */
  advisory: boolean
  /** PASS_AMBIENT: passed on ambient light (flash too weak to judge, allowed by the ambient exception) */
  ambient: boolean
}

const LABELS: Record<string, string> = {
  pad: 'Liveness (PAD)',
  device: 'Phone / screen',
  moire: 'Moiré',
  flash: 'Colour flash',
  mask: 'Mask',
  depth: 'Depth (iPhone)',
  injection: 'Camera / injection',
}
const ORDER = ['pad', 'device', 'moire', 'flash', 'mask', 'depth', 'injection']

function zoneVerdict(zone: string): SignalVerdict {
  switch (zone) {
    case 'PASS':
    case 'PASS_AMBIENT':
      return 'PASS'
    case 'UNSURE':
      return 'SUSPICIOUS'
    case 'FAIL':
      return 'DENIED'
    default:
      return 'NOT_MEASURED' // NOT_AVAILABLE, or a status this page does not know (shown raw)
  }
}

export function chipFor(key: string, status: string): SignalChip {
  const s = status.toUpperCase()
  const advisory = s.startsWith('ADVISORY_')
  const zone = advisory ? s.slice('ADVISORY_'.length) : s
  return { key, label: LABELS[key] ?? key, status, verdict: zoneVerdict(zone), advisory, ambient: zone === 'PASS_AMBIENT' }
}

/** Chips in a fixed order (unknown extra keys last); null when the edge sent no `scores.signals`. */
export function signalChips(scores: Record<string, unknown>): SignalChip[] | null {
  const sig = scores.signals
  if (!isObj(sig)) return null
  const keys = Object.keys(sig).filter((k) => typeof sig[k] === 'string')
  keys.sort((a, b) => {
    const ia = ORDER.indexOf(a)
    const ib = ORDER.indexOf(b)
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || a.localeCompare(b)
  })
  return keys.map((k) => chipFor(k, sig[k] as string))
}

export const CHIP_STYLE: Record<SignalVerdict, { text: string; cls: string }> = {
  PASS: { text: 'PASS', cls: 'bg-allow text-allow-ink' },
  SUSPICIOUS: { text: 'SUSPICIOUS', cls: 'bg-stepup text-stepup-ink' },
  DENIED: { text: 'DENIED', cls: 'bg-deny text-deny-ink' },
  NOT_MEASURED: { text: 'not measured', cls: 'bg-white/10 text-white/70' },
}

// ---------------------------------------------------------------- GET /v1/admin/attempt/{id}/signals

const f3 = (v: unknown): string => (typeof v === 'number' && Number.isFinite(v) ? v.toFixed(3) : v === null ? '—' : String(v))

function list(v: unknown, pick?: (x: Obj) => unknown): string | null {
  if (!Array.isArray(v) || v.length === 0) return null
  return v.map((x) => (pick && isObj(x) ? f3(pick(x)) : isObj(x) ? '{…}' : f3(x))).join(' · ')
}

/** First numeric field among `keys` of an object (the raw models' field names vary per check). */
const firstNum =
  (...keys: string[]) =>
  (o: Obj): unknown => {
    for (const k of keys) if (typeof o[k] === 'number') return o[k]
    return null
  }

/** Human-readable lines for the raw debug view. Unknown shapes degrade to compact JSON, never throw. */
export function rawSignalLines(body: unknown): Array<[string, string]> {
  if (!isObj(body)) return []
  const out: Array<[string, string]> = []
  const raw = isObj(body.raw) ? body.raw : null
  if (raw) {
    const add = (k: string, v: string | null) => {
      if (v) out.push([k, v])
    }
    add('faces per frame', list(raw.faces_per_frame))
    add('p_live per frame', list(raw.p_live))
    add('moiré per frame', list(raw.moire, firstNum('score', 'moire', 'value')))
    add('mask ring per frame', list(raw.mask_ring, firstNum('score', 'm2', 'value')))
    add('device per frame', list(raw.device, firstNum('conf', 'confidence', 'score')))
    if (isObj(raw.flash)) {
      const fl = raw.flash
      const parts = ['r_frames', 'r_client', 'amplitude', 'lag_frames', 'zone']
        .filter((k) => k in fl)
        .map((k) => `${k} ${f3(fl[k])}`)
      add('flash', parts.length ? parts.join(' · ') : JSON.stringify(fl).slice(0, 200))
    }
    if (isObj(raw.cloud_match)) {
      const c = raw.cloud_match
      const parts = Object.entries(c)
        .filter(([, v]) => v === null || ['string', 'number', 'boolean'].includes(typeof v))
        .slice(0, 8)
        .map(([k, v]) => `${k} ${f3(v)}`)
      add('cloud match', parts.join(' · '))
    }
    if (isObj(raw.probe)) add('early probe', JSON.stringify(raw.probe).slice(0, 220))
    if (raw.depth !== undefined && raw.depth !== null) add('depth', JSON.stringify(raw.depth).slice(0, 200))
  }
  if (isObj(body.challenge)) out.push(['challenge', JSON.stringify(body.challenge).slice(0, 240)])
  if (isObj(body.probe)) out.push(['early probe', JSON.stringify(body.probe).slice(0, 220)])
  if (body.mock === true) out.push(['source', 'mock edge (simulated)'])
  return out
}
