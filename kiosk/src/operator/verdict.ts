/**
 * Operator verdict model: decision -> PASS / SUSPICIOUS / DENIED, key scores against the policy bars, the
 * candidate's role. Bars come from GET /v1/mode `policy_bars` (mode-aware, from the running edge); moiré and
 * device bars from config/thresholds.yaml (build time). If the edge does not report policy_bars (older edge,
 * mock) the thresholds.yaml base values are used and labelled as such.
 */
import rawThresholds from 'virtual:thresholds'
import type { Decision, DecisionResponse } from '../api/types'
import { DEMO_USERS } from '../shared/demoUsers'
import type { EdgeUser } from './edgeRaw'

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v)
const finite = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null)

function yaml(path: string): unknown {
  return path.split('.').reduce<unknown>((o, k) => (isObj(o) ? o[k] : undefined), rawThresholds)
}

const yamlNum = (path: string, fallback: number): number => finite(yaml(path)) ?? fallback

export interface PolicyBars {
  pad_pass: number
  flash_pass_r: number
  match_allow: number
  match_margin: number
  /** liveness.moire.unsure_score: moiré >= this -> LIVENESS_UNSURE */
  moire_unsure: number
  /** liveness.device_detector.unsure_conf: phone/screen box >= this over the face -> LIVENESS_UNSURE */
  device_unsure: number
  /** liveness.flash.enforce: false = flash is measured but advisory */
  flash_enforced: boolean
  source: 'edge' | 'thresholds.yaml'
  /** mode the edge reported the bars for (they are mode-aware: offline is stricter) */
  mode: string | null
}

function yamlBars(): Omit<PolicyBars, 'source' | 'mode'> {
  return {
    pad_pass: yamlNum('liveness.pad.pass_min', 0.8),
    flash_pass_r: yamlNum('liveness.flash.pass_min_r', 0.7),
    match_allow: yamlNum('match.local.allow_min_cosine', 0.5),
    match_margin: yamlNum('match.local.min_margin_top1_top2', 0.1),
    moire_unsure: yamlNum('liveness.moire.unsure_score', 0.4),
    device_unsure: yamlNum('liveness.device_detector.unsure_conf', 0.25),
    flash_enforced: yaml('liveness.flash.enforce') === true,
  }
}

export function fallbackBars(): PolicyBars {
  return { ...yamlBars(), source: 'thresholds.yaml', mode: null }
}

/** policy_bars from a raw GET /v1/mode body, or null when the edge does not report them. */
export function barsFromMode(raw: Obj): PolicyBars | null {
  const b = isObj(raw.policy_bars) ? raw.policy_bars : null
  if (!b) return null
  const pad = finite(b.pad_pass)
  const flash = finite(b.flash_pass_r)
  const allow = finite(b.match_allow)
  const margin = finite(b.match_margin)
  if (pad === null || flash === null || allow === null || margin === null) return null
  return {
    ...yamlBars(),
    pad_pass: pad,
    flash_pass_r: flash,
    match_allow: allow,
    match_margin: margin,
    // v1.3 policy_bars also carry these (else the thresholds.yaml values above stay)
    ...(finite(b.moire_unsure) !== null ? { moire_unsure: finite(b.moire_unsure) as number } : {}),
    ...(finite(b.device_unsure) !== null ? { device_unsure: finite(b.device_unsure) as number } : {}),
    ...(typeof b.flash_enforce === 'boolean' ? { flash_enforced: b.flash_enforce } : {}),
    source: 'edge',
    mode: typeof raw.mode === 'string' ? raw.mode : null,
  }
}

export interface ScoreRow {
  key: string
  label: string
  value: number | null
  bar: number
  /** 'min': pass when value >= bar · 'max': pass when value < bar */
  rule: 'min' | 'max'
  /** null = not measured for this attempt */
  pass: boolean | null
  advisory: boolean
}

export function scoreRows(scores: Record<string, unknown>, bars: PolicyBars): ScoreRow[] {
  const row = (key: string, label: string, bar: number, rule: 'min' | 'max', advisory = false): ScoreRow => {
    const value = finite(scores[key])
    return { key, label, value, bar, rule, advisory, pass: value === null ? null : rule === 'min' ? value >= bar : value < bar }
  }
  return [
    row('pad_mean', 'Liveness (PAD mean)', bars.pad_pass, 'min'),
    row('flash_r', 'Colour-flash correlation r', bars.flash_pass_r, 'min', !bars.flash_enforced),
    row('moire', 'Moiré (screen pattern)', bars.moire_unsure, 'max'),
    row('device_conf', 'Phone / screen in view', bars.device_unsure, 'max'),
    row('match_local', 'Face match (cosine)', bars.match_allow, 'min'),
    row('match_margin', 'Match margin (top-1 − top-2)', bars.match_margin, 'min'),
  ]
}

/** Scores other than the six key ones (shown small, for debugging). */
export function otherScores(scores: Record<string, unknown>): Array<[string, number]> {
  const key = new Set(['pad_mean', 'flash_r', 'moire', 'device_conf', 'match_local', 'match_margin'])
  return Object.entries(scores)
    .filter((e): e is [string, number] => !key.has(e[0]) && finite(e[1]) !== null)
    .sort((a, b) => a[0].localeCompare(b[0]))
}

export type Verdict = 'PASS' | 'SUSPICIOUS' | 'DENIED'

export function verdictOf(d: Decision): Verdict {
  return d === 'ALLOW' ? 'PASS' : d === 'STEP_UP' ? 'SUSPICIOUS' : 'DENIED'
}

/**
 * Kiosk decision tones (index.css @theme); the API enum STEP_UP keeps its "REQUEST VERIFICATION" label.
 * Headline = title + tail ("SUSPICIOUS — verification needed"); the tail is set smaller so it fits one line.
 */
export const VERDICT_STYLE: Record<Verdict, { title: string; tail: string; sub: string; cls: string; chip: string }> = {
  PASS: { title: 'PASS', tail: '', sub: 'ALLOW', cls: 'bg-allow text-allow-ink', chip: 'bg-allow text-allow-ink' },
  SUSPICIOUS: {
    title: 'SUSPICIOUS',
    tail: '— verification needed',
    sub: 'REQUEST VERIFICATION · step-up',
    cls: 'bg-stepup text-stepup-ink',
    chip: 'bg-stepup text-stepup-ink',
  },
  DENIED: { title: 'DENIED', tail: '', sub: 'DENY', cls: 'bg-deny text-deny-ink', chip: 'bg-deny text-deny-ink' },
}

export type RoleSource = 'edge response' | 'enrolled users' | 'schedule bundle'

/**
 * candidate.role (edge: signed bundle) > demo schedule source > role stored with the template (enrolment
 * meta, informational: it never decides access) > unknown. Display only.
 */
export function resolveRole(
  userId: string | null,
  rawRole: string | null,
  users: EdgeUser[] | null,
): { role: string | null; source: RoleSource | null } {
  if (rawRole) return { role: rawRole, source: 'edge response' }
  if (!userId) return { role: null, source: null }
  const bundle = DEMO_USERS.find((u) => u.user_id === userId)?.role
  if (bundle) return { role: bundle, source: 'schedule bundle' }
  const enrolled = users?.find((u) => u.user_id === userId)?.role
  if (enrolled) return { role: enrolled, source: 'enrolled users' }
  return { role: null, source: null }
}

export function nextActionText(d: DecisionResponse): string {
  const n = d.next_action
  switch (n.type) {
    case 'OPEN_DOOR':
      return 'door opens'
    case 'RECAPTURE':
      return 'recapture: look at the camera again'
    case 'CHALLENGE':
      return `challenge: ${n.challenge?.actions.join(' + ') ?? '—'}`
    case 'SECOND_FACTOR':
      return `second factor: ${n.methods?.join(' / ') ?? '—'}${n.attempts_left !== null ? ` (${n.attempts_left} left)` : ''}`
    case 'CONTACT_DESK':
      return 'contact the desk'
    case 'NONE':
      return n.retry_after_s ? `none (retry after ${n.retry_after_s} s)` : 'none'
  }
}
