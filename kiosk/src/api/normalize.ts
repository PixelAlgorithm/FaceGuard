/**
 * Defensive normalisation of edge responses. The edge is authoritative, but the kiosk must never crash
 * (or fail open) on a missing/renamed field: anything unparseable becomes a fail-secure DENY view.
 */
import {
  CHALLENGE_ACTIONS,
  FALLBACK_METHODS,
  RANDOM_CHALLENGE_MODES,
  type ChallengeAction,
  type ChallengeSpec,
  type Decision,
  type DecisionResponse,
  type FallbackMethod,
  type ModeDemoClock,
  type ModeResponse,
  type NextAction,
  type NextActionType,
  type RandomChallengeMode,
} from './types'
import { parseDemoClock } from './access'

type Obj = Record<string, unknown>

const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v)
const asStr = (v: unknown): string | null => (typeof v === 'string' ? v : null)
const asNum = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null)
const asStrList = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [])

/** "2026-11-14T21:30:05+05:30" or "21:30" -> "21:30" (the local wall time, as sent by the edge). */
function hhmm(v: string | null): string | null {
  if (!v) return null
  const m = /(?:T|^)(\d{2}):(\d{2})/.exec(v)
  return m ? `${m[1]}:${m[2]}` : v
}

const NEXT_TYPES: readonly NextActionType[] = [
  'OPEN_DOOR',
  'RECAPTURE',
  'CHALLENGE',
  'SECOND_FACTOR',
  'CONTACT_DESK',
  'NONE',
]

function normChallenge(v: unknown): ChallengeSpec | null {
  if (!isObj(v)) return null
  const actions = asStrList(v.actions)
    .map((a) => a.toUpperCase())
    .filter((a): a is ChallengeAction => (CHALLENGE_ACTIONS as readonly string[]).includes(a))
  const challengeId = asStr(v.challenge_id)
  const nonce = asStr(v.nonce)
  if (!challengeId || !nonce || actions.length === 0) return null
  return {
    challenge_id: challengeId,
    nonce,
    actions,
    step_window_ms: asNum(v.step_window_ms) ?? 1500,
    min_reaction_ms: asNum(v.min_reaction_ms) ?? 150,
    expires_at: asStr(v.expires_at) ?? '',
  }
}

function normNextAction(v: unknown, decision: Decision): NextAction {
  const o = isObj(v) ? v : {}
  const rawType = (asStr(o.type) ?? '').toUpperCase()
  const type: NextActionType = (NEXT_TYPES as readonly string[]).includes(rawType)
    ? (rawType as NextActionType)
    : decision === 'ALLOW'
      ? 'OPEN_DOOR'
      : 'NONE'
  const methods = Array.isArray(o.methods)
    ? asStrList(o.methods)
        .map((m) => m.toUpperCase())
        .filter((m): m is FallbackMethod => (FALLBACK_METHODS as readonly string[]).includes(m))
    : null
  return {
    type,
    steps: asStrList(o.steps).map((s) => s.toUpperCase()),
    methods,
    challenge: normChallenge(o.challenge),
    attempts_left: asNum(o.attempts_left),
    retry_after_s: asNum(o.retry_after_s),
  }
}

export function normalizeDecision(raw: unknown): DecisionResponse {
  const o = isObj(raw) ? raw : {}
  const d = asStr(o.decision)
  const decision: Decision = d === 'ALLOW' || d === 'STEP_UP' || d === 'DENY' ? d : 'DENY'
  const reasonCodes = asStrList(o.reason_codes)
  const latency = isObj(o.latency_ms) ? o.latency_ms : {}
  const latencyMs: DecisionResponse['latency_ms'] = { total: asNum(latency.total) ?? NaN }
  for (const [k, val] of Object.entries(latency)) {
    const n = asNum(val)
    if (n !== null) latencyMs[k] = n
  }
  const candidate = isObj(o.candidate)
    ? { user_id: asStr(o.candidate.user_id) ?? '', display: asStr(o.candidate.display) ?? '', role: asStr(o.candidate.role) ?? null }
    : null
  const mode = o.mode === 'OFFLINE' ? 'OFFLINE' : 'ONLINE'
  const bio = asStr(o.bio_result)
  const cache = asStr(o.cache_state)
  return {
    attempt_id: asStr(o.attempt_id) ?? '',
    kiosk_id: asStr(o.kiosk_id) ?? '',
    zone: asStr(o.zone),
    decision,
    // Unparseable decision -> fail secure with SYSTEM_ERROR so the screen explains itself.
    reason_codes: d === decision ? reasonCodes : ['SYSTEM_ERROR'],
    resolved_codes: asStrList(o.resolved_codes),
    next_action: normNextAction(o.next_action, decision),
    bio_result: bio === 'BIO_PASS' || bio === 'BIO_UNSURE' || bio === 'BIO_FAIL' ? bio : null,
    schedule_result: asStr(o.schedule_result),
    mode,
    cache_state: cache === 'FRESH' || cache === 'EXPIRED' || cache === 'INVALID' ? cache : null,
    candidate,
    scores: isObj(o.scores) ? o.scores : {},
    latency_ms: latencyMs,
    policy_version: asStr(o.policy_version),
    bundle_version: asStr(o.bundle_version) ?? asNum(o.bundle_version),
    display_message: asStr(o.display_message),
    stage: asStr(o.stage),
  }
}

/**
 * demo_clock (API.md v1.4): the strict contract parse when the edge sends the full shape; an older edge sends
 * only {active, now_local} - kept for the DEMO CLOCK badge with the other fields null (`contract: false`).
 */
function demoClock(clock: Record<string, unknown>): ModeDemoClock {
  try {
    return { contract: true, ...parseDemoClock(clock) }
  } catch {
    return {
      contract: false,
      active: clock.active === true,
      now_local: hhmm(asStr(clock.now_local)),
      now_utc: null,
      offset_s: null,
      date_local: null,
      bundle_issued_at: null,
      earliest_utc: null,
      earliest_local: hhmm(asStr(clock.earliest_local)),
      earliest_date_local: null,
      bundle_rollback: clock.bundle_rollback === true,
      cache_state: null,
    }
  }
}

export function normalizeMode(raw: unknown): ModeResponse {
  const o = isObj(raw) ? raw : {}
  const mode = o.mode === 'OFFLINE' ? 'OFFLINE' : 'ONLINE'
  const st = asStr(o.state)
  const state = st === 'ONLINE' || st === 'OFFLINE' || st === 'SYNCING' ? st : mode
  const bundle = isObj(o.schedule_bundle) ? o.schedule_bundle : null
  const cache = isObj(o.template_cache) ? o.template_cache : null
  const clock = isObj(o.demo_clock) ? o.demo_clock : null
  return {
    mode,
    state,
    since: asStr(o.since),
    forced: o.forced === true,
    last_cloud_ok_at: asStr(o.last_cloud_ok_at),
    reason: asStr(o.reason),
    schedule_bundle: bundle
      ? {
          version: asNum(bundle.version) ?? asStr(bundle.version),
          expires_at: asStr(bundle.expires_at),
          signature_valid: typeof bundle.signature_valid === 'boolean' ? bundle.signature_valid : null,
          issued_at: asStr(bundle.issued_at),
          cache_state: asStr(bundle.cache_state),
        }
      : null,
    revocation_seq: asNum(o.revocation_seq),
    template_cache: cache
      ? { count: asNum(cache.count) ?? asNum(cache.entitled_users), model: asStr(cache.model) }
      : null,
    sync_queue_depth: asNum(o.sync_queue_depth) ?? 0,
    demo_clock: clock ? demoClock(clock) : null,
    cloud_match: isObj(o.cloud_match)
      ? {
          enabled: typeof o.cloud_match.enabled === 'boolean' ? o.cloud_match.enabled : null,
          degraded: o.cloud_match.degraded === true,
          recent: asNum(o.cloud_match.recent),
          misses: asNum(o.cloud_match.misses),
          last_miss_at: asStr(o.cloud_match.last_miss_at),
          last_ok_at: asStr(o.cloud_match.last_ok_at),
        }
      : null,
    random_challenge: normRandomChallenge(o.random_challenge),
    kiosk_id: asStr(o.kiosk_id),
    zone: asStr(o.zone),
    policy_version: asStr(o.policy_version),
    rate_limit: isObj(o.rate_limit)
      ? {
          enabled: typeof o.rate_limit.enabled === 'boolean' ? o.rate_limit.enabled : null,
          locked: o.rate_limit.locked === true,
          retry_after_s: asNum(o.rate_limit.retry_after_s),
        }
      : null,
    last_sync: isObj(o.last_sync)
      ? { at: asStr(o.last_sync.at), report: isObj(o.last_sync.report) ? o.last_sync.report : null }
      : null,
    server_flags: asStrList(o.server_flags),
    policy_bars: isObj(o.policy_bars) ? normBars(o.policy_bars) : null,
  }
}

function normBars(o: Obj): Record<string, number | boolean | string | null> {
  const out: Record<string, number | boolean | string | null> = {}
  for (const [k, v] of Object.entries(o)) {
    if (typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string' || v === null) out[k] = v
  }
  return out
}

function normRandomChallenge(v: unknown): RandomChallengeMode | null {
  const s = asStr(v)?.toUpperCase() ?? null
  return s && (RANDOM_CHALLENGE_MODES as readonly string[]).includes(s) ? (s as RandomChallengeMode) : null
}
