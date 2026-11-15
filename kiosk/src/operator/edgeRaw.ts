/**
 * Raw edge calls for /operator and /register, next to the shared EdgeApi client (used read-only):
 *  - POST /v1/attempt/{id}/frames keeping the RAW body: additive fields such as `candidate.role` survive
 *    (the shared normaliser keeps only candidate.user_id + display);
 *  - GET /v1/mode raw, for `policy_bars` (edge/policy/runtime.py mode_status; not yet listed in API.md §3.10);
 *  - GET /v1/admin/users (enrol:read) - via the shared client;
 *  - GET /v1/events raw SSE (events:read; same reason as frames). The reader stops for good on HTTP 401/403 and
 *    on the edge's final `event: auth` (design v2 §F), and reports it to the auth layer.
 * Mock mode (?mock=1) routes everything through the shared in-browser mock instead.
 */
import { getApi } from '../api'
import { authHeaders, credentialError, handleSseAuthEvent, notifyUnauthorized, requestAuthRecheck, shouldSignOutOn401 } from '../api/credentials'
import { normalizeDecision } from '../api/normalize'
import { ApiError, type DecisionResponse, type EnrolledUser, type EnrolledUsersResponse, type FramesMeta } from '../api/types'
import { EDGE_URL, MOCK_ENABLED, UI } from '../config'
import { runLiveFeed } from './liveFeed'

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v)

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

function errorFromBody(status: number, body: unknown, attemptId: string | null): ApiError {
  const err = isObj(body) && isObj(body.error) ? body.error : null
  if (err) {
    return new ApiError(
      String(err.code ?? `HTTP_${status}`),
      status,
      String(err.message ?? `HTTP ${status}`),
      typeof err.attempt_id === 'string' ? err.attempt_id : attemptId,
    )
  }
  const detail = isObj(body) && 'detail' in body ? body.detail : null
  const code = status === 422 ? 'VALIDATION_ERROR' : status === 401 ? 'UNAUTHORIZED' : status === 403 ? 'FORBIDDEN' : `HTTP_${status}`
  return new ApiError(code, status, detail ? JSON.stringify(detail).slice(0, 300) : `HTTP ${status}`, attemptId)
}

async function request(path: string, init: RequestInit, timeoutMs: number, attemptId: string | null = null): Promise<unknown> {
  const ctrl = new AbortController()
  const timer = window.setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    let res: Response
    try {
      res = await fetch(EDGE_URL + path, { ...init, signal: ctrl.signal })
    } catch (e) {
      if (ctrl.signal.aborted) throw new ApiError('TIMEOUT', 0, `${path} timed out after ${timeoutMs} ms`, attemptId)
      throw new ApiError('NETWORK', 0, `Edge unreachable (${path}): ${e instanceof Error ? e.message : String(e)}`, attemptId)
    }
    const text = await res.text()
    const body = text ? parseJson(text) : null
    if (!res.ok) throw errorFromBody(res.status, body, attemptId)
    return body
  } catch (e) {
    if (e instanceof ApiError) throw e
    if (ctrl.signal.aborted) throw new ApiError('TIMEOUT', 0, `${path} timed out after ${timeoutMs} ms`, attemptId)
    throw new ApiError('NETWORK', 0, `Edge response failed (${path})`, attemptId)
  } finally {
    window.clearTimeout(timer)
  }
}

// ------------------------------------------------------------------ frames

export interface RawDecision {
  decision: DecisionResponse
  /** the edge's body as received (null in mock mode) */
  raw: Obj | null
}

/** POST /v1/attempt/{id}/frames (multipart frame_0..N + meta JSON), exactly like the kiosk client. */
export async function postFrames(attemptId: string, frames: Blob[], meta: FramesMeta): Promise<RawDecision> {
  if (MOCK_ENABLED) return { decision: await getApi().submitFrames(attemptId, frames, meta), raw: null }
  const form = new FormData()
  frames.forEach((blob, i) => form.append(`frame_${i}`, blob, `frame_${i}.jpg`))
  form.append('meta', JSON.stringify(meta))
  const body = await request(
    `/v1/attempt/${encodeURIComponent(attemptId)}/frames`,
    { method: 'POST', body: form },
    UI.timeouts.frames,
    attemptId,
  )
  return { decision: normalizeDecision(body), raw: isObj(body) ? body : null }
}

/** candidate.role from a raw DecisionResponse (edge additive field), else null. */
export function rawCandidateRole(raw: Obj | null): string | null {
  const c = raw && isObj(raw.candidate) ? raw.candidate : null
  return c && typeof c.role === 'string' && c.role ? c.role : null
}

// ------------------------------------------------------------------ mode (policy_bars)

/** GET /v1/mode as received (mock: the mock's normalised ModeResponse, which has no policy_bars). */
export async function getModeRaw(): Promise<Obj> {
  if (MOCK_ENABLED) return { ...(await getApi().getMode()) }
  const body = await request('/v1/mode', { method: 'GET' }, UI.timeouts.mode)
  return isObj(body) ? body : {}
}

/**
 * Mode WITH policy_bars. edge-app (offline-verification F6): the public GET /v1/mode no longer carries
 * policy_bars / schedule_bundle / last_sync; they moved to GET /v1/admin/mode/detail (store:read). Without
 * store:read (or a token) this returns the public body, and the operator view uses the thresholds.yaml bars,
 * labelled as such. A 401 on the session token signs the UI out.
 */
export async function getModeDetailRaw(token: string, canStoreRead: boolean): Promise<Obj> {
  if (MOCK_ENABLED || !token || !canStoreRead) return getModeRaw()
  const path = '/v1/admin/mode/detail'
  try {
    const body = await request(path, { method: 'GET', headers: authHeaders(token) }, UI.timeouts.mode)
    return isObj(body) ? body : {}
  } catch (e) {
    if (e instanceof ApiError && e.status === 401 && shouldSignOutOn401(path, token)) notifyUnauthorized({ path, reason: e.reason, token })
    throw e
  }
}

// ------------------------------------------------------------------ users

/** A user enrolled on this edge (GET /v1/admin/users). `role` is the role stored with the TEMPLATE at
 *  enrolment: informational only; the signed schedule role decides access. */
export type EdgeUser = EnrolledUser
export type UsersResponse = EnrolledUsersResponse

/** GET /v1/admin/users (enrol:read), through the shared client (the mock implements it too). */
export function getUsers(token: string): Promise<UsersResponse> {
  return getApi().listEnrolledUsers(token)
}

// ------------------------------------------------------------------ live decisions (SSE)

export interface LiveHandlers {
  onDecision: (decision: DecisionResponse, raw: Obj | null) => void
  onRendered?: (raw: Obj) => void
  onStatus?: (status: 'connecting' | 'open' | 'error') => void
  /** The feed ended for an auth reason and will NOT reconnect (401/403 or `event: auth`). */
  onAuthClosed?: (info: { status: number | null; reason: string | null }) => void
}

const EVENTS_PATH = '/v1/events'

/** 401 on a session request signs the UI out; a 403 MISSING_PERMISSION re-reads /v1/auth/me. */
function reportHttpAuth(status: number, reason: string | null, token: string): void {
  if (status === 401 && shouldSignOutOn401(EVENTS_PATH, token)) notifyUnauthorized({ path: EVENTS_PATH, reason, token })
  else if (status === 403) requestAuthRecheck({ path: EVENTS_PATH, reason, token })
}

/**
 * GET /v1/events (text/event-stream, events:read) read via fetch so the raw `decision` payloads are kept.
 * Reader rules in operator/liveFeed.ts: stops for good on 401/403; `event: auth` (always SESSION_ENDED) is
 * verified by one reconnect; 429 waits Retry-After; other failures reconnect after 2 s.
 * Call it only with a token that can(events:read) (the caller gates it); an empty token never connects.
 */
export function subscribeLive(token: string, handlers: LiveHandlers): () => void {
  if (MOCK_ENABLED) {
    return getApi().subscribeEvents(token || 'operator-console', {
      onDecision: (d) => handlers.onDecision(d, null),
      onRendered: (e) => handlers.onRendered?.({ ...e }),
      onStatus: handlers.onStatus,
      onAuthClosed: handlers.onAuthClosed,
    })
  }
  const ctrl = new AbortController()
  if (!token || credentialError(token)) {
    queueMicrotask(() => {
      handlers.onStatus?.('error')
      handlers.onAuthClosed?.({ status: null, reason: token ? 'BAD_CREDENTIAL' : 'NO_CREDENTIAL' })
    })
    return () => ctrl.abort()
  }
  const dispatch = (event: string, payload: unknown) => {
    if (!isObj(payload)) return
    if (event === 'rendered') {
      if (typeof payload.attempt_id === 'string') handlers.onRendered?.(payload)
      return
    }
    if ((event === 'decision' || event === 'message') && 'decision' in payload) {
      handlers.onDecision(normalizeDecision(payload), payload)
    }
  }
  void runLiveFeed(
    {
      url: EDGE_URL + EVENTS_PATH,
      headers: authHeaders(token),
      fetch: (url, init) => fetch(url, init),
      sleep: (ms) => abortableSleep(ms, ctrl.signal),
      onEvent: (event, data) => dispatch(event, parseJson(data)),
      onStatus: handlers.onStatus,
      onHttpAuth: (status, reason) => reportHttpAuth(status, reason, token),
      onAuthEvent: (reason) => handleSseAuthEvent(EVENTS_PATH, token, reason),
      onClosed: (info) => handlers.onAuthClosed?.(info),
    },
    ctrl.signal,
  )
  return () => ctrl.abort()
}

function abortableSleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve()
    const id = window.setTimeout(resolve, ms)
    signal.addEventListener('abort', () => {
      window.clearTimeout(id)
      resolve()
    }, { once: true })
  })
}
