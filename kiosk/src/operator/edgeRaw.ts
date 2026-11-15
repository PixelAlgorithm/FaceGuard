/**
 * Raw edge calls for /operator and /register, next to the shared EdgeApi client (used read-only):
 *  - POST /v1/attempt/{id}/frames keeping the RAW body: additive fields such as `candidate.role` survive
 *    (the shared normaliser keeps only candidate.user_id + display);
 *  - GET /v1/mode raw, for `policy_bars` (edge/policy/runtime.py mode_status; not yet listed in API.md §3.10);
 *  - GET /v1/admin/users (API.md v1.2: enrolled-user list; X-Admin-Token) - via the shared client;
 *  - GET /v1/events raw SSE (same reason as frames).
 * Mock mode (?mock=1) routes everything through the shared in-browser mock instead.
 */
import { getApi } from '../api'
import { normalizeDecision } from '../api/normalize'
import { ApiError, type DecisionResponse, type EnrolledUser, type EnrolledUsersResponse, type FramesMeta } from '../api/types'
import { EDGE_URL, MOCK_ENABLED, UI } from '../config'

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

const adminHeaders = (token: string): Record<string, string> => (token ? { 'X-Admin-Token': token } : {})

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

// ------------------------------------------------------------------ users

/** A user enrolled on this edge (GET /v1/admin/users). `role` is the role stored with the TEMPLATE at
 *  enrolment: informational only; the signed schedule role decides access. */
export type EdgeUser = EnrolledUser
export type UsersResponse = EnrolledUsersResponse

/** GET /v1/admin/users (X-Admin-Token), through the shared client (the mock implements it too). */
export function getUsers(token: string): Promise<UsersResponse> {
  return getApi().listEnrolledUsers(token)
}

// ------------------------------------------------------------------ live decisions (SSE)

export interface LiveHandlers {
  onDecision: (decision: DecisionResponse, raw: Obj | null) => void
  onRendered?: (raw: Obj) => void
  onStatus?: (status: 'connecting' | 'open' | 'error') => void
}

/**
 * GET /v1/events (text/event-stream, localhost-only, no token needed per API.md v1.2) read via fetch so
 * the raw `decision` payloads are kept. Reconnects every 2 s until unsubscribed.
 */
export function subscribeLive(token: string, handlers: LiveHandlers): () => void {
  if (MOCK_ENABLED) {
    return getApi().subscribeEvents(token || 'operator-console', {
      onDecision: (d) => handlers.onDecision(d, null),
      onRendered: (e) => handlers.onRendered?.({ ...e }),
      onStatus: handlers.onStatus,
    })
  }
  const ctrl = new AbortController()
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
  const run = async () => {
    while (!ctrl.signal.aborted) {
      handlers.onStatus?.('connecting')
      try {
        const res = await fetch(EDGE_URL + '/v1/events', {
          headers: { Accept: 'text/event-stream', ...adminHeaders(token) },
          signal: ctrl.signal,
        })
        if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`)
        handlers.onStatus?.('open')
        const reader = res.body.pipeThrough(new TextDecoderStream()).getReader()
        let buf = ''
        for (;;) {
          const { value, done } = await reader.read()
          if (done) break
          buf += value.replace(/\r\n/g, '\n')
          let sep: number
          while ((sep = buf.indexOf('\n\n')) >= 0) {
            const block = buf.slice(0, sep)
            buf = buf.slice(sep + 2)
            const lines = block.split('\n')
            const event = lines.find((l) => l.startsWith('event:'))?.slice(6).trim() || 'message'
            const data = lines
              .filter((l) => l.startsWith('data:'))
              .map((l) => l.slice(5).replace(/^ /, ''))
              .join('\n')
            if (data) dispatch(event, parseJson(data))
          }
        }
        if (!ctrl.signal.aborted) handlers.onStatus?.('error')
      } catch {
        if (ctrl.signal.aborted) return
        handlers.onStatus?.('error')
      }
      await new Promise((r) => setTimeout(r, 2000))
    }
  }
  void run()
  return () => ctrl.abort()
}
