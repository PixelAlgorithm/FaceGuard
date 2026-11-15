/** Real edge client (FastAPI on the kiosk laptop). Endpoints exactly as in the API contract. */
import { UI } from '../config'
import {
  apiErrorFromBody,
  parseAccessUpdate,
  parseAccessUsers,
  parseDemoClock,
  parseEnroll,
  parseEnrolledUsers,
  parseErase,
  parseRefresh,
  parseRevoke,
  parseRotate,
} from './access'
import { normalizeDecision, normalizeMode } from './normalize'
import {
  ApiError,
  type AccessUpdate,
  type AccessUpdateResult,
  type AccessUsersResponse,
  type BundleRefresh,
  type DemoClockStatus,
  type EnrolledUsersResponse,
  type EraseResponse,
  type RevokeRequest,
  type RevokeResult,
  type RotateCodesRequest,
  type RotateCodesResult,
  type ChallengeMeta,
  type DecisionResponse,
  type DemoClockRequest,
  type EnrollMeta,
  type EnrollResponse,
  type EvalContext,
  type EdgeApi,
  type EdgeEventsHandlers,
  type FallbackRequest,
  type ForceMode,
  type FramesMeta,
  type HealthResponse,
  type MetricsResponse,
  type ModeResponse,
  type OtpSendResponse,
  type ProbeResponse,
  type RandomChallengeMode,
  type RenderedEvent,
  type RenderedReport,
  type SessionStartRequest,
  type SessionStartResponse,
} from './types'

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

/** Edge error body -> ApiError with code + reason + extra fields (API.md v1.4 §0 / §3.18.6). */
const errorFromBody = apiErrorFromBody

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/** SSE event types: `decision` (DecisionResponse + "eval") and `rendered`; untyped events are sniffed. */
function dispatchSse(event: string, payload: unknown, handlers: EdgeEventsHandlers): void {
  if (!payload || typeof payload !== 'object') return
  const o = payload as Record<string, unknown>
  if (event === 'rendered' || (event === 'message' && 'rendered_at_ms' in o && !('decision' in o))) {
    if (typeof o.attempt_id === 'string') handlers.onRendered?.(o as RenderedEvent)
    return
  }
  if ((event === 'decision' || event === 'message') && 'decision' in o) {
    const ev = o.eval && typeof o.eval === 'object' ? (o.eval as Record<string, unknown>) : null
    handlers.onDecision(normalizeDecision(o), ev)
  }
}

export class HttpEdgeApi implements EdgeApi {
  readonly kind = 'http' as const
  readonly baseUrl: string

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl
  }

  private async request(path: string, init: RequestInit, timeoutMs: number): Promise<unknown> {
    const ctrl = new AbortController()
    const timer = window.setTimeout(() => ctrl.abort(), timeoutMs)
    let res: Response
    try {
      res = await fetch(this.baseUrl + path, { ...init, signal: ctrl.signal })
    } catch (e) {
      window.clearTimeout(timer)
      if (ctrl.signal.aborted) throw new ApiError('TIMEOUT', 0, `${path} timed out after ${timeoutMs} ms`)
      throw new ApiError('NETWORK', 0, `Edge unreachable (${path}): ${e instanceof Error ? e.message : String(e)}`)
    }
    try {
      const text = await res.text()
      const body = text ? parseJson(text) : null
      if (!res.ok) throw errorFromBody(res.status, body)
      return body
    } catch (e) {
      if (e instanceof ApiError) throw e
      if (ctrl.signal.aborted) throw new ApiError('TIMEOUT', 0, `${path} timed out after ${timeoutMs} ms`)
      throw new ApiError('NETWORK', 0, `Edge response failed (${path})`)
    } finally {
      window.clearTimeout(timer)
    }
  }

  private postJson(path: string, body: unknown, timeoutMs: number, headers: Record<string, string> = {}) {
    return this.request(
      path,
      { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) },
      timeoutMs,
    )
  }

  async sessionStart(req: SessionStartRequest): Promise<SessionStartResponse> {
    const body = await this.postJson('/v1/session/start', req, UI.timeouts.sessionStart)
    const r = body as SessionStartResponse
    if (!r || typeof r.attempt_id !== 'string' || typeof r.nonce !== 'string') {
      throw new ApiError('BAD_RESPONSE', 200, 'session/start returned no attempt_id/nonce')
    }
    return {
      ...r,
      flash_sequence: Array.isArray(r.flash_sequence) ? r.flash_sequence : [],
      capture: {
        frames: r.capture?.frames ?? 5,
        window_ms: r.capture?.window_ms ?? 1000,
        max_width_px: r.capture?.max_width_px ?? 640,
        jpeg_quality: r.capture?.jpeg_quality ?? 0.85,
      },
    }
  }

  async submitFrames(attemptId: string, frames: Blob[], meta: FramesMeta): Promise<DecisionResponse> {
    const form = new FormData()
    frames.forEach((blob, i) => form.append(`frame_${i}`, blob, `frame_${i}.jpg`))
    // `meta` is sent as a plain text form field containing JSON (FastAPI: meta: str = Form(...)).
    form.append('meta', JSON.stringify(meta))
    const body = await this.request(
      `/v1/attempt/${encodeURIComponent(attemptId)}/frames`,
      { method: 'POST', body: form },
      UI.timeouts.frames,
    )
    return normalizeDecision(body)
  }

  /**
   * Early cloud probe (API.md v1.3 §3.1a): the face-lock frame as multipart part "probe", sent right after
   * session/start so the cloud match runs in parallel with the colour-flash capture. Fire-and-forget.
   */
  async submitProbe(attemptId: string, probe: Blob): Promise<ProbeResponse> {
    const form = new FormData()
    form.append('probe', probe, 'probe.jpg')
    const body = await this.request(
      `/v1/attempt/${encodeURIComponent(attemptId)}/probe`,
      { method: 'POST', body: form },
      UI.timeouts.frames,
    )
    const o = (body && typeof body === 'object' ? body : {}) as Partial<ProbeResponse>
    return { accepted: o.accepted === true, cloud: o.cloud === 'started' ? 'started' : 'skipped' }
  }

  async markRendered(attemptId: string, report: RenderedReport): Promise<void> {
    await this.postJson(`/v1/attempt/${encodeURIComponent(attemptId)}/rendered`, report, UI.timeouts.fallback)
  }

  async submitChallenge(attemptId: string, meta: ChallengeMeta, frame: Blob | null): Promise<DecisionResponse> {
    const form = new FormData()
    form.append('meta', JSON.stringify(meta))
    if (frame) form.append('frame_0', frame, 'frame_0.jpg')
    const body = await this.request(
      `/v1/attempt/${encodeURIComponent(attemptId)}/challenge`,
      { method: 'POST', body: form },
      UI.timeouts.challenge,
    )
    return normalizeDecision(body)
  }

  async sendOtp(attemptId: string): Promise<OtpSendResponse> {
    const body = (await this.postJson(
      `/v1/attempt/${encodeURIComponent(attemptId)}/otp/send`,
      {},
      UI.timeouts.fallback,
    )) as OtpSendResponse
    if (!body || typeof body.otp_id !== 'string') throw new ApiError('BAD_RESPONSE', 200, 'otp/send returned no otp_id')
    return body
  }

  async submitFallback(attemptId: string, req: FallbackRequest): Promise<DecisionResponse> {
    const body = await this.postJson(
      `/v1/attempt/${encodeURIComponent(attemptId)}/fallback`,
      req,
      UI.timeouts.fallback,
    )
    return normalizeDecision(body)
  }

  async getMode(): Promise<ModeResponse> {
    return normalizeMode(await this.request('/v1/mode', { method: 'GET' }, UI.timeouts.mode))
  }

  async getHealth(): Promise<HealthResponse> {
    return (await this.request('/v1/health', { method: 'GET' }, UI.timeouts.mode)) as HealthResponse
  }

  private admin(token: string): Record<string, string> {
    return token ? { 'X-Admin-Token': token } : {}
  }

  async getMetrics(token: string): Promise<MetricsResponse> {
    return ((await this.request('/v1/metrics', { method: 'GET', headers: this.admin(token) }, UI.timeouts.admin)) ??
      {}) as MetricsResponse
  }

  setMode(token: string, force: ForceMode): Promise<unknown> {
    return this.postJson('/v1/admin/mode', { force }, UI.timeouts.admin, this.admin(token))
  }

  getStore(token: string): Promise<unknown> {
    return this.request('/v1/admin/store', { method: 'GET', headers: this.admin(token) }, UI.timeouts.admin)
  }

  triggerSync(token: string): Promise<unknown> {
    return this.postJson('/v1/admin/sync', {}, UI.timeouts.admin, this.admin(token))
  }

  setEvalContext(token: string, ctx: EvalContext): Promise<unknown> {
    return this.postJson('/v1/admin/eval/context', ctx, UI.timeouts.admin, this.admin(token))
  }

  clearEvalContext(token: string): Promise<unknown> {
    return this.request('/v1/admin/eval/context', { method: 'DELETE', headers: this.admin(token) }, UI.timeouts.admin)
  }

  resetRateLimit(token: string): Promise<unknown> {
    return this.postJson('/v1/admin/rate-limit/reset', {}, UI.timeouts.admin, this.admin(token))
  }

  async setDemoClock(token: string, req: DemoClockRequest): Promise<DemoClockStatus> {
    return parseDemoClock(await this.postJson('/v1/admin/clock', req, UI.timeouts.admin, this.admin(token)), 'admin.clock')
  }

  setRandomChallenge(token: string, mode: RandomChallengeMode): Promise<unknown> {
    return this.postJson('/v1/admin/random-challenge', { mode }, UI.timeouts.admin, this.admin(token))
  }

  getAttemptSignals(token: string, attemptId: string): Promise<unknown> {
    return this.request(
      `/v1/admin/attempt/${encodeURIComponent(attemptId)}/signals`,
      { method: 'GET', headers: this.admin(token) },
      UI.timeouts.admin,
    )
  }

  async enroll(token: string, frames: Blob[], meta: EnrollMeta): Promise<EnrollResponse> {
    const form = new FormData()
    frames.forEach((blob, i) => form.append(`frame_${i}`, blob, `frame_${i}.jpg`))
    form.append('meta', JSON.stringify(meta))
    return parseEnroll(await this.request('/v1/enroll', { method: 'POST', body: form, headers: this.admin(token) }, 30000))
  }

  async deleteEnrollment(token: string, userId: string): Promise<EraseResponse> {
    return parseErase(
      await this.request(`/v1/enroll/${encodeURIComponent(userId)}`, { method: 'DELETE', headers: this.admin(token) }, UI.timeouts.accessAdmin),
    )
  }

  async listEnrolledUsers(token: string): Promise<EnrolledUsersResponse> {
    return parseEnrolledUsers(await this.request('/v1/admin/users', { method: 'GET', headers: this.admin(token) }, UI.timeouts.admin))
  }

  async listAccessUsers(token: string): Promise<AccessUsersResponse> {
    // The edge merges the cloud master list (one cloud round trip) with the installed bundle + local enrolments.
    return parseAccessUsers(
      await this.request('/v1/admin/access/users', { method: 'GET', headers: this.admin(token) }, UI.timeouts.accessAdmin),
    )
  }

  async putAccessUser(token: string, userId: string, req: AccessUpdate): Promise<AccessUpdateResult> {
    const body = await this.request(
      `/v1/admin/access/users/${encodeURIComponent(userId)}`,
      { method: 'PUT', headers: { 'Content-Type': 'application/json', ...this.admin(token) }, body: JSON.stringify(req) },
      UI.timeouts.accessAdmin,
    )
    return parseAccessUpdate(body)
  }

  async revokeAccessUser(token: string, userId: string, req: RevokeRequest): Promise<RevokeResult> {
    return parseRevoke(
      await this.postJson(`/v1/admin/access/users/${encodeURIComponent(userId)}/revoke`, req, UI.timeouts.accessAdmin, this.admin(token)),
    )
  }

  async rotateStaffCodes(token: string, req: RotateCodesRequest): Promise<RotateCodesResult> {
    // no-store on the response; the plaintext codes live only in the caller's component state (R-D)
    return parseRotate(
      await this.request(
        '/v1/admin/access/codes/rotate',
        { method: 'POST', headers: { 'Content-Type': 'application/json', ...this.admin(token) }, body: JSON.stringify(req), cache: 'no-store' },
        UI.timeouts.accessAdmin,
      ),
    )
  }

  async refreshBundle(token: string): Promise<BundleRefresh> {
    return parseRefresh(await this.postJson('/v1/admin/bundle/refresh', {}, UI.timeouts.accessAdmin, this.admin(token)))
  }

  /**
   * GET /v1/events as Server-Sent Events, read via fetch() so the X-Admin-Token header can be sent
   * (EventSource cannot set headers). Reconnects every 2 s until unsubscribed.
   */
  subscribeEvents(token: string, handlers: EdgeEventsHandlers): () => void {
    const ctrl = new AbortController()
    const run = async () => {
      while (!ctrl.signal.aborted) {
        handlers.onStatus?.('connecting')
        try {
          const res = await fetch(this.baseUrl + '/v1/events', {
            headers: { Accept: 'text/event-stream', ...this.admin(token) },
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
              if (!data) continue
              dispatchSse(event, parseJson(data), handlers)
            }
          }
          if (!ctrl.signal.aborted) handlers.onStatus?.('error')
        } catch {
          if (ctrl.signal.aborted) return
          handlers.onStatus?.('error')
        }
        await sleep(2000)
      }
    }
    void run()
    return () => ctrl.abort()
  }
}
