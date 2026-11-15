/**
 * Real edge client (FastAPI on the kiosk laptop). Endpoints exactly as in the API contract.
 * Privileged calls send the caller's credential (credentials.ts: Bearer fgs_/fgk_, legacy X-Admin-Token),
 * `X-FG-Activity: 1` when user-initiated, and report a 401 on a session request to the auth layer.
 */
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
import {
  parseApiKeyCreated,
  parseApiKeyList,
  parseAuthAuditPage,
  parseAuthMe,
  parseAuthStatus,
  parseLoginResult,
  parseMfaEnrolment,
  parseRolesCatalog,
  parseStaffItem,
  parseStaffList,
} from './authParse'
import type {
  ApiKeyCreate,
  ApiKeyCreated,
  ApiKeyInfo,
  AuditQuery,
  AuthAuditPage,
  AuthMe,
  AuthStatus,
  LoginRequest,
  LoginResult,
  MfaEnrolment,
  PasswordChange,
  Reauth,
  RolesCatalog,
  StaffAccount,
  StaffCreate,
  StaffPasswordReset,
  StaffUpdate,
} from './authTypes'
import {
  activityHeaders,
  authHeaders,
  credentialError,
  handleSseAuthEvent,
  notifyUnauthorized,
  requestAuthRecheck,
  shouldSignOutOn401,
} from './credentials'
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
  type SetModeOptions,
} from './types'

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

/** Edge error body -> ApiError with code + reason + extra fields; Retry-After header fills retry_after_s. */
function errorFromResponse(res: Response, body: unknown): ApiError {
  const err = apiErrorFromBody(res.status, body)
  if (err.extra.retry_after_s != null) return err
  const header = Number(res.headers.get('Retry-After'))
  if (!Number.isFinite(header) || header <= 0) return err
  return new ApiError(err.code, err.status, err.message, err.attemptId, { ...err.extra, retry_after_s: header })
}

/** 403 reasons after which /v1/auth/me is re-read (roles changed, or the session became confined). */
const RECHECK_403 = new Set(['MISSING_PERMISSION', 'PASSWORD_CHANGE_REQUIRED', 'MFA_ENROLMENT_REQUIRED'])

/** After an error on a privileged call: 401 on a session -> sign out; RECHECK_403 -> re-read /me. */
function reportAuthFailure(path: string, token: string, err: ApiError): void {
  if (err.status === 401 && shouldSignOutOn401(path, token)) notifyUnauthorized({ path, reason: err.reason, token })
  else if (err.status === 403 && err.reason !== null && RECHECK_403.has(err.reason)) requestAuthRecheck({ path, reason: err.reason, token })
}

/** SSE: HTTP status codes after which the reader stops for good (no reconnect loop on a dead session). */
const SSE_AUTH_STOP = new Set([401, 403])

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

  /**
   * One edge call. `token` (privileged calls only, '' allowed) adds the credential + activity headers and
   * routes a 401/403 to the auth layer. A credential that cannot be sent in a header is BAD_CREDENTIAL,
   * never reported as "edge unreachable" (audit KAO-12).
   */
  private async request(path: string, init: RequestInit, timeoutMs: number, token?: string): Promise<unknown> {
    let finalInit = init
    if (token !== undefined) {
      const bad = credentialError(token)
      if (bad) throw new ApiError('BAD_CREDENTIAL', 0, bad)
      const method = init.method ?? 'GET'
      finalInit = { ...init, headers: { ...(init.headers as Record<string, string> | undefined), ...authHeaders(token), ...activityHeaders(method) } }
    }
    const ctrl = new AbortController()
    const timer = window.setTimeout(() => ctrl.abort(), timeoutMs)
    let res: Response
    try {
      res = await fetch(this.baseUrl + path, { ...finalInit, signal: ctrl.signal })
    } catch (e) {
      window.clearTimeout(timer)
      if (ctrl.signal.aborted) throw new ApiError('TIMEOUT', 0, `${path} timed out after ${timeoutMs} ms (the edge may still have applied it)`)
      throw new ApiError('NETWORK', 0, `Edge unreachable (${path}): ${e instanceof Error ? e.message : String(e)}`)
    }
    try {
      const text = await res.text()
      const body = text ? parseJson(text) : null
      if (!res.ok) {
        const err = errorFromResponse(res, body)
        if (token) reportAuthFailure(path, token, err)
        throw err
      }
      return body
    } catch (e) {
      if (e instanceof ApiError) throw e
      if (ctrl.signal.aborted) throw new ApiError('TIMEOUT', 0, `${path} timed out after ${timeoutMs} ms (the edge may still have applied it)`)
      throw new ApiError('NETWORK', 0, `Edge response failed (${path})`)
    } finally {
      window.clearTimeout(timer)
    }
  }

  private sendJson(method: string, path: string, body: unknown, timeoutMs: number, token?: string, cache?: RequestCache) {
    return this.request(
      path,
      { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), ...(cache ? { cache } : {}) },
      timeoutMs,
      token,
    )
  }

  private postJson(path: string, body: unknown, timeoutMs: number, token?: string) {
    return this.sendJson('POST', path, body, timeoutMs, token)
  }

  private get(path: string, timeoutMs: number, token: string) {
    return this.request(path, { method: 'GET' }, timeoutMs, token)
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

  async getMetrics(token: string): Promise<MetricsResponse> {
    return ((await this.get('/v1/metrics', UI.timeouts.admin, token)) ?? {}) as MetricsResponse
  }

  setMode(token: string, force: ForceMode, opts: SetModeOptions = {}): Promise<unknown> {
    return this.postJson('/v1/admin/mode', { force, ...opts }, UI.timeouts.admin, token)
  }

  async getModeDetail(token: string): Promise<ModeResponse> {
    return normalizeMode(await this.get('/v1/admin/mode/detail', UI.timeouts.mode, token))
  }

  getStore(token: string): Promise<unknown> {
    return this.get('/v1/admin/store', UI.timeouts.admin, token)
  }

  triggerSync(token: string): Promise<unknown> {
    return this.postJson('/v1/admin/sync', {}, UI.timeouts.admin, token)
  }

  setEvalContext(token: string, ctx: EvalContext): Promise<unknown> {
    return this.postJson('/v1/admin/eval/context', ctx, UI.timeouts.admin, token)
  }

  clearEvalContext(token: string): Promise<unknown> {
    return this.request('/v1/admin/eval/context', { method: 'DELETE' }, UI.timeouts.admin, token)
  }

  resetRateLimit(token: string): Promise<unknown> {
    return this.postJson('/v1/admin/rate-limit/reset', {}, UI.timeouts.admin, token)
  }

  async setDemoClock(token: string, req: DemoClockRequest): Promise<DemoClockStatus> {
    return parseDemoClock(await this.postJson('/v1/admin/clock', req, UI.timeouts.admin, token), 'admin.clock')
  }

  setRandomChallenge(token: string, mode: RandomChallengeMode): Promise<unknown> {
    return this.postJson('/v1/admin/random-challenge', { mode }, UI.timeouts.admin, token)
  }

  getAttemptSignals(token: string, attemptId: string): Promise<unknown> {
    return this.get(`/v1/admin/attempt/${encodeURIComponent(attemptId)}/signals`, UI.timeouts.admin, token)
  }

  async enroll(token: string, frames: Blob[], meta: EnrollMeta): Promise<EnrollResponse> {
    const form = new FormData()
    frames.forEach((blob, i) => form.append(`frame_${i}`, blob, `frame_${i}.jpg`))
    form.append('meta', JSON.stringify(meta))
    // no-store: the response may carry the shown-once TOTP provisioning URI
    return parseEnroll(await this.request('/v1/enroll', { method: 'POST', body: form, cache: 'no-store' }, UI.timeouts.enroll, token))
  }

  async deleteEnrollment(token: string, userId: string): Promise<EraseResponse> {
    return parseErase(await this.request(`/v1/enroll/${encodeURIComponent(userId)}`, { method: 'DELETE' }, UI.timeouts.accessAdmin, token))
  }

  async listEnrolledUsers(token: string): Promise<EnrolledUsersResponse> {
    return parseEnrolledUsers(await this.get('/v1/admin/users', UI.timeouts.admin, token))
  }

  async listAccessUsers(token: string): Promise<AccessUsersResponse> {
    // The edge merges the cloud master list (one cloud round trip) with the installed bundle + local enrolments.
    return parseAccessUsers(await this.get('/v1/admin/access/users', UI.timeouts.accessAdmin, token))
  }

  async putAccessUser(token: string, userId: string, req: AccessUpdate): Promise<AccessUpdateResult> {
    return parseAccessUpdate(await this.sendJson('PUT', `/v1/admin/access/users/${encodeURIComponent(userId)}`, req, UI.timeouts.accessAdmin, token))
  }

  async revokeAccessUser(token: string, userId: string, req: RevokeRequest): Promise<RevokeResult> {
    return parseRevoke(await this.postJson(`/v1/admin/access/users/${encodeURIComponent(userId)}/revoke`, req, UI.timeouts.accessAdmin, token))
  }

  async rotateStaffCodes(token: string, req: RotateCodesRequest): Promise<RotateCodesResult> {
    // no-store on the response; the plaintext codes live only in the caller's component state (R-D)
    return parseRotate(await this.sendJson('POST', '/v1/admin/access/codes/rotate', req, UI.timeouts.accessAdmin, token, 'no-store'))
  }

  async refreshBundle(token: string): Promise<BundleRefresh> {
    return parseRefresh(await this.postJson('/v1/admin/bundle/refresh', {}, UI.timeouts.accessAdmin, token))
  }

  // ---------------------------------------------------------------- authentication (design v2 §C)

  async authStatus(): Promise<AuthStatus> {
    return parseAuthStatus(await this.request('/v1/auth/status', { method: 'GET' }, UI.timeouts.admin))
  }

  async login(req: LoginRequest): Promise<LoginResult> {
    // No credential header: a 401 here is a wrong password / MFA step, never "session expired".
    return parseLoginResult(await this.sendJson('POST', '/v1/auth/login', req, UI.timeouts.auth, undefined, 'no-store'))
  }

  async logout(token: string): Promise<void> {
    await this.postJson('/v1/auth/logout', {}, UI.timeouts.admin, token)
  }

  async me(token: string): Promise<AuthMe> {
    return parseAuthMe(await this.get('/v1/auth/me', UI.timeouts.admin, token))
  }

  async changePassword(token: string, req: PasswordChange): Promise<void> {
    await this.postJson('/v1/auth/password', req, UI.timeouts.auth, token)
  }

  async mfaEnroll(token: string, currentPassword: string): Promise<MfaEnrolment> {
    // current_password is required by the edge (re-authentication; 422 when missing, 403 REAUTH_REQUIRED when wrong)
    const body = { current_password: currentPassword }
    return parseMfaEnrolment(await this.sendJson('POST', '/v1/auth/mfa/enroll', body, UI.timeouts.auth, token, 'no-store'))
  }


  async mfaConfirm(token: string, totpCode: string): Promise<void> {
    await this.postJson('/v1/auth/mfa/confirm', { totp_code: totpCode }, UI.timeouts.auth, token)
  }

  async noteActivity(token: string): Promise<void> {
    await this.postJson('/v1/auth/activity', {}, UI.timeouts.admin, token)
  }

  async listStaff(token: string): Promise<StaffAccount[]> {
    return parseStaffList(await this.get('/v1/admin/staff', UI.timeouts.admin, token))
  }

  async createStaff(token: string, req: StaffCreate): Promise<StaffAccount | null> {
    return parseStaffItem(await this.sendJson('POST', '/v1/admin/staff', req, UI.timeouts.auth, token, 'no-store'))
  }

  async updateStaff(token: string, staffId: string, req: StaffUpdate): Promise<StaffAccount | null> {
    return parseStaffItem(await this.sendJson('PATCH', `/v1/admin/staff/${encodeURIComponent(staffId)}`, req, UI.timeouts.auth, token))
  }

  async resetStaffPassword(token: string, staffId: string, req: StaffPasswordReset): Promise<void> {
    await this.sendJson('POST', `/v1/admin/staff/${encodeURIComponent(staffId)}/password`, req, UI.timeouts.auth, token, 'no-store')
  }

  async unlockStaff(token: string, staffId: string, req: Reauth): Promise<void> {
    await this.postJson(`/v1/admin/staff/${encodeURIComponent(staffId)}/unlock`, req, UI.timeouts.auth, token)
  }

  async listApiKeys(token: string): Promise<ApiKeyInfo[]> {
    return parseApiKeyList(await this.get('/v1/admin/api-keys', UI.timeouts.admin, token))
  }

  async createApiKey(token: string, req: ApiKeyCreate): Promise<ApiKeyCreated> {
    return parseApiKeyCreated(await this.sendJson('POST', '/v1/admin/api-keys', req, UI.timeouts.auth, token, 'no-store'))
  }

  async revokeApiKey(token: string, keyId: string, req: Reauth): Promise<void> {
    await this.sendJson('DELETE', `/v1/admin/api-keys/${encodeURIComponent(keyId)}`, req, UI.timeouts.auth, token)
  }

  async listRoles(token: string): Promise<RolesCatalog> {
    return parseRolesCatalog(await this.get('/v1/admin/roles', UI.timeouts.admin, token))
  }

  async listAuthAudit(token: string, q: AuditQuery = {}): Promise<AuthAuditPage> {
    const p = new URLSearchParams()
    if (q.limit) p.set('limit', String(q.limit))
    if (q.before_seq != null) p.set('before_seq', String(q.before_seq))
    const qs = p.toString()
    return parseAuthAuditPage(await this.get(`/v1/admin/auth/audit${qs ? `?${qs}` : ''}`, UI.timeouts.admin, token))
  }

  /**
   * GET /v1/events as Server-Sent Events, read via fetch() so the Authorization header can be sent
   * (EventSource cannot set headers). Reconnects every 2 s until unsubscribed - except after HTTP 401/403
   * or the edge's final `event: auth`: then it stops for good (onAuthClosed) and, for a dead session,
   * the auth layer signs the console out.
   */
  subscribeEvents(token: string, handlers: EdgeEventsHandlers): () => void {
    const ctrl = new AbortController()
    const path = '/v1/events'
    const stop = (status: number | null, reason: string | null) => {
      ctrl.abort()
      handlers.onStatus?.('error')
      handlers.onAuthClosed?.({ status, reason })
    }
    const bad = credentialError(token)
    if (bad) {
      queueMicrotask(() => stop(null, 'BAD_CREDENTIAL'))
      return () => ctrl.abort()
    }
    const run = async () => {
      while (!ctrl.signal.aborted) {
        handlers.onStatus?.('connecting')
        try {
          const res = await fetch(this.baseUrl + path, { headers: { Accept: 'text/event-stream', ...authHeaders(token) }, signal: ctrl.signal })
          if (SSE_AUTH_STOP.has(res.status)) {
            const err = errorFromResponse(res, parseJson(await res.text().catch(() => '')))
            reportAuthFailure(path, token, err)
            stop(res.status, err.reason)
            return
          }
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
              if (event === 'auth') {
                const o = parseJson(data)
                const reason = o && typeof o === 'object' && typeof (o as { reason?: unknown }).reason === 'string' ? (o as { reason: string }).reason : null
                void reader.cancel().catch(() => undefined)
                handleSseAuthEvent(path, token, reason)
                stop(null, reason)
                return
              }
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
