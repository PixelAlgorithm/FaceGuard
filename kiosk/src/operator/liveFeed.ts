/**
 * The operator live-feed reader (GET /v1/events), with every side effect injected so it runs under plain Node
 * with a scripted fetch (operator/liveFeed.test.ts). edgeRaw.subscribeLive wires it to the real edge.
 *
 * Rules (design v2 §F, edge/events.py):
 *  - HTTP 401 / 403: stop for good and report it (401 on a session signs the UI out, 403 re-reads /v1/auth/me).
 *  - `event: auth`: the edge closes the stream when `authorized()` fails and ALWAYS says reason SESSION_ENDED,
 *    whether the session ended, events:read was lost, or the auth store could not be read (review KA-02). The
 *    event alone is therefore not proof of sign-out: the reader reconnects once to verify, and the HTTP status
 *    of that connect decides (401 / 403 -> stop as above; 200 -> the feed resumes). If the edge keeps
 *    accepting and then closing (MAX_AUTH_CLOSES in a row with no real event between), it stops for good.
 *  - 429 (16-stream cap): wait Retry-After; other failures: reconnect after 2 s.
 */
import { RECONNECT_DEFAULT_MS, RECONNECT_MAX_MS, authEventReason, reconnectDelayMs, sseStopsOn, takeSseEvents } from './sse.ts'

/** `event: auth` closes in a row (with no real event between) before the feed stops for good. */
export const MAX_AUTH_CLOSES = 3

export interface LiveFeedDeps {
  url: string
  headers: Record<string, string>
  fetch: (url: string, init: RequestInit) => Promise<Response>
  sleep: (ms: number) => Promise<void>
  /** one complete SSE event other than `auth` (data still JSON text) */
  onEvent: (event: string, data: string) => void
  onStatus?: (status: 'connecting' | 'open' | 'error') => void
  /** the edge answered 401 / 403 (reason = error.reason) */
  onHttpAuth: (status: number, reason: string | null) => void
  /** the feed stopped after repeated `event: auth` closes */
  onAuthEvent: (reason: string | null) => void
  /** the feed ended for an auth reason and will not reconnect */
  onClosed: (info: { status: number | null; reason: string | null }) => void
}

/** Backoff after the n-th consecutive `event: auth` close (n >= 1): 2 s, 4 s, 8 s ... capped. */
export function authBackoffMs(n: number): number {
  return Math.min(RECONNECT_MAX_MS, RECONNECT_DEFAULT_MS * 2 ** Math.max(0, n - 1))
}

function errorReason(text: string): string | null {
  try {
    const o: unknown = JSON.parse(text)
    const err = o && typeof o === 'object' ? (o as { error?: unknown }).error : null
    return err && typeof err === 'object' && typeof (err as { reason?: unknown }).reason === 'string' ? (err as { reason: string }).reason : null
  } catch {
    return null
  }
}

type ReadOutcome = { kind: 'stop' } | { kind: 'reconnect'; delayMs: number }

/** Runs until `signal` aborts or the feed stops for good. Never throws. */
export async function runLiveFeed(deps: LiveFeedDeps, signal: AbortSignal): Promise<void> {
  let authCloses = 0

  const readOnce = async (): Promise<ReadOutcome> => {
    const res = await deps.fetch(deps.url, { headers: { Accept: 'text/event-stream', ...deps.headers }, signal })
    if (sseStopsOn(res.status)) {
      const reason = errorReason(await res.text().catch(() => ''))
      deps.onHttpAuth(res.status, reason)
      deps.onStatus?.('error')
      deps.onClosed({ status: res.status, reason })
      return { kind: 'stop' }
    }
    if (!res.ok || !res.body) return { kind: 'reconnect', delayMs: reconnectDelayMs(res.status, res.headers.get('Retry-After')) }
    deps.onStatus?.('open')
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader()
    let buf = ''
    for (;;) {
      const { value, done } = await reader.read()
      if (done) return { kind: 'reconnect', delayMs: RECONNECT_DEFAULT_MS }
      const parsed = takeSseEvents(buf + value)
      buf = parsed.rest
      for (const ev of parsed.events) {
        if (ev.event !== 'auth') {
          authCloses = 0 // a real event proves the session works
          deps.onEvent(ev.event, ev.data)
          continue
        }
        void reader.cancel().catch(() => undefined)
        authCloses += 1
        const reason = authEventReason(ev.data)
        if (authCloses >= MAX_AUTH_CLOSES) {
          deps.onAuthEvent(reason)
          deps.onStatus?.('error')
          deps.onClosed({ status: null, reason })
          return { kind: 'stop' }
        }
        return { kind: 'reconnect', delayMs: authBackoffMs(authCloses) }
      }
    }
  }

  while (!signal.aborted) {
    deps.onStatus?.('connecting')
    let delayMs = RECONNECT_DEFAULT_MS
    try {
      const out = await readOnce()
      if (out.kind === 'stop') return
      delayMs = out.delayMs
    } catch {
      if (signal.aborted) return
    }
    if (signal.aborted) return
    deps.onStatus?.('error')
    await deps.sleep(delayMs)
  }
}
