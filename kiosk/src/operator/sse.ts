/**
 * Pure server-sent-events helpers for the operator live feed (operator/edgeRaw.ts subscribeLive), unit-tested
 * with plain Node. Design v2 §F: the reader stops (never reconnects) on HTTP 401/403 and on `event: auth`;
 * other failures reconnect.
 */

/** HTTP statuses after which the live feed must not reconnect (credential missing, expired or not allowed). */
const AUTH_STOP_STATUSES: ReadonlySet<number> = new Set([401, 403])

export function sseStopsOn(status: number): boolean {
  return AUTH_STOP_STATUSES.has(status)
}

export interface SseEvent {
  event: string
  data: string
}

/**
 * Split a text buffer into complete SSE events (blank-line separated). Returns the events and the unparsed
 * remainder. Comment-only blocks (`: heartbeat`) and blocks without data are dropped.
 */
export function takeSseEvents(buffer: string): { events: SseEvent[]; rest: string } {
  let buf = buffer.replace(/\r\n/g, '\n')
  const events: SseEvent[] = []
  let sep: number
  while ((sep = buf.indexOf('\n\n')) >= 0) {
    const lines = buf.slice(0, sep).split('\n')
    buf = buf.slice(sep + 2)
    const event = lines.find((l) => l.startsWith('event:'))?.slice(6).trim() || 'message'
    const data = lines
      .filter((l) => l.startsWith('data:'))
      .map((l) => l.slice(5).replace(/^ /, ''))
      .join('\n')
    if (data) events.push({ event, data })
  }
  return { events, rest: buf }
}

/** `reason` of an `event: auth` payload (JSON {reason}), else null. */
export function authEventReason(data: string): string | null {
  try {
    const o: unknown = JSON.parse(data)
    return o && typeof o === 'object' && typeof (o as { reason?: unknown }).reason === 'string' ? (o as { reason: string }).reason : null
  } catch {
    return null
  }
}

/** Reconnect delays: default, and the ceiling for an edge Retry-After (edge-app: 16-stream cap -> 429). */
export const RECONNECT_DEFAULT_MS = 2000
export const RECONNECT_MAX_MS = 60_000

/** How long to wait before reconnecting after a failed connection (`retryAfter` = Retry-After header). */
export function reconnectDelayMs(status: number | null, retryAfter: string | null): number {
  if (status !== 429 || retryAfter === null) return RECONNECT_DEFAULT_MS
  const s = Number(retryAfter)
  if (!Number.isFinite(s) || s <= 0) return RECONNECT_DEFAULT_MS
  return Math.min(RECONNECT_MAX_MS, Math.round(s * 1000))
}
