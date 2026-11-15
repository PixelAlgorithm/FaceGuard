/** Unit tests for operator/sse.ts (design v2 §F: SSE stops on 401/403 and on `event: auth`; audit KAO-06/10). */
import { done, eq, test } from '../shared/testkit.ts'
import { reconnectDelayMs, sseStopsOn, takeSseEvents } from './sse.ts'

test('401 and 403 stop the live feed for good (no reconnect loop)', () => {
  eq(sseStopsOn(401), true, '401')
  eq(sseStopsOn(403), true, '403')
  eq(sseStopsOn(503), false, '503 retries')
  eq(sseStopsOn(200), false, '200')
})

test('complete blocks are parsed; a partial block stays in the buffer', () => {
  const r = takeSseEvents('event: decision\ndata: {"a":1}\n\nevent: auth\ndata: {"reason":"SESSION_EXPIRED"}\n\nevent: dec')
  eq(r.events, [
    { event: 'decision', data: '{"a":1}' },
    { event: 'auth', data: '{"reason":"SESSION_EXPIRED"}' },
  ], 'events')
  eq(r.rest, 'event: dec', 'rest')
})

test('CRLF, multi-line data and the default `message` event', () => {
  const r = takeSseEvents('data: line1\r\ndata: line2\r\n\r\n: heartbeat\n\n')
  eq(r.events, [{ event: 'message', data: 'line1\nline2' }], 'events (heartbeat comment dropped)')
})

// edge-app item 9: /v1/events capped at 16 streams -> 429 + Retry-After.
test('429 waits Retry-After seconds (bounded), other failures 2 s', () => {
  eq(reconnectDelayMs(429, '7'), 7000, '429 7 s')
  eq(reconnectDelayMs(429, null), 2000, '429 without header')
  eq(reconnectDelayMs(429, '9999'), 60000, 'capped')
  eq(reconnectDelayMs(503, '7'), 2000, 'other')
})

done('sse.test.ts')
