/**
 * Integration-level tests of the operator live-feed reader (operator/liveFeed.ts, used by edgeRaw.subscribeLive)
 * with a scripted fetch and real Response / ReadableStream objects (review KA-02 / KA-04). No network, no camera.
 */
import { done, eq, ok, test } from '../shared/testkit.ts'
import { MAX_AUTH_CLOSES, runLiveFeed, type LiveFeedDeps } from './liveFeed.ts'

const DECISION = 'event: decision\ndata: {"attempt_id":"att_1","decision":"ALLOW"}\n\n'
const AUTH_END = 'event: auth\ndata: {"reason":"SESSION_ENDED"}\n\n'

interface Log {
  fetches: number
  sleeps: number[]
  events: string[]
  httpAuth: Array<[number, string | null]>
  authEvents: Array<string | null>
  closed: Array<{ status: number | null; reason: string | null }>
}

/** Run the feed against scripted responses; each script entry is one connection. Ends when the feed stops
 *  or the script runs out (the fake fetch then aborts). */
async function run(script: Array<() => Response>): Promise<Log> {
  const log: Log = { fetches: 0, sleeps: [], events: [], httpAuth: [], authEvents: [], closed: [] }
  const ctrl = new AbortController()
  const deps: LiveFeedDeps = {
    url: 'http://edge.test/v1/events',
    headers: { Authorization: 'Bearer fgs_test' },
    fetch: async () => {
      const next = script[log.fetches]
      log.fetches += 1
      if (!next) {
        ctrl.abort()
        throw new DOMException('aborted', 'AbortError')
      }
      return next()
    },
    sleep: async (ms) => {
      log.sleeps.push(ms)
    },
    onEvent: (event) => log.events.push(event),
    onHttpAuth: (status, reason) => log.httpAuth.push([status, reason]),
    onAuthEvent: (reason) => log.authEvents.push(reason),
    onClosed: (info) => log.closed.push(info),
  }
  await runLiveFeed(deps, ctrl.signal)
  return log
}

const body401 = () => new Response(JSON.stringify({ error: { code: 'UNAUTHORIZED', reason: 'SESSION_EXPIRED' } }), { status: 401 })
const body403 = () => new Response(JSON.stringify({ error: { code: 'FORBIDDEN', reason: 'MISSING_PERMISSION' } }), { status: 403 })

async function main(): Promise<void> {
  const a = await run([body401, () => new Response(DECISION)])
  test('401 stops for good: reported once, never reconnects', () => {
    eq(a.fetches, 1, 'fetches')
    eq(a.httpAuth, [[401, 'SESSION_EXPIRED']], 'httpAuth')
    eq(a.closed, [{ status: 401, reason: 'SESSION_EXPIRED' }], 'closed')
  })

  const b = await run([body403])
  test('403 stops for good and is reported (permission re-check)', () => {
    eq(b.fetches, 1, 'fetches')
    eq(b.httpAuth, [[403, 'MISSING_PERMISSION']], 'httpAuth')
  })

  // KA-02: the edge always says SESSION_ENDED; the reconnect's HTTP status decides what it meant.
  const c = await run([() => new Response(DECISION + AUTH_END), body401])
  test('event: auth -> one verifying reconnect; the 401 then signs out', () => {
    eq(c.events, ['decision'], 'events')
    eq(c.fetches, 2, 'fetches')
    eq(c.httpAuth, [[401, 'SESSION_EXPIRED']], 'httpAuth')
    eq(c.authEvents, [], 'not treated as terminal by itself')
  })

  const d = await run([() => new Response(AUTH_END), () => new Response(DECISION)])
  test('event: auth while the session is still valid -> the feed resumes', () => {
    eq(d.events, ['decision'], 'events after reconnect')
    eq(d.closed, [], 'not closed')
  })

  const e = await run(Array.from({ length: MAX_AUTH_CLOSES + 2 }, () => () => new Response(AUTH_END)))
  test(`${MAX_AUTH_CLOSES} auth closes in a row (connect accepted, then closed) -> stop for good, with backoff`, () => {
    eq(e.fetches, MAX_AUTH_CLOSES, 'fetches')
    eq(e.authEvents, ['SESSION_ENDED'], 'final auth report')
    eq(e.closed.length, 1, 'closed once')
    ok(e.sleeps.length === MAX_AUTH_CLOSES - 1 && e.sleeps[1] > e.sleeps[0], `backoff grows: ${JSON.stringify(e.sleeps)}`)
  })

  const f = await run([() => new Response('busy', { status: 429, headers: { 'Retry-After': '7' } }), () => new Response(DECISION)])
  test('429 (16-stream cap) waits Retry-After, then reconnects', () => {
    eq(f.sleeps[0], 7000, 'delay')
    eq(f.events, ['decision'], 'events')
  })

  done('liveFeed.test.ts')
}

await main()
