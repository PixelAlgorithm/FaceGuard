/** Unit tests for the control panel's pure rules: audit paging, staff-code gate, store integrity banner. */
import type { AuthAuditEntry } from '../api/authTypes'
import { done, eq, ok, test } from '../shared/testkit.ts'
import { mergeAudit, olderCursor } from './auditPages.ts'
import { OWN_CODES_MAX, codesGate } from './codesGate.ts'
import { storeIntegrity } from './storeIntegrity.ts'

const entry = (seq: number, outcome = 'ok', count: number | null = null): AuthAuditEntry => ({
  seq,
  ts_utc: null,
  actor: { kind: 'staff', id: 's1', username: 'ada' },
  action: 'auth.login',
  target: null,
  outcome,
  client_ip: null,
  detail: null,
  count,
})
const range = (hi: number, lo: number) => Array.from({ length: hi - lo + 1 }, (_, i) => entry(hi - i))
const seqs = (xs: readonly AuthAuditEntry[]) => xs.map((e) => e.seq)

test('audit: a newer head after "load older" leaves no gap (entries that left the head are kept)', () => {
  let held = mergeAudit([], range(200, 101)) // first head
  held = mergeAudit(held, range(100, 1)) // load older
  held = mergeAudit(held, range(205, 106)) // head poll after 5 new entries
  eq(seqs(held), Array.from({ length: 205 }, (_, i) => 205 - i), 'every seq 205..1 once, newest first')
})
test('audit: duplicates collapse and the newer copy wins (aggregated denial count grows)', () => {
  const held = mergeAudit([entry(3, 'denied', 2), entry(2)], [entry(3, 'denied', 5)])
  eq(seqs(held), [3, 2], 'order')
  eq(held[0]?.count, 5, 'newer count')
})
test('audit: the older cursor comes from the last older page, else from the first head', () => {
  eq(olderCursor(undefined, 101), 101, 'head cursor before any older load')
  eq(olderCursor(null, 101), null, 'older pages exhausted')
  eq(olderCursor(40, 106), 40, 'older page cursor wins over a moving head')
  eq(olderCursor(undefined, null), null, 'nothing older')
})

test('codes: codes:rotate = own staff id only, at most OWN_CODES_MAX', () => {
  const g = codesGate({ rotate: true, rotateAny: false }, 's_guard01')
  ok(g.mayRotate && g.ownOnly && !g.noIdentity, JSON.stringify(g))
  eq(g.maxCount, OWN_CODES_MAX, 'max count')
})
test('codes: codes:rotate_any may target anyone (model limit 10)', () => {
  const g = codesGate({ rotate: true, rotateAny: true }, 's_admin')
  ok(g.mayRotate && !g.ownOnly && !g.noIdentity, JSON.stringify(g))
  eq(g.maxCount, 10, 'max count')
})
test('codes: a principal without a staff identity is refused even with codes:rotate_any (edge NO_STAFF_IDENTITY)', () => {
  for (const perms of [{ rotate: true, rotateAny: false }, { rotate: true, rotateAny: true }, { rotate: false, rotateAny: true }]) {
    const g = codesGate(perms, null)
    ok(!g.mayRotate && g.noIdentity, JSON.stringify([perms, g]))
  }
})
test('codes: no permission -> no rotation and no identity notice', () => {
  const g = codesGate({ rotate: false, rotateAny: false }, 's_x')
  ok(!g.mayRotate && !g.noIdentity, JSON.stringify(g))
})

test('store: an intact chain from a FAILED refresh is never shown as PASS (KAO-07)', () => {
  const body = { chain_ok: true, chain_bad_seq: [], records: [{ seq: 1 }] }
  eq(storeIntegrity(body).ok, true, 'fresh')
  eq(storeIntegrity(body, { stale: true }).ok, null, 'stale')
})
test('store: a broken chain stays FAIL even when the data is stale', () => {
  eq(storeIntegrity({ chain_ok: false, records: [] }, { stale: true }).ok, false, 'stale fail')
})

done('admin/adminRules.test.ts')
