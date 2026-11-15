/**
 * Unit tests for admin/storeIntegrity.ts (audit KAO-07): the SC2 store banner says PASS only for an explicit
 * chain_ok:true with no bad sequence numbers and no undecryptable row; anything else is FAIL or unknown.
 */
import { done, eq, ok, test } from '../shared/testkit.ts'
import { storeIntegrity } from './storeIntegrity.ts'

const row = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ seq: 1, kind: 'log', ...over })

test('an intact chain with readable rows is the only PASS', () => {
  eq(storeIntegrity({ chain_ok: true, chain_bad_seq: [], records: [row(), row({ seq: 2 })] }), { ok: true, badSeq: [], errorRows: 0, problems: [] }, 'verdict')
  eq(storeIntegrity({ chain_ok: true }).ok, true, 'no records, no bad list')
})
test('a broken hash chain is FAIL', () => {
  const v = storeIntegrity({ chain_ok: false, chain_bad_seq: [], records: [row()] })
  eq(v.ok, false, 'ok')
  ok(v.problems.includes('hash chain broken'), 'problem named')
})
test('bad sequence numbers are FAIL even when chain_ok claims true', () => {
  const v = storeIntegrity({ chain_ok: true, chain_bad_seq: [4, 7], records: [] })
  eq(v.ok, false, 'ok')
  eq(v.badSeq, [4, 7], 'badSeq')
  ok(v.problems.some((p) => p.includes('4, 7')), 'listed')
})
test('an undecryptable (tampered) row is FAIL even when chain_ok claims true', () => {
  const v = storeIntegrity({ chain_ok: true, chain_bad_seq: [], records: [row(), row({ seq: 2, error: 'UNDECRYPTABLE (tampered or written with another key/kiosk)' })] })
  eq(v.ok, false, 'ok')
  eq(v.errorRows, 1, 'errorRows')
})
test('any non-null error value counts as a bad row (empty string, false, object)', () => {
  for (const error of ['', false, 0, { code: 'x' }]) eq(storeIntegrity({ chain_ok: true, records: [row({ error })] }).ok, false, `error ${JSON.stringify(error)}`)
  eq(storeIntegrity({ chain_ok: true, records: [row({ error: null })] }).ok, true, 'error: null is a clean row')
})
test('all problems are reported together', () => {
  const v = storeIntegrity({ chain_ok: false, chain_bad_seq: [3], records: [row({ error: 'x' }), row({ error: 'y' })] })
  eq(v.ok, false, 'ok')
  eq(v.problems.length, 3, 'three problems')
  eq(v.errorRows, 2, 'errorRows')
})
test('a missing or non-boolean chain_ok is unknown, never PASS', () => {
  for (const chain_ok of [undefined, 'true', 1, null]) {
    const v = storeIntegrity({ chain_ok, chain_bad_seq: [], records: [row()] })
    eq(v.ok, null, `chain_ok ${String(chain_ok)}`)
    ok(v.problems.length === 1, 'explains why')
  }
})
test('a non-object body (edge error, garbage) is unknown, never PASS', () => {
  for (const body of [null, undefined, 'OK', 42, [], [{ chain_ok: true }]]) eq(storeIntegrity(body).ok, null, `body ${JSON.stringify(body)}`)
})
test('non-numeric bad-seq entries and non-object records are ignored, not crashing', () => {
  const v = storeIntegrity({ chain_ok: false, chain_bad_seq: ['5', 6], records: ['x', null, row()] })
  eq(v.badSeq, [6], 'badSeq')
  eq(v.errorRows, 0, 'errorRows')
  eq(v.ok, false, 'still FAIL')
})

done('storeIntegrity.test.ts')
