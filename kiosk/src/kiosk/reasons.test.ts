/** Unit tests for the public-screen detail rules in kiosk/reasons.ts (audit KF-05, policy F13). */
import type { DecisionResponse } from '../api/types'
import { done, eq, ok, test } from '../shared/testkit.ts'
import { describeDecision, operatorDetail } from './reasons.ts'

function deny(bio: DecisionResponse['bio_result'], codes: string[]): DecisionResponse {
  return {
    attempt_id: 'att_1', kiosk_id: 'KIOSK_01', zone: 'MAIN_GATE', decision: 'DENY', reason_codes: codes, resolved_codes: [],
    next_action: { type: 'CONTACT_DESK', steps: [], methods: null, challenge: null, attempts_left: null, retry_after_s: null },
    bio_result: bio, schedule_result: 'OUTSIDE_WINDOW', mode: 'ONLINE', cache_state: 'FRESH', candidate: null, scores: {},
    latency_ms: { total: 10 }, policy_version: null, bundle_version: null, display_message: null, stage: 'schedule',
  }
}

test('identity unconfirmed: no SCHEDULE_* code and no schedule_result in the operator strip', () => {
  const d = operatorDetail(deny('BIO_UNSURE', ['MATCH_LOW', 'SCHEDULE_OUTSIDE_WINDOW']))
  eq(d.codes, ['MATCH_LOW'], 'codes')
  eq(d.scheduleResult, null, 'schedule_result')
})
test('identity confirmed: schedule detail stays', () => {
  const d = operatorDetail(deny('BIO_PASS', ['SCHEDULE_OUTSIDE_WINDOW']))
  eq(d.codes, ['SCHEDULE_OUTSIDE_WINDOW'], 'codes')
  eq(d.scheduleResult, 'OUTSIDE_WINDOW', 'schedule_result')
})
test('the generic §10 message carries no schedule wording', () => {
  const c = describeDecision(deny('BIO_UNSURE', ['SCHEDULE_OUTSIDE_WINDOW']))
  ok(c.generic, 'generic')
  ok(!/hours|window|schedule/i.test(c.reason), `reason: ${c.reason}`)
})
test('with detail off, the primary reason is still a plain sentence (never a raw code)', () => {
  const c = describeDecision(deny('BIO_PASS', ['SCHEDULE_OUTSIDE_WINDOW']))
  ok(!/_/.test(c.reason) && c.reason.length > 0, `reason: ${c.reason}`)
})

done('reasons.test.ts')
