/** Unit tests for shared/auth/passwordPolicy.ts: the local mirror of edge/auth/passwords.py check_policy. */
import { done, eq, ok, test } from '../testkit.ts'
import { PASSWORD_MAX, PASSWORD_MIN, newPasswordProblems, passwordPolicyProblems } from './passwordPolicy.ts'

const GOOD = 'correct-horse-battery'

test('limits match the edge (12..128)', () => {
  eq([PASSWORD_MIN, PASSWORD_MAX], [12, 128], 'limits')
})

test('a good password has no problems', () => {
  eq(passwordPolicyProblems(GOOD, 'nina'), [], 'problems')
})

test('too short / too long', () => {
  eq(passwordPolicyProblems('Abcdefgh12!', ''), ['use at least 12 characters'], 'short')
  ok(passwordPolicyProblems('Abcdefghij'.repeat(13), '').includes('use at most 128 characters'), 'long')
})

test('length counts code points after NFKC, like Python len(normalize("NFKC", p))', () => {
  // 12 astral characters = 24 UTF-16 code units but 12 code points: long enough, not too long
  const emoji = '😀😁😂🤣😃😄😅😆😉😊😋😎'
  eq(passwordPolicyProblems(emoji, ''), [], 'emoji password')
  const astral128 = '😀😁😂🤣😃😄😅😆'.repeat(16)
  ok(!passwordPolicyProblems(astral128, '').includes('use at most 128 characters'), '128 astral code points are allowed')
})

test('needs at least 5 different characters', () => {
  eq(passwordPolicyProblems('aaaabbbbcccc', ''), ['use at least 5 different characters'], 'distinct')
})

test('username rule only applies to usernames of 3+ characters, case-insensitively', () => {
  eq(passwordPolicyProblems('my-NINA-password-x', 'nina'), ['do not include the username'], 'contains')
  eq(passwordPolicyProblems('xy-garden-party-7', 'xy'), [], 'short username ignored')
})

test('change-password extras: must differ, repeat must match', () => {
  eq(newPasswordProblems(GOOD, { username: 'nina', current: GOOD, again: GOOD }), ['the new password must differ from the current one'], 'same')
  eq(newPasswordProblems(GOOD, { username: 'nina', current: 'old-temp-pass', again: 'other' }), ['the two new passwords differ'], 'mismatch')
  eq(newPasswordProblems(GOOD, { username: 'nina', current: 'old-temp-pass', again: '' }), [], 'repeat not typed yet')
})

done('passwordPolicy.test.ts')
