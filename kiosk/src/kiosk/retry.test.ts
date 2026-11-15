/** Unit tests for kiosk/retry.ts (audit KF-M1: a challenge is never submitted without its last frame). */
import { done, eq, test } from '../shared/testkit.ts'
import { firstValue } from './retry.ts'

const noWait = (): Promise<void> => Promise.resolve()

async function main(): Promise<void> {
  let calls = 0
  const got = await firstValue(async () => (++calls < 3 ? null : 'jpeg'), 3, 0, noWait)
  test('returns the first non-null value', () => {
    eq(got, 'jpeg', 'value')
    eq(calls, 3, 'calls')
  })
  let fails = 0
  const none = await firstValue(async () => {
    fails += 1
    throw new Error('encode failed')
  }, 3, 0, noWait)
  test('gives null after the tries are used up (throws count as misses)', () => {
    eq(none, null, 'value')
    eq(fails, 3, 'tries')
  })
  done('retry.test.ts')
}

await main()
