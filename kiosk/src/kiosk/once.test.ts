/** Unit test for kiosk/once.ts (audit KF-09: cleanup must run exactly once on every exit path). */
import { done, eq, test } from '../shared/testkit.ts'
import { once } from './once.ts'

test('once runs the wrapped cleanup a single time however often it is called', () => {
  let calls = 0
  const stop = once(() => {
    calls += 1
  })
  stop()
  stop()
  stop()
  eq(calls, 1, 'calls')
})

done('once.test.ts')
