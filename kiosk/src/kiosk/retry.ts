/**
 * Try `fn` up to `tries` times, `gapMs` apart, until it yields a non-null value; a throw counts as a miss.
 * Returns null when every try missed. `wait` is injectable for tests. Used for the challenge's last frame
 * (audit KF-M1: submitting a challenge with no frame is a terminal DENY on the edge).
 */
export async function firstValue<T>(
  fn: () => Promise<T | null>,
  tries: number,
  gapMs: number,
  wait: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms)),
): Promise<T | null> {
  for (let i = 0; i < tries; i++) {
    if (i > 0) await wait(gapMs)
    try {
      const v = await fn()
      if (v !== null) return v
    } catch {
      /* a miss: try again */
    }
  }
  return null
}
