/** All client timing fields are epoch ms derived from the monotonic clock: performance.timeOrigin + t. */
export const epochFromPerf = (perfMs: number): number => Math.round(performance.timeOrigin + perfMs)
export const epochNow = (): number => epochFromPerf(performance.now())

export const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))

export function nextAnimationFrame(): Promise<number> {
  return new Promise((resolve) => requestAnimationFrame(resolve))
}

/** Median rAF interval over n frames -> display refresh rate (Hz), rounded. */
export async function measureRefreshHz(frames = 30): Promise<number> {
  const deltas: number[] = []
  let prev = await nextAnimationFrame()
  for (let i = 0; i < frames; i++) {
    const t = await nextAnimationFrame()
    deltas.push(t - prev)
    prev = t
  }
  deltas.sort((a, b) => a - b)
  const median = deltas[Math.floor(deltas.length / 2)] || 16.7
  return Math.round(1000 / median)
}
