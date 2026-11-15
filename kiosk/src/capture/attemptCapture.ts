/**
 * Colour-flash capture window (S2).
 *
 * Timing contract (what the edge correlates):
 * - flash_events[i].shown_at_ms = timestamp of the requestAnimationFrame AFTER the one that committed
 *   colour i, i.e. when that colour actually reached the screen. capture_started_at_ms = shown time of
 *   colour 0. Colour changes are instant (no CSS transition smear).
 * - frame_timestamps_ms / chroma_series[].t_ms = the camera CAPTURE time of the exact video frame used
 *   (requestVideoFrameCallback metadata.captureTime, else expectedDisplayTime), on the same
 *   performance.timeOrigin base - never encode/upload time.
 * - The N JPEG frames sit on the colour PLATEAUS shifted by the camera delay (UI.flashCameraLagMs):
 *   at least one frame per colour (2/2/1 for 5 frames x 3 colours), not evenly across the window.
 * - The mean skin-ROI colour of EVERY camera frame from colour 0 until window + tail is the chroma series.
 */
import type { CaptureSpec, ChromaSample, FlashEvent, FlashStep } from '../api/types'
import type { VisionEngine } from './engine'
import { saturate, sortFlash } from './flash'
import { canvasToJpeg } from './imageStats'
import { epochFromPerf } from './time'

export interface CaptureOutput {
  captureStartedAtMs: number
  frames: Blob[]
  frameTimestampsMs: number[]
  flashEvents: FlashEvent[]
  chromaSeries: ChromaSample[]
  /** client-side spans (ms) for the operator strip */
  windowMs: number
  encodeMs: number
}

export class CaptureCancelled extends Error {
  constructor() {
    super('capture cancelled')
    this.name = 'CaptureCancelled'
  }
}

/**
 * Chroma samples continue a little past the window. The edge decides on r_frames (the 5 JPEGs); the
 * client chroma series is diagnostic, so the tail is kept short to post the frames sooner.
 */
const CHROMA_TAIL_MS = 100
/** If the camera stalls, finish with whatever exists (the edge judges it) instead of hanging. */
const SAFETY_EXTRA_MS = 700
/** Hard cap even if requestAnimationFrame never runs (hidden tab). */
const HARD_TIMEOUT_MS = 4000

const r1 = (x: number) => Math.round(x * 10) / 10

/**
 * Frame sample times (ms after colour 0 reached the screen): `n` frames spread over the colour plateaus,
 * each shifted by the camera delay. Steps get floor(n/k) frames, the first n%k steps one extra;
 * 1 frame -> 55 % into the plateau, 2 -> 35 % / 75 %, more -> evenly. No flash -> evenly over the window.
 */
export function plateauTargets(steps: FlashStep[], n: number, lagMs: number, windowMs: number): number[] {
  if (n <= 0) return []
  if (steps.length === 0) return Array.from({ length: n }, (_, i) => ((i + 0.5) * windowMs) / n)
  const t0 = steps[0].offset_ms
  const k = steps.length
  const base = Math.floor(n / k)
  const extra = n % k
  const out: number[] = []
  steps.forEach((s, i) => {
    const m = base + (i < extra ? 1 : 0)
    const fr = m === 1 ? [0.55] : m === 2 ? [0.35, 0.75] : Array.from({ length: m }, (_, j) => (j + 0.5) / m)
    for (const f of fr) out.push(s.offset_ms - t0 + lagMs + f * s.duration_ms)
  })
  return out.sort((a, b) => a - b)
}

export function runFlashCapture(
  engine: VisionEngine,
  spec: CaptureSpec,
  sequence: FlashStep[],
  paint: (color: string | null) => void,
  signal: AbortSignal,
  saturateColours = true,
  cameraLagMs = 150,
): Promise<CaptureOutput> {
  const steps = sortFlash(sequence)
  const n = Math.max(1, spec.frames)
  const windowMs = Math.max(200, spec.window_ms)
  const targets = plateauTargets(steps, n, cameraLagMs, windowMs)
  const endRel = Math.max(windowMs + CHROMA_TAIL_MS, (targets[targets.length - 1] ?? 0) + 40)

  return new Promise<CaptureOutput>((resolve, reject) => {
    // JPEG encoding starts as soon as a frame is grabbed (Chrome encodes off the main thread), so only the
    // residual wait after the window lands on the 2 s critical path.
    const encoded: Promise<Blob>[] = []
    const grab = () => encoded.push(canvasToJpeg(engine.grabFrame(spec.max_width_px), spec.jpeg_quality))
    const frameTs: number[] = []
    const flashEvents: FlashEvent[] = []
    const chroma: ChromaSample[] = []
    let commitTs: number | null = null // rAF timestamp of the frame that committed colour 0 (step clock)
    let startPerf: number | null = null // when colour 0 was ON SCREEN (rAF after commit) = capture t0
    let shown = -1
    let pending: { idx: number; painted: string } | null = null
    let paintingDone = false
    let finished = false
    let safetyTimer = 0

    const cleanup = () => {
      finished = true
      unsubscribe()
      window.clearTimeout(safetyTimer)
      window.clearTimeout(hardTimer)
      signal.removeEventListener('abort', onAbort)
      paint(null)
    }

    const finish = async () => {
      if (finished) return
      cleanup()
      // Camera stalled: top up with the current frame so the request stays well-formed.
      while (encoded.length < n) {
        grab()
        frameTs.push(Math.max(frameTs[frameTs.length - 1] ?? 0, Math.round(performance.timeOrigin + performance.now())))
      }
      const t0 = performance.now()
      try {
        const frames = await Promise.all(encoded)
        resolve({
          captureStartedAtMs: epochFromPerf(startPerf ?? commitTs ?? performance.now()),
          frames,
          frameTimestampsMs: frameTs,
          flashEvents,
          chromaSeries: chroma,
          windowMs,
          encodeMs: Math.round(performance.now() - t0),
        })
      } catch (e) {
        reject(e)
      }
    }

    const onAbort = () => {
      if (finished) return
      cleanup()
      reject(new CaptureCancelled())
    }
    signal.addEventListener('abort', onAbort)
    const hardTimer = window.setTimeout(() => void finish(), HARD_TIMEOUT_MS)

    const unsubscribe = engine.onFrame((f) => {
      if (finished || startPerf === null) return
      const rel = f.perfMs - startPerf // f.perfMs = camera capture time of this frame
      if (rel < 0) return // captured before colour 0 reached the screen
      const rgb = f.face?.crop?.rgb
      if (rgb && rel <= windowMs + CHROMA_TAIL_MS) {
        chroma.push({ t_ms: f.epochMs, r: r1(rgb[0]), g: r1(rgb[1]), b: r1(rgb[2]) })
      }
      // At most one grab per camera frame; the grabbed image IS the frame whose capture time we record.
      if (encoded.length < n && rel >= targets[encoded.length]) {
        grab()
        frameTs.push(f.epochMs)
      }
      if (paintingDone && encoded.length >= n && rel >= endRel) void finish()
    })

    const stepAt = (elapsed: number) =>
      steps.findIndex((s) => elapsed >= s.offset_ms && elapsed < s.offset_ms + s.duration_ms)

    const startClock = (ts: number) => {
      startPerf = ts
      safetyTimer = window.setTimeout(() => void finish(), endRel + SAFETY_EXTRA_MS)
    }

    const frame = (ts: number) => {
      if (finished) return
      // The colour committed in the previous rAF has now been presented: this frame's start time is
      // the best page-side estimate of when it hit the screen.
      if (pending) {
        if (pending.idx === 0 && startPerf === null) startClock(ts)
        flashEvents.push({ step_index: pending.idx, color: steps[pending.idx].color, shown_at_ms: epochFromPerf(ts) })
        pending = null
      }
      if (commitTs === null) {
        commitTs = ts
        if (steps.length === 0) startClock(ts) // no-flash path: the window starts now
      }
      const elapsed = ts - commitTs
      const idx = elapsed >= windowMs ? -1 : stepAt(elapsed)
      if (idx !== shown) {
        if (idx >= 0) {
          const painted = saturateColours ? saturate(steps[idx].color) : steps[idx].color
          paint(painted)
          pending = { idx, painted }
        } else {
          paint(null)
        }
        shown = idx
      }
      if (elapsed >= windowMs && pending === null) {
        paintingDone = true
        return
      }
      requestAnimationFrame(frame)
    }
    requestAnimationFrame(frame)
  })
}
