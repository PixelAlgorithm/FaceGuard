/**
 * Early cloud probe (API.md v1.3 §3.1a): the face-lock frame goes to POST /v1/attempt/{id}/probe right after
 * session/start, so the edge can start the cloud /v1/match in parallel with the 0.7 s colour-flash capture
 * (the cloud round trip from the venue is ~0.4-1.4 s). Strictly fire-and-forget: the frame is copied
 * synchronously at face lock (one drawImage), encoded off the main thread, and every error is ignored —
 * the edge falls back to its normal path (best frame) or decides locally (fail-secure).
 */
import type { EdgeApi } from '../api/types'
import type { VisionEngine } from './engine'
import { canvasToJpeg } from './imageStats'

/** Edge limit for the probe part (> 2 MB -> 413). */
const PROBE_MAX_BYTES = 2 * 1024 * 1024

export type ProbeOutcome = 'started' | 'skipped' | 'failed' | 'not_sent'

/** Copy of the current (= face-lock) video frame, unmirrored, <= maxWidth px wide; null if unavailable. */
export function grabProbeFrame(engine: VisionEngine, maxWidth: number): HTMLCanvasElement | null {
  try {
    return engine.grabFrame(maxWidth)
  } catch {
    return null
  }
}

/** Encode + POST the probe. Never throws, never awaited on the critical path. */
export function sendProbe(
  api: EdgeApi,
  attemptId: string,
  canvas: HTMLCanvasElement | null,
  jpegQuality: number,
  onDone?: (outcome: ProbeOutcome) => void,
): void {
  if (!canvas) {
    onDone?.('not_sent')
    return
  }
  void (async () => {
    try {
      const blob = await canvasToJpeg(canvas, jpegQuality)
      if (blob.size === 0 || blob.size > PROBE_MAX_BYTES) {
        onDone?.('not_sent')
        return
      }
      const r = await api.submitProbe(attemptId, blob)
      onDone?.(r.cloud)
    } catch (e) {
      // 404 (older edge without the route), 409 (frames already in), network: all harmless.
      console.debug('[probe] ignored error', e)
      onDone?.('failed')
    }
  })()
}
