/**
 * One operator-console attempt, the same main path as the kiosk (session/start -> colour-flash capture ->
 * POST frames), built from the kiosk's own capture modules (imported read-only). No step-up here: the
 * console shows the first decision; challenges / second factors stay on the kiosk screen.
 */
import { getApi } from '../api'
import type { DecisionResponse, FramesMeta, SessionStartRequest, SessionStartResponse } from '../api/types'
import { runFlashCapture, type CaptureOutput } from '../capture/attemptCapture'
import { trackSettingsSummary } from '../capture/camera'
import { BLEND_KEYS, type BlendSubset, type FrameAnalysis, type VisionEngine } from '../capture/engine'
import { checkFlashSafety } from '../capture/flash'
import { grabProbeFrame, sendProbe } from '../capture/probe'
import { THRESHOLDS, UI } from '../config'
import { postFrames } from './edgeRaw'

export interface OperatorTiming {
  sessionStartMs: number
  captureWindowMs: number
  encodeMs: number
  uploadAndEdgeMs: number
}

export interface OperatorAttempt {
  decision: DecisionResponse
  raw: Record<string, unknown> | null
  /** epoch ms of the frame that completed the face lock (t0); for a forced scan: the frame at the click */
  faceLockAtMs: number
  /** true = operator forced the scan without a face lock (no rendered beacon is sent for it) */
  forced: boolean
  flash: 'painted' | 'off' | 'refused'
  timing: OperatorTiming
}

const r2 = (x: number) => Math.round(x * 100) / 100
const r4 = (x: number) => Math.round(x * 10000) / 10000

function meanBlend(frames: FrameAnalysis[]): BlendSubset {
  const out: BlendSubset = { mouthSmileLeft: 0, mouthSmileRight: 0, jawOpen: 0, cheekPuff: 0, eyeBlinkLeft: 0, eyeBlinkRight: 0 }
  const withFace = frames.filter((f) => f.face)
  if (withFace.length === 0) return out
  for (const k of BLEND_KEYS) out[k] = r4(withFace.reduce((a, f) => a + (f.face?.blend[k] ?? 0), 0) / withFace.length)
  return out
}

/** FramesMeta exactly as the kiosk builds it (KioskController.buildFramesMeta). */
function buildMeta(
  engine: VisionEngine,
  session: SessionStartResponse,
  lock: FrameAnalysis,
  faceLockAtMs: number,
  baseline: FrameAnalysis[],
  capture: CaptureOutput,
): FramesMeta {
  const face = lock.face
  const scale = Math.min(1, session.capture.max_width_px / lock.width)
  const { fps, jitterMs } = engine.timingStats()
  return {
    nonce: session.nonce,
    face_lock_at_ms: faceLockAtMs,
    capture_started_at_ms: capture.captureStartedAtMs,
    frame_timestamps_ms: capture.frameTimestampsMs,
    flash_events: capture.flashEvents,
    chroma_series: capture.chromaSeries,
    quality: {
      face_count: lock.faceCount,
      iod_px: r2((face?.iodPx ?? 0) * scale),
      yaw_deg: r2(face?.yawDeg ?? 0),
      pitch_deg: r2(face?.pitchDeg ?? 0),
      roll_deg: r2(face?.rollDeg ?? 0),
      blur_var: r2(face?.crop?.blurVar ?? 0),
      luma_mean: r2(face?.crop?.luma ?? 0),
      face_box: (face?.box ?? [0, 0, 0, 0]).map(r4) as [number, number, number, number],
    },
    client_signals: {
      camera_label: engine.camera.label,
      virtual_camera_suspected: engine.camera.virtualSuspected,
      device_count: engine.camera.deviceCount,
      track_settings: trackSettingsSummary(engine.camera, engine.track),
      fps_measured: r2(fps),
      frame_interval_jitter_ms: r2(jitterMs),
      exposure_locked: false, // the kiosk does not lock exposure either (UI.lockExposure = false)
    },
    blendshapes: meanBlend(baseline),
  }
}

export async function runOperatorAttempt(args: {
  engine: VisionEngine
  lockFrame: FrameAnalysis
  kioskId: string
  flashEnabled: boolean
  forced: boolean
  paint: (color: string | null) => void
  signal: AbortSignal
  onStage?: (stage: 'capturing' | 'deciding') => void
  /** attempt_id known (before the frames POST): lets the caller ignore its own decision on the live feed */
  onSession?: (attemptId: string) => void
}): Promise<OperatorAttempt> {
  const { engine, lockFrame, signal } = args
  const api = getApi()
  const faceLockAtMs = lockFrame.epochMs
  // Early cloud probe (same as the kiosk): face-lock frame copied now, posted after session/start, never awaited.
  const probeCanvas = UI.earlyProbe && !args.forced ? grabProbeFrame(engine, UI.defaultUploadMaxWidth) : null
  // Neutral blendshape baseline = frames with a face during the first challenge.baseline_ms after the lock.
  const baseline: FrameAnalysis[] = lockFrame.face ? [lockFrame] : []
  const stopBaseline = engine.onFrame((f) => {
    if (f.face && f.perfMs <= lockFrame.perfMs + THRESHOLDS.challenge.baselineMs) baseline.push(f)
  })
  try {
    const flashWanted = args.flashEnabled && THRESHOLDS.flash.enabled
    const req: SessionStartRequest = {
      kiosk_id: args.kioskId,
      claimed_user_id: null,
      client: {
        // edge validates <= 256 characters (edge-app F10)
        camera_label: engine.camera.label.slice(0, 256),
        user_agent: navigator.userAgent.slice(0, 256),
        screen: { width: window.screen.width, height: window.screen.height, refresh_hz: engine.refreshHz },
      },
      flash_enabled: flashWanted,
    }
    const t1 = performance.now()
    let session = await api.sessionStart(req)
    let flash: OperatorAttempt['flash'] = flashWanted ? 'painted' : 'off'
    const safety = checkFlashSafety(session.flash_sequence, THRESHOLDS.flash.maxChangesPerS)
    if (!safety.ok) {
      // Photosensitivity guard (<= 3 changes/s): never paint it; use the accessible non-flash path.
      console.warn(`[operator] refusing flash sequence (${safety.reason}); flash_enabled=false`)
      session = await api.sessionStart({ ...req, flash_enabled: false })
      flash = 'refused'
    }
    const sessionStartMs = Math.round(performance.now() - t1)
    if (probeCanvas && session.mode === 'ONLINE') sendProbe(api, session.attempt_id, probeCanvas, session.capture.jpeg_quality || 0.85)
    args.onSession?.(session.attempt_id)
    if (signal.aborted) throw new DOMException('cancelled', 'AbortError')
    args.onStage?.('capturing')
    const capture = await runFlashCapture(
      engine,
      session.capture,
      session.flash_sequence,
      args.paint,
      signal,
      UI.flashSaturate,
      UI.flashCameraLagMs,
    )
    stopBaseline()
    args.onStage?.('deciding')
    const meta = buildMeta(engine, session, lockFrame, faceLockAtMs, baseline, capture)
    const t2 = performance.now()
    const { decision, raw } = await postFrames(session.attempt_id, capture.frames, meta)
    return {
      decision,
      raw,
      faceLockAtMs,
      forced: args.forced,
      flash,
      timing: {
        sessionStartMs,
        captureWindowMs: capture.windowMs,
        encodeMs: capture.encodeMs,
        uploadAndEdgeMs: Math.round(performance.now() - t2),
      },
    }
  } finally {
    stopBaseline()
    args.paint(null)
  }
}
