/**
 * Vision engine for /operator and /register: the SAME VisionEngine + MediaPipe Face Landmarker as the kiosk
 * (imported read-only), opened on an explicitly chosen camera (getUserMedia deviceId: exact) and re-opened
 * when the operator switches cameras. One landmarker per page, shared across camera switches.
 */
import { useEffect, useState } from 'react'
import { CameraError, openCamera } from '../capture/camera'
import { VisionEngine } from '../capture/engine'
import { createFaceLandmarker } from '../capture/landmarker'
import { measureRefreshHz } from '../capture/time'

type Landmarker = Awaited<ReturnType<typeof createFaceLandmarker>>

let landmarkerP: Promise<Landmarker> | null = null
let refreshHzP: Promise<number> | null = null

function sharedLandmarker(): Promise<Landmarker> {
  if (!landmarkerP) {
    landmarkerP = createFaceLandmarker().catch((e: unknown) => {
      landmarkerP = null // allow a retry
      throw e
    })
  }
  return landmarkerP
}

function waitForFrames(video: HTMLVideoElement, timeoutMs: number): Promise<void> {
  if (video.readyState >= 2) return Promise.resolve()
  return new Promise((resolve, reject) => {
    const t = window.setTimeout(() => reject(new Error(`Camera produced no frames within ${timeoutMs / 1000} s`)), timeoutMs)
    video.onloadeddata = () => {
      window.clearTimeout(t)
      resolve()
    }
  })
}

export async function openOperatorEngine(deviceId: string | null): Promise<VisionEngine> {
  const { stream, track, info } = await openCamera(deviceId)
  try {
    const video = document.createElement('video')
    video.muted = true
    video.playsInline = true
    video.autoplay = true
    video.srcObject = stream
    await waitForFrames(video, 8000)
    await video.play().catch(() => undefined)
    refreshHzP ??= measureRefreshHz()
    const [{ landmarker, delegate }, refreshHz] = await Promise.all([sharedLandmarker(), refreshHzP])
    const engine = new VisionEngine({ video, stream, track, camera: info, landmarker, delegate, refreshHz })
    engine.start()
    return engine
  } catch (e) {
    stream.getTracks().forEach((t) => t.stop())
    throw e
  }
}

/** Stop frames + camera WITHOUT closing the shared landmarker (VisionEngine.dispose() would close it). */
export function closeOperatorEngine(engine: VisionEngine): void {
  engine.stop()
  const v = engine.video
  const s = v.srcObject
  if (s instanceof MediaStream) s.getTracks().forEach((t) => t.stop())
  engine.track.stop()
  v.pause()
  v.srcObject = null
  v.remove()
}

export interface EngineError {
  title: string
  hint: string
}

export function describeCameraError(e: unknown): EngineError {
  if (e instanceof CameraError) {
    const copy: Record<CameraError['kind'], EngineError> = {
      denied: { title: 'Camera access blocked', hint: 'Allow camera access for this page (address bar camera icon), then press Retry.' },
      not_found: { title: 'Camera not found', hint: 'Connect the camera (or bring the iPhone near the Mac), press Refresh, then pick it.' },
      busy: { title: 'Camera is busy', hint: 'Close other apps using this camera (FaceTime, Zoom, Photo Booth), then press Retry.' },
      insecure: { title: 'Camera unavailable', hint: 'Open this page on http://localhost:5173 (the camera needs a secure origin).' },
      other: { title: 'Camera failed to start', hint: e.message },
    }
    return copy[e.kind]
  }
  return {
    title: 'Face model or camera failed',
    hint: `${e instanceof Error ? e.message : String(e)} (if the model is missing: run "npm run assets" in kiosk/)`,
  }
}

export interface OperatorEngineState {
  engine: VisionEngine | null
  status: 'off' | 'opening' | 'ready' | 'error'
  error: EngineError | null
  /** the saved camera was not available, so the browser default camera was opened instead */
  usedFallback: boolean
}

interface Opened {
  key: string
  engine: VisionEngine | null
  error: EngineError | null
  usedFallback: boolean
}

const OFF: OperatorEngineState = { engine: null, status: 'off', error: null, usedFallback: false }
const OPENING: OperatorEngineState = { engine: null, status: 'opening', error: null, usedFallback: false }
const keyOf = (deviceId: string | null, retryKey: number) => `${deviceId ?? ''}#${retryKey}`

/** Opens the engine for `deviceId` (null = browser default) while `enabled`; re-opens on change / retry. */
export function useOperatorEngine(deviceId: string | null, enabled: boolean, retryKey: number): OperatorEngineState {
  const [opened, setOpened] = useState<Opened | null>(null)
  useEffect(() => {
    if (!enabled) return
    const key = keyOf(deviceId, retryKey)
    let cancelled = false
    let engineOpened: VisionEngine | null = null
    void (async () => {
      try {
        let usedFallback = false
        let engine: VisionEngine
        try {
          engine = await openOperatorEngine(deviceId)
        } catch (e) {
          if (!deviceId || !(e instanceof CameraError) || e.kind !== 'not_found') throw e
          engine = await openOperatorEngine(null)
          usedFallback = true
        }
        if (cancelled) {
          closeOperatorEngine(engine)
          return
        }
        engineOpened = engine
        setOpened({ key, engine, error: null, usedFallback })
      } catch (e) {
        console.error('[operator] camera/engine failed', e)
        if (!cancelled) setOpened({ key, engine: null, error: describeCameraError(e), usedFallback: false })
      }
    })()
    const onHide = () => {
      if (engineOpened) closeOperatorEngine(engineOpened)
    }
    window.addEventListener('pagehide', onHide)
    return () => {
      cancelled = true
      window.removeEventListener('pagehide', onHide)
      if (engineOpened) closeOperatorEngine(engineOpened)
      setOpened((o) => (o && o.key === key ? null : o)) // forget the engine that was just closed
    }
  }, [deviceId, enabled, retryKey])
  if (!enabled) return OFF
  if (!opened || opened.key !== keyOf(deviceId, retryKey)) return OPENING
  return { engine: opened.engine, status: opened.engine ? 'ready' : 'error', error: opened.error, usedFallback: opened.usedFallback }
}
