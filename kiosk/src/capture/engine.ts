/**
 * VisionEngine: owns the camera stream, the <video> element and the MediaPipe Face Landmarker, and runs
 * one analysis per camera frame (requestVideoFrameCallback). Consumers (quality gate, flash capture,
 * challenge trackers) subscribe with onFrame(). Nothing here decides access.
 */
import type { FaceLandmarker, FaceLandmarkerResult, NormalizedLandmark } from '@mediapipe/tasks-vision'
import { CAMERA_FLIPPED } from '../config'
import { openCamera, type CameraInfo } from './camera'
import {
  SKIN_PATCH_LANDMARKS,
  eulerFromMatrix,
  eyeGeometry,
  landmarkBox,
  landmarkExtents,
  poseFromLandmarks,
  yawProxy,
  type EyeGeometry,
  type Point,
} from './geometry'
import { analyseCrop, canvasToJpeg, type CropStats } from './imageStats'
import { createFaceLandmarker } from './landmarker'
import { epochFromPerf, measureRefreshHz } from './time'

export interface BlendSubset {
  mouthSmileLeft: number
  mouthSmileRight: number
  jawOpen: number
  cheekPuff: number
  eyeBlinkLeft: number
  eyeBlinkRight: number
}

export const BLEND_KEYS: readonly (keyof BlendSubset)[] = [
  'mouthSmileLeft',
  'mouthSmileRight',
  'jawOpen',
  'cheekPuff',
  'eyeBlinkLeft',
  'eyeBlinkRight',
]

/** Per-frame diagnostics for the ?debug=1 overlay. */
export interface FrameDiag {
  detectMs: number
  cropMs: number
  tsSource: 'captureTime' | 'expectedDisplayTime' | 'presentationTime' | 'now'
  nCategories: number
  top: Array<[string, number]>
  matrixYawDeg: number | null
}

export type CropMode = 'all' | 'half' | 'off'

export interface FaceObservation {
  landmarks: NormalizedLandmark[]
  box: [number, number, number, number] // normalised x, y, w, h
  truncated: boolean
  center: Point // normalised
  eyes: EyeGeometry
  iodPx: number // video pixels
  faceWidthPx: number // video pixels
  yawDeg: number // + = subject's left
  pitchDeg: number
  rollDeg: number
  yawProxy: number
  blend: BlendSubset
  crop: CropStats | null
}

export interface FrameAnalysis {
  perfMs: number // camera capture time (performance.now() timebase)
  epochMs: number
  faceCount: number
  face: FaceObservation | null
  width: number // video pixels
  height: number
  diag: FrameDiag
}

export type FrameListener = (f: FrameAnalysis) => void

const CROP = 112

function blendFrom(result: FaceLandmarkerResult, idx: number): BlendSubset {
  const out: BlendSubset = {
    mouthSmileLeft: 0,
    mouthSmileRight: 0,
    jawOpen: 0,
    cheekPuff: 0,
    eyeBlinkLeft: 0,
    eyeBlinkRight: 0,
  }
  const cats = result.faceBlendshapes?.[idx]?.categories ?? []
  for (const c of cats) {
    if (c.categoryName in out) out[c.categoryName as keyof BlendSubset] = c.score
  }
  return out
}

export class VisionEngine {
  readonly video: HTMLVideoElement
  readonly track: MediaStreamTrack
  readonly camera: CameraInfo
  readonly delegate: 'GPU' | 'CPU'
  readonly refreshHz: number
  latest: FrameAnalysis | null = null

  private readonly landmarker: FaceLandmarker
  private readonly stream: MediaStream
  private readonly listeners = new Set<FrameListener>()
  private readonly cropCanvas: HTMLCanvasElement
  private readonly cropCtx: CanvasRenderingContext2D
  private readonly intervals: number[] = []
  private prevFramePerf: number | null = null
  private lastDetectTs = 0
  private yawVotes = 0
  private running = false
  private rafHandle = 0
  private cropMode: CropMode = 'all'
  private frameNo = 0
  private lastCrop: CropStats | null = null
  private processedAt: number[] = []

  constructor(args: {
    video: HTMLVideoElement
    stream: MediaStream
    track: MediaStreamTrack
    camera: CameraInfo
    landmarker: FaceLandmarker
    delegate: 'GPU' | 'CPU'
    refreshHz: number
  }) {
    this.video = args.video
    this.stream = args.stream
    this.track = args.track
    this.camera = args.camera
    this.landmarker = args.landmarker
    this.delegate = args.delegate
    this.refreshHz = args.refreshHz
    this.cropCanvas = document.createElement('canvas')
    this.cropCanvas.width = CROP
    this.cropCanvas.height = CROP
    const ctx = this.cropCanvas.getContext('2d', { willReadFrequently: true })
    if (!ctx) throw new Error('2D canvas unavailable')
    this.cropCtx = ctx
  }

  onFrame(listener: FrameListener): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  start(): void {
    if (this.running) return
    this.running = true
    this.schedule()
  }

  stop(): void {
    this.running = false
    cancelAnimationFrame(this.rafHandle)
  }

  dispose(): void {
    this.stop()
    this.stream.getTracks().forEach((t) => t.stop())
    this.landmarker.close()
  }

  /**
   * Which frames get the face-crop statistics (luma / blur / skin chroma). 'all' during the flash capture
   * (chroma on every frame), 'half' while scanning (advisory gate), 'off' during the challenge (unused).
   */
  setCropMode(mode: CropMode): void {
    this.cropMode = mode
  }

  /** Matrix-vs-landmark yaw sign agreement (-50..+50; positive = consistent). */
  yawSignAgreement(): number {
    return this.yawVotes
  }

  /** Frames actually analysed per second over the last ~2 s (wall clock). */
  processedFps(): number {
    const xs = this.processedAt
    if (xs.length < 2) return 0
    return ((xs.length - 1) * 1000) / (xs[xs.length - 1] - xs[0])
  }

  /** Mount the (mirrored) preview <video> into a container; returns a detach function. */
  attachPreview(container: HTMLElement): () => void {
    const v = this.video
    v.className = 'absolute inset-0 h-full w-full object-cover mirror'
    v.setAttribute('aria-hidden', 'true')
    container.appendChild(v)
    void v.play().catch(() => undefined)
    return () => {
      if (v.parentElement === container) container.removeChild(v)
    }
  }

  /** fps + inter-frame jitter (std dev, ms) over the last ~2 s of camera frames. */
  timingStats(): { fps: number; jitterMs: number } {
    const xs = this.intervals
    if (xs.length < 3) return { fps: 0, jitterMs: 0 }
    const mean = xs.reduce((a, b) => a + b, 0) / xs.length
    const variance = xs.reduce((a, b) => a + (b - mean) ** 2, 0) / xs.length
    return { fps: mean > 0 ? 1000 / mean : 0, jitterMs: Math.sqrt(variance) }
  }

  /** Copy the CURRENT video frame (unmirrored) into a new canvas no wider than maxWidth. */
  grabFrame(maxWidth: number): HTMLCanvasElement {
    const w0 = this.video.videoWidth
    const h0 = this.video.videoHeight
    const scale = Math.min(1, maxWidth / w0)
    const canvas = document.createElement('canvas')
    canvas.width = Math.round(w0 * scale)
    canvas.height = Math.round(h0 * scale)
    const ctx = canvas.getContext('2d')
    if (!ctx) throw new Error('2D canvas unavailable')
    ctx.drawImage(this.video, 0, 0, canvas.width, canvas.height)
    return canvas
  }

  grabJpeg(maxWidth: number, quality: number): Promise<Blob> {
    return canvasToJpeg(this.grabFrame(maxWidth), quality)
  }

  private schedule(): void {
    if (!this.running) return
    if (typeof this.video.requestVideoFrameCallback === 'function') {
      this.video.requestVideoFrameCallback((now, meta) => {
        // CAPTURE time of this video frame on the performance.now() timebase (not processing/encode time).
        let t = now
        let src: FrameDiag['tsSource'] = 'now'
        if (typeof meta.captureTime === 'number' && meta.captureTime > 0) {
          t = meta.captureTime
          src = 'captureTime'
        } else if (typeof meta.expectedDisplayTime === 'number' && meta.expectedDisplayTime > 0) {
          t = meta.expectedDisplayTime
          src = 'expectedDisplayTime'
        }
        this.process(t, src)
        this.schedule()
      })
    } else {
      this.rafHandle = requestAnimationFrame((now) => {
        this.process(now, 'now')
        this.schedule()
      })
    }
  }

  private process(framePerf: number, tsSource: FrameDiag['tsSource']): void {
    const W = this.video.videoWidth
    const H = this.video.videoHeight
    if (!W || !H || this.video.readyState < 2) return
    if (this.prevFramePerf !== null) {
      const dt = framePerf - this.prevFramePerf
      if (dt > 0 && dt < 1000) {
        this.intervals.push(dt)
        if (this.intervals.length > 60) this.intervals.shift()
      }
    }
    this.prevFramePerf = framePerf

    const ts = Math.max(this.lastDetectTs + 1, Math.round(performance.now()))
    this.lastDetectTs = ts
    let result: FaceLandmarkerResult
    const tDetect = performance.now()
    try {
      result = this.landmarker.detectForVideo(this.video, ts)
    } catch (e) {
      console.warn('[engine] detectForVideo failed', e)
      return
    }
    const detectMs = performance.now() - tDetect
    const wall = performance.now()
    this.processedAt.push(wall)
    while (this.processedAt.length > 2 && wall - this.processedAt[0] > 2000) this.processedAt.shift()
    this.frameNo++
    const faces = result.faceLandmarks ?? []
    let primary = -1
    let bestArea = 0
    faces.forEach((lms, i) => {
      const [, , w, h] = landmarkBox(lms)
      if (w * h > bestArea) {
        bestArea = w * h
        primary = i
      }
    })
    // A second face only counts if it is a significant size (mirrors quality.secondary_face_min_rel_size).
    const faceCount = faces.filter((lms) => {
      const [, , w, h] = landmarkBox(lms)
      return bestArea > 0 && (w * h) / bestArea >= 0.3
    }).length

    const tCrop = performance.now()
    const face = primary >= 0 ? this.observe(result, primary, W, H) : null
    const cats = primary >= 0 ? (result.faceBlendshapes?.[primary]?.categories ?? []) : []
    const top = cats
      .filter((c) => c.categoryName !== '_neutral')
      .sort((a, b) => b.score - a.score)
      .slice(0, 5)
      .map((c): [string, number] => [c.categoryName, c.score])
    const m = primary >= 0 ? result.facialTransformationMatrixes?.[primary]?.data : undefined
    const analysis: FrameAnalysis = {
      perfMs: framePerf,
      epochMs: epochFromPerf(framePerf),
      faceCount,
      face,
      width: W,
      height: H,
      diag: {
        detectMs,
        cropMs: performance.now() - tCrop,
        tsSource,
        nCategories: cats.length,
        top,
        matrixYawDeg: m && m.length >= 16 ? eulerFromMatrix(m).yaw : null,
      },
    }
    this.latest = analysis
    for (const l of this.listeners) {
      try {
        l(analysis)
      } catch (e) {
        console.error('[engine] frame listener failed', e)
      }
    }
  }

  private observe(result: FaceLandmarkerResult, idx: number, W: number, H: number): FaceObservation {
    const lms = result.faceLandmarks[idx]
    const box = landmarkBox(lms)
    const ext = landmarkExtents(lms)
    const eyes = eyeGeometry(lms, W, H)
    const proxy = yawProxy(lms, W, H, eyes)
    const matrix = result.facialTransformationMatrixes?.[idx]?.data
    const euler = matrix && matrix.length >= 16 ? eulerFromMatrix(matrix) : poseFromLandmarks(lms, W, H, eyes)
    // Yaw = MediaPipe transformation-matrix yaw (column-major). Verified on an unmirrored clip: + = face
    // turned toward image right = the subject's LEFT, agreeing with the landmark proxy and contour geometry.
    // It is continuous through 0 (an earlier proxy-sign x matrix-magnitude mix flipped sign on noise near 0,
    // which looked like a head-turn onset). The proxy only feeds the agreement diagnostic.
    if (Math.abs(proxy) > 0.12 && Math.abs(euler.yaw) > 8) {
      this.yawVotes = Math.max(-50, Math.min(50, this.yawVotes + Math.sign(proxy) * Math.sign(euler.yaw)))
    }
    // ?camflip=1: the camera delivers a mirrored stream -> invert so + stays = the subject's left.
    const flip = CAMERA_FLIPPED ? -1 : 1
    const yawDeg = flip * euler.yaw

    return {
      landmarks: lms,
      box,
      truncated: ext.x0 < 0.005 || ext.y0 < 0.005 || ext.x1 > 0.995 || ext.y1 > 0.995,
      center: { x: box[0] + box[2] / 2, y: box[1] + box[3] / 2 },
      eyes,
      iodPx: eyes.iodPx,
      faceWidthPx: box[2] * W,
      yawDeg,
      pitchDeg: euler.pitch,
      rollDeg: euler.roll,
      yawProxy: flip * proxy,
      blend: blendFrom(result, idx),
      crop: this.cropFor(lms, box, W, H),
    }
  }

  private cropFor(lms: NormalizedLandmark[], box: [number, number, number, number], W: number, H: number): CropStats | null {
    if (this.cropMode === 'off') return null
    if (this.cropMode === 'half' && this.frameNo % 2 === 1 && this.lastCrop) return this.lastCrop
    this.lastCrop = this.cropStats(lms, box, W, H)
    return this.lastCrop
  }

  private cropStats(lms: NormalizedLandmark[], box: [number, number, number, number], W: number, H: number): CropStats | null {
    const cx = (box[0] + box[2] / 2) * W
    const cy = (box[1] + box[3] / 2) * H
    const side = Math.max(box[2] * W, box[3] * H) * 1.05
    if (side < 8) return null
    const sx = cx - side / 2
    const sy = cy - side / 2
    try {
      this.cropCtx.clearRect(0, 0, CROP, CROP)
      this.cropCtx.drawImage(this.video, sx, sy, side, side, 0, 0, CROP, CROP)
      const img = this.cropCtx.getImageData(0, 0, CROP, CROP)
      const k = CROP / side
      const patches = SKIN_PATCH_LANDMARKS.map((i): [number, number] => [
        (lms[i].x * W - sx) * k,
        (lms[i].y * H - sy) * k,
      ])
      return analyseCrop(img, patches, CROP * 0.05)
    } catch {
      return null
    }
  }
}

// ---------------------------------------------------------------- singleton bootstrap

let enginePromise: Promise<VisionEngine> | null = null

export type BootStage = 'camera' | 'model' | 'ready'

export function getEngine(onStage?: (s: BootStage) => void): Promise<VisionEngine> {
  if (!enginePromise) {
    enginePromise = bootEngine(onStage).catch((e) => {
      enginePromise = null // allow a retry
      throw e
    })
  }
  return enginePromise
}

async function bootEngine(onStage?: (s: BootStage) => void): Promise<VisionEngine> {
  onStage?.('camera')
  const { stream, track, info } = await openCamera()
  const video = document.createElement('video')
  video.muted = true
  video.playsInline = true
  video.autoplay = true
  video.srcObject = stream
  await new Promise<void>((resolve, reject) => {
    const t = window.setTimeout(() => reject(new Error('Camera produced no frames within 8 s')), 8000)
    video.onloadeddata = () => {
      window.clearTimeout(t)
      resolve()
    }
  })
  await video.play().catch(() => undefined)
  onStage?.('model')
  const [{ landmarker, delegate }, refreshHz] = await Promise.all([createFaceLandmarker(), measureRefreshHz()])
  const engine = new VisionEngine({ video, stream, track, camera: info, landmarker, delegate, refreshHz })
  engine.start()
  onStage?.('ready')
  window.addEventListener('pagehide', () => engine.dispose(), { once: true })
  return engine
}
