/**
 * Face geometry from MediaPipe Face Landmarker output (478-point mesh, normalised, UNMIRRORED frame).
 * Sign convention used across the kiosk payloads: yaw_deg > 0 means the subject turned to THEIR left
 * (nose moves toward the image's right in the unmirrored camera frame).
 */
import type { NormalizedLandmark } from '@mediapipe/tasks-vision'

export const LM = {
  rightEyeOuter: 33, // subject's right eye (image left)
  rightEyeInner: 133,
  leftEyeInner: 362,
  leftEyeOuter: 263,
  noseTip: 1,
} as const

/** Skin ROI patches for the colour-flash chroma series: forehead + both cheeks (no eyes / mouth). */
export const SKIN_PATCH_LANDMARKS = [151, 108, 337, 50, 118, 280, 347] as const

/** Cheek / nasolabial / mouth-corner points whose displacement evidences real facial deformation. */
export const DEFORMATION_LANDMARKS = [61, 291, 50, 280, 205, 425, 0, 17] as const

export interface Point {
  x: number
  y: number
}

export function toPx(l: NormalizedLandmark, w: number, h: number): Point {
  return { x: l.x * w, y: l.y * h }
}

const mid = (a: Point, b: Point): Point => ({ x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 })
const dist = (a: Point, b: Point) => Math.hypot(a.x - b.x, a.y - b.y)

export interface EyeGeometry {
  iodPx: number // distance between eye centres, video pixels
  eyeMid: Point // video pixels
  /** unit vector from the subject's RIGHT eye centre to their LEFT eye centre (image space, unmirrored) */
  axis: Point
}

export function eyeGeometry(lms: NormalizedLandmark[], w: number, h: number): EyeGeometry {
  const rightEye = mid(toPx(lms[LM.rightEyeOuter], w, h), toPx(lms[LM.rightEyeInner], w, h))
  const leftEye = mid(toPx(lms[LM.leftEyeOuter], w, h), toPx(lms[LM.leftEyeInner], w, h))
  const iod = dist(rightEye, leftEye)
  const axis = iod > 0 ? { x: (leftEye.x - rightEye.x) / iod, y: (leftEye.y - rightEye.y) / iod } : { x: 1, y: 0 }
  return { iodPx: iod, eyeMid: mid(rightEye, leftEye), axis }
}

/** Normalised [x, y, w, h] bounding box of all landmarks (clamped to the frame). */
export function landmarkBox(lms: NormalizedLandmark[]): [number, number, number, number] {
  let x0 = 1
  let y0 = 1
  let x1 = 0
  let y1 = 0
  for (const l of lms) {
    if (l.x < x0) x0 = l.x
    if (l.y < y0) y0 = l.y
    if (l.x > x1) x1 = l.x
    if (l.y > y1) y1 = l.y
  }
  x0 = Math.max(0, x0)
  y0 = Math.max(0, y0)
  x1 = Math.min(1, x1)
  y1 = Math.min(1, y1)
  return [x0, y0, Math.max(0, x1 - x0), Math.max(0, y1 - y0)]
}

/** Unclamped extents, used to detect a face cut off by the frame edge. */
export function landmarkExtents(lms: NormalizedLandmark[]): { x0: number; y0: number; x1: number; y1: number } {
  let x0 = Infinity
  let y0 = Infinity
  let x1 = -Infinity
  let y1 = -Infinity
  for (const l of lms) {
    x0 = Math.min(x0, l.x)
    y0 = Math.min(y0, l.y)
    x1 = Math.max(x1, l.x)
    y1 = Math.max(y1, l.y)
  }
  return { x0, y0, x1, y1 }
}

/**
 * Yaw proxy from landmarks (sign-reliable, roll-invariant): offset of the nose tip from the eye midpoint
 * projected on the eye axis (right eye -> left eye), in units of IOD.
 * > 0 => nose shifted toward the subject's left eye => subject turned to THEIR left.
 */
export function yawProxy(lms: NormalizedLandmark[], w: number, h: number, eyes: EyeGeometry): number {
  if (eyes.iodPx <= 0) return 0
  const nose = toPx(lms[LM.noseTip], w, h)
  return ((nose.x - eyes.eyeMid.x) * eyes.axis.x + (nose.y - eyes.eyeMid.y) * eyes.axis.y) / eyes.iodPx
}

const RAD2DEG = 180 / Math.PI

/**
 * Euler angles (deg) from MediaPipe's 4x4 facial transformation matrix (column-major data).
 * Magnitudes are used for the pose gate; the yaw SIGN is re-derived from the landmark proxy.
 */
export function eulerFromMatrix(data: ArrayLike<number>): { yaw: number; pitch: number; roll: number } {
  const r00 = data[0]
  const r10 = data[1]
  const r20 = data[2]
  const r21 = data[6]
  const r22 = data[10]
  const pitch = Math.atan2(r21, r22) * RAD2DEG
  const yaw = Math.atan2(-r20, Math.hypot(r21, r22)) * RAD2DEG
  const roll = Math.atan2(r10, r00) * RAD2DEG
  return { yaw, pitch, roll }
}

/** Fallback pose from landmarks only (when no matrix is available). */
export function poseFromLandmarks(
  lms: NormalizedLandmark[],
  w: number,
  h: number,
  eyes: EyeGeometry,
): { yaw: number; pitch: number; roll: number } {
  const rightEye = toPx(lms[LM.rightEyeOuter], w, h)
  const leftEye = toPx(lms[LM.leftEyeOuter], w, h)
  const roll = Math.atan2(leftEye.y - rightEye.y, leftEye.x - rightEye.x) * RAD2DEG
  const yaw = Math.asin(Math.max(-1, Math.min(1, yawProxy(lms, w, h, eyes) / 1.1))) * RAD2DEG
  const nose = toPx(lms[LM.noseTip], w, h)
  const pitch = Math.asin(Math.max(-1, Math.min(1, ((nose.y - eyes.eyeMid.y) / eyes.iodPx - 0.55) / 0.9))) * RAD2DEG
  return { yaw, pitch, roll }
}

/** Mean displacement of DEFORMATION_LANDMARKS vs a neutral reference, in units of IOD (pose-normalised). */
export function normalisedPoints(lms: NormalizedLandmark[], w: number, h: number, eyes: EyeGeometry): Point[] {
  const s = eyes.iodPx > 0 ? eyes.iodPx : 1
  return DEFORMATION_LANDMARKS.map((i) => {
    const p = toPx(lms[i], w, h)
    return { x: (p.x - eyes.eyeMid.x) / s, y: (p.y - eyes.eyeMid.y) / s }
  })
}

export function meanShift(a: Point[], b: Point[]): number {
  if (a.length === 0 || a.length !== b.length) return 0
  let sum = 0
  for (let i = 0; i < a.length; i++) sum += dist(a[i], b[i])
  return sum / a.length
}
