/**
 * Client-side quality gate (ADVISORY). Turns one frame analysis into ONE instruction for the user.
 * Thresholds come from config/thresholds.yaml (quality.*); the edge re-checks on the uploaded JPEGs.
 */
import { THRESHOLDS, UI } from '../config'
import type { FrameAnalysis } from './engine'

export type Guidance =
  | 'NO_FACE'
  | 'MULTIPLE_FACES'
  | 'MOVE_BACK'
  | 'MOVE_CLOSER'
  | 'CENTER'
  | 'FACE_CAMERA'
  | 'MORE_LIGHT'
  | 'TOO_BRIGHT'
  | 'HOLD_STILL'
  | 'OK'

export const GUIDANCE_TEXT: Record<Guidance, string> = {
  NO_FACE: 'Look at the camera',
  MULTIPLE_FACES: 'One person at a time',
  MOVE_BACK: 'Move back a little',
  MOVE_CLOSER: 'Move closer',
  CENTER: 'Centre your face in the oval',
  FACE_CAMERA: 'Face the camera',
  MORE_LIGHT: 'More light needed',
  TOO_BRIGHT: 'Too bright – avoid strong light on or behind you',
  HOLD_STILL: 'Hold still',
  OK: 'Hold still',
}

export interface QualityAssessment {
  guidance: Guidance
  ok: boolean
}

export function assessQuality(f: FrameAnalysis, prev: FrameAnalysis | null, uploadMaxWidth: number): QualityAssessment {
  const q = THRESHOLDS.quality
  const face = f.face
  if (!face || f.faceCount === 0) return { guidance: 'NO_FACE', ok: false }
  if (f.faceCount > 1) return { guidance: 'MULTIPLE_FACES', ok: false }
  if (face.truncated || face.box[2] > UI.maxFaceWidthFraction) return { guidance: 'MOVE_BACK', ok: false }

  // Sizes are checked in UPLOADED-frame pixels, which is what the edge measures.
  const scale = Math.min(1, uploadMaxWidth / f.width)
  if (face.iodPx * scale < q.minInterocularPx || face.faceWidthPx * scale < q.minFaceWidthPx) {
    return { guidance: 'MOVE_CLOSER', ok: false }
  }
  if (Math.hypot(face.center.x - 0.5, face.center.y - 0.5) > UI.maxCenterOffset) {
    return { guidance: 'CENTER', ok: false }
  }
  if (
    Math.abs(face.yawDeg) > q.maxAbsYawDeg ||
    Math.abs(face.pitchDeg) > q.maxAbsPitchDeg ||
    Math.abs(face.rollDeg) > q.maxAbsRollDeg
  ) {
    return { guidance: 'FACE_CAMERA', ok: false }
  }
  const crop = face.crop
  if (crop) {
    if (crop.luma < q.minLumaMean) return { guidance: 'MORE_LIGHT', ok: false }
    if (crop.luma > q.maxLumaMean || crop.overexposed > q.maxOverexposedFraction) {
      return { guidance: 'TOO_BRIGHT', ok: false }
    }
    if (crop.blurVar < q.minLaplacianVar * UI.clientBlurFactor) return { guidance: 'HOLD_STILL', ok: false }
  }
  if (prev?.face) {
    const moved = Math.hypot(face.center.x - prev.face.center.x, face.center.y - prev.face.center.y)
    if (moved > UI.maxCenterJitter) return { guidance: 'HOLD_STILL', ok: false }
  }
  return { guidance: 'OK', ok: true }
}
