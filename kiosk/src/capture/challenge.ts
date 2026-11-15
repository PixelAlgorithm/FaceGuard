/**
 * Step-up challenge measurement (client side). The client only MEASURES and reports timings / peaks;
 * the edge decides pass/fail (DECISION_POLICY §7.1). Completion detection here also paces the UI.
 *
 * Real-camera rules (from edge runtime evidence):
 * - Baseline = MEDIAN of the face frames in the baseline_ms right BEFORE each prompt appears.
 * - A response STARTS only when the movement exceeds 30 % of the required delta for >= 2 consecutive
 *   frames (head / blendshape jitter must not count as an early response -> min_reaction hard fail).
 * - completed_at = first frame where the edge's own pass threshold is crossed.
 * - Turns use the DELTA vs the baseline yaw (+ = subject's left), like the edge.
 * - Tracking is "lost" only for a continuous gap > trackingLostMs or a second face persisting >= 3 frames;
 *   identity jumps use IoU + centroid continuity, not single-frame detector glitches.
 */
import { THRESHOLDS, UI } from '../config'
import type { ChallengeAction, ChallengeActionResult } from '../api/types'
import { BLEND_KEYS, type BlendSubset, type FaceObservation, type FrameAnalysis } from './engine'
import { meanShift, normalisedPoints, type Point } from './geometry'

export interface NeutralBaseline {
  blend: BlendSubset
  yawDeg: number
  points: Point[] | null
  frames: number
}

const ZERO_BLEND: BlendSubset = {
  mouthSmileLeft: 0,
  mouthSmileRight: 0,
  jawOpen: 0,
  cheekPuff: 0,
  eyeBlinkLeft: 0,
  eyeBlinkRight: 0,
}

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b)
  const m = s.length >> 1
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2
}

const mean = (xs: number[]) => xs.reduce((a, b) => a + b, 0) / xs.length

/** Baseline over face frames: `median` for challenge baselines (robust to a blink), mean for FramesMeta. */
export function computeBaseline(frames: FrameAnalysis[], agg: 'mean' | 'median' = 'mean'): NeutralBaseline | null {
  const withFace = frames.filter((f): f is FrameAnalysis & { face: FaceObservation } => f.face !== null)
  if (withFace.length === 0) return null
  const red = agg === 'median' ? median : mean
  const blend = { ...ZERO_BLEND }
  for (const k of BLEND_KEYS) blend[k] = red(withFace.map((f) => f.face.blend[k]))
  const yawDeg = red(withFace.map((f) => f.face.yawDeg))
  const sets = withFace.map((f) => normalisedPoints(f.face.landmarks, f.width, f.height, f.face.eyes))
  const points = sets[0].map((_, i) => ({ x: red(sets.map((s) => s[i].x)), y: red(sets.map((s) => s[i].y)) }))
  return { blend, yawDeg, points, frames: withFace.length }
}

export const EMPTY_BASELINE: NeutralBaseline = { blend: { ...ZERO_BLEND }, yawDeg: 0, points: null, frames: 0 }

/** Mean of a blendshape baseline (used for FramesMeta.blendshapes: first baseline_ms after face lock). */
export function blendBaselineMeta(frames: FrameAnalysis[]): BlendSubset {
  return computeBaseline(frames)?.blend ?? { ...ZERO_BLEND }
}

const isDeformation = (a: ChallengeAction) => a === 'SMILE' || a === 'OPEN_MOUTH' || a === 'PUFF_CHEEKS'
const isTurn = (a: ChallengeAction) => a === 'TURN_LEFT' || a === 'TURN_RIGHT'

function metric(action: ChallengeAction, blend: BlendSubset, yawDeg: number): number {
  switch (action) {
    case 'SMILE':
      return (blend.mouthSmileLeft + blend.mouthSmileRight) / 2
    case 'OPEN_MOUTH':
      return blend.jawOpen
    case 'PUFF_CHEEKS':
      return blend.cheekPuff
    case 'BLINK':
      return (blend.eyeBlinkLeft + blend.eyeBlinkRight) / 2
    case 'TURN_LEFT':
      return yawDeg // + = subject's left
    case 'TURN_RIGHT':
      return -yawDeg
  }
}

const r4 = (x: number) => Math.round(x * 10000) / 10000
const r1 = (x: number) => Math.round(x * 10) / 10

/** Continuity of the face over time: tolerant of brief detector drops and one-frame glitches. */
class FaceTrack {
  private gapStart: number | null = null
  private lastPerf: number | null = null
  private lastBox: [number, number, number, number] | null = null
  private multiRun = 0
  longestGapMs = 0
  multiFace = false
  jumped = false

  update(f: FrameAnalysis): void {
    if (!f.face) {
      if (this.gapStart === null) this.gapStart = this.lastPerf ?? f.perfMs
      this.longestGapMs = Math.max(this.longestGapMs, f.perfMs - this.gapStart)
      this.lastPerf = f.perfMs
      return
    }
    if (this.gapStart !== null) {
      this.longestGapMs = Math.max(this.longestGapMs, f.perfMs - this.gapStart)
      this.gapStart = null
    }
    this.lastPerf = f.perfMs
    // A second significant face must persist (>= 3 consecutive frames) - single-frame false detections happen.
    this.multiRun = f.faceCount > 1 ? this.multiRun + 1 : 0
    if (this.multiRun >= 3) this.multiFace = true
    const box = f.face.box
    if (this.lastBox) {
      // Identity jump = boxes stop overlapping AND the centre moved more than one face width.
      const a = this.lastBox
      const ix = Math.max(0, Math.min(a[0] + a[2], box[0] + box[2]) - Math.max(a[0], box[0]))
      const iy = Math.max(0, Math.min(a[1] + a[3], box[1] + box[3]) - Math.max(a[1], box[1]))
      const inter = ix * iy
      const iou = inter / (a[2] * a[3] + box[2] * box[3] - inter || 1)
      const dx = a[0] + a[2] / 2 - (box[0] + box[2] / 2)
      const dy = a[1] + a[3] / 2 - (box[1] + box[3] / 2)
      if (iou < 0.2 && Math.hypot(dx, dy) > Math.max(a[2], box[2])) this.jumped = true
    }
    this.lastBox = box
  }

  get lost(): boolean {
    return this.multiFace || this.jumped || this.longestGapMs > UI.trackingLostMs
  }
}

export class ActionTracker {
  readonly action: ChallengeAction
  private readonly baseline: NeutralBaseline
  private readonly base: number
  private readonly track = new FaceTrack()
  private promptedPerf: number | null = null
  private promptedEpoch = 0
  private startedEpoch: number | null = null
  private onsetCandidate: number | null = null
  private onsetRun = 0
  private completedEpoch: number | null = null
  private peak = -Infinity
  private shiftMax = 0
  private yawCmdPeak: number | null = null // signed yaw furthest in the commanded direction
  private yawWrongPeak: number | null = null // signed yaw furthest in the opposite direction
  private blinkClosed = false
  private frames = 0

  constructor(action: ChallengeAction, baseline: NeutralBaseline) {
    this.action = action
    this.baseline = baseline
    this.base = metric(action, baseline.blend, baseline.yawDeg)
  }

  get armed(): boolean {
    return this.promptedPerf !== null
  }

  get complete(): boolean {
    return this.completedEpoch !== null
  }

  /** Diagnostics for the ?debug=1 overlay / console summary. */
  get framesSeen(): number {
    return this.frames
  }

  get currentPeak(): number | null {
    return Number.isFinite(this.peak) ? this.peak : null
  }

  get baselineValue(): number {
    return this.base
  }

  /** Called when the prompt is on screen (layout effect of the prompt). */
  arm(promptedPerf: number): void {
    if (this.promptedPerf !== null) return
    this.promptedPerf = promptedPerf
    this.promptedEpoch = Math.round(performance.timeOrigin + promptedPerf)
  }

  update(f: FrameAnalysis): void {
    if (this.promptedPerf === null || f.perfMs < this.promptedPerf) return
    this.track.update(f)
    const face = f.face
    if (!face) return
    this.frames++
    const c = THRESHOLDS.challenge
    const v = metric(this.action, face.blend, face.yawDeg)
    if (v > this.peak) this.peak = v
    if (isTurn(this.action)) {
      const want = this.action === 'TURN_LEFT' ? 1 : -1
      if (this.yawCmdPeak === null || want * face.yawDeg > want * this.yawCmdPeak) this.yawCmdPeak = face.yawDeg
      if (this.yawWrongPeak === null || want * face.yawDeg < want * this.yawWrongPeak) this.yawWrongPeak = face.yawDeg
    }
    if (isDeformation(this.action) && this.baseline.points) {
      const shift = meanShift(normalisedPoints(face.landmarks, f.width, f.height, face.eyes), this.baseline.points)
      if (shift > this.shiftMax) this.shiftMax = shift
    }
    const delta = v - this.base
    // Onset = >= 30 % of the required delta, sustained for >= 2 consecutive frames (jitter is not a response).
    const onset = isDeformation(this.action)
      ? 0.3 * c.deformationRiseMin
      : this.action === 'BLINK'
        ? 0.3 * Math.max(0.05, c.blinkCloseMin - this.base)
        : 0.3 * c.turnYawMinDeg
    if (this.startedEpoch === null) {
      if (delta >= onset) {
        if (this.onsetCandidate === null) this.onsetCandidate = f.epochMs
        this.onsetRun++
        if (this.onsetRun >= 2) this.startedEpoch = this.onsetCandidate
      } else {
        this.onsetCandidate = null
        this.onsetRun = 0
      }
    }
    if (this.completedEpoch !== null || this.startedEpoch === null) return
    // completed_at = first frame where the edge's pass threshold is crossed.
    if (isDeformation(this.action)) {
      const abs =
        this.action === 'SMILE' ? c.smileAbsMin : this.action === 'OPEN_MOUTH' ? c.jawOpenAbsMin : c.cheekPuffAbsMin
      if (v >= abs && delta >= c.deformationRiseMin) this.completedEpoch = f.epochMs
    } else if (this.action === 'BLINK') {
      if (v >= c.blinkCloseMin) this.blinkClosed = true
      else if (this.blinkClosed && v <= Math.max(c.blinkOpenMax, this.base + 0.1)) this.completedEpoch = f.epochMs
    } else if (delta >= c.turnYawMinDeg) {
      // Turn: delta vs the neutral baseline yaw in the commanded direction (edge uses the same delta).
      this.completedEpoch = f.epochMs
    }
  }

  /**
   * Turn evidence: absolute signed yaw (deg, + = subject's left) at the extreme in the commanded direction,
   * or the wrong-way extreme if the head clearly moved further the wrong way; `baseline` = neutral yaw so
   * the edge can use the delta.
   */
  private turnPeak(): number {
    const b = this.baseline.yawDeg
    const want = this.action === 'TURN_LEFT' ? 1 : -1
    const cmd = this.yawCmdPeak ?? b
    const wrong = this.yawWrongPeak ?? b
    const movedRight = want * (cmd - b)
    const movedWrong = want * (b - wrong)
    return movedWrong > movedRight + 5 ? wrong : cmd
  }

  result(): ChallengeActionResult {
    const turn = isTurn(this.action)
    const peak = Number.isFinite(this.peak) ? this.peak : this.base
    const yawPeak = turn ? r1(this.turnPeak()) : null
    return {
      action: this.action,
      prompted_at_ms: this.promptedEpoch,
      started_at_ms: this.startedEpoch,
      completed_at_ms: this.completedEpoch,
      baseline: turn ? r1(this.baseline.yawDeg) : r4(this.base),
      peak: turn ? (yawPeak ?? 0) : r4(peak),
      landmark_shift: isDeformation(this.action) ? r4(this.shiftMax) : null,
      yaw_peak_deg: yawPeak,
      tracking_lost: this.track.lost,
    }
  }
}

/** same_track for the whole challenge (same tolerant rules as per-action tracking). */
export class TrackContinuity {
  private readonly track = new FaceTrack()

  update(f: FrameAnalysis): void {
    this.track.update(f)
  }

  sameTrack(): boolean {
    return !this.track.lost
  }

  describe(): string {
    const t = this.track
    return `longest_gap=${Math.round(t.longestGapMs)}ms multi=${t.multiFace} jump=${t.jumped}`
  }
}
