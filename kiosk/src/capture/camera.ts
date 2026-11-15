/** Camera open + injection signals (virtual-camera label check, device count, settings). */
import { THRESHOLDS } from '../config'

export interface CameraInfo {
  label: string
  deviceCount: number
  deviceIdHash: string
  settings: MediaTrackSettings
  virtualSuspected: boolean
  virtualMatch: string | null
  knownGood: boolean
  allLabels: string[]
  /** exposure / white-balance controls the camera exposes (describeCameraControls) */
  controls: string
}

export class CameraError extends Error {
  readonly kind: 'denied' | 'not_found' | 'busy' | 'insecure' | 'other'
  constructor(kind: CameraError['kind'], message: string) {
    super(message)
    this.name = 'CameraError'
    this.kind = kind
  }
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

/** Case-insensitive whole-word match of the label against injection.virtual_camera_label_patterns. */
export function matchVirtualCamera(label: string, patterns: readonly string[]): string | null {
  for (const p of patterns) {
    if (!p.trim()) continue
    if (new RegExp(`(^|[^a-z0-9])${escapeRe(p.trim().toLowerCase())}([^a-z0-9]|$)`, 'i').test(label)) return p
  }
  return null
}

export function matchesAny(label: string, patterns: readonly string[]): boolean {
  const l = label.toLowerCase()
  return patterns.some((p) => p && l.includes(p.toLowerCase()))
}

async function sha256Short(text: string): Promise<string> {
  if (!text || !crypto.subtle) return ''
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return Array.from(new Uint8Array(buf).slice(0, 8), (b) => b.toString(16).padStart(2, '0')).join('')
}

export async function openCamera(preferredDeviceId?: string | null): Promise<{
  stream: MediaStream
  track: MediaStreamTrack
  info: CameraInfo
}> {
  if (!window.isSecureContext || !navigator.mediaDevices?.getUserMedia) {
    throw new CameraError('insecure', 'Camera API unavailable: open the kiosk on http://localhost or https.')
  }
  const video: MediaTrackConstraints = {
    width: { ideal: 1280 },
    height: { ideal: 720 },
    frameRate: { ideal: 30 },
    ...(preferredDeviceId ? { deviceId: { exact: preferredDeviceId } } : { facingMode: 'user' }),
  }
  let stream: MediaStream
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video, audio: false })
  } catch (e) {
    const name = e instanceof DOMException ? e.name : ''
    if (name === 'NotAllowedError' || name === 'SecurityError') {
      throw new CameraError('denied', 'Camera permission was denied.')
    }
    if (name === 'NotFoundError' || name === 'OverconstrainedError') {
      throw new CameraError('not_found', 'No usable camera was found.')
    }
    if (name === 'NotReadableError' || name === 'AbortError') {
      throw new CameraError('busy', 'The camera is in use by another application.')
    }
    throw new CameraError('other', `Camera failed to start: ${e instanceof Error ? e.message : String(e)}`)
  }
  const track = stream.getVideoTracks()[0]
  if (!track) throw new CameraError('not_found', 'Camera stream has no video track.')

  // Labels are only exposed after permission is granted, so enumerate after getUserMedia.
  let devices: MediaDeviceInfo[] = []
  try {
    devices = (await navigator.mediaDevices.enumerateDevices()).filter((d) => d.kind === 'videoinput')
  } catch {
    devices = []
  }
  const settings = track.getSettings()
  const activeDevice = devices.find((d) => d.deviceId && d.deviceId === settings.deviceId)
  const label = track.label || activeDevice?.label || ''
  const virtualMatch = matchVirtualCamera(label, THRESHOLDS.injection.virtualCameraLabelPatterns)
  return {
    stream,
    track,
    info: {
      label,
      deviceCount: devices.length,
      deviceIdHash: await sha256Short(settings.deviceId ?? ''),
      settings,
      virtualSuspected: virtualMatch !== null,
      virtualMatch,
      knownGood: matchesAny(label, THRESHOLDS.injection.knownGoodLabelPatterns),
      allLabels: devices.map((d) => d.label).filter(Boolean),
      controls: describeCameraControls(track),
    },
  }
}

type Range = { min?: number; max?: number; step?: number }
type ImageCaps = MediaTrackCapabilities & {
  exposureMode?: string[]
  whiteBalanceMode?: string[]
  exposureTime?: Range
  colorTemperature?: Range
}
type ImageSettings = MediaTrackSettings & {
  exposureMode?: string
  whiteBalanceMode?: string
  exposureTime?: number
  colorTemperature?: number
  resizeMode?: string
}

export interface ExposureLock {
  locked: boolean
  /** constraints to re-apply after the flash window (the modes that were active before) */
  restore: Record<string, string | number> | null
  applied: Record<string, string | number>
}

export const NO_LOCK: ExposureLock = { locked: false, restore: null, applied: {} }

/** What the camera exposes for exposure / white balance (reported for the operator / lead). */
export function describeCameraControls(track: MediaStreamTrack): string {
  const caps = (track.getCapabilities?.() ?? {}) as ImageCaps
  const s = track.getSettings() as ImageSettings
  const parts: string[] = []
  if (caps.exposureMode?.length) parts.push(`exposureMode=[${caps.exposureMode.join(',')}]${s.exposureMode ? `(${s.exposureMode})` : ''}`)
  if (caps.whiteBalanceMode?.length) {
    parts.push(`whiteBalanceMode=[${caps.whiteBalanceMode.join(',')}]${s.whiteBalanceMode ? `(${s.whiteBalanceMode})` : ''}`)
  }
  if (caps.exposureTime) parts.push(`exposureTime=${caps.exposureTime.min}..${caps.exposureTime.max}`)
  if (caps.colorTemperature) parts.push(`colorTemperature=${caps.colorTemperature.min}..${caps.colorTemperature.max}`)
  return parts.length ? parts.join(' ') : 'none (no exposure/white-balance controls exposed)'
}

/**
 * Lock auto-exposure and auto white balance for the flash window so the camera does not chase (and cancel)
 * the colour cast: 'manual' mode pinned at the CURRENT exposureTime / colorTemperature where exposed.
 * Best effort - many built-in laptop cameras expose none of these in Chrome. Restore with restoreExposure().
 */
export async function lockExposure(track: MediaStreamTrack): Promise<ExposureLock> {
  const caps = (track.getCapabilities?.() ?? {}) as ImageCaps
  const before = track.getSettings() as ImageSettings
  const set: Record<string, string | number> = {}
  if (caps.exposureMode?.includes('manual')) {
    set.exposureMode = 'manual'
    if (caps.exposureTime && typeof before.exposureTime === 'number') set.exposureTime = before.exposureTime
  }
  if (caps.whiteBalanceMode?.includes('manual')) {
    set.whiteBalanceMode = 'manual'
    if (caps.colorTemperature && typeof before.colorTemperature === 'number') set.colorTemperature = before.colorTemperature
  }
  if (Object.keys(set).length === 0) return NO_LOCK
  const restore: Record<string, string | number> = {}
  if (before.exposureMode && before.exposureMode !== 'manual') restore.exposureMode = before.exposureMode
  if (before.whiteBalanceMode && before.whiteBalanceMode !== 'manual') restore.whiteBalanceMode = before.whiteBalanceMode
  try {
    await track.applyConstraints({ advanced: [set as MediaTrackConstraintSet] })
    const s = track.getSettings() as ImageSettings
    return {
      locked: s.exposureMode === 'manual' || s.whiteBalanceMode === 'manual',
      restore: Object.keys(restore).length ? restore : null,
      applied: set,
    }
  } catch (e) {
    console.warn('[camera] exposure/white-balance lock rejected', e)
    return NO_LOCK
  }
}

export async function restoreExposure(track: MediaStreamTrack, lock: ExposureLock): Promise<void> {
  if (!lock.restore) return
  try {
    await track.applyConstraints({ advanced: [lock.restore as MediaTrackConstraintSet] })
  } catch {
    /* ignore */
  }
}

/** Compact, JSON-safe subset of MediaTrackSettings for client_signals.track_settings. */
export function trackSettingsSummary(info: CameraInfo, track: MediaStreamTrack): Record<string, string | number | boolean> {
  const s = track.getSettings() as ImageSettings
  const out: Record<string, string | number | boolean> = {}
  if (typeof s.width === 'number') out.width = s.width
  if (typeof s.height === 'number') out.height = s.height
  if (typeof s.frameRate === 'number') out.frameRate = Math.round(s.frameRate * 100) / 100
  if (typeof s.facingMode === 'string' && s.facingMode) out.facingMode = s.facingMode
  if (typeof s.resizeMode === 'string' && s.resizeMode) out.resizeMode = s.resizeMode
  if (typeof s.exposureMode === 'string') out.exposureMode = s.exposureMode
  if (typeof s.whiteBalanceMode === 'string') out.whiteBalanceMode = s.whiteBalanceMode
  if (info.deviceIdHash) out.deviceIdHash = info.deviceIdHash
  out.controls = info.controls
  return out
}
