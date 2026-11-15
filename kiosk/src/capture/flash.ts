/**
 * Colour-flash photosensitivity guard. The kiosk paints whatever sequence the edge issues (currently
 * 3 colours x ~333 ms) UNLESS it would exceed liveness.flash.max_changes_per_s colour changes in any 1 s
 * window or strobe (step < 200 ms). A refused sequence -> the kiosk restarts the attempt on the
 * accessible non-flash path (flash_enabled = false) instead of flashing the user.
 */
import type { FlashStep } from '../api/types'

const HEX = /^#?([0-9a-f]{6})$/i
const MIN_STEP_MS = 200

export function parseHex(color: string): [number, number, number] | null {
  const m = HEX.exec(color.trim())
  if (!m) return null
  const n = parseInt(m[1], 16)
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255]
}

/**
 * Max-saturation variant of an issued colour (each channel to 0 or 255, same hue family):
 * #FF4D4D -> #FF0000, #4DFF6A -> #00FF00, #4D6BFF -> #0000FF, #FFF04D -> #FFFF00 ... (more light on the face).
 */
export function saturate(color: string): string {
  const rgb = parseHex(color)
  if (!rgb) return color
  const hex = rgb.map((c) => (c >= 128 ? 'FF' : '00')).join('')
  return hex === '000000' ? color : `#${hex}`
}

export function sortFlash(seq: FlashStep[]): FlashStep[] {
  return [...seq].sort((a, b) => a.offset_ms - b.offset_ms)
}

export function checkFlashSafety(seq: FlashStep[], maxChangesPerS: number): { ok: boolean; reason: string | null } {
  if (seq.length === 0) return { ok: true, reason: null }
  const steps = sortFlash(seq)
  for (const s of steps) {
    if (!parseHex(s.color)) return { ok: false, reason: `invalid colour ${s.color}` }
    if (!(s.duration_ms >= MIN_STEP_MS)) return { ok: false, reason: `step shorter than ${MIN_STEP_MS} ms` }
  }
  // Colour-to-colour transitions happen at the start of every step after the first.
  const changes = steps.slice(1).map((s) => s.offset_ms)
  for (let i = 0; i < changes.length; i++) {
    const inWindow = changes.filter((t) => t >= changes[i] && t < changes[i] + 1000).length
    if (inWindow > maxChangesPerS) return { ok: false, reason: `${inWindow} colour changes within 1 s` }
  }
  return { ok: true, reason: null }
}
