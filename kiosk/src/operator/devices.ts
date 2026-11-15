/**
 * Camera device list for /operator and /register: every `videoinput` the browser exposes (built-in camera,
 * USB webcams, the iPhone via macOS Continuity Camera), the persisted choice, and live updates when a
 * camera appears or disappears (`devicechange`, e.g. the iPhone connecting).
 * Labels are only exposed after camera permission, so callers refresh after the first stream opens.
 */
import { useCallback, useEffect, useState } from 'react'
import { matchVirtualCamera } from '../capture/camera'
import { THRESHOLDS, writeLocal } from '../config'

/** localStorage key of the chosen camera (deviceId). The kiosk route can pass it to openCamera(). */
export const CAMERA_STORAGE_KEY = 'hid.cameraDeviceId'

export type CameraKind = 'iphone' | 'virtual' | 'builtin' | 'external'

export interface VideoDevice {
  deviceId: string
  label: string
  kind: CameraKind
  /** virtual-camera label pattern it matched (the edge DENIES these: INJECTION_VIRTUAL_CAMERA) */
  virtualMatch: string | null
}

export function classifyCamera(label: string): { kind: CameraKind; virtualMatch: string | null } {
  const virtualMatch = matchVirtualCamera(label, THRESHOLDS.injection.virtualCameraLabelPatterns)
  if (virtualMatch) return { kind: 'virtual', virtualMatch }
  const l = label.toLowerCase()
  if (l.includes('iphone') || l.includes('continuity')) return { kind: 'iphone', virtualMatch: null }
  if (/facetime|built-in|macbook|integrated/.test(l)) return { kind: 'builtin', virtualMatch: null }
  return { kind: 'external', virtualMatch: null }
}

export const KIND_TAG: Record<CameraKind, string> = {
  iphone: 'iPhone · Continuity Camera',
  virtual: 'VIRTUAL CAMERA · edge will DENY',
  builtin: 'built-in',
  external: 'external',
}

export function readPreferredCamera(): string | null {
  try {
    return window.localStorage.getItem(CAMERA_STORAGE_KEY)
  } catch {
    return null
  }
}

export function writePreferredCamera(deviceId: string | null): void {
  writeLocal(CAMERA_STORAGE_KEY, deviceId)
}

export async function listVideoInputs(): Promise<VideoDevice[]> {
  if (!navigator.mediaDevices?.enumerateDevices) return []
  const all = await navigator.mediaDevices.enumerateDevices()
  return all
    .filter((d) => d.kind === 'videoinput' && d.deviceId)
    .map((d, i) => {
      const label = d.label || `Camera ${i + 1} (name hidden until camera permission is granted)`
      return { deviceId: d.deviceId, label, ...classifyCamera(d.label) }
    })
}

export function useVideoDevices(): { devices: VideoDevice[]; refresh: () => Promise<void>; error: string | null } {
  const [devices, setDevices] = useState<VideoDevice[]>([])
  const [error, setError] = useState<string | null>(null)
  const refresh = useCallback(
    () =>
      listVideoInputs().then(
        (list) => {
          setDevices(list)
          setError(null)
        },
        (e: unknown) => setError(e instanceof Error ? e.message : String(e)),
      ),
    [],
  )
  useEffect(() => {
    let alive = true
    const load = () => {
      listVideoInputs().then(
        (list) => {
          if (!alive) return
          setDevices(list)
          setError(null)
        },
        (e: unknown) => {
          if (alive) setError(e instanceof Error ? e.message : String(e))
        },
      )
    }
    load()
    const md = navigator.mediaDevices
    md?.addEventListener?.('devicechange', load)
    return () => {
      alive = false
      md?.removeEventListener?.('devicechange', load)
    }
  }, [])
  return { devices, refresh, error }
}
