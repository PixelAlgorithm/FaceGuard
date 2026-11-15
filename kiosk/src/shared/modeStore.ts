/** Polls GET /v1/mode every 2 s for the always-visible ONLINE/OFFLINE/SYNCING badge + sync-queue depth. */
import { useSyncExternalStore } from 'react'
import { getApi } from '../api'
import type { ModeResponse } from '../api/types'

export interface ModeSnapshot {
  mode: ModeResponse | null
  reachable: boolean
  error: string | null
  updatedAt: number
}

let snapshot: ModeSnapshot = { mode: null, reachable: true, error: null, updatedAt: 0 }
const listeners = new Set<() => void>()
let timer = 0
let running = false
/** One GET /v1/mode at a time: refreshMode() during a request re-polls once after it (never a 2nd chain). */
let inFlight = false
let rerun = false

const POLL_MS = 2000 // kiosk-frontend spec: /v1/mode polled every 2 s

function emit(next: ModeSnapshot) {
  snapshot = next
  listeners.forEach((l) => l())
}

async function poll() {
  if (!running) return
  if (inFlight) {
    rerun = true
    return
  }
  window.clearTimeout(timer)
  inFlight = true
  try {
    const mode = await getApi().getMode()
    emit({ mode, reachable: true, error: null, updatedAt: Date.now() })
  } catch (e) {
    emit({ ...snapshot, reachable: false, error: e instanceof Error ? e.message : String(e), updatedAt: Date.now() })
  } finally {
    inFlight = false
  }
  if (!running) return
  if (rerun) {
    rerun = false
    void poll()
  } else {
    timer = window.setTimeout(poll, POLL_MS)
  }
}

/** Force an immediate refresh (e.g. after the admin toggles the mode). */
export function refreshMode(): void {
  if (!running) return
  void poll()
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  if (!running) {
    running = true
    rerun = false
    void poll()
  }
  return () => {
    listeners.delete(listener)
    if (listeners.size === 0) {
      running = false
      window.clearTimeout(timer)
    }
  }
}

const getSnapshot = () => snapshot

export function useModeStatus(): ModeSnapshot {
  return useSyncExternalStore(subscribe, getSnapshot)
}
