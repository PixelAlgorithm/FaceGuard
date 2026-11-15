/**
 * One capturing tab at a time (kiosk "/" and the opt-in capture on "/operator"). A face in front of two
 * tabs' cameras used to produce two attempts per person. Only the tab that HOLDS this lock may arm a face
 * lock / start an attempt.
 *
 * - Web Locks API (navigator.locks, same origin, cross-tab, released automatically when a tab closes or
 *   crashes) when available; otherwise a localStorage lease with a heartbeat.
 * - Holder info ({tab, role, since, beat}) is published in localStorage and announced on a BroadcastChannel,
 *   so the other tab can say who holds the camera ("Kiosk tab is capturing").
 * - enable() queues for the lock; enable(true) takes it over (the previous holder is told it lost it and
 *   queues again). disable() releases it / leaves the queue.
 */
import { useEffect, useState, useSyncExternalStore } from 'react'

export type CaptureRole = 'kiosk' | 'operator'
export type LockState = 'off' | 'waiting' | 'held'

export interface LockHolder {
  tab: string
  role: CaptureRole
  since: number
  beat: number
}

const LOCK_NAME = 'hid-kiosk-capture'
export const HOLDER_KEY = 'hid.captureLock.holder'
const CHANNEL = 'hid-capture-lock'
/** Holder info older than this is stale (crashed tab, or a lease that was not renewed). */
const LEASE_MS = 4000
const BEAT_MS = 1000
const POLL_MS = 400

function newTabId(): string {
  try {
    return crypto.randomUUID()
  } catch {
    return `tab_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`
  }
}

/** This tab's id (one per page load). */
export const TAB_ID = newTabId()

const hasWebLocks = (): boolean => typeof navigator !== 'undefined' && 'locks' in navigator && !!navigator.locks

export function readHolder(): LockHolder | null {
  try {
    const raw = window.localStorage.getItem(HOLDER_KEY)
    if (!raw) return null
    const h = JSON.parse(raw) as Partial<LockHolder>
    if (typeof h.tab !== 'string' || (h.role !== 'kiosk' && h.role !== 'operator')) return null
    return { tab: h.tab, role: h.role, since: Number(h.since) || 0, beat: Number(h.beat) || 0 }
  } catch {
    return null
  }
}

let channel: BroadcastChannel | null = null
function getChannel(): BroadcastChannel | null {
  if (channel || typeof BroadcastChannel === 'undefined') return channel
  try {
    channel = new BroadcastChannel(CHANNEL)
  } catch {
    channel = null
  }
  return channel
}

function announce(): void {
  try {
    getChannel()?.postMessage({ kind: 'holder-changed', from: TAB_ID })
  } catch {
    /* ignore */
  }
  holderListeners.forEach((l) => l())
}

function writeHolder(h: LockHolder | null): void {
  try {
    if (h) window.localStorage.setItem(HOLDER_KEY, JSON.stringify(h))
    else window.localStorage.removeItem(HOLDER_KEY)
  } catch {
    /* storage unavailable: the Web Lock itself still works */
  }
}

/** Remove the holder record only if it is ours (never clobber another tab's record). */
function clearOwnHolder(): void {
  if (readHolder()?.tab === TAB_ID) {
    writeHolder(null)
    announce()
  }
}

export class CaptureLock {
  private state: LockState = 'off'
  private readonly listeners = new Set<() => void>()
  private wanted = false
  private since = 0
  /** Web Locks: resolves the held callback (releases the lock). */
  private releaseHeld: (() => void) | null = null
  /** Web Locks: the current request (aborts a queued one; identifies stale callbacks). */
  private request: AbortController | null = null
  private beatTimer = 0
  private leaseTimer = 0
  /** localStorage lease: we wrote our claim and confirm it on the next tick. */
  private claiming = false
  private readonly role: CaptureRole

  constructor(role: CaptureRole) {
    this.role = role
  }

  getState = (): LockState => this.state

  subscribe = (fn: () => void): (() => void) => {
    this.listeners.add(fn)
    return () => this.listeners.delete(fn)
  }

  isHeld(): boolean {
    return this.state === 'held'
  }

  private setState(s: LockState): void {
    if (s === this.state) return
    this.state = s
    if (s === 'held') {
      this.since = Date.now()
      this.publish(true)
      window.clearInterval(this.beatTimer)
      this.beatTimer = window.setInterval(() => this.publish(false), BEAT_MS)
    } else {
      window.clearInterval(this.beatTimer)
      this.beatTimer = 0
      clearOwnHolder()
    }
    this.listeners.forEach((l) => l())
  }

  /**
   * Write our holder record. A heartbeat never overwrites another tab's fresh record: that tab has just
   * taken the lock over (lease) or stolen it (Web Locks, before our AbortError arrives).
   */
  private publish(force: boolean): void {
    if (this.state !== 'held') return
    const prev = readHolder()
    const now = Date.now()
    if (!force && prev && prev.tab !== TAB_ID && now - prev.beat <= LEASE_MS) return
    writeHolder({ tab: TAB_ID, role: this.role, since: this.since, beat: now })
    if (!prev || prev.tab !== TAB_ID) announce()
  }

  /** Queue for the lock (no-op if already queued / held). `takeOver` = steal it from the current holder. */
  enable(takeOver = false): void {
    if (this.wanted && !takeOver) return
    if (this.wanted && takeOver && this.state === 'held') return
    this.wanted = true
    if (hasWebLocks()) this.requestWebLock(takeOver)
    else this.startLease(takeOver)
  }

  /** Release the lock, or leave the queue. */
  disable(): void {
    this.wanted = false
    this.claiming = false
    const req = this.request
    this.request = null
    req?.abort()
    const release = this.releaseHeld
    this.releaseHeld = null
    release?.()
    window.clearTimeout(this.leaseTimer)
    this.leaseTimer = 0
    this.setState('off')
  }

  // ---------------------------------------------------------------- Web Locks

  private requestWebLock(steal: boolean): void {
    // A previous queued request is superseded (e.g. "take over" while waiting).
    const old = this.request
    const oldRelease = this.releaseHeld
    this.releaseHeld = null
    const ctrl = new AbortController()
    this.request = ctrl
    old?.abort()
    oldRelease?.()
    if (this.state !== 'held') this.setState('waiting')
    // `signal` cannot be combined with `steal` (NotSupportedError); a steal is granted at once anyway.
    const opts: LockOptions = steal ? { mode: 'exclusive', steal: true } : { mode: 'exclusive', signal: ctrl.signal }
    navigator.locks
      .request(LOCK_NAME, opts, () => {
        if (this.request !== ctrl || !this.wanted) return undefined // superseded / disabled meanwhile
        this.setState('held')
        return new Promise<void>((resolve) => {
          this.releaseHeld = resolve
        })
      })
      .catch((e: unknown) => {
        if (this.request !== ctrl || !this.wanted) return // our own abort / release
        // The lock was stolen by another tab (AbortError on the held request): pause and queue again.
        console.info('[capture-lock] lost the camera lock to another tab; waiting', e instanceof Error ? e.name : e)
        this.releaseHeld = null
        this.request = null
        this.setState('waiting')
        this.requestWebLock(false)
      })
  }

  // ---------------------------------------------------------------- localStorage lease (fallback)

  private startLease(steal: boolean): void {
    window.clearTimeout(this.leaseTimer)
    if (this.state !== 'held') this.setState('waiting')
    let stealNow = steal
    const tick = () => {
      if (!this.wanted) return
      const h = readHolder()
      const now = Date.now()
      const othersFresh = !!h && h.tab !== TAB_ID && now - h.beat <= LEASE_MS
      if (this.state === 'held') {
        if (othersFresh) {
          this.claiming = false
          this.setState('waiting') // someone took it over
        } else this.publish(false)
      } else if (this.claiming) {
        this.claiming = false
        if (h?.tab === TAB_ID) this.setState('held')
      } else if (!othersFresh || stealNow) {
        stealNow = false
        writeHolder({ tab: TAB_ID, role: this.role, since: now, beat: now })
        this.claiming = true // confirm on the next tick (two tabs writing at once: the last writer wins)
      }
      this.leaseTimer = window.setTimeout(tick, this.state === 'held' ? BEAT_MS : POLL_MS)
    }
    tick()
  }
}

// ---------------------------------------------------------------- holder view (other tabs)

const holderListeners = new Set<() => void>()

/** Who holds the camera lock right now (null = nobody / stale record). Re-checked every second. */
export function useLockHolder(): LockHolder | null {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(t)
  }, [])
  const raw = useSyncExternalStore(subscribeHolder, holderSnapshot)
  const h = parseSnapshot(raw)
  return h && now - h.beat <= LEASE_MS ? h : null
}

function holderSnapshot(): string {
  try {
    return window.localStorage.getItem(HOLDER_KEY) ?? ''
  } catch {
    return ''
  }
}

function parseSnapshot(raw: string): LockHolder | null {
  if (!raw) return null
  try {
    const h = JSON.parse(raw) as LockHolder
    return typeof h.tab === 'string' ? h : null
  } catch {
    return null
  }
}

function subscribeHolder(cb: () => void): () => void {
  holderListeners.add(cb)
  const onStorage = (e: StorageEvent) => {
    if (e.key === HOLDER_KEY || e.key === null) cb()
  }
  window.addEventListener('storage', onStorage)
  const ch = getChannel()
  const onMsg = () => cb()
  ch?.addEventListener('message', onMsg)
  return () => {
    holderListeners.delete(cb)
    window.removeEventListener('storage', onStorage)
    ch?.removeEventListener('message', onMsg)
  }
}

/** Hook over a CaptureLock instance's state. */
export function useLockState(lock: CaptureLock): LockState {
  return useSyncExternalStore(lock.subscribe, lock.getState)
}

export function holderText(h: LockHolder | null): string {
  if (!h) return 'nobody'
  const who = h.tab === TAB_ID ? 'this tab' : h.role === 'kiosk' ? 'the kiosk tab' : 'an operator console tab'
  return who
}
