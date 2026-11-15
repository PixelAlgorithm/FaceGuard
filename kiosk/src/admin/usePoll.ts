import { useCallback, useEffect, useRef, useState } from 'react'

export interface PollState<T> {
  data: T | null
  error: string | null
  loadedAt: number | null
  /** a request is in flight */
  loading: boolean
  refresh: () => void
}

interface Inner<T> {
  data: T | null
  error: string | null
  loadedAt: number | null
  loading: boolean
  /** the key/enabled pair this state belongs to (state of another key is never shown) */
  for: string
}

const EMPTY = { data: null, error: null, loadedAt: null, loading: false }

/**
 * Minimal polling hook (no query library on an offline kiosk): ONE sequential setTimeout chain per
 * key, so a slow edge never gets overlapping requests. refresh() while a request is in flight does not
 * start a second chain; it re-runs once right after the current request. Restarts (and drops the previous
 * data, e.g. another admin token's user list) when `key` or `enabled` changes; stops on unmount.
 */
export function usePoll<T>(fetcher: () => Promise<T>, intervalMs: number, enabled: boolean, key: string): PollState<T> {
  const stateKey = `${enabled ? 1 : 0}|${key}`
  const [state, setState] = useState<Inner<T>>({ ...EMPTY, for: stateKey })
  const fetcherRef = useRef(fetcher)
  const kick = useRef<() => void>(() => undefined)

  useEffect(() => {
    fetcherRef.current = fetcher
  })

  useEffect(() => {
    if (!enabled) return
    let cancelled = false
    let timer = 0
    let inFlight = false
    let rerun = false
    const run = async () => {
      if (cancelled) return
      if (inFlight) {
        rerun = true
        return
      }
      window.clearTimeout(timer)
      inFlight = true
      setState((s) => (s.for === stateKey ? { ...s, loading: true } : { ...EMPTY, loading: true, for: stateKey }))
      try {
        const data = await fetcherRef.current()
        if (!cancelled) setState({ data, error: null, loadedAt: Date.now(), loading: false, for: stateKey })
      } catch (e) {
        if (!cancelled) {
          const error = e instanceof Error ? e.message : String(e)
          setState((s) => ({ ...(s.for === stateKey ? s : { ...EMPTY, for: stateKey }), error, loadedAt: Date.now(), loading: false }))
        }
      } finally {
        inFlight = false
      }
      if (cancelled) return
      if (rerun) {
        rerun = false
        void run()
      } else {
        timer = window.setTimeout(() => void run(), intervalMs)
      }
    }
    kick.current = () => void run()
    void run()
    return () => {
      cancelled = true
      window.clearTimeout(timer)
      kick.current = () => undefined
    }
  }, [enabled, intervalMs, key, stateKey])

  const refresh = useCallback(() => kick.current(), [])
  const current = state.for === stateKey ? state : { ...EMPTY, for: stateKey }
  return { data: current.data, error: current.error, loadedAt: current.loadedAt, loading: current.loading, refresh }
}
