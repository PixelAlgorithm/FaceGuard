/**
 * /operator: verdict console. OBSERVER by default: every decision of the kiosk tab arrives on the live feed
 * (GET /v1/events) and is shown at a glance: PASS / SUSPICIOUS / DENIED, per-signal chips (scores.signals),
 * decision time, key scores against the policy bars, reason codes, name + role, plus the raw per-attempt
 * signals (GET /v1/admin/attempt/{id}/signals, admin token). No camera is opened in observer mode.
 *
 * Capturing here is opt-in (toggle) and takes the one-capturing-tab lock (shared/captureLock.ts) that the
 * kiosk tab also holds, so a face in front of both cameras no longer produces two attempts. Nothing on this
 * page can open a door; step-ups stay on the kiosk screen.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { getApi } from '../api'
import { asApiError, type DecisionResponse } from '../api/types'
import type { FrameAnalysis } from '../capture/engine'
import { GUIDANCE_TEXT, assessQuality, type Guidance } from '../capture/quality'
import { KIOSK_IDS, THRESHOLDS, UI, getAdminToken, getKioskId, setAdminToken } from '../config'
import { usePoll } from '../admin/usePoll'
import { CaptureLock, holderText, useLockHolder, useLockState } from '../shared/captureLock'
import { useModeStatus } from '../shared/modeStore'
import { runOperatorAttempt } from './attempt'
import { readPreferredCamera, useVideoDevices, writePreferredCamera } from './devices'
import { getModeRaw, getUsers, subscribeLive } from './edgeRaw'
import { useOperatorEngine } from './opEngine'
import { Btn, CameraPicker, OpHeader, Preview, inputCls } from './ui'
import { VerdictChip, VerdictPanel, type VerdictEntry } from './VerdictPanel'
import { barsFromMode, fallbackBars, type PolicyBars } from './verdict'

type Phase = 'idle' | 'armed' | 'capturing' | 'deciding' | 'result' | 'error'

/** Size checks use the edge's upload width (capture.max_width_px = 1280, API.md v1.2). */
const UPLOAD_W = UI.defaultUploadMaxWidth
/** After a verdict, re-arm once the face has been out of view this long (auto re-arm). */
const REARM_ABSENT_MS = 1000
const MAX_ENTRIES = 30

/** policy_bars per mode as last reported by GET /v1/mode (filled by the poller, read when a verdict lands). */
const barsByMode: Record<string, PolicyBars> = {}

async function fetchModeWithBars(): Promise<Record<string, unknown>> {
  const raw = await getModeRaw()
  const b = barsFromMode(raw)
  if (b?.mode) barsByMode[b.mode] = b
  return raw
}

const PHASE_TEXT: Record<Phase, string> = {
  idle: 'Not scanning. Press Start scanning (Space).',
  armed: 'Scanning: waiting for a steady face',
  capturing: 'Capturing (colour flash)…',
  deciding: 'Checking with the edge…',
  result: 'Verdict shown',
  error: 'Scan failed',
}

function errorText(e: unknown): string {
  const err = asApiError(e)
  if (!err) return e instanceof Error ? e.message : String(e)
  if (err.isUnreachable) return `Edge not responding (${err.code}). No access can be granted.`
  return `${err.code}: ${err.message}`
}

export default function OperatorApp() {
  const api = getApi()
  const devices = useVideoDevices()
  const [preferred, setPreferred] = useState<string | null>(readPreferredCamera)
  const [retryKey, setRetryKey] = useState(0)
  // Observer by default; capture is opt-in and needs the one-capturing-tab lock.
  const [captureOn, setCaptureOn] = useState(false)
  const lock = useMemo(() => new CaptureLock('operator'), [])
  const lockState = useLockState(lock)
  const holder = useLockHolder()
  useEffect(() => {
    if (captureOn) lock.enable()
    else lock.disable()
  }, [captureOn, lock])
  useEffect(() => () => lock.disable(), [lock])
  const capturing = captureOn && lockState === 'held'
  const eng = useOperatorEngine(preferred, capturing, retryKey)
  const engine = eng.engine
  const activeId = engine ? (engine.track.getSettings().deviceId ?? null) : null

  const [kioskId, setKioskId] = useState(getKioskId)
  const [flashOn, setFlashOn] = useState(true)
  const [autoRearm, setAutoRearm] = useState(true)
  const [showKiosk, setShowKiosk] = useState(true)
  const [token, setToken] = useState(getAdminToken)
  const [phase, setPhaseState] = useState<Phase>('idle')
  const [guidance, setGuidance] = useState<Guidance>('NO_FACE')
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [entries, setEntries] = useState<VerdictEntry[]>([])
  const [pinned, setPinned] = useState<string | null>(null)
  const [live, setLive] = useState<'connecting' | 'open' | 'error'>('connecting')

  // Refs read by the per-frame listener and async attempt code (no re-subscribe per render).
  const phaseRef = useRef<Phase>('idle')
  const busyRef = useRef(false)
  const abortRef = useRef<AbortController | null>(null)
  const pendingIds = useRef(new Set<string>())
  const beaconSent = useRef(new Set<string>())
  const entriesRef = useRef<VerdictEntry[]>([])
  const fillRef = useRef<HTMLDivElement>(null)
  const settings = useRef({ kioskId, flashOn, autoRearm, showKiosk, capturing, token })
  useEffect(() => {
    settings.current = { kioskId, flashOn, autoRearm, showKiosk, capturing, token }
  }, [kioskId, flashOn, autoRearm, showKiosk, capturing, token])
  useEffect(() => {
    entriesRef.current = entries
  }, [entries])

  const setPhase = useCallback((p: Phase) => {
    phaseRef.current = p
    setPhaseState(p)
  }, [])

  // Labels are only visible after permission: re-list once a stream is open.
  const refreshDevices = devices.refresh
  useEffect(() => {
    if (engine) void refreshDevices()
  }, [engine, refreshDevices])

  // ---------------------------------------------------------------- policy bars + users (role fallback)
  const modeRaw = usePoll(fetchModeWithBars, 5000, true, 'operator-mode-raw')
  const latestBars: PolicyBars = useMemo(() => (modeRaw.data ? barsFromMode(modeRaw.data) : null) ?? fallbackBars(), [modeRaw.data])
  const latestBarsRef = useRef(latestBars)
  useEffect(() => {
    latestBarsRef.current = latestBars
  }, [latestBars])
  /** Bars of the mode the decision was made in (offline bars are stricter), else the latest reported. */
  const barsFor = useCallback((mode: string) => barsByMode[mode] ?? latestBarsRef.current, [])

  const usersPoll = usePoll(() => getUsers(token), 30000, Boolean(token), `operator-users:${token}`)
  /** the only kiosk_id the edge serves in session/start (others are refused with 409) */
  const servedKiosk = useModeStatus().mode?.kiosk_id ?? null
  const users = usersPoll.data?.users ?? null

  // ---------------------------------------------------------------- verdict list
  const upsert = useCallback(
    (d: DecisionResponse, raw: Record<string, unknown> | null, patch: Partial<VerdictEntry>, source: VerdictEntry['source']) => {
      setEntries((list) => {
        const i = list.findIndex((e) => e.attemptId === d.attempt_id)
        if (i >= 0) {
          const old = list[i]
          const changed = old.decision.decision !== d.decision || old.decision.reason_codes.join() !== d.reason_codes.join()
          const next: VerdictEntry = {
            ...old,
            ...patch,
            decision: d,
            raw: raw ?? old.raw,
            history: changed ? [...old.history, d.decision] : old.history,
            source: old.source === 'console' ? 'console' : source,
          }
          return [next, ...list.slice(0, i), ...list.slice(i + 1)]
        }
        const entry: VerdictEntry = {
          attemptId: d.attempt_id,
          source,
          decision: d,
          history: [d.decision],
          raw,
          receivedAt: Date.now(),
          faceLockAtMs: null,
          clientMs: null,
          forced: false,
          flash: null,
          timing: null,
          bars: barsFor(d.mode),
          ...patch,
        }
        return [entry, ...list].slice(0, MAX_ENTRIES)
      })
    },
    [barsFor],
  )

  // Raw per-attempt signals (observer view). Needs the admin token; failures only annotate the entry.
  const signalsSeq = useRef(new Map<string, number>())
  const fetchSignals = useCallback(
    (attemptId: string) => {
      const tok = settings.current.token
      if (!tok || !attemptId) return
      const seq = (signalsSeq.current.get(attemptId) ?? 0) + 1
      signalsSeq.current.set(attemptId, seq)
      const apply = (patch: Partial<VerdictEntry>) => {
        if (signalsSeq.current.get(attemptId) !== seq) return // a newer fetch for this attempt is in flight
        setEntries((list) => list.map((e) => (e.attemptId === attemptId ? { ...e, ...patch } : e)))
      }
      api.getAttemptSignals(tok, attemptId).then(
        (body) => apply({ signals: body, signalsError: null }),
        (err: unknown) => apply({ signalsError: `signals: ${errorText(err)}` }),
      )
    },
    [api],
  )

  // Live feed: decisions from the kiosk tab (and our own, de-duplicated by attempt_id).
  useEffect(
    () =>
      subscribeLive(getAdminToken(), {
        onDecision: (d, raw) => {
          if (!d.attempt_id || pendingIds.current.has(d.attempt_id)) return
          const known = entriesRef.current.some((e) => e.attemptId === d.attempt_id)
          // In observer mode every decision is shown; while capturing here the kiosk feed is optional.
          if (!known && settings.current.capturing && !settings.current.showKiosk) return
          upsert(d, raw, {}, 'kiosk')
          fetchSignals(d.attempt_id)
        },
        onRendered: (raw) => {
          const id = typeof raw.attempt_id === 'string' ? raw.attempt_id : null
          const clientMs = typeof raw.client_latency_ms === 'number' ? raw.client_latency_ms : null
          if (!id || clientMs === null) return
          setEntries((list) => list.map((e) => (e.attemptId === id && e.clientMs === null ? { ...e, clientMs } : e)))
        },
        onStatus: setLive,
      }),
    [upsert, fetchSignals],
  )

  // ---------------------------------------------------------------- flash paint (direct DOM, same rAF as the timestamps)
  const paint = useCallback((color: string | null) => {
    const f = fillRef.current
    if (!f) return
    if (color) {
      f.style.backgroundColor = color
      f.style.opacity = '1'
    } else {
      f.style.opacity = '0'
    }
  }, [])

  // ---------------------------------------------------------------- attempt
  const engineRef = useRef(engine)
  useEffect(() => {
    engineRef.current = engine
  }, [engine])

  const start = useCallback(
    async (lockFrame: FrameAnalysis, forced: boolean) => {
      const e = engineRef.current
      if (!e || busyRef.current || !lock.isHeld()) return
      busyRef.current = true
      const abort = new AbortController()
      abortRef.current = abort
      setError(null)
      setPhase('capturing')
      const s = settings.current
      try {
        const res = await runOperatorAttempt({
          engine: e,
          lockFrame,
          kioskId: s.kioskId,
          flashEnabled: s.flashOn,
          forced,
          paint,
          signal: abort.signal,
          onStage: (stage) => setPhase(stage),
          onSession: (id) => pendingIds.current.add(id),
        })
        upsert(res.decision, res.raw, { faceLockAtMs: res.faceLockAtMs, forced: res.forced, flash: res.flash, timing: res.timing }, 'console')
        pendingIds.current.delete(res.decision.attempt_id)
        fetchSignals(res.decision.attempt_id)
        setPinned(null)
        setPhase('result')
      } catch (err) {
        if (abort.signal.aborted) {
          setPhase('idle')
        } else {
          console.error('[operator] attempt failed', err)
          setError(errorText(err))
          setPhase('error')
        }
      } finally {
        busyRef.current = false
        if (abortRef.current === abort) abortRef.current = null
      }
    },
    [paint, setPhase, upsert, fetchSignals, lock],
  )

  const arm = useCallback(() => {
    if (busyRef.current || !lock.isHeld()) return
    setError(null)
    setPhase('armed')
  }, [setPhase, lock])

  const cancel = useCallback(() => {
    abortRef.current?.abort()
    if (!busyRef.current) setPhase('idle')
  }, [setPhase])

  const forceScan = useCallback(() => {
    const f = engineRef.current?.latest
    if (f && !busyRef.current) void start(f, true)
  }, [start])

  // Per-frame: quality gate -> face lock (same rule as the kiosk: OK held for UI.lockStableMs) + auto re-arm.
  useEffect(() => {
    if (!engine) return
    let prev: FrameAnalysis | null = null
    let okSince: number | null = null
    let absentSince: number | null = null
    let lastG: Guidance | null = null
    let lastP = -1
    return engine.onFrame((f) => {
      const a = assessQuality(f, prev, UPLOAD_W)
      prev = f
      const ph = phaseRef.current
      if ((ph === 'result' || ph === 'error') && settings.current.autoRearm) {
        if (!f.face) {
          absentSince ??= f.perfMs
          if (f.perfMs - absentSince >= REARM_ABSENT_MS) {
            absentSince = null
            arm()
          }
        } else {
          absentSince = null
        }
      }
      let p = 0
      if (phaseRef.current === 'armed' && a.ok && !busyRef.current) {
        okSince ??= f.perfMs
        const held = f.perfMs - okSince
        p = Math.min(1, held / UI.lockStableMs)
        if (held >= UI.lockStableMs) {
          okSince = null
          p = 0
          void start(f, false)
        }
      } else {
        okSince = null
      }
      if (a.guidance !== lastG) {
        lastG = a.guidance
        setGuidance(a.guidance)
      }
      const q = Math.round(p * 10) / 10
      if (q !== lastP) {
        lastP = q
        setProgress(q)
      }
    })
  }, [engine, arm, start])

  // A camera switch mid-attempt cancels the attempt; so does losing the capture lock / turning capture off.
  useEffect(() => {
    if (!engine) abortRef.current?.abort()
  }, [engine])
  useEffect(() => {
    if (capturing) return
    abortRef.current?.abort()
    if (!busyRef.current && phaseRef.current !== 'idle') setPhase('idle')
  }, [capturing, setPhase])

  // Keyboard: Space = start / scan again · F = force scan · Esc = stop.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null
      if (t && (t.tagName === 'INPUT' || t.tagName === 'SELECT' || t.tagName === 'TEXTAREA')) return
      if (!settings.current.capturing) return // observer: no capture shortcuts
      if (e.code === 'Space') {
        e.preventDefault()
        arm()
      } else if (e.key === 'f' || e.key === 'F') forceScan()
      else if (e.key === 'Escape') cancel()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [arm, cancel, forceScan])

  // Rendered beacon (face lock -> verdict painted), once per console attempt, like the kiosk decision screen.
  const onPainted = useCallback(
    (attemptId: string, renderedAtMs: number) => {
      const e = entriesRef.current.find((x) => x.attemptId === attemptId)
      if (!e || e.faceLockAtMs === null || beaconSent.current.has(attemptId)) return
      beaconSent.current.add(attemptId)
      const faceLock = e.faceLockAtMs
      setEntries((list) => list.map((x) => (x.attemptId === attemptId ? { ...x, clientMs: renderedAtMs - faceLock } : x)))
      api
        .markRendered(attemptId, { face_lock_at_ms: faceLock, rendered_at_ms: renderedAtMs })
        .catch((err: unknown) => console.warn('[operator] POST rendered failed (non-blocking)', err))
    },
    [api],
  )

  const selected = (pinned ? entries.find((e) => e.attemptId === pinned) : null) ?? entries[0] ?? null
  const ring = phase === 'armed' ? (guidance === 'OK' ? '#34d399' : guidance === 'NO_FACE' ? 'rgba(255,255,255,0.6)' : '#f2a900') : 'rgba(255,255,255,0.35)'
  const busy = phase === 'capturing' || phase === 'deciding'

  return (
    <div className="min-h-full bg-kiosk font-sans text-white">
      <OpHeader title="Operator console" current="/operator" />
      <main className="grid gap-5 p-5 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <section className="flex flex-col gap-3" aria-label="Observer and capture controls">
          <div className={`rounded-xl p-3 ${captureOn ? 'bg-sky-900/40 ring-1 ring-sky-400/40' : 'bg-white/5'}`}>
            <div className="flex flex-wrap items-center gap-3">
              <div className="min-w-0 flex-1">
                <p className="text-base font-bold">
                  {!captureOn ? 'Observer mode' : capturing ? 'Capturing on this console' : 'Waiting for the camera lock…'}
                </p>
                <p className="text-sm text-white/70">
                  {!captureOn
                    ? `Showing every decision from the kiosk tab (live feed: ${live}). No camera is used here.`
                    : capturing
                      ? 'This tab holds the one-capturing-tab lock; the kiosk tab is paused until you stop.'
                      : `Only one tab captures at a time (no duplicate attempts). The camera lock is held by ${holderText(holder)}.`}
                </p>
              </div>
              <Btn big={!captureOn} tone={captureOn ? 'default' : 'primary'} onClick={() => setCaptureOn((v) => !v)}>
                {captureOn ? 'Stop capturing here' : 'Capture on this console'}
              </Btn>
              {captureOn && !capturing ? (
                <Btn tone="danger" onClick={() => lock.enable(true)} title="Take the camera lock from the other tab (it pauses until you stop)">
                  Take over
                </Btn>
              ) : null}
            </div>
          </div>
          {capturing ? (
            <>
              <CameraPicker
                devices={devices.devices}
                activeId={activeId}
                preferredId={preferred}
                state={eng}
                onSelect={(id) => {
                  writePreferredCamera(id)
                  setPreferred(id)
                }}
                onRefresh={() => void devices.refresh()}
                onRetry={() => setRetryKey((k) => k + 1)}
              />
              <Preview engine={engine} ring={ring} progress={progress} inset={phase === 'capturing'}>
                <p className="absolute inset-x-0 bottom-3 text-center text-[clamp(1rem,2.2vw,1.6rem)] font-bold text-shadow">
                  {phase === 'armed' ? GUIDANCE_TEXT[guidance] : PHASE_TEXT[phase]}
                </p>
              </Preview>
              <div className="flex flex-wrap items-center gap-2">
                {phase === 'armed' || busy ? (
                  <Btn big tone="default" onClick={cancel}>
                    {busy ? 'Cancel' : 'Stop scanning'} (Esc)
                  </Btn>
                ) : (
                  <Btn big tone="primary" onClick={arm} disabled={!engine}>
                    {entries.some((e) => e.source === 'console') ? 'Scan again' : 'Start scanning'} (Space)
                  </Btn>
                )}
                <Btn onClick={forceScan} disabled={!engine || busy} title="Send the current frame without waiting for a face lock (no latency beacon)">
                  Force scan (F)
                </Btn>
              </div>
            </>
          ) : null}
          {error ? <p className="rounded-lg bg-red-600/25 px-3 py-2 text-sm text-red-100">{error}</p> : null}
          <div className="grid gap-2 rounded-xl bg-white/5 p-3 text-sm sm:grid-cols-2">
            <label className="flex flex-col gap-1 sm:col-span-2">
              <span className="text-xs text-white/60">Admin token (raw signals per attempt + role lookup)</span>
              <input
                className={inputCls}
                type="password"
                autoComplete="off"
                value={token}
                placeholder="X-Admin-Token"
                onChange={(e) => {
                  setToken(e.target.value.trim())
                  setAdminToken(e.target.value.trim())
                }}
              />
            </label>
            {captureOn ? (
              <>
                <label className="flex flex-col gap-1 sm:col-span-2">
                  <span className="text-xs text-white/60">Kiosk id (sets the zone / schedule; the edge serves only {servedKiosk ?? 'its own kiosk'})</span>
                  <select className={inputCls} value={kioskId} onChange={(e) => setKioskId(e.target.value)}>
                    {[...new Set([...(servedKiosk ? [servedKiosk] : []), kioskId, ...KIOSK_IDS])].map((k) => (
                      <option key={k} value={k} disabled={servedKiosk !== null && k !== servedKiosk && k !== kioskId}>
                        {k}
                        {servedKiosk !== null && k !== servedKiosk ? ' (not served by this edge)' : ''}
                      </option>
                    ))}
                  </select>
                  {servedKiosk !== null && kioskId !== servedKiosk ? (
                    <span className="text-xs text-red-300">
                      {kioskId} is not served by this edge: attempts will be refused.{' '}
                      <button type="button" className="underline" onClick={() => setKioskId(servedKiosk)}>
                        Use {servedKiosk}
                      </button>
                    </span>
                  ) : null}
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={flashOn && THRESHOLDS.flash.enabled}
                    disabled={!THRESHOLDS.flash.enabled}
                    onChange={(e) => setFlashOn(e.target.checked)}
                  />
                  Colour flash (off = accessible path; the edge then requires a challenge)
                </label>
                <label className="flex items-center gap-2">
                  <input type="checkbox" checked={autoRearm} onChange={(e) => setAutoRearm(e.target.checked)} />
                  Auto re-arm when the face leaves
                </label>
                <label className="flex items-center gap-2 sm:col-span-2">
                  <input type="checkbox" checked={showKiosk} onChange={(e) => setShowKiosk(e.target.checked)} />
                  Also show kiosk-tab decisions (live feed: {live})
                </label>
              </>
            ) : null}
          </div>
          {capturing && engine ? (
            <p className="text-xs text-white/50">
              {engine.camera.label || '(no label)'} · {engine.video.videoWidth}×{engine.video.videoHeight} · {engine.delegate} · camera
              choice saved in this browser. The kiosk tab keeps its own camera.
            </p>
          ) : null}
        </section>

        <section className="flex min-w-0 flex-col gap-3" aria-label="Verdict">
          {selected ? (
            <VerdictPanel entry={selected} users={users} onPainted={onPainted} />
          ) : (
            <div className="grid min-h-64 place-items-center rounded-2xl bg-white/5 p-8 text-center text-lg text-white/60">
              No verdict yet. Use the kiosk tab: its decisions appear here live. (To scan from this console instead, press Capture on this
              console.)
            </div>
          )}
          {entries.length > 1 || pinned ? (
            <div className="rounded-2xl bg-white/5 p-3">
              <div className="mb-2 flex items-center gap-2">
                <h2 className="text-xs font-semibold tracking-wide text-white/60 uppercase">Recent verdicts</h2>
                {pinned ? (
                  <Btn tone="ghost" onClick={() => setPinned(null)}>
                    Follow latest
                  </Btn>
                ) : null}
              </div>
              <ul className="flex flex-col gap-1">
                {entries.map((e) => (
                  <li key={e.attemptId}>
                    <button
                      type="button"
                      onClick={() => setPinned(e.attemptId)}
                      className={`flex w-full flex-wrap items-center gap-2 rounded-lg px-2 py-1 text-left text-sm hover:bg-white/10 ${
                        selected?.attemptId === e.attemptId ? 'bg-white/10 ring-1 ring-white/30' : ''
                      }`}
                    >
                      <VerdictChip decision={e.decision.decision} />
                      <span className="tabular-nums">{Number.isFinite(e.decision.latency_ms.total) ? `${Math.round(e.decision.latency_ms.total)} ms` : '—'}</span>
                      <span className="font-semibold">{e.decision.candidate?.display ?? '—'}</span>
                      <span className="text-white/60">{e.decision.reason_codes.join(', ') || '—'}</span>
                      <span className="ml-auto text-xs text-white/45">
                        {e.source === 'console' ? 'console' : 'kiosk'} · {new Date(e.receivedAt).toLocaleTimeString([], { hour12: false })}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </section>
      </main>
      {/* Colour-flash light source: opaque full-viewport fill; the preview is lifted above it while capturing. */}
      <div ref={fillRef} className="flash-fill" aria-hidden />
    </div>
  )
}
