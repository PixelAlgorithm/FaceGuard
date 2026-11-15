/** Kiosk route: camera + face oval + one instruction at a time + full-screen decisions. */
import { useEffect, useSyncExternalStore } from 'react'
import { MOCK_SCENARIOS } from '../api/mockScenarios'
import { DEBUG_ENABLED, MOCK_ENABLED, STORAGE_KEYS, THRESHOLDS } from '../config'
import { selectMockScenario } from '../shared/mockScenarioStore'
import { CameraStage, type OvalTone } from './components/CameraStage'
import { DebugOverlay } from './components/DebugOverlay'
import { MockPanel } from './components/MockPanel'
import { TopBar } from './components/TopBar'
import { CAPTURE_PAUSED_NOTE, getKioskController } from './controller'
import { ChallengeOverlay } from './screens/ChallengeOverlay'
import { DecisionScreen } from './screens/DecisionScreen'
import { FallbackScreen } from './screens/FallbackScreen'
import { CapturingOverlay, DecidingOverlay, ScanningOverlay } from './screens/ScanningOverlay'
import { BootScreen, FatalScreen, ServiceErrorScreen } from './screens/SystemScreen'

function subscribeFullscreen(cb: () => void) {
  document.addEventListener('fullscreenchange', cb)
  return () => document.removeEventListener('fullscreenchange', cb)
}
const isFullscreen = () => document.fullscreenElement !== null

export function KioskApp() {
  const ctrl = getKioskController()
  const snap = useSyncExternalStore(ctrl.subscribe, ctrl.getSnapshot)
  const view = snap.view
  const fullscreen = useSyncExternalStore(subscribeFullscreen, isFullscreen)

  // Fullscreen on the first user tap (browsers require a gesture): no browser chrome cutting the lit area.
  useEffect(() => {
    const onDown = () => {
      if (!document.fullscreenElement) void document.documentElement.requestFullscreen?.().catch(() => undefined)
    }
    window.addEventListener('pointerdown', onDown)
    return () => window.removeEventListener('pointerdown', onDown)
  }, [])

  useEffect(() => {
    void ctrl.boot()
  }, [ctrl])

  // Keep the screen awake on the kiosk (best effort).
  useEffect(() => {
    let lock: WakeLockSentinel | null = null
    const acquire = async () => {
      try {
        if (document.visibilityState === 'visible' && 'wakeLock' in navigator) lock = await navigator.wakeLock.request('screen')
      } catch {
        lock = null
      }
    }
    void acquire()
    document.addEventListener('visibilitychange', acquire)
    return () => {
      document.removeEventListener('visibilitychange', acquire)
      void lock?.release().catch(() => undefined)
    }
  }, [])

  // Operator shortcuts: Esc = reset, F = fullscreen, A = control panel (new tab), T = take the capture lock back from /operator,
  // 1-9/0 = mock scenario.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null
      if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA')) return
      if (e.key === 'Escape') ctrl.reset()
      else if (e.key === 't' || e.key === 'T') ctrl.takeOverCapture()
      else if (e.key === 'a' || e.key === 'A') window.open(`/admin${window.location.search}`, '_blank', 'noopener')
      else if (e.key === 'f' || e.key === 'F') {
        if (document.fullscreenElement) void document.exitFullscreen()
        else void document.documentElement.requestFullscreen().catch(() => undefined)
      } else if (MOCK_ENABLED && /^[0-9]$/.test(e.key)) {
        const idx = e.key === '0' ? 9 : Number(e.key) - 1
        const s = MOCK_SCENARIOS[idx]
        if (s) selectMockScenario(s.id)
      }
    }
    // Kiosk id may be changed from /admin in another tab.
    const onStorage = (e: StorageEvent) => {
      if (e.key === STORAGE_KEYS.kioskId) ctrl.refreshKioskId()
    }
    const onKioskId = () => ctrl.refreshKioskId()
    window.addEventListener('keydown', onKey)
    window.addEventListener('storage', onStorage)
    window.addEventListener('hid-kiosk-id', onKioskId)
    return () => {
      window.removeEventListener('keydown', onKey)
      window.removeEventListener('storage', onStorage)
      window.removeEventListener('hid-kiosk-id', onKioskId)
    }
  }, [ctrl])

  const tone: OvalTone =
    view.kind === 'scanning'
      ? view.note === CAPTURE_PAUSED_NOTE
        ? 'idle'
        : view.guidance === 'OK'
        ? 'ok'
        : view.guidance === 'NO_FACE'
          ? 'idle'
          : 'guide'
      : view.kind === 'challenge'
        ? 'challenge'
        : 'busy'
  // The preview is hidden under the opaque flash fill while capturing.
  const ovalVisible = ['scanning', 'deciding', 'challenge'].includes(view.kind)

  return (
    <main className="fixed inset-0 select-none overflow-hidden bg-kiosk font-sans text-white">
      <CameraStage
        engine={snap.engineReady ? ctrl.getEngine() : null}
        controller={ctrl}
        tone={tone}
        progress={view.kind === 'scanning' ? view.lockProgress : 0}
        visible={ovalVisible}
        inset={view.kind === 'capturing'}
      />
      <TopBar kioskId={snap.kioskId} zone={snap.lastZone} />

      {view.kind === 'scanning' ? (
        <ScanningOverlay
          guidance={view.guidance}
          note={view.note}
          rateLimitedUntil={view.rateLimitedUntil}
          flashEnabled={snap.flashEnabled}
          onToggleFlash={ctrl.toggleFlash}
          fullscreen={fullscreen}
        />
      ) : null}
      {view.kind === 'capturing' ? <CapturingOverlay /> : null}
      {view.kind === 'deciding' ? <DecidingOverlay /> : null}
      {view.kind === 'challenge' ? <ChallengeOverlay vm={view.vm} onPrompted={ctrl.markPrompted} /> : null}
      {view.kind === 'decision' ? (
        <DecisionScreen vm={view.vm} onContinue={ctrl.continueNow} onRendered={ctrl.onDecisionRendered} />
      ) : null}
      {view.kind === 'fallback' ? (
        <FallbackScreen
          vm={view.vm}
          onSelect={ctrl.selectMethod}
          onSubmit={(req) => void ctrl.submitFallback(req)}
          onRequestOtp={() => void ctrl.requestOtp()}
          onCancel={ctrl.reset}
          onActivity={ctrl.touch}
        />
      ) : null}
      {view.kind === 'boot' ? <BootScreen stage={view.stage} /> : null}
      {view.kind === 'fatal' ? <FatalScreen title={view.title} message={view.message} hint={view.hint} /> : null}
      {view.kind === 'service-error' ? (
        <ServiceErrorScreen title={view.title} message={view.message} retryAt={view.retryAt} />
      ) : null}

      {THRESHOLDS.ui.showDetailedReasons && snap.camera && view.kind === 'scanning' ? (
        <p className="absolute right-[2.2vh] bottom-[10vh] z-30 rounded bg-black/70 px-2 py-1 text-xs text-white/70">
          camera: {snap.camera.label || '(no label)'} · {snap.camera.deviceCount} device(s) · {snap.camera.delegate} ·
          controls: {snap.camera.controls}
          {snap.camera.virtualMatch ? ` · virtual-camera pattern "${snap.camera.virtualMatch}"` : ''}
        </p>
      ) : null}
      {MOCK_ENABLED && (view.kind === 'scanning' || view.kind === 'boot') ? <MockPanel /> : null}
      {DEBUG_ENABLED && view.kind !== 'capturing' ? (
        <DebugOverlay engine={snap.engineReady ? ctrl.getEngine() : null} controller={ctrl} />
      ) : null}
    </main>
  )
}
