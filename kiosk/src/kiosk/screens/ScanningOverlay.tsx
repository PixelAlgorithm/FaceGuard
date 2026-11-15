import { useEffect, useState } from 'react'
import { THRESHOLDS } from '../../config'
import { GUIDANCE_TEXT, type Guidance } from '../../capture/quality'
import { Spinner } from '../components/Icons'
import { CAPTURE_PAUSED_NOTE } from '../controller'

function useCountdown(until: number | null): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (until === null) return
    const id = window.setInterval(() => setNow(Date.now()), 250)
    return () => window.clearInterval(id)
  }, [until])
  return until === null ? 0 : Math.max(0, Math.ceil((until - now) / 1000))
}

export function ScanningOverlay({
  guidance,
  note,
  rateLimitedUntil,
  flashEnabled,
  onToggleFlash,
  fullscreen,
}: {
  guidance: Guidance
  note: string | null
  rateLimitedUntil: number | null
  flashEnabled: boolean
  onToggleFlash: () => void
  fullscreen: boolean
}) {
  const wait = useCountdown(rateLimitedUntil)
  // Another tab (/operator) holds the one-capturing-tab lock: no face lock here until it is released.
  const paused = note === CAPTURE_PAUSED_NOTE
  const text = paused ? 'Paused' : wait > 0 ? `Too many attempts – please wait ${wait} s` : GUIDANCE_TEXT[guidance]
  const ok = guidance === 'OK' && wait === 0 && !paused
  return (
    <>
      <div className="pointer-events-none absolute inset-x-0 top-[79vh] z-30 flex flex-col items-center gap-3 px-6 text-center">
        <p
          aria-live="assertive"
          className={`text-shadow text-[clamp(30px,6.2vh,76px)] leading-tight font-extrabold ${ok ? 'text-emerald-300' : 'text-white'}`}
        >
          {text}
        </p>
        {note ? (
          <p
            className={
              paused
                ? 'rounded-xl bg-black/80 px-5 py-2 text-[clamp(15px,2.3vh,26px)] font-semibold text-amber-200'
                : 'text-shadow text-[clamp(16px,2.6vh,30px)] text-amber-200'
            }
          >
            {note}
          </p>
        ) : null}
      </div>
      <div className="absolute inset-x-0 bottom-0 z-30 flex items-end justify-between gap-4 p-[2.2vh]">
        <div className="flex max-w-[60vw] flex-col items-start gap-1.5">
          <p className="rounded-xl bg-black/70 px-4 py-2 text-[clamp(13px,1.9vh,22px)] text-white/85">
            {flashEnabled && THRESHOLDS.flash.enabled
              ? 'The screen will briefly change colour (about 1 second) during the check.'
              : 'No-flash check selected: the screen will not change colour.'}
          </p>
          <p className="rounded-lg bg-black/60 px-3 py-1 text-[clamp(11px,1.5vh,16px)] text-amber-200/90">
            {/* KA-01 / KF-04: no link or shortcut to a privileged console on the public route */}
            Operator: screen brightness to maximum{fullscreen ? '' : ' · tap the screen once for fullscreen'}
          </p>
        </div>
        <button
          type="button"
          onClick={onToggleFlash}
          aria-pressed={!flashEnabled}
          className={`min-h-14 rounded-xl px-5 py-3 text-[clamp(14px,2vh,22px)] font-semibold ring-2 transition-colors ${
            flashEnabled ? 'bg-black/70 text-white ring-white/40 hover:bg-black/85' : 'bg-sky-600 text-white ring-sky-300'
          }`}
        >
          {flashEnabled ? 'Light-sensitive? Use no-flash check' : 'No-flash check: ON'}
        </button>
      </div>
    </>
  )
}

export function CapturingOverlay() {
  // No background box: every lit pixel helps the reflection signal.
  return (
    <div className="pointer-events-none absolute inset-x-0 top-[44vh] z-[46] flex flex-col items-center px-6 text-center">
      <p className="text-shadow text-[clamp(34px,7vh,84px)] leading-none font-black text-white">Hold still – light check</p>
    </div>
  )
}

export function DecidingOverlay() {
  return (
    <div className="pointer-events-none absolute inset-x-0 top-[79vh] z-30 flex items-center justify-center gap-4 px-6">
      <Spinner className="h-[5vh] w-[5vh] text-white" />
      <p className="text-shadow text-[clamp(28px,5.5vh,64px)] font-bold">Checking…</p>
    </div>
  )
}
