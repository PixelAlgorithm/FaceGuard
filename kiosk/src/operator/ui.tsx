/** Shared pieces for /operator and /register (dark kiosk theme, large type for a projector). */
import { useEffect, useRef, type ReactNode } from 'react'
import type { VisionEngine } from '../capture/engine'
import { MOCK_ENABLED } from '../config'
import { ModeBadge } from '../shared/ModeBadge'
import { KIND_TAG, type VideoDevice } from './devices'
import type { OperatorEngineState } from './opEngine'

const NAV: Array<{ href: string; label: string }> = [
  { href: '/', label: 'Kiosk' },
  { href: '/operator', label: 'Operator' },
  { href: '/register', label: 'Register' },
  { href: '/admin', label: 'Control panel' },
]

/** Keeps ?mock=1 etc. when moving between routes. */
const withQuery = (href: string) => `${href}${window.location.search}`

export function OpHeader({ title, current }: { title: string; current: string }) {
  return (
    <header className="flex flex-wrap items-center gap-3 border-b border-white/10 bg-black/60 px-5 py-3">
      <span className="text-lg font-bold tracking-wide">HID kiosk</span>
      <span className="text-lg text-white/60">· {title}</span>
      <ModeBadge size="sm" showBundle />
      <nav className="ml-auto flex flex-wrap gap-1" aria-label="Kiosk pages">
        {NAV.map((n) => (
          <a
            key={n.href}
            href={withQuery(n.href)}
            aria-current={n.href === current ? 'page' : undefined}
            className={`rounded-lg px-3 py-1.5 text-sm font-semibold ${
              n.href === current ? 'bg-white text-black' : 'text-white/80 ring-1 ring-white/20 hover:bg-white/10'
            }`}
          >
            {n.label}
          </a>
        ))}
      </nav>
      {MOCK_ENABLED ? <span className="w-full text-xs text-fuchsia-300">Mock edge (?mock=1): decisions are simulated in the browser.</span> : null}
    </header>
  )
}

type BtnTone = 'primary' | 'default' | 'danger' | 'ghost'
const BTN: Record<BtnTone, string> = {
  primary: 'bg-[#2a78d6] text-white hover:bg-[#256abf]',
  default: 'bg-white/10 text-white ring-1 ring-white/25 hover:bg-white/20',
  danger: 'bg-[#b71c1c] text-white hover:bg-[#9c1717]',
  ghost: 'text-white/80 hover:bg-white/10',
}

export function Btn({
  children,
  onClick,
  tone = 'default',
  disabled = false,
  big = false,
  title,
}: {
  children: ReactNode
  onClick: () => void
  tone?: BtnTone
  disabled?: boolean
  big?: boolean
  title?: string
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={`rounded-xl font-semibold disabled:cursor-not-allowed disabled:opacity-40 ${big ? 'px-6 py-3 text-lg' : 'px-3 py-1.5 text-sm'} ${BTN[tone]}`}
    >
      {children}
    </button>
  )
}

export const inputCls =
  'w-full rounded-lg border border-white/20 bg-black/40 px-3 py-2 text-base text-white placeholder:text-white/40 focus:border-[#60a5fa] focus:outline-none'

/** Camera dropdown: every videoinput (iPhone Continuity Camera included), Refresh, current camera status. */
export function CameraPicker({
  devices,
  activeId,
  preferredId,
  onSelect,
  onRefresh,
  state,
  onRetry,
}: {
  devices: VideoDevice[]
  activeId: string | null
  preferredId: string | null
  onSelect: (deviceId: string | null) => void
  onRefresh: () => void
  state: OperatorEngineState
  onRetry: () => void
}) {
  const value = activeId ?? preferredId ?? ''
  const hasIphone = devices.some((d) => d.kind === 'iphone')
  const active = devices.find((d) => d.deviceId === activeId) ?? null
  return (
    <div className="flex flex-col gap-1.5">
      <label className="text-xs font-semibold tracking-wide text-white/60 uppercase" htmlFor="op-camera">
        Camera
      </label>
      <div className="flex gap-2">
        <select
          id="op-camera"
          className={`${inputCls} min-w-0 flex-1`}
          value={devices.some((d) => d.deviceId === value) ? value : ''}
          onChange={(e) => onSelect(e.target.value || null)}
        >
          <option value="">Browser default camera</option>
          {devices.map((d) => (
            <option key={d.deviceId} value={d.deviceId}>
              {d.label} · {KIND_TAG[d.kind]}
            </option>
          ))}
        </select>
        <Btn onClick={onRefresh} title="Re-list cameras (e.g. after the iPhone connects)">
          Refresh
        </Btn>
      </div>
      <p className="text-xs text-white/60">
        {state.status === 'opening' ? 'Opening camera…' : null}
        {state.status === 'ready' && active ? `Using: ${active.label}` : null}
        {state.status === 'ready' && !active ? 'Using the browser default camera' : null}
        {state.status === 'off' ? 'Camera off' : null}
        {devices.length ? ` · ${devices.length} camera${devices.length === 1 ? '' : 's'} found` : ''}
        {!hasIphone ? ' · iPhone not listed: unlock it near the Mac (same Apple ID, Wi-Fi + Bluetooth on), then Refresh' : ''}
      </p>
      {state.usedFallback ? (
        <p className="rounded-lg bg-amber-500/20 px-2 py-1 text-xs text-amber-200">
          The saved camera is not available right now, so the default camera was opened. Pick another camera or Refresh.
        </p>
      ) : null}
      {active?.virtualMatch ? (
        <p className="rounded-lg bg-red-600/30 px-2 py-1 text-xs text-red-100">
          “{active.label}” matches the virtual-camera pattern “{active.virtualMatch}”: the edge will DENY (INJECTION_VIRTUAL_CAMERA).
        </p>
      ) : null}
      {state.status === 'error' && state.error ? (
        <div className="rounded-lg bg-red-600/25 px-3 py-2 text-sm text-red-100">
          <b>{state.error.title}.</b> {state.error.hint}{' '}
          <button type="button" className="ml-1 underline" onClick={onRetry}>
            Retry
          </button>
        </div>
      ) : null}
    </div>
  )
}

/** Mirrored live preview with a face oval. `inset` lifts it above the flash fill (keeps the video composited). */
export function Preview({
  engine,
  ring,
  progress,
  inset,
  children,
}: {
  engine: VisionEngine | null
  ring: string
  progress: number
  inset: boolean
  children?: ReactNode
}) {
  const holder = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const el = holder.current
    if (!el || !engine) return
    return engine.attachPreview(el)
  }, [engine])
  return (
    <div className="relative aspect-video w-full overflow-hidden rounded-2xl bg-black ring-1 ring-white/15">
      <div
        ref={holder}
        className={
          inset
            ? 'fixed top-[3vh] left-1/2 z-[47] h-[18vh] w-[32vh] -translate-x-1/2 overflow-hidden rounded-2xl ring-4 ring-white/80'
            : 'absolute inset-0'
        }
      />
      {!inset ? (
        <svg className="pointer-events-none absolute inset-0 h-full w-full" viewBox="0 0 160 90" preserveAspectRatio="xMidYMid meet" aria-hidden>
          <ellipse cx="80" cy="44" rx="25" ry="34" fill="none" stroke={ring} strokeWidth="1.4" />
          {progress > 0 ? (
            <ellipse
              cx="80"
              cy="44"
              rx="25"
              ry="34"
              fill="none"
              stroke="#34d399"
              strokeWidth="2.6"
              pathLength={100}
              strokeDasharray="100"
              strokeDashoffset={100 - progress * 100}
              transform="rotate(-90 80 44)"
            />
          ) : null}
        </svg>
      ) : null}
      {engine ? null : <div className="absolute inset-0 grid place-items-center text-white/50">No camera</div>}
      {children}
    </div>
  )
}
