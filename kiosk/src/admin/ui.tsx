/** Small dashboard primitives (light theme for projector legibility). */
import { useState, type ReactNode } from 'react'
import { useAuth } from '../shared/auth/context'
import { authErrorText } from '../shared/auth/authErrorText'
import { needsText } from '../shared/auth/permissions'

export function Card({ title, actions, children, className = '' }: { title: string; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-xl border border-black/10 bg-[#fcfcfb] p-4 shadow-sm ${className}`}>
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 className="text-sm font-bold tracking-wide text-[#52514e] uppercase">{title}</h2>
        {actions}
      </div>
      {children}
    </section>
  )
}

export function KeyVal({ k, v, mono = false }: { k: string; v: ReactNode; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-3 border-b border-[#e1e0d9] py-1 text-sm last:border-0">
      <span className="text-[#52514e]">{k}</span>
      <span className={`text-right text-[#0b0b0b] ${mono ? 'font-mono text-xs' : 'font-medium'}`}>{v}</span>
    </div>
  )
}

type Tone = 'default' | 'primary' | 'danger'

const TONES: Record<Tone, string> = {
  default: 'bg-white text-[#0b0b0b] ring-1 ring-black/15 hover:bg-[#f0efec]',
  primary: 'bg-[#2a78d6] text-white hover:bg-[#256abf]',
  danger: 'bg-[#d03b3b] text-white hover:bg-[#b83232]',
}

/**
 * Button that runs an async action, shows busy state and the last result/error inline. `perm`: the edge
 * permission the action needs; without it the button is disabled with "Needs <perm>" (the edge enforces it too).
 */
export function ActionButton({
  label,
  run,
  tone = 'default',
  disabled = false,
  perm,
}: {
  label: string
  run: () => Promise<unknown>
  tone?: Tone
  disabled?: boolean
  perm?: string
}) {
  const { can } = useAuth()
  const allowed = !perm || can(perm)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  return (
    <span className="inline-flex flex-col items-start gap-1">
      <button
        type="button"
        disabled={busy || disabled || !allowed}
        title={allowed ? undefined : needsText(perm ?? '')}
        onClick={async () => {
          setBusy(true)
          setMsg(null)
          try {
            const r = await run()
            setMsg({ ok: true, text: summarise(r) })
          } catch (e) {
            setMsg({ ok: false, text: authErrorText(e) })
          } finally {
            setBusy(false)
          }
        }}
        className={`rounded-lg px-3 py-1.5 text-sm font-semibold disabled:opacity-50 ${TONES[tone]}`}
      >
        {busy ? '…' : label}
      </button>
      {!allowed ? <span className="text-xs text-[#8a6d00]">{needsText(perm ?? '')}</span> : null}
      {msg ? (
        <span className={`max-w-[22rem] truncate text-xs ${msg.ok ? 'text-[#006300]' : 'text-[#d03b3b]'}`} title={msg.text}>
          {msg.ok ? 'OK' : 'Error'}
          {msg.text ? `: ${msg.text}` : ''}
        </span>
      ) : null}
    </span>
  )
}

function summarise(r: unknown): string {
  if (r === undefined || r === null || r === '') return ''
  try {
    const s = JSON.stringify(r)
    return s.length > 160 ? s.slice(0, 157) + '…' : s
  } catch {
    return String(r)
  }
}

/** Card body shown instead of a panel the principal may not use. */
export function NeedsCard({ title, perm, children }: { title: string; perm: string; children?: ReactNode }) {
  return (
    <Card title={title}>
      <p className="text-sm text-[#8a6d00]">{needsText(perm)}</p>
      {children}
    </Card>
  )
}
