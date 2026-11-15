/** Small pieces shared by the Staff & roles and API key panels. */
import { useEffect, useRef, useState } from 'react'
import type { RoleInfo } from '../api/authTypes'
import { SECRET_VISIBLE_MS } from './staffUtil'

/** Role checkboxes (max `max`); `allowed` filters the catalog (e.g. key_allowed for API keys). */
export function RolePicker({
  roles,
  value,
  onChange,
  max,
  disabled = false,
  idPrefix,
}: {
  roles: readonly RoleInfo[]
  value: readonly string[]
  onChange: (next: string[]) => void
  max: number
  disabled?: boolean
  idPrefix: string
}) {
  return (
    <fieldset className="flex flex-wrap gap-2" disabled={disabled}>
      <legend className="mb-1 text-xs text-[#52514e]">Roles (1–{max})</legend>
      {roles.map((r) => {
        const on = value.includes(r.name)
        const full = !on && value.length >= max
        return (
          <label
            key={r.name}
            htmlFor={`${idPrefix}-${r.name}`}
            title={r.description}
            className={`flex items-center gap-1.5 rounded-lg px-2 py-1 text-xs ring-1 ${on ? 'bg-[#cde2fb] ring-[#2a78d6]' : 'bg-white ring-black/15'} ${full ? 'opacity-50' : ''}`}
          >
            <input
              id={`${idPrefix}-${r.name}`}
              type="checkbox"
              checked={on}
              disabled={full}
              onChange={() => onChange(on ? value.filter((x) => x !== r.name) : [...value, r.name])}
            />
            {r.name}
          </label>
        )
      })}
    </fieldset>
  )
}

/** A secret shown once: masked until revealed, auto-hidden after SECRET_VISIBLE_MS. */
export function ShownOnce({ label, secret, note, onHide }: { label: string; secret: string; note: string; onHide: () => void }) {
  const [revealed, setRevealed] = useState(false)
  const hideRef = useRef(onHide)
  useEffect(() => {
    hideRef.current = onHide
  })
  // one timer per secret (a parent re-render must not restart it)
  useEffect(() => {
    const t = window.setTimeout(() => hideRef.current(), SECRET_VISIBLE_MS)
    return () => window.clearTimeout(t)
  }, [secret])
  return (
    <div className="mt-3 rounded-xl border-2 border-[#d03b3b] bg-[#fff8f0] p-3" role="alert">
      <p className="text-sm font-bold text-[#8f1d1d]">{label}: shown once, hidden automatically after 2 minutes.</p>
      <p className="mt-1 text-xs text-[#5c4300]">{note}</p>
      <code className="mt-2 block rounded bg-white p-2 font-mono text-sm break-all ring-1 ring-black/15 select-all">{revealed ? secret : '•'.repeat(Math.min(secret.length, 32))}</code>
      <div className="mt-2 flex gap-2">
        <button type="button" className="rounded-lg px-3 py-1 text-sm ring-1 ring-black/15" onClick={() => setRevealed((v) => !v)}>
          {revealed ? 'Mask' : 'Reveal'}
        </button>
        <button type="button" className="rounded-lg bg-[#0b0b0b] px-3 py-1 text-sm font-semibold text-white" onClick={onHide}>
          I stored it: hide
        </button>
      </div>
    </div>
  )
}
