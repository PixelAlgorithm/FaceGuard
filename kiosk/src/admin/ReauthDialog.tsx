/**
 * Password prompt used by useReauth (confirm_password for staff:manage mutations). Modal: focus moves into
 * the field on open, Tab stays inside the dialog, Esc cancels, and focus returns to the control that opened it.
 */
import { useEffect, useId, useRef, useState, type FormEvent, type KeyboardEvent } from 'react'

const FOCUSABLE = 'input, button:not([disabled])'

export function ReauthDialog({ action, onDone }: { action: string; onDone: (password: string | null) => void }) {
  const [password, setPassword] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)
  const formRef = useRef<HTMLFormElement>(null)
  const doneRef = useRef(onDone)
  const titleId = useId()
  const descId = useId()
  useEffect(() => {
    doneRef.current = onDone
  })
  // once per dialog: focus the field, Esc cancels, restore focus on close (a parent re-render must not steal it)
  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null
    inputRef.current?.focus()
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key !== 'Escape') return
      e.preventDefault()
      doneRef.current(null)
    }
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('keydown', onKey)
      if (opener?.isConnected) opener.focus()
    }
  }, [])
  const trapTab = (e: KeyboardEvent<HTMLFormElement>) => {
    if (e.key !== 'Tab' || !formRef.current) return
    const items = [...formRef.current.querySelectorAll<HTMLElement>(FOCUSABLE)]
    const first = items[0]
    const last = items[items.length - 1]
    if (!first || !last) return
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault()
      last.focus()
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault()
      first.focus()
    }
  }
  const submit = (e: FormEvent) => {
    e.preventDefault()
    const pw = password
    setPassword('')
    if (pw) onDone(pw)
  }
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true" aria-labelledby={titleId} aria-describedby={descId}>
      <form ref={formRef} onSubmit={submit} onKeyDown={trapTab} className="w-full max-w-sm rounded-xl bg-white p-5 shadow-2xl">
        <h2 id={titleId} className="text-base font-bold">
          Confirm with your password
        </h2>
        <p id={descId} className="mt-1 text-sm text-[#52514e]">
          {action}
        </p>
        <input
          ref={inputRef}
          type="password"
          autoComplete="current-password"
          className="mt-3 w-full rounded-lg border border-black/20 px-3 py-2 text-base"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          aria-label="Your password"
        />
        <div className="mt-4 flex justify-end gap-2">
          <button type="button" className="rounded-lg px-3 py-1.5 text-sm ring-1 ring-black/15" onClick={() => onDone(null)}>
            Cancel
          </button>
          <button type="submit" disabled={!password} className="rounded-lg bg-[#2a78d6] px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-50">
            Confirm
          </button>
        </div>
      </form>
    </div>
  )
}
