/**
 * Self-service password change for a signed-in staff member (POST /v1/auth/password). An admin cannot reset
 * their own password through Staff & roles (403 SELF_MODIFICATION), so this is the only path. The edge revokes
 * the member's other sessions; this session continues. Passwords live only in this dialog and are cleared.
 */
import { useEffect, useRef, useState, type FormEvent } from 'react'
import { getApi } from '../../api'
import { authErrorText } from './authErrorText'
import { useAuth } from './context'
import { GIVEN_PASSWORD_MAX, newPasswordProblems } from './passwordPolicy'

const field = 'w-full rounded-lg border border-black/20 px-3 py-2 text-base text-black'

export function OwnPasswordDialog({ onClose }: { onClose: (changed: boolean) => void }) {
  const api = getApi()
  const { token, principal, refresh } = useAuth()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [again, setAgain] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const firstRef = useRef<HTMLInputElement>(null)
  const closeRef = useRef(onClose)
  useEffect(() => {
    closeRef.current = onClose
  })
  useEffect(() => {
    firstRef.current?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeRef.current(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])
  const problems = newPasswordProblems(next, { username: principal?.username ?? '', current, again })
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (busy || !current || !next || next !== again || problems.length) return
    setBusy(true)
    setError(null)
    try {
      await api.changePassword(token, { current_password: current, new_password: next })
      setNext('')
      setAgain('')
      await refresh()
      onClose(true)
    } catch (err) {
      setError(authErrorText(err))
    } finally {
      setCurrent('')
      setBusy(false)
    }
  }
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true" aria-labelledby="own-pw-title">
      <form onSubmit={submit} className="w-full max-w-sm rounded-xl bg-white p-5 text-[#0b0b0b] shadow-2xl">
        <h2 id="own-pw-title" className="text-base font-bold">
          Change my password
        </h2>
        <p className="mt-1 text-xs text-[#52514e]">Your other sessions are signed out; this one continues.</p>
        <label className="mt-3 flex flex-col gap-1 text-sm">
          Current password
          <input ref={firstRef} className={field} type="password" autoComplete="current-password" maxLength={GIVEN_PASSWORD_MAX} value={current} onChange={(e) => setCurrent(e.target.value)} />
        </label>
        <label className="mt-2 flex flex-col gap-1 text-sm">
          New password
          <input className={field} type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
        </label>
        <label className="mt-2 flex flex-col gap-1 text-sm">
          New password again
          <input className={field} type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} />
        </label>
        {next && problems.length ? <p className="mt-2 text-xs text-[#8a6d00]">{problems.join('; ')}</p> : null}
        {error ? (
          <p role="alert" className="mt-2 text-sm text-[#d03b3b]">
            {error}
          </p>
        ) : null}
        <div className="mt-4 flex justify-end gap-2">
          <button type="button" className="rounded-lg px-3 py-1.5 text-sm ring-1 ring-black/15" onClick={() => onClose(false)}>
            Cancel
          </button>
          <button type="submit" disabled={busy || !current || !next || next !== again || problems.length > 0} className="rounded-lg bg-[#2a78d6] px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-50">
            {busy ? 'Saving…' : 'Change password'}
          </button>
        </div>
      </form>
    </div>
  )
}
