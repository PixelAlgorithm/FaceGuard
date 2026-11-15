/**
 * Re-authentication prompt for staff:manage mutations and API key creation (design v2 §C: every such call
 * carries `confirm_password`; a wrong one is 403 REAUTH_REQUIRED, which never signs the user out).
 * `ask(action)` resolves with the typed password, or null when cancelled. The password lives only in this
 * dialog's state and is handed to the caller once. A prompt that is replaced by a newer ask(), or whose owner
 * unmounts, resolves with null (an awaiting caller never hangs).
 */
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { ReauthDialog } from './ReauthDialog'

interface Pending {
  id: number
  action: string
  resolve: (password: string | null) => void
}

export function useReauth(): { ask: (action: string) => Promise<string | null>; dialog: ReactNode } {
  const [pending, setPending] = useState<Pending | null>(null)
  const current = useRef<Pending | null>(null)
  const nextId = useRef(0)

  const settle = useCallback((p: Pending, password: string | null) => {
    if (current.current?.id !== p.id) return
    current.current = null
    setPending(null)
    p.resolve(password)
  }, [])

  const ask = useCallback(
    (action: string) =>
      new Promise<string | null>((resolve) => {
        const prev = current.current
        if (prev) settle(prev, null)
        nextId.current += 1
        const p: Pending = { id: nextId.current, action, resolve }
        current.current = p
        setPending(p)
      }),
    [settle],
  )

  useEffect(
    () => () => {
      const p = current.current
      current.current = null
      p?.resolve(null)
    },
    [],
  )

  const dialog = pending ? <ReauthDialog key={pending.id} action={pending.action} onDone={(pw) => settle(pending, pw)} /> : null
  return { ask, dialog }
}
