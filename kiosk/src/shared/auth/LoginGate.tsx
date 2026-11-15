/**
 * Gates for privileged UI (design v2 §F).
 * - <LoginGate requires={[...]} title> renders children only for a signed-in principal holding AT LEAST ONE
 *   of `requires` (empty = any signed-in principal); otherwise the login / pending / not-allowed screen.
 * - <RequirePermission perm> renders children, or a "Needs <permission>" hint.
 * - <SignedInBadge> header widget: display name, roles, Sign out.
 * The edge enforces every permission; these only keep the UI honest.
 */
import { useState, type ReactNode } from 'react'
import { toast } from '../toast'
import { OwnPasswordDialog } from './OwnPasswordDialog'
import { useAuth } from './context'
import { LoginScreen } from './LoginScreen'
import { needsText } from './permissions'

function Centered({ children }: { children: ReactNode }) {
  return (
    <main className="flex min-h-full items-center justify-center bg-[#0b0f14] px-4 py-10 font-sans text-white">
      <section className="w-full max-w-md rounded-2xl border border-white/10 bg-[#121821] p-6 text-center shadow-2xl">{children}</section>
    </main>
  )
}

export function LoginGate({ requires = [], title, children }: { requires?: readonly string[]; title: string; children: ReactNode }) {
  const auth = useAuth()
  if (auth.status === 'loading') {
    return (
      <Centered>
        <p className="text-lg" role="status">
          Checking your sign-in…
        </p>
      </Centered>
    )
  }
  if (auth.status === 'error') {
    return (
      <Centered>
        <h1 className="text-xl font-bold">Cannot check your sign-in</h1>
        <p className="mt-2 text-sm text-white/70">{auth.error}</p>
        <div className="mt-4 flex justify-center gap-3">
          <button type="button" className="rounded-lg bg-sky-600 px-4 py-2 font-semibold" onClick={() => void auth.refresh()}>
            Retry
          </button>
          <button type="button" className="rounded-lg px-4 py-2 ring-1 ring-white/20" onClick={() => void auth.signOut()}>
            Sign out
          </button>
        </div>
      </Centered>
    )
  }
  if (auth.status !== 'signed_in') return <LoginScreen title={title} />
  if (requires.length && !auth.canAny(requires)) {
    return (
      <Centered>
        <h1 className="text-xl font-bold">{title}: not allowed</h1>
        <p className="mt-2 text-sm text-white/70">
          {auth.principal?.display_name} ({auth.principal?.roles.join(', ') || 'no roles'}) needs one of: {requires.join(', ')}.
        </p>
        <button type="button" className="mt-4 rounded-lg bg-sky-600 px-4 py-2 font-semibold" onClick={() => void auth.signOut()}>
          Sign in as someone else
        </button>
      </Centered>
    )
  }
  return <>{children}</>
}

/** "Needs <permission>" hint for a hidden / disabled control. */
export function NeedsPermission({ perm, className = '' }: { perm: string; className?: string }) {
  return <span className={`text-xs text-[#8a6d00] ${className}`}>{needsText(perm)}</span>
}

export function RequirePermission({ perm, children, fallback }: { perm: string; children: ReactNode; fallback?: ReactNode }) {
  const { can } = useAuth()
  if (can(perm)) return <>{children}</>
  return <>{fallback === undefined ? <NeedsPermission perm={perm} /> : fallback}</>
}

/** Header widget: who is signed in + Sign out. `tone` matches the surrounding header. */
export function SignedInBadge({ tone = 'dark' }: { tone?: 'dark' | 'light' }) {
  const { principal, signOut } = useAuth()
  const [changing, setChanging] = useState(false)
  if (!principal) return null
  const box = tone === 'dark' ? 'bg-white/10 text-white ring-white/20' : 'bg-white text-[#0b0b0b] ring-black/15'
  const sub = tone === 'dark' ? 'text-white/60' : 'text-[#52514e]'
  return (
    <div className={`flex items-center gap-3 rounded-lg px-3 py-1.5 ring-1 ${box}`}>
      <span className="flex flex-col leading-tight">
        <span className="text-sm font-semibold">
          {principal.display_name}
          {principal.kind === 'legacy' ? ' (legacy token)' : principal.kind === 'api_key' ? ' (API key)' : ''}
        </span>
        <span className={`text-[11px] ${sub}`}>{principal.roles.join(', ') || 'no roles'}</span>
      </span>
      {principal.kind === 'staff' ? (
        <button type="button" className="rounded-md px-2.5 py-1 text-xs font-semibold ring-1 ring-current/30 hover:opacity-80" onClick={() => setChanging(true)}>
          Password
        </button>
      ) : null}
      <button type="button" className="rounded-md bg-[#d03b3b] px-2.5 py-1 text-xs font-semibold text-white hover:bg-[#b83232]" onClick={() => void signOut()}>
        Sign out
      </button>
      {changing ? (
        <OwnPasswordDialog
          onClose={(changed) => {
            setChanging(false)
            if (changed) toast.success('Password changed. Your other sessions were signed out.')
          }}
        />
      ) : null}
    </div>
  )
}
