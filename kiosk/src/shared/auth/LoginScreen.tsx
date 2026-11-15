/**
 * Staff sign-in for /admin, /operator, /register (design v2 §F). Steps:
 *   credentials -> (MFA_REQUIRED) mfa code with the opaque mfa_ticket -> signed in
 *   pending PASSWORD_CHANGE_REQUIRED -> change-password form
 *   pending MFA_ENROLMENT_REQUIRED   -> re-enter password, show secret + otpauth URI as TEXT, confirm a code
 * GET /v1/auth/status EMPTY shows the bootstrap CLI command; RATE_LIMITED shows the wait.
 * Passwords live only in this component's state; the current / re-auth password is cleared after each request
 * (the new password survives a PASSWORD_POLICY answer so it can be edited).
 * The MFA ticket is single use and lives 2 minutes: any failed code, or the timeout, restarts at the password.
 */
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { asApiError, getApi } from '../../api'
import { AUTH_LIMITS, type AuthStatus, type MfaEnrolment } from '../../api/authTypes'
import { MOCK_DEMO_USERS, MOCK_TOTP_CODE } from '../../api/mockAuth'
import { MOCK_ENABLED } from '../../config'
import { authErrorText } from './authErrorText'
import { useAuth } from './context'
import { MFA_TICKET_TTL_MS, secondsLeft } from './lifecycle'
import { GIVEN_PASSWORD_MAX, PASSWORD_MAX, PASSWORD_MIN, newPasswordProblems } from './passwordPolicy'

/** Run on the edge machine as the edge OS user (design v2 §A); `admin` itself is a reserved username. */
const BOOTSTRAP_COMMAND = 'edge/.venv/bin/python -m edge.auth create-user --username ops_admin --display-name "Ops Admin" --role admin --mfa'

const INPUT = 'w-full rounded-lg border border-white/20 bg-white/5 px-3 py-2 text-base text-white placeholder:text-white/40 focus:border-sky-400 focus:outline-none'
const BUTTON = 'w-full rounded-lg bg-sky-600 px-4 py-2.5 text-base font-semibold text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50'
const LINK = 'text-sm text-sky-300 underline-offset-2 hover:underline'

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1 text-sm text-white/80">
      {label}
      {children}
    </label>
  )
}

/** A labelled read-only value (a <label> may only wrap form controls). */
function Readout({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1 text-sm text-white/80">
      <span>{label}</span>
      {children}
    </div>
  )
}

function Shell({ title, subtitle, children, footer }: { title: string; subtitle?: string; children: ReactNode; footer?: ReactNode }) {
  return (
    <main className="flex min-h-full items-center justify-center bg-[#0b0f14] px-4 py-10 font-sans text-white">
      <section className="w-full max-w-md rounded-2xl border border-white/10 bg-[#121821] p-6 shadow-2xl" aria-labelledby="login-title">
        <p className="text-xs font-semibold tracking-wider text-sky-300 uppercase">FaceGuard · staff sign-in</p>
        <h1 id="login-title" className="mt-1 text-2xl font-bold">
          {title}
        </h1>
        {subtitle ? <p className="mt-1 text-sm text-white/60">{subtitle}</p> : null}
        <div className="mt-5 flex flex-col gap-4">{children}</div>
        {footer ? <div className="mt-5 border-t border-white/10 pt-4">{footer}</div> : null}
      </section>
    </main>
  )
}

function Alert({ tone, children }: { tone: 'error' | 'info' | 'warn'; children: ReactNode }) {
  const cls =
    tone === 'error'
      ? 'bg-red-500/15 text-red-200 ring-red-400/30'
      : tone === 'warn'
        ? 'bg-amber-500/15 text-amber-100 ring-amber-400/30'
        : 'bg-sky-500/10 text-sky-100 ring-sky-400/30'
  return (
    <p role={tone === 'error' ? 'alert' : 'status'} className={`rounded-lg px-3 py-2 text-sm ring-1 ${cls}`}>
      {children}
    </p>
  )
}

interface Countdown {
  /** whole seconds left (0 = not waiting) */
  wait: number
  /** a countdown was started and has not been reset (it may have reached 0) */
  started: boolean
  start: (seconds: number) => void
  reset: () => void
}

/**
 * RATE_LIMITED wait. `now` is captured together with `until` when the wait starts (never a clock read at mount,
 * which would show a too-long wait at first), then refreshed twice a second until the wait is over.
 */
function useCountdown(): Countdown {
  const [clock, setClock] = useState({ until: 0, now: 0 })
  useEffect(() => {
    if (clock.until <= clock.now) return
    const t = window.setInterval(() => setClock((c) => ({ ...c, now: Date.now() })), 500)
    return () => window.clearInterval(t)
  }, [clock.until, clock.now])
  return {
    wait: secondsLeft(clock.until, clock.now),
    started: clock.until > 0,
    start: (seconds) => {
      const now = Date.now()
      setClock({ until: now + seconds * 1000, now })
    },
    reset: () => setClock({ until: 0, now: 0 }),
  }
}

/** Wait shown when a 429 carries neither retry_after_s nor Retry-After. */
const DEFAULT_RETRY_S = 5

function StoreNotice({ status }: { status: AuthStatus | null }) {
  if (!status) return null
  if (status.store === 'EMPTY') {
    return (
      <Alert tone="warn">
        No staff accounts exist yet. On the edge machine (as the edge OS user), create the first admin:
        <code className="mt-2 block rounded bg-black/40 p-2 font-mono text-xs break-all select-all">{BOOTSTRAP_COMMAND}</code>
      </Alert>
    )
  }
  if (status.store === 'MISSING' || status.store === 'UNAVAILABLE') {
    return (
      <Alert tone="error">
        Staff sign-in is unavailable: the edge reports the staff store as {status.store}. Nobody can sign in until it is restored (see the edge logs).
      </Alert>
    )
  }
  return null
}

function MockHint() {
  if (!MOCK_ENABLED) return null
  return (
    <Alert tone="info">
      SIMULATED edge: any password works (except “wrong”), MFA code {MOCK_TOTP_CODE}. Demo users:{' '}
      {MOCK_DEMO_USERS.map((u) => `${u.username} – ${u.roles}`).join(' · ')}
    </Alert>
  )
}

function LegacyTokenForm() {
  const { signInWithToken } = useAuth()
  const [legacy, setLegacy] = useState('')
  return (
    <details className="text-sm text-white/70">
      <summary className="cursor-pointer">Use the legacy shared admin token (deprecated)</summary>
      <form
        className="mt-3 flex flex-col gap-2"
        onSubmit={(e) => {
          e.preventDefault()
          const t = legacy.trim()
          setLegacy('')
          if (t) void signInWithToken(t)
        }}
      >
        <input type="password" className={INPUT} value={legacy} onChange={(e) => setLegacy(e.target.value)} autoComplete="off" aria-label="Legacy admin token" />
        <button type="submit" className={BUTTON} disabled={!legacy.trim()}>
          Use token
        </button>
        <span className="text-xs text-white/50">Every use is audited as legacy:admin_token. Staff accounts are preferred.</span>
      </form>
    </details>
  )
}

function CredentialsStep({ title, onMfa, banner }: { title: string; onMfa: (ticket: string) => void; banner: string | null }) {
  const api = getApi()
  const { acceptLogin, notice } = useAuth()
  const [status, setStatus] = useState<AuthStatus | null>(null)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const countdown = useCountdown()
  const wait = countdown.wait
  const rateLimited = countdown.started

  useEffect(() => {
    let cancelled = false
    api.authStatus().then(
      (s) => {
        if (!cancelled) setStatus(s)
      },
      (e) => {
        if (!cancelled) setError(authErrorText(e))
      },
    )
    return () => {
      cancelled = true
    }
  }, [api])

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (busy || wait > 0) return
    setBusy(true)
    setError(null)
    countdown.reset()
    try {
      const r = await api.login({ username: username.trim().toLowerCase(), password })
      setPassword('')
      acceptLogin(r)
    } catch (err) {
      setPassword('')
      const a = asApiError(err)
      if (a?.reason === 'MFA_REQUIRED' && a.extra.mfa_ticket) {
        onMfa(a.extra.mfa_ticket)
        return
      }
      if (a?.status === 429) countdown.start(a.extra.retry_after_s ?? DEFAULT_RETRY_S)
      setError(authErrorText(err))
    } finally {
      setBusy(false)
    }
  }

  const blocked = status?.store === 'EMPTY' || status?.store === 'MISSING' || status?.store === 'UNAVAILABLE'
  return (
    <Shell title={title} subtitle="Sign in with your own staff account." footer={status?.legacy_token_enabled ? <LegacyTokenForm /> : null}>
      {banner ? <Alert tone="error">{banner}</Alert> : null}
      {notice ? <Alert tone="warn">{notice}</Alert> : null}
      <MockHint />
      <StoreNotice status={status} />
      <form className="flex flex-col gap-4" onSubmit={submit}>
        <Field label="Username">
          <input
            className={INPUT}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            required
            autoFocus
          />
        </Field>
        <Field label="Password">
          <input
            className={INPUT}
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
            maxLength={GIVEN_PASSWORD_MAX}
          />
        </Field>
        {/* static alert text (a live countdown inside role=alert would be re-announced every tick) */}
        {error ? <Alert tone={rateLimited && wait === 0 ? 'info' : 'error'}>{rateLimited && wait === 0 ? 'You can try again now.' : error}</Alert> : null}
        <button type="submit" className={BUTTON} disabled={busy || wait > 0 || blocked || !username.trim() || !password}>
          {busy ? 'Signing in…' : wait > 0 ? `Wait ${wait} s` : 'Sign in'}
        </button>
      </form>
    </Shell>
  )
}

function CodeInput({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <input
      className={`${INPUT} font-mono tracking-[0.4em]`}
      value={value}
      onChange={(e) => onChange(e.target.value.replace(/\D/g, '').slice(0, 6))}
      inputMode="numeric"
      autoComplete="one-time-code"
      autoFocus
    />
  )
}

const TICKET_EXPIRED_TEXT = 'The sign-in step expired after 2 minutes. Sign in again.'

function MfaStep({ ticket, onRestart }: { ticket: string; onRestart: (msg: string | null) => void }) {
  const api = getApi()
  const { acceptLogin } = useAuth()
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const busyRef = useRef(false)
  const restartRef = useRef(onRestart)
  useEffect(() => {
    restartRef.current = onRestart
  }, [onRestart])
  // the edge forgets the ticket after 2 minutes: go back to the password instead of failing on submit
  useEffect(() => {
    const t = window.setTimeout(() => {
      if (!busyRef.current) restartRef.current(TICKET_EXPIRED_TEXT)
    }, MFA_TICKET_TTL_MS)
    return () => window.clearTimeout(t)
  }, [ticket])
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (busyRef.current) return // one use per ticket: never post it twice
    busyRef.current = true
    setBusy(true)
    try {
      acceptLogin(await api.login({ mfa_ticket: ticket, totp_code: code }))
    } catch (err) {
      // the ticket is single use (consumed even by a wrong code): start again with the password
      busyRef.current = false
      setBusy(false)
      onRestart(`${authErrorText(err)} Sign in again.`)
    }
  }
  return (
    <Shell title="Authenticator code" subtitle="Enter the 6-digit code from your authenticator app. This step expires after 2 minutes.">
      <MockHint />
      <form className="flex flex-col gap-4" onSubmit={submit}>
        <Field label="Code (6 digits)">
          <CodeInput value={code} onChange={setCode} />
        </Field>
        <button type="submit" className={BUTTON} disabled={busy || !AUTH_LIMITS.totpPattern.test(code)}>
          {busy ? 'Checking…' : 'Verify'}
        </button>
        <button type="button" className={LINK} onClick={() => onRestart(null)}>
          Back to username and password
        </button>
      </form>
    </Shell>
  )
}

function SignOutLink() {
  const { signOut } = useAuth()
  return (
    <button type="button" className={LINK} onClick={() => void signOut()}>
      Sign out
    </button>
  )
}

function ChangePasswordStep() {
  const api = getApi()
  const { token, principal, refresh } = useAuth()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [again, setAgain] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const problems = newPasswordProblems(next, { username: principal?.username ?? '', current, again })
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (busy) return
    setBusy(true)
    setError(null)
    try {
      await api.changePassword(token, { current_password: current, new_password: next })
      setNext('')
      setAgain('')
      await refresh()
    } catch (err) {
      setError(authErrorText(err))
    } finally {
      setCurrent('')
      setBusy(false)
    }
  }
  return (
    <Shell title="Choose a new password" subtitle={`${principal?.display_name ?? 'You'} must replace the temporary password before continuing.`} footer={<SignOutLink />}>
      <form className="flex flex-col gap-4" onSubmit={submit}>
        <Field label="Current (temporary) password">
          <input className={INPUT} type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" required autoFocus maxLength={GIVEN_PASSWORD_MAX} />
        </Field>
        <Field label={`New password (${PASSWORD_MIN}–${PASSWORD_MAX} characters, at least 5 different)`}>
          <input className={INPUT} type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" required />
        </Field>
        <Field label="New password again">
          <input className={INPUT} type="password" value={again} onChange={(e) => setAgain(e.target.value)} autoComplete="new-password" required />
        </Field>
        {next && problems.length ? <Alert tone="warn">{problems.join('; ')}</Alert> : null}
        {error ? <Alert tone="error">{error}</Alert> : null}
        <button type="submit" className={BUTTON} disabled={busy || !current || !next || next !== again || problems.length > 0}>
          {busy ? 'Saving…' : 'Change password'}
        </button>
      </form>
    </Shell>
  )
}

function MfaEnrolStep() {
  const api = getApi()
  const { token, principal, refresh } = useAuth()
  const [password, setPassword] = useState('')
  const [setup, setSetup] = useState<MfaEnrolment | null>(null)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const start = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      setSetup(await api.mfaEnroll(token, password))
    } catch (err) {
      if (asApiError(err)?.reason === 'MFA_ALREADY_ENABLED') await refresh()
      else setError(authErrorText(err))
    } finally {
      setPassword('')
      setBusy(false)
    }
  }
  const confirm = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.mfaConfirm(token, code)
      setSetup(null)
      await refresh()
    } catch (err) {
      setError(authErrorText(err))
    } finally {
      setCode('')
      setBusy(false)
    }
  }
  return (
    <Shell title="Set up two-factor sign-in" subtitle={`Your role (${principal?.roles.join(', ') ?? ''}) requires an authenticator app (TOTP).`} footer={<SignOutLink />}>
      <MockHint />
      {!setup ? (
        <form className="flex flex-col gap-4" onSubmit={start}>
          <Field label="Confirm your password">
            <input className={INPUT} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required autoFocus maxLength={GIVEN_PASSWORD_MAX} />
          </Field>
          {error ? <Alert tone="error">{error}</Alert> : null}
          <button type="submit" className={BUTTON} disabled={busy || !password}>
            {busy ? 'Starting…' : 'Show my secret'}
          </button>
        </form>
      ) : (
        <form className="flex flex-col gap-4" onSubmit={confirm}>
          <p className="text-sm text-white/80">
            Add this account to your authenticator app by typing the secret (manual entry, time-based, 6 digits, 30 s). It is shown only now.
          </p>
          <Readout label="Secret">
            <code className="rounded bg-black/40 p-2 font-mono text-base tracking-wider break-all select-all">{setup.secret.replace(/(.{4})/g, '$1 ').trim()}</code>
          </Readout>
          <Readout label="otpauth URI">
            <code className="rounded bg-black/40 p-2 font-mono text-xs break-all select-all">{setup.otpauth_uri}</code>
          </Readout>
          <Field label="Code from the app">
            <CodeInput value={code} onChange={setCode} />
          </Field>
          {error ? <Alert tone="error">{error}</Alert> : null}
          <button type="submit" className={BUTTON} disabled={busy || !AUTH_LIMITS.totpPattern.test(code)}>
            {busy ? 'Checking…' : 'Confirm and continue'}
          </button>
        </form>
      )}
    </Shell>
  )
}

/** The whole sign-in flow: credentials / MFA code, or the pending password-change / MFA-enrolment step. */
export function LoginScreen({ title }: { title: string }) {
  const { pending } = useAuth()
  const [ticket, setTicket] = useState<string | null>(null)
  const [banner, setBanner] = useState<string | null>(null)
  if (pending === 'PASSWORD_CHANGE_REQUIRED') return <ChangePasswordStep />
  if (pending === 'MFA_ENROLMENT_REQUIRED') return <MfaEnrolStep />
  if (ticket) {
    return (
      <MfaStep
        ticket={ticket}
        onRestart={(msg) => {
          setTicket(null)
          setBanner(msg)
        }}
      />
    )
  }
  return (
    <CredentialsStep
      title={title}
      banner={banner}
      onMfa={(t) => {
        setBanner(null)
        setTicket(t)
      }}
    />
  )
}
