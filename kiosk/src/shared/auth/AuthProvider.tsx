/**
 * <AuthProvider> for the privileged pages (/admin, /operator, /register). Design v2 §F:
 * - token in memory (session.ts persists it to sessionStorage only on those paths);
 * - a 401 on any session request (http.ts / mock) -> session cleared, login shown "Session expired, sign in again";
 * - 10 minutes without pointer / keyboard input -> client-side sign out (and POST /v1/auth/logout);
 *   the first input after a long gap (sleeping laptop, throttled background tab) signs out instead of reviving;
 * - pointerdown / keydown -> X-FG-Activity on the next request + a debounced POST /v1/auth/activity (<= 1 / 60 s);
 * - a 403 MISSING_PERMISSION or an SSE `event: auth` -> /v1/auth/me is re-read (roles may have changed), at most
 *   once per 5 s with a trailing re-read so a burst never hides the latest change;
 * - a 401 reported for an OLDER token (in flight across a sign-out / sign-in) never ends the current session;
 * - only the newest /v1/auth/me answer is applied (overlapping refreshes cannot resurrect stale permissions).
 */
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { asApiError, getApi } from '../../api'
import type { LoginResult, Principal, SessionInfo } from '../../api/authTypes'
import { isSessionToken, noteUserInput, setAuthRecheckHandler, setUnauthorizedHandler } from '../../api/credentials'
import { AuthContext, pendingOf, type AuthContextValue, type AuthStatusKind } from './context'
import { IDLE_CHECK_MS, activityPostDue, isIdleExpired, planRecheck, restoredLastInput, unauthorizedMatches } from './lifecycle'
import { clearSessionToken, getSessionToken, getStoredLastInput, setSessionToken, setStoredLastInput } from './session'

export { CLIENT_IDLE_SIGNOUT_MS } from './lifecycle'

const INPUT_EVENTS = ['pointerdown', 'keydown'] as const

export const SESSION_EXPIRED_TEXT = 'Session expired, sign in again.'
export const IDLE_SIGNOUT_TEXT = 'Signed out after 10 minutes without input.'

interface State {
  status: AuthStatusKind
  token: string
  principal: Principal | null
  session: SessionInfo | null
  notice: string | null
  error: string | null
}

function stateFor(token: string, principal: Principal, session: SessionInfo | null): State {
  return { status: pendingOf(principal) ? 'pending' : 'signed_in', token, principal, session, notice: null, error: null }
}

const signedOut = (notice: string | null): State => ({ status: 'signed_out', token: '', principal: null, session: null, notice, error: null })

interface Boot {
  state: State
  /** restored idle clock (KAUTH-02) */
  lastInputAt: number
  /** a stored session that was already idle too long: logged out on the edge at mount */
  expiredToken: string
}

function boot(): Boot {
  const token = getSessionToken()
  if (!token) return { state: signedOut(null), lastInputAt: 0, expiredToken: '' }
  const idle = restoredLastInput(getStoredLastInput(), Date.now())
  if (idle.expired) {
    clearSessionToken()
    return { state: signedOut(IDLE_SIGNOUT_TEXT), lastInputAt: 0, expiredToken: token }
  }
  return { state: { status: 'loading', token, principal: null, session: null, notice: null, error: null }, lastInputAt: idle.lastInputAt, expiredToken: '' }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const api = getApi()
  const [initial] = useState(boot)
  const [state, setState] = useState<State>(initial.state)
  const tokenRef = useRef(state.token)
  const lastInputRef = useRef(initial.lastInputAt)
  const expiredBootToken = useRef(initial.expiredToken)
  const lastActivityPostRef = useRef(0)
  const lastRecheckRef = useRef(0)
  const recheckTimerRef = useRef<number | null>(null)
  const loadSeqRef = useRef(0)
  const bootToken = useRef(state.status === 'loading' ? state.token : '')

  const clientSignOut = useCallback((notice: string | null) => {
    clearSessionToken()
    tokenRef.current = ''
    setState(signedOut(notice))
  }, [])

  const signOut = useCallback(
    async (notice: string | null = null) => {
      const token = tokenRef.current
      clientSignOut(notice)
      // best effort: the session is already gone locally
      if (token && isSessionToken(token)) await api.logout(token).catch(() => undefined)
    },
    [api, clientSignOut],
  )

  const load = useCallback(
    async (token: string) => {
      const seq = ++loadSeqRef.current
      // signed out / replaced meanwhile, or a newer /me answer is on its way
      const stale = () => tokenRef.current !== token || loadSeqRef.current !== seq
      try {
        const me = await api.me(token)
        if (stale()) return
        setState(stateFor(token, me.principal, me.session))
      } catch (e) {
        if (stale()) return
        const err = asApiError(e)
        if (err && (err.status === 401 || err.status === 403 || err.code === 'BAD_CREDENTIAL')) {
          // a session 401 already signed us out via the handler; a legacy token 401/403 lands here
          clientSignOut(err.status === 401 ? SESSION_EXPIRED_TEXT : `Not accepted: ${err.message}`)
          return
        }
        setState((s) => ({ ...s, status: 'error', error: err?.message ?? String(e) }))
      }
    },
    [api, clientSignOut],
  )

  const refresh = useCallback(async () => {
    const token = tokenRef.current
    if (token) await load(token)
  }, [load])

  // initial check of a stored session (once)
  useEffect(() => {
    const token = bootToken.current
    bootToken.current = ''
    if (token) void load(token)
    const expired = expiredBootToken.current
    expiredBootToken.current = ''
    if (expired && isSessionToken(expired)) void api.logout(expired).catch(() => undefined)
  }, [api, load])

  // 401 on a session request anywhere on the page / SSE `event: auth` / 403 MISSING_PERMISSION
  useEffect(() => {
    const offUnauth = setUnauthorizedHandler((info) => {
      if (unauthorizedMatches(info, tokenRef.current)) clientSignOut(SESSION_EXPIRED_TEXT)
    })
    const runRecheck = () => {
      recheckTimerRef.current = null
      lastRecheckRef.current = Date.now()
      void refresh()
    }
    const offRecheck = setAuthRecheckHandler(() => {
      if (recheckTimerRef.current !== null) return // a trailing re-read is already scheduled
      const plan = planRecheck(lastRecheckRef.current, Date.now())
      if (plan.runNow) runRecheck()
      else recheckTimerRef.current = window.setTimeout(runRecheck, plan.delayMs)
    })
    return () => {
      offUnauth()
      offRecheck()
      if (recheckTimerRef.current !== null) window.clearTimeout(recheckTimerRef.current)
      recheckTimerRef.current = null
    }
  }, [clientSignOut, refresh])

  const noteActivity = useCallback(() => {
    const now = Date.now()
    const token = tokenRef.current
    // the first input after > 10 min (timers throttled in a background tab / a sleeping laptop) must not revive
    if (token && lastInputRef.current && isIdleExpired(lastInputRef.current, now)) {
      void signOut(IDLE_SIGNOUT_TEXT)
      return
    }
    noteUserInput(now)
    lastInputRef.current = now
    setStoredLastInput(now)
    if (!token || !isSessionToken(token) || !activityPostDue(lastActivityPostRef.current, now)) return
    lastActivityPostRef.current = now
    void api.noteActivity(token).catch(() => undefined) // a 401 here signs out through the handler
  }, [api, signOut])

  // input tracking + client idle sign-out (only while a session exists)
  const active = state.status === 'signed_in' || state.status === 'pending'
  useEffect(() => {
    if (!active) return
    // KAUTH-02: a restored session keeps its idle clock; only a session without one starts it now
    if (!lastInputRef.current) lastInputRef.current = Date.now()
    setStoredLastInput(lastInputRef.current)
    const onInput = () => noteActivity()
    const checkIdle = () => {
      if (isIdleExpired(lastInputRef.current, Date.now())) void signOut(IDLE_SIGNOUT_TEXT)
    }
    const onVisible = () => {
      if (document.visibilityState === 'visible') checkIdle()
    }
    for (const ev of INPUT_EVENTS) window.addEventListener(ev, onInput, { capture: true, passive: true })
    document.addEventListener('visibilitychange', onVisible)
    const timer = window.setInterval(checkIdle, IDLE_CHECK_MS)
    return () => {
      for (const ev of INPUT_EVENTS) window.removeEventListener(ev, onInput, { capture: true })
      document.removeEventListener('visibilitychange', onVisible)
      window.clearInterval(timer)
    }
  }, [active, noteActivity, signOut])

  const acceptLogin = useCallback((r: LoginResult) => {
    setSessionToken(r.token)
    tokenRef.current = r.token
    lastInputRef.current = Date.now() // a fresh session never inherits the previous one's idle clock
    setStoredLastInput(lastInputRef.current)
    lastActivityPostRef.current = Date.now() // the login itself counts as activity
    setState(stateFor(r.token, r.principal, { session_id: null, expires_at: r.expires_at, idle_timeout_s: r.idle_timeout_s }))
  }, [])

  const signInWithToken = useCallback(
    async (token: string) => {
      setSessionToken(token)
      tokenRef.current = token
      lastInputRef.current = Date.now()
      setStoredLastInput(lastInputRef.current)
      setState({ status: 'loading', token, principal: null, session: null, notice: null, error: null })
      await load(token)
    },
    [load],
  )

  const value = useMemo<AuthContextValue>(() => {
    const perms = new Set(state.status === 'signed_in' ? (state.principal?.permissions ?? []) : [])
    return {
      ...state,
      pending: state.status === 'pending' ? pendingOf(state.principal) : null,
      can: (perm) => perms.has(perm),
      canAny: (list) => list.some((p) => perms.has(p)),
      signOut,
      noteActivity,
      acceptLogin,
      signInWithToken,
      refresh,
    }
  }, [state, signOut, noteActivity, acceptLogin, signInWithToken, refresh])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
