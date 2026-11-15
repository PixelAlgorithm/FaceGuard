/**
 * /operator (verdict console) and /register (enrolment). Lazy, so the kiosk route never loads them.
 * Each page sits behind a LoginGate (design v2 §F): /operator needs events:read, /register needs enrol:write.
 * App.tsx provides the <AuthProvider> around this component.
 */
import { Suspense, lazy } from 'react'
import { LoginGate } from '../shared/auth/LoginGate'
import { PERM } from '../shared/auth/permissions'

const OperatorApp = lazy(() => import('./OperatorApp'))
const RegisterApp = lazy(() => import('./RegisterApp'))

const OPERATOR_REQUIRES = [PERM.eventsRead] as const
const REGISTER_REQUIRES = [PERM.enrolWrite] as const

export function OperatorPages() {
  const register = /\/register\/?$/.test(window.location.pathname)
  return (
    <LoginGate requires={register ? REGISTER_REQUIRES : OPERATOR_REQUIRES} title={register ? 'Register a person' : 'Operator console'}>
      <Suspense fallback={<div className="p-8 text-lg text-white">Loading…</div>}>{register ? <RegisterApp /> : <OperatorApp />}</Suspense>
    </LoginGate>
  )
}
