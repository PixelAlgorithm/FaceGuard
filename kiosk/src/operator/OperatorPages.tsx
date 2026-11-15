/** /operator (verdict console) and /register (enrolment). Lazy, so the kiosk route never loads them. */
import { Suspense, lazy } from 'react'

const OperatorApp = lazy(() => import('./OperatorApp'))
const RegisterApp = lazy(() => import('./RegisterApp'))

export function OperatorPages() {
  const register = /\/register\/?$/.test(window.location.pathname) || window.location.hash.startsWith('#/register')
  return (
    <Suspense fallback={<div className="p-8 text-lg text-white">Loading…</div>}>{register ? <RegisterApp /> : <OperatorApp />}</Suspense>
  )
}
