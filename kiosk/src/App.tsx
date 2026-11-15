/**
 * Routes by PATH only: "/" = public kiosk, "/operator", "/register", "/admin" = staff consoles.
 * Hash routes (#/admin …) were removed: they rendered the control panel on the public kiosk path (audit KAO-M1).
 * The staff consoles are lazy chunks wrapped in <AuthProvider>; the public kiosk route never holds a staff
 * credential (it wipes hid.session / hid.adminToken and ends that session on mount, audit KAO-02).
 */
import { Suspense, lazy, useEffect } from 'react'
import { KioskApp } from './kiosk/KioskApp'
import { AuthProvider } from './shared/auth/AuthProvider'
import { publicPageNeedsWipe } from './shared/auth/lifecycle'
import { clearSessionOnPublicRoute } from './shared/auth/publicKiosk'
import { SimulatedBanner } from './shared/SimulatedBanner'
import { Toaster } from './shared/Toaster'

const AdminApp = lazy(() => import('./admin/AdminApp'))
const OperatorPages = lazy(() => import('./operator/OperatorPages').then((m) => ({ default: m.OperatorPages })))

type RouteName = 'kiosk' | 'admin' | 'operator'

function routeOf(pathname: string): RouteName {
  const p = pathname.replace(/\/+$/, '')
  if (p.endsWith('/admin')) return 'admin'
  if (p.endsWith('/operator') || p.endsWith('/register')) return 'operator'
  return 'kiosk'
}

function PublicKiosk() {
  useEffect(() => {
    clearSessionOnPublicRoute()
    // KAUTH-01: a back/forward-cache restore re-shows "/" without a mount; wipe again then (idempotent)
    const onShow = (e: PageTransitionEvent) => {
      if (publicPageNeedsWipe({ type: 'pageshow', persisted: e.persisted })) clearSessionOnPublicRoute()
    }
    const onVisibility = () => {
      if (publicPageNeedsWipe({ type: 'visibilitychange', visible: document.visibilityState === 'visible' })) clearSessionOnPublicRoute()
    }
    window.addEventListener('pageshow', onShow)
    document.addEventListener('visibilitychange', onVisibility)
    return () => {
      window.removeEventListener('pageshow', onShow)
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [])
  return <KioskApp />
}

function Route() {
  const route = routeOf(window.location.pathname)
  if (route === 'kiosk') return <PublicKiosk />
  return (
    <AuthProvider>
      <Suspense fallback={<div className="p-8 text-lg text-white">Loading…</div>}>{route === 'admin' ? <AdminApp /> : <OperatorPages />}</Suspense>
    </AuthProvider>
  )
}

export function App() {
  return (
    <>
      <Route />
      <SimulatedBanner />
      <Toaster />
    </>
  )
}
