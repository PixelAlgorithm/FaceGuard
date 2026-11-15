/** Routes: "/" = kiosk, "/operator", "/register", "/admin" (or "#/admin") = control panel. */
import { Suspense, lazy } from 'react'
import { KioskApp } from './kiosk/KioskApp'
import { OperatorPages } from './operator/OperatorPages'
import { SimulatedBanner } from './shared/SimulatedBanner'
import { Toaster } from './shared/Toaster'

const AdminApp = lazy(() => import('./admin/AdminApp'))

function isAdminRoute(): boolean {
  return window.location.pathname.replace(/\/+$/, '').endsWith('/admin') || window.location.hash.startsWith('#/admin')
}

function Route() {
  if (/\/(operator|register)\/?$/.test(window.location.pathname) || /^#\/(operator|register)/.test(window.location.hash)) return <OperatorPages />
  if (isAdminRoute()) {
    return (
      <Suspense fallback={<div className="p-8 text-lg text-white">Loading control panel…</div>}>
        <AdminApp />
      </Suspense>
    )
  }
  return <KioskApp />
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
