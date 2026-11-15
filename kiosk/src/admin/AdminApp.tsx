/**
 * /admin - CONTROL PANEL (X-Admin-Token entered once, kept in sessionStorage). Tabs:
 *  1. Users & access - signed campus schedule (roles, extended hours, add / end access) + quick enrol
 *  2. Live system    - mode / demo clock / random challenge / sync / rate limit / kiosk id, status, live feed, store
 *  3. Staff codes    - rotate one-time STAFF_OVERRIDE codes (plaintext shown once)
 *  4. Eval           - eval context labelling + metrics
 * The tab is kept in the URL hash (#users, #system, #codes, #eval) so a reload stays on it.
 */
import { useEffect, useState } from 'react'
import { getApi, type MetricsResponse } from '../api'
import { EDGE_URL, MOCK_ENABLED, THRESHOLDS, THRESHOLDS_MISSING, getAdminToken, setAdminToken } from '../config'
import { ModeBadge } from '../shared/ModeBadge'
import { useModeStatus } from '../shared/modeStore'
import { ControlPanel } from './panels/ControlPanel'
import { EnrolPanel } from './panels/EnrolPanel'
import { EvalContextPanel } from './panels/EvalContextPanel'
import { LiveFeed } from './panels/LiveFeed'
import { MetricsPanel } from './panels/MetricsPanel'
import { MockControls } from './panels/MockControls'
import { StaffCodesPanel } from './panels/StaffCodesPanel'
import { StoreViewer } from './panels/StoreViewer'
import { SystemStatusPanel } from './panels/SystemStatusPanel'
import { UsersAccessPanel } from './panels/UsersAccessPanel'
import { usePoll } from './usePoll'

type Tab = 'users' | 'system' | 'codes' | 'eval'

const TABS: Array<{ id: Tab; label: string; hint: string }> = [
  { id: 'users', label: 'Users & access', hint: 'roles, hours, enrolment' },
  { id: 'system', label: 'Live system', hint: 'mode, clock, health, feed' },
  { id: 'codes', label: 'Staff codes', hint: 'override code rotation' },
  { id: 'eval', label: 'Eval', hint: 'labelling + metrics' },
]

const NAV: Array<{ href: string; label: string }> = [
  { href: '/', label: 'Kiosk' },
  { href: '/operator', label: 'Operator' },
  { href: '/register', label: 'Register' },
  { href: '/admin', label: 'Control panel' },
]

function tabFromHash(): Tab {
  const h = window.location.hash.replace(/^#\/?(admin\/?)?/, '')
  return TABS.find((t) => t.id === h)?.id ?? 'users'
}

function TokenForm({ initial, onSave }: { initial: string; onSave: (t: string) => void }) {
  const [value, setValue] = useState(initial)
  return (
    <form
      className="flex items-center gap-2"
      onSubmit={(e) => {
        e.preventDefault()
        onSave(value.trim())
      }}
    >
      <label className="text-xs text-[#52514e]" htmlFor="admin-token">
        X-Admin-Token
      </label>
      <input
        id="admin-token"
        type="password"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        autoComplete="off"
        className="w-48 rounded-lg border border-black/20 bg-white px-2 py-1 text-sm text-black"
        placeholder={MOCK_ENABLED ? 'any value (mock)' : 'from .env ADMIN_TOKEN'}
      />
      <button type="submit" className="rounded-lg bg-[#2a78d6] px-3 py-1 text-sm font-semibold text-white">
        Use
      </button>
      {initial ? (
        <button
          type="button"
          className="rounded-lg px-2 py-1 text-xs text-[#52514e] ring-1 ring-black/15"
          onClick={() => {
            setValue('')
            onSave('')
          }}
        >
          Forget
        </button>
      ) : null}
    </form>
  )
}

export default function AdminApp() {
  const api = getApi()
  const [token, setToken] = useState(getAdminToken)
  const [tab, setTab] = useState<Tab>(tabFromHash)
  const { mode } = useModeStatus()
  const metrics = usePoll<MetricsResponse>(() => api.getMetrics(token), 3000, !!token && tab === 'eval', `m-${token}`)
  const store = usePoll<unknown>(() => api.getStore(token), 4000, !!token && tab === 'system', `s-${token}`)

  useEffect(() => {
    const onHash = () => setTab(tabFromHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  const go = (t: Tab) => {
    setTab(t)
    if (window.location.hash !== `#${t}`) window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}#${t}`)
  }

  return (
    <div className="min-h-full bg-[#f9f9f7] font-sans text-[#0b0b0b]">
      <header className="sticky top-0 z-20 border-b border-black/10 bg-[#0b0b0b] text-white">
        <div className="flex flex-wrap items-center gap-3 px-5 py-3">
          <h1 className="text-lg font-bold">FaceGuard · Control panel</h1>
          <ModeBadge size="sm" showBundle />
          <span className="font-mono text-xs text-white/60">
            {MOCK_ENABLED ? 'mock://edge' : EDGE_URL} · {mode?.kiosk_id ?? '…'} · policy {mode?.policy_version ?? THRESHOLDS.policyVersion}
          </span>
          {mode?.demo_clock?.active ? (
            <span className="rounded-full bg-violet-700 px-3 py-0.5 text-xs font-bold ring-1 ring-violet-300">DEMO CLOCK {mode.demo_clock.now_local}</span>
          ) : null}
          <nav className="flex flex-wrap gap-1" aria-label="Kiosk pages">
            {NAV.map((n) => (
              <a
                key={n.href}
                href={`${n.href}${window.location.search}`}
                aria-current={n.href === '/admin' ? 'page' : undefined}
                target={n.href === '/' ? '_blank' : undefined}
                rel={n.href === '/' ? 'noreferrer' : undefined}
                className={`rounded-lg px-3 py-1 text-sm font-semibold ${n.href === '/admin' ? 'bg-white text-black' : 'text-white/80 ring-1 ring-white/20 hover:bg-white/10'}`}
              >
                {n.label}
              </a>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-2 rounded-lg bg-white px-3 py-1.5">
            <span className={`text-xs font-semibold ${token ? 'text-[#006300]' : 'text-[#d03b3b]'}`}>{token ? 'token set' : 'no token'}</span>
            <TokenForm
              key={token ? 'set' : 'empty'}
              initial={token}
              onSave={(t) => {
                setAdminToken(t)
                setToken(t)
              }}
            />
          </div>
        </div>
        <div className="flex gap-1 px-5" role="tablist" aria-label="Control panel sections">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              aria-selected={tab === t.id}
              onClick={() => go(t.id)}
              className={`rounded-t-lg px-4 py-2 text-left text-sm font-semibold ${tab === t.id ? 'bg-[#f9f9f7] text-[#0b0b0b]' : 'text-white/75 hover:bg-white/10'}`}
            >
              {t.label}
              <span className={`block text-[11px] font-normal ${tab === t.id ? 'text-[#52514e]' : 'text-white/50'}`}>{t.hint}</span>
            </button>
          ))}
        </div>
      </header>

      {THRESHOLDS_MISSING.length ? (
        <p className="mx-5 mt-3 rounded-lg bg-[#fff4d6] px-3 py-2 text-sm text-[#5c4300]">
          config/thresholds.yaml is missing keys the kiosk expected (using safe defaults): {THRESHOLDS_MISSING.join(', ')}
        </p>
      ) : null}
      {!token ? (
        <p className="mx-5 mt-3 rounded-lg bg-[#fde2e1] px-3 py-2 text-sm text-[#8f1d1d]">
          Enter the admin token (top right) to load users, controls, metrics and the live feed.
        </p>
      ) : null}

      <main className="p-5" role="tabpanel" aria-label={TABS.find((t) => t.id === tab)?.label}>
        {tab === 'users' ? (
          <div className="grid gap-4 2xl:grid-cols-[minmax(0,1fr)_26rem]">
            <UsersAccessPanel token={token} />
            <EnrolPanel token={token} />
          </div>
        ) : null}
        {tab === 'system' ? (
          <div className="grid gap-4 xl:grid-cols-[26rem_minmax(0,1fr)]">
            <div className="flex flex-col gap-4">
              <ControlPanel token={token} />
              {MOCK_ENABLED ? <MockControls /> : null}
            </div>
            <div className="flex min-w-0 flex-col gap-4">
              <SystemStatusPanel token={token} />
              {token ? <LiveFeed key={token} token={token} /> : null}
              <StoreViewer body={store.data} error={store.error} onRefresh={store.refresh} />
            </div>
          </div>
        ) : null}
        {tab === 'codes' ? (
          <div className="max-w-4xl">
            <StaffCodesPanel token={token} />
          </div>
        ) : null}
        {tab === 'eval' ? (
          <div className="grid gap-4 xl:grid-cols-[24rem_minmax(0,1fr)]">
            <EvalContextPanel token={token} />
            <MetricsPanel metrics={metrics.data} error={metrics.error} />
          </div>
        ) : null}
      </main>
    </div>
  )
}
