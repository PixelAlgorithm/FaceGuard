/**
 * /admin - CONTROL PANEL behind staff sign-in (design v2 §F: <LoginGate>, permissions from /v1/auth/me).
 * Tabs (each shown only when the principal holds at least one of its permissions):
 *  1. Users & access - signed campus schedule (roles, extended hours, add / end access) + quick enrol
 *  2. Live system    - mode / demo clock / random challenge / sync / rate limit / kiosk id, status, live feed, store
 *  3. Staff codes    - rotate one-time STAFF_OVERRIDE codes (plaintext shown once)
 *  4. Eval           - eval context labelling + metrics
 *  5. Staff & roles  - staff accounts and API keys (staff:manage)
 *  6. Audit log      - sign-ins, staff changes, denials (audit:read)
 * Every poll is enabled by `token && can(perm)`; buttons without permission say "Needs <permission>".
 * The tab is kept in the URL hash (#users, #system, …) so a reload stays on it.
 */
import { useEffect, useState, type KeyboardEvent } from 'react'
import { getApi, type MetricsResponse, type ModeResponse } from '../api'
import { EDGE_URL, MOCK_ENABLED, THRESHOLDS_MISSING } from '../config'
import { useAuth } from '../shared/auth/context'
import { LoginGate, SignedInBadge } from '../shared/auth/LoginGate'
import { PERM } from '../shared/auth/permissions'
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
import { AuditLogPanel } from './panels/AuditLogPanel'
import { StaffPanel } from './panels/StaffPanel'
import { UsersAccessPanel } from './panels/UsersAccessPanel'
import { NeedsCard } from './ui'
import { usePoll } from './usePoll'

type Tab = 'users' | 'system' | 'codes' | 'eval' | 'staff' | 'audit'

/** `perms`: the tab is shown when the principal holds at least one of them. */
const TABS: Array<{ id: Tab; label: string; hint: string; perms: readonly string[] }> = [
  { id: 'users', label: 'Users & access', hint: 'roles, hours, enrolment', perms: [PERM.accessRead, PERM.enrolRead, PERM.enrolWrite] },
  {
    id: 'system',
    label: 'Live system',
    hint: 'mode, clock, health, feed',
    perms: [PERM.modeSwitch, PERM.syncRun, PERM.storeRead, PERM.eventsRead, PERM.rateLimitReset, PERM.demoClock, PERM.challengeControl],
  },
  { id: 'codes', label: 'Staff codes', hint: 'override code rotation', perms: [PERM.codesRotate, PERM.codesRotateAny] },
  { id: 'eval', label: 'Eval', hint: 'labelling + metrics', perms: [PERM.evalAdmin, PERM.metricsRead] },
  { id: 'staff', label: 'Staff & roles', hint: 'accounts, API keys', perms: [PERM.staffManage] },
  { id: 'audit', label: 'Audit log', hint: 'sign-ins, changes', perms: [PERM.auditRead] },
]

const NAV: Array<{ href: string; label: string }> = [
  { href: '/', label: 'Kiosk' },
  { href: '/operator', label: 'Operator' },
  { href: '/register', label: 'Register' },
  { href: '/admin', label: 'Control panel' },
]

function tabFromHash(): Tab | null {
  const h = window.location.hash.replace(/^#\/?/, '')
  return TABS.find((t) => t.id === h)?.id ?? null
}

/** Any signed-in principal may open the panel; each tab / panel / button checks its own permission. */
export default function AdminApp() {
  return (
    <LoginGate requires={[]} title="Control panel">
      <ControlPanelApp />
    </LoginGate>
  )
}

function ControlPanelApp() {
  const api = getApi()
  const { token, can, canAny } = useAuth()
  const visible = TABS.filter((t) => canAny(t.perms))
  const [requested, setTab] = useState<Tab | null>(tabFromHash)
  const tab: Tab | null = visible.find((t) => t.id === requested)?.id ?? visible[0]?.id ?? null
  const { mode } = useModeStatus()
  const metrics = usePoll<MetricsResponse>(() => api.getMetrics(token), 3000, !!token && can(PERM.metricsRead) && tab === 'eval', `m-${token}`)
  // the full mode status is store:read since the public /v1/mode became a subset
  // fast on the Live system tab, slow elsewhere (the header's policy version, KAUTH-03)
  const detail = usePoll<ModeResponse>(() => api.getModeDetail(token), tab === 'system' ? 3000 : 30000, !!token && can(PERM.storeRead), `md-${token}`)
  // the public /v1/mode no longer carries policy_version: show it only when the edge reported it
  const policyVersion = detail.data?.policy_version ?? mode?.policy_version ?? null
  const store = usePoll<unknown>(() => api.getStore(token), 4000, !!token && can(PERM.storeRead) && tab === 'system', `s-${token}`)

  useEffect(() => {
    const onHash = () => setTab(tabFromHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  const go = (t: Tab) => {
    setTab(t)
    if (window.location.hash !== `#${t}`) window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}#${t}`)
  }
  // WAI-ARIA tabs: Left/Right/Home/End move between the visible tabs (roving tabindex)
  const onTabKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const i = visible.findIndex((t) => t.id === tab)
    if (i < 0 || !visible.length) return
    const n = visible.length
    const to = e.key === 'ArrowRight' ? (i + 1) % n : e.key === 'ArrowLeft' ? (i - 1 + n) % n : e.key === 'Home' ? 0 : e.key === 'End' ? n - 1 : -1
    const target = visible[to]
    if (!target) return
    e.preventDefault()
    go(target.id)
    document.getElementById(`tab-${target.id}`)?.focus()
  }

  return (
    <div className="min-h-full bg-[#f9f9f7] font-sans text-[#0b0b0b]">
      <header className="sticky top-0 z-20 border-b border-black/10 bg-[#0b0b0b] text-white">
        <div className="flex flex-wrap items-center gap-3 px-5 py-3">
          <h1 className="text-lg font-bold">FaceGuard · Control panel</h1>
          <ModeBadge size="sm" showBundle />
          <span className="font-mono text-xs text-white/60">
            {MOCK_ENABLED ? 'mock://edge' : EDGE_URL} · {mode?.kiosk_id ?? '…'}
            {policyVersion ? ` · policy ${policyVersion}` : ''}
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
          <div className="ml-auto">
            <SignedInBadge tone="dark" />
          </div>
        </div>
        <div className="flex gap-1 px-5" role="tablist" aria-label="Control panel sections" onKeyDown={onTabKey}>
          {visible.map((t) => (
            <button
              key={t.id}
              id={`tab-${t.id}`}
              type="button"
              role="tab"
              aria-selected={tab === t.id}
              aria-controls="admin-tabpanel"
              tabIndex={tab === t.id ? 0 : -1}
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
      {tab === null ? (
        <p className="mx-5 mt-3 rounded-lg bg-[#fff4d6] px-3 py-2 text-sm text-[#5c4300]">
          Your roles grant no control-panel permission. Ask an admin to change your roles.
        </p>
      ) : null}

      <main className="p-5" id="admin-tabpanel" role={tab ? 'tabpanel' : undefined} aria-labelledby={tab ? `tab-${tab}` : undefined}>
        {tab === 'users' ? (
          <div className="grid gap-4 2xl:grid-cols-[minmax(0,1fr)_26rem]">
            <UsersAccessPanel token={token} />
            {canAny([PERM.enrolWrite, PERM.enrolErase]) ? <EnrolPanel token={token} /> : <NeedsCard title="Quick enrol" perm={PERM.enrolWrite} />}
          </div>
        ) : null}
        {tab === 'system' ? (
          <div className="grid gap-4 xl:grid-cols-[26rem_minmax(0,1fr)]">
            <div className="flex flex-col gap-4">
              <ControlPanel token={token} detail={detail.data} />
              {MOCK_ENABLED ? <MockControls /> : null}
            </div>
            <div className="flex min-w-0 flex-col gap-4">
              <SystemStatusPanel token={token} detail={detail.data} />
              {can(PERM.eventsRead) ? <LiveFeed key={token} token={token} /> : <NeedsCard title="Live decision feed" perm={PERM.eventsRead} />}
              {can(PERM.storeRead) ? <StoreViewer body={store.data} error={store.error} onRefresh={store.refresh} /> : <NeedsCard title="Offline store" perm={PERM.storeRead} />}
            </div>
          </div>
        ) : null}
        {tab === 'codes' ? (
          <div className="max-w-4xl">
            <StaffCodesPanel key={token} token={token} />
          </div>
        ) : null}
        {tab === 'eval' ? (
          <div className="grid gap-4 xl:grid-cols-[24rem_minmax(0,1fr)]">
            <EvalContextPanel token={token} />
            {can(PERM.metricsRead) ? <MetricsPanel metrics={metrics.data} error={metrics.error} /> : <NeedsCard title="Metrics" perm={PERM.metricsRead} />}
          </div>
        ) : null}
        {tab === 'staff' ? (
          <div className="max-w-6xl">
            <StaffPanel key={token} />
          </div>
        ) : null}
        {tab === 'audit' ? <AuditLogPanel key={token} /> : null}
      </main>
    </div>
  )
}
