/** Mode (SC2), sync, demo clock (SC1), random challenge (§3.14a) and the kiosk selector. */
import { useEffect, useRef, useState, useSyncExternalStore } from 'react'
import { RANDOM_CHALLENGE_MODES, getApi, type RandomChallengeMode } from '../../api'
import { DEFAULT_KIOSK_ID, KIOSK_IDS, STORAGE_KEYS, getKioskId, kioskIdSource, writeLocal } from '../../config'
import { errorText } from '../../shared/accessDirectory'
import { HHMM_WRITE, defaultDemoTime, isRollbackTime } from '../../shared/accessRules'
import { ModeBadge } from '../../shared/ModeBadge'
import { refreshMode, useModeStatus } from '../../shared/modeStore'
import { toast } from '../../shared/toast'
import { fmtTime } from '../format'
import { ActionButton, Card, KeyVal } from '../ui'

const RANDOM_HELP: Record<RandomChallengeMode, string> = {
  AUTO: 'configured challenge.random_rate (0.15 online / 0.30 offline)',
  FORCE_NEXT: 'the next would-be ALLOW gets a challenge, then back to AUTO',
  FORCE: 'every would-be ALLOW gets a challenge',
  OFF: 'never (eval profile)',
}

function subscribeStorage(cb: () => void) {
  window.addEventListener('storage', cb)
  window.addEventListener('hid-kiosk-id', cb)
  return () => {
    window.removeEventListener('storage', cb)
    window.removeEventListener('hid-kiosk-id', cb)
  }
}

export function ControlPanel({ token }: { token: string }) {
  const api = getApi()
  const { mode, reachable, error } = useModeStatus()
  const kioskId = useSyncExternalStore(subscribeStorage, getKioskId)
  const dc = mode?.demo_clock ?? null
  // R-E: default = max(now_local, earliest_local) of the edge's demo clock (never a rollback by default)
  const suggested = dc ? defaultDemoTime(dc) : null
  const [clock, setClock] = useState('')
  const touched = useRef(false)
  useEffect(() => {
    if (!touched.current && suggested) setClock(suggested)
  }, [suggested])
  const after = async <T,>(p: Promise<T>, okText?: string) => {
    try {
      const r = await p
      if (okText) toast.success(okText)
      return r
    } catch (e) {
      toast.error(errorText(e))
      throw e
    } finally {
      refreshMode()
    }
  }
  const served = mode?.kiosk_id ?? null
  const kioskOptions = [...new Set([...(served ? [served] : []), kioskId, ...KIOSK_IDS])]
  const earliest = dc?.earliest_local ?? null
  const earliestText = earliest ? `${earliest}${dc?.earliest_date_local && dc.date_local && dc.earliest_date_local !== dc.date_local ? ` on ${dc.earliest_date_local}` : ''}` : null
  const rollbackNow = dc?.active === true && dc.bundle_rollback
  const clockOk = HHMM_WRITE.test(clock)
  const clockUnsafe = !!dc && clockOk && isRollbackTime(clock, dc)
  const demoMode = dc !== null
  const ROLLBACK_EFFECT =
    'the schedule bundle counts as INVALID (rollback guard), so every attempt becomes STEP_UP with SCHEDULE_BUNDLE_INVALID: the person needs a staff override code (never DENY, never automatic ALLOW)'

  return (
    <Card title="Mode · sync · demo controls">
      <div className="mb-3">
        <ModeBadge size="sm" showBundle />
      </div>
      {!reachable ? <p className="mb-2 text-sm text-[#d03b3b]">Edge unreachable: {error}</p> : null}
      <div className="mb-3">
        <KeyVal k="State" v={mode ? `${mode.state}${mode.forced ? ' (forced)' : ''}` : '–'} />
        <KeyVal k="Since" v={fmtTime(mode?.since)} />
        <KeyVal k="Reason" v={mode?.reason ?? '–'} />
        <KeyVal k="Last cloud OK" v={fmtTime(mode?.last_cloud_ok_at)} />
        <KeyVal k="Sync queue depth" v={<span className="tabular-nums">{mode?.sync_queue_depth ?? '–'}</span>} />
        <KeyVal k="Revocation seq" v={mode?.revocation_seq ?? '–'} />
        <KeyVal
          k="Template cache"
          v={mode?.template_cache ? [mode.template_cache.count ?? '?', mode.template_cache.model].filter((x) => x !== null).join(' · ') : '–'}
        />
        <KeyVal k="Demo clock" v={mode?.demo_clock?.active ? `ACTIVE ${mode.demo_clock.now_local ?? ''}` : 'real time'} />
      </div>

      <p className="mb-2 text-xs font-bold tracking-wide text-[#52514e] uppercase">Connectivity (SC2)</p>
      <div className="flex flex-wrap items-start gap-2">
        <ActionButton label="Force OFFLINE" tone="danger" disabled={!token} run={() => after(api.setMode(token, 'OFFLINE'), 'Forced OFFLINE')} />
        <ActionButton label="AUTO (reconnect)" tone="primary" disabled={!token} run={() => after(api.setMode(token, 'AUTO'), 'Mode AUTO: reconnecting')} />
        <ActionButton label="Sync now" disabled={!token} run={() => after(api.triggerSync(token), 'Sync done')} />
      </div>

      <div className="mt-4 border-t border-[#e1e0d9] pt-3">
        <p className="mb-2 text-xs font-bold tracking-wide text-[#52514e] uppercase">Demo clock (Asia/Kolkata, DEMO_MODE=1)</p>
        {!demoMode ? (
          <p className="mb-2 text-sm text-[#52514e]">The edge does not run with DEMO_MODE=1: the demo clock is not available (real time only).</p>
        ) : (
          <p className="mb-2 text-sm text-[#52514e]">
            Edge time {dc.now_local ?? '–'}
            {dc.date_local ? ` · ${dc.date_local}` : ''} · {dc.active ? <b className="text-[#5b21b6]">DEMO CLOCK active</b> : 'real time'}
            {dc.cache_state ? ` · bundle ${dc.cache_state}` : ''}
            {earliestText ? ` · earliest safe time ${earliestText}` : ''}
          </p>
        )}
        {rollbackNow ? (
          <p className="mb-2 rounded-lg bg-[#fff4d6] px-3 py-2 text-sm font-semibold text-[#5c4300] ring-1 ring-[#f2a900]">
            The demo clock ({dc.now_local}) is before the bundle’s earliest accepted time{earliestText ? ` (${earliestText})` : ''}: {ROLLBACK_EFFECT}. Set
            {earliest ? ` ${earliest} or later` : ' a later time'}, or reset to real time.
          </p>
        ) : null}
        <div className="flex flex-wrap items-start gap-2">
          <input
            type="time"
            value={clock}
            disabled={!demoMode}
            onChange={(e) => {
              touched.current = true
              setClock(e.target.value)
            }}
            className={`rounded-lg border bg-white px-2 py-1 text-sm disabled:bg-[#f0efec] ${clockUnsafe ? 'border-[#f2a900] ring-2 ring-[#f2a900]/40' : 'border-black/20'}`}
            aria-label="Demo clock time (HH:MM)"
          />
          <ActionButton
            label="Set clock"
            tone="primary"
            disabled={!token || !clockOk || !demoMode}
            run={() => {
              if (
                clockUnsafe &&
                !window.confirm(
                  `${clock} is before the earliest time this schedule bundle accepts (${earliestText ?? 'bundle issued_at − 5 min'}). If you set it, ${ROLLBACK_EFFECT}.\n\nSet ${clock} anyway?`,
                )
              ) {
                return Promise.resolve('cancelled')
              }
              return after(api.setDemoClock(token, { set_local: clock }), `Demo clock set to ${clock}`).then((r) => {
                touched.current = false
                return `now ${r.now_local}${r.bundle_rollback ? ' · bundle INVALID (rollback): STEP_UP SCHEDULE_BUNDLE_INVALID' : ''}`
              })
            }}
          />
          <ActionButton
            label="Reset to real time"
            disabled={!token || !demoMode}
            run={() =>
              after(api.setDemoClock(token, { reset: true }), 'Demo clock reset to real time').then((r) => {
                touched.current = false
                return `real time ${r.now_local}`
              })
            }
          />
          {suggested && suggested !== clock ? (
            <button
              type="button"
              className="self-center text-xs text-[#2a78d6] underline"
              onClick={() => {
                touched.current = false
                setClock(suggested)
              }}
            >
              use {suggested}
            </button>
          ) : null}
        </div>
        <p className={`mt-1 text-xs ${clockUnsafe ? 'font-semibold text-[#8a5a00]' : 'text-[#898781]'}`}>
          {clockUnsafe
            ? `${clock} is before ${earliestText}: ${ROLLBACK_EFFECT}.`
            : `Rollback guard: a time before the bundle's issued_at − 5 min${earliestText ? ` (${earliestText})` : ''} makes the bundle INVALID (STEP_UP SCHEDULE_BUNDLE_INVALID with a staff override). Every schedule change re-signs the bundle and moves this limit to “now − 5 min”, so make access changes before an “outside hours” demo.`}
        </p>
      </div>

      <div className="mt-4 border-t border-[#e1e0d9] pt-3">
        <p className="mb-2 text-xs font-bold tracking-wide text-[#52514e] uppercase">
          Random liveness challenge · now <span className="font-mono">{mode?.random_challenge ?? '?'}</span>
        </p>
        <div className="flex flex-wrap items-start gap-2">
          {RANDOM_CHALLENGE_MODES.map((m) => (
            <ActionButton
              key={m}
              label={m}
              disabled={!token}
              tone={mode?.random_challenge === m ? 'primary' : 'default'}
              run={() => after(api.setRandomChallenge(token, m), `Random challenge: ${m}`)}
            />
          ))}
        </div>
        <p className="mt-1 text-xs text-[#898781]">
          {mode?.random_challenge ? `${mode.random_challenge}: ${RANDOM_HELP[mode.random_challenge]}. ` : ''}Only a would-be ALLOW is ever converted
          (DEMO_MODE=1).
        </p>
      </div>

      <div className="mt-4 border-t border-[#e1e0d9] pt-3">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-xs font-bold tracking-wide text-[#52514e] uppercase">Kiosk id (session/start)</span>
          <select
            value={kioskId}
            onChange={(e) => {
              writeLocal(STORAGE_KEYS.kioskId, e.target.value === DEFAULT_KIOSK_ID ? null : e.target.value)
              window.dispatchEvent(new Event('hid-kiosk-id'))
            }}
            className="w-full rounded-lg border border-black/20 bg-white px-2 py-1 font-mono text-sm"
          >
            {kioskOptions.map((k) => (
              <option key={k} value={k} disabled={served !== null && k !== served && k !== kioskId}>
                {k}
                {served !== null && k !== served ? ' (not served by this edge)' : ''}
              </option>
            ))}
          </select>
        </label>
        {served !== null && kioskId !== served ? (
          <p className="mt-1 rounded-lg bg-[#fde2e1] px-2 py-1 text-xs text-[#8f1d1d]">
            This browser uses {kioskId}
            {kioskIdSource() === 'query' ? ' (from ?kiosk= in the address)' : ''}, but the edge serves only {served}: every attempt would be refused.{' '}
            <button
              type="button"
              className="font-semibold underline"
              onClick={() => {
                writeLocal(STORAGE_KEYS.kioskId, served === DEFAULT_KIOSK_ID ? null : served)
                window.dispatchEvent(new Event('hid-kiosk-id'))
              }}
            >
              Use {served}
            </button>
          </p>
        ) : (
          <p className="mt-1 text-xs text-[#898781]">
            The edge evaluates attempts only for its own kiosk ({served ?? 'unknown until /v1/mode answers'}). Another gate needs an edge restarted with
            that KIOSK_ID.
          </p>
        )}
      </div>
    </Card>
  )
}
