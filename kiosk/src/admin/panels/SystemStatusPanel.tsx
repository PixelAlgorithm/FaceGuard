/**
 * Live system status from GET /v1/mode (2 s store) + GET /v1/health: kiosk / zone / policy, rate-limit lock,
 * enforcement switches (policy_bars), cloud match, schedule bundle, last sync report, models / self-test /
 * depth probe and the health degraded_reasons. Read-only except the rate-limit reset.
 */
import { getApi, type HealthResponse, type ModeResponse } from '../../api'
import { refreshMode, useModeStatus } from '../../shared/modeStore'
import { fmtTime } from '../format'
import { usePoll } from '../usePoll'
import { PERM } from '../../shared/auth/permissions'
import { ActionButton, Card, KeyVal } from '../ui'

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v)

/** Switches whose value decides whether a check is ENFORCED or only advisory. */
const ENFORCE_KEYS = ['moire_enforce', 'm2_rgb_enforce', 'flash_enforce', 'rekognition', 'ambient_exception']

function Pill({ on, onText = 'on', offText = 'off', warnOff = false }: { on: boolean; onText?: string; offText?: string; warnOff?: boolean }) {
  return (
    <span
      className={`rounded-full px-2 py-0.5 text-xs font-bold ${on ? 'bg-[#e3f4e3] text-[#0f5132]' : warnOff ? 'bg-[#fff4d6] text-[#5c4300]' : 'bg-[#f0efec] text-[#52514e]'}`}
    >
      {on ? onText : offText}
    </span>
  )
}

function bar(v: number | boolean | string | null): string {
  if (v === null) return '–'
  if (typeof v === 'number') return Number.isInteger(v) ? String(v) : v.toFixed(2)
  return String(v)
}

/** `detail`: GET /v1/admin/mode/detail (store:read); without it only the public /v1/mode subset is shown. */
export function SystemStatusPanel({ token, detail: modeDetail = null }: { token: string; detail?: ModeResponse | null }) {
  const api = getApi()
  const { mode: publicMode, reachable, error, updatedAt } = useModeStatus()
  const mode = modeDetail ?? publicMode
  const health = usePoll<HealthResponse>(() => api.getHealth(), 5000, true, 'status-health')
  const h = health.data
  const detail = h && isObj(h.detail) ? h.detail : {}
  const degraded = Array.isArray(h?.degraded_reasons) ? (h.degraded_reasons as unknown[]).filter((x): x is string => typeof x === 'string') : []
  const models = h && isObj(h.models_loaded) ? h.models_loaded : null
  const selfTest = h && isObj(h.self_test) ? h.self_test : null
  const bars = mode?.policy_bars ?? null
  const report = mode?.last_sync?.report ?? null
  const rl = mode?.rate_limit ?? null

  return (
    <Card
      title="System status"
      actions={<span className="text-xs text-[#898781]">{reachable ? `mode ${fmtTime(new Date(updatedAt).toISOString())}` : 'edge unreachable'}</span>}
    >
      {!reachable ? <p className="mb-2 rounded-lg bg-[#fde2e1] px-3 py-2 text-sm text-[#8f1d1d]">Edge unreachable: {error}</p> : null}
      {h ? (
        <div className={`mb-3 rounded-lg px-3 py-2 text-sm ${h.status === 'ok' ? 'bg-[#e3f4e3] text-[#0f5132]' : 'bg-[#fde2e1] text-[#8f1d1d]'}`}>
          <b>Health: {String(h.status)}</b>
          {h.version ? ` · edge v${String(h.version)}` : ''}
          {typeof h.uptime_s === 'number' ? ` · up ${Math.round(h.uptime_s / 60)} min` : ''}
          {degraded.length ? (
            <ul className="mt-1 list-disc pl-5">
              {degraded.map((d) => (
                <li key={d}>{d}</li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : health.error ? (
        <p className="mb-3 text-sm text-[#d03b3b]">Health: {health.error}</p>
      ) : null}

      <div className="grid gap-x-6 md:grid-cols-2">
        <div>
          <KeyVal k="Kiosk served by this edge" v={mode?.kiosk_id ?? '–'} mono />
          <KeyVal k="Zone" v={mode?.zone ?? '–'} mono />
          <KeyVal k="Policy version" v={mode?.policy_version ?? '–'} mono />
          <KeyVal
            k="Schedule bundle"
            v={
              mode?.schedule_bundle
                ? `v${String(mode.schedule_bundle.version ?? '?')} · ${mode.schedule_bundle.cache_state ?? '?'} · sig ${mode.schedule_bundle.signature_valid === null ? '?' : mode.schedule_bundle.signature_valid ? 'valid' : 'INVALID'}`
                : '–'
            }
          />
          <KeyVal k="Bundle issued / expires" v={`${fmtTime(mode?.schedule_bundle?.issued_at)} / ${fmtTime(mode?.schedule_bundle?.expires_at)}`} />
          <KeyVal
            k="Cloud match"
            v={
              mode?.cloud_match
                ? `${mode.cloud_match.degraded ? 'DEGRADED (deciding locally)' : 'ok'} · misses ${mode.cloud_match.misses ?? '?'}/${mode.cloud_match.recent ?? '?'}`
                : '–'
            }
          />
          <KeyVal
            k="Rate limit"
            v={
              rl ? (
                <span className="inline-flex items-center gap-2">
                  {rl.locked ? <span className="font-bold text-[#d03b3b]">LOCKED{rl.retry_after_s !== null ? ` ${rl.retry_after_s} s` : ''}</span> : 'not locked'}
                  {rl.enabled === false ? ' (disabled)' : ''}
                </span>
              ) : (
                '–'
              )
            }
          />
          <div className="mt-2">
            <ActionButton
              label="Reset rate limit"
              perm={PERM.rateLimitReset}
              disabled={!token}
              run={async () => {
                const r = await api.resetRateLimit(token)
                refreshMode()
                return r
              }}
            />
          </div>
        </div>
        <div>
          <KeyVal
            k="Models"
            v={
              models
                ? Object.entries(models)
                    .map(([k, v]) => `${k} ${v === true ? 'ok' : 'MISSING'}`)
                    .join(' · ')
                : '–'
            }
          />
          <KeyVal
            k="PAD self-test"
            v={selfTest ? (selfTest.passed === true || selfTest.ok === true ? <Pill on onText="passed" /> : <Pill on={false} offText="FAILED" warnOff />) : '–'}
          />
          <KeyVal k="Depth probe (iPhone)" v={typeof h?.depth_probe === 'string' ? h.depth_probe : '–'} />
          <KeyVal k="Demo mode" v={typeof detail.demo_mode === 'boolean' ? (detail.demo_mode ? 'DEMO_MODE=1' : 'off') : '–'} />
          <KeyVal k="Server flags" v={mode?.server_flags?.length ? mode.server_flags.join(', ') : 'none'} />
          <KeyVal
            k="Last sync"
            v={
              mode?.last_sync?.at
                ? `${fmtTime(mode.last_sync.at)}${report ? ` · ${report.ok === false ? 'FAILED' : 'ok'} · sent ${String(report.sent ?? '?')} · accepted ${String(report.accepted ?? '?')} · dup ${String(report.duplicates ?? '?')} · rejected ${String(report.rejected ?? '?')} · bundle ${String(report.bundle ?? '?')}` : ''}`
                : '–'
            }
          />
          {report && typeof report.error === 'string' && report.error ? <p className="text-xs text-[#d03b3b]">sync error: {report.error}</p> : null}
        </div>
      </div>

      {bars ? (
        <div className="mt-4 border-t border-[#e1e0d9] pt-3">
          <p className="mb-2 text-xs font-bold tracking-wide text-[#52514e] uppercase">Policy bars and enforcement switches (from the edge)</p>
          <div className="mb-2 flex flex-wrap gap-2">
            {ENFORCE_KEYS.filter((k) => k in bars).map((k) => (
              <span key={k} className="inline-flex items-center gap-1.5 rounded-lg bg-white px-2 py-1 text-xs ring-1 ring-black/10">
                <span className="font-mono">{k}</span>
                <Pill on={bars[k] === true} onText={k.endsWith('_enforce') ? 'ENFORCED' : 'on'} offText={k.endsWith('_enforce') ? 'advisory' : 'off'} warnOff={k !== 'flash_enforce'} />
              </span>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-x-6 md:grid-cols-3">
            {Object.entries(bars)
              .filter(([k]) => !ENFORCE_KEYS.includes(k))
              .map(([k, v]) => (
                <KeyVal key={k} k={k} v={bar(v)} mono />
              ))}
          </div>
          <p className="mt-1 text-xs text-[#898781]">The colour flash is advisory by design until the kiosk frame timing is re-validated.</p>
        </div>
      ) : null}
    </Card>
  )
}
