/**
 * /register: consent -> details -> quality-gated capture (5 frames, slight pose variation, chosen camera)
 * -> R-A flow (shared/registerFlow.ts): a new person / role or name change / ERASED person (R-B "Re-admit
 * and enrol") is first written to the SIGNED SCHEDULE (PUT /v1/admin/access/users/{id} {display, role,
 * consent: true}, ONLINE only; the edge installs the re-signed bundle), THEN POST /v1/enroll -> result with
 * the role from the schedule, cloud_state / warnings (R-F) and the TOTP QR only when it is active.
 * Offline, only people already in the installed bundle can enrol. Right column: enrolled users
 * (GET /v1/admin/users) with DPDP erasure (DELETE /v1/enroll/{user_id}; cloud deleted | queued).
 * The camera starts only after consent and takes the one-capturing-tab lock.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import QRCode from 'qrcode'
import { getApi } from '../api'
import { type EnrolledUser, type EraseResponse, type HealthResponse } from '../api/types'
import type { FrameAnalysis } from '../capture/engine'
import { canvasToJpeg } from '../capture/imageStats'
import { GUIDANCE_TEXT, assessQuality, type Guidance } from '../capture/quality'
import { sleep } from '../capture/time'
import { EDGE_URL, MOCK_ENABLED, UI, getAdminToken, setAdminToken } from '../config'
import { usePoll } from '../admin/usePoll'
import { ERASE_CLOUD_TEXT, REASON_HINT, ROLE_SOURCE_TEXT, errorText, useAccessDirectory, type Identity } from '../shared/accessDirectory'
import { displayError, registerPlan } from '../shared/accessRules'
import { CaptureLock, useLockState } from '../shared/captureLock'
import { toast } from '../shared/toast'
import { USER_ID_HINT, USER_ID_RE } from '../shared/userId'
import { CONSENT_VERSION, registerPerson, type RegisterOutcome } from '../shared/registerFlow'
import { readPreferredCamera, useVideoDevices, writePreferredCamera } from './devices'
import { useOperatorEngine } from './opEngine'
import { Btn, CameraPicker, OpHeader, Preview, inputCls } from './ui'

const PROMPTS = [
  'Look straight at the camera',
  'Turn slightly to your left',
  'Turn slightly to your right',
  'Lift your chin slightly',
  'Look straight again',
]
/** Per shot: let the pose settle, then wait up to this long for the quality gate before taking it anyway. */
const SETTLE_MS = 700
const QUALITY_WAIT_MS = 3500

type Step = 'consent' | 'details' | 'capture' | 'submitting' | 'done'

interface Shot {
  blob: Blob
  url: string
  /** the client quality gate was OK when the frame was taken */
  ok: boolean
  prompt: string
}

interface Form {
  user_id: string
  display_name: string
  /** role to set in the signed schedule; null = keep the schedule role */
  role: string | null
  email: string
  card_id: string
  provision_totp: boolean
}

const EMPTY_FORM: Form = { user_id: '', display_name: '', role: null, email: '', card_id: '', provision_totp: false }

/** A new authenticator secret by default only for a person who has none on this edge yet. */
function defaultProvisionTotp(u: Identity | null): boolean {
  if (!u) return true
  return !u.enrolled && !u.totp && u.user_id !== 'u_prj1'
}

const NOTE_CLS = { ok: 'bg-emerald-500/15 text-emerald-100', warn: 'bg-amber-500/20 text-amber-50', block: 'bg-red-600/40 text-white font-semibold ring-2 ring-red-300' }

function eraseText(r: EraseResponse): string {
  const cloud = ERASE_CLOUD_TEXT[r.cloud]
  return `Erased ${r.user_id}: local data ${r.local_removed ? 'removed' : 'was not on this edge'} · ${cloud}${r.message ? ` (${r.message})` : ''}. To register this person again, use “Re-admit and enrol” (needs fresh consent, ONLINE).`
}

/** Edge frames_rejected item {frame, reasons[], p_live} (edge/enroll.py) -> "frame 3: PAD_BELOW_PASS (p_live 0.41)". */
function rejectedText(r: Record<string, unknown>): string {
  const reasons = Array.isArray(r.reasons) ? r.reasons.filter((x) => typeof x === 'string').join(', ') : ''
  if (typeof r.frame !== 'number' || !reasons) return JSON.stringify(r)
  return `frame ${r.frame + 1}: ${reasons}${typeof r.p_live === 'number' ? ` (p_live ${r.p_live.toFixed(2)})` : ''}`
}

function healthLine(h: HealthResponse | null, error: string | null): { text: string; ok: boolean } {
  if (error && !h) return { text: `Edge not reachable (${error})`, ok: false }
  if (!h) return { text: 'Checking edge…', ok: true }
  const st = h.self_test as { passed?: boolean } | undefined
  if (st && st.passed === false) return { text: 'Edge PAD self-test FAILED: enrolment will be refused', ok: false }
  return { text: `Edge ${String(h.status)}${h.version ? ` v${String(h.version)}` : ''}`, ok: h.status === 'ok' }
}

export default function RegisterApp() {
  const api = getApi()
  const [step, setStep] = useState<Step>('consent')
  const [consent, setConsent] = useState(false)
  const [declined, setDeclined] = useState(false)
  const [token, setToken] = useState(getAdminToken)
  const [form, setForm] = useState<Form>(EMPTY_FORM)
  /** display name last filled in from the schedule (cleared again when the id changes to an unknown one) */
  const autoName = useRef('')
  const [outcome, setOutcome] = useState<RegisterOutcome | null>(null)
  const [shots, setShots] = useState<Shot[]>([])
  const [prompt, setPrompt] = useState<string | null>(null)
  const [capturing, setCapturing] = useState(false)
  /** the person was already enrolled when Register was pressed (the edge appended a look) */
  const [addedLook, setAddedLook] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [qr, setQr] = useState<string | null>(null)
  const [listMsg, setListMsg] = useState<string | null>(null)
  const [guidance, setGuidance] = useState<Guidance>('NO_FACE')

  const health = usePoll<HealthResponse>(() => api.getHealth(), 10000, true, 'register-health')
  // Signed-schedule users (role source of truth) + this edge's enrolments.
  const dir = useAccessDirectory(token, 'register')
  const users: EnrolledUser[] = useMemo(() => dir.enrolled?.users ?? [], [dir.enrolled])
  const identities = dir.identities

  /**
   * Every user-id change (picked OR typed): name and role come from the schedule when the id is known; the
   * TOTP default is recomputed (never a silent new secret for an enrolled person); a name auto-filled for
   * the previous id is cleared for an unknown one.
   */
  const selectUser = (raw: string) => {
    const id = raw.trim().toLowerCase()
    const u = identities.find((x) => x.user_id === id) ?? null
    // Decide outside the state updater (StrictMode runs updaters twice; the ref must change once).
    let display = form.display_name
    if (u) {
      display = u.display
      autoName.current = u.display
    } else if (form.display_name === autoName.current) {
      display = ''
      autoName.current = ''
    }
    setForm({ ...form, user_id: id, display_name: display, role: null, provision_totp: defaultProvisionTotp(u) })
  }

  const setField = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => ({ ...f, [k]: v }))
  const idOk = USER_ID_RE.test(form.user_id)
  const nameErr = displayError(form.display_name)
  const nameOk = nameErr === null
  const existing = identities.find((x) => x.user_id === form.user_id) ?? null
  const known = existing !== null && existing.status !== 'NOT_IN_SCHEDULE' && existing.source !== 'demo-file'
  const scheduleRole: string | null = known ? existing.role : null
  /** role shown in the dropdown and written to the schedule BEFORE the enrolment when it differs */
  const role: string | null = form.role ?? scheduleRole ?? (dir.roles.includes('student') ? 'student' : (dir.roles[0] ?? null))
  const roleChange = known ? role !== scheduleRole : true
  const nameChange = known ? form.display_name.trim() !== existing.display : false
  const roleSource = existing ? ROLE_SOURCE_TEXT(existing.source, dir.bundleVersion) : ROLE_SOURCE_TEXT('schedule', dir.bundleVersion)
  const erased = existing?.status === 'ERASED'
  /** what Register will do (R-A / R-B); null while the schedule list is not loaded (the edge then decides) */
  const plan = dir.access && idOk ? registerPlan(existing?.row ?? null, dir.canEdit, role, form.display_name) : null
  const blocked = plan?.kind === 'blocked'
  const registerLabel = erased || outcome?.reason === 'ERASED_IN_BUNDLE' ? 'Re-admit and enrol' : 'Register'

  /** user id for which the operator already confirmed replacing the authenticator secret */
  const totpConfirmed = useRef<string | null>(null)
  const toggleTotp = (on: boolean) => {
    if (
      on &&
      (existing?.enrolled || existing?.totp) &&
      totpConfirmed.current !== form.user_id &&
      !window.confirm(
        `${form.user_id} is already enrolled. A new authenticator secret REPLACES the current one: the code in their authenticator app stops working. Create a new secret?`,
      )
    ) {
      return
    }
    if (on && (existing?.enrolled || existing?.totp)) totpConfirmed.current = form.user_id
    setField('provision_totp', on)
  }

  // ---------------------------------------------------------------- camera (capture + submitting steps)
  // The camera stays open while the edge decides (no black preview, instant Retake after a refusal) and
  // takes the one-capturing-tab lock over from the kiosk tab while open.
  const cameraWanted = step === 'capture' || step === 'submitting'
  const lock = useMemo(() => new CaptureLock('operator'), [])
  const lockState = useLockState(lock)
  useEffect(() => {
    if (cameraWanted) lock.enable(true)
    else lock.disable()
  }, [cameraWanted, lock])
  useEffect(() => () => lock.disable(), [lock])
  const devices = useVideoDevices()
  const [preferred, setPreferred] = useState<string | null>(readPreferredCamera)
  const [retryKey, setRetryKey] = useState(0)
  const eng = useOperatorEngine(preferred, cameraWanted && lockState === 'held', retryKey)
  const engine = eng.engine
  const activeId = engine ? (engine.track.getSettings().deviceId ?? null) : null
  const engineRef = useRef(engine)
  const qualityOk = useRef(false)
  const gen = useRef(0)
  /** bumped per submit and by "Register another person": a late schedule result never lands on a new form */
  const submitGen = useRef(0)
  const refreshDevices = devices.refresh
  useEffect(() => {
    engineRef.current = engine
    if (engine) void refreshDevices()
  }, [engine, refreshDevices])

  useEffect(() => {
    if (!engine) return
    let prev: FrameAnalysis | null = null
    let last: Guidance | null = null
    return engine.onFrame((f) => {
      const a = assessQuality(f, prev, UI.defaultUploadMaxWidth)
      prev = f
      qualityOk.current = a.ok
      if (a.guidance !== last) {
        last = a.guidance
        setGuidance(a.guidance)
      }
    })
  }, [engine])

  // Thumbnail object URLs: released when a new capture starts, on restart and on unmount (not on every
  // setShots: the growing array keeps re-using the URLs of the earlier shots).
  const shotUrls = useRef(new Set<string>())
  const releaseShots = useCallback(() => {
    shotUrls.current.forEach((u) => URL.revokeObjectURL(u))
    shotUrls.current.clear()
  }, [])
  useEffect(() => releaseShots, [releaseShots])

  const result = outcome?.enrol ?? null
  useEffect(() => {
    // the QR is offered only when the policy can actually use the secret (totp_active, R-F)
    const uri = result?.totp_active ? result.totp_provisioning_uri : null
    let cancelled = false
    if (uri) {
      QRCode.toDataURL(uri, { margin: 1, width: 200 })
        .then((u) => !cancelled && setQr(u))
        .catch(() => !cancelled && setQr(null))
    }
    return () => {
      cancelled = true
    }
  }, [result])

  const capture = useCallback(async () => {
    const e = engineRef.current
    if (!e) return
    const g = ++gen.current
    const alive = () => g === gen.current
    setCapturing(true)
    setSubmitError(null)
    setShots([])
    releaseShots()
    try {
      for (const n of [3, 2, 1]) {
        setPrompt(`Get ready… ${n}`)
        await sleep(700)
        if (!alive()) return
      }
      const out: Shot[] = []
      for (const p of PROMPTS) {
        setPrompt(p)
        await sleep(SETTLE_MS)
        const t0 = performance.now()
        while (!qualityOk.current && performance.now() - t0 < QUALITY_WAIT_MS) {
          await sleep(50)
          if (!alive()) return
        }
        const cur = engineRef.current
        if (!alive() || !cur) return
        const ok = qualityOk.current
        const blob = await canvasToJpeg(cur.grabFrame(UI.defaultUploadMaxWidth), 0.92) // unmirrored, <= 1280 px wide
        const url = URL.createObjectURL(blob)
        shotUrls.current.add(url)
        out.push({ blob, url, ok, prompt: p })
        setShots([...out])
      }
    } finally {
      if (alive()) {
        setPrompt(null)
        setCapturing(false)
      }
    }
  }, [releaseShots])

  const submit = async () => {
    if (
      form.provision_totp &&
      (existing?.enrolled || existing?.totp) &&
      totpConfirmed.current !== form.user_id &&
      !window.confirm(`This replaces ${form.user_id}'s authenticator code (new TOTP secret). Continue?`)
    ) {
      return
    }
    const forceReadmit = outcome?.reason === 'ERASED_IN_BUNDLE'
    const g = ++submitGen.current
    setAddedLook(existing?.enrolled ?? false)
    setStep('submitting')
    setSubmitError(null)
    setOutcome(null)
    const o = await registerPerson(
      token,
      existing,
      { online: dir.canEdit, listLoaded: !!dir.access },
      {
        userId: form.user_id,
        display: form.display_name,
        role,
        email: form.email,
        cardId: form.card_id,
        provisionTotp: form.provision_totp,
        frames: shots.map((s) => s.blob),
        actor: 'register',
        forceReadmit,
      },
    )
    if (g !== submitGen.current) return // "Register another person" meanwhile
    setOutcome(o)
    health.refresh()
    dir.refresh()
    if (o.ok) {
      setStep('done')
      if (o.notes.some((n) => n.tone === 'block')) toast.error(`${form.user_id} enrolled on this kiosk, but NOT indexed in the cloud`)
      else toast.success(`Registered ${form.user_id} · ${o.scheduleRole ?? 'no schedule role'}`)
    } else {
      console.warn('[register] not registered', o.stage, o.reason)
      setSubmitError(o.error)
      setStep('capture')
    }
  }

  const restart = () => {
    gen.current++
    submitGen.current++
    setStep('consent')
    setConsent(false)
    setDeclined(false)
    setShots([])
    releaseShots()
    setOutcome(null)
    setQr(null)
    setSubmitError(null)
    setPrompt(null)
    setCapturing(false)
    autoName.current = ''
    setForm(EMPTY_FORM)
  }

  const erase = async (u: EnrolledUser) => {
    if (!window.confirm(`Erase ${u.user_id} (${u.display_name})? This removes the face template, TOTP secret and card hash from this edge (DPDP erasure).`)) return
    setListMsg(null)
    try {
      const r = await api.deleteEnrollment(token, u.user_id)
      setListMsg(eraseText(r))
      if (r.cloud === 'failed') toast.error(`${r.user_id}: local erase done, cloud erasure could not be queued. Erase again while ONLINE.`)
    } catch (e) {
      setListMsg(`Erase failed: ${errorText(e)}`)
    }
    dir.refresh()
    health.refresh()
  }

  const hl = healthLine(health.data, health.error)
  const goodShots = shots.filter((s) => s.ok).length
  const secret = result?.totp_active && result.totp_provisioning_uri ? (/[?&]secret=([^&]+)/.exec(result.totp_provisioning_uri)?.[1] ?? null) : null
  const rejected = result?.frames_rejected ?? []

  return (
    <div className="min-h-full bg-kiosk font-sans text-white">
      <OpHeader title="Register a person" current="/register" />
      <main className="grid gap-5 p-5 xl:grid-cols-[minmax(0,7fr)_minmax(0,4fr)]">
        <section className="flex min-w-0 flex-col gap-4" aria-label="Registration">
          <div className="flex flex-wrap items-end gap-3 rounded-xl bg-white/5 p-3">
            <label className="flex min-w-60 flex-1 flex-col gap-1">
              <span className="text-xs text-white/60">Admin token (X-Admin-Token, ADMIN_TOKEN in the project .env)</span>
              <input
                className={inputCls}
                type="password"
                autoComplete="off"
                placeholder="paste admin token"
                value={token}
                onChange={(e) => {
                  setToken(e.target.value.trim())
                  setAdminToken(e.target.value.trim())
                }}
              />
            </label>
            <p className={`text-sm ${hl.ok ? 'text-white/70' : 'text-red-300'}`}>
              {hl.text} · {MOCK_ENABLED ? 'mock edge' : EDGE_URL}
            </p>
          </div>

          <ol className="flex flex-wrap gap-2 text-sm" aria-label="Steps">
            {(['consent', 'details', 'capture', 'done'] as const).map((s, i) => {
              const order = ['consent', 'details', 'capture', 'done']
              const cur = order.indexOf(step === 'submitting' ? 'capture' : step)
              return (
                <li
                  key={s}
                  className={`rounded-full px-3 py-1 font-semibold ${i === cur ? 'bg-white text-black' : i < cur ? 'bg-white/20' : 'bg-white/5 text-white/50'}`}
                >
                  {i + 1}. {s === 'done' ? 'Result' : s[0].toUpperCase() + s.slice(1)}
                </li>
              )
            })}
          </ol>

          {step === 'consent' ? (
            <div className="rounded-2xl bg-white/5 p-6">
              <h1 className="text-[clamp(1.6rem,3vw,2.4rem)] font-black">Register for face access</h1>
              {declined ? (
                <p className="mt-4 rounded-xl bg-white/10 p-4 text-lg">
                  No problem: nothing was captured or stored. You can still enter with a card, a code or help from the desk.
                </p>
              ) : null}
              <ul className="mt-4 flex list-disc flex-col gap-2 pl-6 text-lg leading-snug text-white/90">
                <li>
                  We take 5 camera frames and turn them into a <b>face template</b> (a list of numbers), not a photo album. No photos are kept on
                  this kiosk.
                </li>
                <li>
                  The template is stored <b>encrypted</b> on this kiosk laptop and, when online, on the hackathon AWS account, only for campus access
                  control during this event.
                </li>
                <li>
                  It is <b>deleted after the event</b>, or earlier whenever you ask (the operator erases it on this page).
                </li>
                <li>Saying no is fine: nothing is captured, and you can use a card, a code or the desk instead.</li>
              </ul>
              <p className="mt-3 text-sm text-white/60">India DPDP Act 2023: purpose and storage limitation, right to erasure. Consent version {CONSENT_VERSION}.</p>
              <label className="mt-5 flex items-start gap-3 text-lg">
                <input type="checkbox" className="mt-1.5 h-5 w-5" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
                <span>I have read this and I agree to register my face for campus access.</span>
              </label>
              <div className="mt-5 flex flex-wrap gap-3">
                <Btn
                  big
                  tone="primary"
                  disabled={!consent}
                  onClick={() => {
                    setDeclined(false)
                    setStep('details')
                  }}
                >
                  I agree, continue
                </Btn>
                <Btn
                  big
                  tone="ghost"
                  onClick={() => {
                    setConsent(false)
                    setDeclined(true)
                  }}
                >
                  I do not agree
                </Btn>
              </div>
            </div>
          ) : null}

          {step === 'details' ? (
            <div className="grid gap-3 rounded-2xl bg-white/5 p-6 md:grid-cols-2">
              <label className="flex flex-col gap-1 md:col-span-2">
                <span className="text-xs text-white/60">
                  Person (users of the {dir.access ? ROLE_SOURCE_TEXT('schedule', dir.bundleVersion) : ROLE_SOURCE_TEXT('demo-file', null)} and users
                  enrolled on this edge)
                </span>
                <select
                  className={inputCls}
                  value={identities.some((x) => x.user_id === form.user_id) ? form.user_id : ''}
                  onChange={(e) => selectUser(e.target.value)}
                >
                  <option value="">Type a user id below…</option>
                  {identities.map((u) => (
                    <option key={u.user_id} value={u.user_id}>
                      {u.user_id} · {u.display} · {u.role ?? 'not in schedule'}
                      {u.template_role && u.template_role !== u.role ? ` (enrolled as ${u.template_role})` : ''}
                      {u.enrolled ? ' · enrolled' : ''}
                    </option>
                  ))}
                </select>
                {!token ? (
                  <span className="text-xs text-amber-200">Enter the admin token above to load the signed schedule (roles shown now come from the demo source file).</span>
                ) : dir.accessError && !dir.access ? (
                  <span className="text-xs text-amber-200">Signed schedule list not available ({dir.accessError}); roles shown come from the demo source file.</span>
                ) : null}
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-xs text-white/60">User id (u_ + 4 lowercase letters/digits)</span>
                <input
                  className={`${inputCls} font-mono ${form.user_id && !idOk ? 'border-red-400' : ''}`}
                  value={form.user_id}
                  placeholder="u_prj1"
                  list="register-known-ids"
                  onChange={(e) => selectUser(e.target.value)}
                />
                <datalist id="register-known-ids">
                  {identities.map((u) => (
                    <option key={u.user_id} value={u.user_id} />
                  ))}
                </datalist>
                {form.user_id && !idOk ? <span className="text-xs text-red-300">{USER_ID_HINT}</span> : null}
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-xs text-white/60">Display name (shown on ALLOW, 1–80 characters)</span>
                <input className={inputCls} value={form.display_name} maxLength={80} onChange={(e) => setField('display_name', e.target.value)} />
                {form.display_name && nameErr ? <span className="text-xs text-red-300">{nameErr}</span> : null}
                {nameChange && dir.canEdit ? <span className="text-xs text-white/55">Differs from the schedule ({existing?.display}): it is updated there first.</span> : null}
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-xs text-white/60">Role in the campus schedule (decides access hours)</span>
                <select className={inputCls} value={role ?? ''} disabled={!dir.canEdit} onChange={(e) => setField('role', e.target.value || null)}>
                  {(dir.canEdit && dir.roles.length ? dir.roles : role ? [role] : []).map((r) => (
                    <option key={r} value={r}>
                      {r}
                      {r === scheduleRole ? ' (current)' : ''}
                    </option>
                  ))}
                </select>
                <span className="text-xs text-white/55">
                  {scheduleRole
                    ? `Current role: ${scheduleRole} (${roleSource}).`
                    : idOk
                      ? `${form.user_id} is not in the signed schedule yet.`
                      : 'The role comes from the signed campus schedule.'}
                  {existing?.template_role && existing.template_role !== scheduleRole ? ` Face template stored as ${existing.template_role} (informational).` : ''}
                  {dir.canEdit
                    ? roleChange && role
                      ? ` Register first sets ${form.user_id || 'the person'} to ${role} in the signed schedule, then enrols the face.`
                      : ''
                    : ` ${dir.editBlockedReason ?? ''} The role can't change until then.`}
                </span>
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-xs text-white/60">Email for one-time codes (optional)</span>
                <input className={inputCls} type="email" value={form.email} onChange={(e) => setField('email', e.target.value)} />
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-xs text-white/60">HID card id, simulated (optional; stored only as a keyed hash)</span>
                <input className={inputCls} value={form.card_id} placeholder="HID-DEMO-0001" onChange={(e) => setField('card_id', e.target.value)} />
              </label>
              <label className="flex items-start gap-2 pt-5 text-sm">
                <input type="checkbox" className="mt-1" checked={form.provision_totp} onChange={(e) => toggleTotp(e.target.checked)} />
                <span>
                  Create a new authenticator (TOTP) secret
                  <span className="block text-xs text-white/55">
                    {existing?.enrolled || existing?.totp
                      ? 'Off by default: this person is already enrolled, and a new secret replaces their current authenticator code.'
                      : 'Leave off if this person already has one (e.g. u_prj1 from the demo bundle): a new secret replaces the old one.'}
                  </span>
                </span>
              </label>
              {existing?.enrolled ? (
                <p className="rounded-lg bg-amber-500/15 px-3 py-2 text-sm text-amber-100 md:col-span-2">
                  {existing.user_id} is already enrolled on this edge. Registering again <b>adds a new look</b> (e.g. glasses on or off) to the
                  stored templates; it does not replace them. The new photos must resemble the original enrolment, otherwise the edge refuses them
                  (LOOK_MISMATCH). To replace a person, erase them first (right column), then use “Re-admit and enrol” with fresh consent.
                </p>
              ) : null}
              {plan?.kind === 'blocked' ? (
                <p className="rounded-lg bg-red-600/25 px-3 py-2 text-sm text-red-50 md:col-span-2" role="alert">
                  {plan.why === 'OFFLINE'
                    ? `${form.user_id} ${erased ? 'was erased and needs re-admission' : 'is not in this kiosk’s signed schedule'}: ${REASON_HINT.OFFLINE} People already in the installed bundle can still register offline.`
                    : plan.why === 'REVOKED'
                      ? REASON_HINT.USER_REVOKED
                      : plan.why === 'NOT_AT_THIS_KIOSK'
                        ? `${form.user_id} is in the campus schedule but has no access at this kiosk’s zone, so they cannot be enrolled here.`
                        : 'Pick a role from the campus schedule.'}
                </p>
              ) : erased ? (
                <p className="rounded-lg bg-amber-500/15 px-3 py-2 text-sm text-amber-100 md:col-span-2">
                  {form.user_id} was <b>erased</b> (DPDP). <b>Re-admit and enrol</b> re-admits them in the signed schedule as {role} with the consent given
                  on the first step, then enrols the new photos.
                </p>
              ) : plan?.kind === 'put-then-enrol' && plan.create ? (
                <p className="rounded-lg bg-sky-500/15 px-3 py-2 text-sm text-sky-50 md:col-span-2">
                  New person: Register first adds {form.user_id} to the signed campus schedule as <b>{role}</b> (the cloud re-signs the bundle and this
                  kiosk installs it), then enrols the face.
                </p>
              ) : !dir.access && idOk ? (
                <p className="rounded-lg bg-amber-500/15 px-3 py-2 text-sm text-amber-100 md:col-span-2">
                  The schedule list is not loaded{dir.accessError ? ` (${dir.accessError})` : ''}: the edge decides at enrolment, and refuses ids that are not in its
                  bundle.
                </p>
              ) : null}
              <div className="flex gap-3 md:col-span-2">
                <Btn tone="ghost" onClick={() => setStep('consent')}>
                  Back
                </Btn>
                <Btn tone="primary" big disabled={!idOk || !nameOk || blocked || (!!dir.access && !role)} onClick={() => setStep('capture')}>
                  Next: take photos
                </Btn>
              </div>
            </div>
          ) : null}

          {step === 'capture' || step === 'submitting' ? (
            <div className="grid gap-4 rounded-2xl bg-white/5 p-5 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
              <div className="flex flex-col gap-3">
                <Preview engine={engine} ring={guidance === 'OK' ? '#34d399' : '#f2a900'} progress={0} inset={false}>
                  <p className="absolute inset-x-0 bottom-3 text-center text-[clamp(1rem,2.4vw,1.8rem)] font-bold text-shadow">
                    {prompt ?? (engine ? GUIDANCE_TEXT[guidance] : '')}
                  </p>
                </Preview>
                <CameraPicker
                  devices={devices.devices}
                  activeId={activeId}
                  preferredId={preferred}
                  state={eng}
                  onSelect={(id) => {
                    gen.current++
                    setCapturing(false)
                    setPrompt(null)
                    writePreferredCamera(id)
                    setPreferred(id)
                  }}
                  onRefresh={() => void devices.refresh()}
                  onRetry={() => setRetryKey((k) => k + 1)}
                />
              </div>
              <div className="flex flex-col gap-3">
                <p className="text-base text-white/85">
                  Registering <b>{form.display_name || form.user_id}</b> <span className="font-mono text-sm text-white/60">{form.user_id}</span> · {role ?? 'role from the schedule'}
                  {plan?.kind === 'put-then-enrol' ? (plan.readmit ? ' (re-admitted in the schedule first)' : ' (written to the schedule first)') : ''}
                </p>
                <p className="text-xs text-white/55">
                  {lockState === 'held'
                    ? 'This tab holds the camera lock: the kiosk tab is paused until you leave this step.'
                    : 'Taking the camera lock from the kiosk tab…'}
                </p>
                <p className="text-sm text-white/65">
                  Face the camera from about 50 cm with light from the front and no phone or screen in view. Each photo is taken when the face is
                  steady and the right size (green oval), or after a few seconds.
                </p>
                <div className="grid grid-cols-5 gap-1.5">
                  {PROMPTS.map((p, i) => {
                    const s = shots[i]
                    return (
                      <div key={p} className="relative aspect-video overflow-hidden rounded-lg bg-black/50 ring-1 ring-white/15" title={p}>
                        {s ? <img src={s.url} alt={`frame ${i + 1}: ${p}`} className="h-full w-full object-cover" /> : null}
                        {s ? (
                          <span className={`absolute right-0.5 bottom-0.5 rounded px-1 text-[10px] font-bold ${s.ok ? 'bg-emerald-500 text-black' : 'bg-amber-400 text-black'}`}>
                            {s.ok ? 'OK' : 'check'}
                          </span>
                        ) : null}
                      </div>
                    )
                  })}
                </div>
                {shots.length === PROMPTS.length && goodShots < 3 ? (
                  <p className="text-sm text-amber-200">Only {goodShots} of 5 frames passed the camera check; the edge needs at least 3 usable frames. Consider retaking.</p>
                ) : null}
                {submitError ? (
                  <div className="rounded-lg bg-red-600/25 px-3 py-2 text-sm text-red-100" role="alert">
                    <p>{submitError}</p>
                    {outcome?.reason === 'ERASED_IN_BUNDLE' ? (
                      <p className="mt-1 text-red-50">
                        {dir.canEdit ? 'Press “Re-admit and enrol” to re-admit this person with the consent given, then enrol.' : REASON_HINT.OFFLINE}
                      </p>
                    ) : null}
                    {outcome?.notes.map((n) => (
                      <p key={n.text} className="mt-1 text-xs">
                        {n.text}
                      </p>
                    ))}
                  </div>
                ) : null}
                {blocked ? <p className="text-sm text-red-200">Registration is blocked: see the details step.</p> : null}
                <div className="flex flex-wrap gap-3">
                  <Btn tone="ghost" disabled={capturing || step === 'submitting'} onClick={() => setStep('details')}>
                    Back
                  </Btn>
                  <Btn big tone={shots.length ? 'default' : 'primary'} disabled={!engine || capturing || step === 'submitting'} onClick={() => void capture()}>
                    {shots.length ? 'Retake photos' : 'Take 5 photos'}
                  </Btn>
                  <Btn
                    big
                    tone="primary"
                    disabled={shots.length < 3 || capturing || step === 'submitting' || !token || blocked}
                    onClick={() => void submit()}
                    title={!token ? 'Enter the admin token first' : undefined}
                  >
                    {step === 'submitting' ? 'Registering…' : registerLabel}
                  </Btn>
                </div>
                {!token ? <p className="text-xs text-amber-200">Enter the admin token above to register.</p> : null}
              </div>
            </div>
          ) : null}

          {step === 'done' && result ? (
            <div className="rounded-2xl bg-white/5 p-6">
              {(() => {
                const blocking = outcome?.notes.some((n) => n.tone === 'block') ?? false
                const offlineOnly = result.cloud_state !== 'indexed'
                return (
                  <div className={`rounded-xl px-5 py-4 ${blocking || offlineOnly ? 'bg-stepup text-stepup-ink' : 'bg-allow text-allow-ink'}`}>
                    <p className="text-[clamp(1.6rem,3vw,2.4rem)] font-black">
                      {blocking
                        ? 'Face stored on this kiosk · NOT in the cloud'
                        : offlineOnly
                          ? 'Registered on this kiosk only'
                          : outcome?.apply?.result?.readmitted
                            ? 'Re-admitted and registered'
                            : addedLook
                              ? 'New look added'
                              : 'Registered'}
                    </p>
                    <p className="text-lg font-semibold">
                      {result.schedule_display ?? form.display_name} · {outcome?.scheduleRole ?? 'no schedule role'} · <span className="font-mono">{result.user_id}</span>
                      {result.bundle_version !== null ? ` · schedule v${result.bundle_version}` : ''}
                    </p>
                    <p className="mt-1 text-sm">Role from the signed campus schedule{outcome?.apply?.ok ? ` (${outcome.apply.message})` : ''}.</p>
                  </div>
                )
              })()}
              {outcome?.notes.length ? (
                <ul className="mt-3 flex flex-col gap-2" aria-label="Registration warnings">
                  {outcome.notes.map((n) => (
                    <li key={n.text} className={`rounded-lg px-3 py-2 text-sm ${NOTE_CLS[n.tone]}`}>
                      {n.tone === 'block' ? 'Action needed: ' : ''}
                      {n.text}
                    </li>
                  ))}
                </ul>
              ) : null}
              <dl className="mt-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
                <dt className="text-white/55">frames used</dt>
                <dd>
                  {result.frames_used ?? '—'} of {shots.length}
                  {rejected.length ? ` · rejected ${rejected.length}` : ''}
                </dd>
                {rejected.length ? (
                  <>
                    <dt className="text-white/55">rejected</dt>
                    <dd className="font-mono text-xs">{rejected.map(rejectedText).join(' · ')}</dd>
                  </>
                ) : null}
                <dt className="text-white/55">min pairwise cosine</dt>
                <dd>{typeof result.min_pairwise_cosine === 'number' ? result.min_pairwise_cosine.toFixed(2) : '—'}</dd>
                <dt className="text-white/55">template</dt>
                <dd>
                  v{result.template_version} · local cache {result.local_cache_updated ? 'updated' : 'NOT updated'} · cloud {result.cloud_state.replace('_', ' ')}
                </dd>
              </dl>
              {secret ? (
                <div className="mt-4 flex flex-wrap items-center gap-4 rounded-xl bg-white p-4 text-black">
                  {qr && result.totp_active ? <img src={qr} alt="TOTP QR code" className="h-40 w-40" /> : null}
                  <div className="min-w-0 flex-1">
                    <p className="font-bold">Scan now in an authenticator app (shown only once)</p>
                    <p className="text-sm">6 digits, 30 s. Or type the secret:</p>
                    <p className="mt-1 font-mono text-base break-all">{decodeURIComponent(secret)}</p>
                  </div>
                </div>
              ) : null}
              <div className="mt-5 flex flex-wrap gap-3">
                <a href={`/operator${window.location.search}`} className="rounded-xl bg-[#2a78d6] px-6 py-3 text-lg font-semibold text-white hover:bg-[#256abf]">
                  Test recognition (operator console)
                </a>
                <a href={`/${window.location.search}`} className="rounded-xl bg-white/10 px-6 py-3 text-lg font-semibold ring-1 ring-white/25 hover:bg-white/20">
                  Open the kiosk
                </a>
                <Btn big tone="ghost" onClick={restart}>
                  Register another person
                </Btn>
              </div>
            </div>
          ) : null}
        </section>

        <aside className="flex min-w-0 flex-col gap-3 rounded-2xl bg-white/5 p-4" aria-label="Enrolled users">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-bold tracking-wide text-white/70 uppercase">Enrolled on this edge</h2>
            <span className="text-xs text-white/50">
              {dir.enrolled ? `${dir.enrolled.count ?? dir.enrolled.users.length} users${dir.enrolled.model ? ` · ${dir.enrolled.model}` : ''}` : ''}
            </span>
            <span className="ml-auto">
              <Btn onClick={() => dir.refresh()} disabled={!token}>
                {dir.loading ? 'Loading…' : 'Refresh'}
              </Btn>
            </span>
          </div>
          {!token ? <p className="text-sm text-white/60">Enter the admin token to list and erase users.</p> : null}
          {dir.enrolledError && token ? <p className="text-sm text-red-300">{errorText(dir.enrolledError)}</p> : null}
          {listMsg ? <p className="text-sm text-white/80">{listMsg}</p> : null}
          {users.length ? (
            <ul className="flex flex-col divide-y divide-white/10">
              {users.map((u) => (
                <li key={u.user_id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2">
                  <div className="min-w-0 flex-1">
                    <p className="font-semibold">
                      {u.display_name || u.user_id}{' '}
                      <span className="text-sm font-normal text-white/60">
                        · {identities.find((x) => x.user_id === u.user_id)?.role ?? u.bundle_role ?? 'not in schedule'}
                        {u.template_role && u.template_role !== (identities.find((x) => x.user_id === u.user_id)?.role ?? u.bundle_role) ? ` (template stored as ${u.template_role})` : ''}
                      </span>
                    </p>
                    <p className="font-mono text-xs text-white/50">
                      {u.user_id} · {u.templates ?? '?'} template{u.templates === 1 ? '' : 's'} · v{u.template_version ?? '?'}
                      {u.totp_local ? ' · TOTP' : ''}
                      {u.card ? ' · card' : ''}
                      {u.updated_at ? ` · ${new Date(u.updated_at).toLocaleString([], { hour12: false })}` : ''}
                    </p>
                  </div>
                  <Btn tone="danger" onClick={() => void erase(u)}>
                    Erase
                  </Btn>
                </li>
              ))}
            </ul>
          ) : token && dir.enrolled ? (
            <p className="text-sm text-white/60">Nobody is enrolled yet.</p>
          ) : null}
        </aside>
      </main>
    </div>
  )
}
