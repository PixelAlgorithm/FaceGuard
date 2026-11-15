/**
 * Quick enrolment from the control panel with explicit consent, using this browser's camera (5 frames with
 * slight pose variation, <= 1280 px). Same R-A flow as /register (shared/registerFlow.ts): a new person,
 * a role / name change or an ERASED person (R-B re-admission) is first written to the signed schedule
 * (PUT /v1/admin/access/users/{id}, ONLINE only; the edge installs the re-signed bundle), THEN POST
 * /v1/enroll. Offline, only people already in the installed bundle can enrol. cloud_state / warnings[] are
 * shown (R-F). Erasure: DELETE /v1/enroll/{user_id}. The camera holds the one-capturing-tab lock while open.
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import QRCode from 'qrcode'
import { getApi, type EraseResponse, type HealthResponse } from '../../api'
import { canvasToJpeg } from '../../capture/imageStats'
import { sleep } from '../../capture/time'
import { ERASE_CLOUD_TEXT, ROLE_SOURCE_TEXT, errorText, useAccessDirectory } from '../../shared/accessDirectory'
import { askAdminText, displayError, gatePlan, registerPlan, userIdError } from '../../shared/accessRules'
import { useAuth } from '../../shared/auth/context'
import { PERM } from '../../shared/auth/permissions'
import { CaptureLock, useLockState } from '../../shared/captureLock'
import { CONSENT_VERSION, registerPerson, type RegisterOutcome } from '../../shared/registerFlow'
import { toast } from '../../shared/toast'
import { usePoll } from '../usePoll'
import { ActionButton, Card } from '../ui'

const PROMPTS = [
  'Look straight at the camera',
  'Turn slightly to your left',
  'Turn slightly to your right',
  'Lift your chin slightly',
  'Look straight again',
]
const field = 'w-full rounded-lg border border-black/20 bg-white px-2 py-1 text-sm disabled:bg-[#f0efec]'
const NOTE_CLS = { ok: 'bg-[#e3f4e3] text-[#0f5132]', warn: 'bg-[#fff4d6] text-[#5c4300]', block: 'bg-[#fde2e1] text-[#8f1d1d] font-semibold' }

interface Shot {
  blob: Blob
  url: string
}

interface Form {
  user_id: string
  display_name: string
  email: string
  /** role to set in the schedule; null = keep the schedule role */
  role: string | null
  card_id: string
  provision_totp: boolean
  consent: boolean
}

function templateCount(h: HealthResponse | null): number | null {
  if (!h) return null
  const pick = (o: unknown): number | null => {
    const tc = o && typeof o === 'object' ? (o as Record<string, unknown>).template_cache : null
    const c = tc && typeof tc === 'object' ? (tc as Record<string, unknown>).count : null
    return typeof c === 'number' ? c : null
  }
  return pick(h) ?? pick(h.detail)
}

function eraseText(r: EraseResponse): string {
  const cloud = ERASE_CLOUD_TEXT[r.cloud]
  return `Erased ${r.user_id}: local data ${r.local_removed ? 'removed' : 'was not on this edge'} · ${cloud}${r.message ? ` · ${r.message}` : ''}`
}

export function EnrolPanel({ token }: { token: string }) {
  const api = getApi()
  const videoRef = useRef<HTMLVideoElement>(null)
  const [stream, setStream] = useState<MediaStream | null>(null)
  const { can } = useAuth()
  const mayEditAccess = can(PERM.accessEdit)
  // accessEdit: true -> dir.canEdit means "the schedule is writable here"; the permission is applied by gatePlan
  const dir = useAccessDirectory(token, 'enrol-card', {
    accessRead: can(PERM.accessRead),
    enrolRead: can(PERM.enrolRead),
    accessEdit: true,
    bundleRefresh: can(PERM.bundleRefresh),
  })
  const [form, setForm] = useState<Form>({ user_id: '', display_name: '', email: '', role: null, card_id: '', provision_totp: false, consent: false })
  const autoName = useRef('')
  const [shots, setShots] = useState<Shot[]>([])
  const [prompt, setPrompt] = useState<string | null>(null)
  const [outcome, setOutcome] = useState<RegisterOutcome | null>(null)
  const [qr, setQr] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [eraseId, setEraseId] = useState('')
  const [eraseMsg, setEraseMsg] = useState<string | null>(null)
  const health = usePoll<HealthResponse>(() => api.getHealth(), 5000, true, 'health')

  // One capturing tab at a time: hold the lock (taken over from the kiosk tab) while the camera is open.
  const lock = useMemo(() => new CaptureLock('operator'), [])
  const lockState = useLockState(lock)
  useEffect(() => {
    if (stream) lock.enable(true)
    else lock.disable()
  }, [stream, lock])
  useEffect(() => () => lock.disable(), [lock])

  useEffect(() => {
    const v = videoRef.current
    if (v && stream) {
      v.srcObject = stream
      void v.play().catch(() => undefined)
    }
    return () => stream?.getTracks().forEach((t) => t.stop())
  }, [stream])

  useEffect(() => () => shots.forEach((s) => URL.revokeObjectURL(s.url)), [shots])

  const enrolled = outcome?.enrol ?? null
  useEffect(() => {
    const uri = enrolled?.totp_active ? enrolled.totp_provisioning_uri : null
    let cancelled = false
    if (uri) {
      QRCode.toDataURL(uri, { margin: 1, width: 168 })
        .then((u) => !cancelled && setQr(u))
        .catch(() => !cancelled && setQr(null))
    }
    return () => {
      cancelled = true
    }
  }, [enrolled])

  const userId = form.user_id.trim()
  const existing = dir.identities.find((u) => u.user_id === userId) ?? null
  const scheduleRole = existing && existing.status !== 'NOT_IN_SCHEDULE' ? existing.role : null
  const role = form.role ?? scheduleRole ?? (dir.roles.includes('student') ? 'student' : (dir.roles[0] ?? null))
  const plan = dir.access ? gatePlan(registerPlan(existing?.row ?? null, dir.canEdit, role, form.display_name), mayEditAccess) : null
  const erased = existing?.status === 'ERASED'

  /** Picked or typed id: name / role from the schedule, TOTP default off for an enrolled person. */
  const selectUser = (raw: string) => {
    const id = raw.trim().toLowerCase()
    const u = dir.identities.find((x) => x.user_id === id) ?? null
    let display = form.display_name
    if (u) {
      display = u.display
      autoName.current = u.display
    } else if (form.display_name === autoName.current) {
      display = ''
      autoName.current = ''
    }
    setOutcome(null)
    setForm({ ...form, user_id: id, display_name: display, role: null, provision_totp: u ? !u.enrolled && !u.totp && u.user_id !== 'u_prj1' : true })
  }

  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => ({ ...f, [k]: v }))
  const idErr = userId ? userIdError(userId) : null
  const nameErr = form.display_name ? displayError(form.display_name) : null
  const eraseOk = !userIdError(eraseId.trim())
  const ready = !userIdError(userId) && !displayError(form.display_name) && form.consent && shots.length >= 3 && plan?.kind !== 'blocked'

  const startCamera = async () => {
    setError(null)
    try {
      setStream(await navigator.mediaDevices.getUserMedia({ video: { width: { ideal: 1280 }, height: { ideal: 720 } }, audio: false }))
    } catch (e) {
      setError(`Camera failed: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const capture = async () => {
    const v = videoRef.current
    if (!v || !v.videoWidth) return
    setOutcome(null)
    setQr(null)
    const out: Shot[] = []
    for (const p of PROMPTS) {
      setPrompt(p)
      await sleep(900)
      const c = document.createElement('canvas')
      const scale = Math.min(1, 1280 / v.videoWidth) // same width as the edge's capture.max_width_px
      c.width = Math.round(v.videoWidth * scale)
      c.height = Math.round(v.videoHeight * scale)
      c.getContext('2d')?.drawImage(v, 0, 0, c.width, c.height) // unmirrored frame
      const blob = await canvasToJpeg(c, 0.9)
      out.push({ blob, url: URL.createObjectURL(blob) })
    }
    setPrompt(null)
    setShots(out)
  }

  const enrol = async (forceReadmit = false) => {
    if (form.provision_totp && (existing?.enrolled || existing?.totp) && !window.confirm(`This replaces ${userId}'s authenticator code (new TOTP secret). Continue?`)) {
      return 'cancelled'
    }
    setError(null)
    setOutcome(null)
    const o = await registerPerson(
      token,
      existing,
      { online: dir.canEdit, listLoaded: !!dir.access, canEditAccess: mayEditAccess },
      {
        userId,
        display: form.display_name,
        role,
        email: form.email,
        cardId: form.card_id,
        provisionTotp: form.provision_totp,
        frames: shots.map((s) => s.blob),
        actor: 'control-panel', // informational: the edge derives the real actor from the session
        forceReadmit,
      },
    )
    setOutcome(o)
    health.refresh()
    if (!o.ok) {
      setError(o.error)
      throw new Error(o.error ?? 'registration failed')
    }
    if (o.notes.some((n) => n.tone === 'block')) toast.error(`${o.enrol?.user_id} enrolled locally, but NOT indexed in the cloud`)
    else toast.success(`Enrolled ${o.enrol?.user_id} · ${o.scheduleRole ?? 'no schedule role'}`)
    return `${o.enrol?.user_id} · ${o.enrol?.frames_used} frames · role ${o.scheduleRole ?? '–'}`
  }

  const secret = enrolled?.totp_active && enrolled.totp_provisioning_uri ? (/[?&]secret=([^&]+)/.exec(enrolled.totp_provisioning_uri)?.[1] ?? null) : null
  const templates = templateCount(health.data)

  return (
    <Card
      title="Quick enrol (consent required)"
      actions={
        <span className="text-xs text-[#52514e]">
          templates: {templates ?? '–'} ·{' '}
          <a className="text-[#2a78d6] underline" href={`/register${window.location.search}`}>
            guided /register
          </a>
        </span>
      }
    >
      {dir.offline && token ? (
        <p className="mb-2 rounded-lg bg-[#fff4d6] px-2 py-1.5 text-xs text-[#5c4300]">
          {dir.editBlockedReason ?? 'Read-only schedule.'} New people cannot be registered now; people already in this kiosk’s bundle can enrol (local
          template only).
        </p>
      ) : null}
      <div className="grid grid-cols-2 gap-2 text-sm">
        <label className="col-span-2">
          <span className="text-xs text-[#52514e]">Person ({ROLE_SOURCE_TEXT(dir.access ? 'schedule' : 'demo-file', dir.bundleVersion)})</span>
          <select className={field} value={dir.identities.some((u) => u.user_id === userId) ? userId : ''} onChange={(e) => selectUser(e.target.value)}>
            <option value="">new person / type an id…</option>
            {dir.identities.map((u) => (
              <option key={u.user_id} value={u.user_id}>
                {u.user_id} · {u.display} · {u.role ?? 'not in schedule'}
                {u.status !== 'ACTIVE' && u.status !== 'NOT_IN_SCHEDULE' ? ` · ${u.status}` : ''}
                {u.enrolled ? ' · enrolled' : ''}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="text-xs text-[#52514e]">user_id</span>
          <input className={`${field} font-mono ${idErr ? 'border-[#d03b3b]' : ''}`} value={form.user_id} placeholder="u_ab12" onChange={(e) => selectUser(e.target.value)} />
          {idErr ? <span className="text-xs text-[#d03b3b]">{idErr}</span> : null}
        </label>
        <label>
          <span className="text-xs text-[#52514e]">display name (1–80)</span>
          <input className={field} value={form.display_name} maxLength={80} onChange={(e) => set('display_name', e.target.value)} />
          {nameErr ? <span className="text-xs text-[#d03b3b]">{nameErr}</span> : null}
        </label>
        <label>
          <span className="text-xs text-[#52514e]">role in the signed schedule</span>
          <select className={field} value={role ?? ''} disabled={!dir.canEdit} onChange={(e) => set('role', e.target.value || null)}>
            {(dir.canEdit && dir.roles.length ? dir.roles : role ? [role] : []).map((r) => (
              <option key={r} value={r}>
                {r}
                {r === scheduleRole ? ' (current)' : ''}
              </option>
            ))}
          </select>
          <span className="text-[11px] text-[#898781]">
            {scheduleRole ? `schedule: ${scheduleRole}` : userId && !idErr ? 'not in the schedule yet' : ''}
            {plan?.kind === 'put-then-enrol' ? ` · ${plan.create ? 'added' : plan.readmit ? 're-admitted' : 'updated'} as ${role} BEFORE the face is enrolled` : ''}
          </span>
        </label>
        <label>
          <span className="text-xs text-[#52514e]">email (for OTP, optional)</span>
          <input className={field} value={form.email} onChange={(e) => set('email', e.target.value)} />
        </label>
        <label>
          <span className="text-xs text-[#52514e]">HID card id (simulated, optional)</span>
          <input className={field} value={form.card_id} onChange={(e) => set('card_id', e.target.value)} placeholder="HID-…" />
        </label>
        <label className="flex items-end gap-2 pb-1">
          <input
            type="checkbox"
            checked={form.provision_totp}
            onChange={(e) => {
              const on = e.target.checked
              if (on && (existing?.enrolled || existing?.totp) && !window.confirm(`${userId} is already enrolled: a new TOTP secret replaces their current authenticator code. Continue?`)) return
              set('provision_totp', on)
            }}
          />
          <span className="text-xs">new TOTP secret{existing?.enrolled ? ' (replaces the current one)' : ''}</span>
        </label>
      </div>
      {plan?.kind === 'blocked' && userId && !idErr ? (
        <p className="mt-2 rounded-lg bg-[#fde2e1] px-2 py-1.5 text-xs text-[#8f1d1d]">
          {plan.why === 'OFFLINE'
            ? `${userId} ${existing?.status === 'ERASED' ? 'was erased' : 'is not in this kiosk’s schedule'}: new people can only be registered while ONLINE.`
            : plan.why === 'REVOKED'
              ? `${userId} is revoked: restore them first (Users & access → Restore).`
              : plan.why === 'NOT_AT_THIS_KIOSK'
                ? `${userId} has no access at this kiosk’s zone.`
                : plan.why === 'NEEDS_ACCESS_EDIT'
                  ? askAdminText(userId)
                  : 'Pick a role first.'}
        </p>
      ) : null}
      {erased && plan?.kind !== 'blocked' ? (
        <p className="mt-2 rounded-lg bg-[#fff4d6] px-2 py-1.5 text-xs text-[#5c4300]">
          {userId} was erased (DPDP). “Re-admit and enrol” re-admits them in the schedule with the consent below, then enrols the new photos.
        </p>
      ) : null}

      <div className="mt-3 overflow-hidden rounded-lg bg-black">
        {stream ? (
          <div className="relative">
            <video ref={videoRef} muted playsInline className="mirror aspect-video w-full object-cover" />
            {prompt ? <p className="absolute inset-x-0 bottom-2 text-center text-sm font-bold text-white drop-shadow">{prompt}</p> : null}
          </div>
        ) : (
          <button type="button" onClick={startCamera} className="w-full py-8 text-sm font-semibold text-white">
            Start camera for enrolment
          </button>
        )}
      </div>
      {stream ? (
        <p className="mt-1 flex items-center gap-2 text-xs text-[#52514e]">
          {lockState === 'held' ? 'Camera lock held: the kiosk tab is paused.' : 'Taking the camera lock from the kiosk tab…'}
          <button type="button" className="underline" onClick={() => setStream(null)}>
            stop camera
          </button>
        </p>
      ) : null}
      {shots.length ? (
        <div className="mt-2 grid grid-cols-5 gap-1">
          {shots.map((s) => (
            <img key={s.url} src={s.url} alt="enrolment frame" className="aspect-video w-full rounded object-cover" />
          ))}
        </div>
      ) : null}

      <label className="mt-3 flex items-start gap-2 rounded-lg bg-[#f0efec] p-2 text-xs">
        <input type="checkbox" checked={form.consent} onChange={(e) => set('consent', e.target.checked)} className="mt-0.5" />
        <span>
          The person agrees that a face <b>template</b> (not a photo) is stored encrypted on this kiosk and used only for campus access control, and
          that they can request deletion at any time (India DPDP Act 2023). Consent version {CONSENT_VERSION}.
        </span>
      </label>

      <div className="mt-3 flex flex-wrap items-start gap-2">
        <ActionButton label={shots.length ? 'Re-capture 5 frames' : 'Capture 5 frames'} disabled={!stream || prompt !== null || lockState !== 'held'} run={capture} />
        <ActionButton label={erased ? 'Re-admit and enrol' : 'Enrol'} tone="primary" perm={PERM.enrolWrite} disabled={!ready || !token} run={() => enrol(false)} />
        {outcome?.reason === 'ERASED_IN_BUNDLE' && dir.canEdit && mayEditAccess ? (
          <ActionButton label="Re-admit and enrol" tone="primary" perm={PERM.enrolWrite} disabled={!ready || !token} run={() => enrol(true)} />
        ) : null}
      </div>
      {!form.consent ? <p className="mt-1 text-xs text-[#8f1d1d]">Consent is required before enrolment.</p> : null}
      <p className="mt-1 text-xs text-[#52514e]">
        Enrolling an id that is already enrolled ADDS a look (e.g. glasses on / off). The new frames must resemble the original enrolment (else 409
        LOOK_MISMATCH); erase the user first to replace them.
      </p>
      {error ? <p className="mt-2 text-xs text-[#d03b3b]">{error}</p> : null}
      {outcome?.apply?.ok ? <p className="mt-2 rounded bg-[#e3f4e3] px-2 py-1 text-xs text-[#0f5132]">Schedule: {outcome.apply.message}</p> : null}
      {enrolled ? (
        <div className="mt-3 rounded-lg border border-black/10 bg-white p-2 text-xs">
          <p>
            Enrolled <b>{enrolled.user_id}</b> as <b>{enrolled.schedule_role ?? 'no schedule role'}</b> · frames used {enrolled.frames_used} · rejected{' '}
            {enrolled.frames_rejected.length} · min pairwise cosine {enrolled.min_pairwise_cosine !== null ? enrolled.min_pairwise_cosine.toFixed(2) : '–'} · cloud{' '}
            {enrolled.cloud_state}
            {enrolled.bundle_version !== null ? ` · bundle v${enrolled.bundle_version}` : ''}
          </p>
          {outcome?.notes.map((n) => (
            <p key={n.text} className={`mt-1 rounded px-2 py-1 ${NOTE_CLS[n.tone]}`}>
              {n.text}
            </p>
          ))}
          {secret ? (
            <div className="mt-2 flex items-center gap-3">
              {qr && enrolled?.totp_active ? <img src={qr} alt="TOTP QR code" className="h-28 w-28" /> : null}
              <span>
                Scan now in an authenticator app (TOTP, 6 digits, 30 s) or enter the secret:
                <span className="mt-1 block font-mono text-sm break-all">{decodeURIComponent(secret)}</span>
              </span>
            </div>
          ) : null}
        </div>
      ) : null}

      <div className="mt-4 flex items-start gap-2 border-t border-[#e1e0d9] pt-3">
        <input
          className={`${field} font-mono ${eraseId && !eraseOk ? 'border-[#d03b3b]' : ''}`}
          placeholder="user_id to erase (u_xxxx)"
          value={eraseId}
          onChange={(e) => setEraseId(e.target.value.trim().toLowerCase())}
        />
        <ActionButton
          label="Erase"
          perm={PERM.enrolErase}
          tone="danger"
          disabled={!eraseOk || !token}
          run={async () => {
            if (!window.confirm(`Erase ${eraseId}? Removes the face template, TOTP secret and card hash from this edge and the cloud (DPDP erasure).`)) return 'cancelled'
            setEraseMsg(null)
            try {
              const r = await api.deleteEnrollment(token, eraseId.trim())
              setEraseMsg(eraseText(r))
              if (r.cloud === 'failed') toast.error(`${r.user_id}: local erase done, cloud erasure could not be queued. Erase again while ONLINE.`)
              return r.cloud
            } catch (e) {
              setEraseMsg(`Erase failed: ${errorText(e)}`)
              throw e
            } finally {
              health.refresh()
              dir.refresh()
            }
          }}
        />
      </div>
      {eraseMsg ? <p className="mt-1 text-xs text-[#52514e]">{eraseMsg}</p> : null}
    </Card>
  )
}
