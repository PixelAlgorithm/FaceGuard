/**
 * Staff override codes (R-D, API.md v1.4 §3.18.4): POST /v1/admin/access/codes/rotate mints fresh one-time
 * codes for a staff id; the cloud stores only PBKDF2 hashes and re-signs the bundle. The plaintext arrives
 * ONCE (`codes[{code_id, code}]`, Cache-Control: no-store), is kept only in this component's state (never
 * localStorage / sessionStorage / URL / console) and is wiped when the box is hidden or the page is left.
 * Minted codes are shown even when the edge could not install the new bundle yet (`bundle.applied: false`):
 * they then work on this kiosk only after a bundle refresh.
 * RBAC (design v2 §D): codes:rotate = the caller's OWN staff_id only; codes:rotate_any = any staff id; a session
 * principal is required (API keys / legacy token: 403 NO_STAFF_IDENTITY). Audit KAO-14: codes are masked until
 * revealed, auto-hidden after CODES_VISIBLE_MS, there is no "copy all", and a copied code is cleared from the
 * clipboard after CLIPBOARD_CLEAR_MS.
 */
import { useEffect, useState } from 'react'
import { getApi, type RotateCodesResult } from '../../api'
import { refreshMode } from '../../shared/modeStore'
import { bundleApplied, errorText, useAccessDirectory, versionText } from '../../shared/accessDirectory'
import { LIMITS, STAFF_ID_HINT, codeLengthText, rotateErrors, validUntilText } from '../../shared/accessRules'
import { useAuth } from '../../shared/auth/context'
import { PERM, needsText } from '../../shared/auth/permissions'
import { toast } from '../../shared/toast'
import { codesGate } from '../codesGate'
import { Card } from '../ui'

/** Minted codes disappear from the screen this long after they were shown. */
const CODES_VISIBLE_MS = 120_000
/** A copied code is wiped from the clipboard after this long (best effort). */
const CLIPBOARD_CLEAR_MS = 30_000

async function copy(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    window.setTimeout(() => void navigator.clipboard.writeText('').catch(() => undefined), CLIPBOARD_CLEAR_MS)
    return true
  } catch {
    return false
  }
}

export function StaffCodesPanel({ token }: { token: string }) {
  const api = getApi()
  const { can, principal } = useAuth()
  const rotateAny = can(PERM.codesRotateAny)
  const rotateOwn = can(PERM.codesRotate)
  const ownId = principal?.kind === 'staff' ? principal.staff_id : null
  // the edge mints codes for a signed-in staff session only, even with codes:rotate_any (NO_STAFF_IDENTITY)
  const gate = codesGate({ rotate: rotateOwn, rotateAny }, ownId)
  const { mayRotate, noIdentity, maxCount } = gate
  const dir = useAccessDirectory(token, 'codes-tab', {
    accessRead: can(PERM.accessRead),
    enrolRead: can(PERM.enrolRead),
    accessEdit: mayRotate,
    bundleRefresh: can(PERM.bundleRefresh),
  })
  const [staffIdInput, setStaffId] = useState(ownId ?? '')
  // without codes:rotate_any the edge accepts only the caller's own staff id
  const staffId = gate.ownOnly ? (ownId ?? '') : staffIdInput
  const [revealed, setRevealed] = useState(false)
  const [count, setCount] = useState<number>(LIMITS.rotateCountDefault)
  const [replace, setReplace] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [minted, setMinted] = useState<RotateCodesResult | null>(null)
  // one id per mint: the 2-min auto-hide runs from the mint, a later bundle refresh (new object) must not extend it
  const [mintId, setMintId] = useState(0)
  const [copied, setCopied] = useState<number | null>(null)
  const [refreshing, setRefreshing] = useState(false)

  // the plaintext lives only in this component's state: a tab switch / navigation unmounts it and wipes it
  // `actor` is informational only: the edge derives it from the session (design v2 §D)
  const req = { staff_id: staffId, count, replace_existing: replace, actor: principal?.actor_id ?? 'control-panel' }
  const reqErrors = [...rotateErrors(req), ...(Number.isInteger(count) && count > maxCount ? [`count: at most ${maxCount} for your own codes`] : [])]
  const idOk = !reqErrors.some((e) => e.startsWith('staff id'))

  const rotate = async () => {
    if (reqErrors.length || !dir.canEdit || busy || !mayRotate) return
    const what = replace
      ? `This REPLACES ${staffId}'s current override codes (they stop working, including any printed demo codes).`
      : `${staffId}'s existing codes stay valid.`
    if (!window.confirm(`Mint ${count} new one-time override code(s) for ${staffId}? ${what} The new codes are shown once.`)) return
    setBusy(true)
    setError(null)
    setMinted(null)
    setCopied(null)
    setRevealed(false)
    try {
      const r = await api.rotateStaffCodes(token, req)
      setMinted(r)
      setMintId((n) => n + 1)
      if (r.bundle.applied === false) toast.error(`Codes minted, but this kiosk still runs bundle v${String(r.bundle.installed_version ?? '?')}: refresh the bundle before using them here.`)
      else toast.success(`${r.codes.length} new code(s) for ${r.staff_id} · bundle ${versionText(r.cloud_bundle_version)}`)
      dir.refresh()
      refreshMode()
    } catch (e) {
      const msg = errorText(e)
      setError(msg)
      toast.error(`Code rotation failed: ${msg}`)
    } finally {
      setBusy(false)
    }
  }

  const pullBundle = async () => {
    if (!minted) return
    setRefreshing(true)
    try {
      const b = await api.refreshBundle(token)
      const ok = bundleApplied(b, minted.cloud_bundle_version)
      setMinted({ ...minted, bundle: { ...b, applied: ok } })
      if (ok) toast.success(`Bundle v${b.installed_version} installed: the codes work on this kiosk now.`)
      else toast.error(`This kiosk still runs v${String(b.installed_version ?? '?')} (needs ${minted.cloud_bundle_version === null ? 'the new bundle' : `v${minted.cloud_bundle_version}`}).`)
      refreshMode()
    } catch (e) {
      toast.error(`Bundle refresh failed: ${errorText(e)}`)
    } finally {
      setRefreshing(false)
    }
  }

  // KAO-14: never leave plaintext codes on a projector-facing screen
  const showing = minted !== null
  useEffect(() => {
    if (!showing) return
    const t = window.setTimeout(() => {
      setMinted(null)
      setCopied(null)
      setRevealed(false)
      toast.info('The minted codes were hidden after 2 minutes.')
    }, CODES_VISIBLE_MS)
    return () => window.clearTimeout(t)
  }, [showing, mintId])

  return (
    <Card title="Staff override codes">
      <p className="mb-3 text-sm text-[#52514e]">
        STAFF_OVERRIDE is the last-resort second factor (a staff member enters a one-time code at the kiosk). Rotating mints fresh random codes
        into a newly signed bundle; the cloud keeps only PBKDF2 hashes and drops the publicly documented fixture codes (OVR-001…003).
      </p>
      {!rotateAny && !rotateOwn ? <p className="mb-3 text-sm text-[#8a6d00]">{needsText(PERM.codesRotate)}</p> : null}
      {noIdentity ? <p className="mb-3 text-sm text-[#8f1d1d]">Staff codes need a signed-in staff account (not an API key or the legacy token).</p> : null}
      {gate.ownOnly && mayRotate && ownId ? (
        <p className="mb-3 text-xs text-[#52514e]">
          You can rotate codes for your own staff id ({ownId}) only, at most {maxCount} at a time; {needsText(PERM.codesRotateAny)} for others.
        </p>
      ) : null}
      {mayRotate && dir.editBlockedReason ? (
        <p className="mb-3 rounded-lg bg-[#fff4d6] px-3 py-2 text-sm text-[#5c4300]">
          <b>Unavailable.</b> {dir.editBlockedReason}
        </p>
      ) : null}
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault()
          void rotate()
        }}
      >
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-xs text-[#52514e]">Staff id</span>
          <input
            className={`w-48 rounded-lg border bg-white px-2 py-1 font-mono text-sm ${staffId && !idOk ? 'border-[#d03b3b]' : 'border-black/20'}`}
            value={staffId}
            list="staff-ids"
            readOnly={gate.ownOnly}
            onChange={(e) => setStaffId(e.target.value.trim().toLowerCase())}
          />
          <datalist id="staff-ids">
            {(dir.access?.staff_ids ?? []).map((s) => (
              <option key={s} value={s} />
            ))}
          </datalist>
          {staffId && !idOk ? <span className="text-xs text-[#d03b3b]">{STAFF_ID_HINT}</span> : null}
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-xs text-[#52514e]">
            How many ({LIMITS.rotateCountMin}–{maxCount})
          </span>
          <input
            type="number"
            min={LIMITS.rotateCountMin}
            max={maxCount}
            className="w-24 rounded-lg border border-black/20 bg-white px-2 py-1 text-sm"
            value={count}
            onChange={(e) => setCount(Number(e.target.value))}
          />
        </label>
        <label className="flex items-center gap-2 pb-1.5 text-sm">
          <input type="checkbox" checked={replace} onChange={(e) => setReplace(e.target.checked)} />
          <span className="text-xs">replace this staff member's existing codes</span>
        </label>
        <button
          type="submit"
          disabled={reqErrors.length > 0 || !dir.canEdit || busy || !mayRotate}
          className="rounded-lg bg-[#2a78d6] px-4 py-1.5 text-sm font-semibold text-white hover:bg-[#256abf] disabled:opacity-50"
        >
          {busy ? 'Rotating…' : 'Rotate codes'}
        </button>
      </form>
      {reqErrors.length && staffId ? <p className="mt-2 text-xs text-[#d03b3b]">{reqErrors.join(' · ')}</p> : null}
      {error ? <p className="mt-3 rounded-lg bg-[#fde2e1] px-3 py-2 text-sm text-[#8f1d1d]">{error}</p> : null}

      {minted ? (
        <div className="mt-4 rounded-xl border-2 border-[#d03b3b] bg-[#fff8f0] p-4" role="alert">
          <p className="text-sm font-bold text-[#8f1d1d]">
            Shown once: store these codes safely (e.g. a sealed envelope for {minted.staff_id}), then hide this box. They are not saved in this
            browser, cannot be shown again (rotate again if they are lost) and are hidden automatically after 2 minutes.
          </p>
          <p className="mt-1 text-xs text-[#5c4300]">{minted.warning}</p>
          {minted.bundle.applied === false ? (
            <div className="mt-2 flex flex-wrap items-center gap-2 rounded-lg bg-[#fff4d6] px-3 py-2 text-sm text-[#5c4300]">
              <span>
                <b>Not active on this kiosk yet:</b> it still runs bundle v{String(minted.bundle.installed_version ?? '?')}, the codes are in{' '}
                {minted.cloud_bundle_version === null ? 'a new bundle (version pending refresh)' : `v${minted.cloud_bundle_version}`}.
              </span>
              <button
                type="button"
                disabled={!dir.canRefreshBundle || refreshing}
                title={dir.refreshBlockedReason ?? undefined}
                onClick={() => void pullBundle()}
                className="rounded-lg px-2 py-0.5 text-xs font-semibold ring-1 ring-black/20 hover:bg-white disabled:opacity-50"
              >
                {refreshing ? 'Refreshing…' : 'Refresh edge bundle'}
              </button>
            </div>
          ) : null}
          {minted.warnings.length ? (
            <ul className="mt-2 list-disc pl-5 text-xs text-[#5c4300]">
              {minted.warnings.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
          ) : null}
          <ul className="mt-3 flex flex-wrap gap-2">
            {minted.codes.map((c, i) => (
              <li key={`${String(i)}:${c.code_id ?? ''}`} className="flex items-center gap-2 rounded-lg bg-white px-3 py-1.5 ring-1 ring-black/15">
                <span className="flex flex-col">
                  <span className="font-mono text-lg tracking-widest">{revealed ? c.code : '•'.repeat(c.code.length)}</span>
                  <span className="font-mono text-[10px] text-[#898781]">{c.code_id ?? 'id unknown'}</span>
                </span>
                <button
                  type="button"
                  className="rounded px-2 py-0.5 text-xs ring-1 ring-black/15 hover:bg-[#f0efec]"
                  onClick={async () => {
                    const ok = await copy(c.code)
                    setCopied(ok ? i : null)
                    if (!ok) toast.error('Clipboard not available: copy the code by hand')
                  }}
                >
                  {copied === i ? 'copied' : 'copy'}
                </button>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-[#52514e]">
            staff {minted.staff_id} · {codeLengthText(minted.code_length)} · signed bundle {versionText(minted.cloud_bundle_version)} · valid until{' '}
            {validUntilText(minted.valid_until)} · each code works once
            {minted.dropped_code_ids.length ? ` · replaced ${minted.dropped_code_ids.length} older code(s)` : ''}
          </p>
          <div className="mt-3 flex gap-2">
            <button type="button" className="rounded-lg px-3 py-1 text-sm ring-1 ring-black/15 hover:bg-[#f0efec]" onClick={() => setRevealed((v) => !v)}>
              {revealed ? 'Mask codes' : 'Reveal codes'}
            </button>
            <button
              type="button"
              className="rounded-lg bg-[#0b0b0b] px-3 py-1 text-sm font-semibold text-white"
              onClick={() => {
                setMinted(null)
                setCopied(null)
                setRevealed(false)
              }}
            >
              I stored them: hide
            </button>
          </div>
        </div>
      ) : null}
    </Card>
  )
}
