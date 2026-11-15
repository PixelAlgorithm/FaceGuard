/**
 * SECOND_FACTOR step: method picker limited to next_action.methods, then the method's entry screen.
 * TOTP 6-digit keypad · STAFF_OVERRIDE staff id + 8-digit code · CARD (simulated reader: card id)
 * · EMAIL_OTP (POST otp/send, then code). Submits POST /v1/attempt/{id}/fallback.
 */
import { useRef, useState, type FormEvent, type ReactNode } from 'react'
import type { FallbackMethod, FallbackRequest } from '../../api/types'
import { MOCK_ENABLED, THRESHOLDS } from '../../config'
import { MOCK_CREDENTIALS } from '../../api/mockScenarios'
import type { FallbackViewModel } from '../controller'
import { MethodIcon, Spinner } from '../components/Icons'
import { primaryCode, reasonText, triesLeftText } from '../reasons'

const METHOD_TEXT: Record<FallbackMethod, { title: string; sub: string }> = {
  TOTP: { title: 'Authenticator code', sub: '6-digit code from your app (works offline)' },
  CARD: { title: 'HID card', sub: 'Tap your access card on the reader' },
  EMAIL_OTP: { title: 'Email code', sub: 'We send a one-time code to your email' },
  STAFF_OVERRIDE: { title: 'Staff override', sub: 'A staff member enters their one-time code' },
}

interface Props {
  vm: FallbackViewModel
  onSelect: (m: FallbackMethod | null) => void
  onSubmit: (req: FallbackRequest) => void
  onRequestOtp: () => void
  onCancel: () => void
  onActivity: () => void
}

function CodeEntry({
  length,
  label,
  mask,
  busy,
  extraValid = true,
  autoFocus = true,
  leading,
  onSubmit,
  onActivity,
}: {
  length: number
  label: string
  mask: boolean
  busy: boolean
  extraValid?: boolean
  /** focus the (hidden) code input on mount; false when a field rendered in `leading` takes focus first */
  autoFocus?: boolean
  /** extra fields inside the same form (e.g. Staff ID), so Enter submits / moves on from them too */
  leading?: ReactNode
  onSubmit: (code: string) => void
  onActivity: () => void
}) {
  const [code, setCode] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)
  const update = (next: string, refocus = false) => {
    setCode(next.replace(/\D/g, '').slice(0, length))
    onActivity()
    // A keypad tap moves focus to the button: give it back to the hidden input so physical keys still work.
    if (refocus) inputRef.current?.focus({ preventScroll: true })
  }
  const submit = (e?: FormEvent) => {
    e?.preventDefault()
    if (code.length === length && extraValid && !busy) onSubmit(code)
    else if (code.length !== length) inputRef.current?.focus({ preventScroll: true }) // e.g. Enter in Staff ID
  }
  const keys = ['1', '2', '3', '4', '5', '6', '7', '8', '9', 'clear', '0', 'back']
  return (
    <form
      onSubmit={submit}
      onKeyDown={(e) => {
        // Enter in a leading field (Staff ID): the disabled Verify button blocks implicit submission, so
        // move on to the code explicitly (or submit when everything is complete).
        if (e.key !== 'Enter' || e.target === inputRef.current || !(e.target instanceof HTMLInputElement)) return
        e.preventDefault()
        submit()
      }}
      className="flex flex-col items-center gap-[1.4vh]"
    >
      {leading}
      <label htmlFor="fallback-code" className="text-[clamp(18px,2.8vh,32px)] font-semibold">
        {label}
      </label>
      <input
        id="fallback-code"
        ref={inputRef}
        value={code}
        onChange={(e) => update(e.target.value)}
        inputMode="numeric"
        autoComplete="one-time-code"
        autoFocus={autoFocus}
        maxLength={length}
        className="sr-only"
      />
      <div className="flex gap-[0.8vw]" aria-hidden>
        {Array.from({ length }, (_, i) => (
          <span
            key={i}
            className={`flex h-[7vh] w-[min(6vw,6.4vh)] items-center justify-center rounded-xl text-[clamp(26px,5vh,58px)] font-bold tabular-nums ring-2 ${
              i < code.length ? 'bg-white text-black ring-white' : 'bg-white/10 ring-white/30'
            }`}
          >
            {i < code.length ? (mask ? '•' : code[i]) : ''}
          </span>
        ))}
      </div>
      <div className="grid grid-cols-3 gap-[0.8vh]">
        {keys.map((k) => (
          <button
            key={k}
            type="button"
            onClick={() =>
              update(k === 'clear' ? '' : k === 'back' ? code.slice(0, -1) : code.length < length ? code + k : code, true)
            }
            className="h-[7vh] w-[min(12vw,12vh)] rounded-2xl bg-white/12 text-[clamp(22px,4vh,46px)] font-bold ring-1 ring-white/25 hover:bg-white/20 active:bg-white/30"
            aria-label={k === 'clear' ? 'Clear' : k === 'back' ? 'Delete last digit' : k}
          >
            {k === 'clear' ? 'Clear' : k === 'back' ? '⌫' : k}
          </button>
        ))}
      </div>
      <button
        type="submit"
        disabled={busy || code.length !== length || !extraValid}
        className="flex min-h-[7vh] min-w-[30vw] items-center justify-center gap-3 rounded-2xl bg-stepup px-10 text-[clamp(22px,3.8vh,44px)] font-black text-stepup-ink disabled:opacity-40"
      >
        {busy ? <Spinner className="h-[4vh] w-[4vh]" /> : null}
        Verify
      </button>
    </form>
  )
}

function MethodBody({ vm, onSubmit, onRequestOtp, onActivity }: Omit<Props, 'onSelect' | 'onCancel'>) {
  const [staffId, setStaffId] = useState('')
  const [cardId, setCardId] = useState('')
  const f = THRESHOLDS.fallback
  switch (vm.selected) {
    case 'TOTP':
      return (
        <CodeEntry
          length={f.totpDigits}
          label="Enter the code from your authenticator app"
          mask={false}
          busy={vm.busy}
          onActivity={onActivity}
          onSubmit={(code) => onSubmit({ method: 'TOTP', code })}
        />
      )
    case 'EMAIL_OTP':
      return vm.otp ? (
        <CodeEntry
          length={f.emailOtpDigits}
          label={`Code sent to ${vm.otp.destination_masked}`}
          mask={false}
          busy={vm.busy}
          onActivity={onActivity}
          onSubmit={(code) => onSubmit({ method: 'EMAIL_OTP', code, otp_id: vm.otp?.otp_id })}
        />
      ) : (
        <button
          type="button"
          onClick={onRequestOtp}
          disabled={vm.busy}
          className="flex min-h-[9vh] items-center gap-3 rounded-2xl bg-stepup px-10 text-[clamp(22px,3.8vh,44px)] font-black text-stepup-ink disabled:opacity-50"
        >
          {vm.busy ? <Spinner className="h-[4vh] w-[4vh]" /> : null}
          Email me a code
        </button>
      )
    case 'STAFF_OVERRIDE':
      return (
        <CodeEntry
          length={f.staffCodeLength}
          label="Staff member: enter the one-time override code"
          mask
          busy={vm.busy}
          autoFocus={false}
          extraValid={staffId.trim().length > 0}
          onActivity={onActivity}
          onSubmit={(code) => onSubmit({ method: 'STAFF_OVERRIDE', staff_id: staffId.trim(), code })}
          leading={
            <label className="mb-[0.6vh] flex items-center gap-3 text-[clamp(18px,2.8vh,32px)] font-semibold">
              Staff ID
              <input
                value={staffId}
                onChange={(e) => {
                  setStaffId(e.target.value)
                  onActivity()
                }}
                autoFocus
                autoComplete="off"
                enterKeyHint="next"
                className="w-[22vw] rounded-xl bg-white px-4 py-2 text-[clamp(18px,3vh,34px)] text-black"
                placeholder="e.g. s_guard01"
              />
            </label>
          }
        />
      )
    case 'CARD':
      return (
        <form
          className="flex flex-col items-center gap-[2.4vh]"
          onSubmit={(e) => {
            e.preventDefault()
            if (cardId.trim() && !vm.busy) onSubmit({ method: 'CARD', card_id: cardId.trim() })
          }}
        >
          <MethodIcon method="CARD" className="h-[16vh] w-[16vh] text-stepup" />
          <p className="text-[clamp(24px,4.4vh,52px)] font-black">Tap your HID card on the reader</p>
          <label className="flex items-center gap-3 text-[clamp(14px,2.2vh,24px)] text-white/80">
            Card ID (simulated reader)
            <input
              value={cardId}
              onChange={(e) => {
                setCardId(e.target.value)
                onActivity()
              }}
              autoFocus
              autoComplete="off"
              className="w-[20vw] rounded-xl bg-white px-4 py-2 text-[clamp(16px,2.6vh,30px)] text-black"
              placeholder="HID-…"
            />
          </label>
          <button
            type="submit"
            disabled={vm.busy || !cardId.trim()}
            className="flex min-h-[8vh] items-center gap-3 rounded-2xl bg-stepup px-10 text-[clamp(22px,3.8vh,44px)] font-black text-stepup-ink disabled:opacity-40"
          >
            {vm.busy ? <Spinner className="h-[4vh] w-[4vh]" /> : null}
            Tap card
          </button>
        </form>
      )
    default:
      return null
  }
}

export function FallbackScreen(props: Props) {
  const { vm, onSelect, onCancel, onActivity } = props
  const code = primaryCode(vm.decision.reason_codes.filter((c) => c !== 'FALLBACK_FAILED'))
  const reason = code ? reasonText(code, 'STEP_UP') : 'Please verify your identity'
  const steps = vm.decision.next_action.steps
  return (
    <section
      className="absolute inset-0 z-50 flex flex-col bg-kiosk text-white"
      onPointerDown={onActivity}
      aria-labelledby="fallback-title"
    >
      <div className="bg-stepup px-[4vw] pt-[11vh] pb-[1.6vh] text-stepup-ink">
        <h1 id="fallback-title" className="text-[clamp(32px,6.4vh,76px)] leading-none font-black">
          Verify it’s you
        </h1>
        <p className="mt-[1vh] text-[clamp(18px,3.2vh,38px)] font-semibold">{reason}</p>
        {vm.attemptsLeft !== null && vm.selected !== null ? (
          <p className="mt-[0.4vh] text-[clamp(14px,2.2vh,24px)] font-semibold">{triesLeftText(vm.attemptsLeft)}</p>
        ) : null}
        {steps.length > 1 ? (
          <p className="mt-[0.6vh] text-[clamp(14px,2.2vh,24px)]">Steps: {steps.join(' → ').toLowerCase().replace(/_/g, ' ')}</p>
        ) : null}
      </div>

      <div className="flex flex-1 flex-col items-center justify-center gap-[1.6vh] px-[4vw]">
        {vm.error ? (
          <p role="alert" className="rounded-xl bg-deny px-6 py-3 text-[clamp(18px,3vh,34px)] font-bold">
            {vm.error}
          </p>
        ) : null}

        {vm.selected === null ? (
          <div className="grid w-full max-w-[80vw] grid-cols-2 gap-[2vh]">
            {vm.methods.map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => onSelect(m)}
                className="flex min-h-[18vh] items-center gap-[2vw] rounded-3xl bg-white/10 px-[2vw] text-left ring-2 ring-white/25 hover:bg-white/15 active:bg-white/25"
              >
                <MethodIcon method={m} className="h-[10vh] w-[10vh] shrink-0 text-stepup" />
                <span>
                  <span className="block text-[clamp(22px,3.8vh,44px)] font-black">{METHOD_TEXT[m].title}</span>
                  <span className="block text-[clamp(14px,2.2vh,24px)] text-white/75">{METHOD_TEXT[m].sub}</span>
                </span>
              </button>
            ))}
          </div>
        ) : (
          <MethodBody key={`${vm.selected}-${vm.attemptsLeft ?? 'n'}`} {...props} />
        )}
      </div>

      <div className="flex items-center justify-between gap-4 px-[4vw] pb-[2vh]">
        <button
          type="button"
          onClick={onCancel}
          className="min-h-14 rounded-xl bg-white/10 px-6 py-3 text-[clamp(16px,2.4vh,26px)] font-semibold ring-1 ring-white/30"
        >
          Cancel
        </button>
        {MOCK_ENABLED ? (
          <p className="text-[clamp(12px,1.7vh,18px)] text-fuchsia-300">
            mock codes: TOTP {MOCK_CREDENTIALS.TOTP} · email {MOCK_CREDENTIALS.EMAIL_OTP} · staff any id +{' '}
            {MOCK_CREDENTIALS.STAFF_OVERRIDE} · card {MOCK_CREDENTIALS.CARD}
          </p>
        ) : null}
        {vm.selected !== null && vm.methods.length > 1 ? (
          <button
            type="button"
            onClick={() => onSelect(null)}
            className="min-h-14 rounded-xl bg-white/10 px-6 py-3 text-[clamp(16px,2.4vh,26px)] font-semibold ring-1 ring-white/30"
          >
            Other method
          </button>
        ) : (
          <span />
        )}
      </div>
    </section>
  )
}
