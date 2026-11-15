import { useEffect, useState } from 'react'
import { AlertIcon, Spinner } from '../components/Icons'

export function BootScreen({ stage }: { stage: 'camera' | 'model' | 'ready' }) {
  return (
    <section className="absolute inset-0 z-50 flex flex-col items-center justify-center gap-6 bg-kiosk text-center">
      <Spinner className="h-[10vh] w-[10vh] text-white" />
      <p className="text-[clamp(26px,5vh,60px)] font-bold">
        {stage === 'camera' ? 'Starting camera…' : stage === 'model' ? 'Loading face model…' : 'Ready'}
      </p>
      <p className="text-[clamp(14px,2.2vh,24px)] text-white/70">
        Allow camera access if the browser asks. Everything runs on this kiosk.
      </p>
    </section>
  )
}

export function FatalScreen({ title, message, hint }: { title: string; message: string; hint: string | null }) {
  return (
    <section role="alert" className="absolute inset-0 z-50 flex flex-col items-center justify-center gap-5 bg-zinc-900 px-[6vw] text-center">
      <AlertIcon className="h-[14vh] w-[14vh] text-amber-400" />
      <h1 className="text-[clamp(32px,6.5vh,78px)] font-black">{title}</h1>
      <p className="text-[clamp(18px,3.2vh,38px)]">{message}</p>
      {hint ? <p className="max-w-[80vw] text-[clamp(14px,2.4vh,28px)] text-amber-200">{hint}</p> : null}
      <button
        type="button"
        onClick={() => window.location.reload()}
        className="mt-4 min-h-14 rounded-xl bg-white px-8 py-3 text-[clamp(16px,2.6vh,30px)] font-bold text-black"
      >
        Reload
      </button>
    </section>
  )
}

export function ServiceErrorScreen({ title, message, retryAt }: { title: string; message: string; retryAt: number }) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 250)
    return () => window.clearInterval(id)
  }, [])
  const s = Math.max(0, Math.ceil((retryAt - now) / 1000))
  return (
    <section role="alert" className="absolute inset-0 z-50 flex flex-col items-center justify-center gap-5 bg-deny px-[6vw] text-center text-deny-ink">
      <AlertIcon className="h-[16vh] w-[16vh]" />
      <h1 className="text-[clamp(36px,8vh,96px)] leading-none font-black">{title}</h1>
      <p className="max-w-[85vw] text-[clamp(20px,3.6vh,44px)] font-semibold">{message}</p>
      <p className="text-[clamp(14px,2.4vh,28px)] opacity-85">Retrying in {s} s</p>
    </section>
  )
}
