/** Step-up challenge prompts: one big instruction + icon at a time, camera oval stays visible. */
import { useLayoutEffect } from 'react'
import type { ChallengeAction } from '../../api/types'
import type { ChallengeViewModel } from '../controller'
import { ChallengeIcon, CheckIcon, Spinner } from '../components/Icons'

const ACTION_TEXT: Record<ChallengeAction, string> = {
  SMILE: 'Smile',
  OPEN_MOUTH: 'Open your mouth',
  PUFF_CHEEKS: 'Puff your cheeks',
  BLINK: 'Blink',
  TURN_LEFT: 'Turn your head left',
  TURN_RIGHT: 'Turn your head right',
}

function Prompt({
  action,
  index,
  windowMs,
  onPrompted,
}: {
  action: ChallengeAction
  index: number
  windowMs: number
  onPrompted: (index: number) => void
}) {
  // Layout effect = DOM updated, not yet painted: the closest hook to "prompt shown" (prompted_at_ms).
  useLayoutEffect(() => {
    onPrompted(index)
  }, [index, onPrompted])
  return (
    <div className="flex flex-col items-center gap-[1.5vh]">
      <div className="flex items-center gap-[2vw] rounded-3xl bg-black/80 px-[3vw] py-[1.6vh]">
        <ChallengeIcon action={action} className="h-[9vh] w-[9vh] text-sky-300" />
        <p aria-live="assertive" className="text-[clamp(34px,7vh,86px)] leading-none font-black">
          {ACTION_TEXT[action]}
        </p>
      </div>
      <div className="h-[1vh] w-[40vw] overflow-hidden rounded-full bg-white/20">
        <div key={index} className="countdown-bar h-full bg-sky-400" style={{ animationDuration: `${windowMs}ms` }} />
      </div>
    </div>
  )
}

export function ChallengeOverlay({ vm, onPrompted }: { vm: ChallengeViewModel; onPrompted: (index: number) => void }) {
  const step = Math.min(vm.index + 1, vm.total)
  return (
    <>
      <div className="pointer-events-none absolute inset-x-0 top-[11vh] z-30 flex justify-center">
        <p className="rounded-full bg-black/75 px-6 py-2 text-[clamp(18px,3vh,36px)] font-semibold">
          {vm.retry ? 'One more try · ' : 'Quick check · '}
          {vm.phase === 'ready' ? `${vm.total} steps` : `Step ${step} of ${vm.total}`}
        </p>
      </div>
      <div className="pointer-events-none absolute inset-x-0 top-[78vh] z-30 flex flex-col items-center px-6 text-center">
        {vm.phase === 'ready' ? (
          <p className="text-shadow text-[clamp(28px,5.4vh,64px)] font-extrabold">Look at the camera and relax your face</p>
        ) : null}
        {vm.phase === 'prompt' && vm.action ? (
          <Prompt action={vm.action} index={vm.index} windowMs={vm.windowMs} onPrompted={onPrompted} />
        ) : null}
        {vm.phase === 'done' ? (
          <div className="pop-in flex items-center gap-4 rounded-3xl bg-black/80 px-8 py-3">
            <CheckIcon className="h-[7vh] w-[7vh] text-emerald-400" title="Done" />
            <p className="text-[clamp(30px,6vh,72px)] font-black">Good</p>
          </div>
        ) : null}
        {vm.phase === 'submitting' ? (
          <div className="flex items-center gap-4">
            <Spinner className="h-[5vh] w-[5vh]" />
            <p className="text-shadow text-[clamp(28px,5.4vh,64px)] font-bold">Checking…</p>
          </div>
        ) : null}
      </div>
    </>
  )
}
