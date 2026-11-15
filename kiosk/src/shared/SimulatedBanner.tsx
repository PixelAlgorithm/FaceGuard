/** Unmissable "SIMULATED" marker on every route while this tab uses the in-browser mock edge (?mock=1). */
import { MOCK_ENABLED, exitMockHref } from '../config'

export function SimulatedBanner() {
  if (!MOCK_ENABLED) return null
  return (
    <div className="fixed bottom-3 left-3 z-[190] flex items-center gap-3 rounded-full bg-fuchsia-700 px-4 py-2 text-sm font-bold text-white shadow-lg ring-2 ring-fuchsia-300">
      <span className="tracking-wider">SIMULATED EDGE</span>
      <span className="font-normal text-white/85">decisions and latencies are fake (this tab only)</span>
      <a href={exitMockHref()} className="rounded-full bg-white px-3 py-0.5 text-fuchsia-800 hover:bg-fuchsia-100">
        Exit
      </a>
    </div>
  )
}
