/** Decision chip for the dashboard: status colour + icon + text label (never colour alone). */
import type { Decision } from '../api/types'
import { STATUS } from './decisionStatus'

export function DecisionChip({ decision, compact = false }: { decision: Decision; compact?: boolean }) {
  const s = STATUS[decision]
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-bold whitespace-nowrap"
      style={{ background: s.fill, color: s.ink }}
      title={decision}
    >
      <s.Icon className="h-3.5 w-3.5" />
      {compact && decision === 'STEP_UP' ? 'REQ. VERIFICATION' : s.label}
      {s.sub && !compact ? <span className="font-medium opacity-80">· {s.sub}</span> : null}
    </span>
  )
}
