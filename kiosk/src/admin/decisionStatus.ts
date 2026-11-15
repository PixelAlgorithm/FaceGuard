/** Status palette (dataviz reference: good / warning / critical) + labels for the three outcomes. */
import { AlertIcon, CheckIcon, CrossIcon } from '../kiosk/components/Icons'

export const STATUS = {
  ALLOW: { fill: '#0ca30c', ink: '#ffffff', label: 'ALLOW', sub: null as string | null, Icon: CheckIcon },
  STEP_UP: { fill: '#fab219', ink: '#0b0b0b', label: 'REQUEST VERIFICATION', sub: 'step-up' as string | null, Icon: AlertIcon },
  DENY: { fill: '#d03b3b', ink: '#ffffff', label: 'DENY', sub: null as string | null, Icon: CrossIcon },
} as const
