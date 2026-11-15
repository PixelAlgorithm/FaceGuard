/** Inline SVG icons (no icon fonts / CDN - the kiosk must render offline). */
import type { ReactNode } from 'react'
import type { ChallengeAction, FallbackMethod } from '../../api/types'

interface IconProps {
  className?: string
  title?: string
}

const stroke = {
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 2.4,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
}

function Svg({ className, title, children }: IconProps & { children: ReactNode }) {
  return (
    <svg viewBox="0 0 48 48" className={className} role={title ? 'img' : undefined} aria-hidden={title ? undefined : true}>
      {title ? <title>{title}</title> : null}
      {children}
    </svg>
  )
}

export function CheckIcon(p: IconProps) {
  return (
    <Svg {...p}>
      <circle cx="24" cy="24" r="21" {...stroke} />
      <path d="M14 24.5l7 7 13-14" {...stroke} strokeWidth={3.4} />
    </Svg>
  )
}

export function CrossIcon(p: IconProps) {
  return (
    <Svg {...p}>
      <circle cx="24" cy="24" r="21" {...stroke} />
      <path d="M16 16l16 16M32 16L16 32" {...stroke} strokeWidth={3.4} />
    </Svg>
  )
}

export function AlertIcon(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M24 5L44 41H4L24 5z" {...stroke} />
      <path d="M24 19v10" {...stroke} strokeWidth={3.4} />
      <circle cx="24" cy="35" r="1.9" fill="currentColor" />
    </Svg>
  )
}

export function Spinner({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 48 48" className={`spin ${className ?? ''}`} aria-hidden>
      <circle cx="24" cy="24" r="19" fill="none" stroke="currentColor" strokeOpacity="0.25" strokeWidth="5" />
      <path d="M24 5a19 19 0 0 1 19 19" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" />
    </svg>
  )
}

function FaceBase({ children, wide = false }: { children?: ReactNode; wide?: boolean }) {
  return (
    <>
      <ellipse cx="24" cy="25" rx={wide ? 19 : 16} ry="19" {...stroke} />
      {children}
    </>
  )
}

export function ChallengeIcon({ action, className }: { action: ChallengeAction; className?: string }) {
  switch (action) {
    case 'SMILE':
      return (
        <Svg className={className}>
          <FaceBase>
            <circle cx="18" cy="20" r="2" fill="currentColor" />
            <circle cx="30" cy="20" r="2" fill="currentColor" />
            <path d="M15.5 28c4.5 6.5 12.5 6.5 17 0" {...stroke} strokeWidth={3} />
          </FaceBase>
        </Svg>
      )
    case 'OPEN_MOUTH':
      return (
        <Svg className={className}>
          <FaceBase>
            <circle cx="18" cy="19" r="2" fill="currentColor" />
            <circle cx="30" cy="19" r="2" fill="currentColor" />
            <ellipse cx="24" cy="32" rx="5" ry="6.5" fill="currentColor" />
          </FaceBase>
        </Svg>
      )
    case 'PUFF_CHEEKS':
      return (
        <Svg className={className}>
          <FaceBase wide>
            <circle cx="18" cy="19" r="2" fill="currentColor" />
            <circle cx="30" cy="19" r="2" fill="currentColor" />
            <circle cx="12.5" cy="29" r="4.5" {...stroke} strokeWidth={2} />
            <circle cx="35.5" cy="29" r="4.5" {...stroke} strokeWidth={2} />
            <path d="M21 31.5h6" {...stroke} strokeWidth={3} />
          </FaceBase>
        </Svg>
      )
    case 'BLINK':
      return (
        <Svg className={className}>
          <FaceBase>
            <path d="M14.5 20.5c2 2.2 5 2.2 7 0M26.5 20.5c2 2.2 5 2.2 7 0" {...stroke} strokeWidth={2.6} />
            <path d="M19 32h10" {...stroke} strokeWidth={2.6} />
          </FaceBase>
        </Svg>
      )
    case 'TURN_LEFT':
    case 'TURN_RIGHT': {
      // The preview is mirrored, so the subject's left is on the screen's left.
      const left = action === 'TURN_LEFT'
      return (
        <Svg className={className}>
          <g transform={left ? undefined : 'translate(48 0) scale(-1 1)'}>
            <ellipse cx="28" cy="25" rx="13" ry="18" {...stroke} />
            <circle cx="22" cy="20" r="1.8" fill="currentColor" />
            <path d="M17.5 23l-2.5 5h4" {...stroke} strokeWidth={2} />
            <path d="M21 32h5" {...stroke} strokeWidth={2.4} />
            <path d="M12 8H3m0 0l4-4M3 8l4 4" {...stroke} strokeWidth={2.8} />
          </g>
        </Svg>
      )
    }
  }
}

export function MethodIcon({ method, className }: { method: FallbackMethod; className?: string }) {
  switch (method) {
    case 'TOTP':
      return (
        <Svg className={className}>
          <rect x="13" y="4" width="22" height="40" rx="4" {...stroke} />
          <path d="M19 15h10M19 22h10M19 29h6" {...stroke} />
          <circle cx="24" cy="38" r="1.6" fill="currentColor" />
        </Svg>
      )
    case 'CARD':
      return (
        <Svg className={className}>
          <rect x="4" y="11" width="40" height="27" rx="4" {...stroke} />
          <path d="M4 19h40" {...stroke} />
          <path d="M10 30h10" {...stroke} />
          <path d="M33 27c1.6 1.6 1.6 4.4 0 6M37 25c2.8 2.8 2.8 7.2 0 10" {...stroke} strokeWidth={2} />
        </Svg>
      )
    case 'EMAIL_OTP':
      return (
        <Svg className={className}>
          <rect x="4" y="10" width="40" height="28" rx="4" {...stroke} />
          <path d="M5 12l19 14 19-14" {...stroke} />
        </Svg>
      )
    case 'STAFF_OVERRIDE':
      return (
        <Svg className={className}>
          <path d="M24 4l17 6v12c0 11-7.5 18.5-17 22-9.5-3.5-17-11-17-22V10l17-6z" {...stroke} />
          <circle cx="24" cy="20" r="5" {...stroke} />
          <path d="M15.5 33c2-4.5 5-6.5 8.5-6.5s6.5 2 8.5 6.5" {...stroke} />
        </Svg>
      )
  }
}
