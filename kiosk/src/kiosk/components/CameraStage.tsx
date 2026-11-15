/**
 * Full-screen mirrored camera preview + large face oval. During the 1 s colour flash an OPAQUE
 * full-viewport fill covers the screen so the maximum light reaches the face; the live preview shrinks to
 * a small inset above the fill (the person stays framed and the video stays composited, so
 * requestVideoFrameCallback keeps firing at full rate).
 */
import { useEffect, useRef } from 'react'
import type { VisionEngine } from '../../capture/engine'
import type { KioskController } from '../controller'

export type OvalTone = 'idle' | 'guide' | 'ok' | 'busy' | 'challenge'

const RING: Record<OvalTone, string> = {
  idle: 'rgba(255,255,255,0.55)',
  guide: '#f2a900',
  ok: '#34d399',
  busy: 'rgba(255,255,255,0.85)',
  challenge: '#60a5fa',
}

export function CameraStage({
  engine,
  controller,
  tone,
  progress,
  visible,
  inset,
}: {
  engine: VisionEngine | null
  controller: KioskController
  tone: OvalTone
  progress: number
  visible: boolean
  inset: boolean
}) {
  const holder = useRef<HTMLDivElement>(null)
  const fill = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const el = holder.current
    if (!el || !engine) return
    return engine.attachPreview(el)
  }, [engine])

  useEffect(() => {
    // Direct DOM writes (no React render) so the colour lands in the rAF that the capture timestamps.
    controller.setTintSink((color) => {
      const f = fill.current
      if (!f) return
      if (color) {
        f.style.backgroundColor = color
        f.style.opacity = '1'
      } else {
        f.style.opacity = '0'
      }
    })
    return () => controller.setTintSink(null)
  }, [controller])

  return (
    <div className="absolute inset-0 overflow-hidden bg-black" aria-hidden>
      <div
        ref={holder}
        className={
          inset
            ? 'fixed top-[3vh] left-1/2 z-[47] h-[18vh] w-[32vh] -translate-x-1/2 overflow-hidden rounded-2xl ring-4 ring-white/80'
            : 'absolute inset-0'
        }
      />
      <div className="face-oval" style={{ opacity: visible ? 1 : 0 }} />
      <svg className="face-ring" viewBox="0 0 100 136" preserveAspectRatio="none" style={{ opacity: visible ? 1 : 0 }}>
        <ellipse
          cx="50"
          cy="68"
          rx="49"
          ry="67"
          fill="none"
          stroke={RING[tone]}
          vectorEffect="non-scaling-stroke"
          style={{ strokeWidth: 6 }}
        />
        {progress > 0 ? (
          <ellipse
            cx="50"
            cy="68"
            rx="49"
            ry="67"
            fill="none"
            stroke="#34d399"
            pathLength={100}
            strokeDasharray="100"
            strokeDashoffset={100 - progress * 100}
            vectorEffect="non-scaling-stroke"
            style={{ strokeWidth: 12, transition: 'stroke-dashoffset 90ms linear' }}
            transform="rotate(-90 50 68)"
          />
        ) : null}
      </svg>
      <div ref={fill} className="flash-fill" />
    </div>
  )
}
