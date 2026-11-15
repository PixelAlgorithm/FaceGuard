/**
 * ?debug=1 live sensor overlay - lets the operator self-check the camera in ~10 s:
 * smile / open mouth / puff cheeks / blink must move the bars past the markers, and turning the head to
 * YOUR left must make yaw POSITIVE (dot moves left on this mirrored screen). If yaw goes the wrong way,
 * the camera stream is mirrored: reload with ?camflip=1.
 */
import { useEffect, useRef, useState } from 'react'
import type { FrameAnalysis, VisionEngine } from '../../capture/engine'
import { CAMERA_FLIPPED, DELEGATE_OVERRIDE, THRESHOLDS } from '../../config'
import type { KioskController } from '../controller'

const C = THRESHOLDS.challenge
const BARS: Array<{ key: 'mouthSmileLeft' | 'mouthSmileRight' | 'jawOpen' | 'cheekPuff' | 'eyeBlinkLeft' | 'eyeBlinkRight'; label: string; thr: number }> = [
  { key: 'mouthSmileLeft', label: 'smile L', thr: C.smileAbsMin },
  { key: 'mouthSmileRight', label: 'smile R', thr: C.smileAbsMin },
  { key: 'jawOpen', label: 'jawOpen', thr: C.jawOpenAbsMin },
  { key: 'cheekPuff', label: 'cheekPuff', thr: C.cheekPuffAbsMin },
  { key: 'eyeBlinkLeft', label: 'blink L', thr: C.blinkCloseMin },
  { key: 'eyeBlinkRight', label: 'blink R', thr: C.blinkCloseMin },
]

function Bar({ value, thr }: { value: number; thr: number }) {
  const ok = value >= thr
  return (
    <span className="relative inline-block h-3 w-40 overflow-hidden rounded bg-white/15 align-middle">
      <span className="absolute inset-y-0 left-0" style={{ width: `${Math.min(1, value) * 100}%`, background: ok ? '#34d399' : '#60a5fa' }} />
      <span className="absolute inset-y-[-2px] w-[2px] bg-amber-300" style={{ left: `${thr * 100}%` }} />
    </span>
  )
}

interface Sample {
  f: FrameAnalysis | null
  ch: ReturnType<KioskController['getDebugChallenge']>
  fps: number
  camFps: number
}

export function DebugOverlay({ engine, controller }: { engine: VisionEngine | null; controller: KioskController }) {
  const latest = useRef<FrameAnalysis | null>(null)
  const [sample, setSample] = useState<Sample>({ f: null, ch: null, fps: 0, camFps: 0 })

  useEffect(() => {
    if (!engine) return
    const stop = engine.onFrame((f) => {
      latest.current = f
    })
    const id = window.setInterval(
      () =>
        setSample({
          f: latest.current,
          ch: controller.getDebugChallenge(),
          fps: engine.processedFps(),
          camFps: engine.timingStats().fps,
        }),
      120,
    )
    return () => {
      stop()
      window.clearInterval(id)
    }
  }, [engine, controller])

  const { f, ch } = sample
  const face = f?.face ?? null
  const yaw = face?.yawDeg ?? 0
  const turnMin = C.turnYawMinDeg
  // Mirrored screen: the subject's left (+ yaw) is on the screen's LEFT.
  const dotLeft = 50 - Math.max(-45, Math.min(45, yaw)) * (50 / 45)
  return (
    <aside className="pointer-events-none fixed top-[13vh] right-[1.5vh] z-[80] w-[360px] rounded-xl bg-black/85 p-3 font-mono text-[11px] leading-tight text-white ring-1 ring-white/30">
      <div className="mb-1 font-bold text-amber-300">DEBUG (?debug=0 hides)</div>
      {!engine ? <div>engine not started</div> : null}
      {engine ? (
        <div className="text-white/80">
          engine {sample.fps.toFixed(1)} fps · camera {sample.camFps.toFixed(1)} fps · {engine.delegate}
          {DELEGATE_OVERRIDE ? ' (forced)' : ''}
          <br />
          detect {f ? f.diag.detectMs.toFixed(1) : '–'} ms · crop {f ? f.diag.cropMs.toFixed(1) : '–'} ms · ts={f?.diag.tsSource ?? '–'}
          <br />
          video {f ? `${f.width}×${f.height}` : '–'} · faces {f?.faceCount ?? 0} · blendshapes {f?.diag.nCategories ?? 0}/52
        </div>
      ) : null}
      <div className="mt-2 flex flex-col gap-1">
        {BARS.map((b) => {
          const v = face?.blend[b.key] ?? 0
          return (
            <div key={b.key} className="flex items-center gap-2">
              <span className="w-16">{b.label}</span>
              <Bar value={v} thr={b.thr} />
              <span className="w-10 text-right tabular-nums">{v.toFixed(2)}</span>
            </div>
          )
        })}
      </div>
      <div className="mt-2">
        <div className="flex justify-between text-white/70">
          <span>← YOUR LEFT (+)</span>
          <span>(−) YOUR RIGHT →</span>
        </div>
        <div className="relative mt-0.5 h-4 w-full rounded bg-white/15">
          <span className="absolute inset-y-0 w-[1px] bg-white/60" style={{ left: '50%' }} />
          <span className="absolute inset-y-0 w-[1px] bg-amber-300" style={{ left: `${50 - turnMin * (50 / 45)}%` }} />
          <span className="absolute inset-y-0 w-[1px] bg-amber-300" style={{ left: `${50 + turnMin * (50 / 45)}%` }} />
          <span
            className="absolute top-0.5 h-3 w-3 -translate-x-1/2 rounded-full"
            style={{ left: `${dotLeft}%`, background: Math.abs(yaw) >= turnMin ? '#34d399' : '#60a5fa' }}
          />
        </div>
        <div className="mt-0.5 tabular-nums">
          yaw {yaw >= 0 ? '+' : ''}
          {yaw.toFixed(1)}° · pitch {(face?.pitchDeg ?? 0).toFixed(1)}° · roll {(face?.rollDeg ?? 0).toFixed(1)}°
          <br />
          proxy {(face?.yawProxy ?? 0).toFixed(3)} · matrix yaw {f?.diag.matrixYawDeg?.toFixed(1) ?? '–'}° · camflip{' '}
          {CAMERA_FLIPPED ? 'ON' : 'off'}
        </div>
        <div className="mt-0.5 text-amber-200">Turn to YOUR left: yaw must go + (dot left). If not: reload with ?camflip=1</div>
      </div>
      <div className="mt-2 text-white/80">
        top: {(f?.diag.top ?? []).map(([n, v]) => `${n} ${v.toFixed(2)}`).join(' · ') || '–'}
      </div>
      {ch ? (
        <div className="mt-2 rounded bg-sky-900/70 p-1">
          challenge {ch.action} · {ch.armed ? 'armed' : 'waiting'} · frames {ch.frames} · baseline {ch.baseline.toFixed(2)} · peak{' '}
          {ch.peak === null ? '–' : ch.peak.toFixed(2)} · {ch.complete ? 'COMPLETE' : 'in progress'}
        </div>
      ) : null}
    </aside>
  )
}
