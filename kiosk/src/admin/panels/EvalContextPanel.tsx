/** Eval harness context: POST/DELETE /v1/admin/eval/context (tags subsequent attempts on the edge). */
import { useState, useSyncExternalStore } from 'react'
import { EVAL_CONDITIONS, EVAL_LABELS, SPLITS, getApi, type EvalCondition, type EvalContext, type EvalLabel, type Split } from '../../api'
import { STORAGE_KEYS, getEvalContextLocal, writeLocal } from '../../config'
import { ActionButton, Card } from '../ui'

function subscribeStorage(cb: () => void) {
  window.addEventListener('storage', cb)
  window.addEventListener('hid-eval-context', cb)
  return () => {
    window.removeEventListener('storage', cb)
    window.removeEventListener('hid-eval-context', cb)
  }
}

/** Exactly edge/schemas.py EvalContext: condition Literal['normal','dim','backlit','far'] (anything else is a 422). */
const CONDITION_HELP: Record<EvalCondition, string> = {
  normal: 'office light, ~50 cm',
  dim: 'low light',
  backlit: 'window / lamp behind the subject',
  far: 'at the edge of the face-size gate',
}

function today(): string {
  const d = new Date()
  return `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`
}

const input = 'w-full rounded-lg border border-black/20 bg-white px-2 py-1 text-sm'

/** A context stored by an older build may carry values the edge rejects (e.g. condition "office"). */
function sanitize(raw: string | null): EvalContext {
  const base: EvalContext = { run_id: `run_${today()}_1`, subject_id: 'S01', label: 'bona_fide', condition: 'normal', split: 'dev' }
  if (!raw) return base
  try {
    const o = JSON.parse(raw) as Partial<Record<keyof EvalContext, unknown>>
    return {
      run_id: typeof o.run_id === 'string' && o.run_id ? o.run_id : base.run_id,
      subject_id: typeof o.subject_id === 'string' && o.subject_id ? o.subject_id : base.subject_id,
      label: (EVAL_LABELS as readonly unknown[]).includes(o.label) ? (o.label as EvalLabel) : base.label,
      condition: (EVAL_CONDITIONS as readonly unknown[]).includes(o.condition) ? (o.condition as EvalCondition) : base.condition,
      split: (SPLITS as readonly unknown[]).includes(o.split) ? (o.split as Split) : base.split,
    }
  } catch {
    return base
  }
}

export function EvalContextPanel({ token }: { token: string }) {
  const api = getApi()
  const currentRaw = useSyncExternalStore(subscribeStorage, getEvalContextLocal)
  const [ctx, setCtx] = useState<EvalContext>(() => sanitize(currentRaw))
  const set = <K extends keyof EvalContext>(k: K, v: EvalContext[K]) => setCtx((c) => ({ ...c, [k]: v }))
  const publish = (value: EvalContext | null) => {
    writeLocal(STORAGE_KEYS.evalContext, value ? JSON.stringify(value) : null)
    window.dispatchEvent(new Event('hid-eval-context'))
  }
  return (
    <Card title="Eval context (ISO 30107-3 labelling)">
      <div className="grid grid-cols-2 gap-2 text-sm">
        <label className="col-span-2">
          <span className="text-xs text-[#52514e]">run_id</span>
          <input className={input} value={ctx.run_id} onChange={(e) => set('run_id', e.target.value)} />
        </label>
        <label>
          <span className="text-xs text-[#52514e]">subject_id</span>
          <input className={input} value={ctx.subject_id} onChange={(e) => set('subject_id', e.target.value)} />
        </label>
        <label>
          <span className="text-xs text-[#52514e]">label (PAI species)</span>
          <select className={input} value={ctx.label} onChange={(e) => set('label', e.target.value as EvalLabel)}>
            {EVAL_LABELS.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="text-xs text-[#52514e]">condition</span>
          <select className={input} value={ctx.condition} onChange={(e) => set('condition', e.target.value as EvalCondition)}>
            {EVAL_CONDITIONS.map((l) => (
              <option key={l} value={l}>
                {l} · {CONDITION_HELP[l]}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="text-xs text-[#52514e]">split</span>
          <select className={input} value={ctx.split} onChange={(e) => set('split', e.target.value as Split)}>
            {SPLITS.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="mt-3 flex flex-wrap items-start gap-2">
        <ActionButton
          label="Set eval context"
          tone="primary"
          disabled={!token || !ctx.run_id.trim() || !ctx.subject_id.trim() || ctx.run_id.length > 64 || ctx.subject_id.length > 64}
          run={async () => {
            const r = await api.setEvalContext(token, { ...ctx, run_id: ctx.run_id.trim(), subject_id: ctx.subject_id.trim() })
            publish(ctx)
            return r
          }}
        />
        <ActionButton
          label="Clear"
          disabled={!token}
          run={async () => {
            const r = await api.clearEvalContext(token)
            publish(null)
            return r
          }}
        />
      </div>
      <p className="mt-2 text-xs text-[#898781]">
        Active (set from this browser):{' '}
        <span className="font-mono text-[#0b0b0b]">{currentRaw ? currentRaw : 'none – attempts are unlabelled'}</span>
      </p>
    </Card>
  )
}
