/** Operator-only mock scenario switcher on the kiosk (visible only when the mock edge is active). */
import { useState } from 'react'
import { MOCK_SCENARIOS } from '../../api/mockScenarios'
import { selectMockScenario, useMockScenario } from '../../shared/mockScenarioStore'

export function MockPanel() {
  const current = useMockScenario()
  const [open, setOpen] = useState(false)
  const scen = MOCK_SCENARIOS.find((s) => s.id === current)
  return (
    <div className="absolute top-[12vh] left-[2.2vh] z-[60] max-w-[34vw] text-sm">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="rounded-lg bg-fuchsia-700/90 px-3 py-1.5 font-semibold text-white shadow"
        aria-expanded={open}
      >
        MOCK · {scen?.label ?? current} {open ? '▾' : '▸'}
      </button>
      {open ? (
        <div className="mt-2 max-h-[55vh] overflow-auto rounded-xl bg-black/90 p-3 text-white ring-1 ring-fuchsia-500/60">
          <p className="mb-2 text-xs text-white/70">Keys 1–9, 0 select a scenario · Esc resets the kiosk</p>
          <ul className="flex flex-col gap-1">
            {MOCK_SCENARIOS.map((s, i) => (
              <li key={s.id}>
                <label className="flex cursor-pointer items-start gap-2 rounded px-1 py-0.5 hover:bg-white/10">
                  <input
                    type="radio"
                    name="mock-scenario"
                    checked={s.id === current}
                    onChange={() => selectMockScenario(s.id)}
                    className="mt-1"
                  />
                  <span>
                    <span className="font-mono text-fuchsia-300">{i < 10 ? `${(i + 1) % 10} ` : '  '}</span>
                    <span className="font-semibold">{s.label}</span>
                    <span className="block text-xs text-white/65">{s.hint}</span>
                  </span>
                </label>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  )
}
