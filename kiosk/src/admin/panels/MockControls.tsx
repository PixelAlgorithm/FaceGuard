/** Mock edge scenario switcher (only rendered when the in-browser mock is active). */
import { resetMockState } from '../../api/mock'
import { resetMockAccess } from '../../api/mockAccess'
import { MOCK_CREDENTIALS, MOCK_SCENARIOS } from '../../api/mockScenarios'
import { refreshMode } from '../../shared/modeStore'
import { selectMockScenario, useMockScenario } from '../../shared/mockScenarioStore'
import { Card } from '../ui'

export function MockControls() {
  const current = useMockScenario()
  return (
    <Card
      title="Mock edge scenario"
      actions={
        <button
          type="button"
          onClick={() => {
            resetMockState()
            resetMockAccess()
            window.dispatchEvent(new Event('hid-mock-scenario'))
            refreshMode()
          }}
          className="rounded px-2 py-0.5 text-xs ring-1 ring-black/15"
        >
          Reset mock state
        </button>
      }
    >
      <p className="mb-2 text-xs text-[#8a2a8a]">
        In-browser mock (VITE_MOCK=1 / ?mock=1). Latencies are simulated – never quote them.
      </p>
      <ul className="flex flex-col gap-1">
        {MOCK_SCENARIOS.map((s, i) => (
          <li key={s.id}>
            <label className="flex cursor-pointer items-start gap-2 rounded px-1 py-0.5 text-sm hover:bg-[#f0efec]">
              <input
                type="radio"
                name="admin-mock-scenario"
                checked={current === s.id}
                onChange={() => {
                  selectMockScenario(s.id)
                  refreshMode()
                }}
                className="mt-1"
              />
              <span>
                <span className="font-mono text-xs text-[#898781]">{i < 10 ? `[${(i + 1) % 10}] ` : ''}</span>
                <span className="font-semibold">{s.label}</span>
                <span className="block text-xs text-[#52514e]">{s.hint}</span>
              </span>
            </label>
          </li>
        ))}
      </ul>
      <p className="mt-2 font-mono text-xs text-[#52514e]">
        codes: TOTP {MOCK_CREDENTIALS.TOTP} · EMAIL {MOCK_CREDENTIALS.EMAIL_OTP} · STAFF any id + {MOCK_CREDENTIALS.STAFF_OVERRIDE} · CARD{' '}
        {MOCK_CREDENTIALS.CARD}
      </p>
    </Card>
  )
}
