/** Selected mock scenario, shared across tabs (localStorage) and within the tab (custom event). */
import { useSyncExternalStore } from 'react'
import { getMockScenarioId, setMockScenarioId } from '../api/mock'

const EVENT = 'hid-mock-scenario'

function subscribe(cb: () => void) {
  window.addEventListener('storage', cb)
  window.addEventListener(EVENT, cb)
  return () => {
    window.removeEventListener('storage', cb)
    window.removeEventListener(EVENT, cb)
  }
}

export function selectMockScenario(id: string): void {
  setMockScenarioId(id)
  window.dispatchEvent(new Event(EVENT))
}

export function useMockScenario(): string {
  return useSyncExternalStore(subscribe, getMockScenarioId)
}
