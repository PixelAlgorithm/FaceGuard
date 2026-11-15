/** Tiny toast store (no dependency): success / error / info messages, auto-dismiss, screen-reader live region. */

export type ToastTone = 'success' | 'error' | 'info'

export interface ToastItem {
  id: number
  tone: ToastTone
  text: string
}

let items: ToastItem[] = []
let nextId = 1
const listeners = new Set<() => void>()

function emit() {
  listeners.forEach((l) => l())
}

export function dismissToast(id: number): void {
  items = items.filter((t) => t.id !== id)
  emit()
}

function push(tone: ToastTone, text: string, ms: number): void {
  const id = nextId++
  items = [...items.slice(-4), { id, tone, text }]
  emit()
  window.setTimeout(() => dismissToast(id), ms)
}

export const toast = {
  success: (text: string) => push('success', text, 5000),
  info: (text: string) => push('info', text, 5000),
  /** errors stay longer: no silent failures */
  error: (text: string) => push('error', text, 10000),
}

export const subscribeToasts = (l: () => void) => {
  listeners.add(l)
  return () => listeners.delete(l)
}
export const toastSnapshot = () => items

