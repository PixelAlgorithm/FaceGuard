/** Toast renderer (store: shared/toast.ts). */
import { useSyncExternalStore } from 'react'
import { dismissToast, subscribeToasts, toastSnapshot, type ToastTone } from './toast'

const TONE: Record<ToastTone, string> = {
  success: 'bg-[#0f5132] text-white ring-emerald-300/50',
  error: 'bg-[#8f1d1d] text-white ring-red-300/60',
  info: 'bg-[#1f2937] text-white ring-white/30',
}

export function Toaster() {
  const list = useSyncExternalStore(subscribeToasts, toastSnapshot)
  return (
    <div className="pointer-events-none fixed right-4 bottom-4 z-[200] flex w-[min(28rem,calc(100vw-2rem))] flex-col gap-2" aria-live="polite" role="status">
      {list.map((t) => (
        <div key={t.id} className={`pointer-events-auto flex items-start gap-3 rounded-xl px-4 py-3 text-sm shadow-lg ring-1 ${TONE[t.tone]}`}>
          <span className="font-bold">{t.tone === 'success' ? 'Done' : t.tone === 'error' ? 'Error' : 'Note'}</span>
          <span className="min-w-0 flex-1 break-words">{t.text}</span>
          <button type="button" className="text-white/80 hover:text-white" aria-label="Dismiss" onClick={() => dismissToast(t.id)}>
            ×
          </button>
        </div>
      ))}
    </div>
  )
}
