/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_EDGE_URL?: string
  readonly VITE_KIOSK_ID?: string
  readonly VITE_MOCK?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

/** config/thresholds.yaml parsed at build time by the plugin in vite.config.ts. */
declare module 'virtual:thresholds' {
  const thresholds: Record<string, unknown>
  export default thresholds
  export const THRESHOLDS_SOURCE: string
}

/** Demo users from config/schedule.example.json (id, display, role only). */
declare module 'virtual:demo-users' {
  const users: Array<{ user_id: string; display: string; role: string }>
  export default users
}
