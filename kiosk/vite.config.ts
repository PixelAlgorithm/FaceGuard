import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig, type Plugin } from 'vite'
import { parse } from 'yaml'

const kioskDir = path.dirname(fileURLToPath(import.meta.url))
const thresholdsPath = path.resolve(kioskDir, process.env.HID_THRESHOLDS_YAML ?? '../config/thresholds.yaml')

/**
 * Exposes config/thresholds.yaml (the single source of truth for every threshold) as the virtual
 * module `virtual:thresholds`, parsed at build time. The kiosk only uses these values as ADVISORY
 * client-side gates; the edge service re-checks everything authoritatively.
 */
function thresholdsYaml(): Plugin {
  const publicId = 'virtual:thresholds'
  const resolvedId = '\0' + publicId
  return {
    name: 'hid-thresholds-yaml',
    resolveId(id) {
      return id === publicId ? resolvedId : null
    },
    load(id) {
      if (id !== resolvedId) return null
      this.addWatchFile(thresholdsPath)
      const parsed: unknown = parse(readFileSync(thresholdsPath, 'utf8'))
      if (!parsed || typeof parsed !== 'object') {
        throw new Error(`thresholds.yaml did not parse to an object: ${thresholdsPath}`)
      }
      const source = path.relative(kioskDir, thresholdsPath)
      return `export default ${JSON.stringify(parsed)};\nexport const THRESHOLDS_SOURCE = ${JSON.stringify(source)};\n`
    },
  }
}

const schedulePath = path.resolve(kioskDir, process.env.HID_SCHEDULE_JSON ?? '../config/schedule.example.json')

/**
 * Exposes the demo users of config/schedule.example.json as `virtual:demo-users` (id, display name, role
 * ONLY - no card hashes, codes or other bundle secrets) so /admin can enrol teammates under those ids.
 */
function demoUsers(): Plugin {
  const publicId = 'virtual:demo-users'
  const resolvedId = '\0' + publicId
  return {
    name: 'hid-demo-users',
    resolveId(id) {
      return id === publicId ? resolvedId : null
    },
    load(id) {
      if (id !== resolvedId) return null
      this.addWatchFile(schedulePath)
      let users: Array<{ user_id: string; display: string; role: string }> = []
      try {
        const doc = JSON.parse(readFileSync(schedulePath, 'utf8')) as { users?: Record<string, { display?: string; role?: string }> }
        users = Object.entries(doc.users ?? {}).map(([uid, u]) => ({ user_id: uid, display: u.display ?? uid, role: u.role ?? 'student' }))
      } catch {
        users = []
      }
      return `export default ${JSON.stringify(users)};\n`
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [thresholdsYaml(), demoUsers(), react(), tailwindcss()],
  server: { port: 5173, strictPort: true },
  preview: { port: 4173, strictPort: true },
  build: { chunkSizeWarningLimit: 1600 },
})
