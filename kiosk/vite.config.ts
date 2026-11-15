import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv, type HtmlTagDescriptor, type Plugin } from 'vite'
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

const DEFAULT_EDGE_URL = 'http://127.0.0.1:8000'

function originOf(url: string): string {
  try {
    return new URL(url).origin
  } catch {
    throw new Error(`CSP: not a URL: ${url}`)
  }
}

/**
 * Content-Security-Policy <meta> (design v2 §F). connect-src = 'self' + the configured edge origin
 * (VITE_EDGE_URL, default http://127.0.0.1:8000) + optional extra origins (VITE_CSP_CONNECT_SRC, comma-separated).
 * script-src 'self' 'wasm-unsafe-eval': MediaPipe Face Landmarker compiles its WebAssembly at runtime.
 * worker-src 'self' blob:: MediaPipe's loader may start a blob worker. The dev server additionally needs
 * 'unsafe-inline' scripts (React fast-refresh preamble) and ws: for HMR; production builds never get them.
 */
export function buildCsp(edgeUrl: string, extra: readonly string[], dev: boolean): string {
  const connect = [...new Set(["'self'", originOf(edgeUrl), ...extra.map(originOf), ...(dev ? ['ws:', 'wss:'] : [])])]
  const script = ["'self'", "'wasm-unsafe-eval'", ...(dev ? ["'unsafe-inline'"] : [])]
  return [
    "default-src 'self'",
    `connect-src ${connect.join(' ')}`,
    "img-src 'self' data: blob:",
    "media-src 'self' blob:",
    `script-src ${script.join(' ')}`,
    "worker-src 'self' blob:",
    "style-src 'self' 'unsafe-inline'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; ')
}

function cspMeta(): Plugin {
  let csp = ''
  return {
    name: 'hid-csp',
    configResolved(config) {
      const env = loadEnv(config.mode, config.envDir || kioskDir, 'VITE_')
      const extra = (env.VITE_CSP_CONNECT_SRC ?? '').split(',').map((x) => x.trim()).filter(Boolean)
      csp = buildCsp(env.VITE_EDGE_URL || DEFAULT_EDGE_URL, extra, config.command === 'serve')
    },
    transformIndexHtml: {
      order: 'post',
      handler(): HtmlTagDescriptor[] {
        return [{ tag: 'meta', attrs: { 'http-equiv': 'Content-Security-Policy', content: csp }, injectTo: 'head-prepend' }]
      },
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [cspMeta(), thresholdsYaml(), demoUsers(), react(), tailwindcss()],
  server: { port: 5173, strictPort: true },
  preview: { port: 4173, strictPort: true },
  build: { chunkSizeWarningLimit: 1600 },
})
