/**
 * Staff session token storage (design v2 §F). The token lives in a module variable; it is persisted to
 * sessionStorage `hid.session` ONLY while the page path is /admin, /operator or /register, so a reload of
 * a staff console keeps the sign-in but the public kiosk tab never holds a credential. The public kiosk
 * route ("/") wipes hid.session and the legacy hid.adminToken and ends the session on the edge
 * (audit KAO-02 / KAO-M1).
 */
import { STORAGE_KEYS } from '../../config'

const PRIVILEGED_PATH = /\/(admin|operator|register)\/?$/

let memoryToken = ''
/** KAUTH-02: last pointer / keyboard input (ms epoch), persisted next to the token so a reload keeps the idle clock */
const LAST_INPUT_KEY = `${STORAGE_KEYS.session}.lastInput`

/** /admin, /operator, /register by PATH (hash routes never count: they render on the public origin path). */
export function isPrivilegedRoute(pathname: string = window.location.pathname): boolean {
  return PRIVILEGED_PATH.test(pathname)
}

function readStored(key: string): string {
  try {
    return window.sessionStorage.getItem(key) ?? ''
  } catch {
    return ''
  }
}

function removeStored(key: string): void {
  try {
    window.sessionStorage.removeItem(key)
  } catch {
    /* storage unavailable: nothing persisted */
  }
}

/** The current token: memory first, then (privileged routes only) the tab's sessionStorage. */
export function getSessionToken(): string {
  if (memoryToken) return memoryToken
  if (!isPrivilegedRoute()) return ''
  memoryToken = readStored(STORAGE_KEYS.session)
  return memoryToken
}

export function setSessionToken(token: string): void {
  memoryToken = token
  if (!token || !isPrivilegedRoute()) {
    removeStored(STORAGE_KEYS.session)
    removeStored(LAST_INPUT_KEY)
    return
  }
  try {
    window.sessionStorage.setItem(STORAGE_KEYS.session, token)
  } catch {
    /* private mode: the session stays in memory only (lost on reload) */
  }
}

export function clearSessionToken(): void {
  setSessionToken('')
}

/**
 * Public kiosk route: forget every staff credential in this tab and return the one that was there (so the
 * caller can POST /v1/auth/logout with it). Idempotent.
 */
export function takeAndClearStoredCredentials(): string {
  const token = memoryToken || readStored(STORAGE_KEYS.session)
  memoryToken = ''
  removeStored(STORAGE_KEYS.session)
  removeStored(LAST_INPUT_KEY)
  removeStored(STORAGE_KEYS.adminToken)
  return token
}

/** The persisted last-input time (string ms epoch) of this tab's session, or null. Privileged routes only. */
export function getStoredLastInput(): string | null {
  if (!isPrivilegedRoute()) return null
  try {
    return window.sessionStorage.getItem(LAST_INPUT_KEY)
  } catch {
    return null
  }
}

/** Persist the last-input time with the session (privileged routes only, like the token). */
export function setStoredLastInput(at: number): void {
  if (!isPrivilegedRoute() || !memoryToken) return
  try {
    window.sessionStorage.setItem(LAST_INPUT_KEY, String(at))
  } catch {
    /* private mode: the idle clock then restarts only together with the in-memory token */
  }
}
