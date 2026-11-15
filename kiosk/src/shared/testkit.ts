/**
 * Minimal test helpers for the kiosk's pure-logic unit tests (*.test.ts), runnable with plain Node
 * (`node --test "src/**\/*.test.ts"`, native type stripping). No node: imports, so the files also type-check
 * under the browser tsconfig. A failing check throws, which fails the test file.
 */

const failures: string[] = []

/** Run one named check synchronously; failures are collected and reported by done(). */
export function test(name: string, fn: () => void): void {
  try {
    fn()
  } catch (e) {
    failures.push(`${name}: ${e instanceof Error ? e.message : String(e)}`)
  }
}

function show(v: unknown): string {
  try {
    return JSON.stringify(v)
  } catch {
    return String(v)
  }
}

/** Structural equality on JSON-like values (key order independent). */
function same(a: unknown, b: unknown): boolean {
  if (a === b) return true
  if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) return false
  if (Array.isArray(a) !== Array.isArray(b)) return false
  const ka = Object.keys(a)
  const kb = Object.keys(b)
  if (ka.length !== kb.length) return false
  return ka.every((k) => same((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]))
}

export function eq(actual: unknown, expected: unknown, what = 'value'): void {
  if (!same(actual, expected)) throw new Error(`${what}: expected ${show(expected)}, got ${show(actual)}`)
}

export function ok(cond: boolean, what: string): void {
  if (!cond) throw new Error(what)
}

/** Call at the end of a test file: throws (non-zero exit) when any check failed. */
export function done(file: string): void {
  if (failures.length) throw new Error(`${file}: ${failures.length} failing check(s)\n  - ${failures.join('\n  - ')}`)
}
