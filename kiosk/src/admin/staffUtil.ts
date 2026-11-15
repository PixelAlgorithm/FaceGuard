/** Helpers shared by the Staff & roles and API key panels (no components: fast refresh). */

/** Shown-once secrets (temporary passwords, API keys) disappear after this long. */
export const SECRET_VISIBLE_MS = 120_000
const TEMP_PASSWORD_LENGTH = 16
const TEMP_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'

/** Random temporary password (crypto RNG, unambiguous alphabet, rejection sampling for an unbiased pick). */
export function generateTempPassword(): string {
  const out: string[] = []
  const limit = 256 - (256 % TEMP_ALPHABET.length)
  while (out.length < TEMP_PASSWORD_LENGTH) {
    const buf = crypto.getRandomValues(new Uint8Array(32))
    for (const b of buf) if (b < limit && out.length < TEMP_PASSWORD_LENGTH) out.push(TEMP_ALPHABET[b % TEMP_ALPHABET.length])
  }
  return out.join('')
}

export const fmtWhen = (iso: string | null) => (iso ? new Date(iso).toLocaleString([], { hour12: false }) : '–')

