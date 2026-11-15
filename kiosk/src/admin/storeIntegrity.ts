/**
 * SC2 offline-store integrity verdict for GET /v1/admin/store (audit KAO-07). The banner must never say
 * PASS for a broken hash chain or an undecryptable (tampered) row: `ok` is true only when the edge
 * explicitly reports chain_ok:true, no bad sequence numbers and no row carries an `error`, and the body is
 * fresh (`stale`: the last refresh failed, so an older PASS is not shown as current).
 */

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v)

export interface StoreIntegrity {
  /** true = verified intact, false = tampered / broken, null = the edge did not report the chain state */
  ok: boolean | null
  badSeq: number[]
  errorRows: number
  problems: string[]
}

export function storeIntegrity(body: unknown, opts: { stale?: boolean } = {}): StoreIntegrity {
  const o = isObj(body) ? body : {}
  const badSeq = Array.isArray(o.chain_bad_seq) ? o.chain_bad_seq.filter((x): x is number => typeof x === 'number') : []
  const records = Array.isArray(o.records) ? o.records.filter(isObj) : []
  const errorRows = records.filter((r) => r.error !== undefined && r.error !== null).length
  const problems: string[] = []
  if (o.chain_ok === false) problems.push('hash chain broken')
  if (badSeq.length) problems.push(`bad sequence numbers: ${badSeq.join(', ')}`)
  if (errorRows) problems.push(`${errorRows} row(s) could not be decrypted (tampered?)`)
  if (problems.length) return { ok: false, badSeq, errorRows, problems }
  if (o.chain_ok !== true) return { ok: null, badSeq, errorRows, problems: ['the edge did not report the hash-chain state'] }
  if (opts.stale) return { ok: null, badSeq, errorRows, problems: ['the last refresh failed: this is older data'] }
  return { ok: true, badSeq, errorRows, problems }
}
