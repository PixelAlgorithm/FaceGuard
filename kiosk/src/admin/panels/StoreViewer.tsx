/**
 * GET /v1/admin/store: shows EXACTLY which fields the edge keeps offline (SC2d "store only minimum
 * temporary information") and flags any field that looks like biometric payload.
 */
import { Card } from '../ui'

const SUSPICIOUS = /(image|frame|jpeg|jpg|png|crop|photo|embedding|template|depth_map|landmark|totp_value|card_id$)/i

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v)

function findRecords(body: unknown): { records: Obj[]; meta: Obj } {
  if (Array.isArray(body)) return { records: body.filter(isObj), meta: {} }
  if (!isObj(body)) return { records: [], meta: {} }
  for (const key of ['records', 'items', 'rows', 'decision_log', 'queue', 'sync_queue', 'pending']) {
    const v = body[key]
    if (Array.isArray(v)) {
      const meta = { ...body }
      delete meta[key]
      return { records: v.filter(isObj), meta }
    }
  }
  return { records: [], meta: { ...body } }
}

function collectKeys(v: unknown, prefix = '', out = new Set<string>()): Set<string> {
  if (Array.isArray(v)) v.forEach((x) => collectKeys(x, prefix, out))
  else if (isObj(v)) {
    for (const [k, x] of Object.entries(v)) {
      out.add(prefix + k)
      if (isObj(x) || Array.isArray(x)) collectKeys(x, `${prefix}${k}.`, out)
    }
  }
  return out
}

function cell(v: unknown): string {
  if (v === null || v === undefined) return '–'
  if (typeof v === 'string') return v.length > 24 && /^[0-9a-f]{24,}$/i.test(v) ? `${v.slice(0, 10)}…` : v
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  return JSON.stringify(v)
}

export function StoreViewer({ body, error, onRefresh }: { body: unknown; error: string | null; onRefresh: () => void }) {
  const { records, meta } = findRecords(body)
  // The edge declares its whitelist in `fields`; fall back to the union of record keys.
  const declared = Array.isArray(meta.fields) && meta.fields.every((f) => typeof f === 'string') ? (meta.fields as string[]) : null
  delete meta.fields
  const columns: string[] = declared ? [...declared] : []
  for (const r of records) for (const k of Object.keys(r)) if (!columns.includes(k)) columns.push(k)
  const keys = [...new Set([...(declared ?? []), ...collectKeys(records)])]
  const flagged = keys.filter((k) => SUSPICIOUS.test(k.split('.').pop() ?? ''))
  return (
    <Card
      title="Offline store (GET /v1/admin/store) – SC2 minimal data"
      actions={
        <button type="button" onClick={onRefresh} className="rounded px-2 py-0.5 text-xs ring-1 ring-black/15">
          Refresh
        </button>
      }
    >
      {error ? <p className="mb-2 text-sm text-[#d03b3b]">store error: {error}</p> : null}
      <div className="mb-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-[#52514e]">
        {Object.entries(meta).map(([k, v]) => (
          <span key={k}>
            {k}: <span className="font-mono text-[#0b0b0b]">{cell(v)}</span>
          </span>
        ))}
        <span>
          records: <span className="font-semibold text-[#0b0b0b]">{records.length}</span>
        </span>
      </div>
      <p
        className={`mb-2 rounded-md px-2 py-1 text-xs font-semibold ${
          flagged.length ? 'bg-[#fde2e1] text-[#8f1d1d]' : 'bg-[#e3f4e3] text-[#006300]'
        }`}
      >
        {flagged.length
          ? `Check: fields that look biometric: ${flagged.join(', ')}`
          : records.length
            ? `PASS: no image / crop / embedding / template fields among ${keys.length} stored field paths`
            : 'Queue empty (records are purged once the cloud acknowledges the sync).'}
      </p>
      {columns.length && records.length ? (
        <>
          <p className="mb-1 text-xs text-[#52514e]">
            Fields stored per decision{declared ? ' (edge whitelist)' : ''}:{' '}
            <span className="font-mono text-[#0b0b0b]">{columns.join(', ')}</span>
          </p>
          <div className="max-h-72 overflow-auto rounded border border-black/10">
            <table className="w-full text-left text-[11px]">
              <thead className="sticky top-0 bg-[#f0efec] text-[#52514e]">
                <tr>
                  {columns.map((c) => (
                    <th key={c} className="px-2 py-1 font-mono font-semibold whitespace-nowrap">
                      {c}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="font-mono">
                {records.map((r, i) => (
                  <tr key={String(r.attempt_id ?? i)} className="border-t border-[#e1e0d9] align-top">
                    {columns.map((c) => (
                      <td key={c} className="max-w-64 truncate px-2 py-1" title={JSON.stringify(r[c])}>
                        {cell(r[c])}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : null}
    </Card>
  )
}
