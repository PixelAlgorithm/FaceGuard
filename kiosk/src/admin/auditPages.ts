/**
 * Paging helpers for the auth audit log (GET /v1/admin/auth/audit: newest first, `before_seq` exclusive,
 * `next_before_seq` = the cursor for the next older page or null). Every page ever received is merged by
 * `seq`, so a head poll that moves on (new entries) never opens a gap between the head and the older pages.
 */
import type { AuthAuditEntry } from '../api/authTypes'

/** Union of `held` and `page` by seq, newest first; the copy from `page` wins (an aggregated count grows). */
export function mergeAudit(held: readonly AuthAuditEntry[], page: readonly AuthAuditEntry[]): AuthAuditEntry[] {
  const bySeq = new Map<number, AuthAuditEntry>()
  for (const e of held) bySeq.set(e.seq, e)
  for (const e of page) bySeq.set(e.seq, e)
  return [...bySeq.values()].sort((a, b) => b.seq - a.seq)
}

/**
 * Cursor for "Load older": the last older page's cursor once one was loaded (null = exhausted), else the
 * cursor of the first head page (`firstHeadNext`; later heads move with new entries, the held set does not).
 */
export function olderCursor(lastOlderNext: number | null | undefined, firstHeadNext: number | null): number | null {
  return lastOlderNext === undefined ? firstHeadNext : lastOlderNext
}
