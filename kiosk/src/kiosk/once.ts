/** Wrap a cleanup (unsubscribe / restore) so that calling it again is a no-op (audit KF-09). */
export function once(fn: () => void): () => void {
  let done = false
  return () => {
    if (done) return
    done = true
    fn()
  }
}
