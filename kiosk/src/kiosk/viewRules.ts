/**
 * Pure rules over the kiosk view (no runtime imports), unit-tested with plain Node.
 *
 * KF-10: once frames, challenge evidence or a fallback code are with the edge, the edge decides and logs that
 * decision (an ALLOW consumes a TOTP step or a one-time override code). A user Cancel / operator Esc in that
 * window would drop the answer and show nothing, so it is refused until the response arrives. Capturing is
 * still cancellable: the capture is aborted before anything is sent for a decision.
 */
export interface ViewState {
  kind: string
  busy?: boolean
  phase?: string
}

export function userCancelAllowed(v: ViewState): boolean {
  if (v.kind === 'deciding') return false
  if (v.kind === 'fallback') return v.busy !== true
  if (v.kind === 'challenge') return v.phase !== 'submitting'
  return true
}
