/**
 * The public kiosk route ("/") must never hold a staff credential (audit KAO-02 / KAO-M1): wipe the tab's
 * hid.session and the legacy hid.adminToken, and end the session on the edge if one was there.
 */
import { getApi } from '../../api'
import { isSessionToken } from '../../api/credentials'
import { takeAndClearStoredCredentials } from './session'

export function clearSessionOnPublicRoute(): void {
  const token = takeAndClearStoredCredentials()
  if (token && isSessionToken(token)) void getApi().logout(token).catch(() => undefined)
}
