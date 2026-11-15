/** Staff authentication for the privileged kiosk UIs (/admin, /operator, /register). Design v2 §F. */
export { AuthProvider, CLIENT_IDLE_SIGNOUT_MS, IDLE_SIGNOUT_TEXT, SESSION_EXPIRED_TEXT } from './AuthProvider'
export { useAuth, type AuthContextValue, type AuthStatusKind, type PendingAction } from './context'
export { LoginGate, NeedsPermission, RequirePermission, SignedInBadge } from './LoginGate'
export { LoginScreen } from './LoginScreen'
export { authErrorText } from './authErrorText'
export { EDGE_ROUTE_PERMISSION, PERM, needsText, type Permission } from './permissions'
export { clearSessionOnPublicRoute } from './publicKiosk'
export { isPrivilegedRoute } from './session'
