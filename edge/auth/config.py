"""Auth policy settings (AUTH_* environment variables), validated at startup with clear errors."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from edge.auth.rbac import EDGE_ROLES

MIB = 1024 * 1024
LEGACY_FLAG_VAR = "AUTH_LEGACY_ADMIN_TOKEN"
DEFAULT_MFA_REQUIRED_ROLES: frozenset[str] = frozenset({"admin", "security_officer"})
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off", ""})

# name -> (default, minimum, maximum)
_INT_VARS: Mapping[str, tuple[int, int, int]] = {
    "AUTH_SESSION_IDLE_MIN": (30, 1, 24 * 60),
    "AUTH_SESSION_MAX_HOURS": (12, 1, 72),
    "AUTH_MAX_SESSIONS_PER_USER": (5, 1, 50),
    "AUTH_LOCKOUT_THRESHOLD": (5, 1, 100),
    "AUTH_LOCKOUT_MIN": (15, 1, 24 * 60),
    "AUTH_LOGIN_GLOBAL_MAX": (60, 1, 100_000),
    "AUTH_LOGIN_GLOBAL_WINDOW_MIN": (5, 1, 24 * 60),
    "AUTH_AUDIT_MAX_BYTES": (5 * MIB, 64 * 1024, 1024 * MIB),
    "AUTH_AUDIT_KEEP": (5, 1, 100),
}


@dataclass(frozen=True)
class AuthConfig:
    session_idle_min: int = 30
    session_max_hours: int = 12
    max_sessions_per_user: int = 5
    lockout_threshold: int = 5   # failures before the progressive per-username delay starts
    lockout_min: int = 15        # cap of that delay
    login_global_max: int = 60   # all login attempts, all usernames, per window
    login_global_window_min: int = 5
    legacy_admin_token_enabled: bool = False
    legacy_admin_token: str = field(default="", repr=False)
    mfa_required_roles: frozenset[str] = DEFAULT_MFA_REQUIRED_ROLES
    demo_mode: bool = False
    audit_max_bytes: int = 5 * MIB
    audit_keep: int = 5

    @property
    def idle_timeout_s(self) -> int:
        return self.session_idle_min * 60

    @property
    def max_session_s(self) -> int:
        return self.session_max_hours * 3600

    @property
    def lockout_cap_s(self) -> int:
        return self.lockout_min * 60

    @property
    def login_global_window_s(self) -> int:
        return self.login_global_window_min * 60

    @classmethod
    def from_env(cls, env: Mapping[str, str], *, legacy_admin_token: str = "") -> AuthConfig:
        """Build from AUTH_* variables. Raises ValueError naming the offending variable."""
        ints = {name: _int_var(env, name, *spec) for name, spec in _INT_VARS.items()}
        legacy = legacy_token_enabled(env)
        if legacy and not legacy_admin_token:
            raise ValueError("AUTH_LEGACY_ADMIN_TOKEN=1 requires a non-empty ADMIN_TOKEN")
        if ints["AUTH_SESSION_IDLE_MIN"] > ints["AUTH_SESSION_MAX_HOURS"] * 60:
            raise ValueError("AUTH_SESSION_IDLE_MIN must not exceed AUTH_SESSION_MAX_HOURS * 60")
        return cls(
            session_idle_min=ints["AUTH_SESSION_IDLE_MIN"],
            session_max_hours=ints["AUTH_SESSION_MAX_HOURS"],
            max_sessions_per_user=ints["AUTH_MAX_SESSIONS_PER_USER"],
            lockout_threshold=ints["AUTH_LOCKOUT_THRESHOLD"],
            lockout_min=ints["AUTH_LOCKOUT_MIN"],
            login_global_max=ints["AUTH_LOGIN_GLOBAL_MAX"],
            login_global_window_min=ints["AUTH_LOGIN_GLOBAL_WINDOW_MIN"],
            legacy_admin_token_enabled=legacy,
            legacy_admin_token=legacy_admin_token if legacy else "",
            mfa_required_roles=_roles_var(env, "AUTH_MFA_REQUIRED_ROLES"),
            demo_mode=_bool_var(env, "DEMO_MODE", default=False),
            audit_max_bytes=ints["AUTH_AUDIT_MAX_BYTES"],
            audit_keep=ints["AUTH_AUDIT_KEEP"],
        )


def legacy_token_enabled(env: Mapping[str, str]) -> bool:
    """AUTH_LEGACY_ADMIN_TOKEN parsed exactly as AuthConfig.from_env parses it (for CORS and health callers).
    Raises ValueError naming the variable for an unrecognised value."""
    return _bool_var(env, LEGACY_FLAG_VAR, default=False)


def _int_var(env: Mapping[str, str], name: str, default: int, low: int, high: int) -> int:
    raw = (env.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw[:20]!r}") from None
    if not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high}, got {value}")
    return value


def _bool_var(env: Mapping[str, str], name: str, *, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ValueError(f"{name} must be 0/1 (or true/false), got {raw[:20]!r}")


def _roles_var(env: Mapping[str, str], name: str) -> frozenset[str]:
    """Unset or empty -> DEFAULT_MFA_REQUIRED_ROLES; only the explicit word "none" turns MFA off for every
    role (an empty `AUTH_MFA_REQUIRED_ROLES=` line in a copied .env must never disable it silently)."""
    raw = (env.get(name) or "").strip()
    if raw.lower() == "none":
        return frozenset()
    roles = frozenset(r.strip() for r in raw.split(",") if r.strip())
    if not roles:
        return DEFAULT_MFA_REQUIRED_ROLES
    unknown = sorted(roles - set(EDGE_ROLES))
    if unknown:
        raise ValueError(f"{name} lists unknown role(s): {', '.join(unknown)}")
    return roles
