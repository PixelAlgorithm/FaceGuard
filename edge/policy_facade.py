"""Loads the policy-engine's PolicyRuntime (edge/policy/runtime.py).

If the runtime cannot be imported or constructed (missing key, corrupt store, ...), a
FailSecureRuntime is used instead: every attempt is DENY + SYSTEM_ERROR (DECISION_POLICY P1) and
/v1/health reports `degraded`. There is deliberately no permissive fallback policy.
"""

from __future__ import annotations

import logging
from typing import Any

from edge.config import Settings, Thresholds
from edge.policy.signals import AttemptSignals, ChallengeEvidence, FallbackSubmission

log = logging.getLogger("edge.policy_facade")

# API.md v1.1 DecisionResponse: every latency key is a required int; scores keys are nullable.
LATENCY_KEYS = ("total", "liveness", "match", "schedule", "policy")
EMPTY_SCORES: dict[str, Any] = {
    "pad_mean": None, "pad_pass_frames": None, "flash_r": None, "flash_amp": None, "moire": None,
    "device_conf": None, "depth": None, "mask": {}, "match_local": None, "match_margin": None,
    "rekognition": None, "rekognition_runner_up": None, "signals": None,
}

try:  # exception types are part of the runtime contract (409 / 404 mapping)
    from edge.policy.runtime import AttemptClosedError, AttemptNotFoundError
except ImportError:  # pragma: no cover - only before the runtime existed

    class AttemptClosedError(Exception):  # type: ignore[no-redef]
        pass

    class AttemptNotFoundError(Exception):  # type: ignore[no-redef]
        pass


def load_runtime(settings: Settings, thresholds: Thresholds) -> tuple[Any, str]:
    try:
        from edge.policy.runtime import PolicyRuntime
    except ImportError as exc:
        log.error("edge.policy.runtime not importable (%s): FAIL-SECURE runtime (DENY all)", exc)
        return FailSecureRuntime(settings, thresholds, f"import: {exc}"), "fail_secure"
    try:
        return PolicyRuntime.from_env(settings.project_root), "real"
    except Exception as exc:  # noqa: BLE001 - any construction failure must deny, never allow
        log.error("PolicyRuntime.from_env failed (%s): FAIL-SECURE runtime (DENY all)", type(exc).__name__)
        return FailSecureRuntime(settings, thresholds, f"{type(exc).__name__}: {exc}"), "fail_secure"


class FailSecureRuntime:
    """Same interface as PolicyRuntime; every decision is DENY SYSTEM_ERROR."""

    def __init__(self, settings: Settings, thresholds: Thresholds, reason: str) -> None:
        self.settings = settings
        self.th = thresholds
        self.reason = reason
        self._attempts: dict[str, dict[str, Any]] = {}

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def mode(self) -> str:
        return "OFFLINE"

    def mode_status(self) -> dict[str, Any]:
        return {"mode": "OFFLINE", "state": "OFFLINE", "forced": False, "reason": "policy_runtime_unavailable",
                "policy_runtime_error": self.reason, "demo_clock": None, "sync_queue_depth": None}

    def set_forced_mode(self, force: str, reason: str | None = None, max_minutes: Any = None) -> dict[str, Any]:
        return self.mode_status()  # nothing to force: every attempt is DENY SYSTEM_ERROR

    def record_cloud_result(self, ok: bool) -> None: ...

    def kiosk_zone(self) -> str | None:
        return None

    def entitled_user_ids(self) -> set[str]:
        return set()

    def excluded_user_ids(self) -> set[str]:
        return set()  # every attempt is DENY SYSTEM_ERROR here anyway

    def bundle_kiosk_ids(self) -> set[str]:
        return set()  # no verified bundle: the DEMO_MODE kiosk switch serves KIOSK_ID only

    def revoked_user_ids(self) -> set[str]:
        return set()

    def add_erase_hook(self, fn: Any) -> None: ...  # no bundle/feed -> nothing is ever erased here

    def store_view(self) -> dict[str, Any]:
        return {"error": "policy runtime unavailable", "records": []}

    def sync_now(self) -> dict[str, Any]:
        return {"error": "policy runtime unavailable"}

    def reset_rate_limit(self) -> None: ...

    def get_attempt(self, attempt_id: str) -> dict[str, Any] | None:
        return self._attempts.get(attempt_id)

    def _deny(self, attempt_id: str | None, kiosk_id: str | None, latency_ms: dict[str, int] | None = None,
              ) -> dict[str, Any]:
        """API.md DecisionResponse-valid DENY SYSTEM_ERROR (zone UNKNOWN, stage system, OFFLINE)."""
        lat = {k: int((latency_ms or {}).get(k, 0) or 0) for k in LATENCY_KEYS}
        resp = {
            "attempt_id": attempt_id or "", "kiosk_id": kiosk_id or self.settings.kiosk_id, "zone": "UNKNOWN",
            "decision": "DENY", "stage": "system", "reason_codes": ["SYSTEM_ERROR", "OFFLINE_MODE"],
            "resolved_codes": [], "next_action": {"type": "CONTACT_DESK", "steps": [], "methods": None,
                                                  "challenge": None, "attempts_left": None,
                                                  "retry_after_s": None, "hint": None},
            "bio_result": None, "schedule_result": None, "mode": "OFFLINE", "cache_state": None,
            "candidate": None, "scores": dict(EMPTY_SCORES), "latency_ms": lat,
            "policy_version": self.th.policy_version, "bundle_version": None,
            "display_message": "Access not available - please contact the desk",
        }
        if attempt_id:
            self._attempts[attempt_id] = resp
        return resp

    def decide(self, signals: AttemptSignals, latency_ms: dict[str, int] | None = None) -> dict[str, Any]:
        return self._deny(signals.attempt_id, signals.kiosk_id, latency_ms)

    def decide_error(self, attempt_id: str, *, detail: str | None = None,
                     latency_ms: dict[str, int] | None = None) -> dict[str, Any]:
        return self._deny(attempt_id, None, latency_ms)

    def resolve_challenge(self, attempt_id: str, ev: ChallengeEvidence) -> dict[str, Any]:
        raise AttemptNotFoundError(attempt_id)

    def resolve_fallback(self, attempt_id: str, sub: FallbackSubmission) -> dict[str, Any]:
        raise AttemptNotFoundError(attempt_id)
