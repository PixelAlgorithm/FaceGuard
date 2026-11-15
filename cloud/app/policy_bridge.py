"""Bridge to the shared policy code owned by policy-engine (never re-implemented here).

- Schedule evaluation: `edge.policy.schedule.evaluate_schedule(user_id, zone, t0, bundle, cfg)` with
  cfg = thresholds `schedule` section ({grace_minutes, grace_minutes_high_risk, ...}). Same function the
  edge runs offline, so the cloud's re-evaluation of offline ALLOWs cannot drift from the kiosk.
- Bundle canonicalisation / chain hashing: if `edge.offline` exposes them, they are preferred; otherwise
  the documented formulas in `cloud.app.canonical` are used (cross-checked by tests when both exist).

The project root is put on sys.path so this works from `uvicorn cloud.app.main:app` and from the
deploy artifact (which vendor-copies edge/policy + edge/offline, see cloud/infra/build_artifact.sh).
"""

from __future__ import annotations

import importlib
import logging
import sys
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from .config import PROJECT_ROOT

log = logging.getLogger("hid.cloud.policy")

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

SCHEDULE_RESULTS = {"IN_WINDOW", "GRACE_WINDOW", "OUTSIDE_WINDOW", "NO_ENTITLEMENT", "ZONE_NOT_PERMITTED",
                    "HOLIDAY", "REVOKED"}

Evaluator = Callable[[str, str, datetime, Mapping[str, Any], Mapping[str, Any]], Any]


class PolicyBridge:
    def __init__(self, evaluator: Evaluator | None = None, source: str | None = None) -> None:
        self._eval = evaluator
        self.source = source or ("injected" if evaluator else "unavailable")
        self.error: str | None = None
        if evaluator is None:
            self._load()

    def _load(self) -> None:
        try:
            mod = importlib.import_module("edge.policy.schedule")
            self._eval = mod.evaluate_schedule
            self.source = "edge.policy.schedule.evaluate_schedule"
        except Exception as exc:  # module missing or broken -> sync marks offline ALLOWs NOT_EVALUATED
            self._eval = None
            self.source = "unavailable"
            self.error = f"{type(exc).__name__}: {exc}"
            log.warning("schedule evaluator unavailable: %s", self.error)

    @property
    def available(self) -> bool:
        return self._eval is not None

    def evaluate(self, user_id: str, zone: str, t0: datetime, bundle: Mapping[str, Any],
                 schedule_cfg: Mapping[str, Any]) -> str:
        if self._eval is None:
            raise RuntimeError("schedule evaluator unavailable")
        res = self._eval(user_id, zone, t0, bundle, schedule_cfg)
        res = getattr(res, "value", res)
        if isinstance(res, tuple):
            res = res[0]
        res = str(res)
        if res not in SCHEDULE_RESULTS:
            raise ValueError(f"unexpected schedule result {res!r}")
        return res


def find_edge_function(candidates: list[tuple[str, str]]) -> tuple[Callable | None, str]:
    """First importable (module, attr) pair, e.g. for chain hashing provided by edge/offline."""
    for mod_name, attr in candidates:
        try:
            fn = getattr(importlib.import_module(mod_name), attr)
            if callable(fn):
                return fn, f"{mod_name}.{attr}"
        except Exception:  # noqa: S112 - optional discovery, try the next candidate
            continue
    return None, "cloud.app.canonical (documented formula)"


_SIGNER_MOD: object | None = None


def load_sign_bundle_module():
    """scripts/sign_bundle.py (policy-engine), loaded once; None when it is not shipped or fails to import."""
    global _SIGNER_MOD
    if _SIGNER_MOD is not None:
        return _SIGNER_MOD
    import importlib.util

    path = PROJECT_ROOT / "scripts" / "sign_bundle.py"
    if not path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("hid_sign_bundle", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # import-safe: main() only runs under __main__
    except Exception as exc:  # noqa: BLE001 - callers fail secure
        log.warning("scripts/sign_bundle.py unavailable: %s", type(exc).__name__)
        return None
    _SIGNER_MOD = mod
    return mod


def load_card_hash_recompute() -> Callable | None:
    """scripts/sign_bundle.py recompute_card_hashes(bundle, pepper: bytes) (policy-engine). Demo schedules carry
    placeholder card hashes ("RECOMPUTED-BY-sign_bundle.py"); the cloud fills them exactly like the signer does."""
    mod = load_sign_bundle_module()
    return getattr(mod, "recompute_card_hashes", None) if mod is not None else None


def load_documented_override_values() -> tuple[str, ...] | None:
    """The publicly documented demo override code VALUES (scripts/sign_bundle.py DOC_OVERRIDE_CODES), or None."""
    mod = load_sign_bundle_module()
    vals = getattr(mod, "DOC_OVERRIDE_CODES", None) if mod is not None else None
    if not isinstance(vals, dict) or not vals:
        return None
    return tuple(str(v) for v in vals.values())
