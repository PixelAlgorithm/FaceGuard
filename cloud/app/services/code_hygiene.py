"""Override-code hygiene: publicly documented demo codes never reach a live bundle.

Same rule as scripts/sign_bundle.py `drop_documented_codes`: a code is "documented" when its PBKDF2 hash
matches ANY publicly documented value (scripts/sign_bundle.py DOC_OVERRIDE_CODES, i.e. OVR-001..003 of
config/schedule.example.json / SURPRISE_CHALLENGES SC2.4), whatever its code_id. Additionally a code that
re-uses a documented code_id (OVR-001..003) is dropped. Fail secure: if the documented values cannot be
loaded, EVERY override code is treated as documented (the staff-override fallback is then unavailable until
a freshly signed bundle is uploaded via PUT /v1/admin/schedule/{kiosk_id}, which is served verbatim).

Iterations: the edge verifies with max(bundle iterations, thresholds fallback.staff_override.pbkdf2_iterations)
(edge/policy/fallback.py), so a code is checked at the declared count AND at that effective count. Checking only
the declared count let a documented value hashed at 100000 iterations pass in a bundle that declares fewer.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Any

from ..policy_bridge import load_documented_override_values

log = logging.getLogger("hid.cloud.codes")

DOCUMENTED_CODE_IDS = frozenset({"OVR-001", "OVR-002", "OVR-003"})
# (iterations, edge floor, salt, hash, documented values) -> documented? (PBKDF2 is ~40 ms each). Keyed by the
# values too, so an explicit list (rotate) is memoised as well instead of re-hashing every stored code each time.
_MEMO: dict[tuple[int, int, str, str, tuple[str, ...]], bool] = {}
_MEMO_MAX = 4096
_EDGE_MIN_ITERATIONS = 100000  # thresholds.yaml fallback.staff_override.pbkdf2_iterations (set_edge_min_iterations)


def set_edge_min_iterations(n: int) -> None:
    """The edge's PBKDF2 floor (same thresholds.yaml as the cloud); called once by ScheduleService."""
    global _EDGE_MIN_ITERATIONS
    _EDGE_MIN_ITERATIONS = max(1, int(n))


def _candidate_iterations(declared: int) -> tuple[int, ...]:
    return tuple(dict.fromkeys((declared, max(declared, _EDGE_MIN_ITERATIONS))))


def is_documented(code: Any, iterations: int, values: tuple[str, ...] | None = None) -> bool:
    if not isinstance(code, dict):
        return True
    if str(code.get("code_id", "")) in DOCUMENTED_CODE_IDS:
        return True
    vals = values if values is not None else load_documented_override_values()
    if vals is None:
        return True  # fail secure: cannot tell -> treat as documented
    salt_hex, want = str(code.get("salt", "")), str(code.get("hash", ""))
    memo_key = (iterations, _EDGE_MIN_ITERATIONS, salt_hex, want, tuple(vals))
    if memo_key in _MEMO:
        return _MEMO[memo_key]
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return True  # malformed code entry is unusable anyway
    hit = any(hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", v.encode(), salt, n).hex(), want)
              for n in _candidate_iterations(iterations) for v in vals)
    if len(_MEMO) >= _MEMO_MAX:
        _MEMO.clear()
    _MEMO[memo_key] = hit
    return hit


def documented_code_ids(doc: dict, values: tuple[str, ...] | None = None) -> list[str]:
    oc = doc.get("override_codes") or {}
    it = int(oc.get("iterations") or 100000)
    return [str((c or {}).get("code_id")) for c in oc.get("codes") or [] if is_documented(c, it, values)]


def strip_documented_codes(doc: dict, values: tuple[str, ...] | None = None) -> list[str]:
    """Remove documented codes from `doc` in place; returns the dropped code_ids."""
    oc = doc.get("override_codes")
    if not isinstance(oc, dict) or not oc.get("codes"):
        return []
    it = int(oc.get("iterations") or 100000)
    keep, dropped = [], []
    for c in oc["codes"]:
        (dropped if is_documented(c, it, values) else keep).append(c)
    if dropped:
        oc["codes"] = keep
        log.warning("dropped %d publicly documented override code(s) from the schedule: %s", len(dropped),
                    [str((c or {}).get("code_id")) for c in dropped])
    return [str((c or {}).get("code_id")) for c in dropped]
