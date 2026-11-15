"""Canonical JSON + HMAC helpers shared by bundle signing and sync-item verification.

Canonicalisation (config/schedule.example.json `signature.canonicalization`, SURPRISE_CHALLENGES §SC2.2):
    json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
HMAC keys are the .env strings encoded as UTF-8. Output is lower-case hex.

When the policy-engine's implementation in `edge/offline/` exposes equivalent functions they are used
instead (see `cloud.app.policy_bridge`), so edge and cloud cannot drift.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def hmac_hex(key: str, data: bytes) -> str:
    return hmac.new(key.encode("utf-8"), data, hashlib.sha256).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def without(obj: dict, *keys: str) -> dict:
    return {k: v for k, v in obj.items() if k not in keys}


def item_hmac(key: str, item: dict) -> str:
    """Sync item MAC: HMAC-SHA256(kiosk key, canonical item JSON without the `hmac` field)."""
    return hmac_hex(key, canonical_json(without(item, "hmac")))


def verify_item_hmac(key: str, item: dict) -> bool:
    presented = item.get("hmac")
    if not isinstance(presented, str) or not presented:
        return False
    return hmac.compare_digest(item_hmac(key, item), presented.lower())
