"""Durable edge -> cloud replay queues (encrypted, owner-only, atomic + fsync'd writes).

PendingErasures (R-J, docs/API.md §3.15 DELETE /v1/enroll `queued`): when a DPDP erasure cannot reach the cloud
(OFFLINE, transport error, 5xx, any other status), the edge erases its local data at once and queues the cloud
erasure here; the sync agent replays `DELETE /v1/enroll/{user_id}[?actor=...]` at every sync until the cloud
confirms. Stored per entry: `user_id`, `queued_at` (UTC) and the `actor` who asked for it (V2 D: staff:<id> |
key:<id> | legacy:admin_token, or None) -- no names, no images, no embeddings.

PendingEnrolments (SC2-D4): metadata-only audit records of enrolments made while the cloud was unreachable
({user_id, actor, at, template_count, model, kiosk_id}); edge-app replays them from a runtime sync hook. Face
images / embeddings / crops are refused (SC2.5 minimisation: never persisted for later replay).

A 0-byte / truncated / foreign-key file (power loss, wrong key) is quarantined as *.corrupt-<ts> and the queue
starts empty with `corrupt` set, so the runtime can raise an alert instead of failing to start (EO-08).
Without a path / key (tests) a queue lives in memory.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from edge.offline.crypto import DataCipher, read_encrypted, write_private_atomic

USER_ID_RE = re.compile(r"^u_[0-9a-z]{4}$")  # R-H: one user_id rule everywhere (also keeps the URL path safe)
ACTOR_RE = re.compile(r"^(staff:s_[0-9a-z_]{2,32}|key:[a-z0-9]{8}|legacy:admin_token)$")  # V2 E actor rule
_AAD = b"pending-erasures"
_ENROL_AAD = b"pending-enrolments"
ENROL_FIELDS = ("user_id", "actor", "at", "template_count", "model", "kiosk_id")
_FORBIDDEN_ENROL_KEYS = frozenset({"images", "image", "frames", "frame", "embedding", "embeddings", "crops",
                                   "face_crops", "templates", "depth", "depth_maps", "jpeg", "photo"})


def valid_user_id(user_id: Any) -> str:
    if not isinstance(user_id, str) or not USER_ID_RE.fullmatch(user_id):
        raise ValueError("user_id must match ^u_[0-9a-z]{4}$")
    return user_id


def valid_actor(actor: Any) -> str | None:
    if actor is None:
        return None
    if not isinstance(actor, str) or not ACTOR_RE.fullmatch(actor):
        raise ValueError("actor must match ^(staff:s_[0-9a-z_]{2,32}|key:[a-z0-9]{8}|legacy:admin_token)$")
    return actor


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class _EncryptedList:
    """A small encrypted JSON list of dict items keyed by user_id (base for both queues)."""

    def __init__(self, path: Path | str | None, data_key: str | bytes | None, purpose: str, aad: bytes) -> None:
        self.path = Path(path) if path else None
        self._c = DataCipher(data_key, purpose) if data_key else None
        self._aad = aad
        self._lock = threading.Lock()
        self._items: dict[str, dict[str, Any]] = {}
        self.corrupt: Path | None = None  # quarantined file (EO-08) -> runtime alert
        if self.path and self._c:
            plain, self.corrupt = read_encrypted(self.path, self._c, aad)
            data = json.loads(plain) if plain else {}
            items = data.get("items") if isinstance(data, Mapping) else None
            for e in items if isinstance(items, list) else []:
                uid = e.get("user_id") if isinstance(e, Mapping) else None
                if isinstance(uid, str) and USER_ID_RE.fullmatch(uid):
                    self._items[uid] = self._load_item(e)

    def _load_item(self, e: Mapping[str, Any]) -> dict[str, Any]:
        return dict(e)

    def remove(self, user_id: str) -> bool:
        with self._lock:
            if self._items.pop(user_id, None) is None:
                return False
            self._save()
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def _save(self) -> None:
        if not (self.path and self._c):
            return
        blob = json.dumps({"items": [self._items[u] for u in sorted(self._items)]})
        write_private_atomic(self.path, self._c.encrypt(blob.encode(), self._aad), prefix=".queue-")


class PendingErasures(_EncryptedList):
    def __init__(self, path: Path | str | None, data_key: str | bytes | None) -> None:
        super().__init__(path, data_key, "erasures", _AAD)

    def _load_item(self, e: Mapping[str, Any]) -> dict[str, Any]:
        actor = e.get("actor")
        return {"user_id": e["user_id"], "queued_at": str(e.get("queued_at") or ""),
                "actor": actor if isinstance(actor, str) and ACTOR_RE.fullmatch(actor) else None}

    def add(self, user_id: str, queued_at: datetime, actor: str | None = None) -> dict[str, Any]:
        """Queue (idempotent: an already queued user keeps the first queued_at and actor). ValueError on a bad
        user_id or actor."""
        uid, who = valid_user_id(user_id), valid_actor(actor)
        with self._lock:
            if uid not in self._items:
                self._items[uid] = {"user_id": uid, "queued_at": _iso(queued_at), "actor": who}
                self._save()
            return dict(self._items[uid])

    def items(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(self._items[u]) for u in sorted(self._items)]


class PendingEnrolments(_EncryptedList):
    def __init__(self, path: Path | str | None, data_key: str | bytes | None) -> None:
        super().__init__(path, data_key, "pending-enrolments", _ENROL_AAD)

    def add(self, record: Mapping[str, Any]) -> dict[str, Any]:
        """Queue one metadata-only enrolment record (a newer record for the same user replaces the older one).
        ValueError for biometric payload keys, a bad user_id / actor or an unknown field."""
        if not isinstance(record, Mapping):
            raise ValueError("record must be a mapping")  # noqa: TRY004 - API contract: ValueError -> 422
        bad = set(record) & _FORBIDDEN_ENROL_KEYS
        if bad:
            raise ValueError(f"biometric data is never queued: {sorted(bad)}")
        extra = set(record) - set(ENROL_FIELDS)
        if extra:
            raise ValueError(f"unknown enrolment record fields: {sorted(extra)}")
        rec = {k: record.get(k) for k in ENROL_FIELDS}
        rec["user_id"], rec["actor"] = valid_user_id(rec["user_id"]), valid_actor(rec["actor"])
        if rec["template_count"] is not None and (isinstance(rec["template_count"], bool)
                                                  or not isinstance(rec["template_count"], int)):
            raise ValueError("template_count must be an int")
        for k in ("at", "model", "kiosk_id"):
            if rec[k] is not None and (not isinstance(rec[k], str) or len(rec[k]) > 64):
                raise ValueError(f"{k} must be a short string")
        with self._lock:
            self._items[rec["user_id"]] = rec
            self._save()
        return dict(rec)

    def items(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(self._items[u]) for u in sorted(self._items)]
