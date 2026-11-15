"""Pending CLOUD erasures (R-J, docs/API.md §3.15 DELETE /v1/enroll `queued`).

When a DPDP erasure cannot reach the cloud (OFFLINE, transport error, 5xx, any other status), the edge erases its
local data at once and queues the cloud erasure here; the sync agent replays `DELETE /v1/enroll/{user_id}` at every
sync until the cloud answers 200 / 204 / 404 (idempotent). Stored per entry: `user_id` + `queued_at` (UTC) only --
no names, no images, no embeddings. Encrypted at rest (AES-256-GCM, HKDF purpose "erasures"), owner-only 0600,
atomic writes. Without a path / key (tests) the queue lives in memory.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from edge.offline.crypto import DataCipher

USER_ID_RE = re.compile(r"^u_[0-9a-z]{4}$")  # R-H: one user_id rule everywhere (also keeps the URL path safe)
_AAD = b"pending-erasures"


def valid_user_id(user_id: Any) -> str:
    if not isinstance(user_id, str) or not USER_ID_RE.fullmatch(user_id):
        raise ValueError("user_id must match ^u_[0-9a-z]{4}$")
    return user_id


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class PendingErasures:
    def __init__(self, path: Path | str | None, data_key: str | bytes | None) -> None:
        self.path = Path(path) if path else None
        self._c = DataCipher(data_key, "erasures") if data_key else None
        self._lock = threading.Lock()
        self._items: dict[str, str] = {}  # user_id -> queued_at (UTC Z)
        if self.path and self._c and self.path.exists():
            data = json.loads(self._c.decrypt(self.path.read_bytes(), _AAD))
            for e in data.get("items") or []:
                uid = e.get("user_id") if isinstance(e, dict) else None
                if isinstance(uid, str) and USER_ID_RE.fullmatch(uid):
                    self._items[uid] = str(e.get("queued_at") or "")

    def add(self, user_id: str, queued_at: datetime) -> dict[str, str]:
        """Queue (idempotent: an already queued user keeps the first queued_at). Raises ValueError on a bad id."""
        uid = valid_user_id(user_id)
        with self._lock:
            if uid not in self._items:
                self._items[uid] = _iso(queued_at)
                self._save()
            return {"user_id": uid, "queued_at": self._items[uid]}

    def remove(self, user_id: str) -> bool:
        with self._lock:
            if self._items.pop(user_id, None) is None:
                return False
            self._save()
            return True

    def items(self) -> list[dict[str, str]]:
        with self._lock:
            return [{"user_id": u, "queued_at": t} for u, t in sorted(self._items.items())]

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def _save(self) -> None:
        if not (self.path and self._c):
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        blob = json.dumps({"items": [{"user_id": u, "queued_at": t} for u, t in sorted(self._items.items())]})
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".erasures-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(self._c.encrypt(blob.encode(), _AAD))
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
