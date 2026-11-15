"""Encrypted local template cache (Fernet, key = EDGE_DATA_KEY). No images are ever stored.

One Fernet token on disk (edge/data/templates.fernet, gitignored) holding, per user: display name,
role, ArcFace templates (float32), model id, template version, consent version, HMAC card hash and
(optionally) the TOTP secret used for offline fallback. Decrypted into memory at startup; every write
is atomic (tmp + os.replace). Templates from a different embedding model are refused.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel

from edge.ml.matcher import EMB_DIM, Gallery

# Storage cap per user for append-mode re-enrolment (glasses on / off, lighting...). The first
# PINNED_TEMPLATES (the original enrolment) are never evicted, so repeated appends cannot drift an
# account to a different face; the newest of the rest are kept.
MAX_TEMPLATES_PER_USER = 24
PINNED_TEMPLATES = 5


def write_private(path: Path, data: bytes) -> None:
    """Atomic write of an edge/data file readable by the owner only: the tmp file is CREATED 0600 (never
    briefly world-readable), fsynced, then os.replace'd; a new data dir is created 0700."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with contextlib.suppress(FileNotFoundError):
        tmp.unlink()  # a stale tmp may carry wider permissions
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)  # umask can only narrow; make it exact
        with os.fdopen(fd, "wb") as fh:
            fd = -1
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    finally:
        if fd != -1:
            os.close(fd)
    os.replace(tmp, path)


class TemplateStoreError(RuntimeError):
    pass


class LocalUser(BaseModel):
    user_id: str
    display_name: str
    role: str
    model_id: str
    templates_b64: list[str]
    template_version: int = 1
    consent_version: str
    created_at: str
    updated_at: str
    card_id_hash: str | None = None
    totp_secret: str | None = None

    def embeddings(self) -> np.ndarray:
        return np.stack([np.frombuffer(base64.b64decode(t), dtype=np.float32) for t in self.templates_b64])


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class TemplateStore:
    def __init__(self, path: Path, key: str, model_id: str) -> None:
        if not key:
            raise TemplateStoreError("EDGE_DATA_KEY is not set")
        try:
            self._fernet = Fernet(key.encode() if isinstance(key, str) else key)
        except (ValueError, TypeError) as exc:
            raise TemplateStoreError("EDGE_DATA_KEY is not a valid Fernet key") from exc
        self.path = path
        self.model_id = model_id
        self._lock = threading.RLock()
        self._users: dict[str, LocalUser] = {}
        self._updated_at: datetime | None = None
        self._loaded_at: datetime | None = None
        self._gallery = Gallery()
        self.skipped_model_mismatch = 0

    # ------------------------------------------------------------------ persistence
    def load(self) -> None:
        with self._lock:
            self._loaded_at = datetime.now(UTC)
            if not self.path.is_file():
                self._users, self._updated_at = {}, None
                self._rebuild()
                return
            try:
                payload = json.loads(self._fernet.decrypt(self.path.read_bytes()))
            except InvalidToken as exc:
                raise TemplateStoreError("template cache cannot be decrypted with EDGE_DATA_KEY") from exc
            users = {}
            self.skipped_model_mismatch = 0
            for uid, raw in payload.get("users", {}).items():
                user = LocalUser.model_validate(raw)
                if user.model_id != self.model_id:
                    self.skipped_model_mismatch += 1
                    continue
                users[uid] = user
            self._users = users
            ts = payload.get("updated_at")
            self._updated_at = datetime.fromisoformat(ts) if ts else None
            self._rebuild()

    def _persist(self) -> None:
        self._updated_at = datetime.now(UTC)
        payload = {
            "format": 1,
            "updated_at": self._updated_at.isoformat().replace("+00:00", "Z"),
            "model_id": self.model_id,
            "users": {uid: u.model_dump() for uid, u in self._users.items()},
        }
        token = self._fernet.encrypt(json.dumps(payload, separators=(",", ":")).encode())
        write_private(self.path, token)

    def _rebuild(self) -> None:
        ids: list[str] = []
        rows: list[np.ndarray] = []
        for uid, user in sorted(self._users.items()):
            emb = user.embeddings()
            ids += [uid] * len(emb)
            rows.append(emb)
        matrix = np.vstack(rows).astype(np.float32) if rows else np.zeros((0, EMB_DIM), np.float32)
        self._gallery = Gallery(user_ids=tuple(ids), matrix=matrix)

    # ------------------------------------------------------------------ API
    @property
    def gallery(self) -> Gallery:
        return self._gallery  # immutable snapshot, safe to read without the lock

    def age_hours(self, now: datetime | None = None) -> float | None:
        """Hours since the last write; an empty, never-written store counts from load. None only
        if the store was never loaded (policy: unusable cache)."""
        ref = self._updated_at or self._loaded_at
        if ref is None:
            return None
        now = now or datetime.now(UTC)
        return round(max(0.0, (now - ref).total_seconds()) / 3600.0, 3)

    def count(self) -> int:
        return len(self._users)

    def get(self, user_id: str) -> LocalUser | None:
        return self._users.get(user_id)

    def upsert(
        self,
        *,
        user_id: str,
        display_name: str,
        role: str,
        embeddings: np.ndarray,
        consent_version: str,
        card_id_hash: str | None,
        totp_secret: str | None,
        append: bool = False,
    ) -> LocalUser:
        """`append=True` keeps the user's existing templates and adds the new ones (capped at
        MAX_TEMPLATES_PER_USER: the first PINNED_TEMPLATES stay, the newest of the rest are kept), so several
        enrolments (glasses on / off) all match: the matcher scores the max over a user's templates.
        `append=False` replaces them. Non-finite or zero embeddings are refused (they would be NaN rows)."""
        emb = np.asarray(embeddings, dtype=np.float32)
        if emb.ndim != 2 or emb.shape[1] != EMB_DIM or len(emb) == 0:
            raise TemplateStoreError(f"embeddings must be (N, {EMB_DIM})")
        norms = np.linalg.norm(emb, axis=1, keepdims=True)
        if not np.isfinite(emb).all() or not (norms > 0).all():
            raise TemplateStoreError("embeddings must be finite and non-zero")
        emb = emb / norms
        with self._lock:
            prev = self._users.get(user_id)
            if append and prev is not None and prev.model_id == self.model_id:
                old = prev.embeddings()
                pinned, rest = old[:PINNED_TEMPLATES], np.concatenate([old[PINNED_TEMPLATES:], emb])
                keep = max(0, MAX_TEMPLATES_PER_USER - len(pinned))
                emb = np.concatenate([pinned, rest[max(0, len(rest) - keep):]])
            now = _now()
            user = LocalUser(
                user_id=user_id,
                display_name=display_name,
                role=role,
                model_id=self.model_id,
                templates_b64=[base64.b64encode(e.tobytes()).decode() for e in emb],
                template_version=(prev.template_version + 1) if prev else 1,
                consent_version=consent_version,
                created_at=prev.created_at if prev else now,
                updated_at=now,
                card_id_hash=card_id_hash if card_id_hash is not None else (prev.card_id_hash if prev else None),
                totp_secret=totp_secret if totp_secret is not None else (prev.totp_secret if prev else None),
            )
            self._users[user_id] = user
            self._persist()
            self._rebuild()
            return user

    def delete(self, user_id: str) -> bool:
        with self._lock:
            if user_id not in self._users:
                return False
            del self._users[user_id]
            self._persist()
            self._rebuild()
            return True

    def summary(self) -> dict:
        return {
            "count": self.count(),
            "model": self.model_id,
            "age_h": self.age_hours(),
            "skipped_model_mismatch": self.skipped_model_mismatch,
        }
