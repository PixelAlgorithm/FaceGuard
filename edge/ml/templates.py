"""Encrypted local template cache (Fernet, key = EDGE_DATA_KEY). No images are ever stored.

One Fernet token on disk (edge/data/templates.fernet, gitignored) holding, per user: display name,
role, ArcFace templates (float32), model id, template version, consent version, HMAC card hash,
the size of the original enrolment (`pinned_n`) and (optionally) the TOTP secret used for offline
fallback. Decrypted into memory at startup; every write is atomic (0600 tmp, fsync, os.replace,
directory fsync). Templates from a different embedding model are not matched, but they are kept on
disk untouched so a DPDP erasure still reaches them (and a boot without ArcFace loses nothing).

Write discipline (audit EM-02): every change builds the new state immutably, persists it, and only
then swaps it into memory. A failed write raises TemplateStoreError and leaves memory == disk (the
change, e.g. an erasure, was NOT applied). Unchanged users are never re-decoded or re-serialised on
a write (EM-05); the single-token format still re-encrypts the whole gallery per write, so very
large galleries (thousands of users) need a per-record format (see below).

Cache age (audit EM-01, review ML-R3): `age_hours()` counts from the last `mark_validated()` call,
a small encrypted sidecar (`<file>.validated`) the runtime touches after it has installed a verified
bundle and applied its revocations/erasures. Local writes (offline enrol / erase) do NOT refresh it.
So the policy's `cache.template_cache_max_age_hours` means "time since the last online
reconciliation", not "time since the last enrolment". Migration path: a store that has never been
validated (no cloud configured, or written by an older build) falls back to the last local write.
A clock more than the configured tolerance BEFORE the reference gives a NEGATIVE age, which the
policy treats as an unusable cache (EM-M1). A reconcile is authoritative for "now": one recorded
while the clock was far ahead is replaced by the next reconcile, so a forward clock jump cannot
disable local matching until the wall clock catches up (ML-R1).

Known architectural limits (documented, not solved here):
- EM-04: templates exist only on the kiosk that enrolled the user. Nothing distributes or refreshes
  them, so offline (SC2) face matching works only at the enrolling kiosk. A multi-kiosk deployment
  needs a cloud-held, per-kiosk, entitled-only, signed + encrypted template bundle bound to
  `model_id` and reconciled at every bundle refresh (raw embeddings must never travel in the
  decision ledger); `mark_validated()` is the hook such a reconciliation would call.
- EM-14: one static Fernet key from EDGE_DATA_KEY protects templates, card hashes and (stub
  runtimes only) TOTP secrets. There is no key id / MultiFernet rotation: a rotated key makes
  load() fail (templates=None, every offline attempt NOT_ENROLLED) until the old key is restored.
  Production should hold the key in the OS keychain / Secure Enclave and support rotation. The
  default pydantic repr of LocalUser includes `card_id_hash` and `totp_secret`: never log a record.
"""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import os
import threading
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import numpy as np
from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, Field

from edge.ml.matcher import EMB_DIM, Gallery

try:  # macOS: fsync() does not flush the drive cache; F_FULLFSYNC does
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None  # type: ignore[assignment]

log = logging.getLogger(__name__)

# Storage cap per user for append-mode re-enrolment (glasses on / off, lighting...). The rows of the
# ORIGINAL enrolment (at most PINNED_TEMPLATES, recorded per user as `pinned_n`) are never evicted and
# are the reference for the LOOK_MISMATCH check, so repeated appends cannot drift an account to a
# different face; the newest of the rest are kept.
MAX_TEMPLATES_PER_USER = 24
PINNED_TEMPLATES = 5
SUPPORTED_FORMAT = 1  # payload["format"] written and accepted by this code
VALIDATION_SUFFIX = ".validated"


def _durable_fsync(fd: int) -> None:
    os.fsync(fd)
    full = getattr(fcntl, "F_FULLFSYNC", None) if fcntl is not None else None
    if full is not None:
        with contextlib.suppress(OSError):  # not every filesystem supports it; fsync already ran
            fcntl.fcntl(fd, full)


def _fsync_dir(directory: Path) -> None:
    """Persist the directory entry created by os.replace (best effort: some filesystems refuse)."""
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError as exc:
        log.debug("directory fsync skipped (%s)", type(exc).__name__)
        return
    try:
        os.fsync(fd)
    except OSError as exc:
        log.debug("directory fsync failed (%s)", type(exc).__name__)
    finally:
        os.close(fd)


def write_private(path: Path, data: bytes) -> None:
    """Atomic, durable write of an edge/data file readable by the owner only: the tmp file is CREATED
    0600 (never briefly world-readable), fsynced (F_FULLFSYNC on macOS), os.replace'd, then the
    directory is fsynced so a power cut cannot undo the replace (e.g. resurrect an erased user). A new
    data dir is created 0700."""
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
            _durable_fsync(fh.fileno())
    finally:
        if fd != -1:
            os.close(fd)
    os.replace(tmp, path)
    _fsync_dir(path.parent)


class TemplateStoreError(RuntimeError):
    pass


class _PayloadError(ValueError):
    """Internal: the decrypted payload is authentic but not in a shape this code understands."""


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
    # Rows of the original enrolment at the start of templates_b64 (EM-06). None = record written
    # before this field existed: the previous positional rule (first PINNED_TEMPLATES rows) applies.
    pinned_n: int | None = Field(default=None, ge=1)

    def embeddings(self) -> np.ndarray:
        return np.stack([np.frombuffer(base64.b64decode(t), dtype=np.float32) for t in self.templates_b64])

    @property
    def pinned_count(self) -> int:
        """Number of leading rows that belong to the original enrolment."""
        cap = self.pinned_n if self.pinned_n is not None else PINNED_TEMPLATES
        return min(cap, len(self.templates_b64))

    def pinned_embeddings(self) -> np.ndarray:
        """The original enrolment's templates: the reference a new look must resemble."""
        return self.embeddings()[: self.pinned_count]


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _iso(ts: datetime) -> str:
    return ts.isoformat().replace("+00:00", "Z")


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise _PayloadError("timestamp is not a string")
    ts = datetime.fromisoformat(value)
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=UTC)


def _decode_rows(user: LocalUser) -> np.ndarray:
    rows = user.embeddings()
    if rows.ndim != 2 or rows.shape[1] != EMB_DIM:
        raise _PayloadError("template rows have the wrong dimension")
    return rows


def _fragment(record: Mapping[str, Any]) -> str:
    return json.dumps(record, separators=(",", ":"))


class _State:
    """One immutable snapshot of the store contents (replaced as a whole, never edited)."""

    __slots__ = ("emb", "foreign", "frags", "users")

    def __init__(self, users: dict[str, LocalUser], foreign: dict[str, dict[str, Any]],
                 emb: dict[str, np.ndarray], frags: dict[str, str]) -> None:
        self.users = users  # matched users (this model_id)
        self.foreign = foreign  # raw records of another model_id: kept on disk, never matched
        self.emb = emb  # decoded, L2-normalised rows per matched user
        self.frags = frags  # cached serialised JSON per record (filled lazily on the first write)


_EMPTY = _State({}, {}, {}, {})


class TemplateStore:
    def __init__(self, path: Path, key: str, model_id: str, *, clock_rollback_tolerance_s: float = 0.0) -> None:
        if not key:
            raise TemplateStoreError("EDGE_DATA_KEY is not set")
        try:
            self._fernet = Fernet(key.encode() if isinstance(key, str) else key)
        except (ValueError, TypeError) as exc:
            raise TemplateStoreError("EDGE_DATA_KEY is not a valid Fernet key") from exc
        self.path = path
        self.model_id = model_id
        self._rollback_tolerance_s = max(0.0, float(clock_rollback_tolerance_s))
        self._lock = threading.RLock()
        self._state = _EMPTY
        self._updated_at: datetime | None = None
        self._validated_at: datetime | None = None
        self._loaded_at: datetime | None = None
        self._gallery = Gallery()
        self.skipped_model_mismatch = 0

    @property
    def _users(self) -> dict[str, LocalUser]:  # read-only view kept for diagnostics/tests
        return self._state.users

    @property
    def _validation_path(self) -> Path:
        return self.path.with_name(self.path.name + VALIDATION_SUFFIX)

    # ------------------------------------------------------------------ persistence
    def load(self) -> None:
        """Decrypt the cache into memory. Any unreadable, undecryptable or unexpected (version skew,
        downgrade) payload raises TemplateStoreError without echoing record values; the file is left
        untouched (the app then runs with templates=None, i.e. no local matching)."""
        with self._lock:
            self._loaded_at = datetime.now(UTC)
            if not self.path.is_file():
                self._install(_EMPTY, updated_at=None)
                self._validated_at = self._read_validation()
                return
            try:
                token = self.path.read_bytes()
            except OSError as exc:
                raise TemplateStoreError(f"template cache cannot be read ({type(exc).__name__})") from None
            try:
                raw = self._fernet.decrypt(token)
            except InvalidToken as exc:
                raise TemplateStoreError("template cache cannot be decrypted with EDGE_DATA_KEY") from exc
            try:
                state, updated_at = self._parse(raw)
            except (ValueError, TypeError, KeyError, AttributeError) as exc:  # pydantic ValidationError is a ValueError
                raise TemplateStoreError(
                    f"template cache payload is not a supported format ({type(exc).__name__})"
                ) from None
            self._install(state, updated_at=updated_at)
            self._validated_at = self._read_validation()

    def _parse(self, raw: bytes) -> tuple[_State, datetime | None]:
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise _PayloadError("payload is not an object")
        if payload.get("format") != SUPPORTED_FORMAT:
            raise _PayloadError("unsupported payload format")
        records = payload.get("users", {})
        if not isinstance(records, dict):
            raise _PayloadError("users is not an object")
        users: dict[str, LocalUser] = {}
        foreign: dict[str, dict[str, Any]] = {}
        emb: dict[str, np.ndarray] = {}
        for uid, record in records.items():
            user = LocalUser.model_validate(record)
            if user.user_id != uid:
                raise _PayloadError("record key does not match its user_id")
            if user.model_id != self.model_id:
                foreign[uid] = record
                continue
            emb[uid] = _decode_rows(user)
            users[uid] = user
        return _State(users, foreign, emb, {}), _parse_ts(payload.get("updated_at"))

    def _read_validation(self) -> datetime | None:
        """The last reconciliation time, or None if absent or not authentic (fail-secure: older ref)."""
        path = self._validation_path
        if not path.is_file():
            return None
        try:
            data = json.loads(self._fernet.decrypt(path.read_bytes()))
            if not isinstance(data, dict) or data.get("format") != SUPPORTED_FORMAT:
                raise _PayloadError("unsupported validation marker")
            return _parse_ts(data.get("validated_at"))
        except (OSError, InvalidToken, ValueError, TypeError) as exc:
            log.warning("template cache validation marker ignored (%s)", type(exc).__name__)
            return None

    def _serialise(self, state: _State, updated_at: datetime) -> bytes:
        users = ",".join(f"{json.dumps(uid)}:{state.frags[uid]}" for uid in (*state.users, *state.foreign))
        head = (f'{{"format":{SUPPORTED_FORMAT},"updated_at":{json.dumps(_iso(updated_at))},'
                f'"model_id":{json.dumps(self.model_id)},"users":{{')
        return (head + users + "}}").encode()

    @staticmethod
    def _with_fragments(state: _State) -> _State:
        """Serialise records that have no cached JSON yet (each record at most once per process)."""
        missing = {uid: _fragment(u.model_dump()) for uid, u in state.users.items() if uid not in state.frags}
        missing |= {uid: _fragment(r) for uid, r in state.foreign.items() if uid not in state.frags}
        if not missing:
            return state
        return _State(state.users, state.foreign, state.emb, {**state.frags, **missing})

    def _commit(self, state: _State) -> None:
        """Persist `state`, then (only on success) make it the in-memory state."""
        state = self._with_fragments(state)
        updated_at = datetime.now(UTC)
        token = self._fernet.encrypt(self._serialise(state, updated_at))
        try:
            write_private(self.path, token)
        except OSError as exc:
            raise TemplateStoreError(
                f"template cache write failed ({type(exc).__name__}: {exc.strerror or exc}); change NOT applied"
            ) from exc
        self._install(state, updated_at=updated_at)

    def _install(self, state: _State, *, updated_at: datetime | None) -> None:
        self._state = state
        self._updated_at = updated_at
        self.skipped_model_mismatch = len(state.foreign)
        self._gallery = self._build_gallery(state)

    @staticmethod
    def _build_gallery(state: _State) -> Gallery:
        ids: list[str] = []
        rows: list[np.ndarray] = []
        for uid in sorted(state.emb):
            emb = state.emb[uid]
            ids += [uid] * len(emb)
            rows.append(emb)
        matrix = np.vstack(rows).astype(np.float32) if rows else np.zeros((0, EMB_DIM), np.float32)
        return Gallery(user_ids=tuple(ids), matrix=matrix)

    # ------------------------------------------------------------------ API
    @property
    def gallery(self) -> Gallery:
        return self._gallery  # immutable snapshot, safe to read without the lock

    @property
    def validated_at(self) -> datetime | None:
        return self._validated_at

    def mark_validated(self, now: datetime | None = None) -> None:
        """Record that the cache was reconciled online (a verified bundle installed and its
        revocations / erasures applied). Persisted in an encrypted sidecar. A reconcile is
        authoritative for "now": a stored marker more than the rollback tolerance AFTER `now` (one
        recorded while the clock was ahead) is replaced; a backward step within the tolerance (NTP
        jitter) is ignored. Raises TemplateStoreError (state unchanged) if the marker cannot be written."""
        ts = now or datetime.now(UTC)
        with self._lock:
            prev = self._validated_at
            if prev is not None and prev - timedelta(seconds=self._rollback_tolerance_s) <= ts <= prev:
                return
            body = json.dumps({"format": SUPPORTED_FORMAT, "validated_at": _iso(ts)}, separators=(",", ":"))
            try:
                write_private(self._validation_path, self._fernet.encrypt(body.encode()))
            except OSError as exc:
                raise TemplateStoreError(
                    f"template cache validation marker write failed ({type(exc).__name__})"
                ) from exc
            self._validated_at = ts

    def age_hours(self, now: datetime | None = None) -> float | None:
        """Hours since the last validation (online reconciliation). Local writes do not refresh it.
        Never validated: since the last write (migration path), else since load. None only if the
        store was never loaded (policy: unusable cache). A clock more than the rollback tolerance
        BEFORE the reference gives a negative age (policy: unusable cache) instead of reading as fresh."""
        ref = self._validated_at or self._updated_at or self._loaded_at
        if ref is None:
            return None
        now = now or datetime.now(UTC)
        delta_s = (now - ref).total_seconds()
        if delta_s < -self._rollback_tolerance_s:
            return min(-0.001, round(delta_s / 3600.0, 3))
        return round(max(0.0, delta_s) / 3600.0, 3)

    def count(self) -> int:
        return len(self._state.users)

    def get(self, user_id: str) -> LocalUser | None:
        return self._state.users.get(user_id)

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
        MAX_TEMPLATES_PER_USER: the original enrolment's rows stay, the newest of the rest are kept), so
        several enrolments (glasses on / off) all match: the matcher scores the max over a user's
        templates. `append=False` replaces them (and the new rows become the original enrolment).
        Non-finite or zero embeddings are refused (they would be NaN rows). A record of another
        model_id under the same user_id is replaced. Raises TemplateStoreError on a failed write, with
        memory and disk unchanged."""
        emb = np.asarray(embeddings, dtype=np.float32)
        if emb.ndim != 2 or emb.shape[1] != EMB_DIM or len(emb) == 0:
            raise TemplateStoreError(f"embeddings must be (N, {EMB_DIM})")
        norms = np.linalg.norm(emb, axis=1, keepdims=True)
        if not np.isfinite(emb).all() or not (norms > 0).all():
            raise TemplateStoreError("embeddings must be finite and non-zero")
        emb = emb / norms
        with self._lock:
            state = self._state
            prev = state.users.get(user_id)
            if append and prev is not None:
                pinned_n = prev.pinned_count
                old = state.emb[user_id]
                pinned, rest = old[:pinned_n], np.concatenate([old[pinned_n:], emb])
                keep = max(0, MAX_TEMPLATES_PER_USER - pinned_n)
                emb = np.concatenate([pinned, rest[max(0, len(rest) - keep):]])
            else:
                pinned_n = min(len(emb), PINNED_TEMPLATES)
            user = self._new_user(prev, emb, pinned_n, user_id=user_id, display_name=display_name, role=role,
                                  consent_version=consent_version, card_id_hash=card_id_hash,
                                  totp_secret=totp_secret)
            frags = {**state.frags, user_id: _fragment(user.model_dump())}
            foreign = {k: v for k, v in state.foreign.items() if k != user_id}
            self._commit(_State({**state.users, user_id: user}, foreign,
                                {**state.emb, user_id: emb.astype(np.float32)}, frags))
            return user

    def _new_user(self, prev: LocalUser | None, emb: np.ndarray, pinned_n: int, *, user_id: str,
                  display_name: str, role: str, consent_version: str, card_id_hash: str | None,
                  totp_secret: str | None) -> LocalUser:
        now = _now()
        return LocalUser(
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
            pinned_n=pinned_n,
        )

    def delete(self, user_id: str) -> bool:
        """DPDP erasure of the user's record (templates, card hash, TOTP), including a record of
        another model_id that was not loaded for matching. False = no record on disk. Raises
        TemplateStoreError on a failed write: the erasure was NOT applied (memory == disk)."""
        with self._lock:
            state = self._state
            if user_id not in state.users and user_id not in state.foreign:
                return False
            self._commit(_State(
                {k: v for k, v in state.users.items() if k != user_id},
                {k: v for k, v in state.foreign.items() if k != user_id},
                {k: v for k, v in state.emb.items() if k != user_id},
                {k: v for k, v in state.frags.items() if k != user_id},
            ))
            return True

    def summary(self) -> dict:
        return {
            "count": self.count(),
            "model": self.model_id,
            "age_h": self.age_hours(),
            "skipped_model_mismatch": self.skipped_model_mismatch,
        }
