"""edge-ml hardening: encrypted template store (audit EM-01, EM-02, EM-05, EM-06, EM-11, EM-M1).

Model-free: random unit embeddings, a fresh dummy Fernet key per test, files only under tmp_path.
"""

from __future__ import annotations

import base64
import errno
import json
from datetime import UTC, datetime, timedelta

import numpy as np
import pytest
from cryptography.fernet import Fernet

import edge.ml.templates as tmod
from edge.ml.matcher import search
from edge.ml.templates import (
    MAX_TEMPLATES_PER_USER,
    PINNED_TEMPLATES,
    LocalUser,
    TemplateStore,
    TemplateStoreError,
)

MODEL = "arcface_test@1"


def unit(v: np.ndarray) -> np.ndarray:
    v = np.asarray(v, np.float32)
    return v / np.linalg.norm(v, axis=-1, keepdims=True)


def embs(seed: int, n: int = 1) -> np.ndarray:
    return unit(np.random.default_rng(seed).normal(size=(n, 512)))


@pytest.fixture
def key() -> str:
    return Fernet.generate_key().decode()


def make_store(tmp_path, key: str, model: str = MODEL, **kw) -> TemplateStore:
    store = TemplateStore(tmp_path / "templates.fernet", key, model, **kw)
    store.load()
    return store


def put(store: TemplateStore, uid: str, e: np.ndarray, *, append: bool = True, totp: str | None = None) -> LocalUser:
    return store.upsert(user_id=uid, display_name=uid.upper(), role="student", embeddings=e,
                        consent_version="v1", card_id_hash=None, totp_secret=totp, append=append)


def reload(tmp_path, key: str, model: str = MODEL) -> TemplateStore:
    return make_store(tmp_path, key, model)


def write_payload(tmp_path, key: str, payload: object) -> None:
    raw = json.dumps(payload).encode() if not isinstance(payload, bytes) else payload
    (tmp_path / "templates.fernet").write_bytes(Fernet(key.encode()).encrypt(raw))


def disk_fail(*_a, **_k):
    raise OSError(errno.ENOSPC, "No space left on device")


# ---------------------------------------------------------------- EM-01: cache age = time since validation
def test_em01_idle_store_is_stale_after_72h_without_validation(tmp_path, key):
    store = make_store(tmp_path, key)
    put(store, "u_a", embs(1))
    t0 = datetime.now(UTC)
    again = reload(tmp_path, key)  # a restart reads the persisted timestamp back
    assert again.age_hours(t0 + timedelta(hours=73)) == pytest.approx(73.0, abs=0.01)


def test_em01_validation_refreshes_age_and_survives_restart(tmp_path, key):
    store = make_store(tmp_path, key)
    put(store, "u_a", embs(1))
    t0 = datetime.now(UTC)
    store.mark_validated(t0 + timedelta(hours=70))  # bundle refreshed + reconciled at T+70 h
    assert store.age_hours(t0 + timedelta(hours=100)) == pytest.approx(30.0, abs=0.01)
    again = reload(tmp_path, key)
    assert again.validated_at == t0 + timedelta(hours=70)
    assert again.age_hours(t0 + timedelta(hours=100)) == pytest.approx(30.0, abs=0.01)
    assert again.age_hours(t0 + timedelta(hours=143)) > 72  # no further refresh: unusable again


def test_em01_validation_marker_is_encrypted_and_tamper_is_ignored(tmp_path, key):
    store = make_store(tmp_path, key)
    put(store, "u_a", embs(1))
    t0 = datetime.now(UTC)
    store.mark_validated(t0 + timedelta(hours=70))
    marker = tmp_path / "templates.fernet.validated"
    blob = marker.read_bytes()
    assert blob.startswith(b"gAAAA") and b"validated_at" not in blob
    marker.write_bytes(Fernet(Fernet.generate_key()).encrypt(b'{"format":1}'))  # forged with another key
    again = reload(tmp_path, key)
    assert again.validated_at is None  # fail-secure: falls back to the last write
    assert again.age_hours(t0 + timedelta(hours=73)) == pytest.approx(73.0, abs=0.01)


def test_em01_validation_ignores_small_backward_steps_within_tolerance(tmp_path, key):
    store = make_store(tmp_path, key, clock_rollback_tolerance_s=300)
    t0 = datetime.now(UTC)
    store.mark_validated(t0)
    store.mark_validated(t0 - timedelta(seconds=60))  # NTP jitter between two reconciles
    assert store.validated_at == t0


def test_mlr1_future_dated_marker_is_corrected_by_the_next_reconcile(tmp_path, key):
    """ML-R1: one sync while the clock was 200 days ahead must not disable local matching for 200 days."""
    store = make_store(tmp_path, key, clock_rollback_tolerance_s=300)
    put(store, "u_a", embs(1))
    now = datetime.now(UTC)
    store.mark_validated(now + timedelta(days=200))  # clock jumped ahead during a successful sync
    assert store.age_hours(now) < 0  # until corrected: unusable (EM-M1 rollback rule, fail-secure)
    store.mark_validated(now)  # clock corrected; the next good reconcile is authoritative
    assert store.validated_at == now and store.age_hours(now) == 0.0
    again = TemplateStore(tmp_path / "templates.fernet", key, MODEL, clock_rollback_tolerance_s=300)
    again.load()
    assert again.validated_at == now and again.age_hours(now + timedelta(hours=1)) == pytest.approx(1.0, abs=0.01)


def test_mlr1_future_dated_write_does_not_outlive_a_validation(tmp_path, key, monkeypatch):
    store = make_store(tmp_path, key, clock_rollback_tolerance_s=300)
    now = datetime.now(UTC)
    put(store, "u_a", embs(1))
    store._updated_at = now + timedelta(days=200)  # an enrol ran while the clock was far ahead
    store.mark_validated(now)
    assert store.age_hours(now + timedelta(hours=2)) == pytest.approx(2.0, abs=0.01)


# ---------------------------------------------------------------- ML-R3: only reconciliation refreshes the age
def test_mlr3_local_write_does_not_refresh_a_validated_store(tmp_path, key):
    store = make_store(tmp_path, key)
    t0 = datetime.now(UTC)
    store.mark_validated(t0 - timedelta(hours=80))  # last online reconciliation 80 h ago
    put(store, "u_new", embs(3))  # offline enrolment now
    store.delete("u_new")  # offline erasure now
    assert store.age_hours(t0 + timedelta(hours=1)) == pytest.approx(81.0, abs=0.01)  # still stale (> 72)
    assert reload(tmp_path, key).age_hours(t0 + timedelta(hours=1)) == pytest.approx(81.0, abs=0.01)


def test_mlr3_never_validated_store_falls_back_to_the_last_write(tmp_path, key):
    """Migration path for a store that has never been reconciled (e.g. no cloud configured)."""
    store = make_store(tmp_path, key)
    put(store, "u_a", embs(1))
    t0 = datetime.now(UTC)
    assert store.validated_at is None
    assert store.age_hours(t0 + timedelta(hours=5)) == pytest.approx(5.0, abs=0.01)


def test_em01_validation_write_failure_leaves_state(tmp_path, key, monkeypatch):
    store = make_store(tmp_path, key)
    put(store, "u_a", embs(1))
    monkeypatch.setattr(tmod, "write_private", disk_fail)
    with pytest.raises(TemplateStoreError):
        store.mark_validated(datetime.now(UTC) + timedelta(hours=70))
    assert store.validated_at is None


# ---------------------------------------------------------------- EM-M1: rolled-back clock is not "fresh"
def test_emm1_clock_rollback_beyond_tolerance_gives_negative_age(tmp_path, key):
    store = make_store(tmp_path, key, clock_rollback_tolerance_s=300)
    put(store, "u_a", embs(1))
    now = datetime.now(UTC)
    assert store.age_hours(now - timedelta(seconds=60)) == 0.0  # within tolerance: NTP jitter
    assert store.age_hours(now - timedelta(hours=1)) < 0  # policy: cache_age_h < 0 -> unusable


# ---------------------------------------------------------------- EM-02: persist before mutating memory
def test_em02_failed_delete_leaves_memory_and_disk_consistent(tmp_path, key, monkeypatch):
    store = make_store(tmp_path, key)
    a = embs(1)
    put(store, "u_a", a, totp="JBSWY3DPEHPK3PXP")
    monkeypatch.setattr(tmod, "write_private", disk_fail)
    with pytest.raises(TemplateStoreError):
        store.delete("u_a")
    assert store.get("u_a") is not None and store.count() == 1  # memory == disk: erasure NOT applied
    assert search(a[0], store.gallery).top1_user == "u_a"
    assert reload(tmp_path, key).get("u_a") is not None
    monkeypatch.undo()
    assert store.delete("u_a") is True  # the retry really erases
    assert store.get("u_a") is None and search(a[0], store.gallery).top1_user is None
    assert reload(tmp_path, key).get("u_a") is None


def test_em02_failed_upsert_of_new_user_leaves_no_phantom(tmp_path, key, monkeypatch):
    store = make_store(tmp_path, key)
    put(store, "u_a", embs(1))
    monkeypatch.setattr(tmod, "write_private", disk_fail)
    with pytest.raises(TemplateStoreError):
        put(store, "u_b", embs(2))
    assert store.get("u_b") is None and store.count() == 1
    assert set(store.gallery.user_ids) == {"u_a"}


def test_em02_failed_append_keeps_previous_templates(tmp_path, key, monkeypatch):
    store = make_store(tmp_path, key)
    before = put(store, "u_a", embs(1, 3))
    monkeypatch.setattr(tmod, "write_private", disk_fail)
    with pytest.raises(TemplateStoreError):
        put(store, "u_a", embs(9, 3))
    assert store.get("u_a") == before
    assert store.gallery.matrix.shape == (3, 512)


def test_em02_erasure_reaches_users_skipped_for_model_mismatch(tmp_path, key):
    old = make_store(tmp_path, key, "m@1")
    put(old, "u_a", embs(1))
    put(old, "u_b", embs(2))
    other = reload(tmp_path, key, "m@2")  # e.g. ArcFace unavailable at boot
    assert other.count() == 0 and other.skipped_model_mismatch == 2
    assert other.delete("u_a") is True  # DPDP erasure must not report "not enrolled"
    assert other.skipped_model_mismatch == 1
    back = reload(tmp_path, key, "m@1")  # models restored
    assert back.get("u_a") is None and back.get("u_b") is not None  # erased; the other user kept


def test_em02_reenrol_under_new_model_replaces_the_foreign_record(tmp_path, key):
    old = make_store(tmp_path, key, "m@1")
    put(old, "u_a", embs(1))
    new = reload(tmp_path, key, "m@2")
    put(new, "u_a", embs(5))
    assert new.skipped_model_mismatch == 0 and new.get("u_a").model_id == "m@2"
    assert reload(tmp_path, key, "m@1").get("u_a") is None


def test_em02_write_private_fsyncs_file_and_directory(tmp_path, monkeypatch):
    calls: list[int] = []
    real = tmod.os.fsync
    monkeypatch.setattr(tmod.os, "fsync", lambda fd: (calls.append(fd), real(fd))[1])
    tmod.write_private(tmp_path / "x.bin", b"abc")
    assert (tmp_path / "x.bin").read_bytes() == b"abc"
    assert len(calls) >= 2  # the tmp file and the directory entry (os.replace survives a power cut)


# ---------------------------------------------------------------- EM-05: no re-decode, identical output
def test_em05_write_output_is_identical_to_the_reference_format(tmp_path, key):
    store = make_store(tmp_path, key)
    for i in range(4):
        put(store, f"u_{i}", embs(10 + i, 2))
    put(store, "u_1", embs(30, 2))  # append
    store.delete("u_2")
    payload = json.loads(Fernet(key.encode()).decrypt((tmp_path / "templates.fernet").read_bytes()))
    expected_users = {uid: store.get(uid).model_dump() for uid in ("u_0", "u_1", "u_3")}
    assert payload["format"] == 1 and payload["model_id"] == MODEL
    assert payload["users"] == expected_users
    again = reload(tmp_path, key)
    assert again.gallery.user_ids == store.gallery.user_ids
    np.testing.assert_array_equal(again.gallery.matrix, store.gallery.matrix)


def test_em05_writes_do_not_re_decode_unchanged_users(tmp_path, key, monkeypatch):
    store = make_store(tmp_path, key)
    for i in range(10):
        put(store, f"u_{i}", embs(i, 3))
    calls = {"n": 0}
    real = LocalUser.embeddings

    def counting(self):
        calls["n"] += 1
        return real(self)

    monkeypatch.setattr(LocalUser, "embeddings", counting)
    put(store, "u_new", embs(99, 3))
    store.delete("u_3")
    assert calls["n"] <= 1  # was: every user's templates decoded again on every write
    assert store.gallery.matrix.shape == (30, 512)


# ---------------------------------------------------------------- EM-06: pinned = the original enrolment
def test_em06_pinned_rows_are_exactly_the_original_enrolment(tmp_path, key):
    store = make_store(tmp_path, key)
    original = embs(1, 3)  # min_usable_frames = 3: a valid original enrolment can be 3 rows
    put(store, "u_a", original)
    put(store, "u_a", embs(2, 3))  # look X1
    user = store.get("u_a")
    assert user.pinned_n == 3
    np.testing.assert_allclose(user.pinned_embeddings(), original, atol=1e-6)  # never X1 rows
    for k in range(10):  # fill to the cap: only appended looks are evicted
        put(store, "u_a", embs(100 + k, 3))
    user = reload(tmp_path, key).get("u_a")
    assert len(user.templates_b64) == MAX_TEMPLATES_PER_USER and user.pinned_n == 3
    np.testing.assert_allclose(user.pinned_embeddings(), original, atol=1e-6)
    np.testing.assert_allclose(user.embeddings()[:3], original, atol=1e-6)


def test_em06_replace_resets_the_pinned_set(tmp_path, key):
    store = make_store(tmp_path, key)
    put(store, "u_a", embs(1, 2))
    put(store, "u_a", embs(2, 4), append=False)
    assert store.get("u_a").pinned_n == 4


def test_em06_original_enrolment_larger_than_pin_cap(tmp_path, key):
    store = make_store(tmp_path, key)
    put(store, "u_a", embs(1, PINNED_TEMPLATES + 2))
    assert store.get("u_a").pinned_n == PINNED_TEMPLATES


def test_em06_legacy_records_without_pinned_n(tmp_path, key):
    def legacy(uid: str, n: int, version: int) -> dict:
        e = embs(len(uid) + n, n)
        return {"user_id": uid, "display_name": uid, "role": "student", "model_id": MODEL,
                "templates_b64": [base64.b64encode(r.tobytes()).decode() for r in e],
                "template_version": version, "consent_version": "v1", "created_at": "t", "updated_at": "t"}

    write_payload(tmp_path, key, {"format": 1, "updated_at": None, "model_id": MODEL,
                                  "users": {"u_new": legacy("u_new", 3, 1), "u_re": legacy("u_re", 9, 3)}})
    store = reload(tmp_path, key)
    assert store.get("u_new").pinned_count == 3  # never re-enrolled: every row is original
    assert store.get("u_re").pinned_count == PINNED_TEMPLATES  # unknown history: previous rule


# ---------------------------------------------------------------- EM-11: unexpected authenticated payloads
SECRET_NAME = "Very Secret Display Name"


@pytest.mark.parametrize(
    "payload",
    [
        {"format": 2, "users": {}},
        {"users": {}},  # no format marker
        {"format": 1, "users": {"u_a": {"user_id": "u_a", "display_name": SECRET_NAME}}},  # field rename
        {"format": 1, "users": {"u_a": {"user_id": "u_a", "display_name": SECRET_NAME, "role": "r",
                                        "model_id": MODEL, "templates_b64": ["!!notb64"],
                                        "consent_version": "v1", "created_at": "t", "updated_at": "t"}}},
        {"format": 1, "users": ["u_a"]},
        {"format": 1, "updated_at": "not-a-date", "users": {}},
        ["not", "an", "object"],
        b"\xff\xfe not json",
    ],
)
def test_em11_unexpected_payload_raises_template_store_error_without_values(tmp_path, key, payload):
    write_payload(tmp_path, key, payload)
    store = TemplateStore(tmp_path / "templates.fernet", key, MODEL)
    with pytest.raises(TemplateStoreError) as info:
        store.load()
    assert SECRET_NAME not in str(info.value) and "notb64" not in str(info.value)
    assert info.value.__cause__ is None and info.value.__suppress_context__  # pydantic text not chained
    assert (tmp_path / "templates.fernet").is_file()  # never overwritten or deleted
