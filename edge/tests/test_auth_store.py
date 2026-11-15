"""StaffStore: encryption, atomic cross-process updates, states, fail-closed behaviour, rollback, rekey."""

from __future__ import annotations

import contextlib
import fcntl
import inspect
import json
import os
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.fernet import Fernet, InvalidToken

from edge.auth.models import AuthError, StaffAccount, StoreData, auth_monotonic
from edge.auth.store import LOCK_FILE, MARKER_FILE, STORE_FILE, StaffStore
from edge.config import PROJECT_ROOT
from edge.tests import test_auth_support as support
from edge.tests.test_auth_support import DATA_KEY, OTHER_KEY, FakeClock, add_user, make_service

clock = support.clock  # pytest fixtures shared by the auth tests
fast_scrypt = support.fast_scrypt

FAKE_HASH = "scrypt$10$8$1$AAAAAAAAAAAAAAAAAAAAAA$" + "A" * 43


def account(username: str) -> StaffAccount:
    return StaffAccount(staff_id=f"s_{username}", username=username, display_name=username,
                        roles=("auditor",), password_hash=FAKE_HASH)


def add(store: StaffStore, username: str) -> None:
    store.update(lambda d: (d.with_account(account(username)), None))


def test_missing_file_is_an_empty_bootstrap_store(tmp_path: Path) -> None:
    store = StaffStore(tmp_path, DATA_KEY)
    assert store.state == "EMPTY" and store.available
    assert store.snapshot().accounts == {}


def test_roundtrip_is_encrypted_private_and_bumps_generation(tmp_path: Path) -> None:
    store = StaffStore(tmp_path, DATA_KEY)
    add(store, "guard01")
    add(store, "guard02")
    again = StaffStore(tmp_path, DATA_KEY)
    assert set(again.snapshot().accounts) == {"s_guard01", "s_guard02"} and again.generation == 2
    raw = (tmp_path / STORE_FILE).read_bytes()
    assert b"guard01" not in raw and b"scrypt" not in raw
    assert stat.S_IMODE((tmp_path / STORE_FILE).stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".staff.fernet.*.tmp"))


def test_store_key_is_derived_not_the_raw_edge_data_key(tmp_path: Path) -> None:
    add(StaffStore(tmp_path, DATA_KEY), "guard01")
    with pytest.raises(InvalidToken):
        Fernet(DATA_KEY.encode()).decrypt((tmp_path / STORE_FILE).read_bytes())


@pytest.mark.parametrize("key", [OTHER_KEY, "", "not-a-fernet-key"])
def test_wrong_or_missing_key_fails_closed_and_never_touches_the_file(tmp_path: Path, key: str) -> None:
    add(StaffStore(tmp_path, DATA_KEY), "guard01")
    before = (tmp_path / STORE_FILE).read_bytes()
    store = StaffStore(tmp_path, key)
    assert store.state == "UNAVAILABLE" and not store.available and store.error
    with pytest.raises(AuthError) as err:
        store.snapshot()
    assert err.value.code == "AUTH_UNAVAILABLE" and err.value.status == 503
    with pytest.raises(AuthError):
        add(store, "intruder")
    assert (tmp_path / STORE_FILE).read_bytes() == before


def test_corrupt_file_fails_closed_and_is_never_overwritten(tmp_path: Path) -> None:
    (tmp_path / STORE_FILE).write_bytes(b"garbage-not-fernet")
    store = StaffStore(tmp_path, DATA_KEY)
    assert store.state == "UNAVAILABLE"
    with pytest.raises(AuthError):
        add(store, "guard01")
    assert (tmp_path / STORE_FILE).read_bytes() == b"garbage-not-fernet"


def test_deleted_store_with_audit_history_is_missing_not_bootstrap(tmp_path: Path, clock: FakeClock,
                                                                   fast_scrypt: None) -> None:
    auth = make_service(tmp_path, clock)
    add_user(auth, "guard01", ["auditor"])
    (tmp_path / STORE_FILE).unlink()
    store = StaffStore(tmp_path, DATA_KEY)
    assert store.state == "MISSING" and not store.available
    with pytest.raises(AuthError):
        add(store, "guard02")
    store.update(lambda d: (d.with_account(account("guard02")), None), allow_missing=True)  # console recovery
    assert store.state == "OK"


def test_generation_going_backwards_is_a_rollback(tmp_path: Path) -> None:
    clock = FakeClock()
    store = StaffStore(tmp_path, DATA_KEY, monotonic=clock.mono)
    add(store, "guard01")
    old = (tmp_path / STORE_FILE).read_bytes()
    add(store, "guard02")
    (tmp_path / STORE_FILE).write_bytes(old)
    clock.advance(2)
    assert store.state == "UNAVAILABLE" and "rollback" in (store.error or "")


def test_readers_reload_on_change_at_most_once_per_interval(tmp_path: Path) -> None:
    clock = FakeClock()
    writer = StaffStore(tmp_path, DATA_KEY)
    reader = StaffStore(tmp_path, DATA_KEY, monotonic=clock.mono)
    add(writer, "guard01")
    assert reader.snapshot().accounts == {}  # stat throttled (< 1 s)
    clock.advance(1.1)
    assert set(reader.snapshot().accounts) == {"s_guard01"}


def test_updates_are_copy_on_write(tmp_path: Path) -> None:
    store = StaffStore(tmp_path, DATA_KEY)
    add(store, "guard01")
    before = store.snapshot()
    add(store, "guard02")
    assert set(before.accounts) == {"s_guard01"}
    with pytest.raises(TypeError):
        before.accounts["s_x"] = account("x")  # type: ignore[index]


def test_concurrent_writers_in_threads_lose_no_update(tmp_path: Path) -> None:
    stores = [StaffStore(tmp_path, DATA_KEY), StaffStore(tmp_path, DATA_KEY)]

    def work(i: int) -> None:
        for n in range(15):
            add(stores[i], f"user{i}x{n:02d}")

    threads = [threading.Thread(target=work, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    final = StaffStore(tmp_path, DATA_KEY).snapshot()
    assert len(final.accounts) == 30 and final.generation == 30


_CHILD = """
import sys
from edge.auth.models import StaffAccount
from edge.auth.store import StaffStore
store = StaffStore(sys.argv[1], sys.argv[2])
for n in range(8):
    acc = StaffAccount(staff_id=f"s_{sys.argv[3]}{n}", username=f"{sys.argv[3]}{n}", display_name="x",
                       roles=("auditor",), password_hash="h")
    store.update(lambda d, a=acc: (d.with_account(a), None))
"""


def test_concurrent_writers_in_separate_processes_lose_no_update(tmp_path: Path) -> None:
    env = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT)}
    procs = [subprocess.Popen([sys.executable, "-c", _CHILD, str(tmp_path), DATA_KEY, name], env=env)
             for name in ("proca", "procb")]
    assert all(p.wait(timeout=120) == 0 for p in procs)
    assert len(StaffStore(tmp_path, DATA_KEY).snapshot().accounts) == 16


def test_lock_held_elsewhere_gives_auth_busy(tmp_path: Path) -> None:
    store = StaffStore(tmp_path, DATA_KEY, lock_timeout_s=0.2)
    fd = os.open(tmp_path / "staff.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with pytest.raises(AuthError) as err:
            add(store, "guard01")
        assert err.value.code == "AUTH_BUSY" and err.value.status == 503
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    add(store, "guard01")


def test_failed_update_function_writes_nothing(tmp_path: Path) -> None:
    store = StaffStore(tmp_path, DATA_KEY)
    add(store, "guard01")

    def boom(_: StoreData) -> tuple[StoreData, None]:
        raise AuthError("INVALID_STATE", "no")

    with pytest.raises(AuthError):
        store.update(boom)
    assert store.generation == 1


def test_staff_store_key_override_and_rekey(tmp_path: Path) -> None:
    override = Fernet.generate_key().decode()
    store = StaffStore(tmp_path, DATA_KEY, store_key=override)
    add(store, "guard01")
    assert StaffStore(tmp_path, DATA_KEY).state == "UNAVAILABLE"  # derived key cannot read it
    new_key = Fernet.generate_key().decode()
    store.rekey(new_key)
    assert set(StaffStore(tmp_path, "", store_key=new_key).snapshot().accounts) == {"s_guard01"}
    assert StaffStore(tmp_path, DATA_KEY, store_key=override).state == "UNAVAILABLE"


# ---------------------------------------------------------------- EAC-04: OSError never escapes
_needs_non_root = pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                                     reason="root ignores file permissions")


@pytest.fixture
def restore_modes(tmp_path: Path) -> Iterator[list[Path]]:
    """Paths the test chmods; their modes are restored (0700 dirs, 0600 files) on teardown."""
    paths: list[Path] = []
    yield paths
    for p in paths:
        with contextlib.suppress(FileNotFoundError):
            os.chmod(p, 0o700 if p.is_dir() else 0o600)


@_needs_non_root
def test_unreadable_store_file_fails_closed_without_raising(tmp_path: Path, restore_modes: list[Path]) -> None:
    add(StaffStore(tmp_path, DATA_KEY), "guard01")
    restore_modes.append(tmp_path / STORE_FILE)
    os.chmod(tmp_path / STORE_FILE, 0)
    store = StaffStore(tmp_path, DATA_KEY)  # must not raise
    assert store.state == "UNAVAILABLE" and "PermissionError" in (store.error or "")
    with pytest.raises(AuthError) as err:
        store.snapshot()
    assert err.value.code == "AUTH_UNAVAILABLE" and err.value.status == 503
    with pytest.raises(AuthError) as err:
        add(store, "guard02")
    assert err.value.code == "AUTH_UNAVAILABLE"
    os.chmod(tmp_path / STORE_FILE, 0o600)
    store.refresh(force=True)
    assert store.state == "OK" and set(store.snapshot().accounts) == {"s_guard01"}


def test_directory_in_place_of_the_store_file_fails_closed(tmp_path: Path) -> None:
    (tmp_path / STORE_FILE).mkdir()
    store = StaffStore(tmp_path, DATA_KEY)
    assert store.state == "UNAVAILABLE" and "Error" in (store.error or "")
    with pytest.raises(AuthError) as err:
        store.snapshot()
    assert err.value.code == "AUTH_UNAVAILABLE"


def test_directory_in_place_of_the_lock_file_gives_auth_unavailable(tmp_path: Path) -> None:
    store = StaffStore(tmp_path, DATA_KEY)
    (tmp_path / LOCK_FILE).mkdir()
    with pytest.raises(AuthError) as err:
        add(store, "guard01")
    assert err.value.code == "AUTH_UNAVAILABLE" and err.value.status == 503
    with pytest.raises(AuthError) as err:
        store.rekey(Fernet.generate_key().decode())
    assert err.value.code == "AUTH_UNAVAILABLE"


@_needs_non_root
def test_unreadable_audit_history_fails_closed_without_raising(tmp_path: Path,
                                                              restore_modes: list[Path]) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_bytes(b'{"action":"staff.create"}\n')
    restore_modes.append(audit)
    os.chmod(audit, 0)
    store = StaffStore(tmp_path, DATA_KEY)  # must not raise
    assert store.state == "UNAVAILABLE" and "PermissionError" in (store.error or "")
    with pytest.raises(AuthError):
        add(store, "guard01")
    assert not (tmp_path / STORE_FILE).exists()


@_needs_non_root
def test_unreadable_marker_fails_closed_without_raising(tmp_path: Path, restore_modes: list[Path]) -> None:
    add(StaffStore(tmp_path, DATA_KEY), "guard01")
    restore_modes.append(tmp_path / MARKER_FILE)
    os.chmod(tmp_path / MARKER_FILE, 0)
    store = StaffStore(tmp_path, DATA_KEY)
    assert store.state == "UNAVAILABLE" and "PermissionError" in (store.error or "")


@_needs_non_root
def test_write_failure_gives_auth_unavailable_not_a_raw_oserror(tmp_path: Path,
                                                              restore_modes: list[Path]) -> None:
    store = StaffStore(tmp_path, DATA_KEY)
    add(store, "guard01")
    restore_modes.append(tmp_path)
    os.chmod(tmp_path, 0o500)  # the tmp file for the atomic write cannot be created
    with pytest.raises(AuthError) as err:
        add(store, "guard02")
    assert err.value.code == "AUTH_UNAVAILABLE"
    os.chmod(tmp_path, 0o700)
    assert set(StaffStore(tmp_path, DATA_KEY).snapshot().accounts) == {"s_guard01"}


# ---------------------------------------------------------------- EAC-02: readers never wait on the flock
def test_snapshot_does_not_block_while_an_update_waits_for_the_file_lock(tmp_path: Path) -> None:
    store = StaffStore(tmp_path, DATA_KEY, lock_timeout_s=1.5)
    add(store, "guard01")
    fd = os.open(tmp_path / LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
    outcome: list[str] = []

    def writer() -> None:
        try:
            add(store, "guard02")
            outcome.append("written")
        except AuthError as exc:
            outcome.append(exc.code)

    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        thread = threading.Thread(target=writer)
        thread.start()
        time.sleep(0.2)  # the writer is now polling the held flock
        started = time.perf_counter()
        snap = store.snapshot()
        elapsed = time.perf_counter() - started
        assert set(snap.accounts) == {"s_guard01"}
        assert elapsed < 0.1, f"snapshot blocked {elapsed:.3f}s behind a writer waiting on staff.lock"
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    thread.join(timeout=5)
    assert outcome == ["written"] and set(store.snapshot().accounts) == {"s_guard01", "s_guard02"}


# ---------------------------------------------------------------- EAC-09: persisted high-water mark
def _marker(tmp_path: Path) -> dict[str, object]:
    return json.loads((tmp_path / MARKER_FILE).read_bytes())


def test_every_write_persists_a_private_maced_marker(tmp_path: Path) -> None:
    store = StaffStore(tmp_path, DATA_KEY)
    add(store, "guard01")
    add(store, "guard02")
    marker = _marker(tmp_path)
    assert marker["generation"] == 2 and isinstance(marker["mac"], str) and len(marker["mac"]) == 64
    assert stat.S_IMODE((tmp_path / MARKER_FILE).stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".staff.marker.*.tmp"))


def test_rollback_is_detected_by_a_fresh_store_after_restart(tmp_path: Path) -> None:
    store = StaffStore(tmp_path, DATA_KEY)
    add(store, "guard01")
    gen1 = (tmp_path / STORE_FILE).read_bytes()
    add(store, "guard02")
    add(store, "guard03")
    assert store.generation == 3
    (tmp_path / STORE_FILE).write_bytes(gen1)
    reopened = StaffStore(tmp_path, DATA_KEY)  # new process: nothing in memory
    assert reopened.state == "UNAVAILABLE" and "rollback" in (reopened.error or "")
    with pytest.raises(AuthError):
        add(reopened, "guard04")
    assert (tmp_path / STORE_FILE).read_bytes() == gen1


@pytest.mark.parametrize("tamper", ["mac", "generation", "garbage", "empty", "not-a-dict", "bool-gen"])
def test_tampered_or_unparseable_marker_fails_closed(tmp_path: Path, tamper: str) -> None:
    add(StaffStore(tmp_path, DATA_KEY), "guard01")
    marker = _marker(tmp_path)
    if tamper == "mac":
        raw = json.dumps({**marker, "mac": "0" * 64}).encode()
    elif tamper == "generation":
        raw = json.dumps({**marker, "generation": 0}).encode()
    elif tamper == "garbage":
        raw = b"\x00not json"
    elif tamper == "empty":
        raw = b""
    elif tamper == "not-a-dict":
        raw = b"[1, 2]"
    else:
        raw = json.dumps({**marker, "generation": True}).encode()
    (tmp_path / MARKER_FILE).write_bytes(raw)
    store = StaffStore(tmp_path, DATA_KEY)
    assert store.state == "UNAVAILABLE" and "marker" in (store.error or "")
    with pytest.raises(AuthError):
        store.snapshot()


def test_marker_under_another_key_is_invalid(tmp_path: Path) -> None:
    add(StaffStore(tmp_path, DATA_KEY), "guard01")
    elsewhere = tmp_path / "other"
    add(StaffStore(elsewhere, OTHER_KEY), "x")
    (tmp_path / MARKER_FILE).write_bytes((elsewhere / MARKER_FILE).read_bytes())
    assert StaffStore(tmp_path, DATA_KEY).state == "UNAVAILABLE"


def test_store_without_a_marker_still_loads_and_the_next_write_creates_it(tmp_path: Path) -> None:
    add(StaffStore(tmp_path, DATA_KEY), "guard01")
    (tmp_path / MARKER_FILE).unlink()  # deployment from before the sidecar existed
    store = StaffStore(tmp_path, DATA_KEY)
    assert store.state == "OK"
    add(store, "guard02")
    assert _marker(tmp_path)["generation"] == 2


def test_rekey_rewrites_the_marker_under_the_new_key(tmp_path: Path) -> None:
    store = StaffStore(tmp_path, DATA_KEY)
    add(store, "guard01")
    gen1_marker = (tmp_path / MARKER_FILE).read_bytes()
    new_key = Fernet.generate_key().decode()
    store.rekey(new_key)
    assert _marker(tmp_path)["generation"] == 2 and (tmp_path / MARKER_FILE).read_bytes() != gen1_marker
    reopened = StaffStore(tmp_path, "", store_key=new_key)
    assert reopened.state == "OK" and set(reopened.snapshot().accounts) == {"s_guard01"}
    add(reopened, "guard02")
    assert StaffStore(tmp_path, DATA_KEY, store_key=new_key).generation == 3


# ---------------------------------------------------------------- F7 / EAC-03: MISSING without audit history
def test_deleted_store_is_missing_even_after_all_audit_files_rotated_away(
        tmp_path: Path, clock: FakeClock, fast_scrypt: None) -> None:
    auth = make_service(tmp_path, clock)
    add_user(auth, "guard01", ["auditor"])
    for p in tmp_path.glob("audit.jsonl*"):
        p.unlink()
    (tmp_path / STORE_FILE).unlink()
    store = StaffStore(tmp_path, DATA_KEY)
    assert store.state == "MISSING" and not store.available
    with pytest.raises(AuthError):
        add(store, "guard02")
    store.update(lambda d: (d.with_account(account("guard02")), None), allow_missing=True)
    assert store.state == "OK" and store.generation > 1


def test_marker_alone_marks_a_deleted_store_missing(tmp_path: Path) -> None:
    add(StaffStore(tmp_path, DATA_KEY), "guard01")
    (tmp_path / STORE_FILE).unlink()
    assert not list(tmp_path.glob("audit.jsonl*"))
    assert StaffStore(tmp_path, DATA_KEY).state == "MISSING"


def test_audit_history_alone_still_marks_a_deleted_store_missing(tmp_path: Path, clock: FakeClock,
                                                                 fast_scrypt: None) -> None:
    auth = make_service(tmp_path, clock)
    add_user(auth, "guard01", ["auditor"])
    (tmp_path / STORE_FILE).unlink()
    (tmp_path / MARKER_FILE).unlink()  # old deployment: no sidecar, only audit lines
    assert StaffStore(tmp_path, DATA_KEY).state == "MISSING"


# ---------------------------------------------------------------- EAC-05: sleep-inclusive clock by default
def test_default_monotonic_is_the_sleep_inclusive_auth_clock() -> None:
    assert inspect.signature(StaffStore).parameters["monotonic"].default is auth_monotonic


# ---------------------------------------------------------------- EAC-10: key fingerprint for the CLI
def test_fernet_fingerprint_tracks_the_effective_key_and_never_leaks_it(tmp_path: Path) -> None:
    store = StaffStore(tmp_path, DATA_KEY)
    same = StaffStore(tmp_path / "b", DATA_KEY)
    other = StaffStore(tmp_path / "c", OTHER_KEY)
    fp = store.fernet_fingerprint
    assert fp and fp == same.fernet_fingerprint and fp != other.fernet_fingerprint
    assert fp not in DATA_KEY and DATA_KEY not in fp
    add(store, "guard01")
    new_key = Fernet.generate_key().decode()
    store.rekey(new_key)
    assert store.fernet_fingerprint == StaffStore(tmp_path, "", store_key=new_key).fernet_fingerprint != fp
    assert StaffStore(tmp_path, "").fernet_fingerprint is None
