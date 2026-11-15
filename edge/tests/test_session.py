import itertools
from datetime import UTC, datetime, timedelta

import pytest

from edge.session import FLASH_PALETTE, NONCE_TTL_S, AttemptStore, NonceError, make_flash_sequence


def test_flash_sequence_constraints(thresholds):
    """Lead decision (round 2): exactly 3 distinct colours x ~333 ms in the 1000 ms window."""
    total = thresholds.get("liveness.flash.duration_ms")
    max_changes = thresholds.get("liveness.flash.max_changes_per_s")
    third = total // 3
    for _ in range(500):
        seq = make_flash_sequence(thresholds)
        colours = [s.color for s in seq]
        assert len(seq) == 3
        assert [s.duration_ms for s in seq] == [third, third, total - 2 * third]
        assert len(set(colours)) == len(colours), "colours must be distinct"
        assert set(colours) <= set(FLASH_PALETTE)
        assert seq[0].offset_ms == 0
        assert sum(s.duration_ms for s in seq) == total
        assert all(s.duration_ms >= 200 for s in seq)
        assert all(b.offset_ms == a.offset_ms + a.duration_ms for a, b in itertools.pairwise(seq))
        assert (len(seq) - 1) <= max_changes * total / 1000.0  # <= 3 changes per second


def test_flash_sequences_are_unpredictable(thresholds):
    seqs = {tuple(s.color for s in make_flash_sequence(thresholds)) for _ in range(50)}
    assert len(seqs) > 10


def _new(store: AttemptStore, now=None):
    return store.create(kiosk_id="K", flash_enabled=True, flash_sequence=[], camera_label="cam",
                        claimed_user_id=None, recapture_of=None, recapture_count=0, now=now)


def test_attempt_ids_and_nonce_single_use():
    store = AttemptStore()
    att = _new(store)
    assert att.attempt_id.startswith("att_") and len(att.attempt_id) == 30
    assert att.nonce.startswith("n_")
    store.consume_nonce(att.attempt_id, att.nonce)
    with pytest.raises(NonceError) as e:
        store.consume_nonce(att.attempt_id, att.nonce)
    assert e.value.code == "NONCE_REUSED"


def test_nonce_mismatch_and_expiry():
    store = AttemptStore()
    att = _new(store)
    with pytest.raises(NonceError) as e:
        store.consume_nonce(att.attempt_id, "n_wrong")
    assert e.value.code == "NONCE_INVALID"
    late = datetime.now(UTC) + timedelta(seconds=NONCE_TTL_S + 1)
    with pytest.raises(NonceError) as e:
        store.consume_nonce(att.attempt_id, att.nonce, now=late)
    assert e.value.code == "NONCE_EXPIRED"
    with pytest.raises(NonceError) as e:  # an expired nonce is burnt
        store.consume_nonce(att.attempt_id, att.nonce)
    assert e.value.code == "NONCE_REUSED"


def test_unknown_attempt():
    with pytest.raises(NonceError) as e:
        AttemptStore().consume_nonce("att_x", "n_x")
    assert e.value.code == "ATTEMPT_NOT_FOUND"
