"""R-J (docs/API.md §3.15 DELETE /v1/enroll `queued`): pending CLOUD erasures persisted encrypted in edge/offline and
replayed at every sync until the cloud answers 200/204/404 (idempotent). Stored fields: user_id + queued_at only.
All in-process with the fake cloud -- never the live :8000 edge.
"""

from __future__ import annotations

import os
import stat

import httpx
import pytest

from edge.offline.erasures import PendingErasures
from edge.offline.store import iso_utc
from edge.policy.runtime import CloudUnavailableError
from edge.policy.tests.builders import RT_CLOCK, TEST_DATA_KEY


class EraseCloud:
    """Wraps the offline FakeCloud: answers DELETE /v1/enroll/{user_id} with a scripted status."""

    def __init__(self, inner, statuses: dict[str, int | None] | None = None) -> None:
        self.inner, self.statuses, self.deletes = inner, statuses or {}, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        p = request.url.path
        if request.method == "DELETE" and p.startswith("/v1/enroll/"):
            self.inner.calls.append((request.method, p))
            if not self.inner.up:
                raise httpx.ConnectError("cloud down", request=request)
            uid = p.rsplit("/", 1)[1]
            self.deletes.append(uid)
            status = self.statuses.get(uid, 200)
            if status is None:
                raise httpx.ReadTimeout("timeout", request=request)
            return httpx.Response(status, json={"user_id": uid, "erased": status == 200})
        return self.inner(request)


@pytest.fixture
def erase_rt(make_rt, cloud, tmp_path):
    def make(statuses: dict[str, int | None] | None = None):
        ec = EraseCloud(cloud, statuses)
        rt = make_rt(cloud)
        rt._client._transport = httpx.MockTransport(ec)  # same signed client, DELETE answered by EraseCloud
        return rt, ec
    return make


# ---------------------------------------------------------------- store
def test_store_round_trip_encrypted_owner_only(tmp_path):
    path = tmp_path / "pending_erasures.enc"
    s = PendingErasures(path, TEST_DATA_KEY)
    t0 = RT_CLOCK()
    first = s.add("u_3c4d", t0)
    assert first == {"user_id": "u_3c4d", "queued_at": iso_utc(t0)}
    s.add("u_3c4d", t0.replace(year=2027))  # idempotent: the first queued_at is kept
    s.add("u_1a2b", t0)
    assert [e["user_id"] for e in s.items()] == ["u_1a2b", "u_3c4d"]
    raw = path.read_bytes()
    assert b"u_3c4d" not in raw and b"queued_at" not in raw  # encrypted at rest
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    again = PendingErasures(path, TEST_DATA_KEY)
    assert again.items() == s.items()
    assert set(again.items()[0]) == {"user_id", "queued_at"}  # minimum fields only
    assert again.remove("u_3c4d") is True and again.remove("u_3c4d") is False
    assert [e["user_id"] for e in PendingErasures(path, TEST_DATA_KEY).items()] == ["u_1a2b"]


@pytest.mark.parametrize("bad", ["", "u_ABCD", "u_abc", "../etc", "u_abcd/x", "s_guard01", None, 42])
def test_store_rejects_invalid_user_ids(tmp_path, bad):
    s = PendingErasures(tmp_path / "p.enc", TEST_DATA_KEY)
    with pytest.raises(ValueError):
        s.add(bad, RT_CLOCK())
    assert s.items() == []


def test_store_without_a_path_is_in_memory(tmp_path):
    s = PendingErasures(None, None)
    s.add("u_3c4d", RT_CLOCK())
    assert [e["user_id"] for e in s.items()] == ["u_3c4d"]


# ---------------------------------------------------------------- runtime + sync replay
def test_queue_is_listed_and_survives_a_restart(make_rt, tmp_path):
    rt = make_rt()
    out = rt.queue_cloud_erasure("u_3c4d")
    assert set(out) == {"user_id", "queued_at"} and out["user_id"] == "u_3c4d"
    assert out["queued_at"].startswith("2026-11-14T04:35") and out["queued_at"].endswith("Z")  # real clock, UTC
    assert [e["user_id"] for e in rt.pending_cloud_erasures()] == ["u_3c4d"]
    rt.stop()
    assert [e["user_id"] for e in make_rt().pending_cloud_erasures()] == ["u_3c4d"]
    assert any(e["type"] == "CLOUD_ERASURE_QUEUED" for e in rt.events())


def test_sync_replays_pending_erasures_and_purges_on_200_204_404(erase_rt):
    rt, ec = erase_rt({"u_1a2b": 204, "u_7a8b": 404})
    for uid in ("u_3c4d", "u_1a2b", "u_7a8b"):
        rt.queue_cloud_erasure(uid)
    rep = rt.sync_now()
    assert sorted(ec.deletes) == ["u_1a2b", "u_3c4d", "u_7a8b"]
    assert rt.pending_cloud_erasures() == []
    assert sorted(rep["cloud_erasures"]["done"]) == ["u_1a2b", "u_3c4d", "u_7a8b"]
    assert rep["cloud_erasures"]["pending"] == 0
    rt.sync_now()
    assert len(ec.deletes) == 3  # nothing replayed twice


def test_failed_replay_stays_queued_and_is_retried(erase_rt):
    rt, ec = erase_rt({"u_3c4d": 500, "u_1a2b": 401})
    rt.queue_cloud_erasure("u_3c4d")
    rt.queue_cloud_erasure("u_1a2b")
    rep = rt.sync_now()
    assert {e["user_id"] for e in rt.pending_cloud_erasures()} == {"u_3c4d", "u_1a2b"}
    assert rep["cloud_erasures"]["pending"] == 2 and rep["cloud_erasures"]["done"] == []
    assert {f["user_id"] for f in rep["cloud_erasures"]["failed"]} == {"u_3c4d", "u_1a2b"}
    ec.statuses = {}
    rt.sync_now()
    assert rt.pending_cloud_erasures() == []


def test_transport_failure_keeps_the_queue_and_fails_the_sync(erase_rt):
    rt, _ = erase_rt({"u_3c4d": None})
    rt.queue_cloud_erasure("u_3c4d")
    with pytest.raises(CloudUnavailableError):
        rt.sync_now()
    assert [e["user_id"] for e in rt.pending_cloud_erasures()] == ["u_3c4d"]


def test_replay_runs_after_revocations_and_before_the_bundle_pull(erase_rt, cloud):
    rt, _ = erase_rt()
    rt.queue_cloud_erasure("u_3c4d")
    cloud.calls.clear()
    rt.sync_now()
    paths = [p for _, p in cloud.calls]
    i_rev, i_del = paths.index("/v1/revocations"), paths.index("/v1/enroll/u_3c4d")
    i_bundle = next(i for i, p in enumerate(paths) if p.startswith("/v1/schedule/"))
    assert i_rev < i_del < i_bundle  # the erasure re-signs the bundle: installed in the same cycle


def test_no_replay_while_forced_offline_or_unconfigured(erase_rt, make_rt):
    rt, ec = erase_rt()
    rt.queue_cloud_erasure("u_3c4d")
    rt.set_forced_mode("OFFLINE")
    with pytest.raises(CloudUnavailableError):
        rt.replay_cloud_erasures()
    assert ec.deletes == []
    bare = make_rt()
    with pytest.raises(CloudUnavailableError):
        bare.replay_cloud_erasures()


def test_replay_cloud_erasures_flush(erase_rt):
    rt, ec = erase_rt()
    rt.queue_cloud_erasure("u_3c4d")
    rep = rt.replay_cloud_erasures()
    assert rep["done"] == ["u_3c4d"] and rep["pending"] == 0 and ec.deletes == ["u_3c4d"]


def test_queue_rejects_invalid_user_ids(make_rt):
    rt = make_rt()
    with pytest.raises(ValueError):
        rt.queue_cloud_erasure("../v1/admin")
    assert rt.pending_cloud_erasures() == []
