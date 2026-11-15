"""offline-sync hardening (swarm 2026-11-15): bundle freshness ETag (EO-01 / RBAC v2 E), revocation feed cursor
(EO-M1 / cloud F1), SYNCING -> ONLINE gate (EO-03), clock skew (EO-04), corrupt overlay state (EO-08) and the
erasure replay contract (actor query + 404 rule). Unit level: SyncAgent wired to a scripted fake cloud on
temp paths with fixture keys; never the live edge."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from edge.offline.bundle import BundleStore, sign_bundle
from edge.offline.connectivity import ONLINE, SYNCING, ConnectivityMonitor
from edge.offline.erasures import PendingErasures
from edge.offline.signing import KioskAuth, verify_request
from edge.offline.store import DecisionLog
from edge.offline.sync import RevocationOverlay, SyncAgent, derived_etag
from edge.policy.tests.builders import (
    PROJECT_ROOT,
    TEST_BUNDLE_KEY,
    TEST_DATA_KEY,
    TEST_KIOSK_KEY,
    load_example_bundle,
)
from edge.policy.thresholds import Thresholds

KIOSK = "KIOSK_LIB_01"
T0 = datetime(2026, 11, 14, 4, 30, tzinfo=UTC)
OTHER_DATA_KEY = "a2V5LWZvci10ZXN0cy1vbmx5LTAxMjM0NTY3ODlhYmM="  # 32-byte urlsafe b64 (not TEST_DATA_KEY)


def _z(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def bundle_at(issued: datetime, version: int = 42) -> dict:
    b = load_example_bundle()
    b["bundle_version"] = version
    b["issued_at"], b["expires_at"] = _z(issued), _z(issued + timedelta(hours=12))
    return sign_bundle(b, TEST_BUNDLE_KEY)


class Clock:
    def __init__(self, t: datetime) -> None:
        self.t = t

    def __call__(self) -> datetime:
        return self.t


class Cloud:
    """Scripted cloud. etag_mode "old": ETag '"<v>"', 304 when If-None-Match carries the version (pre-fix cloud);
    "new": ETag '"v<v>-<issued epoch>"', 304 only on the exact ETag. Every 200 re-stamps issued_at = now."""

    def __init__(self, clock: Clock, etag_mode: str = "old", version: int = 42) -> None:
        self.clock, self.etag_mode, self.version = clock, etag_mode, version
        self.issued: datetime = clock()
        self.inm: list[str | None] = []
        self.revocations: dict = {"revocation_seq": 0, "items": []}
        self.sync_status = 200
        self.reject: set[str] = set()
        self.posted: list[list[str]] = []
        self.paths: list[str] = []
        self.erase_status: dict[str, tuple[int, dict | None]] = {}

    def etag(self) -> str:
        if self.etag_mode == "old":
            return f'"{self.version}"'
        return f'"v{self.version}-{int(self.issued.timestamp())}"'

    def __call__(self, request: httpx.Request) -> httpx.Response:
        raw = request.url.raw_path.decode()
        self.paths.append(raw)
        assert verify_request(request.method, raw, request.content or b"", request.headers, kiosk_key=TEST_KIOSK_KEY)
        path = request.url.path
        if path == "/v1/revocations":
            return httpx.Response(200, json=self.revocations)
        if path.startswith("/v1/schedule/"):
            return self._schedule(request)
        if path == "/v1/sync":
            if self.sync_status != 200:
                return httpx.Response(self.sync_status)
            items = json.loads(request.content)["items"]
            keys = [i["idempotency_key"] for i in items if "idempotency_key" in i]
            self.posted.append(keys)
            return httpx.Response(200, json={
                "accepted": [k for k in keys if k not in self.reject], "duplicates": [],
                "rejected": [{"idempotency_key": k, "error": "VALIDATION_ERROR"} for k in keys if k in self.reject],
                "flags": []})
        if path.startswith("/v1/enroll/"):
            status, body = self.erase_status.get(path.rsplit("/", 1)[1], (204, None))
            return httpx.Response(status, json=body) if body is not None else httpx.Response(status)
        return httpx.Response(404)

    def _schedule(self, request: httpx.Request) -> httpx.Response:
        inm = request.headers.get("If-None-Match")
        self.inm.append(inm)
        tags = {t.strip() for t in (inm or "").split(",") if t.strip()}
        if self.etag_mode == "old" and (f'"{self.version}"' in tags or str(self.version) in tags):
            return httpx.Response(304, headers={"ETag": self.etag()})
        if self.etag_mode == "new" and self.etag() in tags:
            return httpx.Response(304, headers={"ETag": self.etag()})
        self.issued = self.clock()  # the cloud re-stamps on every issue
        return httpx.Response(200, json=bundle_at(self.issued, self.version), headers={"ETag": self.etag()})


def make_agent(tmp_path: Path, cloud: Cloud, clock: Clock, *, state: str = SYNCING, log: DecisionLog | None = None,
               erasures: PendingErasures | None = None, overlay: RevocationOverlay | None = None) -> SyncAgent:
    cfg = Thresholds.load(PROJECT_ROOT / "config" / "thresholds.yaml")
    bpath = tmp_path / "bundle.signed.json"
    if not bpath.exists():
        bpath.write_text(json.dumps(bundle_at(cloud.issued, cloud.version)), encoding="utf-8")
    bundles = BundleStore(bpath, TEST_BUNDLE_KEY, KIOSK, clock=clock)
    log = log or DecisionLog(tmp_path / f"decisions_{KIOSK}.sqlite", TEST_DATA_KEY, KIOSK)
    monitor = ConnectivityMonitor(cfg, configured=True, initial=state, clock=clock)
    client = httpx.Client(base_url="https://cloud.test", transport=httpx.MockTransport(cloud),
                          auth=KioskAuth(KIOSK, TEST_KIOSK_KEY, "api"))
    return SyncAgent(cfg, log, bundles, monitor, client=client, kiosk_id=KIOSK, kiosk_key=TEST_KIOSK_KEY,
                     overlay=overlay or RevocationOverlay(tmp_path / "revocations.enc", TEST_DATA_KEY), clock=clock,
                     erasures=erasures)


def record(aid: str, seq_ts: datetime) -> dict:
    return {"attempt_id": aid, "kiosk_id": KIOSK, "zone": "LIBRARY", "ts_utc": _z(seq_ts), "user_id": "u_3c4d",
            "candidate_user_id": "u_3c4d", "decision": "ALLOW", "reason_codes": ["ACCESS_OK"], "resolved_codes": [],
            "scores": {"pad": 0.95}, "fallback": None, "schedule_version": 42, "cache_state": "FRESH",
            "mode": "OFFLINE"}


# ---------------------------------------------------------------- EO-01 bundle freshness
def test_EO01_old_cloud_304_by_version_still_renews_freshness_near_expiry(tmp_path):
    """Probe G3b: a pre-fix cloud answers 304 to If-None-Match '"42"' forever; the LVB must still be re-stamped
    before issued_at + 12 h, so an online kiosk never drops to STAFF_OVERRIDE-only."""
    clock = Clock(T0)
    cloud = Cloud(clock, "old")
    agent = make_agent(tmp_path, cloud, clock, state=ONLINE)
    for hours in (1, 3, 5, 7, 9, 11, 13, 15):
        clock.t = T0 + timedelta(hours=hours)
        report = agent.run_once()
        assert report["ok"] and report["error"] is None
        issued = datetime.fromisoformat(agent.bundles.lvb["issued_at"])
        eff = min(datetime.fromisoformat(agent.bundles.lvb["expires_at"]), issued + timedelta(hours=12))
        assert eff > clock.t + timedelta(hours=4), f"LVB about to expire at +{hours} h"
    assert None in cloud.inm  # near expiry the edge fetched unconditionally (no If-None-Match)


def test_EO01_new_cloud_full_etag_is_stored_and_sent_verbatim(tmp_path):
    clock = Clock(T0)
    cloud = Cloud(clock, "new")
    agent = make_agent(tmp_path, cloud, clock, state=ONLINE)
    agent.run_once()  # boot: no stored ETag -> the derived "v42-<epoch>" form of the installed LVB
    assert cloud.inm[-1] == derived_etag(agent.bundles.lvb) == cloud.etag()
    clock.t = T0 + timedelta(minutes=15)
    rep = agent.run_once()
    assert rep["bundle"] == "not_modified" and cloud.inm[-1] == cloud.etag()  # full ETag, never '"42"'
    assert agent.bundles.refresh_age_s() is not None and agent.bundles.refresh_age_s() < 1


def test_EO01_same_version_restamp_is_installed_and_counts_as_refresh(tmp_path):
    clock = Clock(T0)
    cloud = Cloud(clock, "new")
    agent = make_agent(tmp_path, cloud, clock, state=ONLINE)
    clock.t = T0 + timedelta(hours=7)  # within the refresh lead (effective expiry in 5 h)
    rep = agent.run_once()
    assert cloud.inm[-1] is None and rep["bundle"] == "installed"
    assert agent.bundles.lvb["issued_at"] == _z(clock.t) and agent.bundles.version == 42


def test_EO01_admin_force_refresh_never_sends_if_none_match(tmp_path):
    clock = Clock(T0)
    cloud = Cloud(clock, "old")
    agent = make_agent(tmp_path, cloud, clock, state=ONLINE)
    report: dict = {"bundle": None}
    agent._pull_bundle(report, force=True)
    assert cloud.inm[-1] is None and report["bundle"] in ("installed", "not_modified")


def test_derived_etag_handles_both_forms_and_bad_input():
    b = bundle_at(T0)
    assert derived_etag(b) == f'"v42-{int(T0.timestamp())}"'
    assert derived_etag(None) is None and derived_etag({"bundle_version": "42", "issued_at": _z(T0)}) is None
    assert derived_etag({"bundle_version": 42, "issued_at": "not a date"}) is None


# ---------------------------------------------------------------- EO-M1 feed cursor
def test_EOM1_feed_cursor_follows_received_items_not_the_server_counter(tmp_path):
    ov = RevocationOverlay(tmp_path / "revocations.enc", TEST_DATA_KEY)
    ov.apply({"revocation_seq": 9, "items": [{"seq": 9, "type": "USER", "target_id": "u_1a2b", "reason": "ADMIN"}]})
    # seq 10 is allocated but not yet written; the counter already says 11
    ov.apply({"revocation_seq": 11, "items": [{"seq": 11, "type": "USER", "target_id": "u_5e6f", "reason": "ADMIN"}]})
    assert ov.seq == 11
    ov2 = RevocationOverlay(tmp_path / "r2.enc", TEST_DATA_KEY)
    ov2.apply({"revocation_seq": 11, "items": [{"seq": 10, "type": "USER", "target_id": "u_a", "reason": "ADMIN"}]})
    assert ov2.seq == 10  # never the counter beyond the received items
    ov2.apply({"revocation_seq": 15, "items": []})
    assert ov2.seq == 10  # an empty page never moves the cursor


# ---------------------------------------------------------------- EO-03 SYNCING -> ONLINE gate
def test_EO03a_one_rejected_record_does_not_wedge_syncing_and_is_not_hot_resent(tmp_path):
    clock = Clock(T0)
    cloud = Cloud(clock, "new")
    agent = make_agent(tmp_path, cloud, clock)
    for aid in ("att_1", "att_bad", "att_3"):
        agent.log.append_final(record(aid, T0), created_real=T0)
    cloud.reject = {"att_bad"}
    rep = agent.run_once()
    assert agent.monitor.state == ONLINE  # rejected rows are quarantined, not an ONLINE blocker
    assert rep["quarantined"]["rejected"] == 1 and rep["queue_depth"] == 1 and rep["ok"] is False
    n = len(cloud.posted)
    agent.run_once()
    assert len(cloud.posted) == n  # the rejected row is not re-POSTed in a 2 s hot loop


def test_EO03b_undecryptable_rows_at_the_head_never_starve_valid_ones(tmp_path):
    clock = Clock(T0)
    cloud = Cloud(clock, "new")
    path = tmp_path / f"decisions_{KIOSK}.sqlite"
    old = DecisionLog(path, OTHER_DATA_KEY, KIOSK)
    for i in range(51):
        old.append_final(record(f"att_old{i:02d}", T0), created_real=T0)
    old.close()
    log = DecisionLog(path, TEST_DATA_KEY, KIOSK)
    log.append_final(record("att_new1", T0), created_real=T0)
    log.append_final(record("att_new2", T0), created_real=T0)
    agent = make_agent(tmp_path, cloud, clock, log=log)
    rep = agent.run_once()
    assert ["att_new1", "att_new2"] in cloud.posted
    assert rep["quarantined"]["undecryptable"] == 51 and agent.monitor.state == ONLINE


def test_EO03d_a_failing_push_still_refreshes_the_bundle(tmp_path):
    clock = Clock(T0)
    cloud = Cloud(clock, "new")
    agent = make_agent(tmp_path, cloud, clock, state=ONLINE)
    agent.log.append_final(record("att_1", T0), created_real=T0)
    cloud.sync_status = 503
    rep = agent.run_once()
    assert rep["error"] and rep["bundle"] in ("installed", "not_modified")
    assert agent.bundles.refresh_age_s() is not None and agent.monitor.state == ONLINE  # one miss only


# ---------------------------------------------------------------- EO-04 clock skew
def test_EO04_kiosk_auth_learns_server_time_and_resigns_once_on_401():
    skew = 90  # cloud clock 90 s ahead: outside the 60 s window
    seen: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        server_now = int(time.time()) + skew
        ok = verify_request(request.method, request.url.raw_path.decode(), request.content, request.headers,
                            kiosk_key=TEST_KIOSK_KEY, now_s=server_now)
        seen.append(200 if ok else 401)
        return httpx.Response(200 if ok else 401, headers={"X-Server-Time": str(server_now)})

    auth = KioskAuth(KIOSK, TEST_KIOSK_KEY)
    with httpx.Client(base_url="https://c", transport=httpx.MockTransport(handler), auth=auth) as c:
        assert c.get("/v1/revocations", params={"since": 0}).status_code == 200
        assert c.post("/v1/sync", content=b"{}").status_code == 200  # signed with the learned offset first time
    assert seen == [401, 200, 200] and abs(auth.clock_offset_s - skew) < 3
    assert auth.last_drift_s is not None


def test_EO04_small_drift_is_not_corrected_and_bad_headers_are_ignored():
    auth = KioskAuth(KIOSK, TEST_KIOSK_KEY)
    assert auth.observe(httpx.Response(200, headers={"X-Server-Time": str(time.time() + 10)})) is False
    assert auth.clock_offset_s == 0.0
    for bad in ("nan", "inf", "x", ""):
        assert auth.observe(httpx.Response(200, headers={"X-Server-Time": bad})) is False
    assert auth.clock_offset_s == 0.0


# ---------------------------------------------------------------- EO-08 corrupt overlay state
@pytest.mark.parametrize("content", [b"", b"\x00" * 7, b"garbage-not-aes-gcm" * 4])
def test_EO08_corrupt_overlay_file_is_quarantined_and_fails_safe(tmp_path, content):
    path = tmp_path / "revocations.enc"
    path.write_bytes(content)
    ov = RevocationOverlay(path, TEST_DATA_KEY)  # must not raise
    quarantined = list(tmp_path.glob("revocations.enc.corrupt-*"))
    assert len(quarantined) == 1 and quarantined[0].read_bytes() == content
    assert ov.state_lost is True and ov.seq == 0
    assert RevocationOverlay(path, TEST_DATA_KEY).state_lost is True  # persisted: a restart cannot clear it


def test_EO08_lost_overlay_blocks_online_until_a_full_feed_re_pull(tmp_path):
    clock = Clock(T0)
    cloud = Cloud(clock, "new")
    (tmp_path / "revocations.enc").write_bytes(b"")
    overlay = RevocationOverlay(tmp_path / "revocations.enc", TEST_DATA_KEY)
    agent = make_agent(tmp_path, cloud, clock, overlay=overlay)
    cloud.revocations = {"revocation_seq": 3, "items": [
        {"seq": 3, "type": "USER", "target_id": "u_3c4d", "revoked_at": _z(T0), "reason": "ADMIN"}]}
    rep = agent.run_once()  # since=0 -> full feed rebuilt -> may go ONLINE
    assert "/v1/revocations?since=0" in cloud.paths
    assert overlay.state_lost is False and overlay.reason("u_3c4d") == "ADMIN"
    assert agent.monitor.state == ONLINE and rep["revocations_state_lost"] is False


def test_EO08_overlay_stays_lost_when_the_feed_pull_fails(tmp_path):
    clock = Clock(T0)
    cloud = Cloud(clock, "new")
    (tmp_path / "revocations.enc").write_bytes(b"")
    overlay = RevocationOverlay(tmp_path / "revocations.enc", TEST_DATA_KEY)
    agent = make_agent(tmp_path, cloud, clock, overlay=overlay)
    cloud.revocations = {"broken": True}  # 200 but no items -> nothing applied ...

    def boom(_payload):
        raise ValueError("feed unparsable")

    overlay.apply = boom  # ... and the apply step fails
    agent.run_once()
    assert overlay.state_lost is True and agent.monitor.state != ONLINE


# ---------------------------------------------------------------- erasure replay contract (policy-fixes / EAE-12)
def test_erasure_replay_signs_the_actor_query_and_only_a_reasoned_404_is_done(tmp_path):
    clock = Clock(T0)
    cloud = Cloud(clock, "new")
    er = PendingErasures(None, None)
    for uid in ("u_1a2b", "u_3c4d", "u_5e6f"):
        er.add(uid, T0)
    agent = make_agent(tmp_path, cloud, clock, erasures=er)
    agent.erasures.items = lambda: [  # store with the V2 D actor field
        {"user_id": "u_1a2b", "queued_at": _z(T0), "actor": "staff:s_admin01"},
        {"user_id": "u_3c4d", "queued_at": _z(T0), "actor": None},
        {"user_id": "u_5e6f", "queued_at": _z(T0)},
    ]
    cloud.erase_status = {"u_3c4d": (404, {"error": {"code": "NOT_FOUND", "message": "x", "reason": "NOT_ENROLLED"}}),
                          "u_5e6f": (404, {"error": {"code": "NOT_FOUND", "message": "no such route"}})}
    out = agent.replay_erasures()
    deletes = [p for p in cloud.paths if p.startswith("/v1/enroll/")]
    assert parse_qs(urlsplit(deletes[0]).query) == {"actor": ["staff:s_admin01"]}  # signed raw path incl. query
    assert deletes[1] == "/v1/enroll/u_3c4d" and deletes[2] == "/v1/enroll/u_5e6f"
    assert sorted(out["done"]) == ["u_1a2b", "u_3c4d"]
    assert out["failed"] == [{"user_id": "u_5e6f", "status": 404}]  # a bare 404 stays queued


# ---------------------------------------------------------------- EO-13 public summary (review OS-9)
def test_EO13_public_mode_status_report_carries_no_user_or_attempt_ids(make_rt, cloud):
    """The path GET /v1/mode actually serves (runtime.mode_status -> last_sync.report), not a helper copy."""
    from edge.offline.tests.conftest import attempt

    rt = make_rt(cloud)
    rt.decide(attempt("att_eo13"))
    cloud.revocations = [{"seq": 1, "type": "USER", "target_id": "u_5e6f", "revoked_at": "2026-11-14T04:00:00Z",
                          "reason": "ADMIN"}]
    cloud.flags = [{"attempt_id": "att_eo13", "type": "POST_HOC_REVOKED"}]
    full = rt.sync_now()
    assert full["revoked_users"] == ["u_5e6f"]  # the authenticated admin caller sees the detail
    public = json.dumps(rt.mode_status()["last_sync"])
    assert "u_5e6f" not in public and "att_eo13" not in public


# ---------------------------------------------------------------- review round 2 (OS-1/2/3/6/7)
def test_OS1_rebuild_from_since_0_never_purges_a_readmitted_user(tmp_path):
    path = tmp_path / "revocations.enc"
    path.write_bytes(b"")  # quarantined -> seq 0, full history next
    ov = RevocationOverlay(path, TEST_DATA_KEY)
    ov.apply({"revocation_seq": 3, "items": [
        {"seq": 1, "type": "ERASE", "target_id": "u_prj1", "revoked_at": "2026-11-14T01:00:00Z", "reason": "ERASED"},
        {"seq": 2, "type": "READMIT", "target_id": "u_prj1", "revoked_at": "2026-11-14T02:00:00Z",
         "reason": "READMIT"},
        {"seq": 3, "type": "ERASE", "target_id": "u_tm02", "revoked_at": "2026-11-14T03:00:00Z", "reason": "ERASED"}]})
    assert ov.pending_purge() == ["u_tm02"]  # still erased -> purge; readmitted (maybe re-enrolled) -> untouched
    assert ov.reason("u_prj1") is None and ov.state_lost is False


def test_OS1_incremental_erase_then_readmit_still_purges_pre_erasure_data(tmp_path):
    ov = RevocationOverlay(tmp_path / "revocations.enc", TEST_DATA_KEY)
    ov.apply({"revocation_seq": 1, "items": [{"seq": 1, "type": "USER", "target_id": "u_x", "reason": "ADMIN"}]})
    ov.apply({"revocation_seq": 3, "items": [
        {"seq": 2, "type": "ERASE", "target_id": "u_prj1", "revoked_at": "2026-11-14T01:00:00Z", "reason": "ERASED"},
        {"seq": 3, "type": "READMIT", "target_id": "u_prj1", "revoked_at": "2026-11-14T02:00:00Z",
         "reason": "READMIT"}]})
    assert ov.pending_purge() == ["u_prj1"]  # this kiosk still holds the pre-erasure templates: delete them


def test_OS2_quarantined_rows_are_not_sendable_work(tmp_path):
    clock = Clock(T0)
    cloud = Cloud(clock, "new")
    agent = make_agent(tmp_path, cloud, clock)
    agent.log.append_final(record("att_bad", T0), created_real=T0)
    cloud.reject = {"att_bad"}
    agent.run_once()
    assert agent.log.queue_depth() == 1 and agent.has_sendable_work() is False  # no 2 s ONLINE hot loop
    agent.log.append_final(record("att_new", T0), created_real=T0)
    assert agent.has_sendable_work() is True
    agent.run_once()
    assert agent.has_sendable_work() is False
    agent._rejected_at = {k: v - 3600 for k, v in agent._rejected_at.items()}  # retry window elapsed
    assert agent.has_sendable_work() is True


def test_OS3_cloud_bundle_older_than_the_lvb_is_a_no_progress_cycle_alerted_once(tmp_path):
    clock = Clock(T0)
    cloud = Cloud(clock, "new", version=45)
    (tmp_path / "bundle.signed.json").write_text(json.dumps(bundle_at(T0, 46)), encoding="utf-8")  # local re-sign
    agent = make_agent(tmp_path, cloud, clock)
    reports = [agent.run_once() for _ in range(3)]
    assert all(r["bundle"] == "newer_than_cloud" and r["no_progress"] is True for r in reports)
    assert agent.bundles.version == 46 and agent.monitor.state == SYNCING  # never confirmed by an older cloud
    assert agent.bundles.refresh_age_s() is None
    alerts = [a for a in agent.bundles.alerts if a["type"] in ("BUNDLE_REJECTED", "BUNDLE_NEWER_THAN_CLOUD")]
    assert len(alerts) == 1 and alerts[0]["type"] == "BUNDLE_NEWER_THAN_CLOUD"
    assert cloud.inm[1] == cloud.etag()  # later cycles ask with the cloud's own ETag -> 304, no re-download
    cloud.version = 47  # the cloud publishes a newer version -> installed, progress again
    clock.t = T0 + timedelta(minutes=1)
    rep = agent.run_once()
    assert rep["bundle"] == "installed" and rep["no_progress"] is False and agent.bundles.version == 47


def test_OS6_a_rejected_tombstone_is_quarantined_not_a_wedge(tmp_path):
    clock = Clock(T0)
    cloud = Cloud(clock, "new")
    log = DecisionLog(tmp_path / f"decisions_{KIOSK}.sqlite", TEST_DATA_KEY, KIOSK, retention_hours=1)
    log.append_final(record("att_old", T0 - timedelta(hours=3)), created_real=T0 - timedelta(hours=3))
    assert log.purge_expired(T0) is not None and len(log.tombstones()) == 1
    agent = make_agent(tmp_path, cloud, clock, log=log)
    orig = cloud.__call__

    def reject_tombstones(request):
        if request.url.path == "/v1/sync":
            items = json.loads(request.content)["items"]
            if any(i.get("type") == "TOMBSTONE" for i in items):
                return httpx.Response(200, json={"accepted": [], "duplicates": [], "flags": [],
                                                 "rejected": [{"idempotency_key": None, "error": "VALIDATION_ERROR"}]})
        return orig(request)

    agent.client._transport = httpx.MockTransport(reject_tombstones)
    rep = agent.run_once()
    assert agent.monitor.state == ONLINE and rep["quarantined"]["tombstones"] == 1
    assert len(log.tombstones()) == 1 and agent.has_sendable_work() is False


def test_OS7_a_feed_404_never_clears_a_lost_overlay(tmp_path):
    clock = Clock(T0)
    cloud = Cloud(clock, "new")
    (tmp_path / "revocations.enc").write_bytes(b"")
    overlay = RevocationOverlay(tmp_path / "revocations.enc", TEST_DATA_KEY)
    agent = make_agent(tmp_path, cloud, clock, overlay=overlay)
    orig = cloud.__call__
    agent.client._transport = httpx.MockTransport(
        lambda r: httpx.Response(404) if r.url.path == "/v1/revocations" else orig(r))
    rep = agent.run_once()
    assert overlay.state_lost is True and RevocationOverlay(tmp_path / "revocations.enc", TEST_DATA_KEY).state_lost
    assert rep["revocations_feed"] == "unavailable" and agent.monitor.state != ONLINE
