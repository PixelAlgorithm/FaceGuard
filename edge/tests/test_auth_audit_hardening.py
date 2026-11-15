"""Audit aggregation hardening (EAC-03): denials keyed on the route template, a cap on pending slots with an
overflow bucket, aggregated legacy-token use, and a MAC chain that still verifies under concurrent writers."""

from __future__ import annotations

import secrets
import string
import threading
from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.testclient import TestClient

from edge.auth import audit as audit_mod
from edge.auth.audit import AuditLog
from edge.auth.deps import route_template
from edge.auth.keys import audit_mac_key
from edge.tests import test_auth_support as support
from edge.tests.test_auth_http import bearer, make_app, sign_in
from edge.tests.test_auth_support import DATA_KEY, FakeClock, add_user, make_service

clock = support.clock
fast_scrypt = support.fast_scrypt
STAFF_TEMPLATE = "/v1/admin/staff/{staff_id}"
LEGACY_ACTOR = {"kind": "legacy", "id": "legacy:admin_token", "username": None}


def audit_log(tmp_path: Path, clock: FakeClock) -> AuditLog:
    return AuditLog(tmp_path, mac_key=audit_mac_key(DATA_KEY), max_bytes=8 * 1024 * 1024, keep=3, clock=clock)


def random_staff_id() -> str:
    return "s_a" + "".join(secrets.choice(string.ascii_lowercase) for _ in range(12))


def entries(log: AuditLog, action: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    cursor: int | None = None
    while True:
        page, cursor = log.read(limit=500, before_seq=cursor)
        out += [e for e in page if e["action"] == action]
        if cursor is None:
            return out


def staff_actor(i: int) -> dict[str, Any]:
    return {"kind": "staff", "id": f"s_user{i}", "username": f"user{i}"}


# ------------------------------------------------------------------ route template (deps)
def test_route_template_falls_back_to_unmatched_without_a_route() -> None:
    request = Request({"type": "http", "method": "GET", "path": "/v1/admin/staff/s_x", "headers": []})
    assert route_template(request) == "<unmatched>"


def test_denials_aggregate_on_the_route_template_not_the_raw_path(tmp_path: Path, clock: FakeClock,
                                                                 fast_scrypt: None) -> None:
    auth = make_service(tmp_path, clock)
    add_user(auth, "viewer01", ["auditor"])
    c = TestClient(make_app({"auth": auth}))
    token = sign_in(c, "viewer01")
    for _ in range(200):
        r = c.get(f"/v1/admin/staff/{random_staff_id()}", headers=bearer(token))
        assert r.status_code == 403 and r.json()["error"]["reason"] == "MISSING_PERMISSION"
    clock.advance(60)
    denials = entries(auth.audit, "auth.denied")
    assert len(denials) == 1
    assert denials[0]["target"] == STAFF_TEMPLATE and denials[0]["count"] == 200
    assert auth.audit.verify()


def test_pending_gate_denials_also_use_the_route_template(tmp_path: Path, clock: FakeClock,
                                                          fast_scrypt: None) -> None:
    auth = make_service(tmp_path, clock)
    add_user(auth, "temp01", ["admin"], must_change=True)
    c = TestClient(make_app({"auth": auth}))
    token = sign_in(c, "temp01")
    for _ in range(50):
        r = c.get(f"/v1/admin/staff/{random_staff_id()}", headers=bearer(token))
        assert r.json()["error"]["reason"] == "PASSWORD_CHANGE_REQUIRED"
    clock.advance(60)
    denials = entries(auth.audit, "auth.denied")
    assert [(d["target"], d["count"]) for d in denials] == [(STAFF_TEMPLATE, 50)]


# ------------------------------------------------------------------ slot cap (audit)
def test_pending_slots_are_capped_and_overflow_keeps_every_count(tmp_path: Path, clock: FakeClock) -> None:
    log = audit_log(tmp_path, clock)
    for i in range(5000):
        log.record_denial(actor=staff_actor(i), route=f"/v1/x/{i}", reason="MISSING_PERMISSION")
    log.record_denial(actor=staff_actor(1), route="/v1/x/1", reason="MISSING_PERMISSION")  # existing slot
    assert log.pending_slots() <= audit_mod.MAX_DENIAL_SLOTS + 2
    clock.advance(60)
    denials = entries(log, "auth.denied")
    assert sum(d["count"] for d in denials) == 5001
    overflow = [d for d in denials if d["target"] == "<other>"]
    assert len(overflow) == 1 and overflow[0]["detail"]["reason"] == "OVERFLOW"
    assert overflow[0]["count"] == 5000 - audit_mod.MAX_DENIAL_SLOTS
    assert next(d["count"] for d in denials if d["target"] == "/v1/x/1") == 2
    assert len(denials) == audit_mod.MAX_DENIAL_SLOTS + 1
    assert log.pending_slots() == 0 and log.verify()


def test_overflow_bucket_is_per_minute(tmp_path: Path, clock: FakeClock) -> None:
    log = audit_log(tmp_path, clock)
    for minute in range(2):
        for i in range(audit_mod.MAX_DENIAL_SLOTS + 3):
            log.record_denial(actor=staff_actor(i), route=f"/v1/m{minute}/{i}", reason="MISSING_PERMISSION")
        clock.advance(60)
    log.flush_denials()
    overflow = [d for d in entries(log, "auth.denied") if d["target"] == "<other>"]
    assert sorted(d["count"] for d in overflow) == [3, 3]
    assert len({d["detail"]["minute"] for d in overflow}) == 2


# ------------------------------------------------------------------ legacy-token use (audit)
def test_record_legacy_use_aggregates_per_route_and_minute(tmp_path: Path, clock: FakeClock) -> None:
    log = audit_log(tmp_path, clock)
    for _ in range(30):
        log.record_legacy_use(actor=LEGACY_ACTOR, route="/v1/admin/mode", client_ip="127.0.0.1")
    log.record_legacy_use(actor=LEGACY_ACTOR, route="/v1/admin/store", client_ip="127.0.0.1")
    assert not log.path.exists()  # the minute is still open
    minute = clock().strftime(audit_mod.MINUTE_FORMAT)
    clock.advance(60)
    lines = entries(log, "auth.legacy_token")
    assert {e["detail"]["route"]: e["count"] for e in lines} == {"/v1/admin/mode": 30, "/v1/admin/store": 1}
    for e in lines:
        assert e["outcome"] == "ok" and e["detail"]["minute"] == minute
        assert e["actor"]["kind"] == "legacy" and e["client_ip"] == "127.0.0.1"
    assert not entries(log, "auth.denied") and log.verify()


def test_flush_denials_writes_open_legacy_slots_too(tmp_path: Path, clock: FakeClock) -> None:
    log = audit_log(tmp_path, clock)
    log.record_legacy_use(actor=LEGACY_ACTOR, route="/v1/admin/mode", client_ip=None)
    log.record_denial(actor=None, route="/v1/admin/mode", reason="MISSING_PERMISSION")
    log.flush_denials(complete_only=True)
    assert not log.path.exists()
    log.flush_denials()  # shutdown: open minutes too
    assert log.pending_slots() == 0
    assert [e["count"] for e in entries(log, "auth.legacy_token")] == [1]
    assert [e["count"] for e in entries(log, "auth.denied")] == [1]


# ------------------------------------------------------------------ concurrency + chain
def test_concurrent_record_denial_counts_sum_and_chain_verifies(tmp_path: Path, clock: FakeClock) -> None:
    log = audit_log(tmp_path, clock)
    threads_n, per_thread = 8, 400
    barrier = threading.Barrier(threads_n)

    def worker(t: int) -> None:
        barrier.wait()
        for i in range(per_thread):
            log.record_denial(actor=staff_actor(i % 5), route=f"/v1/r{t % 3}", reason="MISSING_PERMISSION")
            if i % 50 == 0:
                log.record_legacy_use(actor=LEGACY_ACTOR, route=f"/v1/r{t % 3}", client_ip=None)
                log.flush_denials(complete_only=True)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(threads_n)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    clock.advance(60)
    denials = entries(log, "auth.denied")
    assert sum(d["count"] for d in denials) == threads_n * per_thread
    assert len(denials) == 5 * 3  # one line per (actor, route) in the single minute
    assert sum(e["count"] for e in entries(log, "auth.legacy_token")) == threads_n * (per_thread // 50)
    assert log.verify()


def test_concurrent_flushes_across_minutes_never_lose_or_duplicate(tmp_path: Path, clock: FakeClock) -> None:
    log = audit_log(tmp_path, clock)
    lock = threading.Lock()
    threads_n, per_thread = 8, 200

    def worker(t: int) -> None:
        for i in range(per_thread):
            log.record_denial(actor=staff_actor(t), route="/v1/r", reason="MISSING_PERMISSION")
            if t == 0 and i % 40 == 0:
                with lock:
                    clock.advance(60)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(threads_n)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    log.flush_denials()
    assert sum(d["count"] for d in entries(log, "auth.denied")) == threads_n * per_thread
    assert log.verify()
