"""Revocation feed v1.4 (docs/API.md §4.3, lead rulings R-B / R-C): ERASE / READMIT items, USER revocations.

- ERASE (and a legacy USER item with reason ERASED): purge the user's local templates (erase hooks) + TOTP secret
  once per event; NOT a permanent deny entry: a time-aware ERASED suspension until READMIT / re-enrolment.
- READMIT reason READMIT (or any non-RESTORE reason): drop ERASED state <= the event time, clear the runtime's
  once-per-user marker (a later ERASE purges again); ADMIN / security entries stay.
- READMIT reason RESTORE: drop ALL of the user's USER entries <= the event time.
- USER (ADMIN, ...) revocation: SCHEDULE_REVOKED online and offline, persisted encrypted (survives a restart).
All in-process with the fake cloud -- never the live :8000 edge.
"""

from __future__ import annotations

import copy
import json
from datetime import timedelta

import pytest

from edge.offline.bundle import sign_bundle
from edge.offline.store import iso_utc
from edge.offline.sync import RevocationOverlay
from edge.offline.tests.conftest import attempt, bring_online
from edge.policy.tests.builders import RT_CLOCK, TEST_BUNDLE_KEY, TEST_DATA_KEY


def _t(minutes: float = 0) -> str:
    return iso_utc(RT_CLOCK() + timedelta(minutes=minutes))


def _feed(cloud, *items) -> None:
    cloud.revocations = [{"seq": i + 1, **it} for i, it in enumerate(items)]


def _erase(uid: str, at: str) -> dict:
    return {"type": "ERASE", "target_id": uid, "revoked_at": at, "reason": "ERASED"}


def _readmit(uid: str, at: str, reason: str = "READMIT") -> dict:
    return {"type": "READMIT", "target_id": uid, "revoked_at": at, "reason": reason}


def _user(uid: str, at: str, reason: str = "ADMIN") -> dict:
    return {"type": "USER", "target_id": uid, "revoked_at": at, "reason": reason}


def _hooked(rt) -> list[str]:
    calls: list[str] = []
    rt.add_erase_hook(calls.append)
    return calls


# ---------------------------------------------------------------- ERASE
def test_erase_item_purges_once_and_suspends_until_lifted(make_rt, cloud):
    rt = make_rt(cloud)
    calls = _hooked(rt)
    _feed(cloud, _erase("u_3c4d", _t(-1)))
    rt.sync.pull_revocations()  # the purge runs right after the feed is applied (no tick needed)
    assert calls == ["u_3c4d"] and rt.credentials.totp_secret("u_3c4d") is None
    rt.tick()
    rt.sync.pull_revocations()
    assert calls == ["u_3c4d"]  # once per ERASE event
    assert rt.overlay.reason("u_3c4d") == "ERASED"  # enrolment sees an erasure, not an ADMIN revocation
    assert any(e["type"] == "USER_ERASED_LOCAL" and e["user_id"] == "u_3c4d" for e in rt.events())
    # fail-secure suspension until the re-signed bundle / READMIT (even if a purge hook had failed)
    assert [e["reason"] for e in rt.overlay.entries() if e["user_id"] == "u_3c4d"] == ["ERASED"]
    assert "u_3c4d" not in rt.entitled_user_ids()
    body = rt.decide(attempt("att_erased_suspended"))
    assert body["decision"] == "DENY" and "SCHEDULE_REVOKED" in body["reason_codes"]
    cloud.revocations.append({"seq": 2, **_readmit("u_3c4d", _t(0))})
    rt.sync.pull_revocations()
    assert all(e["user_id"] != "u_3c4d" for e in rt.overlay.entries())  # not permanent
    assert "u_3c4d" in rt.entitled_user_ids()


def test_legacy_user_item_with_reason_erased_is_treated_as_erase(make_rt, cloud):
    rt = make_rt(cloud)
    calls = _hooked(rt)
    _feed(cloud, _user("u_3c4d", _t(-1), "ERASED"))
    rt.sync.pull_revocations()
    assert calls == ["u_3c4d"] and rt.overlay.reason("u_3c4d") == "ERASED"
    assert [e["reason"] for e in rt.overlay.entries()] == ["ERASED"]  # one suspension, no ADMIN-style deny entry


def test_legacy_overlay_file_with_an_erased_deny_entry_is_migrated_on_load(tmp_path):
    """The live edge may hold a USER/ERASED entry (u_prj1) written by the old overlay: on load it becomes erasure
    state (cleared by READMIT / re-enrolment), not a permanent deny entry."""
    path = tmp_path / "revocations.enc"
    old = RevocationOverlay(path, TEST_DATA_KEY)
    old.users = {"u_prj1": {"user_id": "u_prj1", "revoked_at": "2026-11-14T11:02:10Z", "reason": "ERASED"},
                 "u_1a2b": {"user_id": "u_1a2b", "revoked_at": "2026-11-14T11:00:00Z", "reason": "ADMIN"}}
    old.seq = 9
    # the pre-v1.4 file layout exactly: {"seq", "users", "cards"}
    blob = json.dumps({"seq": old.seq, "users": old.users, "cards": []}).encode()
    path.write_bytes(old._c.encrypt(blob, b"revocations"))
    ov = RevocationOverlay(path, TEST_DATA_KEY)
    assert ov.seq == 9
    assert [(e["user_id"], e["reason"]) for e in ov.entries()] == [("u_1a2b", "ADMIN"), ("u_prj1", "ERASED")]
    assert ov.reason("u_prj1") == "ERASED" and ov.reason("u_1a2b") == "ADMIN"
    ov.apply({"items": [{**_readmit("u_prj1", "2026-11-14T12:45:00Z"), "seq": 11}], "revocation_seq": 11})
    again = RevocationOverlay(path, TEST_DATA_KEY)
    assert again.reason("u_prj1") is None and again.reason("u_1a2b") == "ADMIN" and again.seq == 11
    assert [e["user_id"] for e in again.entries()] == ["u_1a2b"]  # the legacy erasure no longer blocks


def test_erase_does_not_overwrite_an_admin_revocation(make_rt, cloud):
    rt = make_rt(cloud)
    _feed(cloud, _user("u_3c4d", _t(-2)), _erase("u_3c4d", _t(-1)))
    rt.sync.pull_revocations()
    assert rt.overlay.reason("u_3c4d") == "ADMIN" and "u_3c4d" in rt.revoked_user_ids()
    assert [e["reason"] for e in rt.overlay.entries() if e["user_id"] == "u_3c4d"] == ["ADMIN"]


# ---------------------------------------------------------------- READMIT
def test_readmit_clears_the_erasure_and_a_later_erase_purges_again(make_rt, cloud):
    rt = make_rt(cloud)
    calls = _hooked(rt)
    _feed(cloud, _erase("u_3c4d", _t(-3)))
    rt.sync.pull_revocations()
    cloud.revocations.append({"seq": 2, **_readmit("u_3c4d", _t(-2))})
    rt.sync.pull_revocations()
    assert rt.overlay.reason("u_3c4d") is None and "u_3c4d" not in rt._erased
    rt.set_totp_secret("u_3c4d", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")  # re-enrolled
    rt.tick()
    assert calls == ["u_3c4d"] and rt.credentials.totp_secret("u_3c4d") is not None  # not purged again
    cloud.revocations.append({"seq": 3, **_erase("u_3c4d", _t(-1))})
    rt.sync.pull_revocations()
    assert calls == ["u_3c4d", "u_3c4d"] and rt.credentials.totp_secret("u_3c4d") is None


def test_erase_then_readmit_in_one_pull_still_purges(make_rt, cloud):
    """An edge that was offline gets both events at once: the erasure happened, so the old local data goes."""
    rt = make_rt(cloud)
    calls = _hooked(rt)
    _feed(cloud, _erase("u_3c4d", _t(-3)), _readmit("u_3c4d", _t(-2)))
    rt.sync.pull_revocations()
    assert calls == ["u_3c4d"] and rt.credentials.totp_secret("u_3c4d") is None
    assert rt.overlay.reason("u_3c4d") is None and "u_3c4d" not in rt._erased


def test_readmit_older_than_the_erase_keeps_the_erasure(make_rt, cloud):
    rt = make_rt(cloud)
    _feed(cloud, _erase("u_3c4d", _t(-1)), _readmit("u_3c4d", _t(-5)))
    rt.sync.pull_revocations()
    assert rt.overlay.reason("u_3c4d") == "ERASED"


def test_readmit_keeps_admin_revocations(make_rt, cloud):
    rt = make_rt(cloud)
    _feed(cloud, _user("u_3c4d", _t(-3)), _readmit("u_3c4d", _t(-1)))
    rt.sync.pull_revocations()
    assert rt.overlay.reason("u_3c4d") == "ADMIN" and "u_3c4d" in rt.revoked_user_ids()


def test_readmit_with_another_reason_behaves_like_readmit(make_rt, cloud):
    """The cloud also emits READMIT with CONSENT_RECORDED / ADMIN_ACCESS: narrow (ERASED-only) semantics."""
    rt = make_rt(cloud)
    _feed(cloud, _user("u_1a2b", _t(-4)), _erase("u_3c4d", _t(-3)),
          _readmit("u_3c4d", _t(-2), "CONSENT_RECORDED"), _readmit("u_1a2b", _t(-1), "ADMIN_ACCESS"))
    rt.sync.pull_revocations()
    assert rt.overlay.reason("u_3c4d") is None and rt.overlay.reason("u_1a2b") == "ADMIN"


def test_readmit_without_a_parsable_time_drops_nothing(make_rt, cloud):
    rt = make_rt(cloud)
    _feed(cloud, _erase("u_3c4d", _t(-3)), _user("u_1a2b", _t(-3)),
          {"type": "READMIT", "target_id": "u_3c4d", "revoked_at": "garbage", "reason": "READMIT"},
          {"type": "READMIT", "target_id": "u_1a2b", "reason": "RESTORE"})
    rt.sync.pull_revocations()
    assert rt.overlay.reason("u_3c4d") == "ERASED" and rt.overlay.reason("u_1a2b") == "ADMIN"


# ---------------------------------------------------------------- R-C: USER revocation + RESTORE
def test_user_revocation_from_the_feed_denies_offline_and_survives_a_restart(make_rt, cloud, tmp_path):
    rt = make_rt(cloud)
    assert rt.decide(attempt("att_rc_before"))["decision"] == "ALLOW"
    _feed(cloud, _user("u_3c4d", _t(-1)))
    rt.sync.pull_revocations()
    rt.set_forced_mode("OFFLINE")
    body = rt.decide(attempt("att_rc_off"))
    assert body["decision"] == "DENY" and "SCHEDULE_REVOKED" in body["reason_codes"] and body["mode"] == "OFFLINE"
    assert "u_3c4d" not in rt.entitled_user_ids()  # the gallery filter drops them too (NOT_ENROLLED offline)
    rt.stop()
    rt2 = make_rt()  # same data dir, no cloud: the encrypted overlay is reloaded
    body = rt2.decide(attempt("att_rc_restart"))
    assert body["decision"] == "DENY" and "SCHEDULE_REVOKED" in body["reason_codes"]


def test_restore_drops_all_user_entries_up_to_the_event_time(make_rt, cloud):
    rt = make_rt(cloud)
    _feed(cloud, _user("u_3c4d", _t(-3)), _readmit("u_3c4d", _t(-2), "RESTORE"))
    rt.sync.pull_revocations()
    assert rt.overlay.reason("u_3c4d") is None and "u_3c4d" not in rt.revoked_user_ids()
    rt.set_forced_mode("OFFLINE")
    assert rt.decide(attempt("att_rc_restored"))["decision"] == "ALLOW"


def test_restore_keeps_a_revocation_issued_after_it(make_rt, cloud):
    rt = make_rt(cloud)
    _feed(cloud, _readmit("u_3c4d", _t(-2), "RESTORE"), _user("u_3c4d", _t(-1), "LOST_CARD"))
    rt.sync.pull_revocations()
    assert rt.overlay.reason("u_3c4d") == "LOST_CARD"


def test_restore_also_lifts_an_erasure(make_rt, cloud):
    rt = make_rt(cloud)
    _feed(cloud, _erase("u_3c4d", _t(-3)), _readmit("u_3c4d", _t(-2), "RESTORE"))
    rt.sync.pull_revocations()
    assert rt.overlay.reason("u_3c4d") is None and "u_3c4d" not in rt._erased


# ---------------------------------------------------------------- reinstate_user (edge-ml enrolment API)
def test_reinstate_user_drops_only_erasure_state(make_rt, cloud):
    rt = make_rt(cloud)
    _feed(cloud, _erase("u_3c4d", _t(-2)), _user("u_1a2b", _t(-2)))
    rt.sync.pull_revocations()
    assert rt.reinstate_user("u_3c4d") is True
    assert rt.overlay.reason("u_3c4d") is None and "u_3c4d" not in rt._erased
    assert "u_3c4d" in rt.entitled_user_ids()  # the gallery admits the re-enrolled user again
    assert rt.reinstate_user("u_3c4d") is False  # nothing left
    assert rt.reinstate_user("u_1a2b") is False and rt.overlay.reason("u_1a2b") == "ADMIN"


def test_reinstate_user_completes_a_not_yet_run_purge_first(make_rt, cloud):
    """Overlay applied without the runtime (or a crash before the purge): EO-05 -- the pre-erasure data is purged
    BEFORE the re-enrolment is accepted (exactly once), never silently kept as the new identity anchor."""
    rt = make_rt(cloud)
    calls = _hooked(rt)
    rt.overlay.apply({"items": [_erase("u_3c4d", _t(-2))], "revocation_seq": 1})
    assert rt.reinstate_user("u_3c4d") is True
    rt.tick()
    assert calls == ["u_3c4d"] and rt.credentials.totp_secret("u_3c4d") is None


def test_reinstate_user_refuses_while_the_old_purge_keeps_failing(make_rt, cloud):
    rt = make_rt(cloud)
    rt.add_erase_hook(lambda uid: (_ for _ in ()).throw(OSError("disk full")))
    rt.overlay.apply({"items": [_erase("u_3c4d", _t(-2))], "revocation_seq": 1})
    rt.apply_erasures()
    with pytest.raises(RuntimeError):
        rt.reinstate_user("u_3c4d")
    assert "u_3c4d" in rt.excluded_user_ids()


def test_EO05_failed_erase_hook_keeps_the_purge_pending_and_retries(make_rt, cloud):
    rt = make_rt(cloud)
    attempts = {"n": 0}

    def flaky(uid):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise OSError("disk full")

    rt.add_erase_hook(flaky)
    rt.overlay.apply({"items": [_erase("u_3c4d", _t(-2))], "revocation_seq": 1})
    assert rt.apply_erasures() == []  # not complete
    assert "u_3c4d" in rt.overlay.pending_purge() and "u_3c4d" not in rt._erased
    types = [e["type"] for e in rt.events()]
    assert "ALERT_LOCAL_ERASURE_FAILED" in types and "USER_ERASED_LOCAL" not in types
    assert not rt.erasures_complete()
    rt.tick()  # retried
    assert attempts["n"] == 2 and rt.overlay.pending_purge() == [] and rt.erasures_complete()
    assert "USER_ERASED_LOCAL" in [e["type"] for e in rt.events()]


def test_a_crash_before_the_purge_purges_after_restart(make_rt, cloud):
    rt = make_rt(cloud)
    rt.overlay.apply({"items": [_erase("u_3c4d", _t(-2))], "revocation_seq": 1})  # no runtime purge yet
    rt.stop()
    rt2 = make_rt()
    calls = _hooked(rt2)
    rt2.tick()
    assert calls == ["u_3c4d"] and rt2.credentials.totp_secret("u_3c4d") is None
    rt2.tick()
    assert calls == ["u_3c4d"]


# ---------------------------------------------------------------- bundle-carried erasures (marker lifecycle)
def _bundle_with_erasure(rt, version: int, erased: bool) -> dict:
    b = copy.deepcopy(rt.bundles.lvb)
    b.pop("signature")
    b["bundle_version"] = version
    b["revocations"] = [r for r in b.get("revocations") or [] if r.get("user_id") != "u_3c4d"]
    if erased:
        b["revocations"].append({"user_id": "u_3c4d", "revoked_at": _t(-1), "reason": "ERASED"})
    return sign_bundle(b, TEST_BUNDLE_KEY)


def test_marker_is_cleared_when_the_bundle_drops_the_erasure(make_rt, cloud):
    rt = make_rt(cloud)
    calls = _hooked(rt)
    v = rt.bundles.version
    cloud.bundle = _bundle_with_erasure(rt, v + 1, True)
    rt.refresh_bundle_now()
    rt.tick()
    assert calls == ["u_3c4d"] and "u_3c4d" in rt._erased
    cloud.bundle = _bundle_with_erasure(rt, v + 2, False)  # re-admitted
    rt.refresh_bundle_now()
    rt.tick()
    assert "u_3c4d" not in rt._erased and calls == ["u_3c4d"]
    cloud.bundle = _bundle_with_erasure(rt, v + 3, True)  # erased again in the same process
    rt.refresh_bundle_now()
    rt.tick()
    assert calls == ["u_3c4d", "u_3c4d"]


def test_bring_online_applies_feed_before_the_queue(make_rt, cloud):
    rt = make_rt(cloud)
    calls = _hooked(rt)
    _feed(cloud, _erase("u_3c4d", _t(-1)))
    bring_online(rt)
    assert calls == ["u_3c4d"]
