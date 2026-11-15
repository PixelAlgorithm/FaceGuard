"""Control-panel access administration (ROLE / ACCESS DESIGN): GET /v1/admin/users, PUT
/v1/admin/users/{user_id}/access (incl. "Add user"), POST /v1/admin/codes/rotate, audit ledger; plus the
enrolment role / card-hash / TOTP-flag contract, erase -> re-enrol readmission, schedule replace validation,
revocation ordering, fixture-code hygiene on read / stored uploads, and the enrolment liveness gate."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from cloud.app.clock import iso_z
from cloud.app.services import schedule_service as sched_mod
from cloud.app.services.schedule_service import NS_KIOSK_BUNDLE, NS_SCHED, ScheduleConflict, verify_bundle
from cloud.tools.fakeimg import make_fake_jpeg

from .conftest import ADMIN, BUNDLE_KEY, PEPPER, T0, Signed, etag

ADMIN_H = {"X-Admin-Token": ADMIN}
# Sat 14 Nov 2026 22:30 IST: student Main Gate window ends 22:00 (+15 min grace), faculty ends 23:00
T_LATE = datetime(2026, 11, 14, 17, 0, tzinfo=UTC)
# Sat 14 Nov 2026 23:40 IST: outside faculty hours (and their grace)
T_NIGHT = datetime(2026, 11, 14, 18, 10, tzinfo=UTC)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


@pytest.fixture
def main(client) -> Signed:
    return Signed(client, kiosk="KIOSK_MAIN_01")


def access(c: Signed, uid: str, body: dict, *, admin: bool = True):
    return c.request("PUT", f"/v1/admin/users/{uid}/access", json_body=body, headers=ADMIN_H if admin else None)


def edge_style_enrol(c: Signed, uid: str = "u_tm02", role: str = "faculty", card: str | None = "HID-CARD-9002",
                     salt: str = "e", **kw):
    """What edge/enroll.py sends: its meta without card_id, plus card_id_hash (and its provision_totp)."""
    meta = {"user_id": uid, "display_name": "Team Member Two", "email": None, "role": role, "consent": True,
            "consent_version": "2026-11-14.v1", "provision_totp": True,
            "card_id_hash": hashlib.sha256(card.encode()).hexdigest() if card else None}
    meta.update(kw)
    imgs = [b64(make_fake_jpeg(uid, salt=f"{salt}{i}")) for i in range(3)]  # distinct bodies: replay cache
    return c.post("/v1/enroll", {**meta, "images_b64": imgs})


def check(c: Signed, uid: str, t0: datetime) -> str:
    r = c.post("/v1/schedule/check", {"user_id": uid, "t0": iso_z(t0)})
    assert r.status_code == 200, r.text
    return r.json()["result"]


def bundle(c: Signed, kiosk: str = "KIOSK_MAIN_01") -> dict:
    r = Signed(c.c, kiosk=kiosk).get(f"/v1/schedule/{kiosk}")
    assert r.status_code == 200, r.text
    b = r.json()
    assert verify_bundle(b, BUNDLE_KEY)
    return b


# ------------------------------------------------------------------ "registered as faculty, shows student"
def test_enrolment_role_is_echoed_never_self_applied_and_put_access_applies_it(main, services):
    v0 = services.schedule.current()["version"]
    r = edge_style_enrol(main)
    assert r.status_code == 201, r.text
    out = r.json()
    # role no longer silently dropped: echoed, not applied (the signed schedule decides), and no version churn
    assert out["requested_role"] == "faculty" and out["schedule_role"] is None and out["role_applied"] is False
    assert out["schedule_entitlement"] is False and out["bundle_version"] == v0
    row = services.kv.get("users", "u_tm02")
    assert row["card_id_hash"] == hashlib.sha256(b"HID-CARD-9002").hexdigest() and row["totp_enrolled"] is True
    assert out["totp_provisioning_uri"] is None and row["totp_seed_enc"] is None  # no unused cloud secret

    # the control panel / register page applies the role (admin token)
    r = access(main, "u_tm02", {"role": "faculty", "display": "Team Member Two", "consent": True, "actor": "operator"})
    assert r.status_code == 200, r.text
    put = r.json()
    assert put["created"] is True and put["role"] == "faculty" and put["bundle_version"] == v0 + 1
    assert put["user"]["fallback"] == {"totp_enrolled": True, "card": True}  # carried from the enrolment row

    b = bundle(main)
    u = b["users"]["u_tm02"]
    assert b["bundle_version"] == v0 + 1 and u["role"] == "faculty" and u["display"] == "Team Member Two"
    assert u["fallback"]["card_id_hash"] == hashlib.sha256(b"HID-CARD-9002").hexdigest()
    assert check(main, "u_tm02", T_LATE) == "IN_WINDOW"  # faculty hours, a student would be OUTSIDE_WINDOW

    # the edge's own BundleStore installs the re-signed bundle
    import tempfile
    from pathlib import Path

    from edge.offline.bundle import BundleStore

    with tempfile.TemporaryDirectory() as d:
        ok, reason = BundleStore(Path(d) / "b.json", BUNDLE_KEY.encode(), "KIOSK_MAIN_01").install(b, T0)
        assert ok, reason

    # re-enrolment of a scheduled user: role matches -> role_applied, unchanged fallback -> no new version
    r2 = edge_style_enrol(main, salt="again")
    assert r2.status_code == 201 and r2.json()["role_applied"] is True and r2.json()["schedule_role"] == "faculty"
    assert r2.json()["bundle_version"] == v0 + 1 and r2.json()["schedule_entitlement"] is True


def test_enrolment_never_changes_role_of_existing_user(main, services):
    r = edge_style_enrol(main, uid="u_3c4d", role="faculty", card=None)
    assert r.status_code == 201 and r.json()["schedule_role"] == "student" and r.json()["role_applied"] is False
    assert services.schedule.current()["doc"]["users"]["u_3c4d"]["role"] == "student"


def test_card_id_hash_from_edge_reaches_bundle(main, services):
    h = hashlib.sha256(b"new-card").hexdigest()
    r = edge_style_enrol(main, uid="u_3c4d", role="student", card="new-card")
    assert r.status_code == 201 and r.json()["bundle_version"] == 43  # one publish for the new card hash
    assert bundle(main, "KIOSK_LIB_01")["users"]["u_3c4d"]["fallback"]["card_id_hash"] == h
    # a raw card_id (older clients) is still hashed with the pepper
    from cloud.app.services.enroll_service import card_hash

    r = edge_style_enrol(main, uid="u_3c4d", role="student", card=None, card_id="HID-CARD-1002", salt="raw")
    assert r.status_code == 201
    assert services.kv.get("users", "u_3c4d")["card_id_hash"] == card_hash(PEPPER, "HID-CARD-1002")


def test_explicit_totp_enrolled_false_wins(main, services):
    edge_style_enrol(main, uid="u_3c4d", role="student", card=None, totp_enrolled=False)
    assert services.schedule.current()["doc"]["users"]["u_3c4d"]["fallback"]["totp_enrolled"] is False


def test_display_name_up_to_80_like_the_edge(main):
    assert edge_style_enrol(main, display_name="D" * 80).status_code == 201
    assert edge_style_enrol(main, display_name="D" * 81).status_code == 422


# ------------------------------------------------------------------ PUT access: role, hours, validation
def test_extended_hours_and_role_change_apply_and_are_audited(main, services):
    assert check(main, "u_5e6f", T_NIGHT) == "OUTSIDE_WINDOW"  # faculty Main Gate until 23:00
    r = access(main, "u_5e6f", {"role": "faculty", "actor": "warden",
                                "extra_windows": {"MAIN_GATE": [{"days": ["SAT"], "start": "23:00", "end": "23:59"}]}})
    assert r.status_code == 200 and r.json()["warnings"] == [], r.text
    assert check(main, "u_5e6f", T_NIGHT) == "IN_WINDOW"
    assert bundle(main)["users"]["u_5e6f"]["extra_windows"] == {
        "MAIN_GATE": [{"days": ["SAT"], "start": "23:00", "end": "23:59"}]}

    assert check(main, "u_3c4d", T_LATE) == "OUTSIDE_WINDOW"
    r = access(main, "u_3c4d", {"role": "faculty", "actor": "warden"})
    assert r.status_code == 200 and r.json()["previous_role"] == "student" and r.json()["role"] == "faculty"
    assert check(main, "u_3c4d", T_LATE) == "IN_WINDOW"

    a = main.get("/v1/admin/audit?user_id=u_3c4d", headers=ADMIN_H).json()["items"]
    assert a[-1]["action"] == "ACCESS_UPDATE" and a[-1]["role_change"] == ["student", "faculty"]
    # V2 §E: the legacy credential is the actor (a client-supplied actor is only honoured from an edge_proxy key)
    assert a[-1]["kiosk_id"] == "KIOSK_MAIN_01" and a[-1]["actor"] == "legacy:admin_token" and a[-1]["ts_utc"]
    assert a[-1]["actor_assurance"] == "legacy"
    hist = services.kv.get("schedule_hist", f"{r.json()['bundle_version']:08d}")
    assert hist["actor"] == "legacy:admin_token" and hist["reason"] == "admin:access:u_3c4d"


def test_identical_put_is_unchanged_without_version_bump(main, services):
    body = {"role": "student", "zones_add": ["HOSTEL"]}
    v1 = access(main, "u_1a2b", body).json()
    assert v1["unchanged"] is True and v1["bundle_version"] == 42  # already exactly this
    v2 = access(main, "u_1a2b", {"role": "staff"}).json()
    assert v2["unchanged"] is False and v2["bundle_version"] == 43
    assert access(main, "u_1a2b", {"role": "staff", "actor": "again"}).json()["bundle_version"] == 43


def test_valid_from_until_set_and_cleared(main, services):
    r = access(main, "u_3c4d", {"role": "student", "valid_from": "2026-11-01T00:00:00+05:30",
                                "valid_until": "2026-11-30T00:00:00+05:30"})
    assert r.status_code == 200
    u = services.schedule.current()["doc"]["users"]["u_3c4d"]
    assert u["valid_from"] == "2026-10-31T18:30:00Z" and u["valid_until"] == "2026-11-29T18:30:00Z"
    access(main, "u_3c4d", {"role": "student", "valid_until": None})  # explicit null clears
    u = services.schedule.current()["doc"]["users"]["u_3c4d"]
    assert u["valid_until"] is None and u["valid_from"] == "2026-10-31T18:30:00Z"


@pytest.mark.parametrize("uid,body,fragment", [
    ("u_3c4d", {"role": "dean"}, "not one of"),
    ("u_3c4d", {"role": "student", "zones_add": ["MOON_BASE"]}, "unknown zones"),
    ("u_3c4d", {"role": "student", "extra_windows": {"MOON_BASE": [{"days": ["MON"], "start": "08:00",
                                                                    "end": "09:00"}]}}, "unknown zone"),
    ("u_3c4d", {"role": "student", "extra_windows": {"MAIN_GATE": [{"days": ["MON"], "start": "10:00",
                                                                    "end": "09:00"}]}}, "after start"),
    ("u_3c4d", {"role": "student", "extra_windows": {"MAIN_GATE": [{"days": ["MON"], "start": "8:00",
                                                                    "end": "09:00"}]}}, "start"),
    ("u_3c4d", {"role": "student", "extra_windows": {"MAIN_GATE": [{"days": ["XYZ"], "start": "08:00",
                                                                    "end": "09:00"}]}}, "days"),
    ("u_3c4d", {"role": "student", "valid_from": "2026-11-20T00:00:00Z", "valid_until": "2026-11-19T00:00:00Z"},
     "after valid_from"),
    ("u_3c4d", {"role": "student", "valid_from": "tomorrow"}, "ISO-8601"),
    ("u_new1", {"role": "student", "consent": True}, "display is required"),
    ("u_new1", {"role": "student", "display": "New One"}, "consent: true is required"),
    ("u_3c4d", {"role": "student", "extra_windows": {"MAIN_GATE": [{"days": ["MON"], "start": "08:00",
                                                                    "end": "24:00"}]}}, "end"),  # read-only value
    ("u_3c4d", {"role": "student", "extra_windows": {"MAIN_GATE": [{"days": ["MON", "MON"], "start": "08:00",
                                                                    "end": "09:00"}]}}, "unique"),
    ("u_3c4d", {"role": "student", "display": "   "}, "display"),
    ("u_3c4d", {"role": "student", "restore": True}, "restore requires consent"),
    # L2 (R-H, edge access_models.AccessUpdate): consent / restore are StrictBool, never coerced
    ("u_new1", {"role": "student", "display": "New One", "consent": "true"}, "consent"),
    ("u_new1", {"role": "student", "display": "New One", "consent": 1}, "consent"),
    ("u_a3b4", {"role": "faculty", "consent": True, "restore": "yes"}, "restore"),
    ("u_a3b4", {"role": "faculty", "consent": True, "restore": 1}, "restore"),
    ("u_3c4d", {"role": "student", "actor": "bad actor!"}, "actor"),
    ("u_3c4d", {"role": "student", "zones_add": ["MAIN_GATE"] * 17}, "zones_add"),
    ("U_3C4D", {"role": "student"}, "user_id"),
    ("u_3c4d5", {"role": "student"}, "user_id"),
    ("u_3c4d", {"role": "student", "revoked": False}, "revoked"),  # unknown field (e.g. un-revoke) refused
    ("u" * 65, {"role": "student"}, "user_id"),
])
def test_put_access_validation(main, services, uid, body, fragment):
    v0 = services.schedule.current()["version"]
    r = access(main, uid, body)
    assert r.status_code == 422 and fragment in r.json()["error"]["message"], r.text
    assert services.schedule.current()["version"] == v0


@pytest.mark.parametrize("body,fragment", [
    ({"staff_id": "s_guard01", "replace_existing": "false"}, "replace_existing"),  # StrictBool (edge parity)
    ({"staff_id": "s_guard01", "replace_existing": 0}, "replace_existing"),
    ({"staff_id": "s_guard01", "count": 11}, "count"),
    ({"staff_id": "s_guard01", "count": 0}, "count"),
    ({"staff_id": "S_GUARD01"}, "staff_id"),
    ({"staff_id": " s_guard01 "}, "staff_id"),  # never trimmed (edge CodesRotateRequest parity)
    ({"staff_id": "s_guard01", "actor": " operator "}, "actor"),
])
def test_rotate_codes_validation(main, services, body, fragment):
    v0 = services.schedule.current()["version"]
    r = main.post("/v1/admin/codes/rotate", body, headers=ADMIN_H)
    assert r.status_code == 422 and fragment in r.json()["error"]["message"], r.text
    assert services.schedule.current()["version"] == v0


@pytest.mark.parametrize("body,fragment", [
    ({"type": "USER", "target_id": "u_typo", "force": "true"}, "force"),  # StrictBool: a string never forces
    ({"type": "USER", "target_id": "u_3c4d", "reason": "ERASED"}, "DELETE /v1/enroll"),
    ({"type": "USER", "target_id": "u_3c4d", "reason": "admin"}, "reason"),
    ({"type": "USER", "target_id": "u_3c4d", "actor": "bad actor!"}, "actor"),
    ({"type": "USER", "target_id": "u_3c4d", "reason": " ADMIN "}, "reason"),  # never trimmed (edge parity)
    ({"type": "USER", "target_id": " u_3c4d "}, "target_id"),
])
def test_revoke_validation(main, services, body, fragment):
    v0 = services.schedule.current()["version"]
    r = main.post("/v1/admin/revocations", body, headers=ADMIN_H)
    assert r.status_code == 422 and fragment in r.json()["error"]["message"], r.text
    assert services.schedule.current()["version"] == v0


def test_audit_filter_takes_r_h_user_ids_only(main):
    assert main.get("/v1/admin/audit?user_id=u_3c4d", headers=ADMIN_H).status_code == 200
    r = main.get("/v1/admin/audit?user_id=bad%20id", headers=ADMIN_H)
    assert r.status_code == 422 and r.json()["error"]["code"] == "VALIDATION_ERROR"


def test_display_name_is_trimmed_before_the_length_check(main, services):
    """R-H: display / display_name are 1-80 characters after trimming (edge EnrollMeta strips too)."""
    assert edge_style_enrol(main, display_name="   ").status_code == 422
    r = edge_style_enrol(main, display_name="  " + "D" * 80 + "  ")
    assert r.status_code == 201, r.text
    assert services.kv.get("users", "u_tm02")["display_name"] == "D" * 80


def test_put_access_needs_admin_token(main):
    r = access(main, "u_3c4d", {"role": "faculty"}, admin=False)
    assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN"
    assert main.get("/v1/admin/users").status_code == 403
    assert main.post("/v1/admin/codes/rotate", {"staff_id": "s_guard01"}).status_code == 403


def test_put_access_never_unrevokes(main, services):
    r = access(main, "u_a3b4", {"role": "faculty"})  # u_a3b4 is ADMIN-revoked in the seed
    assert r.status_code == 200 and any("revoked" in w for w in r.json()["warnings"])
    doc = services.schedule.current()["doc"]
    assert doc["users"]["u_a3b4"]["revoked"] is True and any(
        x["user_id"] == "u_a3b4" and x["reason"] == "ADMIN" for x in doc["revocations"])
    assert check(main, "u_a3b4", T0) == "REVOKED"


def test_extra_windows_for_an_unreachable_zone_warn(main):
    r = access(main, "u_3c4d", {"role": "student", "extra_windows": {
        "SERVER_ROOM": [{"days": ["MON"], "start": "09:00", "end": "10:00"}]}})
    assert r.status_code == 200 and "no effect" in r.json()["warnings"][0]


def test_list_users_merges_schedule_and_enrolment(main, services):
    edge_style_enrol(main)  # u_tm02 enrolled in the cloud, not yet in the schedule
    r = main.get("/v1/admin/users", headers=ADMIN_H)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["bundle_version"] == 42 and set(body["roles"]) >= {"student", "faculty", "staff"}
    assert body["roles"]["faculty"]["windows"]["MAIN_GATE"][0]["end"] == "23:00"
    users = {u["user_id"]: u for u in body["users"]}
    assert users["u_tm02"]["in_schedule"] is False and users["u_tm02"]["enrolled"] is True
    assert users["u_tm02"]["faces"] == 3 and users["u_tm02"]["role"] is None
    assert users["u_5e6f"]["role"] == "faculty" and users["u_5e6f"]["enrolled"] is False
    assert users["u_a3b4"]["status"] == "REVOKED" and users["u_a3b4"]["revoked_reason"] == "ADMIN"
    assert users["u_3c4d"]["status"] == "ACTIVE" and users["u_tm02"]["status"] == "NOT_IN_SCHEDULE"
    assert "revoked" not in users["u_3c4d"] and "erased" not in users["u_3c4d"]  # v1.4: status replaces both
    assert users["u_1a2b"]["zones_add"] == ["HOSTEL"]
    assert users["u_1a2b"]["fallback"]["card"] is True
    assert "card_id_hash" not in json.dumps(body) and "email" not in json.dumps(body)


# ------------------------------------------------------------------ staff override codes
def test_rotate_codes_returns_plaintext_once_and_stores_hashes(main, services):
    from edge.policy.fallback import override_hash

    r = main.post("/v1/admin/codes/rotate", {"staff_id": "s_guard01", "count": 3, "actor": "operator"},
                  headers=ADMIN_H)
    assert r.status_code == 201, r.text
    assert "no-store" in r.headers["cache-control"]
    out = r.json()
    # EO-11: new codes are thresholds code_length (10) digits; legacy 8-digit codes stay accepted by the edge
    assert out["bundle_version"] == 43 and len(out["codes"]) == 3 and out["code_length"] == 10
    assert all(len(c["code"]) == 10 and c["code"].isdigit() for c in out["codes"])
    # nothing in the store holds a plaintext code (master, history, audit)
    dump = json.dumps([services.kv.list(ns) for ns in ("schedule", "schedule_hist", "admin_audit")])
    assert not any(c["code"] in dump for c in out["codes"])
    b = bundle(main)
    entries = {c["code_id"]: c for c in b["override_codes"]["codes"]}
    it = int(b["override_codes"]["iterations"])
    for c in out["codes"]:
        e = entries[c["code_id"]]
        assert e["staff_id"] == "s_guard01" and override_hash(c["code"], e["salt"], it) == e["hash"]
    assert all(cid not in entries for cid in ("OVR-001", "OVR-002", "OVR-003"))
    a = main.get("/v1/admin/audit", headers=ADMIN_H).json()["items"][-1]
    assert a["action"] == "CODES_ROTATE" and a["minted_code_ids"] == [c["code_id"] for c in out["codes"]]

    # rotation drops this staff member's previous codes only
    other = main.post("/v1/admin/codes/rotate", {"staff_id": "s_guard02", "count": 1}, headers=ADMIN_H).json()
    again = main.post("/v1/admin/codes/rotate", {"staff_id": "s_guard01", "count": 2}, headers=ADMIN_H).json()
    assert set(again["dropped_code_ids"]) == {c["code_id"] for c in out["codes"]}
    ids = {c["code_id"] for c in bundle(main)["override_codes"]["codes"]}
    assert ids == {c["code_id"] for c in again["codes"]} | {other["codes"][0]["code_id"]}


def test_rotate_codes_strips_documented_fixture_codes(main, services):
    # a legacy master that still carries OVR-001..003 (e.g. seeded before the hygiene rule)
    example = json.loads((sched_mod.Path(services.settings.seed_schedule_path)).read_text(encoding="utf-8"))
    rec = services.kv.get(NS_SCHED, "current")
    rec["doc"]["override_codes"] = copy.deepcopy(example["override_codes"])
    rev = rec.pop("_rev")
    assert services.kv.cas(NS_SCHED, "current", rec, rev)
    services.schedule._cache = None
    out = main.post("/v1/admin/codes/rotate", {"staff_id": "s_guard01", "count": 1}, headers=ADMIN_H).json()
    ids = [c["code_id"] for c in services.schedule.current()["doc"]["override_codes"]["codes"]]
    assert ids == [out["codes"][0]["code_id"]]


def test_rotate_codes_fails_secure_without_documented_list(main, services, monkeypatch):
    monkeypatch.setattr(sched_mod, "load_documented_override_values", lambda: None)
    r = main.post("/v1/admin/codes/rotate", {"staff_id": "s_guard01"}, headers=ADMIN_H)
    assert r.status_code == 503 and r.json()["error"]["code"] == "CLOUD_UNAVAILABLE"
    assert services.schedule.current()["version"] == 42


def test_dirty_master_gets_a_hygiene_version_bump_on_read(main, services):
    """A kiosk holding a dirty vN must not get 304 forever: cleaning on read publishes vN+1."""
    example = json.loads((sched_mod.Path(services.settings.seed_schedule_path)).read_text(encoding="utf-8"))
    rec = services.kv.get(NS_SCHED, "current")
    rec["doc"]["override_codes"] = copy.deepcopy(example["override_codes"])
    rev = rec.pop("_rev")
    assert services.kv.cas(NS_SCHED, "current", rec, rev)
    services.schedule._cache = None
    r = main.get("/v1/schedule/KIOSK_MAIN_01", headers={"If-None-Match": etag(42)})
    assert r.status_code == 200 and r.json()["bundle_version"] == 43 and r.json()["override_codes"]["codes"] == []
    assert services.kv.get(NS_SCHED, "current")["doc"]["override_codes"]["codes"] == []  # persisted


def test_stored_upload_with_documented_codes_is_never_served(main, services):
    example = json.loads((sched_mod.Path(services.settings.seed_schedule_path)).read_text(encoding="utf-8"))
    dirty = {**bundle(main), "override_codes": copy.deepcopy(example["override_codes"])}
    services.kv.put(NS_KIOSK_BUNDLE, "KIOSK_MAIN_01", {
        "version": 42, "bundle": dirty, "signature": "x", "expires_at": iso_z(T0 + timedelta(hours=12)),
        "verbatim": True})
    services.schedule._cache = None
    b = bundle(main)
    assert b["override_codes"]["codes"] == []


# ------------------------------------------------------------------ erase -> re-enrol (DPDP vs access)
def test_erase_keeps_entitlement_and_reenrolment_readmits(main, services):
    assert edge_style_enrol(main, uid="u_3c4d", role="student", card=None).status_code == 201
    assert check(main, "u_3c4d", T0) == "IN_WINDOW"
    e = main.delete("/v1/enroll/u_3c4d")
    assert e.status_code == 200, e.text
    assert check(main, "u_3c4d", T0) == "REVOKED"  # suspended until consent is re-recorded
    b = bundle(main, "KIOSK_LIB_01")
    assert "u_3c4d" in b["users"] and any(r["user_id"] == "u_3c4d" and r["reason"] == "ERASED"
                                          for r in b["revocations"])  # edge purges templates + TOTP on this

    r = edge_style_enrol(main, uid="u_3c4d", role="student", card=None, salt="back")
    assert r.status_code == 201 and r.json()["readmitted"] is True and r.json()["schedule_entitlement"] is True
    assert check(main, "u_3c4d", T0) == "IN_WINDOW"
    b = bundle(main, "KIOSK_LIB_01")
    assert not any(x["user_id"] == "u_3c4d" for x in b["revocations"]) and b["users"]["u_3c4d"]["role"] == "student"
    _, feed = services.schedule.revocations_since(0)
    assert [(i["type"], i["target_id"], i["reason"]) for i in feed if i["target_id"] == "u_3c4d"] == [
        ("ERASE", "u_3c4d", "ERASED"), ("READMIT", "u_3c4d", "READMIT")]  # never a deny-only USER revocation
    assert main.get("/v1/revocations?since=0").status_code == 200  # feed schema accepts the new types


def test_put_access_readmits_a_legacy_erased_user(main, services):
    """Live state: u_prj1 popped by the old erase (no users entry) + an ERASED revocation. "Add user" again."""
    rec = services.kv.get(NS_SCHED, "current")
    rec["doc"].setdefault("revocations", []).append({"user_id": "u_prj1", "revoked_at": "2026-11-14T12:00:00Z",
                                                     "reason": "ERASED"})
    rev = rec.pop("_rev")
    assert services.kv.cas(NS_SCHED, "current", rec, rev)
    services.schedule._cache = None
    assert access(main, "u_prj1", {"role": "staff", "display": "Prajwal M."}).status_code == 422  # no consent
    listed = {u["user_id"]: u for u in main.get("/v1/admin/users", headers=ADMIN_H).json()["users"]}
    assert listed["u_prj1"]["status"] == "ERASED" and listed["u_prj1"]["in_schedule"] is False  # "Re-admit" offered
    r = access(main, "u_prj1", {"role": "staff", "display": "Prajwal M.", "consent": True})
    assert r.status_code == 200 and r.json()["created"] and r.json()["readmitted"], r.text
    b = bundle(main)
    assert b["users"]["u_prj1"]["role"] == "staff" and not any(x["user_id"] == "u_prj1" for x in b["revocations"])
    assert check(main, "u_prj1", T0) == "IN_WINDOW"


# ------------------------------------------------------------------ schedule replace / revocations
def test_replace_carries_revocations_and_validates(main, services):
    old = main.get("/v1/admin/schedule", headers=ADMIN_H).json()["doc"]
    assert main.post("/v1/admin/revocations", {"type": "USER", "target_id": "u_3c4d", "reason": "LOST_CARD"},
                     headers=ADMIN_H).status_code == 201
    r = main.request("PUT", "/v1/admin/schedule", json_body=old, headers=ADMIN_H)  # doc fetched pre-revocation
    assert r.status_code == 200, r.text
    assert services.schedule.current()["doc"]["users"]["u_3c4d"]["revoked"] is True
    assert check(main, "u_3c4d", T0) == "REVOKED"

    v = services.schedule.current()["version"]
    bad_docs = [
        ({**old, "kiosks": {}, "zones": {}}, "kiosks"),
        ({**old, "kiosks": {k: v for k, v in old["kiosks"].items() if k != "KIOSK_MAIN_01"}}, "calling kiosk"),
        ({**old, "kiosks": {**old["kiosks"], "KIOSK_X": {"zone": "ATTIC"}}}, "zone must be one of"),
        ({**old, "users": {**old["users"], "u_zz99": {**old["users"]["u_3c4d"], "role": "dean"}}}, "not in roles"),
    ]
    for doc, fragment in bad_docs:
        r = main.request("PUT", "/v1/admin/schedule", json_body=doc, headers=ADMIN_H)
        assert r.status_code == 422 and fragment in r.json()["error"]["message"], r.text
    assert services.schedule.current()["version"] == v
    assert main.get("/v1/schedule/KIOSK_MAIN_01").status_code == 200  # nobody locked out


def test_revoke_unknown_user_is_404_unless_forced(main, services):
    r = main.post("/v1/admin/revocations", {"type": "USER", "target_id": "u_typo"}, headers=ADMIN_H)
    assert r.status_code == 404 and r.json()["error"]["code"] == "NOT_FOUND"
    assert services.schedule.current()["version"] == 42
    r = main.post("/v1/admin/revocations", {"type": "USER", "target_id": "u_typo", "force": True}, headers=ADMIN_H)
    assert r.status_code == 201


def test_failed_publish_leaves_no_orphan_feed_event_and_maps_to_409(main, services, monkeypatch):
    seq0, _ = services.schedule.revocations_since(0)

    def conflict(*_a, **_k):
        raise ScheduleConflict("concurrent schedule updates")

    monkeypatch.setattr(services.schedule, "publish", conflict)
    r = main.post("/v1/admin/revocations", {"type": "USER", "target_id": "u_3c4d"}, headers=ADMIN_H)
    assert r.status_code == 409 and r.json()["error"]["code"] == "INVALID_STATE"
    r = access(main, "u_3c4d", {"role": "faculty"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "INVALID_STATE"
    _, items = services.schedule.revocations_since(0)
    assert [i for i in items if i["seq"] > seq0] == []


# ------------------------------------------------------------------ enrolment liveness gate
def _session(c: Signed, uid: str, att: str = "att_lv1") -> str:
    r = c.post("/v1/liveness/session", {"attempt_id": att, "kiosk_id": "KIOSK_MAIN_01", "user_id": uid})
    assert r.status_code == 201, r.text
    return r.json()["session_id"]


def test_enrolment_liveness_gate_first_time_user_bound_and_single_use(main, services):
    sid = _session(main, "u_tm03")
    # bound to the user_id it was created for
    other = edge_style_enrol(main, uid="u_tm04", liveness_session_id=_session(main, "u_tm03", "att_lv2"))
    assert other.status_code == 403 and "another user" in other.json()["error"]["message"]
    # a first-time user (no faces yet) passes: liveness reference vs the enrolment frame (CompareFaces)
    first = main.post("/v1/enroll", {
        "user_id": "u_tm03", "display_name": "T3", "consent": True, "consent_version": "v1",
        "liveness_session_id": sid, "images_b64": [b64(make_fake_jpeg("u_tm03", salt=f"g{i}")) for i in range(3)]})
    assert first.status_code == 201, first.text
    again = main.post("/v1/enroll", {
        "user_id": "u_tm03", "display_name": "T3", "consent": True, "consent_version": "v1",
        "liveness_session_id": sid, "images_b64": [b64(make_fake_jpeg("u_tm03", salt="h"))]})
    assert again.status_code == 403 and "already used" in again.json()["error"]["message"]


def test_enrolment_liveness_gate_rejects_a_different_face(main, services):
    sid = _session(main, "u_tm05")
    r = main.post("/v1/enroll", {
        "user_id": "u_tm05", "display_name": "T5", "consent": True, "consent_version": "v1",
        "liveness_session_id": sid, "images_b64": [b64(make_fake_jpeg("someone_else"))]})
    assert r.status_code == 403 and "do not match" in r.json()["error"]["message"]
    assert services.kv.get("users", "u_tm05") is None


# ------------------------------------------------------------------ v1.4: hygiene at the edge's iterations
def _documented_entry(code_id: str, iterations: int) -> dict:
    """A publicly documented value (scripts/sign_bundle.py DOC_OVERRIDE_CODES) under a fresh code_id."""
    from cloud.app.policy_bridge import load_documented_override_values

    value = load_documented_override_values()[0]
    salt = "ab" * 8
    return {"code_id": code_id, "staff_id": "s_guard01", "salt": salt,
            "hash": hashlib.pbkdf2_hmac("sha256", value.encode(), bytes.fromhex(salt), iterations).hex()}


@pytest.mark.parametrize("declared", [100000, 1000])
def test_documented_value_is_stripped_at_the_edge_effective_iterations(main, services, declared):
    """The edge verifies with max(bundle iterations, thresholds 100000): a documented value hashed at 100000 in a
    bundle that DECLARES fewer iterations would still verify at the edge, so hygiene must catch it too."""
    doc = main.get("/v1/admin/schedule", headers=ADMIN_H).json()["doc"]
    doc["override_codes"] = {"kdf": "PBKDF2-HMAC-SHA256", "iterations": declared,
                             "codes": [_documented_entry("OVR-LEAK-01", 100000)]}
    r = main.request("PUT", "/v1/admin/schedule", json_body=doc, headers=ADMIN_H)  # every publish strips
    assert r.status_code == 200, r.text
    assert services.schedule.current()["doc"]["override_codes"]["codes"] == []
    assert bundle(main)["override_codes"]["codes"] == []  # and every re-sign


def test_restore_of_a_revoked_and_erased_user_lifts_both(main, services):
    assert edge_style_enrol(main, uid="u_3c4d", role="student", card=None).status_code == 201
    assert main.delete("/v1/enroll/u_3c4d").status_code == 200
    assert main.post("/v1/admin/revocations", {"type": "USER", "target_id": "u_3c4d", "reason": "ADMIN"},
                     headers=ADMIN_H).status_code == 201
    seq0, _ = services.schedule.revocations_since(0)
    # REVOKED wins over ERASED: consent alone is refused, consent + restore lifts everything
    r = access(main, "u_3c4d", {"role": "student", "consent": True})
    assert r.status_code == 409 and r.json()["error"]["reason"] == "USER_REVOKED"
    r = access(main, "u_3c4d", {"role": "student", "consent": True, "restore": True, "actor": "cp"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["restored"] is True and out["readmitted"] is True and out["user"]["status"] == "ACTIVE"
    _, feed = services.schedule.revocations_since(seq0)
    assert [(i["type"], i["reason"]) for i in feed] == [("READMIT", "READMIT"), ("READMIT", "RESTORE")]
    assert check(main, "u_3c4d", T0) == "IN_WINDOW"
    a = main.get("/v1/admin/audit?user_id=u_3c4d", headers=ADMIN_H).json()["items"][-1]
    assert a["action"] == "RESTORE" and a["previous_status"] == "REVOKED" and a["actor"] == "legacy:admin_token"


def test_edit_of_a_revoked_user_without_consent_keeps_the_revocation(main, services):
    r = access(main, "u_a3b4", {"role": "student", "valid_until": "2026-12-31T00:00:00+05:30"})
    assert r.status_code == 200 and r.json()["user"]["status"] == "REVOKED"
    assert r.json()["warnings"] == ["user is revoked: access changes do not lift a revocation (use Restore)"]
    assert check(main, "u_a3b4", T0) == "REVOKED"


def test_erase_of_a_readmitted_user_emits_a_fresh_erase(main, services):
    assert edge_style_enrol(main, uid="u_3c4d", role="student", card=None).status_code == 201
    assert main.delete("/v1/enroll/u_3c4d").status_code == 200
    assert access(main, "u_3c4d", {"role": "student", "consent": True}).json()["readmitted"] is True
    assert edge_style_enrol(main, uid="u_3c4d", role="student", card=None, salt="2nd").status_code == 201
    # same method + path within one second = same signature: re-sign one second later (replay cache)
    import time as _time

    assert main.request("DELETE", "/v1/enroll/u_3c4d", now=_time.time() + 1).status_code == 200
    _, feed = services.schedule.revocations_since(0)
    assert [i["type"] for i in feed if i["target_id"] == "u_3c4d"] == ["ERASE", "READMIT", "ERASE"]
    doc = services.schedule.current()["doc"]
    assert doc["users"]["u_3c4d"]["role"] == "student"  # the entitlement survives every erasure
    assert [r["reason"] for r in doc["revocations"] if r["user_id"] == "u_3c4d"] == ["ERASED"]


def test_readmit_feed_reasons_match_the_contract_enum(services):
    """L4: READMIT feed entries carry reason READMIT | RESTORE only (contract enums.readmit_reason)."""
    from pathlib import Path

    contract = json.loads((Path(__file__).resolve().parents[2] / "docs/contracts/admin_access.examples.json")
                          .read_text())
    assert tuple(contract["enums"]["readmit_reason"]) == sched_mod.READMIT_REASONS
    seq0 = services.schedule.revocations_since(0)[0]
    with pytest.raises(ValueError, match="READMIT feed reason"):
        services.schedule._feed_event("READMIT", "u_3c4d", "ENROL")
    assert services.schedule.revocations_since(0)[0] == seq0  # nothing written, no seq burnt


# ------------------------------------------------------------------ read windows = edge WindowRead (days required)
ALL_DAYS = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]


def test_master_windows_without_days_read_as_every_day(main, services):
    """A master document may omit `days` (= every day for the evaluators). The admin read view spells that out as
    all seven days so it parses into ReadWindow / edge WindowRead, which require days."""
    from cloud.app import schemas as S

    def drop_days(doc):
        doc["roles"]["student"]["windows"]["MAIN_GATE"] = [{"start": "06:00", "end": "23:00"}]
        doc["users"]["u_3c4d"]["extra_windows"] = {"MAIN_GATE": [{"start": "05:00", "end": "06:00"}]}
    services.schedule.publish(drop_days, "test:days-less windows")
    r = main.get("/v1/admin/users", headers=ADMIN_H)
    assert r.status_code == 200, r.text
    body = S.AdminUsersResponse.model_validate(r.json())
    assert body.roles["student"].windows["MAIN_GATE"][0].days == ALL_DAYS
    row = next(u for u in body.users if u.user_id == "u_3c4d")
    assert row.extra_windows["MAIN_GATE"][0].days == ALL_DAYS
    stored = services.schedule.current()["doc"]["roles"]["student"]["windows"]["MAIN_GATE"][0]
    assert "days" not in stored  # read-view normalisation only: the signed bundle is unchanged


def test_read_window_requires_days_and_a_written_start():
    from pydantic import ValidationError

    from cloud.app import schemas as S

    assert S.ReadWindow.model_validate({"days": ["MON"], "start": "22:00", "end": "24:00"}).end == "24:00"
    for bad in ({"start": "06:00", "end": "07:00"}, {"days": ["MON"], "start": "24:00", "end": "24:00"}):
        with pytest.raises(ValidationError):
            S.ReadWindow.model_validate(bad)


def test_master_window_start_2400_is_refused(services):
    """start is 00:00-23:59 everywhere (edge Window / WindowRead); only end may be 24:00 in a master document."""
    doc = copy.deepcopy(services.schedule.current()["doc"])
    doc["roles"]["student"]["windows"]["MAIN_GATE"] = [{"days": ["MON"], "start": "24:00", "end": "24:00"}]
    with pytest.raises(sched_mod.BundleRejected, match="start"):
        sched_mod.validate_schedule_doc(doc)
    doc["roles"]["student"]["windows"]["MAIN_GATE"] = [{"days": ["MON"], "start": "22:00", "end": "24:00"}]
    sched_mod.validate_schedule_doc(doc)
