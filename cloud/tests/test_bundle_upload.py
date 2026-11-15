"""PUT /v1/admin/schedule/{kiosk_id} (operator-signed authoritative bundle), override-code hygiene,
optional enrolment e-mail and the single-source code grace hours (config/thresholds.yaml)."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import time
from datetime import timedelta

import pytest

from cloud.app.clock import iso_z, parse_ts
from cloud.app.config import PROJECT_ROOT
from cloud.app.services import code_hygiene
from cloud.app.services.schedule_service import verify_bundle
from cloud.tools.fakeimg import make_fake_jpeg

from .conftest import ADMIN, BUNDLE_KEY, T0, Signed, etag

ADMIN_H = {"X-Admin-Token": ADMIN}
EXAMPLE = PROJECT_ROOT / "config" / "schedule.example.json"
DEMO = PROJECT_ROOT / "config" / "schedule.demo.json"


def fresh_code(i: int = 1, code: str = "60417223") -> dict:
    salt = f"{i:016x}"
    return {"code_id": f"OVR-DTEST-{i:02d}", "staff_id": "s_guard01", "salt": salt,
            "valid_until": iso_z(T0 + timedelta(hours=36)),
            "hash": hashlib.pbkdf2_hmac("sha256", code.encode(), bytes.fromhex(salt), 100000).hex()}


def operator_bundle(version: int = 46, *, src=DEMO, kiosks: list[str] | None = None, codes: list[dict] | None = None,
                    key: str = BUNDLE_KEY, issued=T0, hours: int = 12) -> dict:
    """What scripts/sign_bundle.py writes: full schedule, stamped, fresh codes, signed with the EDGE signer."""
    from edge.offline.bundle import sign_bundle as edge_sign

    doc = json.loads(src.read_text(encoding="utf-8"))
    doc.pop("signature", None)
    doc["bundle_version"] = version
    doc["issued_at"] = iso_z(issued)
    doc["expires_at"] = iso_z(issued + timedelta(hours=hours))
    doc["override_codes"]["codes"] = [fresh_code(1), fresh_code(2)] if codes is None else codes
    if kiosks is not None:  # kiosk-filtered upload
        doc["kiosks"] = {k: v for k, v in doc["kiosks"].items() if k in kiosks}
        doc["scope"] = {"kiosk_ids": list(kiosks)}
    return edge_sign(doc, key.encode(), key_id="demo-k1")


def put(signed: Signed, kiosk: str, bundle, *, admin: bool = True, now: float | None = None):
    return signed.request("PUT", f"/v1/admin/schedule/{kiosk}", json_body=bundle,
                          headers=ADMIN_H if admin else None, now=now)


@pytest.fixture
def main(client) -> Signed:
    return Signed(client, kiosk="KIOSK_MAIN_01")


# ------------------------------------------------------------------ accept + serve verbatim
def test_upload_is_served_verbatim_with_version_etag_and_edge_accepts_it(main, services, tmp_path):
    b = operator_bundle(46)
    r = put(main, "KIOSK_MAIN_01", b)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["bundle_version"] == 46 and out["etag"] == etag(46) and out["served"] == "verbatim"
    assert out["master"] == "replaced" and out["override_codes"] == 2 and out["unchanged"] is False

    g = main.get("/v1/schedule/KIOSK_MAIN_01")
    assert g.status_code == 200 and g.headers["etag"] == etag(46) and g.json() == b  # byte-for-byte content
    assert main.get("/v1/schedule/KIOSK_MAIN_01", headers={"If-None-Match": etag(46)}).status_code == 304
    # a bare version tag is not the representation the kiosk holds: 200 (EO-01)
    assert main.get("/v1/schedule/KIOSK_MAIN_01", headers={"If-None-Match": '"46"'}).status_code == 200

    # the edge's own BundleStore installs it (signature + kiosk scope + version rules of edge/offline/bundle.py)
    from edge.offline.bundle import BundleStore

    store = BundleStore(tmp_path / "bundle.json", BUNDLE_KEY.encode(), "KIOSK_MAIN_01")
    ok, reason = store.install(g.json(), T0)
    assert ok, reason

    # master content follows the upload: other kiosks get it cloud-signed at the same version
    lib = Signed(main.c, kiosk="KIOSK_LIB_01").get("/v1/schedule/KIOSK_LIB_01").json()
    assert lib["bundle_version"] == 46 and verify_bundle(lib, BUNDLE_KEY)
    assert [c["code_id"] for c in lib["override_codes"]["codes"]] == ["OVR-DTEST-01", "OVR-DTEST-02"]
    assert services.schedule.current()["version"] == 46


def test_identical_reupload_is_idempotent(main):
    b = operator_bundle(46)
    ts = time.time()
    assert put(main, "KIOSK_MAIN_01", b, now=ts).status_code == 200
    # the exact same signed request is single-use (replay cache, auth.py) -- that check stays
    assert put(main, "KIOSK_MAIN_01", b, now=ts).status_code == 401
    again = put(main, "KIOSK_MAIN_01", b, now=ts + 2)  # operator retry re-signs -> idempotent no-op
    assert again.status_code == 200 and again.json()["unchanged"] is True
    assert main.get("/v1/schedule/KIOSK_MAIN_01").headers["etag"] == etag(46)


# ------------------------------------------------------------------ refusals (nothing changes)
def _unchanged(main, services, version: int = 42) -> None:
    assert services.schedule.current()["version"] == version
    assert main.get("/v1/schedule/KIOSK_MAIN_01").headers["etag"] == etag(version)


def test_bad_signature_rejected_403(main, services):
    b = operator_bundle(46)
    b["users"]["u_prj1"]["role"] = "admin_staff"  # tampered after signing
    r = put(main, "KIOSK_MAIN_01", b)
    assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN"
    wrong_key = operator_bundle(46, key="x" * 64)
    assert put(main, "KIOSK_MAIN_01", wrong_key).status_code == 403
    unsigned = {k: v for k, v in operator_bundle(46).items() if k != "signature"}
    assert put(main, "KIOSK_MAIN_01", unsigned).status_code == 403
    _unchanged(main, services)


@pytest.mark.parametrize("version", [41, 42])
def test_lower_or_equal_version_rejected_409(main, services, version):
    r = put(main, "KIOSK_MAIN_01", operator_bundle(version))
    assert r.status_code == 409 and r.json()["error"]["code"] == "INVALID_STATE"
    assert "--version 43" in r.json()["error"]["message"]
    _unchanged(main, services)


def test_lower_than_previous_upload_rejected(main, services):
    assert put(main, "KIOSK_MAIN_01", operator_bundle(46)).status_code == 200
    assert put(main, "KIOSK_MAIN_01", operator_bundle(45)).status_code == 409
    assert put(main, "KIOSK_MAIN_01", operator_bundle(46, codes=[fresh_code(9)])).status_code == 409  # same v, new
    assert services.schedule.current()["version"] == 46


def test_wrong_kiosk_scope_rejected_403(main, services):
    only_main = operator_bundle(46, kiosks=["KIOSK_MAIN_01"])
    r = put(main, "KIOSK_LIB_01", only_main)  # bundle does not cover the path kiosk
    assert r.status_code == 403 and "scope" in r.json()["error"]["message"]
    scoped_out = copy.deepcopy(operator_bundle(46))
    from edge.offline.bundle import sign_bundle as edge_sign

    scoped_out["scope"] = {"kiosk_ids": ["KIOSK_LIB_01"]}  # kiosk listed but outside the signed scope
    scoped_out = edge_sign({k: v for k, v in scoped_out.items() if k != "signature"}, BUNDLE_KEY.encode(), "demo-k1")
    assert put(main, "KIOSK_MAIN_01", scoped_out).status_code == 403
    assert put(main, "KIOSK_NOPE_01", operator_bundle(46)).status_code == 403  # not in the bundle either
    _unchanged(main, services)


def test_documented_codes_and_expired_bundles_rejected_422(main, services):
    example = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    doc_codes = example["override_codes"]["codes"]
    r = put(main, "KIOSK_MAIN_01", operator_bundle(46, codes=doc_codes))
    assert r.status_code == 422 and "documented" in r.json()["error"]["message"]
    renamed = [{**doc_codes[0], "code_id": "OVR-D1114-01"}]  # same documented value under a fresh id
    assert put(main, "KIOSK_MAIN_01", operator_bundle(46, codes=renamed)).status_code == 422
    expired = operator_bundle(46, issued=T0 - timedelta(hours=13))
    assert put(main, "KIOSK_MAIN_01", expired).status_code == 422
    _unchanged(main, services)


def test_upload_needs_admin_token_and_kiosk_signature(main, client):
    b = operator_bundle(46)
    r = put(main, "KIOSK_MAIN_01", b, admin=False)
    assert r.status_code == 403
    raw = client.put("/v1/admin/schedule/KIOSK_MAIN_01", json=b, headers=ADMIN_H)
    assert raw.status_code == 401


# ------------------------------------------------------------------ later cloud changes supersede the upload
def test_revocation_after_upload_publishes_higher_version_with_uploaded_codes(main):
    assert put(main, "KIOSK_MAIN_01", operator_bundle(46)).status_code == 200
    rv = main.request("POST", "/v1/admin/revocations", json_body={"type": "USER", "target_id": "u_prj1"},
                      headers=ADMIN_H)
    assert rv.status_code == 201 and rv.json()["bundle_version"] == 47
    g = main.get("/v1/schedule/KIOSK_MAIN_01", headers={"If-None-Match": etag(46)})
    assert g.status_code == 200 and g.headers["etag"] == etag(47)
    b = g.json()
    assert verify_bundle(b, BUNDLE_KEY) and b["users"]["u_prj1"]["revoked"] is True
    assert [c["code_id"] for c in b["override_codes"]["codes"]] == ["OVR-DTEST-01", "OVR-DTEST-02"]


def test_upload_never_unrevokes_a_live_revocation(main, services):
    # u_prj1 is not in the example seed: without force a typo-protected 404 (test_admin_access.py)
    rv = main.request("POST", "/v1/admin/revocations", json_body={"type": "USER", "target_id": "u_prj1",
                                                                  "reason": "LOST_CARD", "force": True},
                      headers=ADMIN_H)
    assert rv.status_code == 201 and rv.json()["bundle_version"] == 43
    r = put(main, "KIOSK_MAIN_01", operator_bundle(46))  # signed from a source that predates the revocation
    assert r.status_code == 200 and r.json()["revocations_carried_over"] == ["u_prj1"]
    assert r.json()["served"] == "cloud_resigned"
    b = main.get("/v1/schedule/KIOSK_MAIN_01").json()
    assert b["bundle_version"] == 46 and b["users"]["u_prj1"]["revoked"] is True and verify_bundle(b, BUNDLE_KEY)


def test_kiosk_filtered_upload_merges_codes_only(main, services):
    before = services.schedule.doc()
    r = put(main, "KIOSK_MAIN_01", operator_bundle(46, kiosks=["KIOSK_MAIN_01"]))
    assert r.status_code == 200 and r.json()["master"] == "codes_merged"
    after = services.schedule.doc()
    assert set(after["kiosks"]) == set(before["kiosks"]) and after["users"] == before["users"]
    assert [c["code_id"] for c in after["override_codes"]["codes"]] == ["OVR-DTEST-01", "OVR-DTEST-02"]


def test_expired_upload_falls_back_to_cloud_signed_bundle(main, services, clock):
    assert put(main, "KIOSK_MAIN_01", operator_bundle(46)).status_code == 200
    clock.advance(hours=13)
    b = main.get("/v1/schedule/KIOSK_MAIN_01").json()
    assert b["bundle_version"] == 46 and parse_ts(b["expires_at"]) > T0 + timedelta(hours=13)
    assert verify_bundle(b, BUNDLE_KEY) and len(b["override_codes"]["codes"]) == 2


# ------------------------------------------------------------------ hygiene of the cloud's own seed/sign path
def test_seed_and_admin_replace_strip_documented_codes(main, services):
    doc = main.request("GET", "/v1/admin/schedule", headers=ADMIN_H).json()["doc"]
    assert doc["override_codes"]["codes"] == []  # schedule.example.json seed: OVR-001..003 stripped
    for kiosk in doc["kiosks"]:
        b = Signed(main.c, kiosk=kiosk).get(f"/v1/schedule/{kiosk}").json()
        assert code_hygiene.documented_code_ids(b) == [] and b["override_codes"]["codes"] == []
    example = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    example["override_codes"]["codes"].append(fresh_code(3))
    r = main.request("PUT", "/v1/admin/schedule", json_body=example, headers=ADMIN_H)
    assert r.status_code == 200
    kept = [c["code_id"] for c in services.schedule.doc()["override_codes"]["codes"]]
    assert kept == ["OVR-DTEST-03"]


def test_store_seeded_before_the_rule_is_cleaned_on_read(services):
    """The live v45 master was seeded with OVR-001..003: reading it must never serve them."""
    from cloud.app.services.schedule_service import NS_SCHED

    rec = services.kv.get(NS_SCHED, "current") or (services.schedule.current() and services.kv.get(NS_SCHED,
                                                                                                   "current"))
    dirty = {k: v for k, v in rec.items() if k != "_rev"}
    dirty["doc"]["override_codes"]["codes"] = json.loads(EXAMPLE.read_text())["override_codes"]["codes"]
    services.kv.put(NS_SCHED, "current", dirty)
    services.schedule._cache = None
    bundle, _ = services.schedule.signed_bundle("KIOSK_MAIN_01")
    assert bundle["override_codes"]["codes"] == []


def test_hygiene_rule_matches_scripts_sign_bundle():
    from cloud.app.policy_bridge import load_sign_bundle_module

    mod = load_sign_bundle_module()
    example = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    a, b = copy.deepcopy(example), copy.deepcopy(example)
    a["override_codes"]["codes"].append(fresh_code(4))
    b["override_codes"]["codes"].append(fresh_code(4))
    assert sorted(mod.drop_documented_codes(a)) == sorted(code_hygiene.strip_documented_codes(b)) == \
        ["OVR-001", "OVR-002", "OVR-003"]
    assert a["override_codes"]["codes"] == b["override_codes"]["codes"]


def test_hygiene_fails_secure_without_the_documented_list(monkeypatch):
    monkeypatch.setattr(code_hygiene, "load_documented_override_values", lambda: None)
    monkeypatch.setattr(code_hygiene, "_MEMO", {})
    doc = {"override_codes": {"iterations": 100000, "codes": [fresh_code(5)]}}
    assert code_hygiene.strip_documented_codes(doc) == ["OVR-DTEST-05"] and doc["override_codes"]["codes"] == []


# ------------------------------------------------------------------ single source: thresholds.yaml grace hours
def test_code_grace_hours_come_from_thresholds_yaml(tmp_path, clock):
    import yaml

    from cloud.app.container import build_services

    from .conftest import make_settings

    cfg = yaml.safe_load((PROJECT_ROOT / "config" / "thresholds.yaml").read_text(encoding="utf-8"))
    assert cfg["fallback"]["staff_override"]["valid_after_expiry_h"] == 24
    cfg["fallback"]["staff_override"]["valid_after_expiry_h"] = 6
    p = tmp_path / "thresholds.yaml"
    p.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    svc = build_services(make_settings(thresholds_path=str(p)), clock=clock)
    assert svc.thresholds.override_valid_after_expiry_h == 6.0
    svc.schedule.publish(lambda d: d["override_codes"]["codes"].append(fresh_code(6)), "test")
    b, _ = svc.schedule.signed_bundle("KIOSK_MAIN_01")
    assert {c["valid_until"] for c in b["override_codes"]["codes"]} == {
        iso_z(parse_ts(b["expires_at"]) + timedelta(hours=6))}
    assert not hasattr(svc.settings, "override_grace_hours")  # no second (env) knob


# ------------------------------------------------------------------ enrolment without e-mail
@pytest.mark.parametrize("email", [None, "", "   "])
def test_enroll_without_email_indexes_face_and_otp_is_unavailable(signed, services, email):
    body = {"user_id": "u_tm02", "display_name": "Teammate 2", "groups": ["student"], "consent": True,
            "consent_version": "2026-11-14.v1", "provision_totp": False,
            "images_b64": [base64.b64encode(make_fake_jpeg("u_tm02", salt=f"f{i}")).decode() for i in range(3)]}
    if email is not None:
        body["email"] = email
    r = signed.post("/v1/enroll", body)
    assert r.status_code == 201, r.text
    assert r.json()["faces_indexed"] == 3 and r.json()["destination_masked"] is None
    assert services.kv.get("users", "u_tm02")["email"] is None
    o = signed.post("/v1/otp/send", {"attempt_id": "att_noemail", "user_id": "u_tm02", "channel": "email"})
    assert o.status_code == 404 and o.json()["error"]["code"] == "NOT_FOUND"


def test_reenroll_without_email_keeps_the_email_on_file(signed, services):
    imgs = [base64.b64encode(make_fake_jpeg("u_tm03", salt=f"g{i}")).decode() for i in range(2)]
    base = {"user_id": "u_tm03", "display_name": "Teammate 3", "consent": True, "consent_version": "v1",
            "provision_totp": False, "images_b64": imgs}
    assert signed.post("/v1/enroll", {**base, "email": "tm3@example.org"}).status_code == 201
    r = signed.post("/v1/enroll", base)
    assert r.status_code == 201 and r.json()["destination_masked"] == "t**@example.org"
    assert services.kv.get("users", "u_tm03")["email"] == "tm3@example.org"


def test_malformed_email_still_rejected(signed):
    body = {"user_id": "u_tm04", "display_name": "x", "email": "not-an-email", "consent": True,
            "consent_version": "v1", "images_b64": [base64.b64encode(make_fake_jpeg("u_tm04")).decode()]}
    assert signed.post("/v1/enroll", body).status_code == 422
