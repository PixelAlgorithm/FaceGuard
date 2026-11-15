"""scripts/sign_bundle.py end to end (subprocess, fixture keys via the environment, temp output paths)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys

from edge.offline.bundle import verify_bundle
from edge.policy.tests.builders import (
    PROJECT_ROOT,
    SIGNED_BUNDLE,
    TEST_BUNDLE_KEY,
    TEST_CARD_PEPPER,
    sign_fixture_bundle,
)

SCRIPT = PROJECT_ROOT / "scripts" / "sign_bundle.py"
EXAMPLE = PROJECT_ROOT / "config" / "schedule.example.json"
DEMO = PROJECT_ROOT / "config" / "schedule.demo.json"
DOC_VALUES = ("48213907", "75530182", "19064425")  # publicly documented (SURPRISE_CHALLENGES SC2.4)


def run(tmp_path, *args, src=EXAMPLE):
    env = {**os.environ, "SCHEDULE_BUNDLE_HMAC_KEY": TEST_BUNDLE_KEY.decode(), "CARD_ID_PEPPER": TEST_CARD_PEPPER.decode()}
    out, codes = tmp_path / "bundle.signed.json", tmp_path / "DEMO_CODES.txt"
    r = subprocess.run([sys.executable, str(SCRIPT), "--src", str(src), "--out", str(out), "--codes-file",
                        str(codes), *args], env=env, capture_output=True, text=True, timeout=60,
                       check=False)
    assert r.returncode == 0, r.stderr
    return r, json.loads(out.read_text(encoding="utf-8")), codes


def _verifies(c, value):
    return hashlib.pbkdf2_hmac("sha256", value.encode(), bytes.fromhex(c["salt"]), 100000).hex() == c["hash"]


def test_signs_and_restamps(tmp_path):
    _r, b, _codes = run(tmp_path, "--now", "2026-11-14T04:30:00Z", "--extra-codes", "2", "--allow-doc-codes")
    assert verify_bundle(b, TEST_BUNDLE_KEY)
    body = {k: v for k, v in b.items() if k != "signature"}
    assert sign_fixture_bundle(body)["signature"]["value"] == b["signature"]["value"]  # independent check
    assert b["issued_at"] == "2026-11-14T04:30:00Z" and b["expires_at"] == "2026-11-14T16:30:00Z"
    assert {c["valid_until"] for c in b["override_codes"]["codes"]} == {"2026-11-15T16:30:00Z"}  # expires + 24 h
    for uid in ("u_3c4d", "u_7a8b"):  # demo pepper -> recomputed hashes equal the documented ones
        assert b["users"][uid]["fallback"]["card_id_hash"] == SIGNED_BUNDLE["users"][uid]["fallback"]["card_id_hash"]
    assert len(b["override_codes"]["codes"]) == 5


def test_secrets_only_in_the_mode_600_codes_file(tmp_path):
    r, b, codes = run(tmp_path, "--extra-codes", "2", "--allow-doc-codes")
    text = codes.read_text(encoding="utf-8")
    assert stat.S_IMODE(os.stat(codes).st_mode) == 0o600
    listed = re.findall(r"^\s+(OVR-\S+)\s+(s_guard\d+)\s+(\d{8})$", text, re.MULTILINE)
    assert {c[0] for c in listed} >= {"OVR-001", "OVR-002", "OVR-003"} and len(listed) == 5
    by_id = {c["code_id"]: c for c in b["override_codes"]["codes"]}
    for cid, _staff, code in listed:  # every listed code verifies against its PBKDF2 hash
        c = by_id[cid]
        assert hashlib.pbkdf2_hmac("sha256", code.encode(), bytes.fromhex(c["salt"]), 100000).hex() == c["hash"]
    for _cid, _staff, code in listed:
        assert code not in r.stdout
    assert TEST_BUNDLE_KEY.decode() not in r.stdout and "otpauth" not in r.stdout


def test_keep_times(tmp_path):
    _r, b, _codes = run(tmp_path, "--keep-times", "--no-card-hashes", "--allow-doc-codes", "--min-codes", "0")
    assert b["issued_at"] == "2026-11-14T02:30:00Z" and b["expires_at"] == "2026-11-14T14:30:00Z"
    assert {k: v for k, v in b.items() if k != "signature"} == {
        k: v for k, v in json.loads(EXAMPLE.read_text(encoding="utf-8")).items() if k != "signature"}


def test_documented_codes_never_enter_a_signed_bundle_by_default(tmp_path):
    """Lead 2026-11-14 (security): OVR-001..003 are printed in tracked files -> dropped; fresh codes minted."""
    r, b, codes = run(tmp_path)
    oc = b["override_codes"]["codes"]
    assert len(oc) >= 4 and not any(_verifies(c, v) for c in oc for v in DOC_VALUES)
    assert not {c["code_id"] for c in oc} & {"OVR-001", "OVR-002", "OVR-003"}
    text = codes.read_text(encoding="utf-8")
    listed = re.findall(r"^\s+(OVR-\S+)\s+(s_guard\d+)\s+(\d{8})$", text, re.MULTILINE)
    by_id = {c["code_id"]: c for c in oc}
    assert {cid for cid, _s, _v in listed} == set(by_id)  # every bundle code is usable, nothing else listed
    for cid, staff, value in listed:
        assert _verifies(by_id[cid], value) and by_id[cid]["staff_id"] == staff and value not in r.stdout
    assert not any(v in text for v in DOC_VALUES)
    assert "documented codes dropped 3" in r.stdout


def test_a_renamed_documented_code_is_still_dropped(tmp_path):
    src = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    src["override_codes"]["codes"][0]["code_id"] = "GUARD-A"  # same public value under another id
    f = tmp_path / "src.json"
    f.write_text(json.dumps(src), encoding="utf-8")
    _r, b, _codes = run(tmp_path, "--min-codes", "0", src=f)
    assert b["override_codes"]["codes"] == []


def test_live_demo_source_carries_no_override_codes(tmp_path):
    assert json.loads(DEMO.read_text(encoding="utf-8"))["override_codes"]["codes"] == []
    _r, b, _codes = run(tmp_path, src=DEMO)
    oc = b["override_codes"]["codes"]
    assert len(oc) == 4 and {c["staff_id"] for c in oc} == {"s_guard01", "s_guard02"}
    assert not any(_verifies(c, v) for c in oc for v in DOC_VALUES)


# ---------------------------------------------------------------- default bundle_version (swarm 2026-11-14 item 6)
def _install(tmp_path, version):
    """Plant an 'installed' bundle at the --out path (the edge persists every installed bundle there)."""
    b = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    b["bundle_version"] = version
    (tmp_path / "bundle.signed.json").write_text(json.dumps(sign_fixture_bundle(b)), encoding="utf-8")


def test_default_version_is_above_the_installed_bundle_so_a_re_sign_is_never_rejected_as_older(tmp_path):
    src_v = json.loads(EXAMPLE.read_text(encoding="utf-8"))["bundle_version"]
    _install(tmp_path, src_v + 3)  # e.g. a cloud-issued v45 is installed, the source file still says v42
    r, b, _codes = run(tmp_path)
    assert b["bundle_version"] == src_v + 4 and verify_bundle(b, TEST_BUNDLE_KEY)
    assert f"v{src_v + 4}" in r.stdout and f"installed v{src_v + 3}" in r.stdout
    assert not any(_verifies(c, v) for c in b["override_codes"]["codes"] for v in DOC_VALUES)  # still refused


def test_default_version_keeps_the_source_version_when_it_is_already_newer(tmp_path):
    src_v = json.loads(EXAMPLE.read_text(encoding="utf-8"))["bundle_version"]
    _install(tmp_path, src_v - 1)
    _r, b, _codes = run(tmp_path)
    assert b["bundle_version"] == src_v


def test_default_version_bumps_an_equal_installed_version(tmp_path):
    src_v = json.loads(EXAMPLE.read_text(encoding="utf-8"))["bundle_version"]
    _install(tmp_path, src_v)
    _r, b, _codes = run(tmp_path)
    assert b["bundle_version"] == src_v + 1  # strictly greater than the installed one


def test_unreadable_installed_bundle_falls_back_to_the_source_version(tmp_path):
    src_v = json.loads(EXAMPLE.read_text(encoding="utf-8"))["bundle_version"]
    (tmp_path / "bundle.signed.json").write_text("{not json", encoding="utf-8")
    _r, b, _codes = run(tmp_path)
    assert b["bundle_version"] == src_v


def test_explicit_version_below_the_installed_one_is_signed_but_warned(tmp_path):
    src_v = json.loads(EXAMPLE.read_text(encoding="utf-8"))["bundle_version"]
    _install(tmp_path, src_v + 3)
    r, b, _codes = run(tmp_path, "--version", str(src_v))
    assert b["bundle_version"] == src_v
    assert "warning" in r.stderr and "older" in r.stderr
