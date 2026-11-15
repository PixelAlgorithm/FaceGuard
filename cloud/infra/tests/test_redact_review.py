"""CI-01 (cloud/infra/redact.py: secrets echoed back as JSON / quoted text, value-based masking) and CI-07
(cloud/tools/redact.py: override-code hash/salt never printed). Dummy values only."""

# ruff: noqa: S603, S607, S105, S106, S108

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from cloud.tools import redact as tools_redact

from .conftest import INFRA

REDACT = INFRA / "redact.py"
S1, S2, S3 = "DUMMYSECRET1", "DUMMYSECRET2", "DUMMYSECRET3"
LAMBDA_4KB = (
    "An error occurred (InvalidParameterValueException) when calling the UpdateFunctionConfiguration operation: "
    "Lambda was unable to configure your environment variables because the environment variables you have "
    'provided exceeded the 4KB limit. String measured: {"KIOSK_HMAC_KEY":"' + S1 + '","ADMIN_TOKEN":"' + S2 + '"}'
)


def _redact(text: str, values_file: Path | None = None) -> str:
    env = {k: v for k, v in os.environ.items() if k != "HID_REDACT_VALUES_FILE"}
    if values_file is not None:
        env["HID_REDACT_VALUES_FILE"] = str(values_file)
    r = subprocess.run([sys.executable, str(REDACT)], input=text, capture_output=True, text=True, timeout=30,
                       env=env)
    assert r.returncode == 0, r.stderr
    return r.stdout


def _assert_hidden(out: str, *secrets: str) -> None:
    for s in secrets:
        assert s not in out, f"{s} leaked in: {out}"


# --------------------------------------------------------------------------- CI-01 pattern rules
def test_lambda_4kb_string_measured_is_masked_wholesale():
    out = _redact(LAMBDA_4KB)
    _assert_hidden(out, S1, S2)
    assert "String measured: ***" in out
    assert "UpdateFunctionConfiguration" in out and "4KB limit" in out


def test_string_measured_truncated_json_is_masked_to_end():
    out = _redact(LAMBDA_4KB[: LAMBDA_4KB.index(S2) + 4])  # head -c 600 style truncation mid-value
    _assert_hidden(out, S1, S2[:4] + "SECRET")
    assert "String measured: ***" in out


def test_single_and_double_quoted_env_lines_are_masked():
    text = f"line1 KIOSK_HMAC_KEY='{S1}' and\nADMIN_TOKEN=\"{S2}\"\nexport CLOUD_API_KEY= '{S3}'\n"
    out = _redact(text)
    _assert_hidden(out, S1, S2, S3)
    assert "KIOSK_HMAC_KEY=" in out and "ADMIN_TOKEN=" in out


def test_json_key_value_forms_in_text_are_masked():
    text = f'error: bad config {{"CLOUD_API_KEY": "{S3}", "region": "us-east-1"}} trailing words'
    out = _redact(text)
    _assert_hidden(out, S3)
    assert "us-east-1" in out and "trailing words" in out


def test_colon_and_escaped_json_forms_are_masked():
    text = f'ADMIN_TOKEN: {S2}\nmsg="{{\\"KIOSK_HMAC_KEY\\":\\"{S1}\\"}}"\n'
    out = _redact(text)
    _assert_hidden(out, S1, S2)


def test_json_embedded_in_text_line_masks_environment_block():
    body = json.dumps({"FunctionName": "hid-kiosk-cloud-api",
                       "Environment": {"Variables": {"SOME_URL": "https://x.example.org/" + S1}}})
    out = _redact("response was " + body + " end")
    _assert_hidden(out, S1)
    assert "hid-kiosk-cloud-api" in out


def test_non_secret_key_names_stay_visible():
    text = ("KeyType=HASH KMSMasterKeyId=alias/hid-kiosk Key=Project,Value=hid TagKey=Owner "
            '{"KeyType": "RANGE", "KmsKeyArn": "arn:aws:kms:us-east-1:1:key/abc", "KeySchema": "x"} '
            "AttributeName=pk SSEKeyName=main")
    out = _redact(text)
    for kept in ("KeyType=HASH", "KMSMasterKeyId=alias/hid-kiosk", "Key=Project", "TagKey=Owner", "RANGE",
                 "arn:aws:kms:us-east-1:1:key/abc", "AttributeName=pk", "SSEKeyName=main"):
        assert kept in out, kept


def test_whole_json_input_still_masks_env_and_keeps_names():
    body = json.dumps({"FunctionName": "hid-kiosk-cloud-api",
                       "Environment": {"Variables": {"KIOSK_HMAC_KEY": S1}},
                       "LastUpdateStatusReason": f"String measured: {{\"ADMIN_TOKEN\":\"{S2}\"}}"})
    out = _redact(body)
    _assert_hidden(out, S1, S2)
    assert "hid-kiosk-cloud-api" in out


# --------------------------------------------------------------------------- CI-01 value-based masking
def _values_file(tmp_path: Path) -> Path:
    p = tmp_path / "values.env"
    p.write_text(
        "# comment line\n\n"
        "export STAFF_STORE_KEY=plainvalue-0001 # trailing comment\n"
        "SOME_SECRET='quoted-single-0002'\n"
        'OTHER_SECRET="quoted-double-0003"\n'
        "SHORT_ONE=abc1234\n"
        "LONGER=plainvalue-0001-extended\n"
    )
    return p


def test_values_file_masks_values_anywhere(tmp_path):
    vf = _values_file(tmp_path)
    text = ("free text plainvalue-0001 here; json {\"note\": \"quoted-single-0002\"} and "
            "url?x=quoted-double-0003 plus plainvalue-0001-extended done")
    out = _redact(text, vf)
    _assert_hidden(out, "plainvalue-0001", "quoted-single-0002", "quoted-double-0003", "-extended")
    assert "free text" in out and "done" in out


def test_values_file_masks_values_in_whole_json(tmp_path):
    vf = _values_file(tmp_path)
    out = _redact(json.dumps({"Description": "made with quoted-single-0002", "Name": "fn"}), vf)
    _assert_hidden(out, "quoted-single-0002")
    assert '"fn"' in out


def test_values_file_short_values_are_not_masked(tmp_path):
    vf = _values_file(tmp_path)
    out = _redact("value abc1234 stays visible", vf)
    assert "abc1234" in out


def test_values_file_missing_is_silent_and_rules_still_apply(tmp_path):
    out = _redact(f"KIOSK_HMAC_KEY='{S1}' quoted-single-0002", tmp_path / "does-not-exist.env")
    _assert_hidden(out, S1)
    assert "quoted-single-0002" in out


# --------------------------------------------------------------------------- CI-07 override-code hash/salt
SCHEDULE = {
    "doc": {
        "bundle_version": 51, "record_hash": "a" * 64, "chain_head": "b" * 64,
        "override_codes": {"codes": [{"code_id": "OVR-01", "staff_id": "s_guard01", "hash": "c" * 64,
                                      "salt": "d" * 32, "iterations": 200000, "algo": "pbkdf2_sha256"}]},
    },
    "audit": [{"prev_hash": "e" * 64, "sha256": "f" * 64, "content_hash": "9" * 64, "hash": "8" * 64}],
    "kdf": {"salt": "7" * 32},
}


def test_override_code_hash_and_salt_are_masked():
    red = tools_redact.redact_json(SCHEDULE)
    dumped = json.dumps(red)
    assert "c" * 64 not in dumped and "d" * 32 not in dumped and "7" * 32 not in dumped
    code = red["doc"]["override_codes"]["codes"][0]
    assert code["hash"] == "***" and code["salt"] == "***"
    assert code["code_id"] == "OVR-01" and code["staff_id"] == "s_guard01" and code["iterations"] == 200000


def test_non_secret_digests_stay_visible():
    red = tools_redact.redact_json(SCHEDULE)
    assert red["doc"]["record_hash"] == "a" * 64 and red["doc"]["chain_head"] == "b" * 64
    audit = red["audit"][0]
    assert audit["prev_hash"] == "e" * 64 and audit["sha256"] == "f" * 64 and audit["content_hash"] == "9" * 64
    assert audit["hash"] == "8" * 64  # `hash` outside override_codes is a digest, not a secret


def test_tools_redact_text_masks_override_hash():
    out = tools_redact.redact_text(json.dumps(SCHEDULE))
    assert "c" * 64 not in out and "d" * 32 not in out and "a" * 64 in out
