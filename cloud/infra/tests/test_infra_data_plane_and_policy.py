"""CIT-09 / CI-03 (alarm actions, publishable topic), CIT-15 (least-privilege policy, strict render, CMK
wiring), CIT-01 (table protection)."""

# ruff: noqa: S603, S607, S105, S106, S108

from __future__ import annotations

import json

from .conftest import INFRA


def _render(h, template: str, **env: str):
    return h.bash(f'render "{INFRA}/templates/{template}"', **env)


POLICY_ENV = {"HID_REGION": "us-east-1", "ACCOUNT_ID": "123456789012", "COLLECTION_ID": "c", "DDB_USERS": "u",
              "DDB_DECISIONS": "d", "DDB_STATE": "s", "BUCKET": "b", "LAMBDA_NAME": "l", "SSM_PREFIX": "/p",
              "SES_FROM_ADDRESS": "sender@example.org", "KMS_KEY_ARN": "arn:aws:kms:us-east-1:123456789012:key/k1"}


def test_render_fails_on_unresolved_variable(h):
    env = {k: v for k, v in POLICY_ENV.items() if k != "SSM_PREFIX"}
    r = _render(h, "app-policy.json.tmpl", **env)
    assert r.returncode != 0
    assert "SSM_PREFIX" in r.stderr


def test_policy_scopes_ses_to_sender_and_grants_cmk(h):
    r = _render(h, "app-policy.json.tmpl", **POLICY_ENV)
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    ses = next(s for s in doc["Statement"] if s["Sid"] == "SesSend")
    assert ses["Resource"] != "*"
    assert ses["Condition"]["StringEquals"]["ses:FromAddress"] == "sender@example.org"
    kms = next(s for s in doc["Statement"] if s["Sid"] == "AppDataKey")
    assert kms["Resource"] == POLICY_ENV["KMS_KEY_ARN"]
    assert set(kms["Action"]) == {"kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"}


def test_alarm_without_topic_warns(h):
    r = h.run("data_plane.sh", "--skip-rekognition", "--skip-dynamodb", "--skip-s3")
    assert r.returncode == 0, r.stderr
    assert "nobody is notified" in (r.stdout + r.stderr)


def test_alarm_email_creates_publishable_topic_and_sets_actions(h):
    h.rule("sns", "create-topic", stdout="arn:aws:sns:us-east-1:123456789012:hid-kiosk-security-alerts\n")
    r = h.run("data_plane.sh", "--apply", "--skip-rekognition", "--skip-dynamodb", "--skip-s3",
              "--alarm-email", "oncall@example.org", HID_KEEP_RENDERED="1")
    assert r.returncode == 0, r.stdout + r.stderr
    calls = h.joined_calls()
    creates = [c for c in calls if "create-topic" in c]
    # CI-03: CloudWatch cannot publish to an alias/aws/sns topic; without a stack CMK the topic is unencrypted
    assert creates and not any("alias/aws/sns" in c or "KmsMasterKeyId" in c for c in creates)
    assert any("subscribe" in c and "oncall@example.org" in c for c in calls)
    alarms = [c for c in calls if "put-metric-alarm" in c]
    assert len(alarms) >= 3  # revoked-admitted + log-tamper + sync-conflict (+ spoof burst)
    rendered = sorted((h.tmp / "tmpdir").glob("hid-alarm-*.json"))
    assert rendered, "HID_KEEP_RENDERED keeps rendered alarm files for inspection"
    for f in rendered:
        doc = json.loads(f.read_text())
        assert doc["AlarmActions"] == ["arn:aws:sns:us-east-1:123456789012:hid-kiosk-security-alerts"]
    assert h.state()["ALARM_TOPIC_ARN"].endswith("hid-kiosk-security-alerts")


def test_tables_created_with_deletion_protection(h):
    h.not_found("describe-table")
    r = h.run("data_plane.sh", "--apply", "--skip-rekognition", "--skip-s3", "--skip-cloudwatch")
    assert r.returncode == 0, r.stdout + r.stderr
    creates = [c for c in h.joined_calls() if "create-table" in c]
    assert len(creates) == 3 and all("--deletion-protection-enabled" in c for c in creates)


def test_cmk_wired_into_tables_and_bucket(h):
    h.not_found("describe-key")
    h.rule("kms", "create-key", stdout="k1\n")
    h.not_found("describe-table")
    h.not_found("head-bucket", code="404")
    r = h.run("data_plane.sh", "--apply", "--with-cmk", "--skip-rekognition", "--skip-cloudwatch")
    assert r.returncode == 0, r.stdout + r.stderr
    calls = h.joined_calls()
    assert all("KMSMasterKeyId=k1" in c for c in calls if "create-table" in c)
    enc = [c for c in calls if "put-bucket-encryption" in c]
    assert enc and "KMSMasterKeyID" in enc[0] and "k1" in enc[0]
