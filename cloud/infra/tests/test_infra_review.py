"""Review findings CI-03 (alarm topic publishable by CloudWatch), CI-04 (shell variables never act as stack
state), CI-06 (teardown idempotent once the CMK is pending deletion), CI-08 (injective stack id), CI-09 (SSM tier
never downgraded)."""

# ruff: noqa: S603, S607, S105, S106, S108

from __future__ import annotations

import json

from .test_infra_deploy_ec2 import _apply_rules, _deploy

STAGING = "hid-kiosk-staging"
TOPIC = "arn:aws:sns:us-east-1:123456789012:hid-kiosk-security-alerts"
PROD_LEAK = {"KMS_KEY_ID": "1234abcd-prod-key", "BUCKET": "prod-audit-bucket", "INSTANCE_ID": "i-0prod0000",
             "API_ID": "prodapi1", "ALARM_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:prod-alerts",
             "ALARM_TOPIC_CREATED": "1", "SES_IDENTITY_PROD": "prod@example.org", "REC_ACCOUNT_ID": "999999999999"}


def _teardown_ok_rules(h):
    h.rule("get-apis", stdout="")
    h.not_found("lambda", "get-function")
    h.rule("describe-instances", stdout="")
    h.rule("describe-security-groups", stdout="")
    h.not_found("get-instance-profile", code="NoSuchEntity")
    h.not_found("get-role", code="NoSuchEntity")
    h.not_found("describe-table")
    h.not_found("head-bucket", code="404")
    h.not_found("describe-collection")
    h.not_found("ssm", "delete-parameter", code="ParameterNotFound")
    h.not_found("delete-dashboards", code="ResourceNotFound")
    h.not_found("logs", "delete-log-group")


# --------------------------------------------------------------------------- CI-03
def test_alarm_topic_not_encrypted_with_aws_managed_sns_key(h):
    h.rule("sns", "create-topic", stdout=TOPIC + "\n")
    r = h.run("data_plane.sh", "--apply", "--skip-rekognition", "--skip-dynamodb", "--skip-s3",
              "--alarm-email", "oncall@example.org")
    assert r.returncode == 0, r.stdout + r.stderr
    creates = [c for c in h.joined_calls() if "create-topic" in c]
    assert creates and not any("alias/aws/sns" in c for c in creates)


def test_alarm_topic_uses_stack_cmk_with_cloudwatch_grant(h):
    h.write_state({"KMS_KEY_ID": "k1"})
    policy = {"Version": "2012-10-17", "Statement": [
        {"Sid": "Root", "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
         "Action": "kms:*", "Resource": "*"}]}
    h.rule("kms", "get-key-policy", stdout=json.dumps(policy) + "\n")
    h.rule("sns", "create-topic", stdout=TOPIC + "\n")
    r = h.run("data_plane.sh", "--apply", "--skip-rekognition", "--skip-dynamodb", "--skip-s3",
              "--alarm-email", "oncall@example.org", HID_KEEP_RENDERED="1")
    assert r.returncode == 0, r.stdout + r.stderr
    calls = h.joined_calls()
    creates = [c for c in calls if "create-topic" in c]
    assert creates and "KmsMasterKeyId=k1" in creates[0] and "alias/aws/sns" not in creates[0]
    i_put = next(i for i, c in enumerate(calls) if "put-key-policy" in c)
    assert i_put < next(i for i, c in enumerate(calls) if "create-topic" in c)
    put = h.calls()[i_put]
    assert put[put.index("--key-id") + 1] == "k1"


def test_cmk_key_policy_grant_is_not_duplicated(h):
    h.write_state({"KMS_KEY_ID": "k1"})
    policy = {"Version": "2012-10-17", "Statement": [
        {"Sid": "AllowCloudWatchAlarmsToPublish", "Effect": "Allow",
         "Principal": {"Service": "cloudwatch.amazonaws.com"},
         "Action": ["kms:Decrypt", "kms:GenerateDataKey*"], "Resource": "*"}]}
    h.rule("kms", "get-key-policy", stdout=json.dumps(policy) + "\n")
    h.rule("sns", "create-topic", stdout=TOPIC + "\n")
    r = h.run("data_plane.sh", "--apply", "--skip-rekognition", "--skip-dynamodb", "--skip-s3",
              "--alarm-email", "oncall@example.org")
    assert r.returncode == 0, r.stdout + r.stderr
    assert not any("put-key-policy" in c for c in h.joined_calls())


def test_key_policy_merge_adds_cloudwatch_statement(h, tmp_path):
    src = tmp_path / "p.json"
    src.write_text(json.dumps({"Version": "2012-10-17", "Statement": [{"Sid": "Root", "Effect": "Allow"}]}))
    r = h.bash(f'cw_key_policy_merge "{src}"')
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert doc["Statement"][0]["Sid"] == "Root"
    cw = doc["Statement"][1]
    assert cw["Principal"] == {"Service": "cloudwatch.amazonaws.com"}
    assert set(cw["Action"]) == {"kms:Decrypt", "kms:GenerateDataKey*"}


def test_existing_topic_with_aws_managed_key_warns(h):
    h.rule("get-topic-attributes", stdout="alias/aws/sns\n")
    r = h.run("data_plane.sh", "--apply", "--skip-rekognition", "--skip-dynamodb", "--skip-s3",
              "--alarm-topic-arn", "arn:aws:sns:us-east-1:123456789012:ops-alerts")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "WARNING" in r.stderr and "alias/aws/sns" in r.stderr
    assert any("get-topic-attributes" in c and "ops-alerts" in c for c in h.joined_calls())


def test_existing_unencrypted_topic_does_not_warn(h):
    h.rule("get-topic-attributes", stdout="None\n")
    r = h.run("data_plane.sh", "--apply", "--skip-rekognition", "--skip-dynamodb", "--skip-s3",
              "--alarm-topic-arn", "arn:aws:sns:us-east-1:123456789012:ops-alerts")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "alias/aws/sns" not in r.stderr


# --------------------------------------------------------------------------- CI-04
def test_load_state_clears_inherited_state_variables(h):
    h.write_state({"INSTANCE_ID": "i-1"})
    r = h.bash('load_state; echo "[${KMS_KEY_ID:-}][${BUCKET:-}][${INSTANCE_ID:-}][${API_ID:-}]'
               '[${ALARM_TOPIC_ARN:-}][${SES_IDENTITY_PROD:-}][${REC_ACCOUNT_ID:-}]"', **PROD_LEAK)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "[][][i-1][][][][]"


def test_teardown_plan_ignores_inherited_state_variables(h):
    r = h.run("teardown.sh", HID_PREFIX=STAGING, **PROD_LEAK)
    assert r.returncode == 0, r.stdout + r.stderr
    out = r.stdout + r.stderr
    for value in ("prod-audit-bucket", "1234abcd-prod-key", "prod-alerts", "prod@example.org", "i-0prod0000"):
        assert value not in out
    assert f"s3://{STAGING}-123456789012-us-east-1" not in out  # PLAN: account placeholder, staging bucket
    assert f"s3://{STAGING}-<ACCOUNT_ID>-us-east-1" in out


def test_deploy_ec2_plan_ignores_inherited_state_variables(h):
    r = _deploy(h, "--demo", "--replace", HID_PREFIX=STAGING, **PROD_LEAK)
    assert r.returncode == 0, r.stdout + r.stderr
    out = r.stdout + r.stderr
    for value in ("prod-audit-bucket", "1234abcd-prod-key", "i-0prod0000", "prodapi1"):
        assert value not in out


# --------------------------------------------------------------------------- CI-06
def test_teardown_skips_cmk_already_pending_deletion(h):
    h.write_state({"KMS_KEY_ID": "k1"})
    _teardown_ok_rules(h)
    h.rule("kms", "describe-key", "KeyState", stdout="PendingDeletion\n")
    h.not_found("kms", "delete-alias", code="NotFoundException")
    r = h.run("teardown.sh", "--apply", "--confirm", "hid-kiosk")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "already pending deletion" in r.stdout
    assert not any("schedule-key-deletion" in c for c in h.joined_calls())


def test_teardown_schedules_enabled_cmk(h):
    h.write_state({"KMS_KEY_ID": "k1"})
    _teardown_ok_rules(h)
    h.rule("kms", "describe-key", "KeyState", stdout="Enabled\n")
    r = h.run("teardown.sh", "--apply", "--confirm", "hid-kiosk")
    assert r.returncode == 0, r.stdout + r.stderr
    assert any("schedule-key-deletion --key-id k1" in c for c in h.joined_calls())


def test_teardown_tolerates_invalid_state_on_schedule(h):
    h.write_state({"KMS_KEY_ID": "k1"})
    _teardown_ok_rules(h)
    h.rule("kms", "describe-key", "KeyState", stdout="Enabled\n")
    h.rule("schedule-key-deletion", rc=254,
           stderr="An error occurred (KMSInvalidStateException) when calling the ScheduleKeyDeletion operation")
    r = h.run("teardown.sh", "--apply", "--confirm", "hid-kiosk")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "already" in r.stdout


def test_teardown_absent_cmk_is_skipped(h):
    h.write_state({"KMS_KEY_ID": "k1"})
    _teardown_ok_rules(h)
    h.not_found("kms", "describe-key", code="NotFoundException")
    r = h.run("teardown.sh", "--apply", "--confirm", "hid-kiosk")
    assert r.returncode == 0, r.stdout + r.stderr
    assert not any("schedule-key-deletion" in c for c in h.joined_calls())


def test_teardown_cmk_describe_access_denied_aborts(h):
    h.write_state({"KMS_KEY_ID": "k1"})
    _teardown_ok_rules(h)
    h.rule("kms", "describe-key", rc=254, stderr="An error occurred (AccessDeniedException) when calling DescribeKey")
    r = h.run("teardown.sh", "--apply", "--confirm", "hid-kiosk")
    assert r.returncode != 0
    assert (h.state_dir / "deploy.env").exists()


# --------------------------------------------------------------------------- CI-08
def test_stack_id_is_injective_across_prefix_and_region(h):
    r = h.bash('echo "$STACK_ID $ROLE_EC2 $STATE_FILE"', HID_REGION="ap-south-1")
    assert r.returncode == 0, r.stderr
    stack, role, state_file = r.stdout.split()
    assert stack == "hid-kiosk--ap-south-1"
    r2 = h.bash('echo "$STACK_ID $ROLE_EC2 $STATE_FILE"', HID_PREFIX="hid-kiosk-ap-south-1")
    assert r2.returncode != 0 and "HID_PREFIX" in r2.stderr  # the colliding prefix is refused outright


def test_prefix_with_double_hyphen_refused(h):
    r = h.bash("echo ok", HID_PREFIX="hid--kiosk")
    assert r.returncode != 0 and "HID_PREFIX" in r.stderr


def test_ordinary_suffixed_prefixes_still_accepted(h):
    for prefix in ("hid-kiosk-staging", "hid-kiosk-staging-2", "hid-kiosk-eu"):
        r = h.bash('echo "$STACK_ID"', HID_PREFIX=prefix)
        assert r.returncode == 0 and r.stdout.strip() == prefix, (prefix, r.stderr)


def test_teardown_confirm_token_uses_injective_stack_id(h):
    r = h.run("teardown.sh", "--apply", "--confirm", "hid-kiosk-ap-south-1", HID_REGION="ap-south-1")
    assert r.returncode != 0
    assert "--confirm hid-kiosk--ap-south-1" in r.stderr


# --------------------------------------------------------------------------- CI-09
def test_ssm_tier_never_downgraded_from_advanced(h):
    h.rule("describe-parameters", "Tier", stdout="Advanced\n")
    _apply_rules(h)
    r = _deploy(h, "--demo", "--apply")
    assert r.returncode == 0, r.stdout + r.stderr
    puts = [c for c in h.joined_calls() if "put-parameter" in c]
    assert puts and all("--tier Advanced" in c and "--overwrite" in c for c in puts)


def test_ssm_small_env_on_standard_parameter_stays_standard(h):
    h.rule("describe-parameters", "Tier", stdout="Standard\n")
    _apply_rules(h)
    r = _deploy(h, "--demo", "--apply")
    assert r.returncode == 0, r.stdout + r.stderr
    puts = [c for c in h.joined_calls() if "put-parameter" in c]
    assert puts and all("--tier Standard" in c for c in puts)


# --------------------------------------------------------------------------- redaction wiring
def test_common_exports_secret_values_for_redaction(h):
    # only secret entries are value-masked; region / names stay readable in printed commands
    h.write_env(SES_SENDER="sender@example.org")
    r = h.bash('f="$(printenv HID_REDACT_VALUES_FILE)"; stat -f %Lp "$f"; cat "$f"; '
               'printf "aws --region us-east-1 KIOSK_HMAC_KEY: %s" "$(grep ^KIOSK_HMAC_KEY= "$f" | cut -d= -f2)" '
               '| redact')
    assert r.returncode == 0, r.stderr
    lines = r.stdout.splitlines()
    assert lines[0] == "600"
    assert "KIOSK_HMAC_KEY=" in r.stdout and "SES_SENDER" not in r.stdout
    assert lines[-1].startswith("aws --region us-east-1 KIOSK_HMAC_KEY: ***")
