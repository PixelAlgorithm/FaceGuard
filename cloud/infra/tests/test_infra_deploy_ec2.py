"""deploy_ec2.sh: CIT-02 (sqlite on replaceable instances), CIT-05 (demo seed only with --demo), CIT-07 (checked
API Gateway cutover), CIT-08 (ingress/throttling), CIT-10 (no secret URL in user-data, cleanup, encrypted root),
CIT-11 (TLS pin only on a confirmed fingerprint), CIT-16 (artifact hash checked on the instance)."""

# ruff: noqa: S603, S607, S105, S106, S108

from __future__ import annotations

import json

from .conftest import INFRA

STAMP = "20261115T000000Z"
NEW_URI = "http://new.dns:9000/{proxy}"


def _apply_rules(h, *, health_stamp: str | None = STAMP, api_stamp: str | None = STAMP,
                 integration_uri: str = NEW_URI, update_rc: int = 0, ingress: str = "0.0.0.0/0") -> None:
    h.rule("head-bucket", stdout="{}")
    h.rule("s3", "presign", stdout="https://bucket.s3.amazonaws.com/deploy/x?X-Amz-Signature=abc\n")
    h.rule("describe-parameters", "Parameters[0].Name", stdout="/hid-kiosk/app-env\n")
    h.rule("iam", "get-role", stdout="{}")
    h.rule("get-instance-profile", stdout="{}")
    h.rule("describe-vpcs", stdout="vpc-1\n")
    h.rule("describe-security-groups", "IpRanges", stdout=ingress + "\n")
    h.rule("describe-security-groups", stdout="sg-1\n")
    h.rule("ssm", "get-parameters", stdout="ami-1\n")
    h.rule("run-instances", stdout="i-0abc123\n")
    h.rule("describe-instances", "PublicDnsName", stdout="new.dns\n")
    h.rule("describe-instances", "State.Name", stdout="running\n")
    h.rule("get-apis", stdout="api1\n")
    h.rule("get-integrations", stdout="int1\n")
    throttled = "An error occurred (TooManyRequestsException)" if update_rc else ""
    h.rule("update-integration", rc=update_rc, stderr=throttled)
    h.rule("get-integration ", stdout=integration_uri + "\n")
    body = {"status": "ok"}
    if health_stamp:
        body["deploy_stamp"] = health_stamp
    h.rule("new.dns:9000/v1/health", tool="curl", stdout=json.dumps(body))
    api_body = {"status": "ok"}
    if api_stamp:
        api_body["deploy_stamp"] = api_stamp
    h.rule("execute-api", "/v1/health", tool="curl", stdout=json.dumps(api_body))


def _deploy(h, *args: str, **env: str):
    return h.run("deploy_ec2.sh", "--skip-build", *args, HID_DEPLOY_STAMP=STAMP, **env)


# --------------------------------------------------------------------------- CIT-02
def test_sqlite_store_refused_without_ephemeral_ok(h):
    r = _deploy(h, "--demo", "--store", "sqlite")
    assert r.returncode != 0
    assert "--ephemeral-ok" in r.stderr


def test_sqlite_store_allowed_with_ephemeral_ok(h):
    r = _deploy(h, "--demo", "--store", "sqlite", "--ephemeral-ok")
    assert r.returncode == 0, r.stdout + r.stderr


def test_unknown_backend_values_refused(h):
    for flag, val in (("--face", "fake"), ("--store", "memory"), ("--email", "fake"), ("--tls", "plain")):
        r = _deploy(h, "--demo", flag, val)
        assert r.returncode != 0, (flag, val)


# --------------------------------------------------------------------------- CIT-05
def test_seed_is_mandatory(h):
    r = _deploy(h)
    assert r.returncode != 0
    assert "--demo" in r.stderr and "--seed-schedule" in r.stderr


def test_demo_seed_refused_without_demo_flag(h):
    r = _deploy(h, "--seed-schedule", "config/schedule.demo.json")
    assert r.returncode != 0
    assert "demo" in r.stderr.lower()


def test_demo_flag_seeds_demo_schedule(h):
    r = _deploy(h, "--demo")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "config/schedule.demo.json" in r.stdout


# --------------------------------------------------------------------------- CIT-10
def test_no_role_secret_path_removed(h):
    r = _deploy(h, "--demo", "--no-role")
    assert r.returncode != 0
    assert "--instance-profile" in r.stderr


def test_user_data_template_has_no_env_url_and_checks_artifact_hash():
    tmpl = (INFRA / "templates" / "user_data.sh.tmpl").read_text()
    assert "HID_ENV_URL" not in tmpl
    assert "sha256sum" in tmpl and "${HID_ARTIFACT_SHA256}" in tmpl


def test_plan_encrypts_root_volume_and_cleans_leftover_env_objects(h):
    r = _deploy(h, "--demo")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "Encrypted=true" in r.stdout
    assert "--include '*/app.env'" in r.stdout or '--include */app.env' in r.stdout


def test_temp_files_removed_on_early_failure(h):
    h.rule("head-bucket", stdout="{}")
    h.rule("s3", "cp", rc=254, stderr="An error occurred (ExpiredToken)")
    r = _deploy(h, "--demo", "--apply")
    assert r.returncode != 0
    assert list((h.tmp / "tmpdir").iterdir()) == []


# --------------------------------------------------------------------------- CIT-07
def test_failed_reroute_never_terminates_old_instance(h):
    h.write_state({"INSTANCE_ID": "i-old", "PUBLIC_DNS": "old.dns", "ACCOUNT_ID": "123456789012"})
    _apply_rules(h, update_rc=254)
    r = _deploy(h, "--demo", "--apply", "--replace")
    assert r.returncode != 0
    assert not any("terminate-instances" in c and "i-old" in c for c in h.joined_calls())
    assert h.state()["INSTANCE_ID"] == "i-old"


def test_integration_uri_mismatch_never_terminates(h):
    h.write_state({"INSTANCE_ID": "i-old", "PUBLIC_DNS": "old.dns", "ACCOUNT_ID": "123456789012"})
    _apply_rules(h, integration_uri="http://old.dns:9000/{proxy}")
    r = _deploy(h, "--demo", "--apply", "--replace")
    assert r.returncode != 0
    assert not any("terminate-instances" in c for c in h.joined_calls())


def test_api_answered_by_old_backend_never_terminates(h):
    h.write_state({"INSTANCE_ID": "i-old", "PUBLIC_DNS": "old.dns", "ACCOUNT_ID": "123456789012"})
    _apply_rules(h, api_stamp="20200101T000000Z")
    r = _deploy(h, "--demo", "--apply", "--replace")
    assert r.returncode != 0
    assert not any("terminate-instances" in c for c in h.joined_calls())
    st = h.state()
    assert st["INSTANCE_ID"] == "i-old" and st["FAILED_INSTANCE_ID"] == "i-0abc123"  # CIT-M3: orphan recorded
    assert any("update-integration" in c and "old.dns" in c for c in h.joined_calls())  # rolled back


def test_large_app_env_uses_advanced_tier(h):
    # CIT-M4: SSM Standard SecureStrings cap at 4 KB; many per-kiosk keys / API keys exceed it
    import json as _json

    big = _json.dumps({f"KIOSK_{i:03d}": "k" * 60 for i in range(80)})
    h.write_env(KIOSK_KEYS_JSON=big)
    r = _deploy(h, "--demo")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "--tier Advanced" in r.stdout


def test_verified_cutover_terminates_old_instance(h):
    h.write_state({"INSTANCE_ID": "i-old", "PUBLIC_DNS": "old.dns", "ACCOUNT_ID": "123456789012"})
    _apply_rules(h)
    r = _deploy(h, "--demo", "--apply", "--replace")
    assert r.returncode == 0, r.stdout + r.stderr
    assert any("terminate-instances --instance-ids i-old" in c for c in h.joined_calls())
    st = h.state()
    assert st["INSTANCE_ID"] == "i-0abc123" and "CUTOVER_AT" in st
    assert st["ARTIFACT_SHA256"]


def test_failed_api_create_does_not_record_url(h):
    _apply_rules(h)
    h.rules = [r for r in h.rules if "get-apis" not in r["match"]]
    h.rules.insert(1, {"tool": "aws", "match": ["get-apis"], "rc": 0, "stdout": "None\n", "stderr": "", "once": False})
    h.rules.insert(1, {"tool": "aws", "match": ["create-integration"], "rc": 254, "stdout": "",
                       "stderr": "An error occurred (BadRequestException)", "once": False})
    h.rules_file.write_text(json.dumps(h.rules))
    h.rule("create-api", stdout="api9\n")
    r = _deploy(h, "--demo", "--apply")
    assert r.returncode != 0
    assert "CLOUD_API_URL" not in h.state()


# --------------------------------------------------------------------------- CIT-08
def test_stale_ingress_rules_revoked_and_stage_throttled(h):
    _apply_rules(h, ingress="0.0.0.0/0\t10.0.0.0/8")
    r = _deploy(h, "--demo", "--apply", "--cidr", "10.0.0.0/8")
    assert r.returncode == 0, r.stdout + r.stderr
    calls = h.joined_calls()
    assert any("revoke-security-group-ingress" in c and "0.0.0.0/0" in c for c in calls)
    assert not any("revoke-security-group-ingress" in c and "10.0.0.0/8" in c for c in calls)
    assert any("ThrottlingRateLimit" in c for c in calls if "stage" in c)


def test_invalid_cidr_refused(h):
    r = _deploy(h, "--demo", "--cidr", "10.0.0.0/8;reboot")
    assert r.returncode != 0


# --------------------------------------------------------------------------- CIT-11
def test_selfsigned_pin_written_only_on_confirmed_fingerprint(h):
    _apply_rules(h)
    h.rule("get-console-output", stdout="HID_TLS_FINGERPRINT_SHA256=AA:BB\n")
    h.rule("-fingerprint", tool="openssl", stdout="sha256 Fingerprint=CC:DD\n")
    r = _deploy(h, "--demo", "--apply", "--no-apigw", "--tls", "selfsigned", "--cidr", "203.0.113.0/24")
    assert r.returncode != 0
    assert not (h.state_dir / "cloud-cert.pem").exists()


def test_selfsigned_pin_kept_when_fingerprint_matches(h):
    _apply_rules(h)
    h.rule("get-console-output", stdout="HID_TLS_FINGERPRINT_SHA256=AA:BB\n")
    h.rule("-fingerprint", tool="openssl", stdout="sha256 Fingerprint=AA:BB\n")
    r = _deploy(h, "--demo", "--apply", "--no-apigw", "--tls", "selfsigned", "--cidr", "203.0.113.0/24")
    assert r.returncode == 0, r.stdout + r.stderr
    assert (h.state_dir / "cloud-cert.pem").exists()
