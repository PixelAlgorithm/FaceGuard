"""Adapter contracts: KV (memory / sqlite / DynamoDB via moto), Rekognition request shapes (Stubber),
SES, metrics (EMF + PutMetricData), config validation."""

from __future__ import annotations

import io
import json
import time
from contextlib import redirect_stdout

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from cloud.app.config import ConfigError, settings_from_env
from cloud.app.metrics import Metrics
from cloud.app.services.adapters import SesMailer
from cloud.app.services.faces import FaceError, RekognitionFaces
from cloud.app.services.kv import DynamoKV, MemoryKV, SqliteKV
from cloud.tools.fakeimg import make_fake_jpeg

REGION = "us-east-1"


def _ddb_tables(client) -> None:
    for name in ("t_users", "t_decisions", "t_state"):
        client.create_table(TableName=name, BillingMode="PAY_PER_REQUEST",
                            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                                                  {"AttributeName": "sk", "AttributeType": "S"}],
                            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                                       {"AttributeName": "sk", "KeyType": "RANGE"}])


@pytest.fixture(params=["memory", "sqlite", "dynamodb"])
def kv(request, tmp_path, monkeypatch):
    if request.param == "memory":
        yield MemoryKV()
    elif request.param == "sqlite":
        yield SqliteKV(str(tmp_path / "kv.sqlite"))
    else:
        for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
            monkeypatch.setenv(k, "testing")
        monkeypatch.delenv("AWS_PROFILE", raising=False)
        with mock_aws():
            c = boto3.client("dynamodb", region_name=REGION)
            _ddb_tables(c)
            yield DynamoKV(c, users_table="t_users", decisions_table="t_decisions", state_table="t_state")


def test_kv_contract(kv):
    assert kv.get("decisions", "att_1") is None
    item = {"attempt_id": "att_1", "scores": {"pad": 0.93, "n": 3, "one": 1.0}, "codes": ["A", "B"], "none": None}
    assert kv.put_if_absent("decisions", "att_1", item) is True
    assert kv.put_if_absent("decisions", "att_1", {"other": True}) is False  # idempotency
    got = kv.get("decisions", "att_1")
    assert got["scores"] == {"pad": 0.93, "n": 3, "one": 1.0} and isinstance(got["scores"]["one"], float)
    assert got["codes"] == ["A", "B"] and got["none"] is None and got["_rev"] == 1
    assert kv.cas("decisions", "att_1", {**item, "v": 2}, expected_rev=99) is False
    assert kv.cas("decisions", "att_1", {**item, "v": 2}, expected_rev=1) is True
    assert kv.get("decisions", "att_1")["_rev"] == 2
    kv.put("state", "a#2", {"x": 2})
    kv.put("state", "a#1", {"x": 1})
    kv.put("state", "b#1", {"x": 3})
    assert [k for k, _ in kv.list("state", prefix="a#")] == ["a#1", "a#2"]
    kv.put("state", "expired", {"x": 0}, ttl=int(time.time()) - 5)
    assert kv.get("state", "expired") is None and "expired" not in [k for k, _ in kv.list("state")]
    assert kv.put_if_absent("state", "expired", {"x": 9}) is True  # expired == absent
    kv.delete("decisions", "att_1")
    assert kv.get("decisions", "att_1") is None
    kv.ping()


def test_dynamodb_item_layout_is_browsable(monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(k, "testing")
    with mock_aws():
        c = boto3.client("dynamodb", region_name=REGION)
        _ddb_tables(c)
        kv = DynamoKV(c, users_table="t_users", decisions_table="t_decisions", state_table="t_state")
        kv.put("decisions", "att_9", {"decision": "ALLOW", "mode": "OFFLINE"}, ttl=2_000_000_000)
        raw = c.get_item(TableName="t_decisions", Key={"pk": {"S": "decisions"}, "sk": {"S": "att_9"}})["Item"]
        assert raw["decision"] == {"S": "ALLOW"} and raw["ttl"] == {"N": "2000000000"}
        kv.put("users", "u_1", {"email": "a@b.co"})
        assert c.get_item(TableName="t_users", Key={"pk": {"S": "users"}, "sk": {"S": "u_1"}}).get("Item")


def test_sqlite_file_is_private(tmp_path):
    import os
    import stat

    p = tmp_path / "x.sqlite"
    SqliteKV(str(p)).put("users", "u", {"email": "a@b.co"})
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


# ---------------------------------------------------------------- Rekognition request shapes
def _rek():
    client = boto3.client("rekognition", region_name=REGION, aws_access_key_id="x", aws_secret_access_key="y")
    return client, Stubber(client)


def test_search_users_by_image_parameters_and_parsing():
    client, stub = _rek()
    img = make_fake_jpeg("u_3c4d")
    stub.add_response("search_users_by_image",
                      {"UserMatches": [{"Similarity": 97.1, "User": {"UserId": "u_b", "UserStatus": "ACTIVE"}},
                                       {"Similarity": 99.3, "User": {"UserId": "u_a", "UserStatus": "ACTIVE"}}],
                       "SearchedFace": {"FaceDetail": {"Confidence": 99.9}}},
                      {"CollectionId": "hid-kiosk-users", "Image": {"Bytes": img}, "UserMatchThreshold": 80.0,
                       "MaxUsers": 2, "QualityFilter": "AUTO"})
    with stub:
        res = RekognitionFaces(client, "hid-kiosk-users").search_users_by_image(img, 80, 2, "AUTO")
    assert [(m.user_id, m.similarity) for m in res.matches] == [("u_a", 99.3), ("u_b", 97.1)]
    assert res.face_detected


@pytest.mark.parametrize("code,msg,kind", [
    ("ThrottlingException", "slow down", "THROTTLED"),
    ("ProvisionedThroughputExceededException", "x", "THROTTLED"),
    ("ExpiredTokenException", "expired", "CREDS_EXPIRED"),
    ("AccessDeniedException", "SCP", "UNAVAILABLE"),
    ("ResourceNotFoundException", "no collection", "NOT_FOUND"),
    ("InvalidImageFormatException", "bad", "INVALID_IMAGE"),
])
def test_rekognition_error_mapping(code, msg, kind):
    client, stub = _rek()
    stub.add_client_error("search_users_by_image", service_error_code=code, service_message=msg)
    with stub, pytest.raises(FaceError) as ei:
        RekognitionFaces(client, "c").search_users_by_image(make_fake_jpeg("x"), 80, 2, "AUTO")
    assert ei.value.kind == kind


def test_no_face_is_not_an_error():
    client, stub = _rek()
    stub.add_client_error("search_users_by_image", service_error_code="InvalidParameterException",
                          service_message="There are no faces in the image. Should be at least 1.")
    with stub:
        res = RekognitionFaces(client, "c").search_users_by_image(make_fake_jpeg("x"), 80, 2, "AUTO")
    assert res.face_detected is False and res.matches == []


def test_enrolment_call_sequence_shapes():
    client, stub = _rek()
    img = make_fake_jpeg("u_1")
    stub.add_response("index_faces", {"FaceRecords": [{"Face": {"FaceId": "f-1"}}]},
                      {"CollectionId": "c", "Image": {"Bytes": img}, "ExternalImageId": "u_1", "MaxFaces": 1,
                       "QualityFilter": "AUTO", "DetectionAttributes": ["DEFAULT"]})
    stub.add_response("create_user", {}, {"CollectionId": "c", "UserId": "u_1", "ClientRequestToken": "tok-c"})
    stub.add_response("associate_faces", {"AssociatedFaces": [{"FaceId": "f-1"}]},
                      {"CollectionId": "c", "UserId": "u_1", "FaceIds": ["f-1"], "ClientRequestToken": "tok-a"})
    with stub:
        f = RekognitionFaces(client, "c")
        assert f.index_face(img, "u_1", "AUTO") == "f-1"
        f.create_user("u_1", "tok-c")
        assoc = f.associate_faces("u_1", ["f-1"], "tok-a")
        assert assoc.associated == ["f-1"] and assoc.unsuccessful == {}


def test_append_association_threshold_refusals_and_disassociate_shapes():
    """Append path: UserMatchThreshold is sent; LOW_MATCH_CONFIDENCE refusals are parsed; eviction uses
    DisassociateFaces (associated faces cannot be deleted directly)."""
    client, stub = _rek()
    stub.add_response("list_faces", {"Faces": [{"FaceId": "f-old"}]},
                      {"CollectionId": "c", "UserId": "u_1", "MaxResults": 100})
    stub.add_response("associate_faces", {
        "AssociatedFaces": [{"FaceId": "f-2"}],
        "UnsuccessfulFaceAssociations": [{"FaceId": "f-3", "UserId": "u_1", "Confidence": 41.0,
                                          "Reasons": ["LOW_MATCH_CONFIDENCE"]}],
        "UserStatus": "UPDATING"},
        {"CollectionId": "c", "UserId": "u_1", "FaceIds": ["f-2", "f-3"], "ClientRequestToken": "tok-a",
         "UserMatchThreshold": 80.0})
    stub.add_response("disassociate_faces", {"DisassociatedFaces": [{"FaceId": "f-old"}], "UserStatus": "UPDATING"},
                      {"CollectionId": "c", "UserId": "u_1", "FaceIds": ["f-old"], "ClientRequestToken": "tok-x"})
    with stub:
        f = RekognitionFaces(client, "c")
        assert f.list_user_faces("u_1") == ["f-old"]
        assoc = f.associate_faces("u_1", ["f-2", "f-3"], "tok-a", match_threshold=80)
        assert assoc.associated == ["f-2"] and assoc.unsuccessful == {"f-3": ["LOW_MATCH_CONFIDENCE"]}
        assert f.disassociate_faces("u_1", ["f-old"], "tok-x") == ["f-old"]
        assert f.disassociate_faces("u_1", [], "tok-y") == []  # no API call for an empty list


def test_create_user_conflict_is_idempotent_and_liveness_shapes():
    client, stub = _rek()
    stub.add_client_error("create_user", service_error_code="ConflictException")
    stub.add_response("create_face_liveness_session", {"SessionId": "11111111-1111-4111-8111-111111111111"},
                      {"Settings": {"AuditImagesLimit": 0,
                                    "ChallengePreferences": [{"Type": "FaceMovementAndLightChallenge"}]},
                       "ClientRequestToken": "att_1"})
    with stub:
        f = RekognitionFaces(client, "c")
        f.create_user("u_1", "t")
        sid = f.create_liveness_session(token="att_1", challenge="FaceMovementAndLightChallenge", s3_bucket=None,
                                        s3_prefix="liveness/att_1/", kms_key_id=None)
    assert sid.startswith("1111")


def test_ses_mailer_sends_via_sesv2():
    client = boto3.client("sesv2", region_name=REGION, aws_access_key_id="x", aws_secret_access_key="y")
    stub = Stubber(client)
    stub.add_response("send_email", {"MessageId": "m-1"}, {
        "FromEmailAddress": "kiosk@example.org", "Destination": {"ToAddresses": ["p@example.org"]},
        "Content": {"Simple": {"Subject": {"Data": "s", "Charset": "UTF-8"},
                               "Body": {"Text": {"Data": "b", "Charset": "UTF-8"}}}}})
    with stub:
        assert SesMailer(client, "kiosk@example.org").send("p@example.org", "s", "b") == "m-1"


# ---------------------------------------------------------------- metrics
def test_emf_stdout_format():
    m = Metrics("emf_stdout", "HIDKiosk")
    buf = io.StringIO()
    with redirect_stdout(buf):
        m.put("MatchLatencyMs", 412.0, Mode="1:N")
    rec = json.loads(buf.getvalue())
    cw = rec["_aws"]["CloudWatchMetrics"][0]
    assert cw["Namespace"] == "HIDKiosk" and cw["Metrics"] == [{"Name": "MatchLatencyMs", "Unit": "Milliseconds"}]
    assert rec["MatchLatencyMs"] == 412.0 and rec["Mode"] == "1:N" and sorted(cw["Dimensions"][0]) == ["Mode",
                                                                                                    "Service"]


def test_put_metric_data_batches_values_for_percentiles():
    client = boto3.client("cloudwatch", region_name=REGION, aws_access_key_id="x", aws_secret_access_key="y")
    stub = Stubber(client)
    stub.add_response("put_metric_data", {}, {"Namespace": "HIDKiosk", "MetricData": [{
        "MetricName": "RequestLatencyMs", "Dimensions": [{"Name": "Service", "Value": "hid-cloud"},
                                                         {"Name": "Route", "Value": "/v1/match"}],
        "Values": [400.0, 610.0], "Counts": [2.0, 1.0], "Unit": "Milliseconds"}]})
    m = Metrics("put_metric_data", "HIDKiosk", cw_client=client, flush_s=3600)
    for v in (400, 400, 610):
        m.put("RequestLatencyMs", v, Route="/v1/match")
    with stub:
        m.flush()
    assert m.last_error is None
    stub.assert_no_pending_responses()


# ---------------------------------------------------------------- config
def test_config_requires_secrets_and_defaults_to_us_east_1():
    with pytest.raises(ConfigError) as ei:
        settings_from_env({}, load_env_file=False)
    assert "KIOSK_HMAC_KEY" in str(ei.value) and "CLOUD_API_KEY" in str(ei.value)
    env = {"KIOSK_HMAC_KEY": "SECRET-K-123", "SCHEDULE_BUNDLE_HMAC_KEY": "SECRET-B-456",
           "CLOUD_API_KEY": "SECRET-A-789", "ADMIN_TOKEN": "SECRET-T-000", "AWS_REGION": "ap-south-1"}
    s = settings_from_env(env, load_env_file=False)
    assert s.region == "us-east-1"  # AWS_REGION deliberately ignored (sandbox = us-east-1)
    assert "SECRET-" not in repr(s)  # secrets never in repr / logs
    with pytest.raises(ConfigError):
        settings_from_env({**env, "DECISIONS_TTL_DAYS": "30"}, load_env_file=False)
    with pytest.raises(ConfigError):
        settings_from_env({**env, "EMAIL_BACKEND": "ses", "SES_SENDER": "you@example.com"}, load_env_file=False)
