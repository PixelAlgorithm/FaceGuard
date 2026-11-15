#!/usr/bin/env bash
# =============================================================================
# data_plane.sh - Rekognition collection, DynamoDB tables (on-demand, TTL, deletion protection), S3 bucket
# (SSE-KMS, lifecycle 1 day on every prefix, TLS-only, no public access), CloudWatch dashboard + alarms
# (optionally wired to an SNS topic). Idempotent. Names derive from the stack (HID_PREFIX/HID_REGION) and
# are recorded in its state file (see common.sh).
# =============================================================================
# Default = PLAN (prints commands, no AWS calls). --apply executes (lead approval required).
#   --skip-rekognition | --skip-dynamodb | --skip-s3 | --skip-cloudwatch   (for services the probe DENIED)
#   --with-cmk   create (or reuse) a customer-managed KMS key and USE it for the tables, the bucket, the SSM
#                app env and the app's TOTP-seed box (HARD TO TEAR DOWN: >= 7-day deletion wait; ~$1/month)
#   --with-pitr  DynamoDB point-in-time recovery (note: AWS keeps a system backup for 35 days after a table
#                is deleted, so teardown is then not an immediate DPDP erasure)
#   --alarm-email ADDR      create an SNS topic subscribed by ADDR (owner confirms the AWS e-mail) and use it as
#                           AlarmActions/OKActions. Unencrypted (alarm payloads hold no personal data; alarms
#                           cannot publish to alias/aws/sns topics), or with the stack CMK when one exists
#   --alarm-topic-arn ARN   use an existing SNS topic instead (APPLY warns if it uses alias/aws/sns)
# Without a topic the alarms only turn red in the console: nobody is notified (a warning says so).
# Encryption without --with-cmk: AWS-managed keys aws/s3 (SSE-KMS + bucket key) and aws/dynamodb.
# =============================================================================
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
parse_common_flags "$@"
SKIP_REK=0; SKIP_DDB=0; SKIP_S3=0; SKIP_CW=0; WITH_CMK=0; WITH_PITR=0; ALARM_EMAIL=""; ALARM_TOPIC_ARG=""
set -- "${REST[@]+"${REST[@]}"}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-rekognition) SKIP_REK=1 ;; --skip-dynamodb) SKIP_DDB=1 ;; --skip-s3) SKIP_S3=1 ;;
    --skip-cloudwatch) SKIP_CW=1 ;; --with-cmk) WITH_CMK=1 ;; --with-pitr) WITH_PITR=1 ;;
    --alarm-email) ALARM_EMAIL="${2:-}"; shift ;;
    --alarm-topic-arn) ALARM_TOPIC_ARG="${2:-}"; shift ;;
    *) echo "unknown arg $1"; exit 2 ;;
  esac
  shift
done
[[ -z "$ALARM_EMAIL" || "$ALARM_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "bad --alarm-email"
[[ -z "$ALARM_TOPIC_ARG" || "$ALARM_TOPIC_ARG" =~ ^arn:aws:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]+$ ]] || die "bad --alarm-topic-arn"
banner "HID data plane"
init_stack
BUCKET="$(bucket_name "$ACCOUNT_ID")"
export HID_REGION HID_PREFIX ACCOUNT_ID BUCKET
TAGS_KV="Key=$HID_TAG_KEY,Value=$HID_TAG_VALUE Key=Owner,Value=cloud-aws"
record_stack "$ACCOUNT_ID"

if [[ $WITH_CMK -eq 1 ]]; then
  echo "[kms] customer-managed key alias/${HID_PREFIX} (deletion needs a 7-30 day waiting period)"
  if [[ -n "${KMS_KEY_ID:-}" ]]; then
    echo "  = recorded key $KMS_KEY_ID"
  elif [[ $APPLY -eq 1 ]] && probe kms describe-key --key-id "alias/${HID_PREFIX}"; then
    KMS_KEY_ID="$(awsq kms describe-key --key-id "alias/${HID_PREFIX}" --query KeyMetadata.KeyId --output text)" \
      || die "describe-key failed"
    save_state KMS_KEY_ID "$KMS_KEY_ID"
    echo "  = exists ($KMS_KEY_ID)"
  elif [[ $APPLY -eq 1 ]]; then
    KMS_KEY_ID="$(awsq kms create-key --description "HID kiosk data key ($STACK_ID)" \
      --tags "TagKey=$HID_TAG_KEY,TagValue=$HID_TAG_VALUE" --query KeyMetadata.KeyId --output text)" \
      || die "create-key failed: ${AWSQ_LAST_ERR:-}"
    [[ "$KMS_KEY_ID" =~ ^[0-9a-zA-Z-]+$ ]] || die "unexpected key id from create-key"
    save_state KMS_KEY_ID "$KMS_KEY_ID"
    run "alias" -- kms create-alias --alias-name "alias/${HID_PREFIX}" --target-key-id "$KMS_KEY_ID"
  else
    run "create key" -- kms create-key --description "HID kiosk data key ($STACK_ID)"
    KMS_KEY_ID="<KEY_ID>"
    run "alias" -- kms create-alias --alias-name "alias/${HID_PREFIX}" --target-key-id "$KMS_KEY_ID"
  fi
fi

if [[ $SKIP_REK -eq 0 ]]; then
  echo "[rekognition] collection $COLLECTION_ID (face/user vectors of consenting team members only)"
  if [[ $APPLY -eq 1 ]] && probe rekognition describe-collection --collection-id "$COLLECTION_ID"; then
    echo "  = exists"
  else
    run "create collection" -- rekognition create-collection --collection-id "$COLLECTION_ID" \
      --tags "$HID_TAG_KEY=$HID_TAG_VALUE,Owner=cloud-aws"
  fi
fi

if [[ $SKIP_DDB -eq 0 ]]; then
  SSE="Enabled=true,SSEType=KMS"
  [[ -n "${KMS_KEY_ID:-}" ]] && SSE="$SSE,KMSMasterKeyId=$KMS_KEY_ID"
  for t in "$DDB_USERS" "$DDB_DECISIONS" "$DDB_STATE"; do
    echo "[dynamodb] table $t (pk/sk, on-demand, SSE ${KMS_KEY_ID:+CMK }KMS, TTL=ttl, deletion protection)"
    if [[ $APPLY -eq 1 ]] && probe dynamodb describe-table --table-name "$t"; then
      echo "  = exists"
      run_ok "deletion protection on $t" -- dynamodb update-table --table-name "$t" --deletion-protection-enabled
      [[ -n "${KMS_KEY_ID:-}" ]] && run_ok "CMK encryption on $t" -- dynamodb update-table --table-name "$t" \
        --sse-specification "$SSE"
    else
      # shellcheck disable=SC2086
      run "create table $t" -- dynamodb create-table --table-name "$t" --billing-mode PAY_PER_REQUEST \
        --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
        --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE \
        --sse-specification "$SSE" --deletion-protection-enabled --tags $TAGS_KV
      run "wait $t active" -- dynamodb wait table-exists --table-name "$t"
    fi
    # TTL on `ttl` is load-bearing: decisions/alerts (7 d), OTPs and the request-replay cache expire by it
    run_ok "enable TTL on $t" -- dynamodb update-time-to-live --table-name "$t" \
      --time-to-live-specification Enabled=true,AttributeName=ttl
    if [[ $WITH_PITR -eq 1 ]]; then
      run "point-in-time recovery on $t" -- dynamodb update-continuous-backups --table-name "$t" \
        --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true
    fi
  done
fi

if [[ $SKIP_S3 -eq 0 ]]; then
  echo "[s3] bucket $BUCKET (SSE-KMS${KMS_KEY_ID:+ CMK} + bucket key, lifecycle 1 day on every prefix)"
  if [[ $APPLY -eq 1 ]] && probe s3api head-bucket --bucket "$BUCKET"; then
    echo "  = exists"
  else
    if [[ "$HID_REGION" == "us-east-1" ]]; then
      run "create bucket" -- s3api create-bucket --bucket "$BUCKET"
    else
      run "create bucket" -- s3api create-bucket --bucket "$BUCKET" \
        --create-bucket-configuration "LocationConstraint=$HID_REGION"
    fi
  fi
  run "block public access" -- s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  if [[ -n "${KMS_KEY_ID:-}" ]]; then
    ENC="{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\",\"KMSMasterKeyID\":\"$KMS_KEY_ID\"},\"BucketKeyEnabled\":true}]}"
    run "default encryption SSE-KMS (CMK)" -- s3api put-bucket-encryption --bucket "$BUCKET" \
      --server-side-encryption-configuration "$ENC"
  else
    run "default encryption SSE-KMS" -- s3api put-bucket-encryption --bucket "$BUCKET" \
      --server-side-encryption-configuration "file://$INFRA_DIR/templates/s3-encryption.json"
  fi
  run "lifecycle (1 day, every prefix)" -- s3api put-bucket-lifecycle-configuration --bucket "$BUCKET" \
    --lifecycle-configuration "file://$INFRA_DIR/templates/s3-lifecycle.json"
  mktemp_reg POLICY_FILE hid-policy; render_to "$INFRA_DIR/templates/s3-tls-only-policy.json.tmpl" "$POLICY_FILE"
  run "TLS-only + KMS-only bucket policy" -- s3api put-bucket-policy --bucket "$BUCKET" --policy "file://$POLICY_FILE"
  run "tags" -- s3api put-bucket-tagging --bucket "$BUCKET" \
    --tagging "TagSet=[{Key=$HID_TAG_KEY,Value=$HID_TAG_VALUE},{Key=Owner,Value=cloud-aws}]"
  save_state BUCKET "$BUCKET"
fi

if [[ $SKIP_CW -eq 0 ]]; then
  echo "[sns] security alert topic"
  TOPIC="${ALARM_TOPIC_ARG:-${ALARM_TOPIC_ARN:-}}"
  # CI-03: CloudWatch alarms cannot publish to a topic encrypted with the AWS-managed key alias/aws/sns (its
  # key policy cannot grant cloudwatch.amazonaws.com), so such a topic silently drops every alarm. The topic is
  # created UNENCRYPTED unless the stack has its own CMK (--with-cmk): alarm payloads carry no personal data,
  # only the alarm name, metric and threshold. With a CMK the key policy first gets a CloudWatch grant.
  TOPIC_ATTR=()
  if [[ -n "$ALARM_EMAIL" && -z "$TOPIC" && -n "${KMS_KEY_ID:-}" ]]; then
    echo "  topic encrypted with the stack CMK $KMS_KEY_ID; granting CloudWatch kms:Decrypt + kms:GenerateDataKey*"
    if [[ $APPLY -eq 1 ]]; then
      mktemp_reg KEYPOL_IN hid-keypol; mktemp_reg KEYPOL_OUT hid-keypol
      awsq kms get-key-policy --key-id "$KMS_KEY_ID" --policy-name default --query Policy --output text >"$KEYPOL_IN" \
        || die "kms get-key-policy failed: ${AWSQ_LAST_ERR:-}"
      rc=0; cw_key_policy_merge "$KEYPOL_IN" >"$KEYPOL_OUT" || rc=$?
      if [[ $rc -eq 10 ]]; then
        echo "  = key policy already grants CloudWatch"
      elif [[ $rc -eq 0 ]]; then
        run "key policy: allow CloudWatch alarms to publish to the encrypted topic" -- kms put-key-policy \
          --key-id "$KMS_KEY_ID" --policy-name default --policy "file://$KEYPOL_OUT"
      else
        die "could not merge the CloudWatch grant into the key policy of $KMS_KEY_ID (rc=$rc)"
      fi
    else
      run "read key policy" -- kms get-key-policy --key-id "$KMS_KEY_ID" --policy-name default --query Policy --output text
      run "key policy + statement $CW_KMS_SID (cloudwatch.amazonaws.com: kms:Decrypt, kms:GenerateDataKey*)" -- \
        kms put-key-policy --key-id "$KMS_KEY_ID" --policy-name default --policy "file://<merged-key-policy.json>"
    fi
    TOPIC_ATTR=(--attributes "KmsMasterKeyId=$KMS_KEY_ID")
  fi
  if [[ -n "$ALARM_EMAIL" && -z "$TOPIC" ]]; then
    if [[ $APPLY -eq 1 ]]; then
      TOPIC="$(awsq sns create-topic --name "$ALARM_TOPIC_NAME" "${TOPIC_ATTR[@]+"${TOPIC_ATTR[@]}"}" \
        --tags "Key=$HID_TAG_KEY,Value=$HID_TAG_VALUE" --query TopicArn --output text)" \
        || die "sns create-topic failed: ${AWSQ_LAST_ERR:-}"
      save_state ALARM_TOPIC_CREATED 1
    else
      run "create topic" -- sns create-topic --name "$ALARM_TOPIC_NAME" "${TOPIC_ATTR[@]+"${TOPIC_ATTR[@]}"}"
      TOPIC="arn:aws:sns:$HID_REGION:$ACCOUNT_ID:$ALARM_TOPIC_NAME"
    fi
  elif [[ -n "$TOPIC" && $APPLY -eq 1 ]]; then
    # an existing topic (--alarm-topic-arn, or one recorded by an earlier run) may use alias/aws/sns
    TOPIC_KEY="$(awsq sns get-topic-attributes --topic-arn "$TOPIC" --query Attributes.KmsMasterKeyId --output text)" \
      || die "sns get-topic-attributes $TOPIC failed: ${AWSQ_LAST_ERR:-}"
    if [[ "$TOPIC_KEY" == "alias/aws/sns" || "$TOPIC_KEY" == */alias/aws/sns ]]; then
      echo "  ! WARNING: topic $TOPIC is encrypted with alias/aws/sns: CloudWatch alarms CANNOT publish to it," \
        "nobody will be notified. Use an unencrypted topic or one encrypted with a CMK whose key policy allows" \
        "cloudwatch.amazonaws.com kms:Decrypt + kms:GenerateDataKey*." >&2
    fi
  fi
  if [[ -n "$ALARM_EMAIL" ]]; then
    run "subscribe $ALARM_EMAIL (owner must confirm the AWS e-mail)" -- sns subscribe --topic-arn "$TOPIC" \
      --protocol email --notification-endpoint "$ALARM_EMAIL"
  fi
  if [[ -n "$TOPIC" ]]; then
    save_state ALARM_TOPIC_ARN "$TOPIC"
    ALARM_ACTIONS_JSON="[\"$TOPIC\"]"
  else
    ALARM_ACTIONS_JSON="[]"
    echo "  ! WARNING: no SNS topic (--alarm-email / --alarm-topic-arn): alarms turn red in the console only," \
      "nobody is notified of a revoked user admitted offline." >&2
  fi
  echo "[cloudwatch] dashboard $DASHBOARD + alarms on SC2.6 sync alerts"
  mktemp_reg DASH_FILE hid-dash; render_to "$INFRA_DIR/templates/cloudwatch-dashboard.json.tmpl" "$DASH_FILE"
  run "put dashboard" -- cloudwatch put-dashboard --dashboard-name "$DASHBOARD" --dashboard-body "file://$DASH_FILE"
  for spec in $ALARM_SPECS; do
    ALARM_NAME="$HID_PREFIX-${spec%%|*}"; ALERT_NAME="${spec##*|}"
    export ALARM_NAME ALERT_NAME ALARM_ACTIONS_JSON
    mktemp_reg ALARM_FILE "hid-alarm-${spec%%|*}"; mv "$ALARM_FILE" "$ALARM_FILE.json"; ALARM_FILE="$ALARM_FILE.json"
    _TMP_FILES+=("$ALARM_FILE")
    render_to "$INFRA_DIR/templates/cloudwatch-alarm-posthoc.json.tmpl" "$ALARM_FILE"
    run "put alarm $ALARM_NAME ($ALERT_NAME)" -- cloudwatch put-metric-alarm --cli-input-json "file://$ALARM_FILE"
  done
fi

echo
echo "Data plane done. App settings for this stack:"
echo "  REKOGNITION_COLLECTION_ID=$COLLECTION_ID DDB_TABLE_USERS=$DDB_USERS DDB_TABLE_DECISIONS=$DDB_DECISIONS"
echo "  DDB_TABLE_STATE=$DDB_STATE S3_AUDIT_BUCKET=$BUCKET CLOUD_AWS_REGION=$HID_REGION${KMS_KEY_ID:+ KMS_KEY_ID=$KMS_KEY_ID}"
