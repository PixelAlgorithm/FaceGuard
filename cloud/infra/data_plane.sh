#!/usr/bin/env bash
# =============================================================================
# data_plane.sh - Rekognition collection, DynamoDB tables (on-demand, TTL), S3 bucket (SSE-KMS,
# lifecycle 1 day on every prefix, TLS-only, no public access), CloudWatch dashboard + alarm. Idempotent.
# =============================================================================
# Default = PLAN (prints commands, no AWS calls). --apply executes (lead approval required).
#   --skip-rekognition | --skip-dynamodb | --skip-s3 | --skip-cloudwatch   (for services the probe DENIED)
#   --with-cmk   create a customer-managed KMS key (HARD TO TEAR DOWN: >= 7-day deletion wait; ~$1/month)
# Encryption without --with-cmk: AWS-managed keys aws/s3 (SSE-KMS + bucket key) and aws/dynamodb.
# =============================================================================
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
parse_common_flags "$@"
SKIP_REK=0; SKIP_DDB=0; SKIP_S3=0; SKIP_CW=0; WITH_CMK=0
for a in "${REST[@]+"${REST[@]}"}"; do
  case "$a" in
    --skip-rekognition) SKIP_REK=1 ;; --skip-dynamodb) SKIP_DDB=1 ;; --skip-s3) SKIP_S3=1 ;;
    --skip-cloudwatch) SKIP_CW=1 ;; --with-cmk) WITH_CMK=1 ;;
    *) echo "unknown arg $a"; exit 2 ;;
  esac
done
banner "HID data plane"
ACCOUNT_ID="$(account_id)"; BUCKET="$(bucket_name)"
export HID_REGION HID_PREFIX ACCOUNT_ID BUCKET
TAGS_KV="Key=$HID_TAG_KEY,Value=$HID_TAG_VALUE Key=Owner,Value=cloud-aws"

if [[ $SKIP_REK -eq 0 ]]; then
  echo "[rekognition] collection $COLLECTION_ID (face/user vectors of consenting team members only)"
  if [[ $APPLY -eq 1 ]] && awsq rekognition describe-collection --collection-id "$COLLECTION_ID" >/dev/null 2>&1; then
    echo "  = exists"
  else
    run "create collection" -- rekognition create-collection --collection-id "$COLLECTION_ID" \
      --tags "$HID_TAG_KEY=$HID_TAG_VALUE,Owner=cloud-aws"
  fi
fi

if [[ $SKIP_DDB -eq 0 ]]; then
  for t in "$DDB_USERS" "$DDB_DECISIONS" "$DDB_STATE"; do
    echo "[dynamodb] table $t (pk/sk, on-demand, SSE aws/dynamodb, TTL=ttl)"
    if [[ $APPLY -eq 1 ]] && awsq dynamodb describe-table --table-name "$t" >/dev/null 2>&1; then
      echo "  = exists"
    else
      # shellcheck disable=SC2086
      run "create table $t" -- dynamodb create-table --table-name "$t" --billing-mode PAY_PER_REQUEST \
        --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
        --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE \
        --sse-specification Enabled=true,SSEType=KMS --tags $TAGS_KV
      run "wait $t active" -- dynamodb wait table-exists --table-name "$t"
    fi
    run_ok "enable TTL on $t" -- dynamodb update-time-to-live --table-name "$t" \
      --time-to-live-specification Enabled=true,AttributeName=ttl
  done
fi

if [[ $WITH_CMK -eq 1 ]]; then
  echo "[kms] customer-managed key alias/${HID_PREFIX} (deletion needs a 7-30 day waiting period)"
  if [[ $APPLY -eq 1 ]] && awsq kms describe-key --key-id "alias/${HID_PREFIX}" >/dev/null 2>&1; then
    echo "  = exists"
  else
    if [[ $APPLY -eq 1 ]]; then
      KEY_ID="$(awsq kms create-key --description 'HID kiosk demo data key' --tags "TagKey=$HID_TAG_KEY,TagValue=$HID_TAG_VALUE" --query KeyMetadata.KeyId --output text)"
      run "alias" -- kms create-alias --alias-name "alias/${HID_PREFIX}" --target-key-id "$KEY_ID"
      save_state KMS_KEY_ID "$KEY_ID"
    else
      run "create key" -- kms create-key --description "HID kiosk demo data key"
      run "alias" -- kms create-alias --alias-name "alias/${HID_PREFIX}" --target-key-id "<KEY_ID>"
    fi
  fi
fi

if [[ $SKIP_S3 -eq 0 ]]; then
  echo "[s3] bucket $BUCKET (SSE-KMS + bucket key, lifecycle 1 day on every prefix)"
  if [[ $APPLY -eq 1 ]] && awsq s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1; then
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
  run "default encryption SSE-KMS" -- s3api put-bucket-encryption --bucket "$BUCKET" \
    --server-side-encryption-configuration "file://$INFRA_DIR/templates/s3-encryption.json"
  run "lifecycle (1 day, every prefix)" -- s3api put-bucket-lifecycle-configuration --bucket "$BUCKET" \
    --lifecycle-configuration "file://$INFRA_DIR/templates/s3-lifecycle.json"
  POLICY_FILE="$(mktemp)"; render "$INFRA_DIR/templates/s3-tls-only-policy.json.tmpl" >"$POLICY_FILE"
  run "TLS-only + KMS-only bucket policy" -- s3api put-bucket-policy --bucket "$BUCKET" --policy "file://$POLICY_FILE"
  rm -f "$POLICY_FILE"
  run "tags" -- s3api put-bucket-tagging --bucket "$BUCKET" \
    --tagging "TagSet=[{Key=$HID_TAG_KEY,Value=$HID_TAG_VALUE},{Key=Owner,Value=cloud-aws}]"
  save_state BUCKET "$BUCKET"
fi

if [[ $SKIP_CW -eq 0 ]]; then
  echo "[cloudwatch] dashboard $DASHBOARD + alarm on post-hoc revoked offline ALLOWs"
  DASH_FILE="$(mktemp)"; render "$INFRA_DIR/templates/cloudwatch-dashboard.json.tmpl" >"$DASH_FILE"
  run "put dashboard" -- cloudwatch put-dashboard --dashboard-name "$DASHBOARD" --dashboard-body "file://$DASH_FILE"
  ALARM_FILE="$(mktemp)"; render "$INFRA_DIR/templates/cloudwatch-alarm-posthoc.json.tmpl" >"$ALARM_FILE"
  run "put alarm" -- cloudwatch put-metric-alarm --cli-input-json "file://$ALARM_FILE"
  rm -f "$DASH_FILE" "$ALARM_FILE"
fi

echo
echo "Data plane done. App settings for this account:"
echo "  REKOGNITION_COLLECTION_ID=$COLLECTION_ID DDB_TABLE_USERS=$DDB_USERS DDB_TABLE_DECISIONS=$DDB_DECISIONS"
echo "  DDB_TABLE_STATE=$DDB_STATE S3_AUDIT_BUCKET=$BUCKET CLOUD_AWS_REGION=$HID_REGION"
