#!/usr/bin/env bash
# =============================================================================
# deploy_ec2.sh - RECOMMENDED host: one warm t3.small (AL2023) running uvicorn under systemd, fronted by
# an API Gateway HTTP API (HTTPS) that proxies to it. See cloud/SANDBOX.md §6.
# =============================================================================
# Default = PLAN (prints commands, no AWS calls). --apply executes (lead approval required).
# Options:
#   --instance-profile NAME  use a PRE-PROVISIONED instance profile (no IAM writes)       [IAM blocked, option A]
#   --no-role                no instance profile: sqlite store, Rekognition/SES/S3 off      [IAM blocked, option B]
#   --face rekognition|disabled  --store dynamodb|sqlite  --email ses|disabled  (match probe results)
#   --no-apigw               skip API Gateway; then use --tls selfsigned (fingerprint pinned by the edge)
#   --tls none|selfsigned    default: none behind API Gateway, selfsigned with --no-apigw
#   --cidr CIDR              ingress to port 9000 (default 0.0.0.0/0: API Gateway has no fixed source IPs;
#                            every route except /v1/health requires the HMAC signature + API key)
#   --replace                blue-green: launch new, wait healthy, re-point API Gateway, verify, THEN terminate the
#                            previous instance (records CUTOVER_AT in .state for cloud.tools.backfill_metrics)
#   --skip-build             reuse cloud/infra/build/hid-cloud.tgz
#   --seed-schedule PATH     schedule seeded into an empty store (default config/schedule.demo.json)
#   --ses-sender EMAIL       verified SES sender (else .env SES_SENDER; placeholder -> EMAIL_BACKEND=disabled)
# Requires data_plane.sh first (the S3 bucket carries the artifact via presigned URLs).
# Secrets: SSM SecureString /hid-kiosk/app-env (aws/ssm key, standard tier) read at boot with the instance
# role; never in user-data, logs or stdout. (--no-role fallback: one-shot presigned SSE-KMS S3 object,
# deleted after the health check.) No AWS keys are ever written to the instance.
# =============================================================================
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
parse_common_flags "$@"
IP_NAME=""; NO_ROLE=0; FACE=rekognition; STORE=dynamodb; EMAIL=ses; USE_APIGW=1; TLS=""; CIDR="0.0.0.0/0"
REPLACE=0; SKIP_BUILD=0; SEED_SCHEDULE="config/schedule.demo.json"; SES_SENDER_ARG=""
set -- "${REST[@]+"${REST[@]}"}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --instance-profile) IP_NAME="$2"; shift ;;
    --no-role) NO_ROLE=1 ;;
    --face) FACE="$2"; shift ;; --store) STORE="$2"; shift ;; --email) EMAIL="$2"; shift ;;
    --no-apigw) USE_APIGW=0 ;;
    --tls) TLS="$2"; shift ;;
    --cidr) CIDR="$2"; shift ;;
    --replace) REPLACE=1 ;;
    --skip-build) SKIP_BUILD=1 ;;
    --seed-schedule) SEED_SCHEDULE="$2"; shift ;;
    --ses-sender) SES_SENDER_ARG="$2"; shift ;;
    *) echo "unknown arg $1"; exit 2 ;;
  esac
  shift
done
[[ -z "$TLS" ]] && TLS=$([[ $USE_APIGW -eq 1 ]] && echo none || echo selfsigned)
BLOB=s3; METRICS=put_metric_data
if [[ $NO_ROLE -eq 1 ]]; then FACE=disabled; STORE=sqlite; EMAIL=disabled; BLOB=disabled; METRICS=emf_stdout; fi
banner "HID cloud API on EC2 ($INSTANCE_TYPE) - face=$FACE store=$STORE email=$EMAIL tls=$TLS apigw=$USE_APIGW"
load_state
ACCOUNT_ID="$(account_id)"; BUCKET="$(bucket_name)"; STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SSM_PARAM="$SSM_PREFIX/app-env"
export HID_REGION HID_PREFIX ACCOUNT_ID BUCKET COLLECTION_ID DDB_USERS DDB_DECISIONS DDB_STATE LAMBDA_NAME SSM_PREFIX

if [[ $APPLY -eq 1 ]]; then
  awsq s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1 || { echo "bucket $BUCKET missing: run data_plane.sh --apply first"; exit 1; }
fi

echo "[1/9] build artifact (local)"
if [[ $SKIP_BUILD -eq 0 ]]; then "$INFRA_DIR/build_artifact.sh" | tail -2; fi
ART="$INFRA_DIR/build/hid-cloud.tgz"
[[ -f "$ART" ]] || { echo "missing $ART"; exit 1; }

echo "[2/9] upload artifact (presigned, code only) + app env (SSM SecureString)"
ENV_FILE="$(mktemp)"; chmod 600 "$ENV_FILE"
python3 "$INFRA_DIR/make_app_env.py" --out "$ENV_FILE" --format env --face "$FACE" --store "$STORE" --email "$EMAIL" \
  --blob "$BLOB" --metrics "$METRICS" --bucket "$([[ $BLOB == s3 ]] && echo "$BUCKET")" --region "$HID_REGION" \
  --collection "$COLLECTION_ID" --seed-schedule "$SEED_SCHEDULE" --ses-sender "$SES_SENDER_ARG" || exit 1
run "upload artifact" -- s3 cp "$ART" "s3://$BUCKET/deploy/$STAMP/hid-cloud.tgz" --sse aws:kms --only-show-errors
ENV_URL=""; SSM_ARG="$SSM_PARAM"
if [[ $NO_ROLE -eq 1 ]]; then
  SSM_ARG=""
  run "upload app env (no-role fallback)" -- s3 cp "$ENV_FILE" "s3://$BUCKET/deploy/$STAMP/app.env" --sse aws:kms --only-show-errors
fi
if [[ $NO_ROLE -eq 0 ]]; then
  if [[ $APPLY -eq 1 ]] && awsq ssm describe-parameters --parameter-filters "Key=Name,Values=$SSM_PARAM" \
      --query 'Parameters[0].Name' --output text 2>/dev/null | grep -q "$SSM_PARAM"; then
    run "update SSM SecureString $SSM_PARAM (value from mode-600 temp file, never printed)" -- ssm put-parameter \
      --name "$SSM_PARAM" --type SecureString --value "file://$ENV_FILE" --overwrite --tier Standard
  else
    run "create SSM SecureString $SSM_PARAM (aws/ssm key; value never printed)" -- ssm put-parameter \
      --name "$SSM_PARAM" --type SecureString --value "file://$ENV_FILE" --tier Standard \
      --tags "Key=$HID_TAG_KEY,Value=$HID_TAG_VALUE"
  fi
fi
rm -f "$ENV_FILE"
if [[ $APPLY -eq 1 ]]; then
  ART_URL="$(awsq s3 presign "s3://$BUCKET/deploy/$STAMP/hid-cloud.tgz" --expires-in 3600 | tr -d '"')"
  [[ -n "$ART_URL" ]] || { echo "presign failed"; exit 1; }
  if [[ $NO_ROLE -eq 1 ]]; then
    ENV_URL="$(awsq s3 presign "s3://$BUCKET/deploy/$STAMP/app.env" --expires-in 1800 | tr -d '"')"
  fi
else
  echo "    aws s3 presign s3://$BUCKET/deploy/$STAMP/hid-cloud.tgz --expires-in 3600"
  ART_URL="<presigned-artifact-url>"
fi

echo "[3/9] IAM instance profile"
PROFILE_ARG=()
if [[ $NO_ROLE -eq 1 ]]; then
  echo "  (no role: Rekognition/DynamoDB/SES/S3/CloudWatch unavailable from the instance)"
elif [[ -n "$IP_NAME" ]]; then
  echo "  using pre-provisioned instance profile $IP_NAME"
  PROFILE_ARG=(--iam-instance-profile "Name=$IP_NAME")
else
  POLICY_FILE="$(mktemp)"; render "$INFRA_DIR/templates/app-policy.json.tmpl" >"$POLICY_FILE"
  if [[ $APPLY -eq 1 ]] && awsq iam get-role --role-name "$ROLE_EC2" >/dev/null 2>&1; then
    echo "  = role $ROLE_EC2 exists"
  else
    run "create role" -- iam create-role --role-name "$ROLE_EC2" \
      --assume-role-policy-document "file://$INFRA_DIR/templates/ec2-trust.json" \
      --tags "Key=$HID_TAG_KEY,Value=$HID_TAG_VALUE"
  fi
  run "least-privilege inline policy" -- iam put-role-policy --role-name "$ROLE_EC2" --policy-name "$POLICY_NAME" \
    --policy-document "file://$POLICY_FILE"
  rm -f "$POLICY_FILE"
  if [[ $APPLY -eq 1 ]] && awsq iam get-instance-profile --instance-profile-name "$PROFILE_EC2" >/dev/null 2>&1; then
    echo "  = instance profile $PROFILE_EC2 exists"
  else
    run "create instance profile" -- iam create-instance-profile --instance-profile-name "$PROFILE_EC2"
    run_ok "attach role" -- iam add-role-to-instance-profile --instance-profile-name "$PROFILE_EC2" --role-name "$ROLE_EC2"
    [[ $APPLY -eq 1 ]] && sleep 12  # IAM propagation before RunInstances
  fi
  PROFILE_ARG=(--iam-instance-profile "Name=$PROFILE_EC2")
fi

echo "[4/9] security group $SG_NAME (tcp $APP_PORT from $CIDR)"
if [[ $APPLY -eq 1 ]]; then
  VPC_ID="$(awsq ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
  [[ "$VPC_ID" == "None" || -z "$VPC_ID" ]] && { echo "no default VPC in $HID_REGION"; exit 1; }
  SG_ID="$(awsq ec2 describe-security-groups --filters "Name=group-name,Values=$SG_NAME" "Name=vpc-id,Values=$VPC_ID" \
    --query 'SecurityGroups[0].GroupId' --output text)"
  if [[ "$SG_ID" == "None" || -z "$SG_ID" ]]; then
    SG_ID="$(awsq ec2 create-security-group --group-name "$SG_NAME" --description "HID kiosk cloud API" --vpc-id "$VPC_ID" \
      --tag-specifications "ResourceType=security-group,Tags=[{Key=$HID_TAG_KEY,Value=$HID_TAG_VALUE}]" \
      --query GroupId --output text)"
    echo "  + created $SG_ID"
  else
    echo "  = $SG_ID"
  fi
  save_state SG_ID "$SG_ID"
else
  run "create SG in default VPC" -- ec2 create-security-group --group-name "$SG_NAME" --description "HID kiosk cloud API" --vpc-id "<default-vpc>"
  SG_ID="<sg-id>"
fi
run_ok "ingress tcp/$APP_PORT" -- ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port "$APP_PORT" --cidr "$CIDR"

echo "[5/9] replace previous instance? ($REPLACE)  (blue-green: old one is terminated only after cutover)"
OLD_INSTANCE_ID=""; OLD_DNS=""
if [[ $REPLACE -eq 1 && -n "${INSTANCE_ID:-}" ]]; then
  OLD_INSTANCE_ID="$INSTANCE_ID"; OLD_DNS="${PUBLIC_DNS:-}"
  echo "  old instance $OLD_INSTANCE_ID keeps serving until API Gateway is re-pointed to the new one"
elif [[ $REPLACE -eq 0 && -n "${INSTANCE_ID:-}" && $APPLY -eq 1 ]]; then
  # a plain re-run would launch a second instance, overwrite INSTANCE_ID in .state and orphan the first
  CUR_STATE="$(awsq ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || echo unknown)"
  if [[ "$CUR_STATE" == running || "$CUR_STATE" == pending || "$CUR_STATE" == stopped || "$CUR_STATE" == stopping ]]; then
    echo "  ! instance $INSTANCE_ID is $CUR_STATE: refusing to launch another one." >&2
    echo "    use --replace (blue-green redeploy) or teardown.sh first." >&2
    exit 1
  fi
  echo "  previous instance $INSTANCE_ID is $CUR_STATE: launching a fresh one"
fi

echo "[6/9] launch $INSTANCE_TYPE (AL2023, IMDSv2 only)"
UD_FILE="$(mktemp)"
HID_ARTIFACT_URL="$ART_URL" HID_ENV_URL="$ENV_URL" HID_SSM_PARAM="$SSM_ARG" HID_TLS_MODE="$TLS" \
  HID_APP_PORT="$APP_PORT" render "$INFRA_DIR/templates/user_data.sh.tmpl" >"$UD_FILE"
if [[ $APPLY -eq 1 ]]; then
  AMI="$(awsq ssm get-parameters --names /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
    --query 'Parameters[0].Value' --output text)"
  INSTANCE_ID=""
  for attempt in 1 2 3; do
    INSTANCE_ID="$(awsq ec2 run-instances --image-id "$AMI" --instance-type "$INSTANCE_TYPE" --count 1 \
      --security-group-ids "$SG_ID" "${PROFILE_ARG[@]+"${PROFILE_ARG[@]}"}" --user-data "file://$UD_FILE" \
      --metadata-options HttpTokens=required,HttpEndpoint=enabled \
      --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$HID_PREFIX-api},{Key=$HID_TAG_KEY,Value=$HID_TAG_VALUE}]" \
      "ResourceType=volume,Tags=[{Key=$HID_TAG_KEY,Value=$HID_TAG_VALUE}]" \
      --query 'Instances[0].InstanceId' --output text)" && break
    echo "  run-instances failed (attempt $attempt; IAM propagation?) - retrying in 10 s"; sleep 10
  done
  rm -f "$UD_FILE"
  [[ -n "$INSTANCE_ID" ]] || { echo "launch failed"; exit 1; }
  save_state INSTANCE_ID "$INSTANCE_ID"
  awsq ec2 wait instance-running --instance-ids "$INSTANCE_ID"
  DNS="$(awsq ec2 describe-instances --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].PublicDnsName' --output text)"
  save_state PUBLIC_DNS "$DNS"
  echo "  instance $INSTANCE_ID  dns $DNS"
else
  run "launch" -- ec2 run-instances --image-id "<al2023-ami>" --instance-type "$INSTANCE_TYPE" --count 1 \
    --security-group-ids "$SG_ID" "${PROFILE_ARG[@]+"${PROFILE_ARG[@]}"}" --user-data "file://<rendered user_data>" \
    --metadata-options HttpTokens=required,HttpEndpoint=enabled --tag-specifications "ResourceType=instance,Tags=[...]"
  rm -f "$UD_FILE"
  DNS="<public-dns>"
fi

echo "[7/9] wait for /v1/health on the instance (boot ~2-3 min)"
SCHEME=$([[ "$TLS" == selfsigned ]] && echo https || echo http)
DIRECT_URL="$SCHEME://$DNS:$APP_PORT"
if [[ $APPLY -eq 1 ]]; then
  ok=0
  for _ in $(seq 1 72); do
    if curl -fsS -k --max-time 3 "$DIRECT_URL/v1/health" >/dev/null 2>&1; then ok=1; break; fi
    sleep 5
  done
  [[ $ok -eq 1 ]] && echo "  healthy: $DIRECT_URL/v1/health" || echo "  ! not healthy yet: check 'aws ec2 get-console-output --instance-id $INSTANCE_ID'"
  if [[ $ok -ne 1 ]]; then
    # health gate (unconditional): never point API Gateway at an instance that is not healthy
    if [[ -n "$OLD_INSTANCE_ID" ]]; then
      save_state INSTANCE_ID "$OLD_INSTANCE_ID"; [[ -n "$OLD_DNS" ]] && save_state PUBLIC_DNS "$OLD_DNS"
      save_state FAILED_INSTANCE_ID "$INSTANCE_ID"
      echo "  ! new instance $INSTANCE_ID unhealthy: API NOT re-pointed, $OLD_INSTANCE_ID still serving." >&2
    else
      echo "  ! instance $INSTANCE_ID unhealthy: API Gateway NOT (re-)pointed; instance kept for inspection." >&2
    fi
    echo "    inspect, then: aws ec2 terminate-instances --instance-ids $INSTANCE_ID" >&2
    exit 1
  fi
fi
[[ $NO_ROLE -eq 1 ]] && run_ok "delete one-shot app env object from S3" -- s3 rm "s3://$BUCKET/deploy/$STAMP/app.env" --only-show-errors

if [[ "$TLS" == selfsigned && $APPLY -eq 1 ]]; then
  echo "  TLS: pinning self-signed certificate"
  FP="$(awsq ec2 get-console-output --instance-id "$INSTANCE_ID" --latest --output text 2>/dev/null | sed -n 's/.*HID_TLS_FINGERPRINT_SHA256=\([0-9A-F:]*\).*/\1/p' | tail -1)"
  mkdir -p "$STATE_DIR"
  echo | openssl s_client -connect "$DNS:$APP_PORT" -servername "$DNS" 2>/dev/null | openssl x509 >"$STATE_DIR/cloud-cert.pem"
  GOT="$(openssl x509 -in "$STATE_DIR/cloud-cert.pem" -noout -fingerprint -sha256 | cut -d= -f2)"
  if [[ -n "$FP" && "$FP" == "$GOT" ]]; then echo "  pinned (fingerprint matches console): $STATE_DIR/cloud-cert.pem"
  else echo "  ! fingerprint not confirmed via console yet (console=$FP served=$GOT) - verify before trusting"; fi
fi

echo "[8/9] API Gateway HTTP API (HTTPS front)"
API_URL=""
if [[ $USE_APIGW -eq 1 ]]; then
  URI="http://$DNS:$APP_PORT/{proxy}"
  if [[ $APPLY -eq 1 ]]; then
    API_ID="$(awsq apigatewayv2 get-apis --query "Items[?Name=='$API_NAME'].ApiId | [0]" --output text)"
    if [[ "$API_ID" == "None" || -z "$API_ID" ]]; then
      API_ID="$(awsq apigatewayv2 create-api --name "$API_NAME" --protocol-type HTTP --tags "$HID_TAG_KEY=$HID_TAG_VALUE" --query ApiId --output text)"
      INT_ID="$(awsq apigatewayv2 create-integration --api-id "$API_ID" --integration-type HTTP_PROXY --integration-method ANY \
        --integration-uri "$URI" --payload-format-version 1.0 --query IntegrationId --output text)"
      awsq apigatewayv2 create-route --api-id "$API_ID" --route-key 'ANY /{proxy+}' --target "integrations/$INT_ID" >/dev/null
      awsq apigatewayv2 create-stage --api-id "$API_ID" --stage-name '$default' --auto-deploy >/dev/null
      echo "  + created API $API_ID"
    else
      INT_ID="$(awsq apigatewayv2 get-integrations --api-id "$API_ID" --query 'Items[0].IntegrationId' --output text)"
      awsq apigatewayv2 update-integration --api-id "$API_ID" --integration-id "$INT_ID" --integration-uri "$URI" >/dev/null
      echo "  = API $API_ID re-pointed to $DNS"
    fi
    API_URL="https://$API_ID.execute-api.$HID_REGION.amazonaws.com"
    save_state API_ID "$API_ID"
  else
    run "create HTTP API" -- apigatewayv2 create-api --name "$API_NAME" --protocol-type HTTP
    run "HTTP_PROXY integration" -- apigatewayv2 create-integration --api-id "<api-id>" --integration-type HTTP_PROXY \
      --integration-method ANY --integration-uri "$URI" --payload-format-version 1.0
    run "route ANY /{proxy+}" -- apigatewayv2 create-route --api-id "<api-id>" --route-key 'ANY /{proxy+}' --target "integrations/<int-id>"
    run "auto-deploy stage" -- apigatewayv2 create-stage --api-id "<api-id>" --stage-name '$default' --auto-deploy
    API_URL="https://<api-id>.execute-api.$HID_REGION.amazonaws.com"
  fi
fi

if [[ -n "$OLD_INSTANCE_ID" && $APPLY -eq 1 ]]; then
  echo "[8b] cutover check via ${API_URL:-$DIRECT_URL}/v1/health, then retire $OLD_INSTANCE_ID"
  cut_ok=0
  for _ in $(seq 1 24); do
    if curl -fsS --max-time 5 "${API_URL:-$DIRECT_URL}/v1/health" >/dev/null 2>&1; then cut_ok=1; break; fi
    sleep 5
  done
  if [[ $cut_ok -eq 1 ]]; then
    save_state CUTOVER_AT "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    run "terminate previous instance $OLD_INSTANCE_ID" -- ec2 terminate-instances --instance-ids "$OLD_INSTANCE_ID"
  else
    echo "  ! new instance not reachable through the API; previous instance $OLD_INSTANCE_ID left running" >&2
    if [[ -n "$OLD_DNS" && -n "${INT_ID:-}" ]]; then  # roll the integration back to the old instance
      awsq apigatewayv2 update-integration --api-id "$API_ID" --integration-id "$INT_ID" \
        --integration-uri "http://$OLD_DNS:$APP_PORT/{proxy}" >/dev/null \
        && echo "  rolled API $API_ID back to $OLD_DNS" >&2
      save_state INSTANCE_ID "$OLD_INSTANCE_ID"; save_state PUBLIC_DNS "$OLD_DNS"
    fi
    exit 1
  fi
fi

echo "[9/9] result"
FINAL_URL="${API_URL:-$DIRECT_URL}"
[[ $APPLY -eq 1 ]] && save_state CLOUD_API_URL "$FINAL_URL"
echo "  CLOUD_API_URL=$FINAL_URL"
[[ "$TLS" == selfsigned ]] && echo "  edge TLS pin: CLOUD_TLS_CA_FILE=$STATE_DIR/cloud-cert.pem"
echo "  verify: cloud/.venv/bin/python -m cloud.tools.smoke --base $FINAL_URL [--images DIR --probe JPG --cleanup]"
