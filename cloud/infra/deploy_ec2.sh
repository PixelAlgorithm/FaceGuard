#!/usr/bin/env bash
# =============================================================================
# deploy_ec2.sh - RECOMMENDED host: one warm t3.small (AL2023) running uvicorn under systemd, fronted by
# an API Gateway HTTP API (HTTPS) that proxies to it. See cloud/SANDBOX.md §6.
# =============================================================================
# Default = PLAN (prints commands, no AWS calls). --apply executes (lead approval required).
# Seed (mandatory, CIT-05):
#   --seed-schedule config/<file>.json   schedule seeded into an EMPTY store (must contain no demo cards)
#   --demo                               demo deployment: seeds config/schedule.demo.json (publicly documented
#                                        demo card ids become working CARD credentials - demo only)
# Options:
#   --instance-profile NAME  use a PRE-PROVISIONED instance profile (no IAM writes)       [IAM blocked]
#   --face rekognition|disabled  --store dynamodb|sqlite  --email ses|disabled  (match probe results)
#   --ephemeral-ok           required with --store sqlite: the sqlite file lives on the instance volume and is
#                            LOST on every replacement/relaunch (master schedule, revocation feed and ledger
#                            restart from the seed; edges keep a higher revocation cursor and bundle version, so
#                            later revocations/erasures do not reach them) - CIT-02
#   --no-apigw               skip API Gateway; then use --tls selfsigned (fingerprint pinned by the edge)
#   --tls none|selfsigned    default: none behind API Gateway, selfsigned with --no-apigw
#   --cidr CIDR              ingress to port 9000 (default 0.0.0.0/0: API Gateway has no fixed source IPs;
#                            every route except /v1/health requires the HMAC signature + API key). Rules for
#                            other CIDRs on that port are REVOKED on every run (CIT-08)
#   --replace                blue-green: launch new, wait healthy, re-point API Gateway, verify the new backend
#                            answers through the API, THEN terminate the previous instance (records CUTOVER_AT)
#   --skip-build             reuse the built artifact (cloud/infra/build/hid-cloud.tgz)
#   --ses-sender EMAIL       verified SES sender (else .env SES_SENDER; placeholder -> EMAIL_BACKEND=disabled)
#   --no-role                REMOVED (it shipped a presigned app.env URL in user-data, CIT-10): use
#                            --instance-profile NAME, or host the cloud on the laptop (SANDBOX.md §6)
# Requires data_plane.sh first (the S3 bucket carries the artifact via a presigned URL).
# Secrets: SSM SecureString /<prefix>/app-env (CMK when data_plane.sh --with-cmk was used, else aws/ssm) read at
# boot with the instance role; never in user-data, logs or stdout. No AWS keys are ever written to the instance.
# The root EBS volume is encrypted; the artifact's SHA-256 is verified on the instance before extraction.
# =============================================================================
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
parse_common_flags "$@"
IP_NAME=""; FACE=rekognition; STORE=dynamodb; EMAIL=ses; USE_APIGW=1; TLS=""; CIDR="0.0.0.0/0"
REPLACE=0; SKIP_BUILD=0; SEED_SCHEDULE=""; DEMO=0; EPHEMERAL_OK=0; SES_SENDER_ARG=""
CUTOVER_POLLS=24; CUTOVER_CONSECUTIVE=3; HEALTH_POLLS=72; TLS_PIN_POLLS=12
SSM_STANDARD_MAX_BYTES=4096; SSM_ADVANCED_MAX_BYTES=8192
NIL_KEY_ARN_SUFFIX="key/00000000-0000-0000-0000-000000000000"  # matches no key: no CMK -> no kms:* grant
set -- "${REST[@]+"${REST[@]}"}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --instance-profile) IP_NAME="${2:-}"; shift ;;
    --no-role) die "--no-role was removed (it put a presigned URL to every app secret into EC2 user-data). Use --instance-profile NAME (pre-provisioned) or laptop hosting (cloud/SANDBOX.md §6)." ;;
    --face) FACE="${2:-}"; shift ;; --store) STORE="${2:-}"; shift ;; --email) EMAIL="${2:-}"; shift ;;
    --no-apigw) USE_APIGW=0 ;;
    --tls) TLS="${2:-}"; shift ;;
    --cidr) CIDR="${2:-}"; shift ;;
    --replace) REPLACE=1 ;;
    --skip-build) SKIP_BUILD=1 ;;
    --seed-schedule) SEED_SCHEDULE="${2:-}"; shift ;;
    --demo) DEMO=1 ;;
    --ephemeral-ok) EPHEMERAL_OK=1 ;;
    --ses-sender) SES_SENDER_ARG="${2:-}"; shift ;;
    *) echo "unknown arg $1"; exit 2 ;;
  esac
  shift
done
case "$FACE" in rekognition|disabled) ;; *) die "--face must be rekognition|disabled (test backends are never deployed)" ;; esac
case "$STORE" in dynamodb|sqlite) ;; *) die "--store must be dynamodb|sqlite" ;; esac
case "$EMAIL" in ses|disabled) ;; *) die "--email must be ses|disabled" ;; esac
[[ -z "$TLS" ]] && TLS=$([[ $USE_APIGW -eq 1 ]] && echo none || echo selfsigned)
case "$TLS" in none|selfsigned) ;; *) die "--tls must be none|selfsigned" ;; esac
[[ "$CIDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] || die "--cidr must be an IPv4 CIDR like 203.0.113.0/24"
[[ -z "$IP_NAME" || "$IP_NAME" =~ ^[A-Za-z0-9+=,.@_-]{1,128}$ ]] || die "bad --instance-profile name"
[[ -z "$SES_SENDER_ARG" || "$SES_SENDER_ARG" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "bad --ses-sender"
if [[ -z "$SEED_SCHEDULE" ]]; then
  [[ $DEMO -eq 1 ]] || die "a seed is required: --seed-schedule config/<file>.json (production data), or --demo (seeds config/schedule.demo.json with publicly documented demo cards)"
  SEED_SCHEDULE="config/schedule.demo.json"
fi
if [[ "$STORE" == sqlite && $EPHEMERAL_OK -eq 0 ]]; then
  die "--store sqlite keeps the master schedule, revocation feed and ledger on the instance volume: every --replace or relaunch loses them and kiosks stop receiving revocations. Use --store dynamodb, or pass --ephemeral-ok for a throwaway demo."
fi
STAMP="${HID_DEPLOY_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
[[ "$STAMP" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || die "bad deploy stamp"
BLOB=s3; METRICS=put_metric_data
banner "HID cloud API on EC2 ($INSTANCE_TYPE) - face=$FACE store=$STORE email=$EMAIL tls=$TLS apigw=$USE_APIGW seed=$SEED_SCHEDULE"
[[ "$STORE" == sqlite ]] && echo "  ! WARNING: sqlite store is EPHEMERAL (--ephemeral-ok): replacing this instance resets all cloud state." >&2
[[ $DEMO -eq 1 ]] && echo "  ! DEMO deployment: documented demo card ids are valid credentials for the demo users." >&2
if [[ "$CIDR" == "0.0.0.0/0" && $USE_APIGW -eq 0 ]]; then
  echo "  ! WARNING: --no-apigw with --cidr 0.0.0.0/0 exposes port $APP_PORT to the internet without a gateway throttle; pass --cidr <your egress>/32." >&2
fi
init_stack
BUCKET="$(bucket_name "$ACCOUNT_ID")"
SSM_PARAM="$SSM_PREFIX/app-env"
record_stack "$ACCOUNT_ID"
save_state DEPLOY_STAMP "$STAMP"
if [[ -n "${KMS_KEY_ID:-}" ]]; then KMS_KEY_ARN="arn:aws:kms:$HID_REGION:$ACCOUNT_ID:key/$KMS_KEY_ID"
else KMS_KEY_ARN="arn:aws:kms:$HID_REGION:$ACCOUNT_ID:$NIL_KEY_ARN_SUFFIX"; fi
SES_FROM="$("$HID_PY" "$INFRA_DIR/make_app_env.py" --resolve-sender --ses-sender "$SES_SENDER_ARG" --env-file "$ENV_FILE_SRC")" || exit 1
[[ "$EMAIL" == ses && -n "$SES_FROM" ]] && SES_FROM_ADDRESS="$SES_FROM" || SES_FROM_ADDRESS="no-sender@invalid"
export HID_REGION HID_PREFIX ACCOUNT_ID BUCKET COLLECTION_ID DDB_USERS DDB_DECISIONS DDB_STATE LAMBDA_NAME SSM_PREFIX \
  SES_FROM_ADDRESS KMS_KEY_ARN

if [[ $APPLY -eq 1 ]]; then
  probe s3api head-bucket --bucket "$BUCKET" || die "bucket $BUCKET missing: run data_plane.sh --apply first"
fi

echo "[1/9] build artifact (local)"
if [[ $SKIP_BUILD -eq 0 ]]; then "$INFRA_DIR/build_artifact.sh" | tail -3 || die "artifact build failed"; fi
ART="$BUILD_DIR/hid-cloud.tgz"
[[ -f "$ART" ]] || die "missing $ART"
ART_SHA="$(shasum -a 256 "$ART" | cut -d' ' -f1)"
save_state ARTIFACT_SHA256 "$ART_SHA"
echo "  artifact sha256 $ART_SHA (verified on the instance before extraction)"

echo "[2/9] upload artifact (presigned, code only) + app env (SSM SecureString)"
mktemp_reg ENV_FILE hid-appenv
DEMO_ARG=(); [[ $DEMO -eq 1 ]] && DEMO_ARG=(--demo)
"$HID_PY" "$INFRA_DIR/make_app_env.py" --env-file "$ENV_FILE_SRC" --out "$ENV_FILE" --format env --face "$FACE" \
  --store "$STORE" --email "$EMAIL" --blob "$BLOB" --metrics "$METRICS" --bucket "$BUCKET" --region "$HID_REGION" \
  --collection "$COLLECTION_ID" --ddb-users "$DDB_USERS" --ddb-decisions "$DDB_DECISIONS" --ddb-state "$DDB_STATE" \
  --kms-key-id "${KMS_KEY_ID:-}" --deploy-stamp "$STAMP" --seed-schedule "$SEED_SCHEDULE" \
  --ses-sender "$SES_SENDER_ARG" "${DEMO_ARG[@]+"${DEMO_ARG[@]}"}" || exit 1
run "upload artifact" -- s3 cp "$ART" "s3://$BUCKET/deploy/$STAMP/hid-cloud.tgz" --sse aws:kms --only-show-errors
# leftovers of the removed --no-role path (one-shot app.env objects holding every secret)
run_ok "remove leftover one-shot app env objects" -- s3 rm "s3://$BUCKET/deploy/" --recursive --exclude '*' \
  --include '*/app.env' --only-show-errors
KEY_ARG=(); [[ -n "${KMS_KEY_ID:-}" ]] && KEY_ARG=(--key-id "$KMS_KEY_ID")
# SSM SecureString size limits (CIT-M4): Standard 4 KB, Advanced 8 KB (~$0.05/month per parameter)
ENV_BYTES="$(wc -c <"$ENV_FILE" | tr -d ' ')"
SSM_TIER=Standard
if [[ "$ENV_BYTES" -gt "$SSM_STANDARD_MAX_BYTES" ]]; then
  [[ "$ENV_BYTES" -le "$SSM_ADVANCED_MAX_BYTES" ]] || die "app env is $ENV_BYTES bytes (> $SSM_ADVANCED_MAX_BYTES, the SSM limit): move KIOSK_KEYS_JSON / CLOUD_API_KEYS_JSON to Secrets Manager"
  SSM_TIER=Advanced
  echo "  app env is $ENV_BYTES bytes (> $SSM_STANDARD_MAX_BYTES): using the SSM Advanced tier"
fi
SSM_EXISTS=0
if [[ $APPLY -eq 1 ]] && awsq ssm describe-parameters --parameter-filters "Key=Name,Values=$SSM_PARAM" \
    --query 'Parameters[0].Name' --output text | grep -qx "$SSM_PARAM"; then
  SSM_EXISTS=1
  # CI-09: SSM cannot downgrade an Advanced parameter (put-parameter --overwrite --tier Standard is rejected),
  # so a smaller env on a parameter that once needed Advanced keeps Advanced
  CUR_TIER="$(awsq ssm describe-parameters --parameter-filters "Key=Name,Values=$SSM_PARAM" \
    --query 'Parameters[0].Tier' --output text)" || die "ssm describe-parameters (tier) failed: ${AWSQ_LAST_ERR:-}"
  if [[ "$CUR_TIER" == Advanced && "$SSM_TIER" != Advanced ]]; then
    SSM_TIER=Advanced
    echo "  $SSM_PARAM is already an Advanced parameter (SSM cannot downgrade it): keeping the Advanced tier"
  fi
fi
if [[ $SSM_EXISTS -eq 1 ]]; then
  run "update SSM SecureString $SSM_PARAM (value from mode-600 temp file, never printed)" -- ssm put-parameter \
    --name "$SSM_PARAM" --type SecureString --value "file://$ENV_FILE" --overwrite --tier "$SSM_TIER" \
    "${KEY_ARG[@]+"${KEY_ARG[@]}"}"
else
  run "create SSM SecureString $SSM_PARAM (value never printed)" -- ssm put-parameter \
    --name "$SSM_PARAM" --type SecureString --value "file://$ENV_FILE" --tier "$SSM_TIER" \
    --tags "Key=$HID_TAG_KEY,Value=$HID_TAG_VALUE" "${KEY_ARG[@]+"${KEY_ARG[@]}"}"
fi
rm -f "$ENV_FILE"
if [[ $APPLY -eq 1 ]]; then
  ART_URL="$(awsq s3 presign "s3://$BUCKET/deploy/$STAMP/hid-cloud.tgz" --expires-in 3600 | tr -d '"')"
  [[ "$ART_URL" == https://* ]] || die "presign failed"
else
  echo "    aws s3 presign s3://$BUCKET/deploy/$STAMP/hid-cloud.tgz --expires-in 3600"
  ART_URL="<presigned-artifact-url>"
fi

echo "[3/9] IAM instance profile"
if [[ -n "$IP_NAME" ]]; then
  echo "  using pre-provisioned instance profile $IP_NAME"
  PROFILE_ARG=(--iam-instance-profile "Name=$IP_NAME")
else
  mktemp_reg POLICY_FILE hid-policy; render_to "$INFRA_DIR/templates/app-policy.json.tmpl" "$POLICY_FILE"
  if [[ $APPLY -eq 1 ]] && probe iam get-role --role-name "$ROLE_EC2"; then
    echo "  = role $ROLE_EC2 exists"
  else
    run "create role" -- iam create-role --role-name "$ROLE_EC2" \
      --assume-role-policy-document "file://$INFRA_DIR/templates/ec2-trust.json" \
      --tags "Key=$HID_TAG_KEY,Value=$HID_TAG_VALUE"
  fi
  run "least-privilege inline policy" -- iam put-role-policy --role-name "$ROLE_EC2" --policy-name "$POLICY_NAME" \
    --policy-document "file://$POLICY_FILE"
  if [[ $APPLY -eq 1 ]] && probe iam get-instance-profile --instance-profile-name "$PROFILE_EC2"; then
    echo "  = instance profile $PROFILE_EC2 exists"
  else
    run "create instance profile" -- iam create-instance-profile --instance-profile-name "$PROFILE_EC2"
    run_ok "attach role" -- iam add-role-to-instance-profile --instance-profile-name "$PROFILE_EC2" --role-name "$ROLE_EC2"
    [[ $APPLY -eq 1 ]] && sleep 12  # IAM propagation before RunInstances
  fi
  PROFILE_ARG=(--iam-instance-profile "Name=$PROFILE_EC2")
fi

echo "[4/9] security group $SG_NAME (tcp $APP_PORT from $CIDR only)"
if [[ $APPLY -eq 1 ]]; then
  VPC_ID="$(awsq ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
  [[ "$VPC_ID" == "None" || -z "$VPC_ID" ]] && die "no default VPC in $HID_REGION"
  SG_ID="$(awsq ec2 describe-security-groups --filters "Name=group-name,Values=$SG_NAME" "Name=vpc-id,Values=$VPC_ID" \
    --query 'SecurityGroups[0].GroupId' --output text)" || die "describe-security-groups failed"
  if [[ "$SG_ID" == "None" || -z "$SG_ID" ]]; then
    SG_ID="$(awsq ec2 create-security-group --group-name "$SG_NAME" --description "HID kiosk cloud API" --vpc-id "$VPC_ID" \
      --tag-specifications "ResourceType=security-group,Tags=[{Key=$HID_TAG_KEY,Value=$HID_TAG_VALUE}]" \
      --query GroupId --output text)" || die "create-security-group failed"
    echo "  + created $SG_ID"
  else
    echo "  = $SG_ID"
  fi
  save_state SG_ID "$SG_ID"
else
  run "create SG in default VPC" -- ec2 create-security-group --group-name "$SG_NAME" --description "HID kiosk cloud API" --vpc-id "<default-vpc>"
  SG_ID="<sg-id>"
fi
run_ok "ingress tcp/$APP_PORT from $CIDR" -- ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port "$APP_PORT" --cidr "$CIDR"
if [[ $APPLY -eq 1 ]]; then
  CUR_CIDRS="$(awsq ec2 describe-security-groups --group-ids "$SG_ID" \
    --query "SecurityGroups[0].IpPermissions[?FromPort==\`$APP_PORT\`].IpRanges[].CidrIp" --output text)" \
    || die "could not list ingress rules of $SG_ID"
  for c in $CUR_CIDRS; do
    [[ "$c" == "$CIDR" || "$c" == None ]] && continue
    run "revoke stale ingress tcp/$APP_PORT from $c" -- ec2 revoke-security-group-ingress --group-id "$SG_ID" \
      --protocol tcp --port "$APP_PORT" --cidr "$c"
  done
else
  echo "  (apply: every other CIDR on tcp/$APP_PORT is revoked)"
fi

echo "[5/9] replace previous instance? ($REPLACE)  (blue-green: old one is terminated only after a verified cutover)"
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

abort_cutover() {
  # keep the previous instance recorded as the serving one; the new one is kept for inspection
  echo "  ! $1" >&2
  if [[ -n "$OLD_INSTANCE_ID" ]]; then
    save_state INSTANCE_ID "$OLD_INSTANCE_ID"; [[ -n "$OLD_DNS" ]] && save_state PUBLIC_DNS "$OLD_DNS"
    save_state FAILED_INSTANCE_ID "$INSTANCE_ID"
    echo "    previous instance $OLD_INSTANCE_ID was NOT terminated." >&2
  fi
  echo "    inspect, then: aws ec2 terminate-instances --instance-ids $INSTANCE_ID" >&2
  exit 1
}

echo "[6/9] launch $INSTANCE_TYPE (AL2023, IMDSv2 only, encrypted gp3 root volume)"
mktemp_reg UD_FILE hid-userdata
HID_ARTIFACT_URL="$ART_URL" HID_ARTIFACT_SHA256="$ART_SHA" HID_SSM_PARAM="$SSM_PARAM" HID_TLS_MODE="$TLS" \
  HID_APP_PORT="$APP_PORT" HID_TLS_CERT_DAYS="$TLS_CERT_DAYS" render_to "$INFRA_DIR/templates/user_data.sh.tmpl" "$UD_FILE"
BDM='DeviceName=/dev/xvda,Ebs={Encrypted=true,VolumeType=gp3,DeleteOnTermination=true}'
if [[ $APPLY -eq 1 ]]; then
  AMI="$(awsq ssm get-parameters --names /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
    --query 'Parameters[0].Value' --output text)" || die "AMI lookup failed"
  INSTANCE_ID=""
  for attempt in 1 2 3; do
    INSTANCE_ID="$(awsq ec2 run-instances --image-id "$AMI" --instance-type "$INSTANCE_TYPE" --count 1 \
      --security-group-ids "$SG_ID" "${PROFILE_ARG[@]}" --user-data "file://$UD_FILE" \
      --block-device-mappings "$BDM" --metadata-options HttpTokens=required,HttpEndpoint=enabled \
      --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$HID_PREFIX-api},{Key=$HID_TAG_KEY,Value=$HID_TAG_VALUE}]" \
      "ResourceType=volume,Tags=[{Key=$HID_TAG_KEY,Value=$HID_TAG_VALUE}]" \
      --query 'Instances[0].InstanceId' --output text)" && break
    echo "  run-instances failed (attempt $attempt; IAM propagation?) - retrying in 10 s"; sleep 10
  done
  rm -f "$UD_FILE"
  [[ "$INSTANCE_ID" =~ ^i-[0-9a-f]+$ ]] || die "launch failed"
  save_state INSTANCE_ID "$INSTANCE_ID"
  awsq ec2 wait instance-running --instance-ids "$INSTANCE_ID" || abort_cutover "instance $INSTANCE_ID did not reach running"
  DNS="$(awsq ec2 describe-instances --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].PublicDnsName' --output text)"
  [[ -n "$DNS" && "$DNS" != None ]] || abort_cutover "no public DNS for $INSTANCE_ID"
  save_state PUBLIC_DNS "$DNS"
  echo "  instance $INSTANCE_ID  dns $DNS"
else
  run "launch" -- ec2 run-instances --image-id "<al2023-ami>" --instance-type "$INSTANCE_TYPE" --count 1 \
    --security-group-ids "$SG_ID" "${PROFILE_ARG[@]}" --user-data "file://<rendered user_data>" \
    --block-device-mappings "$BDM" --metadata-options HttpTokens=required,HttpEndpoint=enabled \
    --tag-specifications "ResourceType=instance,Tags=[...]"
  rm -f "$UD_FILE"
  DNS="<public-dns>"
fi

health_stamp() {
  # health_stamp URL: prints the deploy_stamp /v1/health reports ("" when the app does not report one);
  # returns non-zero when the health call fails
  local body
  body="$(curl -fsS -k --max-time 5 "$1/v1/health" 2>/dev/null)" || return 1
  printf '%s' "$body" | "$HID_PY" -c 'import json,sys
try:
    print(str(json.load(sys.stdin).get("deploy_stamp") or ""))
except Exception:
    print("")'
}

echo "[7/9] wait for /v1/health on the instance (boot ~2-3 min)"
SCHEME=$([[ "$TLS" == selfsigned ]] && echo https || echo http)
DIRECT_URL="$SCHEME://$DNS:$APP_PORT"
STAMP_REPORTED=0
if [[ $APPLY -eq 1 ]]; then
  ok=0
  for _ in $(seq 1 "$HEALTH_POLLS"); do
    if got="$(health_stamp "$DIRECT_URL")"; then
      if [[ -z "$got" ]]; then ok=1; break; fi
      if [[ "$got" == "$STAMP" ]]; then ok=1; STAMP_REPORTED=1; break; fi
    fi
    sleep 5
  done
  # health gate (unconditional): never point API Gateway at an instance that is not healthy
  [[ $ok -eq 1 ]] || abort_cutover "instance $INSTANCE_ID not healthy at $DIRECT_URL/v1/health: API Gateway NOT (re-)pointed"
  echo "  healthy: $DIRECT_URL/v1/health"
  [[ $STAMP_REPORTED -eq 1 ]] || echo "  ! the app does not report deploy_stamp in /v1/health: cutover is verified by the integration URI only" >&2
fi

if [[ "$TLS" == selfsigned && $APPLY -eq 1 ]]; then
  echo "  TLS: pinning the self-signed certificate ONLY on an exact console fingerprint match (CIT-11)"
  FP=""
  for _ in $(seq 1 "$TLS_PIN_POLLS"); do
    FP="$(awsq ec2 get-console-output --instance-id "$INSTANCE_ID" --latest --output text 2>/dev/null \
      | sed -n 's/.*HID_TLS_FINGERPRINT_SHA256=\([0-9A-F:]*\).*/\1/p' | tail -1)"
    [[ -n "$FP" ]] && break
    sleep 10
  done
  mktemp_reg CERT_TMP hid-cert
  echo | openssl s_client -connect "$DNS:$APP_PORT" -servername "$DNS" 2>/dev/null | openssl x509 >"$CERT_TMP" 2>/dev/null
  GOT="$(openssl x509 -in "$CERT_TMP" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
  if [[ -z "$FP" || "$FP" != "$GOT" ]]; then
    rm -f "$CERT_TMP" "$STATE_DIR/cloud-cert.pem"
    abort_cutover "TLS fingerprint NOT confirmed (console=${FP:-<none>} served=${GOT:-<none>}): no pin written; do not trust this endpoint"
  fi
  mkdir -p "$STATE_DIR"
  mv "$CERT_TMP" "$STATE_DIR/cloud-cert.pem"
  echo "  pinned (fingerprint matches console): $STATE_DIR/cloud-cert.pem (valid $TLS_CERT_DAYS days: redeploy before expiry)"
fi

echo "[8/9] API Gateway HTTP API (HTTPS front, stage throttle $APIGW_THROTTLE_RATE rps / burst $APIGW_THROTTLE_BURST)"
API_URL=""
THROTTLE="ThrottlingBurstLimit=$APIGW_THROTTLE_BURST,ThrottlingRateLimit=$APIGW_THROTTLE_RATE"
if [[ $USE_APIGW -eq 1 ]]; then
  URI="http://$DNS:$APP_PORT/{proxy}"
  if [[ $APPLY -eq 1 ]]; then
    API_ID="$(awsq apigatewayv2 get-apis --query "Items[?Name=='$API_NAME'].ApiId | [0]" --output text)" \
      || abort_cutover "get-apis failed: ${AWSQ_LAST_ERR:-}"
    if [[ "$API_ID" == "None" || -z "$API_ID" ]]; then
      API_ID="$(awsq apigatewayv2 create-api --name "$API_NAME" --protocol-type HTTP --tags "$HID_TAG_KEY=$HID_TAG_VALUE" --query ApiId --output text)" \
        || abort_cutover "create-api failed: ${AWSQ_LAST_ERR:-}"
      INT_ID="$(awsq apigatewayv2 create-integration --api-id "$API_ID" --integration-type HTTP_PROXY --integration-method ANY \
        --integration-uri "$URI" --payload-format-version 1.0 --query IntegrationId --output text)" \
        || abort_cutover "create-integration failed: ${AWSQ_LAST_ERR:-} (API $API_ID left without routes; teardown removes it)"
      awsq apigatewayv2 create-route --api-id "$API_ID" --route-key 'ANY /{proxy+}' --target "integrations/$INT_ID" >/dev/null \
        || abort_cutover "create-route failed: ${AWSQ_LAST_ERR:-}"
      awsq apigatewayv2 create-stage --api-id "$API_ID" --stage-name '$default' --auto-deploy \
        --default-route-settings "$THROTTLE" >/dev/null || abort_cutover "create-stage failed: ${AWSQ_LAST_ERR:-}"
      echo "  + created API $API_ID"
    else
      INT_ID="$(awsq apigatewayv2 get-integrations --api-id "$API_ID" --query 'Items[0].IntegrationId' --output text)" \
        || abort_cutover "get-integrations failed: ${AWSQ_LAST_ERR:-}"
      [[ -n "$INT_ID" && "$INT_ID" != None ]] || abort_cutover "API $API_ID has no integration"
      awsq apigatewayv2 update-integration --api-id "$API_ID" --integration-id "$INT_ID" --integration-uri "$URI" >/dev/null \
        || abort_cutover "update-integration failed: ${AWSQ_LAST_ERR:-}"
      awsq apigatewayv2 update-stage --api-id "$API_ID" --stage-name '$default' --default-route-settings "$THROTTLE" >/dev/null \
        || echo "  ! could not set stage throttling: ${AWSQ_LAST_ERR:-}" >&2
    fi
    GOT_URI="$(awsq apigatewayv2 get-integration --api-id "$API_ID" --integration-id "$INT_ID" --query IntegrationUri --output text)" \
      || abort_cutover "get-integration failed: ${AWSQ_LAST_ERR:-}"
    [[ "$GOT_URI" == "$URI" ]] || abort_cutover "integration $INT_ID points at $GOT_URI, expected $URI"
    echo "  = API $API_ID -> $DNS (integration verified)"
    API_URL="https://$API_ID.execute-api.$HID_REGION.amazonaws.com"
    save_state API_ID "$API_ID"
  else
    run "create HTTP API" -- apigatewayv2 create-api --name "$API_NAME" --protocol-type HTTP
    run "HTTP_PROXY integration" -- apigatewayv2 create-integration --api-id "<api-id>" --integration-type HTTP_PROXY \
      --integration-method ANY --integration-uri "$URI" --payload-format-version 1.0
    run "route ANY /{proxy+}" -- apigatewayv2 create-route --api-id "<api-id>" --route-key 'ANY /{proxy+}' --target "integrations/<int-id>"
    run "auto-deploy stage (throttled)" -- apigatewayv2 create-stage --api-id "<api-id>" --stage-name '$default' --auto-deploy \
      --default-route-settings "$THROTTLE"
    run "verify integration URI" -- apigatewayv2 get-integration --api-id "<api-id>" --integration-id "<int-id>"
    API_URL="https://<api-id>.execute-api.$HID_REGION.amazonaws.com"
  fi
fi

if [[ -n "$OLD_INSTANCE_ID" && $APPLY -eq 1 ]]; then
  CUT_URL="${API_URL:-$DIRECT_URL}"
  echo "[8b] cutover check: $CUTOVER_CONSECUTIVE consecutive answers from the NEW backend via $CUT_URL, then retire $OLD_INSTANCE_ID"
  streak=0
  for _ in $(seq 1 "$CUTOVER_POLLS"); do
    if got="$(health_stamp "$CUT_URL")" && { [[ $STAMP_REPORTED -eq 0 ]] || [[ "$got" == "$STAMP" ]]; }; then
      streak=$((streak + 1)); [[ $streak -ge $CUTOVER_CONSECUTIVE ]] && break
    else
      streak=0
    fi
    sleep 5
  done
  if [[ $streak -lt $CUTOVER_CONSECUTIVE ]]; then
    if [[ -n "$OLD_DNS" && -n "${INT_ID:-}" && -n "${API_ID:-}" ]]; then  # roll the integration back to the old instance
      if awsq apigatewayv2 update-integration --api-id "$API_ID" --integration-id "$INT_ID" \
          --integration-uri "http://$OLD_DNS:$APP_PORT/{proxy}" >/dev/null; then
        echo "  rolled API $API_ID back to $OLD_DNS" >&2
      else
        echo "  ! ROLLBACK FAILED: API $API_ID may point at the new, unverified instance" >&2
      fi
    fi
    abort_cutover "the new backend did not answer through $CUT_URL"
  fi
  save_state CUTOVER_AT "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  run "terminate previous instance $OLD_INSTANCE_ID" -- ec2 terminate-instances --instance-ids "$OLD_INSTANCE_ID"
fi

echo "[9/9] result"
FINAL_URL="${API_URL:-$DIRECT_URL}"
save_state CLOUD_API_URL "$FINAL_URL"
echo "  CLOUD_API_URL=$FINAL_URL"
[[ "$TLS" == selfsigned ]] && echo "  edge TLS pin: CLOUD_TLS_CA_FILE=$STATE_DIR/cloud-cert.pem (certificate valid $TLS_CERT_DAYS days)"
echo "  verify: cloud/.venv/bin/python -m cloud.tools.smoke_noface --live --base $FINAL_URL"
