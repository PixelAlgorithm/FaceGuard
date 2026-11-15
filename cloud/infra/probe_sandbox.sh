#!/usr/bin/env bash
# =============================================================================
# probe_sandbox.sh - READ-ONLY permission probe for the HID hackathon AWS sandbox
# =============================================================================
# Sandbox = AWS Workshop Studio event "HID Hackathon GenAI - University".
# Only region us-east-1 is accessible (production would use ap-south-1 for
# data residency). The event role "has limited permissions", so every service
# we need is tested individually and classified ALLOWED / DENIED.
#
# Every AWS call in the default run is a List / Describe / Get or an IAM policy
# *simulation*. Nothing is created, modified or deleted. Calls that address a
# resource id that cannot exist ("hid-probe-does-not-exist") tell
# "API allowed, resource absent" (ResourceNotFound => ALLOWED) apart from
# "API blocked" (AccessDenied => DENIED).
#
# Optional --with-dry-run adds EC2 RunInstances/CreateSecurityGroup calls with
# --dry-run (AWS evaluates permissions + SCPs and creates NOTHING). OFF by
# default because they are "create" verbs; only run them with lead approval.
#
# Usage:
#   cloud/infra/probe_sandbox.sh [--profile hid-sandbox] [--region us-east-1]
#                                [--alt-region ap-south-1] [--with-dry-run]
# Credentials: profile hid-sandbox in ~/.aws/credentials (default; temporary
# session credentials) or AWS_ACCESS_KEY_ID/... env vars. Secrets are never
# printed. Exit code 3 = credentials missing or EXPIRED (refresh and re-run).
# Output: stdout + cloud/infra/probe_results/probe_<utc>.txt (account id and
# role ARN only, no secrets).
# =============================================================================
set -uo pipefail

REGION="us-east-1"
ALT_REGION="ap-south-1"
PROFILE="${AWS_PROFILE:-hid-sandbox}"
WITH_DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --alt-region) ALT_REGION="$2"; shift 2 ;;
    --with-dry-run) WITH_DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

command -v aws >/dev/null 2>&1 || { echo "aws CLI not found (brew install awscli)"; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "jq not found"; exit 2; }

# Never let the coding harness' Bedrock token leak into these calls.
unset AWS_BEARER_TOKEN_BEDROCK
export AWS_PAGER=""

PROFILE_ARGS=()
if [[ -n "${AWS_ACCESS_KEY_ID:-}" ]]; then
  CRED_SOURCE="environment variables"
else
  PROFILE_ARGS=(--profile "$PROFILE")
  CRED_SOURCE="profile $PROFILE"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/probe_results"
mkdir -p "$OUT_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_FILE="$OUT_DIR/probe_${STAMP}.txt"
TMP_ERR="$(mktemp)"; TMP_OUT="$(mktemp)"
trap 'rm -f "$TMP_ERR" "$TMP_OUT"' EXIT

AWS=(aws ${PROFILE_ARGS[@]+"${PROFILE_ARGS[@]}"} --output json --cli-connect-timeout 5 --cli-read-timeout 20)

declare -a SUMMARY=()

log() { printf '%s\n' "$*" | tee -a "$OUT_FILE"; }

classify_error() {
  # $1 = stderr text -> prints STATUS|detail
  local e="$1" code
  code="$(printf '%s' "$e" | sed -n 's/.*An error occurred (\([A-Za-z0-9_.]*\)).*/\1/p' | head -1)"
  if printf '%s' "$e" | grep -qiE 'ExpiredToken|RequestExpired|token included in the request is expired|security token .* expired'; then
    echo "CREDS_EXPIRED|${code:-ExpiredToken}"; return
  fi
  if printf '%s' "$e" | grep -qiE 'Unable to locate credentials|could not be found|InvalidClientTokenId|SignatureDoesNotMatch|UnrecognizedClient|security token included in the request is invalid'; then
    echo "NO_VALID_CREDS|${code:-no-credentials}"; return
  fi
  if printf '%s' "$e" | grep -qiE 'service control policy'; then
    echo "DENIED|SCP ${code}"; return
  fi
  if printf '%s' "$e" | grep -qiE 'permissions boundary'; then
    echo "DENIED|boundary ${code}"; return
  fi
  if printf '%s' "$e" | grep -qiE 'AccessDenied|UnauthorizedOperation|not authorized|AuthorizationError|Forbidden|OptInRequired'; then
    echo "DENIED|${code:-AccessDenied}"; return
  fi
  if printf '%s' "$e" | grep -qiE 'DryRunOperation'; then
    echo "ALLOWED|dry-run: request would have succeeded"; return
  fi
  if printf '%s' "$e" | grep -qiE 'ResourceNotFound|NoSuchEntity|NotFoundException|SessionNotFound|NoSuchBucket|does not exist|not found'; then
    echo "ALLOWED|api reachable, probe resource absent (${code:-NotFound})"; return
  fi
  if printf '%s' "$e" | grep -qiE 'Could not connect|EndpointConnectionError|Connect timeout|Read timeout'; then
    echo "ENDPOINT_ERROR|${code:-connect}"; return
  fi
  echo "ERROR|${code:-$(printf '%s' "$e" | head -1 | cut -c1-120)}"
}

# probe <label> <jq-summary-filter|-> <aws args...>
probe() {
  local label="$1" filter="$2"; shift 2
  local status detail rc
  "${AWS[@]}" "$@" >"$TMP_OUT" 2>"$TMP_ERR"; rc=$?
  if [[ $rc -eq 0 ]]; then
    status="ALLOWED"
    if [[ "$filter" != "-" ]]; then
      detail="$(jq -r "$filter" <"$TMP_OUT" 2>/dev/null | tr '\n' ' ' | cut -c1-300)"
    else
      detail=""
    fi
  else
    IFS='|' read -r status detail <<<"$(classify_error "$(cat "$TMP_ERR")")"
  fi
  printf '%-15s %-50s %s\n' "$status" "$label" "$detail" | tee -a "$OUT_FILE"
  SUMMARY+=("$status|$label")
  if [[ "$status" == "CREDS_EXPIRED" ]]; then
    log ""; log "FATAL: sandbox credentials EXPIRED ($CRED_SOURCE). Get fresh credentials from the"
    log "Workshop Studio event page (Get AWS CLI credentials), update ~/.aws/credentials [$PROFILE], re-run."
    exit 3
  fi
  if [[ "$status" == "NO_VALID_CREDS" ]]; then
    log ""; log "FATAL: no valid credentials ($CRED_SOURCE). Put the event credentials in ~/.aws/credentials"
    log "as profile [$PROFILE] (aws_access_key_id / aws_secret_access_key / aws_session_token), re-run."
    exit 3
  fi
  return 0
}

section() { log ""; log "=== $* ==="; }

log "HID sandbox probe  utc=$STAMP  region=$REGION  alt_region=$ALT_REGION  creds=$CRED_SOURCE"
log "$(aws --version 2>&1)"
log "Read-only. Results also written to $OUT_FILE"

section "Identity / session"
probe "sts get-caller-identity" '"account=" + .Account + " arn=" + .Arn' sts get-caller-identity --region "$REGION"
CALLER_ARN="$("${AWS[@]}" sts get-caller-identity --region "$REGION" --query Arn --output text 2>/dev/null || true)"
ACCOUNT_ID="$("${AWS[@]}" sts get-caller-identity --region "$REGION" --query Account --output text 2>/dev/null || true)"
# Expiration only (CLI v2.9+). Credential values never leave the pipe.
EXP="$(aws ${PROFILE_ARGS[@]+"${PROFILE_ARGS[@]}"} configure export-credentials --format process 2>/dev/null | jq -r '.Expiration // "unknown"' 2>/dev/null || echo unknown)"
log "credential expiration (UTC): ${EXP:-unknown}"

section "Regions (expect only $REGION usable)"
probe "ec2 describe-regions (enabled list)" '[.Regions[].RegionName] | join(",")' ec2 describe-regions --region "$REGION"
probe "ec2 describe-availability-zones $REGION" '[.AvailabilityZones[].ZoneName] | join(",")' ec2 describe-availability-zones --region "$REGION"
probe "ec2 describe-vpcs ($ALT_REGION, expect DENIED)" '"vpcs=" + (.Vpcs|length|tostring)' ec2 describe-vpcs --region "$ALT_REGION"
probe "rekognition list-collections ($ALT_REGION)" '"collections=" + (.CollectionIds|length|tostring)' rekognition list-collections --region "$ALT_REGION"

section "Rekognition ($REGION) - face match (step 4) + optional Face Liveness"
probe "rekognition list-collections" '"collections=" + (.CollectionIds|join(","))' rekognition list-collections --region "$REGION"
probe "rekognition describe-collection (absent id)" '-' rekognition describe-collection --collection-id hid-probe-does-not-exist --region "$REGION"
probe "rekognition list-users (user vectors, absent)" '-' rekognition list-users --collection-id hid-probe-does-not-exist --region "$REGION"
probe "rekognition list-faces (absent)" '-' rekognition list-faces --collection-id hid-probe-does-not-exist --region "$REGION"
probe "rekognition get-face-liveness-session-results" '-' rekognition get-face-liveness-session-results --session-id 00000000-0000-4000-8000-000000000000 --region "$REGION"
probe "service-quotas rekognition (TPS)" '[.Quotas[] | select(.QuotaName|test("SearchUsersByImage|SearchFacesByImage|IndexFaces|CompareFaces|Liveness|AssociateFaces|CreateUser";"i")) | "\(.QuotaName)=\(.Value)"] | join("; ")' service-quotas list-service-quotas --service-code rekognition --region "$REGION"

section "DynamoDB (users / decisions / state)"
probe "dynamodb list-tables" '"tables=" + (.TableNames|join(","))' dynamodb list-tables --region "$REGION"
probe "dynamodb describe-table (absent)" '-' dynamodb describe-table --table-name hid-probe-does-not-exist --region "$REGION"
probe "dynamodb describe-limits" '"acct_max_wcu=" + (.AccountMaxWriteCapacityUnits|tostring)' dynamodb describe-limits --region "$REGION"

section "S3 / KMS"
probe "s3api list-buckets" '"buckets=" + (.Buckets|length|tostring)' s3api list-buckets --region "$REGION"
probe "s3api head-bucket (absent)" '-' s3api head-bucket --bucket hid-probe-does-not-exist-7f3a91 --region "$REGION"
probe "kms list-keys" '"keys=" + (.Keys|length|tostring)' kms list-keys --region "$REGION"
probe "kms list-aliases (aws-managed)" '[.Aliases[].AliasName] | map(select(startswith("alias/aws/"))) | join(",")' kms list-aliases --region "$REGION"
probe "kms describe-key alias/aws/s3" '"state=" + .KeyMetadata.KeyState' kms describe-key --key-id alias/aws/s3 --region "$REGION"

section "SES (email OTP; SMS to India impossible: TRAI DLT)"
probe "sesv2 get-account" '"production_access=" + (.ProductionAccessEnabled|tostring) + " sending=" + (.SendingEnabled|tostring) + " max24h=" + (.SendQuota.Max24HourSend|tostring) + " rate/s=" + (.SendQuota.MaxSendRate|tostring)' sesv2 get-account --region "$REGION"
probe "ses get-send-quota" '"max24h=" + (.Max24HourSend|tostring)' ses get-send-quota --region "$REGION"
probe "sesv2 list-email-identities" '[.EmailIdentities[] | "\(.IdentityName):\(.VerificationStatus // .SendingEnabled)"] | join(",")' sesv2 list-email-identities --region "$REGION"

section "Compute: EC2 (preferred host)"
probe "ec2 describe-instances" '"reservations=" + (.Reservations|length|tostring)' ec2 describe-instances --region "$REGION"
probe "ec2 describe-vpcs (default?)" '[.Vpcs[] | "\(.VpcId):default=\(.IsDefault)"] | join(",")' ec2 describe-vpcs --region "$REGION"
probe "ec2 describe-subnets (default-for-az)" '"default_subnets=" + (.Subnets|length|tostring)' ec2 describe-subnets --filters Name=default-for-az,Values=true --region "$REGION"
probe "ec2 describe-security-groups" '"sgs=" + (.SecurityGroups|length|tostring)' ec2 describe-security-groups --region "$REGION"
probe "ec2 instance-type offerings" '[.InstanceTypeOfferings[].InstanceType] | sort | join(",")' ec2 describe-instance-type-offerings --location-type region --filters Name=instance-type,Values=t3.micro,t3.small,t3.medium,t3a.small,c6i.large,c7i.large,m6i.large --region "$REGION"
probe "ssm get-parameters (AL2023 AMI id)" '[.Parameters[].Value] | join(",")' ssm get-parameters --names /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 --region "$REGION"
probe "ec2 describe-key-pairs" '"keypairs=" + (.KeyPairs|length|tostring)' ec2 describe-key-pairs --region "$REGION"
probe "ec2 describe-iam-instance-profile-assoc" '"assocs=" + (.IamInstanceProfileAssociations|length|tostring)' ec2 describe-iam-instance-profile-associations --region "$REGION"
probe "ssm describe-instance-information" '"managed=" + (.InstanceInformationList|length|tostring)' ssm describe-instance-information --region "$REGION"

section "Compute: Lambda / API Gateway (alternative host; also TLS front for EC2)"
probe "lambda list-functions" '"functions=" + (.Functions|length|tostring)' lambda list-functions --region "$REGION"
probe "lambda get-account-settings (concurrency)" '"concurrency_limit=" + (.AccountLimit.ConcurrentExecutions|tostring) + " unreserved=" + (.AccountLimit.UnreservedConcurrentExecutions|tostring)' lambda get-account-settings --region "$REGION"
probe "apigatewayv2 get-apis (HTTP API)" '"apis=" + (.Items|length|tostring)' apigatewayv2 get-apis --region "$REGION"

section "Observability"
probe "cloudwatch list-dashboards" '"dashboards=" + (.DashboardEntries|length|tostring)' cloudwatch list-dashboards --region "$REGION"
probe "cloudwatch list-metrics (HIDKiosk)" '"metrics=" + (.Metrics|length|tostring)' cloudwatch list-metrics --namespace HIDKiosk --region "$REGION"
probe "logs describe-log-groups" '"groups=" + (.logGroups|length|tostring)' logs describe-log-groups --limit 5 --region "$REGION"

section "Secrets / config stores / databases"
probe "ssm describe-parameters" '"params=" + (.Parameters|length|tostring)' ssm describe-parameters --max-results 5 --region "$REGION"
probe "secretsmanager list-secrets" '"secrets=" + (.SecretList|length|tostring)' secretsmanager list-secrets --max-results 5 --region "$REGION"
probe "rds describe-db-instances" '"dbs=" + (.DBInstances|length|tostring)' rds describe-db-instances --region "$REGION"

section "IAM + CloudFormation (role creation is the usual sandbox blocker)"
probe "iam list-roles (non-service-linked)" '[.Roles[] | select(.Path|startswith("/aws-service-role/")|not) | .RoleName] | .[0:30] | join(",")' iam list-roles --max-items 300
probe "iam list-instance-profiles" '[.InstanceProfiles[] | "\(.InstanceProfileName)<-\([.Roles[].RoleName]|join("+"))"] | .[0:15] | join(",")' iam list-instance-profiles --max-items 100
probe "cloudformation list-stacks (workshop template)" '[.StackSummaries[].StackName] | join(",")' cloudformation list-stacks --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE --region "$REGION"
STACKS="$("${AWS[@]}" cloudformation list-stacks --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE --region "$REGION" --query 'StackSummaries[].StackName' --output text 2>/dev/null || true)"
for st in $STACKS; do
  probe "cfn roles/profiles in stack $st" '[.StackResources[] | select(.ResourceType|test("AWS::IAM::(Role|InstanceProfile)")) | "\(.ResourceType|sub("AWS::IAM::";"")):\(.PhysicalResourceId)"] | join(",")' cloudformation describe-stack-resources --stack-name "$st" --region "$REGION"
done
ROLE_NAME=""
if [[ "$CALLER_ARN" == arn:aws:sts::*:assumed-role/* ]]; then
  ROLE_NAME="$(printf '%s' "$CALLER_ARN" | cut -d/ -f2)"
elif [[ "$CALLER_ARN" == arn:aws:iam::*:user/* ]]; then
  log "caller is an IAM user ($CALLER_ARN)"
fi
POLICY_SOURCE_ARN="$CALLER_ARN"
if [[ -n "$ROLE_NAME" ]]; then
  probe "iam get-role (caller role)" '"arn=" + .Role.Arn + " maxSession=" + (.Role.MaxSessionDuration|tostring) + "s boundary=" + ((.Role.PermissionsBoundary.PermissionsBoundaryArn) // "none")' iam get-role --role-name "$ROLE_NAME"
  probe "iam list-attached-role-policies (caller)" '[.AttachedPolicies[].PolicyName] | join(",")' iam list-attached-role-policies --role-name "$ROLE_NAME"
  ROLE_ARN="$("${AWS[@]}" iam get-role --role-name "$ROLE_NAME" --query Role.Arn --output text 2>/dev/null || true)"
  [[ -n "$ROLE_ARN" && "$ROLE_ARN" != "None" ]] && POLICY_SOURCE_ARN="$ROLE_ARN"
fi
probe "organizations describe-organization" '"org=" + .Organization.Id' organizations describe-organization
if [[ -n "$ACCOUNT_ID" ]]; then
  probe "budgets describe-budgets" '[.Budgets[]? | "\(.BudgetName)=\(.BudgetLimit.Amount)\(.BudgetLimit.Unit)"] | join(",")' budgets describe-budgets --account-id "$ACCOUNT_ID"
fi

section "Cognito (Face Liveness browser credentials, optional)"
probe "cognito-identity list-identity-pools" '"pools=" + (.IdentityPools|length|tostring)' cognito-identity list-identity-pools --max-results 5 --region "$REGION"

section "IAM policy simulation of the WRITE actions we would need (read-only API)"
SIM_ACTIONS=(
  rekognition:CreateCollection rekognition:IndexFaces rekognition:CreateUser rekognition:AssociateFaces
  rekognition:SearchUsersByImage rekognition:CompareFaces rekognition:DeleteUser rekognition:DeleteFaces
  rekognition:DeleteCollection rekognition:CreateFaceLivenessSession rekognition:StartFaceLivenessSession
  rekognition:GetFaceLivenessSessionResults
  dynamodb:CreateTable dynamodb:UpdateTimeToLive dynamodb:PutItem dynamodb:DeleteTable
  s3:CreateBucket s3:PutLifecycleConfiguration s3:PutEncryptionConfiguration s3:PutBucketPublicAccessBlock s3:DeleteBucket
  kms:CreateKey kms:ScheduleKeyDeletion
  ses:CreateEmailIdentity ses:SendEmail
  ec2:RunInstances ec2:CreateSecurityGroup ec2:AuthorizeSecurityGroupIngress ec2:TerminateInstances
  ec2:AssociateIamInstanceProfile
  iam:CreateRole iam:PutRolePolicy iam:AttachRolePolicy iam:CreateInstanceProfile iam:AddRoleToInstanceProfile
  iam:PassRole iam:DeleteRole
  lambda:CreateFunction lambda:PutProvisionedConcurrencyConfig lambda:DeleteFunction
  apigateway:POST apigateway:DELETE
  cloudwatch:PutMetricData cloudwatch:PutDashboard logs:CreateLogGroup
  ssm:PutParameter ssm:GetParameters ssm:SendCommand
  cognito-identity:CreateIdentityPool
)
if [[ -n "$POLICY_SOURCE_ARN" ]]; then
  if "${AWS[@]}" iam simulate-principal-policy --policy-source-arn "$POLICY_SOURCE_ARN" \
       --action-names "${SIM_ACTIONS[@]}" >"$TMP_OUT" 2>"$TMP_ERR"; then
    jq -r '.EvaluationResults[] | (.OrganizationsDecisionDetail.AllowedByOrganizations) as $org | [ (if .EvalDecision=="allowed" and ($org != false) then "SIM_ALLOWED" else "SIM_DENIED" end), .EvalActionName, ("eval=" + .EvalDecision + " org_allowed=" + (if $org == null then "n/a" else ($org|tostring) end)) ] | @tsv' <"$TMP_OUT" \
      | while IFS=$'\t' read -r st act det; do printf '%-15s %-50s %s\n' "$st" "$act" "$det"; done | tee -a "$OUT_FILE"
    log "(simulation = identity policies + SCPs where AWS reports them; confirm critical writes with an approved smoke test)"
  else
    IFS='|' read -r st det <<<"$(classify_error "$(cat "$TMP_ERR")")"
    printf '%-15s %-50s %s\n' "$st" "iam simulate-principal-policy" "$det" | tee -a "$OUT_FILE"
    log "-> cannot simulate; write permissions must be confirmed by the (approved) smoke test."
  fi
fi

if [[ $WITH_DRY_RUN -eq 1 ]]; then
  section "EC2 dry-run permission checks (creates NOTHING; --dry-run)"
  AMI="$("${AWS[@]}" ssm get-parameters --names /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 --region "$REGION" --query 'Parameters[0].Value' --output text 2>/dev/null || true)"
  for itype in t3.small t3.micro c6i.large; do
    probe "ec2 run-instances --dry-run $itype" '-' ec2 run-instances --dry-run --image-id "${AMI:-ami-00000000000000000}" --instance-type "$itype" --count 1 --region "$REGION"
  done
  DEF_VPC="$("${AWS[@]}" ec2 describe-vpcs --filters Name=isDefault,Values=true --region "$REGION" --query 'Vpcs[0].VpcId' --output text 2>/dev/null || true)"
  probe "ec2 create-security-group --dry-run" '-' ec2 create-security-group --dry-run --group-name hid-probe-dryrun --description probe --vpc-id "${DEF_VPC:-vpc-00000000}" --region "$REGION"
fi

section "SUMMARY"
for s in "${SUMMARY[@]}"; do log "  ${s%%|*}  ${s#*|}"; done
log ""
REK="$(printf '%s\n' "${SUMMARY[@]}" | grep -E '\|rekognition list-collections$' | cut -d'|' -f1)"
log "Rekognition ($REGION) verdict: ${REK:-unknown}"
if [[ "$REK" != "ALLOWED" ]]; then
  log "!! Rekognition unavailable -> cloud /v1/match returns 503 (FACE_BACKEND=disabled); edge uses local ArcFace + OFFLINE rules. Report to lead now."
fi
log "Next: copy this output into cloud/SANDBOX.md section 4 (Probe results)."
