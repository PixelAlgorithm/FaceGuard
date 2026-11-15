# cloud/SANDBOX.md — AWS sandbox: what we need, what may be blocked, how we degrade

Owner: `cloud-aws`. Last update: 2026-11-15 ~06:20 UTC / 11:50 IST (code + docs only, no AWS calls; L2 strict booleans + R-H trims, READMIT reason guard, README route list). The §13b blue-green redeploy ran (cutover 2026-11-14T17:18:00Z per `cloud/infra/.state/deploy.env`); the v1.4 admin-access code (§13d) is **NOT live** and needs a new blue-green redeploy, **PENDING operator approval**.

**Identity authority (one line, used everywhere below):** decisions are made on the edge (local-first); online,
Rekognition is authoritative with a local cross-check (`edge/policy/identity.py`); offline or on cloud timeout the
local matcher decides under offline bars (P7).

## 0. Status (read first)

| Item | State |
|---|---|
| Sandbox | AWS Workshop Studio event **"HID Hackathon GenAI - University"**, account <ACCOUNT_ID>, role `WSParticipantRole/Participant` (AdministratorAccess attached), **us-east-1 only** for Rekognition (ap-south-1 Rekognition denied by SCP). **Production would run in ap-south-1 (Mumbai)** for data residency (DPDP optics) and ~20–40 ms RTT. |
| Deployed (2026-11-14 ~10:00 UTC, operator-approved) | **`CLOUD_API_URL=https://8c1yi8fjgj.execute-api.us-east-1.amazonaws.com`** (API Gateway HTTP API `8c1yi8fjgj` → EC2 `i-0cde00aab5c12d5bf` t3.small AL2023, port 9000, instance profile `hid-kiosk-ec2-profile`). FACE_BACKEND=rekognition, STORE_BACKEND=dynamodb, EMAIL_BACKEND=ses, seed `config/schedule.demo.json` (bundle v42, `u_prj1` entitled, demo card hashes recomputed with CARD_ID_PEPPER). Secrets: SSM SecureString `/hid-kiosk/app-env` (aws/ssm), not in user-data (verified). |
| Data plane | Rekognition collection `hid-kiosk-users`: **10 faces, 2 users** (read-only check 2026-11-14 15:50 UTC: `u_prj1` ACTIVE 5 faces, `u_tm03` ACTIVE 5 faces, no orphan faces, face model 7.0); DynamoDB `hid_users`, `hid_decisions`, `hid_state` (on-demand, SSE aws/dynamodb, TTL `ttl` ENABLED); S3 `hid-kiosk-<ACCOUNT_ID>-us-east-1` (SSE-KMS aws/s3 + bucket key, public access blocked, TLS-only policy, **lifecycle 1 day on every prefix**); CloudWatch dashboard `hid-kiosk` + alarm `hid-kiosk-post-hoc-revoked`. No CMK. |
| SES | identity `studies.prajwalm@gmail.com` requested (sandbox: 200/day, 1/s); OTP only after the operator clicks the AWS verification mail. |
| Rekognition | Consenting team faces only (operator decision), indexed by edge enrolments made while ONLINE: `u_prj1`, `u_tm03`. **Edge user `u_tm02` is missing from Rekognition** (enrolled on the edge only): online, with `match.rekognition.enabled: true`, it gets no cloud match -> `NOT_ENROLLED` -> DENY (API.md §3.15). Fix = a consented re-enrolment of `u_tm02` while the edge is ONLINE, with the e-mail field filled (the LIVE build requires `email`; blank -> cloud 422, `cloud_indexed: false`; after the redeploy `email` is optional and the face is indexed without it). Decisions are made on the edge (local-first); online, Rekognition is authoritative with a local cross-check (`edge/policy/identity.py`); offline or on cloud timeout the local matcher decides under offline bars (P7). |
| Live state (read-only check 2026-11-14 16:24 UTC) | `GET /v1/health` -> `status ok, rekognition ok, dynamodb ok, face_backend rekognition, email_backend ses`, uptime 23100 s (still the ~09:55 UTC build). Live edge `GET /v1/mode` -> `ONLINE`, bundle **v45** FRESH (cloud-issued, issued 12:30:41Z, expires 2026-11-15T00:30:41Z), `revocation_seq 7`, sync queue 0, `cloud_match.degraded: true` (recent cloud matches missed the edge time-box; each such attempt is decided OFFLINE by the local matcher under offline bars, P7; miss count not stored, so not quoted). Creds: `sts get-caller-identity` OK (WSParticipantRole/Participant). |
| Redeploys | **Round 5 (§13b) ran**: `cloud/infra/.state/deploy.env` records `CUTOVER_AT=2026-11-14T17:18:00Z`, instance `i-01b6e4e075101b819`, same API `8c1yi8fjgj`; artifact `cloud/infra/build/hid-cloud.tgz` built 2026-11-14 17:16 UTC (append-mode enrolment, optional `email`, override-code hygiene, `PUT /v1/admin/schedule/{kiosk_id}`, synthetic tagging). Not re-checked against AWS this round (no AWS calls). **v1.4 admin-access (§13d) - PENDING operator approval, NOT live**: the live build predates `GET /v1/admin/users`, `PUT /v1/admin/users/{user_id}/access` (create / re-admit R-B / restore R-C, `consent`, `restore`), `POST /v1/admin/codes/rotate`, `GET /v1/admin/audit`, `error.reason`, `409 ALREADY_REVOKED`, the ERASE / READMIT feed types and the v1.4 field limits, so the edge reports `503 CLOUD_UNAVAILABLE` reason `ENDPOINT_NOT_DEPLOYED` for those writes until the redeploy. Green in code: `pytest cloud/tests` 259 passed (2026-11-15 ~06:20 UTC, after the L2 / L4 fixes; incl. `test_contract_admin_access.py` against `docs/contracts/admin_access.examples.json`), ruff check clean; scratch run on 127.0.0.1:9094 (fake backends, dummy keys): `cloud.tools.smoke` PASS. |
| S3 audit frames | **Not implemented.** The cloud never uploads decision / audit frames to S3; the bucket holds only deploy artifacts (and, if `ENROLL_STORE_REFERENCE=true`, which is off, an enrolment reference image). The 1-day lifecycle on every prefix (incl. `audit/`) is in place for when it is built. |
| Teardown | `AWS_PROFILE=hid-sandbox bash cloud/infra/teardown.sh --apply` (deletes API, instance, SG, IAM role/profile, tables, bucket, collection, SSM parameter, dashboard/alarm, SES identity). |

## 1. How to run the probe (once the lead confirms credentials are live)

```bash
# ~/.aws/credentials  [hid-sandbox] aws_access_key_id / aws_secret_access_key / aws_session_token
# ~/.aws/config       [profile hid-sandbox] region = us-east-1
cloud/infra/probe_sandbox.sh                 # read-only: list/describe/get + IAM policy *simulation*
cloud/infra/probe_sandbox.sh --with-dry-run  # ONLY with lead approval: adds ec2 run-instances --dry-run (creates nothing)
```
Prints `ALLOWED / DENIED / ERROR` per call and saves `cloud/infra/probe_results/probe_<utc>.txt`
(account id + role ARN only; secrets are never printed). Classification: `AccessDenied`/`UnauthorizedOperation`
→ DENIED (tagged `SCP` when the message says "service control policy"); `ResourceNotFound` on a deliberately
absent id → ALLOWED (API reachable). It also lists pre-provisioned roles / instance profiles / CloudFormation
stack resources (the workshop template may already contain an EC2 instance profile) and runs
`iam simulate-principal-policy` for every **write** action we would need, so the write map is known without
creating anything.

## 2. What we need from the sandbox

| Service | APIs | Used for | Needed? |
|---|---|---|---|
| Rekognition (image) | `CreateCollection`, `IndexFaces`, `CreateUser`, `AssociateFaces`, `SearchUsersByImage` (UserMatchThreshold 80, MaxUsers 2, QualityFilter AUTO), `CompareFaces`, `DeleteUser`, `DeleteFaces`, `DeleteCollection`, `DescribeCollection` | `/v1/enroll`, `/v1/match`, erasure, health, teardown | Online identity authority (edge decides local-first; local cross-check in `edge/policy/identity.py`; offline / cloud timeout -> local matcher under offline bars, P7) |
| Rekognition Face Liveness | `CreateFaceLivenessSession`, `GetFaceLivenessSessionResults` (+ browser `StartFaceLivenessSession` via Cognito Identity Pool) | Optional step-up only, never on the 2 s path | Optional |
| DynamoDB | `CreateTable`, `UpdateTimeToLive`, `Get/Put/Update/DeleteItem` (conditional), `Query`, `DescribeTable` | users, decisions (idempotent sync ledger, TTL 7 d), state (schedule versions, revocations, OTPs with TTL, alerts) | Preferred store |
| S3 + SSE-KMS | `CreateBucket`, `PutBucketEncryption` (aws:kms, bucket key), `PutLifecycleConfiguration` (1 d on every prefix), `PutPublicAccessBlock`, `Put/Get/DeleteObject` | deploy artifact; optional enrolment reference image for 1:1 `CompareFaces` (off by default); optional Face Liveness `OutputConfig`. **No decision / audit-frame upload is implemented.** | Nice to have |
| KMS | AWS-managed keys `aws/s3`, `aws/dynamodb` (no CMK by default); `Encrypt/Decrypt` only if a CMK is approved | at-rest encryption | Default = managed keys |
| SES (sandbox) | `CreateEmailIdentity` (verify sender + each recipient), `SendEmail` | `/v1/otp/send` email OTP. **SMS to India is impossible today (TRAI DLT registration needs PAN/TAN/GSTIN/CIN).** | Optional |
| CloudWatch | `PutMetricData` (namespace `HIDKiosk`), `PutDashboard`, Logs | latency p50/p95, decisions, sync alerts | Nice to have |
| EC2 + VPC | `RunInstances` (t3.small, AL2023 x86_64), security group, default VPC/subnet, public IPv4 | warm cloud API host (recommended) | Yes (or laptop fallback) |
| IAM | `CreateRole`, `PutRolePolicy`, `CreateInstanceProfile`, `AddRoleToInstanceProfile`, **`PassRole`** — or a pre-provisioned instance profile | credentials for the EC2 app (no keys on the box, ever) | Usual blocker |
| API Gateway HTTP API | `CreateApi` (HTTP_PROXY → EC2) | public **HTTPS** endpoint in front of EC2 | Optional (TLS alt: self-signed + pinning) |
| Lambda | `CreateFunction`, alias, `PutProvisionedConcurrencyConfig` | alternative host only | Alternative |
| SSM Parameter Store | `PutParameter` (SecureString), `GetParameters`; Run Command | ship app secrets to EC2 without user-data/plaintext; redeploys | Nice to have |

## 3. Typical Workshop Studio restrictions and how we cope

| Restriction | Coping |
|---|---|
| Region lock (SCP) — us-east-1 only | All scripts/app default `us-east-1`; probe confirms ap-south-1 is denied. |
| Limited event role (template is EC2/S3/VPC/RDS-centric) | Every service probed individually; each has a degraded mode (section 5) selected by env vars — no code changes. |
| No IAM role creation / `iam:PassRole` limited | Look for a pre-provisioned instance profile first; else options in section 5 (no credentials are ever copied onto an instance). |
| Short-lived session credentials (often 1–12 h) | Never hard-coded; scripts fail with exit 3 on `ExpiredToken`; app `/v1/health` reports `creds_expired` for the dependency instead of crashing. |
| No quota increases / support cases | Client-side token buckets sized to the **Mumbai** defaults (stricter than us-east-1), one jittered retry, then `503 UPSTREAM_THROTTLED`. |
| Budget caps; account wiped after the event | Small footprint (one t3.small); all IaC in `cloud/infra/`; `teardown.sh` removes everything; no CMK by default (KMS keys cannot be deleted immediately — 7-day minimum waiting period). |
| SES sandbox | Only verified recipients, ~200 msgs/24 h, 1 msg/s. Verify the team's own addresses; TOTP/staff code remain. |
| Lambda account concurrency limit may be 10 | Provisioned concurrency then impossible (needs ≥ 10 unreserved) → another reason for EC2. |

## 4. Probe results (2026-11-14 09:40 UTC, `AWS_PROFILE=hid-sandbox bash cloud/infra/probe_sandbox.sh`, read-only)

Caller `arn:aws:sts::<ACCOUNT_ID>:assumed-role/WSParticipantRole/Participant` (account <ACCOUNT_ID>); role
policies `ws-default-policy, CloudFrontFullAccess, AdministratorAccess`, no permissions boundary, max session 12 h;
credential expiry not exposed for this profile (temporary Workshop Studio creds - scripts exit 3 on ExpiredToken).
Raw output: `cloud/infra/probe_results/probe_20261114T094031Z.txt` (gitignored).
Re-check 2026-11-14 16:24 UTC: `sts get-caller-identity` still valid (same role); no new denials observed (the deployed API reports `rekognition ok`, `dynamodb ok`). Rekognition remains available - no fallback to `match.rekognition.enabled: false` needed.

| Probe | us-east-1 | Notes |
|---|---|---|
| sts get-caller-identity | ALLOWED | WSParticipantRole/Participant |
| ap-south-1 | Rekognition **DENIED** (SCP), `ec2 describe-vpcs` allowed | per-service region lock -> everything stays in us-east-1 |
| Rekognition list-collections / describe / list-users / list-faces / liveness get | **ALLOWED** | no collections yet (at probe time; current state in §0) |
| Rekognition quotas (service-quotas) | SearchUsersByImage 50, IndexFaces 50, SearchFacesByImage 50, CompareFaces 100, CreateUser 5, AssociateFaces 5, DeleteUser 5, DeleteFaces 5 TPS; Face Liveness 25 TPS, 75 concurrent | client caps stay at the stricter ap-south-1 values (5 / 25 / 5 / 15) |
| DynamoDB list-tables / describe-table / limits | ALLOWED | no tables; account max WCU 80000 |
| S3 list-buckets / head-bucket | ALLOWED | 0 buckets |
| KMS list-keys / aliases / aws/s3 | ALLOWED | aws/s3, aws/dynamodb, aws/ssm managed keys Enabled |
| SES get-account / quota / identities | ALLOWED | **sandbox** (production_access=false), 200 msgs/24 h, 1 msg/s, no identities yet |
| EC2 describe-* / offerings / AMI | ALLOWED | default VPC vpc-0eed6adbb9d83b01c, 6 default subnets; t3.micro/small/medium, t3a.small, c6i/c7i/m6i.large offered; AL2023 ami-096ef200a877f36af |
| SSM describe-parameters / instance information | ALLOWED | 0 parameters |
| Lambda / API Gateway | ALLOWED | account concurrency 400 (110 unreserved) - provisioned concurrency possible; 0 HTTP APIs |
| CloudWatch / Logs | ALLOWED | no dashboards, no HIDKiosk metrics |
| IAM list-roles / instance profiles / CFN stacks | ALLOWED | WS* system roles only; no instance profiles; no stacks |
| Organizations describe | DENIED | irrelevant |
| Cognito identity pools | ALLOWED | 0 pools |
| IAM simulate (49 write actions incl. iam:CreateRole, iam:PassRole, ec2:RunInstances, dynamodb:CreateTable, rekognition:CreateCollection, ses:SendEmail, ssm:PutParameter) | **all SIM_ALLOWED** (org_allowed=true) | role creation is NOT blocked -> recommended EC2 + instance profile path |

## 5. Degraded plan for each likely denial

All switches are env vars of the cloud app (`cloud/README.md`); defaults are the full-AWS path.

| Denied | Effect | Plan |
|---|---|---|
| **Rekognition** | No cloud face match / enrolment vectors | `FACE_BACKEND=disabled`: `/v1/match` and `/v1/enroll` return `503 CLOUD_UNAVAILABLE`, `/v1/health` reports `"rekognition": "disabled"`. Edge falls back to local ArcFace + OFFLINE rules (P7); with `match.rekognition.enabled: false` no cloud match is requested and identity comes from the local matcher with the offline (stricter) bars (ARCHITECTURE identity table). Schedule, revocations, sync, OTP keep working. Pitch: "Rekognition-ready, sandbox-blocked". |
| Face Liveness / Cognito | No managed liveness step-up | Endpoints return 503; step-up = our own mouth/cheek challenge + TOTP/staff/card (already the primary path). |
| **DynamoDB** | No managed ledger | `STORE_BACKEND=sqlite` (`SQLITE_PATH` on the EC2 EBS volume or the laptop): same conditional-put idempotency, TTL purge on read + sweep. Lost on instance termination (acceptable for the demo; edge queue is the source until acked). |
| S3 | No artifact bucket, no reference images | Deploy artifact goes through user-data (small) or `scp`; 1:1 match uses `SearchUsersByImage` restricted to the claimed user instead of `CompareFaces` (no images stored at all — the default anyway). |
| KMS (CMK) | — | Default already uses AWS-managed keys; TOTP seeds encrypted with Fernet (`CLOUD_DATA_KEY`) or not persisted. |
| **SES** | No email OTP | `EMAIL_BACKEND=disabled`: `/v1/otp/send` → `503`, edge switches `next_action` to TOTP / staff code / card (API.md §4.5). |
| CloudWatch PutMetricData | No custom metrics / dashboard | `METRICS_SINK=emf_stdout` (EMF JSON lines in the service log); every response still carries `X-Latency-Ms`; dashboard skipped. |
| API Gateway | No managed HTTPS front | uvicorn serves TLS with a **self-signed certificate generated on the instance**; its SHA-256 fingerprint is printed to the EC2 console log and the edge pins it (`CLOUD_TLS_CA_FILE`). HMAC request signing protects integrity either way. |
| Lambda | — | Not needed (EC2 recommended). |
| **IAM role creation / PassRole** | EC2 instance cannot get its own credentials | (A) **Use a pre-provisioned instance profile** if the probe finds one (CFN stack of the workshop template) and its simulated permissions cover what we need. (B) **EC2 without a role**: cloud API on EC2 with `STORE_BACKEND=sqlite`, `FACE_BACKEND=disabled`, `EMAIL_BACKEND=disabled` — AWS hosts compute; schedule/sync/revocations are real. (C) **Laptop-hosted cloud API** (`uvicorn cloud.app.main:app --port 9000` on the demo or a second laptop) using the operator's `hid-sandbox` session profile for whatever the event role allows (Rekognition/SES/DynamoDB) — real managed services, local hosting. (D) **Rejected:** copying temporary session keys onto the instance (credentials on servers, expire mid-demo). Recommendation without a role: **C if Rekognition is ALLOWED for the event role, else B.** |
| EC2 | No AWS compute | Option C above (second laptop preferred so "pull the plug" really cuts the edge off; on one laptop use the edge admin force-offline toggle). |
| Everything | — | Fully local: edge + this cloud app with in-memory/sqlite fakes; architecture slide still shows AWS. |

## 6. Hosting decision — EC2 (warm) vs Lambda, for us-east-1

**Latency facts that drive it (estimates to measure, not slide numbers):**

| Segment | Bangalore → us-east-1 | Notes |
|---|---|---|
| RTT | ~200–250 ms | lead-provided expectation |
| New TCP + TLS connection | 2–3 RTT ≈ 0.45–0.75 s | must be paid **once**: the edge must reuse one keep-alive `httpx.AsyncClient`; the 5 s heartbeat keeps it warm |
| Upload 150 KB full frame | ~3–4 RTT on a cold congestion window ≈ 0.7–0.9 s | far too slow |
| Upload ≤ 30 KB face crop (≥ 200 px face) | 1–2 RTT ≈ 0.2–0.5 s | Rekognition needs ≥ 40×40 px; 200 px is comfortable |
| `SearchUsersByImage` | ~0.3–0.6 s | AWS publishes no SLA; measure |
| API Gateway hop | ~10–30 ms | only with the APIGW front |
| **Cloud match, warm connection, face crop** | **≈ 0.55–1.1 s** | vs ≈ 0.35–0.65 s from Bangalore → ap-south-1 |

**What the 2 s budget means for the cloud path:** t0 (face lock) → decision ≤ 2 s, and the colour-flash capture
alone takes 0.8–1.0 s. If the edge only calls `/v1/match` after the frames arrive, the online path is
≈ 0.1 + 1.0 + (0.55–1.1) + 0.05 s = **1.7–2.25 s → misses the budget at p95**, and the current
`latency_budget_ms.rekognition_timeout: 700` would time out most calls and flip attempts to OFFLINE (P7).
To keep the cloud on the critical path in us-east-1:
1. **Start the cloud match at face lock** (kiosk sends the lock frame / first frame early; edge fires `/v1/match`
   in parallel with the flash capture; the local matcher re-checks that the flash frames are the same identity).
   Then total ≈ max(1.0 + 0.15 liveness, 1.1 match) + policy ≈ **1.2–1.3 s**.
2. Send a **face crop ≤ 30 KB**, not the full frame.
3. Budgets as configured now (`config/thresholds.yaml`, owned by `policy-engine`): early probe at face lock with
   `latency_budget_ms.rekognition_probe_deadline` 1500 ms measured from probe start; no-probe path
   `rekognition_timeout` 700 ms. Exceeded -> the attempt is OFFLINE (P7).
4. Decisions are made on the edge (local-first); online, Rekognition is authoritative with a local cross-check
   (`edge/policy/identity.py`); offline or on cloud timeout the local matcher decides under offline bars (P7).
   A late or failed cloud match never blocks a decision and never produces an online ALLOW on its own.
5. Production in ap-south-1 cuts ~1 RTT of the budget (estimate, not measured).
`/v1/sync`, `/v1/schedule`, `/v1/revocations` are off the critical path; `/v1/health` (heartbeat, timeout 2 s) is fine.

**EC2 vs Lambda:**

| | EC2 t3.small, warm (recommended) | Lambda + API Gateway (alternative) |
|---|---|---|
| Cold start | none | FastAPI + pydantic + boto3 init ≈ 1–2 s (estimate) on top of the 0.55–1.1 s network → certain miss after idle |
| Mitigation | — | Provisioned concurrency needs ≥ 10 unreserved account concurrency (sandbox limit may be 10 → impossible); SnapStart needs Python ≥ 3.12 (we are 3.11) and excludes PC |
| Rekognition TPS control | one process → exact in-process token bucket | one bucket per execution environment |
| Connections to Rekognition | pooled keep-alive (saves a TLS setup per call) | per environment |
| Permissions needed | instance profile (CreateRole+PassRole, or pre-provisioned) | execution role (same IAM problem) |
| Ops | user-data boot, systemd, ~2–3 min to first health | zip deploy, but APIGW + alias + PC config |
| Cost (us-east-1 list, approx.) | t3.small $0.0208/h + public IPv4 $0.005/h + 8 GB gp3 ≈ **$0.27 per 10 h** | ≈ $0 at demo volume (+ ~$0.0075/h per 512 MB PC) |

**Recommendation: EC2 t3.small (Amazon Linux 2023, x86_64), one uvicorn worker under systemd, instance profile
with a least-privilege inline policy, HTTPS via API Gateway HTTP API (HTTP_PROXY) if allowed, otherwise
self-signed TLS + fingerprint pinning.** Lambda stays as `cloud/infra/deploy_lambda.sh` only.
**If IAM role creation is blocked:** section 5 row "IAM role creation" (A → pre-provisioned profile, else C/B).

## 7. Quotas we design for

| API | us-east-1 default | ap-south-1 default (production) | Our client-side cap |
|---|---|---|---|
| SearchUsersByImage / IndexFaces / AssociateFaces / CreateUser | 50 TPS | 5 TPS | **5 TPS** token bucket (`REKOGNITION_SEARCH_TPS`) |
| CompareFaces / DetectFaces | 100 TPS | 25 TPS | 25 TPS |
| Face Liveness APIs / concurrent sessions | 25 TPS / 75 | 5 TPS / 15 | 5 TPS / 15 concurrent |

Throttling (`ThrottlingException`, `ProvisionedThroughputExceededException`) → one jittered retry only if the
remaining match budget allows, else `503 UPSTREAM_THROTTLED` (edge → local match). The probe's service-quotas
line shows the account's real values.

## 8. Cost of the planned deploy (approximate us-east-1 list prices; sandbox-funded)

| Item | Price | Demo-day estimate |
|---|---|---|
| EC2 t3.small + IPv4 + 8 GB gp3 | $0.0208/h + $0.005/h + $0.08/GB-mo | ~$0.27 / 10 h |
| API Gateway HTTP API | ~$1.00 per million requests | < $0.01 (heartbeat every 5 s) |
| Rekognition image APIs | ~$0.001 per image | ~$0.50 for 500 calls |
| Face Liveness (optional) | ~$0.015 per check | ~$0.30 for 20 checks |
| DynamoDB on-demand (3 tables) | per request | < $0.01 |
| S3 + SSE-KMS (aws/s3) | per GB / request | < $0.01 |
| SES | $0.10 per 1000 emails | < $0.01 |
| CloudWatch custom metrics + 1 dashboard | ~$0.30/metric-month (prorated), dashboard $3/mo (3 free) | < $0.50 / day |
| KMS CMK (only if approved; **hard to tear down**: 7-day deletion wait) | $1/month prorated | ~$0.03 / day |
| **Total** | | **≈ $1–2 for the day** |

## 9. What I need from the operator

1. **Credentials**: from the Workshop Studio event page ("Get AWS CLI credentials"), paste into `~/.aws/credentials`
   as profile `[hid-sandbox]` (`aws_access_key_id`, `aws_secret_access_key`, `aws_session_token`) and add
   `region = us-east-1` under `[profile hid-sandbox]` in `~/.aws/config`. Never into the repo or `.env`.
   Re-paste when they expire (scripts exit 3 with a clear message).
2. **SES**: one sender address and the recipient address(es) of consenting team members (in the SES sandbox
   every recipient must be verified). Each person must click the AWS verification e-mail within 24 h.
3. **Consent**: only team members who agreed are enrolled; their faces are deleted by `teardown.sh`.

## 10. Commands for the lead to get approved (run by cloud-aws only after approval)

All scripts print every AWS command in PLAN mode first (`<script>` without `--apply`; verified to make zero AWS calls).
Order, what each creates, and approximate us-east-1 cost (sandbox-funded):

| # | Command | Creates | Cost | Teardown |
|---|---|---|---|---|
| 0 | `cloud/infra/probe_sandbox.sh` | nothing (read-only) | $0 | — |
| 0b | `cloud/infra/probe_sandbox.sh --with-dry-run` (optional) | nothing (`--dry-run` permission checks) | $0 | — |
| 1 | `cloud/infra/data_plane.sh --apply` | Rekognition collection `hid-kiosk-users`; DynamoDB `hid_users`, `hid_decisions`, `hid_state` (on-demand, TTL `ttl`, SSE aws/dynamodb); S3 `hid-kiosk-<acct>-us-east-1` (SSE-KMS aws/s3 + bucket key, public access blocked, TLS-only, lifecycle 1 d on every prefix); dashboard `hid-kiosk`; alarm `hid-kiosk-post-hoc-revoked` | < $0.10/day | immediate |
| 2 | `cloud/infra/ses_setup.sh --apply --sender <a> --recipient <b>` (optional) | SES e-mail identities (verification mails) | $0 | immediate |
| 3 | `cloud/infra/deploy_ec2.sh --apply` | IAM role `hid-kiosk-ec2-role` + inline least-privilege policy + instance profile; SG `hid-kiosk-api-sg` (tcp 9000); 1× t3.small AL2023 (IMDSv2, 8 GB gp3); API Gateway HTTP API `hid-kiosk-api` | ≈ $0.027/h (~$0.27 per 10 h) | immediate |
| 4 | `cloud/.venv/bin/python -m cloud.tools.smoke --base <url> --user u_smoke_<name> --images <dir> --probe <jpg> --cleanup` | 1 enrolled test user (consenting member), deleted at the end | ~$0.01 | `--cleanup` |
| 5 | `cloud/infra/teardown.sh --apply` | deletes all of the above (incl. the face collection) | $0 | — |
| (opt) | `cloud/infra/data_plane.sh --apply --with-cmk` | customer-managed KMS key | ~$1/month prorated | **hard: AWS enforces ≥ 7-day deletion wait** — not recommended |
| (alt) | `cloud/infra/deploy_lambda.sh --apply [--pc 1]` | Lambda + role + HTTP API (only if EC2 is denied) | ≈ $0 (+$0.0075/h with PC) | immediate |

If the probe shows IAM role creation denied: step 3 becomes `deploy_ec2.sh --apply --instance-profile <pre-provisioned>`
(option A) or `--no-role` (option B), or skip AWS hosting and run the API on a laptop with the `hid-sandbox`
profile (option C) — see §5.

## 11. Lead decisions applied (rounds 1-2)

- us-east-1 only (all scripts, app default `CLOUD_AWS_REGION=us-east-1`; `AWS_REGION` is ignored by the app on purpose).
- Bundles: `issued_at = now`, `expires_at = now + 12 h`, override codes `valid_until = expires_at + 24 h`; ETag `"<version>"`.
- `/v1/sync` is the only sync path; request `{kiosk_id, batch_id, chain_head, chain_head_hmac, items ≤ 50}` (+ the
  `kiosk_now_utc` the edge sync agent already sends, used for ALERT_CLOCK_SKEW / Y09); response exactly
  `{accepted, duplicates, rejected[{idempotency_key, error}], flags[{attempt_id, type}], server_time}`.
- Rekognition only for consenting team faces; collection deleted by `teardown.sh`. Decisions are made on the edge
  (local-first); online, Rekognition is authoritative with a local cross-check (`edge/policy/identity.py`); offline or
  on cloud timeout the local matcher decides under offline bars (P7).

## 12. Latency from the build Mac (Bangalore venue Wi-Fi) to us-east-1 - no stored measurement

Rounds 1-2 (2026-11-14 ~10:05 UTC, `cloud.tools.latency`, one keep-alive HTTPS connection, `/v1/match` with a
NON-face JPEG) were run interactively and their console output was **not saved to a file**. Their numbers are
therefore **withdrawn from this document and must not go on a slide**. What the runs showed qualitatively, and what
drove the design: the server-side match time (`X-Latency-Ms`) was small compared with the client round trip, which was
dominated by RTT and heavy venue-Wi-Fi jitter. So the cloud match cannot sit on the 2 s critical path from this
network: decisions are made on the edge (local-first); online, Rekognition is authoritative with a local cross-check
(`edge/policy/identity.py`); the cloud match runs in parallel and time-boxed (early probe, §6), and offline or on cloud
timeout the local matcher decides under offline bars (P7). ap-south-1 would remove most of the RTT (estimate).

To get a quotable number, re-run and **store** the output (eval/ owner keeps the file; nearest-rank p95; this sends a
non-face JPEG only):
`cloud/.venv/bin/python -m cloud.tools.latency --base https://8c1yi8fjgj.execute-api.us-east-1.amazonaws.com --n 20 --image cloud/tools/fixtures/noface_gradient_noise.jpg | tee eval/results/cloud_latency_$(date -u +%Y%m%dT%H%MZ).txt`
Not run yet: it is step 6 of §13b (after the redeploy, which is PENDING operator approval).

### 11b. Round 3 (deployment, operator-approved) — applied
- Deployed exactly the approved list: data plane (no CMK), SES identity `studies.prajwalm@gmail.com`, EC2 t3.small +
  IAM role/instance profile + SG + API Gateway HTTP API, plus the sanctioned SSM SecureString `/hid-kiosk/app-env`.
- S3 lifecycle tightened to **1 day on every prefix** (D10), verified with `get-bucket-lifecycle-configuration`.
- Cloud seeds `config/schedule.demo.json` (u_prj1 entitled); placeholder demo card hashes are recomputed at seed time
  with `scripts/sign_bundle.py recompute_card_hashes` and the shared CARD_ID_PEPPER (verified equal to the edge's).
- Same KIOSK_HMAC_KEY / SCHEDULE_BUNDLE_HMAC_KEY / CLOUD_API_KEY as the project .env, delivered via SSM SecureString
  (instance role `ssm:GetParameter` on that parameter only); user-data and deploy log checked: no secret values.
- No face image has been sent to Rekognition (only a non-face JPEG for latency); face path = edge enrolment of u_prj1.

## 13. Data hygiene — test-fixture traffic against the live cloud (2026-11-14 10:10–10:15Z), cleaned 10:36Z

- Cause: edge pytest fixtures read the new `CLOUD_API_URL` from `.env` (edge tests now force it empty).
- Found (read-only, via `hid_decisions` scan + per-minute CloudWatch metrics; bodies are never logged):
  35 synthetic decisions in 11 batches from KIOSK_MAIN_01 (all DENY, zone `UNKNOWN`/u_3c4d `SCHEDULE_BUNDLE_INVALID`/
  `NOT_ENROLLED`, chain seq 1..7) + 2 records and 1 `ALERT_TARGETED_SPOOF` from my own 10:01Z smoke. 15 enroll-route calls
  (10 x 5xx) changed nothing: collection 0 faces / 0 users, `hid_users` empty, schedule still v42, revocation feed only u_a3b4.
- Deleted (lead-approved plan `cloud/infra/.state/cleanup_synthetic_plan.sh`: 38 conditional `delete-item`, each
  guarded by `batch_id` + `received_at` / `attempt_id`): hid_decisions 327 -> 293 while the live edge kept syncing
  (all 281 records kept at plan time still present; 0 of the 37 keys remain); alerts 27 -> 26; chain head = live edge (seq 293).
  These table counts are operational console observations from the read-only scans (only the delete plan itself is
  stored, in `.state/`); they are hygiene evidence, not metrics, and are not for slides.
- CloudWatch points are immutable: the 10:01-10:02Z and 10:10-10:15Z synthetic spike stays in the raw metrics
  (lead: dashboard uses a short time range in the demo). Code now tags everything with `Synthetic=true|false`
  (ledger item flag, metric dimension, admin aggregates exclude synthetic; smoke tools set `synthetic: true`);
  takes effect at the next blue-green redeploy (§13b, PENDING operator approval): `deploy_ec2.sh --apply --replace`, then
  `data_plane.sh --apply --skip-rekognition --skip-dynamodb --skip-s3` (dashboard + alarm filter `Synthetic="false"`),
  then `python -m cloud.tools.backfill_metrics --cutover <CUTOVER_AT from .state> --apply` (once; idempotent marker).
- Latent bug fixed in code (not deployed): `DELETE /v1/enroll/{id}` for a schedule-only user would have removed the
  user from the authoritative schedule and broadcast an ERASED revocation; now 404 unless an enrolment row exists.
  Rekognition `InvalidParameter` during enrolment -> 422 (was 503).

### 13b. Round-5 blue-green redeploy runbook - RAN (cutover 2026-11-14T17:18:00Z per `.state/deploy.env`)

**State (2026-11-15): ran**; kept for reference, the v1.4 redeploy is §13d. Original note: **State: PENDING operator approval.** The `deploy_ec2.sh --apply --replace` run from the cloud-aws agent was
**blocked by the auto-mode permission classifier** (it touches shared live infrastructure), so nothing was replaced:
the live API is still the ~09:55 UTC build and `cloud/infra/.state/deploy.env` has no `CUTOVER_AT`. Agents must not
retry it; the operator approves and runs the block below (or tells the lead to). Code readiness:
`pytest cloud/tests` -> **147 passed** (Y01-Y11 included) and ruff clean, stored run
`eval/results/tests_20261114T1705Z.txt`. Same resource types only (new t3.small
from the same role/profile/SG, API Gateway integration re-pointed, old instance terminated after cutover); the
DynamoDB store is not empty, so the seed file is ignored and the live master (v45, revocations) is kept.

```bash
cd /Users/prajwalm/Documents/hidhack/Project
export AWS_PROFILE=hid-sandbox B=https://8c1yi8fjgj.execute-api.us-east-1.amazonaws.com
aws sts get-caller-identity >/dev/null || echo "ExpiredToken -> bash tooling/aws_creds_from_clipboard.sh"
# 1. blue-green: aborts WITHOUT touching the API if the new instance is unhealthy; rolls the API back on cutover failure
bash cloud/infra/deploy_ec2.sh --apply --replace
# 2. dashboard + alarm with the Synthetic="false" filter (no data-plane resources touched)
bash cloud/infra/data_plane.sh --apply --skip-rekognition --skip-dynamodb --skip-s3
# 3. backfill once (idempotent marker)
cloud/.venv/bin/python -m cloud.tools.backfill_metrics --cutover "$(grep '^CUTOVER_AT=' cloud/infra/.state/deploy.env | cut -d= -f2)" --apply
# 4. smoke WITHOUT faces: health, signed bundle + ETag/304, sync replay -> duplicates (items tagged synthetic)
cloud/.venv/bin/python -m cloud.tools.smoke_noface --base "$B"
#    upload refusals only (stores nothing): tampered -> 403 FORBIDDEN, lower version -> 409 INVALID_STATE, ETag unchanged
cloud/.venv/bin/python -m cloud.tools.smoke_upload --base "$B"
# 5. live edge still ONLINE (read-only)
curl -sS http://127.0.0.1:8000/v1/mode | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["mode"], d["schedule_bundle"]["version"])'
# 6. /v1/match latency, 20 x non-face JPEG; STORE the output (§12) - only stored numbers may be quoted
cloud/.venv/bin/python -m cloud.tools.latency --base "$B" --n 20 --image cloud/tools/fixtures/noface_gradient_noise.jpg \
  | tee "eval/results/cloud_latency_$(date -u +%Y%m%dT%H%MZ).txt"
```

Local verification of steps 4 (scratch port 8096, fake backends, dummy keys, 2026-11-14 16:25 UTC): `smoke_upload`
PASS (403 / 409 / ETag unchanged "42"); `smoke_noface` sync 2 accepted -> replay 2 duplicates, bundle verified by the
edge verifier, 304 on If-None-Match (its health step requires real Rekognition/DynamoDB, so it reports FAIL on fakes).

### 13c. Fresh v46 bundle - steps READY, run right after §13b

**State: READY, not run.** The commands below are prepared and the tooling exists in code (`scripts/sign_bundle.py`
`--src/--version/--out/--codes-file`, mode-600 codes file; `cloud/tools/cloudcurl.py --admin`; route
`PUT /v1/admin/schedule/{kiosk_id}` in `cloud/app/routers/admin.py`). They depend on §13b because the upload route is
not in the live build (there, step (b) is refused because the route does not exist, and nothing changes). Signer stamps
`issued_at` = now, `expires_at` = now + 12 h, override `valid_until` = `expires_at` + 24 h (HMAC-SHA256,
`SCHEDULE_BUNDLE_HMAC_KEY`). If the live master has moved past v45 by then, use `--version <stored + 1>` (409 says so).

Codes are freshly generated (OVR-001..003 dropped); values go only to the mode-600 codes file. Keep `--out` /
`--codes-file` OUTSIDE `edge/data/` (the default `--out` is the live edge's `bundle.signed.json`).

```bash
cd /Users/prajwalm/Documents/hidhack/Project && B=https://8c1yi8fjgj.execute-api.us-east-1.amazonaws.com
mkdir -p -m 700 ~/.hid
# (a) source = the live authoritative master (keeps v43-v45 changes); keys read from .env, never printed
cloud/.venv/bin/python -c "import json,sys; from cloud.tools.cloudclient import CloudClient as C; r,_=C(sys.argv[1],'KIOSK_MAIN_01').request('GET','/v1/admin/schedule',admin=True); r.raise_for_status(); json.dump(r.json()['doc'],open(sys.argv[2],'w'))" "$B" ~/.hid/master_live.json
cloud/.venv/bin/python scripts/sign_bundle.py --src ~/.hid/master_live.json --version 46 \
  --out ~/.hid/bundle_v46.signed.json --codes-file ~/.hid/DEMO_CODES_v46.txt
# (b) upload: kiosk HMAC request signature + X-Admin-Token from .env (curl line shows $CLOUD_API_KEY / $ADMIN_TOKEN only)
cloud/.venv/bin/python -m cloud.tools.cloudcurl --base "$B" --admin PUT /v1/admin/schedule/KIOSK_MAIN_01 --data @"$HOME/.hid/bundle_v46.signed.json"
#     expect HTTP 200 {"bundle_version":46,"etag":"\"46\"","served":"verbatim"|"cloud_resigned",...}
#     403 = signature/scope, 409 = version not > stored (message says which --version), 422 = expired/documented codes
# (c) the edge installs it on its next 15-min refresh; check read-only:
curl -sS http://127.0.0.1:8000/v1/mode | python3 -c 'import json,sys; print(json.load(sys.stdin)["schedule_bundle"])'
```

### 13d. v1.4 admin-access redeploy + `u_prj1` re-admission - PENDING operator approval (NOT run)

**State: PENDING operator approval, prepared by cloud-aws, NOT run** (it changes shared live infrastructure; agents
must not run it). Code: `cloud/app/routers/admin.py`, `services/schedule_service.py`, `services/code_hygiene.py`,
`schemas.py`, `errors.py`, `main.py`. What changes for the live system after it:

- the Control Panel / `/register` writes work (no more `ENDPOINT_NOT_DEPLOYED`); creating a user needs `display` +
  `consent: true` (R-A); an ERASED user is re-admitted only with `consent: true` (R-B); Restore = `consent: true,
  restore: true` (R-C); revoke twice -> `409 ALREADY_REVOKED`; `reason: "ERASED"` on revocations -> 422;
- written window times are 00:00-23:59 (`24:00` -> 422), `staff_id ^s_[0-9a-z_]{2,32}$`, admin `user_id ^u_[0-9a-z]{4}$`
  (also the `GET /v1/admin/audit?user_id=` filter);
- strict booleans like the edge (`edge/access_models.py`): `consent` / `restore` (PUT access), `replace_existing`
  (codes rotate) and `force` (revocations) refuse `"true"` / `1` with 422 instead of coercing them;
  `display` / `display_name` are trimmed before the 1-80 check on `/v1/enroll` and `/v1/admin/users/{id}/contact` too;
- `READMIT` feed items carry reason `READMIT` (consented enrolment / re-admit) or `RESTORE` (Restore) only; any other
  value is refused before a seq is used (`schedule_service.READMIT_REASONS` = contract `enums.readmit_reason`);
- override-code hygiene also checks the edge's effective PBKDF2 count (max(declared, 100000)): a documented value
  can no longer pass in a bundle that declares fewer iterations. A dirty stored master gets a hygiene version bump.
- The live master keeps its data (DynamoDB is not empty: the seed is ignored). Its bundle has **no override codes**
  (leftover report: v48 with 0 codes) until someone rotates them (step 6; the plaintext is shown once).

```bash
cd /Users/prajwalm/Documents/hidhack/Project
export AWS_PROFILE=hid-sandbox B=https://8c1yi8fjgj.execute-api.us-east-1.amazonaws.com
aws sts get-caller-identity >/dev/null || echo "ExpiredToken -> bash tooling/aws_creds_from_clipboard.sh"
cloud/.venv/bin/python -m pytest cloud/tests -q            # must be green before shipping
# 1. blue-green, same backends as the last deploy (defaults: rekognition / dynamodb / ses, seed ignored on a non-empty
#    store). Do NOT pass --skip-build: build/hid-cloud.tgz (2026-11-14 17:16 UTC) predates the v1.4 code.
bash cloud/infra/deploy_ec2.sh --apply --replace
# 2. health + the new route answers (read-only)
curl -sS "$B/v1/health"; echo
cloud/.venv/bin/python -m cloud.tools.cloudcurl --base "$B" --kiosk KIOSK_MAIN_01 --admin GET /v1/admin/users \
  | tail -n +3 | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["bundle_version"], d["staff_ids"], {u["user_id"]: (u["role"], u["status"]) for u in d["users"]})'
#    expect every row to carry "status"; u_prj1 shows ERASED (or is absent if a legacy erase popped it with no revocation)
# 3. smoke without faces (health, bundle ETag/304, sync replay -> duplicates) + upload refusals
cloud/.venv/bin/python -m cloud.tools.smoke_noface --base "$B"
cloud/.venv/bin/python -m cloud.tools.smoke_upload --base "$B"
# 4. re-add u_prj1 "Prajwal M." (ROLE = the operator's choice; default student). One call: creates the entry if a legacy
#    erase removed it, and lifts the ERASED suspension (consent: true) -> feed READMIT reason READMIT
ROLE=student
cloud/.venv/bin/python -m cloud.tools.cloudcurl --base "$B" --kiosk KIOSK_MAIN_01 --admin \
  PUT /v1/admin/users/u_prj1/access --data "{\"display\":\"Prajwal M.\",\"role\":\"$ROLE\",\"consent\":true,\"actor\":\"lead\"}"
#    expect 200 {"created": true|false, "readmitted": true (if he was ERASED), "user": {"status": "ACTIVE", ...}}
#    409 USER_REVOKED -> he also holds an ADMIN revocation: repeat with "restore":true if the operator agrees
cloud/.venv/bin/python -m cloud.tools.cloudcurl --base "$B" --kiosk KIOSK_MAIN_01 GET "/v1/revocations?since=0" | tail -n 12
#    expect the last u_prj1 item: {"type": "READMIT", "target_id": "u_prj1", "reason": "READMIT"}
# 5. the live edge (lead restarts it with the v1.4 edge code first) installs the re-signed bundle now:
curl -sS -X POST http://127.0.0.1:8000/v1/admin/bundle/refresh -H "X-Admin-Token: $(grep '^ADMIN_TOKEN=' .env | cut -d= -f2-)"; echo
#    alternative to step 4 once the v1.4 edge is live (one call: cloud PUT + bundle install + feed pull):
#    curl -sS -X PUT http://127.0.0.1:8000/v1/admin/access/users/u_prj1 -H 'Content-Type: application/json' \
#      -H "X-Admin-Token: $(grep '^ADMIN_TOKEN=' .env | cut -d= -f2-)" \
#      --data "{\"display\":\"Prajwal M.\",\"role\":\"$ROLE\",\"consent\":true,\"actor\":\"lead\"}"
# 6. staff override codes: rotate from the Control Panel (Staff codes -> s_guard01), plaintext shown ONCE; or here
#    (prints the codes to this terminal only; replace_existing drops s_guard01's older codes):
#    cloud/.venv/bin/python -m cloud.tools.cloudcurl --base "$B" --kiosk KIOSK_MAIN_01 --admin POST /v1/admin/codes/rotate \
#      --data '{"staff_id":"s_guard01","count":4,"actor":"lead"}'
```

After step 4 `u_prj1` is entitled again but has **no faces in Rekognition** if the earlier erasure deleted them: he
re-enrols with consent while ONLINE via `/register` (the kiosk offers "Re-admit and enrol"), which indexes new faces.
Rollback: `deploy_ec2.sh --replace` aborts without touching the API if the new instance is unhealthy and rolls the
integration back if the cutover check fails; the data plane (DynamoDB master, Rekognition) is not changed by step 1.
