# cloud/ — HID kiosk cloud API (FastAPI) + AWS infra

Owner: `cloud-aws`. Sandbox region **us-east-1** (Workshop Studio; production target ap-south-1).
Sandbox findings, hosting decision and degraded modes: [`SANDBOX.md`](SANDBOX.md).

Identity authority: decisions are made on the edge (local-first); online, Rekognition is authoritative with a local
cross-check (`edge/policy/identity.py`); offline or on cloud timeout the local matcher decides under offline bars (P7).
Deployment state: live API = the 2026-11-14 ~09:55 UTC build; the blue-green redeploy with the newer code
(`SANDBOX.md` §13b) is **PENDING operator approval** (blocked by the auto-mode permission classifier, not run), and
the fresh v46 bundle sign + upload (§13c) is ready to run after it.

## Run locally (no AWS needed)

```bash
cd <project root>
uv sync --project cloud --group dev                                # once (Python 3.11)
cloud/.venv/bin/python -m cloud.tools.ensure_env                    # adds CLOUD_API_KEY/OTP_PEPPER/CLOUD_DATA_KEY to .env (values never printed)
cloud/.venv/bin/python -m uvicorn cloud.app.main:app --host 127.0.0.1 --port 9000
cloud/.venv/bin/python -m cloud.tools.smoke --base http://127.0.0.1:9000 --cleanup   # done-criteria smoke
cloud/.venv/bin/python -m pytest cloud/tests -q                     # incl. Y01-Y11 + edge contract; last stored run: eval/results/tests_20261114T1705Z.txt (147 passed)
```
Defaults are local fakes: `FACE_BACKEND=fake STORE_BACKEND=memory EMAIL_BACKEND=fake BLOB_BACKEND=memory
METRICS_SINK=memory`. Persist locally with `STORE_BACKEND=sqlite` (`SQLITE_PATH`, file mode 0600).
The edge points at it with `CLOUD_API_URL=http://127.0.0.1:9000` (same `KIOSK_HMAC_KEY`/`CLOUD_API_KEY` in `.env`).

**Fake faces** (`FACE_BACKEND=fake`): identity comes from a marker inside the JPEG, never from biometrics —
`python -m cloud.tools.fakeimg "u_3c4d" a.jpg`, `"u_3c4d=97.5;u_1a2b=85"` (runner-up), `NOFACE`.
Unmarked images only match byte-identical enrolment frames. Fake OTP codes: `GET /v1/admin/fake/outbox`.

## Endpoints (docs/API.md §4)

| Method + path | Auth | Purpose |
|---|---|---|
| `GET /v1/health` (`/health`) | public | `{status, rekognition, dynamodb, region, store, policy, server_time…}` from a cached probe (answers in ms; edge heartbeat) |
| `POST /v1/match` | kiosk | Rekognition `SearchUsersByImage` (UserMatchThreshold 80, MaxUsers 2, QualityFilter AUTO from thresholds.yaml) or 1:1 (`claimed_user_id`); raw 0–100 similarity + runner-up; throttled → one jittered retry within `MATCH_BUDGET_MS` (900) else `503 UPSTREAM_THROTTLED` |
| `POST /v1/enroll` | kiosk | JSON `{meta…, images_b64[]}` (edge client) or multipart `frame_N` + `meta`: IndexFaces ×N → validate → CreateUser → AssociateFaces (new faces only). Re-enrolment **appends** like the edge (cap `ENROLL_MAX_FACES_PER_USER`=24, first `ENROLL_PINNED_FACES`=5 never evicted); a failed enrolment changes nothing (its own faces are removed again); a face that does not match the existing user (AssociateFaces `UserMatchThreshold` 80) → 409. No replace path: erase, then enrol. `consent: true` required, `email` optional, `display_name` 1–80 after trimming. The request `role` is echoed (`requested_role`) but never applied: the response carries `schedule_role` (the signed schedule's), `role_applied`, `readmitted` (an ERASED suspension lifted, feed `READMIT` reason `READMIT`); `totp_enrolled` / `provision_totp` only set the schedule's `fallback.totp_enrolled` flag (the edge owns TOTP secrets; the cloud never mints a seed) |
| `DELETE /v1/enroll/{user_id}` | kiosk | DPDP erasure of an ENROLLED user: row face ids ∪ ListFaces(user) → DeleteUser + DeleteFaces + row (+ reference image). The schedule entry (entitlement) stays, suspended by an `ERASED` bundle revocation (the edge purges templates + TOTP on it) until a consented re-enrolment or an admin re-admit; the feed gets a non-deny `ERASE` item. Users without an enrolment row -> 404, nothing changes |
| `GET /v1/schedule/{kiosk_id}` | kiosk (own id) | signed bundle in `config/schedule.example.json` format, filtered to the kiosk's zone + candidate users (revoked kept); `issued_at=now`, `expires_at=now+12 h`, override `valid_until=expires_at+24 h`; `ETag: "<version>"`, `If-None-Match` → 304 |
| `GET /v1/revocations?since=N` | kiosk | `{as_of, revocation_seq, items[{seq,type,target_id,revoked_at,reason}]}` |
| `POST /v1/sync` | kiosk | idempotent decision ingest (below) |
| `POST /v1/otp/send` · `/v1/otp/verify` | kiosk | SES e-mail OTP: 6 digits, 300 s, 3 attempts, keyed hash only, single use, resend ≥ 30 s; SES failure → 503 (edge → TOTP) |
| `POST /v1/liveness/session` · `GET …/{id}/result` | kiosk | optional Face Liveness step-up (5 TPS / 15 concurrent caps); `verified = conf ≥ 80 ∧ 1:1 ≥ 99` |
| `POST /v1/schedule/check` | kiosk | optional authoritative SC1 check via the shared evaluator (edge decided not to call it per attempt) |
| `/v1/admin/schedule` (GET/PUT) · `PUT /v1/admin/schedule/{kiosk_id}` · `POST /v1/admin/revocations` · `GET /v1/admin/alerts` · `GET /v1/admin/decisions` · `GET /v1/admin/stats` · `GET /v1/admin/metrics` · `PUT /v1/admin/users/{id}/contact` · `GET /v1/admin/fake/outbox` | kiosk + `X-Admin-Token` | demo control: edit the master, upload an operator-signed kiosk bundle (served verbatim), revoke during an outage (`USER` / `CARD`; reason `ERASED` → 422, already revoked → `409 ALREADY_REVOKED`, unknown user → `404 UNKNOWN_USER` unless `force: true`), SC2.6 alerts / ledger / aggregates (synthetic test traffic excluded unless `?include_synthetic=true`), in-memory metrics, contact e-mail without biometrics, fake-mailer outbox |
| `GET /v1/admin/users` | kiosk + `X-Admin-Token` | Control Panel list (v1.4, docs/API.md §4.9a): master roles / zones / kiosks / `staff_ids` + every user `{user_id, display, role, in_schedule, status ACTIVE·REVOKED·ERASED·NOT_IN_SCHEDULE, zones_add, extra_windows, valid_from/until, fallback, enrolled, faces, consent_version}`; no card hashes, secrets or faces |
| `PUT /v1/admin/users/{user_id}/access` | kiosk + `X-Admin-Token` | create (`display` + `consent: true`) / edit role, zones, extra windows, validity / re-admit an ERASED user (`consent: true` → feed `READMIT` reason `READMIT`) / Restore a REVOKED user (`consent: true, restore: true` → feed `READMIT` reason `RESTORE`). `user_id ^u_[0-9a-z]{4}$`, `extra="forbid"`, `consent` / `restore` strict booleans; every change bumps `bundle_version` + audit entry (`USER_CREATE` / `ACCESS_UPDATE` / `READMIT` / `RESTORE`); identical request → `unchanged: true` |
| `POST /v1/admin/codes/rotate` | kiosk + `X-Admin-Token` | mint `count` (1–10, default 4) one-time staff override codes for `staff_id ^s_[0-9a-z_]{2,32}$`; plaintext returned ONCE (`Cache-Control: no-store`), only PBKDF2 hashes enter the schedule; `replace_existing` (strict boolean, default true) drops the staff member's older codes; bumps `bundle_version` |
| `GET /v1/admin/audit?limit=&user_id=` | kiosk + `X-Admin-Token` | access-administration ledger (who = calling `kiosk_id` + forwarded `actor`, what, when; never code values); `user_id` filter `^u_[0-9a-z]{4}$`; entries kept 30 days |

Every response carries `X-Latency-Ms` and `X-Server-Time`. Errors: `{"error": {"code", "message", "attempt_id"}}`,
plus a machine-readable `reason` on domain errors (docs/API.md §3.18.6; validation errors never echo input).
Admin field limits (R-H) are the edge's (`edge/access_models.py` is the reference; contract
`docs/contracts/admin_access.examples.json`, checked by `tests/test_contract_admin_access.py`). OpenAPI docs only with `CLOUD_ENABLE_DOCS=1`.

## Contracts the edge must match (verified by `tests/test_edge_contract.py` against `edge/offline/*`)

- **Request signing** (`cloud/app/auth.py`, stdlib): `X-Signature = hex HMAC-SHA256(key, "METHOD\nPATH\nX-Timestamp\nhex(sha256(body))")`,
  key = the `.env` string **UTF-8-encoded (not hex-decoded)**; PATH = URL path (with or without `?query`, both accepted);
  ±60 s; non-GET requests are single-use within the window except the idempotent `/v1/sync` → re-sign retries.
  A kiosk with a drifting clock should sign with `local + (X-Server-Time − local)`.
- **Bundle signature**: `{"alg":"HMAC-SHA256","key_id":"demo-k1","value": hex}` over
  `json.dumps(bundle_without_signature, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode()`, key `SCHEDULE_BUNDLE_HMAC_KEY` (UTF-8).
- **Sync** request `{kiosk_id, batch_id, kiosk_now_utc?, chain_head, chain_head_hmac, items ≤ 50}`; items = SC2.5 record +
  `type:"DECISION"` + `idempotency_key` (= attempt_id) + `hmac` (HMAC over canonical item without `hmac`), or
  `{type:"TOMBSTONE", idempotency_key, count, first_seq, last_seq, chain_head, hmac}`.
  Response exactly `{accepted, duplicates, rejected[{idempotency_key, error}], flags[{attempt_id, type}], server_time}`;
  flag types `POST_HOC_REVOKED | SCHEDULE_CHANGED | RECORDS_PURGED_UNSYNCED`. `?verbose=true` adds `alerts` (SC2.6 alert
  names + severity), `acks` (verdict CONFIRMED/DISCREPANCY), `conflicts`. Same attempt_id with different content → stored
  as a conflict variant, `ALERT_SYNC_CONFLICT`, listed in `duplicates` (safe to purge). Items with strings > 512 chars or
  numeric arrays > 64 (images/embeddings) are rejected. Offline ALLOWs are re-evaluated with
  `edge.policy.schedule.evaluate_schedule` on the authoritative document at the skew-corrected decision time.

## Deploy (only after the lead's approval; every script defaults to PLAN = prints commands, no AWS calls)

```bash
cloud/infra/probe_sandbox.sh                     # read-only permission map (exit 3 on expired creds)
cloud/infra/data_plane.sh --apply                # collection, 3 DynamoDB tables (TTL), S3 (SSE-KMS, 1-day lifecycle on every prefix), dashboard, alarm
cloud/infra/ses_setup.sh --apply --sender a@x --recipient b@y   # optional e-mail OTP
cloud/infra/deploy_ec2.sh --apply                # t3.small + instance profile + API Gateway HTTPS  (recommended)
cloud/.venv/bin/python -m cloud.tools.smoke --base https://<api-id>.execute-api.us-east-1.amazonaws.com \
    --user u_smoke_<name> --images <consented-frames-dir> --probe <consented.jpg> --cleanup
cloud/infra/teardown.sh --apply                  # deletes everything incl. the face collection
```
Face-free deployed checks (no face image is sent; third-party faces are personal data):
```bash
cloud/.venv/bin/python -m cloud.tools.smoke_noface --base <url>          # health, signed bundle (edge verifier), sync replay
cloud/.venv/bin/python -m cloud.tools.smoke_noface --base <url> --otp-user u_prj1 --otp-email <verified>   # + SES OTP
cloud/.venv/bin/python -m cloud.tools.latency --base <url> --n 20 --image cloud/tools/fixtures/noface_gradient_noise.jpg \
    | tee eval/results/cloud_latency_$(date -u +%Y%m%dT%H%MZ).txt   # p50/p95; only stored output may be quoted
```
Secrets on EC2: SSM SecureString `/hid-kiosk/app-env` (aws/ssm key, standard tier), read at boot with the instance
role (`ssm:GetParameter` on that one parameter); never in user-data, logs or stdout.
Degraded flags: `--instance-profile NAME` (pre-provisioned), `--no-role` (sqlite, no Rekognition/SES),
`--face disabled`, `--store sqlite`, `--email disabled`, `--no-apigw --tls selfsigned` (edge pins `cloud/infra/.state/cloud-cert.pem`).
Alternative host: `cloud/infra/deploy_lambda.sh` (zip, python3.11, API Gateway; not recommended for the 2 s path).
`cloud/infra/build_artifact.sh` vendors pinned manylinux wheels and copies `edge/policy` + `edge/offline` so the cloud
runs the same evaluator as the kiosk.

## Privacy / security (DPDP Act 2023 talking points)

No face image is stored by default (`ENROLL_STORE_REFERENCE=false`), and S3 upload of decision/audit frames is
**not implemented** (the bucket only carries deploy artifacts; its 1-day lifecycle already covers `audit/`). Rekognition keeps only face/user vectors of
consenting team members and `teardown.sh` deletes the collection. Decisions/alerts TTL 7 d, OTP TTL ≈ 1 h, S3 lifecycle
1 day on every prefix, SSE-KMS with AWS-managed keys, TLS-only bucket policy, public access
blocked. Secrets live only in `.env` (gitignored) and reach EC2 via the SSM SecureString above.
TOTP seeds are persisted only encrypted (KMS or Fernet `CLOUD_DATA_KEY`). Logs never contain bodies, images or codes.

## Synthetic (test / smoke) traffic

Sync items with `"synthetic": true`, an attempt id starting with `att_smoke_` / `att_test_` / `att_lat_`
(`SYNTHETIC_ATTEMPT_PREFIXES`) or a kiosk in `SYNTHETIC_KIOSKS` are stored (idempotency still holds) but flagged
`synthetic: true`; their metrics carry `Synthetic=true`, they never feed the spoof-burst detector, and admin
aggregates and the dashboard (`Synthetic="false"`) exclude them. Never point test suites at the live
`CLOUD_API_URL`; use the local fake (`uvicorn cloud.app.main:app`, default backends).
