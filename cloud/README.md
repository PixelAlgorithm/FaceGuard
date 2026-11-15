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
The edge points at it with `CLOUD_API_URL=http://127.0.0.1:9000` (same kiosk key / `CLOUD_API_KEY` in `.env`).

## Authentication and roles (design v2 §E)

- **Kiosk HMAC on every route** (except health): per-kiosk keys in `KIOSK_KEYS_JSON` (`{kiosk_id: key}`). The single
  shared `KIOSK_HMAC_KEY` is used only with `ALLOW_SHARED_KIOSK_KEY=1` (one leaked kiosk `.env` would otherwise
  impersonate every kiosk); startup fails when neither is configured.
- **Admin routes** (`/v1/admin/*`) additionally need an API key: `Authorization: Bearer fgk_<key_id>.<secret>`, looked up
  in `CLOUD_API_KEYS_JSON` = `[{key_id, sha256 (of the secret part), roles, name, kiosk_ids?, expires_at?}]`. Mint one
  with `cloud/.venv/bin/python -m cloud.tools.apikey --name X --roles admin` (prints the key once + the JSON entry).
  Roles come from `edge/auth/rbac.py` `CLOUD_ROLES` (imported, never copied; the app refuses to start without it):
  `admin` (all, plus `outbox:read` only while `EMAIL_BACKEND=fake`), `edge_proxy` (`schedule:read`, `access:read`,
  `access:edit`, `revocations:write`, `codes:rotate`; must list exactly one `kiosk_id` = the HMAC kiosk), `auditor`
  (read-only). Route -> permission table: `cloud/app/rbac.py` `ROUTE_PERMISSIONS` (`tests/test_rbac.py` walks it).
- If an `Authorization` header is present it alone decides. `X-Admin-Token` (legacy, role admin, actor
  `legacy:admin_token`) works only with `AUTH_LEGACY_ADMIN_TOKEN=1`; `ADMIN_TOKEN` is required only then.
- Every admin-credential failure is **403 FORBIDDEN** (401 = kiosk HMAC failed) with `error.reason`
  `ADMIN_KEY_INVALID | ADMIN_KEY_EXPIRED | MISSING_PERMISSION` (+ `error.required`) `| KIOSK_NOT_BOUND | LEGACY_DISABLED`.
- **Actor**: an `edge_proxy` key may assert the human (`actor` in the signed body, `?actor=` on DELETE), pattern
  `^(staff:s_[0-9a-z_]{2,32}|key:[a-z0-9]{8}|legacy:admin_token)$` (else 422 `ACTOR_INVALID`); stored with
  `actor_assurance: edge_asserted`, `via: key:<key_id>`, `kiosk_id`, never used for authorisation. Other keys are
  audited as `key:<key_id>` (client value ignored). `POST/DELETE /v1/enroll` and `POST /v1/enroll/offline-record` stay
  device-scoped (kiosk HMAC) and record the asserted actor the same way.
- `GET /v1/admin/schedule` redacts override-code `hash` / `salt` unless the caller also holds `schedule:write`.
- `OTP_PEPPER` is required unless `STORE_BACKEND=memory`. The replay guard lives in the KV store (ns `replay`, TTL),
  so it holds across workers / instances; a store outage answers 503 `CLOUD_UNAVAILABLE`, never a misleading 401.

**Fake faces** (`FACE_BACKEND=fake`): identity comes from a marker inside the JPEG, never from biometrics —
`python -m cloud.tools.fakeimg "u_3c4d" a.jpg`, `"u_3c4d=97.5;u_1a2b=85"` (runner-up), `NOFACE`.
Unmarked images only match byte-identical enrolment frames. Fake OTP codes: `GET /v1/admin/fake/outbox`.

## Endpoints (docs/API.md §4)

| Method + path | Auth | Purpose |
|---|---|---|
| `GET /v1/health` (`/health`) | public | `{status, rekognition, dynamodb, region, store, policy, server_time, deploy_stamp…}` from a cached probe (answers in ms; edge heartbeat). `deploy_stamp` = `HID_DEPLOY_STAMP` (`YYYYMMDDTHHMMSSZ`, set by the deploy; used by `deploy_ec2.sh --replace`) |
| `POST /v1/match` | kiosk | Rekognition `SearchUsersByImage` (UserMatchThreshold 80, MaxUsers 2, QualityFilter AUTO from thresholds.yaml) or 1:1 (`claimed_user_id`); raw 0–100 similarity + runner-up; throttled → one jittered retry within `MATCH_BUDGET_MS` (900) else `503 UPSTREAM_THROTTLED` |
| `POST /v1/enroll` | kiosk | JSON `{meta…, images_b64[]}` (edge client) or multipart `frame_N` + `meta`: IndexFaces ×N → validate → CreateUser → AssociateFaces (new faces only). Re-enrolment **appends** like the edge (cap `ENROLL_MAX_FACES_PER_USER`=24; the original enrolment's own faces, at most `ENROLL_PINNED_FACES`=5, are never evicted); a failed enrolment changes nothing (its own faces are removed again); a face that does not match the existing user (AssociateFaces `UserMatchThreshold` 80) → 409. No replace path: erase, then enrol. `consent: true` required, `email` optional, `display_name` 1–80 after trimming. The request `role` is echoed (`requested_role`) but never applied: the response carries `schedule_role` (the signed schedule's), `role_applied`, `readmitted` (an ERASED suspension lifted, feed `READMIT` reason `READMIT`); `totp_enrolled` / `provision_totp` only set the schedule's `fallback.totp_enrolled` flag (the edge owns TOTP secrets; the cloud never mints a seed) |
| `DELETE /v1/enroll/{user_id}?actor=` | kiosk | DPDP erasure of an ENROLLED user: row face ids ∪ ListFaces(user) → DeleteUser + DeleteFaces (any face Rekognition refuses to delete → 503 `ERASE_INCOMPLETE`, nothing else changes) → reference image → `ERASED` bundle revocation → row deleted LAST (a failure leaves the row, the retry finishes). The schedule entry (entitlement) stays suspended (the edge purges templates + TOTP on it) until a consented re-enrolment or an admin re-admit; the feed gets a non-deny `ERASE` item. Users without an enrolment row → 404 reason `NOT_ENROLLED`, nothing changes |
| `POST /v1/enroll/offline-record` | kiosk | an edge enrolled a face while offline: `{user_id, kiosk_id, at, template_count, model, actor?}` (no images) → 201 recorded / 200 duplicate (idempotent on kiosk+user+at), audit `OFFLINE_ENROLMENT`; that user's offline ALLOWs are flagged `OFFLINE_TEMPLATE_UNCONFIRMED` until a cloud enrolment indexes a face |
| `GET /v1/schedule/{kiosk_id}` | kiosk (own id) | signed bundle in `config/schedule.example.json` format, filtered to the kiosk's zone + candidate users (revoked kept); `issued_at=now`, `expires_at=now+12 h`, override `valid_until=expires_at+24 h`; signed `consumed_code_ids` (override codes used by a synced `STAFF_OVERRIDE` ALLOW, until their valid_until); a staff_id's codes only reach its owner kiosk's bundle. `ETag: "v<version>-<issued_at epoch>"`; 304 only on the full ETag; the same stamps are reused for ttl/2, then the bundle is re-issued (200) so online kiosks never age towards expiry |
| `GET /v1/revocations?since=N` | kiosk | `{as_of, revocation_seq, items[{seq,type,target_id,revoked_at,reason}]}`; `revocation_seq` is the watermark up to which every event is visible (never jumps over an in-flight write; gaps older than 120 s are burnt seqs) |
| `POST /v1/sync` | kiosk | idempotent decision ingest (below) |
| `POST /v1/otp/send` · `/v1/otp/verify` | kiosk | SES e-mail OTP: 6 digits, 300 s, 3 attempts, keyed hash only, single use, resend ≥ 30 s (a resend invalidates the attempt's previous code), ≤ 5 codes per user per hour (429 `OTP_SEND_CAP`); stored before the mail is sent; mailer failure → 503 reason `EMAIL_UNAVAILABLE` (edge → TOTP) |
| `POST /v1/liveness/session` · `GET …/{id}/result` | kiosk | optional Face Liveness step-up (5 TPS / 15 concurrent caps); `verified = conf ≥ 80 ∧ 1:1 ≥ 99` |
| `POST /v1/schedule/check` | kiosk | optional authoritative SC1 check via the shared evaluator (edge decided not to call it per attempt) |
| `/v1/admin/schedule` (GET/PUT) · `PUT /v1/admin/schedule/{kiosk_id}` · `POST /v1/admin/revocations` · `GET /v1/admin/alerts` · `GET /v1/admin/decisions` · `GET /v1/admin/stats` · `GET /v1/admin/metrics` · `PUT /v1/admin/users/{id}/contact` · `GET /v1/admin/fake/outbox` | kiosk + admin key | demo control: edit the master, upload an operator-signed kiosk bundle (served verbatim), revoke during an outage (`USER` / `CARD`; reason `ERASED` → 422, already revoked → `409 ALREADY_REVOKED`, unknown user → `404 UNKNOWN_USER` unless `force: true`), SC2.6 alerts / ledger / aggregates (synthetic test traffic excluded unless `?include_synthetic=true`), in-memory metrics, contact e-mail without biometrics, fake-mailer outbox |
| `GET /v1/admin/users` | kiosk + admin key | Control Panel list (v1.4, docs/API.md §4.9a): master roles / zones / kiosks / `staff_ids` + every user `{user_id, display, role, in_schedule, status ACTIVE·REVOKED·ERASED·NOT_IN_SCHEDULE, zones_add, extra_windows, valid_from/until, fallback, enrolled, faces, consent_version}`; no card hashes, secrets or faces |
| `PUT /v1/admin/users/{user_id}/access` | kiosk + admin key | create (`display` + `consent: true`) / edit role, zones, extra windows, validity / re-admit an ERASED user (`consent: true` → feed `READMIT` reason `READMIT`) / Restore a REVOKED user (`consent: true, restore: true` → feed `READMIT` reason `RESTORE`). `user_id ^u_[0-9a-z]{4}$`, `extra="forbid"`, `consent` / `restore` strict booleans; every change bumps `bundle_version` + audit entry (`USER_CREATE` / `ACCESS_UPDATE` / `READMIT` / `RESTORE`); identical request → `unchanged: true` |
| `POST /v1/admin/codes/rotate` | kiosk + admin key | mint `count` (1–10, default 4) one-time staff override codes (thresholds `code_length` = 10 digits) for `staff_id ^s_[0-9a-z_]{2,32}$`; plaintext returned ONCE (`Cache-Control: no-store`), only PBKDF2 hashes enter the schedule; `replace_existing` (strict boolean, default true) drops the staff member's older codes; every dropped id is in `dropped_code_ids` + the audit entry. The staff_id belongs to the first kiosk that rotates it (another kiosk → 409 `STAFF_ID_TAKEN`); ≤ 10 active codes per staff_id (422 `TOO_MANY_ACTIVE_CODES`); bumps `bundle_version` |
| `GET /v1/admin/audit?limit=&user_id=` | kiosk + admin key | access-administration ledger (who = calling `kiosk_id` + `actor` + `actor_assurance` + `via`, what, when; never code values; also `SCHEDULE_UPLOAD`, `CONTACT_UPDATE`, `CODE_CONSUMED`, `ENROL`, `ERASE`, `OFFLINE_ENROLMENT`); `user_id` filter `^u_[0-9a-z]{4}$`; entries kept 30 days |

Every response carries `X-Latency-Ms` and `X-Server-Time` (also 401 / 413 / 500 / 503, built by the middleware; a
declared `Content-Length` over `MAX_BODY_BYTES` is refused before the body is read). Errors: `{"error": {"code", "message", "attempt_id"}}`,
plus a machine-readable `reason` on domain errors (docs/API.md §3.18.6; validation errors never echo input).
Admin field limits (R-H) are the edge's (`edge/access_models.py` is the reference; contract
`docs/contracts/admin_access.examples.json`, checked by `tests/test_contract_admin_access.py`). OpenAPI docs only with `CLOUD_ENABLE_DOCS=1`.

## Contracts the edge must match (verified by `tests/test_edge_contract.py` against `edge/offline/*`)

- **Request signing** (`cloud/app/auth.py`, stdlib): `X-Signature = hex HMAC-SHA256(key, "METHOD\nPATH\nX-Timestamp\nhex(sha256(body))")`,
  key = the `.env` string **UTF-8-encoded (not hex-decoded)**; PATH = URL path + `?query` when there is one (a bare-path
  signature for a request with a query is refused; transition switch `CLOUD_ACCEPT_BARE_PATH_SIG=1`);
  ±60 s; non-GET requests are single-use within the window except the idempotent `/v1/sync` → re-sign retries.
  A kiosk with a drifting clock should sign with `local + (X-Server-Time − local)`.
- **Bundle signature**: `{"alg":"HMAC-SHA256","key_id":"demo-k1","value": hex}` over
  `json.dumps(bundle_without_signature, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode()`, key `SCHEDULE_BUNDLE_HMAC_KEY` (UTF-8).
- **Sync** request `{kiosk_id, batch_id, kiosk_now_utc?, chain_head, chain_head_hmac, items ≤ 50}`; items = SC2.5 record +
  `type:"DECISION"` + `idempotency_key` (= attempt_id) + `hmac` (HMAC over canonical item without `hmac`), or
  `{type:"TOMBSTONE", idempotency_key, count, first_seq, last_seq, chain_head, hmac}`.
  Response exactly `{accepted, duplicates, rejected[{idempotency_key, error}], flags[{attempt_id, type}], server_time}`;
  flag types `POST_HOC_REVOKED | SCHEDULE_CHANGED | RECORDS_PURGED_UNSYNCED | OFFLINE_TEMPLATE_UNCONFIRMED`; a
  `DUPLICATE` returns the flags of the first delivery. `?verbose=true` adds `alerts` (SC2.6 alert names + severity),
  `acks` (verdict CONFIRMED / DISCREPANCY / MANUAL_REVIEW (offline A3 staff override without user_id) / NOT_REQUIRED /
  NOT_EVALUATED), `conflicts`. Decisions are keyed `<kiosk_id>|<attempt_id>`; the same key with different content → stored
  as a conflict variant, `ALERT_SYNC_CONFLICT`, listed in `duplicates` (safe to purge). One malformed item is rejected on
  its own (never a 500); a body that is not JSON (or absurdly nested) → 400. A seq gap not covered by a tombstone →
  `ALERT_CHAIN_GAP`; an unhashed record from a kiosk with a chain → `ALERT_LOG_TAMPER` (records are still ingested). Items with strings > 512 chars or
  numeric arrays > 64 (images/embeddings) are rejected. Offline ALLOWs are re-evaluated with
  `edge.policy.schedule.evaluate_schedule` on the authoritative document at the skew-corrected decision time.

## Deploy (only after the lead's approval; every script defaults to PLAN = prints commands, no AWS calls)

```bash
cloud/infra/probe_sandbox.sh                     # read-only permission map (exit 3 on expired creds)
cloud/infra/data_plane.sh --apply                # collection, 3 DynamoDB tables (TTL), S3 (SSE-KMS, 1-day lifecycle on every prefix), dashboard, alarm
cloud/infra/ses_setup.sh --apply --sender a@x --recipient b@y   # optional e-mail OTP
cloud/infra/deploy_ec2.sh --apply --seed-schedule config/<file>.json   # (or --demo) t3.small + instance profile + API Gateway HTTPS
cloud/.venv/bin/python -m cloud.tools.smoke --base https://<api-id>.execute-api.us-east-1.amazonaws.com \
    --user u_smoke_<name> --images <consented-frames-dir> --probe <consented.jpg> --cleanup
cloud/infra/teardown.sh --apply --confirm hid-kiosk   # typed confirmation; deletes everything incl. the face collection
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
Degraded flags: `--instance-profile NAME` (pre-provisioned; `--no-role` was removed: use it or laptop hosting),
`--face disabled`, `--store sqlite --ephemeral-ok`, `--email disabled`, `--no-apigw --tls selfsigned` (edge pins
`cloud/infra/.state/cloud-cert.pem`). The smoke / smoke_noface / smoke_upload / latency / cloudcurl tools need `--live`
for any non-loopback `--base`; their admin calls send `Authorization: Bearer $FG_CLOUD_ADMIN_KEY` (X-Admin-Token only
with `FG_ALLOW_LEGACY_ADMIN_TOKEN=1`). Details: `SANDBOX.md` §14.
Alternative host: `cloud/infra/deploy_lambda.sh` (zip, python3.11, API Gateway; not recommended for the 2 s path).
`cloud/infra/build_artifact.sh` vendors pinned manylinux wheels and copies `edge/policy` + `edge/offline` (same
evaluator as the kiosk) and the allowlist `edge/auth/{__init__,rbac,tokens}.py` (RBAC catalog), and fails the build if
`import edge.auth.rbac, cloud.app.main` fails in the stage.

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
