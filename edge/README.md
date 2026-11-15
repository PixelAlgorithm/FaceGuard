# edge/ - local edge service (FastAPI): perception layer + API

Local-first: liveness + local face match + policy decision run on the kiosk laptop and work
offline. `edge/policy/` and `edge/offline/` are owned by the policy-engine; everything else here
is perception + API glue. Thresholds come only from `config/thresholds.yaml`.

## 1. Start (from the project root)

```bash
bash scripts/fetch_models.sh                      # once: weights + PAD fixtures -> models/ (SHA-256 pinned)
# once: the first admin account (prompts for the password twice; --mfa enrols TOTP right away)
edge/.venv/bin/python -m edge.auth create-user --username <name> --display-name "<Full Name>" --role admin --mfa
edge/.venv/bin/python -m uvicorn edge.app:app --host 127.0.0.1 --port 8000
```

There is no shared admin password any more: every privileged route needs a staff session or an API key
(section 1a). Bootstrap the first admin with the CLI above before the first start (the CLI also works while
the edge runs; it uses a cross-process file lock). Until an account exists, `GET /v1/auth/status` reports
`store: EMPTY`. The username must match `^[a-z][a-z0-9_]{1,30}$` and must not be a reserved name (admin,
root, administrator, sa, test, demo, system, kiosk); new passwords need at least 12 characters.

Startup takes about 1.5 s on the M4 laptop. It loads and warms every model, runs the mandatory
MiniFASNet self-test (section 4), loads the encrypted template cache and starts the policy-engine's
`PolicyRuntime` (`edge/policy/runtime.py`, signed bundle `edge/data/bundle.signed.json`). It then
logs `edge ready: ... pad_self_test=True runtime=real lan_port=8001`. At startup the edge also sets
`EDGE_DATA_DIR` to 0700 and its files to 0600 (logged when it had to change them), and builds the staff
auth service. An invalid `AUTH_*` setting (for example `AUTH_LEGACY_ADMIN_TOKEN=1` with an empty
`ADMIN_TOKEN`) stops the edge from starting, with the variable named in the error.

Fail-secure: if the runtime cannot be imported or constructed, `FailSecureRuntime` is used instead.
It answers every attempt with DENY `SYSTEM_ERROR`, and `/v1/health` `detail.policy_runtime` reports
`fail_secure`. There is no permissive fallback policy.

With `EDGE_LAN_PORT=8001` set in `.env`, a second listener on `0.0.0.0:8001` serves **only**
`GET /v1/depth/pending` and `POST /v1/depth/frames` for the DepthProbe iPhone app (section 6). The
edge binds this socket itself, so a busy port is logged (`detail.lan_listener = bind_failed`) and
the kiosk API on 127.0.0.1:8000 keeps running. The LAN app has no other route (`/v1/auth/*` is 404 there).

**Trust boundary.** RBAC protects the HTTP surface only. The edge OS account and its `.env` are fully
trusted: whoever can read them holds every edge secret and the cloud `edge_proxy` key. So:

- run the edge as a dedicated OS user that owns `.env` (mode 0600) and `EDGE_DATA_DIR` (mode 0700);
- run the public kiosk browser as a different, non-admin OS user in locked kiosk mode (no `file://`,
  devtools or downloads);
- open the staff consoles (`/admin`, `/operator`, `/register`) in a separate browser profile.

A group- or world-accessible project `.env` (mode & 0o077) puts `env_file_permissive` in `/v1/health`
`degraded_reasons`.

**New environment variables** (all documented in the root `.env.example`):

| variable | meaning |
|---|---|
| `AUTH_LEGACY_ADMIN_TOKEN` | default `0`. `1` also accepts the deprecated `X-Admin-Token: $ADMIN_TOKEN` (section 1a). |
| `AUTH_SESSION_IDLE_MIN`, `AUTH_SESSION_MAX_HOURS` | staff session idle timeout (default 30 min) and absolute lifetime (default 12 h) |
| `AUTH_MAX_SESSIONS_PER_USER` | concurrent sessions per account (default 5) |
| `AUTH_LOCKOUT_THRESHOLD`, `AUTH_LOCKOUT_MIN` | failed sign-ins before the progressive per-username delay starts (default 5) and its cap (default 15 min) |
| `AUTH_LOGIN_GLOBAL_MAX`, `AUTH_LOGIN_GLOBAL_WINDOW_MIN` | all sign-in attempts per window before 429 `RATE_LIMITED` (default 60 per 5 min) |
| `AUTH_MFA_REQUIRED_ROLES` | roles that must enrol TOTP first (default `admin,security_officer`; `none` disables) |
| `AUTH_AUDIT_MAX_BYTES`, `AUTH_AUDIT_KEEP` | rotation of `<EDGE_DATA_DIR>/audit.jsonl` (default 5 MiB, 5 files) |
| `STAFF_STORE_KEY` | optional Fernet key for `staff.fernet` (default: derived from `EDGE_DATA_KEY`; change with `python -m edge.auth rekey`) |
| `EDGE_CORS_ORIGINS` | exact kiosk origins (default `http://localhost:5173,http://127.0.0.1:5173`); also the foreign-Origin allow-list |
| `EDGE_EXTRA_ALLOWED_HOSTS` | extra exact Host names the main API answers (default only 127.0.0.1, localhost, [::1]) |
| `CLOUD_EDGE_PROXY_KEY` | outbound cloud API key (role `edge_proxy`), sent as `Authorization: Bearer` |
| `CLOUD_ADMIN_TOKEN` | legacy outbound `X-Admin-Token`, used only when `CLOUD_EDGE_PROXY_KEY` is empty |
| `CLOUD_TLS_CA_FILE` | optional PEM the cloud certificate must chain to (pinning); empty = system trust store |

## 1a. Staff accounts, roles and API keys (RBAC)

Code: `edge/auth/**` (catalog `edge/auth/rbac.py`, HTTP routes `edge/auth/routes.py`, CLI
`edge/auth/cli.py`), wired in `edge/app.py`. The store is `<EDGE_DATA_DIR>/staff.fernet` (Fernet), and the
HMAC-chained audit log is `<EDGE_DATA_DIR>/audit.jsonl`. These SYSTEM roles are unrelated to the ENTRANT
roles (student, faculty, ...) in the signed schedule bundle.

**Credentials** (one per request):

- Staff session: `Authorization: Bearer fgs_...`, from `POST /v1/auth/login`
  `{username, password, totp_code?}`. The reply is `{token, token_type: "Bearer", expires_at,
  idle_timeout_s, principal}` with `Cache-Control: no-store`. For an MFA account without `totp_code` the
  answer is 401 reason `MFA_REQUIRED` with a single-use `mfa_ticket` (2 min); re-post
  `{mfa_ticket, totp_code}`. Only non-GET requests, requests with `X-FG-Activity: 1` and
  `POST /v1/auth/activity` refresh the idle timer; GET polls and SSE never do.
- API key (automation): `Authorization: Bearer fgk_<key_id>.<secret>`, shown once by
  `python -m edge.auth create-api-key --name <n> --role <role> [--role ...] [--expires-days N] [--print-key-only]`
  or `POST /v1/admin/api-keys`. 1..3 roles, never `admin`; expiry default 30 days, max 90. A key never
  holds `staff:manage`, `codes:rotate`, `codes:rotate_any`, `access:edit`, `access:revoke`, `enrol:erase` or
  `demo:clock`, whatever its roles.
- Legacy `X-Admin-Token: $ADMIN_TOKEN`: accepted ONLY when `AUTH_LEGACY_ADMIN_TOKEN=1` (default off; without
  the flag it is 401). It is a reduced admin: every permission except `staff:manage` and `codes:rotate_any`.
  Every use is audited and logged as a warning, and `/v1/health` reports `legacy_admin_token`.

Accounts that `AUTH_MFA_REQUIRED_ROLES` covers and that have no TOTP yet get 403 reason
`MFA_ENROLMENT_REQUIRED` everywhere except `/v1/auth/me|logout|activity|password` and `/v1/auth/mfa/*`
(`POST /v1/auth/mfa/enroll`, then `POST /v1/auth/mfa/confirm {totp_code}`). Other CLI commands:
`set-password`, `set-roles`, `disable`, `enable`, `unlock`, `enable-mfa`, `disable-mfa`, `list`,
`revoke-api-key`, `rekey` (`python -m edge.auth <command> --help`).

**Roles** (`rbac.EDGE_ROLES`; `demo:clock` and `challenge:control` are removed from every principal while
`DEMO_MODE=0`):

| role | permissions |
|---|---|
| `admin` | every permission |
| `security_officer` | events:read, metrics:read, store:read, attempt:signals, mode:switch, sync:run, ratelimit:reset, enrol:read, access:read, access:revoke, codes:rotate, bundle:refresh, audit:read |
| `enroller` | enrol:read, enrol:write, enrol:erase, access:read, bundle:refresh |
| `auditor` | events:read, metrics:read, store:read, enrol:read, access:read, audit:read |
| `evaluator` | events:read, metrics:read, attempt:signals, eval:admin, ratelimit:reset, challenge:control, mode:switch, store:read |

**Route -> permission** (`rbac.ROUTE_PERMISSIONS` and `rbac.PUBLIC_ROUTES`):

| permission | routes |
|---|---|
| public (no credential) | `GET /v1/health`, `GET /v1/mode`, `GET /v1/auth/status`, `POST /v1/auth/login`, `POST /v1/session/start`, `GET /v1/attempt/{attempt_id}`, `POST /v1/attempt/{attempt_id}/frames\|probe\|rendered\|challenge\|fallback\|otp/send` |
| `X-Depth-Token` only | `GET /v1/depth/pending`, `POST /v1/depth/frames` |
| any authenticated principal | `GET /v1/auth/me`, `POST /v1/auth/logout\|activity\|password\|mfa/enroll\|mfa/confirm`, `GET /v1/admin/roles` |
| `events:read` | `GET /v1/events` |
| `metrics:read` | `GET /v1/metrics` |
| `store:read` | `GET /v1/admin/store`, `GET /v1/admin/mode/detail` |
| `attempt:signals` | `GET /v1/admin/attempt/{attempt_id}/signals` |
| `mode:switch` | `POST /v1/admin/mode` |
| `sync:run` | `POST /v1/admin/sync` |
| `ratelimit:reset` | `POST /v1/admin/rate-limit/reset` |
| `eval:admin` | `POST`, `DELETE /v1/admin/eval/context` |
| `demo:clock` (DEMO_MODE=1) | `POST /v1/admin/clock` |
| `challenge:control` (DEMO_MODE=1) | `POST /v1/admin/random-challenge` |
| `enrol:read` | `GET /v1/admin/users` |
| `enrol:write` | `POST /v1/enroll` |
| `enrol:erase` | `DELETE /v1/enroll/{user_id}` |
| `access:read` | `GET /v1/admin/access/users` |
| `access:edit` | `PUT /v1/admin/access/users/{user_id}` |
| `access:revoke` | `POST /v1/admin/access/users/{user_id}/revoke` |
| `codes:rotate` (another staff_id: + `codes:rotate_any`) | `POST /v1/admin/access/codes/rotate` |
| `bundle:refresh` | `POST /v1/admin/bundle/refresh` |
| `audit:read` | `GET /v1/admin/alerts`, `GET /v1/admin/sync/last`, `GET /v1/admin/auth/audit` |
| `staff:manage` | `GET`, `POST /v1/admin/staff`; `GET`, `PATCH`, `DELETE /v1/admin/staff/{staff_id}`; `POST /v1/admin/staff/{staff_id}/password\|unlock\|mfa/reset`; `GET`, `POST /v1/admin/api-keys`; `DELETE /v1/admin/api-keys/{key_id}` |

- `GET /v1/events` re-checks the principal before every event and at every heartbeat. When the session
  ends (expired, logged out, revoked) or loses `events:read`, the stream sends a final `event: auth` and
  closes.
- `POST /v1/admin/clock` and `POST /v1/admin/random-challenge` answer 403 reason `NOT_DEMO_MODE` with
  `DEMO_MODE=0`.
- The password and MFA routes act on the caller's own staff account: an API key or the legacy token gets
  403 `NO_STAFF_IDENTITY` there.
- **Codes rotate** (`POST /v1/admin/access/codes/rotate`): staff sessions only; an API key gets 403
  `MISSING_PERMISSION` (keys can never hold `codes:rotate`) and the legacy token gets 403
  `NO_STAFF_IDENTITY`. `codes:rotate` = only the caller's own `staff_id` (else 403
  `STAFF_ID_NOT_OWN`) and `count <= 4`; `codes:rotate_any` = any staff id (the request model's limits).
- **Actor:** the edge always derives the audit actor from the principal: `staff:<staff_id>`,
  `key:<key_id>` or `legacy:admin_token`. A client `actor` field is accepted but ignored. The actor is sent
  to the cloud inside the HMAC-signed JSON body (POST/PUT, including cloud `POST /v1/enroll`) and as
  `?actor=` on `DELETE /v1/enroll/{user_id}` (signed, because the signed path includes the query).
- Errors: 401 `UNAUTHORIZED`, 403 `FORBIDDEN` with `reason` (`MISSING_PERMISSION` + `required`,
  `MFA_ENROLMENT_REQUIRED`, `PASSWORD_CHANGE_REQUIRED`, ...), 429 `RATE_LIMITED` with `retry_after_s` +
  `Retry-After`, 503 `AUTH_UNAVAILABLE` / `AUTH_BUSY`. An unreadable or missing staff store makes every
  authenticated route 503 (the legacy token does not bypass it) and `/v1/health` reports `auth_unavailable`;
  20 or more failed sign-ins within 10 min report `auth_bruteforce`.

## 1b. HTTP hardening (`edge/app.py`, `edge/http_guards.py`, `edge/config.py`)

- Host allow-list (TrustedHostMiddleware, main app only): `127.0.0.1`, `localhost`, `[::1]`, plus the exact
  names in `EDGE_EXTRA_ALLOWED_HOSTS` (no wildcards). Any other Host header gets 400.
- A non-GET/HEAD/OPTIONS request whose `Origin` header is present and not in `EDGE_CORS_ORIGINS` gets 403
  `FORBIDDEN` reason `ORIGIN_NOT_ALLOWED`. Requests without `Origin` (curl, scripts) are not affected.
- CORS: origins from `EDGE_CORS_ORIGINS` (default the Vite `:5173` origins); headers `Content-Type`,
  `Authorization`, `X-FG-Activity` (+ `X-Admin-Token` only with the legacy flag); exposed `X-Latency-Ms`,
  `Retry-After`.
- Body caps before any parsing (`http_guards.ROUTE_BODY_MAX`): 12 MB for `.../frames` and `/v1/enroll`, 3 MB
  for `.../probe`, 7 MB for `.../challenge`, 30 MB for `/v1/depth/frames`; every other route
  `DEFAULT_BODY_MAX` = 64 KB. Over the cap -> 413 `PAYLOAD_TOO_LARGE`.
- `/docs`, `/redoc` and `/openapi.json` exist only with `DEMO_MODE=1`. `DEMO_MODE=1` also logs a loud
  warning at startup and puts `demo_mode` in `/v1/health` `degraded_reasons`.
- `GET /v1/events` serves at most 16 concurrent streams; the 17th gets 429 `RATE_LIMITED` with
  `Retry-After: 30`.
- `CLOUD_API_URL` must be `https://` unless its host is loopback or `DEMO_MODE=1` (else the edge refuses to
  start).

## 2. Smoke test (curl)

```bash
EDGE_URL=http://127.0.0.1:<scratch port> bash scripts/smoke_edge.sh   # health -> session/start -> 5 frames + meta -> decision -> nonce replay (409)
```

`EDGE_URL` is required. The script refuses port 8000 (the live edge) unless `SMOKE_LIVE=1`. Every step uses
public routes, so it needs no credential.

The frames are synthetic: the public-domain NASA `astronaut` portrait from scikit-image, with a
simulated colour-flash reflection. You can also run the steps by hand:

```bash
curl -s http://127.0.0.1:8000/v1/health | python3 -m json.tool
curl -s -X POST http://127.0.0.1:8000/v1/session/start -H 'Content-Type: application/json' \
  -d '{"kiosk_id":"KIOSK_MAIN_01","client":{"camera_label":"FaceTime HD Camera","user_agent":"curl","screen":{}},"flash_enabled":true}' \
  | tee /tmp/s.json
edge/.venv/bin/python -m edge.synth /tmp/att < /tmp/s.json     # writes frame_0..4.jpg + meta.json
ATT=$(python3 -c 'import json;print(json.load(open("/tmp/s.json"))["attempt_id"])')
curl -s -X POST http://127.0.0.1:8000/v1/attempt/$ATT/frames \
  -F frame_0=@/tmp/att/frame_0.jpg -F frame_1=@/tmp/att/frame_1.jpg -F frame_2=@/tmp/att/frame_2.jpg \
  -F frame_3=@/tmp/att/frame_3.jpg -F frame_4=@/tmp/att/frame_4.jpg -F "meta=</tmp/att/meta.json"
```

## 3. Enrol a face (`enrol:write`)

Send `POST /v1/enroll` as multipart: `frame_0..frame_4` (JPEG, slight pose variation) plus a
`meta` JSON string, with `Authorization: Bearer <session token or API key>` (permission `enrol:write`,
for example role `enroller`). It works offline (local gallery).

```bash
FG_TOKEN=$(curl -s -X POST http://127.0.0.1:8000/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"<name>","password":"<password>","totp_code":"<6 digits, MFA accounts only>"}' \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
curl -s -X POST http://127.0.0.1:8000/v1/enroll -H "Authorization: Bearer $FG_TOKEN" \
  -F frame_0=@f0.jpg -F frame_1=@f1.jpg -F frame_2=@f2.jpg -F frame_3=@f3.jpg -F frame_4=@f4.jpg \
  -F 'meta={"user_id":"u_3c4d","display_name":"Priya N.","consent":true,"consent_version":"2026-11-14.v1","card_id":"CARD-1234","provision_totp":true}'
```

- Every frame must pass the edge quality checks and passive PAD (`liveness.pad.pass_min`) with no
  phone, laptop or TV around the face. At least `quality.min_usable_frames` frames must pass.
- The frames must be one identity: the minimum pairwise cosine must be at least
  `match.local.allow_min_cosine`. A face already enrolled under a different `user_id` is refused (409
  `FACE_ENROLLED_OTHER`).
- **Re-enrolment** (the user already has templates) appends templates. Every new frame must resemble the
  user's original (pinned) enrolment, else 409 `LOOK_MISMATCH`. ONLINE it is cloud-first: the bar is
  `match.local.allow_min_cosine`, and the cloud `POST /v1/enroll` identity check runs BEFORE anything is
  stored locally (cloud refusal -> 409 `CLOUD_REFUSED_REENROLMENT`; cloud unreachable or 5xx -> 503
  `CLOUD_UNAVAILABLE` reason `CLOUD_ERROR`; nothing is changed). OFFLINE there is no cloud check, so the bar
  is the highest of `match.local.allow_min_cosine`, the offline override of that key and
  `enrol.reenrol_min_cosine_offline`.
- The ArcFace templates are stored Fernet-encrypted (`EDGE_DATA_KEY`) in `edge/data/templates.fernet`.
  No images are stored. The card ID is stored only as HMAC-SHA256(`CARD_ID_PEPPER`, card_id), and
  the email is never stored on the edge. The TOTP secret is stored encrypted, and its provisioning
  URI is returned once.
- `user_id` must match `^u_[0-9a-z]{4}$` and **be in the verified schedule bundle**. Otherwise the edge
  refuses before analysing any frame: `409 INVALID_STATE` with `error.reason` `NOT_IN_SCHEDULE` (or
  `NO_BUNDLE` when no verified bundle is installed). Such a user could never be admitted (the gallery only
  holds entitled bundle users). Add the user first: control panel, Users & Access, Add user
  (`PUT /v1/admin/access/users/{user_id}`). Note: `u_prj1` is **not** in the live bundle v48.
- **Role**: the signed schedule is the single source of truth. `meta.role` is accepted for compatibility
  and **never applied**. The template stores the bundle role. The response carries `schedule_role`,
  `schedule_display`, `role_requested`, `role_applied: false` and a `warnings[]` entry when the requested
  role differs (`meta.role` is optional; omitted = no warning). To change a role, use `PUT /v1/admin/access/users/{user_id}` (section 3a).
- Every enrolment error carries `error.reason` (v1.4): `USER_REVOKED` (403), `NOT_IN_SCHEDULE`, `NO_BUNDLE`,
  `ERASED_IN_BUNDLE`, `ERASED_PENDING_READMIT`, `FACE_ENROLLED_OTHER`, `LOOK_MISMATCH`,
  `CLOUD_REFUSED_REENROLMENT` (409), `CLOUD_BODY_CAP` (413), `FRAMES_REJECTED` (422),
  `POLICY_RUNTIME_UNAVAILABLE`, `LOCAL_WRITE_FAILED`, `ERASURE_PENDING`, `CLOUD_ERROR` (503). `totp_active` is
  true only when this edge holds the TOTP secret AND the bundle marks `fallback.totp_enrolled`; otherwise a
  warning says TOTP is not active yet (the kiosk must not say "Scan now").
- Revocations: an ADMIN / security revocation gives `403 FORBIDDEN`. A DPDP erasure (`reason: ERASED`) does
  not block a re-enrolment once the cloud has re-admitted the user to the schedule. While the bundle itself
  still carries the erasure, the answer is `409` with `reason: ERASED_IN_BUNDLE`. While the revocation feed
  still holds an un-lifted ERASE entry and the installed bundle was not issued after it, the answer is `409`
  with `reason: ERASED_PENDING_READMIT` (re-admit in Users & Access, or refresh the bundle). A successful
  re-enrolment clears the stale ERASED revocation-feed entry (`reinstated_after_erasure: true`).
- Cloud (ONLINE only): the accepted frames go to cloud `POST /v1/enroll`, with the edge-derived `actor` in the
  signed body (section 1a). When the accepted frames together exceed 5 MiB as base64, face crops (at most
  640 px) are sent instead; if even those do not fit, the edge answers 413 `CLOUD_BODY_CAP` before storing
  anything. `cloud_state` is `indexed`, `failed`, `skipped_offline` or `not_configured`. Any state other than `indexed` adds a
  `warnings[]` entry: while ONLINE, Rekognition is authoritative, so an un-indexed user is NOT_ENROLLED
  online until re-enrolled while ONLINE (the face indexing itself is never retried automatically).
  - `skipped_offline`: the enrolment is recorded (metadata only: `user_id`, `actor`, `template_count`, time,
    model, `kiosk_id`; never images) in the policy runtime's queue. After every successful sync the edge
    replays the records to cloud `POST /v1/enroll/offline-record` (the cloud audit). A record is cleared on
    2xx, dropped with an error log on 400/403/409/413/422, and kept for the next sync on any other status
    (e.g. 404, 401, 429, 5xx) or a transport error. If the runtime cannot queue it, a warning says so.
  - After `indexed`, the edge installs the newly signed bundle at once (`bundle_version`). The
    cloud's own `totp_provisioning_uri` is stripped from `cloud.body`, so the browser sees exactly one TOTP
    secret (the edge's). `provision_totp` is forwarded only when this edge holds a TOTP secret for the user.
- TOTP is provisioned by `PolicyRuntime.provision_totp`, and the secret is held in its encrypted credential
  store. `GET /v1/admin/users` `totp_local` reads that store.
- `DELETE /v1/enroll/{user_id}` (`enrol:erase`) erases the user (DPDP; `user_id` pattern, else 422). Every key
  is always present: `{user_id, local_removed, cloud: deleted | queued | not_configured | failed, cloud_status,
  message, bundle}`. The local template and the TOTP secret are erased first; the cloud call
  (`DELETE /v1/enroll/{user_id}?actor=...`) runs only while ONLINE. The cloud erasure counts as `deleted` on
  200/204, or on a 404 whose `error.code` is `NOT_FOUND` with a `reason` (the cloud holds nothing). A bare
  404 (for example the route is not deployed) is NOT counted as erased: it is queued. OFFLINE or a failed
  cloud call: the cloud erasure is persisted by `PolicyRuntime.queue_cloud_erasure` (edge/offline, with the
  actor) and replayed at sync (R-J, `queued`; `pending_cloud_erasures[]` in the access list). `failed` (M1) =
  the local erasure queue could not be written (e.g. disk error) or the runtime has none: the local template
  IS erased, the cloud erasure did not happen; retry while ONLINE (honest, never `queued`).
- Erasure also works when the template cache is unavailable: the TOTP and cloud steps still run, and the
  answer has `local_removed: false` plus a `message` that says the local templates are deleted when the
  cloud's ERASE event reaches the edge with the cache loaded. A failed template-store write gives 503
  `MODELS_UNAVAILABLE` reason `LOCAL_ERASE_FAILED` with nothing changed. Write responses (M2) may carry
  `cloud_bundle_version` / `revoked_at` / `seq` = null when the follow-up pull failed (`bundle.applied`
  false). Cache loaded, user not enrolled and no cloud: `404 NOT_FOUND` reason `NOT_ENROLLED`.
- `GET /v1/admin/users` lists the enrolled users. `role` / `display_name` / `bundle_role` / `bundle_display`
  come from the verified bundle and are authoritative. `template_role` / `template_display_name` are the
  labels stored with the template. `in_schedule: false` means the user is not in the bundle.

## 3a. Users & Access (control panel proxies; permissions in section 1a): API v1.4

The canonical contract is `docs/API.md` v1.4 §3.18 (+ §3.15 enrolment) and the machine-readable examples in
`docs/contracts/admin_access.examples.json`. Models: `edge/access_models.py` (request models validate; response
models are `extra="forbid"`). Handlers: `edge/access.py`. `edge/tests/test_contract_admin_access.py` validates
every edge example against those models AND replays every example (valid + error) through the handlers
against a contract-shaped fake cloud (`edge/tests/contract_cloud.py`).

| Edge route | Cloud call | Notes |
|---|---|---|
| `GET /v1/admin/access/users` | `GET /v1/admin/users` | `AccessUsersResponse`: top-level `roles[]`, `role_defaults{role:{zones,windows}}`, `zones{}`, `staff_ids[]`, `pending_cloud_erasures[]`, `users[AccessUser]` (`status`, `bundle_role`, `in_bundle`, `today{...}` object). Offline / cloud error: `source: "bundle"`, `read_only: true`, `read_only_code` (`OFFLINE`, `NOT_CONFIGURED`, `CLOUD_ERROR`, `ENDPOINT_NOT_DEPLOYED`, `CLOUD_ADMIN_TOKEN`; a cloud 403 with any other reason shows as `CLOUD_ERROR`). Only the edge's own auth errors (401 / 403 / 503 `AUTH_*`) are errors. |
| `PUT /v1/admin/access/users/{user_id}` | `PUT /v1/admin/users/{user_id}/access` | Create (`display` + `consent: true`), update, re-admit an ERASED user (`consent: true`, R-B), restore a REVOKED one (`consent` + `restore`, R-C). Returns `{created, unchanged, readmitted, restored, previous_role, role, cloud_bundle_version, bundle, user, warnings}`. |
| `POST /v1/admin/access/users/{user_id}/revoke` | `POST /v1/admin/revocations` `{type: USER, target_id, reason, actor}` | Body optional, `reason` default `ADMIN`, `ERASED` refused (422). |
| `POST /v1/admin/access/codes/rotate` | `POST /v1/admin/codes/rotate` | Body `{staff_id ^s_[0-9a-z_]{2,32}$, count 1..10 (default 4), replace_existing (default true)}`; identity rules in section 1a. The codes come back **flat** (`codes[{code_id, code}]`), once, `Cache-Control: no-store`, also when the bundle pull failed (`applied: false` + warning). Never logged or stored. |
| `POST /v1/admin/bundle/refresh` | `GET /v1/schedule/{kiosk}` (`refresh_bundle_now`) | `BundleRefresh`. 503 `OFFLINE` (forced) / `NOT_CONFIGURED` / `CLOUD_ERROR`, 409 `BUNDLE_REJECTED`, all with `installed_version`. |

- **Writes need ONLINE**: cloud URL + an outbound cloud credential (`CLOUD_EDGE_PROXY_KEY`, else
  `CLOUD_ADMIN_TOKEN`), not forced OFFLINE, and mode ONLINE (or reason `bundle_stale`). Else
  `503 CLOUD_UNAVAILABLE` reason `OFFLINE` / `NOT_CONFIGURED`, before any cloud call.
- **Validation order**: request model (422 `details[]`) -> ONLINE (503) -> role in the installed bundle's role
  names (422 `UNKNOWN_ROLE`) -> cloud. Zones are checked by the cloud only (the bundle is filtered to this
  kiosk's zone).
- **After every successful write** the edge calls `refresh_bundle_now(expect_version=<cloud bundle_version>)`
  and pulls the revocation feed. A failed pull keeps the 2xx: `bundle.applied: false`, `user: null` (PUT),
  plus a warning. `user.in_bundle: false` = the role has no access at this kiosk's zone (do not enrol here).
- **Error mapping** (`access.cloud_admin`): transport / timeout / 401 / 5xx -> 503 `CLOUD_ERROR`; 404
  without `error.reason`, or 405 -> 503 `ENDPOINT_NOT_DEPLOYED`; 403 -> 403 `FORBIDDEN` with the cloud's
  reason unchanged (e.g. `ADMIN_KEY_INVALID`, `MISSING_PERMISSION`; `CLOUD_ADMIN_TOKEN` when it gives none);
  other 4xx -> same status + code, the cloud `reason` forwarded verbatim, plus `cloud_status` / `cloud_code`.
- **Field limits (R-H)**: `user_id ^u_[0-9a-z]{4}$` (path), `display` 1-80 after trimming, `role ^[a-z_]{1,32}$`,
  zones `^[A-Z0-9_]{1,32}$`, written times `00:00-23:59` with end > start (24:00 only in read data), unique
  days, <= 16 zones_add, <= 16 extra-window zones x 14 windows, tz-aware `valid_*` (normalised to UTC `Z`),
  `actor ^[A-Za-z0-9_.:@-]{1,64}$` (validated, then ignored: the edge sends the principal's actor),
  `extra="forbid"` on every write body.

**Registration (R-A)**: `PUT` access `{display, role, consent: true}` first (needs `access:edit`, which
role `enroller` does not have), require `bundle.applied && user.in_bundle` (else `POST /v1/admin/bundle/refresh`), then `POST /v1/enroll`. Offline,
new people cannot be registered (503 `OFFLINE`); users already in the bundle still enrol (`skipped_offline`).

## 4. MiniFASNet "real" index + normalisation: verified finding (2026-11-14)

Models: yakhyo/face-anti-spoofing ONNX exports, MiniFASNetV2 (crop 2.7x) and MiniFASNetV1SE
(crop 4.0x), both 80x80 BGR. The crop reproduces minivision `CropImage` exactly, with the window
shifted into the image rather than shrunk. The face box comes from RetinaFace-MNv2 (uniface weights).

**Finding: output index 1 = real, and the input is raw 0-255 BGR float32 (no /255).**

Evidence comes from `run_self_test`, which runs at every startup. The values below are the fused
softmax (V2 + V1SE) / 2.

| fixture | kind | P[idx 0] | **P[idx 1]** | P[idx 2] | P[idx 1] with /255 input |
|---|---|---|---|---|---|
| skimage `astronaut` (NASA, public domain) | bona fide | 0.054 | **0.852** | 0.095 | 0.016 |
| minivision `image_T1.jpg` | bona fide | 0.000 | **1.000** | 0.000 | 0.016 |
| minivision `image_F1.jpg` | attack | 0.046 | **0.196** | 0.758 | 0.017 |
| minivision `image_F2.jpg` | attack | 0.001 | **0.004** | 0.995 | 0.016 |

- Raw 0-255 input with index 1 separates the sets: bona-fide min 0.852 > attack max 0.196.
  This is the only one of the 6 hypotheses (3 indices x 2 scales) that separates them.
- With /255 input the network output collapses to the same vector, about [0.03, 0.016, 0.95],
  for every image. So /255 is wrong for these exports, and the HF model card claim
  "[live, print, replay]" with /255 does not apply here.
- The self-test rule needs no tunable numbers. Every bona-fide fixture's P_live must be strictly
  greater than every attack fixture's, for the configured `liveness.pad.real_class_index` and the
  input scale (`liveness.pad.input_scale`, default 1.0). If the test fails, PAD signals become
  `None`, which the policy treats as missing (never ALLOW), and `/v1/health` reports `degraded`.
- **Still TODO:** run the self-test with a live webcam frame from the kiosk camera and a printed
  photo of the operator. Put the JPEGs in `eval/fixtures/live_*.jpg` and `eval/fixtures/print_*.jpg`;
  they are picked up automatically at startup. This needs the operator at the camera.
- The sample size is tiny (4 images) and the fixtures come from a different camera. Calibrate
  `pass_min` / `fail_max` on 50 or more captures from the demo webcam. Synthetic colour tints
  already move P_live by about 0.2 on some frames, so calibrate under the real flash.

## 5. Parallelism + latency

`POST /v1/attempt/{id}/frames` runs in two stages:

1. decode, detect, align and quality for all frames, in parallel on a thread pool
   (`latency_ms.quality`);
2. `asyncio.gather`:
   - **liveness**: MiniFASNet batch, YOLOX device check on every frame, moire and mask ring per
     frame, flash correlation;
   - **match**: ArcFace (CoreML EP, after a CPU-parity check) on the first, last and sharpest
     frames, with the cloud match in parallel when `CLOUD_API_URL` is set;
   - **depth**: a bounded wait of `depth_max_wait`.

**Early cloud probe** (`POST /v1/attempt/{id}/probe`, multipart part `probe`, JPEG of at most 2 MB).
The kiosk sends its face-lock frame right after face lock, without waiting for the response. The edge
detects the face and starts the cloud `/v1/match` on the ~10-16 KB face crop (`_face_crop_jpeg`) while the
0.7 s flash capture is still running, and it computes the probe's local ArcFace embedding.

- Response: 202 `{"accepted": true, "cloud": "started" | "skipped"}`. It is `skipped` when the attempt
  will not call the cloud (OFFLINE, no cloud configured, `match.rekognition.enabled` false), when the
  probe shows no face, or when the frames got there first.
- Errors: 409 `INVALID_STATE` after the frames or on a second probe; 413 when the probe is over 2 MB;
  422 when it is not a JPEG. A rejected (422) probe does not use up the one probe slot, so a valid
  probe can follow. It never returns a 500.
- Challenge: the challenge nonce is released when the submission is rejected with 422 (undecodable
  frame; nothing was decided), so the retry is not `NONCE_REUSED`. A perception crash on the challenge
  frame is DENY `SYSTEM_ERROR` (HTTP 200), never a 500.
- `POST /v1/attempt/{id}/otp/send`: a cloud 404 (no e-mail on file) gives `404 NOT_FOUND` with
  `reason: NO_EMAIL_ON_FILE`, and EMAIL_OTP is dropped from the step (R11 path, nothing counted; the new
  `methods` are in the error and in `GET /v1/attempt/{id}`). A cloud 429 gives `429 RATE_LIMITED` with
  `retry_after_s` + `Retry-After`. Any other cloud 4xx gives 422. A 401, 5xx or transport error gives 503.
  Only transport errors and 5xx count as a connectivity miss, so taps on "Email me a code" can no longer
  flip a healthy kiosk to OFFLINE.
- Frames path: the edge waits for the probe until `latency_budget_ms.rekognition_probe_deadline` (1500
  ms, counted from probe start). It uses the probe's result only if the probe's local top-1 user equals
  the best frame's local top-1 user AND cosine(probe, best frame) is at least
  `match.local.allow_min_cosine`. Otherwise it uses `CloudMatch(ok=False)`, so the attempt is decided
  OFFLINE (P7).
- No probe means the old path: the best frame with `rekognition_timeout` (700 ms).
- The outcome is shown in `GET /v1/admin/attempt/{id}/signals` under `raw.probe`.
- Scratch-port check (2026-11-14, 3 attempts, localhost fake cloud with a 0.9 s `/v1/match`): with the
  probe, the attempts were decided ONLINE (binding ok, cosine 0.99). The no-probe control timed out and
  was decided OFFLINE.

ONNX Runtime releases the GIL, and each session uses 2 intra-op threads. The measured table is in
`eval/results/latency_edge.md`. To reproduce it:
`edge/.venv/bin/python scripts/bench_latency.py --runs 30`.

## 6. Endpoints (docs/API.md v1.1) and edge-specific notes

| route | notes |
|---|---|
| `POST /v1/session/start` | 201. Exactly 3 random distinct off-primary colours x 333/333/334 ms (lead decision; at most 2 changes/s). The nonce is single-use with a 10 s TTL. `kiosk_id` must equal `KIOSK_ID`; any other value is refused before an attempt exists: 403 `FORBIDDEN` with `DEMO_MODE=0`, 409 `INVALID_STATE` with `DEMO_MODE=1` (see the caveat below). `recapture_of` must name this kiosk's attempt that is pending RECAPTURE, else 409; that old attempt is then closed |
| `POST /v1/attempt/{id}/frames` | 3-5 contiguous `frame_i` JPEGs + `meta`. Returns 410 NONCE_EXPIRED, 409 NONCE_REUSED / ATTEMPT_CLOSED, 403 when the nonce does not match the attempt, or 422 VALIDATION_ERROR. Every policy outcome is HTTP 200 with a DecisionResponse. A perception crash goes to `PolicyRuntime.decide_error` and gives DENY SYSTEM_ERROR |
| `POST /v1/attempt/{id}/challenge` | multipart `meta` + `frame_0`, the last challenge frame. `last_frame_cosine` is computed against the candidate's templates. Returns 409 INVALID_STATE unless CHALLENGE is pending, and 422 if `challenge_id` does not match the issued challenge |
| `POST /v1/attempt/{id}/fallback` | 409 INVALID_STATE unless SECOND_FACTOR is pending. EMAIL_OTP goes through the cloud `/v1/otp/verify`. If that verify times out or errors (DECISION_POLICY R11), the edge re-issues the same STEP_UP without `EMAIL_OTP`: reason codes and `attempts_left` are unchanged and nothing is counted. Later step-up responses for that attempt keep it removed |
| `POST /v1/attempt/{id}/otp/send` | 201. Online only (503 offline). 409 unless EMAIL_OTP is an offered method |
| `POST /v1/attempt/{id}/rendered` | 204. `face_lock_at_ms` must equal the FramesMeta value. The first beacon wins. The value feeds `/v1/metrics` `latency_ms.client` and the `rendered` SSE event |
| `GET /v1/attempt/{id}` | latest DecisionResponse. 404 for an unknown attempt; 409 before frames |
| `GET /v1/events` | `events:read`. SSE with `event: decision` (DecisionResponse + `eval`) and `event: rendered`, plus a `: ping` every 15 s. A final `event: auth` closes the stream when the session ends or loses `events:read`. At most 16 streams (429) |
| `GET /v1/health` | public. `{status: ok \| degraded, degraded_reasons[], version, models_loaded{minifasnet_v2, minifasnet_v1se, face_detector, device_detector, arcface}, self_test{minifasnet_real_index, input_scale, passed}, depth_probe, uptime_s}`, with diagnostics under `detail`. `degraded_reasons` (`health_problems` / `auth_problems`): `policy_runtime_fail_secure`, `model_missing:<model>`, `pad_self_test_failed` / `pad_self_test_not_run`, `template_cache_unavailable`, `demo_mode`, `env_file_permissive`, `legacy_admin_token`, `auth_unavailable`, `auth_bruteforce` |
| `GET /v1/mode` | public: only the kiosk badge subset (`public_mode`): `mode, state, reason, forced, forced_until, kiosk_id, sync_queue_depth, demo_clock, template_cache{count}, cache_state, cloud_match{degraded}`. `demo_clock` is null or `{active, now_local "HH:MM", now_utc, offset_s, ...}` |
| `GET /v1/admin/mode/detail` | `store:read`. The full runtime status (the former `/v1/mode` body): bundle, rate limit, policy bars, last sync, cloud match, random challenge, zone, `template_cache{count, model, age_h}` from the edge store, demo clock |
| staff routes (permission per route in section 1a) | `POST /v1/admin/mode` (`{force: OFFLINE\|AUTO, reason?, max_minutes? 1..240}`; a forced OFFLINE auto-reverts to AUTO after `max_minutes`, default `connectivity.forced_offline_default_min`; only `DEMO_MODE=1` with `reason: "DEMO"` and no `max_minutes` stays forced without a deadline; returns the mode detail), `GET /v1/admin/store`, `GET /v1/admin/alerts` (`?limit` 1..200, default 50; policy alerts and security events), `GET /v1/admin/sync/last` (full last-sync report incl. server flags), `POST /v1/admin/sync` (503 offline), `POST /v1/admin/random-challenge` (`{mode: AUTO\|FORCE\|FORCE_NEXT\|OFF}`, `DEMO_MODE=1` only, else 403 `NOT_DEMO_MODE`; the mask-contingency demo control), `POST /v1/admin/rate-limit/reset` (204), `POST`/`DELETE /v1/admin/eval/context` (200/204; tags attempts started afterwards), `POST /v1/admin/clock` (`DEMO_MODE=1` only, `{set_local:"HH:MM"}` or `{offset_s}` or `{reset:true}`), `GET /v1/admin/attempt/{id}/signals` (the raw AttemptSignals for calibration; no images or embeddings), `GET /v1/admin/users`, `POST /v1/enroll`, `DELETE /v1/enroll/{user_id}`, Users & Access proxies (section 3a), staff auth routes (section 1a) |
| `GET /v1/metrics` | `metrics:read`. Final decision per attempt, latency from `frames` only, `latency_ms.client`, `by_label` with rule-of-3 / Clopper-Pearson upper bounds |

**DepthProbe (iPhone) flow.** Gated by `liveness.depth.enabled`, which is currently false.

- Every depth request needs header `X-Depth-Token: $DEPTH_DEVICE_TOKEN`; without it the edge
  returns 401.
- `GET /v1/depth/pending?wait_s=20` is a long poll. It returns 204, or
  `{attempt_id, phase, frames, deadline_ms, depth_nonce}`. CHALLENGE jobs add `delay_ms` /
  `interval_ms` so the 3 frames land on the deformation step: `delay = 500 ms lead-in + index of the
  deformation action x step_window_ms + min_reaction_ms`, and `interval = (step_window_ms -
  min_reaction_ms) / 3`. A re-issued challenge replaces the earlier CHALLENGE job.
- `POST /v1/depth/frames` takes `meta`, which **must echo `depth_nonce`** (single use, bound to the
  attempt and phase; otherwise 403), plus `depth_0..2` as raw little-endian `width x height`
  float16/float32 and an optional `rgb_0`. With `rgb_0` the edge finds the face box and landmarks
  itself when they are not sent.
- The edge calls `depth.protocol.process_upload`, which runs D0-D4/M2 and, for CHALLENGE, M1
  against the same attempt's PASSIVE result using `face_box_norm_frames` / `landmarks_norm_frames`.
  Malformed uploads return 422. The reply is only `{accepted: true, attempt_id, phase}`: the measured checks
  stay server-side.
- Depth counts only if it arrives within `latency_budget_ms.depth_max_wait` of the RGB frames.
  Depth maps stay in RAM and are dropped after 180 s.

**Policy-runtime hooks used by the edge:**

- `set_template_cache_status(count, model, age_h)`: at startup and after every enrol or delete.
  `AttemptSignals.template_cache_age_h` is always set while the cache is loaded.
- `mode()`: checked before every cloud match. When the next attempt would be OFFLINE, Rekognition is
  skipped entirely.
- `set_forced_mode(force, reason=, max_minutes=)`, `queue_cloud_erasure(user_id, actor=)`,
  `queue_pending_enrolment(record)` / `pending_enrolments()` / `clear_pending_enrolment(user_id)` and
  `add_sync_hook(fn)` (the offline-enrolment replay runs after every successful sync), `bundle_kiosk_ids()`,
  `recent_alerts(limit=)`, `sync_detail()`.
- Error mapping: `CloudUnavailableError` -> 503, `PermissionError` -> 403, `ValueError` -> 422. Any
  other runtime exception -> DENY SYSTEM_ERROR, never an HTTP 500.

**Cloud signing:** `.env` keys are encoded as UTF-8. When `|X-Server-Time - local| > 30 s` the edge
signs with server-corrected time, and it re-signs once if the cloud returned a 401 that taught it
a new offset.

**Cloud credential and TLS:** cloud admin calls use `CLOUD_EDGE_PROXY_KEY` as `Authorization: Bearer`, else
the legacy `CLOUD_ADMIN_TOKEN` as `X-Admin-Token`; never the inbound `ADMIN_TOKEN`. `CLOUD_TLS_CA_FILE` pins
the cloud certificate (`config.cloud_tls_verify`: only that PEM is trusted; a missing or unreadable file
stops the edge from starting). It is used by `CloudClient` and by the policy runtime's client.
`CLOUD_API_URL` must be `https://` unless its host is loopback or `DEMO_MODE=1`.

**Known gaps and caveats**

- There is no working `DEMO_MODE` kiosk switch: `PolicyRuntime` evaluates every attempt against its fixed
  `KIOSK_ID`. `session/start` (`allowed_kiosks` / `_kiosk_refusal` in `edge/app.py`) serves only the
  runtime's own `KIOSK_ID`; with `DEMO_MODE=1` it would also accept a kiosk that the verified bundle covers
  AND that equals the policy runtime's `kiosk_id`, which in practice is the same `KIOSK_ID`. Any other
  `kiosk_id` is refused up front: 409 `INVALID_STATE` with `DEMO_MODE=1` (the message says the kiosk is not
  covered by the verified bundle, or "restart the edge with KIOSK_ID=..."), 403 `FORBIDDEN` with
  `DEMO_MODE=0`. To demo another kiosk, restart the edge with that `KIOSK_ID`. A real switch needs a
  per-attempt kiosk override in the runtime.
- The gallery is filtered to the runtime's entitled users. When there is no valid bundle, the
  cache is searched unfiltered so DECISION_POLICY §9.5 I1 (STEP_UP via staff override only) stays
  reachable.
- Moire, mask-ring and flash amplitude scaling are uncalibrated `[cal]` feature maps. Calibrate
  them on demo-webcam captures (live, print, phone replay) before the eval run.
- Tests: `edge/tests/conftest.py` `HERMETIC_ENV` sets `AUTH_LEGACY_ADMIN_TOKEN=1`,
  `AUTH_MFA_REQUIRED_ROLES=none` and `EDGE_EXTRA_ALLOWED_HOSTS=testserver` so the existing tests keep using
  `X-Admin-Token` and the TestClient Host. The production defaults (legacy token off, MFA required) and the
  full route -> permission matrix are covered by `edge/tests/test_rbac_wiring.py`.
