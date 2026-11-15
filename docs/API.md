# API.md — REST Contracts (Edge + Cloud)

API version: v1.4 (2026-11-15, admin-access contract: Control Panel, registration, revoke / re-admit)

Architecture context: `docs/ARCHITECTURE.md`. Decision rules / thresholds: `docs/DECISION_POLICY.md`,
`config/thresholds.yaml`. Schedule bundle format: `config/schedule.example.json` (test fixture); the live demo
bundle is signed from `config/schedule.demo.json`. Offline record format:
`docs/SURPRISE_CHALLENGES.md` §SC2.5. Reason codes in §2 are canonical and shared with
`DECISION_POLICY.md` §6. **Do not rename or add codes without updating both files.** Test vectors:
`docs/POLICY_TEST_CASES.md` (implemented in `edge/policy/tests/test_cases.py`).

This version describes the **implemented** edge (`edge/app.py`, `edge/schemas.py`, `edge/errors.py`,
`edge/policy/runtime.py`, `edge/depth_bridge.py`) and cloud (`cloud/app/`) APIs. Where the code still differs
from a lead ruling, the ruling is documented and the gap is marked **(code pending)**.

All JSON examples are valid JSON. All numeric values in examples are **illustrative, not measured**. Real
numbers come only from the eval run (`eval/results/`), which has not been run yet. The only measured numbers in
this file are dev measurements, labelled as such: the edge-only latency bench in §3.16 (stored in
`eval/results/latency_edge_1280_20261114T171323Z.md`), the venue `/v1/match` round trip (about 0.4–1.4 s, dev observation, no stored
file) and the genuine-user moiré / M2 score ranges in §2.

## Changes since v1.3 (v1.4, admin-access contract)

v1.4 is the single canonical contract for the Control Panel / registration routes on all three sides (kiosk ↔
edge ↔ cloud). It replaces the shapes each side guessed at in the previous round (gate failures: kiosk parsed
`codes` at the top level while the edge nested them under `cloud`; `bundle.roles` list vs object; `today` object
vs array; register flow enrolled before creating the schedule entry). Machine-readable examples for **every**
route below, valid and error cases, are in **`docs/contracts/admin_access.examples.json`**; the edge, cloud and
kiosk test suites load that file and validate it against their models / parsers. The edge, cloud (tree) and
kiosk code implement this list except where an item is marked **(code pending)**; the verifier gate is still
pending, and the live cloud runs older code until the lead redeploys with the operator's OK.

- **New edge routes** (§3.18, all `X-Admin-Token`): `GET /v1/admin/access/users`, `PUT
  /v1/admin/access/users/{user_id}`, `POST /v1/admin/access/users/{user_id}/revoke`, `POST
  /v1/admin/access/codes/rotate`, `POST /v1/admin/bundle/refresh`. **New cloud routes** (§4.9a, kiosk HMAC +
  `X-Admin-Token`): `GET /v1/admin/users`, `PUT /v1/admin/users/{user_id}/access`, `POST /v1/admin/codes/rotate`,
  `GET /v1/admin/audit`; `POST /v1/admin/revocations` gains `actor`, `force`, `409 ALREADY_REVOKED` and refuses
  `reason: "ERASED"`.
- **Registration (R-A)**: `/register` and the admin enrol card first `PUT` the access entry `{display, role,
  consent: true}` (creates the user in the cloud master; ONLINE only), the edge installs the re-signed bundle in
  the same call, **then** `POST /v1/enroll`. Offline, new people cannot be registered (`503 CLOUD_UNAVAILABLE`
  reason `OFFLINE`); people already in the installed bundle can still enrol offline (`cloud_state:
  "skipped_offline"` + warning). `EnrollMeta.role` becomes optional and is never applied.
- **Erase → re-register (R-B)**: a `PUT` with `consent: true` for an ERASED user re-admits them (`readmitted:
  true`, cloud drops the ERASED revocation, feed entry type `READMIT`, reason `READMIT`). Without `consent: true` → `409
  INVALID_STATE` reason `ERASED_IN_BUNDLE`. The UI offers **"Re-admit and enrol"**.
- **Revoke / Restore (R-C)**: dedicated revoke route → cloud USER revocation (`SCHEDULE_REVOKED`, offline feed).
  **Restore** = `PUT` with `consent: true, restore: true` (`restored: true`, feed entry type `READMIT`, reason `RESTORE`). No
  `valid_until` hacks; unknown body fields are rejected (`extra=forbid`).
- **Staff codes (R-D)**: the edge returns the cloud's plaintext codes **flat** (`codes[{code_id, code}]`), once,
  `Cache-Control: no-store`; minted codes are returned even when the follow-up bundle pull fails.
- **Demo clock (R-E)**: `GET /v1/mode` `demo_clock` is present whenever `DEMO_MODE=1` (with `active`), and carries
  `date_local`, `bundle_issued_at`, `earliest_local`, `earliest_date_local`, `earliest_utc`, `bundle_rollback`,
  `cache_state`. The fail-secure rollback rule is unchanged: a time before `issued_at − 300 s` makes the bundle
  INVALID → **STEP_UP `SCHEDULE_BUNDLE_INVALID`** (staff override possible), not DENY.
- **Enrolment response (R-F)**: `cloud_state`, `warnings[]`, `schedule_role`, `schedule_display`,
  `role_requested`, `role_applied` (always false), `bundle_version`, `reinstated_after_erasure`, `totp_active`.
  Every enrolment `409` carries `error.reason`.
- **Erasure retry (R-J)**: `DELETE /v1/enroll/{user_id}` returns `cloud: "queued"` again: a failed / offline cloud
  erasure is persisted in `edge/offline` and replayed at sync. `cloud` is `deleted | queued | not_configured |
  failed`; `failed` (M1) means the local erasure queue itself could not be written (e.g. a disk error): the local
  template and TOTP secret **are** erased, the cloud erasure is not queued, and the UI tells the operator to retry
  the erasure while ONLINE (§3.15).
- **Nullable write fields (M2)**: in the write responses (§3.18.2–§3.18.4) `cloud_bundle_version` is `int | null`
  and, for revoke, `revoked_at` is `string | null` and `seq` is `int | null`. They are null when the cloud reply did
  not carry them; this goes with a failed follow-up pull (`bundle.applied: false`). The kiosk then shows **"pending
  refresh"** for them instead of an error.
- **Field limits (R-H)**, one set on all sides: `user_id ^u_[0-9a-z]{4}$`; `staff_id ^s_[0-9a-z_]{2,32}$`;
  `display` / `display_name` 1–80 characters after trimming; written times `HH:MM` 00:00–23:59 with end > start
  (`24:00` only appears in **read** data, e.g. role defaults); `role` must be a role of the master, zones must be
  zones of the master. The `user_id` pattern applies to the **admin-access routes only** (§3.18, §4.9a); the cloud
  enrolment model (`POST /v1/enroll` `EnrollMeta.user_id`, `cloud/app/schemas.py`) keeps the broad
  `^[A-Za-z0-9_.\-]{1,64}$`. `staff_id` and revoke `reason` are **not stripped**: leading/trailing whitespace is a
  `422` on the edge and the cloud. `consent_version` is 1–40 characters everywhere (also `AdminContactRequest`).
- **v1.4 round-2 clarifications** (version label unchanged): **R-K** rotate `codes[].code_id`, `code_length` and
  `valid_until` are nullable (the cloud reply may omit them; the edge emits null and the kiosk still shows the codes
  once; example `minted_fields_unknown`). **R-L** `consent` / `restore` / `replace_existing` are strict booleans on
  both sides (examples `consent_string_rejected`, `restore_int_rejected`). **R-M** no whitespace stripping of
  `staff_id` / `reason`. **R-N** the `^u_[0-9a-z]{4}$` pattern is admin-access-only; `consent_version` max 40; read
  windows follow the edge `WindowRead` (§3.18.1). **L3** the "Refresh edge bundle" control is enabled whenever the
  edge is reachable and not forced OFFLINE (§3.18.5).
- **`error.reason`**: protocol errors may carry a machine-readable `reason` (§0); the edge forwards the cloud's
  `reason` verbatim. Registry: §3.18.6.
- Challenge nonce (R-G, §3.3): the nonce is released on **any** failure before a decision is produced, not only
  on `VALIDATION_ERROR`.

## Changes in v1.3 (round 3, since v1.2)

Items marked **(in progress)** are being built in this round. Until the code lands, the text describes the
agreed contract, and the current behaviour is stated next to it.

- **Random challenge is on again**: `challenge.random_rate` is **0.15 online / 0.30 offline** (restored at the
  operator's request: "i want that blink and stuff"). A would-be ALLOW becomes STEP_UP / CHALLENGE
  `[RANDOM_CHALLENGE]` with that probability. A forced draw (`FORCE_NEXT`, or `FORCE` in the runtime) fires
  whatever the rate is (§3.14a). This replaces the v1.2 "0.0 in both modes".
- **Challenge actions**: the deformation step is one of **`SMILE` | `OPEN_MOUTH`**. `PUFF_CHEEKS` was removed
  from `challenge.deformation_actions` at the operator's request. It is still accepted by the wire enum
  (`edge/policy/signals.py` `ActionName`) but is never issued. The secondary step is one of
  `BLINK | TURN_LEFT | TURN_RIGHT`. A challenge is never blink-only.
- **Moiré and the RGB mask ring (M2) are enforced**, with new switches `liveness.moire.enforce: true` (bands
  0.40 / 0.70) and `liveness.mask.m2_rgb_enforce: true` (bands 0.50 / 0.75). With `false` the signal is
  advisory, like the flash: it is measured and reported as `ADVISORY_<zone>` but has no decision effect. A
  missing moiré measurement stays UNSURE even when moiré is advisory. Known false positives: genuine
  flash-lit frames scored 0.42–0.79 on moiré and genuine spectacle frames 0.35–0.80 on M2 (dev data), so a
  genuine user can get REQUEST VERIFICATION. Both bands are to be calibrated on the eval dev split.
- **Flash stays ADVISORY** (`liveness.flash.enforce: false`), 700 ms, 3 colours × ~233 ms.
- **Rekognition is enabled and authoritative online** (`match.rekognition.enabled: true`). The edge uploads a
  small face crop (about 10 KB; `edge/attempts.py` `_face_crop_jpeg`), not the 1280 px frame. `session/start`
  pre-opens the cloud keep-alive connection (`warm_cloud_match`, fire-and-forget). Measured problem: from the
  venue network the `/v1/match` round trip is about 0.4–1.4 s, so most online attempts miss the 700 ms budget
  and are decided OFFLINE (P7) while the badge says ONLINE. `GET /v1/mode` `cloud_match.degraded` shows this
  state (§3.10).
- **Early cloud probe (live since the edge restart with policy 2026-11-14.3)**: new edge route `POST /v1/attempt/{id}/probe` (§3.1a) starts the cloud
  match at face lock, in parallel with the 0.7 s capture, with the new YAML key
  `latency_budget_ms.rekognition_probe_deadline` (1500 ms, measured from probe start). Identity binding
  rules are in §3.1a. Without a probe the old path applies (cloud match on the best frame after the frames
  arrive, 700 ms budget). Not measured yet.
- **New response fields**: `scores.signals` (per-signal status, §1). `GET /v1/mode` adds the `policy_bars` keys
  `moire_unsure`, `device_unsure`, `flash_enforce`, `moire_enforce`, `m2_rgb_enforce`, `rekognition`,
  `rekognition_timeout_ms`, `rekognition_probe_deadline_ms`, and a
  `cloud_match` block `{enabled, recent, misses, last_miss_at, last_ok_at, degraded}` (§3.10).
- **Health and OTP**: `GET /v1/health` adds `degraded_reasons[]` (§3.9) and `depth_probe` can read `rejected_token`
  (wrong `X-Depth-Token`). Edge handling of cloud `POST /v1/otp/verify`: `401` / `429` / `5xx` / timeout = cloud
  unavailable (EMAIL_OTP dropped, not counted); any other 4xx = `verified: false` (counted) (§3.4, §4.6).
- **Last-resort SYSTEM_ERROR body** is complete (every §1 `scores` and `latency_ms` key; `edge/attempts.py`
  `_static_system_error`, §1).
- **Fallback hardening**: `STAFF_OVERRIDE` needs `staff_id`; a missing one counts as a wrong code. A CARD whose
  hash is revoked (bundle `revocations[]` item with `type: CARD`, or the revocation feed) fails. A revocation
  with `reason: "ERASED"` (cloud DPDP erasure) also deletes the user's local face templates and TOTP secret on
  the edge (§4.3).
- **Re-enrolment appends on the edge**: a new look is appended to an enrolled user (at most 24 templates per
  user, the first 5 pinned, `template_version` + 1; `edge/ml/templates.py`). The new frames must resemble the
  original enrolment (the 5 pinned templates) at `match.local.allow_min_cosine`, else `409 INVALID_STATE`. To
  replace a user, erase first
  (§3.15). **Cloud (being aligned)**: the cloud code in the tree appends the same way (24 faces, 5 pinned,
  `cloud/app/services/enroll_service.py`), but the **deployed** EC2 build (~09:55 UTC artifact) still
  *replaces* the user's Rekognition faces on re-enrolment until the lead redeploys (`cloud/SANDBOX.md` §0).
- **Sync conflicts**: the same `attempt_id` with different content is acknowledged in `duplicates` (so the
  edge purges it), both versions are kept and `ALERT_SYNC_CONFLICT` is raised (§4.4). It is never `rejected`.
- **Cloud**: deployed in us-east-1 on 2026-11-14 ~10:00 UTC (API Gateway HTTP API → EC2 t3.small). New admin
  route `GET /v1/admin/stats`. In the code but **not in the deployed build until the lead redeploys**
  (`cloud/SANDBOX.md` §0): `PUT /v1/admin/schedule/{kiosk_id}` (upload an operator-signed bundle, §4.9), an
  optional `email` on cloud enrolment (§4.8) and append-mode re-enrolment.
- **Closed code-pending items**: oversized frame / depth parts now return `413 PAYLOAD_TOO_LARGE`; the edge skips
  the cloud match when `match.rekognition.enabled` is false (no call, no miss) and when the next attempt would be
  OFFLINE anyway; `/v1/metrics` `sync.last_sync_at` reads `GET /v1/mode` `last_sync.at`.
- **S3 audit frames are not implemented.** No attempt frame is uploaded for audit (§4).
- **Override codes**: the documented `OVR-001`…`OVR-003` (`config/schedule.example.json`,
  `SURPRISE_CHALLENGES.md` §SC2.4) are **test fixtures only**. `scripts/sign_bundle.py` drops them and mints fresh
  random codes (values only in `edge/data/DEMO_CODES.txt`). Live state at the time of writing (checked against
  the installed `edge/data/bundle.signed.json`): the cloud-issued bundle **v45** (`issued_at` 12:30:41Z, scope
  `KIOSK_MAIN_01` only) still carries the three fixture codes, so a STAFF_OVERRIDE with a publicly documented
  code would be accepted. The fix is a new bundle **v46+** with fresh codes, signed with
  `scripts/sign_bundle.py --version 46` and uploaded with `PUT /v1/admin/schedule/KIOSK_MAIN_01` after the
  redeploy (lead action). Until then: no STAFF_OVERRIDE in demos.

## Changes in v1.2 (since v1.1)

- **Capture**: `CaptureSpec.max_width_px` is **1280** (was 640). At 640 px the face had an inter-ocular
  distance of about 50 px, below `quality.min_interocular_px` (60), so every frame failed `QUALITY_POSE`.
  The kiosk sends 5 frames over the `liveness.flash.duration_ms` window (700 ms; operator speed request,
  was 1000 ms).
- **Flash**: always exactly **3 colours × ~233 ms** in the 700 ms window (`colours_min = colours_max = 3`;
  2 changes in 0.7 s = 2.86/s ≤ `max_changes_per_s` 3). Correlation `r` is measured by the edge on the uploaded frames only. The client
  `chroma_series` is untrusted and is used only for timing. Lag window is 0–8 frames, lag std ≤ 1.5 frames,
  `min_amplitude` 2.0.
- **Flash is ADVISORY**: `liveness.flash.enforce: false`. The flash is measured and reported but has no
  decision effect until the kiosk frame timing is re-validated (§2, `SPOOF_FLASH_MISMATCH`). The non-flash path
  (`flash_enabled: false`) still requires a CHALLENGE.
- **Rate limit**: `lockout_s` is 5 s (was 60). Only attack-evidence DENYs are counted.
- **Random challenge** (superseded in v1.3: now 0.15 online / 0.30 offline): `challenge.random_rate` was set to
  0.0 online and offline. New demo route `POST /v1/admin/random-challenge` (`DEMO_MODE=1`, §3.14a).
- **EMAIL_OTP cloud-verify error** (DECISION_POLICY R11): the edge re-issues the same STEP_UP without `EMAIL_OTP`
  (HTTP 200, nothing counted). v1.1 described this case as a counted `FALLBACK_FAILED`.
- **Candidate**: `candidate.role` was added (bundle role, for the kiosk / operator UI).
- **Admin routes**: `POST /v1/admin/mode` now returns the full `GET /v1/mode` body. Admin runtime errors map to
  `503` / `403` / `422` instead of 500.
- **Mode**: `ModeResponse.reason` now lists exactly the values the code emits (§3.10). The heartbeat timeout is
  2000 ms (`connectivity.heartbeat_timeout_ms`).
- **No last valid bundle**: DENY `SCHEDULE_BUNDLE_INVALID` / CONTACT_DESK, with `zone: "UNKNOWN"` (R6).
- **New edge routes**:
  - `GET /v1/admin/users`: enrolled-user list.
  - `GET /v1/admin/attempt/{id}/signals`: raw-signal debug view.
- **Protocol errors**: added `NOT_FOUND` (404), `PAYLOAD_TOO_LARGE` (413) and `MODELS_UNAVAILABLE` (503). An
  attempt nonce that does not match surfaces as `403 FORBIDDEN`.
- **Depth**: LAN listener `0.0.0.0:EDGE_LAN_PORT` (8001), `X-Depth-Token`, single-use `depth_nonce` and
  `DepthFramesMeta.accuracy` are ratified. The `depth/frames` response echoes `attempt_id` and `phase`.
- **Ratified additive fields**: `session/start` returns `recapture_count` and `depth_requested`; enrolment
  returns diagnostics (`frames_used`, `frames_rejected`, `min_pairwise_cosine`, `cloud`).
- **Sync record**: `fallback` also carries `totp_step`. It is a non-secret time-step counter that lets the cloud
  detect cross-kiosk TOTP replay (`ALERT_TOTP_REPLAY`, Y07).
- **Staff override codes**: `valid_until = expires_at + 24 h` (`fallback.staff_override.valid_after_expiry_h`,
  R7). The v1.1 open decision is closed.
- **Localhost routes**: `/v1/events` and `/v1/metrics` are localhost-only and need no admin token.
- **Cloud**: the `/v1/health` fields are those of the implemented service. `MatchResponse.source` adds `fake`.
  Cloud admin routes are listed in §4.9. Sync conflicts are acknowledged as `duplicates` (§4.4).
- **AWS**: runs in the Workshop Studio sandbox, us-east-1 only (role `WSParticipantRole`). The IAM probe allowed
  every service we use. (v1.3: deployed, §4.)

## Changes in v1.1 (since v1.0)

- **AWS region**: cloud runs in **us-east-1**, the only region the AWS Workshop Studio sandbox ("HID
  Hackathon GenAI - University") allows. Production would pin ap-south-1 (Mumbai) for DPDP data residency.
  Every cloud feature has a degraded path because the sandbox IAM role may deny Rekognition, SES, DynamoDB or KMS.
- **IDs** follow `config/schedule.example.json`: `KIOSK_MAIN_01`, `MAIN_GATE`, `u_3c4d`, `s_guard01`,
  `att_<ULID>`. Removed: `ksk_…`, `zone_…`, `usr_…`, `rule_…`.
- **DecisionResponse** is now `DECISION_POLICY.md` §10 plus `stage`. Fields are `next_action` (always present),
  `bio_result`, `schedule_result`, `cache_state`, `candidate`, `resolved_codes`, `policy_version`,
  `bundle_version` and `display_message`, with the §10 `scores` keys and `latency_ms.schedule`. Removed:
  `schedule_rule_id`, `Scores{liveness, match, flash, depth, schedule}` and `NextAction{type, details}`.
- **next_action** follows DECISION_POLICY §7: `type`, `steps`, `methods`, `challenge`, `attempts_left`,
  `retry_after_s`, `hint`. Challenge actions are UPPER_CASE (`SMILE|OPEN_MOUTH|PUFF_CHEEKS` +
  `BLINK|TURN_LEFT|TURN_RIGHT`; since v1.3 `PUFF_CHEEKS` is wire-only and never issued). Fallback methods are `TOTP|CARD|EMAIL_OTP|STAFF_OVERRIDE`.
- **Every policy outcome returns HTTP 200** with a DecisionResponse, including DENY `RATE_LIMITED` and DENY `SYSTEM_ERROR`.
- **Reason-code table** (§2) replaced by the closed list of DECISION_POLICY §6 (39 codes, including `RANDOM_CHALLENGE`, added in v1.1).
  `MATCH_LOW` is UNSURE (step-up), not DENY. Recaptures exhausted → manual review (`STAFF_OVERRIDE`) in
  low/medium zones. Removed the "max 2 step-ups" rule; the real limits are listed in §2.
- **Online schedule** is evaluated on the edge from the newest cloud-signed bundle. There is no per-attempt
  cloud schedule call. A bundle older than `schedule.online_max_bundle_age_min` makes the attempt OFFLINE.
- **Schedule bundle** = `config/schedule.example.json` format, signed with HMAC-SHA256
  (`SCHEDULE_BUNDLE_HMAC_KEY`); Ed25519 is the production roadmap. Removed: KMS/ECDSA signature,
  `templates_enc` and `totp_seed_enc` in the bundle.
- **New edge endpoints**:
  - attempt routes: `GET /v1/attempt/{id}`, `POST /v1/attempt/{id}/otp/send`, `POST /v1/attempt/{id}/rendered`
  - streaming: `GET /v1/events` (SSE)
  - admin routes: `GET /v1/admin/store`, `POST /v1/admin/sync`, `POST /v1/admin/rate-limit/reset`,
    `POST|DELETE /v1/admin/eval/context`, `POST /v1/admin/clock`
  - DepthProbe routes: `GET /v1/depth/pending`, `POST /v1/depth/frames`. They are also served on `EDGE_LAN_PORT`
    (8001), LAN-only, and require `X-Depth-Token`. `/pending` issues a single-use `depth_nonce` that
    `DepthFramesMeta` must echo; `DepthFramesMeta` adds optional `accuracy` (`absolute|relative`, needed for D4).
  - `session/start` 201 also returns `recapture_count` and `depth_requested`.
- **Removed**: the `X-Eval-Label` header (replaced by `/v1/admin/eval/context`) and the Record3D depth bridge
  (`http://127.0.0.1:8765/v1/depth/checks`). Also removed: the names `/v1/authenticate`, `/v1/challenge`,
  `/v1/stepup`, `/v1/fallback/verify`, `/v1/enrol`, `/v1/attempts/{id}`, `/status`, `/admin/connectivity`.
- **Sync** items are the SC2.5 record exactly, plus `idempotency_key` and `hmac`. A batch can carry tombstones
  and has a hash-chain head. Batches are at most 50 items.
- **Metrics** add client-side latency (face lock → rendered), per-label latency and Clopper-Pearson bounds.

---

## 0. Conventions

| Item | Rule |
|---|---|
| Base URLs | Edge `http://127.0.0.1:8000`: localhost bind; CORS allows only `http://localhost:5173` and `http://127.0.0.1:5173` (methods GET/POST/PUT/DELETE, request headers `Content-Type` and `X-Admin-Token`, exposes `X-Latency-Ms`). When `EDGE_LAN_PORT` is set (demo: 8001), a second listener on `0.0.0.0:EDGE_LAN_PORT` serves **only** `GET /v1/depth/pending` and `POST /v1/depth/frames` for the DepthProbe iPhone app (§3.17). If that port is busy, the kiosk API still starts and `/v1/health` `detail.lan_listener` reports `bind_failed: …`. Cloud `https://<cloud-host>` in **AWS us-east-1** (sandbox constraint; production ap-south-1). There is no separate depth bridge. |
| Versioning | All paths prefixed `/v1` |
| Content type | `application/json` unless stated; `multipart/form-data` for frames, challenge, enrolment and depth |
| Time | Request/response timestamps are UTC ISO-8601 (`2026-11-14T04:35:12.345Z`). Client timing fields are epoch ms; the kiosk uses `performance.timeOrigin + performance.now()`. |
| Local time | Schedules are evaluated in `Asia/Kolkata`; local times are `"HH:MM"`. The edge clock is the demo clock when one is active (§3.14). |
| Scores | PAD, flash, moiré, device, mask and cosine scores are floats 0–1. Rekognition similarity is reported raw, 0–100 (`scores.rekognition`). |
| Latency | Header `X-Latency-Ms` (server wall time) on **every** response: edge 1 dp, cloud integer ms. Decisions also carry `latency_ms{total, liveness, match, schedule, policy}` (ints, server-side), plus the additive keys in §1. The user-visible time comes from §3.8. |
| Edge auth | Localhost bind + CORS. Admin routes require `X-Admin-Token` (= `ADMIN_TOKEN`, constant-time compare); a missing or wrong token gives `401 UNAUTHORIZED`. Admin routes: every `/v1/admin/*` route, `POST /v1/enroll` and `DELETE /v1/enroll/{user_id}`. `GET /v1/events` and `GET /v1/metrics` are localhost-only (127.0.0.1 bind; not on the LAN listener) and need **no** token. The DepthProbe routes use `X-Depth-Token` (§3.17). |
| Cloud auth | `X-Kiosk-Id`, `X-Timestamp` (epoch s) and `X-Signature`, plus `X-Api-Key`. `X-Signature` = hex HMAC-SHA256(`KIOSK_HMAC_KEY` as UTF-8, `METHOD\nPATH\nX-Timestamp\nhex(sha256(body))`). `PATH` includes `?query` when a query string is present; the server also accepts the bare path. Skew of ±60 s is allowed. Non-GET requests are single-use within the window (replay cache), so retries must be re-signed; `/v1/sync` (idempotent) and `/v1/schedule/check` (read-only) are exempt (`cloud/app/middleware.py` `REPLAY_EXEMPT`). Only `GET /v1/health` is public. Every cloud response carries `X-Server-Time` (epoch s). Cloud admin routes (§4.9) also need `X-Admin-Token`; a missing or wrong token gives `403 FORBIDDEN`. |
| Idempotency | Mutating cloud calls accept an `Idempotency-Key` header. `/v1/sync` uses a per-item `idempotency_key` (= `attempt_id`). |
| Canonical JSON | Wherever a hash, HMAC or signature covers JSON: `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")` |

**IDs**

| Entity | Format / values |
|---|---|
| Kiosk | `KIOSK_MAIN_01`, `KIOSK_LIB_01`, `KIOSK_LAB_01`, `KIOSK_HOSTEL_01`, `KIOSK_SRV_01` |
| Zone | `MAIN_GATE` (low), `LIBRARY` (low), `LAB_BLOCK` (medium), `HOSTEL` (medium), `SERVER_ROOM` (high) |
| User | `u_xxxx`, exactly `^u_[0-9a-z]{4}$` on every side (pseudonymous; e.g. `u_3c4d` = Priya N., `u_7a8b` = Rahul V.) |
| Staff | `^s_[0-9a-z_]{2,32}$` (e.g. `s_guard01`); override codes `OVR-NNN` (fixtures) / `OVR-R<mmddHHMMSS>-NN` (rotated) |
| Attempt / challenge / OTP / batch | `att_<ULID>` / `chl_<12 hex>` / `otp_<id>` / `b_<ULID>` |
| Nonces | attempt nonce `n_<token_urlsafe(18)>`; challenge nonce `<token_urlsafe(16)>`; depth nonce `dn_<token_urlsafe(16)>` (all CSPRNG) |

**HTTP status policy**

- Edge attempt endpoints (`frames`, `challenge`, `fallback`, `GET attempt`) return **HTTP 200 + DecisionResponse
  for every policy outcome**, including ALLOW, STEP_UP and DENY. That covers DENY `RATE_LIMITED` and
  DENY `SYSTEM_ERROR`.
- **Runtime exceptions on the edge are DENY `SYSTEM_ERROR`, never HTTP 500** (P1, R14):
  - A perception-stage or policy-runtime exception goes to `runtime.decide_error`, which also logs the minimal
    record. If that fails too, a static DENY `SYSTEM_ERROR` / CONTACT_DESK with `zone: "UNKNOWN"` is returned
    (`edge/attempts.py` `_decide`).
  - Unknown enum values in signals give DENY `SYSTEM_ERROR`.
  - P9 (every ALLOW is logged) is an explicit check, not an `assert`.
  - If the policy runtime cannot be constructed at all (missing `EDGE_DATA_KEY`, corrupt store), a fail-secure
    runtime answers DENY `SYSTEM_ERROR` to every attempt and `/v1/health` reports `degraded`.
- **Protocol errors** are non-2xx responses with this body:
  `{"error": {"code": "NONCE_EXPIRED", "message": "...", "attempt_id": "att_..."}}`.
  - Edge request-validation errors add `details[]` (`loc`, `msg`).
  - **`reason`** (v1.4): an optional machine-readable sub-reason inside `error` (e.g. `{"code": "INVALID_STATE",
    "reason": "ERASED_IN_BUNDLE", ...}`). Clients branch on `code` + `reason`, never on `message`. The edge
    forwards a cloud error's `reason` verbatim and adds `cloud_status` / `cloud_code`. Registry: §3.18.6. A cloud
    `404` **without** `reason` means "route not deployed" (§3.18.6 `ENDPOINT_NOT_DEPLOYED`).
  - The cloud omits `attempt_id` when it is not known and never echoes request input (bodies can carry images).
  - Protocol errors are used only for:
    - malformed requests
    - unknown or closed attempts
    - expired or reused nonces
    - wrong state
    - missing models
    - cloud-only operations while offline

  They are transport/protocol errors, distinct from decision reason codes. The kiosk must treat any
  protocol error, timeout or network failure as **no access** (fail-secure).

Protocol error codes (`edge/errors.py` `STATUS`, `cloud/app/errors.py` `STATUS_BY_CODE`):

| Code | HTTP | Meaning |
|---|---|---|
| `VALIDATION_ERROR` | 422 | malformed request (also: undecodable JPEG, too few frames, enrolment frames rejected, `challenge_id` mismatch) |
| `UNAUTHORIZED` | 401 | bad or missing auth (edge `X-Admin-Token` / `X-Depth-Token`; cloud HMAC headers) |
| `FORBIDDEN` | 403 | e.g. `kiosk_id` not served by this edge, `/v1/admin/clock` without `DEMO_MODE=1`, wrong or reused `depth_nonce`, **attempt nonce that does not match the attempt** (the internal `NONCE_INVALID` surfaces as 403 `FORBIDDEN`), cloud admin token missing |
| `NOT_FOUND` | 404 | unknown non-attempt resource: `DELETE /v1/enroll/{user_id}` for a user not enrolled here (cloud not configured), unknown route, cloud unknown kiosk or zone |
| `ATTEMPT_NOT_FOUND` | 404 | unknown attempt |
| `ATTEMPT_CLOSED` | 409 | attempt already terminal (ALLOW, DENY, or superseded by a recapture) |
| `INVALID_STATE` | 409 | e.g. fallback while no SECOND_FACTOR step is pending; rendered beacon before a decision; face already enrolled under another `user_id`; template cache unavailable for `/v1/admin/users` |
| `NONCE_EXPIRED` | 410 | nonce past its TTL |
| `NONCE_REUSED` | 409 | nonce already used |
| `PAYLOAD_TOO_LARGE` | 413 | body or part over the size limit. Cloud: request body > `MAX_BODY_BYTES` (6 MB). Edge: frame or probe part > 2 MB, depth part > 8 MB (`edge/app.py` `MAX_FRAME_BYTES` / `MAX_DEPTH_BYTES`). |
| `RATE_LIMITED` | 429 | **cloud-side request throttling only** |
| `CLOUD_UNAVAILABLE` | 503 | cloud unreachable or the AWS service is denied |
| `UPSTREAM_THROTTLED` | 503 | Rekognition throttling |
| `MODELS_UNAVAILABLE` | 503 | edge: face detector / ArcFace not loaded, PAD self-test not passed, or template cache unavailable. Used by `POST /v1/enroll`. Attempts never return it: a missing model gives DENY `SYSTEM_ERROR`. |
| `INTERNAL` | 500 | internal error (cloud catch-all; never used for an edge decision) |

The 429 `RATE_LIMITED` protocol error is unrelated to the `RATE_LIMITED` **decision reason code**. The kiosk
lockout is a DENY DecisionResponse (HTTP 200), described in §2.

---

## 1. DecisionResponse (returned by `frames`, `challenge`, `fallback`, `GET /v1/attempt/{id}`)

Exactly `DECISION_POLICY.md` §10 plus `stage`. Every key is always present (nullable fields are `null`, never omitted).

```python
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Decision = Literal["ALLOW", "STEP_UP", "DENY"]   # UI label for STEP_UP: "REQUEST VERIFICATION" (subtitle "step-up")
Mode = Literal["ONLINE", "OFFLINE"]
Stage = Literal["precheck", "quality", "injection", "liveness", "match", "schedule",
                "mode", "challenge", "fallback", "final", "system"]
BioResult = Literal["BIO_PASS", "BIO_UNSURE", "BIO_FAIL"]
ScheduleResult = Literal["IN_WINDOW", "GRACE_WINDOW", "OUTSIDE_WINDOW", "NO_ENTITLEMENT",
                         "ZONE_NOT_PERMITTED", "HOLIDAY", "REVOKED"]
CacheState = Literal["FRESH", "EXPIRED", "INVALID"]
NextActionType = Literal["OPEN_DOOR", "RECAPTURE", "CHALLENGE", "SECOND_FACTOR", "CONTACT_DESK", "NONE"]
StepName = Literal["CHALLENGE", "SECOND_FACTOR"]
FallbackMethod = Literal["TOTP", "CARD", "EMAIL_OTP", "STAFF_OVERRIDE"]
# Wire enum (edge/policy/signals.py). PUFF_CHEEKS stays accepted but is never issued: the shipped
# challenge.deformation_actions is ["SMILE", "OPEN_MOUTH"] (removed 2026-11-14 at the operator's request).
ChallengeAction = Literal["SMILE", "OPEN_MOUTH", "PUFF_CHEEKS", "BLINK", "TURN_LEFT", "TURN_RIGHT"]
DEFORMATION_ACTIONS = frozenset({"SMILE", "OPEN_MOUTH", "PUFF_CHEEKS"})
SECONDARY_ACTIONS = frozenset({"BLINK", "TURN_LEFT", "TURN_RIGHT"})
Hint = Literal["move_closer", "more_light", "hold_still", "one_person", "face_camera"]

# Closed list = DECISION_POLICY.md section 6 (required + added; RANDOM_CHALLENGE added in v1.1). Section 2 below.
ReasonCode = Literal[
    "RATE_LIMITED", "SYSTEM_ERROR",
    "MULTIPLE_FACES", "QUALITY_LOW_LIGHT", "QUALITY_BLUR", "QUALITY_POSE", "QUALITY_DEPTH_INVALID",
    "INJECTION_VIRTUAL_CAMERA",
    "SPOOF_PASSIVE", "SPOOF_DEVICE_DETECTED", "SPOOF_MOIRE", "SPOOF_FLASH_MISMATCH",
    "SPOOF_FLAT_DEPTH", "SPOOF_DEPTH_SCALE",
    "MASK_CUE_RIGID", "MASK_CUE_EDGE", "MASK_CUE_SHAPE", "MASK_CUE_SPECTRAL",
    "LIVENESS_UNSURE", "RANDOM_CHALLENGE",
    "MATCH_LOW", "MATCH_AMBIGUOUS", "NOT_ENROLLED",
    "SCHEDULE_OUTSIDE_WINDOW", "SCHEDULE_GRACE_WINDOW", "SCHEDULE_NO_ENTITLEMENT",
    "SCHEDULE_ZONE_NOT_PERMITTED", "SCHEDULE_HOLIDAY", "SCHEDULE_REVOKED", "SCHEDULE_HIGH_RISK_ZONE",
    "SCHEDULE_EXPIRED_CACHE", "SCHEDULE_BUNDLE_INVALID",
    "OFFLINE_MODE", "OFFLINE_HIGH_RISK_ZONE", "OFFLINE_FALLBACK_REQUIRED",
    "CHALLENGE_FAILED", "FALLBACK_OK", "FALLBACK_FAILED",
    "ACCESS_OK",
]


class _Out(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ChallengeSpec(_Out):
    challenge_id: str                       # chl_<12 hex>
    nonce: str                              # single-use; TTL = challenge.session_ttl_s (120 s)
    actions: list[ChallengeAction] = Field(min_length=2, max_length=2)   # random order
    step_window_ms: int                     # challenge.step_window_ms (1500)
    min_reaction_ms: int                    # challenge.min_reaction_ms (150)
    expires_at: datetime

    @model_validator(mode="after")
    def _one_deformation_one_secondary(self) -> "ChallengeSpec":
        kinds = sorted(a in DEFORMATION_ACTIONS for a in self.actions)
        if kinds != [False, True]:          # exactly 1 deformation (mandatory) + 1 secondary; never blink-only
            raise ValueError("challenge needs exactly one of SMILE|OPEN_MOUTH|PUFF_CHEEKS "
                             "and one of BLINK|TURN_LEFT|TURN_RIGHT")
        return self


class NextAction(_Out):
    type: NextActionType
    steps: list[StepName] = Field(default_factory=list)   # remaining step-up steps, in order
    methods: list[FallbackMethod] | None = None            # non-null iff SECOND_FACTOR in steps
    challenge: ChallengeSpec | None = None                 # non-null iff type == CHALLENGE
    attempts_left: int | None = None    # further failures tolerated for the pending step: first issue 1, after one failure 0 (= last try)
    retry_after_s: int | None = None    # only for DENY RATE_LIMITED
    hint: Hint | None = None            # only for RECAPTURE

    @model_validator(mode="after")
    def _shape(self) -> "NextAction":
        if self.type in ("CHALLENGE", "SECOND_FACTOR"):
            if not self.steps or self.steps[0] != self.type:
                raise ValueError("type must equal steps[0] for step-up actions")
        elif self.steps:
            raise ValueError("steps must be [] unless type is CHALLENGE or SECOND_FACTOR")
        if (self.challenge is not None) != (self.type == "CHALLENGE"):
            raise ValueError("challenge is set iff type == CHALLENGE")
        if (self.methods is not None) != ("SECOND_FACTOR" in self.steps):
            raise ValueError("methods is set iff SECOND_FACTOR is in steps")
        if self.hint is not None and self.type != "RECAPTURE":
            raise ValueError("hint only for RECAPTURE")
        return self


class Candidate(_Out):
    user_id: str                        # u_xxxx
    display: str                        # display name from the bundle; never logged / synced
    role: str | None = None             # bundle role (student, faculty, staff, ...), for the kiosk / operator UI


class Scores(_Out):
    """DECISION_POLICY.md section 10 keys; null = not computed (short-circuit) or NOT_AVAILABLE."""
    pad_mean: float | None = None                 # mean P_live over usable frames
    pad_pass_frames: int | None = None            # frames with P_live >= pad.pass_min
    flash_r: float | None = None                  # chroma correlation vs nonce sequence
    flash_amp: float | None = None                # mean |dRGB| in face ROI (0-255)
    moire: float | None = None                    # FFT moire score 0-1
    device_conf: float | None = None              # max phone/laptop/tv box conf overlapping the face
    depth: dict[str, float | None] | None = None  # d0..d5 / m1..m3 values; null = depth NOT_AVAILABLE
    mask: dict[str, float] = Field(default_factory=dict)   # cue -> score, e.g. {"m2_ring": 0.58}
    match_local: float | None = None              # local ArcFace top-1 cosine
    match_margin: float | None = None             # top1 - top2 (different user)
    rekognition: float | None = None              # top-1 similarity 0-100 (online only)
    rekognition_runner_up: float | None = None
    # per-signal status (edge/policy/engine.py): {pad, device, moire, flash, mask, depth, injection} ->
    # PASS | PASS_AMBIENT | UNSURE | FAIL | NOT_AVAILABLE | ADVISORY_<zone>; null if liveness never ran
    signals: dict[str, str] | None = None


class LatencyMs(BaseModel):
    model_config = ConfigDict(extra="allow")   # additive diagnostic keys, see the field rules below
    total: int       # server: frames request received -> response serialised
    liveness: int    # liveness branch wall time
    match: int       # match branch wall time (local + cloud, parallel with liveness)
    schedule: int    # local evaluate_schedule on the signed bundle (no cloud call, D2)
    policy: int      # fusion + combine + record write
    quality: int | None = None                       # frames only: JPEG decode + per-frame analysis
    face_lock_to_decision_server: int | None = None  # frames only: edge now - FramesMeta.face_lock_at_ms
    challenge_edge: int | None = None                # challenge only: whole edge handler
    fallback_edge: int | None = None                 # fallback only: whole edge handler (incl. cloud OTP verify)


class DecisionResponse(_Out):
    attempt_id: str
    kiosk_id: str
    zone: str                               # kiosk zone from the last valid bundle; "UNKNOWN" when there is none
    decision: Decision
    reason_codes: list[ReasonCode] = Field(min_length=1)   # stage order; UI shows the first
    resolved_codes: list[ReasonCode] = Field(default_factory=list)  # step-up triggers resolved by an ALLOW
    next_action: NextAction
    bio_result: BioResult | None            # null when short-circuited before biometrics
    schedule_result: ScheduleResult | None  # null when not evaluated
    mode: Mode
    cache_state: CacheState | None          # bundle state used for this decision; null if not consulted
    candidate: Candidate | None             # null on BIO_FAIL and before biometrics
    scores: Scores
    latency_ms: LatencyMs
    policy_version: str                     # == config/thresholds.yaml policy_version
    bundle_version: int | None
    display_message: str
    stage: Stage                            # stage that determined the decision

    @model_validator(mode="after")
    def _invariants(self) -> "DecisionResponse":
        codes, t = set(self.reason_codes), self.next_action.type
        if ("OFFLINE_MODE" in codes) != (self.mode == "OFFLINE"):
            raise ValueError("OFFLINE_MODE present iff mode == OFFLINE")
        if (self.decision == "ALLOW") != (t == "OPEN_DOOR"):
            raise ValueError("ALLOW iff next_action.type == OPEN_DOOR")
        if self.decision == "ALLOW" and "ACCESS_OK" not in codes:
            raise ValueError("every ALLOW carries ACCESS_OK")
        if self.decision == "STEP_UP" and t not in ("RECAPTURE", "CHALLENGE", "SECOND_FACTOR"):
            raise ValueError("STEP_UP needs RECAPTURE, CHALLENGE or SECOND_FACTOR")
        if self.decision == "DENY" and t not in ("CONTACT_DESK", "NONE"):
            raise ValueError("DENY needs CONTACT_DESK or NONE")
        if self.bio_result == "BIO_FAIL" and (self.candidate is not None or self.schedule_result is not None):
            raise ValueError("BIO_FAIL: no candidate shown, schedule not evaluated")
        if self.resolved_codes and self.decision != "ALLOW":
            raise ValueError("resolved_codes only on an ALLOW after step-up")
        return self
```

Field rules:

- **`stage`**: maps to the DECISION_POLICY §6 stages as follows.
  - pre-check → `precheck`
  - identity → `match`
  - step-up → `challenge` or `fallback`
  - any exception → `system`
  - a clean ALLOW → `final`; an ALLOW after a step-up → `challenge` or `fallback`
- **`bio_result`**: `null` for A1/A2/A4/A5 short-circuits and for quality-exhausted decisions. In those cases
  `candidate`, `schedule_result` and the match scores are `null`.
- **`cache_state`**: online, the state of the newest signed bundle (D2). Online it is always `FRESH`: an older
  bundle makes the attempt OFFLINE. Offline it is `FRESH`, `EXPIRED` or `INVALID` (DECISION_POLICY §5). It is
  `null` when the bundle was not consulted (short-circuit or BIO_FAIL). Exception: the quality-exhausted
  decisions (A3 STEP_UP SECOND_FACTOR and A6 high-risk DENY) carry the bundle `cache_state`.
- **`zone`**: the kiosk's zone from the last valid bundle (LVB). Zone and risk are only ever read from a verified
  bundle. With no LVB, `zone` is `"UNKNOWN"`, the zone is treated as high risk, and a non-failing biometric
  result gives DENY `SCHEDULE_BUNDLE_INVALID` / CONTACT_DESK (R6, §2).
- **`attempts_left`** (R15, `stepup.attempts_left_semantics: "retries_after"`): the number of further failures
  tolerated for the pending step.
  - A CHALLENGE (`1 + challenge.soft_fail_retries`) or SECOND_FACTOR (`stepup.max_attempts_per_step` = 2) step
    is first issued with `1`. After one failure it is re-issued with `0`, meaning this is the last try.
  - RECAPTURE: `quality.max_recaptures − recapture_count − 1`, i.e. `1` on the first recapture and `0` on the last.
- **`latency_ms`**:
  - On `challenge` and `fallback` responses it measures that request only: `liveness` and `match` = 0, and
    `total` is the policy time. The whole edge handler time is in `challenge_edge` / `fallback_edge`.
  - On `frames` responses, `quality` and `face_lock_to_decision_server` are added.
  - `total` is never lower than the runtime's own total.
- **`scores`** are rounded to 3 dp in the response. While the flash is advisory (§2), `flash_r` / `flash_amp`
  are still reported. `scores.signals` gives the zone of each liveness signal; an advisory signal reads
  `ADVISORY_<zone>` (e.g. `"flash": "ADVISORY_PASS"`) and had no decision effect.
- **Last-resort SYSTEM_ERROR**: if the runtime's own `decide_error` fails, the edge returns a static DENY
  `SYSTEM_ERROR` (`zone: "UNKNOWN"`, `stage: "system"`, `next_action.type: "CONTACT_DESK"`, plus `OFFLINE_MODE`
  when the mode is OFFLINE or unreadable). Implemented in `edge/attempts.py` `_static_system_error`: the body is a
  valid §1 DecisionResponse, with every `scores` key present (`null`, `mask: {}`) and the `latency_ms` keys `total`,
  `liveness`, `match`, `schedule`, `policy` as ints (0 when not measured). It is never ALLOW.
- **Display rules**:
  - Show `display_message` plus the human text of the first reason code (§2).
  - BIO_UNSURE + schedule deny shows the generic "Access not available — please contact the desk".
  - `ui.show_detailed_reasons` (demo: true) shows all codes.
  - The middle outcome is labelled **"REQUEST VERIFICATION"** with subtitle "step-up" (brief wording).
    The enum stays `STEP_UP`.

### 1.1 Example — online ALLOW (Priya at the library, Saturday 10:05 IST, in window; matrix N1)

The examples in §1 use the fixture users and kiosks of `config/schedule.example.json` (Priya, Rahul, the library and
server-room kiosks). The live bundle v45 covers `KIOSK_MAIN_01` / MAIN_GATE only, so on the live edge only the
MAIN_GATE variants can be reproduced.

```json
{
  "attempt_id": "att_01JDA3K7Q9V2M4N6P8R0S2T4V6",
  "kiosk_id": "KIOSK_LIB_01",
  "zone": "LIBRARY",
  "decision": "ALLOW",
  "reason_codes": ["ACCESS_OK"],
  "resolved_codes": [],
  "next_action": {"type": "OPEN_DOOR", "steps": [], "methods": null, "challenge": null,
                  "attempts_left": null, "retry_after_s": null, "hint": null},
  "bio_result": "BIO_PASS",
  "schedule_result": "IN_WINDOW",
  "mode": "ONLINE",
  "cache_state": "FRESH",
  "candidate": {"user_id": "u_3c4d", "display": "Priya N.", "role": "student"},
  "scores": {"pad_mean": 0.94, "pad_pass_frames": 5, "flash_r": 0.82, "flash_amp": 9.1,
             "moire": 0.12, "device_conf": 0.0, "depth": null, "mask": {},
             "match_local": 0.72, "match_margin": 0.31, "rekognition": 99.6, "rekognition_runner_up": null,
             "signals": {"pad": "PASS", "device": "PASS", "moire": "PASS", "flash": "ADVISORY_PASS",
                         "mask": "PASS", "depth": "NOT_AVAILABLE", "injection": "PASS"}},
  "latency_ms": {"total": 498, "liveness": 312, "match": 461, "schedule": 3, "policy": 2,
                 "quality": 41, "face_lock_to_decision_server": 1530},
  "policy_version": "2026-11-14.3",
  "bundle_version": 42,
  "display_message": "Access granted",
  "stage": "final"
}
```

### 1.2 Example — STEP_UP CHALLENGE for one mask cue (Aarav at the main gate; matrix N9)

The single weak `MASK_CUE_EDGE` cue makes the result BIO_UNSURE with a LIVENESS cause. Online, in window and in
a low-risk zone, so the only step is a CHALLENGE (no second factor).

```json
{
  "attempt_id": "att_01JDA3M2C8D4F6H8J0K2M4N6P8",
  "kiosk_id": "KIOSK_MAIN_01",
  "zone": "MAIN_GATE",
  "decision": "STEP_UP",
  "reason_codes": ["MASK_CUE_EDGE"],
  "resolved_codes": [],
  "next_action": {
    "type": "CHALLENGE",
    "steps": ["CHALLENGE"],
    "methods": null,
    "challenge": {"challenge_id": "chl_3f9a1c2b7d4e", "nonce": "Hk3q9ZpL0wRtVb7Xc2Nd4A",
                  "actions": ["TURN_LEFT", "OPEN_MOUTH"], "step_window_ms": 1500, "min_reaction_ms": 150,
                  "expires_at": "2026-11-14T04:37:12.400Z"},
    "attempts_left": 1,
    "retry_after_s": null,
    "hint": null
  },
  "bio_result": "BIO_UNSURE",
  "schedule_result": "IN_WINDOW",
  "mode": "ONLINE",
  "cache_state": "FRESH",
  "candidate": {"user_id": "u_1a2b", "display": "Aarav S.", "role": "student"},
  "scores": {"pad_mean": 0.83, "pad_pass_frames": 4, "flash_r": 0.77, "flash_amp": 7.4,
             "moire": 0.09, "device_conf": 0.0, "depth": null, "mask": {"m2_ring": 0.58},
             "match_local": 0.66, "match_margin": 0.27, "rekognition": 99.2, "rekognition_runner_up": null},
  "latency_ms": {"total": 503, "liveness": 330, "match": 468, "schedule": 3, "policy": 2},
  "policy_version": "2026-11-14.3",
  "bundle_version": 42,
  "display_message": "Please follow the on-screen check",
  "stage": "liveness"
}
```

### 1.3 Example — offline, high-risk zone: STEP_UP SECOND_FACTOR (Rahul at the server room; matrix F2)

Staff `u_7a8b` has an explicit SERVER_ROOM grant, and exception `EXC-SRV-HACK` opens 09:00–21:00 on 2026-11-14,
so the result is IN_WINDOW. Offline, a high-risk zone never auto-ALLOWs: methods = `stepup.methods.offline_high_risk`.

```json
{
  "attempt_id": "att_01JDA3R5T7V9X1Z3B5D7F9H1K3",
  "kiosk_id": "KIOSK_SRV_01",
  "zone": "SERVER_ROOM",
  "decision": "STEP_UP",
  "reason_codes": ["OFFLINE_MODE", "OFFLINE_HIGH_RISK_ZONE", "OFFLINE_FALLBACK_REQUIRED"],
  "resolved_codes": [],
  "next_action": {"type": "SECOND_FACTOR", "steps": ["SECOND_FACTOR"], "methods": ["TOTP", "STAFF_OVERRIDE"],
                  "challenge": null, "attempts_left": 1, "retry_after_s": null, "hint": null},
  "bio_result": "BIO_PASS",
  "schedule_result": "IN_WINDOW",
  "mode": "OFFLINE",
  "cache_state": "FRESH",
  "candidate": {"user_id": "u_7a8b", "display": "Rahul V.", "role": "staff"},
  "scores": {"pad_mean": 0.91, "pad_pass_frames": 5, "flash_r": 0.80, "flash_amp": 8.2,
             "moire": 0.10, "device_conf": 0.0, "depth": null, "mask": {},
             "match_local": 0.69, "match_margin": 0.33, "rekognition": null, "rekognition_runner_up": null},
  "latency_ms": {"total": 341, "liveness": 298, "match": 41, "schedule": 2, "policy": 1},
  "policy_version": "2026-11-14.3",
  "bundle_version": 42,
  "display_message": "Offline: please verify with your code or a staff member",
  "stage": "mode"
}
```

### 1.4 Example — DENY screen replay (phone showing Priya's photo; matrix N12)

PAD fails on the majority of frames. A phone box contains the face, and moiré ≥ 0.70 is corroborated by
PAD ≠ PASS. The flash is reported but, while advisory, it has no decision effect. Its amplitude is below
`min_amplitude` here because the screen emits its own light; when enforced, that would make the flash WEAK.
This DENY therefore rests on passive PAD + the device detector + moiré. On BIO_FAIL, unsure codes are not added. `candidate` is not shown. The top-1 user is kept internally as
`candidate_user_id` for targeted-spoof alerts.

```json
{
  "attempt_id": "att_01JDA3W8Y0A2C4E6G8J0L2N4Q6",
  "kiosk_id": "KIOSK_LIB_01",
  "zone": "LIBRARY",
  "decision": "DENY",
  "reason_codes": ["SPOOF_PASSIVE", "SPOOF_DEVICE_DETECTED", "SPOOF_MOIRE"],
  "resolved_codes": [],
  "next_action": {"type": "NONE", "steps": [], "methods": null, "challenge": null,
                  "attempts_left": null, "retry_after_s": null, "hint": null},
  "bio_result": "BIO_FAIL",
  "schedule_result": null,
  "mode": "ONLINE",
  "cache_state": null,
  "candidate": null,
  "scores": {"pad_mean": 0.21, "pad_pass_frames": 0, "flash_r": 0.18, "flash_amp": 1.4,
             "moire": 0.81, "device_conf": 0.87, "depth": null, "mask": {},
             "match_local": 0.61, "match_margin": 0.22, "rekognition": 97.4, "rekognition_runner_up": null},
  "latency_ms": {"total": 472, "liveness": 305, "match": 452, "schedule": 0, "policy": 2},
  "policy_version": "2026-11-14.3",
  "bundle_version": 42,
  "display_message": "Access denied",
  "stage": "liveness"
}
```

---

## 2. Canonical reason codes

This is the closed list of `DECISION_POLICY.md` §6 (39 codes; `RANDOM_CHALLENGE` was added in v1.1). No other codes may
appear in `reason_codes` or `resolved_codes`. "Typical decision" is indicative: DECISION_POLICY §3–§9 decide
when each code fires. `reason_codes` are in stage order: pre-check, quality, injection, liveness hard, mask,
liveness unsure, identity, schedule, mode, step-up, final. Tests compare sets.

**Quality outcome (applies to all five quality codes).** While `recapture_count < quality.max_recaptures` (2):
STEP_UP / RECAPTURE with a `hint`. When recaptures are exhausted:

- **Low/medium-risk zone**: STEP_UP / SECOND_FACTOR, `methods` = `stepup.methods.quality_exhausted`
  (`["STAFF_OVERRIDE"]`), `reason_codes` = the quality codes. This is manual review by
  desk staff ("OTP or manual review" in the brief). On success the result is ALLOW `[ACCESS_OK, FALLBACK_OK]`,
  with `resolved_codes` = the quality codes and `staff_id` recorded. The schedule is not evaluated (no
  identity): the staff member vouches. Offline adds `OFFLINE_MODE` and `OFFLINE_FALLBACK_REQUIRED`.
- The injection check runs first, also on a quality-exhausted attempt: FAIL → DENY `INJECTION_VIRTUAL_CAMERA`
  (A4 / Q19). An unknown zone risk is treated as high.
- **High-risk zone** (offline: any zone above `offline.auto_allow_max_risk`): DENY / CONTACT_DESK.

| Code | Stage | Typical decision (`next_action`) | Trigger | Kiosk text |
|---|---|---|---|---|
| `RATE_LIMITED` | pre-check | DENY (NONE, `retry_after_s`) | Kiosk lockout: ≥ `rate_limit.max_failures` (5) **attack-evidence** DENYs within `window_s` (180 s) → `lockout_s` (5 s; operator request, was 60). See the rate-limit rules below the table. | "Kiosk paused, try again in N s" |
| `SYSTEM_ERROR` | any (`stage: system`) | DENY (CONTACT_DESK) | Exception, invalid input, missing signal, unparsable config (P1) | "System error, please contact the desk" |
| `MULTIPLE_FACES` | quality | Quality outcome (hint `one_person`) | Secondary face ≥ 0.5 × main face area | "One person at a time" |
| `QUALITY_LOW_LIGHT` | quality | Quality outcome (hint `more_light`) | Face luma outside [60, 210] or over-exposed fraction > 0.15 (dark or backlit) | "More light needed" |
| `QUALITY_BLUR` | quality | Quality outcome (hint `hold_still`) | Laplacian variance < 80 | "Please hold still" |
| `QUALITY_POSE` | quality | Quality outcome (hint `face_camera`) | Face < 112 px, IOD < 60 px, \|yaw\| > 25°, \|pitch\| or \|roll\| > 20° | "Move closer and face the camera" |
| `QUALITY_DEPTH_INVALID` | quality | Quality outcome (hint `move_closer`) | Depth enabled and D0 valid ratio < 0.40 (sunlight, glasses, out of range) | "Depth check unclear, please retake" |
| `INJECTION_VIRTUAL_CAMERA` | injection | DENY (NONE) | Virtual-camera label, or non-monotonic / out-of-range frame timing | "Camera not trusted" |
| `SPOOF_PASSIVE` | liveness | DENY (NONE) | `P_live` ≤ `pad.fail_max` (0.30) on a **strict majority** of usable frames (R11). PASS needs ≥ `pad.min_pass_frames` (3) frames ≥ `pad.pass_min` (0.80; offline 0.85) **and** at most 1 frame ≤ 0.30. Anything else is UNSURE and gives `LIVENESS_UNSURE`. | "Liveness check failed" |
| `SPOOF_DEVICE_DETECTED` | liveness | DENY (NONE) | Phone/laptop/TV box conf ≥ `device_detector.fail_conf` (0.40) containing ≥ 80 % of the face. An overlapping box with conf ≥ `unsure_conf` (0.25) that is not a FAIL gives `LIVENESS_UNSURE` (R10). A failed detector run nulls PAD, so the attempt can never auto-ALLOW. | "Screen detected" |
| `SPOOF_MOIRE` | liveness | DENY (NONE) | Moiré ≥ 0.70 **and** (PAD ≠ PASS or flash ≠ PASS). While the flash is advisory it counts as PASS here, so corroboration comes from PAD. Uncorroborated or 0.40–0.70 gives `LIVENESS_UNSURE` instead. **Enforced** (`liveness.moire.enforce: true`); with `false` it would be advisory (`ADVISORY_<zone>`, no effect), but a missing moiré measurement stays UNSURE either way. Known false positives (dev data): genuine flash-lit frames scored 0.42–0.79, so a genuine user can get REQUEST VERIFICATION, and a genuine user with moiré ≥ 0.70 whose PAD is not PASS gets this DENY. | "Screen pattern detected" |
| `SPOOF_FLASH_MISMATCH` | liveness | DENY (NONE), **only when `liveness.flash.enforce: true`** | Amplitude ≥ `min_amplitude` (2.0) and (r < `fail_max_r` 0.30, lag outside `lag_min_frames`–`lag_max_frames` (0–8 frames), or wrong colour order). `r` is the edge-measured frame correlation only. WEAK (amplitude < 2.0) and a lag std > `lag_max_std_frames` (1.5) only block PASS: they give UNSURE (`LIVENESS_UNSURE` when enforced), never FAIL. **ADVISORY now** (`enforce: false`): measured and reported (internal signal `ADVISORY_<zone>`), no decision effect, so this code is never emitted. See the flash note below the table. | "Light check failed" |
| `SPOOF_FLAT_DEPTH` | liveness | DENY (NONE) | Depth D1, D2 or D3 FAIL (flat or bent plane, no nose relief) | "3D check failed" |
| `SPOOF_DEPTH_SCALE` | liveness | DENY (NONE) | D4 metric inter-pupil distance outside 45–80 mm (absolute depth only) | "3D check failed" |
| `MASK_CUE_RIGID` | liveness (also from a challenge, R5) | DENY (NONE) | M1: blendshape says the face moved, but depth stays rigid (mouth residual < 4 mm). Decisive, so an immediate DENY. | "Extra check failed" |
| `MASK_CUE_EDGE` | liveness | STEP_UP (CHALLENGE) for ≥ 1 cue with < 2 strong; DENY (NONE) for ≥ 2 strong cues | M2 eye-hole / outline ring (ring ≥ 0.50 weak, ≥ 0.75 strong) or depth step ≥ 10 mm. The RGB ring is **enforced** (`liveness.mask.m2_rgb_enforce: true`; `false` = advisory, reported in `scores.mask` / `advisory_cues` only). Known false positive (dev data): spectacle frames scored 0.35–0.80, so glasses can step up a genuine user. | "Extra check needed" |
| `MASK_CUE_SHAPE` | liveness | as `MASK_CUE_EDGE` | M3 depth vs enrolled template ≥ 6 mm (weak), ≥ 8 mm (strong) | "Extra check needed" |
| `MASK_CUE_SPECTRAL` | liveness | as `MASK_CUE_EDGE` | Optional (disabled by default): non-skin flash response | "Extra check needed" |
| `LIVENESS_UNSURE` | liveness | STEP_UP (CHALLENGE; offline also SECOND_FACTOR) | Any liveness signal in its UNSURE band. Includes: PAD UNSURE (R11), device box 0.25–0.40 overlapping the face (R10), an unknown camera label only when `injection.unknown_label_is_unsure` is true (currently false: an unknown non-virtual label is PASS), D0 0.40–0.60, flash WEAK when enforced and the ambient exception does not apply, and **flash NOT_AVAILABLE because `flash_enabled=false`** (accessibility path, R3/D5: never auto-ALLOW without the flash check, even while the flash is advisory). | "Please follow the on-screen check" |
| `RANDOM_CHALLENGE` | liveness | STEP_UP (CHALLENGE) | **On** (restored 2026-11-14 at the operator's request): `challenge.random_rate` is **0.15 online / 0.30 offline** (`offline.overrides.challenge.random_rate`). A BIO_PASS that would be ALLOW is converted with that probability as a rigid-mask defence (D6): one draw per would-be ALLOW, never on STEP_UP or DENY. The challenge is one of SMILE / OPEN_MOUTH plus one of BLINK / TURN_LEFT / TURN_RIGHT. Demo control via `POST /v1/admin/random-challenge` (§3.14a: `FORCE_NEXT`, `FORCE`, `OFF`, `AUTO`). On pass the result is ALLOW `[ACCESS_OK]`, `resolved_codes: ["RANDOM_CHALLENGE"]`. | "Quick extra check" |
| `MATCH_LOW` | identity (`stage: match`) | STEP_UP (SECOND_FACTOR) | Low-confidence band (UNSURE, **not** a failure): local cosine in [0.30, allow), or Rekognition 80–99 | "Please verify your identity" |
| `MATCH_AMBIGUOUS` | identity | STEP_UP (SECOND_FACTOR) | Margin top1 − top2 too small, Rekognition runner-up ≥ 80, local/Rekognition disagreement (local top-1 is a different user with cosine ≥ `identity.cross_check_conflict_min_cosine` 0.50, R9), no usable local cross-check online, or identity switch between first and last frame | "Please verify your identity" |
| `NOT_ENROLLED` | identity | DENY (CONTACT_DESK) | The **only** match FAIL: local top-1 < 0.30, or Rekognition < 80 / no match, or (offline / Rekognition disabled) the template cache is unusable (> 72 h). Online with Rekognition, a missing local cross-check gives `MATCH_AMBIGUOUS` instead. | "Not enrolled, please contact the desk" |
| `SCHEDULE_OUTSIDE_WINDOW` | schedule | DENY (NONE); with BIO_UNSURE, DENY (CONTACT_DESK) | No window covers t0, beyond grace | "Outside your access hours" |
| `SCHEDULE_GRACE_WINDOW` | schedule | STEP_UP (SECOND_FACTOR) with BIO_PASS; with BIO_UNSURE, DENY (CONTACT_DESK) | Within `grace_minutes` (15) of a window edge (0 for high-risk zones) | "Extra check needed (outside hours)" |
| `SCHEDULE_NO_ENTITLEMENT` | schedule | DENY (CONTACT_DESK) | Unknown in the bundle, validity range or visitor pass not covering t0 | "No access entitlement" |
| `SCHEDULE_ZONE_NOT_PERMITTED` | schedule | DENY (CONTACT_DESK) | Role or user not permitted in this zone | "Zone not permitted" |
| `SCHEDULE_HOLIDAY` | schedule | DENY (NONE) | Holiday or closure for this zone, and the role is not exempt | "Campus closed today" |
| `SCHEDULE_REVOKED` | schedule | DENY (CONTACT_DESK) | User revoked (bundle or revocation feed). Time-aware: applies when `revoked_at` ≤ t0. Checked first (precedence over every other schedule result). Revoked users' templates are purged at the next refresh, so offline they come out `NOT_ENROLLED` (R16). The code currently excludes them from the gallery search instead, which has the same offline result **(code pending:** actual purge). | "Access revoked" |
| `SCHEDULE_HIGH_RISK_ZONE` | schedule | STEP_UP (SECOND_FACTOR, `online_high_risk` methods) | Online high-risk zone needs a step-up even IN_WINDOW, when `schedule.high_risk_requires_stepup_online` is true (default; R8) | "Second factor required for this zone" |
| `SCHEDULE_EXPIRED_CACHE` | mode | STEP_UP (SECOND_FACTOR `[STAFF_OVERRIDE]`) for BIO_PASS IN_WINDOW/GRACE and BIO_UNSURE IN_WINDOW (E1/E3); added to the DENY for deny-type results and for BIO_UNSURE + GRACE (E2/E4, CONTACT_DESK) | Offline and bundle past `min(expires_at, issued_at + 12 h)`. Stale data may deny, never allow (P5). | "Offline: staff verification needed" |
| `SCHEDULE_BUNDLE_INVALID` | mode | **No last valid bundle** (none ever verified): DENY (CONTACT_DESK), `zone: "UNKNOWN"`, `schedule_result: null` (R6). **LVB present but clock rolled back** (now < LVB `issued_at` − 300 s, offline): STEP_UP (SECOND_FACTOR `cache_untrusted` = `[STAFF_OVERRIDE]`, preceded by CHALLENGE if liveness was unsure). | A received bundle that fails verification is rejected with an alert and **never** replaces the LVB. A bundle file tampered on disk while running is rejected the same way, and the in-memory LVB stays in force. Override codes and kiosk zone/risk always come from the LVB. | "Please contact the desk" / "Offline: staff verification needed" |
| `OFFLINE_MODE` | mode | (informational) | Present **iff** `mode == "OFFLINE"`, on every decision | "Offline mode" badge |
| `OFFLINE_HIGH_RISK_ZONE` | mode | STEP_UP (SECOND_FACTOR, `offline_high_risk` = `[TOTP, STAFF_OVERRIDE]`; `[STAFF_OVERRIDE]` when the bundle is EXPIRED, E1) | Offline in a high-risk zone (or above `auto_allow_max_risk`) | "Offline: second factor required" |
| `OFFLINE_FALLBACK_REQUIRED` | mode | STEP_UP (SECOND_FACTOR) | Added whenever an offline step-up includes a SECOND_FACTOR step | "Offline: enter code / tap card" |
| `CHALLENGE_FAILED` | step-up (`stage: challenge`) | DENY (NONE) after a hard fail, a 2nd soft fail or session expiry; STEP_UP (CHALLENGE, new nonce, `attempts_left: 0`) after the first soft fail | Wrong / early / absent response, track lost, identity switch | "Check failed" |
| `FALLBACK_OK` | step-up (`stage: fallback`) | ALLOW (OPEN_DOOR), with `ACCESS_OK` | Second factor or staff override verified | "Verified" |
| `FALLBACK_FAILED` | step-up (`stage: fallback`) | STEP_UP (SECOND_FACTOR, `attempts_left: 0`) on the first failure; DENY (NONE) when exhausted or the session expired | Wrong, replayed or expired code, method not in `methods`, card of another user | "Verification failed" |
| `ACCESS_OK` | final | ALLOW (OPEN_DOOR) | Every ALLOW carries it (P9) | "Access granted" |

**Rate-limit rules (`RATE_LIMITED`, D3)**

- **Counted DENYs**:
  - any `SPOOF_*`
  - `MASK_CUE_RIGID` or a strong-mask DENY
  - `INJECTION_VIRTUAL_CAMERA`
  - `CHALLENGE_FAILED`
  - `FALLBACK_FAILED`
- **Never counted**: schedule, identity (`NOT_ENROLLED`), quality, `SYSTEM_ERROR` and `RATE_LIMITED` DENYs.
  A DENY that carries any `SCHEDULE_*` code is never counted, even if it also carries a mask cue.
- **Config**: `rate_limit.counted_code_prefixes` (`SPOOF_`, `MASK_CUE_`, `INJECTION_`), `counted_codes`
  (`CHALLENGE_FAILED`, `FALLBACK_FAILED`), `max_failures` 5, `window_s` 180 and `lockout_s` 5.
  `rate_limit.enabled` is true by default; an eval or demo profile may disable it.
- **Clock**: the limiter runs on the monotonic clock, so the demo clock does not affect it.
- **On lockout**: the policy runtime records `ALERT_RATE_LIMIT_LOCKOUT` in its in-memory event log. That log is
  not exposed on any HTTP route yet (`/v1/events` carries only `decision` and `rendered`).
  `POST /v1/admin/rate-limit/reset` clears the counter. `GET /v1/mode` `rate_limit` shows
  `{enabled, locked, retry_after_s}`.
- **Re-lock**: the counted events stay in the sliding window after a lockout ends. While ≥ `max_failures` (5)
  counted DENYs remain within `window_s` (180 s), every further counted DENY starts a new 5 s lockout.

**Flash note (advisory mode, C3)**

`liveness.flash.enforce` is **false** until the kiosk frame timing is re-validated. While advisory:

- The flash is still issued (3 colours) and measured. `scores.flash_r` / `flash_amp` are reported.
- It has **no decision effect**: no `SPOOF_FLASH_MISMATCH`, no WEAK → `LIVENESS_UNSURE`, and no ambient
  exception. For moiré corroboration it counts as PASS.
- The non-flash accessibility path (`flash_enabled: false`) still gives `LIVENESS_UNSURE` → CHALLENGE.
- Video/screen-replay defence therefore rests on passive PAD + the phone/laptop/TV detector + moiré (+ depth when
  `liveness.depth.enabled`). The colour-flash nonce is the designed video-replay defence and is re-enabled
  after validation. **Never present it as enforced.**

When enforced, the online ambient exception (WEAK flash treated as PASS) needs PAD PASS with mean
`P_live` ≥ `pad.strong_live` (0.90), a clean device detector and moiré < `moire.unsure_score` (R12). It is
never applied offline.

**Matcher authority (C4, `edge/policy/engine.py` stage 2–4, `edge/policy/identity.py`)**

Decisions are always made on the edge (local-first). The cloud only supplies a Rekognition score.

| Situation | Mode of the attempt | Identity rule |
|---|---|---|
| Online, `match.rekognition.enabled: true`, `/v1/match` OK | ONLINE | Rekognition is authoritative (DECISION_POLICY §3.5). The local ArcFace matcher can only tighten: a cross-check conflict, a missing local cross-check or a first/last-frame identity switch gives `MATCH_AMBIGUOUS`. |
| Online, Rekognition enabled, `/v1/match` error / timeout (> `rekognition_timeout` 700 ms; with the early probe, > `rekognition_probe_deadline` 1500 ms from probe start, §3.1a) / non-200 | **OFFLINE** for this attempt (P7). The failure also counts as a heartbeat miss. | Local matcher, offline bars. Every other threshold is re-applied with the offline values on the same raw scores. |
| Online, `match.rekognition.enabled: false` | ONLINE (online liveness bars, online schedule) | Local matcher with the **offline (stricter) identity bars**. No cloud miss is recorded. |
| Offline / SYNCING | OFFLINE | Local matcher, offline bars |

With `match.rekognition.enabled: false` the edge makes no `/v1/match` call at all (no cloud latency, no miss), and
it also skips the call when the next attempt would be OFFLINE anyway (`edge/attempts.py` `match_branch`).

**Current state (cold connections, measured 2026-11-14)**: from the venue network the `/v1/match` round trip is
about 0.4–1.4 s, so most online attempts miss the 700 ms budget. Those decisions carry `OFFLINE_MODE` and
`scores.rekognition: null` while the badge says ONLINE (the heartbeat still succeeds); `GET /v1/mode`
`cloud_match.degraded` is true after such an attempt. `session/start` pre-opens the keep-alive connection
(`warm_cloud_match`); the early probe (§3.1a, live since the edge restart with policy 2026-11-14.3, latency not yet
measured) is the fix.

**Limits and invariants**

- `quality.max_recaptures` = 2. Two recaptures are allowed; the 3rd quality failure is "exhausted".
- `challenge.soft_fail_retries` = 1. One retry with a new nonce after a soft fail; a hard fail DENYs immediately.
- `stepup.max_attempts_per_step` = 2. Two second-factor tries, then DENY `FALLBACK_FAILED`.
- Step-up session TTL `stepup.session_ttl_s` = `challenge.session_ttl_s` = 120 s. Expiry gives DENY with the
  pending step's failure code (R10).
- Staff-override brute force: 3 wrong codes lock `STAFF_OVERRIDE` on the kiosk for 300 s
  (`fallback.staff_override`).
- **DENY is terminal**, and ALLOW is terminal. Any later step-up or fallback POST returns `409 ATTEMPT_CLOSED`.
  A schedule DENY can never be fixed by a fallback (P8).
- `reason_codes` is never empty. `OFFLINE_MODE` is present iff `mode == "OFFLINE"`. Schedule codes appear only
  after a non-FAIL biometric result. `resolved_codes` is non-empty only on an ALLOW after a step-up.

---

## 3. Edge service API (`http://127.0.0.1:8000`)

### 3.1 `POST /v1/session/start` → 201

Starts an attempt. The response carries the anti-replay nonce and the random flash sequence.

```python
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Mode = Literal["ONLINE", "OFFLINE"]


class _In(BaseModel):
    model_config = ConfigDict(extra="ignore")   # edge request models ignore unknown fields


class ClientInfo(_In):
    camera_label: str = ""                # MediaStreamTrack.label
    user_agent: str = ""
    screen: dict[str, Any] = Field(default_factory=dict)   # e.g. {"width": 1920, "height": 1080, "refresh_hz": 60}


class SessionStartRequest(_In):
    kiosk_id: str                         # must equal the edge's KIOSK_ID (DEMO_MODE=1: any kiosk in bundle scope)
    claimed_user_id: str | None = None    # card/QR tapped first -> 1:1 match
    client: ClientInfo = Field(default_factory=ClientInfo)
    flash_enabled: bool = True            # False = accessibility non-flash path -> LIVENESS_UNSURE -> CHALLENGE (R3)
    recapture_of: str | None = None       # attempt_id whose next_action is RECAPTURE


class FlashStep(BaseModel):
    color: str                            # "#RRGGBB", from a 6-colour off-primary palette, each colour once
    offset_ms: int                        # from capture start
    duration_ms: int


class CaptureSpec(BaseModel):
    frames: int                           # quality.frames_per_attempt (5)
    window_ms: int                        # liveness.flash.duration_ms (700)
    max_width_px: int = 1280              # 640 px left the face at ~50 px IOD (< quality.min_interocular_px 60)
    jpeg_quality: float = 0.85


class SessionStartResponse(BaseModel):
    attempt_id: str                       # att_<ULID>
    nonce: str                            # n_<token>; single-use, TTL 10 s, bound to this attempt
    flash_sequence: list[FlashStep]       # exactly 3 distinct colours x ~233 ms; [] if flash disabled
    capture: CaptureSpec
    mode: Mode                            # mode at session start; the attempt may still become OFFLINE (P7)
    expires_at: datetime                  # issued + 10 s
    recapture_count: int = 0              # 0, or recapture_of's recapture_count + 1
    depth_requested: bool = False         # True when a PASSIVE depth capture was queued for DepthProbe
```

Request:

```json
{"kiosk_id": "KIOSK_LIB_01", "claimed_user_id": null,
 "client": {"camera_label": "FaceTime HD Camera", "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "screen": {"width": 1920, "height": 1080, "refresh_hz": 60}},
 "flash_enabled": true, "recapture_of": null}
```

Response 201:

```json
{"attempt_id": "att_01JDA3K7Q9V2M4N6P8R0S2T4V6", "nonce": "n_4c1eT9xQb7Lm2Rz8Vw0KpYdH",
 "flash_sequence": [{"color": "#FF4D4D", "offset_ms": 0, "duration_ms": 233},
                    {"color": "#4D6BFF", "offset_ms": 233, "duration_ms": 233},
                    {"color": "#4DFF6A", "offset_ms": 466, "duration_ms": 234}],
 "capture": {"frames": 5, "window_ms": 700, "max_width_px": 1280, "jpeg_quality": 0.85},
 "mode": "ONLINE", "expires_at": "2026-11-14T04:35:21.700Z", "recapture_count": 0, "depth_requested": false}
```

Rules:

- **Flash sequence** (R17):
  - Exactly **3** distinct colours (`liveness.flash.colours_min = colours_max = 3`), drawn at random per attempt
    from `#FF4D4D`, `#4DFF6A`, `#4D6BFF`, `#FFF04D`, `#FF4DFF`, `#4DFFFF` (off-primary, no saturated red).
  - Each colour is shown for ~233 ms in the `liveness.flash.duration_ms` (700 ms) window: 2 changes in 0.7 s
    (2.86/s), within the `max_changes_per_s` (3) photosensitivity bound. The edge refuses to build a sequence that would break it.
  - If `flash_enabled` is false or `liveness.flash.enabled` is false, `flash_sequence` is `[]`. The flash
    signal is then NOT_AVAILABLE, which means `LIVENESS_UNSURE` and a mandatory CHALLENGE (R3/D5).
  - The flash is currently **advisory** (§2 flash note): measured and reported, but no decision effect.
- **`recapture_of`**:
  - It must name an attempt of this kiosk whose latest decision is STEP_UP / RECAPTURE.
  - Otherwise the edge returns `409 INVALID_STATE`, or `404 ATTEMPT_NOT_FOUND` for an unknown attempt.
  - The old attempt is closed. The new attempt carries `recapture_count` = old + 1.
- **Depth**: when `liveness.depth.enabled` is true, the edge queues a PASSIVE depth capture for the DepthProbe
  app (§3.17) and sets `depth_requested: true`.
- **Errors**: `403 FORBIDDEN` for a kiosk that this edge does not serve; `422 VALIDATION_ERROR`.

### 3.1a `POST /v1/attempt/{attempt_id}/probe` → 202 (early cloud probe, new in v1.3)

**State**: implemented (`edge/app.py` `attempt_probe` / `_probe_window`, `edge/attempts.py` `start_probe` /
`bind_probe` / `_probe_cloud`, response model `edge/schemas.py` `ProbeResponse`, YAML key
`latency_budget_ms.rekognition_probe_deadline`, kiosk `submitProbe`). Live since the edge restart with policy
2026-11-14.3 (`GET /v1/mode` `policy_bars.rekognition_probe_deadline_ms` = 1500). Its latency effect has **not been
measured** yet. Without a probe the cloud match starts only after the frames arrive (§3.2).

Why: the cloud `/v1/match` round trip from the venue is about 0.4–1.4 s (dev observation). Started only after the
frames arrive with a 700 ms budget, most online attempts time out and are decided OFFLINE (P7) while the badge says
ONLINE. The probe starts the cloud match right after face lock, in parallel with the 0.7 s capture.

`multipart/form-data`, exactly one file part (no `meta` part):

| Part | Type | Notes |
|---|---|---|
| `probe` | `image/jpeg` | The face-lock frame. ≤ 2 MB (`MAX_FRAME_BYTES`); decoded size ≤ 4096 × 4096 px (`MAX_JPEG_SIDE_PX`) |

Response 202 (`ProbeResponse`: `accepted` is always `true`, `cloud` is `"started"` or `"skipped"`):

```json
{"accepted": true, "cloud": "started"}
```

- **Order of checks** (`attempt_probe`): unknown `attempt_id` → `404 ATTEMPT_NOT_FOUND`. Then the probe window
  (`_probe_window`): the attempt must be open (not terminal), its nonce unused and no frames received yet,
  otherwise `409 INVALID_STATE` ("probe only between session/start and the frames upload"); a second probe for the
  same attempt → `409 INVALID_STATE` ("one per attempt"). Then the multipart body is parsed (malformed →
  `422 VALIDATION_ERROR`); a missing `probe` part, a non-file `probe` part or an empty one → `422 VALIDATION_ERROR`;
  more than 2 MB → `413 PAYLOAD_TOO_LARGE` (a part above the 4 MB multipart parser limit already fails parsing →
  `422`). The window is checked **again** after the upload, then the probe is
  claimed (`probe_received = true`) with no await in between, so a probe racing the frames cannot be accepted twice.
- **`cloud: "skipped"`** (nothing started; the frames use the normal path, §3.2). The edge logs the reason (`why`):
  `no_cloud_this_attempt` (no cloud configured, the runtime's next attempt mode is not ONLINE, or
  `match.rekognition.enabled` is false; `edge/attempts.py` `cloud_wanted`), `detector_error` (face detection
  raised), `no_face` (no usable face crop in the probe frame), `frames_first` (the frames consumed the nonce while
  the probe was being analysed).
- A probe that is not a decodable JPEG or is larger than 4096 px on a side → `422 VALIDATION_ERROR`. This check runs
  only when the cloud is wanted (otherwise the response is `skipped` without decoding).
- **`cloud: "started"`**: the edge detected the face, made the ~10 KB face crop (`_face_crop_jpeg`), started
  `ctx.cloud.match(...)` as an asyncio task with its own total deadline, and started the probe's local ArcFace
  embedding. The attempt stores the start time, the deadline and the outcome (no image bytes).
- **Deadline**: `latency_budget_ms.rekognition_probe_deadline` (1500 ms; falls back to `rekognition_timeout` if the
  key is absent), measured **from probe start**. The frames request waits at most `max(0, deadline − elapsed)` for
  the task (§3.2 step 2). A probe task that misses its deadline or fails is `CloudMatch(ok=False)`.
- **Identity binding** (fail-secure, `bind_probe`): the probe's cloud result is used only if the probe's local top-1
  user equals the frames' best-frame local top-1 user **and** cosine(probe embedding, best-frame embedding) ≥
  `match.local.allow_min_cosine`. Otherwise the result is discarded as `CloudMatch(ok=False)`, so the attempt is
  OFFLINE (P7). A probe can never upgrade a decision.
- **Never a 500**: any probe failure leaves the attempt on the normal path (P1).
- **Kiosk**: fire-and-forget POST of the face-lock frame right after face lock (session prefetched). It never
  delays the flash or the capture, and errors are ignored. The mock API supports it.
- **Budget** (arithmetic, not a measurement): the cloud deadline is 1500 ms from probe start, which overlaps the
  700 ms capture window; the edge-side processing of the frames is measured only on synthetic frames
  (`eval/results/latency_edge_1280_20261114T171323Z.md`). Face lock → rendered with the probe: **measurement pending**.
- The probe image is never stored; its embedding stays in RAM until the attempt is decided and is never exported.
  `GET /v1/admin/attempt/{id}/signals` shows the probe outcome (no embeddings).

### 3.2 `POST /v1/attempt/{attempt_id}/frames` → 200 DecisionResponse

`multipart/form-data`:

| Part | Type | Notes |
|---|---|---|
| `frame_0` … `frame_4` | `image/jpeg` | ≤ `capture.max_width_px` (1280) px wide, ≤ 2 MB each, in capture order. 3–5 contiguous parts (`quality.min_usable_frames` ≤ n ≤ `quality.frames_per_attempt`). |
| `meta` | `application/json` (string field) | `FramesMeta` below |

All quality, pose and texture numbers are **recomputed on the edge** from the JPEGs. The client `quality` block
is advisory, and every client-reported field is untrusted.

```python
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _In(BaseModel):
    model_config = ConfigDict(extra="ignore")


class FlashEvent(_In):
    step_index: int
    color: str
    shown_at_ms: float                 # epoch ms when the tint was painted (requestAnimationFrame)


class ChromaSample(_In):
    t_ms: float                        # mean skin-ROI colour per video frame (~30 fps)
    r: float                           # UNTRUSTED: used only for flash timing (lag); r is edge-measured
    g: float
    b: float


class ClientQuality(_In):              # advisory; the edge recomputes quality on the frames
    face_count: int | None = None
    iod_px: float | None = None        # inter-ocular distance
    yaw_deg: float | None = None       # + = subject turned to their left
    pitch_deg: float | None = None
    roll_deg: float | None = None
    blur_var: float | None = None      # Laplacian variance (client estimate)
    luma_mean: float | None = None     # 0-255 on face ROI
    face_box: list[float] | None = None   # [x, y, w, h] normalised 0-1


class ClientSignals(_In):
    camera_label: str = ""
    virtual_camera_suspected: bool = False   # client-side denylist hit (OBS, ManyCam, DroidCam, "Virtual", ...)
    device_count: int | None = None          # enumerateDevices videoinput count
    track_settings: dict[str, Any] = Field(default_factory=dict)   # getSettings(): width, height, frameRate
    fps_measured: float | None = None        # 5-120 -> used as the frame interval for flash lag (lag_ms x fps)
    frame_interval_jitter_ms: float | None = None
    exposure_locked: bool | None = None


class FramesMeta(_In):
    nonce: str
    face_lock_at_ms: int               # t0 for the 2 s SLA (also sent in the rendered beacon, 3.8)
    capture_started_at_ms: int
    frame_timestamps_ms: list[int]     # exactly one per frame part
    flash_events: list[FlashEvent] = Field(default_factory=list)
    chroma_series: list[ChromaSample] = Field(default_factory=list)
    quality: ClientQuality = Field(default_factory=ClientQuality)
    client_signals: ClientSignals = Field(default_factory=ClientSignals)
    blendshapes: dict[str, float] = Field(default_factory=dict)   # neutral baseline for the challenge
    landmarks_hash: str | None = None
```

```json
{"nonce": "n_b64url_4c1eT9xQ", "face_lock_at_ms": 1794630911820, "capture_started_at_ms": 1794630911905,
 "frame_timestamps_ms": [1794630911990, 1794630912130, 1794630912270, 1794630912410, 1794630912550],
 "flash_events": [{"step_index": 0, "color": "#FF2D2D", "shown_at_ms": 1794630911906},
                  {"step_index": 1, "color": "#2D6BFF", "shown_at_ms": 1794630912139},
                  {"step_index": 2, "color": "#2DFF7A", "shown_at_ms": 1794630912372}],
 "chroma_series": [{"t_ms": 1794630911940, "r": 142.1, "g": 101.3, "b": 92.0},
                   {"t_ms": 1794630912173, "r": 118.4, "g": 104.0, "b": 121.7}],
 "quality": {"face_count": 1, "iod_px": 92.4, "yaw_deg": 4.1, "pitch_deg": -2.3, "roll_deg": 1.0,
             "blur_var": 212.5, "luma_mean": 128.0, "face_box": [0.31, 0.22, 0.38, 0.51]},
 "client_signals": {"camera_label": "FaceTime HD Camera", "virtual_camera_suspected": false,
                    "device_count": 1, "track_settings": {"width": 1280, "height": 720, "frameRate": 30},
                    "fps_measured": 29.8, "frame_interval_jitter_ms": 2.1, "exposure_locked": false},
 "blendshapes": {"mouthSmileLeft": 0.04, "mouthSmileRight": 0.05, "jawOpen": 0.02, "cheekPuff": 0.01,
                 "eyeBlinkLeft": 0.06, "eyeBlinkRight": 0.05}}
```

Processing (DECISION_POLICY §2):

1. **Pre-checks, in order**: rate limit → quality gate → injection. Each one short-circuits.
   - **t0**: the client `face_lock_at_ms` is untrusted. Its lag is clamped to
     [0, `latency_budget_ms.t0_max_lag` (10 s)] and re-based onto the edge wall clock (the demo clock when one
     is active), so a client cannot pick its own schedule time.
   - **Injection**: the camera label is checked against `injection.virtual_camera_label_patterns`. A change of
     camera label since `session/start` counts as `virtual_camera_suspected`. Frame timestamps must be monotonic
     with intervals in [`min_frame_interval_ms`, `max_frame_interval_ms`].
2. **Liveness and identity run in parallel.** The cloud match (§4.1, only when `CLOUD_API_URL` is configured,
   `match.rekognition.enabled` is true and the attempt is ONLINE) uploads a ~10 KB face crop of the sharpest frame
   and is bounded by `latency_budget_ms.rekognition_timeout` (700 ms, a hard total deadline). Measured from the
   venue, the round trip is about 0.4–1.4 s, so most attempts miss it today (§2 matcher authority, current state).
   With an early probe (§3.1a) the edge instead awaits the probe task for
   `rekognition_probe_deadline` (1500 ms) − elapsed since probe start, and applies the identity binding rule.
   With `match.rekognition.enabled: true`, any cloud failure, timeout, non-200 or denied service makes **this
   attempt OFFLINE (P7)**: the same raw scores are re-thresholded with the offline values (no re-inference).
   See the matcher-authority table in §2 for `enabled: false`.
   - **Flash**: `r` is the edge-measured correlation on the uploaded frames only (`r_frames`; the client chroma
     series is ignored for `r`). The frame lag from the flash fit is converted with `lag_ms × fps` when the client
     sends `fps_measured`.
3. **Depth**: depth checks count only if DepthProbe frames for this attempt arrive within
   `latency_budget_ms.depth_max_wait` (150 ms) after the RGB frames. Otherwise depth is NOT_AVAILABLE and has no effect.
4. **Schedule (SC1, D2)**: the edge runs `edge.policy.schedule.evaluate_schedule` locally on the newest
   cloud-signed bundle. The bundle is refreshed every `cache.bundle_refresh_interval_min` (15 min), and the
   revocation feed is applied at each heartbeat. There is **no per-attempt cloud schedule call**. If the edge is
   online but the bundle was not confirmed by the cloud within `schedule.online_max_bundle_age_min` (30 min),
   the attempt is decided **OFFLINE** (P7) under the offline cache rules.
5. **Random challenge (D6, R4)**: a BIO_PASS that would be ALLOW becomes STEP_UP / CHALLENGE `[RANDOM_CHALLENGE]`
   with probability `challenge.random_rate`: **0.15 online, 0.30 offline**. The demo can force or disable it via
   `POST /v1/admin/random-challenge` (§3.14a). One draw per would-be ALLOW; the RNG is injected, so tests are
   deterministic.
6. The SC2.5 minimal record is written before the response is returned, and a `decision` event is published (§3.7).
   A STEP_UP is kept as a pending record (one chained record per attempt). If the record cannot be written, the
   answer is DENY `SYSTEM_ERROR` (P9).
7. When the decision is STEP_UP / CHALLENGE and depth is enabled, a CHALLENGE-phase depth capture is queued (§3.17).

There is no eval header: eval tags come from `/v1/admin/eval/context` (§3.13).

Errors:

- `410 NONCE_EXPIRED`: more than 10 s after session start. The nonce is burnt.
- `409 NONCE_REUSED`: second submission for the same attempt.
- `403 FORBIDDEN`: the nonce does not belong to this attempt (internal `NONCE_INVALID`).
- `409 ATTEMPT_CLOSED`: terminal, or superseded by a recapture.
- `404 ATTEMPT_NOT_FOUND`: unknown, or purged (in-RAM attempt metadata is kept for 600 s).
- `422 VALIDATION_ERROR`: fewer than 3 frames, timestamp count ≠ part count, non-contiguous parts, undecodable
  JPEG, or a meta parse error.
- `413 PAYLOAD_TOO_LARGE`: a frame part > 2 MB.
- The multipart body, `meta` and the frame count are validated before the nonce is consumed, so those errors do
  not burn the nonce. JPEG decoding happens after consumption, so an undecodable JPEG does burn it.

### 3.3 `POST /v1/attempt/{attempt_id}/challenge` → 200 DecisionResponse

Valid only while the pending step is CHALLENGE (`next_action.type == "CHALLENGE"`); otherwise
`409 INVALID_STATE`. `multipart/form-data`:

| Part | Type | Notes |
|---|---|---|
| `meta` | `application/json` (string field) | `ChallengeMeta` below |
| `frame_0` (… `frame_2`) | `image/jpeg` | Challenge frame(s); the **last** part is used for the identity check (local cosine to the candidate ≥ `challenge.min_identity_cosine` 0.30). Required: without it the identity check is a missing signal and the challenge cannot pass (P1). |

The edge also accepts a plain `application/json` body (the `ChallengeMeta` alone). That form has no frame, so it
can never pass the identity check. Action names are also accepted in lower-case aliases (`jaw_open`,
`cheek_puff`, `turn_left`, …).

The field names are those of `edge/policy/signals.py` `ActionEvidence` / `ChallengeEvidence`. The edge adds
`last_frame_cosine` (from the last `frame_N` part) and `depth` (from the CHALLENGE-phase DepthProbe capture) to build `ChallengeEvidence`.

```python
from typing import Literal

from pydantic import BaseModel, ConfigDict

ActionName = Literal["SMILE", "OPEN_MOUTH", "PUFF_CHEEKS", "BLINK", "TURN_LEFT", "TURN_RIGHT"]


class ActionEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: ActionName                  # in the order issued in next_action.challenge.actions
    prompted_at_ms: int                 # epoch ms the prompt was shown
    started_at_ms: int | None = None    # first qualifying movement; null = no response
    completed_at_ms: int | None = None  # threshold reached (blink: re-opened); null = not completed
    baseline: float                     # blendshape: neutral score; turn: signed yaw at the prompt (deg, + = subject's left)
    peak: float                         # blendshape: max score in window; turn: = yaw_peak_deg (not used by the policy)
    landmark_shift: float | None = None # deformation only: cheek/nasolabial shift, 0-1 normalised (units of IOD)
    yaw_peak_deg: float | None = None   # turns only: signed yaw at largest excursion, + = subject's left;
                                        # the policy judges the delta yaw_peak_deg - baseline
    tracking_lost: bool = False


class ChallengeMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_id: str
    nonce: str                          # the challenge nonce from next_action.challenge (single-use)
    actions: list[ActionEvidence]
    same_track: bool                    # one continuous MediaPipe face track for the whole challenge
```

```json
{"challenge_id": "chl_3f9a1c2b7d4e", "nonce": "Hk3q9ZpL0wRtVb7Xc2Nd4A", "same_track": true,
 "actions": [{"action": "TURN_LEFT", "prompted_at_ms": 1794630914000, "started_at_ms": 1794630914260,
              "completed_at_ms": 1794630914410, "baseline": 3.0, "peak": 22.5, "landmark_shift": null,
              "yaw_peak_deg": 22.5, "tracking_lost": false},
             {"action": "OPEN_MOUTH", "prompted_at_ms": 1794630915100, "started_at_ms": 1794630915320,
              "completed_at_ms": 1794630915560, "baseline": 0.02, "peak": 0.61, "landmark_shift": 0.18,
              "yaw_peak_deg": null, "tracking_lost": false}]}
```

Outcome via `resolve_stepup` (DECISION_POLICY §7.1, §9.6):

| Outcome | Condition | Result |
|---|---|---|
| Pass | All actions passed | Next pending step: STEP_UP / SECOND_FACTOR (R3); or ALLOW `[ACCESS_OK]`, `resolved_codes` = trigger codes (R2). The schedule is never re-run. |
| Hard fail | Response < `min_reaction_ms`, wrong action or turn direction, `tracking_lost`, `same_track: false`, identity cosine < 0.30, `nonce` not the issued challenge nonce (replay) | DENY `CHALLENGE_FAILED` (R4) |
| M1 contradiction | Blendshape moved but depth rigid | DENY `MASK_CUE_RIGID` (R5) |
| First soft fail | No qualifying response in `step_window_ms` | STEP_UP with trigger codes + `CHALLENGE_FAILED`, a **new** `challenge` (new id + nonce), `attempts_left: 0` (R6) |
| Second soft fail | Soft fail again | DENY `CHALLENGE_FAILED` (R7) |
| Session expired | Step-up session > 120 s | DENY `CHALLENGE_FAILED` (R10) |

When the challenge is issued, the edge queues a CHALLENGE-phase depth capture for DepthProbe, so M1 can be
measured during the deformation. That depth counts only if it arrives within `depth_max_wait` after this
submission; otherwise M1 is NOT_AVAILABLE.

Errors:

- `409 INVALID_STATE`: no CHALLENGE pending.
- `409 NONCE_REUSED`: this challenge nonce was already submitted **and a decision was produced for it**. The
  edge claims the nonce before any await (a concurrent replay gets 409) and releases it again on **any** failure
  before a DecisionResponse exists (protocol error, undecodable frame, analyse / embed exception), so the
  kiosk's retry with the same nonce is processed, not refused (R-G, v1.4; `edge/app.py` releases the nonce unless
  it is in `decided_challenge_nonces`, which `edge/attempts.py` sets once a decision exists).
- `409 ATTEMPT_CLOSED`.
- `404 ATTEMPT_NOT_FOUND`.
- `422 VALIDATION_ERROR`: `challenge_id` mismatch or malformed meta.
- A wrong nonce is not a protocol error: it is a hard fail (DENY `CHALLENGE_FAILED`, HTTP 200). An expired
  step-up session is DENY `CHALLENGE_FAILED` (R10), not `410`.

### 3.4 `POST /v1/attempt/{attempt_id}/fallback` → 200 DecisionResponse

Valid only while the pending step is SECOND_FACTOR; otherwise `409 INVALID_STATE`.

```python
from typing import Literal

from pydantic import BaseModel, ConfigDict


class FallbackRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    method: Literal["TOTP", "CARD", "EMAIL_OTP", "STAFF_OVERRIDE"]   # aliases accepted: totp, card, email_otp, otp, staff, staff_code
    code: str | None = None       # TOTP 6 digits | EMAIL_OTP 6 digits | STAFF_OVERRIDE 8 digits
    card_id: str | None = None    # CARD: simulated HID card / mobile credential ID (hashed on arrival, never stored)
    staff_id: str | None = None   # STAFF_OVERRIDE: s_xxx, recorded with the decision
    otp_id: str | None = None     # EMAIL_OTP: from POST /v1/attempt/{id}/otp/send
```

| Method | Required fields | Online | Offline | Verification (DECISION_POLICY §7.2) |
|---|---|---|---|---|
| `TOTP` | `code` | yes | yes | RFC 6238, SHA1, 6 digits, 30 s, ±1 step (`fallback.totp`). Verified against **real wall time**, never the demo clock, because authenticator apps use real time (R18). Per-user secret provisioned at enrolment and stored encrypted on the edge (never in the bundle). Replay-protected (last accepted step per user, device-wide). The accepted step is recorded as `fallback.totp_step` so the cloud can detect cross-kiosk replay. Must verify for the **candidate**. |
| `CARD` | `card_id` | yes | yes (not high-risk) | HMAC-SHA256(`CARD_ID_PEPPER`, card_id).hex() == `users[candidate].fallback.card_id_hash`, **and** the hash is not revoked: a bundle `revocations[]` item with `type: CARD` and `target_id` = the hash, or a CARD item of the revocation feed (§4.3), makes the card fail (deny-only, immediate). |
| `EMAIL_OTP` | `otp_id`, `code` | yes | **no** | Edge → Cloud `POST /v1/otp/verify` (§4.6) |
| `STAFF_OVERRIDE` | `staff_id`, `code` | yes (not high-risk) | yes | `staff_id` is required: a submission without it counts as a wrong code (`FALLBACK_FAILED`, counted towards the 3-failure lock). One-time 8-digit code: PBKDF2-HMAC-SHA256(code, per-code salt, 100 000 iterations) == an unused, unexpired `override_codes.codes[].hash` with matching `staff_id`. Codes always come from the **last valid bundle**. Each code is valid until `valid_until` = bundle `expires_at` + 24 h (`fallback.staff_override.valid_after_expiry_h`, R7), so it still works on an EXPIRED cache. Consumed locally, recorded with `staff_id` and `code_id`. 3 wrong codes lock the method for 300 s. Verifies the staff member, not the person (manual review). |

Rules:

- The method must be in `next_action.methods`. A method outside the set counts as a failed submission (R8/R9),
  not a protocol error. Example: CARD in the offline SERVER_ROOM returns STEP_UP `FALLBACK_FAILED`.
- `stepup.max_attempts_per_step` = 2: the first failure gives STEP_UP + `FALLBACK_FAILED` with
  `attempts_left: 0` (R8); the second gives DENY `FALLBACK_FAILED` (R9).
- Success with all steps done gives ALLOW `[ACCESS_OK, FALLBACK_OK]` (+ `OFFLINE_MODE`), with `resolved_codes`
  = trigger codes (R1).
- DENY is terminal: `409 ATTEMPT_CLOSED`. A schedule DENY can never be fixed by a fallback (P8): there is no
  pending step to submit to.
- **EMAIL_OTP cloud error** (DECISION_POLICY §7.2 row R11; `edge/cloud_client.py` `otp_verify` returns `None`): a
  transport error or timeout (3 s), HTTP `401` (kiosk signature/key rejected), `429`, any `5xx`, or an unreadable
  200 body means the cloud did not judge the code. This is the cloud being unavailable, not
  attack evidence and not a counted failure. The edge re-issues the same STEP_UP with `EMAIL_OTP` removed from
  `methods`, `attempts_left` unchanged, and no new `FALLBACK_FAILED` (a retry code already on the last response
  is kept) (HTTP 200).
  - Implementation: `edge/attempts.py` `drop_method` → `PolicyRuntime.drop_method` → `edge/policy/stepup.py`
    `drop_method`. The display message is the normal SECOND_FACTOR message. The failed call also counts as a
    heartbeat miss (`record_cloud_result`; if it tips the kiosk OFFLINE, the mode reason is `match_timeout`).
  - If `EMAIL_OTP` was the **only** method left, it cannot be dropped: the step-up stays open unchanged and the
    edge returns `503 CLOUD_UNAVAILABLE` (retry later or call staff).
  - Online, `EMAIL_OTP` without both `otp_id` and `code` returns `422 VALIDATION_ERROR`
    ("EMAIL_OTP needs otp_id and code").
  - Afterwards, `otp/send` for that attempt returns `409 INVALID_STATE`.
  - A wrong EMAIL_OTP code is a failed submission (R8/R9): `verified: false` in a 200 body, **or any other 4xx**
    (unknown / expired / used `otp_id`), is counted as `verified: false`.
  - EMAIL_OTP offline is outside `next_action.methods`, so it is also R8/R9.
  - With `fallback.email_otp.enabled: false`, EMAIL_OTP is never offered.

Request (offline, Rahul at the server room, continuing §1.3):

```json
{"method": "TOTP", "code": "482913"}
```

Response 200:

```json
{
  "attempt_id": "att_01JDA3R5T7V9X1Z3B5D7F9H1K3",
  "kiosk_id": "KIOSK_SRV_01",
  "zone": "SERVER_ROOM",
  "decision": "ALLOW",
  "reason_codes": ["OFFLINE_MODE", "FALLBACK_OK", "ACCESS_OK"],
  "resolved_codes": ["OFFLINE_HIGH_RISK_ZONE"],
  "next_action": {"type": "OPEN_DOOR", "steps": [], "methods": null, "challenge": null,
                  "attempts_left": null, "retry_after_s": null, "hint": null},
  "bio_result": "BIO_PASS",
  "schedule_result": "IN_WINDOW",
  "mode": "OFFLINE",
  "cache_state": "FRESH",
  "candidate": {"user_id": "u_7a8b", "display": "Rahul V.", "role": "staff"},
  "scores": {"pad_mean": 0.91, "pad_pass_frames": 5, "flash_r": 0.80, "flash_amp": 8.2,
             "moire": 0.10, "device_conf": 0.0, "depth": null, "mask": {},
             "match_local": 0.69, "match_margin": 0.33, "rekognition": null, "rekognition_runner_up": null},
  "latency_ms": {"total": 9, "liveness": 0, "match": 0, "schedule": 0, "policy": 3},
  "policy_version": "2026-11-14.3",
  "bundle_version": 42,
  "display_message": "Access granted (offline mode)",
  "stage": "fallback"
}
```

Staff override example request (the `OVR-001` **test-fixture** code from SURPRISE_CHALLENGES §SC2.4; real demo codes
exist only in `edge/data/DEMO_CODES.txt`, and the live bundle v45 still carries the fixture codes until v46, see the
v1.3 notes):

```json
{"method": "STAFF_OVERRIDE", "staff_id": "s_guard01", "code": "48213907"}
```

### 3.5 `POST /v1/attempt/{attempt_id}/otp/send` → 201 (no request body)

Online only. The edge proxies Cloud `POST /v1/otp/send` (§4.5) for the attempt's candidate. It requires a
pending SECOND_FACTOR whose `methods` contain `EMAIL_OTP`; otherwise `409 INVALID_STATE`.

```json
{"otp_id": "otp_8HK2", "channel": "email", "destination_masked": "p*****@pes.edu",
 "expires_at": "2026-11-14T04:40:12Z", "resend_after_s": 30, "code_length": 6}
```

Offline, or when SES is unavailable or denied in the sandbox, the edge returns `503 CLOUD_UNAVAILABLE` and the
kiosk offers the other methods.

### 3.6 `GET /v1/attempt/{attempt_id}` → 200 DecisionResponse

Returns the latest DecisionResponse of the attempt, for kiosk reload and debugging. Errors:

- `404 ATTEMPT_NOT_FOUND`: unknown or purged attempt.
- `409 INVALID_STATE`: frames not yet submitted.

### 3.7 `GET /v1/events` → `text/event-stream`

Server-Sent Events, used by the admin dashboard and `eval/capture.py`. Localhost-only (127.0.0.1 bind), no
admin token (C9). Two event types:

- **`decision`**: emitted for every DecisionResponse returned by `frames`, `challenge` or `fallback`. Its data is
  the DecisionResponse JSON plus an `eval` key (the attempt's eval tags from §3.13, or `null`).
- **`rendered`**: emitted for the first rendered beacon of an attempt (§3.8). Data:
  `{attempt_id, client_latency_ms, face_lock_at_ms, rendered_at_ms, decision, eval}`.

A `: ping` comment line is sent every 15 s.

```text
event: decision
data: {"attempt_id": "att_01JDA3K7Q9V2M4N6P8R0S2T4V6", "decision": "ALLOW", "...": "rest of DecisionResponse", "eval": {"run_id": "run_0930", "subject_id": "S03", "label": "bona_fide", "condition": "normal", "split": "test"}}

event: rendered
data: {"attempt_id": "att_01JDA3K7Q9V2M4N6P8R0S2T4V6", "client_latency_ms": 1554, "face_lock_at_ms": 1794630911820, "rendered_at_ms": 1794630913374, "decision": "ALLOW", "eval": null}
```

```python
from typing import Literal

from pydantic import BaseModel


class EvalTag(BaseModel):              # "eval" key of a decision event (null when no context is set)
    run_id: str
    subject_id: str
    label: Literal["bona_fide", "print", "screen_photo", "video", "mask_paper", "mask_3d", "injection"]
    condition: Literal["normal", "dim", "backlit", "far"]
    split: Literal["dev", "test"]


class RenderedEvent(BaseModel):
    attempt_id: str
    client_latency_ms: int             # rendered_at_ms - face_lock_at_ms
    face_lock_at_ms: int
    rendered_at_ms: int
    decision: Literal["ALLOW", "STEP_UP", "DENY"] | None   # decision of the frames response that was rendered
    eval: EvalTag | None = None
```

### 3.8 `POST /v1/attempt/{attempt_id}/rendered` → 204

The kiosk sends this beacon after the first decision screen of the attempt (the `frames` response) has been
painted, at the `requestAnimationFrame` after render. Both values use the same kiosk clock (epoch ms).

```json
{"face_lock_at_ms": 1794630911820, "rendered_at_ms": 1794630913374}
```

The edge computes `client_latency_ms = rendered_at_ms − face_lock_at_ms`, emits a `rendered` event and adds the
value to `/v1/metrics` `latency_ms.client`. This is the **user-visible decision time used for the 2 s claim**.
No stored measurement of it exists yet (§3.16); once one is stored under `eval/results/`, slides show it next to the
server `latency_ms.total`.

- `face_lock_at_ms` must equal the value sent in FramesMeta.
- The first beacon per attempt wins; repeats return 204 and are ignored.
- Step-up screens are "verification time", not on the 2 s path.

Errors:

- `404 ATTEMPT_NOT_FOUND`.
- `409 INVALID_STATE`: no decision returned yet.
- `422 VALIDATION_ERROR`: a `face_lock_at_ms` mismatch, or `rendered_at_ms − face_lock_at_ms` outside 0–60 000 ms.

### 3.9 `GET /v1/health`

```json
{"status": "ok", "degraded_reasons": [], "version": "0.1.0",
 "models_loaded": {"minifasnet_v2": true, "minifasnet_v1se": true, "face_detector": true,
                   "device_detector": true, "arcface": true},
 "self_test": {"minifasnet_real_index": 1, "input_scale": "0-255 BGR", "passed": true},
 "depth_probe": "connected", "uptime_s": 3121,
 "detail": {"kiosk_id": "KIOSK_MAIN_01", "policy_runtime": "real", "policy_version": "2026-11-14.3",
            "cloud_configured": true, "arcface_provider": "CoreMLExecutionProvider", "model_errors": {},
            "self_test": {"ok": true, "real_class_index": 1, "input_scale": 1.0},
            "template_cache": {"count": 4, "model": "arcface_r50", "age_h": 1.4, "skipped_model_mismatch": 0},
            "depth_enabled": false, "lan_listener": "listening 0.0.0.0:8001", "demo_mode": true}}
```

- `status` is `degraded` exactly when `degraded_reasons` is non-empty (`edge/app.py` `health_problems`). The
  reasons are: `policy_runtime_fail_secure`; `model_missing:<name>` for `face_detector`, `minifasnet_v2`,
  `minifasnet_v1se`, `coco_detector` (reported as `device_detector` in `models_loaded`) or `arcface`;
  `pad_self_test_failed` or `pad_self_test_not_run`; `template_cache_unavailable`. `detail.policy_runtime` is `real`, or `fail_secure` when the policy runtime could not start
  (every attempt is then DENY `SYSTEM_ERROR`). The `detail` block is diagnostic and its inner keys may grow.
- `self_test` checks the MiniFASNet "real" output index and the input scale on a real face image at startup
  (CLAUDE.md §6). Enrolment is refused unless `self_test.passed` is true.
- `depth_probe` (`edge/depth_bridge.py` `status()`) is `rejected_token` if the latest depth call within the last
  30 s was refused for a wrong `X-Depth-Token` (the token itself is never reported), else `connected` if DepthProbe
  long-polled with a valid token within the last 30 s, else `unavailable` (the live edge
  reported `unavailable` at the time of writing: the app is not polling). The DepthProbe app (v0.3.0 sideloaded;
  a v0.3.1 IPA is built) connects over the LAN listener when running, but `liveness.depth.enabled` stays
  **false** because the H4 go/no-go (10 live vs 10 printed photo) has **not been run** (`depth/calibration/` is
  empty). Until then, depth has no decision effect.
- Measured at startup on the dev laptop (self-test, not an eval result): MiniFASNet output index 1 = real, input
  raw 0–255 BGR.

### 3.10 `GET /v1/mode` and `POST /v1/admin/mode`

The canonical connectivity state. The kiosk badge polls it every **2 s**. Owner: policy-engine
(`edge/offline/connectivity.py`).

```python
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class BundleStatus(BaseModel):
    version: int | None
    issued_at: datetime | None
    expires_at: datetime | None
    signature_valid: bool | None        # true iff a last valid bundle (LVB) is installed
    cache_state: Literal["FRESH", "EXPIRED", "INVALID"] | None   # INVALID when there is no LVB
    refresh_age_s: int | None = None    # seconds since the cloud last confirmed the bundle (200 or 304)
    rejected: list[dict[str, Any]] = []  # last 5 BUNDLE_REJECTED alerts (bad signature, older version, ...)


class TemplateCacheStatus(BaseModel):
    count: int
    model: str                          # e.g. "arcface_r50" (buffalo_l)
    age_h: float | None                 # > cache.template_cache_max_age_hours (72) -> unusable


class DemoClock(BaseModel):
    # v1.4: present whenever DEMO_MODE=1 (also with no offset: active=false), so the Control Panel can read
    # earliest_local BEFORE setting a time. The kiosk shows the "DEMO CLOCK hh:mm" badge only when active=true.
    active: bool                        # offset_s != 0
    now_local: str                      # "HH:MM" Asia/Kolkata (edge clock = real clock when active=false)
    now_utc: str
    offset_s: int
    date_local: str                     # "YYYY-MM-DD" Asia/Kolkata of now_local
    bundle_issued_at: str | None        # issued_at of the installed LVB (null = no LVB)
    earliest_utc: str | None            # issued_at - cache.clock_rollback_tolerance_s (300 s)
    earliest_local: str | None          # first whole minute ("HH:MM", Asia/Kolkata) >= earliest_utc
    earliest_date_local: str | None     # local date of earliest_local
    bundle_rollback: bool               # now < earliest_utc: the bundle is INVALID (STEP_UP SCHEDULE_BUNDLE_INVALID)
    cache_state: Literal["FRESH", "EXPIRED", "INVALID"]   # bundle cache state at the edge clock


ModeReason = Literal[
    "heartbeat_timeout",            # >= misses_to_offline consecutive heartbeat misses (or a miss while SYNCING)
    "match_timeout",                # the miss that tipped it over was a failed cloud call made for an attempt (match or OTP verify)
    "forced",                       # POST /v1/admin/mode {"force": "OFFLINE"} or FORCE_OFFLINE=1
    "not_configured",               # CLOUD_API_URL empty: offline rules permanently
    "bundle_stale",                 # connectivity ONLINE but the bundle is not usable online (MO2 and MO3)
    "policy_runtime_unavailable",   # fail-secure runtime: every attempt is DENY SYSTEM_ERROR
]


class ModeResponse(BaseModel):
    model_config = ConfigDict(extra="allow")          # diagnostic keys below
    mode: Literal["ONLINE", "OFFLINE"]                # the mode the NEXT attempt would use
    state: Literal["ONLINE", "OFFLINE", "SYNCING"]   # SYNCING: offline rules still apply (R13)
    since: datetime
    forced: bool                                      # admin force active
    last_cloud_ok_at: datetime | None
    reason: ModeReason | None                         # null = ONLINE, SYNCING, or OFFLINE awaiting heartbeats
    schedule_bundle: BundleStatus
    revocation_seq: int
    template_cache: TemplateCacheStatus | None
    sync_queue_depth: int
    demo_clock: DemoClock | None                      # null unless DEMO_MODE=1 (v1.4: present, active=false, with no offset)
    # additive diagnostics (dashboard): kiosk_id, zone, policy_version,
    # rate_limit {enabled, locked, retry_after_s}, last_sync {at, report}, server_flags[],
    # random_challenge ("AUTO" | "FORCE" | "FORCE_NEXT" | "OFF"; in memory, AUTO after an edge restart),
    # policy_bars {pad_pass, flash_pass_r, match_allow, match_margin, random_rate, ambient_exception,
    #   moire_unsure, device_unsure, flash_enforce, moire_enforce, m2_rgb_enforce, rekognition,
    #   rekognition_timeout_ms, rekognition_probe_deadline_ms},
    # cloud_match {enabled, recent, misses, last_miss_at, last_ok_at, degraded}
```

```json
{"mode": "OFFLINE", "state": "OFFLINE", "since": "2026-11-14T04:38:11Z", "forced": true,
 "last_cloud_ok_at": "2026-11-14T04:38:05Z", "reason": "forced",
 "schedule_bundle": {"version": 42, "issued_at": "2026-11-14T02:00:00Z", "expires_at": "2026-11-14T14:00:00Z",
                     "signature_valid": true, "cache_state": "FRESH", "refresh_age_s": 380, "rejected": []},
 "revocation_seq": 7, "template_cache": {"count": 6, "model": "arcface_r50", "age_h": 1.4},
 "sync_queue_depth": 3, "demo_clock": null,
 "kiosk_id": "KIOSK_LIB_01", "zone": "LIBRARY", "policy_version": "2026-11-14.3",
 "rate_limit": {"enabled": true, "locked": false, "retry_after_s": null},
 "random_challenge": "AUTO",
 "policy_bars": {"pad_pass": 0.85, "flash_pass_r": 0.75, "match_allow": 0.55, "match_margin": 0.15,
                 "random_rate": 0.3, "ambient_exception": false, "moire_unsure": 0.4, "device_unsure": 0.25,
                 "flash_enforce": false, "moire_enforce": true, "m2_rgb_enforce": true, "rekognition": false,
                 "rekognition_timeout_ms": 700, "rekognition_probe_deadline_ms": 1500},
 "cloud_match": {"enabled": true, "recent": 11, "misses": 6, "last_miss_at": "2026-11-14T04:37:58Z",
                 "last_ok_at": "2026-11-14T04:36:20Z", "degraded": true}}
```

- **`policy_bars`**: the bars the engine applies in the **effective** mode. `rekognition` is true only when the
  effective mode is ONLINE and `match.rekognition.enabled` is true; otherwise `match_allow` / `match_margin` are the
  local matcher's offline bars. `*_enforce` mirror the YAML switches (a missing key means enforce).
  `rekognition_timeout_ms` = `latency_budget_ms.rekognition_timeout` (no-probe cloud budget) and
  `rekognition_probe_deadline_ms` = `latency_budget_ms.rekognition_probe_deadline` (early-probe budget from probe
  start, §3.1a), both read from the effective-mode thresholds (`edge/policy/runtime.py` `_policy_bars`).
- **`cloud_match`** (P7 visibility): the last 20 online attempts' Rekognition outcomes. `degraded` is true when the
  latest online attempt fell back to an offline decision (cloud miss), while heartbeats can keep the kiosk ONLINE.
  The kiosk can use it to explain an `OFFLINE_MODE` decision under an ONLINE badge.
- **`random_challenge`** is held in memory; an edge restart resets it to `AUTO` (§3.14a).

- **`POST /v1/admin/mode`** (`X-Admin-Token`), body `{"force": "OFFLINE"}` or `{"force": "AUTO"}`. Returns the
  same body as `GET /v1/mode`.
  - **The forced switch is immediate**: it applies to the next attempt.
  - Heartbeats keep running underneath a forced OFFLINE. `AUTO` goes straight to SYNCING if the last
    `connectivity.successes_to_online` (3) heartbeats succeeded; otherwise it stays OFFLINE until they do.
  - The way back to ONLINE always passes through SYNCING (`require_sync_before_online: true`): the sync queue is
    acknowledged and the bundle refreshed, then ONLINE. Any miss while SYNCING goes back to OFFLINE.
- **Heartbeat**: `GET {CLOUD_API_URL}/v1/health` (`connectivity.health_path`), every
  `connectivity.heartbeat_interval_s` (5 s), timeout `connectivity.heartbeat_timeout_ms` (**2000 ms**). On
  success (not forced), the revocation feed is pulled too.
- **Natural detection time**: `misses_to_offline` (3) consecutive misses at a 5 s interval. With a hanging
  cloud, the worst case is about 5 + 5 + 5 s + one 2 s probe timeout = **≤ ~17 s**. It is faster when the
  connection is refused. A failed cloud call inside an attempt also counts as a miss, and independently makes
  **that attempt** OFFLINE at once (P7).
- **Startup**: the state starts OFFLINE with `reason: null` and needs 3 successful heartbeats (≥ ~10 s) plus a
  sync before it reaches ONLINE.
- **Kiosk badge**: polls `GET /v1/mode` every `connectivity.status_poll_ms` (2000 ms).
- `GET /v1/mode` reports the mode the **next attempt** would use (DECISION_POLICY §8.1). Connectivity ONLINE
  with an online-unusable bundle reports `mode: OFFLINE`, `state: OFFLINE`, `reason: bundle_stale` (R5):
  - MO2: the bundle refresh age exceeds `schedule.online_max_bundle_age_min` (30 min).
  - MO3: there is no verified bundle, or the cache is EXPIRED / INVALID.

  The code emits `bundle_stale` for both.

### 3.11 `GET /v1/admin/store` and `POST /v1/admin/sync`

`GET /v1/admin/store` (`X-Admin-Token`) is the SC2d demo view of what is stored locally. `records` holds the
decrypted minimal records, **exactly** the `docs/SURPRISE_CHALLENGES.md` §SC2.5 field list
(`edge/offline/store.py` `RECORD_FIELDS`).

- **`scores`** is a 2-dp projection of float scalars only, with no per-frame data. Keys: `pad`, `flash`,
  `flash_amp`, `moire`, `device`, `match`, `margin`, `rek`, `rek_runner_up`, present when computed.
- **`fallback`** is `{method, staff_id, code_id, totp_step}` or `null`. It never contains a code or TOTP value.
  `totp_step` is the non-secret RFC 6238 time-step counter accepted for a TOTP fallback.
- **`zone`** is `"UNKNOWN"` when there was no last valid bundle.
- Hashes are truncated here for readability.

```json
{"records": [{"attempt_id": "att_01JDA3R5T7V9X1Z3B5D7F9H1K3", "seq": 1042, "kiosk_id": "KIOSK_SRV_01",
              "zone": "SERVER_ROOM", "ts_utc": "2026-11-14T04:40:00Z", "user_id": "u_7a8b",
              "candidate_user_id": null, "decision": "ALLOW",
              "reason_codes": ["OFFLINE_MODE", "FALLBACK_OK", "ACCESS_OK"],
              "resolved_codes": ["OFFLINE_HIGH_RISK_ZONE"],
              "scores": {"pad": 0.91, "flash": 0.80, "flash_amp": 8.2, "moire": 0.10, "device": 0.0,
                         "match": 0.69, "margin": 0.33},
              "fallback": {"method": "TOTP", "staff_id": null, "code_id": null, "totp_step": 59821030},
              "schedule_version": 42, "cache_state": "FRESH", "mode": "OFFLINE",
              "prev_hash": "5f0c9a1e…", "record_hash": "a83d27c4…"}],
 "queue_depth": 3,
 "tombstones": [],
 "chain_head": "a83d27c4…",
 "db_bytes": 24576,
 "never_stored": ["images", "face_crops", "depth_maps", "embeddings", "display_names",
                  "totp_values", "raw_card_ids"],
 "pending": [],
 "chain_ok": true,
 "chain_bad_seq": null,
 "fields": ["attempt_id", "seq", "kiosk_id", "zone", "ts_utc", "user_id", "candidate_user_id", "decision",
            "reason_codes", "resolved_codes", "scores", "fallback", "schedule_version", "cache_state", "mode",
            "prev_hash", "record_hash"],
 "encryption": "AES-256-GCM (HKDF from EDGE_DATA_KEY), per-row AAD kiosk|seq|attempt",
 "retention_hours": 24.0}
```

- **Storage**: SQLite with AES-256-GCM row payloads (key derived via HKDF from `EDGE_DATA_KEY`, per-row AAD)
  and a hash chain (SC2.5). `chain_ok` / `chain_bad_seq` show the local chain verification.
- **Pending records**: an open STEP_UP is kept as one `pending` record per attempt. It is chained when the
  attempt reaches ALLOW/DENY, or when it is abandoned (session TTL + 60 s).
- **Retention**: records are purged on server ack (`accepted` or `duplicates`). Unsynced records are purged at
  `offline_store.max_retention_hours` (24 h), leaving a tombstone `{count, first_seq, last_seq, chain_head}`.
- **Templates**: the face template cache is a separate Fernet-encrypted file (`templates.fernet`).

`POST /v1/admin/sync` (`X-Admin-Token`) runs one sync cycle immediately (SC2.6): revocations first, then queue
replay in batches to Cloud `/v1/sync` (§4.4), then a bundle refresh. It returns counts summed over all batches
sent, the flags list, and the full sync `report` (diagnostic):

```json
{"accepted": 3, "duplicates": 0, "rejected": 0,
 "flags": [{"attempt_id": "att_01JDA3W1B3D5F7H9K1M3P5R7T9", "type": "POST_HOC_REVOKED"}],
 "queue_depth": 0,
 "report": {"accepted": 3, "duplicates": 0, "rejected": 0, "flags": [], "queue_depth": 0, "ok": true,
            "error": null, "bundle": "not_modified", "sent": 3, "revoked_users": [], "rejected_items": []}}
```

`report.bundle` is `installed`, `not_modified`, `unavailable` or `rejected: <reason>`; a rejected bundle keeps
the LVB (R6). The route returns `503 CLOUD_UNAVAILABLE` when the cloud is not configured, when the kiosk is
forced OFFLINE, or when the sync fails.

### 3.12 `POST /v1/admin/rate-limit/reset` → 204

Requires `X-Admin-Token`. Clears this kiosk's attack-evidence failure counter and any active lockout (D3).

### 3.13 `POST /v1/admin/eval/context` → 200 · `DELETE /v1/admin/eval/context` → 204

Requires `X-Admin-Token`. The context tags every attempt started **after** the call until it is cleared. Tags
flow into `/v1/events` (`eval` key) and `/v1/metrics` `by_label`. This replaces the v1.0 `X-Eval-Label` header.

```python
from typing import Literal

from pydantic import BaseModel


class EvalContext(BaseModel):
    run_id: str
    subject_id: str                     # pseudonymous subject (S01..), never a name
    label: Literal["bona_fide", "print", "screen_photo", "video", "mask_paper", "mask_3d", "injection"]
    condition: Literal["normal", "dim", "backlit", "far"]
    split: Literal["dev", "test"]       # dev = calibration, test = reported numbers
```

Request:

```json
{"run_id": "run_0930", "subject_id": "S03", "label": "print", "condition": "normal", "split": "test"}
```

Response 200:

```json
{"active": true, "context": {"run_id": "run_0930", "subject_id": "S03", "label": "print",
                             "condition": "normal", "split": "test"},
 "since": "2026-11-14T04:00:00Z"}
```

FAR/FRR do **not** come from this path. They come from `eval/collect_faces.py` + `eval/compare.py` on consenting
team photos (`eval/captures/`, gitignored, deleted after the event). The edge never exports embeddings.

### 3.14 `POST /v1/admin/clock` (demo only)

Requires `X-Admin-Token` and env `DEMO_MODE=1`; otherwise `403 FORBIDDEN`. The body must contain exactly one of
the following (otherwise `422 VALIDATION_ERROR`):

```json
{"set_local": "21:10"}
```

```json
{"offset_s": -3600}
```

```json
{"reset": true}
```

`set_local` is `"HH:MM"` for today in Asia/Kolkata. Response 200 (also reported as `demo_clock` in `/v1/mode`,
which drives the visible **"DEMO CLOCK hh:mm"** kiosk badge):

```json
{"active": true, "now_local": "21:10", "now_utc": "2026-11-14T15:40:00Z", "offset_s": 3000,
 "date_local": "2026-11-14", "bundle_issued_at": "2026-11-14T12:40:00Z", "earliest_utc": "2026-11-14T12:35:00Z",
 "earliest_local": "18:05", "earliest_date_local": "2026-11-14", "bundle_rollback": false, "cache_state": "FRESH"}
```

The body is the §3.10 `DemoClock` (v1.4 fields; examples: `docs/contracts/admin_access.examples.json` routes
`edge.admin.clock.post` and `edge.mode.get`). A `set_local` before `earliest_local` is **accepted** (200) and
flagged `bundle_rollback: true`, `cache_state: "INVALID"`; `403 FORBIDDEN` reason `NOT_DEMO_MODE` without
`DEMO_MODE=1`; `422` for `set_local` outside `00:00`–`23:59`.

**Control Panel rule (R-E, lead ruling v1.4)**: the fail-secure rollback rule below stays. The Control Panel's
demo-clock input defaults to **max(`now_local`, `earliest_local`)** (same `date_local`; if
`earliest_date_local` is after `date_local`, every `HH:MM` today is a rollback and the panel says so). Before
applying a time earlier than `earliest_local` it asks for confirmation with this wording: *"Before the installed
bundle's issued_at − 5 min: the bundle becomes INVALID and every attempt is STEP_UP SCHEDULE_BUNDLE_INVALID
(staff override can still ALLOW), not a schedule demo."* After applying, `bundle_rollback: true` shows a
persistent warning. The wording must say STEP_UP, never DENY. Every access change (`PUT` access, revoke, code
rotation) re-signs the bundle with `issued_at = now`, which moves `earliest_local` forward: make access changes
**before** setting evening demo times, or pick times after the last change.

- **What the clock drives**: the edge wall clock used for `t0`, schedule evaluation, bundle freshness, record
  `ts_utc` and the `GET /v1/mode` view.
- **What it does not drive**: nonce and step-up TTLs, the rate limiter and all latency use the monotonic or
  real clock. **TOTP always verifies against real wall time** (authenticator apps), never the demo clock (R18).
- **It does not re-sign the bundle.** A demo-clock time earlier than the bundle's `issued_at − 300 s`
  (`cache.clock_rollback_tolerance_s`) reads as a clock rollback, so the cache becomes INVALID.
  - The demo therefore uses **evening** times with a bundle issued earlier the same day. With the live bundle
    v45 (`issued_at` 2026-11-14T12:30:41Z = 18:00:41 IST) every demo-clock time must be **after ~17:55:41 IST**.
    Example at MAIN_GATE (the only zone in v45; students Sat 06:00–22:00, grace 15 min): 22:10 = grace → STEP_UP
    `SCHEDULE_GRACE_WINDOW`; 22:30 = outside window → DENY `SCHEDULE_OUTSIDE_WINDOW`.
  - A newer bundle moves the bar: the rule is checked against the `issued_at` of the last valid bundle. Sign a
    replacement bundle with `--now` set early enough (e.g. the v45 `issued_at`) if the demo clock must go back.
  - Never set the clock to the morning after signing (test X13).
- **Bundle signing** (R7): `scripts/sign_bundle.py` (from `config/schedule.demo.json`) and the cloud's
  `GET /v1/schedule/{kiosk_id}` stamp `issued_at = now` (or `--now`) and `expires_at = now + 12 h`. Every override
  code gets `valid_until = expires_at + 24 h` (`fallback.staff_override.valid_after_expiry_h` = 24), so
  STAFF_OVERRIDE still works on an EXPIRED bundle.
  - **Do not re-run `scripts/sign_bundle.py` with its defaults while the edge holds v45**: the source carries
    `bundle_version` 42, which the edge rejects as older (`BUNDLE_REJECTED`, the LVB stays), and the script
    overwrites `edge/data/DEMO_CODES.txt`. A replacement must use `--version` > the installed version (46+).
- **Reset before mode AUTO and any sync**: send `{"reset": true}` before `POST /v1/admin/mode {"force": "AUTO"}`
  or `POST /v1/admin/sync`. Sync stamps `kiosk_now_utc` from the demo clock, and a skew over 120 s raises
  `ALERT_CLOCK_SKEW` on the cloud.
- If the policy runtime has no demo clock (fail-secure runtime), the route returns `409 INVALID_STATE`.

### 3.14a `POST /v1/admin/random-challenge` (demo only)

Requires `X-Admin-Token` and `DEMO_MODE=1`; otherwise `403 FORBIDDEN`. It controls the random liveness challenge
(R4). The configured rate is 0.15 online / 0.30 offline. The scripted demo switches it `OFF` first (so no scripted
ALLOW draws a challenge) and uses `FORCE_NEXT` for the step that shows it. The `/admin` UI has no control for it
yet: use curl.

```json
{"mode": "FORCE_NEXT"}
```

Response 200:

```json
{"random_challenge": "FORCE_NEXT"}
```

| `mode` | Effect |
|---|---|
| `AUTO` | Use the configured `challenge.random_rate` (0.15 online / 0.30 offline). |
| `FORCE` | Every would-be ALLOW becomes STEP_UP / CHALLENGE `[RANDOM_CHALLENGE]`, until the mode is changed. |
| `FORCE_NEXT` | Stays armed until a would-be ALLOW uses it: that attempt becomes STEP_UP / CHALLENGE `[RANDOM_CHALLENGE]`, then the mode returns to **`AUTO`** (not `OFF`). Attempts that are not would-be ALLOWs (DENY, other step-ups) do not use it. |
| `OFF` | Never, whatever the rate (eval / scripted-demo profile). Also disarms a pending `FORCE_NEXT`. |

- A forced draw fires whatever the configured rate is (`edge/policy/engine.py` stage 8b).
- The mode is held **in memory**: an edge restart resets it to `AUTO`. After a `FORCE_NEXT` has been used the mode
  is `AUTO` again, so a scripted run re-sends `{"mode": "OFF"}` afterwards.
- The current value is shown in `GET /v1/mode` `random_challenge`.
- Only a would-be ALLOW is ever converted. Forcing never loosens a decision.
- Any other value → `422 VALIDATION_ERROR`.
- If the runtime has no random challenge (fail-secure runtime), the route returns `409 INVALID_STATE`.

### 3.15 `POST /v1/enroll` (admin) → 201 · `DELETE /v1/enroll/{user_id}` (admin) · `GET /v1/admin/users` (admin)

**Enrolment page**: `kiosk/public/enroll.html`, served by the kiosk dev server. It has a consent checkbox with
the DPDP notice ("purpose and storage limitation"; deleted after the event), an admin-token field and an
optional TOTP provisioning box. It captures 5 frames of slightly varied pose at up to 1280 px wide.

`multipart/form-data`: `frame_0..frame_4` (`image/jpeg`, ≤ 2 MB each) + `meta`:

```python
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class EnrollMeta(BaseModel):
    model_config = ConfigDict(extra="ignore")
    user_id: str = Field(pattern=r"^u_[0-9a-z]{4}$")   # v1.4: MUST be in the installed bundle (else 409 NOT_IN_SCHEDULE)
    display_name: str = Field(min_length=1, max_length=80)   # stripped first (R-H)
    email: str | None = None                # EMAIL_OTP target, forwarded to the cloud only (never stored on the edge)
    role: str | None = None                 # v1.4: optional, NEVER applied (the signed schedule owns the role);
                                            # clients omit it; a value that differs from the schedule adds a warning
    consent: Literal[True]                  # explicit consent; DPDP notice version recorded
    consent_version: str = Field(min_length=1, max_length=40)   # e.g. "2026-11-14.v1"
    card_id: str | None = None              # simulated HID card; stored only as HMAC-SHA256(CARD_ID_PEPPER, id)
    provision_totp: bool = True


class EnrollResponse(BaseModel):
    user_id: str
    template_version: int
    local_cache_updated: bool
    cloud_indexed: bool = False             # False when offline / not configured / cloud enrol failed
    totp_provisioning_uri: str | None = None   # shown once on the enrolment page; never logged
    frames_used: int                        # diagnostics (ratified, C7)
    frames_rejected: list[dict[str, Any]] = Field(default_factory=list)   # {frame, reasons[], p_live}
    min_pairwise_cosine: float | None = None
    cloud: dict[str, Any] | None = None     # cloud enrol call result {status, body} (secret-bearing keys removed)
                                            # or {status: null, error}; diagnostic only, clients use cloud_state
    # ---- v1.4 additions (R-A / R-F)
    cloud_state: Literal["indexed", "failed", "skipped_offline", "not_configured"] = "not_configured"
    totp_active: bool = False               # a local TOTP secret exists AND the installed bundle marks the user
                                            # fallback.totp_enrolled: only then is TOTP offered at the kiosk
    schedule_role: str | None = None        # the role decisions use (installed bundle), never meta.role
    schedule_display: str | None = None
    role_requested: str | None = None       # meta.role echoed (null when omitted)
    role_applied: bool = False              # always false: enrolment never sets a role
    bundle_version: int | None = None       # installed after the post-enrolment refresh
    reinstated_after_erasure: bool = False  # a stale ERASED overlay entry was cleared (re-admitted user)
    warnings: list[str] = Field(default_factory=list)   # human-readable; shown verbatim in the UI
```

```json
{"user_id": "u_kv02", "template_version": 1, "local_cache_updated": true, "cloud_indexed": true,
 "cloud_state": "indexed",
 "totp_provisioning_uri": "otpauth://totp/HID-Kiosk:u_kv02?secret=JBSWY3DPEHPK3PXP&issuer=HID-Kiosk&digits=6&period=30",
 "totp_active": true, "frames_used": 5, "frames_rejected": [], "min_pairwise_cosine": 0.7132,
 "cloud": {"status": 201, "body": {"user_id": "u_kv02", "faces_indexed": 5, "bundle_version": 51}},
 "schedule_role": "faculty", "schedule_display": "Prof. Arjun T.", "role_requested": null, "role_applied": false,
 "bundle_version": 51, "reinstated_after_erasure": false, "warnings": []}
```

**`cloud_state`** (R-F): `indexed` = the cloud indexed the faces (Rekognition) · `failed` = ONLINE but the cloud
enrol failed or was unreachable: the UI shows a **blocking-style warning** ("NOT_ENROLLED online until
re-enrolled with the cloud reachable") and must not present the enrolment as complete · `skipped_offline` = the
kiosk was OFFLINE: the UI shows a clear offline note (local template only; re-enrol once ONLINE) ·
`not_configured` = no cloud. The TOTP QR is shown as "Scan now" only when `totp_active` is true; otherwise it is
labelled "not active until the schedule marks this user TOTP-enrolled (re-enrol while ONLINE)".

**Registration sequence (R-A, lead ruling v1.4)**, `/register` and the admin enrol card:

1. ONLINE check. A person **not in the schedule** (status `NOT_IN_SCHEDULE`, or no row) needs ONLINE; offline the
   UI blocks with "New people can only be registered while the kiosk is ONLINE (the cloud signs the schedule)".
2. `PUT /v1/admin/access/users/{user_id}` `{display, role, consent: true, actor: "register"}` (§3.18.2): creates
   the user (or applies a changed role) and installs the re-signed bundle in the same call. Proceed only when
   `bundle.applied` is true **and** `user.in_bundle` is true; if `applied` is false, call `POST
   /v1/admin/bundle/refresh` (up to 3 tries, 1 s apart), then stop with the warning. `in_bundle: false` means the
   role has no access at this kiosk's zone: stop and say so.
   - status `ERASED`: the same PUT with `consent: true` is the re-admission (R-B); the UI labels the button
     **"Re-admit and enrol"**.
   - status `REVOKED`: the PUT returns `409 USER_REVOKED`; registration stops ("revoked: Restore in Users &
     Access first").
   - a person already in the bundle with the same role may skip the PUT (offline enrolment of bundle users works).
3. `POST /v1/enroll` (meta without `role`). Render `warnings[]` and `cloud_state` as above.

**Enrolment errors** (all with `error.reason` in v1.4; examples: route `edge.enroll.post`):

| HTTP | `code` | `reason` | When |
|---|---|---|---|
| 403 | `FORBIDDEN` | `USER_REVOKED` | user revoked (any non-ERASED revocation); nothing analysed or stored |
| 409 | `INVALID_STATE` | `NOT_IN_SCHEDULE` | `user_id` not in the installed bundle (`bundle_version` in the error) |
| 409 | `INVALID_STATE` | `NO_BUNDLE` | no verified bundle installed |
| 409 | `INVALID_STATE` | `ERASED_IN_BUNDLE` | erased and not re-admitted (the bundle still carries the ERASED revocation) |
| 409 | `INVALID_STATE` | `FACE_ENROLLED_OTHER` | the face matches a different enrolled user |
| 409 | `INVALID_STATE` | `LOOK_MISMATCH` | re-enrolment frames do not resemble the original templates |
| 422 | `VALIDATION_ERROR` | `FRAMES_REJECTED` | fewer than `quality.min_usable_frames` frames passed, or not one identity |
| 422 | `VALIDATION_ERROR` | — | malformed meta (`details[]`), `card_id` without `CARD_ID_PEPPER` |
| 503 | `MODELS_UNAVAILABLE` | — | detector / ArcFace / PAD self-test / template cache missing |

- **Liveness first**: every frame must pass the edge quality gate and passive PAD (`P_live` ≥ `pad.pass_min`)
  with no device box near the face. Rejection reasons are `NO_FACE`, `FACE_COUNT`, `QUALITY_*`,
  `PAD_BELOW_PASS` and `DEVICE_NEAR_FACE`.
  - Fewer than `quality.min_usable_frames` (3) accepted frames, or accepted frames that are not one identity
    (min pairwise cosine < `match.local.allow_min_cosine`), give `422 VALIDATION_ERROR`.
  - A face that already matches a **different** enrolled user gives `409 INVALID_STATE`.
  - **Re-enrolment appends** (same `user_id`): the accepted frames are added as a new look, at most 24
    templates per user (`MAX_TEMPLATES_PER_USER`), the first 5 (the original enrolment) pinned and never evicted,
    the newest of the rest kept; `template_version` + 1 (`edge/ml/templates.py`). Every new frame must resemble the
    original enrolment (the 5 pinned templates) at `match.local.allow_min_cosine`, else `409 INVALID_STATE` and
    nothing changes, so a chain of re-enrolments cannot walk an account to a different face. To replace
    a user's look, `DELETE /v1/enroll/{user_id}` first, then enrol (`edge/enroll.py`).
  - A missing detector / ArcFace / PAD self-test / template cache gives `503 MODELS_UNAVAILABLE`.
  - A `card_id` without `CARD_ID_PEPPER` gives `422`.
- **Local template**: the ArcFace template goes into the encrypted local cache (Fernet, `EDGE_DATA_KEY`). This
  **works offline**, so the demo gallery can be built without AWS.
- **Cloud indexing**: when the edge is ONLINE, it forwards the accepted frames + meta (with `card_id_hash` and
  no raw `card_id`) to Cloud `POST /v1/enroll` (§4.8), which indexes them in Rekognition. Only consenting team
  faces are indexed, and they are deleted at teardown.
  - **E-mail**: `enroll.html` has an e-mail field (pre-filled only for `u_prj1`) and sends `email` only when it is
    filled. The **deployed** cloud enrol model still requires `email`, so an enrolment without one ends with
    `cloud_indexed: false` (cloud 422). The cloud code in the tree makes it optional (no e-mail = no EMAIL_OTP for
    that user); that change is live only after the lead redeploys.
  - **Cloud re-enrolment**: the deployed cloud build *replaces* the user's Rekognition faces (it deletes them
    first, so a re-enrolment that then fails leaves the user with none). The tree code appends (24 faces, 5
    pinned) like the edge, after the redeploy. Until then do not re-enrol `u_prj1` / `u_tm03` while ONLINE
    (`cloud/SANDBOX.md` §0).
  - With Rekognition authoritative online, an un-indexed user is `NOT_ENROLLED` online. Collection state at the
    time of writing: `u_prj1` and `u_tm03` are indexed, `u_tm02` is not (enrolled on the edge only).
- **TOTP**: the secret is provisioned by the policy runtime's encrypted credential store, never in the bundle.

`DELETE /v1/enroll/{user_id}` (DPDP erasure; `user_id` must match `^u_[0-9a-z]{4}$`, else 422) removes the local
template and the TOTP secret, and when the cloud is configured calls Cloud `DELETE /v1/enroll/{user_id}`.
Response 200 (v1.4, every key always present):

```json
{"user_id": "u_prj1", "local_removed": true, "cloud": "deleted", "cloud_status": 200, "message": null,
 "bundle": {"previous_version": 49, "installed_version": 50, "changed": true, "result": "installed", "error": null}}
```

- `cloud` is one of `deleted | queued | not_configured | failed`: `deleted` (cloud 200/204/404; the edge then
  installs the re-signed bundle, `bundle`), `queued`, `not_configured` or `failed` (`bundle` null for the last
  three).
- **`queued` (R-J, v1.4)**: OFFLINE, or the cloud call failed (transport, 5xx, another status). The local data is
  erased at once; the pending cloud erasure (`user_id` + `queued_at` only) is persisted encrypted in
  `edge/offline` (`PolicyRuntime.queue_cloud_erasure`) and replayed at every sync until the cloud answers
  200/204/404 (idempotent). `message` says so; `GET /v1/admin/access/users` lists them in
  `pending_cloud_erasures[]`.
- **`failed` (M1, v1.4)**: as `queued`, but the local erasure queue itself could not be written (e.g. a disk
  error, or a runtime without the queue). The local template and TOTP secret **are** erased (`local_removed`
  as usual); the cloud erasure did **not** happen and is **not** queued. `cloud_status` is the cloud's HTTP status
  when there was one (else null); `message` says what failed and to retry `DELETE /v1/enroll/{user_id}` while the
  kiosk is ONLINE. The UI shows this as a warning, not as a completed erasure: "Local data erased. The cloud
  erasure could not be queued: retry the erasure while the kiosk is ONLINE." Example: route `edge.enroll.delete`,
  `cloud_erasure_failed`.
- A user that is neither enrolled locally nor erasable in the cloud (cloud not configured) gives `404 NOT_FOUND`
  reason `NOT_ENROLLED`.
- The cloud erasure keeps the campus entitlement suspended by an ERASED revocation (§4.3 `ERASE`); re-admission is
  `PUT` access with `consent: true` (§3.18.2).

`GET /v1/admin/users` (`X-Admin-Token`) lists the locally enrolled users (no templates, no secrets). `role` /
`display_name` are the **installed bundle's** (what decisions use; null when not in the bundle); the label stored
with the template is `template_role` / `template_display_name` (informational only):

```json
{"users": [{"user_id": "u_3c4d", "display_name": "Priya N.", "role": "student", "bundle_role": "student",
            "bundle_display": "Priya N.", "in_schedule": true, "template_role": "student",
            "template_display_name": "Priya N.", "template_version": 1, "templates": 5, "totp_local": true,
            "card": true, "updated_at": "2026-11-14T03:12:40Z"}],
 "bundle_version": 49, "count": 1, "model": "arcface_r50", "age_h": 1.4, "skipped_model_mismatch": 0}
```

`409 INVALID_STATE` when the template cache is unavailable.

`GET /v1/admin/attempt/{attempt_id}/signals` (`X-Admin-Token`) is the per-attempt debug view. It returns the
policy input (`signals`, i.e. the AttemptSignals model), raw per-frame values (`raw`: `p_live`, device, moiré,
mask ring, flash fit incl. `r_frames` / `r_client`, match scores, cloud match, depth, and `probe`: the early-probe
outcome, §3.1a) and the challenge evidence.
There are no images and no embeddings. `404 ATTEMPT_NOT_FOUND` after the 600 s in-RAM retention.

### 3.16 `GET /v1/metrics?since=<iso>&label=<eval_label>`

The dashboard feed. The official numbers are computed by `eval/` from the event stream with bootstrap CIs (D14).

```json
{"window": {"since": "2026-11-14T03:00:00Z", "until": "2026-11-14T07:00:00Z"},
 "attempts": 214,
 "decisions": {"ALLOW": 61, "STEP_UP": 38, "DENY": 115},
 "by_mode": {"ONLINE": 180, "OFFLINE": 34},
 "reason_codes": {"SPOOF_DEVICE_DETECTED": 41, "SPOOF_PASSIVE": 29, "MASK_CUE_EDGE": 9},
 "latency_ms": {"client": {"p50": 1520, "p95": 1880, "n": 198},
                "total": {"p50": 480, "p95": 610, "n": 214},
                "liveness": {"p50": 290, "p95": 360, "n": 214},
                "match": {"p50": 440, "p95": 590, "n": 214}},
 "by_label": {"print": {"n": 40, "accepted": 0, "apcer": 0.0, "apcer_upper_95": 0.075,
                        "attack_label_known": true,
                        "latency_ms": {"client": {"p50": 1490, "p95": 1820, "n": 40}}},
              "bona_fide": {"n": 50, "rejected": 1, "step_up": 6, "bpcer": 0.02, "bpcer_upper_95": 0.0914,
                            "latency_ms": {"client": {"p50": 1540, "p95": 1900, "n": 50}}}},
 "sync": {"queue_depth": 0, "last_sync_at": "2026-11-14T06:58:40Z"}}
```

Values are illustrative only. Localhost-only, no admin token (C9). `latency_ms` has one entry per server stage
seen (`total`, `liveness`, `match`, `schedule`, `policy`, `quality`, …) plus `client`.
Every non-`bona_fide` `by_label` entry is scored as an attack (`accepted`, `apcer`, `apcer_upper_95`) and carries
`attack_label_known`: true when the label is a known attack label (`print`, `screen_photo`, `video`, `mask_paper`,
`mask_3d`, `injection`, `replay`, `screen`; `edge/metrics.py` `ATTACK_LABELS`), false for any other label.
`sync.last_sync_at` is the `GET /v1/mode` `last_sync.at` value. The metrics are in memory: an edge restart starts a
new sample.

**Latency evidence on file** (stored sources; not eval results): `eval/results/latency_edge_1280_20261114T171323Z.md`
(+ `.csv`), an edge-only bench (`scripts/bench_latency.py --runs 40`, synthetic 1280×720 frames over localhost, offline,
local match, cloud not configured, policy 2026-11-14.3): server `latency_ms.total` p50 76.0 ms [95% bootstrap CI
75.0–81.0] / p95 106.4 ms [88.1–122.0], n = 40. The older `eval/results/latency_edge.md` (640×480 frames, policy
2026-11-14.2, n = 30) is superseded. Both exclude face lock, the 700 ms capture window, the cloud match and browser
rendering, so neither is the face lock → rendered number.

- Kiosk face lock → decision rendered (`latency_ms.client`): **measurement pending**. Earlier live `/v1/metrics`
  snapshots were in memory only and were lost at edge restarts; no file in `eval/results/` holds them, so they
  are not quoted. Record a fresh `GET /v1/metrics` snapshot into `eval/results/` (with the early probe live)
  before any client latency goes on a slide.
- The server `latency_ms.total` includes the cloud wait when Rekognition is called, so it is not an "edge-only"
  number either.
- The official numbers, with confidence bounds, come from the eval run, which **has not been run**
  (`eval/results/runs/` holds only a 0-attempt metrics snapshot,
  `snapshot_20261114T171349Z`).

- **Final decision**: decisions and labels use each attempt's final decision. A STEP_UP later resolved to
  ALLOW counts as ALLOW (system-level APCER).
- **Latency**: `latency_ms.client` is face lock → rendered (§3.8). `total`, `liveness` and `match` are
  server-side, from `frames` requests only.
- **Confidence bounds**: `apcer_upper_95` and `bpcer_upper_95` are one-sided 95 % Clopper-Pearson upper bounds.
  With **0 errors** the rule of 3 is reported (3/n; the exact bound is 1 − 0.05^(1/n), e.g. 0.072 for n = 40).
  A zero-error result is therefore always shown as "< 3/n", never as 0 %.
- **Honesty**: never round up; "iBeta Level 1-style protocol" (designed, not yet run), never "certified".

### 3.17 DepthProbe endpoints: `GET /v1/depth/pending` · `POST /v1/depth/frames`

The free DepthProbe SwiftUI app on the iPhone 16 Pro Max (front TrueDepth) talks to the edge directly. There is
no Record3D and no `:8765` bridge.

- **Network** (C6, ratified): the phone reaches the edge over the LAN via a second listener on
  `0.0.0.0:EDGE_LAN_PORT` (demo 8001; unset or 0 = no LAN listener). That listener serves **only**
  `GET /v1/depth/pending` and `POST /v1/depth/frames`. The same two routes are also mounted on the localhost API.
- **Auth**: both routes require the header `X-Depth-Token`, which must equal `DEPTH_DEVICE_TOKEN`
  (constant-time compare). A missing or wrong token, or an unset `DEPTH_DEVICE_TOKEN`, gives `401 UNAUTHORIZED`.
- **Anti-replay**: `/pending` issues a single-use `depth_nonce` bound to `attempt_id` + `phase`. `/frames` must
  echo it; a mismatch or reuse gives `403 FORBIDDEN`.
- **Gating**: everything is gated by `liveness.depth.enabled`, which stays **false** until the H4 calibration
  (10 live vs 10 printed photo) passes. H4 has **not been run** (`depth/calibration/` is empty). While it is false, no captures are queued (`/pending` long-polls to
  204) and `POST /v1/depth/frames` returns `409 INVALID_STATE`.
- **App**: DepthProbe v0.3.0 is built as an **unsigned IPA** and sideloaded by the operator with Sideloadly (a
  v0.3.1 IPA is also built, `depth/ios/dist/`). The app connects when it is running and polling (`/v1/health`
  `depth_probe`: `connected`, `unavailable`, or `rejected_token` when it polls with a wrong `X-Depth-Token`);
  the live edge reported `unavailable` at the time of writing. Xcode builds use
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer` (xcode-select still points at the Command Line
  Tools).
- **Simulator**: the iOS Simulator has no TrueDepth camera. It can only exercise the long-poll/upload path, with
  synthetic frames (`depth/synth.py`).

**`GET /v1/depth/pending?wait_s=20`** is a long-poll (0 ≤ `wait_s` ≤ 30). It returns 204 when no capture is
pending, otherwise 200:

```json
{"attempt_id": "att_01JDA3K7Q9V2M4N6P8R0S2T4V6", "phase": "PASSIVE", "frames": 3, "deadline_ms": 1794630913040,
 "depth_nonce": "dn_Qm7xK2pV9sLr4TfA8cWz1g"}
```

- `phase`: `PASSIVE` is queued by `session/start`; `CHALLENGE` is queued when a challenge is issued (for M1).
- `frames`: 1–3.
- `delay_ms`, `interval_ms` (optional, **CHALLENGE only**; absent for PASSIVE): wait `delay_ms` before the first
  capture, then `interval_ms` between captures, so the frames land on the challenge's deformation step (M1 needs
  the expression, not the neutral face). Computed by `edge/depth_bridge.py` `challenge_capture_timing`:
  `delay_ms` = min(3000, 500 + k × `challenge.step_window_ms` + `challenge.min_reaction_ms`), where k is the
  index of the first deformation action (SMILE / OPEN_MOUTH; `PUFF_CHEEKS` is wire-only, never issued); `interval_ms` = max(100,
  (`step_window_ms` − `min_reaction_ms`) // 3).
- `deadline_ms`: epoch ms by which the frames must arrive = queue time + window (PASSIVE: `liveness.flash.duration_ms`,
  700 ms; CHALLENGE: 0) + `delay_ms` + `interval_ms` × (frames − 1) + 2000 ms upload margin
  + `latency_budget_ms.depth_max_wait` (150 ms).
- `depth_nonce`: single-use, bound to `attempt_id` + `phase`; must be echoed in `DepthFramesMeta`.
- Unknown extra fields must be ignored by the app.

**`POST /v1/depth/frames`** is `multipart/form-data`:

| Part | Type | Notes |
|---|---|---|
| `meta` | `application/json` (string field) | `DepthFramesMeta` below |
| `depth_0` … `depth_2` | `application/octet-stream` | Raw little-endian, row-major, `width × height` values of `dtype`. Depth in **metres** or disparity in **1/m**. NaN or 0 = invalid. Size must equal `width × height × itemsize`, at most 8 MB per part. |
| `rgb_0` | `image/jpeg` (optional) | Synchronised RGB frame; the edge uses it to locate the face if `face_box_norm` / `landmarks_norm` are null |

```python
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class DepthFramesMeta(BaseModel):
    model_config = ConfigDict(extra="ignore")
    attempt_id: str
    depth_nonce: str                              # echo of /v1/depth/pending depth_nonce (required, single-use)
    phase: Literal["PASSIVE", "CHALLENGE"] = "PASSIVE"
    depth_type: Literal["disparity", "depth"]     # TrueDepth delivers disparity natively
    dtype: Literal["float16", "float32"]
    width: int = Field(gt=0, le=4096)
    height: int = Field(gt=0, le=4096)
    intrinsics: dict[str, float] | None = None    # {fx, fy, cx, cy, ref_width, ref_height}; ref_* = resolution
                                                  # the intrinsics refer to (scaled to the depth map by the edge)
    face_box_norm: list[float] | None = None      # [x, y, w, h], Vision face rect on the RGB frame, normalised, top-left origin
    landmarks_norm: dict[str, list[float]] | None = None   # {"left_eye": [x, y], "right_eye": [x, y], "nose": [x, y]}
    timestamps_ms: list[float] = Field(default_factory=list)   # one per depth part, epoch ms
    device: dict[str, Any] | str | None = None    # e.g. "iPhone17,2 / iOS 26.1"
    accuracy: Literal["absolute", "relative"] | None = None   # AVDepthData.depthDataAccuracy; D4 needs absolute
```

```json
{"attempt_id": "att_01JDA3K7Q9V2M4N6P8R0S2T4V6", "depth_nonce": "dn_Qm7xK2pV9sLr4TfA8cWz1g",
 "phase": "PASSIVE", "depth_type": "disparity",
 "dtype": "float16", "width": 320, "height": 240,
 "intrinsics": {"fx": 2741.3, "fy": 2741.3, "cx": 1516.2, "cy": 2015.8, "ref_width": 3088, "ref_height": 2316},
 "face_box_norm": [0.30, 0.21, 0.39, 0.52],
 "landmarks_norm": {"left_eye": [0.42, 0.38], "right_eye": [0.58, 0.38], "nose": [0.50, 0.50]},
 "timestamps_ms": [1794630912100, 1794630912433, 1794630912766], "device": "iPhone17,2 / iOS 26.1",
 "accuracy": "relative"}
```

Response 200:

```json
{"accepted": true, "attempt_id": "att_01JDA3K7Q9V2M4N6P8R0S2T4V6", "phase": "PASSIVE",
 "checks": {"d0_valid_ratio": 0.82, "d1_plane_rms_mm": 9.4, "d2_quad_rms_mm": 6.1, "d3_nose_relief_mm": 19.0,
            "d4_ipd_mm": null, "m2_depth_step_mm": 1.2, "m3_template_rms_mm": null}}
```

- The edge runs `depth.checks.compute_depth_checks` on the frames.
- `accepted` means the frames were parsed and attached to the attempt.
- Depth **counts** only if it arrived within `latency_budget_ms.depth_max_wait` after the RGB frames (PASSIVE),
  or after the challenge submission (CHALLENGE). Otherwise it is NOT_AVAILABLE with no effect, and
  `DecisionResponse.scores.depth` is `null`.
- `checks` may also include the remaining `DepthSignal` fields (`available`, `absolute`, `d5_disagree`, `m1_*`).
- Depth maps stay in RAM only and are dropped after 180 s; they are never stored. Calibration values for H4 are
  collected with `depth/calibrate.py`.
- The H4 go/no-go is unchanged (`docs/IPHONE_SETUP.md`).

Errors:

- `401 UNAUTHORIZED`: missing or wrong `X-Depth-Token`.
- `404 ATTEMPT_NOT_FOUND`.
- `403 FORBIDDEN`: `depth_nonce` reused, mismatched, or never issued for this attempt + phase.
- `409 INVALID_STATE`: depth disabled, or attempt closed.
- `422 VALIDATION_ERROR`: missing `depth_nonce`, size or dtype mismatch, or no `depth_*` part.
- `413 PAYLOAD_TOO_LARGE`: a part > 8 MB.

### 3.18 Users & Access (Control Panel) admin routes (new in v1.4)

All routes need `X-Admin-Token` (`401 UNAUTHORIZED` otherwise). They are the edge proxies of the cloud master
schedule (§4.9a): the **signed schedule is the single source of truth** for a user's role, zones, hours, validity
and revocation (cloud master → signed per-kiosk bundle → edge). The edge never assigns a role itself. Owners:
edge-ml (`edge/access.py`, `edge/app.py`), cloud-aws (`cloud/app/routers/admin.py`,
`services/schedule_service.py`), kiosk-frontend (`kiosk/src/api/access.ts`, `kiosk/src/admin/**`,
`kiosk/src/operator/RegisterApp.tsx`). **Every** route below has valid and error examples in
`docs/contracts/admin_access.examples.json` (route ids in brackets); the three test suites validate against it.
Edge implementation: `edge/access.py` + `edge/access_models.py` (models are the reference for the field limits);
anything still open is marked **(code pending)** in place.

**ONLINE requirement** (writes: §3.18.2–§3.18.4): the cloud is configured (`CLOUD_API_URL` and a cloud admin
token) **and** the kiosk is not forced OFFLINE **and** `GET /v1/mode` reports `mode: ONLINE` or `reason:
bundle_stale` (connectivity is up but the bundle needs a refresh; a write is what fixes it). Otherwise `503
CLOUD_UNAVAILABLE` reason `OFFLINE` / `NOT_CONFIGURED`, before any cloud call. Reads (§3.18.1) work offline from
the installed bundle, read-only.

**Validation order** (writes): request model (`422`, `details[]`) → ONLINE (`503`) → edge pre-check of `role`
against the installed bundle's role names (`422 UNKNOWN_ROLE`; skipped without a bundle) → cloud call (cloud
errors forwarded, §3.18.6) → bundle pull. Zones are checked by the **cloud** only: the per-kiosk bundle is
filtered to the kiosk's zone (`filter_for_kiosk`), so the edge must not reject `LIBRARY` just because its
`MAIN_GATE` bundle lacks it.

**After every successful write** the edge pulls + verifies + installs the newest bundle
(`PolicyRuntime.refresh_bundle_now(expect_version=<cloud bundle_version>)`) **and** pulls the revocation feed
(§4.3), so a revoke / re-admit / restore applies to the very next attempt. A failed pull never turns a
successful cloud write into an error: the response is still 2xx with `bundle.applied: false` and a warning.

**Nullable write fields (M2)**: `cloud_bundle_version` (all three write responses) and, for revoke, `revoked_at`
and `seq` are typed `int | null` / `string | null`. They are null when the cloud reply did not carry them, which
goes with a failed follow-up pull (`bundle.applied: false`); the edge never invents them. Clients parse them as
nullable (kiosk `kiosk/src/api/access.ts`: `r.intN` / `r.strN`) and show **"pending refresh"** in their place,
never an error; the next `POST /v1/admin/bundle/refresh` (or `GET /v1/admin/access/users`) shows the applied
state. Examples: `saved_version_unknown`, `revoked_but_not_installed`, `minted_version_unknown`.

Shared shapes:

```python
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool

HHMM = r"^([01]\d|2[0-3]):[0-5]\d$"          # written times (R-H): 00:00-23:59
HHMM_READ_END = r"^(([01]\d|2[0-3]):[0-5]\d|24:00)$"   # read data only (role defaults may end at 24:00)
Day = Literal["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]


class Window(BaseModel):                   # write model; extra="forbid"
    model_config = ConfigDict(extra="forbid")
    days: list[Day] = Field(min_length=1, max_length=7)   # unique
    start: str = Field(pattern=HHMM)
    end: str = Field(pattern=HHMM)         # end > start (same day), else 422


class BundleRefresh(BaseModel):            # outcome of the edge's bundle pull
    previous_version: int | None           # installed before the pull
    installed_version: int | None          # installed after the pull
    changed: bool                          # installed_version != previous_version
    result: Literal["installed", "not_modified", "failed"]
    error: str | None                      # set when result == "failed"
    applied: bool | None = None            # only in write responses: installed_version >= cloud_bundle_version


class Fallback(BaseModel):                 # schedule flags (never the card hash, never a secret)
    totp_enrolled: bool
    card: bool                             # a card_id_hash is on file


class LocalEnrolment(BaseModel):           # this edge's template cache
    enrolled: bool
    templates: int
    template_version: int | None
    template_role: str | None              # label stored with the template (informational only)
    totp_local: bool                       # the runtime credential store holds a TOTP secret
    updated_at: str | None


class TodayWindow(BaseModel):
    start: str                             # "HH:MM"; an end before the start crosses midnight
    end: str                               # may be "24:00"
    source: Literal["role", "extra"]       # role / visitor-pass / exception windows = "role"; users[].extra_windows = "extra"


class Today(BaseModel):                    # what the edge enforces today at THIS kiosk's zone (edge clock incl. demo clock)
    zone: str
    date: str                              # "YYYY-MM-DD" Asia/Kolkata
    day: Day
    now_local: str
    permitted: bool                        # zone in the user's permitted zones (role zones + zones_add - zones_remove + passes)
    holiday: bool
    windows: list[TodayWindow]             # [] when not permitted
    status_now: Literal["IN_WINDOW", "GRACE_WINDOW", "OUTSIDE_WINDOW", "NO_ENTITLEMENT", "ZONE_NOT_PERMITTED",
                        "HOLIDAY", "REVOKED"]   # edge/policy/schedule.py evaluate_schedule


class AccessUser(BaseModel):               # one row of the Users & Access table
    user_id: str
    display: str                           # schedule display; template display_name when not in the schedule
    role: str | None                       # authoritative per `source`: cloud master (cloud+bundle) else bundle
    bundle_role: str | None                # role in the INSTALLED bundle (what decisions use now); null = not in it
    in_schedule: bool                      # in the cloud master (cloud+bundle) / in the bundle (bundle)
    in_bundle: bool                        # in this kiosk's installed bundle (filtered to its zone)
    status: Literal["ACTIVE", "REVOKED", "ERASED", "NOT_IN_SCHEDULE"]   # REVOKED wins over ERASED (R16)
    revoked_at: str | None                 # REVOKED / ERASED: when
    revoked_reason: str | None             # e.g. "ADMIN"; "ERASED" for status ERASED
    bundle_stale: bool                     # cloud role / zones_add / extra_windows / status differ from the bundle
    zones_add: list[str]
    zones_remove: list[str]
    extra_windows: dict[str, list[Window]] # zone -> windows (full set, all zones in cloud+bundle; kiosk zone only offline)
    valid_from: str | None                 # UTC ISO-8601 "Z"
    valid_until: str | None
    fallback: Fallback
    cloud_faces: int | None                # faces indexed in Rekognition; null = unknown (offline / not listed)
    local: LocalEnrolment
    today: Today | None                    # null when not in the installed bundle or no kiosk zone
```

**Hours display (R-I)**: the kiosk computes the hours it shows for a selected zone / day as
`role_defaults[role].windows[zone]` (when `zone` ∈ `role_defaults[role].zones` ∪ `zones_add` − `zones_remove`) plus
`extra_windows[zone]`, filtered by `days`. Exceptions and holidays are not shipped to the kiosk; `today` is the
edge's authoritative view for the kiosk's own zone and is shown next to it ("enforced today").

#### 3.18.1 `GET /v1/admin/access/users` → 200 [`edge.access.users.list`]

```python
class AccessUsersResponse(BaseModel):
    source: Literal["cloud+bundle", "bundle"]   # "bundle" = the cloud list could not be loaded
    read_only: bool                             # true iff source == "bundle"
    read_only_code: Literal["OFFLINE", "NOT_CONFIGURED", "CLOUD_ERROR", "ENDPOINT_NOT_DEPLOYED",
                            "CLOUD_ADMIN_TOKEN"] | None
    read_only_reason: str | None                # human-readable
    mode: Literal["ONLINE", "OFFLINE"]
    kiosk_id: str
    zone: str | None                            # this kiosk's zone
    now_local: str                              # "HH:MM" (edge clock)
    date_local: str                             # "YYYY-MM-DD"
    day: Day
    bundle: dict                                # {version: int|None, issued_at: str|None, expires_at: str|None} (installed LVB)
    cloud_bundle_version: int | None            # the master's version (null offline)
    roles: list[str]                            # role names, sorted (master online, bundle offline)
    role_defaults: dict[str, dict]              # role -> {zones: [str], windows: {zone: [{days, start, end}]}};
                                                # online = master (all zones), offline = bundle (kiosk zone only);
                                                # "end" may be "24:00" (read data)
    zones: dict[str, dict]                      # zone -> {risk: "low"|"medium"|"high", requires_explicit_grant: bool}
    staff_ids: list[str]                        # staff ids that hold override codes (ids only; never hashes / codes)
    pending_cloud_erasures: list[str]           # user_ids whose cloud erasure is queued (R-J)
    users: list[AccessUser]                     # sorted by user_id: master ∪ bundle ∪ local templates
```

Offline the list is still served (`source: "bundle"`, `read_only: true`), and the kiosk disables every write
control with `read_only_reason`. Only `401` is an error for this route; a cloud failure degrades to read-only.

#### 3.18.2 `PUT /v1/admin/access/users/{user_id}` → 200 [`edge.access.users.put`]

Create or update a user's schedule entry; also **re-admit** (R-B) and **restore** (R-C). Path `user_id`
`^u_[0-9a-z]{4}$`. Body (`extra="forbid"`; absent = unchanged, forwarded to the cloud as sent, `exclude_unset`):

```python
class AccessUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    role: str = Field(pattern=r"^[a-z_]{1,32}$")          # required on every PUT; must be a master role
    display: str | None = Field(default=None, min_length=1, max_length=80)   # required to create
    consent: StrictBool | None = None # true = the person consented: required to create, to re-admit an ERASED
                                      # user, and with restore
    restore: StrictBool | None = None # true = lift this user's revocation (R-C "Restore"); requires consent: true
    zones_add: list[str] | None = Field(default=None, max_length=16)         # REPLACES the old list
    extra_windows: dict[str, list[Window]] | None = None  # REPLACES all zones' extra windows; {} clears; <=16 zones,
                                                          # <=14 windows per zone
    valid_from: str | None = None     # ISO-8601 with offset; explicit null clears
    valid_until: str | None = None    # > valid_from; explicit null clears
    actor: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.:@-]{1,64}$")   # audit ("register",
                                      # "control-panel"); forwarded to the cloud
```

`consent` / `restore` (and rotate's `replace_existing`) are `StrictBool` on the edge and the cloud (L2): `"true"`,
`1` and other coercible values are rejected with `422` (round 2, R-L; examples `consent_string_rejected` on
`edge.access.users.put`, `restore_int_rejected` on `cloud.admin.access.put`). The edge models
(`edge/access_models.py`) are the reference for every R-H limit; the cloud mirrors them.

R-H round-2 clarifications:

- **Whitespace (R-M)**: `staff_id` (rotate) and `reason` (revoke) are validated as sent, with **no stripping**, on
  the edge and the cloud: `" s_guard01"` or `"ADMIN "` fails the pattern with `422`. (`display` / `display_name`
  are still measured after trimming.)
- **`user_id` scope (R-N)**: `^u_[0-9a-z]{4}$` applies to the admin-access routes only (§3.18.x paths, §4.9a
  paths, `DELETE /v1/enroll/{user_id}`). Enrolment keeps its own model: cloud `POST /v1/enroll`
  `EnrollMeta.user_id` keeps the broad `^[A-Za-z0-9_.\-]{1,64}$`; the edge's own `/v1/enroll` meta (§3.15) is
  narrow as built because every edge enrolment must already be a bundle user.
- **`consent_version`**: 1–40 characters everywhere (edge and cloud `EnrollMeta`, cloud `AdminContactRequest`).
- **Read windows (R-N)**: the edge `WindowRead` (`edge/access_models.py`) is the reference for read data
  (`GET /v1/admin/access/users`, cloud `GET /v1/admin/users` `roles{}.windows` / `extra_windows`): `days` is
  **required** (a non-null list of `MON`..`SUN`), `start` is `HH:MM` 00:00–23:59, `end` may additionally be
  `24:00`. The cloud's `ReadWindow` matches this; master-document windows without `days` are read back as all
  seven days (same meaning as the evaluator), and a master window `start` of `24:00` is refused.

State rules (cloud, authoritative; same reasons at the edge):

| Stored state | Request | Result |
|---|---|---|
| absent | `display` + `consent: true` | created (`created: true`) |
| absent | no `consent: true` / no `display` | `422` `CONSENT_REQUIRED` / `DISPLAY_REQUIRED` |
| ACTIVE | any | updated, or `unchanged: true` (same version, no publish) |
| ERASED | `consent: true` | ERASED revocation dropped, `readmitted: true`, feed `READMIT` reason `READMIT` |
| ERASED | no `consent: true` | `409 INVALID_STATE` `ERASED_IN_BUNDLE` |
| REVOKED | `consent: true, restore: true` | all of the user's revocations dropped, `restored: true` (and `readmitted` if an ERASED one went too), feed `READMIT` reason `RESTORE` |
| REVOKED | `consent: true`, no `restore` | `409 INVALID_STATE` `USER_REVOKED` (e.g. `/register` of a revoked person) |
| REVOKED | no `consent` | the edit is applied, revocation kept, warning "user is revoked: access changes do not lift a revocation (use Restore)" |

```python
class AccessUpdateResult(BaseModel):
    user_id: str
    created: bool
    unchanged: bool                   # nothing changed: no new bundle version
    readmitted: bool                  # an ERASED suspension was lifted (R-B)
    restored: bool                    # a revocation was lifted (R-C)
    previous_role: str | None         # null when created
    role: str
    cloud_bundle_version: int | None  # master version after the change; null = not in the cloud reply (M2)
    bundle: BundleRefresh             # with applied
    user: AccessUser | None           # the row after the pull (cloud_faces null); null if the pull failed
    warnings: list[str]               # cloud warnings + edge warnings (pull failed, not in this kiosk's bundle)
```

`user.in_bundle: false` after a successful pull means the role gives no access at this kiosk's zone (e.g. a
visitor without a pass): the kiosk must not proceed to enrolment here. Response timestamps are normalised to UTC
`Z` (`2026-12-15T23:59:00+05:30` → `2026-12-15T18:29:00Z`).

#### 3.18.3 `POST /v1/admin/access/users/{user_id}/revoke` → 200 [`edge.access.users.revoke`]

Body optional (`extra="forbid"`): `{"reason": "ADMIN", "actor": "control-panel"}`; `reason` matches
`^[A-Z][A-Z_]{1,31}$`, default `ADMIN`, and `ERASED` is refused (`422`: the DPDP erasure is `DELETE
/v1/enroll/{user_id}`). The edge calls cloud `POST /v1/admin/revocations` `{type: "USER", target_id, reason,
actor}` (never `force`), then pulls bundle + feed: decisions become `SCHEDULE_REVOKED` (DENY) online and offline
(the feed entry is kept in the encrypted overlay). Response:

```json
{"user_id": "u_3c4d", "type": "USER", "reason": "ADMIN", "revoked_at": "2026-11-14T12:50:00Z", "seq": 12,
 "cloud_bundle_version": 50,
 "bundle": {"previous_version": 49, "installed_version": 50, "changed": true, "result": "installed", "error": null,
            "applied": true},
 "user": {"user_id": "u_3c4d", "status": "REVOKED", "revoked_at": "2026-11-14T12:50:00Z",
          "revoked_reason": "ADMIN", "bundle_role": "student", "in_bundle": true},
 "warnings": []}
```

(`user` is the full §3.18 `AccessUser`; it is abbreviated here, and the complete row is in the examples file.)

Response types: `revoked_at: str | None`, `seq: int | None`, `cloud_bundle_version: int | None` (M2: null when the
cloud reply lacked them, with `bundle.applied: false`; the kiosk shows "pending refresh"), `user: AccessUser |
None`. Until the pull succeeds the row still shows the installed bundle's state (e.g. `ACTIVE`); example
`revoked_but_not_installed`.

Errors: `404 NOT_FOUND` `UNKNOWN_USER`; `409 INVALID_STATE` `ALREADY_REVOKED`; ONLINE / cloud errors (§3.18.6).
**Restore** is `PUT` access with `consent: true, restore: true` (§3.18.2).

#### 3.18.4 `POST /v1/admin/access/codes/rotate` → 200, `Cache-Control: no-store` [`edge.access.codes.rotate`]

Body (`extra="forbid"`): `{"staff_id": "s_guard01", "count": 4, "replace_existing": true, "actor":
"control-panel"}`; `staff_id` `^s_[0-9a-z_]{2,32}$`; `count` 1–10, default **4**; `replace_existing` default
true (drops this staff member's previous codes, including any in `edge/data/DEMO_CODES.txt`). All fields are
forwarded to cloud `POST /v1/admin/codes/rotate`. Response (flat; the edge never nests the cloud body):

```python
class RotateCodesResult(BaseModel):
    staff_id: str
    codes: list[dict]                 # [{code_id: "OVR-R1114125000-01" | null, code: "40718325"}]: plaintext, ONCE
    code_length: int | None           # fallback.staff_override.code_length (8); null = cloud reply omitted it (R-K)
    valid_until: str | None           # bundle expires_at + 24 h; null = cloud reply omitted it (R-K)
    one_time: Literal[True]
    dropped_code_ids: list[str]
    warning: str                      # the cloud's "Shown once: store these codes safely ..." text
    cloud_bundle_version: int | None  # null = the cloud reply lacked it (M2): "pending refresh"
    bundle: BundleRefresh             # with applied; codes work on this kiosk once applied is true
    warnings: list[str]
```

R-D: the codes are minted only by the cloud, which stores PBKDF2 hashes only. The edge never logs, persists or
caches the response. Once the cloud has minted, the edge **always** returns 200 with the codes, also when the
bundle pull fails (`applied: false` + warning), because a shown-once secret must never be lost. The kiosk shows them
once, with a copy button and a "store safely" warning, keeps them only in component state (never
`localStorage` / `sessionStorage` / URL / console), and clears them when the panel closes.

**Nullable minted fields (R-K, round 2)**: `codes[].code_id`, `code_length` and `valid_until` are nullable. When the
cloud reply omits them the edge emits `null` (never invents values) and the kiosk **still shows the codes once**,
with "unknown" / "pending refresh" in place of the missing fields. `codes[].code` is never null. Example
`minted_fields_unknown` (200, the three fields null, `bundle.applied: false`).

#### 3.18.5 `POST /v1/admin/bundle/refresh` → 200 [`edge.bundle.refresh`]

Body `{}` or none. Pull + verify + install the newest cloud bundle now (`refresh_bundle_now`), also used by the
register flow when a write reported `applied: false`. 200 body = `BundleRefresh` with `result` `installed` or
`not_modified` and `error: null`. Errors carry `installed_version`: `503 CLOUD_UNAVAILABLE` reason `OFFLINE`
(**forced** OFFLINE only), `NOT_CONFIGURED` (no `CLOUD_API_URL`) or `CLOUD_ERROR`; `409 INVALID_STATE` reason
`BUNDLE_REJECTED` (bad signature, older version or expired: the last valid bundle is kept, fail-secure).

**Connectivity OFFLINE (L3, as built in `edge/access.py` `refresh_route`)**: unlike the writes, a refresh is **not**
refused when the heartbeat reports OFFLINE. It is attempted unless the kiosk is **forced** OFFLINE (`POST
/v1/admin/mode`), because a manual refresh is the quickest way back once the network returns. If the pull then
fails (cloud still unreachable), the answer is `503 CLOUD_UNAVAILABLE` reason **`CLOUD_ERROR`**, not `OFFLINE`.
Kiosk (L3): the Control Panel's **"Refresh edge bundle"** control is enabled whenever the edge is reachable and the
kiosk is not forced OFFLINE, independent of whether editing is allowed (it stays enabled while the panel is read-only
because connectivity is OFFLINE).

#### 3.18.6 Error mapping and `reason` registry

Edge mapping of cloud admin calls (`edge/access.py` `cloud_admin`):

| Cloud outcome | Edge response |
|---|---|
| transport error, timeout, `401`, `5xx`, unreadable body | `503 CLOUD_UNAVAILABLE` reason `CLOUD_ERROR` (+ `cloud_status` when there was one); counts as a connectivity miss only for transport errors / 5xx |
| `404` **without** `error.reason`, or `405` | `503 CLOUD_UNAVAILABLE` reason `ENDPOINT_NOT_DEPLOYED` (the live cloud predates the route; redeploy) |
| `403` | `403 FORBIDDEN` reason `CLOUD_ADMIN_TOKEN` (the cloud refused `X-Admin-Token`; not the edge's own token) |
| other `4xx` | same status and `code`; `reason` forwarded verbatim; `cloud_status`, `cloud_code` added; `retry_after_s` from `Retry-After` |

| `reason` | HTTP · `code` | Routes |
|---|---|---|
| `OFFLINE` | 503 · `CLOUD_UNAVAILABLE` | writes: forced OFFLINE or connectivity OFFLINE · refresh: forced OFFLINE only (L3) |
| `NOT_CONFIGURED` | 503 · `CLOUD_UNAVAILABLE` | writes: no `CLOUD_API_URL` / cloud admin token · refresh: no `CLOUD_API_URL` |
| `CLOUD_ERROR` | 503 · `CLOUD_UNAVAILABLE` | writes, refresh (incl. a refresh attempted while connectivity is OFFLINE that fails) |
| `ENDPOINT_NOT_DEPLOYED` | 503 · `CLOUD_UNAVAILABLE` | writes |
| `CLOUD_ADMIN_TOKEN` | 403 · `FORBIDDEN` | writes |
| `UNKNOWN_ROLE` | 422 · `VALIDATION_ERROR` | PUT (edge pre-check + cloud) |
| `UNKNOWN_ZONE` | 422 · `VALIDATION_ERROR` | PUT (cloud) |
| `DISPLAY_REQUIRED`, `CONSENT_REQUIRED` | 422 · `VALIDATION_ERROR` | PUT (create) |
| `ERASED_IN_BUNDLE` | 409 · `INVALID_STATE` | PUT (ERASED, no consent), `POST /v1/enroll` |
| `USER_REVOKED` | 409 · `INVALID_STATE` / 403 · `FORBIDDEN` | PUT (consent without restore) / `POST /v1/enroll` |
| `SCHEDULE_CONFLICT` | 409 · `INVALID_STATE` | PUT, revoke, rotate (master CAS contention: retry) |
| `ALREADY_REVOKED` | 409 · `INVALID_STATE` | revoke |
| `UNKNOWN_USER` | 404 · `NOT_FOUND` | revoke |
| `BUNDLE_REJECTED` | 409 · `INVALID_STATE` | refresh |
| `NOT_IN_SCHEDULE`, `NO_BUNDLE`, `FACE_ENROLLED_OTHER`, `LOOK_MISMATCH` | 409 · `INVALID_STATE` | `POST /v1/enroll` |
| `FRAMES_REJECTED` | 422 · `VALIDATION_ERROR` | `POST /v1/enroll` |
| `NOT_ENROLLED` | 404 · `NOT_FOUND` | `DELETE /v1/enroll/{user_id}` |
| `NOT_DEMO_MODE` | 403 · `FORBIDDEN` | `POST /v1/admin/clock` |
| `CODES_UNAVAILABLE` | 503 · `CLOUD_UNAVAILABLE` | cloud rotate only (the edge reports it as `CLOUD_ERROR`) |

Request-model `422`s carry `details[]` and no `reason`. The kiosk maps `reason` (not `message`) to its hints:
e.g. `OFFLINE` → "New people can only be registered while ONLINE", `ERASED_IN_BUNDLE` → offer "Re-admit and
enrol", `USER_REVOKED` → "Restore first", `ENDPOINT_NOT_DEPLOYED` → "cloud redeploy pending",
`FACE_ENROLLED_OTHER` → "this face is already enrolled as someone else" (not "already enrolled under another
user_id" for every `INVALID_STATE`).

---

## 4. Cloud service API (AWS us-east-1)

All requests except `GET /v1/health` carry the cloud auth headers (§0). All responses include `X-Latency-Ms`
and `X-Server-Time`. Implementation: `cloud/app/` (FastAPI). Routes are in `routers/core.py` and
`routers/admin.py`; auth, size limit and metrics are in `middleware.py`.

**Sandbox and deployment (C10)**

- **Sandbox**: AWS Workshop Studio, **us-east-1 only**, role `WSParticipantRole`. Our IAM probe found
  Rekognition, DynamoDB, S3, KMS, SES, EC2, Lambda, API Gateway, IAM and CloudWatch all allowed.
- **Deployment** (approved by the operator, **deployed 2026-11-14 ~10:00 UTC**): EC2 t3.small behind an API
  Gateway HTTP API (`https://8c1yi8fjgj.execute-api.us-east-1.amazonaws.com`), DynamoDB, S3 with SSE-KMS and a
  1-day lifecycle rule, the Rekognition collection `hid-kiosk-users`, and SES email OTP. SES is in sandbox mode,
  so the recipient (the operator's verified address) must be verified. The deployed build is the ~09:55 UTC
  artifact; fixes made in the code since then (append-mode enrolment, optional `email`,
  `PUT /v1/admin/schedule/{kiosk_id}`) are live only after the lead redeploys (`cloud/SANDBOX.md` §0).
- **Rekognition** holds consenting team faces only, and they are deleted at teardown.
- **Production** would pin ap-south-1 (Mumbai) for DPDP data residency.

**Degraded paths**: every endpoint has one, and the local-first edge keeps working without any of them.

- A denied or failing AWS service returns `503 CLOUD_UNAVAILABLE`.
- `/v1/health` reports per-service status.
- Backends are switchable for local integration tests: `FACE_BACKEND=fake|rekognition`,
  `STORE_BACKEND=memory|dynamodb`, `EMAIL_BACKEND=fake|ses`, `BLOB_BACKEND`, `METRICS_SINK`.
- A request body over `MAX_BODY_BYTES` (6 MB) gives `413 PAYLOAD_TOO_LARGE`.

**S3 audit-frame upload is not implemented.** No attempt frame is uploaded for audit, online or offline. The bucket
(SSE-KMS, 1-day lifecycle rule) is used only for the Face Liveness reference/output (`OutputConfig`) and an optional
enrolment reference image, which is off by default (`ENROLL_STORE_REFERENCE=false`). The audit-frame design (online
only, DENY/STEP_UP only, SSE-KMS, 1-day expiry) is roadmap.

### 4.1 `POST /v1/match`

```python
from typing import Literal

from pydantic import BaseModel, Field


class MatchRequest(BaseModel):
    attempt_id: str
    kiosk_id: str                       # must equal X-Kiosk-Id (else 403 FORBIDDEN)
    image_b64: str                      # ~10 KB face crop of the sharpest frame (or of the early probe, §3.1a)
    mode: Literal["1:N", "1:1"] = "1:N"  # the edge sends 1:1 when claimed_user_id is set
    claimed_user_id: str | None = None  # required for 1:1 (CompareFaces vs enrolled reference)
    max_users: int = Field(default=2, ge=1, le=5)   # runner-up needed for the margin check


class MatchResponse(BaseModel):
    attempt_id: str
    matched: bool                       # top-1 similarity >= UserMatchThreshold (80) used in the call
    user_id: str | None                 # u_xxxx
    similarity: float | None            # 0-100 raw Rekognition similarity
    runner_up_user_id: str | None
    runner_up_similarity: float | None
    face_detected: bool
    source: Literal["rekognition", "arcface", "fake"]   # fake = FACE_BACKEND=fake (local tests); arcface reserved
    user_status: Literal["ACTIVE", "SUSPENDED", "REVOKED"] | None   # REVOKED if revoked in the cloud schedule
    latency_ms: int
```

Response 200:

```json
{"attempt_id": "att_01JDA3K7Q9V2M4N6P8R0S2T4V6", "matched": true, "user_id": "u_3c4d", "similarity": 99.6,
 "runner_up_user_id": null, "runner_up_similarity": null, "face_detected": true,
 "source": "rekognition", "user_status": "ACTIVE", "latency_ms": 402}
```

- **Implementation**: `SearchUsersByImage(CollectionId, Image.Bytes, UserMatchThreshold=80, MaxUsers=2,
  QualityFilter="AUTO")`, or `CompareFaces(SimilarityThreshold=80)` for 1:1.
- **Throttling**: one jittered retry within the edge budget, else `503 UPSTREAM_THROTTLED`.
- **Rekognition denied in the sandbox**: `503 CLOUD_UNAVAILABLE`.
- **Edge reaction**: on any non-200 or timeout (> `rekognition_timeout` 700 ms on the no-probe path, or
  > `rekognition_probe_deadline` 1500 ms from probe start with the early probe), the edge proceeds with the local
  match under OFFLINE rules (P7), when `match.rekognition.enabled` is true (§2 matcher-authority table). The edge
  uses only `user_id`, `similarity` and `runner_up_similarity`.
- **Measured round trip** (from the venue, 2026-11-14, cold connections): about 0.4–1.4 s, so with the 700 ms
  budget most online attempts are decided OFFLINE (P7) while the badge says ONLINE (`GET /v1/mode`
  `cloud_match.degraded`). The edge pre-opens the keep-alive connection at `session/start` and, with the early
  probe, starts the call at face lock.
- **Collection**: holds consenting team faces only and is deleted at teardown.

### 4.2 `GET /v1/schedule/{kiosk_id}`: signed offline bundle

The response body is the bundle itself, in `config/schedule.example.json` format, filtered to the kiosk's zone
and entitled users:

- **Top-level keys**: `format_version`, `bundle_version`, `issued_at`, `expires_at`, `issuer`, `timezone`,
  `scope`, `revocations_version`
- **Data keys**: `zones`, `kiosks`, `roles`, `exceptions`, `holidays`, `visitor_passes`, `users`, `revocations`,
  `override_codes`, `card_id_hash_scheme`
- **`signature`**

**Signature**: `{"alg": "HMAC-SHA256", "key_id": "demo-k1", "value": "<hex>", "canonicalization": "..."}`.
It is computed over the canonical JSON of the bundle **without** the `signature` key, with
`SCHEDULE_BUNDLE_HMAC_KEY` (hackathon). The production roadmap is **Ed25519**, so the kiosk holds only a
public key and a stolen kiosk cannot forge bundles. KMS/ECDSA is not used.

```python
import hashlib
import hmac
import json


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_bundle(bundle: dict, key: bytes, key_id: str = "demo-k1") -> dict:
    body = {k: v for k, v in bundle.items() if k != "signature"}
    sig = hmac.new(key, canonical(body), hashlib.sha256).hexdigest()
    return {**body, "signature": {"alg": "HMAC-SHA256", "key_id": key_id, "value": sig,
                                  "canonicalization": "json.dumps(bundle_without_signature, sort_keys=True, "
                                                      "separators=(',', ':'), ensure_ascii=False).encode('utf-8')"}}


def verify_bundle(bundle: dict, key: bytes) -> bool:
    sig = bundle.get("signature") or {}
    if sig.get("alg") != "HMAC-SHA256" or not isinstance(sig.get("value"), str):
        return False                                     # unsigned / unknown alg -> INVALID
    body = {k: v for k, v in bundle.items() if k != "signature"}
    expected = hmac.new(key, canonical(body), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig["value"])
```

Rules:

- **Caching**: `ETag` = `"<bundle_version>"` (also `X-Bundle-Version`). `If-None-Match` with that version gives
  `304`. A 304 counts as the cloud confirming the bundle: it resets the online freshness timer (`refresh_age_s`,
  D2). It does not extend offline validity. A kiosk may only fetch its own bundle (`403 FORBIDDEN`); an unknown
  kiosk gives `404 NOT_FOUND`.
- **Acceptance** (R6, `edge/offline/bundle.py`): the edge rejects a bundle with an invalid signature, a
  `kiosk_id` outside `scope.kiosk_ids`, a `bundle_version` lower than the current one, or the same version with
  an older `issued_at`. An equal version with a newer `issued_at` (re-sign) is accepted.
  - A rejected bundle raises a `BUNDLE_REJECTED` alert and **never replaces the last valid bundle (LVB)**.
  - The same applies to a bundle file changed on disk while the edge runs: the in-memory LVB stays in force.
- **Expiry**: `effective_expiry = min(expires_at, issued_at + 12 h)` (`cache.bundle_max_staleness_hours`).
  - The cache is INVALID only when there is no LVB, or on clock rollback (now < LVB `issued_at` − 300 s,
    `cache.clock_rollback_tolerance_s`).
  - No LVB → DENY `SCHEDULE_BUNDLE_INVALID` / CONTACT_DESK with `zone: "UNKNOWN"` (§2).
- **Signer** (R7): the cloud and `scripts/sign_bundle.py` stamp `issued_at = now` and `expires_at = now + 12 h`.
  They also set every override code's `valid_until = expires_at + 24 h` (§3.14).
- **Refresh**: the edge refreshes every `cache.bundle_refresh_interval_min` (15 min) online and at each sync.
  It runs `evaluate_schedule` on the newest valid bundle for both online and offline decisions (D2, R5). There is
  no per-attempt cloud schedule call.
- **Not in the bundle**: templates (the edge enrols locally; roadmap: encrypted template distribution) and TOTP
  secrets (provisioned at enrolment, stored encrypted on the edge). Card IDs appear only as
  `HMAC-SHA256(CARD_ID_PEPPER, card_id)` hashes; override codes only as PBKDF2 hashes.

### 4.3 `GET /v1/revocations?since=<revocation_seq>`

```json
{"as_of": "2026-11-14T04:58:00Z", "revocation_seq": 9,
 "items": [{"seq": 8, "type": "USER", "target_id": "u_3c4d", "revoked_at": "2026-11-14T04:41:00Z", "reason": "ADMIN"},
           {"seq": 9, "type": "CARD", "target_id": "d321eef09d98d6f2…", "revoked_at": "2026-11-14T04:50:00Z", "reason": "LOST"}]}
```

The edge polls this at each successful heartbeat and applies revocations immediately, so online decisions see
them within one heartbeat. On reconnect the edge applies revocations **before** replaying the sync queue.

- `type` is `USER`, `CARD`, `RULE`, `ERASE` or `READMIT` (v1.4). A `CARD` `target_id` is a card-ID hash: the edge
  refuses that card as a fallback factor at once (also when it comes from the bundle's own `revocations[]`).
- **`ERASE`** (reason `ERASED`, the cloud's DPDP erasure, `DELETE /v1/enroll/{user_id}`): the edge deletes the
  user's local face templates and TOTP secret (`USER_ERASED_LOCAL` event), once per ERASE event, and the user is
  suspended by the bundle's ERASED revocation. It is **not** a permanent deny entry in the overlay. A legacy
  `USER` item with reason `ERASED` is treated the same way.
- **`READMIT`** (v1.4; `revoked_at` = the event time, the field name is kept so every item has one shape):
  - reason `READMIT` (an ERASED user re-admitted with consent, §3.18.2, or a consented cloud enrolment): the edge
    drops the user's overlay entries with reason `ERASED` and `revoked_at` ≤ the event time, and clears the
    runtime's once-per-user erasure marker, so a later ERASE purges again. ADMIN / security entries stay.
  - reason `RESTORE` (R-C Restore): the edge drops **all** of the user's `USER` overlay entries with `revoked_at` ≤
    the event time.
  - An edge that never sees the READMIT (offline) keeps denying: fail-secure.

```json
{"as_of": "2026-11-14T12:50:00Z", "revocation_seq": 13,
 "items": [{"seq": 10, "type": "ERASE", "target_id": "u_prj1", "revoked_at": "2026-11-14T11:02:10Z", "reason": "ERASED"},
           {"seq": 11, "type": "READMIT", "target_id": "u_prj1", "revoked_at": "2026-11-14T12:45:00Z", "reason": "READMIT"},
           {"seq": 13, "type": "READMIT", "target_id": "u_a3b4", "revoked_at": "2026-11-14T12:50:00Z", "reason": "RESTORE"}]}
```
- Revocation is **time-aware**: it applies to attempts with t0 ≥ `revoked_at`.
- `SCHEDULE_REVOKED` takes precedence over every other schedule result (R16).
- Offline, revoked users are not matchable (`NOT_ENROLLED`, §2).
- A 404 (feed not deployed) is ignored; the bundle's own `revocations` still apply.

### 4.4 `POST /v1/sync`

The batch is idempotent. Each item is the `docs/SURPRISE_CHALLENGES.md` §SC2.5 record **exactly**, plus
`idempotency_key` and `hmac`. Edge implementation: `edge/offline/sync.py`; server:
`cloud/app/services/sync_service.py`. The edge also sends the batch id as the `Idempotency-Key` header. The
request is exempt from the replay cache, so an identical re-send of a batch whose ack was lost is safe (Y01).

```python
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class FallbackUsed(BaseModel):
    method: Literal["TOTP", "CARD", "EMAIL_OTP", "STAFF_OVERRIDE"]
    staff_id: str | None = None         # STAFF_OVERRIDE only
    code_id: str | None = None          # OVR-NNN; never the code / TOTP value
    totp_step: int | None = None        # TOTP only: accepted RFC 6238 time step (non-secret) -> cross-kiosk replay check (Y07)


class SyncItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attempt_id: str
    seq: int                            # per-kiosk monotonic
    kiosk_id: str                       # must equal the batch kiosk_id (else rejected KIOSK_MISMATCH)
    zone: str                           # "UNKNOWN" when there was no last valid bundle
    ts_utc: datetime
    user_id: str | None
    candidate_user_id: str | None       # top-1 on BIO_FAIL (targeted-spoof alerts); never displayed
    decision: Literal["ALLOW", "STEP_UP", "DENY"]
    reason_codes: list[str]
    resolved_codes: list[str]
    scores: dict[str, float | None]     # 2-dp projection: pad, flash, flash_amp, moire, device, match, margin, rek, rek_runner_up
    fallback: FallbackUsed | None
    schedule_version: int | None
    cache_state: Literal["FRESH", "EXPIRED", "INVALID"] | None
    mode: Literal["ONLINE", "OFFLINE"]
    prev_hash: str
    record_hash: str                    # SHA256(prev_hash || canonical_json(record))
    idempotency_key: str                # == attempt_id
    hmac: str                           # HMAC-SHA256(KIOSK_HMAC_KEY, canonical item JSON without "hmac")


class TombstoneItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["TOMBSTONE"]
    count: int
    first_seq: int
    last_seq: int
    chain_head: str
    hmac: str


class SyncRequest(BaseModel):
    kiosk_id: str                       # must equal X-Kiosk-Id (else 403 FORBIDDEN)
    batch_id: str                       # b_<ULID>
    chain_head: str                     # record_hash of the last item in this batch
    chain_head_hmac: str                # HMAC-SHA256(KIOSK_HMAC_KEY, chain_head)
    kiosk_now_utc: datetime | None = None   # edge wall clock at send time -> ALERT_CLOCK_SKEW if > 120 s off
    items: list[TombstoneItem | SyncItem] = Field(max_length=50)   # sync.batch_size


class Rejected(BaseModel):
    idempotency_key: str | None
    error: Literal["HMAC_INVALID", "VALIDATION_ERROR", "KIOSK_MISMATCH"]


class Flag(BaseModel):
    attempt_id: str                     # tombstones: "TOMBSTONE:<first_seq>-<last_seq>"
    type: Literal["POST_HOC_REVOKED", "SCHEDULE_CHANGED", "RECORDS_PURGED_UNSYNCED"]


class SyncResponse(BaseModel):
    accepted: list[str]                 # idempotency keys newly stored
    duplicates: list[str]               # already stored (same content, or a conflict kept server-side): safe to purge
    rejected: list[Rejected]
    flags: list[Flag]
    server_time: datetime
```

Request:

```json
{"kiosk_id": "KIOSK_SRV_01", "batch_id": "b_01JDA4B6D8F0H2K4M6P8R0T2V4", "chain_head": "a83d27c4…",
 "chain_head_hmac": "1f9be0d2…", "kiosk_now_utc": "2026-11-14T04:58:40Z",
 "items": [{"attempt_id": "att_01JDA3R5T7V9X1Z3B5D7F9H1K3", "seq": 1042, "kiosk_id": "KIOSK_SRV_01",
            "zone": "SERVER_ROOM", "ts_utc": "2026-11-14T04:40:00Z", "user_id": "u_7a8b",
            "candidate_user_id": null, "decision": "ALLOW",
            "reason_codes": ["OFFLINE_MODE", "FALLBACK_OK", "ACCESS_OK"],
            "resolved_codes": ["OFFLINE_HIGH_RISK_ZONE"],
            "scores": {"pad": 0.91, "flash": 0.80, "match": 0.69, "margin": 0.33},
            "fallback": {"method": "TOTP", "staff_id": null, "code_id": null, "totp_step": 59821030},
            "schedule_version": 42, "cache_state": "FRESH", "mode": "OFFLINE",
            "prev_hash": "5f0c9a1e…", "record_hash": "a83d27c4…",
            "idempotency_key": "att_01JDA3R5T7V9X1Z3B5D7F9H1K3", "hmac": "5d2c81aa…"}]}
```

Response 200:

```json
{"accepted": ["att_01JDA3R5T7V9X1Z3B5D7F9H1K3"], "duplicates": [], "rejected": [], "flags": [],
 "server_time": "2026-11-14T04:58:41Z"}
```

`?verbose=true` (dashboard/debug) adds `batch_id`, `kiosk_id`, `conflicts[]`, `alerts[]`, `acks[]` (per item:
`ACCEPTED|DUPLICATE|CONFLICT|REJECTED` + `verdict`) and per-item rejection `detail`. Batch-level errors:
`403 FORBIDDEN` (batch `kiosk_id` ≠ `X-Kiosk-Id`, unknown kiosk) and `422 VALIDATION_ERROR` (no `items[]`,
> 50 items, body not a JSON object).

**Server behaviour**

- **Storage**: DynamoDB conditional put (`STORE_BACKEND=dynamodb`); `memory` for local tests. Decisions expire
  after `DECISIONS_TTL_DAYS` (7).
- **Duplicates**: same `attempt_id` with the same content → `duplicates` (not an error).
- **Conflicts**: same `attempt_id` with different content → also acknowledged in `duplicates`, so the edge
  purges it. The server keeps both versions and raises `ALERT_SYNC_CONFLICT`; `verbose` lists it in `conflicts`.
- **Item checks**: every item `hmac` must verify (`SYNC_REQUIRE_ITEM_HMAC`, default on), else `HMAC_INVALID`.
  Items over 8 KB, long strings or long numeric arrays are rejected (`VALIDATION_ERROR`): images and embeddings
  can never enter the ledger.
- **Integrity**: the server verifies `record_hash`, chain continuity and `chain_head_hmac`. A break raises
  `ALERT_LOG_TAMPER`, and the records are still ingested.
- **Re-evaluation**: every offline ALLOW is re-evaluated against the authoritative schedule and revocations at
  `ts_utc` (skew-corrected). The resulting flags map to SC2.6 alerts:

  | Flag | SC2.6 alert |
  |---|---|
  | `POST_HOC_REVOKED` | `ALERT_REVOKED_USER_ADMITTED` |
  | `SCHEDULE_CHANGED` | `ALERT_SCHEDULE_MISMATCH` |
  | `RECORDS_PURGED_UNSYNCED` (tombstone) | `ALERT_RECORDS_PURGED_UNSYNCED` |

- **Alerts without a flag**: `ALERT_TOTP_REPLAY` (same user + `totp_step` accepted on two attempts),
  `ALERT_OVERRIDE_USED` / `ALERT_OVERRIDE_REUSE`, `ALERT_OFFLINE_POLICY_VIOLATION` (offline auto-ALLOW in a
  high-risk zone), `ALERT_TARGETED_SPOOF`, `ALERT_SPOOF_BURST` (≥ 3 offline SPOOF/INJECTION DENYs in 10 min),
  `ALERT_CLOCK_SKEW`. They are visible via `verbose` and `GET /v1/admin/alerts`.
- **Online mode** uses the same endpoint: while ONLINE, the edge sync loop pushes whenever the queue is
  non-empty.

**Edge-side retention**

- Records are purged on ack (`accepted` or `duplicates`).
- Unsynced records are purged at **24 h**, leaving a tombstone that is synced later. There is no separate 72 h
  queue cap.
- `rejected` records stay until the 24 h purge.
- The template cache has a max age of 72 h.

### 4.5 `POST /v1/otp/send`

Request:

```json
{"attempt_id": "att_01JDA3M2C8D4F6H8J0K2M4N6P8", "user_id": "u_1a2b", "channel": "email"}
```

Response 201:

```json
{"otp_id": "otp_8HK2", "channel": "email", "destination_masked": "a*****@pes.edu",
 "expires_at": "2026-11-14T04:42:12Z", "resend_after_s": 30, "code_length": 6}
```

- SES only: SMS to India is blocked by TRAI DLT.
- In the SES sandbox, the recipient must be verified.
- If SES is denied or fails → `503 CLOUD_UNAVAILABLE`, and the kiosk offers the other methods.
- The edge calls this only through `POST /v1/attempt/{id}/otp/send` (§3.5).

### 4.6 `POST /v1/otp/verify`

Request:

```json
{"otp_id": "otp_8HK2", "attempt_id": "att_01JDA3M2C8D4F6H8J0K2M4N6P8", "code": "551204"}
```

Response 200:

```json
{"otp_id": "otp_8HK2", "verified": true, "attempts_remaining": 2}
```

- The code is stored hashed, with TTL 300 s (`fallback.email_otp.ttl_s`) and single use.
- The cloud allows 3 verify attempts, but the edge's `stepup.max_attempts_per_step` = 2 governs the kiosk flow.
- The response may add `reason` (e.g. expired / used) when `verified` is false.
- Edge handling (`edge/cloud_client.py` `otp_verify`, §3.4): `401`, `429`, any `5xx`, a transport error, a timeout
  (3 s) or a 200 body without a boolean `verified` = **cloud unavailable** (EMAIL_OTP dropped, not counted). Any
  other non-200 (other 4xx, e.g. unknown / expired / used `otp_id`) = `verified: false` (counted).

### 4.7 `POST /v1/liveness/session`: Rekognition Face Liveness step-up (optional)

Request:

```json
{"attempt_id": "att_01JDA3M2C8D4F6H8J0K2M4N6P8", "kiosk_id": "KIOSK_MAIN_01", "user_id": "u_1a2b",
 "challenge": "FaceMovementAndLightChallenge"}
```

Response 201:

```json
{"session_id": "4f1c2b7e-9a0d-4c55-8f3e-2d1b6a7c9e10", "region": "us-east-1", "expires_at": "2026-11-14T04:38:12Z"}
```

- **Kiosk side**: renders `<FaceLivenessDetector sessionId region="us-east-1">`, which needs a Cognito Identity
  Pool unauth role; the sandbox may deny it.
- **Result**: `GET /v1/liveness/session/{session_id}/result`:

  ```json
  {"session_id": "4f1c2b7e-9a0d-4c55-8f3e-2d1b6a7c9e10", "status": "SUCCEEDED", "confidence": 93.4, "live": true,
   "compare_similarity": 99.1, "verified": true}
  ```

- **Verification**: `verified = confidence ≥ challenge.face_liveness_min_confidence (80) AND CompareFaces(reference
  image vs enrolled) ≥ 99`.
- **Edge use**: designed as an alternative to the CHALLENGE step (pass → R2/R3; fail → DENY `CHALLENGE_FAILED`).
  It is **not wired into the edge or kiosk step-up flow today**: the cloud routes exist, and the cloud can
  require a verified session for enrolment (`liveness_session_id`). It is **never on the 2 s path**.
- **Session**: single-use, expires after 3 min, uses `KmsKeyId` + S3 `OutputConfig` when KMS/S3 are permitted.
  Default service quotas apply.

### 4.8 Other cloud endpoints

| Endpoint | Purpose |
|---|---|
| `GET /v1/health` (public, no auth) | Cached health snapshot; see the example below. Per-service values come from a background probe (`ok`, `error`, `creds_expired`, `timeout`, `unknown`, …). `status` is `degraded` when Rekognition or the store is failing. Used by the edge connectivity monitor (timeout `connectivity.heartbeat_timeout_ms` = 2000 ms; any HTTP 200 counts as a heartbeat success). `/health` is an alias. |
| `POST /v1/enroll` | `multipart/form-data` (`meta` + `frame_N`) or JSON with `images_b64[]` (≤ 10). Meta: `user_id`, `display_name`, `email` (**required in the deployed build**; optional in the tree code: without it EMAIL_OTP is unavailable for the user), `groups[]`, `role` (optional, `^[a-z_]{1,32}$`: echoed as `requested_role`, **never applied**), `consent: true`, `consent_version`, `card_id` / `card_id_hash`, `provision_totp` (cloud default false), `totp_enrolled` (optional bool, wins over `provision_totp`: the cloud only records `fallback.totp_enrolled` in the schedule, it never mints a seed), optional `liveness_session_id` (must be a verified Face Liveness session, else 403). Runs `IndexFaces` ×N → `CreateUser` → `AssociateFaces`. Re-enrolment: the deployed build replaces the user's faces; the tree code **appends** (≤ 24 faces per user, first 5 pinned, frames that do not match the enrolled user → `409 INVALID_STATE`, existing faces kept). Returns 201 `{user_id, rekognition_user_id, face_ids[], faces_indexed, frames_rejected, template_version, local_cache_updated, schedule_entitlement, bundle_version, totp_seed_persisted, destination_masked, totp_provisioning_uri, schedule_role, requested_role, role_applied, readmitted}` (`cloud/app/schemas.py` `EnrollResponse`): `schedule_role` = the signed schedule's role (null = not in the schedule yet), `requested_role` = meta `role` echoed, `role_applied` = true only when the schedule role already equals `requested_role` (enrolment never changes a role), `readmitted` = this consented enrolment lifted an ERASED suspension (feed `READMIT` reason `READMIT`, §4.3); `totp_provisioning_uri` is always null (the edge owns TOTP secrets). Templates stay on the edge. Rekognition unavailable → `503 CLOUD_UNAVAILABLE` (edge sets `cloud_indexed: false`). |
| `DELETE /v1/enroll/{user_id}` | Erasure (DPDP): Rekognition `DeleteUser` + `DeleteFaces`, deletes records, emits an `ERASE` feed event (§4.3; the schedule entry stays, suspended by an ERASED revocation). Idempotent. Returns `{user_id, erased, rekognition_user_deleted, faces_deleted, revocation_seq, bundle_version}`. |
| `POST /v1/schedule/check` | Authoritative single-user SC1 check `{user_id, zone?, t0?}` → `{user_id, zone, result, bundle_version, revocations_version, evaluated_at, evaluator}`, using the same evaluator as the edge. **Diagnostic only: the edge never calls it** (R5: no per-attempt cloud schedule call). |

Cloud health example:

```json
{"status": "ok", "rekognition": "ok", "dynamodb": "ok", "region": "us-east-1", "store": "dynamodb:ok",
 "face_backend": "rekognition", "email_backend": "ses", "policy": "ok", "version": "0.1.0", "uptime_s": 5120,
 "server_time": "2026-11-14T05:10:00Z", "checked_at": "2026-11-14T05:09:55Z"}
```

### 4.9 Cloud admin endpoints (kiosk HMAC + `X-Admin-Token`)

These are used by the operator dashboard and the demo script, never by the edge decision path. A missing or
wrong `X-Admin-Token` gives `403 FORBIDDEN`.

| Endpoint | Purpose |
|---|---|
| `GET /v1/admin/schedule` | Current authoritative schedule document `{version, published_at, doc}` |
| `PUT /v1/admin/schedule` | Replace the schedule document → `{bundle_version}`; invalid → `422` |
| `PUT /v1/admin/schedule/{kiosk_id}` | **(in the code, not deployed until the redeploy)** Upload an operator-signed bundle (`scripts/sign_bundle.py` output, as-is). Verified: HMAC-SHA256 with the bundle key (else 403), kiosk in `kiosks{}` and `scope.kiosk_ids` (403), `bundle_version` strictly greater than the stored one (409; an identical re-upload → 200 unchanged), not expired and no publicly documented override codes (422). Then served verbatim by `GET /v1/schedule/{kiosk_id}` with ETag `"<bundle_version>"`. This is how v46+ with fresh codes replaces v45. |
| `POST /v1/admin/revocations` | `{type: USER\|CARD, target_id, reason, revoked_at?, force?, actor?}` → 201. Demo step "revoke Priya during the outage". v1.4 details in §4.9a. |
| `GET /v1/admin/users` · `PUT /v1/admin/users/{user_id}/access` · `POST /v1/admin/codes/rotate` · `GET /v1/admin/audit` | Control Panel access administration (v1.4, §4.9a). **(in the code, not deployed until the redeploy)** |
| `GET /v1/admin/alerts?since=&limit=` | SC2.6 alerts (`ALERT_*`) |
| `GET /v1/admin/decisions?kiosk_id=&limit=` | Synced decision ledger, with server verdicts |
| `GET /v1/admin/stats` | Aggregates over the synced decision ledger (synthetic test traffic excluded unless `?include_synthetic=true`) |
| `GET /v1/admin/metrics` | Request/decision metrics (in-memory sink only) |
| `PUT /v1/admin/users/{user_id}/contact` | Contact-only user record `{display_name, email, consent: true, consent_version}` (no biometrics), for an OTP smoke test before enrolment |
| `GET /v1/admin/fake/outbox` | Last 20 e-mails (only with `EMAIL_BACKEND=fake`; else `404 NOT_FOUND`) |

`PUT /v1/admin/users/{user_id}/contact`: `display_name` is 1–80 characters (R-H, v1.4; was 64); `consent_version` 1–40 characters (R-N, round 2; the code had 32).

### 4.9a Cloud access administration (v1.4; called by the edge proxies of §3.18)

Auth: kiosk HMAC (`401`) + `X-Admin-Token` = `CLOUD_ADMIN_TOKEN` (`403 FORBIDDEN`). The cloud records the calling
`kiosk_id` and the forwarded `actor` in every audit entry. Domain errors carry `error.reason` (§3.18.6); a `404`
for an unknown user carries `reason: "UNKNOWN_USER"` so the edge can tell it from a missing route. Field limits
are §3.18's (R-H): `user_id ^u_[0-9a-z]{4}$` on these routes, `staff_id ^s_[0-9a-z_]{2,32}$`, `display` 1–80,
written times 00:00–23:59 with end > start. Examples: routes `cloud.*` in
`docs/contracts/admin_access.examples.json`.

- **`GET /v1/admin/users`** → 200 `{as_of, bundle_version, published_at, timezone, roles{name: {zones,
  windows}}, zones{name: {risk, requires_explicit_grant}}, kiosks{id: {zone, label}}, staff_ids[], users[]}`.
  Each user: `{user_id, display, role, in_schedule, status, revoked_at, revoked_reason, zones_add, zones_remove,
  extra_windows, valid_from, valid_until, fallback{totp_enrolled, card}, enrolled, faces, consent_version}`.
  `status` ∈ `ACTIVE | REVOKED | ERASED | NOT_IN_SCHEDULE` (replaces the v1.3 code's `revoked` / `erased`
  booleans; REVOKED wins). Users = master ∪ cloud enrolment store. No card hashes, no secrets, no faces.
- **`PUT /v1/admin/users/{user_id}/access`** → 200. Body = §3.18.2 `AccessUpdate` (same fields, `extra="forbid"`,
  as forwarded by the edge). State rules = the §3.18.2 table. Every change publishes a new `bundle_version`
  (re-signed on the next `GET /v1/schedule`, `issued_at = now`) and writes an audit entry (`USER_CREATE`,
  `ACCESS_UPDATE`, `READMIT`, `RESTORE`). Response:
  `{user_id, bundle_version, created, unchanged, readmitted, restored, previous_role, role, user{display, role,
  zones_add, zones_remove, extra_windows, valid_from, valid_until, status, revoked_at, revoked_reason,
  fallback{totp_enrolled, card}}, changed_at, warnings[]}` (`changed_at` null when `unchanged`). Errors: `422`
  (`details` in `message`, or reason `UNKNOWN_ROLE`, `UNKNOWN_ZONE`, `DISPLAY_REQUIRED`, `CONSENT_REQUIRED`),
  `409` (`ERASED_IN_BUNDLE`, `USER_REVOKED`, `SCHEDULE_CONFLICT`).
- **`POST /v1/admin/revocations`** → 201 `{seq, type, target_id, revoked_at, reason, bundle_version}`. v1.4:
  USER `target_id` must match `^u_[0-9a-z]{4}$`; `reason` `^[A-Z][A-Z_]{1,31}$` and **not** `ERASED` (only
  `DELETE /v1/enroll` creates an erasure); unknown user without `force` → `404` `UNKNOWN_USER`; a user that
  already holds a non-ERASED USER revocation → `409` `ALREADY_REVOKED` (no new seq).
- **`POST /v1/admin/codes/rotate`** → 201, `Cache-Control: no-store`. Body `{staff_id, count (1–10, default 4),
  replace_existing (default true), actor?}`. Response `{staff_id, bundle_version, codes[{code_id, code}],
  dropped_code_ids[], code_length, valid_until, one_time: true, warning}`. Plaintext exists only in this response
  (PBKDF2 hashes in the master; never logged). Documented fixture codes are dropped on every publish. `503
  CLOUD_UNAVAILABLE` reason `CODES_UNAVAILABLE` when the documented-code list is missing from the build (fail
  secure: a minted code could never work).
- **`GET /v1/admin/audit?limit=1..500&user_id=`** → 200 `{as_of, count, items[{ts_utc, action, kiosk_id, actor,
  ...detail}]}` (never code values).

---

## 5. Endpoint summary

| Service | Method & path | Purpose | Auth | Offline |
|---|---|---|---|---|
| Edge | `POST /v1/session/start` | attempt_id, nonce, flash sequence (+ PASSIVE depth job) | — | ✔ |
| Edge | `POST /v1/attempt/{id}/probe` | early cloud probe: face-lock frame, starts the Rekognition match (202) | — | ✔ (`cloud: skipped`) |
| Edge | `POST /v1/attempt/{id}/frames` | main decision (DecisionResponse) | — | ✔ |
| Edge | `POST /v1/attempt/{id}/challenge` | step-up challenge result | — | ✔ |
| Edge | `POST /v1/attempt/{id}/fallback` | TOTP / CARD / EMAIL_OTP / STAFF_OVERRIDE | — | ✔ (no EMAIL_OTP) |
| Edge | `POST /v1/attempt/{id}/otp/send` | send email OTP via cloud | — | ✘ (503) |
| Edge | `POST /v1/attempt/{id}/rendered` | client face-lock → rendered beacon | — | ✔ |
| Edge | `GET /v1/attempt/{id}` | latest DecisionResponse | — | ✔ |
| Edge | `GET /v1/events` | SSE: `decision` + `rendered` events | localhost | ✔ |
| Edge | `GET /v1/health` | models, PAD self-test, DepthProbe status | — | ✔ |
| Edge | `GET /v1/mode` | connectivity, bundle, cache, queue, demo clock | — | ✔ |
| Edge | `POST /v1/admin/mode` | force OFFLINE / AUTO (immediate) | admin | ✔ |
| Edge | `GET /v1/admin/store` · `POST /v1/admin/sync` | SC2 store view · sync now | admin | ✔ · ✘ (503) |
| Edge | `GET /v1/admin/users` | enrolled-user list (no templates) | admin | ✔ |
| Edge | `GET /v1/admin/access/users` | Users & Access table: cloud master + bundle + local enrolment (§3.18.1) | admin | ✔ (read-only, bundle) |
| Edge | `PUT /v1/admin/access/users/{user_id}` | create / edit / re-admit / restore a schedule entry (§3.18.2) | admin | ✘ (503 `OFFLINE`) |
| Edge | `POST /v1/admin/access/users/{user_id}/revoke` | USER revocation → `SCHEDULE_REVOKED` (§3.18.3) | admin | ✘ (503 `OFFLINE`) |
| Edge | `POST /v1/admin/access/codes/rotate` | one-time staff override codes, shown once (§3.18.4) | admin | ✘ (503 `OFFLINE`) |
| Edge | `POST /v1/admin/bundle/refresh` | pull + verify + install the newest bundle now (§3.18.5) | admin | ✘ (503) |
| Edge | `GET /v1/admin/attempt/{id}/signals` | raw-signal debug view | admin | ✔ |
| Edge | `POST /v1/admin/rate-limit/reset` | clear lockout counter | admin | ✔ |
| Edge | `POST` · `DELETE /v1/admin/eval/context` | tag / untag eval attempts | admin | ✔ |
| Edge | `POST /v1/admin/clock` | demo clock (`DEMO_MODE=1` only) | admin | ✔ |
| Edge | `POST /v1/admin/random-challenge` | random challenge `AUTO` / `FORCE` / `FORCE_NEXT` / `OFF` (`DEMO_MODE=1` only) | admin | ✔ |
| Edge | `POST /v1/enroll` · `DELETE /v1/enroll/{user_id}` | enrolment (bundle users only) / erasure | admin | ✔ (`cloud_state: skipped_offline` / cloud erasure `queued`) |
| Edge | `GET /v1/metrics` | dashboard metrics | localhost | ✔ |
| Edge | `GET /v1/depth/pending` · `POST /v1/depth/frames` | DepthProbe long-poll · depth upload (also on `0.0.0.0:EDGE_LAN_PORT`) | `X-Depth-Token` + `depth_nonce` | ✔ |
| Cloud | `POST /v1/match` | Rekognition 1:N / 1:1 | kiosk HMAC | — |
| Cloud | `GET /v1/schedule/{kiosk_id}` | signed bundle (ETag / 304) | kiosk HMAC | — |
| Cloud | `GET /v1/revocations` | revocation feed since seq | kiosk HMAC | — |
| Cloud | `POST /v1/sync` | idempotent decision ingest | kiosk HMAC | — |
| Cloud | `POST /v1/otp/send` · `POST /v1/otp/verify` | SES email OTP | kiosk HMAC | — |
| Cloud | `POST /v1/liveness/session` · `GET …/result` | Face Liveness step-up (optional) | kiosk HMAC | — |
| Cloud | `GET /v1/health` | heartbeat | public | — |
| Cloud | `POST /v1/enroll` · `DELETE /v1/enroll/{user_id}` | enrolment · erasure | kiosk HMAC | — |
| Cloud | `POST /v1/schedule/check` | diagnostic SC1 check (not called by the edge) | kiosk HMAC | — |
| Cloud | `/v1/admin/*` (§4.9, §4.9a) | schedule (+ per-kiosk signed-bundle upload), revocations, users / access / code rotation / audit, alerts, decisions, stats, metrics, contact, fake outbox | kiosk HMAC + admin | — |

**Removed in v1.1 (must not be implemented or referenced)**:

- the YAML key `latency_budget_ms.schedule_check_timeout`: **removed** (not in `config/thresholds.yaml`, not read by
  `edge/` or `cloud/app/`; only stale build copies under `cloud/infra/build/` still list it; no per-attempt cloud schedule call since v1.1, R5). The cloud budgets are `rekognition_timeout` and
  `rekognition_probe_deadline`.

- `/v1/authenticate`, `/v1/challenge` (top-level), `/v1/stepup`, `/v1/fallback/verify`, `/v1/enrol`, `/v1/attempts/{id}`
- `/status`, `/admin/connectivity` (use `/v1/mode` and `/v1/admin/mode`)
- `/v1/sync/decisions` (use `/v1/sync`)
- the `X-Eval-Label` header
- the Record3D depth bridge `http://127.0.0.1:8765/v1/depth/checks`
