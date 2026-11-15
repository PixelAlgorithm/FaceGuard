# edge/ - local edge service (FastAPI): perception layer + API

Local-first: liveness + local face match + policy decision run on the kiosk laptop and work
offline. `edge/policy/` and `edge/offline/` are owned by the policy-engine; everything else here
is perception + API glue. Thresholds come only from `config/thresholds.yaml`.

## 1. Start (from the project root)

```bash
bash scripts/fetch_models.sh                      # once: weights + PAD fixtures -> models/ (SHA-256 pinned)
edge/.venv/bin/python -m uvicorn edge.app:app --host 127.0.0.1 --port 8000
```

Startup takes about 1.5 s on the M4 laptop. It loads and warms every model, runs the mandatory
MiniFASNet self-test (section 4), loads the encrypted template cache and starts the policy-engine's
`PolicyRuntime` (`edge/policy/runtime.py`, signed bundle `edge/data/bundle.signed.json`). It then
logs `edge ready: ... pad_self_test=True runtime=real lan_port=8001`.

Fail-secure: if the runtime cannot be imported or constructed, `FailSecureRuntime` is used instead.
It answers every attempt with DENY `SYSTEM_ERROR`, and `/v1/health` `detail.policy_runtime` reports
`fail_secure`. There is no permissive fallback policy.

With `EDGE_LAN_PORT=8001` set in `.env`, a second listener on `0.0.0.0:8001` serves **only**
`GET /v1/depth/pending` and `POST /v1/depth/frames` for the DepthProbe iPhone app (section 6). The
edge binds this socket itself, so a busy port is logged (`detail.lan_listener = bind_failed`) and
the kiosk API on 127.0.0.1:8000 keeps running.

## 2. Smoke test (curl)

```bash
bash scripts/smoke_edge.sh        # health -> session/start -> 5 frames + meta -> decision -> nonce replay (409)
```

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

## 3. Enrol a face (admin)

Send `POST /v1/enroll` as multipart: `frame_0..frame_4` (JPEG, slight pose variation) plus a
`meta` JSON string, with header `X-Admin-Token: $ADMIN_TOKEN`. It works offline (local gallery).

```bash
curl -s -X POST http://127.0.0.1:8000/v1/enroll -H "X-Admin-Token: $ADMIN_TOKEN" \
  -F frame_0=@f0.jpg -F frame_1=@f1.jpg -F frame_2=@f2.jpg -F frame_3=@f3.jpg -F frame_4=@f4.jpg \
  -F 'meta={"user_id":"u_3c4d","display_name":"Priya N.","consent":true,"consent_version":"2026-11-14.v1","card_id":"CARD-1234","provision_totp":true}'
```

- Every frame must pass the edge quality checks and passive PAD (`liveness.pad.pass_min`) with no
  phone, laptop or TV around the face. At least `quality.min_usable_frames` frames must pass.
- The frames must be one identity: the minimum pairwise cosine must be at least
  `match.local.allow_min_cosine`. A face already enrolled under a different `user_id` is refused (409).
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
  `ERASED_IN_BUNDLE`, `FACE_ENROLLED_OTHER`, `LOOK_MISMATCH` (409), `FRAMES_REJECTED` (422). `totp_active` is
  true only when this edge holds the TOTP secret AND the bundle marks `fallback.totp_enrolled`; otherwise a
  warning says TOTP is not active yet (the kiosk must not say "Scan now").
- Revocations: an ADMIN / security revocation gives `403 FORBIDDEN`. A DPDP erasure (`reason: ERASED`) does
  not block a re-enrolment once the cloud has re-admitted the user to the schedule. While the bundle itself
  still carries the erasure, the answer is `409` with `reason: ERASED_IN_BUNDLE`. A successful re-enrolment
  clears the stale ERASED revocation-feed entry (`reinstated_after_erasure: true`).
- Cloud (ONLINE only): the accepted frames go to cloud `POST /v1/enroll`. `cloud_state` is `indexed`,
  `failed`, `skipped_offline` or `not_configured`. Any state other than `indexed` adds a `warnings[]` entry:
  while ONLINE, Rekognition is authoritative, so an un-indexed user is NOT_ENROLLED online. Nothing is
  retried later. After `indexed`, the edge installs the newly signed bundle at once (`bundle_version`). The
  cloud's own `totp_provisioning_uri` is stripped from `cloud.body`, so the browser sees exactly one TOTP
  secret (the edge's). `provision_totp` is forwarded only when this edge holds a TOTP secret for the user.
- TOTP is provisioned by `PolicyRuntime.provision_totp`, and the secret is held in its encrypted credential
  store. `GET /v1/admin/users` `totp_local` reads that store.
- `DELETE /v1/enroll/{user_id}` erases the user (DPDP; `user_id` pattern, else 422). Every key is always
  present: `{user_id, local_removed, cloud: deleted | queued | not_configured | failed, cloud_status, message, bundle}`.
  OFFLINE or a failed cloud call: the local data is erased now and the cloud erasure is persisted by
  `PolicyRuntime.queue_cloud_erasure` (edge/offline) and replayed at sync (R-J, `queued`;
  `pending_cloud_erasures[]` in the access list). `failed` (M1) = the local erasure queue could not be
  written (e.g. disk error) or the runtime has none: the local template IS erased, the cloud erasure did not
  happen; retry while ONLINE (honest, never `queued`). Write responses (M2) may carry `cloud_bundle_version` /
  `revoked_at` / `seq` = null when the follow-up pull failed (`bundle.applied` false). Nothing enrolled and no cloud: `404 NOT_FOUND` reason `NOT_ENROLLED`.
- `GET /v1/admin/users` lists the enrolled users. `role` / `display_name` / `bundle_role` / `bundle_display`
  come from the verified bundle and are authoritative. `template_role` / `template_display_name` are the
  labels stored with the template. `in_schedule: false` means the user is not in the bundle.

## 3a. Users & Access (control panel proxies, `X-Admin-Token`): API v1.4

The canonical contract is `docs/API.md` v1.4 §3.18 (+ §3.15 enrolment) and the machine-readable examples in
`docs/contracts/admin_access.examples.json`. Models: `edge/access_models.py` (request models validate; response
models are `extra="forbid"`). Handlers: `edge/access.py`. `edge/tests/test_contract_admin_access.py` validates
every edge example against those models AND replays every example (valid + error) through the handlers
against a contract-shaped fake cloud (`edge/tests/contract_cloud.py`).

| Edge route | Cloud call | Notes |
|---|---|---|
| `GET /v1/admin/access/users` | `GET /v1/admin/users` | `AccessUsersResponse`: top-level `roles[]`, `role_defaults{role:{zones,windows}}`, `zones{}`, `staff_ids[]`, `pending_cloud_erasures[]`, `users[AccessUser]` (`status`, `bundle_role`, `in_bundle`, `today{...}` object). Offline / cloud error: `source: "bundle"`, `read_only: true`, `read_only_code` (`OFFLINE`, `NOT_CONFIGURED`, `CLOUD_ERROR`, `ENDPOINT_NOT_DEPLOYED`, `CLOUD_ADMIN_TOKEN`). Only 401 is an error. |
| `PUT /v1/admin/access/users/{user_id}` | `PUT /v1/admin/users/{user_id}/access` | Create (`display` + `consent: true`), update, re-admit an ERASED user (`consent: true`, R-B), restore a REVOKED one (`consent` + `restore`, R-C). Returns `{created, unchanged, readmitted, restored, previous_role, role, cloud_bundle_version, bundle, user, warnings}`. |
| `POST /v1/admin/access/users/{user_id}/revoke` | `POST /v1/admin/revocations` `{type: USER, target_id, reason, actor?}` | Body optional, `reason` default `ADMIN`, `ERASED` refused (422). |
| `POST /v1/admin/access/codes/rotate` | `POST /v1/admin/codes/rotate` | Body `{staff_id ^s_[0-9a-z_]{2,32}$, count 1..10 (default 4), replace_existing (default true), actor?}`. The codes come back **flat** (`codes[{code_id, code}]`), once, `Cache-Control: no-store`, also when the bundle pull failed (`applied: false` + warning). Never logged or stored. |
| `POST /v1/admin/bundle/refresh` | `GET /v1/schedule/{kiosk}` (`refresh_bundle_now`) | `BundleRefresh`. 503 `OFFLINE` (forced) / `NOT_CONFIGURED` / `CLOUD_ERROR`, 409 `BUNDLE_REJECTED`, all with `installed_version`. |

- **Writes need ONLINE**: cloud URL + cloud admin token, not forced OFFLINE, and mode ONLINE (or reason
  `bundle_stale`). Else `503 CLOUD_UNAVAILABLE` reason `OFFLINE` / `NOT_CONFIGURED`, before any cloud call.
- **Validation order**: request model (422 `details[]`) -> ONLINE (503) -> role in the installed bundle's role
  names (422 `UNKNOWN_ROLE`) -> cloud. Zones are checked by the cloud only (the bundle is filtered to this
  kiosk's zone).
- **After every successful write** the edge calls `refresh_bundle_now(expect_version=<cloud bundle_version>)`
  and pulls the revocation feed. A failed pull keeps the 2xx: `bundle.applied: false`, `user: null` (PUT),
  plus a warning. `user.in_bundle: false` = the role has no access at this kiosk's zone (do not enrol here).
- **Error mapping** (`access.cloud_admin`): transport / timeout / 401 / 5xx -> 503 `CLOUD_ERROR`; 404
  without `error.reason`, or 405 -> 503 `ENDPOINT_NOT_DEPLOYED`; 403 -> 403 `FORBIDDEN` `CLOUD_ADMIN_TOKEN`;
  other 4xx -> same status + code, the cloud `reason` forwarded verbatim, plus `cloud_status` / `cloud_code`.
- **Field limits (R-H)**: `user_id ^u_[0-9a-z]{4}$` (path), `display` 1-80 after trimming, `role ^[a-z_]{1,32}$`,
  zones `^[A-Z0-9_]{1,32}$`, written times `00:00-23:59` with end > start (24:00 only in read data), unique
  days, <= 16 zones_add, <= 16 extra-window zones x 14 windows, tz-aware `valid_*` (normalised to UTC `Z`),
  `actor ^[A-Za-z0-9_.:@-]{1,64}$`, `extra="forbid"` on every write body.

**Registration (R-A)**: `PUT` access `{display, role, consent: true, actor: "register"}` first, require
`bundle.applied && user.in_bundle` (else `POST /v1/admin/bundle/refresh`), then `POST /v1/enroll`. Offline,
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
| `POST /v1/session/start` | 201. Exactly 3 random distinct off-primary colours x 333/333/334 ms (lead decision; at most 2 changes/s). The nonce is single-use with a 10 s TTL. `kiosk_id` must equal `KIOSK_ID`; with `DEMO_MODE=1` any kiosk in the bundle scope is accepted (see the caveat below). `recapture_of` must name this kiosk's attempt that is pending RECAPTURE, else 409; that old attempt is then closed |
| `POST /v1/attempt/{id}/frames` | 3-5 contiguous `frame_i` JPEGs + `meta`. Returns 410 NONCE_EXPIRED, 409 NONCE_REUSED / ATTEMPT_CLOSED, 403 when the nonce does not match the attempt, or 422 VALIDATION_ERROR. Every policy outcome is HTTP 200 with a DecisionResponse. A perception crash goes to `PolicyRuntime.decide_error` and gives DENY SYSTEM_ERROR |
| `POST /v1/attempt/{id}/challenge` | multipart `meta` + `frame_0`, the last challenge frame. `last_frame_cosine` is computed against the candidate's templates. Returns 409 INVALID_STATE unless CHALLENGE is pending, and 422 if `challenge_id` does not match the issued challenge |
| `POST /v1/attempt/{id}/fallback` | 409 INVALID_STATE unless SECOND_FACTOR is pending. EMAIL_OTP goes through the cloud `/v1/otp/verify`. If that verify times out or errors (DECISION_POLICY R11), the edge re-issues the same STEP_UP without `EMAIL_OTP`: reason codes and `attempts_left` are unchanged and nothing is counted. Later step-up responses for that attempt keep it removed |
| `POST /v1/attempt/{id}/otp/send` | 201. Online only (503 offline). 409 unless EMAIL_OTP is an offered method |
| `POST /v1/attempt/{id}/rendered` | 204. `face_lock_at_ms` must equal the FramesMeta value. The first beacon wins. The value feeds `/v1/metrics` `latency_ms.client` and the `rendered` SSE event |
| `GET /v1/attempt/{id}` | latest DecisionResponse. 404 for an unknown attempt; 409 before frames |
| `GET /v1/events` | SSE with `event: decision` (DecisionResponse + `eval`) and `event: rendered`, plus a `: ping` every 15 s |
| `GET /v1/health` | `{status, version, models_loaded{minifasnet_v2, minifasnet_v1se, face_detector, device_detector, arcface}, self_test{minifasnet_real_index, input_scale, passed}, depth_probe, uptime_s}`, with diagnostics under `detail` |
| `GET /v1/mode` | the runtime's ModeResponse. `template_cache{count, model, age_h}` comes from the edge store. `demo_clock` is null or `{active, now_local "HH:MM", now_utc, offset_s}` |
| admin (`X-Admin-Token`) | `POST /v1/admin/mode`, `GET /v1/admin/store`, `POST /v1/admin/sync` (503 offline), `POST /v1/admin/random-challenge` (`{mode: AUTO\|FORCE_NEXT\|OFF}`, `DEMO_MODE=1` only, else 403; the mask-contingency demo control), `POST /v1/admin/rate-limit/reset` (204), `POST`/`DELETE /v1/admin/eval/context` (200/204; tags attempts started afterwards), `POST /v1/admin/clock` (`DEMO_MODE=1` only, `{set_local:"HH:MM"}` or `{offset_s}` or `{reset:true}`), `GET /v1/admin/attempt/{id}/signals` (the raw AttemptSignals for calibration; no images or embeddings), `GET /v1/admin/users`, `POST /v1/enroll`, `DELETE /v1/enroll/{user_id}`, Users & Access proxies (section 3a) |
| `GET /v1/metrics` | final decision per attempt, latency from `frames` only, `latency_ms.client`, `by_label` with rule-of-3 / Clopper-Pearson upper bounds |

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
  Malformed uploads return 422.
- Depth counts only if it arrives within `latency_budget_ms.depth_max_wait` of the RGB frames.
  Depth maps stay in RAM and are dropped after 180 s.

**Policy-runtime hooks used by the edge:**

- `set_template_cache_status(count, model, age_h)`: at startup and after every enrol or delete.
  `AttemptSignals.template_cache_age_h` is always set while the cache is loaded.
- `mode()`: checked before every cloud match. When the next attempt would be OFFLINE, Rekognition is
  skipped entirely.
- Error mapping: `CloudUnavailableError` -> 503, `PermissionError` -> 403, `ValueError` -> 422. Any
  other runtime exception -> DENY SYSTEM_ERROR, never an HTTP 500.

**Cloud signing:** `.env` keys are encoded as UTF-8. When `|X-Server-Time - local| > 30 s` the edge
signs with server-corrected time, and it re-signs once if the cloud returned a 401 that taught it
a new offset.

**Known gaps and caveats**

- The `DEMO_MODE` kiosk switch is accepted at `session/start`, but `PolicyRuntime` evaluates every
  attempt against its fixed `KIOSK_ID`. Another kiosk's attempt is therefore currently DENY
  SYSTEM_ERROR (fail-secure). It needs a per-attempt kiosk override in the runtime.
- The gallery is filtered to the runtime's entitled users. When there is no valid bundle, the
  cache is searched unfiltered so DECISION_POLICY §9.5 I1 (STEP_UP via staff override only) stays
  reachable.
- Moire, mask-ring and flash amplitude scaling are uncalibrated `[cal]` feature maps. Calibrate
  them on demo-webcam captures (live, print, phone replay) before the eval run.
