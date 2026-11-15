# BUILD_PLAN: 10-hour day, Claude Code builds everything with parallel subagents

> **Execution model (D17):** Claude Code builds the WHOLE system by orchestrating subagents in parallel.
> Column letters below are agent lanes, not people: **F → `kiosk-frontend`**, **M → `edge-ml`**,
> **A → `policy-engine` + `cloud-aws`**, **E → `eval-metrics`**, depth → **`depth-iphone`**.
> The human operator only does physical tasks Claude cannot: sit in front of the camera, hold
> printed photos / phones / masks, plug in and mount the iPhone, AWS login / credentials, approve prompts.
> The iPhone 16 Pro Max IS available → `depth-iphone` is in scope (still gated at H4; app built and sideloaded, H4 calibration not run). Depth comes from our own
> free SwiftUI app **DepthProbe** (`depth/ios/`), which pushes 1–3 TrueDepth depth frames (+1 JPEG) per attempt
> to the edge (`GET /v1/depth/pending` long-poll, `POST /v1/depth/frames`); no Record3D. See `docs/IPHONE_SETUP.md`.
>
> **AWS (D1):** Workshop Studio event "HID Hackathon GenAI - University", **us-east-1 only** (production would pin
> ap-south-1 Mumbai for DPDP data residency). The event IAM role is limited, so every cloud feature has a degraded
> path (`docs/ARCHITECTURE.md` §10, `cloud/SANDBOX.md`); the local-first edge keeps working without the cloud.

Source of truth: `CLAUDE.md`. Interface contracts: `docs/API.md` v1.3 (endpoints and JSON shapes) and `docs/DECISION_POLICY.md`
(rules, thresholds, reason codes), test IDs in `docs/POLICY_TEST_CASES.md`. Evaluation: `.claude/skills/pad-evaluation/SKILL.md`. Demo: `docs/DEMO_AND_PITCH.md`.

Hard rules: **thin E2E by hour 3, SC1 + SC2 by hour 5, eval by hour 6, feature freeze at hour 7.**
Nothing is integrated, marked done or put on a slide until the `verifier` agent returns PASS.

Clock: H0 = build start. All times are elapsed hours. Adjust to the venue's real start time and write it here: `H0 = __:__ IST`.

---

## 0. Status (2026-11-14, ~22:10 IST)

Key: **built** = code exists and runs; **verified** = the `verifier` agent returned PASS (only that
makes something "done", CLAUDE.md §9); **in progress** = being changed now; **pending** = not started.
Builders are still editing, so test counts move. Snapshot from the lead's swarm brief (~21:40 IST), **not**
a verifier PASS: edge + policy + offline + depth pytest 1262 passed / 0 failed; `cloud/tests` 3 failing
(`tests/test_bundle_upload.py`); `eval/tests` 2 failing (`tests/test_schema.py`). The verifier must re-run
all of these before any checkpoint is marked.

| Workstream | State | Notes |
|---|---|---|
| W2 edge-ml: perception + edge API | **built**, running on `127.0.0.1:8000` (+ depth LAN listener `0.0.0.0:8001`) | MiniFASNet self-test passes (index 1 = real, raw 0-255 BGR); RetinaFace, YOLOX-Tiny device detector, moiré, flash correlation, ArcFace matcher, encrypted templates, enrolment (re-enrolment **appends**: ≤ 24 templates, first 5 pinned), `POST /v1/admin/random-challenge` (`AUTO` / `FORCE` / `FORCE_NEXT` / `OFF`), cloud crop upload + keep-alive warm-up. **Early cloud probe** `POST /v1/attempt/{id}/probe` is in the code (API.md §3.1a); the running edge predates it, so it is live only after the lead restarts the edge; not measured |
| W3 policy-engine: policy, SC1, SC2 | **built** | Round-2 rulings R1–R18; moiré and M2 enforce switches (both `true`); random challenge 0.15 / 0.30; deformation SMILE / OPEN_MOUTH; `latency_budget_ms.rekognition_probe_deadline` 1500 ms; `STAFF_OVERRIDE` needs `staff_id`; CARD revocations; `ERASED` → local erase; `GET /v1/mode` `policy_bars` + `cloud_match` |
| W1 kiosk-frontend | **built**, running (`npm run dev`, `http://localhost:5173`; Vite listens on IPv6 only, so `127.0.0.1:5173` refuses) | 5 frames over 700 ms at up to 1280 px; enrolment page `/register` behind staff sign-in (`kiosk/public/enroll.html` now only redirects there); early-probe client call (`submitProbe`). Flash stays advisory until the kiosk frame timing is re-validated |
| W4 cloud-aws | **deployed** in us-east-1 (2026-11-14 ~10:00 UTC) | EC2 t3.small + API Gateway HTTP API, DynamoDB, S3 SSE-KMS (1-day lifecycle), Rekognition collection `hid-kiosk-users` (`u_prj1`, `u_tm03`; `u_tm02` missing), SES email OTP to one verified recipient. **S3 audit-frame upload not implemented.** In the code, **pending the lead's redeploy**: append-mode re-enrolment, optional e-mail, `PUT /v1/admin/schedule/{kiosk_id}`. Live bundle: cloud-issued **v45** (`KIOSK_MAIN_01` only) still holding the public fixture override codes until v46+ is uploaded. From the venue most cloud matches miss the 700 ms box → attempts decided OFFLINE (P7) |
| W6 depth-iphone | **built**; **H4 go/no-go not run** | DepthProbe v0.3.0 sideloaded as an unsigned IPA with Sideloadly (v0.3.1 IPA built; `docs/IPHONE_SETUP.md`); connects when running (`/v1/health` `depth_probe` was `unavailable` at the time of writing). `depth/calibration/` is empty. `liveness.depth.enabled` stays `false` until `python -m depth.calibrate summary` reports GO on ≥ 10 live + ≥ 10 printed-photo PASSIVE captures |
| W5 eval-metrics | tooling **built**; **no eval run** (`eval/results/runs/` is empty) | The iBeta Level 1-style protocol is designed, not run. No APCER / BPCER / FAR / FRR numbers exist. Only the dev measurements below may be cited, labelled as dev |
| Slides / pitch | **pending** | Must say: flash advisory, depth pending H4, moiré / M2 bands uncalibrated, no eval numbers until the run (`docs/DEMO_AND_PITCH.md`) |

**Measured so far (dev measurement, not an eval result):** kiosk face lock → rendered p50 1656 ms, p95
1697 ms [95% CI 1692–1724], n = 202 (back-to-back test attempts, MacBook webcam, 700 ms window, Rekognition
timing out at 700 ms; from the live `/v1/metrics` snapshot of the ~19:20–20:37 IST docs audit, lost since
in an edge restart): p95 under 2 s **in this sample**; a later window (n = 59) had p95 2005 ms. Edge-only
server total with synthetic frames and no cloud: p50 106.5 ms / p95 136.5 ms, n = 30
(`eval/results/latency_edge.md`). The MiniFASNet self-test confirms output index 1 = real with raw 0-255
BGR input.

**Calibration and operator changes today (dev data, real MacBook webcam):** capture `max_width_px`
1280 (C1); flash lag window 0–8 frames, lag std ≤ 1.5, `min_amplitude` 2.0, `r` from edge-measured
frames only (C2); **flash ADVISORY** (`liveness.flash.enforce: false`, C3); rate-limit lockout 5 s;
`challenge.random_rate` 0.15 online / 0.30 offline (was 0.0 for part of the day, restored at the
operator's request); `PUFF_CHEEKS` removed from the issued challenge actions; moiré (0.40 / 0.70) and M2
(0.50 / 0.75) enforced. Genuine flash-lit moiré 0.42–0.79 and spectacle frames 0.35–0.80 on M2 (dev data)
mean genuine users can be stepped up until the bands are calibrated on the eval dev split.

---

## 1. Hour-by-hour (by agent)

Columns: **F** = `kiosk-frontend`, **M** = `edge-ml`, **A** = `policy-engine` + `cloud-aws`, **E** = `eval-metrics` (operator assists with physical capture).

| Hour | F: kiosk (React/Vite/TS) | M: edge ML (FastAPI, ONNX) | A: cloud/AWS + policy | E: eval + pitch |
|---|---|---|---|---|
| **0–0.5** | Vite + Tailwind scaffold; webcam; device list | Python 3.11 venv; download MiniFASNetV2/V1SE ONNX; **verify "real" index on a real face** | Operator logs in; `aws sts get-caller-identity`; `cloud/infra/probe_sandbox.sh` (read-only + IAM simulation) for Rekognition, DynamoDB, S3/KMS, SES, EC2/IAM in **us-east-1** → `cloud/SANDBOX.md` §4 → **GATE G1** | Consent form; artefact shopping list; print photos; load phone/laptop replays |
| **0.5–1** | MediaPipe Face Landmarker (VIDEO mode, blendshapes) + face lock | Edge `/v1/health`, `/v1/session/start` + `/v1/attempt/{id}/frames` stubs returning fixed JSON from `docs/API.md` | Write `docs/DECISION_POLICY.md` + `config/thresholds.yaml` + `config/schedule.example.json` with lead; freeze `docs/API.md` (now v1.1) | Write `eval/PROTOCOL.md`, subject split (dev/test), shuffled attempt schedule |
| **1–2** | Quality gate (single face, IOD, pose, blur, luma) + hints | Face detect/crop (2.7× / 4.0×, 80×80), PAD ensemble, per-frame voting; ArcFace embeddings | Policy engine skeleton + **pytest decision matrix first** (TDD); enrolment endpoint (local + Rekognition IndexFaces/CreateUser/AssociateFaces) | `eval/capture.py` appends `attempts.csv` from API responses; enrol 4 teammates |
| **2–3** | Capture 3–5 frames → POST edge → decision screen with reason codes | Local matcher vs encrypted template cache; device-in-frame detector; FFT moiré | Cloud API on EC2 (warm) with `SearchUsersByImage`/`CompareFaces`; edge → cloud call with timeout | First office-lighting capture round (genuine + print + phone) |
| **H3 checkpoint** | **Thin E2E**: live face → ALLOW, print → DENY, on the kiosk, via edge (and cloud if G1 passed). `verifier` PASS required. | | | |
| **3–4** | Colour-flash: server nonce, tint sequence (≤ 3 changes/s), chroma series from cheek/forehead | Flash correlation + lag check server side; virtual-camera check | **SC1** schedule engine (window, grace, zone, holiday, high-risk) + tests; signed bundle (HMAC-SHA256, `scripts/sign_bundle.py`); cloud schedule store (DynamoDB or SQLite) + `/v1/schedule/{kiosk_id}` | Attacks: phone video, laptop replay, eye-cut print; backlit round |
| **4–5** | Step-up state machine (deformation step mandatory + blink/turn), "REQUEST VERIFICATION" screen, offline badge (polls `/v1/mode` every 2 s), DEMO CLOCK badge, fallback TOTP/staff/card screen, `/rendered` beacon | Mask cues (no-deform, eye-hole ring); latency spans per stage; offline threshold profile | **SC2**: connectivity monitor (`edge/offline/connectivity.py`, `GET /v1/mode`, `POST /v1/admin/mode`), encrypted SQLite queue, purge-on-ack + 24 h tombstone, offline rules, sync agent + cloud `/v1/sync` idempotent replay + discrepancy alerts; SES email OTP (if allowed) | Dim round; paper/3D mask if available (force a challenge via the DEMO_MODE random-challenge admin control if needed); offline-mode attempts |
| **H4 gate** | **G2 depth go/no-go** (see section 5) | | | |
| **H5 checkpoint** | **SC1 + SC2 live**: same user outside schedule → DENY, in grace → REQUEST VERIFICATION; pull plug (or force OFFLINE) → OFFLINE badge, local ALLOW in low-risk zone, TOTP/staff in high-risk, reconnect → queue drains. `verifier` PASS. | | | |
| **5–6** | Admin metrics dashboard (use `dataviz` skill): tiles, per-species bars, live feed, badge, sync count | **Calibrate** thresholds on dev split only; commit `thresholds.yaml`, record hash | Impostor cross-matching job (`eval/compare.py`, ArcFace + Rekognition if allowed); attack-evidence rate limiter (D3); S3 SSE-KMS + 1-day lifecycle on the audit bucket | Held-out test run with frozen thresholds; `eval/metrics.py` → `metrics.json` + DET |
| **H6 checkpoint** | **Eval numbers exist** with bounds, from CSV via script. `verifier` re-runs `metrics.py` independently. | | | |
| **6–7** | DET + latency histogram + confusion matrix panels | Latency profiling; trim detector input; parallelise PAD ∥ match | Load test at the Rekognition TPS design limit (Mumbai defaults, ~5 TPS search); measure Bangalore → us-east-1 match latency; laptop-only fallback deployment rehearsed | Slides 1–6 drafted; "HID target vs ours (95% UB)" table |
| **H7** | **FEATURE FREEZE.** Only bug fixes, copy, and threshold changes justified by dev data from here on. `spec-auditor` full sweep. | | | |
| **7–8** | UI polish, reason-code wording, accessibility non-flash path | Fix failure cases found in eval (no new models) | Teardown script; hardening; secrets check | Slides 7–12; record backup demo video |
| **8–9** | Full rehearsal under venue lighting | Re-check thresholds under venue light (dev-style captures only) | Confirm endpoint + offline switch on stage network | Rehearse 5-min pitch, timed; Q&A drill |
| **9–10** | Buffer / dry runs | Buffer | Final p50/p95 measured on stage hardware | Final numbers into slides (only from `metrics.json`) |

---

## 2. Claude Code subagent workstreams

Each agent owns its paths exclusively. Cross-boundary changes go through the owner, or through a contract change in
`docs/API.md` / `docs/DECISION_POLICY.md` announced to all agents. Agents are defined in `.claude/agents/`.

| # | Agent | Lane | Owns (write) | Reads (contracts) | Inputs | Outputs |
|---|---|---|---|---|---|---|
| W1 | `kiosk-frontend` | F | `kiosk/` | `docs/API.md` v1.1, reason-code table in `docs/DECISION_POLICY.md` §6 | edge API, MediaPipe, nonce + flash sequence from `POST /v1/session/start` | kiosk app (capture, quality gate, flash, step-up, fallback, ONLINE/OFFLINE + DEMO CLOCK badges, `/rendered` beacon), `/admin` dashboard |
| W2 | `edge-ml` | M | `edge/` **except** `edge/policy/`, `edge/offline/`; `scripts/` (except `scripts/sign_bundle.py`); `models/` | `docs/API.md` v1.1, `docs/DECISION_POLICY.md` §3 + §6, `edge/policy/signals.py`, `config/thresholds.yaml` | frames, nonce, enrolled templates, DepthProbe frames | `POST /v1/attempt/{id}/frames` signal layer: PAD scores, flash r/lag, moiré, device box, vcam flag, mask cues, depth checks, match scores, stage spans; all edge endpoints |
| W3 | `policy-engine` | A | `edge/policy/`, `edge/offline/` (incl. connectivity monitor C10 `edge/offline/connectivity.py` and the sync agent), `config/`, `scripts/sign_bundle.py` | `docs/DECISION_POLICY.md` (owner), `docs/SURPRISE_CHALLENGES.md`, `docs/POLICY_TEST_CASES.md`, `docs/API.md` v1.1 | signal dict from W2, signed bundle, connectivity state | pure `evaluate()` / `combine()` / `resolve_stepup()`; SC1 schedule engine; SC2 offline rules, encrypted decision log, purge + tombstone, sync agent, connectivity monitor, fallback TOTP/staff/card, attack-evidence rate limiter, random challenge; pytest suite |
| W4 | `cloud-aws` | A | `cloud/` (incl. `cloud/infra/`) | `docs/API.md` v1.1, `docs/SURPRISE_CHALLENGES.md` §SC2.5–SC2.6, `docs/POLICY_TEST_CASES.md` §7 (Y01–Y11) | face crops, enrolment requests, sync batches | cloud API in us-east-1 (EC2 or laptop-hosted): Rekognition match, enrolment, authoritative schedule + HMAC-signed bundles, revocations, `/v1/sync` with re-evaluation + alerts, SES OTP, CloudWatch metrics, teardown |
| W5 | `eval-metrics` | E | `eval/` | `pad-evaluation` skill, `docs/API.md` v1.1 | `GET /v1/events` stream tagged via `POST /v1/admin/eval/context`, `/rendered` latencies, team photos for `eval/collect_faces.py` + `eval/compare.py` | `eval/capture.py`, `eval/metrics.py`, `metrics.json`, DET PNGs, `RUN_INFO.md`, `/v1/metrics` payload shape for W1 |
| W6 | `depth-iphone` (H4 go/no-go) | depth | `depth/` (`depth/ios/DepthProbe`, `depth/checks.py`) | `docs/API.md` v1.1 (`/v1/depth/pending`, `/v1/depth/frames`), `docs/IPHONE_SETUP.md` | iPhone 16 Pro Max front TrueDepth (DepthProbe app) | 1–3 depth frames per `attempt_id` pushed to the edge; D0–D4, M1–M3 checks |
| V | `verifier`, `spec-auditor` | lead | read-only | everything | "done" claims | PASS/FAIL with evidence; coverage report |

### 2.1 Interface contracts (write first, H0–H1)

- `docs/API.md` v1.1 (owner: lead + W4; frozen at H1, versioned after that). Canonical edge endpoints (D16) — exactly these:
  `POST /v1/session/start` · `POST /v1/attempt/{id}/frames` · `POST /v1/attempt/{id}/challenge` · `POST /v1/attempt/{id}/fallback` ·
  `POST /v1/attempt/{id}/otp/send` · `POST /v1/attempt/{id}/rendered` · `GET /v1/attempt/{id}` · `GET /v1/events` (SSE) · `GET /v1/health` ·
  `GET /v1/mode` · `POST /v1/admin/mode` · `GET /v1/admin/store` · `POST /v1/admin/sync` · `POST /v1/admin/rate-limit/reset` ·
  `POST` / `DELETE /v1/admin/eval/context` · `POST /v1/admin/clock` (DEMO_MODE=1 only) · `GET /v1/admin/users` · `GET /v1/admin/attempt/{id}/signals` ·
  `POST /v1/admin/random-challenge` (DEMO_MODE=1 only, being added) · `POST /v1/enroll` (+ `DELETE /v1/enroll/{user_id}`) · `GET /v1/metrics` ·
  `GET /v1/depth/pending` · `POST /v1/depth/frames` (these two also on the LAN listener `0.0.0.0:EDGE_LAN_PORT`, `X-Depth-Token`).
  `GET /v1/events` and `GET /v1/metrics` are localhost-only and need no admin token. Every decision returns `decision`, `reason_codes[]`, `scores{}`, `latency_ms`, `mode`, `next_action`.
  Cloud: `POST /v1/match` · `GET /v1/schedule/{kiosk_id}` · `GET /v1/revocations` · `POST /v1/sync` (idempotent on `attempt_id`) · `/v1/otp/*` · `POST /v1/liveness/session` (+ `GET /v1/liveness/session/{session_id}/result`) · `POST /v1/enroll` (+ `DELETE /v1/enroll/{user_id}`) · `GET /v1/health`.
  Retired names (do not implement): `/v1/authenticate`, top-level `/v1/challenge`, `/v1/stepup`, `/v1/fallback/verify`, `/v1/enrol`, `/v1/attempts/{id}`, `/status`, `/admin/connectivity`, `/v1/sync/decisions`, the `X-Eval-Label` header, the Record3D `:8765` depth bridge.
- `docs/DECISION_POLICY.md` (owner: W3): three-zone thresholds by key name, rule order (rate limit → quality → injection → liveness/mask ‖ match → biometric result → SC1 schedule → SC2 offline), closed reason-code list (§6), offline profile, grace window, high-risk zone list.
- Signal dict between W2 and W3 is a Pydantic model in `edge/schemas.py` (owned by W2, reviewed by W3). W3 tests against fixtures, not live models.

### 2.2 Dependency order

```
H0  contracts (API.md, DECISION_POLICY.md, thresholds.yaml, schedule.example.json)
     ├─► W3 policy-engine (pure functions + tests, fixtures only)   ── no deps on models
     ├─► W2 edge-ml (signals)  ──────────┐
     ├─► W1 kiosk (stub edge first) ─────┤──► H3 thin E2E (W1+W2+W3)
     ├─► W4 cloud (after G1) ────────────┘        │
     └─► W5 eval capture tool (stub API)          ▼
                                     W3 SC1/SC2 + W4 sync ──► H5 SC checkpoint
                                     W5 test run ───────────► H6 eval
                                     W6 depth (gate G2 at H4) ─► merge or roadmap slide
```

W1, W2, W3 and W5 can all start at H0.5 against stubs. W4 builds against fakes from H0.5 and switches to real AWS services only where G1 says ALLOWED; if the sandbox blocks most services, W4 ships the laptop-hosted cloud API (sync, bundles, revocations) plus the deploy/teardown scripts.

### 2.3 Integration checkpoints

| When | Checkpoint | Pass evidence (collected by `verifier`) |
|---|---|---|
| H1 | Contracts frozen | `spec-auditor`: every SC1/SC2 bullet and every spoof type maps to a rule or reason code |
| **H3** | **Thin E2E** | Live face → ALLOW, print → DENY on the kiosk; JSON has all required fields; `pytest edge/policy/tests` green; one row in `attempts.csv` written by `capture.py` from `GET /v1/events` |
| **H5** | **SC1 + SC2** | `docs/POLICY_TEST_CASES.md` IDs green: SC1 = S01–S32; SC2 = O01–O29, X01–X06, D01–D06 (`pytest edge/policy/tests edge/offline/tests`) and Y01–Y11 (`pytest cloud/tests`); Q01–Q12, L01–L19, M01–M04, C01–C08, I01–I11 and P01–P08 still green; live pull-the-plug demo once; SQLite inspection shows no images/embeddings (D01–D03) |
| **H6** | **Eval** | `metrics.py --split test` reproduces `metrics.json`; every species has N ≥ 30 or is flagged "low N"; latency p50/p95 with bootstrap CI measured (client face-lock → rendered and server `latency_ms.total`) |
| **H7** | **Freeze** | `spec-auditor` sweep; tag the commit `freeze`; slides cite only the `metrics.json` from this tag (or a later eval rerun) |

### 2.4 Definition of done per workstream

- **W1 kiosk-frontend**: face lock + quality hints; flash capture with server nonce; decision screen (ALLOW / **REQUEST VERIFICATION** (subtitle "step-up") / DENY, plain-English reason, no raw scores; API enum stays `STEP_UP`); step-up flow with a mandatory deformation step; fallback TOTP / staff / card entry; ONLINE/OFFLINE badge from `GET /v1/mode` polled every 2 s (a forced switch shows within 2 s; natural detection about 12–17 s per `connectivity:` in the YAML: 3 misses × 5 s interval, 2 s timeout); DEMO CLOCK badge when the demo clock is active; non-flash accessibility path; admin dashboard per the skill spec; `npm run build` clean; `POST /v1/attempt/{id}/rendered` beacon with the browser-measured face-lock → rendered time.
- **W2 edge-ml**: PAD ensemble with verified class index; flash correlation + lag; moiré; device detector (licence checked); vcam label check; mask cues; depth endpoints for DepthProbe; local matcher with encrypted templates; stage spans; exactly the D16 endpoint set; runs fully offline; p50 server time ≤ 300 ms on the demo laptop (measured).
- **W3 policy-engine**: `evaluate()` / `combine()` are pure and deterministic (clock and RNG injected); all thresholds read from `config/thresholds.yaml`; every `docs/POLICY_TEST_CASES.md` edge row is a pytest case in `edge/policy/tests/` or `edge/offline/tests/`; fail-secure on any exception or missing input; offline SQLite encrypted, purge-on-ack + 24 h tombstone, idempotent sync agent; connectivity monitor (`GET /v1/mode`, forced mode); attack-evidence rate limiter (5 in 180 s → 5 s lockout, D3/R1); optional random challenge (rate 0.0 by default, R4).
- **W4 cloud-aws**: EC2 (warm) in **us-east-1** (or the laptop-hosted fallback); Rekognition user-vector match on consenting team faces (if allowed); DynamoDB (or SQLite) users/state/decisions; HMAC-SHA256 signed bundles; S3 SSE-KMS + 1-day lifecycle (audit-frame upload not implemented); `/v1/sync` idempotent with re-evaluation and alerts — **Y01–Y11 green**; SES email OTP to verified addresses (if allowed); CloudWatch latency metric (or EMF stdout); `cloud/infra/teardown.sh` deletes the collection, buckets and instances; no keys in git.
- **W5 eval-metrics**: protocol doc; capture tool on the D9 data path (`/v1/admin/eval/context` + `GET /v1/events` + `/rendered` beacon; FAR/FRR via `eval/collect_faces.py` + `eval/compare.py`); ≥ 120 genuine + ≥ 30 per species on test split (or honestly flagged); D14 metrics in `metrics.json` + DET PNGs + `RUN_INFO.md` with thresholds hash; `/v1/metrics` feed for dashboard; slide numbers table generated from JSON.
- **W6 depth-iphone**: DepthProbe builds (`DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`, destination = the iPhone 16 Pro Max by UDID) and runs on the phone; it long-polls `GET /v1/depth/pending` and pushes 1–3 depth frames per `attempt_id` via `POST /v1/depth/frames` within the capture window; D1 flatness rejects a print on 10/10 tries while passing a live face; degrades to depth `NOT_AVAILABLE` (no effect on decision) when the phone is absent or late.

---

## 3. Go/no-go gates

| Gate | When | Test | GO | NO-GO fallback |
|---|---|---|---|---|
| **G1 Rekognition** | H0.5 | In **us-east-1** (only accessible region): probe, then CreateCollection, IndexFaces, CompareFaces, SearchUsersByImage on a consenting teammate photo; also try CreateFaceLivenessSession | Cloud match cross-check + (optionally) Face Liveness step-up | **Local-only matcher** (ArcFace on edge) for everything; cloud = sync + bundles (or laptop-hosted); pitch states "Rekognition-ready, sandbox-blocked" |
| G1b EC2/IAM | H0.5 | Launch t3.small with a pre-provisioned or new instance profile (PassRole) | EC2 warm API | Run the "cloud" API on a second laptop or the same machine, on a separate port, so online/offline switching is still real |
| G1c SES | H1 | Send to a verified address | Email OTP step-up | On-screen/offline TOTP only |
| **G2 iPhone depth** | **H4** | DepthProbe runs on the iPhone, a depth result reaches the edge for a real attempt, **and** D1 rejects a printed photo while passing a live face | Merge W6 depth signals | Drop to a roadmap slide; reassign `depth-iphone` capacity to eval/attacks |
| G3 Flash signal | H4.5 | r ≥ 0.7 on a live face vs < 0.3 on a phone replay, office light, **with validated kiosk frame timing** | Set `liveness.flash.enforce: true`: flash becomes a DENY-capable signal | **Current state: ADVISORY** (`enforce: false`, measured + reported, no decision effect). Video/screen replay defence = PAD + device detector + moiré. Never claim the flash is enforced |
| G4 Freeze | H7 | All H5 checks still green | Freeze | Cut the lowest-value unfinished feature, don't extend |

---

## 4. Risk register

| # | Risk | Likelihood | Impact | Mitigation | Owner |
|---|---|---|---|---|---|
| R1 | Workshop Studio role blocks Rekognition / SES / DynamoDB / KMS / IAM / EC2 | Med | High | G1 at H0.5; degraded path per service; local-first architecture means the demo never depends on cloud | A |
| R2 | Rekognition quota throttled during demo (design for Mumbai defaults, ~5 TPS search) | Med | Med | CompareFaces 1:1 where possible; jittered retry; local matcher is primary anyway | A |
| R2b | Venue → us-east-1 round trip makes the cloud match miss its timeout | **Happened** (round trip about 0.4–1.4 s vs the 700 ms box; most online attempts decided OFFLINE under an ONLINE badge) | Med | Match is parallel and time-boxed; timeout → attempt OFFLINE (P7, fail-secure); `GET /v1/mode` `cloud_match.degraded` explains it; face-crop upload + keep-alive warm-up; **early cloud probe** at face lock with a 1500 ms deadline (in the code, live after an edge restart, not measured); schedule evaluated locally (D2) | A/M |
| R3 | MiniFASNet class index or crop scale wrong → inverted PAD | Med | High | Verify on a real face and a print at H0.5; unit test with two fixture images | M |
| R4 | High-res phone replay passes PAD (most likely live failure) | High | High | Device detector + moiré + flash nonce carry it; rehearse with judges' phone types | M |
| R5 | Flash check weak in bright venue / auto-exposure; kiosk frame timing unvalidated (genuine users got false flash mismatches) | **Happened** | Med | Flash set ADVISORY (`liveness.flash.enforce: false`) until the flash-timing fix is validated; weak flash = UNSURE, never DENY; G3 | F/M |
| R6 | Venue lighting differs from capture lighting → BPCER spike | Med | High | Dim/backlit rounds in eval; re-check thresholds at H8 with dev-style captures | E |
| R7 | Latency > 2 s on the ALLOW path | Med (online) | High | Dev sample p50 1656 / p95 1697 ms (n = 202, Rekognition timing out at 700 ms); a later window (n = 59) had p95 2005 ms, so ≥ 3 attempts went over 2 s. Early probe budget ≈ 1.6 s worst case by arithmetic (not measured). Re-measure after the edge restart; parallel PAD ∥ match; warm instance | M |
| R8 | Venue Wi-Fi unstable | High | Med | Offline mode *is* the feature; phone hotspot backup; recorded demo video | A/E |
| R9 | Eye-cut mask passes step-up (deformation threshold too loose) | Med | High | Deformation step mandatory; baseline-relative blendshape delta; test at H4–5 | F |
| R10 | Too little eval data → no credible numbers | Med | High | Start captures at H2; interleave during dev; report bounds honestly | E |
| R11 | Licence issue (InsightFace weights, YOLO AGPL, CelebA-Spoof) | Certain | Low today / high for product | State on licence slide; prefer Apache/MIT components; roadmap to licensed matcher | M/E |
| R12 | Biometric data leakage (images in logs, keys in git) | Low | High | No images offline; Fernet/AES-GCM templates; `.env` only; teardown script; consent | A |
| R13 | Integration hell at H3 (schema drift between agents) | Med | High | Contracts frozen at H1; Pydantic models; `spec-auditor` at each checkpoint | lead |
| R14 | Photosensitivity complaint from the flash | Low | Med | ≤ 3 tint changes/s, gentle tints, non-flash path | F |
| R15 | Demo-laptop failure | Low | High | Second laptop with the same build; backup video | E |
| R16 | Depth stretch eats core time | Med | Med | Single owner (`depth-iphone`); hard G2 at H4 | lead |

---

## 5. Daily operating rules

- Commit small and often. Tag `h3-e2e`, `h5-sc`, `h6-eval`, `freeze`.
- Every threshold change after H6 needs a dev-split justification line in `RUN_INFO.md`.
- Update the checklist in `CLAUDE.md` section 10 at each checkpoint.
- If a checkpoint slips by more than 30 min, cut scope (flash → STEP-UP-only, depth → roadmap, SES → TOTP) rather than moving the freeze.
