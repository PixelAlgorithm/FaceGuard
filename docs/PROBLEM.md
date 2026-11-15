# PROBLEM.md — Official Brief (verbatim requirements)

> **Status: VERBATIM REQUIREMENTS.** Sections 1–5 transcribe the official HID Hackathon 2026 brief from
> the images in `docs/images/` (01–05). Wording, numbers and capitalisation follow the source; layout
> is converted to markdown. Text in *[square-bracket italics]* is a transcriber's note, not part of the brief.
> Section 6 (requirements checklist) is **ours**: it maps each requirement to the component that satisfies it.

Event context (from the banner in images 02–04): **HID HACKATHON 2026 — BUILD BEYOND — "Build the next
layer of trust."** Inaugural edition, hosted and sponsored by HID (part of ASSA ABLOY), at PES University.
**14 NOV** — 2026 · One-day hackathon · MRD Auditorium, Ring Road Campus. Prize: **₹2 lakh** in prizes to be won.

---

## 1. Challenge poster (`docs/images/01_challenge_poster.jpg`)

**HID | HACKATHON**

# Can You Spot a Spoof?
### Face Liveness Detection & Authentication

Build an application that can tell if a person is truly present or if it's a spoof, and decide access
**within 2 seconds.**

### The Challenge
How might we help an HID entry kiosk distinguish a live person from a presentation attack such as a
printed photograph, screen replay, video, or mask?

### Why it Matters?
The same face can look real, but it may not be the real person. Your solution must verify both
**liveness** and **identity.**

*[Illustration: laptop showing "HID Liveness Check" — face in a green frame — "ALLOW — Live person
detected & identity verified — Decision time: 1.4 s — Confidence: 0.96".]*

### Spoof Types to Test
| # | Spoof type |
|---|---|
| 1 | Printed Photo |
| 2 | Screen Replay (Photo) |
| 3 | Video Replay |
| 4 | Mask (3D / Printed) |

### Decision Outcomes
| Outcome | Meaning |
|---|---|
| **ALLOW** | Live person and identity match. |
| **REQUEST VERIFICATION** | When confidence is low (e.g., poor lighting, unclear face). Ask for an additional step (recapture, simple action, or OTP). |
| **DENY** | Spoof detected, identity does not match, or verification fails. |

### Key Requirements
| Requirement | Detail |
|---|---|
| **≤ 2 Seconds** | Liveness decision within two seconds. |
| **Handle Multiple Spoofs** | Demonstrate against ≥ 2 spoof types (e.g., photo, screen, video, mask). |
| **Show Performance** | Report results for each scenario (e.g., detection rate, false acceptance/ rejection, decision time). |

### What to Demonstrate
- [ ] A working prototype.
- [ ] Clear handling of low-confidence cases (with additional verification).
- [ ] Test results on more than one spoof type.
- [ ] Measured performance (e.g., accuracy, false acceptance, decision time ≤ 2s).

### aws | AWS Sandbox
Build, experiment, and deploy your solution using AWS services from the provided sandbox.

**https://tinyurl.com/hid-hackathon**

Access code will be provided.

---

## 2. Evaluation Criteria (`docs/images/02_evaluation_criteria.jpg`)

**Evaluation Criteria** — *How the implementation will be evaluated*

| Criterion | Weight | Bullets (verbatim) |
|---|---|---|
| **Problem-Solution Fit** | **25%** | • Relevance of the solution to the problem statement. • How well the proposed solution addresses the core challenges. • Understanding and innovation in framing the problem. |
| **Innovation & Creativity** | **20%** | • Understanding and innovation in framing the problem. • Use of new techniques, tools, or creative problem-solving methodologies. • Differentiation from existing solutions. |
| **Technical Implementation** | **25%** | • Feasibility and practicality of the solution. • Use of APIs, frameworks, and integration architecture, and scalability. |
| **Functionality & Usability** | **15%** | • How well the solution works (demonstrated prototype). • User-friendliness of the interface. • Ability to achieve intended objectives effectively. |
| **Presentation & Communication** | **15%** | • Clarity and structure of the presentation. • Ability to explain technical details to a non-technical audience. • Response to questions from judges. |

Total: 100%.

---

## 3. Performance Evaluation targets (`docs/images/03_performance_targets.jpg`)

**Performance Evaluation**

| Target | Metric |
|---|---|
| **99.4%** | liveness detection accuracy |
| **99.2%** | face authentication accuracy |
| **0.2%** | false acceptance rate (FAR) |
| **0.6%** | false rejection rate (FRR) |
| **< 2 SECONDS** | DECISION TIME |

*Validated across printed photo, screen replay, video, and mask attacks*

---

## 4. Prototype Flow and Decision Logic (`docs/images/04_prototype_flow.jpg`)

**Prototype Flow**

| Step | Name | Description |
|---|---|---|
| 01 | **Capture** | Use camera to capture face image/video |
| 02 | **Liveness Detection** | Determine if the subject is a live physical person |
| 03 | **Face Authentication** | Verify if face matches enrolled user |
| 04 | **Decision** | Combine results and decide within 2 seconds |

`01 Capture → 02 Liveness Detection → 03 Face Authentication → 04 Decision`

**Decision Logic**

| # | Decision | Description |
|---|---|---|
| 01 | **Allow** | Live person detected and identity verified |
| 02 | **Request Additional Verification** | Low confidence cases require extra checks such as OTP or manual review |
| 03 | **Deny** | Spoof detected or identity verification failed |

---

## 5. Surprise Challenges sheet (`docs/images/05_surprise_challenges.png`)

**HID | HACKATHON — FOLLOW-UP CHALLENGES**

# Surprise Challenges
**ADDITIONAL PROBLEM STATEMENTS**

Extend your solution beyond liveness and recognition with these two follow-up challenges.

### 1 — Access with Campus Schedule
A live, recognized person is not automatically authorized. The system must combine the biometric
result with the campus access schedule and return one of the following decisions:

**BIOMETRIC RESULT + CAMPUS ACCESS SCHEDULE**

| ALLOW | STEP-UP VERIFICATION | DENY |
|---|---|---|

### 2 — Offline Mode with Safe Access
The kiosk loses connection to the central service. Teams must update the prototype so it can:

- Continue using a safe local decision process.
- Avoid unsafe automatic access.
- Provide fallback verification.
- Store only minimum temporary information.
- Synchronize decisions when the connection returns.

*Footer: HID HACKATHON · SURPRISE CHALLENGE*

---

## 6. Requirements checklist (ours — maps every requirement to where we satisfy it)

Each row points to the **implemented** component (file path) and endpoint. Endpoints are in `docs/API.md` v1.1, decision
rules in `docs/DECISION_POLICY.md`, thresholds in `config/thresholds.yaml` (key names as cited), component names in
`docs/ARCHITECTURE.md`. Edge = `http://127.0.0.1:8000`; cloud = the AWS us-east-1 sandbox API. Decision `STEP_UP` in our
API = brief's "REQUEST VERIFICATION" / "Request Additional Verification" / "STEP-UP VERIFICATION". Every number in the
evidence column has a stored source under `eval/results/` (named in the row) and is not an evaluation result; no eval
capture has been run yet (iBeta Level 1-style protocol designed, not run).

| # | Requirement (source) | Where we satisfy it (implemented component · endpoint) | Evidence for judges |
|---|---|---|---|
| R1 | Capture face image/video (Flow 01) | **Kiosk UI** `kiosk/src/capture/` (`camera.ts`, `landmarker.ts`, `quality.ts`, `flash.ts`, `attemptCapture.ts`): `getUserMedia` + MediaPipe Face Landmarker face lock and quality pre-check → edge `POST /v1/session/start` (nonce, `flash_sequence`, `CaptureSpec`: 5 frames over `window_ms` = `liveness.flash.duration_ms` 700 ms at up to `max_width_px` 1280) → `POST /v1/attempt/{id}/frames` | Live demo |
| R2 | Liveness: live person vs presentation attack (Flow 02, Challenge) | **Edge Liveness Engine** `edge/ml/` (`pad.py` MiniFASNetV2 + V1SE, `device.py` COCO phone/laptop/TV detector, `moire.py` FFT, `flash.py`, `mask.py`) fused by `edge/policy/liveness.py`. Colour flash is **advisory** today (`liveness.flash.enforce: false`: measured and reported as `ADVISORY_<zone>`, no decision effect). iPhone TrueDepth via our **DepthProbe** app on the LAN listener (`EDGE_LAN_PORT` 8001: `GET /v1/depth/pending`, `POST /v1/depth/frames`, `X-Depth-Token`, per-attempt `depth_nonce`); `liveness.depth.enabled: false` until the H4 calibration passes. Self-test in `GET /v1/health` | Per-attack APCER table |
| R3 | Face authentication vs enrolled user (Flow 03) | **Cloud Match Service** cloud `POST /v1/match` (Rekognition `SearchUsersByImage`, collection `hid-kiosk-users`) + **Edge Local Matcher** `edge/ml/matcher.py` / `templates.py` (ArcFace vs the encrypted cache `edge/data/templates.fernet`), decided in `edge/policy/identity.py`: online Rekognition is authoritative with a local cross-check; `match.rekognition.enabled: false` → local matcher with the offline bars; Rekognition error/timeout → that attempt OFFLINE. Enrolment: `/register` (staff with `enrol:write`; `kiosk/public/enroll.html` redirects there) → `POST /v1/enroll`, `GET /v1/admin/users`, `DELETE /v1/enroll/{user_id}` | FAR/FRR + DET curve |
| R4 | Decision ALLOW / REQUEST VERIFICATION / DENY (Decision Outcomes, Flow 04) | **Edge Policy Engine** `edge/policy/engine.py` `evaluate()` (via `edge/policy/runtime.py`) → `DecisionResponse` (`edge/schemas.py`; `decision` `ALLOW`/`STEP_UP`/`DENY` + `reason_codes` from the closed list in `edge/policy/codes.py`); unknown enums and runtime exceptions → DENY `SYSTEM_ERROR`, never HTTP 500; kiosk labels `STEP_UP` as "REQUEST VERIFICATION" (subtitle "step-up") | Reason codes on screen |
| R5 | Decision time: p95 < 2000 ms (image 03) / within 2 s (image 01) (Key Req., Perf. target) | Liveness ‖ match in parallel on the edge (`edge/attempts.py`); schedule evaluated locally on the cloud-signed bundle (no per-attempt WAN hop); cloud match time-boxed (`latency_budget_ms.rekognition_timeout` 700 ms after the frames; with the early probe `POST /v1/attempt/{id}/probe` at face lock, `latency_budget_ms.rekognition_probe_deadline` 1500 ms from probe start), miss → attempt OFFLINE (P7); `latency_ms` on every response; kiosk `POST /v1/attempt/{id}/rendered` beacon for face lock → rendered; `GET /v1/metrics` p50/p95 | Stored: edge server total (synthetic 1280×720 frames, offline, local match; excludes face lock, capture window, cloud and rendering) p50 76.0 ms / p95 106.4 ms, n = 40, `eval/results/latency_edge_1280_20261114T171323Z.md`. Face lock → rendered: **measurement pending** (no stored file yet). Eval: measured p50/p95 with bootstrap CI |
| R6 | Printed photo attack | MiniFASNet PAD (`SPOOF_PASSIVE`: strict majority of frames ≤ `liveness.pad.fail_max`) + deformation challenge when UNSURE; flash and depth D1 flatness designed, not enforced today | APCER (print) |
| R7 | Screen replay (photo) attack | Device detector (`SPOOF_DEVICE_DETECTED`, conf ≥ `liveness.device_detector.fail_conf` 0.40; 0.25–0.40 overlap → UNSURE) + moiré FFT (`SPOOF_MOIRE`, corroborated) + PAD | APCER (screen photo) |
| R8 | Video replay attack | Today: PAD + device detector + moiré, plus the random deformation challenge whenever UNSURE. Designed defence: server-issued random colour sequence (3 colours × ~233 ms in 700 ms) with edge-measured correlation and lag (`SPOOF_FLASH_MISMATCH`), **advisory until kiosk frame timing is re-validated** | APCER (video) |
| R9 | Mask (3D / printed) attack | Mask cues (`MASK_CUE_EDGE`; with depth `MASK_CUE_SHAPE` / `MASK_CUE_RIGID`) → step-up challenge with mandatory mouth/cheek deformation (`edge/policy/challenge.py`, `POST /v1/attempt/{id}/challenge`); random deformation challenge `RANDOM_CHALLENGE` on would-be ALLOWs, shipped on (`challenge.random_rate` 0.15 online / 0.30 offline via `offline.overrides.challenge.random_rate`) | APCER (mask), honest limit for silicone |
| R10 | Handle ≥ 2 spoof types | R6–R9 (4 types + eye-cut paper mask + injection: `edge/policy/injection.py`, `INJECTION_VIRTUAL_CAMERA`) | Per-type results |
| R11 | Low-confidence handling with additional step (recapture / simple action / OTP / manual review) | **Step-up Orchestrator** `edge/policy/stepup.py` + `challenge.py` + `fallback.py`: RECAPTURE (`quality.max_recaptures` 2) → challenge (`POST /v1/attempt/{id}/challenge`) → second factor (`POST /v1/attempt/{id}/fallback`): TOTP, HID card ID (simulated), staff override (manual review), SES email OTP online (`POST /v1/attempt/{id}/otp/send` → cloud `POST /v1/otp/send` / `/v1/otp/verify`); quality exhausted in a low/medium zone → `STAFF_OVERRIDE` manual review (`stepup.methods.quality_exhausted`); optional Rekognition Face Liveness (cloud `POST /v1/liveness/session`) | Demo of STEP_UP path |
| R12 | Show performance per scenario (detection rate, FAR/FRR, decision time) | **Eval harness** (`eval/`) + **Admin/Metrics Dashboard** (`kiosk/src/admin/`, `GET /v1/metrics`, `GET /v1/events`); ISO/IEC 30107-3 APCER/BPCER, rule-of-3 bounds | Dashboard + **Results** slide |
| R13 | Use AWS sandbox | **Cloud API** `cloud/app/` deployed with `cloud/infra/` in the AWS Workshop Studio sandbox, region **us-east-1** only (production would pin ap-south-1 Mumbai for DPDP data residency): EC2 t3.small + API Gateway, Rekognition, DynamoDB (`hid_users`, `hid_decisions`, `hid_state`), S3 SSE-KMS with a 1-day lifecycle, SES email OTP, CloudWatch dashboard `hid-kiosk`; every feature has a degraded path | **AWS architecture** slide; 10 s AWS console view in the demo |
| SC1 | Biometric result + campus access schedule → ALLOW / STEP-UP / DENY | **Schedule Engine** `edge/policy/schedule.py` `evaluate_schedule()` on the newest verified (last valid) bundle: roles × zones × windows, exceptions, holidays, visitor passes, time-aware revocations (REVOKED first); combined in `engine.combine()`; bundle store `edge/offline/bundle.py`, refreshed from cloud `GET /v1/schedule/{kiosk_id}` every 15 min + revocation feed `GET /v1/revocations`; online with a bundle not confirmed for `schedule.online_max_bundle_age_min` 30 → attempt OFFLINE. Demo bundle `config/schedule.demo.json`, signed by `scripts/sign_bundle.py`; demo clock `POST /v1/admin/clock` (DEMO_MODE only) | `SCHEDULE_*` reason codes in demo |
| SC2a | Continue using a safe local decision process | **Edge service** always decides; **Connectivity monitor** `edge/offline/connectivity.py` (heartbeat cloud `GET /v1/health`, 5 s interval, 2000 ms timeout, 3 misses → OFFLINE; SYNCING uses offline rules); `GET /v1/mode`, `POST /v1/admin/mode` (forced switch) | Forced OFFLINE / Wi-Fi off in demo |
| SC2b | Avoid unsafe automatic access | **Offline Policy**: `offline.overrides` in `config/thresholds.yaml` (stricter bars) + code-enforced invariants in `edge/policy/engine.py` (UNSURE, high-risk and stale bundle never auto-ALLOW offline); no valid bundle → DENY `SCHEDULE_BUNDLE_INVALID`; rate limiter `edge/policy/ratelimit.py` | `OFFLINE_*` reason codes |
| SC2c | Provide fallback verification | **Fallback Verifier** `edge/policy/fallback.py`: offline TOTP (real wall time, replay-protected), single-use staff override codes (PBKDF2 hashes in the bundle), HID card ID (simulated, keyed hash; not in high-risk zones offline) · `POST /v1/attempt/{id}/fallback` | Fallback demo |
| SC2d | Store only minimum temporary information | **Offline Store** `edge/offline/store.py`: AES-256-GCM encrypted SQLite, hash-chained minimal records (`RECORD_FIELDS`), no images / embeddings / names / codes, 2-dp scores, 24 h retention (`offline_store.max_retention_hours`) + purge on ack · `GET /v1/admin/store` | Show store contents |
| SC2e | Synchronize decisions when the connection returns | **Sync Agent** `edge/offline/sync.py` → cloud `POST /v1/sync` (≤ 50 items + TOMBSTONE items, `chain_head` / `chain_head_hmac`; response `accepted` / `duplicates` / `rejected` / `flags`); server re-check and alerts in `cloud/app/services/sync_service.py`; manual `POST /v1/admin/sync` | Queue depth → 0 on reconnect |
| T1 | 99.4% liveness detection accuracy (image 03) | Edge Liveness Engine + eval harness (`eval/`) | Liveness accuracy with CI, plus APCER per species (Clopper-Pearson UB; rule of 3 for 0 errors) and BPCER — measured, never rounded up |
| T2 | 99.2% face authentication accuracy (image 03) | Cloud Match Service + Edge Local Matcher | Face-auth accuracy with CI; rank-1 identification rate |
| T3 | 0.2% false acceptance rate (FAR) (image 03) | Local threshold at the 99.8th impostor percentile (dev split; `match.local.calibration_impostor_percentile`); `eval/collect_faces.py` + `eval/compare.py` on consenting team photos | FAR at the operating threshold with 95% UB; trials needed for 0.2% (about 1,497 error-free) stated |
| T4 | 0.6% false rejection rate (FRR) (image 03) | Same operating threshold; step-up instead of DENY in the UNSURE band | FRR with 95% UB; step-up rate; trials needed for 0.6% (about 498 error-free) stated |
| T5 | < 2 s decision time (image 03) | = R5 | = R5 |
| T6 | "Validated across printed photo, screen replay, video, and mask attacks" (image 03) | R6–R9; species print, eye-cut print, phone photo, phone video, laptop replay, paper mask (+ rigid 3D mask stretch tier); virtual-camera injection reported separately | Per-species results table |
| J1 | Problem-Solution Fit 25% (image 02) | Every brief attack type + SC1 + SC2 handled by the policy engine (`docs/DECISION_POLICY.md`, tests in `edge/policy/tests/`) | Demo steps 1–16 (`docs/DEMO_AND_PITCH.md` §1) |
| J2 | Innovation & Creativity 20% (image 02) | Mandatory-deformation step-up, injection layer, colour-flash nonce (built, advisory), own DepthProbe TrueDepth app (built, enabled after H4), random deformation challenge shipped on (`challenge.random_rate` 0.15 online / 0.30 offline), early cloud probe at face lock (live, not yet measured) | **Innovation** slide (`slides/index.html`); demo steps 4–5 |
| J3 | Technical Implementation 25% (image 02) | Local-first edge (FastAPI, `edge/`) + AWS cloud API (`cloud/`); config-driven thresholds; tested policy engine; idempotent sync | **Our answer** and **AWS architecture** slides; `pytest` decision matrix (`docs/POLICY_TEST_CASES.md`, `edge/policy/tests/test_cases.py`) |
| J4 | Functionality & Usability 15% (image 02) | Kiosk UI (`kiosk/src/kiosk/`): decision + plain-language reason + decision time + ONLINE/OFFLINE badge (polls `GET /v1/mode` every 2 s); passive happy path; consent-based enrolment page | Live demo |
| J5 | Presentation & Communication 15% (image 02) | 5-minute script, slides, judge Q&A (`docs/DEMO_AND_PITCH.md`) | Honest metrics with bounds; iBeta Level 1-style (not certified) |
| P1 | Privacy / consent (CLAUDE.md §7; India DPDP Act 2023) | `/register` (staff sign-in with `enrol:write`; `kiosk/public/enroll.html` now redirects there) consent checkbox (DPDP text) → `POST /v1/enroll`; templates encrypted at rest (`edge/data/templates.fernet`, max age 72 h); erasure `DELETE /v1/enroll/{user_id}` (local + cloud); no images stored offline; Rekognition holds consenting team faces only, removed by `cloud/infra/teardown.sh` | Enrolment moment in the demo (step 7) |
