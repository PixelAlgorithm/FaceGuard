# CLAUDE.md — HID Hackathon 2026: "Can You Spot a Spoof?"

You are the lead engineer on a **one-day hackathon build (14 Nov 2026, PES University, Bangalore)**.
**You build the whole system yourself by orchestrating subagents** — no human team split. The human
operator only does physical tasks (being on camera, holding attacks, plugging in the iPhone, AWS login).
Ship a working, demo-able prototype fast. Correctness of the decision logic and honest metrics
beat feature count. When in doubt, pick the simpler option that keeps the demo working.

## 1. The mission (read fully before coding)

Build an **HID entry-kiosk application** that, within **≤ 2 seconds** of face lock:
1. **Capture** a face from a camera.
2. **Liveness**: decide if a real person is present vs a presentation attack
   (printed photo, screen replay of a photo, video replay, 3D/printed mask).
3. **Face authentication**: verify the face matches an enrolled user.
4. **Decision**: return exactly one of **ALLOW / REQUEST VERIFICATION (step-up) / DENY**.

Plus two **surprise challenges** (mandatory — see `docs/SURPRISE_CHALLENGES.md`):
- **SC1 — Access with Campus Schedule**: a live, recognized person is NOT automatically authorized.
  Final decision = BIOMETRIC RESULT + CAMPUS ACCESS SCHEDULE → ALLOW / STEP-UP VERIFICATION / DENY.
- **SC2 — Offline Mode with Safe Access**: when the central service is unreachable the kiosk must
  (a) continue with a safe local decision process, (b) avoid unsafe automatic access,
  (c) provide fallback verification, (d) store only minimum temporary information,
  (e) synchronize decisions when the connection returns.

Full original problem text: `docs/PROBLEM.md`. Images of the brief: `docs/images/`.

## 2. How we are judged (optimise for this)

| Criterion | Weight | What it means for us |
|---|---|---|
| Problem-Solution Fit | 25% | Every spoof type + both surprise challenges visibly handled |
| Technical Implementation | 25% | Clean architecture, AWS + APIs, scalable, feasible |
| Innovation & Creativity | 20% | Colour-flash challenge, risk-adaptive step-up, depth, injection detection |
| Functionality & Usability | 15% | Live demo works, kiosk UI clear, reason codes shown |
| Presentation | 15% | Clear story, honest metrics, answer judges' questions |

Organiser reference targets: liveness accuracy 99.4%, face-auth accuracy 99.2%, FAR 0.2%, FRR 0.6%,
decision < 2 s. We report ISO/IEC 30107-3 metrics (APCER per attack type, BPCER) + FAR/FRR +
p50/p95 latency **with confidence bounds**. Never fake or round-up numbers.

## 3. Architecture (decided — do not re-litigate without a blocker)

```
 Kiosk browser (React + Vite + TS)
   ├─ MediaPipe Face Landmarker: face lock, quality gate, blendshapes (smile/jawOpen/cheekPuff)
   ├─ Colour-flash capture: server-issued random 3–4 colour sequence, ~1 s, sends 3–5 frames
   ├─ Virtual-camera / injection check (device label + frame timing)
   ├─ Connectivity monitor → ONLINE / OFFLINE mode badge
   └─ calls → Local Edge API (always) ──► Cloud API (when online)

 Local Edge Service (FastAPI, Python 3.11, runs on the kiosk laptop)   ← works OFFLINE
   ├─ Liveness: MiniFASNetV2 + MiniFASNetV1SE (ONNX, Apache-2.0) + moiré FFT + device detector
   │            + flash-reflection correlation + iPhone 16 Pro Max TrueDepth depth checks
   │            (available; own free SwiftUI app 'DepthProbe' → JSON to edge — docs/IPHONE_SETUP.md; H4 go/no-go)
   ├─ Local matcher: uniface/ArcFace embeddings vs encrypted local template cache (kiosk's users only)
   ├─ Policy engine: biometric fusion + campus schedule (SC1) + offline rules (SC2)
   ├─ Offline store: encrypted SQLite — sync queue + minimal decision log, TTL purge
   └─ Fallback verification: offline TOTP / staff override code / HID card ID (simulated)

 Cloud (AWS us-east-1 — Workshop Studio sandbox allows only this region; production: ap-south-1 Mumbai)
   ├─ API: FastAPI on EC2 (warm) or Lambda behind API Gateway
   ├─ Rekognition: user vectors (IndexFaces/CreateUser/AssociateFaces, SearchUsersByImage), CompareFaces
   ├─ Rekognition Face Liveness: ONLY for step-up/enrolment (too slow for the 2 s main path)
   ├─ DynamoDB: users, schedules, decisions;  S3 + KMS: short-retention audit images
   ├─ SES email OTP (SMS to India needs TRAI DLT — not possible today)
   └─ CloudWatch: latency + decision metrics;  /sync endpoint for offline queue replay
```

Key principle: **local-first, cloud-enhanced.** The edge service always produces a decision; when
online it also consults Rekognition + the authoritative schedule. This makes SC2 a natural mode,
not a bolt-on.

## 4. Decision logic (source of truth: `docs/DECISION_POLICY.md`)

- Three zones per signal: PASS ≥ hi, FAIL ≤ lo, in-between = UNSURE → REQUEST VERIFICATION.
- Hard spoof evidence (phone in frame, flat depth, flash mismatch, virtual camera, failed challenge) → DENY.
- One mask cue → STEP-UP; ≥ 2 strong mask cues → DENY.
- Step-up challenge must include **mouth/cheek movement** (smile/open-mouth/puff), never blink-only
  (eye-cut paper masks let real eyes blink).
- Then schedule (SC1) is applied; then offline restrictions (SC2). **Fail-secure always.**
- Every decision returns `decision`, `reason_codes[]`, `scores{}`, `latency_ms`, `mode`.

## 5. Repo layout (create as you go)

```
Project/
  CLAUDE.md                 ← this file
  KICKOFF_PROMPT.md         ← prompt used to start sessions
  docs/                     ← PROBLEM, ARCHITECTURE, DECISION_POLICY, SURPRISE_CHALLENGES, BUILD_PLAN, API, research/
  config/                   ← schedule.example.json, thresholds.yaml
  edge/                     ← FastAPI local edge service (liveness, matcher, policy, offline store)
  cloud/                    ← cloud API + AWS deploy scripts (infra/)
  kiosk/                    ← React kiosk UI + admin/metrics dashboard
  depth/                    ← iPhone TrueDepth: ios/DepthProbe app + checks.py (H4 go/no-go)
  eval/                     ← test protocol, capture scripts, metrics, results/
  models/                   ← downloaded ONNX weights (gitignored)
```

## 6. Starter repos (see `docs/research/notes/starter_repos.md`)

- `yakhyo/uniface` (MIT, pip) — detection, quality, MiniFASNet, ArcFace, FAISS.
- `yakhyo/face-anti-spoofing` releases — `MiniFASNetV2.onnx`, `MiniFASNetV1SE.onnx` (Apache-2.0).
  Crop scales MUST match upstream (V2 = 2.7×, V1SE = 4.0×, 80×80). **Verify output index for "real"
  on a real image** (upstream: index 1 = real; some model cards say otherwise).
- `vadimgodev/face-recognition` — FastAPI two-threshold matching reference.
- `aws-samples/rekognition-user-vectors` — `helpers.py` for user vectors.
- `google-ai-edge/mediapipe-samples` → `examples/face_landmarker/js`.
- `@aws-amplify/ui-react-liveness` — step-up only.
- iPhone depth: own SwiftUI app (Record3D streaming is paid → not used). Reference: Apple sample "Streaming depth data from the TrueDepth camera" (TrueDepthStreamer). Setup: `docs/IPHONE_SETUP.md`.
- Colour-flash check: **write our own** (references have no licence; don't copy code).

Never run downloaded code from inside its own directory without reviewing it; pin versions.

## 7. Conventions

- Python 3.11, FastAPI, Pydantic v2, `uv` or `pip -r requirements.txt`, type hints, `ruff`.
  Use the `fastapi-patterns` / `python-patterns` skills when writing backend code.
- Frontend: React + Vite + TypeScript + Tailwind. Use `frontend-patterns` / `ui-styling`.
- All thresholds live in `config/thresholds.yaml` — never hard-code them in logic.
- All times in `Asia/Kolkata`; store UTC ISO-8601 in logs.
- Every endpoint logs `latency_ms`; every decision has reason codes.
- Tests: `pytest` for policy engine (decision matrix + schedule + offline) — these are cheap and the
  policy is where judges will poke. Write them first (`test-driven-development` skill).
- Secrets via `.env` (see `.env.example`); never commit AWS keys.
- Biometric data: no raw images stored offline; templates encrypted at rest (Fernet/AES-GCM);
  S3 objects KMS-encrypted with lifecycle expiry. Mention India DPDP Act 2023 in pitch.

## 8. Honesty rules (important for judging)

- Say "followed an iBeta Level 1-**style** protocol", never "certified".
- Report 0-error results as an upper bound (rule of 3: 0/N → < 3/N at 95%).
- Silicone masks = known limit of RGB; depth "raises the bar", doesn't "solve" masks.
- Licence caveats: InsightFace weights + CelebA-Spoof-trained models are non-commercial.
- Latency numbers must be measured, not estimated, before they go on a slide.

## 9. Skills and subagents

Full map in `SKILLS.md`. Project skills:
- `.claude/skills/liveness-kiosk/SKILL.md` — how to implement each pipeline stage, policy, SC1, SC2.
- `.claude/skills/pad-evaluation/SKILL.md` — test protocol, metrics, demo script, pitch claims.

Subagents (`.claude/agents/`) — build in parallel, each owns one directory:
`kiosk-frontend` (kiosk/), `edge-ml` (edge/), `policy-engine` (edge/policy, edge/offline, config/),
`cloud-aws` (cloud/), `eval-metrics` (eval/), `depth-iphone` (depth/, iPhone available, H4 go/no-go).
Verification (read-only, independent):
- `verifier` — re-runs tests/builds/measurements after every "done" claim; returns PASS/FAIL with evidence.
- `spec-auditor` — requirements coverage + cross-doc/code consistency at kickoff and each checkpoint.
**Rule: nothing is integrated, marked done, or put on a slide until `verifier` returns PASS.**
Orchestration steps: `KICKOFF_PROMPT.md`.

## 10. Current status

- [x] Research complete (`docs/research/`)
- [x] Scaffold edge / kiosk / cloud / eval / depth (all built by subagents; per-workstream tests green)
- [~] Thin end-to-end path (capture → liveness → match → decision) — WORKING live on the operator's
      MacBook webcam; early cloud probe live (policy 2026-11-14.3). Latency: only stored numbers count
      (see `eval/results/`); online face-lock→render with the probe still to be measured + stored.
      Verifier: core path checked (no unsafe ALLOW in ~200 probes); gate re-run pending (doc/slide fixes).
- [~] SC1 schedule engine + SC2 offline mode — implemented; tests stored in
      `eval/results/tests_20261114T1705Z.txt` (edge+policy+offline+depth 1344, cloud 147, eval 129 passed).
      Live: reconnect sync + legacy-record migration observed; verifier gate re-run pending.
- [~] Colour flash ADVISORY (kiosk frame timing to re-validate); moiré + mask-ring ENFORCED, random
      challenge 15%/30% (operator's choice); step-up challenge tracker fixed (real-camera re-check);
      AWS deployed us-east-1 (cloud blue-green redeploy for bundle upload + append-enrol PENDING operator OK)
- [ ] iPhone depth (DepthProbe v0.3.0 built + connected earlier; H4 calibration 10 live vs 10 print pending;
      depth disabled)
- [ ] Eval capture run (reduced ~45-min plan ready in eval/) → APCER/BPCER/FAR/FRR — needs the operator
- [~] Slides (`slides/index.html` + `deck.pdf`, 12+ slides) — sourced-numbers fix in progress

Update this checklist as work progresses.
