# Kickoff prompt — paste this into a new Claude Code session started in `Project/`

---

You are the **lead engineer and orchestrator** for our HID Hackathon 2026 build (one day,
14 Nov 2026). Our challenge: **"Can You Spot a Spoof?" — Face Liveness Detection & Authentication**
for an HID entry kiosk, decision **ALLOW / STEP-UP VERIFICATION / DENY within 2 seconds**, plus two
mandatory **surprise challenges**: **SC1 Access with Campus Schedule** and **SC2 Offline Mode with
Safe Access**.

## Step 0 — Load context (do this before anything else)

Read, in order:
1. `CLAUDE.md` — mission, decided architecture, conventions, honesty rules.
2. `docs/PROBLEM.md` — verbatim brief (main + surprise challenges + judging + targets). Images in `docs/images/`.
3. `docs/ARCHITECTURE.md`, `docs/API.md` — components and contracts.
4. `docs/DECISION_POLICY.md`, `docs/SURPRISE_CHALLENGES.md`, `docs/POLICY_TEST_CASES.md`,
   `config/thresholds.yaml`, `config/schedule.example.json` — decision logic, SC1, SC2.
5. `docs/BUILD_PLAN.md`, `docs/DEMO_AND_PITCH.md` — schedule, workstreams, demo.
6. `SKILLS.md` and `.claude/agents/` — skills to use and the subagents available.
7. Skim `idea.pdf` / `docs/research/basic_idea.txt`; deep detail in `docs/research/FULL_REPORT.md`
   and `docs/research/notes/` (only when needed).

Then reply with: (a) a 10-line summary of what we're building, (b) any contradictions or gaps you
found between the docs, (c) only the questions you truly need answered by me (e.g. the AWS sandbox
access code / credentials). Keep questions minimal.

**Execution model: YOU (Claude) build the entire system end-to-end** using subagents — there is no
human team split; ignore any human-role wording in older docs. I (the operator) only do physical
tasks: sit in front of the camera, hold printed photos / phones / masks, connect the iPhone, enter
AWS credentials, approve prompts. Tell me exactly when you need one of those.

**iPhone 16 Pro Max is available.** Record3D streaming is paid, so we use the FREE route: you
(`depth-iphone`) write a small SwiftUI app "DepthProbe" that reads the front TrueDepth camera and POSTs
1–3 depth frames per attempt to the edge service, where Python runs the depth checks. Xcode 27.2 is installed at /Applications/Xcode.app; the iOS platform is still downloading. Before
building DepthProbe check: `xcode-select -p` points to Xcode (else ask me to run
`sudo xcode-select -s /Applications/Xcode.app/Contents/Developer` and `sudo xcodebuild -license accept`),
`xcodebuild -showsdks` lists iOS, `xcrun devicectl list devices` shows the iPhone. Start `depth-iphone`
only when those pass — don't block the other agents on it. I will add my free Apple ID + enable Developer Mode. Follow `docs/IPHONE_SETUP.md`; H4 go/no-go (drop to roadmap if
Xcode isn't ready by ~H2).

## Step 1 — Verify before building

Spawn **two verification agents in parallel** on the docs alone (no code exists yet), and fix every
BLOCKER/MAJOR finding before Step 2 — doc contradictions are cheapest to fix now:

1. **`spec-auditor`** — build its OWN requirement checklist from the brief images in `docs/images/`
   (do not trust `docs/PROBLEM.md`), then mark each requirement COVERED / PARTIAL / MISSING across
   design docs, `docs/POLICY_TEST_CASES.md`, `docs/DEMO_AND_PITCH.md`, owning agent, and `idea.pdf`.
   Must include both surprise challenges (SC1 schedule; all 5 SC2 bullets).
2. **`verifier`** — cross-document consistency check (run greps / parse YAML+JSON, report file:line):
   reason codes, decision enum spelling, endpoints, thresholds, policy semantics, agent ownership,
   referenced paths exist. Source of truth: `docs/DECISION_POLICY.md` (policy + reason codes),
   `docs/API.md` (endpoints/schemas), `config/thresholds.yaml` (numbers).

Known issues the prep session already spotted — confirm and fix these first:
- `DECISION_POLICY.md` added 11 reason codes (`ACCESS_OK`, `QUALITY_POSE`, `QUALITY_DEPTH_INVALID`,
  `LIVENESS_UNSURE`, `SPOOF_DEPTH_SCALE`, `MASK_CUE_SHAPE`, `MASK_CUE_SPECTRAL`,
  `SCHEDULE_HIGH_RISK_ZONE`, `SCHEDULE_BUNDLE_INVALID`, `RATE_LIMITED`, `SYSTEM_ERROR`) — add them to `docs/API.md`.
- `BUILD_PLAN.md` / `DEMO_AND_PITCH.md` may use `SCHEDULE_GRACE` → must be `SCHEDULE_GRACE_WINDOW`;
  they also reference endpoints (`GET /v1/attempts/{id}`, `GET /v1/events`) that may be missing from `API.md`.
- Schedule bundle signature: HMAC-SHA256 (CLAUDE/.env) vs Ed25519 (`idea.pdf`) — pick one everywhere.
- `MATCH_LOW` means UNSURE → STEP_UP (only `NOT_ENROLLED` is a match FAIL) — ensure all docs agree.
- Challenge failure: clear failure → DENY; "no movement in time" → one retry → DENY. Align `API.md`
  ("two step-ups → DENY", "DENY never overturned by fallback") with `DECISION_POLICY.md`.
- Sync queue cap 72 h (`API.md`) vs offline log TTL ≤ 24 h (SC2 docs) — reconcile.
- MiniFASNet input normalisation (raw 0–255 vs /255) and "real" output index are unverified — the
  startup self-test in the `liveness-kiosk` skill is mandatory.
- If `idea.pdf` changes, edit `docs/idea/idea.html` and re-render with headless Chrome.

## Step 2 — Build with parallel subagents

Follow `docs/BUILD_PLAN.md`, using the `subagent-driven-development` skill. Spawn these agents
**in parallel** (one message, multiple Agent calls), each owning only its own directory:

| Agent | Owns | First deliverable |
|---|---|---|
| `policy-engine` | `edge/policy/`, `edge/offline/`, `config/` | all `docs/POLICY_TEST_CASES.md` rows as passing pytest |
| `edge-ml` | `edge/` (rest) , `scripts/`, `models/` | `/v1/session/start` + `/v1/attempt/{id}/frames` returning real liveness + match signals |
| `kiosk-frontend` | `kiosk/` | camera → quality gate → colour flash → decision screen against edge API (mock first) |
| `cloud-aws` | `cloud/` | `cloud/SANDBOX.md` (what's allowed) within 30 min, then `/v1/match`, `/v1/schedule`, `/v1/sync` |
| `eval-metrics` | `eval/` | capture logger + metrics script working on a dummy CSV |
| `depth-iphone` | `depth/` (incl. `depth/ios/DepthProbe/`) | DepthProbe app on phone posts D0–D4 to edge; D1 rejects a print by hour 4 (go/no-go) |

Rules for orchestration:
- Interfaces are frozen in `docs/API.md` / `docs/DECISION_POLICY.md`. A change to them requires
  updating the doc first and notifying affected agents.
- Agents must not edit outside their owned paths.
- **Every "done" claim goes through the `verifier` agent** (independent, read-only, re-runs tests
  and measurements). Nothing is integrated or put on a slide until the verifier returns PASS.
- At each checkpoint (hour 3 thin E2E, hour 5 SC1+SC2, hour 6 eval, hour 7 freeze) run
  **verifier** on the integrated system AND **spec-auditor** for coverage; fix gaps in priority order.
- Use the `verification-before-completion` skill yourself before reporting progress to me.

## Step 3 — Prove it

`eval-metrics` runs the protocol from the `pad-evaluation` skill, produces `eval/results/SUMMARY.md`
and the dashboard; `verifier` recomputes every number from raw CSVs. Then build the deck with the
`slides` skill following `docs/DEMO_AND_PITCH.md`.

## Non-negotiables

- Final decision ∈ {ALLOW, STEP_UP, DENY} with reason codes and measured `latency_ms`.
- Fail-secure everywhere: errors, missing signals, expired cache, offline + uncertain → never ALLOW.
- SC1: live + recognized + outside schedule → not ALLOW. SC2: all 5 bullets demonstrably met.
- Step-up challenge includes mouth/cheek movement, not blink-only.
- No fabricated metrics; bounds for zero-error results; "iBeta-style", never "certified".
- No secrets committed; no face images or embeddings in offline logs.
- Ask me before any AWS action that costs money outside the sandbox or is hard to undo.

Update the status checklist in `CLAUDE.md` §10 as milestones complete. Report progress to me in
short updates: what's done (verified), what's next, blockers.

---
