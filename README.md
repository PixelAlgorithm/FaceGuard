# FaceGuard — HID Hackathon 2026: "Can You Spot a Spoof?"

**FaceGuard** is a face liveness + face authentication kiosk with campus-schedule authorization (SC1) and safe
offline mode (SC2). Decision ALLOW / REQUEST VERIFICATION (step-up; API enum `STEP_UP`) / DENY in ≤ 2 s
from face lock.

Local-first edge service (FastAPI) on the kiosk laptop + React kiosk UI; cloud in AWS us-east-1
(Workshop Studio sandbox; production would pin ap-south-1 Mumbai); optional iPhone 16 Pro Max depth via
our own DepthProbe app. Claude Code builds everything through subagents; the human operator only does
physical tasks (camera, holding attacks, iPhone, AWS login).

- Proposal: `idea.pdf`
- Start a Claude Code session here and paste `KICKOFF_PROMPT.md`.
- Context for Claude: `CLAUDE.md`, `SKILLS.md`, `.claude/agents/`, `.claude/skills/`, `docs/`.
- Contracts: `docs/API.md` v1.3, `docs/DECISION_POLICY.md`, `config/thresholds.yaml`, `docs/POLICY_TEST_CASES.md`.
- Architecture: `docs/ARCHITECTURE.md`; plan: `docs/BUILD_PLAN.md`; iPhone: `docs/IPHONE_SETUP.md`.

## Status (2026-11-14, ~22:05 IST)

Built and running locally: edge (`127.0.0.1:8000`, plus a depth-only LAN listener on `0.0.0.0:8001`), kiosk
(`http://localhost:5173`; Vite listens on IPv6 only, so `127.0.0.1:5173` refuses), policy engine with SC1 + SC2,
encrypted offline store + sync. The cloud runs in AWS **us-east-1**, because the sandbox allows only that region
(production would pin ap-south-1). It is deployed (2026-11-14 ~10:00 UTC): EC2 t3.small behind API Gateway, DynamoDB,
S3 SSE-KMS with a 1-day lifecycle, SES, and the Rekognition collection `hid-kiosk-users`, which holds `u_prj1` and
`u_tm03` (`u_tm02` is missing). S3 audit-frame upload is **not implemented**. Cloud fixes made since the deploy
(append-mode re-enrolment, optional enrolment e-mail, `PUT /v1/admin/schedule/{kiosk_id}`) are live only after the lead
redeploys. Details: `cloud/SANDBOX.md` §0, `docs/BUILD_PLAN.md` §0. The installed schedule bundle is cloud-issued
**v45** (`KIOSK_MAIN_01` / MAIN_GATE only, so no kiosk switch); it still holds the publicly documented fixture
override codes until the lead uploads v46+ with fresh codes. Re-enrolment on the edge appends a look (≤ 24 templates,
first 5 pinned); the deployed cloud still replaces the user's faces until the redeploy.

Switches that matter for any claim (`config/thresholds.yaml`):
- `liveness.flash.enforce: false`: the colour flash is **ADVISORY**. It is measured on every attempt but does not
  decide, so never claim it stops attacks. Replay defence today = passive PAD + phone/laptop/TV detector + moiré.
- `liveness.moire.enforce: true` (0.40 / 0.70) and `liveness.mask.m2_rgb_enforce: true` (0.50 / 0.75): both enforced.
  Genuine users can score 0.42–0.79 on moiré and spectacle frames 0.35–0.80 on M2, so a genuine attempt can step
  up. No glasses on camera.
- `liveness.depth.enabled: false`: DepthProbe v0.3.0 (sideloaded; a v0.3.1 IPA is built) connects when running, but
  the H4 go/no-go has not been run, so depth has no decision effect.
- `challenge.random_rate: 0.15` online / `0.30` offline (restored at the user's request): a would-be ALLOW can
  become a 2-action challenge, one of SMILE / OPEN_MOUTH plus one of BLINK / TURN_LEFT / TURN_RIGHT (PUFF_CHEEKS was
  removed at the user's request; still accepted by the wire enum, never issued). Demo control:
  `POST /v1/admin/random-challenge` with `AUTO`, `FORCE`, `FORCE_NEXT` (stays armed until a would-be ALLOW uses it,
  then `AUTO`) or `OFF`. The mode is in memory; an edge restart resets it to `AUTO`.
- `match.rekognition.enabled: true`: from the venue the cloud `/v1/match` round trip is about 0.4–1.4 s, so with the
  700 ms budget most online attempts are decided OFFLINE (rule P7, `OFFLINE_MODE`) while the badge says ONLINE
  (`GET /v1/mode` `cloud_match.degraded`). Fix: the **early cloud probe** (`POST /v1/attempt/{id}/probe` at face lock,
  1500 ms deadline from probe start, `docs/API.md` §3.1a) is live since the edge restart with policy 2026-11-14.3;
  its latency effect has not been measured yet.

Measured so far (stored sources only; none of these is an eval result):
- Edge server-side latency (frames received → decision; synthetic 1280×720 frames, offline, local match, policy
  2026-11-14.3; excludes face lock, the 700 ms capture window, Rekognition and rendering): p50 76.0 ms, p95 106.4 ms,
  n = 40 (`eval/results/latency_edge_1280_20261114T171323Z.md`).
- Test suites: edge + policy + offline + depth 1344 passed, cloud 147 passed, eval 129 passed, kiosk tsc / lint /
  build OK, ruff clean (`eval/results/tests_20261114T1705Z.txt`).
- Kiosk face lock → decision on screen (the 2 s number): **measurement pending**, no stored file yet.

No eval capture has been run (`eval/results/runs/` holds only a 0-attempt metrics snapshot), so there are no
APCER/BPCER/FAR/FRR numbers. The iBeta Level 1-style protocol is designed, not yet run.

## Run (operator laptop)

```bash
edge/.venv/bin/python scripts/sign_bundle.py           # FIRST SETUP ONLY (no bundle installed yet): config/schedule.demo.json -> edge/data/bundle.signed.json (v42, 12 h)
edge/.venv/bin/python -m uvicorn edge.app:app --host 127.0.0.1 --port 8000
cd kiosk && npm run dev                                 # kiosk http://localhost:5173/?mock=0, admin /admin?mock=0, enrolment /enroll.html
```
Do not re-run `scripts/sign_bundle.py` with its defaults while the edge holds the cloud bundle v45. It signs v42, which
the edge rejects as older, and it overwrites `edge/data/DEMO_CODES.txt`. A replacement bundle needs `--version 46` (or
higher), and demo-clock times must stay after its `issued_at` − 300 s (use `--now` to stamp an earlier time if needed).
Demo run sheet: `docs/DEMO_AND_PITCH.md`.
Agents and tests use their own ports, never the live `:8000` edge. iPhone depth: `docs/IPHONE_SETUP.md`.
Evaluation: `.claude/skills/pad-evaluation/SKILL.md` and `eval/`.
