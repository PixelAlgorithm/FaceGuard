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
- Contracts: `docs/API.md` v1.5, `docs/DECISION_POLICY.md`, `config/thresholds.yaml`, `docs/POLICY_TEST_CASES.md`.
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
cd kiosk && npm run dev                                 # kiosk http://localhost:5173/?mock=0; staff /admin, /operator, enrolment /register
```
Re-running `scripts/sign_bundle.py` signs `bundle_version` = max(source version, installed version + 1), so the edge
does not reject it as older (an explicit `--version` at or below the installed one is only warned about), and it
overwrites `edge/data/DEMO_CODES.txt` with fresh override codes. Demo-clock times must stay after the bundle's
`issued_at` − 300 s (`cache.clock_rollback_tolerance_s`; use `--now` to stamp an earlier time if needed).
`?mock=0|1` works only in a dev server build or a `VITE_ALLOW_MOCK=1` build (`kiosk/src/config.ts`
`DEV_TOOLS_ALLOWED`); a production build ignores it. `/enroll.html` only redirects to `/register`.
Demo run sheet: `docs/DEMO_AND_PITCH.md`.
Agents and tests use their own ports, never the live `:8000` edge. iPhone depth: `docs/IPHONE_SETUP.md`.
Evaluation: `.claude/skills/pad-evaluation/SKILL.md` and `eval/`.

Staff access (RBAC, `docs/API.md` §0.1) applies to the live `:8000` edge only after the edge restart, and to the
cloud only after the cloud redeploy.

### Upgrading an existing edge (after the restart)

- The legacy `X-Admin-Token` is off by default (`AUTH_LEGACY_ADMIN_TOKEN=0`), so the old admin-token box and
  scripts that send `ADMIN_TOKEN` stop working (401 `UNAUTHORIZED`).
- Create a personal admin with `edge/.venv/bin/python -m edge.auth create-user --username <personal name>
  --display-name "..." --role admin --mfa` ([First admin](#first-admin-bootstrap-and-more-staff); reserved
  usernames such as `admin` are refused). Stop-gap: `AUTH_LEGACY_ADMIN_TOKEN=1` (needs `ADMIN_TOKEN`) turns the
  token back on; each use is audited as `legacy:admin_token` and `/v1/health` reports `legacy_admin_token`.
- Edge → cloud admin calls need `CLOUD_EDGE_PROXY_KEY`, or the legacy `CLOUD_ADMIN_TOKEN`; there is no fallback
  to `ADMIN_TOKEN` ([Edge → cloud credential](#edge--cloud-credential)).
- Eval tools need `FG_EVAL_API_KEY` / `FG_OPS_API_KEY` ([API keys](#api-keys-for-eval-and-bench)).
- `GET /v1/events` and `GET /v1/metrics` now need a credential (`events:read`, `metrics:read`). `GET /v1/mode`
  is the public badge subset; the full status is `GET /v1/admin/mode/detail` (`store:read`).
- `CLOUD_API_URL` must be `https://` unless the host is loopback or `DEMO_MODE=1`; otherwise the edge does not
  start (`edge/config.py` `validate_cloud_url`).
- `EDGE_CORS_ORIGINS` must list the kiosk origin when it is not the Vite dev origin (`http://localhost:5173`,
  `http://127.0.0.1:5173`). A request other than GET / HEAD / OPTIONS with any other `Origin` gets 403
  `FORBIDDEN` reason `ORIGIN_NOT_ALLOWED` (`edge/http_guards.py`).
- Add the host name to `EDGE_EXTRA_ALLOWED_HOSTS` when the kiosk reaches the edge by a name other than
  `127.0.0.1`, `localhost` or `[::1]` (exact names, no wildcard).

### First admin (bootstrap) and more staff

`GET /v1/auth/status` with `store: "EMPTY"` means no staff store exists yet; the login screen then shows the
bootstrap command. Run it on the edge machine as the edge OS user (it works with the edge running or stopped):

```bash
edge/.venv/bin/python -m edge.auth create-user --username <personal name> --display-name "Full Name" --role admin --mfa
```
- The password comes from a `getpass` prompt (asked twice), or from the first stdin line with `--password-stdin`.
- Reserved usernames are refused: `admin`, `root`, `administrator`, `sa`, `test`, `demo`, `system`, `kiosk`
  (`edge/auth/models.py` `RESERVED_USERNAMES`). The account cannot be called `admin`; use a personal name.
- `--mfa` enrols TOTP at once: it prints the secret and `otpauth://` URI once and asks for a 6-digit code.
  Roles in `AUTH_MFA_REQUIRED_ROLES` (default `admin`, `security_officer`) must enrol MFA before they can do
  anything else (403 `MFA_ENROLMENT_REQUIRED`).
- More staff: `create-user ... --role security_officer` (or `enroller`, `auditor`, `evaluator`; 1-3 roles,
  `--temporary` forces a password change at first sign-in), or the Control Panel tab "Staff & roles"
  (`staff:manage`). `list [--json]` shows accounts and keys without secrets. Other commands: `set-password`,
  `set-roles`, `disable`, `enable`, `unlock`, `enable-mfa`, `disable-mfa`, `revoke-api-key`, `rekey --force` (a running
  edge answers 503 until it is restarted with the new `STAFF_STORE_KEY`).
- Exit codes (`edge/auth/cli.py`): 0 ok, 2 usage / validation error, 75 store busy (retry), 1 any other error.

### API keys for eval and bench

```bash
edge/.venv/bin/python -m edge.auth create-api-key --name eval --role evaluator --expires-days 7 --print-key-only                      # -> FG_EVAL_API_KEY
edge/.venv/bin/python -m edge.auth create-api-key --name ops --role security_officer --role evaluator --expires-days 7 --print-key-only  # -> FG_OPS_API_KEY
```
- A key (`fgk_<key_id>.<secret>`) is shown once, lives 1-90 days (default 30) and can never hold role `admin`.
  Put it in `.env` (`chmod 600 .env`); never print it in logs or chat.
- `FG_EVAL_API_KEY` serves `eval/capture.py` and `eval/snapshot_metrics.py`; `FG_OPS_API_KEY` serves
  `eval/scenarios/run_scenarios.py` (`eval/evallib/auth.py`). They exit 5 on a missing or refused (401/403)
  credential. The legacy `ADMIN_TOKEN` is used only with `FG_ALLOW_LEGACY_ADMIN_TOKEN=1`.
- `scripts/bench_latency.py` provisions its own scratch key (1 day) for its scratch edge.

### Staff sign-in (`/admin`, `/operator`, `/register`)

- Sign in with username + password, plus the 6-digit TOTP code when MFA is on. An account with
  `must_change_password` gets the change-password step first; an MFA-required role without MFA gets the
  enrolment step (secret + URI as text, then a code).
- Sessions end after 30 min idle (`AUTH_SESSION_IDLE_MIN`) or 12 h (`AUTH_SESSION_MAX_HOURS`); polls do not
  count as activity. Sessions are in memory, so an edge restart signs everyone out. The browser also signs out
  after 10 min without input, and the public kiosk `/` wipes any staff session it finds (`kiosk/README.md`
  "Staff sign-in and roles").
- `/operator` needs `events:read`, `/register` needs `enrol:write`; `/admin` opens for any signed-in account and
  shows each tab and button only with its permission (`kiosk/src/shared/auth/LoginGate.tsx`, `admin/AdminApp.tsx`).
- There is no admin-token box by default. Only when the edge runs with `AUTH_LEGACY_ADMIN_TOKEN=1` (migration
  aid; audited as `legacy:admin_token`) does the login screen offer a collapsed "legacy shared admin token" field.

### Trust boundary

RBAC protects the HTTP surface only. The edge OS account and its `.env` are fully trusted, and a compromised
kiosk laptop means a compromised `edge_proxy` key. Run the edge as a dedicated OS user that owns `.env` (0600)
and `EDGE_DATA_DIR` (0700). Run the public kiosk browser as a different, non-admin OS user in locked kiosk mode
(no `file://`, devtools or downloads). Open the staff consoles in a separate browser profile. `/v1/health`
reports `degraded_reasons` `env_file_permissive` (`.env` readable by group/other), `legacy_admin_token`,
`auth_unavailable` (staff store unreadable) and `auth_bruteforce` (≥ 20 failed logins in 10 min).
Details: `docs/API.md` §0.1, `docs/ARCHITECTURE.md` §2.1.

### Edge → cloud credential

Mint an `edge_proxy` key bound to the HMAC kiosk, then put the key in the edge `.env` as `CLOUD_EDGE_PROXY_KEY`
and append the printed JSON entry to `CLOUD_API_KEYS_JSON` on the cloud (takes effect after the cloud redeploy):

```bash
cloud/.venv/bin/python -m cloud.tools.apikey --name "edge main" --roles edge_proxy --kiosk-id KIOSK_MAIN_01
```
Without `CLOUD_EDGE_PROXY_KEY` the edge falls back to the legacy `CLOUD_ADMIN_TOKEN` (`X-Admin-Token`).
Key names are at most 64 characters. Cloud deploys refuse a `.env` without per-kiosk `KIOSK_KEYS_JSON` (or
`ALLOW_SHARED_KIOSK_KEY=1` together with `KIOSK_HMAC_KEY`), the same rule the cloud app enforces at startup;
the deploy runbook and its new flags are in `cloud/SANDBOX.md` §14.
