# kiosk/ — HID entry kiosk UI + operator dashboard

React 19 + Vite 8 + TypeScript + Tailwind 4. MediaPipe Face Landmarker (VIDEO mode) runs in the browser;
the edge service (`edge/`, FastAPI on `http://127.0.0.1:8000`) makes every decision.

## Run

```bash
cd kiosk
npm install            # once
npm run dev            # http://localhost:5173  (predev copies the offline MediaPipe assets)
```

| URL | What |
|---|---|
| `http://localhost:5173/?mock=0` | Kiosk against the real edge (`VITE_EDGE_URL`, default `http://127.0.0.1:8000`) |
| `http://localhost:5173/admin` | **Control panel** behind staff sign-in (tabs: Users & access · Live system · Staff codes · Eval · Staff & roles · Audit log; `#users`, `#system`, `#codes`, `#eval`, `#staff`, `#audit`; a tab shows only when your roles grant one of its permissions). Open it in a **separate window**: a hidden kiosk tab stops processing camera frames |
| `http://localhost:5173/register` | Guided enrolment (consent → details → 5 frames → result). `/enroll.html` redirects here |
| `…/?mock=1`, `…/admin?mock=1` | In-browser mock edge (demo safety net, **dev server / `VITE_ALLOW_MOCK=1` builds only**). **Per tab only** (sessionStorage) with a "SIMULATED EDGE" banner and an Exit link; other tabs stay on the real edge |
| `…/?kiosk=KIOSK_SRV_01` | Kiosk id for this page load only (dev builds). The edge serves only its own `kiosk_id` (`GET /v1/mode`); any other id is refused (409), and the kiosk then drops the override and shows an operator error |

Routing is by **path** only (`/`, `/admin`, `/operator`, `/register`); `#/admin`-style hash routes were removed.
`npm run dev:mock` starts with the mock as the default. Grant camera permission when Chrome asks.

## Staff sign-in and roles (RBAC, design v2 §F)

`/admin`, `/operator` and `/register` require a staff account (`src/shared/auth/`: `AuthProvider`, `useAuth()`,
`<LoginGate requires title>`, `<RequirePermission>`, `<SignedInBadge>`). Create the first admin on the edge machine,
as the edge OS user: `edge/.venv/bin/python -m edge.auth create-user --username ops_admin --display-name "Ops Admin" --role admin --mfa` (`--mfa` enrols the TOTP right away; admin requires MFA)
(the login screen shows this when `GET /v1/auth/status` reports `EMPTY`; `admin` itself is a reserved username).

- Login: username + password (`POST /v1/auth/login`); MFA accounts get a second step with the opaque `mfa_ticket`;
  roles in `AUTH_MFA_REQUIRED_ROLES` (admin, security_officer) enrol TOTP at first sign-in (secret + `otpauth://` URI
  shown as text); a temporary password must be changed first; `429 RATE_LIMITED` shows the wait.
- The UI never derives permissions from role names: it uses `principal.permissions` from `GET /v1/auth/me`. Every
  poll / subscription is enabled by `token && can(perm)`; buttons without the permission say `Needs <permission>`.
  The edge enforces every route regardless (`docs/contracts/admin_access.examples.json` lists each route's `permission`).
- Credentials (`src/api/credentials.ts`): `fgs_…` session tokens and `fgk_…` API keys go in `Authorization: Bearer`;
  anything else is the deprecated shared token in `X-Admin-Token` (accepted only when the edge runs with
  `AUTH_LEGACY_ADMIN_TOKEN=1`; the login screen then offers it). User-initiated requests carry `X-FG-Activity: 1`;
  pointer / keyboard input posts `POST /v1/auth/activity` at most once a minute. Polls and SSE never extend a session.
- Session token: module memory, persisted to sessionStorage `hid.session` only on `/admin`, `/operator`, `/register`.
  The public kiosk route (`/`) wipes `hid.session` and the legacy `hid.adminToken` and logs that session out.
  10 minutes without input signs the console out (the edge's own idle limit is 30 min, absolute 12 h). Any 401 on a
  session request shows "Session expired, sign in again"; the SSE feed stops on 401/403 and on `event: auth`.
- Staff & roles tab (`staff:manage`): create accounts (random temporary password shown once), edit roles,
  disable / enable, reset password, unlock, API keys (1–3 roles, never admin, 1–90 days, key shown once, revoke). Every
  mutation asks for your own password (`confirm_password`). Audit log tab (`audit:read`): `GET /v1/admin/auth/audit`.
- Mock (`?mock=1`, dev only): demo staff `ada` (admin, MFA code 123456), `olivia` (security_officer, MFA enrolment),
  `emma` (enroller), `audra` (auditor), `evan` (evaluator), `nina` (must change password). Any password except `wrong`.

Production build: `?mock`, `?debug`, `?camflip`, `?delegate` and `?kiosk` are ignored (set `VITE_CAMERA_FLIPPED=1` /
`VITE_DELEGATE=cpu|gpu` at build time instead; `VITE_ALLOW_MOCK=1` re-enables the developer tools in a build).
The build carries a Content-Security-Policy `<meta>` (vite.config.ts `hid-csp`): `connect-src 'self'` + the
`VITE_EDGE_URL` origin (+ `VITE_CSP_CONNECT_SRC`, comma-separated), `script-src 'self' 'wasm-unsafe-eval'` (MediaPipe
WebAssembly), `img-src 'self' data: blob:`; the dev server additionally allows inline scripts (React refresh) and `ws:`.

Operator keys on the kiosk: `Esc` reset, `F` fullscreen, `T` take the capture lock
back from /operator, `1`–`9`/`0` mock scenario (mock only).

## Roles and access (signed schedule = single source of truth, API.md v1.4 §3.18)

A person's role, zones and hours come only from the signed campus schedule (cloud master → signed bundle → edge).
Enrolment never assigns a role (`POST /v1/enroll` meta has no role). Registering (`/register` or the Quick enrol
card, shared flow `src/shared/registerFlow.ts`):

1. new person, role / name change, or an ERASED person ("Re-admit and enrol"): `PUT /v1/admin/access/users/{id}`
   `{display, role, consent: true, actor}` **first** (ONLINE only). The edge installs the re-signed bundle in the
   same call; when it reports `bundle.applied: false` the kiosk calls `POST /v1/admin/bundle/refresh` (up to 3x).
   If the person is then not in this kiosk's bundle (`user.in_bundle: false`) nothing is enrolled here;
2. `POST /v1/enroll`; the result shows the schedule role (`schedule_role`), `cloud_state` (`failed` = blocking
   warning, `skipped_offline` = offline note) and `warnings[]`; the TOTP QR only when `totp_active`.

Offline, new people cannot be registered; people already in the installed bundle can enrol (local template).
Kiosk calls (edge proxies, signed-in staff credential; all parsed strictly by `src/api/access.ts`):

| Route | Use |
|---|---|
| `GET /v1/admin/access/users` | users (status ACTIVE/REVOKED/ERASED/NOT_IN_SCHEDULE) + roles + `role_defaults` + zones + `today` (offline: bundle, `read_only` + `read_only_code`) |
| `PUT /v1/admin/access/users/{id}` | create / edit (`zones_add`, `extra_windows` replace; null clears validity) / re-admit (`consent`) / restore (`consent` + `restore`) |
| `POST /v1/admin/access/users/{id}/revoke` | `{reason, actor}`: cloud USER revocation (SCHEDULE_REVOKED, also offline) |
| `POST /v1/admin/access/codes/rotate` | `{staff_id, count, replace_existing, actor}` → `codes[{code_id, code}]` shown once (component state only) |
| `POST /v1/admin/bundle/refresh` | pull + verify + install the newest bundle now |
| `DELETE /v1/enroll/{id}` | DPDP erasure: cloud `deleted` / `queued` (replayed at sync) / `not_configured` |

Hours (R-I) in the Users tab = `role_defaults[role].windows[zone]` (zone permitted) + `extra_windows[zone]` for the
chosen zone / day; "Enforced now here" is the edge's own `today`. Written times are 00:00–23:59 ("All day" =
00:00–23:59). Field limits (R-H) live in `src/shared/accessRules.ts`, identical to the contract. The demo clock
defaults to max(now, `earliest_local`) and warns before an earlier time: that makes the bundle INVALID, so attempts
become STEP_UP `SCHEDULE_BUNDLE_INVALID` (staff override), never DENY.

- **One capturing tab**: the kiosk tab and the opt-in capture on `/operator` share a cross-tab lock
  (`src/shared/captureLock.ts`, Web Locks with a localStorage-lease fallback). `/operator` is an observer by
  default (live feed + per-signal chips + `GET /v1/admin/attempt/{id}/signals`); "Capture on this console" waits
  for the lock, "Take over" pauses the kiosk tab. A hidden kiosk tab releases the lock.
- **Early cloud probe**: right after face lock the kiosk posts the face-lock frame to
  `POST /v1/attempt/{id}/probe` (fire-and-forget, API.md v1.3). `?probe=0` disables it for A/B timing.
- Mock knobs: `?mockslowcloud=1` reports `cloud_match.degraded` (badge "ONLINE · cloud slow – deciding locally").
- Demo identities for /register and /admin come from `config/schedule.demo.json`, generated into
  `src/shared/demoUsers.generated.ts` by `npm run assets` (also runs before `dev` and `build`).

## Checks

```bash
npm run lint           # oxlint
npx tsc --noEmit       # app type-check (npm run typecheck also checks vite.config.ts + scripts/contract-test.ts)
npm test               # contract test (parsers, validators, RBAC route permissions vs docs/contracts/admin_access.examples.json) + unit tests (node --test src/**/*.test.ts)
npm run build          # type-check + contract test + production build -> dist/ (fully offline: wasm + model in dist/)
```

## Offline assets (SC2)

`npm run assets` copies `@mediapipe/tasks-vision` WASM into `public/mediapipe/wasm/` and checks
`public/models/face_landmarker.task` against a pinned SHA-256. It downloads the model only if it is missing.

## Where things are

- `src/kiosk/controller.ts`: the flow as a state machine. Face lock → `session/start` → colour flash
  + 5 frames → `frames` → decision. After that the kiosk follows `next_action.type` of each response:
  RECAPTURE / CHALLENGE / SECOND_FACTOR / OPEN_DOOR / CONTACT_DESK / NONE.
- `src/capture/`: camera + virtual-camera check, MediaPipe engine, quality gate, flash capture,
  challenge trackers.
- `src/api/`: wire types, HTTP client and the mock (`mock.ts`, scenarios in `mockScenarios.ts`).
- `src/admin/`: control panel. Users & access (`UsersAccessPanel`, `AccessEditor`, `EnrolPanel`), Live system
  (`ControlPanel`: mode/sync/demo clock with the bundle rollback warning/random challenge/kiosk id;
  `SystemStatusPanel`: health, policy bars, rate limit, last sync; live SSE feed; offline-store viewer), Staff
  codes (`StaffCodesPanel`), Eval (`EvalContextPanel` with the edge's literal values, metrics).
- `src/shared/accessDirectory.ts`: who-is-who (schedule role vs template role), `applyAccess()`, reason → hint map.
- `src/shared/accessRules.ts`: R-H limits + request validators, R-I hours, R-E demo-clock default, R-A plan.
- Thresholds come from `../config/thresholds.yaml` at build time (`virtual:thresholds`). The kiosk uses them
  only as advisory client gates; the edge re-checks everything.

Mock latencies are simulated. Never quote them. The kiosk-measured decision time is
face lock → decision screen painted, reported to the edge via `POST /v1/attempt/{id}/rendered`.
