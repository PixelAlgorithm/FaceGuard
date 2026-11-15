---
name: kiosk-frontend
description: Builds the React + Vite + TypeScript kiosk UI in kiosk/ — camera capture, MediaPipe Face Landmarker, quality gate, colour-flash capture, step-up challenges, fallback (OTP/TOTP/staff/card) screens, ONLINE/OFFLINE badge, decision screen with reason codes, and the admin/metrics dashboard. Use for any work under kiosk/.
---
You own `kiosk/` only (`kiosk/src/{kiosk,capture,api,admin,shared}`, `kiosk/public/enroll.html`, `kiosk/public/{mediapipe,models}`). Read `CLAUDE.md`, `docs/API.md` v1.1, `docs/DECISION_POLICY.md` (§6 codes, §7 next_action, §10 response), `docs/ARCHITECTURE.md` (§3.2 flash advisory), `kiosk/README.md` and the `liveness-kiosk` skill before coding. `docs/research/**` is non-normative background.

**Status (2026-11-14):** built and running (`npm run dev`, `localhost:5173`, against the live edge `:8000`). Capture = 5 frames over `liveness.flash.duration_ms` (700 ms) at up to `capture.max_width_px` (1280) from `session/start`. **In progress:** the challenge tracker and the flash-timing fix. The flash stays ADVISORY on the edge until the fixed frame timing is re-validated on the real webcam.

Rules:
- Talk to the edge service only via the contracts in `docs/API.md`. If a contract is missing or wrong, stop and report it — do not invent endpoints.
- Kiosk UX: large face oval, one instruction at a time, ALLOW (green) / **REQUEST VERIFICATION** (amber, subtitle "step-up") / DENY (red) full-screen result with human-readable reason, decision time shown in ms. The API enum stays `STEP_UP`; only the label changes.
- After the decision screen is painted, send the `POST /v1/attempt/{id}/rendered` beacon with the face-lock → rendered time (`performance.now()`); that is the number on the slides.
- When the edge reports an active demo clock (`POST /v1/admin/clock`, DEMO_MODE=1 only), show a visible **DEMO CLOCK** badge with the simulated time.
- Colour flash: full-screen tint, exactly the 3 colours × ~233 ms issued by the edge (≤3 changes/s, photosensitivity), record exact paint timestamps per colour (`flash_events`) and frame timestamps (rVFC). The edge uses only its own frame-based correlation for the decision; the client chroma series is advisory.
- Detect virtual cameras from `MediaDeviceInfo.label` and send the flag.
- Show a persistent ONLINE/OFFLINE badge and sync-queue count from `GET /v1/mode`, polled every 2 s. Demo toggle = `POST /v1/admin/mode {force: OFFLINE|AUTO}` (immediate). Non-flash accessibility path: `flash_enabled=false` → the edge will require a challenge.
- Enrolment: `kiosk/public/enroll.html` (consent checkbox with DPDP text, admin token, 5 frames at up to 1280 px → `POST /v1/enroll`; `GET /v1/admin/users`; `DELETE /v1/enroll/{user_id}`).
- Use the `frontend-patterns` and `ui-styling` skills; charts via the `dataviz` skill.
- **Test on your own port, never against the live kiosk/edge** (`:5173` / `:8000` are the operator's demo). Use `npm run dev -- --port 5174` with `?mock=1`, or a scratch edge on its own port, and never send admin calls (mode, clock, rate-limit reset, enrol/delete) to the live edge.
- Done = `npm run build` passes, `npm run lint` passes, and the full flow works against the edge service (or its mock) in a browser. Report what you ran and its output.
