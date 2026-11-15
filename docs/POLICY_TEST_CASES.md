# POLICY_TEST_CASES.md — normative test vectors for the policy engine

Every row is a pytest case: initial decisions in `edge/policy/tests/test_cases.py`, step-up continuations in
`test_stepup.py`, RL rows in `test_ratelimit.py`, matrix rows in `test_matrix.py`, properties in
`test_invariants.py`, flash advisory rows in `test_flash_advisory.py`, unit rows in `test_signal_units.py`,
X/D/Y rows in `edge/offline/tests/` (cloud side of Y rows in `cloud/tests/`). H rows (§6b, v1.5 audit fixes) in `edge/policy/tests/test_pf_*.py`, each row naming its test.
Semantics: `docs/DECISION_POLICY.md` policy `2026-11-14.3` (matrix row ids MO*, A*, N*, F*, E*, I*, R*
referenced below; rate limiter §9.7). These IDs are the canonical test IDs used by `docs/BUILD_PLAN.md`
gates and the pad-evaluation skill.
Thresholds: `config/thresholds.yaml`, except the few values the fixture pins (table below: random
challenge rates, flash enforcement, unknown-label rule) so the vectors keep testing those mechanisms whatever
the shipped profile sets (shipped today: random challenge 0.15 / 0.30, flash advisory, unknown label PASS). Schedule data: `config/schedule.example.json` **signed in the test
fixture** with a test HMAC key (unsigned → no verified bundle).

**Assertions:** `decision` exact; `reason_codes` compared as a **set** (exact — no missing, no extra);
`next_action.steps` exact list; `next_action.methods` exact set when listed; `next_action.type` when listed.
Engine functions under test are pure: feed signal results/scores, not images.

## Baseline fixture `B` (every case = B + listed deltas)

| Field | Value |
|---|---|
| mode | ONLINE (connectivity ONLINE; all cloud calls succeed) |
| kiosk | `KIOSK_LIB_01` → zone `LIBRARY` (risk low) |
| t0 / now | `2026-11-14T10:05:00+05:30` (Saturday) = `04:35:00Z` |
| bundle | v42 content, valid signature (= the last valid bundle, LVB). **Stamps:** unless a case says `fixed stamps`, the fixture signs at `now` like `scripts/sign_bundle.py`: `issued_at` = now − 5 min, `expires_at` = issued_at + 12 h, override `valid_until` = expires_at + 24 h (`fallback.staff_override.valid_after_expiry_h`) → FRESH at any t0. `fixed stamps` = the example file as-is: `issued_at` `2026-11-14T02:30:00Z` (08:00 IST) / `expires_at` `2026-11-14T14:30:00Z` (effective expiry 20:00 IST), and override `valid_until` as in the file (`2026-11-15T14:30:00Z`) |
| online bundle refresh | last successful refresh 5 min before now (≤ `online_max_bundle_age_min` 30 → online-usable, MO1) |
| override list | the list of the last bundle that verified (= v42's OVR-001..003). These are the **publicly documented fixture codes** (`48213907`, `75530182`, `19064425`). The vectors run at engine / verifier level: `FallbackVerifier` reads the raw verified bundle (`ctx.lvb`, `edge/policy/tests/test_stepup.py` `Flow`). The running edge instead hands the verifier `BundleStore.decision_bundle`, which **drops documented codes unless `DEMO_MODE=1`** (EO-10, `edge/offline/tests/test_os_bundle.py::test_EO10_documented_codes_never_reach_the_decision_bundle_without_demo_mode` / `::test_EO10_demo_mode_keeps_them`). Rows marked ‡ therefore hold end to end only with `DEMO_MODE=1` or with fresh codes from `POST /v1/admin/access/codes/rotate` |
| quality | 5 frames, all pass (luma 120, lapvar 150, yaw 5°, 1 face), `recapture_count` 0 |
| camera | label `"FaceTime HD Camera"`, frame interval 33 ms monotonic; fixture pins `injection.unknown_label_is_unsure: true` (shipped false; Q09 vs Q25) |
| PAD `P_live` per frame | `[0.95, 0.93, 0.94, 0.92, 0.96]` (mean 0.94) |
| device detector | no box |
| moiré | 0.10 |
| flash | r 0.85 (edge-measured `r_frames`), amplitude 9.0, lag 1 frame, lag std 0.5, order correct. Fixture pins **`liveness.flash.enforce: true`** (shipped false = ADVISORY): every flash row in §2 describes **enforce mode**; advisory-mode rows are §2a. Calibrated bars from the YAML: lag window [0, 8] frames, lag std ≤ 1.5, `min_amplitude` 2.0 |
| depth | disabled (NOT_AVAILABLE) · mask cues: none |
| local match | top1 `u_3c4d` 0.72, top2 `u_1a2b` 0.41 (margin 0.31); first = last frame identity |
| Rekognition | top1 `u_3c4d` 99.6, no runner-up |
| cloud capabilities | Rekognition enabled; SES / EMAIL_OTP available. If SES is denied (`fallback.email_otp.enabled: false`): `on` = {TOTP, CARD, STAFF_OVERRIDE}, `onH` = {TOTP, CARD} (S50) |
| session | `flash_enabled` true (session/start); `DEMO_MODE` 0 (wall clock = real clock) |
| random challenge | injected `rng` stub returns **0.99** (≥ any rate → never fires); fixture pins `challenge.random_rate` 0.15 online / 0.30 offline (= the shipped YAML, restored 2026-11-14 at the operator's request; RC18) |
| rate limiter | `rate_limit.enabled` true, 5 / 180 s / **5 s** lockout (from the YAML), clean, key `KIOSK_LIB_01` · step-up session: none |

`OB` = B with mode OFFLINE (connectivity OFFLINE; no Rekognition; the same installed bundle, offline
thresholds). The schedule is evaluated on the installed bundle in **both** B and OB (no cloud schedule call).
Rate-limiter rows use `t` = monotonic seconds; each attempt's other inputs are those of the referenced case.
Methods shorthands: `on` = {TOTP, CARD, EMAIL_OTP, STAFF_OVERRIDE}; `onH` = {TOTP, CARD, EMAIL_OTP};
`off` = {TOTP, CARD, STAFF_OVERRIDE}; `offH` = {TOTP, STAFF_OVERRIDE}; `stf` = {STAFF_OVERRIDE}.

## 1. Quality, injection, pre-checks

| ID | Base + deltas | Decision | reason_codes | next_action | Row |
|---|---|---|---|---|---|
| Q01 | B | ALLOW | ACCESS_OK | OPEN_DOOR | N1 |
| Q02 | B; luma 40 on all frames | STEP_UP | QUALITY_LOW_LIGHT | RECAPTURE, `hint` more_light, attempts_left 1 | A2 |
| Q03 | B; lapvar 30 on all frames | STEP_UP | QUALITY_BLUR | RECAPTURE | A2 |
| Q04 | B; second face at 0.7× area on frame 2 | STEP_UP | MULTIPLE_FACES | RECAPTURE | A2 |
| Q05 | B; luma 40 all frames; `recapture_count` 2 (LIBRARY, low) | STEP_UP | QUALITY_LOW_LIGHT | type SECOND_FACTOR, steps [SECOND_FACTOR], methods stf, attempts_left 1; schedule not evaluated; candidate null | A3 |
| Q06 | B; 3 frames pass, 2 frames blurred (usable = 3) | ALLOW | ACCESS_OK | OPEN_DOOR (PAD on 3 frames all ≥0.8) | N1 |
| Q07 | B; yaw 35° on 3 frames (usable = 2) | STEP_UP | QUALITY_POSE | RECAPTURE | A2 |
| Q08 | B; camera label `"OBS Virtual Camera"` | DENY | INJECTION_VIRTUAL_CAMERA | NONE | A4 |
| Q09 | B (fixture: `unknown_label_is_unsure` true); camera label `""` (unknown) | STEP_UP | LIVENESS_UNSURE | CHALLENGE | N9 |
| Q10 | B; 5 prior L05 spoof DENYs on this kiosk at t = 0, 10, 20, 30, 40 (lockout until 45); this attempt at t = 42 | DENY | RATE_LIMITED | NONE, `retry_after_s` 3 (= ceil(lockout_until − t); the engine vector injects 40 s left → 40) | A1 |
| Q11 | B; PAD model raises exception | DENY | SYSTEM_ERROR | CONTACT_DESK | A5 |
| Q12 | OB; luma 40 all frames | STEP_UP | QUALITY_LOW_LIGHT, OFFLINE_MODE | RECAPTURE | A2 |
| Q13 ‡ | Q05 → STAFF_OVERRIDE `48213907` (desk staff manual review) | ALLOW | ACCESS_OK, FALLBACK_OK | OPEN_DOOR; `resolved_codes` = {QUALITY_LOW_LIGHT}; log `user_id` null, `fallback` {STAFF_OVERRIDE, s_guard01, OVR-001}; code consumed | R1 |
| Q14 | Q05 → valid TOTP for `u_3c4d` (TOTP not in stf) | STEP_UP | QUALITY_LOW_LIGHT, FALLBACK_FAILED | SECOND_FACTOR, attempts_left 0 | R8 |
| Q15 | B; kiosk `KIOSK_SRV_01` (SERVER_ROOM, high); luma 40; `recapture_count` 2 | DENY | QUALITY_LOW_LIGHT | CONTACT_DESK | A6 |
| Q16 | OB; luma 40; `recapture_count` 2 (LIBRARY) | STEP_UP | QUALITY_LOW_LIGHT, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED | steps [SECOND_FACTOR], methods stf | A3 |
| Q17 ‡ | Q16 → STAFF_OVERRIDE `48213907` | ALLOW | ACCESS_OK, FALLBACK_OK, OFFLINE_MODE | OPEN_DOOR; `resolved_codes` = {QUALITY_LOW_LIGHT}; `user_id` null; `staff_id` s_guard01 | R1 |
| Q18 | OB; `auto_allow_max_risk: low`; kiosk `KIOSK_LAB_01` (medium → treated high); luma 40; `recapture_count` 2 | DENY | QUALITY_LOW_LIGHT, OFFLINE_MODE | CONTACT_DESK | A6 |
| Q19 | B; luma 40; `recapture_count` 2; camera label `"OBS Virtual Camera"` | DENY | INJECTION_VIRTUAL_CAMERA | NONE (injection checked before the manual-review step-up) | A4 |
| Q20 | OB; kiosk `KIOSK_SRV_01`; luma 40; `recapture_count` 2 | DENY | QUALITY_LOW_LIGHT, OFFLINE_MODE | CONTACT_DESK | A6 |
| Q21 | Q05 → wrong override code `00000000` twice | STEP_UP then DENY | {QUALITY_LOW_LIGHT, FALLBACK_FAILED} then {FALLBACK_FAILED} | attempts_left 0 → NONE (the DENY counts toward A1) | R8, R9 |
| Q22 | B; luma 40; `recapture_count` 1 (last recapture) | STEP_UP | QUALITY_LOW_LIGHT | RECAPTURE, attempts_left 0 | A2 |
| Q23 | *withdrawn* — former A7 (device detector before manual review) is not implemented; a quality-exhausted attempt with a phone in frame reaches A3 / A6 and the desk staff member sees it | — | — | — | — |
| Q24 | Q13 record synced | — | — | cloud raises `ALERT_OVERRIDE_USED` for the STAFF_OVERRIDE ALLOW (online and offline; `cloud/tests/test_sync.py`); kiosk `display_message` "Please see the desk staff for a manual check" | R1 / P8 |
| Q25 | B with the **shipped** YAML (no fixture pins); camera label `"MacBook Pro Camera"` or `""` | ALLOW | ACCESS_OK | OPEN_DOOR (unknown non-virtual label alone no longer steps up); label `"OBS Virtual Camera"` → DENY INJECTION_VIRTUAL_CAMERA | N1 / A4 |

## 2. Liveness fusion

Flash rows (L07–L12, L14, L15, LCAL*) describe **enforce mode** (`liveness.flash.enforce: true`, pinned
by the fixture). The shipped YAML runs the flash ADVISORY; see §2a.

| ID | Base + deltas | Decision | reason_codes | next_action | Row |
|---|---|---|---|---|---|
| L01 | B; PAD `[0.10, 0.20, 0.15, 0.90, 0.25]` | DENY | SPOOF_PASSIVE | NONE | N12 |
| L02 | B; PAD `[0.85, 0.82, 0.60, 0.50, 0.81]` (exactly 3 ≥ 0.80) | ALLOW | ACCESS_OK | OPEN_DOOR | N1 |
| L03 | B; PAD `[0.85, 0.82, 0.60, 0.50, 0.70]` (2 pass, 0 fail) | STEP_UP | LIVENESS_UNSURE | steps [CHALLENGE] | N9 |
| L04 | B; PAD `[0.10, 0.20, 0.90, 0.92, 0.95]` (2 spoof-like frames = not a majority, 3 pass) | STEP_UP | LIVENESS_UNSURE | steps [CHALLENGE] (PASS needs ≤ 1 frame ≤ 0.30) | N9 |
| L05 | B; device box `cell phone` conf 0.62 containing face | DENY | SPOOF_DEVICE_DETECTED | NONE | N12 |
| L06 | B; device box conf 0.30 overlapping face | STEP_UP | LIVENESS_UNSURE | steps [CHALLENGE] | N9 |
| L06b | B; device box conf 0.62 covering < 80 % of the face box (not FAIL) | STEP_UP | LIVENESS_UNSURE | steps [CHALLENGE] (any box ≥ 0.25 that is not FAIL → UNSURE; unit test `test_device_high_conf_without_containment_is_unsure`) | N9 |
| L07 | B; flash r 0.12, amplitude 9.0 | DENY | SPOOF_FLASH_MISMATCH | NONE | N12 |
| L08 | B; flash r 0.85 but lag 9 frames (`lag_max_frames` + 1; window [0, 8]) | DENY | SPOOF_FLASH_MISMATCH | NONE | N12 |
| L09 | B; flash r 0.50 | STEP_UP | LIVENESS_UNSURE | steps [CHALLENGE] | N9 |
| L10 | B; flash amplitude 1.5 (< `min_amplitude` 2.0: bright room), r 0.10 (noise) | ALLOW | ACCESS_OK | OPEN_DOOR (ambient exception: PAD pass, mean 0.94 ≥ 0.90, no device box, moiré 0.10) | N1 |
| L11 | L10 with PAD `[0.85, 0.84, 0.83, 0.86, 0.82]` (mean 0.84 < 0.90) | STEP_UP | LIVENESS_UNSURE | steps [CHALLENGE] | N9 |
| L12 | OB; flash amplitude 1.5 (exception disabled offline) | STEP_UP | LIVENESS_UNSURE, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED | steps [CHALLENGE, SECOND_FACTOR], methods off | F5 |
| LCAL1 | B; flash r 0.90, lag 7 frames, lag std 1.05 (genuine operator-webcam values, 2026-11-14) | ALLOW | ACCESS_OK | OPEN_DOOR (inside the calibrated window [0, 8], std ≤ 1.5) | N1 |
| LCAL2 | B; flash r 0.90, lag 9 frames | DENY | SPOOF_FLASH_MISMATCH | NONE (replay lag outside [0, 8]) | N12 |
| LCAL3 | B; flash r 0.90, amplitude 2.5 (≥ `min_amplitude` 2.0) | ALLOW | ACCESS_OK | OPEN_DOOR (plain flash PASS) | N1 |
| LCAL4 | B; flash r 0.90, amplitude 1.5 (WEAK) | ALLOW | ACCESS_OK | OPEN_DOOR via the online ambient exception (`signals.flash` = PASS_AMBIENT: PAD mean 0.94, clean device, moiré 0.10) | N1 |
| LCAL4O | OB; as LCAL4 | STEP_UP | LIVENESS_UNSURE, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED | steps [CHALLENGE, SECOND_FACTOR], methods off (no ambient exception offline) | F5 |
| LCAL5 | B; flash r 0.90, `lag_frames` 1 but `lag_ms` 233 @ 30 fps (= 7.0 frames) / 300 @ 30 fps (= 9.0) / 175 @ 40 fps (= 7.0); lag std 20 ms | ALLOW / DENY SPOOF_FLASH_MISMATCH / ALLOW | — | `lag_ms` × fps / 1000 overrides `lag_frames` when both are sent | N1 / N12 |
| L13 | B; moiré 0.80 (PAD pass, flash pass → not corroborated) | STEP_UP | LIVENESS_UNSURE | steps [CHALLENGE] | N9 |
| L14 | B; moiré 0.80 + flash r 0.50 | DENY | SPOOF_MOIRE | NONE | N12 |
| L15 | B; device conf 0.62 **and** flash r 0.12 | DENY | SPOOF_DEVICE_DETECTED, SPOOF_FLASH_MISMATCH | NONE | N12 |
| L16 | B; depth enabled, D0 0.90, D1 RMS 1.8 mm | DENY | SPOOF_FLAT_DEPTH | NONE | N12 |
| L17 | B; depth enabled, D0 0.30 | STEP_UP | QUALITY_DEPTH_INVALID | RECAPTURE | A2 |
| L18 | B; depth enabled, D0 0.90, D1 9 mm, D2 6 mm, D3 22 mm, D4 IPD 30 mm (absolute) | DENY | SPOOF_DEPTH_SCALE | NONE | N12 |
| L19 | B; depth enabled, all D pass | ALLOW | ACCESS_OK | OPEN_DOOR | N1 |
| L20 | B; `flash_enabled` false (non-flash accessibility path) → flash NOT_AVAILABLE; PAD mean 0.94 | STEP_UP | LIVENESS_UNSURE | steps [CHALLENGE] (ambient exception does not apply; RNG not consulted) | N15 |
| L21 | L20 → CHALLENGE passed (as C02) | ALLOW | ACCESS_OK | OPEN_DOOR; `resolved_codes` = {LIVENESS_UNSURE} | R2 |
| L22 | OB; `flash_enabled` false | STEP_UP | LIVENESS_UNSURE, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED | steps [CHALLENGE, SECOND_FACTOR], methods off | F10 |
| L23 | B; `flash_enabled` false; moiré 0.80 (flash ≠ PASS → corroborated) | DENY | SPOOF_MOIRE | NONE | N12 |
| L24 | B; `flash_enabled` false; Rahul `u_7a8b` / SRV / Sat 14 Nov 10:00 | STEP_UP | LIVENESS_UNSURE, SCHEDULE_HIGH_RISK_ZONE | steps [CHALLENGE, SECOND_FACTOR], methods onH | N15 → N10 |
| L25 | B; `liveness.flash.enabled: false` (global), `flash_enabled` true | STEP_UP | LIVENESS_UNSURE | steps [CHALLENGE] | N15 |
| L26 | L10 + moiré 0.45 (ambient exception needs moiré < 0.40) | STEP_UP | LIVENESS_UNSURE | steps [CHALLENGE] (unit test `test_ambient_exception_needs_clean_device_and_low_moire_r12`) | N9 |
| L27 | L10 + device box conf 0.30 overlapping face (ambient exception needs device PASS) | STEP_UP | LIVENESS_UNSURE | steps [CHALLENGE] (same unit test) | N9 |

### 2a. Flash ADVISORY mode (`liveness.flash.enforce: false`, the shipped setting) — `test_flash_advisory.py`

The flash is measured and reported (`signals.flash` = `ADVISORY_<zone>`, `scores.flash_r` / `flash_amp`)
but has no decision effect; for moiré corroboration it counts as PASS.

| ID | Base + deltas (advisory) | Decision | reason_codes | next_action / note | Row |
|---|---|---|---|---|---|
| LA01 | B; flash r 0.12 (FAIL in enforce mode, L07) | ALLOW | ACCESS_OK | OPEN_DOOR; `signals.flash` ADVISORY_FAIL | N1 |
| LA02 | B; flash lag 20 frames, or colour order wrong (FAIL in enforce mode) | ALLOW | ACCESS_OK | OPEN_DOOR | N1 |
| LA03 | B; flash r 0.50 (UNSURE in enforce mode, L09) | ALLOW | ACCESS_OK | OPEN_DOOR; ADVISORY_UNSURE | N1 |
| LA04 | B; flash amplitude 1.5, r 0.10 (WEAK) | ALLOW | ACCESS_OK | OPEN_DOOR; ADVISORY_WEAK | N1 |
| LA05 | OB; flash amplitude 1.5 (WEAK; no ambient exception offline) | ALLOW | ACCESS_OK, OFFLINE_MODE | OPEN_DOOR (advisory applies offline too) | F1 |
| LA06 | B; no flash measurement at all | ALLOW | ACCESS_OK | OPEN_DOOR (enforce mode: STEP_UP) | N1 |
| LA07 | B; `flash_enabled` false (non-flash path), or `liveness.flash.enabled: false` | STEP_UP | LIVENESS_UNSURE | steps [CHALLENGE] — NOT_AVAILABLE still requires a challenge | N15 |
| LA08 | B; moiré 0.80 + flash r 0.12 (PAD pass) | STEP_UP | LIVENESS_UNSURE | steps [CHALLENGE] (moiré not corroborated: advisory flash counts as PASS; enforce mode → DENY SPOOF_MOIRE, SPOOF_FLASH_MISMATCH) | N9 |
| LA09 | B; moiré 0.80 + PAD as L03 | DENY | SPOOF_MOIRE | NONE (PAD ≠ PASS corroborates) | N12 |
| LA10 | B; L05 phone + flash r 0.12 | DENY | SPOOF_DEVICE_DETECTED | NONE (other hard evidence unaffected) | N12 |
| LA11 | thresholds without an `enforce` key; flash r 0.12 | DENY | SPOOF_FLASH_MISMATCH | NONE (missing key = enforce) | N12 |

## 3. Mask cues and challenge

| ID | Base + deltas | Decision | reason_codes | next_action | Row |
|---|---|---|---|---|---|
| M01 | B; M2 ring score 0.60 (weak) | STEP_UP | MASK_CUE_EDGE | steps [CHALLENGE], challenge has 1 deformation action (shipped `challenge.deformation_actions`: SMILE / OPEN_MOUTH; PUFF_CHEEKS is wire-only, never issued) | N9 |
| M02 | B; depth on; M2 depth step 12 mm (strong) + M3 RMS 9 mm (strong) | DENY | MASK_CUE_EDGE, MASK_CUE_SHAPE | NONE | N12 |
| M03 | B; M2 strong (ring 0.80) only | STEP_UP | MASK_CUE_EDGE | steps [CHALLENGE] | N9 |
| M04 | B; M2 weak 0.55 + M3 weak 6.5 mm | STEP_UP | MASK_CUE_EDGE, MASK_CUE_SHAPE | steps [CHALLENGE] | N9 |
| C01 | every issued challenge (property test, 1 000 draws) | — | — | exactly 2 actions; exactly 1 deformation; never [BLINK] alone; nonce unique | §7.1 |
| C02 | L03 → submit CHALLENGE: smile rise 0.55 (abs 0.62) at 400 ms, turn left 20° at 700 ms | ALLOW | ACCESS_OK | OPEN_DOOR; `resolved_codes` = {LIVENESS_UNSURE} | R2 |
| C03 | M01 → submit CHALLENGE: smile blendshape 0.60, depth M1 mouth residual 1.2 mm | DENY | MASK_CUE_RIGID | NONE | R5 |
| C04 | L03 → submit CHALLENGE: response starts 80 ms after prompt | DENY | CHALLENGE_FAILED | NONE | R4 |
| C05 | L03 → submit CHALLENGE: TURN_RIGHT performed when TURN_LEFT asked | DENY | CHALLENGE_FAILED | NONE | R4 |
| C06 | M01 (eye-cut paper mask) → CHALLENGE: blink ok, smile rise 0.05 (no deformation in 1 500 ms) | STEP_UP | MASK_CUE_EDGE, CHALLENGE_FAILED | steps [CHALLENGE] (new nonce), attempts_left 0 | R6 |
| C07 | C06 → second CHALLENGE also no deformation | DENY | CHALLENGE_FAILED | NONE | R7 |
| C08 | L03 → CHALLENGE submitted 130 s after STEP_UP | DENY | CHALLENGE_FAILED | NONE | R10 |
| C09 | S01 → correct TOTP for `u_3c4d` submitted 130 s after STEP_UP (SECOND_FACTOR pending) | DENY | FALLBACK_FAILED | NONE | R10 |
| C10 | I06 → CHALLENGE passed at 20 s, TOTP submitted 125 s after the original STEP_UP (TTL counts from the STEP_UP, not from the challenge) | DENY | FALLBACK_FAILED | NONE | R3 → R10 |
| C11 | `POST /v1/attempt/att_UNKNOWN/challenge` (no such attempt) | HTTP 404 `ATTEMPT_NOT_FOUND` | — | no DecisionResponse, no log record, rate limiter unchanged | §9.6 |
| C12 | I06 (CHALLENGE pending) → `POST …/fallback` with a TOTP | HTTP 409 `INVALID_STATE` | — | session unchanged (still CHALLENGE pending, attempts_left 1) | §9.6 |
| C13 | C02 (ALLOW) → another `POST …/challenge` | HTTP 409 `ATTEMPT_CLOSED` | — | no new decision | §9.6 |
| C14 | L03 with `DEMO_MODE` 1 → demo clock moved +3 h (`POST /v1/admin/clock`) at 10 s; CHALLENGE passed at 20 s (real time) | ALLOW | ACCESS_OK | OPEN_DOOR (the session TTL uses the real wall clock (UTC), never the demo clock) | R2 |

### 3a. Random deformation challenge (optional; injected RNG `r`, fires iff r < `challenge.random_rate`)

The shipped YAML has `challenge.random_rate` **0.15 online / 0.30 offline** (restored 2026-11-14 at the
operator's request, "i want that blink and stuff"; it was 0.0 for part of the day). RC01–RC17 run with the
fixture's pinned rates (the same values) so the mechanism stays tested whatever the YAML says; RC18–RC19 pin
the shipped profile and the demo control.

| ID | Base + deltas | Decision | reason_codes | next_action | Row |
|---|---|---|---|---|---|
| RC01 | B; r = 0.05 (forced on) | STEP_UP | RANDOM_CHALLENGE | steps [CHALLENGE] (exactly 1 deformation action, SMILE / OPEN_MOUTH with the shipped list, + 1 of BLINK/TURN_LEFT/TURN_RIGHT), attempts_left 1, no methods | N14 |
| RC02 | B; r = 0.15 (= rate, not <) | ALLOW | ACCESS_OK | OPEN_DOOR | N1 |
| RC03 | B; r = 0.1499 | STEP_UP | RANDOM_CHALLENGE | steps [CHALLENGE] | N14 |
| RC04 | RC01 → CHALLENGE passed | ALLOW | ACCESS_OK | OPEN_DOOR; `resolved_codes` = {RANDOM_CHALLENGE} | R2 |
| RC05 | RC01 → no deformation within 1 500 ms (soft fail) | STEP_UP | RANDOM_CHALLENGE, CHALLENGE_FAILED | steps [CHALLENGE] (new nonce), attempts_left 0 | R6 |
| RC06 | RC05 → second soft fail | DENY | CHALLENGE_FAILED | NONE | R7 |
| RC07 | B; depth enabled, all D pass (rigid 3D mask); r = 0.05 → CHALLENGE: jawOpen 0.55, depth M1 mouth residual 1.0 mm | DENY | MASK_CUE_RIGID | NONE | N14 → R5 |
| RC08 | OB; r = 0.20 (≥ 0.15 online, < 0.30 offline) | STEP_UP | RANDOM_CHALLENGE, OFFLINE_MODE | steps [CHALLENGE], no SECOND_FACTOR, no OFFLINE_FALLBACK_REQUIRED | F9 |
| RC09 | RC08 → CHALLENGE passed | ALLOW | ACCESS_OK, OFFLINE_MODE | OPEN_DOOR; `resolved_codes` = {RANDOM_CHALLENGE} | R2 |
| RC10 | B; r = 0.20 | ALLOW | ACCESS_OK | OPEN_DOOR | N1 |
| RC11 | OB; r = 0.30 | ALLOW | ACCESS_OK, OFFLINE_MODE | OPEN_DOOR | F1 |
| RC12 | B; r = 0.05; Priya / LIB / Sat 14 Nov 07:50 (GRACE) | STEP_UP | SCHEDULE_GRACE_WINDOW | steps [SECOND_FACTOR], methods on; RNG call count 0 | N3 |
| RC13 | B; r = 0.05; PAD as L03 | STEP_UP | LIVENESS_UNSURE | steps [CHALLENGE]; RNG call count 0 | N9 |
| RC14 | B; r = 0.05; L05 phone spoof | DENY | SPOOF_DEVICE_DETECTED | NONE; RNG call count 0 | N12 |
| RC15 | B; `challenge.random_rate: 0` (rate switched off); r = 0.0 | ALLOW | ACCESS_OK | OPEN_DOOR | N1 |
| RC16 | B; `challenge.random_rate: 1.0`; r = 0.99 | STEP_UP | RANDOM_CHALLENGE | steps [CHALLENGE] | N14 |
| RC17 | B (r = 0.99) | ALLOW | ACCESS_OK | OPEN_DOOR; RNG call count exactly 1 | N1 |
| RC18 | B with the **shipped** YAML (rate 0.15 online / 0.30 offline); r = 0.0, then r = 0.99 | STEP_UP, then ALLOW | RANDOM_CHALLENGE, then ACCESS_OK | CHALLENGE, then OPEN_DOOR; one draw each (`test_cases.test_shipped_yaml_random_challenge_restored`) | N14 / N1 |
| RC19 | `POST /v1/admin/random-challenge {"mode": "FORCE" \| "FORCE_NEXT" \| "OFF" \| "AUTO"}` (admin token, `DEMO_MODE=1`) | HTTP 200 | — | runtime mode set, echoed in `GET /v1/mode` `random_challenge`; `{"mode": "BOGUS"}` → 422; no token → 401; `DEMO_MODE=0` → 403 FORBIDDEN (`edge/tests/test_round3.py`, `test_round4.py`). `OFF` = no RNG draw. A forced draw fires whatever the rate (even 0.0). `FORCE_NEXT` stays armed until a would-be ALLOW uses it, then the mode is `AUTO`; the mode is in memory (restart → `AUTO`) | §3.4 |

## 4. Identity match

| ID | Base + deltas | Decision | reason_codes | next_action | Row |
|---|---|---|---|---|---|
| I01 | B; Rekognition 92.0 | STEP_UP | MATCH_LOW | steps [SECOND_FACTOR], methods on | N9 |
| I02 | B; Rekognition 99.5, runner-up `u_1a2b` 85.0 | STEP_UP | MATCH_AMBIGUOUS | steps [SECOND_FACTOR], methods on | N9 |
| I03 | B; Rekognition no UserMatches; local top1 0.22 | DENY | NOT_ENROLLED | CONTACT_DESK | N13 |
| I04 | B; Rekognition `u_3c4d` 99.6 but local top1 `u_1a2b` 0.61 | STEP_UP | MATCH_AMBIGUOUS | steps [SECOND_FACTOR] | N9 |
| I05 | B; last frame local top1 = `u_1a2b` (identity switch) | STEP_UP | MATCH_AMBIGUOUS | steps [SECOND_FACTOR] | N9 |
| I06 | B; PAD as L03 **and** Rekognition 92.0 | STEP_UP | LIVENESS_UNSURE, MATCH_LOW | steps [CHALLENGE, SECOND_FACTOR], methods on | N9 |
| I07 | B; Rekognition call times out (> 700 ms) | ALLOW | ACCESS_OK, OFFLINE_MODE | OPEN_DOOR; response `mode` = OFFLINE; heartbeat miss recorded | F1 / P7 |
| I08 | OB; local top1 0.53 (≥ online 0.50, < offline 0.55) | STEP_UP | MATCH_LOW, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED | steps [SECOND_FACTOR], methods off | F5 |
| I09 | OB; local top1 0.70, top2 0.58 (margin 0.12 < 0.15) | STEP_UP | MATCH_AMBIGUOUS, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED | steps [SECOND_FACTOR], methods off | F5 |
| I10 | OB; unknown person, local top1 0.18 | DENY | NOT_ENROLLED, OFFLINE_MODE | CONTACT_DESK | F8 |
| I11 | B; device conf 0.62 + Rekognition no match | DENY | SPOOF_DEVICE_DETECTED, NOT_ENROLLED | NONE | N12 |
| I12 | B; `match.rekognition.enabled: false` (sandbox IAM denies Rekognition) | ALLOW | ACCESS_OK | OPEN_DOOR; `mode` ONLINE; local matcher with offline bars (0.72 ≥ 0.55, margin 0.31 ≥ 0.15); no heartbeat miss | N1 |
| I13 | I12; local top1 0.53 (≥ 0.50 online bar, < 0.55 offline bar) | STEP_UP | MATCH_LOW | steps [SECOND_FACTOR], methods on; `mode` ONLINE | N9 |
| I14 | B; Rekognition returns AccessDenied (enabled, error during attempt) | ALLOW | ACCESS_OK, OFFLINE_MODE | OPEN_DOOR; `mode` OFFLINE; heartbeat miss recorded | F1 / P7 |

## 5. Schedule (SC1) — B with identity/kiosk/time deltas

| ID | Who / kiosk / local time | Decision | reason_codes | next_action | Row |
|---|---|---|---|---|---|
| S01 | Priya `u_3c4d` / LIB / Sat 14 Nov 07:50 | STEP_UP | SCHEDULE_GRACE_WINDOW | steps [SECOND_FACTOR], methods on | N3 |
| S02 | S01 → TOTP correct for `u_3c4d` | ALLOW | ACCESS_OK, FALLBACK_OK | OPEN_DOOR | R1 |
| S03 | S01 → TOTP for `u_1a2b` (wrong user), then correct `u_3c4d` TOTP | STEP_UP then ALLOW | {SCHEDULE_GRACE_WINDOW, FALLBACK_FAILED} then {ACCESS_OK, FALLBACK_OK} | attempts_left 0 → OPEN_DOOR | R8, R1 |
| S04 | Priya / LIB / Sat 14 Nov 07:40 (20 min early) | DENY | SCHEDULE_OUTSIDE_WINDOW | NONE | N4 |
| S05 | Priya / LAB / Sat 14 Nov 20:30 (EXC-HACK-2026) | ALLOW | ACCESS_OK | OPEN_DOOR | N1 |
| S06 | Priya / LAB / Sun 15 Nov 11:00 | DENY | SCHEDULE_OUTSIDE_WINDOW | NONE | N4 |
| S07 | Priya / LAB / Mon 16 Nov 10:00 (EXC-LABS-CLOSED-EXAM) | DENY | SCHEDULE_OUTSIDE_WINDOW | NONE | N4 |
| S08 | Priya / LIB / Wed 18 Nov 23:30 (EXC-EXAM-NOV26 replace 06:00–24:00) | ALLOW | ACCESS_OK | OPEN_DOOR | N1 |
| S09 | Priya / HOSTEL / Sat 14 Nov 21:00 | DENY | SCHEDULE_ZONE_NOT_PERMITTED | CONTACT_DESK | N6 |
| S10 | Aarav `u_1a2b` / HOSTEL / Sat 14 Nov 23:10 | STEP_UP | SCHEDULE_GRACE_WINDOW | steps [SECOND_FACTOR], methods on | N3 |
| S11 | Aarav / HOSTEL / Sat 14 Nov 23:20 | DENY | SCHEDULE_OUTSIDE_WINDOW | NONE | N4 |
| S12 | Aarav / HOSTEL / Sun 15 Nov 00:30 (yesterday's grace must not leak past 23:15) | DENY | SCHEDULE_OUTSIDE_WINDOW | NONE | N4 |
| S13 | Rahul `u_7a8b` / SRV / Sat 14 Nov 10:00 (EXC-SRV-HACK) | STEP_UP | SCHEDULE_HIGH_RISK_ZONE | steps [SECOND_FACTOR], methods onH | N2 |
| S14 | S13 → STAFF_OVERRIDE submitted (not in onH) | STEP_UP | SCHEDULE_HIGH_RISK_ZONE, FALLBACK_FAILED | attempts_left 0 | R8 |
| S15 | Rahul / SRV / Sat 14 Nov 08:55 (high-risk grace = 0) | DENY | SCHEDULE_OUTSIDE_WINDOW | NONE | N4 |
| S16 | Dr. Meera `u_5e6f` / SRV / Mon 16 Nov 11:00 | DENY | SCHEDULE_ZONE_NOT_PERMITTED | CONTACT_DESK | N6 |
| S17 | Kiran `u_a3b4` (revoked) / MAIN / Sat 14 Nov 09:00 | DENY | SCHEDULE_REVOKED | CONTACT_DESK | N8 |
| S18 | Ananya `u_e1f2` (visitor) / LAB / Sat 14 Nov 15:00 | ALLOW | ACCESS_OK | OPEN_DOOR | N1 |
| S19 | Ananya / LAB / Sat 14 Nov 18:10 (pass ended 18:00; no grace past pass) | DENY | SCHEDULE_NO_ENTITLEMENT | CONTACT_DESK | N5 |
| S20 | Ananya / LIB / Sat 14 Nov 11:00 (pass zones exclude LIBRARY) | DENY | SCHEDULE_ZONE_NOT_PERMITTED | CONTACT_DESK | N6 |
| S21 | Suresh `u_9c0d` (contractor) / LAB / Fri 20 Nov 10:00 (Campus Closure Day) | DENY | SCHEDULE_HOLIDAY | NONE | N7 |
| S22 | Rahul (staff, exempt) / LAB / Fri 20 Nov 10:00 | ALLOW | ACCESS_OK | OPEN_DOOR | N1 |
| S23 | Suresh / LAB / Tue 1 Dec 10:00 (valid_until 30 Nov) | DENY | SCHEDULE_NO_ENTITLEMENT | CONTACT_DESK | N5 |
| S24 | Neha `u_c5d6` / LIB / Sun 15 Nov 08:00 (extra_windows) | ALLOW | ACCESS_OK | OPEN_DOOR | N1 |
| S25 | Rahul / LIB / Sun 15 Nov 08:00 | DENY | SCHEDULE_OUTSIDE_WINDOW | NONE | N4 |
| S26 | Neha / LAB / Mon 16 Nov 10:00 (zones_remove LAB_BLOCK) | DENY | SCHEDULE_ZONE_NOT_PERMITTED | CONTACT_DESK | N6 |
| S27 | Rekognition match `u_zz99` 99.7 (enrolled, absent from bundle); local top1 `u_1a2b` 0.25 (below the 0.50 `identity.cross_check_conflict_min_cosine` bar, so no `MATCH_AMBIGUOUS`) | DENY | SCHEDULE_NO_ENTITLEMENT | CONTACT_DESK | N5 |
| S28 | L03 signals (BIO_UNSURE) + Priya / LAB / Sun 15 Nov 11:00 | DENY | LIVENESS_UNSURE, SCHEDULE_OUTSIDE_WINDOW | CONTACT_DESK; display generic | N11 |
| S29 | L03 signals + Priya / LIB / Sat 14 Nov 07:50 (GRACE) | DENY | LIVENESS_UNSURE, SCHEDULE_GRACE_WINDOW | CONTACT_DESK | N11 |
| S30 | L05 (phone spoof) with candidate Kiran (revoked) | DENY | SPOOF_DEVICE_DETECTED | NONE; schedule not evaluated; `candidate_user_id` = u_a3b4 logged | N12 |
| S31 | L03 signals + Rahul / SRV / Sat 14 Nov 10:00 | STEP_UP | LIVENESS_UNSURE, SCHEDULE_HIGH_RISK_ZONE | steps [CHALLENGE, SECOND_FACTOR], methods onH | N10 |
| S32 | `high_risk_requires_stepup_online: false`; Rahul / SRV / Sat 10:00 | ALLOW | ACCESS_OK | OPEN_DOOR | N1 (config) |

Window and grace edges (real windows from `config/schedule.example.json`; `start ≤ t < end`, grace
`[start − 15, start)` and `[end, end + 15)`; all times `:00` seconds, IST, B otherwise):

| ID | Who / kiosk / local time | Decision | reason_codes | next_action | Row |
|---|---|---|---|---|---|
| S33 | Priya / LIB / Sat 14 Nov 08:00 (student LIBRARY MON–SAT 08:00–21:00: window start) | ALLOW | ACCESS_OK | OPEN_DOOR | N1 |
| S34 | Priya / LIB / Sat 14 Nov 07:45 (start − grace) | STEP_UP | SCHEDULE_GRACE_WINDOW | steps [SECOND_FACTOR], methods on | N3 |
| S35 | Priya / LIB / Sat 14 Nov 07:44 (one minute before grace) | DENY | SCHEDULE_OUTSIDE_WINDOW | NONE | N4 |
| S36 | Priya / LIB / Sat 14 Nov 20:59 (last in-window minute) | ALLOW | ACCESS_OK | OPEN_DOOR | N1 |
| S37 | Priya / LIB / Sat 14 Nov 21:00 (window end, exclusive) | STEP_UP | SCHEDULE_GRACE_WINDOW | steps [SECOND_FACTOR], methods on | N3 |
| S38 | Priya / LIB / Sat 14 Nov 21:14 (last grace minute) | STEP_UP | SCHEDULE_GRACE_WINDOW | steps [SECOND_FACTOR], methods on | N3 |
| S39 | Priya / LIB / Sat 14 Nov 21:15 (end + grace, exclusive) | DENY | SCHEDULE_OUTSIDE_WINDOW | NONE | N4 |
| S40 | Priya / LIB / Sat 14 Nov 21:16 (one minute beyond) | DENY | SCHEDULE_OUTSIDE_WINDOW | NONE | N4 |
| S41 | Rahul / SRV / Sat 14 Nov 09:00 (EXC-SRV-HACK 09:00–21:00 start; high-risk, grace 0) | STEP_UP | SCHEDULE_HIGH_RISK_ZONE | steps [SECOND_FACTOR], methods onH | N2 |
| S42 | Rahul / SRV / Sat 14 Nov 08:59 | DENY | SCHEDULE_OUTSIDE_WINDOW | NONE | N4 |
| S43 | Rahul / SRV / Sat 14 Nov 20:59 | STEP_UP | SCHEDULE_HIGH_RISK_ZONE | steps [SECOND_FACTOR], methods onH | N2 |
| S44 | Rahul / SRV / Sat 14 Nov 21:00 (end; no grace for high risk) | DENY | SCHEDULE_OUTSIDE_WINDOW | NONE | N4 |
| S51 | Priya / LIB / Thu 19 Nov 00:05 (Wed EXC-EXAM-NOV26 window 06:00–24:00 ends at midnight; grace does not cross midnight, SC1.2) | DENY | SCHEDULE_OUTSIDE_WINDOW | NONE | N4 |
| S52 | Priya / LIB / Thu 19 Nov 05:50 (start-grace of 06:00–24:00, same date) | STEP_UP | SCHEDULE_GRACE_WINDOW | steps [SECOND_FACTOR], methods on | N3 |

Online EMAIL_OTP (SES via cloud; `POST /v1/attempt/{id}/otp/send` then `/fallback`):

| ID | Base + deltas | Decision | reason_codes | next_action | Row |
|---|---|---|---|---|---|
| S45 | S01 → otp/send, then EMAIL_OTP with the correct code | ALLOW | ACCESS_OK, FALLBACK_OK | OPEN_DOOR; log `fallback.method` EMAIL_OTP | R1 |
| S46 | S01 → EMAIL_OTP wrong code | STEP_UP | SCHEDULE_GRACE_WINDOW, FALLBACK_FAILED | SECOND_FACTOR, attempts_left 0 | R8 |
| S47 | S46 → EMAIL_OTP wrong code again | DENY | FALLBACK_FAILED | NONE | R9 |
| S48 | S01 → EMAIL_OTP; cloud verify times out / unreachable | STEP_UP | SCHEDULE_GRACE_WINDOW | SECOND_FACTOR, methods {TOTP, CARD, STAFF_OVERRIDE} (EMAIL_OTP removed for the rest of this step-up), attempts_left 1 (unchanged), no FALLBACK_FAILED; session `mode` stays ONLINE; heartbeat miss recorded; rate limiter unchanged | R11 |
| S48P | policy level: S01 → `resolve_fallback` with EMAIL_OTP and no cloud verdict (`email_otp_verified` None; defence in depth, unreachable through HTTP) | STEP_UP | SCHEDULE_GRACE_WINDOW, FALLBACK_FAILED | SECOND_FACTOR, attempts_left 0; `mode` ONLINE | R8 |
| S49 | S46 → correct TOTP for `u_3c4d` (method switch within the remaining attempt) | ALLOW | ACCESS_OK, FALLBACK_OK | OPEN_DOOR | R1 |
| S50 | B with SES denied (EMAIL_OTP not offered); Priya / LIB / Sat 14 Nov 07:50 | STEP_UP | SCHEDULE_GRACE_WINDOW | steps [SECOND_FACTOR], methods {TOTP, CARD, STAFF_OVERRIDE} | N3 |

## 6. Offline (SC2)

| ID | Base + deltas | Decision | reason_codes | next_action | Row |
|---|---|---|---|---|---|
| O01 | OB | ALLOW | ACCESS_OK, OFFLINE_MODE | OPEN_DOOR | F1 |
| O02 | OB; Priya / LAB (medium) / Sat 14 Nov 11:00 | ALLOW | ACCESS_OK, OFFLINE_MODE | OPEN_DOOR | F1 |
| O03 | OB; `auto_allow_max_risk: low`; Priya / LAB / Sat 11:00 | STEP_UP | OFFLINE_MODE, OFFLINE_HIGH_RISK_ZONE, OFFLINE_FALLBACK_REQUIRED | steps [SECOND_FACTOR], methods offH | F2 |
| O04 | OB; Rahul / SRV / Sat 14 Nov 10:00 | STEP_UP | OFFLINE_MODE, OFFLINE_HIGH_RISK_ZONE, OFFLINE_FALLBACK_REQUIRED | steps [SECOND_FACTOR], methods offH | F2 |
| O05 | O04 → CARD `HID-CARD-1004` (not in offH) | STEP_UP | OFFLINE_MODE, OFFLINE_HIGH_RISK_ZONE, OFFLINE_FALLBACK_REQUIRED, FALLBACK_FAILED | attempts_left 0 | R8 |
| O06 | O04 → valid TOTP for `u_7a8b` | ALLOW | ACCESS_OK, FALLBACK_OK, OFFLINE_MODE | OPEN_DOOR; log `fallback.method` = TOTP | R1 |
| O07 | O04 → wrong TOTP twice | DENY | FALLBACK_FAILED, OFFLINE_MODE | NONE | R9 |
| O08 | O06 then a new attempt reusing the same TOTP time-step | STEP_UP (then DENY on 2nd reuse) | …, FALLBACK_FAILED | replay rejected | R8/R9 |
| O09 ‡ | O04 → STAFF_OVERRIDE `48213907` | ALLOW | ACCESS_OK, FALLBACK_OK, OFFLINE_MODE | OPEN_DOOR; log `staff_id` s_guard01, `code_id` OVR-001; code consumed | R1 |
| O10 ‡ | new attempt → STAFF_OVERRIDE `48213907` again | STEP_UP | …, FALLBACK_FAILED | consumed code rejected | R8 |
| O11 | OB; Priya / LIB / 07:50 (GRACE) | STEP_UP | SCHEDULE_GRACE_WINDOW, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED | steps [SECOND_FACTOR], methods off | F3 |
| O12 | O11 → CARD `HID-CARD-1002` | ALLOW | ACCESS_OK, FALLBACK_OK, OFFLINE_MODE | OPEN_DOOR | R1 |
| O13 | OB; PAD as L03 (also unsure under 0.85 bar) | STEP_UP | LIVENESS_UNSURE, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED | steps [CHALLENGE, SECOND_FACTOR], methods off | F5 |
| O14 | OB; PAD `[0.83, 0.82, 0.84, 0.81, 0.83]` (pass online, unsure offline) | STEP_UP | LIVENESS_UNSURE, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED | steps [CHALLENGE, SECOND_FACTOR] | F5 |
| O15 | O13 → challenge passed only (no second factor yet) | STEP_UP | unchanged | steps [SECOND_FACTOR] remaining | R3 |
| O16 | OB; L03 signals + Priya / LIB / 07:50 | DENY | LIVENESS_UNSURE, SCHEDULE_GRACE_WINDOW, OFFLINE_MODE | CONTACT_DESK | F7 |
| O17 | OB; L05 phone spoof | DENY | SPOOF_DEVICE_DETECTED, OFFLINE_MODE | NONE | F8 |
| O18 | OB; Kiran / MAIN / Sat 09:00 | DENY | SCHEDULE_REVOKED, OFFLINE_MODE | CONTACT_DESK | F4 |
| O19 | OB; `fixed stamps`; now = t0 = Sat 14 Nov 21:00 IST (15:30Z > effective expiry 14:30Z); Priya / MAIN | STEP_UP | SCHEDULE_EXPIRED_CACHE, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED | steps [SECOND_FACTOR], methods stf | E1 |
| O20 | O19 → TOTP valid | STEP_UP | …, FALLBACK_FAILED | TOTP not in stf | R8 |
| O21 ‡ | O19 → STAFF_OVERRIDE `75530182` | ALLOW | ACCESS_OK, FALLBACK_OK, OFFLINE_MODE | OPEN_DOOR | R1 |
| O22 | OB; `fixed stamps`; now 21:00 (expired); Kiran / MAIN | DENY | SCHEDULE_REVOKED, SCHEDULE_EXPIRED_CACHE, OFFLINE_MODE | CONTACT_DESK | E2 |
| O23 | OB; `fixed stamps`; now = t0 = Sat 14 Nov 20:45 IST (15:15Z, expired); Rahul / SRV (stale IN_WINDOW 09:00–21:00, high) | STEP_UP | SCHEDULE_EXPIRED_CACHE, OFFLINE_MODE, OFFLINE_HIGH_RISK_ZONE, OFFLINE_FALLBACK_REQUIRED | methods stf | E1 |
| O24 | OB; **no last valid bundle**: the only bundle (boot file) was tampered (one window edited) and never verified | DENY | SCHEDULE_BUNDLE_INVALID, OFFLINE_MODE | CONTACT_DESK; response `zone` `"UNKNOWN"`, `schedule_result` null, `mode` OFFLINE | I1a |
| O25 | OB; no LVB: unsigned `config/schedule.example.json` loaded as-is | DENY | SCHEDULE_BUNDLE_INVALID, OFFLINE_MODE | CONTACT_DESK; zone `"UNKNOWN"` | I1a |
| O26 | OB; `fixed stamps` (LVB present); kiosk clock `2026-11-13T20:00:00Z` (< issued_at − 300 s, clock rollback) | STEP_UP | SCHEDULE_BUNDLE_INVALID, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED | methods stf | I1b |
| O27 | OB; no LVB (tampered) + L05 phone spoof | DENY | SPOOF_DEVICE_DETECTED, OFFLINE_MODE | NONE (BIO_FAIL first) | I3 |
| O28 | OB; template cache age 80 h (> 72 h) | DENY | NOT_ENROLLED, OFFLINE_MODE | CONTACT_DESK | F8 |
| O29 | O04 (Rahul / SRV, offline); STAFF_OVERRIDE with `staff_id` **`s_guard01` (known to the bundle)**: wrong `11111111`, wrong `22222222` (attempt 1 → DENY FALLBACK_FAILED), new attempt wrong `33333333` (3rd consecutive → `s_guard01` locked 300 s), then the correct `48213907` 1 s later | STEP_UP | FALLBACK_LOCKED, OFFLINE_MODE, OFFLINE_HIGH_RISK_ZONE, OFFLINE_FALLBACK_REQUIRED | SECOND_FACTOR, methods offH, `attempts_left` 0 (unchanged: not counted), `retry_after_s` 299; rejected **without a hash check**; a fresh attempt after the 300 s lock → ALLOW. An unknown or missing `staff_id` never starts this per-staff lock (only the device backstop, H12). `test_stepup.py::test_O29_staff_override_lockout_without_hash_check` | R12 |

Stale online bundle and mode resolution (DECISION_POLICY §5.1, §9.0):

| ID | Base + deltas | Decision | reason_codes | next_action | Row |
|---|---|---|---|---|---|
| O30 | B; connectivity ONLINE, last bundle refresh 31 min ago (bundle still FRESH) | ALLOW | ACCESS_OK, OFFLINE_MODE | OPEN_DOOR; response `mode` OFFLINE; Rekognition not called; no heartbeat miss recorded | MO2 → F1 |
| O31 | B; last refresh exactly 30 min ago | ALLOW | ACCESS_OK | OPEN_DOOR; `mode` ONLINE | MO1 → N1 |
| O32 | B; last refresh 45 min ago; Rahul / SRV / Sat 14 Nov 10:00 | STEP_UP | OFFLINE_MODE, OFFLINE_HIGH_RISK_ZONE, OFFLINE_FALLBACK_REQUIRED | steps [SECOND_FACTOR], methods offH | MO2 → F2 |
| O33 | B; last refresh 45 min ago; PAD `[0.83, 0.82, 0.84, 0.81, 0.83]` (pass online, unsure offline) | STEP_UP | LIVENESS_UNSURE, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED | steps [CHALLENGE, SECOND_FACTOR], methods off | MO2 → F5 |
| O34 | B; connectivity ONLINE but no verified bundle at all (boot file and cloud fetch both failed verification) | DENY | SCHEDULE_BUNDLE_INVALID, OFFLINE_MODE | CONTACT_DESK; `mode` OFFLINE, zone `"UNKNOWN"` | MO3 → I1a |
| O35 | B; `fixed stamps`; connectivity ONLINE; now = t0 = Sat 14 Nov 21:00 IST (bundle EXPIRED); Priya / MAIN | STEP_UP | SCHEDULE_EXPIRED_CACHE, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED | steps [SECOND_FACTOR], methods stf | MO3 → E1 |
| O36 | B; last refresh 31 min ago; r = 0.20 (offline rate 0.30 applies) | STEP_UP | RANDOM_CHALLENGE, OFFLINE_MODE | steps [CHALLENGE] | MO2 → F9 |

Matrix rows F6, E3, E4, E5, I2a and offline step-up / last-valid-bundle edges:

| ID | Base + deltas | Decision | reason_codes | next_action | Row |
|---|---|---|---|---|---|
| O37 | OB; PAD as L03; Rahul / SRV / Sat 14 Nov 10:00 | STEP_UP | LIVENESS_UNSURE, OFFLINE_MODE, OFFLINE_HIGH_RISK_ZONE, OFFLINE_FALLBACK_REQUIRED | steps [CHALLENGE, SECOND_FACTOR], methods offH | F6 |
| O38 | OB; `fixed stamps`; now = t0 = Sat 14 Nov 21:00 IST (EXPIRED); PAD as L03; Priya / MAIN (stale IN_WINDOW 06:00–22:00) | STEP_UP | LIVENESS_UNSURE, SCHEDULE_EXPIRED_CACHE, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED | steps [CHALLENGE, SECOND_FACTOR], methods stf | E3 |
| O39 | OB; `fixed stamps`; now 21:00 IST; PAD as L03; Priya / LIB (21:00 = end of 08:00–21:00 → GRACE) | DENY | LIVENESS_UNSURE, SCHEDULE_GRACE_WINDOW, SCHEDULE_EXPIRED_CACHE, OFFLINE_MODE | CONTACT_DESK | E4 |
| O40 | OB; `fixed stamps`; now 21:00 IST; PAD as L03; Kiran `u_a3b4` / MAIN | DENY | LIVENESS_UNSURE, SCHEDULE_REVOKED, SCHEDULE_EXPIRED_CACHE, OFFLINE_MODE | CONTACT_DESK | E4 |
| O41 | OB; `fixed stamps`; now 21:00 IST; L05 phone spoof | DENY | SPOOF_DEVICE_DETECTED, OFFLINE_MODE | NONE | E5 |
| O42 | O24 bundle state (no LVB); PAD as L03 | DENY | LIVENESS_UNSURE, SCHEDULE_BUNDLE_INVALID, OFFLINE_MODE | CONTACT_DESK; zone `"UNKNOWN"` | I2a |
| O43 | O24 bundle state (no LVB); local top1 0.53 | DENY | MATCH_LOW, SCHEDULE_BUNDLE_INVALID, OFFLINE_MODE | CONTACT_DESK; zone `"UNKNOWN"` | I2a |
| O44 | OB; LVB v42 in memory; the bundle file on disk is then tampered while the edge runs | ALLOW | ACCESS_OK, OFFLINE_MODE | OPEN_DOOR: the tampered file is rejected (listed in `GET /v1/mode` `schedule_bundle.rejected`), the in-memory LVB stays in force (`edge/offline/tests/test_bundle.py::test_hot_reload_of_a_tampered_file_keeps_lvb`) | F1 |
| O45 | O04 (LVB v42); a received bundle that fails verification adds an override hash for `11112222` → rejected; submit `11112222` | STEP_UP | OFFLINE_MODE, OFFLINE_HIGH_RISK_ZONE, OFFLINE_FALLBACK_REQUIRED, FALLBACK_FAILED | attempts_left 0 (planted hash never used: codes only come from the LVB) | R8 |
| O46 | O15 → SECOND_FACTOR submitted 130 s after the original STEP_UP | DENY | FALLBACK_FAILED, OFFLINE_MODE | NONE | R10 |
| O47 | O11 → EMAIL_OTP submitted (not in off; SES needs the cloud) | STEP_UP | SCHEDULE_GRACE_WINDOW, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED, FALLBACK_FAILED | attempts_left 0 | R8 |
| O48 | OB; signer stamps 12 h 5 min before now (`expires_at` = now − 5 min → EXPIRED; override `valid_until` = `expires_at` + 24 h = now + 23 h 55 min); Priya / MAIN → STAFF_OVERRIDE `75530182` | STEP_UP, then ALLOW | {SCHEDULE_EXPIRED_CACHE, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED} (methods stf) → {ACCESS_OK, FALLBACK_OK, OFFLINE_MODE} | OPEN_DOOR (codes stay valid for 24 h after bundle expiry, DECISION_POLICY §9.4); once now ≥ `valid_until` the same submission → FALLBACK_FAILED (R8 → R9) | E1 → R1 |

O18, O22 and O40 feed the local match result for Kiran `u_a3b4` straight into the engine. They test the
cached-revocation path (P5), as if her template were still cached (e.g. a revocation that reached the
kiosk through the feed after the last template refresh). End to end, SC2.2 purges a revoked user's
template at the next refresh, so offline Kiran gets DENY {NOT_ENROLLED, OFFLINE_MODE}, CONTACT_DESK (F8 / E5;
schedule not evaluated). O49 pins that.

| ID | Base + deltas | Decision | reason_codes | next_action | Row |
|---|---|---|---|---|---|
| O49 | OB; Kiran / MAIN / Sat 09:00; template cache built from v42 (u_a3b4 excluded as revoked) → local top1 < 0.30 | DENY | NOT_ENROLLED, OFFLINE_MODE | CONTACT_DESK | F8 |

### 6b. Hardening vectors (v1.5, audit fixes)

Each row names the test that proves it. "schedule" / "verifier" rows test one function (`evaluate_schedule`,
`FallbackVerifier.verify`) and list its result instead of a DecisionResponse. Exact `reason_codes` sets on
engine rows were checked against `evaluate()` output on 2026-11-15. Where the test itself asserts less, for
example "not ALLOW + MATCH_AMBIGUOUS present", the row says so.

| ID | Base + deltas | Decision / result | reason_codes | next_action / detail | Row · test |
|---|---|---|---|---|---|
| H01 | schedule; contractor `u_9c0d` gets `extra_windows` LAB_BLOCK FRI 22:00–02:00; Fri 20 Nov is a LAB_BLOCK holiday (contractors not exempt); t0 Fri 20 Nov 23:00 and Sat 21 Nov 01:00 IST | HOLIDAY both times (01:00 was IN_WINDOW before F02) | — | a holiday on the start day also closes the part after midnight | F02 · `test_pf_schedule.py::test_F02_holiday_on_the_start_day_closes_the_tail_after_midnight` |
| H02 | H01 window; t0 Sat 28 Nov 01:00 IST (Fri 27 Nov is a normal day) | IN_WINDOW | — | a normal crossing window still crosses midnight | F02 · `test_pf_schedule.py::test_F02_same_window_on_a_normal_friday_still_crosses_midnight` |
| H03 | schedule; held revocation for Priya `revoked_at` 04:35:00Z; edge t0 = 04:33:00Z (edge clock 120 s behind the cloud) | strict (slack 0, the cloud re-evaluation): not REVOKED; `revocation_slack_s` = 300 (live edge): REVOKED | — | slack = `cache.clock_rollback_tolerance_s` | F03 · `test_pf_schedule.py::test_F03_received_revocation_counts_although_the_edge_clock_is_behind` |
| H04 | OB; Priya / LIB / Sat 10:00; held revocation dated t0 + 120 s | DENY | SCHEDULE_REVOKED, OFFLINE_MODE | CONTACT_DESK (the test asserts DENY + `SCHEDULE_REVOKED`) | F03 → F4 · `test_pf_schedule.py::test_F03_live_engine_applies_the_revocation_slack` |
| H05 | OB; LVB present but `issued_at` = now + 2 h (clock rollback, cache INVALID); no revocation for Priya | STEP_UP | SCHEDULE_BUNDLE_INVALID, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED | steps [SECOND_FACTOR], methods stf | I1b · `test_pf_schedule.py::test_F04_clock_rollback_still_denies_a_revoked_candidate` |
| H06 | H05 + a held revocation for Priya with any `revoked_at` (2026-12-31, or null) | DENY | SCHEDULE_REVOKED, SCHEDULE_BUNDLE_INVALID, OFFLINE_MODE | CONTACT_DESK | I4 (F04) · same test |
| H07 | B; local frames top1 = [`u_3c4d` 0.72, `u_1a2b` 0.70 ×3, `u_3c4d` 0.72] (first = last, but the middle names another user at ≥ `deny_below_cosine` 0.30) | STEP_UP | MATCH_AMBIGUOUS | SECOND_FACTOR, methods on (the test asserts not ALLOW + `MATCH_AMBIGUOUS`) | M01 · `test_pf_identity.py::test_M01_mixed_identity_burst_is_ambiguous_not_allow[B]` |
| H08 | H07 frames with OB | STEP_UP | MATCH_AMBIGUOUS, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED | SECOND_FACTOR, methods off | M01 · same test `[OB]` |
| H09 | OB; frames 2–4 have no match (top1 none) | ALLOW | ACCESS_OK, OFFLINE_MODE | OPEN_DOOR | M01 · `test_pf_identity.py::test_M01_unmatched_middle_frames_still_allow` |
| H10 | OB; frame 3 top1 `u_1a2b` 0.20 (< 0.30) | ALLOW | ACCESS_OK, OFFLINE_MODE | OPEN_DOOR | M01 · `test_pf_identity.py::test_M01_low_scoring_other_user_below_the_deny_bar_does_not_break_consistency` |
| H11 | OB (runtime); the revocation overlay is lost (`state_lost`, e.g. a quarantined `revocations.enc`) | STEP_UP | OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED | SECOND_FACTOR, methods off; `GET /v1/admin/mode/detail` `revocations_state_lost` true. Online the same rule gives STEP_UP {OFFLINE_FALLBACK_REQUIRED}, methods on (engine output; no dedicated test) | EO-08 · `test_pf_runtime.py::test_EO08_lost_revocation_overlay_never_auto_allows` |
| H12 | verifier, OFFLINE; 10 STAFF_OVERRIDE failures within 5 min, unknown (`s_unknown`) or missing staff ids; then the correct `48213907` / `s_guard01` 2 s later | rejected "staff override locked" | — | device backstop: every override locked 300 s, alert `ALERT_FALLBACK_LOCKOUT` `STAFF_OVERRIDE_DEVICE`; accepted again at +302 s | F05 · `test_pf_fallback_limits.py::test_F05_device_backstop_locks_every_override_after_10_failures_in_5_min` |
| H13 | verifier; 3 wrong codes for `s_nobody` + 3 wrong codes without `staff_id`; then `48213907` / `s_guard01` | accepted | — | anonymous guesses never lock a named guard (backstop only) | F05 · `test_pf_fallback_limits.py::test_F05_anonymous_guesses_do_not_lock_out_a_named_guard` |
| H14 | verifier; 10 failures 40 s apart (6 min) | correct code accepted at +401 s | — | the backstop window (300 s) expires; slow failures do not lock | F05 · `test_pf_fallback_limits.py::test_backstop_window_expires_slow_failures_do_not_lock` |
| H15 | verifier, persisted state (`fallback_state.sqlite`); 3 wrong codes for `s_guard01`; "restart" (new state object on the same file); correct code at +30 s, then at +301 s | rejected (locked, `locked_until` set), then accepted | — | locks survive a restart (real UTC) | SC2-D9 · `test_pf_fallback_limits.py::test_D9_override_lockout_survives_a_restart`, runtime `test_pf_runtime.py::test_D9_lockout_survives_a_runtime_restart` |
| H16 | verifier; a per-staff lock set 1 day in the future, then the real clock steps back one day | still rejected, accepted at +301 s | — | a lock is clamped to at most `lockout_s` from now | — · `test_pf_fallback_limits.py::test_lock_is_clamped_when_the_real_clock_steps_backwards` |
| H17 | verifier; one failure row of `fallback_state.sqlite` overwritten with garbage | correct code rejected | — | a tampered row reads as locked | — · `test_pf_fallback_limits.py::test_tampered_failure_row_reads_as_locked` |
| H18 | verifier; 5 wrong TOTP codes for `u_3c4d`; then the valid TOTP (persisted state reopened) | rejected, `locked_until` set | — | per-user TOTP limit 5 → 300 s, checked without verifying the code; `u_5e6f` is not locked | F06 · `test_pf_fallback_limits.py::test_F06_totp_per_user_failure_limit_persists_and_locks_unchecked` |
| H19 | verifier; 5 wrong cards for `u_3c4d`; then `HID-CARD-1002`, and again at +301 s | rejected (locked), then accepted | — | per-user CARD limit 5 → 300 s | F06 · `test_pf_fallback_limits.py::test_F06_card_per_user_failure_limit` |
| H20 | verifier; bundle `consumed_code_ids` = [`OVR-001`]; submit `48213907` / `s_guard01` | rejected, counted as a failure | — | a code consumed at any kiosk never matches; the runtime tick persists the ids (`test_pf_runtime.py::test_D8_tick_persists_consumed_code_ids_from_the_bundle`) | SC2-D8 · `test_pf_fallback_limits.py::test_D8_code_listed_in_consumed_code_ids_is_rejected_and_counted` |
| H21 | verifier; bundle adds `OVR-NEW` (`s_guard09`, 10-digit `0123456789`); submit it; submit legacy 8-digit `48213907` / `s_guard01`; submit 9-digit `482139071` | accepted; accepted; rejected | — | `code_length` 10, `legacy_code_lengths` [8] | EO-11 · `test_pf_fallback_limits.py::test_EO11_ten_digit_codes_and_legacy_eight_digit_codes_are_accepted` |
| H22 | verifier; `OVR-NEW` with signed scope `zones` [LIBRARY], `kiosk_ids` [KIOSK_LIB_01]; submit at SERVER_ROOM / KIOSK_LIB_01, LIBRARY / KIOSK_SRV_01, LIBRARY / KIOSK_LIB_01 | rejected; rejected; accepted | — | outside its scope a code never matches | F09 · `test_pf_fallback_limits.py::test_F09_code_scope_restricts_zones_and_kiosks` |

H12–H22 use the fixture code `48213907` at verifier level (raw bundle, see the baseline note ‡).

### 6a. Rate limiter (A1, DECISION_POLICY §9.7) — all attempts at `KIOSK_LIB_01`

Lockout `rate_limit.lockout_s` = **5 s** (operator 2026-11-14; was 60 s), window 180 s, 5 failures.
`test_ratelimit.py` reads L and W from the YAML and checks the same expressions (`retry_after_s` =
max(1, ceil(lockout_until − t))).

| ID | Sequence (t = monotonic s) | Expected |
|---|---|---|
| RL01 | 5× S04 (OUTSIDE_WINDOW DENY) at t = 0, 10, 20, 30, 40; B at t = 50 | B → ALLOW ACCESS_OK (schedule DENYs do not count) |
| RL02 | 5× I03 (NOT_ENROLLED) + 5× Q11 (SYSTEM_ERROR) at t = 0…90; B at t = 100 | B → ALLOW (identity / SYSTEM_ERROR DENYs do not count) |
| RL03 | 5× S29 (DENY LIVENESS_UNSURE, SCHEDULE_GRACE_WINDOW) + 5× (M01 signals + Priya / LIB / 07:50 → DENY MASK_CUE_EDGE, SCHEDULE_GRACE_WINDOW, CONTACT_DESK) at t = 0…90; B at t = 100 | B → ALLOW (BIO_UNSURE + schedule DENYs never count, even with MASK_CUE_*) |
| RL04 | 4× L05 at t = 0, 10, 20, 30; B at t = 40 | B → ALLOW (4 < 5) |
| RL05 | 5× L05 at t = 0, 10, 20, 30, 40; B at t = 41 | 5th L05 → DENY SPOOF_DEVICE_DETECTED (normal result); `ALERT_RATE_LIMIT_LOCKOUT` emitted once; B → DENY RATE_LIMITED, NONE, `retry_after_s` 4 (lockout until 45) |
| RL06 | RL05; RATE_LIMITED attempts at t = 42 and t = 43; B at t = 44.5 | t 42 → `retry_after_s` 3; t 43 → 2 (not extended); t 44.5 → RATE_LIMITED `retry_after_s` 1 |
| RL07 | RL06; B at t = 45 | ALLOW ACCESS_OK (lockout ended at 45; RATE_LIMITED DENYs did not re-arm) |
| RL08 | RL07; L05 at t = 46; B at t = 47 | L05 → DENY SPOOF_DEVICE_DETECTED (6 events in [−134, 46] → new lockout to 51, second alert); B → RATE_LIMITED `retry_after_s` 4 |
| RL09 | RL05; `POST /v1/admin/rate-limit/reset` at t = 42 (during the lockout); B at t = 43; 4× L05 at t = 50…80; B at t = 90 | both B → ALLOW (reset cleared events and lockout; 4 < 5) |
| RL10 | L01 at t = 0, 10, 20, 30, 180; B at t = 181 | event at t = 0 = 180 − 180 still counts → lockout 180–185; B → RATE_LIMITED `retry_after_s` 4 |
| RL11 | L01 at t = 0, 10, 20, 30, 181; B at t = 182 | event at 0 dropped (4 in window) → B → ALLOW |
| RL12 | Q08 (INJECTION) t = 0, M02 (strong-mask DENY) t = 10, C04 (CHALLENGE_FAILED after L03) t = 20, C03 (MASK_CUE_RIGID) t = 30, S47 (FALLBACK_FAILED) t = 40; B at t = 42 | B → DENY RATE_LIMITED `retry_after_s` 3 (all five are attack evidence) |
| RL13 | 5× S46 (STEP_UP with FALLBACK_FAILED retry) at t = 0…40; B at t = 50 | B → ALLOW (STEP_UP retries are not DENYs) |
| RL14 | `rate_limit.enabled: false`; RL05 sequence | B at t = 41 → ALLOW; no alert; limiter state empty |
| RL15 | OB; 5× O17 (offline phone spoof) at t = 0…40; OB at t = 41 | DENY RATE_LIMITED, OFFLINE_MODE, NONE, `retry_after_s` 4 |
| RL16 | S01 STEP_UP opened at t = 0; 5× L05 (other attempts) at t = 1…5 (lockout until 10); S01 → correct TOTP at t = 5.5 | ALLOW ACCESS_OK, FALLBACK_OK (open step-up sessions are not blocked by a lockout) |
| RL17 | 5× C11 (posts to unknown attempt IDs) + 5× S48 (EMAIL_OTP cloud-verify timeout) at t = 0…90; B at t = 100 | B → ALLOW (protocol errors and R11 re-issues never count) |
| RL18 | *withdrawn* with Q23 (former A7 not implemented) | — |
| RL19 | 5× O24 / O42 (no-LVB DENYs) at t = 0…40; B at t = 41 | B → ALLOW (`SCHEDULE_BUNDLE_INVALID` DENYs carry a SCHEDULE_* code and no attack-evidence code; never counted) |

## 7. Connectivity, storage, sync

| ID | Setup | Expected |
|---|---|---|
| X01 | ONLINE; heartbeat results ok, miss, miss | mode ONLINE (2 misses) |
| X02 | X01 + third consecutive miss | mode OFFLINE; `GET /v1/mode` → `mode` OFFLINE, `state` OFFLINE; next attempt reason_codes include OFFLINE_MODE |
| X03 | OFFLINE; 3 consecutive successes, queue_len 4 | `state` SYNCING, `mode` OFFLINE: attempts still evaluated with the OFFLINE rules (O14 still STEP_UP, OFFLINE_MODE present) |
| X04 | X03; sync acks all 4, bundle v43 installed | mode ONLINE; queue_len 0; `bundle_version` 43 |
| X05 | SYNCING; one heartbeat miss | mode OFFLINE |
| X06 | `POST /v1/admin/mode {"force": "OFFLINE"}` (X-Admin-Token) while ONLINE | `GET /v1/mode` → OFFLINE, `forced` true **immediately**; the very next attempt has OFFLINE_MODE (no heartbeat wait); heartbeats keep running in the background. `FORCE_OFFLINE=1` at start-up = the same forced state |
| X07 | X06; `{"force": "AUTO"}`; last 3 heartbeats ok; queue_len 2 | state SYNCING at once (`forced` false); ONLINE only after both records are acked and the bundle refreshed |
| X08 | X06; `{"force": "AUTO"}` while the cloud is still unreachable | stays OFFLINE (`forced` false) until 3 consecutive heartbeat successes |
| X09 | ONLINE; last ok heartbeat at t = 0, cloud unreachable afterwards; `heartbeat_interval_s` 5, `misses_to_offline` 3, `heartbeat_timeout_ms` 2000 (from the YAML) | pings at 5, 10, 15 s each time out after 2 s → OFFLINE at t ≈ 17 s (≈ 15 s if the failures are immediate, e.g. connection refused); never before the 3rd miss |
| X10 | ONLINE; the heartbeat at t delivers a revocation feed entry for `u_3c4d` (effective now); no bundle refresh | next B attempt → DENY SCHEDULE_REVOKED, CONTACT_DESK, `mode` ONLINE (feed overlays the bundle) |
| X11 | ONLINE; heartbeats ok but bundle refresh failing (cloud 500) since t = 0 | B at refresh age 29 min → ONLINE ALLOW; at 31 min → O30 (attempt OFFLINE, {ACCESS_OK, OFFLINE_MODE}); `GET /v1/mode` reports `mode` OFFLINE, `reason` `bundle_stale` (details in `schedule_bundle.refresh_age_s`); no heartbeat miss counted |
| X12 | `DEMO_MODE=0`; `POST /v1/admin/clock` | rejected; wall clock unchanged |
| X13 | `DEMO_MODE=1`; real now Sat 10:05 IST, bundle signed at 10:00 (relative stamps); demo clock set to Sat 07:50 IST (`{"set_local": "07:50"}`; the demo clock never re-signs) | LVB present but clock rollback (07:50 < issued_at − 300 s) → cache INVALID → MO3 → B → STEP_UP SCHEDULE_BUNDLE_INVALID, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED, methods stf (I1b; the trap the demo script avoids by using evening times, X15) |
| X14 | X13, then the bundle file is re-signed with `issued_at` 07:50 IST and picked up while running (verified file reload = a refresh) | B → S01 result (STEP_UP SCHEDULE_GRACE_WINDOW, methods on, `mode` ONLINE); kiosk shows the DEMO CLOCK badge; `{"reset": true}` → wall clock = real clock again |
| X15 | demo rehearsal (manual) on the live bundle v45 (cloud-issued 18:00:41 IST, `KIOSK_MAIN_01` / MAIN_GATE only; demo-clock times must be after ~17:55:41 IST); demo clock `22:10` then `22:30`; `u_prj1` (student) at `KIOSK_MAIN_01` | 22:10 → STEP_UP SCHEDULE_GRACE_WINDOW (TOTP from the phone verifies: TOTP uses real time, never the demo clock; the card works too); 22:30 → DENY SCHEDULE_OUTSIDE_WINDOW; reset the clock before mode AUTO / any sync (`docs/DEMO_AND_PITCH.md` §1.2) |
| D01 | any decision record in `decision_log` (decrypted) | keys ⊆ {attempt_id, seq, kiosk_id, zone, ts_utc, user_id, candidate_user_id, decision, reason_codes, resolved_codes, scores, fallback, schedule_version, cache_state, mode, prev_hash, record_hash}; `fallback` keys ⊆ {method, staff_id, code_id, totp_step}; no key/value contains image bytes, base64 > 256 chars, embedding arrays, display names, TOTP/override code values, raw card IDs |
| D02 | record scores | every float rounded to 2 dp; no per-frame arrays |
| D03 | DB file on disk | `payload` column not valid JSON plaintext (AES-GCM ciphertext); grep for "u_3c4d" in raw file finds nothing |
| D04 | 3 records, server acks 2 | 2 rows deleted, 1 remains |
| D05 | unsynced record aged 24 h 1 min | purged; tombstone {count 1, first_seq, last_seq, chain_head} queued |
| D06 | records 1..5, modify payload of record 3 | `verify_chain()` fails at seq 3; server returns ALERT_LOG_TAMPER |
| D07 | Q17 decision record | `user_id` null, `candidate_user_id` null, `resolved_codes` [QUALITY_LOW_LIGHT], `fallback` {method STAFF_OVERRIDE, staff_id s_guard01, code_id OVR-001, totp_step null}, no code value |
| D08 | RC04 decision record | `reason_codes` [ACCESS_OK], `resolved_codes` [RANDOM_CHALLENGE]; scores 2 dp |
| Y01 | POST the same batch twice (same `batch_id`, same items) | second response: every key in `duplicates`, `accepted` []; server record count unchanged |
| Y02 | same `attempt_id`, different `record_hash` | cloud: acknowledged in **`duplicates`** (never `rejected`), so the edge purges it like any ack; `verbose` lists it in `conflicts` and the ack status is `CONFLICT`; ALERT_SYNC_CONFLICT; both versions stored; a re-send of the same variant raises no new alert (`cloud/tests/test_sync.py` `test_Y02_same_attempt_different_content_is_conflict`). Edge: the record is purged on the ack (queue depth 0, `rejected` 0), the first stored version is not replaced and exactly one ALERT_SYNC_CONFLICT is raised; a verbose `CONFLICT` ack is parsed as a duplicate plus an ALERT_SYNC_CONFLICT flag (`edge/offline/tests/test_sync.py` `test_Y02_*`) |
| Y03 | offline ALLOW Priya at 04:35Z; authoritative revocation of u_3c4d effective 03:30Z (issued while kiosk offline) | `flags` [{attempt_id, type POST_HOC_REVOKED}]; ALERT_REVOKED_USER_ADMITTED (high) |
| Y04 | as Y03 but revocation effective 05:30Z (after the ALLOW; user record `revoked` true, `revoked_at` 05:30Z) | no flag; no alert (time-aware REVOKED, SC1.3) |
| Y05 | offline ALLOW; authoritative schedule gained a closure for that date while offline | `flags` [{attempt_id, type SCHEDULE_CHANGED}]; ALERT_SCHEDULE_MISMATCH |
| Y06 | OVR-001 used offline at KIOSK_LIB_01 (04:40Z) and KIOSK_MAIN_01 (05:10Z) | first: no flag + ALERT_OVERRIDE_USED; second: ALERT_OVERRIDE_REUSE |
| Y07 | same user TOTP step accepted at two kiosks (records carry `fallback.totp_step`, a counter, not a secret) | ALERT_TOTP_REPLAY |
| Y08 | 3 SPOOF_* DENY on one kiosk within 10 min (offline) | ALERT_SPOOF_BURST |
| Y09 | request `X-Timestamp` 5 min behind server receipt time | ALERT_CLOCK_SKEW; Y03-style re-evaluation uses corrected time |
| Y10 | tombstone item received | `flags` [{attempt_id null, type RECORDS_PURGED_UNSYNCED}]; ALERT_RECORDS_PURGED_UNSYNCED |
| Y11 | after successful sync | kiosk pulls bundle/revocations/templates; revoked user's template removed from local cache; with Rekognition enabled, an online attempt by newly revoked Priya → DENY SCHEDULE_REVOKED (with `match.rekognition.enabled: false` → DENY NOT_ENROLLED) |
| Y12 | 120 queued records | edge sends 3 batches (50, 50, 20; `sync.batch_size`) in `seq` order; each item carries `idempotency_key` = `attempt_id` and `hmac` |

## 8. Invariant / property tests (fuzz `combine()` and `evaluate()` over random signal inputs)

**IDs.** P01–P13 (two digits) are *test properties*, implemented by `test_P01…test_P13` in
`edge/policy/tests/test_invariants.py` (P10 in `test_ratelimit.py`). They are **not** the same numbering
as the DECISION_POLICY §1 invariants P1–P12 (one digit): for example DECISION_POLICY P9 = explainable /
logged, but test property P09 = random challenge. The mapping table is below the property table.

| ID | Property |
|---|---|
| P01 | Any hard spoof code present ⇒ decision DENY, for all schedules, modes, step-up evidence. |
| P02 | `reason_codes` non-empty for every decision; every code ∈ the closed list in DECISION_POLICY §6. |
| P03 | mode OFFLINE ∧ decision ALLOW ⇒ (bio was PASS ∧ schedule IN_WINDOW ∧ cache FRESH ∧ risk ≤ auto_allow_max_risk) ∨ `FALLBACK_OK` ∈ codes. |
| P04 | bio UNSURE ∧ decision ALLOW ⇒ the CHALLENGE (if LIVENESS cause) and SECOND_FACTOR (if MATCH cause, or offline) steps were passed. |
| P05 | Schedule deny-type ⇒ DENY regardless of step-up submissions. |
| P06 | Raising any pass threshold never turns a DENY or STEP_UP into ALLOW (monotonicity). `liveness.flash.min_amplitude` is a validity bar, not a pass bar, so it is excluded: in enforce mode, raising it can turn a flash FAIL (r < `fail_max_r`) into WEAK and, online, `PASS_AMBIENT` (DECISION_POLICY §3.3). `_raise_pass_bars` does not vary it. |
| P07 | Mode OFFLINE never yields fewer restrictions than ONLINE for the same inputs (decision rank DENY > STEP_UP > ALLOW). |
| P08 | Engine never raises; injected exceptions ⇒ DENY + SYSTEM_ERROR. |
| P09 | Random challenge only tightens: for any inputs, the decision with r = 0.0 differs from r = 0.99 only where the r = 0.99 result is an N1/F1 ALLOW, which becomes STEP_UP {RANDOM_CHALLENGE} (+ OFFLINE_MODE); the RNG is called at most once per `evaluate()` and never in `resolve_stepup()`. |
| P10 | Rate-limiter state changes only on DENYs that satisfy DECISION_POLICY §9.7 (fuzz all outcomes: ALLOW, STEP_UP, schedule / identity / quality / SYSTEM_ERROR / RATE_LIMITED DENYs leave it unchanged). |
| P11 | decision ALLOW ∧ `user_id` null ⇒ the attempt was quality-exhausted (A3) ∧ `FALLBACK_OK` ∈ codes ∧ fallback method STAFF_OVERRIDE ∧ `staff_id` set. |
| P12 | flash NOT_AVAILABLE ∧ decision ALLOW ⇒ a CHALLENGE step was passed (no auto-ALLOW on the non-flash path), **except** the A3 manual-review ALLOW (P11, e.g. Q13 with `flash_enabled` false). A quality-exhausted attempt evaluates no liveness and reaches ALLOW only through STAFF_OVERRIDE. `test_P12` checks initial decisions only. |
| P13 | mode ONLINE ⇒ the bundle was verified, FRESH and refreshed ≤ `online_max_bundle_age_min` before the attempt. |

Mapping to the DECISION_POLICY §1 invariants:

| DECISION_POLICY invariant | Test properties |
|---|---|
| P1 default DENY / exceptions → SYSTEM_ERROR | P08 |
| P2 hard spoof evidence is final | P01 |
| P3 uncertainty never auto-allows | P04, P12 |
| P4 biometrics → schedule → mode, only tighten | P05, P06 (monotonicity) |
| P5 stale data may deny, never allow | P03 |
| P6 offline stricter than online | P07 |
| P7 cloud failure ⇒ attempt OFFLINE | P13 |
| P8 step-up cannot fix schedule DENY; A3 manual review | P05, P11 |
| P9 explainable and logged (no `assert`) | P02 |
| P10 no biometric data in logs | — (case D01, §7) |
| P11 only attack evidence arms the rate limiter | P10 |
| P12 randomness only tightens | P09 |
