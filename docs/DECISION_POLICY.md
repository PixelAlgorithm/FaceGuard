# DECISION_POLICY.md — single source of truth for kiosk decisions

Policy version: `2026-11-14.3` (must equal `policy_version` in `config/thresholds.yaml`).
Changes in `.2`: online schedule evaluated on the newest signed bundle (no per-attempt cloud call) and a
stale online bundle makes the attempt OFFLINE; the rate limiter counts attack-evidence DENYs only;
quality-exhausted → staff manual review (A3/A6); non-flash path needs a challenge; random deformation
challenge (`RANDOM_CHALLENGE`); connectivity names `/v1/mode` + `/v1/admin/mode`; demo clock.
Round-2 rulings folded into `.2` (the code in `edge/policy/` + `edge/offline/` implements them): PAD
PASS needs ≥ 3 live frames **and** ≤ 1 spoof-like frame (L04 → CHALLENGE); device box ≥ 0.25 that is
not FAIL → UNSURE; the ambient flash exception also needs a clean device detector and moiré < 0.40;
flash calibration (lag window 0–8 frames, lag std ≤ 1.5, `min_amplitude` 2.0, edge-measured `r` only)
and **flash ADVISORY mode** (`liveness.flash.enforce: false`, §3.3); last-valid-bundle rule (no verified
bundle → DENY `SCHEDULE_BUNDLE_INVALID`, zone `UNKNOWN`, §9.5); override codes valid until bundle
`expires_at` + 24 h; rate-limit lockout 5 s; flash/capture window `liveness.flash.duration_ms` 700 ms
(operator speed request, was 1000; re-validate the flash at 700 ms before enforce); `challenge.random_rate` 0.0 (superseded, see below); unknown camera label alone no
longer steps up (`injection.unknown_label_is_unsure: false`); time-aware revocation, REVOKED first;
no `assert` on the decision path. The device-detector check on quality-exhausted attempts (former row
A7) is **not implemented** and has been removed from the matrix. Step-up protocol errors are HTTP
404/409, not decisions; an unreachable EMAIL_OTP verify re-issues the same STEP_UP without EMAIL_OTP (R11); `next_action` carries the full
API.md shape (`challenge_id`, `min_reaction_ms`, `expires_at`, `hint`).
Shipped behaviour since `.2` (2026-11-14, operator requests; `config/thresholds.yaml` is the source):
random challenge **on again**, `challenge.random_rate` 0.15 online / 0.30 offline (§3.4); deformation
actions SMILE | OPEN_MOUTH (`PUFF_CHEEKS` removed from `challenge.deformation_actions`, still accepted by
the wire enum, never issued; §7.1); enforce switches `liveness.moire.enforce` and
`liveness.mask.m2_rgb_enforce`, both **true** (§3.3, §3.4); random-challenge demo control adds `FORCE`, and a
forced draw fires whatever the rate (§3.4); early cloud probe with
`latency_budget_ms.rekognition_probe_deadline` 1500 ms and its identity-binding rule (§3.5); `STAFF_OVERRIDE`
needs `staff_id`, revoked CARD hashes fail, an `ERASED` revocation deletes the user's local templates and
TOTP secret (§7.2, §5.1).
Audit fixes in the code (policy version unchanged, `2026-11-14.3`): a holiday on a window's start day also
closes that window's part after midnight (F02, §5); live revocation slack (F03, §5); a held revocation still
denies when the clock rolled back (F04, §9.5); persisted second-factor failure limits with a device backstop and
the new code `FALLBACK_LOCKED` (§7.2, §9.6 R12); consumed / scoped / 10-digit override codes (§7.2); a lost
revocation overlay never auto-ALLOWs (§7.2); offline overrides only on an allowlist of keys (§3); an
identity switch on any embedded frame gives `MATCH_AMBIGUOUS` (§3.5). Known limits that stay open: §7.3.
Scope: every decision the edge service (`edge/policy/`) returns, online and offline, plus the
step-up resolution and the server-side re-evaluation of offline decisions.
Companion files: `docs/SURPRISE_CHALLENGES.md` (rationale for SC1/SC2), `config/thresholds.yaml`
(all numbers; key names in this file are the real YAML keys), `config/schedule.example.json` (schedule
bundle format and test fixture), `config/schedule.demo.json` (source of the live demo bundle, signed by
`scripts/sign_bundle.py`), `docs/POLICY_TEST_CASES.md` (normative test vectors, implemented in
`edge/policy/tests/`). If code and this file disagree, this file wins; fix the code.

---

## 1. Fail-secure principles (invariants — tests must enforce them)

Numbering: P1–P12 (one digit) are these invariants. P01–P13 (two digits) are the test properties in
`docs/POLICY_TEST_CASES.md` §8, which has the mapping between the two (e.g. invariant P9 → property P02,
invariant P12 → property P09).

| # | Invariant |
|---|---|
| P1 | **Default is DENY.** Any exception, timeout without fallback, missing input, unparsable config or unknown enum value → `DENY` + `SYSTEM_ERROR`. No code path returns ALLOW by falling through. A runtime exception anywhere in the edge decision path (perception, policy runtime, log write) is returned as a logged `DENY` + `SYSTEM_ERROR` DecisionResponse, never as HTTP 500. |
| P2 | **Hard spoof evidence is final.** Device in frame, flat depth, flash mismatch (when the flash is enforced, §3.3), virtual camera, failed challenge, passive-PAD majority fail, ≥ 2 strong mask cues → `DENY`. Nothing (schedule, step-up, staff override) can upgrade it. |
| P3 | **Uncertainty never auto-allows.** Every UNSURE signal routes to `STEP_UP`; ALLOW after UNSURE requires the matching step-up to pass. Offline, UNSURE additionally always requires a second factor. The only exception is the online ambient-light flash exception (§3.3), which requires PAD = PASS with mean `P_live` ≥ 0.90, no device box ≥ 0.25 and moiré < 0.40; it is disabled offline. While the flash is ADVISORY (`liveness.flash.enforce: false`) its result is measured and reported but has no decision effect, so it is neither an UNSURE nor a FAIL signal (§3.3). |
| P4 | **Biometrics first, schedule second, mode third.** Schedule is only evaluated for a candidate identity whose biometric result is PASS or UNSURE. Each later stage can only keep or tighten the decision (ALLOW → STEP_UP → DENY), never loosen it. The only loosening operation is `resolve_stepup()`, which turns STEP_UP into ALLOW after every required step passed. |
| P5 | **Stale data may deny, never allow.** An expired schedule bundle can still produce DENY (e.g. a cached revocation), but an IN_WINDOW/GRACE result from it can only reach ALLOW through a staff override, and only with an override code whose `valid_until` has not passed (§7.2). Data from a bundle whose signature did not verify is never used (last-valid-bundle rule, §5.1 / §9.5). |
| P6 | **Offline is stricter than online.** Offline pass bars are higher (`offline.overrides`), high-risk zones never auto-ALLOW, the ambient-light flash exception is disabled. (The random-challenge rate is also higher offline: shipped 0.15 online / 0.30 offline, §3.4.) |
| P7 | **Any cloud dependency failure during the main evaluation (`evaluate()`) makes that attempt OFFLINE.** No "half-online" decisions. This includes a Rekognition timeout/error (when `match.rekognition.enabled`) and an online schedule bundle that is not usable (no verified bundle, not FRESH, or last refresh older than `schedule.online_max_bundle_age_min`=30 min — §5.1). During step-up resolution the session keeps the mode it was opened in; an EMAIL_OTP cloud verification that times out or errors re-issues the same STEP_UP without `EMAIL_OTP` (nothing consumed or counted, §9.6 R11), not a mode switch. |
| P8 | **Step-up cannot fix schedule DENY.** A second factor or staff override only resolves STEP_UP decisions. A3 (quality exhausted) is not a schedule decision: there is no identity, so the desk staff member is responsible for checking entitlement. The kiosk shows "Please see the desk staff for a manual check"; the staff screen must state that the schedule was NOT checked, and every A3 ALLOW (a STAFF_OVERRIDE ALLOW) raises `ALERT_OVERRIDE_USED` at the cloud when the record syncs (online and offline). |
| P9 | **Every decision is explainable and logged.** Response always carries `decision`, `reason_codes[]` (non-empty), `next_action`, `scores{}`, `latency_ms`, `mode`, `policy_version`, `bundle_version`. The minimal log record (`docs/SURPRISE_CHALLENGES.md` §SC2.5) is written before the response is returned; if it cannot be written the answer is `DENY` + `SYSTEM_ERROR`. Empty `reason_codes` is checked explicitly (raises → `SYSTEM_ERROR`), never with `assert` (asserts vanish under `python -O`). |
| P10 | **No biometric data in logs.** Logs/sync queue never contain images, crops or embeddings. |
| P11 | **Only attack evidence arms the rate limiter** (§11 `counts_toward_rate_limit`): schedule, identity, quality, `SYSTEM_ERROR` and `RATE_LIMITED` DENYs never count, so a crowd of legitimate-but-unentitled people cannot lock a kiosk. |
| P12 | **Randomness only tightens.** The random challenge (`challenge.random_rate`, shipped 0.15 online / 0.30 offline) can only turn a would-be ALLOW into STEP_UP CHALLENGE; it never touches STEP_UP or DENY. The RNG is injected (`rng`) so tests are deterministic; it is consulted at most once per `evaluate()`. |

---

## 2. Pipeline order

```
attempt (3–5 frames + flash nonce + camera meta [+ DepthProbe depth frames])
  │
  M. mode resolution (§8.1) ................. ONLINE only if connectivity ONLINE and the last valid bundle
                                               (LVB) is FRESH and refreshed ≤ 30 min ago; else OFFLINE (P7)
  0. rate limit (if rate_limit.enabled) ..... RATE_LIMITED → DENY
  1. quality gate ........................... QUALITY_* / MULTIPLE_FACES → STEP_UP(RECAPTURE); when exhausted:
                                               injection check first (A4), then
                                               STEP_UP(SECOND_FACTOR [STAFF_OVERRIDE]) low/medium zone,
                                               DENY(CONTACT_DESK) high-risk zone   (A3 / A6)
  2. injection check ........................ INJECTION_VIRTUAL_CAMERA → DENY
  P7 flip ................................... Rekognition enabled online but its result missing / failed
                                               → the attempt becomes OFFLINE (+ heartbeat miss)
  3. liveness fusion (PAD, device, moiré, flash, depth, mask cues)  → PASS | UNSURE | FAIL
  4. identity match (online: Rekognition + local cross-check; offline or Rekognition disabled:
                     local only, offline bars) → PASS | UNSURE | FAIL
  5. biometric result ....................... BIO_PASS | BIO_UNSURE | BIO_FAIL
  6. schedule evaluation (SC1) .............. evaluate_schedule() on the LVB (+ revocation feed), both modes:
                                               REVOKED | NO_ENTITLEMENT | ZONE_NOT_PERMITTED | HOLIDAY |
                                               IN_WINDOW | GRACE_WINDOW | OUTSIDE_WINDOW   (+ cache state)
  7. mode restrictions (SC2) ................ ONLINE | OFFLINE (+ bundle FRESH | EXPIRED | INVALID, or no LVB)
  8. final decision ......................... ALLOW | STEP_UP | DENY + reason_codes + next_action
  8b. random challenge (shipped on) ......... would-be ALLOW → STEP_UP CHALLENGE [RANDOM_CHALLENGE]
                                               with probability challenge.random_rate (shipped 0.15 / offline 0.30)
  9. resolve_stepup (on step-up submissions) STEP_UP → ALLOW | STEP_UP (retry) | DENY
 10. log minimal record → sync queue; attack-evidence DENYs → rate limiter (P11)
```

Liveness and Rekognition inference run **in parallel** in the perception layer (`edge/attempts.py`);
the policy engine then evaluates stages 3–5 as pure functions on those raw scores, so the fusion order
below is logical, not temporal. Stages 0–2 short-circuit (later stages are not run), except that a
quality-exhausted attempt still runs the injection check (2) before A3 / A6 is offered (§3.1). There is
no per-attempt cloud schedule call (§5.1): online, the only cloud call on the 2 s path is the
time-boxed Rekognition search, run in parallel with liveness.

**Clocks.** Calendar checks — `t0` for the schedule, bundle `issued_at`/`expires_at`, clock-rollback,
override `valid_until` — use the edge wall clock, which in `DEMO_MODE=1` is the demo clock set by
`POST /v1/admin/clock` (`{"set_local": "HH:MM"}` | `{"offset_s": n}` | `{"reset": true}`; 403 unless
`DEMO_MODE=1`; kiosk shows a "DEMO CLOCK" badge). The client's face-lock `t0` is untrusted: the runtime
re-bases it onto the edge wall clock, with the client lag clamped to [0, `latency_budget_ms.t0_max_lag`
= 10 s]. Elapsed-time checks — online bundle refresh age, rate-limit window and lockout — use the real
monotonic clock; connectivity switches on counts of consecutive heartbeat misses / successes (the wall
clock only stamps `since` in the status). Session nonce and step-up session / challenge TTLs use the **real wall
clock** (UTC `datetime.now`, never the demo clock): immune to the demo clock, but not to an OS clock /
NTP jump. TOTP always verifies against real wall time (authenticator apps), never the demo clock.
The demo clock does **not** re-sign the bundle. A demo-clock time earlier than the LVB's `issued_at` −
300 s (`cache.clock_rollback_tolerance_s`) reads as clock rollback → cache INVALID (§9.5 I1b/I2b), and a
time after its effective expiry reads as EXPIRED. `scripts/sign_bundle.py` stamps `issued_at` = now,
`expires_at` = now + 12 h (the cloud does the same), so the demo uses **evening** demo times on a bundle
issued the same day: with the live cloud-issued v45 (`issued_at` 18:00:41 IST, MAIN_GATE only), e.g.
MAIN_GATE 22:10 = grace STEP_UP, 22:30 = outside DENY; any demo time before ~17:55:41 IST is a rollback.
The clock is reset before mode AUTO and any sync (sync stamps `kiosk_now_utc` from the demo clock; a skew
> 120 s raises `ALERT_CLOCK_SKEW`). Override codes are stamped `valid_until` = `expires_at` + 24 h
(`fallback.staff_override.valid_after_expiry_h`), so they stay usable for a day after the bundle
expires (§7.2, §9.4).

---

## 3. Per-signal three-zone thresholds

All values live in `config/thresholds.yaml`; names in `code` are the YAML keys. "Online" is the base
value; "Offline" is the value after deep-merging `offline.overrides`.

**Offline overrides allowlist** (`edge/policy/thresholds.py` `OFFLINE_OVERRIDABLE`, audit F08). `offline.overrides`
may set only these leaves; any other leaf is a `ConfigError` when the thresholds load
(`_check_offline_scope`). Deny bars of device / moiré / depth / mask, step-up method sets, attempt counts,
the rate limit and the fallback limits are therefore the same in both modes.

| Leaves | Offline rule (checked at load) |
|---|---|
| `liveness.pad.pass_min`, `liveness.pad.min_pass_frames`, `liveness.flash.pass_min_r`, `match.local.allow_min_cosine`, `match.local.min_margin_top1_top2`, `challenge.random_rate` | offline value ≥ online value |
| `liveness.pad.fail_max`, `liveness.flash.fail_max_r`, `match.local.deny_below_cosine` | offline value = online value |
| `liveness.flash.enforce`, `liveness.moire.enforce`, `liveness.mask.m2_rgb_enforce` | may not be switched off offline while on online |
| `liveness.flash.ambient_exception_enabled` | must be false offline |
| `challenge.deformation_actions`, `challenge.secondary_actions` | **not overridable** offline (a narrower offline pool would weaken the randomness): any offline value is a `ConfigError` (`test_pf_thresholds.py::test_offline_cannot_narrow_the_challenge_action_pools`) |

### 3.1 Quality gate (per frame; a frame failing any check is dropped)

| Check | Pass | Fail code |
|---|---|---|
| Exactly one face (secondary face ≥ `secondary_face_min_rel_size`=0.5 × main face area → fail) | 1 face | `MULTIPLE_FACES` |
| Face ROI mean luma in [`min_luma_mean`=60, `max_luma_mean`=210] and over-exposed fraction ≤ 0.15 | inside | `QUALITY_LOW_LIGHT` (covers dark *and* backlit/over-exposed) |
| Laplacian variance of 112×112 face crop ≥ `min_laplacian_var`=80 | ≥ | `QUALITY_BLUR` |
| Face width ≥ 112 px, inter-ocular ≥ 60 px, \|yaw\| ≤ 25°, \|pitch\| ≤ 20°, \|roll\| ≤ 20° | all | `QUALITY_POSE` |
| Depth enabled: D0 valid-depth ratio ≥ 0.40 | ≥ | `QUALITY_DEPTH_INVALID` |

Attempt-level: usable frames ≥ `min_usable_frames`=3, else the attempt fails quality with the codes of
the dropped frames (deduplicated, ordered as in the table). `MULTIPLE_FACES` on any frame fails the
attempt. Quality fail → `STEP_UP` / `RECAPTURE` while `recapture_count < max_recaptures`=2.
Fewer than 3 frames submitted at all is invalid input → `DENY` `SYSTEM_ERROR` (P1).

Capture (`CaptureSpec` from `POST /v1/session/start`): 5 frames (`quality.frames_per_attempt`) over
`window_ms` = `liveness.flash.duration_ms` = 700 ms (was 1000), up to `max_width_px` =
1280. Calibration note (2026-11-14, operator MacBook webcam, dev data): at 640 px the face at kiosk
distance had ≈ 50 px inter-ocular distance (< 60), so every frame failed `QUALITY_POSE`; 1280 px fixed it.

**Quality exhausted** (`recapture_count ≥ max_recaptures`; the brief's "OTP or manual review"):
- The injection check (§3.2) runs on all received frames first; FAIL → `DENY` `INJECTION_VIRTUAL_CAMERA`
  (A4) — an injected stream must not reach the manual-review path.
- No liveness signal is evaluated on quality-failed frames: dark / blurred / off-angle crops give low
  `P_live` for genuine users, so a PAD FAIL there is not hard evidence. (A device-detector check before
  manual review — former row A7 — is not implemented; the desk staff member sees the person and any
  held-up phone.)
- Low/medium-risk zone (not "high" as defined in §8.2 rules 4–5) → `STEP_UP`, reason codes = the quality
  codes, `next_action` SECOND_FACTOR with methods `stepup.methods.quality_exhausted` = `[STAFF_OVERRIDE]`
  = **manual review by desk staff** (row A3), `attempts_left` 1. There is no identity, so there is no
  candidate and the schedule is **not** evaluated (`bio_result`, `schedule_result`, `candidate` null):
  the staff member checks the person (photo ID / card) and vouches with a one-time override code.
  Success → `ALLOW` [`ACCESS_OK`, `FALLBACK_OK`] with `resolved_codes` = the quality codes, `user_id` =
  null and `fallback.staff_id` recorded (R1). Every A3 ALLOW raises `ALERT_OVERRIDE_USED` at sync (P8).
- High-risk zone → `DENY` / `CONTACT_DESK` with the quality codes (row A6).
- Offline: the same, plus `OFFLINE_MODE` and `OFFLINE_FALLBACK_REQUIRED` on the STEP_UP.
- Zone risk is read from the kiosk's zone in the last valid (verified) bundle; no LVB or unknown risk
  is treated as high (→ A6).

### 3.2 Injection check

| Result | Condition | Effect |
|---|---|---|
| FAIL | client flag `virtual_camera_suspected`, or camera label matches `injection.virtual_camera_label_patterns` (OBS, ManyCam, Snap Camera, XSplit, "virtual", …), or frame timestamps non-monotonic / interval outside [`min_frame_interval_ms`=15, `max_frame_interval_ms`=400] | `DENY` `INJECTION_VIRTUAL_CAMERA` (short-circuit) |
| UNSURE | fewer than 2 timestamps (timing cannot be verified); or label empty/unknown (not on `known_good_label_patterns`) **only if** `injection.unknown_label_is_unsure` is true | adds `LIVENESS_UNSURE` |
| PASS | otherwise | — |

`injection.unknown_label_is_unsure` ships **false** (operator 2026-11-14: "extra verification only if
suspicious"; macOS names the built-in camera "MacBook … Camera"): an unknown, non-virtual label alone no
longer steps up. Virtual-camera labels, the client flag and timing anomalies still DENY. The test
fixture pins it to true so Q09 keeps testing the UNSURE rule.

### 3.3 Liveness signals

| Signal | PASS | UNSURE | FAIL (hard) | Code |
|---|---|---|---|---|
| PAD ensemble, per-frame `P_live` = mean(MiniFASNetV2, MiniFASNetV1SE) | ≥ 3 usable frames with `P_live` ≥ `pad.pass_min` 0.80 (offline 0.85) **and** at most 1 frame ≤ `pad.fail_max` 0.30 | anything else (e.g. 3 live + 2 spoof-like frames, L04) | `P_live` ≤ 0.30 on a strict majority of usable frames | `SPOOF_PASSIVE` / `LIVENESS_UNSURE` |
| Device detector (COCO cell phone / laptop / tv), per frame | no box ≥ 0.25 | any box conf ≥ `unsure_conf` 0.25 overlapping the face that is not FAIL (incl. conf ≥ 0.40 covering < 80 % of the face box); detector output missing / non-finite | box conf ≥ `fail_conf` 0.40 containing ≥ `face_containment` 80 % of the face box, on any frame | `SPOOF_DEVICE_DETECTED` / `LIVENESS_UNSURE` |
| Moiré FFT score (face ROI, 0–1; worst frame) | < 0.40 | [0.40, 0.70), **or** ≥ 0.70 while PAD=PASS and flash=PASS; missing score | ≥ 0.70 **and** (PAD ≠ PASS or flash ≠ PASS) — corroboration rule | `SPOOF_MOIRE` / `LIVENESS_UNSURE` |
| Flash correlation `r` (chroma response vs nonce sequence) — **enforce mode** (`liveness.flash.enforce: true`) | r ≥ `pass_min_r` 0.70 (offline 0.75), lag finite and within [`lag_min_frames` 0, `lag_max_frames` 8], lag std ≤ `lag_max_std_frames` 1.5, colour order correct | 0.30 ≤ r < pass bar, or lag std > 1.5, or no measurement; **or** amplitude < `min_amplitude` 2.0 (WEAK) | amplitude ≥ `min_amplitude` and (r < `fail_max_r` 0.30, or lag outside [0, 8] frames, or wrong colour order) | `SPOOF_FLASH_MISMATCH` / `LIVENESS_UNSURE` |
| Depth D1 plane-fit RMS | > 6 mm | 3–6 mm | < 3 mm | `SPOOF_FLAT_DEPTH` |
| Depth D2 quadratic-fit RMS (bent print) | > 4 mm | 2–4 mm | < 2 mm | `SPOOF_FLAT_DEPTH` |
| Depth D3 nose relief | ≥ 15 mm | 8–15 mm | < 8 mm | `SPOOF_FLAT_DEPTH` |
| Depth D4 metric inter-pupil distance (only if absolute depth) | 45–80 mm | relative depth → skipped | outside 45–80 mm | `SPOOF_DEPTH_SCALE` |
| Depth D0 valid ratio | ≥ 0.60 | [0.40, 0.60) → `LIVENESS_UNSURE` | < 0.40 handled by quality gate | — |

**Moiré enforce switch.** `liveness.moire.enforce: true` (shipped): the moiré row above decides. With
`false` moiré would be ADVISORY like the flash (measured, reported as `signals.moire` = `ADVISORY_<zone>`, no
UNSURE / FAIL effect), except that a **missing** moiré measurement stays UNSURE either way. A missing key
means enforce. Known false positives (dev data, not an eval result): genuine flash-lit frames scored
0.42–0.79, so a genuine user can get `LIVENESS_UNSURE` → CHALLENGE, and moiré ≥ 0.70 with PAD ≠ PASS gives
`SPOOF_MOIRE` DENY even for a genuine user. The bands (0.40 / 0.70) are to be calibrated on the eval dev
split; the ambient flash exception always needs moiré < 0.40.

PAD notes: a frame whose two model outputs are not both valid probabilities counts as neither live nor
spoof-like. MiniFASNet self-test on the kiosk laptop: output index 1 = real (`liveness.pad.real_class_index`),
input raw 0–255 BGR.

**Flash signal and calibration.** The kiosk shows exactly 3 colours × ≈ 233 ms in the 700 ms window
(`liveness.flash.duration_ms` 700, operator speed request 2026-11-14, was 1000 ms / ≈ 333 ms per colour;
`colours_min` = `colours_max` = 3; 3 colours / 0.7 s = 2.86 changes/s ≤ `max_changes_per_s` 3, the
photosensitivity bound). The flash calibration below was measured at 1000 ms; it must be re-validated
at 700 ms before `enforce` is set back to true (return to 1000 ms if `r_frames` degrades). `r` is
computed by the edge from the **received frames** (`r_frames`) only; the client's own chroma series is
untrusted and is not used (it was also noisy on genuine users: r_client 0.33–0.98 vs r_frames 0.86–0.99,
dev data). Lag is taken as `lag_ms` × measured fps / 1000 when the producer sends both, else
`lag_frames`. Calibration 2026-11-14 (operator MacBook webcam, n = 3 genuine, dev data — not an eval
result): webcam pipeline delay 4–7 frames (genuine lag 3.75–7.0) → lag window widened from [0, 3] to
[0, 8]; genuine lag std 0.65–1.05 → bar 1.5 (was 1.0); genuine amplitude 2.1–8.5 → `min_amplitude` 2.0
(was 4.0). Vectors LCAL1–LCAL4 / LCAL4O pin the new bars.

**Flash ADVISORY mode (shipped).** `liveness.flash.enforce: false` (2026-11-14) until the kiosk's
real-camera flash timing is re-validated: genuine users were getting false `SPOOF_FLASH_MISMATCH` and
step-ups. In advisory mode the flash is still measured and reported (`signals.flash` =
`ADVISORY_PASS | ADVISORY_UNSURE | ADVISORY_FAIL | ADVISORY_WEAK`, `scores.flash_r` / `flash_amp`), but
it has **no decision effect**: it is treated as PASS for fusion and for moiré corroboration (so moiré
≥ 0.70 is corroborated only by PAD ≠ PASS), in both modes. A missing `enforce` key means enforce. The
non-flash path (`NOT_AVAILABLE`, below) is unchanged and still requires a CHALLENGE. Honesty note for
the pitch / demo: while the flash is advisory, video / screen-replay defence rests on passive PAD +
the phone / laptop / TV detector + moiré (+ depth when enabled); the colour-flash nonce is the designed
video-replay defence and is re-enabled (`enforce: true`) after validation. Never claim it is enforced.
The flash rows of the table above and all flash test vectors describe **enforce mode**.

**Flash ambient exception (online only, enforce mode):** flash = WEAK only because amplitude <
`min_amplitude` (bright room / auto-exposure) **and** PAD = PASS **and** mean `P_live` ≥
`pad.strong_live`=0.90 **and** the device detector is PASS (no box ≥ `device_detector.unsure_conf` 0.25)
**and** moiré is measured and < `liveness.moire.unsure_score` 0.40 → flash treated as PASS
(`signals.flash` = `PASS_AMBIENT`). Otherwise WEAK → `LIVENESS_UNSURE`. A self-lit screen replay usually
gives a WEAK flash, so the device and moiré conditions keep it out of the exception. Disabled offline
(`offline.overrides.liveness.flash.ambient_exception_enabled: false`; the engine also checks
mode = ONLINE). Low amplitude is never FAIL: the amplitude test runs before the `r` / lag / order
tests, so `min_amplitude` is a **validity bar, not a pass bar**. Raising it can turn a measured flash
FAIL (amplitude between the old and new bar, r < 0.30) into WEAK, which online can become
`PASS_AMBIENT` and then ALLOW. It is therefore excluded from the monotonicity property
(test property P06 in `docs/POLICY_TEST_CASES.md` §8); this matters only in enforce mode (advisory mode has no flash decision effect).

**Non-flash accessibility path:** `flash_enabled=false` in `POST /v1/session/start` (photosensitive
user) or `liveness.flash.enabled: false` → flash = `NOT_AVAILABLE`, which adds `LIVENESS_UNSURE`
(LIVENESS cause) → a CHALLENGE step is always required (N15 / F10), in enforce **and** advisory mode.
The attempt is **never** auto-ALLOWed without the flash check; the ambient exception does not apply (it
needs a WEAK measurement, not an absent one); for moiré corroboration flash counts as ≠ PASS (moiré ≥
0.70 → `SPOOF_MOIRE`).

Depth signals are used only when `liveness.depth.enabled` and DepthProbe frames for this `attempt_id`
(iPhone app → `POST /v1/depth/frames` on the LAN listener, 1–3 frames per attempt) arrived within
`latency_budget_ms.depth_max_wait`; otherwise they are `NOT_AVAILABLE` and have no effect. D4 runs only
on absolute depth (`DepthFramesMeta.accuracy` = absolute) while `require_absolute_depth_for_d4` is true.
`liveness.depth.enabled` ships **false**: the DepthProbe app (v0.3.0 sideloaded) connects when running, but
depth stays off until the H4 calibration (10 live vs 10 printed-photo captures) passes; H4 has not been run
(`depth/calibration/` is empty) and the depth thresholds are estimates.
D5 (depth vs RGB disagreement) is logged in `scores.depth.d5_disagree`; it changes nothing because
D1–D4 FAIL and PAD FAIL are each already hard DENY.

### 3.4 Mask cues (soft evidence)

| Cue | Source | Weak (counts as 1 cue) | Strong | Code |
|---|---|---|---|---|
| M1 rigid under deformation | depth during challenge: mouth/cheek residual vs forehead residual after rigid alignment | — | mouth residual < 4 mm while blendshape says moved (jawOpen > 0.4 or mouthSmile > 0.5) → **immediate DENY** (treated as decisive) | `MASK_CUE_RIGID` |
| M2 edge / eye-hole ring | RGB Laplacian ring score around eyes / jaw, or depth step on a closed ring | ring score ≥ 0.50 | ring score ≥ 0.75 or depth step ≥ 10 mm | `MASK_CUE_EDGE` |
| M3 enrolled depth template RMS | depth vs enrolled 64×64 template | ≥ 6 mm | ≥ 8 mm | `MASK_CUE_SHAPE` |
| Spectral (optional) | flash response not skin-like | skin score ≤ 0.40 | skin score ≤ 0.20 | `MASK_CUE_SPECTRAL` |

Rules: **≥ 2 strong cues → FAIL (DENY)** with all strong cue codes. **≥ 1 cue (weak or strong) and
< 2 strong → UNSURE** with the cue codes; the step-up must be a CHALLENGE (with deformation).

**M2 RGB enforce switch.** `liveness.mask.m2_rgb_enforce: true` (shipped): the RGB ring score counts as an
M2 cue. With `false` it would be ADVISORY (reported in `scores.mask.m2_ring` and `advisory_cues`, never a
cue); the depth M2 step, M1 and M3 are always enforced. Known false positive (dev data): genuine spectacle
frames scored 0.35–0.80, so glasses can produce `MASK_CUE_EDGE` → CHALLENGE (no glasses for the scripted
demo). To be calibrated on the eval dev split.

**Random deformation challenge (hardening against rigid 3D masks; shipped on).** A rigid mask can pass
every passive cue, so a BIO_PASS attempt that would end in ALLOW (rows N1 / F1) can be converted to
`STEP_UP` CHALLENGE with `RANDOM_CHALLENGE` when `rng.random() < challenge.random_rate` — rows N14 / F9.
Exactly one draw per would-be ALLOW; no draw otherwise. The challenge is the normal §7.1 challenge
(mouth/cheek deformation mandatory; M1 checked when depth is present).
- **Shipped: on.** `challenge.random_rate` = **0.15 online / 0.30 offline**
  (`offline.overrides.challenge.random_rate`; restored 2026-11-14 at the operator's request, "i want that
  blink and stuff"; it was 0.0 for part of the day). The test fixture pins the same rates, so the RC
  vectors test the mechanism whatever the YAML says (RC18 pins the shipped YAML).
- **Demo control** (`DEMO_MODE=1` only, admin token): `POST /v1/admin/random-challenge
  {"mode": "AUTO" | "FORCE" | "FORCE_NEXT" | "OFF"}`. `AUTO` = configured rate; `FORCE` = every would-be
  ALLOW is challenged; `FORCE_NEXT` = stays armed until a would-be ALLOW uses it, then the mode is `AUTO`;
  `OFF` = no draw at all (also disarms `FORCE_NEXT`). A forced draw fires **whatever the rate** (even 0.0:
  `edge/policy/engine.py` stage 8b checks `rng.forced`). The mode is held in memory: an edge restart resets
  it to `AUTO`. The scripted demo sends `OFF` before the run and `FORCE_NEXT` only for the step that shows
  the challenge (`docs/DEMO_AND_PITCH.md`).
Pitch wording: random deformation challenges *raise the bar* for rigid masks; silicone masks remain a
known RGB limit; depth M1 helps when the iPhone is present (depth is currently off, §3.3).

### 3.5 Identity match

| Matcher | PASS | UNSURE | FAIL |
|---|---|---|---|
| Local ArcFace cosine (uniface / buffalo_l), gallery = this kiosk's entitled users | top1 ≥ `allow_min_cosine` 0.50 (offline 0.55) **and** top1 − top2 ≥ 0.10 (offline 0.15) | 0.30 ≤ top1 < allow → `MATCH_LOW`; top1 ≥ allow but margin < min → `MATCH_AMBIGUOUS` | top1 < `deny_below_cosine` 0.30 → `NOT_ENROLLED` |
| Rekognition `SearchUsersByImage` similarity (online only) | top1 ≥ 99 **and** runner-up < 80 | 80 ≤ top1 < 99 → `MATCH_LOW`; top1 ≥ 99 but runner-up ≥ 80 → `MATCH_AMBIGUOUS` | no UserMatches or top1 < 80 → `NOT_ENROLLED` |

- `allow_min_cosine` 0.50 is a **starting value**. Recalibrate before the eval run: compute all impostor
  cosine scores on the team gallery (+ LFW padding), set `allow_min_cosine` to the **99.8th percentile**
  of impostor scores (`match.local.calibration_impostor_percentile`, target FAR 0.2 %), record N impostor
  pairs and the resulting bound in `eval/results/`. Offline adds `offline.match_offline_delta` (+0.05)
  to whatever the calibrated value is (recompute `offline.overrides.match.local.allow_min_cosine`).
- **Decisions are always made on the edge** (local-first); the cloud only supplies a match result.
- **Online with Rekognition enabled** (`match.rekognition.enabled: true`): Rekognition is authoritative
  for the identity. The local cosine bands of the table above (`MATCH_LOW` / `NOT_ENROLLED` / margin)
  are **not applied online** (e.g. Rekognition 99.6 with local same-user cosine 0.35 is a PASS); the
  local result can only add `MATCH_AMBIGUOUS`, in exactly these cases:
  - cross-check (`match.cross_check_local_conflict`): local top1 is a **different user** with cosine ≥
    `identity.cross_check_conflict_min_cosine` (0.50, its own key, so raising `allow_min_cosine` never
    relaxes it) → `MATCH_AMBIGUOUS`;
  - no usable local summary (template cache missing / older than `cache.template_cache_max_age_hours` 72,
    or no local match) → `MATCH_AMBIGUOUS` (cannot cross-check → never auto-ALLOW);
  - identity switch between the first and last usable frame (below) → `MATCH_AMBIGUOUS`.

  Rekognition's own bands (table above) still apply: no UserMatches or top1 < 80 → `NOT_ENROLLED`
  (BIO_FAIL); 80 ≤ top1 < 99 → `MATCH_LOW`; runner-up ≥ 80 → `MATCH_AMBIGUOUS`.
- **Identity consistency (both modes; `edge/policy/identity.py` `local_summary`):** the embedded frames are the
  usable frames that carry a local top-1 user and a finite top-1 cosine. The candidate is the top-1 user of the
  first embedded frame; its top1 / top2 are the means over the embedded frames whose top-1 is the candidate.
  With `match.local.require_same_identity_first_last_frame` true (shipped), the identity is **inconsistent** if
  the last embedded frame's top-1 is a different user, **or any** embedded frame's top-1 is a different
  enrolled user with cosine ≥ `match.local.deny_below_cosine` (0.30) (verify M01: a victim photo inside a
  live-face burst). Inconsistent → `MATCH_AMBIGUOUS` (offline: UNSURE unless the result is already
  `NOT_ENROLLED`; online: added to the Rekognition result). A different user below 0.30 on a middle frame,
  or a frame without a match, does not break consistency (`edge/policy/tests/test_pf_identity.py`).
- Rekognition runs in parallel with liveness and is time-boxed by `latency_budget_ms.rekognition_timeout`
  (700 ms, a hard total deadline; the sandbox is us-east-1, production would pin ap-south-1). Timeout,
  error or missing result → the whole attempt is OFFLINE (P7): offline thresholds, local matcher only,
  offline method sets; it also counts as a heartbeat miss. The edge uploads a ~10 KB face crop, not the
  full frame. **Measured state** (venue network, 2026-11-14, dev observation): the round trip is about
  0.4–1.4 s, so most online attempts miss the 700 ms box and are decided OFFLINE while the heartbeat keeps
  the badge ONLINE (`GET /v1/mode` `cloud_match.degraded`).
- **Early cloud probe** (`POST /v1/attempt/{id}/probe`, API.md §3.1a; in the code, live after an edge
  restart, not yet measured): the kiosk sends the face-lock frame right after face lock and the edge starts
  the Rekognition match then, in parallel with the capture. The frames then wait at most
  `latency_budget_ms.rekognition_probe_deadline` (1500 ms, measured **from probe start**) − elapsed
  (≥ 0). **Identity binding** (fail-secure): the probe's cloud result is used only if the probe's local
  top-1 user equals the frames' local top-1 user **and** cosine(probe embedding, best frame embedding) ≥
  `match.local.allow_min_cosine`; otherwise it is treated as a failed cloud match (`CloudMatch(ok=False)`),
  so the attempt is OFFLINE (P7). Without a probe the 700 ms path above applies. A probe never causes a
  `SYSTEM_ERROR` or an HTTP 500 (P1), and it cannot upgrade a decision.
- The edge makes no cloud match call when the next attempt would be OFFLINE anyway, or when
  `match.rekognition.enabled` is false.
- Rekognition **disabled** (`match.rekognition.enabled: false`, e.g. the sandbox IAM role denies it) is a
  configured capability, not a per-attempt failure: identity = local matcher with the **offline** match
  bars (`offline.overrides.match.local`: allow 0.55, margin 0.15); liveness keeps the online bars; mode
  stays ONLINE (online schedule, online method sets incl. EMAIL_OTP); no heartbeat miss.
- `MATCH_LOW` is the *low-confidence band* code (UNSURE), not a failure. Failure is `NOT_ENROLLED`.
- Revoked users' templates are purged at refresh (the gallery is filtered to users entitled at this
  kiosk's zone), so with the local matcher a revoked user normally comes out `NOT_ENROLLED`, not
  `SCHEDULE_REVOKED` (§5, SC1.3).

---

## 4. Biometric result

```
liveness FAIL (any hard code)          → BIO_FAIL   codes = hard spoof codes
≥ 2 strong mask cues                    → BIO_FAIL   codes = strong cue codes
identity FAIL                           → BIO_FAIL   codes = [NOT_ENROLLED]
liveness UNSURE or ≥1 mask cue
  or identity UNSURE                    → BIO_UNSURE codes = unsure codes; causes ⊆ {LIVENESS, MATCH}
otherwise                               → BIO_PASS   codes = []
```

If both liveness and identity fail, codes = spoof codes first, then `NOT_ENROLLED`. On BIO_FAIL the
unsure codes are **not** added to `reason_codes` (they remain visible in `scores`/`signals`).
`causes` determines step-up steps: `LIVENESS` (any of `LIVENESS_UNSURE`, `MASK_CUE_*`) → `CHALLENGE`;
`MATCH` (`MATCH_LOW`, `MATCH_AMBIGUOUS`) → `SECOND_FACTOR`.

The top-1 candidate `user_id` is recorded even on BIO_FAIL (as `candidate_user_id`, never displayed),
so the cloud can raise a "targeted spoof against user X" alert.

---

## 5. Schedule evaluation (SC1) — summary

Full model and examples in `docs/SURPRISE_CHALLENGES.md` §SC1. Evaluated only for BIO_PASS / BIO_UNSURE,
for the candidate user, at the attempt start time `t0` (re-based onto the edge wall clock, §2) in
`Asia/Kolkata`, by `edge.policy.schedule.evaluate_schedule` on the **last valid bundle** (LVB, the newest
bundle whose signature verified) with the revocation feed overlaid — the same function and the same
data source in both modes.

### 5.1 Online schedule source (no per-attempt cloud call) and the last valid bundle

- Online, the edge refreshes the bundle every `cache.bundle_refresh_interval_min`=15 min
  (`GET /v1/schedule/{kiosk_id}` on the cloud, `If-None-Match` → 304 = confirmed) and pulls the
  revocation feed (`GET /v1/revocations?since=`) at every successful heartbeat
  (`connectivity.heartbeat_interval_s`=5 s); feed revocations overlay the bundle (`REVOKED`) in both
  modes. There is no per-attempt cloud schedule call.
- **Last valid bundle (LVB).** A received bundle (cloud fetch, or the bundle file changing on disk) that
  fails signature verification, does not cover this kiosk, or is older than the LVB is **rejected**
  (listed in `GET /v1/mode` → `schedule_bundle.rejected`) and never replaces the LVB; data from an
  unverified bundle is never used. A bundle file tampered on disk while the edge runs is rejected and
  the in-memory LVB stays in force. Override codes and the kiosk's zone / risk always come from the LVB.
- **Refresh age** = real elapsed time since the last successful refresh: a verified bundle installed
  from the cloud, the cloud confirming the installed version (304), or a verified re-signed bundle file
  picked up while running (`scripts/sign_bundle.py`). The bundle loaded at boot is **not** a refresh
  (refresh age unknown → OFFLINE until the first cloud refresh).
- An attempt is evaluated ONLINE only if an LVB exists, its cache state is `FRESH` and refresh age ≤
  `schedule.online_max_bundle_age_min`=30. Otherwise the attempt is **OFFLINE** (P7; rows MO2/MO3) —
  offline thresholds and the §8.2 cache rules apply (a 45-min-old but unexpired bundle is evaluated as
  offline FRESH). `GET /v1/mode` then reports `mode` OFFLINE with `reason` `bundle_stale`. A stale
  bundle alone is not a heartbeat miss.
- Removing the serial cloud schedule hop (≈ 300 ms from Bangalore to us-east-1) keeps the 2 s budget;
  the price is that an online revocation takes effect within one heartbeat (≤ 5 s + feed latency).
- **Revocation types** (bundle `revocations[]` or feed items): `USER` (time-aware `REVOKED`, below);
  `CARD` (`target_id` = card-ID hash): that card fails as a fallback factor at once (§7.2); `reason:
  "ERASED"` (cloud DPDP erasure): the user is revoked **and** the edge deletes the user's local face
  templates and TOTP secret, once per user (`USER_ERASED_LOCAL` event; `PolicyRuntime.apply_erasures`).
- **Live state** (2026-11-14): the installed LVB is the cloud-issued v45 (`issued_at` 12:30:41Z, scope
  `KIOSK_MAIN_01` only). A bundle with a lower `bundle_version` (e.g. `scripts/sign_bundle.py` with its
  default v42) is rejected as older. With v45 any demo-clock time before ~17:55:41 IST reads as clock
  rollback (INVALID, below).

Precedence (first match wins): `REVOKED` (time-aware: a revocation — bundle `revocations[]`, the user's
`revoked`/`revoked_at`, or the feed — counts only if its `revoked_at` ≤ `t0`; an undated revocation
always counts; checked first, also for users absent from `users{}`) → `NO_ENTITLEMENT` (unknown user,
user validity range or visitor pass not covering `t0`) → `ZONE_NOT_PERMITTED` → `HOLIDAY` → `IN_WINDOW`
→ `GRACE_WINDOW` (within `grace_minutes`=15 before a window start or after a window end;
`grace_minutes_high_risk`=0) → `OUTSIDE_WINDOW`.

- **Midnight-crossing windows and holidays (F02).** A window whose end is before its start belongs to the day
  it starts on. A holiday on that start day closes the whole window, its part after midnight included: `t0`
  inside that tail → `HOLIDAY` (not `OUTSIDE_WINDOW`), and the tail is never `IN_WINDOW` or a grace source.
  A holiday on `t0`'s own date → `HOLIDAY` as before (it also closes the tail of the previous day's window).
  The same window on a normal day still crosses midnight (`edge/policy/schedule.py` `_crossing_from`,
  `test_pf_schedule.py`).
- **Live revocation slack (F03).** For live edge decisions, a revocation the edge already holds counts when
  its `revoked_at` ≤ `t0` + `revocation_slack_s`, with slack = `cache.clock_rollback_tolerance_s` (300 s)
  (`edge/policy/engine.py` → `evaluate_schedule(..., revocation_slack_s=...)`; `PolicyRuntime._revocation_slack_s`,
  also used for the gallery filter `entitled_user_ids`). An edge clock up to 300 s behind the cloud therefore
  cannot ignore a revocation it has received. The slack only adds revocations. The cloud's re-evaluation at
  sync keeps the strict default 0 (time-aware rule above, Y04).
- **Clock rollback (F04).** When the cache is `INVALID` by clock rollback (LVB present), the schedule is not
  evaluated, but a deny-only check still runs: **any** revocation the edge holds for the candidate (bundle
  `revocations[]`, the user's `revoked` flag or the feed, whatever its `revoked_at`; `schedule.revoked_any`)
  → `DENY` `SCHEDULE_REVOKED` + `SCHEDULE_BUNDLE_INVALID` + `OFFLINE_MODE`, CONTACT_DESK (§9.5 I4).

Cache state of the LVB (computed in both modes; ONLINE requires `FRESH`, so `EXPIRED`/`INVALID` only
reach the matrix offline): `FRESH` | `EXPIRED` (now > min(`expires_at`, `issued_at` +
`cache.bundle_max_staleness_hours` 12 h)) | `INVALID` (**no LVB at all**, or the clock rolled back:
now < LVB `issued_at` − `cache.clock_rollback_tolerance_s` 300 s). §9.5 distinguishes the two INVALID
cases.
Signature: HMAC-SHA256 (`SCHEDULE_BUNDLE_HMAC_KEY`) over canonical JSON for the hackathon; Ed25519
(kiosk holds only the public key) in production. Signer: `scripts/sign_bundle.py` (`issued_at` = now,
`expires_at` = now + 12 h, override `valid_until` = `expires_at` + 24 h; it signs v42 by default, so a
replacement for the live bundle needs `--version` > the installed version). The live bundle is the
**cloud-issued v45**, built from the cloud's copy of `config/schedule.demo.json` and filtered to
`KIOSK_MAIN_01`.

Schedule result → reason code: `GRACE_WINDOW→SCHEDULE_GRACE_WINDOW`, `OUTSIDE_WINDOW→SCHEDULE_OUTSIDE_WINDOW`,
`NO_ENTITLEMENT→SCHEDULE_NO_ENTITLEMENT`, `ZONE_NOT_PERMITTED→SCHEDULE_ZONE_NOT_PERMITTED`,
`HOLIDAY→SCHEDULE_HOLIDAY`, `REVOKED→SCHEDULE_REVOKED`; `IN_WINDOW` adds no code.
"Deny-type" results = OUTSIDE_WINDOW, NO_ENTITLEMENT, ZONE_NOT_PERMITTED, HOLIDAY, REVOKED.

---

## 6. Reason codes (exact strings)

Required set (from the brief):

| Code | Stage | Meaning |
|---|---|---|
| `QUALITY_LOW_LIGHT` | quality | face too dark or backlit / over-exposed |
| `QUALITY_BLUR` | quality | motion/focus blur |
| `MULTIPLE_FACES` | quality | more than one significant face |
| `SPOOF_PASSIVE` | liveness | PAD ensemble fails on majority of frames |
| `SPOOF_DEVICE_DETECTED` | liveness | phone/laptop/TV around face |
| `SPOOF_MOIRE` | liveness | screen moiré, corroborated |
| `SPOOF_FLASH_MISMATCH` | liveness | reflection does not follow nonce colours/timing |
| `SPOOF_FLAT_DEPTH` | liveness | D1/D2/D3 fail (flat or bent plane, no nose relief) |
| `MASK_CUE_RIGID` | liveness | M1 rigid under deformation |
| `MASK_CUE_EDGE` | liveness | M2 eye-hole / outline ring |
| `INJECTION_VIRTUAL_CAMERA` | injection | virtual camera or frame-timing anomaly |
| `CHALLENGE_FAILED` | step-up | challenge wrong/early/absent |
| `MATCH_LOW` | identity | score in low-confidence (UNSURE) band |
| `MATCH_AMBIGUOUS` | identity | margin too small, matcher disagreement, identity switch (last embedded frame, or any embedded frame whose top-1 is another user at cosine ≥ 0.30, §3.5) |
| `NOT_ENROLLED` | identity | no enrolled identity above deny threshold |
| `SCHEDULE_OUTSIDE_WINDOW` | schedule | no window covers t0 (beyond grace) |
| `SCHEDULE_GRACE_WINDOW` | schedule | within grace of a window |
| `SCHEDULE_NO_ENTITLEMENT` | schedule | no active entitlement (unknown in bundle, expired validity, no visitor pass) |
| `SCHEDULE_ZONE_NOT_PERMITTED` | schedule | role/user not permitted in this zone |
| `SCHEDULE_HOLIDAY` | schedule | holiday/closure for this zone |
| `SCHEDULE_REVOKED` | schedule | user revoked (time-aware with the live slack, §5; any held revocation on a rolled-back clock, §9.5 I4) |
| `SCHEDULE_EXPIRED_CACHE` | mode | offline bundle beyond max staleness |
| `OFFLINE_MODE` | mode | decision made offline (always present when mode=OFFLINE) |
| `OFFLINE_HIGH_RISK_ZONE` | mode | high-risk zone while offline |
| `OFFLINE_FALLBACK_REQUIRED` | mode | offline step-up needs a fallback factor |
| `FALLBACK_OK` | step-up | second factor / fallback verified |
| `FALLBACK_FAILED` | step-up | second factor / fallback rejected |

Added codes (allowed, closed list — no others; the required and added codes together are the 40 codes of
`edge/policy/codes.py` `CODE_ORDER`):

| Code | Stage | Why added |
|---|---|---|
| `ACCESS_OK` | final | every ALLOW carries ≥ 1 code (P9) |
| `QUALITY_POSE` | quality | face too small / off-angle / cut off |
| `QUALITY_DEPTH_INVALID` | quality | D0 < 0.40 (sunlight, glasses, out of range) → retake |
| `LIVENESS_UNSURE` | liveness | any liveness signal in its UNSURE band (incl. unverifiable frame timing, unknown camera label when `injection.unknown_label_is_unsure`, D0 0.40–0.60, flash `NOT_AVAILABLE` on the non-flash path) |
| `RANDOM_CHALLENGE` | liveness | hardening: would-be ALLOW randomly converted to a deformation CHALLENGE (`challenge.random_rate`, shipped 0.15 online / 0.30 offline; rigid-mask defence) |
| `SPOOF_DEPTH_SCALE` | liveness | D4 metric face size implausible (scaled photo / small screen) |
| `MASK_CUE_SHAPE` | liveness | M3 differs from enrolled depth template |
| `MASK_CUE_SPECTRAL` | liveness | non-skin flash spectral response (optional signal) |
| `SCHEDULE_HIGH_RISK_ZONE` | schedule | online high-risk zone requires step-up even in window |
| `SCHEDULE_BUNDLE_INVALID` | mode | no last valid (verified) bundle at all, or clock rollback (now < LVB `issued_at` − 300 s) |
| `RATE_LIMITED` | pre-check | ≥ `rate_limit.max_failures`=5 **attack-evidence** DENYs in `rate_limit.window_s`=180 s on this kiosk → `rate_limit.lockout_s`=5 s lockout (P11; operator 2026-11-14, was 60 s) |
| `SYSTEM_ERROR` | any | exception / invalid input / unknown enum / log write failure → DENY (P1) |
| `FALLBACK_LOCKED` | step-up | the submitted second-factor method is locked by its failure limit (§7.2); STEP_UP with `next_action.retry_after_s`, not counted as a factor failure (§9.6 R12) |

**Ordering in `reason_codes`:** the order is `CODE_ORDER` in `edge/policy/codes.py`, which is
`SYSTEM_ERROR` first, then stage order (pre-check, quality, injection, liveness hard, mask, liveness
unsure [`LIVENESS_UNSURE`, `RANDOM_CHALLENGE`], identity, schedule, mode, step-up, final). Within the
quality stage it follows the §3.1 order (`MULTIPLE_FACES`, `QUALITY_LOW_LIGHT`, `QUALITY_BLUR`,
`QUALITY_POSE`, `QUALITY_DEPTH_INVALID`). The mode stage is ordered `SCHEDULE_EXPIRED_CACHE`,
`SCHEDULE_BUNDLE_INVALID`, `OFFLINE_MODE`, `OFFLINE_HIGH_RISK_ZONE`, `OFFLINE_FALLBACK_REQUIRED`; the step-up
stage `CHALLENGE_FAILED`, `FALLBACK_OK`, `FALLBACK_FAILED`, `FALLBACK_LOCKED`. Where
this differs from the row order of the tables above, `CODE_ORDER` wins. Tests compare **sets** (`docs/POLICY_TEST_CASES.md`), the UI shows the
first code. The list above is closed: any other string in `reason_codes` is a bug (P02).

**Composition rules (deterministic):**
- `DENY` from BIO_FAIL → BIO_FAIL codes only (+ `OFFLINE_MODE` if offline). No schedule codes.
- `DENY` from schedule with BIO_PASS → schedule code (+ `SCHEDULE_EXPIRED_CACHE` if cache EXPIRED) (+ `OFFLINE_MODE`).
- `DENY` from BIO_UNSURE + non-IN_WINDOW → bio unsure codes + schedule code (+ cache/mode codes).
- `STEP_UP` → trigger codes (bio unsure codes, schedule code if GRACE, `SCHEDULE_HIGH_RISK_ZONE` online)
  + mode codes. Offline replaces `SCHEDULE_HIGH_RISK_ZONE` with `OFFLINE_HIGH_RISK_ZONE`, and adds
  `OFFLINE_FALLBACK_REQUIRED` whenever a SECOND_FACTOR step is required.
- `STEP_UP` from quality exhausted (A3) → the quality codes (+ `OFFLINE_MODE`, `OFFLINE_FALLBACK_REQUIRED`
  offline); steps `[SECOND_FACTOR]`, methods `[STAFF_OVERRIDE]`; no schedule codes, no candidate.
  High-risk zone (A6) → `DENY` with the quality codes (+ `OFFLINE_MODE`), CONTACT_DESK.
- `STEP_UP` from the random challenge (N14/F9) → `RANDOM_CHALLENGE` (+ `OFFLINE_MODE`); steps
  `[CHALLENGE]` only, never `OFFLINE_FALLBACK_REQUIRED` (bio was PASS; no SECOND_FACTOR step).
- `DENY` with no last valid bundle (I1a/I2a) → bio unsure codes + `SCHEDULE_BUNDLE_INVALID` +
  `OFFLINE_MODE`; CONTACT_DESK; response `zone` = `"UNKNOWN"`; no schedule result.
- `STEP_UP` after clock rollback with an LVB (I1b/I2b) → bio unsure codes + `SCHEDULE_BUNDLE_INVALID` +
  `OFFLINE_MODE` + `OFFLINE_FALLBACK_REQUIRED`; methods `[STAFF_OVERRIDE]`.
- `DENY` for a held revocation after clock rollback (I4, F04) → bio unsure codes + `SCHEDULE_REVOKED` +
  `SCHEDULE_BUNDLE_INVALID` + `OFFLINE_MODE`; CONTACT_DESK.
- `DENY` from the rate limiter (A1) → `RATE_LIMITED` (+ `OFFLINE_MODE`) only.
- `ALLOW` → `ACCESS_OK` (+ `FALLBACK_OK` if a SECOND_FACTOR step was passed) (+ `OFFLINE_MODE`).
  The step-up trigger codes move to `resolved_codes[]` (audit only). **Trigger codes** = the reason codes
  of the original STEP_UP minus `OFFLINE_MODE`, `OFFLINE_FALLBACK_REQUIRED`, `CHALLENGE_FAILED` and
  `FALLBACK_FAILED` (e.g. `[LIVENESS_UNSURE]`, `[RANDOM_CHALLENGE]`, `[QUALITY_LOW_LIGHT]`,
  `[OFFLINE_HIGH_RISK_ZONE]`).
- Step-up retry → `STEP_UP` with the original reason codes + `CHALLENGE_FAILED` or `FALLBACK_FAILED`
  (R6 / R8). The R11 cloud-verify re-issue keeps the codes of the last response unchanged and only drops `EMAIL_OTP`.
- Step-up retry on a locked method (R12) → `STEP_UP` with the original reason codes +
  `FALLBACK_LOCKED` (no `FALLBACK_FAILED`), `attempts_left` unchanged, `next_action.retry_after_s` = seconds
  until the lock ends.
- Step-up exhausted → `DENY` with `CHALLENGE_FAILED` or `FALLBACK_FAILED` (+ `OFFLINE_MODE`).

---

## 7. next_action

```json
{
  "type": "CHALLENGE",
  "steps": ["CHALLENGE", "SECOND_FACTOR"],
  "methods": ["TOTP", "STAFF_OVERRIDE"],
  "challenge": {"challenge_id": "chl_01JD…", "nonce": "…", "actions": ["SMILE", "TURN_LEFT"],
                "step_window_ms": 1500, "min_reaction_ms": 150, "expires_at": "2026-11-14T04:37:12Z"},
  "attempts_left": 1,
  "retry_after_s": null,
  "hint": null
}
```

Field rules (the wire model is `docs/API.md` §1 `NextAction`, whose validator enforces them):
- `steps`: remaining step-up steps in order; non-empty iff `type` is `CHALLENGE` or `SECOND_FACTOR`, and
  then `type` = `steps[0]`. `[]` for `OPEN_DOOR`, `RECAPTURE`, `CONTACT_DESK` and `NONE`.
- `methods`: non-null iff `SECOND_FACTOR` ∈ `steps` (§8.3).
- `challenge`: non-null iff `type` = `CHALLENGE`: `{challenge_id, nonce, actions, step_window_ms,
  min_reaction_ms, expires_at}` (§7.1).
- `retry_after_s`: `DENY` `RATE_LIMITED`, and `STEP_UP` `FALLBACK_LOCKED` (seconds until the lock ends,
  ≥ 1; §7.2). `hint`: `RECAPTURE` only, one of `move_closer`, `more_light`,
  `hold_still`, `one_person`, `face_camera`.

`attempts_left` = retries remaining **after** the currently requested submission
(`stepup.attempts_left_semantics: "retries_after"`, final 2026-11-14): first issue = 1, after one failed
submission = 0 ("last try"), a further failure → DENY. Initial CHALLENGE = `challenge.soft_fail_retries`
(1); initial SECOND_FACTOR = `stepup.max_attempts_per_step` − 1 (1); RECAPTURE = `max_recaptures` −
`recapture_count` − 1 (1 on the first recapture, 0 on the last). The alternative `"including_next"`
(submissions left including the next one: 2 → 1) is one YAML switch away and is not used.

| type | When |
|---|---|
| `OPEN_DOOR` | ALLOW |
| `RECAPTURE` | quality fail (incl. `QUALITY_DEPTH_INVALID`) with recaptures left |
| `CHALLENGE` | BIO_UNSURE with LIVENESS cause (incl. the non-flash path), or `RANDOM_CHALLENGE` (randomised 2-step, one deformation mandatory) |
| `SECOND_FACTOR` | MATCH cause, GRACE, high-risk zone, any offline step-up except `RANDOM_CHALLENGE`; `methods` from §8.3. Quality exhausted in a low/medium zone (A3): methods `[STAFF_OVERRIDE]` = manual review by desk staff |
| `CONTACT_DESK` | DENY for a probably-legitimate person: NOT_ENROLLED, NO_ENTITLEMENT, ZONE_NOT_PERMITTED, REVOKED, BIO_UNSURE+schedule deny, no last valid bundle (`SCHEDULE_BUNDLE_INVALID` DENY, I1a/I2a), quality exhausted in a high-risk zone (A6), SYSTEM_ERROR |
| `NONE` | DENY for spoof/injection/challenge/fallback failure, OUTSIDE_WINDOW, HOLIDAY, RATE_LIMITED |

UI label (kiosk): `STEP_UP` is displayed as **"REQUEST VERIFICATION"** (subtitle "step-up") to match the
brief; the API enum stays `STEP_UP`.

### 7.1 Step-up challenge (mandatory mouth/cheek movement)

- 2 actions, random order, server-issued single-use nonce (TTL `challenge.session_ttl_s`=120):
  exactly one from `challenge.deformation_actions` = `{SMILE, OPEN_MOUTH}` (deformation — **mandatory**)
  + one from `{BLINK, TURN_LEFT, TURN_RIGHT}`. **Blink-only is forbidden** (eye-cut paper masks blink).
  `PUFF_CHEEKS` was removed from the issued list on 2026-11-14 at the operator's request; it is still a
  valid deformation in the wire enum (`edge/policy/signals.py`), so a site could re-add it, but it is
  never issued with the shipped YAML.
- Neutral baseline = mean blendshapes over first 200 ms after face lock.
- Deformation passes if the blendshape rises ≥ 0.45 above baseline **and** absolute value exceeds
  (mouthSmile ≥ 0.50 | jawOpen ≥ 0.40; cheekPuff ≥ 0.40 only if PUFF_CHEEKS were issued), with correlated
  cheek/nasolabial landmark shift.
- Blink: eyeBlink ≥ 0.5 then ≤ 0.2. Turn: yaw **delta** ≥ `turn_yaw_min_deg` 15° in the commanded
  direction, measured against the yaw at the prompt (baseline), so a user whose neutral pose is already
  turned is judged on the movement, not the absolute pose.
- Timing: response must start ≥ `min_reaction_ms`=150 after prompt and complete ≤ `step_window_ms`=1500.
- Same face track throughout; last challenge frame local cosine to the candidate ≥
  `challenge.min_identity_cosine` 0.30.
- **Hard fail → DENY `CHALLENGE_FAILED` immediately:** response before `min_reaction_ms`, reported
  actions differ from the issued ones, challenge id / nonce mismatch (replay), wrong turn direction
  (delta ≥ 15° the other way), face track lost / identity switch.
- **M1 contradiction** (blendshape moved, depth rigid) → DENY `MASK_CUE_RIGID` immediately.
- **Soft fail** (no qualifying response in window): one retry with a new nonce
  (`soft_fail_retries`=1), second soft fail → DENY `CHALLENGE_FAILED`.
- Optional online extra: Rekognition Face Liveness (confidence ≥ 80) may replace the challenge; never
  on the 2 s main path.

### 7.2 Second factor / fallback methods

| Method | Online | Offline | Verification |
|---|---|---|---|
| `TOTP` | yes | yes | RFC 6238, SHA1, 6 digits, 30 s, ±1 step, per-user secret from enrolment, replay-protected (last used step per user); only if the user's verified bundle entry has `fallback.totp_enrolled`. Failure limit per candidate user (below) |
| `CARD` | yes | yes (not high-risk) | simulated HID card / mobile credential ID; HMAC-SHA256(`CARD_ID_PEPPER`, card_id) == user `card_id_hash`, **and** the hash is not revoked (an LVB `revocations[]` item or a feed item with `type: CARD` and `target_id` = the hash → fails at once). Failure limit per candidate user (below) |
| `EMAIL_OTP` | yes | no | SES via the cloud (`POST /v1/attempt/{id}/otp/send`, then `/fallback`), 6 digits, TTL 300 s; sent to the candidate's enrolled address (sandbox: the operator's verified address only). A wrong code is a failed submission (R8/R9). A cloud verify **timeout/error** is not attack evidence: the edge re-issues the same STEP_UP (HTTP 200) with `EMAIL_OTP` removed from `methods` for the rest of this step-up, `attempts_left` unchanged and no `FALLBACK_FAILED`; nothing is counted by the rate limiter (R11; the failure is recorded as a heartbeat miss). If the sandbox denies SES (`fallback.email_otp.enabled: false`), the method is simply not offered. |
| `STAFF_OVERRIDE` | yes (not high-risk) | yes | `staff_id` required (a submission without it can never match and counts only toward the device backstop); one-time code of `fallback.staff_override.code_length` = **10** digits (`legacy_code_lengths` [8] still accepted, for codes in bundles signed earlier); PBKDF2-HMAC-SHA256 (max(bundle `iterations`, `pbkdf2_iterations` 100 000), per-code salt) matches a code of **that** `staff_id` in the LVB that is not consumed locally, **not** listed in the signed bundle array `consumed_code_ids`, inside its optional signed scope, **and** now < the code's `valid_until` (edge wall clock); marked consumed locally. Failure limits per named staff member + device backstop (below) |

A second factor must verify **for the candidate user** (top-1) — except `STAFF_OVERRIDE`, which
verifies the staff member and is recorded with `staff_id` (for A3 there is no candidate at all:
`user_id` = null). `max_attempts_per_step`=2. Override-code hashes are only ever taken from the last
valid bundle: a received bundle that fails verification is rejected and cannot plant its own override
hash (P5, O45). `valid_until` is stamped by the signer as the bundle's `expires_at` + 24 h
(`fallback.staff_override.valid_after_expiry_h`; a code without `valid_until` gets the same default), so
the guard's codes stay usable for a day after the bundle expires — this is what lets an EXPIRED-cache
step-up (E1/E3) resolve through a staff override (§9.4). The verified TOTP time-step (`totp_step`, a
counter, not a secret) is recorded in the log's `fallback` so the cloud can detect cross-kiosk TOTP
replay (Y07).

Override codes in a live bundle must never be the publicly documented test-fixture codes (`OVR-001`…`OVR-003`
of `config/schedule.example.json`): `scripts/sign_bundle.py` drops them and the cloud's bundle upload rejects
them. Live state 2026-11-14: the cloud-issued v45 still carries them (fix: v46+ with fresh codes, lead action).

**Override code rules** (`edge/policy/fallback.py`):
- **Consumed across kiosks** (SC2-D8): a code whose `code_id` is in the signed `consumed_code_ids` of the LVB
  never matches. The cloud lists a code there after `/v1/sync` received a STAFF_OVERRIDE ALLOW with that
  `code_id`. A code consumed locally never matches either.
- **Optional per-code scope** (F09): a code entry may carry signed `zones` and / or `kiosk_ids` lists.
  An attempt whose zone or kiosk id is not in a listed scope never matches that code (a malformed scope
  never matches). A code without these keys is valid at every kiosk the bundle covers.
- A code entry with a malformed salt never matches.

**Second-factor failure limits** (`edge/policy/lockouts.py`, audit F05 / F06 / SC2-D9 / EO-12). The counters
are persisted in the device-wide `fallback_state.sqlite` (`edge/offline/store.py` `SqliteFallbackState`,
AES-GCM per row, keyed pseudonyms for user / staff / code ids) and run on **real UTC**, never the demo clock.
An edge restart does not reset them. No code, hash or card check runs while a scope is locked.

| Scope | Counts | Limit (`config/thresholds.yaml`) |
|---|---|---|
| `staff:<staff_id>` | a rejected STAFF_OVERRIDE whose `staff_id` is a staff member known to the LVB (`override_codes.codes[].staff_id`) | `fallback.staff_override.max_failures` 3 consecutive → `lockout_s` 300 s; a success or a served lock resets it |
| `device:staff_override` (device backstop) | **every** rejected STAFF_OVERRIDE, unknown and missing staff ids included (those count only here) | `device_max_failures` 10 within `device_window_s` 300 s of the first → `device_lockout_s` 300 s: every override on this device is locked; a success never resets this window |
| `totp:<user_id>` | a wrong or replayed TOTP code for the step-up candidate | `fallback.totp.max_failures` 5 consecutive → `lockout_s` 300 s |
| `card:<user_id>` | a card that is not the candidate's, or a revoked card | `fallback.card.max_failures` 5 consecutive → `lockout_s` 300 s |

- Not counted toward these limits: a method that was not offered (still R8), TOTP without enrolment or without
  a cached secret, a card that cannot be verified (no pepper / no bundle), EMAIL_OTP.
- A failure row that does not decrypt (tampered or written with another key) reads as **locked** (for one
  lockout period from the first read, by the clamp below). A lock that
  lies further ahead than its configured lockout (the real clock stepped backwards) is clamped to now +
  lockout: still locked, never longer than configured.
- A locked method gives `STEP_UP` + `FALLBACK_LOCKED` with `next_action.retry_after_s` (§9.6 R12). It is not
  a factor failure: `attempts_left` is unchanged and nothing reaches the rate limiter.
- The failure that starts a lock emits `ALERT_FALLBACK_LOCKOUT` with `lock` = `STAFF_OVERRIDE_STAFF` (subject =
  the staff id), `STAFF_OVERRIDE_DEVICE` (no subject), `TOTP_USER` or `CARD_USER` (subject = the user id).
- At start-up the runtime compares the state file's random `epoch` with the one the decision log recorded. A
  different epoch (the file was deleted or replaced) emits `ALERT_FALLBACK_STATE_RESET`; consumed codes and
  TOTP steps are always re-seeded from the decision log (`FALLBACK_STATE_RESEEDED` when something was
  re-seeded without an epoch mismatch). Failure counters and locks are not re-seeded.
- Both alerts are edge events (in memory), listed by `GET /v1/admin/alerts` (permission `audit:read`).

**Lost revocation overlay** (EO-08). If the feed file `revocations.enc` was unreadable and quarantined, feed
revocations may be missing (`revocations_state_lost`). Every would-be ALLOW then becomes `STEP_UP`
`[SECOND_FACTOR]` with `OFFLINE_FALLBACK_REQUIRED` (+ `OFFLINE_MODE` offline; the code also appears online),
methods `offline_default` / `online_default`. This runs before the random-challenge draw. STEP_UP and DENY
are unchanged.

### 7.3 Known limits (open, not fixed in code)

- **Challenge evidence is client-asserted (F01, architectural).** The edge verifies blendshape peaks, timings,
  landmark shift and `same_track` that the kiosk client measured and sent. It binds them to the issued
  `challenge_id` / nonce / TTL and checks the last challenge frame's identity, but it does not measure the
  deformation itself and does not run PAD / device / moiré on the challenge frames. A modified kiosk page or a
  local process on the kiosk host can forge a passing challenge (`edge/policy/challenge.py` docstring). A
  passed CHALLENGE is not server-verified liveness.
- **Device backstop as a denial of service.** One anonymous person can lock every staff override on the
  kiosk for 300 s with 10 wrong submissions, and again after each lock. Each lock raises
  `ALERT_FALLBACK_LOCKOUT`. TOTP and CARD are not affected by this lock.
- **Lockout rows are not tamper-proof against deletion.** A tampered row reads as locked, but someone with
  write access to `fallback_state.sqlite` can delete a single failure row and so end that lock without an
  alert. Deleting or replacing the whole file is detected (`ALERT_FALLBACK_STATE_RESET`), but its locks are
  lost.
- **DE-08 (depth M1).** `depth/checks.py` takes the M1 mouth residual as the maximum of the depth-surface
  residual and a displacement computed from client-sent 2D landmarks, so forged landmarks can turn a rigid
  mask from RIGID to DEFORMED. Not fixed: there is no depth calibration data yet to set a
  depth-corroboration bound. Depth is currently disabled (§3.3), so this affects no shipped decision.
- **PAD frames and identity frames are not tied (M01, medium).** The frames that pass PAD need not be the
  frames that produced the match; the any-frame `MATCH_AMBIGUOUS` rule (§3.5) only catches a frame whose top-1
  is a *different enrolled* user. Full fix = embed every PAD-live frame; its latency cost is not measured yet.
- **Own-code rotation replaces old codes (DR2-04, RT2-10, RT2-11; deliberate).** `replace_existing` defaults to
  true: old codes leave the cloud master at once, but an offline kiosk keeps them until its next bundle
  refresh (a consumed code is still blocked fleet-wide via `consumed_code_ids`). There is no separate
  codes/revoke route; replace codes by rotating.
- **`ratelimit:reset` is held by `evaluator` (RT0-08, low).** Evaluator API keys can reset the attack-evidence
  lockout with no `DEMO_MODE` or eval-context gate (bench and eval need it). Mint evaluator keys only for eval
  runs, with a short expiry.
- **Liveness exceptions (EM-M2, low).** PAD / texture exceptions are not caught inside the liveness branch;
  `process_frames` turns them into DENY `SYSTEM_ERROR` (fail-secure, P1), so the attempt is lost, never allowed.

---

## 8. Mode restrictions (SC2)

### 8.1 Mode
`ONLINE` when the connectivity monitor says ONLINE **and** the LVB is online-usable (§5.1: exists,
`FRESH`, refresh age ≤ `schedule.online_max_bundle_age_min`=30) **and** every cloud call of this attempt
succeeded within budget; otherwise `OFFLINE` (P7). **`SYNCING` uses the OFFLINE rules** (offline
thresholds, method sets and `OFFLINE_MODE`). Thresholds: `T = cfg.for_mode(mode)`.

Connectivity monitor (owner: policy-engine, `edge/offline/connectivity.py`): heartbeat
`GET {CLOUD_API_URL}{connectivity.health_path}` (= cloud `GET /v1/health`) every
`connectivity.heartbeat_interval_s`=5 s with timeout `connectivity.heartbeat_timeout_ms`=2000 ms;
`misses_to_offline`=3 consecutive misses → OFFLINE. Natural detection after an outage that starts just
after a good heartbeat: pings at ≈ 5, 10, 15 s; if each has to time out, OFFLINE at ≈ 17 s (15 s + the
last 2 s timeout, plus ≤ 0.5 s scheduler tick); ≈ 15 s if the failures are immediate (connection
refused). A cloud call that fails during an attempt (Rekognition) also counts as a miss.
`successes_to_online`=3 → SYNCING → ONLINE only after the queue is acked and the bundle refreshed
(`require_sync_before_online`). A miss during SYNCING → OFFLINE. `CLOUD_API_URL` empty → permanently
OFFLINE (`reason` `not_configured`).
State: `GET /v1/mode`, which the kiosk badge polls every `connectivity.status_poll_ms` = 2000 ms. It
reports the mode the next attempt would use: a stale or missing online bundle shows `mode` OFFLINE,
`state` OFFLINE, `reason` `bundle_stale`; other reasons are `heartbeat_timeout`, `match_timeout`,
`forced`, `not_configured`; details in `schedule_bundle` (`issued_at`, `cache_state`, `refresh_age_s`,
`rejected`). Demo override: `POST /v1/admin/mode {"force": "OFFLINE" | "AUTO"}` (admin token; env
`FORCE_OFFLINE=1` at start-up = the same forced state) — `OFFLINE` takes effect **immediately** for the
next attempt (heartbeats keep running underneath); `AUTO` hands control back to the heartbeat state
machine (→ SYNCING if the last 3 heartbeats succeeded, else OFFLINE until they do).

### 8.2 Offline rules (applied after schedule)
1. Always add `OFFLINE_MODE`.
2. Bundle `INVALID` → no schedule evaluation. No LVB at all → BIO_PASS/BIO_UNSURE → `DENY`
   [`SCHEDULE_BUNDLE_INVALID`, …], CONTACT_DESK, zone `UNKNOWN` (unknown zone = high risk; nothing to
   verify a staff override against). LVB present but clock rolled back → `STEP_UP`
   [`SCHEDULE_BUNDLE_INVALID`, …], methods = `stepup.methods.cache_untrusted` = `[STAFF_OVERRIDE]`.
3. Bundle `EXPIRED` → evaluate schedule on stale data; deny-type → `DENY` (+`SCHEDULE_EXPIRED_CACHE`);
   IN_WINDOW/GRACE → `STEP_UP` [`SCHEDULE_EXPIRED_CACHE`, …], methods = `[STAFF_OVERRIDE]` (P5).
4. High-risk zone (`risk: high`) → never auto-ALLOW: BIO_PASS+IN_WINDOW → `STEP_UP`
   [`OFFLINE_HIGH_RISK_ZONE`, `OFFLINE_FALLBACK_REQUIRED`], methods = `offline_high_risk`.
5. Zone risk above `offline.auto_allow_max_risk` (default `medium`) treated as rule 4.
6. BIO_UNSURE (IN_WINDOW) → steps = [`CHALLENGE` if LIVENESS cause] + [`SECOND_FACTOR`] always.
7. BIO_PASS + GRACE → `STEP_UP` SECOND_FACTOR (offline methods).
8. The only automatic ALLOW (F1: BIO_PASS + IN_WINDOW + FRESH + low/medium) is subject to the optional
   random challenge at the offline rate (F9; shipped 0.30).
9. Quality exhausted → A3 (STAFF_OVERRIDE manual review, + `OFFLINE_FALLBACK_REQUIRED`) or A6 (high).

### 8.3 Method sets (`stepup.methods`)
| Context | Methods |
|---|---|
| online, low/medium | `[TOTP, CARD, EMAIL_OTP, STAFF_OVERRIDE]` |
| online, high-risk | `[TOTP, CARD, EMAIL_OTP]` |
| offline, low/medium | `[TOTP, CARD, STAFF_OVERRIDE]` |
| offline, high-risk | `[TOTP, STAFF_OVERRIDE]` |
| offline, bundle EXPIRED, or INVALID by clock rollback (`cache_untrusted`) | `[STAFF_OVERRIDE]` |
| quality exhausted, low/medium zone, any mode (A3) | `[STAFF_OVERRIDE]` (`quality_exhausted`) |

YAML keys under `stepup.methods`: `online_default`, `online_high_risk`, `offline_default`,
`offline_high_risk`, `cache_untrusted`, `quality_exhausted`. `EMAIL_OTP` is dropped from any set when
`fallback.email_otp.enabled` is false.

---

## 9. Full decision matrix

Notation: `bio*` = the BIO_UNSURE codes; `S` = schedule code; `+OM` = `OFFLINE_MODE`;
`+OFR` = `OFFLINE_FALLBACK_REQUIRED`; `CH?` = `CHALLENGE` step present iff LIVENESS cause;
`SF?` = `SECOND_FACTOR` present iff MATCH cause; `SF{x}` = SECOND_FACTOR with method set x
(on = online default, onH = online high-risk, off = offline default, offH = offline high-risk, stf = `[STAFF_OVERRIDE]`).
"deny-type" = OUTSIDE_WINDOW / NO_ENTITLEMENT / ZONE_NOT_PERMITTED / HOLIDAY / REVOKED.
`r` = the injected RNG draw for the random challenge (`challenge.random_rate`, shipped 0.15 online / 0.30
offline; a forced draw, §3.4, fires whatever `r` is); "no draw" rows never consume one.

### 9.0 Mode resolution (before every attempt; §8.1)

| # | Condition | Attempt mode | Then |
|---|---|---|---|
| MO1 | connectivity ONLINE; LVB `FRESH`, refresh age ≤ 30 min; all cloud calls succeed | ONLINE | §9.2 |
| MO2 | connectivity ONLINE but refresh age > `schedule.online_max_bundle_age_min` (30) or unknown (no cloud refresh since boot) | OFFLINE (P7) | §9.3 / §9.4 by cache state (usually FRESH) |
| MO3 | connectivity ONLINE but no LVB, or cache `EXPIRED` / `INVALID` (clock rollback) | OFFLINE (P7) | §9.4 / §9.5 |
| MO4 | connectivity OFFLINE or SYNCING, forced OFFLINE, or (Rekognition enabled) the match call fails / times out during the attempt | OFFLINE | §9.3–§9.5 |

### 9.1 Pre-biometric short-circuits (all modes; offline adds `OFFLINE_MODE`)

| # | Condition | Decision | reason_codes | next_action |
|---|---|---|---|---|
| A1 | kiosk locked out (`rate_limit.enabled` and ≥ 5 attack-evidence DENYs in 180 s; lockout 5 s) | DENY | `RATE_LIMITED` | NONE (retry_after_s) |
| A2 | quality fail, recaptures left | STEP_UP | quality codes | RECAPTURE (+ `hint`, `attempts_left`) |
| A3 | quality fail, recaptures exhausted, injection not FAIL, zone low/medium (not "high" per §8.2 rules 4–5) | STEP_UP | quality codes (+OM, +OFR offline) | SF{stf} = manual review (`stepup.methods.quality_exhausted`), attempts_left 1; no schedule, no candidate |
| A6 | quality fail, recaptures exhausted, injection not FAIL, high-risk zone (incl. no LVB / unknown risk) | DENY | quality codes (+OM) | CONTACT_DESK |
| A4 | virtual camera / timing anomaly (also checked on a quality-exhausted attempt) | DENY | `INJECTION_VIRTUAL_CAMERA` | NONE |
| A5 | internal error / invalid input / unknown enum | DENY | `SYSTEM_ERROR` | CONTACT_DESK |

(Former row A7 — device detector FAIL on a quality-exhausted attempt → DENY — is not implemented and
has been withdrawn; such an attempt reaches A3 / A6.)

### 9.2 ONLINE

| # | Bio | Schedule | Zone risk | Decision | reason_codes | next_action |
|---|---|---|---|---|---|---|
| N1 | PASS | IN_WINDOW | low/med, no random challenge (r ≥ `challenge.random_rate`) | **ALLOW** | `ACCESS_OK` | OPEN_DOOR |
| N2 | PASS | IN_WINDOW | high | STEP_UP | `SCHEDULE_HIGH_RISK_ZONE` | SF{onH} |
| N3 | PASS | GRACE_WINDOW | low/med | STEP_UP | `SCHEDULE_GRACE_WINDOW` | SF{on} |
| N4 | PASS | OUTSIDE_WINDOW | any | DENY | `SCHEDULE_OUTSIDE_WINDOW` | NONE |
| N5 | PASS | NO_ENTITLEMENT | any | DENY | `SCHEDULE_NO_ENTITLEMENT` | CONTACT_DESK |
| N6 | PASS | ZONE_NOT_PERMITTED | any | DENY | `SCHEDULE_ZONE_NOT_PERMITTED` | CONTACT_DESK |
| N7 | PASS | HOLIDAY | any | DENY | `SCHEDULE_HOLIDAY` | NONE |
| N8 | PASS | REVOKED | any | DENY | `SCHEDULE_REVOKED` | CONTACT_DESK |
| N9 | UNSURE | IN_WINDOW | low/med | STEP_UP | bio* | CH? → SF?{on} |
| N10 | UNSURE | IN_WINDOW | high | STEP_UP | bio* + `SCHEDULE_HIGH_RISK_ZONE` | CH? → SF{onH} |
| N11 | UNSURE | GRACE or deny-type | any | DENY | bio* + S | CONTACT_DESK |
| N12 | FAIL (spoof/mask/injection) | not evaluated | any | DENY | spoof/mask codes | NONE |
| N13 | FAIL (`NOT_ENROLLED`) | not evaluated | any | DENY | `NOT_ENROLLED` | CONTACT_DESK |
| N14 | PASS | IN_WINDOW | low/med, r < `challenge.random_rate` (0.15 shipped) or forced | STEP_UP | `RANDOM_CHALLENGE` | CHALLENGE |
| N15 | UNSURE because flash `NOT_AVAILABLE` (non-flash path) | IN_WINDOW | low/med | STEP_UP | `LIVENESS_UNSURE` (+ other bio*) | CHALLENGE (→ SF? as N9); high-risk as N10, GRACE/deny-type as N11 |

(GRACE never occurs for high-risk zones because `grace_minutes_high_risk`=0. The random draw happens
only in N1 and F1 situations: every other row is "no draw".)

### 9.3 OFFLINE, bundle FRESH

| # | Bio | Schedule | Zone risk | Decision | reason_codes | next_action |
|---|---|---|---|---|---|---|
| F1 | PASS | IN_WINDOW | low/med, no random challenge (r ≥ offline `challenge.random_rate`) | **ALLOW** | `ACCESS_OK`, `OFFLINE_MODE` | OPEN_DOOR |
| F2 | PASS | IN_WINDOW | high | STEP_UP | `OFFLINE_MODE`, `OFFLINE_HIGH_RISK_ZONE`, `OFFLINE_FALLBACK_REQUIRED` | SF{offH} |
| F3 | PASS | GRACE_WINDOW | low/med | STEP_UP | `SCHEDULE_GRACE_WINDOW`, +OM, +OFR | SF{off} |
| F4 | PASS | deny-type | any | DENY | S, +OM | as N4–N8 |
| F5 | UNSURE | IN_WINDOW | low/med | STEP_UP | bio*, +OM, +OFR | CH? → SF{off} |
| F6 | UNSURE | IN_WINDOW | high | STEP_UP | bio*, +OM, `OFFLINE_HIGH_RISK_ZONE`, +OFR | CH? → SF{offH} |
| F7 | UNSURE | GRACE or deny-type | any | DENY | bio*, S, +OM | CONTACT_DESK |
| F8 | FAIL | not evaluated | any | DENY | fail codes, +OM | as N12/N13 |
| F9 | PASS | IN_WINDOW | low/med, r < offline `challenge.random_rate` (0.30 shipped) or forced | STEP_UP | `RANDOM_CHALLENGE`, +OM | CHALLENGE (no SECOND_FACTOR) |
| F10 | UNSURE because flash `NOT_AVAILABLE` (non-flash path) | IN_WINDOW | low/med | STEP_UP | `LIVENESS_UNSURE` (+ other bio*), +OM, +OFR | CHALLENGE → SF{off}; high as F6, GRACE/deny-type as F7 |

A stale online bundle (MO2) lands here: same rows, offline thresholds, `mode` = OFFLINE.

### 9.4 OFFLINE, bundle EXPIRED (stale may deny, never allow)

| # | Bio | Stale schedule | Decision | reason_codes | next_action |
|---|---|---|---|---|---|
| E1 | PASS | IN_WINDOW or GRACE | STEP_UP | (`SCHEDULE_GRACE_WINDOW` if GRACE), `SCHEDULE_EXPIRED_CACHE`, +OM, (`OFFLINE_HIGH_RISK_ZONE` if high), +OFR | SF{stf} |
| E2 | PASS | deny-type | DENY | S, `SCHEDULE_EXPIRED_CACHE`, +OM | as N4–N8 |
| E3 | UNSURE | IN_WINDOW | STEP_UP | bio*, `SCHEDULE_EXPIRED_CACHE`, +OM, (`OFFLINE_HIGH_RISK_ZONE`), +OFR | CH? → SF{stf} |
| E4 | UNSURE | GRACE or deny-type | DENY | bio*, S, `SCHEDULE_EXPIRED_CACHE`, +OM | CONTACT_DESK |
| E5 | FAIL | not evaluated | DENY | fail codes, +OM | as N12/N13 |

Override codes are stamped `valid_until` = bundle `expires_at` + 24 h
(`fallback.staff_override.valid_after_expiry_h`), so a guard can still resolve E1/E3 through R1 with
an unused code for a day after the bundle expired (O21, O48). Beyond that, every STAFF_OVERRIDE
submission fails (R8 → R9 DENY `FALLBACK_FAILED`) until a newer verified bundle is installed (which
makes the cache FRESH again) — the fail-secure outcome.

### 9.5 Bundle INVALID (no last valid bundle, or clock rollback)

Always OFFLINE (an INVALID cache is never online-usable, MO3). Two cases:

| # | Bio | Case | Decision | reason_codes | next_action |
|---|---|---|---|---|---|
| I1a | PASS | no LVB (nothing ever verified: boot file tampered / unsigned, no cloud bundle yet) | DENY | `SCHEDULE_BUNDLE_INVALID`, +OM | CONTACT_DESK; response `zone` `"UNKNOWN"`, `schedule_result` null |
| I2a | UNSURE | no LVB | DENY | bio*, `SCHEDULE_BUNDLE_INVALID`, +OM | CONTACT_DESK; zone `"UNKNOWN"` |
| I1b | PASS | LVB present, clock rolled back (now < `issued_at` − 300 s) | STEP_UP | `SCHEDULE_BUNDLE_INVALID`, +OM, +OFR | SF{stf} (`cache_untrusted`) |
| I2b | UNSURE | LVB present, clock rolled back | STEP_UP | bio*, `SCHEDULE_BUNDLE_INVALID`, +OM, +OFR | CH? → SF{stf} |
| I3 | FAIL | either | DENY | fail codes, +OM | as N12/N13 |
| I4 | PASS or UNSURE | LVB present, clock rolled back, and the edge holds **any** revocation for the candidate (bundle, user flag or feed; any `revoked_at`) (F04) | DENY | (bio*), `SCHEDULE_REVOKED`, `SCHEDULE_BUNDLE_INVALID`, +OM | CONTACT_DESK |

Without an LVB there is no zone, no risk (treated as high) and no verified override list, so a staff
override could never verify: the honest answer is DENY + CONTACT_DESK. A bundle that fails verification
while an LVB exists is simply rejected and the LVB stays in force — the attempt is evaluated normally
(§5.1, O44). (If the template cache is also unavailable, identity is FAIL → `NOT_ENROLLED`.)
`edge/policy/tests/test_matrix.py` tags I1b/I2b as `I1`/`I2` and the no-LVB rows via
`test_no_last_valid_bundle_denies_contact_desk_r6`. I4 is checked before I1b/I2b (`engine.combine`); test
`test_pf_schedule.py::test_F04_clock_rollback_still_denies_a_revoked_candidate`.

### 9.6 Step-up resolution (all modes)

| # | Submitted evidence | Decision | reason_codes | next_action |
|---|---|---|---|---|
| R1 | all required steps passed, SECOND_FACTOR among them (incl. A3 STAFF_OVERRIDE) | ALLOW | `ACCESS_OK`, `FALLBACK_OK` (+OM) | OPEN_DOOR; `resolved_codes` = trigger codes; `staff_id` logged for STAFF_OVERRIDE |
| R2 | all required steps passed, CHALLENGE only (incl. `RANDOM_CHALLENGE`, non-flash path) | ALLOW | `ACCESS_OK` (+OM) | OPEN_DOOR; `resolved_codes` = trigger codes |
| R3 | required step not yet submitted | STEP_UP | unchanged | remaining steps |
| R4 | CHALLENGE hard fail | DENY | `CHALLENGE_FAILED` (+OM) | NONE |
| R5 | CHALLENGE M1 contradiction | DENY | `MASK_CUE_RIGID` (+OM) | NONE |
| R6 | CHALLENGE soft fail, retry left | STEP_UP | original reason codes + `CHALLENGE_FAILED` | CHALLENGE (new nonce), attempts_left 0 |
| R7 | CHALLENGE soft fail, no retry left | DENY | `CHALLENGE_FAILED` (+OM) | NONE |
| R8 | SECOND_FACTOR wrong / replayed / expired / method not in `methods` / wrong user / cloud OTP verify rejected the code, attempts left | STEP_UP | original reason codes + `FALLBACK_FAILED` | SECOND_FACTOR, attempts_left 0 |
| R9 | SECOND_FACTOR failed, no attempts left | DENY | `FALLBACK_FAILED` (+OM) | NONE |
| R10 | step-up session expired (> `stepup.session_ttl_s` 120 s after the STEP_UP was issued, real clock; exactly 120 s is still open), or the pending challenge's own TTL passed | DENY | `CHALLENGE_FAILED` or `FALLBACK_FAILED` (the pending step) (+OM) | NONE |
| R11 | EMAIL_OTP submitted, cloud verify times out / errors | STEP_UP | codes of the last response (unchanged) | SECOND_FACTOR, `methods` without `EMAIL_OTP` (for the rest of this step-up), attempts_left unchanged; heartbeat miss recorded |
| R12 | SECOND_FACTOR with an offered method whose failure-limit scope is locked (§7.2; no code / hash check) | STEP_UP | original reason codes + `FALLBACK_LOCKED` | SECOND_FACTOR, attempts_left unchanged, `retry_after_s` = ceil(seconds until the lock ends), ≥ 1 |

The step-up session keeps the mode it was opened in (P7). DENYs from R4, R5, R7, R9 and R10 are attack
evidence and count toward A1 (P11); STEP_UP retries (R6, R8, R11, R12) do not. R12 is not a factor failure.
A user revocation received while the step-up was open turns its ALLOW into `DENY` `SCHEDULE_REVOKED`
(+OM), CONTACT_DESK (any `revoked_at`, F11, `PolicyRuntime._revoked_before_allow`). R11 is handled before the
policy is asked to verify anything (`edge/attempts.py` → `PolicyRuntime.drop_method`); if an EMAIL_OTP
submission ever reached `resolve_fallback()` without a cloud verdict it would be an R8 failed
submission (defence in depth, vector S48P).

Protocol errors are not decisions: a submission for an unknown attempt (`404 ATTEMPT_NOT_FOUND`), a
closed attempt (`409 ATTEMPT_CLOSED`), a step that is not pending (`409 INVALID_STATE`) or a reused
challenge nonce (`409 NONCE_REUSED`) is rejected by the HTTP layer (`docs/API.md` §0) before `resolve_stepup()` runs. It produces no
DecisionResponse and no log record, and it does not touch the rate limiter. Only TTL expiry (R10) turns
a pending session into a DENY; an abandoned session that nobody submits to is finalised by the
maintenance tick with its last STEP_UP decision (no new DENY, nothing counted).

### 9.7 Rate limiter (A1) — counting rule (P11)

- Counted: a `DENY` whose codes contain a code starting with one of `rate_limit.counted_code_prefixes`
  (`SPOOF_`, `MASK_CUE_`, `INJECTION_`) or one of `rate_limit.counted_codes` (`CHALLENGE_FAILED`,
  `FALLBACK_FAILED`) — YAML keys read by `edge/policy/ratelimit.py` — **except** a DENY that carries any
  `SCHEDULE_*` code, i.e. the BIO_UNSURE + schedule DENYs N11 / F7 / E4 and the no-LVB DENYs I2a, whose
  `MASK_CUE_*` codes are unsure evidence, not attack evidence. So: spoof / strong-mask / M1-rigid
  (`MASK_CUE_RIGID`) / injection / challenge / fallback DENYs count (also when the step-up started from
  BIO_UNSURE or A3).
- Never counted: schedule, identity (`NOT_ENROLLED`), quality (A6), `SYSTEM_ERROR`, `RATE_LIMITED`, the
  R11 EMAIL_OTP re-issue, STEP_UP retries, and protocol errors (404/409, no decision).
- Sliding window per kiosk on the monotonic clock: on a counted DENY at time t, drop events older than
  t − `window_s` (an event at exactly t − 180 s still counts), append t; if the count ≥ `max_failures`
  (5) → `lockout_until` = t + `lockout_s` (**5 s**, operator request 2026-11-14; was 60 s) and raise
  `ALERT_RATE_LIMIT_LOCKOUT` (event stream `GET /v1/events`). The DENY that triggers the lockout is
  returned normally; attempts started while now < `lockout_until` get A1 with `retry_after_s` =
  max(1, ceil(`lockout_until` − now)).
- `RATE_LIMITED` DENYs are not recorded: they neither extend the lockout nor re-arm the counter. Events
  stay in the window after a lockout ends, so one more counted DENY inside the window locks again.
- `POST /v1/admin/rate-limit/reset` clears events and lockout. `rate_limit.enabled: false` (eval/demo
  profile only) disables both counting and blocking. Open step-up sessions are not blocked by a lockout.

---

## 10. Response schema

```json
{
  "attempt_id": "att_01JD…",              "kiosk_id": "KIOSK_LIB_01", "zone": "LIBRARY",
  "decision": "STEP_UP",                   "reason_codes": ["LIVENESS_UNSURE"],
  "resolved_codes": [],                    "next_action": { "...": "see §7" },
  "bio_result": "BIO_UNSURE",              "schedule_result": "IN_WINDOW",
  "mode": "ONLINE",                        "cache_state": "FRESH",
  "candidate": {"user_id": "u_3c4d", "display": "Priya N.", "role": "student"},
  "scores": {"pad_mean": 0.71, "pad_pass_frames": 2, "flash_r": 0.82, "flash_amp": 9.1,
             "moire": 0.12, "device_conf": 0.0, "depth": null, "mask": {},
             "match_local": 0.72, "match_margin": 0.31, "rekognition": 99.6, "rekognition_runner_up": null,
             "signals": {"pad": "UNSURE", "device": "PASS", "moire": "PASS", "flash": "ADVISORY_PASS",
                         "mask": "PASS", "depth": "NOT_AVAILABLE", "injection": "PASS"}},
  "latency_ms": {"total": 1430, "liveness": 310, "match": 420, "schedule": 18, "policy": 2},
  "policy_version": "2026-11-14.3",        "bundle_version": 42,
  "display_message": "Please follow the on-screen check"
}
```

The response also carries `stage` (`precheck | quality | injection | liveness | match | schedule | mode |
challenge | fallback | final | system`, API.md v1.1). `zone` is `"UNKNOWN"` when there is no last valid
bundle (I1a/I2a). `candidate` is null on BIO_FAIL and on A3 (the BIO_FAIL top-1 is logged internally
only, as `candidate_user_id`). Kiosk UI shows `display_message` + first reason code (human text). For BIO_UNSURE + schedule deny it
shows a generic "Access not available — please contact the desk" (no schedule detail to a person
whose identity is unconfirmed). `ui.show_detailed_reasons` (demo: true) shows all codes. `STEP_UP` is
labelled "REQUEST VERIFICATION" (subtitle "step-up"). `scores.signals` gives each liveness signal's zone
(`PASS | PASS_AMBIENT | UNSURE | FAIL | NOT_AVAILABLE | ADVISORY_<zone>`; null if liveness never ran). The
exact wire format is `docs/API.md` (v1.3);
this section lists the policy fields it must carry. `latency_ms.total` is server-side; the user-visible
face-lock → rendered latency comes from the `POST /v1/attempt/{id}/rendered` beacon.
Latency evidence: the stored latency file is `eval/results/latency_edge_1280_20261114T171323Z.md` (edge-only
bench on synthetic 1280×720 frames, localhost, cloud not configured, n = 40; it excludes face lock, the capture window, the
cloud match and rendering). Face-lock → rendered latency (with and without the early cloud probe):
**measurement pending**. No eval run exists yet.

---

## 11. Pseudocode

Mirrors `edge/policy/engine.py` (`evaluate`, `combine`), `edge/policy/stepup.py` (`resolve_*`),
`edge/policy/ratelimit.py` and `edge/policy/runtime.py` (`PolicyRuntime.decide`). The engine is pure:
no I/O, no clock reads (`now` is injected), randomness only through the injected `rng`.

```python
# edge/policy/engine.py — pure; I/O (models, cloud, DB, clocks) stays in the runtime / perception layer.
ALLOW, STEP_UP, DENY = "ALLOW", "STEP_UP", "DENY"
BIO_PASS, BIO_UNSURE, BIO_FAIL = "BIO_PASS", "BIO_UNSURE", "BIO_FAIL"
DENY_TYPE = {"OUTSIDE_WINDOW", "NO_ENTITLEMENT", "ZONE_NOT_PERMITTED", "HOLIDAY", "REVOKED"}
SCHED_CODE = {"GRACE_WINDOW": "SCHEDULE_GRACE_WINDOW", "OUTSIDE_WINDOW": "SCHEDULE_OUTSIDE_WINDOW",
              "NO_ENTITLEMENT": "SCHEDULE_NO_ENTITLEMENT", "ZONE_NOT_PERMITTED": "SCHEDULE_ZONE_NOT_PERMITTED",
              "HOLIDAY": "SCHEDULE_HOLIDAY", "REVOKED": "SCHEDULE_REVOKED"}
CONTACT_DESK_CODES = {"NOT_ENROLLED", "SCHEDULE_NO_ENTITLEMENT", "SCHEDULE_ZONE_NOT_PERMITTED",
                      "SCHEDULE_REVOKED", "SYSTEM_ERROR", "SCHEDULE_BUNDLE_INVALID"}
RISK = {"low": 0, "medium": 1, "high": 2}


def online_bundle_ok(ctx, now, T) -> bool:
    """§5.1 / §9.0: ONLINE needs an LVB, cache FRESH and refresh age <= online_max_bundle_age_min."""
    if ctx.lvb is None or cache_state(ctx.lvb, now, T.cache) != "FRESH":
        return False
    return ctx.refresh_age_s is not None and 0 <= ctx.refresh_age_s <= T.schedule.online_max_bundle_age_min * 60


def is_high(risk, mode, T) -> bool:
    r = risk if risk in RISK else "high"                      # no LVB / unknown risk -> high
    if mode == "OFFLINE":                                     # §8.2 rules 4-5
        return r == "high" or RISK[r] > RISK[T.offline.auto_allow_max_risk]
    return r == "high"


def evaluate(signals, ctx, mode, now, *, cfg, rate_limit_retry_s=None, rng=None) -> Decision:
    """Never raises: any exception (incl. unknown enum / mode, naive datetimes) -> DENY SYSTEM_ERROR (P1)."""
    try:
        return _evaluate(signals, ctx, mode, now, cfg, rate_limit_retry_s, CountingRng(rng))  # <= 1 draw
    except Exception as exc:
        return system_error(signals, ctx, mode, now, cfg, detail=repr(exc))


def _evaluate(signals, ctx, mode, now, cfg, retry_s, rng):
    if mode not in ("ONLINE", "OFFLINE"):
        raise ValueError("unknown mode")                      # SYNCING / forced arrive here as OFFLINE
    lvb = ctx.lvb                                             # last VERIFIED bundle (+ revocation feed) or None
    zone = kiosk_zone(lvb, ctx.kiosk_id)                      # zone / risk only ever from the LVB
    if mode == "ONLINE" and not online_bundle_ok(ctx, now, cfg.for_mode("ONLINE")):
        mode = "OFFLINE"                                      # MO2 / MO3 (P7) -- not a heartbeat miss
    T = cfg.for_mode(mode)
    cache = cache_state(lvb, now, T.cache) if lvb else "INVALID"
    risk = zone_risk(lvb, zone) if (lvb and zone) else None

    # 0. rate limit: the runtime passes the seconds left of an active lockout (None = not locked)
    if T.rate_limit.enabled and retry_s:
        return finish(DENY, ["RATE_LIMITED"], NextAction("NONE", retry_after_s=max(1, ceil(retry_s))))  # A1
    # 1. quality gate (< 3 frames submitted -> ValueError -> SYSTEM_ERROR)
    q = quality_gate(signals.frames, signals.depth, T)
    if q.codes:
        if signals.recapture_count < T.quality.max_recaptures:                                    # A2
            return finish(STEP_UP, q.codes, NextAction("RECAPTURE", hint=HINTS[q.codes[0]],
                          attempts_left=T.quality.max_recaptures - signals.recapture_count - 1))
        if injection_check(signals.camera, signals.frames, T) == "FAIL":                          # A4
            return finish(DENY, ["INJECTION_VIRTUAL_CAMERA"], NextAction("NONE"))
        if is_high(risk, mode, T):                                                                # A6
            return finish(DENY, q.codes, NextAction("CONTACT_DESK"))
        codes = q.codes + (["OFFLINE_FALLBACK_REQUIRED"] if mode == "OFFLINE" else [])            # A3
        return finish(STEP_UP, codes, NextAction("SECOND_FACTOR", steps=["SECOND_FACTOR"],
                      methods=methods(T, "quality_exhausted"), attempts_left=1))   # no candidate, no schedule
    # 2. injection (timing judged on ALL submitted frames)
    inj = injection_check(signals.camera, signals.frames, T)                         # PASS | UNSURE | FAIL
    if inj == "FAIL":
        return finish(DENY, ["INJECTION_VIRTUAL_CAMERA"], NextAction("NONE"))
    # P7: Rekognition enabled online but its result is missing / failed -> the whole attempt is OFFLINE
    rek = T.match.rekognition.enabled
    cloud_miss = mode == "ONLINE" and rek and not (signals.cloud_match and signals.cloud_match.ok)
    if cloud_miss:
        mode, T = "OFFLINE", cfg.for_mode("OFFLINE")          # runtime records a heartbeat miss
        cache = cache_state(lvb, now, T.cache) if lvb else "INVALID"
    # 3 + 4 on the same raw scores (inference already ran in parallel in the perception layer)
    live = liveness_fusion(q.usable, signals, inj, T, mode)  # flash ADVISORY / NOT_AVAILABLE handled inside
    if mode == "ONLINE" and rek:
        ident = identity_match(q.usable, signals.cloud_match, T, "ONLINE", signals.template_cache_age_h)
    else:                                                     # offline, or Rekognition disabled online
        ident = identity_match(q.usable, None, cfg.for_mode("OFFLINE"), "OFFLINE", signals.template_cache_age_h)
    # 5. biometric result
    bio, bio_codes, causes = biometric_result(live, ident, T.liveness.mask.strong_cue_deny_count)
    if bio == BIO_FAIL:                                       # candidate_user_id logged, never displayed
        return finish(DENY, bio_codes, NextAction("CONTACT_DESK" if bio_codes == ["NOT_ENROLLED"] else "NONE"))
    # 6. schedule (SC1) on the LVB, both modes; no cloud call
    sched = None
    merged = lvb_with_revocation_feed(ctx)
    if lvb and cache != "INVALID":                            # F03: held revocations count up to t0 + slack
        sched = evaluate_schedule(ident.user_id, zone, signals.t0, merged, T.schedule,
                                  revocation_slack_s=T.cache.clock_rollback_tolerance_s)
    elif lvb and revoked_any(merged, ident.user_id):          # F04: clock untrusted, deny-only check survives
        sched = "REVOKED"
    # 7 + 8. mode restrictions + final decision (the matrix, §9)
    comb = combine(bio, bio_codes, causes, sched, cache, risk, mode, T, lvb=lvb is not None)
    if comb.decision == ALLOW and ctx.revocations_incomplete:  # EO-08: lost feed overlay -> second factor
        off = mode == "OFFLINE"
        comb = Combined(STEP_UP, (["OFFLINE_MODE"] if off else []) + ["OFFLINE_FALLBACK_REQUIRED"], ["SECOND_FACTOR"],
                        methods(T, "offline_default" if off else "online_default"))
    # 8b. random challenge: only a would-be ALLOW, exactly one draw (P12); rng None = OFF;
    #     rng.forced = FORCE / FORCE_NEXT demo control (fires whatever the rate)
    if comb.decision == ALLOW and rng.rng is not None and (rng.random() < T.challenge.random_rate or rng.forced):
        comb = Combined(STEP_UP, ["RANDOM_CHALLENGE"], ["CHALLENGE"], None)          # N14 / F9
    if comb.decision == STEP_UP:
        nxt = NextAction(comb.steps[0], steps=comb.steps, methods=comb.methods, attempts_left=1)
    elif comb.decision == ALLOW:
        nxt = NextAction("OPEN_DOOR")
    else:
        nxt = NextAction("CONTACT_DESK" if contact_desk(comb.codes, bio) else "NONE")
    return finish(comb.decision, comb.codes, nxt)

    # finish(decision, codes, next_action): adds OFFLINE_MODE when mode == OFFLINE, orders the codes
    # (an unknown code raises -> SYSTEM_ERROR), and raises on empty codes (P9; explicit check, no assert).


def biometric_result(live, ident, strong_deny_count=2):
    strong_deny = len(live.strong_mask_codes) >= strong_deny_count
    if live.hard_codes or strong_deny:
        codes = live.hard_codes + (live.strong_mask_codes if strong_deny else [])
        return BIO_FAIL, codes + (["NOT_ENROLLED"] if ident.status == "FAIL" else []), set()
    if ident.status == "FAIL":
        return BIO_FAIL, ["NOT_ENROLLED"], set()
    causes, codes = set(), []
    if live.status == "UNSURE" or live.mask_codes:
        causes.add("LIVENESS"); codes += live.mask_codes + live.unsure_codes
    if ident.status == "UNSURE":
        causes.add("MATCH"); codes += ident.codes                 # MATCH_LOW | MATCH_AMBIGUOUS
    return (BIO_UNSURE, codes, causes) if causes else (BIO_PASS, [], set())


def combine(bio, bio_codes, causes, sched, cache, risk, mode, T, *, lvb=True) -> Combined:
    off = mode == "OFFLINE"
    om = ["OFFLINE_MODE"] if off else []
    if not lvb:                                               # I1a / I2a: nothing verified to trust
        return Combined(DENY, bio_codes + ["SCHEDULE_BUNDLE_INVALID"] + om, [], None)        # CONTACT_DESK
    if off and cache == "INVALID" and sched == "REVOKED":     # I4 (F04): held revocation, clock rolled back
        return Combined(DENY, bio_codes + ["SCHEDULE_REVOKED", "SCHEDULE_BUNDLE_INVALID"] + om, [], None)
    if off and cache == "INVALID":                            # I1b / I2b: LVB present, clock rolled back
        steps = (["CHALLENGE"] if "LIVENESS" in causes else []) + ["SECOND_FACTOR"]
        return Combined(STEP_UP, bio_codes + ["SCHEDULE_BUNDLE_INVALID"] + om + ["OFFLINE_FALLBACK_REQUIRED"],
                        steps, methods(T, "cache_untrusted"))
    if sched not in DENY_TYPE | {"IN_WINDOW", "GRACE_WINDOW"}:
        raise ValueError("unknown schedule result")           # P1
    high = is_high(risk, mode, T) and (off or T.schedule.high_risk_requires_stepup_online)   # S32
    exp = ["SCHEDULE_EXPIRED_CACHE"] if off and cache == "EXPIRED" else []
    s_code = [SCHED_CODE[sched]] if sched in SCHED_CODE else []
    if sched in DENY_TYPE:                                    # stale data may deny (P5)
        return Combined(DENY, bio_codes + s_code + exp + om, [], None)
    if bio == BIO_UNSURE and sched != "IN_WINDOW":            # two uncertainties -> DENY
        return Combined(DENY, bio_codes + s_code + exp + om, [], None)
    if bio == BIO_PASS and sched == "IN_WINDOW" and not high and not exp:
        return Combined(ALLOW, ["ACCESS_OK"] + om, [], None)                                  # N1 / F1
    steps = ["CHALLENGE"] if "LIVENESS" in causes else []
    codes = bio_codes + s_code + (["OFFLINE_HIGH_RISK_ZONE" if off else "SCHEDULE_HIGH_RISK_ZONE"] if high else [])
    if "MATCH" in causes or sched == "GRACE_WINDOW" or high or off:
        steps.append("SECOND_FACTOR")
    codes += exp + om + (["OFFLINE_FALLBACK_REQUIRED"] if off and "SECOND_FACTOR" in steps else [])
    key = ("cache_untrusted" if exp else ("offline_high_risk" if high else "offline_default") if off
           else ("online_high_risk" if high else "online_default"))
    return Combined(STEP_UP, codes, steps, methods(T, key) if "SECOND_FACTOR" in steps else None)


def methods(T, key):                                          # §8.3; EMAIL_OTP dropped if SES is off
    return [m for m in T.stepup.methods[key] if m != "EMAIL_OTP" or T.fallback.email_otp.enabled]


def contact_desk(codes, bio) -> bool:
    return bio == BIO_UNSURE or any(c in CONTACT_DESK_CODES for c in codes)
```

```python
# edge/policy/stepup.py — the only loosening operation (P4). Sessions are immutable; schedule never re-run.
def resolve_challenge(s, evidence, now_real, cfg, new_challenge_fn, wall_now):
    if s.status != OPEN: raise SessionClosed                  # HTTP 409 ATTEMPT_CLOSED (checked earlier too)
    if now_real > s.expires_at or now_real > s.challenge.expires_at:
        return deny(s, ["CHALLENGE_FAILED"])                                                  # R10
    out = verify_challenge(s.challenge, evidence, T, depth_enabled=T.liveness.depth.enabled)
    if out == M1_CONTRADICTION: return deny(s, ["MASK_CUE_RIGID"])                            # R5
    if out == HARD_FAIL:        return deny(s, ["CHALLENGE_FAILED"])                          # R4
    if out == SOFT_FAIL:
        if s.challenge_soft_fails < T.challenge.soft_fail_retries:                            # R6
            return retry(s, extra="CHALLENGE_FAILED", challenge=new_challenge_fn(now_real), attempts_left=0)
        return deny(s, ["CHALLENGE_FAILED"])                                                  # R7
    return after_pass(s, "CHALLENGE")                         # R3 (next step pending) or R2 ALLOW


def resolve_fallback(s, sub, now_real, cfg, verifier, wall_now):
    if now_real > s.expires_at: return deny(s, ["FALLBACK_FAILED"])                           # R10
    res = verifier.verify(sub, s.candidate_user_id, s.mode, now_real, wall_now, zone=s.zone, kiosk_id=s.kiosk_id) \
        if sub.method in s.methods else None
    if res is not None and not res.ok and res.locked_until is not None:   # R12: locked, nothing checked or counted
        return retry(s, extra="FALLBACK_LOCKED", retry_after_s=max(1, ceil(res.locked_until - now_real)))
    ok = res is not None and res.ok
    # failure limits (§7.2) are counted inside verifier.verify on real UTC and persisted
    # TOTP/CARD/EMAIL_OTP bind to the candidate; STAFF_OVERRIDE binds to staff_id, needs wall_now < valid_until
    # and an unused code of the LVB, then consumes it. (EMAIL_OTP with the cloud verify unreachable never gets
    # here: the HTTP layer re-issues the STEP_UP without EMAIL_OTP via runtime.drop_method, R11.)
    if not ok:
        s.factor_failures += 1
        if s.factor_failures < T.stepup.max_attempts_per_step:
            return retry(s, extra="FALLBACK_FAILED", attempts_left=0)                         # R8
        return deny(s, ["FALLBACK_FAILED"])                                                   # R9
    return after_pass(s, "SECOND_FACTOR", fallback=verified_info)  # R1: ACCESS_OK + FALLBACK_OK;
    # resolved_codes = trigger codes (original STEP_UP codes minus OFFLINE_MODE / OFFLINE_FALLBACK_REQUIRED /
    # CHALLENGE_FAILED / FALLBACK_FAILED); A3: user_id stays None, staff_id logged
```

```python
# edge/policy/ratelimit.py — counted on the monotonic clock (P11), thresholds.rate_limit = RL
def counts_toward_rate_limit(decision, codes, RL) -> bool:
    if decision != DENY:
        return False
    if any(c.startswith("SCHEDULE_") for c in codes):         # N11 / F7 / E4 / I2a: unsure evidence only
        return False
    return any(c in RL.counted_codes or c.startswith(tuple(RL.counted_code_prefixes)) for c in codes)


# edge/policy/runtime.py — PolicyRuntime.decide (I/O + clocks live here, under one lock)
def decide(signals):
    wall, real = now_wall(), now_real()                       # wall = demo clock when DEMO_MODE=1
    if not valid(signals): return persist(system_error(...))  # invalid input -> logged DENY SYSTEM_ERROR
    if closed(signals.attempt_id): raise AttemptClosedError   # HTTP 409
    signals = rebase_t0(signals)                              # client lag clamped to [0, t0_max_lag]
    d = evaluate(signals, bundles.schedule_ctx(revocation_feed), monitor.mode(), wall, cfg=cfg,
                 rate_limit_retry_s=limiter.retry_after_s(monotonic()), rng=attempt_rng())  # None when OFF
    monitor.record(False, "match_timeout") if d.cloud_miss else ...   # P7: also a heartbeat miss
    if d.decision == STEP_UP and d.next_action.steps:
        open_session(d, real, cfg, new_challenge(...) if "CHALLENGE" in d.next_action.steps else None)
    d = persist(d)          # minimal SC2.5 record BEFORE returning (STEP_UP waits as one pending record per
                            # attempt); write failure -> DENY SYSTEM_ERROR (P9), never an unlogged ALLOW
    if limiter.record(d.decision, d.reason_codes, monotonic()):   # True when this DENY starts a lockout
        emit("ALERT_RATE_LIMIT_LOCKOUT")                       # GET /v1/events
    return d.to_response(latency_ms)
# Any exception escaping the runtime is converted by the HTTP layer (edge/attempts.py) into a logged
# DENY SYSTEM_ERROR via runtime.decide_error() -- never HTTP 500 (P1).
```

Notes for the implementer:
- `liveness_fusion` implements §3.3–3.4 and returns `status`, `hard_codes`, `unsure_codes`,
  `mask_codes` (all cues), `strong_mask_codes`, `signals` (incl. `flash` = `PASS_AMBIENT` / `ADVISORY_*`)
  and `scores`. It is called with the effective mode's thresholds; the P7 flip happens **before**
  fusion, so the same raw scores are thresholded once with the right bars (no re-inference).
- `identity_match` online = Rekognition + local cross-check; offline or Rekognition disabled = local
  only with the offline bars (§3.5).
- There is **no** per-attempt cloud schedule call: online and offline both run `evaluate_schedule`
  (`edge/policy/schedule.py`) on the LVB (§5.1). The cloud runs the same module to re-evaluate offline
  decisions at sync (SC2.6).
- `rng` is injected (`secrets.SystemRandom` in production, a stub in tests, `None` when the demo control
  is `OFF`); it is consulted only in step 8b.
- Keep `combine` a pure function: it is the matrix in §9 and is exhaustively tested
  (`edge/policy/tests/test_matrix.py`). The random challenge and A2/A3/A6 live outside `combine` so the
  matrix tests stay deterministic.
