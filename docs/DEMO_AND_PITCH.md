# DEMO_AND_PITCH: 5-minute demo, slides, judge Q&A

**No evaluation run exists yet.** No eval capture has been run; `eval/results/runs/` holds only a read-only metrics
snapshot with 0 attempts (`eval/results/runs/snapshot_20261114T171349Z/SNAPSHOT.md`). The iBeta Level 1-style
protocol is **designed**, not run, so there are no APCER / BPCER / FAR / FRR numbers to show. Once a run exists, every
evaluation number spoken or shown comes from `eval/results/report/metrics.json` at the `freeze` tag (or a later rerun)
and is stated with its 95% upper bound. Rules: `.claude/skills/pad-evaluation/SKILL.md` section 9. Placeholders such
as `[k/N]`, `[UB]`, `[p95]` are filled from the JSON only. Never fill them by estimate.
The only other numbers allowed on stage are the measurements below, each with a stored source file and always
labelled as not an eval result:

| Measurement (not an eval result) | Value | Stored source |
|---|---|---|
| Edge server total `latency_ms.total` (frames received → decision), server side only: synthetic 1280×720 frames, Apple M4, offline, local match, policy 2026-11-14.3. Excludes face lock, the 700 ms capture window, Rekognition and rendering | p50 76.0 ms [95% bootstrap CI 75.0–81.0], p95 106.4 ms [95% bootstrap CI 88.1–122.0], n = 40 | `eval/results/latency_edge_1280_20261114T171323Z.md` (+ `.csv`) |
| Automated tests | edge + policy + offline + depth 1344 passed; cloud 147 passed; eval 129 passed; kiosk tsc / lint / build OK; ruff clean | `eval/results/tests_20261114T1705Z.txt` |
| MiniFASNet self-test (`GET /v1/health` → `self_test`) | output index 1 = real; input raw 0–255 BGR | live `GET /v1/health` (re-checked at startup) |

**Kiosk face lock → decision rendered** (the user-visible 2 s number, `POST /v1/attempt/{id}/rendered` beacon):
**measurement pending**. Earlier live `/v1/metrics` samples were in memory only, were lost at edge restarts and have
no stored file, so they are not quoted anywhere. The early cloud probe (`docs/API.md` §3.1a) is live since the edge
restart with policy 2026-11-14.3 and is not measured either. Before any client latency goes on a slide: record it
(e.g. a `snapshot_metrics.py` snapshot after a set of attempts) into `eval/results/`, then quote it with n and its CI,
as "p95 under 2 s **in this sample**" if it is, never "always" or "guaranteed", and never rounded.

Judging weights: Problem-Solution Fit 25 · Technical 25 · Innovation 20 · Functionality/Usability 15 · Presentation 15.

Sources for every expected outcome below: `docs/DECISION_POLICY.md` (matrix rows N*/F*/R*), the code
(`edge/policy/engine.py`, `liveness.py`, `identity.py`, `schedule.py`, `stepup.py`), **the installed bundle
`edge/data/bundle.signed.json`** and `config/thresholds.yaml`. The installed bundle is the **cloud-issued v45**
(`issued_at` 2026-11-14T12:30:41Z = 18:00:41 IST, `expires_at` 00:30:41Z = 06:00:41 IST on 15 Nov), built from the
cloud's copy of `config/schedule.demo.json` and **filtered to `KIOSK_MAIN_01` / MAIN_GATE only**. It still holds the
publicly documented fixture override codes `OVR-001`…`OVR-003` until the lead uploads v46+ with fresh codes.
`config/schedule.example.json` is the test fixture behind the canonical test vectors (Q01, L05, S01 …) in
`docs/POLICY_TEST_CASES.md`; where a step cites a vector, the vector uses the fixture users (Priya, Rahul) and the step
uses the demo user with the same role and rule.
Kiosk wording: the middle outcome is shown as **REQUEST VERIFICATION** (subtitle "step-up"); the API value stays `STEP_UP`.

---

## 1. Five-minute live demo script

### 1.1 Setup and pre-flight (before going on stage)

Layout: kiosk laptop facing the presenter; projector shows the kiosk UI (`http://localhost:5173/?mock=0`) and the
`/admin` dashboard (`http://localhost:5173/admin?mock=0`) side by side: live decision feed from `GET /v1/events`, metrics
from `GET /v1/metrics`, mode badge, sync-queue counter. Use `localhost`: Vite listens on IPv6 `[::1]:5173` only, so
`127.0.0.1:5173` refuses. The kiosk result screen shows **decision + plain-language reason + decision time +
ONLINE/OFFLINE badge**, plus a **DEMO CLOCK** badge whenever the demo clock is active. The badge polls `GET /v1/mode`
every 2 s (`connectivity.status_poll_ms` 2000). "Decision time" on screen is the **client face lock → rendered**
latency from the `POST /v1/attempt/{id}/rendered` beacon; the server `latency_ms.total` is shown next to it in the
operator view.

People: the **presenter** talks; the **subject** is Prajwal (`u_prj1`, "Prajwal M.", role `student`, demo card
`HID-DEMO-0001`). **No glasses on camera** for the scripted run: spectacle frames score 0.35–0.80 on the enforced RGB
mask ring (M2, bands 0.50 / 0.75), so glasses can turn a genuine ALLOW into REQUEST VERIFICATION. The **operator**
(physical tasks only) holds props and fires the admin calls: from the `/admin` page control panel
(`kiosk/src/admin/panels/ControlPanel.tsx`: mode force OFFLINE / AUTO, sync now, rate-limit reset, demo clock, and a
**random liveness challenge** control with `AUTO` / `FORCE_NEXT` / `FORCE` / `OFF` buttons showing the current mode;
admin token required, `DEMO_MODE=1`), or with the curl lines in 1.4 as the fallback. A consenting teammate who is **not enrolled** is needed for step 6 (the bundle placeholders `u_tm02`–`u_tm04`
are "Team member 2–4"; check with `GET /v1/admin/users` who has a template). Rekognition collection `hid-kiosk-users`
holds `u_prj1` and `u_tm03`; `u_tm02` is enrolled on the edge only, so online it gets no cloud match. Never put a judge or
audience member in front of the camera: online frames go to Rekognition, and only consenting team faces are used.

Today is **Saturday 14 Nov 2026** (IST). The live bundle v45 has one zone, so every step runs at `KIOSK_MAIN_01`:

| Subject at zone | Rule in v45 | Window (Sat) | Grace |
|---|---|---|---|
| `u_prj1` at MAIN_GATE (low) | student role | 06:00–22:00 (Sun 08:00–20:00) | 15 min (`schedule.grace_minutes`) → grace 22:00–22:15, outside from 22:15 |

**There is no kiosk switch today.** v45 lists only `KIOSK_MAIN_01`, so `session/start` for `KIOSK_LIB_01` /
`KIOSK_SRV_01` returns `403 FORBIDDEN`, and an edge restarted as `KIOSK_SRV_01` would reject v45 (scope mismatch). The
LIBRARY and SERVER_ROOM scenarios exist only as test vectors (S01, O04, F2) and as the recorded backup clip.

**Demo-clock rule** (`docs/API.md` §3.14): any demo-clock time must be later than the bundle's `issued_at` − 300 s
(**after ~17:55:41 IST with v45**), or the cache reads as clock rollback (INVALID). If the lead installs v46+, the bar
moves to v46's `issued_at` − 300 s; sign it with `scripts/sign_bundle.py --version 46 --now <early enough>` if the demo
clock must go back to e.g. 21:00.

Props, in order: A4 colour print of Prajwal · phone showing Prajwal's photo · phone playing a short video of Prajwal
(blinking, smiling) · eye-cut print of Prajwal (worn by a teammate) · demo card ID `HID-DEMO-0001` · Prajwal's
authenticator app (the `u_prj1` TOTP) · backup video cued (including a recorded virtual-camera / injection clip, since
OBS Studio is not installed on the kiosk laptop). **No staff code**: v45 carries only the public fixture codes, so
STAFF_OVERRIDE is not used in the scripted run; the CARD and TOTP are the fallback factors.

Pre-flight checklist (rehearse once, end to end):

| # | Check | Why |
|---|---|---|
| P1 | Edge runs with `DEMO_MODE=1`, `KIOSK_ID=KIOSK_MAIN_01`; `GET /v1/health` → `status: ok`, all models loaded, `self_test.passed` true (`minifasnet_real_index` 1, `input_scale` "0-255 BGR"), `detail.policy_runtime` `real` | anything else means the policy runtime is fail-secure (every attempt DENY `SYSTEM_ERROR`) |
| P2 | `GET /v1/mode` → `schedule_bundle.version` 45 (or the lead's v46+), `cache_state` FRESH, `expires_at` after the end of the run. **Do not run `scripts/sign_bundle.py` with its defaults**: it signs `bundle_version` 42 from `config/schedule.demo.json`, which the edge rejects as older than v45 (`BUNDLE_REJECTED`, the LVB stays), and it overwrites `edge/data/DEMO_CODES.txt`. A replacement needs `--version` > the installed version | the demo clock is moved to 22:10–22:30; both are after v45's `issued_at` − 300 s. Later than `issued_at` + 12 h (`cache.bundle_max_staleness_hours`) → EXPIRED. The demo clock never re-signs the bundle |
| P3 | `GET /v1/mode` → `mode` ONLINE, `schedule_bundle.refresh_age_s` < 1800, `demo_clock` null | online needs a bundle confirmed by the cloud within `schedule.online_max_bundle_age_min` (30 min); otherwise every attempt runs OFFLINE with mode reason `bundle_stale`. The cloud 304 confirmation every `cache.bundle_refresh_interval_min` (15) keeps it fresh |
| P3b | Nobody `PUT`s a new schedule during the run. Cloud `GET /v1/admin/schedule` (kiosk-signed + `X-Admin-Token`) → `doc.users` contains `u_prj1` | step 14 re-checks each offline ALLOW against the cloud's authoritative document; a document without `u_prj1` would show `SCHEDULE_CHANGED` / `ALERT_SCHEDULE_MISMATCH` on stage. A newer bundle published during the run moves the demo-clock bar (P2) |
| P4 | Profile in `config/thresholds.yaml` (shipped, do not change): `challenge.random_rate` 0.15 and `offline.overrides.challenge.random_rate` 0.30; `liveness.moire.enforce` true; `liveness.mask.m2_rgb_enforce` true; `liveness.flash.enforce` false; `liveness.depth.enabled` false; `rate_limit.enabled` true. **Pre-run**: `POST /v1/admin/random-challenge {"mode": "OFF"}` and `POST /v1/admin/rate-limit/reset` | random challenges stay on in the product; they are switched **off for the scripted run only**, so no scripted ALLOW draws one by chance (the mode is in memory: re-send `OFF` after any edge restart, which resets it to `AUTO`). Moiré and M2 are enforced; flash is **advisory** and depth is off, and we say both on stage |
| P5 | `GET /v1/admin/users` lists `u_prj1` with templates, `totp_local` true, `card` true; `GET /v1/mode` → `template_cache.age_h` < 72; the step-6 teammate is **not** listed | offline matching is local-only against this kiosk's entitled users; a template cache older than `cache.template_cache_max_age_hours` (72) is unusable |
| P6 | One online dry run of Prajwal: ALLOW. **Expected today** (cold connections): `reason_codes` `[ACCESS_OK, OFFLINE_MODE]`, `scores.rekognition` null, while the badge says ONLINE, and `GET /v1/mode` `cloud_match.degraded` true. The early probe is live since the edge restart with policy 2026-11-14.3; the target is ALLOW `[ACCESS_OK]` with `scores.rekognition` set (not yet measured, so check which you get) | from the venue the `/v1/match` round trip is about 0.4–1.4 s, so it misses the 700 ms budget and that attempt is decided OFFLINE (P7, fail-secure). Know which state you are in before going on stage, and say it if asked |
| P7 | Kiosk stays on `KIOSK_MAIN_01` for the whole run. No `?kiosk=` switch, no restart as another kiosk | v45 covers only `KIOSK_MAIN_01` (see above) |
| P8 | Real IST time is between **06:00 and 21:55** for the real-time steps (1–7, 10–11, 13–14). **If the run is later than 21:55**, set the demo clock for those steps too, e.g. `{"set_local": "21:00"}` (in window, and after v45's `issued_at` − 300 s), and reset it before step 14 | student MAIN_GATE window ends 22:00 (grace to 22:15); after that a real-time ALLOW becomes REQUEST VERIFICATION (grace) or DENY `SCHEDULE_OUTSIDE_WINDOW` |
| P9 | AWS console tab pre-opened in **us-east-1** on the CloudWatch dashboard `hid-kiosk` (or the DynamoDB table `hid_decisions`) | step 15 is a 10-second view |
| P10 | Dry run of the random challenge: `POST /v1/admin/random-challenge {"mode": "FORCE_NEXT"}` → the next would-be ALLOW is REQUEST VERIFICATION `RANDOM_CHALLENGE` (2 actions: one of SMILE / OPEN_MOUTH, one of BLINK / TURN_LEFT / TURN_RIGHT) → then `{"mode": "OFF"}` again | `FORCE_NEXT` stays armed until a would-be ALLOW uses it and then returns to **`AUTO`** (rate 0.15 / 0.30), not to `OFF`; `OFF` also disarms it. Forced draws fire regardless of the rate |
| P11 | DepthProbe (v0.3.0 sideloaded; a v0.3.1 IPA is built) running on the iPhone: `GET /v1/health` → `depth_probe` `connected` if you want to show it | depth is **not** part of today's decision: `liveness.depth.enabled` stays false because the H4 go/no-go (10 live vs 10 printed photo) has not been run. Mention it, don't demo it as a defence |
| P12 | Injection: OBS Studio is **not installed**. For the optional injection extension (1.6) either install OBS and start "OBS Virtual Camera", or use the recorded clip | the `/operator` page's camera picker can select "OBS Virtual Camera" → DENY `INJECTION_VIRTUAL_CAMERA`; the main kiosk view always opens the default camera |

Rate-limit budget: only attack-evidence DENYs count (codes with prefix `SPOOF_`, `MASK_CUE_`, `INJECTION_`, plus
`CHALLENGE_FAILED`, `FALLBACK_FAILED`; never schedule, identity, quality, `SYSTEM_ERROR` or `RATE_LIMITED` DENYs).
`rate_limit.max_failures` 5 in `window_s` 180 → `lockout_s` **5 s**. Start from a reset counter (P4). Steps 2–5 produce up
to 4 counted DENYs, so one on-stage retry would trip a 5-second lockout. The operator calls
`POST /v1/admin/rate-limit/reset` after step 5 and after any retried spoof step (or simply waits 5 s). The injection
extension (1.6) adds one more counted DENY. Steps 6 and 8 (`NOT_ENROLLED`, `SCHEDULE_OUTSIDE_WINDOW`) are not counted.

### 1.2 Run sheet (all dates Sat 14 Nov 2026, times IST)

General note for every online step: until the early probe is live, an online attempt usually also carries
`OFFLINE_MODE` (the cloud match missed its 700 ms budget, P7) while the badge says ONLINE. The decision is the same
or stricter (offline bars), never looser. Expected codes below are the ONLINE ones; add `OFFLINE_MODE` if P6 showed
the cold-connection state.

| # | t (mm:ss) | Kiosk · zone (risk) | Clock | Presented | Operator action | Expected: decision · `reason_codes` · next_action | Ref |
|---|---|---|---|---|---|---|---|
| 1 | 0:00–0:25 | `KIOSK_MAIN_01` · MAIN_GATE (low) | real (P8) | Prajwal (live, enrolled, no glasses) | none (random challenge is `OFF`, P4) | **ALLOW** · `ACCESS_OK` · OPEN_DOOR (today usually `ACCESS_OK`, `OFFLINE_MODE`, see the note above). Student MAIN_GATE Sat 06:00–22:00 → IN_WINDOW. Screen: "Welcome, Prajwal M." + decision time + badge | N1 · Q01 (F1 if offline) |
| 2 | 0:25–0:40 | `KIOSK_MAIN_01` | real | A4 print of Prajwal | hold the print at face distance | **DENY** · `SPOOF_PASSIVE` (plus any other hard code that fires) · NONE. PAD FAIL = strict majority of frames ≤ `liveness.pad.fail_max` 0.30. Schedule not evaluated | N12 · L01 |
| 3 | 0:40–0:55 | `KIOSK_MAIN_01` | real | phone showing Prajwal's photo, bezel in view | — | **DENY** · `SPOOF_DEVICE_DETECTED` (phone box conf ≥ 0.40 containing the face; plus `SPOOF_PASSIVE` / `SPOOF_MOIRE` if they fire) · NONE | N12 · L05 |
| 4 | 0:55–1:15 | `KIOSK_MAIN_01` | real | phone playing the video of Prajwal (blinking, smiling) | — | **DENY** · `SPOOF_DEVICE_DETECTED` and/or `SPOOF_PASSIVE` / `SPOOF_MOIRE` · NONE. Flash is advisory: the operator view shows `scores.signals.flash` = `ADVISORY_<zone>` with no decision effect. If PAD, detector and moiré only reach UNSURE: **REQUEST VERIFICATION** · `LIVENESS_UNSURE` · CHALLENGE → the clip cannot follow the random 2-action challenge → **DENY** · `CHALLENGE_FAILED` | N12, or N9 → R6/R7 |
| 5 | 1:15–1:55 | `KIOSK_MAIN_01` | real | teammate wearing the eye-cut print of Prajwal, blinking on purpose | **before**: `POST /v1/admin/random-challenge {"mode": "FORCE_NEXT"}`; **after**: `{"mode": "OFF"}` + `POST /v1/admin/rate-limit/reset` | A mask cue or UNSURE signal → **REQUEST VERIFICATION** · `MASK_CUE_EDGE` and/or `LIVENESS_UNSURE` · CHALLENGE. If nothing looked suspicious, the forced draw makes the would-be ALLOW a **REQUEST VERIFICATION** · `RANDOM_CHALLENGE` · CHALLENGE instead. Either way: 2 actions in random order, one of SMILE / OPEN_MOUTH (mandatory) + one of BLINK / TURN_LEFT / TURN_RIGHT → the blink or turn passes, the paper does not smile or open its mouth → `STEP_UP` · original codes + `CHALLENGE_FAILED` · CHALLENGE (new nonce, `attempts_left` 0) → second miss → **DENY** · `CHALLENGE_FAILED` · NONE. Honest contingency: PAD may DENY it outright (`SPOOF_PASSIVE`), see 1.6. Always send `OFF` afterwards: an unused `FORCE_NEXT` stays armed and would hit step 11 | N9 / N14 → R6 → R7 · M01, RC05, RC06, C06, C07 |
| 6 | 1:55–2:10 | `KIOSK_MAIN_01` | real | consenting teammate who is **not enrolled** | — | **DENY** · `NOT_ENROLLED` · CONTACT_DESK. Schedule not evaluated | N13 · I03 |
| 7 | 2:10–2:40 | — (enrolment page) | real | the same teammate | open `http://localhost:5173/enroll.html` | **Enrolment with consent** (30 s): consent checkbox with the DPDP text (purpose + storage limitation, deleted after the event) must be ticked; admin token; **e-mail field filled** (the deployed cloud requires it; without it the face is enrolled on the edge only, `cloud_indexed: false`); 5 frames at up to 1280 px → `POST /v1/enroll` (liveness-gated, template encrypted on the laptop, forwarded to Rekognition only when online) → `GET /v1/admin/users` now lists the user. Use a bundle placeholder ID that has no template yet (`u_tm04` unless P5 showed otherwise). Say: re-enrolling the same ID **appends** a look on the edge (≤ 24 templates, first 5 pinned; new frames that don't resemble the original → 409; erase to replace), and erasure is `DELETE /v1/enroll/{user_id}`. Never re-enrol `u_prj1` / `u_tm03` online before the cloud redeploy (the deployed cloud replaces their Rekognition faces). Re-presenting for an ALLOW is optional, only if rehearsed | API §3.15 |
| 8 | 2:40–2:55 | `KIOSK_MAIN_01` · MAIN_GATE (low) | **22:30** | Prajwal (live) | `POST /v1/admin/clock {"set_local": "22:30"}`; DEMO CLOCK badge visible | **DENY** · `SCHEDULE_OUTSIDE_WINDOW` · NONE. Main gate closes 22:00 for students, grace ends 22:15. Live and recognised, still denied | N4 (S04 = the 07:40 variant) |
| 9 | 2:55–3:20 | `KIOSK_MAIN_01` · MAIN_GATE (low) | **22:10** | Prajwal (live), then card `HID-DEMO-0001` | `POST /v1/admin/clock {"set_local": "22:10"}`; on the prompt, enter the card ID (or a TOTP) | **REQUEST VERIFICATION** · `SCHEDULE_GRACE_WINDOW` · SECOND_FACTOR, methods `[TOTP, CARD, EMAIL_OTP, STAFF_OVERRIDE]` (`stepup.methods.online_default`; if the attempt fell back to OFFLINE: `OFFLINE_MODE`, `OFFLINE_FALLBACK_REQUIRED`, methods `[TOTP, CARD, STAFF_OVERRIDE]`) → card hash matches `u_prj1` and is not revoked → **ALLOW** · `ACCESS_OK`, `FALLBACK_OK` · OPEN_DOOR; `resolved_codes` = `[SCHEDULE_GRACE_WINDOW]`. TOTP also works: it always verifies against real wall time, never the demo clock | N3 → R1 · S01 / S02 |
| 10 | 3:20–3:25 | — | **reset** (or `21:00` if P8 applies) | — | `POST /v1/admin/clock {"reset": true}`; DEMO CLOCK badge disappears | real IST time from here on (P8) | R18 |
| 11 | 3:25–3:40 | `KIOSK_MAIN_01` · MAIN_GATE (low) | real (P8) | Prajwal (live) | `POST /v1/admin/mode {"force": "OFFLINE"}` → badge **OFFLINE** at the next 2 s poll | **ALLOW** · `ACCESS_OK`, `OFFLINE_MODE` · OPEN_DOOR. Local liveness + local ArcFace at the stricter offline bars (`offline.overrides`: PAD 0.85, cosine 0.55, margin 0.15); cached signed bundle FRESH; IN_WINDOW. (Random challenge is `OFF` for the script; in the product the offline rate is 0.30) | F1 · O01 |
| 12 | 3:40–4:10 | `KIOSK_MAIN_01` · MAIN_GATE (low) | **22:10** | Prajwal (live), then his TOTP (or the card) | still OFFLINE; `POST /v1/admin/clock {"set_local": "22:10"}` | **REQUEST VERIFICATION** · `SCHEDULE_GRACE_WINDOW`, `OFFLINE_MODE`, `OFFLINE_FALLBACK_REQUIRED` · SECOND_FACTOR, methods `[TOTP, CARD, STAFF_OVERRIDE]` (`stepup.methods.offline_default`; no EMAIL_OTP offline) → 6-digit TOTP (or card) → **ALLOW** · `ACCESS_OK`, `FALLBACK_OK`, `OFFLINE_MODE` · OPEN_DOOR; `resolved_codes` = `[SCHEDULE_GRACE_WINDOW]`. Then `POST /v1/admin/clock {"reset": true}` **at once** (before step 14). The high-risk offline rule (SERVER_ROOM: always a second factor, `[TOTP, STAFF_OVERRIDE]`, no card) is told, not shown: it is not in v45 (test vectors O04, F2) | F3 → R1 · O11 / O12 |
| 13 | 4:10–4:25 | — | real | — | `GET /v1/admin/store` on the dashboard | the queued records with exactly the SC2.5 fields: `attempt_id, seq, kiosk_id, zone, ts_utc, user_id, candidate_user_id, decision, reason_codes, resolved_codes, scores` (2 dp), `fallback` (`method`, `staff_id`, `code_id`, `totp_step`: a non-secret time-step counter, never the code), `schedule_version, cache_state, mode, prev_hash, record_hash`; plus `never_stored` (images, face crops, depth maps, embeddings, display names, TOTP values, raw card IDs), `chain_ok`, encryption AES-256-GCM, `retention_hours` 24 | SC2.5 |
| 14 | 4:25–4:45 | — | **real (reset first)** | — | check the DEMO CLOCK badge is gone (`{"reset": true}` again if not), then `POST /v1/admin/mode {"force": "AUTO"}`; if the queue has not started draining after ~15 s, `POST /v1/admin/sync` | badge SYNCING (offline rules still apply) → queue counts down to **0** → ONLINE. `POST /v1/sync`: ≤ 50 items per batch (`sync.batch_size`) plus TOMBSTONE items, with `chain_head` / `chain_head_hmac`; response `accepted` / `duplicates` / `rejected` / `flags`. The cloud re-checks each offline ALLOW against the authoritative schedule; acked records are purged locally. Sync stamps `kiosk_now_utc` from the demo clock, so a clock left shifted by more than 120 s raises `ALERT_CLOCK_SKEW` on stage | SC2.6 |
| 15 | 4:45–4:55 | — | — | — | switch to the AWS console tab (us-east-1) | 10 s: the `hid-kiosk` CloudWatch dashboard moving, or the synced record (same `attempt_id`) in DynamoDB `hid_decisions` | — |
| 16 | 4:55–5:00 | — | — | — | dashboard tiles | **no eval numbers** (none exist yet): the dev latency measurement with its label, the decision feed, and "protocol designed, eval run next" (1.5) | — |

Why CARD in step 9 and TOTP in step 12: one shows the HID card factor, the other shows a factor that works with zero
connectivity. Why the demo clock goes 22:30 then 22:10: both times are later than v45's `issued_at` − 300 s, so moving
the clock backwards between them is safe. Reset the clock before step 11 (or set 21:00 under P8), and **always before
mode AUTO / any sync** (step 14).
Natural offline detection (Wi-Fi off instead of the forced switch): heartbeat `GET {CLOUD_API_URL}/v1/health` every
`connectivity.heartbeat_interval_s` 5 s with `heartbeat_timeout_ms` 2000; `misses_to_offline` 3 → OFFLINE
**≈ 12–17 s after the outage starts** (worst case 17 s with 2 s timeouts; 10–15 s if the connection is refused; a
failed cloud match during an attempt also counts as a miss). Reconnect needs `successes_to_online`
3 good heartbeats (about 15 s) → SYNCING, and ONLINE only after the queue is acked and the bundle refreshed
(`require_sync_before_online`). The forced switch is immediate.

### 1.3 Script lines

| # | Say (one line) | Criterion |
|---|---|---|
| 1 | "Here's the real me: passive checks and the face match ran in parallel. Face lock to decision is on screen. In our dev sample on this webcam, 202 attempts, the p95 was 1.697 seconds, under the 2 s target in that sample; we'll show the full eval when it's run." (If the screen shows OFFLINE_MODE under an ONLINE badge: "the cloud match missed its time box, so this attempt was decided offline, at stricter thresholds; that's the fail-secure design.") | Fit / Functionality |
| 2 | "Same face, same identity. The liveness layer says no, and it tells the operator why." | Fit |
| 3 | "A phone in the frame is hard evidence. No schedule lookup, no hint about whether I have access right now." | Fit |
| 4 | "A video blinks and smiles. Today it's stopped by the passive model, the phone detector and the moiré check. Our colour-flash nonce measures every attempt, but it's advisory until we re-validate the kiosk's frame timing, so it doesn't decide yet." | Fit / Honesty |
| 5 | "Real eyes blink through the holes, so a blink check would pass this. Our challenge always includes a mouth movement, a smile or an open mouth, plus a blink or a head turn. Paper can't smile. In production 15% of normal entries also get a random challenge, 30% offline; I forced one here so you can see it." | Innovation / Fit |
| 6 | "Live, but nobody we know. That's a DENY with 'please contact the desk', not a spoof alarm." | Fit |
| 7 | "Enrolment is opt-in: no tick, no template. The template stays encrypted on this laptop, and one call deletes it. A second enrolment adds a look, say without glasses, but only if it's clearly the same person. We store the minimum: no images offline, ever." | Fit / Privacy |
| 8 | "Same live, recognised person at the main gate at 22:30. Students' access ended at 22:00. A live, recognised person is not automatically authorised." | Fit (SC1) |
| 9 | "At 22:10 I'm inside the 15-minute grace window, so instead of a hard no it asks for a second factor, here my HID card." | Fit (SC1) |
| 10–11 | "Back to real time. Now the central service is gone, and the kiosk keeps deciding locally with stricter thresholds and its signed cached schedule." | Fit (SC2) / Tech |
| 12 | "No unsafe automatic access: offline and outside normal hours, it never opens on the face alone. It asks for a factor that works with zero connectivity, my authenticator code. A high-risk door offline always asks for one." | Fit (SC2) |
| 13 | "This is everything we keep: no images, no embeddings, rounded scores, a hash chain, encrypted, purged on sync." | Fit / Privacy |
| 14 | "Connection back: the queue drains idempotently and the cloud re-checks every offline decision." | Tech |
| 15 | "And here it is in AWS." | Tech |
| 16 | "We designed an iBeta Level 1-style protocol with ISO 30107-3 metrics and bounds rather than point claims; the run is next. Here's what it would take to confirm HID's 0.2% FAR." | Presentation / Tech |

### 1.4 Admin calls (operator cheat sheet)

All admin calls need `X-Admin-Token`; `/v1/admin/clock` and `/v1/admin/random-challenge` work only with `DEMO_MODE=1`.
Body field names follow `docs/API.md` §3.14 / §3.14a. Codes are typed on the kiosk, never on a command line.

```bash
E=http://127.0.0.1:8000; H="X-Admin-Token: $ADMIN_TOKEN"; J="Content-Type: application/json"
curl -s       $E/v1/health                                                              # P1
curl -s       $E/v1/mode                                                                # P2, P3, P6, badge state any time
curl -s       $E/v1/admin/users -H "$H"                                                 # P5, step 7
curl -sX POST $E/v1/admin/random-challenge -H "$H" -H "$J" -d '{"mode": "OFF"}'         # pre-run (P4), after step 5
curl -sX POST $E/v1/admin/rate-limit/reset -H "$H"                                      # pre-run, after step 5, any retried spoof step
curl -sX POST $E/v1/admin/random-challenge -H "$H" -H "$J" -d '{"mode": "FORCE_NEXT"}'  # before step 5 (P10)
curl -sX POST $E/v1/admin/clock -H "$H" -H "$J" -d '{"set_local": "22:30"}'             # step 8
curl -sX POST $E/v1/admin/clock -H "$H" -H "$J" -d '{"set_local": "22:10"}'             # steps 9 and 12
curl -sX POST $E/v1/admin/clock -H "$H" -H "$J" -d '{"reset": true}'                    # step 10, end of step 12, before step 14
curl -sX POST $E/v1/admin/clock -H "$H" -H "$J" -d '{"set_local": "21:00"}'             # only if the run is after 21:55 (P8)
curl -sX POST $E/v1/admin/mode  -H "$H" -H "$J" -d '{"force": "OFFLINE"}'               # step 11
curl -s       $E/v1/admin/store -H "$H"                                                 # step 13
curl -sX POST $E/v1/admin/mode  -H "$H" -H "$J" -d '{"force": "AUTO"}'                  # step 14 (clock reset first)
curl -sX POST $E/v1/admin/sync  -H "$H"                                                 # step 14 (if slow)
```

After the run: `curl -sX POST $E/v1/admin/random-challenge -H "$H" -H "$J" -d '{"mode": "AUTO"}'` restores the shipped
random-challenge behaviour (an edge restart does the same).

### 1.5 Closing metrics (step 16)

No eval run exists yet, so step 16 shows **no** APCER / BPCER / FAR / FRR / accuracy numbers. Say: "we designed an iBeta
Level 1-style protocol; the run is next", and show the trial counts needed (the **Results** slide). The only latency on
a slide is the stored edge bench above (`eval/results/latency_edge_1280_20261114T171323Z.md`), labelled "server side
only, synthetic frames, n = 40; face lock → rendered not measured yet". Once `metrics.json` exists: latency p50/p95 with bootstrap CI, per species × final decision
and overall, for both client face lock → rendered and server `latency_ms.total`; liveness accuracy and face-auth accuracy
with CIs; rank-1 identification rate; APCER per species (Clopper-Pearson upper bound; rule of 3 when 0 errors); BPCER;
step-up rate; FAR/FRR at the operating threshold. Never round up; never say "certified".

### 1.6 Contingencies (say what happened, never hide it)

- **No LIBRARY / SERVER_ROOM route today**: v45 covers only `KIOSK_MAIN_01`. If a judge asks about other doors, show the
  test vectors (S01, O04, F2) or the recorded clip; don't switch kiosks on stage.
- **PAD denies the eye-cut print before any challenge** (step 5 ends at once in **DENY** · `SPOOF_PASSIVE` · NONE): say
  "the passive layer caught the paper texture before we even needed the challenge", then play the recorded run of the
  challenge path (C06 → C07) from the backup video. Send `{"mode": "OFF"}` anyway (the `FORCE_NEXT` is still armed).
- **A mask passes** (step 5 ends in ALLOW): say so, and log it as an attack error. With `FORCE_NEXT` sent before the step,
  a would-be ALLOW cannot pass without a challenge, so an ALLOW here means the paper completed a smile / open-mouth
  step: name it as a failure, not a feature. Random challenges raise the bar for rigid masks; silicone masks remain a
  known RGB limit; depth is not enabled today.
- **The video replay is ALLOWed** (step 4): say so plainly. "That's exactly the gap the colour-flash nonce is designed
  to close; it's advisory until we re-validate it on this webcam." It is logged as an attack error.
- **The genuine user gets REQUEST VERIFICATION**: do the challenge or recapture and say "when we're unsure we don't
  guess, we ask". Known genuine causes: moiré is **enforced** and genuine flash-lit frames scored 0.42–0.79 (≥ 0.40 =
  UNSURE → `LIVENESS_UNSURE`); glasses on the M2 ring (0.35–0.80, ≥ 0.50 = `MASK_CUE_EDGE`); backlight; `MATCH_LOW`;
  `QUALITY_POSE` → RECAPTURE. Rarely a genuine user with moiré ≥ 0.70 and PAD not PASS is DENIED `SPOOF_MOIRE`; say
  it is a known false positive of an uncalibrated band, to be calibrated on the eval dev split. Offline the same
  step-up case is `STEP_UP` with `OFFLINE_MODE`, `OFFLINE_FALLBACK_REQUIRED` and CHALLENGE → SECOND_FACTOR (F5).
- **Quality exhausted** (after `quality.max_recaptures` = 2, low/medium zone; the injection check still runs first):
  **REQUEST VERIFICATION** · the quality codes · SECOND_FACTOR `[STAFF_OVERRIDE]` (`stepup.methods.quality_exhausted`) =
  manual review at the desk. **Send the person to the desk**: v45 has no usable non-public staff code, so we don't
  type one on stage. Say "this is the manual-review path from the brief".
- **Kiosk shows RATE_LIMITED** (`DENY` · `RATE_LIMITED` · NONE with `retry_after_s`): "that's the lockout after five
  attack attempts". Wait 5 s or `POST /v1/admin/rate-limit/reset`.
- **TOTP rejected in step 12**: use the card `HID-DEMO-0001` (CARD is allowed offline in a low-risk zone) → same ALLOW.
- **An online step shows OFFLINE_MODE under an ONLINE badge**: expected today (P6). The cloud match missed its 700 ms
  budget (venue round trip about 0.4–1.4 s), or the bundle was not confirmed within 30 min (`GET /v1/mode` reason
  `bundle_stale`). Both decide the attempt offline (P7). Say that this is the fail-secure design, and that the early
  probe (cloud match started at face lock, live since the 2026-11-14.3 restart) is the fix, not yet measured.
- **Venue network already down**: start at step 11 and say so. That turns the failure into the demo.
- Any other misbehaviour: "here's the recorded run of the same step", play the backup clip, move on. Never retry more
  than once on stage.

Optional extensions (only if time allows):

- **Injection** (needs OBS installed, P12, or the recorded clip): on the `/operator` page select "OBS Virtual Camera"
  in the camera picker → **DENY** · `INJECTION_VIRTUAL_CAMERA` · NONE (`injection.virtual_camera_label_patterns`). Adds
  one counted DENY. The main kiosk view always opens the default camera, so this runs from `/operator`.
- **Revocation during the outage** (SC2.7 step 5): revoke a demo user on the cloud admin API while the kiosk is
  OFFLINE; their offline ALLOW still happens (the kiosk cannot know, which we say honestly) and sync raises
  `ALERT_REVOKED_USER_ADMITTED`. Revocation is time-aware (`revoked_at` ≤ t0 → REVOKED first); offline, revoked users
  are excluded from the local gallery search, so they come out `NOT_ENROLLED`. A cloud erasure (`reason: "ERASED"`)
  also deletes the user's local templates and TOTP secret on the edge.

---

## 2. Slide outline (`slides/index.html`, referred to by title; judging weights in brackets)

Slides are named by their title (`data-title` in `slides/index.html`), never by number, because the deck order can
change. Every number on a slide must come from a stored file under `eval/results/` (the speaker notes cite it).

| Slide (title) | Content | Weight served |
|---|---|---|
| **Title** | "Can You Spot a Spoof?", team, "Spot the spoof, check the schedule, never fail open.", the three outcome colours | Presentation 15 |
| **Problem** | 4 attack types + "live ≠ authorised" (SC1) + "network down ≠ door open" (SC2); HID targets shown as targets, not results | Fit 25 |
| **Our answer** | Local-first, cloud-enhanced: kiosk browser → local edge (always decides) → AWS cloud when online; early cloud probe live, latency not measured | Fit 25 / Tech 25 |
| **Decision logic** | Three outcomes with their reason codes; fail-secure rules enforced by tests | Fit 25 |
| **Liveness stack** | Each signal with its rule and honest status: PAD, phone/screen detector, moiré (enforced), RGB mask ring M2 (enforced), random deformation challenge (15% online / 30% offline + every unsure), injection layer, colour flash **advisory**, depth **off** (H4 not run) | Fit 25 / Innovation 20 |
| **Innovation** | Random colour-flash nonce (advisory), risk-adaptive step-up with mandatory mouth movement and random challenges, early cloud probe (live, not measured), own DepthProbe TrueDepth app, injection layer, reason codes on every decision | Innovation 20 |
| **SC1 Campus schedule** | Biometric × signed schedule bundle table (inside / grace / outside / no grant / holiday / revoked), high-risk zones, "stale data may deny, never allow" | Fit 25 |
| **SC2 Offline mode** | 5 brief requirements → 5 mechanisms: local engine; stricter bars, no auto-ALLOW when unsure or high-risk; TOTP / staff code / HID card fallback; minimal encrypted store + 24 h TTL; idempotent sync + alerts (show the live dashboard, no queue numbers quoted) | Fit 25 / Tech 25 |
| **AWS architecture** | API Gateway → EC2, Rekognition (on, time-boxed), DynamoDB, S3 SSE-KMS (audit upload not built), SES, CloudWatch; each with a degraded path; ap-south-1 in production | Tech 25 |
| **Privacy and security** | DPDP Act 2023: consent, templates not images, encryption, retention, erasure; signed bundles, HMAC requests, single-use nonce, injection layer, hash chain | Presentation 15 / Fit 25 |
| **Results** | **No eval run, so no accuracy numbers.** Stored edge server-side bench (`eval/results/latency_edge_1280_20261114T171323Z.md`) and the stored test run (`eval/results/tests_20261114T1705Z.txt`); trial counts needed (1,497 for 0.2% FAR, 498 for 0.6% FRR). After a run: per-species APCER (Clopper-Pearson UB; rule of 3 for 0 errors), BPCER, accuracies with CIs, FAR/FRR, step-up rate, p50/p95 latency with bootstrap CI | Tech 25 / Presentation 15 |
| **Honest limits** | Silicone masks, flash advisory, depth off, moiré / M2 bands uncalibrated, licences; not measured yet: eval, client face lock → decision latency, the probe's speed-up | Presentation 15 |
| **Scale and roadmap** | Edge per door, cloud per campus, per-kiosk bundles, idempotent sync, Ed25519, ap-south-1; roadmap: run the eval, calibrate moiré / M2, enforce the flash, enable depth after H4, and further items on the slide | Tech 25 / Fit 25 |
| **Thank you** | Questions; local-first, explainable, honest | Presentation 15 |
| (backup) Q&A appendix | Threshold table, reason-code list, stored latency breakdown | — |

The live demo runs after the **Innovation** slide and before **SC1 Campus schedule**; alternatively the **SC1** and
**SC2** slides are shown on the live dashboard.

---

## 3. Anticipated judge questions

**Does step-up break the 2 s rule?**
No. REQUEST VERIFICATION is one of the three outcomes the brief asks for, and it is itself a decision rendered inside the
2 s budget (face lock → rendered, measured by the kiosk beacon). The brief says low-confidence cases "require extra
checks such as OTP or manual review", and those checks take as long as a human needs. We report the verification time
separately, together with the genuine step-up rate `[x%]`, so judges can see how often real users pay that cost.

**How fast is it really?**
What we have stored: the edge's server-side time, frames received → decision, on synthetic 1280×720 frames with a
local match and no cloud, is p50 76.0 ms and p95 106.4 ms over 40 attempts (`eval/results/latency_edge_1280_20261114T171323Z.md`;
server side only, not an eval result). It excludes face lock, the 700 ms capture window, Rekognition and rendering.
The number that matters for the 2 s rule is face lock → decision rendered, measured by the kiosk beacon; we have **no
stored measurement of it yet**, so we don't quote one. The cloud match is time-boxed (700 ms after the frames, or
1.5 s from face lock with the early probe, which is live but not measured), and a miss makes that attempt an offline
decision rather than a slow one. The eval run will report client and server latency with bootstrap CIs.

**Where is your confidence score?**
Every response carries `scores{}`: PAD mean and per-frame pass count, flash correlation `r` and amplitude (advisory),
moiré, device-detector confidence, local cosine and top-1/top-2 margin, and Rekognition similarity when online. The
operator dashboard shows them next to the PASS/FAIL lines from `config/thresholds.yaml`. We deliberately don't collapse
them into one number: each signal has its own three zones, and the reason codes say which one decided. For the system
as a whole, our confidence is the 95% bound on each metric, not a single accuracy figure.

**Who decides, the cloud or the kiosk?**
Always the edge (local-first). Online, Rekognition is the authoritative matcher (similarity ≥ 99 to pass, runner-up
< 80) and the local ArcFace result can only tighten it: a conflicting local candidate at cosine ≥ 0.50
(`identity.cross_check_conflict_min_cosine`) or no usable local result gives `MATCH_AMBIGUOUS`, never an ALLOW. If
`match.rekognition.enabled` is false, online identity uses the local matcher with the stricter offline bars. If
Rekognition errors or times out, that attempt is decided OFFLINE and counted as a heartbeat miss. Honestly, from this
venue that happens on most attempts today (the round trip is about 0.4–1.4 s against a 700 ms box), so you will often
see `OFFLINE_MODE` under an ONLINE badge; `GET /v1/mode` shows it as `cloud_match.degraded`. The fix, live since the last edge
restart but not yet measured, starts the call at face lock with a 1.5 s deadline, and uses that result only if the face-lock frame and the captured frames are provably
the same person.

**Show me AWS.**
The console tab is open in us-east-1: the cloud API (deployed this morning) on an EC2 t3.small behind API Gateway, DynamoDB tables
(`hid_users`, `hid_decisions`, `hid_state`), the Rekognition collection, S3 with SSE-KMS and a 1-day lifecycle rule, SES
for email OTP (one verified address), and the `hid-kiosk` CloudWatch dashboard. Our sandbox probe showed Rekognition,
DynamoDB, S3, KMS, SES, EC2, Lambda, API Gateway, IAM and CloudWatch all allowed for the `WSParticipantRole`. Every cloud
feature still has a degraded path, because the edge must keep deciding when any of them is unreachable.

**Why us-east-1?**
The hackathon sandbox (AWS Workshop Studio) only allows us-east-1. Production would pin ap-south-1 (Mumbai) for India
DPDP data residency and lower latency. Bangalore ↔ us-east-1 is about 200–250 ms round trip, which is why the cloud
match runs in parallel and is time-boxed; if it misses the budget, that attempt is decided offline (P7). The schedule is
evaluated locally on the newest cloud-signed bundle, so there is no per-attempt cloud schedule call.

**Is face data sent to AWS?**
Only for consenting team members. Online, a small face crop (about 10 KB, not the full frame) goes to Rekognition
`SearchUsersByImage`, against a collection that holds only our own consenting team faces (enrolled through the consent
page). S3 audit-frame upload is **not implemented**: no attempt frame is stored in S3. The bucket (SSE-KMS, 1-day
lifecycle) holds only Face Liveness output and, if switched on (off by default), an enrolment reference image. The
teardown script deletes the users, faces and collection after the event. Offline, nothing leaves the laptop and no
image is ever stored.

**Why not just use AWS Rekognition Face Liveness?**
It's a strong, iBeta-tested service; our cloud API exposes it only as an optional step-up (`POST /v1/liveness/session`), never on the main path. It takes several seconds (oval fit plus light sequence; AWS's own sizing assumes about 10 s per session), its default regional quotas are low (check the us-east-1 quota page before quoting a number), and it needs the cloud. A door must decide in under 2 s and keep working offline (SC2). Our passive edge path handles the common case fast, and the AWS liveness check is the expensive second opinion when we're unsure.

**Is the colour flash actually doing anything?**
It runs on every attempt: exactly 3 colours × ~233 ms in the 700 ms window (`liveness.flash.duration_ms`; ≤ 3 changes/s), measured by the edge on the frames
(correlation `r`, lag, amplitude), and reported as `ADVISORY_<zone>`. Right now it is **advisory**
(`liveness.flash.enforce: false`) and has no decision effect. Why: on the real MacBook webcam the pipeline delay was
4–7 frames, outside our original lag window, and the browser's chroma series was noisy (r 0.33–0.98 on genuine users vs
0.86–0.99 measured by the edge on the frames, dev data), so genuine users were getting false mismatches. We retuned it
(lag 0–8 frames, lag std ≤ 1.5, amplitude ≥ 2.0, edge-measured `r` only) and will enforce it after re-validating the
kiosk's frame timing. Until then, video and screen replay defence rests on passive PAD + the phone/laptop/TV detector +
moiré. We don't claim the flash is enforced.

**How do you stop deepfake / injection attacks?**
We treat injection as its own layer, because ISO 30107-3 PAD testing excludes it (CEN/TS 18099 covers it). Today: (1) a virtual-camera check on device labels (OBS, ManyCam, DroidCam...) and frame-timing bounds (15–400 ms between frames); (2) a single-use server nonce per capture (reuse → 409 `NONCE_REUSED`, a nonce that does not belong to the attempt → 403 `FORBIDDEN`); (3) on a fixed HID kiosk the camera is wired, so the realistic attack surface is smaller than for mobile KYC. Designed and measured but advisory: the random colour nonce, which a pre-recorded or slowly generated stream can't reflect in real time. Virtual-camera attempts are evaluated and reported separately from PAD. Roadmap: signed capture on the device.

**What about 3D and silicone masks?**
Be honest. Paper and eye-cut masks fail the deformation challenge, because paper can't smile. Rigid 3D masks are harder: a weak mask cue routes to REQUEST VERIFICATION, never ALLOW. On top of that, 15% of would-be ALLOWs online and 30% offline get a random deformation challenge (`RANDOM_CHALLENGE`: a smile or open mouth plus a blink or head turn), so a mask that looks clean still has to move like a face. That raises the bar for rigid masks; it doesn't make them impossible. Silicone masks deform like skin, and an RGB webcam can't reliably stop them. That is a known limit and we say so. Our DepthProbe iPhone app is built and connects to the kiosk, but depth stays off because the H4 calibration hasn't been run yet; even then it raises the bar rather than solving the problem (Face ID itself was fooled by a ~$150 mask in 2017). The product answer is depth + NIR hardware, which HID already ships in other modalities.

**Why did you switch the random challenge off for the demo?**
Only for the scripted run, so a random draw doesn't change the order of the story; the shipped setting is on (15% online,
30% offline) and we showed one forced in step 5. Every random challenge costs a genuine user a few seconds, so the rate
is a per-site policy value. The mechanism is tested with exactly one random draw per would-be ALLOW, and it can only
turn an ALLOW into a challenge, never loosen a decision.

**Why a 5-second lockout? Isn't that weak?**
It's a deliberate demo-day trade-off at the operator's request (was 60 s): 5 attack-evidence DENYs in 180 s lock the
kiosk for 5 s and raise `ALERT_RATE_LIMIT_LOCKOUT`. Only attack evidence counts (spoof, mask, injection, failed
challenge, failed fallback), never schedule, identity or quality denials, so genuine users can't lock themselves out.
5 s slows scripted attempts and flags them, but it doesn't stop a patient attacker; production would use a longer,
escalating lockout plus the cloud's spoof-burst alert (≥ 3 spoof DENYs in 10 min).

**Is it certified?**
No. We **designed** an iBeta Level 1-**style** protocol (ISO/IEC 30107-3 vocabulary, per-species APCER, BPCER, subject-disjoint split) and have not run it yet. It is not an iBeta test and not a certification. Formal PAD testing is on the roadmap.

**You had zero errors on an attack type. Is that 0%?**
No. Zero errors in N trials only bounds the rate: below 3/N at 95% confidence (rule of 3), and we show the
Clopper-Pearson upper bound on the slide. For example, 0/30 print attacks accepted means APCER < 10%, not 0%.

**How can you claim 0.2% FAR with so little data?**
We don't claim it. Zero errors in N trials only bounds the rate below 3/N at 95%, so 0.2% needs about 1,497 error-free impostor comparisons. We generate impostor comparisons offline with `eval/collect_faces.py` + `eval/compare.py` on consenting team photos (`eval/captures/`, gitignored, deleted after the event), cross-matching every probe against every other subject's template (`[N_imp]` comparisons, plus LFW padding), and set the threshold at the 99.8th impostor percentile on a dev split of subjects. Then we report FMR on held-out subjects: `[k/N]`, 95% UB `[UB]`. Live FRR of 0.6% would need about 500 error-free genuine transactions, so we show our bound and the volume needed.

**Privacy / DPDP Act 2023?**
Consent page (`/enroll.html`: no tick, no template) and purpose limitation (access control only). Templates, not images, are stored on the edge, encrypted, with a 72 h maximum template-cache age; enrolment is liveness-gated. No images are stored offline at all; the offline decision log is AES-256-GCM encrypted, holds pseudonymous IDs and 2-dp scores, and is purged on sync ack or after 24 h. Erasure: `DELETE /v1/enroll/{user_id}` removes the local template, the TOTP secret and the cloud user. Today's sandbox is in us-east-1; production would keep data in ap-south-1 (Mumbai). Only consenting team faces were used today, and everything is deleted by the teardown script.

**Is offline mode a security hole?**
Offline is stricter than online, never looser. Higher PAD and match thresholds; no auto-ALLOW in high-risk zones; no automatic offline ALLOW if the cached schedule is past its 12 h limit (only a staff override can admit), and no match at all if templates are older than 72 h. SYNCING still uses offline rules, and an online kiosk whose bundle hasn't been confirmed by the cloud for 30 min also switches to offline rules. A bundle that fails verification (in transit or tampered on disk) is rejected and never replaces the last valid one. Fallback factors work with zero connectivity (offline TOTP, staff code, HID card ID; no card in high-risk zones). The queue is encrypted, hash-chained and minimal, and every offline decision is re-evaluated by the cloud on reconnect, with discrepancy alerts (for example a user revoked while the kiosk was offline, or the same TOTP step used at two kiosks). Templates are scoped to that kiosk's entitled users only.

**How does this scale to many kiosks?**
The heavy work runs at the edge (about 2 MB PAD models on CPU, so no GPU), and the cloud handles identity, schedules and audit. Per-campus template sync pushes only the users authorised for each door. `/v1/sync` is idempotent and keyed by `attempt_id`. The API is stateless (EC2 ASG or Lambda with provisioned concurrency). Rekognition quotas can be raised for production, and the 1:1 CompareFaces path avoids 1:N search where a card or claimed ID exists. Metrics go to CloudWatch for the fleet dashboard.

**What does a check cost?**
Edge path: about zero marginal cost (local CPU inference). With cloud match: one Rekognition image call (on the order of $0.001; check current us-east-1 / ap-south-1 pricing before quoting it) plus negligible DynamoDB/Lambda. Face Liveness step-up is the expensive call (on the order of a cent per session), and only the uncertain minority triggers it. Our measured genuine step-up rate is `[x%]`. A warm t3-class EC2 instance is a few cents per hour. Mark every figure on the slide "list price, to verify".

**What if someone can't look at flashing colours?**
The flash is exactly 3 gentle colours in 0.7 s (≤ 3 changes per second). The kiosk also has a non-flash accessibility path (`flash_enabled: false`): the flash signal is then NOT_AVAILABLE, which adds `LIVENESS_UNSURE`, so that user always gets a deformation challenge. The non-flash path never auto-ALLOWs.

**Did you tune on your test data?** There is no test run yet. The protocol chooses thresholds on a subject-disjoint dev split, commits them (git hash in `RUN_INFO.md`) and freezes them for the test split. Today's flash and capture changes were made on dev captures and are labelled as such in `config/thresholds.yaml`; the moiré and M2 bands are marked to be calibrated on the dev split, because genuine users can currently score into them.

**Why rules instead of one ML score?** Operators and auditors can follow a rule set, every decision carries reason codes, and the uncertain band is an explicit outcome.

**What's your weakest attack?** After the eval, from `metrics.json`: the species with the highest APCER UB and the signal carrying it. Today, honestly: video replay, because its designed defence (the flash nonce) is advisory; and silicone masks, which RGB can't reliably stop.

**What would you do with more time?**
Run the eval we designed, with more subjects and lighting conditions; calibrate the moiré and mask-ring bands on its dev
split; measure the early cloud probe; re-validate the kiosk's frame timing and enforce the colour-flash nonce; run the H4
depth calibration and enable depth; S3 audit frames; Ed25519-signed bundles (HMAC-SHA256 today); a licensed
matcher; depth/NIR hardware for masks; real HID reader / mobile-credential integration; CEN/TS 18099 injection testing.

---

## 4. Differentiators (say these, in this order)

1. **Live ≠ authorised ≠ online**: one policy engine combines biometrics, campus schedule (SC1) and offline rules (SC2), and fails secure at every layer.
2. **Local-first, cloud-enhanced**: the edge always decides, so offline mode is a natural state rather than a bolt-on, with idempotent sync and discrepancy alerts.
3. **Risk-adaptive step-up** with a **mandatory deformation** step (smile or open mouth, plus blink or head turn). It is fast for real users and beats the eye-cut mask that fools blink checks. Random deformation challenges on 15% of normal entries online, 30% offline.
4. **Random colour-flash nonce**: challenge-response liveness with no extra hardware; built and measured on every attempt, advisory until the kiosk timing is re-validated.
5. **Separate injection-attack layer** (virtual camera + timing + single-use nonce), aware of CEN/TS 18099.
6. **Reason codes on every decision**, plain English for the user and full scores for the operator.
7. **Standards-literate evaluation design**: ISO 30107-3 per-species APCER, BPCER, IAPMR, FMR/FNMR, DET, Clopper–Pearson bounds, subject-disjoint split, iBeta Level 1-style protocol (designed; the run is next).
8. **Live attack dashboard**: the decision feed and metrics fill in as judges watch, with an ONLINE/OFFLINE badge and sync queue.
9. **Lighting/fairness breakdown** of BPCER (office / backlit / dim), modelled on FIDO's per-group FRR check.
10. **Privacy by design**: consent page, no offline images, encrypted templates and log, deletion endpoint, KMS + TTL, DPDP-aware, teardown script.
11. **HID fit**: kiosk/door framing, HID card or mobile ID as the fallback factor (revocable card hashes), Rekognition already integrated in HID's camera line, and our own DepthProbe iPhone app for TrueDepth depth (built; enabled only after the H4 calibration, not yet run) that "raises the bar" for masks.
12. **Honesty as a feature**: we show the trial counts needed for HID's 0.2% / 0.6% targets and name our limits (eval not run yet, advisory flash, uncalibrated moiré / M2 bands, cloud time-box misses, silicone masks, licences).
