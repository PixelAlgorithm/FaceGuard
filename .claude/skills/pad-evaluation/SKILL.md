---
name: pad-evaluation
description: Use when collecting liveness/face-auth test data, logging attempts, computing ISO/IEC 30107-3 PAD metrics (APCER per species, BPCER, IAPMR) and FAR/FRR with confidence bounds, measuring latency, running SC1 (campus schedule) and SC2 (offline mode) scenario tests, building the metrics dashboard, or preparing demo and pitch claims about accuracy, speed or security.
---

# PAD evaluation: protocol, metrics, dashboard, honest claims

Source of truth: `CLAUDE.md` (sections 2 and 8). Research backing: `docs/research/notes/evaluation_differentiation.md`
and `docs/research/FULL_REPORT.md` ("Report ISO metrics with confidence bounds"). Decision semantics come from
`docs/DECISION_POLICY.md`. The demo script and judge Q&A are in `docs/DEMO_AND_PITCH.md`.

Goal: make every number on a slide traceable to a CSV row and a script, and state each one with its confidence bound.

**Contracts win.** Where this skill conflicts with `docs/DECISION_POLICY.md`, `config/thresholds.yaml`,
`docs/API.md` v1.1 or `docs/POLICY_TEST_CASES.md`, those files win. Use **canonical reason codes only**
(closed list, `DECISION_POLICY.md` §6). Scenario tests are identified by `docs/POLICY_TEST_CASES.md` IDs
(§5 below). The authoritative CSV column list is `eval/evallib/schema.py` (owned by `eval-metrics`).

**Eval data path (D9, as built in `eval/capture.py`).** There is no `X-Eval-Label` header.
0. **Credentials (RBAC, `eval/evallib/auth.py`).** `capture.py` and `snapshot_metrics.py` send
   `Authorization: Bearer $FG_EVAL_API_KEY` (role `evaluator`) on the SSE feed, `GET /v1/metrics` and every
   `/v1/admin/*` call; `scenarios/run_scenarios.py` uses `FG_OPS_API_KEY` (roles `security_officer` +
   `evaluator`); its `--backend store` records D01/D02 as `NOT_RUN` without it. Mint a key once (shown once, never printed by the
   tools): `edge/.venv/bin/python -m edge.auth create-api-key --name eval --role evaluator --expires-days 7
   --print-key-only` (ops key: `--name ops --role security_officer --role evaluator`). In `capture.py`,
   `snapshot_metrics.py` and `run_scenarios.py --backend api` a missing or refused credential (401/403) stops
   the tool with exit code 5 (`EXIT_AUTH`), never a silent fallback. The legacy
   `ADMIN_TOKEN` is used only with `FG_ALLOW_LEGACY_ADMIN_TOKEN=1` (and the edge's `AUTH_LEGACY_ADMIN_TOKEN=1`).
   Credentials go only to a loopback edge, or to an https one with `--allow-remote-edge`. For the config
   cross-check (`policy_version`, policy bars) `capture.py` reads `GET /v1/admin/mode/detail` (`store:read`):
   the public `GET /v1/mode` is now only the badge subset. Full steps:
   `eval/PROTOCOL.md` §5 pre-flight item 2.
1. Before each attempt, `capture.py` sets `POST /v1/admin/eval/context` (`eval:admin`) with
   `{run_id, subject_id (pseudonymous), label, condition, split}`. `label` is the coarse edge
   label (`bona_fide`, `print`, `screen_photo`, `video`, `mask_paper`, `mask_3d`, `injection`). The
   fine-grained `species` (§2.2) stays in the CSV, mapped by `eval/evallib/schema.py` `SPECIES_TO_LABEL`.
   After the row is written it clears the context (`DELETE /v1/admin/eval/context`).
2. It consumes `GET /v1/events` (SSE, `events:read`): **decision** events, followed through any
   step-up to a terminal decision, and the kiosk's **rendered** event. The `POST /v1/attempt/{id}/rendered`
   beacon gives the user-visible **face lock → rendered** latency, which is the slide number, shown next
   to the server's `latency_ms.total`. Fallback: `GET /v1/attempt/{id}`.
3. **Rate limiter:** `capture.py` calls `POST /v1/admin/rate-limit/reset` (`ratelimit:reset`) **before every attempt** by default
   (`--reset-rate-limit attempt`; `block` / `never` are options). Otherwise five consecutive attack DENYs
   would lock the kiosk (5 s now), and the next attempt would be decided by the limiter instead of the
   biometrics. Alternatively the eval profile sets `rate_limit.enabled: false`. Record which in
   `RUN_INFO.md`. Rows that still carry `RATE_LIMITED` or `SYSTEM_ERROR` are flagged and **excluded** from
   APCER, BPCER and FRR by `eval/metrics.py` (not evaluated). Excluding them can only raise APCER.
4. FAR/FRR come from `eval/collect_faces.py` + `eval/compare.py` on consenting team photos
   (`eval/captures/`, gitignored, deleted after the event). The edge never exports embeddings.
5. Never point eval or test tooling at a scratch edge as if it were the live one, or the reverse: the
   operator's live edge is `127.0.0.1:8000`, and builder agents test on their own port.

**Flash caveat (as built).** `liveness.flash.enforce` is **false** (ADVISORY): the colour-flash result is
recorded in the signals (`ADVISORY_<zone>`) but has no decision effect. Any APCER for `phone_video`,
`laptop_replay` or `phone_photo` measured in this state measures PAD + device detector + moiré **without**
the flash. Say so next to the number, record the flag in `RUN_INFO.md`, and re-run those species if the
flash is enforced later. Depth is also disabled until H4, and `challenge.random_rate` is 0.15 online / 0.30 offline. Record all
three switches with the thresholds hash.

---

## 1. Metrics and how they map to HID's targets

### 1.1 Vocabulary

| Metric | Definition | Unit of count | Notes |
|---|---|---|---|
| **APCER(s)** | attack presentations of PAI species *s* wrongly classified as bona fide / attacks presented | per species | Report every species. **Headline = max APCER over species**, never the average. |
| **BPCER** | bona fide presentations wrongly classified as attacks / bona fide presentations | all genuine | `eval/metrics.py` reports two: **headline** = bona fide whose FINAL decision is DENY for **any** cause (conservative), and **PAD-only** = final DENY attributable to PAD codes. Also report per lighting condition (fairness/robustness). |
| **APNRR / BPNRR** | attack or bona fide attempts that got **no decision** (face never locked, timeout, crash) / attempts of that class | per class | Log these and do not drop them. A timeout is not a success. |
| **ACER** | (max APCER + BPCER) / 2 | summary | Academic only (OULU, CASIA-SURF). ISO 30107-3 does not endorse it. Show it only next to APCER/BPCER. |
| **IAPMR** | impostor attacks that pass PAD **and** match the targeted enrolled identity / impostor attacks | full system | This is the real spoof success rate at the door. Attacks use a photo or video of an enrolled user. |
| **FMR / FNMR** | matcher comparison errors at a threshold (impostor score ≥ T / genuine score < T) | comparisons | Algorithm level. Comes from offline cross-matching. |
| **FAR / FRR** | transaction-level false accept / false reject, **including retries and failure-to-acquire** | transactions | What the user experiences. FRR ≈ 1 − (1 − BPCER)(1 − FNMR) + FTA. |
| **Step-up rate** | genuine attempts whose first decision was `STEP_UP` (shown as REQUEST VERIFICATION) | genuine | The usability cost of the three-zone design. Report it, and report the step-up clearance rate. |
| **Liveness accuracy** | correct PAD outcomes (attack not ALLOWed + bona fide not spoof-DENYed) / all, with a Clopper–Pearson CI | all | Only to translate HID's slide; always state the class mix. On a 150:50 attack:genuine mix, a system that rejects everything scores 75%. |
| **Face-auth accuracy** | genuine attempts identified as the correct enrolled user and not falsely matched / genuine attempts, with CI | genuine | Next to FAR/FRR, never instead of them. |
| **Rank-1 identification rate** | genuine probes whose top-1 candidate is the true subject / genuine probes, with CI | comparisons | From `eval/compare.py` (1:N over the kiosk gallery). |

### 1.2 Two levels of "attack accepted": always say which one

- **PAD-level APCER**: the liveness stage alone labels the attack bona fide — i.e. the first decision carries no liveness-stage code (`SPOOF_*`, `MASK_CUE_*`, `LIVENESS_UNSURE`, `INJECTION_VIRTUAL_CAMERA`); `RANDOM_CHALLENGE` does not count as a liveness rejection because it is drawn at random — recorded as `liveness_result` by `eval/capture.py`. This is the ISO subsystem metric.
- **System-level APCER (attack success)**: the attempt's **final** decision is ALLOW, after any step-up. This is what matters at a door. With the three-zone policy, an attack that lands in STEP-UP and then fails the challenge counts as **not** accepted. Report the share of attacks routed to STEP-UP separately ("attack step-up rate").
- Bona fide attempts (as computed by `eval/metrics.py`): headline BPCER counts genuine attempts whose **final** decision is DENY for any cause; PAD-only BPCER counts those whose DENY is attributable to PAD codes. A genuine attempt whose first decision is STEP-UP feeds the step-up rate. If its step-up then fails and ends in DENY, it counts in BPCER. Transaction FRR = genuine attempts whose final decision is not ALLOW (incl. `NO_RESPONSE`) / all genuine. `RATE_LIMITED` / `SYSTEM_ERROR` rows are excluded (not evaluated) and counted separately.
- PAD-level APCER as computed: attacks whose liveness stage said PASS (an `UNKNOWN` liveness result counts as PASS, which is conservative) / attacks where liveness was evaluated.

### 1.3 Mapping to HID's slide (`docs/images/03_performance_targets.jpg`)

| HID target | What we report instead (with bound) | Data source |
|---|---|---|
| 99.4% liveness accuracy | max APCER per species + BPCER at the chosen operating point, each with a 95% upper bound; also the accuracy figure with its class mix stated | live attempts (`attempts.csv`) |
| 99.2% face-auth accuracy | face-auth accuracy with CI, FNMR @ FMR = 0.2%, and rank-1 identification rate on genuine probes | `comparisons.csv` + attempts |
| 0.2% FAR | FAR (FMR) at the operating threshold `match.local.allow_min_cosine`, from impostor cross-matching (≥ 1,500 comparisons), plus the transaction FAR seen live (0/N → < 3/N) | `comparisons.csv` |
| 0.6% FRR | FRR at the operating threshold (comparisons) + transaction FRR on genuine attempts, upper bound; say plainly that confirming 0.6% needs ≥ 500 error-free genuine transactions | `comparisons.csv` + `attempts.csv` |
| < 2 s decision | p50/p95 with bootstrap CI (and max) of **face lock → decision rendered** (the `/rendered` beacon) per species × final decision and overall, next to server `latency_ms.total`; step-up "verification time" reported separately | `latency_ms` (client) + `lat_server_total_ms` + stage spans |
| "validated across printed photo, screen replay, video, mask" | per-species table with N, errors, APCER, 95% UB for every species | `attempts.csv` |

---

## 2. One-day iBeta Level 1-style protocol

Say "iBeta Level 1-style". Never say certified or compliant.

### 2.1 Subjects and conditions
- **8–12 consenting subjects** (team plus neighbouring teams). Aim for a spread of skin tones, glasses/no glasses, beard, hair covering. Record a coarse self-reported group only if the subject consents (for example `monk_bucket` light/medium/dark). Optional, never required.
- **3 lighting conditions**: `office` (ambient overhead), `backlit` (window or lamp behind the subject), `dim` (lights partly off, < ~50 lux at the face).
- Enrol every subject once (`/register`, signed-in staff with `enrol:write`; `kiosk/public/enroll.html` only redirects there: consent checkbox, 5 frames at up to 1280 px, office lighting) **before** any test attempt. Enrolment frames are never used as probes. Erase with `DELETE /v1/enroll/{user_id}` after the event.

### 2.2 Attack species (PAI)
Build each artefact from an enrolled subject's photo or video so that IAPMR can be measured. Keep each artefact under about $30.

| `species` code | Artefact | HID scenario |
|---|---|---|
| `print` | A4 laser/inkjet colour print of a frontal photo | printed photo |
| `print_eyecut` | same print with eye holes cut, worn by an attacker so real eyes blink | mask (paper) |
| `phone_photo` | photo shown on a phone at full brightness | screen replay |
| `phone_video` | video of the subject (blinking, smiling) replayed on a phone | video |
| `laptop_replay` | video replayed on a laptop/tablet screen | video / screen |
| `paper_mask` / `mask_3d` | printed paper mask shaped on the face, or a rigid/3D-printed mask **if available** | mask (report as a stretch tier) |
| `inject_vcam` (optional) | OBS/ManyCam virtual camera playing a video | injection: **report separately, not as PAD** |

Bona fide attempts use `species = bona_fide`.

### 2.3 Volumes (target, adjust down honestly if time runs out)
- Genuine: ≥ 5 attempts × 3 lighting conditions × each subject → 120–180.
- Attacks: ≥ 5 attempts per species per artefact subject, using 6 artefact subjects (or all subjects) → about 30–60 per species. With 0 errors, 60 per species bounds APCER below 5%.
- **Interleave** genuine and attack attempts (for example G, A, G, A, A, G...). Never run all attacks in one block, because the system or the operator can "settle". The capture script prints the next attempt type from a pre-shuffled schedule.
- Each attempt is one transaction. Cap it at 30 s. If no decision arrives in 30 s, log `decision = NO_RESPONSE`, which feeds APNRR/BPNRR.
- Hold artefact angle, distance (30–60 cm) and motion natural. The attacker tries to pass and follows challenge prompts with the artefact (wiggles it, tilts it, smiles behind an eye-cut print).

### 2.4 Splits (no tuning on test data)
- **Subject-disjoint**: about 40% of subjects form `dev` (threshold tuning), about 60% form `test` (reported numbers). Assign by `subject_id` before capture and record it in the `split` column.
- Thresholds come from `config/thresholds.yaml`. After tuning on `dev`, **commit the file and record its git hash** in `eval/results/RUN_INFO.md`. Then run `test` with that file frozen.
- Optional: leave one attack species out of dev tuning (for example `laptop_replay`) and report it as "unseen species".
- When you report dev numbers, label them "dev (tuned on)".

---

## 3. Confidence bounds

### 3.1 Formulas
- **Zero errors (rule of 3)**: 0 errors in N trials → one-sided 95% upper bound ≈ **3/N** (exact: 1 − 0.05^(1/N)). FIDO's 80% bound is 1.61/N.
- **Nonzero errors**: use the **Clopper–Pearson** exact interval. Upper bound = `beta.ppf(1 − α, k + 1, N − k)` (one-sided 95% → α = 0.05). Wilson is acceptable. Never use the normal approximation for small k.
- Always print `k/N = p̂ (95% UB = x%)`.

### 3.2 Trials needed (one-sided 95%)

| Claim | 0 errors | 1 error | 2 errors |
|---|---|---|---|
| FAR / FMR ≤ 0.2% | **1,497** impostor comparisons | 2,371 | 3,146 |
| FRR ≤ 0.6% | **498** genuine transactions | 789 | 1,048 |
| APCER ≤ 5% per species | 59 | 93 | 124 |
| APCER ≤ 2% per species | 149 | 236 | 313 |
| BPCER ≤ 15% (iBeta cap) | 19 | 30 | 40 |

Conclusion for the pitch: **live** FRR at 0.6% cannot be confirmed in one day. Say so and show the required volume. FMR at 0.2% **can** be supported offline:

### 3.3 Impostor cross-matching (FAR volume, offline)
- The edge does **not** export embeddings. `eval/collect_faces.py` captures consenting team photos into `eval/captures/` (gitignored, deleted after the event); `eval/compare.py` embeds them offline with the same model as the edge matcher and writes `comparisons.csv`.
- Compare every probe against every **other** subject's enrolled template. 12 subjects × 30 probes × 11 other templates = 3,960 impostor comparisons, which exceeds the 1,497 needed. Pad with a public set (for example LFW) for more volume and demographic spread. Mark rows from it `source = lfw`.
- Genuine comparisons: each probe against its own template → FNMR.
- Set **`allow_min_cosine` at the 99.8th percentile of impostor scores on dev** (`DECISION_POLICY.md` §3.5; `policy-engine` writes it into the YAML), then report FMR/FNMR (FAR/FRR at the operating threshold) on test. Rank-1 identification rate comes from the same run.
- Rekognition similarity can be cross-matched the same way with `CompareFaces` if the Workshop Studio role allows Rekognition (sandbox region us-east-1; design limit = Mumbai default 25 TPS for CompareFaces; consenting team faces only). Otherwise, use the local ArcFace matcher only and say which matcher the number is for.

---

## 4. Latency

- SLA definition: **face lock → decision rendered** on the kiosk (`performance.now()` in the browser), reported by the `POST /v1/attempt/{id}/rendered` beacon and streamed on `GET /v1/events`. This is the slide number; show server `latency_ms.total` next to it.
- Log server stage spans from the decision (`latency_ms{liveness, match, schedule, policy, total}` → `lat_*` columns) and the client value (`latency_ms`, with `latency_source` = beacon).
- Report **p50 and p95 with a bootstrap 95% CI** (resample attempts, ≥ 2,000 resamples) and max, **per species × final decision** and **overall**, for both client and server latency, per mode (online/offline). Show the stage breakdown as stacked p50 bars. Step-up "verification time" is a separate metric. Small cells (n < 20): show the values but flag "low N".
- Measure on the demo laptop and venue Wi-Fi (Bangalore → us-east-1 RTT ≈ 200–250 ms affects online attempts). Re-measure after feature freeze. Only measured numbers go on slides; never round up.
- **What exists so far (dev measurement, n = 32, OFFLINE, MacBook webcam; not an eval result):** kiosk face lock → rendered p50 1518 ms / p95 1559 ms; edge server total p50 127 ms / p95 154 ms. This may be cited only as "dev measurement, n = 32, offline". There is no online number yet: the cloud match has a 700 ms time box, and the ONLINE ALLOW path must be measured once the us-east-1 deployment is up.

---

## 5. SC1 and SC2 scenario tests

The normative cases are the IDs in `docs/POLICY_TEST_CASES.md` (D15). Do not keep a separate list: the
pytest suites (`edge/policy/tests/`, `edge/offline/tests/`, `cloud/tests/`) implement every row, and
`eval/scenarios/` references the same IDs (legacy `S1-x` / `S2-x` scenario IDs are retired; map them to
the IDs below). Run the scripted tests with fixed clocks **and** at least one live run per group. Log live
runs to `attempts.csv` with `species = bona_fide` and the POLICY_TEST_CASES ID in `scenario`.
Expected reason codes are exactly those in the POLICY_TEST_CASES row (set comparison).

### 5.1 SC1: biometric result + campus schedule

Data: `config/schedule.example.json` is the test fixture (signed in the tests). The **live** demo bundle
comes from `config/schedule.demo.json` via `scripts/sign_bundle.py` (`issued_at` = now). Clock
`Asia/Kolkata`. Live runs switch time with the demo clock (`POST /v1/admin/clock {set_local: "HH:MM"}`,
`DEMO_MODE=1`; the kiosk shows a DEMO CLOCK badge). The demo clock does not re-sign the bundle, and a time
earlier than `issued_at` − 300 s reads as clock rollback (INVALID). So use **evening times** with a bundle
signed the same day (e.g. LIBRARY 21:10 → grace STEP_UP, 21:30 → outside DENY). TOTP always uses real
wall time.

| What is shown | POLICY_TEST_CASES IDs |
|---|---|
| In window → ALLOW (`ACCESS_OK`) | Q01, S05, S08, S18, S22, S24 |
| Outside window → DENY `SCHEDULE_OUTSIDE_WINDOW` | S04, S06, S07, S11, S12, S15, S25 |
| Grace band → STEP_UP `SCHEDULE_GRACE_WINDOW` → second factor | S01, S02, S03, S10 |
| Zone not permitted → DENY `SCHEDULE_ZONE_NOT_PERMITTED` | S09, S16, S20, S26 |
| Holiday → DENY `SCHEDULE_HOLIDAY` (exempt staff allowed) | S21, S22 |
| No entitlement / expired pass → DENY `SCHEDULE_NO_ENTITLEMENT` | S19, S23, S27 |
| Revoked → DENY `SCHEDULE_REVOKED` | S17 |
| High-risk zone in window → STEP_UP `SCHEDULE_HIGH_RISK_ZONE` | S13, S14, S31, S32 (config off) |
| Biometric UNSURE never upgraded by the schedule | S28, S29, S31 |
| Spoof DENY never overridden by the schedule | S30 |
| Missing / unsigned / tampered bundle (fail-secure) | O24, O25, O26, P08 |

**Pass**: every S01–S32 case green, plus the cross-references above. Live: the same live user shown
ALLOW (in window), REQUEST VERIFICATION (grace) and DENY (outside window) by moving the demo clock; reset
the clock afterwards. Property P05 (schedule deny-type ⇒ DENY) and P04 hold.

### 5.2 SC2: offline mode with safe access

| What is shown | POLICY_TEST_CASES IDs | Live-run pass criterion |
|---|---|---|
| Connectivity detection, hysteresis, SYNCING | X01–X06 | Forced switch (`POST /v1/admin/mode {"force":"OFFLINE"}`, `mode:switch`; auto-reverts to AUTO after `max_minutes`, default 60) shows on the badge within one 2 s poll (`connectivity.status_poll_ms`). Natural detection (Wi-Fi off) = 3 consecutive misses (`misses_to_offline`) of `GET /v1/health` every `heartbeat_interval_s` 5 s with `heartbeat_timeout_ms` 2000 → about 12–17 s after the link drops. SYNCING uses OFFLINE rules. No crash. |
| Cloud failure mid-attempt → that attempt OFFLINE (P7) | I07 | Never hangs, never ALLOWs by default. |
| Strong pass, low/medium zone, fresh bundle → offline ALLOW | O01, O02 | `ACCESS_OK`, `OFFLINE_MODE`; stricter offline thresholds active. |
| High-risk zone offline → STEP_UP, fallback | O03, O04, O05, O06, O07, O09 | `OFFLINE_HIGH_RISK_ZONE`, `OFFLINE_FALLBACK_REQUIRED`; never auto-ALLOW. |
| Any UNSURE offline → CHALLENGE + SECOND_FACTOR | L12, I08, I09, O13, O14, O15, O16 | Never ALLOW without the second factor. |
| Spoof offline → DENY (same as online) | O17, O27 | APCER offline is measured too. |
| Expired bundle / stale templates | O19, O20, O21, O22, O23, O28 | STAFF_OVERRIDE only for allow paths; deny-type still DENY. |
| Invalid bundle | O24, O25, O26 | A bad received bundle is rejected and the last valid bundle stays in force. No LVB → DENY `SCHEDULE_BUNDLE_INVALID` CONTACT_DESK. Clock rollback with an LVB → `SCHEDULE_BUNDLE_INVALID`, STAFF_OVERRIDE only. |
| Fallback factors (TOTP replay, staff code single use + lockout: 10-digit codes (legacy 8-digit accepted), 3 wrong per named `staff_id` → 300 s, device backstop 10 failures in 300 s → all overrides 300 s, locks survive a restart; card) | O06, O08, O09, O10, O12, O29 | `FALLBACK_OK` / `FALLBACK_FAILED` as listed. |
| Minimum storage, encryption, 2 dp scores | D01, D02, D03 | Show decrypted record keys and the raw `sqlite3` file (no images, no embeddings, no plaintext IDs). |
| Purge on ack, 24 h tombstone, hash chain | D04, D05, D06 | |
| Reconnect: idempotent sync, conflicts, re-evaluation alerts, refresh | Y01–Y11 | Queue count → 0; replaying the same batch = no duplicates; revoked-while-offline user raises `ALERT_REVOKED_USER_ADMITTED`. |
| Rate limit | Q10 | Only attack-evidence DENYs count (D3, R1): 5 in 180 s → **5 s** DENY `RATE_LIMITED` with `retry_after_s` (`rate_limit.lockout_s`; was 60). |

**Pass**: every listed ID green (`pytest edge/policy/tests edge/offline/tests cloud/tests`). Live: pull
the plug, offline ALLOW in a low-risk zone, high-risk TOTP/staff fallback, SQLite inspection and
reconnect + queue drain, run once on stage hardware with a screen recording as backup. Reset the demo
clock before this segment. `mode` is correct on every logged row.

---

## 6. Data capture log format

Directory: `eval/results/` (gitignore any images; CSVs are fine because they hold no biometrics).

### 6.1 `eval/results/attempts.csv`: one row per transaction

| Column | Type | Example | Notes |
|---|---|---|---|
| `attempt_id` | str (`att_<ulid>`) | `att_01JDA3…` | same ID the edge API returns; key for sync |
| `subject_id` | str | `S07` | the **presenter** for bona fide; for attacks, the **targeted** enrolled identity |
| `species` | enum | `bona_fide`, `print`, `print_eyecut`, `phone_photo`, `phone_video`, `laptop_replay`, `paper_mask`, `mask_3d`, `inject_vcam` | |
| `lighting` | enum | `office`, `backlit`, `dim` | |
| `mode` | enum | `ONLINE`, `OFFLINE` | from the response, not from the operator |
| `zone` | str | `LIBRARY`, `LAB_BLOCK`, `SERVER_ROOM` | bundle zone names; drives SC1/SC2 risk |
| `ts_utc` | ISO-8601 UTC | `2026-11-14T08:41:07.123Z` | |
| `decision` | enum | `ALLOW`, `STEP_UP`, `DENY`, `NO_RESPONSE` | **final** decision after step-up |
| `reason_codes` | `;`-joined | `SPOOF_DEVICE_DETECTED;SPOOF_FLASH_MISMATCH` | canonical codes only |
| `first_decision`, `first_reason_codes` | enum / `;`-joined | `STEP_UP`, `LIVENESS_UNSURE` | pre-step-up decision (step-up rate, PAD-level APCER) |
| `liveness_result` | enum | `PASS` / `UNSURE` / `FAIL` / `NOT_EVALUATED` | derived from the first decision's liveness-stage codes |
| `scores` | JSON string | `{"pad_mean":0.12,"pad_pass_frames":0,"flash_r":0.08,"flash_amp":9.1,"moire":0.71,"device_conf":0.83,"match_local":0.41,"rekognition":null}` | the response `scores{}` keys (`DECISION_POLICY.md` §10) |
| `latency_ms` | float | `1430` | client face lock → rendered (`/rendered` beacon; `latency_source` says so) |
| `lat_server_total_ms` | float | `410` | server `latency_ms.total` (+ `lat_liveness_ms`, `lat_match_ms`, `lat_schedule_ms`, `lat_policy_ms`) |
| `split` | enum (extra) | `dev` / `test` | assigned per subject before capture |
| `operator` | str (extra) | `op1` | who held the artefact (initials or alias) |
| `scenario` | str (extra) | `S01` | `docs/POLICY_TEST_CASES.md` ID for scenario runs |
| `notes` | str (extra) | `grace test, demo clock 07:50` | |

### 6.2 `eval/results/comparisons.csv`: offline matcher cross-matching
`probe_attempt_id, probe_subject, gallery_subject, matcher (arcface|rekognition), score, genuine (0/1), split, source (live|lfw)`

### 6.3 `eval/results/RUN_INFO.md`
Date, hardware, camera, thresholds git hash, subjects per split, known deviations from protocol.

Capture tooling: `eval/capture.py` prints the next attempt from the shuffled schedule and has the operator confirm species/lighting, then sets `POST /v1/admin/eval/context`. It reads decision + rendered events from `GET /v1/events` (fallback `GET /v1/attempt/{id}`) and appends the row. **The operator never types scores or decisions by hand.**

---

## 7. Metrics script (reference sketch; the owned implementation is `eval/metrics.py`)

The sketch below shows the counting rules. `eval/metrics.py` must additionally produce every D14 metric:
latency p50/p95 with bootstrap CI per species × final decision and overall (client and server),
liveness accuracy and face-auth accuracy with CIs, rank-1 identification rate, APCER per species
(Clopper–Pearson upper bound; rule of 3 for 0 errors), BPCER, step-up rate, FAR/FRR at the operating
threshold.

```python
"""Compute ISO/IEC 30107-3 PAD metrics + FMR/FNMR + latency from eval/results/*.csv.
Usage: python eval/metrics.py --split test --out eval/results/report
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
import numpy as np, pandas as pd
from scipy.stats import beta, norm

def cp_upper(k: int, n: int, conf: float = 0.95) -> float:
    """One-sided Clopper-Pearson upper bound; k=0 -> ~3/n at 95%."""
    if n == 0:
        return float("nan")
    return 1.0 if k >= n else float(beta.ppf(conf, k + 1, n - k))

def fmt(k: int, n: int) -> dict:
    return {"k": k, "n": n, "rate": k / n if n else float("nan"), "ub95": cp_upper(k, n)}

def boot_pct(x: np.ndarray, q: float, n_boot: int = 2000, seed: int = 0) -> dict:
    """Percentile q (e.g. 50, 95) with a 95% bootstrap CI over attempts."""
    x = np.asarray(x, float); x = x[~np.isnan(x)]
    if len(x) == 0:
        return {"n": 0}
    rng = np.random.default_rng(seed)
    bs = np.percentile(rng.choice(x, (n_boot, len(x)), replace=True), q, axis=1)
    return {"n": len(x), "value": float(np.percentile(x, q)),
            "ci95": [float(np.percentile(bs, 2.5)), float(np.percentile(bs, 97.5))]}

LIVENESS_CODES_PREFIX = ("SPOOF_", "MASK_CUE_")
LIVENESS_CODES = {"LIVENESS_UNSURE", "INJECTION_VIRTUAL_CAMERA"}

def pad_said_live(first_codes: str) -> bool:
    codes = [c for c in str(first_codes or "").split(";") if c]
    return not any(c.startswith(LIVENESS_CODES_PREFIX) or c in LIVENESS_CODES for c in codes)

def pad_metrics(df: pd.DataFrame) -> dict:
    df = df.copy()
    bona = df[df.species == "bona_fide"]
    attacks = df[(df.species != "bona_fide") & (df.species != "inject_vcam")]
    out: dict = {"apcer_system": {}, "apcer_pad": {}, "attack_stepup": {}}
    for sp, g in attacks.groupby("species"):
        resp = g[g.decision != "NO_RESPONSE"]
        out["apcer_system"][sp] = fmt(int((resp.decision == "ALLOW").sum()), len(resp))
        out["apcer_pad"][sp] = fmt(int(resp.first_reason_codes.apply(pad_said_live).sum()), len(resp))
        out["attack_stepup"][sp] = fmt(int(resp.first_decision.eq("STEP_UP").sum()), len(resp))
    worst = max(out["apcer_system"].items(), key=lambda kv: kv[1]["ub95"], default=(None, None))
    out["max_apcer_system"] = {"species": worst[0], **(worst[1] or {})}
    resp_b = bona[bona.decision != "NO_RESPONSE"]
    spoof_deny = resp_b.decision.eq("DENY")
    out["bpcer"] = fmt(int(spoof_deny.sum()), len(resp_b))
    out["bpcer_by_lighting"] = {l: fmt(int(g.decision.eq("DENY").sum()), len(g)) for l, g in resp_b.groupby("lighting")}
    out["genuine_stepup_rate"] = fmt(int(resp_b.first_decision.eq("STEP_UP").sum()), len(resp_b))
    out["frr_transaction"] = fmt(int((bona.decision != "ALLOW").sum()), len(bona))  # includes NO_RESPONSE
    out["far_transaction_attacks"] = fmt(int((attacks.decision == "ALLOW").sum()), len(attacks))  # = IAPMR when attacks target enrolled IDs
    out["bpnrr"] = fmt(int(bona.decision.eq("NO_RESPONSE").sum()), len(bona))
    out["apnrr"] = fmt(int(attacks.decision.eq("NO_RESPONSE").sum()), len(attacks))
    m = out["max_apcer_system"].get("rate", float("nan"))
    out["acer_academic_only"] = (m + out["bpcer"]["rate"]) / 2
    resp_all = df[df.decision != "NO_RESPONSE"]
    def lat_block(g):
        return {col: {"p50": boot_pct(g[col], 50), "p95": boot_pct(g[col], 95), "max": float(g[col].max())}
                for col in ("latency_ms", "lat_server_total_ms") if col in g}
    out["latency"] = {"overall": lat_block(resp_all),
                      "by_species_decision": {f"{sp}|{d}": lat_block(g)
                                              for (sp, d), g in resp_all.groupby(["species", "decision"])},
                      "by_mode_allow": {m: lat_block(g) for m, g in resp_b[resp_b.decision == "ALLOW"].groupby("mode")}}
    return out

def det_points(genuine: np.ndarray, impostor: np.ndarray, n: int = 400):
    """Return thresholds, FMR, FNMR (higher score = more similar / more live)."""
    ts = np.unique(np.quantile(np.concatenate([genuine, impostor]), np.linspace(0, 1, n)))
    fmr = np.array([(impostor >= t).mean() for t in ts])
    fnmr = np.array([(genuine < t).mean() for t in ts])
    return ts, fmr, fnmr

def matcher_metrics(cmp: pd.DataFrame, target_fmr: float = 0.002) -> dict:
    g = cmp[cmp.genuine == 1].score.to_numpy(); i = cmp[cmp.genuine == 0].score.to_numpy()
    t_allow = float(np.quantile(i, 1 - target_fmr))  # use dev split to choose; report on test
    k_fm, k_fnm = int((i >= t_allow).sum()), int((g < t_allow).sum())
    ts, fmr, fnmr = det_points(g, i)
    eer_idx = int(np.argmin(np.abs(fmr - fnmr)))
    return {"t_allow": t_allow, "fmr": fmt(k_fm, len(i)), "fnmr": fmt(k_fnm, len(g)),
            "eer": float((fmr[eer_idx] + fnmr[eer_idx]) / 2), "det": (ts, fmr, fnmr)}

def plot_det(fmr, fnmr, path: Path, label: str):
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    eps = 1e-4
    x, y = norm.ppf(np.clip(fmr, eps, 1 - eps)), norm.ppf(np.clip(fnmr, eps, 1 - eps))
    ticks = [0.001, 0.002, 0.01, 0.05, 0.2, 0.5]
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot(x, y, label=label)
    ax.axvline(norm.ppf(0.002), ls="--", lw=0.8, label="HID FAR 0.2%")
    ax.axhline(norm.ppf(0.006), ls=":", lw=0.8, label="HID FRR 0.6%")
    ax.set_xticks(norm.ppf(ticks), [f"{t:.1%}" for t in ticks]); ax.set_yticks(norm.ppf(ticks), [f"{t:.1%}" for t in ticks])
    ax.set_xlabel("FMR (log-normal deviate)"); ax.set_ylabel("FNMR"); ax.legend(frameon=False); ax.grid(alpha=0.2)
    fig.tight_layout(); fig.savefig(path, dpi=160); plt.close(fig)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--split", default="test"); ap.add_argument("--out", default="eval/results/report")
    a = ap.parse_args(); out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    att = pd.read_csv("eval/results/attempts.csv"); att = att[att.split == a.split]
    report = {"split": a.split, "pad": pad_metrics(att)}
    cmp_path = Path("eval/results/comparisons.csv")
    if cmp_path.exists():
        cmp = pd.read_csv(cmp_path); cmp = cmp[cmp.split == a.split]
        for matcher, c in cmp.groupby("matcher"):
            mm = matcher_metrics(c); ts, fmr, fnmr = mm.pop("det")
            plot_det(fmr, fnmr, out / f"det_{matcher}.png", matcher); report[f"match_{matcher}"] = mm
    (out / "metrics.json").write_text(json.dumps(report, indent=2, default=float))
    print(json.dumps(report, indent=2, default=float))
```

The PAD DET curve uses the same `det_points` with genuine = bona fide `scores.pad` and impostor = attack `scores.pad`, one curve per species (APCER on x, BPCER on y). Choose T_allow on `--split dev`, write it to `thresholds.yaml`, then rerun with `--split test` using a **fixed** threshold. Do not re-derive it on test. The quantile line above is for dev only.

---

## 8. Dashboard spec (`kiosk/` admin route, for example `/admin/metrics`)

**Before writing any chart code, invoke the `dataviz` skill** for palette, mark specs and stat-tile layout. Charts must work in light and dark mode on the projector.

Data: `GET /v1/metrics` (`metrics:read`; aggregates from `metrics.json` + live attempts), `GET /v1/events` (`events:read`; SSE stream of decision + rendered events) and `GET /v1/mode` (public badge subset, polled every 2 s; the full status is `GET /v1/admin/mode/detail`, `store:read`). The dashboard sits behind the staff sign-in (`docs/API.md` §0.1). Poll metrics every 5 s.

| Panel | Form | Content |
|---|---|---|
| Header strip | stat tiles | max APCER (UB95), BPCER (UB95), FMR@T (UB95), p95 latency vs 2 s, each with HID target beside it and an N count |
| **Online/offline badge** | pill, always visible | `ONLINE` / `SYNCING` / `OFFLINE since 10:42:13` from `GET /v1/mode`; colour plus text, never colour only; a **DEMO CLOCK** badge whenever the demo clock is active |
| **Sync queue** | counter + sparkline | queued decisions, last sync time, discrepancy alerts count (clickable) |
| **Per-species bars** | horizontal bars, one per species | APCER point estimate + 95% UB whisker; label `k/N`; reference line at 0%; species sorted by UB |
| BPCER by lighting | small bars | office / backlit / dim with UB; genuine step-up rate alongside |
| **DET curve** | line, normal-deviate axes | matcher FMR vs FNMR; HID 0.2% / 0.6% reference lines; operating point marked; optional per-species PAD DETs |
| **Latency histogram** | histogram + p50/p95 markers (with CI) | client face lock → rendered and server total; 2 s target line; toggle online/offline and species × decision; stacked stage bar (p50) beneath |
| **Live decision feed** | table, newest first | time, decision chip (ALLOW / REQUEST VERIFICATION / DENY), species (from the eval context), reason codes in plain English, latency, mode, zone |
| Confusion matrix | grid | rows = species, cols = ALLOW / REQUEST VERIFICATION / DENY / NO_RESPONSE, counts; fills in live during the demo |

Rules: show N on every rate, show the bound next to every point estimate, never show raw biometric images, and keep the kiosk-facing screen showing only the decision and reason (scores belong to admin only).

---

## 9. Honesty rules for slides and Q&A

1. "We followed an **iBeta Level 1-style** protocol." Never "iBeta certified/compliant/tested".
2. **Bounds, not point claims**: "0/58 print attacks accepted → APCER < 5.2% (95% upper bound, rule of 3)". Never "100% liveness". Never round a number up (e.g. 98.6% is not "99%").
3. State the matcher behind each number (local ArcFace vs Rekognition) and the split (dev vs test).
4. FRR 0.6% / FAR 0.2%: give the trial counts needed (498 / 1,497 at zero errors) and what we actually ran.
5. **Silicone masks are a known limit** of RGB liveness. The mandatory mouth/cheek challenge step (and the random challenge, 15 % online / 30 % offline) raises the bar for rigid masks. Depth (iPhone TrueDepth, M1) "raises the bar", it does not "solve" masks, and it is disabled until the H4 calibration passes. Rigid/paper masks are reported as a separate stretch tier.
6. Injection (virtual camera) is reported **separately** from PAD (ISO 30107-3 and FIDO exclude it from PAD; CEN/TS 18099 covers it).
7. Latency: only measured p50/p95 (with bootstrap CI) from the demo hardware; say client (face lock → rendered) vs server, and online (us-east-1 sandbox) vs offline. The dev numbers (n = 32, offline) are labelled "dev measurement", never "eval".
8. Licence caveats: InsightFace `buffalo_l` weights and CelebA-Spoof-trained models are non-commercial. MiniFASNet is Apache-2.0.
9. Never edit `attempts.csv` by hand except to drop a row with a written reason in `RUN_INFO.md` (for example "operator mis-tagged species").
10. Small, consenting cohort: say "N subjects, team-sourced, not demographically representative".
11. **Colour flash is ADVISORY** while `liveness.flash.enforce` is false. Never say it blocks video replay. Say "video/screen replay is handled by PAD + device detector + moiré; the colour-flash nonce is designed and measured, and will be enforced after frame-timing validation".
