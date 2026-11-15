# eval/PROTOCOL.md - one-day iBeta Level 1-**style** evaluation protocol (14 Nov 2026)

We follow an **iBeta Level 1-style** protocol with ISO/IEC 30107-3 vocabulary. It is **not** an iBeta test,
not a certification and not "compliant" with anything. Subjects are consenting team members only:
**N subjects, team-sourced, not demographically representative.** Every number we publish comes from a CSV in
`eval/results/` written by a real run, through `eval/metrics.py`, with its 95 % bound. Nothing is typed by hand,
rounded up or extrapolated. Sources: `.claude/skills/pad-evaluation/SKILL.md`, `docs/DECISION_POLICY.md`,
`docs/API.md` (3.7, 3.8, 3.12, 3.13, 3.16), `docs/POLICY_TEST_CASES.md`, lead decisions of round 2.

## 1. Roles and equipment

| Role | Who | Does |
|---|---|---|
| Operator | human (physical tasks only) | sits/stands in front of the kiosk, holds artefacts, switches lights, follows the prompts printed by `capture.py` |
| Logger | `eval/capture.py` on the kiosk laptop | sets the edge eval context, waits for the decision, writes one CSV row per attempt |
| Analyst | `eval/metrics.py`, `eval/summary.py` | computes all numbers + bounds from the CSVs |

Equipment: kiosk laptop (edge on `127.0.0.1:8000`, kiosk UI in the browser, same machine), its webcam, an A4
colour printer, scissors, one phone (full brightness), one laptop/tablet for replays, a desk lamp (backlight),
optional rigid/3D mask, optional OBS virtual camera (injection, reported separately). Artefacts < $30 each.

## 2. Subjects, consent, enrolment, split

1. **Consent first.** Each subject gives written consent for capture, enrolment and the eval; consent version is
   recorded as `consent=yes, consent_version=...` in `eval/subjects.csv`. No names anywhere: pseudonymous ids
   `S01..`. Optional coarse self-reported group only with consent; never required.
2. **Split before any capture (subject-disjoint).** `uv run python plan.py subjects --ids S01,S02,...` assigns
   about 40 % of subjects to `dev` (threshold tuning) and 60 % to `test` (reported numbers) with a fixed seed.
   The split column is copied into every row; `metrics.py` refuses data where a subject appears in both splits.
3. **Enrol once** (3-5 frames, office light, `POST /v1/enroll`) under a user id that is **entitled IN_WINDOW at
   the eval kiosk** and write that id into `enrolled_user_id`. The live edge is `KIOSK_MAIN_01` / zone `MAIN_GATE`
   with the cloud-issued bundle (v45 at the time of writing; `GET /v1/mode` `schedule_bundle`); the test fixture
   `config/schedule.example.json` uses `KIOSK_LIB_01` / LIBRARY. Pass `--zone` / `--kiosk-id` to capture.py to
   match the live kiosk (they only fill NO_RESPONSE rows; responded rows take zone and kiosk from the edge).
   Enrolment frames are never probes. Otherwise schedule rules (SC1) would DENY genuine users and pollute the
   headline BPCER (the PAD-only BPCER separates them, 6.4).
4. Thresholds: `config/thresholds.yaml` is tuned on `dev` only (sections 6.6 and 6.7), then **frozen**; the sha256 of the
   file (no git repo here) and `policy_version` are recorded per run (`results/runs/<run_id>.json`) and in
   `RUN_INFO.md`. `metrics.py` warns if the file changed after capture. Dev numbers are labelled "dev (tuned on)".

## 3. Conditions and volumes

Conditions (`lighting` x `distance`; the edge eval context uses one `condition` value, mapped automatically):

| CSV `lighting` | Meaning | edge `condition` | | CSV `distance` | Meaning |
|---|---|---|---|---|---|
| `office` | ambient overhead light | `normal` (`far` if distance = far) | | `near` | ~30 cm |
| `backlit` | window / lamp behind the subject | `backlit` | | `mid` | ~45 cm (default) |
| `dim` | lights partly off, < ~50 lux at the face | `dim` | | `far` | ~60 cm |

Targets for the **test** split (cells below are flagged `LOW_N` in every output, never hidden):

| Class | Target (test) | Dev | With 3 test subjects |
|---|---|---|---|
| bona fide | >= 120 | ~30 | 14 per subject x 3 lighting (mid) |
| each attack species | >= 30 | ~10 | 10 per subject per species |
| zero-effort impostor (optional) | 10-20 | - | live non-matching person |
| injection (optional, separate) | 6-10 | - | OBS virtual camera |

`uv run python plan.py schedule --split test --out plans/test_plan.csv` derives per-cell counts from these
targets and the number of test subjects, spreads attacks over the lighting blocks, and shuffles each lighting
block so that **never more than 3 genuine or 3 attack attempts follow each other** (iBeta-style interleaving).
At ~20 s per attempt, 306 test attempts take about 100 min. Plan honestly: if time runs out, stop and report the
N reached; do not top up a species after looking at results.

What zero errors can support (one-sided 95 %, computed by `evallib.stats.trials_needed`, unit-tested):

| Claim | 0 errors | 1 error | 2 errors |
|---|---|---|---|
| FAR / FMR <= 0.2 % | 1,497 independent impostor trials (6.6: distinct unordered live subject pairs) | 2,371 | 3,146 |
| FRR <= 0.6 % | 498 genuine transactions | 789 | 1,048 |
| APCER <= 5 % per species | 59 | 93 | 124 |
| APCER <= 2 % per species | 149 | 236 | 313 |
| BPCER <= 15 % (iBeta cap) | 19 | 30 | 40 |

Conclusion we say out loud: live FRR at 0.6 % cannot be confirmed in one day; FMR at 0.2 % can be supported only
offline with >= 1,497 independent impostor trials (section 6.6), which a team-sized cohort cannot reach.

## 4. Presentation attack instruments (species) - what the operator physically does

`species` is the fine-grained PAI species (CSV); `label` is the coarse edge eval label (API 3.13), set
automatically. Each artefact is built from an **enrolled** subject's photo/video so IAPMR can be measured;
`subject_id` of an attack row is the **targeted** enrolled identity.

| `species` | `label` | HID scenario | Artefact | Operator action per attempt |
|---|---|---|---|---|
| `bona_fide` | bona_fide | live person | - | subject faces the screen at the planned distance, natural; follows any prompt |
| `print` | print | Printed photo | A4 laser/inkjet colour print of a frontal photo | hold flat, face in the oval, ~40 cm, natural hand motion; tilt/wiggle when prompted |
| `print_eyecut` | mask_paper | Mask (printed) | same print, eye holes cut | attacker wears it, real eyes blink through the holes; tries to smile when prompted |
| `phone_photo` | screen_photo | Screen replay (photo) | photo on a phone, full brightness | phone ~30 cm, face fills the oval |
| `phone_video` | video | Video replay | video of the subject blinking/smiling, phone | play on loop ~30 cm |
| `laptop_replay` | video | Video / screen replay | same video on a laptop/tablet | screen ~40 cm |
| `paper_mask` | mask_paper | Mask (paper) | printed paper mask shaped on the face | attacker wears it; follows prompts |
| `mask_3d` | mask_3d | Mask (3D) - stretch tier | rigid / 3D-printed mask if available | attacker wears it; follows prompts |
| `inject_vcam` | injection | **reported separately, not PAD** | OBS virtual camera playing a video | switch the kiosk camera source to the virtual camera |

Zero-effort impostor (optional): a live consenting person who is not the target presents normally
(`capture.py --zero-effort`); used only for the live transaction FAR, not for BPCER/FRR.

Silicone masks are a known limit of RGB liveness; depth (iPhone TrueDepth) "raises the bar", it does not "solve"
masks. Injection is reported separately from PAD (ISO/IEC 30107-3 and FIDO exclude it; CEN/TS 18099 covers it).

## 5. Session procedure

Pre-flight (once per session):

1. Edge healthy: `curl -s 127.0.0.1:8000/v1/health` shows `status: ok` and the PAD self-test passed.
2. Edge API keys (RBAC; mint them once on the kiosk laptop, they are shown once and never printed by the tools):
   `../edge/.venv/bin/python -m edge.auth create-api-key --name eval --role evaluator --expires-days 7 --print-key-only`
   -> `FG_EVAL_API_KEY` (capture.py, snapshot_metrics.py: SSE `GET /v1/events`, `/v1/admin/eval/context`,
   `/v1/admin/rate-limit/reset`, `GET /v1/metrics`, `GET /v1/admin/mode/detail` for the config cross-check:
   the public `GET /v1/mode` is only the badge subset), and
   `... create-api-key --name ops --role security_officer --role evaluator --expires-days 7 --print-key-only`
   -> `FG_OPS_API_KEY` (scenarios/run_scenarios.py `--backend store|api`: `GET /v1/admin/store`,
   `POST /v1/admin/mode`). Put them in the environment or the project `.env`. The tools send
   `Authorization: Bearer <key>`; a missing key or a 401/403 stops the tool with a clear error and exit code 5
   (no silent fallback). The legacy shared `ADMIN_TOKEN` is used only with `FG_ALLOW_LEGACY_ADMIN_TOKEN=1`
   (and the edge's `AUTH_LEGACY_ADMIN_TOKEN=1`). Revoke the keys after the session
   (`python -m edge.auth revoke-api-key --key-id <id>`).
3. Eval profile recorded automatically (`evallib/config.py` `shipped_switches`, written into the run manifest
   `results/runs/<run_id>.json` `shipped_switches`, into `RUN_INFO.md` and `SUMMARY.md`): thresholds sha256 +
   `policy_version`, `liveness.flash.enforce` (shipped **false = ADVISORY**: replay-species APCER is measured
   without the flash, and SUMMARY.md says so next to the number), flash duration / colours (700 ms, 3 colours),
   `liveness.moire.enforce` (true, 0.40 / 0.70), `liveness.mask.m2_rgb_enforce` (true, 0.50 / 0.75),
   `liveness.depth.enabled` (false until H4), `challenge.random_rate` (0.15 online / 0.30 offline;
   deformation SMILE / OPEN_MOUTH + secondary BLINK / TURN_LEFT / TURN_RIGHT), `rate_limit` (5 in 180 s -> 5 s
   lockout), `match.rekognition.enabled` (true). At start capture.py also cross-checks the same switches against
   the running edge (`GET /v1/mode` `policy_bars`) and records any difference as `edge_config_diff` (e.g.
   thresholds.yaml edited but the edge not restarted); `metrics.py` repeats it as a RUN_INFO note. We evaluate the
   deployed configuration (random challenge on); the step-up rate is reported split by trigger
   (`RANDOM_CHALLENGE` separately).
4. Kiosk clock / demo clock: real time inside the eval kiosk's window for every enrolled subject (check one
   bona fide attempt per subject ends `ACCESS_OK` before the plan starts), or the demo clock set inside it; mode
   `ONLINE` unless the block is an offline block.

Per attempt (`capture.py --plan plans/test_plan.csv --run-id <id> --operator <initial>`):

1. capture.py prints the next planned attempt and the physical instruction; operator presses Enter.
2. capture.py calls `POST /v1/admin/rate-limit/reset` (default before every attempt, see 6.5), then
   `POST /v1/admin/eval/context {run_id, subject_id, label, condition, split}`, then arms.
3. The presenter steps up; the kiosk locks the face and submits frames. capture.py takes the **next new attempt**
   on `GET /v1/events` (`decision` events), follows any STEP_UP (challenge, second factor, recapture) to a
   terminal ALLOW/DENY, joins the `rendered` event (client face lock -> rendered), writes one row, clears the
   context (`DELETE /v1/admin/eval/context`).
4. **30 s transaction cap**: no first decision within 30 s -> row with `decision = NO_RESPONSE` (APNRR/BPNRR).
   A STEP_UP that is not resolved within 130 s (session TTL 120 s + margin) -> `decision = STEP_UP`,
   `stepup_outcome = unresolved`.
5. **Event source and fallback.** SSE `GET /v1/events` is primary. The edge has no attempt list, so the
   fallback is `GET /v1/attempt/{id}` (API.md 3.6): while the stream is down, the attempts being followed are
   polled by id between reconnects; with `--transport poll` (or SSE 404 under `auto`) polling by id is the only
   source and capture.py asks the operator to type the attempt id shown on the admin live feed (`x` abort,
   `n` NO_RESPONSE). The by-id response is only the **latest** DecisionResponse and carries no `eval` key and no
   `rendered` event, so such rows are flagged `eval_tags_not_in_poll_response` and `no_render_event`, and
   `POLL_MISSED_STEPUP(first_seen_stage=...)` when the first response seen was already a challenge / fallback
   result (the STEP_UP before it was not observed: that row's step-up fields are unreliable). A recapture that
   opens a new attempt id is not discovered by id polling. A new attempt that starts while SSE is down cannot be
   discovered either: press `x` and redo it once the stream is back, or restart with `--transport poll`.
6. **De-duplication (two capture clients).** If two kiosk clients (e.g. kiosk page + operator console) submit the
   same face lock, the edge creates two attempt ids. A decision whose face lock (`face_lock_at_ms` from the
   `rendered` event, else receive time minus `latency_ms.face_lock_to_decision_server`) is within **+-50 ms** of an
   earlier attempt **and** whose score fingerprint (all `s_*` scores + mask ring) is identical is dropped as a
   duplicate: no row, `dup_dropped:<id>(<decision>)` in the kept row's `notes`, and the run manifest lists every
   drop (`duplicates_dropped` count + `duplicates[]` audit trail: kept id, dropped id, its decision and codes,
   face-lock delta). An attempt without any score is never dropped. `RUN_INFO.md` reports the count per run.
7. Operator keys while waiting: `x` abort (no row, the plan item is re-queued - use for operator errors such as
   the wrong artefact, before the decision only), `n` NO_RESPONSE now, `g` give up a pending step-up, `r` reset the
   rate limiter, `q` quit after this attempt. Resume: re-run the same command; logged plan items are skipped.
8. After a decision, a wrong row is never edited or deleted: add `attempt_id, reason, excluded_by, ts_utc` to
   `eval/results/exclusions.csv`; `metrics.py` applies it and lists it in `RUN_INFO.md`.

The attacker tries to pass: natural angle and distance (30-60 cm), follows challenge prompts with the artefact.
Lighting changes happen only at block boundaries printed by capture.py.

SC1/SC2 live demonstrations are logged with `--scenario <POLICY_TEST_CASES id>` (e.g. `S04`, `O01`); these rows
are **excluded from PAD and latency metrics** and appear as live evidence in the scenario table (section 8).

## 6. Metric definitions (exactly what `metrics.py` computes)

All rates are `k/N` with a one-sided 95 % Clopper-Pearson upper bound `beta.ppf(0.95, k+1, N-k)`; with 0 errors
the bound is exact `1 - 0.05^(1/N)` and the rule-of-3 value `3/N` is reported next to it ("0/58 -> < 3/58").
Two-sided 95 % CP intervals are also stored. Displayed percentages are rounded **conservatively**: error rates
and upper bounds up, accuracies and lower bounds down. "Final decision" = after any step-up.

### 6.1 PAD (ISO/IEC 30107-3 vocabulary), per species, reported split only

| Metric | Numerator | Denominator |
|---|---|---|
| **APCER (system, headline)** per species | attacks whose **final** decision is ALLOW - **an attack that reaches ALLOW only via a passed step-up counts as accepted** | attacks of that species with a decision, excluding NO_RESPONSE (-> APNRR), RATE_LIMITED (6.5) and SYSTEM_ERROR DENYs (not evaluated; excluding them can only raise APCER) |
| max APCER (headline) | species with the highest 95 % UB (point-estimate maximum also reported) | - |
| APCER (PAD level) | attacks whose liveness stage said PASS on the first evaluated decision (UNKNOWN counted as PASS) | attacks where liveness ran |
| attack step-up rate | attacks whose **first** decision is STEP_UP (by trigger) | as APCER |
| step-up bypass | of those, final ALLOW | attacks with first STEP_UP |
| APNRR / BPNRR | NO_RESPONSE | all attempts of the class |
| IAPMR | attacks with final ALLOW **and** candidate = targeted enrolled user | attacks with a target id |
| ACER | (max APCER + BPCER PAD-only) / 2 | academic summary only, never alone |

PAD-level labels (`liveness_result`) are derived, because the DecisionResponse has no PAD label: FAIL = DENY with
a hard spoof code / strong mask cues / stage `liveness`; UNSURE = any `LIVENESS_UNSURE`, `MASK_CUE_*` or
`SPOOF_*` code on a STEP_UP; NOT_EVALUATED = quality / injection / RATE_LIMITED / SYSTEM_ERROR short-circuits;
UNKNOWN = DENY with only `NOT_ENROLLED` (the policy hides liveness codes on BIO_FAIL); PASS otherwise (including a
`RANDOM_CHALLENGE` STEP_UP, whose signals passed). An explicit edge field wins if one is ever added.

### 6.2 Bona fide

| Metric | Numerator | Denominator |
|---|---|---|
| **BPCER (headline)** | bona fide whose **final** decision is DENY (any cause - conservative), with a cause breakdown (pad, quality, match, schedule, fallback, system) | bona fide with a decision (RATE_LIMITED excluded) |
| BPCER (PAD-only, ISO-style) | final DENY attributable to PAD codes (`SPOOF_*`, `MASK_CUE_*`, `CHALLENGE_FAILED`, `INJECTION_*`, `LIVENESS_UNSURE`) | same |
| **step-up rate** | bona fide whose **first** decision is STEP_UP, incl. `RANDOM_CHALLENGE` and RECAPTURE; split by trigger; also excluding random challenges | same - **reported separately, never in BPCER** |
| step-up clearance | of those, final ALLOW | bona fide with first STEP_UP |
| FRR (transaction) | final decision != ALLOW, incl. NO_RESPONSE and unresolved STEP_UP | all bona fide (RATE_LIMITED excluded) |
| FRR (first pass) | first decision != ALLOW | all bona fide |
| BPCER / step-up by lighting and distance | as above per condition (robustness / fairness view) | |

STEP_UP counting rule in one line: **attack -> ALLOW via step-up = accepted (APCER); bona fide -> STEP_UP =
step-up rate (not BPCER); bona fide -> STEP_UP -> DENY = BPCER; unresolved STEP_UP = not ALLOW (FRR).**

### 6.3 Accuracy translations of HID's slide (always with the class mix)

- **Liveness accuracy (HID-style)** = 1 - (attacks with final ALLOW + bona fide PAD-attributable DENY) /
  (attacks evaluated + bona fide with a decision); 95 % two-sided CP interval and one-sided LB; class mix stated
  (a reject-everything system scores attacks / (attacks + bona fide)). The ISO view (max APCER + BPCER) is shown
  next to it.
- **Face-auth accuracy** = 1 - FNMR at the configured threshold on the test split (genuine users authenticated),
  with CP bounds; the verification accuracy over the genuine + impostor mix is reported with its mix.
- **Rank-1 identification rate**: live (bona fide attempts whose top-1 candidate is the target) and offline
  (`comparisons.csv`: probe's best gallery subject is its own).

### 6.4 DENY cause attribution (priority order)

`system` (RATE_LIMITED, SYSTEM_ERROR) > `schedule` (deny-type SCHEDULE_* - a protocol error in PAD blocks) >
`pad` > `quality` (recaptures exhausted = failure to acquire) > `match` (NOT_ENROLLED, MATCH_*) > `fallback` > `other`.

### 6.5 RATE_LIMITED rows

The edge limiter counts attack-evidence DENYs (5 in 180 s -> 5 s lockout, `rate_limit.lockout_s`; was 60 s). Rows containing `RATE_LIMITED` are
flagged in `notes`, **excluded from APCER, BPCER and FRR**, and their count is reported (lead decision).
`capture.py` calls `POST /v1/admin/rate-limit/reset` at start, at every plan block change and, by default,
before every attempt: at ~20 s per attempt an attack block reaches 5 attack DENYs inside 180 s, so a reset only
between blocks would still lock out later attempts of the same block. The handling (`--reset-rate-limit
attempt|block|never`, plus `rate_limit.enabled` from the config and the edge's limiter state at start) is recorded
in the run manifest `rate_limit_handling` and in the `RUN_INFO.md` capture-run table.

### 6.6 Face matcher (offline cross-matching, `comparisons.csv`)

- `collect_faces.py` stores consented photos in `eval/captures/` (gitignored, deleted after the event);
  `compare.py` embeds them with the **same** edge pipeline (`edge.ml.detect` + `align112` +
  `edge.ml.matcher.ArcFaceEmbedder`, w600k_r50) and scores **max cosine over the subject's enrolment templates**
  (as the edge's 1:N search does). Genuine = probe vs own templates; impostor = probe vs every other subject.
- Pairs are labelled `dev` (both subjects dev), `test` (both test) or `cross` (reported as supplementary only).
- LFW padding (optional, `source = lfw`): Labeled Faces in the Wild, UMass Amherst (vis-www.cs.umass.edu/lfw),
  public-figure web images, no formal licence - research use only; identities split dev/test by hash.
- **FMR / FNMR at the operating threshold** = `match.local.allow_min_cosine` from `config/thresholds.yaml`
  (online; offline override reported too), test split, accept rule `score >= threshold`, CP bounds.
  The headline (`at_configured_online_live`, and the HID FAR row) uses **live impostors only**; the pooled
  value with LFW padding is reported next to it, never instead of it.
- **Dependence**: one probe image is compared with every other gallery subject, so impostor comparisons are
  not independent Bernoulli trials and the CP bound on comparisons is optimistic. `metrics.py` reports
  `impostor_units_live` (comparisons, probe images, subject pairs), a subject-pair-level FMR (a pair is a false
  match if any of its comparisons is >= threshold) and gates `fmr_claim_supportable` on the number of distinct
  **unordered** live impostor subject pairs ({A,B} counted once; >= 1,497 at 0 errors), with the basis spelled
  out in `fmr_claim_basis`. The HID FAR row takes its status from the subject-pair-level FMR, never from the
  comparison-level CP bound (shown for information only). The face-auth accuracy (FNMR) row uses live genuine
  comparisons only; probe images of one subject are not independent, so its lower bound is optimistic.
- **Calibration (DECISION_POLICY 3.5)**: suggested `allow_min_cosine` = 99.8th percentile (numpy linear) of the
  **dev** impostor scores, with N; flagged if N < 500 (the percentile is then not resolvable below the max).
  Offline suggestion = calibrated + `offline.match_offline_delta`. FMR/FNMR at the calibrated value are then
  reported on **test** (never re-derived on test). EER and DET (normal-deviate axes) for test, dev in gray.

### 6.7 Live transaction FAR

Attacks reaching final ALLOW / all attack presentations (skill definition; equals IAPMR when attacks target
enrolled ids) and, if run, zero-effort impostors reaching ALLOW. 0/N is reported as "< 3/N".

### 6.8 Decision time

- **Decision time = client face lock -> decision rendered** (`client_latency_ms` from the kiosk beacon
  `POST /v1/attempt/{id}/rendered`, joined from the SSE `rendered` event; first beacon = first decision screen).
  This is the number for the 2 s claim. The server `latency_ms.total` is always reported next to it and is never
  presented as decision time.
- SLA scope: bona fide attempts whose **first** decision is ALLOW (ALLOW path), per mode and overall:
  p50, p95, max, fraction <= 2,000 ms (`latency_budget_ms.total_decision`) with its CP lower bound.
- Also: all first decisions; **per species x final decision**; server stages (total, liveness, match,
  schedule, policy); step-up "verification time" separately.
- CIs: percentile bootstrap, 2,000 resamples, seed 20261114, numpy linear quantiles; cells with n < 20 are LOW_N.
- Measured on the demo laptop and venue network only; re-measured after feature freeze.

## 7. Data files (`eval/results/` holds real runs only; DUMMY fixtures live in `eval/tests/fixtures/`)

Privacy: no images, crops, embeddings, names or tokens in any results file (`capture.py` whitelists fields and
strips blobs; `metrics.py` rejects blob-like values and forbidden column names). Consented photos and their
embedding cache live only in `eval/captures/` (gitignored) and are deleted after the event
(`collect_faces.py purge --yes`). India DPDP Act 2023: consent, purpose limitation, storage limitation.

### 7.1 `attempts.csv` - one row per transaction (written by `capture.py` only)

| Column | Content |
|---|---|
| `run_id` | capture session id; `results/runs/<run_id>.json` holds the command, edge health, thresholds sha256 |
| `plan_seq` | plan row number (`f<n>` flags mode, `i<n>` interactive) |
| `ts_utc` | ISO-8601 UTC with ms and `Z` (the skill's `timestamp`) |
| `split` | dev / test, from `subjects.csv` |
| `subject_id` | presenter (bona fide) or targeted enrolled identity (attack) |
| `target_user_id` | the subject's enrolled edge user id |
| `attempt_class` | genuine / zero_effort / attack / injection |
| `species` | PAI species (section 4) |
| `label` | coarse edge eval label derived from species |
| `condition` | edge eval-context condition (normal/dim/backlit/far) derived from lighting + distance |
| `lighting`, `distance` | office/backlit/dim; near/mid/far |
| `zone`, `kiosk_id`, `operator` | from the event or flags |
| `scenario` | POLICY_TEST_CASES id for SC1/SC2 live demonstrations (row excluded from PAD metrics); empty otherwise |
| `attempt_id` | edge attempt id (root of a recapture chain); `noresp_*` for NO_RESPONSE |
| `decision` | **final** decision: ALLOW / STEP_UP / DENY / NO_RESPONSE |
| `reason_codes` | final reason codes, `;`-joined |
| `stage`, `bio_result`, `schedule_result`, `mode`, `cache_state` | from the decision events (mode from the response, never the operator) |
| `candidate_user_id` | top-1 candidate (pseudonymous id) |
| `liveness_result`, `liveness_result_source` | PAD-level PASS/UNSURE/FAIL/NOT_EVALUATED/UNKNOWN; derived or explicit (6.1) |
| `first_decision`, `first_reason_codes`, `first_stage` | first decision of the attempt (pre step-up) |
| `next_action_type`, `stepup_methods` | first STEP_UP's next action (CHALLENGE, SECOND_FACTOR, RECAPTURE...) and methods |
| `stepup_outcome` | none / passed / failed / unresolved |
| `stepup_rounds`, `recaptures`, `stepup_ms` | STEP_UP events, RECAPTURE prompts, first -> final decision time |
| `resolved_codes` | step-up triggers resolved on ALLOW |
| `latency_ms`, `latency_source` | decision time (6.8): `kiosk_render` = client face lock -> rendered (the slide number); `edge_face_lock_to_decision` = server-side face lock -> decision (`latency_ms.face_lock_to_decision_server`, excludes the render) when no beacon arrived; `none` otherwise. `metrics.py` uses one source only (kiosk_render if any row has it) and counts the others as rows without decision time |
| `lat_server_total_ms`, `lat_liveness_ms`, `lat_match_ms`, `lat_schedule_ms`, `lat_policy_ms` | server spans of the first decision |
| `s_pad`, `s_pad_pass_frames`, `s_flash_r`, `s_flash_amp`, `s_moire`, `s_device_conf`, `s_depth`, `s_match`, `s_match_margin`, `s_rekognition` | key scalar scores of the first evaluated decision |
| `scores` | JSON of the skill's 6.1 keys (pad, pad_label, flash_r, moire, device_conf, match, first_decision, t_pad, t_match) - derived, scalars only |
| `eval_label_echo` | the edge's `eval.label` tag (cross-checked; mismatches flagged as `EVAL_TAG_MISMATCH(...)` in notes) |
| `policy_version`, `bundle_version`, `events` | provenance; number of decision events joined |
| `notes` | flags: RATE_LIMITED, EVAL_TAGS_MISSING, EVAL_TAG_MISMATCH, no_render_event, chain:..., stepup_*, dup_dropped:<id>(<decision>) (5.6), eval_tags_not_in_poll_response, POLL_MISSED_STEPUP(...) (5.5), mode_changed:... |
| `face_lock_at_ms` | kiosk epoch ms of the face lock, from the `rendered` event (empty without a beacon); used for de-duplication (5.6). v2 column, optional when reading older files |
| `s_mask_ring` | RGB eye-hole / outline ring score of the first evaluated decision (`scores.mask.m2_ring`; mask M2, enforced at 0.50 / 0.75). v2 column, optional when reading older files |
| `signals` | fused per-signal status of the first evaluated decision, `key=STATUS;...` for `pad, device, moire, flash, mask, depth, injection` (`scores.signals`: PASS, PASS_AMBIENT, UNSURE, FAIL, NOT_AVAILABLE, ADVISORY_<zone>); input of `calibrate.py`. v2 column, optional when reading older files |

### 7.2 Other files

| File | Written by | Content |
|---|---|---|
| `comparisons.csv` | `compare.py` | `probe_attempt_id, probe_subject, gallery_subject, matcher, score, genuine, split, source` (skill 6.2) + `run_id, model, gallery_template, probe_lighting`; no embeddings |
| `scenarios.csv` | `scenarios/run_scenarios.py` | `run_id, ts_utc, scenario_id, challenge, title, backend, status (PASS/FAIL/NOT_RUN/BLOCKED/ERROR), expected, observed_decision, observed_codes, detail, policy_case` |
| `exclusions.csv` | operator (by hand, the only hand-edited file) | `attempt_id, reason, excluded_by, ts_utc` |
| `runs/<run_id>.json` | every tool | command line, host, inputs and their sha256, counts; capture runs add `shipped_switches`, `edge_config_diff`, `rate_limit_handling`, `transport_used`, `poll_calls`, `duplicates_dropped` + `duplicates[]` |
| `runs/snapshot_<ts>/` | `snapshot_metrics.py` (read-only GETs) | `edge_metrics.json` (`GET /v1/metrics`), `edge_mode.json`, `edge_health.json`, `attempts.json` (whitelisted `GET /v1/attempt/{id}` fields for the run's attempt ids), `SNAPSHOT.md` (switches, edge-vs-config diff, edge decision vs CSV final decision per attempt). Provenance only, not an eval result |
| `calibration/CALIBRATION_<split>.md` + `.json` | `calibrate.py` | per-signal distributions (min / p05 / p25 / p50 / p75 / p95 / max) bona fide vs each attack species, k/N on the wrong side of every configured bar with the 95% UB, `signals` status counts. Descriptive, never a threshold suggestion; on `test` labelled "do not tune" |
| `metrics.json` | `metrics.py` | everything in section 6 + `RUN_INFO` (thresholds sha256, policy_version, inputs, exclusions, warnings) |
| `det_*.png` (+ `_dark`) | `metrics.py` | matcher DET (test vs dev), PAD DET small multiples |
| `RUN_INFO.md` | `metrics.py` (auto block) + operator (manual block) | date, hardware, camera, thresholds hash, subjects per split, deviations |
| `SUMMARY.md`, `dashboard.json`, `*.png` | `summary.py` | slide-ready tables + charts, `/v1/metrics`-shaped JSON for the dashboard |

## 8. SC1 / SC2 scenario gate

The gate is keyed by the normative IDs of `docs/POLICY_TEST_CASES.md` (lead decision): section 5 (S01-S32) = SC1;
sections 6 (O01-O29) and 7 (X, D, Y) = SC2. `scenarios/cases.py` parses expected decisions and codes from that
document at run time. `scenarios/run_scenarios.py` records one row per ID in `scenarios.csv`:

| Backend | IDs | How |
|---|---|---|
| `pytest` | all gate IDs | runs the edge (and cloud, if its venv exists) pytest suites with JUnit XML; an ID is PASS if every test whose name contains the ID passed, FAIL if any failed, NOT_RUN if no test references it |
| `store` | D01-D03 | inspects the edge offline store file: no plaintext JSON payloads, no user ids / names / JPEG markers in the raw bytes |
| `api` | X06 (partial; + X07 only when records were queued) | Reads `GET /v1/mode` first; if an operator already forced OFFLINE it does not toggle (X06/X07 NOT_RUN "edge already forced OFFLINE by an operator; not toggled"). Otherwise `POST /v1/admin/mode` force OFFLINE (reason, `max_minutes` auto-revert), polls `GET /v1/mode` (mode, `forced`, `sync_queue_depth`), then AUTO. X06 is NOT_RUN (partial) when the badge is right and FAIL when it is wrong or slower than 3 s: next-attempt OFFLINE_MODE and background heartbeats are not exercised (the tool never drives attempts on the live kiosk). AUTO is always restored once the OFFLINE POST was sent, even if it timed out. X02 / X04 are never recorded from a forced toggle |
| `live` | demo IDs (`Q01`, `S04`, `S01`/`S02`, `S13`, `O01`, `O04`/`O06`, `O17`, `L01`, `L05`) | operator runs them on the kiosk with `capture.py --scenario <ID>`; metrics compares the logged final decision with the document |

Pass/fail is only ever taken from a recorded run; an ID without one is reported `NOT_RUN`. The H5 checkpoint
needs every gate ID PASS on `pytest` plus at least one live run of the demo IDs.

## 9. Commands

```bash
cd eval
uv run pytest                                              # metric math, schema, DET, capture (DUMMY only)
uv run python plan.py subjects --ids S01,S02,S03,S04,S05   # then fill enrolled_user_id + consent=yes
uv run python plan.py schedule --split dev  --target-genuine 30 --target-per-species 10 --out plans/dev_plan.csv
uv run python plan.py schedule --split test --out plans/test_plan.csv
uv run python capture.py --plan plans/dev_plan.csv  --run-id R-dev-1  --operator E
#   tune on dev -> thresholds.yaml (policy-engine owner) -> freeze
uv run python capture.py --plan plans/test_plan.csv --run-id R-test-1 --operator E
../edge/.venv/bin/python collect_faces.py webcam --subject S01 --n 12 --lighting office --consent-confirmed
../edge/.venv/bin/python compare.py --out results/comparisons.csv
uv run python scenarios/run_scenarios.py --backend pytest       # no credential needed
FG_OPS_API_KEY=... uv run python scenarios/run_scenarios.py --backend store   # D01-D03 (store:read)
uv run python metrics.py                                   # -> results/metrics.json, det_*.png, RUN_INFO.md
uv run python summary.py                                   # -> results/SUMMARY.md, dashboard.json, charts
uv run python snapshot_metrics.py --attempts results/attempts.csv --run-id R-test-1   # edge aggregates (metrics:read)
uv run python calibrate.py --split dev                     # -> results/calibration/CALIBRATION_dev.md
```

Dry runs (DUMMY fixtures, never into `results/`):
`uv run python snapshot_metrics.py --fixture tests/fixtures/edge_snapshot_DUMMY.json --attempts tests/fixtures/attempts_DUMMY.csv --run-id DUMMY-R1 --out-root /tmp/snap`;
`uv run python calibrate.py --attempts tests/fixtures/attempts_DUMMY.csv --exclusions tests/fixtures/exclusions_DUMMY.csv --split test --out-dir /tmp/calib`.

Edge latency (scratch edge, never :8000; provisions its own 1-day evaluator+enroller key, `--auth legacy` for a
random scratch ADMIN_TOKEN instead): `edge/.venv/bin/python scripts/bench_latency.py --runs 40 --port 8096`
(from the project root). Curl smoke: `EDGE_URL=http://127.0.0.1:<scratch port> scripts/smoke_edge.sh`
(port 8000 refused unless `SMOKE_LIVE=1`, 8001 always refused; the URL is parsed, so `:08000` or `:8000?x` count as 8000).

Credentials (all commands above): capture.py and snapshot_metrics.py need `FG_EVAL_API_KEY`, run_scenarios.py
`--backend store|api` needs `FG_OPS_API_KEY` (pre-flight item 2); exit code 5 = credential missing or refused.

DUMMY demo (never written into `results/`):
`uv run python metrics.py --attempts tests/fixtures/attempts_DUMMY.csv --comparisons tests/fixtures/comparisons_DUMMY.csv --scenarios tests/fixtures/scenarios_DUMMY.csv --exclusions tests/fixtures/exclusions_DUMMY.csv --out-dir /tmp/eval_dummy`

## 10. Known limits and open points

- Team-sourced, small cohort; per-species N of 30 bounds APCER only below ~9.5 % at 0 errors (3/N ~ 10 %).
- 0.2 % FAR / 0.6 % FRR cannot be confirmed live today; matcher FMR is supported only with >= 1,497
  independent unordered live impostor subject pairs (test split; 6.6) and only for the local ArcFace matcher
  (Rekognition not cross-matched).
- The skill's SC tables (S1-x / S2-x) are superseded by POLICY_TEST_CASES IDs; documented heartbeat detection is
  about 15-17 s (3 misses x 5 s), not the 5 s mentioned in older demo text.
- Licences: InsightFace w600k_r50 (buffalo_l) recognition weights are non-commercial research only;
  MiniFASNet is Apache-2.0.
- Online identity uses Rekognition (`match.rekognition.enabled: true`) next to the local matcher; offline FMR /
  FNMR in `comparisons.csv` are for the local ArcFace matcher only unless `compare.py` is extended.

## 11. REDUCED ~45-minute operator plan (3 enrolled team members)

Status: **designed, not run.** No eval numbers exist yet. Until it runs, the only citable latency is the dev
measurement (n = 32, offline, MacBook webcam): face lock -> rendered p50 1518 / p95 1559 ms, edge total p50 127 /
p95 154 ms, labelled "dev measurement".

Design choices (state them next to the numbers):

- Subjects: `S01` = `u_prj1`, `S02` = `u_tm02`, `S03` = `u_tm03` (the three users already enrolled on the live
  edge; names are never written into any file). All three are in **`test`**: the thresholds are **frozen at the
  shipped configuration** (operator decision: keep moire 0.40 / 0.70 + M2 0.50 / 0.75 enforced, flash advisory,
  random_rate 0.15 / 0.30, lockout 5 s, Rekognition on), so nothing is tuned and every number is held-out.
  `calibrate.py --split test` is therefore **descriptive only**; any threshold changed after reading it needs a new
  capture before a number is reported.
- Volumes (`plan.py reduced`, seed 20261114): bona fide 40 (office 28 + dim 12, spread over S01-S03), print 15,
  phone_photo 15, phone_video 15, print_eyecut 10 (attacks target S01-S03 round-robin; `--attack-targets S01` if
  only one subject's artefacts exist). Attacks and most genuine attempts are interleaved in one office block
  (never > 3 of one class in a row); the dim block is bona fide only. 95 attempts at ~20 s = ~32 min.
- FAR / FRR: `collect_faces.py` (3 enrol + 30 probes per subject) + `compare.py` -> 90 genuine and 180 impostor
  comparisons at the configured `match.local.allow_min_cosine` (local ArcFace matcher).

Bounds it can support (one-sided 95 %; printed by `plan.py reduced`; report `k/N (95% UB)`, never a point claim):

| cell | N | 0 errors: rule of 3 | 0 errors: exact UB | 1 error: CP UB |
|---|---|---|---|---|
| BPCER, bona fide all | 40 | < 7.50% | < 7.22% | 11.32% |
| BPCER office / dim | 28 / 12 | < 10.72% / < 25.00% | < 10.15% / < 22.10% | 15.86% / 33.87% |
| APCER print, phone_photo, phone_video (each) | 15 | < 20.00% | < 18.11% | 27.94% |
| APCER print_eyecut | 10 | < 30.00% | < 25.89% | 39.42% |
| attacks pooled (supplementary; headline = max per species) | 55 | < 5.46% | < 5.31% | 8.34% |
| FNMR (genuine comparisons) | 90 | < 3.34% | < 3.28% | 5.17% |
| FMR (impostor comparisons) | 180 | < 1.67% | < 1.66% | 2.61% |

It **cannot** confirm HID's FAR 0.2 % (needs 1,497 error-free impostor comparisons) or FRR 0.6 % (498 error-free
genuine transactions), nor APCER <= 5 % per species (59 per species). Say so on the slide. phone_photo /
phone_video APCER is measured **without** the colour flash (advisory).

Checklist and exact commands (from `eval/`):

1. Pre-flight (~5 min)
   - [ ] `curl -s 127.0.0.1:8000/v1/health | python3 -m json.tool` -> `status: ok`, PAD self-test passed.
   - [ ] `curl -s 127.0.0.1:8000/v1/mode | python3 -m json.tool` -> `ONLINE`, `kiosk_id KIOSK_MAIN_01`,
         `zone MAIN_GATE`, `template_cache.count 3`, `policy_version` equal to `config/thresholds.yaml`
         (if not, the lead restarts the edge first - capture.py prints the difference as a WARNING).
   - [ ] `uv run python plan.py reduced --write-subjects --out plans/reduced_plan.csv`
   - [ ] Ask each person for consent; set `consent=yes` for S01-S03 in `subjects.csv` (capture refuses otherwise).
   - [ ] Only one kiosk client submits frames (duplicates are dropped and counted anyway, 5.6).
   - [ ] Artefacts ready: A4 colour print per target, eye-cut print (worn by a different team member), photo and
         blink/smile video of each target on the phone at full brightness.
2. Schedule check (~1 min; logged as scenario rows, excluded from PAD metrics):
   `uv run python capture.py --subject S01 --species bona_fide --scenario Q01 --count 1 --run-id R-red-pre --operator PM --zone MAIN_GATE --kiosk-id KIOSK_MAIN_01`
   (repeat for S02, S03). Each must end `ACCESS_OK`; a `SCHEDULE_*` deny means the window is closed - stop.
3. Capture (~32 min): `uv run python capture.py --plan plans/reduced_plan.csv --run-id R-red-1 --operator PM --zone MAIN_GATE --kiosk-id KIOSK_MAIN_01`
   - limiter reset before every attempt (default `--reset-rate-limit attempt`), recorded in the manifest.
   - switch the room to `dim` when capture.py prints the block change.
   - `x` = operator error before the decision (redo), never edit the CSV afterwards (exclusions.csv).
4. Snapshot (~1 min): `uv run python snapshot_metrics.py --attempts results/attempts.csv --run-id R-red-1`
5. FAR / FRR photos (~6 min, after capture so the kiosk is idle), per subject S01, S02, S03:
   `../edge/.venv/bin/python collect_faces.py webcam --subject S01 --n 3 --role enrol --consent-confirmed --operator PM`
   `../edge/.venv/bin/python collect_faces.py webcam --subject S01 --n 20 --lighting office --consent-confirmed --operator PM`
   `../edge/.venv/bin/python collect_faces.py webcam --subject S01 --n 10 --lighting dim --consent-confirmed --operator PM`
   then `../edge/.venv/bin/python compare.py --run-id C-red-1`
6. Analysis (~2 min): `uv run python metrics.py && uv run python summary.py && uv run python calibrate.py --split test --out-dir results/calibration_test`
7. Fill the manual block of `results/RUN_INFO.md` (hardware, camera, lighting, deviations). After the event:
   `../edge/.venv/bin/python collect_faces.py purge --yes` and `DELETE /v1/enroll/{user_id}` for the three users.
