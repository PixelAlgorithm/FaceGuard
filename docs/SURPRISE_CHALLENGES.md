# SURPRISE_CHALLENGES.md — SC1 (Campus Schedule) and SC2 (Offline Safe Access)

Normative decision logic lives in `docs/DECISION_POLICY.md` (matrix §9, pseudocode §11). This file is
the design + rationale, mapped bullet-by-bullet to the brief (`docs/images/05_surprise_challenges.png`).
Numbers come from `config/thresholds.yaml`; the schedule format is `config/schedule.example.json` (test
fixture); the demo schedule is `config/schedule.demo.json`. The bundle installed on the live edge is the
**cloud-issued v45**, built from the cloud's copy of that file and filtered to `KIOSK_MAIN_01` / MAIN_GATE
(`scripts/sign_bundle.py` now signs installed version + 1 by default, but a default re-sign drops the documented demo
card hashes unless `--demo-cards` and overwrites `edge/data/DEMO_CODES.txt`, so do not re-run it with its defaults
while v45 is installed).
All local times are `Asia/Kolkata` (IST, UTC+05:30); stored timestamps are UTC ISO-8601.

---

## SC1 — Access with Campus Schedule

> "A live, recognized person is not automatically authorized. The system must combine the biometric
> result with the campus access schedule and return one of the following decisions:
> ALLOW / STEP-UP VERIFICATION / DENY." (BIOMETRIC RESULT + CAMPUS ACCESS SCHEDULE)

### SC1.1 Brief → design mapping

| Brief phrase | Our design |
|---|---|
| "A live, recognized person is not automatically authorized" | BIO_PASS alone never opens the door: `combine()` requires schedule = IN_WINDOW (and, for high-risk zones, a second factor). |
| "combine the biometric result" | Biometric pipeline emits exactly one of `BIO_PASS / BIO_UNSURE / BIO_FAIL` + candidate `user_id` (DECISION_POLICY §4). |
| "with the campus access schedule" | Signed schedule bundle: roles × zones × weekly windows, exceptions, holidays, visitor passes, per-user overrides, revocations (SC1.2). Evaluated by one pure function `evaluate_schedule(user_id, zone, t0, bundle)` (`edge/policy/schedule.py`) on the last valid (verified) bundle + revocation feed in **both** modes — no per-attempt cloud schedule call (SC1.7); the cloud runs the same function to build bundles and to re-evaluate offline decisions at sync. |
| "return one of ALLOW / STEP-UP / DENY" | Decision matrix DECISION_POLICY §9.2; every combination maps to exactly one decision + reason codes + `next_action`. |

### SC1.2 Schedule model

```
bundle
 ├─ zones{ZONE: {risk: low|medium|high, requires_explicit_grant: bool}}
 │     MAIN_GATE low · LIBRARY low · LAB_BLOCK medium · HOSTEL medium · SERVER_ROOM high (explicit grant)
 ├─ kiosks{KIOSK_ID: {zone}}                       one kiosk = one zone (entry point)
 ├─ roles{student|faculty|staff|contractor|visitor: {zones[], windows{ZONE: [ {days[], start, end} ]}}}
 ├─ exceptions[]  date-bounded: {id, name, date_from, date_to, roles[], zones[], mode: add|replace|close,
 │                windows[], overrides_holiday}
 ├─ holidays[]    {date, name, closed_zones[] | "ALL", exempt_roles[]}
 ├─ visitor_passes[] {pass_id, user_id, host_user_id, valid_from, valid_until, zones[], windows[]?}
 ├─ users{user_id: {display, role, zones_add[], zones_remove[], extra_windows{ZONE: [...]},
 │                  valid_from?, valid_until?, revoked, revoked_at?, fallback{totp_enrolled, card_id_hash}}}
 ├─ revocations[] {user_id, revoked_at, reason}
 ├─ override_codes[] (hashed, for SC2 fallback)
 └─ metadata: format_version, bundle_version, issued_at, expires_at, timezone, signature{alg, key_id, value}
```

Window semantics: `days` ⊆ {MON..SUN}; `start ≤ t < end`; `end` may be `"24:00"`; `end < start`
means the window crosses midnight and belongs to the day it starts on (so evaluation also looks at
yesterday's windows). Dates in exceptions/holidays are local calendar dates, inclusive.
**Grace never crosses midnight on its own:** yesterday's windows are included only when the window
itself crosses midnight (`end < start`). A window ending at `"24:00"` (or 23:50) therefore has no
end-grace on the next date (Thu 00:05 after Wed 06:00–24:00 → `OUTSIDE_WINDOW`), and a window starting
at 00:00–00:14 has no start-grace on the previous evening. This is the more restrictive reading and is
what `edge/policy/schedule.py` implements (tests S51–S52).

**Permitted zones** for user u = (`role.zones` ∪ `u.zones_add` ∪ zones of an active visitor pass) −
`u.zones_remove`; a zone with `requires_explicit_grant` is permitted only via `zones_add` (role
membership is not enough — not every staff member gets the server room).

**Windows** for (u, zone, local date d): role windows for the weekday → apply active exceptions for
u's role & zone in list order (`add` unions, `replace` replaces, `close` empties) → union
`u.extra_windows` (personal overrides apply last) → for visitors, the pass `windows` (or role windows)
clipped to the pass validity.

### SC1.3 Evaluation algorithm (precedence = most restrictive first)

```python
def evaluate_schedule(user_id, zone, t0, bundle, T, *, revocation_slack_s=0) -> str:
    u = bundle.users.get(user_id)
    t = t0.astimezone(ZoneInfo("Asia/Kolkata")); d = t.date()
    # FIRST; time-aware (SC2.6 rule 3). Live edge: slack = cache.clock_rollback_tolerance_s (300 s, F03);
    # the cloud re-evaluation passes 0.
    if revoked_at_or_before(bundle, user_id, u, t0 + revocation_slack_s): return "REVOKED"
    if u is None:                                             return "NO_ENTITLEMENT"   # enrolled, no schedule record
    if not within(u.valid_from, u.valid_until, t0):           return "NO_ENTITLEMENT"   # contract/graduation
    vp = bundle.active_visitor_pass(user_id, t0)
    if u.role == "visitor" and vp is None:                    return "NO_ENTITLEMENT"   # no valid pass now
    if zone.id not in permitted_zones(u, vp, bundle):         return "ZONE_NOT_PERMITTED"
    if holiday_applies(bundle, u.role, zone, d):              return "HOLIDAY"   # not exempt, no overriding exception
    # a crossing window (end < start) belongs to its START day; a holiday on that day closes its tail too (F02)
    if holiday_applies(bundle, u.role, zone, d - timedelta(days=1)) and any(
            w.contains(t) for w in windows_for(u, zone, d - timedelta(days=1), bundle, crossing_only=True)):
                                                              return "HOLIDAY"
    windows = windows_for(u, zone, d, bundle)
    if not holiday_applies(bundle, u.role, zone, d - timedelta(days=1)):
        windows += windows_for(u, zone, d - timedelta(days=1), bundle, crossing_only=True)   # end < start only
    if any(w.contains(t) for w in windows):                   return "IN_WINDOW"
    g = T.grace_minutes_high_risk if zone.risk == "high" else T.grace_minutes      # 0 / 15
    if g and any(w.start - g <= t < w.start or w.end <= t < w.end + g for w in windows):
                                                              return "GRACE_WINDOW"
    return "OUTSIDE_WINDOW"
```

`revoked_at_or_before` is true iff some revocation for the user — a `revocations[]` entry (the edge
merges the cloud revocation feed into this list), or the user's own `revoked` flag — has `revoked_at` ≤
`t0` (+ the slack below); a revocation without (or with an unparsable) timestamp counts as always revoked.

- **Revocation slack (F03, live edge decisions only).** The edge calls `evaluate_schedule` with
  `revocation_slack_s` = `cache.clock_rollback_tolerance_s` (300 s; `edge/policy/engine.py`,
  `PolicyRuntime._revocation_slack_s`, also for the gallery filter `entitled_user_ids`). A revocation the edge
  already holds counts when `revoked_at` ≤ `t0` + 300 s, so an edge clock up to 300 s behind the cloud cannot
  ignore it. The slack only adds revocations. The cloud's re-evaluation at sync keeps the strict default 0.
- **Holiday and midnight-crossing windows (F02).** A holiday on a crossing window's start day closes the whole
  window, its part after midnight included: `t0` in that tail → `HOLIDAY`, and the tail gives no grace. The
  same window on a normal day still crosses midnight (`edge/policy/schedule.py` `_crossing_from`).
- **Clock rollback (F04).** With the cache `INVALID` by clock rollback the edge does not call
  `evaluate_schedule`. It still runs a deny-only check: any revocation it holds for the candidate, whatever its
  `revoked_at` (`schedule.revoked_any`), gives `DENY` `SCHEDULE_REVOKED` + `SCHEDULE_BUNDLE_INVALID` +
  `OFFLINE_MODE`, CONTACT_DESK (DECISION_POLICY §9.5 I4). Without such a revocation the rollback rule of
  SC2.3 applies (STAFF_OVERRIDE only). **REVOKED takes
precedence over everything**, including users absent from `users{}`. The same time-aware rule is used
by the server when it re-evaluates at sync, so a revocation effective after an offline ALLOW does not
flag it (Y04). Because revoked users' templates are purged from the kiosk gallery at refresh, a revoked
user matched only by the local matcher (offline, or Rekognition disabled) normally gets `NOT_ENROLLED`
before the schedule is ever consulted; `SCHEDULE_REVOKED` appears when Rekognition identifies her
online, or when the revocation reached the kiosk before her template was purged.

Visitor validity: a pass's `valid_until` is a hard edge — grace never extends a pass (validity is
checked before windows).

### SC1.4 Combination rules (biometric × schedule)

| Biometric | IN_WINDOW | GRACE_WINDOW | OUTSIDE / NO_ENTITLEMENT / ZONE_NOT_PERMITTED / HOLIDAY / REVOKED |
|---|---|---|---|
| BIO_PASS | **ALLOW** (high-risk zone: STEP_UP second factor — configurable `schedule.high_risk_requires_stepup_online`, default true) | STEP_UP (second factor) | DENY |
| BIO_UNSURE | STEP_UP (challenge and/or second factor per cause) | DENY | DENY |
| BIO_FAIL | DENY (schedule not evaluated) | DENY | DENY |

Spoof evidence is **always DENY regardless of schedule** (P2). Rationale for the two non-obvious cells:
- **BIO_PASS + GRACE → STEP_UP**: a person 10 minutes early is probably legitimate; a second factor
  (TOTP/card) confirms intent and identity instead of hard-denying, while the log shows the exception.
- **BIO_UNSURE + GRACE/OUTSIDE → DENY**: making someone do a challenge that cannot end in ALLOW is
  bad UX, and stacking two uncertainties (identity/liveness *and* time) is exactly the risky case.
- **High-risk + IN_WINDOW → STEP_UP**: server room access is rare and valuable; one extra factor costs
  seconds. Grace for high-risk zones is 0.
- **Random deformation challenge (on)**: BIO_PASS + IN_WINDOW becomes STEP_UP CHALLENGE
  (`RANDOM_CHALLENGE`) with probability `challenge.random_rate`: **0.15 online / 0.30 offline** (restored
  2026-11-14 at the operator's request). The challenge is one of SMILE / OPEN_MOUTH plus one of BLINK /
  TURN_LEFT / TURN_RIGHT. Random deformation challenges *raise the bar* for rigid 3D masks; silicone masks
  remain a known RGB limit; depth M1 helps once depth is enabled (H4 not run yet). Demo control:
  `POST /v1/admin/random-challenge` (`DEMO_MODE=1`, permission `challenge:control`: roles `admin`, `evaluator`) with `FORCE_NEXT` (stays armed until a
  would-be ALLOW uses it, then `AUTO`), `FORCE`, `OFF` or `AUTO`; a forced draw fires whatever the rate.
  The mode is in memory (edge restart → `AUTO`).
- **No identity at all** (quality still failing after 2 recaptures): the injection check still runs (an
  injected stream is DENYed, row A4). Otherwise the schedule cannot be evaluated, so a low/medium-risk
  door offers manual review by desk staff (STAFF_OVERRIDE); a high-risk door (or a kiosk with no valid
  bundle) DENYs (`CONTACT_DESK`). DECISION_POLICY rows A3 / A6. A3 is not a schedule decision: the kiosk
  shows "Please see the desk staff for a manual check", the guard checks the person's entitlement, and
  every A3 ALLOW raises `ALERT_OVERRIDE_USED` at sync (P8).
- The kiosk labels the middle outcome **"REQUEST VERIFICATION"** (subtitle "step-up"); the API enum is `STEP_UP`.

### SC1.5 Why the schedule is evaluated *after* biometrics

1. **No entitlement oracle.** If schedule ran first, a spoofer holding a photo of user X could learn
   whether X has access *now* from the response (DENY-outside-window vs step-up). With biometrics first,
   every spoof gets the same `SPOOF_*` DENY irrespective of X's schedule.
2. **Spoof is never "excused" or "masked" by schedule.** A spoof of a revoked user is logged as a
   spoof (`SPOOF_DEVICE_DETECTED`), which is the security-relevant fact, not as `SCHEDULE_REVOKED`.
3. **Schedule needs an identity**, which only exists after matching; for BIO_UNSURE we use the top-1
   candidate and show only a generic message ("please contact the desk") so no schedule detail leaks to
   an unconfirmed person.
4. **Still logged.** The BIO_FAIL record keeps `candidate_user_id` (pseudonymous) so the cloud can
   alert "targeted spoof attempt against u_3c4d at KIOSK_LIB_01", and for BIO_PASS/UNSURE the
   `schedule_result` + `bundle_version` are logged with every decision.
5. **Cheap anyway**: schedule evaluation is < 1 ms on the locally cached signed bundle, online and
   offline (no cloud round trip on the 2 s path), so ordering costs nothing.

### SC1.6 Worked examples (data = `config/schedule.example.json`; 14 Nov 2026 is a Saturday)

These use the test fixture's users and zones. The live bundle v45 covers only `KIOSK_MAIN_01` / MAIN_GATE, so
only the MAIN_GATE rows can be reproduced on the live edge (with `u_prj1`, a student like Priya and Aarav).

| # | Who (role) | Kiosk / zone | Local time | Biometric | Schedule reasoning | Decision · codes · next_action |
|---|---|---|---|---|---|---|
| 1 | Priya N. (student) `u_3c4d` | KIOSK_LIB_01 / LIBRARY | Sat 14 Nov 10:05 | BIO_PASS | student LIBRARY MON–SAT 08:00–21:00 → IN_WINDOW | **ALLOW** · `ACCESS_OK` · OPEN_DOOR |
| 2 | Priya N. | LIBRARY | Sat 14 Nov 07:50 | BIO_PASS | 10 min before 08:00, grace 15 → GRACE_WINDOW | STEP_UP · `SCHEDULE_GRACE_WINDOW` · SECOND_FACTOR[TOTP, CARD, EMAIL_OTP, STAFF_OVERRIDE]; correct TOTP → **ALLOW** · `ACCESS_OK, FALLBACK_OK` |
| 3 | Priya N. | KIOSK_LAB_01 / LAB_BLOCK | Sat 14 Nov 20:30 | BIO_PASS | base Sat 09:00–13:00, but exception `EXC-HACK-2026` adds 08:00–23:00 on 14 Nov → IN_WINDOW | **ALLOW** · `ACCESS_OK` |
| 4 | Priya N. | LAB_BLOCK | Sun 15 Nov 11:00 | BIO_PASS | no Sunday LAB_BLOCK window for students | DENY · `SCHEDULE_OUTSIDE_WINDOW` · NONE |
| 5 | Priya N. | LAB_BLOCK | Mon 16 Nov 10:00 | BIO_PASS | exam week `EXC-LABS-CLOSED-EXAM` (mode `close`) empties students' LAB_BLOCK windows 16–21 Nov | DENY · `SCHEDULE_OUTSIDE_WINDOW` |
| 6 | Priya N. | LIBRARY | Wed 18 Nov 23:30 | BIO_PASS | exam week `EXC-EXAM-NOV26` replaces LIBRARY with 06:00–24:00 | **ALLOW** · `ACCESS_OK` |
| 7 | Priya N. | KIOSK_HOSTEL_01 / HOSTEL | Sat 14 Nov 21:00 | BIO_PASS | HOSTEL not in student role zones; Priya has no `zones_add` | DENY · `SCHEDULE_ZONE_NOT_PERMITTED` · CONTACT_DESK |
| 8 | Aarav S. (student, hostel resident) `u_1a2b` | HOSTEL | Sat 14 Nov 23:10 / 23:20 | BIO_PASS | HOSTEL daily 05:00–23:00 via `zones_add`; 23:10 in grace, 23:20 beyond | 23:10 STEP_UP · `SCHEDULE_GRACE_WINDOW`; 23:20 DENY · `SCHEDULE_OUTSIDE_WINDOW` |
| 9 | Rahul V. (IT staff, server-room grant) `u_7a8b` | KIOSK_SRV_01 / SERVER_ROOM | Sat 14 Nov 10:00 | BIO_PASS | staff SERVER_ROOM is MON–FRI; exception `EXC-SRV-HACK` adds 09:00–21:00 today; zone high-risk | STEP_UP · `SCHEDULE_HIGH_RISK_ZONE` · SECOND_FACTOR[TOTP, CARD, EMAIL_OTP] → TOTP ok → **ALLOW** · `ACCESS_OK, FALLBACK_OK` |
| 10 | Dr. Meera I. (faculty) `u_5e6f` | SERVER_ROOM | Mon 16 Nov 11:00 | BIO_PASS | SERVER_ROOM requires explicit grant | DENY · `SCHEDULE_ZONE_NOT_PERMITTED` |
| 11 | Kiran P. (student, revoked 10 Nov) `u_a3b4` | KIOSK_MAIN_01 / MAIN_GATE | Sat 14 Nov 09:00 | BIO_PASS (Rekognition) | revocation (10 Nov ≤ t0) precedes everything | DENY · `SCHEDULE_REVOKED` · CONTACT_DESK (local matcher only: her template is purged → DENY · `NOT_ENROLLED`) |
| 12 | Ananya R. (visitor, judge) `u_e1f2` | LAB_BLOCK | Sat 14 Nov 15:00 / Sun 15 Nov 10:00 | BIO_PASS | pass `VP-2026-1113` valid 13 Nov 09:00 → 14 Nov 18:00, zones MAIN_GATE + LAB_BLOCK | 14 Nov **ALLOW**; 15 Nov DENY · `SCHEDULE_NO_ENTITLEMENT` |
| 13 | Suresh K. (contractor) `u_9c0d` | LAB_BLOCK | Fri 20 Nov 10:00 | BIO_PASS | "Campus Closure Day" closes LAB_BLOCK; contractors not exempt | DENY · `SCHEDULE_HOLIDAY` · NONE |
| 14 | Neha G. (library staff) `u_c5d6` vs Rahul V. (staff) | LIBRARY | Sun 15 Nov 08:00 | BIO_PASS | Neha has personal `extra_windows` LIBRARY SUN 07:00–21:00; Rahul only has staff MON–SAT | Neha **ALLOW**; Rahul DENY · `SCHEDULE_OUTSIDE_WINDOW` |
| 15 | Photo of Priya on a phone | LIBRARY | Sat 14 Nov 10:05 | BIO_FAIL | schedule **not evaluated**; candidate u_3c4d logged for alert | DENY · `SPOOF_DEVICE_DETECTED` · NONE |
| 16 | Priya, mild side light (passes the quality gate; PAD in the UNSURE band, as L03) | LIBRARY | Sat 14 Nov 10:05 | BIO_UNSURE (`LIVENESS_UNSURE`) | IN_WINDOW | STEP_UP · `LIVENESS_UNSURE` · CHALLENGE[SMILE, TURN_LEFT] → pass → **ALLOW** · `ACCESS_OK` |
| 17 | Priya, mild side light (as row 16) | LAB_BLOCK | Sun 15 Nov 11:00 | BIO_UNSURE | OUTSIDE_WINDOW | DENY · `LIVENESS_UNSURE, SCHEDULE_OUTSIDE_WINDOW` · CONTACT_DESK (no pointless challenge) |

A truly backlit face fails the quality gate first (`QUALITY_LOW_LIGHT` covers over-exposure) and gets
STEP_UP · `QUALITY_LOW_LIGHT` · RECAPTURE (A2), not rows 16–17.

Rows 1, 3, 6, 12 and 14 (ALLOW) would become STEP_UP · `RANDOM_CHALLENGE` · CHALLENGE only if the
random challenge fires (shipped rate 0.15 online / 0.30 offline, SC1.4); test vectors pin the RNG and rate
(`docs/POLICY_TEST_CASES.md` §3a). Window/grace edges for rows 1–2 and 9 are pinned in S33–S44.

### SC1.7 Online schedule source (no per-attempt cloud call)

- Online and offline both evaluate the **newest verified signed bundle** with the same function. Online
  the edge refreshes it every `cache.bundle_refresh_interval_min` = 15 min (`GET /v1/schedule/{kiosk_id}`)
  and pulls the revocation feed (`GET /v1/revocations?since=`) at every heartbeat (5 s); feed entries
  overlay the bundle, so an online revocation bites within one heartbeat.
- If the last successful refresh is older than `schedule.online_max_bundle_age_min` = 30 min (or the
  bundle is not verified / not FRESH), the attempt is treated as **OFFLINE** (P7): offline thresholds and
  the SC2.3 cache rules apply, and the public `GET /v1/mode` shows `mode` OFFLINE with `reason`
  `bundle_stale` and `cache_state` (details in `schedule_bundle` of `GET /v1/admin/mode/detail`, permission
  `store:read`: `issued_at`, `cache_state`, `refresh_age_s`, `rejected`).
- The bundle loaded at boot is not a refresh: the kiosk starts OFFLINE until the cloud confirms or
  replaces it. A bundle that fails verification (cloud fetch or a file tampered on disk) is rejected and
  never replaces the last valid bundle (SC2.2).
- Why: the sandbox cloud is in us-east-1 (Bangalore↔us-east-1 RTT ≈ 200–250 ms; production would pin
  ap-south-1 Mumbai for DPDP data residency). A serial ≈ 300 ms schedule hop would eat the 2 s budget;
  the only cloud call left on the main path is the parallel, time-boxed Rekognition search.

### SC1.8 Demo clock (showing schedule edges live)

- `POST /v1/admin/clock` (permission `demo:clock`, role `admin` only, never an API key; **`DEMO_MODE=1` only**,
  else 403 reason `NOT_DEMO_MODE`) with `{"set_local": "HH:MM"}`
  (today, IST) | `{"offset_s": n}` | `{"reset": true}`. It moves the edge wall clock used for `t0`, the
  schedule, bundle freshness and override `valid_until`; the kiosk shows a "DEMO CLOCK" badge
  (`GET /v1/mode` → `demo_clock`).
- It does **not** re-sign the bundle. A demo time earlier than the bundle's `issued_at` − 300 s reads as
  clock rollback → bundle INVALID → STAFF_OVERRIDE-only step-up (POLICY_TEST_CASES X13); a time past the
  effective expiry reads as EXPIRED. The cloud and `scripts/sign_bundle.py` stamp `issued_at` = now and
  `expires_at` = now + 12 h, so the demo uses **evening** times on a bundle issued the same day. The current cloud
  code also re-issues the same version with fresh stamps once its last issue for the kiosk is older than half the
  bundle lifetime, so read `issued_at` from `GET /v1/admin/mode/detail` right before the demo. With the
  live v45 (`issued_at` 18:00:41 IST, MAIN_GATE only) every demo-clock time must be after ~17:55:41 IST:
  MAIN_GATE (student MON–SAT 06:00–22:00, grace 15 min) at **22:10** = GRACE_WINDOW → STEP_UP, at
  **22:30** = OUTSIDE_WINDOW → DENY. Reset the clock before mode AUTO and any sync.
- TOTP always verifies against real wall time (the authenticator app on the phone), never the demo
  clock; step-up / nonce TTLs use the real wall clock (UTC, never the demo clock) and the rate limiter
  uses the real monotonic clock.
- **Reset the clock before the SC2 segment**, so offline records and sync carry real time.

---

## SC2 — Offline Mode with Safe Access

> "The kiosk loses connection to the central service. Teams must update the prototype so it can:
> Continue using a safe local decision process. Avoid unsafe automatic access. Provide fallback
> verification. Store only minimum temporary information. Synchronize decisions when the connection returns."

### SC2.0 Brief → design mapping

| Brief bullet | Our design (section) |
|---|---|
| **Continue using a safe local decision process** | Local-first architecture: the edge service *always* runs liveness (MiniFASNet, flash, moiré, device, depth) + local ArcFace matching + the same policy engine; offline it uses a cached **signed** schedule bundle and an encrypted template cache of this kiosk's users (SC2.1–SC2.2). |
| **Avoid unsafe automatic access** | Stricter offline thresholds (+0.05 PAD / flash / match / margin), ambient-flash exception off, never auto-ALLOW on UNSURE, high-risk zones never auto-ALLOW, stale bundle (> 12 h) → no automatic ALLOW, clock rollback → staff override only, no valid bundle at all → DENY + contact desk, revocation list cached (SC2.3). Random deformation challenge: a would-be ALLOW becomes a CHALLENGE with p = 0.30 offline (0.15 online, `challenge.random_rate`). |
| **Provide fallback verification** | Offline-capable factors: TOTP (RFC 6238, verified locally), staff/guard one-time override code (hashed), simulated HID card / mobile credential ID; method sets depend on zone risk and cache state (SC2.4). |
| **Store only minimum temporary information** | Log record is a fixed field whitelist (no images/crops/embeddings); pseudonymous IDs; scores rounded to 2 dp; AES-GCM encrypted SQLite; purge on sync ack, unsynced purge at 24 h with a tombstone; template cache max 72 h; hash chain for tamper evidence (SC2.5). |
| **Synchronize decisions when the connection returns** | Heartbeat hysteresis → SYNCING (offline rules) → revocations pulled → batched idempotent `POST /v1/sync` (`docs/API.md` §4.4) → server re-evaluates offline ALLOWs against authoritative schedule/revocations → alerts → local purge → refresh bundle/templates → ONLINE (SC2.6). |

### SC2.1 Connectivity detection

Owner: policy-engine (`edge/offline/connectivity.py`). Numbers from `config/thresholds.yaml` `connectivity`.

- Edge service pings the cloud `GET {CLOUD_API_URL}/v1/health` (`connectivity.health_path`) every
  **5 s** (`heartbeat_interval_s`) with a **2000 ms** timeout (`heartbeat_timeout_ms`) and, on success,
  pulls the revocation feed (`GET /v1/revocations?since=`).
- **3 consecutive misses → OFFLINE** (`misses_to_offline`): natural detection after an outage ≈ **17 s**
  when each ping has to time out (pings at ≈ 5, 10, 15 s + the last 2 s timeout, ≤ 0.5 s scheduler tick),
  ≈ 15 s when the failures are immediate (connection refused). Any cloud call that fails/times out
  during an attempt (Rekognition) also counts as a miss **and makes that attempt OFFLINE** (P7) — so the
  decision is safe even before the heartbeat flips. An online bundle whose last refresh is > 30 min old
  also makes attempts OFFLINE (SC1.7) without counting as a miss.
- **Hysteresis back:** 3 consecutive successes → `SYNCING`. **SYNCING uses the OFFLINE rules** (offline
  thresholds and method sets, `OFFLINE_MODE` on every decision; badge "RECONNECTING · syncing N"). Only
  when the sync queue is fully acknowledged **and** the bundle is refreshed (installed or confirmed) →
  `ONLINE`. A miss during SYNCING → back to OFFLINE. `CLOUD_API_URL` empty → permanently OFFLINE
  (`reason` `not_configured`).
- State is exposed in two views (`docs/API.md` §3.10). The public badge subset `GET /v1/mode` (no
  credential) → `{mode, state, reason, forced, forced_until, kiosk_id, sync_queue_depth, demo_clock,
  template_cache{count}, cache_state, cloud_match{degraded}}`. The full status `GET /v1/admin/mode/detail`
  (permission `store:read`) → `{…, since, last_cloud_ok_at, schedule_bundle{version, issued_at, expires_at,
  signature_valid, cache_state, refresh_age_s, rejected}, rate_limit, policy_bars, …}`. `mode` is the mode
  the next attempt would use (`reason` ∈ `heartbeat_timeout`, `match_timeout`, `forced`,
  `not_configured`, `bundle_stale`). The kiosk badge polls `GET /v1/mode` every **2 s**
  (`connectivity.status_poll_ms` 2000).
- Demo switches: `POST /v1/admin/mode {"force": "OFFLINE", "reason"?, "max_minutes"?}` (permission
  `mode:switch`) — takes effect **immediately** for the next attempt (heartbeats keep running underneath).
  A forced OFFLINE **auto-reverts to AUTO** after `max_minutes` (1–240; default 60,
  `connectivity.forced_offline_default_min` / `forced_offline_max_min`; real UTC, never the demo clock), shown
  as `forced_until`; only `DEMO_MODE=1` with `reason` `"DEMO"` and no `max_minutes` stays forced without a
  deadline. The Control Panel's "Force OFFLINE" button sends `{"force": "OFFLINE"}` (60 min). `{"force":
  "AUTO"}` hands control back to the heartbeat state machine (→ SYNCING at once if the last 3 heartbeats
  succeeded, else OFFLINE until they do). Env `FORCE_OFFLINE=1` starts the edge in the forced state with no
  deadline. Or physically turn off Wi-Fi (edge runs on localhost, so the kiosk keeps working; detection ≈
  15–17 s).

```
ONLINE ──3 misses──▶ OFFLINE ──3 successes──▶ SYNCING ──queue acked + bundle refreshed──▶ ONLINE
   ▲                    ▲                        │
   └────────────────────┴────── any miss ────────┘
```

### SC2.2 Local decision assets

| Asset | Content | Protection | Freshness |
|---|---|---|---|
| Schedule bundle | `config/schedule.example.json` format, filtered to this kiosk's zone + users | Signature over canonical JSON (keys sorted, `separators=(",",":")`, UTF-8, `signature` object removed). Hackathon: **HMAC-SHA256** (`SCHEDULE_BUNDLE_HMAC_KEY` in `.env`). The signature's `key_id` must equal the configured `SCHEDULE_BUNDLE_KEY_ID` (default `demo-k1`, same default as the cloud), so a rotated-out key id is refused. **Open risk:** HMAC is symmetric, so every kiosk holds the signing key and one stolen kiosk could sign a bundle for any kiosk; key-id pinning only makes rotation possible. Production: **Ed25519** (kiosk holds only the public key, so a stolen kiosk cannot forge bundles) — `alg` field selects; not built. Ordering: a candidate replaces the LVB only when its `bundle_version` is higher, or equal with a strictly later `issued_at`; **open risk:** there is no persisted anti-rollback floor at boot yet. **Last valid bundle (LVB):** a received bundle (cloud fetch, or the file changing on disk) that is unsigned / fails verification / does not cover this kiosk / is older is rejected (listed in `GET /v1/admin/mode/detail` `schedule_bundle.rejected`) and never replaces the LVB; a file tampered on disk while running is rejected and the in-memory LVB stays in force. Zone, risk and override codes always come from the LVB. No LVB at all → every non-spoof attempt DENY `SCHEDULE_BUNDLE_INVALID` · CONTACT_DESK (zone `UNKNOWN`). Signer `scripts/sign_bundle.py` stamps `issued_at` = now, `expires_at` = now + 12 h, override `valid_until` = `expires_at` + 24 h (`fallback.staff_override.valid_after_expiry_h`), so guards' codes still work for a day after the bundle expires (DECISION_POLICY §9.4). | `effective_expiry = min(expires_at, issued_at + 12 h)`; refreshed every 15 min online; online use needs last refresh ≤ 30 min (SC1.7). Within max(staleness / 2, 2 × refresh interval) of the effective expiry (6 h with the shipped config) the edge fetches without `If-None-Match`, so a re-stamped copy at the same version is always installed (SC2.6 step 4). Clock < `issued_at` − 300 s → INVALID (rollback → STAFF_OVERRIDE only). |
| Revocation list | inside the bundle (`revocations[]`, time-aware `revoked_at`) + the cloud revocation feed overlay (`GET /v1/revocations?since=`, deny-only, encrypted at rest) | bundle: same signature; feed: kiosk-authenticated cloud call. An unreadable feed file (`revocations.enc`, e.g. truncated by power loss or a foreign key) is quarantined as `*.corrupt-<ts>`; feed revocations may then be missing, so the state is marked lost (persisted, `revocations_state_lost` in `GET /v1/admin/mode/detail`): every would-be ALLOW becomes STEP_UP SECOND_FACTOR (`OFFLINE_FALLBACK_REQUIRED`) and the kiosk does not go SYNCING → ONLINE until a full feed re-pull from `since=0` has been applied | bundle: every refresh; feed: every successful heartbeat (5 s) and first step of every sync |
| Template cache | ArcFace embeddings **only for users entitled at this kiosk's zone** in the current bundle | Fernet/AES-GCM, key `EDGE_DATA_KEY` (.env / OS keychain); purged for revoked or no-longer-entitled users at each refresh, so offline a revoked user normally gets `NOT_ENROLLED` (no local template), not `SCHEDULE_REVOKED` | max age 72 h, else unusable → `NOT_ENROLLED` |
| Credential cache | per-user TOTP secrets, card-ID hashes (bundle), override-code hashes (bundle) | TOTP secrets AES-GCM encrypted, same key; never logged. An unreadable credentials file is quarantined as `*.corrupt-<ts>` (`ALERT_STATE_FILE_QUARANTINED`); TOTP is then not offered until re-provisioned, never a crash. Override hashes are only taken from the LVB — a tampered bundle cannot plant its own override code (POLICY_TEST_CASES O45); codes listed in the signed `consumed_code_ids` never match (SC2.4). | with bundle |

### SC2.3 Offline restrictions (what makes local decisions safe)

| Rule | Value | Reason code |
|---|---|---|
| PAD pass bar | 0.80 → **0.85** | — |
| Flash pass bar | r 0.70 → **0.75**; ambient-light exception **off** (flash currently ADVISORY in both modes, DECISION_POLICY §3.3) | — |
| Local match allow | cosine 0.50 → **0.55** (calibrated + 0.05); margin 0.10 → **0.15** | `MATCH_LOW` / `MATCH_AMBIGUOUS` |
| Deny thresholds | unchanged (0.30) — widening only the UNSURE band avoids extra false DENY | — |
| UNSURE | never auto-ALLOW: CHALLENGE (if liveness cause) **+ SECOND_FACTOR always** | `OFFLINE_FALLBACK_REQUIRED` |
| High-risk zone (SERVER_ROOM) | never auto-ALLOW, even BIO_PASS + IN_WINDOW; methods TOTP or STAFF_OVERRIDE (card alone is too weak) | `OFFLINE_HIGH_RISK_ZONE`, `OFFLINE_FALLBACK_REQUIRED` |
| Zone risk > `offline.auto_allow_max_risk` (medium) | treated as high-risk | same |
| Bundle EXPIRED (> 12 h) | deny-type results still DENY; IN_WINDOW/GRACE → STAFF_OVERRIDE only | `SCHEDULE_EXPIRED_CACHE` |
| Bundle INVALID — clock rollback (LVB present) | no schedule; everything non-spoof → STAFF_OVERRIDE only | `SCHEDULE_BUNDLE_INVALID` |
| No last valid bundle at all | no zone / risk / override list to trust → non-spoof attempts DENY · CONTACT_DESK, zone `UNKNOWN` | `SCHEDULE_BUNDLE_INVALID` |
| Random deformation challenge | would-be ALLOW → CHALLENGE with p = offline `challenge.random_rate` **0.30** (online 0.15); no second factor added | `RANDOM_CHALLENGE` |
| Quality still failing after 2 recaptures | low/medium zone → STAFF_OVERRIDE manual review; high-risk → DENY | quality codes + `OFFLINE_FALLBACK_REQUIRED` |
| Rate limiter | 5 attack-evidence DENYs in 180 s → **5 s** lockout (`rate_limit.lockout_s`, operator 2026-11-14), works offline too (schedule / identity / quality / `SYSTEM_ERROR` DENYs never count) | `RATE_LIMITED` |
| Offline threshold overrides | `offline.overrides` may set only the allowlisted leaves (`edge/policy/thresholds.py` `OFFLINE_OVERRIDABLE`: pass bars ≥ online, deny bars = online, enforce switches never off, ambient exception off; the challenge action pools are not overridable offline); any other leaf is a `ConfigError` at load (F08, DECISION_POLICY §3) | — |
| Lost revocation overlay (`revocations_state_lost`) | no auto-ALLOW: would-be ALLOW → SECOND_FACTOR | `OFFLINE_FALLBACK_REQUIRED` |
| Every offline decision | tagged | `OFFLINE_MODE` |

The only automatic offline ALLOW is: BIO_PASS (strict thresholds) + IN_WINDOW on a fresh, valid bundle
+ low/medium-risk zone (matrix row F1); each of those is additionally challenged at random with p = 0.30
(F9; shipped offline `challenge.random_rate`).
Rekognition, email OTP and Face Liveness are unavailable offline.

### SC2.4 Fallback verification (works with zero connectivity)

| Method | How it works offline | Binding | Abuse controls |
|---|---|---|---|
| **TOTP** (RFC 6238) | Per-user secret provisioned at enrolment (QR into any authenticator app), copy cached encrypted on kiosks where the user is entitled. Kiosk computes HMAC-SHA1, 30 s step, 6 digits, accepts ±1 step. | must verify for the face top-1 candidate | last accepted time-step stored per user (replay → `FALLBACK_FAILED`); 2 attempts; 5 consecutive wrong or replayed codes for one candidate → TOTP locked 300 s for that user (`fallback.totp.max_failures` / `lockout_s`, persisted, real UTC); always verified against real wall time (never the demo clock); the accepted `totp_step` (a counter, not a secret) is in the log record, so the server detects cross-kiosk reuse at sync (`ALERT_TOTP_REPLAY`) |
| **Staff / guard override code** | Guards hold a printed list of one-time **10-digit** codes (`fallback.staff_override.code_length`; 8-digit codes in bundles signed earlier stay accepted via `legacy_code_lengths` until they expire); bundle stores `PBKDF2-HMAC-SHA256(code, salt, 100 000)` per code + `staff_id`. Kiosk hashes the entry, matches an unused code of that `staff_id`, marks it consumed locally. A code whose `code_id` is in the signed bundle array `consumed_code_ids` never matches: when `/v1/sync` receives a STAFF_OVERRIDE ALLOW with a `code_id`, the cloud retires the code and lists it there until its original `valid_until`. Minting: on the kiosk, a signed-in staff member rotates codes on `/admin` (`StaffCodesPanel`; `POST /v1/admin/access/codes/rotate`, permission `codes:rotate`, staff session only, own `staff_id` only, at most 4 per call; `codes:rotate_any` (admin) may target any staff id), which the edge proxies to the cloud `POST /v1/admin/codes/rotate`; there a `staff_id` is bound to the kiosk that first rotates it (another kiosk → `409 STAFF_ID_TAKEN`), at most 10 active codes per `staff_id` (`422 TOO_MANY_ACTIVE_CODES`). `staff_id` is required: a submission without it can never match and counts only towards the device backstop. A code may carry an optional signed scope (`zones`, `kiosk_ids`): outside it the code never matches (F09). | records `staff_id`; the person stays the face candidate | single use (locally, and across kiosks once a kiosk has installed the bundle listing the code in `consumed_code_ids`); valid until bundle `expires_at` + 24 h; **3 consecutive wrong codes for one named `staff_id` known to the bundle → that staff member's overrides locked 300 s; device backstop: any 10 override failures within 300 s (unknown / missing staff ids included) → every override locked 300 s** (`fallback.staff_override.max_failures` / `lockout_s` / `device_*`); no hash check while locked; locks are persisted (real UTC, `fallback_state.sqlite`), so an edge restart does not reset them (`edge/policy/lockouts.py`); a failure row that does not decrypt (tampered) reads as locked; the failure that starts a lock raises `ALERT_FALLBACK_LOCKOUT`; every use raises `ALERT_OVERRIDE_USED` for review at sync; cross-kiosk reuse → `ALERT_OVERRIDE_REUSE` |
| **HID card / mobile credential (simulated)** | Kiosk UI "Tap card" field (keyboard-wedge / QR / typed ID). `HMAC-SHA256(CARD_ID_PEPPER, card_id)` compared with the user's `card_id_hash`. Real deployment: HID reader / HID Mobile Access. | must belong to the face candidate | not accepted alone for high-risk zones offline; a revoked card hash (bundle `revocations[]` item `type: CARD`, or the revocation feed) fails at once; 5 consecutive wrong or revoked cards for one candidate → CARD locked 300 s for that user (`fallback.card.max_failures` / `lockout_s`, persisted, real UTC) |

Which methods are offered (DECISION_POLICY §8.3): offline low/medium `[TOTP, CARD, STAFF_OVERRIDE]`;
offline high-risk `[TOTP, STAFF_OVERRIDE]`; expired/invalid bundle `[STAFF_OVERRIDE]` (TOTP proves
identity but not *current* entitlement — a human must vouch); quality exhausted (no usable face at a
low/medium door, any mode) `[STAFF_OVERRIDE]` = manual review by desk staff (the brief's "OTP or manual
review"; the ALLOW records `staff_id` and `user_id` = null). Online adds `EMAIL_OTP` (SES via the cloud,
sandbox: verified operator address only; if the sandbox IAM denies SES the method is simply not offered;
if the cloud verify is unreachable mid-flow the same STEP_UP is re-issued without `EMAIL_OTP`, nothing
counted). YAML keys: `stepup.methods.{offline_default, offline_high_risk, cache_untrusted,
quality_exhausted, online_default, online_high_risk}`.

**Locked method.** A submission with a method whose limit is locked (any row above) is rejected without any
code / hash / card check. The answer is `STEP_UP` with the original reason codes + `FALLBACK_LOCKED` and
`next_action.retry_after_s` (seconds until the lock ends). It is not a factor failure: `attempts_left` is
unchanged and the rate limiter sees nothing (DECISION_POLICY §7.2, §9.6 R12). Edge alerts:
`ALERT_FALLBACK_LOCKOUT` (`lock` = `STAFF_OVERRIDE_STAFF` | `STAFF_OVERRIDE_DEVICE` | `TOTP_USER` | `CARD_USER`)
and, at start-up, `ALERT_FALLBACK_STATE_RESET` when `fallback_state.sqlite` was deleted or replaced (its random
`epoch` differs from the one in the decision log; consumed codes and TOTP steps are re-seeded from the log,
locks are not). Both are listed by `GET /v1/admin/alerts` (`audit:read`).

**Lost revocation overlay.** While `revocations_state_lost` is set (SC2.2), no attempt auto-ALLOWs: a would-be
ALLOW becomes `STEP_UP` `[SECOND_FACTOR]` with `OFFLINE_FALLBACK_REQUIRED`.

**Honest limits.** (1) The device backstop lets one anonymous person block every staff override on the kiosk
for 300 s at a time (10 wrong submissions; each lock is alerted); TOTP and CARD stay usable. (2) Someone with
write access to `fallback_state.sqlite` can delete a single failure row and so end that lock without an alert;
only a deleted or replaced file is detected. (3) Challenge evidence (the step-up CHALLENGE) is measured and
asserted by the kiosk client, not by the edge (audit F01, architectural; DECISION_POLICY §7.3). (4) The depth
M1 rigid-mask cue can be defeated by forged client landmarks (DE-08, open; depth is disabled).

**Test-fixture** override codes (hashes in `config/schedule.example.json`; for the test vectors only, never
in a live bundle): `OVR-001` = `48213907`, `OVR-002` = `75530182` (guard `s_guard01`), `OVR-003` = `19064425`
(`s_guard02`). Because they are public, `scripts/sign_bundle.py` drops them and mints fresh random 10-digit codes
(values only in `edge/data/DEMO_CODES.txt`), the cloud's `PUT /v1/admin/schedule/{kiosk_id}` rejects a
bundle that contains them, the cloud strips them from every bundle it signs, and the edge leaves them out of
its decisions unless `DEMO_MODE=1` (`edge/offline/bundle.py` `decision_bundle`). **Live state**: the
cloud-issued v45 still carries these three fixture codes (the hashes match), and the demo edge runs with
`DEMO_MODE=1`, so they would still match there: STAFF_OVERRIDE must not be used in demos until the lead
installs v46+ with fresh codes.
Demo card IDs `HID-CARD-1001` … `HID-CARD-1008` with pepper `hidhack-demo-pepper`. These and the team's
`HID-DEMO-0001` … `HID-DEMO-0004` form the documented list `DEMO_CARDS` in `scripts/sign_bundle.py`; because they
are public, the signer hashes them into a bundle only with `--demo-cards` and otherwise removes any card hash that
matches one of them.

### SC2.5 Minimum temporary information

Exactly these fields are stored per decision (online and offline use the same queue):

| Field | Example | Note |
|---|---|---|
| `attempt_id` | `att_01JDA3…` (ULID) | idempotency key |
| `seq` | 1042 | per-kiosk monotonic counter |
| `kiosk_id` | `KIOSK_LIB_01` | |
| `zone` | `LIBRARY` | |
| `ts_utc` | `2026-11-14T04:35:12Z` | |
| `user_id` | `u_3c4d` or `null` | pseudonymous; candidate id on BIO_FAIL in `candidate_user_id` |
| `candidate_user_id` | `u_3c4d` or `null` | top-1 candidate on BIO_FAIL (targeted-spoof alerts); never displayed |
| `decision` | `ALLOW` | |
| `reason_codes` | `["ACCESS_OK","OFFLINE_MODE"]` | + `resolved_codes` |
| `resolved_codes` | `["OFFLINE_HIGH_RISK_ZONE"]` | step-up triggers that were resolved |
| `scores` | `{"pad":0.93,"flash":0.81,"match":0.72,"margin":0.31}` | **rounded to 2 dp**; no per-frame data; keys ⊆ {pad, flash, flash_amp, moire, device, match, margin, rek, rek_runner_up} |
| `fallback` | `{"method":"STAFF_OVERRIDE","staff_id":"s_guard01","code_id":"OVR-001","totp_step":null}` or `null` | never the code / TOTP value; `totp_step` = the accepted TOTP time-step counter (TOTP only; not a secret) for cross-kiosk replay detection (Y07) |
| `schedule_version` | 42 | + `cache_state` |
| `cache_state` | `FRESH` | FRESH / EXPIRED / INVALID |
| `mode` | `OFFLINE` | |
| `prev_hash`, `record_hash` | hex | hash chain |

**Never stored:** images, face crops, depth maps, embeddings, display names, TOTP values, raw card IDs.
Frames live in RAM only for the duration of the attempt. **S3 audit-frame upload is not implemented**:
no attempt frame is stored anywhere, online or offline. (Design, roadmap: online DENY/STEP_UP frames to S3
with SSE-KMS and the **1-day** lifecycle rule that already exists on the bucket,
`cloud/infra/templates/s3-lifecycle.json`; never offline.) The sandbox bucket in **us-east-1** holds only
Face Liveness output and an optional enrolment reference (off by default); production would pin
ap-south-1.
One record per attempt: a STEP_UP waits (encrypted) as a pending record and enters the chain once the
attempt is final (ALLOW / DENY, or abandoned → its last STEP_UP), so the server never sees two versions.

Storage: SQLite table `decision_log(seq PK, attempt_id UNIQUE, ts_utc, payload BLOB /*AES-GCM(JSON)*/,
prev_hash, record_hash, synced_at NULL)`; key `EDGE_DATA_KEY` (alternative: encrypted JSONL, one
AES-GCM line per record). `record_hash = SHA256(prev_hash || canonical_json(record))`; genesis
`prev_hash = SHA256("genesis:" + kiosk_id)`; the chain head is HMAC'd with the kiosk key at each sync.

Retention: purge a record as soon as the server acks it. Unsynced records are purged at **24 h**; the
purge leaves a tombstone `{count, first_seq, last_seq, chain_head}` that is synced later →
`ALERT_RECORDS_PURGED_UNSYNCED`. India DPDP Act 2023: purpose limitation + data minimisation +
storage limitation are the talking points.

### SC2.6 Synchronisation on reconnect

Format and server behaviour are exactly `docs/API.md` v1.3 §4.4 (`POST /v1/sync`); the edge side is
`edge/offline/sync.py`.

1. Enter `SYNCING` (OFFLINE rules still apply to new attempts; they simply join the queue). Each sync
   cycle first pulls the revocation feed (`GET /v1/revocations?since=`) so revocations apply before the
   queue is replayed.
2. `POST /v1/sync` in batches of **≤ 50 items** (`sync.batch_size`, `SyncRequest.items` max_length 50)
   in `seq` order; body `{kiosk_id, batch_id: "b_<ULID>", chain_head, chain_head_hmac, items[]}` where
   `chain_head` = `record_hash` of the last record in the batch and `chain_head_hmac` =
   HMAC-SHA256(`KIOSK_HMAC_KEY`, `chain_head`). Each item is a `SyncItem` = the SC2.5 record exactly +
   `idempotency_key` (= `attempt_id`) + `hmac` (HMAC-SHA256 over the canonical item JSON without
   `hmac`), or a `TombstoneItem` `{type: "TOMBSTONE", count, first_seq, last_seq, chain_head, hmac}`.
   The request carries the signed cloud-auth headers (`X-Kiosk-Id`, `X-Timestamp`, `X-Signature`,
   `X-Api-Key`, API.md §0; the signed PATH includes `?query` when the request has one, and the cloud accepts a
   bare-path signature for such a request only with the transition switch `CLOUD_ACCEPT_BARE_PATH_SIG=1`) and
   an `Idempotency-Key` = `batch_id`. Retry with exponential backoff
   1 → 60 s, ±20 % jitter (`sync.backoff_*`).
3. Server, per item (idempotent on `idempotency_key` = `attempt_id`):
   - verify the item `hmac`, chain continuity from the last acknowledged hash and `chain_head_hmac` →
     else `ALERT_LOG_TAMPER` (records still ingested, flagged);
   - store immutably (the kiosk's decision is a fact; the server annotates, never rewrites);
   - **re-evaluate every offline ALLOW** (and STEP_UP→ALLOW) with the authoritative schedule and
     revocations at `ts_utc` (same `evaluate_schedule()`), plus fallback validity;
   - respond `SyncResponse` `{accepted[], duplicates[], rejected[{idempotency_key, error:
     HMAC_INVALID|VALIDATION_ERROR}], flags[{attempt_id, type:
     POST_HOC_REVOKED|SCHEDULE_CHANGED|RECORDS_PURGED_UNSYNCED}], server_time}`; `attempt_id` is null for
     the tombstone flag. An item whose `attempt_id` is already stored with a **different** hash is a
     conflict (Y02): it is acknowledged in `duplicates` (never `rejected`, so the kiosk purges it), listed
     in `conflicts` with ack status `CONFLICT` in the verbose shape, both versions are kept and
     `ALERT_SYNC_CONFLICT` is raised once (`cloud/app/services/sync_service.py` `_existing`).
     Flags map to the alerts below (`POST_HOC_REVOKED` → `ALERT_REVOKED_USER_ADMITTED`, `SCHEDULE_CHANGED`
     → `ALERT_SCHEDULE_MISMATCH`, `RECORDS_PURGED_UNSYNCED` → `ALERT_RECORDS_PURGED_UNSYNCED`); the
     other alerts are raised server-side and shown on the dashboard.
   - **Clock skew** is measured as server receipt time − the batch's `kiosk_now_utc` (the kiosk wall
     clock at send time, i.e. the **demo clock** if one is active); > 120 s raises `ALERT_CLOCK_SKEW` and
     re-evaluation uses the corrected time. The edge also compares `server_time` in the response with its
     own clock.
4. Kiosk deletes acked records (`accepted` + `duplicates`; `rejected` stay until the 24 h purge), then
   refreshes the bundle (`GET /v1/schedule/{kiosk_id}` with `If-None-Match` = the full ETag it last received,
   cloud form `"v<bundle_version>-<issued_at epoch>"`; 304 only on a full-ETag match, so an old `"<version>"`
   ETag gets a fresh 200; the cloud re-issues the same version with fresh stamps once its last issue for the
   kiosk is older than half the bundle lifetime; near the effective expiry the edge sends no `If-None-Match` at
   all (SC2.2); 304 = confirmed; a bundle that
   fails verification is rejected and the LVB kept); the local template gallery is filtered to users
   entitled in the LVB + revocation feed (revoked / no-longer-entitled users drop out); `ONLINE` once every
   sendable record was acked or rejected in this cycle, every tombstone was acked, the bundle is installed or
   confirmed and the revocation feed state is not lost (SC2.2). Server-rejected and undecryptable rows stay
   queued (24 h purge → tombstone) and are retried at most every `sync.backoff_max_s`, but no longer hold the
   kiosk in offline rules (`edge/offline/sync.py`).
   Online, the same endpoint is used continuously (the queue is replayed whenever it is non-empty).
5. Queued DPDP erasures (made while the cloud was unreachable; local data is erased at once) are replayed at
   every sync as `DELETE /v1/enroll/{user_id}?actor=<actor>` (the actor is inside the signed PATH). 200 / 204
   is done; a cloud 404 counts as done only when its error says `NOT_FOUND` with a reason (e.g.
   `NOT_ENROLLED`: the cloud holds nothing); any other status stays queued for the next sync.

Server-side alert types (not decision reason codes):

| Alert | Trigger | Severity |
|---|---|---|
| `ALERT_REVOKED_USER_ADMITTED` | offline ALLOW for a user whose authoritative `revoked_at` ≤ record `ts_utc` | high |
| `ALERT_SCHEDULE_MISMATCH` | offline ALLOW but authoritative schedule ≠ IN_WINDOW at `ts_utc` (e.g. new closure published while offline) | medium |
| `ALERT_OVERRIDE_USED` | any STAFF_OVERRIDE ALLOW, including every A3 manual-review ALLOW (quality exhausted, schedule not checked), online and offline | info (review); an offline A3 ALLOW without `user_id` gets verdict `MANUAL_REVIEW` |
| `ALERT_OVERRIDE_REUSE` / `ALERT_TOTP_REPLAY` | same code / same TOTP step accepted at two kiosks | high |
| `ALERT_SPOOF_BURST` | ≥ 3 `SPOOF_*`/`INJECTION_*` DENY on one kiosk within 10 min while offline | medium |
| `ALERT_LOG_TAMPER` | hash chain break, bad item `hmac` or bad `chain_head_hmac` | high |
| `ALERT_CHAIN_GAP` | a `seq` gap in a kiosk's records not covered by a tombstone (`cloud/app/services/sync_service.py`) | high |
| `ALERT_OFFLINE_POLICY_VIOLATION` | offline auto-ALLOW in a high-risk zone, an override code used under another `staff_id`, or a code bound to another kiosk (verdict `DISCREPANCY`) | high |
| `ALERT_OFFLINE_TEMPLATE_UNCONFIRMED` | offline ALLOW for a user enrolled offline (`POST /v1/enroll/offline-record`) whom no cloud enrolment has indexed yet (flag `OFFLINE_TEMPLATE_UNCONFIRMED`) | medium |
| `ALERT_REEVALUATION_UNAVAILABLE` | the cloud cannot re-evaluate (verdict `NOT_EVALUATED`) | low |
| `ALERT_SYNC_CONFLICT` | same `attempt_id`, different `record_hash` (acked in `duplicates`, both versions kept; Y02) | high |
| `ALERT_CLOCK_SKEW` | \|server receipt time − batch `kiosk_now_utc`\| > `sync.clock_skew_alert_s` (120 s) (re-evaluation uses corrected time) | low |
| `ALERT_RECORDS_PURGED_UNSYNCED` | tombstone received | medium |
| `ALERT_RATE_LIMIT_LOCKOUT` | raised by the edge when the rate limiter locks the kiosk (5 attack-evidence DENYs in 180 s → 5 s lockout); kept in the edge's in-memory alert log and listed by `GET /v1/admin/alerts` (`audit:read`); it is **not** streamed on `GET /v1/events` (that feed carries only `decision` and `rendered` events); the counted DENYs themselves sync as normal records | medium |

Conflict rules: (1) kiosk records immutable, server annotates; (2) same `attempt_id` + same hash →
`duplicates` (no double count); different hash → also acknowledged in `duplicates` (so the kiosk purges
it; `verbose` lists it in `conflicts`) + `ALERT_SYNC_CONFLICT`, both versions kept, never `rejected` (test
vector Y02); (3) entitlement truth =
server data **effective at `ts_utc`** — a revocation issued *after* the offline ALLOW is not a
discrepancy; (4) one-time codes are globally single-use — first use by `ts_utc` wins, the other is
flagged, and the cloud retires a synced code via the signed `consumed_code_ids` (SC2.4); (5) skew-corrected time is used for (3) and (4); (6) sync completes before ONLINE, so no
online decision can race a stale offline queue.

### SC2.7 Live demo plan (≈ 3 min)

The authoritative run sheet is `docs/DEMO_AND_PITCH.md` §1.2 (steps 10–14). This is the SC2 view of it.

Setup: kiosk badge shows `ONLINE · bundle v45 · queue 0`. The live bundle **v45** is cloud-issued
(`issued_at` 18:00:41 IST) and covers **`KIOSK_MAIN_01` / MAIN_GATE only**, so there is no kiosk switch:
the high-risk SERVER_ROOM and the LIBRARY scenarios are told (test vectors O04 / F2, O11 / O12) or shown
from the recorded clip, not run live. Subject: `u_prj1` (Prajwal, student; MAIN_GATE Sat 06:00–22:00, grace
to 22:15). Rekognition holds consenting team faces only and is wiped at teardown. The operator is
signed in to `/admin` with a personal `admin`-role staff account (the demo clock needs `demo:clock`, admin
only; see `docs/DEMO_AND_PITCH.md` §1.4 for the curl session). **Before this
segment:** reset the demo clock (`POST /v1/admin/clock {"reset": true}`; the "DEMO CLOCK" badge must be
gone, or set `{"set_local": "21:00"}` if the real time is after 21:55), keep the random challenge `OFF`
for the scripted run (`POST /v1/admin/random-challenge {"mode": "OFF"}`; the shipped rate is 0.15 online /
0.30 offline) and reset the rate limiter (`POST /v1/admin/rate-limit/reset`; lockout is only 5 s anyway).
The colour flash is ADVISORY: do not present it as an enforced check (DECISION_POLICY §3.3). **No staff
code on stage**: v45 still carries the publicly documented fixture codes until the lead uploads v46+.

1. **Pull the plug**: turn off Wi-Fi → badge turns red `OFFLINE` after ≈ 12–17 s (3 missed 5 s
   heartbeats, 2 s timeout each; the badge polls `GET /v1/mode` every 2 s). Backup / instant:
   `POST /v1/admin/mode {"force": "OFFLINE"}` (what the Control Panel button sends; it auto-reverts to AUTO
   after 60 min, far longer than this segment). Point out the queue counter.
2. **Safe ALLOW**: Prajwal at MAIN_GATE → `ALLOW` · `ACCESS_OK, OFFLINE_MODE` (strict thresholds; the
   operator view shows offline scores vs bars, `GET /v1/admin/mode/detail` `policy_bars`).
3. **No unsafe automatic access** (offline grace): demo clock `{"set_local": "22:10"}` (after v45's
   `issued_at` − 300 s) → `STEP_UP` · `SCHEDULE_GRACE_WINDOW, OFFLINE_MODE, OFFLINE_FALLBACK_REQUIRED`,
   SECOND_FACTOR `[TOTP, CARD, STAFF_OVERRIDE]` → TOTP from the phone (real time) or card `HID-DEMO-0001` →
   `ALLOW` · `ACCESS_OK, FALLBACK_OK, OFFLINE_MODE`, `resolved_codes` `[SCHEDULE_GRACE_WINDOW]`. Then
   `{"reset": true}` at once. Say: a high-risk door offline always needs TOTP or a staff code, never the
   face alone and never the card alone.
4. **DENY**: phone photo of Prajwal → `DENY` · `SPOOF_DEVICE_DETECTED, OFFLINE_MODE` (liveness works
   offline).
5. **Store view**: `GET /v1/admin/store`: the SC2.5 fields only, `never_stored`, chain OK.
6. **Reconnect** (clock reset first): Wi-Fi on (and `POST /v1/admin/mode {"force": "AUTO"}` if forced) →
   badge `SYNCING` → queue counts down to **0** → `ONLINE`. The cloud re-checks every offline ALLOW
   against the authoritative schedule. A demo clock left shifted would stamp `kiosk_now_utc` wrong and
   raise `ALERT_CLOCK_SKEW` (> 120 s).
7. Optional, if time allows: revoke a demo user on the cloud admin API during the outage; their offline
   ALLOW still happens (the kiosk cannot know, honest) and sync raises `ALERT_REVOKED_USER_ADMITTED`.

Honest framing: offline mode bounds the damage of stale data (12 h max, revocations re-checked at sync)
but cannot prevent a revoked user being admitted during an outage at a low-risk door; that is why
high-risk zones always need a second factor offline.
