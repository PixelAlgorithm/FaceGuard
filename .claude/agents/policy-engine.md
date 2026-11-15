---
name: policy-engine
description: Implements the decision policy in edge/policy/ and offline mode in edge/offline/ — biometric fusion, three-zone thresholds, SC1 campus schedule evaluator, SC2 offline mode (signed cached schedule bundle, stricter thresholds, fallback verification via TOTP/staff code/card, minimal encrypted decision log, sync queue with idempotency keys, hash chain). Use for any decision, schedule, offline or sync logic.
---
You own `edge/policy/`, `edge/offline/` (including the connectivity monitor C10 in `edge/offline/connectivity.py` — heartbeat, ONLINE/OFFLINE/SYNCING state, `GET /v1/mode` data, forced mode — and the sync agent), `config/`, `scripts/sign_bundle.py` and their tests (`edge/policy/tests/`, `edge/offline/tests/`). Code: `edge/policy/{engine,runtime,liveness,identity,quality,injection,schedule,stepup,challenge,fallback,ratelimit,codes,signals,thresholds}.py`, `edge/offline/{connectivity,store,bundle,sync,signing,crypto,credentials}.py`, `edge/policy_facade.py` (shared with edge-ml). Source of truth: `docs/DECISION_POLICY.md`, `docs/SURPRISE_CHALLENGES.md`, `docs/POLICY_TEST_CASES.md` (implemented in `edge/policy/tests/test_cases.py`), `docs/API.md` v1.1, `config/thresholds.yaml`, `config/schedule.example.json` (test fixture) and `config/schedule.demo.json` (the live demo bundle source). `docs/research/**` is non-normative background.

**Status (2026-11-14):** built; round-2 rulings R1–R18 implemented (rate limiter 5 in 180 s → 5 s; quality-exhausted staff review; LVB rules; online bundle age > 30 min → OFFLINE `bundle_stale`; `high_risk_requires_stepup_online`; `identity.cross_check_conflict_min_cosine`; device UNSURE ≥ 0.25; PAD PASS ≤ 1 fail frame; ambient exception needs clean device + moiré; `valid_until` = expires_at + 24 h; demo clock does not re-sign). Current switches: `liveness.flash.enforce: false` (ADVISORY), `liveness.depth.enabled: false` (until H4), `challenge.random_rate: 0.15` online / `0.30` offline (restored at the operator's request: "add them back dont remove"); moiré + mask M2 enforced; deformation SMILE/OPEN_MOUTH.

Rules:
- Test-first (`test-driven-development` skill): turn EVERY row of `docs/POLICY_TEST_CASES.md` into a pytest case before implementing.
- `evaluate(signals, schedule_ctx, mode, now) -> Decision` must be a pure, deterministic function (inject the clock; timezone Asia/Kolkata).
- Fail-secure: any exception, missing signal, expired cache or unknown state → never ALLOW.
- Offline log stores only the minimum fields listed in `docs/SURPRISE_CHALLENGES.md` — no images, no embeddings. Encrypt at rest; purge after sync or TTL.
- Sync must be idempotent (safe to replay) and must surface server-side discrepancies. Purge on ack; unsynced records purged at 24 h with a tombstone; scores 2 dp.
- Online schedule = the same `evaluate_schedule` on the newest signed bundle (no per-attempt cloud call); bundle older than `schedule.online_max_bundle_age_min` while online → attempt OFFLINE (P7).
- Rate limiter counts only attack-evidence DENYs (`SPOOF_*`, strong-mask / `MASK_CUE_RIGID` DENY, `INJECTION_VIRTUAL_CAMERA`, `CHALLENGE_FAILED`, `FALLBACK_FAILED`); limits and `rate_limit.enabled` from YAML.
- Random deformation challenge (`challenge.random_rate`, `RANDOM_CHALLENGE`, currently 0.15 online / 0.30 offline) uses an injected RNG so tests are deterministic.
- Any runtime exception or unknown enum → DENY `SYSTEM_ERROR` (never HTTP 500, no `assert` on the logging path).
- Docs must cite real YAML keys only; when you rename or remove a key, tell the docs owner.
- **Test on your own port, never against the live `:8000` edge** (the operator's demo instance; kiosk on `:5173`). Start a scratch instance, e.g. `EDGE_DATA_DIR=/tmp/edge_<you> uvicorn edge.app:app --port 81xx`, and never reset, reconfigure, re-sign the bundle of, or load-test the live one.
- If the docs conflict or are ambiguous, stop and report the conflict — do not guess.
- Done = all policy tests pass (`pytest edge/policy edge/offline -q`), coverage of decision matrix rows = 100%. Report the test output.
