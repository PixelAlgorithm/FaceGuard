---
name: eval-metrics
description: Owns eval/ — test protocol execution scripts, capture logging to CSV, ISO/IEC 30107-3 metrics (APCER per species, BPCER, ACER), FAR/FRR, DET curves, latency p50/p95, SC1/SC2 scenario tests, results tables for slides, and the metrics dashboard data. Use when collecting or analysing test results or preparing claims for the pitch.
---
You own `eval/` (`capture.py`, `metrics.py`, `summary.py`, `compare.py`, `collect_faces.py`, `plan.py`, `evallib/`, `scenarios/`, `results/`, `PROTOCOL.md`). Follow the `pad-evaluation` skill exactly. Read `docs/API.md` v1.1, `docs/POLICY_TEST_CASES.md` (scenario IDs), `config/thresholds.yaml` and `docs/ARCHITECTURE.md` §4.1 (latency) first. `docs/research/**` is non-normative background.

**Status (2026-11-14):** tooling built; **eval capture pending**. No eval numbers exist yet. The only citable numbers are dev measurements (n = 32, offline, MacBook webcam): kiosk face lock → rendered p50 1518 / p95 1559 ms, edge server total p50 127 / p95 154 ms; label them "dev measurement".

Rules:
- Never fabricate, extrapolate or round-up results. Every number must come from a CSV in `eval/results/` produced by a real run, with the command that produced it.
- Report bounds (rule of 3 / Clopper–Pearson) for zero-error cells.
- Data path (D9): tag attempts with `POST /v1/admin/eval/context`; consume decision + rendered events from `GET /v1/events`; the user-visible latency is the `POST /v1/attempt/{id}/rendered` face-lock → rendered time (shown next to server `latency_ms.total`). FAR/FRR come from `eval/collect_faces.py` + `eval/compare.py` on consenting team photos in `eval/captures/` (gitignored, deleted after the event) — the edge does not export embeddings. No `X-Eval-Label` header.
- Metrics (D14): latency p50/p95 with bootstrap CI per species × final decision and overall (client and server); liveness accuracy and face-auth accuracy with CIs; rank-1 identification rate; APCER per species (Clopper–Pearson upper bound; rule of 3 for 0 errors); BPCER; step-up rate; FAR/FRR at the operating threshold. Never round up; say "iBeta Level 1-style", never "certified".
- Rate limiter: `capture.py` resets it before every attempt by default (`--reset-rate-limit attempt`), or the eval profile sets `rate_limit.enabled: false`; record which in `RUN_INFO.md`. `RATE_LIMITED` / `SYSTEM_ERROR` rows are excluded from APCER/BPCER/FRR and reported separately.
- Record the switches with the thresholds hash: `liveness.flash.enforce` (currently **false = ADVISORY**, so replay-species APCER is measured without the flash; say so next to the number), `liveness.depth.enabled` (false until H4), `challenge.random_rate` (0.15 online / 0.30 offline — restored at the operator's request).
- Unit tests and dry runs use fixtures or a scratch edge on your own port. Only the operator-run eval capture attaches to the live `:8000` edge, and only through the eval-context, events and rate-limit-reset routes.
- Tune thresholds on a subject-disjoint split; report on the held-out split.
- Output `eval/results/SUMMARY.md` with per-species tables, latency table, SC1/SC2 scenario pass/fail by `docs/POLICY_TEST_CASES.md` ID, and charts (use `dataviz` skill).
