"""Slide-ready SUMMARY.md + charts + dashboard JSON from metrics.json (never from anything else).

Usage (from eval/):
  uv run python summary.py                                        # results/metrics.json -> results/SUMMARY.md
  uv run python summary.py --metrics /tmp/eval_dummy/metrics.json --out-dir /tmp/eval_dummy   # DUMMY demo

Every number is copied from metrics.json; percentages are rounded conservatively (error rates / upper bounds up,
accuracies / lower bounds down). Each table row links the source run manifests (runs/<run_id>.json).
Organiser targets are shown side by side as "target" vs "measured (95% CI)".
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

from evallib import RESULTS_DIR
from evallib import config as ecfg
from evallib import io as eio
from evallib import schema as S
from evallib import stats as st

NA = "n/a"


def pct_up(x) -> str:
    return st.pct(x, up=True)


def pct_dn(x) -> str:
    return st.pct(x, up=False)


def ms(x) -> str:
    return NA if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x:.0f}"


def rate_cell(r: dict | None) -> str:
    if not r or not r.get("n"):
        return "no data"
    return f"{r['k']}/{r['n']} = {pct_up(r['rate'])} (UB {pct_up(r['ub95'])})"


def runs_links(runs: list[str] | None, runs_rel: str) -> str:
    runs = [r for r in (runs or []) if r]
    if not runs:
        return "-"
    shown = ", ".join(f"[{r}]({runs_rel}/{r}.json)" for r in runs[:4])
    return shown + (f" +{len(runs) - 4}" if len(runs) > 4 else "")


def lat_row(scope: str, mode: str, rec: dict, source: str, runs_rel: str) -> str:
    if not rec or not rec.get("n"):
        return f"| {scope} | {mode} | 0 | {NA} | {NA} | {NA} | {NA} | {source} | - |"
    w = rec.get("within_sla")
    within = f"{w['k']}/{w['n']} (LB {pct_dn(w['lb95'])})" if w else "-"
    flag = " LOW_N" if rec.get("low_n") else ""
    return (f"| {scope} | {mode} | {rec['n']}{flag} | {ms(rec['p50'])} ({ms(rec['p50_ci95'][0])}-"
            f"{ms(rec['p50_ci95'][1])}) | {ms(rec['p95'])} ({ms(rec['p95_ci95'][0])}-{ms(rec['p95_ci95'][1])}) | "
            f"{ms(rec['max'])} | {within} | {source} | {runs_links(rec.get('runs'), runs_rel)} |")


def charts(m: dict, out: Path) -> dict[str, list[str]]:
    from evallib import style
    pad = m.get("pad") or {}
    made: dict[str, list[str]] = {}
    ap = pad.get("apcer_system") or {}
    if ap:
        rows = sorted(ap.items(), key=lambda kv: (kv[1]["ub95"], kv[1]["rate"]), reverse=True)
        made["apcer"] = style.plot_rate_bars(
            out / "apcer_by_species.png", [(sp, rec) for sp, rec in rows],
            f"APCER per attack species ({pad.get('split')} split)",
            "bar = attacks accepted after any step-up (k/N); whisker = one-sided 95% Clopper-Pearson upper bound",
            "APCER (system level)")
    bl = pad.get("bpcer_by_lighting") or {}
    if bl:
        made["bpcer_lighting"] = style.plot_rate_bars(
            out / "bpcer_by_lighting.png", [(lg, bl[lg]) for lg in S.LIGHTING if lg in bl],
            "BPCER by lighting (bona fide, final DENY)",
            "bar = k/N; whisker = 95% upper bound; STEP_UP is not counted here (see step-up chart)", "BPCER")
    sl = pad.get("genuine_stepup_by_lighting") or {}
    if sl:
        made["stepup_lighting"] = style.plot_rate_bars(
            out / "stepup_by_lighting.png", [(lg, sl[lg]) for lg in S.LIGHTING if lg in sl],
            "Bona fide step-up rate by lighting (first decision STEP_UP)",
            "includes RANDOM_CHALLENGE and RECAPTURE; whisker = 95% upper bound", "step-up rate")
    stages = ((m.get("latency") or {}).get("stages") or {})
    srows = []
    for name in ("server_total", "liveness", "match", "schedule", "policy"):
        o = (stages.get(name) or {}).get("overall") or {}
        if o.get("n"):
            srows.append((name, o["p50"], o["p95"], o["n"]))
    if srows:
        made["stages"] = style.plot_stage_ranges(
            out / "latency_stages.png", srows, "Server stage latency (edge spans, first decision)",
            "bar = p50, whisker = p95; liveness and match run in parallel, so stages do not add up")
    return {k: [Path(p).name for p in v] for k, v in made.items() if v}


def img(files: list[str] | None, alt: str) -> str:
    return f"![{alt}]({files[0]})  (dark: `{files[1]}`)" if files and len(files) > 1 else (
        f"![{alt}]({files[0]})" if files else "_chart not generated (no data)_")


def build(m: dict, metrics_path: Path, chart_files: dict, runs_rel: str) -> tuple[str, dict]:
    info = m["RUN_INFO"]
    pad = m.get("pad") or {}
    lat = m.get("latency") or {}
    L: list[str] = []
    add = L.append
    add("# HID kiosk - evaluation summary (PAD + face authentication + SC1/SC2)")
    add("")
    if info.get("dummy_data"):
        add("> **DUMMY DATA - synthetic test fixtures. Not a measurement. Never quote these numbers.**")
        add("")
    add("> iBeta Level 1-**style** protocol (not an iBeta test, not certified). "
        f"{len(info['subjects_per_split'].get('test', []))} test + {len(info['subjects_per_split'].get('dev', []))} "
        "dev subjects, team-sourced, consenting, not demographically representative. Thresholds frozen before the "
        "test split; numbers below are the held-out **test** split unless labelled \"dev (tuned on)\".")
    add("")
    add(f"- Source: `{metrics_path}` (sha256 `{eio.sha256_file(metrics_path)}`), generated "
        f"{info['generated_at_utc']} by `{info['command']}`")
    for k, v in info["inputs"].items():
        if v.get("exists"):
            add(f"- Input `{k}`: `{v['path']}` sha256 `{v['sha256']}` ({v.get('rows')} rows"
                + (f", {v.get('rows_excluded')} excluded" if v.get("rows_excluded") else "") + ")")
    add(f"- Thresholds `{info['thresholds']['path']}` sha256 `{info['thresholds']['sha256']}`, policy_version "
        f"`{info['thresholds']['policy_version']}` (attempts: {info['policy_versions_in_attempts']})")
    add(f"- Capture runs: {runs_links(info['run_ids']['attempts'], runs_rel)}; comparison runs: "
        f"{runs_links(info['run_ids']['comparisons'], runs_rel)}; scenario runs: "
        f"{runs_links(info['run_ids']['scenarios'], runs_rel)}")
    sw = info.get("switches")
    if sw:
        add("- Configuration under test (recorded with the thresholds hash):")
        L.extend("  " + ln for ln in ecfg.switch_lines(sw))
    add("- Rounding: error rates and upper bounds rounded **up**, accuracies and lower bounds rounded **down**; "
        "0 errors reported as an upper bound (rule of 3: 0/N -> < 3/N).")
    add("")

    # 1. targets
    add("## 1. HID targets vs measured")
    add("")
    add("| HID target | Target | Measured (95% CI) | Status | ISO / supporting view |")
    add("|---|---|---|---|---|")
    for t in m.get("hid_targets", []):
        tv = t["target_value"]
        tgt = f"< {tv / 1000:.0f} s" if "Decision time" in t["target"] else pct_up(tv) if tv < 0.5 else pct_dn(tv)
        mrec = t.get("measured") or {}
        meas = mrec.get("text") or "not measured"
        if mrec.get("unit"):  # FAR: independent units; comparison-level rate for information only
            cmp_txt = (mrec.get("comparison_level") or {}).get("text")
            meas += f" per {mrec['unit']}" + (f"; comparison-level {cmp_txt} (not independent)" if cmp_txt else "")
        add(f"| {t['target']} | {tgt} | {meas} | {t['status']} | {t.get('iso_view') or '-'} |")
    add("")

    # 2. APCER
    add("## 2. Attack presentations - APCER per species (system level: final decision after any step-up)")
    add("")
    if pad.get("max_apcer_system"):
        mx = pad["max_apcer_system"]
        add(f"**Headline - max APCER (species with the highest 95% UB): {mx['species']}: {mx['text']}**")
        add("")
    add("| Species | HID scenario | APCER k/N (95% UB) | 0-error rule of 3 | PAD-level APCER | Attack step-up | "
        "Step-up bypass | IAPMR | Not evaluated | Flag | Runs |")
    add("|---|---|---|---|---|---|---|---|---|---|---|")
    for sp, r in (pad.get("apcer_system") or {}).items():
        ne = pad["attack_not_evaluated"][sp]
        r3 = r.get("rule_of_3_text", "-") if r["k"] == 0 else "-"
        add(f"| {sp} | {r['hid_scenario']} | {rate_cell(r)} | {r3} | {rate_cell(pad['apcer_pad'][sp])} | "
            f"{rate_cell(pad['attack_stepup'][sp])} | {rate_cell(pad['attack_stepup_bypass'][sp])} | "
            f"{rate_cell(pad['iapmr'][sp])} | NR {ne['no_response']}, RL {ne['rate_limited_excluded']}, "
            f"SE {ne['system_error']} | {'LOW_N' if r.get('low_n') else ''} | {runs_links(r.get('runs'), runs_rel)} |")
    if sw and not sw["flash"]["enforce"]:
        add("")
        add("Colour flash is **ADVISORY** (`liveness.flash.enforce: false`) in this run: phone_photo / phone_video / "
            "laptop_replay APCER is measured with PAD + device detector + moire **without** the flash.")
    if pad.get("species_missing"):
        add("")
        add(f"Species not captured on this split: {', '.join(pad['species_missing'])}.")
    add("")
    add("By HID scenario (coarse label):")
    add("")
    add("| HID scenario | Species | APCER k/N (95% UB) | Flag |")
    add("|---|---|---|---|")
    for r in (pad.get("apcer_by_label") or {}).values():
        add(f"| {r['hid_scenario']} | {', '.join(r['species'])} | {rate_cell(r)} | {'LOW_N' if r.get('low_n') else ''} |")
    if pad.get("injection"):
        inj = pad["injection"]
        add("")
        add(f"Injection (reported separately from PAD): accepted {rate_cell(inj['accepted'])}; flagged "
            f"`INJECTION_VIRTUAL_CAMERA` {inj['flagged_injection']['text']}; no response {inj['no_response']}.")
    if pad.get("rate_limited", {}).get("total"):
        add("")
        add(f"RATE_LIMITED rows excluded from APCER/BPCER/FRR: {pad['rate_limited']['total']} "
            f"({pad['rate_limited']['by_species']}).")
    add("")
    add(img(chart_files.get("apcer"), "APCER per species"))
    add("")

    # 3. bona fide
    add("## 3. Bona fide - BPCER, step-up rate, FRR")
    add("")
    add("| Metric | Value (95% UB) | Definition |")
    add("|---|---|---|")
    for key, name in (("bpcer", "BPCER (headline, any final DENY)"), ("bpcer_pad_only", "BPCER (PAD-attributable)"),
                      ("bpcer_pad_subsystem", "BPCER (PAD subsystem, first decision)"),
                      ("genuine_stepup_rate", "Step-up rate (first decision STEP_UP)"),
                      ("genuine_stepup_rate_excl_random", "Step-up rate excl. RANDOM_CHALLENGE"),
                      ("frr_transaction", "FRR (transaction, final != ALLOW)"),
                      ("frr_first_pass", "FRR (first pass)"), ("bpnrr", "BPNRR (no response)"),
                      ("apnrr", "APNRR (attacks, no response)"),
                      ("far_transaction_attacks", "Live FAR: attacks reaching ALLOW"),
                      ("far_zero_effort", "Live FAR: zero-effort impostors reaching ALLOW")):
        r = pad.get(key)
        if r:
            add(f"| {name} | {rate_cell(r)} | {r.get('definition', '')} |")
    if pad.get("stepup_clearance"):
        c = pad["stepup_clearance"]
        add(f"| Step-up clearance (step-up -> ALLOW) | {c['text']} | bona fide with first STEP_UP |")
    if pad.get("rank1_live"):
        add(f"| Rank-1 identification (live) | {pad['rank1_live']['text']} | top-1 candidate = target |")
    add("")
    if pad.get("genuine_stepup_rate"):
        add(f"Step-up triggers: {pad['genuine_stepup_rate'].get('by_trigger')}; BPCER causes: "
            f"{pad.get('bpcer_by_cause')}.")
        add("")
    add("| Lighting | BPCER k/N (95% UB) | Step-up k/N (95% UB) |")
    add("|---|---|---|")
    for lg in S.LIGHTING:
        b = (pad.get("bpcer_by_lighting") or {}).get(lg)
        su = (pad.get("genuine_stepup_by_lighting") or {}).get(lg)
        if b or su:
            add(f"| {lg} | {rate_cell(b)} | {rate_cell(su)} |")
    add("")
    add(img(chart_files.get("bpcer_lighting"), "BPCER by lighting"))
    add("")
    add(img(chart_files.get("stepup_lighting"), "Step-up rate by lighting"))
    add("")
    if pad.get("liveness_accuracy_hid_style"):
        la = pad["liveness_accuracy_hid_style"]
        lo, hi = la["accuracy_ci95_two_sided"]
        add(f"Liveness accuracy (HID-style translation): {pct_dn(la['accuracy'])} (95% CI {pct_dn(lo)}-{pct_dn(hi)}),"
            f" class mix {la['class_mix']} - {la['note']}")
        add("")
    if pad.get("acer_academic_only"):
        add(f"ACER (academic summary only): {pct_up(pad['acer_academic_only']['value'])}.")
        add("")

    # 4. matcher
    add("## 4. Face matcher (local ArcFace w600k_r50, offline cross-matching)")
    add("")
    match = m.get("match") or {}
    if not match:
        add("_No comparisons.csv yet - FMR/FNMR not measured._")
        add("")
    for name, b in match.items():
        add(f"Matcher `{name}`, models {b['models']}, sources {b['sources']}, runs {runs_links(b['runs'], runs_rel)}.")
        add("")
        add("| Split | Operating point | Threshold | FMR k/N (95% UB) | FNMR k/N (95% UB) |")
        add("|---|---|---|---|---|")
        for split_key, label in (("test", "test (reported)"), ("dev_tuned_on", "dev (tuned on)")):
            blk = b.get(split_key) or {}
            for op_key, op in (("at_configured_online_live", "configured (online), live impostors only"),
                               ("at_configured_online", "configured (online), all sources"),
                               ("at_configured_offline", "configured (offline)"), ("at_calibrated", "calibrated (dev)"),
                               ("at_calibrated_offline", "calibrated + offline delta")):
                rec = blk.get(op_key)
                if rec and "fmr" in rec:
                    add(f"| {label} | {op} | {rec['threshold']:.4f} | {rate_cell(rec['fmr'])} | "
                        f"{rate_cell(rec['fnmr'])} |")
        cal = b["calibration"]
        add("")
        add(f"Calibration: {cal.get('note', 'n/a')} Suggested `allow_min_cosine` = "
            f"{cal.get('suggested_allow_min_cosine', float('nan')):.4f} from N = {cal.get('n_impostor')} "
            f"{cal.get('split')} impostor scores{'; ' + cal['warning'] if cal.get('warning') else ''}.")
        t = b["test"]
        add(f"EER (test) {pct_up(t['eer']['eer'])}; rank-1 (test) {t['rank1']['text']}; "
            f"0.2% FMR claim supportable: {t['fmr_claim_supportable']} "
            f"({t.get('fmr_claim_basis') or 'needs ' + str(b['trials_needed_fmr_0p2pct']['0_errors'])})."
            + (f" Subject-pair-level live FMR: {rate_cell(t['fmr_subject_pair_level_live'])}."
               if t.get("fmr_subject_pair_level_live") else ""))
        if t.get("verification_accuracy_at_configured"):
            va = t["verification_accuracy_at_configured"]
            add(f"Verification accuracy at the configured threshold: {pct_dn(va['accuracy'])} (95% CI "
                f"{pct_dn(va['accuracy_ci95_two_sided'][0])}-{pct_dn(va['accuracy_ci95_two_sided'][1])}), mix "
                f"{va['class_mix']}.")
        add("")
        add(img(b.get("det_png"), f"DET {name}"))
        add("")

    # 5. latency
    add("## 5. Decision time (client face lock -> rendered) and server latency")
    add("")
    add(f"Source of decision time: **{lat.get('decision_time_source', 'not measured')}**; "
        f"{lat.get('rows_without_decision_time', 0)} responded rows without it. {lat.get('note', '')}")
    add("")
    add("| Scope | Mode | N | p50 ms (95% CI) | p95 ms (95% CI) | max ms | <= 2 s (95% LB) | Source | Runs |")
    add("|---|---|---|---|---|---|---|---|---|")
    for scope, key, src in (("Decision time, ALLOW path", "sla_allow_path", lat.get("decision_time_source", "")),
                            ("Decision time, all first decisions", "all_first_decisions",
                             lat.get("decision_time_source", "")),
                            ("Server latency_ms.total, ALLOW path", "server_total_allow_path", "edge"),
                            ("Server latency_ms.total, all", "server_total", "edge")):
        for mode, rec in (lat.get(key) or {}).items():
            add(lat_row(scope, mode, rec, src, runs_rel))
    add("")
    add("Per species x final decision (decision time / server total, p50 and p95 ms):")
    add("")
    add("| Species | Final decision | N | client p50 | client p95 (95% CI) | server p50 | server p95 |")
    add("|---|---|---|---|---|---|---|")
    for sp, cells in (lat.get("by_species_final_decision") or {}).items():
        for d, c in cells.items():
            cl, sv = c["client"], c["server_total"]
            ci = f"{ms(cl['p95'])} ({ms(cl['p95_ci95'][0])}-{ms(cl['p95_ci95'][1])})" if cl.get("n") else NA
            add(f"| {sp} | {d} | {max(cl.get('n', 0), sv.get('n', 0))} | {ms(cl.get('p50'))} | {ci} | "
                f"{ms(sv.get('p50'))} | {ms(sv.get('p95'))} |")
    sv = (lat.get("stepup_verification_time") or {}).get("overall") or {}
    if sv.get("n"):
        add("")
        add(f"Step-up verification time (first STEP_UP -> final decision, not on the 2 s path): p50 {ms(sv['p50'])} ms, "
            f"p95 {ms(sv['p95'])} ms, n = {sv['n']}.")
    add("")
    add(img([f for f in (m.get("files") or {}).get("charts_png", []) if f.startswith("latency_hist")],
            "Decision time histogram"))
    add("")
    add(img(chart_files.get("stages"), "Server stage latency"))
    add("")

    # 6. decision mix
    add("## 6. Decision mix (final decision per species)")
    add("")
    add("| Species | ALLOW | STEP_UP | DENY | NO_RESPONSE |")
    add("|---|---|---|---|---|")
    for sp, c in (pad.get("decision_mix_final") or {}).items():
        add(f"| {sp} | {c['ALLOW']} | {c['STEP_UP']} | {c['DENY']} | {c['NO_RESPONSE']} |")
    add("")

    # 7. scenarios
    scn = m.get("scenarios") or {}
    add("## 7. SC1 / SC2 gate (IDs from docs/POLICY_TEST_CASES.md)")
    add("")
    add(f"Summary: {scn.get('summary')}. {scn.get('rule', '')}")
    add("")
    add("| ID | Challenge | Setup | Expected | Status | Backend | Live evidence (match/N) | Run |")
    add("|---|---|---|---|---|---|---|---|")
    for t in scn.get("table", []):
        le = t.get("live_evidence") or {}
        live = f"{le.get('matching_expected', 0)}/{le.get('n', 0)}" if le.get("n") else "-"
        setup = (t.get("setup") or "").replace("|", "/")[:70]
        exp = (t.get("expected") or "").replace("|", "/")[:80]
        add(f"| {t['id']} | {t['challenge']} | {setup} | {exp} | **{t['status']}** | {t.get('backend') or '-'} | "
            f"{live} | {runs_links([t['run_id']] if t.get('run_id') else [], runs_rel)} |")
    add("")

    # 8. trials
    add("## 8. Trials needed to confirm a target (one-sided 95%)")
    add("")
    add("| Claim | 0 errors | 1 error | 2 errors |")
    add("|---|---|---|---|")
    for t in m.get("trials_needed", []):
        add(f"| {t['claim']} | {t['n_0_errors']:,} | {t['n_1_errors']:,} | {t['n_2_errors']:,} |")
    add("")

    # 9. honesty
    add("## 9. Honesty notes")
    add("")
    for line in (
        "We followed an iBeta Level 1-style protocol. It is not an iBeta test and not a certification.",
        "Zero-error cells are upper bounds, never \"100%\": 0/N -> < 3/N at 95% (exact 1 - 0.05^(1/N)).",
        "FAR 0.2% / FRR 0.6% need 1,497 / 498 error-free trials; section 8 shows what we ran.",
        "Matcher numbers are for the local ArcFace matcher only (Rekognition not cross-matched).",
        "Silicone masks are a known RGB limit; depth raises the bar, it does not solve masks.",
        "Injection is reported separately from PAD (ISO/IEC 30107-3 / FIDO scope; CEN/TS 18099).",
        "Licences: InsightFace w600k_r50 (buffalo_l) weights are non-commercial research only; MiniFASNet Apache-2.0.",
        "Decision time is the kiosk-measured face lock -> rendered time on the demo laptop; server time shown beside it.",
    ):
        add(f"- {line}")
    for n in info.get("notes", []):
        add(f"- RUN_INFO note: {n}")
    if info["validation"]["warnings"]:
        add(f"- {len(info['validation']['warnings'])} validation warnings (see RUN_INFO.md).")
    add("")

    dash = dashboard(m)
    add("## 10. Dashboard JSON (`dashboard.json`, `GET /v1/metrics`-compatible shape)")
    add("")
    add("```json")
    add(json.dumps(dash, indent=1, default=str)[:6000])
    add("```")
    add("")
    return "\n".join(L), dash


def _clean(x):
    if isinstance(x, float) and math.isnan(x):
        return None
    if isinstance(x, dict):
        return {k: _clean(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_clean(v) for v in x]
    return x


def dashboard(m: dict) -> dict:
    pad = m.get("pad") or {}
    lat = m.get("latency") or {}
    mix = pad.get("decision_mix_final") or {}
    decisions = {d: sum(c.get(d, 0) for c in mix.values()) for d in ("ALLOW", "STEP_UP", "DENY", "NO_RESPONSE")}
    by_label: dict = {}
    for lab, r in (pad.get("apcer_by_label") or {}).items():
        by_label[lab] = {"n": r["n"], "accepted": r["k"], "apcer": r["rate"], "apcer_upper_95": r["ub95"],
                         "rule_of_3": (3 / r["n"]) if r["k"] == 0 and r["n"] else None, "low_n": r.get("low_n")}
    if pad.get("bpcer"):
        b = pad["bpcer"]
        su = pad["genuine_stepup_rate"]
        by_label["bona_fide"] = {"n": b["n"], "rejected": b["k"], "step_up": su["k"], "bpcer": b["rate"],
                                 "bpcer_upper_95": b["ub95"], "step_up_rate": su["rate"], "low_n": b.get("low_n")}

    def lsum(block):
        o = ((lat.get(block) or {}).get("overall") or {})
        return {"p50": o.get("p50"), "p95": o.get("p95"), "p95_ci95": o.get("p95_ci95"), "n": o.get("n", 0)}

    out = {
        "source": "eval/results/metrics.json",
        "generated_at_utc": m["RUN_INFO"]["generated_at_utc"],
        "dummy_data": m["RUN_INFO"]["dummy_data"],
        "split": pad.get("split"),
        "attempts": sum(decisions.values()),
        "decisions": decisions,
        "by_mode": {k: {"attacks_accepted": v["attacks_accepted"]["k"], "attacks": v["attacks_accepted"]["n"],
                        "bona_fide_denied": v["bpcer"]["k"], "bona_fide": v["bpcer"]["n"]}
                    for k, v in (pad.get("by_mode") or {}).items()},
        "reason_codes": pad.get("reason_codes_final", {}),
        "latency_ms": {"client": lsum("sla_allow_path"), "total": lsum("server_total"),
                       "liveness": {k: (((lat.get("stages") or {}).get("liveness") or {}).get("overall") or {}).get(k)
                                    for k in ("p50", "p95", "n")},
                       "match": {k: (((lat.get("stages") or {}).get("match") or {}).get("overall") or {}).get(k)
                                 for k in ("p50", "p95", "n")},
                       "client_source": lat.get("decision_time_source")},
        "by_label": by_label,
        "max_apcer": pad.get("max_apcer_system"),
        "hid_targets": [{"target": t["target"], "target_value": t["target_value"], "status": t["status"],
                         "measured": (t.get("measured") or {}).get("text")} for t in m.get("hid_targets", [])],
        "scenarios_summary": (m.get("scenarios") or {}).get("summary"),
    }
    return _clean(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--metrics", type=Path, default=RESULTS_DIR / "metrics.json")
    ap.add_argument("--out-dir", type=Path, default=None, help="default: directory of --metrics")
    ap.add_argument("--no-plots", action="store_true")
    a = ap.parse_args(argv)
    if not a.metrics.exists():
        print(f"{a.metrics} not found - run metrics.py first", file=sys.stderr)
        return 3
    m = json.loads(a.metrics.read_text(encoding="utf-8"))
    out = a.out_dir or a.metrics.parent
    eio.refuse_dummy_into_results([out], bool(m["RUN_INFO"].get("dummy_data")))
    out.mkdir(parents=True, exist_ok=True)
    cf = {} if a.no_plots else charts(m, out)
    runs_rel = "runs"
    text, dash = build(m, a.metrics, cf, runs_rel)
    (out / "SUMMARY.md").write_text(text, encoding="utf-8")
    eio.write_json(out / "dashboard.json", dash)
    print(f"wrote {out / 'SUMMARY.md'} and {out / 'dashboard.json'}" + (f" + {sum(len(v) for v in cf.values())} charts"
                                                                       if cf else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
