"""ISO/IEC 30107-3 PAD metrics + matcher FMR/FNMR + latency + SC1/SC2 scenario table.

Reads   eval/results/attempts.csv, comparisons.csv, scenarios.csv, exclusions.csv (all optional except
        that at least one of attempts/comparisons/scenarios must exist), config/thresholds.yaml,
        eval/targets.yaml, eval/scenarios/scenarios.yaml
Writes  <out-dir>/metrics.json, <out-dir>/det_*.png (+ _dark), <out-dir>/RUN_INFO.md (auto block only)

Usage (run from eval/):
  uv run python metrics.py                                   # real data -> results/
  uv run python metrics.py --attempts tests/fixtures/attempts_DUMMY.csv \
      --comparisons tests/fixtures/comparisons_DUMMY.csv --scenarios tests/fixtures/scenarios_DUMMY.csv \
      --exclusions tests/fixtures/exclusions_DUMMY.csv --out-dir /tmp/eval_dummy   # DUMMY demo, never into results/

Counting rules (PROTOCOL.md section 6) - final decision = after any step-up:
  APCER(system, species) = attacks whose FINAL decision is ALLOW (also via a passed step-up)
                           / attacks that got a decision (NO_RESPONSE -> APNRR; RATE_LIMITED/SYSTEM_ERROR
                           DENY = not evaluated -> excluded, which can only raise APCER)
  APCER(PAD, species)    = attacks whose liveness stage said PASS (UNKNOWN counted as PASS) / liveness evaluated
  BPCER (headline)       = bona fide whose FINAL decision is DENY (any cause; conservative) / bona fide responded
  BPCER (PAD-only)       = bona fide FINAL DENY attributable to PAD codes / bona fide responded
  step-up rate           = bona fide whose FIRST decision is STEP_UP (reported separately, not BPCER)
  FRR (transaction)      = bona fide whose FINAL decision is not ALLOW (incl. NO_RESPONSE) / all bona fide
"""

from __future__ import annotations

import argparse
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from evallib import EVAL_DIR, RESULTS_DIR, THRESHOLDS_PATH
from evallib import config as ecfg
from evallib import det as detlib
from evallib import io as eio
from evallib import schema as S
from evallib import stats as st
from scenarios import cases as scases

NAN = float("nan")
SCHEMA_VERSION = "hid-eval-metrics/1"


# ===================================================================== loading

def _f(v: str | None) -> float:
    try:
        return float(v) if v not in (None, "") else NAN
    except ValueError:
        return NAN


def prep_attempt(r: dict) -> dict:
    r = dict(r)
    r["_codes"] = S.split_codes(r.get("reason_codes"))
    r["_first_codes"] = S.split_codes(r.get("first_reason_codes"))
    for c in S.ATTEMPT_FLOAT_COLS:
        r["_" + c] = _f(r.get(c))
    r["mode"] = (r.get("mode") or "").upper()
    return r


def load_table(path: Path | None, validator, results_file: bool) -> dict:
    out = {"path": str(path) if path else None, "exists": False, "rows": [], "header": [], "errors": [],
           "warnings": [], "sha256": None}
    if path is None or not Path(path).exists():
        return out
    header, rows = eio.read_csv(Path(path))
    errs, warns = validator(rows, header, results_file=results_file)
    out.update(exists=True, rows=rows, header=header, errors=errs, warnings=warns, sha256=eio.sha256_file(Path(path)))
    return out


def _validate_exclusions(rows: list[dict], header: list[str], results_file: bool = True) -> tuple[list, list]:
    errs = []
    if rows and any(c not in header for c in S.EXCLUSION_COLUMNS):
        errs.append(f"exclusions.csv must have columns {S.EXCLUSION_COLUMNS}")
    for i, r in enumerate(rows, start=2):
        if not (r.get("reason") or "").strip():
            errs.append(f"exclusions.csv line {i}: every exclusion needs a written reason")
    return errs, []


# ===================================================================== PAD block

def _decision_mix(rows: list[dict], key: str = "decision") -> dict:
    c = Counter(r.get(key) or "NO_RESPONSE" for r in rows)
    return {d: int(c.get(d, 0)) for d in S.DECISIONS}


def _not_evaluated_deny(r: dict) -> bool:
    return r["decision"] == "DENY" and S.deny_cause(r["_codes"]) == "system"


def _low(n: int, minimum: int) -> bool:
    return n < minimum


def is_rate_limited(r: dict) -> bool:
    return "RATE_LIMITED" in r["_codes"] or "RATE_LIMITED" in r["_first_codes"]


def pad_block(rows: list[dict], minimums: dict) -> dict:
    rl = [r for r in rows if is_rate_limited(r)]
    rows = [r for r in rows if not is_rate_limited(r)]
    gen = [r for r in rows if r["attempt_class"] == "genuine"]
    zero = [r for r in rows if r["attempt_class"] == "zero_effort"]
    att = [r for r in rows if r["attempt_class"] == "attack"]
    inj = [r for r in rows if r["attempt_class"] == "injection"]
    min_att = int(minimums.get("attacks_per_species_test", 30))
    min_bona = int(minimums.get("bona_fide_test", 120))

    out: dict = {
        "counts": {
            "bona_fide": len(gen), "zero_effort_impostor": len(zero), "attacks": len(att), "injection": len(inj),
            "by_species": {sp: sum(1 for r in rows if r["species"] == sp) for sp in S.SPECIES},
            "by_lighting": dict(Counter(r["lighting"] for r in rows)),
            "subjects": sorted({r["subject_id"] for r in rows}),
        },
        "apcer_system": {}, "apcer_pad": {}, "attack_stepup": {}, "attack_stepup_bypass": {},
        "attack_not_evaluated": {}, "attack_quality_rejected": {}, "iapmr": {},
        "rate_limited": {
            "total": len(rl), "by_species": dict(Counter(r["species"] for r in rl)),
            "attempt_ids": [r["attempt_id"] for r in rl][:50],
            "note": "RATE_LIMITED rows are flagged and excluded from APCER, BPCER and FRR (lead decision, round 2); "
                    "capture.py resets the limiter before attempts (POST /v1/admin/rate-limit/reset)"},
    }
    ev_all: list[dict] = []
    for sp in S.ATTACK_SPECIES:
        g = [r for r in att if r["species"] == sp]
        if not g:
            continue
        ev = [r for r in g if r["decision"] in S.RESPONDED and not _not_evaluated_deny(r)]
        ev_all += ev
        rec = st.rate(sum(r["decision"] == "ALLOW" for r in ev), len(ev))
        rec.update(species=sp, label=S.SPECIES_TO_LABEL[sp], hid_scenario=S.HID_SCENARIO[S.SPECIES_TO_LABEL[sp]],
                   low_n=_low(len(ev), min_att), runs=sorted({r["run_id"] for r in g}))
        out["apcer_system"][sp] = rec
        pad_ev = [r for r in ev if r.get("liveness_result") in ("PASS", "UNSURE", "FAIL", "UNKNOWN")]
        prec = st.rate(sum(r["liveness_result"] in ("PASS", "UNKNOWN") for r in pad_ev), len(pad_ev))
        prec["unknown_counted_as_pass"] = sum(r["liveness_result"] == "UNKNOWN" for r in pad_ev)
        prec["unsure"] = sum(r["liveness_result"] == "UNSURE" for r in pad_ev)
        out["apcer_pad"][sp] = prec
        su = [r for r in ev if r["first_decision"] == "STEP_UP"]
        out["attack_stepup"][sp] = st.rate(len(su), len(ev)) | {
            "by_trigger": dict(Counter(S.stepup_trigger(r["_first_codes"]) for r in su))}
        out["attack_stepup_bypass"][sp] = st.rate(sum(r["decision"] == "ALLOW" for r in su), len(su))
        out["attack_not_evaluated"][sp] = {
            "no_response": sum(r["decision"] == "NO_RESPONSE" for r in g),
            "system_error": sum(_not_evaluated_deny(r) for r in g),
            "rate_limited_excluded": sum(1 for r in rl if r["species"] == sp),
        }
        out["attack_quality_rejected"][sp] = sum(
            r["decision"] == "DENY" and S.deny_cause(r["_codes"]) == "quality" for r in ev)
        tgt = [r for r in ev if r.get("target_user_id")]
        out["iapmr"][sp] = st.rate(
            sum(r["decision"] == "ALLOW" and r.get("candidate_user_id") == r["target_user_id"] for r in tgt), len(tgt))

    present = [v for v in out["apcer_system"].values() if v["n"] > 0]
    if present:
        worst_ub = max(present, key=lambda v: (v["ub95"], v["rate"]))
        worst_pt = max(present, key=lambda v: (v["rate"], v["ub95"]))
        out["max_apcer_system"] = {k: worst_ub[k] for k in ("species", "k", "n", "rate", "ub95", "text", "low_n")}
        out["max_apcer_system"]["rule"] = "species with the highest one-sided 95% upper bound (headline)"
        out["max_apcer_point"] = {k: worst_pt[k] for k in ("species", "k", "n", "rate", "ub95", "text")}
    else:
        out["max_apcer_system"] = None
        out["max_apcer_point"] = None
    out["species_missing"] = [sp for sp in ATTACK_REQUIRED if sp not in out["apcer_system"]]

    # HID scenario (coarse label) aggregation
    by_label: dict = {}
    for lab in [x for x in S.LABELS if x not in ("bona_fide", "injection")]:
        ev = [r for r in ev_all if r["label"] == lab]
        if ev:
            rec = st.rate(sum(r["decision"] == "ALLOW" for r in ev), len(ev))
            rec.update(hid_scenario=S.HID_SCENARIO[lab], species=sorted({r["species"] for r in ev}),
                       low_n=_low(len(ev), min_att))
            by_label[lab] = rec
    out["apcer_by_label"] = by_label

    # bona fide
    resp_b = [r for r in gen if r["decision"] in S.RESPONDED]
    deny_b = [r for r in resp_b if r["decision"] == "DENY"]
    causes = Counter(S.deny_cause(r["_codes"]) for r in deny_b)
    out["bpcer"] = st.rate(len(deny_b), len(resp_b)) | {
        "definition": "bona fide FINAL DENY (any cause, conservative) / bona fide with a decision",
        "low_n": _low(len(resp_b), min_bona), "runs": sorted({r["run_id"] for r in gen})}
    out["bpcer_by_cause"] = {c: int(causes.get(c, 0)) for c in
                             ("pad", "quality", "match", "schedule", "fallback", "system", "other")}
    out["bpcer_pad_only"] = st.rate(causes.get("pad", 0), len(resp_b)) | {
        "definition": "bona fide FINAL DENY attributable to PAD codes (SPOOF_*, MASK_CUE_*, CHALLENGE_FAILED, "
                      "INJECTION_*, LIVENESS_UNSURE) / bona fide with a decision (ISO-style)"}
    out["bpcer_by_lighting"] = {
        lg: st.rate(sum(r["decision"] == "DENY" for r in resp_b if r["lighting"] == lg),
                    sum(1 for r in resp_b if r["lighting"] == lg))
        for lg in S.LIGHTING if any(r["lighting"] == lg for r in resp_b)}
    out["bpcer_by_distance"] = {
        d: st.rate(sum(r["decision"] == "DENY" for r in resp_b if r["distance"] == d),
                   sum(1 for r in resp_b if r["distance"] == d))
        for d in S.DISTANCE if any(r["distance"] == d for r in resp_b)}
    pad_b = [r for r in resp_b if r.get("liveness_result") in ("PASS", "UNSURE", "FAIL", "UNKNOWN")]
    out["bpcer_pad_subsystem"] = st.rate(sum(r["liveness_result"] == "FAIL" for r in pad_b), len(pad_b)) | {
        "definition": "bona fide whose liveness stage said FAIL on the first decision / liveness evaluated"}
    out["bona_fide_pad_unsure"] = st.rate(sum(r["liveness_result"] == "UNSURE" for r in pad_b), len(pad_b))
    su_b = [r for r in resp_b if r["first_decision"] == "STEP_UP"]
    out["genuine_stepup_rate"] = st.rate(len(su_b), len(resp_b)) | {
        "definition": "bona fide whose FIRST decision is STEP_UP (incl. RANDOM_CHALLENGE and RECAPTURE) / "
                      "bona fide with a decision - reported separately, never counted in BPCER",
        "by_type": dict(Counter((r.get("next_action_type") or "UNKNOWN") for r in su_b)),
        "by_trigger": dict(Counter(S.stepup_trigger(r["_first_codes"]) for r in su_b))}
    non_random = [r for r in su_b if S.stepup_trigger(r["_first_codes"]) != "random_challenge"]
    out["genuine_stepup_rate_excl_random"] = st.rate(len(non_random), len(resp_b))
    out["genuine_stepup_by_lighting"] = {
        lg: st.rate(sum(r["first_decision"] == "STEP_UP" for r in resp_b if r["lighting"] == lg),
                    sum(1 for r in resp_b if r["lighting"] == lg))
        for lg in S.LIGHTING if any(r["lighting"] == lg for r in resp_b)}
    out["stepup_clearance"] = st.rate(sum(r["decision"] == "ALLOW" for r in su_b), len(su_b), higher_is_better=True)
    out["frr_transaction"] = st.rate(sum(r["decision"] != "ALLOW" for r in gen), len(gen)) | {
        "definition": "bona fide FINAL decision != ALLOW, incl. NO_RESPONSE and unresolved STEP_UP / all bona fide",
        "low_n": _low(len(gen), min_bona)}
    out["frr_first_pass"] = st.rate(sum(r["first_decision"] != "ALLOW" for r in gen), len(gen))
    out["bpnrr"] = st.rate(sum(r["decision"] == "NO_RESPONSE" for r in gen), len(gen))
    out["apnrr"] = st.rate(sum(r["decision"] == "NO_RESPONSE" for r in att), len(att))
    out["far_transaction_attacks"] = st.rate(sum(r["decision"] == "ALLOW" for r in att), len(att)) | {
        "definition": "all attack presentations whose FINAL decision is ALLOW / all attack presentations"}
    if zero:
        resp_z = [r for r in zero if r["decision"] in S.RESPONDED]
        out["far_zero_effort"] = st.rate(sum(r["decision"] == "ALLOW" for r in resp_z), len(resp_z))
    with_cand = [r for r in resp_b if r.get("candidate_user_id") and r.get("target_user_id")]
    out["rank1_live"] = st.rate(sum(r["candidate_user_id"] == r["target_user_id"] for r in with_cand), len(with_cand),
                                higher_is_better=True)
    if out["max_apcer_point"] and resp_b:
        out["acer_academic_only"] = {
            "value": (out["max_apcer_point"]["rate"] + out["bpcer_pad_only"]["rate"]) / 2,
            "note": "ACER = (max APCER + BPCER(PAD-only))/2 - academic summary only; ISO/IEC 30107-3 does not "
                    "endorse it. Always read APCER per species + BPCER."}
    n_err = sum(r["decision"] == "ALLOW" for r in ev_all) + causes.get("pad", 0)
    n_all = len(ev_all) + len(resp_b)
    if n_all:
        acc_err = st.rate(n_err, n_all)
        lo, hi = acc_err["ci95_two_sided"]
        out["liveness_accuracy_hid_style"] = {
            "accuracy": 1 - acc_err["rate"], "accuracy_lb95": 1 - acc_err["ub95"], "errors": acc_err,
            "accuracy_ci95_two_sided": [1 - hi, 1 - lo],
            "definition": "1 - (attacks with FINAL ALLOW + bona fide FINAL DENY for PAD reasons) / "
                          "(attacks evaluated + bona fide with a decision)",
            "class_mix": {"attacks": len(ev_all), "bona_fide": len(resp_b)},
            "note": "translation of HID's 'liveness accuracy' only; depends on the class mix (a reject-all system "
                    "scores attacks/(attacks+bona fide)). Read per-species APCER + BPCER instead."}
    if inj:
        resp_i = [r for r in inj if r["decision"] in S.RESPONDED]
        out["injection"] = {
            "note": "reported separately from PAD (ISO/IEC 30107-3 and FIDO exclude injection; CEN/TS 18099)",
            "accepted": st.rate(sum(r["decision"] == "ALLOW" for r in resp_i), len(resp_i)),
            "flagged_injection": st.rate(sum("INJECTION_VIRTUAL_CAMERA" in r["_codes"] for r in resp_i), len(resp_i),
                                         higher_is_better=True),
            "no_response": sum(r["decision"] == "NO_RESPONSE" for r in inj)}
    out["decision_mix_final"] = {sp: _decision_mix([r for r in rows if r["species"] == sp])
                                 for sp in S.SPECIES if any(r["species"] == sp for r in rows)}
    if zero:
        out["decision_mix_final"]["zero_effort_impostor"] = _decision_mix(zero)
        out["decision_mix_final"]["bona_fide"] = _decision_mix(gen)
    out["decision_mix_first"] = {sp: _decision_mix([r for r in rows if r["species"] == sp], "first_decision")
                                 for sp in S.SPECIES if any(r["species"] == sp for r in rows)}
    out["by_mode"] = {}
    for m in sorted({r["mode"] for r in rows if r["mode"]}):
        a_m = [r for r in ev_all if r["mode"] == m]
        b_m = [r for r in resp_b if r["mode"] == m]
        out["by_mode"][m] = {
            "attacks_accepted": st.rate(sum(r["decision"] == "ALLOW" for r in a_m), len(a_m)),
            "bpcer": st.rate(sum(r["decision"] == "DENY" for r in b_m), len(b_m)),
            "genuine_stepup_rate": st.rate(sum(r["first_decision"] == "STEP_UP" for r in b_m), len(b_m))}
    out["reason_codes_final"] = dict(Counter(c for r in rows for c in r["_codes"]).most_common())
    out["liveness_result_source"] = dict(Counter(r.get("liveness_result_source") or "none" for r in rows))
    return out


ATTACK_REQUIRED = ["print", "phone_photo", "phone_video", "print_eyecut"]  # HID's 4 scenarios, min. coverage


# ===================================================================== latency block

def latency_block(rows: list[dict], sla_ms: float, n_boot: int, seed: int, min_n: int) -> dict:
    """Decision time = client face lock -> decision rendered (kiosk 'rendered' beacon, latency_source kiosk_render).
    Server latency_ms.total reported alongside. RATE_LIMITED rows excluded (as in the PAD block)."""
    resp = [r for r in rows if r["decision"] in S.RESPONDED and not is_rate_limited(r)]
    src_counts = Counter(r.get("latency_source") or "none" for r in resp)
    use_src = "kiosk_render" if src_counts.get("kiosk_render") else (
        "edge_face_lock_to_decision" if src_counts.get("edge_face_lock_to_decision") else None)
    out: dict = {
        "sla_ms": sla_ms,
        "decision_time_source": use_src or "not measured",
        "definition": "decision time = client face lock -> decision rendered on the kiosk (POST /v1/attempt/{id}/"
                      "rendered beacon, joined from the SSE 'rendered' event; latency_ms column). SLA scope = bona "
                      "fide attempts whose FIRST decision is ALLOW (ALLOW path). server_total = edge latency_ms.total "
                      "(excludes the ~1 s capture window and the browser). p50/p95 with percentile-bootstrap 95% CI.",
        "latency_source_counts": dict(src_counts),
        "rows_without_decision_time": sum(1 for r in resp if r.get("latency_source") != use_src),
    }

    def vals(rs, col, only_src=None):
        return [r["_" + col] for r in rs if not math.isnan(r["_" + col])
                and (only_src is None or r.get("latency_source") == only_src)]

    def summ(rs, col, sla=None, only_src=None):
        groups = {"overall": rs} | {m: [r for r in rs if r["mode"] == m] for m in sorted({r["mode"] for r in rs})}
        res = {}
        for g, rr in groups.items():
            rec = st.latency_summary(vals(rr, col, only_src), sla, n_boot=n_boot, seed=seed, low_n=min_n)
            rec["runs"] = sorted({r["run_id"] for r in rr})
            res[g] = rec
        return res

    allow_path = [r for r in resp if r["attempt_class"] == "genuine" and r["first_decision"] == "ALLOW"]
    out["sla_allow_path"] = summ(allow_path, "latency_ms", sla_ms, use_src) if use_src else {
        "overall": {"n": 0, "note": "client decision time not measured (no kiosk 'rendered' events)"}}
    out["all_first_decisions"] = summ(resp, "latency_ms", sla_ms, use_src) if use_src else {"overall": {"n": 0}}
    out["server_total"] = summ(resp, "lat_server_total_ms")
    out["server_total_allow_path"] = summ(allow_path, "lat_server_total_ms")
    out["measured"] = bool(use_src) and out["sla_allow_path"]["overall"]["n"] > 0
    if not out["measured"]:
        out["note"] = ("client face-lock -> rendered time NOT measured in these rows; server_total is shown but is not "
                       "the 2 s decision-time metric and must not be presented as such.")
    by = {}
    for sp in S.SPECIES:
        rs = [r for r in resp if r["species"] == sp]
        if not rs:
            continue
        cell = {}
        for d in ("ALLOW", "STEP_UP", "DENY"):
            rd = [r for r in rs if r["decision"] == d]
            if rd:
                cell[d] = {
                    "client": st.latency_summary(vals(rd, "latency_ms", use_src) if use_src else [], None,
                                                 n_boot=n_boot, seed=seed, low_n=min_n),
                    "server_total": st.latency_summary(vals(rd, "lat_server_total_ms"), None, n_boot=n_boot,
                                                       seed=seed, low_n=min_n)}
        by[sp] = cell
    out["by_species_final_decision"] = by
    out["stages"] = {name: summ(resp, col) for name, col in (
        ("server_total", "lat_server_total_ms"), ("liveness", "lat_liveness_ms"), ("match", "lat_match_ms"),
        ("schedule", "lat_schedule_ms"), ("policy", "lat_policy_ms"))}
    su = [r for r in resp if r["first_decision"] == "STEP_UP"]
    out["stepup_verification_time"] = summ(su, "stepup_ms")
    return out


# ===================================================================== matcher block

def _scores(rows: list[dict], split: str, genuine: int) -> np.ndarray:
    return np.array([float(r["score"]) for r in rows if r["split"] == split and int(r["genuine"]) == genuine])


def _impostor_units(rows: list[dict], split: str) -> dict:
    """Independence units behind the impostor comparisons of one split (DE-07): each probe image is compared
    with every other gallery subject, so comparisons are not independent Bernoulli trials. The claim gate uses
    distinct UNORDERED subject pairs ({A,B}: A's probes vs B's gallery and B's probes vs A's gallery are one
    identity pair, T-02), the most conservative unit available."""
    imp = [r for r in rows if r["split"] == split and int(r["genuine"]) == 0]
    return {"comparisons": len(imp), "probe_images": len({r["probe_attempt_id"] for r in imp}),
            "subject_pairs": len({_pair_key(r) for r in imp})}


def _pair_key(r: dict) -> tuple[str, str]:
    a, b = r["probe_subject"], r["gallery_subject"]
    return (a, b) if a <= b else (b, a)


def _pair_level_fmr(rows: list[dict], split: str, t: float) -> dict:
    """FMR over unordered impostor subject pairs: a pair is a false match if ANY of its comparisons is >= t."""
    pairs: dict[tuple[str, str], bool] = {}
    for r in rows:
        if r["split"] == split and int(r["genuine"]) == 0:
            key = _pair_key(r)
            pairs[key] = pairs.get(key, False) or float(r["score"]) >= t
    return st.rate(sum(pairs.values()), len(pairs))


def _rank1(rows: list[dict], split: str) -> dict:
    best: dict[str, tuple[float, str, str]] = {}
    for r in rows:
        if r["split"] != split:
            continue
        s = float(r["score"])
        key = r["probe_attempt_id"]
        if key not in best or s > best[key][0]:
            best[key] = (s, r["gallery_subject"], r["probe_subject"])
    k = sum(1 for s, gal, probe in best.values() if gal == probe)
    return st.rate(k, len(best), higher_is_better=True)


def match_block(cmp_rows: list[dict], th: dict, calib_split: str, report_split: str, out_dir: Path,
                make_plots: bool) -> dict:
    out: dict = {}
    th_on = eio.thresholds_for_mode(th, "ONLINE")
    th_off = eio.thresholds_for_mode(th, "OFFLINE")
    local = (th.get("match") or {}).get("local") or {}
    pctl = float(local.get("calibration_impostor_percentile", 99.8))
    delta = float((th.get("offline") or {}).get("match_offline_delta", 0.05))
    for matcher in sorted({r["matcher"] for r in cmp_rows}):
        m = [r for r in cmp_rows if r["matcher"] == matcher]
        if matcher == "arcface":
            t_on = float(th_on["match"]["local"]["allow_min_cosine"])
            t_off = float(th_off["match"]["local"]["allow_min_cosine"])
            src = "config/thresholds.yaml match.local.allow_min_cosine (online) / offline override"
        else:
            t_on = float(th_on["match"]["rekognition"]["allow_min_similarity"]) / 100.0
            t_off = t_on
            src = "config/thresholds.yaml match.rekognition.allow_min_similarity / 100"
        g_dev, i_dev = _scores(m, calib_split, 1), _scores(m, calib_split, 0)
        g_test, i_test = _scores(m, report_split, 1), _scores(m, report_split, 0)
        live = [r for r in m if r["source"] == "live"]
        g_test_live, i_test_live = _scores(live, report_split, 1), _scores(live, report_split, 0)
        cal = detlib.calibrate_threshold(i_dev, pctl)
        cal["split"] = calib_split
        cal["sources"] = dict(Counter(r["source"] for r in m if r["split"] == calib_split and r["genuine"] == "0"))
        t_cal = cal["threshold"]
        if not math.isnan(t_cal):
            cal["suggested_allow_min_cosine"] = t_cal
            cal["suggested_offline_allow_min_cosine"] = t_cal + delta
            cal["note"] = (f"{pctl}th percentile of {cal['n_impostor']} {calib_split}-split impostor scores; offline "
                           f"= calibrated + match_offline_delta ({delta}). Write into config/thresholds.yaml via the "
                           "policy-engine owner, then freeze before the test run.")
            if not cal["resolution_ok"]:
                cal["warning"] = (f"only {cal['n_impostor']} impostor scores: the {pctl}th percentile is not "
                                  f"resolvable below the max (need >= {cal['n_needed_for_resolution']}); add LFW "
                                  "padding or more probes")

        def at(t: float, g: np.ndarray, i: np.ndarray) -> dict:
            if math.isnan(t):
                return {"threshold": t}
            kfm, ni, kfnm, ng = detlib.counts_at(g, i, t)
            return {"threshold": t, "fmr": st.rate(kfm, ni), "fnmr": st.rate(kfnm, ng)}

        blk = {
            "configured_threshold_source": src,
            "counts": {s: {"genuine": len(_scores(m, s, 1)), "impostor": len(_scores(m, s, 0))}
                       for s in S.COMPARISON_SPLITS},
            "sources": dict(Counter(r["source"] for r in m)),
            "models": sorted({r.get("model") or "" for r in m}),
            "runs": sorted({r.get("run_id") or "" for r in m}),
            "calibration": cal,
            "test": {
                "split": report_split,
                "at_configured_online": at(t_on, g_test, i_test),
                "at_configured_online_live": at(t_on, g_test_live, i_test_live),
                "at_configured_offline": at(t_off, g_test, i_test),
                "at_calibrated": at(t_cal, g_test, i_test),
                "at_calibrated_offline": at(t_cal + delta if not math.isnan(t_cal) else NAN, g_test, i_test),
                "eer": detlib.eer(g_test, i_test),
                "rank1": _rank1(m, report_split),
            },
            "dev_tuned_on": {
                "split": calib_split,
                "at_configured_online": at(t_on, g_dev, i_dev),
                "at_calibrated": at(t_cal, g_dev, i_dev),
                "eer": detlib.eer(g_dev, i_dev),
            },
            "cross_split_supplementary": at(t_on, _scores(m, "cross", 1), _scores(m, "cross", 0)),
            "trials_needed_fmr_0p2pct": {f"{k}_errors": st.trials_needed(0.002, k) for k in (0, 1, 2)},
        }
        cfg = blk["test"]["at_configured_online"]
        if "fmr" in cfg and (cfg["fmr"]["n"] + cfg["fnmr"]["n"]):
            err = st.rate(cfg["fmr"]["k"] + cfg["fnmr"]["k"], cfg["fmr"]["n"] + cfg["fnmr"]["n"])
            lo, hi = err["ci95_two_sided"]
            blk["test"]["verification_accuracy_at_configured"] = {
                "accuracy": 1 - err["rate"], "accuracy_lb95": 1 - err["ub95"], "accuracy_ci95_two_sided": [1 - hi, 1 - lo],
                "errors": err, "class_mix": {"genuine": cfg["fnmr"]["n"], "impostor": cfg["fmr"]["n"]},
                "note": "HID-style 'face-auth accuracy' translation; depends on the genuine:impostor mix - read FMR "
                        "and FNMR."}
        units = _impostor_units(live, report_split)
        needed = blk["trials_needed_fmr_0p2pct"]["0_errors"]
        blk["test"]["impostor_units_live"] = units
        if not math.isnan(t_on):
            blk["test"]["fmr_subject_pair_level_live"] = _pair_level_fmr(live, report_split, t_on)
        blk["test"]["fmr_claim_supportable"] = units["subject_pairs"] >= needed
        blk["test"]["fmr_claim_basis"] = (
            f"{units['subject_pairs']} distinct unordered live impostor subject pairs (from {units['comparisons']} "
            f"comparisons of {units['probe_images']} probe images) vs {needed} needed at 0 errors; comparisons "
            "sharing a probe image or subject are not independent trials and LFW padding is excluded")
        if make_plots and (len(g_test) and len(i_test) or len(g_dev) and len(i_dev)):
            pts = []
            for lab, rec in (("configured", blk["test"]["at_configured_online"]),
                             ("calibrated (dev)", blk["test"]["at_calibrated"])):
                if "fmr" in rec:
                    pts.append((f"{lab} t={rec['threshold']:.3f}", rec["fmr"]["rate"], rec["fnmr"]["rate"]))
            files = _plot_det_safe(out_dir / f"det_{matcher}.png", (g_test, i_test), (g_dev, i_dev), pts,
                                   f"Face matcher DET - {matcher}",
                                   f"test: {len(g_test)} genuine / {len(i_test)} impostor comparisons"
                                   f"  ·  dev: {len(g_dev)} / {len(i_dev)}")
            blk["det_png"] = [Path(p).name for p in files]
        out[matcher] = blk
    return out


def _plot_det_safe(path, test, dev, pts, title, n_text) -> list[str]:
    from evallib import style
    return style.plot_det_matcher(path, test if len(test[0]) and len(test[1]) else None,
                                  dev if len(dev[0]) and len(dev[1]) else None, pts, title, n_text)


PAD_EVALUATED = ("PASS", "UNSURE", "FAIL", "UNKNOWN")


def latency_hist(rows: list[dict], lat: dict, out_dir: Path, split: str) -> list[str]:
    """Histogram of the client decision time on the ALLOW path, one panel per mode (raw values needed)."""
    from evallib import style
    src = lat.get("decision_time_source")
    if not lat.get("measured") or src not in ("kiosk_render", "edge_face_lock_to_decision"):
        return []
    sel = [r for r in rows if r["decision"] in S.RESPONDED and not is_rate_limited(r) and r["attempt_class"] == "genuine"
           and r["first_decision"] == "ALLOW" and r.get("latency_source") == src and not math.isnan(r["_latency_ms"])]
    per = {m: np.array([r["_latency_ms"] for r in sel if r["mode"] == m]) for m in sorted({r["mode"] for r in sel})}
    files = style.plot_latency_hist(out_dir / "latency_hist.png", per, float(lat["sla_ms"]),
                                    f"Decision time, face lock -> rendered (bona fide, ALLOW path, {split} split)",
                                    f"source: {src}; p50/p95 = numpy linear quantiles; target = "
                                    f"latency_budget_ms.total_decision")
    return [Path(p).name for p in files]


def pad_det(rows: list[dict], out_dir: Path, split: str) -> list[str]:
    """PAD DET on the first-decision liveness score; only rows where the liveness stage actually ran."""
    from evallib import style
    ok = [r for r in rows if r.get("liveness_result") in PAD_EVALUATED and not math.isnan(r["_s_pad"])]
    bona = np.array([r["_s_pad"] for r in ok if r["attempt_class"] == "genuine"])
    per = {}
    for sp in S.ATTACK_SPECIES:
        a = np.array([r["_s_pad"] for r in ok if r["species"] == sp])
        if len(a):
            per[sp] = (bona, a)
    if not per or not len(bona):
        return []
    files = style.plot_det_pad(out_dir / "det_pad.png", per,
                               f"PAD DET per species - liveness score (first decision), {split} split")
    return [Path(p).name for p in files]


# ===================================================================== scenarios block

def scenario_block(scn_rows: list[dict], cases: dict[str, dict], attempts: list[dict]) -> dict:
    """SC1/SC2 gate table keyed by docs/POLICY_TEST_CASES.md IDs (sections 5-7; lead decision round 2).
    Status comes only from recorded runs (scenarios.csv); live evidence = capture.py rows tagged --scenario <ID>."""
    latest: dict[str, dict] = {}
    for r in scn_rows:
        sid = r["scenario_id"]
        if sid not in latest or r["ts_utc"] >= latest[sid]["ts_utc"]:
            latest[sid] = r
    live = defaultdict(list)
    for r in attempts:
        if r.get("scenario"):
            live[r["scenario"]].append(r)
    ids = [k for k, c in cases.items() if c["gate"]]
    ids += sorted((set(latest) | set(live)) - set(ids))
    table = []
    for sid in ids:
        c = cases.get(sid, {})
        row = latest.get(sid)
        exp_final = c.get("final_decision")
        lv = live.get(sid, [])
        table.append({
            "id": sid, "challenge": c.get("challenge") or (row or {}).get("challenge") or "UNKNOWN",
            "gate": bool(c.get("gate")), "section": c.get("section"), "setup": c.get("setup"),
            "expected": scases.expected_text(c) if c else (row or {}).get("expected"),
            "status": row["status"] if row else "NOT_RUN",
            "backend": row["backend"] if row else None, "run_id": row["run_id"] if row else None,
            "ts_utc": row["ts_utc"] if row else None,
            "observed": (f"{row['observed_decision']} [{row['observed_codes']}]".strip() if row else None),
            "detail": row["detail"] if row else "no recorded run",
            "live_evidence": {"n": len(lv), "expected_final": exp_final,
                              "matching_expected": sum(1 for r in lv if exp_final and r["decision"] == exp_final),
                              "runs": sorted({r["run_id"] for r in lv}),
                              "attempt_ids": [r["attempt_id"] for r in lv][:10]},
        })
    summary = {ch: dict(Counter(t["status"] for t in table if t["challenge"] == ch and t["gate"]))
               for ch in ("SC1", "SC2")}
    return {"source": str(scases.DOC), "gate_ids": len([t for t in table if t["gate"]]), "table": table,
            "summary": summary,
            "rule": "PASS only from a recorded run (scenarios.csv); IDs without a run are NOT_RUN. "
                    "Expected values parsed from docs/POLICY_TEST_CASES.md at run time."}


# ===================================================================== targets

FAR_DEPENDENT_STATUS = "NOT CONFIRMED (dependent comparisons; see fmr_claim_basis)"


def _far_row(arc_test: dict, fmr: dict | None, target: float, err_status, pad: dict | None) -> dict:
    """FAR target row (T-01): status from the subject-pair-level FMR (independent units), never from the
    comparison-level CP bound; the comparison-level rate is shown for information only."""
    pair = arc_test.get("fmr_subject_pair_level_live")
    info = None if not fmr or not fmr["n"] else {"rate": fmr["rate"], "ub95": fmr["ub95"], "text": fmr["text"]}
    if pair and pair.get("n"):
        measured = {"rate": pair["rate"], "ub95": pair["ub95"], "n": pair["n"], "text": pair["text"],
                    "unit": "unordered live impostor subject pairs",
                    "what": "matcher FMR at configured threshold, test split, live only (LFW excluded); a pair is a "
                            "false match if any of its comparisons is >= threshold",
                    "comparison_level": info}
        status = err_status(pair, target)
    else:
        measured = None if info is None else {**info, "comparison_level": info,
                                              "what": "comparison-level only; comparisons are not independent"}
        status = "NO_DATA" if info is None else FAR_DEPENDENT_STATUS
    return {"target": "False acceptance rate (FAR)", "target_value": target, "measured": measured,
            "status": status, "basis": arc_test.get("fmr_claim_basis"),
            "iso_view": None if not pad else f"live attacks reaching ALLOW {pad['far_transaction_attacks']['text']}"}


def target_rows(pad: dict | None, match: dict, lat: dict | None, targets: dict) -> list[dict]:
    rows = []

    def err_status(rec: dict | None, target: float) -> str:
        if not rec or rec.get("n", 0) == 0:
            return "NO_DATA"
        if rec["ub95"] <= target:
            return "SUPPORTED (95% UB <= target)"
        if rec["rate"] <= target:
            return (f"NOT CONFIRMED (point <= target, UB > target; N needed at 0 errors = "
                    f"{st.trials_needed(target, 0)}, at {rec['k']} errors = {st.trials_needed(target, rec['k'])})")
        return "NOT MET (point estimate worse than target)"

    la = (pad or {}).get("liveness_accuracy_hid_style")
    rows.append({
        "target": "Liveness detection accuracy", "target_value": targets["liveness_accuracy"],
        "measured": None if not la else {"accuracy": la["accuracy"], "lb95": la["accuracy_lb95"],
                                         "text": f"{la['errors']['n'] - la['errors']['k']}/{la['errors']['n']} correct"
                                                 f" = {st.pct(la['accuracy'], up=False)} (95% LB = "
                                                 f"{st.pct(la['accuracy_lb95'], up=False)})",
                                         "class_mix": la["class_mix"]},
        "status": "NO_DATA" if not la else err_status(la["errors"], 1 - targets["liveness_accuracy"]),
        "iso_view": None if not pad or not pad.get("max_apcer_system") else
        f"max APCER {pad['max_apcer_system']['text']} ({pad['max_apcer_system']['species']}); "
        f"BPCER {pad['bpcer']['text']}",
    })
    arc = match.get("arcface") or {}
    arc_test = arc.get("test") or {}
    op = arc_test.get("at_configured_online_live") or arc_test.get("at_configured_online") or {}
    fnmr = op.get("fnmr")
    rows.append({
        "target": "Face authentication accuracy", "target_value": targets["face_auth_accuracy"],
        "measured": None if not fnmr or not fnmr["n"] else {
            "accuracy": 1 - fnmr["rate"], "lb95": 1 - fnmr["ub95"], "n": fnmr["n"],
            "text": f"1 - FNMR at configured threshold: {fnmr['n'] - fnmr['k']}/{fnmr['n']} = "
                    f"{st.pct(1 - fnmr['rate'], up=False)} (95% LB = {st.pct(1 - fnmr['ub95'], up=False)})",
            "what": "live genuine comparisons only (LFW excluded), test split; probe images of one subject are not "
                    "independent trials, so the LB is optimistic for a small cohort"},
        "status": err_status(fnmr, 1 - targets["face_auth_accuracy"]),
        "iso_view": None if not pad else f"live rank-1 {pad['rank1_live']['text']}",
    })
    rows.append(_far_row(arc_test, op.get("fmr"), targets["far"], err_status, pad))
    frr = (pad or {}).get("frr_transaction")
    rows.append({
        "target": "False rejection rate (FRR)", "target_value": targets["frr"],
        "measured": None if not frr or not frr["n"] else {"rate": frr["rate"], "ub95": frr["ub95"], "text": frr["text"],
                                                          "what": "transaction FRR, bona fide, final decision"},
        "status": err_status(frr, targets["frr"]),
        "iso_view": None if not pad else f"first-pass FRR {pad['frr_first_pass']['text']}",
    })
    sla = (lat or {}).get("sla_allow_path", {}).get("overall") if lat else None
    if sla and sla.get("n"):
        hi = sla["p95_ci95"][1]
        status = ("SUPPORTED (bootstrap 95% CI of p95 < target)" if hi < targets["decision_time_ms"] else
                  "NOT CONFIRMED (p95 < target, CI crosses)" if sla["p95"] < targets["decision_time_ms"] else "NOT MET")
        if sla.get("low_n"):
            status += " [LOW_N]"
        meas = {"p50": sla["p50"], "p95": sla["p95"], "p95_ci95": sla["p95_ci95"], "max": sla["max"], "n": sla["n"],
                "within_sla": sla["within_sla"]["text"],
                "text": f"p95 {sla['p95']:.0f} ms (95% CI {sla['p95_ci95'][0]:.0f}-{sla['p95_ci95'][1]:.0f}), "
                        f"p50 {sla['p50']:.0f} ms, n={sla['n']}"}
    else:
        status, meas = "NOT MEASURED", None
    rows.append({"target": "Decision time (face lock -> decision)", "target_value": targets["decision_time_ms"],
                 "measured": meas, "status": status, "iso_view": "ALLOW path, bona fide; see latency block"})
    return rows


def trials_table() -> list[dict]:
    claims = [("FAR / FMR <= 0.2%", 0.002), ("FRR <= 0.6%", 0.006), ("APCER <= 5% per species", 0.05),
              ("APCER <= 2% per species", 0.02), ("BPCER <= 15% (iBeta cap)", 0.15)]
    return [{"claim": c, "p": p, **{f"n_{k}_errors": st.trials_needed(p, k) for k in (0, 1, 2)}} for c, p in claims]


# ===================================================================== RUN_INFO.md

RUN_INFO_TEMPLATE = """# RUN_INFO - evaluation run record

Manual section: edit freely; `metrics.py` only rewrites the block between the AUTO markers.

- Date / venue: 14 Nov 2026, PES University (fill in)
- Kiosk hardware (laptop model, CPU, RAM):
- Camera (model / label):
- Lighting setup (office / backlit / dim; lux if measured):
- Subjects: team-sourced, consenting, not demographically representative
- Known deviations from eval/PROTOCOL.md:
- Dropped rows: never edit attempts.csv - add a line to eval/results/exclusions.csv
  (attempt_id, reason, excluded_by, ts_utc); metrics.py applies and lists them below.

{begin}
{end}
"""
AUTO_BEGIN = "<!-- AUTO:BEGIN generated by eval/metrics.py - do not edit inside this block -->"
AUTO_END = "<!-- AUTO:END -->"


def write_run_info_md(path: Path, info: dict, metrics_rel: str) -> None:
    lines = [AUTO_BEGIN, "", f"Generated {info['generated_at_utc']} by `{info['command']}`", ""]
    lines += [f"- metrics file: `{metrics_rel}`",
              f"- DUMMY data: **{info['dummy_data']}**",
              (f"- thresholds: `{info['thresholds']['path']}` sha256 `{info['thresholds']['sha256']}` "
               f"policy_version `{info['thresholds']['policy_version']}`"),
              f"- git: {info['git']}",
              f"- split reported: `{info['split']['reported']}`, calibration split: `{info['split']['calibration']}`",
              f"- subjects per split: {info['subjects_per_split']} (subject-disjoint: {info['subject_disjoint']})",
              f"- policy_version values in attempts: {info['policy_versions_in_attempts']}",
              "", "Shipped configuration under test (from thresholds.yaml; recorded with the hash):", ""]
    lines += ecfg.switch_lines(info["switches"])
    lines.append("")
    if info.get("capture_runs"):
        lines.append("| capture run | rate limiter handling | config rate_limit.enabled | transport | "
                     "duplicates dropped | thresholds sha256 | edge config diff |")
        lines.append("|---|---|---|---|---|---|---|")
        for rid, c in info["capture_runs"].items():
            diff = "; ".join(c.get("edge_config_diff") or []) or "none"
            lines.append(f"| `{rid}` | {c.get('reset_rate_limit')} | {c.get('rate_limit_enabled_config')} | "
                         f"{c.get('transport_used')} | {c.get('duplicates_dropped')} | "
                         f"`{(c.get('thresholds_sha256') or '')[:12]}` | {diff} |")
        lines.append("")
    else:
        lines += [("No capture run manifests found next to the attempts file (rate-limiter handling and "
                   "duplicate counts unknown)."), ""]
    lines.append("| input | rows used | rows excluded | sha256 |")
    lines.append("|---|---|---|---|")
    for k, v in info["inputs"].items():
        lines.append(f"| {k}: `{v.get('path')}` | {v.get('rows_used', '')} | {v.get('rows_excluded', '')} | "
                     f"`{v.get('sha256')}` |")
    lines.append("")
    if info.get("exclusions"):
        lines.append("Excluded attempts:")
        for e in info["exclusions"]:
            lines.append(f"- `{e['attempt_id']}`: {e['reason']} ({e.get('excluded_by', '')}, {e.get('ts_utc', '')})")
        lines.append("")
    if info["validation"]["warnings"]:
        lines.append(f"Validation warnings ({len(info['validation']['warnings'])}):")
        lines += [f"- {w}" for w in info["validation"]["warnings"][:30]]
        lines.append("")
    if info.get("notes"):
        lines.append("Notes:")
        lines += [f"- {n}" for n in info["notes"]]
        lines.append("")
    lines.append(AUTO_END)
    block = "\n".join(lines)
    if path.exists():
        txt = path.read_text(encoding="utf-8")
        if AUTO_BEGIN.split(" generated")[0] in txt and AUTO_END in txt:
            pre = txt.split("<!-- AUTO:BEGIN")[0]
            post = txt.split(AUTO_END, 1)[1]
            path.write_text(pre + block + post, encoding="utf-8")
            return
        path.write_text(txt.rstrip() + "\n\n" + block + "\n", encoding="utf-8")
        return
    path.write_text(RUN_INFO_TEMPLATE.replace("{begin}\n{end}", block), encoding="utf-8")


# ===================================================================== main

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--attempts", type=Path, default=RESULTS_DIR / "attempts.csv")
    ap.add_argument("--comparisons", type=Path, default=RESULTS_DIR / "comparisons.csv")
    ap.add_argument("--scenarios", type=Path, default=RESULTS_DIR / "scenarios.csv")
    ap.add_argument("--exclusions", type=Path, default=RESULTS_DIR / "exclusions.csv")
    ap.add_argument("--policy-cases", type=Path, default=scases.DOC, help="docs/POLICY_TEST_CASES.md")
    ap.add_argument("--thresholds", type=Path, default=THRESHOLDS_PATH)
    ap.add_argument("--targets", type=Path, default=EVAL_DIR / "targets.yaml")
    ap.add_argument("--split", default="test", choices=S.SPLITS, help="reported split (default test)")
    ap.add_argument("--calib-split", default="dev", choices=S.SPLITS)
    ap.add_argument("--out-dir", type=Path, default=RESULTS_DIR)
    ap.add_argument("--boot", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=20261114)
    ap.add_argument("--no-plots", action="store_true")
    a = ap.parse_args(argv)

    th = eio.load_yaml(a.thresholds)
    targets = eio.load_yaml(a.targets)
    cases = scases.parse(a.policy_cases) if a.policy_cases.exists() else {}
    tabs = {
        "attempts": load_table(a.attempts, S.validate_attempts, eio.is_inside(a.attempts, RESULTS_DIR)),
        "comparisons": load_table(a.comparisons, S.validate_comparisons, eio.is_inside(a.comparisons, RESULTS_DIR)),
        "scenarios": load_table(a.scenarios, S.validate_scenarios, eio.is_inside(a.scenarios, RESULTS_DIR)),
        "exclusions": load_table(a.exclusions, _validate_exclusions, True),
    }
    if not any(tabs[k]["exists"] for k in ("attempts", "comparisons", "scenarios")):
        print(f"no input data: none of {a.attempts}, {a.comparisons}, {a.scenarios} exists", file=sys.stderr)
        return 3
    errors = [e for t in tabs.values() for e in t["errors"]]
    warnings = [w for t in tabs.values() for w in t["warnings"]]
    if errors:
        print("VALIDATION ERRORS (fix the data, do not edit results by hand):", file=sys.stderr)
        for e in errors[:60]:
            print("  " + e, file=sys.stderr)
        return 2
    dummy = any(S.is_dummy_run(r.get("run_id")) for k in ("attempts", "comparisons", "scenarios")
                for r in tabs[k]["rows"])
    eio.refuse_dummy_into_results([a.out_dir], dummy)
    a.out_dir.mkdir(parents=True, exist_ok=True)

    excl = {r["attempt_id"]: r for r in tabs["exclusions"]["rows"]}
    all_att = [prep_attempt(r) for r in tabs["attempts"]["rows"]]
    used = [r for r in all_att if r["attempt_id"] not in excl]
    protocol = [r for r in used if not r.get("scenario")]
    rep = [r for r in protocol if r["split"] == a.split]
    dev = [r for r in protocol if r["split"] == a.calib_split]
    minimums = targets.get("protocol_minimums") or {}
    sla_ms = float((th.get("latency_budget_ms") or {}).get("total_decision", targets.get("decision_time_ms", 2000)))
    notes = []
    if sla_ms != float(targets.get("decision_time_ms", sla_ms)):
        notes.append(f"SLA mismatch: thresholds.yaml total_decision={sla_ms} vs targets.yaml "
                     f"{targets.get('decision_time_ms')}")

    metrics: dict = {"schema_version": SCHEMA_VERSION}
    pad = pad_block(rep, minimums) if rep else None
    metrics["pad"] = pad or {"status": "NO_DATA", "split": a.split}
    if pad:
        metrics["pad"]["split"] = a.split
    metrics["pad_dev_tuned_on"] = (pad_block(dev, {"attacks_per_species_test": 0, "bona_fide_test": 0}) | {
        "split": a.calib_split, "label": "dev (tuned on) - not a reported result"}) if dev else {"status": "NO_DATA"}
    lat = latency_block(rep, sla_ms, a.boot, a.seed, int(minimums.get("latency_samples", 20))) if rep else None
    metrics["latency"] = lat or {"status": "NO_DATA"}
    cmp_rows = tabs["comparisons"]["rows"]
    metrics["match"] = match_block(cmp_rows, th, a.calib_split, a.split, a.out_dir, not a.no_plots) if cmp_rows else {}
    metrics["scenarios"] = scenario_block(tabs["scenarios"]["rows"], cases, used)
    metrics["hid_targets"] = target_rows(pad, metrics["match"], lat, targets)
    metrics["trials_needed"] = trials_table()
    files = []
    if not a.no_plots and rep:
        files += pad_det(rep, a.out_dir, a.split)
        if lat:
            files += latency_hist(rep, lat, a.out_dir, a.split)
    for blk in metrics["match"].values():
        files += blk.get("det_png", [])
    metrics["files"] = {"charts_png": files}

    subj_split: dict[str, set] = defaultdict(set)
    for r in used:
        subj_split[r["subject_id"]].add(r["split"])
    att_runs = sorted({r["run_id"] for r in used})
    info = {
        "generated_at_utc": eio.utc_now_iso(),
        "command": eio.command_line(),
        "host": eio.host_info(),
        "git": eio.git_info(),
        "dummy_data": dummy,
        "thresholds": {"path": str(a.thresholds), "sha256": eio.sha256_file(a.thresholds),
                       "policy_version": th.get("policy_version")},
        "targets": {"path": str(a.targets), "sha256": eio.sha256_file(a.targets)},
        "policy_cases": {"path": str(a.policy_cases), "sha256": eio.sha256_file(a.policy_cases)},
        "split": {"reported": a.split, "calibration": a.calib_split},
        "subjects_per_split": {s: sorted(k for k, v in subj_split.items() if s in v) for s in S.SPLITS},
        "subject_disjoint": all(len(v) == 1 for v in subj_split.values()),
        "policy_versions_in_attempts": dict(Counter(r.get("policy_version") or "missing" for r in used)),
        "bundle_versions_in_attempts": dict(Counter(r.get("bundle_version") or "missing" for r in used)),
        "run_ids": {"attempts": att_runs,
                    "comparisons": sorted({r.get("run_id") or "" for r in cmp_rows}),
                    "scenarios": sorted({r.get("run_id") or "" for r in tabs["scenarios"]["rows"]})},
        "inputs": {k: {"path": t["path"], "exists": t["exists"], "sha256": t["sha256"], "rows": len(t["rows"])}
                   for k, t in tabs.items()},
        "exclusions": [{"attempt_id": k, **{c: v.get(c) for c in ("reason", "excluded_by", "ts_utc")}}
                       for k, v in excl.items()],
        "validation": {"errors": errors, "warnings": warnings},
        "bootstrap": {"resamples": a.boot, "seed": a.seed, "method": "percentile bootstrap; numpy linear quantiles"},
        "notes": notes,
    }
    info["inputs"]["attempts"].update(rows_used=len(used), rows_excluded=len(all_att) - len(used),
                                      scenario_rows=sum(1 for r in used if r.get("scenario")),
                                      reported_split_rows=len(rep), calibration_split_rows=len(dev))
    pv_cfg = th.get("policy_version")
    seen = {v for v in info["policy_versions_in_attempts"] if v != "missing"}
    info["policy_version_consistent"] = not seen or seen == {pv_cfg}
    if not info["policy_version_consistent"]:
        notes.append(f"policy_version in attempts {sorted(seen)} != thresholds.yaml {pv_cfg}: thresholds changed "
                     "between capture and analysis?")
    runs_dir = Path(a.attempts).parent / "runs"
    info["switches"] = ecfg.shipped_switches(th, a.thresholds)
    info["capture_runs"] = {}
    for rid in att_runs:
        man = runs_dir / f"{rid}.json"
        if man.exists():
            try:
                import json as _json
                md = _json.loads(man.read_text(encoding="utf-8"))
            except ValueError:
                continue
            sha = md.get("thresholds_sha256")
            if sha and sha != info["thresholds"]["sha256"]:
                notes.append(f"run {rid} was captured with thresholds sha256 {sha[:12]}..., current file differs")
            rl = md.get("rate_limit_handling") or {}
            info["capture_runs"][rid] = {
                "thresholds_sha256": sha, "reset_rate_limit": rl.get("reset_rate_limit"),
                "rate_limit_enabled_config": rl.get("rate_limit_enabled_config"),
                "transport_used": md.get("transport_used"), "duplicates_dropped": md.get("duplicates_dropped"),
                "edge_config_diff": md.get("edge_config_diff") or [],
            }
            for d in md.get("edge_config_diff") or []:
                if "unavailable" not in d:
                    notes.append(f"run {rid}: edge config differed from thresholds.yaml at capture start: {d}")
    if not info["subject_disjoint"]:
        notes.append("subjects appear in more than one split - dev/test are NOT subject-disjoint")
    metrics["RUN_INFO"] = info

    out_json = a.out_dir / "metrics.json"
    eio.write_json(out_json, metrics)
    write_run_info_md(a.out_dir / "RUN_INFO.md", info, str(out_json))
    _print_brief(metrics)
    print(f"\nwrote {out_json}" + (f" and {len(files)} chart files" if files else ""))
    return 0


def _print_brief(m: dict) -> None:
    pad = m.get("pad") or {}
    print(f"split={pad.get('split')}  dummy={m['RUN_INFO']['dummy_data']}")
    for sp, rec in (pad.get("apcer_system") or {}).items():
        print(f"  APCER {sp:14s} {rec['text']}{'  LOW_N' if rec.get('low_n') else ''}")
    if pad.get("bpcer"):
        print(f"  BPCER (any DENY)   {pad['bpcer']['text']}")
        print(f"  BPCER (PAD-only)   {pad['bpcer_pad_only']['text']}")
        print(f"  step-up rate       {pad['genuine_stepup_rate']['text']}")
        print(f"  FRR (transaction)  {pad['frr_transaction']['text']}")
    for name, blk in (m.get("match") or {}).items():
        t = blk["test"]["at_configured_online"]
        if "fmr" in t:
            print(f"  {name}: FMR {t['fmr']['text']}  FNMR {t['fnmr']['text']}  (t={t['threshold']})")
        print(f"  {name}: calibrated allow_min_cosine = {blk['calibration'].get('threshold')} "
              f"(N impostor {blk['calibration'].get('n_impostor')})")
    lat = m.get("latency") or {}
    o = (lat.get("sla_allow_path") or {}).get("overall")
    if o and o.get("n"):
        print(f"  latency ALLOW path p50 {o['p50']:.0f} p95 {o['p95']:.0f} ms (CI {o['p95_ci95'][0]:.0f}-"
              f"{o['p95_ci95'][1]:.0f}) n={o['n']} within SLA {o['within_sla']['text']}")
    for row in m.get("hid_targets", []):
        print(f"  target {row['target']}: {row['status']}")
    print(f"  scenarios: {m['scenarios']['summary']}")


if __name__ == "__main__":
    sys.exit(main())
