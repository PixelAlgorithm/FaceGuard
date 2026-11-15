"""Calibration readout: per-signal score distributions, bona fide vs each attack species, from attempts.csv.

Descriptive only. It shows where genuine and attack scores fall relative to the CONFIGURED bars in
config/thresholds.yaml, and how often each fused signal reported PASS / UNSURE / FAIL / ADVISORY_* (`signals`
column). It never writes thresholds and never suggests one: threshold changes belong to the policy-engine owner,
are tuned on the `dev` split only, and are then frozen before the `test` split is captured. Run on `test`, the
readout is labelled "held-out - do not tune on these numbers".

Single-signal separation is NOT APCER / BPCER: the decision fuses signals (DECISION_POLICY.md), so an attack can
pass one bar and still be denied. The official PAD numbers come from metrics.py.

  uv run python calibrate.py --split dev                        # results/attempts.csv -> results/calibration/
  uv run python calibrate.py --split test --out-dir results/calibration_test
  uv run python calibrate.py --attempts tests/fixtures/attempts_DUMMY.csv --split dev --out-dir /tmp/calib

Excluded rows (counted): scenario rows, exclusions.csv entries, NO_RESPONSE, RATE_LIMITED / SYSTEM_ERROR,
injection (not PAD). Zero-error cells carry the one-sided 95 % Clopper-Pearson upper bound (rule of 3 at 0).
"""

from __future__ import annotations

import argparse
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from evallib import RESULTS_DIR, THRESHOLDS_PATH
from evallib import config as ecfg
from evallib import io as eio
from evallib import schema as S
from evallib import stats as st

# column, description, higher_means ("live" | "attack"), [(bar label, thresholds.yaml dotted path)]
SIGNALS: list[tuple[str, str, str, list[tuple[str, str]]]] = [
    ("s_pad", "MiniFASNet mean P(live)", "live",
     [("pad.pass_min", "liveness.pad.pass_min"), ("pad.fail_max", "liveness.pad.fail_max")]),
    ("s_pad_pass_frames", "frames with P(live) >= pass_min", "live",
     [("pad.min_pass_frames", "liveness.pad.min_pass_frames")]),
    ("s_flash_r", "colour-flash chroma correlation", "live",
     [("flash.pass_min_r", "liveness.flash.pass_min_r"), ("flash.fail_max_r", "liveness.flash.fail_max_r")]),
    ("s_flash_amp", "colour-flash response amplitude", "live", []),
    ("s_moire", "moire FFT peak score", "attack",
     [("moire.unsure_score", "liveness.moire.unsure_score"), ("moire.fail_score", "liveness.moire.fail_score")]),
    ("s_device_conf", "phone/laptop/tv detector confidence", "attack",
     [("device.unsure_conf", "liveness.device_detector.unsure_conf"),
      ("device.fail_conf", "liveness.device_detector.fail_conf")]),
    ("s_mask_ring", "RGB eye-hole / outline ring (mask M2)", "attack",
     [("mask.m2_ring_score_weak", "liveness.mask.m2_ring_score_weak"),
      ("mask.m2_ring_score_strong", "liveness.mask.m2_ring_score_strong")]),
    ("s_depth", "TrueDepth score (disabled until H4)", "live", []),
    ("s_match", "ArcFace top-1 cosine (local)", "live",
     [("match.allow_min_cosine", "match.local.allow_min_cosine")]),
    ("s_match_margin", "top-1 minus top-2 cosine", "live",
     [("match.min_margin_top1_top2", "match.local.min_margin_top1_top2")]),
    ("s_rekognition", "Rekognition similarity (online)", "live", []),
]
QS = (0, 5, 25, 50, 75, 95, 100)
GENUINE = "bona_fide"


def _get(d: dict, dotted: str):
    cur = d
    for k in dotted.split("."):
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def _float(v) -> float | None:
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(x) else x


def select_rows(rows: list[dict], split: str, excluded_ids: set[str]) -> tuple[list[dict], Counter]:
    used, dropped = [], Counter()
    for r in rows:
        codes = set(S.split_codes(r.get("reason_codes"))) | set(S.split_codes(r.get("first_reason_codes")))
        if r.get("split") != split:
            continue
        if r.get("attempt_id") in excluded_ids:
            dropped["exclusions.csv"] += 1
        elif r.get("scenario"):
            dropped["scenario rows"] += 1
        elif r.get("decision") == "NO_RESPONSE":
            dropped["NO_RESPONSE"] += 1
        elif codes & S.SYSTEM or "RATE_LIMITED" in (r.get("notes") or ""):
            dropped["RATE_LIMITED / SYSTEM_ERROR"] += 1
        elif r.get("species") == "inject_vcam":
            dropped["injection (not PAD)"] += 1
        elif r.get("attempt_class") == "zero_effort":
            dropped["zero-effort impostor (not PAD)"] += 1
        else:
            used.append(r)
    return used, dropped


def group_of(r: dict) -> str:
    return GENUINE if r["species"] == GENUINE else r["species"]


def describe(vals: list[float]) -> dict:
    if not vals:
        return {"n": 0}
    x = np.asarray(vals, float)
    return {"n": len(vals), **{f"p{q:02d}" if q not in (0, 100) else ("min" if q == 0 else "max"):
                               round(float(np.percentile(x, q)), 4) for q in QS}}


def side_counts(vals: list[float], bar: float, higher: str, group: str) -> dict:
    """Genuine: share on the attack side of the bar. Attack: share on the live side. k/N + one-sided 95 % UB."""
    if not vals:
        return {"n": 0}
    if group == GENUINE:
        k = sum(v < bar for v in vals) if higher == "live" else sum(v >= bar for v in vals)
        what = "bona fide on the attack side"
    else:
        k = sum(v >= bar for v in vals) if higher == "live" else sum(v < bar for v in vals)
        what = "attacks on the live side"
    r = st.rate(int(k), len(vals))
    return {"what": what, "k": int(k), "n": len(vals), "rate": r["rate"], "ub95": r["ub95"], "text": r["text"]}


def readout(rows: list[dict], th: dict) -> dict:
    groups = [GENUINE] + [s for s in S.ATTACK_SPECIES if any(r["species"] == s for r in rows)]
    out: dict = {"groups": groups, "n_by_group": dict(Counter(group_of(r) for r in rows)), "signals": {}}
    for col, desc, higher, bars in SIGNALS:
        by: dict[str, list[float]] = defaultdict(list)
        for r in rows:
            v = _float(r.get(col))
            if v is not None:
                by[group_of(r)].append(v)
                if r["species"] != GENUINE:
                    by["all_attacks"].append(v)
        if not any(by.values()):
            out["signals"][col] = {"description": desc, "status": "NO_DATA"}
            continue
        sig = {"description": desc, "higher_means": higher, "distribution": {}, "bars": {}}
        for g in [*groups, "all_attacks"]:
            sig["distribution"][g] = describe(by.get(g, []))
        for label, path in bars:
            bar = _float(_get(th, path))
            if bar is None:
                sig["bars"][label] = {"path": path, "status": "not in thresholds.yaml"}
                continue
            sig["bars"][label] = {"path": path, "value": bar,
                                  **{g: side_counts(by.get(g, []), bar, higher, g) for g in [*groups, "all_attacks"]}}
        out["signals"][col] = sig
    status: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    for r in rows:
        for part in S.split_codes(r.get("signals")):
            k, _, v = part.partition("=")
            if k and v:
                status[k][group_of(r)][v] += 1
    out["signal_status"] = {k: {g: dict(c) for g, c in v.items()} for k, v in status.items()}
    return out


def _fmt(v) -> str:
    return "-" if v is None else f"{v:g}" if isinstance(v, float) else str(v)


def to_md(res: dict, meta: dict) -> str:
    L = ["# Calibration readout - per-signal distributions (bona fide vs attack species)", ""]
    if meta["dummy"]:
        L += ["> **DUMMY DATA - synthetic fixtures. Not a measurement.**", ""]
    if meta["split"] == "test":
        L += [("> **Held-out `test` split: descriptive only - do not tune on these numbers.** Any threshold "
               "change made after reading this needs a fresh capture to be reported."), ""]
    else:
        L += [(f"> `{meta['split']}` split (tuning split). Thresholds tuned here must be frozen and recorded "
               "(sha256 + policy_version) before the `test` split is captured."), ""]
    L += [("Single-signal separation at the configured bar. **Not APCER/BPCER**: the policy fuses signals, so "
           "an attack on the live side of one bar can still be denied by another. Official numbers: `metrics.py`."),
          "", (f"- source `{meta['attempts']}` sha256 `{meta['attempts_sha256']}`; generated "
               f"{meta['generated_at_utc']} by `{meta['command']}`"),
          f"- rows used {meta['rows_used']} by group {res['n_by_group']}; dropped {meta['dropped']}", ""]
    L += ["Configuration the bars come from:", ""] + ecfg.switch_lines(meta["switches"]) + [""]
    groups = [*res["groups"], "all_attacks"]
    for col, sig in res["signals"].items():
        L.append(f"## `{col}` - {sig['description']}")
        L.append("")
        if sig.get("status") == "NO_DATA":
            L += ["_no values in these rows_", ""]
            continue
        L.append(f"Higher means **{sig['higher_means']}**.")
        L.append("")
        L += ["| group | n | min | p05 | p25 | p50 | p75 | p95 | max |", "|---|---|---|---|---|---|---|---|---|"]
        for g in groups:
            d = sig["distribution"].get(g, {"n": 0})
            if d["n"]:
                L.append(f"| {g} | {d['n']} | " + " | ".join(_fmt(d[k]) for k in
                                                         ("min", "p05", "p25", "p50", "p75", "p95", "max")) + " |")
            else:
                L.append(f"| {g} | 0 | - | - | - | - | - | - | - |")
        L.append("")
        for label, b in sig["bars"].items():
            if "value" not in b:
                L += [f"- bar `{label}` (`{b['path']}`): {b['status']}", ""]
                continue
            L.append(f"Bar `{label}` = {b['value']} (`{b['path']}`):")
            L.append("")
            L += ["| group | on the wrong side of the bar | k/N (95% UB) |", "|---|---|---|"]
            for g in groups:
                c = b.get(g) or {"n": 0}
                L.append(f"| {g} | {c.get('what', '-')} | {c.get('text', 'no data')} |")
            L.append("")
    if res["signal_status"]:
        L += ["## Fused signal status (`signals` column, first evaluated decision)", "",
              ("`ADVISORY_<zone>` = measured with no decision effect (e.g. colour flash while "
               "`liveness.flash.enforce: false`)."), ""]
        for k, by in res["signal_status"].items():
            vals = sorted({v for c in by.values() for v in c})
            L += [f"### `{k}`", "", "| group | " + " | ".join(vals) + " |", "|---|" + "---|" * len(vals)]
            for g in res["groups"]:
                c = by.get(g, {})
                L.append(f"| {g} | " + " | ".join(str(c.get(v, 0)) for v in vals) + " |")
            L.append("")
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--attempts", type=Path, default=RESULTS_DIR / "attempts.csv")
    ap.add_argument("--exclusions", type=Path, default=RESULTS_DIR / "exclusions.csv")
    ap.add_argument("--thresholds", type=Path, default=THRESHOLDS_PATH)
    ap.add_argument("--split", choices=S.SPLITS, default="dev")
    ap.add_argument("--out-dir", type=Path, default=RESULTS_DIR / "calibration")
    a = ap.parse_args(argv)

    header, rows = eio.read_csv(a.attempts)
    if not rows:
        print(f"no rows in {a.attempts}", file=sys.stderr)
        return 3
    errors, _ = S.validate_attempts(rows, header, results_file=eio.is_inside(a.attempts, RESULTS_DIR))
    if errors:
        print("VALIDATION ERRORS (fix the data, do not edit results by hand):", file=sys.stderr)
        for e in errors[:30]:
            print("  " + e, file=sys.stderr)
        return 2
    dummy = any(S.is_dummy_run(r.get("run_id")) for r in rows)
    eio.refuse_dummy_into_results([a.out_dir], dummy)
    excluded = {r["attempt_id"] for r in eio.read_csv(a.exclusions)[1]} if a.exclusions.exists() else set()
    used, dropped = select_rows(rows, a.split, excluded)
    if not used:
        print(f"no usable rows on split {a.split}", file=sys.stderr)
        return 3
    th = eio.load_yaml(a.thresholds) or {}
    res = readout(used, th)
    meta = {"generated_at_utc": eio.utc_now_iso(), "command": eio.command_line(), "attempts": str(a.attempts),
            "attempts_sha256": eio.sha256_file(a.attempts), "split": a.split, "dummy": dummy,
            "rows_used": len(used), "dropped": dict(dropped),
            "switches": ecfg.shipped_switches(th, a.thresholds),
            "label": "descriptive calibration readout - not APCER/BPCER" + (
                "; held-out test split, do not tune" if a.split == "test" else "")}
    a.out_dir.mkdir(parents=True, exist_ok=True)
    eio.write_json(a.out_dir / f"calibration_{a.split}.json", {"meta": meta, **res})
    (a.out_dir / f"CALIBRATION_{a.split}.md").write_text(to_md(res, meta), encoding="utf-8")
    print(f"calibration readout ({a.split}, {len(used)} rows, groups {res['n_by_group']}) -> "
          f"{a.out_dir / f'CALIBRATION_{a.split}.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
