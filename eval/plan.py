"""Subject registry (subject-disjoint dev/test split) and pre-shuffled, interleaved capture plans.

Usage (from eval/):
  # 1) register consenting subjects and assign splits BEFORE any capture (~40 % dev, seeded)
  uv run python plan.py subjects --ids S01,S02,S03,S04,S05 --dev-frac 0.4 --seed 20261114 --out subjects.csv
  #    then fill enrolled_user_id per subject (the edge user id after enrolment) and consent=yes
  # 2) generate a shuffled plan for one split (volumes derived from the targets unless given)
  uv run python plan.py schedule --split test --out plans/test_plan.csv
  uv run python plan.py schedule --split dev --target-genuine 30 --target-per-species 10 --out plans/dev_plan.csv
  # REDUCED ~45 min plan (3 enrolled team members, thresholds frozen at the shipped config, all held-out `test`)
  uv run python plan.py reduced --write-subjects --out plans/reduced_plan.csv
"""

from __future__ import annotations

import argparse
import math
import random
import sys
from collections import Counter
from pathlib import Path

from evallib import EVAL_DIR
from evallib import io as eio
from evallib import schema as S
from evallib import stats as st

SUBJECT_COLUMNS = ["subject_id", "split", "enrolled_user_id", "consent", "consent_version", "notes"]
PLAN_COLUMNS = ["plan_seq", "split", "block", "subject_id", "species", "attempt_class", "lighting", "distance",
                "zone", "scenario"]
DEFAULT_SPECIES = ["print", "print_eyecut", "phone_photo", "phone_video", "laptop_replay", "paper_mask"]
MAX_RUN = 3  # never more than 3 consecutive attempts of the same class (genuine vs attack)


def assign_splits(ids: list[str], dev_frac: float, seed: int) -> dict[str, str]:
    """Seeded subject-level split: round(dev_frac * n) subjects (at least 1 each when n >= 2) go to dev."""
    ids = sorted(set(ids))
    rng = random.Random(seed)
    order = ids[:]
    rng.shuffle(order)
    n_dev = max(1, round(dev_frac * len(ids))) if len(ids) >= 2 else 0
    n_dev = min(n_dev, len(ids) - 1) if len(ids) >= 2 else n_dev
    return {s: ("dev" if i < n_dev else "test") for i, s in enumerate(order)}


def interleave(items: list[dict], rng: random.Random) -> list[dict]:
    """Constructive shuffle: genuine and attack items drawn at random (weighted by what is left), never more than
    MAX_RUN consecutive of one class while the other class still has items, and never a choice that makes the
    rest infeasible (n_big <= MAX_RUN * (n_small + 1))."""
    pools = {"g": [x for x in items if x["attempt_class"] in ("genuine", "zero_effort")],
             "a": [x for x in items if x["attempt_class"] not in ("genuine", "zero_effort")]}
    for p in pools.values():
        rng.shuffle(p)
    out: list[dict] = []
    run_cls, run = None, 0

    def ok(pick: str) -> bool:
        other = "a" if pick == "g" else "g"
        n_pick, n_other = len(pools[pick]) - 1, len(pools[other])
        if run_cls == pick and run >= MAX_RUN and n_other:
            return False
        # both classes must stay placeable: n_x <= MAX_RUN * (n_y + 1)
        return (n_pick <= MAX_RUN * (n_other + 1) or not n_other) and n_other <= MAX_RUN * (n_pick + 1)

    while pools["g"] or pools["a"]:
        cands = [c for c in ("g", "a") if pools[c] and ok(c)] or [c for c in ("g", "a") if pools[c]]
        if len(cands) == 2:
            pick = "g" if rng.random() < len(pools["g"]) / (len(pools["g"]) + len(pools["a"])) else "a"
        else:
            pick = cands[0]
        out.append(pools[pick].pop())
        run, run_cls = (run + 1, pick) if pick == run_cls else (1, pick)
    return out


def make_schedule(subjects: dict[str, dict], split: str, species: list[str], lighting: list[str], distance: list[str],
                  genuine_per_cell: int, attacks_per_species_subject: int, extra: dict[str, int], zone: str,
                  seed: int) -> list[dict]:
    subj = sorted(s for s, r in subjects.items() if r["split"] == split)
    if not subj:
        raise SystemExit(f"no subjects in split {split}")
    rng = random.Random(seed)
    blocks: dict[str, list[dict]] = {lg: [] for lg in lighting}
    for s in subj:
        for lg in lighting:
            for d in distance:
                for _ in range(genuine_per_cell):
                    blocks[lg].append({"subject_id": s, "species": "bona_fide", "attempt_class": "genuine",
                                       "lighting": lg, "distance": d})
        for sp in species:
            for k in range(attacks_per_species_subject):
                lg = lighting[k % len(lighting)]  # spread attacks over the lighting blocks
                blocks[lg].append({"subject_id": s, "species": sp, "attempt_class": S.attempt_class_for(sp),
                                   "lighting": lg, "distance": distance[k % len(distance)]})
    for sp, n in extra.items():  # e.g. mask_3d / inject_vcam / zero_effort, spread over subjects, office light
        for k in range(n):
            s = subj[k % len(subj)]
            cls = "zero_effort" if sp == "zero_effort" else S.attempt_class_for(sp)
            blocks[lighting[0]].append({"subject_id": s, "species": "bona_fide" if sp == "zero_effort" else sp,
                                        "attempt_class": cls, "lighting": lighting[0], "distance": distance[0]})
    plan: list[dict] = []
    for lg in lighting:  # lighting changes are physical: one block per condition, shuffled inside
        for item in interleave(blocks[lg], rng):
            plan.append(item | {"split": split, "block": lg, "zone": zone, "scenario": ""})
    for i, p in enumerate(plan, start=1):
        p["plan_seq"] = i
    return plan


# ===================================================================== reduced ~45 min plan

# pseudonymous subject id -> enrolled edge user id (no names in any file; the operator knows who is who)
REDUCED_SUBJECTS = {"S01": "u_prj1", "S02": "u_tm02", "S03": "u_tm03"}
REDUCED_ATTACKS = {"print": 15, "phone_photo": 15, "phone_video": 15, "print_eyecut": 10}
REDUCED_GENUINE = {"office": 28, "dim": 12}  # ~40 bona fide; dim block = BPCER-by-lighting glimpse only


def _spread(n: int, subjects: list[str]) -> list[str]:
    """n items round-robin over subjects (deterministic): 10 over 3 -> S01 x4, S02 x3, S03 x3."""
    return [subjects[k % len(subjects)] for k in range(n)]


def make_reduced(subjects: list[str], attack_targets: list[str], genuine: dict[str, int], attacks: dict[str, int],
                 zone: str, seed: int) -> list[dict]:
    rng = random.Random(seed)
    blocks: dict[str, list[dict]] = {lg: [] for lg in genuine}
    for lg, n in genuine.items():
        for s in _spread(n, subjects):
            blocks[lg].append({"subject_id": s, "species": "bona_fide", "attempt_class": "genuine", "lighting": lg,
                               "distance": "mid"})
    first = next(iter(genuine))  # attacks in the first (office) block: no artefact handling in the dark
    for sp, n in attacks.items():
        for s in _spread(n, attack_targets):
            blocks[first].append({"subject_id": s, "species": sp, "attempt_class": S.attempt_class_for(sp),
                                  "lighting": first, "distance": "mid"})
    plan: list[dict] = []
    for lg, items in blocks.items():
        for item in interleave(items, rng):
            plan.append(item | {"split": "test", "block": lg, "zone": zone, "scenario": ""})
    for i, row in enumerate(plan, start=1):
        row["plan_seq"] = i
    return plan


def bounds_table(counts: dict[str, int]) -> list[str]:
    """What a cell of N attempts can support at 0 errors (one-sided 95 %): rule of 3 and the exact bound."""
    lines = ["| cell | N | 0 errors -> rule of 3 (3/N) | exact 95% UB 1-0.05^(1/N) | 1 error -> CP 95% UB |",
             "|---|---|---|---|---|"]
    for name, n in counts.items():
        if n <= 0:
            continue
        lines.append(f"| {name} | {n} | < {st.pct(st.rule_of_three(n))} | < {st.pct(st.zero_error_upper_exact(n))} | "
                     f"{st.pct(st.cp_upper(1, n))} |")
    return lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a1 = sub.add_parser("subjects", help="create the subject registry with a seeded dev/test split")
    a1.add_argument("--ids", required=True, help="comma-separated pseudonymous subject ids (no names)")
    a1.add_argument("--dev-frac", type=float, default=0.4)
    a1.add_argument("--seed", type=int, default=20261114)
    a1.add_argument("--out", type=Path, default=EVAL_DIR / "subjects.csv")
    a1.add_argument("--force", action="store_true", help="overwrite an existing registry (re-splitting!)")
    a2 = sub.add_parser("schedule", help="pre-shuffled interleaved plan for one split")
    a2.add_argument("--subjects", type=Path, default=EVAL_DIR / "subjects.csv")
    a2.add_argument("--split", choices=S.SPLITS, required=True)
    a2.add_argument("--species", default=",".join(DEFAULT_SPECIES))
    a2.add_argument("--lighting", default=",".join(S.LIGHTING))
    a2.add_argument("--distance", default="mid")
    a2.add_argument("--target-genuine", type=int, default=120, help="bona fide attempts in this split")
    a2.add_argument("--target-per-species", type=int, default=30, help="attacks per species in this split")
    a2.add_argument("--genuine-per-cell", type=int, default=0, help="override: per subject x lighting x distance")
    a2.add_argument("--attacks-per-subject", type=int, default=0, help="override: per species x subject")
    a2.add_argument("--extra", default="", help="e.g. mask_3d:6,inject_vcam:6,zero_effort:10")
    a2.add_argument("--zone", default="LIBRARY")
    a2.add_argument("--seed", type=int, default=1)
    a2.add_argument("--out", type=Path, required=True)
    a3 = sub.add_parser("reduced", help="REDUCED ~45 min operator plan (3 enrolled team members, all test split)")
    a3.add_argument("--subjects", type=Path, default=EVAL_DIR / "subjects.csv")
    a3.add_argument("--write-subjects", action="store_true",
                    help="create the 3-subject registry (S01=u_prj1, S02=u_tm02, S03=u_tm03, split test, consent "
                         "blank - the operator sets consent=yes after asking each person)")
    a3.add_argument("--attack-targets", default="S01,S02,S03", help="subjects whose artefacts exist")
    a3.add_argument("--genuine", default="office:28,dim:12")
    a3.add_argument("--attacks", default=",".join(f"{k}:{v}" for k, v in REDUCED_ATTACKS.items()))
    a3.add_argument("--zone", default="MAIN_GATE", help="zone of the live kiosk (KIOSK_MAIN_01)")
    a3.add_argument("--probes-per-subject", type=int, default=30, help="collect_faces probes per subject (FAR/FRR)")
    a3.add_argument("--seed", type=int, default=20261114)
    a3.add_argument("--out", type=Path, default=EVAL_DIR / "plans" / "reduced_plan.csv")
    a = ap.parse_args(argv)

    if a.cmd == "reduced":
        return _reduced(a)

    if a.cmd == "subjects":
        if a.out.exists() and not a.force:
            raise SystemExit(f"{a.out} exists - splits are fixed before capture; use --force only before any capture")
        ids = [x.strip() for x in a.ids.split(",") if x.strip()]
        split = assign_splits(ids, a.dev_frac, a.seed)
        rows = [{"subject_id": s, "split": split[s], "enrolled_user_id": "", "consent": "",
                 "consent_version": "2026-11-14.v1", "notes": ""} for s in sorted(ids)]
        eio.write_csv(a.out, SUBJECT_COLUMNS, rows)
        print(f"wrote {a.out}: {dict(Counter(split.values()))} (seed {a.seed}); fill enrolled_user_id + consent=yes")
        return 0

    _, rows = eio.read_csv(a.subjects)
    subjects = {r["subject_id"]: r for r in rows}
    lighting = [x for x in a.lighting.split(",") if x]
    distance = [x for x in a.distance.split(",") if x]
    species = [x for x in a.species.split(",") if x]
    for sp in species:
        if sp not in S.ATTACK_SPECIES:
            raise SystemExit(f"--species: {sp} is not a PAD attack species ({S.ATTACK_SPECIES})")
    n_subj = sum(1 for r in rows if r["split"] == a.split)
    gpc = a.genuine_per_cell or max(1, math.ceil(a.target_genuine / max(1, n_subj * len(lighting) * len(distance))))
    aps = a.attacks_per_subject or max(1, math.ceil(a.target_per_species / max(1, n_subj)))
    extra = {}
    for tok in [t for t in a.extra.split(",") if t]:
        k, v = tok.split(":")
        extra[k] = int(v)
    plan = make_schedule(subjects, a.split, species, lighting, distance, gpc, aps, extra, a.zone, a.seed)
    eio.write_csv(a.out, PLAN_COLUMNS, plan)
    c = Counter(p["species"] for p in plan)
    print(f"wrote {a.out}: {len(plan)} attempts for split {a.split} ({n_subj} subjects); "
          f"genuine/cell={gpc}, attacks/species/subject={aps}; {dict(c)}")
    est = len(plan) * 20 / 60
    print(f"estimated capture time at ~20 s/attempt: {est:.0f} min")
    return 0



def _kv(spec: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for tok in [t for t in spec.split(",") if t]:
        k, v = tok.split(":")
        out[k.strip()] = int(v)
    return out


def _reduced(a) -> int:
    genuine, attacks = _kv(a.genuine), _kv(a.attacks)
    for lg in genuine:
        if lg not in S.LIGHTING:
            raise SystemExit(f"--genuine: unknown lighting {lg}")
    for sp in attacks:
        if sp not in S.ATTACK_SPECIES:
            raise SystemExit(f"--attacks: {sp} is not a PAD attack species ({S.ATTACK_SPECIES})")
    if a.write_subjects:
        if a.subjects.exists():
            raise SystemExit(f"{a.subjects} exists - splits are fixed before capture; not overwriting")
        eio.write_csv(a.subjects, SUBJECT_COLUMNS, [
            {"subject_id": s, "split": "test", "enrolled_user_id": u, "consent": "", "consent_version": "2026-11-14.v1",
             "notes": "reduced plan; thresholds frozen at shipped config (no tuning)"}
            for s, u in REDUCED_SUBJECTS.items()])
        print(f"wrote {a.subjects}: S01..S03 -> {list(REDUCED_SUBJECTS.values())}, split test; "
              "set consent=yes per person before any capture")
    _, rows = eio.read_csv(a.subjects)
    reg = {r["subject_id"]: r for r in rows}
    subjects = sorted(s for s, r in reg.items() if r["split"] == "test")
    targets = [x.strip() for x in a.attack_targets.split(",") if x.strip()]
    if not subjects:
        raise SystemExit(f"no test-split subjects in {a.subjects}")
    bad = [t for t in targets if t not in subjects]
    if bad:
        raise SystemExit(f"--attack-targets not in the test split of {a.subjects}: {bad}")
    plan = make_reduced(subjects, targets, genuine, attacks, a.zone, a.seed)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    eio.write_csv(a.out, PLAN_COLUMNS, plan)
    c = Counter(r["species"] for r in plan)
    n_att = sum(v for k, v in c.items() if k != "bona_fide")
    n_sub = len(subjects)
    probes = a.probes_per_subject * n_sub
    print(f"wrote {a.out}: {len(plan)} attempts ({dict(c)}); blocks {list(genuine)}; zone {a.zone}")
    print(f"estimated capture time at ~20 s/attempt: {len(plan) * 20 / 60:.0f} min "
          f"(+ ~10 min pre-flight, collect_faces and analysis)")
    cells = {"bona fide (BPCER, all)": c["bona_fide"], **{f"bona fide {lg}": n for lg, n in genuine.items()},
             **{f"APCER {sp}": c[sp] for sp in attacks}, "attacks pooled (supplementary; headline = max APCER per species)": n_att,
             f"FNMR genuine comparisons ({a.probes_per_subject} probes x {n_sub})": probes,
             f"FMR impostor comparisons ({probes} probes x {n_sub - 1} other templates)": probes * (n_sub - 1)}
    print("\nBounds this plan can support (one-sided 95%; report k/N with the bound, never a point claim):")
    for line in bounds_table(cells):
        print("  " + line)
    print(f"  needed for HID's targets at 0 errors: FAR 0.2% -> {st.trials_needed(0.002)} impostor comparisons, "
          f"FRR 0.6% -> {st.trials_needed(0.006)} genuine transactions (not reachable with this plan)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
