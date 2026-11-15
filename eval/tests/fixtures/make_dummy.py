"""Generate the DUMMY fixtures (synthetic - see README_DUMMY.md). Deterministic (seeded).

Usage (from eval/): uv run python tests/fixtures/make_dummy.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from evallib import io as eio
from evallib import schema as S

RUN = "DUMMY-R1"
SUBJECTS = {f"DUMMY_S0{i}": ("dev" if i <= 2 else "test") for i in range(1, 7)}
USERS = {s: f"u_dummy{i}" for i, s in enumerate(SUBJECTS, start=1)}


MASKED = ("print_eyecut", "paper_mask", "mask_3d")


def _signals(species: str, is_live: bool, first_codes: list[str]) -> str:
    """scores.signals as capture.py flattens it (edge/policy/engine.py): flash is ADVISORY (shipped config)."""
    if "INJECTION_VIRTUAL_CAMERA" in first_codes:
        return "injection=FAIL"
    pad = "PASS" if is_live else "FAIL"
    device = "FAIL" if "SPOOF_DEVICE_DETECTED" in first_codes else "PASS"
    mask = "UNSURE" if species in MASKED else "PASS"
    flash = "ADVISORY_PASS" if is_live else "ADVISORY_FAIL"
    return f"pad={pad};device={device};moire=PASS;flash={flash};mask={mask};depth=NOT_AVAILABLE;injection=PASS"


def _row(rng, seq, subj, species, lighting, distance, outcome, mode="ONLINE", scenario="", notes=""):
    """outcome: dict(first=..., final=..., codes=..., first_codes=..., next=..., live=...)"""
    split = SUBJECTS[subj]
    cls = S.attempt_class_for(species, zero_effort=outcome.get("zero_effort", False))
    first, final = outcome["first"], outcome["final"]
    aid = f"noresp_{RUN}_{seq}" if final == "NO_RESPONSE" else f"att_DUMMY{seq:04d}"
    codes = outcome.get("codes", ["ACCESS_OK"] if final == "ALLOW" else [])
    first_codes = outcome.get("first_codes", codes)
    if mode == "OFFLINE" and final != "NO_RESPONSE":
        codes = codes + (["OFFLINE_MODE"] if "OFFLINE_MODE" not in codes else [])
        first_codes = first_codes + (["OFFLINE_MODE"] if "OFFLINE_MODE" not in first_codes else [])
    resp = final != "NO_RESPONSE"
    is_live = outcome.get("live", species == "bona_fide")
    pad = float(np.clip(rng.normal(0.9 if is_live else 0.12, 0.06), 0, 1)) if resp else None
    if resp and outcome.get("pad"):
        pad = outcome["pad"]
    e2e = float(max(300, rng.normal(1450 if mode == "ONLINE" else 1250, 170))) if resp else None
    stepup_out = "none" if first != "STEP_UP" else {"ALLOW": "passed", "DENY": "failed", "STEP_UP": "unresolved"}[final]
    lr = outcome.get("liveness_result") or (
        "" if not resp else S.derive_liveness_result(first, outcome.get("first_stage", "final"), first_codes))
    row = {
        "run_id": RUN, "plan_seq": seq, "ts_utc": f"2026-11-14T06:{seq // 60 % 60:02d}:{seq % 60:02d}.000Z",
        "split": split, "subject_id": subj, "target_user_id": USERS[subj], "attempt_class": cls,
        "species": species, "label": S.SPECIES_TO_LABEL[species],
        "condition": lighting if lighting in ("dim", "backlit") else ("far" if distance == "far" else "normal"),
        "lighting": lighting, "distance": distance,
        "zone": "LIBRARY", "kiosk_id": "KIOSK_LIB_01", "operator": "DUMMY", "scenario": scenario,
        "attempt_id": aid, "decision": final, "reason_codes": S.join_codes(codes) if resp else "",
        "stage": outcome.get("stage", "final" if final == "ALLOW" else "liveness") if resp else "",
        "bio_result": outcome.get("bio", "BIO_PASS" if final == "ALLOW" else "BIO_FAIL") if resp else "",
        "schedule_result": "IN_WINDOW" if resp and final != "DENY" else "",
        "mode": mode if resp else "", "cache_state": "FRESH" if resp else "",
        "candidate_user_id": outcome.get("candidate", USERS[subj]) if resp else "",
        "liveness_result": lr if resp else "", "liveness_result_source": "derived" if resp else "",
        "first_decision": first if resp else "", "first_reason_codes": S.join_codes(first_codes) if resp else "",
        "first_stage": outcome.get("first_stage", "final" if first == "ALLOW" else "liveness") if resp else "",
        "next_action_type": outcome.get("next", "") if first == "STEP_UP" else "",
        "stepup_methods": "", "stepup_outcome": stepup_out if resp else "none",
        "stepup_rounds": 1 if first == "STEP_UP" else 0, "recaptures": 1 if outcome.get("next") == "RECAPTURE" else 0,
        "stepup_ms": round(float(rng.normal(4200, 900)), 1) if first == "STEP_UP" and resp else "",
        "resolved_codes": "", "latency_ms": round(e2e, 1) if e2e else "",
        "latency_source": "kiosk_render" if resp else "none",
        "lat_server_total_ms": round(float(rng.normal(320, 40)), 1) if resp else "",
        "lat_liveness_ms": round(float(rng.normal(120, 15)), 1) if resp else "",
        "lat_match_ms": round(float(rng.normal(250 if mode == "ONLINE" else 60, 30)), 1) if resp else "",
        "lat_schedule_ms": round(float(rng.normal(15, 3)), 1) if resp else "",
        "lat_policy_ms": round(float(abs(rng.normal(3, 1))), 1) if resp else "",
        "s_pad": round(pad, 4) if pad is not None else "", "s_pad_pass_frames": "",
        "s_flash_r": round(float(rng.normal(0.8 if is_live else 0.1, 0.08)), 3) if resp else "",
        "s_flash_amp": "", "s_moire": "", "s_device_conf": "", "s_depth": "",
        "s_match": round(float(rng.normal(0.7, 0.06)), 3) if resp else "", "s_match_margin": "", "s_rekognition": "",
        "eval_label_echo": S.SPECIES_TO_LABEL[species] if resp else "", "policy_version": "2026-11-14.1",
        "bundle_version": 42 if resp else "", "events": (2 if first == "STEP_UP" else 1) if resp else 0,
        "notes": notes,
        # v2 columns: deterministic (no rng draw, so the v1 columns above are unchanged by their addition)
        "face_lock_at_ms": 1_794_630_000_000 + seq * 20_000 if resp else "",
        "s_mask_ring": (0.62 if species in MASKED else 0.21) if resp else "",
        "signals": _signals(species, is_live, first_codes) if resp else "",
    }
    row["scores"] = json.dumps({"pad": row["s_pad"] or None, "pad_label": S.PAD_LABEL.get(lr, "none"),
                                "first_decision": row["first_decision"] or None}) if resp else ""
    return row


def attempts() -> list[dict]:
    rng = np.random.default_rng(1114)
    rows: list[dict] = []
    seq = 0

    def add(*a, **k):
        nonlocal seq
        seq += 1
        rows.append(_row(rng, seq, *a, **k))

    ok_g = {"first": "ALLOW", "final": "ALLOW", "codes": ["ACCESS_OK"]}
    su_pass = {"first": "STEP_UP", "final": "ALLOW", "codes": ["ACCESS_OK"], "first_codes": ["LIVENESS_UNSURE"],
               "next": "CHALLENGE", "first_stage": "liveness", "bio": "BIO_UNSURE"}
    deny_spoof = {"first": "DENY", "final": "DENY", "codes": ["SPOOF_DEVICE_DETECTED"], "live": False}
    deny_flash = {"first": "DENY", "final": "DENY", "codes": ["SPOOF_FLASH_MISMATCH", "SPOOF_PASSIVE"], "live": False}
    deny_chal = {"first": "STEP_UP", "final": "DENY", "codes": ["CHALLENGE_FAILED"],
                 "first_codes": ["MASK_CUE_EDGE"], "next": "CHALLENGE", "live": False, "stage": "challenge"}
    for subj, subj_split in SUBJECTS.items():
        for lg in S.LIGHTING:
            for dist in ("mid", "near"):
                for rep in range(3):
                    mode = "OFFLINE" if rep == 2 and dist == "near" else "ONLINE"
                    out = su_pass if (lg == "dim" and rep == 0) else ok_g
                    add(subj, "bona_fide", lg, dist, out, mode=mode)
        for sp in ("print", "print_eyecut", "phone_photo", "phone_video", "laptop_replay", "paper_mask"):
            n = 8 if subj_split == "test" else 4
            for rep in range(n):
                lg = S.LIGHTING[rep % 3]
                mode = "OFFLINE" if rep == 5 else "ONLINE"
                if sp in ("print_eyecut", "paper_mask"):
                    out = deny_chal
                elif sp == "print":
                    out = deny_flash
                else:
                    out = deny_spoof
                add(subj, sp, lg, "mid", out, mode=mode)
    test_subj = [s for s, sp in SUBJECTS.items() if sp == "test"]
    # deliberate errors / edge cases (test split)
    add(test_subj[0], "phone_video", "office", "mid",
        {"first": "STEP_UP", "final": "ALLOW", "codes": ["ACCESS_OK"], "first_codes": ["LIVENESS_UNSURE"],
         "next": "CHALLENGE", "live": False, "pad": 0.71}, notes="DUMMY step-up bypass (counts as accepted)")
    add(test_subj[1], "paper_mask", "office", "mid", {"first": "ALLOW", "final": "ALLOW", "codes": ["ACCESS_OK"],
                                                      "live": False, "pad": 0.86}, notes="DUMMY first-pass miss")
    add(test_subj[2], "bona_fide", "dim", "far", {"first": "STEP_UP", "final": "DENY", "codes": ["CHALLENGE_FAILED"],
                                                  "first_codes": ["LIVENESS_UNSURE"], "next": "CHALLENGE",
                                                  "stage": "challenge", "bio": "BIO_UNSURE"})
    add(test_subj[3], "bona_fide", "backlit", "far",
        {"first": "STEP_UP", "final": "DENY", "codes": ["QUALITY_LOW_LIGHT"], "first_codes": ["QUALITY_LOW_LIGHT"],
         "next": "RECAPTURE", "first_stage": "quality", "stage": "quality", "bio": ""})
    add(test_subj[0], "bona_fide", "office", "far", {"first": "DENY", "final": "DENY", "codes": ["NOT_ENROLLED"],
                                                     "stage": "match", "candidate": ""})
    add(test_subj[1], "bona_fide", "dim", "mid", {"first": "NO_RESPONSE", "final": "NO_RESPONSE"})
    add(test_subj[2], "bona_fide", "office", "mid",
        {"first": "STEP_UP", "final": "STEP_UP", "codes": ["MATCH_LOW"], "first_codes": ["MATCH_LOW"],
         "next": "SECOND_FACTOR", "first_stage": "match", "stage": "match", "bio": "BIO_UNSURE"},
        notes="DUMMY unresolved step-up")
    add(test_subj[3], "print", "office", "mid", {"first": "NO_RESPONSE", "final": "NO_RESPONSE"})
    add(test_subj[0], "print", "office", "mid", {"first": "DENY", "final": "DENY", "codes": ["RATE_LIMITED"],
                                                 "stage": "final", "live": False})
    for i in range(5):
        add(test_subj[i % 4], "mask_3d", "office", "mid", deny_chal)
    for i in range(6):
        add(test_subj[i % 4], "inject_vcam", "office", "mid",
            {"first": "DENY", "final": "DENY", "codes": ["INJECTION_VIRTUAL_CAMERA"], "stage": "injection",
             "first_stage": "injection", "live": True})
    for i in range(6):
        add(test_subj[i % 4], "bona_fide", "office", "mid",
            {"first": "DENY", "final": "DENY", "codes": ["NOT_ENROLLED"], "stage": "match", "zero_effort": True,
             "candidate": ""})
    # RANDOM_CHALLENGE on a bona fide (passed) and on a print that passed PAD (caught by the challenge)
    add(test_subj[1], "bona_fide", "office", "mid",
        {"first": "STEP_UP", "final": "ALLOW", "codes": ["ACCESS_OK"], "first_codes": ["RANDOM_CHALLENGE"],
         "next": "CHALLENGE", "first_stage": "final", "bio": "BIO_PASS"})
    add(test_subj[2], "print", "office", "mid",
        {"first": "STEP_UP", "final": "DENY", "codes": ["CHALLENGE_FAILED"], "first_codes": ["RANDOM_CHALLENGE"],
         "next": "CHALLENGE", "first_stage": "final", "stage": "challenge", "live": False, "pad": 0.83})
    # a bona fide blocked by the rate limiter (flagged + excluded from BPCER/FRR)
    add(test_subj[3], "bona_fide", "office", "mid", {"first": "DENY", "final": "DENY", "codes": ["RATE_LIMITED"],
                                                     "stage": "final", "bio": ""})
    # live SC demonstrations (excluded from PAD metrics)
    add(test_subj[0], "bona_fide", "office", "mid", {"first": "DENY", "final": "DENY",
                                                     "codes": ["SCHEDULE_OUTSIDE_WINDOW"], "stage": "schedule",
                                                     "bio": "BIO_PASS"}, scenario="S04")
    add(test_subj[0], "bona_fide", "office", "mid", ok_g, mode="OFFLINE", scenario="O01")
    return rows


def comparisons() -> list[dict]:
    rng = np.random.default_rng(2026)
    rows = []

    def gen_block(split, subjects, probes, source, prefix):
        for s in subjects:
            for p in range(probes):
                pid = f"{prefix}{s}_p{p:02d}"
                for gsub in subjects:
                    gen = s == gsub
                    score = float(np.clip(rng.normal(0.68, 0.08) if gen else rng.normal(0.12, 0.07), -1, 1))
                    rows.append({"probe_attempt_id": pid, "probe_subject": s, "gallery_subject": gsub,
                                 "matcher": "arcface", "score": round(score, 5), "genuine": int(gen), "split": split,
                                 "source": source, "run_id": "DUMMY-C1", "model": "dummy", "gallery_template": "mean3",
                                 "probe_lighting": ""})

    dev = [s for s, sp in SUBJECTS.items() if sp == "dev"]
    test = [s for s, sp in SUBJECTS.items() if sp == "test"]
    gen_block("dev", dev, 12, "live", "img_")
    gen_block("test", test, 12, "live", "img_")
    gen_block("dev", [f"DUMMY_LFW_{i:02d}" for i in range(12)], 5, "lfw", "lfw_")
    gen_block("test", [f"DUMMY_LFW_{i:02d}" for i in range(12, 30)], 5, "lfw", "lfw_")
    return rows


def scenarios() -> list[dict]:
    base = {"run_id": "DUMMY-SC1", "backend": "runtime", "detail": "DUMMY", "policy_case": ""}
    out = []
    for i, (sid, ch, status, dec, codes) in enumerate([
        ("S04", "SC1", "PASS", "DENY", "SCHEDULE_OUTSIDE_WINDOW"),
        ("S01", "SC1", "FAIL", "ALLOW", "ACCESS_OK"),
        ("O01", "SC2", "PASS", "ALLOW", "ACCESS_OK;OFFLINE_MODE"),
        ("Y01", "SC2", "BLOCKED", "", ""),
        ("Q01", "CORE", "PASS", "ALLOW", "ACCESS_OK"),
    ]):
        out.append(base | {"ts_utc": f"2026-11-14T07:00:{i:02d}.000Z", "scenario_id": sid, "challenge": ch,
                           "title": f"DUMMY {sid}", "status": status, "expected": "see scenarios.yaml",
                           "observed_decision": dec, "observed_codes": codes})
    return out


def main() -> None:
    eio.write_csv(HERE / "attempts_DUMMY.csv", S.ATTEMPT_COLUMNS, attempts())
    eio.write_csv(HERE / "comparisons_DUMMY.csv", S.COMPARISON_COLUMNS, comparisons())
    eio.write_csv(HERE / "scenarios_DUMMY.csv", S.SCENARIO_COLUMNS, scenarios())
    eio.write_csv(HERE / "exclusions_DUMMY.csv", S.EXCLUSION_COLUMNS, [
        {"attempt_id": "att_DUMMY0003", "reason": "DUMMY: operator mis-tagged lighting", "excluded_by": "DUMMY",
         "ts_utc": "2026-11-14T08:00:00.000Z"}])
    eio.write_csv(HERE / "subjects_DUMMY.csv", ["subject_id", "split", "enrolled_user_id", "consent",
                                                "consent_version", "notes"],
                  [{"subject_id": s, "split": sp, "enrolled_user_id": USERS[s], "consent": "yes",
                    "consent_version": "DUMMY", "notes": "DUMMY"} for s, sp in SUBJECTS.items()])
    print("wrote DUMMY fixtures to", HERE)


if __name__ == "__main__":
    main()
