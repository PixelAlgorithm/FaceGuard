"""Counting rules (PROTOCOL.md section 6) on hand-built rows + an end-to-end run on the DUMMY fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import metrics as M
from evallib import EVAL_DIR, RESULTS_DIR, THRESHOLDS_PATH
from evallib import io as eio
from evallib import schema as S


def mk(species, first, final, codes=None, first_codes=None, *, lighting="office", mode="ONLINE", next_type="",
       liveness=None, cand="u1", target="u1", s_pad="", lat="", subj="X1", cls=None):
    codes = codes if codes is not None else (["ACCESS_OK"] if final == "ALLOW" else [])
    first_codes = first_codes if first_codes is not None else codes
    resp = final != "NO_RESPONSE"
    lr = liveness if liveness is not None else (S.derive_liveness_result(first, "liveness", first_codes) if resp else "")
    r = {c: "" for c in S.ATTEMPT_COLUMNS}
    r.update({
        "run_id": "DUMMY-T", "split": "test", "subject_id": subj, "target_user_id": target,
        "attempt_class": cls or S.attempt_class_for(species), "species": species, "label": S.SPECIES_TO_LABEL[species],
        "lighting": lighting, "distance": "mid", "attempt_id": f"a{id(codes)}", "decision": final,
        "reason_codes": S.join_codes(codes), "first_decision": first if resp else "",
        "first_reason_codes": S.join_codes(first_codes), "mode": mode if resp else "", "liveness_result": lr,
        "candidate_user_id": cand if resp else "", "next_action_type": next_type,
        "stepup_outcome": "none" if first != "STEP_UP" else {"ALLOW": "passed", "DENY": "failed",
                                                              "STEP_UP": "unresolved"}[final],
        "s_pad": s_pad, "latency_ms": lat,
    })
    return M.prep_attempt(r)


SPOOF = ["SPOOF_DEVICE_DETECTED"]
MINS = {"attacks_per_species_test": 30, "bona_fide_test": 120}


def test_stepup_bypass_counts_as_accepted_and_exclusions_raise_apcer():
    rows = [mk("print", "DENY", "DENY", SPOOF) for _ in range(8)]
    rows.append(mk("print", "STEP_UP", "ALLOW", ["ACCESS_OK"], ["LIVENESS_UNSURE"], next_type="CHALLENGE"))
    rows.append(mk("print", "STEP_UP", "DENY", ["CHALLENGE_FAILED"], ["LIVENESS_UNSURE"], next_type="CHALLENGE"))
    rows.append(mk("print", "NO_RESPONSE", "NO_RESPONSE"))
    rows.append(mk("print", "DENY", "DENY", ["RATE_LIMITED"]))
    out = M.pad_block(rows, MINS)
    a = out["apcer_system"]["print"]
    assert (a["k"], a["n"]) == (1, 10)  # NO_RESPONSE + RATE_LIMITED not in the denominator
    assert out["attack_stepup"]["print"]["k"] == 2 and out["attack_stepup"]["print"]["n"] == 10
    assert (out["attack_stepup_bypass"]["print"]["k"], out["attack_stepup_bypass"]["print"]["n"]) == (1, 2)
    assert out["attack_not_evaluated"]["print"] == {"no_response": 1, "system_error": 0, "rate_limited_excluded": 1}
    assert out["rate_limited"]["total"] == 1
    assert out["apnrr"]["k"] == 1 and out["apnrr"]["n"] == 11
    assert a["low_n"] is True
    # PAD-level: the bypass attempt was UNSURE at PAD level, so it is not a PAD-level acceptance
    assert out["apcer_pad"]["print"]["k"] == 0
    assert out["iapmr"]["print"]["k"] == 1


def test_zero_errors_reported_as_upper_bound():
    rows = [mk("phone_photo", "DENY", "DENY", SPOOF) for _ in range(30)]
    a = M.pad_block(rows, MINS)["apcer_system"]["phone_photo"]
    assert a["k"] == 0 and a["n"] == 30
    assert a["ub95"] == pytest.approx(1 - 0.05 ** (1 / 30))
    assert a["rule_of_3"] == pytest.approx(0.1)
    assert a["low_n"] is False


def test_bona_fide_counting_rules():
    rows = [mk("bona_fide", "ALLOW", "ALLOW") for _ in range(6)]
    rows.append(mk("bona_fide", "STEP_UP", "ALLOW", ["ACCESS_OK"], ["LIVENESS_UNSURE"], next_type="CHALLENGE",
                   lighting="dim"))
    rows.append(mk("bona_fide", "STEP_UP", "DENY", ["CHALLENGE_FAILED"], ["LIVENESS_UNSURE"], next_type="CHALLENGE",
                   lighting="dim"))
    rows.append(mk("bona_fide", "DENY", "DENY", ["NOT_ENROLLED"], cand=""))
    rows.append(mk("bona_fide", "NO_RESPONSE", "NO_RESPONSE"))
    rows.append(mk("bona_fide", "STEP_UP", "STEP_UP", ["MATCH_LOW"], ["MATCH_LOW"], next_type="SECOND_FACTOR"))
    out = M.pad_block(rows, MINS)
    # BPCER (any DENY, conservative) counts the failed step-up and the matcher DENY; not STEP_UP->ALLOW
    assert (out["bpcer"]["k"], out["bpcer"]["n"]) == (2, 10)
    assert (out["bpcer_pad_only"]["k"], out["bpcer_pad_only"]["n"]) == (1, 10)
    assert out["bpcer_by_cause"]["pad"] == 1 and out["bpcer_by_cause"]["match"] == 1
    # step-up rate = first decision STEP_UP, reported separately
    assert (out["genuine_stepup_rate"]["k"], out["genuine_stepup_rate"]["n"]) == (3, 10)
    assert out["stepup_clearance"]["k"] == 1 and out["stepup_clearance"]["n"] == 3
    # FRR = final != ALLOW incl. NO_RESPONSE and unresolved STEP_UP
    assert (out["frr_transaction"]["k"], out["frr_transaction"]["n"]) == (4, 11)
    assert out["bpnrr"]["k"] == 1
    assert out["bpcer_by_lighting"]["dim"]["k"] == 1 and out["bpcer_by_lighting"]["dim"]["n"] == 2
    assert out["rank1_live"]["k"] == 9 and out["rank1_live"]["n"] == 9


def test_rate_limited_excluded_and_counted():
    rows = [mk("bona_fide", "ALLOW", "ALLOW") for _ in range(4)]
    rows.append(mk("bona_fide", "DENY", "DENY", ["RATE_LIMITED"]))
    rows.append(mk("print", "DENY", "DENY", ["RATE_LIMITED"]))
    out = M.pad_block(rows, MINS)
    assert (out["bpcer"]["k"], out["bpcer"]["n"]) == (0, 4)
    assert (out["frr_transaction"]["k"], out["frr_transaction"]["n"]) == (0, 4)
    assert out["rate_limited"]["total"] == 2 and out["rate_limited"]["by_species"] == {"bona_fide": 1, "print": 1}
    assert "print" not in out["apcer_system"]


def test_random_challenge_counted_as_stepup_with_trigger():
    rows = [mk("bona_fide", "ALLOW", "ALLOW") for _ in range(8)]
    rows.append(mk("bona_fide", "STEP_UP", "ALLOW", ["ACCESS_OK"], ["RANDOM_CHALLENGE"], next_type="CHALLENGE"))
    rows.append(mk("bona_fide", "STEP_UP", "ALLOW", ["ACCESS_OK"], ["LIVENESS_UNSURE"], next_type="CHALLENGE"))
    out = M.pad_block(rows, MINS)
    su = out["genuine_stepup_rate"]
    assert (su["k"], su["n"]) == (2, 10)
    assert su["by_trigger"] == {"random_challenge": 1, "liveness_unsure": 1}
    assert out["genuine_stepup_rate_excl_random"]["k"] == 1
    # a RANDOM_CHALLENGE is PAD-level PASS (signals passed), not UNSURE
    assert S.derive_liveness_result("STEP_UP", "final", ["RANDOM_CHALLENGE"]) == "PASS"


def test_latency_block_uses_kiosk_render_and_species_decision_cells():
    rows = [mk("bona_fide", "ALLOW", "ALLOW", lat=str(1000 + 10 * i)) for i in range(30)]
    for r in rows:
        r["latency_source"] = "kiosk_render"
        r["_lat_server_total_ms"] = 300.0
    rows.append(mk("print", "DENY", "DENY", SPOOF, lat="900"))
    rows[-1]["latency_source"] = "kiosk_render"
    lat = M.latency_block(rows, 2000, 200, 1, 20)
    assert lat["decision_time_source"] == "kiosk_render" and lat["measured"]
    o = lat["sla_allow_path"]["overall"]
    assert o["n"] == 30 and o["within_sla"]["k"] == 30 and o["p50_ci95"][0] <= o["p50"] <= o["p50_ci95"][1]
    assert lat["by_species_final_decision"]["print"]["DENY"]["client"]["n"] == 1
    assert lat["server_total"]["overall"]["p50"] == 300.0


def test_latency_not_measured_without_render():
    rows = [mk("bona_fide", "ALLOW", "ALLOW", lat="") for _ in range(5)]
    lat = M.latency_block(rows, 2000, 50, 1, 20)
    assert lat["measured"] is False and lat["decision_time_source"] == "not measured" and "note" in lat


def test_max_apcer_headline_uses_upper_bound():
    rows = [mk("print", "DENY", "DENY", SPOOF) for _ in range(100)]
    rows += [mk("phone_video", "DENY", "DENY", SPOOF) for _ in range(9)]  # 0/9 -> large UB
    rows += [mk("print", "ALLOW", "ALLOW", liveness="PASS")]  # 1/101
    out = M.pad_block(rows, MINS)
    assert out["max_apcer_system"]["species"] == "phone_video"  # highest UB (skill rule)
    assert out["max_apcer_point"]["species"] == "print"  # highest point estimate
    assert "print_eyecut" in out["species_missing"]


def test_injection_reported_separately_not_in_apcer():
    rows = [mk("inject_vcam", "DENY", "DENY", ["INJECTION_VIRTUAL_CAMERA"]) for _ in range(4)]
    rows += [mk("print", "DENY", "DENY", SPOOF)]
    out = M.pad_block(rows, MINS)
    assert "inject_vcam" not in out["apcer_system"]
    assert out["injection"]["flagged_injection"]["k"] == 4
    assert out["injection"]["accepted"]["k"] == 0


def test_end_to_end_on_dummy_fixtures(dummy_args, tmp_path):
    assert M.main(dummy_args) == 0
    out = tmp_path / "out"
    m = json.loads((out / "metrics.json").read_text())
    info = m["RUN_INFO"]
    assert info["dummy_data"] is True
    assert info["inputs"]["attempts"]["rows_excluded"] == 1
    assert info["inputs"]["attempts"]["scenario_rows"] == 2
    assert info["subject_disjoint"] is True
    assert len(info["thresholds"]["sha256"]) == 64
    cfg_pv = eio.load_yaml(THRESHOLDS_PATH)["policy_version"]
    assert info["thresholds"]["policy_version"] == cfg_pv
    # DUMMY rows carry policy_version 2026-11-14.1: a mismatch with the config must be flagged, never hidden
    assert info["policy_version_consistent"] is (cfg_pv == "2026-11-14.1")
    pad = m["pad"]
    assert (pad["apcer_system"]["phone_video"]["k"], pad["apcer_system"]["phone_video"]["n"]) == (1, 33)
    # 32 plain prints + 1 print that passed PAD and was caught by a RANDOM_CHALLENGE; NO_RESPONSE + RL excluded
    assert (pad["apcer_system"]["print"]["k"], pad["apcer_system"]["print"]["n"]) == (0, 33)
    assert pad["attack_stepup"]["print"]["by_trigger"] == {"random_challenge": 1}
    assert pad["apcer_system"]["mask_3d"]["low_n"] is True
    assert (pad["bpcer"]["k"], pad["bpcer"]["n"]) == (3, 77)  # bona fide RATE_LIMITED row excluded
    assert (pad["frr_transaction"]["k"], pad["frr_transaction"]["n"]) == (5, 78)
    assert pad["genuine_stepup_rate"]["by_trigger"]["random_challenge"] == 1
    assert pad["far_zero_effort"]["k"] == 0 and pad["far_zero_effort"]["n"] == 6
    arc = m["match"]["arcface"]
    assert arc["counts"]["test"] == {"genuine": 138, "impostor": 1674}
    assert arc["calibration"]["n_impostor"] == 684 and arc["calibration"]["resolution_ok"]
    assert arc["test"]["at_configured_online"]["threshold"] == 0.5
    assert arc["test"]["at_configured_offline"]["threshold"] == 0.55
    lat = m["latency"]["sla_allow_path"]["overall"]
    assert lat["n"] > 0 and lat["p50"] <= lat["p95"] <= lat["max"]
    assert lat["p95_ci95"][0] <= lat["p95"] <= lat["p95_ci95"][1]
    scn = {r["id"]: r for r in m["scenarios"]["table"]}
    assert scn["S01"]["status"] == "FAIL" and scn["S04"]["status"] == "PASS"
    assert scn["S09"]["status"] == "NOT_RUN"  # no run recorded -> never PASS
    assert scn["S04"]["live_evidence"]["n"] == 1 and scn["S04"]["live_evidence"]["matching_expected"] == 1
    assert scn["O01"]["live_evidence"]["matching_expected"] == 1
    assert pad["rate_limited"]["total"] == 2  # one print + one bona fide RATE_LIMITED row in the test split

    assert {t["target"] for t in m["hid_targets"]} >= {"False acceptance rate (FAR)", "False rejection rate (FRR)"}
    assert m["trials_needed"][0]["n_0_errors"] == 1497
    for f in ("det_arcface.png", "det_arcface_dark.png", "det_pad.png", "det_pad_dark.png", "RUN_INFO.md"):
        assert (out / f).exists(), f
    txt = (out / "RUN_INFO.md").read_text()
    assert "AUTO:BEGIN" in txt
    # shipped switches are recorded with the hash (pad-evaluation skill): flash state, moire / M2, random rate
    sw = info["switches"]
    assert sw["thresholds_sha256"] == info["thresholds"]["sha256"]
    assert ("ADVISORY" in txt) is (sw["flash"]["enforce"] is False)
    for needle in ("colour flash:", "moire: enforce", "mask M2 RGB ring: enforce", "random challenge",
                   "rate limit: enabled", "Rekognition (`match.rekognition.enabled`)", "liveness.depth.enabled"):
        assert needle in txt, needle


def test_run_info_lists_capture_manifest(dummy_args, tmp_path, fixtures):
    att = tmp_path / "in" / "attempts.csv"
    att.parent.mkdir()
    att.write_text((fixtures / "attempts_DUMMY.csv").read_text())
    eio.write_json(tmp_path / "in" / "runs" / "DUMMY-R1.json", {
        "run_id": "DUMMY-R1", "thresholds_sha256": "0" * 64, "transport_used": "sse", "duplicates_dropped": 2,
        "rate_limit_handling": {"reset_rate_limit": "attempt", "rate_limit_enabled_config": True},
        "edge_config_diff": ["flash_enforce: edge True != thresholds.yaml False"]})
    args = list(dummy_args)
    args[args.index("--attempts") + 1] = str(att)
    assert M.main(args) == 0
    m = json.loads((tmp_path / "out" / "metrics.json").read_text())
    run = m["RUN_INFO"]["capture_runs"]["DUMMY-R1"]
    assert run["duplicates_dropped"] == 2 and run["reset_rate_limit"] == "attempt"
    notes = " ".join(m["RUN_INFO"]["notes"])
    assert "thresholds sha256 000000000000" in notes and "flash_enforce" in notes
    assert "| `DUMMY-R1` | attempt | True | sse | 2 |" in (tmp_path / "out" / "RUN_INFO.md").read_text()


def test_run_info_manual_section_preserved(dummy_args, tmp_path):
    out = tmp_path / "out"
    assert M.main(dummy_args) == 0
    p = out / "RUN_INFO.md"
    p.write_text(p.read_text().replace("- Camera (model / label):", "- Camera (model / label): DUMMY CAM 9000"))
    assert M.main(dummy_args) == 0
    txt = p.read_text()
    assert "DUMMY CAM 9000" in txt and txt.count("AUTO:BEGIN") == 1


def test_refuses_to_write_dummy_into_results(dummy_args):
    args = list(dummy_args)
    args[args.index("--out-dir") + 1] = str(RESULTS_DIR)
    before = sorted(p.name for p in RESULTS_DIR.iterdir())
    with pytest.raises(SystemExit):
        M.main(args)
    assert sorted(p.name for p in RESULTS_DIR.iterdir()) == before


def test_validation_errors_abort(tmp_path, fixtures):
    bad = tmp_path / "attempts.csv"
    txt = (fixtures / "attempts_DUMMY.csv").read_text().splitlines()
    txt[1] = txt[1].replace(",bona_fide,bona_fide,", ",bona_fide,video,", 1)
    bad.write_text("\n".join(txt) + "\n")
    assert M.main(["--attempts", str(bad), "--comparisons", str(tmp_path / "none.csv"),
                   "--scenarios", str(tmp_path / "none2.csv"), "--out-dir", str(tmp_path / "o")]) == 2


def test_no_inputs_returns_3(tmp_path):
    assert M.main(["--attempts", str(tmp_path / "a.csv"), "--comparisons", str(tmp_path / "c.csv"),
                   "--scenarios", str(tmp_path / "s.csv"), "--out-dir", str(tmp_path / "o")]) == 3
    assert not (Path(tmp_path) / "o").exists()


# ------------------------------------------------------------------ DE-07: FMR independence + source split

def _cmp_rows(n_subj=10, n_probe=30, lfw_pairs=0, false_match_pairs=()):
    """Live: every probe of every subject vs every other gallery subject; optional LFW-vs-LFW padding."""
    rows = []
    subs = [f"DUMMY_S{i:02d}" for i in range(n_subj)]
    for split in ("dev", "test"):
        for p in subs:
            for j in range(n_probe):
                pid = f"img_{split}_{p}_{j}"
                for g in subs:
                    fm = (p, g) in false_match_pairs and j == 0
                    rows.append({"probe_attempt_id": pid, "probe_subject": p, "gallery_subject": g,
                                 "matcher": "arcface", "score": 0.9 if (g == p or fm) else 0.1,
                                 "genuine": "1" if g == p else "0", "split": split, "source": "live",
                                 "run_id": "DUMMY-C", "model": "dummy"})
        for k in range(lfw_pairs):
            rows.append({"probe_attempt_id": f"lfw_{split}_{k}", "probe_subject": f"LFW_{k}",
                         "gallery_subject": f"LFW_{k + 1}", "matcher": "arcface", "score": 0.05, "genuine": "0",
                         "split": split, "source": "lfw", "run_id": "DUMMY-C", "model": "dummy"})
    return rows


def _th():
    return eio.load_yaml(THRESHOLDS_PATH)


def test_fmr_claim_needs_independent_subject_pairs_not_raw_comparisons(tmp_path):
    rows = _cmp_rows()  # 10 x 30 x 9 = 2700 impostor comparisons > 1497, but only 90 subject pairs
    blk = M.match_block(rows, _th(), "dev", "test", tmp_path, make_plots=False)["arcface"]
    t = blk["test"]
    assert blk["counts"]["test"]["impostor"] == 2700
    # T-02: (A,B) and (B,A) are one identity pair: 10 subjects -> 45 unordered pairs, not 90
    assert t["impostor_units_live"] == {"comparisons": 2700, "probe_images": 300, "subject_pairs": 45}
    assert t["fmr_claim_supportable"] is False
    assert "distinct unordered live impostor subject pairs" in t["fmr_claim_basis"]


def test_headline_fmr_is_live_only_and_lfw_reported_separately(tmp_path):
    rows = _cmp_rows(lfw_pairs=5000, false_match_pairs={("DUMMY_S01", "DUMMY_S02")})
    blk = M.match_block(rows, _th(), "dev", "test", tmp_path, make_plots=False)["arcface"]
    live = blk["test"]["at_configured_online_live"]["fmr"]
    assert (live["k"], live["n"]) == (1, 2700)  # LFW padding never dilutes the headline FMR
    pooled = blk["test"]["at_configured_online"]["fmr"]
    assert pooled["n"] == 7700
    assert blk["test"]["fmr_subject_pair_level_live"]["k"] == 1
    assert blk["test"]["fmr_subject_pair_level_live"]["n"] == 45
    targets = eio.load_yaml(EVAL_DIR / "targets.yaml")
    far = next(r for r in M.target_rows(None, {"arcface": blk}, None, targets)
               if r["target"].startswith("False acceptance"))
    assert far["measured"]["comparison_level"]["rate"] == live["rate"]  # shown for information only


def _row(blk, prefix):
    targets = eio.load_yaml(EVAL_DIR / "targets.yaml")
    return next(r for r in M.target_rows(None, {"arcface": blk}, None, targets) if r["target"].startswith(prefix))


def test_far_row_never_supported_from_dependent_comparisons(tmp_path):
    """T-01: 2700 error-free comparisons from 10 identities (45 pairs) must not read as FAR <= 0.2 % SUPPORTED."""
    blk = M.match_block(_cmp_rows(), _th(), "dev", "test", tmp_path, make_plots=False)["arcface"]
    assert blk["test"]["at_configured_online_live"]["fmr"]["ub95"] <= 0.002  # comparison-level CP would claim it
    far = _row(blk, "False acceptance")
    assert not far["status"].startswith("SUPPORTED")
    assert far["measured"]["n"] == 45 and far["measured"]["unit"] == "unordered live impostor subject pairs"
    assert far["measured"]["ub95"] == blk["test"]["fmr_subject_pair_level_live"]["ub95"]


def test_far_row_without_pair_level_record_is_not_confirmed(tmp_path):
    blk = M.match_block(_cmp_rows(), _th(), "dev", "test", tmp_path, make_plots=False)["arcface"]
    blk = {**blk, "test": {k: v for k, v in blk["test"].items() if k != "fmr_subject_pair_level_live"}}
    far = _row(blk, "False acceptance")
    assert far["status"].startswith("NOT CONFIRMED") and "fmr_claim_basis" in far["status"]


def test_fnmr_row_is_live_only_lfw_genuine_padding_ignored(tmp_path):
    """T-03: LFW genuine pairs (matched within LFW) must not inflate the face-auth accuracy row."""
    base = _cmp_rows()
    lfw_gen = [{"probe_attempt_id": f"lfwg_{k}", "probe_subject": f"LFW_{k}", "gallery_subject": f"LFW_{k}",
                "matcher": "arcface", "score": 0.95, "genuine": "1", "split": "test", "source": "lfw",
                "run_id": "DUMMY-C", "model": "dummy"} for k in range(3000)]
    a = _row(M.match_block(base, _th(), "dev", "test", tmp_path, make_plots=False)["arcface"], "Face auth")
    b = _row(M.match_block(base + lfw_gen, _th(), "dev", "test", tmp_path, make_plots=False)["arcface"],
             "Face auth")
    assert a["measured"]["n"] == b["measured"]["n"] == 300
    assert a["status"] == b["status"] and "not independent" in b["measured"]["what"]
