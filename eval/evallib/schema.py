"""CSV schemas, enums and validation for eval/results/*.csv.

Single source for column names; PROTOCOL.md section 7 documents the same schema in prose.
Reason-code classes follow docs/DECISION_POLICY.md section 6 (closed list).
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable
from datetime import datetime

# --------------------------------------------------------------------- enums

# Fine-grained PAI species (pad-evaluation skill section 2.2) -> coarse X-Eval-Label (docs/API.md 3.8)
SPECIES_TO_LABEL: dict[str, str] = {
    "bona_fide": "bona_fide",
    "print": "print",
    "print_eyecut": "mask_paper",
    "phone_photo": "screen_photo",
    "phone_video": "video",
    "laptop_replay": "video",
    "paper_mask": "mask_paper",
    "mask_3d": "mask_3d",
    "inject_vcam": "injection",
}
SPECIES: list[str] = list(SPECIES_TO_LABEL)  # fixed order -> fixed chart colour per entity
ATTACK_SPECIES: list[str] = [s for s in SPECIES if s not in ("bona_fide", "inject_vcam")]
LABELS: list[str] = ["bona_fide", "print", "screen_photo", "video", "mask_paper", "mask_3d", "injection"]
LABEL_DEFAULT_SPECIES: dict[str, str] = {
    "bona_fide": "bona_fide",
    "print": "print",
    "screen_photo": "phone_photo",
    "video": "phone_video",
    "mask_paper": "paper_mask",
    "mask_3d": "mask_3d",
    "injection": "inject_vcam",
}
HID_SCENARIO: dict[str, str] = {  # coarse label -> wording of the HID brief (docs/PROBLEM.md section 1)
    "bona_fide": "Bona fide (live person)",
    "print": "Printed photo",
    "screen_photo": "Screen replay (photo)",
    "video": "Video replay",
    "mask_paper": "Mask (printed / paper)",
    "mask_3d": "Mask (3D)",
    "injection": "Injection (virtual camera) - reported separately, not PAD",
}
SPECIES_DESC: dict[str, str] = {
    "bona_fide": "live enrolled subject",
    "print": "A4 colour print of a frontal photo",
    "print_eyecut": "print with eye holes cut, worn (real eyes blink)",
    "phone_photo": "photo on a phone, full brightness",
    "phone_video": "video (blink/smile) replayed on a phone",
    "laptop_replay": "video replayed on a laptop/tablet",
    "paper_mask": "printed paper mask shaped on the face",
    "mask_3d": "rigid / 3D-printed mask (stretch tier)",
    "inject_vcam": "virtual camera (OBS) playing a video - injection, not PAD",
}
ATTEMPT_CLASSES = ["genuine", "zero_effort", "attack", "injection"]
LIGHTING = ["office", "backlit", "dim"]
DISTANCE = ["near", "mid", "far"]  # ~30 / ~45 / ~60 cm from the camera
SPLITS = ["dev", "test"]
DECISIONS = ["ALLOW", "STEP_UP", "DENY", "NO_RESPONSE"]
RESPONDED = {"ALLOW", "STEP_UP", "DENY"}
STEPUP_OUTCOMES = ["none", "passed", "failed", "unresolved"]
LIVENESS_RESULTS = ["PASS", "UNSURE", "FAIL", "NOT_EVALUATED", "UNKNOWN"]
LATENCY_SOURCES = ["edge_face_lock_to_decision", "kiosk_render", "capture_recv_minus_face_lock", "none"]


def attempt_class_for(species: str, zero_effort: bool = False) -> str:
    if species == "inject_vcam":
        return "injection"
    if species == "bona_fide":
        return "zero_effort" if zero_effort else "genuine"
    return "attack"


# --------------------------------------------------------------------- reason codes (DECISION_POLICY 6)

PAD_HARD = {
    "SPOOF_PASSIVE", "SPOOF_DEVICE_DETECTED", "SPOOF_MOIRE", "SPOOF_FLASH_MISMATCH",
    "SPOOF_FLAT_DEPTH", "SPOOF_DEPTH_SCALE",
}
MASK = {"MASK_CUE_RIGID", "MASK_CUE_EDGE", "MASK_CUE_SHAPE", "MASK_CUE_SPECTRAL"}
LIVENESS_UNSURE = {"LIVENESS_UNSURE"}
CHALLENGE = {"CHALLENGE_FAILED"}
INJECTION = {"INJECTION_VIRTUAL_CAMERA"}
QUALITY = {"QUALITY_LOW_LIGHT", "QUALITY_BLUR", "QUALITY_POSE", "QUALITY_DEPTH_INVALID", "MULTIPLE_FACES"}
MATCH = {"MATCH_LOW", "MATCH_AMBIGUOUS", "NOT_ENROLLED"}
SCHEDULE_DENY = {
    "SCHEDULE_OUTSIDE_WINDOW", "SCHEDULE_NO_ENTITLEMENT", "SCHEDULE_ZONE_NOT_PERMITTED",
    "SCHEDULE_HOLIDAY", "SCHEDULE_REVOKED",
}
SCHEDULE_OTHER = {"SCHEDULE_GRACE_WINDOW", "SCHEDULE_HIGH_RISK_ZONE"}
MODE = {
    "OFFLINE_MODE", "OFFLINE_HIGH_RISK_ZONE", "OFFLINE_FALLBACK_REQUIRED",
    "SCHEDULE_EXPIRED_CACHE", "SCHEDULE_BUNDLE_INVALID",
}
FALLBACK = {"FALLBACK_OK", "FALLBACK_FAILED"}
SYSTEM = {"RATE_LIMITED", "SYSTEM_ERROR"}
FINAL = {"ACCESS_OK"}
RANDOM = {"RANDOM_CHALLENGE"}  # policy-random deformation challenge on a would-be ALLOW (counted as step-up)
LIVENESS_CODES = PAD_HARD | MASK | LIVENESS_UNSURE
ALL_CODES = (
    PAD_HARD | MASK | LIVENESS_UNSURE | CHALLENGE | INJECTION | QUALITY | MATCH | SCHEDULE_DENY
    | SCHEDULE_OTHER | MODE | FALLBACK | SYSTEM | FINAL | RANDOM
)
CONDITIONS = ["normal", "dim", "backlit", "far"]  # edge eval-context enum (lead decision, round 2)


def stepup_trigger(first_codes) -> str:
    """Why the FIRST decision was STEP_UP (reporting only)."""
    c = set(first_codes)
    if c & RANDOM:
        return "random_challenge"
    if c & QUALITY:
        return "quality_recapture"
    if c & (LIVENESS_CODES | MASK):
        return "liveness_unsure"
    if c & MATCH:
        return "match_unsure"
    if c & SCHEDULE_OTHER:
        return "schedule"
    if c & MODE:
        return "offline_rules"
    return "other"


def split_codes(s: str | None) -> list[str]:
    if not s:
        return []
    return [c for c in (p.strip() for p in str(s).split(";")) if c]


def join_codes(codes: Iterable[str]) -> str:
    return ";".join(c for c in codes if c)


def deny_cause(codes: Iterable[str]) -> str:
    """Attribute a final DENY to one cause (priority order documented in PROTOCOL.md 6.4)."""
    c = set(codes)
    if c & SYSTEM:
        return "system"
    if c & SCHEDULE_DENY:
        return "schedule"
    if c & (PAD_HARD | MASK | CHALLENGE | INJECTION | LIVENESS_UNSURE):
        return "pad"
    if c & QUALITY:
        return "quality"
    if c & MATCH:
        return "match"
    if c & FALLBACK:
        return "fallback"
    return "other"


def derive_liveness_result(decision: str, stage: str, codes: Iterable[str]) -> str:
    """PAD-level label from the FIRST decision when the edge does not send it explicitly.

    PASS / UNSURE / FAIL / NOT_EVALUATED / UNKNOWN. UNKNOWN = BIO_FAIL with only NOT_ENROLLED: the policy
    hides liveness UNSURE codes on BIO_FAIL (DECISION_POLICY 4), so PASS vs UNSURE cannot be told apart;
    metrics treat UNKNOWN as PASS for APCER (conservative).
    """
    c = set(codes)
    stage = (stage or "").lower()
    if decision not in RESPONDED:
        return "NOT_EVALUATED"
    if c & SYSTEM or stage in ("quality", "injection") or c & INJECTION or (c & QUALITY and decision != "ALLOW"):
        return "NOT_EVALUATED"
    if decision == "DENY" and (c & PAD_HARD or c & MASK or stage == "liveness"):
        return "FAIL"
    if c & LIVENESS_CODES:  # unsure codes on STEP_UP, or BIO_UNSURE + schedule deny (N11)
        return "UNSURE"
    if decision == "DENY" and c <= (MATCH | MODE) and "NOT_ENROLLED" in c:
        return "UNKNOWN"
    return "PASS"


PAD_LABEL = {"PASS": "live", "UNSURE": "unsure", "FAIL": "spoof", "NOT_EVALUATED": "none", "UNKNOWN": "unknown"}

# --------------------------------------------------------------------- attempts.csv

ATTEMPT_COLUMNS: list[str] = [
    # who / what (operator-provided via capture.py flags, plan or prompt)
    "run_id", "plan_seq", "ts_utc", "split", "subject_id", "target_user_id", "attempt_class",
    "species", "label", "condition", "lighting", "distance", "zone", "kiosk_id", "operator", "scenario",
    # what the edge decided (copied from the decision events, never typed by the operator)
    "attempt_id", "decision", "reason_codes", "stage", "bio_result", "schedule_result", "mode",
    "cache_state", "candidate_user_id", "liveness_result", "liveness_result_source",
    "first_decision", "first_reason_codes", "first_stage", "next_action_type", "stepup_methods",
    "stepup_outcome", "stepup_rounds", "recaptures", "stepup_ms", "resolved_codes",
    # latency
    "latency_ms", "latency_source", "lat_server_total_ms", "lat_liveness_ms", "lat_match_ms",
    "lat_schedule_ms", "lat_policy_ms",
    # key scores (first decision)
    "s_pad", "s_pad_pass_frames", "s_flash_r", "s_flash_amp", "s_moire", "s_device_conf", "s_depth",
    "s_match", "s_match_margin", "s_rekognition",
    # skill section 6.1 compatibility + provenance
    "scores", "eval_label_echo", "policy_version", "bundle_version", "events", "notes",
    # v2 (2026-11-14 evening): calibration + de-duplication support. Optional when reading older files.
    "face_lock_at_ms", "s_mask_ring", "signals",
]
ATTEMPT_OPTIONAL_COLUMNS = {"face_lock_at_ms", "s_mask_ring", "signals"}
ATTEMPT_INT_COLS = {  # plan_seq is an identifier (plan row number, "f<n>" flags mode, "i<n>" interactive)
    "stepup_rounds", "recaptures", "events", "s_pad_pass_frames", "face_lock_at_ms",
}
ATTEMPT_FLOAT_COLS = {
    "stepup_ms", "latency_ms", "lat_server_total_ms", "lat_liveness_ms", "lat_match_ms", "lat_schedule_ms",
    "lat_policy_ms", "s_pad", "s_flash_r", "s_flash_amp", "s_moire", "s_device_conf", "s_depth", "s_match",
    "s_match_margin", "s_rekognition", "s_mask_ring",
}

COMPARISON_COLUMNS: list[str] = [
    # pad-evaluation skill section 6.2 (exact) + provenance extras
    "probe_attempt_id", "probe_subject", "gallery_subject", "matcher", "score", "genuine", "split", "source",
    "run_id", "model", "gallery_template", "probe_lighting",
]
COMPARISON_SPLITS = ["dev", "test", "cross"]
COMPARISON_SOURCES = ["live", "lfw"]
MATCHERS = ["arcface", "rekognition"]

SCENARIO_COLUMNS: list[str] = [
    "run_id", "ts_utc", "scenario_id", "challenge", "title", "backend", "status", "expected",
    "observed_decision", "observed_codes", "detail", "policy_case",
]
SCENARIO_STATUSES = ["PASS", "FAIL", "NOT_RUN", "BLOCKED", "ERROR"]

EXCLUSION_COLUMNS = ["attempt_id", "reason", "excluded_by", "ts_utc"]

# privacy guard: names that must never appear as a column / score key in results
FORBIDDEN_KEY_RE = re.compile(r"(embed|vector|image|img|frame|crop|jpeg|jpg|png|b64|base64|template|photo|face_?data)",
                              re.IGNORECASE)
LONG_BLOB_RE = re.compile(r"[A-Za-z0-9+/=_-]{256,}")


def is_dummy_run(run_id: str | None) -> bool:
    return bool(run_id) and str(run_id).upper().startswith("DUMMY")


def _parse_ts(s: str) -> bool:
    try:
        datetime.fromisoformat(str(s))  # 3.11 parses a trailing Z
        return str(s).endswith("Z") or str(s).endswith("+00:00")
    except ValueError:
        return False


def _num(v: str, cast) -> bool:
    if v in ("", None):
        return True
    try:
        x = cast(v)
        return not (isinstance(x, float) and math.isnan(x))  # NaN not allowed
    except (TypeError, ValueError):
        return False


def privacy_check_value(col: str, v) -> str | None:
    v = "" if v is None else str(v)
    if v and (len(v) > 2000 or LONG_BLOB_RE.search(v)):
        return f"{col}: value looks like a blob ({len(v)} chars) - images/embeddings must never be stored"
    return None


def validate_attempts(rows: list[dict], header: list[str], results_file: bool = True) -> tuple[list[str], list[str]]:
    """Return (errors, warnings). results_file=True forbids DUMMY rows (eval/results/ is real data only)."""
    errors: list[str] = []
    warnings: list[str] = []
    missing = [c for c in ATTEMPT_COLUMNS if c not in header and c not in ATTEMPT_OPTIONAL_COLUMNS]
    if missing:
        errors.append(f"attempts.csv missing columns: {missing}")
        return errors, warnings
    extra = [c for c in header if c not in ATTEMPT_COLUMNS]
    for c in extra:
        if FORBIDDEN_KEY_RE.search(c):
            errors.append(f"forbidden column name (biometric data?): {c}")
        else:
            warnings.append(f"extra column ignored: {c}")
    seen_ids: dict[str, int] = {}
    subj_split: dict[str, str] = {}
    for i, r in enumerate(rows, start=2):  # line numbers incl. header
        where = f"attempts.csv line {i}"
        if results_file and is_dummy_run(r.get("run_id")):
            errors.append(f"{where}: DUMMY row in a results file (run_id={r.get('run_id')})")
        sp = r.get("species", "")
        if sp not in SPECIES:
            errors.append(f"{where}: unknown species {sp!r}")
        elif r.get("label") != SPECIES_TO_LABEL[sp]:
            errors.append(f"{where}: label {r.get('label')!r} inconsistent with species {sp!r}")
        ac = r.get("attempt_class", "")
        if sp in SPECIES:
            ok_classes = {"genuine", "zero_effort"} if sp == "bona_fide" else {attempt_class_for(sp)}
            if ac not in ok_classes:
                errors.append(f"{where}: attempt_class {ac!r} inconsistent with species {sp!r}")
        if r.get("split") not in SPLITS:
            errors.append(f"{where}: split must be dev|test, got {r.get('split')!r}")
        subj = r.get("subject_id", "")
        if not subj:
            errors.append(f"{where}: empty subject_id")
        elif subj in subj_split and subj_split[subj] != r.get("split"):
            errors.append(f"{where}: subject {subj} appears in both splits (must be subject-disjoint)")
        else:
            subj_split.setdefault(subj, r.get("split", ""))
        if r.get("condition") not in CONDITIONS:
            errors.append(f"{where}: condition must be one of {CONDITIONS}")
        if r.get("lighting") not in LIGHTING:
            errors.append(f"{where}: lighting must be one of {LIGHTING}")
        if r.get("distance") not in DISTANCE:
            errors.append(f"{where}: distance must be one of {DISTANCE}")
        d = r.get("decision", "")
        if d not in DECISIONS:
            errors.append(f"{where}: decision {d!r} not in {DECISIONS}")
        fd = r.get("first_decision", "")
        if d in RESPONDED and fd not in RESPONDED:
            errors.append(f"{where}: first_decision {fd!r} missing for a responded attempt")
        if d == "NO_RESPONSE" and fd not in ("", "NO_RESPONSE"):
            errors.append(f"{where}: NO_RESPONSE row with a first_decision")
        if d in RESPONDED and fd in ("ALLOW", "DENY") and d != fd:
            errors.append(f"{where}: terminal first decision {fd} changed to {d}")
        so = r.get("stepup_outcome", "")
        if so not in STEPUP_OUTCOMES:
            errors.append(f"{where}: stepup_outcome {so!r} not in {STEPUP_OUTCOMES}")
        elif d in RESPONDED:
            expect = ("none" if fd != "STEP_UP" else
                      {"ALLOW": "passed", "DENY": "failed", "STEP_UP": "unresolved"}[d])
            if so != expect:
                errors.append(f"{where}: stepup_outcome {so!r} inconsistent with {fd}->{d} (expected {expect})")
        lr = r.get("liveness_result", "")
        if d in RESPONDED and lr not in LIVENESS_RESULTS:
            errors.append(f"{where}: liveness_result {lr!r} not in {LIVENESS_RESULTS}")
        aid = r.get("attempt_id", "")
        if not aid:
            errors.append(f"{where}: empty attempt_id")
        elif aid in seen_ids:
            errors.append(f"{where}: duplicate attempt_id {aid} (first at line {seen_ids[aid]})")
        else:
            seen_ids[aid] = i
        if not _parse_ts(r.get("ts_utc", "")):
            errors.append(f"{where}: ts_utc must be ISO-8601 UTC (…Z), got {r.get('ts_utc')!r}")
        for c in ATTEMPT_FLOAT_COLS:
            if not _num(r.get(c, ""), float):
                errors.append(f"{where}: {c} not numeric: {r.get(c)!r}")
        for c in ATTEMPT_INT_COLS:
            if not _num(r.get(c, ""), int):
                errors.append(f"{where}: {c} not an integer: {r.get(c)!r}")
        lat = r.get("latency_ms", "")
        if lat not in ("", None) and _num(lat, float) and float(lat) < 0:
            errors.append(f"{where}: negative latency_ms")
        for c in ("reason_codes", "first_reason_codes", "resolved_codes"):
            for code in split_codes(r.get(c)):
                if code not in ALL_CODES:
                    warnings.append(f"{where}: {c} has non-canonical code {code!r}")
        if r.get("scores"):
            try:
                sc = json.loads(r["scores"])
            except ValueError:
                sc = None
            if not isinstance(sc, dict):
                errors.append(f"{where}: scores is not a JSON object")
            else:
                for k, v in sc.items():
                    if FORBIDDEN_KEY_RE.search(k) or isinstance(v, (list, dict)):
                        errors.append(f"{where}: scores key {k!r} not allowed (scalars only, no biometrics)")
        for c, v in r.items():
            msg = privacy_check_value(c, v or "")
            if msg:
                errors.append(f"{where}: {msg}")
    return errors, warnings


def validate_comparisons(rows: list[dict], header: list[str], results_file: bool = True) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    missing = [c for c in COMPARISON_COLUMNS if c not in header]
    if missing:
        return [f"comparisons.csv missing columns: {missing}"], warnings
    for i, r in enumerate(rows, start=2):
        where = f"comparisons.csv line {i}"
        if results_file and is_dummy_run(r.get("run_id")):
            errors.append(f"{where}: DUMMY row in a results file")
        if r.get("matcher") not in MATCHERS:
            errors.append(f"{where}: matcher must be one of {MATCHERS}")
        if r.get("split") not in COMPARISON_SPLITS:
            errors.append(f"{where}: split must be one of {COMPARISON_SPLITS}")
        if r.get("source") not in COMPARISON_SOURCES:
            errors.append(f"{where}: source must be one of {COMPARISON_SOURCES}")
        g = r.get("genuine")
        if g not in ("0", "1"):
            errors.append(f"{where}: genuine must be 0/1")
        elif (g == "1") != (r.get("probe_subject") == r.get("gallery_subject")):
            errors.append(f"{where}: genuine flag inconsistent with probe/gallery subjects")
        try:
            s = float(r.get("score", ""))
            if r.get("matcher") == "arcface" and not -1.0001 <= s <= 1.0001:
                errors.append(f"{where}: arcface cosine out of [-1, 1]: {s}")
        except ValueError:
            errors.append(f"{where}: score not numeric")
        for c, v in r.items():
            msg = privacy_check_value(c, v or "")
            if msg:
                errors.append(f"{where}: {msg}")
        if len(errors) > 50:
            errors.append("... (truncated)")
            break
    return errors, warnings


def validate_scenarios(rows: list[dict], header: list[str], results_file: bool = True) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    missing = [c for c in SCENARIO_COLUMNS if c not in header]
    if missing:
        return [f"scenarios.csv missing columns: {missing}"], []
    for i, r in enumerate(rows, start=2):
        if results_file and is_dummy_run(r.get("run_id")):
            errors.append(f"scenarios.csv line {i}: DUMMY row in a results file")
        if r.get("status") not in SCENARIO_STATUSES:
            errors.append(f"scenarios.csv line {i}: status {r.get('status')!r} not in {SCENARIO_STATUSES}")
    return errors, []
