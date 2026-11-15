"""Capture logger - one row per attempt in eval/results/attempts.csv, built from the edge's decision events.

The operator never types scores or decisions. capture.py takes the LABEL (species), SUBJECT and CONDITION
(lighting, distance) from a pre-shuffled plan, CLI flags or an interactive prompt, sets the edge eval context
(POST /v1/admin/eval/context), arms, waits for the next NEW
attempt on GET /v1/events (SSE "decision" events), follows it through any step-up (challenge / second factor /
recapture) to a terminal ALLOW / DENY, joins the kiosk "rendered" event (client_latency_ms = face lock ->
decision rendered, the user-visible decision time), appends exactly one row, then clears the context.
No first decision within --first-timeout (30 s transaction cap) -> decision NO_RESPONSE (APNRR / BPNRR).
The rate limiter is reset (POST /v1/admin/rate-limit/reset) before EVERY attempt by default
(--reset-rate-limit attempt; `block` = at start + plan block changes, `never`); the mode goes into the run manifest.
SSE is primary. Fallback: GET /v1/attempt/{id} (the edge has no attempt list): while SSE is down the attempts being
followed are polled by id; with --transport poll (or SSE 404) the operator types the attempt id shown on the
admin live feed (the by-id response is the LATEST one only: no eval tags, no render, a missed STEP_UP is flagged).
Two capture clients (e.g. kiosk + operator console) on one face lock produce two attempt ids with the same
face_lock_at_ms (+-50 ms) and identical scores: the second is dropped as a duplicate and counted (manifest
`duplicates_dropped`, row note `dup_dropped:<id>`). RANDOM_CHALLENGE first decisions are step-ups (followed to the
terminal decision; liveness_result stays PASS when the signals passed).
Only whitelisted scalar fields are written: never images, crops, embeddings or names.
Auth (RBAC): every authenticated call (SSE GET /v1/events, /v1/admin/*) sends `Authorization: Bearer
$FG_EVAL_API_KEY` (an evaluator API key, from the environment or the project .env; never printed). The legacy
ADMIN_TOKEN (X-Admin-Token) is used only with FG_ALLOW_LEGACY_ADMIN_TOKEN=1. No usable credential, or a 401/403
from the edge, stops the run with a clear error and exit code 5 (no silent fallback).

Usage (from eval/; edge at --edge, default http://127.0.0.1:8000):
  uv run python capture.py --plan plans/test_plan.csv --run-id R-test-1 --operator E          # recommended
  uv run python capture.py --subject S03 --species print --lighting office --distance mid --count 10 --run-id R-t1
  uv run python capture.py --interactive --run-id R-dev-1
  uv run python capture.py --subject S01 --species bona_fide --scenario S04 --count 1 --run-id R-sc1  # SC1/SC2 demo
Keys while waiting (terminal): x = abort this attempt (no row, redo), n = log NO_RESPONSE now,
g = give up a pending step-up (row with decision STEP_UP / unresolved), r = reset rate limiter, q = quit after this.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import select
import sys
import threading
import time
import uuid
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from evallib import EVAL_DIR, PROJECT_DIR, RESULTS_DIR, THRESHOLDS_PATH
from evallib import auth as A
from evallib import config as ecfg
from evallib import io as eio
from evallib import schema as S

TERMINAL = {"ALLOW", "DENY"}
DEFAULT_EDGE = os.environ.get("EDGE_URL", "http://127.0.0.1:8000")
EVAL_TAG_KEYS = ("run_id", "subject_id", "label", "condition", "split")

SCORE_ALIASES: dict[str, list[str]] = {  # canonical column <- DecisionResponse.scores keys (API.md 1 / DECISION_POLICY 10)
    "s_pad": ["pad_mean", "liveness", "pad"],
    "s_pad_pass_frames": ["pad_pass_frames"],
    "s_flash_r": ["flash_r", "flash"],
    "s_flash_amp": ["flash_amp"],
    "s_moire": ["moire"],
    "s_device_conf": ["device_conf"],
    "s_depth": ["depth", "depth_score"],
    "s_match": ["match_local", "match"],
    "s_match_margin": ["match_margin"],
    "s_rekognition": ["rekognition"],
}
LATENCY_MAP = {"lat_server_total_ms": "total", "lat_liveness_ms": "liveness", "lat_match_ms": "match",
               "lat_schedule_ms": "schedule", "lat_policy_ms": "policy"}
# server-side fallback when no kiosk 'rendered' beacon arrived (excludes the render; latency_source says so)
E2E_EDGE_KEYS = ["face_lock_to_decision", "face_lock_to_decision_ms", "face_lock_to_decision_server"]
LIVENESS_ALIASES = {"LIVE": "PASS", "BONA_FIDE": "PASS", "SPOOF": "FAIL", "ATTACK": "FAIL"}
MAX_FIELD_CHARS = 400  # privacy guard: no field of a results row may carry a blob
ATTEMPT_PATH = "/v1/attempt/{id}"  # poll fallback (API.md 3.6); the edge has no attempt list route
DUP_WINDOW_MS = 50.0  # two capture clients: same face lock within +-50 ms and identical scores = one presentation
SIGNAL_KEYS = ("pad", "device", "moire", "flash", "mask", "depth", "injection")  # scores.signals (edge/policy/engine)

INSTRUCTIONS: dict[str, str] = {
    "bona_fide": "LIVE subject {s}: stand 30-60 cm, look at the screen, natural; follow any challenge prompt.",
    "zero_effort": "LIVE NON-matching person presents as normal (zero-effort impostor; target {s}).",
    "print": "Hold the A4 colour print of {s} flat, face in the oval, ~40 cm; natural hand motion; follow prompts.",
    "print_eyecut": "Attacker WEARS the eye-cut print of {s} (real eyes behind the holes); blink; try the prompts.",
    "phone_photo": "Show the photo of {s} on the phone, full brightness, ~30 cm, face in the oval.",
    "phone_video": "Play the video of {s} (blinks/smiles) on the phone, full brightness, ~30 cm.",
    "laptop_replay": "Replay the video of {s} on the laptop/tablet screen, ~40 cm.",
    "paper_mask": "Attacker WEARS the paper mask of {s}; follow the prompts with the mask on.",
    "mask_3d": "Attacker WEARS the rigid/3D mask of {s}; follow the prompts.",
    "inject_vcam": "Switch the kiosk camera to the OBS virtual camera playing {s}'s video (injection, not PAD).",
}


def now_ms() -> float:
    return time.time() * 1000.0


def edge_condition(lighting: str, distance: str) -> str:
    """CSV lighting/distance -> edge eval-context condition enum (normal|dim|backlit|far)."""
    if lighting in ("dim", "backlit"):
        return lighting
    return "far" if distance == "far" else "normal"


# ===================================================================== event parsing

def iter_sse(lines: Iterator[str]) -> Iterator[tuple[str, str, str | None]]:
    """Minimal WHATWG SSE parser: yields (event_type, data, last_event_id) per dispatched event."""
    ev_type, data, last_id = "message", [], None
    for raw in lines:
        line = raw.rstrip("\r\n")
        if line == "":
            if data:
                yield ev_type, "\n".join(data), last_id
            ev_type, data = "message", []
            continue
        if line.startswith(":"):
            continue
        name, _, value = line.partition(":")
        value = value.removeprefix(" ")
        if name == "data":
            data.append(value)
        elif name == "event":
            ev_type = value or "message"
        elif name == "id":
            last_id = value
    if data:
        yield ev_type, "\n".join(data), last_id


def _scalar(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def classify(ev_type: str, obj: dict) -> str:
    """'decision' | 'rendered' | 'other' from the SSE event name, a type field, or the payload shape."""
    t = (ev_type if ev_type not in ("", "message") else str(obj.get("type") or obj.get("event") or "")).lower()
    if t in ("decision", "rendered"):
        return t
    if obj.get("decision") and obj.get("attempt_id"):
        return "decision"
    if obj.get("attempt_id") and ("client_latency_ms" in obj or "rendered_at_ms" in obj):
        return "rendered"
    return "other"


def normalize_rendered(ev: dict) -> dict | None:
    if not isinstance(ev, dict) or not ev.get("attempt_id"):
        return None
    lat = _scalar(ev.get("client_latency_ms"))
    fl, ra = _scalar(ev.get("face_lock_at_ms")), _scalar(ev.get("rendered_at_ms"))
    if lat is None and fl is not None and ra is not None:
        lat = ra - fl
    return {"attempt_id": str(ev["attempt_id"]), "client_latency_ms": float(lat) if lat is not None else None,
            "face_lock_at_ms": float(fl) if fl is not None else None}


def normalize(ev: dict) -> dict | None:
    """DecisionResponse (API.md 1 / DECISION_POLICY 10) -> whitelisted flat record. None if not a decision."""
    if not isinstance(ev, dict):
        return None
    aid, dec = ev.get("attempt_id"), str(ev.get("decision") or "").upper()
    if not aid or dec not in S.RESPONDED:
        return None
    na = ev.get("next_action") or {}
    na = na if isinstance(na, dict) else {}
    scores = ev.get("scores") if isinstance(ev.get("scores"), dict) else {}
    lat = ev.get("latency_ms")
    lat = lat if isinstance(lat, dict) else ({"total": lat} if _scalar(lat) is not None else {})
    cand = ev.get("candidate")
    cand_id = (cand.get("user_id") if isinstance(cand, dict) else None) or ev.get("candidate_user_id")
    liv = ev.get("liveness") if isinstance(ev.get("liveness"), dict) else {}
    tags = ev.get("eval") if isinstance(ev.get("eval"), dict) else None
    methods = na.get("methods") or (na.get("details") or {}).get("methods") or []
    lr_raw = str(ev.get("liveness_result") or ev.get("liveness_status") or liv.get("status") or "").upper()
    mask = scores.get("mask") if isinstance(scores.get("mask"), dict) else {}
    sig = scores.get("signals") if isinstance(scores.get("signals"), dict) else {}
    return {
        "attempt_id": str(aid),
        "decision": dec,
        "stage": str(ev.get("stage") or ""),
        "reason_codes": [str(c) for c in (ev.get("reason_codes") or [])],
        "resolved_codes": [str(c) for c in (ev.get("resolved_codes") or [])],
        "bio_result": str(ev.get("bio_result") or ""),
        "schedule_result": str(ev.get("schedule_result") or ""),
        "mode": str(ev.get("mode") or "").upper(),
        "cache_state": str(ev.get("cache_state") or ""),
        "candidate_user_id": str(cand_id) if cand_id else "",
        "kiosk_id": str(ev.get("kiosk_id") or ""),
        "zone": str(ev.get("zone") or ""),
        "next_action_type": str(na.get("type") or "").upper(),
        "methods": [str(m).upper() for m in methods if isinstance(m, str)],
        "scores": {col: next((_scalar(scores.get(k)) for k in keys if _scalar(scores.get(k)) is not None), None)
                   for col, keys in SCORE_ALIASES.items()},
        "latency": {k: float(v) for k, v in lat.items() if _scalar(v) is not None},
        "policy_version": str(ev.get("policy_version") or ""),
        "bundle_version": ev.get("bundle_version") if _scalar(ev.get("bundle_version")) is not None else "",
        "eval_tags": None if tags is None else {k: str(tags.get(k) or "") for k in EVAL_TAG_KEYS},
        "liveness_result": LIVENESS_ALIASES.get(lr_raw, lr_raw),
        "parent_attempt_id": str(ev.get("parent_attempt_id") or ev.get("recapture_of") or ""),
        "mask_ring": _scalar(mask.get("m2_ring")),
        "signals": ";".join(f"{k}={str(sig[k]).upper()}" for k in SIGNAL_KEYS
                            if isinstance(sig.get(k), str) and sig[k].replace("_", "").isalnum()),
        "via": "",
    }


def score_signature(ev: dict) -> tuple | None:
    """Comparable score fingerprint of one decision; None when nothing was scored (cannot prove a duplicate)."""
    vals = tuple(sorted(ev["scores"].items())) + (("mask_ring", ev.get("mask_ring")),)
    return vals if any(v is not None for _, v in vals) else None


# ===================================================================== labels + rows

@dataclass
class Label:
    run_id: str
    subject_id: str
    split: str
    species: str
    lighting: str
    distance: str
    target_user_id: str = ""
    attempt_class: str = ""
    zone: str = ""
    kiosk_id: str = ""
    operator: str = ""
    scenario: str = ""
    notes: str = ""
    plan_seq: int | str = ""
    block: str = ""

    def __post_init__(self):
        if self.species not in S.SPECIES:
            raise ValueError(f"unknown species {self.species!r}; one of {S.SPECIES}")
        if self.lighting not in S.LIGHTING:
            raise ValueError(f"lighting must be one of {S.LIGHTING}")
        if self.distance not in S.DISTANCE:
            raise ValueError(f"distance must be one of {S.DISTANCE}")
        if self.split not in S.SPLITS:
            raise ValueError(f"split must be one of {S.SPLITS}")
        if not self.attempt_class:
            self.attempt_class = S.attempt_class_for(self.species)
        if self.attempt_class not in S.ATTEMPT_CLASSES:
            raise ValueError(f"attempt_class must be one of {S.ATTEMPT_CLASSES}")

    @property
    def label(self) -> str:
        return S.SPECIES_TO_LABEL[self.species]

    @property
    def condition(self) -> str:
        return edge_condition(self.lighting, self.distance)

    def context(self) -> dict:
        return {"run_id": self.run_id, "subject_id": self.subject_id, "label": self.label,
                "condition": self.condition, "split": self.split}

    def instruction(self) -> str:
        key = "zero_effort" if self.attempt_class == "zero_effort" else self.species
        return INSTRUCTIONS[key].format(s=self.subject_id)


def _fmt(v) -> str:
    if v is None or v == "":
        return ""
    if isinstance(v, float):
        if v.is_integer():
            return str(int(v))
        return f"{v:.4f}".rstrip("0").rstrip(".") if abs(v) < 10 else f"{v:.1f}"
    return str(v)


def _e2e(first: dict, render: dict | None) -> tuple[float | None, str]:
    """User-visible decision time: kiosk 'rendered' client_latency_ms first, then an edge face-lock field."""
    if render and render.get("client_latency_ms") is not None:
        return float(render["client_latency_ms"]), "kiosk_render"
    for k in E2E_EDGE_KEYS:
        if k in first["latency"]:
            return first["latency"][k], "edge_face_lock_to_decision"
    return None, "none"


def build_row(lab: Label, chain: list[tuple[float, dict]], render: dict | None = None, note: str = "") -> dict:
    first_recv, first = chain[0]
    last_recv, last = chain[-1]
    final, fd = last["decision"], first["decision"]
    # first event where the liveness stage actually ran (skip RECAPTURE / pre-check events)
    evaluated, lr, src = first, "", ""
    for _, e in chain:
        explicit = e["liveness_result"] if e["liveness_result"] in S.LIVENESS_RESULTS else ""
        cand = explicit or S.derive_liveness_result(e["decision"], e["stage"], e["reason_codes"])
        if cand != "NOT_EVALUATED":
            evaluated, lr, src = e, cand, "explicit" if explicit else "derived"
            break
    if not lr:
        lr, src = "NOT_EVALUATED", "derived"
    e2e, e2e_src = _e2e(first, render)
    notes = [lab.notes] if lab.notes else []
    ids = list(dict.fromkeys(e["attempt_id"] for _, e in chain))
    if len(ids) > 1:
        notes.append("chain:" + ">".join(ids))
    tags = first["eval_tags"]
    if first.get("via") == "poll" and first["stage"].lower() in ("challenge", "fallback"):
        # GET /v1/attempt/{id} returns only the LATEST response: the STEP_UP before it was not observed
        notes.append(f"POLL_MISSED_STEPUP(first_seen_stage={first['stage']})")
    if tags is None and first.get("via") == "poll":
        notes.append("eval_tags_not_in_poll_response")  # GET /v1/attempt/{id} carries no eval key (API 3.6)
    elif tags is None:
        notes.append("EVAL_TAGS_MISSING")
    else:
        exp = lab.context()
        bad = [f"{k}={tags[k]}" for k in EVAL_TAG_KEYS if tags.get(k) and tags[k] != exp[k]]
        if bad:
            notes.append("EVAL_TAG_MISMATCH(" + ",".join(bad) + ")")
    modes = [e["mode"] for _, e in chain if e["mode"]]
    if len(set(modes)) > 1:
        notes.append("mode_changed:" + ">".join(modes))
    if "RATE_LIMITED" in last["reason_codes"] or "RATE_LIMITED" in first["reason_codes"]:
        notes.append("RATE_LIMITED")
    if render is None:
        notes.append("no_render_event")
    if note:
        notes.append(note)
    su_events = [e for _, e in chain if e["decision"] == "STEP_UP"]
    methods = next((e["methods"] for e in su_events if e["methods"]), [])
    outcome = "none" if fd != "STEP_UP" else {"ALLOW": "passed", "DENY": "failed"}.get(final, "unresolved")
    row = {
        "run_id": lab.run_id, "plan_seq": lab.plan_seq, "ts_utc": eio.utc_now_iso(),
        "split": lab.split, "subject_id": lab.subject_id, "target_user_id": lab.target_user_id,
        "attempt_class": lab.attempt_class, "species": lab.species, "label": lab.label,
        "condition": lab.condition, "lighting": lab.lighting, "distance": lab.distance,
        "zone": evaluated["zone"] or lab.zone, "kiosk_id": evaluated["kiosk_id"] or lab.kiosk_id,
        "operator": lab.operator, "scenario": lab.scenario,
        "attempt_id": ids[0], "decision": final, "reason_codes": S.join_codes(last["reason_codes"]),
        "stage": last["stage"], "bio_result": evaluated["bio_result"], "schedule_result": evaluated["schedule_result"],
        "mode": evaluated["mode"] or first["mode"], "cache_state": evaluated["cache_state"],
        "candidate_user_id": evaluated["candidate_user_id"],
        "liveness_result": lr, "liveness_result_source": src,
        "first_decision": fd, "first_reason_codes": S.join_codes(first["reason_codes"]), "first_stage": first["stage"],
        "next_action_type": first["next_action_type"] if fd == "STEP_UP" else "",
        "stepup_methods": ";".join(methods), "stepup_outcome": outcome,
        "stepup_rounds": len(su_events), "recaptures": sum(e["next_action_type"] == "RECAPTURE" for e in su_events),
        "stepup_ms": _fmt(round(last_recv - first_recv, 1)) if fd == "STEP_UP" and final in TERMINAL else "",
        "resolved_codes": S.join_codes(last["resolved_codes"]),
        "latency_ms": _fmt(round(e2e, 1)) if e2e is not None else "", "latency_source": e2e_src,
        **{col: _fmt(first["latency"].get(key)) for col, key in LATENCY_MAP.items()},
        **{col: _fmt(evaluated["scores"].get(col)) for col in SCORE_ALIASES},
        "eval_label_echo": (tags or {}).get("label", ""), "policy_version": first["policy_version"],
        "bundle_version": first["bundle_version"], "events": len(chain), "notes": "; ".join(notes),
        "face_lock_at_ms": _fmt((render or {}).get("face_lock_at_ms")),
        "s_mask_ring": _fmt(evaluated.get("mask_ring")), "signals": evaluated.get("signals", ""),
    }
    row["scores"] = json.dumps({  # pad-evaluation skill 6.1 compatibility (scalars only; derived, not edge fields)
        "pad": evaluated["scores"].get("s_pad"), "pad_label": S.PAD_LABEL.get(lr, "none"),
        "flash_r": evaluated["scores"].get("s_flash_r"), "moire": evaluated["scores"].get("s_moire"),
        "device_conf": evaluated["scores"].get("s_device_conf"), "match": evaluated["scores"].get("s_match"),
        "first_decision": fd, "t_pad": first["latency"].get("liveness"), "t_match": first["latency"].get("match"),
    }, separators=(",", ":"))
    return sanitize(row)


def sanitize(row: dict) -> dict:
    """Last line of defence before a row is written: only schema columns, no blob-like values."""
    out = {c: row.get(c, "") for c in S.ATTEMPT_COLUMNS}
    for c, v in out.items():
        if isinstance(v, str) and (len(v) > MAX_FIELD_CHARS or S.LONG_BLOB_RE.search(v)):
            out[c] = "[REMOVED: oversized value]"
    return out


def no_response_row(lab: Label, reason: str) -> dict:
    row = {c: "" for c in S.ATTEMPT_COLUMNS}
    row.update({
        "run_id": lab.run_id, "plan_seq": lab.plan_seq, "ts_utc": eio.utc_now_iso(), "split": lab.split,
        "subject_id": lab.subject_id, "target_user_id": lab.target_user_id, "attempt_class": lab.attempt_class,
        "species": lab.species, "label": lab.label, "condition": lab.condition, "lighting": lab.lighting,
        "distance": lab.distance, "zone": lab.zone, "kiosk_id": lab.kiosk_id, "operator": lab.operator,
        "scenario": lab.scenario, "attempt_id": f"noresp_{lab.run_id}_{lab.plan_seq or 'x'}_{uuid.uuid4().hex[:8]}",
        "decision": "NO_RESPONSE", "stepup_outcome": "none", "latency_source": "none", "events": 0,
        "notes": "; ".join(n for n in (lab.notes, reason) if n),
    })
    return row


# ===================================================================== tracker (pure state machine)

@dataclass
class Tracker:
    seen: set[str]
    first_timeout_ms: float = 30_000
    stepup_timeout_ms: float = 130_000
    render_wait_ms: float = 2_500
    dup_window_ms: float = DUP_WINDOW_MS
    state: str = "IDLE"  # IDLE | ARMED | FOLLOWING | AWAIT_RENDER
    label: Label | None = None
    arm_ms: float = 0.0
    chain: list[tuple[float, dict]] = field(default_factory=list)
    ids: set[str] = field(default_factory=set)
    rendered: dict[str, dict] = field(default_factory=dict)  # first 'rendered' event per attempt id
    terminal_ms: float = 0.0
    log: list[str] = field(default_factory=list)
    counts: Counter = field(default_factory=Counter)
    sigs: dict[str, list] = field(default_factory=dict)  # first decision per attempt id: [face_lock_ms, score sig]
    dups: dict[str, str] = field(default_factory=dict)  # dropped duplicate attempt id -> kept attempt id
    duplicates: list[dict] = field(default_factory=list)  # audit trail (run manifest)
    row_notes: list[str] = field(default_factory=list)
    manual_ids: set[str] = field(default_factory=set)  # poll-only mode: attempt id typed by the operator

    def arm(self, lab: Label, t: float) -> None:
        self.state, self.label, self.arm_ms, self.chain, self.ids = "ARMED", lab, t, [], set()
        self.row_notes, self.manual_ids = [], set()

    # ------------------------------------------------------------ duplicate presentations (two capture clients)

    def _face_lock(self, recv: float, ev: dict) -> float | None:
        """Exact face_lock_at_ms from the attempt's rendered event, else recv - latency.face_lock_to_decision_server
        (same machine: the error is the SSE delivery delay, a few ms)."""
        r = self.rendered.get(ev["attempt_id"])
        if r and r.get("face_lock_at_ms") is not None:
            return float(r["face_lock_at_ms"])
        srv = ev["latency"].get("face_lock_to_decision_server")
        return recv - srv if srv is not None else None

    def _duplicate_of(self, recv: float, ev: dict) -> str | None:
        sig = score_signature(ev)
        fl = self._face_lock(recv, ev)
        if sig is None or fl is None:
            return None  # no evidence -> never drop
        for kid, (kfl, ksig) in self.sigs.items():
            if kid != ev["attempt_id"] and ksig == sig and kfl is not None and abs(kfl - fl) <= self.dup_window_ms:
                return kid
        return None

    def _remember(self, recv: float, ev: dict) -> None:
        if ev["attempt_id"] not in self.sigs:
            self.sigs[ev["attempt_id"]] = [self._face_lock(recv, ev), score_signature(ev)]
            if len(self.sigs) > 200:
                del self.sigs[next(iter(self.sigs))]

    def _drop_duplicate(self, recv: float, ev: dict, kept: str) -> None:
        aid = ev["attempt_id"]
        self.dups[aid] = kept
        self.seen.add(aid)
        self.counts["dropped_duplicate"] += 1
        kfl = self.sigs[kept][0]
        fl = self._face_lock(recv, ev)
        self.duplicates.append({"dropped": aid, "kept": kept, "dropped_decision": ev["decision"],
                                "dropped_reason_codes": S.join_codes(ev["reason_codes"]),
                                "face_lock_dt_ms": round(abs(fl - kfl), 1) if fl is not None else None})
        self.log.append(f"dropped duplicate attempt {aid} ({ev['decision']}) = same face lock + scores as {kept}")
        if kept in self.ids:
            self.row_notes.append(f"dup_dropped:{aid}({ev['decision']})")

    # ------------------------------------------------------------ rows

    def _ignore(self, aid: str, why: str) -> None:
        if aid not in self.seen:
            self.seen.add(aid)
            self.counts["ignored_" + why] += 1
            self.log.append(f"ignored attempt {aid} ({why})")

    def _render(self) -> dict | None:
        root = self.chain[0][1]["attempt_id"] if self.chain else None
        return self.rendered.get(root) if root else None

    def _finish(self, note: str = "") -> dict:
        notes = "; ".join(n for n in [*self.row_notes, note] if n)
        row = build_row(self.label, self.chain, self._render(), notes)
        self.state, self.chain, self.row_notes = "IDLE", [], []
        if len(self.rendered) > 500:
            self.rendered.clear()
        return row

    def _terminal(self, t: float) -> dict | None:
        """Terminal decision seen: finish now if the first decision's render is known, else wait briefly."""
        if self._render() is not None or self.render_wait_ms <= 0:
            return self._finish()
        self.state, self.terminal_ms = "AWAIT_RENDER", t
        return None

    def feed_rendered(self, recv: float, r: dict) -> dict | None:
        self.rendered.setdefault(r["attempt_id"], r)
        if r["attempt_id"] in self.sigs and r.get("face_lock_at_ms") is not None:
            self.sigs[r["attempt_id"]][0] = float(r["face_lock_at_ms"])  # exact value replaces the estimate
        if self.state == "AWAIT_RENDER" and r["attempt_id"] == self.chain[0][1]["attempt_id"]:
            return self._finish()
        return None

    def _repeat(self, ev: dict) -> bool:
        """Same response delivered twice (SSE + GET /v1/attempt/{id} poll after a reconnect)."""
        key = (ev["attempt_id"], ev["decision"], tuple(ev["reason_codes"]), ev["stage"], ev["next_action_type"])
        return any((e["attempt_id"], e["decision"], tuple(e["reason_codes"]), e["stage"], e["next_action_type"]) == key
                   for _, e in self.chain[-1:])

    def feed(self, recv: float, ev: dict) -> dict | None:
        aid = ev["attempt_id"]
        if aid in self.dups:
            return None  # follow-up event of a dropped duplicate
        if aid not in self.seen and aid not in self.ids:
            kept = self._duplicate_of(recv, ev)
            if kept is not None:
                self._drop_duplicate(recv, ev, kept)
                return None
            self._remember(recv, ev)
        if aid in self.ids and self._repeat(ev):
            return None
        if self.state == "AWAIT_RENDER":
            if aid in self.ids:
                return None
            if aid not in self.seen:  # next attempt started before the render arrived: close this one first
                row = self._finish()
                self._ignore(aid, "unarmed")
                return row
            return None
        if self.state == "IDLE" or (self.state == "ARMED" and recv < self.arm_ms):
            if aid not in self.ids:
                self._ignore(aid, "unarmed")
            return None
        if self.state == "ARMED":
            if aid in self.seen:
                return None  # late event of an attempt already logged / ignored
            self.seen.add(aid)
            self.ids = {aid}
            self.chain = [(recv, ev)]
            if ev["decision"] in TERMINAL:
                return self._terminal(recv)
            self.state = "FOLLOWING"
            return None
        # FOLLOWING a STEP_UP (incl. RANDOM_CHALLENGE)
        last = self.chain[-1][1]
        if aid in self.ids:
            self.chain.append((recv, ev))
            return self._terminal(recv) if ev["decision"] in TERMINAL else None
        if aid in self.seen:
            return None
        if last["next_action_type"] == "RECAPTURE" or (ev["parent_attempt_id"] and ev["parent_attempt_id"] in self.ids):
            self.seen.add(aid)
            self.ids.add(aid)
            self.chain.append((recv, ev))
            return self._terminal(recv) if ev["decision"] in TERMINAL else None
        row = self._finish("stepup_abandoned:new_attempt_started")
        self._ignore(aid, "started_during_stepup")
        return row

    def tick(self, t: float) -> dict | None:
        if self.state == "ARMED" and t - self.arm_ms > self.first_timeout_ms:
            self.state = "IDLE"
            return no_response_row(self.label, f"no decision within {self.first_timeout_ms / 1000:.0f} s")
        if self.state == "FOLLOWING" and t - self.chain[0][0] > self.stepup_timeout_ms:
            return self._finish(f"stepup_unresolved_after_{self.stepup_timeout_ms / 1000:.0f}s")
        if self.state == "AWAIT_RENDER" and t - self.terminal_ms > self.render_wait_ms:
            return self._finish()
        return None

    def force_no_response(self) -> dict | None:
        if self.state == "ARMED":
            self.state = "IDLE"
            return no_response_row(self.label, "operator: no response")
        return None

    def give_up(self) -> dict | None:
        return self._finish("operator: step-up abandoned") if self.state == "FOLLOWING" else None

    def abort(self) -> None:
        for aid in self.ids:
            self.counts["aborted"] += 1
            self.log.append(f"aborted attempt {aid} (no row; redo)")
        self.state, self.chain, self.row_notes = "IDLE", [], []


# ===================================================================== edge admin (eval context, rate limit)

class EdgeAdmin:
    """Admin calls with the run's credential. A 401/403 raises evallib.auth.AuthFailure (the run stops)."""

    def __init__(self, edge: str, cred: A.EdgeCredential):
        self.edge, self.cred = edge.rstrip("/"), cred
        self.counts: Counter = Counter()

    def _call(self, method: str, path: str, body: dict | None = None) -> bool:
        try:
            r = httpx.request(method, self.edge + path, json=body, headers=self.cred.headers(), timeout=3.0)
        except (httpx.HTTPError, OSError) as e:
            self.counts[f"{method} {path}:{type(e).__name__}"] += 1
            return False
        ok = 200 <= r.status_code < 300
        self.counts[f"{method} {path}:{'ok' if ok else r.status_code}"] += 1
        A.raise_for_auth(r.status_code, method, path, self.cred, _json_or_none(r))
        return ok

    def set_context(self, lab: Label) -> bool:
        return self._call("POST", "/v1/admin/eval/context", lab.context())

    def clear_context(self) -> bool:
        return self._call("DELETE", "/v1/admin/eval/context")

    def reset_rate_limit(self) -> bool:
        return self._call("POST", "/v1/admin/rate-limit/reset")


def _json_or_none(r: httpx.Response) -> object:
    try:
        return r.json()
    except ValueError:
        return None


# ===================================================================== transports

class EventSource(threading.Thread):
    """Background reader pushing (kind, recv_ms, normalized) into a queue. transport: sse | poll | auto.

    SSE (`GET /v1/events`) is primary. The edge has no attempt list, so the fallback is `GET /v1/attempt/{id}`
    (API.md 3.6) for the attempt ids being followed (`follow()`): while the SSE stream is down they are polled by
    id between reconnects; with --transport poll (or SSE 404 under auto) polling by id is the only source and the
    operator types the attempt id shown on the admin live feed (`needs_manual_id`). Poll responses carry no
    `eval` key and no `rendered` event (rows note `eval_tags_not_in_poll_response`)."""

    def __init__(self, edge: str, q: queue.Queue, transport: str = "auto", poll_s: float = 0.25,
                 events_path: str = "/v1/events", attempt_path: str = ATTEMPT_PATH,
                 cred: A.EdgeCredential | None = None):
        super().__init__(daemon=True)
        self.edge, self.q, self.transport = edge.rstrip("/"), q, transport
        self.cred = cred
        self.auth_error: str | None = None  # set on SSE 401/403 or a final `event: auth`; the run stops
        self.poll_s, self.events_path, self.attempt_path = poll_s, events_path, attempt_path
        self.stop = threading.Event()
        self.status = "starting"
        self.non_decision = 0
        self.mode_used: str | None = None
        self.poll_calls: Counter = Counter()
        self._lock = threading.Lock()
        self._follow: set[str] = set()
        self._last_seen: dict[str, str] = {}  # attempt id -> last polled response fingerprint

    # ------------------------------------------------------------ attempt ids to poll
    def follow(self, ids: set[str] | list[str]) -> None:
        with self._lock:
            self._follow = {i for i in ids if i}

    def followed(self) -> set[str]:
        with self._lock:
            return set(self._follow)

    @property
    def needs_manual_id(self) -> bool:
        """Poll-only mode: no stream announces new attempts, so the operator must type the attempt id."""
        return self.mode_used == "poll"

    # ------------------------------------------------------------ main loop
    def run(self) -> None:
        mode, backoff, last_id = self.transport, 0.5, None
        while not self.stop.is_set():
            if mode in ("sse", "auto"):
                try:
                    headers = ({"Accept": "text/event-stream"} | (self.cred.headers() if self.cred else {})
                               | ({"Last-Event-ID": last_id} if last_id else {}))
                    with httpx.stream("GET", self.edge + self.events_path, headers=headers,
                                      timeout=httpx.Timeout(3.0, read=None)) as r:
                        if r.status_code in A.AUTH_FAILURE_CODES:
                            r.read()
                            return self._auth_failed(A.failure_message(
                                r.status_code, "GET", self.events_path, self.cred, _json_or_none(r)))
                        if r.status_code == 404 and mode == "auto":
                            mode = "poll"
                            continue
                        r.raise_for_status()
                        self.status, self.mode_used, backoff = "connected (sse)", "sse", 0.5
                        for typ, data, eid in iter_sse(r.iter_lines()):
                            last_id = eid or last_id
                            if typ == "auth":  # edge closes the stream: credential expired / revoked / lost
                                return self._auth_failed(
                                    f"edge closed GET {self.events_path} with `event: auth` (credential expired, "
                                    f"revoked or lost events:read; {self.cred.describe() if self.cred else 'none'})")
                            self.push(typ, data)
                            if self.stop.is_set():
                                return
                    self.poll_followed()  # stream closed: catch up on followed attempts before reconnecting
                    time.sleep(0.5)
                except (httpx.HTTPError, OSError) as e:
                    self.status = f"sse down ({type(e).__name__}); polling followed attempts by id, retrying"
                    self.poll_followed()
                    time.sleep(backoff)
                    backoff = min(5.0, backoff * 2)
                continue
            self.mode_used = "poll"
            self.status = "poll by attempt id (GET /v1/attempt/{id})"
            while not self.stop.is_set():
                self.poll_followed()
                time.sleep(self.poll_s)
            return

    def _auth_failed(self, message: str) -> None:
        self.auth_error, self.status = message, "auth refused"
        self.stop.set()

    def poll_followed(self) -> int:
        """GET /v1/attempt/{id} for every followed id; pushes changed responses. Returns responses pushed."""
        pushed = 0
        for aid in sorted(self.followed()):
            try:
                r = httpx.get(self.edge + self.attempt_path.format(id=aid), timeout=3.0)
            except (httpx.HTTPError, OSError) as e:
                self.poll_calls[f"error:{type(e).__name__}"] += 1
                continue
            self.poll_calls[str(r.status_code)] += 1
            if r.status_code != 200:  # 404 ATTEMPT_NOT_FOUND / 409 INVALID_STATE (frames not submitted yet)
                continue
            try:
                obj = r.json()
            except ValueError:
                self.non_decision += 1
                continue
            key = json.dumps(obj, sort_keys=True, default=str)
            if self._last_seen.get(aid) == key:
                continue
            self._last_seen[aid] = key
            self.push("decision", key, via="poll")
            pushed += 1
        return pushed

    def push(self, typ: str, data: str, via: str = "") -> None:
        try:
            obj = json.loads(data)
        except ValueError:
            self.non_decision += 1
            return
        for item in obj if isinstance(obj, list) else [obj]:
            if not isinstance(item, dict):
                self.non_decision += 1
                continue
            kind = classify(typ, item)
            ev = normalize(item) if kind == "decision" else normalize_rendered(item) if kind == "rendered" else None
            if ev is None:
                self.non_decision += 1
            else:
                if kind == "decision" and via:
                    ev["via"] = via
                self.q.put((kind, now_ms(), ev))


# ===================================================================== registry / plan

def load_subjects(path: Path) -> dict[str, dict]:
    _, rows = eio.read_csv(path)
    if not rows:
        raise SystemExit(f"no subjects registry at {path}: create it first (uv run python plan.py subjects ...)")
    reg = {}
    for r in rows:
        if r.get("split") not in S.SPLITS:
            raise SystemExit(f"{path}: subject {r.get('subject_id')} has invalid split {r.get('split')!r}")
        if (r.get("consent") or "").lower() not in ("yes", "y", "true", "1"):
            raise SystemExit(f"{path}: subject {r.get('subject_id')} has no recorded consent - not capturable")
        reg[r["subject_id"]] = r
    return reg


def labels_from_plan(path: Path, a, reg: dict, done: set[tuple[str, str]]) -> Iterator[Label]:
    _, rows = eio.read_csv(path)
    for r in rows:
        if (a.run_id, str(r["plan_seq"])) in done:
            continue
        sid = r["subject_id"]
        if sid not in reg:
            raise SystemExit(f"plan subject {sid} not in subjects registry")
        if r.get("split") and r["split"] != reg[sid]["split"]:
            raise SystemExit(f"plan split {r['split']} != registry split for {sid}")
        yield Label(run_id=a.run_id, subject_id=sid, split=reg[sid]["split"], species=r["species"],
                    lighting=r["lighting"], distance=r.get("distance") or "mid",
                    target_user_id=reg[sid].get("enrolled_user_id", ""), attempt_class=r.get("attempt_class", ""),
                    zone=r.get("zone") or a.zone, kiosk_id=a.kiosk_id, operator=a.operator,
                    scenario=r.get("scenario", ""), plan_seq=r["plan_seq"], block=r.get("block", ""))


def label_from_flags(a, reg: dict, seq: int) -> Label:
    if a.subject not in reg:
        raise SystemExit(f"subject {a.subject!r} not in the subjects registry {a.subjects}")
    species = a.species or S.LABEL_DEFAULT_SPECIES.get(a.label or "", "")
    if a.label and a.species and S.SPECIES_TO_LABEL[a.species] != a.label:
        raise SystemExit(f"--species {a.species} maps to label {S.SPECIES_TO_LABEL[a.species]}, not {a.label}")
    return Label(run_id=a.run_id, subject_id=a.subject, split=reg[a.subject]["split"], species=species,
                 lighting=a.lighting, distance=a.distance, target_user_id=reg[a.subject].get("enrolled_user_id", ""),
                 attempt_class="zero_effort" if a.zero_effort else "", zone=a.zone, kiosk_id=a.kiosk_id,
                 operator=a.operator, scenario=a.scenario or "", notes=a.notes or "", plan_seq=f"f{seq}")


def label_interactive(a, reg: dict, prev: Label | None, seq: int) -> Label | None:
    def ask(q, default):
        v = input(f"  {q} [{default}]: ").strip()
        return v or default
    print("\nnext attempt (Enter keeps the value in brackets, 'q' quits)")
    subj = ask("subject_id", prev.subject_id if prev else next(iter(reg)))
    if subj == "q":
        return None
    sp = ask(f"species {S.SPECIES}", prev.species if prev else "bona_fide")
    lg = ask(f"lighting {S.LIGHTING}", prev.lighting if prev else "office")
    ds = ask(f"distance {S.DISTANCE}", prev.distance if prev else "mid")
    try:
        return Label(run_id=a.run_id, subject_id=subj, split=reg[subj]["split"], species=sp, lighting=lg, distance=ds,
                     target_user_id=reg[subj].get("enrolled_user_id", ""), zone=a.zone, kiosk_id=a.kiosk_id,
                     operator=a.operator, scenario=a.scenario or "", plan_seq=f"i{seq}")
    except (KeyError, ValueError) as e:
        print(f"  invalid: {e}")
        return label_interactive(a, reg, prev, seq)


# ===================================================================== main loop

def _stdin_key() -> str | None:
    if not sys.stdin.isatty():
        return None
    r, _, _ = select.select([sys.stdin], [], [], 0.0)
    return sys.stdin.readline().strip().lower() if r else None


def _summary(row: dict) -> str:
    codes = row["reason_codes"] or "-"
    lat = f"{row['latency_ms']} ms ({row['latency_source']})" if row["latency_ms"] else "decision time n/a"
    su = f" step-up:{row['stepup_outcome']}" if row["stepup_outcome"] not in ("none", "") else ""
    srv = f" server {row['lat_server_total_ms']} ms" if row["lat_server_total_ms"] else ""
    return (f"  -> {row['decision']} ({codes}) {lat}{srv} {row['mode']}{su}  [{row['species']} {row['subject_id']} "
            f"{row['lighting']}/{row['distance']}] {row['attempt_id']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--edge", default=DEFAULT_EDGE)
    ap.add_argument("--transport", choices=["auto", "sse", "poll"], default="auto")
    ap.add_argument("--out", type=Path, default=RESULTS_DIR / "attempts.csv")
    ap.add_argument("--runs-dir", type=Path, default=None, help="run manifests (default: <out dir>/runs)")
    ap.add_argument("--subjects", type=Path, default=EVAL_DIR / "subjects.csv")
    ap.add_argument("--env-file", type=Path, default=PROJECT_DIR / ".env", help="fallback source of FG_EVAL_API_KEY (and of ADMIN_TOKEN with FG_ALLOW_LEGACY_ADMIN_TOKEN=1)")
    ap.add_argument("--allow-remote-edge", action="store_true",
                    help="allow a non-loopback edge (https only); credentials never go to remote plain http")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--operator", default="")
    ap.add_argument("--zone", default="LIBRARY")
    ap.add_argument("--kiosk-id", default=os.environ.get("KIOSK_ID", "KIOSK_LIB_01"))
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--plan", type=Path, help="pre-shuffled plan CSV from plan.py schedule")
    g.add_argument("--interactive", action="store_true")
    ap.add_argument("--subject")
    ap.add_argument("--species", choices=S.SPECIES)
    ap.add_argument("--label", choices=S.LABELS, help="coarse eval label (maps to a default species)")
    ap.add_argument("--lighting", choices=S.LIGHTING, default="office")
    ap.add_argument("--distance", choices=S.DISTANCE, default="mid")
    ap.add_argument("--zero-effort", action="store_true", help="bona fide presenter is NOT the target (impostor)")
    ap.add_argument("--scenario", default="", help="docs/POLICY_TEST_CASES.md id (row excluded from PAD metrics)")
    ap.add_argument("--notes", default="")
    ap.add_argument("--count", type=int, default=0, help="flags mode: attempts to log (0 = until Ctrl-C)")
    ap.add_argument("--no-prompt", action="store_true", help="arm the next attempt immediately (no Enter)")
    ap.add_argument("--first-timeout", type=float, default=30.0)
    ap.add_argument("--stepup-timeout", type=float, default=130.0)
    ap.add_argument("--render-wait", type=float, default=2.5, help="s to wait for the kiosk 'rendered' event")
    ap.add_argument("--reset-rate-limit", choices=["attempt", "block", "never"], default="attempt",
                    help="POST /v1/admin/rate-limit/reset before every attempt (default), at block changes, or never")
    a = ap.parse_args(argv)

    a.run_id = a.run_id or "R" + eio.utc_now_iso(ms=False).replace("-", "").replace(":", "")
    if S.is_dummy_run(a.run_id) and eio.is_inside(a.out, RESULTS_DIR):
        raise SystemExit("refusing DUMMY run ids in eval/results/")
    if not a.plan and not a.interactive and not (a.subject and (a.species or a.label)):
        ap.error("give --plan, --interactive, or --subject with --species/--label")
    reg = load_subjects(a.subjects)
    header, existing = eio.read_csv(a.out)
    if existing and header != S.ATTEMPT_COLUMNS:
        raise SystemExit(f"{a.out} has a different header; use a new --out file")
    seen = {r["attempt_id"] for r in existing}
    done = {(r["run_id"], r["plan_seq"]) for r in existing}
    runs_dir = a.runs_dir or a.out.parent / "runs"
    try:
        A.check_edge_url(a.edge, a.allow_remote_edge)
        cred = A.load_credential(A.EVAL_KEY_ENV, a.env_file)
    except A.AuthFailure as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return A.EXIT_AUTH
    admin = EdgeAdmin(a.edge, cred)
    print(f"edge credential: {cred.describe()}")
    try:
        health, mode = _get_json(a.edge + "/v1/health"), mode_detail(a.edge, cred)
    except A.AuthFailure as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return A.EXIT_AUTH
    switches = ecfg.shipped_switches(eio.load_yaml(THRESHOLDS_PATH) or {}, THRESHOLDS_PATH)
    edge_diff = ecfg.compare_with_edge(switches, mode)
    lockout_s = switches["rate_limit"]["lockout_s"]
    man = eio.RunManifest(a.run_id, "capture", runs_dir, {
        "edge_url": a.edge, "transport_requested": a.transport, "operator": a.operator, "out": str(a.out),
        "plan": str(a.plan) if a.plan else None, "plan_sha256": eio.sha256_file(a.plan) if a.plan else None,
        "subjects": str(a.subjects), "subjects_sha256": eio.sha256_file(a.subjects),
        "thresholds_sha256": switches["thresholds_sha256"],
        "policy_version_config": switches["policy_version"],
        "shipped_switches": switches, "edge_config_diff": edge_diff,
        "rate_limit_handling": {"reset_rate_limit": a.reset_rate_limit,
                                "rate_limit_enabled_config": switches["rate_limit"]["enabled"],
                                "edge_rate_limit_at_start": (mode or {}).get("rate_limit")},
        "dedup": {"face_lock_window_ms": DUP_WINDOW_MS, "rule": "same face_lock_at_ms (+-window) AND identical scores"},
        "edge_health_at_start": health, "edge_mode_at_start": mode, "edge_credential": cred.describe(),
        "timeouts_s": {"first_decision": a.first_timeout, "stepup": a.stepup_timeout, "render_wait": a.render_wait},
    })
    for d in edge_diff:
        print(f"WARNING: config cross-check: {d}")
    q: queue.Queue = queue.Queue()
    src = EventSource(a.edge, q, a.transport, cred=cred)
    tr = Tracker(seen, a.first_timeout * 1000, a.stepup_timeout * 1000, a.render_wait * 1000)
    written: Counter = Counter()
    prev: Label | None = None
    seq, block, rc = 0, None, 0
    labels: Iterator[Label] | None = labels_from_plan(a.plan, a, reg, done) if a.plan else None
    print(f"capture run {a.run_id} -> {a.out}  (edge {a.edge}; Ctrl-C to stop)")
    try:
        admin.clear_context()  # preflight: verifies the credential (eval:admin) before anything is armed
        src.start()
        if a.reset_rate_limit != "never":
            admin.reset_rate_limit()
        while True:
            _check_stream_auth(src)
            seq += 1
            if labels is not None:
                lab = next(labels, None)
            elif a.interactive:
                lab = label_interactive(a, reg, prev, seq)
            else:
                lab = label_from_flags(a, reg, seq) if (a.count == 0 or seq <= a.count) else None
            if lab is None:
                break
            prev = lab
            if lab.block and lab.block != block:
                if block is not None:
                    print(f"\n=== block change {block} -> {lab.block}: set the {lab.block} lighting now ===")
                block = lab.block
                if a.reset_rate_limit != "never":
                    admin.reset_rate_limit()
            print(f"\n#{lab.plan_seq} {lab.attempt_class.upper()} {lab.species} target {lab.subject_id} | "
                  f"{lab.lighting}/{lab.distance} | split {lab.split}{' | ' + lab.scenario if lab.scenario else ''}")
            print("  " + lab.instruction())
            if not a.no_prompt:
                ans = input("  Enter = arm (s = skip, q = quit): ").strip().lower()
                if ans == "q":
                    break
                if ans == "s":
                    written["skipped"] += 1
                    continue
            _drain_unarmed(q, tr)
            if src.needs_manual_id:
                tr.render_wait_ms = 0  # no 'rendered' events without SSE
            if a.reset_rate_limit == "attempt":
                admin.reset_rate_limit()
            if not admin.set_context(lab):
                print("  WARNING: POST /v1/admin/eval/context failed - edge tags will be missing for this attempt")
            tr.arm(lab, now_ms())
            print(f"  armed - waiting for the edge ({src.status}) ...")
            row, quit_after = None, False
            while row is None:
                if tr.state == "ARMED" and src.needs_manual_id and not tr.manual_ids:
                    typed = _ask_attempt_id()
                    if typed == "x":
                        tr.abort()
                        print("  aborted - redo this attempt")
                        break
                    if typed == "n":
                        row = tr.force_no_response()
                        break
                    tr.manual_ids.add(typed)
                _check_stream_auth(src)
                src.follow(tr.ids | tr.manual_ids)
                try:
                    kind, recv, ev = q.get(timeout=0.2)
                    if kind == "rendered":
                        row = tr.feed_rendered(recv, ev)
                    else:
                        row = tr.feed(recv, ev)
                        if row is None and tr.state == "FOLLOWING" and ev["decision"] == "STEP_UP":
                            print(f"  STEP_UP ({';'.join(ev['reason_codes'])}) next={ev['next_action_type'] or '?'}"
                                  " - following until ALLOW/DENY")
                except queue.Empty:
                    pass
                row = row or tr.tick(now_ms())
                key = _stdin_key()
                if key == "x":
                    tr.abort()
                    print("  aborted - redo this attempt")
                    break
                if key == "n":
                    row = tr.force_no_response()
                elif key == "g":
                    row = tr.give_up()
                elif key == "r":
                    print("  rate limiter reset: " + ("ok" if admin.reset_rate_limit() else "FAILED"))
                elif key == "q":
                    quit_after = True
            admin.clear_context()
            for line in tr.log:
                print("  note: " + line)
            tr.log.clear()
            if row is None:
                if labels is not None:  # re-queue an aborted plan item
                    labels = _prepend(lab, labels)
                continue
            eio.append_csv_row(a.out, S.ATTEMPT_COLUMNS, row)
            written[row["decision"]] += 1
            if "EVAL_TAG_MISMATCH" in row["notes"]:
                print("  WARNING: edge eval tags differ from the operator label - check the eval context")
            if "RATE_LIMITED" in row["notes"]:
                print(f"  WARNING: RATE_LIMITED - press r (or wait {lockout_s} s); row excluded from APCER/BPCER")
            print(_summary(row))
            man.update(counts=dict(written) | dict(tr.counts), admin_calls=dict(admin.counts),
                       transport_used=src.mode_used, poll_calls=dict(src.poll_calls),
                       duplicates_dropped=len(tr.duplicates), duplicates=tr.duplicates)
            if quit_after:
                break
    except KeyboardInterrupt:
        print("\nstopped")
    except A.AuthFailure as e:
        print(f"\nERROR: {e}\nrun stopped; rows already written are kept", file=sys.stderr)
        rc = A.EXIT_AUTH
    finally:
        src.stop.set()
        if rc != A.EXIT_AUTH:
            try:
                admin.clear_context()
            except A.AuthFailure as e:
                print(f"ERROR: {e}", file=sys.stderr)
                rc = A.EXIT_AUTH
        man.close(auth_failed=rc == A.EXIT_AUTH, counts=dict(written) | dict(tr.counts), admin_calls=dict(admin.counts),
                  transport_used=src.mode_used, non_decision_events=src.non_decision, poll_calls=dict(src.poll_calls),
                  duplicates_dropped=len(tr.duplicates), duplicates=tr.duplicates)
    print(f"done: {dict(written)}  duplicates dropped: {len(tr.duplicates)}  manifest {man.path}")
    return rc


def _check_stream_auth(src: EventSource) -> None:
    if src.auth_error:
        raise A.AuthFailure(src.auth_error)


def _ask_attempt_id() -> str:
    """Poll-only mode: the operator types the attempt id from the admin live feed (x = abort, n = NO_RESPONSE)."""
    while True:
        v = input("  poll mode: attempt id from the admin live feed (x = abort, n = no response): ").strip()
        if v.lower() in ("x", "n"):
            return v.lower()
        if v.startswith("att_") and v.replace("_", "").isalnum() and len(v) <= 64:
            return v
        print("  not an attempt id (expected att_...)")


def _prepend(item: Label, it: Iterator[Label]) -> Iterator[Label]:
    yield item
    yield from it


def _drain_unarmed(q: queue.Queue, tr: Tracker) -> None:
    while True:
        try:
            kind, recv, ev = q.get_nowait()
        except queue.Empty:
            return
        if kind == "rendered":
            tr.feed_rendered(recv, ev)
        else:
            tr.feed(recv, ev)  # tracker is IDLE -> marked seen/ignored


def mode_detail(edge: str, cred: A.EdgeCredential) -> dict | None:
    """GET /v1/admin/mode/detail (store:read: policy_version, policy_bars, rate_limit, ...) for the config
    cross-check; an older edge without the route (404) -> the public GET /v1/mode. 401/403 -> AuthFailure."""
    edge = edge.rstrip("/")
    try:
        r = httpx.get(edge + A.MODE_DETAIL_PATH, headers=cred.headers(), timeout=2.0)
    except (httpx.HTTPError, OSError) as e:
        return {"error": type(e).__name__}
    A.raise_for_auth(r.status_code, "GET", A.MODE_DETAIL_PATH, cred, _json_or_none(r))
    if r.status_code == 404:
        return _get_json(edge + A.PUBLIC_MODE_PATH)
    obj = _json_or_none(r)
    if r.status_code == 200 and isinstance(obj, dict):
        return obj
    return {"http_status": r.status_code}


def _get_json(url: str) -> dict | None:
    try:
        r = httpx.get(url, timeout=2.0)
        if r.status_code == 200:
            obj = r.json()
            return obj if isinstance(obj, dict) else {"value": obj}
        return {"http_status": r.status_code}
    except (httpx.HTTPError, ValueError, OSError) as e:
        return {"error": type(e).__name__}


if __name__ == "__main__":
    sys.exit(main())
