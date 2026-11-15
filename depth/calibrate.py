"""Depth calibration + H4 go/no-go: label real attempts and log the raw check values (numbers only).

`serve` is a stand-alone stand-in for the edge's LAN depth listener: same port (EDGE_LAN_PORT, 8001),
same X-Depth-Token check (DEPTH_DEVICE_TOKEN from env / .env, never printed), same depth_nonce echo,
same multipart contract (depth/protocol.py). If the edge LAN listener holds the port, serve falls back
to :8002 (FALLBACK_PORT); set that URL in the DepthProbe settings for the calibration session.

    edge/.venv/bin/python -m depth.calibrate serve --label live --subject s01
        phone: DepthProbe > edge URL http://<mac-lan-ip>:8001, token = DEPTH_DEVICE_TOKEN > Start
        console: Enter = capture, "l print" = switch label, "c" = challenge capture (open mouth / smile
        when prompted), "n 10" = 10 captures, "sum" = summary, "q" = quit
    edge/.venv/bin/python -m depth.calibrate summary            # per-label stats + H4 GO / NO-GO line
    edge/.venv/bin/python -m depth.calibrate synth              # pipeline smoke test, no phone

Output: depth/calibration/depth_calibration.csv (real captures only; synthetic runs go to
depth_calibration_synthetic.csv). Rows hold numbers and labels only: no depth maps, images or tokens.
"""

from __future__ import annotations

import argparse
import csv
import hmac
import json
import math
import secrets
import sys
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from statistics import median
from typing import Any
from urllib.parse import parse_qs, urlparse

import numpy as np

from depth import synth
from depth.checks import PROJECT_ROOT, classify, depth_score, load_thresholds
from depth.protocol import DepthProtocolError, DepthResult, encode_multipart, parse_multipart, process_upload
from depth.settings import device_token, lan_port

CAL_DIR = PROJECT_ROOT / "depth" / "calibration"
DEFAULT_CSV = CAL_DIR / "depth_calibration.csv"
SYNTH_CSV = CAL_DIR / "depth_calibration_synthetic.csv"
MAX_BODY = 8 * 1024 * 1024
FALLBACK_PORT = 8002  # 8765 is taken by an unrelated local service on this Mac
LABELS = ("live", "print", "print_bent", "screen", "mask_paper", "mask_3d", "other")
VALUE_COLS = (
    "d0_valid_ratio",
    "d1_plane_rms_mm",
    "d2_quad_rms_mm",
    "d3_nose_relief_mm",
    "d4_ipd_mm",
    "m2_depth_step_mm",
    "m3_template_rms_mm",
    "m1_mouth_residual_mm",
    "m1_forehead_residual_mm",
)
CSV_FIELDS = (
    "ts_utc",
    "attempt_id",
    "phase",
    "label",
    "subject",
    "device",
    "app_version",
    "depth_type",
    "dtype",
    "width",
    "height",
    "frames",
    "accuracy",
    "absolute",
    "intrinsics_source",
    "face_found",
    "landmarks_found",
    "median_face_depth_mm",
    *VALUE_COLS,
    "d4_ipd_mm_raw",
    "m1_surface_mm",
    "m1_landmark_mm",
    "cls_d0",
    "cls_d1",
    "cls_d2",
    "cls_d3",
    "cls_d4",
    "cls_m1",
    "cls_m2",
    "cls_m3",
    "overall",
    "codes",
    "depth_score",
    "valid_ratio_device",
    "capture_ms",
    "dispatch_to_result_ms",
    "compute_ms",
    "late",
    "reason",
    "error",
    "notes",
)


def _utc() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")  # spreadsheet formula triggers (CSV injection)


def _csv_cell(v: Any) -> Any:
    """'' for None; strings that a spreadsheet would evaluate get a leading quote. Numbers are untouched."""
    if v is None:
        return ""
    if isinstance(v, str) and v.startswith(CSV_FORMULA_PREFIXES):
        return "'" + v
    return v


def append_row(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.exists() or path.stat().st_size == 0
    with path.open("a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        if new:
            w.writeheader()
        w.writerow({k: _csv_cell(row.get(k)) for k in CSV_FIELDS})


def result_row(
    res: DepthResult, meta: dict[str, Any], cfg: Any, *, label: str, subject: str, **extra: Any
) -> dict:
    cls = classify(res.signal, cfg)
    diag = res.diag
    m1d = diag.get("m1", {})
    row: dict[str, Any] = {
        "ts_utc": _utc(),
        "attempt_id": res.attempt_id,
        "phase": res.phase,
        "label": label,
        "subject": subject,
        "device": str(meta.get("device", ""))[:40],
        "app_version": str(meta.get("app_version", ""))[:20],
        "depth_type": meta.get("depth_type"),
        "dtype": meta.get("dtype"),
        "width": meta.get("width"),
        "height": meta.get("height"),
        "frames": res.n_frames,
        "accuracy": res.accuracy or "unknown",
        "absolute": res.signal.get("absolute"),
        "intrinsics_source": diag.get("intrinsics_source"),
        "face_found": res.face_box_norm is not None,
        "landmarks_found": res.landmarks_norm is not None,
        "median_face_depth_mm": diag.get("median_face_depth_mm"),
        "d4_ipd_mm_raw": diag.get("d4_ipd_mm_raw"),
        "m1_surface_mm": m1d.get("m1_surface_mm"),
        "m1_landmark_mm": m1d.get("m1_landmark_mm"),
        "overall": cls["overall"],
        "codes": " ".join(cls["codes"]),
        "depth_score": depth_score(res.signal, cfg),
        "valid_ratio_device": meta.get("valid_ratio_device"),
        "capture_ms": meta.get("capture_ms"),
        "compute_ms": res.compute_ms,
        "reason": diag.get("reason") or m1d.get("reason"),
        "error": diag.get("error") or m1d.get("error"),
    }
    row.update({k: res.signal.get(k) for k in VALUE_COLS})
    row.update({f"cls_{k}": v for k, v in cls["checks"].items()})
    row.update(extra)
    return row


def describe(row: dict[str, Any]) -> str:
    def f(k: str) -> str:
        v = row.get(k)
        return "-" if v in (None, "") else (f"{v:.2f}" if isinstance(v, float) else str(v))

    return (
        f"{row['attempt_id']} {row['phase']:<9} label={row['label']:<10} {row['overall']:<13} "
        f"D0={f('d0_valid_ratio')}({row.get('cls_d0')}) D1={f('d1_plane_rms_mm')}({row.get('cls_d1')}) "
        f"D2={f('d2_quad_rms_mm')}({row.get('cls_d2')}) D3={f('d3_nose_relief_mm')}({row.get('cls_d3')}) "
        f"D4={f('d4_ipd_mm')}({row.get('cls_d4')}) M2={f('m2_depth_step_mm')} M1={f('m1_mouth_residual_mm')}/"
        f"{f('m1_forehead_residual_mm')}({row.get('cls_m1')}) dist={f('median_face_depth_mm')}mm "
        f"{row.get('depth_type')}/{row.get('accuracy')} t={f('dispatch_to_result_ms')}ms "
        f"codes=[{row.get('codes')}]" + (f" reason={row['reason']}" if row.get("reason") else "")
    )


# ------------------------------------------------------------------------------------------- server
@dataclass
class Job:
    attempt_id: str
    phase: str
    frames: int
    label: str
    subject: str
    nonce: str
    created_ms: float
    deadline_ms: float
    dispatched_ms: float | None = None
    done: bool = False
    in_flight: bool = False  # an upload holding the nonce is being measured (claimed under the lock)


class CalibrationServer:
    """Thread-safe job queue + HTTP endpoints mirroring the edge LAN depth listener."""

    def __init__(
        self,
        cfg: Any,
        csv_path: Path = DEFAULT_CSV,
        *,
        token: str | None,
        host: str = "0.0.0.0",
        port: int = 8001,
        frames: int = 3,
        deadline_s: float = 5.0,
        log: Callable[[str], None] = print,
    ) -> None:
        self.cfg, self.csv_path, self.token = cfg, csv_path, token
        self.frames, self.deadline_s, self.log = frames, deadline_s, log
        self.cond = threading.Condition()
        self.queue: deque[Job] = deque()
        self.jobs: dict[tuple[str, str], Job] = {}
        self.passive: dict[str, DepthResult] = {}
        self.rows: list[dict[str, Any]] = []
        self._seq = 0
        self.httpd = ThreadingHTTPServer((host, port), _make_handler(self))
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self._thread: threading.Thread | None = None

    # queue ---------------------------------------------------------------------------------------
    def enqueue(
        self,
        *,
        phase: str = "PASSIVE",
        label: str = "live",
        subject: str = "s00",
        attempt_id: str | None = None,
        frames: int | None = None,
    ) -> Job:
        with self.cond:
            if attempt_id is None:
                self._seq += 1
                attempt_id = f"att_cal_{int(time.time())}_{self._seq:03d}"
            now = time.time() * 1000.0
            job = Job(
                attempt_id,
                phase,
                frames or self.frames,
                label,
                subject,
                secrets.token_urlsafe(12),
                now,
                now + self.deadline_s * 1000.0,
            )
            self.jobs[(attempt_id, phase)] = job
            self.queue.append(job)
            self.cond.notify_all()
            return job

    def next_job(self, wait_s: float) -> Job | None:
        end = time.monotonic() + max(0.0, min(wait_s, 30.0))
        with self.cond:
            while True:
                now = time.time() * 1000.0
                while self.queue and self.queue[0].deadline_ms < now:
                    stale = self.queue.popleft()
                    self.log(
                        f"[calibrate] {stale.attempt_id} {stale.phase} expired before the phone picked it up"
                    )
                if self.queue:
                    job = self.queue.popleft()
                    job.dispatched_ms = now
                    return job
                remaining = end - time.monotonic()
                if remaining <= 0:
                    return None
                self.cond.wait(remaining)

    def wait_rows(self, n: int, timeout_s: float) -> bool:
        end = time.monotonic() + timeout_s
        with self.cond:
            while len(self.rows) < n:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    return False
                self.cond.wait(remaining)
            return True

    # requests ------------------------------------------------------------------------------------
    def authorised(self, headers: Any) -> bool:
        if not self.token:
            return True
        got = headers.get("X-Depth-Token") or ""
        return hmac.compare_digest(got.encode(), self.token.encode())

    def handle_frames(self, content_type: str, body: bytes) -> tuple[int, dict[str, Any]]:
        received = time.time() * 1000.0
        try:
            parts = parse_multipart(body, content_type)
            if "meta" not in parts:
                raise DepthProtocolError("meta part missing")
            meta_text = parts["meta"][1]
            meta = json.loads(meta_text)
            blobs = [parts[f"depth_{i}"][1] for i in range(3) if f"depth_{i}" in parts]
            phase = str(meta.get("phase", "")).upper()
            key = (str(meta.get("attempt_id")), phase)
            with self.cond:  # check + claim atomically: one upload per nonce is ever measured
                job = self.jobs.get(key)
                if job is None:
                    return 404, _err("ATTEMPT_NOT_FOUND", "unknown attempt_id/phase")
                if job.done or job.in_flight:
                    return 409, _err("ATTEMPT_CLOSED", "frames already received for this attempt/phase")
                if not hmac.compare_digest(str(meta.get("depth_nonce") or "").encode(), job.nonce.encode()):
                    return 403, _err("FORBIDDEN", "depth_nonce missing or mismatched")
                job.in_flight = True
                neutral = self.passive.get(job.attempt_id) if phase == "CHALLENGE" else None
        except DepthProtocolError as exc:
            return 422, _err("VALIDATION_ERROR", str(exc))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return 422, _err("VALIDATION_ERROR", f"bad meta: {exc}")
        try:
            res = process_upload(meta_text, blobs, self.cfg, neutral=neutral)
        except DepthProtocolError as exc:
            with self.cond:
                job.in_flight = False  # malformed upload: the phone may retry with the same nonce
            return 422, _err("VALIDATION_ERROR", str(exc))
        except BaseException:
            with self.cond:
                job.in_flight = False
            raise
        late = received > job.deadline_ms
        row = result_row(
            res,
            meta,
            self.cfg,
            label=job.label,
            subject=job.subject,
            late=late,
            dispatch_to_result_ms=round(received - (job.dispatched_ms or job.created_ms)),
        )
        with self.cond:
            job.done = True
            if phase == "PASSIVE":
                self.passive[job.attempt_id] = res
                while len(self.passive) > 20:  # memory only, bounded
                    self.passive.pop(next(iter(self.passive)))
            self.rows.append(row)
            append_row(self.csv_path, row)
            self.cond.notify_all()
        self.log("[calibrate] " + describe(row))
        return 200, {
            "attempt_id": res.attempt_id,
            "phase": res.phase,
            "accepted": True,
            "signal": res.signal,
            "overall": row["overall"],
            "codes": row["codes"].split(),
            "compute_ms": res.compute_ms,
        }

    # lifecycle -----------------------------------------------------------------------------------
    def start(self) -> None:
        self._thread = threading.Thread(target=self.httpd.serve_forever, name="calibrate-http", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def _err(code: str, message: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message}}


def _make_handler(server: CalibrationServer) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet; never logs headers (token)
            pass

        def _send(self, status: int, payload: dict[str, Any] | None = None) -> None:
            body = b"" if payload is None else json.dumps(payload).encode()
            self.send_response(status)
            if payload is not None:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            url = urlparse(self.path)
            if url.path in ("/health", "/v1/health"):
                return self._send(200, {"status": "ok", "mode": "depth-calibration"})
            if url.path != "/v1/depth/pending":
                return self._send(404, _err("NOT_FOUND", url.path))
            if not server.authorised(self.headers):
                # same text as the edge (edge/app.py require_depth_device): DepthProbe's Find Mac and
                # "Token missing / rejected" diagnosis key on it
                return self._send(401, _err("UNAUTHORIZED", "depth device token required"))
            try:
                wait_s = float(parse_qs(url.query).get("wait_s", ["20"])[0])
            except ValueError:
                wait_s = 20.0
            job = server.next_job(wait_s)
            if job is None:
                return self._send(204)
            return self._send(
                200,
                {
                    "attempt_id": job.attempt_id,
                    "phase": job.phase,
                    "frames": job.frames,
                    "deadline_ms": round(job.deadline_ms),
                    "depth_nonce": job.nonce,
                },
            )

        def do_POST(self) -> None:  # noqa: N802
            if urlparse(self.path).path != "/v1/depth/frames":
                return self._send(404, _err("NOT_FOUND", self.path))
            if not server.authorised(self.headers):
                # same text as the edge (edge/app.py require_depth_device): DepthProbe's Find Mac and
                # "Token missing / rejected" diagnosis key on it
                return self._send(401, _err("UNAUTHORIZED", "depth device token required"))
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0  # malformed header -> 422 below (never an unhandled exception)
            if length <= 0 or length > MAX_BODY:
                too_big = length > MAX_BODY  # API.md section 0: 413 = PAYLOAD_TOO_LARGE
                return self._send(
                    413 if too_big else 422,
                    _err("PAYLOAD_TOO_LARGE" if too_big else "VALIDATION_ERROR", "bad Content-Length"),
                )
            body = self.rfile.read(length)
            status, payload = server.handle_frames(self.headers.get("Content-Type", ""), body)
            return self._send(status, payload)

    return Handler


# ------------------------------------------------------------------------------------------ summary
def _f(v: str) -> float | None:
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return x if math.isfinite(x) else None


def summarise(rows: Iterable[dict[str, str]], *, min_n: int = 10) -> tuple[str, str]:
    """Per-label stats and the H4 verdict (D1 must FAIL every print and PASS every live face)."""
    by: dict[tuple[str, str], list[dict[str, str]]] = {}
    for r in rows:
        by.setdefault((r.get("label", ""), r.get("phase", "")), []).append(r)
    lines = []
    for (label, phase), rs in sorted(by.items()):
        lines.append(f"{label} / {phase}: n={len(rs)}  overall={_counts(r.get('overall') for r in rs)}")
        for col in VALUE_COLS:
            vals = [x for x in (_f(r.get(col, "")) for r in rs) if x is not None]
            if vals:
                lines.append(
                    f"    {col:<24} n={len(vals):<3} min={min(vals):8.2f} med={median(vals):8.2f} "
                    f"max={max(vals):8.2f}  cls={_counts(r.get('cls_' + col[:2]) for r in rs)}"
                )
    live = [r for r in by.get(("live", "PASSIVE"), [])]
    prints = [r for r in by.get(("print", "PASSIVE"), [])]
    live_pass = sum(r.get("cls_d1") == "PASS" for r in live)
    print_fail = sum(r.get("cls_d1") == "FAIL" for r in prints)
    if len(live) < min_n or len(prints) < min_n:
        verdict = (
            f"H4 depth: INSUFFICIENT DATA (need >= {min_n} live and >= {min_n} print PASSIVE attempts; "
            f"have live {len(live)}, print {len(prints)})"
        )
    elif live_pass == len(live) and print_fail == len(prints):
        verdict = (
            f"H4 depth: GO - D1 rejected {print_fail}/{len(prints)} prints, passed {live_pass}/{len(live)} "
            f"live (0 errors: true error rate < {3 / len(prints):.0%} prints / < {3 / len(live):.0%} live "
            "at 95 %, rule of 3)"
        )
    else:
        verdict = (
            f"H4 depth: NO-GO - D1 rejected {print_fail}/{len(prints)} prints, "
            f"passed {live_pass}/{len(live)} "
            "live -> drop depth to a roadmap slide (or fix and re-run)"
        )
    return "\n".join(lines), verdict


def _counts(vals: Iterable[str | None]) -> str:
    c: dict[str, int] = {}
    for v in vals:
        c[v or "-"] = c.get(v or "-", 0) + 1
    return " ".join(f"{k}:{v}" for k, v in sorted(c.items()))


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# -------------------------------------------------------------------------------------------- synth
def run_synth(
    cfg: Any, csv_path: Path = SYNTH_CSV, *, seed: int = 0, repeats: int = 3
) -> list[dict[str, Any]]:
    """Full wire path (encode -> parse -> measure) on synthetic scenes; label = synthetic_<scene>."""
    rng = np.random.default_rng(seed)
    cam = synth.SynthCamera(320, 240)
    rows = []
    for scene in synth.SCENES:
        for i in range(repeats):
            passive: DepthResult | None = None
            for phase in ("PASSIVE", "CHALLENGE") if scene in ("face", "mask_rigid") else ("PASSIVE",):
                att = f"att_syn_{scene}_{i}"
                clean = synth.make_scene(scene, cam, rng, phase=phase, sigma_mm=0.0, hole_fraction=0.0)
                blobs = [
                    synth.to_wire(synth.add_sensor_noise(clean.depth_m, rng), "disparity", "float16")
                    for _ in range(3)
                ]
                meta = {
                    "attempt_id": att,
                    "phase": phase,
                    "depth_type": "disparity",
                    "dtype": "float16",
                    "width": cam.width,
                    "height": cam.height,
                    "intrinsics": cam.intrinsics(640, 480),
                    "face_box_norm": clean.face_box_norm,
                    "landmarks_norm": clean.landmarks_norm,
                    "timestamps_ms": [0, 33, 67],
                    "device": "synthetic",
                    "depth_accuracy": "absolute",
                }
                body, ctype = encode_multipart(meta, blobs)
                parts = parse_multipart(body, ctype)
                res = process_upload(
                    parts["meta"][1], [parts[f"depth_{k}"][1] for k in range(3)], cfg, neutral=passive
                )
                if phase == "PASSIVE":
                    passive = res
                row = result_row(res, meta, cfg, label=f"synthetic_{scene}", subject="synthetic")
                append_row(csv_path, row)
                rows.append(row)
                print(describe(row))
    return rows


# ---------------------------------------------------------------------------------------------- CLI
HELP = (
    "Enter=capture  c=challenge capture (ask: OPEN MOUTH)  n <k>=k captures  l <label>=label "
    f"({', '.join(LABELS)})  s <id>=subject  sum=summary  q=quit"
)


def _console(server: CalibrationServer, label: str, subject: str, gap_s: float) -> None:
    last: Job | None = None
    print(HELP)
    while True:
        try:
            line = input(f"[{label}/{subject}] > ").strip()
        except EOFError:
            print("stdin closed; serving until Ctrl-C")
            while True:
                time.sleep(3600)
        if line == "q":
            return
        if line == "sum":
            text, verdict = summarise(read_rows(server.csv_path))
            print(text + "\n" + verdict)
        elif line.startswith("l "):
            label = line[2:].strip() or label
        elif line.startswith("s "):
            subject = line[2:].strip() or subject
        elif line == "c":
            if last is None:
                print("no PASSIVE attempt yet")
            else:
                print("NOW: open mouth wide (or big smile) and hold")
                server.enqueue(phase="CHALLENGE", label=label, subject=subject, attempt_id=last.attempt_id)
        elif line.startswith("n "):
            try:
                k = int(line[2:])
            except ValueError:
                print("usage: n <count>")
                continue
            for _ in range(k):
                last = server.enqueue(label=label, subject=subject)
                time.sleep(gap_s)
        elif line == "":
            last = server.enqueue(label=label, subject=subject)
            print(f"queued {last.attempt_id} (phone must be running DepthProbe > Start)")
        else:
            print(HELP)


def _answers_locally(port: int) -> bool:
    """macOS lets 0.0.0.0:port bind next to 127.0.0.1:port; probe so local clients are not misrouted."""
    import socket

    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="calibration server for the real phone")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=None, help="default EDGE_LAN_PORT (8001)")
    s.add_argument("--label", default="live")
    s.add_argument("--subject", default="s01", help="pseudonymous id, never a name")
    s.add_argument("--frames", type=int, default=3)
    s.add_argument("--deadline-s", type=float, default=5.0)
    s.add_argument("--gap-s", type=float, default=2.0)
    s.add_argument("--auto", type=int, default=0, help="queue N captures without the console, then exit")
    s.add_argument("--auto-challenge", action="store_true", help="with --auto: CHALLENGE after each PASSIVE")
    s.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    s.add_argument("--no-token", action="store_true", help="accept requests without X-Depth-Token (dev only)")
    m = sub.add_parser("summary", help="per-label stats + H4 verdict")
    m.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    m.add_argument("--min-n", type=int, default=10)
    y = sub.add_parser("synth", help="pipeline smoke test on synthetic scenes (separate CSV)")
    y.add_argument("--csv", type=Path, default=SYNTH_CSV)
    y.add_argument("--repeats", type=int, default=3)
    a = ap.parse_args(argv)
    cfg = load_thresholds()

    if a.cmd == "summary":
        text, verdict = summarise(read_rows(a.csv), min_n=a.min_n)
        print(text or "(no rows)")
        print(verdict)
        return 0
    if a.cmd == "synth":
        run_synth(cfg, a.csv, repeats=a.repeats)
        print(f"wrote {a.csv}")
        return 0

    token = None if a.no_token else device_token()
    if token is None and not a.no_token:
        print(
            "DEPTH_DEVICE_TOKEN not set (env or .env); pass --no-token to run open (dev only)",
            file=sys.stderr,
        )
        return 2
    ports = [a.port] if a.port else [lan_port(), FALLBACK_PORT]
    server = None
    for port in ports:
        if _answers_locally(port):
            print(
                f"port {port} already answers on 127.0.0.1 (edge LAN listener or another service)",
                file=sys.stderr,
            )
            continue
        try:
            server = CalibrationServer(
                cfg, a.csv, token=token, host=a.host, port=port, frames=a.frames, deadline_s=a.deadline_s
            )
            break
        except OSError as exc:
            print(
                f"cannot bind {a.host}:{port} ({exc}): the edge LAN listener probably holds it",
                file=sys.stderr,
            )
    if server is None:
        return 2
    if server.port != lan_port():
        print(
            f"NOTE: set the DepthProbe edge URL to http://<mac-lan-ip>:{server.port} for calibration "
            f"(and back to :{lan_port()} for the kiosk afterwards)"
        )
    server.start()
    print(
        f"depth calibration listening on {a.host}:{server.port} (token {'required' if token else 'OFF'}); "
        f"CSV -> {a.csv}"
    )
    try:
        if a.auto:
            for _ in range(a.auto):
                job = server.enqueue(label=a.label, subject=a.subject)
                n_before = len(server.rows)
                if not server.wait_rows(n_before + 1, a.deadline_s + 25):
                    print(f"no upload for {job.attempt_id} (is DepthProbe running and pointed here?)")
                    continue
                if a.auto_challenge:
                    print("NOW: open mouth wide and hold")
                    time.sleep(1.0)
                    server.enqueue(
                        phase="CHALLENGE", label=a.label, subject=a.subject, attempt_id=job.attempt_id
                    )
                    server.wait_rows(n_before + 2, a.deadline_s + 25)
                time.sleep(a.gap_s)
            text, verdict = summarise(read_rows(a.csv))
            print(verdict)
        else:
            _console(server, a.label, a.subject, a.gap_s)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
