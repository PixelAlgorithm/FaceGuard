"""Measure edge-side latency of the 2 s path over real HTTP (never estimated).

Starts its OWN `uvicorn edge.app:app` in a subprocess on a scratch port (isolated EDGE_DATA_DIR with a copy
of edge/data/bundle.signed.json, CLOUD_API_URL="" unless --with-cloud, LAN listener off), enrols the
synthetic public-domain face so 1:N matching runs, warms up, then runs N sequential attempts:
POST /v1/session/start -> POST /v1/attempt/{id}/frames (5 x WxH JPEG q85 + meta).

Default frame size is the shipped capture size: CaptureSpec.max_width_px = 1280 (edge/schemas.py) with the
kiosk's camera request 1280x720 (kiosk/src/capture/camera.ts). `--width 640 --height 480` reproduces the
earlier 640 px benchmark.

Reports p50/p95 per stage (server latency_ms) and client round trips with a percentile-bootstrap 95 % CI
(2000 resamples) and a distribution-free order-statistic 95 % CI; writes a Markdown report + raw CSV.

    edge/.venv/bin/python scripts/bench_latency.py --runs 40 --port 8096

Never points at the live edge: ports 8000/8001/5173 are refused.

Auth (RBAC): before starting the scratch edge the script provisions an API key into the scratch EDGE_DATA_DIR
(`python -m edge.auth create-api-key --name bench --role evaluator --role enroller --expires-days 1
--print-key-only`) and sends it as `Authorization: Bearer` (POST /v1/enroll, POST /v1/admin/rate-limit/reset).
`--auth legacy` instead sets AUTH_LEGACY_ADMIN_TOKEN=1 plus a random ADMIN_TOKEN in the child env only.
`--auth auto` (default) = key when edge/auth/cli.py exists, else legacy. The scratch edge always gets a fresh
random EDGE_DATA_KEY (the live data key is never used). The key/token is never printed or written; a 401/403
stops the run with a clear error (exit 5).
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import math
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import numpy as np
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from edge import synth
from edge.config import load_dotenv

STAGES = ["quality", "liveness", "match", "policy", "total"]
LIVE_PORTS = {8000, 8001, 5173}
EXCLUDED_CODES = {"RATE_LIMITED", "SYSTEM_ERROR"}
N_BOOT = 2000
EXIT_AUTH = 5
AUTH_CLI = ROOT / "edge" / "auth" / "cli.py"
API_KEY_RE = re.compile(r"^fgk_(?P<key_id>[a-z0-9]{8})\.[A-Za-z0-9_-]{32,128}$")
CLI_LOCK_BUSY = 75  # edge.auth CLI: store lock busy, retry
KEY_ROLES = ("evaluator", "enroller")  # ratelimit:reset + store:read (mode detail) + enrol:write
SCOPE_NOTE = "server-side only, synthetic frames, offline mode, excludes face lock / flash window / rendering"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def sha256_file(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def binom_cdf(k: int, n: int, p: float) -> float:
    return sum(math.comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(k + 1))


def quantile_ci(values: list[float], q: float, conf: float = 0.95) -> tuple[float, float, str]:
    """Distribution-free CI for the q-quantile from order statistics (coverage >= conf)."""
    x = sorted(values)
    n = len(x)
    alpha = (1 - conf) / 2
    lo = max([j for j in range(n + 1) if binom_cdf(j - 1, n, q) <= alpha] or [0])
    hi = min([k for k in range(1, n + 1) if binom_cdf(k - 1, n, q) >= 1 - alpha] or [n])
    note = "" if hi < n else " (upper = max)"
    return x[max(lo, 1) - 1], x[min(hi, n) - 1], note


def boot_ci(values: list[float], q: float, n_boot: int = N_BOOT, seed: int = 0) -> tuple[float, float]:
    """Percentile-bootstrap 95 % CI of the q-quantile (resample attempts with replacement)."""
    x = np.asarray(values, dtype=np.float64)
    rng = np.random.default_rng(seed)
    bs = np.percentile(rng.choice(x, (n_boot, len(x)), replace=True), q * 100, axis=1)
    return float(np.percentile(bs, 2.5)), float(np.percentile(bs, 97.5))


def pct(values: list[float], q: float) -> float:
    return float(np.percentile(np.asarray(values, dtype=np.float64), q * 100))


class ScratchAuth:
    """Credential for the scratch edge only. Holds the secret; describe() never includes it."""

    def __init__(self, kind: str, secret: str, key_id: str = "") -> None:
        self.kind, self._secret, self.key_id = kind, secret, key_id

    def headers(self) -> dict[str, str]:
        if self.kind == "api_key":
            return {"Authorization": f"Bearer {self._secret}"}
        return {"X-Admin-Token": self._secret}

    def describe(self) -> str:
        if self.kind == "api_key":
            return f"API key key:{self.key_id} (roles {'+'.join(KEY_ROLES)}, expires in 1 day, scratch store)"
        return "legacy X-Admin-Token (AUTH_LEGACY_ADMIN_TOKEN=1, random ADMIN_TOKEN in the child env only)"


def scratch_env(data_dir: Path, with_cloud: bool) -> dict[str, str]:
    env = {**os.environ, "EDGE_DATA_DIR": str(data_dir), "EDGE_LAN_PORT": "0", "FORCE_OFFLINE": "0",
           "DEMO_MODE": "0", "EDGE_DATA_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()}
    for k in ("BUNDLE_PATH", "STAFF_STORE_KEY"):
        env.pop(k, None)
    if not with_cloud:  # synthetic frames must not reach Rekognition or the cloud decision ledger
        env["CLOUD_API_URL"] = ""
    return env


def provision_api_key(env: dict[str, str]) -> ScratchAuth:
    """Mint a 1-day evaluator+enroller key in the scratch store via the edge.auth CLI (stdout = the key only)."""
    cmd = [sys.executable, "-m", "edge.auth", "create-api-key", "--name", "bench",
           *[x for r in KEY_ROLES for x in ("--role", r)], "--expires-days", "1", "--print-key-only"]
    for _ in range(2):
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=60, check=False)
        if r.returncode != CLI_LOCK_BUSY:
            break
        time.sleep(1.0)
    key = r.stdout.strip()
    m = API_KEY_RE.match(key)
    if r.returncode != 0 or not m:
        tail = " | ".join(r.stderr.strip().splitlines()[-3:])[:300]
        raise SystemExit(f"edge.auth create-api-key failed (exit {r.returncode}): {tail or 'no key on stdout'}")
    return ScratchAuth("api_key", key, m["key_id"])


def scratch_auth(mode: str, env: dict[str, str]) -> ScratchAuth:
    """Set up the child env for the chosen auth mode and return the credential to send."""
    if mode == "auto":
        mode = "key" if AUTH_CLI.is_file() else "legacy"
    if mode == "key":
        env["AUTH_LEGACY_ADMIN_TOKEN"] = "0"
        return provision_api_key(env)
    token = secrets.token_urlsafe(32)
    env |= {"AUTH_LEGACY_ADMIN_TOKEN": "1", "ADMIN_TOKEN": token}
    return ScratchAuth("legacy", token)


def check_auth(r: httpx.Response, what: str, auth: ScratchAuth) -> None:
    if r.status_code in (401, 403):
        try:
            err = (r.json() or {}).get("error") or {}
        except ValueError:
            err = {}
        reason = " ".join(str(err.get(k)) for k in ("code", "reason", "required") if err.get(k))[:200]
        print(f"ERROR: scratch edge refused {what}: HTTP {r.status_code} {reason} ({auth.describe()})",
              file=sys.stderr)
        raise SystemExit(EXIT_AUTH)


def mode_detail(client: httpx.Client, auth: ScratchAuth) -> dict:
    """GET /v1/admin/mode/detail (store:read: bundle, zone, policy_version); 404 (older edge) -> GET /v1/mode."""
    r = client.get("/v1/admin/mode/detail", headers=auth.headers())
    check_auth(r, "GET /v1/admin/mode/detail", auth)
    if r.status_code == 404:
        r = client.get("/v1/mode")
    r.raise_for_status()
    return r.json()


def wait_ready(base: str, proc: subprocess.Popen, timeout_s: float = 120.0) -> float:
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < timeout_s:
        if proc.poll() is not None:
            raise RuntimeError(f"scratch edge exited with code {proc.returncode} before ready")
        try:
            if httpx.get(f"{base}/v1/health", timeout=1.0).status_code == 200:
                return time.perf_counter() - t0
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    raise RuntimeError("edge did not become ready")


def make_attempt_sized(session: dict[str, Any], size: tuple[int, int], *, n_frames: int = 5,
                       lag_ms: float = 50.0, gain: float = 0.12) -> tuple[list[bytes], dict[str, Any]]:
    """synth.make_attempt at an arbitrary canvas size (the face scales with the frame height).

    Same reflection model, timing and meta as edge/synth.py; only the canvas size, the chroma ROI, the IOD hint
    and track_settings follow `size`. Kept here so edge/ stays untouched (edge-ml owns it).
    """
    w, h = size
    if size == (640, 480):
        return synth.make_attempt(session, n_frames=n_frames, lag_ms=lag_ms, gain=gain)
    seq = session.get("flash_sequence") or []
    window = float(session.get("capture", {}).get("window_ms", 1000))
    start = int(time.time() * 1000) - int(window) - 60
    face_lock = start - 120
    frame_t = [start + window * (i + 0.6) / n_frames for i in range(n_frames)]
    base = [synth.base_frame(shift_px=(i % 3) - 1, size=size) for i in range(n_frames)]
    frames = [synth.jpeg(synth.tint(base[i], synth.colour_at(seq, t - start - lag_ms), gain))
              for i, t in enumerate(frame_t)]
    fw = int(250 * h / 300)
    x0 = (w - fw) // 2
    roi = base[0][int(0.23 * h):int(0.52 * h), x0 + int(0.35 * fw):x0 + int(0.65 * fw)].reshape(-1, 3).mean(axis=0)
    series = []
    for k in range(int(window / 33.3) + 1):
        t = start + k * 33.3
        col = synth.colour_at(seq, t - start - lag_ms)
        v = roi if col is None else np.clip(
            roi * (1.0 + gain * (synth.hex_bgr01(col) - synth.hex_bgr01(col).mean())), 0, 255)
        series.append({"t_ms": round(t, 1), "r": float(v[2]), "g": float(v[1]), "b": float(v[0])})
    meta = {
        "nonce": session["nonce"],
        "face_lock_at_ms": int(face_lock),
        "capture_started_at_ms": int(start),
        "frame_timestamps_ms": [int(t) for t in frame_t],
        "flash_events": [{"step_index": i, "color": s["color"], "shown_at_ms": start + s["offset_ms"]}
                         for i, s in enumerate(seq)],
        "chroma_series": series,
        "quality": {"face_count": 1, "iod_px": round(90.0 * h / 480, 1), "yaw_deg": 0.0, "pitch_deg": 0.0,
                    "roll_deg": 0.0, "blur_var": 200.0, "luma_mean": 120.0, "face_box": [0.3, 0.2, 0.4, 0.5]},
        "client_signals": {"camera_label": "FaceTime HD Camera", "virtual_camera_suspected": False,
                           "device_count": 1, "track_settings": {"width": w, "height": h, "frameRate": 30},
                           "fps_measured": 30.0, "frame_interval_jitter_ms": 2.0, "exposure_locked": False},
        "blendshapes": {"mouthSmileLeft": 0.03, "mouthSmileRight": 0.03, "jawOpen": 0.02, "cheekPuff": 0.01},
    }
    return frames, meta


def attempt(client: httpx.Client, kiosk: str, size: tuple[int, int], auth: ScratchAuth, reset: bool) -> dict:
    if reset:  # scratch edge only: keep the limiter from deciding instead of the pipeline
        r = client.post("/v1/admin/rate-limit/reset", headers=auth.headers())
        check_auth(r, "POST /v1/admin/rate-limit/reset", auth)
        r.raise_for_status()
    t0 = time.perf_counter()
    r = client.post("/v1/session/start", json={"kiosk_id": kiosk, "client": {
        "camera_label": "FaceTime HD Camera", "user_agent": "bench", "screen": {}}, "flash_enabled": True})
    r.raise_for_status()
    start_ms = (time.perf_counter() - t0) * 1000
    sess = r.json()
    frames, meta = make_attempt_sized(sess, size)
    files, data = synth.multipart_files(frames, meta)
    t1 = time.perf_counter()
    r = client.post(f"/v1/attempt/{sess['attempt_id']}/frames", files=files, data=data)
    rtt = (time.perf_counter() - t1) * 1000
    r.raise_for_status()
    d = r.json()
    codes = list(d.get("reason_codes") or [])
    return {"attempt_id": sess["attempt_id"], "session_start_rtt": start_ms, "frames_rtt": rtt,
            "x_latency_ms": float(r.headers["x-latency-ms"]), "decision": d["decision"],
            "mode": d.get("mode"), "reason_codes": ";".join(codes),
            "excluded": bool(EXCLUDED_CODES & set(codes)),
            "upload_bytes": sum(len(b) for b in frames), **{s: d["latency_ms"].get(s) for s in STAGES}}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=30)
    ap.add_argument("--warmup", type=int, default=3)
    ap.add_argument("--width", type=int, default=1280, help="frame width (shipped CaptureSpec.max_width_px)")
    ap.add_argument("--height", type=int, default=720, help="frame height (kiosk camera request 1280x720)")
    ap.add_argument("--port", type=int, default=0, help="scratch port (0 = free port); 8000/8001/5173 refused")
    ap.add_argument("--out", default=None, help="Markdown report (default eval/results/latency_edge_<w>_<ts>.md)")
    ap.add_argument("--csv", default=None, help="raw CSV (default: report path with .csv)")
    ap.add_argument("--no-reset-rate-limit", action="store_true",
                    help="do not reset the scratch edge's rate limiter before each attempt")
    ap.add_argument("--with-cloud", action="store_true",
                    help="keep CLOUD_API_URL (Rekognition on the path); default measures the edge only")
    ap.add_argument("--auth", choices=["auto", "key", "legacy"], default="auto",
                    help="scratch credential: API key via edge.auth CLI, or legacy random ADMIN_TOKEN")
    args = ap.parse_args()
    if args.runs < 20:
        raise SystemExit("--runs must be >= 20")
    if args.port in LIVE_PORTS:
        raise SystemExit(f"--port {args.port} is a live demo port; use a scratch port (e.g. 8096)")
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out = Path(args.out) if args.out else ROOT / "eval" / "results" / f"latency_edge_{args.width}_{ts}.md"
    csv_path = Path(args.csv) if args.csv else out.with_suffix(".csv")
    size = (args.width, args.height)
    load_dotenv(ROOT / ".env")
    port = args.port or free_port()
    base = f"http://127.0.0.1:{port}"
    data_dir = Path(tempfile.mkdtemp(prefix="edge_bench_"))
    env = scratch_env(data_dir, args.with_cloud)
    try:
        auth = scratch_auth(args.auth, env)
    except BaseException:
        shutil.rmtree(data_dir, ignore_errors=True)
        raise
    print(f"scratch edge credential: {auth.describe()}")
    src_bundle = ROOT / "edge" / "data" / "bundle.signed.json"
    bundle_sha = sha256_file(src_bundle)
    if src_bundle.is_file():  # copy: the scratch edge never writes next to the live edge's files
        shutil.copy2(src_bundle, data_dir / "bundle.signed.json")
    thr_path = ROOT / "config" / "thresholds.yaml"
    thr_sha = sha256_file(thr_path)
    thr = yaml.safe_load(thr_path.read_text(encoding="utf-8"))
    log_fd, log_path = tempfile.mkstemp(prefix="edge_bench_", suffix=".log")
    log = os.fdopen(log_fd, "w")
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "edge.app:app", "--host", "127.0.0.1",
                             "--port", str(port), "--log-level", "warning"], cwd=ROOT, env=env,
                            stdout=log, stderr=subprocess.STDOUT)
    load_before = os.getloadavg()
    try:
        startup_s = wait_ready(base, proc)
        with httpx.Client(base_url=base, timeout=30.0) as c:
            health = c.get("/v1/health").json()
            mode = mode_detail(c, auth)
            frames = [synth.jpeg(synth.base_frame(shift_px=s, size=size)) for s in (-8, -4, 0, 4, 8)]
            files = {f"frame_{i}": (f"f{i}.jpg", b, "image/jpeg") for i, b in enumerate(frames)}
            meta = {"user_id": "u_3c4d", "display_name": "Synthetic", "role": "student", "consent": True,
                    "consent_version": "bench", "provision_totp": False}
            er = c.post("/v1/enroll", files=files, data={"meta": json.dumps(meta)}, headers=auth.headers())
            check_auth(er, "POST /v1/enroll", auth)
            enrolled = er.status_code == 201
            if not enrolled:
                print(f"WARNING: enrolment failed (HTTP {er.status_code}); 1:N match runs on an empty gallery")
            kiosk = health["detail"]["kiosk_id"]
            reset = not args.no_reset_rate_limit
            for _ in range(args.warmup):
                attempt(c, kiosk, size, auth, reset)
            load_start = os.getloadavg()
            runs = [attempt(c, kiosk, size, auth, reset) for _ in range(args.runs)]
            load_end = os.getloadavg()
            mode_after = c.get("/v1/mode").json()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        log.close()
        shutil.rmtree(data_dir, ignore_errors=True)  # encrypted decision log of synthetic attempts only
    ctx = {"ts": ts, "port": port, "size": size, "health": health, "mode": mode, "mode_after": mode_after,
           "startup_s": startup_s, "enrolled": enrolled, "reset": reset, "thr_sha": thr_sha, "thr": thr,
           "bundle_sha": bundle_sha, "bundle_copied": src_bundle.is_file(), "proc_rc": proc.returncode,
           "load": {"before_spawn": load_before, "before_runs": load_start, "after_runs": load_end},
           "log_path": log_path, "auth": auth.describe()}
    write_csv(csv_path, runs, size)
    write_report(args, out, csv_path, runs, ctx)


def write_csv(path: Path, runs: list[dict], size: tuple[int, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    cols = ["run", "attempt_id", "width_px", "height_px", "upload_bytes", *STAGES, "x_latency_ms", "frames_rtt_ms",
            "session_start_rtt_ms", "decision", "mode", "reason_codes", "excluded"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for i, r in enumerate(runs, 1):
            w.writerow([i, r["attempt_id"], size[0], size[1], r["upload_bytes"], *(r[s] for s in STAGES),
                        f"{r['x_latency_ms']:.1f}", f"{r['frames_rtt']:.1f}", f"{r['session_start_rtt']:.1f}",
                        r["decision"], r["mode"], r["reason_codes"], int(r["excluded"])])


def _get(d: dict, dotted: str) -> Any:
    for k in dotted.split("."):
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


def write_report(args, out: Path, csv_path: Path, runs: list[dict], ctx: dict) -> None:
    import onnxruntime as ort

    d = ctx["health"]["detail"]
    mode, thr = ctx["mode"], ctx["thr"]
    kept = [r for r in runs if not r["excluded"]]
    rows = []
    for key, label in [("quality", "decode + detect + align + quality (5 frames, parallel)"),
                       ("liveness", "liveness branch: MiniFASNet x2, YOLOX device x5, moire, mask ring, flash"),
                       ("match", "match branch: ArcFace r50 x<=3 + 1:N (local only)"),
                       ("policy", "PolicyRuntime.decide"),
                       ("total", "**server total `latency_ms.total`: frames received -> decision**"),
                       ("x_latency_ms", "X-Latency-Ms (incl. multipart parse)"),
                       ("frames_rtt", "client RTT POST /frames (localhost HTTP, upload incl.)"),
                       ("session_start_rtt", "client RTT POST /session/start")]:
        vals = [float(r[key]) for r in kept if r.get(key) is not None]
        if not vals:
            rows.append(f"| {label} | 0 | - | - | - | - | - | - |")
            continue
        b50, b95 = boot_ci(vals, 0.5), boot_ci(vals, 0.95)
        lo50, hi50, _ = quantile_ci(vals, 0.5)
        lo95, hi95, n95 = quantile_ci(vals, 0.95)
        rows.append(f"| {label} | {len(vals)} | {pct(vals, .5):.1f} | [{b50[0]:.1f}, {b50[1]:.1f}] / "
                    f"[{lo50:.0f}, {hi50:.0f}] | {pct(vals, .95):.1f} | [{b95[0]:.1f}, {b95[1]:.1f}] / "
                    f"[{lo95:.0f}, {hi95:.0f}]{n95} | {max(vals):.1f} |")
    decisions = {k: sum(r["decision"] == k for r in runs) for k in ("ALLOW", "STEP_UP", "DENY")}
    codes: dict[str, int] = {}
    for r in runs:
        for c in filter(None, r["reason_codes"].split(";")):
            codes[c] = codes.get(c, 0) + 1
    modes = sorted({str(r["mode"]) for r in runs})
    cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True,
                         check=False).stdout.strip()
    la = ctx["load"]
    fmt_la = lambda t: "/".join(f"{x:.2f}" for x in t)
    w, h = ctx["size"]
    rel_csv = csv_path.relative_to(ROOT) if csv_path.is_relative_to(ROOT) else csv_path
    cmd = "edge/.venv/bin/python scripts/bench_latency.py " + " ".join(sys.argv[1:])
    sb = mode.get("schedule_bundle") or {}
    md = f"""# Edge latency at the shipped capture size ({w}x{h}) - measured {ctx['ts']}

> **Scope: {SCOPE_NOTE}.** Not an eval result and not the slide number: the user-visible SLA is kiosk face
> lock -> decision rendered (`POST /v1/attempt/{{id}}/rendered`), which this run does not measure.

Command (from the project root): `{cmd}`

Raw per-attempt values: `{rel_csv}` ({len(runs)} rows). The script spawned its own `uvicorn edge.app:app` on
scratch port {ctx['port']} (127.0.0.1) with a temp `EDGE_DATA_DIR` holding a copy of
`edge/data/bundle.signed.json`, `CLOUD_API_URL=""`, `EDGE_LAN_PORT=0`, `FORCE_OFFLINE=0`, `DEMO_MODE=0`, a fresh
random `EDGE_DATA_KEY`; admin calls authenticated with {ctx['auth']}. It ran
{args.warmup} warm-up attempts, then {len(runs)} sequential measured attempts. The scratch edge was stopped
afterwards (exit code {ctx['proc_rc']}) and its temp data dir deleted. The live edge (:8000/:8001) was not touched.

| stage | n | p50 ms | 95% CI p50: bootstrap / order-stat | p95 ms | 95% CI p95: bootstrap / order-stat | max ms |
|---|---|---|---|---|---|---|
{chr(10).join(rows)}

Rows excluded from the table (reason code `RATE_LIMITED` or `SYSTEM_ERROR`): {len(runs) - len(kept)}.
Bootstrap = percentile bootstrap over attempts, {N_BOOT} resamples, seed 0. Order-stat = distribution-free
binomial bound (coverage >= 95 %); "(upper = max)" means n is too small for a tighter upper bound than
the sample maximum. Percentiles use numpy linear interpolation. With n = {len(kept)} the p95 is estimated
from the top few samples; treat its CI as indicative.

## Configuration under test

- policy_version (edge `/v1/health`): `{d.get('policy_version')}`; thresholds.yaml `policy_version`:
  `{thr.get('policy_version')}`; policy runtime: `{d.get('policy_runtime')}`.
- Config hash: `config/thresholds.yaml` sha256 `{ctx['thr_sha']}`.
- Schedule bundle: `edge/data/bundle.signed.json` sha256 `{ctx['bundle_sha']}` (copied: {ctx['bundle_copied']}),
  bundle v{sb.get('version')} ({sb.get('cache_state')}).
- Switches: `liveness.flash.enforce` = {_get(thr, 'liveness.flash.enforce')} (false = ADVISORY: the flash
  analysis runs and is timed, no decision effect); `liveness.moire.enforce` = {_get(thr, 'liveness.moire.enforce')};
  `liveness.mask.m2_rgb_enforce` = {_get(thr, 'liveness.mask.m2_rgb_enforce')}; `liveness.depth.enabled` =
  {_get(thr, 'liveness.depth.enabled')}; `challenge.random_rate` = {_get(thr, 'challenge.random_rate')}
  (offline override {_get(thr, 'offline.overrides.challenge.random_rate')}); `match.rekognition.enabled` =
  {_get(thr, 'match.rekognition.enabled')} (not on this path: no cloud configured); `rate_limit.enabled` =
  {_get(thr, 'rate_limit.enabled')}, scratch-edge limiter reset before every attempt: {ctx['reset']}.
- Mode: {mode.get('mode')} at start, {ctx['mode_after'].get('mode')} at end; per-attempt `mode` values: {modes};
  zone {mode.get('zone')}. Cloud configured: {d.get('cloud_configured')}, so the match branch is local
  ArcFace only and the online Rekognition call (time box 700 ms) is NOT included.

## Setup

- Machine: {cpu}, {os.cpu_count()} logical cores, {platform.system()} {platform.release()}, Python
  {platform.python_version()}, onnxruntime {ort.__version__}. ArcFace provider: {d.get('arcface_provider')}.
- Input per attempt: 5 synthetic frames of **{w}x{h} JPEG q85** (= `CaptureSpec.max_width_px` 1280 at the
  kiosk's 1280x720 camera request), mean upload {np.mean([r['upload_bytes'] for r in runs]) / 1024:.0f} KiB,
  plus meta with a ~30 fps chroma series and the session's flash events.
- Frames: the public-domain NASA `astronaut` portrait (`edge/synth.py` `base_frame(size=({w}, {h}))`), face
  scaled with the frame height, with a simulated flash reflection. Gallery: 1 enrolled synthetic user
  (enrolment at {w}x{h}, ok = {ctx['enrolled']}); 1:N is one [N, 512] matrix product.
- Decisions during the measured run: {decisions}; reason codes: {codes}. These are NOT an accuracy
  result; synthetic frames only exercise the code paths (a STEP_UP from `RANDOM_CHALLENGE` is the random
  challenge at its configured rate and does not change the measured path, which ends at the first decision).
- Startup (spawn -> `/v1/health` 200, incl. model load, warm-up, PAD self-test): {ctx['startup_s']:.1f} s.
- Load average (1/5/15 min): before spawn {fmt_la(la['before_spawn'])}, before measured runs
  {fmt_la(la['before_runs'])}, after {fmt_la(la['after_runs'])}. The live edge, kiosk browser (MediaPipe,
  camera) and other agents share this laptop's CPU, so compare tables only at similar load.
"""
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    print(md)
    print(f"wrote {out}\nwrote {csv_path}\nscratch edge log: {ctx['log_path']}")


if __name__ == "__main__":
    main()
