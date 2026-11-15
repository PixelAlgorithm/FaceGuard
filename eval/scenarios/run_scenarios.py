"""SC1/SC2 gate runner -> eval/results/scenarios.csv, one row per docs/POLICY_TEST_CASES.md gate ID per run.

Backends (expected values always parsed from docs/POLICY_TEST_CASES.md by scenarios/cases.py):
  pytest  runs the edge (and cloud, if cloud/.venv exists) pytest suites in their own venvs with JUnit XML and maps
          test cases to IDs by name (test_policy_case[S01], test_S28_...). PASS = every referencing test passed;
          FAIL = any failed/errored; NOT_RUN = no test references the ID (or only skipped).
  store   D01-D03 on the edge offline store: raw file has no plaintext JSON payload, no user ids / display names /
          JPEG markers; GET /v1/admin/store records use only whitelisted keys with 2-dp scores.
  api     X06 (and X07 when records are queued) against the running edge: POST /v1/admin/mode force OFFLINE,
          poll GET /v1/mode (OFFLINE + forced, immediately); then AUTO and wait for ONLINE with sync_queue_depth 0.
          X06 from the badge alone is partial: NOT_RUN when the badge is right, FAIL when it is wrong (next-attempt
          OFFLINE_MODE and heartbeats are not exercised). An operator's existing forced OFFLINE is never touched
          (X06/X07 NOT_RUN). X02 / X04 (heartbeat misses, offline backlog sync) are NOT exercised here. Toggles
          the live kiosk -> requires --yes-toggle-mode.

Usage (from eval/):
  uv run python scenarios/run_scenarios.py --backend pytest            # records results/scenarios.csv
  uv run python scenarios/run_scenarios.py --backend pytest --dry-run  # print only
  uv run python scenarios/run_scenarios.py --backend store
  uv run python scenarios/run_scenarios.py --backend api --yes-toggle-mode
Statuses are only ever derived from what actually ran; nothing is assumed to pass.

Auth (RBAC): the store+admin and api backends send `Authorization: Bearer $FG_OPS_API_KEY` (an API key with roles
security_officer + evaluator: store:read, mode:switch; environment or project .env; never printed). The legacy
ADMIN_TOKEN is used only with FG_ALLOW_LEGACY_ADMIN_TOKEN=1. A 401/403 exits 5 with a clear error and writes no
rows. --backend api without a credential exits 5; --backend store without one records D01/D02 as NOT_RUN.
The api backend forces OFFLINE with a reason and max_minutes (the edge auto-reverts) and always restores AUTO.
"""

from __future__ import annotations

import argparse
import glob
import json
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

EVAL = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EVAL))

import httpx

from evallib import PROJECT_DIR, RESULTS_DIR
from evallib import auth as A
from evallib import io as eio
from evallib import schema as S
from scenarios import cases as C

FORCE_OFFLINE_MAX_MINUTES = 10  # edge auto-reverts a forced OFFLINE after this, even if this tool dies
MODE_REASON = "eval X06/X07 (scenarios/run_scenarios.py)"
MODE_IMMEDIATE_S = 3.0  # X06: forced OFFLINE shows on GET /v1/mode "immediately" (no heartbeat wait)
MODE_OFFLINE_WAIT_S = 20.0
MODE_SYNC_WAIT_S = 120.0
ADMIN_TIMEOUT_S = 3.0  # per admin/mode request
OPERATOR_FORCED_DETAIL = "edge already forced OFFLINE by an operator; not toggled"
ID_IN_NAME = re.compile(r"(?<![A-Za-z0-9])([A-Z]\d{2})(?![0-9])")
SUITES = {  # name -> (python, cwd)
    "edge": (PROJECT_DIR / "edge" / ".venv" / "bin" / "python", PROJECT_DIR / "edge"),
    "cloud": (PROJECT_DIR / "cloud" / ".venv" / "bin" / "python", PROJECT_DIR / "cloud"),
}
D01_KEYS = {"attempt_id", "seq", "kiosk_id", "zone", "ts_utc", "user_id", "candidate_user_id", "decision",
            "reason_codes", "resolved_codes", "scores", "fallback", "schedule_version", "cache_state", "mode",
            "prev_hash", "record_hash"}


def row(run_id: str, case: dict, backend: str, status: str, detail: str, obs_dec: str = "", obs_codes: str = "") -> dict:
    return {"run_id": run_id, "ts_utc": eio.utc_now_iso(), "scenario_id": case["id"], "challenge": case["challenge"],
            "title": (case.get("setup") or "")[:120], "backend": backend, "status": status,
            "expected": C.expected_text(case)[:200], "observed_decision": obs_dec, "observed_codes": obs_codes,
            "detail": detail[:300], "policy_case": case["id"]}


# --------------------------------------------------------------------- pytest backend

def parse_junit(xml_path: Path) -> list[tuple[str, str, str]]:
    """[(name, classname, outcome pass|fail|skip)]"""
    out = []
    for tc in ET.parse(xml_path).getroot().iter("testcase"):
        kids = {c.tag for c in tc}
        outcome = "fail" if kids & {"failure", "error"} else "skip" if "skipped" in kids else "pass"
        out.append((tc.get("name", ""), tc.get("classname", ""), outcome))
    return out


def map_outcomes(tests: list[tuple[str, str, str]], suite: str) -> dict[str, list[tuple[str, str]]]:
    by_id: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for name, _cls, outcome in tests:
        for cid in set(ID_IN_NAME.findall(name)):
            by_id[cid].append((f"{suite}:{name}", outcome))
    return by_id


def status_for(outcomes: list[tuple[str, str]]) -> tuple[str, str]:
    if not outcomes:
        return "NOT_RUN", "no test references this ID"
    c = Counter(o for _, o in outcomes)
    names = ", ".join(n for n, _ in outcomes[:3])
    if c["fail"]:
        bad = ", ".join(n for n, o in outcomes if o == "fail")[:200]
        return "FAIL", f"{c['fail']} failed of {len(outcomes)}: {bad}"
    if c["pass"]:
        return "PASS", f"{c['pass']}/{len(outcomes)} passed ({names})"
    return "NOT_RUN", f"only skipped tests ({names})"


def run_pytest(cases: dict, run_id: str, suites: list[str], timeout_s: int) -> tuple[list[dict], dict]:
    combined: dict[str, list[tuple[str, str]]] = defaultdict(list)
    meta: dict = {}
    for suite in suites:
        py, cwd = SUITES[suite]
        if not py.exists():
            meta[suite] = {"status": "skipped", "reason": f"{py} not found"}
            continue
        with tempfile.TemporaryDirectory() as td:
            xml = Path(td) / "junit.xml"
            t0 = time.time()
            proc = subprocess.run([str(py), "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={xml}"],
                                  cwd=cwd, capture_output=True, text=True, timeout=timeout_s, check=False)
            tests = parse_junit(xml) if xml.exists() else []
        tail = (proc.stdout or "").strip().splitlines()[-1:] or [""]
        meta[suite] = {"returncode": proc.returncode, "seconds": round(time.time() - t0, 1), "tests": len(tests),
                       "outcomes": dict(Counter(o for *_, o in tests)), "summary_line": tail[0]}
        for cid, outs in map_outcomes(tests, suite).items():
            combined[cid] += outs
    rows = []
    for cid in C.gate_ids(cases):
        st, detail = status_for(combined.get(cid, []))
        rows.append(row(run_id, cases[cid], "pytest:" + "+".join(s for s in suites if SUITES[s][0].exists()), st,
                        detail))
    return rows, meta


# --------------------------------------------------------------------- store backend

def _forbidden_strings() -> list[bytes]:
    bundle = json.loads((PROJECT_DIR / "config" / "schedule.example.json").read_text(encoding="utf-8"))
    out = [b"JFIF", b"\xff\xd8\xff", b'"embedding"']
    for uid, u in (bundle.get("users") or {}).items():
        out.append(uid.encode())
        if u.get("display"):
            out.append(str(u["display"]).encode())
    return out


def inspect_store(files: list[Path]) -> tuple[str, str]:
    if not files:
        return "NOT_RUN", "no offline store file found"
    problems, notes = [], []
    for f in files:
        raw = f.read_bytes()
        hits = [s.decode(errors="replace") for s in _forbidden_strings() if s in raw]
        if hits:
            problems.append(f"{f.name}: plaintext {hits[:4]}")
        try:
            con = sqlite3.connect(f"file:{f}?mode=ro", uri=True)
            tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
            notes.append(f"{f.name}: tables {tables}")
            for t in tables:
                cols = [r[1] for r in con.execute(f"pragma table_info('{t}')")]
                if any(S.FORBIDDEN_KEY_RE.search(c) for c in cols):
                    problems.append(f"{t}: forbidden column in {cols}")
                if "payload" in cols:
                    for (p,) in con.execute(f"select payload from '{t}' limit 50"):
                        try:
                            json.loads(p if isinstance(p, str) else bytes(p).decode())
                            problems.append(f"{t}.payload is plaintext JSON")
                            break
                        except (ValueError, UnicodeDecodeError):
                            pass
                for c in cols:
                    big = con.execute(f"select count(*) from '{t}' where length(\"{c}\") > 4096").fetchone()[0]
                    if big:
                        problems.append(f"{t}.{c}: {big} values > 4 KB")
            con.close()
        except sqlite3.DatabaseError as e:
            notes.append(f"{f.name}: not sqlite ({e})")
    return ("FAIL", "; ".join(problems)[:300]) if problems else ("PASS", "; ".join(notes)[:300])


def _checked(r: httpx.Response, cred: A.EdgeCredential) -> httpx.Response:
    """AuthFailure on 401/403 (never a silent fallback), else raise_for_status."""
    try:
        body = r.json()
    except ValueError:
        body = None
    A.raise_for_auth(r.status_code, r.request.method, r.request.url.path, cred, body)
    return r.raise_for_status()


def check_admin_store(edge: str, cred: A.EdgeCredential | None) -> dict[str, tuple[str, str]]:
    if cred is None:
        return {k: ("NOT_RUN", f"no {A.OPS_KEY_ENV}") for k in ("D01", "D02")}
    try:
        obj = _checked(httpx.get(edge.rstrip("/") + "/v1/admin/store", headers=cred.headers(), timeout=5), cred).json()
    except (httpx.HTTPError, ValueError) as e:
        return {k: ("NOT_RUN", f"GET /v1/admin/store failed: {type(e).__name__}") for k in ("D01", "D02")}
    recs = obj if isinstance(obj, list) else (obj.get("records") or obj.get("items") or [])
    if not recs:
        return {k: ("NOT_RUN", "store has no records yet") for k in ("D01", "D02")}
    extra = sorted({k for rec in recs for k in rec if k not in D01_KEYS})
    blob = [k for rec in recs for k, v in rec.items() if isinstance(v, str) and S.LONG_BLOB_RE.search(v)]
    d01 = ("FAIL", f"non-whitelisted keys {extra} / blobs {blob[:3]}") if (extra or blob) else (
        "PASS", f"{len(recs)} records, keys within the D01 whitelist")
    bad = []
    for rec in recs:
        for k, v in (rec.get("scores") or {}).items():
            if isinstance(v, list) or (isinstance(v, float) and round(v, 2) != v):
                bad.append(k)
    d02 = ("FAIL", f"scores not 2-dp / arrays: {sorted(set(bad))[:5]}") if bad else ("PASS", "all scores <= 2 dp")
    return {"D01": d01, "D02": d02}


# --------------------------------------------------------------------- api backend

def _force_mode(edge: str, cred: A.EdgeCredential, force: str) -> None:
    body = {"force": force, "reason": MODE_REASON} | (
        {"max_minutes": FORCE_OFFLINE_MAX_MINUTES} if force == "OFFLINE" else {})
    _checked(httpx.post(edge + "/v1/admin/mode", json=body, headers=cred.headers(), timeout=ADMIN_TIMEOUT_S),
             cred)


def _get_mode(edge: str) -> dict:
    obj = httpx.get(edge + "/v1/mode", timeout=ADMIN_TIMEOUT_S).json()
    if not isinstance(obj, dict):
        raise TypeError("GET /v1/mode did not return a JSON object")
    return obj


def _wait_mode(edge: str, done, timeout_s: float, poll_s: float) -> tuple[dict, float]:
    t0, m = time.time(), {}
    while time.time() - t0 < timeout_s:
        m = _get_mode(edge)
        if done(m):
            break
        time.sleep(poll_s)
    return m, time.time() - t0


def _x06_row(run_id: str, case: dict, m: dict, dt: float) -> dict:
    """X06 from the GET /v1/mode badge only. A correct badge is a partial result (NOT_RUN), never PASS: the
    case also expects OFFLINE_MODE on the very next attempt and heartbeats in the background, which this
    backend does not exercise (it never drives attempts on the live kiosk). A wrong or slow badge is FAIL."""
    badge = f"mode {m.get('mode')}, forced {m.get('forced')} after {dt:.1f} s (immediate = <= {MODE_IMMEDIATE_S} s)"
    ok = m.get("mode") == "OFFLINE" and m.get("forced") is True and dt <= MODE_IMMEDIATE_S
    if not ok:
        return row(run_id, case, "api", "FAIL", f"POST /v1/admin/mode force OFFLINE: badge wrong: {badge}",
                   m.get("mode", ""))
    return row(run_id, case, "api", "NOT_RUN",
               f"partial: GET /v1/mode badge ok ({badge}); next-attempt OFFLINE_MODE and background heartbeats "
               "not exercised by the api backend", m.get("mode", ""))


def _x07_row(run_id: str, case: dict, edge: str, queued: int) -> dict:
    if queued <= 0:
        return row(run_id, case, "api", "NOT_RUN", "sync queue empty when AUTO was set (X07 needs queued "
                   "offline records); AUTO restored")
    m, dt = _wait_mode(edge, lambda m: m.get("mode") == "ONLINE" and not m.get("sync_queue_depth"),
                       MODE_SYNC_WAIT_S, 1.0)
    ok = m.get("mode") == "ONLINE" and not m.get("sync_queue_depth") and m.get("forced") is not True
    return row(run_id, case, "api", "PASS" if ok else "FAIL",
               f"after AUTO with {queued} queued: mode {m.get('mode')}, sync_queue_depth "
               f"{m.get('sync_queue_depth')} in {dt:.1f} s", m.get("mode", ""))


def _restore_auto(edge: str, cred: A.EdgeCredential) -> None:
    """Best effort: never leave the kiosk forced OFFLINE (the edge also auto-reverts after max_minutes)."""
    try:
        _force_mode(edge, cred, "AUTO")
    except (httpx.HTTPError, A.AuthFailure) as e:
        print(f"WARNING: could not restore AUTO ({type(e).__name__}); edge reverts after "
              f"{FORCE_OFFLINE_MAX_MINUTES} min", file=sys.stderr)


def run_api(cases: dict, run_id: str, edge: str, cred: A.EdgeCredential) -> list[dict]:
    """X06 (forced OFFLINE badge, partial: NOT_RUN when correct, FAIL when wrong) and, only when records were
    queued at AUTO time, X07 (SYNCING, then ONLINE once the queue drains). The forced toggle never exercises
    X02 (three heartbeat misses) or X04 (sync of an offline backlog + bundle install), so those IDs are left to
    the pytest backend (NOT_RUN here). Case rows are resolved and the current mode read before the kiosk is
    touched: an operator's existing forced OFFLINE is left alone (no POST at all). Once the OFFLINE POST has
    been sent, AUTO is always restored (finally), even if that POST timed out after being applied."""
    x06, x07 = cases["X06"], cases["X07"]
    if _get_mode(edge).get("forced") is True:
        print(f"WARNING: {OPERATOR_FORCED_DETAIL}; the api backend did not toggle the kiosk", file=sys.stderr)
        return [row(run_id, c, "api", "NOT_RUN", OPERATOR_FORCED_DETAIL) for c in (x06, x07)]
    out: list[dict] = []
    forced = False
    try:
        forced = True  # set BEFORE the POST: the edge may apply the force and still time out the reply
        _force_mode(edge, cred, "OFFLINE")
        m, dt = _wait_mode(edge, lambda m: m.get("mode") == "OFFLINE", MODE_OFFLINE_WAIT_S, 0.5)
        out.append(_x06_row(run_id, x06, m, dt))
        queued = int(m.get("sync_queue_depth") or 0)
        _force_mode(edge, cred, "AUTO")
        forced = False
        out.append(_x07_row(run_id, x07, edge, queued))
    except (httpx.HTTPError, ValueError, TypeError) as e:
        out.append(row(run_id, x07 if out else x06, "api", "ERROR", f"{type(e).__name__}: {e}"))
    finally:
        if forced:
            _restore_auto(edge, cred)
    return out


def _credential(backend: str, env_file: Path) -> A.EdgeCredential | None:
    """Ops credential for the backends that call admin routes; None when not needed or (store) not set."""
    if backend == "pytest":
        return None
    try:
        return A.load_credential(A.OPS_KEY_ENV, env_file)
    except A.AuthFailure:
        if backend == "api":
            raise
        print(f"WARNING: no {A.OPS_KEY_ENV}: D01/D02 recorded as NOT_RUN", file=sys.stderr)
        return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", choices=["pytest", "store", "api"], required=True)
    ap.add_argument("--cases", type=Path, default=C.DOC)
    ap.add_argument("--out", type=Path, default=RESULTS_DIR / "scenarios.csv")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--suites", default="edge,cloud")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--edge", default="http://127.0.0.1:8000")
    ap.add_argument("--store-glob", default=str(PROJECT_DIR / "edge" / "data" / "**" / "*.sqlite*"))
    ap.add_argument("--yes-toggle-mode", action="store_true", help="required for --backend api (toggles the kiosk)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--allow-remote-edge", action="store_true",
                    help="allow a non-loopback edge (https only); credentials never go to remote plain http")
    ap.add_argument("--env-file", type=Path, default=A.DEFAULT_ENV_FILE,
                    help="fallback source of FG_OPS_API_KEY (and of ADMIN_TOKEN with FG_ALLOW_LEGACY_ADMIN_TOKEN=1)")
    a = ap.parse_args(argv)

    cases = C.parse(a.cases)
    run_id = a.run_id or f"SC-{a.backend}-" + eio.utc_now_iso(ms=False).replace("-", "").replace(":", "")
    if S.is_dummy_run(run_id) and eio.is_inside(a.out, RESULTS_DIR):
        raise SystemExit("refusing DUMMY run ids in eval/results/")
    try:
        return _run_backend(a, cases, run_id)
    except A.AuthFailure as e:
        print(f"ERROR: {e}\nnothing written", file=sys.stderr)
        return A.EXIT_AUTH


def _run_backend(a: argparse.Namespace, cases: dict, run_id: str) -> int:
    if a.backend == "api" and not a.yes_toggle_mode:
        raise SystemExit("--backend api toggles the live kiosk OFFLINE/AUTO; add --yes-toggle-mode")
    if a.backend != "pytest":
        A.check_edge_url(a.edge, a.allow_remote_edge)
    cred = _credential(a.backend, a.env_file)
    meta: dict = {"edge_credential": cred.describe() if cred else None}
    if a.backend == "pytest":
        rows, pmeta = run_pytest(cases, run_id, [s for s in a.suites.split(",") if s in SUITES], a.timeout)
        meta |= pmeta
    elif a.backend == "store":
        files = [Path(p) for p in glob.glob(a.store_glob, recursive=True) if not p.endswith(("-wal", "-shm"))]
        st, detail = inspect_store(files)
        rows = [row(run_id, cases["D03"], "store", st, detail)]
        for cid, (s2, d2) in check_admin_store(a.edge, cred).items():
            rows.append(row(run_id, cases[cid], "store+admin", s2, d2))
        meta["files"] = [str(f) for f in files]
    else:
        if cred is None:  # unreachable: _credential raises for api; kept explicit (no assert in tools)
            raise A.AuthFailure(f"no {A.OPS_KEY_ENV}")
        rows = run_api(cases, run_id, a.edge.rstrip("/"), cred)
    c = Counter((r["challenge"], r["status"]) for r in rows)
    for r in rows:
        print(f"  {r['scenario_id']:4s} {r['challenge']} {r['status']:8s} {r['detail'][:110]}")
    print(f"{run_id}: {dict(sorted(c.items()))}")
    if a.dry_run:
        print("(dry run - nothing written)")
        return 0
    for r in rows:
        eio.append_csv_row(a.out, S.SCENARIO_COLUMNS, r)
    eio.RunManifest(run_id, f"scenarios-{a.backend}", a.out.parent / "runs", {
        "out": str(a.out), "cases_doc": str(a.cases), "cases_sha256": eio.sha256_file(a.cases), "meta": meta,
        "counts": {f"{k[0]}/{k[1]}": v for k, v in sorted(c.items())}}).close()
    print(f"appended {len(rows)} rows to {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
