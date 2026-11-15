"""SC1/SC2 gate runner -> eval/results/scenarios.csv, one row per docs/POLICY_TEST_CASES.md gate ID per run.

Backends (expected values always parsed from docs/POLICY_TEST_CASES.md by scenarios/cases.py):
  pytest  runs the edge (and cloud, if cloud/.venv exists) pytest suites in their own venvs with JUnit XML and maps
          test cases to IDs by name (test_policy_case[S01], test_S28_...). PASS = every referencing test passed;
          FAIL = any failed/errored; NOT_RUN = no test references the ID (or only skipped).
  store   D01-D03 on the edge offline store: raw file has no plaintext JSON payload, no user ids / display names /
          JPEG markers; GET /v1/admin/store records use only whitelisted keys with 2-dp scores.
  api     X02 / X04 against the running edge: POST /v1/admin/mode force OFFLINE, poll GET /v1/mode; then AUTO and
          wait for ONLINE with sync_queue_depth 0. Toggles the live kiosk -> requires --yes-toggle-mode.

Usage (from eval/):
  uv run python scenarios/run_scenarios.py --backend pytest            # records results/scenarios.csv
  uv run python scenarios/run_scenarios.py --backend pytest --dry-run  # print only
  uv run python scenarios/run_scenarios.py --backend store
  uv run python scenarios/run_scenarios.py --backend api --yes-toggle-mode
Statuses are only ever derived from what actually ran; nothing is assumed to pass.
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
from evallib import io as eio
from evallib import schema as S
from scenarios import cases as C

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


def check_admin_store(edge: str, token: str | None) -> dict[str, tuple[str, str]]:
    if not token:
        return {k: ("NOT_RUN", "no ADMIN_TOKEN") for k in ("D01", "D02")}
    try:
        r = httpx.get(edge.rstrip("/") + "/v1/admin/store", headers={"X-Admin-Token": token}, timeout=5)
        r.raise_for_status()
        obj = r.json()
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

def run_api(cases: dict, run_id: str, edge: str, token: str | None) -> list[dict]:
    if not token:
        return [row(run_id, cases[c], "api", "NOT_RUN", "no ADMIN_TOKEN") for c in ("X02", "X04") if c in cases]
    h = {"X-Admin-Token": token}
    out = []

    def mode():
        return httpx.get(edge + "/v1/mode", timeout=3).json()

    try:
        t0 = time.time()
        httpx.post(edge + "/v1/admin/mode", json={"force": "OFFLINE"}, headers=h, timeout=3).raise_for_status()
        m = {}
        while time.time() - t0 < 20:
            m = mode()
            if m.get("mode") == "OFFLINE":
                break
            time.sleep(0.5)
        dt = time.time() - t0
        st = "PASS" if m.get("mode") == "OFFLINE" else "FAIL"
        out.append(row(run_id, cases["X02"], "api", st, f"forced via POST /v1/admin/mode (simulated misses); mode "
                       f"{m.get('mode')} after {dt:.1f} s", m.get("mode", "")))
        t1 = time.time()
        httpx.post(edge + "/v1/admin/mode", json={"force": "AUTO"}, headers=h, timeout=3).raise_for_status()
        while time.time() - t1 < 120:
            m = mode()
            if m.get("mode") == "ONLINE" and not m.get("sync_queue_depth"):
                break
            time.sleep(1.0)
        ok = m.get("mode") == "ONLINE" and not m.get("sync_queue_depth")
        out.append(row(run_id, cases["X04"], "api", "PASS" if ok else "FAIL",
                       f"after AUTO: mode {m.get('mode')}, sync_queue_depth {m.get('sync_queue_depth')} in "
                       f"{time.time() - t1:.1f} s", m.get("mode", "")))
    except (httpx.HTTPError, ValueError, KeyError) as e:
        out.append(row(run_id, cases.get("X02") or {"id": "X02", "challenge": "SC2"}, "api", "ERROR",
                       f"{type(e).__name__}: {e}"))
    return out


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
    a = ap.parse_args(argv)

    cases = C.parse(a.cases)
    run_id = a.run_id or f"SC-{a.backend}-" + eio.utc_now_iso(ms=False).replace("-", "").replace(":", "")
    if S.is_dummy_run(run_id) and eio.is_inside(a.out, RESULTS_DIR):
        raise SystemExit("refusing DUMMY run ids in eval/results/")
    from capture import load_admin_token

    token = load_admin_token()
    meta: dict = {}
    if a.backend == "pytest":
        rows, meta = run_pytest(cases, run_id, [s for s in a.suites.split(",") if s in SUITES], a.timeout)
    elif a.backend == "store":
        files = [Path(p) for p in glob.glob(a.store_glob, recursive=True) if not p.endswith(("-wal", "-shm"))]
        st, detail = inspect_store(files)
        rows = [row(run_id, cases["D03"], "store", st, detail)]
        for cid, (s2, d2) in check_admin_store(a.edge, token).items():
            rows.append(row(run_id, cases[cid], "store+admin", s2, d2))
        meta = {"files": [str(f) for f in files]}
    else:
        if not a.yes_toggle_mode:
            raise SystemExit("--backend api toggles the live kiosk OFFLINE/AUTO; add --yes-toggle-mode")
        rows = run_api(cases, run_id, a.edge.rstrip("/"), token)
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
