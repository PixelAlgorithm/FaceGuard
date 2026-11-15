"""CSV / config / provenance helpers (stdlib + pyyaml only)."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from . import PROJECT_DIR, RESULTS_DIR


def utc_now_iso(ms: bool = True) -> str:
    t = datetime.now(UTC)
    return t.isoformat(timespec="milliseconds" if ms else "seconds").replace("+00:00", "Z")


def sha256_file(path: Path) -> str | None:
    p = Path(path)
    if not p.exists():
        return None
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def read_csv(path: Path) -> tuple[list[str], list[dict]]:
    p = Path(path)
    if not p.exists():
        return [], []
    with p.open(newline="", encoding="utf-8") as f:
        rd = csv.DictReader(f)
        rows = [dict(r) for r in rd]
        return list(rd.fieldnames or []), rows


def append_csv_row(path: Path, columns: list[str], row: dict) -> None:
    """Append one row; write the header if the file is new. Refuses a header mismatch (no silent corruption)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    new = not p.exists() or p.stat().st_size == 0
    if not new:
        with p.open(newline="", encoding="utf-8") as f:
            header = next(csv.reader(f), [])
        if header != columns:
            raise RuntimeError(
                f"{p}: existing header does not match the current schema; refusing to append. "
                "Start a new file (--out) instead of editing results by hand."
            )
    with p.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=columns, extrasaction="raise")
        if new:
            w.writeheader()
        w.writerow({c: ("" if row.get(c) is None else row.get(c)) for c in columns})
        f.flush()
        os.fsync(f.fileno())


def write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({c: ("" if r.get(c) is None else r.get(c)) for c in columns})
    tmp.replace(p)


def load_yaml(path: Path) -> dict:
    with Path(path).open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def thresholds_for_mode(th: dict, mode: str) -> dict:
    """ONLINE = base; OFFLINE = deep_merge(base, offline.overrides) (config/thresholds.yaml header)."""
    if str(mode).upper() == "OFFLINE":
        return deep_merge(th, (th.get("offline") or {}).get("overrides") or {})
    return th


def git_info(path: Path = PROJECT_DIR) -> dict:
    try:
        rev = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True,
                             timeout=5, check=False)
        if rev.returncode != 0:
            return {"available": False, "commit": None, "note": "not a git repository - sha256 hashes used instead"}
        dirty = subprocess.run(["git", "-C", str(path), "status", "--porcelain"], capture_output=True, text=True,
                               timeout=5, check=False)
        return {"available": True, "commit": rev.stdout.strip(), "dirty": bool(dirty.stdout.strip())}
    except (OSError, subprocess.SubprocessError):
        return {"available": False, "commit": None, "note": "git not available"}


def host_info() -> dict:
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": sys.version.split()[0],
        "node": platform.node(),
    }


def command_line() -> str:
    return " ".join([Path(sys.executable).name] + sys.argv)


def write_json(path: Path, obj: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, sort_keys=False, default=_json_default, allow_nan=True) + "\n",
                   encoding="utf-8")
    tmp.replace(p)


def _json_default(o: Any) -> Any:
    try:
        import numpy as np

        if isinstance(o, np.integer):
            return int(o)
        if isinstance(o, np.floating):
            return float(o)
        if isinstance(o, np.ndarray):
            return o.tolist()
    except ImportError:  # pragma: no cover
        pass
    if isinstance(o, Path):
        return str(o)
    if isinstance(o, set):
        return sorted(o)
    raise TypeError(f"not JSON serialisable: {type(o)}")


def is_inside(path: Path, parent: Path) -> bool:
    try:
        Path(path).resolve().relative_to(Path(parent).resolve())
        return True
    except ValueError:
        return False


def refuse_dummy_into_results(out_paths: list[Path], dummy: bool) -> None:
    """Hard guard: DUMMY fixtures must never be written into eval/results/."""
    if not dummy:
        return
    for p in out_paths:
        if is_inside(p, RESULTS_DIR):
            raise SystemExit(f"refusing to write DUMMY-derived output into {RESULTS_DIR} ({p}); use --out-dir /tmp/...")


class RunManifest:
    """eval/results/runs/<run_id>.json - provenance for every number (command, inputs, counts)."""

    def __init__(self, run_id: str, kind: str, runs_dir: Path, extra: dict | None = None):
        self.path = Path(runs_dir) / f"{run_id}.json"
        self.data: dict = {
            "run_id": run_id,
            "kind": kind,
            "started_at_utc": utc_now_iso(),
            "ended_at_utc": None,
            "command": command_line(),
            "cwd": os.getcwd(),
            "host": host_info(),
        }
        if self.path.exists():  # resumed run: keep history
            try:
                old = json.loads(self.path.read_text(encoding="utf-8"))
                self.data["previous_sessions"] = old.get("previous_sessions", []) + [
                    {k: old.get(k) for k in ("started_at_utc", "ended_at_utc", "command", "counts")}
                ]
            except (OSError, ValueError):
                pass
        self.data.update(extra or {})
        self.save()

    def update(self, **kw: Any) -> None:
        self.data.update(kw)
        self.save()

    def close(self, **kw: Any) -> None:
        self.data["ended_at_utc"] = utc_now_iso()
        self.update(**kw)

    def save(self) -> None:
        write_json(self.path, self.data)
