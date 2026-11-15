"""Snapshot of the edge's own dashboard aggregates + the decisions of given attempts -> eval/results/runs/<ts>/.

Read-only provenance tool for the operator-run eval: it only issues GETs (`/v1/health`, `/v1/mode`, `/v1/metrics`,
`GET /v1/attempt/{id}`; API.md 3.6, 3.9, 3.16). It never sets context, resets the limiter or changes the edge.
The snapshot is evidence that the CSV rows match what the edge itself counted; it is NOT the eval result (the
official numbers, with bounds, come from metrics.py on attempts.csv). Attempt responses are reduced to the same
whitelisted scalar fields capture.py writes (never images, crops, embeddings or names).

  # after a capture run (attempt ids of that run taken from attempts.csv)
  uv run python snapshot_metrics.py --attempts results/attempts.csv --run-id R-test-1
  # explicit ids, other edge
  uv run python snapshot_metrics.py --attempt-ids att_01J...,att_01J... --edge http://127.0.0.1:8000
  # dry run (no network) against the DUMMY fixture; never written into eval/results/
  uv run python snapshot_metrics.py --fixture tests/fixtures/edge_snapshot_DUMMY.json --out-root /tmp/snap

Writes <out-root>/<UTC ts>/: edge_metrics.json, edge_mode.json, edge_health.json, attempts.json, SNAPSHOT.md.

Auth (RBAC): `GET /v1/metrics` needs metrics:read, sent as `Authorization: Bearer $FG_EVAL_API_KEY` (evaluator key,
environment or project .env; never printed). Legacy ADMIN_TOKEN only with FG_ALLOW_LEGACY_ADMIN_TOKEN=1. A missing
credential or a 401/403 exits 5 with a clear error and writes nothing. The other routes are public (no credential
sent). --fixture runs need no credential.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import quote

import httpx

import capture as C
from evallib import RESULTS_DIR, THRESHOLDS_PATH
from evallib import auth as A
from evallib import config as ecfg
from evallib import io as eio
from evallib import schema as S

DEFAULT_EDGE = C.DEFAULT_EDGE
ATTEMPT_FIELDS = ("attempt_id", "decision", "stage", "reason_codes", "resolved_codes", "bio_result",
                  "schedule_result", "mode", "cache_state", "zone", "kiosk_id", "next_action_type", "scores",
                  "latency", "policy_version", "bundle_version", "liveness_result", "mask_ring", "signals")


class Source:
    """HTTP GETs against the edge, or canned responses from a DUMMY fixture (dry run)."""

    def __init__(self, edge: str, fixture: Path | None = None, cred: A.EdgeCredential | None = None):
        self.edge, self.cred = edge.rstrip("/"), cred
        self.fx = json.loads(fixture.read_text(encoding="utf-8")) if fixture else None
        self.calls: Counter = Counter()

    def get(self, path: str, authed: bool = False) -> tuple[int, dict | None]:
        """GET; `authed` sends the credential and raises evallib.auth.AuthFailure on 401/403."""
        if self.fx is not None:
            key = path.split("?")[0]
            if key.startswith("/v1/attempt/"):
                obj = (self.fx.get("attempts") or {}).get(key.rsplit("/", 1)[1])
            else:
                obj = self.fx.get(key.removeprefix("/v1/"))
            self.calls[f"fixture {key.split('/att_')[0]}:{200 if obj is not None else 404}"] += 1
            return (200, obj) if obj is not None else (404, None)
        try:
            headers = self.cred.headers() if authed and self.cred else {}
            r = httpx.get(self.edge + path, headers=headers, timeout=3.0)
        except (httpx.HTTPError, OSError) as e:
            self.calls[f"GET {path.split('/att_')[0]}:{type(e).__name__}"] += 1
            return 0, None
        self.calls[f"GET {path.split('/att_')[0]}:{r.status_code}"] += 1
        try:
            body = r.json()
        except ValueError:
            body = None
        if authed:
            A.raise_for_auth(r.status_code, "GET", path.split("?")[0], self.cred, body)
        obj = body if r.status_code == 200 else None
        return r.status_code, obj if isinstance(obj, dict) else None


def privacy_scan(obj, where: str = "") -> list[str]:
    """Forbidden keys (embedding / image / frame / ...) or blob-like strings anywhere in a JSON object."""
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if S.FORBIDDEN_KEY_RE.search(str(k)):
                out.append(f"{where}.{k}: forbidden key")
            else:
                out += privacy_scan(v, f"{where}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:2000]):
            out += privacy_scan(v, f"{where}[{i}]")
    elif isinstance(obj, str):
        msg = S.privacy_check_value(where, obj)
        if msg:
            out.append(msg)
    return out


REDACTED = "<redacted: privacy filter>"


def redact(obj):
    """Copy of `obj` with every forbidden-key subtree and blob-like string replaced by REDACTED.

    Same rules as privacy_scan, applied per value instead of per document, so a harmless metadata key such as
    `/v1/mode` `template_cache: {count, model, age_h}` no longer drops policy_version / policy_bars as well.
    Nothing that privacy_scan flags is ever persisted.
    """
    if isinstance(obj, dict):
        return {k: REDACTED if S.FORBIDDEN_KEY_RE.search(str(k)) else redact(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj[:2000]]
    if isinstance(obj, str) and S.privacy_check_value("", obj):
        return REDACTED
    return obj


def reduce_attempt(resp: dict) -> dict | None:
    ev = C.normalize(resp)
    if ev is None:
        return None
    return {k: ev.get(k) for k in ATTEMPT_FIELDS}


def ids_from_csv(path: Path, run_id: str | None) -> list[str]:
    _, rows = eio.read_csv(path)
    out = []
    for r in rows:
        if run_id and r.get("run_id") != run_id:
            continue
        aid = r.get("attempt_id") or ""
        if aid.startswith("att_"):
            out.append(aid)
            for part in (r.get("notes") or "").split(";"):  # recapture chain members
                part = part.strip()
                if part.startswith("chain:"):
                    out += [x for x in part[6:].split(">") if x.startswith("att_")]
    return list(dict.fromkeys(out))


def snapshot_md(meta: dict, metrics: dict | None, attempts: dict, csv_rows: dict[str, dict]) -> str:
    L = ["# Edge metrics snapshot", "",
         ("> Edge dashboard aggregates (`GET /v1/metrics`) + per-attempt decisions (`GET /v1/attempt/{id}`), "
          "captured read-only. **Provenance only - not an eval result.** Official numbers with 95% bounds come "
          "from `eval/metrics.py` on `attempts.csv`."), ""]
    if meta.get("dummy"):
        L += ["> **DUMMY fixture (dry run) - not a measurement.**", ""]
    origin = "fixture " + str(meta["fixture"]) if meta.get("fixture") else "HTTP"
    L += [f"- taken {meta['taken_at_utc']} by `{meta['command']}`", f"- edge `{meta['edge']}` (source: {origin})",
          f"- requests: {meta['calls']}", ""]
    L += ["Shipped configuration (thresholds.yaml):", ""] + ecfg.switch_lines(meta["switches"]) + [""]
    diff = meta.get("edge_config_diff") or []
    L.append("Edge vs thresholds.yaml (`GET /v1/mode` policy_bars): " + ("; ".join(diff) if diff else "consistent"))
    L.append("")
    if metrics:
        L += [(f"Edge `/v1/metrics`: attempts {metrics.get('attempts')}, decisions {metrics.get('decisions')}, "
               f"by_mode {metrics.get('by_mode')}"), ""]
        lat = metrics.get("latency_ms") or {}
        if lat:
            L += ["| edge latency key | p50 ms | p95 ms | n |", "|---|---|---|---|"]
            for k, v in lat.items():
                if isinstance(v, dict):
                    L.append(f"| {k} | {v.get('p50')} | {v.get('p95')} | {v.get('n')} |")
            L.append("")
    L += [(f"Attempts requested {meta['n_requested']}, found {meta['n_found']}, not found / not decided "
           f"{meta['n_missing']}."), ""]
    if attempts:
        L += ["| attempt_id | edge latest decision | CSV final decision | match | reason codes |",
              "|---|---|---|---|---|"]
        for aid, a in attempts.items():
            row = csv_rows.get(aid)
            csv_dec = row.get("decision") if row else "-"
            ok = ("-" if not row else "chain root (see CSV notes)" if "chain:" in (row.get("notes") or "")
                  else "yes" if row.get("decision") == a["decision"] else "**NO**")
            L.append(f"| `{aid}` | {a['decision']} | {csv_dec} | {ok} | {';'.join(a['reason_codes'])} |")
        L.append("")
    if meta.get("privacy_findings"):
        L += ["Privacy findings (values redacted):", ""] + [f"- {p}" for p in meta["privacy_findings"]] + [""]
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--edge", default=DEFAULT_EDGE)
    ap.add_argument("--attempts", type=Path, default=None, help="attempts.csv to take attempt ids from")
    ap.add_argument("--run-id", default=None, help="only this capture run's rows of --attempts")
    ap.add_argument("--attempt-ids", default="", help="comma-separated attempt ids")
    ap.add_argument("--since", default=None, help="passed to /v1/metrics?since=<iso>")
    ap.add_argument("--fixture", type=Path, default=None, help="dry run: canned responses (DUMMY), no network")
    ap.add_argument("--out-root", type=Path, default=RESULTS_DIR / "runs")
    ap.add_argument("--max-attempts", type=int, default=500)
    ap.add_argument("--allow-remote-edge", action="store_true",
                    help="allow a non-loopback edge (https only); credentials never go to remote plain http")
    ap.add_argument("--env-file", type=Path, default=A.DEFAULT_ENV_FILE,
                    help="fallback source of FG_EVAL_API_KEY (and of ADMIN_TOKEN with FG_ALLOW_LEGACY_ADMIN_TOKEN=1)")
    a = ap.parse_args(argv)

    dummy = a.fixture is not None
    eio.refuse_dummy_into_results([a.out_root], dummy)
    ids = [x.strip() for x in a.attempt_ids.split(",") if x.strip()]
    csv_rows: dict[str, dict] = {}
    if a.attempts:
        ids += ids_from_csv(a.attempts, a.run_id)
        csv_rows = {r["attempt_id"]: r for r in eio.read_csv(a.attempts)[1]}
    ids = list(dict.fromkeys(ids))[: a.max_attempts]

    try:
        if not dummy:
            A.check_edge_url(a.edge, a.allow_remote_edge)
        cred = None if dummy else A.load_credential(A.EVAL_KEY_ENV, a.env_file)
        src = Source(a.edge, a.fixture, cred)
        _, metrics = src.get("/v1/metrics" + (f"?since={quote(a.since, safe='')}" if a.since else ""), authed=True)
    except A.AuthFailure as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return A.EXIT_AUTH
    _, health = src.get("/v1/health")
    try:
        code, mode = src.get(A.MODE_DETAIL_PATH, authed=True)  # store:read; config cross-check fields
    except A.AuthFailure as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return A.EXIT_AUTH
    if code == 404:  # older edge (or fixture) without the detail route: public badge subset
        _, mode = src.get(A.PUBLIC_MODE_PATH)
    attempts: dict[str, dict] = {}
    missing: dict[str, int] = {}
    for aid in ids:
        code, resp = src.get(f"/v1/attempt/{aid}")
        red = reduce_attempt(resp) if resp else None
        if red is None:
            missing[aid] = code
        else:
            attempts[aid] = red
    findings = privacy_scan(metrics, "metrics") + privacy_scan(mode, "mode") + privacy_scan(health, "health")
    if findings:  # never persist a blob / forbidden key: redact the offending values, keep the finding
        metrics, mode, health = redact(metrics), redact(mode), redact(health)

    sw = ecfg.shipped_switches(eio.load_yaml(THRESHOLDS_PATH) or {}, THRESHOLDS_PATH)
    ts = eio.utc_now_iso(ms=False).replace("-", "").replace(":", "")
    out = a.out_root / (("DUMMY-" if dummy else "") + f"snapshot_{ts}")
    out.mkdir(parents=True, exist_ok=True)
    meta = {"taken_at_utc": eio.utc_now_iso(), "command": eio.command_line(), "edge": a.edge,
            "fixture": str(a.fixture) if a.fixture else None, "dummy": dummy,
            "edge_credential": cred.describe() if cred else None, "switches": sw,
            "edge_config_diff": ecfg.compare_with_edge(sw, mode), "calls": dict(src.calls),
            "n_requested": len(ids), "n_found": len(attempts), "n_missing": len(missing), "missing": missing,
            "attempts_csv": str(a.attempts) if a.attempts else None,
            "attempts_csv_sha256": eio.sha256_file(a.attempts) if a.attempts else None, "run_id": a.run_id,
            "privacy_findings": findings}
    eio.write_json(out / "edge_metrics.json", metrics)
    eio.write_json(out / "edge_mode.json", mode)
    eio.write_json(out / "edge_health.json", health)
    eio.write_json(out / "attempts.json", {"meta": meta, "attempts": attempts})
    (out / "SNAPSHOT.md").write_text(snapshot_md(meta, metrics, attempts, csv_rows), encoding="utf-8")
    mism = [k for k, v in attempts.items() if k in csv_rows and "chain:" not in (csv_rows[k].get("notes") or "")
            and csv_rows[k].get("decision") != v["decision"]]
    print(f"snapshot -> {out}  (attempts found {len(attempts)}/{len(ids)}; CSV decision mismatches {len(mism)}; "
          f"edge config diff {len(meta['edge_config_diff'])})")
    return 0 if metrics is not None else 4


if __name__ == "__main__":
    sys.exit(main())
