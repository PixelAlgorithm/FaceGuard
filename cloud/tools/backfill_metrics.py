"""One-shot CloudWatch backfill after the Synthetic-dimension redeploy (NOT run yet; lead schedules the redeploy).

Why: CloudWatch data points are immutable, so the dashboard switches to series carrying Synthetic="false".
Points emitted before the redeploy have no Synthetic dimension; this tool re-publishes the REAL (non-synthetic)
ledger history with Synthetic=false at the original received_at minute, so dashboards show real traffic only.

    cloud/.venv/bin/python -m cloud.tools.backfill_metrics --cutover 2026-11-14T12:00:00Z          # plan (prints)
    cloud/.venv/bin/python -m cloud.tools.backfill_metrics --cutover 2026-11-14T12:00:00Z --apply  # publish once

--cutover = when the new server started serving (records/alerts at or after it were already emitted with the
dimension). Idempotent: a marker item (hid_state pk=backfill) is written with a conditional put; a second
--apply refuses. PutMetricData accepts timestamps up to 14 days old.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from datetime import datetime

MARKER_NS, MARKER_KEY = "backfill", "metrics-synthetic-dim-v1"


def minute(ts: str) -> str:
    return ts[:16] + ":00Z"


def plan(kv, cutover: str) -> tuple[Counter, Counter, Counter]:
    decisions, items, alerts = Counter(), Counter(), Counter()
    for key, it in kv.list("decisions"):
        rec = str(it.get("received_at") or "")
        if "#conflict#" in key or it.get("synthetic") or not rec or rec >= cutover:
            continue
        decisions[(minute(rec), it.get("decision"), it.get("mode"))] += 1
        items[(minute(rec), "accepted")] += 1
    for _, a in kv.list("alerts"):
        rec = str(a.get("raised_at") or "")
        if a.get("synthetic") or not rec or rec >= cutover:
            continue
        alerts[(minute(rec), a.get("alert"))] += 1
    return decisions, items, alerts


def datums(decisions: Counter, items: Counter, alerts: Counter) -> list[dict]:
    def d(name: str, ts: str, value: float, **dims: str) -> dict:
        return {"MetricName": name, "Timestamp": datetime.fromisoformat(ts.replace("Z", "+00:00")),
                "Value": float(value), "Unit": "Count",
                "Dimensions": [{"Name": "Service", "Value": "hid-cloud"},
                               *[{"Name": k, "Value": v} for k, v in dims.items()],
                               {"Name": "Synthetic", "Value": "false"}]}

    out = [d("Decisions", ts, n, Decision=str(dec), Mode=str(mode)) for (ts, dec, mode), n in sorted(decisions.items())]
    out += [d("SyncItems", ts, n, Status=st) for (ts, st), n in sorted(items.items())]
    out += [d("SyncAlerts", ts, n, Alert=str(al)) for (ts, al), n in sorted(alerts.items())]
    return out


def publish(cw, kv, data: list[dict], namespace: str = "HIDKiosk") -> int:
    if not kv.put_if_absent(MARKER_NS, MARKER_KEY, {"datums": len(data)}):
        raise SystemExit("backfill already done (marker present) - refusing to double count")
    for i in range(0, len(data), 500):
        cw.put_metric_data(Namespace=namespace, MetricData=data[i:i + 500])
    return len(data)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cutover", required=True, help="ISO UTC, e.g. 2026-11-14T12:00:00Z")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--profile", default="hid-sandbox")
    ap.add_argument("--region", default="us-east-1")
    a = ap.parse_args(argv)
    import boto3

    from cloud.app.services.kv import DynamoKV

    sess = boto3.session.Session(profile_name=a.profile, region_name=a.region)
    kv = DynamoKV(sess.client("dynamodb"), users_table="hid_users", decisions_table="hid_decisions",
                  state_table="hid_state")
    dec, items, alerts = plan(kv, a.cutover)
    data = datums(dec, items, alerts)
    print(f"real decisions={sum(dec.values())} accepted-items={sum(items.values())} alerts={sum(alerts.values())} "
          f"-> {len(data)} datums (Synthetic=false) before {a.cutover}")
    if not a.apply:
        print("PLAN only (re-run with --apply after the redeploy)")
        return 0
    print("published", publish(sess.client("cloudwatch"), kv, data), "datums")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
