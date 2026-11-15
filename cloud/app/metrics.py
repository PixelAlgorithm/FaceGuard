"""CloudWatch metrics in Embedded Metric Format (EMF), namespace HIDKiosk.

Sinks (METRICS_SINK):
  emf_stdout       one EMF JSON line per datum on stdout (Lambda / CloudWatch agent ingest it as metrics)
  put_metric_data  background thread batches values -> PutMetricData every 20 s (EC2, no agent needed);
                   Values/Counts arrays keep raw distributions, so p50/p95 work in CloudWatch
  memory           kept in a list (tests, /v1/admin/metrics)
  none             dropped
Dimensions are low-cardinality only (Route, Status, Decision, Mode, Alert, Result). Never images/PII.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from collections import defaultdict

log = logging.getLogger("hid.cloud.metrics")

UNITS = {"Milliseconds", "Count", "None"}


def emf_record(namespace: str, name: str, value: float, unit: str, dims: dict[str, str],
               service: str = "hid-cloud") -> dict:
    d = {"Service": service, **dims}
    return {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [{
                "Namespace": namespace,
                "Dimensions": [sorted(d.keys())],
                "Metrics": [{"Name": name, "Unit": unit}],
            }],
        },
        **d,
        name: value,
    }


class Metrics:
    def __init__(self, sink: str, namespace: str = "HIDKiosk", cw_client=None, flush_s: float = 20.0) -> None:
        self.sink = sink
        self.namespace = namespace
        self.records: list[dict] = []
        self._cw = cw_client
        self._lock = threading.Lock()
        self._agg: dict[tuple, dict[float, int]] = defaultdict(lambda: defaultdict(int))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_error: str | None = None
        if sink == "put_metric_data":
            self._thread = threading.Thread(target=self._loop, args=(flush_s,), daemon=True, name="cw-flush")
            self._thread.start()

    def put(self, name: str, value: float, unit: str = "Milliseconds", **dims: str) -> None:
        if self.sink == "none":
            return
        dims = {k: str(v) for k, v in dims.items() if v is not None}
        if self.sink == "emf_stdout":
            sys.stdout.write(json.dumps(emf_record(self.namespace, name, value, unit, dims)) + "\n")
            sys.stdout.flush()
        elif self.sink == "memory":
            with self._lock:
                self.records.append({"name": name, "value": value, "unit": unit, "dims": dims})
                if len(self.records) > 5000:
                    self.records = self.records[-2500:]
        elif self.sink == "put_metric_data":
            key = (name, unit, tuple(sorted(dims.items())))
            with self._lock:
                self._agg[key][round(float(value), 1)] += 1

    def count(self, name: str, n: int = 1, **dims: str) -> None:
        self.put(name, n, "Count", **dims)

    def _loop(self, flush_s: float) -> None:
        while not self._stop.wait(flush_s):
            self.flush()

    def flush(self) -> None:
        if self.sink != "put_metric_data" or self._cw is None:
            return
        with self._lock:
            agg, self._agg = self._agg, defaultdict(lambda: defaultdict(int))
        data = []
        for (name, unit, dims), hist in agg.items():
            items = list(hist.items())
            for i in range(0, len(items), 150):  # PutMetricData: <= 150 distinct values per datum
                chunk = items[i:i + 150]
                data.append({
                    "MetricName": name,
                    "Dimensions": [{"Name": "Service", "Value": "hid-cloud"}]
                    + [{"Name": k, "Value": v} for k, v in dims],
                    "Values": [v for v, _ in chunk],
                    "Counts": [float(c) for _, c in chunk],
                    "Unit": unit,
                })
        for i in range(0, len(data), 500):
            try:
                self._cw.put_metric_data(Namespace=self.namespace, MetricData=data[i:i + 500])
                self.last_error = None
            except Exception as exc:  # metrics must never break the API
                self.last_error = type(exc).__name__
                log.warning("put_metric_data failed: %s", type(exc).__name__)

    def close(self) -> None:
        self._stop.set()
        self.flush()
