"""Cached dependency health for GET /v1/health (the edge heartbeat: must answer in milliseconds).

A background task probes Rekognition (DescribeCollection) and the store (GetItem / SELECT 1) every
HEALTH_REFRESH_S with a short timeout; the endpoint only reads the cached snapshot. The first probe at
startup also warms the TLS connection pool to Rekognition.
"""

from __future__ import annotations

import asyncio
import logging
import time

from .faces import FaceError, map_aws_error

log = logging.getLogger("hid.cloud.health")


def _status_of(exc: Exception) -> str:
    fe = exc if isinstance(exc, FaceError) else map_aws_error(exc)
    return "creds_expired" if fe.kind == "CREDS_EXPIRED" else "error"


class HealthMonitor:
    def __init__(self, faces, kv, *, refresh_s: float, store_backend: str, timeout_s: float = 2.0) -> None:
        self.faces = faces
        self.kv = kv
        self.refresh_s = refresh_s
        self.timeout_s = timeout_s
        self.store_backend = store_backend
        self.snapshot = {"rekognition": "unknown", "dynamodb": "unknown", "store": "unknown"}
        self.checked_at: float | None = None
        self._task: asyncio.Task | None = None

    async def probe_once(self) -> dict:
        snap: dict[str, str] = {}
        if getattr(self.faces, "name", "") == "disabled":
            snap["rekognition"] = "disabled"
        elif getattr(self.faces, "name", "") == "fake":
            snap["rekognition"] = "fake"
        else:
            try:
                await asyncio.wait_for(asyncio.to_thread(self.faces.ping), timeout=self.timeout_s)
                snap["rekognition"] = "ok"
            except TimeoutError:
                snap["rekognition"] = "timeout"
            except Exception as exc:
                snap["rekognition"] = _status_of(exc)
                log.warning("rekognition health: %s", snap["rekognition"])
        try:
            await asyncio.wait_for(asyncio.to_thread(self.kv.ping), timeout=self.timeout_s)
            store = "ok"
        except TimeoutError:
            store = "timeout"
        except Exception as exc:
            store = _status_of(exc)
            log.warning("store health: %s", store)
        snap["store"] = store
        snap["dynamodb"] = store if self.store_backend == "dynamodb" else "disabled"
        self.snapshot = snap
        self.checked_at = time.time()
        return snap

    async def _loop(self) -> None:
        while True:
            try:
                await self.probe_once()
            except Exception:  # never let the monitor die
                log.exception("health probe failed")
            await asyncio.sleep(self.refresh_s)

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._loop(), name="health-monitor")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: S110 - shutdown
                pass
            self._task = None
