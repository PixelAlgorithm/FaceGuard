"""In-process SSE fan-out (GET /v1/events). Event types: "decision" (DecisionResponse + "eval"
tags or null) and "rendered" (kiosk-reported face-lock -> decision-rendered latency)."""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator
from typing import Any

EVENT_TYPES = ("decision", "rendered")


class EventBus:
    def __init__(self, queue_size: int = 100) -> None:
        self._subs: set[asyncio.Queue[str]] = set()
        self._size = queue_size

    @property
    def subscribers(self) -> int:
        return len(self._subs)

    def publish(self, event: str, payload: dict[str, Any]) -> None:
        if event not in EVENT_TYPES:
            raise ValueError(f"unknown SSE event type {event!r}")
        msg = f"event: {event}\ndata: {json.dumps(payload, separators=(',', ':'), default=str)}\n\n"
        for q in list(self._subs):
            if q.full():
                with contextlib.suppress(asyncio.QueueEmpty):
                    q.get_nowait()  # drop the oldest event for a slow consumer
            q.put_nowait(msg)

    async def stream(self, is_disconnected, heartbeat_s: float = 15.0) -> AsyncIterator[str]:
        q: asyncio.Queue[str] = asyncio.Queue(maxsize=self._size)
        self._subs.add(q)
        try:
            yield ": connected\n\n"
            while True:
                try:
                    yield await asyncio.wait_for(q.get(), timeout=heartbeat_s)
                except TimeoutError:
                    if await is_disconnected():
                        break
                    yield ": ping\n\n"
        finally:
            self._subs.discard(q)
