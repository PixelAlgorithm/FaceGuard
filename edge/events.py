"""In-process SSE fan-out (GET /v1/events). Event types: "decision" (DecisionResponse + "eval"
tags or null) and "rendered" (kiosk-reported face-lock -> decision-rendered latency).

RBAC v2 D: stream() re-checks `authorized()` before every event and at every heartbeat (<= 15 s); when it turns
False (session expired / revoked / logged out, key revoked, events:read lost) the stream sends a final
`event: auth` and closes. F5: at most `max_subscribers` concurrent streams (has_capacity).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

EVENT_TYPES = ("decision", "rendered")
HEARTBEAT_S = 15.0
DEFAULT_MAX_SUBSCRIBERS = 16
AUTH_CLOSED_EVENT = 'event: auth\ndata: {"reason":"SESSION_ENDED"}\n\n'


def _always() -> bool:
    return True


class EventBus:
    def __init__(self, queue_size: int = 100, max_subscribers: int = DEFAULT_MAX_SUBSCRIBERS) -> None:
        self._subs: set[asyncio.Queue[str]] = set()
        self._size = queue_size
        self._max = max_subscribers

    @property
    def subscribers(self) -> int:
        return len(self._subs)

    def has_capacity(self) -> bool:
        """False when `max_subscribers` streams are live (GET /v1/events then answers 429)."""
        return len(self._subs) < self._max

    def publish(self, event: str, payload: dict[str, Any]) -> None:
        if event not in EVENT_TYPES:
            raise ValueError(f"unknown SSE event type {event!r}")
        msg = f"event: {event}\ndata: {json.dumps(payload, separators=(',', ':'), default=str)}\n\n"
        for q in list(self._subs):
            if q.full():
                with contextlib.suppress(asyncio.QueueEmpty):
                    q.get_nowait()  # drop the oldest event for a slow consumer
            q.put_nowait(msg)

    async def stream(self, is_disconnected: Callable[[], Awaitable[bool]],
                     authorized: Callable[[], bool] = _always,
                     heartbeat_s: float = HEARTBEAT_S) -> AsyncIterator[str]:
        q: asyncio.Queue[str] = asyncio.Queue(maxsize=self._size)
        self._subs.add(q)
        try:
            if not authorized():
                yield AUTH_CLOSED_EVENT
                return
            yield ": connected\n\n"
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=heartbeat_s)
                except TimeoutError:
                    if await is_disconnected():
                        break
                    if not authorized():
                        yield AUTH_CLOSED_EVENT
                        break
                    yield ": ping\n\n"
                    continue
                if not authorized():
                    yield AUTH_CLOSED_EVENT
                    break
                yield msg
        finally:
            self._subs.discard(q)
