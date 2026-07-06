"""Debounced WireGuard "apply".

Peer changes on pfSense don't take effect until applied. Rather than firing an
apply per change, we coalesce rapid changes into a single apply after a short
quiet window. This is a single background task shared by the whole app.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from .pfsense import PfSenseAPIError, PfSenseClient

logger = logging.getLogger("apply")


class ApplyManager:
    def __init__(self, client: PfSenseClient, debounce_seconds: float = 2.0):
        self._client = client
        self._debounce = debounce_seconds
        self._pending = asyncio.Event()
        self._task: asyncio.Task | None = None
        self.last_applied_at: datetime | None = None
        self.last_error: str | None = None

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="wg-apply-worker")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    def request(self) -> None:
        """Signal that an apply is needed soon (debounced)."""
        self._pending.set()

    async def _run(self) -> None:
        while True:
            await self._pending.wait()
            # Quiet window: everything requested within `debounce` collapses into one.
            await asyncio.sleep(self._debounce)
            self._pending.clear()
            try:
                await self._client.apply()
                self.last_applied_at = datetime.now(timezone.utc)
                self.last_error = None
                logger.info("WireGuard changes applied")
            except PfSenseAPIError as e:
                self.last_error = str(e)
                logger.warning("apply failed: %s", e)
                # Re-arm so a later change (or retry) will try again.
                self._pending.set()
                await asyncio.sleep(min(self._debounce * 2, 10))
