"""Service for streaming logs in real-time via SSE."""

import asyncio
import json
from collections import deque
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger()

# Log entries kept per scan so late subscribers can replay what they missed.
HISTORY_SIZE = 500
# How long a finished scan's history stays available for replay.
RETENTION_SECONDS = 300.0


@dataclass
class _ScanChannel:
    history: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=HISTORY_SIZE))
    subscribers: list[asyncio.Queue[dict[str, Any]]] = field(default_factory=list)
    complete: bool = False


class LogStreamer:
    """Manage log streaming for multiple scan sessions."""

    def __init__(self, retention_seconds: float = RETENTION_SECONDS) -> None:
        """Initialize log streamer."""
        self._channels: dict[str, _ScanChannel] = {}
        self._retention_seconds = retention_seconds

    def register(self, scan_id: str) -> None:
        """Start recording logs for a scan (call before the scan begins)."""
        self._channels.setdefault(scan_id, _ScanChannel())

    def is_tracked(self, scan_id: str) -> bool:
        """Return True if logs for this scan are being recorded or still retained."""
        return scan_id in self._channels

    def history(self, scan_id: str) -> list[dict[str, Any]]:
        """Return the log entries recorded so far for a scan (empty if untracked)."""
        channel = self._channels.get(scan_id)
        return list(channel.history) if channel else []

    async def send_log(self, scan_id: str, log_data: dict[str, Any]) -> None:
        """
        Record a log entry and send it to all subscribers of a scan.

        Logs for scans that were never registered (e.g. one-off quick endpoints) are dropped.

        Args:
            scan_id: Scan identifier
            log_data: Log message with metadata
        """
        channel = self._channels.get(scan_id)
        if channel is None:
            logger.debug("log_for_untracked_scan", scan_id=scan_id)
            return

        log_entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "scan_id": scan_id,
            **log_data,
        }
        channel.history.append(log_entry)
        for queue in channel.subscribers:
            queue.put_nowait(log_entry)

    async def complete(self, scan_id: str, status: str = "success") -> None:
        """Mark a scan as complete, notify subscribers and schedule history cleanup."""
        channel = self._channels.get(scan_id)
        if channel is None or channel.complete:
            return
        await self.send_log(
            scan_id, {"type": "complete", "status": status, "message": "Scan completed"}
        )
        channel.complete = True
        asyncio.get_running_loop().call_later(self._retention_seconds, self._forget, scan_id)

    def _forget(self, scan_id: str) -> None:
        channel = self._channels.get(scan_id)
        if channel is not None and not channel.subscribers:
            del self._channels[scan_id]
        elif channel is not None:
            # Still streaming: retry later.
            asyncio.get_running_loop().call_later(self._retention_seconds, self._forget, scan_id)

    async def subscribe(
        self, scan_id: str, finished_status: str | None = None
    ) -> AsyncGenerator[str, None]:
        """
        Subscribe to logs for a specific scan.

        Replays the scan's recorded history, then streams live entries until the
        scan completes.

        Args:
            scan_id: Scan identifier
            finished_status: Final status from the database, used when the scan is no
                longer tracked in memory (finished long ago, or API restarted)

        Yields:
            SSE formatted log messages
        """

        def _sse(entry: dict[str, Any]) -> str:
            return f"data: {json.dumps(entry)}\n\n"

        yield _sse(
            {
                "type": "connected",
                "scan_id": scan_id,
                "timestamp": datetime.now(UTC).isoformat(),
                "message": "Connected to log stream",
            }
        )

        channel = self._channels.get(scan_id)
        if channel is None:
            yield _sse(
                {
                    "type": "complete",
                    "scan_id": scan_id,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "status": finished_status or "unknown",
                    "message": "Scan logs are no longer available",
                }
            )
            return

        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        # Snapshot history and subscribe atomically (no await in between).
        backlog = list(channel.history)
        channel.subscribers.append(queue)
        logger.info("client_subscribed", scan_id=scan_id, subscribers=len(channel.subscribers))

        try:
            for entry in backlog:
                yield _sse(entry)
                if entry.get("type") == "complete":
                    return

            while True:
                try:
                    entry = await asyncio.wait_for(queue.get(), timeout=30.0)
                except TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                yield _sse(entry)
                if entry.get("type") == "complete":
                    return
        finally:
            channel.subscribers.remove(queue)
            logger.info(
                "client_unsubscribed", scan_id=scan_id, subscribers=len(channel.subscribers)
            )


# Global instance
log_streamer = LogStreamer()
