"""Service for streaming logs in real-time via SSE."""

import asyncio
import json
from collections import OrderedDict, defaultdict, deque
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger()

# Log entries kept per scan so late subscribers can replay them.
HISTORY_SIZE = 500
# Number of scans whose history is kept in memory.
MAX_TRACKED_SCANS = 50


class LogStreamer:
    """Manage log streaming for multiple scan sessions."""

    def __init__(self) -> None:
        """Initialize log streamer."""
        self._queues: dict[str, list[asyncio.Queue[dict[str, Any]]]] = defaultdict(list)
        self._scan_status: dict[str, str] = {}
        self._history: OrderedDict[str, deque[dict[str, Any]]] = OrderedDict()

    def _remember(self, scan_id: str, log_entry: dict[str, Any]) -> None:
        history = self._history.get(scan_id)
        if history is None:
            history = deque(maxlen=HISTORY_SIZE)
            self._history[scan_id] = history
            while len(self._history) > MAX_TRACKED_SCANS:
                self._history.popitem(last=False)
        history.append(log_entry)

    def history(self, scan_id: str) -> list[dict[str, Any]]:
        """Return the log entries recorded so far for a scan."""
        return list(self._history.get(scan_id, ()))

    async def send_log(self, scan_id: str, log_data: dict[str, Any]) -> None:
        """
        Send log to all subscribers of a scan.

        Args:
            scan_id: Scan identifier
            log_data: Log message with metadata
        """
        log_entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "scan_id": scan_id,
            **log_data,
        }
        self._remember(scan_id, log_entry)

        # Send to all connected clients for this scan
        for queue in self._queues.get(scan_id, []):
            try:
                await queue.put(log_entry)
            except Exception as e:
                logger.error("failed_to_send_log", scan_id=scan_id, error=str(e))

    async def subscribe(self, scan_id: str) -> AsyncGenerator[str, None]:
        """
        Subscribe to logs for a specific scan.

        Args:
            scan_id: Scan identifier

        Yields:
            SSE formatted log messages
        """
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._queues[scan_id].append(queue)
        # Snapshot before the first yield: later entries arrive through the queue.
        backlog = self.history(scan_id)

        logger.info(
            "client_subscribed", scan_id=scan_id, total_subscribers=len(self._queues[scan_id])
        )

        try:
            # Send initial connection message
            initial_message = {
                "type": "connected",
                "scan_id": scan_id,
                "timestamp": datetime.now(UTC).isoformat(),
                "message": "Connecté au stream de logs",
            }
            yield f"data: {json.dumps(initial_message)}\n\n"

            # Replay what happened before this client connected
            for log_entry in backlog:
                yield f"data: {json.dumps(log_entry)}\n\n"
                if log_entry.get("type") == "complete":
                    return

            # Stream logs
            while True:
                try:
                    log_entry = await asyncio.wait_for(queue.get(), timeout=30.0)

                    # Check if scan is complete
                    if log_entry.get("type") == "complete":
                        yield f"data: {json.dumps(log_entry)}\n\n"
                        break

                    yield f"data: {json.dumps(log_entry)}\n\n"

                except TimeoutError:
                    # Send keepalive
                    yield ": keepalive\n\n"
                except Exception as e:
                    logger.error("stream_error", scan_id=scan_id, error=str(e))
                    break

        finally:
            # Cleanup
            self._queues[scan_id].remove(queue)
            logger.info(
                "client_unsubscribed",
                scan_id=scan_id,
                remaining_subscribers=len(self._queues[scan_id]),
            )

            if not self._queues[scan_id]:
                del self._queues[scan_id]

    def mark_scan_complete(self, scan_id: str) -> None:
        """Mark scan as complete and notify all subscribers."""
        self._scan_status[scan_id] = "complete"
        asyncio.create_task(
            self.send_log(
                scan_id,
                {
                    "type": "complete",
                    "message": "Scan completed",
                },
            )
        )


# Global instance
log_streamer = LogStreamer()
