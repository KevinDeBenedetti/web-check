"""Service for streaming logs in real-time via SSE."""

import asyncio
import json
from collections import defaultdict
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger()


class LogStreamer:
    """Manage log streaming for multiple scan sessions."""

    def __init__(self) -> None:
        """Initialize log streamer."""
        self._queues: dict[str, list[asyncio.Queue[dict[str, Any]]]] = defaultdict(list)
        self._scan_status: dict[str, str] = {}

    async def send_log(self, scan_id: str, log_data: dict[str, Any]) -> None:
        """
        Send log to all subscribers of a scan.

        Args:
            scan_id: Scan identifier
            log_data: Log message with metadata
        """
        if scan_id not in self._queues:
            logger.debug("no_subscribers", scan_id=scan_id)
            return

        log_entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "scan_id": scan_id,
            **log_data,
        }

        # Send to all connected clients for this scan
        for queue in self._queues[scan_id]:
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
