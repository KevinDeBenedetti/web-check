"""Tests for the SSE log streamer."""

import asyncio
import json

import pytest
from api.services.log_streamer import LogStreamer


async def _collect(streamer: LogStreamer, scan_id: str) -> list[dict]:
    events = []
    async for chunk in streamer.subscribe(scan_id):
        if chunk.startswith("data: "):
            events.append(json.loads(chunk.removeprefix("data: ")))
    return events


@pytest.mark.asyncio
async def test_late_subscriber_replays_history_and_stops_on_complete() -> None:
    streamer = LogStreamer()
    await streamer.send_log("s1", {"type": "info", "message": "first"})
    await streamer.send_log("s1", {"type": "success", "message": "second"})
    await streamer.send_log("s1", {"type": "complete", "message": "done"})

    events = await asyncio.wait_for(_collect(streamer, "s1"), timeout=2)

    assert [e["type"] for e in events] == ["connected", "info", "success", "complete"]


@pytest.mark.asyncio
async def test_live_subscriber_receives_new_logs_once() -> None:
    streamer = LogStreamer()
    await streamer.send_log("s2", {"type": "info", "message": "before"})

    task = asyncio.create_task(_collect(streamer, "s2"))
    await asyncio.sleep(0.05)
    await streamer.send_log("s2", {"type": "info", "message": "after"})
    await streamer.send_log("s2", {"type": "complete", "message": "done"})
    events = await asyncio.wait_for(task, timeout=2)

    assert [e.get("message") for e in events[1:]] == ["before", "after", "done"]


@pytest.mark.asyncio
async def test_history_is_bounded_per_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("api.services.log_streamer.MAX_TRACKED_SCANS", 2)
    streamer = LogStreamer()
    for scan_id in ("a", "b", "c"):
        await streamer.send_log(scan_id, {"type": "info", "message": scan_id})
    assert streamer.history("a") == []
    assert [e["message"] for e in streamer.history("c")] == ["c"]
