"""Tests for the scan lifecycle: background runs, log streaming and scanner parsing."""

import asyncio
import json
import re
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

import pytest
from api.database import Base, get_session
from api.main import app
from api.models import CheckResult, Finding, ScanRequest
from api.routers import scans
from api.services import db_service
from api.services.docker_runner import unique_output_name
from api.services.log_streamer import LogStreamer
from api.services.nuclei import _parse_nuclei_output
from api.utils import security
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def session_maker(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """Isolated SQLite database wired into the scans router."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    @asynccontextmanager
    async def _session_context():
        async with maker() as session:
            yield session

    async def _get_session():
        async with maker() as session:
            yield session

    monkeypatch.setattr(scans, "get_session_context", _session_context)
    app.dependency_overrides[get_session] = _get_session
    yield maker
    app.dependency_overrides.pop(get_session, None)
    await engine.dispose()


@pytest.fixture
def streamer(monkeypatch: pytest.MonkeyPatch) -> LogStreamer:
    instance = LogStreamer(retention_seconds=60)
    monkeypatch.setattr(scans, "log_streamer", instance)
    return instance


@pytest.fixture(autouse=True)
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _resolve(hostname: str) -> list:
        return []

    monkeypatch.setattr(security, "_resolve", _resolve)


def _result(module: str, status: str = "success", findings: int = 0) -> CheckResult:
    return CheckResult(
        module=module,
        category="quick",
        target="https://example.com",
        duration_ms=1,
        status=status,  # ty: ignore[invalid-argument-type]
        findings=[Finding(severity="low", title=f"f{i}", description="d") for i in range(findings)],
    )


def _fake_runners(monkeypatch: pytest.MonkeyPatch, behaviours: dict[str, Any]) -> None:
    """Replace scanner coroutines: value is a CheckResult to return or an exception to raise."""

    def _make(module: str, behaviour: Any):
        async def _run(target: str, timeout: int) -> CheckResult:
            if isinstance(behaviour, Exception):
                raise behaviour
            return behaviour

        return _run

    monkeypatch.setattr(
        scans,
        "_module_runners",
        lambda scan_id: {m: _make(m, b) for m, b in behaviours.items()},
    )


async def _wait_for_background_scans() -> None:
    while scans._background_tasks:
        await asyncio.gather(*scans._background_tasks)


# ---------------------------------------------------------------------------
# ScanRequest
# ---------------------------------------------------------------------------


def test_scan_request_rejects_unknown_module() -> None:
    with pytest.raises(ValidationError):
        ScanRequest(target="https://example.com", modules=["nuclei", "rm -rf"])  # ty: ignore[invalid-argument-type]
    with pytest.raises(ValidationError):
        ScanRequest(target="https://example.com", modules=[])


# ---------------------------------------------------------------------------
# Background scan run
# ---------------------------------------------------------------------------


async def test_start_scan_runs_modules_and_persists(
    session_maker, streamer: LogStreamer, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_runners(
        monkeypatch,
        {"nuclei": _result("nuclei", findings=2), "nikto": RuntimeError("container missing")},
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/scans/start",
            json={"target": "https://example.com", "modules": ["nuclei", "nikto"]},
        )
        assert resp.status_code == 200
        scan_id = resp.json()["scan_id"]
        # Timestamp plus a random suffix: readable, and unique within a second.
        assert re.fullmatch(r"\d{8}-\d{6}-[0-9a-f]{4}", scan_id)
        assert resp.json()["target"] == "https://example.com"

        await _wait_for_background_scans()

        status = (await client.get(f"/api/scans/{scan_id}")).json()

    # One module succeeded → scan succeeded; the failing module is recorded, not dropped.
    assert status["status"] == "success"
    by_module = {r["module"]: r for r in status["results"]}
    assert by_module["nuclei"]["status"] == "success"
    assert len(by_module["nuclei"]["findings"]) == 2
    assert by_module["nikto"]["status"] == "error"
    assert "container missing" in by_module["nikto"]["error"]


async def test_scan_fails_when_every_module_fails(
    session_maker, streamer: LogStreamer, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_runners(monkeypatch, {"nuclei": _result("nuclei", status="timeout")})
    request = ScanRequest(target="https://example.com", modules=["nuclei"])
    async with session_maker() as session:
        await db_service.create_scan(session, "scan-1", request.target, ["nuclei"])
    streamer.register("scan-1")

    await scans._run_scans("scan-1", request.target, ["nuclei"], request.timeout)

    async with session_maker() as session:
        scan = await db_service.get_scan(session, "scan-1")
    assert scan is not None
    assert scan.status == "error"
    assert scan.completed_at is not None
    assert list(streamer._channels["scan-1"].history)[-1]["type"] == "complete"


async def test_scan_reaches_terminal_state_on_unexpected_error(
    session_maker, streamer: LogStreamer, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_runners(monkeypatch, {"nuclei": _result("nuclei")})

    async def _broken_save(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("disk full")

    monkeypatch.setattr(db_service, "save_scan_result", _broken_save)
    request = ScanRequest(target="https://example.com", modules=["nuclei"])
    async with session_maker() as session:
        await db_service.create_scan(session, "scan-2", request.target, ["nuclei"])
    streamer.register("scan-2")

    await scans._run_scans("scan-2", request.target, ["nuclei"], request.timeout)

    async with session_maker() as session:
        scan = await db_service.get_scan(session, "scan-2")
    assert scan is not None
    assert scan.status == "error"  # not stuck in "running"


async def test_fail_interrupted_scans(session_maker) -> None:
    async with session_maker() as session:
        await db_service.create_scan(session, "running-1", "https://example.com")
        await db_service.create_scan(session, "done-1", "https://example.com")
        await db_service.update_scan_status(session, "done-1", "success")

        assert await db_service.fail_interrupted_scans(session) == 1

        interrupted = await db_service.get_scan(session, "running-1")
        finished = await db_service.get_scan(session, "done-1")
        assert interrupted is not None and interrupted.status == "error"
        assert finished is not None and finished.status == "success"


async def test_logs_endpoint_unknown_scan_404(session_maker, streamer: LogStreamer) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        assert (await client.get("/api/scans/does-not-exist/logs")).status_code == 404


# ---------------------------------------------------------------------------
# LogStreamer
# ---------------------------------------------------------------------------


async def _collect(stream) -> list[dict[str, Any]]:
    events = []
    async for chunk in stream:
        if chunk.startswith("data: "):
            events.append(json.loads(chunk[len("data: ") :]))
    return events


async def test_late_subscriber_replays_history() -> None:
    streamer = LogStreamer(retention_seconds=60)
    streamer.register("s")
    await streamer.send_log("s", {"type": "info", "message": "one"})
    await streamer.send_log("s", {"type": "info", "message": "two"})
    await streamer.complete("s", "success")

    events = await asyncio.wait_for(_collect(streamer.subscribe("s")), timeout=2)

    assert [e["type"] for e in events] == ["connected", "info", "info", "complete"]
    assert events[-1]["status"] == "success"


async def test_live_subscriber_receives_new_logs() -> None:
    streamer = LogStreamer(retention_seconds=60)
    streamer.register("s")
    await streamer.send_log("s", {"type": "info", "message": "before"})

    collector = asyncio.create_task(_collect(streamer.subscribe("s")))
    await asyncio.sleep(0)  # let it subscribe
    await streamer.send_log("s", {"type": "info", "message": "after"})
    await streamer.complete("s")
    events = await asyncio.wait_for(collector, timeout=2)

    assert [e.get("message") for e in events[1:-1]] == ["before", "after"]
    assert not streamer._channels["s"].subscribers


async def test_untracked_scan_stream_ends_immediately() -> None:
    streamer = LogStreamer()
    events = await asyncio.wait_for(
        _collect(streamer.subscribe("old", finished_status="error")), timeout=2
    )
    assert [e["type"] for e in events] == ["connected", "complete"]
    assert events[-1]["status"] == "error"


async def test_logs_for_unregistered_scans_are_dropped_and_history_expires() -> None:
    streamer = LogStreamer(retention_seconds=0)
    await streamer.send_log("never-registered", {"type": "info"})
    assert not streamer.is_tracked("never-registered")

    streamer.register("s")
    await streamer.complete("s")
    await asyncio.sleep(0.01)
    assert not streamer.is_tracked("s")


# ---------------------------------------------------------------------------
# Scanners
# ---------------------------------------------------------------------------


def test_unique_output_names() -> None:
    names = {unique_output_name("nuclei", "json") for _ in range(100)}
    assert len(names) == 100
    assert all(n.startswith("nuclei_") and n.endswith(".json") for n in names)


def test_nuclei_cve_comes_from_classification_not_matched_url() -> None:
    findings = _parse_nuclei_output(
        [
            {
                "template-id": "apache-rce",
                "matched-at": "https://example.com/cgi-bin/x",
                "info": {
                    "name": "Apache RCE",
                    "severity": "critical",
                    "reference": ["https://nvd.nist.gov/x", "https://other"],
                    "classification": {"cve-id": ["cve-2021-41773"], "cvss-score": 9.8},
                },
            },
            {
                "template-id": "CVE-2023-12345",
                "matched-at": "https://example.com/",
                "info": {"name": "Templated CVE", "severity": "high"},
            },
            {
                "template-id": "tech-detect",
                "matched-at": "https://example.com/",
                "info": {"name": "Tech", "severity": "weird", "classification": None},
            },
        ]
    )

    assert findings[0].cve == "CVE-2021-41773"
    assert findings[0].cvss_score == 9.8
    assert findings[0].reference == "https://nvd.nist.gov/x"
    assert "https://example.com/cgi-bin/x" in findings[0].description
    assert findings[1].cve == "CVE-2023-12345"
    assert findings[2].cve is None
    assert findings[2].severity == "info"


async def test_zap_timeout_stops_spider_and_active_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    from api.services import zap_native

    calls: list[str] = []
    zap = SimpleNamespace(
        urlopen=lambda target: None,
        spider=SimpleNamespace(
            scan=lambda target: "1",
            status=lambda sid: "10",
            stop=lambda sid: calls.append("spider.stop"),
        ),
        ascan=SimpleNamespace(
            scan=lambda target: "2",
            status=lambda sid: "10",
            stop=lambda sid: calls.append("ascan.stop"),
        ),
        core=SimpleNamespace(alerts=lambda baseurl: []),
    )
    monkeypatch.setattr(zap_native, "_get_zap_client", lambda: zap)

    result = await zap_native.run_zap_scan("https://example.com", timeout=0)

    assert calls == ["spider.stop", "ascan.stop"]
    assert result.status == "timeout"
    assert result.data == {"alerts_count": 0, "partial": True}
