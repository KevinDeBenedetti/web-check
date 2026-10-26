"""Tests for the scan management endpoints and the scan orchestrator."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import pytest
from api.main import app
from api.models import CheckResult, Finding
from api.routers import scans
from api.services import db_service
from api.services.log_streamer import log_streamer
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

TARGET = "https://example.com"


def _result(module: str, titles: list[str], status: str = "success") -> CheckResult:
    return CheckResult(
        module=module,
        category="quick",
        target=TARGET,
        duration_ms=100,
        status=status,  # ty: ignore[invalid-argument-type]
        findings=[
            Finding(severity="medium", title=title, description="d", remediation=f"fix {title}")
            for title in titles
        ],
    )


async def _store_scan(
    maker: async_sessionmaker[AsyncSession], scan_id: str, results: list[CheckResult]
) -> None:
    async with maker() as session:
        await db_service.create_scan(session, scan_id, TARGET, [r.module for r in results])
        for result in results:
            await db_service.save_scan_result(session, scan_id, result)
        await db_service.update_scan_status(session, scan_id, "success")


@pytest.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "status_code"),
    [
        ({"target": "example.com"}, 400),
        ({"target": "https://not-allowed.org"}, 403),
        ({"target": TARGET, "modules": ["unknown"]}, 400),
        ({"target": TARGET, "profile": "unknown"}, 400),
    ],
)
async def test_start_scan_rejects_invalid_requests(
    allowed_domains: list[str], client: AsyncClient, payload: dict, status_code: int
) -> None:
    response = await client.post("/api/scans/start", json=payload)
    assert response.status_code == status_code


@pytest.mark.asyncio
async def test_start_scan_with_profile(
    allowed_domains: list[str],
    session_maker: async_sessionmaker[AsyncSession],
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple] = []

    async def fake_run_scans(*args) -> None:
        calls.append(args)

    monkeypatch.setattr(scans, "_run_scans", fake_run_scans)
    response = await client.post("/api/scans/start", json={"target": TARGET, "profile": "quick"})

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "running"
    assert data["modules"] == ["headers", "dns", "testssl"]
    assert calls == [(data["scan_id"], TARGET, ["headers", "dns", "testssl"], 300)]


@pytest.mark.asyncio
async def test_scan_findings_are_deduplicated(
    session_maker: async_sessionmaker[AsyncSession], client: AsyncClient
) -> None:
    await _store_scan(
        session_maker, "scan-a", [_result("headers", ["HSTS"]), _result("nikto", ["HSTS", "x"])]
    )

    response = await client.get("/api/scans/scan-a/findings")

    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["score"] == 92
    assert [(f["title"], f["sources"]) for f in data["findings"]] == [
        ("HSTS", ["headers", "nikto"]),
        ("x", ["nikto"]),
    ]
    assert data["findings"][0]["remediation"] == "fix HSTS"


@pytest.mark.asyncio
async def test_get_scan_includes_score_and_modules(
    session_maker: async_sessionmaker[AsyncSession], client: AsyncClient
) -> None:
    await _store_scan(session_maker, "scan-b", [_result("headers", ["a", "b"])])

    data = (await client.get("/api/scans/scan-b")).json()

    assert data["modules"] == ["headers"]
    assert data["score"] == 92
    assert data["severity_counts"]["medium"] == 2
    assert data["completed_at"] is not None


@pytest.mark.asyncio
async def test_compare_scans(
    session_maker: async_sessionmaker[AsyncSession], client: AsyncClient
) -> None:
    await _store_scan(session_maker, "base", [_result("headers", ["kept", "fixed", "fixed2"])])
    await _store_scan(session_maker, "head", [_result("headers", ["kept", "new"])])

    response = await client.get("/api/scans/base/compare/head")

    assert response.status_code == 200
    data = response.json()
    assert [f["title"] for f in data["new"]] == ["new"]
    assert [f["title"] for f in data["fixed"]] == ["fixed", "fixed2"]
    assert [f["title"] for f in data["unchanged"]] == ["kept"]
    assert data["score_delta"] == 4


@pytest.mark.asyncio
async def test_compare_unknown_scan_returns_404(
    session_maker: async_sessionmaker[AsyncSession], client: AsyncClient
) -> None:
    await _store_scan(session_maker, "only", [])
    response = await client.get("/api/scans/only/compare/missing")
    assert response.status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fmt", "media_type", "extension"),
    [
        ("json", "application/json", "json"),
        ("markdown", "text/markdown; charset=utf-8", "md"),
        ("sarif", "application/sarif+json", "sarif"),
    ],
)
async def test_export_scan(
    session_maker: async_sessionmaker[AsyncSession],
    client: AsyncClient,
    fmt: str,
    media_type: str,
    extension: str,
) -> None:
    await _store_scan(session_maker, "scan-c", [_result("headers", ["a"])])

    response = await client.get("/api/scans/scan-c/export", params={"format": fmt})

    assert response.status_code == 200
    assert response.headers["content-type"] == media_type
    assert response.headers["content-disposition"] == (
        f'attachment; filename="web-check-scan-c.{extension}"'
    )


@pytest.mark.asyncio
async def test_export_rejects_unknown_format(
    session_maker: async_sessionmaker[AsyncSession], client: AsyncClient
) -> None:
    await _store_scan(session_maker, "scan-d", [])
    response = await client.get("/api/scans/scan-d/export", params={"format": "pdf"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_run_scans_stores_each_result_and_survives_module_errors(
    session_maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def ok(target: str, timeout: int) -> CheckResult:
        return _result("headers", ["finding"])

    async def boom(target: str, timeout: int) -> CheckResult:
        raise RuntimeError("container not running")

    @asynccontextmanager
    async def session_context() -> AsyncGenerator[AsyncSession, None]:
        async with session_maker() as session:
            yield session

    monkeypatch.setattr(scans, "_module_runners", lambda scan_id: {"headers": ok, "nikto": boom})
    monkeypatch.setattr("api.database.get_session_context", session_context)
    async with session_maker() as session:
        await db_service.create_scan(session, "run-1", TARGET, ["headers", "nikto"])

    await scans._run_scans("run-1", TARGET, ["headers", "nikto"], 30)

    async with session_maker() as session:
        scan = await db_service.get_scan(session, "run-1")
        stored = await db_service.get_scan_results(session, "run-1")
    assert scan is not None and scan.status == "success"
    assert [(r.module, r.status) for r, _ in stored] == [("headers", "success"), ("nikto", "error")]
    assert stored[1][0].error == "container not running"
    events = [e.get("event") for e in log_streamer.history("run-1")]
    assert events.count("module_completed") == 2
