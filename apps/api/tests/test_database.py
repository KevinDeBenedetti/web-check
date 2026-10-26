"""Tests for the startup schema upgrade."""

from pathlib import Path

import pytest
from api.database import upgrade_schema
from api.services import db_service
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


@pytest.mark.asyncio
async def test_upgrade_schema_adds_remediation_to_existing_database(tmp_path: Path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'old.db'}")
    async with engine.begin() as conn:
        # Table as created by releases before remediation was stored
        await conn.execute(
            text(
                "CREATE TABLE findings (id INTEGER PRIMARY KEY, scan_result_id INTEGER NOT NULL, "
                "scan_id VARCHAR(50) NOT NULL, severity VARCHAR(20) NOT NULL, "
                "title VARCHAR(500) NOT NULL, description TEXT NOT NULL, reference VARCHAR(500), "
                "cve VARCHAR(50), cvss_score FLOAT)"
            )
        )

    async with engine.begin() as conn:
        await upgrade_schema(conn)
        # Running it twice must be harmless
        await upgrade_schema(conn)
        columns = await conn.run_sync(
            lambda sync_conn: {c["name"] for c in inspect(sync_conn).get_columns("findings")}
        )
        tables = await conn.run_sync(lambda sync_conn: set(inspect(sync_conn).get_table_names()))
    await engine.dispose()

    assert "remediation" in columns
    assert {"scans", "scan_results", "findings"} <= tables


@pytest.mark.asyncio
async def test_fail_interrupted_scans(session_maker: async_sessionmaker[AsyncSession]) -> None:
    async with session_maker() as session:
        await db_service.create_scan(session, "left-running", "https://example.com")
        await db_service.create_scan(session, "done", "https://example.com")
        await db_service.update_scan_status(session, "done", "success")

        assert await db_service.fail_interrupted_scans(session) == 1

        interrupted = await db_service.get_scan(session, "left-running")
        done = await db_service.get_scan(session, "done")
    assert interrupted is not None and interrupted.status == "error"
    assert interrupted.completed_at is not None
    assert done is not None and done.status == "success"
