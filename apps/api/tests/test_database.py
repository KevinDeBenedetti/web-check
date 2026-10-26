"""Tests for the startup schema upgrade."""

from pathlib import Path

import pytest
from api.database import upgrade_schema
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import create_async_engine


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
