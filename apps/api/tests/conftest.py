"""Pytest configuration."""

import ipaddress
from collections.abc import AsyncGenerator, Iterator
from pathlib import Path

import api.models.db_models  # noqa: F401  (populate Base.metadata)
import pytest
from api.database import Base, get_session
from api.utils import security
from api.utils.config import get_settings
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# A public address (example.com's), so a target passes the non-public address check.
PUBLIC_IP = ipaddress.ip_address("93.184.215.14")


@pytest.fixture(autouse=True)
def _public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """validate_target resolves every target: answer without the network (see ../../conftest.py)."""

    async def _resolve(hostname: str) -> list:
        return [PUBLIC_IP]

    monkeypatch.setattr(security, "_resolve", _resolve)


@pytest.fixture
def anyio_backend():
    """Use asyncio as the async backend."""
    return "asyncio"


@pytest.fixture
def allowed_domains(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Scope rules used by tests that start scans or check the scope."""
    rules = ["example.com", "*.staging.test"]
    monkeypatch.setenv("ALLOWED_DOMAINS", ",".join(rules))
    get_settings.cache_clear()
    yield rules
    get_settings.cache_clear()


@pytest.fixture
async def session_maker(tmp_path: Path) -> AsyncGenerator[async_sessionmaker[AsyncSession], None]:
    """A throwaway SQLite database, wired into the app's get_session dependency."""
    from api.main import app

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_session() -> AsyncGenerator[AsyncSession, None]:
        async with maker() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    yield maker
    app.dependency_overrides.pop(get_session, None)
    await engine.dispose()
