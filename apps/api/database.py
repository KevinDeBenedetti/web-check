"""Database configuration and session management."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from api.utils.config import get_settings
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

logger = structlog.get_logger()
settings = get_settings()

ALEMBIC_INI = Path(__file__).resolve().parent.parent / "alembic.ini"
INITIAL_REVISION = "1dd0c571c561"

# Ensure database directory exists
db_path = settings.database_path
db_path.parent.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite+aiosqlite:///{db_path}"

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False},
)

async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class for all database models."""

    pass


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for getting async database session.

    Yields:
        AsyncSession instance
    """
    async with async_session_maker() as session:
        yield session


@asynccontextmanager
async def get_session_context() -> AsyncGenerator[AsyncSession, None]:
    """
    Context manager for getting async database session.

    Yields:
        AsyncSession instance
    """
    async with async_session_maker() as session:
        yield session


def sync_database_url(db_path: Path | None = None) -> str:
    """Synchronous SQLAlchemy URL of the application database (used by Alembic)."""
    return f"sqlite:///{db_path or settings.database_path}"


def run_migrations(db_path: Path | None = None) -> None:
    """
    Upgrade the database schema to the latest Alembic revision (blocking).

    Databases created by the former ``Base.metadata.create_all()`` startup have the
    tables but no ``alembic_version``: they are stamped at the initial revision first
    so the upgrade does not try to recreate existing tables.
    """
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    url = sync_database_url(db_path)
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(ALEMBIC_INI.parent / "alembic"))
    config.attributes["configure_logger"] = False
    config.attributes["url"] = url

    sync_engine = create_engine(url)
    try:
        tables = set(inspect(sync_engine).get_table_names())
    finally:
        sync_engine.dispose()

    if "scans" in tables and "alembic_version" not in tables:
        logger.info("database_stamped_legacy_schema", revision=INITIAL_REVISION)
        command.stamp(config, INITIAL_REVISION)
    command.upgrade(config, "head")
