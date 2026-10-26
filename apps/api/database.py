"""Database configuration and session management."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from api.utils.config import get_settings
from sqlalchemy import Connection, inspect, text
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

settings = get_settings()

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


# Columns added after the initial schema: (table, column, SQL type).
_ADDED_COLUMNS: tuple[tuple[str, str, str], ...] = (("findings", "remediation", "TEXT"),)


def _add_missing_columns(sync_conn: Connection) -> None:
    inspector = inspect(sync_conn)
    tables = set(inspector.get_table_names())
    for table, column, sql_type in _ADDED_COLUMNS:
        if table not in tables:
            continue
        existing = {col["name"] for col in inspector.get_columns(table)}
        if column not in existing:
            sync_conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}"))


async def upgrade_schema(conn: AsyncConnection) -> None:
    """Create missing tables and add columns introduced since the database was created.

    ``create_all`` never alters existing tables, so databases created by an older
    release would otherwise fail on queries touching the new columns.
    """
    await conn.run_sync(Base.metadata.create_all)
    await conn.run_sync(_add_missing_columns)


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
