"""Tests for Alembic migrations and version consistency."""

import json
import tomllib
from pathlib import Path

import api
import api.models.db_models  # noqa: F401  (populate Base.metadata)
import cli
import my_check
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from api.database import ALEMBIC_INI, Base, run_migrations
from sqlalchemy import create_engine, inspect, text

REPO_ROOT = Path(__file__).resolve().parents[3]


def _head_revision() -> str:
    from alembic.config import Config

    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(ALEMBIC_INI.parent / "alembic"))
    head = ScriptDirectory.from_config(config).get_current_head()
    assert head is not None
    return head


def _current_revision(db_path: Path) -> str | None:
    engine = create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as conn:
            return MigrationContext.configure(conn).get_current_revision()
    finally:
        engine.dispose()


def test_migrations_create_schema_on_fresh_database(tmp_path: Path) -> None:
    db = tmp_path / "fresh.db"
    run_migrations(db)

    assert _current_revision(db) == _head_revision()
    engine = create_engine(f"sqlite:///{db}")
    try:
        assert {"scans", "scan_results", "findings"} <= set(inspect(engine).get_table_names())
    finally:
        engine.dispose()

    # Idempotent: running again on an up-to-date database is a no-op.
    run_migrations(db)
    assert _current_revision(db) == _head_revision()


def test_migrations_match_models(tmp_path: Path) -> None:
    """Fails when db_models.py changes without a matching migration."""
    db = tmp_path / "drift.db"
    run_migrations(db)
    engine = create_engine(f"sqlite:///{db}")
    try:
        with engine.connect() as conn:
            diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    finally:
        engine.dispose()
    assert diff == []


def test_legacy_create_all_database_is_stamped_and_kept(tmp_path: Path) -> None:
    """Databases created by the former create_all() startup keep their data."""
    db = tmp_path / "legacy.db"
    engine = create_engine(f"sqlite:///{db}")
    try:
        Base.metadata.create_all(engine)
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO scans (scan_id, target, status, started_at, timeout) "
                    "VALUES ('old', 'https://example.com', 'success', '2026-01-01', 300)"
                )
            )
    finally:
        engine.dispose()
    assert _current_revision(db) is None

    run_migrations(db)

    assert _current_revision(db) == _head_revision()
    engine = create_engine(f"sqlite:///{db}")
    try:
        with engine.connect() as conn:
            assert conn.execute(text("SELECT scan_id FROM scans")).scalars().all() == ["old"]
    finally:
        engine.dispose()


def test_versions_are_consistent() -> None:
    """Every __version__ follows pyproject.toml (release-please bumps them together)."""
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    manifest = json.loads((REPO_ROOT / ".github/release/.release-please-manifest.json").read_text())
    version = pyproject["project"]["version"]

    assert manifest["."] == version
    assert api.__version__ == cli.__version__ == my_check.__version__ == version
