"""Align findings columns with models

The initial migration declared ``cvss_score`` as INTEGER (the model is a Float, so
scores such as 9.8 were truncated) and ``cve`` as VARCHAR(50), too short for
findings that reference several CVEs.

Revision ID: d2302b4b6c60
Revises: 1dd0c571c561
Create Date: 2026-10-22 16:45:49.621751

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d2302b4b6c60"
down_revision: str | Sequence[str] | None = "1dd0c571c561"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # SQLite cannot ALTER COLUMN: batch mode recreates the table.
    with op.batch_alter_table("findings") as batch_op:
        batch_op.alter_column(
            "cve",
            existing_type=sa.VARCHAR(length=50),
            type_=sa.String(length=255),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "cvss_score",
            existing_type=sa.INTEGER(),
            type_=sa.Float(),
            existing_nullable=True,
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("findings") as batch_op:
        batch_op.alter_column(
            "cvss_score",
            existing_type=sa.Float(),
            type_=sa.INTEGER(),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "cve",
            existing_type=sa.String(length=255),
            type_=sa.VARCHAR(length=50),
            existing_nullable=True,
        )
