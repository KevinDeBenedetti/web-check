"""Add remediation to findings

Revision ID: 7c2e5a9f4b1d
Revises: d2302b4b6c60
Create Date: 2026-10-26 11:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "7c2e5a9f4b1d"
down_revision: str | Sequence[str] | None = "d2302b4b6c60"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # Databases upgraded by the former startup code (ALTER TABLE) already have it.
    columns = {col["name"] for col in sa.inspect(op.get_bind()).get_columns("findings")}
    if "remediation" not in columns:
        op.add_column("findings", sa.Column("remediation", sa.Text(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("findings", "remediation")
