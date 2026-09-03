"""Persist reproducible confidence evidence.

Revision ID: 0003
Revises: 0002
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("iocs", sa.Column("source_confidence_hint", sa.Float(), nullable=True))
    op.add_column(
        "iocs", sa.Column("confidence_model_version", sa.String(length=32), nullable=True)
    )
    op.add_column(
        "iocs", sa.Column("confidence_scored_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("iocs", sa.Column("confidence_components", sa.JSON(), nullable=True))
    # Pre-lineage scores cannot be audited because their formula snapshot was
    # never persisted. Mark them pending; the required post-migration
    # coordinator run will recreate complete deterministic evidence.
    op.execute(sa.text("UPDATE iocs SET confidence_score = 0.0"))


def downgrade() -> None:
    op.drop_column("iocs", "confidence_components")
    op.drop_column("iocs", "confidence_scored_at")
    op.drop_column("iocs", "confidence_model_version")
    op.drop_column("iocs", "source_confidence_hint")
