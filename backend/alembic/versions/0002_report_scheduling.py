"""Persist automatic report cadence and report type.

Revision ID: 0002
Revises: 0001
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "reports",
        sa.Column(
            "cadence",
            sa.String(length=16),
            server_default="weekly",
            nullable=False,
        ),
    )
    report_schedules = op.create_table(
        "report_schedules",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "cadence",
            sa.String(length=16),
            server_default="weekly",
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.current_timestamp(),
            nullable=False,
        ),
        sa.CheckConstraint("id = 1", name="ck_report_schedules_report_schedule_singleton"),
        sa.CheckConstraint(
            "cadence IN ('weekly', 'monthly')",
            name="ck_report_schedules_report_schedule_cadence",
        ),
    )
    op.bulk_insert(report_schedules, [{"id": 1, "cadence": "weekly"}])


def downgrade() -> None:
    op.drop_table("report_schedules")
    op.drop_column("reports", "cadence")
