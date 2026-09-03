"""Make scheduled report generation idempotent.

Revision ID: 0004
Revises: 0003
"""

from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa

from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("reports", sa.Column("schedule_key", sa.String(length=128), nullable=True))
    reports = sa.table(
        "reports",
        sa.column("id", sa.Integer()),
        sa.column("period_start", sa.DateTime(timezone=True)),
        sa.column("period_end", sa.DateTime(timezone=True)),
        sa.column("cadence", sa.String(length=16)),
        sa.column("is_demo", sa.Boolean()),
        sa.column("schedule_key", sa.String(length=128)),
    )
    connection = op.get_bind()
    legacy_rows = connection.execute(
        sa.select(
            reports.c.id,
            reports.c.period_start,
            reports.c.period_end,
            reports.c.cadence,
            reports.c.is_demo,
        ).order_by(reports.c.id.desc())
    ).mappings()
    assigned: set[str] = set()
    for row in legacy_rows:
        cadence = getattr(row["cadence"], "value", row["cadence"])
        provenance = "demo" if row["is_demo"] else "live"
        schedule_key = (
            f"{cadence}:{_utc_iso(row['period_start'])}:{_utc_iso(row['period_end'])}:{provenance}"
        )
        # Keep the newest of any pre-existing duplicate periods canonical.
        # Older duplicates remain historical records with a null key.
        if schedule_key in assigned:
            continue
        connection.execute(
            reports.update().where(reports.c.id == row["id"]).values(schedule_key=schedule_key)
        )
        assigned.add(schedule_key)
    op.create_index("uq_reports_schedule_key", "reports", ["schedule_key"], unique=True)


def downgrade() -> None:
    op.drop_index("uq_reports_schedule_key", table_name="reports")
    op.drop_column("reports", "schedule_key")


def _utc_iso(value: datetime | str) -> str:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    normalized = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return normalized.isoformat()
