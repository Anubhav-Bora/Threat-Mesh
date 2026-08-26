"""Create the ThreatMesh baseline schema.

Revision ID: 0001
Revises:
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op
from app.models.entities import GeographyPoint
from app.models.enums import FeedRunStatus, IOCType, RuleType

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("CREATE EXTENSION IF NOT EXISTS postgis")

    op.create_table(
        "attack_techniques",
        sa.Column("technique_id", sa.String(20), primary_key=True),
        sa.Column("tactic", sa.String(128), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("stix_id", sa.String(128), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("stix_id", name="uq_attack_techniques_stix_id"),
    )
    op.create_table(
        "campaigns",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("label", sa.String(180), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ioc_count", sa.Integer(), nullable=False),
        sa.Column("summary_text", sa.Text(), nullable=True),
        sa.Column("shared_attributes", sa.JSON(), nullable=False),
        sa.Column("is_demo", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "feed_runs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("feed_name", sa.String(64), nullable=False),
        sa.Column("status", sa.Enum(FeedRunStatus, native_enum=False, length=16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("received_count", sa.Integer(), nullable=False),
        sa.Column("inserted_count", sa.Integer(), nullable=False),
        sa.Column("updated_count", sa.Integer(), nullable=False),
        sa.Column("rejected_count", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
    )
    op.create_index("ix_feed_runs_feed_name", "feed_runs", ["feed_name"])
    op.create_table(
        "geo_cache",
        sa.Column("ip_address", sa.String(45), primary_key=True),
        sa.Column("country", sa.String(128), nullable=True),
        sa.Column("country_code", sa.String(2), nullable=True),
        sa.Column("city", sa.String(128), nullable=True),
        sa.Column("asn", sa.String(32), nullable=True),
        sa.Column("asn_org", sa.String(255), nullable=True),
        sa.Column("latitude", sa.Float(), nullable=True),
        sa.Column("longitude", sa.Float(), nullable=True),
        sa.Column("successful", sa.Boolean(), nullable=False),
        sa.Column("failure_reason", sa.String(255), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_geo_cache_fetched_at", "geo_cache", ["fetched_at"])
    op.create_table(
        "reports",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("report_text", sa.Text(), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("facts_json", sa.JSON(), nullable=False),
        sa.Column("is_demo", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_reports_created_at", "reports", ["created_at"])
    op.create_table(
        "iocs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("ioc_value", sa.String(2048), nullable=False),
        sa.Column("indicator_key", sa.String(2100), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("ioc_type", sa.Enum(IOCType, native_enum=False, length=16), nullable=False),
        sa.Column("malware_family", sa.String(255), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_feed", sa.String(64), nullable=False),
        sa.Column("is_demo", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("country", sa.String(128), nullable=True),
        sa.Column("country_code", sa.String(2), nullable=True),
        sa.Column("city", sa.String(128), nullable=True),
        sa.Column("asn", sa.String(32), nullable=True),
        sa.Column("asn_org", sa.String(255), nullable=True),
        sa.Column("latitude", sa.Float(), nullable=True),
        sa.Column("longitude", sa.Float(), nullable=True),
        sa.Column("location", GeographyPoint(), nullable=True),
        sa.Column("attack_technique_ids", sa.JSON(), nullable=False),
        sa.Column("cluster_id", sa.Integer(), nullable=True),
        sa.Column("raw_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["cluster_id"],
            ["campaigns.id"],
            name="fk_iocs_cluster_id_campaigns",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint(
            "ioc_type", "indicator_key", "source_feed", name="uq_iocs_type_key_source"
        ),
    )
    op.create_index("ix_iocs_cluster_id", "iocs", ["cluster_id"])
    op.create_index("ix_iocs_seen", "iocs", ["last_seen", "first_seen"])
    op.create_index("ix_iocs_family", "iocs", ["malware_family"])
    op.create_index("ix_iocs_country", "iocs", ["country"])
    op.create_index("ix_iocs_confidence", "iocs", ["confidence_score"])
    op.create_index("ix_iocs_location_gist", "iocs", ["location"], postgresql_using="gist")
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("ioc_id", sa.Integer(), nullable=False),
        sa.Column("detection_key", sa.String(2100), nullable=False),
        sa.Column("rule_type", sa.Enum(RuleType, native_enum=False, length=16), nullable=False),
        sa.Column("rule_text", sa.Text(), nullable=False),
        sa.Column("corroborating_sources", sa.JSON(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("requires_review", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(
            ["ioc_id"], ["iocs.id"], name="fk_detection_rules_ioc_id_iocs", ondelete="CASCADE"
        ),
        sa.UniqueConstraint("detection_key", "rule_type", name="uq_detection_rule_key_type"),
    )
    op.create_index("ix_detection_rules_ioc_id", "detection_rules", ["ioc_id"])


def downgrade() -> None:
    op.drop_table("detection_rules")
    op.drop_table("iocs")
    op.drop_table("reports")
    op.drop_table("geo_cache")
    op.drop_table("feed_runs")
    op.drop_table("campaigns")
    op.drop_table("attack_techniques")
    # PostGIS is deliberately retained because other schemas may depend on it.
