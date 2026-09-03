from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    false,
)
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql.functions import FunctionElement
from sqlalchemy.types import UserDefinedType

from app.models.base import Base, TimestampMixin, utcnow
from app.models.enums import FeedRunStatus, IOCType, ReportCadence, RuleType


def report_cadence_type() -> Enum:
    return Enum(
        ReportCadence,
        native_enum=False,
        length=16,
        values_callable=lambda enum: [item.value for item in enum],
    )


class GeographyPoint(UserDefinedType[str]):
    """PostGIS geography point, represented as EWKT and TEXT in SQLite tests."""

    cache_ok = True

    def get_col_spec(self, **kw: Any) -> str:  # noqa: ARG002
        return "GEOGRAPHY(POINT, 4326)"

    def bind_expression(self, bindvalue: Any) -> Any:
        return GeographyFromText(bindvalue)

    def column_expression(self, column: Any) -> Any:
        return GeographyAsEWKT(column)


class GeographyFromText(FunctionElement[str]):
    type = String()
    inherit_cache = True


class GeographyAsEWKT(FunctionElement[str]):
    type = String()
    inherit_cache = True


@compiles(GeographyFromText)
def compile_geography_bind_default(element: Any, compiler: Any, **kw: Any) -> str:
    return compiler.process(element.clauses, **kw)


@compiles(GeographyFromText, "postgresql")
def compile_geography_bind_postgres(element: Any, compiler: Any, **kw: Any) -> str:
    return f"ST_GeogFromText({compiler.process(element.clauses, **kw)})"


@compiles(GeographyAsEWKT)
def compile_geography_column_default(element: Any, compiler: Any, **kw: Any) -> str:
    return compiler.process(element.clauses, **kw)


@compiles(GeographyAsEWKT, "postgresql")
def compile_geography_column_postgres(element: Any, compiler: Any, **kw: Any) -> str:
    return f"ST_AsEWKT({compiler.process(element.clauses, **kw)})"


@compiles(GeographyPoint, "sqlite")
def compile_geography_sqlite(type_: GeographyPoint, compiler: Any, **kw: Any) -> str:  # noqa: ARG001
    return "TEXT"


@compiles(GeographyPoint, "postgresql")
def compile_geography_postgres(type_: GeographyPoint, compiler: Any, **kw: Any) -> str:  # noqa: ARG001
    return "GEOGRAPHY(POINT, 4326)"


class Campaign(TimestampMixin, Base):
    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    label: Mapped[str] = mapped_column(String(180), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ioc_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    summary_text: Mapped[str | None] = mapped_column(Text)
    shared_attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    is_demo: Mapped[bool] = mapped_column(default=False, server_default=false(), nullable=False)

    iocs: Mapped[list[IOC]] = relationship(back_populates="campaign")


class IOC(TimestampMixin, Base):
    __tablename__ = "iocs"
    __table_args__ = (
        UniqueConstraint(
            "ioc_type",
            "indicator_key",
            "source_feed",
            name="uq_iocs_type_key_source",
        ),
        Index("ix_iocs_location_gist", "location", postgresql_using="gist"),
        Index("ix_iocs_seen", "last_seen", "first_seen"),
        Index("ix_iocs_family", "malware_family"),
        Index("ix_iocs_country", "country"),
        Index("ix_iocs_confidence", "confidence_score"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ioc_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    indicator_key: Mapped[str] = mapped_column(String(2100), nullable=False)
    port: Mapped[int | None] = mapped_column(Integer)
    ioc_type: Mapped[IOCType] = mapped_column(
        Enum(IOCType, native_enum=False, length=16), nullable=False
    )
    malware_family: Mapped[str | None] = mapped_column(String(255))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_feed: Mapped[str] = mapped_column(String(64), nullable=False)
    is_demo: Mapped[bool] = mapped_column(default=False, server_default=false(), nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    source_confidence_hint: Mapped[float | None] = mapped_column(Float)
    confidence_model_version: Mapped[str | None] = mapped_column(String(32))
    confidence_scored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    confidence_components: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON)
    country: Mapped[str | None] = mapped_column(String(128))
    country_code: Mapped[str | None] = mapped_column(String(2))
    city: Mapped[str | None] = mapped_column(String(128))
    asn: Mapped[str | None] = mapped_column(String(32))
    asn_org: Mapped[str | None] = mapped_column(String(255))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    location: Mapped[str | None] = mapped_column(GeographyPoint())
    attack_technique_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    cluster_id: Mapped[int | None] = mapped_column(
        ForeignKey("campaigns.id", ondelete="SET NULL"), index=True
    )
    raw_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    campaign: Mapped[Campaign | None] = relationship(back_populates="iocs")
    detection_rules: Mapped[list[DetectionRule]] = relationship(
        back_populates="ioc", cascade="all, delete-orphan"
    )


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    technique_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    tactic: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    stix_id: Mapped[str | None] = mapped_column(String(128), unique=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (
        UniqueConstraint("detection_key", "rule_type", name="uq_detection_rule_key_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ioc_id: Mapped[int] = mapped_column(
        ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    detection_key: Mapped[str] = mapped_column(String(2100), nullable=False)
    rule_type: Mapped[RuleType] = mapped_column(
        Enum(RuleType, native_enum=False, length=16), nullable=False
    )
    rule_text: Mapped[str] = mapped_column(Text, nullable=False)
    corroborating_sources: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    requires_review: Mapped[bool] = mapped_column(default=True, nullable=False)

    ioc: Mapped[IOC] = relationship(back_populates="detection_rules")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    report_text: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    cadence: Mapped[ReportCadence] = mapped_column(
        report_cadence_type(),
        default=ReportCadence.WEEKLY,
        server_default=ReportCadence.WEEKLY.value,
        nullable=False,
    )
    schedule_key: Mapped[str | None] = mapped_column(String(128), unique=True)
    facts_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    is_demo: Mapped[bool] = mapped_column(default=False, server_default=false(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )


class ReportSchedule(Base):
    __tablename__ = "report_schedules"
    __table_args__ = (
        CheckConstraint("id = 1", name="report_schedule_singleton"),
        CheckConstraint(
            "cadence IN ('weekly', 'monthly')",
            name="report_schedule_cadence",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    cadence: Mapped[ReportCadence] = mapped_column(
        report_cadence_type(),
        default=ReportCadence.WEEKLY,
        server_default=ReportCadence.WEEKLY.value,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
    )


class GeoCache(Base):
    __tablename__ = "geo_cache"

    ip_address: Mapped[str] = mapped_column(String(45), primary_key=True)
    country: Mapped[str | None] = mapped_column(String(128))
    country_code: Mapped[str | None] = mapped_column(String(2))
    city: Mapped[str | None] = mapped_column(String(128))
    asn: Mapped[str | None] = mapped_column(String(32))
    asn_org: Mapped[str | None] = mapped_column(String(255))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    successful: Mapped[bool] = mapped_column(default=True, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(String(255))
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )


class FeedRun(Base):
    __tablename__ = "feed_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    feed_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[FeedRunStatus] = mapped_column(
        Enum(FeedRunStatus, native_enum=False, length=16), nullable=False
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    received_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    inserted_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    rejected_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
