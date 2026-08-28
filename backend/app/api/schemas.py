from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.enums import IOCType, ReportCadence, RuleType


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class IOCProperties(ORMModel):
    id: int
    ioc_value: str
    ioc_type: IOCType
    port: int | None
    malware_family: str | None
    first_seen: datetime
    last_seen: datetime
    source_feed: str
    is_demo: bool
    corroborating_feeds: int = 1
    corroborating_sources: list[str] = Field(default_factory=list)
    confidence_score: float
    country: str | None
    country_code: str | None
    city: str | None
    asn: str | None
    asn_org: str | None
    attack_technique_ids: list[str]
    cluster_id: int | None
    location_precision_km: int = Field(
        default=25,
        description=(
            "Illustrative map context radius only; not provider-measured accuracy or a "
            "geolocation confidence interval."
        ),
    )


class GeoJSONPoint(BaseModel):
    type: Literal["Point"] = "Point"
    coordinates: tuple[float, float]


class IOCFeature(BaseModel):
    type: Literal["Feature"] = "Feature"
    id: int
    geometry: GeoJSONPoint | None
    properties: IOCProperties


class GeoJSONFeatureCollection(BaseModel):
    type: Literal["FeatureCollection"] = "FeatureCollection"
    features: list[IOCFeature]
    total: int
    limit: int
    offset: int


class IOCDetail(IOCProperties):
    latitude: float | None
    longitude: float | None
    raw_json: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class CampaignSummary(ORMModel):
    id: int
    label: str
    first_seen: datetime
    last_seen: datetime
    is_demo: bool
    observation_count: int
    unique_indicator_count: int
    summary_text: str | None
    average_ioc_confidence: float = 0
    relationship_evidence: dict[str, Any]
    observed_context: dict[str, Any]


class CampaignDetail(CampaignSummary):
    iocs: list[IOCDetail]


class CountBucket(BaseModel):
    key: str
    count: int


class CountryBucket(BaseModel):
    country: str
    country_code: str | None
    count: int
    average_confidence: float


class SummaryStats(BaseModel):
    total_iocs: int
    demo_iocs: int
    live_iocs: int
    corpus_mode: Literal["empty", "demo", "live", "mixed"]
    analysis_scope: Literal["none", "demo", "live"]
    geolocated_iocs: int
    high_confidence_iocs: int
    active_campaigns: int
    affected_countries: int
    ingestion_last_hour: int
    feed_health: float
    trend: dict[str, float]
    generated_at: datetime


class TechniqueTrend(BaseModel):
    technique_id: str
    name: str | None = None
    tactic: str | None = None
    count: int


class RuleResponse(ORMModel):
    id: int
    ioc_id: int
    detection_key: str
    rule_type: RuleType
    rule_text: str
    corroborating_sources: list[str]
    generated_at: datetime
    requires_review: bool
    is_demo: bool = False
    malware_family: str | None = None
    ioc_value: str | None = None
    severity: str = "medium"
    tags: list[str] = Field(default_factory=list)


class RuleGenerationRequest(BaseModel):
    minimum_confidence: float = Field(default=70, ge=0, le=100)
    limit: int = Field(default=500, ge=1, le=5000)


class OperationResult(BaseModel):
    status: str = "completed"
    details: dict[str, Any]


class ReportSummary(ORMModel):
    id: int
    period_start: datetime
    period_end: datetime
    title: str
    provider: str
    model: str
    cadence: ReportCadence
    is_demo: bool
    created_at: datetime


class ReportDetail(ReportSummary):
    report_text: str
    facts_json: dict[str, Any]


class UpdateReportScheduleRequest(BaseModel):
    cadence: ReportCadence


class ReportScheduleResponse(BaseModel):
    cadence: ReportCadence
    scheduler_running: bool
    provider_configured: bool
    next_run_at: datetime | None
    timezone: Literal["UTC"] = "UTC"
    hour_utc: int
    weekly_day: str
    monthly_day: int = 1
    updated_at: datetime
    admin_auth_required: bool


class AskRequest(BaseModel):
    question: str = Field(min_length=3, max_length=500)
    date_from: datetime | None = None
    date_to: datetime | None = None

    @field_validator("date_from", "date_to")
    @classmethod
    def normalize_request_datetime(cls, value: datetime | None) -> datetime | None:
        return _as_utc(value) if value else None

    @field_validator("question")
    @classmethod
    def normalize_question(cls, value: str) -> str:
        return " ".join(value.split())

    @model_validator(mode="after")
    def validate_dates(self) -> AskRequest:
        now = datetime.now(UTC)
        if self.date_from and self.date_from > now:
            raise ValueError("date_from cannot be in the future")
        if self.date_to and self.date_to > now:
            raise ValueError("date_to cannot be in the future")
        if self.date_from and self.date_to and self.date_from >= self.date_to:
            raise ValueError("date_from must be earlier than date_to")
        return self


class AssistantCitation(BaseModel):
    record_id: str = Field(min_length=3, max_length=161)
    kind: Literal["indicator", "campaign", "technique", "report", "aggregate"]
    label: str = Field(min_length=1, max_length=240)


class CitationIntegrity(BaseModel):
    status: Literal["verified", "partial", "absent"]
    validated_count: int = Field(ge=0)
    rejected_count: int = Field(ge=0)


class AskResponse(BaseModel):
    answer: str
    provider: str
    model: str
    grounded_facts: dict[str, Any]
    citations: list[AssistantCitation] = Field(default_factory=list)
    citation_integrity: CitationIntegrity
    disclaimer: str = (
        "Citation IDs are server-validated against this response's retrieved facts. "
        "Generated wording and claim support still require analyst review."
    )


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
