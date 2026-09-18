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
    confidence_model_version: str | None
    confidence_scored_at: datetime | None
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


class IOCInvestigationRequest(BaseModel):
    values: list[str] = Field(min_length=1, max_length=100)

    @field_validator("values")
    @classmethod
    def normalize_values(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for raw_value in values:
            value = " ".join(str(raw_value).strip().split())
            if not value or value in seen:
                continue
            if len(value) > 2048:
                raise ValueError("each observable must be 2048 characters or fewer")
            seen.add(value)
            normalized.append(value)
        if not normalized:
            raise ValueError("at least one non-empty observable is required")
        return normalized


class IOCInvestigationMatch(BaseModel):
    query: str
    normalized_query: str
    indicator: IOCProperties
    blocklist_eligible: bool = True
    warnings: list[str] = Field(default_factory=list)


class IOCInvestigationResponse(BaseModel):
    queried: int
    matched: int
    matches: list[IOCInvestigationMatch]
    unmatched: list[str]
    invalid: list[str]


class IOCDetail(IOCProperties):
    latitude: float | None
    longitude: float | None
    created_at: datetime
    updated_at: datetime


class LineageIdentity(BaseModel):
    value: str
    type: IOCType
    port: int | None
    is_demo: bool


class ProvenanceObservation(BaseModel):
    record_id: str
    source_feed: str
    first_seen: datetime
    last_seen: datetime
    source_confidence_hint: float | None
    is_selected: bool


class RawPayloadEvidence(BaseModel):
    retained: bool
    sha256: str | None
    field_names: list[str] = Field(default_factory=list)


class ProvenanceEvidence(BaseModel):
    selected_source: str
    observations: list[ProvenanceObservation]
    raw_payload: RawPayloadEvidence


class ConfidenceComponentEvidence(BaseModel):
    key: str
    label: str
    score: float
    max_score: float
    evidence: str


class ConfidenceEvidence(BaseModel):
    status: Literal["available", "pending"]
    total: float
    formula_version: str | None
    calculated_at: datetime | None
    components: list[ConfidenceComponentEvidence] = Field(default_factory=list)


class EnrichmentEvidence(BaseModel):
    status: Literal["available", "not_applicable", "unavailable"]
    provider: str | None
    method: str
    country: str | None
    country_code: str | None
    city: str | None
    asn: str | None
    asn_org: str | None
    approximate: bool


class AttackMappingEvidence(BaseModel):
    record_id: str
    technique_id: str
    name: str
    tactic: str
    method: str
    basis: str | None
    inference: bool = True


class CampaignMembershipEvidence(BaseModel):
    record_id: str
    label: str
    snapshot: Literal["current"] = "current"
    reasons: list[str] = Field(default_factory=list)


class DerivedRuleEvidence(BaseModel):
    record_id: str
    rule_type: RuleType
    requires_review: bool
    generated_at: datetime


class ReportMentionEvidence(BaseModel):
    record_id: str
    title: str
    period_start: datetime
    period_end: datetime


class DerivedArtifactsEvidence(BaseModel):
    rules: list[DerivedRuleEvidence] = Field(default_factory=list)
    report_mentions: list[ReportMentionEvidence] = Field(default_factory=list)


class IOCLineageResponse(BaseModel):
    indicator_id: int
    record_id: str
    identity: LineageIdentity
    provenance: ProvenanceEvidence
    confidence: ConfidenceEvidence
    enrichment: EnrichmentEvidence
    attack_mappings: list[AttackMappingEvidence] = Field(default_factory=list)
    campaign_membership: CampaignMembershipEvidence | None
    derived_artifacts: DerivedArtifactsEvidence
    limitations: list[str]


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
    scheduler_mode: Literal["embedded", "external", "disabled"]
    provider_configured: bool
    next_run_at: datetime | None
    timezone: Literal["UTC"] = "UTC"
    hour_utc: int
    weekly_day: str
    monthly_day: int = 1
    updated_at: datetime
    admin_auth_required: bool


class AssistantHistoryItem(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=1000)

    @field_validator("content")
    @classmethod
    def normalize_content(cls, value: str) -> str:
        return " ".join(value.split())


class AskRequest(BaseModel):
    question: str = Field(min_length=3, max_length=500)
    date_from: datetime | None = None
    date_to: datetime | None = None
    mode: Literal["auto", "threatmesh", "general"] = "auto"
    history: list[AssistantHistoryItem] = Field(default_factory=list, max_length=8)

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
    response_mode: Literal["threatmesh", "general"]
    grounded_facts: dict[str, Any]
    citations: list[AssistantCitation] = Field(default_factory=list)
    citation_integrity: CitationIntegrity
    disclaimer: str = (
        "Citation IDs are server-validated against this response's retrieved facts. "
        "General-mode answers use model knowledge and may not be current; generated wording "
        "and claim support still require appropriate review."
    )


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
