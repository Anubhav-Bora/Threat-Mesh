from __future__ import annotations

import json
from functools import lru_cache
from typing import Annotated, Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables or ``.env``."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        env_ignore_empty=True,
        extra="ignore",
    )

    app_name: str = "ThreatMesh API"
    app_version: str = "0.1.0"
    environment: str = "development"
    debug: bool = Field(default=False, validation_alias="APP_DEBUG")
    log_level: str = "INFO"
    api_v1_prefix: str = "/api/v1"
    database_url: str = "postgresql+asyncpg://threatmesh:threatmesh@db:5432/threatmesh"
    database_echo: bool = False
    auto_create_schema: bool = True

    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://localhost:3000"]
    )
    trusted_hosts: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1", "testserver", "backend"]
    )
    admin_api_key: str | None = None
    public_rate_limit_per_minute: int = Field(default=120, gt=0)
    ai_rate_limit_per_minute: int = Field(default=12, gt=0)

    scheduler_enabled: bool = True
    run_jobs_on_startup: bool = False
    feed_sync_hours: int = Field(default=3, gt=0)
    enrichment_interval_minutes: int = Field(default=15, gt=0)
    analysis_interval_hours: int = Field(default=6, gt=0)
    report_day_of_week: str = "mon"
    report_hour_utc: int = Field(default=6, ge=0, le=23)

    http_timeout_seconds: float = Field(default=30.0, gt=0)
    feed_max_response_bytes: int = Field(default=8_388_608, gt=0)
    http_user_agent: str = "ThreatMesh/0.1 (+https://github.com/Anubhav-Bora/Threat-Mesh)"
    abusech_auth_key: str | None = None
    urlhaus_url: str = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    threatfox_url: str = "https://threatfox-api.abuse.ch/api/v1/"
    feodo_url: str = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

    geolocation_enabled: bool = True
    geolocation_base_url: str = "http://ip-api.com/json"
    geolocation_requests_per_minute: int = Field(default=40, ge=1, le=45)
    geolocation_cache_days: int = Field(default=30, gt=0)
    enrichment_batch_size: int = Field(default=100, ge=1, le=100)

    cluster_window_hours: int = Field(default=72, gt=0)
    cluster_max_iocs: int = Field(default=5000, gt=0)
    minimum_rule_confidence: float = Field(default=70.0, ge=0, le=100)

    llm_provider: str = "disabled"
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-3.5-flash-lite"
    gemini_base_url: str = "https://generativelanguage.googleapis.com/v1beta"
    ollama_base_url: str = "http://host.docker.internal:11434"
    ollama_model: str = "llama3.1:8b"
    llm_timeout_seconds: float = Field(default=75.0, gt=0)
    llm_max_context_rows: int = Field(default=100, gt=0)

    @field_validator("cors_origins", "trusted_hosts", mode="before")
    @classmethod
    def parse_list(cls, value: Any) -> Any:
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith("["):
                return json.loads(stripped)
            return [item.strip() for item in stripped.split(",") if item.strip()]
        return value

    @field_validator("api_v1_prefix")
    @classmethod
    def validate_prefix(cls, value: str) -> str:
        value = "/" + value.strip("/")
        return value

    @field_validator("report_day_of_week")
    @classmethod
    def validate_report_day(cls, value: str) -> str:
        aliases = {
            "mon": "mon",
            "monday": "mon",
            "tue": "tue",
            "tuesday": "tue",
            "wed": "wed",
            "wednesday": "wed",
            "thu": "thu",
            "thursday": "thu",
            "fri": "fri",
            "friday": "fri",
            "sat": "sat",
            "saturday": "sat",
            "sun": "sun",
            "sunday": "sun",
        }
        normalized = value.strip().lower()
        if normalized not in aliases:
            raise ValueError("report_day_of_week must be a weekday name or three-letter code")
        return aliases[normalized]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
