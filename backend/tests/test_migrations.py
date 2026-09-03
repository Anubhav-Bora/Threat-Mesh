from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from alembic import command


def test_baseline_migration_persists_demo_provenance(tmp_path, monkeypatch) -> None:
    database_path = tmp_path / "migration.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{database_path.as_posix()}")
    backend_root = Path(__file__).resolve().parents[1]
    config = Config(str(backend_root / "alembic.ini"))

    command.upgrade(config, "head")

    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    try:
        inspector = inspect(engine)
        ioc_columns = {column["name"]: column for column in inspector.get_columns("iocs")}
        campaign_columns = {column["name"]: column for column in inspector.get_columns("campaigns")}
        report_columns = {column["name"]: column for column in inspector.get_columns("reports")}
        report_schedule_columns = {
            column["name"]: column for column in inspector.get_columns("report_schedules")
        }
        report_indexes = {index["name"]: index for index in inspector.get_indexes("reports")}
        ioc_constraints = {
            constraint["name"]: tuple(constraint["column_names"])
            for constraint in inspector.get_unique_constraints("iocs")
        }
    finally:
        engine.dispose()
    for columns in (ioc_columns, campaign_columns, report_columns):
        assert columns["is_demo"]["nullable"] is False
        assert columns["is_demo"]["default"] is not None
    assert report_columns["cadence"]["nullable"] is False
    assert report_columns["cadence"]["default"] is not None
    assert report_columns["schedule_key"]["nullable"] is True
    assert bool(report_indexes["uq_reports_schedule_key"]["unique"]) is True
    assert report_schedule_columns["cadence"]["nullable"] is False
    assert report_schedule_columns["updated_at"]["nullable"] is False
    assert ioc_columns["source_confidence_hint"]["nullable"] is True
    assert ioc_columns["confidence_model_version"]["nullable"] is True
    assert ioc_columns["confidence_scored_at"]["nullable"] is True
    assert ioc_columns["confidence_components"]["nullable"] is True
    assert ioc_constraints["uq_iocs_type_key_source"] == (
        "ioc_type",
        "indicator_key",
        "source_feed",
    )


def test_populated_legacy_upgrade_invalidates_scores_and_keys_reports(
    tmp_path, monkeypatch
) -> None:
    database_path = tmp_path / "legacy-migration.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{database_path.as_posix()}")
    backend_root = Path(__file__).resolve().parents[1]
    config = Config(str(backend_root / "alembic.ini"))
    command.upgrade(config, "0002")

    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO iocs (
                    ioc_value, indicator_key, port, ioc_type, malware_family,
                    first_seen, last_seen, source_feed, confidence_score,
                    attack_technique_ids, raw_json, created_at, updated_at
                ) VALUES (
                    :value, :key, :port, :type, :family,
                    :first_seen, :last_seen, :source, :score,
                    :techniques, :raw_json, :created_at, :updated_at
                )
                """
            ),
            {
                "value": "203.0.113.9",
                "key": "203.0.113.9:443",
                "port": 443,
                "type": "IP",
                "family": "LegacyLoader",
                "first_seen": "2026-08-28 00:00:00+00:00",
                "last_seen": "2026-08-30 00:00:00+00:00",
                "source": "threatfox",
                "score": 88,
                "techniques": "[]",
                "raw_json": "{}",
                "created_at": "2026-08-30 01:00:00+00:00",
                "updated_at": "2026-08-30 01:00:00+00:00",
            },
        )
        connection.execute(
            text(
                """
                INSERT INTO reports (
                    period_start, period_end, title, report_text, provider,
                    model, facts_json, created_at
                ) VALUES (
                    :period_start, :period_end, :title, :report_text, :provider,
                    :model, :facts_json, :created_at
                )
                """
            ),
            {
                "period_start": "2026-08-24 00:00:00+00:00",
                "period_end": "2026-08-31 00:00:00+00:00",
                "title": "Legacy weekly report",
                "report_text": "Legacy evidence-bounded narrative.",
                "provider": "gemini",
                "model": "legacy-model",
                "facts_json": "{}",
                "created_at": "2026-08-31 06:00:00+00:00",
            },
        )
    engine.dispose()

    command.upgrade(config, "head")

    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    try:
        with engine.connect() as connection:
            score = connection.execute(
                text(
                    "SELECT confidence_score, confidence_model_version, "
                    "confidence_scored_at, confidence_components FROM iocs"
                )
            ).one()
            schedule_key = connection.scalar(text("SELECT schedule_key FROM reports"))
    finally:
        engine.dispose()

    assert tuple(score) == (0.0, None, None, None)
    assert schedule_key == ("weekly:2026-08-24T00:00:00+00:00:2026-08-31T00:00:00+00:00:live")
