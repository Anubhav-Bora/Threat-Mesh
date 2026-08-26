from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from sqlalchemy import create_engine, inspect

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
        ioc_constraints = {
            constraint["name"]: tuple(constraint["column_names"])
            for constraint in inspector.get_unique_constraints("iocs")
        }
    finally:
        engine.dispose()
    for columns in (ioc_columns, campaign_columns, report_columns):
        assert columns["is_demo"]["nullable"] is False
        assert columns["is_demo"]["default"] is not None
    assert ioc_constraints["uq_iocs_type_key_source"] == (
        "ioc_type",
        "indicator_key",
        "source_feed",
    )
