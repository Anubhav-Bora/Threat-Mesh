from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest

from app.attack_mapping.sync import fetch_official_bundle
from app.demo_seed import seed_demo
from app.export_artifacts import export_artifacts


@pytest.mark.asyncio
async def test_export_preserves_existing_files(app, settings, tmp_path) -> None:
    await seed_demo(app.state.database.session_factory, settings, now=datetime.now(UTC))
    rules = tmp_path / "rules"
    reports = tmp_path / "reports"
    first = await export_artifacts(
        app.state.database, rules_dir=rules, reports_dir=reports, overwrite=False
    )
    second = await export_artifacts(
        app.state.database, rules_dir=rules, reports_dir=reports, overwrite=False
    )
    assert first["rules"].written > 0
    assert first["reports"].written == 1
    assert second["rules"].written == 0
    assert second["rules"].skipped_existing == first["rules"].written
    filenames = [path.name for path in rules.iterdir()]
    assert len(filenames) == len(set(filenames))
    assert all(name.startswith("threatmesh-") and not name.startswith("ioc-") for name in filenames)
    assert all(
        "SYNTHETIC DEMO ONLY" in path.read_text(encoding="utf-8") for path in rules.iterdir()
    )
    report_files = list(reports.iterdir())
    assert len(report_files) == 1
    assert "Provenance: SYNTHETIC DEMO ONLY" in report_files[0].read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_attack_fetch_validates_shape_without_live_network() -> None:
    bundle = {"type": "bundle", "objects": []}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=json.dumps(bundle).encode(), request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        assert await fetch_official_bundle(client=client) == bundle


@pytest.mark.asyncio
async def test_attack_fetch_enforces_size_limit() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Length": "1000"},
            content=b"{}",
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="limit"):
            await fetch_official_bundle(client=client, max_bytes=10)
