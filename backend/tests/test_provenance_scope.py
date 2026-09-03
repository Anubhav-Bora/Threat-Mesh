from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from app.clustering import ClusteringService
from app.demo_seed import seed_demo
from app.detection_rules import DetectionRuleService
from app.genai.providers import StaticProvider
from app.genai.reports import ReportService
from app.models import IOC, Campaign, DetectionRule, FeedRun, FeedRunStatus, Report
from app.scoring import ConfidenceService, confidence_score
from tests.factories import make_ioc


def _campaign(*, label: str, is_demo: bool, average: float, count: int = 2) -> Campaign:
    now = datetime.now(UTC)
    return Campaign(
        label=label,
        first_seen=now - timedelta(days=2),
        last_seen=now - timedelta(hours=1),
        ioc_count=count,
        is_demo=is_demo,
        shared_attributes={
            "relationship_evidence": {},
            "observed_context": {
                "average_ioc_confidence": average,
                "unique_indicator_count": count,
                "observation_count": count,
            },
        },
    )


@pytest.mark.asyncio
async def test_confidence_and_clustering_never_mix_demo_and_live(app, settings) -> None:
    demo_duplicate = make_ioc(
        value="8.8.8.8", source="demo-source", is_demo=True, confidence_score=0
    )
    live_duplicate = make_ioc(
        value="8.8.8.8", source="live-source", is_demo=False, confidence_score=0
    )
    demo_members = [
        make_ioc(value="10.0.0.1", source="demo-a", family="Shared", asn="AS64500", is_demo=True),
        make_ioc(value="10.0.0.2", source="demo-b", family="Shared", asn="AS64500", is_demo=True),
    ]
    live_members = [
        make_ioc(value="10.0.0.3", source="live-a", family="Shared", asn="AS64500"),
        make_ioc(value="10.0.0.4", source="live-b", family="Shared", asn="AS64500"),
    ]
    async with app.state.database.session_factory() as session:
        session.add_all([demo_duplicate, live_duplicate, *demo_members, *live_members])
        await session.commit()

    scoring = await ConfidenceService(app.state.database.session_factory).recalculate()
    assert scoring["corroborated"] == 0
    async with app.state.database.session_factory() as session:
        duplicates = list(
            (
                await session.scalars(
                    select(IOC).where(IOC.ioc_value == "8.8.8.8").order_by(IOC.is_demo)
                )
            ).all()
        )
        for item in duplicates:
            assert item.confidence_score == confidence_score(item, corroborating_feeds=1)

    result = await ClusteringService(app.state.database.session_factory, settings).rebuild()
    assert result["campaigns_created"] == 2
    async with app.state.database.session_factory() as session:
        campaigns = list(
            (await session.scalars(select(Campaign).order_by(Campaign.is_demo, Campaign.id))).all()
        )
        assert {campaign.is_demo for campaign in campaigns} == {False, True}
        for campaign in campaigns:
            member_provenance = set(
                (
                    await session.scalars(select(IOC.is_demo).where(IOC.cluster_id == campaign.id))
                ).all()
            )
            assert member_provenance == {campaign.is_demo}


@pytest.mark.asyncio
async def test_rule_generation_is_live_first_and_removes_stale_candidates(client, app) -> None:
    async with app.state.database.session_factory() as session:
        session.add(
            make_ioc(
                value="8.8.8.8",
                source="demo-feed",
                is_demo=True,
                confidence_score=95,
            )
        )
        await session.commit()
    demo_result = await DetectionRuleService(app.state.database.session_factory).generate(
        minimum_confidence=70, limit=10
    )
    assert demo_result["analysis_scope"] == "demo"
    assert demo_result["created"] == 2

    async with app.state.database.session_factory() as session:
        session.add(
            make_ioc(
                value="8.8.8.8",
                source="live-feed",
                confidence_score=10,
            )
        )
        await session.commit()
    below_threshold = await DetectionRuleService(app.state.database.session_factory).generate(
        minimum_confidence=70, limit=10
    )
    assert below_threshold["analysis_scope"] == "live"
    assert below_threshold["unique_detections"] == 0
    assert below_threshold["removed"] == 2
    async with app.state.database.session_factory() as session:
        assert await session.scalar(select(func.count(DetectionRule.id))) == 0
        live = await session.scalar(select(IOC).where(IOC.is_demo.is_(False)))
        assert live is not None
        live.confidence_score = 90
        await session.commit()

    live_result = await DetectionRuleService(app.state.database.session_factory).generate(
        minimum_confidence=70, limit=10
    )
    assert live_result["analysis_scope"] == "live"
    rules = (await client.get("/api/v1/rules")).json()
    assert rules and all(rule["is_demo"] is False for rule in rules)
    assert {tuple(rule["corroborating_sources"]) for rule in rules} == {("live-feed",)}

    async with app.state.database.session_factory() as session:
        live = await session.scalar(select(IOC).where(IOC.is_demo.is_(False)))
        assert live is not None
        live.confidence_score = 5
        await session.commit()
    expired = await DetectionRuleService(app.state.database.session_factory).generate(
        minimum_confidence=70, limit=10
    )
    assert expired["removed"] == 2
    async with app.state.database.session_factory() as session:
        assert await session.scalar(select(func.count(DetectionRule.id))) == 0


@pytest.mark.asyncio
async def test_mixed_report_qa_stats_and_api_use_live_scope(client, app) -> None:
    now = datetime.now(UTC)
    demo_campaign = _campaign(label="Synthetic lead", is_demo=True, average=99)
    live_campaign = _campaign(label="Live lead", is_demo=False, average=45)
    demo_ioc = make_ioc(
        value="192.0.2.1",
        source="demo-feed",
        family="DemoFamily",
        is_demo=True,
        confidence_score=99,
        country="Demo Country",
        country_code="ZZ",
        latitude=1.0,
        longitude=2.0,
    )
    live_ioc = make_ioc(
        value="198.51.100.1",
        source="live-feed",
        family="LiveFamily",
        confidence_score=45,
        country="Live Country",
        country_code="LC",
    )
    async with app.state.database.session_factory() as session:
        session.add_all([demo_campaign, live_campaign])
        await session.flush()
        demo_ioc.cluster_id = demo_campaign.id
        live_ioc.cluster_id = live_campaign.id
        session.add_all([demo_ioc, live_ioc])
        session.add_all(
            [
                Report(
                    period_start=now - timedelta(days=7),
                    period_end=now,
                    title="Synthetic report",
                    report_text="demo",
                    provider="demo",
                    model="demo",
                    facts_json={"included_provenance": "demo"},
                    is_demo=True,
                ),
                Report(
                    period_start=now - timedelta(days=7),
                    period_end=now,
                    title="Live report",
                    report_text="live",
                    provider="static",
                    model="test",
                    facts_json={"included_provenance": "live"},
                    is_demo=False,
                ),
            ]
        )
        await session.commit()
        facts = await ReportService.collect_facts(
            session, now - timedelta(days=7), now + timedelta(minutes=1)
        )

    assert facts["analysis_scope"] == "live"
    assert facts["included_provenance"] == "live"
    assert facts["period_corpus_mode"] == "mixed"
    assert facts["total_observations"] == 1
    assert facts["unique_indicator_count"] == 1
    assert facts["sample_high_confidence_observations"] == []
    assert facts["top_malware_families_by_observation"] == [["LiveFamily", 1]]
    assert [campaign["label"] for campaign in facts["notable_campaigns"]] == ["Live lead"]

    provider = StaticProvider("Grounded live-only response.")
    generated = await ReportService(app.state.database.session_factory, provider).generate(
        period_start=now - timedelta(days=7), period_end=now + timedelta(minutes=1)
    )
    assert generated.is_demo is False
    assert generated.facts_json["included_provenance"] == "live"

    app.state.llm_provider_override = provider
    answer = await client.post(
        "/api/v1/assistant/ask", json={"question": "Summarize the latest weekly report"}
    )
    qa_facts = answer.json()["grounded_facts"]
    assert qa_facts["analysis_scope"] == "live"
    assert qa_facts["period_corpus_mode"] == "mixed"
    assert qa_facts["matching_observation_count"] == 1
    assert all(item["is_demo"] is False for item in qa_facts["indicators"])
    assert all(item["is_demo"] is False for item in qa_facts["campaigns"])
    assert all(item["is_demo"] is False for item in qa_facts["recent_reports"])

    summary = (await client.get("/api/v1/stats/summary")).json()
    assert summary["corpus_mode"] == "mixed"
    assert summary["analysis_scope"] == "live"
    assert (summary["demo_iocs"], summary["live_iocs"]) == (1, 1)
    assert summary["high_confidence_iocs"] == 0
    assert summary["geolocated_iocs"] == 0
    assert summary["active_campaigns"] == 1
    assert summary["affected_countries"] == 1
    families = (await client.get("/api/v1/stats/by-malware-family")).json()
    assert families == [{"key": "LiveFamily", "count": 1}]

    all_iocs = (await client.get("/api/v1/iocs", params={"provenance": "all"})).json()
    live_iocs = (await client.get("/api/v1/iocs", params={"provenance": "live"})).json()
    demo_iocs = (await client.get("/api/v1/iocs", params={"provenance": "demo"})).json()
    assert (all_iocs["total"], live_iocs["total"], demo_iocs["total"]) == (2, 1, 1)
    assert live_iocs["features"][0]["properties"]["is_demo"] is False
    assert demo_iocs["features"][0]["properties"]["is_demo"] is True

    campaigns = (await client.get("/api/v1/campaigns")).json()
    reports = (await client.get("/api/v1/reports")).json()
    assert {item["is_demo"] for item in campaigns} == {False, True}
    assert {item["is_demo"] for item in reports} == {False, True}


@pytest.mark.asyncio
async def test_failed_first_live_feed_run_cannot_be_masked_by_demo_runs(
    client, app, settings
) -> None:
    await seed_demo(app.state.database.session_factory, settings)
    assert (await client.get("/api/v1/stats/summary")).json()["feed_health"] == 100
    now = datetime.now(UTC)
    async with app.state.database.session_factory() as session:
        session.add(
            FeedRun(
                feed_name="urlhaus",
                status=FeedRunStatus.FAILED,
                started_at=now - timedelta(minutes=2),
                completed_at=now - timedelta(minutes=1),
                error="schema drift",
            )
        )
        await session.commit()
    summary = (await client.get("/api/v1/stats/summary")).json()
    assert summary["analysis_scope"] == "demo"
    assert summary["feed_health"] == 0
