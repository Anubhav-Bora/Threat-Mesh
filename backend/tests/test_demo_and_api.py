from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pytest
import yaml
from sqlalchemy import func, select

from app.demo_seed import DEMO_IOCS, seed_demo
from app.detection_rules import DetectionRuleService
from app.genai.providers import StaticProvider
from app.genai.reports import ReportService
from app.models import (
    IOC,
    Campaign,
    DetectionRule,
    FeedRun,
    FeedRunStatus,
    IOCType,
    Report,
    RuleType,
)
from tests.factories import make_ioc


@pytest.mark.asyncio
async def test_demo_seed_is_idempotent_and_complete(app, settings) -> None:
    anchor = datetime(2026, 8, 26, 12, tzinfo=UTC)
    first = await seed_demo(app.state.database.session_factory, settings, now=anchor)
    second = await seed_demo(app.state.database.session_factory, settings, now=anchor)
    assert first["inserted"] == len(DEMO_IOCS)
    assert second["inserted"] == 0
    async with app.state.database.session_factory() as session:
        assert await session.scalar(select(func.count(IOC.id))) == len(DEMO_IOCS)
        assert await session.scalar(select(func.count(IOC.id)).where(IOC.is_demo.is_(True))) == len(
            DEMO_IOCS
        )
        assert (await session.scalar(select(func.count(DetectionRule.id)))) > 0
        seeded_https_rule = await session.scalar(
            select(DetectionRule.rule_text)
            .join(IOC, DetectionRule.ioc_id == IOC.id)
            .where(IOC.ioc_type == IOCType.URL, DetectionRule.rule_type == RuleType.SURICATA)
        )
        assert seeded_https_rule and "alert tls" in seeded_https_rule
        assert "tls.sni" in seeded_https_rule and "http.uri" not in seeded_https_rule
        assert await session.scalar(select(func.count(Report.id))) == 1
        report = await session.scalar(select(Report))
        assert report is not None and report.is_demo is True
        assert report.facts_json["included_provenance"] == "demo"
        assert await session.scalar(select(func.count(FeedRun.id))) == 3


@pytest.mark.asyncio
async def test_detection_identity_collapses_sources_and_distinguishes_ports(app, settings) -> None:
    anchor = datetime(2026, 8, 26, 12, tzinfo=UTC)
    await seed_demo(app.state.database.session_factory, settings, now=anchor)
    async with app.state.database.session_factory() as session:
        session.add(
            make_ioc(
                value="198.51.100.24",
                port=443,
                source="live-feed-one",
                confidence_score=92,
            )
        )
        session.add(
            make_ioc(
                value="198.51.100.24",
                port=443,
                source="live-feed-two",
                confidence_score=90,
            )
        )
        session.add(
            make_ioc(
                value="198.51.100.24",
                port=8443,
                source="urlhaus",
                confidence_score=91,
            )
        )
        await session.commit()

    generated = await DetectionRuleService(app.state.database.session_factory).generate(
        minimum_confidence=0, limit=500
    )
    assert generated["analysis_scope"] == "live"
    identities = {"ip:198.51.100.24:443", "ip:198.51.100.24:8443"}
    async with app.state.database.session_factory() as session:
        rules = list(
            (
                await session.scalars(
                    select(DetectionRule)
                    .where(DetectionRule.detection_key.in_(identities))
                    .order_by(DetectionRule.detection_key, DetectionRule.rule_type)
                )
            ).all()
        )

    by_identity = {
        identity: [rule for rule in rules if rule.detection_key == identity]
        for identity in identities
    }
    assert len(by_identity["ip:198.51.100.24:443"]) == 2
    assert {tuple(rule.corroborating_sources) for rule in by_identity["ip:198.51.100.24:443"]} == {
        ("live-feed-one", "live-feed-two")
    }

    sigma_ids: set[str] = set()
    suricata_sids: set[str] = set()
    for detection_rules in by_identity.values():
        assert len(detection_rules) == 2
        for rule in detection_rules:
            if rule.rule_type is RuleType.SIGMA:
                sigma_ids.add(yaml.safe_load(rule.rule_text)["id"])
            else:
                match = re.search(r"\bsid:(\d+);", rule.rule_text)
                assert match
                suricata_sids.add(match.group(1))
    assert len(sigma_ids) == 2
    assert len(suricata_sids) == 2


@pytest.mark.asyncio
async def test_rule_api_uses_shared_confidence_bands(client, app) -> None:
    async with app.state.database.session_factory() as session:
        session.add(make_ioc(value="8.8.8.8", confidence_score=70))
        session.add(make_ioc(value="8.8.4.4", confidence_score=40))
        session.add(make_ioc(value="1.1.1.1", confidence_score=39.9))
        await session.commit()
    await DetectionRuleService(app.state.database.session_factory).generate(
        minimum_confidence=0, limit=10
    )

    rules = (await client.get("/api/v1/rules")).json()
    severities = {rule["ioc_value"]: rule["severity"] for rule in rules}
    assert severities == {"8.8.8.8": "high", "8.8.4.4": "medium", "1.1.1.1": "low"}


@pytest.mark.asyncio
async def test_dashboard_api_contract(client, app, settings) -> None:
    await seed_demo(app.state.database.session_factory, settings)
    health = await client.get("/health")
    assert health.status_code == 200
    assert health.headers["x-content-type-options"] == "nosniff"
    openapi = (await client.get("/openapi.json")).json()
    precision_schema = openapi["components"]["schemas"]["IOCProperties"]["properties"][
        "location_precision_km"
    ]
    assert "not provider-measured accuracy" in precision_schema["description"]

    collection = await client.get("/api/v1/iocs", params={"country": "DE"})
    assert collection.status_code == 200
    payload = collection.json()
    assert payload["type"] == "FeatureCollection"
    assert payload["total"] == 2
    assert payload["features"][0]["properties"]["port"] == 443
    assert all(feature["properties"]["is_demo"] is True for feature in payload["features"])
    duplicate_features = [
        feature
        for feature in payload["features"]
        if feature["properties"]["ioc_value"] == "198.51.100.24"
    ]
    assert {feature["properties"]["corroborating_feeds"] for feature in duplicate_features} == {2}
    assert all(
        feature["properties"]["corroborating_sources"] == ["feodo", "threatfox"]
        for feature in duplicate_features
    )
    detail = (await client.get(f"/api/v1/iocs/{duplicate_features[0]['id']}")).json()
    assert detail["corroborating_feeds"] == 2
    assert detail["corroborating_sources"] == ["feodo", "threatfox"]
    assert detail["is_demo"] is True

    stats = (await client.get("/api/v1/stats/summary")).json()
    assert stats["total_iocs"] == len(DEMO_IOCS)
    assert stats["demo_iocs"] == len(DEMO_IOCS)
    assert stats["live_iocs"] == 0
    assert stats["corpus_mode"] == "demo"
    assert stats["analysis_scope"] == "demo"
    assert stats["geolocated_iocs"] > 0

    campaigns = (await client.get("/api/v1/campaigns")).json()
    assert campaigns
    assert "average_ioc_confidence" in campaigns[0]
    assert "relationship_evidence" in campaigns[0]
    assert "observed_context" in campaigns[0]
    assert campaigns[0]["is_demo"] is True
    assert "countries" not in campaigns[0]["relationship_evidence"]
    assert "sources" not in campaigns[0]["relationship_evidence"]

    rule_items = (await client.get("/api/v1/rules")).json()
    assert rule_items and all(item["is_demo"] is True for item in rule_items)
    downloaded_rule = await client.get(f"/api/v1/rules/{rule_items[0]['id']}/download")
    assert "SYNTHETIC DEMO ONLY" in downloaded_rule.text
    reports = (await client.get("/api/v1/reports")).json()
    assert reports[0]["provider"] == "demo"
    assert reports[0]["is_demo"] is True
    downloaded_report = await client.get(f"/api/v1/reports/{reports[0]['id']}/download")
    assert "Provenance: SYNTHETIC DEMO ONLY" in downloaded_report.text
    feed_status = (await client.get("/api/v1/feeds/status")).json()
    assert all(item["feed"].startswith("demo-") for item in feed_status)


@pytest.mark.asyncio
async def test_summary_corpus_mode_transitions(client, app) -> None:
    empty = (await client.get("/api/v1/stats/summary")).json()
    assert (
        empty["demo_iocs"],
        empty["live_iocs"],
        empty["corpus_mode"],
        empty["analysis_scope"],
    ) == (
        0,
        0,
        "empty",
        "none",
    )

    async with app.state.database.session_factory() as session:
        session.add(make_ioc(value="8.8.8.8", source="threatfox"))
        await session.commit()
    live = (await client.get("/api/v1/stats/summary")).json()
    assert (
        live["demo_iocs"],
        live["live_iocs"],
        live["corpus_mode"],
        live["analysis_scope"],
    ) == (0, 1, "live", "live")

    async with app.state.database.session_factory() as session:
        session.add(make_ioc(value="1.1.1.1", source="feodo", is_demo=True))
        await session.commit()
    mixed = (await client.get("/api/v1/stats/summary")).json()
    assert (
        mixed["demo_iocs"],
        mixed["live_iocs"],
        mixed["corpus_mode"],
        mixed["analysis_scope"],
    ) == (
        1,
        1,
        "mixed",
        "live",
    )


@pytest.mark.asyncio
async def test_admin_and_validation_errors_are_structured(client) -> None:
    unauthorized = await client.post("/api/v1/analysis/run", headers={"X-API-Key": "wrong"})
    assert unauthorized.status_code == 401
    assert unauthorized.json()["error"]["code"] == "invalid_api_key"

    invalid = await client.get("/api/v1/iocs", params={"confidence_min": 101})
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "validation_error"


@pytest.mark.asyncio
async def test_future_derived_period_starts_are_rejected(client) -> None:
    future = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    ask = await client.post(
        "/api/v1/assistant/ask",
        json={"question": "What happened?", "date_from": future},
    )
    report = await client.post(
        "/api/v1/reports",
        json={"period_start": future},
        headers={"X-API-Key": "test-admin-key"},
    )
    assert ask.status_code == 422
    assert report.status_code == 422
    assert "future" in str(ask.json()).lower()
    assert "future" in str(report.json()).lower()


@pytest.mark.asyncio
async def test_empty_period_report_stops_before_provider_call(client, app) -> None:
    provider = StaticProvider("This must not be generated.")
    app.state.llm_provider_override = provider

    response = await client.post(
        "/api/v1/reports",
        json={},
        headers={"X-API-Key": "test-admin-key"},
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "report_no_evidence"
    assert provider.prompts == []
    async with app.state.database.session_factory() as session:
        assert await session.scalar(select(func.count(Report.id))) == 0


@pytest.mark.asyncio
async def test_api_dates_normalize_mixed_naive_and_aware_values(client, app) -> None:
    period_ioc = make_ioc(value="8.8.8.8")
    period_ioc.first_seen = datetime(2026, 1, 14, tzinfo=UTC)
    period_ioc.last_seen = datetime(2026, 1, 15, tzinfo=UTC)
    async with app.state.database.session_factory() as session:
        session.add(period_ioc)
        await session.commit()
    app.state.llm_provider_override = StaticProvider("Grounded response.")
    valid_iocs = await client.get(
        "/api/v1/iocs",
        params={
            "date_from": "2026-01-01T00:00:00",
            "date_to": "2026-02-01T00:00:00Z",
        },
    )
    valid_ask = await client.post(
        "/api/v1/assistant/ask",
        json={
            "question": "Summarize this period",
            "date_from": "2026-01-01T00:00:00",
            "date_to": "2026-02-01T00:00:00Z",
        },
    )
    valid_report = await client.post(
        "/api/v1/reports",
        json={
            "period_start": "2026-01-01T00:00:00",
            "period_end": "2026-02-01T00:00:00Z",
        },
        headers={"X-API-Key": "test-admin-key"},
    )
    assert (valid_iocs.status_code, valid_ask.status_code, valid_report.status_code) == (
        200,
        200,
        201,
    )

    invalid_iocs = await client.get(
        "/api/v1/iocs",
        params={
            "date_from": "2026-02-01T00:00:00",
            "date_to": "2026-01-01T00:00:00Z",
        },
    )
    invalid_ask = await client.post(
        "/api/v1/assistant/ask",
        json={
            "question": "Summarize this period",
            "date_from": "2026-02-01T00:00:00",
            "date_to": "2026-01-01T00:00:00Z",
        },
    )
    invalid_report = await client.post(
        "/api/v1/reports",
        json={
            "period_start": "2026-02-01T00:00:00",
            "period_end": "2026-01-01T00:00:00Z",
        },
        headers={"X-API-Key": "test-admin-key"},
    )
    assert (invalid_iocs.status_code, invalid_ask.status_code, invalid_report.status_code) == (
        422,
        422,
        422,
    )


@pytest.mark.asyncio
async def test_retrieval_grounded_ai_and_report_routes(client, app, settings) -> None:
    await seed_demo(app.state.database.session_factory, settings)
    provider = StaticProvider("Emotet is the leading family in the retrieved facts.")
    app.state.llm_provider_override = provider

    answer = await client.post(
        "/api/v1/assistant/ask", json={"question": "Which Emotet IOCs appeared this week?"}
    )
    assert answer.status_code == 200
    body = answer.json()
    assert body["provider"] == "static"
    assert body["grounded_facts"]["filters"]["malware_family"] == "Emotet"
    assert body["grounded_facts"]["indicators"][0]["record_id"].startswith("ioc:")
    assert "campaign_id" in body["grounded_facts"]["indicators"][0]
    assert "technique_ids" in body["grounded_facts"]["indicators"][0]
    assert body["grounded_facts"]["campaigns"][0]["record_id"].startswith("campaign:")
    matching_campaign_ids = {
        item["campaign_id"]
        for item in body["grounded_facts"]["indicators"]
        if item["campaign_id"] is not None
    }
    assert {item["id"] for item in body["grounded_facts"]["campaigns"]}.issubset(
        matching_campaign_ids
    )
    assert body["grounded_facts"]["recent_reports"] == []
    assert (
        body["grounded_facts"]["matching_observation_count"]
        >= body["grounded_facts"]["matching_ioc_count"]
    )
    assert provider.prompts

    report_context = await client.post(
        "/api/v1/assistant/ask",
        json={"question": "Summarize the latest weekly report"},
    )
    assert report_context.json()["grounded_facts"]["recent_reports"][0]["record_id"].startswith(
        "report:"
    )

    report = await client.post(
        "/api/v1/reports",
        json={},
        headers={"X-API-Key": "test-admin-key"},
    )
    assert report.status_code == 201
    assert report.json()["provider"] == "static"


@pytest.mark.asyncio
async def test_retrieval_matches_existing_country_dimensions(client, app, settings) -> None:
    await seed_demo(app.state.database.session_factory, settings)
    app.state.llm_provider_override = StaticProvider("Two records matched Germany.")

    response = await client.post(
        "/api/v1/assistant/ask", json={"question": "Which IPs were observed in Germany?"}
    )

    assert response.status_code == 200
    facts = response.json()["grounded_facts"]
    assert facts["filters"]["country"] == "Germany"
    assert facts["filters"]["country_code"] == "DE"
    assert facts["matching_ioc_count"] == 1
    assert facts["matching_observation_count"] == 2
    assert all(item["country"] == "Germany" for item in facts["indicators"])


@pytest.mark.asyncio
async def test_retrieval_requires_explicit_country_code_syntax(client, app, settings) -> None:
    await seed_demo(app.state.database.session_factory, settings)
    app.state.llm_provider_override = StaticProvider("Grounded response.")

    ordinary_word = await client.post(
        "/api/v1/assistant/ask",
        json={"question": "Can you show us IP indicators seen this month?"},
    )
    uppercase_code = await client.post(
        "/api/v1/assistant/ask",
        json={"question": "Which IP indicators were observed in US?"},
    )
    explicit_code = await client.post(
        "/api/v1/assistant/ask",
        json={"question": "Which indicators match country:de?"},
    )

    ordinary_facts = ordinary_word.json()["grounded_facts"]
    assert ordinary_facts["filters"]["country"] is None
    assert ordinary_facts["matching_ioc_count"] > 2
    assert uppercase_code.json()["grounded_facts"]["filters"]["country_code"] == "US"
    assert explicit_code.json()["grounded_facts"]["filters"]["country_code"] == "DE"


@pytest.mark.asyncio
async def test_retrieval_family_matching_requires_boundaries(client, app) -> None:
    async with app.state.database.session_factory() as session:
        session.add(make_ioc(value="8.8.8.8", family="RAT", source="threatfox"))
        session.add(make_ioc(value="1.1.1.1", family="Emotet", source="feodo"))
        await session.commit()
    app.state.llm_provider_override = StaticProvider("Grounded response.")

    ordinary = await client.post(
        "/api/v1/assistant/ask",
        json={"question": "Which infrastructure was corroborated recently?"},
    )
    explicit = await client.post(
        "/api/v1/assistant/ask",
        json={"question": "Which indicators match family:RAT?"},
    )
    assert ordinary.json()["grounded_facts"]["filters"]["malware_family"] is None
    assert explicit.json()["grounded_facts"]["filters"]["malware_family"] == "RAT"


@pytest.mark.asyncio
async def test_suggestion_queries_use_exact_periods_and_campaign_confidence_order(
    client, app
) -> None:
    now = datetime.now(UTC)
    high_average = Campaign(
        label="High average",
        first_seen=now - timedelta(days=3),
        last_seen=now - timedelta(days=1),
        ioc_count=2,
        is_demo=False,
        shared_attributes={
            "relationship_evidence": {},
            "observed_context": {
                "average_ioc_confidence": 98,
                "unique_indicator_count": 2,
                "observation_count": 2,
            },
        },
    )
    large_low_average = Campaign(
        label="Large low average",
        first_seen=now - timedelta(days=3),
        last_seen=now - timedelta(days=1),
        ioc_count=100,
        is_demo=False,
        shared_attributes={
            "relationship_evidence": {},
            "observed_context": {
                "average_ioc_confidence": 20,
                "unique_indicator_count": 100,
                "observation_count": 100,
            },
        },
    )
    async with app.state.database.session_factory() as session:
        session.add_all([high_average, large_low_average])
        await session.flush()
        recent = make_ioc(
            value="8.8.8.8",
            hours_old=2,
            attack_technique_ids=["T1105"],
            cluster_id=high_average.id,
        )
        old = make_ioc(
            value="1.1.1.1",
            hours_old=24 * 8,
            attack_technique_ids=["T1071"],
            cluster_id=large_low_average.id,
        )
        session.add_all([recent, old])
        await session.commit()
    app.state.llm_provider_override = StaticProvider("Grounded response.")

    campaigns = await client.post(
        "/api/v1/assistant/ask",
        json={"question": "Which campaigns have the highest average IOC confidence?"},
    )
    attack = await client.post(
        "/api/v1/assistant/ask",
        json={"question": "What are the most observed ATT&CK techniques in the last 7 days?"},
    )
    month = await client.post(
        "/api/v1/assistant/ask",
        json={"question": "What are the top malware families this month?"},
    )

    campaign_facts = campaigns.json()["grounded_facts"]
    attack_facts = attack.json()["grounded_facts"]
    month_facts = month.json()["grounded_facts"]
    assert campaign_facts["campaigns"][0]["label"] == "High average"
    assert attack_facts["attack_techniques"] == [["T1105", 1]]
    attack_start = datetime.fromisoformat(attack_facts["period_start"])
    attack_end = datetime.fromisoformat(attack_facts["period_end"])
    assert timedelta(days=6, hours=23) < attack_end - attack_start <= timedelta(days=7)
    month_start = datetime.fromisoformat(month_facts["period_start"])
    assert month_start.day == 1
    assert (month_start.hour, month_start.minute, month_start.second) == (0, 0, 0)


@pytest.mark.asyncio
async def test_retrieval_counts_and_aggregates_cover_full_filtered_set(client, app) -> None:
    async with app.state.database.session_factory() as session:
        for index in range(30):
            high_priority = index < 10
            session.add(
                make_ioc(
                    value=f"12.0.0.{index + 1}",
                    family="Emotet" if high_priority else "Mirai",
                    country="Germany" if high_priority else "France",
                    confidence_score=95 if high_priority else 45,
                    attack_technique_ids=["T1105"] if high_priority else ["T1071"],
                )
            )
        session.add(
            make_ioc(
                value="12.0.0.1",
                source="urlhaus",
                family="Emotet",
                country="Germany",
                confidence_score=95,
                attack_technique_ids=["T1105"],
            )
        )
        await session.commit()
    app.state.llm_provider_override = StaticProvider("Grounded response.")

    response = await client.post(
        "/api/v1/assistant/ask", json={"question": "Summarize recent indicators"}
    )
    facts = response.json()["grounded_facts"]
    assert facts["matching_ioc_count"] == 30
    assert facts["matching_observation_count"] == 31
    assert facts["retrieved_observation_count"] == 25
    assert facts["truncated"] is True
    assert facts["top_malware_families"][0] == ["Mirai", 20]
    assert facts["observed_host_countries"][0] == ["France", 20]
    assert facts["attack_techniques"][0] == ["T1071", 20]


@pytest.mark.asyncio
async def test_weekly_report_facts_are_exact_with_bounded_samples(app) -> None:
    now = datetime.now(UTC)
    async with app.state.database.session_factory() as session:
        for index in range(40):
            session.add(
                make_ioc(
                    value=f"11.0.0.{index + 1}",
                    port=443,
                    source="threatfox" if index % 2 else "urlhaus",
                    family="Emotet" if index < 30 else "Mirai",
                    confidence_score=90 if index < 20 else 60,
                    country="Germany" if index < 25 else "France",
                    asn="AS64500" if index < 35 else "AS64501",
                    attack_technique_ids=["T1105"] if index < 32 else ["T1071"],
                )
            )
        session.add(
            make_ioc(
                value="11.0.0.1",
                port=443,
                source="threatfox",
                family="Emotet",
                confidence_score=90,
                country="Germany",
                asn="AS64500",
                attack_technique_ids=["T1105"],
            )
        )
        await session.commit()
        facts = await ReportService.collect_facts(
            session, now - timedelta(days=7), now + timedelta(minutes=1)
        )

    assert facts["total_observations"] == 41
    assert facts["unique_indicator_count"] == 40
    assert facts["high_confidence_observations"] == 21
    assert len(facts["sample_high_confidence_observations"]) == 25
    assert facts["top_malware_families_by_observation"][0] == ["Emotet", 31]
    assert facts["top_observed_host_countries_by_observation"][0] == ["Germany", 26]
    assert facts["top_asns_by_observation"][0] == ["AS64500", 36]
    assert sum(count for _, count in facts["source_observation_distribution"]) == 41
    assert facts["ioc_type_observation_distribution"] == [["ip", 41]]
    assert facts["attack_technique_observation_counts"][0] == ["T1105", 33]


@pytest.mark.asyncio
async def test_manual_analysis_includes_rule_generation(client, app, settings) -> None:
    settings.minimum_rule_confidence = 0
    async with app.state.database.session_factory() as session:
        session.add(make_ioc(value="8.8.8.8", port=443, source="threatfox"))
        await session.commit()

    response = await client.post("/api/v1/analysis/run", headers={"X-API-Key": "test-admin-key"})

    assert response.status_code == 200
    rules = response.json()["details"]["rules"]
    assert rules["unique_detections"] == 1
    assert rules["created"] == 2
    async with app.state.database.session_factory() as session:
        assert await session.scalar(select(func.count(DetectionRule.id))) == 2


@pytest.mark.asyncio
async def test_feed_health_requires_recent_success(client, app, settings) -> None:
    assert (await client.get("/api/v1/stats/summary")).json()["feed_health"] == 0
    now = datetime.now(UTC)
    async with app.state.database.session_factory() as session:
        session.add_all(
            [
                FeedRun(
                    feed_name="urlhaus",
                    status=FeedRunStatus.SUCCEEDED,
                    started_at=now - timedelta(minutes=2),
                    completed_at=now - timedelta(minutes=1),
                ),
                FeedRun(
                    feed_name="threatfox",
                    status=FeedRunStatus.SUCCEEDED,
                    started_at=now - timedelta(hours=settings.feed_sync_hours * 3),
                    completed_at=now - timedelta(hours=settings.feed_sync_hours * 3),
                ),
                FeedRun(
                    feed_name="feodo",
                    status=FeedRunStatus.FAILED,
                    started_at=now - timedelta(minutes=2),
                    completed_at=now - timedelta(minutes=1),
                ),
            ]
        )
        await session.commit()
    assert (await client.get("/api/v1/stats/summary")).json()["feed_health"] == 33.3

    async with app.state.database.session_factory() as session:
        run = await session.scalar(select(FeedRun).where(FeedRun.feed_name == "urlhaus"))
        assert run is not None
        run.status = FeedRunStatus.PARTIAL
        await session.commit()
    assert (await client.get("/api/v1/stats/summary")).json()["feed_health"] == 0


@pytest.mark.asyncio
async def test_disabled_ai_has_actionable_error(client) -> None:
    response = await client.post(
        "/api/v1/assistant/ask", json={"question": "What happened this week?"}
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "llm_disabled"
