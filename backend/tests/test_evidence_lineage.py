from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.detection_rules.generator import detection_key
from app.models import (
    IOC,
    Campaign,
    DetectionRule,
    IOCType,
    Report,
    ReportCadence,
    RuleType,
)
from app.scoring import CONFIDENCE_MODEL_VERSION, ConfidenceService, confidence_breakdown
from tests.factories import make_ioc


def test_confidence_breakdown_has_exact_bounded_components_and_timestamp() -> None:
    scored_at = datetime(2026, 9, 3, 17, 30, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    ioc = make_ioc(
        source="feodo",
        family="Emotet",
        asn="AS64500",
        attack_technique_ids=["T1105"],
    )
    ioc.last_seen = scored_at.astimezone(UTC)

    breakdown = confidence_breakdown(ioc, corroborating_feeds=999, now=scored_at)
    components = {component.key: component for component in breakdown.components}

    assert breakdown.calculated_at == scored_at.astimezone(UTC)
    assert breakdown.formula_version == CONFIDENCE_MODEL_VERSION
    assert {key: component.score for key, component in components.items()} == {
        "source_reputation": 38.0,
        "corroboration": 20.0,
        "recency": 30.0,
        "context": 10.0,
    }
    assert all(0 <= component.score <= component.max_score for component in breakdown.components)
    assert breakdown.total == 98.0
    assert breakdown.total == sum(component.score for component in breakdown.components)


@pytest.mark.asyncio
async def test_confidence_batch_persists_one_shared_scored_at(app) -> None:
    async with app.state.database.session_factory() as session:
        session.add_all(
            [
                make_ioc(value="8.8.8.8", source="threatfox"),
                make_ioc(value="8.8.4.4", source="urlhaus"),
                make_ioc(value="1.1.1.1", source="feodo"),
            ]
        )
        await session.commit()

    result = await ConfidenceService(app.state.database.session_factory).recalculate()

    async with app.state.database.session_factory() as session:
        indicators = list((await session.scalars(select(IOC).order_by(IOC.id))).all())

    assert result["updated"] == 3
    assert len({ioc.confidence_scored_at for ioc in indicators}) == 1
    assert indicators[0].confidence_scored_at is not None
    for ioc in indicators:
        assert ioc.confidence_model_version == CONFIDENCE_MODEL_VERSION
        assert ioc.confidence_components is not None
        assert ioc.confidence_score == round(
            sum(float(component["score"]) for component in ioc.confidence_components), 1
        )


@pytest.mark.asyncio
async def test_lineage_api_exposes_persisted_evidence_without_crossing_scope_or_port(
    client, app
) -> None:
    observed_at = datetime(2026, 9, 3, 12, tzinfo=UTC)
    secret_value = "raw-feed-secret-must-not-leak"
    raw_payload = {
        "auth_token": secret_value,
        "nested": {"operator_note": "untrusted payload value"},
        "status": "online",
    }
    async with app.state.database.session_factory() as session:
        campaign = Campaign(
            label="Emotet infrastructure lead",
            first_seen=observed_at - timedelta(days=2),
            last_seen=observed_at,
            ioc_count=1,
            is_demo=False,
            shared_attributes={
                "relationship_evidence": {
                    "repeated_indicators": [
                        {
                            "ioc_type": "ip",
                            "indicator_key": "8.8.8.8:443",
                            "observation_count": 2,
                        }
                    ],
                    "malware_families": [{"value": "Emotet", "unique_indicator_count": 3}],
                    "asns": [{"value": "AS64500", "unique_indicator_count": 2}],
                },
                "observed_context": {},
            },
        )
        session.add(campaign)
        await session.flush()
        selected = make_ioc(
            value="8.8.8.8",
            port=443,
            source="threatfox",
            source_confidence_hint=0.9,
            attack_technique_ids=["T1105"],
            asn="AS64500",
            cluster_id=campaign.id,
        )
        selected.raw_json = raw_payload
        corroborating = make_ioc(
            value="8.8.8.8",
            port=443,
            source="urlhaus",
            source_confidence_hint=0.8,
        )
        other_port = make_ioc(
            value="8.8.8.8",
            port=8443,
            source="feodo",
        )
        demo_copy = make_ioc(
            value="8.8.8.8",
            port=443,
            source="demo-feed",
            is_demo=True,
        )
        session.add_all(
            [
                selected,
                corroborating,
                other_port,
                demo_copy,
            ]
        )
        await session.flush()
        selected_id = selected.id
        demo_id = demo_copy.id
        session.add(
            DetectionRule(
                ioc_id=corroborating.id,
                detection_key=detection_key(selected),
                rule_type=RuleType.SIGMA,
                rule_text="title: Test lineage rule",
                corroborating_sources=["threatfox", "urlhaus"],
                generated_at=observed_at,
                requires_review=True,
            )
        )
        session.add_all(
            [
                Report(
                    period_start=observed_at - timedelta(days=7),
                    period_end=observed_at,
                    title="Report with explicit IOC evidence",
                    report_text="Grounded report",
                    provider="static",
                    model="test",
                    cadence=ReportCadence.WEEKLY,
                    facts_json={
                        "sample_high_confidence_observations": [{"record_id": f"ioc:{selected_id}"}]
                    },
                    is_demo=False,
                ),
                Report(
                    period_start=observed_at - timedelta(days=7),
                    period_end=observed_at,
                    title="Report without the IOC",
                    report_text="Other evidence",
                    provider="static",
                    model="test",
                    cadence=ReportCadence.WEEKLY,
                    facts_json={"sample_high_confidence_observations": []},
                    is_demo=False,
                ),
                Report(
                    period_start=observed_at - timedelta(days=7),
                    period_end=observed_at,
                    title="Demo report must stay isolated",
                    report_text="Synthetic evidence",
                    provider="demo",
                    model="demo",
                    cadence=ReportCadence.WEEKLY,
                    facts_json={
                        "sample_high_confidence_observations": [{"record_id": f"ioc:{selected_id}"}]
                    },
                    is_demo=True,
                ),
            ]
        )
        await session.commit()

    await ConfidenceService(app.state.database.session_factory).recalculate()

    response = await client.get(f"/api/v1/iocs/{selected_id}/lineage")
    assert response.status_code == 200
    payload = response.json()

    assert payload["record_id"] == f"ioc:{selected_id}"
    assert payload["confidence"]["status"] == "available"
    assert payload["confidence"]["formula_version"] == CONFIDENCE_MODEL_VERSION
    assert payload["confidence"]["calculated_at"] is not None
    assert (
        sum(item["score"] for item in payload["confidence"]["components"])
        == payload["confidence"]["total"]
    )
    assert {item["source_feed"] for item in payload["provenance"]["observations"]} == {
        "threatfox",
        "urlhaus",
    }
    assert all(
        item["record_id"] != f"ioc:{demo_id}" for item in payload["provenance"]["observations"]
    )
    assert payload["provenance"]["raw_payload"] == {
        "retained": True,
        "sha256": hashlib.sha256(
            json.dumps(
                raw_payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                default=str,
            ).encode("utf-8")
        ).hexdigest(),
        "field_names": ["auth_token", "nested", "status"],
    }
    assert secret_value not in response.text
    assert "untrusted payload value" not in response.text
    assert payload["attack_mappings"] == [
        {
            "record_id": "technique:T1105",
            "technique_id": "T1105",
            "name": "Ingress Tool Transfer",
            "tactic": "command-and-control",
            "method": "reviewed_family_alias_catalog_v1",
            "basis": "Emotet",
            "inference": True,
        }
    ]
    membership = payload["campaign_membership"]
    assert membership["snapshot"] == "current"
    assert membership["record_id"] == f"campaign:{campaign.id}"
    assert membership["reasons"] == [
        "Repeated indicator across 2 source observations",
        "Shared malware-family context across 3 indicators",
        "Shared ASN context across 2 indicators",
    ]
    assert len(payload["derived_artifacts"]["rules"]) == 1
    assert payload["derived_artifacts"]["rules"][0]["requires_review"] is True
    assert [item["title"] for item in payload["derived_artifacts"]["report_mentions"]] == [
        "Report with explicit IOC evidence"
    ]

    demo_payload = (await client.get(f"/api/v1/iocs/{demo_id}/lineage")).json()
    assert [item["source_feed"] for item in demo_payload["provenance"]["observations"]] == [
        "demo-feed"
    ]
    assert demo_payload["derived_artifacts"]["rules"] == []


@pytest.mark.asyncio
async def test_lineage_api_marks_unscored_confidence_as_pending(client, app) -> None:
    ioc = make_ioc(
        value="example.test",
        ioc_type=IOCType.DOMAIN,
        port=None,
        family=None,
    )
    ioc.raw_json = {}
    async with app.state.database.session_factory() as session:
        session.add(ioc)
        await session.commit()
        ioc_id = ioc.id

    response = await client.get(f"/api/v1/iocs/{ioc_id}/lineage")

    assert response.status_code == 200
    payload = response.json()
    assert payload["confidence"] == {
        "status": "pending",
        "total": 0.0,
        "formula_version": None,
        "calculated_at": None,
        "components": [],
    }
    assert payload["provenance"]["raw_payload"] == {
        "retained": False,
        "sha256": None,
        "field_names": [],
    }
