from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.detection_rules.generator import detection_key
from app.models import IOC, AttackTechnique, Campaign, DetectionRule, Report


async def build_ioc_lineage(session: AsyncSession, ioc: IOC) -> dict[str, Any]:
    """Assemble only persisted, provenance-isolated evidence for an IOC observation."""

    observations = list(
        (
            await session.scalars(
                select(IOC)
                .where(
                    IOC.ioc_type == ioc.ioc_type,
                    IOC.indicator_key == ioc.indicator_key,
                    IOC.is_demo.is_(ioc.is_demo),
                )
                .order_by(IOC.source_feed, IOC.id)
            )
        ).all()
    )
    technique_ids = list(dict.fromkeys(ioc.attack_technique_ids or []))
    techniques = (
        list(
            (
                await session.scalars(
                    select(AttackTechnique).where(AttackTechnique.technique_id.in_(technique_ids))
                )
            ).all()
        )
        if technique_ids
        else []
    )
    techniques_by_id = {item.technique_id: item for item in techniques}
    campaign = await session.get(Campaign, ioc.cluster_id) if ioc.cluster_id else None
    rules = list(
        (
            await session.scalars(
                select(DetectionRule)
                .join(IOC, DetectionRule.ioc_id == IOC.id)
                .where(
                    DetectionRule.detection_key == detection_key(ioc),
                    IOC.is_demo.is_(ioc.is_demo),
                )
                .order_by(DetectionRule.rule_type, DetectionRule.id)
            )
        ).all()
    )
    reports = list(
        (
            await session.scalars(
                select(Report)
                .where(Report.is_demo.is_(ioc.is_demo))
                .order_by(Report.created_at.desc(), Report.id.desc())
                .limit(100)
            )
        ).all()
    )

    raw_payload = ioc.raw_json if isinstance(ioc.raw_json, dict) else {}
    canonical_payload = json.dumps(
        raw_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    components = _valid_confidence_components(ioc.confidence_components)
    confidence_available = bool(
        ioc.confidence_model_version and ioc.confidence_scored_at and components
    )
    return {
        "indicator_id": ioc.id,
        "record_id": f"ioc:{ioc.id}",
        "identity": {
            "value": ioc.ioc_value,
            "type": ioc.ioc_type,
            "port": ioc.port,
            "is_demo": ioc.is_demo,
        },
        "provenance": {
            "selected_source": ioc.source_feed,
            "observations": [
                {
                    "record_id": f"ioc:{item.id}",
                    "source_feed": item.source_feed,
                    "first_seen": item.first_seen,
                    "last_seen": item.last_seen,
                    "source_confidence_hint": item.source_confidence_hint,
                    "is_selected": item.id == ioc.id,
                }
                for item in observations
            ],
            "raw_payload": {
                "retained": bool(raw_payload),
                "sha256": hashlib.sha256(canonical_payload).hexdigest() if raw_payload else None,
                "field_names": sorted(str(key)[:128] for key in raw_payload)[:50],
            },
        },
        "confidence": {
            "status": "available" if confidence_available else "pending",
            "total": ioc.confidence_score,
            "formula_version": ioc.confidence_model_version,
            "calculated_at": ioc.confidence_scored_at,
            "components": components if confidence_available else [],
        },
        "enrichment": _enrichment_evidence(ioc),
        "attack_mappings": [
            {
                "record_id": f"technique:{technique_id}",
                "technique_id": technique_id,
                "name": techniques_by_id[technique_id].name,
                "tactic": techniques_by_id[technique_id].tactic,
                "method": "reviewed_family_alias_catalog_v1",
                "basis": ioc.malware_family,
                "inference": True,
            }
            for technique_id in technique_ids
            if technique_id in techniques_by_id
        ],
        "campaign_membership": _campaign_membership(ioc, campaign),
        "derived_artifacts": {
            "rules": [
                {
                    "record_id": f"rule:{rule.id}",
                    "rule_type": rule.rule_type,
                    "requires_review": rule.requires_review,
                    "generated_at": rule.generated_at,
                }
                for rule in rules
            ],
            "report_mentions": [
                {
                    "record_id": f"report:{report.id}",
                    "title": report.title,
                    "period_start": report.period_start,
                    "period_end": report.period_end,
                }
                for report in reports
                if _report_explicitly_mentions(report, ioc.id)
            ],
        },
        "limitations": [
            "Confidence is a deterministic prioritization heuristic, not a probability.",
            "ATT&CK mappings are family-level analytic context, not observed host behavior.",
            "Geolocation is approximate infrastructure context and may be stale.",
            "Campaign membership is the current correlation snapshot, not durable attribution.",
            "Generated detections require analyst review before deployment.",
        ],
    }


def _valid_confidence_components(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        try:
            score = float(item["score"])
            max_score = float(item["max_score"])
            key = str(item["key"])
            label = str(item["label"])
            evidence = str(item["evidence"])
        except (KeyError, TypeError, ValueError):
            continue
        if not key or not label or max_score <= 0 or score < 0 or score > max_score:
            continue
        result.append(
            {
                "key": key[:64],
                "label": label[:128],
                "score": round(score, 1),
                "max_score": round(max_score, 1),
                "evidence": evidence[:300],
            }
        )
    return result


def _enrichment_evidence(ioc: IOC) -> dict[str, Any]:
    if ioc.ioc_type.value != "ip":
        status = "not_applicable"
        method = "Only literal IP observations are geolocated; domains are never resolved."
    elif ioc.latitude is None or ioc.longitude is None:
        status = "unavailable"
        method = "No cached literal-IP enrichment is available."
    else:
        status = "available"
        method = (
            "Curated synthetic location context."
            if ioc.is_demo
            else "Cached literal-IP geolocation and ASN lookup."
        )
    return {
        "status": status,
        # The provider is not persisted today, so do not infer one from runtime config.
        "provider": "demo-seed" if status == "available" and ioc.is_demo else None,
        "method": method,
        "country": ioc.country,
        "country_code": ioc.country_code,
        "city": ioc.city,
        "asn": ioc.asn,
        "asn_org": ioc.asn_org,
        "approximate": status == "available",
    }


def _campaign_membership(ioc: IOC, campaign: Campaign | None) -> dict[str, Any] | None:
    if campaign is None or campaign.is_demo != ioc.is_demo:
        return None
    evidence = (campaign.shared_attributes or {}).get("relationship_evidence", {})
    reasons: list[str] = []
    for item in evidence.get("repeated_indicators", []):
        if (
            isinstance(item, dict)
            and item.get("ioc_type") == ioc.ioc_type.value
            and item.get("indicator_key") == ioc.indicator_key
        ):
            reasons.append(
                "Repeated indicator across "
                f"{int(item.get('observation_count', 0))} source observations"
            )
    for item in evidence.get("malware_families", []):
        if (
            isinstance(item, dict)
            and ioc.malware_family
            and str(item.get("value", "")).casefold() == ioc.malware_family.casefold()
        ):
            reasons.append(
                "Shared malware-family context across "
                f"{int(item.get('unique_indicator_count', 0))} indicators"
            )
    for item in evidence.get("asns", []):
        if (
            isinstance(item, dict)
            and ioc.asn
            and str(item.get("value", "")).upper() == ioc.asn.upper()
        ):
            reasons.append(
                f"Shared ASN context across {int(item.get('unique_indicator_count', 0))} indicators"
            )
    return {
        "record_id": f"campaign:{campaign.id}",
        "label": campaign.label,
        "snapshot": "current",
        "reasons": reasons,
    }


def _report_explicitly_mentions(report: Report, ioc_id: int) -> bool:
    facts = report.facts_json if isinstance(report.facts_json, dict) else {}
    samples = facts.get("sample_high_confidence_observations", [])
    if not isinstance(samples, list):
        return False
    record_id = f"ioc:{ioc_id}"
    return any(
        isinstance(item, dict) and (item.get("record_id") == record_id or item.get("id") == ioc_id)
        for item in samples
    )
