from __future__ import annotations

from fastapi import APIRouter, Query, Request, Response
from sqlalchemy import select

from app.api.dependencies import AdminDep, SessionDep
from app.api.schemas import OperationResult, RuleGenerationRequest, RuleResponse
from app.detection_rules import DetectionRuleService, artifact_filename, confidence_level
from app.errors import AppError
from app.models import IOC, DetectionRule, RuleType

router = APIRouter(prefix="/rules", tags=["detection rules"])


@router.get("", response_model=list[RuleResponse])
async def list_rules(
    session: SessionDep,
    rule_type: RuleType | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[RuleResponse]:
    query = select(DetectionRule)
    if rule_type:
        query = query.where(DetectionRule.rule_type == rule_type)
    rows = list(
        (
            await session.execute(
                query.join(IOC, DetectionRule.ioc_id == IOC.id)
                .add_columns(IOC)
                .order_by(DetectionRule.generated_at.desc())
                .offset(offset)
                .limit(limit)
            )
        ).all()
    )
    return [
        RuleResponse.model_validate(rule).model_copy(
            update={
                "malware_family": ioc.malware_family,
                "ioc_value": ioc.ioc_value,
                "severity": confidence_level(ioc.confidence_score),
                "tags": list(ioc.attack_technique_ids or []),
                "is_demo": ioc.is_demo,
            }
        )
        for rule, ioc in rows
    ]


@router.post("/generate", response_model=OperationResult)
async def generate_rules(
    body: RuleGenerationRequest, request: Request, _: AdminDep
) -> OperationResult:
    service = DetectionRuleService(request.app.state.database.session_factory)
    details = await service.generate(minimum_confidence=body.minimum_confidence, limit=body.limit)
    return OperationResult(details=details)


@router.get("/{rule_id}/download")
async def download_rule(rule_id: int, session: SessionDep) -> Response:
    rule = await session.get(DetectionRule, rule_id)
    if rule is None:
        raise AppError(404, "rule_not_found", f"Detection rule {rule_id} was not found")
    filename = artifact_filename(rule.detection_key, rule.rule_type)
    return Response(
        content=rule.rule_text,
        media_type="text/yaml" if rule.rule_type is RuleType.SIGMA else "text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
