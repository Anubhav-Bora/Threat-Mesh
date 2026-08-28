from __future__ import annotations

from fastapi import APIRouter, Request

from app.api.dependencies import AIRateLimitDep
from app.api.schemas import AskRequest, AskResponse, AssistantCitation, CitationIntegrity
from app.genai import RetrievalQAService, build_provider

router = APIRouter(prefix="/assistant", tags=["AI assistant"])


@router.post("/ask", response_model=AskResponse)
async def ask(body: AskRequest, request: Request, _: AIRateLimitDep) -> AskResponse:
    provider = getattr(request.app.state, "llm_provider_override", None) or build_provider(
        request.app.state.settings
    )
    service = RetrievalQAService(
        request.app.state.database.session_factory,
        provider,
        max_rows=request.app.state.settings.llm_max_context_rows,
    )
    result = await service.answer(body.question, date_from=body.date_from, date_to=body.date_to)
    return AskResponse(
        answer=result.text,
        provider=result.provider,
        model=result.model,
        grounded_facts=result.facts,
        citations=[
            AssistantCitation(
                record_id=citation.record_id,
                kind=citation.kind,
                label=citation.label,
            )
            for citation in result.citations
        ],
        citation_integrity=CitationIntegrity(
            status=result.citation_integrity.status,
            validated_count=result.citation_integrity.validated_count,
            rejected_count=result.citation_integrity.rejected_count,
        ),
    )
