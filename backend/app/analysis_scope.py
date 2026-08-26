from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from sqlalchemy import case, false, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from app.models import IOC

AnalysisScope = Literal["none", "demo", "live"]
CorpusMode = Literal["empty", "demo", "live", "mixed"]


@dataclass(frozen=True)
class ScopeSelection:
    """A deterministic live-first view over a possibly mixed IOC corpus."""

    analysis_scope: AnalysisScope
    corpus_mode: CorpusMode
    demo_observations: int
    live_observations: int

    @property
    def included_is_demo(self) -> bool | None:
        if self.analysis_scope == "demo":
            return True
        if self.analysis_scope == "live":
            return False
        return None

    def ioc_condition(self) -> ColumnElement[bool]:
        if self.included_is_demo is None:
            return false()
        return IOC.is_demo.is_(self.included_is_demo)


async def resolve_analysis_scope(
    session: AsyncSession,
    *conditions: ColumnElement[bool],
) -> ScopeSelection:
    """Select live observations when present, otherwise demo observations.

    ``conditions`` normally define a reporting or retrieval period. This keeps
    synthetic quick-start records from strengthening or obscuring live analysis.
    """

    demo_count, live_count = (
        await session.execute(
            select(
                func.coalesce(func.sum(case((IOC.is_demo.is_(True), 1), else_=0)), 0),
                func.coalesce(func.sum(case((IOC.is_demo.is_(False), 1), else_=0)), 0),
            ).where(*conditions)
        )
    ).one()
    return scope_from_counts(int(demo_count), int(live_count))


def scope_from_counts(demo_observations: int, live_observations: int) -> ScopeSelection:
    if demo_observations and live_observations:
        mode: CorpusMode = "mixed"
    elif demo_observations:
        mode = "demo"
    elif live_observations:
        mode = "live"
    else:
        mode = "empty"

    if live_observations:
        analysis_scope: AnalysisScope = "live"
    elif demo_observations:
        analysis_scope = "demo"
    else:
        analysis_scope = "none"
    return ScopeSelection(
        analysis_scope=analysis_scope,
        corpus_mode=mode,
        demo_observations=demo_observations,
        live_observations=live_observations,
    )
