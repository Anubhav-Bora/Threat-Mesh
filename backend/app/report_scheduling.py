from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models import ReportCadence, ReportSchedule
from app.models.base import utcnow

REPORT_SCHEDULE_ID = 1
WEEKDAY_INDEX = {
    "mon": 0,
    "tue": 1,
    "wed": 2,
    "thu": 3,
    "fri": 4,
    "sat": 5,
    "sun": 6,
}


class ReportScheduleStore:
    """Persists the single automatic-report cadence for one deployment."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def get(self) -> ReportSchedule:
        async with self.session_factory() as session:
            schedule = await session.get(ReportSchedule, REPORT_SCHEDULE_ID)
            if schedule is not None:
                return schedule
            schedule = ReportSchedule(
                id=REPORT_SCHEDULE_ID,
                cadence=ReportCadence.WEEKLY,
            )
            session.add(schedule)
            try:
                await session.commit()
            except IntegrityError:
                # Another process may have initialized the singleton concurrently.
                await session.rollback()
                schedule = await session.get(ReportSchedule, REPORT_SCHEDULE_ID)
                if schedule is None:
                    raise
            else:
                await session.refresh(schedule)
            return schedule

    async def set(self, cadence: ReportCadence) -> ReportSchedule:
        async with self.session_factory() as session:
            schedule = await session.get(ReportSchedule, REPORT_SCHEDULE_ID)
            if schedule is None:
                schedule = ReportSchedule(id=REPORT_SCHEDULE_ID, cadence=cadence)
                session.add(schedule)
            else:
                schedule.cadence = cadence
                schedule.updated_at = utcnow()
            await session.commit()
            await session.refresh(schedule)
            return schedule


def calendar_report_period(
    cadence: ReportCadence,
    reference: datetime,
    *,
    weekly_day: str = "mon",
) -> tuple[datetime, datetime]:
    """Return the last complete UTC calendar period for a scheduled run."""

    current = _utc(reference)
    if cadence is ReportCadence.MONTHLY:
        end = datetime(current.year, current.month, 1, tzinfo=UTC)
        if end.month == 1:
            start = datetime(end.year - 1, 12, 1, tzinfo=UTC)
        else:
            start = datetime(end.year, end.month - 1, 1, tzinfo=UTC)
        return start, end

    target_weekday = WEEKDAY_INDEX[weekly_day]
    days_since_boundary = (current.weekday() - target_weekday) % 7
    end = (current - timedelta(days=days_since_boundary)).replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0,
    )
    return end - timedelta(days=7), end


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
