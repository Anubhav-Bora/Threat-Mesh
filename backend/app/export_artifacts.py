from __future__ import annotations

import argparse
import asyncio
import os
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select

from app.config import Settings
from app.database import Database
from app.detection_rules import artifact_filename
from app.models import DetectionRule, Report


@dataclass
class ExportStats:
    written: int = 0
    skipped_existing: int = 0


def _write_atomic(path: Path, content: str, *, overwrite: bool) -> bool:
    if path.exists() and not overwrite:
        return False
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    temporary.replace(path)
    return True


async def export_artifacts(
    database: Database,
    *,
    rules_dir: Path | None,
    reports_dir: Path | None,
    overwrite: bool = False,
) -> dict[str, ExportStats]:
    """Export database artifacts without overwriting operator edits by default."""

    result = {"rules": ExportStats(), "reports": ExportStats()}
    async with database.session_factory() as session:
        if rules_dir is not None:
            await asyncio.to_thread(rules_dir.mkdir, parents=True, exist_ok=True)
            rules = list(
                (
                    await session.scalars(
                        select(DetectionRule).order_by(
                            DetectionRule.rule_type, DetectionRule.detection_key
                        )
                    )
                ).all()
            )
            for rule in rules:
                path = rules_dir / artifact_filename(rule.detection_key, rule.rule_type)
                if _write_atomic(path, rule.rule_text.rstrip() + "\n", overwrite=overwrite):
                    result["rules"].written += 1
                else:
                    result["rules"].skipped_existing += 1
        if reports_dir is not None:
            await asyncio.to_thread(reports_dir.mkdir, parents=True, exist_ok=True)
            reports = list(
                (await session.scalars(select(Report).order_by(Report.created_at))).all()
            )
            for report in reports:
                filename = f"{report.period_end.date().isoformat()}-report-{report.id}.md"
                provenance = (
                    "SYNTHETIC DEMO ONLY — not live threat intelligence."
                    if report.is_demo
                    else "Live-corpus analysis."
                )
                content = (
                    f"# {report.title}\n\n> Provenance: {provenance}\n\n"
                    f"{report.report_text.rstrip()}\n"
                )
                if _write_atomic(reports_dir / filename, content, overwrite=overwrite):
                    result["reports"].written += 1
                else:
                    result["reports"].skipped_existing += 1
    return result


async def _main() -> None:
    parser = argparse.ArgumentParser(
        description="Export ThreatMesh rules/reports for explicit human review and versioning"
    )
    parser.add_argument("--rules-dir", type=Path)
    parser.add_argument("--reports-dir", type=Path)
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Explicitly replace files with the same stable artifact name",
    )
    args = parser.parse_args()
    if args.rules_dir is None and args.reports_dir is None:
        parser.error("provide --rules-dir, --reports-dir, or both")
    database = Database(Settings())
    try:
        result = await export_artifacts(
            database,
            rules_dir=args.rules_dir,
            reports_dir=args.reports_dir,
            overwrite=args.overwrite,
        )
        print(
            "Export complete — "
            f"rules: {result['rules'].written} written, "
            f"{result['rules'].skipped_existing} preserved; "
            f"reports: {result['reports'].written} written, "
            f"{result['reports'].skipped_existing} preserved."
        )
    finally:
        await database.dispose()


if __name__ == "__main__":
    asyncio.run(_main())
