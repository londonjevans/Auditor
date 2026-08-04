"""Test-only helpers for emitting exact private terminal report authority."""

from __future__ import annotations

from pathlib import Path

from mmaudit.models.scheduler import SchedulerArtifact
from mmaudit.models.schemas import AuditReport
from mmaudit.reporting.json_report import write_json
from mmaudit.reporting.run_authority import (
    RUN_TERMINAL_REPORT_AUTHORITY_PATH,
    RunTerminalReportAuthority,
)


def write_run_terminal_report_authority(
    run_dir: Path,
    report: AuditReport,
    *,
    scheduler_artifact: SchedulerArtifact | None = None,
) -> Path:
    """Write the same exact private authority emitted by the production pipeline."""

    path = run_dir / RUN_TERMINAL_REPORT_AUTHORITY_PATH
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    write_json(
        path,
        RunTerminalReportAuthority.build(
            report,
            scheduler_artifact=scheduler_artifact,
        ),
    )
    path.chmod(0o600)
    return path
