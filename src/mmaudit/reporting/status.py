"""Canonical public projection of audit completion, quality, and limitations."""

from __future__ import annotations

from pydantic import model_validator

from mmaudit.models.schemas import (
    AnalysisState,
    AuditQualityStatus,
    AuditReport,
    AuditRunStatus,
    QualityGateResult,
    StrictModel,
)

LEGACY_MINIMUM_FLOOR_LIMITATION = (
    "legacy report lacks typed minimum-analysis-floor evidence; completion cannot be established"
)


def quality_status_for_run_status(status: AuditRunStatus) -> AuditQualityStatus:
    """Return the sole public quality status compatible with a terminal run status."""

    return {
        AuditRunStatus.COMPLETE: AuditQualityStatus.COMPLETED,
        AuditRunStatus.DEGRADED: AuditQualityStatus.COMPLETED_WITH_LIMITATIONS,
        AuditRunStatus.INCOMPLETE: AuditQualityStatus.INCOMPLETE,
        AuditRunStatus.FAILED: AuditQualityStatus.FAILED,
    }[status]


class ReportStatusProjection(StrictModel):
    """One internally consistent status projection shared by every report deliverable."""

    run_status: AuditRunStatus
    quality_status: AuditQualityStatus
    completed: bool
    quality_gates: list[QualityGateResult]
    limitations: list[str]

    @model_validator(mode="after")
    def status_quality_and_limitations_are_consistent(self) -> ReportStatusProjection:
        if self.quality_status is not quality_status_for_run_status(self.run_status):
            raise ValueError("report quality status conflicts with the effective run status")
        if self.completed != (self.run_status is AuditRunStatus.COMPLETE):
            raise ValueError("report completion conflicts with the effective run status")
        if self.limitations != list(dict.fromkeys(self.limitations)):
            raise ValueError("report limitations must be unique and ordered")
        if self.run_status is AuditRunStatus.COMPLETE and self.limitations:
            raise ValueError("COMPLETE report projection cannot retain incomplete limitations")
        if self.run_status is not AuditRunStatus.COMPLETE and not self.limitations:
            raise ValueError("non-complete report projection requires a prominent limitation")
        floor_gates = [gate for gate in self.quality_gates if gate.gate == "minimum_analysis_floor"]
        if len(floor_gates) != 1 or not floor_gates[0].required:
            raise ValueError("report projection requires one status-consistent minimum-floor gate")
        if self.run_status is AuditRunStatus.COMPLETE and not floor_gates[0].passed:
            raise ValueError("COMPLETE report projection requires a passing minimum-floor gate")
        if self.completed and any(gate.required and not gate.passed for gate in self.quality_gates):
            raise ValueError("COMPLETE report projection contains a failed required quality gate")
        return self


def effective_report_status(report: AuditReport) -> ReportStatusProjection:
    """Project current evidence exactly and fail legacy no-floor reports closed."""

    report = AuditReport.model_validate(report.model_dump(mode="python"))
    if report.schema_version == "1.2":
        assert report.run_status is not None
        return ReportStatusProjection(
            run_status=report.run_status,
            quality_status=quality_status_for_run_status(report.run_status),
            completed=report.run_status is AuditRunStatus.COMPLETE,
            quality_gates=list(report.quality_gates),
            limitations=list(dict.fromkeys(report.incomplete_reasons)),
        )

    run_status = (
        AuditRunStatus.FAILED
        if report.quality_status
        in {
            AuditQualityStatus.FAILED,
            AuditQualityStatus.ENVIRONMENT_UNSAFE,
            AuditQualityStatus.TARGET_UNSUPPORTED,
        }
        else AuditRunStatus.INCOMPLETE
    )
    limitation = LEGACY_MINIMUM_FLOOR_LIMITATION
    legacy_floor_gate = QualityGateResult(
        gate="minimum_analysis_floor",
        required=True,
        passed=False,
        detail=limitation,
        state=(
            AnalysisState.ATTEMPTED_FAILED
            if run_status is AuditRunStatus.FAILED
            else AnalysisState.NOT_ANALYZED
        ),
    )
    return ReportStatusProjection(
        run_status=run_status,
        quality_status=quality_status_for_run_status(run_status),
        completed=False,
        quality_gates=[
            legacy_floor_gate,
            *(gate for gate in report.quality_gates if gate.gate != "minimum_analysis_floor"),
        ],
        limitations=list(dict.fromkeys([limitation, *report.incomplete_reasons])),
    )
