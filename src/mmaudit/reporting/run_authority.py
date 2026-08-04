"""Private terminal authority for one exact emitted audit report."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from typing import Any, Literal, Self

from pydantic import Field, model_validator

from mmaudit.models.scheduler import SchedulerArtifact
from mmaudit.models.schemas import (
    AuditProfile,
    AuditReport,
    AuditRunStatus,
    MaximumAssuranceAssessment,
    MaximumAssuranceStatus,
    MinimumAnalysisFloor,
    StrictModel,
)
from mmaudit.reporting.status import ReportStatusProjection, effective_report_status

RUN_TERMINAL_REPORT_AUTHORITY_PATH = "private/run-terminal-report-authority.json"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _exact_report_cost(report: AuditReport) -> str:
    return report.accounted_cost_usd_exact or format(Decimal(str(report.accounted_cost_usd)), "f")


def _achieved_profile(
    report: AuditReport,
    status: ReportStatusProjection,
) -> AuditProfile | None:
    if not status.completed:
        return None
    if report.audit_profile is not AuditProfile.MAXIMUM_ASSURANCE:
        return report.audit_profile
    if (
        report.maximum_assurance is not None
        and report.maximum_assurance.status is MaximumAssuranceStatus.COMPLETE
    ):
        return AuditProfile.MAXIMUM_ASSURANCE
    return None


def _scheduler_values(scheduler: SchedulerArtifact | None) -> dict[str, str | None]:
    return {
        "scheduler_campaign_id": (
            scheduler.summary.manifest.campaign_id if scheduler is not None else None
        ),
        "scheduler_manifest_sha256": (
            scheduler.summary.manifest.manifest_sha256 if scheduler is not None else None
        ),
        "scheduler_summary_sha256": (
            scheduler.summary.summary_sha256 if scheduler is not None else None
        ),
        "scheduler_artifact_sha256": scheduler.artifact_sha256 if scheduler is not None else None,
        "scheduler_campaign_status": (
            scheduler.summary.status.value if scheduler is not None else None
        ),
    }


def _require_coherent_terminal_exit_code(
    run_status: AuditRunStatus | str | None,
    terminal_exit_code: int,
) -> None:
    """Reject terminal process outcomes that contradict the effective run state."""

    normalized = run_status.value if isinstance(run_status, AuditRunStatus) else run_status
    if normalized == AuditRunStatus.COMPLETE.value and terminal_exit_code != 0:
        raise ValueError("runtime terminal exit code conflicts with the effective run status")
    if (
        normalized
        in {
            AuditRunStatus.INCOMPLETE.value,
            AuditRunStatus.FAILED.value,
        }
        and terminal_exit_code == 0
    ):
        raise ValueError("runtime terminal exit code conflicts with the effective run status")


class RunTerminalReportAuthority(StrictModel):
    """Write-once private comparison authority for public report semantics."""

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    algorithm: Literal["mmaudit.run-terminal-report-authority.v2"] = (
        "mmaudit.run-terminal-report-authority.v2"
    )
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    scheduler_campaign_id: str | None = Field(
        default=None,
        pattern=r"^scheduler-campaign-[0-9a-f]{64}$",
    )
    scheduler_manifest_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    scheduler_summary_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    scheduler_artifact_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    scheduler_campaign_status: str | None = Field(default=None, max_length=100)
    report_schema_version: str = Field(min_length=1, max_length=20)
    audit_profile: str = Field(min_length=1, max_length=100)
    achieved_profile: str | None = Field(default=None, max_length=100)
    run_status: str | None = Field(default=None, max_length=100)
    quality_status: str = Field(min_length=1, max_length=100)
    completed: bool
    minimum_analysis_floor_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    maximum_assurance_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    quality_gates_sha256: str = Field(pattern=_SHA256_PATTERN)
    incomplete_reasons_sha256: str = Field(pattern=_SHA256_PATTERN)
    terminal_exit_code: int = Field(ge=0, le=255)
    accounted_cost_usd_exact: str = Field(min_length=1, max_length=100)
    runtime_assessment_sha256: str = Field(pattern=_SHA256_PATTERN)
    report_payload_sha256: str = Field(pattern=_SHA256_PATTERN)
    authority_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        report: AuditReport,
        *,
        scheduler_artifact: SchedulerArtifact | None = None,
    ) -> RunTerminalReportAuthority:
        """Build deterministic synthetic fixture authority from a report projection."""

        validated = AuditReport.model_validate(report.model_dump(mode="python"))
        status = effective_report_status(validated)
        return cls.build_from_runtime(
            report=validated,
            status=status,
            minimum_analysis_floor=validated.minimum_analysis_floor,
            maximum_assurance=validated.maximum_assurance,
            accounted_cost_usd_exact=_exact_report_cost(validated),
            terminal_exit_code=(
                0 if status.run_status in {AuditRunStatus.COMPLETE, AuditRunStatus.DEGRADED} else 6
            ),
            scheduler_artifact=scheduler_artifact,
        )

    @classmethod
    def build_from_runtime(
        cls,
        *,
        report: AuditReport,
        status: ReportStatusProjection,
        minimum_analysis_floor: MinimumAnalysisFloor | None,
        maximum_assurance: MaximumAssuranceAssessment | None,
        accounted_cost_usd_exact: str,
        terminal_exit_code: int,
        scheduler_artifact: SchedulerArtifact | None = None,
    ) -> RunTerminalReportAuthority:
        """Bind public report bytes to independently supplied terminal runtime values."""

        validated = AuditReport.model_validate(report.model_dump(mode="python"))
        validated_status = ReportStatusProjection.model_validate(status.model_dump(mode="python"))
        validated_floor = (
            MinimumAnalysisFloor.model_validate(minimum_analysis_floor.model_dump(mode="python"))
            if minimum_analysis_floor is not None
            else None
        )
        validated_maximum = (
            MaximumAssuranceAssessment.model_validate(maximum_assurance.model_dump(mode="python"))
            if maximum_assurance is not None
            else None
        )
        validated_scheduler = (
            SchedulerArtifact.model_validate(scheduler_artifact.model_dump(mode="python"))
            if scheduler_artifact is not None
            else None
        )
        if effective_report_status(validated) != validated_status:
            raise ValueError("runtime terminal status differs from the validated report")
        if validated.minimum_analysis_floor != validated_floor:
            raise ValueError("runtime minimum analysis floor differs from the validated report")
        if validated.maximum_assurance != validated_maximum:
            raise ValueError("runtime maximum assurance differs from the validated report")
        if _exact_report_cost(validated) != accounted_cost_usd_exact:
            raise ValueError("runtime accounted cost differs from the validated report")
        _require_coherent_terminal_exit_code(validated_status.run_status, terminal_exit_code)
        payload = validated.model_dump(mode="json")
        achieved_profile = _achieved_profile(validated, validated_status)
        runtime_values: dict[str, Any] = {
            "schema_version": "1.0",
            "evidence_authority": "comparison_required",
            "algorithm": "mmaudit.run-terminal-report-authority.v2",
            "run_id": validated.run_id,
            **_scheduler_values(validated_scheduler),
            "report_schema_version": validated.schema_version,
            "audit_profile": validated.audit_profile.value,
            "achieved_profile": (achieved_profile.value if achieved_profile is not None else None),
            "run_status": validated_status.run_status.value,
            "quality_status": validated_status.quality_status.value,
            "completed": validated_status.completed,
            "minimum_analysis_floor_sha256": (
                _canonical_sha256(validated_floor.model_dump(mode="json"))
                if validated_floor is not None
                else None
            ),
            "maximum_assurance_sha256": (
                _canonical_sha256(validated_maximum.model_dump(mode="json"))
                if validated_maximum is not None
                else None
            ),
            "quality_gates_sha256": _canonical_sha256(
                [gate.model_dump(mode="json") for gate in validated_status.quality_gates]
            ),
            "incomplete_reasons_sha256": _canonical_sha256(validated_status.limitations),
            "terminal_exit_code": terminal_exit_code,
            "accounted_cost_usd_exact": accounted_cost_usd_exact,
        }
        values = {
            **runtime_values,
            "runtime_assessment_sha256": _canonical_sha256(runtime_values),
            "report_payload_sha256": _canonical_sha256(payload),
        }
        return cls(**values, authority_sha256=_canonical_sha256(values))

    def require_exact_report(
        self,
        report: AuditReport,
        *,
        scheduler_artifact: SchedulerArtifact | None = None,
    ) -> None:
        """Reject every change to the validated public report projection."""

        validated = AuditReport.model_validate(report.model_dump(mode="python"))
        validated_scheduler = (
            SchedulerArtifact.model_validate(scheduler_artifact.model_dump(mode="python"))
            if scheduler_artifact is not None
            else None
        )
        status = effective_report_status(validated)
        payload = validated.model_dump(mode="json")
        observed = {
            "run_id": validated.run_id,
            **_scheduler_values(validated_scheduler),
            "report_schema_version": validated.schema_version,
            "audit_profile": validated.audit_profile.value,
            "achieved_profile": (
                achieved.value
                if (achieved := _achieved_profile(validated, status)) is not None
                else None
            ),
            "run_status": status.run_status.value,
            "quality_status": status.quality_status.value,
            "completed": status.completed,
            "minimum_analysis_floor_sha256": (
                _canonical_sha256(payload["minimum_analysis_floor"])
                if payload["minimum_analysis_floor"] is not None
                else None
            ),
            "maximum_assurance_sha256": (
                _canonical_sha256(payload["maximum_assurance"])
                if payload["maximum_assurance"] is not None
                else None
            ),
            "quality_gates_sha256": _canonical_sha256(
                [gate.model_dump(mode="json") for gate in status.quality_gates]
            ),
            "incomplete_reasons_sha256": _canonical_sha256(status.limitations),
            "accounted_cost_usd_exact": _exact_report_cost(validated),
            "report_payload_sha256": _canonical_sha256(payload),
        }
        if any(getattr(self, field) != value for field, value in observed.items()):
            raise ValueError("public report differs from private terminal report authority")

    @model_validator(mode="after")
    def authority_is_self_hash_bound(self) -> Self:
        scheduler_fields = (
            self.scheduler_campaign_id,
            self.scheduler_manifest_sha256,
            self.scheduler_summary_sha256,
            self.scheduler_artifact_sha256,
            self.scheduler_campaign_status,
        )
        if any(value is not None for value in scheduler_fields) != all(
            value is not None for value in scheduler_fields
        ):
            raise ValueError("run terminal report scheduler authority is incomplete")
        _require_coherent_terminal_exit_code(self.run_status, self.terminal_exit_code)
        runtime_values = self.model_dump(
            mode="json",
            exclude={
                "runtime_assessment_sha256",
                "report_payload_sha256",
                "authority_sha256",
            },
        )
        if self.runtime_assessment_sha256 != _canonical_sha256(runtime_values):
            raise ValueError("run terminal runtime assessment hash is inconsistent")
        if self.authority_sha256 != _canonical_sha256(
            self.model_dump(mode="json", exclude={"authority_sha256"})
        ):
            raise ValueError("run terminal report authority hash is inconsistent")
        return self
