"""Private terminal authority for one exact emitted audit report."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal, Self

from pydantic import Field, model_validator

from mmaudit.models.scheduler import SchedulerArtifact
from mmaudit.models.schemas import AuditProfile, AuditReport, MaximumAssuranceStatus, StrictModel

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


class RunTerminalReportAuthority(StrictModel):
    """Write-once private comparison authority for public report semantics."""

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    algorithm: Literal["mmaudit.run-terminal-report-authority.v1"] = (
        "mmaudit.run-terminal-report-authority.v1"
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
    report_payload_sha256: str = Field(pattern=_SHA256_PATTERN)
    authority_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        report: AuditReport,
        *,
        scheduler_artifact: SchedulerArtifact | None = None,
    ) -> RunTerminalReportAuthority:
        """Bind one fully validated report before any public manifest is issued."""

        validated = AuditReport.model_validate(report.model_dump(mode="python"))
        validated_scheduler = (
            SchedulerArtifact.model_validate(scheduler_artifact.model_dump(mode="python"))
            if scheduler_artifact is not None
            else None
        )
        payload = validated.model_dump(mode="json")
        achieved_profile: AuditProfile | None = None
        if validated.completed:
            if validated.audit_profile is not AuditProfile.MAXIMUM_ASSURANCE:
                achieved_profile = validated.audit_profile
            elif (
                validated.maximum_assurance is not None
                and validated.maximum_assurance.status is MaximumAssuranceStatus.COMPLETE
            ):
                achieved_profile = AuditProfile.MAXIMUM_ASSURANCE
        values = {
            "schema_version": "1.0",
            "evidence_authority": "comparison_required",
            "algorithm": "mmaudit.run-terminal-report-authority.v1",
            "run_id": validated.run_id,
            "scheduler_campaign_id": (
                validated_scheduler.summary.manifest.campaign_id
                if validated_scheduler is not None
                else None
            ),
            "scheduler_manifest_sha256": (
                validated_scheduler.summary.manifest.manifest_sha256
                if validated_scheduler is not None
                else None
            ),
            "scheduler_summary_sha256": (
                validated_scheduler.summary.summary_sha256
                if validated_scheduler is not None
                else None
            ),
            "scheduler_artifact_sha256": (
                validated_scheduler.artifact_sha256 if validated_scheduler is not None else None
            ),
            "scheduler_campaign_status": (
                validated_scheduler.summary.status.value
                if validated_scheduler is not None
                else None
            ),
            "report_schema_version": validated.schema_version,
            "audit_profile": validated.audit_profile.value,
            "achieved_profile": (achieved_profile.value if achieved_profile is not None else None),
            "run_status": validated.run_status.value if validated.run_status is not None else None,
            "quality_status": validated.quality_status.value,
            "completed": validated.completed,
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
            "quality_gates_sha256": _canonical_sha256(payload["quality_gates"]),
            "incomplete_reasons_sha256": _canonical_sha256(payload["incomplete_reasons"]),
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

        if self != type(self).build(report, scheduler_artifact=scheduler_artifact):
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
        if self.authority_sha256 != _canonical_sha256(
            self.model_dump(mode="json", exclude={"authority_sha256"})
        ):
            raise ValueError("run terminal report authority hash is inconsistent")
        return self
