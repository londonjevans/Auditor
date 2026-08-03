"""Typed client/forensic report projections derived from one final audit report."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from decimal import Decimal
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from mmaudit.models.schemas import (
    AuditQualityStatus,
    AuditReport,
    AuditRunStatus,
    AuditScopeAssessment,
    CandidateCrossExaminationDecision,
    CandidateCrossExaminationVerdict,
    CandidateFinding,
    CandidateReproductionResolution,
    FalsificationDecision,
    Finding,
    FindingStatus,
    ModelReviewCoverage,
    QualityGateResult,
    ReproductionResolutionKind,
    ReproductionResult,
    SolidityCoverage,
    StrictModel,
    UsageRecord,
    VerificationDecision,
)

MANIFEST_BOUND_REPORT_DELIVERABLES = frozenset(
    {
        "client-report.md",
        "forensic-report.md",
        "findings.json",
        "audit-results.sarif",
        "coverage.json",
        "model-execution.json",
    }
)
REQUIRED_REPORT_DELIVERABLES = frozenset(
    {*MANIFEST_BOUND_REPORT_DELIVERABLES, "run-evidence-manifest.json"}
)


class ForensicDisposition(StrEnum):
    """Client-facing projection that cannot increase deterministic finding authority."""

    CONFIRMED = "CONFIRMED"
    SUPPORTED = "SUPPORTED"
    DISPUTED = "DISPUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    REJECTED = "REJECTED"


class SourceExcerptEvidence(StrictModel):
    """A small source excerpt bound to the discovered file and cited range."""

    path: str = Field(min_length=1, max_length=4_096)
    symbol: str | None = Field(default=None, max_length=1_000)
    file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    cited_start_line: int = Field(ge=1)
    cited_end_line: int = Field(ge=1)
    cited_content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    excerpt_start_line: int = Field(ge=1)
    excerpt_end_line: int = Field(ge=1)
    content: str = Field(max_length=16_384)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    omitted_before: bool
    omitted_after: bool

    @model_validator(mode="after")
    def excerpt_is_self_consistent(self) -> SourceExcerptEvidence:
        if (
            self.cited_end_line < self.cited_start_line
            or self.excerpt_end_line < self.excerpt_start_line
            or self.excerpt_start_line > self.cited_start_line
            or self.excerpt_end_line < self.cited_end_line
        ):
            raise ValueError("source excerpt line bounds are inconsistent")
        if hashlib.sha256(self.content.encode()).hexdigest() != self.content_sha256:
            raise ValueError("source excerpt content hash is inconsistent")
        if len(self.content.splitlines()) != self.excerpt_end_line - self.excerpt_start_line + 1:
            raise ValueError("source excerpt line count is inconsistent")
        return self


class ForensicFindingRecord(StrictModel):
    """One final finding with all candidate-linked review evidence kept together."""

    finding_id: str = Field(min_length=1)
    disposition: ForensicDisposition
    finding: Finding
    source_excerpt: SourceExcerptEvidence | None = None
    candidate_findings: list[CandidateFinding] = Field(default_factory=list)
    verification_decisions: list[VerificationDecision] = Field(default_factory=list)
    cross_examination_decisions: list[CandidateCrossExaminationDecision] = Field(
        default_factory=list
    )
    falsification_decisions: list[FalsificationDecision] = Field(default_factory=list)
    reproductions: list[ReproductionResult] = Field(default_factory=list)
    reproduction_resolutions: list[CandidateReproductionResolution] = Field(default_factory=list)

    @model_validator(mode="after")
    def evidence_is_linked_to_the_finding(self) -> ForensicFindingRecord:
        if self.finding_id != self.finding.id:
            raise ValueError("forensic finding ID differs from the embedded finding")
        contributor_ids = set(self.finding.contributing_candidate_ids)
        linked_ids = {
            *(candidate.candidate_id for candidate in self.candidate_findings),
            *(decision.candidate_id for decision in self.verification_decisions),
            *(decision.candidate_id for decision in self.cross_examination_decisions),
            *(decision.candidate_id for decision in self.falsification_decisions),
            *(result.candidate_id for result in self.reproductions),
            *(resolution.candidate_id for resolution in self.reproduction_resolutions),
        }
        if not linked_ids <= contributor_ids:
            raise ValueError("forensic evidence references a non-contributing candidate")
        if self.finding.status is FindingStatus.REJECTED:
            if self.disposition is not ForensicDisposition.REJECTED:
                raise ValueError("rejected finding requires rejected forensic disposition")
            complete_collections = (
                self.finding.preconditions,
                self.finding.locations,
                self.finding.attack_path,
                self.finding.evidence,
                self.finding.false_positive_conditions,
            )
            if (
                any(not value for value in complete_collections)
                or not self.finding.impact
                or not self.finding.recommendation
                or self.finding.verification_test is None
                or not self.finding.disagreement
            ):
                raise ValueError("forensic rejected finding requires complete retained evidence")
        elif self.disposition is ForensicDisposition.REJECTED:
            raise ValueError("active finding cannot receive rejected forensic disposition")
        return self


class FindingsArtifact(StrictModel):
    """Complete final/candidate finding history for the forensic bundle."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: str = Field(min_length=1, max_length=160)
    run_status: AuditRunStatus
    quality_status: AuditQualityStatus
    completed: bool
    findings: list[Finding]
    rejected_findings: list[Finding]
    records: list[ForensicFindingRecord]
    candidate_findings: list[CandidateFinding] = Field(default_factory=list)

    @model_validator(mode="after")
    def inventory_is_exact_and_unique(self) -> FindingsArtifact:
        expected = [*self.findings, *self.rejected_findings]
        if [record.finding for record in self.records] != expected:
            raise ValueError("forensic records differ from the final finding inventories")
        identifiers = [finding.id for finding in expected]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("forensic finding IDs must be unique")
        candidate_ids = [candidate.candidate_id for candidate in self.candidate_findings]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("forensic candidate IDs must be unique")
        return self


class CoverageArtifact(StrictModel):
    """Compact typed coverage projection with full typed coverage bodies retained."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: str = Field(min_length=1, max_length=160)
    run_status: AuditRunStatus
    completed: bool
    scope_assessment: AuditScopeAssessment | None
    solidity_coverage: SolidityCoverage | None
    model_review_coverage: ModelReviewCoverage | None
    quality_gates: list[QualityGateResult]
    limitations: list[str]


class ModelExecutionArtifact(StrictModel):
    """Non-secret model execution and cost evidence for the forensic bundle."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: str = Field(min_length=1, max_length=160)
    run_status: AuditRunStatus
    completed: bool
    configured_models: dict[str, str]
    configured_fallbacks: dict[str, list[str]]
    requested_models: list[str]
    actual_models: list[str]
    provider_endpoints: list[str]
    usage: list[UsageRecord]
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    reasoning_tokens: int = Field(ge=0)
    cached_tokens: int = Field(ge=0)
    accounted_cost_usd: float = Field(ge=0)
    accounted_cost_usd_exact: str = Field(pattern=r"^(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,36})?$")
    budget_usd: float = Field(ge=0)
    privacy_profile: str
    source_code_egress_enabled: bool
    raw_prompts_retained: bool
    raw_responses_retained: bool

    @model_validator(mode="after")
    def totals_are_exact(self) -> ModelExecutionArtifact:
        if self.prompt_tokens != sum(record.prompt_tokens for record in self.usage):
            raise ValueError("model execution prompt-token total is inconsistent")
        if self.completion_tokens != sum(record.completion_tokens for record in self.usage):
            raise ValueError("model execution completion-token total is inconsistent")
        if self.reasoning_tokens != sum(record.reasoning_tokens for record in self.usage):
            raise ValueError("model execution reasoning-token total is inconsistent")
        if self.cached_tokens != sum(record.cached_tokens for record in self.usage):
            raise ValueError("model execution cached-token total is inconsistent")
        if Decimal(self.accounted_cost_usd_exact) != Decimal(str(self.accounted_cost_usd)):
            raise ValueError("model execution exact cost differs from presentation cost")
        return self


def effective_run_status(report: AuditReport) -> AuditRunStatus:
    """Return the typed status, or a calibrated projection for legacy reports."""

    if report.run_status is not None:
        return report.run_status
    if report.quality_status in {
        AuditQualityStatus.FAILED,
        AuditQualityStatus.ENVIRONMENT_UNSAFE,
        AuditQualityStatus.TARGET_UNSUPPORTED,
    }:
        return AuditRunStatus.FAILED
    if not report.completed or report.quality_status is AuditQualityStatus.INCOMPLETE:
        return AuditRunStatus.INCOMPLETE
    if report.quality_status is AuditQualityStatus.COMPLETED_WITH_LIMITATIONS:
        return AuditRunStatus.DEGRADED
    return AuditRunStatus.COMPLETE


def _disposition(
    finding: Finding,
    cross_examinations: Sequence[CandidateCrossExaminationDecision],
    resolutions: Sequence[CandidateReproductionResolution],
) -> ForensicDisposition:
    if finding.status is FindingStatus.REJECTED:
        return ForensicDisposition.REJECTED
    contributor_ids = set(finding.contributing_candidate_ids)
    if any(
        decision.candidate_id in contributor_ids
        and decision.verdict is CandidateCrossExaminationVerdict.DISPUTED
        for decision in cross_examinations
    ):
        return ForensicDisposition.DISPUTED
    if any(
        resolution.candidate_id in contributor_ids
        and resolution.kind is ReproductionResolutionKind.INCONCLUSIVE
        for resolution in resolutions
    ) or finding.status in {
        FindingStatus.NEEDS_REVIEW,
        FindingStatus.INSUFFICIENT_CONTEXT,
        FindingStatus.UNSUPPORTED,
    }:
        return ForensicDisposition.INCONCLUSIVE
    if finding.status is FindingStatus.CONFIRMED:
        return ForensicDisposition.CONFIRMED
    return ForensicDisposition.SUPPORTED


def build_findings_artifact(
    report: AuditReport,
    *,
    candidates: Sequence[CandidateFinding] = (),
    reproduction_resolutions: Sequence[CandidateReproductionResolution] = (),
    source_excerpts: Mapping[str, SourceExcerptEvidence] | None = None,
) -> FindingsArtifact:
    """Build an exact candidate-linked forensic finding inventory."""

    report = AuditReport.model_validate(report.model_dump(mode="python"))
    candidate_by_id = {candidate.candidate_id: candidate for candidate in candidates}
    excerpts = source_excerpts or {}
    records: list[ForensicFindingRecord] = []
    for finding in [*report.findings, *report.rejected_findings]:
        contributor_ids = set(finding.contributing_candidate_ids)
        linked_candidates = [
            candidate_by_id[candidate_id]
            for candidate_id in finding.contributing_candidate_ids
            if candidate_id in candidate_by_id
        ]
        linked_verifications = [
            item for item in report.verification_decisions if item.candidate_id in contributor_ids
        ]
        linked_cross_examinations = [
            item
            for item in report.cross_examination_decisions
            if item.candidate_id in contributor_ids
        ]
        linked_falsifications = [
            item for item in report.falsification_decisions if item.candidate_id in contributor_ids
        ]
        linked_reproductions = [
            item for item in report.reproductions if item.candidate_id in contributor_ids
        ]
        linked_resolutions = [
            item for item in reproduction_resolutions if item.candidate_id in contributor_ids
        ]
        records.append(
            ForensicFindingRecord(
                finding_id=finding.id,
                disposition=_disposition(
                    finding,
                    linked_cross_examinations,
                    linked_resolutions,
                ),
                finding=finding,
                source_excerpt=excerpts.get(finding.id),
                candidate_findings=linked_candidates,
                verification_decisions=linked_verifications,
                cross_examination_decisions=linked_cross_examinations,
                falsification_decisions=linked_falsifications,
                reproductions=linked_reproductions,
                reproduction_resolutions=linked_resolutions,
            )
        )
    return FindingsArtifact(
        run_id=report.run_id,
        run_status=effective_run_status(report),
        quality_status=report.quality_status,
        completed=report.completed,
        findings=list(report.findings),
        rejected_findings=list(report.rejected_findings),
        records=records,
        candidate_findings=list(candidates),
    )


def build_coverage_artifact(report: AuditReport) -> CoverageArtifact:
    """Build the canonical forensic coverage projection."""

    report = AuditReport.model_validate(report.model_dump(mode="python"))
    return CoverageArtifact(
        run_id=report.run_id,
        run_status=effective_run_status(report),
        completed=report.completed,
        scope_assessment=report.scope_assessment,
        solidity_coverage=report.effective_solidity_coverage(),
        model_review_coverage=report.model_review_coverage,
        quality_gates=list(report.quality_gates),
        limitations=list(report.incomplete_reasons),
    )


def _string_mapping(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {
        str(key): item
        for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        if isinstance(item, str)
    }


def _fallback_mapping(value: object) -> dict[str, list[str]]:
    if not isinstance(value, Mapping):
        return {}
    normalized: dict[str, list[str]] = {}
    for key, item in sorted(value.items(), key=lambda pair: str(pair[0])):
        if isinstance(item, (list, tuple)) and all(isinstance(entry, str) for entry in item):
            normalized[str(key)] = list(item)
    return normalized


def build_model_execution_artifact(report: AuditReport) -> ModelExecutionArtifact:
    """Build a non-secret model execution projection from validated usage records."""

    report = AuditReport.model_validate(report.model_dump(mode="python"))
    usage = list(report.usage)
    exact_cost = format(Decimal(str(report.accounted_cost_usd)), "f")
    return ModelExecutionArtifact(
        run_id=report.run_id,
        run_status=effective_run_status(report),
        completed=report.completed,
        configured_models=_string_mapping(report.metadata.get("configured_models")),
        configured_fallbacks=_fallback_mapping(report.metadata.get("configured_fallbacks")),
        requested_models=sorted({record.requested_model for record in usage}),
        actual_models=sorted(
            {
                model
                for record in usage
                for model in (record.actual_model or record.returned_model,)
                if model is not None
            }
        ),
        provider_endpoints=sorted(
            {
                endpoint
                for record in usage
                for endpoint in (
                    [record.actual_provider_endpoint]
                    if record.actual_provider_endpoint is not None
                    else record.configured_provider_endpoints
                )
            }
        ),
        usage=usage,
        prompt_tokens=sum(record.prompt_tokens for record in usage),
        completion_tokens=sum(record.completion_tokens for record in usage),
        reasoning_tokens=sum(record.reasoning_tokens for record in usage),
        cached_tokens=sum(record.cached_tokens for record in usage),
        accounted_cost_usd=report.accounted_cost_usd,
        accounted_cost_usd_exact=exact_cost,
        budget_usd=report.budget_usd,
        privacy_profile=str(report.privacy.get("profile", "UNKNOWN")),
        source_code_egress_enabled=bool(report.privacy.get("code_egress_enabled", False)),
        raw_prompts_retained=bool(report.privacy.get("store_raw_prompts", False)),
        raw_responses_retained=bool(report.privacy.get("store_raw_responses", False)),
    )
