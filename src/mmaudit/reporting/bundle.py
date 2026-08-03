"""Typed client/forensic report projections derived from one final audit report."""

from __future__ import annotations

import hashlib
import re
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
    FalsificationVerdict,
    Finding,
    FindingStatus,
    ModelReviewCoverage,
    QualityGateResult,
    ReproductionResolutionKind,
    ReproductionResult,
    ReproductionState,
    SolidityCoverage,
    StrictModel,
    UsageRecord,
    VerificationDecision,
    VerificationVerdict,
)
from mmaudit.repository.chunking import line_range_hash

_MAX_SOURCE_EXCERPT_EVIDENCE_BYTES = 1_000_000

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
    content: str = Field(max_length=_MAX_SOURCE_EXCERPT_EVIDENCE_BYTES)
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
        relative_start = self.cited_start_line - self.excerpt_start_line + 1
        relative_end = self.cited_end_line - self.excerpt_start_line + 1
        if line_range_hash(self.content, relative_start, relative_end) != self.cited_content_sha256:
            raise ValueError("source excerpt cited range hash is inconsistent")
        if self.symbol is not None and not source_symbol_is_present(
            self.symbol,
            "".join(self.content.splitlines(keepends=True)[relative_start - 1 : relative_end]),
        ):
            raise ValueError("source excerpt symbol is absent from the cited range")
        return self


def source_symbol_is_present(symbol: str, content: str) -> bool:
    """Match a source symbol as an identifier, never as a substring of another symbol."""

    base = symbol.split("(", maxsplit=1)[0].rsplit(".", maxsplit=1)[-1]
    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", base) is None:
        return False
    return re.search(rf"(?<![A-Za-z0-9_$]){re.escape(base)}(?![A-Za-z0-9_$])", content) is not None


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
        candidate_ids = [candidate.candidate_id for candidate in self.candidate_findings]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("forensic candidate evidence must be unique")
        if candidate_ids and set(candidate_ids) != contributor_ids:
            raise ValueError("forensic candidate evidence does not close the contributor set")
        unique_keys: tuple[tuple[str, list[object]], ...] = (
            (
                "verification decisions",
                [decision.candidate_id for decision in self.verification_decisions],
            ),
            (
                "cross-examination decisions",
                [
                    (
                        decision.candidate_id,
                        decision.request_id,
                        decision.reviewer_index,
                        decision.root_lineage,
                    )
                    for decision in self.cross_examination_decisions
                ],
            ),
            (
                "falsification decisions",
                [
                    (decision.candidate_id, decision.test_name)
                    for decision in self.falsification_decisions
                ],
            ),
            (
                "reproductions",
                [(result.candidate_id, result.test_name) for result in self.reproductions],
            ),
            (
                "reproduction resolutions",
                [resolution.candidate_id for resolution in self.reproduction_resolutions],
            ),
        )
        for label, keys in unique_keys:
            if len(keys) != len(set(keys)):
                raise ValueError(f"forensic {label} must be unique")
        if self.finding.status is FindingStatus.REJECTED:
            if self.disposition is not ForensicDisposition.REJECTED:
                raise ValueError("rejected finding requires rejected forensic disposition")
            retained_rejection_evidence = bool(
                self.candidate_findings
                or self.finding.evidence
                or self.finding.location_validation.errors
                or self.verification_decisions
                or self.cross_examination_decisions
                or self.falsification_decisions
                or self.reproductions
                or self.reproduction_resolutions
                or self.finding.execution_provenance
            )
            retained_rejection_rationale = bool(
                self.finding.disagreement
                or self.finding.location_validation.errors
                or any(decision.rationale for decision in self.verification_decisions)
                or any(decision.rationale for decision in self.cross_examination_decisions)
                or any(decision.rationale for decision in self.falsification_decisions)
                or any(resolution.detail for resolution in self.reproduction_resolutions)
                or any(result.limitations for result in self.reproductions)
            )
            if not retained_rejection_rationale or not retained_rejection_evidence:
                raise ValueError(
                    "forensic rejected finding requires complete retained evidence "
                    f"(contributors={len(contributor_ids)}, "
                    f"candidates={len(self.candidate_findings)}, "
                    f"evidence={len(self.finding.evidence)}, "
                    f"location_errors={len(self.finding.location_validation.errors)}, "
                    f"decisions={len(self.verification_decisions) + len(self.cross_examination_decisions) + len(self.falsification_decisions)}, "
                    "including an evidence-backed rejection rationale"
                )
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
        expected_findings = [*self.findings, *self.rejected_findings]
        if [record.finding for record in self.records] != expected_findings:
            raise ValueError("forensic records differ from the final finding inventories")
        identifiers = [finding.id for finding in expected_findings]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("forensic finding IDs must be unique")
        candidate_ids = [candidate.candidate_id for candidate in self.candidate_findings]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("forensic candidate IDs must be unique")
        candidate_id_set = set(candidate_ids)
        referenced_candidate_ids = {
            candidate_id
            for record in self.records
            for candidate_id in record.finding.contributing_candidate_ids
        }
        if not candidate_id_set <= referenced_candidate_ids:
            raise ValueError("forensic candidate inventory contains an orphan record")
        for record in self.records:
            expected_candidate_ids = (
                set(record.finding.contributing_candidate_ids) & candidate_id_set
            )
            observed = {candidate.candidate_id for candidate in record.candidate_findings}
            if observed != expected_candidate_ids:
                raise ValueError("forensic record omits candidate inventory evidence")
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
    # Legacy reports cannot carry the typed minimum-analysis-floor evidence that
    # current reports require. They remain readable, but a new client deliverable
    # must never project their historical ``completed`` flag as evidence of COMPLETE.
    return AuditRunStatus.INCOMPLETE


def _disposition(
    finding: Finding,
    verifications: Sequence[VerificationDecision],
    cross_examinations: Sequence[CandidateCrossExaminationDecision],
    falsifications: Sequence[FalsificationDecision],
    reproductions: Sequence[ReproductionResult],
    resolutions: Sequence[CandidateReproductionResolution],
) -> ForensicDisposition:
    if finding.status is FindingStatus.REJECTED:
        return ForensicDisposition.REJECTED
    contributor_ids = set(finding.contributing_candidate_ids)
    if (
        any(
            decision.candidate_id in contributor_ids
            and decision.verdict is CandidateCrossExaminationVerdict.DISPUTED
            for decision in cross_examinations
        )
        or any(
            decision.candidate_id in contributor_ids
            and decision.verdict is VerificationVerdict.REJECTED
            for decision in verifications
        )
        or any(
            decision.candidate_id in contributor_ids
            and decision.verdict is FalsificationVerdict.FALSIFIED
            for decision in falsifications
        )
        or any(
            result.candidate_id in contributor_ids and result.state is ReproductionState.DISPROVEN
            for result in reproductions
        )
    ):
        return ForensicDisposition.DISPUTED
    if (
        any(
            resolution.candidate_id in contributor_ids
            and resolution.kind is ReproductionResolutionKind.INCONCLUSIVE
            for resolution in resolutions
        )
        or any(
            decision.candidate_id in contributor_ids
            and decision.verdict is VerificationVerdict.INSUFFICIENT_CONTEXT
            for decision in verifications
        )
        or any(
            decision.candidate_id in contributor_ids
            and decision.verdict is CandidateCrossExaminationVerdict.INCONCLUSIVE
            for decision in cross_examinations
        )
        or any(
            decision.candidate_id in contributor_ids
            and decision.verdict in {FalsificationVerdict.INCONCLUSIVE, FalsificationVerdict.UNSAFE}
            for decision in falsifications
        )
        or any(
            result.candidate_id in contributor_ids
            and result.state
            in {
                ReproductionState.GENERATION_FAILED,
                ReproductionState.COMPILE_FAILED,
                ReproductionState.ENVIRONMENT_BLOCKED,
                ReproductionState.NOT_REPRODUCED,
                ReproductionState.PARTIALLY_REPRODUCED,
            }
            for result in reproductions
        )
        or finding.status
        in {
            FindingStatus.NEEDS_REVIEW,
            FindingStatus.INSUFFICIENT_CONTEXT,
            FindingStatus.UNSUPPORTED,
        }
    ):
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
        linked_candidates = sorted(
            [
                candidate_by_id[candidate_id]
                for candidate_id in finding.contributing_candidate_ids
                if candidate_id in candidate_by_id
            ],
            key=lambda item: item.candidate_id,
        )
        linked_verifications = sorted(
            (
                item
                for item in report.verification_decisions
                if item.candidate_id in contributor_ids
            ),
            key=lambda item: item.candidate_id,
        )
        linked_cross_examinations = sorted(
            (
                item
                for item in report.cross_examination_decisions
                if item.candidate_id in contributor_ids
            ),
            key=lambda item: (
                item.candidate_id,
                item.reviewer_index,
                item.root_lineage,
                item.request_id,
            ),
        )
        linked_falsifications = sorted(
            (
                item
                for item in report.falsification_decisions
                if item.candidate_id in contributor_ids
            ),
            key=lambda item: (item.candidate_id, item.test_name),
        )
        linked_reproductions = sorted(
            (item for item in report.reproductions if item.candidate_id in contributor_ids),
            key=lambda item: (item.candidate_id, item.test_name, item.specification_sha256),
        )
        linked_resolutions = sorted(
            (item for item in reproduction_resolutions if item.candidate_id in contributor_ids),
            key=lambda item: (item.candidate_id, item.kind.value, item.detail),
        )
        records.append(
            ForensicFindingRecord(
                finding_id=finding.id,
                disposition=_disposition(
                    finding,
                    linked_verifications,
                    linked_cross_examinations,
                    linked_falsifications,
                    linked_reproductions,
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
    run_status = effective_run_status(report)
    return FindingsArtifact(
        run_id=report.run_id,
        run_status=run_status,
        quality_status=report.quality_status,
        completed=run_status is AuditRunStatus.COMPLETE,
        findings=list(report.findings),
        rejected_findings=list(report.rejected_findings),
        records=records,
        candidate_findings=sorted(candidates, key=lambda item: item.candidate_id),
    )


def build_coverage_artifact(report: AuditReport) -> CoverageArtifact:
    """Build the canonical forensic coverage projection."""

    report = AuditReport.model_validate(report.model_dump(mode="python"))
    run_status = effective_run_status(report)
    return CoverageArtifact(
        run_id=report.run_id,
        run_status=run_status,
        completed=run_status is AuditRunStatus.COMPLETE,
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
    exact_cost = sum(
        (
            Decimal(record.accounted_cost_usd_exact)
            if record.accounted_cost_usd_exact is not None
            else Decimal(str(record.accounted_cost_usd))
            for record in usage
        ),
        start=Decimal("0"),
    )
    if not usage:
        exact_cost = Decimal(str(report.accounted_cost_usd))
    run_status = effective_run_status(report)
    return ModelExecutionArtifact(
        run_id=report.run_id,
        run_status=run_status,
        completed=run_status is AuditRunStatus.COMPLETE,
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
        accounted_cost_usd=float(exact_cost),
        accounted_cost_usd_exact=format(exact_cost, "f"),
        budget_usd=report.budget_usd,
        privacy_profile=str(report.privacy.get("profile", "UNKNOWN")),
        source_code_egress_enabled=bool(report.privacy.get("code_egress_enabled", False)),
        raw_prompts_retained=bool(report.privacy.get("store_raw_prompts", False)),
        raw_responses_retained=bool(report.privacy.get("store_raw_responses", False)),
    )
