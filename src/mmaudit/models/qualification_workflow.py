"""Deterministic, provider-free orchestration for model qualification.

The workflow consumes already-produced discovery and benchmark evidence. It never
performs network access and never upgrades incomplete, mock, or unresolved runtime
evidence into a quality conclusion.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.benchmark.model_portfolio import (
    ModelBenchmarkPortfolio,
    TrustedCandidateBenchmarkCampaignVerification,
    TrustedCandidateReasoningProfileCampaignVerification,
)
from mmaudit.benchmark.models import (
    ModelBenchmarkReport,
    ModelBenchmarkSuite,
)
from mmaudit.config import ModelLineageConfig, ModelQualityMeasurementConfig
from mmaudit.models.calibration import (
    ModelCalibrationArtifact,
    TrustedModelCalibrationVerification,
)
from mmaudit.models.candidate_benchmark import (
    CandidateBenchmarkRunState,
    CandidateReasoningProfileBenchmarkPlan,
)
from mmaudit.models.discovery import (
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
)
from mmaudit.models.generation_evidence import (
    GenerationVerificationRequest,
    TrustedGenerationVerification,
)
from mmaudit.models.openrouter import OpenRouterClient
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    CandidateModel,
    CandidateRegistry,
    ModelQualificationArtifact,
    ModelQualificationResult,
    QualificationBindings,
    QualificationDimensionResult,
    QualificationDisposition,
    QualificationPolicy,
    QualificationVerification,
    RoleQualificationDisposition,
    RoleQualificationResult,
    TrustedBenchmarkVerificationEvidence,
    derive_approved_roles_for_role_qualification,
    evaluate_role_qualification_results,
    issue_trusted_calibrated_qualification_policy,
    qualification_role_class_for_declared_role,
    seal_candidate_registry,
    seal_model_qualification_artifact,
    seal_model_qualification_result,
    validate_candidate_registry_discovery,
    verify_and_seal_trusted_benchmark_evidence,
    verify_model_qualification,
)
from mmaudit.models.reasoning import ReasoningPolicyError, resolve_reasoning_request_role
from mmaudit.models.release_attestation import TrustedReleaseBindingObservation
from mmaudit.models.schemas import ExecutionEvidenceKind, StrictModel
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_COMMIT_PATTERN = r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$"
_MAX_REPORTS = 128
_MAX_GENERATION_VERIFICATION_REQUESTS = 512
_MAX_PRIVATE_REPORT_BYTES = 50_000_000
_MAX_PRIVATE_BUNDLE_BYTES = 100_000_000
_MAX_RELEASE_BINDINGS_BYTES = 1_000_000
_FUTURE_SKEW = timedelta(minutes=5)


def _utc_second(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
        raise ValueError(f"{label} must be a whole-second UTC timestamp")
    return value


def promote_qualified_model_lineages(
    *,
    declared_identities: tuple[ModelLineageConfig, ...],
    candidate_registry: CandidateRegistry,
    qualification_artifact: ModelQualificationArtifact,
    qualification_verification: QualificationVerification,
    promoted_at: datetime,
) -> tuple[ModelLineageConfig, ...]:
    """Attach benchmark-derived quality to exact identity-only production records.

    This deterministic transition does not itself grant runtime selection authority.
    Production still requires the repository's opaque, current qualification capability.
    """

    promoted_at = _utc_second(promoted_at, label="model quality promotion time")
    registry = CandidateRegistry.model_validate(candidate_registry.model_dump(mode="json"))
    artifact = ModelQualificationArtifact.model_validate(
        qualification_artifact.model_dump(mode="json")
    )
    verification = QualificationVerification.model_validate(
        qualification_verification.model_dump(mode="json")
    )
    identities = tuple(
        ModelLineageConfig.model_validate(identity.model_dump(mode="json"))
        for identity in declared_identities
    )

    if not identities:
        raise ValueError("model quality promotion requires identity-only records")
    identity_ids = tuple(identity.canonical_model_id for identity in identities)
    if identity_ids != tuple(sorted(set(identity_ids))):
        raise ValueError("model quality promotion identities must be unique and sorted")
    if any(identity.measured_quality is not None for identity in identities):
        raise ValueError("model quality promotion requires unmeasured identity records")

    if not verification.valid or verification.errors:
        raise ValueError("model quality promotion requires valid qualification verification")
    if not verification.production_selection_ready:
        raise ValueError("model quality promotion requires production-ready Tier A evidence")
    if (
        artifact.bindings.candidate_registry_sha256 != registry.registry_sha256
        or verification.candidate_registry_sha256 != registry.registry_sha256
        or verification.artifact_sha256 != artifact.artifact_sha256
        or verification.policy_sha256 != artifact.bindings.qualification_policy_sha256
    ):
        raise ValueError("model quality promotion evidence bindings are inconsistent")
    if artifact.created_at > verification.verified_at:
        raise ValueError("model quality promotion verification predates its artifact")
    if verification.verified_at > promoted_at:
        raise ValueError("model quality promotion predates qualification verification")

    candidates = {candidate.exact_model_id: candidate for candidate in registry.candidates}
    results = {result.exact_model_id: result for result in artifact.results}
    if set(candidates) != set(results):
        raise ValueError("model quality promotion candidate and result sets differ")
    if any(
        candidate.benchmark_status
        in {CandidateBenchmarkStatus.PENDING, CandidateBenchmarkStatus.INCONCLUSIVE}
        for candidate in candidates.values()
    ) or any(
        result.disposition is QualificationDisposition.INCONCLUSIVE for result in results.values()
    ):
        raise ValueError("model quality promotion rejects pending or inconclusive evidence")

    eligible_ids = verification.eligible_tier_a_model_ids
    if identity_ids != eligible_ids:
        raise ValueError("model quality promotion identities differ from eligible Tier A models")
    tier_a_ids = tuple(
        sorted(
            result.exact_model_id
            for result in artifact.results
            if result.disposition is QualificationDisposition.TIER_A
        )
    )
    if tier_a_ids != eligible_ids:
        raise ValueError("model quality promotion omits or adds a Tier A result")
    observed_roots = {results[model_id].root_lineage for model_id in eligible_ids}
    if any(root is None for root in observed_roots):
        raise ValueError("model quality promotion root-lineage evidence is inconsistent")
    eligible_roots = tuple(sorted(root for root in observed_roots if root is not None))
    if eligible_roots != verification.eligible_root_lineages:
        raise ValueError("model quality promotion root-lineage evidence is inconsistent")

    promoted: list[ModelLineageConfig] = []
    for identity in identities:
        model_id = identity.canonical_model_id
        candidate = candidates[model_id]
        result = results[model_id]
        if (
            candidate.canonical_model_slug != result.canonical_model_slug
            or candidate.root_lineage is None
            or identity.root_lineage != candidate.root_lineage
            or candidate.root_lineage != result.root_lineage
            or candidate.approved_provider_endpoint != result.approved_provider_endpoint
            or candidate.approved_provider_name != result.approved_provider_name
            or candidate.endpoint_snapshot_sha256 != result.endpoint_snapshot_sha256
            or candidate.output_capability_sha256 != result.output_capability_sha256
            or candidate.model_metadata_snapshot_sha256 != result.model_metadata_snapshot_sha256
            or candidate.pricing_snapshot_sha256 != result.pricing_snapshot_sha256
            or candidate.structured_output_mode is not result.structured_output_mode
            or candidate.benchmark_status is not CandidateBenchmarkStatus.PASSED
            or candidate.benchmark_artifact_sha256 != result.benchmark_report_sha256
            or candidate.qualification_expires_at != result.expires_at
            or result.disposition is not QualificationDisposition.TIER_A
            or result.benchmark_verification_sha256 is None
            or not result.approved_roles
            or result.expires_at is None
            or result.expires_at <= promoted_at
        ):
            raise ValueError(f"model quality promotion evidence differs for {model_id}")
        quality = ModelQualityMeasurementConfig(
            score=result.overall_score,
            tier="highest",
            measurement=f"sha256:{result.quality_measurement_sha256}",
        )
        promoted.append(identity.model_copy(update={"measured_quality": quality}))
    return tuple(promoted)


class QualificationReleaseBindings(StrictModel):
    """Explicit non-secret release inputs; derived qualification hashes are excluded."""

    schema_version: Literal["1.0"] = "1.0"
    source_commit: str = Field(pattern=_COMMIT_PATTERN)
    source_tree_sha256: str = Field(pattern=_SHA256_PATTERN)
    effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    response_schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    toolchain_sha256: str = Field(pattern=_SHA256_PATTERN)
    isolation_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_corpus_version: str = Field(min_length=1, max_length=100)
    benchmark_ground_truth_version: str = Field(min_length=1, max_length=100)
    bindings_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def hash_is_consistent(self) -> QualificationReleaseBindings:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"bindings_sha256"}))
        if self.bindings_sha256 != expected:
            raise ValueError("qualification release bindings hash is inconsistent")
        return self


def seal_qualification_release_bindings(
    *,
    source_commit: str,
    source_tree_sha256: str,
    effective_config_sha256: str,
    prompt_sha256: str,
    response_schema_sha256: str,
    toolchain_sha256: str,
    isolation_sha256: str,
    benchmark_corpus_version: str,
    benchmark_ground_truth_version: str,
) -> QualificationReleaseBindings:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "source_commit": source_commit,
        "source_tree_sha256": source_tree_sha256,
        "effective_config_sha256": effective_config_sha256,
        "prompt_sha256": prompt_sha256,
        "response_schema_sha256": response_schema_sha256,
        "toolchain_sha256": toolchain_sha256,
        "isolation_sha256": isolation_sha256,
        "benchmark_corpus_version": benchmark_corpus_version,
        "benchmark_ground_truth_version": benchmark_ground_truth_version,
    }
    payload["bindings_sha256"] = canonical_sha256(payload)
    return QualificationReleaseBindings.model_validate(payload)


def _validated_reasoning_benchmark_report_set(
    *,
    reports: tuple[ModelBenchmarkReport, ...],
    plan: CandidateReasoningProfileBenchmarkPlan | None,
    candidates: dict[str, CandidateModel],
    primary_reports: tuple[ModelBenchmarkReport, ...],
) -> tuple[ModelBenchmarkReport, ...]:
    """Validate duplicate-model reports against an exact distinct-profile route set."""

    validated_plan = (
        None
        if plan is None
        else CandidateReasoningProfileBenchmarkPlan.model_validate(plan.model_dump(mode="json"))
    )
    routes = () if validated_plan is None else validated_plan.routes
    requirement_keys = tuple((item.exact_model_id, item.request_role) for item in routes)
    if requirement_keys != tuple(sorted(set(requirement_keys))):
        raise ValueError("reasoning benchmark requirements must be unique and sorted")
    if len(primary_reports) + len(reports) > _MAX_REPORTS:
        raise ValueError("combined qualification benchmark report set is too large")

    primary_hashes = {report.report_sha256 for report in primary_reports}
    validated: list[ModelBenchmarkReport] = []
    observed_keys: list[tuple[str, str]] = []
    observed_hashes = set(primary_hashes)
    for supplied in reports:
        if type(supplied) is not ModelBenchmarkReport:
            raise ValueError("reasoning benchmark report is not an exact typed value")
        report = ModelBenchmarkReport.model_validate(supplied.model_dump(mode="json"))
        if len(report.results) != 1:
            raise ValueError("reasoning qualification requires exact one-model reports")
        target = report.results[0].target
        try:
            resolution = resolve_reasoning_request_role(target.request_role)
        except ReasoningPolicyError as exc:
            raise ValueError("reasoning benchmark report has an invalid request role") from exc
        if resolution.mapping_kind != "prequalification_role_benchmark":
            raise ValueError("reasoning benchmark report is not a distinct-profile route")
        candidate = candidates.get(target.model_id)
        if candidate is None or target.root_lineage != candidate.root_lineage:
            raise ValueError("reasoning benchmark target differs from the candidate registry")
        route = next(
            (
                item
                for item in routes
                if item.exact_model_id == target.model_id
                and item.request_role == target.request_role
            ),
            None,
        )
        primary = next(
            item for item in primary_reports if item.results[0].target.model_id == target.model_id
        )
        if route is None or route.primary_report_sha256 != primary.report_sha256:
            raise ValueError("reasoning benchmark report differs from its frozen plan route")
        if report.report_sha256 in observed_hashes:
            raise ValueError("reasoning benchmark reports reuse report evidence")
        observed_hashes.add(report.report_sha256)
        observed_keys.append((target.model_id, target.request_role))
        validated.append(report)
    if tuple(sorted(observed_keys)) != requirement_keys or len(set(observed_keys)) != len(
        observed_keys
    ):
        raise ValueError("reasoning benchmark report set differs from required profile routes")
    return tuple(
        report
        for _key, report in sorted(
            zip(observed_keys, validated, strict=True),
            key=lambda item: item[0],
        )
    )


def _reasoning_profile_evidence_passes_policy(
    *,
    evidence: TrustedBenchmarkVerificationEvidence,
    qualified_roles: tuple[str, ...],
    policy: QualificationPolicy,
) -> bool:
    dimensions = {item.dimension: item for item in evidence.dimensions}
    thresholds = {item.dimension: item for item in policy.thresholds}
    overall_score = round(
        sum(item.score for item in evidence.dimensions) / len(evidence.dimensions),
        6,
    )
    if (
        set(dimensions) != set(thresholds)
        or overall_score < policy.tier_a_minimum_overall_score
        or any(
            dimensions[dimension].evaluated < threshold.minimum_cases
            or dimensions[dimension].score < threshold.minimum_score
            for dimension, threshold in thresholds.items()
        )
    ):
        return False
    if not policy.role_policies:
        return True
    role_results = {
        item.role_class: item
        for item in evaluate_role_qualification_results(
            global_disposition=QualificationDisposition.TIER_A,
            dimensions=evidence.dimensions,
            role_policies=policy.role_policies,
        )
    }
    return all(
        role_results[qualification_role_class_for_declared_role(role)].disposition
        is RoleQualificationDisposition.QUALIFIED
        for role in qualified_roles
    )


def _downgrade_profile_incomplete_verification(
    verification: QualificationVerification,
) -> QualificationVerification:
    payload = verification.model_dump(mode="json", exclude={"verification_sha256"})
    payload["production_selection_ready"] = False
    payload["valid"] = False
    payload["errors"] = sorted(
        {*verification.errors, "supplemental reasoning profile thresholds failed"}
    )
    payload["verification_sha256"] = canonical_sha256(payload)
    return QualificationVerification.model_validate(payload)


def candidate_generation_verification_requests(
    *,
    registry: CandidateRegistry,
    benchmark_reports: tuple[ModelBenchmarkReport, ...],
    reasoning_benchmark_reports: tuple[ModelBenchmarkReport, ...] = (),
    reasoning_benchmark_plan: CandidateReasoningProfileBenchmarkPlan | None = None,
) -> tuple[GenerationVerificationRequest, ...]:
    """Derive one exact primary-plus-profile generation set for authenticated re-fetch."""

    registry = CandidateRegistry.model_validate(registry.model_dump(mode="json"))
    candidates = {candidate.exact_model_id: candidate for candidate in registry.candidates}
    primary_reports = _validated_exact_report_set(
        reports=benchmark_reports,
        expected_model_ids=tuple(candidates),
    )
    if any(
        report.results[0].target.request_role != "model_benchmark" for report in primary_reports
    ):
        raise ValueError("primary qualification report has a non-primary request role")
    profile_reports = _validated_reasoning_benchmark_report_set(
        reports=reasoning_benchmark_reports,
        plan=reasoning_benchmark_plan,
        candidates=candidates,
        primary_reports=primary_reports,
    )
    reports = (*primary_reports, *profile_reports)
    request_count = sum(len(report.results[0].cases) for report in reports)
    if request_count > _MAX_GENERATION_VERIFICATION_REQUESTS:
        raise ValueError("combined generation verification request set exceeds the bound")
    reference = primary_reports[0]
    if any(
        report.corpus_name != reference.corpus_name
        or report.corpus_sha256 != reference.corpus_sha256
        or report.ground_truth_sha256 != reference.ground_truth_sha256
        or report.case_ids != reference.case_ids
        or report.execution_evidence is not ExecutionEvidenceKind.REAL
        for report in reports
    ):
        raise ValueError("generation verification reports differ from the full REAL corpus")
    report_hashes = tuple(report.report_sha256 for report in reports)
    if len(set(report_hashes)) != len(report_hashes):
        raise ValueError("generation verification reports reuse report evidence")

    requests: list[GenerationVerificationRequest] = []
    request_ids: set[str] = set()
    generation_ids: set[str] = set()
    request_body_hashes: set[str] = set()
    primary_prompt_schema = {
        (report.results[0].target.model_id, case.case_id): (
            case.usage_record.prompt_sha256,
            case.usage_record.schema_sha256,
        )
        for report in primary_reports
        for case in report.results[0].cases
        if case.usage_record is not None
    }
    for report in reports:
        target = report.results[0].target
        candidate = candidates[target.model_id]
        if target.root_lineage != candidate.root_lineage:
            raise ValueError("generation verification target lineage differs from the candidate")
        for case in report.results[0].cases:
            record = case.usage_record
            if record is None or case.generation_evidence is None:
                raise ValueError(
                    "generation verification requires complete benchmark runtime evidence"
                )
            if (
                case.execution_evidence is not ExecutionEvidenceKind.REAL
                or report.results[0].execution_evidence is not ExecutionEvidenceKind.REAL
                or record.execution_evidence is not ExecutionEvidenceKind.REAL
                or record.role != target.request_role
                or record.openrouter_generation_id is None
                or record.request_body_sha256 is None
                or record.requested_model != candidate.exact_model_id
                or record.returned_model
                not in {
                    candidate.exact_model_id,
                    candidate.canonical_model_slug,
                }
                or record.actual_model
                not in {
                    candidate.exact_model_id,
                    candidate.canonical_model_slug,
                }
                or record.actual_provider_endpoint != candidate.approved_provider_endpoint
                or tuple(record.configured_provider_endpoints)
                != (candidate.approved_provider_endpoint,)
                or record.routing.get("selected_provider_endpoint")
                != candidate.approved_provider_endpoint
                or record.routing.get("selected_provider_name") != candidate.approved_provider_name
                or record.routing.get("selected_model") != record.actual_model
                or record.routing.get("canonical_model") != candidate.canonical_model_slug
                or record.routing.get("catalog_identity_binding_sha256")
                != canonical_sha256(
                    {
                        "canonical_slug": candidate.canonical_model_slug,
                        "id": candidate.exact_model_id,
                    }
                )
                or record.routing.get("discovery_evidence_sha256")
                != candidate.discovery_evidence_sha256
                or record.routing.get("endpoint_snapshot_sha256")
                != candidate.endpoint_snapshot_sha256
                or record.routing.get("endpoint_pricing_sha256")
                != candidate.pricing_snapshot_sha256
                or record.routing.get("output_capability_sha256")
                != candidate.output_capability_sha256
                or record.routing.get("model_metadata_snapshot_sha256")
                != candidate.model_metadata_snapshot_sha256
                or record.routing.get("certification_request") is not True
                or record.openrouter_generation_id != case.generation_evidence.generation_id
            ):
                raise ValueError("generation verification request differs from the candidate route")
            prompt_schema = primary_prompt_schema.get((target.model_id, case.case_id))
            if prompt_schema is None or prompt_schema != (
                record.prompt_sha256,
                record.schema_sha256,
            ):
                raise ValueError(
                    "reasoning benchmark request differs from the primary corpus prompt"
                )
            if (
                record.request_id in request_ids
                or record.openrouter_generation_id in generation_ids
                or record.request_body_sha256 in request_body_hashes
            ):
                raise ValueError("generation verification reports reuse request evidence")
            request_ids.add(record.request_id)
            generation_ids.add(record.openrouter_generation_id)
            request_body_hashes.add(record.request_body_sha256)
            requests.append(
                GenerationVerificationRequest(
                    benchmark_report_sha256=report.report_sha256,
                    case_id=case.case_id,
                    exact_model_id=candidate.exact_model_id,
                    canonical_model_id=candidate.canonical_model_slug,
                    catalog_identity_binding_sha256=canonical_sha256(
                        {
                            "canonical_slug": candidate.canonical_model_slug,
                            "id": candidate.exact_model_id,
                        }
                    ),
                    discovery_evidence_sha256=candidate.discovery_evidence_sha256,
                    expected_provider_name=candidate.approved_provider_name,
                    usage_record=record,
                )
            )
    return tuple(requests)


async def refetch_trusted_benchmark_generations(
    *,
    client: OpenRouterClient,
    registry: CandidateRegistry,
    benchmark_reports: tuple[ModelBenchmarkReport, ...],
    reasoning_benchmark_reports: tuple[ModelBenchmarkReport, ...] = (),
    reasoning_benchmark_plan: CandidateReasoningProfileBenchmarkPlan | None = None,
) -> TrustedGenerationVerification:
    """Authenticate primary and required profile generations as one exact set."""

    requests = candidate_generation_verification_requests(
        registry=registry,
        benchmark_reports=benchmark_reports,
        reasoning_benchmark_reports=reasoning_benchmark_reports,
        reasoning_benchmark_plan=reasoning_benchmark_plan,
    )
    return await OpenRouterClient.create_trusted_generation_verification(
        client,
        requests,
    )


class QualificationWorkflowBundle(StrictModel):
    """Strict private bundle suitable for deterministic CLI serialization."""

    schema_version: Literal["1.0"] = "1.0"
    evaluated_at: datetime
    qualification_expires_at: datetime
    input_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    release_bindings: QualificationReleaseBindings
    policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_corpus_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_ground_truth_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_portfolio_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_reports: tuple[ModelBenchmarkReport, ...] = Field(
        min_length=1,
        max_length=_MAX_REPORTS,
    )
    reasoning_benchmark_plan: CandidateReasoningProfileBenchmarkPlan | None = None
    reasoning_benchmark_reports: tuple[ModelBenchmarkReport, ...] = Field(
        default=(),
        max_length=_MAX_REPORTS,
    )
    updated_registry: CandidateRegistry
    trusted_benchmark_evidence: tuple[TrustedBenchmarkVerificationEvidence, ...] = ()
    trusted_reasoning_benchmark_evidence: tuple[
        TrustedBenchmarkVerificationEvidence,
        ...,
    ] = Field(default=(), max_length=_MAX_REPORTS)
    qualification_artifact: ModelQualificationArtifact
    qualification_verification: QualificationVerification
    workflow_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("evaluated_at", "qualification_expires_at")
    @classmethod
    def evaluated_at_is_utc(cls, value: datetime) -> datetime:
        return _utc_second(value, label="qualification workflow evaluation time")

    @model_validator(mode="after")
    def bundle_is_exact_and_self_bound(self) -> QualificationWorkflowBundle:
        if self.qualification_expires_at <= self.evaluated_at:
            raise ValueError("qualification workflow expiry must follow evaluation")
        report_ids = tuple(report.results[0].target.model_id for report in self.benchmark_reports)
        if any(len(report.results) != 1 for report in self.benchmark_reports):
            raise ValueError("qualification bundle requires exact one-model reports")
        if report_ids != tuple(sorted(set(report_ids))):
            raise ValueError("qualification bundle reports must be unique and sorted")
        candidate_ids = tuple(
            candidate.exact_model_id for candidate in self.updated_registry.candidates
        )
        if report_ids != candidate_ids:
            raise ValueError("qualification bundle report and candidate sets differ")
        plan_routes = (
            () if self.reasoning_benchmark_plan is None else self.reasoning_benchmark_plan.routes
        )
        requirement_keys = tuple((item.exact_model_id, item.request_role) for item in plan_routes)
        reasoning_report_keys = tuple(
            (report.results[0].target.model_id, report.results[0].target.request_role)
            for report in self.reasoning_benchmark_reports
            if len(report.results) == 1
        )
        if (
            requirement_keys != tuple(sorted(set(requirement_keys)))
            or len(reasoning_report_keys) != len(self.reasoning_benchmark_reports)
            or reasoning_report_keys != requirement_keys
        ):
            raise ValueError(
                "qualification bundle reasoning reports differ from required profile routes"
            )
        if self.reasoning_benchmark_plan is not None:
            results_by_model = {
                result.exact_model_id: result for result in self.qualification_artifact.results
            }
            primary_report_hashes = {
                report.results[0].target.model_id: report.report_sha256
                for report in self.benchmark_reports
            }
            if (
                self.reasoning_benchmark_plan.qualification_artifact_sha256
                != self.qualification_artifact.artifact_sha256
                or any(
                    route.exact_model_id not in results_by_model
                    or route.qualification_result_sha256
                    != results_by_model[route.exact_model_id].result_sha256
                    or route.primary_report_sha256
                    != primary_report_hashes.get(route.exact_model_id)
                    for route in plan_routes
                )
            ):
                raise ValueError("qualification bundle reasoning plan differs from its artifact")
        reasoning_evidence_keys: list[tuple[str, str]] = []
        reasoning_evidence_reports: list[str] = []
        for evidence in self.trusted_reasoning_benchmark_evidence:
            roles = tuple(sorted({record.role for record in evidence.usage_records}))
            if len(roles) != 1:
                raise ValueError("qualification bundle reasoning evidence mixed request roles")
            reasoning_evidence_keys.append((evidence.exact_model_id, roles[0]))
            reasoning_evidence_reports.append(evidence.benchmark_report_sha256)
        if (
            tuple(reasoning_evidence_keys) != requirement_keys
            or tuple(reasoning_evidence_reports)
            != tuple(report.report_sha256 for report in self.reasoning_benchmark_reports)
            or set(reasoning_evidence_reports)
            & {report.report_sha256 for report in self.benchmark_reports}
        ):
            raise ValueError(
                "qualification bundle reasoning evidence differs from its exact reports"
            )
        evidence_ids = tuple(item.exact_model_id for item in self.trusted_benchmark_evidence)
        if evidence_ids != tuple(sorted(set(evidence_ids))):
            raise ValueError("qualification bundle trusted evidence is duplicate or unsorted")
        result_ids = tuple(item.exact_model_id for item in self.qualification_artifact.results)
        if result_ids != candidate_ids:
            raise ValueError("qualification bundle result and candidate sets differ")
        if any(
            result.expires_at not in {None, self.qualification_expires_at}
            for result in self.qualification_artifact.results
        ):
            raise ValueError("qualification result expiry differs from workflow input")
        if (
            self.qualification_artifact.bindings.candidate_registry_sha256
            != self.updated_registry.registry_sha256
            or self.qualification_artifact.bindings.qualification_policy_sha256
            != self.policy_sha256
            or self.qualification_artifact.bindings.benchmark_corpus_sha256
            != self.benchmark_corpus_sha256
            or self.qualification_artifact.bindings.benchmark_ground_truth_sha256
            != self.benchmark_ground_truth_sha256
            or self.qualification_artifact.bindings.benchmark_portfolio_sha256
            != self.benchmark_portfolio_sha256
            or self.qualification_verification.artifact_sha256
            != self.qualification_artifact.artifact_sha256
        ):
            raise ValueError("qualification workflow output bindings are inconsistent")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"workflow_sha256"}))
        if self.workflow_sha256 != expected:
            raise ValueError("qualification workflow bundle hash is inconsistent")
        return self


def load_private_model_benchmark_report(path: Path) -> ModelBenchmarkReport:
    """Load one bounded, unshared, duplicate-key-free private report."""

    return _load_bounded_json_model(
        path,
        model=ModelBenchmarkReport,
        maximum_bytes=_MAX_PRIVATE_REPORT_BYTES,
        label="private model benchmark report",
    )


def load_qualification_release_bindings(
    path: Path,
) -> QualificationReleaseBindings:
    """Load one bounded self-hashed release binding document."""

    return _load_bounded_json_model(
        path,
        model=QualificationReleaseBindings,
        maximum_bytes=_MAX_RELEASE_BINDINGS_BYTES,
        label="qualification release bindings",
    )


def load_qualification_workflow_bundle(path: Path) -> QualificationWorkflowBundle:
    """Load one canonical mode-private workflow bundle."""

    bundle, raw = _load_bounded_json_model_with_bytes(
        path,
        model=QualificationWorkflowBundle,
        maximum_bytes=_MAX_PRIVATE_BUNDLE_BYTES,
        label="qualification workflow bundle",
        require_private_mode=True,
    )
    if raw != qualification_workflow_bundle_bytes(bundle):
        raise ValueError("qualification workflow bundle is not canonically serialized")
    return bundle


def qualification_workflow_bundle_bytes(bundle: QualificationWorkflowBundle) -> bytes:
    """Return the sole canonical byte representation of a workflow bundle."""

    validated = QualificationWorkflowBundle.model_validate(bundle.model_dump(mode="json"))
    return stable_json(validated).encode("utf-8")


def write_qualification_workflow_bundle(
    path: Path,
    bundle: QualificationWorkflowBundle,
) -> None:
    """Atomically create one fresh mode-0600 canonical private bundle."""

    serialized = qualification_workflow_bundle_bytes(bundle)
    if not serialized or len(serialized) > _MAX_PRIVATE_BUNDLE_BYTES:
        raise ValueError("qualification workflow bundle exceeds its bounded size")
    absolute = Path(os.path.abspath(path))
    parent = absolute.parent
    _reject_linked_components(parent)
    if not parent.is_dir():
        raise ValueError("qualification workflow output parent must already exist")
    if os.path.lexists(absolute):
        raise ValueError("qualification workflow output must be a fresh file")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{absolute.name}.",
        suffix=".tmp",
        dir=parent,
    )
    temporary = Path(temporary_name)
    published = False
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(serialized)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("qualification workflow output made no write progress")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if os.path.lexists(absolute):
            raise ValueError("qualification workflow output appeared during publication")
        os.link(temporary, absolute, follow_symlinks=False)
        temporary.unlink()
        published = True
        directory_descriptor = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        metadata = absolute.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("qualification workflow output is not an unshared file")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError("qualification workflow output is not mode 0600")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not published:
            temporary.unlink(missing_ok=True)


def run_qualification_workflow(
    *,
    candidate_registry: CandidateRegistry,
    discovery_run_manifest: OpenRouterModelDiscoveryRunManifest,
    discovery_evidence: tuple[OpenRouterModelDiscoveryEvidence, ...],
    policy: QualificationPolicy,
    calibration_artifact: ModelCalibrationArtifact | None = None,
    trusted_calibration_verification: TrustedModelCalibrationVerification | None = None,
    benchmark_suite: ModelBenchmarkSuite,
    benchmark_portfolio: ModelBenchmarkPortfolio,
    benchmark_reports: tuple[ModelBenchmarkReport, ...],
    release_bindings: QualificationReleaseBindings,
    trusted_campaign_verification: TrustedCandidateBenchmarkCampaignVerification | None,
    trusted_generation_verification: TrustedGenerationVerification | None,
    trusted_release_observation: TrustedReleaseBindingObservation,
    evaluated_at: datetime,
    qualification_expires_at: datetime,
    reasoning_benchmark_reports: tuple[ModelBenchmarkReport, ...] = (),
    reasoning_benchmark_plan: CandidateReasoningProfileBenchmarkPlan | None = None,
    trusted_reasoning_campaign_verification: (
        TrustedCandidateReasoningProfileCampaignVerification | None
    ) = None,
) -> QualificationWorkflowBundle:
    """Qualify an exact candidate set from independently verified benchmark evidence."""

    evaluated_at = _utc_second(
        evaluated_at,
        label="qualification workflow evaluation time",
    )
    qualification_expires_at = _utc_second(
        qualification_expires_at,
        label="qualification expiry",
    )
    policy = QualificationPolicy.model_validate(policy.model_dump(mode="json"))
    trusted_calibrated_policy = None
    validated_calibration: ModelCalibrationArtifact | None = None
    if policy.schema_version == "2.0":
        if calibration_artifact is None or trusted_calibration_verification is None:
            raise ValueError("calibrated qualification policy requires live calibration evidence")
        validated_calibration = ModelCalibrationArtifact.model_validate(
            calibration_artifact.model_dump(mode="json")
        )
        trusted_calibrated_policy = issue_trusted_calibrated_qualification_policy(
            policy=policy,
            calibration=validated_calibration,
            trusted_calibration_verification=trusted_calibration_verification,
        )
    elif calibration_artifact is not None or trusted_calibration_verification is not None:
        raise ValueError("legacy qualification policy cannot consume calibration evidence")
    candidate_registry = CandidateRegistry.model_validate(
        candidate_registry.model_dump(mode="json")
    )
    discovery_run_manifest = OpenRouterModelDiscoveryRunManifest.model_validate(
        discovery_run_manifest.model_dump(mode="json")
    )
    discovery_evidence = tuple(
        OpenRouterModelDiscoveryEvidence.model_validate(item.model_dump(mode="json"))
        for item in discovery_evidence
    )
    benchmark_suite = ModelBenchmarkSuite.model_validate(benchmark_suite.model_dump(mode="json"))
    benchmark_portfolio = ModelBenchmarkPortfolio.model_validate(
        benchmark_portfolio.model_dump(mode="json")
    )
    release_bindings = QualificationReleaseBindings.model_validate(
        release_bindings.model_dump(mode="json")
    )
    if validated_calibration is not None and (
        validated_calibration.candidate_registry_sha256 != candidate_registry.registry_sha256
        or validated_calibration.discovery_manifest_sha256 != discovery_run_manifest.manifest_sha256
        or validated_calibration.candidate_set_sha256
        != canonical_sha256(
            [candidate.exact_model_id for candidate in candidate_registry.candidates]
        )
        or validated_calibration.benchmark_corpus_version != benchmark_suite.corpus.schema_version
        or validated_calibration.benchmark_corpus_sha256 != benchmark_suite.corpus_sha256
        or validated_calibration.benchmark_ground_truth_version
        != benchmark_suite.ground_truth.schema_version
        or validated_calibration.benchmark_ground_truth_sha256
        != benchmark_suite.ground_truth_sha256
        or validated_calibration.effective_config_sha256 != release_bindings.effective_config_sha256
    ):
        raise ValueError("calibration evidence differs from qualification inputs")
    if type(trusted_release_observation) is not TrustedReleaseBindingObservation:
        raise ValueError("qualification requires a trusted release observation")
    trusted_release_observation.require_for(release_bindings)
    observed_at = trusted_release_observation.observed_at
    if evaluated_at != observed_at:
        raise ValueError(
            "qualification workflow evaluation time differs from the trusted release observation"
        )
    campaign_completed_at = _portfolio_completion_anchor(benchmark_portfolio)
    if campaign_completed_at > observed_at + _FUTURE_SKEW:
        raise ValueError("qualification benchmark campaign completion is future-dated")
    if observed_at - campaign_completed_at > timedelta(
        days=policy.maximum_benchmark_evidence_age_days
    ):
        raise ValueError("qualification benchmark evidence exceeds the policy age")
    if qualification_expires_at <= campaign_completed_at:
        raise ValueError("qualification expiry must follow benchmark campaign completion")
    maximum_window_days = min(
        policy.maximum_validity_days,
        policy.maximum_benchmark_evidence_age_days,
    )
    if qualification_expires_at > campaign_completed_at + timedelta(days=maximum_window_days):
        raise ValueError("qualification expiry exceeds the policy-bound benchmark window")
    if (
        release_bindings.benchmark_corpus_version != benchmark_suite.corpus.schema_version
        or release_bindings.benchmark_ground_truth_version
        != benchmark_suite.ground_truth.schema_version
    ):
        raise ValueError("qualification release benchmark versions differ from the loaded suite")
    if trusted_campaign_verification is not None and (
        type(trusted_campaign_verification) is not TrustedCandidateBenchmarkCampaignVerification
    ):
        raise ValueError("trusted campaign verification has an invalid authority type")
    validate_candidate_registry_discovery(
        registry=candidate_registry,
        run_manifest=discovery_run_manifest,
        evidence=discovery_evidence,
    )
    if candidate_registry.created_at > campaign_completed_at + _FUTURE_SKEW:
        raise ValueError("candidate discovery postdates qualification evaluation")
    if campaign_completed_at - candidate_registry.created_at > timedelta(
        days=policy.maximum_benchmark_evidence_age_days
    ):
        raise ValueError("candidate discovery exceeds the qualification policy age")
    if policy.created_at > campaign_completed_at + _FUTURE_SKEW:
        raise ValueError("qualification policy postdates evaluation")

    reports = _validated_exact_report_set(
        reports=benchmark_reports,
        expected_model_ids=tuple(
            candidate.exact_model_id for candidate in candidate_registry.candidates
        ),
    )
    candidates_by_id = {
        candidate.exact_model_id: candidate for candidate in candidate_registry.candidates
    }
    reasoning_reports = _validated_reasoning_benchmark_report_set(
        reports=reasoning_benchmark_reports,
        plan=reasoning_benchmark_plan,
        candidates=candidates_by_id,
        primary_reports=reports,
    )
    validated_reasoning_plan = (
        None
        if reasoning_benchmark_plan is None
        else CandidateReasoningProfileBenchmarkPlan.model_validate(
            reasoning_benchmark_plan.model_dump(mode="json")
        )
    )
    trusted_reasoning: list[TrustedBenchmarkVerificationEvidence] = []
    if reasoning_reports:
        if trusted_generation_verification is None:
            raise ValueError(
                "reasoning qualification requires authenticated generation re-fetch evidence"
            )
        if type(trusted_reasoning_campaign_verification) is not (
            TrustedCandidateReasoningProfileCampaignVerification
        ):
            raise ValueError(
                "reasoning qualification requires live supplemental response-content authority"
            )
        assert validated_reasoning_plan is not None
        trusted_reasoning_campaign_verification.require_for(
            plan_sha256=validated_reasoning_plan.plan_sha256,
            reports=reasoning_reports,
            policy_sha256=policy.policy_sha256,
            effective_config_sha256=release_bindings.effective_config_sha256,
        )
        candidate_generation_verification_requests(
            registry=candidate_registry,
            benchmark_reports=reports,
            reasoning_benchmark_reports=reasoning_reports,
            reasoning_benchmark_plan=validated_reasoning_plan,
        )
        for report in reasoning_reports:
            target = report.results[0].target
            candidate = candidates_by_id[target.model_id]
            trusted_reasoning.append(
                verify_and_seal_trusted_benchmark_evidence(
                    report=report,
                    corpus=benchmark_suite,
                    exact_model_id=candidate.exact_model_id,
                    canonical_model_id=candidate.canonical_model_slug,
                    discovery_evidence_sha256=candidate.discovery_evidence_sha256,
                    trusted_generation_verification=trusted_generation_verification,
                )
            )
    elif trusted_reasoning_campaign_verification is not None:
        raise ValueError("supplemental content authority has no required reasoning reports")
    _validate_benchmark_portfolio_binding(
        portfolio=benchmark_portfolio,
        registry=candidate_registry,
        suite=benchmark_suite,
        reports=reports,
        policy=policy,
    )
    if trusted_campaign_verification is not None:
        trusted_campaign_verification.require_for(
            portfolio_sha256=benchmark_portfolio.portfolio_sha256,
            reports=reports,
            policy_sha256=policy.policy_sha256,
            effective_config_sha256=release_bindings.effective_config_sha256,
        )
    thresholds = {threshold.dimension: threshold for threshold in policy.thresholds}
    trusted: list[TrustedBenchmarkVerificationEvidence] = []
    results: list[ModelQualificationResult] = []
    updated_candidates: list[CandidateModel] = []
    for report in reports:
        model_id = report.results[0].target.model_id
        candidate = candidates_by_id[model_id]
        evidence: TrustedBenchmarkVerificationEvidence | None = None
        dimensions: tuple[QualificationDimensionResult, ...]
        role_results: tuple[RoleQualificationResult, ...]
        failure_reasons: tuple[str, ...]
        try:
            if trusted_campaign_verification is None:
                raise ValueError("qualification requires live response-content campaign provenance")
            if trusted_generation_verification is None:
                raise ValueError(
                    "qualification requires authenticated generation re-fetch evidence"
                )
            if report.results[0].target.root_lineage != candidate.root_lineage:
                raise ValueError("benchmark root lineage differs from candidate")
            evidence = verify_and_seal_trusted_benchmark_evidence(
                report=report,
                corpus=benchmark_suite,
                exact_model_id=model_id,
                canonical_model_id=candidate.canonical_model_slug,
                discovery_evidence_sha256=candidate.discovery_evidence_sha256,
                trusted_generation_verification=trusted_generation_verification,
            )
            if any(
                record.requested_model != candidate.exact_model_id
                or record.returned_model
                not in {
                    candidate.exact_model_id,
                    candidate.canonical_model_slug,
                }
                or record.actual_model
                not in {
                    candidate.exact_model_id,
                    candidate.canonical_model_slug,
                }
                or record.actual_provider_endpoint != candidate.approved_provider_endpoint
                or record.routing.get("selected_provider_name") != candidate.approved_provider_name
                or record.routing.get("selected_model") != record.actual_model
                or record.routing.get("canonical_model") != candidate.canonical_model_slug
                or record.routing.get("catalog_identity_binding_sha256")
                != canonical_sha256(
                    {
                        "canonical_slug": candidate.canonical_model_slug,
                        "id": candidate.exact_model_id,
                    }
                )
                or record.routing.get("discovery_evidence_sha256")
                != candidate.discovery_evidence_sha256
                or record.routing.get("endpoint_snapshot_sha256")
                != candidate.endpoint_snapshot_sha256
                or record.routing.get("endpoint_pricing_sha256")
                != candidate.pricing_snapshot_sha256
                for record in evidence.usage_records
            ):
                raise ValueError("benchmark runtime route differs from candidate")
        except ValueError:
            disposition = QualificationDisposition.INCONCLUSIVE
            benchmark_status = CandidateBenchmarkStatus.INCONCLUSIVE
            dimensions = ()
            overall_score = 0.0
            expiry: datetime | None = None
            verification_sha256: str | None = None
            failure_reasons = ("benchmark_real_verification_failed",)
            role_results = (
                evaluate_role_qualification_results(
                    global_disposition=disposition,
                    dimensions=dimensions,
                    role_policies=policy.role_policies,
                )
                if policy.role_policies
                else ()
            )
        else:
            trusted.append(evidence)
            dimensions = evidence.dimensions
            overall_score = round(
                sum(item.score for item in dimensions) / len(dimensions),
                6,
            )
            tier_a = (
                overall_score >= policy.tier_a_minimum_overall_score
                and set(item.dimension for item in dimensions) == set(thresholds)
                and all(
                    next(item for item in dimensions if item.dimension is dimension).evaluated
                    >= threshold.minimum_cases
                    and next(item for item in dimensions if item.dimension is dimension).score
                    >= threshold.minimum_score
                    for dimension, threshold in thresholds.items()
                )
            )
            disposition = (
                QualificationDisposition.TIER_A
                if tier_a
                else QualificationDisposition.NOT_QUALIFIED
            )
            benchmark_status = (
                CandidateBenchmarkStatus.PASSED if tier_a else CandidateBenchmarkStatus.FAILED
            )
            expiry = qualification_expires_at if tier_a else None
            verification_sha256 = evidence.verification_sha256
            failure_reasons = ()
            role_results = (
                evaluate_role_qualification_results(
                    global_disposition=disposition,
                    dimensions=dimensions,
                    role_policies=policy.role_policies,
                )
                if policy.role_policies
                else ()
            )
        approved_roles = (
            derive_approved_roles_for_role_qualification(
                declared_roles=candidate.approved_roles,
                global_disposition=disposition,
                role_results=role_results,
            )
            if policy.role_policies
            else candidate.approved_roles
        )
        if candidate.output_capability_sha256 is None or candidate.structured_output_mode is None:
            raise ValueError(
                f"candidate lacks output capability evidence: {candidate.exact_model_id}"
            )
        result = seal_model_qualification_result(
            exact_model_id=model_id,
            canonical_model_slug=candidate.canonical_model_slug,
            root_lineage=candidate.root_lineage,
            approved_provider_endpoint=candidate.approved_provider_endpoint,
            approved_provider_name=candidate.approved_provider_name,
            endpoint_snapshot_sha256=candidate.endpoint_snapshot_sha256,
            output_capability_sha256=candidate.output_capability_sha256,
            model_metadata_snapshot_sha256=(candidate.model_metadata_snapshot_sha256),
            pricing_snapshot_sha256=candidate.pricing_snapshot_sha256,
            structured_output_mode=candidate.structured_output_mode,
            benchmark_report_sha256=report.report_sha256,
            benchmark_verification_sha256=verification_sha256,
            disposition=disposition,
            dimensions=dimensions,
            overall_score=overall_score,
            approved_roles=approved_roles,
            declared_roles=candidate.approved_roles if policy.role_policies else (),
            role_results=role_results,
            evaluated_at=campaign_completed_at,
            expires_at=expiry,
            failure_reasons=failure_reasons,
        )
        results.append(result)
        updated_candidates.append(
            CandidateModel.model_validate(
                candidate.model_copy(
                    update={
                        "benchmark_status": benchmark_status,
                        "benchmark_artifact_sha256": report.report_sha256,
                        "qualification_expires_at": expiry,
                    }
                ).model_dump(mode="json")
            )
        )

    updated_registry = seal_candidate_registry(
        created_at=candidate_registry.created_at,
        discovery_run_sha256=candidate_registry.discovery_run_sha256,
        candidates=tuple(updated_candidates),
    )
    validate_candidate_registry_discovery(
        registry=updated_registry,
        run_manifest=discovery_run_manifest,
        evidence=discovery_evidence,
    )
    bindings = QualificationBindings(
        source_commit=release_bindings.source_commit,
        source_tree_sha256=release_bindings.source_tree_sha256,
        effective_config_sha256=release_bindings.effective_config_sha256,
        prompt_sha256=release_bindings.prompt_sha256,
        response_schema_sha256=release_bindings.response_schema_sha256,
        toolchain_sha256=release_bindings.toolchain_sha256,
        isolation_sha256=release_bindings.isolation_sha256,
        benchmark_corpus_version=release_bindings.benchmark_corpus_version,
        benchmark_corpus_sha256=benchmark_suite.corpus_sha256,
        benchmark_ground_truth_version=(release_bindings.benchmark_ground_truth_version),
        benchmark_ground_truth_sha256=benchmark_suite.ground_truth_sha256,
        benchmark_portfolio_sha256=benchmark_portfolio.portfolio_sha256,
        candidate_registry_sha256=updated_registry.registry_sha256,
        qualification_policy_sha256=policy.policy_sha256,
    )
    artifact = seal_model_qualification_artifact(
        created_at=campaign_completed_at,
        bindings=bindings,
        results=tuple(results),
    )
    trusted_tuple = tuple(sorted(trusted, key=lambda item: item.exact_model_id))
    verification = verify_model_qualification(
        artifact=artifact,
        registry=updated_registry,
        policy=policy,
        expected_bindings=bindings,
        trusted_benchmark_evidence=trusted_tuple,
        now=observed_at,
        trusted_calibrated_policy=trusted_calibrated_policy,
    )
    if validated_reasoning_plan is not None:
        results_by_model = {result.exact_model_id: result for result in artifact.results}
        if (
            validated_reasoning_plan.qualification_artifact_sha256 != artifact.artifact_sha256
            or any(
                route.exact_model_id not in results_by_model
                or route.qualification_result_sha256
                != results_by_model[route.exact_model_id].result_sha256
                for route in validated_reasoning_plan.routes
            )
        ):
            raise ValueError("reasoning benchmark plan differs from recomputed qualification")
        routes_by_key = {
            (route.exact_model_id, route.request_role): route
            for route in validated_reasoning_plan.routes
        }
        if any(
            not _reasoning_profile_evidence_passes_policy(
                evidence=evidence,
                qualified_roles=routes_by_key[
                    (evidence.exact_model_id, evidence.usage_records[0].role)
                ].qualified_roles,
                policy=policy,
            )
            for evidence in trusted_reasoning
        ):
            verification = _downgrade_profile_incomplete_verification(verification)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "evaluated_at": campaign_completed_at.isoformat().replace("+00:00", "Z"),
        "qualification_expires_at": qualification_expires_at.isoformat().replace(
            "+00:00",
            "Z",
        ),
        "input_registry_sha256": candidate_registry.registry_sha256,
        "discovery_manifest_sha256": discovery_run_manifest.manifest_sha256,
        "release_bindings": release_bindings.model_dump(mode="json"),
        "policy_sha256": policy.policy_sha256,
        "benchmark_corpus_sha256": benchmark_suite.corpus_sha256,
        "benchmark_ground_truth_sha256": benchmark_suite.ground_truth_sha256,
        "benchmark_portfolio_sha256": benchmark_portfolio.portfolio_sha256,
        "benchmark_reports": [report.model_dump(mode="json") for report in reports],
        "reasoning_benchmark_plan": (
            None
            if validated_reasoning_plan is None
            else validated_reasoning_plan.model_dump(mode="json")
        ),
        "reasoning_benchmark_reports": [
            report.model_dump(mode="json") for report in reasoning_reports
        ],
        "updated_registry": updated_registry.model_dump(mode="json"),
        "trusted_benchmark_evidence": [item.model_dump(mode="json") for item in trusted_tuple],
        "trusted_reasoning_benchmark_evidence": [
            item.model_dump(mode="json") for item in trusted_reasoning
        ],
        "qualification_artifact": artifact.model_dump(mode="json"),
        "qualification_verification": verification.model_dump(mode="json"),
    }
    payload["workflow_sha256"] = canonical_sha256(payload)
    return QualificationWorkflowBundle.model_validate(payload)


def _validate_benchmark_portfolio_binding(
    *,
    portfolio: ModelBenchmarkPortfolio,
    registry: CandidateRegistry,
    suite: ModelBenchmarkSuite,
    reports: tuple[ModelBenchmarkReport, ...],
    policy: QualificationPolicy,
) -> None:
    """Require one complete REAL portfolio bound to the exact qualification inputs."""

    validate_qualification_portfolio_readiness(portfolio=portfolio, policy=policy)
    candidate_ids = tuple(candidate.exact_model_id for candidate in registry.candidates)
    report_bindings = tuple(
        (
            report.results[0].target.model_id,
            report.report_sha256,
            report.execution_evidence,
        )
        for report in reports
    )
    artifact_bindings = tuple(
        (
            artifact.exact_model_id,
            artifact.report_sha256,
            artifact.execution_evidence,
        )
        for artifact in portfolio.report_artifacts
    )
    if (
        portfolio.candidate_registry_sha256 != registry.registry_sha256
        or portfolio.discovery_run_manifest_sha256 != registry.discovery_run_sha256
        or portfolio.candidate_model_ids != candidate_ids
        or portfolio.corpus_name != suite.name
        or portfolio.corpus_sha256 != suite.corpus_sha256
        or portfolio.ground_truth_sha256 != suite.ground_truth_sha256
        or artifact_bindings != report_bindings
    ):
        raise ValueError(
            "qualification benchmark portfolio differs from the registry, corpus, or reports"
        )
    if any(
        evidence_kind is not ExecutionEvidenceKind.REAL
        for _model_id, _report_sha256, evidence_kind in report_bindings
    ):
        raise ValueError("qualification requires one complete REAL benchmark portfolio")


def validate_qualification_portfolio_readiness(
    *,
    portfolio: ModelBenchmarkPortfolio,
    policy: QualificationPolicy,
) -> None:
    """Fail closed unless a completed campaign and reconciled budget back qualification."""

    validated_policy = QualificationPolicy.model_validate(policy.model_dump(mode="json"))
    initial = portfolio.initial_cost_ledger_snapshot
    final = portfolio.cost_ledger_snapshot
    snapshots = tuple(item for item in (initial, final) if item is not None)
    if (
        portfolio.execution_evidence is not ExecutionEvidenceKind.REAL
        or portfolio.usage.usage_record_count == 0
        or portfolio.usage.failed_request_count != 0
        or portfolio.usage.unresolved_cost_count != 0
        or not portfolio.diagnostics
        or portfolio.campaign_journal_sha256 is None
        or portfolio.qualification_policy_sha256 != validated_policy.policy_sha256
        or initial is None
        or final is None
        or any(
            artifact.execution_evidence is not ExecutionEvidenceKind.REAL
            for artifact in portfolio.report_artifacts
        )
        or any(
            diagnostic.state is not CandidateBenchmarkRunState.COMPLETE
            or diagnostic.failed_request_count != 0
            or diagnostic.unresolved_cost_count != 0
            for diagnostic in portfolio.diagnostics
        )
        or any(
            snapshot.reserved_count != 0
            or snapshot.uncertain_accounted_count != 0
            or snapshot.reservation_overrun_count != 0
            or snapshot.active_reserved_usd != "0"
            or snapshot.over_cap
            or snapshot.has_reservation_overrun
            for snapshot in snapshots
        )
    ):
        raise ValueError(
            "model qualification requires a journal-bound, policy-matched, "
            "reconciled, complete non-empty all-REAL benchmark portfolio"
        )


def _portfolio_completion_anchor(portfolio: ModelBenchmarkPortfolio) -> datetime:
    """Return the first whole UTC second at or after the last campaign request."""

    ended_at = portfolio.ended_at
    if ended_at is None:
        raise ValueError("qualification benchmark portfolio has no completion timestamp")
    if ended_at.tzinfo is None or ended_at.utcoffset() != timedelta(0):
        raise ValueError("qualification benchmark completion must be UTC")
    if ended_at.microsecond:
        ended_at = (ended_at + timedelta(seconds=1)).replace(microsecond=0)
    return _utc_second(ended_at, label="qualification benchmark completion")


def _validated_exact_report_set(
    *,
    reports: tuple[ModelBenchmarkReport, ...],
    expected_model_ids: tuple[str, ...],
) -> tuple[ModelBenchmarkReport, ...]:
    if not reports or len(reports) > _MAX_REPORTS:
        raise ValueError("qualification requires a bounded non-empty report set")
    validated: list[ModelBenchmarkReport] = []
    for supplied in reports:
        try:
            report = ModelBenchmarkReport.model_validate(supplied.model_dump(mode="json"))
        except ValueError:
            raise ValueError("qualification benchmark report is malformed") from None
        if len(report.results) != 1:
            raise ValueError("qualification requires exact one-model benchmark reports")
        validated.append(report)
    ordered = tuple(sorted(validated, key=lambda item: item.results[0].target.model_id))
    observed = tuple(report.results[0].target.model_id for report in ordered)
    if observed != tuple(sorted(set(observed))):
        raise ValueError("qualification benchmark reports contain duplicate models")
    if observed != expected_model_ids:
        raise ValueError("qualification benchmark report set differs from candidates")
    return ordered


def _load_bounded_json_model[ModelT: StrictModel](
    path: Path,
    *,
    model: type[ModelT],
    maximum_bytes: int,
    label: str,
) -> ModelT:
    loaded, _raw = _load_bounded_json_model_with_bytes(
        path,
        model=model,
        maximum_bytes=maximum_bytes,
        label=label,
    )
    return loaded


def _load_bounded_json_model_with_bytes[ModelT: StrictModel](
    path: Path,
    *,
    model: type[ModelT],
    maximum_bytes: int,
    label: str,
    require_private_mode: bool = False,
) -> tuple[ModelT, bytes]:
    absolute = Path(os.path.abspath(path))
    _reject_linked_components(absolute)
    try:
        metadata = absolute.stat()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > maximum_bytes
    ):
        raise ValueError(f"{label} must be a bounded unshared regular file")
    if require_private_mode and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError(f"{label} must not grant group or world permissions")
    try:
        raw = absolute.read_bytes()
        payload = json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} could not be parsed") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must contain one JSON object")
    try:
        loaded = model.model_validate(payload)
    except ValueError as exc:
        raise ValueError(f"{label} failed strict validation") from exc
    return loaded, raw


def _reject_linked_components(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink() or current.is_junction():
            raise ValueError("qualification artifact paths cannot traverse links")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result
