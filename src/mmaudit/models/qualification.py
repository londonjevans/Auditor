"""Fail-closed model qualification, production selection, and ensemble evidence.

Qualification is deliberately separate from model discovery and benchmark execution.
All production eligibility decisions are recomputed from immutable local evidence;
neither a model-authored tier nor a self-declared benchmark report is trusted.
"""

from __future__ import annotations

import json
import re
import stat
import tomllib
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, TypeAdapter, field_validator, model_validator

from mmaudit.agents.specialists import canonical_specialist_role
from mmaudit.benchmark.models import (
    ModelBenchmarkDimension,
    ModelBenchmarkReport,
    ModelBenchmarkSuite,
    verify_model_benchmark_report_structure,
)
from mmaudit.models.discovery import (
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
)
from mmaudit.models.generation_evidence import (
    OpenRouterGenerationEvidence,
    TrustedGenerationVerification,
    reconcile_generation_evidence,
)
from mmaudit.models.identifiers import (
    EXACT_MODEL_ID_PATTERN,
    require_exact_openrouter_model_id,
)
from mmaudit.models.schemas import ExecutionEvidenceKind, StrictModel, UsageRecord
from mmaudit.models.usage import is_creditable_usage_record
from mmaudit.orchestration.manifest import canonical_sha256

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_LINEAGE_PATTERN = r"^sha256:[0-9a-f]{64}$"
_COMMIT_PATTERN = r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$"
_MODEL_PATTERN = EXACT_MODEL_ID_PATTERN
_ENDPOINT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$"
_PROVIDER_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9 ._:/()&+-]{0,199}$"
_ROLE_PATTERN = r"^[a-z][a-z0-9_:.-]{0,127}$"
_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$"
_MAX_INPUT_BYTES = 50_000_000
_FUTURE_SKEW = timedelta(minutes=5)
_MIN_EXACT_MODELS = 8
_MIN_ROOT_LINEAGES = 6
_MIN_SPECIALIST_RESPONSIBILITIES = 24
_MIN_WHOLE_PROTOCOL_LINEAGES = 4
_MIN_CRITICAL_SURFACE_LINEAGES = 3
_MIN_FALSIFIER_LINEAGES = 2

_JSON_ADAPTER = TypeAdapter(Any)


class LineageReviewStatus(StrEnum):
    """Explicit operator review state; discovery is allowed to remain pending."""

    PENDING = "pending"
    REJECTED = "rejected"
    APPROVED = "approved"


class CandidateOperationalStatus(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DEPRECATED = "deprecated"
    UNKNOWN = "unknown"


class CandidateBenchmarkStatus(StrEnum):
    PENDING = "pending"
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    EXPIRED = "expired"


class QualificationDisposition(StrEnum):
    TIER_A = "tier_a"
    NOT_QUALIFIED = "not_qualified"
    INCONCLUSIVE = "inconclusive"


class RequirementState(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"


def _validate_exact_model_id(value: str) -> str:
    return require_exact_openrouter_model_id(value)


def _validate_sorted_unique(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    if values != tuple(sorted(set(values))):
        raise ValueError(f"{label} must be unique and sorted")
    return values


def _validate_utc_second(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond != 0:
        raise ValueError(f"{label} must be a whole-second UTC timestamp")
    return value


def _canonical_json_sha256(value: Any) -> str:
    return canonical_sha256(_JSON_ADAPTER.dump_python(value, mode="json"))


class OperatorLineageReview(StrictModel):
    """Self-hashed operator decision over exact IDs that share one root lineage."""

    status: LineageReviewStatus
    reviewed_model_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    root_lineage: str | None = Field(default=None, pattern=_LINEAGE_PATTERN)
    reviewed_by: str | None = Field(default=None, min_length=1, max_length=200)
    reviewed_at: datetime | None = None
    rationale: str = Field(min_length=1, max_length=2_000)
    evidence_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    review_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("reviewed_model_ids")
    @classmethod
    def model_ids_are_exact_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for model_id in value:
            _validate_exact_model_id(model_id)
        return _validate_sorted_unique(value, label="reviewed model IDs")

    @field_validator("reviewed_at")
    @classmethod
    def reviewed_at_is_utc(cls, value: datetime | None) -> datetime | None:
        return (
            None if value is None else _validate_utc_second(value, label="lineage review timestamp")
        )

    @model_validator(mode="after")
    def decision_and_hash_are_consistent(self) -> OperatorLineageReview:
        decided = self.status in {
            LineageReviewStatus.APPROVED,
            LineageReviewStatus.REJECTED,
        }
        if decided and (
            self.reviewed_by is None or self.reviewed_at is None or self.evidence_sha256 is None
        ):
            raise ValueError("decided lineage review requires reviewer, time, and evidence")
        if not decided and any(
            value is not None
            for value in (
                self.root_lineage,
                self.reviewed_by,
                self.reviewed_at,
                self.evidence_sha256,
            )
        ):
            raise ValueError("pending lineage review cannot claim a decision or lineage")
        if self.status is LineageReviewStatus.APPROVED and self.root_lineage is None:
            raise ValueError("approved lineage review requires an immutable root lineage")
        if self.status is LineageReviewStatus.REJECTED and self.root_lineage is not None:
            raise ValueError("rejected lineage review cannot approve a root lineage")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"review_sha256"}))
        if self.review_sha256 != expected:
            raise ValueError("operator lineage review self-hash is inconsistent")
        return self


def seal_operator_lineage_review(
    *,
    status: LineageReviewStatus,
    reviewed_model_ids: tuple[str, ...],
    rationale: str,
    root_lineage: str | None = None,
    reviewed_by: str | None = None,
    reviewed_at: datetime | None = None,
    evidence_sha256: str | None = None,
) -> OperatorLineageReview:
    payload: dict[str, Any] = {
        "status": status.value,
        "reviewed_model_ids": list(reviewed_model_ids),
        "root_lineage": root_lineage,
        "reviewed_by": reviewed_by,
        "reviewed_at": reviewed_at,
        "rationale": rationale,
        "evidence_sha256": evidence_sha256,
    }
    payload["review_sha256"] = _canonical_json_sha256(payload)
    return OperatorLineageReview.model_validate(payload)


class CandidateModel(StrictModel):
    """One exact discovered model plus operator-controlled qualification metadata."""

    exact_model_id: str = Field(pattern=_MODEL_PATTERN, max_length=300)
    canonical_model_slug: str = Field(pattern=_MODEL_PATTERN, max_length=300)
    root_lineage: str | None = Field(default=None, pattern=_LINEAGE_PATTERN)
    lineage_review: OperatorLineageReview
    discovery_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    approved_provider_endpoint: str = Field(pattern=_ENDPOINT_PATTERN)
    approved_provider_name: str = Field(pattern=_PROVIDER_NAME_PATTERN)
    endpoint_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    model_metadata_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    pricing_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    context_size: int = Field(ge=1)
    output_limit: int = Field(ge=1)
    structured_output_supported: bool
    reasoning_supported: bool
    zdr_eligible: bool
    data_collection_deny_eligible: bool
    operational_status: CandidateOperationalStatus
    benchmark_status: CandidateBenchmarkStatus = CandidateBenchmarkStatus.PENDING
    benchmark_artifact_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    qualification_expires_at: datetime | None = None
    approved_roles: tuple[str, ...] = Field(default=(), max_length=128)

    @field_validator("exact_model_id", "canonical_model_slug")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        return _validate_exact_model_id(value)

    @field_validator("approved_roles")
    @classmethod
    def roles_are_safe_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(_ROLE_PATTERN, role) is None for role in value):
            raise ValueError("approved roles must be safe canonical role names")
        return _validate_sorted_unique(value, label="approved roles")

    @field_validator("qualification_expires_at")
    @classmethod
    def qualification_expiry_is_utc(cls, value: datetime | None) -> datetime | None:
        return (
            None
            if value is None
            else _validate_utc_second(value, label="candidate qualification expiry")
        )

    @model_validator(mode="after")
    def lineage_and_benchmark_state_are_consistent(self) -> CandidateModel:
        if self.exact_model_id not in self.lineage_review.reviewed_model_ids:
            raise ValueError("candidate exact model ID is outside its lineage review")
        approved = self.lineage_review.status is LineageReviewStatus.APPROVED
        if approved and self.root_lineage != self.lineage_review.root_lineage:
            raise ValueError("candidate root lineage differs from approved review")
        if not approved and self.root_lineage is not None:
            raise ValueError("pending or rejected lineage review cannot assign a root lineage")
        if self.benchmark_status is CandidateBenchmarkStatus.PENDING:
            if (
                self.benchmark_artifact_sha256 is not None
                or self.qualification_expires_at is not None
            ):
                raise ValueError("pending benchmark cannot claim artifact or qualification expiry")
        elif self.benchmark_artifact_sha256 is None:
            raise ValueError("completed benchmark status requires an artifact hash")
        if (
            self.benchmark_status
            in {
                CandidateBenchmarkStatus.PASSED,
                CandidateBenchmarkStatus.EXPIRED,
            }
            and self.qualification_expires_at is None
        ):
            raise ValueError("passed or expired benchmark status requires an expiry")
        if (
            self.benchmark_status
            in {
                CandidateBenchmarkStatus.FAILED,
                CandidateBenchmarkStatus.INCONCLUSIVE,
            }
            and self.qualification_expires_at is not None
        ):
            raise ValueError("failed or inconclusive benchmark cannot claim a qualification expiry")
        return self


class CandidateRegistry(StrictModel):
    """Canonical discovered-candidate inventory; pending lineage review is valid."""

    schema_version: Literal["1.0"] = "1.0"
    created_at: datetime
    discovery_run_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidates: tuple[CandidateModel, ...] = Field(min_length=1, max_length=128)
    registry_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("created_at")
    @classmethod
    def created_at_is_utc(cls, value: datetime) -> datetime:
        return _validate_utc_second(value, label="candidate registry creation time")

    @model_validator(mode="after")
    def ordering_reviews_and_hash_are_consistent(self) -> CandidateRegistry:
        identifiers = tuple(candidate.exact_model_id for candidate in self.candidates)
        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("candidate models must be unique and sorted by exact ID")
        reviews_by_root: dict[str, str] = {}
        unique_reviews: dict[str, OperatorLineageReview] = {}
        canonical_bindings: dict[str, tuple[str | None, str]] = {}
        for candidate in self.candidates:
            existing_review = unique_reviews.setdefault(
                candidate.lineage_review.review_sha256,
                candidate.lineage_review,
            )
            if existing_review != candidate.lineage_review:
                raise ValueError("one review hash identifies conflicting lineage reviews")
            canonical_binding = (
                candidate.root_lineage,
                candidate.lineage_review.review_sha256,
            )
            previous_canonical = canonical_bindings.setdefault(
                candidate.canonical_model_slug,
                canonical_binding,
            )
            if previous_canonical != canonical_binding:
                raise ValueError("one canonical model slug has conflicting lineage assignments")
            if candidate.root_lineage is None:
                continue
            previous = reviews_by_root.setdefault(
                candidate.root_lineage,
                candidate.lineage_review.review_sha256,
            )
            if previous != candidate.lineage_review.review_sha256:
                raise ValueError("one root lineage has conflicting operator review artifacts")
        review_owner_by_model: dict[str, str] = {}
        for review_hash, review in unique_reviews.items():
            for reviewed_model_id in review.reviewed_model_ids:
                previous_owner = review_owner_by_model.setdefault(
                    reviewed_model_id,
                    review_hash,
                )
                if previous_owner != review_hash:
                    raise ValueError("operator lineage review groups overlap")
        if set(review_owner_by_model) != set(identifiers):
            raise ValueError("operator lineage reviews must cover the candidate set exactly once")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"registry_sha256"}))
        if self.registry_sha256 != expected:
            raise ValueError("candidate registry self-hash is inconsistent")
        return self


def seal_candidate_registry(
    *,
    created_at: datetime,
    discovery_run_sha256: str,
    candidates: tuple[CandidateModel, ...],
) -> CandidateRegistry:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "created_at": created_at,
        "discovery_run_sha256": discovery_run_sha256,
        "candidates": [
            candidate.model_dump(mode="json")
            for candidate in sorted(candidates, key=lambda item: item.exact_model_id)
        ],
    }
    payload["registry_sha256"] = _canonical_json_sha256(payload)
    return CandidateRegistry.model_validate(payload)


def validate_candidate_registry_discovery(
    *,
    registry: CandidateRegistry,
    run_manifest: OpenRouterModelDiscoveryRunManifest,
    evidence: tuple[OpenRouterModelDiscoveryEvidence, ...],
) -> None:
    """Cross-check every candidate against independently validated discovery evidence."""

    registry = CandidateRegistry.model_validate(registry.model_dump(mode="json"))
    run_manifest = OpenRouterModelDiscoveryRunManifest.model_validate(
        run_manifest.model_dump(mode="json")
    )
    validated = tuple(
        OpenRouterModelDiscoveryEvidence.model_validate(item.model_dump(mode="json"))
        for item in evidence
    )
    if registry.discovery_run_sha256 != run_manifest.manifest_sha256:
        raise ValueError("candidate registry does not bind the supplied discovery run")
    provenance = run_manifest.run_provenance
    if registry.created_at != provenance.retrieved_at:
        raise ValueError("candidate registry timestamp differs from discovery retrieval")
    if any(item.provenance != provenance for item in validated):
        raise ValueError("candidate registry evidence mixes discovery provenance")
    identifiers = tuple(item.exact_model_id for item in validated)
    expected_identifiers = tuple(route.exact_model_id for route in provenance.candidate_routes)
    if identifiers != expected_identifiers:
        raise ValueError("candidate evidence does not exactly cover discovery provenance")
    artifact_by_model = {artifact.exact_model_id: artifact for artifact in run_manifest.artifacts}
    for item in validated:
        artifact = artifact_by_model.get(item.exact_model_id)
        if (
            artifact is None
            or artifact.approved_provider_endpoint != item.approved_provider_endpoint
            or artifact.discovery_evidence_sha256 != item.discovery_evidence_sha256
        ):
            raise ValueError("candidate evidence differs from its discovery manifest")
    by_model = {item.exact_model_id: item for item in validated}
    if set(by_model) != {candidate.exact_model_id for candidate in registry.candidates}:
        raise ValueError("candidate registry differs from the discovery model inventory")
    for candidate in registry.candidates:
        item = by_model[candidate.exact_model_id]
        expected = (
            item.canonical_slug,
            item.discovery_evidence_sha256,
            item.approved_provider_endpoint,
            item.provider_name,
            item.endpoint_snapshot_sha256,
            item.model_metadata_snapshot_sha256,
            item.pricing_snapshot_sha256,
            item.context_size,
            item.output_limit,
            item.structured_output_supported,
            item.reasoning_supported,
            item.zdr_eligible,
            item.data_collection_deny_eligible,
        )
        observed = (
            candidate.canonical_model_slug,
            candidate.discovery_evidence_sha256,
            candidate.approved_provider_endpoint,
            candidate.approved_provider_name,
            candidate.endpoint_snapshot_sha256,
            candidate.model_metadata_snapshot_sha256,
            candidate.pricing_snapshot_sha256,
            candidate.context_size,
            candidate.output_limit,
            candidate.structured_output_supported,
            candidate.reasoning_supported,
            candidate.zdr_eligible,
            candidate.data_collection_deny_eligible,
        )
        if observed != expected or (
            candidate.operational_status is not CandidateOperationalStatus.AVAILABLE
        ):
            raise ValueError(
                f"candidate metadata differs from validated discovery: {candidate.exact_model_id}"
            )


class QualificationDimensionThreshold(StrictModel):
    dimension: ModelBenchmarkDimension
    minimum_cases: int = Field(ge=1, le=10_000)
    minimum_score: float = Field(ge=0, le=1)


class QualificationPolicy(StrictModel):
    """Self-hashed, non-vacuous Tier A policy."""

    schema_version: Literal["1.0"] = "1.0"
    created_at: datetime
    thresholds: tuple[QualificationDimensionThreshold, ...] = Field(
        min_length=len(ModelBenchmarkDimension),
        max_length=len(ModelBenchmarkDimension),
    )
    tier_a_minimum_overall_score: float = Field(ge=0, le=1)
    maximum_validity_days: int = Field(ge=1, le=90)
    require_real_execution: Literal[True] = True
    require_certification_routing: Literal[True] = True
    policy_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("created_at")
    @classmethod
    def created_at_is_utc(cls, value: datetime) -> datetime:
        return _validate_utc_second(value, label="qualification policy creation time")

    @model_validator(mode="after")
    def dimensions_and_hash_are_complete(self) -> QualificationPolicy:
        dimensions = tuple(threshold.dimension.value for threshold in self.thresholds)
        expected_dimensions = tuple(sorted(item.value for item in ModelBenchmarkDimension))
        if dimensions != expected_dimensions:
            raise ValueError("qualification thresholds must cover every dimension exactly once")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"policy_sha256"}))
        if self.policy_sha256 != expected:
            raise ValueError("qualification policy self-hash is inconsistent")
        return self


def seal_qualification_policy(
    *,
    created_at: datetime,
    thresholds: tuple[QualificationDimensionThreshold, ...],
    tier_a_minimum_overall_score: float,
    maximum_validity_days: int,
) -> QualificationPolicy:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "created_at": created_at,
        "thresholds": [
            threshold.model_dump(mode="json")
            for threshold in sorted(thresholds, key=lambda item: item.dimension.value)
        ],
        "tier_a_minimum_overall_score": float(tier_a_minimum_overall_score),
        "maximum_validity_days": maximum_validity_days,
        "require_real_execution": True,
        "require_certification_routing": True,
    }
    payload["policy_sha256"] = _canonical_json_sha256(payload)
    return QualificationPolicy.model_validate(payload)


class QualificationBindings(StrictModel):
    """Every mutable input that can change a qualification conclusion."""

    source_commit: str = Field(pattern=_COMMIT_PATTERN)
    source_tree_sha256: str = Field(pattern=_SHA256_PATTERN)
    effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    response_schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    toolchain_sha256: str = Field(pattern=_SHA256_PATTERN)
    isolation_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_corpus_version: str = Field(min_length=1, max_length=100)
    benchmark_corpus_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_ground_truth_version: str = Field(min_length=1, max_length=100)
    benchmark_ground_truth_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_portfolio_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    qualification_policy_sha256: str = Field(pattern=_SHA256_PATTERN)


class QualificationDimensionResult(StrictModel):
    dimension: ModelBenchmarkDimension
    passed: int = Field(ge=0)
    evaluated: int = Field(ge=1)
    score: float = Field(ge=0, le=1)

    @model_validator(mode="after")
    def arithmetic_is_consistent(self) -> QualificationDimensionResult:
        if self.passed > self.evaluated or self.score != round(
            self.passed / self.evaluated,
            6,
        ):
            raise ValueError("qualification dimension arithmetic is inconsistent")
        return self


class TrustedBenchmarkVerificationEvidence(StrictModel):
    """Independent deterministic verification input, supplied outside the artifact.

    This evidence must be produced by re-parsing and re-scoring structured responses
    against private ground truth and binding each request to authenticated generation
    evidence. A benchmark report's own execution label is insufficient.
    """

    schema_version: Literal["1.0"] = "1.0"
    verified_by: Literal["mmaudit-deterministic-benchmark-verifier"] = (
        "mmaudit-deterministic-benchmark-verifier"
    )
    exact_model_id: str = Field(pattern=_MODEL_PATTERN, max_length=300)
    benchmark_report_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_corpus_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_ground_truth_sha256: str = Field(pattern=_SHA256_PATTERN)
    prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    response_schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    parsed_responses_sha256: str = Field(pattern=_SHA256_PATTERN)
    generation_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    case_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    usage_records: tuple[UsageRecord, ...] = Field(min_length=1, max_length=10_000)
    generation_attestations: tuple[OpenRouterGenerationEvidence, ...] = Field(
        min_length=1,
        max_length=10_000,
    )
    dimensions: tuple[QualificationDimensionResult, ...] = Field(
        min_length=len(ModelBenchmarkDimension),
        max_length=len(ModelBenchmarkDimension),
    )
    execution_evidence: Literal[ExecutionEvidenceKind.REAL] = ExecutionEvidenceKind.REAL
    valid: Literal[True] = True
    verification_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        return _validate_exact_model_id(value)

    @field_validator("case_ids")
    @classmethod
    def case_ids_are_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(_ID_PATTERN, item) is None for item in value):
            raise ValueError("benchmark case IDs are malformed")
        return _validate_sorted_unique(value, label="benchmark case IDs")

    @model_validator(mode="after")
    def evidence_is_non_vacuous_and_self_hashed(
        self,
    ) -> TrustedBenchmarkVerificationEvidence:
        dimensions = tuple(item.dimension.value for item in self.dimensions)
        if dimensions != tuple(sorted(item.value for item in ModelBenchmarkDimension)):
            raise ValueError("verified benchmark must cover every dimension exactly once")
        request_ids = tuple(record.request_id for record in self.usage_records)
        generation_ids = tuple(
            record.openrouter_generation_id or "" for record in self.usage_records
        )
        attestation_ids = tuple(
            attestation.generation_id for attestation in self.generation_attestations
        )
        if request_ids != tuple(sorted(request_ids)):
            raise ValueError("verified benchmark usage records must be sorted by request ID")
        if attestation_ids != tuple(sorted(attestation_ids)):
            raise ValueError("generation attestations must be sorted by generation ID")
        if len(request_ids) != len(set(request_ids)) or len(generation_ids) != len(
            set(generation_ids)
        ):
            raise ValueError("verified benchmark request and generation IDs must be unique")
        if set(generation_ids) != set(attestation_ids):
            raise ValueError("verified benchmark usage and generation evidence differ")
        attestations = {
            attestation.generation_id: attestation for attestation in self.generation_attestations
        }
        for record in self.usage_records:
            generation_id = record.openrouter_generation_id
            provider_name = record.routing.get("selected_provider_name")
            if generation_id is None or not isinstance(provider_name, str):
                raise ValueError("verified benchmark usage lacks provider generation identity")
            reconcile_generation_evidence(
                attestations[generation_id],
                usage_record=record,
                expected_exact_model=self.exact_model_id,
                expected_provider_name=provider_name,
            )
        expected_generation_hash = canonical_sha256(
            [attestation.model_dump(mode="json") for attestation in self.generation_attestations]
        )
        if self.generation_evidence_sha256 != expected_generation_hash:
            raise ValueError("verified benchmark generation-evidence hash is inconsistent")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"verification_sha256"}))
        if self.verification_sha256 != expected:
            raise ValueError("trusted benchmark verification self-hash is inconsistent")
        return self


def verify_and_seal_trusted_benchmark_evidence(
    *,
    report: ModelBenchmarkReport,
    corpus: ModelBenchmarkSuite,
    exact_model_id: str,
    trusted_generation_verification: TrustedGenerationVerification,
) -> TrustedBenchmarkVerificationEvidence:
    """Recompute and seal one model result after authenticated generation re-fetches."""

    exact_model_id = _validate_exact_model_id(exact_model_id)
    verify_model_benchmark_report_structure(report, corpus=corpus)
    if type(trusted_generation_verification) is not TrustedGenerationVerification:
        raise ValueError("REAL benchmark qualification requires trusted generation verification")
    if report.execution_evidence is not ExecutionEvidenceKind.REAL:
        raise ValueError("REAL model benchmark qualification requires all-real execution")
    matches = [result for result in report.results if result.target.model_id == exact_model_id]
    if len(matches) != 1:
        raise ValueError("verified benchmark report lacks one exact requested model result")
    result = matches[0]
    fresh_attestations: list[OpenRouterGenerationEvidence] = []
    for case in result.cases:
        record = case.usage_record
        embedded = case.generation_evidence
        if (
            case.execution_evidence is not ExecutionEvidenceKind.REAL
            or record is None
            or embedded is None
        ):
            raise ValueError("verified REAL benchmark omitted runtime evidence")
        provider_name = record.routing.get("selected_provider_name")
        if not isinstance(provider_name, str):
            raise ValueError("verified REAL benchmark omitted provider identity")
        try:
            fresh = trusted_generation_verification.attestation_for(
                benchmark_report_sha256=report.report_sha256,
                case_id=case.case_id,
                exact_model_id=exact_model_id,
                usage_record=record,
                expected_provider_name=provider_name,
            )
        except ValueError:
            raise ValueError(
                "verified REAL benchmark generation was not freshly resolved"
            ) from None
        embedded_fields = embedded.model_dump(
            mode="json",
            exclude={"retrieved_at", "evidence_sha256"},
        )
        fresh_fields = fresh.model_dump(
            mode="json",
            exclude={"retrieved_at", "evidence_sha256"},
        )
        if embedded_fields != fresh_fields:
            raise ValueError("fresh generation metadata differs from embedded benchmark evidence")
        fresh_attestations.append(fresh)
    records = tuple(
        sorted(
            (case.usage_record for case in result.cases if case.usage_record is not None),
            key=lambda item: item.request_id,
        )
    )
    attestations = tuple(sorted(fresh_attestations, key=lambda item: item.generation_id))
    if len(records) != len(result.cases) or len(attestations) != len(result.cases):
        raise ValueError("verified REAL benchmark omitted request or generation evidence")
    prompt_set_sha256 = canonical_sha256(sorted(record.prompt_sha256 for record in records))
    schema_hashes = {record.schema_sha256 for record in records}
    if None in schema_hashes or len(schema_hashes) != 1:
        raise ValueError("verified benchmark response schema evidence is inconsistent")
    response_schema_sha256 = next(iter(schema_hashes))
    assert response_schema_sha256 is not None
    parsed_responses_sha256 = canonical_sha256(
        [
            case.normalized_response.model_dump(mode="json")
            if case.normalized_response is not None
            else None
            for case in result.cases
        ]
    )
    dimensions = tuple(
        QualificationDimensionResult(
            dimension=dimension.dimension,
            passed=dimension.passed,
            evaluated=dimension.evaluated,
            score=dimension.score,
        )
        for dimension in result.dimensions
    )
    return _seal_trusted_benchmark_verification(
        exact_model_id=exact_model_id,
        benchmark_report_sha256=report.report_sha256,
        benchmark_corpus_sha256=corpus.corpus_sha256,
        benchmark_ground_truth_sha256=corpus.ground_truth_sha256,
        prompt_sha256=prompt_set_sha256,
        response_schema_sha256=response_schema_sha256,
        parsed_responses_sha256=parsed_responses_sha256,
        case_ids=tuple(report.case_ids),
        usage_records=records,
        generation_attestations=attestations,
        dimensions=dimensions,
    )


def _seal_trusted_benchmark_verification(
    *,
    exact_model_id: str,
    benchmark_report_sha256: str,
    benchmark_corpus_sha256: str,
    benchmark_ground_truth_sha256: str,
    prompt_sha256: str,
    response_schema_sha256: str,
    parsed_responses_sha256: str,
    case_ids: tuple[str, ...],
    usage_records: tuple[UsageRecord, ...],
    generation_attestations: tuple[OpenRouterGenerationEvidence, ...],
    dimensions: tuple[QualificationDimensionResult, ...],
) -> TrustedBenchmarkVerificationEvidence:
    ordered_attestations = tuple(
        sorted(generation_attestations, key=lambda item: item.generation_id)
    )
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "verified_by": "mmaudit-deterministic-benchmark-verifier",
        "exact_model_id": exact_model_id,
        "benchmark_report_sha256": benchmark_report_sha256,
        "benchmark_corpus_sha256": benchmark_corpus_sha256,
        "benchmark_ground_truth_sha256": benchmark_ground_truth_sha256,
        "prompt_sha256": prompt_sha256,
        "response_schema_sha256": response_schema_sha256,
        "parsed_responses_sha256": parsed_responses_sha256,
        "generation_evidence_sha256": canonical_sha256(
            [item.model_dump(mode="json") for item in ordered_attestations]
        ),
        "case_ids": list(case_ids),
        "usage_records": [
            record.model_dump(mode="json")
            for record in sorted(usage_records, key=lambda item: item.request_id)
        ],
        "generation_attestations": [item.model_dump(mode="json") for item in ordered_attestations],
        "dimensions": [
            result.model_dump(mode="json")
            for result in sorted(dimensions, key=lambda item: item.dimension.value)
        ],
        "execution_evidence": ExecutionEvidenceKind.REAL.value,
        "valid": True,
    }
    payload["verification_sha256"] = _canonical_json_sha256(payload)
    return TrustedBenchmarkVerificationEvidence.model_validate(payload)


class ModelQualificationResult(StrictModel):
    """Deterministic qualification conclusion for one exact candidate."""

    exact_model_id: str = Field(pattern=_MODEL_PATTERN, max_length=300)
    canonical_model_slug: str = Field(pattern=_MODEL_PATTERN, max_length=300)
    root_lineage: str | None = Field(default=None, pattern=_LINEAGE_PATTERN)
    approved_provider_endpoint: str = Field(pattern=_ENDPOINT_PATTERN)
    approved_provider_name: str = Field(pattern=_PROVIDER_NAME_PATTERN)
    endpoint_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    model_metadata_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    pricing_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_report_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_verification_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    disposition: QualificationDisposition
    dimensions: tuple[QualificationDimensionResult, ...] = Field(
        default=(),
        max_length=len(ModelBenchmarkDimension),
    )
    overall_score: float = Field(ge=0, le=1)
    approved_roles: tuple[str, ...] = Field(default=(), max_length=128)
    evaluated_at: datetime
    expires_at: datetime | None = None
    failure_reasons: tuple[str, ...] = Field(default=(), max_length=100)
    scored_by: Literal["mmaudit-deterministic-qualification"] = (
        "mmaudit-deterministic-qualification"
    )
    result_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id", "canonical_model_slug")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        return _validate_exact_model_id(value)

    @field_validator("approved_roles")
    @classmethod
    def roles_are_safe_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(_ROLE_PATTERN, role) is None for role in value):
            raise ValueError("qualification roles must be safe canonical role names")
        return _validate_sorted_unique(value, label="qualification roles")

    @field_validator("evaluated_at", "expires_at")
    @classmethod
    def times_are_utc(cls, value: datetime | None) -> datetime | None:
        return (
            None
            if value is None
            else _validate_utc_second(value, label="qualification result timestamp")
        )

    @field_validator("failure_reasons")
    @classmethod
    def failure_reasons_are_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _validate_sorted_unique(value, label="qualification failure reasons")

    @model_validator(mode="after")
    def conclusion_and_hash_are_consistent(self) -> ModelQualificationResult:
        complete = self.disposition in {
            QualificationDisposition.TIER_A,
            QualificationDisposition.NOT_QUALIFIED,
        }
        if complete:
            names = tuple(result.dimension.value for result in self.dimensions)
            if names != tuple(sorted(item.value for item in ModelBenchmarkDimension)):
                raise ValueError("completed qualification must retain every dimension")
            if self.benchmark_verification_sha256 is None:
                raise ValueError("completed qualification requires independent verification")
            expected_overall = round(
                sum(result.score for result in self.dimensions) / len(self.dimensions),
                6,
            )
            if self.overall_score != expected_overall:
                raise ValueError("qualification overall score is inconsistent")
            if self.failure_reasons:
                raise ValueError("completed qualification cannot contain failure reasons")
        else:
            if (
                self.dimensions
                or self.benchmark_verification_sha256 is not None
                or self.overall_score != 0
                or not self.failure_reasons
            ):
                raise ValueError("inconclusive qualification requires only explicit failures")
        if self.disposition is QualificationDisposition.TIER_A:
            if self.expires_at is None:
                raise ValueError("Tier A qualification requires an expiry")
        elif self.expires_at is not None:
            raise ValueError("non-Tier-A qualification cannot claim an expiry")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"result_sha256"}))
        if self.result_sha256 != expected:
            raise ValueError("model qualification result self-hash is inconsistent")
        return self


def seal_model_qualification_result(
    *,
    exact_model_id: str,
    canonical_model_slug: str,
    root_lineage: str | None,
    approved_provider_endpoint: str,
    approved_provider_name: str,
    endpoint_snapshot_sha256: str,
    model_metadata_snapshot_sha256: str,
    pricing_snapshot_sha256: str,
    benchmark_report_sha256: str,
    benchmark_verification_sha256: str | None,
    disposition: QualificationDisposition,
    dimensions: tuple[QualificationDimensionResult, ...],
    overall_score: float,
    approved_roles: tuple[str, ...],
    evaluated_at: datetime,
    expires_at: datetime | None,
    failure_reasons: tuple[str, ...] = (),
) -> ModelQualificationResult:
    payload: dict[str, Any] = {
        "exact_model_id": exact_model_id,
        "canonical_model_slug": canonical_model_slug,
        "root_lineage": root_lineage,
        "approved_provider_endpoint": approved_provider_endpoint,
        "approved_provider_name": approved_provider_name,
        "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
        "model_metadata_snapshot_sha256": model_metadata_snapshot_sha256,
        "pricing_snapshot_sha256": pricing_snapshot_sha256,
        "benchmark_report_sha256": benchmark_report_sha256,
        "benchmark_verification_sha256": benchmark_verification_sha256,
        "disposition": disposition.value,
        "dimensions": [
            result.model_dump(mode="json")
            for result in sorted(dimensions, key=lambda item: item.dimension.value)
        ],
        "overall_score": overall_score,
        "approved_roles": list(approved_roles),
        "evaluated_at": evaluated_at,
        "expires_at": expires_at,
        "failure_reasons": list(failure_reasons),
        "scored_by": "mmaudit-deterministic-qualification",
    }
    payload["result_sha256"] = _canonical_json_sha256(payload)
    return ModelQualificationResult.model_validate(payload)


class ModelQualificationArtifact(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    created_at: datetime
    bindings: QualificationBindings
    results: tuple[ModelQualificationResult, ...] = Field(min_length=1, max_length=128)
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("created_at")
    @classmethod
    def created_at_is_utc(cls, value: datetime) -> datetime:
        return _validate_utc_second(value, label="qualification artifact creation time")

    @model_validator(mode="after")
    def ordering_and_hash_are_consistent(self) -> ModelQualificationArtifact:
        identifiers = tuple(result.exact_model_id for result in self.results)
        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("qualification results must be unique and sorted by exact model")
        if any(result.evaluated_at > self.created_at for result in self.results):
            raise ValueError("qualification result cannot postdate its artifact")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"artifact_sha256"}))
        if self.artifact_sha256 != expected:
            raise ValueError("model qualification artifact self-hash is inconsistent")
        return self


def seal_model_qualification_artifact(
    *,
    created_at: datetime,
    bindings: QualificationBindings,
    results: tuple[ModelQualificationResult, ...],
) -> ModelQualificationArtifact:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "created_at": created_at,
        "bindings": bindings.model_dump(mode="json"),
        "results": [
            result.model_dump(mode="json")
            for result in sorted(results, key=lambda item: item.exact_model_id)
        ],
    }
    payload["artifact_sha256"] = _canonical_json_sha256(payload)
    return ModelQualificationArtifact.model_validate(payload)


class QualificationVerification(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    verified_at: datetime
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    eligible_tier_a_model_ids: tuple[str, ...]
    eligible_root_lineages: tuple[str, ...]
    production_selection_ready: bool
    valid: bool
    errors: tuple[str, ...]
    verification_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("verified_at")
    @classmethod
    def verified_at_is_utc(cls, value: datetime) -> datetime:
        return _validate_utc_second(value, label="qualification verification time")

    @model_validator(mode="after")
    def state_and_hash_are_consistent(self) -> QualificationVerification:
        _validate_sorted_unique(
            self.eligible_tier_a_model_ids,
            label="eligible Tier A model IDs",
        )
        _validate_sorted_unique(self.eligible_root_lineages, label="eligible root lineages")
        _validate_sorted_unique(self.errors, label="qualification verification errors")
        if self.valid != (not self.errors):
            raise ValueError("qualification verification validity differs from errors")
        expected_ready = (
            self.valid
            and len(self.eligible_tier_a_model_ids) >= _MIN_EXACT_MODELS
            and len(self.eligible_root_lineages) >= _MIN_ROOT_LINEAGES
        )
        if self.production_selection_ready is not expected_ready:
            raise ValueError("production-selection readiness differs from eligible evidence")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"verification_sha256"}))
        if self.verification_sha256 != expected:
            raise ValueError("qualification verification self-hash is inconsistent")
        return self


def verify_model_qualification(
    *,
    artifact: ModelQualificationArtifact,
    registry: CandidateRegistry,
    policy: QualificationPolicy,
    expected_bindings: QualificationBindings,
    trusted_benchmark_evidence: tuple[TrustedBenchmarkVerificationEvidence, ...],
    now: datetime,
) -> QualificationVerification:
    """Recompute production eligibility; unresolved evidence always fails closed."""

    now = _validate_utc_second(now, label="qualification verification time")
    errors: list[str] = []
    if artifact.bindings != expected_bindings:
        errors.append("qualification bindings differ from expected release inputs")
    if artifact.bindings.candidate_registry_sha256 != registry.registry_sha256:
        errors.append("qualification artifact does not bind the candidate registry")
    if artifact.bindings.qualification_policy_sha256 != policy.policy_sha256:
        errors.append("qualification artifact does not bind the qualification policy")
    if registry.created_at > artifact.created_at or policy.created_at > artifact.created_at:
        errors.append("qualification artifact predates a bound registry or policy")
    if artifact.created_at > now + _FUTURE_SKEW:
        errors.append("qualification artifact is future-dated")

    candidates = {candidate.exact_model_id: candidate for candidate in registry.candidates}
    results = {result.exact_model_id: result for result in artifact.results}
    if set(candidates) != set(results):
        errors.append("qualification results do not cover the exact candidate set")

    evidence_by_model: dict[str, TrustedBenchmarkVerificationEvidence] = {}
    for supplied_evidence in trusted_benchmark_evidence:
        try:
            trusted_evidence = TrustedBenchmarkVerificationEvidence.model_validate(
                supplied_evidence.model_dump(mode="json")
            )
        except ValueError:
            errors.append("trusted benchmark evidence is schema-invalid")
            continue
        if trusted_evidence.exact_model_id in evidence_by_model:
            errors.append(
                f"duplicate trusted benchmark evidence: {trusted_evidence.exact_model_id}"
            )
        evidence_by_model[trusted_evidence.exact_model_id] = trusted_evidence

    thresholds = {threshold.dimension: threshold for threshold in policy.thresholds}
    eligible_ids: list[str] = []
    eligible_roots: list[str] = []
    for model_id in sorted(set(candidates) & set(results)):
        candidate = candidates[model_id]
        result = results[model_id]
        model_error_count = len(errors)
        _verify_result_candidate_binding(
            candidate,
            result,
            errors,
            artifact_created_at=artifact.created_at,
        )
        evidence = evidence_by_model.get(model_id)
        complete = result.disposition is not QualificationDisposition.INCONCLUSIVE
        threshold_passed = False
        if complete:
            if evidence is None:
                errors.append(f"trusted benchmark evidence is missing: {model_id}")
            else:
                _verify_trusted_benchmark_binding(
                    artifact=artifact,
                    candidate=candidate,
                    result=result,
                    evidence=evidence,
                    errors=errors,
                )
            threshold_passed = _tier_a_thresholds_pass(
                result=result,
                thresholds=thresholds,
                minimum_overall=policy.tier_a_minimum_overall_score,
            )
            if result.disposition is QualificationDisposition.TIER_A and not threshold_passed:
                errors.append(f"Tier A thresholds are not satisfied: {model_id}")
            if result.disposition is QualificationDisposition.NOT_QUALIFIED and threshold_passed:
                errors.append(
                    f"passing deterministic score was mislabeled not-qualified: {model_id}"
                )

        if result.disposition is QualificationDisposition.TIER_A:
            assert result.expires_at is not None
            if result.expires_at <= result.evaluated_at:
                errors.append(f"Tier A expiry is not after evaluation: {model_id}")
            if result.expires_at > result.evaluated_at + timedelta(
                days=policy.maximum_validity_days
            ):
                errors.append(f"Tier A validity exceeds policy: {model_id}")
            if result.expires_at <= now:
                errors.append(f"Tier A qualification is expired: {model_id}")
            review = candidate.lineage_review
            production_eligible = (
                len(errors) == model_error_count
                and threshold_passed
                and evidence is not None
                and review.status is LineageReviewStatus.APPROVED
                and candidate.root_lineage is not None
                and candidate.operational_status is CandidateOperationalStatus.AVAILABLE
                and candidate.structured_output_supported
                and candidate.zdr_eligible
                and candidate.data_collection_deny_eligible
                and bool(candidate.approved_roles)
                and result.expires_at > now
            )
            if production_eligible:
                eligible_ids.append(model_id)
                assert candidate.root_lineage is not None
                eligible_roots.append(candidate.root_lineage)

    errors = sorted(set(errors))
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "verified_at": now,
        "artifact_sha256": artifact.artifact_sha256,
        "candidate_registry_sha256": registry.registry_sha256,
        "policy_sha256": policy.policy_sha256,
        "eligible_tier_a_model_ids": sorted(eligible_ids),
        "eligible_root_lineages": sorted(set(eligible_roots)),
        "production_selection_ready": (
            not errors
            and len(set(eligible_ids)) >= _MIN_EXACT_MODELS
            and len(set(eligible_roots)) >= _MIN_ROOT_LINEAGES
        ),
        "valid": not errors,
        "errors": errors,
    }
    payload["verification_sha256"] = _canonical_json_sha256(payload)
    return QualificationVerification.model_validate(payload)


def _verify_result_candidate_binding(
    candidate: CandidateModel,
    result: ModelQualificationResult,
    errors: list[str],
    *,
    artifact_created_at: datetime,
) -> None:
    fields = (
        (
            "canonical model slug",
            result.canonical_model_slug,
            candidate.canonical_model_slug,
        ),
        ("root lineage", result.root_lineage, candidate.root_lineage),
        (
            "provider endpoint",
            result.approved_provider_endpoint,
            candidate.approved_provider_endpoint,
        ),
        (
            "provider name",
            result.approved_provider_name,
            candidate.approved_provider_name,
        ),
        (
            "endpoint snapshot",
            result.endpoint_snapshot_sha256,
            candidate.endpoint_snapshot_sha256,
        ),
        (
            "model metadata snapshot",
            result.model_metadata_snapshot_sha256,
            candidate.model_metadata_snapshot_sha256,
        ),
        (
            "pricing snapshot",
            result.pricing_snapshot_sha256,
            candidate.pricing_snapshot_sha256,
        ),
        ("approved roles", result.approved_roles, candidate.approved_roles),
    )
    for label, observed, expected in fields:
        if observed != expected:
            errors.append(
                f"qualification result {label} differs from candidate: {candidate.exact_model_id}"
            )
    expected_benchmark_state = CandidateBenchmarkStatus.INCONCLUSIVE
    if result.disposition is QualificationDisposition.TIER_A:
        assert result.expires_at is not None
        expected_benchmark_state = (
            CandidateBenchmarkStatus.PASSED
            if result.expires_at > artifact_created_at
            else CandidateBenchmarkStatus.EXPIRED
        )
    elif result.disposition is QualificationDisposition.NOT_QUALIFIED:
        expected_benchmark_state = CandidateBenchmarkStatus.FAILED
    if candidate.benchmark_status is not expected_benchmark_state:
        errors.append(
            f"candidate benchmark status differs from qualification result: "
            f"{candidate.exact_model_id}"
        )
    expected_report_hash = result.benchmark_report_sha256
    if candidate.benchmark_artifact_sha256 != expected_report_hash:
        errors.append(
            f"candidate benchmark report hash differs from qualification result: "
            f"{candidate.exact_model_id}"
        )
    if candidate.qualification_expires_at != result.expires_at:
        errors.append(
            f"candidate qualification expiry differs from qualification result: "
            f"{candidate.exact_model_id}"
        )


def _verify_trusted_benchmark_binding(
    *,
    artifact: ModelQualificationArtifact,
    candidate: CandidateModel,
    result: ModelQualificationResult,
    evidence: TrustedBenchmarkVerificationEvidence,
    errors: list[str],
) -> None:
    if (
        result.benchmark_verification_sha256 != evidence.verification_sha256
        or result.benchmark_report_sha256 != evidence.benchmark_report_sha256
        or result.dimensions != evidence.dimensions
        or evidence.benchmark_corpus_sha256 != artifact.bindings.benchmark_corpus_sha256
        or evidence.benchmark_ground_truth_sha256 != artifact.bindings.benchmark_ground_truth_sha256
        or evidence.prompt_sha256 != artifact.bindings.prompt_sha256
        or evidence.response_schema_sha256 != artifact.bindings.response_schema_sha256
    ):
        errors.append(
            f"qualification result is not bound to independently verified benchmark "
            f"evidence: {candidate.exact_model_id}"
        )
    for record in evidence.usage_records:
        if (
            not is_creditable_usage_record(
                record,
                require_real=True,
                require_certification=True,
            )
            or record.role != "model_benchmark"
            or record.requested_model != candidate.exact_model_id
            or record.returned_model != candidate.exact_model_id
            or record.actual_provider_endpoint != candidate.approved_provider_endpoint
            or record.routing.get("selected_provider_name") != candidate.approved_provider_name
            or record.routing.get("endpoint_snapshot_sha256") != candidate.endpoint_snapshot_sha256
            or record.routing.get("endpoint_pricing_sha256") != candidate.pricing_snapshot_sha256
        ):
            errors.append(
                f"benchmark request lacks exact certification-grade provider evidence: "
                f"{candidate.exact_model_id}"
            )
            break


def _tier_a_thresholds_pass(
    *,
    result: ModelQualificationResult,
    thresholds: dict[ModelBenchmarkDimension, QualificationDimensionThreshold],
    minimum_overall: float,
) -> bool:
    observed = {dimension.dimension: dimension for dimension in result.dimensions}
    return (
        set(observed) == set(ModelBenchmarkDimension)
        and result.overall_score >= minimum_overall
        and all(
            observed[dimension].evaluated >= threshold.minimum_cases
            and observed[dimension].score >= threshold.minimum_score
            for dimension, threshold in thresholds.items()
        )
    )


class SelectedProductionModel(StrictModel):
    exact_model_id: str = Field(pattern=_MODEL_PATTERN, max_length=300)
    canonical_model_slug: str = Field(pattern=_MODEL_PATTERN, max_length=300)
    root_lineage: str = Field(pattern=_LINEAGE_PATTERN)
    approved_provider_endpoint: str = Field(pattern=_ENDPOINT_PATTERN)
    approved_provider_name: str = Field(pattern=_PROVIDER_NAME_PATTERN)
    approved_roles: tuple[str, ...] = Field(min_length=1, max_length=128)
    qualification_result_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id", "canonical_model_slug")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        return _validate_exact_model_id(value)

    @field_validator("approved_roles")
    @classmethod
    def roles_are_safe_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(_ROLE_PATTERN, role) is None for role in value):
            raise ValueError("selected production roles are malformed")
        return _validate_sorted_unique(value, label="selected production roles")


class ProductionModelSelection(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    selection_policy: Literal["all_eligible_tier_a"] = "all_eligible_tier_a"
    qualification_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    qualification_verification_sha256: str = Field(pattern=_SHA256_PATTERN)
    selected_at: datetime
    expires_at: datetime
    models: tuple[SelectedProductionModel, ...] = Field(
        min_length=_MIN_EXACT_MODELS,
        max_length=128,
    )
    selection_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("selected_at", "expires_at")
    @classmethod
    def timestamps_are_utc(cls, value: datetime) -> datetime:
        return _validate_utc_second(value, label="production selection timestamp")

    @model_validator(mode="after")
    def ordering_window_and_hash_are_consistent(self) -> ProductionModelSelection:
        identifiers = tuple(model.exact_model_id for model in self.models)
        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("selected production models must be unique and sorted")
        if len({model.root_lineage for model in self.models}) < _MIN_ROOT_LINEAGES:
            raise ValueError("production selection requires at least six independent root lineages")
        if self.expires_at <= self.selected_at:
            raise ValueError("production selection expiry must follow selection")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"selection_sha256"}))
        if self.selection_sha256 != expected:
            raise ValueError("production model selection self-hash is inconsistent")
        return self


def seal_production_selection(
    *,
    artifact: ModelQualificationArtifact,
    verification: QualificationVerification,
    selected_at: datetime,
) -> ProductionModelSelection:
    if not verification.valid:
        raise ValueError("cannot select models from invalid qualification evidence")
    if (
        verification.artifact_sha256 != artifact.artifact_sha256
        or verification.candidate_registry_sha256 != artifact.bindings.candidate_registry_sha256
        or verification.policy_sha256 != artifact.bindings.qualification_policy_sha256
    ):
        raise ValueError("qualification verification does not bind the supplied artifact")
    if not verification.production_selection_ready:
        raise ValueError("qualification evidence is not ready for production selection")
    if (
        len(verification.eligible_tier_a_model_ids) < _MIN_EXACT_MODELS
        or len(verification.eligible_root_lineages) < _MIN_ROOT_LINEAGES
    ):
        raise ValueError(
            "production selection requires at least eight models and six root lineages"
        )
    results = {
        result.exact_model_id: result
        for result in artifact.results
        if result.exact_model_id in verification.eligible_tier_a_model_ids
    }
    if set(results) != set(verification.eligible_tier_a_model_ids) or not results:
        raise ValueError("eligible Tier A set cannot be resolved from qualification results")
    expiries = [result.expires_at for result in results.values()]
    if any(expiry is None for expiry in expiries):
        raise ValueError("eligible Tier A result lacks an expiry")
    models = [
        {
            "exact_model_id": model_id,
            "canonical_model_slug": results[model_id].canonical_model_slug,
            "root_lineage": results[model_id].root_lineage,
            "approved_provider_endpoint": results[model_id].approved_provider_endpoint,
            "approved_provider_name": results[model_id].approved_provider_name,
            "approved_roles": list(results[model_id].approved_roles),
            "qualification_result_sha256": results[model_id].result_sha256,
        }
        for model_id in sorted(results)
    ]
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "selection_policy": "all_eligible_tier_a",
        "qualification_artifact_sha256": artifact.artifact_sha256,
        "qualification_verification_sha256": verification.verification_sha256,
        "selected_at": selected_at,
        "expires_at": min(expiry for expiry in expiries if expiry is not None),
        "models": models,
    }
    payload["selection_sha256"] = _canonical_json_sha256(payload)
    return ProductionModelSelection.model_validate(payload)


class SelectionVerification(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    verified_at: datetime
    selection_sha256: str = Field(pattern=_SHA256_PATTERN)
    valid: bool
    errors: tuple[str, ...]
    verification_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("verified_at")
    @classmethod
    def verified_at_is_utc(cls, value: datetime) -> datetime:
        return _validate_utc_second(value, label="selection verification time")

    @model_validator(mode="after")
    def state_and_hash_are_consistent(self) -> SelectionVerification:
        _validate_sorted_unique(self.errors, label="selection verification errors")
        if self.valid != (not self.errors):
            raise ValueError("selection verification validity differs from errors")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"verification_sha256"}))
        if self.verification_sha256 != expected:
            raise ValueError("selection verification self-hash is inconsistent")
        return self


def verify_production_selection(
    *,
    selection: ProductionModelSelection,
    artifact: ModelQualificationArtifact,
    qualification_verification: QualificationVerification,
    now: datetime,
) -> SelectionVerification:
    """Verify exact all-eligible-Tier-A set equality and freshness."""

    now = _validate_utc_second(now, label="selection verification time")
    errors: list[str] = []
    if not qualification_verification.valid:
        errors.append("production selection uses invalid qualification verification")
    if qualification_verification.artifact_sha256 != artifact.artifact_sha256:
        errors.append("qualification verification binds a different qualification artifact")
    if (
        qualification_verification.candidate_registry_sha256
        != artifact.bindings.candidate_registry_sha256
    ):
        errors.append("qualification verification binds a different candidate registry")
    if qualification_verification.policy_sha256 != artifact.bindings.qualification_policy_sha256:
        errors.append("qualification verification binds a different qualification policy")
    if selection.qualification_artifact_sha256 != artifact.artifact_sha256:
        errors.append("production selection binds a different qualification artifact")
    if (
        selection.qualification_verification_sha256
        != qualification_verification.verification_sha256
    ):
        errors.append("production selection binds a different qualification verification")
    if selection.selected_at < artifact.created_at:
        errors.append("production selection predates qualification freeze")
    if selection.selected_at > now + _FUTURE_SKEW:
        errors.append("production selection is future-dated")
    if selection.expires_at <= now:
        errors.append("production selection is expired")

    expected_ids = set(qualification_verification.eligible_tier_a_model_ids)
    selected_ids = {model.exact_model_id for model in selection.models}
    if selected_ids != expected_ids:
        errors.append("production selection is not all_eligible_tier_a set equality")
    results = {result.exact_model_id: result for result in artifact.results}
    expected_expiries: list[datetime] = []
    for selected in selection.models:
        result = results.get(selected.exact_model_id)
        if (
            result is None
            or result.disposition is not QualificationDisposition.TIER_A
            or result.root_lineage != selected.root_lineage
            or result.canonical_model_slug != selected.canonical_model_slug
            or result.approved_provider_endpoint != selected.approved_provider_endpoint
            or result.approved_provider_name != selected.approved_provider_name
            or result.approved_roles != selected.approved_roles
            or result.result_sha256 != selected.qualification_result_sha256
            or result.expires_at is None
        ):
            errors.append(
                f"selected model does not match its Tier A result: {selected.exact_model_id}"
            )
        else:
            expected_expiries.append(result.expires_at)
    if expected_expiries and selection.expires_at != min(expected_expiries):
        errors.append("production selection expiry differs from earliest qualification expiry")

    errors = sorted(set(errors))
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "verified_at": now,
        "selection_sha256": selection.selection_sha256,
        "valid": not errors,
        "errors": errors,
    }
    payload["verification_sha256"] = _canonical_json_sha256(payload)
    return SelectionVerification.model_validate(payload)


class CriticalSurfaceReviewEvidence(StrictModel):
    surface_id: str = Field(pattern=_ID_PATTERN)
    review_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_ids: tuple[str, ...] = Field(min_length=1, max_length=128)

    @field_validator("request_ids")
    @classmethod
    def requests_are_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _validate_sorted_unique(value, label="critical-surface request IDs")


class CandidateFalsifierEvidence(StrictModel):
    candidate_id: str = Field(pattern=_ID_PATTERN)
    cross_examination_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_ids: tuple[str, ...] = Field(min_length=1, max_length=128)

    @field_validator("request_ids")
    @classmethod
    def requests_are_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _validate_sorted_unique(value, label="candidate falsifier request IDs")


class EnsembleRequirement(StrictModel):
    requirement: str = Field(pattern=r"^[a-z][a-z0-9_]{0,99}$")
    state: RequirementState
    observed: int = Field(ge=0)
    required: int = Field(ge=0)
    detail: str = Field(min_length=1, max_length=1_000)


class CertifiedEnsembleEvaluation(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    evaluated_at: datetime
    qualification_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    production_selection_sha256: str = Field(pattern=_SHA256_PATTERN)
    exact_model_ids: tuple[str, ...]
    root_lineages: tuple[str, ...]
    specialist_responsibilities: tuple[str, ...]
    whole_protocol_root_lineages: tuple[str, ...]
    critical_surface_lineages: dict[str, tuple[str, ...]]
    falsifier_candidate_lineages: dict[str, tuple[str, ...]]
    requirements: tuple[EnsembleRequirement, ...]
    passed: bool
    errors: tuple[str, ...]
    evaluation_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("evaluated_at")
    @classmethod
    def evaluated_at_is_utc(cls, value: datetime) -> datetime:
        return _validate_utc_second(value, label="ensemble evaluation time")

    @model_validator(mode="after")
    def ordering_state_and_hash_are_consistent(self) -> CertifiedEnsembleEvaluation:
        for values, label in (
            (self.exact_model_ids, "ensemble exact model IDs"),
            (self.root_lineages, "ensemble root lineages"),
            (self.specialist_responsibilities, "specialist responsibilities"),
            (self.whole_protocol_root_lineages, "whole-protocol root lineages"),
            (self.errors, "ensemble errors"),
        ):
            _validate_sorted_unique(values, label=label)
        names = tuple(requirement.requirement for requirement in self.requirements)
        if names != tuple(sorted(set(names))):
            raise ValueError("ensemble requirements must be unique and sorted")
        if self.passed != (
            not self.errors
            and all(
                requirement.state is not RequirementState.FAIL for requirement in self.requirements
            )
        ):
            raise ValueError("ensemble pass state differs from requirement evidence")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"evaluation_sha256"}))
        if self.evaluation_sha256 != expected:
            raise ValueError("certified ensemble evaluation self-hash is inconsistent")
        return self


def evaluate_certified_ensemble(
    *,
    artifact: ModelQualificationArtifact,
    qualification_verification: QualificationVerification,
    selection: ProductionModelSelection,
    selection_verification: SelectionVerification,
    usage_records: tuple[UsageRecord, ...],
    critical_surface_evidence: tuple[CriticalSurfaceReviewEvidence, ...],
    required_high_critical_candidate_ids: tuple[str, ...],
    falsifier_evidence: tuple[CandidateFalsifierEvidence, ...],
    now: datetime,
) -> CertifiedEnsembleEvaluation:
    """Measure the certified production ensemble only from completed real requests."""

    now = _validate_utc_second(now, label="ensemble evaluation time")
    errors: list[str] = []
    if not qualification_verification.valid:
        errors.append("qualification verification is invalid")
    if not selection_verification.valid:
        errors.append("production selection verification is invalid")
    if qualification_verification.artifact_sha256 != artifact.artifact_sha256:
        errors.append("qualification verification binds a different qualification artifact")
    if (
        qualification_verification.candidate_registry_sha256
        != artifact.bindings.candidate_registry_sha256
    ):
        errors.append("qualification verification binds a different candidate registry")
    if qualification_verification.policy_sha256 != artifact.bindings.qualification_policy_sha256:
        errors.append("qualification verification binds a different qualification policy")
    if selection.qualification_artifact_sha256 != artifact.artifact_sha256:
        errors.append("production selection binds a different qualification artifact")
    if (
        selection.qualification_verification_sha256
        != qualification_verification.verification_sha256
    ):
        errors.append("production selection binds a different qualification verification")
    if selection_verification.selection_sha256 != selection.selection_sha256:
        errors.append("selection verification binds a different production selection")
    if selection.expires_at <= now:
        errors.append("production selection expired before ensemble evaluation")

    selected = {model.exact_model_id: model for model in selection.models}
    records_by_id: dict[str, UsageRecord] = {}
    duplicated_request_ids: set[str] = set()
    for record in usage_records:
        if record.request_id in records_by_id:
            duplicated_request_ids.add(record.request_id)
        records_by_id[record.request_id] = record
    if duplicated_request_ids:
        errors.append("duplicate production request IDs are ambiguous")

    qualifying: dict[str, UsageRecord] = {}
    for request_id, record in records_by_id.items():
        selected_model = selected.get(record.requested_model)
        if (
            request_id not in duplicated_request_ids
            and selected_model is not None
            and record.role != "model_benchmark"
            and is_creditable_usage_record(
                record,
                require_real=True,
                require_certification=True,
            )
            and record.returned_model == selected_model.exact_model_id
            and record.actual_provider_endpoint == selected_model.approved_provider_endpoint
            and record.routing.get("selected_provider_name")
            == selected_model.approved_provider_name
            and _usage_role_is_approved(record.role, selected_model.approved_roles)
            and record.routing.get("qualification_artifact_sha256") == artifact.artifact_sha256
            and record.routing.get("production_selection_sha256") == selection.selection_sha256
        ):
            qualifying[request_id] = record

    exact_ids = sorted({record.requested_model for record in qualifying.values()})
    roots = sorted({selected[model_id].root_lineage for model_id in exact_ids})
    specialists = sorted(
        {
            role
            for record in qualifying.values()
            if (role := canonical_specialist_role(record.role)) is not None
        }
    )
    whole_protocol_roots = sorted(
        {
            selected[record.requested_model].root_lineage
            for record in qualifying.values()
            if record.role == "whole_protocol_review"
            or record.role.startswith("whole_protocol_review:")
        }
    )

    critical_lineages: dict[str, tuple[str, ...]] = {}
    surface_ids = [evidence.surface_id for evidence in critical_surface_evidence]
    if surface_ids != sorted(set(surface_ids)):
        errors.append("critical-surface evidence is duplicate or unsorted")
    for surface_evidence in critical_surface_evidence:
        lineages = sorted(
            {
                selected[qualifying[request_id].requested_model].root_lineage
                for request_id in surface_evidence.request_ids
                if request_id in qualifying
            }
        )
        critical_lineages[surface_evidence.surface_id] = tuple(lineages)

    required_candidates = _validate_sorted_unique(
        required_high_critical_candidate_ids,
        label="required high/critical candidate IDs",
    )
    falsifier_by_candidate = {evidence.candidate_id: evidence for evidence in falsifier_evidence}
    if len(falsifier_by_candidate) != len(falsifier_evidence) or tuple(
        falsifier_by_candidate
    ) != tuple(sorted(falsifier_by_candidate)):
        errors.append("candidate falsifier evidence is duplicate or unsorted")
    if set(falsifier_by_candidate) != set(required_candidates):
        errors.append("candidate falsifier evidence does not match the required candidate set")
    falsifier_lineages: dict[str, tuple[str, ...]] = {}
    for candidate_id in required_candidates:
        candidate_evidence = falsifier_by_candidate.get(candidate_id)
        lineages = sorted(
            {
                selected[qualifying[request_id].requested_model].root_lineage
                for request_id in (
                    candidate_evidence.request_ids if candidate_evidence is not None else ()
                )
                if request_id in qualifying and _is_falsifier_role(qualifying[request_id].role)
            }
        )
        falsifier_lineages[candidate_id] = tuple(lineages)

    requirements = [
        _ensemble_requirement(
            "exact_qualified_models",
            observed=len(exact_ids),
            required=_MIN_EXACT_MODELS,
        ),
        _ensemble_requirement(
            "independent_root_lineages",
            observed=len(roots),
            required=_MIN_ROOT_LINEAGES,
        ),
        _ensemble_requirement(
            "specialist_responsibilities",
            observed=len(specialists),
            required=_MIN_SPECIALIST_RESPONSIBILITIES,
        ),
        _ensemble_requirement(
            "whole_protocol_reviews",
            observed=len(whole_protocol_roots),
            required=_MIN_WHOLE_PROTOCOL_LINEAGES,
        ),
        _ensemble_requirement(
            "critical_surface_lineages",
            observed=min(
                (len(lineages) for lineages in critical_lineages.values()),
                default=0,
            ),
            required=_MIN_CRITICAL_SURFACE_LINEAGES,
        ),
        _ensemble_requirement(
            "all_selected_models_executed",
            observed=len(set(exact_ids) & set(selected)),
            required=len(selected),
        ),
    ]
    if required_candidates:
        requirements.append(
            _ensemble_requirement(
                "candidate_falsifier_lineages",
                observed=min(
                    (len(lineages) for lineages in falsifier_lineages.values()),
                    default=0,
                ),
                required=_MIN_FALSIFIER_LINEAGES,
            )
        )
    else:
        requirements.append(
            EnsembleRequirement(
                requirement="candidate_falsifier_lineages",
                state=RequirementState.NOT_APPLICABLE,
                observed=0,
                required=0,
                detail="no high/critical candidate required falsification",
            )
        )
    requirements.sort(key=lambda item: item.requirement)
    errors = sorted(set(errors))
    passed = not errors and all(
        requirement.state is not RequirementState.FAIL for requirement in requirements
    )
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "evaluated_at": now,
        "qualification_artifact_sha256": artifact.artifact_sha256,
        "production_selection_sha256": selection.selection_sha256,
        "exact_model_ids": exact_ids,
        "root_lineages": roots,
        "specialist_responsibilities": specialists,
        "whole_protocol_root_lineages": whole_protocol_roots,
        "critical_surface_lineages": {
            key: list(critical_lineages[key]) for key in sorted(critical_lineages)
        },
        "falsifier_candidate_lineages": {
            key: list(falsifier_lineages[key]) for key in sorted(falsifier_lineages)
        },
        "requirements": [requirement.model_dump(mode="json") for requirement in requirements],
        "passed": passed,
        "errors": errors,
    }
    payload["evaluation_sha256"] = _canonical_json_sha256(payload)
    return CertifiedEnsembleEvaluation.model_validate(payload)


def _ensemble_requirement(
    requirement: str,
    *,
    observed: int,
    required: int,
) -> EnsembleRequirement:
    return EnsembleRequirement(
        requirement=requirement,
        state=RequirementState.PASS if observed >= required else RequirementState.FAIL,
        observed=observed,
        required=required,
        detail=f"{observed} observed; {required} required",
    )


def _is_falsifier_role(role: str) -> bool:
    return (
        role == "falsifier"
        or role.startswith("candidate_falsifier:")
        or role.startswith("specialist:falsifier:")
    )


def _usage_role_is_approved(role: str, approved_roles: tuple[str, ...]) -> bool:
    specialist = canonical_specialist_role(role)
    if specialist is not None:
        return specialist in approved_roles
    if role == "whole_protocol_review" or role.startswith("whole_protocol_review:"):
        return "whole_protocol_review" in approved_roles
    return role in approved_roles


def load_candidate_registry(path: Path) -> CandidateRegistry:
    return _load_model(path, CandidateRegistry)


def load_qualification_policy(path: Path) -> QualificationPolicy:
    return _load_model(path, QualificationPolicy)


def load_model_qualification_artifact(path: Path) -> ModelQualificationArtifact:
    return _load_model(path, ModelQualificationArtifact)


def load_production_selection(path: Path) -> ProductionModelSelection:
    return _load_model(path, ProductionModelSelection)


def _load_model[T: StrictModel](path: Path, model_type: type[T]) -> T:
    if path.is_symlink() or path.is_junction():
        raise ValueError("qualification input cannot be a link")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise ValueError("qualification input is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > _MAX_INPUT_BYTES
    ):
        raise ValueError("qualification input must be a bounded unshared regular file")
    try:
        if path.suffix.casefold() == ".toml":
            with path.open("rb") as handle:
                payload = tomllib.load(handle)
        else:
            payload = json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=_unique_json_object,
            )
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("qualification input could not be parsed") from exc
    if not isinstance(payload, dict):
        raise ValueError("qualification input must contain one object")
    return model_type.model_validate(payload)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result
