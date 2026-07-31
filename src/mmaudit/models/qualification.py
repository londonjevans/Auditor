"""Fail-closed model qualification, production selection, and ensemble evidence.

Qualification is deliberately separate from model discovery and benchmark execution.
All production eligibility decisions are recomputed from immutable local evidence;
neither a model-authored tier nor a self-declared benchmark report is trusted.
"""

from __future__ import annotations

import json
import re
import stat
import threading
import tomllib
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Never, Self, SupportsIndex

from pydantic import ConfigDict, Field, TypeAdapter, field_validator, model_validator

from mmaudit.benchmark.models import (
    ModelBenchmarkDimension,
    ModelBenchmarkReport,
    ModelBenchmarkSuite,
    verify_model_benchmark_report_structure,
)
from mmaudit.constants import ALL_SPECIALIST_ROLES
from mmaudit.models.discovery import (
    DataCollectionDenyEvidenceSource,
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
)
from mmaudit.models.generation_evidence import (
    OpenRouterGenerationEvidence,
    TrustedGenerationVerification,
    _reconcile_generation_evidence_structural,
)
from mmaudit.models.identifiers import (
    EXACT_MODEL_ID_PATTERN,
    require_exact_openrouter_model_id,
)
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.reasoning import (
    CANONICAL_REASONING_POLICY_ROLES,
    ReasoningControlProfile,
    ReasoningExecutionEvidence,
    ReasoningPolicyArtifact,
    ReasoningPolicyError,
    reasoning_policy_roles_for_qualified_role,
    resolve_reasoning_request_role,
)
from mmaudit.models.release_attestation import TrustedReleaseBindingObservation
from mmaudit.models.schemas import ExecutionEvidenceKind, StrictModel, UsageRecord
from mmaudit.models.usage import (
    _is_structurally_creditable_usage_record,
    is_creditable_usage_record,
    source_backed_whole_protocol_context,
)
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
MIN_CALIBRATION_INCLUDED_CANDIDATES = 3
MIN_CALIBRATION_INCLUDED_ROOT_LINEAGES = 3
MIN_CALIBRATED_JUDGMENT_CASES = 4
DETERMINISTIC_QUALIFICATION_DIMENSIONS = frozenset(
    {
        ModelBenchmarkDimension.EXACT_SOURCE_LOCATION,
        ModelBenchmarkDimension.PROMPT_INJECTION_RESISTANCE,
        ModelBenchmarkDimension.STRUCTURED_OUTPUT_COMPLIANCE,
    }
)

_JSON_ADAPTER = TypeAdapter(Any)


def _canonical_specialist_role(request_role: str) -> str | None:
    """Resolve credited specialist responsibility without importing agent runtime code."""

    parts = request_role.split(":")
    if len(parts) not in {2, 3} or parts[0] != "specialist":
        return None
    role = parts[1]
    if role not in ALL_SPECIALIST_ROLES:
        return None
    dedicated_test_roles = {"test_generation", "exploit_reproduction_planner"}
    if len(parts) == 2:
        return None if role in dedicated_test_roles else role
    if parts[2] == "exploit_test" and role in dedicated_test_roles:
        return role
    return None


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


class QualificationThresholdBasis(StrEnum):
    """Why a frozen qualification threshold has its selected value."""

    DETERMINISTIC_REQUIREMENT = "deterministic_requirement"
    CALIBRATED_DISTRIBUTION = "calibrated_distribution"


class QualificationRoleClass(StrEnum):
    """Security-sensitive role classes with independently measured quality gates."""

    INVESTIGATOR = "investigator"
    VERIFIER = "verifier"
    FALSIFIER = "falsifier"
    JUDGE = "judge"


_REQUIRED_ROLE_QUALIFICATION_DIMENSIONS = {
    QualificationRoleClass.INVESTIGATOR: frozenset(
        {
            ModelBenchmarkDimension.EXACT_SOURCE_LOCATION,
            ModelBenchmarkDimension.FALSE_POSITIVE_REJECTION,
            ModelBenchmarkDimension.SOLIDITY_SECURITY_REASONING,
        }
    ),
    QualificationRoleClass.VERIFIER: frozenset({ModelBenchmarkDimension.VERIFIER_QUALITY}),
    QualificationRoleClass.FALSIFIER: frozenset({ModelBenchmarkDimension.FALSIFIER_QUALITY}),
    QualificationRoleClass.JUDGE: frozenset(
        {
            ModelBenchmarkDimension.FALSIFIER_QUALITY,
            ModelBenchmarkDimension.REPORT_QUALITY,
            ModelBenchmarkDimension.VERIFIER_QUALITY,
        }
    ),
}


class RoleQualificationDisposition(StrEnum):
    """One role-class conclusion subordinate to the global Tier A baseline."""

    QUALIFIED = "qualified"
    NOT_QUALIFIED = "not_qualified"
    INCONCLUSIVE = "inconclusive"


class RoleQualificationFailure(StrEnum):
    """Bounded reasons why a role-specific gate did not authorize a model."""

    GLOBAL_BASELINE_NOT_TIER_A = "global_baseline_not_tier_a"
    GLOBAL_BASELINE_INCONCLUSIVE = "global_baseline_inconclusive"
    MINIMUM_CASES = "minimum_cases"
    MINIMUM_DIMENSION_SCORE = "minimum_dimension_score"
    MINIMUM_OVERALL_SCORE = "minimum_overall_score"


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


class QualifiedReasoningRoleBinding(StrictModel):
    """Immutable exact-profile qualification evidence without selection authority.

    A whole effective-configuration hash is intentionally insufficient here. The
    binding joins one exact model/provider/qualified-role/policy-role tuple to the
    exact reasoning profile and endpoint capability that the benchmark qualified.
    ``selection_authority`` is permanently false: callers must still match every
    field through :meth:`require_exact` and consume the separate production
    qualification capability.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    schema_version: Literal["1.0"] = "1.0"
    binding_status: Literal["exact_evidence_bound"] = "exact_evidence_bound"
    selection_authority: Literal[False] = False
    exact_model_id: str = Field(pattern=_MODEL_PATTERN, max_length=300)
    approved_provider_endpoint: str = Field(pattern=_ENDPOINT_PATTERN)
    approved_provider_name: str = Field(pattern=_PROVIDER_NAME_PATTERN)
    qualified_role: str = Field(pattern=_ROLE_PATTERN)
    configured_policy_role: str = Field(pattern=_ROLE_PATTERN)
    control_profile: ReasoningControlProfile
    control_profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    reasoning_policy_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    reasoning_policy_role_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    endpoint_reasoning_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    qualification_report_sha256: str = Field(pattern=_SHA256_PATTERN)
    qualification_result_sha256: str = Field(pattern=_SHA256_PATTERN)
    qualification_verification_sha256: str = Field(pattern=_SHA256_PATTERN)
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        return _validate_exact_model_id(value)

    @model_validator(mode="after")
    def exact_profile_and_hash_are_consistent(self) -> Self:
        if self.configured_policy_role not in CANONICAL_REASONING_POLICY_ROLES:
            raise ValueError("reasoning qualification names an unknown configured policy role")
        validated_profile = ReasoningControlProfile.model_validate(
            self.control_profile.model_dump(mode="json")
        )
        if (
            type(self.control_profile) is not ReasoningControlProfile
            or validated_profile.profile_sha256 != self.control_profile_sha256
        ):
            raise ValueError("reasoning qualification profile binding is inconsistent")
        expected = _canonical_json_sha256(self.model_dump(mode="json", exclude={"binding_sha256"}))
        if self.binding_sha256 != expected:
            raise ValueError("reasoning role qualification self-hash is inconsistent")
        return self

    def require_exact(
        self,
        *,
        exact_model_id: str,
        approved_provider_endpoint: str,
        approved_provider_name: str,
        qualified_role: str,
        configured_policy_role: str,
        control_profile: ReasoningControlProfile,
        reasoning_policy_artifact_sha256: str,
        reasoning_policy_role_binding_sha256: str,
        endpoint_reasoning_capability_sha256: str,
        qualification_report_sha256: str,
        qualification_result_sha256: str,
        qualification_verification_sha256: str,
    ) -> Self:
        """Return this evidence only when every authorization-sensitive field matches."""

        validated = QualifiedReasoningRoleBinding.model_validate(self.model_dump(mode="json"))
        expected = {
            "exact_model_id": _validate_exact_model_id(exact_model_id),
            "approved_provider_endpoint": approved_provider_endpoint,
            "approved_provider_name": approved_provider_name,
            "qualified_role": qualified_role,
            "configured_policy_role": configured_policy_role,
            "control_profile_sha256": control_profile.profile_sha256,
            "reasoning_policy_artifact_sha256": reasoning_policy_artifact_sha256,
            "reasoning_policy_role_binding_sha256": reasoning_policy_role_binding_sha256,
            "endpoint_reasoning_capability_sha256": endpoint_reasoning_capability_sha256,
            "qualification_report_sha256": qualification_report_sha256,
            "qualification_result_sha256": qualification_result_sha256,
            "qualification_verification_sha256": qualification_verification_sha256,
        }
        observed = {
            "exact_model_id": validated.exact_model_id,
            "approved_provider_endpoint": validated.approved_provider_endpoint,
            "approved_provider_name": validated.approved_provider_name,
            "qualified_role": validated.qualified_role,
            "configured_policy_role": validated.configured_policy_role,
            "control_profile_sha256": validated.control_profile_sha256,
            "reasoning_policy_artifact_sha256": (validated.reasoning_policy_artifact_sha256),
            "reasoning_policy_role_binding_sha256": (
                validated.reasoning_policy_role_binding_sha256
            ),
            "endpoint_reasoning_capability_sha256": (
                validated.endpoint_reasoning_capability_sha256
            ),
            "qualification_report_sha256": validated.qualification_report_sha256,
            "qualification_result_sha256": validated.qualification_result_sha256,
            "qualification_verification_sha256": (validated.qualification_verification_sha256),
        }
        mismatches = tuple(key for key in expected if observed[key] != expected[key])
        if mismatches:
            raise ValueError("reasoning qualification exact match failed: " + ", ".join(mismatches))
        if validated.control_profile != ReasoningControlProfile.model_validate(
            control_profile.model_dump(mode="json")
        ):
            raise ValueError("reasoning qualification exact control profile differs")
        return self


def seal_qualified_reasoning_role_binding(
    *,
    exact_model_id: str,
    approved_provider_endpoint: str,
    approved_provider_name: str,
    qualified_role: str,
    configured_policy_role: str,
    control_profile: ReasoningControlProfile,
    reasoning_policy_artifact_sha256: str,
    reasoning_policy_role_binding_sha256: str,
    endpoint_reasoning_capability_sha256: str,
    qualification_report_sha256: str,
    qualification_result_sha256: str,
    qualification_verification_sha256: str,
) -> QualifiedReasoningRoleBinding:
    """Seal one exact, provider-free reasoning qualification join."""

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "binding_status": "exact_evidence_bound",
        "selection_authority": False,
        "exact_model_id": exact_model_id,
        "approved_provider_endpoint": approved_provider_endpoint,
        "approved_provider_name": approved_provider_name,
        "qualified_role": qualified_role,
        "configured_policy_role": configured_policy_role,
        "control_profile": control_profile.model_dump(mode="json"),
        "control_profile_sha256": control_profile.profile_sha256,
        "reasoning_policy_artifact_sha256": reasoning_policy_artifact_sha256,
        "reasoning_policy_role_binding_sha256": reasoning_policy_role_binding_sha256,
        "endpoint_reasoning_capability_sha256": endpoint_reasoning_capability_sha256,
        "qualification_report_sha256": qualification_report_sha256,
        "qualification_result_sha256": qualification_result_sha256,
        "qualification_verification_sha256": qualification_verification_sha256,
    }
    payload["binding_sha256"] = _canonical_json_sha256(payload)
    return QualifiedReasoningRoleBinding.model_validate(payload)


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
    output_capability_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    model_metadata_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    pricing_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    context_size: int = Field(ge=1)
    max_prompt_tokens: int | None = Field(
        default=None,
        ge=1,
        exclude_if=lambda value: value is None,
    )
    max_prompt_tokens_source: Literal["metadata", "context_limit"] | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    output_limit: int = Field(ge=1)
    output_limit_source: Literal["metadata", "context_limit"] | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    structured_output_supported: bool
    structured_output_mode: StructuredOutputMode | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    reasoning_supported: bool
    zdr_eligible: bool
    data_collection_deny_eligible: bool
    data_collection_deny_request_policy_enforced: bool | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    data_collection_deny_evidence_source: DataCollectionDenyEvidenceSource | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    data_collection_deny_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    data_collection_deny_evidence_expires_at: datetime | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
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

    @field_validator("data_collection_deny_evidence_expires_at")
    @classmethod
    def privacy_evidence_expiry_is_utc(cls, value: datetime | None) -> datetime | None:
        return (
            None
            if value is None
            else _validate_utc_second(value, label="candidate privacy evidence expiry")
        )

    @model_validator(mode="after")
    def lineage_and_benchmark_state_are_consistent(self) -> CandidateModel:
        privacy_values = (
            self.data_collection_deny_request_policy_enforced,
            self.data_collection_deny_evidence_source,
            self.data_collection_deny_evidence_sha256,
            self.data_collection_deny_evidence_expires_at,
        )
        if any(value is not None for value in privacy_values):
            if (
                self.data_collection_deny_request_policy_enforced is None
                or self.data_collection_deny_evidence_source is None
            ):
                raise ValueError("candidate data-collection evidence is incomplete")
            if (
                self.data_collection_deny_evidence_source
                is DataCollectionDenyEvidenceSource.ZDR_ENDPOINT_SNAPSHOT
            ):
                if (
                    self.data_collection_deny_eligible is not True
                    or self.data_collection_deny_request_policy_enforced is not True
                    or self.data_collection_deny_evidence_sha256 is None
                    or self.data_collection_deny_evidence_expires_at is not None
                ):
                    raise ValueError("candidate ZDR evidence is inconsistent")
            elif (
                self.data_collection_deny_evidence_source
                is DataCollectionDenyEvidenceSource.CONSENT_BOUND_ROUTER_REQUEST_POLICY
            ):
                if (
                    self.data_collection_deny_eligible is not False
                    or self.data_collection_deny_request_policy_enforced is not True
                    or self.data_collection_deny_evidence_sha256 is None
                    or self.data_collection_deny_evidence_expires_at is None
                ):
                    raise ValueError(
                        "candidate consent-bound request-policy evidence is incomplete"
                    )
            elif (
                self.data_collection_deny_eligible is not False
                or self.data_collection_deny_request_policy_enforced is not False
                or self.data_collection_deny_evidence_sha256 is not None
                or self.data_collection_deny_evidence_expires_at is not None
            ):
                raise ValueError("unverified candidate privacy evidence cannot receive credit")
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
        output_capability_values = (
            self.output_capability_sha256,
            self.structured_output_mode,
            self.max_prompt_tokens,
            self.max_prompt_tokens_source,
            self.output_limit_source,
        )
        if any(value is None for value in output_capability_values) and any(
            value is not None for value in output_capability_values
        ):
            raise ValueError(
                "candidate output mode, prompt limit, and capability evidence must be present "
                "together"
            )
        if self.max_prompt_tokens is not None:
            if self.max_prompt_tokens > self.context_size:
                raise ValueError("candidate prompt limit exceeds its context")
            if (
                self.max_prompt_tokens_source == "context_limit"
                and self.max_prompt_tokens != self.context_size
            ):
                raise ValueError("candidate derived prompt limit differs from its context")
        if self.output_limit > self.context_size:
            raise ValueError("candidate output limit exceeds its context")
        if self.output_limit_source == "context_limit" and self.output_limit != self.context_size:
            raise ValueError("candidate derived output limit differs from its context")
        if self.structured_output_mode is not None and self.structured_output_supported is not (
            self.structured_output_mode is not StructuredOutputMode.VALIDATED_TEXT_JSON
        ):
            raise ValueError("candidate structured-output boolean differs from its exact mode")
        if self.benchmark_status is not CandidateBenchmarkStatus.PENDING and (
            self.output_capability_sha256 is None
            or self.structured_output_mode is None
            or self.max_prompt_tokens is None
            or self.max_prompt_tokens_source is None
            or self.output_limit_source is None
        ):
            raise ValueError("completed benchmark status requires exact output capability evidence")
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
        endpoint = item.endpoint_snapshot.endpoint(item.approved_provider_endpoint)
        expected = (
            item.canonical_slug,
            item.discovery_evidence_sha256,
            item.approved_provider_endpoint,
            item.provider_name,
            item.endpoint_snapshot_sha256,
            item.output_capability_sha256,
            item.model_metadata_snapshot_sha256,
            item.pricing_snapshot_sha256,
            item.context_size,
            endpoint.max_prompt_tokens,
            endpoint.max_prompt_tokens_source,
            item.output_limit,
            endpoint.max_completion_tokens_source,
            item.structured_output_supported,
            item.structured_output_mode,
            item.reasoning_supported,
            item.zdr_eligible,
            item.data_collection_deny_eligible,
            item.data_collection_deny_request_policy_enforced,
            item.data_collection_deny_evidence_source,
            item.data_collection_deny_evidence_sha256,
            item.data_collection_deny_evidence_expires_at,
        )
        observed = (
            candidate.canonical_model_slug,
            candidate.discovery_evidence_sha256,
            candidate.approved_provider_endpoint,
            candidate.approved_provider_name,
            candidate.endpoint_snapshot_sha256,
            candidate.output_capability_sha256,
            candidate.model_metadata_snapshot_sha256,
            candidate.pricing_snapshot_sha256,
            candidate.context_size,
            candidate.max_prompt_tokens,
            candidate.max_prompt_tokens_source,
            candidate.output_limit,
            candidate.output_limit_source,
            candidate.structured_output_supported,
            candidate.structured_output_mode,
            candidate.reasoning_supported,
            candidate.zdr_eligible,
            candidate.data_collection_deny_eligible,
            candidate.data_collection_deny_request_policy_enforced,
            candidate.data_collection_deny_evidence_source,
            candidate.data_collection_deny_evidence_sha256,
            candidate.data_collection_deny_evidence_expires_at,
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
    basis: QualificationThresholdBasis | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    rationale: str | None = Field(
        default=None,
        min_length=20,
        max_length=2_000,
        exclude_if=lambda value: value is None,
    )
    calibration_distribution_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )

    @model_validator(mode="after")
    def calibration_metadata_is_all_or_nothing(self) -> QualificationDimensionThreshold:
        supplied = (
            self.basis is not None,
            self.rationale is not None,
            self.calibration_distribution_sha256 is not None,
        )
        if any(supplied) and not all(supplied):
            raise ValueError("qualification threshold calibration metadata must be complete")
        return self


def _validate_calibrated_threshold(threshold: QualificationDimensionThreshold) -> None:
    if threshold.basis is None:
        raise ValueError("calibrated qualification threshold requires measurement metadata")
    if threshold.dimension in DETERMINISTIC_QUALIFICATION_DIMENSIONS:
        if (
            threshold.basis is not QualificationThresholdBasis.DETERMINISTIC_REQUIREMENT
            or threshold.minimum_score != 1
        ):
            raise ValueError("deterministic qualification dimensions require an exact 1.0 gate")
        return
    if (
        threshold.basis is not QualificationThresholdBasis.CALIBRATED_DISTRIBUTION
        or threshold.minimum_cases < MIN_CALIBRATED_JUDGMENT_CASES
        or not 0 < threshold.minimum_score < 1
    ):
        raise ValueError(
            "judgment qualification dimensions require measured non-absolute thresholds"
        )


class RoleQualificationPolicy(StrictModel):
    """A non-vacuous secondary quality gate for one security-sensitive role class."""

    role_class: QualificationRoleClass
    thresholds: tuple[QualificationDimensionThreshold, ...] = Field(
        min_length=1,
        max_length=len(ModelBenchmarkDimension),
    )
    minimum_overall_score: float = Field(ge=0, le=1)
    minimum_overall_rationale: str = Field(min_length=20, max_length=2_000)

    @model_validator(mode="after")
    def dimensions_are_unique_and_sorted(self) -> RoleQualificationPolicy:
        dimensions = tuple(threshold.dimension.value for threshold in self.thresholds)
        if dimensions != tuple(sorted(set(dimensions))):
            raise ValueError("role qualification thresholds must be unique and sorted")
        if any(threshold.basis is None for threshold in self.thresholds):
            raise ValueError("role qualification thresholds require calibration metadata")
        required = _REQUIRED_ROLE_QUALIFICATION_DIMENSIONS[self.role_class]
        if not required.issubset({threshold.dimension for threshold in self.thresholds}):
            raise ValueError("role qualification policy omits mandatory semantic dimensions")
        return self


class QualificationPolicy(StrictModel):
    """Self-hashed, non-vacuous Tier A policy."""

    schema_version: Literal["1.0", "2.0"] = "1.0"
    created_at: datetime
    thresholds: tuple[QualificationDimensionThreshold, ...] = Field(
        min_length=len(ModelBenchmarkDimension),
        max_length=len(ModelBenchmarkDimension),
    )
    role_policies: tuple[RoleQualificationPolicy, ...] = Field(
        default=(),
        max_length=len(QualificationRoleClass),
        exclude_if=lambda value: not value,
    )
    calibration_artifact_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    calibration_included_candidate_count: int | None = Field(
        default=None,
        ge=MIN_CALIBRATION_INCLUDED_CANDIDATES,
        le=128,
        exclude_if=lambda value: value is None,
    )
    calibration_included_root_lineage_count: int | None = Field(
        default=None,
        ge=MIN_CALIBRATION_INCLUDED_ROOT_LINEAGES,
        le=128,
        exclude_if=lambda value: value is None,
    )
    tier_a_minimum_overall_score: float = Field(ge=0, le=1)
    tier_a_overall_rationale: str | None = Field(
        default=None,
        min_length=20,
        max_length=2_000,
        exclude_if=lambda value: value is None,
    )
    maximum_validity_days: int = Field(ge=1, le=90)
    maximum_benchmark_evidence_age_days: int = Field(ge=1, le=30)
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
        role_classes = tuple(item.role_class.value for item in self.role_policies)
        expected_role_classes = tuple(sorted(item.value for item in QualificationRoleClass))
        calibration_fields = (
            self.calibration_artifact_sha256,
            self.calibration_included_candidate_count,
            self.calibration_included_root_lineage_count,
            self.tier_a_overall_rationale,
        )
        if self.schema_version == "1.0":
            if role_classes or any(value is not None for value in calibration_fields):
                raise ValueError("qualification policy v1 cannot contain calibrated policy fields")
            if any(threshold.basis is not None for threshold in self.thresholds):
                raise ValueError("qualification policy v1 cannot contain calibrated thresholds")
        else:
            if role_classes != expected_role_classes:
                raise ValueError("qualification policy v2 must cover every role class exactly once")
            if any(value is None for value in calibration_fields):
                raise ValueError("qualification policy v2 requires complete calibration evidence")
            if not 0 < self.tier_a_minimum_overall_score < 1:
                raise ValueError(
                    "calibrated Tier A aggregate threshold must be between zero and one"
                )
            global_thresholds = {item.dimension: item for item in self.thresholds}
            for threshold in self.thresholds:
                _validate_calibrated_threshold(threshold)
            for role_policy in self.role_policies:
                if not 0 < role_policy.minimum_overall_score < 1:
                    raise ValueError(
                        "calibrated role aggregate threshold must be between zero and one"
                    )
                if role_policy.minimum_overall_score < self.tier_a_minimum_overall_score:
                    raise ValueError("role aggregate threshold cannot weaken the Tier A baseline")
                for threshold in role_policy.thresholds:
                    _validate_calibrated_threshold(threshold)
                    global_threshold = global_thresholds[threshold.dimension]
                    if (
                        threshold.minimum_cases != global_threshold.minimum_cases
                        or threshold.calibration_distribution_sha256
                        != global_threshold.calibration_distribution_sha256
                        or threshold.minimum_score < global_threshold.minimum_score
                    ):
                        raise ValueError(
                            "role qualification threshold cannot weaken or rebind calibration"
                        )
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
    maximum_benchmark_evidence_age_days: int = 7,
    role_policies: tuple[RoleQualificationPolicy, ...] = (),
    calibration_artifact_sha256: str | None = None,
    calibration_included_candidate_count: int | None = None,
    calibration_included_root_lineage_count: int | None = None,
    tier_a_overall_rationale: str | None = None,
) -> QualificationPolicy:
    calibrated = bool(role_policies) or any(
        value is not None
        for value in (
            calibration_artifact_sha256,
            calibration_included_candidate_count,
            calibration_included_root_lineage_count,
            tier_a_overall_rationale,
        )
    )
    payload: dict[str, Any] = {
        "schema_version": "2.0" if calibrated else "1.0",
        "created_at": created_at,
        "thresholds": [
            threshold.model_dump(mode="json")
            for threshold in sorted(thresholds, key=lambda item: item.dimension.value)
        ],
        "tier_a_minimum_overall_score": float(tier_a_minimum_overall_score),
        "maximum_validity_days": maximum_validity_days,
        "maximum_benchmark_evidence_age_days": maximum_benchmark_evidence_age_days,
        "require_real_execution": True,
        "require_certification_routing": True,
    }
    if role_policies:
        payload["role_policies"] = [
            role_policy.model_dump(mode="json")
            for role_policy in sorted(role_policies, key=lambda item: item.role_class.value)
        ]
    if calibration_artifact_sha256 is not None:
        payload["calibration_artifact_sha256"] = calibration_artifact_sha256
    if calibration_included_candidate_count is not None:
        payload["calibration_included_candidate_count"] = calibration_included_candidate_count
    if calibration_included_root_lineage_count is not None:
        payload["calibration_included_root_lineage_count"] = calibration_included_root_lineage_count
    if tier_a_overall_rationale is not None:
        payload["tier_a_overall_rationale"] = tier_a_overall_rationale
    payload["policy_sha256"] = _canonical_json_sha256(payload)
    return QualificationPolicy.model_validate(payload)


class TrustedCalibratedQualificationPolicy:
    """Opaque authority proving a v2 policy was joined to live calibration evidence."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls,
        *_args: object,
        **_kwargs: object,
    ) -> TrustedCalibratedQualificationPolicy:
        del cls
        raise TypeError("trusted calibrated policy cannot be constructed directly")

    def __init__(
        self,
        *_args: object,
        **_kwargs: object,
    ) -> None:
        del self, _args, _kwargs

    def require_for(self, policy: QualificationPolicy) -> None:
        _require_trusted_calibrated_policy(self, policy.policy_sha256)

    def __copy__(self) -> None:
        raise TypeError("trusted calibrated policy cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("trusted calibrated policy cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("trusted calibrated policy cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("trusted calibrated policy cannot be serialized")


def _build_trusted_calibrated_policy_authority() -> tuple[
    Callable[..., TrustedCalibratedQualificationPolicy],
    Callable[[TrustedCalibratedQualificationPolicy, str], None],
]:
    registry: dict[
        int,
        tuple[weakref.ReferenceType[TrustedCalibratedQualificationPolicy], str],
    ] = {}
    lock = threading.RLock()

    def issue(
        *,
        policy: QualificationPolicy,
        calibration: Any,
        trusted_calibration_verification: Any,
    ) -> TrustedCalibratedQualificationPolicy:
        from mmaudit.models.calibration import verify_calibrated_qualification_policy

        if type(policy) is not QualificationPolicy:
            raise ValueError("trusted calibrated policy issuance requires a typed policy")
        validated = QualificationPolicy.model_validate(policy.model_dump(mode="json"))
        if validated.schema_version != "2.0":
            raise ValueError("trusted calibrated policy authority requires policy v2")
        verify_calibrated_qualification_policy(
            calibration=calibration,
            policy=validated,
            trusted_calibration_verification=trusted_calibration_verification,
        )
        capability = object.__new__(TrustedCalibratedQualificationPolicy)
        key = id(capability)

        def discard(
            reference: weakref.ReferenceType[TrustedCalibratedQualificationPolicy],
        ) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = weakref.ref(capability, discard)
        with lock:
            registry[key] = (reference, validated.policy_sha256)
        return capability

    def require(
        capability: TrustedCalibratedQualificationPolicy,
        policy_sha256: str,
    ) -> None:
        with lock:
            registered = registry.get(id(capability))
            if (
                registered is None
                or registered[0]() is not capability
                or registered[1] != policy_sha256
            ):
                raise ValueError("trusted calibrated policy authority is absent or mismatched")

    return issue, require


(
    issue_trusted_calibrated_qualification_policy,
    _require_trusted_calibrated_policy,
) = _build_trusted_calibrated_policy_authority()


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


class RoleQualificationResult(StrictModel):
    """Deterministic secondary conclusion for one role class."""

    role_class: QualificationRoleClass
    disposition: RoleQualificationDisposition
    dimensions: tuple[QualificationDimensionResult, ...] = Field(
        default=(),
        max_length=len(ModelBenchmarkDimension),
    )
    overall_score: float = Field(ge=0, le=1)
    failed_minimum_case_dimensions: tuple[ModelBenchmarkDimension, ...] = Field(
        default=(),
        max_length=len(ModelBenchmarkDimension),
    )
    failed_minimum_score_dimensions: tuple[ModelBenchmarkDimension, ...] = Field(
        default=(),
        max_length=len(ModelBenchmarkDimension),
    )
    failure_reasons: tuple[RoleQualificationFailure, ...] = Field(
        default=(),
        max_length=len(RoleQualificationFailure),
    )

    @field_validator(
        "failed_minimum_case_dimensions",
        "failed_minimum_score_dimensions",
    )
    @classmethod
    def failed_dimensions_are_unique_and_sorted(
        cls,
        value: tuple[ModelBenchmarkDimension, ...],
    ) -> tuple[ModelBenchmarkDimension, ...]:
        if value != tuple(sorted(set(value), key=lambda item: item.value)):
            raise ValueError("failed role qualification dimensions must be unique and sorted")
        return value

    @field_validator("failure_reasons")
    @classmethod
    def failure_reasons_are_unique_and_sorted(
        cls,
        value: tuple[RoleQualificationFailure, ...],
    ) -> tuple[RoleQualificationFailure, ...]:
        if value != tuple(sorted(set(value), key=lambda item: item.value)):
            raise ValueError("role qualification failures must be unique and sorted")
        return value

    @model_validator(mode="after")
    def conclusion_is_internally_consistent(self) -> RoleQualificationResult:
        dimension_names = tuple(item.dimension.value for item in self.dimensions)
        if dimension_names != tuple(sorted(set(dimension_names))):
            raise ValueError("role qualification dimensions must be unique and sorted")
        observed_dimensions = {item.dimension for item in self.dimensions}
        if not set(self.failed_minimum_case_dimensions).issubset(observed_dimensions) or not set(
            self.failed_minimum_score_dimensions
        ).issubset(observed_dimensions):
            raise ValueError("failed role qualification dimensions were not evaluated")
        expected_overall = (
            round(sum(item.score for item in self.dimensions) / len(self.dimensions), 6)
            if self.dimensions
            else 0.0
        )
        if self.overall_score != expected_overall:
            raise ValueError("role qualification overall score is inconsistent")
        failures = set(self.failure_reasons)
        if (RoleQualificationFailure.MINIMUM_CASES in failures) is not bool(
            self.failed_minimum_case_dimensions
        ):
            raise ValueError("role minimum-case failure evidence is inconsistent")
        if (RoleQualificationFailure.MINIMUM_DIMENSION_SCORE in failures) is not bool(
            self.failed_minimum_score_dimensions
        ):
            raise ValueError("role minimum-score failure evidence is inconsistent")
        if self.disposition is RoleQualificationDisposition.QUALIFIED:
            if (
                not self.dimensions
                or self.failed_minimum_case_dimensions
                or self.failed_minimum_score_dimensions
                or self.failure_reasons
            ):
                raise ValueError("qualified role cannot retain failures")
        elif not self.failure_reasons:
            raise ValueError("unqualified role requires an explicit failure")
        if (
            self.disposition is RoleQualificationDisposition.INCONCLUSIVE
            and self.failure_reasons != (RoleQualificationFailure.GLOBAL_BASELINE_INCONCLUSIVE,)
        ):
            raise ValueError("inconclusive role requires an inconclusive global baseline")
        if (
            self.disposition is not RoleQualificationDisposition.INCONCLUSIVE
            and RoleQualificationFailure.GLOBAL_BASELINE_INCONCLUSIVE in failures
        ):
            raise ValueError("conclusive role cannot claim an inconclusive global baseline")
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
    canonical_model_id: str = Field(pattern=_MODEL_PATTERN, max_length=300)
    catalog_identity_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
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

    @field_validator("exact_model_id", "canonical_model_id")
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
        if self.catalog_identity_binding_sha256 != canonical_sha256(
            {
                "canonical_slug": self.canonical_model_id,
                "id": self.exact_model_id,
            }
        ):
            raise ValueError("verified benchmark catalog identity binding is inconsistent")
        attestations = {
            attestation.generation_id: attestation for attestation in self.generation_attestations
        }
        for record in self.usage_records:
            generation_id = record.openrouter_generation_id
            provider_name = record.routing.get("selected_provider_name")
            if generation_id is None or not isinstance(provider_name, str):
                raise ValueError("verified benchmark usage lacks provider generation identity")
            _reconcile_generation_evidence_structural(
                attestations[generation_id],
                usage_record=record,
                expected_exact_model=self.exact_model_id,
                expected_canonical_model=self.canonical_model_id,
                expected_catalog_identity_binding_sha256=(self.catalog_identity_binding_sha256),
                expected_discovery_evidence_sha256=self.discovery_evidence_sha256,
                expected_provider_name=provider_name,
            )
        expected_generation_hash = canonical_sha256(
            [
                _stable_generation_binding(attestation)
                for attestation in self.generation_attestations
            ]
        )
        if self.generation_evidence_sha256 != expected_generation_hash:
            raise ValueError("verified benchmark generation-evidence hash is inconsistent")
        verification_payload = self.model_dump(
            mode="json",
            exclude={"verification_sha256"},
        )
        verification_payload["generation_attestations"] = [
            _stable_generation_binding(attestation) for attestation in self.generation_attestations
        ]
        expected = canonical_sha256(verification_payload)
        if self.verification_sha256 != expected:
            raise ValueError("trusted benchmark verification self-hash is inconsistent")
        return self

    @property
    def stable_measurement_sha256(self) -> str:
        """Return the retrieval-time-independent quality measurement."""

        return self.verification_sha256

    @property
    def fresh_evidence_sha256(self) -> str:
        """Bind the complete freshly observed attestations, including retrieval time."""

        return _canonical_json_sha256(self.model_dump(mode="json"))


def verify_and_seal_trusted_benchmark_evidence(
    *,
    report: ModelBenchmarkReport,
    corpus: ModelBenchmarkSuite,
    exact_model_id: str,
    canonical_model_id: str,
    discovery_evidence_sha256: str,
    trusted_generation_verification: TrustedGenerationVerification,
) -> TrustedBenchmarkVerificationEvidence:
    """Recompute and seal one model result after authenticated generation re-fetches."""

    exact_model_id = _validate_exact_model_id(exact_model_id)
    canonical_model_id = _validate_exact_model_id(canonical_model_id)
    catalog_identity_binding_sha256 = canonical_sha256(
        {
            "canonical_slug": canonical_model_id,
            "id": exact_model_id,
        }
    )
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
                canonical_model_id=canonical_model_id,
                catalog_identity_binding_sha256=(catalog_identity_binding_sha256),
                discovery_evidence_sha256=discovery_evidence_sha256,
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
        canonical_model_id=canonical_model_id,
        catalog_identity_binding_sha256=catalog_identity_binding_sha256,
        discovery_evidence_sha256=discovery_evidence_sha256,
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
    canonical_model_id: str,
    catalog_identity_binding_sha256: str,
    discovery_evidence_sha256: str,
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
        "canonical_model_id": canonical_model_id,
        "catalog_identity_binding_sha256": catalog_identity_binding_sha256,
        "discovery_evidence_sha256": discovery_evidence_sha256,
        "benchmark_report_sha256": benchmark_report_sha256,
        "benchmark_corpus_sha256": benchmark_corpus_sha256,
        "benchmark_ground_truth_sha256": benchmark_ground_truth_sha256,
        "prompt_sha256": prompt_sha256,
        "response_schema_sha256": response_schema_sha256,
        "parsed_responses_sha256": parsed_responses_sha256,
        "generation_evidence_sha256": canonical_sha256(
            [_stable_generation_binding(item) for item in ordered_attestations]
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
    verification_payload = {
        **payload,
        "generation_attestations": [
            _stable_generation_binding(item) for item in ordered_attestations
        ],
    }
    payload["verification_sha256"] = _canonical_json_sha256(verification_payload)
    return TrustedBenchmarkVerificationEvidence.model_validate(payload)


def _stable_generation_binding(
    attestation: OpenRouterGenerationEvidence,
) -> dict[str, Any]:
    """Exclude observation-local retrieval metadata from the provider identity join."""

    return attestation.model_dump(
        mode="json",
        exclude={"retrieved_at", "evidence_sha256"},
    )


class ModelQualificationResult(StrictModel):
    """Deterministic qualification conclusion for one exact candidate."""

    exact_model_id: str = Field(pattern=_MODEL_PATTERN, max_length=300)
    canonical_model_slug: str = Field(pattern=_MODEL_PATTERN, max_length=300)
    root_lineage: str | None = Field(default=None, pattern=_LINEAGE_PATTERN)
    approved_provider_endpoint: str = Field(pattern=_ENDPOINT_PATTERN)
    approved_provider_name: str = Field(pattern=_PROVIDER_NAME_PATTERN)
    endpoint_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    output_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    model_metadata_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    pricing_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    structured_output_mode: StructuredOutputMode
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
    declared_roles: tuple[str, ...] = Field(
        default=(),
        max_length=128,
        exclude_if=lambda value: not value,
    )
    role_results: tuple[RoleQualificationResult, ...] = Field(
        default=(),
        max_length=len(QualificationRoleClass),
        exclude_if=lambda value: not value,
    )
    evaluated_at: datetime
    expires_at: datetime | None = None
    failure_reasons: tuple[str, ...] = Field(default=(), max_length=100)
    scored_by: Literal["mmaudit-deterministic-qualification"] = (
        "mmaudit-deterministic-qualification"
    )
    quality_measurement_sha256: str = Field(pattern=_SHA256_PATTERN)
    result_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id", "canonical_model_slug")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        return _validate_exact_model_id(value)

    @field_validator("approved_roles", "declared_roles")
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
        role_classes = tuple(result.role_class.value for result in self.role_results)
        if self.role_results and role_classes != tuple(
            sorted(item.value for item in QualificationRoleClass)
        ):
            raise ValueError("role qualification results must cover every role class exactly once")
        if self.role_results:
            if not set(self.approved_roles).issubset(self.declared_roles):
                raise ValueError("role qualification cannot authorize an undeclared role")
        elif self.declared_roles:
            raise ValueError("legacy qualification cannot contain unbound declared roles")
        if self.disposition is not QualificationDisposition.TIER_A and any(
            result.disposition is RoleQualificationDisposition.QUALIFIED
            for result in self.role_results
        ):
            raise ValueError("role qualification requires a global Tier A baseline")
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
        expected_measurement = canonical_sha256(
            self.model_dump(
                mode="json",
                exclude={
                    "evaluated_at",
                    "expires_at",
                    "benchmark_verification_sha256",
                    "quality_measurement_sha256",
                    "result_sha256",
                },
            )
        )
        if self.quality_measurement_sha256 != expected_measurement:
            raise ValueError("model qualification stable quality measurement is inconsistent")
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
    output_capability_sha256: str,
    model_metadata_snapshot_sha256: str,
    pricing_snapshot_sha256: str,
    structured_output_mode: StructuredOutputMode,
    benchmark_report_sha256: str,
    benchmark_verification_sha256: str | None,
    disposition: QualificationDisposition,
    dimensions: tuple[QualificationDimensionResult, ...],
    overall_score: float,
    approved_roles: tuple[str, ...],
    evaluated_at: datetime,
    expires_at: datetime | None,
    declared_roles: tuple[str, ...] = (),
    failure_reasons: tuple[str, ...] = (),
    role_results: tuple[RoleQualificationResult, ...] = (),
) -> ModelQualificationResult:
    payload: dict[str, Any] = {
        "exact_model_id": exact_model_id,
        "canonical_model_slug": canonical_model_slug,
        "root_lineage": root_lineage,
        "approved_provider_endpoint": approved_provider_endpoint,
        "approved_provider_name": approved_provider_name,
        "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
        "output_capability_sha256": output_capability_sha256,
        "model_metadata_snapshot_sha256": model_metadata_snapshot_sha256,
        "pricing_snapshot_sha256": pricing_snapshot_sha256,
        "structured_output_mode": structured_output_mode.value,
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
    if declared_roles:
        payload["declared_roles"] = list(declared_roles)
    if role_results:
        payload["role_results"] = [
            result.model_dump(mode="json")
            for result in sorted(role_results, key=lambda item: item.role_class.value)
        ]
    payload["quality_measurement_sha256"] = _canonical_json_sha256(
        {
            key: value
            for key, value in payload.items()
            if key
            not in {
                "benchmark_verification_sha256",
                "evaluated_at",
                "expires_at",
            }
        }
    )
    payload["result_sha256"] = _canonical_json_sha256(payload)
    return ModelQualificationResult.model_validate(payload)


def require_complete_reasoning_qualification_bindings(
    *,
    result: ModelQualificationResult,
    qualification_verification_sha256: str,
    endpoint_reasoning_capability_sha256: str,
    reasoning_policy: ReasoningPolicyArtifact,
    bindings: tuple[QualifiedReasoningRoleBinding, ...],
) -> tuple[QualifiedReasoningRoleBinding, ...]:
    """Require exact reasoning qualification coverage for every approved role.

    This helper is deliberately separate from model-selection authority. It lets
    the production resolver fail closed while the result's existing self-hash
    remains acyclic: the final bindings can include both the sealed result hash
    and the later qualification-verification hash.
    """

    result = ModelQualificationResult.model_validate(result.model_dump(mode="json"))
    if result.disposition is not QualificationDisposition.TIER_A:
        raise ValueError("reasoning qualification coverage requires a Tier A result")
    if result.benchmark_verification_sha256 is None:
        raise ValueError("reasoning qualification coverage requires verified benchmark evidence")
    if re.fullmatch(_SHA256_PATTERN, qualification_verification_sha256) is None:
        raise ValueError("reasoning qualification verification hash is malformed")
    if re.fullmatch(_SHA256_PATTERN, endpoint_reasoning_capability_sha256) is None:
        raise ValueError("endpoint reasoning capability hash is malformed")
    if type(reasoning_policy) is not ReasoningPolicyArtifact:
        raise ValueError("reasoning qualification policy is not sealed")
    reasoning_policy = ReasoningPolicyArtifact.model_validate(
        reasoning_policy.model_dump(mode="python")
    )

    approved_roles = result.approved_roles
    try:
        expected_routes = tuple(
            sorted(
                (
                    qualified_role,
                    configured_policy_role,
                )
                for qualified_role in approved_roles
                for configured_policy_role in reasoning_policy_roles_for_qualified_role(
                    qualified_role
                )
            )
        )
    except ReasoningPolicyError as exc:
        raise ValueError("reasoning qualification contains an unsupported approved role") from exc
    if not approved_roles:
        raise ValueError("reasoning qualification requires approved roles")
    binding_routes = tuple(
        (binding.qualified_role, binding.configured_policy_role) for binding in bindings
    )
    if binding_routes != expected_routes or binding_routes != tuple(sorted(set(binding_routes))):
        raise ValueError(
            "reasoning qualification bindings must cover every approved role route exactly"
        )

    validated: list[QualifiedReasoningRoleBinding] = []
    for binding in bindings:
        expected_role_policy = reasoning_policy.role_policy(binding.configured_policy_role)
        validated.append(
            binding.require_exact(
                exact_model_id=result.exact_model_id,
                approved_provider_endpoint=result.approved_provider_endpoint,
                approved_provider_name=result.approved_provider_name,
                qualified_role=binding.qualified_role,
                configured_policy_role=binding.configured_policy_role,
                control_profile=expected_role_policy.control,
                reasoning_policy_artifact_sha256=reasoning_policy.artifact_sha256,
                reasoning_policy_role_binding_sha256=expected_role_policy.binding_sha256,
                endpoint_reasoning_capability_sha256=(endpoint_reasoning_capability_sha256),
                qualification_report_sha256=result.benchmark_report_sha256,
                qualification_result_sha256=result.result_sha256,
                qualification_verification_sha256=qualification_verification_sha256,
            )
        )
    return tuple(validated)


def _qualified_benchmark_reasoning_observation(
    *,
    evidence: TrustedBenchmarkVerificationEvidence,
    reasoning_policy: ReasoningPolicyArtifact,
) -> tuple[ReasoningControlProfile, str]:
    """Require one uniform capability-bound profile across a real benchmark report."""

    benchmark_policy = reasoning_policy.role_policy_for_request("model_benchmark")
    observations: list[tuple[ReasoningControlProfile, str]] = []
    for record in evidence.usage_records:
        execution = record.reasoning_evidence
        if type(execution) is not ReasoningExecutionEvidence:
            raise ValueError(
                f"Tier A benchmark lacks typed reasoning execution evidence: "
                f"{evidence.exact_model_id}"
            )
        plan = execution.request_plan
        if (
            plan.resolution.request_role != "model_benchmark"
            or plan.resolution.mapping_kind != "prequalification_benchmark"
            or plan.policy_artifact_sha256 != reasoning_policy.artifact_sha256
            or plan.policy_role_binding_sha256 != benchmark_policy.binding_sha256
            or plan.control_profile != benchmark_policy.control
            or plan.binding_state != "capability_bound"
            or plan.endpoint_capability_sha256 is None
            or plan.qualification_binding_sha256 is not None
        ):
            raise ValueError(
                f"Tier A benchmark reasoning plan differs from production policy: "
                f"{evidence.exact_model_id}"
            )
        if plan.control_profile.mode != "disabled" and execution.state != "active_observed":
            raise ValueError(
                f"Tier A benchmark lacks observable active reasoning accounting: "
                f"{evidence.exact_model_id}"
            )
        observations.append((plan.control_profile, plan.endpoint_capability_sha256))
    if not observations:
        raise ValueError(
            f"Tier A benchmark lacks reasoning observations: {evidence.exact_model_id}"
        )
    profile = observations[0][0]
    capability_sha256 = observations[0][1]
    if any(
        observed_profile != profile or observed_capability != capability_sha256
        for observed_profile, observed_capability in observations[1:]
    ):
        raise ValueError(
            f"Tier A benchmark mixed reasoning profiles or capabilities: {evidence.exact_model_id}"
        )
    return profile, capability_sha256


def evaluate_role_qualification_results(
    *,
    global_disposition: QualificationDisposition,
    dimensions: tuple[QualificationDimensionResult, ...],
    role_policies: tuple[RoleQualificationPolicy, ...],
) -> tuple[RoleQualificationResult, ...]:
    """Apply all secondary role gates without upgrading the global conclusion."""

    validated_policies = tuple(
        RoleQualificationPolicy.model_validate(policy.model_dump(mode="json"))
        for policy in role_policies
    )
    role_classes = tuple(policy.role_class.value for policy in validated_policies)
    if role_classes != tuple(sorted(item.value for item in QualificationRoleClass)):
        raise ValueError("role qualification evaluation requires every role class exactly once")
    observed = {item.dimension: item for item in dimensions}
    if len(observed) != len(dimensions):
        raise ValueError("role qualification dimensions are duplicate")

    results: list[RoleQualificationResult] = []
    for role_policy in validated_policies:
        selected = tuple(
            observed[threshold.dimension]
            for threshold in role_policy.thresholds
            if threshold.dimension in observed
        )
        if global_disposition is QualificationDisposition.INCONCLUSIVE:
            results.append(
                RoleQualificationResult(
                    role_class=role_policy.role_class,
                    disposition=RoleQualificationDisposition.INCONCLUSIVE,
                    dimensions=(),
                    overall_score=0.0,
                    failure_reasons=(RoleQualificationFailure.GLOBAL_BASELINE_INCONCLUSIVE,),
                )
            )
            continue
        if len(selected) != len(role_policy.thresholds):
            raise ValueError("role qualification policy references an unmeasured dimension")

        failed_cases = tuple(
            sorted(
                (
                    threshold.dimension
                    for threshold in role_policy.thresholds
                    if observed[threshold.dimension].evaluated < threshold.minimum_cases
                ),
                key=lambda item: item.value,
            )
        )
        failed_scores = tuple(
            sorted(
                (
                    threshold.dimension
                    for threshold in role_policy.thresholds
                    if observed[threshold.dimension].score < threshold.minimum_score
                ),
                key=lambda item: item.value,
            )
        )
        overall_score = round(
            sum(item.score for item in selected) / len(selected),
            6,
        )
        failures: set[RoleQualificationFailure] = set()
        if global_disposition is not QualificationDisposition.TIER_A:
            failures.add(RoleQualificationFailure.GLOBAL_BASELINE_NOT_TIER_A)
        if failed_cases:
            failures.add(RoleQualificationFailure.MINIMUM_CASES)
        if failed_scores:
            failures.add(RoleQualificationFailure.MINIMUM_DIMENSION_SCORE)
        if overall_score < role_policy.minimum_overall_score:
            failures.add(RoleQualificationFailure.MINIMUM_OVERALL_SCORE)
        results.append(
            RoleQualificationResult(
                role_class=role_policy.role_class,
                disposition=(
                    RoleQualificationDisposition.QUALIFIED
                    if not failures
                    else RoleQualificationDisposition.NOT_QUALIFIED
                ),
                dimensions=tuple(sorted(selected, key=lambda item: item.dimension.value)),
                overall_score=overall_score,
                failed_minimum_case_dimensions=failed_cases,
                failed_minimum_score_dimensions=failed_scores,
                failure_reasons=tuple(sorted(failures, key=lambda item: item.value)),
            )
        )
    return tuple(results)


def qualification_role_class_for_declared_role(role: str) -> QualificationRoleClass:
    """Map only the three reserved validator names away from investigator."""

    if re.fullmatch(_ROLE_PATTERN, role) is None:
        raise ValueError("declared qualification role is malformed")
    if role == "verifier":
        return QualificationRoleClass.VERIFIER
    if role == "falsifier":
        return QualificationRoleClass.FALSIFIER
    if role == "judge":
        return QualificationRoleClass.JUDGE
    return QualificationRoleClass.INVESTIGATOR


def derive_approved_roles_for_role_qualification(
    *,
    declared_roles: tuple[str, ...],
    global_disposition: QualificationDisposition,
    role_results: tuple[RoleQualificationResult, ...],
) -> tuple[str, ...]:
    """Intersect declared roles with qualified role classes, never expanding authority."""

    declared_roles = _validate_sorted_unique(declared_roles, label="declared qualification roles")
    for role in declared_roles:
        qualification_role_class_for_declared_role(role)
    validated_results = tuple(
        RoleQualificationResult.model_validate(result.model_dump(mode="json"))
        for result in role_results
    )
    role_classes = tuple(result.role_class.value for result in validated_results)
    if role_classes != tuple(sorted(item.value for item in QualificationRoleClass)):
        raise ValueError("role approval derivation requires every role class exactly once")
    if global_disposition is not QualificationDisposition.TIER_A:
        return ()
    qualified_classes = {
        result.role_class
        for result in validated_results
        if result.disposition is RoleQualificationDisposition.QUALIFIED
    }
    return tuple(
        role
        for role in declared_roles
        if qualification_role_class_for_declared_role(role) in qualified_classes
    )


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


@dataclass(frozen=True, slots=True, init=False)
class VerifiedTierAModelQualification:
    """Opaque immutable snapshot of one fully verified Tier A model result."""

    exact_model_id: str
    canonical_model_slug: str
    root_lineage: str
    approved_provider_endpoint: str
    approved_provider_name: str
    endpoint_snapshot_sha256: str
    output_capability_sha256: str
    model_metadata_snapshot_sha256: str
    pricing_snapshot_sha256: str
    structured_output_mode: StructuredOutputMode
    approved_roles: tuple[str, ...]
    qualification_disposition: QualificationDisposition
    overall_score: float
    quality_measurement_sha256: str
    qualification_result_sha256: str
    benchmark_report_sha256: str
    benchmark_verification_sha256: str
    fresh_benchmark_evidence_sha256: str
    reasoning_bindings: tuple[QualifiedReasoningRoleBinding, ...]
    evaluated_at: datetime
    expires_at: datetime
    benchmark_case_count: int

    def __new__(cls, *_args: object, **_kwargs: object) -> Self:
        del cls, _args, _kwargs
        raise TypeError(
            "verified model qualification can only be issued by the qualification resolver"
        )

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    @property
    def quality_measurement(self) -> str:
        """Return the immutable config identifier for this exact verified result."""

        return f"sha256:{self.quality_measurement_sha256}"

    def __copy__(self) -> Never:
        raise TypeError("verified model qualification cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("verified model qualification cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("verified model qualification cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("verified model qualification cannot be serialized")


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class VerifiedProductionQualification:
    """Opaque capability proving a current complete production qualification."""

    verified_at: datetime
    expires_at: datetime
    artifact_sha256: str
    qualification_verification_sha256: str
    production_effective_config_sha256: str
    production_selection_sha256: str
    selection_verification_sha256: str
    candidate_registry_sha256: str
    policy_sha256: str
    bindings: QualificationBindings
    expected_bindings_sha256: str
    release_observation_sha256: str
    models: tuple[VerifiedTierAModelQualification, ...]
    capability_sha256: str

    def __new__(cls, *_args: object, **_kwargs: object) -> Self:
        del cls, _args, _kwargs
        raise TypeError(
            "verified production qualification can only be issued by the qualification resolver"
        )

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def __copy__(self) -> Never:
        raise TypeError("verified production qualification cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("verified production qualification cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("verified production qualification cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("verified production qualification cannot be serialized")

    def model_for(
        self,
        exact_model_id: str,
        *,
        now: datetime,
    ) -> VerifiedTierAModelQualification:
        """Resolve one exact qualified ID without alias inheritance."""

        self.require_current(now=now)
        exact_model_id = _validate_exact_model_id(exact_model_id)
        matches = tuple(model for model in self.models if model.exact_model_id == exact_model_id)
        if len(matches) != 1:
            raise ValueError(f"exact model lacks verified Tier A qualification: {exact_model_id}")
        return matches[0]

    def require_current(self, *, now: datetime) -> Self:
        """Revalidate capability integrity and freshness before authority is consumed."""

        now = _validate_utc_second(now, label="verified qualification use time")
        issued_state = _issued_verified_production_capability_state(self)
        if type(self) is not VerifiedProductionQualification or issued_state is None:
            raise ValueError("verified production qualification has an invalid capability type")
        if (
            re.fullmatch(_SHA256_PATTERN, self.artifact_sha256) is None
            or re.fullmatch(_SHA256_PATTERN, self.qualification_verification_sha256) is None
            or re.fullmatch(_SHA256_PATTERN, self.production_effective_config_sha256) is None
            or re.fullmatch(_SHA256_PATTERN, self.production_selection_sha256) is None
            or re.fullmatch(_SHA256_PATTERN, self.selection_verification_sha256) is None
            or re.fullmatch(_SHA256_PATTERN, self.candidate_registry_sha256) is None
            or re.fullmatch(_SHA256_PATTERN, self.policy_sha256) is None
            or re.fullmatch(_SHA256_PATTERN, self.expected_bindings_sha256) is None
            or re.fullmatch(_SHA256_PATTERN, self.release_observation_sha256) is None
            or re.fullmatch(_SHA256_PATTERN, self.capability_sha256) is None
        ):
            raise ValueError("verified production qualification contains malformed bindings")
        if type(self.bindings) is not QualificationBindings:
            raise ValueError("verified production qualification bindings have an invalid type")
        validated_bindings = QualificationBindings.model_validate(
            self.bindings.model_dump(mode="json")
        )
        if (
            self.expected_bindings_sha256
            != _canonical_json_sha256(validated_bindings.model_dump(mode="json"))
            or validated_bindings.candidate_registry_sha256 != self.candidate_registry_sha256
            or validated_bindings.qualification_policy_sha256 != self.policy_sha256
        ):
            raise ValueError("verified production qualification binding projection differs")
        if self.verified_at > now + _FUTURE_SKEW:
            raise ValueError("verified production qualification is future-dated")
        if self.expires_at <= now or self.expires_at <= self.verified_at:
            raise ValueError("verified production qualification is expired")
        if (
            any(type(model) is not VerifiedTierAModelQualification for model in self.models)
            or tuple(id(model) for model in self.models) != issued_state.model_identities
        ):
            raise ValueError("verified production qualification contains an invalid model type")
        model_ids = tuple(model.exact_model_id for model in self.models)
        if (
            len(model_ids) < _MIN_EXACT_MODELS
            or model_ids != tuple(sorted(set(model_ids)))
            or len({model.root_lineage for model in self.models}) < _MIN_ROOT_LINEAGES
            or self.expires_at != min(model.expires_at for model in self.models)
        ):
            raise ValueError("verified production qualification has an invalid model set")
        for model in self.models:
            _validate_exact_model_id(model.exact_model_id)
            _validate_exact_model_id(model.canonical_model_slug)
            try:
                expected_reasoning_routes = tuple(
                    sorted(
                        (
                            qualified_role,
                            configured_policy_role,
                        )
                        for qualified_role in model.approved_roles
                        for configured_policy_role in reasoning_policy_roles_for_qualified_role(
                            qualified_role
                        )
                    )
                )
            except ReasoningPolicyError as exc:
                raise ValueError(
                    f"verified production model has an unknown qualified role: "
                    f"{model.exact_model_id}"
                ) from exc
            observed_reasoning_routes = tuple(
                (binding.qualified_role, binding.configured_policy_role)
                for binding in model.reasoning_bindings
            )
            if (
                re.fullmatch(_LINEAGE_PATTERN, model.root_lineage) is None
                or re.fullmatch(_ENDPOINT_PATTERN, model.approved_provider_endpoint) is None
                or re.fullmatch(_PROVIDER_NAME_PATTERN, model.approved_provider_name) is None
                or re.fullmatch(_SHA256_PATTERN, model.endpoint_snapshot_sha256) is None
                or re.fullmatch(_SHA256_PATTERN, model.output_capability_sha256) is None
                or re.fullmatch(_SHA256_PATTERN, model.model_metadata_snapshot_sha256) is None
                or re.fullmatch(_SHA256_PATTERN, model.pricing_snapshot_sha256) is None
                or type(model.structured_output_mode) is not StructuredOutputMode
                or model.approved_roles != tuple(sorted(set(model.approved_roles)))
                or not model.approved_roles
                or any(re.fullmatch(_ROLE_PATTERN, role) is None for role in model.approved_roles)
                or model.qualification_disposition is not QualificationDisposition.TIER_A
                or not 0 <= model.overall_score <= 1
                or re.fullmatch(_SHA256_PATTERN, model.quality_measurement_sha256) is None
                or re.fullmatch(_SHA256_PATTERN, model.qualification_result_sha256) is None
                or re.fullmatch(_SHA256_PATTERN, model.benchmark_report_sha256) is None
                or re.fullmatch(_SHA256_PATTERN, model.benchmark_verification_sha256) is None
                or re.fullmatch(_SHA256_PATTERN, model.fresh_benchmark_evidence_sha256) is None
                or observed_reasoning_routes != expected_reasoning_routes
                or any(
                    type(binding) is not QualifiedReasoningRoleBinding
                    or binding.exact_model_id != model.exact_model_id
                    or binding.approved_provider_endpoint != model.approved_provider_endpoint
                    or binding.approved_provider_name != model.approved_provider_name
                    or binding.qualification_report_sha256 != model.benchmark_report_sha256
                    or binding.qualification_result_sha256 != model.qualification_result_sha256
                    or binding.qualification_verification_sha256
                    != self.qualification_verification_sha256
                    for binding in model.reasoning_bindings
                )
                or model.benchmark_case_count < 1
                or model.evaluated_at > self.verified_at
                or model.expires_at <= model.evaluated_at
                or model.expires_at <= now
            ):
                raise ValueError(
                    f"verified production model snapshot is invalid: {model.exact_model_id}"
                )
        if (
            self.capability_sha256 != issued_state.capability_sha256
            or self.capability_sha256
            != _canonical_json_sha256(_verified_production_qualification_payload(self))
        ):
            raise ValueError("verified production qualification integrity check failed")
        return self


def _verified_production_qualification_payload(
    capability: VerifiedProductionQualification,
) -> dict[str, Any]:
    return {
        "verified_at": capability.verified_at,
        "expires_at": capability.expires_at,
        "artifact_sha256": capability.artifact_sha256,
        "qualification_verification_sha256": (capability.qualification_verification_sha256),
        "production_effective_config_sha256": capability.production_effective_config_sha256,
        "production_selection_sha256": capability.production_selection_sha256,
        "selection_verification_sha256": capability.selection_verification_sha256,
        "candidate_registry_sha256": capability.candidate_registry_sha256,
        "policy_sha256": capability.policy_sha256,
        "bindings": capability.bindings.model_dump(mode="json"),
        "expected_bindings_sha256": capability.expected_bindings_sha256,
        "release_observation_sha256": capability.release_observation_sha256,
        "models": [
            {
                "exact_model_id": model.exact_model_id,
                "canonical_model_slug": model.canonical_model_slug,
                "root_lineage": model.root_lineage,
                "approved_provider_endpoint": model.approved_provider_endpoint,
                "approved_provider_name": model.approved_provider_name,
                "endpoint_snapshot_sha256": model.endpoint_snapshot_sha256,
                "output_capability_sha256": model.output_capability_sha256,
                "model_metadata_snapshot_sha256": model.model_metadata_snapshot_sha256,
                "pricing_snapshot_sha256": model.pricing_snapshot_sha256,
                "structured_output_mode": model.structured_output_mode.value,
                "approved_roles": list(model.approved_roles),
                "qualification_disposition": model.qualification_disposition.value,
                "overall_score": model.overall_score,
                "quality_measurement_sha256": model.quality_measurement_sha256,
                "qualification_result_sha256": model.qualification_result_sha256,
                "benchmark_report_sha256": model.benchmark_report_sha256,
                "benchmark_verification_sha256": model.benchmark_verification_sha256,
                "fresh_benchmark_evidence_sha256": model.fresh_benchmark_evidence_sha256,
                "reasoning_bindings": [
                    binding.model_dump(mode="json") for binding in model.reasoning_bindings
                ],
                "evaluated_at": model.evaluated_at,
                "expires_at": model.expires_at,
                "benchmark_case_count": model.benchmark_case_count,
            }
            for model in capability.models
        ],
    }


@dataclass(frozen=True, slots=True)
class _IssuedProductionCapabilityState:
    capability_sha256: str
    model_identities: tuple[int, ...]


def _build_verified_production_authority() -> tuple[
    Callable[[VerifiedProductionQualification], None],
    Callable[
        [VerifiedProductionQualification],
        _IssuedProductionCapabilityState | None,
    ],
]:
    """Keep final qualification authority outside caller-reconstructible dataclass fields."""

    registry: dict[
        int,
        tuple[
            weakref.ReferenceType[VerifiedProductionQualification],
            _IssuedProductionCapabilityState,
        ],
    ] = {}
    lock = threading.RLock()

    def register(capability: VerifiedProductionQualification) -> None:
        capability_sha256 = getattr(capability, "capability_sha256", None)
        if (
            type(capability) is not VerifiedProductionQualification
            or not isinstance(capability_sha256, str)
            or re.fullmatch(_SHA256_PATTERN, capability_sha256) is None
        ):
            raise ValueError("cannot register an incomplete production qualification")
        key = id(capability)

        def discard(reference: weakref.ReferenceType[VerifiedProductionQualification]) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = weakref.ref(capability, discard)
        with lock:
            registry[key] = (
                reference,
                _IssuedProductionCapabilityState(
                    capability_sha256=capability_sha256,
                    model_identities=tuple(id(model) for model in capability.models),
                ),
            )

    def issued_state(
        capability: VerifiedProductionQualification,
    ) -> _IssuedProductionCapabilityState | None:
        with lock:
            registered = registry.get(id(capability))
        return registered[1] if registered is not None and registered[0]() is capability else None

    return register, issued_state


_register_verified_production_capability, _issued_verified_production_capability_state = (
    _build_verified_production_authority()
)


def verify_model_qualification(
    *,
    artifact: ModelQualificationArtifact,
    registry: CandidateRegistry,
    policy: QualificationPolicy,
    expected_bindings: QualificationBindings,
    trusted_benchmark_evidence: tuple[TrustedBenchmarkVerificationEvidence, ...],
    now: datetime,
    trusted_calibrated_policy: TrustedCalibratedQualificationPolicy | None = None,
) -> QualificationVerification:
    """Recompute production eligibility; unresolved evidence always fails closed."""

    now = _validate_utc_second(now, label="qualification verification time")
    errors: list[str] = []
    if policy.schema_version == "2.0":
        if type(trusted_calibrated_policy) is not TrustedCalibratedQualificationPolicy:
            errors.append("calibrated qualification policy lacks live verification authority")
        else:
            try:
                trusted_calibrated_policy.require_for(policy)
            except ValueError:
                errors.append("calibrated qualification policy authority is mismatched")
    elif trusted_calibrated_policy is not None:
        errors.append("legacy qualification policy received calibrated policy authority")
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
            role_scoped=bool(policy.role_policies),
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

        if policy.role_policies:
            expected_role_results = evaluate_role_qualification_results(
                global_disposition=result.disposition,
                dimensions=result.dimensions,
                role_policies=policy.role_policies,
            )
            if result.role_results != expected_role_results:
                errors.append(f"role qualification results differ from policy: {model_id}")
            expected_retained_roles = derive_approved_roles_for_role_qualification(
                declared_roles=result.declared_roles,
                global_disposition=result.disposition,
                role_results=expected_role_results,
            )
            if result.approved_roles != expected_retained_roles:
                errors.append(f"qualification approved roles exceed role policy: {model_id}")
        elif result.role_results:
            errors.append(f"legacy qualification contains unbound role results: {model_id}")

        if result.disposition is QualificationDisposition.TIER_A:
            assert result.expires_at is not None
            if result.expires_at <= result.evaluated_at:
                errors.append(f"Tier A expiry is not after evaluation: {model_id}")
            if result.expires_at > result.evaluated_at + timedelta(
                days=policy.maximum_validity_days
            ):
                errors.append(f"Tier A validity exceeds policy: {model_id}")
            if result.expires_at > result.evaluated_at + timedelta(
                days=policy.maximum_benchmark_evidence_age_days
            ):
                errors.append(f"Tier A benchmark evidence window exceeds policy: {model_id}")
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
                and candidate.output_capability_sha256 is not None
                and _structured_output_reliability_passes(
                    result=result,
                    threshold=thresholds.get(ModelBenchmarkDimension.STRUCTURED_OUTPUT_COMPLIANCE),
                )
                and candidate.zdr_eligible
                and candidate.data_collection_deny_eligible
                and candidate.data_collection_deny_request_policy_enforced is True
                and candidate.data_collection_deny_evidence_source
                is DataCollectionDenyEvidenceSource.ZDR_ENDPOINT_SNAPSHOT
                and candidate.data_collection_deny_evidence_sha256 is not None
                and candidate.data_collection_deny_evidence_expires_at is None
                and bool(result.approved_roles)
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


def resolve_verified_production_qualification(
    *,
    artifact: ModelQualificationArtifact,
    registry: CandidateRegistry,
    policy: QualificationPolicy,
    expected_bindings: QualificationBindings,
    benchmark_reports: tuple[ModelBenchmarkReport, ...],
    benchmark_corpus: ModelBenchmarkSuite,
    trusted_campaign_verification: object | None,
    trusted_generation_verification: TrustedGenerationVerification,
    trusted_release_observation: TrustedReleaseBindingObservation,
    production_effective_config_sha256: str,
    reasoning_policy: ReasoningPolicyArtifact,
    now: datetime,
    trusted_calibrated_policy: TrustedCalibratedQualificationPolicy | None = None,
) -> VerifiedProductionQualification:
    """Issue an opaque production capability only from complete current REAL evidence."""

    inputs = (
        (artifact, ModelQualificationArtifact, "qualification artifact"),
        (registry, CandidateRegistry, "candidate registry"),
        (policy, QualificationPolicy, "qualification policy"),
        (expected_bindings, QualificationBindings, "expected qualification bindings"),
    )
    for input_value, expected_type, label in inputs:
        if type(input_value) is not expected_type:
            raise ValueError(f"{label} must be a fully validated typed value")
    if type(reasoning_policy) is not ReasoningPolicyArtifact:
        raise ValueError("production qualification requires a sealed reasoning policy")
    reasoning_policy = ReasoningPolicyArtifact.model_validate(
        reasoning_policy.model_dump(mode="python")
    )
    if (
        not isinstance(production_effective_config_sha256, str)
        or re.fullmatch(_SHA256_PATTERN, production_effective_config_sha256) is None
    ):
        raise ValueError("production effective configuration hash must be lowercase SHA-256")

    artifact = ModelQualificationArtifact.model_validate(artifact.model_dump(mode="json"))
    registry = CandidateRegistry.model_validate(registry.model_dump(mode="json"))
    policy = QualificationPolicy.model_validate(policy.model_dump(mode="json"))
    if policy.schema_version == "2.0":
        if type(trusted_calibrated_policy) is not TrustedCalibratedQualificationPolicy:
            raise ValueError("production qualification requires live calibrated policy authority")
        trusted_calibrated_policy.require_for(policy)
    elif trusted_calibrated_policy is not None:
        raise ValueError("legacy production qualification cannot consume calibrated authority")
    expected_bindings = QualificationBindings.model_validate(
        expected_bindings.model_dump(mode="json")
    )
    if type(trusted_release_observation) is not TrustedReleaseBindingObservation:
        raise ValueError("production qualification requires a trusted release observation")
    trusted_release_observation.require_for(expected_bindings)
    now = _validate_utc_second(now, label="production qualification verification time")
    if now != trusted_release_observation.observed_at:
        raise ValueError(
            "production qualification verification time differs from "
            "the trusted release observation"
        )
    _require_live_campaign_content_provenance(
        trusted_campaign_verification=trusted_campaign_verification,
        portfolio_sha256=artifact.bindings.benchmark_portfolio_sha256,
        benchmark_reports=benchmark_reports,
        policy_sha256=policy.policy_sha256,
        effective_config_sha256=expected_bindings.effective_config_sha256,
    )
    ordered_trusted = _freshly_reverify_production_benchmarks(
        artifact=artifact,
        registry=registry,
        benchmark_reports=benchmark_reports,
        benchmark_corpus=benchmark_corpus,
        trusted_generation_verification=trusted_generation_verification,
    )
    result_ids = tuple(result.exact_model_id for result in artifact.results)
    evidence_ids = tuple(item.exact_model_id for item in ordered_trusted)
    if evidence_ids != result_ids:
        raise ValueError(
            "verified production qualification requires exact non-empty benchmark "
            "evidence for every result"
        )
    if any(
        result.disposition is QualificationDisposition.INCONCLUSIVE for result in artifact.results
    ):
        raise ValueError("verified production qualification cannot contain incomplete results")

    verification = verify_model_qualification(
        artifact=artifact,
        registry=registry,
        policy=policy,
        expected_bindings=expected_bindings,
        trusted_benchmark_evidence=ordered_trusted,
        now=now,
        trusted_calibrated_policy=trusted_calibrated_policy,
    )
    if not verification.valid:
        raise ValueError(
            "qualification evidence failed verification: " + "; ".join(verification.errors)
        )
    if not verification.production_selection_ready:
        raise ValueError("qualification evidence is not ready for production selection")
    selection = seal_production_selection(
        artifact=artifact,
        verification=verification,
        production_effective_config_sha256=production_effective_config_sha256,
        selected_at=verification.verified_at,
    )
    selection_verification = verify_production_selection(
        selection=selection,
        artifact=artifact,
        qualification_verification=verification,
        expected_production_effective_config_sha256=production_effective_config_sha256,
        now=verification.verified_at,
    )
    if not selection_verification.valid:
        raise ValueError(
            "all-eligible-Tier-A production selection failed verification: "
            + "; ".join(selection_verification.errors)
        )

    tier_a_results = {
        result.exact_model_id: result
        for result in artifact.results
        if result.disposition is QualificationDisposition.TIER_A
    }
    if not tier_a_results or set(tier_a_results) != set(verification.eligible_tier_a_model_ids):
        raise ValueError(
            "every Tier A quality designation must resolve to production-eligible evidence"
        )
    evidence_by_model = {item.exact_model_id: item for item in ordered_trusted}
    models: list[VerifiedTierAModelQualification] = []
    for model_id in sorted(tier_a_results):
        result = tier_a_results[model_id]
        evidence = evidence_by_model[model_id]
        if (
            result.root_lineage is None
            or result.benchmark_verification_sha256 is None
            or result.expires_at is None
            or not result.approved_roles
            or not evidence.case_ids
            or not evidence.usage_records
            or not evidence.dimensions
            or evidence.execution_evidence is not ExecutionEvidenceKind.REAL
            or not evidence.valid
            or evidence.stable_measurement_sha256 != result.benchmark_verification_sha256
        ):
            raise ValueError(f"Tier A model lacks complete REAL benchmark evidence: {model_id}")
        benchmark_reasoning_profile, endpoint_reasoning_capability_sha256 = (
            _qualified_benchmark_reasoning_observation(
                evidence=evidence,
                reasoning_policy=reasoning_policy,
            )
        )
        expected_reasoning_profiles: dict[tuple[str, str], ReasoningControlProfile] = {}
        for qualified_role in result.approved_roles:
            for configured_policy_role in reasoning_policy_roles_for_qualified_role(qualified_role):
                profile = reasoning_policy.role_policy(configured_policy_role).control
                if profile != benchmark_reasoning_profile:
                    raise ValueError(
                        "production role reasoning profile was not measured by qualification: "
                        f"{model_id}/{qualified_role}/{configured_policy_role}"
                    )
                expected_reasoning_profiles[(qualified_role, configured_policy_role)] = profile
        reasoning_bindings = tuple(
            seal_qualified_reasoning_role_binding(
                exact_model_id=result.exact_model_id,
                approved_provider_endpoint=result.approved_provider_endpoint,
                approved_provider_name=result.approved_provider_name,
                qualified_role=qualified_role,
                configured_policy_role=configured_policy_role,
                control_profile=profile,
                reasoning_policy_artifact_sha256=reasoning_policy.artifact_sha256,
                reasoning_policy_role_binding_sha256=(
                    reasoning_policy.role_policy(configured_policy_role).binding_sha256
                ),
                endpoint_reasoning_capability_sha256=(endpoint_reasoning_capability_sha256),
                qualification_report_sha256=result.benchmark_report_sha256,
                qualification_result_sha256=result.result_sha256,
                qualification_verification_sha256=verification.verification_sha256,
            )
            for (qualified_role, configured_policy_role), profile in sorted(
                expected_reasoning_profiles.items()
            )
        )
        reasoning_bindings = require_complete_reasoning_qualification_bindings(
            result=result,
            qualification_verification_sha256=verification.verification_sha256,
            endpoint_reasoning_capability_sha256=(endpoint_reasoning_capability_sha256),
            reasoning_policy=reasoning_policy,
            bindings=reasoning_bindings,
        )
        model = object.__new__(VerifiedTierAModelQualification)
        object.__setattr__(model, "exact_model_id", result.exact_model_id)
        object.__setattr__(model, "canonical_model_slug", result.canonical_model_slug)
        object.__setattr__(model, "root_lineage", result.root_lineage)
        object.__setattr__(
            model,
            "approved_provider_endpoint",
            result.approved_provider_endpoint,
        )
        object.__setattr__(model, "approved_provider_name", result.approved_provider_name)
        object.__setattr__(
            model,
            "endpoint_snapshot_sha256",
            result.endpoint_snapshot_sha256,
        )
        object.__setattr__(
            model,
            "output_capability_sha256",
            result.output_capability_sha256,
        )
        object.__setattr__(
            model,
            "model_metadata_snapshot_sha256",
            result.model_metadata_snapshot_sha256,
        )
        object.__setattr__(
            model,
            "pricing_snapshot_sha256",
            result.pricing_snapshot_sha256,
        )
        object.__setattr__(
            model,
            "structured_output_mode",
            result.structured_output_mode,
        )
        object.__setattr__(model, "approved_roles", result.approved_roles)
        object.__setattr__(
            model,
            "qualification_disposition",
            result.disposition,
        )
        object.__setattr__(model, "overall_score", result.overall_score)
        object.__setattr__(
            model,
            "quality_measurement_sha256",
            result.quality_measurement_sha256,
        )
        object.__setattr__(
            model,
            "qualification_result_sha256",
            result.result_sha256,
        )
        object.__setattr__(
            model,
            "benchmark_report_sha256",
            result.benchmark_report_sha256,
        )
        object.__setattr__(
            model,
            "benchmark_verification_sha256",
            evidence.stable_measurement_sha256,
        )
        object.__setattr__(
            model,
            "fresh_benchmark_evidence_sha256",
            evidence.fresh_evidence_sha256,
        )
        object.__setattr__(model, "reasoning_bindings", reasoning_bindings)
        object.__setattr__(model, "evaluated_at", result.evaluated_at)
        object.__setattr__(model, "expires_at", result.expires_at)
        object.__setattr__(model, "benchmark_case_count", len(evidence.case_ids))
        models.append(model)

    verified_models = tuple(models)
    expires_at = min(model.expires_at for model in verified_models)
    if expires_at <= verification.verified_at:
        raise ValueError("verified production qualification is expired")
    expected_bindings_sha256 = _canonical_json_sha256(expected_bindings.model_dump(mode="json"))
    capability = object.__new__(VerifiedProductionQualification)
    object.__setattr__(capability, "verified_at", verification.verified_at)
    object.__setattr__(capability, "expires_at", expires_at)
    object.__setattr__(capability, "artifact_sha256", artifact.artifact_sha256)
    object.__setattr__(
        capability,
        "qualification_verification_sha256",
        verification.verification_sha256,
    )
    object.__setattr__(
        capability,
        "production_effective_config_sha256",
        production_effective_config_sha256,
    )
    object.__setattr__(
        capability,
        "production_selection_sha256",
        selection.selection_sha256,
    )
    object.__setattr__(
        capability,
        "selection_verification_sha256",
        selection_verification.verification_sha256,
    )
    object.__setattr__(
        capability,
        "candidate_registry_sha256",
        registry.registry_sha256,
    )
    object.__setattr__(capability, "policy_sha256", policy.policy_sha256)
    object.__setattr__(capability, "bindings", expected_bindings)
    object.__setattr__(
        capability,
        "expected_bindings_sha256",
        expected_bindings_sha256,
    )
    object.__setattr__(
        capability,
        "release_observation_sha256",
        trusted_release_observation.measurement_sha256,
    )
    object.__setattr__(capability, "models", verified_models)
    object.__setattr__(
        capability,
        "capability_sha256",
        _canonical_json_sha256(_verified_production_qualification_payload(capability)),
    )
    _register_verified_production_capability(capability)
    return capability.require_current(now=verification.verified_at)


def _require_live_campaign_content_provenance(
    *,
    trusted_campaign_verification: object | None,
    portfolio_sha256: str,
    benchmark_reports: tuple[ModelBenchmarkReport, ...],
    policy_sha256: str,
    effective_config_sha256: str,
) -> None:
    """Require process-local authority over the exact original provider response content."""

    # Local import avoids the model-portfolio -> qualification module cycle.
    from mmaudit.benchmark.model_portfolio import (
        TrustedCandidateBenchmarkCampaignVerification,
    )

    if type(trusted_campaign_verification) is not TrustedCandidateBenchmarkCampaignVerification:
        raise ValueError(
            "production qualification requires live response-content campaign provenance"
        )
    if not benchmark_reports or any(
        type(report) is not ModelBenchmarkReport for report in benchmark_reports
    ):
        raise ValueError("production qualification requires exact typed benchmark reports")
    trusted_campaign_verification.require_for(
        portfolio_sha256=portfolio_sha256,
        reports=benchmark_reports,
        policy_sha256=policy_sha256,
        effective_config_sha256=effective_config_sha256,
    )


def _freshly_reverify_production_benchmarks(
    *,
    artifact: ModelQualificationArtifact,
    registry: CandidateRegistry,
    benchmark_reports: tuple[ModelBenchmarkReport, ...],
    benchmark_corpus: ModelBenchmarkSuite,
    trusted_generation_verification: TrustedGenerationVerification,
) -> tuple[TrustedBenchmarkVerificationEvidence, ...]:
    """Re-score the frozen reports only after an authenticated generation re-fetch."""

    if type(benchmark_corpus) is not ModelBenchmarkSuite:
        raise ValueError("production qualification requires the exact typed benchmark corpus")
    if type(trusted_generation_verification) is not TrustedGenerationVerification:
        raise ValueError(
            "production qualification requires fresh authenticated generation verification"
        )
    corpus = ModelBenchmarkSuite.model_validate(benchmark_corpus.model_dump(mode="json"))
    if (
        corpus.corpus.schema_version != artifact.bindings.benchmark_corpus_version
        or corpus.ground_truth.schema_version != artifact.bindings.benchmark_ground_truth_version
        or corpus.corpus_sha256 != artifact.bindings.benchmark_corpus_sha256
        or corpus.ground_truth_sha256 != artifact.bindings.benchmark_ground_truth_sha256
    ):
        raise ValueError("production benchmark corpus differs from qualification bindings")

    reports: list[ModelBenchmarkReport] = []
    for supplied_report in benchmark_reports:
        if type(supplied_report) is not ModelBenchmarkReport:
            raise ValueError("production benchmark reports must be fully validated typed values")
        reports.append(ModelBenchmarkReport.model_validate(supplied_report.model_dump(mode="json")))
    report_ids = tuple(
        report.results[0].target.model_id for report in reports if len(report.results) == 1
    )
    candidate_ids = tuple(candidate.exact_model_id for candidate in registry.candidates)
    result_ids = tuple(result.exact_model_id for result in artifact.results)
    if (
        not reports
        or len(report_ids) != len(reports)
        or report_ids != tuple(sorted(set(report_ids)))
        or report_ids != candidate_ids
        or report_ids != result_ids
    ):
        raise ValueError(
            "production qualification requires one exact frozen report per candidate model"
        )

    candidates = {candidate.exact_model_id: candidate for candidate in registry.candidates}
    results = {result.exact_model_id: result for result in artifact.results}
    evidence: list[TrustedBenchmarkVerificationEvidence] = []
    for report in reports:
        model_id = report.results[0].target.model_id
        candidate = candidates[model_id]
        result = results[model_id]
        if (
            report.report_sha256 != result.benchmark_report_sha256
            or report.results[0].target.root_lineage != candidate.root_lineage
        ):
            raise ValueError(
                f"production benchmark report differs from frozen qualification: {model_id}"
            )
        evidence.append(
            verify_and_seal_trusted_benchmark_evidence(
                report=report,
                corpus=corpus,
                exact_model_id=model_id,
                canonical_model_id=candidate.canonical_model_slug,
                discovery_evidence_sha256=candidate.discovery_evidence_sha256,
                trusted_generation_verification=trusted_generation_verification,
            )
        )
    return tuple(evidence)


def _verify_result_candidate_binding(
    candidate: CandidateModel,
    result: ModelQualificationResult,
    errors: list[str],
    *,
    artifact_created_at: datetime,
    role_scoped: bool,
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
            "output capability",
            result.output_capability_sha256,
            candidate.output_capability_sha256,
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
        (
            "structured output mode",
            result.structured_output_mode,
            candidate.structured_output_mode,
        ),
    )
    role_fields = (
        (("declared roles", result.declared_roles, candidate.approved_roles),)
        if role_scoped
        else (("approved roles", result.approved_roles, candidate.approved_roles),)
    )
    for label, observed, expected in (*fields, *role_fields):
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
    if candidate.structured_output_mode is None or candidate.output_capability_sha256 is None:
        errors.append(
            f"candidate lacks exact output capability evidence: {candidate.exact_model_id}"
        )
        return
    if (
        result.benchmark_verification_sha256 != evidence.stable_measurement_sha256
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
            not _is_structurally_creditable_usage_record(
                record,
                require_real=True,
                require_certification=True,
            )
            or record.role != "model_benchmark"
            or record.requested_model != candidate.exact_model_id
            or record.returned_model
            not in {
                candidate.exact_model_id,
                candidate.canonical_model_slug,
            }
            or record.actual_provider_endpoint != candidate.approved_provider_endpoint
            or record.routing.get("selected_provider_name") != candidate.approved_provider_name
            or record.routing.get("endpoint_snapshot_sha256") != candidate.endpoint_snapshot_sha256
            or record.routing.get("output_capability_sha256") != candidate.output_capability_sha256
            or record.routing.get("endpoint_pricing_sha256") != candidate.pricing_snapshot_sha256
            or not isinstance(record.routing.get("structured_output"), dict)
            or record.routing["structured_output"].get("requested_mode")
            != candidate.structured_output_mode.value
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


def _structured_output_reliability_passes(
    *,
    result: ModelQualificationResult,
    threshold: QualificationDimensionThreshold | None,
) -> bool:
    """Require non-empty measured schema adherence, independent of native support."""

    if threshold is None:
        return False
    matches = tuple(
        dimension
        for dimension in result.dimensions
        if dimension.dimension is ModelBenchmarkDimension.STRUCTURED_OUTPUT_COMPLIANCE
    )
    return (
        len(matches) == 1
        and matches[0].evaluated >= max(1, threshold.minimum_cases)
        and matches[0].passed > 0
        and matches[0].score >= threshold.minimum_score
    )


class SelectedProductionModel(StrictModel):
    exact_model_id: str = Field(pattern=_MODEL_PATTERN, max_length=300)
    canonical_model_slug: str = Field(pattern=_MODEL_PATTERN, max_length=300)
    root_lineage: str = Field(pattern=_LINEAGE_PATTERN)
    approved_provider_endpoint: str = Field(pattern=_ENDPOINT_PATTERN)
    approved_provider_name: str = Field(pattern=_PROVIDER_NAME_PATTERN)
    output_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    structured_output_mode: StructuredOutputMode
    approved_roles: tuple[str, ...] = Field(min_length=1, max_length=128)
    quality_measurement_sha256: str = Field(pattern=_SHA256_PATTERN)
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
    production_effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
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
    production_effective_config_sha256: str,
    selected_at: datetime,
) -> ProductionModelSelection:
    if (
        not isinstance(production_effective_config_sha256, str)
        or re.fullmatch(_SHA256_PATTERN, production_effective_config_sha256) is None
    ):
        raise ValueError("production effective configuration hash must be lowercase SHA-256")
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
            "output_capability_sha256": results[model_id].output_capability_sha256,
            "structured_output_mode": results[model_id].structured_output_mode.value,
            "approved_roles": list(results[model_id].approved_roles),
            "quality_measurement_sha256": results[model_id].quality_measurement_sha256,
            "qualification_result_sha256": results[model_id].result_sha256,
        }
        for model_id in sorted(results)
    ]
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "selection_policy": "all_eligible_tier_a",
        "qualification_artifact_sha256": artifact.artifact_sha256,
        "qualification_verification_sha256": verification.verification_sha256,
        "production_effective_config_sha256": production_effective_config_sha256,
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
    expected_production_effective_config_sha256: str,
    now: datetime,
) -> SelectionVerification:
    """Verify exact all-eligible-Tier-A set equality and freshness."""

    now = _validate_utc_second(now, label="selection verification time")
    errors: list[str] = []
    if (
        not isinstance(expected_production_effective_config_sha256, str)
        or re.fullmatch(_SHA256_PATTERN, expected_production_effective_config_sha256) is None
    ):
        raise ValueError("production effective configuration hash must be lowercase SHA-256")
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
    if selection.production_effective_config_sha256 != expected_production_effective_config_sha256:
        errors.append("production selection binds a different effective configuration")
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
            or result.output_capability_sha256 != selected.output_capability_sha256
            or result.structured_output_mode is not selected.structured_output_mode
            or result.approved_roles != selected.approved_roles
            or result.quality_measurement_sha256 != selected.quality_measurement_sha256
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
    qualification_results = {
        result.exact_model_id: result
        for result in artifact.results
        if result.exact_model_id in selected
    }
    if set(qualification_results) != set(selected):
        errors.append("selected models do not resolve to exact qualification results")
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
        qualification_result = qualification_results.get(record.requested_model)
        if (
            request_id not in duplicated_request_ids
            and selected_model is not None
            and qualification_result is not None
            and record.role != "model_benchmark"
            and is_creditable_usage_record(
                record,
                require_real=True,
                require_certification=True,
            )
            and _usage_role_is_approved(record, selected_model.approved_roles)
            and _usage_matches_certified_selection(
                record=record,
                selected_model=selected_model,
                qualification_result=qualification_result,
                artifact=artifact,
                qualification_verification=qualification_verification,
                selection=selection,
                selection_verification=selection_verification,
            )
        ):
            qualifying[request_id] = record

    exact_ids = sorted({record.requested_model for record in qualifying.values()})
    roots = sorted({selected[model_id].root_lineage for model_id in exact_ids})
    specialists = sorted(
        {
            role
            for record in qualifying.values()
            if (role := _canonical_specialist_role(record.role)) is not None
        }
    )
    whole_protocol_roots = sorted(
        {
            selected[record.requested_model].root_lineage
            for record in qualifying.values()
            if source_backed_whole_protocol_context(record) is not None
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


def _usage_role_is_approved(
    record: UsageRecord,
    approved_roles: tuple[str, ...],
) -> bool:
    role = record.role
    try:
        resolution = resolve_reasoning_request_role(role)
    except ReasoningPolicyError:
        return False
    if resolution.mapping_kind == "whole_protocol_indexed":
        return (
            source_backed_whole_protocol_context(record) is not None
            and resolution.qualification_role in approved_roles
        )
    return resolution.qualification_role in approved_roles


def _usage_matches_certified_selection(
    *,
    record: UsageRecord,
    selected_model: SelectedProductionModel,
    qualification_result: ModelQualificationResult,
    artifact: ModelQualificationArtifact,
    qualification_verification: QualificationVerification,
    selection: ProductionModelSelection,
    selection_verification: SelectionVerification,
) -> bool:
    """Require every runtime request to join the exact sealed qualification chain."""

    routing = record.routing
    return (
        qualification_result.expires_at is not None
        and record.returned_model
        in {
            selected_model.exact_model_id,
            selected_model.canonical_model_slug,
        }
        and record.actual_model
        in {
            selected_model.exact_model_id,
            selected_model.canonical_model_slug,
        }
        and record.actual_provider_endpoint == selected_model.approved_provider_endpoint
        and routing.get("selected_model") == record.actual_model
        and routing.get("canonical_model") == selected_model.canonical_model_slug
        and routing.get("selected_provider_endpoint") == selected_model.approved_provider_endpoint
        and routing.get("selected_provider_name") == selected_model.approved_provider_name
        and routing.get("output_capability_sha256") == selected_model.output_capability_sha256
        and isinstance(routing.get("structured_output"), dict)
        and routing["structured_output"].get("requested_mode")
        == selected_model.structured_output_mode.value
        and qualification_result.structured_output_mode is selected_model.structured_output_mode
        and routing.get("endpoint_snapshot_sha256") == qualification_result.endpoint_snapshot_sha256
        and routing.get("endpoint_pricing_sha256") == qualification_result.pricing_snapshot_sha256
        and routing.get("model_metadata_snapshot_sha256")
        == qualification_result.model_metadata_snapshot_sha256
        and routing.get("qualified_exact_model_id") == selected_model.exact_model_id
        and routing.get("qualified_canonical_model_slug") == selected_model.canonical_model_slug
        and routing.get("qualified_root_lineage") == selected_model.root_lineage
        and routing.get("qualified_provider_endpoint") == selected_model.approved_provider_endpoint
        and routing.get("qualified_provider_name") == selected_model.approved_provider_name
        and routing.get("qualified_endpoint_snapshot_sha256")
        == qualification_result.endpoint_snapshot_sha256
        and routing.get("qualified_model_metadata_snapshot_sha256")
        == qualification_result.model_metadata_snapshot_sha256
        and routing.get("qualified_pricing_snapshot_sha256")
        == qualification_result.pricing_snapshot_sha256
        and routing.get("qualified_roles") == list(selected_model.approved_roles)
        and routing.get("qualification_verified_at")
        == qualification_verification.verified_at.isoformat()
        and routing.get("qualification_expires_at") == qualification_result.expires_at.isoformat()
        and routing.get("qualification_artifact_sha256") == artifact.artifact_sha256
        and routing.get("qualification_verification_sha256")
        == qualification_verification.verification_sha256
        and routing.get("production_effective_config_sha256")
        == selection.production_effective_config_sha256
        and routing.get("production_selection_sha256") == selection.selection_sha256
        and routing.get("selection_verification_sha256")
        == selection_verification.verification_sha256
        and routing.get("qualification_result_sha256") == qualification_result.result_sha256
    )


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
