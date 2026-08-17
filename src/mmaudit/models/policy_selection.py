"""Audit-scoped join between technical qualification and policy eligibility.

Durable records in this module are evidence only. Runtime model use requires the
separately issued :class:`VerifiedAuditModelSelection` process-local capability.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import weakref
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Any, Literal, Never, Self, SupportsIndex

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator

from mmaudit.models.identifiers import require_exact_openrouter_model_id
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.policy_eligibility import (
    ClientPolicyConstraints,
    ModelPolicyEligibilityArtifact,
    PolicyAuditContext,
    PolicyEligibilityEvaluation,
    PolicyEligibilityExclusion,
    PolicyEligibilityRoute,
    PolicyUsePurpose,
    build_policy_eligibility_route,
    evaluate_model_policy_eligibility,
    policy_eligibility_candidate_routes_sha256,
)
from mmaudit.models.policy_eligibility_authority import (
    ModelPolicyEligibilityAuthorityEvidenceProjection,
    ModelPolicyEligibilityAuthorityVerificationReceipt,
    PolicyEligibilitySourceObservation,
    TrustedModelPolicyEligibilitySelectionVerification,
    validate_policy_eligibility_source_observation,
    verify_model_policy_eligibility_authority_evidence,
)
from mmaudit.models.qualification import (
    QualificationDisposition,
    QualifiedReasoningRoleBinding,
    VerifiedProductionQualification,
    VerifiedTierAModelQualification,
)
from mmaudit.models.reasoning import (
    ReasoningPolicyError,
    reasoning_policy_roles_for_qualified_role,
)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_LINEAGE_PATTERN = r"^sha256:[0-9a-f]{64}$"
_ENDPOINT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$"
_PROVIDER_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9 ._:/()&+-]{0,199}$"
_ROLE_PATTERN = r"^[a-z][a-z0-9_:.-]{0,127}$"
_MIN_EXACT_MODELS = 8
_MIN_ROOT_LINEAGES = 6
_MAX_MODELS = 128
_JSON_ADAPTER = TypeAdapter(Any)
AUDIT_MODEL_SELECTION_EVIDENCE_FILENAME = "audit-model-selection-evidence.json"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


class AuditSelectedTechnicalModel(_FrozenModel):
    """Exact durable projection of one policy-eligible Tier-A technical model."""

    schema_version: Literal["1.0"] = "1.0"
    exact_model_id: str
    canonical_model_slug: str
    root_lineage: str = Field(pattern=_LINEAGE_PATTERN)
    approved_provider_endpoint: str = Field(pattern=_ENDPOINT_PATTERN)
    approved_provider_name: str = Field(pattern=_PROVIDER_NAME_PATTERN)
    endpoint_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    output_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    model_metadata_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    pricing_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    structured_output_mode: StructuredOutputMode
    approved_roles: tuple[str, ...] = Field(min_length=1, max_length=128)
    qualification_disposition: Literal[QualificationDisposition.TIER_A] = (
        QualificationDisposition.TIER_A
    )
    overall_score: float = Field(ge=0, le=1)
    quality_measurement_sha256: str = Field(pattern=_SHA256_PATTERN)
    qualification_result_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_report_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_verification_sha256: str = Field(pattern=_SHA256_PATTERN)
    fresh_benchmark_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    reasoning_bindings: tuple[QualifiedReasoningRoleBinding, ...] = Field(
        min_length=1,
        max_length=1_024,
    )
    evaluated_at: datetime
    expires_at: datetime
    benchmark_case_count: int = Field(ge=1)
    policy_route_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_qualification_status: Literal["VERIFIED_TIER_A"] = "VERIFIED_TIER_A"
    policy_eligibility_status: Literal["ELIGIBLE"] = "ELIGIBLE"
    selected_model_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id", "canonical_model_slug")
    @classmethod
    def model_ids_are_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @field_validator("approved_roles")
    @classmethod
    def roles_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            re.fullmatch(_ROLE_PATTERN, role) is None for role in value
        ):
            raise ValueError("audit-selected technical roles must be exact, unique, and sorted")
        return value

    @field_validator("evaluated_at", "expires_at")
    @classmethod
    def times_are_whole_second_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="audit-selected technical model time")

    @model_validator(mode="after")
    def evidence_is_exact_and_self_hashed(self) -> Self:
        route = build_policy_eligibility_route(
            exact_model_id=self.exact_model_id,
            provider_name=self.approved_provider_name,
            provider_endpoint=self.approved_provider_endpoint,
        )
        if route.route_sha256 != self.policy_route_sha256:
            raise ValueError("audit-selected model policy route is inconsistent")
        if self.expires_at <= self.evaluated_at:
            raise ValueError("audit-selected technical model expiry must follow evaluation")
        try:
            expected_reasoning_routes = tuple(
                sorted(
                    (qualified_role, configured_role)
                    for qualified_role in self.approved_roles
                    for configured_role in reasoning_policy_roles_for_qualified_role(qualified_role)
                )
            )
        except ReasoningPolicyError as exc:
            raise ValueError("audit-selected model contains an unknown qualified role") from exc
        observed_reasoning_routes = tuple(
            (binding.qualified_role, binding.configured_policy_role)
            for binding in self.reasoning_bindings
        )
        if observed_reasoning_routes != expected_reasoning_routes or any(
            binding.exact_model_id != self.exact_model_id
            or binding.approved_provider_endpoint != self.approved_provider_endpoint
            or binding.approved_provider_name != self.approved_provider_name
            or binding.qualification_report_sha256 != self.benchmark_report_sha256
            or binding.qualification_result_sha256 != self.qualification_result_sha256
            for binding in self.reasoning_bindings
        ):
            raise ValueError("audit-selected model reasoning evidence differs from qualification")
        _require_self_hash(self, "selected_model_sha256", label="audit-selected model")
        return self


class AuditModelSelection(_FrozenModel):
    """Self-hashed audit record; possession of this record grants no authority."""

    schema_version: Literal["1.0"] = "1.0"
    selection_policy: Literal["verified_technical_and_policy_eligible"] = (
        "verified_technical_and_policy_eligible"
    )
    audit_scope_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_context_sha256: str = Field(pattern=_SHA256_PATTERN)
    client_constraints_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_qualification_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_qualification_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_qualification_verification_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_production_selection_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_selection_verification_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_production_effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_qualification_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_release_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_evaluation_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_source_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_source_commitment_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_authority_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_authority_statement_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_authority_envelope_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_authority_trust_anchor_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_authority_initial_source_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    eligible_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_model_ids: tuple[str, ...] = Field(
        min_length=_MIN_EXACT_MODELS, max_length=_MAX_MODELS
    )
    selected_model_ids: tuple[str, ...] = Field(
        min_length=_MIN_EXACT_MODELS, max_length=_MAX_MODELS
    )
    policy_excluded_model_ids: tuple[str, ...] = Field(max_length=_MAX_MODELS)
    models: tuple[AuditSelectedTechnicalModel, ...] = Field(
        min_length=_MIN_EXACT_MODELS,
        max_length=_MAX_MODELS,
    )
    policy_exclusions: tuple[PolicyEligibilityExclusion, ...] = Field(max_length=_MAX_MODELS)
    policy_exclusion_sha256s: tuple[str, ...] = Field(max_length=_MAX_MODELS)
    selected_model_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_exclusion_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_qualification_verified_at: datetime
    policy_evaluated_at: datetime
    policy_source_observed_at: datetime
    policy_authority_verified_at: datetime
    selected_at: datetime
    technical_qualification_expires_at: datetime
    policy_evaluation_expires_at: datetime
    policy_source_observation_expires_at: datetime
    policy_authority_expires_at: datetime
    expires_at: datetime
    technical_qualification_authorized: Literal[False] = False
    policy_selection_authorized: Literal[False] = False
    source_egress_authorized: Literal[False] = False
    general_production_authorized: Literal[False] = False
    selection_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "technical_model_ids",
        "selected_model_ids",
        "policy_excluded_model_ids",
    )
    @classmethod
    def model_ids_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        validated = tuple(require_exact_openrouter_model_id(item) for item in value)
        if validated != tuple(sorted(set(validated))):
            raise ValueError("audit selection model IDs must be exact, unique, and sorted")
        return validated

    @field_validator(
        "technical_qualification_verified_at",
        "policy_evaluated_at",
        "policy_source_observed_at",
        "policy_authority_verified_at",
        "selected_at",
        "technical_qualification_expires_at",
        "policy_evaluation_expires_at",
        "policy_source_observation_expires_at",
        "policy_authority_expires_at",
        "expires_at",
    )
    @classmethod
    def times_are_whole_second_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="audit selection time")

    @field_validator(
        "technical_qualification_authorized",
        "policy_selection_authorized",
        "source_egress_authorized",
        "general_production_authorized",
        mode="before",
    )
    @classmethod
    def authority_flags_are_literal_bool(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("durable audit-selection authority flags must be literal booleans")
        return value

    @model_validator(mode="after")
    def selection_is_exact_non_authorizing_and_self_hashed(self) -> Self:
        selected_ids = tuple(model.exact_model_id for model in self.models)
        if (
            selected_ids != tuple(sorted(set(selected_ids)))
            or selected_ids != self.selected_model_ids
        ):
            raise ValueError("audit-selected models must exactly match sorted selected IDs")
        if len({model.root_lineage for model in self.models}) < _MIN_ROOT_LINEAGES:
            raise ValueError("audit selection requires at least six independent root lineages")
        expected_model_set = _canonical_json_sha256(
            [model.model_dump(mode="json") for model in self.models]
        )
        if self.selected_model_set_sha256 != expected_model_set:
            raise ValueError("audit selected-model set hash is inconsistent")

        exclusion_identities = tuple(item.route.identity for item in self.policy_exclusions)
        if exclusion_identities != tuple(sorted(set(exclusion_identities))):
            raise ValueError("audit policy exclusions must be exact, unique, and sorted")
        excluded_ids = tuple(sorted(item.route.exact_model_id for item in self.policy_exclusions))
        if excluded_ids != self.policy_excluded_model_ids:
            raise ValueError("audit policy-excluded IDs differ from exclusions")
        exclusion_hashes = tuple(item.exclusion_sha256 for item in self.policy_exclusions)
        if exclusion_hashes != self.policy_exclusion_sha256s:
            raise ValueError("audit policy-exclusion hashes differ from exclusions")
        expected_exclusion_set = _canonical_json_sha256(
            [item.model_dump(mode="json") for item in self.policy_exclusions]
        )
        if self.policy_exclusion_set_sha256 != expected_exclusion_set:
            raise ValueError("audit policy-exclusion set hash is inconsistent")
        if set(self.selected_model_ids) & set(self.policy_excluded_model_ids):
            raise ValueError("a technical model cannot be both policy-selected and excluded")
        if tuple(sorted((*self.selected_model_ids, *self.policy_excluded_model_ids))) != (
            self.technical_model_ids
        ):
            raise ValueError("audit selection must policy-classify every technical model once")

        eligible_routes = tuple(_route_from_selected_model(model) for model in self.models)
        technical_routes = tuple(
            sorted(
                (*eligible_routes, *(item.route for item in self.policy_exclusions)),
                key=lambda item: item.identity,
            )
        )
        if self.eligible_route_set_sha256 != policy_eligibility_candidate_routes_sha256(
            eligible_routes
        ):
            raise ValueError("audit eligible route-set hash is inconsistent")
        if self.technical_route_set_sha256 != policy_eligibility_candidate_routes_sha256(
            technical_routes
        ):
            raise ValueError("audit technical route-set hash is inconsistent")

        evidence_times = (
            self.technical_qualification_verified_at,
            self.policy_evaluated_at,
            self.policy_source_observed_at,
            self.policy_authority_verified_at,
        )
        component_expiries = (
            self.technical_qualification_expires_at,
            self.policy_evaluation_expires_at,
            self.policy_source_observation_expires_at,
            self.policy_authority_expires_at,
        )
        if any(value > self.selected_at for value in evidence_times):
            raise ValueError("audit selection predates required authority evidence")
        if any(value <= self.selected_at for value in component_expiries):
            raise ValueError("audit selection uses expired authority evidence")
        if self.expires_at != min(component_expiries):
            raise ValueError("audit selection expiry differs from earliest authority expiry")
        if any(model.expires_at < self.technical_qualification_expires_at for model in self.models):
            raise ValueError("audit-selected model expires before technical authority")
        _require_self_hash(self, "selection_sha256", label="audit model selection")
        return self


class AuditModelSelectionEvidenceBundle(_FrozenModel):
    """Policy-complete selection evidence with externally pinned technical pointers.

    The bundle does not embed or replay technical qualification or release authority.
    Its technical hashes are meaningful only when an independent authenticated authority
    supplies the expected values to the detached verifier.
    """

    schema_version: Literal["1.0"] = "1.0"
    technical_evidence_mode: Literal["EXTERNAL_AUTHORITY_HASH_JOIN_REQUIRED"] = (
        "EXTERNAL_AUTHORITY_HASH_JOIN_REQUIRED"
    )
    selection: AuditModelSelection
    policy_artifact: ModelPolicyEligibilityArtifact
    policy_evaluation: PolicyEligibilityEvaluation
    audit_context: PolicyAuditContext
    client_constraints: ClientPolicyConstraints
    current_source_observation: PolicyEligibilitySourceObservation
    policy_authority_evidence: ModelPolicyEligibilityAuthorityEvidenceProjection
    technical_qualification_authorized: Literal[False] = False
    policy_selection_authorized: Literal[False] = False
    source_egress_authorized: Literal[False] = False
    general_production_authorized: Literal[False] = False
    bundle_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "technical_qualification_authorized",
        "policy_selection_authorized",
        "source_egress_authorized",
        "general_production_authorized",
        mode="before",
    )
    @classmethod
    def authority_flags_are_literal_bool(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("audit-selection evidence authority flags must be literal booleans")
        return value

    @model_validator(mode="after")
    def evidence_is_exact_non_authorizing_and_self_hashed(self) -> Self:
        selection = self.selection
        evaluation = self.policy_evaluation
        context = self.audit_context
        constraints = self.client_constraints
        current_source = self.current_source_observation
        authority = self.policy_authority_evidence
        statement = authority.authority_statement
        receipt = authority.verification_receipt

        eligible_routes = tuple(_route_from_selected_model(model) for model in selection.models)
        technical_routes = tuple(
            sorted(
                (*eligible_routes, *(item.route for item in selection.policy_exclusions)),
                key=lambda item: item.identity,
            )
        )
        replayed_evaluation = evaluate_model_policy_eligibility(
            artifact=self.policy_artifact,
            client_constraints=constraints,
            audit_context=context,
            technical_routes=technical_routes,
            observed_at=evaluation.evaluated_at,
        )
        validated_current_source = validate_policy_eligibility_source_observation(
            artifact=self.policy_artifact,
            evaluation=evaluation,
            source_observation=current_source,
            used_at=selection.selected_at,
        )
        candidate_route_sha256s = tuple(sorted(route.route_sha256 for route in technical_routes))
        eligible_route_sha256s = tuple(sorted(route.route_sha256 for route in eligible_routes))
        evaluation_expiry = evaluation.expires_at
        if evaluation_expiry is None:
            raise ValueError("audit-selection evidence requires an eligible policy expiry")

        if (
            constraints.audit_context != context
            or context.intended_use
            is not PolicyUsePurpose.PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT
            or replayed_evaluation != evaluation
            or validated_current_source != current_source
            or current_source != authority.initial_source_observation
            or selection.audit_scope_sha256 != context.audit_scope_sha256
            or selection.source_sha256 != context.source_sha256
            or selection.audit_context_sha256 != context.context_sha256
            or selection.client_constraints_sha256 != constraints.constraints_sha256
            or selection.policy_artifact_sha256 != self.policy_artifact.artifact_sha256
            or selection.policy_evaluation_sha256 != evaluation.evaluation_sha256
            or selection.policy_source_observation_sha256 != current_source.observation_sha256
            or selection.policy_source_commitment_set_sha256
            != current_source.source_commitment_set_sha256
            or selection.policy_authority_receipt_sha256 != receipt.receipt_sha256
            or selection.policy_authority_statement_sha256 != statement.statement_sha256
            or selection.policy_authority_envelope_sha256
            != authority.authority_envelope.authority_envelope_sha256
            or selection.policy_authority_trust_anchor_sha256
            != authority.trust_anchor.trust_anchor_sha256
            or selection.policy_authority_initial_source_observation_sha256
            != authority.initial_source_observation.observation_sha256
            or selection.technical_route_set_sha256 != evaluation.technical_route_set_sha256
            or selection.eligible_route_set_sha256 != evaluation.eligible_route_set_sha256
            or selection.selected_model_ids != evaluation.eligible_model_ids
            or selection.policy_exclusions != evaluation.exclusions
            or evaluation.technical_routes != technical_routes
            or evaluation.eligible_routes != eligible_routes
            or selection.policy_evaluated_at != evaluation.evaluated_at
            or selection.policy_source_observed_at != current_source.observed_at
            or selection.policy_authority_verified_at != receipt.verified_at
            or selection.policy_evaluation_expires_at != evaluation_expiry
            or selection.policy_source_observation_expires_at != current_source.expires_at
            or selection.policy_authority_expires_at != receipt.expires_at
            or statement.artifact_sha256 != self.policy_artifact.artifact_sha256
            or statement.evaluation_sha256 != evaluation.evaluation_sha256
            or statement.audit_context_sha256 != context.context_sha256
            or statement.client_constraints_sha256 != constraints.constraints_sha256
            or statement.technical_route_set_sha256 != evaluation.technical_route_set_sha256
            or statement.eligible_route_set_sha256 != evaluation.eligible_route_set_sha256
            or statement.candidate_route_sha256s != candidate_route_sha256s
            or statement.eligible_route_sha256s != eligible_route_sha256s
            or statement.eligible_model_ids != evaluation.eligible_model_ids
        ):
            raise ValueError("audit-selection evidence has inconsistent exact joins")
        _require_self_hash(self, "bundle_sha256", label="audit model selection evidence")
        return self


class AuditModelRoutingEvidence(_FrozenModel):
    """Exact request-boundary projection; still not runtime authority by itself."""

    schema_version: Literal["1.0"] = "1.0"
    audit_model_selection_bundle_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_selection_sha256: str = Field(pattern=_SHA256_PATTERN)
    selected_model_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_scope_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_context_sha256: str = Field(pattern=_SHA256_PATTERN)
    client_constraints_sha256: str = Field(pattern=_SHA256_PATTERN)
    intended_use: Literal[PolicyUsePurpose.PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT]
    technical_production_selection_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_qualification_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_evaluation_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_authority_receipt_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_authority_statement_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_authority_envelope_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_authority_trust_anchor_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_source_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_source_commitment_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    route: PolicyEligibilityRoute
    selected_model_sha256: str = Field(pattern=_SHA256_PATTERN)
    expires_at: datetime
    runtime_authorized: Literal[False] = False
    routing_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("expires_at")
    @classmethod
    def expiry_is_whole_second_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="audit routing-evidence expiry")

    @field_validator("runtime_authorized", mode="before")
    @classmethod
    def runtime_flag_is_literal_bool(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("audit routing-evidence authority flag must be a literal boolean")
        return value

    @model_validator(mode="after")
    def routing_evidence_is_self_hashed(self) -> Self:
        _require_self_hash(self, "routing_evidence_sha256", label="audit routing evidence")
        return self

    def request_metadata(self) -> Mapping[str, str]:
        """Return immutable scalar joins suitable for request/usage evidence."""

        return MappingProxyType(
            {
                "audit_model_selection_bundle_sha256": (self.audit_model_selection_bundle_sha256),
                "audit_selection_sha256": self.audit_selection_sha256,
                "selected_model_set_sha256": self.selected_model_set_sha256,
                "audit_scope_sha256": self.audit_scope_sha256,
                "source_sha256": self.source_sha256,
                "audit_context_sha256": self.audit_context_sha256,
                "client_constraints_sha256": self.client_constraints_sha256,
                "intended_use": self.intended_use.value,
                "technical_production_selection_sha256": (
                    self.technical_production_selection_sha256
                ),
                "technical_qualification_capability_sha256": (
                    self.technical_qualification_capability_sha256
                ),
                "policy_artifact_sha256": self.policy_artifact_sha256,
                "policy_evaluation_sha256": self.policy_evaluation_sha256,
                "policy_authority_receipt_sha256": self.policy_authority_receipt_sha256,
                "policy_authority_statement_sha256": self.policy_authority_statement_sha256,
                "policy_authority_envelope_sha256": self.policy_authority_envelope_sha256,
                "policy_authority_trust_anchor_sha256": (self.policy_authority_trust_anchor_sha256),
                "policy_source_observation_sha256": self.policy_source_observation_sha256,
                "policy_source_commitment_set_sha256": (self.policy_source_commitment_set_sha256),
                "exact_model_id": self.route.exact_model_id,
                "provider_name": self.route.provider_name,
                "provider_endpoint": self.route.provider_endpoint,
                "policy_route_sha256": self.route.route_sha256,
                "selected_model_sha256": self.selected_model_sha256,
                "selection_expires_at": self.expires_at.isoformat().replace("+00:00", "Z"),
                "routing_evidence_sha256": self.routing_evidence_sha256,
            }
        )


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class VerifiedAuditModelSelection:
    """Opaque live capability exposing only policy-eligible technical models."""

    selected_at: datetime
    expires_at: datetime
    audit_scope_sha256: str
    source_sha256: str
    audit_context_sha256: str
    audit_selection_sha256: str
    technical_qualification_capability_sha256: str
    technical_production_selection_sha256: str
    policy_artifact_sha256: str
    policy_evaluation_sha256: str
    policy_authority_receipt_sha256: str
    policy_source_observation_sha256: str
    models: tuple[VerifiedTierAModelQualification, ...]
    capability_sha256: str

    def __new__(cls, *_args: object, **_kwargs: object) -> Self:
        del cls, _args, _kwargs
        raise TypeError("verified audit model selection can only be issued by the resolver")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def __copy__(self) -> Never:
        raise TypeError("verified audit model selection cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("verified audit model selection cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("verified audit model selection cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("verified audit model selection cannot be serialized")

    def require_current(
        self,
        *,
        now: datetime,
        expected_audit_scope_sha256: str,
        expected_source_sha256: str,
        expected_audit_context_sha256: str,
        expected_client_constraints_sha256: str,
    ) -> Self:
        """Recheck both live authorities and their source observation before use."""

        _require_verified_audit_selection(
            self,
            now=now,
            expected_audit_scope_sha256=expected_audit_scope_sha256,
            expected_source_sha256=expected_source_sha256,
            expected_audit_context_sha256=expected_audit_context_sha256,
            expected_client_constraints_sha256=expected_client_constraints_sha256,
        )
        return self

    def model_for(
        self,
        exact_model_id: str,
        *,
        now: datetime,
        expected_audit_scope_sha256: str,
        expected_source_sha256: str,
        expected_audit_context_sha256: str,
        expected_client_constraints_sha256: str,
    ) -> VerifiedTierAModelQualification:
        """Resolve one exact policy-eligible technical model."""

        self.require_current(
            now=now,
            expected_audit_scope_sha256=expected_audit_scope_sha256,
            expected_source_sha256=expected_source_sha256,
            expected_audit_context_sha256=expected_audit_context_sha256,
            expected_client_constraints_sha256=expected_client_constraints_sha256,
        )
        exact_model_id = require_exact_openrouter_model_id(exact_model_id)
        matches = tuple(model for model in self.models if model.exact_model_id == exact_model_id)
        if len(matches) != 1:
            raise ValueError(f"exact model lacks verified audit selection: {exact_model_id}")
        return matches[0]

    def routing_evidence(
        self,
        exact_model_id: str,
        *,
        now: datetime,
        expected_audit_scope_sha256: str,
        expected_source_sha256: str,
        expected_audit_context_sha256: str,
        expected_client_constraints_sha256: str,
    ) -> AuditModelRoutingEvidence:
        """Recheck authority and project exact durable request-boundary evidence."""

        model = self.model_for(
            exact_model_id,
            now=now,
            expected_audit_scope_sha256=expected_audit_scope_sha256,
            expected_source_sha256=expected_source_sha256,
            expected_audit_context_sha256=expected_audit_context_sha256,
            expected_client_constraints_sha256=expected_client_constraints_sha256,
        )
        state = _issued_verified_audit_selection_state(self)
        if state is None:
            raise ValueError("verified audit model selection is absent or forged")
        selected = next(
            item for item in state.selection.models if item.exact_model_id == model.exact_model_id
        )
        route = _route_from_selected_model(selected)
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "audit_model_selection_bundle_sha256": state.evidence_bundle.bundle_sha256,
            "audit_selection_sha256": state.selection.selection_sha256,
            "selected_model_set_sha256": state.selection.selected_model_set_sha256,
            "audit_scope_sha256": state.selection.audit_scope_sha256,
            "source_sha256": state.selection.source_sha256,
            "audit_context_sha256": state.selection.audit_context_sha256,
            "client_constraints_sha256": state.selection.client_constraints_sha256,
            "intended_use": PolicyUsePurpose.PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT,
            "technical_production_selection_sha256": (
                state.selection.technical_production_selection_sha256
            ),
            "technical_qualification_capability_sha256": (
                state.selection.technical_qualification_capability_sha256
            ),
            "policy_artifact_sha256": state.selection.policy_artifact_sha256,
            "policy_evaluation_sha256": state.selection.policy_evaluation_sha256,
            "policy_authority_receipt_sha256": (state.selection.policy_authority_receipt_sha256),
            "policy_authority_statement_sha256": (
                state.selection.policy_authority_statement_sha256
            ),
            "policy_authority_envelope_sha256": (state.selection.policy_authority_envelope_sha256),
            "policy_authority_trust_anchor_sha256": (
                state.selection.policy_authority_trust_anchor_sha256
            ),
            "policy_source_observation_sha256": (state.selection.policy_source_observation_sha256),
            "policy_source_commitment_set_sha256": (
                state.selection.policy_source_commitment_set_sha256
            ),
            "route": route,
            "selected_model_sha256": selected.selected_model_sha256,
            "expires_at": state.selection.expires_at,
            "runtime_authorized": False,
        }
        values["routing_evidence_sha256"] = _canonical_json_sha256(values)
        return AuditModelRoutingEvidence.model_validate(values)

    def request_metadata(
        self,
        exact_model_id: str,
        *,
        now: datetime,
        expected_audit_scope_sha256: str,
        expected_source_sha256: str,
        expected_audit_context_sha256: str,
        expected_client_constraints_sha256: str,
    ) -> Mapping[str, str]:
        """Recheck authority and return exact immutable request joins."""

        return self.routing_evidence(
            exact_model_id,
            now=now,
            expected_audit_scope_sha256=expected_audit_scope_sha256,
            expected_source_sha256=expected_source_sha256,
            expected_audit_context_sha256=expected_audit_context_sha256,
            expected_client_constraints_sha256=expected_client_constraints_sha256,
        ).request_metadata()


@dataclass(frozen=True, slots=True)
class _IssuedAuditSelectionState:
    capability_sha256: str
    model_identities: tuple[int, ...]
    selection: AuditModelSelection
    evidence_bundle: AuditModelSelectionEvidenceBundle
    technical_qualification: VerifiedProductionQualification
    policy_artifact: ModelPolicyEligibilityArtifact
    policy_evaluation: PolicyEligibilityEvaluation
    audit_context: PolicyAuditContext
    client_constraints: ClientPolicyConstraints
    candidate_routes: tuple[PolicyEligibilityRoute, ...]
    source_observation: PolicyEligibilitySourceObservation
    policy_verification: TrustedModelPolicyEligibilitySelectionVerification


def _build_verified_audit_selection_authority() -> tuple[
    Callable[[VerifiedAuditModelSelection, _IssuedAuditSelectionState], None],
    Callable[[VerifiedAuditModelSelection], _IssuedAuditSelectionState | None],
]:
    registry: dict[
        int,
        tuple[weakref.ReferenceType[VerifiedAuditModelSelection], _IssuedAuditSelectionState],
    ] = {}
    lock = threading.RLock()

    def register(
        capability: VerifiedAuditModelSelection,
        state: _IssuedAuditSelectionState,
    ) -> None:
        if type(capability) is not VerifiedAuditModelSelection:
            raise ValueError("cannot register an invalid audit-selection capability")
        key = id(capability)

        def discard(reference: weakref.ReferenceType[VerifiedAuditModelSelection]) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = weakref.ref(capability, discard)
        with lock:
            registry[key] = (reference, state)

    def issued_state(
        capability: VerifiedAuditModelSelection,
    ) -> _IssuedAuditSelectionState | None:
        with lock:
            registered = registry.get(id(capability))
        return registered[1] if registered is not None and registered[0]() is capability else None

    return register, issued_state


_register_verified_audit_selection, _issued_verified_audit_selection_state = (
    _build_verified_audit_selection_authority()
)
del _build_verified_audit_selection_authority


def resolve_verified_audit_model_selection(
    *,
    technical_qualification: VerifiedProductionQualification,
    policy_artifact: ModelPolicyEligibilityArtifact,
    policy_evaluation: PolicyEligibilityEvaluation,
    audit_context: PolicyAuditContext,
    client_constraints: ClientPolicyConstraints,
    source_observation: PolicyEligibilitySourceObservation,
    trusted_policy_verification: TrustedModelPolicyEligibilitySelectionVerification,
    selected_at: datetime,
) -> tuple[
    AuditModelSelection,
    AuditModelSelectionEvidenceBundle,
    VerifiedAuditModelSelection,
]:
    """Join exact technical and policy authority for one paid client audit."""

    selected_at = _whole_second_utc(selected_at, label="audit model selection time")
    if type(technical_qualification) is not VerifiedProductionQualification:
        raise ValueError("verified production qualification is absent or forged")
    if type(trusted_policy_verification) is not TrustedModelPolicyEligibilitySelectionVerification:
        raise ValueError("trusted policy-selection verification is absent or forged")
    policy_artifact = _strict_copy(ModelPolicyEligibilityArtifact, policy_artifact)
    policy_evaluation = _strict_copy(PolicyEligibilityEvaluation, policy_evaluation)
    audit_context = _strict_copy(PolicyAuditContext, audit_context)
    client_constraints = _strict_copy(ClientPolicyConstraints, client_constraints)
    source_observation = _strict_copy(PolicyEligibilitySourceObservation, source_observation)
    if (
        audit_context.intended_use
        is not PolicyUsePurpose.PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT
    ):
        raise ValueError("production audit selection requires paid customer-facing intended use")

    technical_qualification.require_current(now=selected_at)
    candidate_routes = _policy_routes_from_technical_models(technical_qualification.models)
    if candidate_routes != policy_evaluation.technical_routes:
        raise ValueError("policy evaluation technical routes differ from technical qualification")
    receipt = trusted_policy_verification.require_for_policy_selection(
        artifact=policy_artifact,
        evaluation=policy_evaluation,
        audit_context=audit_context,
        client_constraints=client_constraints,
        candidate_routes=candidate_routes,
        source_observation=source_observation,
        observed_at=selected_at,
    )
    receipt = _strict_copy(ModelPolicyEligibilityAuthorityVerificationReceipt, receipt)
    policy_authority_evidence = trusted_policy_verification.evidence_projection()
    if policy_authority_evidence.verification_receipt != receipt:
        raise ValueError("policy authority projection differs from live verification receipt")

    technical_by_id = {model.exact_model_id: model for model in technical_qualification.models}
    eligible_ids = policy_evaluation.eligible_model_ids
    selected_models = tuple(technical_by_id[item] for item in eligible_ids)
    if len(selected_models) < _MIN_EXACT_MODELS:
        raise ValueError("audit selection requires at least eight policy-eligible exact models")
    if len({model.root_lineage for model in selected_models}) < _MIN_ROOT_LINEAGES:
        raise ValueError("audit selection requires at least six policy-eligible root lineages")
    eligible_routes = {route.exact_model_id: route for route in policy_evaluation.eligible_routes}
    if set(eligible_routes) != set(eligible_ids):
        raise ValueError("policy-eligible routes do not resolve to exact technical models")
    selected_records = tuple(
        _build_selected_model_record(model, eligible_routes[model.exact_model_id])
        for model in selected_models
    )
    evaluation_expiry = policy_evaluation.expires_at
    if evaluation_expiry is None:
        raise ValueError("policy evaluation without eligible expiry cannot authorize selection")
    expires_at = min(
        technical_qualification.expires_at,
        evaluation_expiry,
        source_observation.expires_at,
        receipt.expires_at,
    )
    exclusions = policy_evaluation.exclusions
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "selection_policy": "verified_technical_and_policy_eligible",
        "audit_scope_sha256": audit_context.audit_scope_sha256,
        "source_sha256": audit_context.source_sha256,
        "audit_context_sha256": audit_context.context_sha256,
        "client_constraints_sha256": client_constraints.constraints_sha256,
        "technical_qualification_capability_sha256": technical_qualification.capability_sha256,
        "technical_qualification_artifact_sha256": technical_qualification.artifact_sha256,
        "technical_qualification_verification_sha256": (
            technical_qualification.qualification_verification_sha256
        ),
        "technical_production_selection_sha256": (
            technical_qualification.production_selection_sha256
        ),
        "technical_selection_verification_sha256": (
            technical_qualification.selection_verification_sha256
        ),
        "technical_production_effective_config_sha256": (
            technical_qualification.production_effective_config_sha256
        ),
        "technical_candidate_registry_sha256": technical_qualification.candidate_registry_sha256,
        "technical_qualification_policy_sha256": technical_qualification.policy_sha256,
        "technical_release_observation_sha256": (
            technical_qualification.release_observation_sha256
        ),
        "policy_artifact_sha256": policy_artifact.artifact_sha256,
        "policy_evaluation_sha256": policy_evaluation.evaluation_sha256,
        "policy_source_observation_sha256": source_observation.observation_sha256,
        "policy_source_commitment_set_sha256": (source_observation.source_commitment_set_sha256),
        "policy_authority_receipt_sha256": receipt.receipt_sha256,
        "policy_authority_statement_sha256": receipt.statement_sha256,
        "policy_authority_envelope_sha256": receipt.authority_envelope_sha256,
        "policy_authority_trust_anchor_sha256": receipt.trust_anchor_sha256,
        "policy_authority_initial_source_observation_sha256": (
            receipt.initial_source_observation_sha256
        ),
        "technical_route_set_sha256": policy_evaluation.technical_route_set_sha256,
        "eligible_route_set_sha256": policy_evaluation.eligible_route_set_sha256,
        "technical_model_ids": tuple(sorted(technical_by_id)),
        "selected_model_ids": eligible_ids,
        "policy_excluded_model_ids": tuple(
            sorted(item.route.exact_model_id for item in exclusions)
        ),
        "models": selected_records,
        "policy_exclusions": exclusions,
        "policy_exclusion_sha256s": tuple(item.exclusion_sha256 for item in exclusions),
        "selected_model_set_sha256": _canonical_json_sha256(
            [item.model_dump(mode="json") for item in selected_records]
        ),
        "policy_exclusion_set_sha256": _canonical_json_sha256(
            [item.model_dump(mode="json") for item in exclusions]
        ),
        "technical_qualification_verified_at": technical_qualification.verified_at,
        "policy_evaluated_at": policy_evaluation.evaluated_at,
        "policy_source_observed_at": source_observation.observed_at,
        "policy_authority_verified_at": receipt.verified_at,
        "selected_at": selected_at,
        "technical_qualification_expires_at": technical_qualification.expires_at,
        "policy_evaluation_expires_at": evaluation_expiry,
        "policy_source_observation_expires_at": source_observation.expires_at,
        "policy_authority_expires_at": receipt.expires_at,
        "expires_at": expires_at,
        "technical_qualification_authorized": False,
        "policy_selection_authorized": False,
        "source_egress_authorized": False,
        "general_production_authorized": False,
    }
    values["selection_sha256"] = _canonical_json_sha256(values)
    selection = AuditModelSelection.model_validate(values)
    evidence_bundle = build_audit_model_selection_evidence_bundle(
        selection=selection,
        policy_artifact=policy_artifact,
        policy_evaluation=policy_evaluation,
        audit_context=audit_context,
        client_constraints=client_constraints,
        current_source_observation=source_observation,
        policy_authority_evidence=policy_authority_evidence,
    )

    capability = object.__new__(VerifiedAuditModelSelection)
    object.__setattr__(capability, "selected_at", selected_at)
    object.__setattr__(capability, "expires_at", expires_at)
    object.__setattr__(capability, "audit_scope_sha256", audit_context.audit_scope_sha256)
    object.__setattr__(capability, "source_sha256", audit_context.source_sha256)
    object.__setattr__(capability, "audit_context_sha256", audit_context.context_sha256)
    object.__setattr__(capability, "audit_selection_sha256", selection.selection_sha256)
    object.__setattr__(
        capability,
        "technical_qualification_capability_sha256",
        technical_qualification.capability_sha256,
    )
    object.__setattr__(
        capability,
        "technical_production_selection_sha256",
        technical_qualification.production_selection_sha256,
    )
    object.__setattr__(capability, "policy_artifact_sha256", policy_artifact.artifact_sha256)
    object.__setattr__(
        capability,
        "policy_evaluation_sha256",
        policy_evaluation.evaluation_sha256,
    )
    object.__setattr__(capability, "policy_authority_receipt_sha256", receipt.receipt_sha256)
    object.__setattr__(
        capability,
        "policy_source_observation_sha256",
        source_observation.observation_sha256,
    )
    object.__setattr__(capability, "models", selected_models)
    object.__setattr__(
        capability,
        "capability_sha256",
        _canonical_json_sha256(_verified_audit_selection_payload(capability)),
    )
    state = _IssuedAuditSelectionState(
        capability_sha256=capability.capability_sha256,
        model_identities=tuple(id(model) for model in selected_models),
        selection=selection,
        evidence_bundle=evidence_bundle,
        technical_qualification=technical_qualification,
        policy_artifact=policy_artifact,
        policy_evaluation=policy_evaluation,
        audit_context=audit_context,
        client_constraints=client_constraints,
        candidate_routes=candidate_routes,
        source_observation=source_observation,
        policy_verification=trusted_policy_verification,
    )
    _register_verified_audit_selection(capability, state)
    capability.require_current(
        now=selected_at,
        expected_audit_scope_sha256=audit_context.audit_scope_sha256,
        expected_source_sha256=audit_context.source_sha256,
        expected_audit_context_sha256=audit_context.context_sha256,
        expected_client_constraints_sha256=client_constraints.constraints_sha256,
    )
    return selection, evidence_bundle, capability


def build_audit_model_selection_evidence_bundle(
    *,
    selection: AuditModelSelection,
    policy_artifact: ModelPolicyEligibilityArtifact,
    policy_evaluation: PolicyEligibilityEvaluation,
    audit_context: PolicyAuditContext,
    client_constraints: ClientPolicyConstraints,
    current_source_observation: PolicyEligibilitySourceObservation,
    policy_authority_evidence: ModelPolicyEligibilityAuthorityEvidenceProjection,
) -> AuditModelSelectionEvidenceBundle:
    """Close one selection over its exact durable, non-authorizing policy evidence."""

    values: dict[str, Any] = {
        "schema_version": "1.0",
        "technical_evidence_mode": "EXTERNAL_AUTHORITY_HASH_JOIN_REQUIRED",
        "selection": selection,
        "policy_artifact": policy_artifact,
        "policy_evaluation": policy_evaluation,
        "audit_context": audit_context,
        "client_constraints": client_constraints,
        "current_source_observation": current_source_observation,
        "policy_authority_evidence": policy_authority_evidence,
        "technical_qualification_authorized": False,
        "policy_selection_authorized": False,
        "source_egress_authorized": False,
        "general_production_authorized": False,
    }
    values["bundle_sha256"] = _canonical_json_sha256(values)
    return AuditModelSelectionEvidenceBundle.model_validate(values)


def verify_audit_model_selection_evidence_bundle(
    *,
    evidence_bundle: AuditModelSelectionEvidenceBundle,
    expected_trust_anchor_sha256: str,
    expected_operator_principal: str,
    expected_audit_selection_sha256: str,
    expected_technical_qualification_artifact_sha256: str,
    expected_technical_qualification_verification_sha256: str,
    expected_technical_production_selection_sha256: str,
    expected_technical_selection_verification_sha256: str,
    expected_technical_production_effective_config_sha256: str,
    expected_technical_candidate_registry_sha256: str,
    expected_technical_qualification_policy_sha256: str,
    expected_technical_release_observation_sha256: str,
) -> AuditModelSelectionEvidenceBundle:
    """Replay policy SSHSIG and join externally authorized technical evidence hashes.

    This verifier does not replay technical qualification or release authority and issues
    no authority. Every ``expected_*`` value must come from an independently authenticated,
    non-resealable authority; deriving it from this bundle or a caller-rewritable manifest
    would only restate attacker-controlled hashes.
    """

    bundle = _strict_copy(AuditModelSelectionEvidenceBundle, evidence_bundle)
    selection = bundle.selection
    expected_technical_joins = (
        (expected_audit_selection_sha256, selection.selection_sha256),
        (
            expected_technical_qualification_artifact_sha256,
            selection.technical_qualification_artifact_sha256,
        ),
        (
            expected_technical_qualification_verification_sha256,
            selection.technical_qualification_verification_sha256,
        ),
        (
            expected_technical_production_selection_sha256,
            selection.technical_production_selection_sha256,
        ),
        (
            expected_technical_selection_verification_sha256,
            selection.technical_selection_verification_sha256,
        ),
        (
            expected_technical_production_effective_config_sha256,
            selection.technical_production_effective_config_sha256,
        ),
        (
            expected_technical_candidate_registry_sha256,
            selection.technical_candidate_registry_sha256,
        ),
        (
            expected_technical_qualification_policy_sha256,
            selection.technical_qualification_policy_sha256,
        ),
        (
            expected_technical_release_observation_sha256,
            selection.technical_release_observation_sha256,
        ),
    )
    if any(
        type(expected) is not str
        or re.fullmatch(_SHA256_PATTERN, expected) is None
        or expected != observed
        for expected, observed in expected_technical_joins
    ):
        raise ValueError("audit selection differs from independently authorized technical evidence")
    verified_authority = verify_model_policy_eligibility_authority_evidence(
        evidence=bundle.policy_authority_evidence,
        artifact=bundle.policy_artifact,
        evaluation=bundle.policy_evaluation,
        audit_context=bundle.audit_context,
        client_constraints=bundle.client_constraints,
        candidate_routes=bundle.policy_evaluation.technical_routes,
        expected_trust_anchor_sha256=expected_trust_anchor_sha256,
        expected_operator_principal=expected_operator_principal,
    )
    if verified_authority != bundle.policy_authority_evidence:
        raise ValueError("audit-selection authority replay differs from durable evidence")
    return bundle


def _require_verified_audit_selection(
    capability: VerifiedAuditModelSelection,
    *,
    now: datetime,
    expected_audit_scope_sha256: str,
    expected_source_sha256: str,
    expected_audit_context_sha256: str,
    expected_client_constraints_sha256: str,
) -> None:
    now = _whole_second_utc(now, label="verified audit selection use time")
    if type(capability) is not VerifiedAuditModelSelection:
        raise ValueError("verified audit model selection is absent or forged")
    state = _issued_verified_audit_selection_state(capability)
    if state is None:
        raise ValueError("verified audit model selection is absent or forged")
    expected_bindings = (
        expected_audit_scope_sha256,
        expected_source_sha256,
        expected_audit_context_sha256,
        expected_client_constraints_sha256,
    )
    if any(
        type(value) is not str or re.fullmatch(_SHA256_PATTERN, value) is None
        for value in expected_bindings
    ):
        raise ValueError("expected audit model selection bindings must be exact SHA-256 values")
    if (
        expected_audit_scope_sha256 != capability.audit_scope_sha256
        or expected_audit_scope_sha256 != state.selection.audit_scope_sha256
        or expected_audit_scope_sha256 != state.audit_context.audit_scope_sha256
        or expected_source_sha256 != capability.source_sha256
        or expected_source_sha256 != state.selection.source_sha256
        or expected_source_sha256 != state.audit_context.source_sha256
        or expected_audit_context_sha256 != capability.audit_context_sha256
        or expected_audit_context_sha256 != state.selection.audit_context_sha256
        or expected_audit_context_sha256 != state.audit_context.context_sha256
        or expected_client_constraints_sha256 != state.selection.client_constraints_sha256
        or expected_client_constraints_sha256 != state.client_constraints.constraints_sha256
        or state.client_constraints.audit_context != state.audit_context
        or state.audit_context.intended_use
        is not PolicyUsePurpose.PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT
    ):
        raise ValueError("verified audit model selection differs from expected audit bindings")
    if now < capability.selected_at or now >= capability.expires_at:
        raise ValueError("verified audit model selection is future-dated or expired")
    state.technical_qualification.require_current(now=now)
    receipt = state.policy_verification.require_for_policy_selection(
        artifact=state.policy_artifact,
        evaluation=state.policy_evaluation,
        audit_context=state.audit_context,
        client_constraints=state.client_constraints,
        candidate_routes=state.candidate_routes,
        source_observation=state.source_observation,
        observed_at=now,
    )
    selection = AuditModelSelection.model_validate_json(
        state.selection.model_dump_json(),
        strict=True,
    )
    evidence_bundle = AuditModelSelectionEvidenceBundle.model_validate_json(
        state.evidence_bundle.model_dump_json(),
        strict=True,
    )
    authority_evidence = state.policy_verification.evidence_projection()
    if (
        capability.capability_sha256 != state.capability_sha256
        or evidence_bundle.selection != selection
        or evidence_bundle.policy_artifact != state.policy_artifact
        or evidence_bundle.policy_evaluation != state.policy_evaluation
        or evidence_bundle.audit_context != state.audit_context
        or evidence_bundle.client_constraints != state.client_constraints
        or evidence_bundle.current_source_observation != state.source_observation
        or evidence_bundle.policy_authority_evidence != authority_evidence
        or capability.audit_selection_sha256 != selection.selection_sha256
        or capability.expires_at != selection.expires_at
        or capability.audit_scope_sha256 != selection.audit_scope_sha256
        or capability.source_sha256 != selection.source_sha256
        or capability.audit_context_sha256 != selection.audit_context_sha256
        or capability.technical_qualification_capability_sha256
        != selection.technical_qualification_capability_sha256
        or capability.technical_production_selection_sha256
        != selection.technical_production_selection_sha256
        or capability.policy_artifact_sha256 != selection.policy_artifact_sha256
        or capability.policy_evaluation_sha256 != selection.policy_evaluation_sha256
        or capability.policy_authority_receipt_sha256 != receipt.receipt_sha256
        or capability.policy_source_observation_sha256 != selection.policy_source_observation_sha256
        or tuple(id(model) for model in capability.models) != state.model_identities
        or tuple(model.exact_model_id for model in capability.models)
        != selection.selected_model_ids
        or len(capability.models) < _MIN_EXACT_MODELS
        or len({model.root_lineage for model in capability.models}) < _MIN_ROOT_LINEAGES
        or capability.capability_sha256
        != _canonical_json_sha256(_verified_audit_selection_payload(capability))
    ):
        raise ValueError("verified audit model selection integrity check failed")
    for model, selected in zip(capability.models, selection.models, strict=True):
        if _canonical_json_sha256(_technical_model_payload(model)) != _canonical_json_sha256(
            _selected_technical_payload(selected)
        ):
            raise ValueError(
                f"audit-selected model differs from technical qualification: "
                f"{selected.exact_model_id}"
            )


def _policy_routes_from_technical_models(
    models: tuple[VerifiedTierAModelQualification, ...],
) -> tuple[PolicyEligibilityRoute, ...]:
    return tuple(
        sorted(
            (
                build_policy_eligibility_route(
                    exact_model_id=model.exact_model_id,
                    provider_name=model.approved_provider_name,
                    provider_endpoint=model.approved_provider_endpoint,
                )
                for model in models
            ),
            key=lambda item: item.identity,
        )
    )


def _build_selected_model_record(
    model: VerifiedTierAModelQualification,
    route: PolicyEligibilityRoute,
) -> AuditSelectedTechnicalModel:
    if route.identity != (
        model.exact_model_id,
        model.approved_provider_name,
        model.approved_provider_endpoint,
    ):
        raise ValueError("policy-eligible route differs from technical model identity")
    values: dict[str, Any] = {
        "schema_version": "1.0",
        **_technical_model_payload(model),
        "policy_route_sha256": route.route_sha256,
        "technical_qualification_status": "VERIFIED_TIER_A",
        "policy_eligibility_status": "ELIGIBLE",
    }
    values["selected_model_sha256"] = _canonical_json_sha256(values)
    return AuditSelectedTechnicalModel.model_validate(values)


def _route_from_selected_model(model: AuditSelectedTechnicalModel) -> PolicyEligibilityRoute:
    route = build_policy_eligibility_route(
        exact_model_id=model.exact_model_id,
        provider_name=model.approved_provider_name,
        provider_endpoint=model.approved_provider_endpoint,
    )
    if route.route_sha256 != model.policy_route_sha256:
        raise ValueError("audit-selected model policy route differs")
    return route


def _technical_model_payload(model: VerifiedTierAModelQualification) -> dict[str, Any]:
    return {
        "exact_model_id": model.exact_model_id,
        "canonical_model_slug": model.canonical_model_slug,
        "root_lineage": model.root_lineage,
        "approved_provider_endpoint": model.approved_provider_endpoint,
        "approved_provider_name": model.approved_provider_name,
        "endpoint_snapshot_sha256": model.endpoint_snapshot_sha256,
        "output_capability_sha256": model.output_capability_sha256,
        "model_metadata_snapshot_sha256": model.model_metadata_snapshot_sha256,
        "pricing_snapshot_sha256": model.pricing_snapshot_sha256,
        "structured_output_mode": model.structured_output_mode,
        "approved_roles": model.approved_roles,
        "qualification_disposition": model.qualification_disposition,
        "overall_score": model.overall_score,
        "quality_measurement_sha256": model.quality_measurement_sha256,
        "qualification_result_sha256": model.qualification_result_sha256,
        "benchmark_report_sha256": model.benchmark_report_sha256,
        "benchmark_verification_sha256": model.benchmark_verification_sha256,
        "fresh_benchmark_evidence_sha256": model.fresh_benchmark_evidence_sha256,
        "reasoning_bindings": model.reasoning_bindings,
        "evaluated_at": model.evaluated_at,
        "expires_at": model.expires_at,
        "benchmark_case_count": model.benchmark_case_count,
    }


def _selected_technical_payload(model: AuditSelectedTechnicalModel) -> dict[str, Any]:
    return {
        key: value
        for key, value in model.model_dump().items()
        if key
        not in {
            "schema_version",
            "policy_route_sha256",
            "technical_qualification_status",
            "policy_eligibility_status",
            "selected_model_sha256",
        }
    }


def _verified_audit_selection_payload(
    capability: VerifiedAuditModelSelection,
) -> dict[str, Any]:
    return {
        "selected_at": capability.selected_at,
        "expires_at": capability.expires_at,
        "audit_scope_sha256": capability.audit_scope_sha256,
        "source_sha256": capability.source_sha256,
        "audit_context_sha256": capability.audit_context_sha256,
        "audit_selection_sha256": capability.audit_selection_sha256,
        "technical_qualification_capability_sha256": (
            capability.technical_qualification_capability_sha256
        ),
        "technical_production_selection_sha256": (capability.technical_production_selection_sha256),
        "policy_artifact_sha256": capability.policy_artifact_sha256,
        "policy_evaluation_sha256": capability.policy_evaluation_sha256,
        "policy_authority_receipt_sha256": capability.policy_authority_receipt_sha256,
        "policy_source_observation_sha256": capability.policy_source_observation_sha256,
        "models": [_technical_model_payload(model) for model in capability.models],
    }


def _strict_copy[ModelT: BaseModel](model_type: type[ModelT], value: ModelT) -> ModelT:
    if type(value) is not model_type:
        raise ValueError(f"{model_type.__name__} must be supplied exactly")
    return model_type.model_validate_json(value.model_dump_json(), strict=True)


def _whole_second_utc(value: datetime, *, label: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
        or value.microsecond != 0
    ):
        raise ValueError(f"{label} must be a whole-second UTC timestamp")
    return value


def _require_self_hash(model: BaseModel, field: str, *, label: str) -> None:
    expected = _canonical_json_sha256(model.model_dump(mode="json", exclude={field}))
    if getattr(model, field) != expected:
        raise ValueError(f"{label} self-hash is inconsistent")


def _canonical_json_sha256(value: Any) -> str:
    encoded = json.dumps(
        _JSON_ADAPTER.dump_python(value, mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "AUDIT_MODEL_SELECTION_EVIDENCE_FILENAME",
    "AuditModelRoutingEvidence",
    "AuditModelSelection",
    "AuditModelSelectionEvidenceBundle",
    "AuditSelectedTechnicalModel",
    "VerifiedAuditModelSelection",
    "build_audit_model_selection_evidence_bundle",
    "resolve_verified_audit_model_selection",
    "verify_audit_model_selection_evidence_bundle",
]
