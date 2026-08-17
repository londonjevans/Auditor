"""Provider-free commercial policy-eligibility evidence and structural evaluation.

The models in this module retain operator/legal evidence, but deliberately issue no
runtime authority. Catalogue metadata and automated refreshes may cause exclusion or
request another review; they can never create a positive legal determination here.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from enum import Enum, StrEnum
from typing import Any, Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models.identifiers import require_exact_openrouter_model_id
from mmaudit.privacy import PrivacySourceClassification

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ENDPOINT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$"
_JURISDICTION_PATTERN = r"^[A-Z]{2,3}(?:-[A-Z0-9]{1,8})?$"
_REVIEWER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._@:/-]{0,199}$"
_MAX_EVIDENCE_REFERENCES = 256
_MAX_ROUTES = 128
_MAX_CONSTRAINT_VALUES = 128
_MAX_VALIDITY = timedelta(days=31)
_MAX_EVIDENCE_REVIEW_AGE = timedelta(days=31)


class PolicyEvidenceKind(StrEnum):
    """Bounded kind of official material reviewed by the operator."""

    ACCEPTABLE_USE_POLICY = "ACCEPTABLE_USE_POLICY"
    COMMERCIAL_TERMS = "COMMERCIAL_TERMS"
    MODEL_LICENSE = "MODEL_LICENSE"
    MODEL_PROVIDER_TERMS = "MODEL_PROVIDER_TERMS"
    REGIONAL_TERMS = "REGIONAL_TERMS"
    ROUTING_PROVIDER_TERMS = "ROUTING_PROVIDER_TERMS"


class PolicyLegalCriterion(StrEnum):
    """Exact legal questions required for one global model/endpoint decision."""

    CLIENT_ENTITY_AND_JURISDICTION = "CLIENT_ENTITY_AND_JURISDICTION"
    COMMERCIAL_CUSTOMER_FACING_USE = "COMMERCIAL_CUSTOMER_FACING_USE"
    COMMERCIAL_REPORT_INCORPORATION = "COMMERCIAL_REPORT_INCORPORATION"
    DEFENSIVE_SECURITY_ANALYSIS = "DEFENSIVE_SECURITY_ANALYSIS"
    DEFENSIVE_TASK_SCOPE = "DEFENSIVE_TASK_SCOPE"
    NO_RELEVANT_PROVIDER_OR_MODEL_RESTRICTION = "NO_RELEVANT_PROVIDER_OR_MODEL_RESTRICTION"
    OPERATOR_ENTITY_AND_JURISDICTION = "OPERATOR_ENTITY_AND_JURISDICTION"
    SOURCE_CODE_ANALYSIS = "SOURCE_CODE_ANALYSIS"


class PolicyCriterionDisposition(StrEnum):
    """Operator/legal conclusion for one required criterion."""

    AMBIGUOUS = "AMBIGUOUS"
    PERMITTED = "PERMITTED"
    PROHIBITED = "PROHIBITED"


class PolicyEligibilityDecision(StrEnum):
    """Recorded decision; only ELIGIBLE can pass structural evaluation."""

    ELIGIBLE = "ELIGIBLE"
    INELIGIBLE = "INELIGIBLE"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class PolicyUsePurpose(StrEnum):
    """Exact commercial purpose that one determination may authorize structurally."""

    PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT = "PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT"
    PUBLIC_OR_SYNTHETIC_DEFENSIVE_EVALUATION = "PUBLIC_OR_SYNTHETIC_DEFENSIVE_EVALUATION"


class ClientConstraintMode(StrEnum):
    """One non-ambiguous interpretation for all populated client restrictions."""

    ALLOW_ONLY = "ALLOW_ONLY"
    DENY_ONLY = "DENY_ONLY"


class PolicyExclusionReason(StrEnum):
    """Canonical reasons why one technically supplied route is structurally excluded."""

    AUDIT_SCOPE_RESTRICTED = "AUDIT_SCOPE_RESTRICTED"
    CLIENT_CONSTRAINTS_EXPIRED = "CLIENT_CONSTRAINTS_EXPIRED"
    CLIENT_CONSTRAINTS_FUTURE = "CLIENT_CONSTRAINTS_FUTURE"
    CLIENT_ENDPOINT_RESTRICTED = "CLIENT_ENDPOINT_RESTRICTED"
    CLIENT_ENTITY_RESTRICTED = "CLIENT_ENTITY_RESTRICTED"
    CLIENT_JURISDICTION_RESTRICTED = "CLIENT_JURISDICTION_RESTRICTED"
    CLIENT_MODEL_RESTRICTED = "CLIENT_MODEL_RESTRICTED"
    CLIENT_PROVIDER_RESTRICTED = "CLIENT_PROVIDER_RESTRICTED"
    DECISION_INELIGIBLE = "DECISION_INELIGIBLE"
    DECISION_REVIEW_REQUIRED = "DECISION_REVIEW_REQUIRED"
    DETERMINATION_EXPIRED = "DETERMINATION_EXPIRED"
    DETERMINATION_FUTURE = "DETERMINATION_FUTURE"
    MISSING_DETERMINATION = "MISSING_DETERMINATION"
    OPERATOR_ENTITY_RESTRICTED = "OPERATOR_ENTITY_RESTRICTED"
    OPERATOR_JURISDICTION_RESTRICTED = "OPERATOR_JURISDICTION_RESTRICTED"
    ROUTE_MISMATCH = "ROUTE_MISMATCH"
    SOURCE_RESTRICTED = "SOURCE_RESTRICTED"
    USE_PURPOSE_RESTRICTED = "USE_PURPOSE_RESTRICTED"


class PolicyReviewReason(StrEnum):
    """Refresh-safe states; this enum intentionally has no eligible state."""

    EXPIRED = "EXPIRED"
    MISSING = "MISSING"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    SOURCE_CHANGED = "SOURCE_CHANGED"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class OfficialPolicyEvidenceReference(_FrozenModel):
    """Self-hashed reference to exact operator-supplied official evidence bytes."""

    schema_version: Literal["1.0"] = "1.0"
    kind: PolicyEvidenceKind
    publisher: str = Field(min_length=1, max_length=200)
    official_source_url: str = Field(min_length=9, max_length=2_048)
    source_version: str | None = Field(default=None, min_length=1, max_length=200)
    retrieved_at: datetime
    content_sha256: str = Field(pattern=_SHA256_PATTERN)
    byte_count: int = Field(ge=1, le=20_000_000)
    reference_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("publisher", "source_version")
    @classmethod
    def bounded_text_is_printable(cls, value: str | None) -> str | None:
        if value is not None and (
            value != value.strip() or any(not character.isprintable() for character in value)
        ):
            raise ValueError("policy evidence text must be canonical printable text")
        return value

    @field_validator("official_source_url")
    @classmethod
    def source_url_is_canonical_https(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            value != value.strip()
            or any(not character.isprintable() for character in value)
            or parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("official policy source must be a credential-free canonical HTTPS URL")
        return value

    @field_validator("retrieved_at")
    @classmethod
    def retrieval_time_is_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="policy evidence retrieval time")

    @model_validator(mode="after")
    def reference_is_self_hashed(self) -> Self:
        _require_self_hash(self, "reference_sha256", label="policy evidence reference")
        return self


class PolicyEligibilitySourceReferenceObservation(_FrozenModel):
    """One explicit current-content observation for one cited official reference."""

    schema_version: Literal["1.0"] = "1.0"
    reference_sha256: str = Field(pattern=_SHA256_PATTERN)
    expected_content_sha256: str = Field(pattern=_SHA256_PATTERN)
    current_content_sha256: str = Field(pattern=_SHA256_PATTERN)
    observation_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def observation_is_self_hashed(self) -> Self:
        _require_self_hash(
            self,
            "observation_sha256",
            label="policy source-reference observation",
        )
        return self


class PolicyCriterionAssessment(_FrozenModel):
    """One evidence-bound answer to a fixed legal criterion."""

    schema_version: Literal["1.0"] = "1.0"
    criterion: PolicyLegalCriterion
    disposition: PolicyCriterionDisposition
    evidence_reference_sha256s: tuple[str, ...] = Field(min_length=1, max_length=32)
    assessment_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    assessment_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("evidence_reference_sha256s")
    @classmethod
    def evidence_hashes_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_hashes(value, label="criterion evidence references", allow_empty=False)

    @model_validator(mode="after")
    def assessment_is_self_hashed(self) -> Self:
        _require_self_hash(self, "assessment_sha256", label="policy criterion assessment")
        return self


class PolicyEligibilityRoute(_FrozenModel):
    """One exact model/provider/endpoint identity."""

    schema_version: Literal["1.0"] = "1.0"
    exact_model_id: str
    provider_name: str = Field(min_length=1, max_length=200)
    provider_endpoint: str = Field(pattern=_ENDPOINT_PATTERN)
    route_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @field_validator("provider_name")
    @classmethod
    def provider_is_printable(cls, value: str) -> str:
        return _canonical_printable(value, label="provider name")

    @model_validator(mode="after")
    def route_is_self_hashed(self) -> Self:
        _require_self_hash(self, "route_sha256", label="policy route")
        return self

    @property
    def identity(self) -> tuple[str, str, str]:
        return (self.exact_model_id, self.provider_name, self.provider_endpoint)


class ModelPolicyEligibilityDetermination(_FrozenModel):
    """Unauthenticated operator/legal decision for one exact route."""

    schema_version: Literal["1.0"] = "1.0"
    route: PolicyEligibilityRoute
    decision: PolicyEligibilityDecision
    intended_use: PolicyUsePurpose
    applicable_client_entity_sha256s: tuple[str, ...] = Field(
        min_length=1,
        max_length=_MAX_CONSTRAINT_VALUES,
    )
    applicable_client_jurisdictions: tuple[str, ...] = Field(
        min_length=1,
        max_length=_MAX_CONSTRAINT_VALUES,
    )
    applicable_operator_entity_sha256s: tuple[str, ...] = Field(
        min_length=1,
        max_length=_MAX_CONSTRAINT_VALUES,
    )
    applicable_operator_jurisdictions: tuple[str, ...] = Field(
        min_length=1,
        max_length=_MAX_CONSTRAINT_VALUES,
    )
    assessments: tuple[PolicyCriterionAssessment, ...] = Field(
        min_length=len(PolicyLegalCriterion),
        max_length=len(PolicyLegalCriterion),
    )
    reviewed_by: str = Field(pattern=_REVIEWER_PATTERN)
    reviewed_at: datetime
    effective_at: datetime
    expires_at: datetime
    review_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    determination_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("reviewed_at", "effective_at", "expires_at")
    @classmethod
    def decision_times_are_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="policy determination time")

    @field_validator(
        "applicable_client_entity_sha256s",
        "applicable_operator_entity_sha256s",
    )
    @classmethod
    def applicable_entities_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_hashes(value, label="applicable policy entities", allow_empty=False)

    @field_validator(
        "applicable_client_jurisdictions",
        "applicable_operator_jurisdictions",
    )
    @classmethod
    def applicable_jurisdictions_are_canonical(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _canonical_jurisdictions(value, label="applicable policy jurisdictions")

    @model_validator(mode="after")
    def decision_is_consistent_and_self_hashed(self) -> Self:
        criteria = tuple(assessment.criterion for assessment in self.assessments)
        expected = tuple(sorted(PolicyLegalCriterion, key=lambda item: item.value))
        if criteria != expected:
            raise ValueError("policy determination criteria must be exact, unique, and sorted")
        dispositions = tuple(assessment.disposition for assessment in self.assessments)
        if self.decision is PolicyEligibilityDecision.ELIGIBLE and any(
            item is not PolicyCriterionDisposition.PERMITTED for item in dispositions
        ):
            raise ValueError("eligible policy decision requires every criterion to be permitted")
        if self.decision is PolicyEligibilityDecision.INELIGIBLE and not any(
            item is PolicyCriterionDisposition.PROHIBITED for item in dispositions
        ):
            raise ValueError("ineligible policy decision requires a prohibited criterion")
        if self.decision is PolicyEligibilityDecision.REVIEW_REQUIRED and (
            any(item is PolicyCriterionDisposition.PROHIBITED for item in dispositions)
            or not any(item is PolicyCriterionDisposition.AMBIGUOUS for item in dispositions)
        ):
            raise ValueError(
                "review-required policy decision requires ambiguity without a prohibition"
            )
        if (
            self.effective_at < self.reviewed_at
            or self.expires_at <= self.effective_at
            or self.expires_at - self.reviewed_at > _MAX_VALIDITY
        ):
            raise ValueError("policy determination validity window is invalid")
        _require_self_hash(self, "determination_sha256", label="policy determination")
        return self


class PolicyAuditContext(_FrozenModel):
    """Exact current audit/client/operator facts used by structural evaluation."""

    schema_version: Literal["1.0"] = "1.0"
    audit_scope_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_classification: PrivacySourceClassification
    intended_use: PolicyUsePurpose
    client_entity_sha256: str = Field(pattern=_SHA256_PATTERN)
    client_jurisdiction: str = Field(pattern=_JURISDICTION_PATTERN)
    operator_entity_sha256: str = Field(pattern=_SHA256_PATTERN)
    operator_jurisdiction: str = Field(pattern=_JURISDICTION_PATTERN)
    context_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def context_is_self_hashed(self) -> Self:
        _require_self_hash(self, "context_sha256", label="policy audit context")
        return self


class ClientPolicyConstraints(_FrozenModel):
    """Unauthenticated client-specific restrictions for one exact audit context."""

    schema_version: Literal["1.0"] = "1.0"
    audit_context: PolicyAuditContext
    mode: ClientConstraintMode
    provider_names: tuple[str, ...] = Field(max_length=_MAX_CONSTRAINT_VALUES)
    exact_model_ids: tuple[str, ...] = Field(max_length=_MAX_CONSTRAINT_VALUES)
    exact_routes: tuple[PolicyEligibilityRoute, ...] = Field(max_length=_MAX_CONSTRAINT_VALUES)
    reviewed_by: str = Field(pattern=_REVIEWER_PATTERN)
    reviewed_at: datetime
    effective_at: datetime
    expires_at: datetime
    constraint_basis_sha256: str = Field(pattern=_SHA256_PATTERN)
    constraints_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("provider_names")
    @classmethod
    def providers_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        validated = tuple(_canonical_printable(item, label="client provider") for item in value)
        if validated != tuple(sorted(set(validated))):
            raise ValueError("client providers must be unique and sorted")
        return validated

    @field_validator("exact_model_ids")
    @classmethod
    def models_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        validated = tuple(require_exact_openrouter_model_id(item) for item in value)
        if validated != tuple(sorted(set(validated))):
            raise ValueError("client model constraints must be exact, unique, and sorted")
        return validated

    @field_validator("reviewed_at", "effective_at", "expires_at")
    @classmethod
    def constraint_times_are_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="client policy constraint time")

    @model_validator(mode="after")
    def constraints_are_canonical_and_self_hashed(self) -> Self:
        _require_canonical_routes(self.exact_routes, label="client exact routes")
        if self.mode is ClientConstraintMode.ALLOW_ONLY and not (
            self.provider_names or self.exact_model_ids or self.exact_routes
        ):
            raise ValueError("allow-only client constraints require an explicit allowed value")
        if (
            self.effective_at < self.reviewed_at
            or self.expires_at <= self.effective_at
            or self.expires_at - self.reviewed_at > _MAX_VALIDITY
        ):
            raise ValueError("client policy constraint validity window is invalid")
        _require_self_hash(self, "constraints_sha256", label="client policy constraints")
        return self


class ModelPolicyEligibilityArtifact(_FrozenModel):
    """Provider-free structural registry that explicitly carries no authority."""

    schema_version: Literal["1.0"] = "1.0"
    created_at: datetime
    official_evidence: tuple[OfficialPolicyEvidenceReference, ...] = Field(
        max_length=_MAX_EVIDENCE_REFERENCES
    )
    determinations: tuple[ModelPolicyEligibilityDetermination, ...] = Field(max_length=_MAX_ROUTES)
    operator_decision_authenticity: Literal["NOT_INDEPENDENTLY_PROVEN"] = "NOT_INDEPENDENTLY_PROVEN"
    automated_eligibility_inference: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("created_at")
    @classmethod
    def creation_time_is_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="policy artifact creation time")

    @field_validator(
        "automated_eligibility_inference",
        "production_selection_authorized",
        mode="before",
    )
    @classmethod
    def authority_flags_are_literal_booleans(cls, value: object) -> object:
        return _require_literal_bool(value, label="policy artifact authority flag")

    @model_validator(mode="after")
    def artifact_is_exact_non_authorizing_and_self_hashed(self) -> Self:
        evidence_hashes = tuple(item.reference_sha256 for item in self.official_evidence)
        if evidence_hashes != tuple(sorted(set(evidence_hashes))):
            raise ValueError("official policy evidence must be unique and sorted")
        _require_canonical_determinations(self.determinations)
        references = set(evidence_hashes)
        used: set[str] = set()
        by_hash = {item.reference_sha256: item for item in self.official_evidence}
        for determination in self.determinations:
            if determination.reviewed_at > self.created_at:
                raise ValueError("policy determination cannot postdate its artifact")
            for assessment in determination.assessments:
                assessment_refs = set(assessment.evidence_reference_sha256s)
                if not assessment_refs.issubset(references):
                    raise ValueError("policy determination references unknown official evidence")
                if any(
                    by_hash[item].retrieved_at > determination.reviewed_at
                    for item in assessment_refs
                ):
                    raise ValueError("policy evidence cannot postdate its determination")
                if any(
                    determination.reviewed_at - by_hash[item].retrieved_at
                    > _MAX_EVIDENCE_REVIEW_AGE
                    for item in assessment_refs
                ):
                    raise ValueError("policy evidence is too old for its determination review")
                if any(
                    determination.expires_at > by_hash[item].retrieved_at + _MAX_EVIDENCE_REVIEW_AGE
                    for item in assessment_refs
                ):
                    raise ValueError("policy determination outlives its official evidence")
                used.update(assessment_refs)
        if used != references:
            raise ValueError("official policy evidence must be used exactly by determinations")
        _require_self_hash(self, "artifact_sha256", label="policy eligibility artifact")
        return self


class PolicyEligibilityExclusion(_FrozenModel):
    """Canonical route-specific structural exclusion."""

    schema_version: Literal["1.0"] = "1.0"
    route: PolicyEligibilityRoute
    reasons: tuple[PolicyExclusionReason, ...] = Field(min_length=1)
    determination_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    exclusion_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("reasons")
    @classmethod
    def reasons_are_canonical(
        cls, value: tuple[PolicyExclusionReason, ...]
    ) -> tuple[PolicyExclusionReason, ...]:
        if value != tuple(sorted(set(value), key=lambda item: item.value)):
            raise ValueError("policy exclusion reasons must be unique and sorted")
        return value

    @model_validator(mode="after")
    def exclusion_is_self_hashed(self) -> Self:
        _require_self_hash(self, "exclusion_sha256", label="policy exclusion")
        return self


class PolicyEligibilityEvaluation(_FrozenModel):
    """Deterministic structural projection; never a production capability."""

    schema_version: Literal["1.0"] = "1.0"
    evaluated_at: datetime
    expires_at: datetime | None
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    client_constraints_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_context_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    eligible_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_routes: tuple[PolicyEligibilityRoute, ...] = Field(max_length=_MAX_ROUTES)
    eligible_routes: tuple[PolicyEligibilityRoute, ...] = Field(max_length=_MAX_ROUTES)
    eligible_model_ids: tuple[str, ...] = Field(max_length=_MAX_ROUTES)
    exclusions: tuple[PolicyEligibilityExclusion, ...] = Field(max_length=_MAX_ROUTES)
    operator_decision_authenticity: Literal["NOT_INDEPENDENTLY_PROVEN"] = "NOT_INDEPENDENTLY_PROVEN"
    automated_eligibility_inference: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    evaluation_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("evaluated_at", "expires_at")
    @classmethod
    def evaluation_times_are_utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _whole_second_utc(value, label="policy evaluation time")

    @field_validator("eligible_model_ids")
    @classmethod
    def eligible_ids_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        validated = tuple(require_exact_openrouter_model_id(item) for item in value)
        if validated != tuple(sorted(set(validated))):
            raise ValueError("eligible model IDs must be exact, unique, and sorted")
        return validated

    @field_validator(
        "automated_eligibility_inference",
        "production_selection_authorized",
        mode="before",
    )
    @classmethod
    def authority_flags_are_literal_booleans(cls, value: object) -> object:
        return _require_literal_bool(value, label="policy evaluation authority flag")

    @model_validator(mode="after")
    def evaluation_is_canonical_non_authorizing_and_self_hashed(self) -> Self:
        _require_canonical_routes(self.technical_routes, label="technical policy routes")
        _require_canonical_routes(self.eligible_routes, label="eligible policy routes")
        exclusion_routes = tuple(item.route for item in self.exclusions)
        _require_canonical_routes(exclusion_routes, label="policy exclusion routes")
        technical = {item.identity for item in self.technical_routes}
        eligible = {item.identity for item in self.eligible_routes}
        excluded = {item.identity for item in exclusion_routes}
        if eligible & excluded or eligible | excluded != technical:
            raise ValueError("policy evaluation must classify every technical route exactly once")
        expected_ids = tuple(sorted({item.exact_model_id for item in self.eligible_routes}))
        if self.eligible_model_ids != expected_ids:
            raise ValueError("eligible model IDs differ from eligible exact routes")
        if self.technical_route_set_sha256 != policy_eligibility_candidate_routes_sha256(
            self.technical_routes
        ):
            raise ValueError("technical policy route-set hash is inconsistent")
        if self.eligible_route_set_sha256 != policy_eligibility_candidate_routes_sha256(
            self.eligible_routes
        ):
            raise ValueError("eligible policy route-set hash is inconsistent")
        if bool(self.eligible_routes) is (self.expires_at is None):
            raise ValueError("policy evaluation expiry must exist exactly when routes are eligible")
        if self.expires_at is not None and self.expires_at <= self.evaluated_at:
            raise ValueError("policy evaluation must be current when it has eligible routes")
        _require_self_hash(self, "evaluation_sha256", label="policy eligibility evaluation")
        return self


class PolicyReviewSignal(_FrozenModel):
    """Non-authorizing refresh signal that can only request review."""

    schema_version: Literal["1.0"] = "1.0"
    observed_at: datetime
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    route: PolicyEligibilityRoute
    determination_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    reasons: tuple[PolicyReviewReason, ...] = Field(min_length=1, max_length=4)
    source_reference_observations: (
        tuple[PolicyEligibilitySourceReferenceObservation, ...] | None
    ) = Field(default=None, min_length=1, max_length=32)
    automated_eligibility_inference: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    signal_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("observed_at")
    @classmethod
    def observation_time_is_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="policy review observation time")

    @field_validator("source_reference_observations")
    @classmethod
    def source_observations_are_canonical(
        cls,
        value: tuple[PolicyEligibilitySourceReferenceObservation, ...] | None,
    ) -> tuple[PolicyEligibilitySourceReferenceObservation, ...] | None:
        if value is not None:
            _require_canonical_source_reference_observations(
                value,
                label="policy review source-reference observations",
            )
        return value

    @field_validator("reasons")
    @classmethod
    def review_reasons_are_canonical(
        cls, value: tuple[PolicyReviewReason, ...]
    ) -> tuple[PolicyReviewReason, ...]:
        if value != tuple(sorted(set(value), key=lambda item: item.value)):
            raise ValueError("policy review reasons must be unique and sorted")
        return value

    @field_validator(
        "automated_eligibility_inference",
        "production_selection_authorized",
        mode="before",
    )
    @classmethod
    def authority_flags_are_literal_booleans(cls, value: object) -> object:
        return _require_literal_bool(value, label="policy review authority flag")

    @model_validator(mode="after")
    def signal_is_self_hashed(self) -> Self:
        _require_self_hash(self, "signal_sha256", label="policy review signal")
        return self


def build_official_policy_evidence_reference(
    *,
    kind: PolicyEvidenceKind,
    publisher: str,
    official_source_url: str,
    retrieved_at: datetime,
    content_sha256: str,
    byte_count: int,
    source_version: str | None = None,
) -> OfficialPolicyEvidenceReference:
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "kind": kind,
        "publisher": publisher,
        "official_source_url": official_source_url,
        "source_version": source_version,
        "retrieved_at": retrieved_at,
        "content_sha256": content_sha256,
        "byte_count": byte_count,
    }
    values["reference_sha256"] = _canonical_sha256(values)
    return OfficialPolicyEvidenceReference.model_validate(values)


def build_policy_eligibility_source_reference_observation(
    *,
    reference: OfficialPolicyEvidenceReference,
    current_content_sha256: str,
) -> PolicyEligibilitySourceReferenceObservation:
    """Bind current operator-observed content to one exact official reference."""

    reference = _strict_copy(OfficialPolicyEvidenceReference, reference)
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "reference_sha256": reference.reference_sha256,
        "expected_content_sha256": reference.content_sha256,
        "current_content_sha256": current_content_sha256,
    }
    values["observation_sha256"] = _canonical_sha256(values)
    return PolicyEligibilitySourceReferenceObservation.model_validate(values)


def build_policy_criterion_assessment(
    *,
    criterion: PolicyLegalCriterion,
    disposition: PolicyCriterionDisposition,
    evidence_reference_sha256s: tuple[str, ...],
    assessment_record_sha256: str,
) -> PolicyCriterionAssessment:
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "criterion": criterion,
        "disposition": disposition,
        "evidence_reference_sha256s": evidence_reference_sha256s,
        "assessment_record_sha256": assessment_record_sha256,
    }
    values["assessment_sha256"] = _canonical_sha256(values)
    return PolicyCriterionAssessment.model_validate(values)


def build_policy_eligibility_route(
    *, exact_model_id: str, provider_name: str, provider_endpoint: str
) -> PolicyEligibilityRoute:
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "exact_model_id": exact_model_id,
        "provider_name": provider_name,
        "provider_endpoint": provider_endpoint,
    }
    values["route_sha256"] = _canonical_sha256(values)
    return PolicyEligibilityRoute.model_validate(values)


def policy_eligibility_candidate_routes_sha256(
    routes: tuple[PolicyEligibilityRoute, ...],
) -> str:
    """Hash one canonical exact route set for downstream non-serializable authority."""

    _require_canonical_routes(routes, label="policy candidate routes")
    return _canonical_sha256([item.model_dump(mode="json") for item in routes])


def build_model_policy_eligibility_determination(
    *,
    route: PolicyEligibilityRoute,
    decision: PolicyEligibilityDecision,
    intended_use: PolicyUsePurpose,
    applicable_client_entity_sha256s: tuple[str, ...],
    applicable_client_jurisdictions: tuple[str, ...],
    applicable_operator_entity_sha256s: tuple[str, ...],
    applicable_operator_jurisdictions: tuple[str, ...],
    assessments: tuple[PolicyCriterionAssessment, ...],
    reviewed_by: str,
    reviewed_at: datetime,
    effective_at: datetime,
    expires_at: datetime,
    review_record_sha256: str,
) -> ModelPolicyEligibilityDetermination:
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "route": route,
        "decision": decision,
        "intended_use": intended_use,
        "applicable_client_entity_sha256s": applicable_client_entity_sha256s,
        "applicable_client_jurisdictions": applicable_client_jurisdictions,
        "applicable_operator_entity_sha256s": applicable_operator_entity_sha256s,
        "applicable_operator_jurisdictions": applicable_operator_jurisdictions,
        "assessments": assessments,
        "reviewed_by": reviewed_by,
        "reviewed_at": reviewed_at,
        "effective_at": effective_at,
        "expires_at": expires_at,
        "review_record_sha256": review_record_sha256,
    }
    values["determination_sha256"] = _canonical_sha256(values)
    return ModelPolicyEligibilityDetermination.model_validate(values)


def build_policy_audit_context(
    *,
    audit_scope_sha256: str,
    source_sha256: str,
    source_classification: PrivacySourceClassification,
    intended_use: PolicyUsePurpose,
    client_entity_sha256: str,
    client_jurisdiction: str,
    operator_entity_sha256: str,
    operator_jurisdiction: str,
) -> PolicyAuditContext:
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "audit_scope_sha256": audit_scope_sha256,
        "source_sha256": source_sha256,
        "source_classification": source_classification,
        "intended_use": intended_use,
        "client_entity_sha256": client_entity_sha256,
        "client_jurisdiction": client_jurisdiction,
        "operator_entity_sha256": operator_entity_sha256,
        "operator_jurisdiction": operator_jurisdiction,
    }
    values["context_sha256"] = _canonical_sha256(values)
    return PolicyAuditContext.model_validate(values)


def build_client_policy_constraints(
    *,
    audit_context: PolicyAuditContext,
    mode: ClientConstraintMode,
    provider_names: tuple[str, ...],
    exact_model_ids: tuple[str, ...],
    exact_routes: tuple[PolicyEligibilityRoute, ...],
    reviewed_by: str,
    reviewed_at: datetime,
    effective_at: datetime,
    expires_at: datetime,
    constraint_basis_sha256: str,
) -> ClientPolicyConstraints:
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "audit_context": audit_context,
        "mode": mode,
        "provider_names": provider_names,
        "exact_model_ids": exact_model_ids,
        "exact_routes": exact_routes,
        "reviewed_by": reviewed_by,
        "reviewed_at": reviewed_at,
        "effective_at": effective_at,
        "expires_at": expires_at,
        "constraint_basis_sha256": constraint_basis_sha256,
    }
    values["constraints_sha256"] = _canonical_sha256(values)
    return ClientPolicyConstraints.model_validate(values)


def build_model_policy_eligibility_artifact(
    *,
    created_at: datetime,
    official_evidence: tuple[OfficialPolicyEvidenceReference, ...],
    determinations: tuple[ModelPolicyEligibilityDetermination, ...],
) -> ModelPolicyEligibilityArtifact:
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "created_at": created_at,
        "official_evidence": official_evidence,
        "determinations": determinations,
        "operator_decision_authenticity": "NOT_INDEPENDENTLY_PROVEN",
        "automated_eligibility_inference": False,
        "production_selection_authorized": False,
    }
    values["artifact_sha256"] = _canonical_sha256(values)
    return ModelPolicyEligibilityArtifact.model_validate(values)


def evaluate_model_policy_eligibility(
    *,
    artifact: ModelPolicyEligibilityArtifact,
    client_constraints: ClientPolicyConstraints,
    audit_context: PolicyAuditContext,
    technical_routes: tuple[PolicyEligibilityRoute, ...],
    observed_at: datetime,
) -> PolicyEligibilityEvaluation:
    """Structurally classify technical routes without issuing or implying authority."""

    artifact = _strict_copy(ModelPolicyEligibilityArtifact, artifact)
    client_constraints = _strict_copy(ClientPolicyConstraints, client_constraints)
    audit_context = _strict_copy(PolicyAuditContext, audit_context)
    technical_routes = tuple(
        _strict_copy(PolicyEligibilityRoute, item) for item in technical_routes
    )
    _require_canonical_routes(technical_routes, label="technical policy routes")
    observed_at = _whole_second_utc(observed_at, label="policy evaluation time")

    global_reasons = _audit_context_exclusions(client_constraints.audit_context, audit_context)
    if (
        observed_at < client_constraints.effective_at
        or observed_at < client_constraints.reviewed_at
    ):
        global_reasons.add(PolicyExclusionReason.CLIENT_CONSTRAINTS_FUTURE)
    if observed_at >= client_constraints.expires_at:
        global_reasons.add(PolicyExclusionReason.CLIENT_CONSTRAINTS_EXPIRED)

    by_route = {item.route.identity: item for item in artifact.determinations}
    determination_models = {item.route.exact_model_id for item in artifact.determinations}
    eligible: list[PolicyEligibilityRoute] = []
    eligible_expiries: list[datetime] = []
    exclusions: list[PolicyEligibilityExclusion] = []
    for route in technical_routes:
        reasons = set(global_reasons)
        determination = by_route.get(route.identity)
        if determination is None:
            reasons.add(
                PolicyExclusionReason.ROUTE_MISMATCH
                if route.exact_model_id in determination_models
                else PolicyExclusionReason.MISSING_DETERMINATION
            )
        else:
            if (
                artifact.created_at > observed_at
                or determination.reviewed_at > observed_at
                or determination.effective_at > observed_at
            ):
                reasons.add(PolicyExclusionReason.DETERMINATION_FUTURE)
            if determination.expires_at <= observed_at:
                reasons.add(PolicyExclusionReason.DETERMINATION_EXPIRED)
            if determination.decision is PolicyEligibilityDecision.INELIGIBLE:
                reasons.add(PolicyExclusionReason.DECISION_INELIGIBLE)
            elif determination.decision is PolicyEligibilityDecision.REVIEW_REQUIRED:
                reasons.add(PolicyExclusionReason.DECISION_REVIEW_REQUIRED)
            reasons.update(_determination_context_exclusions(determination, audit_context))

        reasons.update(_client_route_exclusions(client_constraints, route))
        if reasons:
            exclusions.append(_build_exclusion(route, reasons, determination))
        else:
            assert determination is not None
            eligible.append(route)
            eligible_expiries.extend((determination.expires_at, client_constraints.expires_at))

    eligible_routes = tuple(eligible)
    exclusion_tuple = tuple(exclusions)
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "evaluated_at": observed_at,
        "expires_at": min(eligible_expiries) if eligible_expiries else None,
        "artifact_sha256": artifact.artifact_sha256,
        "client_constraints_sha256": client_constraints.constraints_sha256,
        "audit_context_sha256": audit_context.context_sha256,
        "technical_route_set_sha256": policy_eligibility_candidate_routes_sha256(technical_routes),
        "eligible_route_set_sha256": policy_eligibility_candidate_routes_sha256(eligible_routes),
        "technical_routes": technical_routes,
        "eligible_routes": eligible_routes,
        "eligible_model_ids": tuple(sorted({item.exact_model_id for item in eligible_routes})),
        "exclusions": exclusion_tuple,
        "operator_decision_authenticity": "NOT_INDEPENDENTLY_PROVEN",
        "automated_eligibility_inference": False,
        "production_selection_authorized": False,
    }
    values["evaluation_sha256"] = _canonical_sha256(values)
    return PolicyEligibilityEvaluation.model_validate(values)


def policy_review_signal(
    *,
    artifact: ModelPolicyEligibilityArtifact,
    route: PolicyEligibilityRoute,
    observed_at: datetime,
    source_reference_observations: tuple[PolicyEligibilitySourceReferenceObservation, ...]
    | None = None,
) -> PolicyReviewSignal | None:
    """Return only fail-closed refresh/re-review states, never an eligible state."""

    artifact = _strict_copy(ModelPolicyEligibilityArtifact, artifact)
    route = _strict_copy(PolicyEligibilityRoute, route)
    observed_at = _whole_second_utc(observed_at, label="policy review observation time")
    current = (
        None
        if source_reference_observations is None
        else tuple(
            _strict_copy(PolicyEligibilitySourceReferenceObservation, item)
            for item in source_reference_observations
        )
    )
    if current is not None:
        _require_canonical_source_reference_observations(
            current,
            label="current policy source-reference observations",
        )
    determination = next(
        (item for item in artifact.determinations if item.route.identity == route.identity),
        None,
    )
    reasons: set[PolicyReviewReason] = set()
    if determination is None:
        reasons.add(PolicyReviewReason.MISSING)
    else:
        if determination.expires_at <= observed_at:
            reasons.add(PolicyReviewReason.EXPIRED)
        if (
            artifact.created_at > observed_at
            or determination.reviewed_at > observed_at
            or determination.effective_at > observed_at
            or determination.decision is PolicyEligibilityDecision.REVIEW_REQUIRED
        ):
            reasons.add(PolicyReviewReason.REVIEW_REQUIRED)
        evidence_by_hash = {item.reference_sha256: item for item in artifact.official_evidence}
        expected = tuple(
            (reference_sha256, evidence_by_hash[reference_sha256].content_sha256)
            for reference_sha256 in sorted(
                {
                    reference_sha256
                    for assessment in determination.assessments
                    for reference_sha256 in assessment.evidence_reference_sha256s
                }
            )
        )
        if current is not None:
            observed_expected = tuple(
                (item.reference_sha256, item.expected_content_sha256) for item in current
            )
            if observed_expected != expected:
                raise ValueError(
                    "current policy source observations must exactly cover cited references"
                )
            if any(item.current_content_sha256 != item.expected_content_sha256 for item in current):
                reasons.add(PolicyReviewReason.SOURCE_CHANGED)
    if not reasons:
        return None
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "observed_at": observed_at,
        "artifact_sha256": artifact.artifact_sha256,
        "route": route,
        "determination_sha256": (
            None if determination is None else determination.determination_sha256
        ),
        "reasons": tuple(sorted(reasons, key=lambda item: item.value)),
        "source_reference_observations": current,
        "automated_eligibility_inference": False,
        "production_selection_authorized": False,
    }
    values["signal_sha256"] = _canonical_sha256(values)
    return PolicyReviewSignal.model_validate(values)


def _audit_context_exclusions(
    expected: PolicyAuditContext,
    observed: PolicyAuditContext,
) -> set[PolicyExclusionReason]:
    reasons: set[PolicyExclusionReason] = set()
    if expected.intended_use is not observed.intended_use:
        reasons.add(PolicyExclusionReason.USE_PURPOSE_RESTRICTED)
    if expected.audit_scope_sha256 != observed.audit_scope_sha256:
        reasons.add(PolicyExclusionReason.AUDIT_SCOPE_RESTRICTED)
    if (
        expected.source_sha256 != observed.source_sha256
        or expected.source_classification is not observed.source_classification
    ):
        reasons.add(PolicyExclusionReason.SOURCE_RESTRICTED)
    if expected.client_entity_sha256 != observed.client_entity_sha256:
        reasons.add(PolicyExclusionReason.CLIENT_ENTITY_RESTRICTED)
    if expected.client_jurisdiction != observed.client_jurisdiction:
        reasons.add(PolicyExclusionReason.CLIENT_JURISDICTION_RESTRICTED)
    if expected.operator_entity_sha256 != observed.operator_entity_sha256:
        reasons.add(PolicyExclusionReason.OPERATOR_ENTITY_RESTRICTED)
    if expected.operator_jurisdiction != observed.operator_jurisdiction:
        reasons.add(PolicyExclusionReason.OPERATOR_JURISDICTION_RESTRICTED)
    return reasons


def _determination_context_exclusions(
    determination: ModelPolicyEligibilityDetermination,
    context: PolicyAuditContext,
) -> set[PolicyExclusionReason]:
    reasons: set[PolicyExclusionReason] = set()
    if determination.intended_use is not context.intended_use:
        reasons.add(PolicyExclusionReason.USE_PURPOSE_RESTRICTED)
    if context.client_entity_sha256 not in determination.applicable_client_entity_sha256s:
        reasons.add(PolicyExclusionReason.CLIENT_ENTITY_RESTRICTED)
    if context.client_jurisdiction not in determination.applicable_client_jurisdictions:
        reasons.add(PolicyExclusionReason.CLIENT_JURISDICTION_RESTRICTED)
    if context.operator_entity_sha256 not in determination.applicable_operator_entity_sha256s:
        reasons.add(PolicyExclusionReason.OPERATOR_ENTITY_RESTRICTED)
    if context.operator_jurisdiction not in determination.applicable_operator_jurisdictions:
        reasons.add(PolicyExclusionReason.OPERATOR_JURISDICTION_RESTRICTED)
    return reasons


def _client_route_exclusions(
    constraints: ClientPolicyConstraints,
    route: PolicyEligibilityRoute,
) -> set[PolicyExclusionReason]:
    reasons: set[PolicyExclusionReason] = set()
    route_identities = {item.identity for item in constraints.exact_routes}
    if constraints.mode is ClientConstraintMode.ALLOW_ONLY:
        if constraints.provider_names and route.provider_name not in constraints.provider_names:
            reasons.add(PolicyExclusionReason.CLIENT_PROVIDER_RESTRICTED)
        if constraints.exact_model_ids and route.exact_model_id not in constraints.exact_model_ids:
            reasons.add(PolicyExclusionReason.CLIENT_MODEL_RESTRICTED)
        if constraints.exact_routes and route.identity not in route_identities:
            reasons.add(PolicyExclusionReason.CLIENT_ENDPOINT_RESTRICTED)
    else:
        if route.provider_name in constraints.provider_names:
            reasons.add(PolicyExclusionReason.CLIENT_PROVIDER_RESTRICTED)
        if route.exact_model_id in constraints.exact_model_ids:
            reasons.add(PolicyExclusionReason.CLIENT_MODEL_RESTRICTED)
        if route.identity in route_identities:
            reasons.add(PolicyExclusionReason.CLIENT_ENDPOINT_RESTRICTED)
    return reasons


def _build_exclusion(
    route: PolicyEligibilityRoute,
    reasons: set[PolicyExclusionReason],
    determination: ModelPolicyEligibilityDetermination | None,
) -> PolicyEligibilityExclusion:
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "route": route,
        "reasons": tuple(sorted(reasons, key=lambda item: item.value)),
        "determination_sha256": (
            None if determination is None else determination.determination_sha256
        ),
    }
    values["exclusion_sha256"] = _canonical_sha256(values)
    return PolicyEligibilityExclusion.model_validate(values)


def _require_canonical_determinations(
    determinations: tuple[ModelPolicyEligibilityDetermination, ...],
) -> None:
    identities = tuple(item.route.identity for item in determinations)
    if identities != tuple(sorted(set(identities))):
        raise ValueError("policy determinations must be unique and sorted by exact route")


def _require_canonical_routes(
    routes: tuple[PolicyEligibilityRoute, ...],
    *,
    label: str,
) -> None:
    identities = tuple(item.identity for item in routes)
    if identities != tuple(sorted(set(identities))):
        raise ValueError(f"{label} must be unique and sorted")


def _canonical_hashes(
    values: tuple[str, ...],
    *,
    label: str,
    allow_empty: bool,
) -> tuple[str, ...]:
    if not allow_empty and not values:
        raise ValueError(f"{label} cannot be empty")
    if any(
        len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
        for value in values
    ):
        raise ValueError(f"{label} must contain SHA-256 digests")
    if values != tuple(sorted(set(values))):
        raise ValueError(f"{label} must be unique and sorted")
    return values


def _require_canonical_source_reference_observations(
    values: tuple[PolicyEligibilitySourceReferenceObservation, ...],
    *,
    label: str,
) -> None:
    references = tuple(item.reference_sha256 for item in values)
    if references != tuple(sorted(set(references))):
        raise ValueError(f"{label} must be exact, unique, and sorted by reference SHA-256")


def _canonical_jurisdictions(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    if any(re.fullmatch(_JURISDICTION_PATTERN, value) is None for value in values):
        raise ValueError(f"{label} must contain bounded jurisdiction codes")
    if values != tuple(sorted(set(values))):
        raise ValueError(f"{label} must be unique and sorted")
    return values


def _canonical_printable(value: str, *, label: str) -> str:
    if value != value.strip() or any(not character.isprintable() for character in value):
        raise ValueError(f"{label} must be canonical printable text")
    return value


def _whole_second_utc(value: datetime, *, label: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
        or value.microsecond != 0
    ):
        raise ValueError(f"{label} must be a whole-second UTC timestamp")
    return value.astimezone(UTC)


def _require_literal_bool(value: object, *, label: str) -> object:
    if type(value) is not bool:
        raise ValueError(f"{label} must be a literal boolean")
    return value


def _strict_copy[ModelT: BaseModel](model_type: type[ModelT], value: ModelT) -> ModelT:
    return model_type.model_validate_json(value.model_dump_json(), strict=True)


def _require_self_hash(model: BaseModel, field: str, *, label: str) -> None:
    expected = _canonical_sha256(model.model_dump(mode="json", exclude={field}))
    if getattr(model, field) != expected:
        raise ValueError(f"{label} self-hash is inconsistent")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            _canonical_json_value(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _canonical_json_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _canonical_json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_json_value(item) for item in value]
    return value


__all__ = [
    "ClientConstraintMode",
    "ClientPolicyConstraints",
    "ModelPolicyEligibilityArtifact",
    "ModelPolicyEligibilityDetermination",
    "OfficialPolicyEvidenceReference",
    "PolicyAuditContext",
    "PolicyCriterionAssessment",
    "PolicyCriterionDisposition",
    "PolicyEligibilityDecision",
    "PolicyEligibilityEvaluation",
    "PolicyEligibilityExclusion",
    "PolicyEligibilityRoute",
    "PolicyEligibilitySourceReferenceObservation",
    "PolicyEvidenceKind",
    "PolicyExclusionReason",
    "PolicyLegalCriterion",
    "PolicyReviewReason",
    "PolicyReviewSignal",
    "PolicyUsePurpose",
    "build_client_policy_constraints",
    "build_model_policy_eligibility_artifact",
    "build_model_policy_eligibility_determination",
    "build_official_policy_evidence_reference",
    "build_policy_audit_context",
    "build_policy_criterion_assessment",
    "build_policy_eligibility_route",
    "build_policy_eligibility_source_reference_observation",
    "evaluate_model_policy_eligibility",
    "policy_eligibility_candidate_routes_sha256",
    "policy_review_signal",
]
