"""Bounded asynchronous OpenRouter client with structured-output validation."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import math
import random
import re
import sys
import time
import uuid
from collections.abc import Callable, Coroutine, Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation, localcontext
from functools import lru_cache
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, Any, Literal, Protocol, Self, TypeVar, cast
from urllib.parse import quote
from weakref import WeakKeyDictionary

import httpcore
import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from pydantic_core import SchemaValidator

from mmaudit.config import ExecutionConfig, PrivacyConfig, TokenBudgetConfig, model_family
from mmaudit.constants import OPENROUTER_DEFAULT_BASE_URL, VERSION
from mmaudit.models.discovery import (
    _TRUSTED_OPENROUTER_DISCOVERY_ISSUER,
    OPENROUTER_API_IDENTITY,
    OPENROUTER_CATALOG_QUERY,
    OPENROUTER_ZDR_QUERY,
    DiscoveryCandidateRoute,
    DiscoveryEndpointMetadataBinding,
    DiscoveryModelMetadataBinding,
    OpenRouterDiscoveryRunProvenance,
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryPayload,
    OpenRouterModelDiscoveryRunManifest,
    _issue_real_openrouter_discovery_run,
    openrouter_endpoint_query,
    openrouter_model_query,
    validate_openrouter_model_discovery,
)
from mmaudit.models.endpoint_snapshots import (
    OpenRouterEndpointSnapshotEvidence,
    OpenRouterReasoningCapabilityEvidence,
    validate_openrouter_endpoint_snapshot,
)
from mmaudit.models.generation_evidence import (
    MAX_GENERATION_EVIDENCE_RETRIEVAL_ATTEMPTS,
    GenerationEvidenceValidationError,
    GenerationReconciliationExpectation,
    GenerationReconciliationMismatchCode,
    GenerationReconciliationMismatchError,
    GenerationVerificationRequest,
    OpenRouterGenerationEvidence,
    TrustedGenerationVerification,
    _attest_authrunner_generation_origin,
    _issue_trusted_generation_verification,
    _reconcile_generation_evidence_structural,
    _register_authrunner_generation_origin_issuer,
    validate_generation_id,
    validate_openrouter_generation_payload,
)
from mmaudit.models.identifiers import (
    is_exact_openrouter_model_id,
    is_openrouter_catalog_model_id,
)
from mmaudit.models.identity import (
    OpenRouterGenerationIdentityEvidence,
    OpenRouterIdentityBindingResult,
    OpenRouterIdentityDiagnosticCode,
    OpenRouterIdentityEndpointCapabilities,
    OpenRouterIdentityPricingEntry,
    OpenRouterModelEndpointIdentitySnapshot,
    OpenRouterRequestIdentityEvidence,
    seal_bound_openrouter_identity,
    seal_openrouter_identity_provider_policy,
    seal_openrouter_model_endpoint_identity_snapshot,
    seal_unbound_openrouter_identity,
)
from mmaudit.models.output_modes import (
    REASONING_REQUEST_PARAMETER,
    STRUCTURED_OUTPUT_PROTOCOL_VERSION,
    StructuredOutputMode,
    output_mode_capability_parameters,
    output_mode_request_parameters,
    structured_output_parameters,
    supports_provider_structured_output,
    supports_reasoning_request,
)
from mmaudit.models.reasoning import (
    CANONICAL_REASONING_POLICY_ROLES,
    REASONING_EFFORT_ORDER,
    ReasoningControlProfile,
    ReasoningEffort,
    ReasoningExecutionEvidence,
    ReasoningPolicyArtifact,
    ReasoningPolicyError,
    ReasoningRequestPlanEvidence,
    reasoning_policy_roles_for_qualified_role,
    resolve_reasoning_request_role,
)

if TYPE_CHECKING:
    from mmaudit.models.coverage_planning import (
        ModelSurfaceGapTask,
        ModelSurfaceTaskResourcePreview,
    )
    from mmaudit.models.policy_eligibility import (
        ClientPolicyConstraints,
        PolicyAuditContext,
    )
    from mmaudit.models.policy_selection import (
        AuditModelRoutingEvidence,
        VerifiedAuditModelSelection,
    )
    from mmaudit.models.qualification import VerifiedProductionQualification
    from mmaudit.models.refresh_runtime import (
        AuditModelRefreshEvidence,
        AuditModelRefreshPricingEvidence,
        AuditModelRefreshPricingRouteEvidence,
        AuditModelRefreshRouteEvidence,
        VerifiedAuditModelRefreshGuard,
        VerifiedAuditModelRefreshPricingAuthority,
    )
    from mmaudit.models.scheduler import SchedulerCampaignManifest, SchedulerTaskPlan
    from mmaudit.repository.privacy_provenance import PrivacySourceProvenanceObservation
from mmaudit.models.schemas import (
    AuditModelRefreshPricingAttemptEvidence,
    CandidateReviewBatch,
    ContextPackage,
    ContextRequestEvidence,
    ExecutionEvidenceKind,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    StructuredOutputResponseFormat,
    UsageRecord,
    seal_structured_output_evidence,
    structured_output_request_shape_sha256,
)
from mmaudit.models.structured_output import (
    StructuredOutputDecodeError,
    StructuredOutputDecodeResult,
    StructuredOutputFailureCode,
    StructuredOutputRepairEvidence,
    _decode_structured_output_with_schema_generation,
)
from mmaudit.models.token_planning import (
    PROMPT_ALLOCATION_CATEGORIES,
    ContextOmissionItem,
    ContextTokenPlanError,
    EndpointRouteIntersection,
    EndpointRouteTokenCapacity,
    EndpointTokenCapacityError,
    GlobalTokenBudgetPlanningError,
    PromptAllocationCategory,
    PromptTokenAllocation,
    RequestTokenPlan,
    TokenPlanningError,
    build_output_token_allocations,
    build_request_token_plan,
)
from mmaudit.models.truncation import (
    _CANONICAL_JSON_DUMPS as _CANDIDATE_REVIEW_CANONICAL_JSON_DUMPS,
)
from mmaudit.models.truncation import (
    CandidateReviewFramedDocument,
    CandidateReviewNormalizationEvidence,
    CandidateReviewTruncatedEnvelopeEvidence,
    CandidateReviewTruncationError,
    CandidateReviewTruncationProjection,
    candidate_review_batch_schema_sha256,
    candidate_review_frame_wire_schema_sha256,
    candidate_review_protocol_implementation_is_pristine,
    decode_complete_candidate_review_document,
    frame_candidate_review_batch,
    normalize_candidate_review_document,
    project_truncated_candidate_review_prefix,
    seal_candidate_review_truncated_envelope_evidence,
)
from mmaudit.models.usage import (
    UsageLedger,
    _attest_authrunner_owned_real_usage_origin,
    _attest_owned_real_usage_record,
    _authrunner_usage_origin_scope,
    _has_owned_real_usage_attestation,
    _register_authrunner_owned_real_usage_origin_issuer,
    _validated_usage_copy_preserving_owned_attestation,
)
from mmaudit.orchestration.budgets import (
    BudgetExhaustedError,
    BudgetManager,
    BudgetReservationStateError,
    EndpointPriceComponent,
    EndpointRequestCostBound,
    Reservation,
    UnprovenCostBoundError,
    _classmethod_function,
    _property_getter,
    _require_pristine_endpoint_cost_bound_types,
    _require_trusted_budget_accounting_state,
    _trusted_endpoint_request_cost_bound_from_pricing,
    _trusted_endpoint_request_maximum_cost_usd,
    _trusted_endpoint_request_maximum_units_for,
    _TrustedRequestLimitScope,
)
from mmaudit.orchestration.context_manifest import (
    ContextPlanningSnapshot,
    ContextPreflightLedger,
    ContextPreflightReason,
    ContextPreflightRequestEvidence,
    ContextPreflightSource,
    ContextRequestState,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.privacy import (
    EffectivePrivacyPolicyEvidence,
    EndpointPolicyClass,
    PrivacySourceClassification,
    TrustedPrivacyAuthorization,
    validate_trusted_privacy_authorization,
)
from mmaudit.reporting.json_report import stable_json

ResponseT = TypeVar("ResponseT", bound=BaseModel)

_TRUSTED_CANDIDATE_REVIEW_FRAMED_DOCUMENT_TYPE = CandidateReviewFramedDocument
_TRUSTED_CANDIDATE_REVIEW_NORMALIZATION_EVIDENCE_TYPE = CandidateReviewNormalizationEvidence
_TRUSTED_CANDIDATE_REVIEW_TRUNCATION_PROJECTION_TYPE = CandidateReviewTruncationProjection
_TRUSTED_CANDIDATE_REVIEW_TRUNCATED_ENVELOPE_EVIDENCE_TYPE = (
    CandidateReviewTruncatedEnvelopeEvidence
)
_TRUSTED_CANDIDATE_REVIEW_USAGE_RECORD_TYPE = UsageRecord
_TRUSTED_CANDIDATE_REVIEW_WIRE_SCHEMA_SHA256 = candidate_review_frame_wire_schema_sha256
_TRUSTED_CANDIDATE_REVIEW_BATCH_SCHEMA_SHA256 = candidate_review_batch_schema_sha256
_TRUSTED_CANDIDATE_REVIEW_PROTOCOL_IMPLEMENTATION_IS_PRISTINE = (
    candidate_review_protocol_implementation_is_pristine
)
_TRUSTED_DECODE_COMPLETE_CANDIDATE_REVIEW_DOCUMENT = decode_complete_candidate_review_document
_TRUSTED_FRAME_CANDIDATE_REVIEW_BATCH = frame_candidate_review_batch
_TRUSTED_NORMALIZE_CANDIDATE_REVIEW_DOCUMENT = normalize_candidate_review_document
_TRUSTED_PROJECT_TRUNCATED_CANDIDATE_REVIEW_PREFIX = project_truncated_candidate_review_prefix
_TRUSTED_SEAL_CANDIDATE_REVIEW_TRUNCATED_ENVELOPE_EVIDENCE = (
    seal_candidate_review_truncated_envelope_evidence
)


def _candidate_review_protocol_boundary_is_pristine() -> bool:
    """Reject mutable parser/schema aliases before they can govern spend or credit."""

    from mmaudit.models import truncation as truncation_module

    return bool(
        truncation_module.CandidateReviewFramedDocument
        is _TRUSTED_CANDIDATE_REVIEW_FRAMED_DOCUMENT_TYPE
        and truncation_module.CandidateReviewNormalizationEvidence
        is _TRUSTED_CANDIDATE_REVIEW_NORMALIZATION_EVIDENCE_TYPE
        and truncation_module.CandidateReviewTruncationProjection
        is _TRUSTED_CANDIDATE_REVIEW_TRUNCATION_PROJECTION_TYPE
        and truncation_module.CandidateReviewTruncatedEnvelopeEvidence
        is _TRUSTED_CANDIDATE_REVIEW_TRUNCATED_ENVELOPE_EVIDENCE_TYPE
        and truncation_module.candidate_review_frame_wire_schema_sha256
        is _TRUSTED_CANDIDATE_REVIEW_WIRE_SCHEMA_SHA256
        and truncation_module.candidate_review_batch_schema_sha256
        is _TRUSTED_CANDIDATE_REVIEW_BATCH_SCHEMA_SHA256
        and truncation_module.candidate_review_protocol_implementation_is_pristine
        is _TRUSTED_CANDIDATE_REVIEW_PROTOCOL_IMPLEMENTATION_IS_PRISTINE
        and _TRUSTED_CANDIDATE_REVIEW_PROTOCOL_IMPLEMENTATION_IS_PRISTINE()
        and truncation_module.decode_complete_candidate_review_document
        is _TRUSTED_DECODE_COMPLETE_CANDIDATE_REVIEW_DOCUMENT
        and truncation_module.frame_candidate_review_batch is _TRUSTED_FRAME_CANDIDATE_REVIEW_BATCH
        and truncation_module.normalize_candidate_review_document
        is _TRUSTED_NORMALIZE_CANDIDATE_REVIEW_DOCUMENT
        and truncation_module.project_truncated_candidate_review_prefix
        is _TRUSTED_PROJECT_TRUNCATED_CANDIDATE_REVIEW_PREFIX
        and truncation_module.seal_candidate_review_truncated_envelope_evidence
        is _TRUSTED_SEAL_CANDIDATE_REVIEW_TRUNCATED_ENVELOPE_EVIDENCE
        and OpenRouterTruncatedResponseError._attach_projection
        is _TRUSTED_ATTACH_CANDIDATE_REVIEW_TRUNCATION_PROJECTION
        and OpenRouterTruncatedResponseError._attach_failed_usage_record
        is _TRUSTED_ATTACH_CANDIDATE_REVIEW_TRUNCATED_USAGE
        and OpenRouterTruncatedResponseError.projection
        is _TRUSTED_CANDIDATE_REVIEW_TRUNCATION_PROJECTION_PROPERTY
        and OpenRouterTruncatedResponseError.envelope_evidence
        is _TRUSTED_CANDIDATE_REVIEW_TRUNCATED_ENVELOPE_PROPERTY
        and OpenRouterTruncatedResponseError.failed_usage_record
        is _TRUSTED_CANDIDATE_REVIEW_TRUNCATED_USAGE_PROPERTY
        and _candidate_review_error_custody_is_coherent
        is _TRUSTED_CANDIDATE_REVIEW_ERROR_CUSTODY_IS_COHERENT
        and _candidate_review_truncation_projection_routing
        is _TRUSTED_CANDIDATE_REVIEW_TRUNCATION_PROJECTION_ROUTING
        and _candidate_review_truncated_envelope_routing
        is _TRUSTED_CANDIDATE_REVIEW_TRUNCATED_ENVELOPE_ROUTING
        and UsageRecord is _TRUSTED_CANDIDATE_REVIEW_USAGE_RECORD_TYPE
        and UsageRecord.__pydantic_validator__ is _TRUSTED_CANDIDATE_REVIEW_USAGE_RECORD_VALIDATOR
        and UsageRecord.__pydantic_core_schema__
        is _TRUSTED_CANDIDATE_REVIEW_USAGE_RECORD_CORE_SCHEMA
        and OpenRouterClient._failure_routing_evidence is _TRUSTED_FAILURE_ROUTING_EVIDENCE
    )


_NORMALIZED_OPENROUTER_BASE_URL = OPENROUTER_DEFAULT_BASE_URL.rstrip("/") + "/"
_PROVIDER_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,127}$")
_LOGICAL_REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_QUALIFICATION_PROVIDER_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/()&+-]{0,199}$")
_NON_DIRECT_ROUTING_STRATEGIES = {
    "alias",
    "auto",
    "bodybuilder",
    "fallback",
    "free",
    "fusion",
    "latest",
    "pareto",
}
_TRUNCATED_FINISH_REASONS = {
    "content_filter",
    "error",
    "length",
    "max_tokens",
    "max_tokens_exceeded",
    "token_limit_exceeded",
}
_SUPPORTED_TEXT_PRICING_FIELDS = frozenset(
    {
        "completion",
        "image",
        "input_cache_read",
        "input_cache_write",
        "internal_reasoning",
        "prompt",
        "request",
        "web_search",
    }
)
_ROUTER_MAX_PRICE_FIELDS = frozenset({"completion", "image", "prompt", "request"})
_PER_MILLION_ROUTER_PRICE_FIELDS = frozenset({"completion", "prompt"})
_MUTABLE_IDENTITY_TTL = timedelta(days=7)
_MAX_RETAINED_UNBOUND_COMPLETIONS = 512
_GENERATION_METADATA_POLL_DELAYS_SECONDS = (0.0, 1.0, 3.0, 7.0, 15.0, 30.0, 60.0)
_MAXIMUM_GENERATION_METADATA_WAIT_SECONDS = sum(_GENERATION_METADATA_POLL_DELAYS_SECONDS)
_MINIMUM_GENERATION_METADATA_IO_BUDGET_SECONDS = 0.05
_MAXIMUM_GENERATION_METADATA_IO_BUDGET_SECONDS = 15.0
_GENERATION_METADATA_IO_BUDGET_FRACTION = 0.25
_MAX_TRUSTED_GENERATION_VERIFICATION_REQUESTS = 512
_UNENFORCEABLE_VARIABLE_PRICING_FIELDS = frozenset(
    {
        "input_cache_write",
        "internal_reasoning",
    }
)
# OpenRouter bills cache reads as a discounted prompt-token input dimension.  A route is
# admissible only when that snapshot discount is no greater than its fresh prompt price.
# The transmitted ``provider.max_price.prompt`` then supplies the conservative unit ceiling.
_PROMPT_DOMINATED_PRICING_FIELDS = frozenset({"input_cache_read"})
_TRUSTED_ASYNC_CLIENT_SEND = httpx.AsyncClient.send
_TRUSTED_ASYNC_CLIENT_GETATTRIBUTE = httpx.AsyncClient.__getattribute__
_TRUSTED_ASYNC_CLIENT_REQUEST = httpx.AsyncClient.request
_TRUSTED_ASYNC_CLIENT_STREAM = httpx.AsyncClient.stream
_TRUSTED_ASYNC_CLIENT_BUILD_REQUEST = httpx.AsyncClient.build_request
_TRUSTED_ASYNC_CLIENT_MERGE_URL = httpx.AsyncClient._merge_url
_TRUSTED_ASYNC_CLIENT_BUILD_REQUEST_AUTH = httpx.AsyncClient._build_request_auth
_TRUSTED_ASYNC_CLIENT_SEND_HANDLING_AUTH = httpx.AsyncClient._send_handling_auth
_TRUSTED_ASYNC_CLIENT_SEND_HANDLING_REDIRECTS = httpx.AsyncClient._send_handling_redirects
_TRUSTED_ASYNC_CLIENT_TRANSPORT_FOR_URL = httpx.AsyncClient._transport_for_url
_TRUSTED_ASYNC_CLIENT_SEND_SINGLE_REQUEST = httpx.AsyncClient._send_single_request
_TRUSTED_ASYNC_HTTP_TRANSPORT_REQUEST = httpx.AsyncHTTPTransport.handle_async_request
_TRUSTED_ASYNC_HTTP_TRANSPORT_GETATTRIBUTE = httpx.AsyncHTTPTransport.__getattribute__
_TRUSTED_MOCK_TRANSPORT_REQUEST = httpx.MockTransport.handle_async_request
_TRUSTED_MOCK_TRANSPORT_GETATTRIBUTE = httpx.MockTransport.__getattribute__
_TRUSTED_ANYIO_BACKEND_TYPE = httpcore.AnyIOBackend
_TRUSTED_ANYIO_BACKEND_GETATTRIBUTE = httpcore.AnyIOBackend.__getattribute__
_TRUSTED_ANYIO_CONNECT_TCP = httpcore.AnyIOBackend.connect_tcp
_TRUSTED_ANYIO_CONNECT_UNIX_SOCKET = httpcore.AnyIOBackend.connect_unix_socket
_TRUSTED_ANYIO_SLEEP = httpcore.AnyIOBackend.sleep
_QUALIFICATION_FUTURE_SKEW = timedelta(minutes=5)
_QUALIFICATION_LINEAGE_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_QUALIFICATION_ROLE_PATTERN = re.compile(r"^[a-z][a-z0-9_:.-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_COST_DECIMAL_PATTERN = re.compile(r"^(?:0|[1-9][0-9]{0,47})(?:\.[0-9]{1,48})?$")
_PREQUALIFICATION_PROVIDER_ROLES = frozenset({"model_benchmark", "real_provider_smoke"})
_BASE_ENDPOINT_REQUEST_PARAMETERS = frozenset({"max_tokens", "temperature"})
_ROUTE_SENSITIVE_REQUEST_PARAMETERS = frozenset({"reasoning", "response_format"})
_LOCAL_MOCK_PROVIDER_ENDPOINT = "mmaudit-local-mock"
_MAX_TOKEN_EVIDENCE = 2**31 - 1
_REPORTED_COST_USD_QUANTUM = Decimal("1e-18")
_REPORTED_COST_USD_MAGNITUDE_LIMIT = Decimal("1e12")
_CHAT_TEMPLATE_FRAMING_RESERVE_TOKENS = 256
_CONTEXT_PREVIEW_ENVELOPE_RESERVE_TOKENS = 16_384


@dataclass(frozen=True)
class OpenRouterProviderPolicy:
    """Explicit provider routing policy for one exact OpenRouter model."""

    certification: bool = False
    only: tuple[str, ...] = ()
    order: tuple[str, ...] = ()
    allow_fallbacks: bool = False

    def __post_init__(self) -> None:
        if self.only and self.order:
            raise ValueError("provider routing must use either only or order, not both")
        for label, providers in (("only", self.only), ("order", self.order)):
            if len(providers) != len(set(providers)):
                raise ValueError(f"provider.{label} must contain unique endpoints")
            if any(not _PROVIDER_ID_PATTERN.fullmatch(provider) for provider in providers):
                raise ValueError(f"provider.{label} contains an invalid endpoint identifier")
        if self.certification and not (self.only or self.order):
            raise ValueError("certification requires an explicit provider endpoint allowlist")
        if self.certification and self.allow_fallbacks:
            raise ValueError("certification cannot allow provider fallbacks")

    @property
    def configured_endpoints(self) -> tuple[str, ...]:
        return self.only or self.order

    def as_request_payload(
        self,
        *,
        require_zdr: bool,
        require_parameters: bool = True,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "allow_fallbacks": self.allow_fallbacks,
            "data_collection": "deny",
        }
        if require_parameters:
            payload["require_parameters"] = True
        if require_zdr:
            payload["zdr"] = True
        if self.only:
            payload["only"] = list(self.only)
        elif self.order:
            payload["order"] = list(self.order)
        return payload


def _canonical_provider_policy(
    policy: OpenRouterProviderPolicy,
) -> OpenRouterProviderPolicy:
    """Copy caller-owned routing state into one validated immutable snapshot."""

    if not isinstance(policy, OpenRouterProviderPolicy):
        raise OpenRouterProviderPolicyError("provider routing policy has an invalid type")
    certification = policy.certification
    only_source = policy.only
    order_source = policy.order
    allow_fallbacks = policy.allow_fallbacks
    if type(certification) is not bool or type(allow_fallbacks) is not bool:
        raise OpenRouterProviderPolicyError("provider routing booleans must be explicit")
    try:
        only = tuple(only_source)
        order = tuple(order_source)
    except (TypeError, ValueError):
        raise OpenRouterProviderPolicyError("provider routing endpoints are invalid") from None
    if any(type(endpoint) is not str for endpoint in (*only, *order)):
        raise OpenRouterProviderPolicyError("provider routing endpoint identifiers must be strings")
    try:
        return OpenRouterProviderPolicy(
            certification=certification,
            only=only,
            order=order,
            allow_fallbacks=allow_fallbacks,
        )
    except ValueError as exc:
        raise OpenRouterProviderPolicyError(f"provider routing policy is invalid: {exc}") from None


def _canonical_effective_privacy_policy(
    evidence: EffectivePrivacyPolicyEvidence,
) -> EffectivePrivacyPolicyEvidence:
    """Return a strict defensive copy of self-validating privacy evidence."""

    if type(evidence) is not EffectivePrivacyPolicyEvidence:
        raise OpenRouterPrivacyError("effective privacy evidence has an invalid type")
    try:
        return EffectivePrivacyPolicyEvidence.model_validate(
            evidence.model_dump(mode="python"),
            strict=True,
        )
    except (AttributeError, ValidationError):
        raise OpenRouterPrivacyError("effective privacy evidence is invalid") from None


def _validate_live_privacy_source_provenance(
    observation: PrivacySourceProvenanceObservation,
    *,
    policy: EffectivePrivacyPolicyEvidence,
) -> PrivacySourceProvenanceObservation:
    """Revalidate the live opaque provenance behind one effective privacy policy."""

    from mmaudit.repository.privacy_provenance import (
        validate_privacy_source_provenance_observation,
    )

    try:
        evidence = validate_privacy_source_provenance_observation(
            observation,
            source_sha256=policy.source_sha256,
            source_classification=policy.source_classification,
        )
    except (TypeError, ValueError) as exc:
        raise OpenRouterPrivacyError(f"live privacy source provenance is invalid: {exc}") from None
    if (
        evidence.evidence_sha256 != policy.source_provenance_sha256
        or evidence.proof_kind != policy.source_proof_kind
        or evidence.distribution_commit != policy.source_distribution_commit
        or evidence.distribution_scope != policy.source_distribution_scope
        or evidence.synthetic_declaration_sha256 != policy.source_synthetic_declaration_sha256
        or evidence.synthetic_declaration_entry_sha256
        != policy.source_synthetic_declaration_entry_sha256
    ):
        raise OpenRouterPrivacyError(
            "live privacy source provenance differs from effective privacy evidence"
        )
    return observation


def _model_request_privacy_binding(
    evidence: EffectivePrivacyPolicyEvidence | None,
) -> ModelRequestPrivacyBinding | None:
    """Project one canonical in-memory privacy policy for lifecycle comparison."""

    if evidence is None:
        return None
    policy = _canonical_effective_privacy_policy(evidence)
    return ModelRequestPrivacyBinding(
        source_sha256=policy.source_sha256,
        effective_policy_sha256=policy.evidence_sha256,
        source_provenance_sha256=policy.source_provenance_sha256,
    )


@dataclass(frozen=True, slots=True)
class OpenRouterQualifiedReasoningRoutingBinding:
    """Cycle-free projection of one exact qualified reasoning role/profile join."""

    exact_model_id: str
    approved_provider_endpoint: str
    approved_provider_name: str
    qualified_role: str
    configured_policy_role: str
    control_profile: ReasoningControlProfile
    control_profile_sha256: str
    reasoning_policy_artifact_sha256: str
    reasoning_policy_role_binding_sha256: str
    endpoint_reasoning_capability_sha256: str
    reasoning_benchmark_report_sha256: str
    reasoning_benchmark_verification_sha256: str
    reasoning_benchmark_fresh_evidence_sha256: str
    qualification_report_sha256: str
    qualification_result_sha256: str
    qualification_verification_sha256: str
    binding_sha256: str
    schema_version: Literal["1.0"] = "1.0"
    binding_status: Literal["exact_evidence_bound"] = "exact_evidence_bound"
    selection_authority: Literal[False] = False

    def __post_init__(self) -> None:
        _require_exact_model_id(self.exact_model_id)
        if _PROVIDER_ID_PATTERN.fullmatch(self.approved_provider_endpoint) is None:
            raise ValueError("reasoning qualification provider endpoint is malformed")
        if _QUALIFICATION_PROVIDER_NAME_PATTERN.fullmatch(self.approved_provider_name) is None:
            raise ValueError("reasoning qualification provider name is malformed")
        if _QUALIFICATION_ROLE_PATTERN.fullmatch(self.qualified_role) is None:
            raise ValueError("reasoning qualification role is malformed")
        if self.configured_policy_role not in CANONICAL_REASONING_POLICY_ROLES:
            raise ValueError("reasoning qualification policy role is unknown")
        if type(self.control_profile) is not ReasoningControlProfile:
            raise ValueError("reasoning qualification control profile has an invalid type")
        validated_profile = ReasoningControlProfile.model_validate(
            self.control_profile.model_dump(mode="json")
        )
        if validated_profile.profile_sha256 != self.control_profile_sha256:
            raise ValueError("reasoning qualification control profile binding is inconsistent")
        for value in (
            self.control_profile_sha256,
            self.reasoning_policy_artifact_sha256,
            self.reasoning_policy_role_binding_sha256,
            self.endpoint_reasoning_capability_sha256,
            self.reasoning_benchmark_report_sha256,
            self.reasoning_benchmark_verification_sha256,
            self.reasoning_benchmark_fresh_evidence_sha256,
            self.qualification_report_sha256,
            self.qualification_result_sha256,
            self.qualification_verification_sha256,
            self.binding_sha256,
        ):
            if _SHA256_PATTERN.fullmatch(value) is None:
                raise ValueError("reasoning qualification contains a malformed evidence hash")
        if self.binding_sha256 != _canonical_sha256(self._canonical_payload()):
            raise ValueError("reasoning qualification binding self-hash is inconsistent")

    def _canonical_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "binding_status": self.binding_status,
            "selection_authority": self.selection_authority,
            "exact_model_id": self.exact_model_id,
            "approved_provider_endpoint": self.approved_provider_endpoint,
            "approved_provider_name": self.approved_provider_name,
            "qualified_role": self.qualified_role,
            "configured_policy_role": self.configured_policy_role,
            "control_profile": self.control_profile.model_dump(mode="json"),
            "control_profile_sha256": self.control_profile_sha256,
            "reasoning_policy_artifact_sha256": self.reasoning_policy_artifact_sha256,
            "reasoning_policy_role_binding_sha256": (self.reasoning_policy_role_binding_sha256),
            "endpoint_reasoning_capability_sha256": (self.endpoint_reasoning_capability_sha256),
            "reasoning_benchmark_report_sha256": self.reasoning_benchmark_report_sha256,
            "reasoning_benchmark_verification_sha256": (
                self.reasoning_benchmark_verification_sha256
            ),
            "reasoning_benchmark_fresh_evidence_sha256": (
                self.reasoning_benchmark_fresh_evidence_sha256
            ),
            "qualification_report_sha256": self.qualification_report_sha256,
            "qualification_result_sha256": self.qualification_result_sha256,
            "qualification_verification_sha256": self.qualification_verification_sha256,
        }

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
        reasoning_benchmark_report_sha256: str,
        reasoning_benchmark_verification_sha256: str,
        reasoning_benchmark_fresh_evidence_sha256: str,
        qualification_report_sha256: str,
        qualification_result_sha256: str,
        qualification_verification_sha256: str,
    ) -> str:
        """Return this hash only when the exact production request is qualified."""

        expected = {
            "exact_model_id": exact_model_id,
            "approved_provider_endpoint": approved_provider_endpoint,
            "approved_provider_name": approved_provider_name,
            "qualified_role": qualified_role,
            "configured_policy_role": configured_policy_role,
            "control_profile_sha256": control_profile.profile_sha256,
            "reasoning_policy_artifact_sha256": reasoning_policy_artifact_sha256,
            "reasoning_policy_role_binding_sha256": reasoning_policy_role_binding_sha256,
            "endpoint_reasoning_capability_sha256": endpoint_reasoning_capability_sha256,
            "reasoning_benchmark_report_sha256": reasoning_benchmark_report_sha256,
            "reasoning_benchmark_verification_sha256": (reasoning_benchmark_verification_sha256),
            "reasoning_benchmark_fresh_evidence_sha256": (
                reasoning_benchmark_fresh_evidence_sha256
            ),
            "qualification_report_sha256": qualification_report_sha256,
            "qualification_result_sha256": qualification_result_sha256,
            "qualification_verification_sha256": qualification_verification_sha256,
        }
        observed = {
            "exact_model_id": self.exact_model_id,
            "approved_provider_endpoint": self.approved_provider_endpoint,
            "approved_provider_name": self.approved_provider_name,
            "qualified_role": self.qualified_role,
            "configured_policy_role": self.configured_policy_role,
            "control_profile_sha256": self.control_profile_sha256,
            "reasoning_policy_artifact_sha256": self.reasoning_policy_artifact_sha256,
            "reasoning_policy_role_binding_sha256": (self.reasoning_policy_role_binding_sha256),
            "endpoint_reasoning_capability_sha256": (self.endpoint_reasoning_capability_sha256),
            "reasoning_benchmark_report_sha256": self.reasoning_benchmark_report_sha256,
            "reasoning_benchmark_verification_sha256": (
                self.reasoning_benchmark_verification_sha256
            ),
            "reasoning_benchmark_fresh_evidence_sha256": (
                self.reasoning_benchmark_fresh_evidence_sha256
            ),
            "qualification_report_sha256": self.qualification_report_sha256,
            "qualification_result_sha256": self.qualification_result_sha256,
            "qualification_verification_sha256": self.qualification_verification_sha256,
        }
        if any(observed[key] != value for key, value in expected.items()):
            raise OpenRouterQualificationError(
                "reasoning qualification does not match the exact production request"
            )
        if self.control_profile != ReasoningControlProfile.model_validate(
            control_profile.model_dump(mode="json")
        ):
            raise OpenRouterQualificationError(
                "reasoning qualification control profile differs from production"
            )
        return self.binding_sha256


@dataclass(frozen=True, slots=True)
class OpenRouterQualificationRoutingEvidence:
    """Sanitized, non-authoritative routing projection of verified qualification."""

    exact_model_id: str
    canonical_model_slug: str
    root_lineage: str
    approved_provider_endpoint: str
    approved_provider_name: str
    endpoint_snapshot_sha256: str
    output_capability_sha256: str
    structured_output_mode: StructuredOutputMode
    model_metadata_snapshot_sha256: str
    pricing_snapshot_sha256: str
    approved_roles: tuple[str, ...]
    verified_at: datetime
    expires_at: datetime
    qualification_artifact_sha256: str
    qualification_verification_sha256: str
    production_selection_sha256: str
    selection_verification_sha256: str
    qualification_result_sha256: str
    benchmark_report_sha256: str
    reasoning_bindings: tuple[OpenRouterQualifiedReasoningRoutingBinding, ...] = ()

    def __post_init__(self) -> None:
        _require_exact_model_id(self.exact_model_id)
        _require_exact_model_id(self.canonical_model_slug)
        if _QUALIFICATION_LINEAGE_PATTERN.fullmatch(self.root_lineage) is None:
            raise ValueError("qualification routing root lineage is malformed")
        if _PROVIDER_ID_PATTERN.fullmatch(self.approved_provider_endpoint) is None:
            raise ValueError("qualification routing provider endpoint is malformed")
        if _QUALIFICATION_PROVIDER_NAME_PATTERN.fullmatch(self.approved_provider_name) is None:
            raise ValueError("qualification routing provider name is malformed")
        if type(self.structured_output_mode) is not StructuredOutputMode:
            raise ValueError("qualification routing structured-output mode is invalid")
        if (
            not self.approved_roles
            or self.approved_roles != tuple(sorted(set(self.approved_roles)))
            or any(
                _QUALIFICATION_ROLE_PATTERN.fullmatch(role) is None for role in self.approved_roles
            )
        ):
            raise ValueError("qualification routing roles must be non-empty, safe, and sorted")
        if self.verified_at.tzinfo is None or self.verified_at.utcoffset() != timedelta(0):
            raise ValueError("qualification routing verification time must be UTC")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() != timedelta(0):
            raise ValueError("qualification routing expiry must be UTC")
        if self.expires_at <= self.verified_at:
            raise ValueError("qualification routing expiry must follow verification")
        for value in (
            self.qualification_artifact_sha256,
            self.qualification_verification_sha256,
            self.production_selection_sha256,
            self.selection_verification_sha256,
            self.qualification_result_sha256,
            self.benchmark_report_sha256,
            self.endpoint_snapshot_sha256,
            self.output_capability_sha256,
            self.model_metadata_snapshot_sha256,
            self.pricing_snapshot_sha256,
        ):
            if _SHA256_PATTERN.fullmatch(value) is None:
                raise ValueError("qualification routing contains a malformed evidence hash")
        reasoning_routes = tuple(
            (binding.qualified_role, binding.configured_policy_role)
            for binding in self.reasoning_bindings
        )
        try:
            expected_reasoning_routes = tuple(
                sorted(
                    (
                        qualified_role,
                        configured_policy_role,
                    )
                    for qualified_role in self.approved_roles
                    for configured_policy_role in reasoning_policy_roles_for_qualified_role(
                        qualified_role
                    )
                )
            )
        except ReasoningPolicyError as exc:
            raise ValueError("qualification routing contains an unsupported approved role") from exc
        if reasoning_routes != expected_reasoning_routes:
            raise ValueError(
                "qualification routing reasoning bindings must cover every approved role route"
            )
        if any(
            binding.exact_model_id != self.exact_model_id
            or binding.approved_provider_endpoint != self.approved_provider_endpoint
            or binding.approved_provider_name != self.approved_provider_name
            or binding.qualification_report_sha256 != self.benchmark_report_sha256
            or binding.qualification_result_sha256 != self.qualification_result_sha256
            or binding.qualification_verification_sha256 != self.qualification_verification_sha256
            for binding in self.reasoning_bindings
        ):
            raise ValueError("qualification routing reasoning bindings differ from their chain")

    def require_current(
        self,
        *,
        role: str,
        model: str,
        provider_endpoints: tuple[str, ...],
        now: datetime,
        endpoint_policy: _RegisteredEndpointPolicy | None = None,
        model_identity: _RegisteredModelIdentity | None = None,
        require_runtime_snapshots: bool = False,
    ) -> None:
        """Fail closed on stale or mismatched per-request routing authority."""

        if model != self.exact_model_id:
            raise OpenRouterQualificationError(
                "qualification routing does not bind the exact requested model"
            )
        if _qualification_role(role) not in self.approved_roles:
            raise OpenRouterQualificationError(
                "qualification routing does not approve the requested review role"
            )
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise OpenRouterQualificationError("qualification routing check requires UTC")
        if self.verified_at > now + _QUALIFICATION_FUTURE_SKEW:
            raise OpenRouterQualificationError("qualification routing evidence is future-dated")
        if self.expires_at <= now:
            raise OpenRouterQualificationError("qualification routing evidence is expired")
        if self.approved_provider_endpoint not in provider_endpoints:
            raise OpenRouterQualificationError(
                "qualification provider endpoint is outside the configured allowlist"
            )
        if require_runtime_snapshots and (endpoint_policy is None or model_identity is None):
            raise OpenRouterQualificationError(
                "qualified production routing requires current model and endpoint snapshots"
            )
        if endpoint_policy is not None:
            endpoint = endpoint_policy.endpoint(self.approved_provider_endpoint)
            if (
                endpoint_policy.snapshot_sha256 != self.endpoint_snapshot_sha256
                or endpoint_policy.output_capability_sha256 != self.output_capability_sha256
                or endpoint_policy.structured_output_mode is not self.structured_output_mode
                or endpoint is None
                or endpoint.pricing_sha256 != self.pricing_snapshot_sha256
            ):
                raise OpenRouterQualificationError(
                    "current endpoint or pricing snapshot differs from qualification"
                )
        if model_identity is not None and (
            model_identity.exact_model_id != self.exact_model_id
            or model_identity.canonical_slug != self.canonical_model_slug
            or model_identity.model_metadata_snapshot_sha256 != self.model_metadata_snapshot_sha256
            or model_identity.snapshot.endpoint_capabilities.output_capability_sha256
            != self.output_capability_sha256
            or model_identity.snapshot.endpoint_capabilities.structured_output_mode
            is not self.structured_output_mode
        ):
            raise OpenRouterQualificationError(
                "current model identity snapshot differs from qualification"
            )

    def request_provider_policy(self) -> OpenRouterProviderPolicy:
        """Return the exact singleton provider route authorized for this model."""

        return OpenRouterProviderPolicy(
            certification=True,
            only=(self.approved_provider_endpoint,),
            allow_fallbacks=False,
        )

    def reasoning_binding_sha256_for(
        self,
        *,
        role: str,
        control_profile: ReasoningControlProfile,
        reasoning_policy: ReasoningPolicyArtifact,
        endpoint_capability_sha256: str,
    ) -> str:
        """Require exact role/profile/capability qualification before production use."""

        try:
            resolution = resolve_reasoning_request_role(role)
        except ReasoningPolicyError as exc:
            raise OpenRouterQualificationError(
                "reasoning qualification received an unknown exact review role"
            ) from exc
        matches = tuple(
            binding
            for binding in self.reasoning_bindings
            if binding.qualified_role == resolution.qualification_role
            and binding.configured_policy_role == resolution.configured_policy_role
        )
        if len(matches) != 1:
            raise OpenRouterQualificationError(
                "exact review role lacks one qualified reasoning profile"
            )
        return matches[0].require_exact(
            exact_model_id=self.exact_model_id,
            approved_provider_endpoint=self.approved_provider_endpoint,
            approved_provider_name=self.approved_provider_name,
            qualified_role=resolution.qualification_role,
            configured_policy_role=resolution.configured_policy_role,
            control_profile=control_profile,
            reasoning_policy_artifact_sha256=reasoning_policy.artifact_sha256,
            reasoning_policy_role_binding_sha256=(
                reasoning_policy.role_policy(resolution.configured_policy_role).binding_sha256
            ),
            endpoint_reasoning_capability_sha256=endpoint_capability_sha256,
            reasoning_benchmark_report_sha256=(matches[0].reasoning_benchmark_report_sha256),
            reasoning_benchmark_verification_sha256=(
                matches[0].reasoning_benchmark_verification_sha256
            ),
            reasoning_benchmark_fresh_evidence_sha256=(
                matches[0].reasoning_benchmark_fresh_evidence_sha256
            ),
            qualification_report_sha256=self.benchmark_report_sha256,
            qualification_result_sha256=self.qualification_result_sha256,
            qualification_verification_sha256=self.qualification_verification_sha256,
        )

    def request_metadata(self) -> dict[str, str]:
        """Return bounded non-secret hashes for OpenRouter request metadata."""

        return {
            "mmaudit_qualification_artifact_sha256": self.qualification_artifact_sha256,
            "mmaudit_qualification_verification_sha256": (self.qualification_verification_sha256),
            "mmaudit_production_selection_sha256": self.production_selection_sha256,
            "mmaudit_selection_verification_sha256": self.selection_verification_sha256,
            "mmaudit_qualification_result_sha256": self.qualification_result_sha256,
            "mmaudit_qualification_report_sha256": self.benchmark_report_sha256,
            "mmaudit_qualified_endpoint_snapshot_sha256": self.endpoint_snapshot_sha256,
            "mmaudit_qualified_output_capability_sha256": (self.output_capability_sha256),
            "mmaudit_qualified_output_mode": self.structured_output_mode.value,
            "mmaudit_qualified_model_metadata_sha256": self.model_metadata_snapshot_sha256,
            "mmaudit_qualified_pricing_snapshot_sha256": self.pricing_snapshot_sha256,
        }

    def routing_evidence(self) -> dict[str, Any]:
        """Return the sanitized binding joined into durable usage evidence."""

        return {
            "qualified_exact_model_id": self.exact_model_id,
            "qualified_canonical_model_slug": self.canonical_model_slug,
            "qualified_root_lineage": self.root_lineage,
            "qualified_provider_endpoint": self.approved_provider_endpoint,
            "qualified_provider_name": self.approved_provider_name,
            "qualified_endpoint_snapshot_sha256": self.endpoint_snapshot_sha256,
            "qualified_output_capability_sha256": self.output_capability_sha256,
            "qualified_structured_output_mode": self.structured_output_mode.value,
            "qualified_model_metadata_snapshot_sha256": self.model_metadata_snapshot_sha256,
            "qualified_pricing_snapshot_sha256": self.pricing_snapshot_sha256,
            "qualified_roles": list(self.approved_roles),
            "qualification_verified_at": self.verified_at.isoformat(),
            "qualification_expires_at": self.expires_at.isoformat(),
            "qualification_artifact_sha256": self.qualification_artifact_sha256,
            "qualification_verification_sha256": self.qualification_verification_sha256,
            "production_selection_sha256": self.production_selection_sha256,
            "selection_verification_sha256": self.selection_verification_sha256,
            "qualification_result_sha256": self.qualification_result_sha256,
            "benchmark_report_sha256": self.benchmark_report_sha256,
            "qualified_reasoning_binding_sha256": [
                binding.binding_sha256 for binding in self.reasoning_bindings
            ],
        }


def _require_exact_qualification_routing_authority(
    *,
    routing: tuple[OpenRouterQualificationRoutingEvidence, ...],
    qualification: VerifiedProductionQualification,
    now: datetime,
) -> VerifiedProductionQualification:
    """Join the public routing projection to resolver-issued opaque authority."""

    # Local import avoids openrouter -> qualification -> benchmark -> openrouter at import time.
    from mmaudit.models.qualification import VerifiedProductionQualification

    if type(qualification) is not VerifiedProductionQualification:
        raise OpenRouterQualificationError(
            "production qualification authority has an invalid opaque type"
        )
    try:
        verified = qualification.require_current(now=now)
    except ValueError as exc:
        raise OpenRouterQualificationError(
            "production qualification authority is invalid or stale"
        ) from exc
    expected_model_ids = tuple(model.exact_model_id for model in verified.models)
    observed_model_ids = tuple(binding.exact_model_id for binding in routing)
    if observed_model_ids != expected_model_ids:
        raise OpenRouterQualificationError(
            "qualification routing does not exactly project the opaque model set"
        )
    for projected, model in zip(routing, verified.models, strict=True):
        expected = {
            "exact_model_id": model.exact_model_id,
            "canonical_model_slug": model.canonical_model_slug,
            "root_lineage": model.root_lineage,
            "approved_provider_endpoint": model.approved_provider_endpoint,
            "approved_provider_name": model.approved_provider_name,
            "endpoint_snapshot_sha256": model.endpoint_snapshot_sha256,
            "output_capability_sha256": model.output_capability_sha256,
            "structured_output_mode": model.structured_output_mode,
            "model_metadata_snapshot_sha256": model.model_metadata_snapshot_sha256,
            "pricing_snapshot_sha256": model.pricing_snapshot_sha256,
            "approved_roles": model.approved_roles,
            "verified_at": verified.verified_at,
            "expires_at": model.expires_at,
            "qualification_artifact_sha256": verified.artifact_sha256,
            "qualification_verification_sha256": (verified.qualification_verification_sha256),
            "production_selection_sha256": verified.production_selection_sha256,
            "selection_verification_sha256": verified.selection_verification_sha256,
            "qualification_result_sha256": model.qualification_result_sha256,
            "benchmark_report_sha256": model.benchmark_report_sha256,
        }
        if any(getattr(projected, field) != value for field, value in expected.items()):
            raise OpenRouterQualificationError(
                "qualification routing differs from opaque production authority"
            )
        projected_routes = tuple(
            (binding.qualified_role, binding.configured_policy_role)
            for binding in projected.reasoning_bindings
        )
        authority_routes = tuple(
            (binding.qualified_role, binding.configured_policy_role)
            for binding in model.reasoning_bindings
        )
        if projected_routes != authority_routes:
            raise OpenRouterQualificationError(
                "reasoning routing differs from opaque production authority"
            )
        for projected_reasoning, authority_reasoning in zip(
            projected.reasoning_bindings,
            model.reasoning_bindings,
            strict=True,
        ):
            reasoning_expected = {
                "exact_model_id": authority_reasoning.exact_model_id,
                "approved_provider_endpoint": (authority_reasoning.approved_provider_endpoint),
                "approved_provider_name": authority_reasoning.approved_provider_name,
                "qualified_role": authority_reasoning.qualified_role,
                "configured_policy_role": authority_reasoning.configured_policy_role,
                "control_profile": authority_reasoning.control_profile,
                "control_profile_sha256": authority_reasoning.control_profile_sha256,
                "reasoning_policy_artifact_sha256": (
                    authority_reasoning.reasoning_policy_artifact_sha256
                ),
                "reasoning_policy_role_binding_sha256": (
                    authority_reasoning.reasoning_policy_role_binding_sha256
                ),
                "endpoint_reasoning_capability_sha256": (
                    authority_reasoning.endpoint_reasoning_capability_sha256
                ),
                "reasoning_benchmark_report_sha256": (
                    authority_reasoning.reasoning_benchmark_report_sha256
                ),
                "reasoning_benchmark_verification_sha256": (
                    authority_reasoning.reasoning_benchmark_verification_sha256
                ),
                "reasoning_benchmark_fresh_evidence_sha256": (
                    authority_reasoning.reasoning_benchmark_fresh_evidence_sha256
                ),
                "qualification_report_sha256": (authority_reasoning.qualification_report_sha256),
                "qualification_result_sha256": (authority_reasoning.qualification_result_sha256),
                "qualification_verification_sha256": (
                    authority_reasoning.qualification_verification_sha256
                ),
                "binding_sha256": authority_reasoning.binding_sha256,
            }
            if any(
                getattr(projected_reasoning, field) != value
                for field, value in reasoning_expected.items()
            ):
                raise OpenRouterQualificationError(
                    "reasoning routing differs from opaque production authority"
                )
    return verified


def _require_exact_audit_model_selection_authority(
    *,
    selection: VerifiedAuditModelSelection,
    binding: _OpenRouterAuditPolicyBinding,
    now: datetime,
) -> VerifiedAuditModelSelection:
    """Require one resolver-issued, current audit-scoped selection capability."""

    # Local import avoids openrouter -> policy_selection -> manifest -> agents -> openrouter
    # at module-import time.
    from mmaudit.models.policy_selection import VerifiedAuditModelSelection

    if type(selection) is not VerifiedAuditModelSelection:
        raise OpenRouterPolicyEligibilityError(
            "audit model selection authority has an invalid opaque type"
        )
    try:
        verified = selection.require_current(
            now=now,
            expected_audit_scope_sha256=binding.audit_context.audit_scope_sha256,
            expected_source_sha256=binding.audit_context.source_sha256,
            expected_audit_context_sha256=binding.audit_context.context_sha256,
            expected_client_constraints_sha256=(binding.client_constraints.constraints_sha256),
        )
    except ValueError as exc:
        raise OpenRouterPolicyEligibilityError(
            f"audit model selection authority rejected use: {exc}"
        ) from exc
    if verified is not selection:
        raise OpenRouterPolicyEligibilityError(
            "audit model selection authority returned a different capability"
        )
    return verified


@dataclass(frozen=True, slots=True)
class _OpenRouterAuditPolicyBinding:
    """Independent current audit facts supplied by the request-owning runtime."""

    audit_context: PolicyAuditContext
    client_constraints: ClientPolicyConstraints


@dataclass(frozen=True, slots=True)
class _OpenRouterAuditModelRefreshBinding:
    """Atomic durable evidence and opaque veto guard supplied by the audit runtime."""

    evidence: AuditModelRefreshEvidence
    guard: VerifiedAuditModelRefreshGuard


@dataclass(frozen=True, slots=True)
class _OpenRouterAuditModelRefreshPricingBinding:
    """Atomic durable price evidence and its exact opaque live authority."""

    evidence: AuditModelRefreshPricingEvidence
    authority: VerifiedAuditModelRefreshPricingAuthority


@dataclass(frozen=True, slots=True)
class _AuditModelRefreshPricingRequestControl:
    """One immutable current-price input shared by routing and accounting."""

    exact_model_id: str
    provider_endpoint: str
    current_endpoint_snapshot_sha256: str
    qualified_pricing_snapshot_sha256: str
    current_pricing: tuple[tuple[str, str], ...]
    current_pricing_sha256: str
    route_evidence_sha256: str
    evidence_sha256: str
    authority_capability_sha256: str
    routing_max_price: tuple[tuple[str, float], ...]
    cost_bound_pricing: tuple[tuple[str, str], ...]
    control_sha256: str


def _canonical_audit_model_refresh_binding(
    *,
    evidence: AuditModelRefreshEvidence | None,
    guard: VerifiedAuditModelRefreshGuard | None,
) -> _OpenRouterAuditModelRefreshBinding | None:
    """Copy non-authorizing evidence while retaining the exact opaque live guard."""

    from mmaudit.models.refresh_runtime import (
        AuditModelRefreshEvidence,
        VerifiedAuditModelRefreshGuard,
    )

    if evidence is None and guard is None:
        return None
    if evidence is None or guard is None:
        raise OpenRouterModelRefreshError(
            "audit model refresh requires both durable evidence and its opaque live guard"
        )
    if type(evidence) is not AuditModelRefreshEvidence:
        raise OpenRouterModelRefreshError("audit model refresh evidence has an invalid type")
    if type(guard) is not VerifiedAuditModelRefreshGuard:
        raise OpenRouterModelRefreshError("audit model refresh guard is absent or forged")
    try:
        canonical = AuditModelRefreshEvidence.model_validate_json(
            evidence.model_dump_json(),
            strict=True,
        )
    except (AttributeError, ValueError) as exc:
        raise OpenRouterModelRefreshError(
            "audit model refresh evidence is structurally invalid"
        ) from exc
    if canonical != evidence:
        raise OpenRouterModelRefreshError(
            "audit model refresh evidence changed during canonicalization"
        )
    return _OpenRouterAuditModelRefreshBinding(evidence=canonical, guard=guard)


def _canonical_audit_model_refresh_pricing_binding(
    *,
    evidence: AuditModelRefreshPricingEvidence | None,
    authority: VerifiedAuditModelRefreshPricingAuthority | None,
    refresh_binding: _OpenRouterAuditModelRefreshBinding | None,
) -> _OpenRouterAuditModelRefreshPricingBinding | None:
    """Copy pricing evidence while retaining the exact opaque authority identity."""

    from mmaudit.models.refresh_runtime import (
        AuditModelRefreshPricingEvidence,
        VerifiedAuditModelRefreshPricingAuthority,
    )

    if evidence is None and authority is None:
        return None
    if evidence is None or authority is None:
        raise OpenRouterModelRefreshPricingError(
            "audit model refresh pricing requires durable evidence and opaque authority"
        )
    if refresh_binding is None:
        raise OpenRouterModelRefreshPricingError(
            "audit model refresh pricing requires exact refresh evidence and live guard"
        )
    if type(evidence) is not AuditModelRefreshPricingEvidence:
        raise OpenRouterModelRefreshPricingError(
            "audit model refresh pricing evidence has an invalid type"
        )
    if type(authority) is not VerifiedAuditModelRefreshPricingAuthority:
        raise OpenRouterModelRefreshPricingError(
            "audit model refresh pricing authority is absent or forged"
        )
    try:
        canonical = AuditModelRefreshPricingEvidence.model_validate_json(
            evidence.model_dump_json(),
            strict=True,
        )
    except (AttributeError, ValueError) as exc:
        raise OpenRouterModelRefreshPricingError(
            "audit model refresh pricing evidence is structurally invalid"
        ) from exc
    try:
        exact_refresh_custody = (
            canonical == evidence
            and canonical.refresh_evidence_sha256 == refresh_binding.evidence.evidence_sha256
            and canonical.refresh_guard_capability_sha256 == refresh_binding.guard.capability_sha256
            and authority.pricing_evidence_sha256 == canonical.evidence_sha256
            and authority.refresh_evidence_sha256 == refresh_binding.evidence.evidence_sha256
            and authority.refresh_guard_capability_sha256 == refresh_binding.guard.capability_sha256
        )
    except AttributeError as exc:
        raise OpenRouterModelRefreshPricingError(
            "audit model refresh pricing authority is incomplete or forged"
        ) from exc
    if not exact_refresh_custody:
        raise OpenRouterModelRefreshPricingError(
            "audit model refresh pricing differs from its exact refresh custody"
        )
    return _OpenRouterAuditModelRefreshPricingBinding(
        evidence=canonical,
        authority=authority,
    )


def _canonical_audit_policy_binding(
    *,
    policy_audit_context: PolicyAuditContext | None,
    client_policy_constraints: ClientPolicyConstraints | None,
    effective_privacy_policy: EffectivePrivacyPolicyEvidence | None,
) -> _OpenRouterAuditPolicyBinding | None:
    """Validate audit facts independently of any model-selection capability."""

    from mmaudit.models.policy_eligibility import (
        ClientPolicyConstraints,
        PolicyAuditContext,
        PolicyUsePurpose,
    )

    if policy_audit_context is None and client_policy_constraints is None:
        return None
    if policy_audit_context is None or client_policy_constraints is None:
        raise OpenRouterPolicyEligibilityError(
            "audit model selection requires both audit context and client constraints"
        )
    if (
        type(policy_audit_context) is not PolicyAuditContext
        or type(client_policy_constraints) is not ClientPolicyConstraints
    ):
        raise OpenRouterPolicyEligibilityError(
            "audit policy runtime binding has an invalid evidence type"
        )
    try:
        context = PolicyAuditContext.model_validate_json(
            policy_audit_context.model_dump_json(),
            strict=True,
        )
        constraints = ClientPolicyConstraints.model_validate_json(
            client_policy_constraints.model_dump_json(),
            strict=True,
        )
    except (AttributeError, ValueError) as exc:
        raise OpenRouterPolicyEligibilityError(
            "audit policy runtime binding is structurally invalid"
        ) from exc
    if (
        context != policy_audit_context
        or constraints != client_policy_constraints
        or constraints.audit_context != context
        or context.intended_use is not PolicyUsePurpose.PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT
    ):
        raise OpenRouterPolicyEligibilityError(
            "audit policy runtime binding differs from the exact paid audit context"
        )
    if effective_privacy_policy is None:
        raise OpenRouterPolicyEligibilityError(
            "audit policy runtime binding requires effective privacy evidence"
        )
    canonical_privacy_policy = _canonical_effective_privacy_policy(effective_privacy_policy)
    if canonical_privacy_policy != effective_privacy_policy:
        raise OpenRouterPolicyEligibilityError(
            "effective privacy evidence changed during audit policy binding"
        )
    if (
        canonical_privacy_policy.source_sha256 != context.source_sha256
        or canonical_privacy_policy.source_classification is not context.source_classification
    ):
        raise OpenRouterPolicyEligibilityError(
            "audit policy source differs from the effective privacy request source"
        )
    return _OpenRouterAuditPolicyBinding(
        audit_context=context,
        client_constraints=constraints,
    )


@dataclass(frozen=True)
class OpenRouterReasoning:
    """Bounded reasoning controls supported by OpenRouter."""

    effort: ReasoningEffort | None = None
    max_tokens: int | None = None
    exclude: bool = False

    def __post_init__(self) -> None:
        if self.effort is not None and self.effort not in REASONING_EFFORT_ORDER:
            raise ValueError("reasoning effort is not supported")
        if self.effort is not None and self.max_tokens is not None:
            raise ValueError("reasoning effort and max_tokens are mutually exclusive")
        if self.max_tokens is not None and not 1 <= self.max_tokens <= 65_536:
            raise ValueError("reasoning max_tokens must be between 1 and 65536")

    def as_request_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"exclude": self.exclude}
        if self.effort is not None:
            payload["effort"] = self.effort
        if self.max_tokens is not None:
            payload["max_tokens"] = self.max_tokens
        return payload


@dataclass(frozen=True)
class CompletionEnvelope:
    requested_model: str
    generation_id: str
    returned_model: str
    selected_model: str
    provider: str
    finish_reason: str
    native_finish_reason: str | None
    content: str
    usage: dict[str, Any]
    router_metadata: dict[str, Any]
    selected_provider: str
    selected_provider_identity: str
    selected_provider_name: str
    response_provider_identity: str | None
    router_attempt: int
    router_attempt_count: int
    router_attempts_observed: bool
    pipeline: tuple[dict[str, str], ...]


@dataclass(frozen=True, slots=True)
class StructuredCompletion[ValueT: BaseModel]:
    """Validated structured response paired with its exact provider evidence."""

    value: ValueT
    usage_record: UsageRecord


@dataclass(frozen=True, slots=True)
class CandidateReviewCompletion:
    """Normalized review plus exact wire-schema and transformation custody."""

    value: CandidateReviewBatch
    usage_record: UsageRecord
    normalization_evidence: CandidateReviewNormalizationEvidence

    def __post_init__(self) -> None:
        if (
            type(self.value) is not CandidateReviewBatch
            or type(self.usage_record) is not UsageRecord
            or type(self.normalization_evidence)
            is not _TRUSTED_CANDIDATE_REVIEW_NORMALIZATION_EVIDENCE_TYPE
        ):
            raise TypeError("candidate-review completion custody has an invalid exact type")
        evidence = self.normalization_evidence
        if (
            self.usage_record.schema_sha256 != _TRUSTED_CANDIDATE_REVIEW_WIRE_SCHEMA_SHA256()
            or self.usage_record.schema_sha256 != evidence.wire_schema_sha256
            or self.usage_record.validated_response_sha256
            != evidence.wire_validated_response_sha256
            or evidence.normalized_batch_schema_sha256
            != _TRUSTED_CANDIDATE_REVIEW_BATCH_SCHEMA_SHA256()
        ):
            raise ValueError("candidate-review completion wire custody is inconsistent")
        evidence.require_exact_batch(
            self.value,
            request_id=self.usage_record.request_id,
        )


@dataclass(frozen=True, slots=True)
class _StructuredOutputRequestPlan:
    """Exact provider request shape selected from frozen endpoint capability."""

    mode: StructuredOutputMode
    system_prompt: str
    user_prompt: str
    response_format: dict[str, Any] | None
    reasoning_payload: dict[str, Any] | None
    required_provider_parameters: tuple[str, ...]
    require_parameters: bool
    reasoning_request_sha256: str | None
    strict_protocol_sha256: str | None
    schema_sha256: str
    request_shape_sha256: str


@dataclass(frozen=True)
class _RegisteredEndpointPricing:
    provider_endpoint: str
    provider_name: str
    provider_identities: tuple[str, ...]
    endpoint_tag: str | None
    endpoint_slug: str | None
    operational_status: str
    zdr_eligible: bool | None
    pricing: tuple[tuple[str, str], ...]
    pricing_sha256: str
    snapshot_sha256: str
    context_length: int
    max_prompt_tokens: int
    max_prompt_tokens_source: Literal["metadata", "context_limit"]
    max_completion_tokens: int
    max_completion_tokens_source: Literal["metadata", "context_limit"]
    supported_parameters: tuple[str, ...]
    required_request_parameters: tuple[str, ...]
    structured_output_parameters: tuple[str, ...]
    supported_output_modes: tuple[StructuredOutputMode, ...]
    structured_output_mode: StructuredOutputMode


@dataclass(frozen=True)
class _RegisteredEndpointPolicy:
    snapshot_sha256: str
    policy_pricing_sha256: str
    routing_max_price: tuple[tuple[str, float], ...]
    endpoints: tuple[_RegisteredEndpointPricing, ...]
    structured_output_parameters: tuple[str, ...]
    supported_output_modes: tuple[StructuredOutputMode, ...]
    structured_output_mode: StructuredOutputMode
    output_capability_sha256: str

    def endpoint(self, provider_identity: str) -> _RegisteredEndpointPricing | None:
        normalized = provider_identity.casefold()
        matches = [
            endpoint
            for endpoint in self.endpoints
            if normalized in {identity.casefold() for identity in endpoint.provider_identities}
        ]
        return matches[0] if len(matches) == 1 else None


@dataclass(frozen=True)
class _RegisteredModelIdentity:
    exact_model_id: str
    canonical_slug: str
    model_metadata_snapshot_sha256: str
    catalog_identity_binding_sha256: str
    catalog_snapshot_sha256: str
    discovery_provenance_sha256: str
    discovery_evidence_sha256: str
    discovery_manifest_sha256: str | None
    snapshot: OpenRouterModelEndpointIdentitySnapshot

    @property
    def accepted_response_models(self) -> frozenset[str]:
        return frozenset(self.snapshot.frozen_aliases)


class OpenRouterError(RuntimeError):
    """Base provider error containing no source excerpts."""


class OpenRouterAuthenticationError(OpenRouterError):
    pass


class OpenRouterTransientError(OpenRouterError):
    pass


class OpenRouterTimeoutError(OpenRouterTransientError):
    pass


class OpenRouterRateLimitError(OpenRouterTransientError):
    pass


class OpenRouterProviderUnavailableError(OpenRouterTransientError):
    pass


class OpenRouterSchemaError(OpenRouterError):
    pass


class OpenRouterStructuredOutputError(OpenRouterSchemaError):
    """Typed, raw-value-free rejection from strict local response decoding."""

    def __init__(
        self,
        *,
        failure_code: StructuredOutputFailureCode,
        repair_evidence: StructuredOutputRepairEvidence | None = None,
    ) -> None:
        self.failure_code = failure_code
        self.repair_evidence = repair_evidence
        super().__init__(f"model returned invalid structured data ({failure_code.value})")


class OpenRouterCandidateReviewBoundaryError(OpenRouterSchemaError):
    """The frozen candidate-review parser/normalizer boundary changed in-process."""


class OpenRouterTruncatedResponseError(OpenRouterSchemaError):
    """Confirmed truncation with optional raw-free provisional recovery custody."""

    def __init__(
        self,
        message: str,
        *,
        envelope_evidence: CandidateReviewTruncatedEnvelopeEvidence | None = None,
    ) -> None:
        if envelope_evidence is not None:
            if (
                type(envelope_evidence)
                is not _TRUSTED_CANDIDATE_REVIEW_TRUNCATED_ENVELOPE_EVIDENCE_TYPE
                or not _candidate_review_protocol_boundary_is_pristine()
            ):
                raise TypeError("candidate-review truncated envelope custody has an invalid type")
            try:
                envelope_evidence = (
                    _TRUSTED_CANDIDATE_REVIEW_TRUNCATED_ENVELOPE_EVIDENCE_TYPE.model_validate_json(
                        envelope_evidence.model_dump_json(),
                        strict=True,
                    )
                )
            except (TypeError, ValueError):
                raise OpenRouterSchemaError(
                    "candidate-review truncated envelope custody is invalid"
                ) from None
        self._envelope_evidence = envelope_evidence
        self._projection: CandidateReviewTruncationProjection | None = None
        self._failed_usage_record: UsageRecord | None = None
        super().__init__(message)

    @property
    def envelope_evidence(self) -> CandidateReviewTruncatedEnvelopeEvidence | None:
        _candidate_review_error_custody_is_coherent(self)
        return self._envelope_evidence

    @property
    def projection(self) -> CandidateReviewTruncationProjection | None:
        _candidate_review_error_custody_is_coherent(self)
        return self._projection

    @property
    def failed_usage_record(self) -> UsageRecord | None:
        _candidate_review_error_custody_is_coherent(self)
        return self._failed_usage_record

    def _attach_projection(self, projection: CandidateReviewTruncationProjection) -> None:
        if (
            self._projection is not None
            or type(projection) is not _TRUSTED_CANDIDATE_REVIEW_TRUNCATION_PROJECTION_TYPE
            or not _candidate_review_protocol_boundary_is_pristine()
        ):
            raise OpenRouterSchemaError("candidate-review truncation projection is invalid")
        try:
            exact_projection = (
                _TRUSTED_CANDIDATE_REVIEW_TRUNCATION_PROJECTION_TYPE.model_validate_json(
                    projection.model_dump_json(),
                    strict=True,
                )
            )
        except (TypeError, ValueError):
            raise OpenRouterSchemaError(
                "candidate-review truncation projection is invalid"
            ) from None
        self._projection = exact_projection
        try:
            _candidate_review_error_custody_is_coherent(self)
        except OpenRouterSchemaError:
            self._projection = None
            raise

    def _attach_failed_usage_record(self, usage: UsageRecord) -> None:
        if (
            self._failed_usage_record is not None
            or type(usage) is not UsageRecord
            or not _candidate_review_protocol_boundary_is_pristine()
        ):
            raise OpenRouterSchemaError("candidate-review truncated usage custody is invalid")
        try:
            _TRUSTED_CANDIDATE_REVIEW_USAGE_RECORD_VALIDATOR.validate_python(
                usage.model_dump(mode="python"),
                strict=True,
            )
        except (TypeError, ValueError):
            raise OpenRouterSchemaError(
                "candidate-review truncated usage custody is invalid"
            ) from None
        self._failed_usage_record = usage
        try:
            _candidate_review_error_custody_is_coherent(self)
        except OpenRouterSchemaError:
            self._failed_usage_record = None
            raise


def _candidate_review_truncated_envelope_routing(
    envelope: CandidateReviewTruncatedEnvelopeEvidence,
) -> dict[str, Any]:
    """Return the complete raw-free typed envelope inventory for failed usage."""

    return {
        "candidate_review_truncated_envelope_evidence": envelope.model_dump(mode="json"),
        "candidate_review_truncated_envelope_sha256": envelope.evidence_sha256,
    }


def _candidate_review_truncation_projection_routing(
    projection: CandidateReviewTruncationProjection,
) -> dict[str, Any]:
    """Return only non-record projection state needed to join failed usage custody."""

    return {
        "candidate_review_truncation_projection_sha256": projection.evidence_sha256,
        "candidate_review_truncation_termination": projection.termination.value,
        "candidate_review_truncation_findings_state": projection.findings_state.value,
        "candidate_review_truncation_surface_reviews_state": (
            projection.surface_reviews_state.value
        ),
        "candidate_review_truncation_summary_state": projection.summary_state.value,
        "candidate_review_truncation_stream_integrity_valid": (projection.stream_integrity_valid),
        "candidate_review_truncation_document_complete": projection.document_complete,
        "candidate_review_truncation_declared_finding_count": (projection.declared_finding_count),
        "candidate_review_truncation_declared_surface_review_count": (
            projection.declared_surface_review_count
        ),
        "candidate_review_truncation_observed_frame_count": projection.observed_frame_count,
        "candidate_review_truncation_observed_finding_frame_count": (
            projection.observed_finding_frame_count
        ),
        "candidate_review_truncation_observed_surface_review_frame_count": (
            projection.observed_surface_review_frame_count
        ),
        "candidate_review_truncation_accepted_frame_count": len(projection.accepted_frames),
        "candidate_review_truncation_accepted_finding_count": (projection.accepted_finding_count),
        "candidate_review_truncation_accepted_surface_review_count": (
            projection.accepted_surface_review_count
        ),
        "candidate_review_truncation_invalid_frame_count": projection.invalid_frame_count,
        "candidate_review_truncation_credit_eligible": False,
        "candidate_review_truncation_authority_eligible": False,
    }


def _candidate_review_error_custody_is_coherent(
    error: OpenRouterTruncatedResponseError,
) -> bool:
    """Revalidate every raw-free error join before exposing durable recovery custody."""

    if (
        type(error) is not OpenRouterTruncatedResponseError
        or not _candidate_review_protocol_boundary_is_pristine()
    ):
        raise OpenRouterSchemaError("candidate-review truncation custody boundary changed")
    envelope = error._envelope_evidence
    projection = error._projection
    usage = error._failed_usage_record
    if envelope is None:
        if projection is not None or usage is not None:
            raise OpenRouterSchemaError("candidate-review truncation envelope custody is missing")
        return True
    try:
        exact_envelope = (
            _TRUSTED_CANDIDATE_REVIEW_TRUNCATED_ENVELOPE_EVIDENCE_TYPE.model_validate_json(
                envelope.model_dump_json(),
                strict=True,
            )
        )
    except (AttributeError, TypeError, ValueError):
        raise OpenRouterSchemaError(
            "candidate-review truncation envelope custody is invalid"
        ) from None
    if projection is not None:
        try:
            exact_projection = (
                _TRUSTED_CANDIDATE_REVIEW_TRUNCATION_PROJECTION_TYPE.model_validate_json(
                    projection.model_dump_json(),
                    strict=True,
                )
            )
        except (AttributeError, TypeError, ValueError):
            raise OpenRouterSchemaError(
                "candidate-review truncation projection custody is invalid"
            ) from None
        if (
            exact_projection.original_response_sha256 != exact_envelope.response_sha256
            or exact_projection.wire_schema_sha256 != exact_envelope.wire_schema_sha256
            or exact_projection.finish_reason != exact_envelope.finish_reason
            or exact_projection.native_finish_reason != exact_envelope.native_finish_reason
            or exact_projection.review_credit_eligible
            or exact_projection.coverage_credit_eligible
            or exact_projection.summary_credit_eligible
            or exact_projection.authority_eligible
        ):
            raise OpenRouterSchemaError("candidate-review truncation projection custody differs")
    if usage is None:
        return True
    try:
        _TRUSTED_CANDIDATE_REVIEW_USAGE_RECORD_VALIDATOR.validate_python(
            usage.model_dump(mode="python"),
            strict=True,
        )
    except (AttributeError, TypeError, ValueError):
        raise OpenRouterSchemaError("candidate-review truncated usage custody is invalid") from None
    routing = usage.routing
    expected_envelope_routing = _candidate_review_truncated_envelope_routing(exact_envelope)
    expected_projection_routing = (
        _candidate_review_truncation_projection_routing(exact_projection)
        if projection is not None
        else {}
    )
    actual_projection_keys = {
        key for key in routing if key.startswith("candidate_review_truncation_")
    }
    if (
        usage.request_id != exact_envelope.logical_request_id
        or usage.requested_model != exact_envelope.requested_model
        or usage.returned_model != exact_envelope.returned_model
        or usage.actual_model != exact_envelope.selected_model
        or usage.provider != exact_envelope.selected_provider_name
        or usage.openrouter_generation_id != exact_envelope.generation_id
        or usage.actual_provider_endpoint != exact_envelope.selected_provider_endpoint
        or usage.response_sha256 != exact_envelope.response_sha256
        or usage.schema_sha256 != exact_envelope.wire_schema_sha256
        or usage.finish_reason != exact_envelope.finish_reason
        or usage.validation_status is not ModelRequestValidationStatus.TRUNCATED
        or usage.identity_strength is not ModelIdentityStrength.UNBOUND
        or usage.validated_response_sha256 is not None
        or usage.status != "rejected_truncated_response"
        or routing.get("generation_id") != exact_envelope.generation_id
        or routing.get("generation_header_id") != exact_envelope.generation_header_id
        or routing.get("provider") != exact_envelope.selected_provider_name
        or routing.get("router_metadata_sha256") != exact_envelope.router_metadata_sha256
        or routing.get("finish_reason") != exact_envelope.finish_reason
        or routing.get("native_finish_reason") != exact_envelope.native_finish_reason
        or routing.get("schema_sha256") != exact_envelope.wire_schema_sha256
        or any(routing.get(key) != value for key, value in expected_envelope_routing.items())
        or actual_projection_keys != set(expected_projection_routing)
        or any(routing.get(key) != value for key, value in expected_projection_routing.items())
    ):
        raise OpenRouterSchemaError("candidate-review truncated usage custody differs")
    return True


class OpenRouterPrivacyError(OpenRouterError):
    pass


class OpenRouterModelError(OpenRouterError):
    pass


class OpenRouterGenerationMetadataNotReadyError(OpenRouterModelError):
    """Generation metadata remained unavailable after bounded post-call polling."""


class OpenRouterGenerationReconciliationError(OpenRouterSchemaError):
    """A typed, value-free generation/usage mismatch after bounded observation."""

    def __init__(
        self,
        mismatch_code: GenerationReconciliationMismatchCode,
        *,
        attempts: int,
        exhausted: bool,
        last_evidence: OpenRouterGenerationEvidence | None = None,
    ) -> None:
        if (
            not isinstance(mismatch_code, GenerationReconciliationMismatchCode)
            or not isinstance(attempts, int)
            or isinstance(attempts, bool)
            or not 1 <= attempts <= MAX_GENERATION_EVIDENCE_RETRIEVAL_ATTEMPTS
            or not isinstance(exhausted, bool)
        ):
            raise TypeError("generation reconciliation diagnostic is invalid")
        if last_evidence is not None and not isinstance(
            last_evidence,
            OpenRouterGenerationEvidence,
        ):
            raise TypeError("generation reconciliation evidence is invalid")
        self.mismatch_code = mismatch_code
        self.attempts = attempts
        self.exhausted = exhausted
        self.last_evidence = last_evidence
        disposition = "remained unsettled" if exhausted else "was contradictory"
        super().__init__(
            "OpenRouter generation metadata "
            f"{disposition} for {mismatch_code.name} after {attempts} observation(s)"
        )


class OpenRouterUnboundIdentityError(OpenRouterModelError):
    """A valid structured completion that lacks qualifying identity evidence."""

    def __init__(self, completion: StructuredCompletion[Any]) -> None:
        self.completion = completion
        super().__init__(
            "structured completion identity is unbound; preserve the evidence and retry only "
            "after correcting the relevant frozen or generation identity metadata"
        )


class OpenRouterQualificationError(OpenRouterModelError):
    """Raised when certification lacks current exact qualification routing evidence."""


class OpenRouterPolicyEligibilityError(OpenRouterModelError):
    """Raised when a paid audit route lacks current policy-selection authority."""


class OpenRouterModelRefreshError(OpenRouterPolicyEligibilityError):
    """Raised when a REAL paid route lacks its exact current refresh veto guard."""


class OpenRouterModelRefreshPricingError(OpenRouterModelRefreshError):
    """Raised when a REAL paid route lacks exact refreshed-price authority."""


class OpenRouterProviderPolicyError(OpenRouterModelError):
    pass


class OpenRouterResponseIdentityError(OpenRouterProviderPolicyError):
    """A structurally valid response whose provider identity is contradictory."""

    def __init__(
        self,
        message: str,
        *,
        diagnostic_code: str,
        validation_status: ModelRequestValidationStatus,
    ) -> None:
        self.diagnostic_code = diagnostic_code
        self.validation_status = validation_status
        super().__init__(message)


class OpenRouterRequestLimitError(OpenRouterError):
    pass


class _OpenRouterRoutePlanningError(OpenRouterRequestLimitError):
    """Frozen route evidence cannot support token planning."""


class _OpenRouterEndpointCapacityError(OpenRouterRequestLimitError):
    """The conservative request bound cannot fit the frozen endpoint."""


class _OpenRouterContextPlanError(OpenRouterRequestLimitError):
    """Provider-visible prompt composition or local reserves are inconsistent."""


class _OpenRouterGlobalTokenBudgetError(OpenRouterRequestLimitError):
    """The request cannot fit the configured aggregate token ceiling."""


class OpenRouterCostControlError(OpenRouterError):
    pass


class OpenRouterRequestCostPreviewError(OpenRouterCostControlError):
    """An exact provider-free request-cost preview could not be proven or matched."""


def _require_exact_openrouter_request_body(
    body: dict[str, Any],
    *,
    model: str,
    structured_output_plan: _StructuredOutputRequestPlan,
    provider_policy: OpenRouterProviderPolicy,
    require_zdr: bool,
    request_token_plan: RequestTokenPlan,
    request_metadata: Mapping[str, str],
    endpoint_policy: _RegisteredEndpointPolicy | None,
    refresh_pricing_control: _AuditModelRefreshPricingRequestControl | None,
    expected_sha256: str | None = None,
) -> str:
    """Require and hash the canonical semantics of one sealed provider request body."""

    provider: dict[str, Any] = {
        "allow_fallbacks": provider_policy.allow_fallbacks,
        "data_collection": "deny",
    }
    if structured_output_plan.require_parameters:
        provider["require_parameters"] = True
    if require_zdr:
        provider["zdr"] = True
    if provider_policy.only:
        provider["only"] = list(provider_policy.only)
    elif provider_policy.order:
        provider["order"] = list(provider_policy.order)
    if refresh_pricing_control is not None:
        provider["max_price"] = dict(refresh_pricing_control.routing_max_price)
    elif endpoint_policy is not None:
        provider["max_price"] = dict(endpoint_policy.routing_max_price)

    expected: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": structured_output_plan.system_prompt},
            {"role": "user", "content": structured_output_plan.user_prompt},
        ],
        "temperature": 0,
        "max_tokens": request_token_plan.requested_completion_tokens,
        "stream": False,
        "provider": provider,
    }
    if structured_output_plan.response_format is not None:
        expected["response_format"] = structured_output_plan.response_format
    if structured_output_plan.reasoning_payload is not None:
        expected["reasoning"] = structured_output_plan.reasoning_payload
    if request_metadata:
        expected["metadata"] = dict(request_metadata)
    if type(body) is not dict or body != expected:
        error_type = (
            OpenRouterModelRefreshPricingError
            if refresh_pricing_control is not None
            else OpenRouterProviderPolicyError
        )
        raise error_type(
            "request body differs from its sealed provider policy or structured request plan"
        )
    body_sha256 = _TRUSTED_CANONICAL_SHA256(body)
    if expected_sha256 is not None and body_sha256 != expected_sha256:
        raise OpenRouterModelRefreshPricingError(
            "request body changed after exact pricing and budget sealing"
        )
    return body_sha256


def _candidate_review_request_token_plan_projection_sha256(
    plan: RequestTokenPlan,
) -> str:
    """Commit the request-local plan while excluding only live budget-position counters."""

    if type(plan) is not RequestTokenPlan:
        raise OpenRouterCandidateReviewBoundaryError(
            "candidate-review token-plan projection requires exact typed evidence"
        )
    plan_payload = plan.model_dump(
        mode="json",
        exclude={"global_budget", "plan_sha256"},
    )
    global_budget = plan.global_budget
    plan_payload["global_budget"] = {
        "schema_version": global_budget.schema_version,
        "global_input_token_budget": global_budget.global_input_token_budget,
        "global_output_token_budget": global_budget.global_output_token_budget,
        "request_input_tokens": global_budget.request_input_tokens,
        "request_output_tokens": global_budget.request_output_tokens,
    }
    material = _TRUSTED_CANDIDATE_REVIEW_CANONICAL_JSON_DUMPS(
        {
            "domain": "mmaudit.openrouter.candidate-review-token-plan-projection.v1",
            "request_token_plan": plan_payload,
        }
    )
    return _TRUSTED_HASHLIB_SHA256(material.encode("utf-8")).hexdigest()


def _candidate_review_request_material_projection(
    body: dict[str, Any],
    *,
    request_token_plan: RequestTokenPlan,
) -> tuple[str, str, str]:
    """Normalize only the live-budget-derived token-plan hash in canonical body material."""

    token_plan_projection_sha256 = _TRUSTED_CANDIDATE_REVIEW_TOKEN_PLAN_PROJECTION_SHA256(
        request_token_plan
    )
    metadata = body.get("metadata")
    if (
        type(body) is not dict
        or type(metadata) is not dict
        or metadata.get("mmaudit_token_plan_sha256") != request_token_plan.plan_sha256
    ):
        raise OpenRouterCandidateReviewBoundaryError(
            "candidate-review request material lacks its exact live token plan"
        )
    projected_metadata = {**metadata}
    projected_body = {**body, "metadata": projected_metadata}
    projected_metadata["mmaudit_token_plan_sha256"] = token_plan_projection_sha256
    projected_material = _TRUSTED_CANDIDATE_REVIEW_CANONICAL_JSON_DUMPS(projected_body)
    actual_material = _TRUSTED_CANDIDATE_REVIEW_CANONICAL_JSON_DUMPS(body)
    if len(projected_material.encode("utf-8")) != len(actual_material.encode("utf-8")):
        raise OpenRouterCandidateReviewBoundaryError(
            "candidate-review request projection changed the priced material size"
        )
    return (
        token_plan_projection_sha256,
        projected_material,
        _TRUSTED_HASHLIB_SHA256(projected_material.encode("utf-8")).hexdigest(),
    )


def _endpoint_request_cost_bound_projection_sha256(
    bound: EndpointRequestCostBound,
    *,
    request_material_projection_sha256: str,
) -> str:
    """Hash exact pricing/unit bounds against stable request-local material."""

    _require_pristine_endpoint_cost_bound_types()
    if (
        type(bound) is not EndpointRequestCostBound
        or _SHA256_PATTERN.fullmatch(request_material_projection_sha256) is None
        or any(type(component) is not EndpointPriceComponent for component in bound.components)
    ):
        raise OpenRouterCostControlError("endpoint request cost-bound evidence type is invalid")
    maximum_cost = _trusted_endpoint_request_maximum_cost_usd(bound)
    maximum_cost_text = format(maximum_cost, "f")
    if "." in maximum_cost_text:
        maximum_cost_text = maximum_cost_text.rstrip("0").rstrip(".")
    material = _TRUSTED_CANDIDATE_REVIEW_CANONICAL_JSON_DUMPS(
        {
            "domain": "mmaudit.openrouter.endpoint-request-cost-bound.v1",
            "exact_model_id": bound.exact_model_id,
            "provider_endpoint": bound.provider_endpoint,
            "request_material_projection_sha256": request_material_projection_sha256,
            "pricing_snapshot_sha256": bound.pricing_snapshot_sha256,
            "components": [
                {
                    "pricing_field": component.pricing_field,
                    "unit_price_usd_exact": format(component.unit_price_usd, "f"),
                    "maximum_units": component.maximum_units,
                }
                for component in bound.components
            ],
            "maximum_cost_usd_exact": maximum_cost_text or "0",
        }
    )
    return _TRUSTED_HASHLIB_SHA256(material.encode("utf-8")).hexdigest()


def _attempt_request_id(request_id: str, attempt: int) -> str:
    """Return one cost-ledger-safe identity for a bounded provider attempt."""

    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise OpenRouterRequestLimitError("provider attempt number is invalid")
    identifier = request_id if attempt == 1 else f"{request_id}:attempt:{attempt}"
    if _LOGICAL_REQUEST_ID_PATTERN.fullmatch(identifier) is None:
        raise OpenRouterRequestLimitError(
            "logical request ID cannot produce bounded 1-128 character attempt identities"
        )
    return identifier


def _request_ids_for_routes(
    logical_request_id: str | None,
    *,
    route_count: int,
    maximum_attempts: int,
) -> tuple[str, ...]:
    """Resolve scheduler identity into distinct route and retry-safe request IDs."""

    if (
        isinstance(route_count, bool)
        or not isinstance(route_count, int)
        or route_count < 1
        or isinstance(maximum_attempts, bool)
        or not isinstance(maximum_attempts, int)
        or maximum_attempts < 1
    ):
        raise OpenRouterRequestLimitError("request identity bounds are invalid")
    if logical_request_id is not None and (
        not isinstance(logical_request_id, str)
        or _LOGICAL_REQUEST_ID_PATTERN.fullmatch(logical_request_id) is None
    ):
        raise OpenRouterRequestLimitError(
            "logical request ID must use 1-128 restricted non-secret identifier characters"
        )
    identifiers = tuple(
        (
            str(uuid.uuid4())
            if logical_request_id is None
            else (
                logical_request_id
                if route_index == 1
                else f"{logical_request_id}:route:{route_index}"
            )
        )
        for route_index in range(1, route_count + 1)
    )
    for identifier in identifiers:
        _attempt_request_id(identifier, maximum_attempts)
    if len(set(identifiers)) != len(identifiers):
        raise OpenRouterRequestLimitError("request route identities must be unique")
    return identifiers


def is_retryable_status(status_code: int) -> bool:
    return status_code in {408, 409, 425, 429} or 500 <= status_code <= 599


def safe_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return headers safe for diagnostics."""

    return {
        key: (
            "[REDACTED]"
            if key.lower() in {"authorization", "proxy-authorization", "x-api-key"}
            else value
        )
        for key, value in headers.items()
    }


_STRICT_JSON_SCHEMA_CACHE_MAXSIZE = 128


@dataclass(frozen=True, slots=True, eq=False)
class _PydanticSchemaGeneration:
    """Identity-only token for one live Pydantic validator/core-schema pair."""

    validator: SchemaValidator
    core_schema: object

    def __hash__(self) -> int:
        return hash((id(self.validator), id(self.core_schema)))

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, _PydanticSchemaGeneration)
            and self.validator is other.validator
            and self.core_schema is other.core_schema
        )

    def is_current(self, response_model: type[BaseModel]) -> bool:
        return (
            getattr(response_model, "__pydantic_validator__", None) is self.validator
            and getattr(response_model, "__pydantic_core_schema__", None) is self.core_schema
        )

    def require_current(self, response_model: type[BaseModel], *, phase: str) -> None:
        if not self.is_current(response_model):
            raise OpenRouterSchemaError(f"response model changed {phase}")


def _pydantic_schema_generation(
    response_model: type[BaseModel],
) -> _PydanticSchemaGeneration:
    validator = getattr(response_model, "__pydantic_validator__", None)
    core_schema = getattr(response_model, "__pydantic_core_schema__", None)
    if not isinstance(validator, SchemaValidator) or core_schema is None:
        raise TypeError("structured-output response model lacks a live Pydantic schema")
    return _PydanticSchemaGeneration(validator=validator, core_schema=core_schema)


@lru_cache(maxsize=_STRICT_JSON_SCHEMA_CACHE_MAXSIZE)
def _strict_json_schema_json_for_generation(
    response_model: type[BaseModel],
    generation: _PydanticSchemaGeneration,
) -> str:
    """Cache one schema for an exact live Pydantic validator/schema generation."""

    if not generation.is_current(response_model):
        raise OpenRouterSchemaError("response model changed before strict schema generation")

    schema = copy.deepcopy(response_model.model_json_schema())
    if not generation.is_current(response_model):
        raise OpenRouterSchemaError("response model changed during strict schema generation")

    def normalize(node: Any) -> None:
        if isinstance(node, dict):
            node.pop("default", None)
            properties = node.get("properties")
            if isinstance(properties, dict):
                node["required"] = list(properties)
                node["additionalProperties"] = False
            for value in node.values():
                normalize(value)
        elif isinstance(node, list):
            for value in node:
                normalize(value)

    normalize(schema)
    serialized = json.dumps(
        schema,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    if not generation.is_current(response_model):
        raise OpenRouterSchemaError("response model changed during strict schema normalization")
    return serialized


@lru_cache(maxsize=_STRICT_JSON_SCHEMA_CACHE_MAXSIZE)
def _strict_json_schema_sha256_for_generation(
    response_model: type[BaseModel],
    generation: _PydanticSchemaGeneration,
) -> str:
    serialized = _strict_json_schema_json_for_generation(response_model, generation)
    if not generation.is_current(response_model):
        raise OpenRouterSchemaError("response model changed during strict schema hashing")
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _strict_json_schema_for_generation(
    response_model: type[BaseModel],
    generation: _PydanticSchemaGeneration,
) -> dict[str, Any]:
    """Decode only the canonical schema bound to one still-live model generation."""

    serialized = _strict_json_schema_json_for_generation(response_model, generation)
    if not generation.is_current(response_model):
        raise OpenRouterSchemaError("response model changed before strict schema decoding")
    schema = json.loads(serialized)
    if not generation.is_current(response_model):
        raise OpenRouterSchemaError("response model changed during strict schema decoding")
    if not isinstance(schema, dict):  # pragma: no cover - Pydantic guarantees an object schema.
        raise TypeError("strict structured-output schema must be a JSON object")
    return schema


def strict_json_schema(response_model: type[BaseModel]) -> dict[str, Any]:
    """Return a mutation-isolated strict schema backed by an immutable cache."""

    generation = _pydantic_schema_generation(response_model)
    return _strict_json_schema_for_generation(response_model, generation)


def strict_json_schema_sha256(response_model: type[BaseModel]) -> str:
    """Hash the exact strict schema for the current live validator generation."""

    generation = _pydantic_schema_generation(response_model)
    schema_sha256 = _strict_json_schema_sha256_for_generation(response_model, generation)
    if not generation.is_current(response_model):
        raise OpenRouterSchemaError("response model changed after strict schema hashing")
    return schema_sha256


def _strict_output_protocol(
    *,
    schema: dict[str, Any],
    schema_name: str,
) -> str:
    """Return the exact compact text protocol embedded for non-native output modes."""

    return json.dumps(
        {
            "instruction": (
                "Return exactly one complete JSON object matching this schema. "
                "Do not add markdown, code fences, comments, or prose."
            ),
            "protocol": STRUCTURED_OUTPUT_PROTOCOL_VERSION,
            "schema": schema,
            "schema_name": schema_name,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _structured_output_request_plan(
    *,
    mode: StructuredOutputMode,
    system_prompt: str,
    user_prompt: str,
    response_model: type[BaseModel],
    schema_name: str,
    reasoning: OpenRouterReasoning | None = None,
    schema_generation: _PydanticSchemaGeneration | None = None,
) -> _StructuredOutputRequestPlan:
    """Build one deterministic request protocol without model-authored repair."""

    generation = schema_generation or _pydantic_schema_generation(response_model)
    schema = _strict_json_schema_for_generation(response_model, generation)
    schema_sha256 = _canonical_sha256(schema)
    response_format: dict[str, Any] | None
    strict_protocol_sha256: str | None = None
    effective_system_prompt = system_prompt
    if mode is StructuredOutputMode.NATIVE_JSON_SCHEMA:
        response_format = {
            "type": "json_schema",
            "json_schema": {
                "name": schema_name,
                "strict": True,
                "schema": schema,
            },
        }
    else:
        response_format = (
            {"type": "json_object"} if mode is StructuredOutputMode.JSON_OBJECT else None
        )
        protocol = _strict_output_protocol(schema=schema, schema_name=schema_name)
        strict_protocol_sha256 = hashlib.sha256(protocol.encode("utf-8")).hexdigest()
        effective_system_prompt = (
            f"{system_prompt}\n\n"
            f"<MMAUDIT_STRUCTURED_OUTPUT_PROTOCOL>{protocol}"
            "</MMAUDIT_STRUCTURED_OUTPUT_PROTOCOL>"
        )
    reasoning_payload = reasoning.as_request_payload() if reasoning is not None else None
    required_provider_parameters = tuple(
        sorted(
            {
                *output_mode_request_parameters(mode),
                *(("reasoning",) if reasoning_payload is not None else ()),
            }
        )
    )
    if not set(required_provider_parameters).issubset(_ROUTE_SENSITIVE_REQUEST_PARAMETERS):
        raise OpenRouterProviderPolicyError(
            "structured request contains an unknown route-sensitive parameter"
        )
    require_parameters = bool(required_provider_parameters)
    reasoning_request_sha256 = (
        _canonical_sha256(reasoning_payload) if reasoning_payload is not None else None
    )
    request_shape_sha256 = structured_output_request_shape_sha256(
        mode=mode,
        schema_sha256=schema_sha256,
        required_provider_parameters=required_provider_parameters,
        reasoning_request_sha256=reasoning_request_sha256,
        strict_protocol_sha256=strict_protocol_sha256,
    )
    return _StructuredOutputRequestPlan(
        mode=mode,
        system_prompt=effective_system_prompt,
        user_prompt=user_prompt,
        response_format=response_format,
        reasoning_payload=reasoning_payload,
        required_provider_parameters=required_provider_parameters,
        require_parameters=require_parameters,
        reasoning_request_sha256=reasoning_request_sha256,
        strict_protocol_sha256=strict_protocol_sha256,
        schema_sha256=schema_sha256,
        request_shape_sha256=request_shape_sha256,
    )


def structured_output_prompt_sha256(
    *,
    mode: StructuredOutputMode,
    system_prompt: str,
    user_prompt: str,
    response_model: type[BaseModel],
    schema_name: str,
) -> str:
    """Hash the exact provider-visible messages for one output protocol."""

    plan = _structured_output_request_plan(
        mode=mode,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_model=response_model,
        schema_name=schema_name,
    )
    return _structured_output_prompt_sha256_from_plan(plan)


def structured_output_system_prompt_sha256(
    *,
    mode: StructuredOutputMode,
    system_prompt: str,
    user_prompt: str,
    response_model: type[BaseModel],
    schema_name: str,
) -> str:
    """Hash the exact effective system message after output-protocol composition."""

    plan = _structured_output_request_plan(
        mode=mode,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_model=response_model,
        schema_name=schema_name,
    )
    return hashlib.sha256(plan.system_prompt.encode("utf-8")).hexdigest()


def _structured_output_prompt_sha256_from_plan(
    plan: _StructuredOutputRequestPlan,
) -> str:
    return _canonical_sha256(
        [
            {"role": "system", "content": plan.system_prompt},
            {"role": "user", "content": plan.user_prompt},
        ]
    )


@dataclass(frozen=True, slots=True)
class StructuredRequestHashes:
    """Exact pre-transport prompt and schema commitments for one model route."""

    prompt_sha256: str
    system_prompt_sha256: str
    user_prompt_sha256: str
    schema_sha256: str


def _canonical_cost_decimal_text(value: object, *, label: str) -> str:
    """Return bounded, non-negative, non-exponent decimal evidence text."""

    if type(value) is not str or _CANONICAL_COST_DECIMAL_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be canonical non-negative decimal text")
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        raise ValueError(f"{label} must be canonical non-negative decimal text") from None
    if not parsed.is_finite() or parsed < 0:
        raise ValueError(f"{label} must be finite and non-negative")
    normalized = format(parsed, "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    if value != (normalized or "0"):
        raise ValueError(f"{label} must not contain redundant decimal notation")
    return value


def _format_cost_decimal(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"


def _multiply_cost_decimal(value: Decimal, multiplier: int) -> str:
    with localcontext() as context:
        context.prec = 160
        return _format_cost_decimal(value * Decimal(multiplier))


def _request_cost_preview_provider_policy_sha256(
    provider_policy: OpenRouterProviderPolicy,
) -> str:
    return _canonical_sha256(
        {
            "certification": provider_policy.certification,
            "only": provider_policy.only,
            "order": provider_policy.order,
            "allow_fallbacks": provider_policy.allow_fallbacks,
        }
    )


class OpenRouterRequestCostComponentPreview(BaseModel):
    """One exact endpoint price and request-specific unit ceiling."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    pricing_field: str = Field(min_length=1, max_length=64)
    unit_price_usd_exact: str
    maximum_units: int = Field(ge=0, le=2**63 - 1)

    @field_validator("pricing_field")
    @classmethod
    def pricing_field_is_supported(cls, value: str) -> str:
        if value not in _SUPPORTED_TEXT_PRICING_FIELDS:
            raise ValueError("request-cost preview pricing field is unsupported")
        return value

    @field_validator("unit_price_usd_exact")
    @classmethod
    def unit_price_is_canonical(cls, value: str) -> str:
        return _canonical_cost_decimal_text(value, label="request-cost preview unit price")


class OpenRouterStructuredRequestCostPreview(BaseModel):
    """Frozen, non-authorizing exact cost preview for one singleton request route."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    artifact_kind: Literal["openrouter_structured_request_cost_preview"] = (
        "openrouter_structured_request_cost_preview"
    )
    schema_version: Literal["1.0"] = "1.0"
    logical_request_id: str = Field(min_length=1, max_length=128)
    role: str = Field(min_length=1, max_length=128)
    exact_model_id: str = Field(min_length=3, max_length=384)
    provider_endpoint: str = Field(min_length=1, max_length=256)
    maximum_attempts: int = Field(ge=1, le=32)

    execution_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    privacy_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    token_budget_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    discovery_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    discovery_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    discovery_provenance_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    catalog_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    catalog_identity_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_metadata_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_identity_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    endpoint_policy_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    endpoint_record_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    endpoint_policy_pricing_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    endpoint_pricing_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_capability_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reasoning_capability_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    structured_output_mode: StructuredOutputMode
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    system_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    user_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    response_schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_request_shape_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    required_provider_parameters_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    strict_output_protocol_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    reasoning_request_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    reasoning_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reasoning_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reasoning_policy_role_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reasoning_profile_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reasoning_qualification_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    context_request_evidence_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    rendered_context_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    request_token_plan_projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_material_projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_material_projection_utf8_bytes: int = Field(gt=0, le=2**63 - 1)
    endpoint_cost_bound_pricing_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    endpoint_cost_bound_projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    cost_components: tuple[OpenRouterRequestCostComponentPreview, ...] = Field(
        min_length=2,
        max_length=len(_SUPPORTED_TEXT_PRICING_FIELDS),
    )
    prompt_byte_upper_bound_tokens: int = Field(gt=0, le=2**63 - 1)
    requested_completion_tokens: int = Field(gt=0, le=2**63 - 1)
    reserved_output_tokens: int = Field(gt=0, le=2**63 - 1)
    reserved_reasoning_tokens: int = Field(ge=0, le=2**63 - 1)
    maximum_priced_prompt_units: int = Field(gt=0, le=2**63 - 1)
    maximum_cost_usd_per_attempt_exact: str
    maximum_cost_usd_all_attempts_exact: str

    authorizes_dispatch: Literal[False] = False
    authorizes_budget_reservation: Literal[False] = False
    authorizes_provider_transport: Literal[False] = False
    grants_review_credit: Literal[False] = False
    grants_completion_credit: Literal[False] = False
    preview_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("logical_request_id")
    @classmethod
    def request_id_is_explicit_and_canonical(cls, value: str) -> str:
        if _LOGICAL_REQUEST_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("request-cost preview requires a canonical logical request ID")
        return value

    @field_validator("role")
    @classmethod
    def role_is_canonical(cls, value: str) -> str:
        if _QUALIFICATION_ROLE_PATTERN.fullmatch(value) is None:
            raise ValueError("request-cost preview role is invalid")
        return value

    @field_validator("exact_model_id")
    @classmethod
    def model_is_exact(cls, value: str) -> str:
        if not is_exact_openrouter_model_id(value):
            raise ValueError("request-cost preview requires an exact model ID")
        return value

    @field_validator(
        "maximum_cost_usd_per_attempt_exact",
        "maximum_cost_usd_all_attempts_exact",
    )
    @classmethod
    def costs_are_canonical(cls, value: str) -> str:
        return _canonical_cost_decimal_text(value, label="request-cost preview maximum cost")

    @model_validator(mode="after")
    def exact_units_cost_and_hash_are_consistent(self) -> Self:
        fields = tuple(component.pricing_field for component in self.cost_components)
        if fields != tuple(sorted(fields)) or len(fields) != len(set(fields)):
            raise ValueError("request-cost preview components must be unique and sorted")
        if not {"prompt", "completion"}.issubset(fields):
            raise ValueError("request-cost preview pricing is incomplete")
        if self.requested_completion_tokens != (
            self.reserved_output_tokens + self.reserved_reasoning_tokens
        ):
            raise ValueError("request-cost preview completion units do not conserve output")
        expected_prompt_units = max(
            self.request_material_projection_utf8_bytes,
            self.prompt_byte_upper_bound_tokens,
        )
        if self.maximum_priced_prompt_units != expected_prompt_units:
            raise ValueError("request-cost preview prompt pricing units are inconsistent")
        expected_units = {
            "completion": self.requested_completion_tokens,
            "image": 0,
            "input_cache_read": expected_prompt_units,
            "input_cache_write": expected_prompt_units,
            "internal_reasoning": self.reserved_reasoning_tokens,
            "prompt": expected_prompt_units,
            "request": 1,
            "web_search": 0,
        }
        if any(
            component.maximum_units != expected_units[component.pricing_field]
            for component in self.cost_components
        ):
            raise ValueError("request-cost preview metered units differ from the request plan")
        pricing = {
            component.pricing_field: component.unit_price_usd_exact
            for component in self.cost_components
        }
        if set(pricing).intersection(_UNENFORCEABLE_VARIABLE_PRICING_FIELDS):
            raise ValueError(
                "request-cost preview contains an uncappable variable pricing component"
            )
        cache_read_price = pricing.get("input_cache_read")
        if cache_read_price is not None and Decimal(cache_read_price) != Decimal(pricing["prompt"]):
            raise ValueError(
                "request-cost preview input-cache-read bound differs from its prompt-price bound"
            )
        if any(
            field not in _ROUTER_MAX_PRICE_FIELDS
            and field not in _PROMPT_DOMINATED_PRICING_FIELDS
            and Decimal(price) != 0
            for field, price in pricing.items()
        ):
            raise ValueError("request-cost preview contains an uncappable nonzero component")
        maximum_units = {
            component.pricing_field: component.maximum_units for component in self.cost_components
        }
        try:
            rebuilt = _trusted_endpoint_request_cost_bound_from_pricing(
                exact_model_id=self.exact_model_id,
                provider_endpoint=self.provider_endpoint,
                request_material="mmaudit-provider-free-cost-preview",
                pricing=pricing,
                maximum_units=maximum_units,
            )
            maximum_cost = _trusted_endpoint_request_maximum_cost_usd(rebuilt)
        except (BudgetReservationStateError, TypeError, ValueError) as exc:
            raise ValueError("request-cost preview components cannot prove an exact bound") from exc
        maximum_cost_text = _canonical_cost_decimal_text(
            _format_cost_decimal(maximum_cost),
            label="request-cost preview maximum cost",
        )
        if (
            rebuilt.pricing_snapshot_sha256 != self.endpoint_cost_bound_pricing_sha256
            or maximum_cost_text != self.maximum_cost_usd_per_attempt_exact
            or _multiply_cost_decimal(maximum_cost, self.maximum_attempts)
            != self.maximum_cost_usd_all_attempts_exact
        ):
            raise ValueError("request-cost preview exact cost does not match its components")
        if (self.context_request_evidence_sha256 is None) != (self.rendered_context_sha256 is None):
            raise ValueError("request-cost preview context hashes must be present together")
        if self.reasoning_qualification_sha256 is not None:
            raise ValueError(
                "provider-free request-cost preview cannot carry qualification authority"
            )
        expected_hash = _canonical_sha256(self.model_dump(mode="json", exclude={"preview_sha256"}))
        if self.preview_sha256 != expected_hash:
            raise ValueError("request-cost preview hash does not match its exact evidence")
        return self


@dataclass(frozen=True, slots=True, order=True)
class DeliveredSourceDescriptor:
    """Exact provider-visible whole-file identity presented to the lifecycle observer."""

    path: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class ModelRequestPrivacyBinding:
    """Non-secret exact privacy authority supplied to a pre-dispatch observer."""

    source_sha256: str
    effective_policy_sha256: str
    source_provenance_sha256: str

    def __post_init__(self) -> None:
        if any(
            _SHA256_PATTERN.fullmatch(value) is None
            for value in (
                self.source_sha256,
                self.effective_policy_sha256,
                self.source_provenance_sha256,
            )
        ):
            raise ValueError("model-request privacy binding requires exact SHA-256 values")


class ModelRequestLifecycleObserver(Protocol):
    """Durably bind one scheduled request before any provider-side effect."""

    def request_ready(
        self,
        *,
        logical_request_id: str,
        role: str,
        requested_model: str,
        prompt_sha256: str,
        system_prompt_sha256: str,
        user_prompt_sha256: str,
        schema_sha256: str,
        delivered_sources: tuple[DeliveredSourceDescriptor, ...],
        privacy_binding: ModelRequestPrivacyBinding | None,
    ) -> _TrustedRequestLimitScope | None:
        """Persist exact activation and optionally authorize task-scoped request counting."""

        ...

    def request_dispatched(self, *, logical_request_id: str) -> None: ...


class _TestOnlyContextPackageBudgetObserver(Protocol):
    """Observe validated context previews on the sealed synthetic transport only."""

    def __call__(
        self,
        models: tuple[str, ...],
        *,
        role: str | None,
        workflow_byte_upper_bound_tokens: int | None,
        workflow_prompt_sha256: str | None,
        workflow_prompt_provider_visible_bytes: int | None,
        context_json_escape_overhead_tokens: int,
        computed_package_budget: int,
    ) -> None: ...


def _fully_delivered_source_descriptors(
    context_package: ContextPackage | None,
) -> tuple[DeliveredSourceDescriptor, ...]:
    """Return exact identities carried as whole-file context excerpts.

    Repository-map metadata is not source delivery evidence. A path is credited
    only when one provider-visible excerpt contains the complete bytes committed
    by the corresponding repository-map entry, with no omitted prefix or suffix.
    Partial or reconstructed multi-excerpt files intentionally fail closed.
    """

    if context_package is None:
        return ()
    repository_files: dict[str, list[Any]] = {}
    for item in context_package.repository_map.files:
        repository_files.setdefault(item.path, []).append(item)
    delivered: set[DeliveredSourceDescriptor] = set()
    for excerpt in context_package.excerpts:
        matching_files = repository_files.get(excerpt.path, [])
        if len(matching_files) != 1:
            continue
        repository_file = matching_files[0]
        encoded = excerpt.content.encode("utf-8")
        expected_end_line = max(1, repository_file.lines)
        if (
            excerpt.start_line == 1
            and excerpt.end_line == expected_end_line
            and not excerpt.omitted_before
            and not excerpt.omitted_after
            and len(encoded) == repository_file.size
            and excerpt.content_hash == repository_file.sha256
            and hashlib.sha256(encoded).hexdigest() == repository_file.sha256
        ):
            delivered.add(
                DeliveredSourceDescriptor(
                    path=excerpt.path,
                    sha256=hashlib.sha256(encoded).hexdigest(),
                    size=len(encoded),
                )
            )
    return tuple(sorted(delivered))


def _compact_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _top_level_json_value_span(material: str, key: str) -> tuple[int, int]:
    """Locate one exact top-level JSON value without interpreting repository text."""

    decoder = json.JSONDecoder()
    index = 0
    length = len(material)

    def skip_whitespace(position: int) -> int:
        while position < length and material[position].isspace():
            position += 1
        return position

    index = skip_whitespace(index)
    if index >= length or material[index] != "{":
        raise OpenRouterSchemaError("structured protocol is not a JSON object")
    index += 1
    observed: set[str] = set()
    while True:
        index = skip_whitespace(index)
        if index < length and material[index] == "}":
            break
        try:
            observed_key, key_end = decoder.raw_decode(material, index)
        except ValueError:
            raise OpenRouterSchemaError("structured protocol JSON keys are invalid") from None
        if not isinstance(observed_key, str) or observed_key in observed:
            raise OpenRouterSchemaError("structured protocol JSON keys are invalid")
        observed.add(observed_key)
        index = skip_whitespace(key_end)
        if index >= length or material[index] != ":":
            raise OpenRouterSchemaError("structured protocol JSON delimiter is invalid")
        value_start = skip_whitespace(index + 1)
        try:
            _value, value_end = decoder.raw_decode(material, value_start)
        except ValueError:
            raise OpenRouterSchemaError("structured protocol JSON value is invalid") from None
        if observed_key == key:
            return value_start, value_end
        index = skip_whitespace(value_end)
        if index < length and material[index] == ",":
            index += 1
            continue
        if index < length and material[index] == "}":
            break
        raise OpenRouterSchemaError("structured protocol JSON object is malformed")
    raise OpenRouterSchemaError(f"structured protocol omits required {key} value")


def _schema_and_protocol_material(
    *,
    plan: _StructuredOutputRequestPlan,
    schema: dict[str, Any],
    schema_name: str,
    original_system_prompt: str,
) -> tuple[str, str]:
    """Partition exact provider-visible schema and protocol material."""

    protocol_material = ""
    if plan.mode is StructuredOutputMode.NATIVE_JSON_SCHEMA:
        if plan.system_prompt != original_system_prompt or plan.response_format is None:
            raise OpenRouterSchemaError("native schema request shape changed during planning")
        response_material = _compact_json(plan.response_format)
        schema_material = _compact_json(schema)
        schema_start = response_material.find(schema_material)
        if (
            schema_start < 0
            or response_material.find(
                schema_material,
                schema_start + len(schema_material),
            )
            >= 0
        ):
            raise OpenRouterSchemaError("native response schema partition is ambiguous")
        protocol_material = (
            response_material[:schema_start]
            + response_material[schema_start + len(schema_material) :]
        )
    else:
        protocol = _strict_output_protocol(schema=schema, schema_name=schema_name)
        schema_start, schema_end = _top_level_json_value_span(protocol, "schema")
        schema_material = protocol[schema_start:schema_end]
        suffix = plan.system_prompt.removeprefix(original_system_prompt)
        if original_system_prompt + suffix != plan.system_prompt:
            raise OpenRouterSchemaError("structured protocol changed the original system prompt")
        protocol_start = suffix.find(protocol)
        if protocol_start < 0 or suffix.find(protocol, protocol_start + len(protocol)) >= 0:
            raise OpenRouterSchemaError("structured protocol partition is ambiguous")
        absolute_schema_start = protocol_start + schema_start
        absolute_schema_end = protocol_start + schema_end
        protocol_material = suffix[:absolute_schema_start] + suffix[absolute_schema_end:]
        if plan.mode is StructuredOutputMode.JSON_OBJECT:
            if plan.response_format is None:
                raise OpenRouterSchemaError("JSON-object request omitted its response format")
            protocol_material += _compact_json(plan.response_format)
        elif plan.response_format is not None:
            raise OpenRouterSchemaError("validated-text request unexpectedly has a response format")
    if plan.reasoning_payload is not None:
        protocol_material += _compact_json(plan.reasoning_payload)
    return schema_material, protocol_material


def _prompt_token_allocations(
    *,
    plan: _StructuredOutputRequestPlan,
    original_system_prompt: str,
    response_model: type[BaseModel],
    schema_name: str,
    context_package: ContextPackage | None,
) -> tuple[PromptTokenAllocation, ...]:
    """Measure the final request by disjoint semantic category without retaining text."""

    # Local import avoids the context -> review-evidence -> OpenRouter import cycle.
    from mmaudit.orchestration.context import (
        context_category_measurements,
        render_context,
    )

    schema = strict_json_schema(response_model)
    if _canonical_sha256(schema) != plan.schema_sha256:
        raise OpenRouterSchemaError("structured response schema changed during token planning")
    schema_material, protocol_material = _schema_and_protocol_material(
        plan=plan,
        schema=schema,
        schema_name=schema_name,
        original_system_prompt=original_system_prompt,
    )
    context_measurements = (
        context_category_measurements(context_package) if context_package is not None else {}
    )
    if context_package is None:
        workflow_material = plan.user_prompt
    else:
        rendered_context = render_context(context_package)
        context_start = plan.user_prompt.find(rendered_context)
        if (
            context_start < 0
            or plan.user_prompt.find(
                rendered_context,
                context_start + len(rendered_context),
            )
            >= 0
        ):
            raise OpenRouterRequestLimitError(
                "context package must occur exactly once in the provider-visible user prompt"
            )
        workflow_material = (
            plan.user_prompt[:context_start]
            + plan.user_prompt[context_start + len(rendered_context) :]
        )

    exact_material = {
        PromptAllocationCategory.SYSTEM: original_system_prompt,
        PromptAllocationCategory.SCHEMA: schema_material,
        PromptAllocationCategory.PROTOCOL: protocol_material,
        PromptAllocationCategory.WORKFLOW: workflow_material,
    }
    allocations: list[PromptTokenAllocation] = []
    for category in PROMPT_ALLOCATION_CATEGORIES:
        material = exact_material.get(category)
        if material is not None:
            allocations.append(PromptTokenAllocation.from_text(category, material))
            continue
        measurement = context_measurements.get(category.value)
        if measurement is None:
            allocations.append(PromptTokenAllocation.from_text(category, ""))
            continue
        allocations.append(
            PromptTokenAllocation.from_measurement(
                category,
                content_sha256=measurement.content_sha256,
                utf8_bytes=measurement.utf8_bytes,
            )
        )
    return tuple(allocations)


def _context_request_evidence(
    *,
    request_id: str,
    request_role: str,
    context_package: ContextPackage,
) -> ContextRequestEvidence:
    """Bind one request to the exact context bytes checked before transport."""

    # Local import avoids the context -> review-evidence -> OpenRouter import cycle.
    from mmaudit.orchestration.context import (
        render_context,
        revalidate_model_surface_context_package,
    )

    sealed = revalidate_model_surface_context_package(context_package)
    rendered = render_context(sealed).encode("utf-8")
    return ContextRequestEvidence.build(
        request_id=request_id,
        request_role=request_role,
        context_role=sealed.role,
        byte_budget=sealed.byte_budget,
        declared_bytes_used=sealed.bytes_used,
        rendered_bytes=len(rendered),
        source_bytes=sum(len(excerpt.content.encode("utf-8")) for excerpt in sealed.excerpts),
        configured_maximum_source_tokens_per_request=(
            sealed.configured_maximum_source_tokens_per_request
        ),
        effective_source_byte_ceiling=sealed.effective_source_byte_ceiling,
        rendered_sha256=hashlib.sha256(rendered).hexdigest(),
    )


def _prompt_envelope_byte_upper_bound_tokens(
    plan: _StructuredOutputRequestPlan,
) -> int:
    """Bound model-visible chat input without relying on a provider tokenizer.

    Compact JSON deliberately overcounts ordinary message framing and escaped
    content. The fixed reserve covers provider chat-template control tokens that
    are not represented in the serialized model-visible envelope.
    """

    envelope: dict[str, Any] = {
        "messages": [
            {"role": "system", "content": plan.system_prompt},
            {"role": "user", "content": plan.user_prompt},
        ]
    }
    if plan.response_format is not None:
        envelope["response_format"] = plan.response_format
    if plan.reasoning_payload is not None:
        envelope["reasoning"] = plan.reasoning_payload
    bound = len(_compact_json(envelope).encode("utf-8")) + _CHAT_TEMPLATE_FRAMING_RESERVE_TOKENS
    if not 0 < bound <= _MAX_TOKEN_EVIDENCE:
        raise OpenRouterRequestLimitError(
            "provider-visible prompt envelope exceeds the supported token evidence range"
        )
    return bound


def _context_omissions(
    context_package: ContextPackage | None,
) -> tuple[ContextOmissionItem, ...]:
    if context_package is None:
        return ()
    return tuple(context_package.omissions)


def _reasoning_from_control_profile(
    profile: ReasoningControlProfile,
) -> OpenRouterReasoning | None:
    if profile.mode == "disabled":
        return None
    return OpenRouterReasoning(
        effort=profile.effort,
        max_tokens=profile.max_tokens,
        exclude=profile.exclude,
    )


def _structured_request_metadata(
    *,
    request_id: str,
    role: str,
    prompt_sha256: str,
    user_prompt_sha256: str,
    structured_output_plan: _StructuredOutputRequestPlan,
    request_token_plan: RequestTokenPlan,
    context_request_evidence: ContextRequestEvidence | None,
    endpoint_policy: _RegisteredEndpointPolicy | None,
    model_identity_snapshot_sha256: str | None,
    additional_metadata: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build the shared exact metadata surface for preview and provider dispatch."""

    metadata = {
        "mmaudit_request_id": request_id,
        "mmaudit_role": role,
        "mmaudit_prompt_sha256": prompt_sha256,
        "mmaudit_user_prompt_sha256": user_prompt_sha256,
        "mmaudit_schema_sha256": structured_output_plan.schema_sha256,
        "mmaudit_output_mode": structured_output_plan.mode.value,
        "mmaudit_output_request_shape_sha256": structured_output_plan.request_shape_sha256,
        "mmaudit_required_provider_parameters_sha256": _canonical_sha256(
            structured_output_plan.required_provider_parameters
        ),
        "mmaudit_token_plan_sha256": request_token_plan.plan_sha256,
    }
    if endpoint_policy is not None:
        metadata.update(
            {
                "mmaudit_endpoint_snapshot_sha256": endpoint_policy.snapshot_sha256,
                "mmaudit_endpoint_pricing_sha256": endpoint_policy.policy_pricing_sha256,
                "mmaudit_output_capability_sha256": endpoint_policy.output_capability_sha256,
            }
        )
    if model_identity_snapshot_sha256 is not None:
        metadata["mmaudit_identity_snapshot_sha256"] = model_identity_snapshot_sha256
    reasoning_plan = request_token_plan.reasoning_plan
    if reasoning_plan is not None:
        metadata.update(
            {
                "mmaudit_reasoning_plan_sha256": reasoning_plan.evidence_sha256,
                "mmaudit_reasoning_policy_sha256": reasoning_plan.policy_artifact_sha256,
                "mmaudit_reasoning_profile_sha256": (reasoning_plan.control_profile.profile_sha256),
            }
        )
        if reasoning_plan.endpoint_capability_sha256 is not None:
            metadata["mmaudit_reasoning_capability_sha256"] = (
                reasoning_plan.endpoint_capability_sha256
            )
        if reasoning_plan.qualification_binding_sha256 is not None:
            metadata["mmaudit_reasoning_qualification_sha256"] = (
                reasoning_plan.qualification_binding_sha256
            )
    if context_request_evidence is not None:
        metadata["mmaudit_context_request_evidence_sha256"] = (
            context_request_evidence.evidence_sha256
        )
    if structured_output_plan.strict_protocol_sha256 is not None:
        metadata["mmaudit_output_protocol_sha256"] = structured_output_plan.strict_protocol_sha256
    for key, value in (additional_metadata or {}).items():
        if key in metadata and metadata[key] != value:
            raise OpenRouterRequestCostPreviewError(
                "additional request metadata conflicts with an exact structured-request field"
            )
        metadata[key] = value
    if any(not _is_safe_metadata_pair(key, value) for key, value in metadata.items()):
        raise OpenRouterRequestLimitError("request metadata is invalid")
    return metadata


def _assemble_structured_request_body(
    *,
    model: str,
    structured_output_plan: _StructuredOutputRequestPlan,
    provider_policy: OpenRouterProviderPolicy,
    require_zdr: bool,
    requested_completion_tokens: int,
    request_metadata: Mapping[str, str],
    routing_max_price: Mapping[str, float] | None,
) -> dict[str, Any]:
    """Assemble the sole canonical structured request shape used by preview and dispatch."""

    body: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": structured_output_plan.system_prompt},
            {"role": "user", "content": structured_output_plan.user_prompt},
        ],
        "temperature": 0,
        "max_tokens": requested_completion_tokens,
        "stream": False,
        "provider": provider_policy.as_request_payload(
            require_zdr=require_zdr,
            require_parameters=structured_output_plan.require_parameters,
        ),
    }
    if structured_output_plan.response_format is not None:
        body["response_format"] = structured_output_plan.response_format
    provider = body["provider"]
    assert isinstance(provider, dict)
    if routing_max_price is not None:
        provider["max_price"] = dict(routing_max_price)
    if structured_output_plan.reasoning_payload is not None:
        body["reasoning"] = structured_output_plan.reasoning_payload
    if any(not _is_safe_metadata_pair(key, value) for key, value in request_metadata.items()):
        raise OpenRouterRequestLimitError("request metadata is invalid")
    if request_metadata:
        body["metadata"] = dict(request_metadata)
    return body


def _serialized_structured_request_size(body: Mapping[str, Any]) -> int:
    return len(json.dumps(body, sort_keys=True, ensure_ascii=True).encode("utf-8"))


def _structured_request_pricing_unit_ceilings(
    *,
    request_material: str,
    request_token_plan: RequestTokenPlan,
) -> dict[str, int]:
    request_bytes = max(1, len(request_material.encode("utf-8")))
    prompt_pricing_units = max(
        request_bytes,
        request_token_plan.prompt_byte_upper_bound_tokens,
    )
    return {
        "completion": request_token_plan.requested_completion_tokens,
        "image": 0,
        "input_cache_read": prompt_pricing_units,
        "input_cache_write": prompt_pricing_units,
        "internal_reasoning": request_token_plan.reserved_reasoning_tokens,
        "prompt": prompt_pricing_units,
        "request": 1,
        "web_search": 0,
    }


def _provider_free_registered_endpoint_policy(
    *,
    evidence: OpenRouterModelDiscoveryEvidence,
    provider_policy: OpenRouterProviderPolicy,
    privacy: PrivacyConfig,
) -> _RegisteredEndpointPolicy:
    endpoint_snapshot = evidence.endpoint_snapshot
    if (
        endpoint_snapshot.exact_model_id != evidence.exact_model_id
        or endpoint_snapshot.configured_provider_endpoints != (evidence.approved_provider_endpoint,)
        or endpoint_snapshot.provider_policy_mode != "only"
        or endpoint_snapshot.require_zdr is not privacy.require_zdr
        or provider_policy.only != (evidence.approved_provider_endpoint,)
        or provider_policy.order
        or provider_policy.allow_fallbacks
        or not provider_policy.certification
    ):
        raise OpenRouterRequestCostPreviewError(
            "provider-free request-cost preview requires one exact certification route"
        )
    if len(endpoint_snapshot.endpoints) != 1:
        raise OpenRouterRequestCostPreviewError(
            "provider-free request-cost preview requires singleton endpoint evidence"
        )
    endpoint = endpoint_snapshot.endpoints[0]
    pricing = dict(endpoint.pricing)
    if not {"prompt", "completion"}.issubset(pricing) or not set(pricing).issubset(
        _SUPPORTED_TEXT_PRICING_FIELDS
    ):
        raise OpenRouterRequestCostPreviewError(
            "provider-free request-cost preview pricing is incomplete or unsupported"
        )
    provider_identities = tuple(
        sorted(
            {
                identity
                for identity in (
                    endpoint.provider_endpoint,
                    endpoint.endpoint_tag,
                    endpoint.endpoint_slug,
                    endpoint.provider_name,
                )
                if identity is not None
            },
            key=str.casefold,
        )
    )
    registered = _RegisteredEndpointPricing(
        provider_endpoint=endpoint.provider_endpoint,
        provider_name=endpoint.provider_name,
        provider_identities=provider_identities,
        endpoint_tag=endpoint.endpoint_tag,
        endpoint_slug=endpoint.endpoint_slug,
        operational_status=endpoint.operational_status,
        zdr_eligible=endpoint.zdr_eligible,
        pricing=tuple(pricing.items()),
        pricing_sha256=endpoint.pricing_sha256,
        snapshot_sha256=endpoint.endpoint_snapshot_sha256,
        context_length=endpoint.context_length,
        max_prompt_tokens=endpoint.max_prompt_tokens,
        max_prompt_tokens_source=endpoint.max_prompt_tokens_source,
        max_completion_tokens=endpoint.max_completion_tokens,
        max_completion_tokens_source=endpoint.max_completion_tokens_source,
        supported_parameters=endpoint.supported_parameters,
        required_request_parameters=endpoint.required_request_parameters,
        structured_output_parameters=endpoint.structured_output_parameters,
        supported_output_modes=endpoint.supported_output_modes,
        structured_output_mode=endpoint.structured_output_mode,
    )
    selected = _registered_endpoints_for_output_mode(
        (registered,),
        evidence.structured_output_mode,
        reasoning_requested=False,
    )
    routing_max_price = _routing_max_price(selected)
    return _RegisteredEndpointPolicy(
        snapshot_sha256=endpoint_snapshot.snapshot_sha256,
        policy_pricing_sha256=_canonical_sha256(
            {endpoint.provider_endpoint: endpoint.pricing_sha256}
        ),
        routing_max_price=tuple(routing_max_price.items()),
        endpoints=selected,
        structured_output_parameters=output_mode_capability_parameters(
            evidence.structured_output_mode,
            endpoint.structured_output_parameters,
        ),
        supported_output_modes=evidence.supported_output_modes,
        structured_output_mode=evidence.structured_output_mode,
        output_capability_sha256=evidence.output_capability_sha256,
    )


def _build_structured_request_cost_preview(
    *,
    execution: ExecutionConfig,
    privacy: PrivacyConfig,
    token_budgets: TokenBudgetConfig,
    provider_policy: OpenRouterProviderPolicy,
    discovery_manifest: OpenRouterModelDiscoveryRunManifest,
    discovery_evidence: OpenRouterModelDiscoveryEvidence,
    endpoint_policy: _RegisteredEndpointPolicy,
    model_identity_snapshot_sha256: str,
    structured_output_plan: _StructuredOutputRequestPlan,
    request_token_plan: RequestTokenPlan,
    context_request_evidence: ContextRequestEvidence | None,
    request_material_projection: str,
    request_material_projection_sha256: str,
    request_token_plan_projection_sha256: str,
    endpoint_cost_bound: EndpointRequestCostBound,
    maximum_attempts: int,
) -> OpenRouterStructuredRequestCostPreview:
    reasoning_plan = request_token_plan.reasoning_plan
    if reasoning_plan is None or reasoning_plan.endpoint_capability_sha256 is None:
        raise OpenRouterRequestCostPreviewError(
            "provider-free request-cost preview lacks capability-bound reasoning evidence"
        )
    endpoint = endpoint_policy.endpoint(endpoint_cost_bound.provider_endpoint)
    if endpoint is None:
        raise OpenRouterRequestCostPreviewError(
            "provider-free request-cost preview lacks its exact endpoint pricing record"
        )
    maximum_cost = _trusted_endpoint_request_maximum_cost_usd(endpoint_cost_bound)
    components = tuple(
        OpenRouterRequestCostComponentPreview(
            pricing_field=component.pricing_field,
            unit_price_usd_exact=_format_cost_decimal(component.unit_price_usd),
            maximum_units=component.maximum_units,
        )
        for component in endpoint_cost_bound.components
    )
    context_sha256 = (
        context_request_evidence.evidence_sha256 if context_request_evidence is not None else None
    )
    rendered_context_sha256 = (
        context_request_evidence.rendered_sha256 if context_request_evidence is not None else None
    )
    identity = _identity_snapshot_from_discovery(
        discovery_evidence,
        allow_fallbacks=False,
        reasoning_requested=False,
    )
    values: dict[str, Any] = {
        "artifact_kind": "openrouter_structured_request_cost_preview",
        "schema_version": "1.0",
        "logical_request_id": request_token_plan.request_id,
        "role": request_token_plan.role,
        "exact_model_id": discovery_evidence.exact_model_id,
        "provider_endpoint": endpoint_cost_bound.provider_endpoint,
        "maximum_attempts": maximum_attempts,
        "execution_config_sha256": _canonical_sha256(execution.model_dump(mode="json")),
        "privacy_config_sha256": _canonical_sha256(privacy.model_dump(mode="json")),
        "token_budget_config_sha256": _canonical_sha256(token_budgets.model_dump(mode="json")),
        "provider_policy_sha256": _request_cost_preview_provider_policy_sha256(provider_policy),
        "discovery_manifest_sha256": discovery_manifest.manifest_sha256,
        "discovery_evidence_sha256": discovery_evidence.discovery_evidence_sha256,
        "discovery_provenance_sha256": discovery_evidence.provenance.provenance_sha256,
        "catalog_snapshot_sha256": discovery_evidence.provenance.catalog_snapshot_sha256,
        "catalog_identity_binding_sha256": discovery_evidence.catalog_identity_binding_sha256,
        "model_metadata_snapshot_sha256": discovery_evidence.model_metadata_snapshot_sha256,
        "model_identity_snapshot_sha256": model_identity_snapshot_sha256,
        "endpoint_policy_snapshot_sha256": endpoint_policy.snapshot_sha256,
        "endpoint_record_snapshot_sha256": endpoint.snapshot_sha256,
        "endpoint_policy_pricing_sha256": endpoint_policy.policy_pricing_sha256,
        "endpoint_pricing_sha256": endpoint.pricing_sha256,
        "output_capability_sha256": endpoint_policy.output_capability_sha256,
        "reasoning_capability_sha256": reasoning_plan.endpoint_capability_sha256,
        "structured_output_mode": structured_output_plan.mode,
        "prompt_sha256": _structured_output_prompt_sha256_from_plan(structured_output_plan),
        "system_prompt_sha256": hashlib.sha256(
            structured_output_plan.system_prompt.encode("utf-8")
        ).hexdigest(),
        "user_prompt_sha256": hashlib.sha256(
            structured_output_plan.user_prompt.encode("utf-8")
        ).hexdigest(),
        "response_schema_sha256": structured_output_plan.schema_sha256,
        "output_request_shape_sha256": structured_output_plan.request_shape_sha256,
        "required_provider_parameters_sha256": _canonical_sha256(
            structured_output_plan.required_provider_parameters
        ),
        "strict_output_protocol_sha256": structured_output_plan.strict_protocol_sha256,
        "reasoning_request_sha256": structured_output_plan.reasoning_request_sha256,
        "reasoning_plan_sha256": reasoning_plan.evidence_sha256,
        "reasoning_policy_sha256": reasoning_plan.policy_artifact_sha256,
        "reasoning_policy_role_binding_sha256": reasoning_plan.policy_role_binding_sha256,
        "reasoning_profile_sha256": reasoning_plan.control_profile.profile_sha256,
        "reasoning_qualification_sha256": reasoning_plan.qualification_binding_sha256,
        "context_request_evidence_sha256": context_sha256,
        "rendered_context_sha256": rendered_context_sha256,
        "request_token_plan_projection_sha256": request_token_plan_projection_sha256,
        "request_material_projection_sha256": request_material_projection_sha256,
        "request_material_projection_utf8_bytes": len(request_material_projection.encode("utf-8")),
        "endpoint_cost_bound_pricing_sha256": endpoint_cost_bound.pricing_snapshot_sha256,
        "endpoint_cost_bound_projection_sha256": (
            _endpoint_request_cost_bound_projection_sha256(
                endpoint_cost_bound,
                request_material_projection_sha256=request_material_projection_sha256,
            )
        ),
        "cost_components": tuple(component.model_dump(mode="json") for component in components),
        "prompt_byte_upper_bound_tokens": (request_token_plan.prompt_byte_upper_bound_tokens),
        "requested_completion_tokens": request_token_plan.requested_completion_tokens,
        "reserved_output_tokens": request_token_plan.reserved_output_tokens,
        "reserved_reasoning_tokens": request_token_plan.reserved_reasoning_tokens,
        "maximum_priced_prompt_units": _trusted_endpoint_request_maximum_units_for(
            endpoint_cost_bound,
            "prompt",
        ),
        "maximum_cost_usd_per_attempt_exact": _format_cost_decimal(maximum_cost),
        "maximum_cost_usd_all_attempts_exact": _multiply_cost_decimal(
            maximum_cost,
            maximum_attempts,
        ),
        "authorizes_dispatch": False,
        "authorizes_budget_reservation": False,
        "authorizes_provider_transport": False,
        "grants_review_credit": False,
        "grants_completion_credit": False,
    }
    preview = OpenRouterStructuredRequestCostPreview.model_validate(
        {**values, "preview_sha256": _canonical_sha256(values)},
        strict=True,
    )
    if identity.snapshot_sha256 != model_identity_snapshot_sha256:
        raise OpenRouterRequestCostPreviewError(
            "provider-free request-cost preview model identity changed during construction"
        )
    return preview


def preview_openrouter_structured_request_cost(
    *,
    execution: ExecutionConfig,
    privacy: PrivacyConfig,
    token_budgets: TokenBudgetConfig,
    provider_policy: OpenRouterProviderPolicy,
    reasoning_policy: ReasoningPolicyArtifact,
    discovery_manifest: OpenRouterModelDiscoveryRunManifest,
    discovery_evidence: OpenRouterModelDiscoveryEvidence,
    role: str,
    system_prompt: str,
    user_prompt: str,
    response_model: type[BaseModel],
    schema_name: str,
    logical_request_id: str,
    context_package: ContextPackage | None = None,
    maximum_attempts: int | None = None,
) -> OpenRouterStructuredRequestCostPreview:
    """Derive an exact singleton request-cost preview without secrets or provider state."""

    if (
        type(execution) is not ExecutionConfig
        or type(privacy) is not PrivacyConfig
        or type(token_budgets) is not TokenBudgetConfig
        or type(provider_policy) is not OpenRouterProviderPolicy
        or type(reasoning_policy) is not ReasoningPolicyArtifact
        or type(discovery_manifest) is not OpenRouterModelDiscoveryRunManifest
        or type(discovery_evidence) is not OpenRouterModelDiscoveryEvidence
        or type(role) is not str
        or type(system_prompt) is not str
        or type(user_prompt) is not str
        or type(schema_name) is not str
        or type(logical_request_id) is not str
        or not isinstance(response_model, type)
        or not issubclass(response_model, BaseModel)
        or (context_package is not None and type(context_package) is not ContextPackage)
    ):
        raise OpenRouterRequestCostPreviewError(
            "provider-free request-cost preview inputs require exact public evidence types"
        )
    try:
        sealed_execution = ExecutionConfig.model_validate_json(
            execution.model_dump_json(),
            strict=True,
        )
        sealed_privacy = PrivacyConfig.model_validate_json(
            privacy.model_dump_json(),
            strict=True,
        )
        sealed_token_budgets = TokenBudgetConfig.model_validate_json(
            token_budgets.model_dump_json(),
            strict=True,
        )
        sealed_reasoning_policy = ReasoningPolicyArtifact.model_validate_json(
            reasoning_policy.model_dump_json(),
            strict=True,
        )
        sealed_manifest = OpenRouterModelDiscoveryRunManifest.model_validate_json(
            discovery_manifest.model_dump_json(),
            strict=True,
        )
        sealed_evidence = OpenRouterModelDiscoveryEvidence.model_validate_json(
            discovery_evidence.model_dump_json(),
            strict=True,
        )
        sealed_provider_policy = OpenRouterProviderPolicy(
            certification=provider_policy.certification,
            only=provider_policy.only,
            order=provider_policy.order,
            allow_fallbacks=provider_policy.allow_fallbacks,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise OpenRouterRequestCostPreviewError(
            "provider-free request-cost preview inputs failed detached validation"
        ) from exc
    if (
        sealed_execution != execution
        or sealed_privacy != privacy
        or sealed_token_budgets != token_budgets
        or sealed_reasoning_policy != reasoning_policy
        or sealed_manifest != discovery_manifest
        or sealed_evidence != discovery_evidence
        or sealed_provider_policy != provider_policy
        or _LOGICAL_REQUEST_ID_PATTERN.fullmatch(logical_request_id) is None
        or _QUALIFICATION_ROLE_PATTERN.fullmatch(role) is None
    ):
        raise OpenRouterRequestCostPreviewError(
            "provider-free request-cost preview inputs changed across their boundary"
        )
    matching_artifacts = tuple(
        artifact
        for artifact in sealed_manifest.artifacts
        if artifact.exact_model_id == sealed_evidence.exact_model_id
        and artifact.approved_provider_endpoint == sealed_evidence.approved_provider_endpoint
    )
    expected_artifact_sha256 = hashlib.sha256(
        stable_json(sealed_evidence).encode("utf-8")
    ).hexdigest()
    if (
        sealed_manifest.run_provenance != sealed_evidence.provenance
        or len(matching_artifacts) != 1
        or matching_artifacts[0].discovery_evidence_sha256
        != sealed_evidence.discovery_evidence_sha256
        or matching_artifacts[0].artifact_sha256 != expected_artifact_sha256
    ):
        raise OpenRouterRequestCostPreviewError(
            "provider-free request-cost preview discovery manifest does not bind the evidence"
        )
    configured_attempts = sealed_execution.max_model_retries + 1
    attempt_limit = configured_attempts if maximum_attempts is None else maximum_attempts
    if (
        type(attempt_limit) is not int
        or not 1 <= attempt_limit <= configured_attempts
        or sealed_execution.max_requests_per_agent < attempt_limit
    ):
        raise OpenRouterRequestCostPreviewError(
            "provider-free request-cost preview retry bound is invalid"
        )
    endpoint_policy = _provider_free_registered_endpoint_policy(
        evidence=sealed_evidence,
        provider_policy=sealed_provider_policy,
        privacy=sealed_privacy,
    )
    control = sealed_reasoning_policy.control_for_request(role)
    sealed_evidence.require_compatible_reasoning_profile(control)
    reasoning_plan = ReasoningRequestPlanEvidence.build(
        request_role=role,
        policy=sealed_reasoning_policy,
        endpoint_capability_sha256=sealed_evidence.reasoning_capability.capability_sha256,
    )
    response_schema_generation = _pydantic_schema_generation(response_model)
    structured_output_plan = _structured_output_request_plan(
        mode=sealed_evidence.structured_output_mode,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_model=response_model,
        schema_name=schema_name,
        reasoning=_reasoning_from_control_profile(control),
        schema_generation=response_schema_generation,
    )
    response_schema_generation.require_current(
        response_model,
        phase="during provider-free request-cost structured-output planning",
    )
    _require_matching_request_parameter_profile(
        endpoint_policy,
        structured_output_plan,
        sealed_reasoning_plan=reasoning_plan,
    )
    endpoint = endpoint_policy.endpoints[0]
    required_output_tokens = (
        sealed_token_budgets.reserved_output_tokens
        if sealed_token_budgets.reserved_output_tokens is not None
        else sealed_execution.max_output_tokens_per_request
    )
    route_intersection = EndpointRouteIntersection.build(
        (
            EndpointRouteTokenCapacity.build(
                exact_model_id=sealed_evidence.exact_model_id,
                provider_endpoint=endpoint.provider_endpoint,
                endpoint_snapshot_sha256=endpoint.snapshot_sha256,
                context_tokens=endpoint.context_length,
                max_prompt_tokens=endpoint.max_prompt_tokens,
                max_prompt_tokens_source=endpoint.max_prompt_tokens_source,
                max_completion_tokens=endpoint.max_completion_tokens,
                max_completion_tokens_source=endpoint.max_completion_tokens_source,
            ),
        )
    )
    sealed_context = context_package
    if sealed_context is not None:
        from mmaudit.orchestration.context import revalidate_model_surface_context_package

        sealed_context = revalidate_model_surface_context_package(sealed_context)
    allocations = _prompt_token_allocations(
        plan=structured_output_plan,
        original_system_prompt=system_prompt,
        response_model=response_model,
        schema_name=schema_name,
        context_package=sealed_context,
    )
    context_request_evidence = (
        _context_request_evidence(
            request_id=logical_request_id,
            request_role=role,
            context_package=sealed_context,
        )
        if sealed_context is not None
        else None
    )
    request_token_plan = build_request_token_plan(
        request_id=logical_request_id,
        role=role,
        route_intersection=route_intersection,
        allocations=allocations,
        required_output_tokens=required_output_tokens,
        reserved_reasoning_tokens=control.reserved_reasoning_tokens,
        reasoning_plan=reasoning_plan,
        global_input_token_budget=sealed_token_budgets.global_input_token_budget,
        global_output_token_budget=sealed_token_budgets.global_output_token_budget,
        input_tokens_reserved_before=0,
        output_tokens_reserved_before=0,
        context_utilization=Decimal(str(sealed_token_budgets.usable_input_fraction)),
        configured_reserved_system_tokens=sealed_token_budgets.reserved_system_tokens,
        configured_reserved_schema_tokens=sealed_token_budgets.reserved_schema_tokens,
        configured_reserved_protocol_tokens=sealed_token_budgets.reserved_protocol_tokens,
        configured_reserved_workflow_tokens=sealed_token_budgets.reserved_workflow_tokens,
        maximum_source_tokens_per_request=(sealed_token_budgets.maximum_source_tokens_per_request),
        context_package_source_byte_ceiling=(
            sealed_context.effective_source_byte_ceiling if sealed_context is not None else None
        ),
        requested_surface_count=(
            len(sealed_context.requested_model_surfaces) if sealed_context is not None else 0
        ),
        context_omissions=_context_omissions(sealed_context),
        prompt_envelope_byte_upper_bound_tokens=(
            _prompt_envelope_byte_upper_bound_tokens(structured_output_plan)
        ),
    )
    identity = _identity_snapshot_from_discovery(
        sealed_evidence,
        allow_fallbacks=False,
        reasoning_requested=False,
    )
    prompt_sha256 = _structured_output_prompt_sha256_from_plan(structured_output_plan)
    user_prompt_sha256 = hashlib.sha256(user_prompt.encode("utf-8")).hexdigest()
    request_metadata = _structured_request_metadata(
        request_id=logical_request_id,
        role=role,
        prompt_sha256=prompt_sha256,
        user_prompt_sha256=user_prompt_sha256,
        structured_output_plan=structured_output_plan,
        request_token_plan=request_token_plan,
        context_request_evidence=context_request_evidence,
        endpoint_policy=endpoint_policy,
        model_identity_snapshot_sha256=identity.snapshot_sha256,
    )
    body = _assemble_structured_request_body(
        model=sealed_evidence.exact_model_id,
        structured_output_plan=structured_output_plan,
        provider_policy=sealed_provider_policy,
        require_zdr=sealed_privacy.require_zdr,
        requested_completion_tokens=request_token_plan.requested_completion_tokens,
        request_metadata=request_metadata,
        routing_max_price=dict(endpoint_policy.routing_max_price),
    )
    if _serialized_structured_request_size(body) > sealed_execution.max_request_bytes:
        raise OpenRouterRequestLimitError(
            f"serialized model request exceeds {sealed_execution.max_request_bytes} byte limit"
        )
    request_body_sha256 = _require_exact_openrouter_request_body(
        body,
        model=sealed_evidence.exact_model_id,
        structured_output_plan=structured_output_plan,
        provider_policy=sealed_provider_policy,
        require_zdr=sealed_privacy.require_zdr,
        request_token_plan=request_token_plan,
        request_metadata=request_metadata,
        endpoint_policy=endpoint_policy,
        refresh_pricing_control=None,
    )
    response_schema_generation.require_current(
        response_model,
        phase="during provider-free request-cost request hashing",
    )
    request_material = _CANDIDATE_REVIEW_CANONICAL_JSON_DUMPS(body)
    (
        request_token_plan_projection_sha256,
        request_material_projection,
        request_material_projection_sha256,
    ) = _candidate_review_request_material_projection(
        body,
        request_token_plan=request_token_plan,
    )
    ceilings = _structured_request_pricing_unit_ceilings(
        request_material=request_material,
        request_token_plan=request_token_plan,
    )
    bounded_pricing = dict(
        _TRUSTED_PROVIDER_CAPPED_COST_BOUND_PRICING(
            endpoint,
            dict(endpoint_policy.routing_max_price),
        )
    )
    endpoint_cost_bound = _trusted_endpoint_request_cost_bound_from_pricing(
        exact_model_id=sealed_evidence.exact_model_id,
        provider_endpoint=endpoint.provider_endpoint,
        request_material=request_material,
        pricing=bounded_pricing,
        maximum_units={field: ceilings[field] for field in bounded_pricing},
    )
    if endpoint_cost_bound.request_material_sha256 != request_body_sha256:
        raise OpenRouterRequestCostPreviewError(
            "provider-free request-cost preview request material changed during construction"
        )
    return _build_structured_request_cost_preview(
        execution=sealed_execution,
        privacy=sealed_privacy,
        token_budgets=sealed_token_budgets,
        provider_policy=sealed_provider_policy,
        discovery_manifest=sealed_manifest,
        discovery_evidence=sealed_evidence,
        endpoint_policy=endpoint_policy,
        model_identity_snapshot_sha256=identity.snapshot_sha256,
        structured_output_plan=structured_output_plan,
        request_token_plan=request_token_plan,
        context_request_evidence=context_request_evidence,
        request_material_projection=request_material_projection,
        request_material_projection_sha256=request_material_projection_sha256,
        request_token_plan_projection_sha256=request_token_plan_projection_sha256,
        endpoint_cost_bound=endpoint_cost_bound,
        maximum_attempts=attempt_limit,
    )


def _require_matching_structured_request_cost_preview(
    *,
    expected: OpenRouterStructuredRequestCostPreview,
    execution: ExecutionConfig,
    privacy: PrivacyConfig,
    token_budgets: TokenBudgetConfig | None,
    provider_policy: OpenRouterProviderPolicy,
    model_identity: _RegisteredModelIdentity | None,
    endpoint_policy: _RegisteredEndpointPolicy | None,
    structured_output_plan: _StructuredOutputRequestPlan,
    request_token_plan: RequestTokenPlan,
    context_request_evidence: ContextRequestEvidence | None,
    request_material_projection: str,
    request_material_projection_sha256: str,
    request_token_plan_projection_sha256: str,
    endpoint_cost_bound: EndpointRequestCostBound | None,
    maximum_attempts: int,
) -> None:
    """Reject any dispatch material that differs from its provider-free exact preview."""

    reasoning_plan = request_token_plan.reasoning_plan
    if (
        token_budgets is None
        or model_identity is None
        or model_identity.discovery_manifest_sha256 is None
        or endpoint_policy is None
        or endpoint_cost_bound is None
        or reasoning_plan is None
        or reasoning_plan.endpoint_capability_sha256 is None
        or reasoning_plan.qualification_binding_sha256 is not None
    ):
        raise OpenRouterRequestCostPreviewError(
            "provider dispatch lacks the frozen evidence required by its cost preview"
        )
    endpoint = endpoint_policy.endpoint(endpoint_cost_bound.provider_endpoint)
    if endpoint is None:
        raise OpenRouterRequestCostPreviewError(
            "provider dispatch lacks the exact endpoint bound by its cost preview"
        )
    maximum_cost = _trusted_endpoint_request_maximum_cost_usd(endpoint_cost_bound)
    context_sha256 = (
        context_request_evidence.evidence_sha256 if context_request_evidence is not None else None
    )
    rendered_context_sha256 = (
        context_request_evidence.rendered_sha256 if context_request_evidence is not None else None
    )
    actual_fields: dict[str, object] = {
        "logical_request_id": request_token_plan.request_id,
        "role": request_token_plan.role,
        "exact_model_id": endpoint_cost_bound.exact_model_id,
        "provider_endpoint": endpoint_cost_bound.provider_endpoint,
        "maximum_attempts": maximum_attempts,
        "execution_config_sha256": _canonical_sha256(execution.model_dump(mode="json")),
        "privacy_config_sha256": _canonical_sha256(privacy.model_dump(mode="json")),
        "token_budget_config_sha256": _canonical_sha256(token_budgets.model_dump(mode="json")),
        "provider_policy_sha256": _request_cost_preview_provider_policy_sha256(provider_policy),
        "discovery_manifest_sha256": model_identity.discovery_manifest_sha256,
        "discovery_evidence_sha256": model_identity.discovery_evidence_sha256,
        "discovery_provenance_sha256": model_identity.discovery_provenance_sha256,
        "catalog_snapshot_sha256": model_identity.catalog_snapshot_sha256,
        "catalog_identity_binding_sha256": model_identity.catalog_identity_binding_sha256,
        "model_metadata_snapshot_sha256": model_identity.model_metadata_snapshot_sha256,
        "model_identity_snapshot_sha256": model_identity.snapshot.snapshot_sha256,
        "endpoint_policy_snapshot_sha256": endpoint_policy.snapshot_sha256,
        "endpoint_record_snapshot_sha256": endpoint.snapshot_sha256,
        "endpoint_policy_pricing_sha256": endpoint_policy.policy_pricing_sha256,
        "endpoint_pricing_sha256": endpoint.pricing_sha256,
        "output_capability_sha256": endpoint_policy.output_capability_sha256,
        "reasoning_capability_sha256": reasoning_plan.endpoint_capability_sha256,
        "structured_output_mode": structured_output_plan.mode,
        "prompt_sha256": _structured_output_prompt_sha256_from_plan(structured_output_plan),
        "system_prompt_sha256": hashlib.sha256(
            structured_output_plan.system_prompt.encode("utf-8")
        ).hexdigest(),
        "user_prompt_sha256": hashlib.sha256(
            structured_output_plan.user_prompt.encode("utf-8")
        ).hexdigest(),
        "response_schema_sha256": structured_output_plan.schema_sha256,
        "output_request_shape_sha256": structured_output_plan.request_shape_sha256,
        "required_provider_parameters_sha256": _canonical_sha256(
            structured_output_plan.required_provider_parameters
        ),
        "strict_output_protocol_sha256": structured_output_plan.strict_protocol_sha256,
        "reasoning_request_sha256": structured_output_plan.reasoning_request_sha256,
        "reasoning_plan_sha256": reasoning_plan.evidence_sha256,
        "reasoning_policy_sha256": reasoning_plan.policy_artifact_sha256,
        "reasoning_policy_role_binding_sha256": (reasoning_plan.policy_role_binding_sha256),
        "reasoning_profile_sha256": reasoning_plan.control_profile.profile_sha256,
        "reasoning_qualification_sha256": reasoning_plan.qualification_binding_sha256,
        "context_request_evidence_sha256": context_sha256,
        "rendered_context_sha256": rendered_context_sha256,
        "request_token_plan_projection_sha256": request_token_plan_projection_sha256,
        "request_material_projection_sha256": request_material_projection_sha256,
        "request_material_projection_utf8_bytes": len(request_material_projection.encode("utf-8")),
        "endpoint_cost_bound_pricing_sha256": (endpoint_cost_bound.pricing_snapshot_sha256),
        "endpoint_cost_bound_projection_sha256": (
            _endpoint_request_cost_bound_projection_sha256(
                endpoint_cost_bound,
                request_material_projection_sha256=request_material_projection_sha256,
            )
        ),
        "prompt_byte_upper_bound_tokens": (request_token_plan.prompt_byte_upper_bound_tokens),
        "requested_completion_tokens": request_token_plan.requested_completion_tokens,
        "reserved_output_tokens": request_token_plan.reserved_output_tokens,
        "reserved_reasoning_tokens": request_token_plan.reserved_reasoning_tokens,
        "maximum_priced_prompt_units": _trusted_endpoint_request_maximum_units_for(
            endpoint_cost_bound,
            "prompt",
        ),
        "maximum_cost_usd_per_attempt_exact": _format_cost_decimal(maximum_cost),
        "maximum_cost_usd_all_attempts_exact": _multiply_cost_decimal(
            maximum_cost,
            maximum_attempts,
        ),
    }
    mismatched_fields = tuple(
        field for field, actual in actual_fields.items() if getattr(expected, field) != actual
    )
    actual_components = tuple(
        OpenRouterRequestCostComponentPreview(
            pricing_field=component.pricing_field,
            unit_price_usd_exact=_format_cost_decimal(component.unit_price_usd),
            maximum_units=component.maximum_units,
        )
        for component in endpoint_cost_bound.components
    )
    if expected.cost_components != actual_components:
        mismatched_fields = (*mismatched_fields, "cost_components")
    if mismatched_fields:
        raise OpenRouterRequestCostPreviewError(
            "provider request changed after exact cost preview: "
            + ", ".join(sorted(mismatched_fields))
        )


def _validate_provider_token_usage(
    *,
    request_token_plan: RequestTokenPlan,
    prompt_tokens: int,
    completion_tokens: int,
    reasoning_tokens: int,
) -> None:
    """Reject provider usage that exceeds any frozen request or endpoint ceiling."""

    limits = request_token_plan.route_intersection
    if (
        prompt_tokens > request_token_plan.prompt_byte_upper_bound_tokens
        or prompt_tokens > limits.max_prompt_tokens
        or completion_tokens > request_token_plan.requested_completion_tokens
        or completion_tokens > limits.max_completion_tokens
        or prompt_tokens + completion_tokens > limits.context_tokens
        or reasoning_tokens > completion_tokens
        or reasoning_tokens > request_token_plan.reserved_reasoning_tokens
        or completion_tokens - reasoning_tokens > request_token_plan.reserved_output_tokens
    ):
        raise OpenRouterSchemaError(
            "provider-reported token usage exceeds the endpoint-bound request plan"
        )


def _require_matching_request_parameter_profile(
    endpoint_policy: _RegisteredEndpointPolicy,
    plan: _StructuredOutputRequestPlan,
    *,
    sealed_reasoning_plan: ReasoningRequestPlanEvidence | None,
) -> None:
    """Require frozen endpoint metadata to bind every emitted special parameter."""

    planned = set(plan.required_provider_parameters)
    planned_reasoning = REASONING_REQUEST_PARAMETER in planned
    if sealed_reasoning_plan is not None:
        control = sealed_reasoning_plan.control_profile
        expected_reasoning_payload = (
            None
            if control.mode == "disabled"
            else OpenRouterReasoning(
                effort=control.effort,
                max_tokens=control.max_tokens,
                exclude=control.exclude,
            ).as_request_payload()
        )
        if plan.reasoning_payload != expected_reasoning_payload or planned_reasoning is not (
            expected_reasoning_payload is not None
        ):
            raise OpenRouterProviderPolicyError(
                "emitted reasoning request differs from its exact sealed role plan"
            )
    for endpoint in endpoint_policy.endpoints:
        frozen = set(endpoint.required_request_parameters) - _BASE_ENDPOINT_REQUEST_PARAMETERS
        frozen_reasoning = REASONING_REQUEST_PARAMETER in frozen
        output_frozen = frozen - {REASONING_REQUEST_PARAMETER}
        output_planned = planned - {REASONING_REQUEST_PARAMETER}
        if (
            output_frozen != output_planned
            or (sealed_reasoning_plan is None and frozen_reasoning != planned_reasoning)
            or not planned.issubset(endpoint.supported_parameters)
        ):
            raise OpenRouterProviderPolicyError(
                "frozen endpoint request parameter profile differs from the emitted request"
            )


def _registered_endpoints_for_output_mode(
    endpoints: tuple[_RegisteredEndpointPricing, ...],
    mode: StructuredOutputMode,
    *,
    reasoning_requested: bool,
) -> tuple[_RegisteredEndpointPricing, ...]:
    """Project capability snapshots onto one exact runtime request profile."""

    requested_output_parameters = set(output_mode_request_parameters(mode))
    projected: list[_RegisteredEndpointPricing] = []
    for endpoint in endpoints:
        if reasoning_requested and REASONING_REQUEST_PARAMETER not in (
            endpoint.supported_parameters
        ):
            raise OpenRouterProviderPolicyError(
                "requested reasoning lacks exact endpoint parameter support"
            )
        required = tuple(
            sorted(
                (set(endpoint.required_request_parameters) - _ROUTE_SENSITIVE_REQUEST_PARAMETERS)
                | requested_output_parameters
                | ({REASONING_REQUEST_PARAMETER} if reasoning_requested else set())
            )
        )
        if not set(required).issubset(endpoint.supported_parameters):
            raise OpenRouterProviderPolicyError(
                "model-selected output mode is unsupported by a configured endpoint"
            )
        projected.append(
            replace(
                endpoint,
                required_request_parameters=required,
                structured_output_mode=mode,
            )
        )
    return tuple(projected)


@dataclass(frozen=True)
class _TrustedTransportBinding:
    """Issuer-held transport authority that instance attribute mutation cannot create."""

    execution_evidence: ExecutionEvidenceKind
    http_client: httpx.AsyncClient
    transport: object
    base_url: str
    budget_manager: BudgetManager
    paid_controls_required: bool
    budget_total_usd: float
    budget_max_output_tokens: int
    budget_conservative_rate: float
    budget_max_requests_per_agent: int
    budget_require_endpoint_cost_bound: bool
    budget_global_input_token_budget: int | None
    budget_global_output_token_budget: int | None
    budget_per_model_usd_caps: tuple[tuple[str, Decimal], ...]
    budget_per_role_usd_caps: tuple[tuple[str, Decimal], ...]
    budget_lock: asyncio.Lock
    atomic_cost_ledger: AtomicCostLedger | None
    atomic_cost_ledger_path: Path | None
    atomic_cost_ledger_lock_path: Path | None
    atomic_cost_ledger_cap_usd: Decimal | None
    atomic_cost_ledger_thread_lock: object | None
    mock_handler: object | None = None
    test_only_context_package_budget_observer: _TestOnlyContextPackageBudgetObserver | None = None
    request_lock: asyncio.Lock | None = None
    client_attribute_names: frozenset[str] = frozenset()
    transport_attribute_names: frozenset[str] = frozenset()
    owned_pool: object | None = None
    owned_pool_attribute_names: frozenset[str] = frozenset()
    owned_pool_attribute_values: tuple[tuple[str, object], ...] = ()
    owned_pool_request_callable: object | None = None
    owned_pool_create_connection_callable: object | None = None
    owned_pool_assign_requests_callable: object | None = None
    owned_pool_close_connections_callable: object | None = None
    owned_pool_getattribute_callable: object | None = None
    network_backend: object | None = None
    network_backend_type: type[object] | None = None
    network_backend_attribute_names: frozenset[str] = frozenset()
    network_backend_connect_tcp_callable: object | None = None
    network_backend_connect_unix_socket_callable: object | None = None
    network_backend_sleep_callable: object | None = None
    network_backend_init_callable: object | None = None
    network_backend_getattribute_callable: object | None = None
    follow_redirects: bool = False
    max_redirects: int = 0


def _transport_binding_registry() -> tuple[
    Callable[[object, _TrustedTransportBinding], None],
    Callable[[object], _TrustedTransportBinding | None],
]:
    bindings: WeakKeyDictionary[object, _TrustedTransportBinding] = WeakKeyDictionary()
    lock = Lock()

    def register(subject: object, binding: _TrustedTransportBinding) -> None:
        with lock:
            bindings[subject] = binding

    def lookup(subject: object) -> _TrustedTransportBinding | None:
        with lock:
            return bindings.get(subject)

    return register, lookup


_register_trusted_transport_binding, _lookup_trusted_transport_binding = (
    _transport_binding_registry()
)


def _endpoint_snapshot_binding_registry() -> tuple[
    Callable[[object, str, str], None],
    Callable[[object, str], str | None],
]:
    bindings: WeakKeyDictionary[object, dict[str, str]] = WeakKeyDictionary()
    lock = Lock()

    def register(subject: object, exact_model_id: str, snapshot_sha256: str) -> None:
        if _SHA256_PATTERN.fullmatch(snapshot_sha256) is None:
            raise OpenRouterCostControlError("endpoint snapshot binding hash is invalid")
        with lock:
            current = dict(bindings.get(subject, {}))
            current[exact_model_id] = snapshot_sha256
            bindings[subject] = current

    def lookup(subject: object, exact_model_id: str) -> str | None:
        with lock:
            current = bindings.get(subject)
            return None if current is None else current.get(exact_model_id)

    return register, lookup


_register_trusted_endpoint_snapshot, _lookup_trusted_endpoint_snapshot = (
    _endpoint_snapshot_binding_registry()
)

_TRUSTED_PATH_TYPE = type(Path("/"))


def _require_exact_paid_budget_configuration(budget: BudgetManager) -> None:
    """Reject deceptive container and numeric subclasses in paid budget authority."""

    try:
        total_usd = object.__getattribute__(budget, "total_usd")
        max_output_tokens = object.__getattribute__(budget, "max_output_tokens")
        conservative_rate = object.__getattribute__(budget, "conservative_rate")
        max_requests = object.__getattribute__(budget, "max_requests_per_agent")
        require_bound = object.__getattribute__(budget, "require_endpoint_cost_bound")
        global_input = object.__getattribute__(budget, "global_input_token_budget")
        global_output = object.__getattribute__(budget, "global_output_token_budget")
        per_model = object.__getattribute__(budget, "per_model_usd_caps")
        per_role = object.__getattribute__(budget, "per_role_usd_caps")
        budget_lock = object.__getattribute__(budget, "_lock")
    except (AttributeError, TypeError) as exc:
        raise OpenRouterPrivacyError("paid provider budget configuration is invalid") from exc
    if (
        type(total_usd) is not float
        or not math.isfinite(total_usd)
        or type(max_output_tokens) is not int
        or type(conservative_rate) is not float
        or not math.isfinite(conservative_rate)
        or type(max_requests) is not int
        or type(require_bound) is not bool
        or not (global_input is None or type(global_input) is int)
        or not (global_output is None or type(global_output) is int)
        or type(per_model) is not dict
        or type(per_role) is not dict
        or type(budget_lock) is not asyncio.Lock
        or any(
            type(key) is not str or type(value) is not Decimal
            for key, value in (*per_model.items(), *per_role.items())
        )
    ):
        raise OpenRouterPrivacyError("paid provider budget configuration is invalid")


def _require_exact_atomic_ledger_configuration(ledger: AtomicCostLedger) -> None:
    """Require exact immutable primitives before binding persistent paid custody."""

    if (
        type(ledger) is not AtomicCostLedger
        or type(ledger.path) is not _TRUSTED_PATH_TYPE
        or type(ledger.lock_path) is not _TRUSTED_PATH_TYPE
        or type(ledger.cap_usd) is not Decimal
        or not ledger.cap_usd.is_finite()
        or ledger.cap_usd <= 0
    ):
        raise OpenRouterPrivacyError("paid provider cost-ledger configuration is invalid")


def _trusted_paid_controls_required(subject: object) -> bool:
    """Return the construction-time paid-control requirement or fail closed."""

    binding = _lookup_trusted_transport_binding(subject)
    try:
        current = object.__getattribute__(subject, "_requires_paid_controls")
    except (AttributeError, TypeError) as exc:
        raise OpenRouterPrivacyError(
            "provider paid-control requirement changed after validation"
        ) from exc
    if (
        binding is None
        or type(current) is not bool
        or current is not binding.paid_controls_required
    ):
        raise OpenRouterPrivacyError("provider paid-control requirement changed after validation")
    return binding.paid_controls_required


class OpenRouterClient:
    """Minimal client that never enables tools, web access, or random model routing."""

    def __init__(
        self,
        *,
        api_key: str,
        execution: ExecutionConfig,
        privacy: PrivacyConfig,
        budget: BudgetManager,
        usage: UsageLedger,
        base_url: str = OPENROUTER_DEFAULT_BASE_URL,
        http_client: httpx.AsyncClient | None = None,
        run_dir: Path | None = None,
        logger: logging.Logger | None = None,
        random_seed: int = 0,
        provider_policy: OpenRouterProviderPolicy | None = None,
        reasoning: OpenRouterReasoning | None = None,
        reasoning_policy: ReasoningPolicyArtifact | None = None,
        token_budgets: TokenBudgetConfig | None = None,
        qualification_routing: tuple[OpenRouterQualificationRoutingEvidence, ...] = (),
        production_qualification: VerifiedProductionQualification | None = None,
        audit_model_selection: VerifiedAuditModelSelection | None = None,
        policy_audit_context: PolicyAuditContext | None = None,
        client_policy_constraints: ClientPolicyConstraints | None = None,
        audit_model_refresh_evidence: AuditModelRefreshEvidence | None = None,
        audit_model_refresh_guard: VerifiedAuditModelRefreshGuard | None = None,
        audit_model_refresh_pricing_evidence: AuditModelRefreshPricingEvidence | None = None,
        audit_model_refresh_pricing_authority: (
            VerifiedAuditModelRefreshPricingAuthority | None
        ) = None,
        effective_privacy_policy: EffectivePrivacyPolicyEvidence | None = None,
        source_provenance_observation: PrivacySourceProvenanceObservation | None = None,
        privacy_authorization: TrustedPrivacyAuthorization | None = None,
        context_preflight_ledger: ContextPreflightLedger | None = None,
        test_only_mock_handler: (
            Callable[[httpx.Request], httpx.Response]
            | Callable[[httpx.Request], Coroutine[None, None, httpx.Response]]
            | None
        ) = None,
        test_only_context_package_budget_observer: (
            _TestOnlyContextPackageBudgetObserver | None
        ) = None,
    ) -> None:
        if http_client is not None and test_only_mock_handler is not None:
            raise OpenRouterPrivacyError(
                "test-only mock handler cannot be combined with an injected HTTP client"
            )
        if test_only_mock_handler is not None and "synthetic" not in api_key.lower():
            raise OpenRouterPrivacyError(
                "test-only mock transport requires an explicitly synthetic credential"
            )
        if test_only_context_package_budget_observer is not None and test_only_mock_handler is None:
            raise OpenRouterPrivacyError(
                "test-only context budget observer requires the test-only mock transport"
            )
        if test_only_context_package_budget_observer is not None and not callable(
            test_only_context_package_budget_observer
        ):
            raise OpenRouterPrivacyError("test-only context budget observer must be callable")
        if (
            not api_key
            or len(api_key.encode("utf-8")) > 4_096
            or not api_key.isascii()
            or any(not 33 <= ord(character) <= 126 for character in api_key)
        ):
            raise OpenRouterAuthenticationError("operator API credential is missing or invalid")
        self.execution = execution
        self.privacy = privacy
        self.budget = budget
        self.usage = usage
        self.context_preflight = context_preflight_ledger or ContextPreflightLedger()
        self.run_dir = run_dir
        self.logger = logger or logging.getLogger("mmaudit.openrouter")
        self._random = random.Random(random_seed)
        self.provider_policy = _canonical_provider_policy(
            provider_policy if provider_policy is not None else OpenRouterProviderPolicy()
        )
        if reasoning is not None and reasoning_policy is not None:
            raise OpenRouterRequestLimitError(
                "legacy global reasoning and per-role reasoning policy are mutually exclusive"
            )
        self.reasoning = reasoning
        self.reasoning_policy = (
            ReasoningPolicyArtifact.model_validate(reasoning_policy.model_dump(mode="python"))
            if reasoning_policy is not None
            else None
        )
        self.token_budgets = (
            TokenBudgetConfig.model_validate(token_budgets.model_dump(mode="python"))
            if token_budgets is not None
            else None
        )
        if self.token_budgets is not None:
            if (
                self.token_budgets.reserved_output_tokens is not None
                and self.token_budgets.reserved_output_tokens
                != self.execution.max_output_tokens_per_request
            ):
                raise OpenRouterCostControlError(
                    "token output reserve differs from the execution request limit"
                )
            if (
                self.budget.global_input_token_budget
                != self.token_budgets.global_input_token_budget
            ):
                raise OpenRouterCostControlError(
                    "request and atomic global input token budgets differ"
                )
            if (
                self.budget.global_output_token_budget
                != self.token_budgets.global_output_token_budget
            ):
                raise OpenRouterCostControlError(
                    "request and atomic global output token budgets differ"
                )
        self.effective_privacy_policy = (
            _canonical_effective_privacy_policy(effective_privacy_policy)
            if effective_privacy_policy is not None
            else None
        )
        if source_provenance_observation is not None and self.effective_privacy_policy is None:
            raise OpenRouterPrivacyError(
                "live privacy source provenance requires effective privacy evidence"
            )
        self._privacy_source_provenance_observation = (
            _validate_live_privacy_source_provenance(
                source_provenance_observation,
                policy=self.effective_privacy_policy,
            )
            if source_provenance_observation is not None
            and self.effective_privacy_policy is not None
            else None
        )
        self._privacy_authorization = privacy_authorization
        self._endpoint_pricing: dict[str, _RegisteredEndpointPolicy] = {}
        self._model_identities: dict[str, _RegisteredModelIdentity] = {}
        self._reasoning_capabilities: dict[
            str,
            OpenRouterReasoningCapabilityEvidence,
        ] = {}
        self._reasoning_discoveries: dict[str, OpenRouterModelDiscoveryPayload] = {}
        qualification_model_ids = tuple(binding.exact_model_id for binding in qualification_routing)
        if qualification_model_ids != tuple(sorted(set(qualification_model_ids))):
            raise OpenRouterQualificationError(
                "qualification routing bindings must be unique and sorted by exact model"
            )
        self._qualification_routing = {
            binding.exact_model_id: binding for binding in qualification_routing
        }
        self._production_qualification = (
            _require_exact_qualification_routing_authority(
                routing=qualification_routing,
                qualification=production_qualification,
                now=datetime.now(UTC).replace(microsecond=0),
            )
            if production_qualification is not None
            else None
        )
        self._audit_policy_binding = _canonical_audit_policy_binding(
            policy_audit_context=policy_audit_context,
            client_policy_constraints=client_policy_constraints,
            effective_privacy_policy=self.effective_privacy_policy,
        )
        if (audit_model_selection is None) != (self._audit_policy_binding is None):
            raise OpenRouterPolicyEligibilityError(
                "audit model selection and independent audit policy binding must be supplied "
                "together"
            )
        self._audit_model_selection: VerifiedAuditModelSelection | None
        if audit_model_selection is not None:
            assert self._audit_policy_binding is not None
            self._audit_model_selection = _require_exact_audit_model_selection_authority(
                selection=audit_model_selection,
                binding=self._audit_policy_binding,
                now=datetime.now(UTC).replace(microsecond=0),
            )
        else:
            self._audit_model_selection = None
        self._audit_model_refresh_binding = _canonical_audit_model_refresh_binding(
            evidence=audit_model_refresh_evidence,
            guard=audit_model_refresh_guard,
        )
        self._audit_model_refresh_pricing_binding = _canonical_audit_model_refresh_pricing_binding(
            evidence=audit_model_refresh_pricing_evidence,
            authority=audit_model_refresh_pricing_authority,
            refresh_binding=self._audit_model_refresh_binding,
        )
        if self._audit_model_refresh_pricing_binding is not None and (
            self._production_qualification is None
            or self._audit_model_selection is None
            or self._audit_policy_binding is None
        ):
            raise OpenRouterModelRefreshPricingError(
                "audit model refresh pricing lacks exact technical and audit authority"
            )
        if self._audit_model_refresh_pricing_binding is not None:
            self.require_audit_model_refresh_pricing_binding(
                audit_model_refresh_pricing_evidence=(
                    self._audit_model_refresh_pricing_binding.evidence
                ),
                audit_model_refresh_pricing_authority=(
                    self._audit_model_refresh_pricing_binding.authority
                ),
                checked_at=datetime.now(UTC).replace(microsecond=0),
            )
        self._metadata_observations: dict[str, str] = {}
        self._unbound_completions: dict[str, StructuredCompletion[Any]] = {}
        self._claimed_request_ids: set[str] = set()
        self._request_identity_lock = Lock()
        self._request_lifecycle_observer: ModelRequestLifecycleObserver | None = None
        self._authentication_validated = False
        if (effective_privacy_policy is None) != (privacy_authorization is None) and (
            not self.privacy.require_zdr
        ):
            raise OpenRouterPrivacyError(
                "non-ZDR privacy evidence and live authorization must be supplied together"
            )
        if self.effective_privacy_policy is not None and (
            self.effective_privacy_policy.privacy_profile is not self.privacy.profile
            or self.effective_privacy_policy.require_zdr is not self.privacy.require_zdr
        ):
            raise OpenRouterPrivacyError(
                "effective privacy evidence differs from configured provider privacy"
            )
        if self.provider_policy.certification and not self.privacy.require_zdr:
            self._validate_non_zdr_privacy_authorization(
                self.effective_privacy_policy.permitted_model_ids
                if self.effective_privacy_policy is not None
                else ()
            )
        if self.execution.max_json_repair_attempts and self.provider_policy.certification:
            raise OpenRouterSchemaError(
                "model-output repair is disabled for certification because repaired output "
                "cannot count as a review"
            )
        closed_mock_transport = test_only_mock_handler is not None
        self._owns_client = http_client is None and not closed_mock_transport
        normalized_base_url = base_url.rstrip("/") + "/"
        effective_base_url = (
            normalized_base_url
            if http_client is None
            else str(http_client.base_url).rstrip("/") + "/"
        )
        if not closed_mock_transport and effective_base_url != _NORMALIZED_OPENROUTER_BASE_URL:
            raise OpenRouterPrivacyError(
                "operator credentials may only use the canonical OpenRouter API endpoint"
            )
        initial_execution_evidence = (
            ExecutionEvidenceKind.MOCK
            if closed_mock_transport
            else (
                ExecutionEvidenceKind.REAL
                if self._owns_client
                else ExecutionEvidenceKind.UNVERIFIED
            )
        )
        self.execution_evidence = initial_execution_evidence
        self._requires_paid_controls = (
            not closed_mock_transport or self.budget.atomic_ledger is not None
        )
        if self._requires_paid_controls:
            _require_exact_paid_budget_configuration(self.budget)
            if self.budget.atomic_ledger is not None:
                _require_exact_atomic_ledger_configuration(self.budget.atomic_ledger)
        self._credential = bytearray(api_key.encode("utf-8"))
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/mmaudit/mmaudit",
            "X-OpenRouter-Title": "mmaudit",
            "X-OpenRouter-Metadata": "enabled",
        }
        if test_only_mock_handler is not None:
            self._client = httpx.AsyncClient(
                base_url=normalized_base_url,
                timeout=httpx.Timeout(execution.request_timeout_seconds),
                headers=self._headers,
                transport=httpx.MockTransport(test_only_mock_handler),
                trust_env=False,
            )
        else:
            self._client = http_client or httpx.AsyncClient(
                base_url=normalized_base_url,
                timeout=httpx.Timeout(execution.request_timeout_seconds),
                headers=self._headers,
                limits=httpx.Limits(max_keepalive_connections=0),
                trust_env=False,
            )
        self._client_identity = self._client
        self._base_url_identity = str(self._client.base_url)
        self._transport_identity = getattr(self._client, "_transport", None)
        self._test_only_mock_transport_authorized = closed_mock_transport
        self._mock_handler_identity = (
            getattr(self._transport_identity, "handler", None) if closed_mock_transport else None
        )
        self._owned_client_identity = self._client if self._owns_client else None
        self._owned_transport_identity = (
            getattr(self._client, "_transport", None) if self._owns_client else None
        )
        self._close_client_identity = (
            self._client if self._owns_client or closed_mock_transport else None
        )
        if self._owns_client and not _owned_httpx_callables_are_pristine(
            self._client,
            self._owned_transport_identity,
        ):
            raise OpenRouterPrivacyError("owned provider callable provenance is invalid")
        if closed_mock_transport and not _mock_httpx_callables_are_pristine(
            self._client,
            self._transport_identity,
            self._mock_handler_identity,
        ):
            raise OpenRouterPrivacyError("test-only mock transport provenance is invalid")
        if type(self) is OpenRouterClient and initial_execution_evidence in {
            ExecutionEvidenceKind.REAL,
            ExecutionEvidenceKind.MOCK,
        }:
            owned_pool = (
                getattr(self._transport_identity, "_pool", None)
                if initial_execution_evidence is ExecutionEvidenceKind.REAL
                else None
            )
            network_backend = (
                getattr(owned_pool, "_network_backend", None) if owned_pool is not None else None
            )
            _register_trusted_transport_binding(
                self,
                _TrustedTransportBinding(
                    execution_evidence=initial_execution_evidence,
                    http_client=self._client,
                    transport=self._transport_identity,
                    base_url=self._base_url_identity,
                    budget_manager=self.budget,
                    paid_controls_required=self._requires_paid_controls,
                    budget_total_usd=self.budget.total_usd,
                    budget_max_output_tokens=self.budget.max_output_tokens,
                    budget_conservative_rate=self.budget.conservative_rate,
                    budget_max_requests_per_agent=self.budget.max_requests_per_agent,
                    budget_require_endpoint_cost_bound=(self.budget.require_endpoint_cost_bound),
                    budget_global_input_token_budget=(self.budget.global_input_token_budget),
                    budget_global_output_token_budget=(self.budget.global_output_token_budget),
                    budget_per_model_usd_caps=tuple(sorted(self.budget.per_model_usd_caps.items())),
                    budget_per_role_usd_caps=tuple(sorted(self.budget.per_role_usd_caps.items())),
                    budget_lock=self.budget._lock,
                    atomic_cost_ledger=self.budget.atomic_ledger,
                    atomic_cost_ledger_path=(
                        self.budget.atomic_ledger.path
                        if self.budget.atomic_ledger is not None
                        else None
                    ),
                    atomic_cost_ledger_lock_path=(
                        self.budget.atomic_ledger.lock_path
                        if self.budget.atomic_ledger is not None
                        else None
                    ),
                    atomic_cost_ledger_cap_usd=(
                        self.budget.atomic_ledger.cap_usd
                        if self.budget.atomic_ledger is not None
                        else None
                    ),
                    atomic_cost_ledger_thread_lock=(
                        self.budget.atomic_ledger._thread_lock
                        if self.budget.atomic_ledger is not None
                        else None
                    ),
                    mock_handler=self._mock_handler_identity,
                    test_only_context_package_budget_observer=(
                        test_only_context_package_budget_observer
                    ),
                    request_lock=(
                        asyncio.Lock()
                        if initial_execution_evidence is ExecutionEvidenceKind.REAL
                        else None
                    ),
                    client_attribute_names=frozenset(vars(self._client)),
                    transport_attribute_names=frozenset(vars(self._transport_identity)),
                    owned_pool=owned_pool,
                    owned_pool_attribute_names=(
                        frozenset(vars(owned_pool)) if owned_pool is not None else frozenset()
                    ),
                    owned_pool_attribute_values=(
                        tuple(sorted(vars(owned_pool).items())) if owned_pool is not None else ()
                    ),
                    owned_pool_request_callable=(
                        getattr(type(owned_pool), "handle_async_request", None)
                        if owned_pool is not None
                        else None
                    ),
                    owned_pool_create_connection_callable=(
                        getattr(type(owned_pool), "create_connection", None)
                        if owned_pool is not None
                        else None
                    ),
                    owned_pool_assign_requests_callable=(
                        getattr(type(owned_pool), "_assign_requests_to_connections", None)
                        if owned_pool is not None
                        else None
                    ),
                    owned_pool_close_connections_callable=(
                        getattr(type(owned_pool), "_close_connections", None)
                        if owned_pool is not None
                        else None
                    ),
                    owned_pool_getattribute_callable=(
                        getattr(type(owned_pool), "__getattribute__", None)
                        if owned_pool is not None
                        else None
                    ),
                    network_backend=network_backend,
                    network_backend_type=(
                        type(network_backend) if network_backend is not None else None
                    ),
                    network_backend_attribute_names=(
                        frozenset(vars(network_backend))
                        if network_backend is not None
                        else frozenset()
                    ),
                    network_backend_connect_tcp_callable=(
                        getattr(type(network_backend), "connect_tcp", None)
                        if network_backend is not None
                        else None
                    ),
                    network_backend_connect_unix_socket_callable=(
                        getattr(type(network_backend), "connect_unix_socket", None)
                        if network_backend is not None
                        else None
                    ),
                    network_backend_sleep_callable=(
                        getattr(type(network_backend), "sleep", None)
                        if network_backend is not None
                        else None
                    ),
                    network_backend_init_callable=(
                        getattr(type(network_backend), "_init_backend", None)
                        if network_backend is not None
                        else None
                    ),
                    network_backend_getattribute_callable=(
                        getattr(type(network_backend), "__getattribute__", None)
                        if network_backend is not None
                        else None
                    ),
                    follow_redirects=self._client.follow_redirects,
                    max_redirects=self._client.max_redirects,
                ),
            )

    async def __aenter__(self) -> OpenRouterClient:
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.close()

    async def close(self) -> None:
        self.clear_credentials()
        if self._close_client_identity is not None:
            await self._close_client_identity.aclose()

    def retained_unbound_completions(self) -> tuple[StructuredCompletion[Any], ...]:
        """Return bounded in-memory unbound evidence without serializing its values."""

        return tuple(
            self._unbound_completions[request_id]
            for request_id in sorted(self._unbound_completions)
        )

    def clear_retained_unbound_completions(self) -> None:
        """Release all retained unbound structured values after operator handling."""

        self._unbound_completions.clear()

    def _retain_unbound_completion(self, completion: StructuredCompletion[Any]) -> None:
        if not _is_concluded_unbound_completion(completion):
            raise OpenRouterModelError("only concluded unbound evidence may be retained")
        request_id = completion.usage_record.request_id
        existing = self._unbound_completions.get(request_id)
        if existing is completion:
            return
        if existing is not None:
            raise OpenRouterModelError("unbound evidence request identity is duplicated")
        if len(self._unbound_completions) >= _MAX_RETAINED_UNBOUND_COMPLETIONS:
            raise OpenRouterRequestLimitError(
                "unbound evidence retention is full; inspect and clear it before retrying"
            )
        self._unbound_completions[request_id] = completion

    def _validate_non_zdr_privacy_authorization(
        self,
        requested_models: tuple[str, ...] | list[str],
        *,
        request_provider_endpoints: tuple[str, ...] | list[str] | None = None,
    ) -> EffectivePrivacyPolicyEvidence:
        evidence = self.effective_privacy_policy
        authorization = self._privacy_authorization
        if evidence is None or authorization is None:
            raise OpenRouterPrivacyError(
                "non-ZDR provider execution requires live operator privacy authorization"
            )
        try:
            expected_models = tuple(evidence.permitted_model_ids)
            pending_models = tuple(requested_models)
            pending_endpoints = (
                tuple(request_provider_endpoints)
                if request_provider_endpoints is not None
                else None
            )
        except (TypeError, ValueError):
            raise OpenRouterPrivacyError(
                "non-ZDR provider privacy authorization contains invalid route state"
            ) from None
        try:
            validated = validate_trusted_privacy_authorization(
                authorization,
                evidence_sha256=evidence.evidence_sha256,
                source_sha256=evidence.source_sha256,
                source_classification=evidence.source_classification,
                configured_model_ids=expected_models,
                configured_provider_endpoints=self.provider_policy.configured_endpoints,
                requested_budget_usd=Decimal(str(self.budget.total_usd)),
                now=datetime.now(UTC).replace(microsecond=0),
            )
        except ValueError as exc:
            raise OpenRouterPrivacyError(
                f"non-ZDR provider privacy authorization failed: {exc}"
            ) from None
        if not pending_models or any(
            model not in validated.permitted_model_ids for model in pending_models
        ):
            raise OpenRouterPrivacyError(
                "non-ZDR provider execution requested a model outside consent"
            )
        if pending_endpoints is not None:
            if not pending_endpoints or any(
                endpoint not in validated.permitted_provider_endpoints
                for endpoint in pending_endpoints
            ):
                raise OpenRouterPrivacyError(
                    "non-ZDR provider execution requested an endpoint outside consent"
                )
            disclosed_non_zdr_endpoints = frozenset(
                disclosure.provider_endpoint
                for disclosure in validated.endpoint_disclosures
                if disclosure.policy_class is EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED
            )
            if any(endpoint not in disclosed_non_zdr_endpoints for endpoint in pending_endpoints):
                raise OpenRouterPrivacyError(
                    "non-ZDR provider execution requested an endpoint without exact "
                    "non-ZDR disclosure"
                )
        return validated

    def _validate_paid_privacy_policy(
        self,
        requested_models: tuple[str, ...] | list[str],
        *,
        request_provider_endpoints: tuple[str, ...] | list[str],
    ) -> EffectivePrivacyPolicyEvidence:
        """Require canonical policy evidence for the exact pending paid route."""

        evidence = self.effective_privacy_policy
        if evidence is None:
            raise OpenRouterPrivacyError(
                "paid provider execution requires effective privacy evidence"
            )
        validated = _canonical_effective_privacy_policy(evidence)
        if (
            validated.privacy_profile is not self.privacy.profile
            or validated.require_zdr is not self.privacy.require_zdr
        ):
            raise OpenRouterPrivacyError(
                "effective privacy evidence differs from configured provider privacy"
            )
        if Decimal(validated.requested_budget_usd) != Decimal(str(self.budget.total_usd)):
            raise OpenRouterPrivacyError(
                "effective privacy evidence differs from the active model budget"
            )
        try:
            pending_models = tuple(requested_models)
            pending_endpoints = tuple(request_provider_endpoints)
        except (TypeError, ValueError):
            raise OpenRouterPrivacyError(
                "effective privacy evidence contains invalid pending route state"
            ) from None
        if not pending_models or any(
            model not in validated.permitted_model_ids for model in pending_models
        ):
            raise OpenRouterPrivacyError(
                "paid provider execution requested a model outside effective privacy evidence"
            )
        if not pending_endpoints or any(
            endpoint not in validated.permitted_provider_endpoints for endpoint in pending_endpoints
        ):
            raise OpenRouterPrivacyError(
                "paid provider execution requested an endpoint outside effective privacy evidence"
            )
        if self.privacy.require_zdr:
            return validated
        return self._validate_non_zdr_privacy_authorization(
            pending_models,
            request_provider_endpoints=pending_endpoints,
        )

    def bind_effective_privacy_context(
        self,
        *,
        effective_privacy_policy: EffectivePrivacyPolicyEvidence,
        source_provenance_observation: PrivacySourceProvenanceObservation | None = None,
        privacy_authorization: TrustedPrivacyAuthorization | None,
    ) -> None:
        """Bind one canonical source policy before any provider state is observed."""

        if (
            self.effective_privacy_policy is not None
            or self._privacy_source_provenance_observation is not None
            or self._privacy_authorization is not None
        ):
            raise OpenRouterPrivacyError("provider privacy context is already bound")
        if (
            self._endpoint_pricing
            or self._model_identities
            or self._metadata_observations
            or self._unbound_completions
            or self._authentication_validated
        ):
            raise OpenRouterPrivacyError(
                "provider privacy context must be bound before provider state"
            )
        policy = _canonical_effective_privacy_policy(effective_privacy_policy)
        provenance_observation = (
            _validate_live_privacy_source_provenance(
                source_provenance_observation,
                policy=policy,
            )
            if source_provenance_observation is not None
            else None
        )
        if (
            policy.privacy_profile is not self.privacy.profile
            or policy.require_zdr is not self.privacy.require_zdr
        ):
            raise OpenRouterPrivacyError(
                "effective privacy evidence differs from configured provider privacy"
            )
        if policy.require_zdr:
            if privacy_authorization is not None:
                raise OpenRouterPrivacyError("ZDR privacy context rejects retention authorization")
            self.effective_privacy_policy = policy
            self._privacy_source_provenance_observation = provenance_observation
            return
        if privacy_authorization is None:
            raise OpenRouterPrivacyError(
                "non-ZDR privacy evidence and live authorization must be supplied together"
            )
        self.effective_privacy_policy = policy
        self._privacy_source_provenance_observation = provenance_observation
        self._privacy_authorization = privacy_authorization
        try:
            self._validate_non_zdr_privacy_authorization(
                policy.permitted_model_ids,
                request_provider_endpoints=self.provider_policy.configured_endpoints,
            )
        except Exception:
            self.effective_privacy_policy = None
            self._privacy_source_provenance_observation = None
            self._privacy_authorization = None
            raise

    def bind_request_lifecycle_observer(
        self,
        observer: ModelRequestLifecycleObserver,
    ) -> None:
        """Attach one run-local scheduler observer without replacing live custody."""

        if self._request_lifecycle_observer is not None:
            raise OpenRouterRequestLimitError(
                "provider request lifecycle observer is already bound"
            )
        self._request_lifecycle_observer = observer

    def unbind_request_lifecycle_observer(
        self,
        observer: ModelRequestLifecycleObserver,
    ) -> None:
        """Detach only the exact observer installed by the active pipeline run."""

        if self._request_lifecycle_observer is not observer:
            raise OpenRouterRequestLimitError("provider request lifecycle observer differs")
        self._request_lifecycle_observer = None

    def clear_credentials(self) -> None:
        """Drop retained authorization values without serializing them."""

        authorization = self._headers.get("Authorization")
        self._credential[:] = b"\x00" * len(self._credential)
        self._credential.clear()
        self._headers.clear()
        self._privacy_authorization = None
        if (
            self._owned_client_identity is not None
            and self._owned_client_identity.headers.get("Authorization") == authorization
        ):
            self._owned_client_identity.headers.pop("Authorization", None)

    async def validate_authentication(self) -> None:
        """Validate the current bearer credential without returning key metadata."""

        payload = await self._request_metadata("/key")
        if not isinstance(payload.get("data"), dict):
            raise OpenRouterAuthenticationError(
                "OpenRouter key validation returned an invalid response"
            )
        self._authentication_validated = True

    async def list_models(self) -> list[dict[str, Any]]:
        response = await self._request_metadata("/models")
        return _validated_model_catalog(response)

    async def list_certification_models(self) -> list[dict[str, Any]]:
        """Return the unfiltered current candidate catalog.

        Privacy and output capabilities are resolved later from exact endpoint
        evidence. Every returned identifier is still validated locally.
        """

        response = await self.get_certification_model_metadata()
        return _validated_model_catalog(response)

    async def get_certification_model_metadata(self) -> dict[str, Any]:
        """Return the complete fixed-query certification catalog envelope."""

        response = await self._request_metadata(OPENROUTER_CATALOG_QUERY)
        _validated_model_catalog(response)
        return response

    async def get_model_endpoint_metadata(self, model: str) -> dict[str, Any]:
        """Return the exact-model endpoint response envelope after basic validation."""

        response = await self.get_refresh_model_endpoint_metadata(model)
        data = response["data"]
        assert isinstance(data, dict)
        endpoints = data["endpoints"]
        assert isinstance(endpoints, list)
        if not endpoints:
            raise OpenRouterModelError("OpenRouter returned invalid endpoint metadata")
        return response

    async def get_refresh_model_endpoint_metadata(self, model: str) -> dict[str, Any]:
        """Return exact endpoint metadata while preserving an empty withdrawn set."""

        _require_exact_model_id(model)
        response = await self._request_metadata(openrouter_endpoint_query(model))
        data = response.get("data")
        if not isinstance(data, dict):
            raise OpenRouterModelError("OpenRouter returned invalid endpoint metadata")
        if data.get("id") != model:
            raise OpenRouterModelError(
                "OpenRouter endpoint metadata does not bind the exact requested model"
            )
        endpoints = data.get("endpoints")
        if not isinstance(endpoints, list) or any(
            not isinstance(endpoint, dict) for endpoint in endpoints
        ):
            raise OpenRouterModelError("OpenRouter returned invalid endpoint metadata")
        return response

    async def get_model_metadata(self, exact_model_id: str) -> dict[str, Any]:
        """Resolve one exact catalog ID and validate the returned canonical identity."""

        _require_exact_model_id(exact_model_id)
        response = await self._request_metadata(openrouter_model_query(exact_model_id))
        data = response.get("data")
        if not isinstance(data, dict):
            raise OpenRouterModelError("OpenRouter returned invalid single-model metadata")
        observed_id = data.get("id")
        canonical_slug = data.get("canonical_slug")
        if (
            not isinstance(observed_id, str)
            or not is_exact_openrouter_model_id(observed_id)
            or not isinstance(canonical_slug, str)
            or not is_exact_openrouter_model_id(canonical_slug)
            or observed_id.split("/", 1)[0] != exact_model_id.split("/", 1)[0]
            or canonical_slug.split("/", 1)[0] != exact_model_id.split("/", 1)[0]
            or exact_model_id not in {observed_id, canonical_slug}
        ):
            raise OpenRouterModelError(
                "OpenRouter single-model metadata has an invalid canonical identity"
            )
        return response

    async def list_model_endpoints(self, model: str) -> list[dict[str, Any]]:
        """Return endpoint records for one exact author/model slug."""

        response = await self.get_model_endpoint_metadata(model)
        data = response["data"]
        assert isinstance(data, dict)
        endpoints = data["endpoints"]
        assert isinstance(endpoints, list)
        return list(endpoints)

    async def list_zdr_endpoints(self) -> dict[str, Any]:
        response = await self.get_zdr_endpoint_metadata()
        data = response["data"]
        assert isinstance(data, list)
        if not data:
            raise OpenRouterPrivacyError("OpenRouter returned invalid ZDR endpoint metadata")
        return response

    async def get_zdr_endpoint_metadata(self) -> dict[str, Any]:
        """Return the complete ZDR listing, including an authenticated empty result."""

        response = await self._request_metadata(OPENROUTER_ZDR_QUERY)
        data = response.get("data")
        if not isinstance(data, list) or any(not isinstance(endpoint, dict) for endpoint in data):
            raise OpenRouterPrivacyError("OpenRouter returned invalid ZDR endpoint metadata")
        return response

    def seal_real_model_discovery_run(
        self,
        *,
        run_id: str,
        retrieved_at: datetime,
        models_payload: dict[str, Any],
        zdr_payload: dict[str, Any],
        single_model_payloads: Mapping[str, dict[str, Any]],
        endpoint_payloads: Mapping[str, dict[str, Any]],
        candidate_routes: tuple[DiscoveryCandidateRoute, ...],
        payloads: tuple[OpenRouterModelDiscoveryPayload, ...],
    ) -> tuple[
        OpenRouterDiscoveryRunProvenance,
        tuple[OpenRouterModelDiscoveryEvidence, ...],
    ]:
        """Seal metadata only after exact responses crossed this trusted REAL transport."""

        OpenRouterClient._validate_transport_provenance(self)
        if (
            type(self) is not _TRUSTED_OPENROUTER_CLIENT_TYPE
            or trusted_openrouter_execution_evidence(self) is not ExecutionEvidenceKind.REAL
            or not self._owns_client
            or not self._authentication_validated
        ):
            raise OpenRouterPrivacyError(
                "REAL discovery evidence requires an authenticated owned provider client"
            )
        expected_catalog_hash = _canonical_sha256(models_payload)
        expected_zdr_hash = _canonical_sha256(zdr_payload)
        if (
            self._metadata_observations.get(OPENROUTER_CATALOG_QUERY) != expected_catalog_hash
            or self._metadata_observations.get(OPENROUTER_ZDR_QUERY) != expected_zdr_hash
        ):
            raise OpenRouterPrivacyError(
                "discovery payloads do not match trusted transport observations"
            )
        model_bindings: list[DiscoveryModelMetadataBinding] = []
        endpoint_bindings: list[DiscoveryEndpointMetadataBinding] = []
        route_ids = tuple(route.exact_model_id for route in candidate_routes)
        if set(single_model_payloads) != set(route_ids):
            raise OpenRouterPrivacyError(
                "single-model payloads do not exactly cover the discovery candidate set"
            )
        if set(endpoint_payloads) != set(route_ids):
            raise OpenRouterPrivacyError(
                "endpoint payloads do not exactly cover the discovery candidate set"
            )
        supplied_payloads = {payload.exact_model_id: payload for payload in payloads}
        if len(supplied_payloads) != len(payloads) or set(supplied_payloads) != set(route_ids):
            raise OpenRouterPrivacyError(
                "validated payloads do not exactly cover the discovery candidate set"
            )
        for model_id in sorted(route_ids):
            supplied_discovery = supplied_payloads[model_id]
            model_query = openrouter_model_query(model_id)
            single_model_payload = single_model_payloads[model_id]
            single_model_response_hash = _canonical_sha256(single_model_payload)
            if self._metadata_observations.get(model_query) != single_model_response_hash:
                raise OpenRouterPrivacyError(
                    "single-model payload does not match its trusted transport observation"
                )
            model_bindings.append(
                DiscoveryModelMetadataBinding(
                    exact_model_id=model_id,
                    canonical_slug=supplied_discovery.canonical_slug,
                    api_query=model_query,
                    response_snapshot_sha256=single_model_response_hash,
                    model_metadata_snapshot_sha256=(
                        supplied_discovery.model_metadata_snapshot_sha256
                    ),
                )
            )
            endpoint_query = openrouter_endpoint_query(model_id)
            payload = endpoint_payloads[model_id]
            response_hash = _canonical_sha256(payload)
            if self._metadata_observations.get(endpoint_query) != response_hash:
                raise OpenRouterPrivacyError(
                    "endpoint payload does not match its trusted transport observation"
                )
            endpoint_bindings.append(
                DiscoveryEndpointMetadataBinding(
                    exact_model_id=model_id,
                    api_query=endpoint_query,
                    response_snapshot_sha256=response_hash,
                )
            )
            route = next(route for route in candidate_routes if route.exact_model_id == model_id)
            try:
                observed_endpoint_snapshot = validate_openrouter_endpoint_snapshot(
                    exact_model_id=model_id,
                    configured_provider_endpoints=(route.approved_provider_endpoint,),
                    provider_policy_mode="only",
                    endpoint_payload=payload,
                    require_zdr=supplied_discovery.endpoint_snapshot.require_zdr,
                    zdr_payload=zdr_payload,
                    reasoning_requested=False,
                    structured_output_required=(
                        supplied_discovery.endpoint_snapshot.structured_output_mode
                        is not StructuredOutputMode.VALIDATED_TEXT_JSON
                    ),
                )
                observed_payload = validate_openrouter_model_discovery(
                    exact_model_id=model_id,
                    models_payload=models_payload,
                    single_model_payload=single_model_payload,
                    endpoint_snapshot=observed_endpoint_snapshot,
                    effective_privacy_policy=self.effective_privacy_policy,
                )
            except (ValueError, ValidationError):
                raise OpenRouterPrivacyError(
                    "trusted discovery observations failed structural validation"
                ) from None
            if observed_payload != supplied_payloads[model_id]:
                raise OpenRouterPrivacyError(
                    "validated discovery payload does not match trusted observations"
                )
        client_fingerprint = _canonical_sha256(
            {
                "client": "mmaudit.models.openrouter.OpenRouterClient",
                "httpx_version": httpx.__version__,
                "mmaudit_version": VERSION,
            }
        )
        provider_fingerprint = _canonical_sha256(
            {
                "api_identity": OPENROUTER_API_IDENTITY,
                "provider": "OpenRouter",
            }
        )
        return _issue_real_openrouter_discovery_run(
            run_id=run_id,
            retrieved_at=retrieved_at,
            client_fingerprint_sha256=client_fingerprint,
            provider_fingerprint_sha256=provider_fingerprint,
            catalog_snapshot_sha256=expected_catalog_hash,
            zdr_snapshot_sha256=expected_zdr_hash,
            candidate_routes=candidate_routes,
            model_metadata_bindings=tuple(model_bindings),
            endpoint_metadata_bindings=tuple(endpoint_bindings),
            payloads=payloads,
            issuer=_TRUSTED_OPENROUTER_DISCOVERY_ISSUER,
        )

    async def get_generation_evidence(
        self,
        generation_id: str,
        *,
        reconciliation_request: (
            GenerationReconciliationExpectation | GenerationVerificationRequest | None
        ) = None,
        _request_semaphore: asyncio.Semaphore | None = None,
    ) -> OpenRouterGenerationEvidence:
        """Poll boundedly for one eventual, content-free generation attestation."""

        try:
            validated_generation_id = validate_generation_id(generation_id)
        except GenerationEvidenceValidationError as exc:
            raise OpenRouterRequestLimitError(str(exc)) from None
        expectation = (
            reconciliation_request.reconciliation_expectation()
            if isinstance(reconciliation_request, GenerationVerificationRequest)
            else reconciliation_request
        )
        if expectation is not None and (
            not isinstance(expectation, GenerationReconciliationExpectation)
            or expectation.usage_record.openrouter_generation_id != validated_generation_id
        ):
            raise OpenRouterRequestLimitError(
                "generation reconciliation request does not bind the requested generation"
            )
        if _request_semaphore is not None and not isinstance(
            _request_semaphore,
            asyncio.Semaphore,
        ):
            raise OpenRouterRequestLimitError(
                "generation metadata request concurrency control is invalid"
            )
        poll_delays = _generation_metadata_poll_delays(self.execution.request_timeout_seconds)
        operation_timeout = _generation_metadata_operation_timeout(
            self.execution.request_timeout_seconds
        )
        last_pending_error: OpenRouterError | None = None
        last_reconciliation_code: GenerationReconciliationMismatchCode | None = None
        last_reconciliation_evidence: OpenRouterGenerationEvidence | None = None

        async def poll() -> OpenRouterGenerationEvidence:
            nonlocal last_pending_error
            nonlocal last_reconciliation_code
            nonlocal last_reconciliation_evidence
            for attempt, delay_seconds in enumerate(
                poll_delays,
                start=1,
            ):
                if delay_seconds:
                    await self._wait_for_generation_metadata(delay_seconds)
                try:
                    if _request_semaphore is None:
                        payload = await OpenRouterClient._request_metadata(
                            self,
                            f"/generation?id={quote(validated_generation_id, safe='')}",
                            max_bytes=1_000_000,
                            exact_decimal_json=True,
                            maximum_attempts=1,
                            not_found_is_pending=True,
                        )
                    else:
                        async with _request_semaphore:
                            payload = await OpenRouterClient._request_metadata(
                                self,
                                f"/generation?id={quote(validated_generation_id, safe='')}",
                                max_bytes=1_000_000,
                                exact_decimal_json=True,
                                maximum_attempts=1,
                                not_found_is_pending=True,
                            )
                except (
                    OpenRouterGenerationMetadataNotReadyError,
                    OpenRouterProviderUnavailableError,
                    OpenRouterRateLimitError,
                    OpenRouterTimeoutError,
                ) as exc:
                    last_pending_error = exc
                    last_reconciliation_code = None
                    last_reconciliation_evidence = None
                    continue
                try:
                    evidence = validate_openrouter_generation_payload(
                        payload,
                        requested_generation_id=validated_generation_id,
                        retrieved_at=datetime.now(UTC),
                        retrieval_attempts=attempt,
                        execution_evidence=trusted_openrouter_execution_evidence(self),
                    )
                except (GenerationEvidenceValidationError, ValidationError):
                    try:
                        may_be_pending = _generation_metadata_payload_may_be_pending(
                            payload,
                            requested_generation_id=validated_generation_id,
                            reconciliation_expectation=expectation,
                            retrieval_attempts=attempt,
                            execution_evidence=trusted_openrouter_execution_evidence(self),
                        )
                    except GenerationReconciliationMismatchError as exc:
                        raise OpenRouterGenerationReconciliationError(
                            exc.code,
                            attempts=attempt,
                            exhausted=False,
                            last_evidence=None,
                        ) from None
                    except (GenerationEvidenceValidationError, ValidationError):
                        raise OpenRouterSchemaError(
                            "OpenRouter returned invalid generation metadata"
                        ) from None
                    if may_be_pending:
                        last_pending_error = OpenRouterSchemaError(
                            "OpenRouter generation metadata remained incomplete"
                        )
                        last_reconciliation_code = None
                        last_reconciliation_evidence = None
                        continue
                    raise OpenRouterSchemaError(
                        "OpenRouter returned invalid generation metadata"
                    ) from None
                if expectation is not None:
                    try:
                        _reconcile_generation_evidence_structural(
                            evidence,
                            usage_record=expectation.usage_record,
                            expected_exact_model=expectation.exact_model_id,
                            expected_canonical_model=expectation.canonical_model_id,
                            expected_catalog_identity_binding_sha256=(
                                expectation.catalog_identity_binding_sha256
                            ),
                            expected_discovery_evidence_sha256=(
                                expectation.discovery_evidence_sha256
                            ),
                            expected_provider_name=expectation.expected_provider_name,
                            require_certification=expectation.require_certification,
                        )
                    except GenerationReconciliationMismatchError as exc:
                        if not exc.is_eventual_usage_field:
                            raise OpenRouterGenerationReconciliationError(
                                exc.code,
                                attempts=attempt,
                                exhausted=False,
                                last_evidence=evidence,
                            ) from None
                        last_pending_error = None
                        last_reconciliation_code = exc.code
                        last_reconciliation_evidence = evidence
                        continue
                    except GenerationEvidenceValidationError:
                        raise OpenRouterSchemaError(
                            "OpenRouter generation metadata failed structural reconciliation"
                        ) from None
                return evidence
            if last_reconciliation_code is not None:
                assert last_reconciliation_evidence is not None
                raise OpenRouterGenerationReconciliationError(
                    last_reconciliation_code,
                    attempts=len(poll_delays),
                    exhausted=True,
                    last_evidence=last_reconciliation_evidence,
                )
            if isinstance(last_pending_error, OpenRouterGenerationMetadataNotReadyError):
                raise last_pending_error
            if last_pending_error is not None:
                raise last_pending_error
            raise OpenRouterGenerationMetadataNotReadyError(
                "OpenRouter generation metadata was unavailable after bounded polling"
            )

        try:
            async with asyncio.timeout(operation_timeout):
                return await poll()
        except TimeoutError:
            if last_reconciliation_code is not None and last_reconciliation_evidence is not None:
                raise OpenRouterGenerationReconciliationError(
                    last_reconciliation_code,
                    attempts=last_reconciliation_evidence.retrieval_attempts,
                    exhausted=True,
                    last_evidence=last_reconciliation_evidence,
                ) from None
            raise OpenRouterGenerationMetadataNotReadyError(
                "OpenRouter generation metadata exceeded the total readiness deadline"
            ) from None

    async def _wait_for_generation_metadata(self, delay_seconds: float) -> None:
        """Wait only one fixed bounded delay between metadata observations."""

        await asyncio.sleep(delay_seconds)

    async def _fetch_generation_attestations_with_deadline(
        self,
        requests: tuple[GenerationVerificationRequest, ...],
        generation_ids: tuple[str, ...],
    ) -> tuple[OpenRouterGenerationEvidence, ...]:
        """Fetch an ordered generation set under one shared wall-clock deadline."""

        operation_timeout = _generation_metadata_operation_timeout(
            self.execution.request_timeout_seconds
        )
        tasks: list[asyncio.Task[OpenRouterGenerationEvidence]] = []

        async def cancel_and_wait_for_tasks() -> None:
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        async def fetch_attestations() -> tuple[OpenRouterGenerationEvidence, ...]:
            await OpenRouterClient.validate_authentication(self)
            OpenRouterClient._validate_transport_provenance(self)
            if not self._authentication_validated:
                raise OpenRouterAuthenticationError("OpenRouter authentication was not validated")
            semaphore = asyncio.Semaphore(self.execution.concurrency)

            async def fetch_one(
                request: GenerationVerificationRequest,
                generation_id: str,
            ) -> OpenRouterGenerationEvidence:
                return await OpenRouterClient.get_generation_evidence(
                    self,
                    generation_id,
                    reconciliation_request=request.reconciliation_expectation(),
                    _request_semaphore=semaphore,
                )

            tasks.extend(
                asyncio.create_task(fetch_one(request, generation_id))
                for request, generation_id in zip(
                    requests,
                    generation_ids,
                    strict=True,
                )
            )
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, BaseException):
                    raise result
            return tuple(cast(OpenRouterGenerationEvidence, result) for result in results)

        try:
            async with asyncio.timeout(operation_timeout):
                return await fetch_attestations()
        except asyncio.CancelledError:
            await cancel_and_wait_for_tasks()
            raise
        except TimeoutError:
            await cancel_and_wait_for_tasks()
            for task in tasks:
                if task.cancelled():
                    continue
                failure = task.exception()
                if failure is not None:
                    raise failure from None
            raise OpenRouterGenerationMetadataNotReadyError(
                "OpenRouter generation verification exceeded the total readiness deadline"
            ) from None

    async def create_trusted_generation_verification(
        self,
        requests: tuple[GenerationVerificationRequest, ...],
    ) -> TrustedGenerationVerification:
        """Authenticate and freshly re-fetch an exact generation set without completions."""

        if not _openrouter_client_callables_are_pristine():
            raise OpenRouterPrivacyError(
                "trusted generation verification client callables are not pristine"
            )
        OpenRouterClient._validate_transport_provenance(self)
        if not requests:
            raise OpenRouterRequestLimitError(
                "trusted generation verification requires at least one request"
            )
        if len(requests) > _MAX_TRUSTED_GENERATION_VERIFICATION_REQUESTS:
            raise OpenRouterRequestLimitError(
                "trusted generation verification exceeds the fixed request-set limit"
            )
        normalized = tuple(
            GenerationVerificationRequest(
                benchmark_report_sha256=request.benchmark_report_sha256,
                case_id=request.case_id,
                exact_model_id=request.exact_model_id,
                canonical_model_id=request.canonical_model_id,
                catalog_identity_binding_sha256=request.catalog_identity_binding_sha256,
                discovery_evidence_sha256=request.discovery_evidence_sha256,
                expected_provider_name=request.expected_provider_name,
                usage_record=request.usage_record,
            )
            for request in requests
        )
        generation_ids = tuple(
            request.usage_record.openrouter_generation_id for request in normalized
        )
        if None in generation_ids or len(set(generation_ids)) != len(generation_ids):
            raise OpenRouterRequestLimitError(
                "trusted generation verification rejects replayed generation IDs"
            )
        if (
            type(self) is not _TRUSTED_OPENROUTER_CLIENT_TYPE
            or trusted_openrouter_execution_evidence(self) is not ExecutionEvidenceKind.REAL
            or not self._owns_client
        ):
            raise OpenRouterPrivacyError(
                "trusted generation verification requires an owned REAL provider client"
            )
        verification_started_at = datetime.now(UTC)
        attestations = await OpenRouterClient._fetch_generation_attestations_with_deadline(
            self,
            normalized,
            cast(tuple[str, ...], generation_ids),
        )
        OpenRouterClient._validate_transport_provenance(self)
        try:
            capability = _issue_trusted_generation_verification(
                requests=normalized,
                attestations=attestations,
                verification_started_at=verification_started_at,
            )
            return _attest_authrunner_generation_origin(capability, normalized)
        except GenerationReconciliationMismatchError as exc:
            raise OpenRouterGenerationReconciliationError(
                exc.code,
                attempts=1,
                exhausted=False,
            ) from None
        except GenerationEvidenceValidationError:
            raise OpenRouterSchemaError(
                "OpenRouter generation metadata did not reconcile benchmark usage"
            ) from None

    def register_certification_endpoint_snapshot(
        self,
        *,
        evidence: OpenRouterEndpointSnapshotEvidence,
    ) -> None:
        """Bind one exact validated endpoint/pricing snapshot before a paid request."""

        if not self.provider_policy.certification:
            raise OpenRouterCostControlError(
                "endpoint pricing may only be registered for one certification endpoint"
            )
        self.register_endpoint_snapshot(evidence=evidence)

    def register_certification_model_discovery(
        self,
        *,
        evidence: OpenRouterModelDiscoveryEvidence,
        manifest: OpenRouterModelDiscoveryRunManifest | None = None,
    ) -> None:
        """Bind one exact requested/canonical identity from frozen REAL discovery."""

        if not self.provider_policy.certification:
            raise OpenRouterCostControlError(
                "model discovery may only be registered for certification"
            )
        self.register_model_discovery(evidence=evidence, manifest=manifest)

    def register_model_discovery(
        self,
        *,
        evidence: OpenRouterModelDiscoveryEvidence,
        manifest: OpenRouterModelDiscoveryRunManifest | None = None,
    ) -> None:
        """Bind one exact requested/canonical identity from frozen REAL discovery."""

        if not isinstance(evidence, OpenRouterModelDiscoveryEvidence):
            raise OpenRouterModelError("model discovery evidence has an invalid type")
        if evidence.provenance.execution_evidence is not ExecutionEvidenceKind.REAL:
            raise OpenRouterModelError("model discovery evidence is not REAL")
        if manifest is None:
            OpenRouterClient._validate_transport_provenance(self)
            model_binding = next(
                (
                    item
                    for item in evidence.provenance.model_metadata_bindings
                    if item.exact_model_id == evidence.exact_model_id
                ),
                None,
            )
            endpoint_binding = next(
                (
                    item
                    for item in evidence.provenance.endpoint_metadata_bindings
                    if item.exact_model_id == evidence.exact_model_id
                ),
                None,
            )
            if (
                type(self) is not _TRUSTED_OPENROUTER_CLIENT_TYPE
                or trusted_openrouter_execution_evidence(self) is not ExecutionEvidenceKind.REAL
                or not self._owns_client
                or not self._authentication_validated
                or model_binding is None
                or endpoint_binding is None
                or self._metadata_observations.get(OPENROUTER_CATALOG_QUERY)
                != evidence.provenance.catalog_snapshot_sha256
                or self._metadata_observations.get(OPENROUTER_ZDR_QUERY)
                != evidence.provenance.zdr_snapshot_sha256
                or self._metadata_observations.get(model_binding.api_query)
                != model_binding.response_snapshot_sha256
                or self._metadata_observations.get(endpoint_binding.api_query)
                != endpoint_binding.response_snapshot_sha256
            ):
                raise OpenRouterPrivacyError(
                    "unmanifested model discovery must match this authenticated REAL session"
                )
        else:
            if not isinstance(manifest, OpenRouterModelDiscoveryRunManifest):
                raise OpenRouterModelError("model discovery manifest has an invalid type")
            if manifest.run_provenance != evidence.provenance:
                raise OpenRouterModelError("model discovery manifest has different run provenance")
            matching_artifacts = tuple(
                item
                for item in manifest.artifacts
                if item.exact_model_id == evidence.exact_model_id
            )
            expected_artifact_sha256 = hashlib.sha256(
                stable_json(evidence).encode("utf-8")
            ).hexdigest()
            if (
                len(matching_artifacts) != 1
                or matching_artifacts[0].approved_provider_endpoint
                != evidence.approved_provider_endpoint
                or matching_artifacts[0].discovery_evidence_sha256
                != evidence.discovery_evidence_sha256
                or matching_artifacts[0].artifact_sha256 != expected_artifact_sha256
            ):
                raise OpenRouterModelError(
                    "model discovery manifest does not bind the exact evidence artifact"
                )
        reasoning_capability = OpenRouterReasoningCapabilityEvidence.model_validate(
            evidence.reasoning_capability.model_dump(mode="python")
        )
        reasoning_discovery = OpenRouterModelDiscoveryPayload.model_validate(
            evidence.model_dump(
                mode="python",
                exclude={"provenance", "discovery_evidence_sha256"},
            )
        )
        existing_reasoning_capability = self._reasoning_capabilities.get(evidence.exact_model_id)
        existing_reasoning_discovery = self._reasoning_discoveries.get(evidence.exact_model_id)
        if (
            existing_reasoning_discovery is not None
            and existing_reasoning_discovery != reasoning_discovery
        ):
            raise OpenRouterProviderPolicyError(
                "conflicting reasoning discovery evidence cannot replace a binding"
            )
        if (
            existing_reasoning_capability is not None
            and existing_reasoning_capability != reasoning_capability
        ):
            raise OpenRouterProviderPolicyError(
                "conflicting reasoning capability evidence cannot replace a binding"
            )
        identity = _RegisteredModelIdentity(
            exact_model_id=evidence.exact_model_id,
            canonical_slug=evidence.canonical_slug,
            model_metadata_snapshot_sha256=evidence.model_metadata_snapshot_sha256,
            catalog_identity_binding_sha256=evidence.catalog_identity_binding_sha256,
            catalog_snapshot_sha256=evidence.provenance.catalog_snapshot_sha256,
            discovery_provenance_sha256=evidence.provenance.provenance_sha256,
            discovery_evidence_sha256=evidence.discovery_evidence_sha256,
            discovery_manifest_sha256=(manifest.manifest_sha256 if manifest is not None else None),
            snapshot=_identity_snapshot_from_discovery(
                evidence,
                allow_fallbacks=self.provider_policy.allow_fallbacks,
                reasoning_requested=self.reasoning is not None,
            ),
        )
        existing = self._model_identities.get(evidence.exact_model_id)
        if existing is not None and existing != identity:
            raise OpenRouterModelError(
                "conflicting frozen model identity evidence cannot replace a binding"
            )
        self.register_endpoint_snapshot(evidence=evidence.endpoint_snapshot)
        registered_endpoint_policy = self._endpoint_pricing[evidence.exact_model_id]
        if evidence.structured_output_mode not in registered_endpoint_policy.supported_output_modes:
            raise OpenRouterProviderPolicyError(
                "model discovery selected an endpoint-unsupported structured-output mode"
            )
        self._endpoint_pricing[evidence.exact_model_id] = _RegisteredEndpointPolicy(
            snapshot_sha256=registered_endpoint_policy.snapshot_sha256,
            policy_pricing_sha256=registered_endpoint_policy.policy_pricing_sha256,
            routing_max_price=registered_endpoint_policy.routing_max_price,
            endpoints=_registered_endpoints_for_output_mode(
                registered_endpoint_policy.endpoints,
                evidence.structured_output_mode,
                reasoning_requested=self.reasoning is not None,
            ),
            structured_output_parameters=output_mode_capability_parameters(
                evidence.structured_output_mode,
                registered_endpoint_policy.endpoints[0].structured_output_parameters,
            ),
            supported_output_modes=evidence.supported_output_modes,
            structured_output_mode=evidence.structured_output_mode,
            output_capability_sha256=evidence.output_capability_sha256,
        )
        self._reasoning_capabilities[evidence.exact_model_id] = reasoning_capability
        self._reasoning_discoveries[evidence.exact_model_id] = reasoning_discovery
        self._model_identities[evidence.exact_model_id] = identity

    def registered_model_identity_snapshot(
        self,
        exact_model_id: str,
    ) -> OpenRouterModelEndpointIdentitySnapshot:
        """Return the frozen non-secret identity snapshot for one registered model."""

        _require_exact_model_id(exact_model_id)
        identity = self._model_identities.get(exact_model_id)
        if identity is None:
            raise OpenRouterModelError("model identity metadata is not registered")
        return identity.snapshot

    def bind_generation_identity(
        self,
        *,
        usage_record: UsageRecord,
        generation_evidence: OpenRouterGenerationEvidence | None,
        evaluated_at: datetime | None = None,
    ) -> OpenRouterIdentityBindingResult:
        """Classify one valid response using freshly retrieved generation metadata."""

        return self._bind_generation_identity(
            usage_record=usage_record,
            generation_evidence=generation_evidence,
            evaluated_at=evaluated_at,
            trusted_issuer=None,
        )

    def _bind_generation_identity(
        self,
        *,
        usage_record: UsageRecord,
        generation_evidence: OpenRouterGenerationEvidence | None,
        evaluated_at: datetime | None,
        trusted_issuer: object | None,
        missing_diagnostic_codes: tuple[OpenRouterIdentityDiagnosticCode, ...] | None = None,
    ) -> OpenRouterIdentityBindingResult:
        try:
            usage = _validated_usage_copy_preserving_owned_attestation(usage_record)
        except (AttributeError, ValidationError):
            raise OpenRouterModelError("model identity usage evidence is invalid") from None
        identity = self._model_identities.get(usage.requested_model)
        if identity is None:
            raise OpenRouterModelError("model identity metadata is not registered")
        request = _request_identity_evidence(usage)
        evaluation_time = _whole_second_utc(evaluated_at or datetime.now(UTC))
        if (
            usage.execution_evidence is ExecutionEvidenceKind.REAL
            and trusted_issuer is not _TRUSTED_OPENROUTER_IDENTITY_BINDING_ISSUER
        ):
            return seal_unbound_openrouter_identity(
                snapshot=identity.snapshot,
                request=request,
                diagnostic_codes=(OpenRouterIdentityDiagnosticCode.GENERATION_EVIDENCE_UNTRUSTED,),
                evaluated_at=max(evaluation_time, request.completed_at),
            )
        if generation_evidence is None:
            return seal_unbound_openrouter_identity(
                snapshot=identity.snapshot,
                request=request,
                diagnostic_codes=missing_diagnostic_codes
                or (OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_MISSING,),
                evaluated_at=max(evaluation_time, request.completed_at),
            )
        try:
            generation = OpenRouterGenerationEvidence.model_validate(
                generation_evidence.model_dump(mode="json")
            )
        except (AttributeError, ValidationError):
            raise OpenRouterModelError("generation identity evidence is invalid") from None
        generation_identity = OpenRouterGenerationIdentityEvidence(
            generation_id=generation.generation_id,
            execution_evidence=generation.execution_evidence.value,
            generation_model_slug=generation.exact_model_id,
            provider_name=generation.provider_name,
            provider_version_id=None,
            provider_request_id=generation.request_id,
            retrieved_at=_whole_second_utc(generation.retrieved_at),
            generation_evidence_sha256=generation.evidence_sha256,
        )
        try:
            return seal_bound_openrouter_identity(
                snapshot=identity.snapshot,
                request=request,
                generation=generation_identity,
                evaluated_at=max(
                    evaluation_time,
                    generation_identity.retrieved_at,
                    request.completed_at,
                ),
            )
        except ValidationError:
            diagnostics = _identity_binding_diagnostics(
                snapshot=identity.snapshot,
                request=request,
                generation=generation_identity,
                evaluated_at=evaluation_time,
            )
            return seal_unbound_openrouter_identity(
                snapshot=identity.snapshot,
                request=request,
                diagnostic_codes=diagnostics,
                evaluated_at=max(
                    evaluation_time,
                    generation_identity.retrieved_at,
                    request.completed_at,
                ),
            )

    def usage_with_bound_identity(
        self,
        *,
        usage_record: UsageRecord,
        identity_binding: OpenRouterIdentityBindingResult,
    ) -> UsageRecord:
        """Return an immutable validated usage copy carrying its full identity proof."""

        return self._usage_with_bound_identity(
            usage_record=usage_record,
            identity_binding=identity_binding,
            trusted_issuer=None,
        )

    def _usage_with_bound_identity(
        self,
        *,
        usage_record: UsageRecord,
        identity_binding: OpenRouterIdentityBindingResult,
        trusted_issuer: object | None,
    ) -> UsageRecord:
        return self._usage_with_identity_result(
            usage_record=usage_record,
            identity_binding=identity_binding,
            trusted_issuer=trusted_issuer,
            require_bound=True,
        )

    def _usage_with_unbound_identity(
        self,
        *,
        usage_record: UsageRecord,
        identity_binding: OpenRouterIdentityBindingResult,
        trusted_issuer: object | None,
        generation_observation: OpenRouterGenerationEvidence | None = None,
    ) -> UsageRecord:
        return self._usage_with_identity_result(
            usage_record=usage_record,
            identity_binding=identity_binding,
            trusted_issuer=trusted_issuer,
            require_bound=False,
            generation_observation=generation_observation,
        )

    def _usage_with_identity_result(
        self,
        *,
        usage_record: UsageRecord,
        identity_binding: OpenRouterIdentityBindingResult,
        trusted_issuer: object | None,
        require_bound: bool,
        generation_observation: OpenRouterGenerationEvidence | None = None,
    ) -> UsageRecord:
        if (
            usage_record.execution_evidence is ExecutionEvidenceKind.REAL
            and not _has_owned_real_usage_attestation(usage_record)
        ):
            raise OpenRouterModelError(
                "REAL model identity binding requires owned runtime provenance"
            )
        try:
            usage = _validated_usage_copy_preserving_owned_attestation(usage_record)
            binding = OpenRouterIdentityBindingResult.model_validate(
                identity_binding.model_dump(mode="json")
            )
        except (AttributeError, ValidationError):
            raise OpenRouterModelError("model identity binding evidence is invalid") from None
        identity = self._model_identities.get(usage.requested_model)
        if (
            identity is None
            or (
                usage.execution_evidence is ExecutionEvidenceKind.REAL
                and trusted_issuer is not _TRUSTED_OPENROUTER_IDENTITY_BINDING_ISSUER
            )
            or binding.snapshot != identity.snapshot
            or binding.request != _request_identity_evidence(usage)
            or (
                require_bound
                and (
                    binding.strength is ModelIdentityStrength.UNBOUND or binding.generation is None
                )
            )
            or (
                not require_bound
                and (
                    binding.strength is not ModelIdentityStrength.UNBOUND
                    or binding.generation is not None
                )
            )
        ):
            raise OpenRouterModelError(
                "model identity binding does not match the completed request"
            )
        if require_bound and generation_observation is not None:
            raise OpenRouterModelError(
                "bound model identity cannot carry an unbound generation observation"
            )
        observed_generation: dict[str, Any] | None = None
        if generation_observation is not None:
            try:
                observed_generation = OpenRouterGenerationEvidence.model_validate(
                    generation_observation.model_dump(mode="json")
                ).model_dump(mode="json")
            except (AttributeError, ValidationError):
                raise OpenRouterModelError("unbound generation observation is invalid") from None
        binding_status = (
            "generation_metadata_bound" if require_bound else "generation_metadata_unbound"
        )
        routing = {
            **usage.routing,
            "identity_binding": binding.model_dump(mode="json"),
            "identity_binding_sha256": binding.binding_sha256,
            "identity_binding_status": binding_status,
        }
        if observed_generation is not None:
            routing["unbound_generation_observation"] = observed_generation
        concluded_usage = UsageRecord.model_validate(
            {
                **usage.model_dump(mode="json"),
                "routing": routing,
                "identity_strength": binding.strength,
            }
        )
        try:
            _TRUSTED_AUTHRUNNER_USAGE_ORIGIN_SCOPE(concluded_usage)
        except ValueError:
            raise OpenRouterPrivacyError(
                "AUTHRUNNER privacy proof kind does not match its request namespace"
            ) from None
        if concluded_usage.execution_evidence is ExecutionEvidenceKind.REAL:
            concluded_usage = _attest_owned_real_usage_record(concluded_usage)
        try:
            if require_bound:
                self.usage.replace_with_bound_identity(concluded_usage)
            else:
                self.usage.replace_with_unbound_identity(concluded_usage)
        except ValueError:
            raise OpenRouterModelError(
                "model identity binding cannot replace its owned usage evidence"
            ) from None
        if require_bound and concluded_usage.execution_evidence is ExecutionEvidenceKind.REAL:
            try:
                concluded_usage = _attest_authrunner_owned_real_usage_origin(concluded_usage)
            except ValueError:
                raise OpenRouterPrivacyError(
                    "REAL bound usage lacks AUTHRUNNER transport-origin custody"
                ) from None
        return concluded_usage

    def register_endpoint_snapshot(
        self,
        *,
        evidence: OpenRouterEndpointSnapshotEvidence,
    ) -> None:
        """Bind all validated exact endpoints needed to prove a paid request ceiling."""

        if not isinstance(evidence, OpenRouterEndpointSnapshotEvidence):
            raise OpenRouterCostControlError("endpoint pricing evidence has an invalid type")
        _require_exact_model_id(evidence.exact_model_id)
        qualification_binding = self._qualification_routing.get(evidence.exact_model_id)
        configured = (
            (qualification_binding.approved_provider_endpoint,)
            if self.provider_policy.certification and qualification_binding is not None
            else self.provider_policy.configured_endpoints
        )
        if not configured:
            raise OpenRouterCostControlError(
                "endpoint pricing requires an explicit provider endpoint policy"
            )
        if (
            evidence.configured_provider_endpoints != configured
            or evidence.provider_policy_mode
            != (
                "only"
                if qualification_binding is not None or self.provider_policy.only
                else "order"
            )
        ):
            raise OpenRouterProviderPolicyError(
                "endpoint pricing does not match the exact configured provider policy"
            )
        if evidence.require_zdr is not self.privacy.require_zdr:
            raise OpenRouterPrivacyError(
                "paid endpoint pricing privacy mode differs from the configured route"
            )
        if self.privacy.require_zdr:
            if any(endpoint.zdr_eligible is not True for endpoint in evidence.endpoints):
                raise OpenRouterPrivacyError(
                    "paid endpoint pricing requires current ZDR eligibility evidence"
                )
        else:
            self._validate_non_zdr_privacy_authorization((evidence.exact_model_id,))
        registered: list[_RegisteredEndpointPricing] = []
        pricing_hashes: dict[str, str] = {}
        identity_owners: dict[str, str] = {}
        for configured_endpoint in configured:
            endpoint = evidence.endpoint(configured_endpoint)
            pricing = endpoint.pricing
            if (
                not pricing
                or not {"prompt", "completion"}.issubset(pricing)
                or not set(pricing).issubset(_SUPPORTED_TEXT_PRICING_FIELDS)
            ):
                raise OpenRouterCostControlError(
                    "endpoint pricing is incomplete or unsupported for bounded text requests"
                )
            provider_identities = tuple(
                sorted(
                    {
                        identity
                        for identity in (
                            endpoint.provider_endpoint,
                            endpoint.endpoint_tag,
                            endpoint.endpoint_slug,
                            endpoint.provider_name,
                        )
                        if identity is not None
                    },
                    key=str.casefold,
                )
            )
            for identity in provider_identities:
                normalized_identity = identity.casefold()
                existing_owner = identity_owners.get(normalized_identity)
                if existing_owner is not None and existing_owner != endpoint.provider_endpoint:
                    raise OpenRouterProviderPolicyError(
                        "configured endpoints have ambiguous provider response identities"
                    )
                identity_owners[normalized_identity] = endpoint.provider_endpoint
            registered.append(
                _RegisteredEndpointPricing(
                    provider_endpoint=endpoint.provider_endpoint,
                    provider_name=endpoint.provider_name,
                    provider_identities=provider_identities,
                    endpoint_tag=endpoint.endpoint_tag,
                    endpoint_slug=endpoint.endpoint_slug,
                    operational_status=endpoint.operational_status,
                    zdr_eligible=endpoint.zdr_eligible,
                    pricing=tuple(pricing.items()),
                    pricing_sha256=endpoint.pricing_sha256,
                    snapshot_sha256=endpoint.endpoint_snapshot_sha256,
                    context_length=endpoint.context_length,
                    max_prompt_tokens=endpoint.max_prompt_tokens,
                    max_prompt_tokens_source=endpoint.max_prompt_tokens_source,
                    max_completion_tokens=endpoint.max_completion_tokens,
                    max_completion_tokens_source=endpoint.max_completion_tokens_source,
                    supported_parameters=endpoint.supported_parameters,
                    required_request_parameters=endpoint.required_request_parameters,
                    structured_output_parameters=endpoint.structured_output_parameters,
                    supported_output_modes=endpoint.supported_output_modes,
                    structured_output_mode=endpoint.structured_output_mode,
                )
            )
            pricing_hashes[endpoint.provider_endpoint] = endpoint.pricing_sha256
        routing_max_price = _routing_max_price(tuple(registered))
        trusted_existing_snapshot = _lookup_trusted_endpoint_snapshot(
            self,
            evidence.exact_model_id,
        )
        if (
            trusted_existing_snapshot is not None
            and trusted_existing_snapshot != evidence.snapshot_sha256
        ):
            raise OpenRouterCostControlError(
                "endpoint snapshot binding cannot be replaced on an existing provider client"
            )
        self._endpoint_pricing[evidence.exact_model_id] = _RegisteredEndpointPolicy(
            snapshot_sha256=evidence.snapshot_sha256,
            policy_pricing_sha256=_canonical_sha256(pricing_hashes),
            routing_max_price=tuple(routing_max_price.items()),
            endpoints=tuple(registered),
            structured_output_parameters=output_mode_capability_parameters(
                evidence.structured_output_mode,
                evidence.endpoints[0].structured_output_parameters,
            ),
            supported_output_modes=evidence.supported_output_modes,
            structured_output_mode=evidence.structured_output_mode,
            output_capability_sha256=evidence.output_capability_sha256,
        )
        _register_trusted_endpoint_snapshot(
            self,
            evidence.exact_model_id,
            evidence.snapshot_sha256,
        )

    def _required_output_tokens(self) -> int:
        configured = (
            self.token_budgets.reserved_output_tokens if self.token_budgets is not None else None
        )
        return (
            configured if configured is not None else self.execution.max_output_tokens_per_request
        )

    def _reasoning_profile_for_role(
        self,
        role: str | None,
    ) -> ReasoningControlProfile | None:
        if self.reasoning_policy is None:
            return None
        if role is None:
            raise OpenRouterRequestLimitError(
                "per-role reasoning policy requires an exact provider request role"
            )
        return self.reasoning_policy.control_for_request(role)

    def _reasoning_for_role(
        self,
        role: str | None,
    ) -> OpenRouterReasoning | None:
        profile = self._reasoning_profile_for_role(role)
        if profile is None:
            return self.reasoning
        return _reasoning_from_control_profile(profile)

    def _reserved_reasoning_tokens(
        self,
        required_output_tokens: int,
        *,
        role: str | None = None,
    ) -> int:
        profile = self._reasoning_profile_for_role(role)
        if profile is not None:
            return profile.reserved_reasoning_tokens
        if self.reasoning is None or self.reasoning.effort == "none":
            return 0
        if self.reasoning.max_tokens is not None:
            return self.reasoning.max_tokens
        return required_output_tokens

    def _reasoning_request_plan(
        self,
        *,
        role: str,
        model: str,
        qualification_binding: OpenRouterQualificationRoutingEvidence | None,
    ) -> ReasoningRequestPlanEvidence | None:
        if self.reasoning_policy is None:
            return None
        control = self.reasoning_policy.control_for_request(role)
        capability = self._reasoning_capabilities.get(model)
        if capability is None:
            if self._requires_paid_controls:
                raise OpenRouterProviderPolicyError(
                    "paid per-role reasoning requires frozen endpoint capability evidence"
                )
        else:
            if capability.exact_model_id != model:
                raise OpenRouterProviderPolicyError(
                    "reasoning capability differs from the exact requested model"
                )
            discovery = self._reasoning_discoveries.get(model)
            if discovery is None:
                capability.require_compatible_profile(control)
            else:
                if discovery.reasoning_capability != capability:
                    raise OpenRouterProviderPolicyError(
                        "reasoning discovery differs from the registered capability"
                    )
                discovery.require_compatible_reasoning_profile(control)
        return ReasoningRequestPlanEvidence.build(
            request_role=role,
            policy=self.reasoning_policy,
            endpoint_capability_sha256=(
                capability.capability_sha256 if capability is not None else None
            ),
            qualification_binding_sha256=(
                qualification_binding.reasoning_binding_sha256_for(
                    role=role,
                    control_profile=control,
                    reasoning_policy=self.reasoning_policy,
                    endpoint_capability_sha256=capability.capability_sha256,
                )
                if qualification_binding is not None and capability is not None
                else None
            ),
        )

    def _selected_structured_output_mode(self, model: str) -> StructuredOutputMode:
        endpoint_policy = self._endpoint_pricing.get(model)
        return (
            endpoint_policy.structured_output_mode
            if endpoint_policy is not None
            else StructuredOutputMode.NATIVE_JSON_SCHEMA
        )

    def _requires_real_audit_policy_selection(
        self,
        role: str,
        *,
        system_prompt: str | None = None,
        user_prompt: str | None = None,
        response_model: type[BaseModel] | None = None,
        schema_name: str | None = None,
        structured_output_mode: StructuredOutputMode | None = None,
        context_package: ContextPackage | None = None,
    ) -> bool:
        """Require audit policy for every REAL request lacking proven prequalification scope."""

        return (
            trusted_openrouter_execution_evidence(self) is ExecutionEvidenceKind.REAL
            and not OpenRouterClient._is_trusted_prequalification_request(
                self,
                role,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                structured_output_mode=structured_output_mode,
                context_package=context_package,
            )
        )

    def _requires_real_audit_model_refresh(
        self,
        role: str,
        *,
        system_prompt: str | None = None,
        user_prompt: str | None = None,
        response_model: type[BaseModel] | None = None,
        schema_name: str | None = None,
        structured_output_mode: StructuredOutputMode | None = None,
        context_package: ContextPackage | None = None,
    ) -> bool:
        """Apply refresh vetoes only to owned REAL requests outside prequalification."""

        return (
            trusted_openrouter_execution_evidence(self) is ExecutionEvidenceKind.REAL
            and not OpenRouterClient._is_trusted_prequalification_request(
                self,
                role,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                structured_output_mode=structured_output_mode,
                context_package=context_package,
            )
        )

    def _requires_real_audit_model_refresh_pricing(
        self,
        role: str,
        *,
        system_prompt: str | None = None,
        user_prompt: str | None = None,
        response_model: type[BaseModel] | None = None,
        schema_name: str | None = None,
        structured_output_mode: StructuredOutputMode | None = None,
        context_package: ContextPackage | None = None,
    ) -> bool:
        """Require live pricing authority on every owned REAL postqualification call."""

        return _TRUSTED_REQUIRES_REAL_AUDIT_MODEL_REFRESH(
            self,
            role,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            schema_name=schema_name,
            structured_output_mode=structured_output_mode,
            context_package=context_package,
        )

    def _is_trusted_prequalification_request(
        self,
        role: str,
        *,
        system_prompt: str | None = None,
        user_prompt: str | None = None,
        response_model: type[BaseModel] | None = None,
        schema_name: str | None = None,
        structured_output_mode: StructuredOutputMode | None = None,
        context_package: ContextPackage | None = None,
    ) -> bool:
        """Limit policy exemption to a closed role on a non-private benchmark source."""

        policy = self.effective_privacy_policy
        if policy is None:
            return False
        canonical_policy = _canonical_effective_privacy_policy(policy)
        if canonical_policy != policy:
            raise OpenRouterPrivacyError(
                "prequalification privacy evidence changed after canonicalization"
            )
        observation = self._privacy_source_provenance_observation
        if (
            observation is None
            or system_prompt is None
            or user_prompt is None
            or response_model is None
            or schema_name is None
            or structured_output_mode is None
        ):
            return False
        _validate_live_privacy_source_provenance(
            observation,
            policy=canonical_policy,
        )
        from mmaudit.repository.privacy_provenance import (
            validate_provider_visible_source_request,
        )

        try:
            validate_provider_visible_source_request(
                observation,
                request_role=role,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                structured_output_mode=structured_output_mode,
                context_package=context_package,
            )
        except ValueError:
            return False
        trusted_prequalification_source = (
            canonical_policy.source_classification
            is PrivacySourceClassification.SYNTHETIC_COMMITTED
        )
        return _is_prequalification_provider_role(role) and trusted_prequalification_source

    def _require_real_postqualification_routing(
        self,
        *,
        role: str,
        model: str,
        system_prompt: str,
        user_prompt: str,
        response_model: type[BaseModel],
        schema_name: str,
        structured_output_mode: StructuredOutputMode,
        context_package: ContextPackage | None,
        checked_at: datetime,
        require_runtime_snapshots: bool,
        allow_refreshed_pricing: bool = False,
    ) -> OpenRouterQualificationRoutingEvidence:
        """Revalidate opaque production authority and its exact request projection."""

        if not _TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION(
            self,
            role,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            schema_name=schema_name,
            structured_output_mode=structured_output_mode,
            context_package=context_package,
        ):
            raise OpenRouterQualificationError(
                "post-qualification routing authority was requested outside its real "
                "certification boundary"
            )
        if self._production_qualification is None:
            raise OpenRouterQualificationError(
                "real post-qualification certification requires opaque qualification authority"
            )
        _require_exact_qualification_routing_authority(
            routing=tuple(self._qualification_routing.values()),
            qualification=self._production_qualification,
            now=checked_at.replace(microsecond=0),
        )
        binding = self._qualification_routing.get(model)
        if binding is None:
            raise OpenRouterQualificationError(
                "real post-qualification certification requires current qualification "
                "routing evidence"
            )
        binding.require_current(
            role=role,
            model=model,
            provider_endpoints=self.provider_policy.configured_endpoints,
            now=checked_at,
            endpoint_policy=(
                self._endpoint_pricing.get(model)
                if require_runtime_snapshots and not allow_refreshed_pricing
                else None
            ),
            model_identity=(
                self._model_identities.get(model) if require_runtime_snapshots else None
            ),
            require_runtime_snapshots=(require_runtime_snapshots and not allow_refreshed_pricing),
        )
        if (
            allow_refreshed_pricing
            and require_runtime_snapshots
            and (
                self._endpoint_pricing.get(model) is None
                or self._model_identities.get(model) is None
            )
        ):
            raise OpenRouterQualificationError(
                "refreshed-price production routing requires current model and endpoint snapshots"
            )
        return binding

    def _require_real_audit_model_selection(
        self,
        *,
        role: str,
        model: str,
        system_prompt: str,
        user_prompt: str,
        response_model: type[BaseModel],
        schema_name: str,
        structured_output_mode: StructuredOutputMode,
        context_package: ContextPackage | None,
        checked_at: datetime,
        qualification_binding: OpenRouterQualificationRoutingEvidence | None,
        provider_policy: OpenRouterProviderPolicy,
    ) -> AuditModelRoutingEvidence:
        """Recheck exact audit policy authority at one paid transport boundary."""

        from mmaudit.models.policy_selection import AuditModelRoutingEvidence

        if not _TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION(
            self,
            role,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            schema_name=schema_name,
            structured_output_mode=structured_output_mode,
            context_package=context_package,
        ):
            raise OpenRouterPolicyEligibilityError(
                "audit policy selection was requested outside its paid audit boundary"
            )
        if self._audit_model_selection is None:
            raise OpenRouterPolicyEligibilityError(
                "real post-qualification certification requires verified audit model selection"
            )
        audit_policy_binding = _canonical_audit_policy_binding(
            policy_audit_context=(
                self._audit_policy_binding.audit_context
                if self._audit_policy_binding is not None
                else None
            ),
            client_policy_constraints=(
                self._audit_policy_binding.client_constraints
                if self._audit_policy_binding is not None
                else None
            ),
            effective_privacy_policy=self.effective_privacy_policy,
        )
        if audit_policy_binding is None:
            raise OpenRouterPolicyEligibilityError(
                "real post-qualification certification lacks independent audit policy binding"
            )
        if qualification_binding is None or self._production_qualification is None:
            raise OpenRouterPolicyEligibilityError(
                "audit model selection lacks its exact technical qualification binding"
            )
        used_at = checked_at.replace(microsecond=0)
        selection = _require_exact_audit_model_selection_authority(
            selection=self._audit_model_selection,
            binding=audit_policy_binding,
            now=used_at,
        )
        try:
            raw_evidence = selection.routing_evidence(
                model,
                now=used_at,
                expected_audit_scope_sha256=(audit_policy_binding.audit_context.audit_scope_sha256),
                expected_source_sha256=audit_policy_binding.audit_context.source_sha256,
                expected_audit_context_sha256=(audit_policy_binding.audit_context.context_sha256),
                expected_client_constraints_sha256=(
                    audit_policy_binding.client_constraints.constraints_sha256
                ),
            )
            evidence = AuditModelRoutingEvidence.model_validate_json(
                raw_evidence.model_dump_json(),
                strict=True,
            )
        except (AttributeError, ValueError) as exc:
            raise OpenRouterPolicyEligibilityError(
                f"audit model selection rejected exact route: {exc}"
            ) from exc
        route = evidence.route
        if (
            raw_evidence != evidence
            or evidence.audit_scope_sha256 != audit_policy_binding.audit_context.audit_scope_sha256
            or evidence.source_sha256 != audit_policy_binding.audit_context.source_sha256
            or evidence.audit_context_sha256 != audit_policy_binding.audit_context.context_sha256
            or evidence.client_constraints_sha256
            != audit_policy_binding.client_constraints.constraints_sha256
            or route.exact_model_id != model
            or route.provider_endpoint != qualification_binding.approved_provider_endpoint
            or route.provider_name != qualification_binding.approved_provider_name
            or provider_policy.configured_endpoints != (route.provider_endpoint,)
            or evidence.technical_production_selection_sha256
            != self._production_qualification.production_selection_sha256
            or evidence.technical_qualification_capability_sha256
            != self._production_qualification.capability_sha256
        ):
            raise OpenRouterPolicyEligibilityError(
                "audit model selection differs from the exact technical provider route"
            )
        return evidence

    def _require_real_audit_model_refresh(
        self,
        *,
        role: str,
        model: str,
        system_prompt: str,
        user_prompt: str,
        response_model: type[BaseModel],
        schema_name: str,
        structured_output_mode: StructuredOutputMode,
        context_package: ContextPackage | None,
        checked_at: datetime,
        qualification_binding: OpenRouterQualificationRoutingEvidence | None,
        audit_routing_evidence: AuditModelRoutingEvidence | None,
        provider_policy: OpenRouterProviderPolicy,
    ) -> AuditModelRefreshRouteEvidence:
        """Recheck the exact non-authorizing refresh veto for one paid route."""

        from mmaudit.models.refresh_runtime import (
            AuditModelRefreshEvidence,
            AuditModelRefreshRouteEvidence,
        )

        if not _TRUSTED_REQUIRES_REAL_AUDIT_MODEL_REFRESH(
            self,
            role,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            schema_name=schema_name,
            structured_output_mode=structured_output_mode,
            context_package=context_package,
        ):
            raise OpenRouterModelRefreshError(
                "audit model refresh was requested outside its REAL paid-audit boundary"
            )
        binding = self._audit_model_refresh_binding
        if binding is None:
            raise OpenRouterModelRefreshError(
                "REAL audit request requires current model refresh evidence and opaque guard"
            )
        if (
            self._production_qualification is None
            or self._audit_model_selection is None
            or self._audit_policy_binding is None
            or qualification_binding is None
            or audit_routing_evidence is None
        ):
            raise OpenRouterModelRefreshError(
                "audit model refresh lacks exact technical and audit selection authority"
            )
        try:
            evidence = AuditModelRefreshEvidence.model_validate_json(
                binding.evidence.model_dump_json(),
                strict=True,
            )
        except (AttributeError, ValueError) as exc:
            raise OpenRouterModelRefreshError(
                "audit model refresh evidence is no longer structurally current"
            ) from exc
        if evidence != binding.evidence:
            raise OpenRouterModelRefreshError(
                "audit model refresh evidence changed before provider use"
            )
        audit_context = self._audit_policy_binding.audit_context
        client_constraints = self._audit_policy_binding.client_constraints
        used_at = checked_at.replace(microsecond=0)
        try:
            raw_route = binding.guard.route_for(
                model,
                now=used_at,
                expected_workflow_status_sha256=(evidence.expected_workflow_status_sha256),
                technical_qualification=self._production_qualification,
                audit_selection=self._audit_model_selection,
                expected_audit_scope_sha256=audit_context.audit_scope_sha256,
                expected_source_sha256=audit_context.source_sha256,
                expected_audit_context_sha256=audit_context.context_sha256,
                expected_client_constraints_sha256=client_constraints.constraints_sha256,
            )
            route = AuditModelRefreshRouteEvidence.model_validate_json(
                raw_route.model_dump_json(),
                strict=True,
            )
        except (AttributeError, ValueError) as exc:
            raise OpenRouterModelRefreshError(
                f"audit model refresh guard rejected exact route: {exc}"
            ) from exc
        audit_route = audit_routing_evidence.route
        exact_evidence_joins = (
            evidence.expected_workflow_status_sha256 == evidence.workflow_status_sha256,
            evidence.workflow_status_sha256 == binding.guard.workflow_status_sha256,
            evidence.snapshot_sha256 == binding.guard.snapshot_sha256,
            evidence.evidence_sha256 == binding.guard.evidence_sha256,
            evidence.technical_qualification_capability_sha256
            == self._production_qualification.capability_sha256,
            evidence.technical_production_selection_sha256
            == self._production_qualification.production_selection_sha256,
            evidence.audit_selection_capability_sha256
            == self._audit_model_selection.capability_sha256,
            evidence.audit_selection_sha256 == self._audit_model_selection.audit_selection_sha256,
            evidence.audit_scope_sha256 == audit_context.audit_scope_sha256,
            evidence.source_sha256 == audit_context.source_sha256,
            evidence.audit_context_sha256 == audit_context.context_sha256,
            evidence.client_constraints_sha256 == client_constraints.constraints_sha256,
            audit_routing_evidence.audit_scope_sha256 == evidence.audit_scope_sha256,
            audit_routing_evidence.source_sha256 == evidence.source_sha256,
            audit_routing_evidence.audit_context_sha256 == evidence.audit_context_sha256,
            audit_routing_evidence.client_constraints_sha256 == evidence.client_constraints_sha256,
            audit_routing_evidence.audit_selection_sha256 == evidence.audit_selection_sha256,
            audit_routing_evidence.technical_production_selection_sha256
            == evidence.technical_production_selection_sha256,
            audit_routing_evidence.technical_qualification_capability_sha256
            == evidence.technical_qualification_capability_sha256,
        )
        exact_route_joins = (
            raw_route == route,
            route.exact_model_id == model == qualification_binding.exact_model_id,
            route.canonical_model_slug == qualification_binding.canonical_model_slug,
            route.root_lineage == qualification_binding.root_lineage,
            route.approved_provider_endpoint
            == qualification_binding.approved_provider_endpoint
            == audit_route.provider_endpoint,
            route.approved_provider_name
            == qualification_binding.approved_provider_name
            == audit_route.provider_name,
            route.endpoint_snapshot_sha256 == qualification_binding.endpoint_snapshot_sha256,
            route.output_capability_sha256 == qualification_binding.output_capability_sha256,
            route.model_metadata_snapshot_sha256
            == qualification_binding.model_metadata_snapshot_sha256,
            route.qualified_pricing_snapshot_sha256
            == qualification_binding.pricing_snapshot_sha256,
            route.structured_output_mode
            is qualification_binding.structured_output_mode
            is structured_output_mode,
            route.approved_roles == qualification_binding.approved_roles,
            route.benchmark_report_sha256 == qualification_binding.benchmark_report_sha256,
            route.qualification_expires_at == qualification_binding.expires_at,
            route.audit_selected,
            not route.runtime_authorized,
            audit_route.exact_model_id == model,
            provider_policy.configured_endpoints == (route.approved_provider_endpoint,),
            not provider_policy.allow_fallbacks,
        )
        if (
            not all(exact_evidence_joins)
            or not all(exact_route_joins)
            or evidence.technical_selection_authorized
            or evidence.audit_selection_authorized
            or evidence.provider_access_authorized
            or evidence.production_promotion_authorized
        ):
            raise OpenRouterModelRefreshError(
                "audit model refresh differs from the exact technical, audit, or provider route"
            )
        return route

    def _require_real_audit_model_refresh_pricing(
        self,
        *,
        role: str,
        model: str,
        system_prompt: str,
        user_prompt: str,
        response_model: type[BaseModel],
        schema_name: str,
        structured_output_mode: StructuredOutputMode,
        context_package: ContextPackage | None,
        checked_at: datetime,
        qualification_binding: OpenRouterQualificationRoutingEvidence | None,
        audit_routing_evidence: AuditModelRoutingEvidence | None,
        refresh_routing_evidence: AuditModelRefreshRouteEvidence | None,
        provider_policy: OpenRouterProviderPolicy,
    ) -> AuditModelRefreshPricingRouteEvidence:
        """Recheck exact bounded current prices and their live provider route."""

        from mmaudit.models.refresh_runtime import (
            AuditModelRefreshPricingEvidence,
            AuditModelRefreshPricingRouteEvidence,
        )

        if not _TRUSTED_REQUIRES_REAL_AUDIT_MODEL_REFRESH_PRICING(
            self,
            role,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            schema_name=schema_name,
            structured_output_mode=structured_output_mode,
            context_package=context_package,
        ):
            raise OpenRouterModelRefreshPricingError(
                "audit model refresh pricing was requested outside its REAL paid-audit boundary"
            )
        binding = self._audit_model_refresh_pricing_binding
        refresh_binding = self._audit_model_refresh_binding
        if binding is None:
            raise OpenRouterModelRefreshPricingError(
                "REAL audit request requires refresh pricing evidence and opaque authority"
            )
        if (
            refresh_binding is None
            or self._production_qualification is None
            or self._audit_model_selection is None
            or self._audit_policy_binding is None
            or qualification_binding is None
            or audit_routing_evidence is None
            or refresh_routing_evidence is None
        ):
            raise OpenRouterModelRefreshPricingError(
                "audit model refresh pricing lacks exact technical, audit, or refresh authority"
            )
        try:
            evidence = AuditModelRefreshPricingEvidence.model_validate_json(
                binding.evidence.model_dump_json(),
                strict=True,
            )
        except (AttributeError, ValueError) as exc:
            raise OpenRouterModelRefreshPricingError(
                "audit model refresh pricing evidence is no longer structurally current"
            ) from exc
        if evidence != binding.evidence:
            raise OpenRouterModelRefreshPricingError(
                "audit model refresh pricing evidence changed before provider use"
            )
        audit_context = self._audit_policy_binding.audit_context
        client_constraints = self._audit_policy_binding.client_constraints
        used_at = checked_at.replace(microsecond=0)
        try:
            raw_route = binding.authority.route_for(
                model,
                now=used_at,
                expected_workflow_status_sha256=(evidence.expected_workflow_status_sha256),
                refresh_evidence=refresh_binding.evidence,
                refresh_guard=refresh_binding.guard,
                technical_qualification=self._production_qualification,
                audit_selection=self._audit_model_selection,
                expected_audit_scope_sha256=audit_context.audit_scope_sha256,
                expected_source_sha256=audit_context.source_sha256,
                expected_audit_context_sha256=audit_context.context_sha256,
                expected_client_constraints_sha256=client_constraints.constraints_sha256,
            )
            route = AuditModelRefreshPricingRouteEvidence.model_validate_json(
                raw_route.model_dump_json(),
                strict=True,
            )
        except (AttributeError, ValueError) as exc:
            raise OpenRouterModelRefreshPricingError(
                f"audit model refresh pricing authority rejected exact route: {exc}"
            ) from exc
        registered_policy = self._endpoint_pricing.get(model)
        registered_endpoint = (
            registered_policy.endpoint(route.approved_provider_endpoint)
            if registered_policy is not None
            else None
        )
        live_route = refresh_routing_evidence.refresh_route
        exact_evidence_joins = (
            evidence.expected_workflow_status_sha256 == evidence.workflow_status_sha256,
            evidence.workflow_status_sha256 == binding.authority.workflow_status_sha256,
            evidence.refresh_evidence_sha256 == refresh_binding.evidence.evidence_sha256,
            evidence.refresh_guard_capability_sha256 == refresh_binding.guard.capability_sha256,
            evidence.technical_qualification_capability_sha256
            == self._production_qualification.capability_sha256,
            evidence.technical_production_selection_sha256
            == self._production_qualification.production_selection_sha256,
            evidence.audit_selection_capability_sha256
            == self._audit_model_selection.capability_sha256,
            evidence.audit_selection_sha256 == self._audit_model_selection.audit_selection_sha256,
            evidence.audit_scope_sha256 == audit_context.audit_scope_sha256,
            evidence.source_sha256 == audit_context.source_sha256,
            evidence.audit_context_sha256 == audit_context.context_sha256,
            evidence.client_constraints_sha256 == client_constraints.constraints_sha256,
            evidence.evidence_sha256 == binding.authority.pricing_evidence_sha256,
        )
        exact_route_joins = (
            raw_route == route,
            route.exact_model_id
            == model
            == qualification_binding.exact_model_id
            == audit_routing_evidence.route.exact_model_id
            == refresh_routing_evidence.exact_model_id,
            route.approved_provider_endpoint
            == qualification_binding.approved_provider_endpoint
            == audit_routing_evidence.route.provider_endpoint
            == refresh_routing_evidence.approved_provider_endpoint,
            route.qualified_pricing_snapshot_sha256
            == route.baseline_pricing_sha256
            == qualification_binding.pricing_snapshot_sha256,
            route.baseline_snapshot_sha256 == evidence.previous_snapshot_sha256,
            route.current_snapshot_sha256 == evidence.current_snapshot_sha256,
            route.current_snapshot_sha256 == refresh_binding.evidence.snapshot_sha256,
            route.current_pricing == live_route.pricing,
            route.current_pricing_sha256 == live_route.pricing_sha256,
            route.refresh_route_evidence_sha256 == refresh_routing_evidence.route_evidence_sha256,
            route.audit_selected,
            not route.pricing_use_authorized,
            not route.provider_access_authorized,
            not route.model_selection_authorized,
            provider_policy.configured_endpoints == (route.approved_provider_endpoint,),
            not provider_policy.allow_fallbacks,
        )
        exact_registered_joins = (
            registered_policy is not None,
            registered_endpoint is not None,
            registered_policy is not None and len(registered_policy.endpoints) == 1,
            registered_policy is not None
            and registered_policy.output_capability_sha256
            == qualification_binding.output_capability_sha256,
            registered_policy is not None
            and registered_policy.structured_output_mode is structured_output_mode,
            registered_endpoint is not None
            and registered_endpoint.provider_endpoint == live_route.provider_endpoint,
            registered_endpoint is not None
            and registered_endpoint.provider_name == live_route.provider_name,
            registered_endpoint is not None
            and registered_endpoint.provider_identities
            == tuple(
                sorted(
                    {
                        identity
                        for identity in (
                            live_route.provider_endpoint,
                            live_route.endpoint_tag,
                            live_route.endpoint_slug,
                            live_route.provider_name,
                        )
                        if identity is not None
                    },
                    key=str.casefold,
                )
            ),
            registered_endpoint is not None
            and registered_endpoint.endpoint_tag == live_route.endpoint_tag,
            registered_endpoint is not None
            and registered_endpoint.endpoint_slug == live_route.endpoint_slug,
            registered_endpoint is not None
            and registered_endpoint.operational_status == live_route.operational_status,
            registered_endpoint is not None
            and registered_endpoint.zdr_eligible is live_route.zdr_eligible,
            registered_endpoint is not None
            and registered_endpoint.context_length == live_route.context_limit,
            registered_endpoint is not None
            and registered_endpoint.max_prompt_tokens == live_route.max_prompt_tokens,
            registered_endpoint is not None
            and registered_endpoint.max_prompt_tokens_source == live_route.max_prompt_tokens_source,
            registered_endpoint is not None
            and registered_endpoint.max_completion_tokens == live_route.output_limit,
            registered_endpoint is not None
            and registered_endpoint.max_completion_tokens_source == live_route.output_limit_source,
            registered_endpoint is not None
            and registered_endpoint.supported_parameters == live_route.supported_parameters,
            registered_endpoint is not None
            and registered_endpoint.required_request_parameters
            == tuple(
                sorted(
                    {
                        "max_tokens",
                        "temperature",
                        *output_mode_request_parameters(live_route.structured_output_mode),
                    }
                )
            ),
            registered_endpoint is not None
            and registered_endpoint.structured_output_parameters
            == structured_output_parameters(live_route.supported_parameters),
            registered_endpoint is not None
            and registered_endpoint.supported_output_modes == live_route.supported_output_modes,
            registered_endpoint is not None
            and registered_endpoint.structured_output_mode is live_route.structured_output_mode,
            registered_endpoint is not None
            and dict(registered_endpoint.pricing) == route.current_pricing,
            registered_endpoint is not None
            and registered_endpoint.pricing_sha256 == route.current_pricing_sha256,
            live_route.routing_identity_unambiguous,
            live_route.operational,
            live_route.structured_output_supported,
        )
        if (
            not all(exact_evidence_joins)
            or not all(exact_route_joins)
            or not all(exact_registered_joins)
            or evidence.pricing_use_authorized
            or evidence.technical_selection_authorized
            or evidence.audit_selection_authorized
            or evidence.provider_access_authorized
            or evidence.production_promotion_authorized
        ):
            raise OpenRouterModelRefreshPricingError(
                "audit model refresh pricing differs from the exact current provider route"
            )
        return route

    def _seal_audit_model_refresh_pricing_control(
        self,
        route: AuditModelRefreshPricingRouteEvidence,
    ) -> _AuditModelRefreshPricingRequestControl:
        """Seal one exact Decimal price map for both provider cap and reservation."""

        binding = self._audit_model_refresh_pricing_binding
        registered_policy = self._endpoint_pricing.get(route.exact_model_id)
        trusted_endpoint_snapshot_sha256 = _lookup_trusted_endpoint_snapshot(
            self,
            route.exact_model_id,
        )
        registered_endpoint = (
            registered_policy.endpoint(route.approved_provider_endpoint)
            if registered_policy is not None
            else None
        )
        if (
            binding is None
            or registered_policy is None
            or trusted_endpoint_snapshot_sha256 is None
            or registered_policy.snapshot_sha256 != trusted_endpoint_snapshot_sha256
            or registered_endpoint is None
            or dict(registered_endpoint.pricing) != route.current_pricing
            or registered_endpoint.pricing_sha256 != route.current_pricing_sha256
        ):
            raise OpenRouterModelRefreshPricingError(
                "current endpoint pricing changed before request-price sealing"
            )
        routing_max_price = tuple(_routing_max_price((registered_endpoint,)).items())
        try:
            cost_bound_pricing = _TRUSTED_PROVIDER_CAPPED_COST_BOUND_PRICING(
                registered_endpoint,
                dict(routing_max_price),
            )
        except OpenRouterCostControlError as exc:
            raise OpenRouterModelRefreshPricingError(
                "current endpoint price lacks an exact transmitted provider cap"
            ) from exc
        values: dict[str, Any] = {
            "exact_model_id": route.exact_model_id,
            "provider_endpoint": route.approved_provider_endpoint,
            "current_endpoint_snapshot_sha256": trusted_endpoint_snapshot_sha256,
            "qualified_pricing_snapshot_sha256": route.qualified_pricing_snapshot_sha256,
            "current_pricing": tuple(route.current_pricing.items()),
            "current_pricing_sha256": route.current_pricing_sha256,
            "route_evidence_sha256": route.route_evidence_sha256,
            "evidence_sha256": binding.evidence.evidence_sha256,
            "authority_capability_sha256": binding.authority.capability_sha256,
            "routing_max_price": routing_max_price,
            "cost_bound_pricing": tuple(cost_bound_pricing),
        }
        return _AuditModelRefreshPricingRequestControl(
            **values,
            control_sha256=_canonical_sha256(values),
        )

    def require_audit_policy_binding(
        self,
        *,
        audit_model_selection: VerifiedAuditModelSelection,
        policy_audit_context: PolicyAuditContext,
        client_policy_constraints: ClientPolicyConstraints,
        checked_at: datetime,
    ) -> None:
        """Verify exact independently supplied audit authority without exposing it."""

        supplied_binding = _canonical_audit_policy_binding(
            policy_audit_context=policy_audit_context,
            client_policy_constraints=client_policy_constraints,
            effective_privacy_policy=self.effective_privacy_policy,
        )
        if (
            supplied_binding is None
            or supplied_binding != self._audit_policy_binding
            or audit_model_selection is not self._audit_model_selection
        ):
            raise OpenRouterPolicyEligibilityError(
                "OpenRouter client binds different audit policy authority"
            )
        _require_exact_audit_model_selection_authority(
            selection=audit_model_selection,
            binding=supplied_binding,
            now=checked_at.replace(microsecond=0),
        )

    def require_audit_model_refresh_binding(
        self,
        *,
        audit_model_refresh_evidence: AuditModelRefreshEvidence,
        audit_model_refresh_guard: VerifiedAuditModelRefreshGuard,
        checked_at: datetime,
    ) -> None:
        """Verify that an existing client owns the exact live refresh pair."""

        supplied = _canonical_audit_model_refresh_binding(
            evidence=audit_model_refresh_evidence,
            guard=audit_model_refresh_guard,
        )
        current = self._audit_model_refresh_binding
        if (
            supplied is None
            or current is None
            or supplied.evidence != current.evidence
            or supplied.guard is not current.guard
            or self._production_qualification is None
            or self._audit_model_selection is None
            or self._audit_policy_binding is None
        ):
            raise OpenRouterModelRefreshError(
                "OpenRouter client binds different audit model refresh authority"
            )
        context = self._audit_policy_binding.audit_context
        constraints = self._audit_policy_binding.client_constraints
        try:
            verified = current.guard.require_current(
                now=checked_at.replace(microsecond=0),
                expected_workflow_status_sha256=(current.evidence.expected_workflow_status_sha256),
                technical_qualification=self._production_qualification,
                audit_selection=self._audit_model_selection,
                expected_audit_scope_sha256=context.audit_scope_sha256,
                expected_source_sha256=context.source_sha256,
                expected_audit_context_sha256=context.context_sha256,
                expected_client_constraints_sha256=constraints.constraints_sha256,
            )
        except ValueError as exc:
            raise OpenRouterModelRefreshError(
                f"audit model refresh authority rejected use: {exc}"
            ) from exc
        if (
            verified is not current.guard
            or current.evidence.evidence_sha256 != current.guard.evidence_sha256
            or current.evidence.workflow_status_sha256 != current.guard.workflow_status_sha256
            or current.evidence.snapshot_sha256 != current.guard.snapshot_sha256
        ):
            raise OpenRouterModelRefreshError(
                "audit model refresh authority differs from its durable evidence"
            )

    def require_audit_model_refresh_pricing_binding(
        self,
        *,
        audit_model_refresh_pricing_evidence: AuditModelRefreshPricingEvidence,
        audit_model_refresh_pricing_authority: VerifiedAuditModelRefreshPricingAuthority,
        checked_at: datetime,
    ) -> None:
        """Verify that an existing client owns the exact refreshed-pricing pair."""

        current = self._audit_model_refresh_pricing_binding
        refresh = self._audit_model_refresh_binding
        supplied = _canonical_audit_model_refresh_pricing_binding(
            evidence=audit_model_refresh_pricing_evidence,
            authority=audit_model_refresh_pricing_authority,
            refresh_binding=refresh,
        )
        if (
            supplied is None
            or current is None
            or supplied.evidence != current.evidence
            or supplied.authority is not current.authority
            or refresh is None
            or self._production_qualification is None
            or self._audit_model_selection is None
            or self._audit_policy_binding is None
        ):
            raise OpenRouterModelRefreshPricingError(
                "OpenRouter client binds different audit model refresh pricing authority"
            )
        context = self._audit_policy_binding.audit_context
        constraints = self._audit_policy_binding.client_constraints
        try:
            verified = current.authority.require_current(
                now=checked_at.replace(microsecond=0),
                expected_workflow_status_sha256=(current.evidence.expected_workflow_status_sha256),
                refresh_evidence=refresh.evidence,
                refresh_guard=refresh.guard,
                technical_qualification=self._production_qualification,
                audit_selection=self._audit_model_selection,
                expected_audit_scope_sha256=context.audit_scope_sha256,
                expected_source_sha256=context.source_sha256,
                expected_audit_context_sha256=context.context_sha256,
                expected_client_constraints_sha256=constraints.constraints_sha256,
            )
        except ValueError as exc:
            raise OpenRouterModelRefreshPricingError(
                f"audit model refresh pricing authority rejected use: {exc}"
            ) from exc
        if (
            verified is not current.authority
            or current.evidence.evidence_sha256 != current.authority.pricing_evidence_sha256
            or current.evidence.refresh_evidence_sha256 != refresh.evidence.evidence_sha256
            or current.evidence.refresh_guard_capability_sha256 != refresh.guard.capability_sha256
        ):
            raise OpenRouterModelRefreshPricingError(
                "audit model refresh pricing authority differs from durable evidence"
            )

    def _require_real_postqualification_reasoning_plan(
        self,
        *,
        role: str,
        model: str,
        system_prompt: str,
        user_prompt: str,
        response_model: type[BaseModel],
        schema_name: str,
        structured_output_mode: StructuredOutputMode,
        context_package: ContextPackage | None,
        qualification_binding: OpenRouterQualificationRoutingEvidence | None,
    ) -> ReasoningRequestPlanEvidence:
        """Require one exact policy-, capability-, and qualification-bound request plan."""

        if not _TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION(
            self,
            role,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            schema_name=schema_name,
            structured_output_mode=structured_output_mode,
            context_package=context_package,
        ):
            raise OpenRouterQualificationError(
                "post-qualification reasoning authority was requested outside its real "
                "certification boundary"
            )
        if self.reasoning is not None:
            raise OpenRouterQualificationError(
                "real post-qualification certification rejects legacy global reasoning"
            )
        if self.reasoning_policy is None:
            raise OpenRouterQualificationError(
                "real post-qualification certification requires a sealed per-role reasoning policy"
            )
        if qualification_binding is None:
            raise OpenRouterQualificationError(
                "real post-qualification certification requires current qualification "
                "routing evidence"
            )
        plan = self._reasoning_request_plan(
            role=role,
            model=model,
            qualification_binding=qualification_binding,
        )
        if (
            plan is None
            or plan.binding_state != "qualification_bound"
            or plan.endpoint_capability_sha256 is None
            or plan.qualification_binding_sha256 is None
        ):
            raise OpenRouterQualificationError(
                "real post-qualification certification requires an exact capability- and "
                "qualification-bound reasoning plan"
            )
        return plan

    def _route_token_intersection(
        self,
        *,
        model: str,
        provider_policy: OpenRouterProviderPolicy,
        requested_completion_tokens: int,
    ) -> EndpointRouteIntersection:
        registered_policy = self._endpoint_pricing.get(model)
        if registered_policy is None:
            if trusted_openrouter_execution_evidence(self) is not ExecutionEvidenceKind.MOCK:
                raise OpenRouterRequestLimitError(
                    "endpoint token planning requires frozen route capacity evidence"
                )
            prompt_capacity = min(self.execution.max_request_bytes, _MAX_TOKEN_EVIDENCE - 1)
            context_capacity = min(
                _MAX_TOKEN_EVIDENCE,
                prompt_capacity + requested_completion_tokens,
            )
            mock_snapshot_sha256 = _canonical_sha256(
                {
                    "execution_evidence": ExecutionEvidenceKind.MOCK.value,
                    "exact_model_id": model,
                    "max_request_bytes": self.execution.max_request_bytes,
                    "requested_completion_tokens": requested_completion_tokens,
                }
            )
            return EndpointRouteIntersection.build(
                (
                    EndpointRouteTokenCapacity.build(
                        exact_model_id=model,
                        provider_endpoint=_LOCAL_MOCK_PROVIDER_ENDPOINT,
                        endpoint_snapshot_sha256=mock_snapshot_sha256,
                        context_tokens=context_capacity,
                        max_prompt_tokens=prompt_capacity,
                        max_prompt_tokens_source="metadata",
                        max_completion_tokens=requested_completion_tokens,
                        max_completion_tokens_source="metadata",
                    ),
                )
            )

        configured_endpoints = provider_policy.configured_endpoints
        if not configured_endpoints:
            raise OpenRouterRequestLimitError(
                "frozen endpoint token planning requires an explicit route policy"
            )
        routes: list[EndpointRouteTokenCapacity] = []
        for configured_endpoint in configured_endpoints:
            endpoint = registered_policy.endpoint(configured_endpoint)
            if endpoint is None:
                raise OpenRouterRequestLimitError(
                    "request route is absent or ambiguous in frozen endpoint evidence"
                )
            routes.append(
                EndpointRouteTokenCapacity.build(
                    exact_model_id=model,
                    provider_endpoint=endpoint.provider_endpoint,
                    endpoint_snapshot_sha256=endpoint.snapshot_sha256,
                    context_tokens=endpoint.context_length,
                    max_prompt_tokens=endpoint.max_prompt_tokens,
                    max_prompt_tokens_source=endpoint.max_prompt_tokens_source,
                    max_completion_tokens=endpoint.max_completion_tokens,
                    max_completion_tokens_source=endpoint.max_completion_tokens_source,
                )
            )
        return EndpointRouteIntersection.build(routes)

    def context_package_byte_budget(
        self,
        models: Sequence[str],
        *,
        role: str | None = None,
        workflow_byte_upper_bound_tokens: int | None = None,
        workflow_prompt: str | None = None,
        context_json_escape_overhead_tokens: int = 0,
    ) -> int:
        """Return a conservative endpoint-aware serialized-context allowance.

        This preview reserves configured system, schema, protocol, and workflow
        space plus deterministic JSON/chat-envelope headroom. When the exact
        workflow prompt is available, its provider-visible JSON-string encoding
        replaces the raw UTF-8 preview; a supplied raw bound must match that
        prompt. Callers may also deduct the exact JSON-string escape overhead
        measured for the rendered context package. Raw-bound-only calls remain
        supported for compatibility. The exact final request is still measured
        and validated by ``_request_token_plan``; preview evidence can never
        authorize transport on its own.
        """

        canonical_models = tuple(models)
        if not canonical_models or len(canonical_models) != len(set(canonical_models)):
            raise OpenRouterRequestLimitError(
                "context budget preview requires unique configured model IDs"
            )
        if isinstance(workflow_byte_upper_bound_tokens, bool) or (
            workflow_byte_upper_bound_tokens is not None
            and (
                not isinstance(workflow_byte_upper_bound_tokens, int)
                or workflow_byte_upper_bound_tokens < 0
            )
        ):
            raise OpenRouterRequestLimitError("context budget preview workflow bound is invalid")
        if workflow_prompt is not None and not isinstance(workflow_prompt, str):
            raise OpenRouterRequestLimitError("context budget preview workflow prompt is invalid")
        if isinstance(context_json_escape_overhead_tokens, bool) or not isinstance(
            context_json_escape_overhead_tokens,
            int,
        ):
            raise OpenRouterRequestLimitError(
                "context budget preview context JSON escape overhead tokens are invalid"
            )
        if context_json_escape_overhead_tokens < 0:
            raise OpenRouterRequestLimitError(
                "context budget preview context JSON escape overhead tokens are invalid"
            )
        effective_workflow_bound = workflow_byte_upper_bound_tokens or 0
        workflow_prompt_sha256: str | None = None
        workflow_prompt_provider_visible_bytes: int | None = None
        if workflow_prompt is not None:
            raw_workflow_bound = len(workflow_prompt.encode("utf-8"))
            if (
                workflow_byte_upper_bound_tokens is not None
                and workflow_byte_upper_bound_tokens != raw_workflow_bound
            ):
                raise OpenRouterRequestLimitError(
                    "context budget preview raw workflow bound does not match prompt"
                )
            workflow_prompt_sha256 = hashlib.sha256(workflow_prompt.encode("utf-8")).hexdigest()
            workflow_prompt_provider_visible_bytes = len(
                _compact_json(workflow_prompt).encode("utf-8")
            )
            effective_workflow_bound = workflow_prompt_provider_visible_bytes
        required_output_tokens = self._required_output_tokens()
        requested_completion_tokens = required_output_tokens + self._reserved_reasoning_tokens(
            required_output_tokens,
            role=role,
        )
        utilization = Decimal(
            str(
                self.token_budgets.usable_input_fraction if self.token_budgets is not None else 0.70
            )
        )
        budgets: list[int] = []
        for model in canonical_models:
            qualification_binding = self._qualification_routing.get(model)
            self._reasoning_request_plan(
                role=role or "",
                model=model,
                qualification_binding=qualification_binding,
            )
            provider_policy = (
                qualification_binding.request_provider_policy()
                if qualification_binding is not None and self.provider_policy.certification
                else self.provider_policy
            )
            route = self._route_token_intersection(
                model=model,
                provider_policy=_canonical_provider_policy(provider_policy),
                requested_completion_tokens=requested_completion_tokens,
            )
            hard_prompt_tokens = min(
                route.max_prompt_tokens,
                route.context_tokens - requested_completion_tokens,
            )
            usable_prompt_tokens = int(Decimal(hard_prompt_tokens) * utilization)
            configured_system_reserve = (
                self.token_budgets.reserved_system_tokens if self.token_budgets is not None else 0
            )
            configured_schema_reserve = (
                self.token_budgets.reserved_schema_tokens if self.token_budgets is not None else 0
            )
            configured_protocol_reserve = (
                self.token_budgets.reserved_protocol_tokens if self.token_budgets is not None else 0
            )
            configured_workflow_reserve = (
                self.token_budgets.reserved_workflow_tokens if self.token_budgets is not None else 0
            )
            effective_workflow_reserve = max(
                configured_workflow_reserve,
                effective_workflow_bound,
            )
            configured_reserve = (
                configured_system_reserve
                + configured_schema_reserve
                + configured_protocol_reserve
                + effective_workflow_reserve
            )
            package_budget = (
                usable_prompt_tokens
                - configured_reserve
                - _CONTEXT_PREVIEW_ENVELOPE_RESERVE_TOKENS
                - context_json_escape_overhead_tokens
            )
            if package_budget <= 0:
                raise OpenRouterRequestLimitError(
                    "endpoint reserves leave no serialized context-package capacity"
                )
            budgets.append(package_budget)
        computed_package_budget = min(budgets)
        binding = _lookup_trusted_transport_binding(self)
        observer = (
            binding.test_only_context_package_budget_observer
            if binding is not None
            and binding.execution_evidence is ExecutionEvidenceKind.MOCK
            and trusted_openrouter_execution_evidence(self) is ExecutionEvidenceKind.MOCK
            else None
        )
        if observer is not None:
            try:
                observer_result = observer(
                    canonical_models,
                    role=role,
                    workflow_byte_upper_bound_tokens=workflow_byte_upper_bound_tokens,
                    workflow_prompt_sha256=workflow_prompt_sha256,
                    workflow_prompt_provider_visible_bytes=(workflow_prompt_provider_visible_bytes),
                    context_json_escape_overhead_tokens=context_json_escape_overhead_tokens,
                    computed_package_budget=computed_package_budget,
                )
            finally:
                if trusted_openrouter_execution_evidence(self) is not ExecutionEvidenceKind.MOCK:
                    raise OpenRouterPrivacyError(
                        "test-only context budget observer changed the trusted mock boundary"
                    )
            if observer_result is not None:
                raise OpenRouterPrivacyError(
                    "test-only context budget observer must return exact None"
                )
        return computed_package_budget

    def _diagnostic_planning_snapshot(
        self,
        *,
        request_id: str,
        role: str,
        model: str,
        reason: ContextPreflightReason,
        provider_policy: OpenRouterProviderPolicy,
        structured_output_plan: _StructuredOutputRequestPlan | None,
        original_system_prompt: str,
        response_model: type[BaseModel],
        schema_name: str,
        context_package: ContextPackage | None,
    ) -> ContextPlanningSnapshot:
        """Retain independently measurable facts after full-plan rejection."""

        required_output_tokens = self._required_output_tokens()
        reserved_reasoning_tokens = self._reserved_reasoning_tokens(
            required_output_tokens,
            role=role,
        )
        requested_completion_tokens = required_output_tokens + reserved_reasoning_tokens
        requested_surface_count = (
            len(context_package.requested_model_surfaces) if context_package is not None else 0
        )
        try:
            route_intersection = self._route_token_intersection(
                model=model,
                provider_policy=provider_policy,
                requested_completion_tokens=requested_completion_tokens,
            )
        except (OpenRouterError, TokenPlanningError, TypeError, ValueError):
            route_intersection = None
        try:
            output_allocations = build_output_token_allocations(
                required_output_tokens=required_output_tokens,
                requested_surface_count=requested_surface_count,
            )
        except (TokenPlanningError, TypeError, ValueError):
            output_allocations = None
        allocations: tuple[PromptTokenAllocation, ...] | None = None
        envelope_bound: int | None = None
        if structured_output_plan is not None:
            try:
                allocations = _prompt_token_allocations(
                    plan=structured_output_plan,
                    original_system_prompt=original_system_prompt,
                    response_model=response_model,
                    schema_name=schema_name,
                    context_package=context_package,
                )
            except (OpenRouterError, TokenPlanningError, TypeError, ValueError):
                allocations = None
            try:
                envelope_bound = _prompt_envelope_byte_upper_bound_tokens(structured_output_plan)
            except (OpenRouterError, TokenPlanningError, TypeError, ValueError):
                envelope_bound = None
        return ContextPlanningSnapshot.build(
            request_id=request_id,
            role=role,
            requested_model=model,
            reason=reason,
            route_intersection=route_intersection,
            allocations=allocations,
            output_allocations=output_allocations,
            requested_surface_count=requested_surface_count,
            required_output_tokens=required_output_tokens,
            reserved_reasoning_tokens=reserved_reasoning_tokens,
            prompt_envelope_byte_upper_bound_tokens=envelope_bound,
            context_omissions=_context_omissions(context_package),
        )

    def _request_token_plan(
        self,
        *,
        request_id: str,
        role: str,
        model: str,
        provider_policy: OpenRouterProviderPolicy,
        structured_output_plan: _StructuredOutputRequestPlan,
        original_system_prompt: str,
        response_model: type[BaseModel],
        schema_name: str,
        reasoning_plan: ReasoningRequestPlanEvidence | None,
        context_package: ContextPackage | None = None,
    ) -> tuple[RequestTokenPlan, ContextRequestEvidence | None]:
        if context_package is not None:
            from mmaudit.orchestration.context import (
                ContextBoundaryError,
                revalidate_model_surface_context_package,
            )

            try:
                context_package = revalidate_model_surface_context_package(context_package)
            except ContextBoundaryError:
                raise _OpenRouterContextPlanError(
                    "provider request cannot satisfy the bounded context plan"
                ) from None
        required_output_tokens = self._required_output_tokens()
        reserved_reasoning_tokens = self._reserved_reasoning_tokens(
            required_output_tokens,
            role=role,
        )
        requested_completion_tokens = required_output_tokens + reserved_reasoning_tokens
        global_input_budget = (
            self.token_budgets.global_input_token_budget
            if self.token_budgets is not None
            else (
                self.budget.global_input_token_budget
                if self.budget.global_input_token_budget is not None
                else _MAX_TOKEN_EVIDENCE
            )
        )
        global_output_budget = (
            self.token_budgets.global_output_token_budget
            if self.token_budgets is not None
            else (
                self.budget.global_output_token_budget
                if self.budget.global_output_token_budget is not None
                else _MAX_TOKEN_EVIDENCE
            )
        )
        try:
            route_intersection = self._route_token_intersection(
                model=model,
                provider_policy=provider_policy,
                requested_completion_tokens=requested_completion_tokens,
            )
        except (OpenRouterRequestLimitError, TokenPlanningError, TypeError, ValueError):
            raise _OpenRouterRoutePlanningError(
                "provider request lacks a usable frozen endpoint route"
            ) from None
        try:
            allocations = _prompt_token_allocations(
                plan=structured_output_plan,
                original_system_prompt=original_system_prompt,
                response_model=response_model,
                schema_name=schema_name,
                context_package=context_package,
            )
        except (OpenRouterRequestLimitError, TokenPlanningError, TypeError, ValueError):
            raise _OpenRouterContextPlanError(
                "provider-visible prompt differs from its bounded context plan"
            ) from None
        try:
            context_request_evidence = (
                _context_request_evidence(
                    request_id=request_id,
                    request_role=role,
                    context_package=context_package,
                )
                if context_package is not None
                else None
            )
            configured_maximum_source_tokens = (
                self.token_budgets.maximum_source_tokens_per_request
                if self.token_budgets is not None
                else 200_000
            )
            if (
                context_package is not None
                and context_package.configured_maximum_source_tokens_per_request
                != configured_maximum_source_tokens
            ):
                raise ContextTokenPlanError(
                    "context package source ceiling differs from provider planning configuration"
                )
            request_token_plan = build_request_token_plan(
                request_id=request_id,
                role=role,
                route_intersection=route_intersection,
                allocations=allocations,
                required_output_tokens=required_output_tokens,
                reserved_reasoning_tokens=reserved_reasoning_tokens,
                reasoning_plan=reasoning_plan,
                global_input_token_budget=global_input_budget,
                global_output_token_budget=global_output_budget,
                input_tokens_reserved_before=(
                    self.budget.spent_input_tokens + self.budget.reserved_input_tokens
                ),
                output_tokens_reserved_before=(
                    self.budget.spent_output_tokens + self.budget.reserved_output_tokens
                ),
                context_utilization=Decimal(
                    str(
                        self.token_budgets.usable_input_fraction
                        if self.token_budgets is not None
                        else 0.70
                    )
                ),
                configured_reserved_system_tokens=(
                    self.token_budgets.reserved_system_tokens
                    if self.token_budgets is not None
                    else 0
                ),
                configured_reserved_schema_tokens=(
                    self.token_budgets.reserved_schema_tokens
                    if self.token_budgets is not None
                    else 0
                ),
                configured_reserved_protocol_tokens=(
                    self.token_budgets.reserved_protocol_tokens
                    if self.token_budgets is not None
                    else 0
                ),
                configured_reserved_workflow_tokens=(
                    self.token_budgets.reserved_workflow_tokens
                    if self.token_budgets is not None
                    else 0
                ),
                maximum_source_tokens_per_request=configured_maximum_source_tokens,
                context_package_source_byte_ceiling=(
                    context_package.effective_source_byte_ceiling
                    if context_package is not None
                    else None
                ),
                requested_surface_count=(
                    len(context_package.requested_model_surfaces)
                    if context_package is not None
                    else 0
                ),
                context_omissions=_context_omissions(context_package),
                prompt_envelope_byte_upper_bound_tokens=(
                    _prompt_envelope_byte_upper_bound_tokens(structured_output_plan)
                ),
            )
            return request_token_plan, context_request_evidence
        except GlobalTokenBudgetPlanningError:
            raise _OpenRouterGlobalTokenBudgetError(
                "provider request cannot satisfy the configured global token budget"
            ) from None
        except EndpointTokenCapacityError:
            raise _OpenRouterEndpointCapacityError(
                "provider request cannot satisfy the endpoint-bound token plan"
            ) from None
        except (ContextTokenPlanError, TokenPlanningError, TypeError, ValueError):
            raise _OpenRouterContextPlanError(
                "provider request cannot satisfy the bounded context plan"
            ) from None

    async def _request_metadata(
        self,
        path: str,
        *,
        max_bytes: int = 20_000_000,
        exact_decimal_json: bool = False,
        maximum_attempts: int | None = None,
        not_found_is_pending: bool = False,
    ) -> dict[str, Any]:
        attempt_limit = (
            self.execution.max_model_retries + 1 if maximum_attempts is None else maximum_attempts
        )
        if (
            not isinstance(attempt_limit, int)
            or isinstance(attempt_limit, bool)
            or not 1 <= attempt_limit <= 32
        ):
            raise OpenRouterRequestLimitError("metadata retry bound is invalid")
        attempts = 0
        while True:
            attempts += 1
            try:
                response = await _TRUSTED_BOUNDED_REQUEST(
                    self,
                    "GET",
                    path,
                    max_bytes=max_bytes,
                )
            except (httpx.TimeoutException, httpx.NetworkError):
                if attempts >= attempt_limit:
                    raise OpenRouterTimeoutError("OpenRouter metadata request failed") from None
                await self._backoff(attempts, None)
                continue
            except httpx.HTTPError:
                raise OpenRouterModelError(
                    "OpenRouter metadata transport response was invalid"
                ) from None
            if response.status_code in {401, 403}:
                raise OpenRouterAuthenticationError("OpenRouter rejected the API credentials")
            if response.status_code == 404 and not_found_is_pending:
                raise OpenRouterGenerationMetadataNotReadyError(
                    "OpenRouter generation metadata is not ready"
                )
            if is_retryable_status(response.status_code):
                if attempts >= attempt_limit:
                    if response.status_code == 429:
                        raise OpenRouterRateLimitError(
                            "OpenRouter metadata rate limit exhausted the retry policy"
                        )
                    if response.status_code in {408, 425}:
                        raise OpenRouterTimeoutError(
                            f"transient metadata failure (HTTP {response.status_code})"
                        )
                    raise OpenRouterProviderUnavailableError(
                        f"metadata provider unavailable (HTTP {response.status_code})"
                    )
                await self._backoff(attempts, response.headers.get("Retry-After"))
                continue
            if response.status_code >= 400:
                raise OpenRouterModelError(
                    f"OpenRouter metadata request failed with HTTP {response.status_code}"
                )
            break
        try:
            payload = json.loads(
                response.content,
                parse_float=Decimal if exact_decimal_json else float,
                parse_constant=_reject_nonfinite_json_constant,
                object_pairs_hook=_unique_json_object,
            )
            _require_finite_json_numbers(payload)
        except ValueError:
            payload = None
        if not isinstance(payload, dict):
            raise OpenRouterModelError("OpenRouter metadata response was not a valid object")
        _TRUSTED_ENSURE_NO_CREDENTIAL_IN_VALUE(self, payload)
        observation_path = "/" + path.lstrip("/")
        self._metadata_observations[observation_path] = _canonical_sha256(payload)
        return payload

    async def _bounded_request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        max_bytes: int,
        trusted_pre_transport_check: Callable[[], Coroutine[Any, Any, None]] | None = None,
    ) -> httpx.Response:
        binding = _lookup_trusted_transport_binding(self)
        if binding is None:
            raise OpenRouterPrivacyError(
                "network-capable injected provider clients are not permitted"
            )

        async def perform() -> httpx.Response:
            _TRUSTED_VALIDATE_TRANSPORT_PROVENANCE(self)
            chunks: list[bytes] = []
            total = 0
            relative_path = path.lstrip("/")
            try:
                if trusted_pre_transport_check is not None:
                    await trusted_pre_transport_check()
                async with self._client.stream(
                    method,
                    relative_path,
                    json=json_body,
                    headers=self._headers,
                    timeout=httpx.Timeout(self.execution.request_timeout_seconds),
                ) as response:
                    async for chunk in response.aiter_bytes():
                        total += len(chunk)
                        if total > max_bytes:
                            raise OpenRouterSchemaError(
                                "provider response exceeded the configured safety limit"
                            )
                        chunks.append(chunk)
                    safe_request = httpx.Request(method, response.request.url)
                    return httpx.Response(
                        status_code=response.status_code,
                        headers=_decoded_response_headers(response.headers),
                        content=b"".join(chunks),
                        request=safe_request,
                    )
            except OpenRouterError:
                raise
            except httpx.HTTPError as exc:
                if exc.request is not None:
                    exc.request = httpx.Request(method, self._client.base_url.join(relative_path))
                raise
            except Exception:
                pass
            raise OpenRouterSchemaError("model transport failed safely")

        if binding.execution_evidence is ExecutionEvidenceKind.REAL:
            if binding.request_lock is None:
                raise OpenRouterPrivacyError(
                    "provider transport provenance changed after validation"
                )
            async with binding.request_lock:
                return await perform()
        return await perform()

    def _validate_transport_provenance(self) -> ExecutionEvidenceKind:
        if any(
            name in vars(self)
            for name in (
                "validate_authentication",
                "get_generation_evidence",
                "create_trusted_generation_verification",
                "_fetch_generation_attestations_with_deadline",
                "_request_metadata",
                "_bounded_request",
                "_validate_transport_provenance",
                "build_request",
                "_endpoint_request_cost_bound",
                "_seal_audit_model_refresh_pricing_control",
                "_ensure_request_size",
                "_store_debug",
                "_ensure_no_credential_in_value",
                "_validate_paid_privacy_policy",
            )
        ) or any(
            current is not trusted
            for current, trusted in (
                (OpenRouterClient.build_request, _TRUSTED_BUILD_REQUEST),
                (
                    OpenRouterClient._endpoint_request_cost_bound,
                    _TRUSTED_ENDPOINT_REQUEST_COST_BOUND,
                ),
                (
                    OpenRouterClient._seal_audit_model_refresh_pricing_control,
                    _TRUSTED_SEAL_AUDIT_MODEL_REFRESH_PRICING_CONTROL,
                ),
                (OpenRouterClient._ensure_request_size, _TRUSTED_ENSURE_REQUEST_SIZE),
                (OpenRouterClient._store_debug, _TRUSTED_STORE_DEBUG),
                (
                    OpenRouterClient._ensure_no_credential_in_value,
                    _TRUSTED_ENSURE_NO_CREDENTIAL_IN_VALUE,
                ),
                (
                    OpenRouterClient._validate_paid_privacy_policy,
                    _TRUSTED_VALIDATE_PAID_PRIVACY_POLICY,
                ),
            )
        ):
            raise OpenRouterPrivacyError("provider client callables changed after validation")
        binding = _lookup_trusted_transport_binding(self)
        if type(self) is not _TRUSTED_OPENROUTER_CLIENT_TYPE or binding is None:
            raise OpenRouterPrivacyError(
                "network-capable injected provider clients are not permitted"
            )
        try:
            current_client = object.__getattribute__(self, "_client")
            current_transport = object.__getattribute__(current_client, "_transport")
            current_budget = object.__getattribute__(self, "budget")
            current_ledger = object.__getattribute__(current_budget, "atomic_ledger")
            current_paid_controls = object.__getattribute__(
                self,
                "_requires_paid_controls",
            )
        except (AttributeError, TypeError) as exc:
            raise OpenRouterPrivacyError(
                "provider transport provenance changed after validation"
            ) from exc
        if type(current_budget) is not BudgetManager:
            raise OpenRouterPrivacyError("provider transport provenance changed after validation")
        if type(current_paid_controls) is not bool:
            raise OpenRouterPrivacyError("provider transport provenance changed after validation")
        if current_paid_controls:
            _require_exact_paid_budget_configuration(current_budget)
            if current_ledger is not None:
                _require_exact_atomic_ledger_configuration(current_ledger)
            try:
                _require_trusted_budget_accounting_state(current_budget)
            except BudgetReservationStateError as exc:
                raise OpenRouterPrivacyError(
                    "provider budget accounting state changed after validation"
                ) from exc
        current_model_caps = tuple(sorted(current_budget.per_model_usd_caps.items()))
        current_role_caps = tuple(sorted(current_budget.per_role_usd_caps.items()))
        if (
            current_client is not binding.http_client
            or current_transport is not binding.transport
            or str(current_client.base_url) != binding.base_url
            or current_budget is not binding.budget_manager
            or current_ledger is not binding.atomic_cost_ledger
            or current_paid_controls is not binding.paid_controls_required
            or current_budget.total_usd != binding.budget_total_usd
            or current_budget.max_output_tokens != binding.budget_max_output_tokens
            or current_budget.conservative_rate != binding.budget_conservative_rate
            or current_budget.max_requests_per_agent != binding.budget_max_requests_per_agent
            or current_budget.require_endpoint_cost_bound
            is not binding.budget_require_endpoint_cost_bound
            or current_budget.global_input_token_budget != binding.budget_global_input_token_budget
            or current_budget.global_output_token_budget
            != binding.budget_global_output_token_budget
            or current_model_caps != binding.budget_per_model_usd_caps
            or current_role_caps != binding.budget_per_role_usd_caps
            or current_budget._lock is not binding.budget_lock
            or current_budget._atomic_ledger_identity is not binding.atomic_cost_ledger
        ):
            raise OpenRouterPrivacyError("provider transport provenance changed after validation")
        try:
            _require_pristine_endpoint_cost_bound_types()
        except BudgetReservationStateError as exc:
            raise OpenRouterPrivacyError(
                "provider endpoint cost-bound callables changed after validation"
            ) from exc
        if (
            _provider_callable_descriptor_surface(BudgetManager)
            != _TRUSTED_BUDGET_MANAGER_DESCRIPTOR_SURFACE
            or any(
                name in vars(current_budget)
                for name, _descriptor in _TRUSTED_BUDGET_MANAGER_DESCRIPTOR_SURFACE
            )
            or any(
                name in vars(current_budget)
                for name in (
                    "reserve",
                    "reconcile",
                    "reconciled_cost_usd_exact",
                    "release",
                    "commit_active_reservation_for_transport",
                    "_current_atomic_ledger",
                )
            )
            or any(
                current is not trusted
                for current, trusted in (
                    (BudgetManager.reserve, _TRUSTED_BUDGET_RESERVE),
                    (BudgetManager.reconcile, _TRUSTED_BUDGET_RECONCILE),
                    (
                        BudgetManager.reconciled_cost_usd_exact,
                        _TRUSTED_BUDGET_RECONCILED_COST_USD_EXACT,
                    ),
                    (BudgetManager.release, _TRUSTED_BUDGET_RELEASE),
                    (
                        BudgetManager.commit_active_reservation_for_transport,
                        _TRUSTED_BUDGET_COMMIT_FOR_TRANSPORT,
                    ),
                    (
                        BudgetManager._current_atomic_ledger,
                        _TRUSTED_BUDGET_CURRENT_ATOMIC_LEDGER,
                    ),
                )
            )
        ):
            raise OpenRouterPrivacyError("provider budget callables changed after validation")
        if current_ledger is not None and (
            type(current_ledger) is not AtomicCostLedger
            or _provider_callable_descriptor_surface(AtomicCostLedger)
            != _TRUSTED_ATOMIC_LEDGER_DESCRIPTOR_SURFACE
            or any(
                name in vars(current_ledger)
                for name, _descriptor in _TRUSTED_ATOMIC_LEDGER_DESCRIPTOR_SURFACE
            )
            or any(
                name in vars(current_ledger)
                for name in (
                    "reserve",
                    "reconcile",
                    "release",
                    "active_reservation",
                    "snapshot",
                    "_locked",
                    "_required_state",
                    "_read_state",
                    "_write_state",
                )
            )
            or AtomicCostLedger.reserve is not _TRUSTED_ATOMIC_LEDGER_RESERVE
            or AtomicCostLedger.reconcile is not _TRUSTED_ATOMIC_LEDGER_RECONCILE
            or AtomicCostLedger.release is not _TRUSTED_ATOMIC_LEDGER_RELEASE
            or (
                AtomicCostLedger.active_reservation is not _TRUSTED_ATOMIC_LEDGER_ACTIVE_RESERVATION
            )
            or AtomicCostLedger.snapshot is not _TRUSTED_ATOMIC_LEDGER_SNAPSHOT
            or AtomicCostLedger._locked is not _TRUSTED_ATOMIC_LEDGER_LOCKED
            or AtomicCostLedger._required_state is not _TRUSTED_ATOMIC_LEDGER_REQUIRED_STATE
            or AtomicCostLedger._read_state is not _TRUSTED_ATOMIC_LEDGER_READ_STATE
            or AtomicCostLedger._write_state is not _TRUSTED_ATOMIC_LEDGER_WRITE_STATE
            or current_ledger.path is not binding.atomic_cost_ledger_path
            or current_ledger.lock_path is not binding.atomic_cost_ledger_lock_path
            or current_ledger.cap_usd is not binding.atomic_cost_ledger_cap_usd
            or current_ledger._thread_lock is not binding.atomic_cost_ledger_thread_lock
        ):
            raise OpenRouterPrivacyError("provider cost-ledger callables changed after validation")
        if (
            binding.execution_evidence is ExecutionEvidenceKind.REAL
            and not _owned_httpx_callables_are_pristine(current_client, current_transport)
        ):
            raise OpenRouterPrivacyError("owned provider callable provenance is invalid")
        if (
            binding.execution_evidence is ExecutionEvidenceKind.MOCK
            and not _mock_httpx_callables_are_pristine(
                current_client,
                current_transport,
                binding.mock_handler,
            )
        ):
            raise OpenRouterPrivacyError("test-only mock transport provenance is invalid")
        execution_evidence = trusted_openrouter_execution_evidence(self)
        if execution_evidence is ExecutionEvidenceKind.UNVERIFIED:
            raise OpenRouterPrivacyError("provider transport provenance changed after validation")
        return execution_evidence

    def build_request(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
        response_model: type[BaseModel],
        schema_name: str,
        context_package: ContextPackage | None = None,
        request_metadata: Mapping[str, str] | None = None,
        provider_policy: OpenRouterProviderPolicy | None = None,
        structured_output_mode: StructuredOutputMode | None = None,
        request_token_plan: RequestTokenPlan | None = None,
        request_role: str | None = None,
        response_schema_generation: _PydanticSchemaGeneration | None = None,
        refresh_pricing_control: _AuditModelRefreshPricingRequestControl | None = None,
    ) -> dict[str, Any]:
        _require_exact_model_id(model)
        effective_provider_policy = provider_policy or self.provider_policy
        effective_provider_policy = _canonical_provider_policy(effective_provider_policy)
        endpoint_policy = self._endpoint_pricing.get(model)
        selected_mode = structured_output_mode or (
            endpoint_policy.structured_output_mode
            if endpoint_policy is not None
            else StructuredOutputMode.NATIVE_JSON_SCHEMA
        )
        if (
            endpoint_policy is not None
            and selected_mode is not endpoint_policy.structured_output_mode
        ):
            raise OpenRouterProviderPolicyError(
                "requested structured-output mode differs from frozen endpoint capability"
            )
        if (
            request_token_plan is not None
            and request_role is not None
            and request_token_plan.role != request_role
        ):
            raise OpenRouterRequestLimitError(
                "explicit request role differs from its endpoint-bound token plan"
            )
        effective_request_role = (
            request_token_plan.role if request_token_plan is not None else request_role
        )
        request_plan = _structured_output_request_plan(
            mode=selected_mode,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            schema_name=schema_name,
            reasoning=self._reasoning_for_role(effective_request_role),
            schema_generation=response_schema_generation,
        )
        sealed_reasoning_plan = (
            request_token_plan.reasoning_plan if request_token_plan is not None else None
        )
        if self.reasoning_policy is not None:
            if effective_request_role is None or sealed_reasoning_plan is None:
                raise OpenRouterRequestLimitError(
                    "per-role reasoning requires its exact sealed request plan"
                )
            expected_resolution = resolve_reasoning_request_role(effective_request_role)
            expected_role_policy = self.reasoning_policy.role_policy(
                expected_resolution.configured_policy_role
            )
            if (
                sealed_reasoning_plan.resolution != expected_resolution
                or sealed_reasoning_plan.control_profile != expected_role_policy.control
                or sealed_reasoning_plan.policy_artifact_sha256
                != self.reasoning_policy.artifact_sha256
                or sealed_reasoning_plan.policy_role_binding_sha256
                != expected_role_policy.binding_sha256
            ):
                raise OpenRouterRequestLimitError(
                    "request token plan differs from the exact per-role reasoning policy"
                )
        elif sealed_reasoning_plan is not None:
            raise OpenRouterRequestLimitError(
                "sealed per-role reasoning plan has no active client policy"
            )
        if self._requires_real_audit_policy_selection(
            effective_request_role or "",
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            schema_name=schema_name,
            structured_output_mode=selected_mode,
            context_package=context_package,
        ) and (
            sealed_reasoning_plan is None
            or sealed_reasoning_plan.binding_state != "qualification_bound"
        ):
            raise OpenRouterQualificationError(
                "real post-qualification request shape lacks qualification-bound reasoning"
            )
        if endpoint_policy is not None:
            _require_matching_request_parameter_profile(
                endpoint_policy,
                request_plan,
                sealed_reasoning_plan=sealed_reasoning_plan,
            )
        if request_token_plan is not None:
            if (
                request_token_plan.route_intersection.exact_model_ids != (model,)
                or request_metadata is None
                or request_metadata.get("mmaudit_request_id") != request_token_plan.request_id
                or request_metadata.get("mmaudit_role") != request_token_plan.role
                or request_metadata.get("mmaudit_token_plan_sha256")
                != request_token_plan.plan_sha256
            ):
                raise OpenRouterRequestLimitError(
                    "request metadata differs from its endpoint-bound token plan"
                )
            reasoning_plan = request_token_plan.reasoning_plan
            if reasoning_plan is not None and (
                request_metadata.get("mmaudit_reasoning_plan_sha256")
                != reasoning_plan.evidence_sha256
                or request_metadata.get("mmaudit_reasoning_policy_sha256")
                != reasoning_plan.policy_artifact_sha256
                or request_metadata.get("mmaudit_reasoning_profile_sha256")
                != reasoning_plan.control_profile.profile_sha256
                or request_metadata.get("mmaudit_reasoning_capability_sha256")
                != reasoning_plan.endpoint_capability_sha256
                or request_metadata.get("mmaudit_reasoning_qualification_sha256")
                != reasoning_plan.qualification_binding_sha256
            ):
                raise OpenRouterRequestLimitError(
                    "request metadata differs from its sealed reasoning plan"
                )
            planned_endpoints = {
                endpoint.casefold()
                for endpoint in request_token_plan.route_intersection.provider_endpoints
            }
            configured_endpoints = {
                endpoint.casefold() for endpoint in effective_provider_policy.configured_endpoints
            }
            if (
                endpoint_policy is not None
                and configured_endpoints
                and planned_endpoints != configured_endpoints
            ):
                raise OpenRouterRequestLimitError(
                    "provider routes differ from the endpoint-bound token plan"
                )
        maximum_tokens = (
            request_token_plan.requested_completion_tokens
            if request_token_plan is not None
            else self.execution.max_output_tokens_per_request
        )
        routing_max_price: Mapping[str, float] | None = None
        if refresh_pricing_control is not None:
            if (
                refresh_pricing_control.exact_model_id != model
                or effective_provider_policy.configured_endpoints
                != (refresh_pricing_control.provider_endpoint,)
                or refresh_pricing_control.control_sha256
                != _canonical_sha256(
                    {
                        "exact_model_id": refresh_pricing_control.exact_model_id,
                        "provider_endpoint": refresh_pricing_control.provider_endpoint,
                        "current_endpoint_snapshot_sha256": (
                            refresh_pricing_control.current_endpoint_snapshot_sha256
                        ),
                        "qualified_pricing_snapshot_sha256": (
                            refresh_pricing_control.qualified_pricing_snapshot_sha256
                        ),
                        "current_pricing": refresh_pricing_control.current_pricing,
                        "current_pricing_sha256": (refresh_pricing_control.current_pricing_sha256),
                        "route_evidence_sha256": refresh_pricing_control.route_evidence_sha256,
                        "evidence_sha256": refresh_pricing_control.evidence_sha256,
                        "authority_capability_sha256": (
                            refresh_pricing_control.authority_capability_sha256
                        ),
                        "routing_max_price": refresh_pricing_control.routing_max_price,
                        "cost_bound_pricing": refresh_pricing_control.cost_bound_pricing,
                    }
                )
            ):
                raise OpenRouterModelRefreshPricingError(
                    "sealed refresh pricing control differs from the exact request route"
                )
            routing_max_price = dict(refresh_pricing_control.routing_max_price)
        elif endpoint_policy is not None:
            routing_max_price = dict(endpoint_policy.routing_max_price)
        return _assemble_structured_request_body(
            model=model,
            structured_output_plan=request_plan,
            provider_policy=effective_provider_policy,
            require_zdr=self.privacy.require_zdr,
            requested_completion_tokens=maximum_tokens,
            request_metadata=request_metadata or {},
            routing_max_price=routing_max_price,
        )

    def preview_candidate_review_task_resources(
        self,
        *,
        coverage_task: ModelSurfaceGapTask,
        scheduler_task: SchedulerTaskPlan,
        campaign_manifest: SchedulerCampaignManifest,
        context_package: ContextPackage,
        system_prompt: str,
        schema_name: str,
        checked_at: datetime,
    ) -> ModelSurfaceTaskResourcePreview:
        """Return a non-authorizing exact bound for one sealed blind-review task."""

        from mmaudit.models.coverage_planning import (
            ModelSurfaceGapTask,
            ModelSurfaceTaskResourcePreview,
        )
        from mmaudit.models.scheduler import (
            SchedulerCampaignManifest,
            SchedulerPassKind,
            SchedulerScopeKind,
            SchedulerTaskKind,
            SchedulerTaskPlan,
        )
        from mmaudit.models.schemas import ModelSurfaceReviewArtifact
        from mmaudit.orchestration.context import (
            ContextBoundaryError,
            render_context,
            revalidate_model_surface_context_package,
        )

        if (
            type(coverage_task) is not ModelSurfaceGapTask
            or type(scheduler_task) is not SchedulerTaskPlan
            or type(campaign_manifest) is not SchedulerCampaignManifest
            or type(context_package) is not ContextPackage
        ):
            raise OpenRouterCandidateReviewBoundaryError(
                "candidate-review resource preview requires exact typed task and context evidence"
            )
        if type(system_prompt) is not str or type(schema_name) is not str:
            raise OpenRouterCandidateReviewBoundaryError(
                "candidate-review resource preview prompt contract is invalid"
            )
        if type(checked_at) is not datetime:
            raise OpenRouterCandidateReviewBoundaryError(
                "candidate-review resource preview timestamp is invalid"
            )
        try:
            sealed_coverage_task = ModelSurfaceGapTask.model_validate_json(
                coverage_task.model_dump_json(),
                strict=True,
            )
            sealed_scheduler_task = SchedulerTaskPlan.model_validate_json(
                scheduler_task.model_dump_json(),
                strict=True,
            )
            sealed_campaign_manifest = SchedulerCampaignManifest.model_validate_json(
                campaign_manifest.model_dump_json(),
                strict=True,
            )
            sealed_context = revalidate_model_surface_context_package(context_package)
            preview_checked_at = _whole_second_utc(checked_at)
        except (AttributeError, ContextBoundaryError, TypeError, ValueError) as exc:
            raise OpenRouterCandidateReviewBoundaryError(
                "candidate-review resource preview evidence failed detached validation"
            ) from exc
        if (
            sealed_coverage_task != coverage_task
            or sealed_scheduler_task != scheduler_task
            or sealed_campaign_manifest != campaign_manifest
            or sealed_scheduler_task.campaign_id != sealed_campaign_manifest.campaign_id
            or sealed_scheduler_task.manifest_sha256 != sealed_campaign_manifest.manifest_sha256
            or sealed_scheduler_task.pass_id
            != sealed_campaign_manifest.pass_id(SchedulerPassKind.BLIND_SHARD_REVIEW)
            or sealed_scheduler_task.pass_kind is not SchedulerPassKind.BLIND_SHARD_REVIEW
            or sealed_scheduler_task.task_kind is not SchedulerTaskKind.MODEL_REQUEST
            or sealed_scheduler_task.scope.kind is not SchedulerScopeKind.SINGLE_SHARD
            or sealed_scheduler_task.scope.shard_ids != (sealed_coverage_task.scope_id,)
            or sealed_scheduler_task.task_key != sealed_coverage_task.task_id
            or sealed_scheduler_task.role != sealed_coverage_task.review_role
            or sealed_scheduler_task.requested_model != sealed_coverage_task.requested_model
            or sealed_scheduler_task.root_lineage != sealed_coverage_task.root_lineage
            or sealed_scheduler_task.candidate_ids != ()
            or sealed_coverage_task.scope_id not in sealed_campaign_manifest.shard_ids
        ):
            raise OpenRouterCandidateReviewBoundaryError(
                "coverage task differs from its exact blind scheduler task"
            )
        expected_input_recipe_sha256 = _canonical_sha256(
            {
                "domain": "mmaudit.scheduler.model-input-recipe.v1",
                "pass_kind": sealed_scheduler_task.pass_kind,
                "scope_sha256": sealed_scheduler_task.scope.scope_sha256,
                "task_key": sealed_scheduler_task.task_key,
                "role": sealed_scheduler_task.role,
            }
        )
        if sealed_scheduler_task.input_sha256 != expected_input_recipe_sha256:
            raise OpenRouterCandidateReviewBoundaryError(
                "scheduler task input recipe differs from the compact coverage task"
            )
        expected_prompt_recipe_sha256 = _canonical_sha256(
            {
                "domain": "mmaudit.scheduler.model-prompt-recipe.v1",
                "prompt_set_sha256": sealed_campaign_manifest.bindings.prompt_set_sha256,
                "task_key": sealed_scheduler_task.task_key,
                "role": sealed_scheduler_task.role,
            }
        )
        if sealed_scheduler_task.prompt_sha256 != expected_prompt_recipe_sha256:
            raise OpenRouterCandidateReviewBoundaryError(
                "scheduler task prompt recipe differs from the trusted campaign manifest"
            )
        context_surface_ids = tuple(
            request.surface_id for request in sealed_context.requested_model_surfaces
        )
        context_surface_manifest_sha256 = (
            ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(
                sealed_context.requested_model_surfaces
            )
        )
        if (
            sealed_context.role != sealed_coverage_task.review_role
            or context_surface_ids != sealed_coverage_task.surface_ids
            or context_surface_manifest_sha256
            != sealed_coverage_task.requested_surface_manifest_sha256
        ):
            raise OpenRouterCandidateReviewBoundaryError(
                "provider context differs from the exact compact coverage task"
            )
        if (
            not _candidate_review_protocol_boundary_is_pristine()
            or not _openrouter_client_callables_are_pristine()
        ):
            raise OpenRouterCandidateReviewBoundaryError(
                "candidate-review completion boundary changed before resource preview"
            )

        role = sealed_coverage_task.review_role
        model = sealed_coverage_task.requested_model
        user_prompt = render_context(sealed_context)
        response_model = _TRUSTED_CANDIDATE_REVIEW_FRAMED_DOCUMENT_TYPE
        response_schema_sha256 = _TRUSTED_CANDIDATE_REVIEW_WIRE_SCHEMA_SHA256()
        response_normalizer_sha256 = _canonical_sha256(
            {
                "domain": "mmaudit.scheduler.candidate-review-wire-normalizer.v1",
                "protocol": "CANDIDATE_REVIEW_NORMALIZATION_V1",
                "wire_schema_sha256": response_schema_sha256,
                "normalized_batch_schema_sha256": (_TRUSTED_CANDIDATE_REVIEW_BATCH_SCHEMA_SHA256()),
                "json_encoding": "sorted-keys,compact,ascii,no-nan",
                "control_frames_removed": True,
                "semantic_records_unchanged": True,
            }
        )
        if (
            sealed_scheduler_task.response_schema_sha256 != response_schema_sha256
            or sealed_scheduler_task.normalizer_sha256 != response_normalizer_sha256
        ):
            raise OpenRouterCandidateReviewBoundaryError(
                "scheduler task lacks the exact framed candidate-review contract"
            )

        maximum_attempts = self.execution.max_model_retries + 1
        if self.budget.max_requests_per_agent < maximum_attempts:
            raise OpenRouterRequestLimitError(
                "candidate-review retry attempts exceed the configured request limit"
            )
        request_id = _request_ids_for_routes(
            sealed_scheduler_task.logical_request_id,
            route_count=1,
            maximum_attempts=maximum_attempts,
        )[0]
        execution_evidence = trusted_openrouter_execution_evidence(self)
        if execution_evidence is ExecutionEvidenceKind.UNVERIFIED:
            raise OpenRouterPrivacyError(
                "network-capable injected provider clients are not permitted"
            )
        paid_controls_required = _trusted_paid_controls_required(self)
        _TRUSTED_VALIDATE_TRANSPORT_PROVENANCE(self)
        if paid_controls_required and self.budget.atomic_ledger is None:
            raise OpenRouterCostControlError(
                "real provider resource preview requires a durable atomic cost ledger"
            )
        if paid_controls_required and not self.budget.require_endpoint_cost_bound:
            raise OpenRouterCostControlError(
                "real provider resource preview requires endpoint-bound maximum cost proof"
            )
        if paid_controls_required and not self.privacy.require_zdr:
            self._validate_non_zdr_privacy_authorization((model,))
        if paid_controls_required and not self.provider_policy.configured_endpoints:
            raise OpenRouterProviderPolicyError(
                "real provider resource preview requires an explicit endpoint allowlist"
            )
        if model not in self._endpoint_pricing:
            raise OpenRouterCostControlError(
                "candidate-review resource preview lacks validated endpoint pricing"
            )
        if execution_evidence is ExecutionEvidenceKind.REAL:
            if (
                type(self) is not _TRUSTED_OPENROUTER_CLIENT_TYPE
                or not self._owns_client
                or not self._authentication_validated
            ):
                raise OpenRouterPrivacyError(
                    "real provider resource preview requires an authenticated owned client"
                )
            if model not in self._model_identities:
                raise OpenRouterModelError(
                    "real provider resource preview requires frozen model identity metadata"
                )

        response_schema_generation = _pydantic_schema_generation(response_model)
        endpoint_policy = self._endpoint_pricing.get(model)
        structured_output_mode = self._selected_structured_output_mode(model)
        pricing_required = _TRUSTED_REQUIRES_REAL_AUDIT_MODEL_REFRESH_PRICING(
            self,
            role,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            schema_name=schema_name,
            structured_output_mode=structured_output_mode,
            context_package=sealed_context,
        )
        qualification_binding = self._qualification_routing.get(model)
        if (
            self.provider_policy.certification
            and not _is_prequalification_provider_role(role)
            and qualification_binding is None
        ):
            raise OpenRouterQualificationError(
                "certification requires current qualification routing evidence"
            )
        if (
            self.provider_policy.certification
            and qualification_binding is None
            and len(self.provider_policy.configured_endpoints) != 1
        ):
            raise OpenRouterQualificationError(
                "unqualified certification roles require one exact provider endpoint"
            )
        if qualification_binding is not None:
            real_runtime_snapshots = execution_evidence is ExecutionEvidenceKind.REAL
            qualification_binding.require_current(
                role=role,
                model=model,
                provider_endpoints=self.provider_policy.configured_endpoints,
                now=preview_checked_at,
                endpoint_policy=(None if pricing_required else endpoint_policy),
                model_identity=self._model_identities.get(model),
                require_runtime_snapshots=(real_runtime_snapshots and not pricing_required),
            )
            if (
                pricing_required
                and real_runtime_snapshots
                and (endpoint_policy is None or self._model_identities.get(model) is None)
            ):
                raise OpenRouterQualificationError(
                    "refreshed-price routing requires current model and endpoint snapshots"
                )

        real_audit_required = _TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION(
            self,
            role,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            schema_name=schema_name,
            structured_output_mode=structured_output_mode,
            context_package=sealed_context,
        )
        reasoning_plan: ReasoningRequestPlanEvidence | None
        if real_audit_required:
            current_qualification_binding = self._require_real_postqualification_routing(
                role=role,
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                structured_output_mode=structured_output_mode,
                context_package=sealed_context,
                checked_at=preview_checked_at,
                require_runtime_snapshots=True,
                allow_refreshed_pricing=pricing_required,
            )
            if qualification_binding != current_qualification_binding:
                raise OpenRouterQualificationError(
                    "post-qualification routing authority changed before resource preview"
                )
            reasoning_plan = self._require_real_postqualification_reasoning_plan(
                role=role,
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                structured_output_mode=structured_output_mode,
                context_package=sealed_context,
                qualification_binding=current_qualification_binding,
            )
        else:
            reasoning_plan = self._reasoning_request_plan(
                role=role,
                model=model,
                qualification_binding=qualification_binding,
            )
        request_provider_policy = (
            qualification_binding.request_provider_policy()
            if qualification_binding is not None and self.provider_policy.certification
            else self.provider_policy
        )
        request_provider_policy = _canonical_provider_policy(request_provider_policy)
        audit_routing_evidence = (
            _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_SELECTION(
                self,
                role=role,
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                structured_output_mode=structured_output_mode,
                context_package=sealed_context,
                checked_at=preview_checked_at,
                qualification_binding=qualification_binding,
                provider_policy=request_provider_policy,
            )
            if real_audit_required
            else None
        )
        refresh_routing_evidence = (
            _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_REFRESH(
                self,
                role=role,
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                structured_output_mode=structured_output_mode,
                context_package=sealed_context,
                checked_at=preview_checked_at,
                qualification_binding=qualification_binding,
                audit_routing_evidence=audit_routing_evidence,
                provider_policy=request_provider_policy,
            )
            if _TRUSTED_REQUIRES_REAL_AUDIT_MODEL_REFRESH(
                self,
                role,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                structured_output_mode=structured_output_mode,
                context_package=sealed_context,
            )
            else None
        )
        refresh_pricing_routing_evidence = (
            _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_REFRESH_PRICING(
                self,
                role=role,
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                structured_output_mode=structured_output_mode,
                context_package=sealed_context,
                checked_at=preview_checked_at,
                qualification_binding=qualification_binding,
                audit_routing_evidence=audit_routing_evidence,
                refresh_routing_evidence=refresh_routing_evidence,
                provider_policy=request_provider_policy,
            )
            if pricing_required
            else None
        )
        refresh_pricing_control = (
            _TRUSTED_SEAL_AUDIT_MODEL_REFRESH_PRICING_CONTROL(
                self,
                refresh_pricing_routing_evidence,
            )
            if refresh_pricing_routing_evidence is not None
            else None
        )
        if paid_controls_required:
            _TRUSTED_VALIDATE_PAID_PRIVACY_POLICY(
                self,
                (model,),
                request_provider_endpoints=request_provider_policy.configured_endpoints,
            )

        structured_output_plan = _structured_output_request_plan(
            mode=structured_output_mode,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            schema_name=schema_name,
            reasoning=self._reasoning_for_role(role),
            schema_generation=response_schema_generation,
        )
        response_schema_generation.require_current(
            response_model,
            phase="during candidate-review resource preview planning",
        )
        prompt_hash = _structured_output_prompt_sha256_from_plan(structured_output_plan)
        system_prompt_hash = hashlib.sha256(
            structured_output_plan.system_prompt.encode("utf-8")
        ).hexdigest()
        user_prompt_hash = hashlib.sha256(user_prompt.encode("utf-8")).hexdigest()
        schema_hash = structured_output_plan.schema_sha256
        if (
            schema_hash != response_schema_sha256
            or sealed_scheduler_task.system_prompt_sha256 != system_prompt_hash
        ):
            raise OpenRouterCandidateReviewBoundaryError(
                "scheduler task differs from the exact framed provider request"
            )
        request_token_plan, context_request_evidence = self._request_token_plan(
            request_id=request_id,
            role=role,
            model=model,
            provider_policy=request_provider_policy,
            structured_output_plan=structured_output_plan,
            original_system_prompt=system_prompt,
            response_model=response_model,
            schema_name=schema_name,
            reasoning_plan=reasoning_plan,
            context_package=sealed_context,
        )
        response_schema_generation.require_current(
            response_model,
            phase="during candidate-review resource preview token planning",
        )

        request_metadata = {
            "mmaudit_request_id": request_id,
            "mmaudit_role": role,
            "mmaudit_prompt_sha256": prompt_hash,
            "mmaudit_user_prompt_sha256": user_prompt_hash,
            "mmaudit_schema_sha256": schema_hash,
            "mmaudit_output_mode": structured_output_mode.value,
            "mmaudit_output_request_shape_sha256": structured_output_plan.request_shape_sha256,
            "mmaudit_required_provider_parameters_sha256": _canonical_sha256(
                structured_output_plan.required_provider_parameters
            ),
            "mmaudit_token_plan_sha256": request_token_plan.plan_sha256,
        }
        if request_token_plan.reasoning_plan is not None:
            request_metadata.update(
                {
                    "mmaudit_reasoning_plan_sha256": (
                        request_token_plan.reasoning_plan.evidence_sha256
                    ),
                    "mmaudit_reasoning_policy_sha256": (
                        request_token_plan.reasoning_plan.policy_artifact_sha256
                    ),
                    "mmaudit_reasoning_profile_sha256": (
                        request_token_plan.reasoning_plan.control_profile.profile_sha256
                    ),
                }
            )
            if request_token_plan.reasoning_plan.endpoint_capability_sha256 is not None:
                request_metadata["mmaudit_reasoning_capability_sha256"] = (
                    request_token_plan.reasoning_plan.endpoint_capability_sha256
                )
            if request_token_plan.reasoning_plan.qualification_binding_sha256 is not None:
                request_metadata["mmaudit_reasoning_qualification_sha256"] = (
                    request_token_plan.reasoning_plan.qualification_binding_sha256
                )
        if context_request_evidence is not None:
            request_metadata["mmaudit_context_request_evidence_sha256"] = (
                context_request_evidence.evidence_sha256
            )
        if structured_output_plan.strict_protocol_sha256 is not None:
            request_metadata["mmaudit_output_protocol_sha256"] = (
                structured_output_plan.strict_protocol_sha256
            )
        if endpoint_policy is not None:
            request_metadata["mmaudit_endpoint_snapshot_sha256"] = endpoint_policy.snapshot_sha256
            request_metadata["mmaudit_endpoint_pricing_sha256"] = (
                endpoint_policy.policy_pricing_sha256
            )
            request_metadata["mmaudit_output_capability_sha256"] = (
                endpoint_policy.output_capability_sha256
            )
        model_identity = self._model_identities.get(model)
        if model_identity is not None:
            request_metadata["mmaudit_identity_snapshot_sha256"] = (
                model_identity.snapshot.snapshot_sha256
            )
        if qualification_binding is not None:
            request_metadata.update(qualification_binding.request_metadata())
        if audit_routing_evidence is not None:
            request_metadata.update(
                {
                    f"mmaudit_policy_{key}": value
                    for key, value in audit_routing_evidence.request_metadata().items()
                }
            )
            assert self._audit_model_selection is not None
            request_metadata["mmaudit_policy_selection_capability_sha256"] = (
                self._audit_model_selection.capability_sha256
            )
        request_metadata.update(
            self._audit_model_refresh_request_metadata(refresh_routing_evidence)
        )
        request_metadata.update(
            self._audit_model_refresh_pricing_request_metadata(refresh_pricing_routing_evidence)
        )
        body = _TRUSTED_BUILD_REQUEST(
            self,
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            schema_name=schema_name,
            context_package=sealed_context,
            request_metadata=request_metadata,
            provider_policy=request_provider_policy,
            structured_output_mode=structured_output_mode,
            request_token_plan=request_token_plan,
            request_role=role,
            response_schema_generation=response_schema_generation,
            refresh_pricing_control=refresh_pricing_control,
        )
        _TRUSTED_ENSURE_REQUEST_SIZE(self, body)
        request_body_hash = _require_exact_openrouter_request_body(
            body,
            model=model,
            structured_output_plan=structured_output_plan,
            provider_policy=request_provider_policy,
            require_zdr=self.privacy.require_zdr,
            request_token_plan=request_token_plan,
            request_metadata=request_metadata,
            endpoint_policy=endpoint_policy,
            refresh_pricing_control=refresh_pricing_control,
        )
        response_schema_generation.require_current(
            response_model,
            phase="during candidate-review resource preview request hashing",
        )
        request_material = _TRUSTED_CANDIDATE_REVIEW_CANONICAL_JSON_DUMPS(body)
        (
            request_token_plan_projection_sha256,
            request_material_projection,
            request_material_projection_sha256,
        ) = _TRUSTED_CANDIDATE_REVIEW_REQUEST_MATERIAL_PROJECTION(
            body,
            request_token_plan=request_token_plan,
        )
        endpoint_cost_bound = _TRUSTED_ENDPOINT_REQUEST_COST_BOUND(
            self,
            model=model,
            request_material=request_material,
            request_token_plan=request_token_plan,
            refresh_pricing_control=refresh_pricing_control,
        )
        if endpoint_cost_bound is None:
            raise OpenRouterCostControlError(
                "candidate-review resource preview requires endpoint-bound maximum cost proof"
            )
        if context_request_evidence is None or endpoint_policy is None:
            raise OpenRouterCandidateReviewBoundaryError(
                "candidate-review resource preview lacks exact context or endpoint evidence"
            )
        if refresh_pricing_control is not None:
            provider_request = body.get("provider")
            bound_components = {
                component.pricing_field: component.unit_price_usd
                for component in endpoint_cost_bound.components
            }
            expected_bound_components = {
                field: Decimal(value) for field, value in refresh_pricing_control.cost_bound_pricing
            }
            if (
                not isinstance(provider_request, dict)
                or provider_request.get("max_price")
                != dict(refresh_pricing_control.routing_max_price)
                or endpoint_cost_bound.exact_model_id != refresh_pricing_control.exact_model_id
                or endpoint_cost_bound.provider_endpoint
                != refresh_pricing_control.provider_endpoint
                or endpoint_cost_bound.request_material_sha256 != request_body_hash
                or bound_components != expected_bound_components
            ):
                raise OpenRouterModelRefreshPricingError(
                    "resource preview differs from sealed refreshed pricing"
                )
        maximum_cost_text = format(
            _trusted_endpoint_request_maximum_cost_usd(endpoint_cost_bound),
            "f",
        )
        if "." in maximum_cost_text:
            maximum_cost_text = maximum_cost_text.rstrip("0").rstrip(".")
        return ModelSurfaceTaskResourcePreview.build(
            task=sealed_coverage_task,
            scheduler_task_id=sealed_scheduler_task.task_id,
            scheduler_task_plan_sha256=sealed_scheduler_task.task_plan_sha256,
            campaign_manifest_sha256=sealed_campaign_manifest.manifest_sha256,
            rendered_context_sha256=context_request_evidence.rendered_sha256,
            context_request_evidence_sha256=context_request_evidence.evidence_sha256,
            request_token_plan_projection_sha256=(request_token_plan_projection_sha256),
            request_material_projection_sha256=request_material_projection_sha256,
            request_material_projection_utf8_bytes=len(request_material_projection.encode("utf-8")),
            endpoint_policy_snapshot_sha256=endpoint_policy.snapshot_sha256,
            endpoint_policy_pricing_sha256=endpoint_policy.policy_pricing_sha256,
            provider_endpoint=endpoint_cost_bound.provider_endpoint,
            endpoint_pricing_snapshot_sha256=endpoint_cost_bound.pricing_snapshot_sha256,
            endpoint_cost_bound_projection_sha256=(
                _TRUSTED_ENDPOINT_REQUEST_COST_BOUND_PROJECTION_SHA256(
                    endpoint_cost_bound,
                    request_material_projection_sha256=(request_material_projection_sha256),
                )
            ),
            maximum_attempts=maximum_attempts,
            maximum_prompt_tokens_per_attempt=(request_token_plan.prompt_byte_upper_bound_tokens),
            maximum_completion_tokens_per_attempt=(request_token_plan.requested_completion_tokens),
            maximum_cost_usd_per_attempt_exact=maximum_cost_text or "0",
        )

    def preview_structured_request_hashes(
        self,
        *,
        role: str,
        model: str,
        system_prompt: str,
        user_prompt: str,
        response_model: type[BaseModel],
        schema_name: str,
    ) -> StructuredRequestHashes:
        """Commit the exact primary-route messages and schema before transport."""

        _require_exact_model_id(model)
        endpoint_policy = self._endpoint_pricing.get(model)
        mode = (
            endpoint_policy.structured_output_mode
            if endpoint_policy is not None
            else StructuredOutputMode.NATIVE_JSON_SCHEMA
        )
        plan = _structured_output_request_plan(
            mode=mode,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            schema_name=schema_name,
            reasoning=self._reasoning_for_role(role),
        )
        return StructuredRequestHashes(
            prompt_sha256=_structured_output_prompt_sha256_from_plan(plan),
            system_prompt_sha256=hashlib.sha256(plan.system_prompt.encode("utf-8")).hexdigest(),
            user_prompt_sha256=hashlib.sha256(user_prompt.encode("utf-8")).hexdigest(),
            schema_sha256=plan.schema_sha256,
        )

    async def complete(
        self,
        *,
        role: str,
        models: list[str],
        system_prompt: str,
        user_prompt: str,
        context_package: ContextPackage | None = None,
        response_model: type[ResponseT],
        schema_name: str,
        logical_request_id: str | None = None,
        expected_request_cost_preview: OpenRouterStructuredRequestCostPreview | None = None,
    ) -> ResponseT:
        """Compatibility wrapper returning only the validated structured value."""

        completion = await self.complete_with_evidence(
            role=role,
            models=models,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            context_package=context_package,
            response_model=response_model,
            schema_name=schema_name,
            logical_request_id=logical_request_id,
            expected_request_cost_preview=expected_request_cost_preview,
        )
        if _is_concluded_unbound_completion(completion):
            raise OpenRouterUnboundIdentityError(completion)
        if _is_repaired_noncreditable_completion(completion):
            raise OpenRouterSchemaError(
                "syntax-repaired structured output is retained without review credit"
            )
        return completion.value

    async def complete_candidate_review_with_evidence(
        self,
        *,
        role: str,
        models: list[str],
        system_prompt: str,
        user_prompt: str,
        context_package: ContextPackage | None = None,
        schema_name: str,
        logical_request_id: str | None = None,
        single_route_single_attempt: bool = False,
        expected_resource_preview: ModelSurfaceTaskResourcePreview | None = None,
        coverage_task: ModelSurfaceGapTask | None = None,
        scheduler_task: SchedulerTaskPlan | None = None,
        campaign_manifest: SchedulerCampaignManifest | None = None,
        resource_preview_checked_at: datetime | None = None,
    ) -> CandidateReviewCompletion:
        """Request the framed wire protocol and return an explicitly normalized review."""

        instance_state = vars(self)
        if (
            type(single_route_single_attempt) is not bool
            or not _candidate_review_protocol_boundary_is_pristine()
            or not _openrouter_client_callables_are_pristine()
            or any(
                name in instance_state
                for name in (
                    "complete_candidate_review_with_evidence",
                    "complete_with_evidence",
                    "_complete_one",
                    "_failure_routing_evidence",
                )
            )
        ):
            raise OpenRouterCandidateReviewBoundaryError(
                "candidate-review completion boundary changed before provider transport"
            )
        if single_route_single_attempt and len(models) != 1:
            raise OpenRouterRequestLimitError(
                "single-attempt candidate review requires one exact model route"
            )
        preview_coordinates = (
            expected_resource_preview,
            coverage_task,
            scheduler_task,
            campaign_manifest,
            resource_preview_checked_at,
        )
        coordinate_count = sum(value is not None for value in preview_coordinates)
        if coordinate_count not in {0, len(preview_coordinates)}:
            raise OpenRouterCandidateReviewBoundaryError(
                "candidate-review resource preview coordinates must be supplied together"
            )
        sealed_expected_resource_preview: ModelSurfaceTaskResourcePreview | None = None
        if coordinate_count:
            from mmaudit.models.coverage_planning import (
                ModelSurfaceGapTask,
                ModelSurfaceTaskResourcePreview,
            )
            from mmaudit.models.scheduler import SchedulerCampaignManifest, SchedulerTaskPlan
            from mmaudit.orchestration.context import (
                ContextBoundaryError,
                render_context,
                revalidate_model_surface_context_package,
            )

            if (
                type(expected_resource_preview) is not ModelSurfaceTaskResourcePreview
                or type(coverage_task) is not ModelSurfaceGapTask
                or type(scheduler_task) is not SchedulerTaskPlan
                or type(campaign_manifest) is not SchedulerCampaignManifest
                or type(resource_preview_checked_at) is not datetime
                or type(context_package) is not ContextPackage
                or type(models) is not list
                or any(type(model) is not str for model in models)
                or type(role) is not str
                or type(system_prompt) is not str
                or type(user_prompt) is not str
                or type(schema_name) is not str
                or type(logical_request_id) is not str
                or single_route_single_attempt
            ):
                raise OpenRouterCandidateReviewBoundaryError(
                    "candidate-review dispatch requires exact full-retry preview evidence"
                )
            assert expected_resource_preview is not None
            assert coverage_task is not None
            assert scheduler_task is not None
            assert campaign_manifest is not None
            assert resource_preview_checked_at is not None
            assert context_package is not None
            try:
                sealed_expected_resource_preview = (
                    ModelSurfaceTaskResourcePreview.model_validate_json(
                        expected_resource_preview.model_dump_json(),
                        strict=True,
                    )
                )
                sealed_context = revalidate_model_surface_context_package(context_package)
                rendered_context = render_context(sealed_context)
            except (AttributeError, ContextBoundaryError, TypeError, ValueError) as exc:
                raise OpenRouterCandidateReviewBoundaryError(
                    "candidate-review dispatch preview evidence failed detached validation"
                ) from exc
            if (
                sealed_expected_resource_preview != expected_resource_preview
                or role != coverage_task.review_role
                or models != [coverage_task.requested_model]
                or logical_request_id != scheduler_task.logical_request_id
                or user_prompt != rendered_context
            ):
                raise OpenRouterCandidateReviewBoundaryError(
                    "candidate-review dispatch differs from its exact preview coordinates"
                )
            recomputed_preview = _TRUSTED_PREVIEW_CANDIDATE_REVIEW_TASK_RESOURCES(
                self,
                coverage_task=coverage_task,
                scheduler_task=scheduler_task,
                campaign_manifest=campaign_manifest,
                context_package=sealed_context,
                system_prompt=system_prompt,
                schema_name=schema_name,
                checked_at=resource_preview_checked_at,
            )
            if recomputed_preview != sealed_expected_resource_preview:
                raise OpenRouterCandidateReviewBoundaryError(
                    "candidate-review request resources changed after aggregate preflight"
                )
            context_package = sealed_context
            user_prompt = rendered_context
        sanitized_truncation: OpenRouterTruncatedResponseError | None = None
        try:
            completion = await _TRUSTED_COMPLETE_WITH_EVIDENCE(
                self,
                role=role,
                models=models,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                context_package=context_package,
                response_model=_TRUSTED_CANDIDATE_REVIEW_FRAMED_DOCUMENT_TYPE,
                schema_name=schema_name,
                logical_request_id=logical_request_id,
                _maximum_attempts=(1 if single_route_single_attempt else None),
                _expected_resource_preview=sealed_expected_resource_preview,
            )
        except OpenRouterTruncatedResponseError as error:
            if type(error) is not OpenRouterTruncatedResponseError:
                raise OpenRouterCandidateReviewBoundaryError(
                    "candidate-review truncation error has an invalid exact type"
                ) from None
            error.__traceback__ = None
            error.__context__ = None
            error.__cause__ = None
            sanitized_truncation = error
        if sanitized_truncation is not None:
            raise sanitized_truncation from None
        if (
            not _candidate_review_protocol_boundary_is_pristine()
            or type(completion.value) is not _TRUSTED_CANDIDATE_REVIEW_FRAMED_DOCUMENT_TYPE
        ):
            raise OpenRouterCandidateReviewBoundaryError(
                "candidate-review completion boundary changed after provider transport"
            )
        try:
            batch, normalization_evidence = _TRUSTED_NORMALIZE_CANDIDATE_REVIEW_DOCUMENT(
                completion.value,
                request_id=completion.usage_record.request_id,
            )
            return CandidateReviewCompletion(
                value=batch,
                usage_record=completion.usage_record,
                normalization_evidence=normalization_evidence,
            )
        except CandidateReviewTruncationError:
            if not _candidate_review_protocol_boundary_is_pristine():
                raise OpenRouterCandidateReviewBoundaryError(
                    "candidate-review normalization boundary changed after provider transport"
                ) from None
            raise OpenRouterSchemaError(
                "complete candidate-review wire response could not be normalized"
            ) from None

    def _claim_request_ids(self, request_ids: Sequence[str]) -> None:
        """Claim route identities once so retries and resumed work cannot alias evidence."""

        with self._request_identity_lock:
            if len(set(request_ids)) != len(request_ids) or any(
                request_id in self._claimed_request_ids for request_id in request_ids
            ):
                raise OpenRouterRequestLimitError(
                    "logical request identity was already claimed by this provider client"
                )
            self._claimed_request_ids.update(request_ids)

    async def complete_with_evidence(
        self,
        *,
        role: str,
        models: list[str],
        system_prompt: str,
        user_prompt: str,
        context_package: ContextPackage | None = None,
        response_model: type[ResponseT],
        schema_name: str,
        logical_request_id: str | None = None,
        expected_request_cost_preview: OpenRouterStructuredRequestCostPreview | None = None,
        _maximum_attempts: int | None = None,
        _expected_resource_preview: ModelSurfaceTaskResourcePreview | None = None,
    ) -> StructuredCompletion[ResponseT]:
        """Call only the explicitly supplied models, in order."""

        if expected_request_cost_preview is not None and _expected_resource_preview is not None:
            raise OpenRouterRequestCostPreviewError(
                "provider dispatch cannot combine independent request-resource previews"
            )
        if expected_request_cost_preview is not None:
            if (
                type(expected_request_cost_preview) is not OpenRouterStructuredRequestCostPreview
                or type(models) is not list
                or len(models) != 1
                or type(role) is not str
                or type(logical_request_id) is not str
                or self.token_budgets is None
            ):
                raise OpenRouterRequestCostPreviewError(
                    "exact request-cost preview requires one deterministic provider route"
                )
            try:
                sealed_expected_cost_preview = (
                    OpenRouterStructuredRequestCostPreview.model_validate_json(
                        expected_request_cost_preview.model_dump_json(),
                        strict=True,
                    )
                )
            except (AttributeError, TypeError, ValueError) as exc:
                raise OpenRouterRequestCostPreviewError(
                    "request-cost preview failed detached validation"
                ) from exc
            if (
                sealed_expected_cost_preview != expected_request_cost_preview
                or logical_request_id != sealed_expected_cost_preview.logical_request_id
                or role != sealed_expected_cost_preview.role
                or models != [sealed_expected_cost_preview.exact_model_id]
            ):
                raise OpenRouterRequestCostPreviewError(
                    "provider dispatch coordinates differ from the exact request-cost preview"
                )
            expected_request_cost_preview = sealed_expected_cost_preview
        if _expected_resource_preview is not None:
            from mmaudit.models.coverage_planning import ModelSurfaceTaskResourcePreview

            if (
                type(_expected_resource_preview) is not ModelSurfaceTaskResourcePreview
                or response_model is not _TRUSTED_CANDIDATE_REVIEW_FRAMED_DOCUMENT_TYPE
                or len(models) != 1
                or _maximum_attempts is not None
            ):
                raise OpenRouterCandidateReviewBoundaryError(
                    "exact resource previews are restricted to one full-retry candidate review"
                )
            try:
                sealed_expected_resource_preview = (
                    ModelSurfaceTaskResourcePreview.model_validate_json(
                        _expected_resource_preview.model_dump_json(),
                        strict=True,
                    )
                )
            except (AttributeError, TypeError, ValueError) as exc:
                raise OpenRouterCandidateReviewBoundaryError(
                    "candidate-review resource preview failed detached validation"
                ) from exc
            if sealed_expected_resource_preview != _expected_resource_preview:
                raise OpenRouterCandidateReviewBoundaryError(
                    "candidate-review resource preview changed across its boundary"
                )
            _expected_resource_preview = sealed_expected_resource_preview
        if not models:
            raise OpenRouterModelError(f"no model configured for role {role}")
        configured_attempts = self.execution.max_model_retries + 1
        maximum_attempts = configured_attempts if _maximum_attempts is None else _maximum_attempts
        if type(maximum_attempts) is not int or not 1 <= maximum_attempts <= configured_attempts:
            raise OpenRouterRequestLimitError(
                "model attempt override must only tighten the configured retry bound"
            )
        if (
            expected_request_cost_preview is not None
            and maximum_attempts != expected_request_cost_preview.maximum_attempts
        ):
            raise OpenRouterRequestCostPreviewError(
                "provider retry bound differs from the exact request-cost preview"
            )
        for model in models:
            _require_exact_model_id(model)
        if self.provider_policy.certification and len(models) != 1:
            raise OpenRouterModelError(
                "certification requires exactly one explicitly qualified model"
            )
        request_ids = _request_ids_for_routes(
            logical_request_id,
            route_count=len(models),
            maximum_attempts=maximum_attempts,
        )
        checked_at = datetime.now(UTC)
        qualification_bound_reasoning_plans: dict[
            str,
            ReasoningRequestPlanEvidence,
        ] = {}
        requested_output_modes = {self._selected_structured_output_mode(model) for model in models}
        prequalification_output_mode = (
            next(iter(requested_output_modes)) if len(requested_output_modes) == 1 else None
        )
        if _TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION(
            self,
            role,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            schema_name=schema_name,
            structured_output_mode=prequalification_output_mode,
            context_package=context_package,
        ):
            if self.reasoning is not None:
                raise OpenRouterQualificationError(
                    "real post-qualification certification rejects legacy global reasoning"
                )
            if self.reasoning_policy is None:
                raise OpenRouterQualificationError(
                    "real post-qualification certification requires a sealed per-role "
                    "reasoning policy"
                )
            for model in models:
                preflight_binding = self._require_real_postqualification_routing(
                    role=role,
                    model=model,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_model=response_model,
                    schema_name=schema_name,
                    structured_output_mode=self._selected_structured_output_mode(model),
                    context_package=context_package,
                    checked_at=checked_at,
                    require_runtime_snapshots=False,
                )
                qualification_bound_reasoning_plans[model] = (
                    self._require_real_postqualification_reasoning_plan(
                        role=role,
                        model=model,
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        response_model=response_model,
                        schema_name=schema_name,
                        structured_output_mode=self._selected_structured_output_mode(model),
                        context_package=context_package,
                        qualification_binding=preflight_binding,
                    )
                )
        self._reasoning_for_role(role)
        if len(self._unbound_completions) >= _MAX_RETAINED_UNBOUND_COMPLETIONS:
            raise OpenRouterRequestLimitError(
                "unbound evidence retention is full; inspect and clear it before retrying"
            )
        if trusted_openrouter_execution_evidence(self) is ExecutionEvidenceKind.UNVERIFIED:
            raise OpenRouterPrivacyError(
                "network-capable injected provider clients are not permitted"
            )
        paid_controls_required = _trusted_paid_controls_required(self)
        _TRUSTED_VALIDATE_TRANSPORT_PROVENANCE(self)
        if paid_controls_required and self.budget.atomic_ledger is None:
            raise OpenRouterCostControlError(
                "real provider completions require a durable atomic cost ledger"
            )
        if paid_controls_required and not self.budget.require_endpoint_cost_bound:
            raise OpenRouterCostControlError(
                "real provider completions require endpoint-bound maximum cost proof"
            )
        if paid_controls_required and not self.privacy.require_zdr:
            self._validate_non_zdr_privacy_authorization(models)
        if paid_controls_required and not self.provider_policy.configured_endpoints:
            raise OpenRouterProviderPolicyError(
                "real provider completions require an explicit provider endpoint allowlist"
            )
        if paid_controls_required:
            unbound_models = [model for model in models if model not in self._endpoint_pricing]
            if unbound_models:
                raise OpenRouterCostControlError(
                    "real provider completion lacks validated endpoint pricing"
                )
        if trusted_openrouter_execution_evidence(self) is ExecutionEvidenceKind.REAL:
            if (
                type(self) is not _TRUSTED_OPENROUTER_CLIENT_TYPE
                or not self._owns_client
                or not self._authentication_validated
            ):
                raise OpenRouterPrivacyError(
                    "real provider completion requires an authenticated owned provider client"
                )
            missing_identities = [model for model in models if model not in self._model_identities]
            if missing_identities:
                raise OpenRouterModelError(
                    "real provider completion requires frozen model identity metadata"
                )
        qualification_bindings: dict[str, OpenRouterQualificationRoutingEvidence | None] = {}
        audit_routing_bindings: dict[str, AuditModelRoutingEvidence | None] = {}
        refresh_routing_bindings: dict[str, AuditModelRefreshRouteEvidence | None] = {}
        refresh_pricing_routing_bindings: dict[
            str,
            AuditModelRefreshPricingRouteEvidence | None,
        ] = {}
        refresh_pricing_controls: dict[
            str,
            _AuditModelRefreshPricingRequestControl | None,
        ] = {}
        for model_index, model in enumerate(models):
            binding = self._qualification_routing.get(model)
            pricing_required = _TRUSTED_REQUIRES_REAL_AUDIT_MODEL_REFRESH_PRICING(
                self,
                role,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                structured_output_mode=self._selected_structured_output_mode(model),
                context_package=context_package,
            )
            if (
                self.provider_policy.certification
                and not _is_prequalification_provider_role(role)
                and binding is None
            ):
                raise OpenRouterQualificationError(
                    "certification requires current qualification routing evidence"
                )
            if (
                self.provider_policy.certification
                and binding is None
                and len(self.provider_policy.configured_endpoints) != 1
            ):
                raise OpenRouterQualificationError(
                    "unqualified certification roles require one exact provider endpoint"
                )
            if binding is not None:
                real_runtime_snapshots = (
                    trusted_openrouter_execution_evidence(self) is ExecutionEvidenceKind.REAL
                )
                binding.require_current(
                    role=role,
                    model=model,
                    provider_endpoints=self.provider_policy.configured_endpoints,
                    now=checked_at,
                    endpoint_policy=(
                        None if pricing_required else self._endpoint_pricing.get(model)
                    ),
                    model_identity=self._model_identities.get(model),
                    require_runtime_snapshots=(real_runtime_snapshots and not pricing_required),
                )
                if (
                    pricing_required
                    and real_runtime_snapshots
                    and (
                        self._endpoint_pricing.get(model) is None
                        or self._model_identities.get(model) is None
                    )
                ):
                    raise OpenRouterQualificationError(
                        "refreshed-price routing requires current model and endpoint snapshots"
                    )
            qualification_bindings[model] = binding
            audit_routing_evidence: AuditModelRoutingEvidence | None = None
            refresh_routing_evidence: AuditModelRefreshRouteEvidence | None = None
            refresh_pricing_routing_evidence: AuditModelRefreshPricingRouteEvidence | None = None
            try:
                audit_routing_evidence = (
                    _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_SELECTION(
                        self,
                        role=role,
                        model=model,
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        response_model=response_model,
                        schema_name=schema_name,
                        structured_output_mode=self._selected_structured_output_mode(model),
                        context_package=context_package,
                        checked_at=checked_at,
                        qualification_binding=binding,
                        provider_policy=(
                            binding.request_provider_policy()
                            if binding is not None and self.provider_policy.certification
                            else self.provider_policy
                        ),
                    )
                    if _TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION(
                        self,
                        role,
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        response_model=response_model,
                        schema_name=schema_name,
                        structured_output_mode=self._selected_structured_output_mode(model),
                        context_package=context_package,
                    )
                    else None
                )
                if _TRUSTED_REQUIRES_REAL_AUDIT_MODEL_REFRESH(
                    self,
                    role,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_model=response_model,
                    schema_name=schema_name,
                    structured_output_mode=self._selected_structured_output_mode(model),
                    context_package=context_package,
                ):
                    refresh_routing_evidence = _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_REFRESH(
                        self,
                        role=role,
                        model=model,
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        response_model=response_model,
                        schema_name=schema_name,
                        structured_output_mode=self._selected_structured_output_mode(model),
                        context_package=context_package,
                        checked_at=checked_at,
                        qualification_binding=binding,
                        audit_routing_evidence=audit_routing_evidence,
                        provider_policy=(
                            binding.request_provider_policy()
                            if binding is not None and self.provider_policy.certification
                            else self.provider_policy
                        ),
                    )
                if pricing_required:
                    refresh_pricing_routing_evidence = (
                        _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_REFRESH_PRICING(
                            self,
                            role=role,
                            model=model,
                            system_prompt=system_prompt,
                            user_prompt=user_prompt,
                            response_model=response_model,
                            schema_name=schema_name,
                            structured_output_mode=self._selected_structured_output_mode(model),
                            context_package=context_package,
                            checked_at=checked_at,
                            qualification_binding=binding,
                            audit_routing_evidence=audit_routing_evidence,
                            refresh_routing_evidence=refresh_routing_evidence,
                            provider_policy=(
                                binding.request_provider_policy()
                                if binding is not None and self.provider_policy.certification
                                else self.provider_policy
                            ),
                        )
                    )
            except OpenRouterPolicyEligibilityError as exc:
                diagnostic_provider_policy = (
                    binding.request_provider_policy()
                    if binding is not None and self.provider_policy.certification
                    else self.provider_policy
                )
                planning_snapshot = self._diagnostic_planning_snapshot(
                    request_id=request_ids[model_index],
                    role=role,
                    model=model,
                    reason=ContextPreflightReason.ROUTE_UNAVAILABLE,
                    provider_policy=diagnostic_provider_policy,
                    structured_output_plan=None,
                    original_system_prompt=system_prompt,
                    response_model=response_model,
                    schema_name=schema_name,
                    context_package=context_package,
                )
                self._record_context_preflight(
                    request_id=request_ids[model_index],
                    logical_request_id=request_ids[model_index],
                    role=role,
                    model=model,
                    requested_completion_tokens=(
                        self._required_output_tokens()
                        + self._reserved_reasoning_tokens(
                            self._required_output_tokens(),
                            role=role,
                        )
                    ),
                    request_plan=None,
                    planning_snapshot=planning_snapshot,
                    decision_source=ContextPreflightSource.TOKEN_PLANNER,
                    reason=ContextPreflightReason.ROUTE_UNAVAILABLE,
                    error=exc,
                    decision_evidence_sha256s=self._audit_policy_decision_evidence_sha256s(
                        audit_routing_evidence,
                        refresh_routing_evidence=refresh_routing_evidence,
                    ),
                )
                raise
            audit_routing_bindings[model] = audit_routing_evidence
            refresh_routing_bindings[model] = refresh_routing_evidence
            refresh_pricing_routing_bindings[model] = refresh_pricing_routing_evidence
            refresh_pricing_controls[model] = (
                _TRUSTED_SEAL_AUDIT_MODEL_REFRESH_PRICING_CONTROL(
                    self,
                    refresh_pricing_routing_evidence,
                )
                if refresh_pricing_routing_evidence is not None
                else None
            )
        self._claim_request_ids(request_ids)
        last_error: OpenRouterError | None = None
        for index, model in enumerate(models):
            try:
                complete_one = (
                    _TRUSTED_COMPLETE_ONE.__get__(
                        self,
                        _TRUSTED_OPENROUTER_CLIENT_TYPE,
                    )
                    if response_model is _TRUSTED_CANDIDATE_REVIEW_FRAMED_DOCUMENT_TYPE
                    else self._complete_one
                )
                completion = await complete_one(
                    request_id=request_ids[index],
                    role=role,
                    model=model,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    context_package=context_package,
                    response_model=response_model,
                    schema_name=schema_name,
                    fallback_used=index > 0,
                    qualification_binding=qualification_bindings[model],
                    audit_routing_evidence=audit_routing_bindings[model],
                    refresh_routing_evidence=refresh_routing_bindings[model],
                    refresh_pricing_routing_evidence=(refresh_pricing_routing_bindings[model]),
                    refresh_pricing_control=refresh_pricing_controls[model],
                    qualification_bound_reasoning_plan=(
                        qualification_bound_reasoning_plans.get(model)
                    ),
                    maximum_attempts=maximum_attempts,
                    expected_resource_preview=_expected_resource_preview,
                    expected_request_cost_preview=expected_request_cost_preview,
                )
            except (
                OpenRouterTransientError,
                OpenRouterModelError,
                OpenRouterSchemaError,
            ) as exc:
                last_error = exc
                if response_model is _TRUSTED_CANDIDATE_REVIEW_FRAMED_DOCUMENT_TYPE and isinstance(
                    exc,
                    OpenRouterTruncatedResponseError | OpenRouterCandidateReviewBoundaryError,
                ):
                    # A confirmed framed prefix is scheduler input, never a signal to spend on
                    # an implicit model retry/fallback inside this logical request.
                    raise
                self.logger.warning(
                    "Configured model failed; considering the next explicit fallback",
                    extra={"role": role, "status": "fallback"},
                )
                continue
            if _is_repaired_noncreditable_completion(completion):
                self.logger.warning(
                    "Syntax-repaired response retained without review credit",
                    extra={"role": role, "status": "repaired_noncreditable"},
                )
                return completion
            if _is_concluded_unbound_completion(completion):
                self._retain_unbound_completion(completion)
                self.logger.warning(
                    "Completed response identity is unbound; preserving evidence without "
                    "automatic fallback",
                    extra={"role": role, "status": "identity_unbound"},
                )
                return completion
            if trusted_openrouter_execution_evidence(self) is ExecutionEvidenceKind.REAL:
                completion = await self._bind_real_completion_identity(completion)
                if _is_concluded_unbound_completion(completion):
                    self._retain_unbound_completion(completion)
                    self.logger.warning(
                        "Completed response identity is unbound; preserving evidence without "
                        "automatic fallback",
                        extra={"role": role, "status": "identity_unbound"},
                    )
                return completion
            return completion
        assert last_error is not None
        raise last_error

    async def complete_with_bound_identity(
        self,
        *,
        role: str,
        models: list[str],
        system_prompt: str,
        user_prompt: str,
        context_package: ContextPackage | None = None,
        response_model: type[ResponseT],
        schema_name: str,
        logical_request_id: str | None = None,
    ) -> StructuredCompletion[ResponseT]:
        """Complete one owned REAL request and require fresh generation identity."""

        if (
            len(models) != 1
            or models[0] not in self._model_identities
            or not self.provider_policy.certification
        ):
            raise OpenRouterModelError(
                "bound completion requires one certification model with frozen identity metadata"
            )
        if (
            type(self) is not _TRUSTED_OPENROUTER_CLIENT_TYPE
            or trusted_openrouter_execution_evidence(self) is not ExecutionEvidenceKind.REAL
            or not self._owns_client
            or not self._authentication_validated
        ):
            raise OpenRouterPrivacyError(
                "bound completion requires an authenticated owned REAL provider client"
            )
        completion = await self.complete_with_evidence(
            role=role,
            models=models,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            context_package=context_package,
            response_model=response_model,
            schema_name=schema_name,
            logical_request_id=logical_request_id,
        )
        if _is_concluded_unbound_completion(completion):
            raise OpenRouterUnboundIdentityError(completion)
        if _is_repaired_noncreditable_completion(completion):
            raise OpenRouterSchemaError(
                "syntax-repaired structured output cannot satisfy bound completion"
            )
        return completion

    async def _bind_real_completion_identity(
        self,
        completion: StructuredCompletion[ResponseT],
    ) -> StructuredCompletion[ResponseT]:
        """Fetch generation metadata and upgrade one owned REAL completion atomically."""

        if (
            type(self) is not _TRUSTED_OPENROUTER_CLIENT_TYPE
            or trusted_openrouter_execution_evidence(self) is not ExecutionEvidenceKind.REAL
            or not self._owns_client
            or not self._authentication_validated
            or not _openrouter_client_callables_are_pristine()
        ):
            raise OpenRouterPrivacyError(
                "REAL identity binding requires an authenticated owned provider client"
            )
        OpenRouterClient._validate_transport_provenance(self)
        generation_id = completion.usage_record.openrouter_generation_id
        if generation_id is None:
            raise OpenRouterModelError("REAL provider completion lacks a generation identity")
        identity = self._model_identities.get(completion.usage_record.requested_model)
        if identity is None:
            raise OpenRouterModelError("REAL provider completion lacks frozen model identity")

        def conclude_unbound(
            diagnostic_codes: set[OpenRouterIdentityDiagnosticCode],
            *,
            generation_observation: OpenRouterGenerationEvidence | None = None,
        ) -> StructuredCompletion[ResponseT]:
            missing_binding = self._bind_generation_identity(
                usage_record=completion.usage_record,
                generation_evidence=None,
                evaluated_at=None,
                trusted_issuer=_TRUSTED_OPENROUTER_IDENTITY_BINDING_ISSUER,
                missing_diagnostic_codes=tuple(
                    sorted(diagnostic_codes, key=lambda item: item.value)
                ),
            )
            unbound_usage = self._usage_with_unbound_identity(
                usage_record=completion.usage_record,
                identity_binding=missing_binding,
                trusted_issuer=_TRUSTED_OPENROUTER_IDENTITY_BINDING_ISSUER,
                generation_observation=generation_observation,
            )
            return StructuredCompletion(value=completion.value, usage_record=unbound_usage)

        try:
            reconciliation_expectation = GenerationReconciliationExpectation(
                exact_model_id=identity.exact_model_id,
                canonical_model_id=identity.canonical_slug,
                catalog_identity_binding_sha256=identity.catalog_identity_binding_sha256,
                discovery_evidence_sha256=identity.discovery_evidence_sha256,
                expected_provider_name=identity.snapshot.provider_name,
                require_certification=(
                    completion.usage_record.routing.get("certification_request") is True
                ),
                usage_record=completion.usage_record,
            )
        except GenerationEvidenceValidationError:
            usage = completion.usage_record
            diagnostic_codes = {
                OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_INTEGRITY_REJECTED,
                OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_MISSING,
            }
            if usage.actual_provider_endpoint != identity.snapshot.approved_provider_endpoint:
                diagnostic_codes.add(OpenRouterIdentityDiagnosticCode.ENDPOINT_VARIANT_MISMATCH)
            if usage.routing.get("selected_provider_name") != identity.snapshot.provider_name:
                diagnostic_codes.add(OpenRouterIdentityDiagnosticCode.PROVIDER_MISMATCH)
            if usage.fallback_used:
                diagnostic_codes.add(OpenRouterIdentityDiagnosticCode.UNAPPROVED_FALLBACK)
            if (
                usage.returned_model not in identity.accepted_response_models
                or usage.actual_model not in identity.accepted_response_models
            ):
                diagnostic_codes.add(OpenRouterIdentityDiagnosticCode.MODEL_CANONICAL_MISMATCH)
            return conclude_unbound(diagnostic_codes)
        try:
            generation = await OpenRouterClient.get_generation_evidence(
                self,
                generation_id,
                reconciliation_request=reconciliation_expectation,
            )
        except OpenRouterError as exc:
            generation_observation = (
                exc.last_evidence
                if isinstance(exc, OpenRouterGenerationReconciliationError)
                else None
            )
            return conclude_unbound(
                {
                    OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_MISSING,
                    _generation_metadata_failure_diagnostic(exc),
                },
                generation_observation=generation_observation,
            )
        OpenRouterClient._validate_transport_provenance(self)
        binding = self._bind_generation_identity(
            usage_record=completion.usage_record,
            generation_evidence=generation,
            evaluated_at=None,
            trusted_issuer=_TRUSTED_OPENROUTER_IDENTITY_BINDING_ISSUER,
        )
        if binding.strength is ModelIdentityStrength.UNBOUND:
            unbound_usage = self._usage_with_unbound_identity(
                usage_record=completion.usage_record,
                identity_binding=binding,
                trusted_issuer=_TRUSTED_OPENROUTER_IDENTITY_BINDING_ISSUER,
                generation_observation=generation,
            )
            return StructuredCompletion(value=completion.value, usage_record=unbound_usage)
        bound_usage = self._usage_with_bound_identity(
            usage_record=completion.usage_record,
            identity_binding=binding,
            trusted_issuer=_TRUSTED_OPENROUTER_IDENTITY_BINDING_ISSUER,
        )
        return StructuredCompletion(value=completion.value, usage_record=bound_usage)

    async def _complete_one(
        self,
        *,
        request_id: str | None = None,
        role: str,
        model: str,
        system_prompt: str,
        user_prompt: str,
        context_package: ContextPackage | None = None,
        response_model: type[ResponseT],
        schema_name: str,
        fallback_used: bool,
        qualification_binding: OpenRouterQualificationRoutingEvidence | None,
        audit_routing_evidence: AuditModelRoutingEvidence | None = None,
        refresh_routing_evidence: AuditModelRefreshRouteEvidence | None = None,
        refresh_pricing_routing_evidence: (AuditModelRefreshPricingRouteEvidence | None) = None,
        refresh_pricing_control: _AuditModelRefreshPricingRequestControl | None = None,
        qualification_bound_reasoning_plan: ReasoningRequestPlanEvidence | None = None,
        maximum_attempts: int | None = None,
        expected_resource_preview: ModelSurfaceTaskResourcePreview | None = None,
        expected_request_cost_preview: OpenRouterStructuredRequestCostPreview | None = None,
    ) -> StructuredCompletion[ResponseT]:
        paid_controls_required = _trusted_paid_controls_required(self)
        configured_attempts = self.execution.max_model_retries + 1
        attempt_limit = configured_attempts if maximum_attempts is None else maximum_attempts
        if type(attempt_limit) is not int or not 1 <= attempt_limit <= configured_attempts:
            raise OpenRouterRequestLimitError(
                "model attempt bound must only tighten the configured retry policy"
            )
        if expected_resource_preview is not None and (
            response_model is not _TRUSTED_CANDIDATE_REVIEW_FRAMED_DOCUMENT_TYPE
            or attempt_limit != expected_resource_preview.maximum_attempts
        ):
            raise OpenRouterCandidateReviewBoundaryError(
                "candidate-review attempt plan differs from aggregate resource preflight"
            )
        if expected_request_cost_preview is not None and (
            expected_resource_preview is not None
            or attempt_limit != expected_request_cost_preview.maximum_attempts
            or request_id != expected_request_cost_preview.logical_request_id
            or role != expected_request_cost_preview.role
            or model != expected_request_cost_preview.exact_model_id
        ):
            raise OpenRouterRequestCostPreviewError(
                "provider request coordinates differ from the exact cost preview"
            )
        if response_model is _TRUSTED_CANDIDATE_REVIEW_FRAMED_DOCUMENT_TYPE and (
            not _candidate_review_protocol_boundary_is_pristine()
            or not _openrouter_client_callables_are_pristine()
        ):
            raise OpenRouterCandidateReviewBoundaryError(
                "candidate-review completion boundary changed before request planning"
            )
        request_id = _request_ids_for_routes(
            request_id,
            route_count=1,
            maximum_attempts=attempt_limit,
        )[0]
        required_output_tokens = self._required_output_tokens()
        requested_completion_tokens = required_output_tokens + self._reserved_reasoning_tokens(
            required_output_tokens,
            role=role,
        )
        response_schema_generation = _pydantic_schema_generation(response_model)
        request_provider_policy = _canonical_provider_policy(self.provider_policy)
        endpoint_policy = self._endpoint_pricing.get(model)
        structured_output_mode = self._selected_structured_output_mode(model)
        structured_output_plan: _StructuredOutputRequestPlan | None = None
        reasoning_plan: ReasoningRequestPlanEvidence | None = None
        pricing_required = _TRUSTED_REQUIRES_REAL_AUDIT_MODEL_REFRESH_PRICING(
            self,
            role,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            schema_name=schema_name,
            structured_output_mode=structured_output_mode,
            context_package=context_package,
        )

        def require_current_refresh_pricing(
            *,
            phase: str,
            checked_at: datetime | None = None,
        ) -> AuditModelRefreshPricingRouteEvidence | None:
            if not pricing_required:
                if (
                    refresh_pricing_routing_evidence is not None
                    or refresh_pricing_control is not None
                ):
                    raise OpenRouterModelRefreshPricingError(
                        "refresh pricing custody is invalid outside a REAL paid audit request"
                    )
                return None
            current = _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_REFRESH_PRICING(
                self,
                role=role,
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                structured_output_mode=structured_output_mode,
                context_package=context_package,
                checked_at=(checked_at or datetime.now(UTC)).replace(microsecond=0),
                qualification_binding=qualification_binding,
                audit_routing_evidence=audit_routing_evidence,
                refresh_routing_evidence=refresh_routing_evidence,
                provider_policy=request_provider_policy,
            )
            current_control = _TRUSTED_SEAL_AUDIT_MODEL_REFRESH_PRICING_CONTROL(
                self,
                current,
            )
            if (
                refresh_pricing_routing_evidence != current
                or refresh_pricing_control != current_control
            ):
                raise OpenRouterModelRefreshPricingError(
                    f"sealed audit model refresh pricing changed {phase}"
                )
            return current

        def require_current_audit_selection(
            *,
            phase: str,
            checked_at: datetime | None = None,
        ) -> AuditModelRoutingEvidence | None:
            if not _TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION(
                self,
                role,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                structured_output_mode=structured_output_mode,
                context_package=context_package,
            ):
                if audit_routing_evidence is not None:
                    raise OpenRouterPolicyEligibilityError(
                        "audit model routing evidence is invalid outside a paid audit request"
                    )
                return None
            current = _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_SELECTION(
                self,
                role=role,
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                structured_output_mode=structured_output_mode,
                context_package=context_package,
                checked_at=checked_at or datetime.now(UTC),
                qualification_binding=qualification_binding,
                provider_policy=request_provider_policy,
            )
            if current != audit_routing_evidence:
                raise OpenRouterPolicyEligibilityError(
                    f"sealed audit model selection changed {phase}"
                )
            return current

        try:
            if _TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION(
                self,
                role,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                structured_output_mode=structured_output_mode,
                context_package=context_package,
            ):
                current_qualification_binding = self._require_real_postqualification_routing(
                    role=role,
                    model=model,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_model=response_model,
                    schema_name=schema_name,
                    structured_output_mode=structured_output_mode,
                    context_package=context_package,
                    checked_at=datetime.now(UTC),
                    require_runtime_snapshots=True,
                    allow_refreshed_pricing=pricing_required,
                )
                if qualification_binding != current_qualification_binding:
                    raise OpenRouterQualificationError(
                        "sealed post-qualification routing authority changed before transport"
                    )
                current_reasoning_plan = self._require_real_postqualification_reasoning_plan(
                    role=role,
                    model=model,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_model=response_model,
                    schema_name=schema_name,
                    structured_output_mode=structured_output_mode,
                    context_package=context_package,
                    qualification_binding=current_qualification_binding,
                )
                if qualification_bound_reasoning_plan != current_reasoning_plan:
                    raise OpenRouterQualificationError(
                        "sealed post-qualification reasoning authority changed before transport"
                    )
                reasoning_plan = current_reasoning_plan
            else:
                if qualification_bound_reasoning_plan is not None:
                    raise OpenRouterQualificationError(
                        "qualification-bound reasoning authority is invalid for this request"
                    )
                reasoning_plan = self._reasoning_request_plan(
                    role=role,
                    model=model,
                    qualification_binding=qualification_binding,
                )
            request_provider_policy = (
                qualification_binding.request_provider_policy()
                if qualification_binding is not None and self.provider_policy.certification
                else self.provider_policy
            )
            request_provider_policy = _canonical_provider_policy(request_provider_policy)
            if _TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION(
                self,
                role,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                structured_output_mode=structured_output_mode,
                context_package=context_package,
            ):
                current_audit_routing_evidence = _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_SELECTION(
                    self,
                    role=role,
                    model=model,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_model=response_model,
                    schema_name=schema_name,
                    structured_output_mode=structured_output_mode,
                    context_package=context_package,
                    checked_at=datetime.now(UTC),
                    qualification_binding=qualification_binding,
                    provider_policy=request_provider_policy,
                )
                if audit_routing_evidence != current_audit_routing_evidence:
                    raise OpenRouterPolicyEligibilityError(
                        "sealed audit model selection changed before request planning"
                    )
            elif audit_routing_evidence is not None:
                raise OpenRouterPolicyEligibilityError(
                    "audit model routing evidence is invalid outside a paid audit request"
                )
            if (
                not _TRUSTED_REQUIRES_REAL_AUDIT_MODEL_REFRESH(
                    self,
                    role,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_model=response_model,
                    schema_name=schema_name,
                    structured_output_mode=structured_output_mode,
                    context_package=context_package,
                )
                and refresh_routing_evidence is not None
            ):
                raise OpenRouterModelRefreshError(
                    "audit model refresh route is invalid outside a REAL paid audit request"
                )
            require_current_refresh_pricing(phase="before request planning")
            if paid_controls_required:
                _TRUSTED_VALIDATE_PAID_PRIVACY_POLICY(
                    self,
                    (model,),
                    request_provider_endpoints=request_provider_policy.configured_endpoints,
                )
            structured_output_plan = _structured_output_request_plan(
                mode=structured_output_mode,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                reasoning=self._reasoning_for_role(role),
                schema_generation=response_schema_generation,
            )
            response_schema_generation.require_current(
                response_model,
                phase="during structured request planning",
            )
        except Exception as exc:
            reason = ContextPreflightReason.ROUTE_UNAVAILABLE
            planning_snapshot = self._diagnostic_planning_snapshot(
                request_id=request_id,
                role=role,
                model=model,
                reason=reason,
                provider_policy=request_provider_policy,
                structured_output_plan=structured_output_plan,
                original_system_prompt=system_prompt,
                response_model=response_model,
                schema_name=schema_name,
                context_package=context_package,
            )
            self._record_context_preflight(
                request_id=request_id,
                logical_request_id=request_id,
                role=role,
                model=model,
                requested_completion_tokens=requested_completion_tokens,
                request_plan=None,
                planning_snapshot=planning_snapshot,
                decision_source=ContextPreflightSource.TOKEN_PLANNER,
                reason=reason,
                error=exc,
                decision_evidence_sha256s=(
                    self._audit_policy_decision_evidence_sha256s(
                        audit_routing_evidence,
                    )
                ),
            )
            raise
        prompt_hash = _structured_output_prompt_sha256_from_plan(structured_output_plan)
        system_prompt_hash = hashlib.sha256(
            structured_output_plan.system_prompt.encode("utf-8")
        ).hexdigest()
        user_prompt_hash = hashlib.sha256(user_prompt.encode("utf-8")).hexdigest()
        schema_hash = structured_output_plan.schema_sha256
        delivered_sources = _fully_delivered_source_descriptors(context_package)
        observer = self._request_lifecycle_observer
        request_limit_scope = None
        accepted_privacy_binding = _model_request_privacy_binding(self.effective_privacy_policy)
        if observer is not None:
            request_limit_scope = observer.request_ready(
                logical_request_id=request_id,
                role=role,
                requested_model=model,
                prompt_sha256=prompt_hash,
                system_prompt_sha256=system_prompt_hash,
                user_prompt_sha256=user_prompt_hash,
                schema_sha256=schema_hash,
                delivered_sources=delivered_sources,
                privacy_binding=accepted_privacy_binding,
            )
        response_schema_generation.require_current(
            response_model,
            phase="after request evidence activation",
        )
        try:
            request_token_plan, context_request_evidence = self._request_token_plan(
                request_id=request_id,
                role=role,
                model=model,
                provider_policy=request_provider_policy,
                structured_output_plan=structured_output_plan,
                original_system_prompt=system_prompt,
                response_model=response_model,
                schema_name=schema_name,
                reasoning_plan=reasoning_plan,
                context_package=context_package,
            )
            response_schema_generation.require_current(
                response_model,
                phase="during token planning",
            )
            if expected_resource_preview is not None and (
                context_request_evidence is None
                or context_request_evidence.rendered_sha256
                != expected_resource_preview.rendered_context_sha256
                or context_request_evidence.evidence_sha256
                != expected_resource_preview.context_request_evidence_sha256
                or _TRUSTED_CANDIDATE_REVIEW_TOKEN_PLAN_PROJECTION_SHA256(request_token_plan)
                != expected_resource_preview.request_token_plan_projection_sha256
                or request_token_plan.prompt_byte_upper_bound_tokens
                != expected_resource_preview.maximum_prompt_tokens_per_attempt
                or request_token_plan.requested_completion_tokens
                != expected_resource_preview.maximum_completion_tokens_per_attempt
            ):
                raise OpenRouterCandidateReviewBoundaryError(
                    "candidate-review context or token plan changed after aggregate preflight"
                )
            if expected_resource_preview is not None and (
                endpoint_policy is None
                or endpoint_policy.snapshot_sha256
                != expected_resource_preview.endpoint_policy_snapshot_sha256
                or endpoint_policy.policy_pricing_sha256
                != expected_resource_preview.endpoint_policy_pricing_sha256
            ):
                raise OpenRouterCandidateReviewBoundaryError(
                    "candidate-review endpoint policy changed after aggregate preflight"
                )
        except Exception as exc:
            if isinstance(exc, _OpenRouterGlobalTokenBudgetError):
                reason = ContextPreflightReason.GLOBAL_TOKEN_BUDGET
            elif isinstance(exc, _OpenRouterContextPlanError):
                reason = ContextPreflightReason.CONTEXT_PLAN_INVALID
            elif isinstance(exc, _OpenRouterRoutePlanningError):
                reason = ContextPreflightReason.ROUTE_UNAVAILABLE
            else:
                reason = ContextPreflightReason.ENDPOINT_CAPACITY
            planning_snapshot = self._diagnostic_planning_snapshot(
                request_id=request_id,
                role=role,
                model=model,
                reason=reason,
                provider_policy=request_provider_policy,
                structured_output_plan=structured_output_plan,
                original_system_prompt=system_prompt,
                response_model=response_model,
                schema_name=schema_name,
                context_package=context_package,
            )
            self._record_context_preflight(
                request_id=request_id,
                logical_request_id=request_id,
                role=role,
                model=model,
                requested_completion_tokens=requested_completion_tokens,
                request_plan=None,
                planning_snapshot=planning_snapshot,
                decision_source=ContextPreflightSource.TOKEN_PLANNER,
                reason=reason,
                error=exc,
            )
            raise
        model_identity = self._model_identities.get(model)
        request_metadata = _structured_request_metadata(
            request_id=request_id,
            role=role,
            prompt_sha256=prompt_hash,
            user_prompt_sha256=user_prompt_hash,
            structured_output_plan=structured_output_plan,
            request_token_plan=request_token_plan,
            context_request_evidence=context_request_evidence,
            endpoint_policy=endpoint_policy,
            model_identity_snapshot_sha256=(
                model_identity.snapshot.snapshot_sha256 if model_identity is not None else None
            ),
        )
        if qualification_binding is not None:
            request_metadata.update(qualification_binding.request_metadata())
        if audit_routing_evidence is not None:
            request_metadata.update(
                {
                    f"mmaudit_policy_{key}": value
                    for key, value in audit_routing_evidence.request_metadata().items()
                }
            )
            assert self._audit_model_selection is not None
            request_metadata["mmaudit_policy_selection_capability_sha256"] = (
                self._audit_model_selection.capability_sha256
            )
        request_metadata.update(
            self._audit_model_refresh_request_metadata(refresh_routing_evidence)
        )
        request_metadata.update(
            self._audit_model_refresh_pricing_request_metadata(refresh_pricing_routing_evidence)
        )
        try:
            body = _TRUSTED_BUILD_REQUEST(
                self,
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                context_package=context_package,
                request_metadata=request_metadata,
                provider_policy=request_provider_policy,
                structured_output_mode=structured_output_mode,
                request_token_plan=request_token_plan,
                request_role=role,
                response_schema_generation=response_schema_generation,
                refresh_pricing_control=refresh_pricing_control,
            )
            _TRUSTED_ENSURE_REQUEST_SIZE(self, body)
            request_body_hash = _require_exact_openrouter_request_body(
                body,
                model=model,
                structured_output_plan=structured_output_plan,
                provider_policy=request_provider_policy,
                require_zdr=self.privacy.require_zdr,
                request_token_plan=request_token_plan,
                request_metadata=request_metadata,
                endpoint_policy=endpoint_policy,
                refresh_pricing_control=refresh_pricing_control,
            )
            response_schema_generation.require_current(
                response_model,
                phase="during request body hashing",
            )
            request_material = (
                _TRUSTED_CANDIDATE_REVIEW_CANONICAL_JSON_DUMPS(body)
                if expected_resource_preview is not None
                or expected_request_cost_preview is not None
                else json.dumps(
                    body,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
            )
            (
                _request_token_plan_projection_sha256,
                request_material_projection,
                request_material_projection_sha256,
            ) = _TRUSTED_CANDIDATE_REVIEW_REQUEST_MATERIAL_PROJECTION(
                body,
                request_token_plan=request_token_plan,
            )
            endpoint_cost_bound = _TRUSTED_ENDPOINT_REQUEST_COST_BOUND(
                self,
                model=model,
                request_material=request_material,
                request_token_plan=request_token_plan,
                refresh_pricing_control=refresh_pricing_control,
            )
            if expected_request_cost_preview is not None:
                _TRUSTED_REQUIRE_MATCHING_REQUEST_COST_PREVIEW(
                    expected=expected_request_cost_preview,
                    execution=self.execution,
                    privacy=self.privacy,
                    token_budgets=self.token_budgets,
                    provider_policy=request_provider_policy,
                    model_identity=self._model_identities.get(model),
                    endpoint_policy=endpoint_policy,
                    structured_output_plan=structured_output_plan,
                    request_token_plan=request_token_plan,
                    context_request_evidence=context_request_evidence,
                    request_material_projection=request_material_projection,
                    request_material_projection_sha256=request_material_projection_sha256,
                    request_token_plan_projection_sha256=(_request_token_plan_projection_sha256),
                    endpoint_cost_bound=endpoint_cost_bound,
                    maximum_attempts=attempt_limit,
                )
            if expected_resource_preview is not None:
                maximum_cost_text = (
                    format(
                        _trusted_endpoint_request_maximum_cost_usd(endpoint_cost_bound),
                        "f",
                    )
                    if endpoint_cost_bound is not None
                    else ""
                )
                if "." in maximum_cost_text:
                    maximum_cost_text = maximum_cost_text.rstrip("0").rstrip(".")
                if (
                    endpoint_cost_bound is None
                    or request_material_projection_sha256
                    != expected_resource_preview.request_material_projection_sha256
                    or len(request_material_projection.encode("utf-8"))
                    != expected_resource_preview.request_material_projection_utf8_bytes
                    or endpoint_cost_bound.request_material_sha256 != request_body_hash
                    or endpoint_cost_bound.provider_endpoint
                    != expected_resource_preview.provider_endpoint
                    or endpoint_cost_bound.pricing_snapshot_sha256
                    != expected_resource_preview.endpoint_pricing_snapshot_sha256
                    or _TRUSTED_ENDPOINT_REQUEST_COST_BOUND_PROJECTION_SHA256(
                        endpoint_cost_bound,
                        request_material_projection_sha256=(request_material_projection_sha256),
                    )
                    != expected_resource_preview.endpoint_cost_bound_projection_sha256
                    or (maximum_cost_text or "0")
                    != expected_resource_preview.maximum_cost_usd_per_attempt_exact
                ):
                    raise OpenRouterCandidateReviewBoundaryError(
                        "candidate-review request body or pricing changed after aggregate preflight"
                    )
            if refresh_pricing_control is not None:
                provider_request = body.get("provider")
                bound_components = (
                    {
                        component.pricing_field: component.unit_price_usd
                        for component in endpoint_cost_bound.components
                    }
                    if endpoint_cost_bound is not None
                    else None
                )
                expected_bound_components = {
                    field: Decimal(value)
                    for field, value in refresh_pricing_control.cost_bound_pricing
                }
                if (
                    not isinstance(provider_request, dict)
                    or provider_request.get("max_price")
                    != dict(refresh_pricing_control.routing_max_price)
                    or endpoint_cost_bound is None
                    or endpoint_cost_bound.exact_model_id != refresh_pricing_control.exact_model_id
                    or endpoint_cost_bound.provider_endpoint
                    != refresh_pricing_control.provider_endpoint
                    or endpoint_cost_bound.request_material_sha256 != request_body_hash
                    or bound_components != expected_bound_components
                ):
                    raise OpenRouterModelRefreshPricingError(
                        "request body or exact cost bound differs from sealed refreshed pricing"
                    )
        except Exception as exc:
            self._record_context_preflight(
                request_id=request_id,
                logical_request_id=request_id,
                role=role,
                model=model,
                requested_completion_tokens=requested_completion_tokens,
                request_plan=request_token_plan,
                decision_source=ContextPreflightSource.TOKEN_PLANNER,
                reason=(
                    ContextPreflightReason.COST_BUDGET
                    if isinstance(exc, UnprovenCostBoundError)
                    else ContextPreflightReason.CONTEXT_PLAN_INVALID
                ),
                error=exc,
            )
            raise
        if self.privacy.store_raw_prompts:
            _TRUSTED_STORE_DEBUG(
                self,
                request_id,
                "prompt.json",
                json.loads(request_material),
            )
        attempts = 0
        usage_recorded = False
        accounted_cost_usd = 0.0
        accounted_cost_usd_exact = Decimal(0)
        active_reservation: Reservation | None = None
        attempt_reservations: list[Reservation] = []
        refresh_pricing_reservation_checks: dict[str, datetime] = {}
        refresh_pricing_transport_checks: dict[str, datetime] = {}
        refresh_pricing_attempt_routes: dict[str, AuditModelRefreshPricingRouteEvidence] = {}
        last_dispatched_audit_routing_evidence: AuditModelRoutingEvidence | None = None
        last_dispatched_refresh_routing_evidence: AuditModelRefreshRouteEvidence | None = None
        last_dispatched_refresh_pricing_routing_evidence: (
            AuditModelRefreshPricingRouteEvidence | None
        ) = None
        active_network_attempted = False
        active_reservation_committed = False
        active_actual_cost: Decimal | None = None
        active_actual_prompt_tokens: int | None = None
        active_actual_completion_tokens: int | None = None
        active_actual_reasoning_tokens: int | None = None
        started_at = datetime.now(UTC)
        started_clock = time.perf_counter()
        initial_usage: dict[str, Any] = {}
        initial_cost: Decimal | None = None
        response_hash: str | None = None
        validated_response_hash: str | None = None
        decoded_output: StructuredOutputDecodeResult[ResponseT] | None = None
        preserved_unbound_response: ResponseT | None = None
        validated_envelope: CompletionEnvelope | None = None
        raw_payload: dict[str, Any] | None = None
        response_headers: Mapping[str, str] = {}

        async def finalize_active(actual_cost: Decimal | None) -> None:
            nonlocal accounted_cost_usd, accounted_cost_usd_exact, active_reservation
            if active_reservation is None:
                return
            reservation = active_reservation
            active_reservation = None
            try:
                await _TRUSTED_BUDGET_RECONCILE(
                    self.budget,
                    reservation,
                    actual_cost,
                    actual_prompt_tokens=active_actual_prompt_tokens,
                    actual_completion_tokens=active_actual_completion_tokens,
                    actual_reasoning_tokens=active_actual_reasoning_tokens,
                )
                exact = await _TRUSTED_BUDGET_RECONCILED_COST_USD_EXACT(
                    self.budget,
                    reservation,
                )
                with localcontext() as context:
                    context.prec = 160
                    accounted_cost_usd_exact += exact
                accounted_cost_usd = float(accounted_cost_usd_exact)
            except Exception:
                try:
                    exact = await _TRUSTED_BUDGET_RECONCILED_COST_USD_EXACT(
                        self.budget,
                        reservation,
                    )
                except BudgetReservationStateError:
                    exact = (
                        reservation.persistent.reserved_usd
                        if actual_cost is None and reservation.persistent is not None
                        else (
                            Decimal(str(reservation.estimated_cost_usd))
                            if actual_cost is None
                            else max(Decimal(0), actual_cost)
                        )
                    )
                with localcontext() as context:
                    context.prec = 160
                    accounted_cost_usd_exact += exact
                accounted_cost_usd = float(accounted_cost_usd_exact)
                raise

        async def release_active() -> None:
            nonlocal active_reservation
            if active_reservation is None:
                return
            reservation = active_reservation
            active_reservation = None
            await _TRUSTED_BUDGET_RELEASE(self.budget, reservation)

        async def require_current_refresh_inside_transport_lock() -> None:
            nonlocal active_network_attempted
            nonlocal active_reservation_committed
            nonlocal last_dispatched_refresh_pricing_routing_evidence
            if expected_resource_preview is not None and (
                not _candidate_review_protocol_boundary_is_pristine()
                or not _openrouter_client_callables_are_pristine()
            ):
                raise OpenRouterCandidateReviewBoundaryError(
                    "candidate-review projection boundary changed inside provider transport lock"
                )
            _TRUSTED_ENSURE_REQUEST_SIZE(self, body)
            locked_request_body_sha256 = _require_exact_openrouter_request_body(
                body,
                model=model,
                structured_output_plan=structured_output_plan,
                provider_policy=request_provider_policy,
                require_zdr=self.privacy.require_zdr,
                request_token_plan=request_token_plan,
                request_metadata=request_metadata,
                endpoint_policy=endpoint_policy,
                refresh_pricing_control=refresh_pricing_control,
                expected_sha256=request_body_hash,
            )
            locked_request_material = (
                _TRUSTED_CANDIDATE_REVIEW_CANONICAL_JSON_DUMPS(body)
                if expected_resource_preview is not None
                or expected_request_cost_preview is not None
                else json.dumps(
                    body,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
            )
            locked_cost_bound = _TRUSTED_ENDPOINT_REQUEST_COST_BOUND(
                self,
                model=model,
                request_material=locked_request_material,
                request_token_plan=request_token_plan,
                refresh_pricing_control=refresh_pricing_control,
            )
            if (
                locked_request_body_sha256 != request_body_hash
                or locked_request_material != request_material
                or locked_cost_bound != endpoint_cost_bound
            ):
                raise OpenRouterModelRefreshPricingError(
                    "request body or exact reservation changed inside provider transport lock"
                )
            if paid_controls_required:
                _TRUSTED_VALIDATE_PAID_PRIVACY_POLICY(
                    self,
                    (model,),
                    request_provider_endpoints=request_provider_policy.configured_endpoints,
                )
                if (
                    _model_request_privacy_binding(self.effective_privacy_policy)
                    != accepted_privacy_binding
                ):
                    raise OpenRouterPrivacyError(
                        "effective privacy authority changed inside provider transport lock"
                    )
            require_current_audit_selection(
                phase="inside provider transport lock",
                checked_at=datetime.now(UTC),
            )
            if refresh_routing_evidence is not None:
                locked_refresh_routing_evidence = _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_REFRESH(
                    self,
                    role=role,
                    model=model,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_model=response_model,
                    schema_name=schema_name,
                    structured_output_mode=structured_output_mode,
                    context_package=context_package,
                    checked_at=datetime.now(UTC),
                    qualification_binding=qualification_binding,
                    audit_routing_evidence=audit_routing_evidence,
                    provider_policy=request_provider_policy,
                )
                if locked_refresh_routing_evidence != refresh_routing_evidence:
                    raise OpenRouterModelRefreshError(
                        "sealed audit model refresh changed inside provider transport lock"
                    )
            locked_pricing = require_current_refresh_pricing(
                phase="inside provider transport lock",
                checked_at=datetime.now(UTC).replace(microsecond=0),
            )
            if active_reservation is None:
                raise OpenRouterCostControlError(
                    "inside-lock transport check lacks its exact active reservation"
                )
            if paid_controls_required:
                await _TRUSTED_BUDGET_COMMIT_FOR_TRANSPORT(self.budget, active_reservation)
                active_reservation_committed = True
            transport_checked_at = datetime.now(UTC).replace(microsecond=0)
            if paid_controls_required:
                _TRUSTED_VALIDATE_PAID_PRIVACY_POLICY(
                    self,
                    (model,),
                    request_provider_endpoints=request_provider_policy.configured_endpoints,
                )
                if (
                    _model_request_privacy_binding(self.effective_privacy_policy)
                    != accepted_privacy_binding
                ):
                    raise OpenRouterPrivacyError(
                        "effective privacy authority changed after durable transport commit"
                    )
            require_current_audit_selection(
                phase="after durable transport commit",
                checked_at=transport_checked_at,
            )
            if refresh_routing_evidence is not None:
                post_commit_refresh_routing_evidence = _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_REFRESH(
                    self,
                    role=role,
                    model=model,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_model=response_model,
                    schema_name=schema_name,
                    structured_output_mode=structured_output_mode,
                    context_package=context_package,
                    checked_at=transport_checked_at,
                    qualification_binding=qualification_binding,
                    audit_routing_evidence=audit_routing_evidence,
                    provider_policy=request_provider_policy,
                )
                if post_commit_refresh_routing_evidence != refresh_routing_evidence:
                    raise OpenRouterModelRefreshError(
                        "sealed audit model refresh changed after durable transport commit"
                    )
            locked_pricing = require_current_refresh_pricing(
                phase="after durable transport commit",
                checked_at=transport_checked_at,
            )
            if locked_pricing is not None:
                refresh_pricing_transport_checks[active_reservation.identifier] = (
                    transport_checked_at
                )
            last_dispatched_refresh_pricing_routing_evidence = locked_pricing
            active_network_attempted = True

        try:
            while True:
                next_attempt = attempts + 1
                reservation_id = _attempt_request_id(request_id, next_attempt)
                reservation_pricing_checked_at: datetime | None = None
                reservation_pricing_route: AuditModelRefreshPricingRouteEvidence | None = None
                try:
                    if _TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION(
                        self,
                        role,
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        response_model=response_model,
                        schema_name=schema_name,
                        structured_output_mode=structured_output_mode,
                        context_package=context_package,
                    ):
                        current_audit_routing_evidence = (
                            _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_SELECTION(
                                self,
                                role=role,
                                model=model,
                                system_prompt=system_prompt,
                                user_prompt=user_prompt,
                                response_model=response_model,
                                schema_name=schema_name,
                                structured_output_mode=structured_output_mode,
                                context_package=context_package,
                                checked_at=datetime.now(UTC),
                                qualification_binding=qualification_binding,
                                provider_policy=request_provider_policy,
                            )
                        )
                        if current_audit_routing_evidence != audit_routing_evidence:
                            raise OpenRouterPolicyEligibilityError(
                                "sealed audit model selection changed before budget reservation"
                            )
                    if _TRUSTED_REQUIRES_REAL_AUDIT_MODEL_REFRESH(
                        self,
                        role,
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        response_model=response_model,
                        schema_name=schema_name,
                        structured_output_mode=structured_output_mode,
                        context_package=context_package,
                    ):
                        current_refresh_routing_evidence = (
                            _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_REFRESH(
                                self,
                                role=role,
                                model=model,
                                system_prompt=system_prompt,
                                user_prompt=user_prompt,
                                response_model=response_model,
                                schema_name=schema_name,
                                structured_output_mode=structured_output_mode,
                                context_package=context_package,
                                checked_at=datetime.now(UTC),
                                qualification_binding=qualification_binding,
                                audit_routing_evidence=audit_routing_evidence,
                                provider_policy=request_provider_policy,
                            )
                        )
                        if current_refresh_routing_evidence != refresh_routing_evidence:
                            raise OpenRouterModelRefreshError(
                                "sealed audit model refresh changed before budget reservation"
                            )
                    reservation_pricing_checked_at = datetime.now(UTC).replace(microsecond=0)
                    reservation_pricing_route = require_current_refresh_pricing(
                        phase="before budget reservation",
                        checked_at=reservation_pricing_checked_at,
                    )
                    if paid_controls_required:
                        _TRUSTED_VALIDATE_TRANSPORT_PROVENANCE(self)
                    active_reservation = await _TRUSTED_BUDGET_RESERVE(
                        self.budget,
                        reservation_id,
                        role,
                        request_material,
                        endpoint_cost_bound=endpoint_cost_bound,
                        exact_model_id=model,
                        planned_prompt_tokens=(request_token_plan.prompt_byte_upper_bound_tokens),
                        planned_visible_output_tokens=(request_token_plan.reserved_output_tokens),
                        planned_reasoning_tokens=(request_token_plan.reserved_reasoning_tokens),
                        planned_completion_tokens=(request_token_plan.requested_completion_tokens),
                        request_token_plan_sha256=request_token_plan.plan_sha256,
                        request_limit_scope=request_limit_scope,
                    )
                except Exception as exc:
                    self._record_context_preflight(
                        request_id=(request_id if attempts == 0 else f"{reservation_id}:preflight"),
                        logical_request_id=request_id,
                        role=role,
                        model=model,
                        requested_completion_tokens=requested_completion_tokens,
                        request_plan=request_token_plan,
                        decision_source=(
                            ContextPreflightSource.TOKEN_PLANNER
                            if isinstance(exc, OpenRouterPolicyEligibilityError)
                            else ContextPreflightSource.BUDGET_MANAGER
                        ),
                        reason=(
                            self._budget_preflight_reason(request_token_plan)
                            if isinstance(exc, BudgetExhaustedError)
                            else (
                                ContextPreflightReason.ROUTE_UNAVAILABLE
                                if isinstance(exc, OpenRouterPolicyEligibilityError)
                                else ContextPreflightReason.CONTEXT_PLAN_INVALID
                            )
                        ),
                        error=exc,
                        decision_evidence_sha256s=(
                            self._audit_policy_decision_evidence_sha256s(
                                audit_routing_evidence,
                                refresh_routing_evidence=refresh_routing_evidence,
                            )
                        ),
                    )
                    raise
                active_network_attempted = False
                active_reservation_committed = False
                active_actual_cost = None
                active_actual_prompt_tokens = None
                active_actual_completion_tokens = None
                active_actual_reasoning_tokens = None
                self.logger.info(
                    "Sending bounded structured model request",
                    extra={
                        "request_id": request_id,
                        "role": role,
                        "status": "started",
                    },
                )
                try:
                    if paid_controls_required:
                        _TRUSTED_VALIDATE_PAID_PRIVACY_POLICY(
                            self,
                            (model,),
                            request_provider_endpoints=(
                                request_provider_policy.configured_endpoints
                            ),
                        )
                except Exception as exc:
                    assert active_reservation is not None
                    reservation_evidence = active_reservation.token_reservation_evidence
                    self._record_context_preflight(
                        request_id=(request_id if attempts == 0 else f"{reservation_id}:preflight"),
                        logical_request_id=request_id,
                        role=role,
                        model=model,
                        requested_completion_tokens=requested_completion_tokens,
                        request_plan=request_token_plan,
                        decision_source=ContextPreflightSource.TOKEN_PLANNER,
                        reason=ContextPreflightReason.ROUTE_UNAVAILABLE,
                        error=exc,
                        decision_evidence_sha256s=(
                            (reservation_evidence.evidence_sha256,)
                            if reservation_evidence is not None
                            else ()
                        ),
                    )
                    raise
                try:
                    assert active_reservation is not None
                    if (
                        observer is not None
                        and _model_request_privacy_binding(self.effective_privacy_policy)
                        != accepted_privacy_binding
                    ):
                        raise OpenRouterPrivacyError(
                            "effective privacy authority changed before provider transport"
                        )
                    response_schema_generation.require_current(
                        response_model,
                        phase="before provider transport",
                    )
                    if _TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION(
                        self,
                        role,
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        response_model=response_model,
                        schema_name=schema_name,
                        structured_output_mode=structured_output_mode,
                        context_package=context_package,
                    ):
                        try:
                            current_audit_routing_evidence = (
                                _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_SELECTION(
                                    self,
                                    role=role,
                                    model=model,
                                    system_prompt=system_prompt,
                                    user_prompt=user_prompt,
                                    response_model=response_model,
                                    schema_name=schema_name,
                                    structured_output_mode=structured_output_mode,
                                    context_package=context_package,
                                    checked_at=datetime.now(UTC),
                                    qualification_binding=qualification_binding,
                                    provider_policy=request_provider_policy,
                                )
                            )
                            if current_audit_routing_evidence != audit_routing_evidence:
                                raise OpenRouterPolicyEligibilityError(
                                    "sealed audit model selection changed before provider transport"
                                )
                        except OpenRouterPolicyEligibilityError as exc:
                            reservation_evidence = active_reservation.token_reservation_evidence
                            self._record_context_preflight(
                                request_id=(
                                    request_id if attempts == 0 else f"{reservation_id}:preflight"
                                ),
                                logical_request_id=request_id,
                                role=role,
                                model=model,
                                requested_completion_tokens=requested_completion_tokens,
                                request_plan=request_token_plan,
                                decision_source=ContextPreflightSource.TOKEN_PLANNER,
                                reason=ContextPreflightReason.ROUTE_UNAVAILABLE,
                                error=exc,
                                decision_evidence_sha256s=tuple(
                                    evidence_sha256
                                    for evidence_sha256 in (
                                        (
                                            audit_routing_evidence.routing_evidence_sha256
                                            if audit_routing_evidence is not None
                                            else None
                                        ),
                                        (
                                            reservation_evidence.evidence_sha256
                                            if reservation_evidence is not None
                                            else None
                                        ),
                                    )
                                    if evidence_sha256 is not None
                                ),
                            )
                            raise
                        last_dispatched_audit_routing_evidence = current_audit_routing_evidence
                    if _TRUSTED_REQUIRES_REAL_AUDIT_MODEL_REFRESH(
                        self,
                        role,
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        response_model=response_model,
                        schema_name=schema_name,
                        structured_output_mode=structured_output_mode,
                        context_package=context_package,
                    ):
                        try:
                            current_refresh_routing_evidence = (
                                _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_REFRESH(
                                    self,
                                    role=role,
                                    model=model,
                                    system_prompt=system_prompt,
                                    user_prompt=user_prompt,
                                    response_model=response_model,
                                    schema_name=schema_name,
                                    structured_output_mode=structured_output_mode,
                                    context_package=context_package,
                                    checked_at=datetime.now(UTC),
                                    qualification_binding=qualification_binding,
                                    audit_routing_evidence=audit_routing_evidence,
                                    provider_policy=request_provider_policy,
                                )
                            )
                            if current_refresh_routing_evidence != refresh_routing_evidence:
                                raise OpenRouterModelRefreshError(
                                    "sealed audit model refresh changed before provider transport"
                                )
                        except OpenRouterModelRefreshError as exc:
                            reservation_evidence = active_reservation.token_reservation_evidence
                            self._record_context_preflight(
                                request_id=(
                                    request_id if attempts == 0 else f"{reservation_id}:preflight"
                                ),
                                logical_request_id=request_id,
                                role=role,
                                model=model,
                                requested_completion_tokens=requested_completion_tokens,
                                request_plan=request_token_plan,
                                decision_source=ContextPreflightSource.TOKEN_PLANNER,
                                reason=ContextPreflightReason.ROUTE_UNAVAILABLE,
                                error=exc,
                                decision_evidence_sha256s=tuple(
                                    sorted(
                                        {
                                            *self._audit_policy_decision_evidence_sha256s(
                                                audit_routing_evidence,
                                                refresh_routing_evidence=(refresh_routing_evidence),
                                            ),
                                            *(
                                                (reservation_evidence.evidence_sha256,)
                                                if reservation_evidence is not None
                                                else ()
                                            ),
                                        }
                                    )
                                ),
                            )
                            raise
                        last_dispatched_refresh_routing_evidence = current_refresh_routing_evidence
                    require_current_refresh_pricing(phase="after budget reservation")
                    attempt_reservations.append(active_reservation)
                    if reservation_pricing_route is not None:
                        if reservation_pricing_checked_at is None:
                            raise OpenRouterModelRefreshPricingError(
                                "reserved refreshed price lacks its pre-reserve check"
                            )
                        refresh_pricing_reservation_checks[reservation_id] = (
                            reservation_pricing_checked_at
                        )
                        refresh_pricing_attempt_routes[reservation_id] = reservation_pricing_route
                    attempts = next_attempt
                    if observer is not None and attempts == 1:
                        observer.request_dispatched(logical_request_id=request_id)
                    if paid_controls_required:
                        _TRUSTED_VALIDATE_PAID_PRIVACY_POLICY(
                            self,
                            (model,),
                            request_provider_endpoints=(
                                request_provider_policy.configured_endpoints
                            ),
                        )
                        if (
                            _model_request_privacy_binding(self.effective_privacy_policy)
                            != accepted_privacy_binding
                        ):
                            raise OpenRouterPrivacyError(
                                "effective privacy authority changed before provider transport"
                            )
                    final_audit_routing_evidence = require_current_audit_selection(
                        phase="after lifecycle dispatch observation",
                        checked_at=datetime.now(UTC),
                    )
                    if final_audit_routing_evidence is not None:
                        last_dispatched_audit_routing_evidence = final_audit_routing_evidence
                    if _TRUSTED_REQUIRES_REAL_AUDIT_MODEL_REFRESH(
                        self,
                        role,
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        response_model=response_model,
                        schema_name=schema_name,
                        structured_output_mode=structured_output_mode,
                        context_package=context_package,
                    ):
                        final_refresh_routing_evidence = _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_REFRESH(
                            self,
                            role=role,
                            model=model,
                            system_prompt=system_prompt,
                            user_prompt=user_prompt,
                            response_model=response_model,
                            schema_name=schema_name,
                            structured_output_mode=structured_output_mode,
                            context_package=context_package,
                            checked_at=datetime.now(UTC),
                            qualification_binding=qualification_binding,
                            audit_routing_evidence=audit_routing_evidence,
                            provider_policy=request_provider_policy,
                        )
                        if final_refresh_routing_evidence != refresh_routing_evidence:
                            raise OpenRouterModelRefreshError(
                                "sealed audit model refresh changed immediately before provider "
                                "transport"
                            )
                        last_dispatched_refresh_routing_evidence = final_refresh_routing_evidence
                    require_current_refresh_pricing(phase="after lifecycle dispatch observation")
                    response = await _TRUSTED_BOUNDED_REQUEST(
                        self,
                        "POST",
                        "/chat/completions",
                        json_body=body,
                        max_bytes=max(
                            1_000_000,
                            request_token_plan.requested_completion_tokens * 32,
                        ),
                        trusted_pre_transport_check=(require_current_refresh_inside_transport_lock),
                    )
                    if paid_controls_required:
                        _TRUSTED_VALIDATE_TRANSPORT_PROVENANCE(self)
                except (httpx.TimeoutException, httpx.NetworkError):
                    await finalize_active(None)
                    if attempts >= attempt_limit:
                        raise OpenRouterTimeoutError("model request timed out") from None
                    await self._backoff(attempts, None)
                    continue
                except httpx.HTTPError:
                    await finalize_active(None)
                    raise OpenRouterSchemaError("model transport response was invalid") from None
                response_headers = response.headers
                try:
                    response_value = json.loads(
                        response.content,
                        parse_float=Decimal,
                    )
                except (UnicodeDecodeError, ValueError):
                    response_value = None
                if isinstance(response_value, dict):
                    _TRUSTED_ENSURE_NO_CREDENTIAL_IN_VALUE(self, response_value)
                    raw_payload = response_value
                if response.status_code in {401, 403}:
                    await finalize_active(None)
                    raise OpenRouterAuthenticationError("OpenRouter rejected the API credentials")
                if response.status_code == 402:
                    await finalize_active(None)
                    raise BudgetExhaustedError("OpenRouter account budget rejected the request")
                if response.status_code == 404:
                    await finalize_active(None)
                    raise OpenRouterModelError(f"configured model is unavailable: {model}")
                if is_retryable_status(response.status_code):
                    await finalize_active(None)
                    if attempts >= attempt_limit:
                        if response.status_code == 429:
                            raise OpenRouterRateLimitError(
                                "OpenRouter rate limit exhausted the retry policy"
                            )
                        if response.status_code in {408, 425}:
                            raise OpenRouterTimeoutError(
                                f"transient model failure (HTTP {response.status_code})"
                            )
                        raise OpenRouterProviderUnavailableError(
                            f"provider unavailable after retries (HTTP {response.status_code})"
                        )
                    await self._backoff(attempts, response.headers.get("Retry-After"))
                    continue
                if response.status_code >= 400:
                    await finalize_active(None)
                    raise OpenRouterModelError(
                        f"model request rejected with HTTP {response.status_code}"
                    )
                break

            payload = response_value
            if not isinstance(payload, dict):
                raise OpenRouterSchemaError("model provider returned invalid JSON data")
            _raise_provider_payload_error(payload, requested_model=model)
            raw_content = _response_content_if_string(payload)
            if raw_content is not None:
                response_hash = hashlib.sha256(raw_content.encode()).hexdigest()
            raw_usage = payload.get("usage")
            if isinstance(raw_usage, dict):
                initial_cost = _optional_cost_decimal(raw_usage.get("cost"))
                active_actual_cost = initial_cost
            initial_usage = _validate_usage(raw_usage)
            initial_cost = _optional_cost_decimal(initial_usage.get("cost"))
            assert initial_cost is not None
            active_actual_cost = initial_cost
            active_actual_prompt_tokens = _nonnegative_int(initial_usage.get("prompt_tokens"))
            active_actual_completion_tokens = _nonnegative_int(
                initial_usage.get("completion_tokens")
            )
            active_actual_reasoning_tokens = _observed_reasoning_tokens(initial_usage)
            envelope = _validate_completion_envelope(
                payload,
                response.headers,
                requested_model=model,
                provider_policy=request_provider_policy,
                endpoint_policy=endpoint_policy,
                model_identity=self._model_identities.get(model),
            )
            validated_envelope = envelope
            truncated_envelope_evidence = None
            if response_model is _TRUSTED_CANDIDATE_REVIEW_FRAMED_DOCUMENT_TYPE and (
                envelope.finish_reason.casefold() in _TRUNCATED_FINISH_REASONS
                or (
                    envelope.native_finish_reason is not None
                    and envelope.native_finish_reason.casefold() in _TRUNCATED_FINISH_REASONS
                )
            ):
                if not _candidate_review_protocol_boundary_is_pristine():
                    raise OpenRouterCandidateReviewBoundaryError(
                        "candidate-review completion boundary changed during transport"
                    )
                assert response_hash is not None
                try:
                    truncated_envelope_evidence = (
                        _TRUSTED_SEAL_CANDIDATE_REVIEW_TRUNCATED_ENVELOPE_EVIDENCE(
                            logical_request_id=request_id,
                            generation_id=envelope.generation_id,
                            generation_header_id=_header_value(
                                response.headers,
                                "x-generation-id",
                            ),
                            requested_model=envelope.requested_model,
                            returned_model=envelope.returned_model,
                            selected_model=envelope.selected_model,
                            response_provider_identity=(envelope.response_provider_identity),
                            selected_provider_endpoint=envelope.selected_provider,
                            selected_provider_identity=(envelope.selected_provider_identity),
                            selected_provider_name=envelope.selected_provider_name,
                            router_metadata_sha256=_canonical_sha256(envelope.router_metadata),
                            finish_reason=envelope.finish_reason,
                            native_finish_reason=envelope.native_finish_reason,
                            wire_schema_sha256=schema_hash,
                            response_sha256=response_hash,
                        )
                    )
                except CandidateReviewTruncationError:
                    raise OpenRouterCandidateReviewBoundaryError(
                        "candidate-review truncated envelope custody could not be sealed"
                    ) from None
            _raise_for_completion_finish(
                envelope,
                truncated_envelope_evidence=truncated_envelope_evidence,
            )
            initial_usage = envelope.usage
            active_actual_prompt_tokens = _nonnegative_int(initial_usage.get("prompt_tokens"))
            active_actual_completion_tokens = _nonnegative_int(
                initial_usage.get("completion_tokens")
            )
            active_actual_reasoning_tokens = _observed_reasoning_tokens(initial_usage)
            _validate_provider_token_usage(
                request_token_plan=request_token_plan,
                prompt_tokens=active_actual_prompt_tokens,
                completion_tokens=active_actual_completion_tokens,
                reasoning_tokens=_reasoning_tokens(initial_usage),
            )
            response_hash = hashlib.sha256(envelope.content.encode()).hexdigest()
            if self.privacy.store_raw_responses:
                _TRUSTED_STORE_DEBUG(
                    self,
                    request_id,
                    "response.json",
                    copy.deepcopy(payload),
                )
            content = envelope.content
            try:
                response_schema_generation.require_current(
                    response_model,
                    phase="before provider response decoding",
                )
                if response_model is _TRUSTED_CANDIDATE_REVIEW_FRAMED_DOCUMENT_TYPE:
                    if not _candidate_review_protocol_boundary_is_pristine():
                        raise OpenRouterCandidateReviewBoundaryError(
                            "candidate-review completion boundary changed during transport"
                        )
                    assert response_hash is not None
                    try:
                        framed_document = _TRUSTED_DECODE_COMPLETE_CANDIDATE_REVIEW_DOCUMENT(
                            content
                        )
                        _TRUSTED_NORMALIZE_CANDIDATE_REVIEW_DOCUMENT(
                            framed_document,
                            request_id=request_id,
                        )
                    except CandidateReviewTruncationError:
                        raise OpenRouterStructuredOutputError(
                            failure_code=StructuredOutputFailureCode.SCHEMA_VALIDATION_FAILED,
                        ) from None
                    decoded_output = cast(
                        StructuredOutputDecodeResult[ResponseT],
                        StructuredOutputDecodeResult(
                            value=framed_document,
                            original_response_sha256=response_hash,
                            validated_json_sha256=response_hash,
                            repair_evidence=None,
                        ),
                    )
                else:
                    decoded_output = _decode_structured_output_with_schema_generation(
                        content,
                        response_model,
                        schema_validator=response_schema_generation.validator,
                        core_schema=response_schema_generation.core_schema,
                        max_repair_attempts=self.execution.max_json_repair_attempts,
                    )
                response_schema_generation.require_current(
                    response_model,
                    phase="during provider response decoding",
                )
            except StructuredOutputDecodeError as output_error:
                raise OpenRouterStructuredOutputError(
                    failure_code=output_error.code,
                    repair_evidence=output_error.repair_evidence,
                ) from None
            parsed = decoded_output.value
            validated_response_hash = _canonical_sha256(parsed.model_dump(mode="json"))
            response_schema_generation.require_current(
                response_model,
                phase="during validated response hashing",
            )
            await finalize_active(active_actual_cost)
            ended_at = datetime.now(UTC)
            latency_ms = max(0, round((time.perf_counter() - started_clock) * 1_000))
            routing = self._routing_evidence(
                envelope=envelope,
                schema_hash=schema_hash,
                started_at=started_at,
                ended_at=ended_at,
                latency_ms=latency_ms,
                validation_status=(
                    "repaired_noncreditable" if decoded_output.repair_used else "valid"
                ),
                repair_used=decoded_output.repair_used,
                repair_evidence=decoded_output.repair_evidence,
                structured_output_plan=structured_output_plan,
                prompt_sha256=prompt_hash,
                request_body_sha256=request_body_hash,
                response_sha256=response_hash,
                decoded_response_sha256=decoded_output.validated_json_sha256,
                validated_response_sha256=validated_response_hash,
                qualification_binding=qualification_binding,
                provider_policy=request_provider_policy,
                host_model_fallback_used=fallback_used,
                request_token_plan=request_token_plan,
                token_reservations=attempt_reservations,
                context_request_evidence=context_request_evidence,
                audit_routing_evidence=last_dispatched_audit_routing_evidence,
                refresh_routing_evidence=last_dispatched_refresh_routing_evidence,
                refresh_pricing_routing_evidence=(last_dispatched_refresh_pricing_routing_evidence),
                refresh_pricing_control=refresh_pricing_control,
                refresh_pricing_attempt_routes=refresh_pricing_attempt_routes,
                refresh_pricing_reservation_checks=refresh_pricing_reservation_checks,
                refresh_pricing_transport_checks=refresh_pricing_transport_checks,
            )
            if expected_request_cost_preview is not None:
                routing.update(
                    {
                        "request_cost_preview_sha256": (
                            expected_request_cost_preview.preview_sha256
                        ),
                        "request_cost_preview_maximum_cost_usd_per_attempt_exact": (
                            expected_request_cost_preview.maximum_cost_usd_per_attempt_exact
                        ),
                        "request_cost_preview_maximum_cost_usd_all_attempts_exact": (
                            expected_request_cost_preview.maximum_cost_usd_all_attempts_exact
                        ),
                    }
                )
            reasoning_execution_evidence = (
                ReasoningExecutionEvidence.build(
                    request_plan=request_token_plan.reasoning_plan,
                    observed_reasoning_tokens=active_actual_reasoning_tokens,
                    provider_completion_tokens=active_actual_completion_tokens,
                    request_token_plan_sha256=request_token_plan.plan_sha256,
                    request_body_sha256=request_body_hash,
                )
                if request_token_plan.reasoning_plan is not None
                else None
            )
            usage_record = UsageRecord(
                request_id=request_id,
                role=role,
                execution_evidence=trusted_openrouter_execution_evidence(self),
                requested_model=model,
                returned_model=envelope.returned_model,
                actual_model=envelope.selected_model,
                provider=envelope.provider,
                model_family=model_family(model),
                timestamp=started_at,
                prompt_tokens=_nonnegative_int(initial_usage.get("prompt_tokens")),
                completion_tokens=_nonnegative_int(initial_usage.get("completion_tokens")),
                total_tokens=_nonnegative_int(initial_usage.get("total_tokens")),
                reported_cost_usd=float(initial_cost),
                accounted_cost_usd=accounted_cost_usd,
                reported_cost_usd_exact=format(initial_cost, "f"),
                accounted_cost_usd_exact=format(accounted_cost_usd_exact, "f"),
                routing=routing,
                prompt_sha256=prompt_hash,
                user_prompt_sha256=user_prompt_hash,
                response_sha256=response_hash,
                validated_response_sha256=validated_response_hash,
                request_body_sha256=request_body_hash,
                schema_sha256=schema_hash,
                openrouter_generation_id=envelope.generation_id,
                configured_provider_endpoints=list(request_provider_policy.configured_endpoints),
                actual_provider_endpoint=envelope.selected_provider,
                started_at=started_at,
                ended_at=ended_at,
                latency_ms=latency_ms,
                finish_reason=envelope.finish_reason,
                reasoning_tokens=_reasoning_tokens(initial_usage),
                reasoning_evidence=reasoning_execution_evidence,
                cached_tokens=_cached_tokens(initial_usage),
                retry_count=attempts - 1,
                validation_status=(
                    ModelRequestValidationStatus.INVALID_RESPONSE
                    if decoded_output.repair_used
                    else ModelRequestValidationStatus.VALID
                ),
                identity_strength=ModelIdentityStrength.UNBOUND,
                fallback_used=(
                    fallback_used
                    or envelope.router_attempt > 1
                    or envelope.router_attempt_count > 1
                    or envelope.router_metadata["strategy"] == "fallback"
                ),
                substitution_detected=False,
                status=("repaired_noncreditable" if decoded_output.repair_used else "success"),
                attempts=attempts,
            )
            if usage_record.execution_evidence is ExecutionEvidenceKind.REAL:
                usage_record = _attest_owned_real_usage_record(usage_record)
            self.usage.add(usage_record)
            usage_recorded = True
            self.logger.info(
                "Structured model request completed",
                extra={
                    "request_id": request_id,
                    "role": role,
                    "status": "success",
                },
            )
            return StructuredCompletion(value=parsed, usage_record=usage_record)
        except Exception as exc:
            terminal_error = exc
            if active_reservation is not None:
                try:
                    if active_network_attempted or active_reservation_committed:
                        await finalize_active(active_actual_cost)
                    else:
                        await release_active()
                except Exception as budget_error:
                    terminal_error = budget_error
            if not usage_recorded and attempt_reservations:
                raw_content = (
                    _response_content_if_string(raw_payload) if raw_payload is not None else None
                )
                if (
                    response_model is _TRUSTED_CANDIDATE_REVIEW_FRAMED_DOCUMENT_TYPE
                    and type(terminal_error) is OpenRouterTruncatedResponseError
                    and raw_content is not None
                    and _candidate_review_protocol_boundary_is_pristine()
                ):
                    finish_reason = _optional_finish_reason(raw_payload)
                    native_finish_reason = _optional_native_finish_reason(raw_payload)
                    if finish_reason is not None:
                        try:
                            truncation_projection = (
                                _TRUSTED_PROJECT_TRUNCATED_CANDIDATE_REVIEW_PREFIX(
                                    raw_content,
                                    finish_reason=finish_reason,
                                    native_finish_reason=native_finish_reason,
                                )
                            )
                            projection_custody_invalid = (
                                truncation_projection.original_response_sha256 != response_hash
                                or truncation_projection.wire_schema_sha256 != schema_hash
                            )
                        except CandidateReviewTruncationError:
                            pass
                        else:
                            if not projection_custody_invalid:
                                _TRUSTED_ATTACH_CANDIDATE_REVIEW_TRUNCATION_PROJECTION(
                                    terminal_error,
                                    truncation_projection,
                                )
                if (
                    isinstance(terminal_error, OpenRouterResponseIdentityError)
                    and raw_payload is not None
                ):
                    try:
                        preserved_unbound_response = _validate_preservable_structured_response(
                            raw_payload,
                            response_model=response_model,
                            response_schema_generation=response_schema_generation,
                        )
                    except OpenRouterSchemaError as preservation_error:
                        # A length marker cannot turn an already established
                        # identity violation into recoverable truncation.  Keep
                        # the stronger identity error and retain no value.
                        if not isinstance(
                            preservation_error,
                            OpenRouterTruncatedResponseError,
                        ):
                            terminal_error = preservation_error
                    if preserved_unbound_response is not None:
                        validated_response_hash = _canonical_sha256(
                            preserved_unbound_response.model_dump(mode="json")
                        )
                if (
                    preserved_unbound_response is None
                    and validated_response_hash is None
                    and raw_content is not None
                    and not isinstance(terminal_error, OpenRouterTruncatedResponseError)
                    and not _payload_has_truncation_marker(raw_payload)
                ):
                    try:
                        response_schema_generation.require_current(
                            response_model,
                            phase="before failed-response evidence decoding",
                        )
                        hash_only_response = _decode_structured_output_with_schema_generation(
                            raw_content,
                            response_model,
                            schema_validator=response_schema_generation.validator,
                            core_schema=response_schema_generation.core_schema,
                        ).value
                    except StructuredOutputDecodeError:
                        pass
                    else:
                        validated_response_hash = _canonical_sha256(
                            hash_only_response.model_dump(mode="json")
                        )
                ended_at = datetime.now(UTC)
                latency_ms = max(0, round((time.perf_counter() - started_clock) * 1_000))
                returned_model = (
                    validated_envelope.returned_model
                    if validated_envelope is not None
                    else (
                        _optional_string(raw_payload.get("model"))
                        if raw_payload is not None
                        else None
                    )
                )
                actual_provider = (
                    validated_envelope.selected_provider_name
                    if validated_envelope is not None
                    else (
                        _optional_string(raw_payload.get("provider"))
                        if raw_payload is not None
                        else None
                    )
                )
                failed_reasoning_evidence = (
                    ReasoningExecutionEvidence.build(
                        request_plan=request_token_plan.reasoning_plan,
                        observed_reasoning_tokens=active_actual_reasoning_tokens,
                        provider_completion_tokens=active_actual_completion_tokens,
                        request_token_plan_sha256=request_token_plan.plan_sha256,
                        request_body_sha256=request_body_hash,
                    )
                    if request_token_plan.reasoning_plan is not None
                    else None
                )
                failed_usage = UsageRecord(
                    request_id=request_id,
                    role=role,
                    execution_evidence=trusted_openrouter_execution_evidence(self),
                    requested_model=model,
                    returned_model=returned_model,
                    actual_model=(
                        validated_envelope.selected_model
                        if validated_envelope is not None
                        else None
                    ),
                    provider=actual_provider,
                    model_family=model_family(model),
                    timestamp=started_at,
                    prompt_tokens=_nonnegative_int(initial_usage.get("prompt_tokens")),
                    completion_tokens=_nonnegative_int(initial_usage.get("completion_tokens")),
                    total_tokens=_nonnegative_int(initial_usage.get("total_tokens")),
                    reported_cost_usd=(float(initial_cost) if initial_cost is not None else None),
                    accounted_cost_usd=accounted_cost_usd,
                    reported_cost_usd_exact=(
                        format(initial_cost, "f") if initial_cost is not None else None
                    ),
                    accounted_cost_usd_exact=format(accounted_cost_usd_exact, "f"),
                    routing=_TRUSTED_FAILURE_ROUTING_EVIDENCE(
                        self,
                        payload=raw_payload,
                        response_headers=response_headers,
                        schema_hash=schema_hash,
                        started_at=started_at,
                        ended_at=ended_at,
                        latency_ms=latency_ms,
                        error=terminal_error,
                        structured_output_plan=structured_output_plan,
                        request_body_sha256=request_body_hash,
                        response_sha256=response_hash,
                        validated_response_sha256=validated_response_hash,
                        qualification_binding=qualification_binding,
                        provider_policy=request_provider_policy,
                        requested_model=model,
                        model_identity=self._model_identities.get(model),
                        request_token_plan=request_token_plan,
                        token_reservations=attempt_reservations,
                        context_request_evidence=context_request_evidence,
                        audit_routing_evidence=last_dispatched_audit_routing_evidence,
                        refresh_routing_evidence=(last_dispatched_refresh_routing_evidence),
                        refresh_pricing_routing_evidence=(refresh_pricing_routing_evidence),
                        refresh_pricing_control=refresh_pricing_control,
                        refresh_pricing_attempt_routes=refresh_pricing_attempt_routes,
                        refresh_pricing_reservation_checks=(refresh_pricing_reservation_checks),
                        refresh_pricing_transport_checks=refresh_pricing_transport_checks,
                    ),
                    prompt_sha256=prompt_hash,
                    user_prompt_sha256=user_prompt_hash,
                    response_sha256=response_hash,
                    validated_response_sha256=validated_response_hash,
                    request_body_sha256=request_body_hash,
                    schema_sha256=schema_hash,
                    openrouter_generation_id=(
                        validated_envelope.generation_id
                        if validated_envelope is not None
                        else _response_generation_id(raw_payload, response_headers)
                    ),
                    configured_provider_endpoints=list(
                        request_provider_policy.configured_endpoints
                    ),
                    actual_provider_endpoint=(
                        validated_envelope.selected_provider
                        if validated_envelope is not None
                        else actual_provider
                    ),
                    started_at=started_at,
                    ended_at=ended_at,
                    latency_ms=latency_ms,
                    finish_reason=(
                        validated_envelope.finish_reason
                        if validated_envelope is not None
                        else _optional_finish_reason(raw_payload)
                    ),
                    reasoning_tokens=_reasoning_tokens(initial_usage),
                    reasoning_evidence=failed_reasoning_evidence,
                    cached_tokens=_cached_tokens(initial_usage),
                    retry_count=max(0, attempts - 1),
                    provider_error_classification=_provider_error_classification(terminal_error),
                    validation_status=_failure_validation_status(terminal_error),
                    fallback_used=(
                        fallback_used
                        or (
                            validated_envelope is not None
                            and (
                                validated_envelope.router_attempt > 1
                                or validated_envelope.router_attempt_count > 1
                                or validated_envelope.router_metadata["strategy"] == "fallback"
                            )
                        )
                    ),
                    substitution_detected=(
                        validated_envelope is None
                        and returned_model is not None
                        and returned_model
                        not in _accepted_response_models(
                            model,
                            self._model_identities.get(model),
                        )
                    ),
                    status=_failure_status(
                        terminal_error,
                        model,
                        raw_payload,
                        accepted_response_models=_accepted_response_models(
                            model,
                            self._model_identities.get(model),
                        ),
                    ),
                    attempts=max(1, attempts),
                )
                if failed_usage.execution_evidence is ExecutionEvidenceKind.REAL:
                    failed_usage = _attest_owned_real_usage_record(failed_usage)
                if (
                    response_model is _TRUSTED_CANDIDATE_REVIEW_FRAMED_DOCUMENT_TYPE
                    and type(terminal_error) is OpenRouterTruncatedResponseError
                ):
                    if not _candidate_review_protocol_boundary_is_pristine():
                        raise OpenRouterCandidateReviewBoundaryError(
                            "candidate-review completion boundary changed before usage custody"
                        ) from None
                    _TRUSTED_ATTACH_CANDIDATE_REVIEW_TRUNCATED_USAGE(
                        terminal_error,
                        failed_usage,
                    )
                self.usage.add(failed_usage)
                if preserved_unbound_response is not None and isinstance(
                    terminal_error, OpenRouterResponseIdentityError
                ):
                    completion = StructuredCompletion(
                        value=preserved_unbound_response,
                        usage_record=failed_usage,
                    )
                    self.logger.warning(
                        "Structured model response retained with unbound identity",
                        extra={
                            "request_id": request_id,
                            "role": role,
                            "status": "identity_unbound",
                        },
                    )
                    return completion
            self.logger.warning(
                "Structured model request failed",
                extra={
                    "request_id": request_id,
                    "role": role,
                    "status": type(terminal_error).__name__,
                },
            )
            if terminal_error is exc:
                raise
            raise terminal_error from exc

    def _record_context_preflight(
        self,
        *,
        request_id: str,
        logical_request_id: str,
        role: str,
        model: str,
        requested_completion_tokens: int,
        request_plan: RequestTokenPlan | None,
        planning_snapshot: ContextPlanningSnapshot | None = None,
        decision_source: ContextPreflightSource,
        reason: ContextPreflightReason,
        error: Exception,
        decision_evidence_sha256s: Sequence[str] = (),
    ) -> None:
        """Retain a hash-only host decision when provider transport did not begin."""

        endpoint_policy = self._endpoint_pricing.get(model)
        decision_payload = {
            "request_id": request_id,
            "logical_request_id": logical_request_id,
            "role": role,
            "requested_model": model,
            "decision_source": decision_source.value,
            "reason": reason.value,
            "error_class": type(error).__name__,
            "request_plan_sha256": request_plan.plan_sha256 if request_plan is not None else None,
            "planning_snapshot_sha256": (
                planning_snapshot.snapshot_sha256 if planning_snapshot is not None else None
            ),
            "endpoint_snapshot_sha256": (
                endpoint_policy.snapshot_sha256 if endpoint_policy is not None else None
            ),
        }
        evidence_hashes = {
            _canonical_sha256(decision_payload),
            *decision_evidence_sha256s,
        }
        if request_plan is not None:
            evidence_hashes.add(request_plan.plan_sha256)
        if planning_snapshot is not None:
            evidence_hashes.add(planning_snapshot.snapshot_sha256)
        self.context_preflight.add(
            ContextPreflightRequestEvidence.build(
                request_id=request_id,
                logical_request_id=logical_request_id,
                role=role,
                requested_model=model,
                request_state=ContextRequestState.PRE_FLIGHT_REJECTED,
                decision_source=decision_source,
                reason=reason,
                decision_evidence_sha256s=tuple(sorted(evidence_hashes)),
                estimated_prompt_tokens=(
                    request_plan.estimated_prompt_tokens
                    if request_plan is not None
                    else (
                        planning_snapshot.estimated_prompt_tokens
                        if planning_snapshot is not None
                        else None
                    )
                ),
                requested_completion_tokens=requested_completion_tokens,
                request_plan=request_plan,
                planning_snapshot=planning_snapshot,
            )
        )

    def _budget_preflight_reason(
        self,
        request_token_plan: RequestTokenPlan,
    ) -> ContextPreflightReason:
        remaining_input = self.budget.remaining_input_tokens
        remaining_output = self.budget.remaining_output_tokens
        if (
            remaining_input is not None
            and request_token_plan.prompt_byte_upper_bound_tokens > remaining_input
        ) or (
            remaining_output is not None
            and request_token_plan.requested_completion_tokens > remaining_output
        ):
            return ContextPreflightReason.GLOBAL_TOKEN_BUDGET
        return ContextPreflightReason.COST_BUDGET

    def _endpoint_request_cost_bound(
        self,
        *,
        model: str,
        request_material: str,
        request_token_plan: RequestTokenPlan,
        refresh_pricing_control: _AuditModelRefreshPricingRequestControl | None = None,
    ) -> EndpointRequestCostBound | None:
        if not self.budget.require_endpoint_cost_bound:
            return None
        registered_policy = self._endpoint_pricing.get(model)
        if registered_policy is None:
            raise UnprovenCostBoundError("paid request lacks validated endpoint pricing")
        if request_token_plan.route_intersection.exact_model_ids != (model,):
            raise UnprovenCostBoundError("request token plan differs from the priced model")
        ceilings = _structured_request_pricing_unit_ceilings(
            request_material=request_material,
            request_token_plan=request_token_plan,
        )
        output_tokens = request_token_plan.requested_completion_tokens
        registered_endpoints = registered_policy.endpoints
        if refresh_pricing_control is not None:
            if refresh_pricing_control.exact_model_id != model:
                raise UnprovenCostBoundError(
                    "refreshed-price control differs from the priced model"
                )
            matches = tuple(
                endpoint
                for endpoint in registered_endpoints
                if endpoint.provider_endpoint == refresh_pricing_control.provider_endpoint
            )
            if (
                len(matches) != 1
                or dict(matches[0].pricing) != dict(refresh_pricing_control.current_pricing)
                or matches[0].pricing_sha256 != refresh_pricing_control.current_pricing_sha256
            ):
                raise UnprovenCostBoundError(
                    "refreshed-price control differs from exact endpoint pricing"
                )
            registered_endpoints = matches
        bounds: list[EndpointRequestCostBound] = []
        for registered in registered_endpoints:
            if request_token_plan.prompt_byte_upper_bound_tokens > registered.max_prompt_tokens:
                raise UnprovenCostBoundError(
                    "conservative prompt bound exceeds an endpoint prompt-token limit"
                )
            if output_tokens > registered.max_completion_tokens:
                raise UnprovenCostBoundError(
                    "planned completion exceeds an endpoint completion-token limit"
                )
            if (
                request_token_plan.prompt_byte_upper_bound_tokens + output_tokens
                > registered.context_length
            ):
                raise UnprovenCostBoundError(
                    "conservative prompt and completion bounds exceed endpoint context"
                )
            bounded_pricing = (
                dict(refresh_pricing_control.cost_bound_pricing)
                if refresh_pricing_control is not None
                else dict(
                    _TRUSTED_PROVIDER_CAPPED_COST_BOUND_PRICING(
                        registered,
                        dict(registered_policy.routing_max_price),
                    )
                )
            )
            bounds.append(
                _trusted_endpoint_request_cost_bound_from_pricing(
                    exact_model_id=model,
                    provider_endpoint=registered.provider_endpoint,
                    request_material=request_material,
                    pricing=bounded_pricing,
                    maximum_units={field: ceilings[field] for field in bounded_pricing},
                )
            )
        return max(
            bounds,
            key=lambda bound: (
                _trusted_endpoint_request_maximum_cost_usd(bound),
                bound.provider_endpoint,
            ),
        )

    def _token_plan_routing_evidence(
        self,
        *,
        request_token_plan: RequestTokenPlan,
        reservations: Sequence[Reservation],
        context_request_evidence: ContextRequestEvidence | None,
        request_body_sha256: str,
        refresh_pricing_control: _AuditModelRefreshPricingRequestControl | None,
        refresh_pricing_attempt_routes: Mapping[str, AuditModelRefreshPricingRouteEvidence],
        refresh_pricing_reservation_checks: Mapping[str, datetime],
        refresh_pricing_transport_checks: Mapping[str, datetime],
    ) -> dict[str, Any]:
        _require_pristine_endpoint_cost_bound_types()
        if not reservations or len(reservations) > 32:
            raise OpenRouterCostControlError(
                "request usage lacks matching atomic token reservation evidence"
            )
        atomic_inventory = []
        for reservation in reservations:
            if (
                reservation.request_token_plan_sha256 != request_token_plan.plan_sha256
                or reservation.planned_prompt_tokens
                != request_token_plan.prompt_byte_upper_bound_tokens
                or reservation.planned_completion_tokens
                != request_token_plan.requested_completion_tokens
                or reservation.token_reservation_evidence is None
            ):
                raise OpenRouterCostControlError(
                    "request usage has inconsistent atomic token reservation evidence"
                )
            atomic_inventory.append(reservation.token_reservation_evidence)
        expected_ids = tuple(
            (
                request_token_plan.request_id
                if attempt == 1
                else f"{request_token_plan.request_id}:attempt:{attempt}"
            )
            for attempt in range(1, len(atomic_inventory) + 1)
        )
        if tuple(item.request_id for item in atomic_inventory) != expected_ids:
            raise OpenRouterCostControlError(
                "request usage has incomplete atomic token reservation attempts"
            )
        request_limit_inventory = tuple(
            reservation.request_limit_reservation_evidence for reservation in reservations
        )
        if any(item is not None for item in request_limit_inventory):
            if any(item is None for item in request_limit_inventory):
                raise OpenRouterCostControlError(
                    "scheduled request-limit reservation evidence is incomplete"
                )
            scheduled_inventory = tuple(
                item for item in request_limit_inventory if item is not None
            )
            request_limit_start = scheduled_inventory[0].request_limit_count_before
            if (
                tuple(item.request_id for item in scheduled_inventory) != expected_ids
                or len({item.request_limit_scope for item in scheduled_inventory}) != 1
                or tuple(item.request_limit_count_before for item in scheduled_inventory)
                != tuple(
                    range(
                        request_limit_start,
                        request_limit_start + len(scheduled_inventory),
                    )
                )
                or tuple(item.request_limit_count_after for item in scheduled_inventory)
                != tuple(
                    range(
                        request_limit_start + 1,
                        request_limit_start + len(scheduled_inventory) + 1,
                    )
                )
                or len({item.request_limit_maximum for item in scheduled_inventory}) != 1
            ):
                raise OpenRouterCostControlError(
                    "scheduled request-limit reservation attempts are incomplete or unordered"
                )
        atomic_evidence = atomic_inventory[-1]
        atomic_hashes = [item.evidence_sha256 for item in atomic_inventory]
        evidence: dict[str, Any] = {
            "request_token_plan": request_token_plan.model_dump(mode="json"),
            "request_token_plan_sha256": request_token_plan.plan_sha256,
            "atomic_token_reservations": [
                item.model_dump(mode="json") for item in atomic_inventory
            ],
            "atomic_token_reservation_sha256s": atomic_hashes,
            "atomic_token_reservation": atomic_evidence.model_dump(mode="json"),
            "atomic_token_reservation_sha256": atomic_evidence.evidence_sha256,
        }
        if any(item is not None for item in request_limit_inventory):
            scheduled_inventory = tuple(
                item for item in request_limit_inventory if item is not None
            )
            request_limit_evidence = scheduled_inventory[-1]
            evidence.update(
                {
                    "atomic_request_limit_reservations": [
                        item.model_dump(mode="json") for item in scheduled_inventory
                    ],
                    "atomic_request_limit_reservation_sha256s": [
                        item.evidence_sha256 for item in scheduled_inventory
                    ],
                    "atomic_request_limit_reservation": request_limit_evidence.model_dump(
                        mode="json"
                    ),
                    "atomic_request_limit_reservation_sha256": (
                        request_limit_evidence.evidence_sha256
                    ),
                }
            )
        if context_request_evidence is not None:
            evidence["context_request_evidence"] = context_request_evidence.model_dump(mode="json")
            evidence["context_request_evidence_sha256"] = context_request_evidence.evidence_sha256
        pricing_maps_present = bool(
            refresh_pricing_attempt_routes
            or refresh_pricing_reservation_checks
            or refresh_pricing_transport_checks
        )
        if refresh_pricing_control is None:
            if pricing_maps_present:
                raise OpenRouterCostControlError(
                    "request usage has refreshed-price attempts without a sealed control"
                )
            return evidence
        binding = self._audit_model_refresh_pricing_binding
        if binding is None:
            raise OpenRouterCostControlError(
                "request usage refreshed-price attempts lack their exact live authority"
            )
        reservation_ids = tuple(reservation.identifier for reservation in reservations)
        if (
            tuple(refresh_pricing_attempt_routes) != reservation_ids
            or tuple(refresh_pricing_reservation_checks) != reservation_ids
            or not set(refresh_pricing_transport_checks).issubset(reservation_ids)
        ):
            raise OpenRouterCostControlError(
                "request usage refreshed-price attempts are incomplete or unordered"
            )
        pricing_attempts: list[AuditModelRefreshPricingAttemptEvidence] = []
        try:
            for attempt_index, reservation in enumerate(reservations, start=1):
                endpoint_cost_bound = reservation.endpoint_cost_bound
                if endpoint_cost_bound is None:
                    raise ValueError("refreshed-price attempt lacks its endpoint cost bound")
                pricing_attempts.append(
                    AuditModelRefreshPricingAttemptEvidence.from_bound(
                        logical_request_id=request_token_plan.request_id,
                        attempt_request_id=reservation.identifier,
                        attempt_index=attempt_index,
                        reservation_checked_at=(
                            refresh_pricing_reservation_checks[reservation.identifier]
                        ),
                        transport_checked_at=refresh_pricing_transport_checks.get(
                            reservation.identifier
                        ),
                        current_endpoint_snapshot_sha256=(
                            refresh_pricing_control.current_endpoint_snapshot_sha256
                        ),
                        request_body_sha256=request_body_sha256,
                        pricing_evidence=binding.evidence,
                        pricing_authority=binding.authority,
                        pricing_route=refresh_pricing_attempt_routes[reservation.identifier],
                        endpoint_cost_bound=endpoint_cost_bound,
                        provider_max_price=dict(refresh_pricing_control.routing_max_price),
                    )
                )
        except (AttributeError, KeyError, ValueError) as exc:
            raise OpenRouterCostControlError(
                f"request usage refreshed-price attempt evidence is invalid: {exc}"
            ) from exc
        final_pricing_attempt = pricing_attempts[-1]
        evidence.update(
            {
                "audit_model_refresh_pricing_attempts": [
                    item.model_dump(mode="json") for item in pricing_attempts
                ],
                "audit_model_refresh_pricing_attempt_sha256s": [
                    item.evidence_sha256 for item in pricing_attempts
                ],
                "audit_model_refresh_pricing_attempt": final_pricing_attempt.model_dump(
                    mode="json"
                ),
                "audit_model_refresh_pricing_attempt_sha256": (
                    final_pricing_attempt.evidence_sha256
                ),
            }
        )
        return evidence

    def _privacy_routing_evidence(
        self,
        *,
        selected_provider_endpoint: str | None,
    ) -> dict[str, Any]:
        policy = self.effective_privacy_policy
        if policy is None:
            return {}
        endpoint_policy_class: str | None = None
        if self.privacy.require_zdr:
            endpoint_policy_class = EndpointPolicyClass.ZDR.value
        elif policy is not None and selected_provider_endpoint is not None:
            disclosure = next(
                (
                    item
                    for item in policy.endpoint_disclosures
                    if item.provider_endpoint.casefold() == selected_provider_endpoint.casefold()
                ),
                None,
            )
            endpoint_policy_class = (
                disclosure.policy_class.value if disclosure is not None else None
            )
        return {
            "privacy_profile": self.privacy.profile.value,
            "privacy_authorization": (
                "STRICT_ZDR_ENFORCED" if self.privacy.require_zdr else "CONSENT_BOUND_NON_ZDR"
            ),
            "effective_privacy_policy_sha256": (
                policy.evidence_sha256 if policy is not None else None
            ),
            "privacy_source_sha256": policy.source_sha256 if policy is not None else None,
            "privacy_source_provenance_sha256": (
                policy.source_provenance_sha256 if policy is not None else None
            ),
            "privacy_source_classification": (
                policy.source_classification.value if policy is not None else None
            ),
            "privacy_source_proof_kind": policy.source_proof_kind if policy is not None else None,
            "privacy_consent_file_sha256": (
                policy.consent_file_sha256 if policy is not None else None
            ),
            "privacy_consent_sha256": policy.consent_sha256 if policy is not None else None,
            "privacy_consent_expires_at": (
                policy.consent_expires_at.isoformat()
                if policy is not None and policy.consent_expires_at is not None
                else None
            ),
            "privacy_endpoint_policy_class": endpoint_policy_class,
        }

    def _audit_model_selection_routing_evidence(
        self,
        binding: AuditModelRoutingEvidence | None,
    ) -> dict[str, Any]:
        """Project one checked audit route without treating serialized evidence as authority."""

        if binding is None:
            return {}
        from mmaudit.models.policy_selection import AuditModelRoutingEvidence

        if self._audit_model_selection is None:
            raise OpenRouterPolicyEligibilityError(
                "audit routing evidence lacks its live selection authority"
            )
        try:
            validated = AuditModelRoutingEvidence.model_validate_json(
                binding.model_dump_json(),
                strict=True,
            )
        except (AttributeError, ValueError) as exc:
            raise OpenRouterPolicyEligibilityError(
                "audit routing evidence is structurally invalid"
            ) from exc
        if validated != binding:
            raise OpenRouterPolicyEligibilityError(
                "audit routing evidence changed during usage projection"
            )
        metadata = dict(validated.request_metadata())
        routing_evidence_sha256 = metadata.pop("routing_evidence_sha256")
        return {
            **metadata,
            "audit_policy_routing_evidence_sha256": routing_evidence_sha256,
            "audit_selection_capability_sha256": (self._audit_model_selection.capability_sha256),
            "audit_model_routing_evidence": validated.model_dump(mode="json"),
        }

    def _audit_model_refresh_routing_evidence(
        self,
        route_evidence: AuditModelRefreshRouteEvidence | None,
    ) -> dict[str, Any]:
        """Project the last dispatched typed refresh veto without granting authority."""

        if route_evidence is None:
            return {}
        from mmaudit.models.refresh_runtime import (
            AuditModelRefreshEvidence,
            AuditModelRefreshRouteEvidence,
        )

        binding = self._audit_model_refresh_binding
        if binding is None:
            raise OpenRouterModelRefreshError(
                "refresh route usage evidence lacks its live guard binding"
            )
        try:
            evidence = AuditModelRefreshEvidence.model_validate_json(
                binding.evidence.model_dump_json(),
                strict=True,
            )
            route = AuditModelRefreshRouteEvidence.model_validate_json(
                route_evidence.model_dump_json(),
                strict=True,
            )
        except (AttributeError, ValueError) as exc:
            raise OpenRouterModelRefreshError(
                "refresh route usage evidence is structurally invalid"
            ) from exc
        matches = tuple(
            item
            for item in evidence.routes
            if item.exact_model_id == route.exact_model_id and item.audit_selected
        )
        if (
            evidence != binding.evidence
            or route != route_evidence
            or len(matches) != 1
            or matches[0] != route
            or evidence.evidence_sha256 != binding.guard.evidence_sha256
            or evidence.workflow_status_sha256 != binding.guard.workflow_status_sha256
            or evidence.snapshot_sha256 != binding.guard.snapshot_sha256
            or route.runtime_authorized
            or evidence.technical_selection_authorized
            or evidence.audit_selection_authorized
            or evidence.provider_access_authorized
            or evidence.production_promotion_authorized
        ):
            raise OpenRouterModelRefreshError(
                "refresh route usage evidence differs from its dispatched veto guard"
            )
        return {
            "audit_model_refresh_evidence_sha256": evidence.evidence_sha256,
            "audit_model_refresh_workflow_status_sha256": (evidence.workflow_status_sha256),
            "audit_model_refresh_snapshot_sha256": evidence.snapshot_sha256,
            "audit_model_refresh_route_evidence_sha256": route.route_evidence_sha256,
            "audit_model_refresh_guard_capability_sha256": (binding.guard.capability_sha256),
            "audit_model_refresh_technical_route_set_sha256": (evidence.technical_route_set_sha256),
            "audit_model_refresh_audit_route_set_sha256": evidence.audit_route_set_sha256,
            "audit_model_refresh_expires_at": evidence.expires_at.isoformat(),
            "audit_model_refresh_route_evidence": route.model_dump(mode="json"),
        }

    def _audit_model_refresh_request_metadata(
        self,
        route_evidence: AuditModelRefreshRouteEvidence | None,
    ) -> dict[str, str]:
        """Return namespaced scalar refresh joins for the exact provider request body."""

        if route_evidence is None:
            return {}
        projection = self._audit_model_refresh_routing_evidence(route_evidence)
        return {
            "mmaudit_refresh_evidence_sha256": projection["audit_model_refresh_evidence_sha256"],
            "mmaudit_refresh_workflow_status_sha256": projection[
                "audit_model_refresh_workflow_status_sha256"
            ],
            "mmaudit_refresh_snapshot_sha256": projection["audit_model_refresh_snapshot_sha256"],
            "mmaudit_refresh_route_evidence_sha256": projection[
                "audit_model_refresh_route_evidence_sha256"
            ],
            "mmaudit_refresh_guard_capability_sha256": projection[
                "audit_model_refresh_guard_capability_sha256"
            ],
            "mmaudit_refresh_technical_route_set_sha256": projection[
                "audit_model_refresh_technical_route_set_sha256"
            ],
            "mmaudit_refresh_audit_route_set_sha256": projection[
                "audit_model_refresh_audit_route_set_sha256"
            ],
            "mmaudit_refresh_expires_at": projection["audit_model_refresh_expires_at"],
        }

    def _audit_model_refresh_pricing_routing_evidence(
        self,
        route_evidence: AuditModelRefreshPricingRouteEvidence | None,
    ) -> dict[str, Any]:
        """Project the exact accepted current price route without granting authority."""

        if route_evidence is None:
            return {}
        from mmaudit.models.refresh_runtime import (
            AuditModelRefreshPricingEvidence,
            AuditModelRefreshPricingRouteEvidence,
        )

        binding = self._audit_model_refresh_pricing_binding
        refresh = self._audit_model_refresh_binding
        if binding is None or refresh is None:
            raise OpenRouterModelRefreshPricingError(
                "refresh pricing usage evidence lacks exact live authority custody"
            )
        try:
            evidence = AuditModelRefreshPricingEvidence.model_validate_json(
                binding.evidence.model_dump_json(),
                strict=True,
            )
            route = AuditModelRefreshPricingRouteEvidence.model_validate_json(
                route_evidence.model_dump_json(),
                strict=True,
            )
        except (AttributeError, ValueError) as exc:
            raise OpenRouterModelRefreshPricingError(
                "refresh pricing usage evidence is structurally invalid"
            ) from exc
        matches = tuple(
            item
            for item in evidence.routes
            if item.exact_model_id == route.exact_model_id and item.audit_selected
        )
        if (
            evidence != binding.evidence
            or route != route_evidence
            or len(matches) != 1
            or matches[0] != route
            or evidence.evidence_sha256 != binding.authority.pricing_evidence_sha256
            or evidence.refresh_evidence_sha256 != refresh.evidence.evidence_sha256
            or evidence.refresh_guard_capability_sha256 != refresh.guard.capability_sha256
            or route.pricing_use_authorized
            or route.provider_access_authorized
            or route.model_selection_authorized
            or evidence.pricing_use_authorized
            or evidence.technical_selection_authorized
            or evidence.audit_selection_authorized
            or evidence.provider_access_authorized
            or evidence.production_promotion_authorized
        ):
            raise OpenRouterModelRefreshPricingError(
                "refresh pricing usage route differs from its exact live authority"
            )
        return {
            "audit_model_refresh_pricing_evidence_sha256": evidence.evidence_sha256,
            "audit_model_refresh_pricing_workflow_status_sha256": (evidence.workflow_status_sha256),
            "audit_model_refresh_pricing_previous_snapshot_sha256": (
                evidence.previous_snapshot_sha256
            ),
            "audit_model_refresh_pricing_current_snapshot_sha256": (
                evidence.current_snapshot_sha256
            ),
            "audit_model_refresh_pricing_refresh_evidence_sha256": (
                evidence.refresh_evidence_sha256
            ),
            "audit_model_refresh_pricing_refresh_guard_capability_sha256": (
                evidence.refresh_guard_capability_sha256
            ),
            "audit_model_refresh_pricing_route_evidence_sha256": (route.route_evidence_sha256),
            "audit_model_refresh_pricing_authority_capability_sha256": (
                binding.authority.capability_sha256
            ),
            "audit_model_refresh_pricing_technical_route_set_sha256": (
                evidence.technical_pricing_route_set_sha256
            ),
            "audit_model_refresh_pricing_audit_route_set_sha256": (
                evidence.audit_pricing_route_set_sha256
            ),
            "audit_model_refresh_pricing_qualified_pricing_snapshot_sha256": (
                route.qualified_pricing_snapshot_sha256
            ),
            "audit_model_refresh_pricing_current_pricing_snapshot_sha256": (
                route.current_pricing_sha256
            ),
            "audit_model_refresh_pricing_tolerance_fraction": (evidence.pricing_tolerance_fraction),
            "audit_model_refresh_pricing_expires_at": evidence.expires_at.isoformat(),
            "audit_model_refresh_pricing_route_evidence": route.model_dump(mode="json"),
        }

    def _audit_model_refresh_pricing_request_metadata(
        self,
        route_evidence: AuditModelRefreshPricingRouteEvidence | None,
    ) -> dict[str, str]:
        """Return scalar refreshed-price hashes committed into the provider body."""

        if route_evidence is None:
            return {}
        projection = self._audit_model_refresh_pricing_routing_evidence(route_evidence)
        return {
            "mmaudit_refresh_pricing_evidence_sha256": projection[
                "audit_model_refresh_pricing_evidence_sha256"
            ],
            "mmaudit_refresh_pricing_route_sha256": projection[
                "audit_model_refresh_pricing_route_evidence_sha256"
            ],
            "mmaudit_refresh_pricing_authority_sha256": projection[
                "audit_model_refresh_pricing_authority_capability_sha256"
            ],
            "mmaudit_refresh_pricing_baseline_sha256": projection[
                "audit_model_refresh_pricing_qualified_pricing_snapshot_sha256"
            ],
            "mmaudit_refresh_pricing_current_sha256": projection[
                "audit_model_refresh_pricing_current_pricing_snapshot_sha256"
            ],
            "mmaudit_refresh_pricing_expires_at": projection[
                "audit_model_refresh_pricing_expires_at"
            ],
        }

    def _audit_policy_decision_evidence_sha256s(
        self,
        routing_evidence: AuditModelRoutingEvidence | None,
        *,
        refresh_routing_evidence: AuditModelRefreshRouteEvidence | None = None,
    ) -> tuple[str, ...]:
        """Return hash-only joins for a policy routing decision or refusal."""

        hashes: set[str] = set()
        if self._audit_model_selection is not None:
            hashes.add(self._audit_model_selection.capability_sha256)
        if self._audit_policy_binding is not None:
            hashes.update(
                {
                    self._audit_policy_binding.audit_context.audit_scope_sha256,
                    self._audit_policy_binding.audit_context.source_sha256,
                    self._audit_policy_binding.audit_context.context_sha256,
                    self._audit_policy_binding.client_constraints.constraints_sha256,
                }
            )
        if routing_evidence is not None:
            hashes.add(routing_evidence.routing_evidence_sha256)
        refresh_binding = self._audit_model_refresh_binding
        if refresh_binding is not None:
            hashes.update(
                {
                    refresh_binding.evidence.evidence_sha256,
                    refresh_binding.evidence.workflow_status_sha256,
                    refresh_binding.evidence.snapshot_sha256,
                    refresh_binding.guard.capability_sha256,
                }
            )
        if refresh_routing_evidence is not None:
            hashes.add(refresh_routing_evidence.route_evidence_sha256)
        return tuple(sorted(hashes))

    def _routing_evidence(
        self,
        *,
        envelope: CompletionEnvelope,
        schema_hash: str,
        started_at: datetime,
        ended_at: datetime,
        latency_ms: float,
        validation_status: str,
        repair_used: bool,
        repair_evidence: StructuredOutputRepairEvidence | None,
        structured_output_plan: _StructuredOutputRequestPlan,
        prompt_sha256: str,
        request_body_sha256: str,
        response_sha256: str,
        decoded_response_sha256: str,
        validated_response_sha256: str,
        qualification_binding: OpenRouterQualificationRoutingEvidence | None,
        provider_policy: OpenRouterProviderPolicy,
        host_model_fallback_used: bool,
        request_token_plan: RequestTokenPlan,
        token_reservations: Sequence[Reservation],
        context_request_evidence: ContextRequestEvidence | None,
        audit_routing_evidence: AuditModelRoutingEvidence | None,
        refresh_routing_evidence: AuditModelRefreshRouteEvidence | None,
        refresh_pricing_routing_evidence: (AuditModelRefreshPricingRouteEvidence | None),
        refresh_pricing_control: _AuditModelRefreshPricingRequestControl | None,
        refresh_pricing_attempt_routes: Mapping[str, AuditModelRefreshPricingRouteEvidence],
        refresh_pricing_reservation_checks: Mapping[str, datetime],
        refresh_pricing_transport_checks: Mapping[str, datetime],
        repair_request: bool = False,
    ) -> dict[str, Any]:
        usage = envelope.usage
        endpoint_policy = self._endpoint_pricing.get(envelope.requested_model)
        endpoint_pricing = (
            endpoint_policy.endpoint(envelope.selected_provider)
            if endpoint_policy is not None
            else None
        )
        model_identity = self._model_identities.get(envelope.requested_model)
        provider_fallback_used = (
            envelope.router_attempt > 1
            or envelope.router_attempt_count > 1
            or envelope.router_metadata["strategy"] == "fallback"
        )
        provider_policy_sha256 = _canonical_sha256(
            provider_policy.as_request_payload(
                require_zdr=self.privacy.require_zdr,
                require_parameters=structured_output_plan.require_parameters,
            )
        )
        structured_output_evidence: dict[str, Any] | None = None
        if (
            endpoint_policy is not None
            and endpoint_pricing is not None
            and provider_policy.configured_endpoints
        ):
            effective_parameters = output_mode_capability_parameters(
                structured_output_plan.mode,
                endpoint_policy.structured_output_parameters,
            )
            if not set(effective_parameters).issubset(
                endpoint_pricing.structured_output_parameters
            ):
                effective_parameters = output_mode_capability_parameters(
                    structured_output_plan.mode,
                    endpoint_pricing.structured_output_parameters,
                )
            response_format = (
                StructuredOutputResponseFormat.JSON_SCHEMA
                if structured_output_plan.mode is StructuredOutputMode.NATIVE_JSON_SCHEMA
                else (
                    StructuredOutputResponseFormat.JSON_OBJECT
                    if structured_output_plan.mode is StructuredOutputMode.JSON_OBJECT
                    else StructuredOutputResponseFormat.OMITTED
                )
            )
            structured_output_evidence = seal_structured_output_evidence(
                requested_mode=structured_output_plan.mode,
                achieved_mode=structured_output_plan.mode,
                configured_provider_endpoints=(provider_policy.configured_endpoints),
                selected_provider_endpoint=envelope.selected_provider,
                endpoint_snapshot_sha256=endpoint_policy.snapshot_sha256,
                output_capability_sha256=endpoint_policy.output_capability_sha256,
                endpoint_structured_output_parameters=effective_parameters,
                prompt_sha256=prompt_sha256,
                request_body_sha256=request_body_sha256,
                provider_policy_sha256=provider_policy_sha256,
                schema_sha256=schema_hash,
                original_response_sha256=response_sha256,
                decoded_response_sha256=decoded_response_sha256,
                validated_response_sha256=validated_response_sha256,
                response_format=response_format,
                required_provider_parameters=(structured_output_plan.required_provider_parameters),
                provider_require_parameters=(structured_output_plan.require_parameters),
                reasoning_request_sha256=(structured_output_plan.reasoning_request_sha256),
                request_shape_sha256=(structured_output_plan.request_shape_sha256),
                strict_protocol_sha256=(structured_output_plan.strict_protocol_sha256),
                repair_evidence=repair_evidence,
            ).model_dump(mode="json")
        if (
            qualification_binding is not None
            and envelope.selected_provider_name != qualification_binding.approved_provider_name
        ):
            raise OpenRouterResponseIdentityError(
                "provider response differs from the qualification provider binding",
                diagnostic_code="qualification_provider_mismatch",
                validation_status=ModelRequestValidationStatus.PROVIDER_MISMATCH,
            )
        if audit_routing_evidence is not None and (
            audit_routing_evidence.route.exact_model_id != envelope.requested_model
            or audit_routing_evidence.route.provider_endpoint != envelope.selected_provider
            or audit_routing_evidence.route.provider_name != envelope.selected_provider_name
        ):
            raise OpenRouterResponseIdentityError(
                "provider response differs from the policy-eligible audit route",
                diagnostic_code="policy_eligible_route_mismatch",
                validation_status=ModelRequestValidationStatus.PROVIDER_MISMATCH,
            )
        if refresh_routing_evidence is not None and (
            refresh_routing_evidence.exact_model_id != envelope.requested_model
            or refresh_routing_evidence.approved_provider_endpoint != envelope.selected_provider
            or refresh_routing_evidence.approved_provider_name != envelope.selected_provider_name
            or refresh_routing_evidence.structured_output_mode is not structured_output_plan.mode
        ):
            raise OpenRouterResponseIdentityError(
                "provider response differs from the current model refresh route",
                diagnostic_code="model_refresh_route_mismatch",
                validation_status=ModelRequestValidationStatus.PROVIDER_MISMATCH,
            )
        if refresh_pricing_routing_evidence is not None and (
            refresh_pricing_routing_evidence.exact_model_id != envelope.requested_model
            or refresh_pricing_routing_evidence.approved_provider_endpoint
            != envelope.selected_provider
        ):
            raise OpenRouterResponseIdentityError(
                "provider response differs from the refreshed-price route",
                diagnostic_code="model_refresh_pricing_route_mismatch",
                validation_status=ModelRequestValidationStatus.PROVIDER_MISMATCH,
            )
        evidence: dict[str, Any] = {
            "generation_id": envelope.generation_id,
            "requested_model": envelope.requested_model,
            "provider": envelope.provider,
            "selected_model": envelope.selected_model,
            "canonical_model": (
                model_identity.canonical_slug
                if model_identity is not None
                else envelope.returned_model
            ),
            "selected_provider_endpoint": envelope.selected_provider,
            "selected_provider_identity": envelope.selected_provider_identity,
            "selected_provider_name": envelope.selected_provider_name,
            "response_provider_identity": envelope.response_provider_identity,
            "router_strategy": envelope.router_metadata["strategy"],
            "router_attempt": envelope.router_attempt,
            "router_attempt_count": envelope.router_attempt_count,
            "router_attempts_observed": envelope.router_attempts_observed,
            "router_metadata_sha256": _canonical_sha256(envelope.router_metadata),
            "router_pipeline": [dict(stage) for stage in envelope.pipeline],
            "finish_reason": envelope.finish_reason,
            "native_finish_reason": envelope.native_finish_reason,
            "reasoning_tokens": _reasoning_tokens(usage),
            "cached_tokens": _cached_tokens(usage),
            "schema_sha256": schema_hash,
            "provider_policy_sha256": provider_policy_sha256,
            "endpoint_snapshot_sha256": (
                refresh_pricing_control.current_endpoint_snapshot_sha256
                if refresh_pricing_control is not None
                else (endpoint_policy.snapshot_sha256 if endpoint_policy is not None else None)
            ),
            "endpoint_pricing_sha256": (
                endpoint_pricing.pricing_sha256 if endpoint_pricing is not None else None
            ),
            "catalog_identity_binding_sha256": (
                model_identity.catalog_identity_binding_sha256
                if model_identity is not None
                else None
            ),
            "model_metadata_snapshot_sha256": (
                model_identity.model_metadata_snapshot_sha256
                if model_identity is not None
                else None
            ),
            "catalog_snapshot_sha256": (
                model_identity.catalog_snapshot_sha256 if model_identity is not None else None
            ),
            "discovery_provenance_sha256": (
                model_identity.discovery_provenance_sha256 if model_identity is not None else None
            ),
            "discovery_evidence_sha256": (
                model_identity.discovery_evidence_sha256 if model_identity is not None else None
            ),
            "accepted_model_aliases": (
                sorted(model_identity.accepted_response_models)
                if model_identity is not None
                else [envelope.requested_model]
            ),
            "identity_snapshot_sha256": (
                model_identity.snapshot.snapshot_sha256 if model_identity is not None else None
            ),
            "identity_snapshot_expires_at": (
                model_identity.snapshot.expires_at.isoformat()
                if model_identity is not None and model_identity.snapshot.expires_at is not None
                else None
            ),
            "identity_model_author": (
                model_identity.snapshot.model_author if model_identity is not None else None
            ),
            "provisional_identity_strength": (
                ModelIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND.value
                if model_identity is not None
                else ModelIdentityStrength.UNBOUND.value
            ),
            "identity_binding_status": (
                "generation_metadata_pending"
                if model_identity is not None
                else "identity_metadata_unregistered"
            ),
            "configured_provider_only": list(provider_policy.only),
            "configured_provider_order": list(provider_policy.order),
            "provider_fallbacks_allowed": provider_policy.allow_fallbacks,
            "host_model_fallback_used": host_model_fallback_used,
            "provider_fallback_used": provider_fallback_used,
            "certification_request": provider_policy.certification,
            "zdr_requested": self.privacy.require_zdr,
            "data_collection": "deny",
            "request_started_at": started_at.isoformat(),
            "request_ended_at": ended_at.isoformat(),
            "latency_ms": round(latency_ms, 3),
            "validation_status": validation_status,
            "repair_used": repair_used,
            "repair_request": repair_request,
            "repair_evidence": (
                repair_evidence.model_dump(mode="json") if repair_evidence is not None else None
            ),
            "structured_output_mode": structured_output_plan.mode.value,
            "structured_output_supported_modes": (
                [mode.value for mode in endpoint_policy.supported_output_modes]
                if endpoint_policy is not None
                else [StructuredOutputMode.NATIVE_JSON_SCHEMA.value]
            ),
            "structured_output_capability_sha256": (
                endpoint_policy.output_capability_sha256
                if endpoint_policy is not None
                else _canonical_sha256(
                    {
                        "execution_evidence": trusted_openrouter_execution_evidence(self).value,
                        "mode": StructuredOutputMode.NATIVE_JSON_SCHEMA.value,
                        "model": envelope.requested_model,
                    }
                )
            ),
            "structured_output_request_shape_sha256": (structured_output_plan.request_shape_sha256),
            "structured_output_require_parameters": (structured_output_plan.require_parameters),
            "structured_output_required_provider_parameters": list(
                structured_output_plan.required_provider_parameters
            ),
            "structured_output_reasoning_request_sha256": (
                structured_output_plan.reasoning_request_sha256
            ),
            "structured_output_response_format": (
                structured_output_plan.response_format["type"]
                if structured_output_plan.response_format is not None
                else None
            ),
            "structured_output_protocol_sha256": (structured_output_plan.strict_protocol_sha256),
            "structured_output_request_body_sha256": request_body_sha256,
            "structured_output_original_response_sha256": response_sha256,
            "structured_output_validated_response_sha256": (validated_response_sha256),
            "structured_output": structured_output_evidence,
            "output_capability_sha256": (
                endpoint_policy.output_capability_sha256 if endpoint_policy is not None else None
            ),
        }
        evidence.update(
            self._privacy_routing_evidence(
                selected_provider_endpoint=envelope.selected_provider,
            )
        )
        evidence.update(
            self._token_plan_routing_evidence(
                request_token_plan=request_token_plan,
                reservations=token_reservations,
                context_request_evidence=context_request_evidence,
                request_body_sha256=request_body_sha256,
                refresh_pricing_control=refresh_pricing_control,
                refresh_pricing_attempt_routes=refresh_pricing_attempt_routes,
                refresh_pricing_reservation_checks=refresh_pricing_reservation_checks,
                refresh_pricing_transport_checks=refresh_pricing_transport_checks,
            )
        )
        if qualification_binding is not None:
            evidence.update(qualification_binding.routing_evidence())
        evidence.update(self._audit_model_selection_routing_evidence(audit_routing_evidence))
        evidence.update(self._audit_model_refresh_routing_evidence(refresh_routing_evidence))
        evidence.update(
            self._audit_model_refresh_pricing_routing_evidence(refresh_pricing_routing_evidence)
        )
        return evidence

    def _failure_routing_evidence(
        self,
        *,
        payload: dict[str, Any] | None,
        response_headers: Mapping[str, str],
        schema_hash: str,
        started_at: datetime,
        ended_at: datetime,
        latency_ms: float,
        error: Exception,
        structured_output_plan: _StructuredOutputRequestPlan,
        request_body_sha256: str,
        response_sha256: str | None,
        validated_response_sha256: str | None,
        qualification_binding: OpenRouterQualificationRoutingEvidence | None,
        provider_policy: OpenRouterProviderPolicy,
        requested_model: str,
        model_identity: _RegisteredModelIdentity | None,
        request_token_plan: RequestTokenPlan,
        token_reservations: Sequence[Reservation],
        context_request_evidence: ContextRequestEvidence | None,
        audit_routing_evidence: AuditModelRoutingEvidence | None,
        refresh_routing_evidence: AuditModelRefreshRouteEvidence | None,
        refresh_pricing_routing_evidence: (AuditModelRefreshPricingRouteEvidence | None),
        refresh_pricing_control: _AuditModelRefreshPricingRequestControl | None,
        refresh_pricing_attempt_routes: Mapping[str, AuditModelRefreshPricingRouteEvidence],
        refresh_pricing_reservation_checks: Mapping[str, datetime],
        refresh_pricing_transport_checks: Mapping[str, datetime],
    ) -> dict[str, Any]:
        router_metadata = payload.get("openrouter_metadata") if isinstance(payload, dict) else None
        finish_reason = _optional_finish_reason(payload)
        native_finish_reason = _optional_native_finish_reason(payload)
        truncated_envelope = (
            _TRUSTED_CANDIDATE_REVIEW_TRUNCATED_ENVELOPE_FGET(error)
            if type(error) is OpenRouterTruncatedResponseError
            and _TRUSTED_CANDIDATE_REVIEW_TRUNCATED_ENVELOPE_FGET is not None
            else None
        )
        truncation_projection = (
            _TRUSTED_CANDIDATE_REVIEW_TRUNCATION_PROJECTION_FGET(error)
            if type(error) is OpenRouterTruncatedResponseError
            and _TRUSTED_CANDIDATE_REVIEW_TRUNCATION_PROJECTION_FGET is not None
            else None
        )
        endpoint_policy = self._endpoint_pricing.get(requested_model)
        selected_endpoint_pricing = (
            endpoint_policy.endpoint(provider_policy.configured_endpoints[0])
            if endpoint_policy is not None and len(provider_policy.configured_endpoints) == 1
            else None
        )
        evidence: dict[str, Any] = {
            "generation_id": (
                truncated_envelope.generation_id
                if truncated_envelope is not None
                else (_optional_string(payload.get("id")) if payload is not None else None)
            ),
            "generation_header_id": (
                truncated_envelope.generation_header_id
                if truncated_envelope is not None
                else _header_value(response_headers, "x-generation-id")
            ),
            "provider": (
                truncated_envelope.selected_provider_name
                if truncated_envelope is not None
                else (_optional_string(payload.get("provider")) if payload is not None else None)
            ),
            "router_metadata_sha256": (
                truncated_envelope.router_metadata_sha256
                if truncated_envelope is not None
                else (
                    _canonical_sha256(router_metadata)
                    if isinstance(router_metadata, dict)
                    else None
                )
            ),
            "finish_reason": (
                truncated_envelope.finish_reason
                if truncated_envelope is not None
                else finish_reason
            ),
            "native_finish_reason": (
                truncated_envelope.native_finish_reason
                if truncated_envelope is not None
                else native_finish_reason
            ),
            "schema_sha256": schema_hash,
            "provider_policy_sha256": _canonical_sha256(
                provider_policy.as_request_payload(
                    require_zdr=self.privacy.require_zdr,
                    require_parameters=structured_output_plan.require_parameters,
                )
            ),
            "configured_provider_only": list(provider_policy.only),
            "configured_provider_order": list(provider_policy.order),
            "provider_fallbacks_allowed": provider_policy.allow_fallbacks,
            "certification_request": provider_policy.certification,
            "zdr_requested": self.privacy.require_zdr,
            "data_collection": "deny",
            "request_started_at": started_at.isoformat(),
            "request_ended_at": ended_at.isoformat(),
            "latency_ms": round(latency_ms, 3),
            "validation_status": "rejected",
            "provider_error_classification": _provider_error_classification(error),
            "identity_strength": ModelIdentityStrength.UNBOUND.value,
            "endpoint_snapshot_sha256": (
                refresh_pricing_control.current_endpoint_snapshot_sha256
                if refresh_pricing_control is not None
                else (endpoint_policy.snapshot_sha256 if endpoint_policy is not None else None)
            ),
            "endpoint_pricing_sha256": (
                refresh_pricing_routing_evidence.current_pricing_sha256
                if refresh_pricing_routing_evidence is not None
                else (
                    selected_endpoint_pricing.pricing_sha256
                    if selected_endpoint_pricing is not None
                    else None
                )
            ),
            "output_capability_sha256": (
                endpoint_policy.output_capability_sha256 if endpoint_policy is not None else None
            ),
            "structured_output_supported_modes": (
                [mode.value for mode in endpoint_policy.supported_output_modes]
                if endpoint_policy is not None
                else [StructuredOutputMode.NATIVE_JSON_SCHEMA.value]
            ),
            "structured_output_mode": structured_output_plan.mode.value,
            "structured_output_request_shape_sha256": (structured_output_plan.request_shape_sha256),
            "structured_output_require_parameters": (structured_output_plan.require_parameters),
            "structured_output_required_provider_parameters": list(
                structured_output_plan.required_provider_parameters
            ),
            "structured_output_reasoning_request_sha256": (
                structured_output_plan.reasoning_request_sha256
            ),
            "structured_output_response_format": (
                structured_output_plan.response_format["type"]
                if structured_output_plan.response_format is not None
                else None
            ),
            "structured_output_protocol_sha256": (structured_output_plan.strict_protocol_sha256),
            "structured_output_request_body_sha256": request_body_sha256,
            "structured_output_original_response_sha256": response_sha256,
            "structured_output_validated_response_sha256": (validated_response_sha256),
        }
        if truncated_envelope is not None:
            evidence.update(
                _TRUSTED_CANDIDATE_REVIEW_TRUNCATED_ENVELOPE_ROUTING(truncated_envelope)
            )
        if truncation_projection is not None:
            evidence.update(
                _TRUSTED_CANDIDATE_REVIEW_TRUNCATION_PROJECTION_ROUTING(truncation_projection)
            )
        evidence.update(
            self._privacy_routing_evidence(
                selected_provider_endpoint=(
                    provider_policy.configured_endpoints[0]
                    if len(provider_policy.configured_endpoints) == 1
                    else None
                ),
            )
        )
        evidence.update(
            self._token_plan_routing_evidence(
                request_token_plan=request_token_plan,
                reservations=token_reservations,
                context_request_evidence=context_request_evidence,
                request_body_sha256=request_body_sha256,
                refresh_pricing_control=refresh_pricing_control,
                refresh_pricing_attempt_routes=refresh_pricing_attempt_routes,
                refresh_pricing_reservation_checks=refresh_pricing_reservation_checks,
                refresh_pricing_transport_checks=refresh_pricing_transport_checks,
            )
        )
        identity_diagnostic = _identity_failure_diagnostic(
            payload=payload,
            requested_model=requested_model,
            model_identity=model_identity,
            error=error,
        )
        if identity_diagnostic is not None:
            evidence["identity_diagnostic"] = identity_diagnostic
        if isinstance(error, OpenRouterResponseIdentityError):
            evidence["identity_binding_status"] = "response_identity_unbound"
        if isinstance(error, OpenRouterStructuredOutputError):
            evidence["structured_output_failure_code"] = error.failure_code.value
            evidence["repair_used"] = error.repair_evidence is not None
            evidence["repair_request"] = False
            evidence["repair_evidence"] = (
                error.repair_evidence.model_dump(mode="json")
                if error.repair_evidence is not None
                else None
            )
        if qualification_binding is not None:
            evidence.update(qualification_binding.routing_evidence())
        evidence.update(self._audit_model_selection_routing_evidence(audit_routing_evidence))
        evidence.update(self._audit_model_refresh_routing_evidence(refresh_routing_evidence))
        evidence.update(
            self._audit_model_refresh_pricing_routing_evidence(refresh_pricing_routing_evidence)
        )
        return evidence

    async def _backoff(self, attempt: int, retry_after: str | None) -> None:
        delay: float
        try:
            delay = min(30.0, max(0.0, float(retry_after))) if retry_after else 0.0
        except ValueError:
            delay = 0.0
        if delay == 0:
            delay = min(30.0, (2 ** (attempt - 1)) + self._random.uniform(0, 0.5))
        await asyncio.sleep(delay)

    def _store_debug(self, request_id: str, filename: str, value: Any) -> None:
        if self.run_dir is None:
            raise OpenRouterPrivacyError("debug storage requested without a private run directory")
        _TRUSTED_ENSURE_NO_CREDENTIAL_IN_VALUE(self, value)
        debug_dir = self.run_dir / "debug" / request_id
        debug_dir.mkdir(parents=True, exist_ok=True)
        path = debug_dir / filename
        path.write_text(
            json.dumps(
                value,
                sort_keys=True,
                indent=2,
                default=_debug_json_default,
            ),
            encoding="utf-8",
        )

    def _ensure_request_size(self, body: dict[str, Any]) -> None:
        _TRUSTED_ENSURE_NO_CREDENTIAL_IN_VALUE(self, body)
        size = _serialized_structured_request_size(body)
        if size > self.execution.max_request_bytes:
            raise OpenRouterRequestLimitError(
                f"serialized model request exceeds {self.execution.max_request_bytes} byte limit"
            )

    def _ensure_no_credential_in_value(self, value: Any) -> None:
        credential = bytes(self._credential).decode("utf-8")
        if credential and any(credential in item for item in _nested_string_values(value)):
            raise OpenRouterPrivacyError("operator credential appeared in provider data")


def _identity_snapshot_from_discovery(
    evidence: OpenRouterModelDiscoveryEvidence,
    *,
    allow_fallbacks: bool,
    reasoning_requested: bool,
) -> OpenRouterModelEndpointIdentitySnapshot:
    endpoint = evidence.endpoint_snapshot.endpoint(evidence.approved_provider_endpoint)
    if reasoning_requested and not supports_reasoning_request(evidence.reasoning_parameters):
        raise OpenRouterProviderPolicyError(
            "requested reasoning lacks exact model/endpoint parameter support"
        )
    required_parameters = tuple(
        sorted(
            (set(endpoint.required_request_parameters) - _ROUTE_SENSITIVE_REQUEST_PARAMETERS)
            | set(output_mode_request_parameters(evidence.structured_output_mode))
            | ({REASONING_REQUEST_PARAMETER} if reasoning_requested else set())
        )
    )
    provider_policy = seal_openrouter_identity_provider_policy(
        mode=evidence.endpoint_snapshot.provider_policy_mode,
        configured_endpoints=evidence.endpoint_snapshot.configured_provider_endpoints,
        allow_fallbacks=allow_fallbacks,
        zdr_required=evidence.endpoint_snapshot.require_zdr,
        require_parameters=bool(set(required_parameters) - {"max_tokens", "temperature"}),
    )
    capabilities = OpenRouterIdentityEndpointCapabilities(
        operational=True,
        context_tokens=endpoint.context_length,
        output_tokens=endpoint.max_completion_tokens,
        supported_parameters=endpoint.supported_parameters,
        required_parameters=required_parameters,
        structured_output_parameters=endpoint.structured_output_parameters,
        supported_output_modes=endpoint.supported_output_modes,
        structured_output_mode=evidence.structured_output_mode,
        output_capability_sha256=evidence.output_capability_sha256,
        reasoning_parameters=evidence.reasoning_parameters,
        structured_output_supported=supports_provider_structured_output(
            endpoint.supported_parameters
        ),
        reasoning_supported=supports_reasoning_request(evidence.reasoning_parameters),
        zdr_eligible=endpoint.zdr_eligible is True,
        data_collection_deny_eligible=evidence.data_collection_deny_eligible,
        data_collection_deny_request_policy_enforced=(
            evidence.data_collection_deny_request_policy_enforced
        ),
        data_collection_deny_evidence_source=(evidence.data_collection_deny_evidence_source.value),
        data_collection_deny_evidence_sha256=(evidence.data_collection_deny_evidence_sha256),
        data_collection_deny_evidence_expires_at=(
            evidence.data_collection_deny_evidence_expires_at
        ),
    )
    pricing = tuple(
        OpenRouterIdentityPricingEntry(unit=unit, usd_per_unit=value)
        for unit, value in sorted(endpoint.pricing.items())
    )
    retrieved_at = evidence.provenance.retrieved_at
    return seal_openrouter_model_endpoint_identity_snapshot(
        requested_slug=evidence.exact_model_id,
        canonical_slug=evidence.canonical_slug,
        frozen_aliases=tuple(sorted({evidence.exact_model_id, evidence.canonical_slug})),
        model_author=evidence.canonical_slug.split("/", 1)[0],
        model_context_tokens=max(
            evidence.catalog_context_size,
            evidence.catalog_provider_context_size,
        ),
        model_output_tokens=max(
            evidence.catalog_output_limit,
            endpoint.max_completion_tokens,
        ),
        model_supported_parameters=evidence.model_supported_parameters,
        approved_provider_endpoint=evidence.approved_provider_endpoint,
        endpoint_tag=endpoint.endpoint_tag,
        endpoint_slug=endpoint.endpoint_slug,
        provider_name=endpoint.provider_name,
        provider_policy=provider_policy,
        endpoint_capabilities=capabilities,
        pricing=pricing,
        canonical_slug_mutable=True,
        immutable_provider_version=None,
        immutable_provider_version_evidence_sha256=None,
        retrieved_at=retrieved_at,
        expires_at=retrieved_at + _MUTABLE_IDENTITY_TTL,
        catalog_identity_binding_sha256=evidence.catalog_identity_binding_sha256,
        catalog_snapshot_sha256=evidence.provenance.catalog_snapshot_sha256,
        model_metadata_snapshot_sha256=evidence.model_metadata_snapshot_sha256,
        discovery_provenance_sha256=evidence.provenance.provenance_sha256,
        discovery_evidence_sha256=evidence.discovery_evidence_sha256,
        endpoint_snapshot_sha256=evidence.endpoint_snapshot.snapshot_sha256,
        pricing_snapshot_sha256=endpoint.pricing_sha256,
    )


def _request_identity_evidence(usage: UsageRecord) -> OpenRouterRequestIdentityEvidence:
    required = {
        "returned model": usage.returned_model,
        "actual model": usage.actual_model,
        "provider endpoint": usage.actual_provider_endpoint,
        "generation ID": usage.openrouter_generation_id,
        "request body hash": usage.request_body_sha256,
        "response hash": usage.response_sha256,
        "validated response hash": usage.validated_response_sha256,
        "start time": usage.started_at,
        "completion time": usage.ended_at,
    }
    if any(value is None for value in required.values()):
        raise OpenRouterModelError("completed response lacks identity evidence")
    provider_name = usage.routing.get("selected_provider_name")
    if not isinstance(provider_name, str):
        raise OpenRouterModelError("completed response lacks provider identity evidence")
    host_model_fallback_used = usage.routing.get("host_model_fallback_used")
    provider_fallback_used = usage.routing.get("provider_fallback_used")
    if (
        not isinstance(host_model_fallback_used, bool)
        or not isinstance(provider_fallback_used, bool)
        or usage.fallback_used != (host_model_fallback_used or provider_fallback_used)
    ):
        raise OpenRouterModelError("completed response lacks coherent fallback identity evidence")
    assert usage.returned_model is not None
    assert usage.actual_model is not None
    assert usage.actual_provider_endpoint is not None
    assert usage.openrouter_generation_id is not None
    assert usage.request_body_sha256 is not None
    assert usage.response_sha256 is not None
    assert usage.validated_response_sha256 is not None
    assert usage.started_at is not None
    assert usage.ended_at is not None
    return OpenRouterRequestIdentityEvidence(
        internal_request_id=usage.request_id,
        execution_evidence=usage.execution_evidence.value,
        requested_slug=usage.requested_model,
        returned_slug=usage.returned_model,
        selected_model_slug=usage.actual_model,
        actual_provider_endpoint=usage.actual_provider_endpoint,
        actual_provider_name=provider_name,
        openrouter_generation_id=usage.openrouter_generation_id,
        request_body_sha256=usage.request_body_sha256,
        response_sha256=usage.response_sha256,
        validated_response_sha256=usage.validated_response_sha256,
        started_at=_whole_second_utc(usage.started_at),
        completed_at=_whole_second_utc(usage.ended_at),
        fallback_used=provider_fallback_used,
    )


def _identity_binding_diagnostics(
    *,
    snapshot: OpenRouterModelEndpointIdentitySnapshot,
    request: OpenRouterRequestIdentityEvidence,
    generation: OpenRouterGenerationIdentityEvidence,
    evaluated_at: datetime,
) -> tuple[OpenRouterIdentityDiagnosticCode, ...]:
    codes: set[OpenRouterIdentityDiagnosticCode] = set()
    if snapshot.expires_at is not None and snapshot.expires_at <= evaluated_at:
        codes.add(OpenRouterIdentityDiagnosticCode.IDENTITY_SNAPSHOT_EXPIRED)
    if not snapshot.resolves_to_canonical(request.returned_slug):
        codes.add(OpenRouterIdentityDiagnosticCode.MODEL_ALIAS_UNRECOGNIZED)
    if not snapshot.resolves_to_canonical(request.selected_model_slug):
        codes.add(OpenRouterIdentityDiagnosticCode.MODEL_CANONICAL_MISMATCH)
    if request.actual_provider_endpoint != snapshot.approved_provider_endpoint:
        codes.add(OpenRouterIdentityDiagnosticCode.ENDPOINT_VARIANT_MISMATCH)
    if request.actual_provider_name != snapshot.provider_name:
        codes.add(OpenRouterIdentityDiagnosticCode.PROVIDER_MISMATCH)
    if request.fallback_used:
        codes.add(OpenRouterIdentityDiagnosticCode.UNAPPROVED_FALLBACK)
    if generation.generation_id != request.openrouter_generation_id:
        codes.add(OpenRouterIdentityDiagnosticCode.GENERATION_ID_MISMATCH)
    if generation.execution_evidence != request.execution_evidence:
        codes.add(OpenRouterIdentityDiagnosticCode.GENERATION_EXECUTION_EVIDENCE_MISMATCH)
    if not snapshot.resolves_to_canonical(generation.generation_model_slug):
        codes.add(OpenRouterIdentityDiagnosticCode.GENERATION_MODEL_MISMATCH)
    if generation.provider_name != snapshot.provider_name:
        codes.add(OpenRouterIdentityDiagnosticCode.GENERATION_PROVIDER_MISMATCH)
    if generation.retrieved_at < request.completed_at:
        codes.add(OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_MISSING)
    if not codes:
        codes.add(OpenRouterIdentityDiagnosticCode.MODEL_CANONICAL_MISMATCH)
    return tuple(sorted(codes, key=lambda item: item.value))


def _whole_second_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise OpenRouterModelError("identity timestamp is not timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0)


def _require_trusted_candidate_review_dispatch_boundary(
    client: OpenRouterClient,
    *,
    operation: Literal["completion", "resource_preview"],
) -> None:
    """Reject substituted candidate-review dispatch authority before any client lookup."""

    if type(client) is not _TRUSTED_OPENROUTER_CLIENT_TYPE:
        raise OpenRouterCandidateReviewBoundaryError(
            f"candidate-review {operation} dispatch requires the exact provider client"
        )
    try:
        instance_state = object.__getattribute__(client, "__dict__")
    except (AttributeError, TypeError) as exc:
        raise OpenRouterCandidateReviewBoundaryError(
            f"candidate-review {operation} dispatch boundary is unavailable"
        ) from exc
    if type(instance_state) is not dict or any(
        name in instance_state for name in _TRUSTED_OPENROUTER_CLIENT_CALLABLE_NAMES
    ):
        raise OpenRouterCandidateReviewBoundaryError(
            f"candidate-review {operation} dispatch boundary changed before provider work"
        )
    if (
        _candidate_review_protocol_boundary_is_pristine
        is not _TRUSTED_CANDIDATE_REVIEW_PROTOCOL_BOUNDARY_IS_PRISTINE
        or _openrouter_client_callables_are_pristine
        is not _TRUSTED_OPENROUTER_CLIENT_CALLABLES_ARE_PRISTINE
        or _require_trusted_candidate_review_dispatch_boundary
        is not _TRUSTED_REQUIRE_CANDIDATE_REVIEW_DISPATCH_BOUNDARY
        or not _TRUSTED_CANDIDATE_REVIEW_PROTOCOL_BOUNDARY_IS_PRISTINE()
        or not _TRUSTED_OPENROUTER_CLIENT_CALLABLES_ARE_PRISTINE()
    ):
        raise OpenRouterCandidateReviewBoundaryError(
            f"candidate-review {operation} dispatch boundary changed before provider work"
        )


def trusted_preview_candidate_review_task_resources(
    client: OpenRouterClient,
    *,
    coverage_task: ModelSurfaceGapTask,
    scheduler_task: SchedulerTaskPlan,
    campaign_manifest: SchedulerCampaignManifest,
    context_package: ContextPackage,
    system_prompt: str,
    schema_name: str,
    checked_at: datetime,
) -> ModelSurfaceTaskResourcePreview:
    """Invoke the frozen resource-preview descriptor without dynamic client dispatch."""

    _TRUSTED_REQUIRE_CANDIDATE_REVIEW_DISPATCH_BOUNDARY(
        client,
        operation="resource_preview",
    )
    return _TRUSTED_PREVIEW_CANDIDATE_REVIEW_TASK_RESOURCES(
        client,
        coverage_task=coverage_task,
        scheduler_task=scheduler_task,
        campaign_manifest=campaign_manifest,
        context_package=context_package,
        system_prompt=system_prompt,
        schema_name=schema_name,
        checked_at=checked_at,
    )


async def trusted_complete_candidate_review_with_evidence(
    client: OpenRouterClient,
    *,
    role: str,
    models: list[str],
    system_prompt: str,
    user_prompt: str,
    context_package: ContextPackage | None = None,
    schema_name: str,
    logical_request_id: str | None = None,
    single_route_single_attempt: bool = False,
    expected_resource_preview: ModelSurfaceTaskResourcePreview | None = None,
    coverage_task: ModelSurfaceGapTask | None = None,
    scheduler_task: SchedulerTaskPlan | None = None,
    campaign_manifest: SchedulerCampaignManifest | None = None,
    resource_preview_checked_at: datetime | None = None,
) -> CandidateReviewCompletion:
    """Invoke the frozen candidate-review descriptor without dynamic client dispatch."""

    _TRUSTED_REQUIRE_CANDIDATE_REVIEW_DISPATCH_BOUNDARY(
        client,
        operation="completion",
    )
    return await _TRUSTED_COMPLETE_CANDIDATE_REVIEW_WITH_EVIDENCE(
        client,
        role=role,
        models=models,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        context_package=context_package,
        schema_name=schema_name,
        logical_request_id=logical_request_id,
        single_route_single_attempt=single_route_single_attempt,
        expected_resource_preview=expected_resource_preview,
        coverage_task=coverage_task,
        scheduler_task=scheduler_task,
        campaign_manifest=campaign_manifest,
        resource_preview_checked_at=resource_preview_checked_at,
    )


_TRUSTED_OPENROUTER_CLIENT_TYPE = OpenRouterClient
_TRUSTED_CANDIDATE_REVIEW_PROTOCOL_BOUNDARY_IS_PRISTINE = (
    _candidate_review_protocol_boundary_is_pristine
)
_TRUSTED_REQUIRE_CANDIDATE_REVIEW_DISPATCH_BOUNDARY = (
    _require_trusted_candidate_review_dispatch_boundary
)
_TRUSTED_PUBLIC_CANDIDATE_REVIEW_RESOURCE_PREVIEW = trusted_preview_candidate_review_task_resources
_TRUSTED_PUBLIC_CANDIDATE_REVIEW_COMPLETION = trusted_complete_candidate_review_with_evidence
_TRUSTED_ATTACH_CANDIDATE_REVIEW_TRUNCATION_PROJECTION = (
    OpenRouterTruncatedResponseError._attach_projection
)
_TRUSTED_ATTACH_CANDIDATE_REVIEW_TRUNCATED_USAGE = (
    OpenRouterTruncatedResponseError._attach_failed_usage_record
)
_TRUSTED_CANDIDATE_REVIEW_TRUNCATION_PROJECTION_PROPERTY = (
    OpenRouterTruncatedResponseError.projection
)
_TRUSTED_CANDIDATE_REVIEW_TRUNCATION_PROJECTION_FGET = cast(
    Callable[[OpenRouterTruncatedResponseError], CandidateReviewTruncationProjection | None],
    _property_getter(OpenRouterTruncatedResponseError, "projection"),
)
_TRUSTED_CANDIDATE_REVIEW_TRUNCATED_ENVELOPE_PROPERTY = (
    OpenRouterTruncatedResponseError.envelope_evidence
)
_TRUSTED_CANDIDATE_REVIEW_TRUNCATED_ENVELOPE_FGET = cast(
    Callable[
        [OpenRouterTruncatedResponseError],
        CandidateReviewTruncatedEnvelopeEvidence | None,
    ],
    _property_getter(OpenRouterTruncatedResponseError, "envelope_evidence"),
)
_TRUSTED_CANDIDATE_REVIEW_TRUNCATED_USAGE_PROPERTY = (
    OpenRouterTruncatedResponseError.failed_usage_record
)
_TRUSTED_CANDIDATE_REVIEW_TRUNCATED_USAGE_FGET = cast(
    Callable[[OpenRouterTruncatedResponseError], UsageRecord | None],
    _property_getter(OpenRouterTruncatedResponseError, "failed_usage_record"),
)
_TRUSTED_CANDIDATE_REVIEW_ERROR_CUSTODY_IS_COHERENT = _candidate_review_error_custody_is_coherent
_TRUSTED_CANDIDATE_REVIEW_TRUNCATION_PROJECTION_ROUTING = (
    _candidate_review_truncation_projection_routing
)
_TRUSTED_CANDIDATE_REVIEW_TRUNCATED_ENVELOPE_ROUTING = _candidate_review_truncated_envelope_routing
_TRUSTED_CANDIDATE_REVIEW_USAGE_RECORD_VALIDATOR = UsageRecord.__pydantic_validator__
_TRUSTED_CANDIDATE_REVIEW_USAGE_RECORD_CORE_SCHEMA = UsageRecord.__pydantic_core_schema__
_TRUSTED_OPENROUTER_IDENTITY_BINDING_ISSUER = object()
_TRUSTED_RECONCILIATION_EXPECTATION = GenerationVerificationRequest.reconciliation_expectation
_TRUSTED_VALIDATE_AUTHENTICATION = OpenRouterClient.validate_authentication
_TRUSTED_GET_GENERATION_EVIDENCE = OpenRouterClient.get_generation_evidence
_TRUSTED_ISSUE_GENERATION_VERIFICATION = _issue_trusted_generation_verification
_TRUSTED_ATTEST_AUTHRUNNER_GENERATION_ORIGIN = _attest_authrunner_generation_origin
_TRUSTED_ATTEST_AUTHRUNNER_USAGE_ORIGIN = _attest_authrunner_owned_real_usage_origin
_TRUSTED_AUTHRUNNER_USAGE_ORIGIN_SCOPE = _authrunner_usage_origin_scope
_TRUSTED_VALIDATED_USAGE_COPY = _validated_usage_copy_preserving_owned_attestation
_TRUSTED_CREATE_GENERATION_VERIFICATION = OpenRouterClient.create_trusted_generation_verification
_TRUSTED_FETCH_GENERATION_ATTESTATIONS = (
    OpenRouterClient._fetch_generation_attestations_with_deadline
)
_TRUSTED_REQUEST_METADATA = OpenRouterClient._request_metadata
_TRUSTED_BOUNDED_REQUEST = OpenRouterClient._bounded_request
_TRUSTED_BUILD_REQUEST = OpenRouterClient.build_request
_TRUSTED_PREVIEW_CANDIDATE_REVIEW_TASK_RESOURCES = (
    OpenRouterClient.preview_candidate_review_task_resources
)
_TRUSTED_COMPLETE_WITH_EVIDENCE = OpenRouterClient.complete_with_evidence
_TRUSTED_COMPLETE_ONE = OpenRouterClient._complete_one
_TRUSTED_COMPLETE_CANDIDATE_REVIEW_WITH_EVIDENCE = (
    OpenRouterClient.complete_candidate_review_with_evidence
)
_TRUSTED_FAILURE_ROUTING_EVIDENCE = OpenRouterClient._failure_routing_evidence
_TRUSTED_ENDPOINT_REQUEST_COST_BOUND = OpenRouterClient._endpoint_request_cost_bound
_TRUSTED_REQUIRE_MATCHING_REQUEST_COST_PREVIEW = _require_matching_structured_request_cost_preview
_TRUSTED_ENSURE_REQUEST_SIZE = OpenRouterClient._ensure_request_size
_TRUSTED_STORE_DEBUG = OpenRouterClient._store_debug
_TRUSTED_ENSURE_NO_CREDENTIAL_IN_VALUE = OpenRouterClient._ensure_no_credential_in_value
_TRUSTED_VALIDATE_PAID_PRIVACY_POLICY = OpenRouterClient._validate_paid_privacy_policy
_TRUSTED_VALIDATE_TRANSPORT_PROVENANCE = OpenRouterClient._validate_transport_provenance
_TRUSTED_BUDGET_RESERVE = BudgetManager.reserve
_TRUSTED_BUDGET_RECONCILE = BudgetManager.reconcile
_TRUSTED_BUDGET_RECONCILED_COST_USD_EXACT = BudgetManager.reconciled_cost_usd_exact
_TRUSTED_BUDGET_RELEASE = BudgetManager.release
_TRUSTED_BUDGET_COMMIT_FOR_TRANSPORT = BudgetManager.commit_active_reservation_for_transport
_TRUSTED_BUDGET_CURRENT_ATOMIC_LEDGER = BudgetManager._current_atomic_ledger
_TRUSTED_ATOMIC_LEDGER_RESERVE = AtomicCostLedger.reserve
_TRUSTED_ATOMIC_LEDGER_RECONCILE = AtomicCostLedger.reconcile
_TRUSTED_ATOMIC_LEDGER_RELEASE = AtomicCostLedger.release
_TRUSTED_ATOMIC_LEDGER_ACTIVE_RESERVATION = AtomicCostLedger.active_reservation
_TRUSTED_ATOMIC_LEDGER_SNAPSHOT = AtomicCostLedger.snapshot
_TRUSTED_ATOMIC_LEDGER_LOCKED = AtomicCostLedger._locked
_TRUSTED_ATOMIC_LEDGER_REQUIRED_STATE = AtomicCostLedger._required_state
_TRUSTED_ATOMIC_LEDGER_READ_STATE = AtomicCostLedger._read_state
_TRUSTED_ATOMIC_LEDGER_WRITE_STATE = AtomicCostLedger._write_state
_TRUSTED_ENDPOINT_COMPONENT_MAXIMUM_COST_FGET = _property_getter(
    EndpointPriceComponent,
    "maximum_cost_usd",
)
_TRUSTED_ENDPOINT_REQUEST_MAXIMUM_COST_FGET = _property_getter(
    EndpointRequestCostBound,
    "maximum_cost_usd",
)
_TRUSTED_ENDPOINT_REQUEST_FROM_PRICING = _classmethod_function(
    EndpointRequestCostBound,
    "from_endpoint_pricing",
)
_TRUSTED_ENDPOINT_REQUEST_MAXIMUM_UNITS_FOR = EndpointRequestCostBound.maximum_units_for
_TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION = (
    OpenRouterClient._requires_real_audit_policy_selection
)
_TRUSTED_REQUIRES_REAL_AUDIT_MODEL_REFRESH = OpenRouterClient._requires_real_audit_model_refresh
_TRUSTED_REQUIRES_REAL_AUDIT_MODEL_REFRESH_PRICING = (
    OpenRouterClient._requires_real_audit_model_refresh_pricing
)
_TRUSTED_IS_TRUSTED_PREQUALIFICATION_REQUEST = OpenRouterClient._is_trusted_prequalification_request
_TRUSTED_REQUIRE_REAL_AUDIT_MODEL_SELECTION = OpenRouterClient._require_real_audit_model_selection
_TRUSTED_REQUIRE_REAL_AUDIT_MODEL_REFRESH = OpenRouterClient._require_real_audit_model_refresh
_TRUSTED_REQUIRE_REAL_AUDIT_MODEL_REFRESH_PRICING = (
    OpenRouterClient._require_real_audit_model_refresh_pricing
)
_TRUSTED_SEAL_AUDIT_MODEL_REFRESH_PRICING_CONTROL = (
    OpenRouterClient._seal_audit_model_refresh_pricing_control
)
_TRUSTED_REQUIRE_AUDIT_POLICY_BINDING = OpenRouterClient.require_audit_policy_binding
_TRUSTED_REQUIRE_AUDIT_MODEL_REFRESH_BINDING = OpenRouterClient.require_audit_model_refresh_binding
_TRUSTED_REQUIRE_AUDIT_MODEL_REFRESH_PRICING_BINDING = (
    OpenRouterClient.require_audit_model_refresh_pricing_binding
)


def _provider_callable_descriptor_surface(
    subject_type: type[object],
) -> tuple[tuple[str, object], ...]:
    return tuple(
        sorted(
            (
                (name, descriptor)
                for name, descriptor in vars(subject_type).items()
                if callable(descriptor)
                or isinstance(descriptor, (classmethod, staticmethod, property))
            ),
            key=lambda item: item[0],
        )
    )


_TRUSTED_PROVIDER_CALLABLE_DESCRIPTOR_SURFACE = _provider_callable_descriptor_surface
_TRUSTED_OPENROUTER_CLIENT_DESCRIPTOR_SURFACE = _TRUSTED_PROVIDER_CALLABLE_DESCRIPTOR_SURFACE(
    OpenRouterClient
)
_TRUSTED_OPENROUTER_CLIENT_CALLABLE_NAMES = frozenset(
    name for name, _descriptor in _TRUSTED_OPENROUTER_CLIENT_DESCRIPTOR_SURFACE
)


def _copy_deepcopy_dispatch_is_pristine() -> bool:
    """Reject mutation of deepcopy internals still used by schema/evidence planning."""

    current = getattr(copy, "_deepcopy_dispatch", None)
    return bool(
        type(current) is dict
        and current is _TRUSTED_COPY_DEEPCOPY_DISPATCH
        and len(current) == len(_TRUSTED_COPY_DEEPCOPY_DISPATCH_ITEMS)
        and all(current.get(key) is value for key, value in _TRUSTED_COPY_DEEPCOPY_DISPATCH_ITEMS)
    )


_TRUSTED_BUDGET_MANAGER_DESCRIPTOR_SURFACE = _provider_callable_descriptor_surface(BudgetManager)
_TRUSTED_ATOMIC_LEDGER_DESCRIPTOR_SURFACE = _provider_callable_descriptor_surface(AtomicCostLedger)


def _openrouter_client_callables_are_pristine() -> bool:
    """Verify the client-owned request and evidence dispatch boundary is unchanged."""

    return (
        _openrouter_client_callables_are_pristine
        is _TRUSTED_OPENROUTER_CLIENT_CALLABLES_ARE_PRISTINE
        and _candidate_review_protocol_boundary_is_pristine
        is _TRUSTED_CANDIDATE_REVIEW_PROTOCOL_BOUNDARY_IS_PRISTINE
        and _require_trusted_candidate_review_dispatch_boundary
        is _TRUSTED_REQUIRE_CANDIDATE_REVIEW_DISPATCH_BOUNDARY
        and (
            trusted_preview_candidate_review_task_resources
            is _TRUSTED_PUBLIC_CANDIDATE_REVIEW_RESOURCE_PREVIEW
        )
        and (
            trusted_complete_candidate_review_with_evidence
            is _TRUSTED_PUBLIC_CANDIDATE_REVIEW_COMPLETION
        )
        and _provider_callable_descriptor_surface is _TRUSTED_PROVIDER_CALLABLE_DESCRIPTOR_SURFACE
        and (
            GenerationVerificationRequest.reconciliation_expectation
            is _TRUSTED_RECONCILIATION_EXPECTATION
        )
        and _issue_trusted_generation_verification is _TRUSTED_ISSUE_GENERATION_VERIFICATION
        and (_attest_authrunner_generation_origin is _TRUSTED_ATTEST_AUTHRUNNER_GENERATION_ORIGIN)
        and (_attest_authrunner_owned_real_usage_origin is _TRUSTED_ATTEST_AUTHRUNNER_USAGE_ORIGIN)
        and (_authrunner_usage_origin_scope is _TRUSTED_AUTHRUNNER_USAGE_ORIGIN_SCOPE)
        and _validated_usage_copy_preserving_owned_attestation is _TRUSTED_VALIDATED_USAGE_COPY
        and OpenRouterClient.validate_authentication is _TRUSTED_VALIDATE_AUTHENTICATION
        and OpenRouterClient.get_generation_evidence is _TRUSTED_GET_GENERATION_EVIDENCE
        and (
            OpenRouterClient.create_trusted_generation_verification
            is _TRUSTED_CREATE_GENERATION_VERIFICATION
        )
        and (
            OpenRouterClient._fetch_generation_attestations_with_deadline
            is _TRUSTED_FETCH_GENERATION_ATTESTATIONS
        )
        and OpenRouterClient._request_metadata is _TRUSTED_REQUEST_METADATA
        and OpenRouterClient._bounded_request is _TRUSTED_BOUNDED_REQUEST
        and OpenRouterClient.build_request is _TRUSTED_BUILD_REQUEST
        and _canonical_sha256 is _TRUSTED_CANONICAL_SHA256
        and (
            _candidate_review_request_token_plan_projection_sha256
            is _TRUSTED_CANDIDATE_REVIEW_TOKEN_PLAN_PROJECTION_SHA256
        )
        and (
            _candidate_review_request_material_projection
            is _TRUSTED_CANDIDATE_REVIEW_REQUEST_MATERIAL_PROJECTION
        )
        and (
            _endpoint_request_cost_bound_projection_sha256
            is _TRUSTED_ENDPOINT_REQUEST_COST_BOUND_PROJECTION_SHA256
        )
        and (_provider_capped_cost_bound_pricing is _TRUSTED_PROVIDER_CAPPED_COST_BOUND_PRICING)
        and copy.deepcopy is _TRUSTED_COPY_DEEPCOPY
        and _copy_deepcopy_dispatch_is_pristine()
        and hashlib.sha256 is _TRUSTED_HASHLIB_SHA256
        and json.dumps is _TRUSTED_JSON_DUMPS
        and json.JSONEncoder is _TRUSTED_JSON_ENCODER
        and json.JSONEncoder.encode is _TRUSTED_JSON_ENCODER_ENCODE
        and json.JSONEncoder.iterencode is _TRUSTED_JSON_ENCODER_ITERENCODE
        and json.encoder is _TRUSTED_JSON_ENCODER_MODULE
        and (
            _TRUSTED_JSON_ENCODER_MODULE.encode_basestring_ascii
            is _TRUSTED_JSON_ENCODE_BASESTRING_ASCII
        )
        and _TRUSTED_JSON_ENCODER_MODULE.c_make_encoder is _TRUSTED_JSON_MAKE_ENCODER
        and (
            _CANDIDATE_REVIEW_CANONICAL_JSON_DUMPS is _TRUSTED_CANDIDATE_REVIEW_CANONICAL_JSON_DUMPS
        )
        and (
            OpenRouterClient.preview_candidate_review_task_resources
            is _TRUSTED_PREVIEW_CANDIDATE_REVIEW_TASK_RESOURCES
        )
        and OpenRouterClient.complete_with_evidence is _TRUSTED_COMPLETE_WITH_EVIDENCE
        and OpenRouterClient._complete_one is _TRUSTED_COMPLETE_ONE
        and (
            OpenRouterClient.complete_candidate_review_with_evidence
            is _TRUSTED_COMPLETE_CANDIDATE_REVIEW_WITH_EVIDENCE
        )
        and OpenRouterClient._failure_routing_evidence is _TRUSTED_FAILURE_ROUTING_EVIDENCE
        and (OpenRouterClient._endpoint_request_cost_bound is _TRUSTED_ENDPOINT_REQUEST_COST_BOUND)
        and (
            _require_matching_structured_request_cost_preview
            is _TRUSTED_REQUIRE_MATCHING_REQUEST_COST_PREVIEW
        )
        and OpenRouterClient._ensure_request_size is _TRUSTED_ENSURE_REQUEST_SIZE
        and OpenRouterClient._store_debug is _TRUSTED_STORE_DEBUG
        and (
            OpenRouterClient._ensure_no_credential_in_value
            is _TRUSTED_ENSURE_NO_CREDENTIAL_IN_VALUE
        )
        and (
            OpenRouterClient._validate_paid_privacy_policy is _TRUSTED_VALIDATE_PAID_PRIVACY_POLICY
        )
        and (
            OpenRouterClient._requires_real_audit_policy_selection
            is _TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION
        )
        and (
            OpenRouterClient._is_trusted_prequalification_request
            is _TRUSTED_IS_TRUSTED_PREQUALIFICATION_REQUEST
        )
        and (
            OpenRouterClient._requires_real_audit_model_refresh
            is _TRUSTED_REQUIRES_REAL_AUDIT_MODEL_REFRESH
        )
        and (
            OpenRouterClient._requires_real_audit_model_refresh_pricing
            is _TRUSTED_REQUIRES_REAL_AUDIT_MODEL_REFRESH_PRICING
        )
        and (
            OpenRouterClient._require_real_audit_model_selection
            is _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_SELECTION
        )
        and (
            OpenRouterClient._require_real_audit_model_refresh
            is _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_REFRESH
        )
        and (
            OpenRouterClient._require_real_audit_model_refresh_pricing
            is _TRUSTED_REQUIRE_REAL_AUDIT_MODEL_REFRESH_PRICING
        )
        and (
            OpenRouterClient._seal_audit_model_refresh_pricing_control
            is _TRUSTED_SEAL_AUDIT_MODEL_REFRESH_PRICING_CONTROL
        )
        and (OpenRouterClient.require_audit_policy_binding is _TRUSTED_REQUIRE_AUDIT_POLICY_BINDING)
        and (
            OpenRouterClient.require_audit_model_refresh_binding
            is _TRUSTED_REQUIRE_AUDIT_MODEL_REFRESH_BINDING
        )
        and (
            OpenRouterClient.require_audit_model_refresh_pricing_binding
            is _TRUSTED_REQUIRE_AUDIT_MODEL_REFRESH_PRICING_BINDING
        )
        and (
            OpenRouterClient._validate_transport_provenance
            is _TRUSTED_VALIDATE_TRANSPORT_PROVENANCE
        )
        and BudgetManager.reserve is _TRUSTED_BUDGET_RESERVE
        and BudgetManager.reconcile is _TRUSTED_BUDGET_RECONCILE
        and (BudgetManager.reconciled_cost_usd_exact is _TRUSTED_BUDGET_RECONCILED_COST_USD_EXACT)
        and BudgetManager.release is _TRUSTED_BUDGET_RELEASE
        and (
            BudgetManager.commit_active_reservation_for_transport
            is _TRUSTED_BUDGET_COMMIT_FOR_TRANSPORT
        )
        and AtomicCostLedger.reserve is _TRUSTED_ATOMIC_LEDGER_RESERVE
        and AtomicCostLedger.reconcile is _TRUSTED_ATOMIC_LEDGER_RECONCILE
        and AtomicCostLedger.release is _TRUSTED_ATOMIC_LEDGER_RELEASE
        and (AtomicCostLedger.active_reservation is _TRUSTED_ATOMIC_LEDGER_ACTIVE_RESERVATION)
        and AtomicCostLedger.snapshot is _TRUSTED_ATOMIC_LEDGER_SNAPSHOT
        and AtomicCostLedger._locked is _TRUSTED_ATOMIC_LEDGER_LOCKED
        and AtomicCostLedger._required_state is _TRUSTED_ATOMIC_LEDGER_REQUIRED_STATE
        and AtomicCostLedger._read_state is _TRUSTED_ATOMIC_LEDGER_READ_STATE
        and AtomicCostLedger._write_state is _TRUSTED_ATOMIC_LEDGER_WRITE_STATE
        and _property_getter(EndpointPriceComponent, "maximum_cost_usd")
        is _TRUSTED_ENDPOINT_COMPONENT_MAXIMUM_COST_FGET
        and _property_getter(EndpointRequestCostBound, "maximum_cost_usd")
        is _TRUSTED_ENDPOINT_REQUEST_MAXIMUM_COST_FGET
        and _classmethod_function(EndpointRequestCostBound, "from_endpoint_pricing")
        is _TRUSTED_ENDPOINT_REQUEST_FROM_PRICING
        and EndpointRequestCostBound.maximum_units_for
        is _TRUSTED_ENDPOINT_REQUEST_MAXIMUM_UNITS_FOR
        and _TRUSTED_PROVIDER_CALLABLE_DESCRIPTOR_SURFACE(OpenRouterClient)
        == _TRUSTED_OPENROUTER_CLIENT_DESCRIPTOR_SURFACE
        and _TRUSTED_PROVIDER_CALLABLE_DESCRIPTOR_SURFACE(BudgetManager)
        == _TRUSTED_BUDGET_MANAGER_DESCRIPTOR_SURFACE
        and _TRUSTED_PROVIDER_CALLABLE_DESCRIPTOR_SURFACE(AtomicCostLedger)
        == _TRUSTED_ATOMIC_LEDGER_DESCRIPTOR_SURFACE
    )


_TRUSTED_OPENROUTER_CLIENT_CALLABLES_ARE_PRISTINE = _openrouter_client_callables_are_pristine


def _network_backend_graph_is_current(binding: _TrustedTransportBinding) -> bool:
    backend = binding.network_backend
    if backend is None or type(backend) is not binding.network_backend_type:
        return False
    try:
        backend_values = vars(backend)
        backend_type = type(backend)
        if (
            getattr(backend_type, "connect_tcp", None)
            is not binding.network_backend_connect_tcp_callable
            or getattr(backend_type, "connect_unix_socket", None)
            is not binding.network_backend_connect_unix_socket_callable
            or getattr(backend_type, "sleep", None) is not binding.network_backend_sleep_callable
            or getattr(backend_type, "_init_backend", None)
            is not binding.network_backend_init_callable
            or getattr(backend_type, "__getattribute__", None)
            is not binding.network_backend_getattribute_callable
        ):
            return False
        initial_names = binding.network_backend_attribute_names
        if frozenset(backend_values) not in {initial_names, initial_names | {"_backend"}}:
            return False
        inner = backend_values.get("_backend")
        if inner is None:
            return True
        if vars(inner):
            return False
        inner_type = type(inner)
        if inner_type is _TRUSTED_ANYIO_BACKEND_TYPE:
            return (
                inner_type.connect_tcp is _TRUSTED_ANYIO_CONNECT_TCP
                and inner_type.connect_unix_socket is _TRUSTED_ANYIO_CONNECT_UNIX_SOCKET
                and inner_type.sleep is _TRUSTED_ANYIO_SLEEP
                and getattr(inner_type, "__getattribute__", None)
                is _TRUSTED_ANYIO_BACKEND_GETATTRIBUTE
            )
    except (AttributeError, TypeError):
        return False
    return False


def _transport_binding_graph_is_current(binding: _TrustedTransportBinding) -> bool:
    """Verify the bound HTTPX object graph has no new or substituted dispatch authority."""

    try:
        if frozenset(vars(binding.http_client)) != binding.client_attribute_names:
            return False
        if frozenset(vars(binding.transport)) != binding.transport_attribute_names:
            return False
        if (
            binding.http_client.follow_redirects is not binding.follow_redirects
            or binding.http_client.max_redirects != binding.max_redirects
        ):
            return False
        if binding.execution_evidence is ExecutionEvidenceKind.REAL:
            pool = object.__getattribute__(binding.transport, "_pool")
            current_pool_values = vars(pool)
            connections = current_pool_values.get("_connections")
            requests = current_pool_values.get("_requests")
            if (
                pool is not binding.owned_pool
                or frozenset(current_pool_values) != binding.owned_pool_attribute_names
                or any(
                    current_pool_values[name] is not original
                    for name, original in binding.owned_pool_attribute_values
                )
                or "handle_async_request" in current_pool_values
                or getattr(type(pool), "handle_async_request", None)
                is not binding.owned_pool_request_callable
                or getattr(type(pool), "create_connection", None)
                is not binding.owned_pool_create_connection_callable
                or getattr(type(pool), "_assign_requests_to_connections", None)
                is not binding.owned_pool_assign_requests_callable
                or getattr(type(pool), "_close_connections", None)
                is not binding.owned_pool_close_connections_callable
                or getattr(type(pool), "__getattribute__", None)
                is not binding.owned_pool_getattribute_callable
                or type(connections) is not list
                or bool(connections)
                or type(requests) is not list
                or bool(requests)
                or not _network_backend_graph_is_current(binding)
            ):
                return False
    except (AttributeError, TypeError):
        return False
    return True


def trusted_openrouter_execution_evidence(client: OpenRouterClient) -> ExecutionEvidenceKind:
    """Derive execution evidence once from exact sealed transport identities.

    The public descriptive label is deliberately ignored. This function uses base-object
    attribute access and exact concrete types so subclasses, dynamic attribute overrides, and
    concurrent label changes cannot influence the qualification decision.
    """

    if type(client) is not _TRUSTED_OPENROUTER_CLIENT_TYPE:
        return ExecutionEvidenceKind.UNVERIFIED
    if not _openrouter_client_callables_are_pristine():
        return ExecutionEvidenceKind.UNVERIFIED
    binding = _lookup_trusted_transport_binding(client)
    if binding is None:
        return ExecutionEvidenceKind.UNVERIFIED
    try:
        http_client = object.__getattribute__(client, "_client")
        transport = object.__getattribute__(http_client, "_transport")
    except (AttributeError, TypeError):
        return ExecutionEvidenceKind.UNVERIFIED
    if (
        http_client is not binding.http_client
        or transport is not binding.transport
        or str(http_client.base_url) != binding.base_url
        or not _transport_binding_graph_is_current(binding)
    ):
        return ExecutionEvidenceKind.UNVERIFIED
    if binding.execution_evidence is ExecutionEvidenceKind.REAL:
        if (
            binding.base_url == _NORMALIZED_OPENROUTER_BASE_URL
            and _owned_httpx_callables_are_pristine(http_client, transport)
        ):
            return ExecutionEvidenceKind.REAL
        return ExecutionEvidenceKind.UNVERIFIED
    if (
        binding.execution_evidence is ExecutionEvidenceKind.MOCK
        and type(http_client) is httpx.AsyncClient
        and type(transport) is httpx.MockTransport
        and _mock_httpx_callables_are_pristine(
            http_client,
            transport,
            binding.mock_handler,
        )
    ):
        return ExecutionEvidenceKind.MOCK
    return ExecutionEvidenceKind.UNVERIFIED


_register_authrunner_owned_real_usage_origin_issuer(
    module=sys.modules[__name__],
    client_type=_TRUSTED_OPENROUTER_CLIENT_TYPE,
    completion_method=OpenRouterClient.complete_with_evidence,
    bound_origin_method=OpenRouterClient._bind_real_completion_identity,
    bound_wrapper_method=OpenRouterClient._usage_with_bound_identity,
    bound_result_method=OpenRouterClient._usage_with_identity_result,
    trusted_identity_issuer=_TRUSTED_OPENROUTER_IDENTITY_BINDING_ISSUER,
    pristine_predicate=_TRUSTED_OPENROUTER_CLIENT_CALLABLES_ARE_PRISTINE,
    execution_evidence_resolver=trusted_openrouter_execution_evidence,
)
_register_authrunner_generation_origin_issuer(
    module=sys.modules[__name__],
    client_type=_TRUSTED_OPENROUTER_CLIENT_TYPE,
    refetch_method=OpenRouterClient.create_trusted_generation_verification,
    pristine_predicate=_TRUSTED_OPENROUTER_CLIENT_CALLABLES_ARE_PRISTINE,
    execution_evidence_resolver=trusted_openrouter_execution_evidence,
)


def _mock_httpx_callables_are_pristine(
    client: httpx.AsyncClient,
    transport: object,
    handler_identity: object,
) -> bool:
    """Keep the explicitly authorized test transport sealed after construction."""

    if type(client) is not httpx.AsyncClient or type(transport) is not httpx.MockTransport:
        return False
    try:
        client_values = vars(client)
        transport_values = vars(transport)
        handler = object.__getattribute__(transport, "handler")
        selected_transport = httpx.AsyncClient._transport_for_url(client, client.base_url)
    except (AttributeError, TypeError):
        return False
    return (
        handler is handler_identity
        and selected_transport is transport
        and client_values.get("_mounts") == {}
        and client_values.get("_auth") is None
        and client_values.get("_event_hooks") == {"request": [], "response": []}
        and client_values.get("_trust_env") is False
        and "send" not in client_values
        and "request" not in client_values
        and "stream" not in client_values
        and "build_request" not in client_values
        and "_merge_url" not in client_values
        and "_build_request_auth" not in client_values
        and "_send_handling_auth" not in client_values
        and "_send_handling_redirects" not in client_values
        and "_transport_for_url" not in client_values
        and "_send_single_request" not in client_values
        and "handle_async_request" not in transport_values
        and httpx.AsyncClient.send is _TRUSTED_ASYNC_CLIENT_SEND
        and httpx.AsyncClient.request is _TRUSTED_ASYNC_CLIENT_REQUEST
        and httpx.AsyncClient.stream is _TRUSTED_ASYNC_CLIENT_STREAM
        and httpx.AsyncClient.build_request is _TRUSTED_ASYNC_CLIENT_BUILD_REQUEST
        and httpx.AsyncClient.__getattribute__ is _TRUSTED_ASYNC_CLIENT_GETATTRIBUTE
        and httpx.AsyncClient._merge_url is _TRUSTED_ASYNC_CLIENT_MERGE_URL
        and (httpx.AsyncClient._build_request_auth is _TRUSTED_ASYNC_CLIENT_BUILD_REQUEST_AUTH)
        and (httpx.AsyncClient._send_handling_auth is _TRUSTED_ASYNC_CLIENT_SEND_HANDLING_AUTH)
        and (
            httpx.AsyncClient._send_handling_redirects
            is _TRUSTED_ASYNC_CLIENT_SEND_HANDLING_REDIRECTS
        )
        and (httpx.AsyncClient._transport_for_url is _TRUSTED_ASYNC_CLIENT_TRANSPORT_FOR_URL)
        and (httpx.AsyncClient._send_single_request is _TRUSTED_ASYNC_CLIENT_SEND_SINGLE_REQUEST)
        and httpx.MockTransport.handle_async_request is _TRUSTED_MOCK_TRANSPORT_REQUEST
        and httpx.MockTransport.__getattribute__ is _TRUSTED_MOCK_TRANSPORT_GETATTRIBUTE
    )


def _owned_httpx_callables_are_pristine(
    client: httpx.AsyncClient,
    transport: object,
) -> bool:
    """Reject class or instance mutation of callables that can fabricate a response."""

    if type(client) is not httpx.AsyncClient or type(transport) is not httpx.AsyncHTTPTransport:
        return False
    try:
        client_values = vars(client)
        transport_values = vars(transport)
        selected_transport = httpx.AsyncClient._transport_for_url(client, client.base_url)
    except (AttributeError, TypeError):
        return False
    return (
        selected_transport is transport
        and client_values.get("_mounts") == {}
        and client_values.get("_auth") is None
        and client_values.get("_event_hooks") == {"request": [], "response": []}
        and client_values.get("_trust_env") is False
        and "send" not in client_values
        and "request" not in client_values
        and "stream" not in client_values
        and "build_request" not in client_values
        and "_merge_url" not in client_values
        and "_build_request_auth" not in client_values
        and "_send_handling_auth" not in client_values
        and "_send_handling_redirects" not in client_values
        and "_transport_for_url" not in client_values
        and "_send_single_request" not in client_values
        and "handle_async_request" not in transport_values
        and httpx.AsyncClient.send is _TRUSTED_ASYNC_CLIENT_SEND
        and httpx.AsyncClient.request is _TRUSTED_ASYNC_CLIENT_REQUEST
        and httpx.AsyncClient.stream is _TRUSTED_ASYNC_CLIENT_STREAM
        and httpx.AsyncClient.build_request is _TRUSTED_ASYNC_CLIENT_BUILD_REQUEST
        and httpx.AsyncClient.__getattribute__ is _TRUSTED_ASYNC_CLIENT_GETATTRIBUTE
        and httpx.AsyncClient._merge_url is _TRUSTED_ASYNC_CLIENT_MERGE_URL
        and (httpx.AsyncClient._build_request_auth is _TRUSTED_ASYNC_CLIENT_BUILD_REQUEST_AUTH)
        and (httpx.AsyncClient._send_handling_auth is _TRUSTED_ASYNC_CLIENT_SEND_HANDLING_AUTH)
        and (
            httpx.AsyncClient._send_handling_redirects
            is _TRUSTED_ASYNC_CLIENT_SEND_HANDLING_REDIRECTS
        )
        and (httpx.AsyncClient._transport_for_url is _TRUSTED_ASYNC_CLIENT_TRANSPORT_FOR_URL)
        and (httpx.AsyncClient._send_single_request is _TRUSTED_ASYNC_CLIENT_SEND_SINGLE_REQUEST)
        and (httpx.AsyncHTTPTransport.handle_async_request is _TRUSTED_ASYNC_HTTP_TRANSPORT_REQUEST)
        and (
            httpx.AsyncHTTPTransport.__getattribute__ is _TRUSTED_ASYNC_HTTP_TRANSPORT_GETATTRIBUTE
        )
    )


def _debug_json_default(value: Any) -> str:
    if isinstance(value, Decimal):
        return format(value, "f")
    raise TypeError("unsupported debug JSON value")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_nonfinite_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _require_finite_json_numbers(value: Any) -> None:
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, float) and not math.isfinite(current):
            raise ValueError("non-finite decoded JSON number")
        if isinstance(current, dict):
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=_debug_json_default,
        ).encode()
    ).hexdigest()


_TRUSTED_COPY_DEEPCOPY = copy.deepcopy
_TRUSTED_COPY_DEEPCOPY_DISPATCH: Any = copy._deepcopy_dispatch  # type: ignore[attr-defined]
_TRUSTED_COPY_DEEPCOPY_DISPATCH_ITEMS = tuple(_TRUSTED_COPY_DEEPCOPY_DISPATCH.items())
_TRUSTED_HASHLIB_SHA256 = hashlib.sha256
_TRUSTED_JSON_DUMPS = json.dumps
_TRUSTED_JSON_ENCODER = json.JSONEncoder
_TRUSTED_JSON_ENCODER_ENCODE = json.JSONEncoder.encode
_TRUSTED_JSON_ENCODER_ITERENCODE = json.JSONEncoder.iterencode
_TRUSTED_JSON_ENCODER_MODULE: Any = json.encoder
_TRUSTED_JSON_ENCODE_BASESTRING_ASCII = _TRUSTED_JSON_ENCODER_MODULE.encode_basestring_ascii
_TRUSTED_JSON_MAKE_ENCODER: Any = _TRUSTED_JSON_ENCODER_MODULE.c_make_encoder
_TRUSTED_CANDIDATE_REVIEW_CANONICAL_JSON_DUMPS = _CANDIDATE_REVIEW_CANONICAL_JSON_DUMPS
_TRUSTED_CANONICAL_SHA256 = _canonical_sha256
_TRUSTED_CANDIDATE_REVIEW_TOKEN_PLAN_PROJECTION_SHA256 = (
    _candidate_review_request_token_plan_projection_sha256
)
_TRUSTED_CANDIDATE_REVIEW_REQUEST_MATERIAL_PROJECTION = (
    _candidate_review_request_material_projection
)
_TRUSTED_ENDPOINT_REQUEST_COST_BOUND_PROJECTION_SHA256 = (
    _endpoint_request_cost_bound_projection_sha256
)


def _routing_max_price(
    endpoints: tuple[_RegisteredEndpointPricing, ...],
) -> dict[str, float]:
    """Return provider-side price ceilings that cannot round below snapshot prices."""

    if not endpoints:
        raise OpenRouterCostControlError("endpoint pricing policy is empty")
    with localcontext() as context:
        context.prec = 160
        maxima: dict[str, Decimal] = {}
        for endpoint in endpoints:
            fields = tuple(field for field, _raw_price in endpoint.pricing)
            if any(type(field) is not str for field in fields):
                raise OpenRouterCostControlError(
                    "endpoint pricing contains an unknown or duplicate component"
                )
            if len(fields) != len(set(fields)) or not set(fields).issubset(
                _SUPPORTED_TEXT_PRICING_FIELDS
            ):
                raise OpenRouterCostControlError(
                    "endpoint pricing contains an unknown or duplicate component"
                )
            if not {"prompt", "completion"}.issubset(fields):
                raise OpenRouterCostControlError(
                    "endpoint pricing cannot produce provider-side prompt and completion caps"
                )
            prices: dict[str, Decimal] = {}
            for field, raw_price in endpoint.pricing:
                if type(raw_price) is not str or not raw_price or raw_price != raw_price.strip():
                    raise OpenRouterCostControlError(
                        "endpoint price must be an exact finite nonnegative decimal string"
                    )
                try:
                    price = Decimal(raw_price)
                except (InvalidOperation, ValueError) as exc:
                    raise OpenRouterCostControlError(
                        "endpoint price must be an exact finite nonnegative decimal string"
                    ) from exc
                if not price.is_finite() or price < 0 or (price == 0 and price.is_signed()):
                    raise OpenRouterCostControlError(
                        "endpoint price must be an exact finite nonnegative decimal string"
                    )
                prices[field] = price
            cache_read_price = prices.get("input_cache_read")
            if cache_read_price is not None and cache_read_price > prices["prompt"]:
                raise OpenRouterCostControlError(
                    "input-cache-read endpoint price exceeds its provider-capped prompt price"
                )
            for field, price in prices.items():
                if field in _UNENFORCEABLE_VARIABLE_PRICING_FIELDS:
                    raise OpenRouterCostControlError(
                        "variable endpoint pricing component cannot be provider-capped"
                    )
                if field in _PROMPT_DOMINATED_PRICING_FIELDS:
                    continue
                if field not in _ROUTER_MAX_PRICE_FIELDS:
                    if price != 0:
                        raise OpenRouterCostControlError(
                            "nonzero endpoint pricing component cannot be provider-capped"
                        )
                    continue
                maxima[field] = max(maxima.get(field, Decimal(0)), price)
        if not {"prompt", "completion"}.issubset(maxima):
            raise OpenRouterCostControlError(
                "endpoint pricing cannot produce provider-side prompt and completion caps"
            )
        result: dict[str, float] = {}
        for field in sorted(maxima):
            ceiling = maxima[field]
            if field in _PER_MILLION_ROUTER_PRICE_FIELDS:
                ceiling *= Decimal(1_000_000)
            candidate = float(ceiling)
            if not math.isfinite(candidate) or candidate < 0:
                raise OpenRouterCostControlError("endpoint price cannot be represented safely")
            while Decimal(str(candidate)) < ceiling:
                candidate = math.nextafter(candidate, math.inf)
            result[field] = candidate
        return result


def _provider_capped_cost_bound_pricing(
    endpoint: _RegisteredEndpointPricing,
    routing_max_price: Mapping[str, float],
) -> tuple[tuple[str, str], ...]:
    """Price every component at an exact transmitted cap or a dominated prompt ceiling.

    Cache-read is preserved as its own full-input component but priced at the transmitted
    prompt cap, not at its stale discounted snapshot rate.  The request bound therefore adds
    full prompt and full cache-read unit ceilings at that cap and remains conservative even if
    provider accounting reports both dimensions.
    """

    if type(endpoint) is not _RegisteredEndpointPricing or type(routing_max_price) is not dict:
        raise OpenRouterCostControlError("provider-capped cost-bound inputs are invalid")
    if not routing_max_price or not set(routing_max_price).issubset(_ROUTER_MAX_PRICE_FIELDS):
        raise OpenRouterCostControlError("transmitted provider max_price fields are invalid")
    transmitted_caps: dict[str, Decimal] = {}
    with localcontext() as context:
        context.prec = 160
        for field, raw_cap in routing_max_price.items():
            if type(field) is not str or type(raw_cap) is not float or not math.isfinite(raw_cap):
                raise OpenRouterCostControlError(
                    "transmitted provider max_price is not a finite nonnegative float"
                )
            try:
                cap = Decimal(str(raw_cap))
            except (InvalidOperation, ValueError) as exc:
                raise OpenRouterCostControlError(
                    "transmitted provider max_price is not a finite nonnegative float"
                ) from exc
            if not cap.is_finite() or cap < 0 or (cap == 0 and cap.is_signed()):
                raise OpenRouterCostControlError(
                    "transmitted provider max_price is not a finite nonnegative float"
                )
            if field in _PER_MILLION_ROUTER_PRICE_FIELDS:
                cap /= Decimal(1_000_000)
            transmitted_caps[field] = cap

        raw_fields = tuple(field for field, _raw_price in endpoint.pricing)
        if any(type(field) is not str for field in raw_fields) or len(raw_fields) != len(
            set(raw_fields)
        ):
            raise OpenRouterCostControlError("endpoint pricing components are invalid")
        if not {"prompt", "completion"}.issubset(raw_fields):
            raise OpenRouterCostControlError("endpoint pricing is incomplete for cost bounding")
        raw_pricing: dict[str, Decimal] = {}
        for field, raw_price in endpoint.pricing:
            if (
                field not in _SUPPORTED_TEXT_PRICING_FIELDS
                or type(raw_price) is not str
                or not raw_price
                or raw_price != raw_price.strip()
            ):
                raise OpenRouterCostControlError("endpoint pricing is invalid for cost bounding")
            try:
                price = Decimal(raw_price)
            except (InvalidOperation, ValueError) as exc:
                raise OpenRouterCostControlError(
                    "endpoint pricing is invalid for cost bounding"
                ) from exc
            if not price.is_finite() or price < 0 or (price == 0 and price.is_signed()):
                raise OpenRouterCostControlError("endpoint pricing is invalid for cost bounding")
            raw_pricing[field] = price

        prompt_cap = transmitted_caps.get("prompt")
        if prompt_cap is None or prompt_cap < raw_pricing["prompt"]:
            raise OpenRouterCostControlError(
                "transmitted provider prompt cap rounds below endpoint pricing"
            )
        bounded: list[tuple[str, str]] = []
        for field, current in raw_pricing.items():
            if field in _UNENFORCEABLE_VARIABLE_PRICING_FIELDS:
                raise OpenRouterCostControlError(
                    "variable endpoint pricing component cannot be provider-capped"
                )
            if field in _PROMPT_DOMINATED_PRICING_FIELDS:
                if current > raw_pricing["prompt"]:
                    raise OpenRouterCostControlError(
                        "input-cache-read endpoint price exceeds its provider-capped prompt price"
                    )
                price_bound = prompt_cap
            elif field in _ROUTER_MAX_PRICE_FIELDS:
                router_cap = transmitted_caps.get(field)
                if router_cap is None or router_cap < current:
                    raise OpenRouterCostControlError(
                        "transmitted provider max_price rounds below endpoint pricing"
                    )
                price_bound = router_cap
            else:
                if current != 0:
                    raise OpenRouterCostControlError(
                        "nonzero endpoint pricing component cannot be provider-capped"
                    )
                price_bound = current
            bounded.append((field, _format_cost_decimal(price_bound)))
        return tuple(bounded)


_TRUSTED_PROVIDER_CAPPED_COST_BOUND_PRICING = _provider_capped_cost_bound_pricing


def _validated_model_catalog(response: dict[str, Any]) -> list[dict[str, Any]]:
    data = response.get("data")
    if not isinstance(data, list) or not data or any(not isinstance(item, dict) for item in data):
        raise OpenRouterModelError("OpenRouter returned an invalid models response")
    result = list(data)
    for item in result:
        model_id = item.get("id")
        if not isinstance(model_id, str) or not _is_model_slug(model_id):
            raise OpenRouterModelError("OpenRouter returned invalid model metadata")
    return result


def _is_model_slug(model: str) -> bool:
    return is_openrouter_catalog_model_id(model)


def _is_exact_model_id(model: str) -> bool:
    return is_exact_openrouter_model_id(model)


def _require_exact_model_id(model: str) -> None:
    if not _is_exact_model_id(model):
        raise OpenRouterModelError(
            "model must be an exact author/model slug without auto, random, or latest routing"
        )


def _qualification_role(role: str) -> str:
    try:
        return resolve_reasoning_request_role(role).qualification_role
    except ReasoningPolicyError as exc:
        raise OpenRouterQualificationError(
            "qualification routing received an unknown exact review role"
        ) from exc


def _is_prequalification_provider_role(role: str) -> bool:
    """Recognize only fixed provider-free benchmark routes before qualification."""

    if role in _PREQUALIFICATION_PROVIDER_ROLES:
        return True
    try:
        resolution = resolve_reasoning_request_role(role)
    except ReasoningPolicyError:
        return False
    return resolution.mapping_kind in {
        "prequalification_benchmark",
        "prequalification_role_benchmark",
    }


def _is_safe_metadata_pair(key: str, value: str) -> bool:
    return bool(
        isinstance(key, str)
        and isinstance(value, str)
        and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", key)
        and 0 < len(value.encode("utf-8")) <= 500
        and all(ord(character) >= 32 and ord(character) != 127 for character in value)
    )


def _header_value(headers: Mapping[str, str], name: str) -> str | None:
    lowered = name.casefold()
    for key, value in headers.items():
        if key.casefold() == lowered:
            return value
    return None


def _required_safe_string(value: Any, *, field: str, max_length: int = 500) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise OpenRouterSchemaError(f"model response has an invalid {field}")
    return value


def _response_content_if_string(payload: dict[str, Any]) -> str | None:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return None
    message = choices[0].get("message")
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    return content if isinstance(content, str) else None


def _raise_provider_payload_error(
    payload: dict[str, Any],
    *,
    requested_model: str,
) -> None:
    """Raise a closed typed error without retaining provider-controlled text."""

    value = payload.get("error")
    if value is None:
        return
    if not isinstance(value, dict):
        raise OpenRouterSchemaError("model provider returned malformed error data")
    code = value.get("code")
    normalized = (
        str(code).casefold() if isinstance(code, (int, str)) and not isinstance(code, bool) else ""
    )
    if normalized in {"401", "403", "authentication", "authentication_error", "unauthorized"}:
        raise OpenRouterAuthenticationError("OpenRouter rejected the API credentials")
    if normalized in {"402", "insufficient_credits", "payment_required"}:
        raise BudgetExhaustedError("OpenRouter account budget rejected the request")
    if normalized in {"404", "model_not_found", "not_found"}:
        raise OpenRouterModelError(f"configured model is unavailable: {requested_model}")
    if normalized in {"408", "425", "request_timeout", "timeout"}:
        raise OpenRouterTimeoutError("OpenRouter reported a provider timeout")
    if normalized in {"429", "rate_limit", "rate_limit_exceeded"}:
        raise OpenRouterRateLimitError("OpenRouter reported a provider rate limit")
    if normalized in {
        "500",
        "502",
        "503",
        "504",
        "provider_error",
        "provider_unavailable",
        "server_error",
        "service_unavailable",
    }:
        raise OpenRouterProviderUnavailableError(
            "OpenRouter reported that the approved provider was unavailable"
        )
    raise OpenRouterModelError("OpenRouter returned a rejected provider response")


def _validate_preservable_structured_response[ValueT: BaseModel](
    payload: dict[str, Any],
    *,
    response_model: type[ValueT],
    response_schema_generation: _PydanticSchemaGeneration,
) -> ValueT:
    """Validate non-identity envelope structure before retaining an unbound value."""

    _required_safe_string(payload.get("id"), field="generation ID")
    _required_safe_string(payload.get("model"), field="returned model")
    response_provider = payload.get("provider")
    if response_provider is not None:
        _required_safe_string(response_provider, field="provider endpoint")

    choices = payload.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise OpenRouterSchemaError("model response must contain exactly one choice")
    choice = choices[0]
    if choice.get("index") != 0:
        raise OpenRouterSchemaError("model response choice index is invalid")
    finish_reason = _required_safe_string(
        choice.get("finish_reason"),
        field="finish reason",
        max_length=100,
    )
    native_finish_reason = _optional_string(choice.get("native_finish_reason"))
    if native_finish_reason is not None:
        native_finish_reason = _required_safe_string(
            native_finish_reason,
            field="native finish reason",
            max_length=100,
        )
    if finish_reason != "stop":
        if finish_reason.casefold() in _TRUNCATED_FINISH_REASONS:
            raise OpenRouterTruncatedResponseError("model response was incomplete or truncated")
        raise OpenRouterSchemaError("model response did not finish normally")
    if (
        native_finish_reason is not None
        and native_finish_reason.casefold() in _TRUNCATED_FINISH_REASONS
    ):
        raise OpenRouterTruncatedResponseError(
            "model response native finish reason indicates truncation"
        )
    message = choice.get("message")
    if not isinstance(message, dict) or message.get("role") != "assistant":
        raise OpenRouterSchemaError("model response omitted the assistant message role")
    if message.get("tool_calls") or message.get("function_call"):
        raise OpenRouterSchemaError("model response unexpectedly requested a tool")
    if message.get("refusal") not in (None, ""):
        raise OpenRouterSchemaError("model response refused the structured request")
    content = message.get("content")
    if not isinstance(content, str):
        raise OpenRouterSchemaError("model response omitted structured text content")
    _validate_usage(payload.get("usage"))
    _validate_preservable_router_shape(payload.get("openrouter_metadata"))
    try:
        response_schema_generation.require_current(
            response_model,
            phase="before unbound-response evidence decoding",
        )
        return _decode_structured_output_with_schema_generation(
            content,
            response_model,
            schema_validator=response_schema_generation.validator,
            core_schema=response_schema_generation.core_schema,
        ).value
    except StructuredOutputDecodeError as output_error:
        raise OpenRouterStructuredOutputError(
            failure_code=output_error.code,
            repair_evidence=output_error.repair_evidence,
        ) from None


def _validate_preservable_router_shape(value: Any) -> None:
    if not isinstance(value, dict):
        raise OpenRouterSchemaError("model response omitted OpenRouter routing metadata")
    _required_safe_string(value.get("requested"), field="requested model")
    _required_safe_string(value.get("strategy"), field="router strategy")
    attempt = value.get("attempt")
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise OpenRouterSchemaError("router metadata has an invalid attempt number")
    endpoints = value.get("endpoints")
    if not isinstance(endpoints, dict):
        raise OpenRouterSchemaError("router metadata omitted endpoint evidence")
    available = endpoints.get("available")
    total = endpoints.get("total")
    if (
        not isinstance(available, list)
        or not available
        or any(not isinstance(item, dict) for item in available)
        or not isinstance(total, int)
        or isinstance(total, bool)
        or total < len(available)
    ):
        raise OpenRouterSchemaError("router metadata has invalid endpoint evidence")
    for endpoint in available:
        _required_safe_string(endpoint.get("provider"), field="selected provider")
        _required_safe_string(endpoint.get("model"), field="selected model")
        if not isinstance(endpoint.get("selected"), bool):
            raise OpenRouterSchemaError("router metadata has invalid endpoint selection evidence")
    attempts = value.get("attempts")
    if attempts is not None:
        if not isinstance(attempts, list) or any(not isinstance(item, dict) for item in attempts):
            raise OpenRouterSchemaError("router metadata has invalid provider-attempt evidence")
        for provider_attempt in attempts:
            _required_safe_string(provider_attempt.get("provider"), field="attempt provider")
            _required_safe_string(provider_attempt.get("model"), field="attempt model")
            status = provider_attempt.get("status")
            if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
                raise OpenRouterSchemaError("router metadata provider attempt is invalid")
    pipeline = value.get("pipeline", [])
    if not isinstance(pipeline, list) or any(not isinstance(stage, dict) for stage in pipeline):
        raise OpenRouterSchemaError("router metadata pipeline is invalid")
    for stage in pipeline:
        _required_safe_string(stage.get("type"), field="pipeline stage type")
        _required_safe_string(stage.get("name"), field="pipeline stage name")


def _validate_completion_envelope(
    payload: dict[str, Any],
    headers: Mapping[str, str],
    *,
    requested_model: str,
    provider_policy: OpenRouterProviderPolicy,
    endpoint_policy: _RegisteredEndpointPolicy | None,
    model_identity: _RegisteredModelIdentity | None,
) -> CompletionEnvelope:
    generation_id = _required_safe_string(payload.get("id"), field="generation ID")
    raw_header_generation_id = _header_value(headers, "x-generation-id")
    if raw_header_generation_id is not None:
        header_generation_id = _required_safe_string(
            raw_header_generation_id,
            field="X-Generation-Id header",
        )
        if generation_id != header_generation_id:
            raise OpenRouterResponseIdentityError(
                "generation header does not match the response generation ID",
                diagnostic_code="generation_id_mismatch",
                validation_status=ModelRequestValidationStatus.MODEL_MISMATCH,
            )

    returned_model = _required_safe_string(payload.get("model"), field="returned model")
    accepted_response_models = _accepted_response_models(requested_model, model_identity)
    if returned_model not in accepted_response_models:
        raise OpenRouterResponseIdentityError(
            "provider returned an unrelated model outside the frozen exact configured model identity",
            diagnostic_code="returned_model_outside_frozen_identity",
            validation_status=ModelRequestValidationStatus.MODEL_MISMATCH,
        )
    response_provider = _optional_string(payload.get("provider"))
    if response_provider is not None:
        response_provider = _required_safe_string(
            response_provider,
            field="provider endpoint",
        )

    choices = payload.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise OpenRouterSchemaError("model response must contain exactly one choice")
    choice = choices[0]
    if choice.get("index") != 0:
        raise OpenRouterSchemaError("model response choice index is invalid")
    finish_reason = _required_safe_string(
        choice.get("finish_reason"),
        field="finish reason",
        max_length=100,
    )
    native_finish_reason = _optional_string(choice.get("native_finish_reason"))
    if native_finish_reason is not None:
        native_finish_reason = _required_safe_string(
            native_finish_reason,
            field="native finish reason",
            max_length=100,
        )

    message = choice.get("message")
    if not isinstance(message, dict) or message.get("role") != "assistant":
        raise OpenRouterSchemaError("model response omitted the assistant message role")
    if message.get("tool_calls") or message.get("function_call"):
        raise OpenRouterSchemaError("model response unexpectedly requested a tool")
    refusal = message.get("refusal")
    if refusal not in (None, ""):
        raise OpenRouterSchemaError("model response refused the structured request")
    content = message.get("content")
    if not isinstance(content, str):
        raise OpenRouterSchemaError("model response omitted structured text content")

    usage = _validate_usage(payload.get("usage"))
    (
        router_metadata,
        selected_model,
        selected_provider,
        selected_provider_identity,
        selected_provider_name,
        router_attempt,
        router_attempt_count,
        router_attempts_observed,
        pipeline,
    ) = _validate_router_metadata(
        payload.get("openrouter_metadata"),
        requested_model=requested_model,
        response_provider=response_provider,
        provider_policy=provider_policy,
        endpoint_policy=endpoint_policy,
        model_identity=model_identity,
    )
    provider = selected_provider_name
    return CompletionEnvelope(
        requested_model=requested_model,
        generation_id=generation_id,
        returned_model=returned_model,
        selected_model=selected_model,
        provider=provider,
        finish_reason=finish_reason,
        native_finish_reason=native_finish_reason,
        content=content,
        usage=usage,
        router_metadata=router_metadata,
        selected_provider=selected_provider,
        selected_provider_identity=selected_provider_identity,
        selected_provider_name=selected_provider_name,
        response_provider_identity=response_provider,
        router_attempt=router_attempt,
        router_attempt_count=router_attempt_count,
        router_attempts_observed=router_attempts_observed,
        pipeline=pipeline,
    )


def _raise_for_completion_finish(
    envelope: CompletionEnvelope,
    *,
    truncated_envelope_evidence: CandidateReviewTruncatedEnvelopeEvidence | None = None,
) -> None:
    """Apply finish semantics only after the complete identity envelope was validated."""

    if envelope.finish_reason != "stop":
        if envelope.finish_reason.casefold() in _TRUNCATED_FINISH_REASONS:
            raise OpenRouterTruncatedResponseError(
                "model response was incomplete or truncated",
                envelope_evidence=truncated_envelope_evidence,
            )
        raise OpenRouterSchemaError("model response did not finish normally")
    if (
        envelope.native_finish_reason is not None
        and envelope.native_finish_reason.casefold() in _TRUNCATED_FINISH_REASONS
    ):
        raise OpenRouterTruncatedResponseError(
            "model response native finish reason indicates truncation",
            envelope_evidence=truncated_envelope_evidence,
        )
    if truncated_envelope_evidence is not None:
        raise OpenRouterSchemaError("normal completion cannot carry truncation envelope evidence")


def _validate_usage(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OpenRouterSchemaError("model response omitted usage accounting")
    fields: dict[str, int] = {}
    for field in ("prompt_tokens", "completion_tokens", "total_tokens"):
        item = value.get(field)
        if (
            not isinstance(item, int)
            or isinstance(item, bool)
            or item < 0
            or item > _MAX_TOKEN_EVIDENCE
        ):
            raise OpenRouterSchemaError("model response has invalid usage accounting")
        fields[field] = item
    if fields["total_tokens"] != fields["prompt_tokens"] + fields["completion_tokens"]:
        raise OpenRouterSchemaError("model response usage totals are inconsistent")
    if _optional_cost_decimal(value.get("cost")) is None:
        raise OpenRouterSchemaError("model response has invalid cost accounting")
    reasoning_tokens = _validate_token_detail_aliases(
        value,
        direct_field="reasoning_tokens",
        detail_field="completion_tokens_details",
        token_field="reasoning_tokens",
    )
    cached_tokens = _validate_token_detail_aliases(
        value,
        direct_field="cached_tokens",
        detail_field="prompt_tokens_details",
        token_field="cached_tokens",
    )
    normalized_reasoning_tokens = reasoning_tokens or 0
    normalized_cached_tokens = cached_tokens or 0
    if (
        normalized_reasoning_tokens > fields["completion_tokens"]
        or normalized_cached_tokens > fields["prompt_tokens"]
    ):
        raise OpenRouterSchemaError(
            "model response token details are inconsistent "
            f"(prompt_tokens={fields['prompt_tokens']}, "
            f"completion_tokens={fields['completion_tokens']}, "
            f"reasoning_tokens={normalized_reasoning_tokens}, "
            f"cached_tokens={normalized_cached_tokens})"
        )
    return value


def _validate_router_metadata(
    value: Any,
    *,
    requested_model: str,
    response_provider: str | None,
    provider_policy: OpenRouterProviderPolicy,
    endpoint_policy: _RegisteredEndpointPolicy | None,
    model_identity: _RegisteredModelIdentity | None,
) -> tuple[
    dict[str, Any],
    str,
    str,
    str,
    str,
    int,
    int,
    bool,
    tuple[dict[str, str], ...],
]:
    if not isinstance(value, dict):
        raise OpenRouterSchemaError("model response omitted OpenRouter routing metadata")
    if value.get("requested") != requested_model:
        raise OpenRouterResponseIdentityError(
            "router metadata does not bind the exact configured model",
            diagnostic_code="router_request_model_mismatch",
            validation_status=ModelRequestValidationStatus.MODEL_MISMATCH,
        )
    strategy = _required_safe_string(value.get("strategy"), field="router strategy")
    permitted_strategies = {"direct"}
    if provider_policy.allow_fallbacks:
        permitted_strategies.add("fallback")
    if strategy in _NON_DIRECT_ROUTING_STRATEGIES and strategy not in permitted_strategies:
        raise OpenRouterResponseIdentityError(
            "router used an unapproved model or fallback strategy",
            diagnostic_code="unapproved_fallback",
            validation_status=ModelRequestValidationStatus.PROVIDER_MISMATCH,
        )
    if strategy not in permitted_strategies:
        raise OpenRouterResponseIdentityError(
            "router used an unknown or unapproved routing strategy",
            diagnostic_code="router_strategy_unapproved",
            validation_status=ModelRequestValidationStatus.PROVIDER_MISMATCH,
        )
    router_attempt = value.get("attempt")
    if (
        not isinstance(router_attempt, int)
        or isinstance(router_attempt, bool)
        or router_attempt < 1
    ):
        raise OpenRouterSchemaError("router metadata has an invalid attempt number")
    if not provider_policy.allow_fallbacks and router_attempt != 1:
        raise OpenRouterResponseIdentityError(
            "router attempted an unapproved provider fallback",
            diagnostic_code="unapproved_fallback",
            validation_status=ModelRequestValidationStatus.PROVIDER_MISMATCH,
        )

    endpoints = value.get("endpoints")
    if not isinstance(endpoints, dict):
        raise OpenRouterSchemaError("router metadata omitted endpoint evidence")
    available = endpoints.get("available")
    total = endpoints.get("total")
    if (
        not isinstance(available, list)
        or not available
        or any(not isinstance(item, dict) for item in available)
        or not isinstance(total, int)
        or isinstance(total, bool)
        or total < len(available)
    ):
        raise OpenRouterSchemaError("router metadata has invalid endpoint evidence")
    selected = [item for item in available if item.get("selected") is True]
    if len(selected) != 1:
        raise OpenRouterResponseIdentityError(
            "router metadata does not identify exactly one selected provider",
            diagnostic_code="provider_selection_ambiguous",
            validation_status=ModelRequestValidationStatus.PROVIDER_MISMATCH,
        )
    selected_model = _required_safe_string(selected[0].get("model"), field="selected model")
    selected_provider_identity = _required_safe_string(
        selected[0].get("provider"),
        field="selected provider",
    )
    accepted_response_models = frozenset((requested_model,))
    if model_identity is not None:
        if model_identity.exact_model_id != requested_model:
            raise OpenRouterResponseIdentityError(
                "registered model identity does not match the request",
                diagnostic_code="registered_model_identity_mismatch",
                validation_status=ModelRequestValidationStatus.MODEL_MISMATCH,
            )
        accepted_response_models = model_identity.accepted_response_models
    if selected_model not in accepted_response_models:
        raise OpenRouterResponseIdentityError(
            "selected provider used a different exact model",
            diagnostic_code="selected_model_outside_frozen_identity",
            validation_status=ModelRequestValidationStatus.MODEL_MISMATCH,
        )
    selected_provider = _resolve_provider_endpoint(
        selected_provider_identity,
        provider_policy=provider_policy,
        endpoint_policy=endpoint_policy,
    )
    selected_endpoint = (
        endpoint_policy.endpoint(selected_provider_identity)
        if endpoint_policy is not None
        else None
    )
    selected_provider_name = (
        selected_endpoint.provider_name
        if selected_endpoint is not None
        else selected_provider_identity
    )
    if response_provider is not None:
        response_provider_endpoint = _resolve_provider_endpoint(
            response_provider,
            provider_policy=provider_policy,
            endpoint_policy=endpoint_policy,
        )
        if response_provider_endpoint != selected_provider:
            raise OpenRouterResponseIdentityError(
                "selected provider does not match the response provider",
                diagnostic_code="provider_identity_mismatch",
                validation_status=ModelRequestValidationStatus.PROVIDER_MISMATCH,
            )

    attempts = value.get("attempts")
    attempts_observed = attempts is not None
    if attempts is None:
        if router_attempt != 1:
            raise OpenRouterSchemaError(
                "router omitted provider-attempt evidence after multiple attempts"
            )
        if endpoint_policy is None:
            raise OpenRouterSchemaError(
                "router omitted provider-attempt evidence without an exact endpoint binding"
            )
        attempt_count = 1
    else:
        if (
            not isinstance(attempts, list)
            or len(attempts) != router_attempt
            or any(not isinstance(item, dict) for item in attempts)
        ):
            raise OpenRouterSchemaError("router metadata has invalid provider-attempt evidence")
        for index, attempt in enumerate(attempts):
            attempt_model = _required_safe_string(attempt.get("model"), field="attempt model")
            attempt_provider_name = _required_safe_string(
                attempt.get("provider"),
                field="attempt provider",
            )
            status = attempt.get("status")
            if attempt_model != selected_model:
                raise OpenRouterResponseIdentityError(
                    "router metadata provider attempt used a different model",
                    diagnostic_code="provider_attempt_model_mismatch",
                    validation_status=ModelRequestValidationStatus.MODEL_MISMATCH,
                )
            if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
                raise OpenRouterSchemaError("router metadata provider attempt is invalid")
            attempt_provider = _resolve_provider_endpoint(
                attempt_provider_name,
                provider_policy=provider_policy,
                endpoint_policy=endpoint_policy,
            )
            if index == len(attempts) - 1 and (
                status != 200 or attempt_provider != selected_provider
            ):
                raise OpenRouterResponseIdentityError(
                    "router success attempt does not match selected provider",
                    diagnostic_code="provider_success_route_mismatch",
                    validation_status=ModelRequestValidationStatus.PROVIDER_MISMATCH,
                )
        if not provider_policy.allow_fallbacks and len(attempts) != 1:
            raise OpenRouterResponseIdentityError(
                "router performed an unapproved provider fallback",
                diagnostic_code="unapproved_fallback",
                validation_status=ModelRequestValidationStatus.PROVIDER_MISMATCH,
            )
        attempt_count = len(attempts)

    raw_pipeline = value.get("pipeline", [])
    if not isinstance(raw_pipeline, list) or any(
        not isinstance(stage, dict) for stage in raw_pipeline
    ):
        raise OpenRouterSchemaError("router metadata pipeline is invalid")
    pipeline: list[dict[str, str]] = []
    for stage in raw_pipeline:
        stage_type = _required_safe_string(stage.get("type"), field="pipeline stage type")
        stage_name = _required_safe_string(stage.get("name"), field="pipeline stage name")
        pipeline.append({"type": stage_type, "name": stage_name})
    if provider_policy.certification and pipeline:
        raise OpenRouterResponseIdentityError(
            "certification forbids provider-side pipeline transformations",
            diagnostic_code="provider_pipeline_unapproved",
            validation_status=ModelRequestValidationStatus.PROVIDER_MISMATCH,
        )
    return (
        value,
        selected_model,
        selected_provider,
        selected_provider_identity,
        selected_provider_name,
        router_attempt,
        attempt_count,
        attempts_observed,
        tuple(pipeline),
    )


def _resolve_provider_endpoint(
    provider_identity: str,
    *,
    provider_policy: OpenRouterProviderPolicy,
    endpoint_policy: _RegisteredEndpointPolicy | None,
) -> str:
    if endpoint_policy is not None:
        endpoint = endpoint_policy.endpoint(provider_identity)
        if endpoint is None:
            raise OpenRouterResponseIdentityError(
                "provider response identity is outside or ambiguous under the endpoint snapshot",
                diagnostic_code="endpoint_variant_mismatch",
                validation_status=ModelRequestValidationStatus.PROVIDER_MISMATCH,
            )
        return endpoint.provider_endpoint
    configured = {
        provider.casefold(): provider for provider in provider_policy.configured_endpoints
    }
    if configured:
        configured_endpoint = configured.get(provider_identity.casefold())
        if configured_endpoint is None:
            raise OpenRouterResponseIdentityError(
                "selected provider is outside the configured endpoint policy",
                diagnostic_code="provider_outside_approved_route",
                validation_status=ModelRequestValidationStatus.PROVIDER_MISMATCH,
            )
        return configured_endpoint
    return provider_identity


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _decoded_response_headers(headers: httpx.Headers) -> dict[str, str]:
    removed = {"content-encoding", "content-length", "transfer-encoding"}
    return {
        name: value
        for name, value in safe_headers(dict(headers)).items()
        if name.lower() not in removed
    }


def _nested_string_values(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str):
                yield key
            yield from _nested_string_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _nested_string_values(child)


def _optional_cost_decimal(value: Any) -> Decimal | None:
    if isinstance(value, bool) or not isinstance(value, (Decimal, int, float)):
        return None
    try:
        normalized = value if isinstance(value, Decimal) else Decimal(str(value))
    except (ArithmeticError, ValueError):
        return None
    if not normalized.is_finite() or normalized < 0:
        return None
    if normalized == 0:
        return Decimal(0)
    if normalized >= _REPORTED_COST_USD_MAGNITUDE_LIMIT:
        return None
    try:
        with localcontext() as context:
            context.prec = 64
            quantized = normalized.quantize(_REPORTED_COST_USD_QUANTUM)
    except InvalidOperation:
        return None
    if normalized != quantized:
        return None
    return normalized


def _nonnegative_int(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return 0


def _validate_token_detail_aliases(
    usage: Mapping[str, Any],
    *,
    direct_field: str,
    detail_field: str,
    token_field: str,
) -> int | None:
    """Resolve provider aliases; explicit null means the optional count is unavailable."""

    direct_value = _validate_optional_token_detail_count(
        usage.get(direct_field),
        field=direct_field,
    )

    nested_value: int | None = None
    details = usage.get(detail_field)
    if details is not None:
        if not isinstance(details, dict):
            raise OpenRouterSchemaError(f"model response token detail {detail_field} is invalid")
        nested_value = _validate_optional_token_detail_count(
            details.get(token_field),
            field=f"{detail_field}.{token_field}",
        )

    if direct_value is not None and nested_value is not None and direct_value != nested_value:
        raise OpenRouterSchemaError(
            "model response token details are inconsistent "
            f"({direct_field}={direct_value}, "
            f"{detail_field}.{token_field}={nested_value})"
        )
    if direct_value is not None:
        return direct_value
    return nested_value


def _validate_optional_token_detail_count(value: Any, *, field: str) -> int | None:
    if value is None:
        return None
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > _MAX_TOKEN_EVIDENCE
    ):
        raise OpenRouterSchemaError(f"model response token detail {field} is invalid")
    return value


def _reasoning_tokens(usage: Mapping[str, Any]) -> int:
    return _observed_reasoning_tokens(usage) or 0


def _observed_reasoning_tokens(usage: Mapping[str, Any]) -> int | None:
    return _validate_token_detail_aliases(
        usage,
        direct_field="reasoning_tokens",
        detail_field="completion_tokens_details",
        token_field="reasoning_tokens",
    )


def _cached_tokens(usage: Mapping[str, Any]) -> int:
    return (
        _validate_token_detail_aliases(
            usage,
            direct_field="cached_tokens",
            detail_field="prompt_tokens_details",
            token_field="cached_tokens",
        )
        or 0
    )


def _accepted_response_models(
    requested_model: str,
    model_identity: _RegisteredModelIdentity | None,
) -> frozenset[str]:
    if model_identity is None or model_identity.exact_model_id != requested_model:
        return frozenset((requested_model,))
    return model_identity.accepted_response_models


def _is_concluded_unbound_completion(completion: StructuredCompletion[Any]) -> bool:
    return (
        completion.usage_record.identity_strength is ModelIdentityStrength.UNBOUND
        and completion.usage_record.routing.get("identity_binding_status")
        in {"generation_metadata_unbound", "response_identity_unbound"}
    )


def _is_repaired_noncreditable_completion(
    completion: StructuredCompletion[Any],
) -> bool:
    return (
        completion.usage_record.status == "repaired_noncreditable"
        and completion.usage_record.routing.get("repair_used") is True
    )


def _identity_failure_diagnostic(
    *,
    payload: dict[str, Any] | None,
    requested_model: str,
    model_identity: _RegisteredModelIdentity | None,
    error: Exception,
) -> dict[str, str] | None:
    """Return a bounded non-secret reason why provider identity stayed unbound."""

    returned_model = (
        _safe_identity_diagnostic_string(payload.get("model")) if payload is not None else None
    )
    accepted = _accepted_response_models(requested_model, model_identity)
    canonical_model = (
        model_identity.canonical_slug if model_identity is not None else requested_model
    )
    if isinstance(error, OpenRouterResponseIdentityError):
        diagnostic = {
            "code": error.diagnostic_code,
            "requested_model": requested_model,
            "canonical_model": canonical_model,
        }
        if returned_model is not None:
            diagnostic["returned_model"] = returned_model
        return diagnostic
    if returned_model is not None and returned_model not in accepted:
        return {
            "code": "returned_model_outside_frozen_identity",
            "requested_model": requested_model,
            "canonical_model": canonical_model,
            "returned_model": returned_model,
        }
    if isinstance(error, OpenRouterProviderPolicyError):
        return {
            "code": "provider_endpoint_outside_frozen_identity",
            "requested_model": requested_model,
            "canonical_model": canonical_model,
        }
    if isinstance(error, OpenRouterModelError):
        return {
            "code": "model_identity_unbound",
            "requested_model": requested_model,
            "canonical_model": canonical_model,
        }
    return None


def _safe_identity_diagnostic_string(value: Any) -> str | None:
    try:
        return _required_safe_string(value, field="identity diagnostic", max_length=300)
    except OpenRouterSchemaError:
        return None


def _usage_dict(payload: dict[str, Any]) -> dict[str, Any]:
    usage = payload.get("usage", {})
    return usage if isinstance(usage, dict) else {}


def _optional_finish_reason(payload: dict[str, Any] | None) -> str | None:
    if payload is None:
        return None
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return None
    return _optional_string(choices[0].get("finish_reason"))


def _optional_native_finish_reason(payload: dict[str, Any] | None) -> str | None:
    if payload is None:
        return None
    choices = payload.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        return None
    return _optional_string(choices[0].get("native_finish_reason"))


def _payload_has_truncation_marker(payload: dict[str, Any] | None) -> bool:
    """Return true only for a recognized normalized or native length marker."""

    if payload is None:
        return False
    choices = payload.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        return False
    return any(
        isinstance(value, str) and value.casefold() in _TRUNCATED_FINISH_REASONS
        for value in (
            choices[0].get("finish_reason"),
            choices[0].get("native_finish_reason"),
        )
    )


def _response_generation_id(
    payload: dict[str, Any] | None,
    headers: Mapping[str, str],
) -> str | None:
    body_id = _optional_string(payload.get("id")) if payload is not None else None
    return body_id or _header_value(headers, "x-generation-id")


def _provider_error_classification(error: Exception) -> str:
    if isinstance(error, OpenRouterResponseIdentityError):
        return "identity_unbound"
    if isinstance(error, OpenRouterAuthenticationError):
        return "authentication"
    if isinstance(error, BudgetExhaustedError):
        return "budget"
    if isinstance(error, OpenRouterCostControlError):
        return "cost_control"
    if isinstance(error, OpenRouterTimeoutError):
        return "timeout"
    if isinstance(error, OpenRouterRateLimitError):
        return "rate_limit"
    if isinstance(error, OpenRouterProviderUnavailableError):
        return "provider_unavailable"
    if isinstance(error, OpenRouterProviderPolicyError):
        return "provider_policy"
    if isinstance(error, OpenRouterModelError):
        return "model"
    if isinstance(error, OpenRouterTruncatedResponseError):
        return "truncated_response"
    if isinstance(error, OpenRouterSchemaError):
        return "invalid_response"
    if isinstance(error, OpenRouterPrivacyError):
        return "privacy"
    if isinstance(error, OpenRouterRequestLimitError):
        return "request_limit"
    return "internal"


def _generation_metadata_payload_may_be_pending(
    payload: Mapping[str, Any],
    *,
    requested_generation_id: str,
    reconciliation_expectation: GenerationReconciliationExpectation | None,
    retrieval_attempts: int,
    execution_evidence: ExecutionEvidenceKind,
) -> bool:
    """Validate all explicit fields before retrying one incomplete observation."""

    data = payload.get("data")
    if data is None:
        return True
    if not isinstance(data, dict):
        raise GenerationEvidenceValidationError("generation response data is not an object")
    observed_generation_id = data.get("id")
    if observed_generation_id is not None and observed_generation_id != requested_generation_id:
        if reconciliation_expectation is not None:
            raise GenerationReconciliationMismatchError(
                GenerationReconciliationMismatchCode.GENERATION_ID
            )
        raise GenerationEvidenceValidationError(
            "generation response does not bind the requested generation ID"
        )
    required_fields = (
        "id",
        "model",
        "provider_name",
        "finish_reason",
        "tokens_prompt",
        "tokens_completion",
        "total_cost",
        "cancelled",
    )
    missing_fields = tuple(field for field in required_fields if field not in data)
    if not missing_fields:
        return False

    projected_data = dict(data)
    projected_data.setdefault("id", requested_generation_id)
    usage = (
        reconciliation_expectation.usage_record if reconciliation_expectation is not None else None
    )
    projected_data.setdefault(
        "model",
        (
            reconciliation_expectation.canonical_model_id
            if reconciliation_expectation is not None
            else "openrouter/pending-generation"
        ),
    )
    projected_data.setdefault(
        "provider_name",
        (
            reconciliation_expectation.expected_provider_name
            if reconciliation_expectation is not None
            else "Pending Provider"
        ),
    )
    projected_data.setdefault(
        "finish_reason",
        usage.finish_reason if usage is not None else "pending",
    )
    projected_data.setdefault(
        "tokens_prompt",
        usage.prompt_tokens if usage is not None else 0,
    )
    projected_data.setdefault(
        "tokens_completion",
        usage.completion_tokens if usage is not None else 0,
    )
    projected_data.setdefault("cancelled", False)
    if "total_cost" not in projected_data and "usage" in projected_data:
        projected_data["total_cost"] = projected_data["usage"]
    elif "usage" not in projected_data and "total_cost" in projected_data:
        projected_data["usage"] = projected_data["total_cost"]
    elif "total_cost" not in projected_data:
        expected_cost = usage.reported_cost_usd if usage is not None else 0
        projected_data["total_cost"] = expected_cost
        projected_data["usage"] = expected_cost
    if reconciliation_expectation is not None:
        projected_data.setdefault(
            "native_finish_reason",
            reconciliation_expectation.usage_record.routing.get("native_finish_reason"),
        )
    projected = validate_openrouter_generation_payload(
        {"data": projected_data},
        requested_generation_id=requested_generation_id,
        retrieved_at=datetime.now(UTC),
        retrieval_attempts=retrieval_attempts,
        execution_evidence=execution_evidence,
    )
    if reconciliation_expectation is None:
        return True
    try:
        _reconcile_generation_evidence_structural(
            projected,
            usage_record=reconciliation_expectation.usage_record,
            expected_exact_model=reconciliation_expectation.exact_model_id,
            expected_canonical_model=reconciliation_expectation.canonical_model_id,
            expected_catalog_identity_binding_sha256=(
                reconciliation_expectation.catalog_identity_binding_sha256
            ),
            expected_discovery_evidence_sha256=(
                reconciliation_expectation.discovery_evidence_sha256
            ),
            expected_provider_name=reconciliation_expectation.expected_provider_name,
            require_certification=reconciliation_expectation.require_certification,
        )
    except GenerationReconciliationMismatchError as exc:
        if exc.is_eventual_usage_field:
            return True
        raise
    return True


def _generation_metadata_poll_delays(
    request_timeout_seconds: float,
) -> tuple[float, ...]:
    """Select a fixed readiness schedule bounded by the configured request horizon."""

    if (
        not isinstance(request_timeout_seconds, (int, float))
        or isinstance(request_timeout_seconds, bool)
        or not math.isfinite(request_timeout_seconds)
        or request_timeout_seconds <= 0
    ):
        raise OpenRouterRequestLimitError("generation metadata readiness timeout is invalid")
    wait_budget = min(
        float(request_timeout_seconds),
        _MAXIMUM_GENERATION_METADATA_WAIT_SECONDS,
    )
    selected: list[float] = []
    cumulative_wait = 0.0
    for delay_seconds in _GENERATION_METADATA_POLL_DELAYS_SECONDS:
        if cumulative_wait + delay_seconds > wait_budget:
            break
        selected.append(delay_seconds)
        cumulative_wait += delay_seconds
    if not selected or len(selected) > MAX_GENERATION_EVIDENCE_RETRIEVAL_ATTEMPTS:
        raise OpenRouterRequestLimitError("generation metadata readiness schedule is invalid")
    return tuple(selected)


def _generation_metadata_operation_timeout(
    request_timeout_seconds: float,
) -> float:
    """Return one hard wall-clock budget for all observations and waits."""

    poll_delays = _generation_metadata_poll_delays(request_timeout_seconds)
    io_budget = min(
        max(
            float(request_timeout_seconds) * _GENERATION_METADATA_IO_BUDGET_FRACTION,
            _MINIMUM_GENERATION_METADATA_IO_BUDGET_SECONDS,
        ),
        _MAXIMUM_GENERATION_METADATA_IO_BUDGET_SECONDS,
    )
    return sum(poll_delays) + io_budget


def _generation_metadata_failure_diagnostic(
    error: OpenRouterError,
) -> OpenRouterIdentityDiagnosticCode:
    if isinstance(error, OpenRouterAuthenticationError):
        return OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_AUTHENTICATION_FAILED
    if isinstance(error, OpenRouterTimeoutError):
        return OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_TIMEOUT
    if isinstance(error, OpenRouterRateLimitError):
        return OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_RATE_LIMITED
    if isinstance(error, OpenRouterProviderUnavailableError):
        return OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_PROVIDER_UNAVAILABLE
    if isinstance(error, OpenRouterGenerationMetadataNotReadyError):
        return OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_NOT_READY
    if isinstance(error, OpenRouterPrivacyError):
        return OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_INTEGRITY_REJECTED
    if isinstance(error, OpenRouterSchemaError):
        return OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_INVALID
    return OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_RETRIEVAL_FAILED


def _failure_validation_status(error: Exception) -> ModelRequestValidationStatus:
    if isinstance(error, OpenRouterResponseIdentityError):
        return error.validation_status
    if isinstance(error, OpenRouterTruncatedResponseError):
        return ModelRequestValidationStatus.TRUNCATED
    if isinstance(error, OpenRouterProviderPolicyError):
        return ModelRequestValidationStatus.PROVIDER_MISMATCH
    if isinstance(error, OpenRouterModelError):
        return ModelRequestValidationStatus.MODEL_MISMATCH
    if isinstance(error, OpenRouterSchemaError):
        return ModelRequestValidationStatus.INVALID_RESPONSE
    return ModelRequestValidationStatus.PROVIDER_ERROR


def _failure_status(
    error: Exception,
    requested_model: str,
    payload: dict[str, Any] | None,
    *,
    accepted_response_models: frozenset[str] | None = None,
) -> str:
    returned_model = _optional_string(payload.get("model")) if payload is not None else None
    accepted = accepted_response_models or frozenset((requested_model,))
    if isinstance(error, OpenRouterResponseIdentityError):
        return "unbound_identity"
    if isinstance(error, OpenRouterTruncatedResponseError):
        return "rejected_truncated_response"
    if returned_model is not None and returned_model not in accepted:
        return "rejected_model_substitution"
    if isinstance(error, OpenRouterProviderPolicyError):
        return "rejected_provider_substitution"
    return f"failed:{type(error).__name__}"


def _ensure_all_fields_supplied(value: Any, path: str = "response") -> None:
    if isinstance(value, BaseModel):
        missing = sorted(set(type(value).model_fields) - value.model_fields_set)
        if missing:
            raise ValueError(f"{path} omitted required field(s): {', '.join(missing)}")
        for name in type(value).model_fields:
            _ensure_all_fields_supplied(getattr(value, name), f"{path}.{name}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _ensure_all_fields_supplied(item, f"{path}[{index}]")
