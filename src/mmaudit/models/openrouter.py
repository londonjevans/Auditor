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
import time
import uuid
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal, TypeVar, cast
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ValidationError

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
    _issue_trusted_generation_verification,
    _reconcile_generation_evidence_structural,
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
    supports_provider_structured_output,
    supports_reasoning_request,
)
from mmaudit.models.schemas import (
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
    decode_structured_output,
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
from mmaudit.models.usage import (
    UsageLedger,
    _attest_owned_real_usage_record,
    _has_owned_real_usage_attestation,
    _validated_usage_copy_preserving_owned_attestation,
)
from mmaudit.orchestration.budgets import (
    BudgetExhaustedError,
    BudgetManager,
    EndpointRequestCostBound,
    Reservation,
    UnprovenCostBoundError,
)
from mmaudit.orchestration.context_manifest import (
    ContextPlanningSnapshot,
    ContextPreflightLedger,
    ContextPreflightReason,
    ContextPreflightRequestEvidence,
    ContextPreflightSource,
    ContextRequestState,
)
from mmaudit.privacy import (
    EffectivePrivacyPolicyEvidence,
    EndpointPolicyClass,
    TrustedPrivacyAuthorization,
    validate_trusted_privacy_authorization,
)
from mmaudit.reporting.json_report import stable_json

ResponseT = TypeVar("ResponseT", bound=BaseModel)

_NORMALIZED_OPENROUTER_BASE_URL = OPENROUTER_DEFAULT_BASE_URL.rstrip("/") + "/"
_PROVIDER_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,127}$")
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
        "input_cache_read",
        "input_cache_write",
        "internal_reasoning",
    }
)
_TRUSTED_ASYNC_CLIENT_SEND = httpx.AsyncClient.send
_TRUSTED_ASYNC_CLIENT_REQUEST = httpx.AsyncClient.request
_TRUSTED_ASYNC_CLIENT_STREAM = httpx.AsyncClient.stream
_TRUSTED_ASYNC_HTTP_TRANSPORT_REQUEST = httpx.AsyncHTTPTransport.handle_async_request
_QUALIFICATION_FUTURE_SKEW = timedelta(minutes=5)
_QUALIFICATION_LINEAGE_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_QUALIFICATION_ROLE_PATTERN = re.compile(r"^[a-z][a-z0-9_:.-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_PREQUALIFICATION_PROVIDER_ROLES = frozenset({"model_benchmark", "real_provider_smoke"})
_BASE_ENDPOINT_REQUEST_PARAMETERS = frozenset({"max_tokens", "temperature"})
_ROUTE_SENSITIVE_REQUEST_PARAMETERS = frozenset({"reasoning", "response_format"})
_LOCAL_MOCK_PROVIDER_ENDPOINT = "mmaudit-local-mock"
_MAX_TOKEN_EVIDENCE = 2**31 - 1
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
            self.endpoint_snapshot_sha256,
            self.output_capability_sha256,
            self.model_metadata_snapshot_sha256,
            self.pricing_snapshot_sha256,
        ):
            if _SHA256_PATTERN.fullmatch(value) is None:
                raise ValueError("qualification routing contains a malformed evidence hash")

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

    def request_metadata(self) -> dict[str, str]:
        """Return bounded non-secret hashes for OpenRouter request metadata."""

        return {
            "mmaudit_qualification_artifact_sha256": self.qualification_artifact_sha256,
            "mmaudit_qualification_verification_sha256": (self.qualification_verification_sha256),
            "mmaudit_production_selection_sha256": self.production_selection_sha256,
            "mmaudit_selection_verification_sha256": self.selection_verification_sha256,
            "mmaudit_qualification_result_sha256": self.qualification_result_sha256,
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
        }


@dataclass(frozen=True)
class OpenRouterReasoning:
    """Bounded reasoning controls supported by OpenRouter."""

    effort: Literal["none", "minimal", "low", "medium", "high", "xhigh"] | None = None
    max_tokens: int | None = None
    exclude: bool = False

    def __post_init__(self) -> None:
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
    request_shape_sha256: str


@dataclass(frozen=True)
class _RegisteredEndpointPricing:
    provider_endpoint: str
    provider_name: str
    provider_identities: tuple[str, ...]
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


class OpenRouterTruncatedResponseError(OpenRouterSchemaError):
    pass


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


def strict_json_schema(response_model: type[BaseModel]) -> dict[str, Any]:
    """Normalize Pydantic JSON Schema for strict structured-output providers."""

    schema = copy.deepcopy(response_model.model_json_schema())

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
    return schema


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
) -> _StructuredOutputRequestPlan:
    """Build one deterministic request protocol without model-authored repair."""

    schema = strict_json_schema(response_model)
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


def _structured_output_prompt_sha256_from_plan(
    plan: _StructuredOutputRequestPlan,
) -> str:
    return _canonical_sha256(
        [
            {"role": "system", "content": plan.system_prompt},
            {"role": "user", "content": plan.user_prompt},
        ]
    )


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
    from mmaudit.orchestration.context import render_context, revalidate_context_package

    sealed = revalidate_context_package(context_package)
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
) -> None:
    """Require frozen endpoint metadata to bind every emitted special parameter."""

    planned = set(plan.required_provider_parameters)
    for endpoint in endpoint_policy.endpoints:
        frozen = set(endpoint.required_request_parameters) - _BASE_ENDPOINT_REQUEST_PARAMETERS
        if frozen != planned or not planned.issubset(endpoint.supported_parameters):
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
        token_budgets: TokenBudgetConfig | None = None,
        qualification_routing: tuple[OpenRouterQualificationRoutingEvidence, ...] = (),
        effective_privacy_policy: EffectivePrivacyPolicyEvidence | None = None,
        privacy_authorization: TrustedPrivacyAuthorization | None = None,
        context_preflight_ledger: ContextPreflightLedger | None = None,
    ) -> None:
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
        self.reasoning = reasoning
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
        self._privacy_authorization = privacy_authorization
        self._endpoint_pricing: dict[str, _RegisteredEndpointPolicy] = {}
        self._model_identities: dict[str, _RegisteredModelIdentity] = {}
        qualification_model_ids = tuple(binding.exact_model_id for binding in qualification_routing)
        if qualification_model_ids != tuple(sorted(set(qualification_model_ids))):
            raise OpenRouterQualificationError(
                "qualification routing bindings must be unique and sorted by exact model"
            )
        self._qualification_routing = {
            binding.exact_model_id: binding for binding in qualification_routing
        }
        self._metadata_observations: dict[str, str] = {}
        self._unbound_completions: dict[str, StructuredCompletion[Any]] = {}
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
        self._owns_client = http_client is None
        closed_mock_transport = _uses_closed_httpx_mock_transport(http_client)
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
        self.execution_evidence = (
            ExecutionEvidenceKind.MOCK
            if closed_mock_transport
            else (
                ExecutionEvidenceKind.REAL
                if self._owns_client
                else ExecutionEvidenceKind.UNVERIFIED
            )
        )
        self._requires_paid_controls = (
            not closed_mock_transport or self.budget.atomic_ledger is not None
        )
        self._credential = bytearray(api_key.encode("utf-8"))
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/mmaudit/mmaudit",
            "X-OpenRouter-Title": "mmaudit",
            "X-OpenRouter-Metadata": "enabled",
        }
        self._client = http_client or httpx.AsyncClient(
            base_url=normalized_base_url,
            timeout=httpx.Timeout(execution.request_timeout_seconds),
            headers=self._headers,
            trust_env=False,
        )
        self._client_identity = self._client
        self._transport_identity = getattr(self._client, "_transport", None)
        self._owned_client_identity = self._client if self._owns_client else None
        self._owned_transport_identity = (
            getattr(self._client, "_transport", None) if self._owns_client else None
        )
        if self._owns_client and not _owned_httpx_callables_are_pristine(
            self._client,
            self._owned_transport_identity,
        ):
            raise OpenRouterPrivacyError("owned provider callable provenance is invalid")

    async def __aenter__(self) -> OpenRouterClient:
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.close()

    async def close(self) -> None:
        self.clear_credentials()
        if self._owned_client_identity is not None:
            await self._owned_client_identity.aclose()

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
        privacy_authorization: TrustedPrivacyAuthorization | None,
    ) -> None:
        """Bind one canonical source policy before any provider state is observed."""

        if self.effective_privacy_policy is not None or self._privacy_authorization is not None:
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
            return
        if privacy_authorization is None:
            raise OpenRouterPrivacyError(
                "non-ZDR privacy evidence and live authorization must be supplied together"
            )
        self.effective_privacy_policy = policy
        self._privacy_authorization = privacy_authorization
        try:
            self._validate_non_zdr_privacy_authorization(
                policy.permitted_model_ids,
                request_provider_endpoints=self.provider_policy.configured_endpoints,
            )
        except Exception:
            self.effective_privacy_policy = None
            self._privacy_authorization = None
            raise

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
            or self.execution_evidence is not ExecutionEvidenceKind.REAL
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
                        execution_evidence=self.execution_evidence,
                    )
                except (GenerationEvidenceValidationError, ValidationError):
                    try:
                        may_be_pending = _generation_metadata_payload_may_be_pending(
                            payload,
                            requested_generation_id=validated_generation_id,
                            reconciliation_expectation=expectation,
                            retrieval_attempts=attempt,
                            execution_evidence=self.execution_evidence,
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

        if not _openrouter_generation_verification_callables_are_pristine():
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
            or self.execution_evidence is not ExecutionEvidenceKind.REAL
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
            return _issue_trusted_generation_verification(
                requests=normalized,
                attestations=attestations,
                verification_started_at=verification_started_at,
            )
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
                or self.execution_evidence is not ExecutionEvidenceKind.REAL
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
        identity = _RegisteredModelIdentity(
            exact_model_id=evidence.exact_model_id,
            canonical_slug=evidence.canonical_slug,
            model_metadata_snapshot_sha256=evidence.model_metadata_snapshot_sha256,
            catalog_identity_binding_sha256=evidence.catalog_identity_binding_sha256,
            catalog_snapshot_sha256=evidence.provenance.catalog_snapshot_sha256,
            discovery_provenance_sha256=evidence.provenance.provenance_sha256,
            discovery_evidence_sha256=evidence.discovery_evidence_sha256,
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

    def _required_output_tokens(self) -> int:
        configured = (
            self.token_budgets.reserved_output_tokens if self.token_budgets is not None else None
        )
        return (
            configured if configured is not None else self.execution.max_output_tokens_per_request
        )

    def _reserved_reasoning_tokens(self, required_output_tokens: int) -> int:
        if self.reasoning is None or self.reasoning.effort == "none":
            return 0
        if self.reasoning.max_tokens is not None:
            return self.reasoning.max_tokens
        return required_output_tokens

    def _route_token_intersection(
        self,
        *,
        model: str,
        provider_policy: OpenRouterProviderPolicy,
        requested_completion_tokens: int,
    ) -> EndpointRouteIntersection:
        registered_policy = self._endpoint_pricing.get(model)
        if registered_policy is None:
            if self.execution_evidence is not ExecutionEvidenceKind.MOCK:
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
        if workflow_prompt is not None:
            raw_workflow_bound = len(workflow_prompt.encode("utf-8"))
            if (
                workflow_byte_upper_bound_tokens is not None
                and workflow_byte_upper_bound_tokens != raw_workflow_bound
            ):
                raise OpenRouterRequestLimitError(
                    "context budget preview raw workflow bound does not match prompt"
                )
            effective_workflow_bound = len(_compact_json(workflow_prompt).encode("utf-8"))
        required_output_tokens = self._required_output_tokens()
        requested_completion_tokens = required_output_tokens + self._reserved_reasoning_tokens(
            required_output_tokens
        )
        utilization = Decimal(
            str(
                self.token_budgets.usable_input_fraction if self.token_budgets is not None else 0.70
            )
        )
        budgets: list[int] = []
        for model in canonical_models:
            qualification_binding = self._qualification_routing.get(model)
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
        return min(budgets)

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
        reserved_reasoning_tokens = self._reserved_reasoning_tokens(required_output_tokens)
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
        context_package: ContextPackage | None = None,
    ) -> tuple[RequestTokenPlan, ContextRequestEvidence | None]:
        if context_package is not None:
            from mmaudit.orchestration.context import (
                ContextBoundaryError,
                revalidate_context_package,
            )

            try:
                context_package = revalidate_context_package(context_package)
            except ContextBoundaryError:
                raise _OpenRouterContextPlanError(
                    "provider request cannot satisfy the bounded context plan"
                ) from None
        required_output_tokens = self._required_output_tokens()
        reserved_reasoning_tokens = self._reserved_reasoning_tokens(required_output_tokens)
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
                response = await self._bounded_request(
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
        self._ensure_no_credential_in_value(payload)
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
    ) -> httpx.Response:
        self._validate_transport_provenance()
        chunks: list[bytes] = []
        total = 0
        relative_path = path.lstrip("/")
        try:
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

    def _validate_transport_provenance(self) -> None:
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
            )
        ):
            raise OpenRouterPrivacyError("provider client callables changed after validation")
        if (
            self._client is not self._client_identity
            or getattr(self._client, "_transport", None) is not self._transport_identity
        ):
            raise OpenRouterPrivacyError("provider transport provenance changed after validation")
        if self.execution_evidence is ExecutionEvidenceKind.UNVERIFIED:
            raise OpenRouterPrivacyError(
                "network-capable injected provider clients are not permitted"
            )
        if self._owns_client and (
            self._client is not self._owned_client_identity
            or getattr(self._client, "_transport", None) is not self._owned_transport_identity
            or not _owned_httpx_callables_are_pristine(
                self._client,
                self._owned_transport_identity,
            )
        ):
            raise OpenRouterPrivacyError("owned provider callable provenance is invalid")

    def build_request(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
        response_model: type[BaseModel],
        schema_name: str,
        request_metadata: Mapping[str, str] | None = None,
        provider_policy: OpenRouterProviderPolicy | None = None,
        structured_output_mode: StructuredOutputMode | None = None,
        request_token_plan: RequestTokenPlan | None = None,
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
        request_plan = _structured_output_request_plan(
            mode=selected_mode,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            schema_name=schema_name,
            reasoning=self.reasoning,
        )
        if endpoint_policy is not None:
            _require_matching_request_parameter_profile(
                endpoint_policy,
                request_plan,
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
        body: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": request_plan.system_prompt},
                {"role": "user", "content": request_plan.user_prompt},
            ],
            "temperature": 0,
            "max_tokens": maximum_tokens,
            "stream": False,
            "provider": effective_provider_policy.as_request_payload(
                require_zdr=self.privacy.require_zdr,
                require_parameters=request_plan.require_parameters,
            ),
        }
        if request_plan.response_format is not None:
            body["response_format"] = request_plan.response_format
        if endpoint_policy is not None:
            provider = body["provider"]
            assert isinstance(provider, dict)
            provider["max_price"] = dict(endpoint_policy.routing_max_price)
        if request_plan.reasoning_payload is not None:
            body["reasoning"] = request_plan.reasoning_payload
        if request_metadata:
            body["metadata"] = {
                key: value
                for key, value in request_metadata.items()
                if _is_safe_metadata_pair(key, value)
            }
            if len(body["metadata"]) != len(request_metadata):
                raise OpenRouterRequestLimitError("request metadata is invalid")
        return body

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
        )
        if _is_concluded_unbound_completion(completion):
            raise OpenRouterUnboundIdentityError(completion)
        if _is_repaired_noncreditable_completion(completion):
            raise OpenRouterSchemaError(
                "syntax-repaired structured output is retained without review credit"
            )
        return completion.value

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
    ) -> StructuredCompletion[ResponseT]:
        """Call only the explicitly supplied models, in order."""

        if not models:
            raise OpenRouterModelError(f"no model configured for role {role}")
        if len(self._unbound_completions) >= _MAX_RETAINED_UNBOUND_COMPLETIONS:
            raise OpenRouterRequestLimitError(
                "unbound evidence retention is full; inspect and clear it before retrying"
            )
        if self.execution_evidence is ExecutionEvidenceKind.UNVERIFIED:
            raise OpenRouterPrivacyError(
                "network-capable injected provider clients are not permitted"
            )
        if self._requires_paid_controls and self.budget.atomic_ledger is None:
            raise OpenRouterCostControlError(
                "real provider completions require a durable atomic cost ledger"
            )
        if self._requires_paid_controls and not self.budget.require_endpoint_cost_bound:
            raise OpenRouterCostControlError(
                "real provider completions require endpoint-bound maximum cost proof"
            )
        if self._requires_paid_controls and not self.privacy.require_zdr:
            self._validate_non_zdr_privacy_authorization(models)
        if self._requires_paid_controls and not self.provider_policy.configured_endpoints:
            raise OpenRouterProviderPolicyError(
                "real provider completions require an explicit provider endpoint allowlist"
            )
        for model in models:
            _require_exact_model_id(model)
        if self._requires_paid_controls:
            unbound_models = [model for model in models if model not in self._endpoint_pricing]
            if unbound_models:
                raise OpenRouterCostControlError(
                    "real provider completion lacks validated endpoint pricing"
                )
        if self.execution_evidence is ExecutionEvidenceKind.REAL:
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
        if self.provider_policy.certification and len(models) != 1:
            raise OpenRouterModelError(
                "certification requires exactly one explicitly qualified model"
            )
        qualification_bindings: dict[str, OpenRouterQualificationRoutingEvidence | None] = {}
        checked_at = datetime.now(UTC)
        for model in models:
            binding = self._qualification_routing.get(model)
            if (
                self.provider_policy.certification
                and role not in _PREQUALIFICATION_PROVIDER_ROLES
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
                binding.require_current(
                    role=role,
                    model=model,
                    provider_endpoints=self.provider_policy.configured_endpoints,
                    now=checked_at,
                    endpoint_policy=self._endpoint_pricing.get(model),
                    model_identity=self._model_identities.get(model),
                    require_runtime_snapshots=(
                        self.execution_evidence is ExecutionEvidenceKind.REAL
                    ),
                )
            qualification_bindings[model] = binding
        last_error: OpenRouterError | None = None
        for index, model in enumerate(models):
            try:
                completion = await self._complete_one(
                    role=role,
                    model=model,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    context_package=context_package,
                    response_model=response_model,
                    schema_name=schema_name,
                    fallback_used=index > 0,
                    qualification_binding=qualification_bindings[model],
                )
            except (
                OpenRouterTransientError,
                OpenRouterModelError,
                OpenRouterSchemaError,
            ) as exc:
                last_error = exc
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
            if self.execution_evidence is ExecutionEvidenceKind.REAL:
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
            or self.execution_evidence is not ExecutionEvidenceKind.REAL
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
            or self.execution_evidence is not ExecutionEvidenceKind.REAL
            or not self._owns_client
            or not self._authentication_validated
            or not _openrouter_generation_verification_callables_are_pristine()
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
        role: str,
        model: str,
        system_prompt: str,
        user_prompt: str,
        context_package: ContextPackage | None = None,
        response_model: type[ResponseT],
        schema_name: str,
        fallback_used: bool,
        qualification_binding: OpenRouterQualificationRoutingEvidence | None,
    ) -> StructuredCompletion[ResponseT]:
        request_id = str(uuid.uuid4())
        required_output_tokens = self._required_output_tokens()
        requested_completion_tokens = required_output_tokens + self._reserved_reasoning_tokens(
            required_output_tokens
        )
        request_provider_policy = _canonical_provider_policy(self.provider_policy)
        structured_output_plan: _StructuredOutputRequestPlan | None = None
        try:
            request_provider_policy = (
                qualification_binding.request_provider_policy()
                if qualification_binding is not None and self.provider_policy.certification
                else self.provider_policy
            )
            request_provider_policy = _canonical_provider_policy(request_provider_policy)
            if self._requires_paid_controls:
                self._validate_paid_privacy_policy(
                    (model,),
                    request_provider_endpoints=request_provider_policy.configured_endpoints,
                )
            endpoint_policy = self._endpoint_pricing.get(model)
            structured_output_mode = (
                endpoint_policy.structured_output_mode
                if endpoint_policy is not None
                else StructuredOutputMode.NATIVE_JSON_SCHEMA
            )
            structured_output_plan = _structured_output_request_plan(
                mode=structured_output_mode,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                reasoning=self.reasoning,
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
            )
            raise
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
                context_package=context_package,
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
        prompt_hash = _structured_output_prompt_sha256_from_plan(structured_output_plan)
        user_prompt_hash = hashlib.sha256(user_prompt.encode()).hexdigest()
        schema = strict_json_schema(response_model)
        schema_hash = _canonical_sha256(schema)
        request_metadata = {
            "mmaudit_request_id": request_id,
            "mmaudit_role": role,
            "mmaudit_prompt_sha256": prompt_hash,
            "mmaudit_user_prompt_sha256": user_prompt_hash,
            "mmaudit_schema_sha256": schema_hash,
            "mmaudit_output_mode": structured_output_mode.value,
            "mmaudit_output_request_shape_sha256": (structured_output_plan.request_shape_sha256),
            "mmaudit_required_provider_parameters_sha256": _canonical_sha256(
                structured_output_plan.required_provider_parameters
            ),
            "mmaudit_token_plan_sha256": request_token_plan.plan_sha256,
        }
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
        try:
            body = self.build_request(
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                request_metadata=request_metadata,
                provider_policy=request_provider_policy,
                structured_output_mode=structured_output_mode,
                request_token_plan=request_token_plan,
            )
            self._ensure_request_size(body)
            request_body_hash = _canonical_sha256(body)
            request_material = json.dumps(
                body,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            endpoint_cost_bound = self._endpoint_request_cost_bound(
                model=model,
                request_material=request_material,
                request_token_plan=request_token_plan,
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
            self._store_debug(request_id, "prompt.json", body)
        attempts = 0
        usage_recorded = False
        accounted_cost_usd = 0.0
        active_reservation: Reservation | None = None
        attempt_reservations: list[Reservation] = []
        active_network_attempted = False
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
        raw_payload: dict[str, Any] | None = None
        response_headers: Mapping[str, str] = {}

        async def finalize_active(actual_cost: Decimal | None) -> None:
            nonlocal accounted_cost_usd, active_reservation
            if active_reservation is None:
                return
            reservation = active_reservation
            active_reservation = None
            try:
                accounted_cost_usd += await self.budget.reconcile(
                    reservation,
                    actual_cost,
                    actual_prompt_tokens=active_actual_prompt_tokens,
                    actual_completion_tokens=active_actual_completion_tokens,
                    actual_reasoning_tokens=active_actual_reasoning_tokens,
                )
            except Exception:
                accounted_cost_usd += (
                    reservation.estimated_cost_usd
                    if actual_cost is None
                    else max(0.0, float(actual_cost))
                )
                raise

        async def release_active() -> None:
            nonlocal active_reservation
            if active_reservation is None:
                return
            reservation = active_reservation
            active_reservation = None
            await self.budget.release(reservation)

        try:
            while True:
                next_attempt = attempts + 1
                reservation_id = (
                    request_id if next_attempt == 1 else f"{request_id}:attempt:{next_attempt}"
                )
                try:
                    active_reservation = await self.budget.reserve(
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
                    )
                except Exception as exc:
                    self._record_context_preflight(
                        request_id=(request_id if attempts == 0 else f"{reservation_id}:preflight"),
                        logical_request_id=request_id,
                        role=role,
                        model=model,
                        requested_completion_tokens=requested_completion_tokens,
                        request_plan=request_token_plan,
                        decision_source=ContextPreflightSource.BUDGET_MANAGER,
                        reason=(
                            self._budget_preflight_reason(request_token_plan)
                            if isinstance(exc, BudgetExhaustedError)
                            else ContextPreflightReason.CONTEXT_PLAN_INVALID
                        ),
                        error=exc,
                    )
                    raise
                active_network_attempted = False
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
                    if self._requires_paid_controls:
                        self._validate_paid_privacy_policy(
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
                    attempt_reservations.append(active_reservation)
                    attempts = next_attempt
                    active_network_attempted = True
                    response = await self._bounded_request(
                        "POST",
                        "/chat/completions",
                        json_body=body,
                        max_bytes=max(
                            1_000_000,
                            request_token_plan.requested_completion_tokens * 32,
                        ),
                    )
                except (httpx.TimeoutException, httpx.NetworkError):
                    await finalize_active(None)
                    if attempts >= self.execution.max_model_retries + 1:
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
                    self._ensure_no_credential_in_value(response_value)
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
                    if attempts >= self.execution.max_model_retries + 1:
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
            initial_usage = _validate_usage(payload.get("usage"))
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
                self._store_debug(request_id, "response.json", payload)
            content = envelope.content
            try:
                decoded_output = decode_structured_output(
                    content,
                    response_model,
                    max_repair_attempts=self.execution.max_json_repair_attempts,
                )
            except StructuredOutputDecodeError as output_error:
                raise OpenRouterStructuredOutputError(
                    failure_code=output_error.code,
                    repair_evidence=output_error.repair_evidence,
                ) from None
            parsed = decoded_output.value
            validated_response_hash = _canonical_sha256(parsed.model_dump(mode="json"))
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
            )
            usage_record = UsageRecord(
                request_id=request_id,
                role=role,
                execution_evidence=self.execution_evidence,
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
                    if active_network_attempted:
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
                    isinstance(terminal_error, OpenRouterResponseIdentityError)
                    and raw_payload is not None
                ):
                    try:
                        preserved_unbound_response = _validate_preservable_structured_response(
                            raw_payload,
                            response_model=response_model,
                        )
                    except OpenRouterSchemaError as preservation_error:
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
                ):
                    try:
                        hash_only_response = decode_structured_output(
                            raw_content,
                            response_model,
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
                    _optional_string(raw_payload.get("model")) if raw_payload is not None else None
                )
                actual_provider = (
                    _optional_string(raw_payload.get("provider"))
                    if raw_payload is not None
                    else None
                )
                failed_usage = UsageRecord(
                    request_id=request_id,
                    role=role,
                    execution_evidence=self.execution_evidence,
                    requested_model=model,
                    returned_model=returned_model,
                    provider=actual_provider,
                    model_family=model_family(model),
                    timestamp=started_at,
                    prompt_tokens=_nonnegative_int(initial_usage.get("prompt_tokens")),
                    completion_tokens=_nonnegative_int(initial_usage.get("completion_tokens")),
                    total_tokens=_nonnegative_int(initial_usage.get("total_tokens")),
                    reported_cost_usd=(float(initial_cost) if initial_cost is not None else None),
                    accounted_cost_usd=accounted_cost_usd,
                    routing=self._failure_routing_evidence(
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
                    ),
                    prompt_sha256=prompt_hash,
                    user_prompt_sha256=user_prompt_hash,
                    response_sha256=response_hash,
                    validated_response_sha256=validated_response_hash,
                    request_body_sha256=request_body_hash,
                    schema_sha256=schema_hash,
                    openrouter_generation_id=_response_generation_id(raw_payload, response_headers),
                    configured_provider_endpoints=list(
                        request_provider_policy.configured_endpoints
                    ),
                    actual_provider_endpoint=actual_provider,
                    started_at=started_at,
                    ended_at=ended_at,
                    latency_ms=latency_ms,
                    finish_reason=_optional_finish_reason(raw_payload),
                    reasoning_tokens=_reasoning_tokens(initial_usage),
                    cached_tokens=_cached_tokens(initial_usage),
                    retry_count=max(0, attempts - 1),
                    provider_error_classification=_provider_error_classification(terminal_error),
                    validation_status=_failure_validation_status(terminal_error),
                    fallback_used=fallback_used,
                    substitution_detected=(
                        returned_model is not None
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
    ) -> EndpointRequestCostBound | None:
        if not self.budget.require_endpoint_cost_bound:
            return None
        registered_policy = self._endpoint_pricing.get(model)
        if registered_policy is None:
            raise UnprovenCostBoundError("paid request lacks validated endpoint pricing")
        if request_token_plan.route_intersection.exact_model_ids != (model,):
            raise UnprovenCostBoundError("request token plan differs from the priced model")
        request_bytes = max(1, len(request_material.encode("utf-8")))
        prompt_pricing_units = max(
            request_bytes,
            request_token_plan.prompt_byte_upper_bound_tokens,
        )
        output_tokens = request_token_plan.requested_completion_tokens
        reasoning_tokens = request_token_plan.reserved_reasoning_tokens
        ceilings = {
            "completion": output_tokens,
            "image": 0,
            "input_cache_read": prompt_pricing_units,
            "input_cache_write": prompt_pricing_units,
            "internal_reasoning": reasoning_tokens,
            "prompt": prompt_pricing_units,
            "request": 1,
            "web_search": 0,
        }
        policy_prices: dict[str, str] = {}
        for field, price in registered_policy.routing_max_price:
            normalized = Decimal(str(price))
            if field in _PER_MILLION_ROUTER_PRICE_FIELDS:
                normalized /= Decimal(1_000_000)
            policy_prices[field] = format(normalized, "f")
        bounds: list[EndpointRequestCostBound] = []
        for registered in registered_policy.endpoints:
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
            bounded_pricing = {**dict(registered.pricing), **policy_prices}
            bounds.append(
                EndpointRequestCostBound.from_endpoint_pricing(
                    exact_model_id=model,
                    provider_endpoint=registered.provider_endpoint,
                    request_material=request_material,
                    pricing=bounded_pricing,
                    maximum_units={field: ceilings[field] for field in bounded_pricing},
                )
            )
        return max(
            bounds,
            key=lambda bound: (bound.maximum_cost_usd, bound.provider_endpoint),
        )

    @staticmethod
    def _token_plan_routing_evidence(
        *,
        request_token_plan: RequestTokenPlan,
        reservations: Sequence[Reservation],
        context_request_evidence: ContextRequestEvidence | None,
    ) -> dict[str, Any]:
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
        if context_request_evidence is not None:
            evidence["context_request_evidence"] = context_request_evidence.model_dump(mode="json")
            evidence["context_request_evidence_sha256"] = context_request_evidence.evidence_sha256
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
                endpoint_policy.snapshot_sha256 if endpoint_policy is not None else None
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
                        "execution_evidence": self.execution_evidence.value,
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
            )
        )
        if qualification_binding is not None:
            evidence.update(qualification_binding.routing_evidence())
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
    ) -> dict[str, Any]:
        router_metadata = payload.get("openrouter_metadata") if isinstance(payload, dict) else None
        finish_reason = _optional_finish_reason(payload)
        endpoint_policy = self._endpoint_pricing.get(requested_model)
        evidence: dict[str, Any] = {
            "generation_id": (_optional_string(payload.get("id")) if payload is not None else None),
            "generation_header_id": _header_value(response_headers, "x-generation-id"),
            "provider": (
                _optional_string(payload.get("provider")) if payload is not None else None
            ),
            "router_metadata_sha256": (
                _canonical_sha256(router_metadata) if isinstance(router_metadata, dict) else None
            ),
            "finish_reason": finish_reason,
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
                endpoint_policy.snapshot_sha256 if endpoint_policy is not None else None
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
        self._ensure_no_credential_in_value(value)
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
        self._ensure_no_credential_in_value(body)
        serialized = json.dumps(body, sort_keys=True, ensure_ascii=True)
        size = len(serialized.encode("utf-8"))
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


_TRUSTED_OPENROUTER_CLIENT_TYPE = OpenRouterClient
_TRUSTED_OPENROUTER_IDENTITY_BINDING_ISSUER = object()
_TRUSTED_RECONCILIATION_EXPECTATION = GenerationVerificationRequest.reconciliation_expectation
_TRUSTED_VALIDATE_AUTHENTICATION = OpenRouterClient.validate_authentication
_TRUSTED_GET_GENERATION_EVIDENCE = OpenRouterClient.get_generation_evidence
_TRUSTED_CREATE_GENERATION_VERIFICATION = OpenRouterClient.create_trusted_generation_verification
_TRUSTED_FETCH_GENERATION_ATTESTATIONS = (
    OpenRouterClient._fetch_generation_attestations_with_deadline
)
_TRUSTED_REQUEST_METADATA = OpenRouterClient._request_metadata
_TRUSTED_BOUNDED_REQUEST = OpenRouterClient._bounded_request
_TRUSTED_VALIDATE_TRANSPORT_PROVENANCE = OpenRouterClient._validate_transport_provenance


def _openrouter_generation_verification_callables_are_pristine() -> bool:
    return (
        (
            GenerationVerificationRequest.reconciliation_expectation
            is _TRUSTED_RECONCILIATION_EXPECTATION
        )
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
        and (
            OpenRouterClient._validate_transport_provenance
            is _TRUSTED_VALIDATE_TRANSPORT_PROVENANCE
        )
    )


def _uses_closed_httpx_mock_transport(client: httpx.AsyncClient | None) -> bool:
    """Recognize only httpx's exact in-memory test transport as mock execution."""

    if client is None:
        return False
    return type(getattr(client, "_transport", None)) is httpx.MockTransport


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
    except TypeError:
        return False
    return (
        "send" not in client_values
        and "request" not in client_values
        and "stream" not in client_values
        and "handle_async_request" not in transport_values
        and httpx.AsyncClient.send is _TRUSTED_ASYNC_CLIENT_SEND
        and httpx.AsyncClient.request is _TRUSTED_ASYNC_CLIENT_REQUEST
        and httpx.AsyncClient.stream is _TRUSTED_ASYNC_CLIENT_STREAM
        and (httpx.AsyncHTTPTransport.handle_async_request is _TRUSTED_ASYNC_HTTP_TRANSPORT_REQUEST)
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


def _routing_max_price(
    endpoints: tuple[_RegisteredEndpointPricing, ...],
) -> dict[str, float]:
    """Return provider-side price ceilings that cannot round below snapshot prices."""

    if not endpoints:
        raise OpenRouterCostControlError("endpoint pricing policy is empty")
    maxima: dict[str, Decimal] = {}
    for endpoint in endpoints:
        for field, raw_price in endpoint.pricing:
            if field in _UNENFORCEABLE_VARIABLE_PRICING_FIELDS:
                raise OpenRouterCostControlError(
                    "variable endpoint pricing component cannot be provider-capped"
                )
            if field not in _ROUTER_MAX_PRICE_FIELDS:
                if Decimal(raw_price) != 0:
                    raise OpenRouterCostControlError(
                        "nonzero endpoint pricing component cannot be provider-capped"
                    )
                continue
            price = Decimal(raw_price)
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
    if role.startswith("specialist:"):
        return role.split(":", 2)[1]
    if role.startswith("candidate_falsifier:"):
        return "falsifier"
    if role.startswith("whole_protocol_review:"):
        return "whole_protocol_review"
    return role


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
    if finish_reason != "stop":
        if finish_reason.casefold() in _TRUNCATED_FINISH_REASONS:
            raise OpenRouterTruncatedResponseError("model response was incomplete or truncated")
        raise OpenRouterSchemaError("model response did not finish normally")
    native_finish_reason = _optional_string(choice.get("native_finish_reason"))
    if native_finish_reason is not None:
        native_finish_reason = _required_safe_string(
            native_finish_reason,
            field="native finish reason",
            max_length=100,
        )
        if native_finish_reason.casefold() in _TRUNCATED_FINISH_REASONS:
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
        return decode_structured_output(content, response_model).value
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
    if finish_reason != "stop":
        if finish_reason.casefold() in _TRUNCATED_FINISH_REASONS:
            raise OpenRouterTruncatedResponseError("model response was incomplete or truncated")
        raise OpenRouterSchemaError("model response did not finish normally")
    native_finish_reason = _optional_string(choice.get("native_finish_reason"))
    if native_finish_reason is not None:
        native_finish_reason = _required_safe_string(
            native_finish_reason,
            field="native finish reason",
            max_length=100,
        )
        if native_finish_reason.casefold() in _TRUNCATED_FINISH_REASONS:
            raise OpenRouterTruncatedResponseError(
                "model response native finish reason indicates truncation"
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


def _validate_usage(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OpenRouterSchemaError("model response omitted usage accounting")
    fields: dict[str, int] = {}
    for field in ("prompt_tokens", "completion_tokens", "total_tokens"):
        item = value.get(field)
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            raise OpenRouterSchemaError("model response has invalid usage accounting")
        fields[field] = item
    if fields["total_tokens"] != fields["prompt_tokens"] + fields["completion_tokens"]:
        raise OpenRouterSchemaError("model response usage totals are inconsistent")
    if _optional_cost_decimal(value.get("cost")) is None:
        raise OpenRouterSchemaError("model response has invalid cost accounting")
    for detail_field, token_field in (
        ("completion_tokens_details", "reasoning_tokens"),
        ("prompt_tokens_details", "cached_tokens"),
    ):
        details = value.get(detail_field)
        if details is None:
            continue
        if not isinstance(details, dict):
            raise OpenRouterSchemaError("model response token details are invalid")
        token_count = details.get(token_field)
        if token_count is not None and (
            not isinstance(token_count, int) or isinstance(token_count, bool) or token_count < 0
        ):
            raise OpenRouterSchemaError("model response token details are invalid")
    reasoning_tokens = _reasoning_tokens(value)
    cached_tokens = _cached_tokens(value)
    if reasoning_tokens > fields["completion_tokens"] or cached_tokens > fields["prompt_tokens"]:
        raise OpenRouterSchemaError("model response token details are inconsistent")
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
    if normalized.is_finite() and normalized >= 0:
        return normalized
    return None


def _nonnegative_int(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return 0


def _reasoning_tokens(usage: Mapping[str, Any]) -> int:
    return _observed_reasoning_tokens(usage) or 0


def _observed_reasoning_tokens(usage: Mapping[str, Any]) -> int | None:
    direct = usage.get("reasoning_tokens")
    if isinstance(direct, int) and not isinstance(direct, bool) and direct >= 0:
        return direct
    details = usage.get("completion_tokens_details")
    if isinstance(details, dict):
        nested = details.get("reasoning_tokens")
        if isinstance(nested, int) and not isinstance(nested, bool) and nested >= 0:
            return nested
    return None


def _cached_tokens(usage: Mapping[str, Any]) -> int:
    direct = usage.get("cached_tokens")
    if isinstance(direct, int) and not isinstance(direct, bool) and direct >= 0:
        return direct
    details = usage.get("prompt_tokens_details")
    if isinstance(details, dict):
        nested = details.get("cached_tokens")
        if isinstance(nested, int) and not isinstance(nested, bool) and nested >= 0:
            return nested
    return 0


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
