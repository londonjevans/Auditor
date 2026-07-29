"""Typed, non-secret OpenRouter model and endpoint identity evidence.

The types in this module do not perform network access and do not grant model-review
credit. They seal already validated metadata and classify a completed request only
when its model, endpoint, and freshly retrieved generation evidence agree.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models.identifiers import (
    EXACT_MODEL_ID_PATTERN,
    require_exact_openrouter_model_id,
)
from mmaudit.models.output_modes import (
    REASONING_REQUEST_PARAMETER,
    StructuredOutputMode,
    mutually_supported_output_modes,
    output_mode_request_parameters,
    reasoning_capability_parameters,
    structured_output_parameters,
    supported_output_modes,
    supports_provider_structured_output,
    supports_reasoning_request,
)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SAFE_ENDPOINT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"
_SAFE_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$"
_SAFE_PARAMETER_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MAX_ALIASES = 256
_MAX_PARAMETERS = 256
_MAX_PRICING_FIELDS = 64
_BASE_REQUEST_PARAMETERS = frozenset({"max_tokens", "temperature"})


class OpenRouterIdentityStrength(StrEnum):
    """Strength of a completed model and provider identity observation.

    ``CANONICAL_MODEL_AND_ENDPOINT_BOUND`` is a policy-constrained OpenRouter
    binding: exact ``provider.only`` routing, no fallback, router observations,
    and generation metadata agree. OpenRouter does not expose a documented
    preflight-tag to post-call endpoint-ID join, so this is not a cryptographic
    provider-deployment attestation.
    """

    IMMUTABLE_VERSION_BOUND = "IMMUTABLE_VERSION_BOUND"
    CANONICAL_MODEL_AND_ENDPOINT_BOUND = "CANONICAL_MODEL_AND_ENDPOINT_BOUND"
    UNBOUND = "UNBOUND"


class OpenRouterIdentityDiagnosticCode(StrEnum):
    """Bounded, non-secret reasons why a valid response received no identity credit."""

    ENDPOINT_VARIANT_MISMATCH = "ENDPOINT_VARIANT_MISMATCH"
    GENERATION_EXECUTION_EVIDENCE_MISMATCH = "GENERATION_EXECUTION_EVIDENCE_MISMATCH"
    GENERATION_ID_MISMATCH = "GENERATION_ID_MISMATCH"
    GENERATION_EVIDENCE_UNTRUSTED = "GENERATION_EVIDENCE_UNTRUSTED"
    GENERATION_METADATA_AUTHENTICATION_FAILED = "GENERATION_METADATA_AUTHENTICATION_FAILED"
    GENERATION_METADATA_INTEGRITY_REJECTED = "GENERATION_METADATA_INTEGRITY_REJECTED"
    GENERATION_METADATA_INVALID = "GENERATION_METADATA_INVALID"
    GENERATION_METADATA_MISSING = "GENERATION_METADATA_MISSING"
    GENERATION_METADATA_NOT_READY = "GENERATION_METADATA_NOT_READY"
    GENERATION_METADATA_PROVIDER_UNAVAILABLE = "GENERATION_METADATA_PROVIDER_UNAVAILABLE"
    GENERATION_METADATA_RATE_LIMITED = "GENERATION_METADATA_RATE_LIMITED"
    GENERATION_METADATA_RETRIEVAL_FAILED = "GENERATION_METADATA_RETRIEVAL_FAILED"
    GENERATION_METADATA_TIMEOUT = "GENERATION_METADATA_TIMEOUT"
    GENERATION_MODEL_MISMATCH = "GENERATION_MODEL_MISMATCH"
    GENERATION_PROVIDER_MISMATCH = "GENERATION_PROVIDER_MISMATCH"
    IDENTITY_SNAPSHOT_EXPIRED = "IDENTITY_SNAPSHOT_EXPIRED"
    IMMUTABLE_VERSION_UNPROVEN = "IMMUTABLE_VERSION_UNPROVEN"
    MODEL_ALIAS_UNRECOGNIZED = "MODEL_ALIAS_UNRECOGNIZED"
    MODEL_CANONICAL_MISMATCH = "MODEL_CANONICAL_MISMATCH"
    PROVIDER_MISMATCH = "PROVIDER_MISMATCH"
    UNAPPROVED_FALLBACK = "UNAPPROVED_FALLBACK"


class OpenRouterIdentityPricingEntry(BaseModel):
    """One canonical non-negative price from a frozen endpoint snapshot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    unit: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    usd_per_unit: str

    @field_validator("usd_per_unit")
    @classmethod
    def price_is_canonical(cls, value: str) -> str:
        if _canonical_nonnegative_decimal(value) != value:
            raise ValueError("identity pricing must use a canonical non-negative decimal")
        return value


class OpenRouterIdentityEndpointCapabilities(BaseModel):
    """Allowlisted endpoint capabilities relevant to an exact request route."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operational: Literal[True]
    context_tokens: int = Field(gt=0, le=2**31 - 1)
    output_tokens: int = Field(gt=0, le=2**31 - 1)
    supported_parameters: tuple[str, ...] = Field(
        min_length=1,
        max_length=_MAX_PARAMETERS,
    )
    required_parameters: tuple[str, ...] = Field(
        min_length=1,
        max_length=_MAX_PARAMETERS,
    )
    structured_output_parameters: tuple[str, ...] = Field(max_length=8)
    supported_output_modes: tuple[StructuredOutputMode, ...] = Field(
        min_length=1,
        max_length=3,
    )
    structured_output_mode: StructuredOutputMode
    output_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    reasoning_parameters: tuple[str, ...] = Field(max_length=8)
    structured_output_supported: bool
    reasoning_supported: bool
    zdr_eligible: bool
    data_collection_deny_eligible: bool
    data_collection_deny_request_policy_enforced: bool
    data_collection_deny_evidence_source: Literal[
        "ZDR_ENDPOINT_SNAPSHOT",
        "CONSENT_BOUND_ROUTER_REQUEST_POLICY",
        "UNVERIFIED",
    ]
    data_collection_deny_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    data_collection_deny_evidence_expires_at: datetime | None = None

    @field_validator(
        "supported_parameters",
        "required_parameters",
        "structured_output_parameters",
        "reasoning_parameters",
    )
    @classmethod
    def parameters_are_safe_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            _SAFE_PARAMETER_PATTERN.fullmatch(item) is None for item in value
        ):
            raise ValueError("endpoint parameters must be safe, sorted, and unique")
        return value

    @model_validator(mode="after")
    def capabilities_are_coherent(self) -> Self:
        supported = set(self.supported_parameters)
        if not set(self.required_parameters).issubset(supported):
            raise ValueError("required endpoint parameters are not supported")
        if not set(self.structured_output_parameters).issubset(supported):
            raise ValueError("structured-output parameters are not supported")
        if not set(self.reasoning_parameters).issubset(supported):
            raise ValueError("reasoning parameters are not supported")
        expected_structured = structured_output_parameters(supported)
        if self.structured_output_parameters != expected_structured:
            raise ValueError("structured-output parameters are inconsistent")
        expected_modes = supported_output_modes(supported)
        if self.supported_output_modes != expected_modes:
            raise ValueError("supported output modes are inconsistent")
        if self.structured_output_mode not in self.supported_output_modes:
            raise ValueError("negotiated output mode is not supported by the endpoint")
        required_output_parameters = set(
            output_mode_request_parameters(self.structured_output_mode)
        )
        if not required_output_parameters.issubset(self.required_parameters):
            raise ValueError("negotiated output mode is absent from required request parameters")
        if (
            self.structured_output_mode is StructuredOutputMode.VALIDATED_TEXT_JSON
            and "response_format" in self.required_parameters
        ):
            raise ValueError("validated-text output cannot require response_format")
        if self.structured_output_supported is not supports_provider_structured_output(
            self.supported_parameters
        ):
            raise ValueError("structured-output capability status is inconsistent")
        if self.reasoning_supported is not supports_reasoning_request(self.reasoning_parameters):
            raise ValueError("reasoning capability status is inconsistent")
        if REASONING_REQUEST_PARAMETER in self.required_parameters and not self.reasoning_supported:
            raise ValueError("required reasoning request lacks exact capability support")
        if self.output_tokens > self.context_tokens:
            raise ValueError("endpoint output capacity exceeds its context capacity")
        if self.data_collection_deny_evidence_source == "ZDR_ENDPOINT_SNAPSHOT":
            if (
                self.data_collection_deny_eligible is not True
                or self.data_collection_deny_request_policy_enforced is not True
                or self.data_collection_deny_evidence_sha256 is None
                or self.data_collection_deny_evidence_expires_at is not None
            ):
                raise ValueError("identity ZDR privacy evidence is incomplete")
        elif self.data_collection_deny_evidence_source == "CONSENT_BOUND_ROUTER_REQUEST_POLICY":
            expiry = self.data_collection_deny_evidence_expires_at
            if (
                self.data_collection_deny_eligible is not False
                or self.data_collection_deny_request_policy_enforced is not True
                or self.data_collection_deny_evidence_sha256 is None
                or expiry is None
                or expiry.tzinfo is None
                or expiry.utcoffset() != timedelta(0)
                or expiry.microsecond != 0
            ):
                raise ValueError("identity consent-bound request-policy evidence is incomplete")
        elif (
            self.data_collection_deny_eligible is not False
            or self.data_collection_deny_request_policy_enforced is not False
            or self.data_collection_deny_evidence_sha256 is not None
            or self.data_collection_deny_evidence_expires_at is not None
        ):
            raise ValueError("unverified identity privacy evidence cannot receive credit")
        return self


class OpenRouterIdentityProviderPolicy(BaseModel):
    """Self-hashed provider-routing policy frozen before a request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    mode: Literal["only", "order"]
    configured_endpoints: tuple[str, ...] = Field(min_length=1, max_length=100)
    allow_fallbacks: bool
    require_parameters: bool
    data_collection: Literal["deny"]
    zdr_required: bool
    policy_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("configured_endpoints")
    @classmethod
    def endpoints_are_safe_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(
            re.fullmatch(_SAFE_ENDPOINT_PATTERN, endpoint) is None for endpoint in value
        ):
            raise ValueError("provider endpoints must be safe and unique")
        return value

    @model_validator(mode="after")
    def policy_is_self_hashed(self) -> Self:
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"policy_sha256"}))
        if self.policy_sha256 != expected:
            raise ValueError("provider identity policy hash is inconsistent")
        return self


class OpenRouterModelEndpointIdentitySnapshot(BaseModel):
    """Frozen metadata that resolves aliases to one canonical model and endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    requested_slug: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    canonical_slug: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    frozen_aliases: tuple[str, ...] = Field(min_length=1, max_length=_MAX_ALIASES)
    model_author: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")
    model_context_tokens: int = Field(gt=0, le=2**31 - 1)
    model_output_tokens: int = Field(gt=0, le=2**31 - 1)
    model_supported_parameters: tuple[str, ...] = Field(
        min_length=1,
        max_length=_MAX_PARAMETERS,
    )
    approved_provider_endpoint: str = Field(pattern=_SAFE_ENDPOINT_PATTERN)
    endpoint_tag: str | None = Field(default=None, pattern=_SAFE_ENDPOINT_PATTERN)
    endpoint_slug: str | None = Field(default=None, pattern=_SAFE_ENDPOINT_PATTERN)
    provider_name: str = Field(min_length=1, max_length=128)
    endpoint_binding_method: Literal["policy_constrained_openrouter"]
    endpoint_identifier_join_available: Literal[False]
    provider_policy: OpenRouterIdentityProviderPolicy
    endpoint_capabilities: OpenRouterIdentityEndpointCapabilities
    pricing: tuple[OpenRouterIdentityPricingEntry, ...] = Field(
        min_length=2,
        max_length=_MAX_PRICING_FIELDS,
    )
    canonical_slug_mutable: bool
    immutable_provider_version: str | None = Field(
        default=None,
        pattern=_SAFE_IDENTIFIER_PATTERN,
    )
    immutable_provider_version_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    retrieved_at: datetime
    expires_at: datetime | None = None
    catalog_identity_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    catalog_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    model_metadata_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_provenance_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    endpoint_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    pricing_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("requested_slug", "canonical_slug")
    @classmethod
    def primary_slugs_are_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value, label="identity model slug")

    @field_validator("frozen_aliases")
    @classmethod
    def aliases_are_exact_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for alias in value:
            require_exact_openrouter_model_id(alias, label="frozen model alias")
        if value != tuple(sorted(set(value))):
            raise ValueError("frozen model aliases must be sorted and unique")
        return value

    @field_validator("model_supported_parameters")
    @classmethod
    def model_parameters_are_safe_sorted_unique(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            _SAFE_PARAMETER_PATTERN.fullmatch(item) is None for item in value
        ):
            raise ValueError("model parameters must be safe, sorted, and unique")
        return value

    @field_validator("provider_name")
    @classmethod
    def provider_name_is_safe(cls, value: str) -> str:
        if value != value.strip() or any(not character.isprintable() for character in value):
            raise ValueError("identity provider name must be canonical printable text")
        return value

    @field_validator("retrieved_at")
    @classmethod
    def retrieval_time_is_utc(cls, value: datetime) -> datetime:
        return _validate_utc_second(value, label="identity retrieval time")

    @field_validator("expires_at")
    @classmethod
    def expiry_is_utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _validate_utc_second(value, label="identity expiry time")

    @model_validator(mode="after")
    def snapshot_is_coherent_and_self_hashed(self) -> Self:
        if self.model_author != self.canonical_slug.split("/", 1)[0]:
            raise ValueError("identity author differs from the canonical model author")
        if self.model_author != self.requested_slug.split("/", 1)[0]:
            raise ValueError("requested model author differs from the canonical model author")
        catalog_bound_aliases = tuple(sorted({self.requested_slug, self.canonical_slug}))
        if self.frozen_aliases != catalog_bound_aliases:
            raise ValueError(
                "frozen aliases must include requested and canonical slugs and no unbound aliases"
            )
        if self.model_output_tokens > self.model_context_tokens:
            raise ValueError("model output capacity exceeds its context capacity")
        if self.endpoint_capabilities.context_tokens > self.model_context_tokens:
            raise ValueError("endpoint context capacity exceeds model metadata")
        if self.endpoint_capabilities.output_tokens > self.model_output_tokens:
            raise ValueError("endpoint output capacity exceeds model metadata")
        common_parameters = set(self.model_supported_parameters).intersection(
            self.endpoint_capabilities.supported_parameters
        )
        if not set(self.endpoint_capabilities.required_parameters).issubset(common_parameters):
            raise ValueError("required request parameters are not model/endpoint common")
        expected_reasoning = reasoning_capability_parameters(common_parameters)
        if self.endpoint_capabilities.reasoning_parameters != expected_reasoning:
            raise ValueError("reasoning capability inventory is not model/endpoint common")
        compatible_modes = mutually_supported_output_modes(
            (
                self.model_supported_parameters,
                self.endpoint_capabilities.supported_parameters,
            )
        )
        if self.endpoint_capabilities.structured_output_mode is not compatible_modes[0]:
            raise ValueError("negotiated output mode is not model/endpoint compatible")
        provider_specific_required = (
            set(self.endpoint_capabilities.required_parameters) - _BASE_REQUEST_PARAMETERS
        )
        if self.provider_policy.require_parameters is not bool(provider_specific_required):
            raise ValueError("provider parameter policy differs from the exact request shape")
        endpoint_identities = {
            item for item in (self.endpoint_tag, self.endpoint_slug) if item is not None
        }
        if not endpoint_identities:
            raise ValueError("identity snapshot requires an endpoint tag or slug")
        if self.approved_provider_endpoint not in endpoint_identities:
            raise ValueError("approved endpoint differs from its exact tag or slug")
        if self.approved_provider_endpoint not in self.provider_policy.configured_endpoints:
            raise ValueError("approved endpoint is outside the frozen provider policy")
        price_units = tuple(entry.unit for entry in self.pricing)
        if price_units != tuple(sorted(set(price_units))):
            raise ValueError("identity pricing entries must be sorted and unique")
        if not {"prompt", "completion"}.issubset(price_units):
            raise ValueError("identity pricing omits prompt or completion")
        has_version = self.immutable_provider_version is not None
        has_version_evidence = self.immutable_provider_version_evidence_sha256 is not None
        if has_version is not has_version_evidence:
            raise ValueError("immutable provider version and evidence hash must appear together")
        if not self.canonical_slug_mutable and not has_version:
            raise ValueError(
                "an immutable canonical slug requires explicit provider-version evidence"
            )
        alias_resolution_is_mutable = self.requested_slug != self.canonical_slug
        if (
            self.canonical_slug_mutable or alias_resolution_is_mutable or not has_version
        ) and self.expires_at is None:
            raise ValueError("mutable canonical identity evidence requires an expiry")
        if self.expires_at is not None and self.expires_at <= self.retrieved_at:
            raise ValueError("identity expiry must follow metadata retrieval")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"snapshot_sha256"}))
        if self.snapshot_sha256 != expected:
            raise ValueError("model and endpoint identity snapshot hash is inconsistent")
        return self

    def resolves_to_canonical(self, slug: str) -> bool:
        """Return whether a frozen alias resolves to this canonical model."""

        return slug in self.frozen_aliases

    @property
    def has_immutable_provider_version(self) -> bool:
        """Return whether explicit provider-version evidence is present."""

        return (
            self.immutable_provider_version is not None
            and self.immutable_provider_version_evidence_sha256 is not None
        )


class OpenRouterRequestIdentityEvidence(BaseModel):
    """Non-secret response metadata retained even when identity remains unbound."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    internal_request_id: str = Field(pattern=_SAFE_IDENTIFIER_PATTERN)
    execution_evidence: Literal["real", "mock"]
    requested_slug: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    returned_slug: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    selected_model_slug: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    actual_provider_endpoint: str = Field(pattern=_SAFE_ENDPOINT_PATTERN)
    actual_provider_name: str = Field(min_length=1, max_length=128)
    openrouter_generation_id: str = Field(pattern=_SAFE_IDENTIFIER_PATTERN)
    request_body_sha256: str = Field(pattern=_SHA256_PATTERN)
    response_sha256: str = Field(pattern=_SHA256_PATTERN)
    validated_response_sha256: str = Field(pattern=_SHA256_PATTERN)
    started_at: datetime
    completed_at: datetime
    fallback_used: bool = Field(
        description=(
            "Whether OpenRouter used a provider/router fallback; an independently frozen "
            "host-selected model fallback is recorded separately."
        )
    )

    @field_validator("requested_slug", "returned_slug", "selected_model_slug")
    @classmethod
    def request_slugs_are_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value, label="request identity model slug")

    @field_validator("actual_provider_name")
    @classmethod
    def actual_provider_name_is_safe(cls, value: str) -> str:
        if value != value.strip() or any(not character.isprintable() for character in value):
            raise ValueError("request provider name must be canonical printable text")
        return value

    @field_validator("started_at", "completed_at")
    @classmethod
    def request_times_are_utc(cls, value: datetime) -> datetime:
        return _validate_utc_second(value, label="identity request time")

    @model_validator(mode="after")
    def request_times_are_ordered(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("identity request completion precedes its start")
        return self


class OpenRouterGenerationIdentityEvidence(BaseModel):
    """Fresh content-free generation metadata used only for a bound result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    generation_id: str = Field(pattern=_SAFE_IDENTIFIER_PATTERN)
    execution_evidence: Literal["real", "mock"]
    generation_model_slug: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    provider_name: str = Field(min_length=1, max_length=128)
    provider_version_id: str | None = Field(default=None, pattern=_SAFE_IDENTIFIER_PATTERN)
    provider_request_id: str | None = Field(default=None, pattern=_SAFE_IDENTIFIER_PATTERN)
    retrieved_at: datetime
    generation_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("generation_model_slug")
    @classmethod
    def generation_model_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(
            value,
            label="generation identity model slug",
        )

    @field_validator("provider_name")
    @classmethod
    def generation_provider_name_is_safe(cls, value: str) -> str:
        if value != value.strip() or any(not character.isprintable() for character in value):
            raise ValueError("generation provider name must be canonical printable text")
        return value

    @field_validator("retrieved_at")
    @classmethod
    def generation_retrieval_time_is_utc(cls, value: datetime) -> datetime:
        return _validate_utc_second(value, label="generation retrieval time")


class OpenRouterIdentityBindingResult(BaseModel):
    """Self-hashed identity conclusion for one structured provider response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    strength: OpenRouterIdentityStrength
    snapshot: OpenRouterModelEndpointIdentitySnapshot
    request: OpenRouterRequestIdentityEvidence
    generation: OpenRouterGenerationIdentityEvidence | None = None
    diagnostic_codes: tuple[OpenRouterIdentityDiagnosticCode, ...] = Field(max_length=32)
    evaluated_at: datetime
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("diagnostic_codes")
    @classmethod
    def diagnostics_are_sorted_unique(
        cls,
        value: tuple[OpenRouterIdentityDiagnosticCode, ...],
    ) -> tuple[OpenRouterIdentityDiagnosticCode, ...]:
        labels = tuple(item.value for item in value)
        if labels != tuple(sorted(set(labels))):
            raise ValueError("identity diagnostic codes must be sorted and unique")
        return value

    @field_validator("evaluated_at")
    @classmethod
    def evaluation_time_is_utc(cls, value: datetime) -> datetime:
        return _validate_utc_second(value, label="identity evaluation time")

    @model_validator(mode="after")
    def binding_is_coherent_and_self_hashed(self) -> Self:
        if self.request.requested_slug != self.snapshot.requested_slug:
            raise ValueError("identity result uses a snapshot for a different request")
        if self.evaluated_at < self.request.completed_at:
            raise ValueError("identity evaluation precedes request completion")
        if self.strength is OpenRouterIdentityStrength.UNBOUND:
            if self.generation is not None:
                raise ValueError("unbound identity cannot contain generation binding evidence")
            if not self.diagnostic_codes:
                raise ValueError("unbound identity requires a non-secret diagnostic code")
        else:
            self._validate_bound_identity()
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"binding_sha256"}))
        if self.binding_sha256 != expected:
            raise ValueError("OpenRouter identity binding hash is inconsistent")
        return self

    def _validate_bound_identity(self) -> None:
        if self.generation is None:
            raise ValueError("bound identity requires fresh generation evidence")
        if self.diagnostic_codes:
            raise ValueError("bound identity cannot contain failure diagnostics")
        if self.snapshot.retrieved_at > self.request.started_at:
            raise ValueError("identity snapshot was not frozen before the request")
        if self.snapshot.expires_at is not None and self.snapshot.expires_at <= self.evaluated_at:
            raise ValueError("expired identity snapshot cannot support a bound result")
        if self.generation.retrieved_at < self.request.completed_at:
            raise ValueError("generation evidence was not retrieved after completion")
        if self.generation.execution_evidence != self.request.execution_evidence:
            raise ValueError("generation and request execution evidence differ")
        if self.evaluated_at < self.generation.retrieved_at:
            raise ValueError("identity evaluation precedes generation retrieval")
        for observed in (
            self.request.returned_slug,
            self.request.selected_model_slug,
            self.generation.generation_model_slug,
        ):
            if not self.snapshot.resolves_to_canonical(observed):
                raise ValueError("model observation does not resolve to the frozen canonical model")
        if self.request.actual_provider_endpoint != self.snapshot.approved_provider_endpoint:
            raise ValueError("request used a different provider endpoint variant")
        if (
            self.request.actual_provider_name != self.snapshot.provider_name
            or self.generation.provider_name != self.snapshot.provider_name
        ):
            raise ValueError("provider observation differs from the frozen endpoint")
        if self.request.openrouter_generation_id != self.generation.generation_id:
            raise ValueError("generation metadata differs from the response generation ID")
        if self.request.fallback_used:
            raise ValueError("fallback execution cannot support exact endpoint identity")
        expected_version = self.snapshot.immutable_provider_version
        observed_version = self.generation.provider_version_id
        if (
            expected_version is not None
            and observed_version is not None
            and expected_version != observed_version
        ):
            raise ValueError("generation used a different immutable provider version")
        immutable_match = (
            self.snapshot.has_immutable_provider_version and observed_version == expected_version
        )
        if (
            self.strength is OpenRouterIdentityStrength.IMMUTABLE_VERSION_BOUND
            and not immutable_match
        ):
            raise ValueError(
                "immutable identity requires explicit matching provider-version evidence"
            )
        if (
            self.strength is OpenRouterIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND
            and immutable_match
        ):
            raise ValueError("identity strength understates an immutable provider-version binding")


def seal_openrouter_identity_provider_policy(
    *,
    mode: Literal["only", "order"],
    configured_endpoints: tuple[str, ...],
    allow_fallbacks: bool,
    zdr_required: bool,
    require_parameters: bool = True,
) -> OpenRouterIdentityProviderPolicy:
    """Seal a strict OpenRouter provider policy without credentials."""

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "mode": mode,
        "configured_endpoints": configured_endpoints,
        "allow_fallbacks": allow_fallbacks,
        "require_parameters": require_parameters,
        "data_collection": "deny",
        "zdr_required": zdr_required,
    }
    return OpenRouterIdentityProviderPolicy.model_validate(
        {
            **payload,
            "policy_sha256": _canonical_sha256(payload),
        }
    )


def seal_openrouter_model_endpoint_identity_snapshot(
    *,
    requested_slug: str,
    canonical_slug: str,
    frozen_aliases: tuple[str, ...],
    model_author: str,
    model_context_tokens: int,
    model_output_tokens: int,
    model_supported_parameters: tuple[str, ...],
    approved_provider_endpoint: str,
    endpoint_tag: str | None,
    endpoint_slug: str | None,
    provider_name: str,
    provider_policy: OpenRouterIdentityProviderPolicy,
    endpoint_capabilities: OpenRouterIdentityEndpointCapabilities,
    pricing: tuple[OpenRouterIdentityPricingEntry, ...],
    canonical_slug_mutable: bool,
    immutable_provider_version: str | None,
    immutable_provider_version_evidence_sha256: str | None,
    retrieved_at: datetime,
    expires_at: datetime | None,
    catalog_identity_binding_sha256: str,
    catalog_snapshot_sha256: str,
    model_metadata_snapshot_sha256: str,
    discovery_provenance_sha256: str,
    discovery_evidence_sha256: str,
    endpoint_snapshot_sha256: str,
    pricing_snapshot_sha256: str,
) -> OpenRouterModelEndpointIdentitySnapshot:
    """Seal one frozen alias, model, endpoint, capability, and pricing snapshot."""

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "requested_slug": requested_slug,
        "canonical_slug": canonical_slug,
        "frozen_aliases": frozen_aliases,
        "model_author": model_author,
        "model_context_tokens": model_context_tokens,
        "model_output_tokens": model_output_tokens,
        "model_supported_parameters": model_supported_parameters,
        "approved_provider_endpoint": approved_provider_endpoint,
        "endpoint_tag": endpoint_tag,
        "endpoint_slug": endpoint_slug,
        "provider_name": provider_name,
        "endpoint_binding_method": "policy_constrained_openrouter",
        "endpoint_identifier_join_available": False,
        "provider_policy": provider_policy,
        "endpoint_capabilities": endpoint_capabilities,
        "pricing": pricing,
        "canonical_slug_mutable": canonical_slug_mutable,
        "immutable_provider_version": immutable_provider_version,
        "immutable_provider_version_evidence_sha256": (immutable_provider_version_evidence_sha256),
        "retrieved_at": retrieved_at,
        "expires_at": expires_at,
        "catalog_identity_binding_sha256": catalog_identity_binding_sha256,
        "catalog_snapshot_sha256": catalog_snapshot_sha256,
        "model_metadata_snapshot_sha256": model_metadata_snapshot_sha256,
        "discovery_provenance_sha256": discovery_provenance_sha256,
        "discovery_evidence_sha256": discovery_evidence_sha256,
        "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
        "pricing_snapshot_sha256": pricing_snapshot_sha256,
    }
    return OpenRouterModelEndpointIdentitySnapshot.model_validate(
        {
            **payload,
            "snapshot_sha256": _canonical_sha256(payload),
        }
    )


def seal_bound_openrouter_identity(
    *,
    snapshot: OpenRouterModelEndpointIdentitySnapshot,
    request: OpenRouterRequestIdentityEvidence,
    generation: OpenRouterGenerationIdentityEvidence,
    evaluated_at: datetime,
) -> OpenRouterIdentityBindingResult:
    """Seal the strongest defensible identity result for one completed request."""

    immutable_match = (
        snapshot.has_immutable_provider_version
        and generation.provider_version_id == snapshot.immutable_provider_version
    )
    strength = (
        OpenRouterIdentityStrength.IMMUTABLE_VERSION_BOUND
        if immutable_match
        else OpenRouterIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND
    )
    return _seal_identity_result(
        strength=strength,
        snapshot=snapshot,
        request=request,
        generation=generation,
        diagnostic_codes=(),
        evaluated_at=evaluated_at,
    )


def seal_unbound_openrouter_identity(
    *,
    snapshot: OpenRouterModelEndpointIdentitySnapshot,
    request: OpenRouterRequestIdentityEvidence,
    diagnostic_codes: tuple[OpenRouterIdentityDiagnosticCode, ...],
    evaluated_at: datetime,
) -> OpenRouterIdentityBindingResult:
    """Seal a valid response as unbound without attaching generation evidence."""

    return _seal_identity_result(
        strength=OpenRouterIdentityStrength.UNBOUND,
        snapshot=snapshot,
        request=request,
        generation=None,
        diagnostic_codes=diagnostic_codes,
        evaluated_at=evaluated_at,
    )


def _seal_identity_result(
    *,
    strength: OpenRouterIdentityStrength,
    snapshot: OpenRouterModelEndpointIdentitySnapshot,
    request: OpenRouterRequestIdentityEvidence,
    generation: OpenRouterGenerationIdentityEvidence | None,
    diagnostic_codes: tuple[OpenRouterIdentityDiagnosticCode, ...],
    evaluated_at: datetime,
) -> OpenRouterIdentityBindingResult:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "strength": strength,
        "snapshot": snapshot,
        "request": request,
        "generation": generation,
        "diagnostic_codes": diagnostic_codes,
        "evaluated_at": evaluated_at,
    }
    return OpenRouterIdentityBindingResult.model_validate(
        {
            **payload,
            "binding_sha256": _canonical_sha256(payload),
        }
    )


def _validate_utc_second(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond != 0:
        raise ValueError(f"{label} must be a whole-second UTC timestamp")
    return value


def _canonical_nonnegative_decimal(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("identity price must be a non-empty decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        raise ValueError("identity price must be a decimal string") from None
    if not parsed.is_finite() or parsed < 0:
        raise ValueError("identity price must be finite and non-negative")
    normalized = format(parsed, "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    return normalized or "0"


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=_json_default,
        ).encode("utf-8")
    ).hexdigest()


def _json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    raise TypeError(f"unsupported canonical identity value: {type(value).__name__}")
