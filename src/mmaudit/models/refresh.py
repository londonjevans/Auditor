"""Deterministic, non-dispositive OpenRouter catalogue refresh evidence.

Refresh evidence detects provider metadata drift. It never qualifies a model,
assigns a root lineage, or authorizes source egress. Persisted self-hashes are
structural evidence only; live request paths retain their existing authenticated
exact-route checks.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from mmaudit.models.discovery import (
    ModelDiscoveryValidationError,
    canonicalize_openrouter_catalog_supported_parameters,
)
from mmaudit.models.endpoint_snapshots import (
    EndpointSnapshotValidationError,
    canonicalize_openrouter_endpoint_identity,
    canonicalize_openrouter_endpoint_token_limits,
    canonicalize_openrouter_pricing,
    canonicalize_openrouter_supported_parameters,
)
from mmaudit.models.identifiers import (
    EXACT_MODEL_ID_PATTERN,
    OPENROUTER_CATALOG_MODEL_ID_PATTERN,
    is_exact_openrouter_model_id,
    is_openrouter_catalog_model_id,
    require_exact_openrouter_model_id,
)
from mmaudit.models.output_modes import (
    StructuredOutputMode,
    mutually_supported_output_modes,
    reasoning_capability_parameters,
    supported_output_modes,
    supports_provider_structured_output,
    supports_reasoning_request,
)
from mmaudit.models.qualification import (
    CandidateModel,
    CandidateOperationalStatus,
    CandidateRegistry,
)
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.secrets import is_sensitive_workspace_name

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ENDPOINT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$"
_MAX_MODELS = 10_000
_MAX_ROUTES_PER_MODEL = 256
_MAX_PARAMETERS = 256
_MAX_PRICING_FIELDS = 64
_MAX_ARTIFACT_BYTES = 20_000_000
_PRIVATE_FILE_MODE = 0o600
_PRIVATE_DIRECTORY_MODE = 0o700
_REQUIRED_PARAMETERS = frozenset({"max_tokens", "temperature"})
_OPERATIONAL_TEXT = frozenset({"active", "available", "healthy", "online", "operational"})

SNAPSHOT_FILENAME = "model-refresh-snapshot.json"
SOURCE_EVIDENCE_FILENAME = "model-refresh-source-evidence.json"
DIFF_FILENAME = "model-refresh-diff.json"
ATTEMPT_FILENAME = "model-refresh-attempt.json"
FRESHNESS_FILENAME = "model-refresh-freshness.json"

_EndpointIdentityKey = tuple[str | None, str | None]
_CatalogModelId = Annotated[
    str,
    Field(pattern=OPENROUTER_CATALOG_MODEL_ID_PATTERN),
]
_BoundedParameter = Annotated[str, Field(min_length=1, max_length=100)]
_CanonicalPrice = Annotated[str, Field(min_length=1, max_length=128)]
_EndpointStatus = (
    Annotated[StrictInt, Field(ge=-(2**31 - 1), le=2**31 - 1)]
    | Annotated[StrictStr, Field(min_length=1, max_length=32)]
)


@dataclass(frozen=True)
class _EndpointRouteInput:
    raw: Mapping[str, Any]
    identity_key: _EndpointIdentityKey
    provider_endpoint: str
    routing_identity_unambiguous: bool


class ModelRefreshValidationError(ValueError):
    """Raised when catalogue refresh evidence is incomplete or inconsistent."""


class PricingObservationKind(StrEnum):
    EXACT = "EXACT"
    HASH_ONLY = "HASH_ONLY"


class PricingComparisonState(StrEnum):
    EVALUATED = "EVALUATED"
    NOT_EVALUABLE = "NOT_EVALUABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ModelDriftKind(StrEnum):
    NEW_ELIGIBLE_MODEL = "NEW_ELIGIBLE_MODEL"
    WITHDRAWN_MODEL = "WITHDRAWN_MODEL"
    MODEL_IDENTITY_CHANGED = "MODEL_IDENTITY_CHANGED"
    PRICING_CHANGED = "PRICING_CHANGED"
    CONTEXT_LIMIT_CHANGED = "CONTEXT_LIMIT_CHANGED"
    OUTPUT_LIMIT_CHANGED = "OUTPUT_LIMIT_CHANGED"
    STRUCTURED_OUTPUT_SUPPORT_CHANGED = "STRUCTURED_OUTPUT_SUPPORT_CHANGED"
    REASONING_SUPPORT_CHANGED = "REASONING_SUPPORT_CHANGED"
    ZDR_ELIGIBILITY_CHANGED = "ZDR_ELIGIBILITY_CHANGED"
    ENDPOINT_AVAILABILITY_CHANGED = "ENDPOINT_AVAILABILITY_CHANGED"
    ENDPOINT_IDENTITY_CHANGED = "ENDPOINT_IDENTITY_CHANGED"
    ENDPOINT_IDENTITY_UNVERIFIED = "ENDPOINT_IDENTITY_UNVERIFIED"
    LINEAGE_REVIEW_REQUIRED = "LINEAGE_REVIEW_REQUIRED"


class ModelRefreshAttemptStatus(StrEnum):
    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"
    PRODUCTION_BLOCKED = "PRODUCTION_BLOCKED"
    FAILED = "FAILED"


class ModelRefreshFailureCode(StrEnum):
    AUTHENTICATION = "AUTHENTICATION"
    NETWORK_TIMEOUT = "NETWORK_TIMEOUT"
    RATE_LIMIT = "RATE_LIMIT"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    MALFORMED_METADATA = "MALFORMED_METADATA"
    LOCAL_PERSISTENCE = "LOCAL_PERSISTENCE"
    SECRET_PREREQUISITE = "SECRET_PREREQUISITE"


class ModelRefreshFreshnessState(StrEnum):
    CURRENT = "CURRENT"
    STALE = "STALE"
    HARD_EXPIRED = "HARD_EXPIRED"
    NO_SUCCESS = "NO_SUCCESS"


class RefreshBaselineKind(StrEnum):
    PREVIOUS_SNAPSHOT = "PREVIOUS_SNAPSHOT"
    CANDIDATE_REGISTRY_HASH_ONLY = "CANDIDATE_REGISTRY_HASH_ONLY"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ModelRefreshCatalogSource(_FrozenModel):
    """Canonical allowlisted catalogue fields retained for deterministic replay."""

    exact_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    canonical_model_slug: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    catalog_context_length: int = Field(ge=1, le=2**31 - 1)
    provider_context_length: int | None = Field(default=None, ge=1, le=2**31 - 1)
    provider_max_completion_tokens: int | None = Field(
        default=None,
        ge=1,
        le=2**31 - 1,
    )
    supported_parameters: tuple[_BoundedParameter, ...] = Field(max_length=_MAX_PARAMETERS)

    @field_validator("exact_model_id", "canonical_model_slug")
    @classmethod
    def model_ids_are_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @model_validator(mode="after")
    def source_is_canonical(self) -> Self:
        if self.exact_model_id.split("/", 1)[0] != self.canonical_model_slug.split("/", 1)[0]:
            raise ValueError("refresh source canonical slug changes model author")
        effective_context = self.provider_context_length or self.catalog_context_length
        effective_output = self.provider_max_completion_tokens or effective_context
        if effective_output > effective_context:
            raise ValueError("refresh source catalogue output limit exceeds its context")
        if self.supported_parameters != tuple(sorted(set(self.supported_parameters))):
            raise ValueError("refresh source catalogue parameters must be unique and sorted")
        return self


class ModelRefreshEndpointSource(_FrozenModel):
    """Canonical allowlisted endpoint fields retained for deterministic replay."""

    exact_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    endpoint_tag: str | None = Field(default=None, pattern=_ENDPOINT_PATTERN)
    endpoint_slug: str | None = Field(default=None, pattern=_ENDPOINT_PATTERN)
    provider_name: str = Field(min_length=1, max_length=128)
    status: _EndpointStatus
    context_length: int = Field(ge=1, le=2**31 - 1)
    max_prompt_tokens: int | None = Field(default=None, ge=1, le=2**31 - 1)
    max_completion_tokens: int | None = Field(default=None, ge=1, le=2**31 - 1)
    supported_parameters: tuple[_BoundedParameter, ...] = Field(max_length=_MAX_PARAMETERS)
    pricing: dict[str, _CanonicalPrice] = Field(max_length=_MAX_PRICING_FIELDS)

    @field_validator("exact_model_id")
    @classmethod
    def model_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @field_validator("provider_name")
    @classmethod
    def provider_name_is_safe_display_text(cls, value: str) -> str:
        if value != value.strip() or any(not character.isprintable() for character in value):
            raise ValueError("refresh source provider name is invalid")
        return value

    @model_validator(mode="after")
    def source_is_canonical(self) -> Self:
        if self.endpoint_tag is None and self.endpoint_slug is None:
            raise ValueError("refresh source endpoint requires a tag or slug")
        _operational, normalized_status = _operational_status(self.status)
        if isinstance(self.status, str) and normalized_status != self.status:
            raise ValueError("refresh source endpoint status is not canonical")
        canonical_limits = _endpoint_token_limits(_endpoint_source_payload(self))
        expected_limits = (
            self.context_length,
            self.context_length if self.max_prompt_tokens is None else self.max_prompt_tokens,
            "context_limit" if self.max_prompt_tokens is None else "metadata",
            (
                self.context_length
                if self.max_completion_tokens is None
                else self.max_completion_tokens
            ),
            "context_limit" if self.max_completion_tokens is None else "metadata",
        )
        if canonical_limits != expected_limits:
            raise ValueError("refresh source endpoint token limits are not canonical")
        if self.supported_parameters != tuple(sorted(set(self.supported_parameters))):
            raise ValueError("refresh source endpoint parameters must be unique and sorted")
        if _endpoint_supported_parameters(list(self.supported_parameters)) != (
            self.supported_parameters
        ):
            raise ValueError("refresh source endpoint parameters are not canonical")
        if tuple(self.pricing) != tuple(sorted(self.pricing)):
            raise ValueError("refresh source endpoint pricing fields must be sorted")
        if _canonical_pricing(self.pricing) != self.pricing:
            raise ValueError("refresh source endpoint pricing is not canonical")
        return self


class ModelRefreshCandidateEndpointSource(_FrozenModel):
    """One exact candidate endpoint envelope retained for deterministic replay."""

    exact_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    endpoints: tuple[ModelRefreshEndpointSource, ...] = Field(max_length=_MAX_ROUTES_PER_MODEL)

    @field_validator("exact_model_id")
    @classmethod
    def model_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @model_validator(mode="after")
    def endpoint_set_is_canonical(self) -> Self:
        if any(endpoint.exact_model_id != self.exact_model_id for endpoint in self.endpoints):
            raise ValueError("refresh candidate endpoint source changes model identity")
        keys = tuple(_endpoint_source_sort_key(endpoint) for endpoint in self.endpoints)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("refresh candidate endpoint source must be unique and sorted")
        return self


class ExcludedZdrRoutedModelSource(_FrozenModel):
    """Count an ignored routed ZDR identifier without retaining endpoint details."""

    model_id: _CatalogModelId
    occurrence_count: int = Field(ge=1, le=_MAX_MODELS * 4)

    @field_validator("model_id")
    @classmethod
    def model_is_routed_catalog_id(cls, value: str) -> str:
        if not is_openrouter_catalog_model_id(value) or is_exact_openrouter_model_id(value):
            raise ValueError("excluded ZDR routed model ID is invalid")
        return value


class ModelRefreshSourceEvidence(_FrozenModel):
    """Bounded canonical metadata projection used to reproduce a refresh snapshot."""

    schema_version: Literal["1.0"] = "1.0"
    retrieved_at: datetime
    source_api_identity: Literal["https://openrouter.ai/api/v1"] = "https://openrouter.ai/api/v1"
    authenticated_metadata: Literal[True]
    candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    catalog_models: tuple[ModelRefreshCatalogSource, ...] = Field(
        min_length=1,
        max_length=_MAX_MODELS,
    )
    excluded_routed_model_ids: tuple[_CatalogModelId, ...] = Field(max_length=_MAX_MODELS)
    zdr_endpoints: tuple[ModelRefreshEndpointSource, ...] = Field(max_length=_MAX_MODELS * 4)
    excluded_zdr_routed_models: tuple[ExcludedZdrRoutedModelSource, ...] = Field(
        max_length=_MAX_MODELS * 4
    )
    candidate_endpoint_sets: tuple[ModelRefreshCandidateEndpointSource, ...] = Field(
        max_length=_MAX_MODELS
    )
    catalog_projection_sha256: str = Field(pattern=_SHA256_PATTERN)
    zdr_projection_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_endpoint_projection_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("retrieved_at")
    @classmethod
    def retrieval_time_is_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="refresh source retrieval time")

    @field_validator("excluded_routed_model_ids")
    @classmethod
    def excluded_catalog_ids_are_canonical(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            not is_openrouter_catalog_model_id(model_id) or is_exact_openrouter_model_id(model_id)
            for model_id in value
        ):
            raise ValueError("excluded refresh source catalogue IDs are invalid")
        return value

    @model_validator(mode="after")
    def evidence_is_canonical_and_self_bound(self) -> Self:
        catalog_ids = tuple(model.exact_model_id for model in self.catalog_models)
        if catalog_ids != tuple(sorted(set(catalog_ids))):
            raise ValueError("refresh source catalogue models must be unique and sorted")
        if len(catalog_ids) + len(self.excluded_routed_model_ids) > _MAX_MODELS:
            raise ValueError("refresh source catalogue exceeds the model limit")
        zdr_keys = tuple(_endpoint_source_sort_key(endpoint) for endpoint in self.zdr_endpoints)
        if zdr_keys != tuple(sorted(set(zdr_keys))):
            raise ValueError("refresh source ZDR endpoints must be unique and sorted")
        excluded_zdr_ids = tuple(item.model_id for item in self.excluded_zdr_routed_models)
        if excluded_zdr_ids != tuple(sorted(set(excluded_zdr_ids))):
            raise ValueError("excluded refresh source ZDR IDs must be unique and sorted")
        if (
            len(self.zdr_endpoints)
            + sum(item.occurrence_count for item in self.excluded_zdr_routed_models)
            > _MAX_MODELS * 4
        ):
            raise ValueError("refresh source ZDR catalogue exceeds the endpoint limit")
        candidate_ids = tuple(item.exact_model_id for item in self.candidate_endpoint_sets)
        if candidate_ids != tuple(sorted(set(candidate_ids))):
            raise ValueError("refresh source candidate endpoint sets must be unique and sorted")
        expected_catalog_hash = _canonical_sha256(_catalog_payload_from_source(self))
        expected_zdr_hash = _canonical_sha256(_zdr_payload_from_source(self))
        expected_candidate_hash = _canonical_sha256(_candidate_payloads_from_source(self))
        if self.catalog_projection_sha256 != expected_catalog_hash:
            raise ValueError("refresh source catalogue projection hash is inconsistent")
        if self.zdr_projection_sha256 != expected_zdr_hash:
            raise ValueError("refresh source ZDR projection hash is inconsistent")
        if self.candidate_endpoint_projection_sha256 != expected_candidate_hash:
            raise ValueError("refresh source candidate projection hash is inconsistent")
        expected = _canonical_sha256(
            self.model_dump(mode="json", exclude={"source_evidence_sha256"})
        )
        if self.source_evidence_sha256 != expected:
            raise ValueError("refresh source evidence self-hash is inconsistent")
        return self


class ProviderRouteState(_FrozenModel):
    """Allowlisted exact route facts needed for safety and cost drift checks."""

    schema_version: Literal["2.0"] = "2.0"
    exact_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    provider_endpoint: str = Field(pattern=_ENDPOINT_PATTERN)
    endpoint_tag: str | None = Field(default=None, pattern=_ENDPOINT_PATTERN)
    endpoint_slug: str | None = Field(default=None, pattern=_ENDPOINT_PATTERN)
    provider_name: str = Field(min_length=1, max_length=128)
    routing_identity_unambiguous: bool
    operational: bool
    operational_status: str = Field(min_length=1, max_length=32)
    zdr_eligible: bool
    context_limit: int = Field(ge=1, le=2**31 - 1)
    max_prompt_tokens: int | None = Field(default=None, ge=1, le=2**31 - 1)
    max_prompt_tokens_source: Literal["metadata", "context_limit"] | None = None
    output_limit: int = Field(ge=1, le=2**31 - 1)
    output_limit_source: Literal["metadata", "context_limit"] | None = None
    supported_parameters: tuple[str, ...] = Field(max_length=_MAX_PARAMETERS)
    supported_output_modes: tuple[StructuredOutputMode, ...] = Field(
        min_length=1,
        max_length=3,
    )
    structured_output_supported: bool
    structured_output_mode: StructuredOutputMode | None = None
    reasoning_supported: bool
    pricing_observation: PricingObservationKind
    pricing: dict[str, str] | None = Field(default=None, max_length=_MAX_PRICING_FIELDS)
    pricing_sha256: str = Field(pattern=_SHA256_PATTERN)
    route_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id")
    @classmethod
    def model_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @field_validator("provider_name")
    @classmethod
    def provider_name_is_safe_display_text(cls, value: str) -> str:
        if value != value.strip() or any(not character.isprintable() for character in value):
            raise ValueError("refresh route provider name is invalid")
        return value

    @model_validator(mode="after")
    def route_is_canonical_and_self_bound(self) -> Self:
        if self.endpoint_tag is None and self.endpoint_slug is None:
            raise ValueError("refresh route requires an endpoint tag or slug")
        if self.provider_endpoint not in {self.endpoint_tag, self.endpoint_slug}:
            raise ValueError("refresh route endpoint differs from its tag and slug")
        if (self.max_prompt_tokens is None) is not (self.max_prompt_tokens_source is None):
            raise ValueError("refresh route prompt limit evidence is incomplete")
        if self.max_prompt_tokens is not None and self.max_prompt_tokens > self.context_limit:
            raise ValueError("refresh route prompt limit exceeds its context")
        if (
            self.max_prompt_tokens_source == "context_limit"
            and self.max_prompt_tokens != self.context_limit
        ):
            raise ValueError("refresh route derived prompt limit differs from its context")
        if self.output_limit > self.context_limit:
            raise ValueError("refresh route output limit exceeds its context")
        if self.output_limit_source == "context_limit" and self.output_limit != self.context_limit:
            raise ValueError("refresh route derived output limit differs from its context")
        if self.supported_parameters != tuple(sorted(set(self.supported_parameters))):
            raise ValueError("refresh route parameters must be unique and sorted")
        route_modes = supported_output_modes(self.supported_parameters)
        projected_modes = tuple(
            mode for mode in route_modes if mode in frozenset(self.supported_output_modes)
        )
        if self.supported_output_modes != projected_modes:
            raise ValueError("refresh route output-mode projection is inconsistent")
        expected_structured = supports_provider_structured_output(self.supported_parameters)
        if self.structured_output_supported is not expected_structured:
            raise ValueError("refresh route structured-output status is inconsistent")
        if self.structured_output_mode is not None and (
            self.structured_output_mode is not self.supported_output_modes[0]
        ):
            raise ValueError("refresh route selected output mode is inconsistent")
        expected_reasoning = supports_reasoning_request(
            reasoning_capability_parameters(self.supported_parameters)
        )
        if self.reasoning_supported is not expected_reasoning:
            raise ValueError("refresh route reasoning status is inconsistent")
        if self.pricing_observation is PricingObservationKind.EXACT:
            if self.pricing is None or not {"prompt", "completion"}.issubset(self.pricing):
                raise ValueError("exact refresh pricing requires prompt and completion values")
            if (
                self.max_prompt_tokens is None
                or self.max_prompt_tokens_source is None
                or self.output_limit_source is None
                or self.structured_output_mode is None
            ):
                raise ValueError("exact refresh route lacks exact capability evidence")
            if tuple(self.pricing) != tuple(sorted(self.pricing)):
                raise ValueError("refresh route pricing fields must be sorted")
            if _canonical_pricing(self.pricing) != self.pricing:
                raise ValueError("refresh route pricing is not canonical")
            if self.pricing_sha256 != _canonical_sha256(self.pricing):
                raise ValueError("refresh route pricing hash is inconsistent")
        else:
            if self.pricing is not None:
                raise ValueError("hash-only refresh pricing cannot retain exact values")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"route_sha256"}))
        if self.route_sha256 != expected:
            raise ValueError("refresh route self-hash is inconsistent")
        return self

    @property
    def discovery_eligible(self) -> bool:
        """Return only metadata eligibility; this is never model qualification."""

        return (
            self.routing_identity_unambiguous
            and self.operational
            and self.zdr_eligible
            and _REQUIRED_PARAMETERS.issubset(self.supported_parameters)
            and self.pricing_observation is PricingObservationKind.EXACT
        )


class CatalogModelState(_FrozenModel):
    """One exact catalogue model and every normalized observed route."""

    schema_version: Literal["2.0"] = "2.0"
    exact_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    canonical_model_slug: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    variant_family_key: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    catalog_context_limit: int = Field(ge=1, le=2**31 - 1)
    context_limit: int = Field(ge=1, le=2**31 - 1)
    context_limit_source: Literal["metadata", "catalog_context", "candidate_registry"]
    output_limit: int = Field(ge=1, le=2**31 - 1)
    output_limit_source: Literal["metadata", "provider_context", "candidate_registry"]
    supported_parameters: tuple[str, ...] = Field(max_length=_MAX_PARAMETERS)
    supported_output_modes: tuple[StructuredOutputMode, ...] = Field(
        min_length=1,
        max_length=3,
    )
    structured_output_supported: bool
    structured_output_mode: StructuredOutputMode | None = None
    reasoning_supported: bool
    routes: tuple[ProviderRouteState, ...] = Field(max_length=_MAX_ROUTES_PER_MODEL)
    eligible_provider_endpoints: tuple[str, ...] = Field(max_length=_MAX_ROUTES_PER_MODEL)
    state_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id", "canonical_model_slug", "variant_family_key")
    @classmethod
    def model_ids_are_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @model_validator(mode="after")
    def model_is_canonical_and_self_bound(self) -> Self:
        if self.exact_model_id.split("/", 1)[0] != self.canonical_model_slug.split("/", 1)[0]:
            raise ValueError("refresh canonical slug changes model author")
        if self.output_limit > self.context_limit:
            raise ValueError("refresh model output limit exceeds its context")
        if (
            self.context_limit_source == "catalog_context"
            and self.context_limit != self.catalog_context_limit
        ):
            raise ValueError("refresh model derived provider context is inconsistent")
        if (
            self.output_limit_source == "provider_context"
            and self.output_limit != self.context_limit
        ):
            raise ValueError("refresh model derived output limit is inconsistent")
        if self.variant_family_key != model_variant_family_key(self.exact_model_id):
            raise ValueError("refresh model variant-family key is inconsistent")
        if self.supported_parameters != tuple(sorted(set(self.supported_parameters))):
            raise ValueError("refresh model parameters must be unique and sorted")
        expected_modes = supported_output_modes(self.supported_parameters)
        if self.supported_output_modes != expected_modes:
            raise ValueError("refresh model output modes are inconsistent")
        expected_structured = supports_provider_structured_output(self.supported_parameters)
        if self.structured_output_supported is not expected_structured:
            raise ValueError("refresh model structured-output status is inconsistent")
        observation_kinds = {route.pricing_observation for route in self.routes}
        if len(observation_kinds) > 1:
            raise ValueError("refresh model mixes exact and hash-only route observations")
        hash_only_baseline = observation_kinds == {PricingObservationKind.HASH_ONLY}
        if hash_only_baseline:
            if (
                self.context_limit_source != "candidate_registry"
                or self.output_limit_source != "candidate_registry"
            ):
                raise ValueError("hash-only refresh model lacks registry provenance")
            if self.structured_output_mode is not None and (
                self.structured_output_mode is not expected_modes[0]
            ):
                raise ValueError("hash-only refresh model output mode is inconsistent")
        elif (
            self.context_limit_source == "candidate_registry"
            or self.output_limit_source == "candidate_registry"
            or self.structured_output_mode is not expected_modes[0]
        ):
            raise ValueError("exact refresh model lacks exact capability evidence")
        expected_reasoning = supports_reasoning_request(
            reasoning_capability_parameters(self.supported_parameters)
        )
        if self.reasoning_supported is not expected_reasoning:
            raise ValueError("refresh model reasoning status is inconsistent")
        route_keys = tuple(route.provider_endpoint for route in self.routes)
        if route_keys != tuple(sorted(set(route_keys))):
            raise ValueError("refresh model routes must be unique and sorted")
        if any(route.exact_model_id != self.exact_model_id for route in self.routes):
            raise ValueError("refresh model contains a route for another model")
        for route in self.routes:
            expected_route_modes = mutually_supported_output_modes(
                (self.supported_parameters, route.supported_parameters)
            )
            if route.supported_output_modes != expected_route_modes:
                raise ValueError("refresh route output modes differ from the model intersection")
            expected_route_mode = (
                None
                if route.pricing_observation is PricingObservationKind.HASH_ONLY
                and route.structured_output_mode is None
                else expected_route_modes[0]
            )
            if route.structured_output_mode is not expected_route_mode:
                raise ValueError("refresh route output mode differs from the model intersection")
        identity_keys = tuple((route.endpoint_tag, route.endpoint_slug) for route in self.routes)
        if len(identity_keys) != len(set(identity_keys)):
            raise ValueError("refresh model contains duplicate full route identities")
        alias_counts: dict[str, int] = {}
        provider_name_counts: dict[str, int] = {}
        for route in self.routes:
            for alias in {
                value for value in (route.endpoint_tag, route.endpoint_slug) if value is not None
            }:
                alias_counts[alias] = alias_counts.get(alias, 0) + 1
            normalized_name = route.provider_name.casefold()
            provider_name_counts[normalized_name] = provider_name_counts.get(normalized_name, 0) + 1
        for route in self.routes:
            if alias_counts[route.provider_endpoint] != 1:
                raise ValueError("refresh model route selector is ambiguous")
            expected_unambiguous = provider_name_counts[route.provider_name.casefold()] == 1
            if route.routing_identity_unambiguous is not expected_unambiguous:
                raise ValueError("refresh route identity-ambiguity state is inconsistent")
        expected_eligible = tuple(
            route.provider_endpoint
            for route in self.routes
            if route.discovery_eligible and _REQUIRED_PARAMETERS.issubset(self.supported_parameters)
        )
        if self.eligible_provider_endpoints != expected_eligible:
            raise ValueError("refresh model eligible route projection is inconsistent")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"state_sha256"}))
        if self.state_sha256 != expected:
            raise ValueError("refresh model self-hash is inconsistent")
        return self


class LiveProviderRouteState(ProviderRouteState):
    """Schema-visible exact route evidence required in a live refresh snapshot."""

    max_prompt_tokens: int = Field(ge=1, le=2**31 - 1)
    max_prompt_tokens_source: Literal["metadata", "context_limit"]
    output_limit_source: Literal["metadata", "context_limit"]
    structured_output_mode: StructuredOutputMode
    pricing_observation: Literal[PricingObservationKind.EXACT]
    pricing: dict[str, str] = Field(max_length=_MAX_PRICING_FIELDS)


class LiveCatalogModelState(CatalogModelState):
    """Schema-visible exact catalogue evidence required in a live snapshot."""

    context_limit_source: Literal["metadata", "catalog_context"]
    output_limit_source: Literal["metadata", "provider_context"]
    structured_output_mode: StructuredOutputMode
    routes: tuple[LiveProviderRouteState, ...] = Field(max_length=_MAX_ROUTES_PER_MODEL)


class ModelRefreshSnapshot(_FrozenModel):
    """Complete allowlisted semantic snapshot from one provider observation."""

    schema_version: Literal["2.0"] = "2.0"
    retrieved_at: datetime
    source_api_identity: Literal["https://openrouter.ai/api/v1"] = "https://openrouter.ai/api/v1"
    authenticated_metadata: Literal[True]
    candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    catalog_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    zdr_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    catalog_model_count: int = Field(ge=1, le=_MAX_MODELS)
    excluded_routed_model_ids: tuple[str, ...] = Field(max_length=_MAX_MODELS)
    models: tuple[LiveCatalogModelState, ...] = Field(
        min_length=1,
        max_length=_MAX_MODELS,
    )
    semantic_sha256: str = Field(pattern=_SHA256_PATTERN)
    snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("retrieved_at")
    @classmethod
    def retrieval_time_is_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="refresh retrieval time")

    @field_validator("excluded_routed_model_ids")
    @classmethod
    def excluded_ids_are_bounded_non_exact_catalog_ids(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if any(
            not is_openrouter_catalog_model_id(model_id) or is_exact_openrouter_model_id(model_id)
            for model_id in value
        ):
            raise ValueError("excluded routed model IDs are invalid")
        return value

    @model_validator(mode="after")
    def snapshot_is_complete_and_self_bound(self) -> Self:
        model_ids = tuple(model.exact_model_id for model in self.models)
        if model_ids != tuple(sorted(set(model_ids))):
            raise ValueError("refresh snapshot model IDs must be unique and sorted")
        if self.catalog_model_count != len(self.models) + len(self.excluded_routed_model_ids):
            raise ValueError("refresh snapshot catalogue count is inconsistent")
        if self.excluded_routed_model_ids != tuple(sorted(set(self.excluded_routed_model_ids))):
            raise ValueError("excluded routed model IDs must be unique and sorted")
        expected_semantic = _canonical_sha256(
            [model.model_dump(mode="json") for model in self.models]
        )
        if self.semantic_sha256 != expected_semantic:
            raise ValueError("refresh snapshot semantic hash is inconsistent")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"snapshot_sha256"}))
        if self.snapshot_sha256 != expected:
            raise ValueError("refresh snapshot self-hash is inconsistent")
        return self


class SelectedModelRoute(_FrozenModel):
    exact_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    provider_endpoint: str = Field(pattern=_ENDPOINT_PATTERN)

    @field_validator("exact_model_id")
    @classmethod
    def model_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)


class ModelDriftRecord(_FrozenModel):
    exact_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    change_kinds: tuple[ModelDriftKind, ...] = Field(min_length=1)
    before: CatalogModelState | None
    after: LiveCatalogModelState | None
    pricing_comparison: PricingComparisonState
    pricing_increase_fields: tuple[str, ...] = Field(max_length=_MAX_PRICING_FIELDS)
    production_selected: bool
    production_blocking: bool
    lineage_review_required: bool
    record_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id")
    @classmethod
    def model_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @model_validator(mode="after")
    def record_is_consistent(self) -> Self:
        if self.before is None and self.after is None:
            raise ValueError("refresh drift must retain before or after state")
        if self.before is not None and self.before.exact_model_id != self.exact_model_id:
            raise ValueError("refresh drift before state changes model identity")
        if self.after is not None and self.after.exact_model_id != self.exact_model_id:
            raise ValueError("refresh drift after state changes model identity")
        if self.change_kinds != tuple(sorted(set(self.change_kinds), key=lambda item: item.value)):
            raise ValueError("refresh drift kinds must be unique and sorted")
        if self.pricing_increase_fields != tuple(sorted(set(self.pricing_increase_fields))):
            raise ValueError("refresh price-increase fields must be unique and sorted")
        if self.pricing_increase_fields and (
            ModelDriftKind.PRICING_CHANGED not in self.change_kinds
            or self.pricing_comparison is not PricingComparisonState.EVALUATED
        ):
            raise ValueError("refresh price increases require evaluated pricing drift")
        if self.production_blocking and not self.production_selected:
            raise ValueError("unselected refresh drift cannot claim production blocking")
        if self.lineage_review_required is not (
            ModelDriftKind.LINEAGE_REVIEW_REQUIRED in self.change_kinds
        ):
            raise ValueError("refresh lineage-review status differs from its drift kinds")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"record_sha256"}))
        if self.record_sha256 != expected:
            raise ValueError("refresh drift record self-hash is inconsistent")
        return self


class ModelRefreshDiff(_FrozenModel):
    """Deterministic exact-state comparison against a frozen baseline."""

    schema_version: Literal["2.0"] = "2.0"
    compared_at: datetime
    baseline_kind: RefreshBaselineKind
    baseline_sha256: str = Field(pattern=_SHA256_PATTERN)
    current_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    pricing_tolerance_fraction: str
    selected_routes: tuple[SelectedModelRoute, ...]
    changes: tuple[ModelDriftRecord, ...]
    semantic_unchanged: bool
    status: ModelRefreshAttemptStatus
    production_block_reasons: tuple[str, ...]
    diff_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("compared_at")
    @classmethod
    def comparison_time_is_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="refresh comparison time")

    @field_validator("pricing_tolerance_fraction")
    @classmethod
    def pricing_tolerance_is_canonical(cls, value: str) -> str:
        parsed = _canonical_fraction(value)
        if parsed > 1:
            raise ValueError("refresh pricing tolerance cannot exceed one")
        return value

    @model_validator(mode="after")
    def diff_is_canonical_and_self_bound(self) -> Self:
        selected = tuple(
            (route.exact_model_id, route.provider_endpoint) for route in self.selected_routes
        )
        if selected != tuple(sorted(set(selected))):
            raise ValueError("refresh selected routes must be unique and sorted")
        model_ids = tuple(record.exact_model_id for record in self.changes)
        if model_ids != tuple(sorted(set(model_ids))):
            raise ValueError("refresh drift records must be unique and sorted")
        if self.production_block_reasons != tuple(sorted(set(self.production_block_reasons))):
            raise ValueError("refresh production blockers must be unique and sorted")
        selected_labels = {
            f"{route.exact_model_id}={route.provider_endpoint}" for route in self.selected_routes
        }
        if not set(self.production_block_reasons).issubset(selected_labels):
            raise ValueError("refresh production blockers are not selected exact routes")
        blocking_models = {
            record.exact_model_id for record in self.changes if record.production_blocking
        }
        if any(
            route.exact_model_id in blocking_models
            and f"{route.exact_model_id}={route.provider_endpoint}"
            not in self.production_block_reasons
            for route in self.selected_routes
        ):
            raise ValueError("blocking refresh drift lacks its selected route reason")
        expected_unchanged = not self.changes
        if self.semantic_unchanged is not expected_unchanged:
            raise ValueError("refresh semantic unchanged state differs from drift records")
        expected_status = (
            ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
            if self.production_block_reasons
            else (
                ModelRefreshAttemptStatus.UNCHANGED
                if self.semantic_unchanged
                else ModelRefreshAttemptStatus.CHANGED
            )
        )
        if self.status is not expected_status:
            raise ValueError("refresh diff status is inconsistent")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"diff_sha256"}))
        if self.diff_sha256 != expected:
            raise ValueError("refresh diff self-hash is inconsistent")
        return self


class ModelRefreshAttempt(_FrozenModel):
    """Terminal refresh result; failure can never masquerade as unchanged."""

    schema_version: Literal["1.0"] = "1.0"
    attempted_at: datetime
    candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    status: ModelRefreshAttemptStatus
    snapshot_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    diff_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    failure_code: ModelRefreshFailureCode | None
    attempt_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("attempted_at")
    @classmethod
    def attempt_time_is_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="refresh attempt time")

    @model_validator(mode="after")
    def attempt_is_terminal_and_self_bound(self) -> Self:
        if self.status is ModelRefreshAttemptStatus.FAILED:
            if (
                self.failure_code is None
                or self.snapshot_sha256 is not None
                or self.diff_sha256 is not None
            ):
                raise ValueError("failed refresh must retain only a typed failure code")
        elif (
            self.failure_code is not None
            or self.snapshot_sha256 is None
            or self.diff_sha256 is None
        ):
            raise ValueError("successful refresh requires snapshot and diff evidence")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"attempt_sha256"}))
        if self.attempt_sha256 != expected:
            raise ValueError("refresh attempt self-hash is inconsistent")
        return self


class ModelRefreshFreshness(_FrozenModel):
    """Time-bound availability evidence used only as a fail-closed gate."""

    schema_version: Literal["1.0"] = "1.0"
    observed_at: datetime
    last_success_retrieved_at: datetime | None
    snapshot_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    soft_max_age_hours: int = Field(ge=1, le=24 * 30)
    hard_max_age_hours: int = Field(ge=2, le=24 * 90)
    state: ModelRefreshFreshnessState
    production_selection_present: bool
    production_blocked: bool
    freshness_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("observed_at")
    @classmethod
    def observation_time_is_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="refresh freshness observation")

    @field_validator("last_success_retrieved_at")
    @classmethod
    def success_time_is_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return _whole_second_utc(value, label="refresh last success")

    @model_validator(mode="after")
    def freshness_is_consistent(self) -> Self:
        if self.hard_max_age_hours <= self.soft_max_age_hours:
            raise ValueError("refresh hard age must exceed the soft age")
        if (self.last_success_retrieved_at is None) is not (self.snapshot_sha256 is None):
            raise ValueError("refresh freshness success time and snapshot must be paired")
        if self.last_success_retrieved_at is not None:
            if self.last_success_retrieved_at > self.observed_at:
                raise ValueError("refresh success cannot postdate freshness observation")
            age = self.observed_at - self.last_success_retrieved_at
            expected_state = (
                ModelRefreshFreshnessState.HARD_EXPIRED
                if age > timedelta(hours=self.hard_max_age_hours)
                else (
                    ModelRefreshFreshnessState.STALE
                    if age > timedelta(hours=self.soft_max_age_hours)
                    else ModelRefreshFreshnessState.CURRENT
                )
            )
        else:
            expected_state = ModelRefreshFreshnessState.NO_SUCCESS
        if self.state is not expected_state:
            raise ValueError("refresh freshness state is inconsistent")
        expected_blocked = self.production_selection_present and self.state in {
            ModelRefreshFreshnessState.HARD_EXPIRED,
            ModelRefreshFreshnessState.NO_SUCCESS,
        }
        if self.production_blocked is not expected_blocked:
            raise ValueError("refresh freshness production gate is inconsistent")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"freshness_sha256"}))
        if self.freshness_sha256 != expected:
            raise ValueError("refresh freshness self-hash is inconsistent")
        return self


def model_variant_family_key(exact_model_id: str) -> str:
    """Collapse routing/performance variants without asserting root lineage."""

    exact_model_id = require_exact_openrouter_model_id(exact_model_id)
    author, slug = exact_model_id.split("/", 1)
    previous = ""
    while slug != previous:
        previous = slug
        for suffix in (":batch", ":fast", "-batch", "-fast"):
            if slug.endswith(suffix) and len(slug) > len(suffix):
                slug = slug[: -len(suffix)]
    return require_exact_openrouter_model_id(f"{author}/{slug}", label="variant-family key")


def reject_model_refresh_secret_reflection(
    *payloads: Mapping[str, Any],
    forbidden_values: Sequence[str],
) -> None:
    """Reject credential reflection before provider metadata is hashed or persisted."""

    canaries = tuple(value for value in forbidden_values if isinstance(value, str) and value)
    if not canaries:
        raise ModelRefreshValidationError(
            "refresh secret-reflection validation requires an in-memory canary"
        )
    pending: list[Any] = list(payloads)
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            if any(canary in current for canary in canaries):
                raise ModelRefreshValidationError(
                    "provider metadata reflected an operator credential"
                )
        elif isinstance(current, Mapping):
            pending.extend(current.keys())
            pending.extend(current.values())
        elif isinstance(current, (list, tuple)):
            pending.extend(current)


def build_model_refresh_source_evidence(
    *,
    retrieved_at: datetime,
    catalog_payload: Mapping[str, Any],
    zdr_payload: Mapping[str, Any],
    candidate_registry: CandidateRegistry,
    candidate_endpoint_payloads: Mapping[str, Mapping[str, Any]],
    authenticated_metadata: bool,
) -> ModelRefreshSourceEvidence:
    """Retain only canonical provider fields needed to reproduce a refresh snapshot."""

    if authenticated_metadata is not True:
        raise ModelRefreshValidationError(
            "refresh source evidence requires an authenticated metadata session"
        )
    retrieved_at = _whole_second_utc(retrieved_at, label="refresh retrieval time")
    registry = CandidateRegistry.model_validate(candidate_registry.model_dump(mode="json"))
    raw_models = _required_bounded_list(catalog_payload.get("data"), label="model catalogue")
    raw_zdr = _required_bounded_list(
        zdr_payload.get("data"),
        label="ZDR endpoint catalogue",
        allow_empty=True,
        maximum=_MAX_MODELS * 4,
    )
    catalog_models: list[ModelRefreshCatalogSource] = []
    excluded: list[str] = []
    seen_catalog_ids: set[str] = set()
    for raw in raw_models:
        model_id = raw.get("id")
        if not isinstance(model_id, str) or not is_openrouter_catalog_model_id(model_id):
            raise ModelRefreshValidationError("model catalogue contains an invalid model ID")
        if model_id in seen_catalog_ids:
            raise ModelRefreshValidationError("model catalogue contains duplicate model IDs")
        seen_catalog_ids.add(model_id)
        if not is_exact_openrouter_model_id(model_id):
            excluded.append(model_id)
            continue
        catalog_models.append(_catalog_source_from_raw(model_id=model_id, raw=raw))
    if not catalog_models:
        raise ModelRefreshValidationError("model catalogue contains no exact models")

    candidate_ids = tuple(candidate.exact_model_id for candidate in registry.candidates)
    if set(candidate_endpoint_payloads) != set(candidate_ids):
        raise ModelRefreshValidationError(
            "candidate endpoint payloads do not exactly cover the candidate registry"
        )

    zdr_endpoints: list[ModelRefreshEndpointSource] = []
    excluded_zdr_counts: dict[str, int] = {}
    for raw in raw_zdr:
        model_id = raw.get("model_id")
        if not isinstance(model_id, str) or not is_openrouter_catalog_model_id(model_id):
            raise ModelRefreshValidationError("ZDR catalogue contains an invalid model ID")
        if not is_exact_openrouter_model_id(model_id):
            excluded_zdr_counts[model_id] = excluded_zdr_counts.get(model_id, 0) + 1
            continue
        zdr_endpoints.append(
            _endpoint_source_from_raw(
                exact_model_id=model_id,
                raw=raw,
            )
        )

    candidate_sets: list[ModelRefreshCandidateEndpointSource] = []
    for model_id, envelope in sorted(candidate_endpoint_payloads.items()):
        data = envelope.get("data")
        if not isinstance(data, Mapping) or data.get("id") != model_id:
            raise ModelRefreshValidationError(
                "candidate endpoint metadata changes exact model identity"
            )
        endpoints = _required_bounded_list(
            data.get("endpoints"),
            label="candidate endpoint catalogue",
            allow_empty=True,
            maximum=_MAX_ROUTES_PER_MODEL,
        )
        source_endpoints = tuple(
            sorted(
                (
                    _endpoint_source_from_raw(
                        exact_model_id=model_id,
                        raw=endpoint,
                    )
                    for endpoint in endpoints
                ),
                key=_endpoint_source_sort_key,
            )
        )
        if len(source_endpoints) != len(
            {_endpoint_source_sort_key(endpoint) for endpoint in source_endpoints}
        ):
            raise ModelRefreshValidationError(
                "candidate endpoint catalogue contains duplicate exact routes"
            )
        try:
            candidate_sets.append(
                ModelRefreshCandidateEndpointSource(
                    exact_model_id=model_id,
                    endpoints=source_endpoints,
                )
            )
        except ValueError as exc:
            raise ModelRefreshValidationError(
                "candidate endpoint source projection is invalid"
            ) from exc

    ordered_catalog = tuple(sorted(catalog_models, key=lambda item: item.exact_model_id))
    ordered_excluded = tuple(sorted(excluded))
    ordered_zdr = tuple(sorted(zdr_endpoints, key=_endpoint_source_sort_key))
    if len(ordered_zdr) != len({_endpoint_source_sort_key(endpoint) for endpoint in ordered_zdr}):
        raise ModelRefreshValidationError("ZDR catalogue contains duplicate exact routes")
    ordered_excluded_zdr = tuple(
        ExcludedZdrRoutedModelSource(
            model_id=model_id,
            occurrence_count=count,
        )
        for model_id, count in sorted(excluded_zdr_counts.items())
    )
    ordered_candidates = tuple(sorted(candidate_sets, key=lambda item: item.exact_model_id))
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "retrieved_at": retrieved_at,
        "source_api_identity": "https://openrouter.ai/api/v1",
        "authenticated_metadata": True,
        "candidate_registry_sha256": registry.registry_sha256,
        "catalog_models": [item.model_dump(mode="json") for item in ordered_catalog],
        "excluded_routed_model_ids": list(ordered_excluded),
        "zdr_endpoints": [item.model_dump(mode="json") for item in ordered_zdr],
        "excluded_zdr_routed_models": [
            item.model_dump(mode="json") for item in ordered_excluded_zdr
        ],
        "candidate_endpoint_sets": [item.model_dump(mode="json") for item in ordered_candidates],
        "catalog_projection_sha256": _canonical_sha256(
            _catalog_payload_from_parts(
                catalog_models=ordered_catalog,
                excluded_routed_model_ids=ordered_excluded,
            )
        ),
        "zdr_projection_sha256": _canonical_sha256(
            _zdr_payload_from_parts(
                zdr_endpoints=ordered_zdr,
                excluded_zdr_routed_models=ordered_excluded_zdr,
            )
        ),
        "candidate_endpoint_projection_sha256": _canonical_sha256(
            _candidate_payloads_from_parts(candidate_endpoint_sets=ordered_candidates)
        ),
    }
    values["source_evidence_sha256"] = _canonical_sha256(values)
    try:
        return ModelRefreshSourceEvidence.model_validate(values)
    except ValueError as exc:
        raise ModelRefreshValidationError("refresh source evidence is invalid") from exc


def build_model_refresh_snapshot_from_source(
    *,
    source_evidence: ModelRefreshSourceEvidence,
    candidate_registry: CandidateRegistry,
) -> ModelRefreshSnapshot:
    """Reproduce the semantic snapshot from persisted canonical source evidence."""

    source = ModelRefreshSourceEvidence.model_validate(source_evidence.model_dump(mode="json"))
    registry = CandidateRegistry.model_validate(candidate_registry.model_dump(mode="json"))
    if source.candidate_registry_sha256 != registry.registry_sha256:
        raise ModelRefreshValidationError(
            "refresh source evidence binds a different candidate registry"
        )
    candidate_ids = tuple(candidate.exact_model_id for candidate in registry.candidates)
    source_candidate_ids = tuple(
        candidate.exact_model_id for candidate in source.candidate_endpoint_sets
    )
    if source_candidate_ids != tuple(sorted(candidate_ids)):
        raise ModelRefreshValidationError(
            "refresh source candidate endpoints do not exactly cover the registry"
        )
    return _build_model_refresh_snapshot_from_payloads(
        retrieved_at=source.retrieved_at,
        catalog_payload=_catalog_payload_from_source(source),
        zdr_payload=_zdr_payload_from_source(source),
        candidate_registry=registry,
        candidate_endpoint_payloads=_candidate_payloads_from_source(source),
        authenticated_metadata=source.authenticated_metadata,
        source_evidence_sha256=source.source_evidence_sha256,
    )


def build_model_refresh_snapshot(
    *,
    retrieved_at: datetime,
    catalog_payload: Mapping[str, Any],
    zdr_payload: Mapping[str, Any],
    candidate_registry: CandidateRegistry,
    candidate_endpoint_payloads: Mapping[str, Mapping[str, Any]],
    authenticated_metadata: bool,
) -> ModelRefreshSnapshot:
    """Normalize raw metadata through persisted-source semantics for compatibility."""

    source = build_model_refresh_source_evidence(
        retrieved_at=retrieved_at,
        catalog_payload=catalog_payload,
        zdr_payload=zdr_payload,
        candidate_registry=candidate_registry,
        candidate_endpoint_payloads=candidate_endpoint_payloads,
        authenticated_metadata=authenticated_metadata,
    )
    return build_model_refresh_snapshot_from_source(
        source_evidence=source,
        candidate_registry=candidate_registry,
    )


def _build_model_refresh_snapshot_from_payloads(
    *,
    retrieved_at: datetime,
    catalog_payload: Mapping[str, Any],
    zdr_payload: Mapping[str, Any],
    candidate_registry: CandidateRegistry,
    candidate_endpoint_payloads: Mapping[str, Mapping[str, Any]],
    authenticated_metadata: bool,
    source_evidence_sha256: str,
) -> ModelRefreshSnapshot:
    """Build a snapshot only from a canonical allowlisted source projection."""

    if authenticated_metadata is not True:
        raise ModelRefreshValidationError(
            "refresh snapshots require an authenticated metadata session"
        )
    retrieved_at = _whole_second_utc(retrieved_at, label="refresh retrieval time")
    registry = CandidateRegistry.model_validate(candidate_registry.model_dump(mode="json"))
    raw_models = _required_bounded_list(catalog_payload.get("data"), label="model catalogue")
    raw_zdr = _required_bounded_list(
        zdr_payload.get("data"),
        label="ZDR endpoint catalogue",
        allow_empty=True,
        maximum=_MAX_MODELS * 4,
    )
    catalog_by_id: dict[str, Mapping[str, Any]] = {}
    excluded: list[str] = []
    seen_catalog_ids: set[str] = set()
    for raw in raw_models:
        model_id = raw.get("id")
        if not isinstance(model_id, str) or not is_openrouter_catalog_model_id(model_id):
            raise ModelRefreshValidationError("model catalogue contains an invalid model ID")
        if model_id in seen_catalog_ids:
            raise ModelRefreshValidationError("model catalogue contains duplicate model IDs")
        seen_catalog_ids.add(model_id)
        if not is_exact_openrouter_model_id(model_id):
            excluded.append(model_id)
            continue
        catalog_by_id[model_id] = raw
    if not catalog_by_id:
        raise ModelRefreshValidationError("model catalogue contains no exact models")

    candidate_ids = tuple(candidate.exact_model_id for candidate in registry.candidates)
    if set(candidate_endpoint_payloads) != set(candidate_ids):
        raise ModelRefreshValidationError(
            "candidate endpoint payloads do not exactly cover the candidate registry"
        )

    raw_zdr_by_model: dict[str, list[Mapping[str, Any]]] = {}
    for raw in raw_zdr:
        model_id = raw.get("model_id")
        if not isinstance(model_id, str) or not is_openrouter_catalog_model_id(model_id):
            raise ModelRefreshValidationError("ZDR catalogue contains an invalid model ID")
        if not is_exact_openrouter_model_id(model_id):
            continue
        raw_zdr_by_model.setdefault(model_id, []).append(raw)

    zdr_routes_by_model: dict[str, tuple[_EndpointRouteInput, ...]] = {}
    zdr_alias_counts_by_model: dict[str, dict[str, int]] = {}
    zdr_by_identity: dict[tuple[str, _EndpointIdentityKey], _EndpointRouteInput] = {}
    for model_id, raw_routes in sorted(raw_zdr_by_model.items()):
        normalized, alias_counts = _normalize_endpoint_inventory(
            raw_routes,
            label="ZDR catalogue",
        )
        zdr_routes_by_model[model_id] = normalized
        zdr_alias_counts_by_model[model_id] = alias_counts
        for route in normalized:
            zdr_by_identity[(model_id, route.identity_key)] = route

    routes_by_model: dict[str, tuple[_EndpointRouteInput, ...]] = {
        model_id: routes
        for model_id, routes in zdr_routes_by_model.items()
        if model_id in catalog_by_id
    }
    candidates_by_id = {candidate.exact_model_id: candidate for candidate in registry.candidates}
    for model_id, envelope in candidate_endpoint_payloads.items():
        data = envelope.get("data")
        if not isinstance(data, Mapping) or data.get("id") != model_id:
            raise ModelRefreshValidationError(
                "candidate endpoint metadata changes exact model identity"
            )
        endpoints = _required_bounded_list(
            data.get("endpoints"),
            label="candidate endpoint catalogue",
            allow_empty=True,
            maximum=_MAX_ROUTES_PER_MODEL,
        )
        routes_by_model[model_id], _ = _normalize_endpoint_inventory(
            endpoints,
            label="candidate endpoint catalogue",
            preferred_endpoint=candidates_by_id[model_id].approved_provider_endpoint,
        )

    models: list[CatalogModelState] = []
    for model_id, raw_model in sorted(catalog_by_id.items()):
        model_parameters = _catalog_supported_parameters(raw_model.get("supported_parameters"))
        catalog_context_limit = _positive_integer(
            raw_model.get("context_length"),
            label="catalogue context limit",
        )
        top_provider = raw_model.get("top_provider")
        if top_provider is not None and not isinstance(top_provider, Mapping):
            raise ModelRefreshValidationError("catalogue top provider must be an object")
        context_value = (
            top_provider.get("context_length") if isinstance(top_provider, Mapping) else None
        )
        context_limit = (
            catalog_context_limit
            if context_value is None
            else _positive_integer(context_value, label="catalogue provider context limit")
        )
        context_limit_source: Literal["metadata", "catalog_context"] = (
            "catalog_context" if context_value is None else "metadata"
        )
        output_value = (
            top_provider.get("max_completion_tokens") if isinstance(top_provider, Mapping) else None
        )
        output_limit = (
            context_limit
            if output_value is None
            else _positive_integer(output_value, label="catalogue output limit")
        )
        output_limit_source: Literal["metadata", "provider_context"] = (
            "provider_context" if output_value is None else "metadata"
        )
        canonical_slug = raw_model.get("canonical_slug", model_id)
        if (
            not isinstance(canonical_slug, str)
            or not is_exact_openrouter_model_id(canonical_slug)
            or canonical_slug.split("/", 1)[0] != model_id.split("/", 1)[0]
        ):
            raise ModelRefreshValidationError("catalogue canonical model slug is invalid")
        route_states: list[ProviderRouteState] = []
        for route_input in routes_by_model.get(model_id, ()):
            zdr_counterpart = zdr_by_identity.get((model_id, route_input.identity_key))
            zdr_alias_count = zdr_alias_counts_by_model.get(model_id, {}).get(
                route_input.provider_endpoint,
                0,
            )
            route_states.append(
                _route_state_from_raw(
                    exact_model_id=model_id,
                    raw=route_input.raw,
                    model_supported_parameters=model_parameters,
                    provider_endpoint=route_input.provider_endpoint,
                    routing_identity_unambiguous=route_input.routing_identity_unambiguous,
                    zdr_eligible=(
                        zdr_counterpart is not None
                        and zdr_alias_count == 1
                        and _zdr_counterpart_matches(
                            exact_model_id=model_id,
                            provider_endpoint=route_input.provider_endpoint,
                            model_supported_parameters=model_parameters,
                            endpoint_raw=route_input.raw,
                            zdr_raw=zdr_counterpart.raw,
                            routing_identity_unambiguous=(route_input.routing_identity_unambiguous),
                        )
                    ),
                )
            )
        models.append(
            _seal_catalog_model_state(
                exact_model_id=model_id,
                canonical_model_slug=canonical_slug,
                catalog_context_limit=catalog_context_limit,
                context_limit=context_limit,
                context_limit_source=context_limit_source,
                output_limit=output_limit,
                output_limit_source=output_limit_source,
                supported_parameters=model_parameters,
                routes=tuple(route_states),
            )
        )

    values: dict[str, Any] = {
        "schema_version": "2.0",
        "retrieved_at": retrieved_at,
        "source_api_identity": "https://openrouter.ai/api/v1",
        "authenticated_metadata": authenticated_metadata,
        "candidate_registry_sha256": registry.registry_sha256,
        "source_evidence_sha256": source_evidence_sha256,
        "catalog_snapshot_sha256": _canonical_sha256(catalog_payload),
        "zdr_snapshot_sha256": _canonical_sha256(zdr_payload),
        "catalog_model_count": len(raw_models),
        "excluded_routed_model_ids": sorted(excluded),
        "models": [model.model_dump(mode="json") for model in models],
        "semantic_sha256": _canonical_sha256([model.model_dump(mode="json") for model in models]),
    }
    values["snapshot_sha256"] = _canonical_sha256(values)
    return ModelRefreshSnapshot.model_validate(values)


def _catalog_source_from_raw(
    *,
    model_id: str,
    raw: Mapping[str, Any],
) -> ModelRefreshCatalogSource:
    parameters = _catalog_supported_parameters(raw.get("supported_parameters"))
    catalog_context = _positive_integer(
        raw.get("context_length"),
        label="catalogue context limit",
    )
    top_provider = raw.get("top_provider")
    if top_provider is not None and not isinstance(top_provider, Mapping):
        raise ModelRefreshValidationError("catalogue top provider must be an object")
    provider_context_value = (
        top_provider.get("context_length") if isinstance(top_provider, Mapping) else None
    )
    provider_output_value = (
        top_provider.get("max_completion_tokens") if isinstance(top_provider, Mapping) else None
    )
    provider_context = (
        None
        if provider_context_value is None
        else _positive_integer(
            provider_context_value,
            label="catalogue provider context limit",
        )
    )
    provider_output = (
        None
        if provider_output_value is None
        else _positive_integer(
            provider_output_value,
            label="catalogue output limit",
        )
    )
    canonical_slug = raw.get("canonical_slug", model_id)
    if (
        not isinstance(canonical_slug, str)
        or not is_exact_openrouter_model_id(canonical_slug)
        or canonical_slug.split("/", 1)[0] != model_id.split("/", 1)[0]
    ):
        raise ModelRefreshValidationError("catalogue canonical model slug is invalid")
    try:
        return ModelRefreshCatalogSource(
            exact_model_id=model_id,
            canonical_model_slug=canonical_slug,
            catalog_context_length=catalog_context,
            provider_context_length=provider_context,
            provider_max_completion_tokens=provider_output,
            supported_parameters=parameters,
        )
    except ValueError as exc:
        raise ModelRefreshValidationError("catalogue source projection is invalid") from exc


def _endpoint_source_from_raw(
    *,
    exact_model_id: str,
    raw: Mapping[str, Any],
) -> ModelRefreshEndpointSource:
    item_model_id = raw.get("model_id")
    if item_model_id is not None and item_model_id != exact_model_id:
        raise ModelRefreshValidationError(
            "endpoint record is not bound to the exact requested model"
        )
    identity = _endpoint_identity_projection(raw)
    _operational, normalized_status = _operational_status(raw.get("status"))
    raw_status = raw.get("status")
    status: int | str = raw_status if isinstance(raw_status, int) else normalized_status
    context, prompt, prompt_source, output, output_source = _endpoint_token_limits(raw)
    parameters = _endpoint_supported_parameters(raw.get("supported_parameters"))
    pricing = _canonical_pricing(raw.get("pricing"))
    try:
        return ModelRefreshEndpointSource(
            exact_model_id=exact_model_id,
            endpoint_tag=identity["tag"],
            endpoint_slug=identity["slug"],
            provider_name=identity["provider_name"],
            status=status,
            context_length=context,
            max_prompt_tokens=None if prompt_source == "context_limit" else prompt,
            max_completion_tokens=None if output_source == "context_limit" else output,
            supported_parameters=parameters,
            pricing=pricing,
        )
    except ValueError as exc:
        raise ModelRefreshValidationError("endpoint source projection is invalid") from exc


def _endpoint_source_sort_key(
    endpoint: ModelRefreshEndpointSource,
) -> tuple[str, str, str]:
    return (
        endpoint.exact_model_id,
        endpoint.endpoint_tag or "",
        endpoint.endpoint_slug or "",
    )


def _catalog_source_payload(source: ModelRefreshCatalogSource) -> dict[str, Any]:
    return {
        "id": source.exact_model_id,
        "canonical_slug": source.canonical_model_slug,
        "context_length": source.catalog_context_length,
        "top_provider": {
            "context_length": source.provider_context_length,
            "max_completion_tokens": source.provider_max_completion_tokens,
        },
        "supported_parameters": list(source.supported_parameters),
    }


def _endpoint_source_payload(source: ModelRefreshEndpointSource) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model_id": source.exact_model_id,
        "provider_name": source.provider_name,
        "status": source.status,
        "context_length": source.context_length,
        "max_prompt_tokens": source.max_prompt_tokens,
        "max_completion_tokens": source.max_completion_tokens,
        "supported_parameters": list(source.supported_parameters),
        "pricing": dict(source.pricing),
    }
    if source.endpoint_tag is not None:
        payload["tag"] = source.endpoint_tag
    if source.endpoint_slug is not None:
        payload["slug"] = source.endpoint_slug
    return payload


def _catalog_payload_from_parts(
    *,
    catalog_models: Sequence[ModelRefreshCatalogSource],
    excluded_routed_model_ids: Sequence[str],
) -> dict[str, Any]:
    data = [
        *(_catalog_source_payload(model) for model in catalog_models),
        *({"id": model_id} for model_id in excluded_routed_model_ids),
    ]
    return {"data": sorted(data, key=lambda item: str(item["id"]))}


def _zdr_payload_from_parts(
    *,
    zdr_endpoints: Sequence[ModelRefreshEndpointSource],
    excluded_zdr_routed_models: Sequence[ExcludedZdrRoutedModelSource],
) -> dict[str, Any]:
    data = [_endpoint_source_payload(endpoint) for endpoint in zdr_endpoints]
    for excluded in excluded_zdr_routed_models:
        data.extend({"model_id": excluded.model_id} for _index in range(excluded.occurrence_count))
    return {
        "data": sorted(
            data,
            key=lambda item: (
                str(item["model_id"]),
                str(item.get("tag") or ""),
                str(item.get("slug") or ""),
            ),
        )
    }


def _candidate_payloads_from_parts(
    *,
    candidate_endpoint_sets: Sequence[ModelRefreshCandidateEndpointSource],
) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for endpoint_set in candidate_endpoint_sets:
        endpoints: list[dict[str, Any]] = []
        for endpoint in endpoint_set.endpoints:
            payload = _endpoint_source_payload(endpoint)
            payload.pop("model_id")
            endpoints.append(payload)
        result[endpoint_set.exact_model_id] = {
            "data": {
                "id": endpoint_set.exact_model_id,
                "endpoints": endpoints,
            }
        }
    return result


def _catalog_payload_from_source(
    source: ModelRefreshSourceEvidence,
) -> dict[str, Any]:
    return _catalog_payload_from_parts(
        catalog_models=source.catalog_models,
        excluded_routed_model_ids=source.excluded_routed_model_ids,
    )


def _zdr_payload_from_source(
    source: ModelRefreshSourceEvidence,
) -> dict[str, Any]:
    return _zdr_payload_from_parts(
        zdr_endpoints=source.zdr_endpoints,
        excluded_zdr_routed_models=source.excluded_zdr_routed_models,
    )


def _candidate_payloads_from_source(
    source: ModelRefreshSourceEvidence,
) -> dict[str, Mapping[str, Any]]:
    return _candidate_payloads_from_parts(candidate_endpoint_sets=source.candidate_endpoint_sets)


def diff_model_refresh(
    *,
    current: ModelRefreshSnapshot,
    candidate_registry: CandidateRegistry,
    pricing_tolerance_fraction: str,
    compared_at: datetime,
    previous: ModelRefreshSnapshot | None = None,
    selected_routes: Sequence[SelectedModelRoute] = (),
) -> ModelRefreshDiff:
    """Compare exact normalized state without treating discovery as qualification."""

    current = ModelRefreshSnapshot.model_validate(current.model_dump(mode="json"))
    registry = CandidateRegistry.model_validate(candidate_registry.model_dump(mode="json"))
    if current.candidate_registry_sha256 != registry.registry_sha256:
        raise ModelRefreshValidationError("refresh snapshot binds a different candidate registry")
    tolerance = _canonical_fraction(pricing_tolerance_fraction)
    if tolerance > 1:
        raise ModelRefreshValidationError("refresh pricing tolerance cannot exceed one")
    compared_at = _whole_second_utc(compared_at, label="refresh comparison time")
    if compared_at != current.retrieved_at:
        raise ModelRefreshValidationError(
            "refresh comparison time must equal the current snapshot retrieval time"
        )
    selected = tuple(
        sorted(
            (
                SelectedModelRoute.model_validate(route.model_dump(mode="json"))
                for route in selected_routes
            ),
            key=lambda route: (route.exact_model_id, route.provider_endpoint),
        )
    )
    if len(selected) != len(
        {(route.exact_model_id, route.provider_endpoint) for route in selected}
    ):
        raise ModelRefreshValidationError("refresh selected routes contain duplicates")
    selected_by_model: dict[str, set[str]] = {}
    registry_by_model = {candidate.exact_model_id: candidate for candidate in registry.candidates}
    for selected_route in selected:
        candidate = registry_by_model.get(selected_route.exact_model_id)
        if (
            candidate is None
            or candidate.approved_provider_endpoint != selected_route.provider_endpoint
        ):
            raise ModelRefreshValidationError(
                "refresh selected route is absent from the frozen candidate registry"
            )
        selected_by_model.setdefault(selected_route.exact_model_id, set()).add(
            selected_route.provider_endpoint
        )

    exact_previous_snapshot = previous is not None
    if previous is None:
        baseline_kind = RefreshBaselineKind.CANDIDATE_REGISTRY_HASH_ONLY
        baseline_sha256 = registry.registry_sha256
        before_models = _candidate_baseline_models(registry)
    else:
        previous = ModelRefreshSnapshot.model_validate(previous.model_dump(mode="json"))
        if previous.candidate_registry_sha256 != registry.registry_sha256:
            raise ModelRefreshValidationError(
                "previous refresh snapshot binds a different candidate registry"
            )
        if previous.retrieved_at > current.retrieved_at:
            raise ModelRefreshValidationError(
                "previous refresh snapshot is newer than the current snapshot"
            )
        baseline_kind = RefreshBaselineKind.PREVIOUS_SNAPSHOT
        baseline_sha256 = previous.snapshot_sha256
        before_models = {model.exact_model_id: model for model in previous.models}
    after_models = {model.exact_model_id: model for model in current.models}
    baseline_variant_keys = {model.variant_family_key for model in before_models.values()}

    changes: list[ModelDriftRecord] = []
    blockers: list[str] = []
    for model_id in sorted(set(before_models) | set(after_models)):
        before = before_models.get(model_id)
        after = after_models.get(model_id)
        kinds: set[ModelDriftKind] = set()
        pricing_state = PricingComparisonState.NOT_APPLICABLE
        increase_fields: set[str] = set()
        selected_endpoints = selected_by_model.get(model_id, set())
        selected_model = bool(selected_endpoints)

        if before is None:
            assert after is not None
            if after.eligible_provider_endpoints:
                kinds.add(ModelDriftKind.NEW_ELIGIBLE_MODEL)
            kinds.add(ModelDriftKind.LINEAGE_REVIEW_REQUIRED)
        elif after is None:
            kinds.add(ModelDriftKind.WITHDRAWN_MODEL)
        else:
            if before.canonical_model_slug != after.canonical_model_slug:
                kinds.add(ModelDriftKind.MODEL_IDENTITY_CHANGED)
            if exact_previous_snapshot:
                if (
                    before.catalog_context_limit != after.catalog_context_limit
                    or before.context_limit != after.context_limit
                    or before.context_limit_source != after.context_limit_source
                ):
                    kinds.add(ModelDriftKind.CONTEXT_LIMIT_CHANGED)
                if (
                    before.output_limit != after.output_limit
                    or before.output_limit_source != after.output_limit_source
                ):
                    kinds.add(ModelDriftKind.OUTPUT_LIMIT_CHANGED)
                if (
                    before.structured_output_supported != after.structured_output_supported
                    or before.supported_output_modes != after.supported_output_modes
                    or before.structured_output_mode is not after.structured_output_mode
                ):
                    kinds.add(ModelDriftKind.STRUCTURED_OUTPUT_SUPPORT_CHANGED)
                if before.reasoning_supported != after.reasoning_supported:
                    kinds.add(ModelDriftKind.REASONING_SUPPORT_CHANGED)
                if before.supported_parameters != after.supported_parameters:
                    kinds.add(ModelDriftKind.ENDPOINT_AVAILABILITY_CHANGED)
            before_routes = {route.provider_endpoint: route for route in before.routes}
            after_routes = {route.provider_endpoint: route for route in after.routes}
            if set(before_routes) != set(after_routes):
                kinds.add(ModelDriftKind.ENDPOINT_AVAILABILITY_CHANGED)
            common_endpoints = sorted(set(before_routes) & set(after_routes))
            if any(
                (
                    before_routes[endpoint].provider_name,
                    before_routes[endpoint].routing_identity_unambiguous,
                    before_routes[endpoint].operational,
                )
                != (
                    after_routes[endpoint].provider_name,
                    after_routes[endpoint].routing_identity_unambiguous,
                    after_routes[endpoint].operational,
                )
                for endpoint in common_endpoints
            ) or (
                exact_previous_snapshot
                and any(
                    before_routes[endpoint].supported_parameters
                    != after_routes[endpoint].supported_parameters
                    for endpoint in common_endpoints
                )
            ):
                kinds.add(ModelDriftKind.ENDPOINT_AVAILABILITY_CHANGED)
            if exact_previous_snapshot and any(
                before_routes[endpoint].operational_status
                != after_routes[endpoint].operational_status
                for endpoint in common_endpoints
            ):
                kinds.add(ModelDriftKind.ENDPOINT_AVAILABILITY_CHANGED)
            if exact_previous_snapshot and any(
                (
                    before_routes[endpoint].endpoint_tag,
                    before_routes[endpoint].endpoint_slug,
                )
                != (
                    after_routes[endpoint].endpoint_tag,
                    after_routes[endpoint].endpoint_slug,
                )
                for endpoint in common_endpoints
            ):
                kinds.add(ModelDriftKind.ENDPOINT_IDENTITY_CHANGED)
            if any(
                (
                    before_routes[endpoint].context_limit != after_routes[endpoint].context_limit
                    or (
                        before_routes[endpoint].max_prompt_tokens is not None
                        and before_routes[endpoint].max_prompt_tokens
                        != after_routes[endpoint].max_prompt_tokens
                    )
                    or (
                        before_routes[endpoint].max_prompt_tokens_source is not None
                        and before_routes[endpoint].max_prompt_tokens_source
                        != after_routes[endpoint].max_prompt_tokens_source
                    )
                )
                for endpoint in common_endpoints
            ):
                kinds.add(ModelDriftKind.CONTEXT_LIMIT_CHANGED)
            if any(
                (
                    before_routes[endpoint].output_limit != after_routes[endpoint].output_limit
                    or (
                        before_routes[endpoint].output_limit_source is not None
                        and before_routes[endpoint].output_limit_source
                        != after_routes[endpoint].output_limit_source
                    )
                )
                for endpoint in common_endpoints
            ):
                kinds.add(ModelDriftKind.OUTPUT_LIMIT_CHANGED)
            if (
                exact_previous_snapshot
                and any(
                    (
                        before_routes[endpoint].structured_output_supported
                        != after_routes[endpoint].structured_output_supported
                        or before_routes[endpoint].supported_output_modes
                        != after_routes[endpoint].supported_output_modes
                        or before_routes[endpoint].structured_output_mode
                        is not after_routes[endpoint].structured_output_mode
                    )
                    for endpoint in common_endpoints
                )
            ) or (
                not exact_previous_snapshot
                and any(
                    before_routes[endpoint].structured_output_mode is not None
                    and before_routes[endpoint].structured_output_mode
                    not in after_routes[endpoint].supported_output_modes
                    for endpoint in common_endpoints
                )
            ):
                kinds.add(ModelDriftKind.STRUCTURED_OUTPUT_SUPPORT_CHANGED)
            if any(
                (
                    before_routes[endpoint].reasoning_supported
                    != after_routes[endpoint].reasoning_supported
                    if exact_previous_snapshot
                    else (
                        before_routes[endpoint].reasoning_supported
                        and not after_routes[endpoint].reasoning_supported
                    )
                )
                for endpoint in common_endpoints
            ):
                kinds.add(ModelDriftKind.REASONING_SUPPORT_CHANGED)
            if any(
                before_routes[endpoint].zdr_eligible != after_routes[endpoint].zdr_eligible
                for endpoint in common_endpoints
            ):
                kinds.add(ModelDriftKind.ZDR_ELIGIBILITY_CHANGED)
            pricing_state, pricing_changed, increase_fields = _compare_model_pricing(
                before_routes=before_routes,
                after_routes=after_routes,
                tolerance=tolerance,
            )
            if pricing_changed:
                kinds.add(ModelDriftKind.PRICING_CHANGED)

        production_blocking = False
        if selected_model:
            candidate = registry_by_model[model_id]
            if after is None:
                production_blocking = True
                kinds.add(ModelDriftKind.ENDPOINT_AVAILABILITY_CHANGED)
                blockers.extend(f"{model_id}={endpoint}" for endpoint in selected_endpoints)
            else:
                after_routes = {route.provider_endpoint: route for route in after.routes}
                before_routes = (
                    {}
                    if before is None
                    else {route.provider_endpoint: route for route in before.routes}
                )
                for endpoint in selected_endpoints:
                    observed_route = after_routes.get(endpoint)
                    frozen_price_changed = (
                        observed_route is not None
                        and observed_route.pricing_sha256 != candidate.pricing_snapshot_sha256
                    )
                    prior_route = before_routes.get(endpoint)
                    frozen_price_baseline_is_exact = (
                        prior_route is not None
                        and prior_route.pricing is not None
                        and prior_route.pricing_sha256 == candidate.pricing_snapshot_sha256
                    )
                    capability_evidence_missing = (
                        candidate.structured_output_mode is None
                        or candidate.output_capability_sha256 is None
                    )
                    output_source_missing = candidate.output_limit_source is None
                    prompt_evidence_missing = (
                        candidate.max_prompt_tokens is None
                        or candidate.max_prompt_tokens_source is None
                    )
                    mode_blocked = (
                        observed_route is not None
                        and candidate.structured_output_mode is not None
                        and candidate.structured_output_mode
                        not in mutually_supported_output_modes(
                            (after.supported_parameters, observed_route.supported_parameters)
                        )
                    )
                    prompt_blocked = observed_route is not None and (
                        observed_route.max_prompt_tokens is None
                        or (
                            candidate.max_prompt_tokens is not None
                            and observed_route.max_prompt_tokens < candidate.max_prompt_tokens
                        )
                    )
                    prompt_source_changed = (
                        observed_route is not None
                        and candidate.max_prompt_tokens_source is not None
                        and observed_route.max_prompt_tokens_source
                        != candidate.max_prompt_tokens_source
                    )
                    output_source_changed = (
                        observed_route is not None
                        and candidate.output_limit_source is not None
                        and observed_route.output_limit_source != candidate.output_limit_source
                    )
                    endpoint_identity_unverified = not exact_previous_snapshot
                    if capability_evidence_missing or mode_blocked:
                        kinds.add(ModelDriftKind.STRUCTURED_OUTPUT_SUPPORT_CHANGED)
                    if prompt_evidence_missing or prompt_blocked or prompt_source_changed:
                        kinds.add(ModelDriftKind.CONTEXT_LIMIT_CHANGED)
                    if output_source_missing or output_source_changed:
                        kinds.add(ModelDriftKind.OUTPUT_LIMIT_CHANGED)
                    if endpoint_identity_unverified:
                        kinds.add(ModelDriftKind.ENDPOINT_IDENTITY_UNVERIFIED)
                    route_blocked = (
                        observed_route is None
                        or not observed_route.operational
                        or not observed_route.zdr_eligible
                        or not observed_route.discovery_eligible
                        or observed_route.provider_name != candidate.approved_provider_name
                        or after.canonical_model_slug != candidate.canonical_model_slug
                        or capability_evidence_missing
                        or output_source_missing
                        or prompt_evidence_missing
                        or mode_blocked
                        or prompt_source_changed
                        or output_source_changed
                        or endpoint_identity_unverified
                        or (
                            candidate.reasoning_supported
                            and (
                                not after.reasoning_supported
                                or not observed_route.reasoning_supported
                            )
                        )
                        or observed_route.context_limit < candidate.context_size
                        or prompt_blocked
                        or observed_route.output_limit < candidate.output_limit
                        or (
                            exact_previous_snapshot
                            and prior_route is not None
                            and (
                                prior_route.endpoint_tag,
                                prior_route.endpoint_slug,
                            )
                            != (
                                observed_route.endpoint_tag,
                                observed_route.endpoint_slug,
                            )
                        )
                        or (frozen_price_changed and not frozen_price_baseline_is_exact)
                        or endpoint
                        in _endpoints_with_pricing_increase(
                            before=before,
                            after=after,
                            tolerance=tolerance,
                        )
                        or (
                            pricing_state is PricingComparisonState.NOT_EVALUABLE
                            and ModelDriftKind.PRICING_CHANGED in kinds
                        )
                    )
                    if route_blocked:
                        production_blocking = True
                        blockers.append(f"{model_id}={endpoint}")
                    if observed_route is None or not observed_route.discovery_eligible:
                        kinds.add(ModelDriftKind.ENDPOINT_AVAILABILITY_CHANGED)
        if not kinds:
            continue
        lineage_review_required = ModelDriftKind.LINEAGE_REVIEW_REQUIRED in kinds
        if (
            before is None
            and after is not None
            and after.variant_family_key in baseline_variant_keys
        ):
            lineage_review_required = True
            kinds.add(ModelDriftKind.LINEAGE_REVIEW_REQUIRED)
        record_values: dict[str, Any] = {
            "exact_model_id": model_id,
            "change_kinds": [kind.value for kind in sorted(kinds, key=lambda item: item.value)],
            "before": before.model_dump(mode="json") if before is not None else None,
            "after": after.model_dump(mode="json") if after is not None else None,
            "pricing_comparison": pricing_state.value,
            "pricing_increase_fields": sorted(increase_fields),
            "production_selected": selected_model,
            "production_blocking": production_blocking,
            "lineage_review_required": lineage_review_required,
        }
        record_values["record_sha256"] = _canonical_sha256(record_values)
        changes.append(ModelDriftRecord.model_validate(record_values))

    status = (
        ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
        if blockers
        else (
            ModelRefreshAttemptStatus.UNCHANGED
            if not changes
            else ModelRefreshAttemptStatus.CHANGED
        )
    )
    values: dict[str, Any] = {
        "schema_version": "2.0",
        "compared_at": compared_at,
        "baseline_kind": baseline_kind.value,
        "baseline_sha256": baseline_sha256,
        "current_snapshot_sha256": current.snapshot_sha256,
        "candidate_registry_sha256": registry.registry_sha256,
        "pricing_tolerance_fraction": pricing_tolerance_fraction,
        "selected_routes": [route.model_dump(mode="json") for route in selected],
        "changes": [record.model_dump(mode="json") for record in changes],
        "semantic_unchanged": not changes,
        "status": status.value,
        "production_block_reasons": sorted(set(blockers)),
    }
    values["diff_sha256"] = _canonical_sha256(values)
    return ModelRefreshDiff.model_validate(values)


def seal_model_refresh_attempt(
    *,
    attempted_at: datetime,
    candidate_registry_sha256: str,
    diff: ModelRefreshDiff | None = None,
    snapshot: ModelRefreshSnapshot | None = None,
    failure_code: ModelRefreshFailureCode | None = None,
) -> ModelRefreshAttempt:
    """Seal exactly one terminal success or typed failure."""

    attempted_at = _whole_second_utc(attempted_at, label="refresh attempt time")
    if failure_code is not None:
        status = ModelRefreshAttemptStatus.FAILED
        snapshot_sha256 = None
        diff_sha256 = None
    else:
        if snapshot is None or diff is None:
            raise ModelRefreshValidationError(
                "successful refresh attempt requires snapshot and diff"
            )
        if snapshot.candidate_registry_sha256 != candidate_registry_sha256 or (
            diff.current_snapshot_sha256 != snapshot.snapshot_sha256
        ):
            raise ModelRefreshValidationError("refresh attempt snapshot and diff bindings disagree")
        status = diff.status
        snapshot_sha256 = snapshot.snapshot_sha256
        diff_sha256 = diff.diff_sha256
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "attempted_at": attempted_at,
        "candidate_registry_sha256": candidate_registry_sha256,
        "status": status.value,
        "snapshot_sha256": snapshot_sha256,
        "diff_sha256": diff_sha256,
        "failure_code": failure_code.value if failure_code is not None else None,
    }
    values["attempt_sha256"] = _canonical_sha256(values)
    return ModelRefreshAttempt.model_validate(values)


def evaluate_model_refresh_freshness(
    *,
    observed_at: datetime,
    snapshot: ModelRefreshSnapshot | None,
    soft_max_age_hours: int,
    hard_max_age_hours: int,
    production_selection_present: bool,
) -> ModelRefreshFreshness:
    """Evaluate exact soft/hard boundaries without granting positive authority."""

    observed_at = _whole_second_utc(observed_at, label="refresh freshness observation")
    if (
        isinstance(soft_max_age_hours, bool)
        or isinstance(hard_max_age_hours, bool)
        or not isinstance(soft_max_age_hours, int)
        or not isinstance(hard_max_age_hours, int)
        or soft_max_age_hours < 1
        or hard_max_age_hours <= soft_max_age_hours
    ):
        raise ModelRefreshValidationError("refresh freshness hours are invalid")
    last_success = snapshot.retrieved_at if snapshot is not None else None
    snapshot_sha256 = snapshot.snapshot_sha256 if snapshot is not None else None
    if last_success is None:
        state = ModelRefreshFreshnessState.NO_SUCCESS
    else:
        age = observed_at - last_success
        if age < timedelta(0):
            raise ModelRefreshValidationError("refresh snapshot is future-dated")
        state = (
            ModelRefreshFreshnessState.HARD_EXPIRED
            if age > timedelta(hours=hard_max_age_hours)
            else (
                ModelRefreshFreshnessState.STALE
                if age > timedelta(hours=soft_max_age_hours)
                else ModelRefreshFreshnessState.CURRENT
            )
        )
    production_blocked = production_selection_present and state in {
        ModelRefreshFreshnessState.HARD_EXPIRED,
        ModelRefreshFreshnessState.NO_SUCCESS,
    }
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "observed_at": observed_at,
        "last_success_retrieved_at": last_success,
        "snapshot_sha256": snapshot_sha256,
        "soft_max_age_hours": soft_max_age_hours,
        "hard_max_age_hours": hard_max_age_hours,
        "state": state.value,
        "production_selection_present": production_selection_present,
        "production_blocked": production_blocked,
    }
    values["freshness_sha256"] = _canonical_sha256(values)
    return ModelRefreshFreshness.model_validate(values)


def write_model_refresh_success(
    output_dir: Path,
    *,
    source_evidence: ModelRefreshSourceEvidence,
    snapshot: ModelRefreshSnapshot,
    diff: ModelRefreshDiff,
    attempt: ModelRefreshAttempt,
    freshness: ModelRefreshFreshness,
) -> None:
    """Create a fresh private exact-inventory success directory."""

    if attempt.status is ModelRefreshAttemptStatus.FAILED:
        raise ModelRefreshValidationError("failed attempt cannot enter a success bundle")
    if (
        source_evidence.source_evidence_sha256 != snapshot.source_evidence_sha256
        or source_evidence.retrieved_at != snapshot.retrieved_at
        or source_evidence.source_api_identity != snapshot.source_api_identity
        or source_evidence.authenticated_metadata is not snapshot.authenticated_metadata
        or source_evidence.candidate_registry_sha256 != snapshot.candidate_registry_sha256
        or source_evidence.catalog_projection_sha256 != snapshot.catalog_snapshot_sha256
        or source_evidence.zdr_projection_sha256 != snapshot.zdr_snapshot_sha256
        or attempt.snapshot_sha256 != snapshot.snapshot_sha256
        or attempt.diff_sha256 != diff.diff_sha256
        or diff.current_snapshot_sha256 != snapshot.snapshot_sha256
        or freshness.snapshot_sha256 != snapshot.snapshot_sha256
    ):
        raise ModelRefreshValidationError("refresh success artifacts are not hash-bound")
    root = _create_private_output_directory(output_dir)
    try:
        _write_private_artifact(root / SOURCE_EVIDENCE_FILENAME, source_evidence)
        _write_private_artifact(root / SNAPSHOT_FILENAME, snapshot)
        _write_private_artifact(root / DIFF_FILENAME, diff)
        _write_private_artifact(root / ATTEMPT_FILENAME, attempt)
        _write_private_artifact(root / FRESHNESS_FILENAME, freshness)
    except Exception:
        _remove_fresh_output(root)
        raise


def write_model_refresh_failure(
    output_dir: Path,
    *,
    attempt: ModelRefreshAttempt,
) -> None:
    """Create a fresh private failure directory containing only the attempt."""

    if attempt.status is not ModelRefreshAttemptStatus.FAILED:
        raise ModelRefreshValidationError("failure output requires a failed attempt")
    root = _create_private_output_directory(output_dir)
    try:
        _write_private_artifact(root / ATTEMPT_FILENAME, attempt)
    except Exception:
        _remove_fresh_output(root)
        raise


def load_model_refresh_snapshot(path: Path) -> ModelRefreshSnapshot:
    return _load_private_artifact(path, ModelRefreshSnapshot)


def load_model_refresh_source_evidence(path: Path) -> ModelRefreshSourceEvidence:
    return _load_private_artifact(path, ModelRefreshSourceEvidence)


def load_model_refresh_diff(path: Path) -> ModelRefreshDiff:
    return _load_private_artifact(path, ModelRefreshDiff)


def load_model_refresh_attempt(path: Path) -> ModelRefreshAttempt:
    return _load_private_artifact(path, ModelRefreshAttempt)


def load_model_refresh_freshness(path: Path) -> ModelRefreshFreshness:
    return _load_private_artifact(path, ModelRefreshFreshness)


def _candidate_baseline_models(
    registry: CandidateRegistry,
) -> dict[str, CatalogModelState]:
    result: dict[str, CatalogModelState] = {}
    for candidate in registry.candidates:
        operational = candidate.operational_status is CandidateOperationalStatus.AVAILABLE
        parameters = _candidate_baseline_parameters(candidate)
        route = _seal_route_state(
            exact_model_id=candidate.exact_model_id,
            provider_endpoint=candidate.approved_provider_endpoint,
            endpoint_tag=candidate.approved_provider_endpoint,
            endpoint_slug=None,
            provider_name=candidate.approved_provider_name,
            routing_identity_unambiguous=True,
            operational=operational,
            operational_status=("operational" if operational else "unavailable"),
            zdr_eligible=candidate.zdr_eligible,
            context_limit=candidate.context_size,
            max_prompt_tokens=candidate.max_prompt_tokens,
            max_prompt_tokens_source=candidate.max_prompt_tokens_source,
            output_limit=candidate.output_limit,
            output_limit_source=candidate.output_limit_source,
            supported_parameters=parameters,
            model_supported_parameters=parameters,
            structured_output_mode=candidate.structured_output_mode,
            pricing_observation=PricingObservationKind.HASH_ONLY,
            pricing=None,
            pricing_sha256=candidate.pricing_snapshot_sha256,
        )
        result[candidate.exact_model_id] = _seal_catalog_model_state(
            exact_model_id=candidate.exact_model_id,
            canonical_model_slug=candidate.canonical_model_slug,
            catalog_context_limit=candidate.context_size,
            context_limit=candidate.context_size,
            context_limit_source="candidate_registry",
            output_limit=candidate.output_limit,
            output_limit_source="candidate_registry",
            supported_parameters=parameters,
            routes=(route,),
            structured_output_mode=candidate.structured_output_mode,
        )
    return result


def _candidate_baseline_parameters(candidate: CandidateModel) -> tuple[str, ...]:
    parameters = {"max_tokens", "temperature"}
    if candidate.reasoning_supported:
        parameters.add("reasoning")
    mode = candidate.structured_output_mode
    if mode is StructuredOutputMode.NATIVE_JSON_SCHEMA:
        parameters.update({"json_schema", "response_format"})
    elif mode is StructuredOutputMode.JSON_OBJECT:
        parameters.add("response_format")
    elif mode is None and candidate.structured_output_supported:
        # Legacy hash-only candidates prove provider-structured output only as a
        # boolean. The selected-route gate still rejects the missing exact mode.
        parameters.add("response_format")
    if mode is not None and candidate.structured_output_supported is not (
        mode is not StructuredOutputMode.VALIDATED_TEXT_JSON
    ):
        raise ModelRefreshValidationError(
            "candidate structured-output boolean differs from its exact mode"
        )
    return tuple(sorted(parameters))


def _route_state_from_raw(
    *,
    exact_model_id: str,
    raw: Mapping[str, Any],
    model_supported_parameters: tuple[str, ...],
    provider_endpoint: str,
    routing_identity_unambiguous: bool,
    zdr_eligible: bool,
) -> ProviderRouteState:
    item_model_id = raw.get("model_id")
    if item_model_id is not None and item_model_id != exact_model_id:
        raise ModelRefreshValidationError(
            "endpoint record is not bound to the exact requested model"
        )
    identity = _endpoint_identity_projection(raw)
    endpoint_tag = identity["tag"]
    endpoint_slug = identity["slug"]
    provider_name = identity["provider_name"]
    assert isinstance(provider_name, str)
    if provider_endpoint not in {endpoint_tag, endpoint_slug}:
        raise ModelRefreshValidationError(
            "normalized route selector differs from the endpoint tag and slug"
        )
    operational, operational_status = _operational_status(raw.get("status"))
    (
        context,
        max_prompt_tokens,
        max_prompt_tokens_source,
        output,
        output_limit_source,
    ) = _endpoint_token_limits(raw)
    route_parameters = _endpoint_supported_parameters(raw.get("supported_parameters"))
    pricing = _canonical_pricing(raw.get("pricing"))
    effective_modes = mutually_supported_output_modes(
        (model_supported_parameters, route_parameters)
    )
    return _seal_route_state(
        exact_model_id=exact_model_id,
        provider_endpoint=provider_endpoint,
        endpoint_tag=endpoint_tag,
        endpoint_slug=endpoint_slug,
        provider_name=provider_name,
        routing_identity_unambiguous=routing_identity_unambiguous,
        operational=operational,
        operational_status=operational_status,
        zdr_eligible=zdr_eligible,
        context_limit=context,
        max_prompt_tokens=max_prompt_tokens,
        max_prompt_tokens_source=max_prompt_tokens_source,
        output_limit=output,
        output_limit_source=output_limit_source,
        supported_parameters=route_parameters,
        model_supported_parameters=model_supported_parameters,
        structured_output_mode=effective_modes[0],
        pricing_observation=PricingObservationKind.EXACT,
        pricing=pricing,
        pricing_sha256=_canonical_sha256(pricing),
    )


def _zdr_counterpart_matches(
    *,
    exact_model_id: str,
    provider_endpoint: str,
    model_supported_parameters: tuple[str, ...],
    endpoint_raw: Mapping[str, Any],
    zdr_raw: Mapping[str, Any],
    routing_identity_unambiguous: bool,
) -> bool:
    """Grant ZDR only when both authenticated endpoint records agree exactly."""

    endpoint = _route_state_from_raw(
        exact_model_id=exact_model_id,
        raw=endpoint_raw,
        model_supported_parameters=model_supported_parameters,
        provider_endpoint=provider_endpoint,
        routing_identity_unambiguous=routing_identity_unambiguous,
        zdr_eligible=False,
    )
    counterpart = _route_state_from_raw(
        exact_model_id=exact_model_id,
        raw=zdr_raw,
        model_supported_parameters=model_supported_parameters,
        provider_endpoint=provider_endpoint,
        routing_identity_unambiguous=routing_identity_unambiguous,
        zdr_eligible=False,
    )
    return endpoint.route_sha256 == counterpart.route_sha256


def _seal_route_state(
    *,
    exact_model_id: str,
    provider_endpoint: str,
    endpoint_tag: str | None,
    endpoint_slug: str | None,
    provider_name: str,
    routing_identity_unambiguous: bool,
    operational: bool,
    operational_status: str,
    zdr_eligible: bool,
    context_limit: int,
    max_prompt_tokens: int | None,
    max_prompt_tokens_source: Literal["metadata", "context_limit"] | None,
    output_limit: int,
    output_limit_source: Literal["metadata", "context_limit"] | None,
    supported_parameters: tuple[str, ...],
    model_supported_parameters: tuple[str, ...],
    structured_output_mode: StructuredOutputMode | None,
    pricing_observation: PricingObservationKind,
    pricing: dict[str, str] | None,
    pricing_sha256: str,
) -> ProviderRouteState:
    values: dict[str, Any] = {
        "schema_version": "2.0",
        "exact_model_id": exact_model_id,
        "provider_endpoint": provider_endpoint,
        "endpoint_tag": endpoint_tag,
        "endpoint_slug": endpoint_slug,
        "provider_name": provider_name,
        "routing_identity_unambiguous": routing_identity_unambiguous,
        "operational": operational,
        "operational_status": operational_status,
        "zdr_eligible": zdr_eligible,
        "context_limit": context_limit,
        "max_prompt_tokens": max_prompt_tokens,
        "max_prompt_tokens_source": max_prompt_tokens_source,
        "output_limit": output_limit,
        "output_limit_source": output_limit_source,
        "supported_parameters": list(supported_parameters),
        "supported_output_modes": [
            mode.value
            for mode in mutually_supported_output_modes(
                (model_supported_parameters, supported_parameters)
            )
        ],
        "structured_output_supported": supports_provider_structured_output(supported_parameters),
        "structured_output_mode": (
            None if structured_output_mode is None else structured_output_mode.value
        ),
        "reasoning_supported": supports_reasoning_request(
            reasoning_capability_parameters(supported_parameters)
        ),
        "pricing_observation": pricing_observation.value,
        "pricing": pricing,
        "pricing_sha256": pricing_sha256,
    }
    values["route_sha256"] = _canonical_sha256(values)
    return ProviderRouteState.model_validate(values)


def _seal_catalog_model_state(
    *,
    exact_model_id: str,
    canonical_model_slug: str,
    catalog_context_limit: int,
    context_limit: int,
    context_limit_source: Literal["metadata", "catalog_context", "candidate_registry"],
    output_limit: int,
    output_limit_source: Literal["metadata", "provider_context", "candidate_registry"],
    supported_parameters: tuple[str, ...],
    routes: tuple[ProviderRouteState, ...],
    structured_output_mode: StructuredOutputMode | None = None,
) -> CatalogModelState:
    ordered = tuple(sorted(routes, key=lambda route: route.provider_endpoint))
    structured = supports_provider_structured_output(supported_parameters)
    exact_observation = not ordered or any(
        route.pricing_observation is PricingObservationKind.EXACT for route in ordered
    )
    selected_mode = (
        supported_output_modes(supported_parameters)[0]
        if exact_observation
        else structured_output_mode
    )
    eligible = tuple(
        route.provider_endpoint
        for route in ordered
        if route.discovery_eligible and _REQUIRED_PARAMETERS.issubset(supported_parameters)
    )
    values: dict[str, Any] = {
        "schema_version": "2.0",
        "exact_model_id": exact_model_id,
        "canonical_model_slug": canonical_model_slug,
        "variant_family_key": model_variant_family_key(exact_model_id),
        "catalog_context_limit": catalog_context_limit,
        "context_limit": context_limit,
        "context_limit_source": context_limit_source,
        "output_limit": output_limit,
        "output_limit_source": output_limit_source,
        "supported_parameters": list(supported_parameters),
        "supported_output_modes": [
            mode.value for mode in supported_output_modes(supported_parameters)
        ],
        "structured_output_supported": structured,
        "structured_output_mode": None if selected_mode is None else selected_mode.value,
        "reasoning_supported": supports_reasoning_request(
            reasoning_capability_parameters(supported_parameters)
        ),
        "routes": [route.model_dump(mode="json") for route in ordered],
        "eligible_provider_endpoints": list(eligible),
    }
    values["state_sha256"] = _canonical_sha256(values)
    return CatalogModelState.model_validate(values)


def _compare_model_pricing(
    *,
    before_routes: Mapping[str, ProviderRouteState],
    after_routes: Mapping[str, ProviderRouteState],
    tolerance: Decimal,
) -> tuple[PricingComparisonState, bool, set[str]]:
    common = sorted(set(before_routes) & set(after_routes))
    if not common:
        return PricingComparisonState.NOT_APPLICABLE, False, set()
    changed = False
    not_evaluable = False
    increases: set[str] = set()
    for endpoint in common:
        before = before_routes[endpoint]
        after = after_routes[endpoint]
        if before.pricing_sha256 == after.pricing_sha256:
            continue
        changed = True
        if before.pricing is None or after.pricing is None:
            not_evaluable = True
            continue
        for field in sorted(set(before.pricing) | set(after.pricing)):
            old = Decimal(before.pricing.get(field, "0"))
            new = Decimal(after.pricing.get(field, "0"))
            threshold = old * (Decimal(1) + tolerance)
            if new > threshold:
                increases.add(f"{endpoint}:{field}")
    if not_evaluable:
        return PricingComparisonState.NOT_EVALUABLE, changed, increases
    return PricingComparisonState.EVALUATED, changed, increases


def _endpoints_with_pricing_increase(
    *,
    before: CatalogModelState | None,
    after: CatalogModelState,
    tolerance: Decimal,
) -> set[str]:
    if before is None:
        return set()
    before_routes = {route.provider_endpoint: route for route in before.routes}
    result: set[str] = set()
    for route in after.routes:
        prior = before_routes.get(route.provider_endpoint)
        if prior is None or prior.pricing is None or route.pricing is None:
            continue
        for field in set(prior.pricing) | set(route.pricing):
            old = Decimal(prior.pricing.get(field, "0"))
            new = Decimal(route.pricing.get(field, "0"))
            if new > old * (Decimal(1) + tolerance):
                result.add(route.provider_endpoint)
                break
    return result


def _normalize_endpoint_inventory(
    raw_routes: Sequence[Mapping[str, Any]],
    *,
    label: str,
    preferred_endpoint: str | None = None,
) -> tuple[tuple[_EndpointRouteInput, ...], dict[str, int]]:
    """Retain full identity while choosing only injective provider route selectors."""

    if len(raw_routes) > _MAX_ROUTES_PER_MODEL:
        raise ModelRefreshValidationError(f"{label} exceeds the per-model route limit")

    projected: list[
        tuple[
            Mapping[str, Any],
            _EndpointIdentityKey,
            tuple[str, ...],
            str,
        ]
    ] = []
    seen_identity_keys: set[_EndpointIdentityKey] = set()
    alias_counts: dict[str, int] = {}
    provider_name_counts: dict[str, int] = {}
    for raw in raw_routes:
        identity = _endpoint_identity_projection(raw)
        key = (identity["tag"], identity["slug"])
        if key in seen_identity_keys:
            raise ModelRefreshValidationError(f"{label} contains duplicate exact routes")
        seen_identity_keys.add(key)
        aliases = tuple(
            dict.fromkeys(
                value for value in (identity["tag"], identity["slug"]) if isinstance(value, str)
            )
        )
        if not aliases:
            raise ModelRefreshValidationError(
                f"{label} contains a route without an exact tag or slug"
            )
        provider_name = identity["provider_name"]
        assert isinstance(provider_name, str)
        for alias in aliases:
            alias_counts[alias] = alias_counts.get(alias, 0) + 1
        normalized_name = provider_name.casefold()
        provider_name_counts[normalized_name] = provider_name_counts.get(normalized_name, 0) + 1
        projected.append((raw, key, aliases, provider_name))

    normalized: list[_EndpointRouteInput] = []
    for raw, key, aliases, provider_name in sorted(
        projected,
        key=lambda item: (item[1][0] or "", item[1][1] or ""),
    ):
        unique_aliases = tuple(alias for alias in aliases if alias_counts[alias] == 1)
        if not unique_aliases:
            raise ModelRefreshValidationError(
                f"{label} contains a route without a uniquely addressable tag or slug"
            )
        provider_endpoint = (
            preferred_endpoint
            if preferred_endpoint is not None and preferred_endpoint in unique_aliases
            else unique_aliases[0]
        )
        normalized.append(
            _EndpointRouteInput(
                raw=raw,
                identity_key=key,
                provider_endpoint=provider_endpoint,
                routing_identity_unambiguous=(provider_name_counts[provider_name.casefold()] == 1),
            )
        )
    return (
        tuple(sorted(normalized, key=lambda route: route.provider_endpoint)),
        alias_counts,
    )


def _endpoint_identity_projection(raw: Mapping[str, Any]) -> dict[str, str | None]:
    try:
        return canonicalize_openrouter_endpoint_identity(raw)
    except EndpointSnapshotValidationError as exc:
        raise ModelRefreshValidationError("endpoint identity metadata is invalid") from exc


def _operational_status(value: Any) -> tuple[bool, str]:
    if isinstance(value, bool):
        raise ModelRefreshValidationError("endpoint operational status is invalid")
    if isinstance(value, int):
        status = str(value)
        if len(status) > 32:
            raise ModelRefreshValidationError("endpoint operational status is invalid")
        return value == 0, status
    if isinstance(value, str):
        if (
            value != value.strip()
            or any(not character.isprintable() for character in value)
            or not value
            or len(value) > 32
        ):
            raise ModelRefreshValidationError("endpoint operational status is invalid")
        normalized = value.casefold()
        return normalized in _OPERATIONAL_TEXT, normalized
    raise ModelRefreshValidationError("endpoint operational status is invalid")


def _catalog_supported_parameters(value: Any) -> tuple[str, ...]:
    try:
        return canonicalize_openrouter_catalog_supported_parameters(value)
    except ModelDiscoveryValidationError as exc:
        raise ModelRefreshValidationError("catalog supported parameters are malformed") from exc


def _endpoint_supported_parameters(value: Any) -> tuple[str, ...]:
    try:
        return canonicalize_openrouter_supported_parameters(value)
    except EndpointSnapshotValidationError as exc:
        raise ModelRefreshValidationError("endpoint supported parameters are malformed") from exc


def _endpoint_token_limits(
    raw: Mapping[str, Any],
) -> tuple[
    int,
    int,
    Literal["metadata", "context_limit"],
    int,
    Literal["metadata", "context_limit"],
]:
    try:
        return canonicalize_openrouter_endpoint_token_limits(raw)
    except EndpointSnapshotValidationError as exc:
        raise ModelRefreshValidationError("endpoint token-limit metadata is invalid") from exc


def _canonical_pricing(value: Any) -> dict[str, str]:
    try:
        return canonicalize_openrouter_pricing(value)
    except EndpointSnapshotValidationError as exc:
        raise ModelRefreshValidationError("endpoint price metadata is malformed") from exc


def _canonical_fraction(value: str) -> Decimal:
    if not isinstance(value, str):
        raise ModelRefreshValidationError("refresh fraction must be decimal text")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ModelRefreshValidationError("refresh fraction is invalid") from exc
    if not parsed.is_finite() or parsed < 0 or _canonical_decimal(parsed) != value:
        raise ModelRefreshValidationError("refresh fraction is not canonical")
    return parsed


def _canonical_decimal(value: Decimal) -> str:
    normalized = format(value, "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    return normalized or "0"


def _positive_integer(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= 2**31 - 1:
        raise ModelRefreshValidationError(f"{label} must be a positive bounded integer")
    assert isinstance(value, int)
    return value


def _required_bounded_list(
    value: Any,
    *,
    label: str,
    allow_empty: bool = False,
    maximum: int = _MAX_MODELS,
) -> list[Mapping[str, Any]]:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or len(value) > maximum
        or any(not isinstance(item, Mapping) for item in value)
    ):
        raise ModelRefreshValidationError(f"{label} is not a bounded object list")
    return list(value)


def _whole_second_utc(value: datetime, *, label: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
        or value.microsecond != 0
    ):
        raise ModelRefreshValidationError(f"{label} must be a whole-second UTC timestamp")
    return value.astimezone(UTC)


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
            default=_json_default,
        ).encode("utf-8")
    ).hexdigest()


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, StrEnum):
        return value.value
    raise TypeError(f"unsupported canonical JSON type: {type(value).__name__}")


def _create_private_output_directory(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    if is_sensitive_workspace_name(absolute.name):
        raise ModelRefreshValidationError("refusing a sensitive refresh output directory")
    _reject_linked_components(absolute.parent)
    if not absolute.parent.is_dir():
        raise ModelRefreshValidationError("refresh output parent must already exist")
    try:
        os.mkdir(absolute, _PRIVATE_DIRECTORY_MODE)
    except FileExistsError as exc:
        raise ModelRefreshValidationError("refresh output directory must be fresh") from exc
    metadata = os.lstat(absolute)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
    ):
        _remove_fresh_output(absolute)
        raise ModelRefreshValidationError("refresh output directory is not private")
    return absolute


def _write_private_artifact(path: Path, artifact: BaseModel) -> None:
    raw = stable_json(artifact).encode("utf-8")
    if not raw or len(raw) > _MAX_ARTIFACT_BYTES:
        raise ModelRefreshValidationError("refresh artifact exceeds its bounded size")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ModelRefreshValidationError("refresh artifact output requires no-follow support")
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
            _PRIVATE_FILE_MODE,
        )
        os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("refresh artifact write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as exc:
        raise ModelRefreshValidationError("refresh artifact could not be persisted") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _load_private_artifact[ModelT: BaseModel](
    path: Path,
    model: type[ModelT],
) -> ModelT:
    absolute = Path(os.path.abspath(path))
    _reject_linked_components(absolute.parent)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ModelRefreshValidationError("refresh artifact loading requires no-follow support")
    descriptor = -1
    try:
        descriptor = os.open(absolute, os.O_RDONLY | os.O_NONBLOCK | no_follow)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != _PRIVATE_FILE_MODE
            or not 0 < before.st_size <= _MAX_ARTIFACT_BYTES
        ):
            raise ModelRefreshValidationError(
                "refresh artifact must be a bounded private unshared regular file"
            )
        raw = os.read(descriptor, before.st_size + 1)
        after = os.fstat(descriptor)
        if len(raw) != before.st_size or _file_identity(before) != _file_identity(after):
            raise ModelRefreshValidationError("refresh artifact changed during reading")
        current = os.lstat(absolute)
        if _file_identity(current) != _file_identity(after):
            raise ModelRefreshValidationError("refresh artifact path changed during reading")
    except OSError as exc:
        raise ModelRefreshValidationError("refresh artifact is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        payload = json.loads(raw, object_pairs_hook=_unique_json_object)
        artifact = model.model_validate(payload)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ModelRefreshValidationError("refresh artifact failed strict validation") from exc
    if raw != stable_json(artifact).encode("utf-8"):
        raise ModelRefreshValidationError("refresh artifact is not canonically serialized")
    return artifact


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ModelRefreshValidationError("refresh artifact contains duplicate JSON keys")
        result[key] = value
    return result


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _reject_linked_components(path: Path) -> None:
    cursor = path
    while True:
        if cursor.is_symlink() or cursor.is_junction():
            raise ModelRefreshValidationError("refresh artifact path may not traverse links")
        if cursor == cursor.parent:
            return
        cursor = cursor.parent


def _remove_fresh_output(path: Path) -> None:
    if not path.exists() or path.is_symlink():
        return
    for name in (
        SOURCE_EVIDENCE_FILENAME,
        SNAPSHOT_FILENAME,
        DIFF_FILENAME,
        ATTEMPT_FILENAME,
        FRESHNESS_FILENAME,
    ):
        candidate = path / name
        try:
            if candidate.is_file() and not candidate.is_symlink():
                candidate.unlink()
        except OSError:
            pass
    with suppress(OSError):
        path.rmdir()
