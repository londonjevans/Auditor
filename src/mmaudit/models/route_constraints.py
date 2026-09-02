"""Provider-free, finite route constraints shared by selection and admission.

The models in this module contain no transport or provider client.  They normalize
already-observed facts, evaluate one closed predicate inventory, and deliberately
leave empirical schema behavior and token-detail semantics unavailable.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, localcontext
from enum import Enum, StrEnum
from types import CellType, CodeType, FunctionType, MappingProxyType
from typing import Any, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models.identifiers import (
    EXACT_MODEL_ID_PATTERN,
    require_exact_openrouter_model_id,
)
from mmaudit.models.output_modes import StructuredOutputMode, output_mode_request_parameters
from mmaudit.models.reasoning import (
    REASONING_EFFORT_ORDER,
    ReasoningControlMode,
    ReasoningEffort,
    resolve_effective_reasoning_effort_inventory,
)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ENDPOINT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"
_ROLE_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"
_PARAMETER_PATTERN = r"^[a-z][a-z0-9_]{0,99}$"
_DECIMAL_PRICE_PATTERN = re.compile(r"(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,36})?\Z")
_NATIVE_CAPABILITY_MARKER = "structured_outputs"


@dataclass(frozen=True)
class _RouteConstraintFunctionState:
    function: FunctionType
    code: CodeType
    defaults: tuple[Any, ...] | None
    kwdefaults: dict[str, Any] | None
    kwdefault_items: tuple[tuple[str, Any], ...]
    function_globals: dict[str, Any]
    closure: tuple[CellType, ...] | None
    closure_values: tuple[tuple[CellType, object], ...]
    attributes: dict[str, Any]
    attribute_items: tuple[tuple[str, Any], ...]


class RouteConstraintError(ValueError):
    """A provider-free route constraint or requirement failed closed."""


def project_route_emitted_request_parameters(
    *,
    structured_output_mode: StructuredOutputMode,
    reasoning_emitted: bool,
) -> tuple[str, ...]:
    """Project the exact request-body parameter names used by route admission."""

    if (
        type(structured_output_mode) is not StructuredOutputMode
        or type(reasoning_emitted) is not bool
    ):
        raise RouteConstraintError("route request-parameter projection inputs are invalid")
    return tuple(
        sorted(
            {
                "max_tokens",
                "temperature",
                *output_mode_request_parameters(structured_output_mode),
                *(("reasoning",) if reasoning_emitted else ()),
            }
        )
    )


_EMITTED_REQUEST_PARAMETERS = project_route_emitted_request_parameters(
    structured_output_mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
    reasoning_emitted=True,
)


class RoutePredicateId(StrEnum):
    """The complete, ordered route-admission predicate inventory."""

    EXACT_MODEL_IDENTITY = "EXACT_MODEL_IDENTITY"
    EXACT_PROVIDER_ENDPOINT = "EXACT_PROVIDER_ENDPOINT"
    PROVIDER_DISPLAY_NAME_INJECTIVITY = "PROVIDER_DISPLAY_NAME_INJECTIVITY"
    OPERATIONAL_STATUS = "OPERATIONAL_STATUS"
    ZDR_ELIGIBILITY = "ZDR_ELIGIBILITY"
    EMITS_MAX_TOKENS = "EMITS_MAX_TOKENS"
    EMITS_TEMPERATURE = "EMITS_TEMPERATURE"
    EMITS_RESPONSE_FORMAT = "EMITS_RESPONSE_FORMAT"
    EMITS_REASONING = "EMITS_REASONING"
    MODEL_STRUCTURED_OUTPUT_MARKER = "MODEL_STRUCTURED_OUTPUT_MARKER"
    ENDPOINT_STRUCTURED_OUTPUT_MARKER = "ENDPOINT_STRUCTURED_OUTPUT_MARKER"
    NATIVE_STRUCTURED_OUTPUT_MODE = "NATIVE_STRUCTURED_OUTPUT_MODE"
    SINGLETON_EXACT_ROUTE = "SINGLETON_EXACT_ROUTE"
    AUTOMATIC_FALLBACK_DISABLED = "AUTOMATIC_FALLBACK_DISABLED"
    REASONING_POLICY_BINDING = "REASONING_POLICY_BINDING"
    REASONING_CONTROL_BINDING = "REASONING_CONTROL_BINDING"
    REASONING_CONTROL_VALUES = "REASONING_CONTROL_VALUES"
    REASONING_EFFORT_SUPPORT = "REASONING_EFFORT_SUPPORT"
    PROMPT_CAPACITY_ENVELOPE = "PROMPT_CAPACITY_ENVELOPE"
    OUTPUT_CAPACITY_ENVELOPE = "OUTPUT_CAPACITY_ENVELOPE"
    CONTEXT_CAPACITY_ENVELOPE = "CONTEXT_CAPACITY_ENVELOPE"
    METADATA_COMPLETION_CAPACITY = "METADATA_COMPLETION_CAPACITY"
    PRICE_CAP_EXPRESSIBILITY = "PRICE_CAP_EXPRESSIBILITY"
    PRICE_CAP_NO_WEAKER = "PRICE_CAP_NO_WEAKER"
    FROZEN_LIVE_EQUIVALENCE = "FROZEN_LIVE_EQUIVALENCE"
    REGISTRY_SELECTION_HASH_CUSTODY = "REGISTRY_SELECTION_HASH_CUSTODY"
    REGISTRY_CONSTRAINT_HASH_CUSTODY = "REGISTRY_CONSTRAINT_HASH_CUSTODY"
    EMPIRICAL_SCHEMA_CONFORMANCE = "EMPIRICAL_SCHEMA_CONFORMANCE"
    TOKEN_DETAIL_REPORTING_CONVENTION = "TOKEN_DETAIL_REPORTING_CONVENTION"


ROUTE_PREDICATE_IDS: tuple[RoutePredicateId, ...] = tuple(RoutePredicateId)


class RoutePredicateDisposition(StrEnum):
    SATISFIED = "SATISFIED"
    REJECTED = "REJECTED"
    UNAVAILABLE = "UNAVAILABLE"


class RoutePredicateReason(StrEnum):
    """Closed, value-free diagnostics; provider-controlled values are never copied."""

    SATISFIED = "SATISFIED"
    MODEL_IDENTITY_MISMATCH = "MODEL_IDENTITY_MISMATCH"
    PROVIDER_ENDPOINT_MISMATCH = "PROVIDER_ENDPOINT_MISMATCH"
    DISPLAY_INVENTORY_INCOMPLETE = "DISPLAY_INVENTORY_INCOMPLETE"
    DISPLAY_NAME_NOT_INJECTIVE = "DISPLAY_NAME_NOT_INJECTIVE"
    OPERATIONAL_STATUS_NOT_ACCEPTED = "OPERATIONAL_STATUS_NOT_ACCEPTED"
    ZDR_NOT_ELIGIBLE = "ZDR_NOT_ELIGIBLE"
    MAX_TOKENS_NOT_EMITTED = "MAX_TOKENS_NOT_EMITTED"
    TEMPERATURE_NOT_EMITTED = "TEMPERATURE_NOT_EMITTED"
    RESPONSE_FORMAT_NOT_EMITTED = "RESPONSE_FORMAT_NOT_EMITTED"
    REASONING_NOT_EMITTED = "REASONING_NOT_EMITTED"
    EMITTED_PARAMETER_INVENTORY_MISMATCH = "EMITTED_PARAMETER_INVENTORY_MISMATCH"
    EMITTED_PARAMETER_SUPPORT_MISMATCH = "EMITTED_PARAMETER_SUPPORT_MISMATCH"
    MODEL_NATIVE_MARKER_MISSING = "MODEL_NATIVE_MARKER_MISSING"
    ENDPOINT_NATIVE_MARKER_MISSING = "ENDPOINT_NATIVE_MARKER_MISSING"
    NATIVE_OUTPUT_MODE_MISSING = "NATIVE_OUTPUT_MODE_MISSING"
    ROUTE_NOT_SINGLETON = "ROUTE_NOT_SINGLETON"
    AUTOMATIC_FALLBACK_ENABLED = "AUTOMATIC_FALLBACK_ENABLED"
    REASONING_POLICY_HASH_MISMATCH = "REASONING_POLICY_HASH_MISMATCH"
    REASONING_CONTROL_HASH_MISMATCH = "REASONING_CONTROL_HASH_MISMATCH"
    REASONING_CONTROL_MISMATCH = "REASONING_CONTROL_MISMATCH"
    REASONING_EFFORT_INVENTORY_UNAVAILABLE = "REASONING_EFFORT_INVENTORY_UNAVAILABLE"
    REASONING_EFFORT_INVENTORY_EMPTY = "REASONING_EFFORT_INVENTORY_EMPTY"
    REASONING_EFFORT_INVENTORY_CONTRADICTORY = "REASONING_EFFORT_INVENTORY_CONTRADICTORY"
    REASONING_EFFORT_UNSUPPORTED = "REASONING_EFFORT_UNSUPPORTED"
    PROMPT_CAPACITY_INSUFFICIENT = "PROMPT_CAPACITY_INSUFFICIENT"
    OUTPUT_CAPACITY_INSUFFICIENT = "OUTPUT_CAPACITY_INSUFFICIENT"
    RUNTIME_OUTPUT_TOKENS_MISMATCH = "RUNTIME_OUTPUT_TOKENS_MISMATCH"
    CONTEXT_CAPACITY_INSUFFICIENT = "CONTEXT_CAPACITY_INSUFFICIENT"
    COMPLETION_CAPACITY_NOT_METADATA = "COMPLETION_CAPACITY_NOT_METADATA"
    PRICE_CAP_NOT_EXPRESSIBLE = "PRICE_CAP_NOT_EXPRESSIBLE"
    PRICE_CAP_PROOF_UNAVAILABLE = "PRICE_CAP_PROOF_UNAVAILABLE"
    PRICE_CAP_MISSING = "PRICE_CAP_MISSING"
    PRICE_CAP_WEAKER_THAN_ROUTE = "PRICE_CAP_WEAKER_THAN_ROUTE"
    LIVE_EQUIVALENCE_UNAVAILABLE = "LIVE_EQUIVALENCE_UNAVAILABLE"
    LIVE_EQUIVALENCE_MISMATCH = "LIVE_EQUIVALENCE_MISMATCH"
    REGISTRY_SELECTION_CUSTODY_UNAVAILABLE = "REGISTRY_SELECTION_CUSTODY_UNAVAILABLE"
    REGISTRY_SELECTION_CUSTODY_MISMATCH = "REGISTRY_SELECTION_CUSTODY_MISMATCH"
    REGISTRY_CONSTRAINT_CUSTODY_UNAVAILABLE = "REGISTRY_CONSTRAINT_CUSTODY_UNAVAILABLE"
    REGISTRY_CONSTRAINT_CUSTODY_MISMATCH = "REGISTRY_CONSTRAINT_CUSTODY_MISMATCH"
    EMPIRICAL_SCHEMA_EVIDENCE_UNAVAILABLE = "EMPIRICAL_SCHEMA_EVIDENCE_UNAVAILABLE"
    TOKEN_DETAIL_CONVENTION_UNAVAILABLE = "TOKEN_DETAIL_CONVENTION_UNAVAILABLE"
    RUNTIME_EVIDENCE_INVALID = "RUNTIME_EVIDENCE_INVALID"
    RUNTIME_EVIDENCE_BINDING_MISMATCH = "RUNTIME_EVIDENCE_BINDING_MISMATCH"
    RUNTIME_EVIDENCE_STALE = "RUNTIME_EVIDENCE_STALE"


class RouteConstraintPurpose(StrEnum):
    DISCOVERY_PUBLICATION = "DISCOVERY_PUBLICATION"
    REGISTRY_PUBLICATION = "REGISTRY_PUBLICATION"
    NONCREDITING_SMOKE_ADMISSION = "NONCREDITING_SMOKE_ADMISSION"
    FULL_CAMPAIGN_ADMISSION = "FULL_CAMPAIGN_ADMISSION"


class ExactRouteRole(StrEnum):
    CANDIDATE = "candidate"
    PRIMARY_JUDGE = "primary_judge"
    REPLAY_JUDGE = "replay_judge"


class ProviderPriceCapAlgorithm(StrEnum):
    OPENROUTER_MAX_PRICE_CEILING_V1 = "MMAUDIT_OPENROUTER_MAX_PRICE_CEILING_V1"


class RoutePriceComponent(StrEnum):
    COMPLETION = "completion"
    IMAGE = "image"
    INPUT_CACHE_READ = "input_cache_read"
    INPUT_CACHE_WRITE = "input_cache_write"
    INTERNAL_REASONING = "internal_reasoning"
    PROMPT = "prompt"
    REQUEST = "request"
    WEB_SEARCH = "web_search"


class ProviderMaxPriceComponent(StrEnum):
    COMPLETION = "completion"
    IMAGE = "image"
    PROMPT = "prompt"
    REQUEST = "request"


_ROUTER_MAX_PRICE_FIELDS = frozenset(ProviderMaxPriceComponent)
_PER_MILLION_PRICE_FIELDS = frozenset(
    {ProviderMaxPriceComponent.COMPLETION, ProviderMaxPriceComponent.PROMPT}
)
_UNENFORCEABLE_VARIABLE_PRICE_FIELDS = frozenset(
    {RoutePriceComponent.INPUT_CACHE_WRITE, RoutePriceComponent.INTERNAL_REASONING}
)


class _FrozenStrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


class ExactRoutePrice(_FrozenStrictModel):
    component: RoutePriceComponent
    unit_price: str = Field(min_length=1, max_length=50)

    @field_validator("unit_price")
    @classmethod
    def price_is_canonical(cls, value: str) -> str:
        if _canonical_price(value) != value:
            raise ValueError("route price is not a canonical decimal string")
        return value


class ProviderPriceCap(_FrozenStrictModel):
    component: ProviderMaxPriceComponent
    value: float = Field(ge=0)

    @field_validator("value")
    @classmethod
    def cap_is_finite(cls, value: float) -> float:
        if not math.isfinite(value) or (value == 0 and math.copysign(1, value) < 0):
            raise ValueError("provider price cap must be finite and nonnegative")
        return value


class ProviderPriceCapProof(_FrozenStrictModel):
    schema_version: Literal["1.0"] = "1.0"
    algorithm: ProviderPriceCapAlgorithm
    exact_pricing: tuple[ExactRoutePrice, ...] = Field(min_length=2, max_length=8)
    projected_cap: tuple[ProviderPriceCap, ...] = Field(min_length=2, max_length=4)
    configured_cap: tuple[ProviderPriceCap, ...] = Field(min_length=2, max_length=4)
    expressible: Literal[True]
    no_weaker: Literal[True]
    proof_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def proof_is_canonical_and_self_hashed(self) -> Self:
        _require_canonical_pricing(self.exact_pricing)
        _require_canonical_caps(self.projected_cap)
        _require_canonical_caps(self.configured_cap)
        if self.projected_cap != project_provider_price_cap(self.exact_pricing):
            raise ValueError("provider price projection is inconsistent")
        if self.configured_cap != self.projected_cap:
            raise ValueError("configured provider cap is weaker than the exact projection")
        _require_no_weaker_cap(self.exact_pricing, self.configured_cap)
        _require_self_hash(self, "proof_sha256")
        return self


def normalize_exact_route_pricing(
    pricing: Mapping[str, str],
) -> tuple[ExactRoutePrice, ...]:
    """Normalize one exact provider pricing mapping into the finite component inventory."""

    if type(pricing) is not dict or not 2 <= len(pricing) <= len(RoutePriceComponent):
        raise RouteConstraintError("route pricing mapping is invalid")
    try:
        exact = tuple(
            sorted(
                (
                    ExactRoutePrice(
                        component=RoutePriceComponent(component),
                        unit_price=unit_price,
                    )
                    for component, unit_price in pricing.items()
                ),
                key=lambda item: item.component.value,
            )
        )
        _require_canonical_pricing(exact)
    except (TypeError, ValueError) as exc:
        raise RouteConstraintError("route pricing mapping is invalid") from exc
    return exact


class RoutePredicateProfile(_FrozenStrictModel):
    """Shared requirements for every exact AUTHRUNNER route."""

    schema_version: Literal["1.0"] = "1.0"
    predicate_ids: tuple[RoutePredicateId, ...] = Field(
        min_length=len(ROUTE_PREDICATE_IDS),
        max_length=len(ROUTE_PREDICATE_IDS),
    )
    emitted_request_parameters: tuple[str, ...] = Field(min_length=4, max_length=4)
    native_capability_marker: Literal["structured_outputs"]
    required_output_mode: Literal[StructuredOutputMode.NATIVE_JSON_SCHEMA]
    accepted_operational_status: Literal["0"]
    require_zdr: Literal[True]
    require_singleton_route: Literal[True]
    allow_automatic_fallbacks: Literal[False]
    reasoning_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    reasoning_role_profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    reasoning_role_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    reasoning_control_profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    reasoning_mode: ReasoningControlMode
    reasoning_effort: ReasoningEffort | None
    reasoning_max_tokens: int | None = Field(default=None, ge=1, le=65_536)
    reasoning_exclude: bool
    reserved_reasoning_tokens: int = Field(gt=0, le=65_536)
    minimum_prompt_tokens: int = Field(gt=0, le=2**31 - 1)
    required_output_tokens: int = Field(gt=0, le=65_536)
    required_completion_tokens: int = Field(gt=0, le=131_072)
    minimum_context_tokens: int = Field(gt=0, le=2**31 - 1)
    required_completion_limit_source: Literal["metadata"]
    price_cap_algorithm: ProviderPriceCapAlgorithm
    empirical_schema_conformance_disposition: RoutePredicateDisposition
    token_detail_convention_disposition: RoutePredicateDisposition
    profile_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        reasoning_policy_sha256: str,
        reasoning_role_profile_sha256: str,
        reasoning_role_binding_sha256: str,
        reasoning_control_profile_sha256: str,
        reserved_reasoning_tokens: int,
        minimum_prompt_tokens: int,
        required_output_tokens: int,
        minimum_context_tokens: int,
    ) -> Self:
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "predicate_ids": ROUTE_PREDICATE_IDS,
            "emitted_request_parameters": _EMITTED_REQUEST_PARAMETERS,
            "native_capability_marker": _NATIVE_CAPABILITY_MARKER,
            "required_output_mode": StructuredOutputMode.NATIVE_JSON_SCHEMA,
            "accepted_operational_status": "0",
            "require_zdr": True,
            "require_singleton_route": True,
            "allow_automatic_fallbacks": False,
            "reasoning_policy_sha256": reasoning_policy_sha256,
            "reasoning_role_profile_sha256": reasoning_role_profile_sha256,
            "reasoning_role_binding_sha256": reasoning_role_binding_sha256,
            "reasoning_control_profile_sha256": reasoning_control_profile_sha256,
            "reasoning_mode": "effort",
            "reasoning_effort": "high",
            "reasoning_max_tokens": None,
            "reasoning_exclude": False,
            "reserved_reasoning_tokens": reserved_reasoning_tokens,
            "minimum_prompt_tokens": minimum_prompt_tokens,
            "required_output_tokens": required_output_tokens,
            "required_completion_tokens": (required_output_tokens + reserved_reasoning_tokens),
            "minimum_context_tokens": minimum_context_tokens,
            "required_completion_limit_source": "metadata",
            "price_cap_algorithm": (ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1),
            "empirical_schema_conformance_disposition": (RoutePredicateDisposition.UNAVAILABLE),
            "token_detail_convention_disposition": (RoutePredicateDisposition.UNAVAILABLE),
        }
        values["profile_sha256"] = _canonical_sha256(values)
        return cls.model_validate(values)

    @model_validator(mode="after")
    def profile_is_exact_complete_and_self_hashed(self) -> Self:
        if self.predicate_ids != ROUTE_PREDICATE_IDS:
            raise ValueError("route predicate profile inventory is incomplete or reordered")
        if self.emitted_request_parameters != _EMITTED_REQUEST_PARAMETERS:
            raise ValueError("route predicate emitted parameter inventory is not exact")
        if (
            self.native_capability_marker != _NATIVE_CAPABILITY_MARKER
            or self.required_output_mode is not StructuredOutputMode.NATIVE_JSON_SCHEMA
            or self.accepted_operational_status != "0"
            or self.require_zdr is not True
            or self.require_singleton_route is not True
            or self.allow_automatic_fallbacks is not False
        ):
            raise ValueError("route predicate fixed requirements were weakened")
        if (
            self.reasoning_mode != "effort"
            or self.reasoning_effort != "high"
            or self.reasoning_max_tokens is not None
            or self.reasoning_exclude is not False
        ):
            raise ValueError("route predicate reasoning control is not exact effort=high")
        if self.required_completion_tokens != (
            self.required_output_tokens + self.reserved_reasoning_tokens
        ):
            raise ValueError("route predicate completion reserve does not conserve components")
        if self.minimum_context_tokens < (
            self.minimum_prompt_tokens + self.required_completion_tokens
        ):
            raise ValueError("route predicate context minimum does not cover its envelopes")
        if (
            self.required_completion_limit_source != "metadata"
            or self.price_cap_algorithm
            is not ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1
            or self.empirical_schema_conformance_disposition
            is not RoutePredicateDisposition.UNAVAILABLE
            or self.token_detail_convention_disposition is not RoutePredicateDisposition.UNAVAILABLE
        ):
            raise ValueError("route predicate unavailable or capacity policy was weakened")
        _require_self_hash(self, "profile_sha256")
        return self


class ExactRouteConstraint(_FrozenStrictModel):
    schema_version: Literal["1.0"] = "1.0"
    role: ExactRouteRole
    exact_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    provider_endpoint: str = Field(pattern=_ENDPOINT_PATTERN)
    profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    constraint_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        role: ExactRouteRole,
        exact_model_id: str,
        provider_endpoint: str,
        profile: RoutePredicateProfile,
    ) -> Self:
        _require_exact_type(profile, RoutePredicateProfile, "route predicate profile")
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "role": role,
            "exact_model_id": exact_model_id,
            "provider_endpoint": provider_endpoint,
            "profile_sha256": profile.profile_sha256,
        }
        values["constraint_sha256"] = _canonical_sha256(values)
        return cls.model_validate(values)

    @field_validator("exact_model_id")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value, label="route constraint model ID")

    @model_validator(mode="after")
    def constraint_is_self_hashed(self) -> Self:
        _require_self_hash(self, "constraint_sha256")
        return self


class NormalizedRouteFacts(_FrozenStrictModel):
    """Canonical provider-free facts consumed by every route predicate."""

    schema_version: Literal["1.0"] = "1.0"
    observed_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    observed_provider_endpoint: str | None = Field(
        default=None,
        pattern=_ENDPOINT_PATTERN,
    )
    selected_provider_display_name: str = Field(min_length=1, max_length=200)
    provider_display_names: tuple[str, ...] = Field(min_length=1, max_length=2_048)
    provider_identity_inventory_complete: bool
    operational_status: str = Field(min_length=1, max_length=32)
    zdr_eligible: bool | None
    emitted_request_parameters: tuple[str, ...] = Field(max_length=32)
    model_supported_parameters: tuple[str, ...] = Field(max_length=256)
    endpoint_supported_parameters: tuple[str, ...] = Field(max_length=256)
    structured_output_mode: StructuredOutputMode
    configured_provider_endpoints: tuple[str, ...] = Field(min_length=1, max_length=100)
    provider_policy_mode: Literal["only", "order"]
    automatic_fallbacks_allowed: bool
    reasoning_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    reasoning_role_profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    reasoning_role_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    reasoning_control_profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    reasoning_mode: ReasoningControlMode
    reasoning_effort: ReasoningEffort | None
    reasoning_max_tokens: int | None = Field(default=None, ge=1, le=65_536)
    reasoning_exclude: bool
    reserved_reasoning_tokens: int = Field(ge=0, le=65_536)
    endpoint_supported_reasoning_efforts: tuple[ReasoningEffort, ...] | None
    model_supported_reasoning_efforts: tuple[ReasoningEffort, ...] | None
    max_prompt_tokens: int = Field(gt=0, le=2**31 - 1)
    max_completion_tokens: int = Field(gt=0, le=2**31 - 1)
    max_completion_tokens_source: Literal["metadata", "context_limit"]
    context_tokens: int = Field(gt=0, le=2**31 - 1)
    runtime_required_output_tokens: int | None = Field(default=None, ge=256, le=65_536)
    exact_pricing: tuple[ExactRoutePrice, ...] = Field(min_length=2, max_length=8)
    configured_provider_max_price: tuple[ProviderPriceCap, ...] | None
    frozen_live_equivalent: bool | None
    expected_selection_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    registry_selection_plan_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    registry_profile_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    registry_constraint_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    facts_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        observed_model_id: str,
        observed_provider_endpoint: str | None,
        selected_provider_display_name: str,
        provider_display_names: tuple[str, ...],
        provider_identity_inventory_complete: bool,
        operational_status: str,
        zdr_eligible: bool | None,
        emitted_request_parameters: tuple[str, ...],
        model_supported_parameters: tuple[str, ...],
        endpoint_supported_parameters: tuple[str, ...],
        structured_output_mode: StructuredOutputMode,
        configured_provider_endpoints: tuple[str, ...],
        provider_policy_mode: Literal["only", "order"],
        automatic_fallbacks_allowed: bool,
        reasoning_policy_sha256: str,
        reasoning_role_profile_sha256: str,
        reasoning_role_binding_sha256: str,
        reasoning_control_profile_sha256: str,
        reasoning_mode: ReasoningControlMode,
        reasoning_effort: ReasoningEffort | None,
        reasoning_max_tokens: int | None,
        reasoning_exclude: bool,
        reserved_reasoning_tokens: int,
        endpoint_supported_reasoning_efforts: tuple[ReasoningEffort, ...] | None,
        model_supported_reasoning_efforts: tuple[ReasoningEffort, ...] | None,
        max_prompt_tokens: int,
        max_completion_tokens: int,
        max_completion_tokens_source: Literal["metadata", "context_limit"],
        context_tokens: int,
        exact_pricing: tuple[ExactRoutePrice, ...],
        configured_provider_max_price: tuple[ProviderPriceCap, ...] | None,
        frozen_live_equivalent: bool | None,
        expected_selection_plan_sha256: str,
        runtime_required_output_tokens: int | None = None,
        registry_selection_plan_sha256: str | None = None,
        registry_profile_sha256: str | None = None,
        registry_constraint_sha256: str | None = None,
    ) -> Self:
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "observed_model_id": observed_model_id,
            "observed_provider_endpoint": observed_provider_endpoint,
            "selected_provider_display_name": selected_provider_display_name,
            "provider_display_names": provider_display_names,
            "provider_identity_inventory_complete": provider_identity_inventory_complete,
            "operational_status": operational_status,
            "zdr_eligible": zdr_eligible,
            "emitted_request_parameters": emitted_request_parameters,
            "model_supported_parameters": model_supported_parameters,
            "endpoint_supported_parameters": endpoint_supported_parameters,
            "structured_output_mode": structured_output_mode,
            "configured_provider_endpoints": configured_provider_endpoints,
            "provider_policy_mode": provider_policy_mode,
            "automatic_fallbacks_allowed": automatic_fallbacks_allowed,
            "reasoning_policy_sha256": reasoning_policy_sha256,
            "reasoning_role_profile_sha256": reasoning_role_profile_sha256,
            "reasoning_role_binding_sha256": reasoning_role_binding_sha256,
            "reasoning_control_profile_sha256": reasoning_control_profile_sha256,
            "reasoning_mode": reasoning_mode,
            "reasoning_effort": reasoning_effort,
            "reasoning_max_tokens": reasoning_max_tokens,
            "reasoning_exclude": reasoning_exclude,
            "reserved_reasoning_tokens": reserved_reasoning_tokens,
            "endpoint_supported_reasoning_efforts": endpoint_supported_reasoning_efforts,
            "model_supported_reasoning_efforts": model_supported_reasoning_efforts,
            "max_prompt_tokens": max_prompt_tokens,
            "max_completion_tokens": max_completion_tokens,
            "max_completion_tokens_source": max_completion_tokens_source,
            "context_tokens": context_tokens,
            "runtime_required_output_tokens": runtime_required_output_tokens,
            "exact_pricing": exact_pricing,
            "configured_provider_max_price": configured_provider_max_price,
            "frozen_live_equivalent": frozen_live_equivalent,
            "expected_selection_plan_sha256": expected_selection_plan_sha256,
            "registry_selection_plan_sha256": registry_selection_plan_sha256,
            "registry_profile_sha256": registry_profile_sha256,
            "registry_constraint_sha256": registry_constraint_sha256,
        }
        values["facts_sha256"] = _canonical_sha256(values)
        return cls.model_validate(values)

    @field_validator("observed_model_id")
    @classmethod
    def observed_model_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value, label="observed route model ID")

    @field_validator(
        "emitted_request_parameters",
        "model_supported_parameters",
        "endpoint_supported_parameters",
    )
    @classmethod
    def parameters_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            re.fullmatch(_PARAMETER_PATTERN, item) is None for item in value
        ):
            raise ValueError("route parameter inventory must be canonical")
        return value

    @field_validator("provider_display_names")
    @classmethod
    def display_inventory_is_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(value, key=lambda item: (item.casefold(), item))) or any(
            not item or item != item.strip() or len(item) > 200 for item in value
        ):
            raise ValueError("provider display-name inventory must be canonical")
        return value

    @field_validator(
        "endpoint_supported_reasoning_efforts",
        "model_supported_reasoning_efforts",
    )
    @classmethod
    def effort_inventory_is_canonical(
        cls,
        value: tuple[ReasoningEffort, ...] | None,
    ) -> tuple[ReasoningEffort, ...] | None:
        if value is None:
            return None
        selected = frozenset(value)
        if value != tuple(effort for effort in REASONING_EFFORT_ORDER if effort in selected):
            raise ValueError("reasoning effort inventory must be canonical")
        return value

    @model_validator(mode="after")
    def facts_are_canonical_and_self_hashed(self) -> Self:
        if any(
            re.fullmatch(_ENDPOINT_PATTERN, endpoint) is None
            for endpoint in self.configured_provider_endpoints
        ):
            raise ValueError("configured endpoint inventory is invalid")
        _require_canonical_pricing(self.exact_pricing)
        if self.configured_provider_max_price is not None:
            _require_canonical_caps(self.configured_provider_max_price)
        if self.max_prompt_tokens > self.context_tokens:
            raise ValueError("route prompt capacity exceeds context")
        if self.max_completion_tokens > self.context_tokens:
            raise ValueError("route completion capacity exceeds context")
        custody = (
            self.registry_selection_plan_sha256,
            self.registry_profile_sha256,
            self.registry_constraint_sha256,
        )
        if any(item is None for item in custody) and any(item is not None for item in custody):
            raise ValueError("registry route-constraint custody must be all present or absent")
        if self.runtime_required_output_tokens is not None and any(
            item is None for item in custody
        ):
            raise ValueError("runtime route facts require complete registry custody")
        _require_self_hash(self, "facts_sha256")
        return self


class RoutePredicateResult(_FrozenStrictModel):
    predicate_id: RoutePredicateId
    disposition: RoutePredicateDisposition
    reason: RoutePredicateReason

    @model_validator(mode="after")
    def reason_matches_predicate_and_disposition(self) -> Self:
        if self.disposition is RoutePredicateDisposition.SATISFIED:
            if self.reason is not RoutePredicateReason.SATISFIED:
                raise ValueError("satisfied route predicate has a failure reason")
            return self
        if self.reason is RoutePredicateReason.SATISFIED:
            raise ValueError("failed route predicate lacks a closed reason")
        if self.reason not in _FAILURE_REASONS_BY_PREDICATE[self.predicate_id]:
            raise ValueError("route predicate reason belongs to a different predicate")
        expected_unavailable = self.reason in _UNAVAILABLE_REASONS
        if expected_unavailable != (self.disposition is RoutePredicateDisposition.UNAVAILABLE):
            raise ValueError("route predicate reason differs from its disposition")
        return self


class RoutePredicateReport(_FrozenStrictModel):
    schema_version: Literal["1.0"] = "1.0"
    profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    constraint_sha256: str = Field(pattern=_SHA256_PATTERN)
    facts_sha256: str = Field(pattern=_SHA256_PATTERN)
    results: tuple[RoutePredicateResult, ...] = Field(
        min_length=len(ROUTE_PREDICATE_IDS),
        max_length=len(ROUTE_PREDICATE_IDS),
    )
    report_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def report_is_complete_and_self_hashed(self) -> Self:
        if tuple(result.predicate_id for result in self.results) != ROUTE_PREDICATE_IDS:
            raise ValueError("route predicate report inventory is incomplete or reordered")
        _require_self_hash(self, "report_sha256")
        return self


class RoutePredicateRequirementError(RouteConstraintError):
    """One purpose rejected a complete diagnostic report."""

    def __init__(
        self,
        purpose: RouteConstraintPurpose,
        failures: tuple[RoutePredicateResult, ...],
    ) -> None:
        self.purpose = purpose
        self.failures = failures
        rendered = ",".join(
            f"{failure.predicate_id.value}={failure.reason.value}" for failure in failures
        )
        super().__init__(
            "route predicate report does not satisfy its closed purpose: "
            f"purpose={purpose.value}; failures={rendered}"
        )


_FAILURE_REASONS_BY_PREDICATE: Mapping[
    RoutePredicateId,
    frozenset[RoutePredicateReason],
] = MappingProxyType(
    {
        RoutePredicateId.EXACT_MODEL_IDENTITY: frozenset(
            {RoutePredicateReason.MODEL_IDENTITY_MISMATCH}
        ),
        RoutePredicateId.EXACT_PROVIDER_ENDPOINT: frozenset(
            {RoutePredicateReason.PROVIDER_ENDPOINT_MISMATCH}
        ),
        RoutePredicateId.PROVIDER_DISPLAY_NAME_INJECTIVITY: frozenset(
            {
                RoutePredicateReason.DISPLAY_INVENTORY_INCOMPLETE,
                RoutePredicateReason.DISPLAY_NAME_NOT_INJECTIVE,
            }
        ),
        RoutePredicateId.OPERATIONAL_STATUS: frozenset(
            {RoutePredicateReason.OPERATIONAL_STATUS_NOT_ACCEPTED}
        ),
        RoutePredicateId.ZDR_ELIGIBILITY: frozenset({RoutePredicateReason.ZDR_NOT_ELIGIBLE}),
        RoutePredicateId.EMITS_MAX_TOKENS: frozenset(
            {
                RoutePredicateReason.MAX_TOKENS_NOT_EMITTED,
                RoutePredicateReason.EMITTED_PARAMETER_INVENTORY_MISMATCH,
                RoutePredicateReason.EMITTED_PARAMETER_SUPPORT_MISMATCH,
            }
        ),
        RoutePredicateId.EMITS_TEMPERATURE: frozenset(
            {
                RoutePredicateReason.TEMPERATURE_NOT_EMITTED,
                RoutePredicateReason.EMITTED_PARAMETER_INVENTORY_MISMATCH,
                RoutePredicateReason.EMITTED_PARAMETER_SUPPORT_MISMATCH,
            }
        ),
        RoutePredicateId.EMITS_RESPONSE_FORMAT: frozenset(
            {
                RoutePredicateReason.RESPONSE_FORMAT_NOT_EMITTED,
                RoutePredicateReason.EMITTED_PARAMETER_INVENTORY_MISMATCH,
                RoutePredicateReason.EMITTED_PARAMETER_SUPPORT_MISMATCH,
            }
        ),
        RoutePredicateId.EMITS_REASONING: frozenset(
            {
                RoutePredicateReason.REASONING_NOT_EMITTED,
                RoutePredicateReason.EMITTED_PARAMETER_INVENTORY_MISMATCH,
                RoutePredicateReason.EMITTED_PARAMETER_SUPPORT_MISMATCH,
            }
        ),
        RoutePredicateId.MODEL_STRUCTURED_OUTPUT_MARKER: frozenset(
            {RoutePredicateReason.MODEL_NATIVE_MARKER_MISSING}
        ),
        RoutePredicateId.ENDPOINT_STRUCTURED_OUTPUT_MARKER: frozenset(
            {RoutePredicateReason.ENDPOINT_NATIVE_MARKER_MISSING}
        ),
        RoutePredicateId.NATIVE_STRUCTURED_OUTPUT_MODE: frozenset(
            {RoutePredicateReason.NATIVE_OUTPUT_MODE_MISSING}
        ),
        RoutePredicateId.SINGLETON_EXACT_ROUTE: frozenset(
            {RoutePredicateReason.ROUTE_NOT_SINGLETON}
        ),
        RoutePredicateId.AUTOMATIC_FALLBACK_DISABLED: frozenset(
            {RoutePredicateReason.AUTOMATIC_FALLBACK_ENABLED}
        ),
        RoutePredicateId.REASONING_POLICY_BINDING: frozenset(
            {RoutePredicateReason.REASONING_POLICY_HASH_MISMATCH}
        ),
        RoutePredicateId.REASONING_CONTROL_BINDING: frozenset(
            {RoutePredicateReason.REASONING_CONTROL_HASH_MISMATCH}
        ),
        RoutePredicateId.REASONING_CONTROL_VALUES: frozenset(
            {RoutePredicateReason.REASONING_CONTROL_MISMATCH}
        ),
        RoutePredicateId.REASONING_EFFORT_SUPPORT: frozenset(
            {
                RoutePredicateReason.REASONING_EFFORT_INVENTORY_UNAVAILABLE,
                RoutePredicateReason.REASONING_EFFORT_INVENTORY_EMPTY,
                RoutePredicateReason.REASONING_EFFORT_INVENTORY_CONTRADICTORY,
                RoutePredicateReason.REASONING_EFFORT_UNSUPPORTED,
            }
        ),
        RoutePredicateId.PROMPT_CAPACITY_ENVELOPE: frozenset(
            {RoutePredicateReason.PROMPT_CAPACITY_INSUFFICIENT}
        ),
        RoutePredicateId.OUTPUT_CAPACITY_ENVELOPE: frozenset(
            {
                RoutePredicateReason.OUTPUT_CAPACITY_INSUFFICIENT,
                RoutePredicateReason.RUNTIME_OUTPUT_TOKENS_MISMATCH,
            }
        ),
        RoutePredicateId.CONTEXT_CAPACITY_ENVELOPE: frozenset(
            {RoutePredicateReason.CONTEXT_CAPACITY_INSUFFICIENT}
        ),
        RoutePredicateId.METADATA_COMPLETION_CAPACITY: frozenset(
            {RoutePredicateReason.COMPLETION_CAPACITY_NOT_METADATA}
        ),
        RoutePredicateId.PRICE_CAP_EXPRESSIBILITY: frozenset(
            {RoutePredicateReason.PRICE_CAP_NOT_EXPRESSIBLE}
        ),
        RoutePredicateId.PRICE_CAP_NO_WEAKER: frozenset(
            {
                RoutePredicateReason.PRICE_CAP_PROOF_UNAVAILABLE,
                RoutePredicateReason.PRICE_CAP_MISSING,
                RoutePredicateReason.PRICE_CAP_WEAKER_THAN_ROUTE,
            }
        ),
        RoutePredicateId.FROZEN_LIVE_EQUIVALENCE: frozenset(
            {
                RoutePredicateReason.LIVE_EQUIVALENCE_UNAVAILABLE,
                RoutePredicateReason.LIVE_EQUIVALENCE_MISMATCH,
            }
        ),
        RoutePredicateId.REGISTRY_SELECTION_HASH_CUSTODY: frozenset(
            {
                RoutePredicateReason.REGISTRY_SELECTION_CUSTODY_UNAVAILABLE,
                RoutePredicateReason.REGISTRY_SELECTION_CUSTODY_MISMATCH,
            }
        ),
        RoutePredicateId.REGISTRY_CONSTRAINT_HASH_CUSTODY: frozenset(
            {
                RoutePredicateReason.REGISTRY_CONSTRAINT_CUSTODY_UNAVAILABLE,
                RoutePredicateReason.REGISTRY_CONSTRAINT_CUSTODY_MISMATCH,
            }
        ),
        RoutePredicateId.EMPIRICAL_SCHEMA_CONFORMANCE: frozenset(
            {
                RoutePredicateReason.EMPIRICAL_SCHEMA_EVIDENCE_UNAVAILABLE,
                RoutePredicateReason.RUNTIME_EVIDENCE_INVALID,
                RoutePredicateReason.RUNTIME_EVIDENCE_BINDING_MISMATCH,
                RoutePredicateReason.RUNTIME_EVIDENCE_STALE,
            }
        ),
        RoutePredicateId.TOKEN_DETAIL_REPORTING_CONVENTION: frozenset(
            {
                RoutePredicateReason.TOKEN_DETAIL_CONVENTION_UNAVAILABLE,
                RoutePredicateReason.RUNTIME_EVIDENCE_INVALID,
                RoutePredicateReason.RUNTIME_EVIDENCE_BINDING_MISMATCH,
                RoutePredicateReason.RUNTIME_EVIDENCE_STALE,
            }
        ),
    }
)

_UNAVAILABLE_REASONS = frozenset(
    {
        RoutePredicateReason.REASONING_EFFORT_INVENTORY_UNAVAILABLE,
        RoutePredicateReason.PRICE_CAP_PROOF_UNAVAILABLE,
        RoutePredicateReason.LIVE_EQUIVALENCE_UNAVAILABLE,
        RoutePredicateReason.REGISTRY_SELECTION_CUSTODY_UNAVAILABLE,
        RoutePredicateReason.REGISTRY_CONSTRAINT_CUSTODY_UNAVAILABLE,
        RoutePredicateReason.EMPIRICAL_SCHEMA_EVIDENCE_UNAVAILABLE,
        RoutePredicateReason.TOKEN_DETAIL_CONVENTION_UNAVAILABLE,
    }
)

_LATE_LIVE_PREDICATES = frozenset({RoutePredicateId.FROZEN_LIVE_EQUIVALENCE})
_REGISTRY_PREDICATES = frozenset(
    {
        RoutePredicateId.REGISTRY_SELECTION_HASH_CUSTODY,
        RoutePredicateId.REGISTRY_CONSTRAINT_HASH_CUSTODY,
    }
)
_SEPARATE_RUNTIME_PREDICATES = frozenset(
    {
        RoutePredicateId.EMPIRICAL_SCHEMA_CONFORMANCE,
        RoutePredicateId.TOKEN_DETAIL_REPORTING_CONVENTION,
    }
)
_DISCOVERY_REQUIRED = frozenset(ROUTE_PREDICATE_IDS).difference(
    _LATE_LIVE_PREDICATES | _REGISTRY_PREDICATES | _SEPARATE_RUNTIME_PREDICATES
)
_PURPOSE_REQUIRED: Mapping[RouteConstraintPurpose, frozenset[RoutePredicateId]] = MappingProxyType(
    {
        RouteConstraintPurpose.DISCOVERY_PUBLICATION: _DISCOVERY_REQUIRED,
        RouteConstraintPurpose.REGISTRY_PUBLICATION: _DISCOVERY_REQUIRED | _REGISTRY_PREDICATES,
        RouteConstraintPurpose.NONCREDITING_SMOKE_ADMISSION: (
            _DISCOVERY_REQUIRED | _REGISTRY_PREDICATES | _LATE_LIVE_PREDICATES
        ),
        # The zero-state FULL cutoff deliberately runs before any provider metadata refresh.
        # An unavailable live-equivalence result is therefore staged there, while a later
        # explicit mismatch is still a REJECTED result and always fails the requirement.
        RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION: frozenset(ROUTE_PREDICATE_IDS).difference(
            _LATE_LIVE_PREDICATES
        ),
    }
)


def project_provider_price_cap(
    pricing: Sequence[ExactRoutePrice],
) -> tuple[ProviderPriceCap, ...]:
    """Project exact per-token prices into upward-rounded provider max-price floats."""

    if not route_constraint_callables_are_pristine():
        raise RouteConstraintError("route predicate callable boundary changed")
    exact = tuple(pricing)
    _require_canonical_pricing(exact)
    by_component = {item.component: Decimal(item.unit_price) for item in exact}
    if not {RoutePriceComponent.PROMPT, RoutePriceComponent.COMPLETION}.issubset(by_component):
        raise RouteConstraintError("route pricing cannot express prompt and completion caps")
    cache_read = by_component.get(RoutePriceComponent.INPUT_CACHE_READ)
    if cache_read is not None and cache_read > by_component[RoutePriceComponent.PROMPT]:
        raise RouteConstraintError("route cache-read pricing is not prompt dominated")
    projected: list[ProviderPriceCap] = []
    with localcontext() as context:
        context.prec = 160
        for item in exact:
            if item.component in _UNENFORCEABLE_VARIABLE_PRICE_FIELDS:
                raise RouteConstraintError("route contains a variable price without a provider cap")
            if item.component is RoutePriceComponent.INPUT_CACHE_READ:
                continue
            try:
                cap_component = ProviderMaxPriceComponent(item.component.value)
            except ValueError:
                if Decimal(item.unit_price) != 0:
                    raise RouteConstraintError(
                        "route contains a nonzero price without a provider cap"
                    ) from None
                continue
            ceiling = Decimal(item.unit_price)
            if cap_component in _PER_MILLION_PRICE_FIELDS:
                ceiling *= Decimal(1_000_000)
            candidate = float(ceiling)
            if not math.isfinite(candidate) or candidate < 0:
                raise RouteConstraintError("route price cannot be represented safely")
            while Decimal(str(candidate)) < ceiling:
                candidate = math.nextafter(candidate, math.inf)
            projected.append(ProviderPriceCap(component=cap_component, value=candidate))
    result = tuple(sorted(projected, key=lambda item: item.component.value))
    _require_canonical_caps(result)
    if not {
        ProviderMaxPriceComponent.PROMPT,
        ProviderMaxPriceComponent.COMPLETION,
    }.issubset(item.component for item in result):
        raise RouteConstraintError("route pricing cannot express required provider caps")
    return result


def prove_provider_price_cap(
    *,
    pricing: Sequence[ExactRoutePrice],
    configured_cap: Sequence[ProviderPriceCap],
    algorithm: ProviderPriceCapAlgorithm,
) -> ProviderPriceCapProof:
    """Seal proof that a configured cap is expressible and no weaker than exact pricing."""

    if not route_constraint_callables_are_pristine():
        raise RouteConstraintError("route predicate callable boundary changed")
    if algorithm is not ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1:
        raise RouteConstraintError("provider price-cap algorithm is unsupported")
    exact = tuple(pricing)
    configured = tuple(configured_cap)
    projected = project_provider_price_cap(exact)
    _require_canonical_caps(configured)
    _require_no_weaker_cap(exact, configured)
    if configured != projected:
        raise RouteConstraintError("configured provider cap is weaker than the exact projection")
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "algorithm": algorithm,
        "exact_pricing": exact,
        "projected_cap": projected,
        "configured_cap": configured,
        "expressible": True,
        "no_weaker": True,
    }
    values["proof_sha256"] = _canonical_sha256(values)
    return ProviderPriceCapProof.model_validate(values)


def evaluate_route_predicates(
    *,
    profile: RoutePredicateProfile,
    constraint: ExactRouteConstraint,
    facts: NormalizedRouteFacts,
) -> RoutePredicateReport:
    """Evaluate exactly one result for every finite route predicate."""

    if not route_constraint_callables_are_pristine():
        raise RouteConstraintError("route predicate callable boundary changed")
    profile = _detached(profile, RoutePredicateProfile, "route predicate profile")
    constraint = _detached(constraint, ExactRouteConstraint, "exact route constraint")
    facts = _detached(facts, NormalizedRouteFacts, "normalized route facts")
    if constraint.profile_sha256 != profile.profile_sha256:
        raise RouteConstraintError("route constraint does not bind the supplied profile")

    results: dict[RoutePredicateId, RoutePredicateResult] = {}

    def record(
        predicate: RoutePredicateId,
        satisfied: bool,
        reason: RoutePredicateReason,
    ) -> None:
        results[predicate] = _predicate_result(predicate, satisfied, reason)

    record(
        RoutePredicateId.EXACT_MODEL_IDENTITY,
        facts.observed_model_id == constraint.exact_model_id,
        RoutePredicateReason.MODEL_IDENTITY_MISMATCH,
    )
    record(
        RoutePredicateId.EXACT_PROVIDER_ENDPOINT,
        facts.observed_provider_endpoint == constraint.provider_endpoint,
        RoutePredicateReason.PROVIDER_ENDPOINT_MISMATCH,
    )
    normalized_display_names = tuple(item.casefold() for item in facts.provider_display_names)
    display_count = normalized_display_names.count(facts.selected_provider_display_name.casefold())
    if not facts.provider_identity_inventory_complete:
        results[RoutePredicateId.PROVIDER_DISPLAY_NAME_INJECTIVITY] = _rejected_result(
            RoutePredicateId.PROVIDER_DISPLAY_NAME_INJECTIVITY,
            RoutePredicateReason.DISPLAY_INVENTORY_INCOMPLETE,
        )
    else:
        record(
            RoutePredicateId.PROVIDER_DISPLAY_NAME_INJECTIVITY,
            display_count == 1,
            RoutePredicateReason.DISPLAY_NAME_NOT_INJECTIVE,
        )
    record(
        RoutePredicateId.OPERATIONAL_STATUS,
        facts.operational_status == profile.accepted_operational_status,
        RoutePredicateReason.OPERATIONAL_STATUS_NOT_ACCEPTED,
    )
    record(
        RoutePredicateId.ZDR_ELIGIBILITY,
        facts.zdr_eligible is profile.require_zdr,
        RoutePredicateReason.ZDR_NOT_ELIGIBLE,
    )
    emitted_checks = (
        (
            RoutePredicateId.EMITS_MAX_TOKENS,
            "max_tokens",
            RoutePredicateReason.MAX_TOKENS_NOT_EMITTED,
        ),
        (
            RoutePredicateId.EMITS_TEMPERATURE,
            "temperature",
            RoutePredicateReason.TEMPERATURE_NOT_EMITTED,
        ),
        (
            RoutePredicateId.EMITS_RESPONSE_FORMAT,
            "response_format",
            RoutePredicateReason.RESPONSE_FORMAT_NOT_EMITTED,
        ),
        (
            RoutePredicateId.EMITS_REASONING,
            "reasoning",
            RoutePredicateReason.REASONING_NOT_EMITTED,
        ),
    )
    for predicate, parameter, reason in emitted_checks:
        if parameter not in facts.emitted_request_parameters:
            results[predicate] = _rejected_result(predicate, reason)
        elif (
            parameter not in facts.model_supported_parameters
            or parameter not in facts.endpoint_supported_parameters
        ):
            results[predicate] = _rejected_result(
                predicate,
                RoutePredicateReason.EMITTED_PARAMETER_SUPPORT_MISMATCH,
            )
        elif facts.emitted_request_parameters != profile.emitted_request_parameters:
            results[predicate] = _rejected_result(
                predicate,
                RoutePredicateReason.EMITTED_PARAMETER_INVENTORY_MISMATCH,
            )
        else:
            results[predicate] = _satisfied_result(predicate)
    marker = profile.native_capability_marker
    record(
        RoutePredicateId.MODEL_STRUCTURED_OUTPUT_MARKER,
        marker in facts.model_supported_parameters,
        RoutePredicateReason.MODEL_NATIVE_MARKER_MISSING,
    )
    record(
        RoutePredicateId.ENDPOINT_STRUCTURED_OUTPUT_MARKER,
        marker in facts.endpoint_supported_parameters,
        RoutePredicateReason.ENDPOINT_NATIVE_MARKER_MISSING,
    )
    record(
        RoutePredicateId.NATIVE_STRUCTURED_OUTPUT_MODE,
        facts.structured_output_mode is profile.required_output_mode,
        RoutePredicateReason.NATIVE_OUTPUT_MODE_MISSING,
    )
    record(
        RoutePredicateId.SINGLETON_EXACT_ROUTE,
        facts.provider_policy_mode == "only"
        and facts.configured_provider_endpoints == (constraint.provider_endpoint,),
        RoutePredicateReason.ROUTE_NOT_SINGLETON,
    )
    record(
        RoutePredicateId.AUTOMATIC_FALLBACK_DISABLED,
        facts.automatic_fallbacks_allowed is profile.allow_automatic_fallbacks,
        RoutePredicateReason.AUTOMATIC_FALLBACK_ENABLED,
    )
    record(
        RoutePredicateId.REASONING_POLICY_BINDING,
        (
            facts.reasoning_policy_sha256 == profile.reasoning_policy_sha256
            and facts.reasoning_role_profile_sha256 == profile.reasoning_role_profile_sha256
            and facts.reasoning_role_binding_sha256 == profile.reasoning_role_binding_sha256
        ),
        RoutePredicateReason.REASONING_POLICY_HASH_MISMATCH,
    )
    record(
        RoutePredicateId.REASONING_CONTROL_BINDING,
        facts.reasoning_control_profile_sha256 == profile.reasoning_control_profile_sha256,
        RoutePredicateReason.REASONING_CONTROL_HASH_MISMATCH,
    )
    record(
        RoutePredicateId.REASONING_CONTROL_VALUES,
        (
            facts.reasoning_mode == profile.reasoning_mode
            and facts.reasoning_effort == profile.reasoning_effort
            and facts.reasoning_max_tokens == profile.reasoning_max_tokens
            and facts.reasoning_exclude is profile.reasoning_exclude
            and facts.reserved_reasoning_tokens == profile.reserved_reasoning_tokens
        ),
        RoutePredicateReason.REASONING_CONTROL_MISMATCH,
    )
    results[RoutePredicateId.REASONING_EFFORT_SUPPORT] = _reasoning_effort_result(
        profile,
        facts,
    )
    record(
        RoutePredicateId.PROMPT_CAPACITY_ENVELOPE,
        facts.max_prompt_tokens >= profile.minimum_prompt_tokens,
        RoutePredicateReason.PROMPT_CAPACITY_INSUFFICIENT,
    )
    if facts.max_completion_tokens < profile.required_output_tokens:
        results[RoutePredicateId.OUTPUT_CAPACITY_ENVELOPE] = _rejected_result(
            RoutePredicateId.OUTPUT_CAPACITY_ENVELOPE,
            RoutePredicateReason.OUTPUT_CAPACITY_INSUFFICIENT,
        )
    elif (
        facts.runtime_required_output_tokens is not None
        and facts.runtime_required_output_tokens != profile.required_output_tokens
    ):
        results[RoutePredicateId.OUTPUT_CAPACITY_ENVELOPE] = _rejected_result(
            RoutePredicateId.OUTPUT_CAPACITY_ENVELOPE,
            RoutePredicateReason.RUNTIME_OUTPUT_TOKENS_MISMATCH,
        )
    else:
        results[RoutePredicateId.OUTPUT_CAPACITY_ENVELOPE] = _satisfied_result(
            RoutePredicateId.OUTPUT_CAPACITY_ENVELOPE
        )
    record(
        RoutePredicateId.CONTEXT_CAPACITY_ENVELOPE,
        facts.context_tokens >= profile.minimum_context_tokens
        and facts.context_tokens
        >= profile.minimum_prompt_tokens + profile.required_completion_tokens,
        RoutePredicateReason.CONTEXT_CAPACITY_INSUFFICIENT,
    )
    record(
        RoutePredicateId.METADATA_COMPLETION_CAPACITY,
        facts.max_completion_tokens_source == profile.required_completion_limit_source
        and facts.max_completion_tokens >= profile.required_completion_tokens,
        RoutePredicateReason.COMPLETION_CAPACITY_NOT_METADATA,
    )
    try:
        project_provider_price_cap(facts.exact_pricing)
    except RouteConstraintError:
        results[RoutePredicateId.PRICE_CAP_EXPRESSIBILITY] = _rejected_result(
            RoutePredicateId.PRICE_CAP_EXPRESSIBILITY,
            RoutePredicateReason.PRICE_CAP_NOT_EXPRESSIBLE,
        )
        results[RoutePredicateId.PRICE_CAP_NO_WEAKER] = _unavailable_result(
            RoutePredicateId.PRICE_CAP_NO_WEAKER,
            RoutePredicateReason.PRICE_CAP_PROOF_UNAVAILABLE,
        )
    else:
        results[RoutePredicateId.PRICE_CAP_EXPRESSIBILITY] = _satisfied_result(
            RoutePredicateId.PRICE_CAP_EXPRESSIBILITY
        )
        if facts.configured_provider_max_price is None:
            results[RoutePredicateId.PRICE_CAP_NO_WEAKER] = _rejected_result(
                RoutePredicateId.PRICE_CAP_NO_WEAKER,
                RoutePredicateReason.PRICE_CAP_MISSING,
            )
        else:
            try:
                prove_provider_price_cap(
                    pricing=facts.exact_pricing,
                    configured_cap=facts.configured_provider_max_price,
                    algorithm=profile.price_cap_algorithm,
                )
            except RouteConstraintError:
                results[RoutePredicateId.PRICE_CAP_NO_WEAKER] = _rejected_result(
                    RoutePredicateId.PRICE_CAP_NO_WEAKER,
                    RoutePredicateReason.PRICE_CAP_WEAKER_THAN_ROUTE,
                )
            else:
                results[RoutePredicateId.PRICE_CAP_NO_WEAKER] = _satisfied_result(
                    RoutePredicateId.PRICE_CAP_NO_WEAKER
                )
    if facts.frozen_live_equivalent is None:
        results[RoutePredicateId.FROZEN_LIVE_EQUIVALENCE] = _unavailable_result(
            RoutePredicateId.FROZEN_LIVE_EQUIVALENCE,
            RoutePredicateReason.LIVE_EQUIVALENCE_UNAVAILABLE,
        )
    else:
        record(
            RoutePredicateId.FROZEN_LIVE_EQUIVALENCE,
            facts.frozen_live_equivalent,
            RoutePredicateReason.LIVE_EQUIVALENCE_MISMATCH,
        )
    if facts.registry_selection_plan_sha256 is None:
        results[RoutePredicateId.REGISTRY_SELECTION_HASH_CUSTODY] = _unavailable_result(
            RoutePredicateId.REGISTRY_SELECTION_HASH_CUSTODY,
            RoutePredicateReason.REGISTRY_SELECTION_CUSTODY_UNAVAILABLE,
        )
    else:
        record(
            RoutePredicateId.REGISTRY_SELECTION_HASH_CUSTODY,
            facts.registry_selection_plan_sha256 == facts.expected_selection_plan_sha256,
            RoutePredicateReason.REGISTRY_SELECTION_CUSTODY_MISMATCH,
        )
    if facts.registry_constraint_sha256 is None or facts.registry_profile_sha256 is None:
        results[RoutePredicateId.REGISTRY_CONSTRAINT_HASH_CUSTODY] = _unavailable_result(
            RoutePredicateId.REGISTRY_CONSTRAINT_HASH_CUSTODY,
            RoutePredicateReason.REGISTRY_CONSTRAINT_CUSTODY_UNAVAILABLE,
        )
    else:
        record(
            RoutePredicateId.REGISTRY_CONSTRAINT_HASH_CUSTODY,
            facts.registry_constraint_sha256 == constraint.constraint_sha256
            and facts.registry_profile_sha256 == profile.profile_sha256,
            RoutePredicateReason.REGISTRY_CONSTRAINT_CUSTODY_MISMATCH,
        )
    results[RoutePredicateId.EMPIRICAL_SCHEMA_CONFORMANCE] = _unavailable_result(
        RoutePredicateId.EMPIRICAL_SCHEMA_CONFORMANCE,
        RoutePredicateReason.EMPIRICAL_SCHEMA_EVIDENCE_UNAVAILABLE,
    )
    results[RoutePredicateId.TOKEN_DETAIL_REPORTING_CONVENTION] = _unavailable_result(
        RoutePredicateId.TOKEN_DETAIL_REPORTING_CONVENTION,
        RoutePredicateReason.TOKEN_DETAIL_CONVENTION_UNAVAILABLE,
    )
    ordered = tuple(results[predicate] for predicate in ROUTE_PREDICATE_IDS)
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "profile_sha256": profile.profile_sha256,
        "constraint_sha256": constraint.constraint_sha256,
        "facts_sha256": facts.facts_sha256,
        "results": ordered,
    }
    values["report_sha256"] = _canonical_sha256(values)
    return RoutePredicateReport.model_validate(values)


def bind_registry_route_facts(
    facts: NormalizedRouteFacts,
    *,
    registry_selection_plan_sha256: str,
    profile: RoutePredicateProfile,
    constraint: ExactRouteConstraint,
) -> NormalizedRouteFacts:
    """Advance discovery facts exactly once into registry custody."""

    if not route_constraint_callables_are_pristine():
        raise RouteConstraintError("route predicate callable boundary changed")
    facts = _detached(facts, NormalizedRouteFacts, "normalized route facts")
    profile = _detached(profile, RoutePredicateProfile, "route predicate profile")
    constraint = _detached(constraint, ExactRouteConstraint, "exact route constraint")
    if (
        facts.registry_selection_plan_sha256 is not None
        or facts.registry_profile_sha256 is not None
        or facts.registry_constraint_sha256 is not None
    ):
        raise RouteConstraintError("route facts already carry registry custody")
    if facts.frozen_live_equivalent is not None:
        raise RouteConstraintError("live route facts cannot acquire registry custody afterward")
    if constraint.profile_sha256 != profile.profile_sha256:
        raise RouteConstraintError("registry route constraint does not bind its profile")
    return _rebuild_route_facts(
        facts,
        registry_selection_plan_sha256=registry_selection_plan_sha256,
        registry_profile_sha256=profile.profile_sha256,
        registry_constraint_sha256=constraint.constraint_sha256,
    )


def _build_runtime_predicate_consumer_authority() -> tuple[
    Callable[..., None],
    Callable[
        [],
        Callable[..., tuple[RoutePredicateReason | None, RoutePredicateReason | None]],
    ],
    Callable[[], bool],
]:
    """Install the runtime predicate consumer once its import cycle has completed."""

    empty_cell = object()
    late_registered_state = object()
    consumer_state: tuple[object, ...] | None = None
    consumer_state_seal: tuple[object, ...] | None = None

    def snapshot(function: FunctionType) -> _RouteConstraintFunctionState:
        closure = function.__closure__
        closure_values: list[tuple[CellType, object]] = []
        for name, cell in zip(
            function.__code__.co_freevars,
            closure or (),
            strict=True,
        ):
            try:
                value = (
                    late_registered_state
                    if name in {"consumer_state", "consumer_state_seal"}
                    else cell.cell_contents
                )
            except ValueError:
                value = empty_cell
            closure_values.append((cell, value))
        attributes = function.__dict__
        return _RouteConstraintFunctionState(
            function=function,
            code=function.__code__,
            defaults=function.__defaults__,
            kwdefaults=function.__kwdefaults__,
            kwdefault_items=tuple(sorted((function.__kwdefaults__ or {}).items())),
            function_globals=function.__globals__,
            closure=closure,
            closure_values=tuple(closure_values),
            attributes=attributes,
            attribute_items=tuple(sorted(attributes.items())),
        )

    def function_state_is_current(state: _RouteConstraintFunctionState) -> bool:
        function = state.function
        current_kwdefaults = function.__kwdefaults__
        current_attributes = function.__dict__
        if (
            type(function) is not FunctionType
            or type(current_kwdefaults) not in {dict, type(None)}
            or type(current_attributes) is not dict
            or function.__code__ is not state.code
            or function.__defaults__ is not state.defaults
            or current_kwdefaults is not state.kwdefaults
            or function.__globals__ is not state.function_globals
            or function.__closure__ is not state.closure
            or current_attributes is not state.attributes
            or len(current_kwdefaults or {}) != len(state.kwdefault_items)
            or any(
                (current_kwdefaults or {}).get(name) is not value
                for name, value in state.kwdefault_items
            )
            or len(current_attributes) != len(state.attribute_items)
            or any(
                current_attributes.get(name) is not value for name, value in state.attribute_items
            )
        ):
            return False
        current_closure = function.__closure__ or ()
        if len(current_closure) != len(state.closure_values):
            return False
        for current_cell, (expected_cell, expected_value) in zip(
            current_closure,
            state.closure_values,
            strict=True,
        ):
            if current_cell is not expected_cell:
                return False
            try:
                current_value = current_cell.cell_contents
            except ValueError:
                current_value = empty_cell
            if expected_value is not late_registered_state and current_value is not expected_value:
                return False
        return True

    def pristine_unchecked() -> bool:
        if consumer_state is None or consumer_state_seal is None:
            return consumer_state is None and consumer_state_seal is None
        if (
            type(consumer_state) is not tuple
            or consumer_state_seal is not consumer_state
            or len(consumer_state) != 4
        ):
            return False
        module_globals, consumer, function_states, referenced_globals = consumer_state
        runtime_module = sys.modules.get("mmaudit.models.route_runtime_evidence")
        return bool(
            type(module_globals) is dict
            and type(consumer) is FunctionType
            and type(function_states) is tuple
            and function_states
            and type(referenced_globals) is tuple
            and runtime_module is not None
            and vars(runtime_module) is module_globals
            and module_globals.get("runtime_predicate_transition_reasons") is consumer
            and all(
                type(state) is _RouteConstraintFunctionState and function_state_is_current(state)
                for state in function_states
            )
            and all(
                type(binding) is tuple
                and len(binding) == 3
                and type(binding[0]) is dict
                and binding[0].get(binding[1]) is binding[2]
                for binding in referenced_globals
            )
        )

    def pristine() -> bool:
        try:
            return pristine_unchecked()
        except BaseException:
            return False

    def register(
        *,
        module_globals: dict[str, object],
        consumer: FunctionType,
    ) -> None:
        nonlocal consumer_state, consumer_state_seal
        runtime_module = sys.modules.get("mmaudit.models.route_runtime_evidence")
        if (
            consumer_state is not None
            or consumer_state_seal is not None
            or type(module_globals) is not dict
            or runtime_module is None
            or vars(runtime_module) is not module_globals
            or type(consumer) is not FunctionType
            or consumer.__module__ != "mmaudit.models.route_runtime_evidence"
            or consumer.__name__ != "runtime_predicate_transition_reasons"
            or consumer.__globals__ is not module_globals
            or module_globals.get("runtime_predicate_transition_reasons") is not consumer
        ):
            raise RuntimeError("runtime predicate consumer registration is invalid")

        roots = [consumer]
        seen = {id(consumer)}
        cursor = 0
        referenced: dict[tuple[int, str], tuple[dict[str, Any], str, object]] = {}
        while cursor < len(roots):
            function = roots[cursor]
            cursor += 1
            for name in function.__code__.co_names:
                if name not in function.__globals__:
                    continue
                value = function.__globals__[name]
                referenced[(id(function.__globals__), name)] = (
                    function.__globals__,
                    name,
                    value,
                )
                if type(value) is FunctionType and id(value) not in seen:
                    seen.add(id(value))
                    roots.append(value)
            for value in function.__defaults__ or ():
                if type(value) is FunctionType and id(value) not in seen:
                    seen.add(id(value))
                    roots.append(value)
            for value in (function.__kwdefaults__ or {}).values():
                if type(value) is FunctionType and id(value) not in seen:
                    seen.add(id(value))
                    roots.append(value)
            for cell in function.__closure__ or ():
                try:
                    value = cell.cell_contents
                except ValueError:
                    continue
                if type(value) is FunctionType and id(value) not in seen:
                    seen.add(id(value))
                    roots.append(value)
            for value in function.__dict__.values():
                if type(value) is FunctionType and id(value) not in seen:
                    seen.add(id(value))
                    roots.append(value)

        installed = (
            module_globals,
            consumer,
            tuple(snapshot(function) for function in roots),
            tuple(referenced.values()),
        )
        consumer_state = installed
        consumer_state_seal = installed
        if not pristine():
            consumer_state = None
            consumer_state_seal = None
            raise RuntimeError("runtime predicate consumer failed to seal")

    def resolve() -> Callable[..., tuple[RoutePredicateReason | None, RoutePredicateReason | None]]:
        if consumer_state is None:
            __import__("mmaudit.models.route_runtime_evidence")
        if not pristine():
            raise RouteConstraintError("runtime predicate consumer authority changed")
        if consumer_state is None:
            raise RouteConstraintError("runtime predicate consumer authority is unavailable")
        consumer = consumer_state[1]
        if type(consumer) is not FunctionType:
            raise RouteConstraintError("runtime predicate consumer authority is unavailable")
        return cast(
            Callable[..., tuple[RoutePredicateReason | None, RoutePredicateReason | None]],
            consumer,
        )

    return register, resolve, pristine


(
    _register_runtime_predicate_consumer,
    _resolve_runtime_predicate_consumer,
    _runtime_predicate_consumer_is_pristine,
) = _build_runtime_predicate_consumer_authority()
del _build_runtime_predicate_consumer_authority


def transition_full_campaign_runtime_predicates(
    report: RoutePredicateReport,
    *,
    runtime_evidence: object,
    qualification_policy: object,
    role: ExactRouteRole,
    model: object,
    discovery_manifest: object,
    discovery_evidence: object,
    facts: NormalizedRouteFacts,
) -> RoutePredicateReport:
    """Promote runtime predicates only through an opaque verified evidence capability.

    The imported consumer replays process-local capability custody and derives both outcomes;
    callers cannot supply truth booleans or dispositions.  Keeping this transition separate
    leaves the discovery evaluator and every existing sealed discovery artifact unchanged.
    """

    if not route_constraint_callables_are_pristine():
        raise RouteConstraintError("route predicate callable boundary changed")
    if runtime_evidence is None or type(role) is not ExactRouteRole:
        raise RouteConstraintError("runtime predicate transition lacks verified evidence")
    try:
        runtime_predicate_consumer = _resolve_runtime_predicate_consumer()
        empirical_schema_reason, token_detail_reason = runtime_predicate_consumer(
            runtime_evidence,
            qualification_policy=qualification_policy,
            role=role,
            model=model,
            manifest=discovery_manifest,
            evidence=discovery_evidence,
            facts=facts,
            report=report,
        )
    except RouteConstraintError:
        raise
    except (TypeError, ValueError) as exc:
        raise RouteConstraintError("runtime predicate evidence validation failed") from exc
    report = _detached(report, RoutePredicateReport, "route predicate report")
    allowed_failure_reasons = frozenset(
        {
            RoutePredicateReason.RUNTIME_EVIDENCE_INVALID,
            RoutePredicateReason.RUNTIME_EVIDENCE_BINDING_MISMATCH,
            RoutePredicateReason.RUNTIME_EVIDENCE_STALE,
        }
    )
    for reason in (empirical_schema_reason, token_detail_reason):
        if reason is not None and (
            type(reason) is not RoutePredicateReason or reason not in allowed_failure_reasons
        ):
            raise RouteConstraintError("runtime predicate transition reason is invalid")
    by_id = {result.predicate_id: result for result in report.results}
    expected_unavailable = {
        RoutePredicateId.EMPIRICAL_SCHEMA_CONFORMANCE: (
            RoutePredicateReason.EMPIRICAL_SCHEMA_EVIDENCE_UNAVAILABLE
        ),
        RoutePredicateId.TOKEN_DETAIL_REPORTING_CONVENTION: (
            RoutePredicateReason.TOKEN_DETAIL_CONVENTION_UNAVAILABLE
        ),
    }
    if any(
        by_id[predicate].disposition is not RoutePredicateDisposition.UNAVAILABLE
        or by_id[predicate].reason is not reason
        for predicate, reason in expected_unavailable.items()
    ):
        raise RouteConstraintError("runtime predicates were already transitioned")
    replacements = {
        RoutePredicateId.EMPIRICAL_SCHEMA_CONFORMANCE: (
            _satisfied_result(RoutePredicateId.EMPIRICAL_SCHEMA_CONFORMANCE)
            if empirical_schema_reason is None
            else _rejected_result(
                RoutePredicateId.EMPIRICAL_SCHEMA_CONFORMANCE,
                empirical_schema_reason,
            )
        ),
        RoutePredicateId.TOKEN_DETAIL_REPORTING_CONVENTION: (
            _satisfied_result(RoutePredicateId.TOKEN_DETAIL_REPORTING_CONVENTION)
            if token_detail_reason is None
            else _rejected_result(
                RoutePredicateId.TOKEN_DETAIL_REPORTING_CONVENTION,
                token_detail_reason,
            )
        ),
    }
    ordered = tuple(replacements.get(result.predicate_id, result) for result in report.results)
    values: dict[str, Any] = {
        "schema_version": report.schema_version,
        "profile_sha256": report.profile_sha256,
        "constraint_sha256": report.constraint_sha256,
        "facts_sha256": report.facts_sha256,
        "results": ordered,
    }
    values["report_sha256"] = _canonical_sha256(values)
    return RoutePredicateReport.model_validate(values)


def bind_live_route_facts(
    facts: NormalizedRouteFacts,
    *,
    frozen_live_equivalent: bool,
) -> NormalizedRouteFacts:
    """Advance registry facts exactly once into a frozen/live equivalence result."""

    if not route_constraint_callables_are_pristine():
        raise RouteConstraintError("route predicate callable boundary changed")
    facts = _detached(facts, NormalizedRouteFacts, "normalized route facts")
    if type(frozen_live_equivalent) is not bool:
        raise RouteConstraintError("frozen/live equivalence has the wrong exact type")
    if (
        facts.registry_selection_plan_sha256 is None
        or facts.registry_profile_sha256 is None
        or facts.registry_constraint_sha256 is None
    ):
        raise RouteConstraintError("live route facts require complete registry custody")
    if facts.frozen_live_equivalent is not None:
        raise RouteConstraintError("route facts already carry a live equivalence result")
    return _rebuild_route_facts(
        facts,
        frozen_live_equivalent=frozen_live_equivalent,
    )


def bind_runtime_route_facts(
    facts: NormalizedRouteFacts,
    *,
    required_output_tokens: int,
) -> NormalizedRouteFacts:
    """Bind the runtime request output envelope before route admission."""

    if not route_constraint_callables_are_pristine():
        raise RouteConstraintError("route predicate callable boundary changed")
    facts = _detached(facts, NormalizedRouteFacts, "normalized route facts")
    if type(required_output_tokens) is not int or not 256 <= required_output_tokens <= 65_536:
        raise RouteConstraintError("runtime required output tokens are invalid")
    if (
        facts.registry_selection_plan_sha256 is None
        or facts.registry_profile_sha256 is None
        or facts.registry_constraint_sha256 is None
    ):
        raise RouteConstraintError("runtime route facts require complete registry custody")
    if facts.runtime_required_output_tokens is not None:
        raise RouteConstraintError("route facts already carry a runtime output envelope")
    return _rebuild_route_facts(
        facts,
        runtime_required_output_tokens=required_output_tokens,
    )


def require_route_predicates(
    report: RoutePredicateReport,
    *,
    purpose: RouteConstraintPurpose,
) -> RoutePredicateReport:
    """Require the exact dispositions for one publication or admission purpose."""

    if not route_constraint_callables_are_pristine():
        raise RouteConstraintError("route predicate callable boundary changed")
    report = _detached(report, RoutePredicateReport, "route predicate report")
    if type(purpose) is not RouteConstraintPurpose:
        raise RouteConstraintError("route predicate purpose has the wrong exact type")
    required = _PURPOSE_REQUIRED[purpose]
    failures = tuple(
        result
        for result in report.results
        if result.disposition is RoutePredicateDisposition.REJECTED
        or (
            result.predicate_id in required
            and result.disposition is not RoutePredicateDisposition.SATISFIED
        )
    )
    if failures:
        raise RoutePredicateRequirementError(purpose, failures)
    return report


def _rebuild_route_facts(
    facts: NormalizedRouteFacts,
    **updates: object,
) -> NormalizedRouteFacts:
    values = facts.model_dump(mode="python", exclude={"facts_sha256"})
    if not updates or not set(updates).issubset(
        {
            "registry_selection_plan_sha256",
            "registry_profile_sha256",
            "registry_constraint_sha256",
            "frozen_live_equivalent",
            "runtime_required_output_tokens",
        }
    ):
        raise RouteConstraintError("route facts transition contains an unknown field")
    values.update(updates)
    values["facts_sha256"] = _canonical_sha256(values)
    try:
        return NormalizedRouteFacts.model_validate(values)
    except ValueError as exc:
        raise RouteConstraintError("route facts transition is invalid") from exc


def _reasoning_effort_result(
    profile: RoutePredicateProfile,
    facts: NormalizedRouteFacts,
) -> RoutePredicateResult:
    _, state, effective, _ = resolve_effective_reasoning_effort_inventory(
        endpoint_efforts=facts.endpoint_supported_reasoning_efforts,
        model_efforts=facts.model_supported_reasoning_efforts,
    )
    if state == "UNAVAILABLE":
        return _unavailable_result(
            RoutePredicateId.REASONING_EFFORT_SUPPORT,
            RoutePredicateReason.REASONING_EFFORT_INVENTORY_UNAVAILABLE,
        )
    if state == "EMPTY":
        return _rejected_result(
            RoutePredicateId.REASONING_EFFORT_SUPPORT,
            RoutePredicateReason.REASONING_EFFORT_INVENTORY_EMPTY,
        )
    if state == "CONTRADICTORY":
        return _rejected_result(
            RoutePredicateId.REASONING_EFFORT_SUPPORT,
            RoutePredicateReason.REASONING_EFFORT_INVENTORY_CONTRADICTORY,
        )
    assert effective is not None
    if profile.reasoning_effort not in effective:
        return _rejected_result(
            RoutePredicateId.REASONING_EFFORT_SUPPORT,
            RoutePredicateReason.REASONING_EFFORT_UNSUPPORTED,
        )
    return _satisfied_result(RoutePredicateId.REASONING_EFFORT_SUPPORT)


def _predicate_result(
    predicate: RoutePredicateId,
    satisfied: bool,
    reason: RoutePredicateReason,
) -> RoutePredicateResult:
    return _satisfied_result(predicate) if satisfied else _rejected_result(predicate, reason)


def _satisfied_result(predicate: RoutePredicateId) -> RoutePredicateResult:
    return RoutePredicateResult(
        predicate_id=predicate,
        disposition=RoutePredicateDisposition.SATISFIED,
        reason=RoutePredicateReason.SATISFIED,
    )


def _rejected_result(
    predicate: RoutePredicateId,
    reason: RoutePredicateReason,
) -> RoutePredicateResult:
    return RoutePredicateResult(
        predicate_id=predicate,
        disposition=RoutePredicateDisposition.REJECTED,
        reason=reason,
    )


def _unavailable_result(
    predicate: RoutePredicateId,
    reason: RoutePredicateReason,
) -> RoutePredicateResult:
    return RoutePredicateResult(
        predicate_id=predicate,
        disposition=RoutePredicateDisposition.UNAVAILABLE,
        reason=reason,
    )


def _require_no_weaker_cap(
    pricing: tuple[ExactRoutePrice, ...],
    configured: tuple[ProviderPriceCap, ...],
) -> None:
    _require_canonical_pricing(pricing)
    _require_canonical_caps(configured)
    exact = {item.component: Decimal(item.unit_price) for item in pricing}
    caps = {item.component: Decimal(str(item.value)) for item in configured}
    prompt = exact.get(RoutePriceComponent.PROMPT)
    completion = exact.get(RoutePriceComponent.COMPLETION)
    if prompt is None or completion is None:
        raise RouteConstraintError("route pricing omits a required component")
    for component, price in exact.items():
        if component in _UNENFORCEABLE_VARIABLE_PRICE_FIELDS:
            raise RouteConstraintError("route variable pricing is not provider-capped")
        if component is RoutePriceComponent.INPUT_CACHE_READ:
            prompt_cap = caps.get(ProviderMaxPriceComponent.PROMPT)
            if price > prompt or prompt_cap is None:
                raise RouteConstraintError("route cache-read price lacks a prompt cap")
            continue
        try:
            cap_component = ProviderMaxPriceComponent(component.value)
        except ValueError:
            if price != 0:
                raise RouteConstraintError("route nonzero price is not provider-capped") from None
            continue
        cap = caps.get(cap_component)
        if cap is None:
            raise RouteConstraintError("configured provider cap omits a route component")
        if cap_component in _PER_MILLION_PRICE_FIELDS:
            cap /= Decimal(1_000_000)
        if cap < price:
            raise RouteConstraintError("configured provider cap is weaker than route pricing")


def _require_canonical_pricing(pricing: tuple[ExactRoutePrice, ...]) -> None:
    if (
        not 2 <= len(pricing) <= len(RoutePriceComponent)
        or any(type(item) is not ExactRoutePrice for item in pricing)
        or pricing != tuple(sorted(pricing, key=lambda item: item.component.value))
        or len({item.component for item in pricing}) != len(pricing)
    ):
        raise RouteConstraintError("exact route pricing is incomplete or noncanonical")


def _require_canonical_caps(caps: tuple[ProviderPriceCap, ...]) -> None:
    if (
        not 2 <= len(caps) <= len(_ROUTER_MAX_PRICE_FIELDS)
        or any(type(item) is not ProviderPriceCap for item in caps)
        or caps != tuple(sorted(caps, key=lambda item: item.component.value))
        or len({item.component for item in caps}) != len(caps)
    ):
        raise RouteConstraintError("provider price caps are incomplete or noncanonical")


def _canonical_price(value: str) -> str:
    if not isinstance(value, str) or _DECIMAL_PRICE_PATTERN.fullmatch(value) is None:
        raise ValueError("route price is not a bounded decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError("route price is invalid") from exc
    if not parsed.is_finite() or parsed < 0:
        raise ValueError("route price must be finite and nonnegative")
    if parsed == 0:
        return "0"
    canonical = format(parsed, "f")
    if "." in canonical:
        canonical = canonical.rstrip("0").rstrip(".")
    return canonical


def _detached(value: Any, expected: type[Any], label: str) -> Any:
    _require_exact_type(value, expected, label)
    try:
        detached = expected.model_validate_json(value.model_dump_json(), strict=True)
    except (AttributeError, TypeError, ValueError) as exc:
        raise RouteConstraintError(f"{label} failed detached validation") from exc
    if detached != value:
        raise RouteConstraintError(f"{label} changed across detached validation")
    return detached


def _require_exact_type(value: Any, expected: type[Any], label: str) -> None:
    if type(value) is not expected:
        raise RouteConstraintError(f"{label} has the wrong exact type")


def _require_self_hash(model: BaseModel, field: str) -> None:
    expected = _canonical_sha256(model.model_dump(mode="json", exclude={field}))
    if getattr(model, field) != expected:
        raise ValueError(f"{field} does not match canonical route evidence")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=_canonical_json_default,
        ).encode("utf-8")
    ).hexdigest()


def _canonical_json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, StrEnum):
        return value.value
    raise TypeError(f"unsupported canonical route value: {type(value).__name__}")


def _build_route_constraint_callable_guard() -> Callable[[], bool]:
    """Freeze the complete provider-free predicate helper and policy surface."""

    empty_cell = object()
    late_registered_state = object()
    module_globals = globals()
    root_queue = list(
        value
        for name, value in module_globals.items()
        if type(value) is FunctionType
        and value.__module__ == __name__
        and name != "_build_route_constraint_callable_guard"
    )
    root_queue.extend(
        cast(
            tuple[FunctionType, FunctionType],
            (output_mode_request_parameters, require_exact_openrouter_model_id),
        )
    )
    roots_list: list[FunctionType] = []
    seen: set[int] = set()
    while root_queue:
        function = root_queue.pop()
        if id(function) in seen:
            continue
        seen.add(id(function))
        roots_list.append(function)
        for name in function.__code__.co_names:
            if name not in function.__globals__:
                continue
            value = function.__globals__[name]
            if type(value) is FunctionType:
                root_queue.append(value)
        for value in function.__defaults__ or ():
            if type(value) is FunctionType:
                root_queue.append(value)
        for value in (function.__kwdefaults__ or {}).values():
            if type(value) is FunctionType:
                root_queue.append(value)
        for cell in function.__closure__ or ():
            try:
                value = cell.cell_contents
            except ValueError:
                continue
            if type(value) is FunctionType:
                root_queue.append(value)
        for value in function.__dict__.values():
            if type(value) is FunctionType:
                root_queue.append(value)
    guarded_types = tuple(
        value
        for value in module_globals.values()
        if isinstance(value, type) and value.__module__ == __name__
    )
    descriptor_bindings: list[tuple[type[Any], str, object]] = []
    descriptor_functions: list[FunctionType] = []
    for guarded_type in guarded_types:
        for name, descriptor in vars(guarded_type).items():
            functions: tuple[FunctionType, ...]
            if type(descriptor) is FunctionType:
                functions = (descriptor,)
            elif type(descriptor) in {classmethod, staticmethod}:
                functions = (cast(FunctionType, cast(Any, descriptor).__func__),)
            elif type(descriptor) is property:
                functions = tuple(
                    function
                    for function in (descriptor.fget, descriptor.fset, descriptor.fdel)
                    if type(function) is FunctionType
                )
            else:
                functions = ()
            if functions:
                descriptor_bindings.append((guarded_type, name, descriptor))
                descriptor_functions.extend(functions)
    for function in descriptor_functions:
        if id(function) not in seen:
            roots_list.append(function)
            seen.add(id(function))
    roots = tuple(roots_list)
    aliases = tuple(
        (name, function)
        for name, function in module_globals.items()
        if type(function) is FunctionType and function in roots
    )
    descriptor_bindings_tuple = tuple(descriptor_bindings)
    referenced_globals = tuple(
        sorted(
            {
                name: module_globals[name]
                for function in roots
                for name in function.__code__.co_names
                if name in module_globals
            }.items()
        )
    )
    fixed_globals = (
        ("ROUTE_PREDICATE_IDS", ROUTE_PREDICATE_IDS),
        ("_FAILURE_REASONS_BY_PREDICATE", _FAILURE_REASONS_BY_PREDICATE),
        ("_UNAVAILABLE_REASONS", _UNAVAILABLE_REASONS),
        ("_LATE_LIVE_PREDICATES", _LATE_LIVE_PREDICATES),
        ("_REGISTRY_PREDICATES", _REGISTRY_PREDICATES),
        ("_SEPARATE_RUNTIME_PREDICATES", _SEPARATE_RUNTIME_PREDICATES),
        ("_DISCOVERY_REQUIRED", _DISCOVERY_REQUIRED),
        ("_PURPOSE_REQUIRED", _PURPOSE_REQUIRED),
        ("RoutePredicateId", RoutePredicateId),
        ("RoutePredicateDisposition", RoutePredicateDisposition),
        ("RoutePredicateReason", RoutePredicateReason),
        ("RouteConstraintPurpose", RouteConstraintPurpose),
        ("RoutePredicateProfile", RoutePredicateProfile),
        ("ExactRouteConstraint", ExactRouteConstraint),
        ("NormalizedRouteFacts", NormalizedRouteFacts),
        ("RoutePredicateResult", RoutePredicateResult),
        ("RoutePredicateReport", RoutePredicateReport),
        ("output_mode_request_parameters", output_mode_request_parameters),
        ("require_exact_openrouter_model_id", require_exact_openrouter_model_id),
    )
    fixed_mapping_contents: tuple[tuple[Mapping[Any, Any], tuple[tuple[Any, Any], ...]], ...] = (
        (
            _FAILURE_REASONS_BY_PREDICATE,
            tuple(_FAILURE_REASONS_BY_PREDICATE.items()),
        ),
        (_PURPOSE_REQUIRED, tuple(_PURPOSE_REQUIRED.items())),
    )
    fixed_enum_states: tuple[tuple[Any, ...], ...] = tuple(
        (
            value,
            value._member_map_,
            tuple(value._member_map_.items()),
            value._value2member_map_,
            tuple(value._value2member_map_.items()),
            value._member_names_,
            tuple(value._member_names_),
        )
        for value in (
            RoutePredicateId,
            RoutePredicateDisposition,
            RoutePredicateReason,
            RouteConstraintPurpose,
            ExactRouteRole,
            ProviderPriceCapAlgorithm,
            RoutePriceComponent,
            ProviderMaxPriceComponent,
            StructuredOutputMode,
        )
        if isinstance(value, type) and issubclass(value, Enum)
    )

    def snapshot(function: FunctionType) -> _RouteConstraintFunctionState:
        closure = function.__closure__
        closure_values: list[tuple[CellType, object]] = []
        for name, cell in zip(
            function.__code__.co_freevars,
            closure or (),
            strict=True,
        ):
            try:
                value = (
                    late_registered_state
                    if name in {"consumer_state", "consumer_state_seal"}
                    else cell.cell_contents
                )
            except ValueError:
                value = empty_cell
            closure_values.append((cell, value))
        attributes = function.__dict__
        return _RouteConstraintFunctionState(
            function=function,
            code=function.__code__,
            defaults=function.__defaults__,
            kwdefaults=function.__kwdefaults__,
            kwdefault_items=tuple(sorted((function.__kwdefaults__ or {}).items())),
            function_globals=function.__globals__,
            closure=closure,
            closure_values=tuple(closure_values),
            attributes=attributes,
            attribute_items=tuple(sorted(attributes.items())),
        )

    states = tuple(snapshot(function) for function in roots)
    aliases_seal = aliases
    descriptor_bindings_seal = descriptor_bindings_tuple
    empty_cell_seal = empty_cell
    fixed_enum_states_seal = fixed_enum_states
    fixed_globals_seal = fixed_globals
    fixed_mapping_contents_seal = fixed_mapping_contents
    module_globals_seal = module_globals
    referenced_globals_seal = referenced_globals
    states_seal = states

    def pristine() -> bool:
        if (
            aliases is not aliases_seal
            or descriptor_bindings_tuple is not descriptor_bindings_seal
            or empty_cell is not empty_cell_seal
            or fixed_enum_states is not fixed_enum_states_seal
            or fixed_globals is not fixed_globals_seal
            or fixed_mapping_contents is not fixed_mapping_contents_seal
            or module_globals is not module_globals_seal
            or referenced_globals is not referenced_globals_seal
            or states is not states_seal
        ):
            return False
        if module_globals.get("route_constraint_callables_are_pristine") is not pristine:
            return False
        if any(module_globals.get(name) is not expected for name, expected in aliases):
            return False
        if any(
            vars(guarded_type).get(name) is not descriptor
            for guarded_type, name, descriptor in descriptor_bindings_tuple
        ):
            return False
        if any(module_globals.get(name) is not expected for name, expected in fixed_globals):
            return False
        if any(module_globals.get(name) is not expected for name, expected in referenced_globals):
            return False
        for mapping, expected_items in fixed_mapping_contents:
            current_items = tuple(mapping.items())
            if len(current_items) != len(expected_items) or any(
                current_key is not expected_key or current_value is not expected_value
                for (current_key, current_value), (expected_key, expected_value) in zip(
                    current_items,
                    expected_items,
                    strict=True,
                )
            ):
                return False
        for (
            enum_type,
            member_map,
            expected_member_items,
            value_map,
            expected_value_items,
            member_names,
            expected_member_names,
        ) in fixed_enum_states:
            current_member_map = getattr(enum_type, "_member_map_", None)
            current_value_map = getattr(enum_type, "_value2member_map_", None)
            current_member_names = getattr(enum_type, "_member_names_", None)
            if (
                current_member_map is not member_map
                or current_value_map is not value_map
                or current_member_names is not member_names
                or type(current_member_map) is not dict
                or type(current_value_map) is not dict
                or type(current_member_names) is not list
                or len(current_member_map) != len(expected_member_items)
                or any(
                    current_member_map.get(name) is not member
                    for name, member in expected_member_items
                )
                or len(current_value_map) != len(expected_value_items)
                or any(
                    current_value_map.get(value) is not member
                    for value, member in expected_value_items
                )
                or tuple(current_member_names) != expected_member_names
            ):
                return False
        for state in states:
            function = state.function
            if (
                function.__code__ is not state.code
                or function.__defaults__ is not state.defaults
                or function.__kwdefaults__ is not state.kwdefaults
                or function.__globals__ is not state.function_globals
                or function.__closure__ is not state.closure
                or function.__dict__ is not state.attributes
            ):
                return False
            current_kwdefaults = function.__kwdefaults__ or {}
            if len(current_kwdefaults) != len(state.kwdefault_items) or any(
                current_kwdefaults.get(name) is not value for name, value in state.kwdefault_items
            ):
                return False
            current_attributes = function.__dict__
            if len(current_attributes) != len(state.attribute_items) or any(
                current_attributes.get(name) is not value for name, value in state.attribute_items
            ):
                return False
            current_closure = function.__closure__ or ()
            if len(current_closure) != len(state.closure_values):
                return False
            for current_cell, (expected_cell, expected_value) in zip(
                current_closure,
                state.closure_values,
                strict=True,
            ):
                if current_cell is not expected_cell:
                    return False
                try:
                    current_value = current_cell.cell_contents
                except ValueError:
                    current_value = empty_cell
                if (
                    expected_value is not late_registered_state
                    and current_value is not expected_value
                ):
                    return False
        try:
            return bool(_runtime_predicate_consumer_is_pristine())
        except BaseException:
            return False

    return pristine


route_constraint_callables_are_pristine = _build_route_constraint_callable_guard()
del _build_route_constraint_callable_guard
if not route_constraint_callables_are_pristine():
    raise RuntimeError("route predicate callable boundary failed its initial integrity check")


__all__ = [
    "ROUTE_PREDICATE_IDS",
    "ExactRouteConstraint",
    "ExactRoutePrice",
    "ExactRouteRole",
    "NormalizedRouteFacts",
    "ProviderMaxPriceComponent",
    "ProviderPriceCap",
    "ProviderPriceCapAlgorithm",
    "ProviderPriceCapProof",
    "RouteConstraintError",
    "RouteConstraintPurpose",
    "RoutePredicateDisposition",
    "RoutePredicateId",
    "RoutePredicateProfile",
    "RoutePredicateReason",
    "RoutePredicateReport",
    "RoutePredicateRequirementError",
    "RoutePredicateResult",
    "RoutePriceComponent",
    "bind_live_route_facts",
    "bind_registry_route_facts",
    "bind_runtime_route_facts",
    "evaluate_route_predicates",
    "normalize_exact_route_pricing",
    "project_provider_price_cap",
    "project_route_emitted_request_parameters",
    "prove_provider_price_cap",
    "require_route_predicates",
    "route_constraint_callables_are_pristine",
    "transition_full_campaign_runtime_predicates",
]
