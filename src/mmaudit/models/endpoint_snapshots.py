"""Fail-closed validation of OpenRouter endpoint metadata snapshots.

The validator accepts already-fetched provider metadata and emits only a bounded,
allowlisted projection. Unknown provider-controlled fields are neither retained nor
hashed. This keeps the evidence suitable for public manifests while preserving the
exact endpoint pricing and capability data needed to prove a request cost ceiling.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

import mmaudit.models.price_lexemes as price_lexemes_module
from mmaudit.models.identifiers import is_exact_openrouter_model_id
from mmaudit.models.output_modes import (
    StructuredOutputMode,
    mutually_supported_output_modes,
    output_mode_request_parameters,
    structured_output_parameters,
    supported_output_modes,
)
from mmaudit.models.price_lexemes import (
    MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
    ZDR_ENDPOINT_PRICE_LEXEME_LAYOUT,
    OpenRouterJSONPath,
    OpenRouterPriceLexemeLayout,
    captured_openrouter_json_number_decimal,
    captured_openrouter_json_number_matches_path,
    captured_openrouter_json_number_raw,
    openrouter_json_number_is_price_path,
    price_lexeme_callables_are_pristine,
    revoke_captured_openrouter_json_number,
)
from mmaudit.models.reasoning import (
    REASONING_EFFORT_ORDER,
    ReasoningControlProfile,
    ReasoningEffort,
    ReasoningPolicyArtifact,
)
from mmaudit.models.route_constraints import (
    ExactRouteConstraint,
    ExactRoutePriceTier,
    ExactRoutePricingSchedule,
    NormalizedRouteFacts,
    RouteConstraintError,
    RouteConstraintPurpose,
    RoutePredicateProfile,
    RoutePredicateReport,
    RoutePredicateRequirementError,
    evaluate_route_predicates,
    normalize_exact_route_pricing,
    project_provider_price_cap,
    project_route_emitted_request_parameters,
    require_route_predicates,
)

_MODEL_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
_ENDPOINT_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"
_PROVIDER_NAME_MAX_LENGTH = 128
_PRICING_FIELD_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_DECIMAL_PRICE_PATTERN = re.compile(r"(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,36})?\Z")
_CANONICAL_DECIMAL_PRICE_SCHEMA_PATTERN = (
    r"^(?:0|[1-9][0-9]{0,11}|(?:0|[1-9][0-9]{0,11})\.[0-9]{0,35}[1-9])$"
)
_BASE_REQUEST_PARAMETERS = frozenset(
    {
        "max_tokens",
        "temperature",
    }
)
_OPERATIONAL_TEXT_STATUSES = frozenset(
    {
        "active",
        "available",
        "healthy",
        "online",
        "operational",
    }
)
_MAX_ENDPOINTS = 2_048
_MAX_PARAMETERS = 256
_MAX_PRICING_FIELDS = 64
_MAX_PRICING_OVERRIDES = 64
_MAX_PRICING_OVERRIDE_PROMPT_TOKENS = 2**31 - 1
_SNAPSHOT_SCHEMA_VERSION = "1.0"
_NON_BILLABLE_PRICING_METADATA = frozenset({"discount"})
_PRICING_OVERRIDE_CONDITIONS = frozenset({"min_prompt_tokens", "utc_days", "utc_end", "utc_start"})
_SUPPORTED_PRICING_OVERRIDE_FIELDS = frozenset(
    {
        "audio",
        "completion",
        "input_audio_cache",
        "input_cache_read",
        "input_cache_write",
        "input_cache_write_1h",
        "prompt",
    }
)
_PRICING_OVERRIDE_SCHEMA: dict[str, Any] = {
    "propertyNames": {"enum": sorted(_SUPPORTED_PRICING_OVERRIDE_FIELDS)},
    "additionalProperties": {
        "type": "string",
        "minLength": 1,
        "maxLength": 49,
        "pattern": _CANONICAL_DECIMAL_PRICE_SCHEMA_PATTERN,
    },
}

ReasoningParameterSupport = Literal["supported", "unsupported", "unknown"]


class EndpointSnapshotValidationError(ValueError):
    """Raised when endpoint metadata cannot prove the configured routing policy."""


class OpenRouterPricingOverrideTier(BaseModel):
    """One ordered, threshold-conditional partial endpoint price replacement."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    min_prompt_tokens: int = Field(
        ge=0,
        le=_MAX_PRICING_OVERRIDE_PROMPT_TOKENS,
    )
    prices: dict[str, str] = Field(
        min_length=1,
        max_length=_MAX_PRICING_FIELDS,
        json_schema_extra=_PRICING_OVERRIDE_SCHEMA,
    )

    @model_validator(mode="after")
    def tier_is_canonical(self) -> OpenRouterPricingOverrideTier:
        if tuple(self.prices) != tuple(sorted(self.prices)):
            raise ValueError("endpoint pricing override fields must be sorted")
        for field, value in self.prices.items():
            if (
                not _PRICING_FIELD_PATTERN.fullmatch(field)
                or field not in _SUPPORTED_PRICING_OVERRIDE_FIELDS
                or field in _NON_BILLABLE_PRICING_METADATA
                or field == "overrides"
                or field in _PRICING_OVERRIDE_CONDITIONS
            ):
                raise ValueError("endpoint pricing override contains an invalid price field")
            if _canonical_price(value) != value:
                raise ValueError("endpoint pricing override price is not canonically encoded")
        return self


class OpenRouterConstrainedRouteContext(BaseModel):
    """Selection-bound facts required before a constrained snapshot can be sealed."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    route_predicate_profile: RoutePredicateProfile
    exact_route_constraint: ExactRouteConstraint
    expected_selection_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reasoning_policy: ReasoningPolicyArtifact
    reasoning_request_role: str = Field(min_length=1, max_length=200)
    model_supported_parameters: tuple[str, ...] = Field(max_length=_MAX_PARAMETERS)
    model_supported_reasoning_efforts: tuple[ReasoningEffort, ...] | None = Field(
        default=None,
        max_length=len(REASONING_EFFORT_ORDER),
    )
    automatic_fallbacks_allowed: bool

    @field_validator("model_supported_parameters")
    @classmethod
    def model_parameters_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("constrained model parameters must be sorted and unique")
        return value

    @field_validator("model_supported_reasoning_efforts")
    @classmethod
    def model_efforts_are_canonical(
        cls,
        value: tuple[ReasoningEffort, ...] | None,
    ) -> tuple[ReasoningEffort, ...] | None:
        if value is None:
            return None
        selected = frozenset(value)
        if value != tuple(effort for effort in REASONING_EFFORT_ORDER if effort in selected):
            raise ValueError("constrained model reasoning efforts must be canonical")
        return value

    @model_validator(mode="after")
    def context_is_exact_and_self_validating(self) -> OpenRouterConstrainedRouteContext:
        if (
            self.exact_route_constraint.profile_sha256
            != self.route_predicate_profile.profile_sha256
        ):
            raise ValueError("constrained route does not bind its predicate profile")
        try:
            self.reasoning_policy.role_policy_for_request(self.reasoning_request_role)
        except ValueError as exc:
            raise ValueError("constrained route reasoning request role is invalid") from exc
        return self


class OpenRouterEndpointEvidence(BaseModel):
    """Canonical evidence for one exact configured model endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    exact_model_id: str = Field(pattern=_MODEL_ID_PATTERN)
    provider_endpoint: str = Field(pattern=_ENDPOINT_ID_PATTERN)
    endpoint_tag: str | None = Field(default=None, pattern=_ENDPOINT_ID_PATTERN)
    endpoint_slug: str | None = Field(default=None, pattern=_ENDPOINT_ID_PATTERN)
    provider_name: str = Field(min_length=1, max_length=_PROVIDER_NAME_MAX_LENGTH)
    operational: bool
    operational_status: str = Field(min_length=1, max_length=32)
    zdr_eligible: bool | None
    supported_parameters: tuple[str, ...] = Field(max_length=_MAX_PARAMETERS)
    supported_reasoning_efforts: tuple[ReasoningEffort, ...] | None = Field(
        default=None,
        max_length=len(REASONING_EFFORT_ORDER),
    )
    required_request_parameters: tuple[str, ...] = Field(min_length=2, max_length=32)
    structured_output_parameters: tuple[str, ...] = Field(max_length=3)
    supported_output_modes: tuple[StructuredOutputMode, ...] = Field(
        min_length=1,
        max_length=3,
    )
    structured_output_mode: StructuredOutputMode
    output_capability_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    context_length: int = Field(gt=0)
    max_prompt_tokens: int = Field(gt=0)
    max_prompt_tokens_source: Literal["metadata", "context_limit"]
    max_completion_tokens: int = Field(gt=0)
    max_completion_tokens_source: Literal["metadata", "context_limit"]
    pricing: dict[str, str] = Field(min_length=2, max_length=_MAX_PRICING_FIELDS)
    pricing_overrides: tuple[OpenRouterPricingOverrideTier, ...] = Field(
        default_factory=tuple,
        min_length=1,
        max_length=_MAX_PRICING_OVERRIDES,
        exclude_if=lambda value: not value,
    )
    tiered_pricing_cost_projection: ExactRoutePricingSchedule | Literal["unavailable"] | None = (
        Field(
            default=None,
            exclude_if=lambda value: value is None,
        )
    )
    pricing_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    endpoint_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    zdr_endpoint_snapshot_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )

    @model_validator(mode="after")
    def evidence_is_canonical_and_self_bound(self) -> OpenRouterEndpointEvidence:
        _validate_exact_model_id(self.exact_model_id)
        if self.endpoint_tag is None and self.endpoint_slug is None:
            raise ValueError("endpoint evidence requires a tag or slug")
        if self.provider_endpoint not in {self.endpoint_tag, self.endpoint_slug}:
            raise ValueError("configured endpoint does not match its exact tag or slug")
        if _provider_display_name(self.provider_name) != self.provider_name:
            raise ValueError("provider display name is not canonical")
        if self.operational is not True:
            raise ValueError("endpoint evidence cannot credit a non-operational endpoint")
        if self.supported_parameters != tuple(sorted(set(self.supported_parameters))):
            raise ValueError("supported endpoint parameters must be sorted and unique")
        if self.supported_reasoning_efforts is not None:
            selected_efforts = frozenset(self.supported_reasoning_efforts)
            canonical_efforts = tuple(
                effort for effort in REASONING_EFFORT_ORDER if effort in selected_efforts
            )
            if (
                len(selected_efforts) != len(self.supported_reasoning_efforts)
                or self.supported_reasoning_efforts != canonical_efforts
                or "reasoning" not in self.supported_parameters
            ):
                raise ValueError(
                    "endpoint reasoning efforts must be canonical and parameter-supported"
                )
        if self.required_request_parameters != tuple(sorted(set(self.required_request_parameters))):
            raise ValueError("required request parameters must be sorted and unique")
        if not _BASE_REQUEST_PARAMETERS.issubset(self.required_request_parameters):
            raise ValueError("required request parameters omit the base request shape")
        if not set(self.required_request_parameters).issubset(self.supported_parameters):
            raise ValueError("endpoint does not support every emitted request parameter")
        expected_structured = structured_output_parameters(self.supported_parameters)
        if self.structured_output_parameters != expected_structured:
            raise ValueError("structured-output parameter evidence is inconsistent")
        expected_modes = supported_output_modes(self.supported_parameters)
        if self.supported_output_modes != expected_modes:
            raise ValueError("supported output-mode evidence is inconsistent")
        if self.structured_output_mode is not expected_modes[0]:
            raise ValueError("negotiated endpoint output mode is inconsistent")
        if self.output_capability_sha256 != _endpoint_output_capability_sha256(self):
            raise ValueError("endpoint output-capability hash is inconsistent")
        if self.max_prompt_tokens > self.context_length:
            raise ValueError("endpoint prompt limit exceeds its context length")
        if self.max_completion_tokens > self.context_length:
            raise ValueError("endpoint completion limit exceeds its context length")
        if (
            self.max_prompt_tokens_source == "context_limit"
            and self.max_prompt_tokens != self.context_length
        ):
            raise ValueError("derived prompt limit does not match the context ceiling")
        if (
            self.max_completion_tokens_source == "context_limit"
            and self.max_completion_tokens != self.context_length
        ):
            raise ValueError("derived completion limit does not match the context ceiling")
        if tuple(self.pricing) != tuple(sorted(self.pricing)):
            raise ValueError("endpoint pricing fields must be sorted")
        if not {"prompt", "completion"}.issubset(self.pricing):
            raise ValueError("endpoint pricing omits prompt or completion")
        for field, value in self.pricing.items():
            if (
                not _PRICING_FIELD_PATTERN.fullmatch(field)
                or field in _NON_BILLABLE_PRICING_METADATA
                or field == "overrides"
                or field in _PRICING_OVERRIDE_CONDITIONS
            ):
                raise ValueError("endpoint pricing contains an invalid field")
            if _canonical_price(value) != value:
                raise ValueError("endpoint pricing is not canonically encoded")
        if self.pricing_overrides:
            thresholds = tuple(tier.min_prompt_tokens for tier in self.pricing_overrides)
            if len(thresholds) != len(set(thresholds)):
                raise ValueError("endpoint pricing override thresholds are duplicated")
            if thresholds != tuple(sorted(thresholds)):
                raise ValueError(
                    "endpoint pricing override thresholds must be strictly increasing in "
                    "provider order"
                )
            expected_projection = project_openrouter_pricing_schedule(
                self.pricing,
                self.pricing_overrides,
            )
            if self.tiered_pricing_cost_projection != expected_projection:
                raise ValueError("conditional endpoint pricing projection is inconsistent")
        elif self.tiered_pricing_cost_projection is not None:
            raise ValueError("flat endpoint pricing cannot record a tiered cost projection")
        if self.pricing_sha256 != openrouter_pricing_schedule_sha256(
            self.pricing,
            self.pricing_overrides,
        ):
            raise ValueError("endpoint pricing hash is inconsistent")
        expected = _canonical_sha256(
            self.model_dump(
                mode="json",
                exclude={"endpoint_snapshot_sha256"},
            )
        )
        if self.endpoint_snapshot_sha256 != expected:
            raise ValueError("endpoint evidence hash is inconsistent")
        return self

    def effective_pricing(self, prompt_tokens: int) -> dict[str, str]:
        """Resolve documented strict-threshold inheritance without granting cost authority."""

        if (
            type(prompt_tokens) is not int
            or not 0 <= prompt_tokens <= _MAX_PRICING_OVERRIDE_PROMPT_TOKENS
        ):
            raise EndpointSnapshotValidationError(
                "effective endpoint prompt tokens must be an exact bounded nonnegative integer"
            )
        return effective_openrouter_pricing(
            self.pricing,
            self.pricing_overrides,
            prompt_tokens=prompt_tokens,
        )


class OpenRouterReasoningCapabilityEvidence(BaseModel):
    """Frozen endpoint reasoning capability without qualification authority.

    The evidence records only explicit normalized provider metadata. ``None`` and
    ``unknown`` values remain first-class states and are never promoted to
    supported behavior.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    schema_version: Literal["1.0"] = "1.0"
    exact_model_id: str = Field(pattern=_MODEL_ID_PATTERN)
    provider_endpoint: str = Field(pattern=_ENDPOINT_ID_PATTERN)
    endpoint_tag: str | None = Field(default=None, pattern=_ENDPOINT_ID_PATTERN)
    endpoint_slug: str | None = Field(default=None, pattern=_ENDPOINT_ID_PATTERN)
    provider_name: str = Field(min_length=1, max_length=_PROVIDER_NAME_MAX_LENGTH)
    endpoint_metadata_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_metadata_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reasoning_parameter_support: ReasoningParameterSupport
    reasoning_metadata_available: bool
    reasoning_mandatory: bool | None
    reasoning_default_enabled: bool | None
    reasoning_supports_max_tokens: bool | None
    supported_reasoning_efforts: tuple[ReasoningEffort, ...] | None = Field(
        default=None,
        max_length=len(REASONING_EFFORT_ORDER),
    )
    max_output_tokens: int = Field(gt=0, le=2**31 - 1)
    max_reasoning_tokens: int | None = Field(default=None, gt=0, le=65_536)
    capability_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("supported_reasoning_efforts", mode="before")
    @classmethod
    def json_effort_inventory_is_tuple(
        cls,
        value: Any,
    ) -> Any:
        """Accept the JSON array representation without relaxing strict members."""

        return tuple(value) if isinstance(value, list) else value

    @classmethod
    def from_endpoint(
        cls,
        *,
        endpoint: OpenRouterEndpointEvidence,
        model_metadata_snapshot_sha256: str,
        reasoning_parameter_support: ReasoningParameterSupport,
        reasoning_metadata_available: bool,
        reasoning_mandatory: bool | None,
        reasoning_default_enabled: bool | None,
        reasoning_supports_max_tokens: bool | None,
        max_reasoning_tokens: int | None = None,
    ) -> OpenRouterReasoningCapabilityEvidence:
        """Seal explicit normalized metadata for one exact endpoint."""

        if not isinstance(endpoint, OpenRouterEndpointEvidence):
            raise EndpointSnapshotValidationError(
                "reasoning capability requires sealed endpoint evidence"
            )
        try:
            endpoint = OpenRouterEndpointEvidence.model_validate(endpoint.model_dump(mode="python"))
        except ValueError as exc:
            raise EndpointSnapshotValidationError(
                "reasoning capability endpoint evidence is invalid"
            ) from exc
        explicit_parameter_support: ReasoningParameterSupport = (
            "supported" if "reasoning" in endpoint.supported_parameters else "unsupported"
        )
        if reasoning_parameter_support != explicit_parameter_support:
            raise EndpointSnapshotValidationError(
                "reasoning parameter support contradicts the endpoint snapshot"
            )
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "exact_model_id": endpoint.exact_model_id,
            "provider_endpoint": endpoint.provider_endpoint,
            "endpoint_tag": endpoint.endpoint_tag,
            "endpoint_slug": endpoint.endpoint_slug,
            "provider_name": endpoint.provider_name,
            "endpoint_metadata_snapshot_sha256": endpoint.endpoint_snapshot_sha256,
            "model_metadata_snapshot_sha256": model_metadata_snapshot_sha256,
            "reasoning_parameter_support": reasoning_parameter_support,
            "reasoning_metadata_available": reasoning_metadata_available,
            "reasoning_mandatory": reasoning_mandatory,
            "reasoning_default_enabled": reasoning_default_enabled,
            "reasoning_supports_max_tokens": reasoning_supports_max_tokens,
            "supported_reasoning_efforts": endpoint.supported_reasoning_efforts,
            "max_output_tokens": endpoint.max_completion_tokens,
            "max_reasoning_tokens": max_reasoning_tokens,
        }
        payload["capability_sha256"] = _canonical_sha256(payload)
        try:
            return cls.model_validate(payload)
        except ValueError as exc:
            raise EndpointSnapshotValidationError(
                "reasoning capability metadata is invalid"
            ) from exc

    @model_validator(mode="after")
    def capability_is_explicit_consistent_and_self_bound(
        self,
    ) -> OpenRouterReasoningCapabilityEvidence:
        _validate_exact_model_id(self.exact_model_id)
        if self.endpoint_tag is None and self.endpoint_slug is None:
            raise ValueError("reasoning capability requires an endpoint tag or slug")
        if self.provider_endpoint not in {self.endpoint_tag, self.endpoint_slug}:
            raise ValueError("reasoning capability endpoint identity is inconsistent")
        if _provider_display_name(self.provider_name) != self.provider_name:
            raise ValueError("reasoning capability provider name is not canonical")

        semantic_states = (
            self.reasoning_mandatory,
            self.reasoning_default_enabled,
            self.reasoning_supports_max_tokens,
        )
        if not self.reasoning_metadata_available and any(
            state is not None for state in semantic_states
        ):
            raise ValueError("unavailable reasoning metadata cannot contain inferred states")
        if not self.reasoning_metadata_available and self.supported_reasoning_efforts is not None:
            raise ValueError(
                "unavailable reasoning metadata cannot claim a supported-effort inventory"
            )
        if self.supported_reasoning_efforts is not None:
            selected_efforts = frozenset(self.supported_reasoning_efforts)
            canonical_efforts = tuple(
                effort for effort in REASONING_EFFORT_ORDER if effort in selected_efforts
            )
            if (
                len(selected_efforts) != len(self.supported_reasoning_efforts)
                or self.supported_reasoning_efforts != canonical_efforts
            ):
                raise ValueError(
                    "supported reasoning efforts must be unique and canonically ordered"
                )

        if self.reasoning_supports_max_tokens is not True and self.max_reasoning_tokens is not None:
            raise ValueError("reasoning token ceiling requires explicit max-token support")
        if not self.reasoning_metadata_available and self.max_reasoning_tokens is not None:
            raise ValueError("unavailable reasoning metadata cannot claim a token ceiling")

        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"capability_sha256"}))
        if self.capability_sha256 != expected:
            raise ValueError("reasoning capability hash is inconsistent")
        return self

    def require_compatible_profile(self, profile: ReasoningControlProfile) -> None:
        """Require endpoint compatibility without granting benchmark qualification."""

        self._require_compatible_profile_with_efforts(
            profile,
            supported_reasoning_efforts=self.supported_reasoning_efforts,
        )

    def _require_compatible_profile_with_efforts(
        self,
        profile: ReasoningControlProfile,
        *,
        supported_reasoning_efforts: tuple[ReasoningEffort, ...] | None,
    ) -> None:
        """Validate a profile with an inventory selected by sealed outer evidence."""

        try:
            sealed_profile = ReasoningControlProfile.model_validate(profile)
        except ValueError as exc:
            raise EndpointSnapshotValidationError(
                "reasoning control profile is not valid sealed evidence"
            ) from exc

        if sealed_profile.mode == "disabled":
            if (
                self.reasoning_parameter_support == "unsupported"
                and not self.reasoning_metadata_available
            ):
                return
            if self.reasoning_parameter_support == "unknown":
                raise EndpointSnapshotValidationError(
                    "disabled reasoning lacks explicit parameter-support evidence"
                )
            self._require_reasoning_metadata()
            if self.reasoning_mandatory is not False:
                raise EndpointSnapshotValidationError(
                    "disabled reasoning is incompatible with mandatory reasoning"
                )
            if self.reasoning_default_enabled is not False:
                raise EndpointSnapshotValidationError(
                    "disabled reasoning is incompatible with default-enabled reasoning"
                )
            return

        if self.reasoning_parameter_support != "supported":
            raise EndpointSnapshotValidationError(
                "active reasoning requires explicit endpoint parameter support"
            )
        self._require_reasoning_metadata()
        if sealed_profile.reserved_reasoning_tokens > self.max_output_tokens:
            raise EndpointSnapshotValidationError(
                "reasoning token reservation exceeds the frozen output limit"
            )

        if sealed_profile.mode == "default":
            if self.reasoning_default_enabled is None:
                raise EndpointSnapshotValidationError(
                    "default reasoning lacks a frozen default-enabled state"
                )
            return
        if sealed_profile.mode == "effort":
            assert sealed_profile.effort is not None
            if supported_reasoning_efforts is None:
                raise EndpointSnapshotValidationError(
                    "active reasoning effort lacks an exact frozen supported-effort inventory"
                )
            if sealed_profile.effort not in supported_reasoning_efforts:
                raise EndpointSnapshotValidationError(
                    "requested reasoning effort is absent from the exact frozen inventory"
                )
            if sealed_profile.effort == "none" and self.reasoning_mandatory is not False:
                raise EndpointSnapshotValidationError(
                    "effort=none is incompatible with mandatory reasoning"
                )
            return
        if sealed_profile.mode == "max_tokens":
            if self.reasoning_supports_max_tokens is not True:
                raise EndpointSnapshotValidationError(
                    "max-token reasoning lacks exact frozen support"
                )
            assert sealed_profile.max_tokens is not None
            if (
                self.max_reasoning_tokens is not None
                and sealed_profile.max_tokens > self.max_reasoning_tokens
            ):
                raise EndpointSnapshotValidationError(
                    "requested reasoning tokens exceed the published reasoning ceiling"
                )
            return
        raise AssertionError("unreachable reasoning control mode")

    def _require_reasoning_metadata(self) -> None:
        if not self.reasoning_metadata_available:
            raise EndpointSnapshotValidationError(
                "reasoning compatibility requires frozen metadata"
            )


class OpenRouterEndpointSnapshotEvidence(BaseModel):
    """Canonical, self-hashed evidence for an exact endpoint routing policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    exact_model_id: str = Field(pattern=_MODEL_ID_PATTERN)
    provider_policy_mode: Literal["only", "order"]
    configured_provider_endpoints: tuple[str, ...] = Field(min_length=1, max_length=100)
    require_zdr: bool
    endpoints: tuple[OpenRouterEndpointEvidence, ...] = Field(min_length=1, max_length=100)
    supported_output_modes: tuple[StructuredOutputMode, ...] = Field(
        min_length=1,
        max_length=3,
    )
    structured_output_mode: StructuredOutputMode
    output_capability_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    endpoint_metadata_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    zdr_metadata_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    route_predicate_profile: RoutePredicateProfile | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    exact_route_constraint: ExactRouteConstraint | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    normalized_route_facts: NormalizedRouteFacts | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    route_predicate_report: RoutePredicateReport | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def snapshot_is_complete_and_self_bound(self) -> OpenRouterEndpointSnapshotEvidence:
        _validate_exact_model_id(self.exact_model_id)
        if len(self.configured_provider_endpoints) != len(set(self.configured_provider_endpoints)):
            raise ValueError("configured provider endpoints must be unique")
        observed = tuple(item.provider_endpoint for item in self.endpoints)
        if observed != self.configured_provider_endpoints:
            raise ValueError("endpoint evidence does not exactly cover the configured policy")
        if any(item.exact_model_id != self.exact_model_id for item in self.endpoints):
            raise ValueError("endpoint evidence is not bound to the exact model")
        expected_modes = mutually_supported_output_modes(
            endpoint.supported_parameters for endpoint in self.endpoints
        )
        if self.supported_output_modes != expected_modes:
            raise ValueError("endpoint policy output-mode evidence is inconsistent")
        if self.structured_output_mode is not expected_modes[0]:
            raise ValueError("negotiated endpoint policy output mode is inconsistent")
        if self.output_capability_sha256 != _policy_output_capability_sha256(self):
            raise ValueError("endpoint policy output-capability hash is inconsistent")
        if self.require_zdr:
            if self.zdr_metadata_sha256 is None:
                raise ValueError("ZDR-required endpoint evidence omits its ZDR snapshot")
            if any(item.zdr_eligible is not True for item in self.endpoints):
                raise ValueError("ZDR-required endpoint evidence contains an ineligible endpoint")
        _validate_embedded_route_predicate_evidence(self)
        expected = _canonical_sha256(
            self.model_dump(
                mode="json",
                exclude={"snapshot_sha256"},
            )
        )
        if self.snapshot_sha256 != expected:
            raise ValueError("endpoint policy snapshot hash is inconsistent")
        return self

    def endpoint(self, provider_endpoint: str) -> OpenRouterEndpointEvidence:
        """Return one exact configured endpoint, rejecting an unknown identifier."""

        for endpoint in self.endpoints:
            if endpoint.provider_endpoint == provider_endpoint:
                return endpoint
        raise KeyError(provider_endpoint)


def validate_openrouter_endpoint_snapshot(
    *,
    exact_model_id: str,
    configured_provider_endpoints: Sequence[str],
    provider_policy_mode: Literal["only", "order"],
    endpoint_payload: Any,
    require_zdr: bool,
    zdr_payload: Any | None = None,
    reasoning_requested: bool = False,
    structured_output_required: bool = False,
    required_output_mode: StructuredOutputMode | None = None,
    route_constraint_context: OpenRouterConstrainedRouteContext | None = None,
) -> OpenRouterEndpointSnapshotEvidence:
    """Validate provider snapshots and return canonical non-secret evidence.

    ``endpoint_payload`` is the response body from the exact per-model endpoint
    metadata route. ``zdr_payload``, when present, is the response body from the
    global ZDR endpoint route. Every configured provider identifier must match an
    exact endpoint ``tag`` or ``slug``; display names are deliberately ignored.
    """

    _validate_exact_model_id(exact_model_id)
    configured = _validate_configured_endpoints(configured_provider_endpoints)
    if provider_policy_mode not in {"only", "order"}:
        raise EndpointSnapshotValidationError("provider policy mode must be only or order")
    data = _required_mapping(endpoint_payload, "endpoint metadata")
    data = _required_mapping(data.get("data"), "endpoint metadata data")
    if data.get("id") != exact_model_id:
        raise EndpointSnapshotValidationError(
            "endpoint metadata is not bound to the exact requested model"
        )
    raw_endpoints = _required_endpoint_list(data.get("endpoints"), "endpoint metadata")
    matched = _match_configured_endpoints(configured, raw_endpoints)
    common_output_modes = mutually_supported_output_modes(
        _supported_parameters(endpoint.get("supported_parameters"))
        for _endpoint_index, endpoint in matched
    )
    negotiated_output_mode = common_output_modes[0]
    if required_output_mode is not None and required_output_mode not in common_output_modes:
        raise EndpointSnapshotValidationError(
            "configured endpoint does not support the required structured-output mode"
        )
    if (
        required_output_mode is None
        and structured_output_required
        and negotiated_output_mode is StructuredOutputMode.VALIDATED_TEXT_JSON
    ):
        raise EndpointSnapshotValidationError(
            "configured endpoint lacks emitted request parameter support: response_format"
        )
    special_output_parameters = output_mode_request_parameters(negotiated_output_mode)
    required_request_parameters = tuple(
        sorted(
            {
                *_BASE_REQUEST_PARAMETERS,
                *(("reasoning",) if reasoning_requested else ()),
                *special_output_parameters,
            }
        )
    )
    identity_inventory = sorted(
        (canonicalize_openrouter_endpoint_identity(endpoint) for endpoint in raw_endpoints),
        key=lambda item: json.dumps(
            item,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ),
    )
    provider_name_counts: dict[str, int] = {}
    for identity in identity_inventory:
        provider_name = identity["provider_name"]
        assert isinstance(provider_name, str)
        normalized_name = provider_name.casefold()
        provider_name_counts[normalized_name] = provider_name_counts.get(normalized_name, 0) + 1
    for _endpoint_index, raw_endpoint in matched:
        provider_name = _provider_display_name(raw_endpoint.get("provider_name"))
        if provider_name_counts[provider_name.casefold()] != 1:
            raise EndpointSnapshotValidationError(
                "configured endpoint provider display name is ambiguous in exact-model metadata"
            )

    zdr_matches: dict[str, tuple[int, Mapping[str, Any]] | None]
    zdr_projection: dict[str, Any] | None
    if zdr_payload is None:
        if require_zdr:
            raise EndpointSnapshotValidationError(
                "ZDR-required policy needs a current endpoint eligibility snapshot"
            )
        zdr_matches = {endpoint_id: None for endpoint_id in configured}
        zdr_projection = None
    else:
        zdr_matches, zdr_projection = _match_zdr_endpoints(
            exact_model_id=exact_model_id,
            configured=configured,
            payload=zdr_payload,
            required_request_parameters=required_request_parameters,
            enforce_required_parameter_support=route_constraint_context is None,
        )

    endpoint_evidence: list[OpenRouterEndpointEvidence] = []
    endpoint_projection: list[dict[str, Any]] = []
    for endpoint_id, (raw_endpoint_index, raw_endpoint) in zip(configured, matched, strict=True):
        normalized = _normalize_endpoint(
            exact_model_id=exact_model_id,
            configured_endpoint=endpoint_id,
            raw_endpoint=raw_endpoint,
            price_lexeme_layout=MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
            price_lexeme_parent_path=(
                "data",
                "endpoints",
                raw_endpoint_index,
                "pricing",
            ),
            required_request_parameters=required_request_parameters,
            enforce_required_parameter_support=route_constraint_context is None,
        )
        zdr_match = zdr_matches[endpoint_id]
        zdr_hash: str | None = None
        zdr_eligible: bool | None = None if zdr_payload is None else False
        if zdr_match is not None:
            zdr_raw_index, zdr_raw = zdr_match
            normalized_zdr = _normalize_endpoint(
                exact_model_id=exact_model_id,
                configured_endpoint=endpoint_id,
                raw_endpoint=zdr_raw,
                price_lexeme_layout=ZDR_ENDPOINT_PRICE_LEXEME_LAYOUT,
                price_lexeme_parent_path=("data", zdr_raw_index, "pricing"),
                require_item_model_binding=True,
                required_request_parameters=required_request_parameters,
                enforce_required_parameter_support=route_constraint_context is None,
            )
            _validate_zdr_counterpart(normalized, normalized_zdr)
            zdr_eligible = True
            zdr_hash = _canonical_sha256(normalized_zdr)
        if require_zdr and zdr_eligible is not True:
            raise EndpointSnapshotValidationError(
                f"configured endpoint is not present in the exact-model ZDR snapshot: {endpoint_id}"
            )
        if route_constraint_context is not None and not endpoint_evidence:
            _evaluate_route_predicate_evidence(
                exact_model_id=exact_model_id,
                provider_policy_mode=provider_policy_mode,
                configured_provider_endpoints=configured,
                identity_inventory=identity_inventory,
                selected_endpoint={**normalized, "zdr_eligible": zdr_eligible},
                structured_output_mode=negotiated_output_mode,
                context=route_constraint_context,
            )
        endpoint_projection.append(normalized)
        endpoint_evidence.append(
            _seal_endpoint_evidence(
                normalized,
                zdr_eligible=zdr_eligible,
                zdr_endpoint_snapshot_sha256=zdr_hash,
            )
        )

    endpoint_metadata_projection = {
        "model_id": exact_model_id,
        "endpoint_identities": identity_inventory,
        "configured_endpoints": endpoint_projection,
    }
    sealed_common_output_modes = mutually_supported_output_modes(
        endpoint.supported_parameters for endpoint in endpoint_evidence
    )
    if sealed_common_output_modes != common_output_modes:
        raise EndpointSnapshotValidationError(
            "sealed endpoint output modes differ from advertised capabilities"
        )
    output_capability_projection = {
        "schema_version": _SNAPSHOT_SCHEMA_VERSION,
        "exact_model_id": exact_model_id,
        "provider_policy_mode": provider_policy_mode,
        "configured_provider_endpoints": configured,
        "endpoint_output_capability_sha256": tuple(
            endpoint.output_capability_sha256 for endpoint in endpoint_evidence
        ),
        "supported_output_modes": sealed_common_output_modes,
        "structured_output_mode": negotiated_output_mode,
    }
    serialized: dict[str, Any] = {
        "schema_version": _SNAPSHOT_SCHEMA_VERSION,
        "exact_model_id": exact_model_id,
        "provider_policy_mode": provider_policy_mode,
        "configured_provider_endpoints": configured,
        "require_zdr": require_zdr,
        "endpoints": [
            {
                **item.model_dump(mode="json"),
                **(
                    {"tiered_pricing_cost_projection": (item.tiered_pricing_cost_projection)}
                    if isinstance(
                        item.tiered_pricing_cost_projection,
                        ExactRoutePricingSchedule,
                    )
                    else {}
                ),
            }
            for item in endpoint_evidence
        ],
        "supported_output_modes": sealed_common_output_modes,
        "structured_output_mode": negotiated_output_mode,
        "output_capability_sha256": _canonical_sha256(output_capability_projection),
        "endpoint_metadata_sha256": _canonical_sha256(endpoint_metadata_projection),
        "zdr_metadata_sha256": (
            _canonical_sha256(zdr_projection) if zdr_projection is not None else None
        ),
    }
    if route_constraint_context is not None:
        serialized.update(
            _build_route_predicate_evidence(
                exact_model_id=exact_model_id,
                provider_policy_mode=provider_policy_mode,
                configured_provider_endpoints=configured,
                identity_inventory=identity_inventory,
                endpoints=tuple(endpoint_evidence),
                structured_output_mode=negotiated_output_mode,
                context=route_constraint_context,
            )
        )
    return OpenRouterEndpointSnapshotEvidence.model_validate(
        {
            **serialized,
            "snapshot_sha256": _canonical_sha256(serialized),
        }
    )


def _build_route_predicate_evidence(
    *,
    exact_model_id: str,
    provider_policy_mode: Literal["only", "order"],
    configured_provider_endpoints: tuple[str, ...],
    identity_inventory: Sequence[Mapping[str, str | None]],
    endpoints: tuple[OpenRouterEndpointEvidence, ...],
    structured_output_mode: StructuredOutputMode,
    context: OpenRouterConstrainedRouteContext,
) -> dict[str, Any]:
    """Evaluate every discovery predicate before a constrained snapshot can exist."""

    if not endpoints:
        raise EndpointSnapshotValidationError("constrained endpoint snapshot has no route")
    facts, report, context = _evaluate_route_predicate_evidence(
        exact_model_id=exact_model_id,
        provider_policy_mode=provider_policy_mode,
        configured_provider_endpoints=configured_provider_endpoints,
        identity_inventory=identity_inventory,
        selected_endpoint={
            **endpoints[0].model_dump(mode="python"),
            "tiered_pricing_cost_projection": (endpoints[0].tiered_pricing_cost_projection),
        },
        structured_output_mode=structured_output_mode,
        context=context,
    )
    return {
        "route_predicate_profile": context.route_predicate_profile,
        "exact_route_constraint": context.exact_route_constraint,
        "normalized_route_facts": facts,
        "route_predicate_report": report,
    }


def _evaluate_route_predicate_evidence(
    *,
    exact_model_id: str,
    provider_policy_mode: Literal["only", "order"],
    configured_provider_endpoints: tuple[str, ...],
    identity_inventory: Sequence[Mapping[str, str | None]],
    selected_endpoint: Mapping[str, Any],
    structured_output_mode: StructuredOutputMode,
    context: OpenRouterConstrainedRouteContext,
) -> tuple[NormalizedRouteFacts, RoutePredicateReport, OpenRouterConstrainedRouteContext]:
    """Build and require the one complete report before constrained endpoint sealing."""

    if type(context) is not OpenRouterConstrainedRouteContext:
        raise EndpointSnapshotValidationError(
            "constrained endpoint snapshot requires an exact route context"
        )
    try:
        context = OpenRouterConstrainedRouteContext.model_validate_json(
            context.model_dump_json(),
            strict=True,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise EndpointSnapshotValidationError(
            "constrained endpoint route context failed detached validation"
        ) from exc
    role_policy = context.reasoning_policy.role_policy_for_request(context.reasoning_request_role)
    control = role_policy.control
    try:
        exact_pricing = normalize_exact_route_pricing(selected_endpoint["pricing"])
    except RouteConstraintError as exc:
        raise EndpointSnapshotValidationError(
            "constrained endpoint pricing contains an unsupported component"
        ) from exc
    pricing_projection = selected_endpoint.get("tiered_pricing_cost_projection")
    pricing_schedule: ExactRoutePricingSchedule | Literal["unavailable"] | None
    if isinstance(pricing_projection, ExactRoutePricingSchedule):
        pricing_schedule = pricing_projection
    elif type(pricing_projection) is str and pricing_projection == "unavailable":
        pricing_schedule = "unavailable"
    else:
        pricing_schedule = None
    price_cap_failure: str | None = None
    if pricing_schedule == "unavailable":
        configured_cap = None
        price_cap_failure = "pricing schedule unavailable"
    else:
        try:
            configured_cap = project_provider_price_cap(
                exact_pricing,
                schedule=pricing_schedule,
                algorithm=context.route_predicate_profile.price_cap_algorithm,
                price_component_unit_envelopes=(
                    context.route_predicate_profile.price_component_unit_envelopes or ()
                ),
            )
        except RouteConstraintError as exc:
            configured_cap = None
            # Projection errors contain controlled labels and enum components, not raw metadata.
            # Preserve the first refusal for diagnosis; it cannot confer admission or proof.
            price_cap_failure = str(exc)
    provider_display_names = tuple(
        sorted(
            (
                provider_name
                for identity in identity_inventory
                if isinstance((provider_name := identity["provider_name"]), str)
            ),
            key=lambda item: (item.casefold(), item),
        )
    )
    emitted_parameters = project_route_emitted_request_parameters(
        structured_output_mode=structured_output_mode,
        reasoning_emitted=control.mode != "disabled",
    )
    try:
        facts = NormalizedRouteFacts.build(
            observed_model_id=exact_model_id,
            observed_provider_endpoint=selected_endpoint["provider_endpoint"],
            selected_provider_display_name=selected_endpoint["provider_name"],
            provider_display_names=provider_display_names,
            provider_identity_inventory_complete=True,
            operational_status=selected_endpoint["operational_status"],
            zdr_eligible=selected_endpoint["zdr_eligible"],
            emitted_request_parameters=emitted_parameters,
            model_supported_parameters=context.model_supported_parameters,
            endpoint_supported_parameters=selected_endpoint["supported_parameters"],
            structured_output_mode=structured_output_mode,
            configured_provider_endpoints=configured_provider_endpoints,
            provider_policy_mode=provider_policy_mode,
            automatic_fallbacks_allowed=context.automatic_fallbacks_allowed,
            reasoning_policy_sha256=context.reasoning_policy.artifact_sha256,
            reasoning_role_profile_sha256=(context.reasoning_policy.role_profile.profile_sha256),
            reasoning_role_binding_sha256=role_policy.binding_sha256,
            reasoning_control_profile_sha256=control.profile_sha256,
            reasoning_mode=control.mode,
            reasoning_effort=control.effort,
            reasoning_max_tokens=control.max_tokens,
            reasoning_exclude=control.exclude,
            reserved_reasoning_tokens=control.reserved_reasoning_tokens,
            endpoint_supported_reasoning_efforts=(selected_endpoint["supported_reasoning_efforts"]),
            model_supported_reasoning_efforts=(context.model_supported_reasoning_efforts),
            max_prompt_tokens=selected_endpoint["max_prompt_tokens"],
            max_completion_tokens=selected_endpoint["max_completion_tokens"],
            max_completion_tokens_source=selected_endpoint["max_completion_tokens_source"],
            context_tokens=selected_endpoint["context_length"],
            exact_pricing=exact_pricing,
            pricing_schedule=pricing_schedule,
            configured_provider_max_price=configured_cap,
            frozen_live_equivalent=None,
            expected_selection_plan_sha256=context.expected_selection_plan_sha256,
        )
        report = evaluate_route_predicates(
            profile=context.route_predicate_profile,
            constraint=context.exact_route_constraint,
            facts=facts,
        )
        require_route_predicates(
            report,
            purpose=RouteConstraintPurpose.DISCOVERY_PUBLICATION,
        )
    except RoutePredicateRequirementError as exc:
        reasons = ",".join(result.reason.value for result in exc.failures)
        message = "constrained endpoint snapshot failed discovery route predicates: " + reasons
        if price_cap_failure is not None:
            algorithm = context.route_predicate_profile.price_cap_algorithm.value
            message += f"; price-cap projection [{algorithm}]: {price_cap_failure}"
        raise EndpointSnapshotValidationError(message) from exc
    except (RouteConstraintError, ValueError) as exc:
        raise EndpointSnapshotValidationError(
            "constrained endpoint snapshot route facts are invalid"
        ) from exc
    return facts, report, context


def _validate_embedded_route_predicate_evidence(
    snapshot: OpenRouterEndpointSnapshotEvidence,
) -> None:
    embedded = (
        snapshot.route_predicate_profile,
        snapshot.exact_route_constraint,
        snapshot.normalized_route_facts,
        snapshot.route_predicate_report,
    )
    if all(value is None for value in embedded):
        return
    if any(value is None for value in embedded):
        raise ValueError("constrained endpoint route evidence must be all present or absent")
    profile = snapshot.route_predicate_profile
    constraint = snapshot.exact_route_constraint
    facts = snapshot.normalized_route_facts
    report = snapshot.route_predicate_report
    assert profile is not None
    assert constraint is not None
    assert facts is not None
    assert report is not None
    endpoint = snapshot.endpoints[0]
    exact_pricing = normalize_exact_route_pricing(endpoint.pricing)
    pricing_schedule = endpoint.tiered_pricing_cost_projection
    if isinstance(pricing_schedule, str):
        expected_cap = None
    else:
        try:
            expected_cap = project_provider_price_cap(
                exact_pricing,
                schedule=pricing_schedule,
                algorithm=profile.price_cap_algorithm,
                price_component_unit_envelopes=(profile.price_component_unit_envelopes or ()),
            )
        except RouteConstraintError as exc:
            raise ValueError(
                "constrained endpoint pricing is not provider-cap expressible"
            ) from exc
    expected_emitted = project_route_emitted_request_parameters(
        structured_output_mode=snapshot.structured_output_mode,
        reasoning_emitted=facts.reasoning_mode != "disabled",
    )
    if endpoint.required_request_parameters != expected_emitted:
        raise ValueError(
            "constrained endpoint required request parameters differ from shared emission"
        )
    expected_endpoint_facts = (
        snapshot.exact_model_id,
        endpoint.provider_endpoint,
        endpoint.provider_name,
        endpoint.operational_status,
        endpoint.zdr_eligible,
        expected_emitted,
        endpoint.supported_parameters,
        snapshot.structured_output_mode,
        snapshot.configured_provider_endpoints,
        snapshot.provider_policy_mode,
        endpoint.supported_reasoning_efforts,
        endpoint.max_prompt_tokens,
        endpoint.max_completion_tokens,
        endpoint.max_completion_tokens_source,
        endpoint.context_length,
        exact_pricing,
        pricing_schedule,
        expected_cap,
    )
    observed_endpoint_facts = (
        facts.observed_model_id,
        facts.observed_provider_endpoint,
        facts.selected_provider_display_name,
        facts.operational_status,
        facts.zdr_eligible,
        facts.emitted_request_parameters,
        facts.endpoint_supported_parameters,
        facts.structured_output_mode,
        facts.configured_provider_endpoints,
        facts.provider_policy_mode,
        facts.endpoint_supported_reasoning_efforts,
        facts.max_prompt_tokens,
        facts.max_completion_tokens,
        facts.max_completion_tokens_source,
        facts.context_tokens,
        facts.exact_pricing,
        facts.pricing_schedule,
        facts.configured_provider_max_price,
    )
    if observed_endpoint_facts != expected_endpoint_facts:
        raise ValueError("constrained endpoint route facts differ from sealed endpoint metadata")
    if facts.provider_identity_inventory_complete is not True:
        raise ValueError("constrained endpoint provider identity inventory is incomplete")
    expected_report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=facts,
    )
    if report != expected_report:
        raise ValueError("constrained endpoint route predicate report is inconsistent")
    try:
        require_route_predicates(
            report,
            purpose=RouteConstraintPurpose.DISCOVERY_PUBLICATION,
        )
    except RoutePredicateRequirementError as exc:
        raise ValueError(
            "constrained endpoint route predicate report is not publication eligible"
        ) from exc


def _validate_exact_model_id(model_id: str) -> None:
    if not is_exact_openrouter_model_id(model_id):
        raise EndpointSnapshotValidationError(
            "endpoint snapshot rejects router or latest aliases and mutable variants"
        )


def _validate_configured_endpoints(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not 1 <= len(values) <= 100:
        raise EndpointSnapshotValidationError(
            "endpoint snapshot requires a bounded provider endpoint policy"
        )
    configured = tuple(values)
    if len(configured) != len(set(configured)):
        raise EndpointSnapshotValidationError("configured provider endpoints must be unique")
    if any(
        not isinstance(value, str) or re.fullmatch(_ENDPOINT_ID_PATTERN, value) is None
        for value in configured
    ):
        raise EndpointSnapshotValidationError(
            "configured provider policy contains an invalid endpoint identifier"
        )
    return configured


def _required_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise EndpointSnapshotValidationError(f"{label} must be an object")
    return value


def _required_endpoint_list(
    value: Any,
    label: str,
    *,
    allow_empty: bool = False,
) -> list[Mapping[str, Any]]:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or len(value) > _MAX_ENDPOINTS
        or any(not isinstance(item, dict) for item in value)
    ):
        raise EndpointSnapshotValidationError(f"{label} contains an invalid endpoint list")
    return value


def _match_configured_endpoints(
    configured: tuple[str, ...],
    endpoints: list[Mapping[str, Any]],
) -> list[tuple[int, Mapping[str, Any]]]:
    identities = [_endpoint_identities(endpoint) for endpoint in endpoints]
    matched: list[tuple[int, Mapping[str, Any]]] = []
    matched_indexes: set[int] = set()
    for configured_endpoint in configured:
        indexes = [
            index
            for index, endpoint_identities in enumerate(identities)
            if configured_endpoint in endpoint_identities
        ]
        if not indexes:
            raise EndpointSnapshotValidationError(
                f"configured endpoint tag or slug is unavailable: {configured_endpoint}"
            )
        if len(indexes) != 1 or indexes[0] in matched_indexes:
            raise EndpointSnapshotValidationError(
                f"configured endpoint tag or slug is ambiguous: {configured_endpoint}"
            )
        matched_index = indexes[0]
        matched_indexes.add(matched_index)
        matched.append((matched_index, endpoints[matched_index]))
    return matched


def _match_zdr_endpoints(
    *,
    exact_model_id: str,
    configured: tuple[str, ...],
    payload: Any,
    required_request_parameters: tuple[str, ...],
    enforce_required_parameter_support: bool,
) -> tuple[dict[str, tuple[int, Mapping[str, Any]] | None], dict[str, Any]]:
    envelope = _required_mapping(payload, "ZDR endpoint metadata")
    raw_items = _required_endpoint_list(
        envelope.get("data"),
        "ZDR endpoint metadata",
        allow_empty=True,
    )
    exact_model_items: list[tuple[int, Mapping[str, Any]]] = []
    for item_index, item in enumerate(raw_items):
        item_model = item.get("model_id")
        if not isinstance(item_model, str):
            raise EndpointSnapshotValidationError("ZDR endpoint omits its exact model binding")
        if item_model == exact_model_id:
            exact_model_items.append((item_index, item))
    identities = [_endpoint_identities(item) for _item_index, item in exact_model_items]
    matches: dict[str, tuple[int, Mapping[str, Any]] | None] = {}
    projection: list[dict[str, Any]] = []
    for configured_endpoint in configured:
        indexes = [
            index
            for index, endpoint_identities in enumerate(identities)
            if configured_endpoint in endpoint_identities
        ]
        if len(indexes) > 1:
            raise EndpointSnapshotValidationError(
                f"ZDR endpoint tag or slug is ambiguous: {configured_endpoint}"
            )
        match = exact_model_items[indexes[0]] if indexes else None
        matches[configured_endpoint] = match
        matched_item_index, matched_item = match if match is not None else (None, None)
        projection.append(
            {
                "provider_endpoint": configured_endpoint,
                "eligible": match is not None,
                "endpoint": (
                    _normalize_endpoint(
                        exact_model_id=exact_model_id,
                        configured_endpoint=configured_endpoint,
                        raw_endpoint=matched_item,
                        price_lexeme_layout=ZDR_ENDPOINT_PRICE_LEXEME_LAYOUT,
                        price_lexeme_parent_path=(
                            "data",
                            matched_item_index,
                            "pricing",
                        ),
                        require_item_model_binding=True,
                        required_request_parameters=required_request_parameters,
                        enforce_required_parameter_support=(enforce_required_parameter_support),
                    )
                    if matched_item is not None and matched_item_index is not None
                    else None
                ),
            }
        )
    return matches, {"model_id": exact_model_id, "endpoints": projection}


def _endpoint_identities(endpoint: Mapping[str, Any]) -> frozenset[str]:
    tag = _optional_endpoint_id(endpoint.get("tag"), "endpoint tag")
    slug_values = [
        _optional_endpoint_id(endpoint.get(key), f"endpoint {key}")
        for key in ("slug", "provider_slug")
        if endpoint.get(key) is not None
    ]
    if len(set(slug_values)) > 1:
        raise EndpointSnapshotValidationError("endpoint has conflicting slug identities")
    slug = slug_values[0] if slug_values else None
    identities = frozenset(value for value in (tag, slug) if value is not None)
    if not identities:
        raise EndpointSnapshotValidationError("endpoint metadata omits its exact tag or slug")
    return identities


def canonicalize_openrouter_endpoint_identity(
    endpoint: Mapping[str, Any],
) -> dict[str, str | None]:
    """Return the shared exact tag, slug, and provider-name projection."""

    identities = _endpoint_identities(endpoint)
    tag = _optional_endpoint_id(endpoint.get("tag"), "endpoint tag")
    slug_values = [
        _optional_endpoint_id(endpoint.get(key), f"endpoint {key}")
        for key in ("slug", "provider_slug")
        if endpoint.get(key) is not None
    ]
    slug = slug_values[0] if slug_values else None
    if not identities:
        raise EndpointSnapshotValidationError("endpoint identity inventory is empty")
    return {
        "tag": tag,
        "slug": slug,
        "provider_name": _provider_display_name(endpoint.get("provider_name")),
    }


def _optional_endpoint_id(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or re.fullmatch(_ENDPOINT_ID_PATTERN, value) is None:
        raise EndpointSnapshotValidationError(f"{label} is invalid")
    return value


def _provider_display_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > _PROVIDER_NAME_MAX_LENGTH
        or any(not character.isprintable() for character in value)
    ):
        raise EndpointSnapshotValidationError("endpoint provider display name is invalid")
    return value


def _normalize_endpoint(
    *,
    exact_model_id: str,
    configured_endpoint: str,
    raw_endpoint: Mapping[str, Any],
    price_lexeme_layout: OpenRouterPriceLexemeLayout,
    price_lexeme_parent_path: OpenRouterJSONPath,
    require_item_model_binding: bool = False,
    required_request_parameters: tuple[str, ...],
    enforce_required_parameter_support: bool = True,
) -> dict[str, Any]:
    item_model_id = raw_endpoint.get("model_id")
    if (
        require_item_model_binding or item_model_id is not None
    ) and item_model_id != exact_model_id:
        raise EndpointSnapshotValidationError(
            "endpoint record is not bound to the exact requested model"
        )
    identities = _endpoint_identities(raw_endpoint)
    if configured_endpoint not in identities:
        raise EndpointSnapshotValidationError(
            "endpoint record does not match the configured tag or slug"
        )
    tag = _optional_endpoint_id(raw_endpoint.get("tag"), "endpoint tag")
    slug_values = [
        _optional_endpoint_id(raw_endpoint.get(key), f"endpoint {key}")
        for key in ("slug", "provider_slug")
        if raw_endpoint.get(key) is not None
    ]
    slug = slug_values[0] if slug_values else None
    provider_name = _provider_display_name(raw_endpoint.get("provider_name"))
    status = _operational_status(raw_endpoint.get("status"))
    supported = _supported_parameters(raw_endpoint.get("supported_parameters"))
    supported_reasoning_efforts = _optional_endpoint_reasoning_efforts(raw_endpoint)
    structured = structured_output_parameters(supported)
    output_modes = supported_output_modes(supported)
    if enforce_required_parameter_support and not set(required_request_parameters).issubset(
        supported
    ):
        missing = sorted(set(required_request_parameters) - set(supported))
        raise EndpointSnapshotValidationError(
            "configured endpoint lacks emitted request parameter support: " + ", ".join(missing)
        )
    pricing, pricing_overrides = canonicalize_openrouter_pricing_schedule(
        raw_endpoint.get("pricing"),
        price_lexeme_layout=price_lexeme_layout,
        price_lexeme_parent_path=price_lexeme_parent_path,
    )
    (
        context_length,
        max_prompt_tokens,
        max_prompt_tokens_source,
        max_completion_tokens,
        max_completion_tokens_source,
    ) = canonicalize_openrouter_endpoint_token_limits(raw_endpoint)
    normalized: dict[str, Any] = {
        "exact_model_id": exact_model_id,
        "provider_endpoint": configured_endpoint,
        "endpoint_tag": tag,
        "endpoint_slug": slug,
        "provider_name": provider_name,
        "operational": True,
        "operational_status": status,
        "supported_parameters": supported,
        "supported_reasoning_efforts": supported_reasoning_efforts,
        "required_request_parameters": required_request_parameters,
        "structured_output_parameters": structured,
        "supported_output_modes": output_modes,
        "structured_output_mode": output_modes[0],
        "context_length": context_length,
        "max_prompt_tokens": max_prompt_tokens,
        "max_prompt_tokens_source": max_prompt_tokens_source,
        "max_completion_tokens": max_completion_tokens,
        "max_completion_tokens_source": max_completion_tokens_source,
        "pricing": pricing,
        "pricing_sha256": openrouter_pricing_schedule_sha256(
            pricing,
            pricing_overrides,
        ),
    }
    if pricing_overrides:
        normalized["pricing_overrides"] = pricing_overrides
        normalized["tiered_pricing_cost_projection"] = project_openrouter_pricing_schedule(
            pricing,
            pricing_overrides,
        )
    normalized["output_capability_sha256"] = _canonical_sha256(
        _endpoint_output_capability_projection(normalized)
    )
    return normalized


def _operational_status(value: Any) -> str:
    if isinstance(value, bool):
        raise EndpointSnapshotValidationError("endpoint operational status is invalid")
    if isinstance(value, int):
        if value == 0:
            return "0"
        raise EndpointSnapshotValidationError("configured endpoint is not operational")
    if isinstance(value, str):
        normalized = value.casefold()
        if normalized in _OPERATIONAL_TEXT_STATUSES:
            return normalized
        raise EndpointSnapshotValidationError("configured endpoint is not operational")
    raise EndpointSnapshotValidationError("endpoint operational status is missing")


def _supported_parameters(value: Any) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or len(value) > _MAX_PARAMETERS
        or any(
            not isinstance(item, str) or not item or len(item) > 100 or item != item.casefold()
            for item in value
        )
    ):
        raise EndpointSnapshotValidationError("endpoint supported parameters are invalid")
    if len(value) != len(set(value)):
        raise EndpointSnapshotValidationError("endpoint supported parameters are duplicated")
    return tuple(sorted(value))


def _optional_endpoint_reasoning_efforts(
    raw_endpoint: Mapping[str, Any],
) -> tuple[ReasoningEffort, ...] | None:
    raw_reasoning = raw_endpoint.get("reasoning")
    if raw_reasoning is None:
        return None
    if not isinstance(raw_reasoning, dict) or len(raw_reasoning) > 16:
        raise EndpointSnapshotValidationError("endpoint reasoning metadata is invalid")
    value = raw_reasoning.get("supported_efforts")
    if value is None:
        return None
    if (
        not isinstance(value, list)
        or len(value) > len(REASONING_EFFORT_ORDER)
        or any(not isinstance(item, str) or item not in REASONING_EFFORT_ORDER for item in value)
        or len(value) != len(set(value))
    ):
        raise EndpointSnapshotValidationError("endpoint supported reasoning efforts are invalid")
    selected = frozenset(value)
    return tuple(effort for effort in REASONING_EFFORT_ORDER if effort in selected)


def canonicalize_openrouter_supported_parameters(value: Any) -> tuple[str, ...]:
    """Return the exact production endpoint parameter inventory."""

    return _supported_parameters(value)


def canonicalize_openrouter_endpoint_token_limits(
    raw_endpoint: Mapping[str, Any],
) -> tuple[
    int,
    int,
    Literal["metadata", "context_limit"],
    int,
    Literal["metadata", "context_limit"],
]:
    """Return the exact production context, prompt, and completion ceilings."""

    context_length = _positive_integer(
        raw_endpoint.get("context_length"),
        "endpoint context length",
    )
    max_prompt_tokens, max_prompt_tokens_source = _effective_token_limit(
        raw_endpoint.get("max_prompt_tokens"),
        context_length=context_length,
        label="endpoint prompt limit",
    )
    max_completion_tokens, max_completion_tokens_source = _effective_token_limit(
        raw_endpoint.get("max_completion_tokens"),
        context_length=context_length,
        label="endpoint completion limit",
    )
    if max_prompt_tokens > context_length:
        raise EndpointSnapshotValidationError("endpoint prompt limit exceeds its context length")
    if max_completion_tokens > context_length:
        raise EndpointSnapshotValidationError(
            "endpoint completion limit exceeds its context length"
        )
    return (
        context_length,
        max_prompt_tokens,
        max_prompt_tokens_source,
        max_completion_tokens,
        max_completion_tokens_source,
    )


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= 2**31 - 1:
        raise EndpointSnapshotValidationError(f"{label} is invalid")
    return int(value)


def _effective_token_limit(
    value: Any,
    *,
    context_length: int,
    label: str,
) -> tuple[int, Literal["metadata", "context_limit"]]:
    """Use the context ceiling when OpenRouter publishes a null endpoint limit."""

    if value is None:
        return context_length, "context_limit"
    return _positive_integer(value, label), "metadata"


def canonicalize_openrouter_pricing_schedule(
    value: Any,
    *,
    price_lexeme_layout: OpenRouterPriceLexemeLayout | None = None,
    price_lexeme_parent_path: OpenRouterJSONPath | None = None,
    _price_lexeme_guard: Callable[[], bool] = price_lexeme_callables_are_pristine,
    _captured_raw: Callable[[object], str | None] = captured_openrouter_json_number_raw,
    _captured_decimal: Callable[[object], Decimal | None] = (
        captured_openrouter_json_number_decimal
    ),
    _captured_path_matches: Callable[..., bool] = captured_openrouter_json_number_matches_path,
    _captured_revoke: Callable[[object], None] = revoke_captured_openrouter_json_number,
    _price_path_validator: Callable[..., bool] = openrouter_json_number_is_price_path,
) -> tuple[dict[str, str], tuple[OpenRouterPricingOverrideTier, ...]]:
    """Return exact base prices and a validated ordered conditional schedule."""

    if (
        price_lexemes_module.price_lexeme_callables_are_pristine is not _price_lexeme_guard
        or price_lexemes_module.captured_openrouter_json_number_raw is not _captured_raw
        or price_lexemes_module.captured_openrouter_json_number_decimal is not _captured_decimal
        or price_lexemes_module.captured_openrouter_json_number_matches_path
        is not _captured_path_matches
        or price_lexemes_module.revoke_captured_openrouter_json_number is not _captured_revoke
        or price_lexemes_module.openrouter_json_number_is_price_path is not _price_path_validator
        or not _price_lexeme_guard()
    ):
        raise EndpointSnapshotValidationError("endpoint price-lexeme custody changed")

    if (
        not isinstance(value, dict)
        or not 1 <= len(value) <= _MAX_PRICING_FIELDS
        or any(not isinstance(field, str) for field in value)
    ):
        raise EndpointSnapshotValidationError("endpoint pricing must be a bounded object")
    if not {"prompt", "completion"}.issubset(value):
        raise EndpointSnapshotValidationError("endpoint pricing omits prompt or completion")
    if len({field.casefold() for field in value}) != len(value):
        raise EndpointSnapshotValidationError("endpoint pricing fields are ambiguous")
    pricing_items = tuple(dict.items(value))
    captured_values_list = [
        raw_price for _field, raw_price in pricing_items if _captured_raw(raw_price) is not None
    ]
    raw_overrides = value.get("overrides")
    if type(raw_overrides) is list:
        for raw_tier in list.__iter__(raw_overrides):
            if type(raw_tier) is not dict:
                continue
            captured_values_list.extend(
                raw_price
                for _field, raw_price in dict.items(raw_tier)
                if _captured_raw(raw_price) is not None
            )
    captured_values = tuple(captured_values_list)

    def revoke_captured_values() -> None:
        for captured_value in captured_values:
            _captured_revoke(captured_value)

    has_layout = price_lexeme_layout is not None
    has_parent_path = price_lexeme_parent_path is not None
    if has_layout != has_parent_path:
        revoke_captured_values()
        raise EndpointSnapshotValidationError(
            "endpoint price-lexeme layout and full-path context must be supplied together"
        )
    if has_layout:
        assert price_lexeme_layout is not None
        assert price_lexeme_parent_path is not None
        try:
            valid_parent_path = type(price_lexeme_parent_path) is tuple and _price_path_validator(
                (*price_lexeme_parent_path, "prompt"),
                layout=price_lexeme_layout,
            )
        except (TypeError, ValueError):
            valid_parent_path = False
        if not valid_parent_path:
            revoke_captured_values()
            raise EndpointSnapshotValidationError(
                "endpoint price-lexeme full-path context is invalid"
            )
    elif captured_values:
        revoke_captured_values()
        raise EndpointSnapshotValidationError(
            "endpoint captured numeric price lacks full-path custody"
        )
    normalized: dict[str, str] = {}
    for field, raw_price in sorted(pricing_items):
        if not _PRICING_FIELD_PATTERN.fullmatch(field):
            raise EndpointSnapshotValidationError("endpoint pricing field is invalid")
        if field == "overrides":
            continue
        captured_raw = _captured_raw(raw_price)
        if captured_raw is not None:
            assert price_lexeme_layout is not None
            assert price_lexeme_parent_path is not None
            if not _captured_path_matches(
                raw_price,
                layout=price_lexeme_layout,
                path=(*price_lexeme_parent_path, field),
            ):
                raise EndpointSnapshotValidationError(
                    "endpoint captured numeric price full-path binding changed"
                )
        if field in _NON_BILLABLE_PRICING_METADATA:
            _validate_non_billable_pricing_metadata(
                field,
                raw_price,
                _captured_decimal=_captured_decimal,
            )
            continue
        if isinstance(raw_price, str):
            normalized[field] = _canonical_price(raw_price)
            continue
        if captured_raw is None:
            if raw_price is None or (
                isinstance(raw_price, Mapping | Sequence)
                and not isinstance(raw_price, str | bytes | bytearray)
            ):
                raise EndpointSnapshotValidationError(
                    f"endpoint pricing field {field} must be a scalar exact decimal string"
                )
            raise EndpointSnapshotValidationError("endpoint prices must be exact decimal strings")
        canonical = _canonical_price(captured_raw)
        if canonical != captured_raw:
            raise EndpointSnapshotValidationError(
                "endpoint captured numeric price is not canonically encoded"
            )
        normalized[field] = captured_raw
    overrides = _canonicalize_openrouter_pricing_overrides(
        raw_overrides,
        present="overrides" in value,
        price_lexeme_layout=price_lexeme_layout,
        price_lexeme_parent_path=price_lexeme_parent_path,
        captured_raw=_captured_raw,
        captured_path_matches=_captured_path_matches,
        captured_revoke=_captured_revoke,
    )
    return normalized, overrides


def canonicalize_openrouter_pricing(
    value: Any,
    *,
    price_lexeme_layout: OpenRouterPriceLexemeLayout | None = None,
    price_lexeme_parent_path: OpenRouterJSONPath | None = None,
    _price_lexeme_guard: Callable[[], bool] = price_lexeme_callables_are_pristine,
    _captured_raw: Callable[[object], str | None] = captured_openrouter_json_number_raw,
    _captured_decimal: Callable[[object], Decimal | None] = (
        captured_openrouter_json_number_decimal
    ),
    _captured_path_matches: Callable[..., bool] = captured_openrouter_json_number_matches_path,
    _captured_revoke: Callable[[object], None] = revoke_captured_openrouter_json_number,
    _price_path_validator: Callable[..., bool] = openrouter_json_number_is_price_path,
) -> dict[str, str]:
    """Return flat exact prices and refuse a conditional schedule rather than dropping it."""

    pricing, overrides = canonicalize_openrouter_pricing_schedule(
        value,
        price_lexeme_layout=price_lexeme_layout,
        price_lexeme_parent_path=price_lexeme_parent_path,
        _price_lexeme_guard=_price_lexeme_guard,
        _captured_raw=_captured_raw,
        _captured_decimal=_captured_decimal,
        _captured_path_matches=_captured_path_matches,
        _captured_revoke=_captured_revoke,
        _price_path_validator=_price_path_validator,
    )
    if overrides:
        raise EndpointSnapshotValidationError(
            "endpoint pricing contains structured overrides that require schedule-aware evidence"
        )
    return pricing


def _canonicalize_openrouter_pricing_overrides(
    value: Any,
    *,
    present: bool,
    price_lexeme_layout: OpenRouterPriceLexemeLayout | None,
    price_lexeme_parent_path: OpenRouterJSONPath | None,
    captured_raw: Callable[[object], str | None],
    captured_path_matches: Callable[..., bool],
    captured_revoke: Callable[[object], None],
) -> tuple[OpenRouterPricingOverrideTier, ...]:
    if not present:
        return ()
    if type(value) is not list or not 1 <= len(value) <= _MAX_PRICING_OVERRIDES:
        if captured_raw(value) is not None:
            captured_revoke(value)
        raise EndpointSnapshotValidationError(
            "endpoint pricing overrides must be a nonempty bounded list"
        )

    tiers: list[OpenRouterPricingOverrideTier] = []
    previous_threshold: int | None = None
    for index, raw_tier in enumerate(list.__iter__(value)):
        if (
            type(raw_tier) is not dict
            or not 1 <= len(raw_tier) <= _MAX_PRICING_FIELDS + 1
            or any(type(field) is not str for field in raw_tier)
        ):
            raise EndpointSnapshotValidationError(
                "endpoint pricing override entry must be a bounded object"
            )
        if len({field.casefold() for field in raw_tier}) != len(raw_tier):
            raise EndpointSnapshotValidationError("endpoint pricing override fields are ambiguous")
        unsupported_conditions = sorted(
            set(raw_tier).intersection(_PRICING_OVERRIDE_CONDITIONS - {"min_prompt_tokens"})
        )
        if unsupported_conditions:
            raise EndpointSnapshotValidationError(
                "endpoint pricing override condition is unsupported: " + unsupported_conditions[0]
            )
        if "min_prompt_tokens" not in raw_tier:
            raise EndpointSnapshotValidationError(
                "endpoint pricing override entry omits min_prompt_tokens"
            )
        threshold = raw_tier["min_prompt_tokens"]
        if type(threshold) is not int or not 0 <= threshold <= _MAX_PRICING_OVERRIDE_PROMPT_TOKENS:
            raise EndpointSnapshotValidationError(
                "endpoint pricing override min_prompt_tokens must be an exact bounded "
                "nonnegative integer"
            )
        if previous_threshold is not None:
            if threshold == previous_threshold:
                raise EndpointSnapshotValidationError(
                    "endpoint pricing override thresholds are duplicated"
                )
            if threshold < previous_threshold:
                raise EndpointSnapshotValidationError(
                    "endpoint pricing override thresholds must be strictly increasing in "
                    "provider order"
                )
        previous_threshold = threshold

        prices: dict[str, str] = {}
        for field, raw_price in sorted(dict.items(raw_tier)):
            if field == "min_prompt_tokens":
                continue
            if field == "overrides":
                raise EndpointSnapshotValidationError(
                    "endpoint pricing override cannot contain recursive overrides"
                )
            if (
                not _PRICING_FIELD_PATTERN.fullmatch(field)
                or field not in _SUPPORTED_PRICING_OVERRIDE_FIELDS
            ):
                raise EndpointSnapshotValidationError(
                    "endpoint pricing override price field is invalid"
                )
            captured = captured_raw(raw_price)
            if captured is not None:
                if price_lexeme_layout is None or price_lexeme_parent_path is None:
                    captured_revoke(raw_price)
                    raise EndpointSnapshotValidationError(
                        "endpoint captured numeric override price lacks full-path custody"
                    )
                if not captured_path_matches(
                    raw_price,
                    layout=price_lexeme_layout,
                    path=(*price_lexeme_parent_path, "overrides", index, field),
                ):
                    raise EndpointSnapshotValidationError(
                        "endpoint captured numeric override price full-path binding changed"
                    )
            if not isinstance(raw_price, str):
                if raw_price is None or (
                    isinstance(raw_price, Mapping | Sequence)
                    and not isinstance(raw_price, str | bytes | bytearray)
                ):
                    raise EndpointSnapshotValidationError(
                        f"endpoint pricing override field {field} must be a scalar exact "
                        "decimal string"
                    )
                raise EndpointSnapshotValidationError(
                    f"endpoint pricing override field {field} must be an exact decimal string"
                )
            prices[field] = _canonical_price(raw_price)
        if not prices:
            raise EndpointSnapshotValidationError(
                "endpoint pricing override entry must include a billable price"
            )
        try:
            tiers.append(
                OpenRouterPricingOverrideTier(
                    min_prompt_tokens=threshold,
                    prices=prices,
                )
            )
        except ValueError as exc:
            raise EndpointSnapshotValidationError(
                "endpoint pricing override entry is invalid"
            ) from exc
    return tuple(tiers)


def openrouter_pricing_schedule_sha256(
    pricing: Mapping[str, str],
    overrides: Sequence[OpenRouterPricingOverrideTier],
) -> str:
    """Hash base prices exactly as before, and bind every ordered conditional tier."""

    if not overrides:
        return _canonical_sha256(dict(pricing))
    return _canonical_sha256(
        {
            "domain": "mmaudit.openrouter.pricing_schedule.v1",
            "base_pricing": dict(pricing),
            "pricing_overrides": [
                {
                    "min_prompt_tokens": tier.min_prompt_tokens,
                    "prices": dict(tier.prices),
                }
                for tier in overrides
            ],
        }
    )


def project_openrouter_pricing_schedule(
    pricing: Mapping[str, str],
    overrides: Sequence[OpenRouterPricingOverrideTier],
) -> ExactRoutePricingSchedule | Literal["unavailable"]:
    """Derive the shared exact schedule maximum or a fail-closed unavailable state."""

    try:
        base_pricing = normalize_exact_route_pricing(pricing)
        tiers = tuple(
            ExactRoutePriceTier.build(
                min_prompt_tokens=tier.min_prompt_tokens,
                pricing=tier.prices,
            )
            for tier in overrides
        )
        return ExactRoutePricingSchedule.build(
            base_pricing=base_pricing,
            tiers=tiers,
        )
    except (RouteConstraintError, ValueError):
        return "unavailable"


def effective_openrouter_pricing(
    pricing: Mapping[str, str],
    overrides: Sequence[OpenRouterPricingOverrideTier],
    *,
    prompt_tokens: int,
) -> dict[str, str]:
    """Resolve one canonical strict-threshold schedule state without granting authority."""

    if (
        type(prompt_tokens) is not int
        or not 0 <= prompt_tokens <= _MAX_PRICING_OVERRIDE_PROMPT_TOKENS
    ):
        raise EndpointSnapshotValidationError(
            "effective endpoint prompt tokens must be an exact bounded nonnegative integer"
        )
    result = dict(pricing)
    for tier in overrides:
        if prompt_tokens > tier.min_prompt_tokens:
            result.update(tier.prices)
    return dict(sorted(result.items()))


def _validate_non_billable_pricing_metadata(
    field: str,
    value: Any,
    *,
    _captured_decimal: Callable[[object], Decimal | None] = (
        captured_openrouter_json_number_decimal
    ),
) -> None:
    captured_decimal = _captured_decimal(value)
    if captured_decimal is not None:
        parsed = captured_decimal
    elif isinstance(value, bool) or not isinstance(value, int | float | str):
        raise EndpointSnapshotValidationError(
            f"endpoint {field} metadata must be a finite nonnegative fraction"
        )
    else:
        try:
            parsed = Decimal(str(value))
        except InvalidOperation as error:
            raise EndpointSnapshotValidationError(
                f"endpoint {field} metadata is invalid"
            ) from error
    if not parsed.is_finite() or not Decimal(0) <= parsed < Decimal(1):
        raise EndpointSnapshotValidationError(
            f"endpoint {field} metadata must be a finite nonnegative fraction"
        )


def _canonical_price(value: str) -> str:
    if not isinstance(value, str) or _DECIMAL_PRICE_PATTERN.fullmatch(value) is None:
        raise EndpointSnapshotValidationError("endpoint price is not a bounded decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise EndpointSnapshotValidationError("endpoint price is invalid") from error
    if not parsed.is_finite() or parsed < 0:
        raise EndpointSnapshotValidationError("endpoint price must be finite and nonnegative")
    if parsed == 0:
        return "0"
    canonical = format(parsed, "f")
    if "." in canonical:
        canonical = canonical.rstrip("0").rstrip(".")
    return canonical


def _validate_zdr_counterpart(
    endpoint: Mapping[str, Any],
    zdr_endpoint: Mapping[str, Any],
) -> None:
    compared_fields = (
        "exact_model_id",
        "provider_endpoint",
        "endpoint_tag",
        "endpoint_slug",
        "provider_name",
        "operational",
        "operational_status",
        "supported_parameters",
        "supported_reasoning_efforts",
        "structured_output_parameters",
        "supported_output_modes",
        "structured_output_mode",
        "output_capability_sha256",
        "context_length",
        "max_prompt_tokens",
        "max_prompt_tokens_source",
        "max_completion_tokens",
        "max_completion_tokens_source",
        "pricing",
        "pricing_overrides",
        "tiered_pricing_cost_projection",
        "pricing_sha256",
    )
    if any(endpoint.get(field) != zdr_endpoint.get(field) for field in compared_fields):
        raise EndpointSnapshotValidationError(
            "per-model and ZDR endpoint metadata snapshots are inconsistent"
        )


def _endpoint_output_capability_projection(
    endpoint: Mapping[str, Any] | OpenRouterEndpointEvidence,
) -> dict[str, Any]:
    values: Mapping[str, Any]
    if isinstance(endpoint, OpenRouterEndpointEvidence):
        values = endpoint.model_dump(mode="python")
    else:
        values = endpoint
    return {
        "exact_model_id": values["exact_model_id"],
        "provider_endpoint": values["provider_endpoint"],
        "supported_parameters": values["supported_parameters"],
        "supported_reasoning_efforts": values["supported_reasoning_efforts"],
        "required_request_parameters": values["required_request_parameters"],
        "structured_output_parameters": values["structured_output_parameters"],
        "supported_output_modes": values["supported_output_modes"],
        "structured_output_mode": values["structured_output_mode"],
    }


def _endpoint_output_capability_sha256(endpoint: OpenRouterEndpointEvidence) -> str:
    return _canonical_sha256(_endpoint_output_capability_projection(endpoint))


def _policy_output_capability_sha256(
    snapshot: OpenRouterEndpointSnapshotEvidence,
) -> str:
    return _canonical_sha256(
        {
            "schema_version": snapshot.schema_version,
            "exact_model_id": snapshot.exact_model_id,
            "provider_policy_mode": snapshot.provider_policy_mode,
            "configured_provider_endpoints": snapshot.configured_provider_endpoints,
            "endpoint_output_capability_sha256": tuple(
                endpoint.output_capability_sha256 for endpoint in snapshot.endpoints
            ),
            "supported_output_modes": snapshot.supported_output_modes,
            "structured_output_mode": snapshot.structured_output_mode,
        }
    )


def output_capability_binding_sha256(
    snapshot: OpenRouterEndpointSnapshotEvidence,
) -> str:
    """Bind negotiated output capability to the complete endpoint snapshot."""

    return _canonical_sha256(
        {
            "endpoint_snapshot_sha256": snapshot.snapshot_sha256,
            "output_capability_sha256": snapshot.output_capability_sha256,
        }
    )


def _seal_endpoint_evidence(
    normalized: Mapping[str, Any],
    *,
    zdr_eligible: bool | None,
    zdr_endpoint_snapshot_sha256: str | None,
) -> OpenRouterEndpointEvidence:
    serialized = {
        **normalized,
        "zdr_eligible": zdr_eligible,
        "zdr_endpoint_snapshot_sha256": zdr_endpoint_snapshot_sha256,
    }
    return OpenRouterEndpointEvidence.model_validate(
        {
            **serialized,
            "endpoint_snapshot_sha256": _canonical_sha256(serialized),
        }
    )


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=_canonical_json_default,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonical_json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    raise TypeError(f"unsupported canonical endpoint value: {type(value).__name__}")
