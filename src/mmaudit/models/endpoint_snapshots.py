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
from collections.abc import Mapping, Sequence
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mmaudit.models.identifiers import is_exact_openrouter_model_id
from mmaudit.models.output_modes import (
    StructuredOutputMode,
    mutually_supported_output_modes,
    output_mode_request_parameters,
    structured_output_parameters,
    supported_output_modes,
)
from mmaudit.models.reasoning import ReasoningControlProfile

_MODEL_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
_ENDPOINT_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"
_PROVIDER_NAME_MAX_LENGTH = 128
_PRICING_FIELD_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_DECIMAL_PRICE_PATTERN = re.compile(r"(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,36})?\Z")
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
_SNAPSHOT_SCHEMA_VERSION = "1.0"
_NON_BILLABLE_PRICING_METADATA = frozenset({"discount"})

ReasoningParameterSupport = Literal["supported", "unsupported", "unknown"]


class EndpointSnapshotValidationError(ValueError):
    """Raised when endpoint metadata cannot prove the configured routing policy."""


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
            if not _PRICING_FIELD_PATTERN.fullmatch(field):
                raise ValueError("endpoint pricing contains an invalid field")
            if _canonical_price(value) != value:
                raise ValueError("endpoint pricing is not canonically encoded")
        if self.pricing_sha256 != _canonical_sha256(self.pricing):
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
    max_output_tokens: int = Field(gt=0, le=2**31 - 1)
    max_reasoning_tokens: int | None = Field(default=None, gt=0, le=65_536)
    capability_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

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
            endpoint = OpenRouterEndpointEvidence.model_validate(endpoint.model_dump(mode="json"))
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
        _supported_parameters(endpoint.get("supported_parameters")) for endpoint in matched
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
    for raw_endpoint in matched:
        provider_name = _provider_display_name(raw_endpoint.get("provider_name"))
        if provider_name_counts[provider_name.casefold()] != 1:
            raise EndpointSnapshotValidationError(
                "configured endpoint provider display name is ambiguous in exact-model metadata"
            )

    zdr_matches: dict[str, Mapping[str, Any] | None]
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
        )

    endpoint_evidence: list[OpenRouterEndpointEvidence] = []
    endpoint_projection: list[dict[str, Any]] = []
    for endpoint_id, raw_endpoint in zip(configured, matched, strict=True):
        normalized = _normalize_endpoint(
            exact_model_id=exact_model_id,
            configured_endpoint=endpoint_id,
            raw_endpoint=raw_endpoint,
            required_request_parameters=required_request_parameters,
        )
        zdr_raw = zdr_matches[endpoint_id]
        zdr_hash: str | None = None
        zdr_eligible: bool | None = None if zdr_payload is None else False
        if zdr_raw is not None:
            normalized_zdr = _normalize_endpoint(
                exact_model_id=exact_model_id,
                configured_endpoint=endpoint_id,
                raw_endpoint=zdr_raw,
                require_item_model_binding=True,
                required_request_parameters=required_request_parameters,
            )
            _validate_zdr_counterpart(normalized, normalized_zdr)
            zdr_eligible = True
            zdr_hash = _canonical_sha256(normalized_zdr)
        if require_zdr and zdr_eligible is not True:
            raise EndpointSnapshotValidationError(
                f"configured endpoint is not present in the exact-model ZDR snapshot: {endpoint_id}"
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
        "endpoints": [item.model_dump(mode="json") for item in endpoint_evidence],
        "supported_output_modes": sealed_common_output_modes,
        "structured_output_mode": negotiated_output_mode,
        "output_capability_sha256": _canonical_sha256(output_capability_projection),
        "endpoint_metadata_sha256": _canonical_sha256(endpoint_metadata_projection),
        "zdr_metadata_sha256": (
            _canonical_sha256(zdr_projection) if zdr_projection is not None else None
        ),
    }
    return OpenRouterEndpointSnapshotEvidence.model_validate(
        {
            **serialized,
            "snapshot_sha256": _canonical_sha256(serialized),
        }
    )


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
) -> list[Mapping[str, Any]]:
    identities = [_endpoint_identities(endpoint) for endpoint in endpoints]
    matched: list[Mapping[str, Any]] = []
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
        matched_indexes.add(indexes[0])
        matched.append(endpoints[indexes[0]])
    return matched


def _match_zdr_endpoints(
    *,
    exact_model_id: str,
    configured: tuple[str, ...],
    payload: Any,
    required_request_parameters: tuple[str, ...],
) -> tuple[dict[str, Mapping[str, Any] | None], dict[str, Any]]:
    envelope = _required_mapping(payload, "ZDR endpoint metadata")
    raw_items = _required_endpoint_list(
        envelope.get("data"),
        "ZDR endpoint metadata",
        allow_empty=True,
    )
    exact_model_items: list[Mapping[str, Any]] = []
    for item in raw_items:
        item_model = item.get("model_id")
        if not isinstance(item_model, str):
            raise EndpointSnapshotValidationError("ZDR endpoint omits its exact model binding")
        if item_model == exact_model_id:
            exact_model_items.append(item)
    identities = [_endpoint_identities(item) for item in exact_model_items]
    matches: dict[str, Mapping[str, Any] | None] = {}
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
        projection.append(
            {
                "provider_endpoint": configured_endpoint,
                "eligible": match is not None,
                "endpoint": (
                    _normalize_endpoint(
                        exact_model_id=exact_model_id,
                        configured_endpoint=configured_endpoint,
                        raw_endpoint=match,
                        require_item_model_binding=True,
                        required_request_parameters=required_request_parameters,
                    )
                    if match is not None
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
    require_item_model_binding: bool = False,
    required_request_parameters: tuple[str, ...],
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
    structured = structured_output_parameters(supported)
    output_modes = supported_output_modes(supported)
    if not set(required_request_parameters).issubset(supported):
        missing = sorted(set(required_request_parameters) - set(supported))
        raise EndpointSnapshotValidationError(
            "configured endpoint lacks emitted request parameter support: " + ", ".join(missing)
        )
    pricing = canonicalize_openrouter_pricing(raw_endpoint.get("pricing"))
    (
        context_length,
        max_prompt_tokens,
        max_prompt_tokens_source,
        max_completion_tokens,
        max_completion_tokens_source,
    ) = canonicalize_openrouter_endpoint_token_limits(raw_endpoint)
    normalized = {
        "exact_model_id": exact_model_id,
        "provider_endpoint": configured_endpoint,
        "endpoint_tag": tag,
        "endpoint_slug": slug,
        "provider_name": provider_name,
        "operational": True,
        "operational_status": status,
        "supported_parameters": supported,
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
        "pricing_sha256": _canonical_sha256(pricing),
    }
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


def canonicalize_openrouter_pricing(value: Any) -> dict[str, str]:
    """Return the shared exact billable-price projection from endpoint metadata."""

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
    normalized: dict[str, str] = {}
    for field in sorted(value):
        if not _PRICING_FIELD_PATTERN.fullmatch(field):
            raise EndpointSnapshotValidationError("endpoint pricing field is invalid")
        raw_price = value[field]
        if field in _NON_BILLABLE_PRICING_METADATA:
            _validate_non_billable_pricing_metadata(field, raw_price)
            continue
        if not isinstance(raw_price, str):
            raise EndpointSnapshotValidationError("endpoint prices must be exact decimal strings")
        normalized[field] = _canonical_price(raw_price)
    return normalized


def _validate_non_billable_pricing_metadata(field: str, value: Any) -> None:
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        raise EndpointSnapshotValidationError(
            f"endpoint {field} metadata must be a finite nonnegative fraction"
        )
    try:
        parsed = Decimal(str(value))
    except InvalidOperation as error:
        raise EndpointSnapshotValidationError(f"endpoint {field} metadata is invalid") from error
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
    return format(parsed.normalize(), "f")


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
        "pricing_sha256",
    )
    if any(endpoint[field] != zdr_endpoint[field] for field in compared_fields):
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
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
