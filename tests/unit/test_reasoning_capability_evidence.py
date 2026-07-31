from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.endpoint_snapshots import (
    EndpointSnapshotValidationError,
    OpenRouterEndpointEvidence,
    OpenRouterReasoningCapabilityEvidence,
    ReasoningParameterSupport,
    validate_openrouter_endpoint_snapshot,
)
from mmaudit.models.reasoning import ReasoningControlProfile, ReasoningEffort

_MODEL_METADATA_HASH = "a" * 64
_ALL_REASONING_EFFORTS: tuple[ReasoningEffort, ...] = (
    "none",
    "minimal",
    "low",
    "medium",
    "high",
    "xhigh",
)


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _endpoint(
    *,
    reasoning: bool = True,
    supported_efforts: tuple[ReasoningEffort, ...] | None = _ALL_REASONING_EFFORTS,
    max_output_tokens: int = 20_000,
) -> dict[str, Any]:
    supported_parameters = ["max_tokens", "response_format", "temperature"]
    if reasoning:
        supported_parameters.append("reasoning")
    endpoint: dict[str, Any] = {
        "tag": "approved-provider",
        "provider_name": "Approved Provider",
        "status": 0,
        "context_length": 200_000,
        "max_prompt_tokens": 180_000,
        "max_completion_tokens": max_output_tokens,
        "supported_parameters": supported_parameters,
        "pricing": {
            "prompt": "0.000003",
            "completion": "0.000015",
        },
    }
    if reasoning and supported_efforts is not None:
        endpoint["reasoning"] = {"supported_efforts": list(supported_efforts)}
    return endpoint


def _endpoint_evidence(
    *,
    reasoning: bool = True,
    supported_efforts: tuple[ReasoningEffort, ...] | None = _ALL_REASONING_EFFORTS,
    max_output_tokens: int = 20_000,
) -> OpenRouterEndpointEvidence:
    endpoint = _endpoint(
        reasoning=reasoning,
        supported_efforts=supported_efforts,
        max_output_tokens=max_output_tokens,
    )
    return validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("approved-provider",),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": "alpha/atlas-secure",
                "endpoints": [endpoint],
            }
        },
        require_zdr=False,
    ).endpoints[0]


def _capability(
    *,
    endpoint: OpenRouterEndpointEvidence | None = None,
    parameter_support: ReasoningParameterSupport = "supported",
    metadata_available: bool = True,
    mandatory: bool | None = False,
    default_enabled: bool | None = False,
    supports_max_tokens: bool | None = True,
    supported_efforts: tuple[ReasoningEffort, ...] | None = _ALL_REASONING_EFFORTS,
    max_reasoning_tokens: int | None = None,
) -> OpenRouterReasoningCapabilityEvidence:
    return OpenRouterReasoningCapabilityEvidence.from_endpoint(
        endpoint=endpoint or _endpoint_evidence(supported_efforts=supported_efforts),
        model_metadata_snapshot_sha256=_MODEL_METADATA_HASH,
        reasoning_parameter_support=parameter_support,
        reasoning_metadata_available=metadata_available,
        reasoning_mandatory=mandatory,
        reasoning_default_enabled=default_enabled,
        reasoning_supports_max_tokens=supports_max_tokens,
        max_reasoning_tokens=max_reasoning_tokens,
    )


def _profile(
    mode: str,
    *,
    effort: ReasoningEffort | None = None,
    max_tokens: int | None = None,
    reserve: int = 0,
) -> ReasoningControlProfile:
    return ReasoningControlProfile.build(
        mode=mode,  # type: ignore[arg-type]
        effort=effort,
        max_tokens=max_tokens,
        reserved_reasoning_tokens=reserve,
    )


def test_capability_binds_exact_endpoint_model_snapshots_and_normalized_states() -> None:
    evidence = _capability()

    assert evidence.exact_model_id == "alpha/atlas-secure"
    assert evidence.provider_endpoint == "approved-provider"
    assert evidence.endpoint_tag == "approved-provider"
    assert evidence.endpoint_slug is None
    assert evidence.provider_name == "Approved Provider"
    assert (
        evidence.endpoint_metadata_snapshot_sha256 == _endpoint_evidence().endpoint_snapshot_sha256
    )
    assert evidence.model_metadata_snapshot_sha256 == _MODEL_METADATA_HASH
    assert evidence.reasoning_parameter_support == "supported"
    assert evidence.reasoning_metadata_available is True
    assert evidence.supported_reasoning_efforts == _ALL_REASONING_EFFORTS
    assert evidence.max_output_tokens == 20_000
    assert evidence.max_reasoning_tokens is None
    assert len(evidence.capability_sha256) == 64


def test_unknown_capability_is_preserved_and_never_promoted() -> None:
    endpoint = _endpoint_evidence()
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "exact_model_id": endpoint.exact_model_id,
        "provider_endpoint": endpoint.provider_endpoint,
        "endpoint_tag": endpoint.endpoint_tag,
        "endpoint_slug": endpoint.endpoint_slug,
        "provider_name": endpoint.provider_name,
        "endpoint_metadata_snapshot_sha256": endpoint.endpoint_snapshot_sha256,
        "model_metadata_snapshot_sha256": _MODEL_METADATA_HASH,
        "reasoning_parameter_support": "unknown",
        "reasoning_metadata_available": False,
        "reasoning_mandatory": None,
        "reasoning_default_enabled": None,
        "reasoning_supports_max_tokens": None,
        "supported_reasoning_efforts": None,
        "max_output_tokens": endpoint.max_completion_tokens,
        "max_reasoning_tokens": None,
    }
    payload["capability_sha256"] = _canonical_sha256(payload)
    evidence = OpenRouterReasoningCapabilityEvidence.model_validate(payload)

    serialized = evidence.model_dump(mode="json")
    assert serialized["reasoning_parameter_support"] == "unknown"
    assert serialized["reasoning_mandatory"] is None
    with pytest.raises(EndpointSnapshotValidationError, match="lacks explicit"):
        evidence.require_compatible_profile(_profile("disabled"))
    with pytest.raises(EndpointSnapshotValidationError, match="explicit endpoint"):
        evidence.require_compatible_profile(_profile("effort", effort="high", reserve=1_024))


def test_factory_rejects_parameter_support_that_contradicts_exact_endpoint() -> None:
    with pytest.raises(EndpointSnapshotValidationError, match="contradicts"):
        _capability(parameter_support="unknown")
    with pytest.raises(EndpointSnapshotValidationError, match="contradicts"):
        _capability(
            endpoint=_endpoint_evidence(reasoning=False),
            parameter_support="supported",
            metadata_available=False,
            mandatory=None,
            default_enabled=None,
            supports_max_tokens=None,
            supported_efforts=None,
        )


def test_disabled_profile_requires_proof_that_omitting_reasoning_is_safe() -> None:
    unsupported = _capability(
        endpoint=_endpoint_evidence(reasoning=False),
        parameter_support="unsupported",
        metadata_available=False,
        mandatory=None,
        default_enabled=None,
        supports_max_tokens=None,
        supported_efforts=None,
    )
    unsupported.require_compatible_profile(_profile("disabled"))
    with pytest.raises(EndpointSnapshotValidationError, match="default-enabled"):
        _capability(
            endpoint=_endpoint_evidence(reasoning=False),
            parameter_support="unsupported",
            metadata_available=True,
            mandatory=False,
            default_enabled=True,
            supports_max_tokens=None,
        ).require_compatible_profile(_profile("disabled"))

    _capability().require_compatible_profile(_profile("disabled"))
    with pytest.raises(EndpointSnapshotValidationError, match="mandatory"):
        _capability(mandatory=True).require_compatible_profile(_profile("disabled"))
    with pytest.raises(EndpointSnapshotValidationError, match="default-enabled"):
        _capability(default_enabled=True).require_compatible_profile(_profile("disabled"))

    incomplete = _capability(
        metadata_available=False,
        mandatory=None,
        default_enabled=None,
        supports_max_tokens=None,
        supported_efforts=None,
    )
    with pytest.raises(EndpointSnapshotValidationError, match="frozen metadata"):
        incomplete.require_compatible_profile(_profile("disabled"))


def test_default_and_effort_profiles_require_complete_exact_capabilities() -> None:
    evidence = _capability()
    evidence.require_compatible_profile(_profile("default", reserve=2_048))
    evidence.require_compatible_profile(_profile("effort", effort="high", reserve=2_048))
    evidence.require_compatible_profile(_profile("effort", effort="none"))

    incomplete = _capability(
        metadata_available=False,
        mandatory=None,
        default_enabled=None,
        supports_max_tokens=None,
        supported_efforts=None,
    )
    with pytest.raises(EndpointSnapshotValidationError, match="frozen metadata"):
        incomplete.require_compatible_profile(_profile("default", reserve=1_024))
    evidence.require_compatible_profile(_profile("effort", effort="medium", reserve=1_024))
    with pytest.raises(EndpointSnapshotValidationError, match="mandatory"):
        _capability(mandatory=True).require_compatible_profile(_profile("effort", effort="none"))


def test_effort_profile_requires_exact_inventory_membership() -> None:
    generic_parameter_only = _capability(supported_efforts=None)
    with pytest.raises(EndpointSnapshotValidationError, match="supported-effort inventory"):
        generic_parameter_only.require_compatible_profile(
            _profile("effort", effort="high", reserve=1_024)
        )

    bounded_inventory = _capability(supported_efforts=("none", "high"))
    bounded_inventory.require_compatible_profile(_profile("effort", effort="high", reserve=1_024))
    bounded_inventory.require_compatible_profile(_profile("effort", effort="none"))
    with pytest.raises(EndpointSnapshotValidationError, match="absent from"):
        bounded_inventory.require_compatible_profile(
            _profile("effort", effort="xhigh", reserve=1_024)
        )
    _capability(supported_efforts=("xhigh",)).require_compatible_profile(
        _profile("effort", effort="xhigh", reserve=1_024)
    )


def test_effort_inventory_does_not_change_default_max_token_or_disabled_controls() -> None:
    no_inventory = _capability(supported_efforts=None)
    no_inventory.require_compatible_profile(_profile("disabled"))
    no_inventory.require_compatible_profile(_profile("default", reserve=1_024))
    no_inventory.require_compatible_profile(_profile("max_tokens", max_tokens=1_024, reserve=1_024))


def test_available_metadata_preserves_individually_unknown_states() -> None:
    evidence = _capability(
        mandatory=False,
        default_enabled=True,
        supports_max_tokens=None,
    )

    assert evidence.reasoning_metadata_available is True
    assert evidence.reasoning_supports_max_tokens is None
    with pytest.raises(EndpointSnapshotValidationError, match="exact frozen support"):
        evidence.require_compatible_profile(_profile("max_tokens", max_tokens=1_024, reserve=1_024))
    with pytest.raises(EndpointSnapshotValidationError, match="default-enabled state"):
        _capability(default_enabled=None).require_compatible_profile(
            _profile("default", reserve=1_024)
        )


def test_active_profile_reservation_cannot_exceed_frozen_output_limit() -> None:
    evidence = _capability(endpoint=_endpoint_evidence(max_output_tokens=2_000))

    with pytest.raises(EndpointSnapshotValidationError, match="frozen output limit"):
        evidence.require_compatible_profile(_profile("effort", effort="high", reserve=2_001))


def test_max_token_profile_respects_support_reasoning_and_output_bounds() -> None:
    evidence = _capability(endpoint=_endpoint_evidence(max_output_tokens=4_096))
    evidence.require_compatible_profile(_profile("max_tokens", max_tokens=4_096, reserve=4_096))

    with pytest.raises(EndpointSnapshotValidationError, match="frozen output limit"):
        evidence.require_compatible_profile(_profile("max_tokens", max_tokens=4_097, reserve=4_097))
    with pytest.raises(EndpointSnapshotValidationError, match="exact frozen support"):
        _capability(supports_max_tokens=False).require_compatible_profile(
            _profile("max_tokens", max_tokens=1_024, reserve=1_024)
        )
    published_ceiling = _capability(max_reasoning_tokens=2_048)
    published_ceiling.require_compatible_profile(
        _profile("max_tokens", max_tokens=2_048, reserve=2_048)
    )
    with pytest.raises(EndpointSnapshotValidationError, match="published reasoning ceiling"):
        published_ceiling.require_compatible_profile(
            _profile("max_tokens", max_tokens=2_049, reserve=2_049)
        )


def test_metadata_inconsistency_and_self_hash_tampering_fail_closed() -> None:
    with pytest.raises(EndpointSnapshotValidationError, match="invalid"):
        _capability(
            metadata_available=False,
            mandatory=False,
            default_enabled=None,
            supports_max_tokens=None,
            supported_efforts=None,
        )
    with pytest.raises(EndpointSnapshotValidationError, match="invalid"):
        _capability(supports_max_tokens=None, max_reasoning_tokens=1_024)
    with pytest.raises(EndpointSnapshotValidationError, match="invalid"):
        _capability(
            metadata_available=False,
            mandatory=None,
            default_enabled=None,
            supports_max_tokens=None,
            supported_efforts=("high",),
        )
    with pytest.raises(EndpointSnapshotValidationError, match="invalid"):
        _capability(supported_efforts=("high", "high"))

    evidence = _capability()
    payload = evidence.model_dump(mode="python")
    payload["supported_reasoning_efforts"] = ("none", "high")
    with pytest.raises(ValidationError, match="capability hash"):
        OpenRouterReasoningCapabilityEvidence.model_validate(payload)
