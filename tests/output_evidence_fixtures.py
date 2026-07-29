"""Synthetic hash-only structured-output evidence for defensive unit tests."""

from __future__ import annotations

from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.schemas import (
    StructuredOutputResponseFormat,
    seal_structured_output_evidence,
    structured_output_request_shape_sha256,
)

SYNTHETIC_OUTPUT_CAPABILITY_SHA256 = "7" * 64


def synthetic_structured_output_routing(
    *,
    configured_provider_endpoints: tuple[str, ...],
    selected_provider_endpoint: str,
    endpoint_snapshot_sha256: str,
    output_capability_sha256: str = SYNTHETIC_OUTPUT_CAPABILITY_SHA256,
    prompt_sha256: str,
    request_body_sha256: str,
    provider_policy_sha256: str,
    schema_sha256: str,
    original_response_sha256: str,
    validated_response_sha256: str,
    mode: StructuredOutputMode = StructuredOutputMode.JSON_OBJECT,
    reasoning_requested: bool = False,
    request_shape_sha256: str | None = None,
    strict_protocol_sha256: str | None = None,
) -> dict[str, object]:
    """Return canonical synthetic evidence without raw model content."""

    if mode is StructuredOutputMode.NATIVE_JSON_SCHEMA:
        parameters = ("response_format", "structured_outputs")
        response_format = StructuredOutputResponseFormat.JSON_SCHEMA
        provider_require_parameters = True
        effective_protocol_sha256 = None
    elif mode is StructuredOutputMode.JSON_OBJECT:
        parameters = ("response_format",)
        response_format = StructuredOutputResponseFormat.JSON_OBJECT
        effective_protocol_sha256 = strict_protocol_sha256 or ("8" * 64)
    else:
        parameters = ()
        response_format = StructuredOutputResponseFormat.OMITTED
        effective_protocol_sha256 = strict_protocol_sha256 or ("8" * 64)
    required_provider_parameters = tuple(
        sorted(
            {
                *(
                    ("response_format",)
                    if response_format is not StructuredOutputResponseFormat.OMITTED
                    else ()
                ),
                *(("reasoning",) if reasoning_requested else ()),
            }
        )
    )
    provider_require_parameters = bool(required_provider_parameters)
    reasoning_request_sha256 = "a" * 64 if reasoning_requested else None
    expected_request_shape_sha256 = structured_output_request_shape_sha256(
        mode=mode,
        schema_sha256=schema_sha256,
        required_provider_parameters=required_provider_parameters,
        reasoning_request_sha256=reasoning_request_sha256,
        strict_protocol_sha256=effective_protocol_sha256,
    )
    return seal_structured_output_evidence(
        requested_mode=mode,
        achieved_mode=mode,
        configured_provider_endpoints=configured_provider_endpoints,
        selected_provider_endpoint=selected_provider_endpoint,
        endpoint_snapshot_sha256=endpoint_snapshot_sha256,
        output_capability_sha256=output_capability_sha256,
        endpoint_structured_output_parameters=parameters,
        prompt_sha256=prompt_sha256,
        request_body_sha256=request_body_sha256,
        provider_policy_sha256=provider_policy_sha256,
        schema_sha256=schema_sha256,
        original_response_sha256=original_response_sha256,
        decoded_response_sha256=original_response_sha256,
        validated_response_sha256=validated_response_sha256,
        response_format=response_format,
        required_provider_parameters=required_provider_parameters,
        provider_require_parameters=provider_require_parameters,
        reasoning_request_sha256=reasoning_request_sha256,
        request_shape_sha256=(request_shape_sha256 or expected_request_shape_sha256),
        strict_protocol_sha256=effective_protocol_sha256,
        repair_evidence=None,
    ).model_dump(mode="json")
