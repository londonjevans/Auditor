"""Deterministic structured-output capability negotiation.

OpenRouter publishes model and endpoint parameter inventories separately.  These
helpers deliberately treat those inventories as capability evidence, not as a
promise that arbitrary structured output will validate.  Local schema validation
and benchmark qualification remain separate requirements.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

STRUCTURED_OUTPUT_CAPABILITY_PARAMETERS = frozenset(
    {
        "json_schema",
        "response_format",
        "structured_outputs",
    }
)
STRUCTURED_OUTPUT_PROTOCOL_VERSION = "mmaudit-structured-output-v1"
REASONING_CAPABILITY_PARAMETERS = frozenset(
    {
        "include_reasoning",
        "reasoning",
        "reasoning_effort",
    }
)
REASONING_REQUEST_PARAMETER = "reasoning"


class StructuredOutputMode(StrEnum):
    """One exact request/validation protocol for model output."""

    NATIVE_JSON_SCHEMA = "NATIVE_JSON_SCHEMA"
    JSON_OBJECT = "JSON_OBJECT"
    VALIDATED_TEXT_JSON = "VALIDATED_TEXT_JSON"


STRUCTURED_OUTPUT_MODE_PREFERENCE = (
    StructuredOutputMode.NATIVE_JSON_SCHEMA,
    StructuredOutputMode.JSON_OBJECT,
    StructuredOutputMode.VALIDATED_TEXT_JSON,
)


def structured_output_parameters(parameters: Iterable[str]) -> tuple[str, ...]:
    """Return the canonical allowlisted structured-output capability parameters."""

    return tuple(sorted(STRUCTURED_OUTPUT_CAPABILITY_PARAMETERS.intersection(parameters)))


def reasoning_capability_parameters(parameters: Iterable[str]) -> tuple[str, ...]:
    """Return recognized reasoning metadata without conflating request shapes."""

    return tuple(sorted(REASONING_CAPABILITY_PARAMETERS.intersection(parameters)))


def supports_reasoning_request(parameters: Iterable[str]) -> bool:
    """Return whether the exact emitted top-level ``reasoning`` object is supported."""

    return REASONING_REQUEST_PARAMETER in parameters


def supports_provider_structured_output(parameters: Iterable[str]) -> bool:
    """Return whether metadata supports a provider-encoded JSON output mode."""

    return supported_output_modes(parameters)[0] is not StructuredOutputMode.VALIDATED_TEXT_JSON


def supported_output_modes(parameters: Iterable[str]) -> tuple[StructuredOutputMode, ...]:
    """Derive every supported protocol from one exact parameter inventory.

    Native JSON Schema needs both the emitted ``response_format`` request
    parameter and explicit JSON-Schema/structured-output capability evidence.
    JSON-object mode needs only ``response_format``.  Plain text is always
    available but receives structured-review credit only after strict local JSON
    and response-schema validation.
    """

    normalized = frozenset(parameters)
    supported: set[StructuredOutputMode] = {StructuredOutputMode.VALIDATED_TEXT_JSON}
    if "response_format" in normalized:
        supported.add(StructuredOutputMode.JSON_OBJECT)
        if {"json_schema", "structured_outputs"}.intersection(normalized):
            supported.add(StructuredOutputMode.NATIVE_JSON_SCHEMA)
    return tuple(mode for mode in STRUCTURED_OUTPUT_MODE_PREFERENCE if mode in supported)


def mutually_supported_output_modes(
    parameter_sets: Iterable[Iterable[str]],
) -> tuple[StructuredOutputMode, ...]:
    """Return canonical modes supported by every supplied exact route surface."""

    inventories = tuple(parameter_sets)
    if not inventories:
        raise ValueError("output-mode negotiation requires at least one capability inventory")
    common = set(STRUCTURED_OUTPUT_MODE_PREFERENCE)
    for parameters in inventories:
        common.intersection_update(supported_output_modes(parameters))
    return tuple(mode for mode in STRUCTURED_OUTPUT_MODE_PREFERENCE if mode in common)


def negotiate_output_mode(parameter_sets: Iterable[Iterable[str]]) -> StructuredOutputMode:
    """Select the strongest mode supported by every supplied exact route surface."""

    modes = mutually_supported_output_modes(parameter_sets)
    if not modes:
        # VALIDATED_TEXT_JSON is always present, so reaching this branch means a
        # future mode implementation violated the negotiation invariant.
        raise ValueError("exact route has no mutually supported output mode")
    return modes[0]


def mode_for_supported_parameters(parameters: Iterable[str]) -> StructuredOutputMode:
    """Select the strongest mode supported by one exact capability inventory."""

    return supported_output_modes(parameters)[0]


def output_mode_request_parameters(mode: StructuredOutputMode) -> tuple[str, ...]:
    """Return special top-level request parameters emitted for one mode."""

    if mode in {
        StructuredOutputMode.NATIVE_JSON_SCHEMA,
        StructuredOutputMode.JSON_OBJECT,
    }:
        return ("response_format",)
    return ()


def output_mode_capability_parameters(
    mode: StructuredOutputMode,
    available_parameters: Iterable[str],
) -> tuple[str, ...]:
    """Return the minimal canonical capability tuple proving ``mode``.

    The tuple is suitable for request evidence: it omits unrelated endpoint
    parameters and chooses one deterministic native-schema marker when metadata
    advertises both spellings.
    """

    available = frozenset(available_parameters)
    if mode not in supported_output_modes(available):
        raise ValueError("selected output mode is not supported by the capability inventory")
    if mode is StructuredOutputMode.NATIVE_JSON_SCHEMA:
        native_marker = "json_schema" if "json_schema" in available else "structured_outputs"
        return tuple(sorted(("response_format", native_marker)))
    if mode is StructuredOutputMode.JSON_OBJECT:
        return ("response_format",)
    return ()


def mode_requires_response_format(mode: StructuredOutputMode) -> bool:
    """Return whether selecting ``mode`` emits ``response_format``."""

    return bool(output_mode_request_parameters(mode))
