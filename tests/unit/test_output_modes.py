from __future__ import annotations

import pytest

from mmaudit.models.output_modes import (
    StructuredOutputMode,
    mode_for_supported_parameters,
    mutually_supported_output_modes,
    output_mode_capability_parameters,
    output_mode_request_parameters,
    supported_output_modes,
)


def test_native_schema_requires_response_format_and_explicit_schema_capability() -> None:
    assert supported_output_modes(("response_format", "structured_outputs")) == (
        StructuredOutputMode.NATIVE_JSON_SCHEMA,
        StructuredOutputMode.JSON_OBJECT,
        StructuredOutputMode.VALIDATED_TEXT_JSON,
    )
    assert mode_for_supported_parameters(("structured_outputs",)) is (
        StructuredOutputMode.VALIDATED_TEXT_JSON
    )


def test_common_route_mode_is_deterministic_across_different_native_markers() -> None:
    modes = mutually_supported_output_modes(
        (
            ("response_format", "structured_outputs"),
            ("json_schema", "response_format"),
        )
    )

    assert modes == (
        StructuredOutputMode.NATIVE_JSON_SCHEMA,
        StructuredOutputMode.JSON_OBJECT,
        StructuredOutputMode.VALIDATED_TEXT_JSON,
    )


def test_validated_text_mode_emits_no_provider_specific_output_parameter() -> None:
    assert output_mode_request_parameters(StructuredOutputMode.NATIVE_JSON_SCHEMA) == (
        "response_format",
    )
    assert output_mode_request_parameters(StructuredOutputMode.JSON_OBJECT) == ("response_format",)
    assert output_mode_request_parameters(StructuredOutputMode.VALIDATED_TEXT_JSON) == ()


def test_capability_evidence_uses_a_minimal_deterministic_mode_tuple() -> None:
    available = ("json_schema", "response_format", "structured_outputs")

    assert output_mode_capability_parameters(
        StructuredOutputMode.NATIVE_JSON_SCHEMA,
        available,
    ) == ("json_schema", "response_format")
    assert output_mode_capability_parameters(
        StructuredOutputMode.NATIVE_JSON_SCHEMA,
        ("response_format", "structured_outputs"),
    ) == ("response_format", "structured_outputs")
    assert output_mode_capability_parameters(
        StructuredOutputMode.JSON_OBJECT,
        available,
    ) == ("response_format",)
    assert (
        output_mode_capability_parameters(
            StructuredOutputMode.VALIDATED_TEXT_JSON,
            available,
        )
        == ()
    )


def test_capability_evidence_rejects_an_unsupported_selected_mode() -> None:
    with pytest.raises(ValueError, match="not supported"):
        output_mode_capability_parameters(
            StructuredOutputMode.NATIVE_JSON_SCHEMA,
            ("response_format",),
        )


def test_empty_capability_inventory_set_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one"):
        mutually_supported_output_modes(())
