from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from mmaudit.models.endpoint_inventory import (
    EndpointInventoryValidationError,
    OpenRouterEndpointInventoryDiagnostic,
    build_openrouter_endpoint_inventory_diagnostic,
)
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.reporting.json_report import stable_json

MODEL_ID = "alpha/atlas-secure"
OBSERVED_AT = datetime(2026, 8, 30, 18, 0, tzinfo=UTC)


def _endpoint(
    *,
    tag: str,
    slug: str | None = None,
    provider_name: str = "Provider Alpha",
    status: int | str = 0,
    parameters: list[str] | None = None,
    efforts: list[str] | None = None,
    include_reasoning: bool = True,
    include_model_id: bool = False,
) -> dict[str, Any]:
    endpoint: dict[str, Any] = {
        "tag": tag,
        "provider_name": provider_name,
        "status": status,
        "supported_parameters": sorted(
            parameters
            or [
                "max_tokens",
                "reasoning",
                "response_format",
                "structured_outputs",
                "temperature",
            ]
        ),
    }
    if slug is not None:
        endpoint["slug"] = slug
    if include_reasoning:
        endpoint["reasoning"] = {
            "supported_efforts": list(["medium", "high"] if efforts is None else efforts),
        }
    if include_model_id:
        endpoint["model_id"] = MODEL_ID
    return endpoint


def _zdr(*endpoints: dict[str, Any]) -> dict[str, Any]:
    return {
        "data": [
            {**endpoint, "model_id": endpoint.get("model_id", MODEL_ID)} for endpoint in endpoints
        ]
    }


def _model(
    *,
    model_id: str = MODEL_ID,
    parameters: list[str] | None = None,
    efforts: list[str] | None = None,
    include_reasoning: bool = True,
) -> dict[str, Any]:
    model: dict[str, Any] = {
        "id": model_id,
        "supported_parameters": sorted(
            parameters
            if parameters is not None
            else [
                "max_tokens",
                "reasoning",
                "response_format",
                "structured_outputs",
                "temperature",
            ]
        ),
    }
    if include_reasoning:
        model["reasoning"] = {
            "supported_efforts": list(["medium", "high"] if efforts is None else efforts),
        }
    return model


def _catalog(*models: dict[str, Any]) -> dict[str, Any]:
    return {"data": list(models or (_model(),))}


def _sha256(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _reseal_payload(payload: dict[str, Any]) -> None:
    for endpoint in payload["endpoints"]:
        endpoint["endpoint_sha256"] = _sha256(
            {key: value for key, value in endpoint.items() if key != "endpoint_sha256"}
        )
    payload["diagnostic_sha256"] = _sha256(
        {key: value for key, value in payload.items() if key != "diagnostic_sha256"}
    )


def test_endpoint_inventory_projects_current_route_facts_and_selection_arguments() -> None:
    first = _endpoint(tag="provider-alpha/fp8", slug="provider-alpha")
    second = _endpoint(
        tag="provider-alpha/regional",
        provider_name="Provider Alpha",
        status=-2,
        parameters=["json_schema", "max_tokens", "reasoning", "response_format"],
        include_reasoning=False,
    )

    diagnostic = build_openrouter_endpoint_inventory_diagnostic(
        exact_model_id=MODEL_ID,
        retrieved_at=OBSERVED_AT,
        catalog_payload=_catalog(),
        endpoint_records=[second, first],
        zdr_payload=_zdr(first),
    )

    assert diagnostic.endpoint_count == 2
    assert tuple(endpoint.endpoint_tag for endpoint in diagnostic.endpoints) == (
        "provider-alpha/fp8",
        "provider-alpha/regional",
    )
    selected, unavailable = diagnostic.endpoints
    assert selected.selection_arguments == (
        f"{MODEL_ID}=provider-alpha",
        f"{MODEL_ID}=provider-alpha/fp8",
    )
    assert selected.route_addressable is True
    assert selected.zdr_eligible is True
    assert selected.operational is True
    assert selected.operational_status == 0
    assert selected.routing_identity_unambiguous is False
    assert selected.provider_name_occurrences == 2
    assert selected.native_structured_output_supported is True
    assert selected.structured_outputs_marker_present is True
    assert selected.reasoning_effort_inventory_present is True
    assert selected.reasoning_effort_inventory_state == "PUBLISHED"
    assert selected.supported_reasoning_efforts == ("medium", "high")
    assert selected.high_reasoning_effort_supported is True
    assert selected.effective_reasoning_effort_inventory_source == "ENDPOINT"
    assert selected.effective_reasoning_effort_inventory_state == "PUBLISHED"
    assert selected.effective_supported_reasoning_efforts == ("medium", "high")
    assert selected.effective_high_reasoning_effort_supported is True

    assert unavailable.operational is False
    assert unavailable.operational_status == -2
    assert unavailable.zdr_eligible is False
    assert unavailable.supported_output_modes[0] is StructuredOutputMode.NATIVE_JSON_SCHEMA
    assert unavailable.native_structured_output_supported is True
    assert unavailable.structured_outputs_marker_present is False
    assert unavailable.reasoning_effort_inventory_present is False
    assert unavailable.reasoning_effort_inventory_state == "UNAVAILABLE"
    assert unavailable.supported_reasoning_efforts is None
    assert unavailable.high_reasoning_effort_supported is None
    assert unavailable.effective_reasoning_effort_inventory_source == "MODEL"
    assert unavailable.effective_reasoning_effort_inventory_state == "PUBLISHED"
    assert unavailable.effective_supported_reasoning_efforts == ("medium", "high")
    assert unavailable.effective_high_reasoning_effort_supported is True

    assert diagnostic.schema_version == "1.1"
    assert diagnostic.model_supported_parameters == (
        "max_tokens",
        "reasoning",
        "response_format",
        "structured_outputs",
        "temperature",
    )
    assert diagnostic.model_supported_output_modes[0] is StructuredOutputMode.NATIVE_JSON_SCHEMA
    assert diagnostic.model_native_structured_output_supported is True
    assert diagnostic.model_structured_outputs_marker_present is True
    assert diagnostic.model_reasoning_effort_inventory_state == "PUBLISHED"
    assert diagnostic.model_reasoning_effort_inventory_present is True
    assert diagnostic.model_supported_reasoning_efforts == ("medium", "high")
    assert diagnostic.model_high_reasoning_effort_supported is True
    assert diagnostic.authenticated_control_plane_metadata is True
    assert diagnostic.metadata_only is True
    assert diagnostic.completion_requested is False
    assert diagnostic.cost_ledger_opened is False
    assert diagnostic.cost_ledger_mutated is False
    assert diagnostic.secret_persisted is False
    assert diagnostic.provider_authority is False
    assert diagnostic.runner_authority is False
    assert diagnostic.qualification_authority is False
    assert diagnostic.selection_authority is False
    assert diagnostic.egress_authority is False
    assert diagnostic.completion_authority is False
    assert diagnostic.release_authority is False
    assert (
        OpenRouterEndpointInventoryDiagnostic.model_validate_json(stable_json(diagnostic))
        == diagnostic
    )


def test_endpoint_inventory_retains_empty_reasoning_inventory_without_support_claim() -> None:
    endpoint = _endpoint(tag="provider-alpha", efforts=[])

    diagnostic = build_openrouter_endpoint_inventory_diagnostic(
        exact_model_id=MODEL_ID,
        retrieved_at=OBSERVED_AT,
        catalog_payload=_catalog(),
        endpoint_records=[endpoint],
        zdr_payload={"data": []},
    )

    route = diagnostic.endpoints[0]
    assert route.reasoning_effort_inventory_present is True
    assert route.reasoning_effort_inventory_state == "EMPTY"
    assert route.supported_reasoning_efforts == ()
    assert route.high_reasoning_effort_supported is False
    assert route.zdr_eligible is False


@pytest.mark.parametrize(
    (
        "endpoint_efforts",
        "model_efforts",
        "expected_source",
        "expected_state",
        "expected_efforts",
        "expected_high",
    ),
    (
        (None, ("medium", "high"), "MODEL", "PUBLISHED", ("medium", "high"), True),
        ((), ("medium", "high"), "ENDPOINT", "EMPTY", (), False),
        (("medium",), ("medium", "high"), "ENDPOINT", "PUBLISHED", ("medium",), False),
        (("high",), ("medium",), "ENDPOINT", "CONTRADICTORY", ("high",), True),
        (None, (), "MODEL", "EMPTY", (), False),
        (None, None, "UNAVAILABLE", "UNAVAILABLE", None, None),
    ),
)
def test_endpoint_inventory_resolves_endpoint_first_reasoning_inventory(
    endpoint_efforts: tuple[str, ...] | None,
    model_efforts: tuple[str, ...] | None,
    expected_source: str,
    expected_state: str,
    expected_efforts: tuple[str, ...] | None,
    expected_high: bool | None,
) -> None:
    endpoint = _endpoint(
        tag="provider-alpha",
        efforts=None if endpoint_efforts is None else list(endpoint_efforts),
        include_reasoning=endpoint_efforts is not None,
    )
    model = _model(
        efforts=None if model_efforts is None else list(model_efforts),
        include_reasoning=model_efforts is not None,
    )

    diagnostic = build_openrouter_endpoint_inventory_diagnostic(
        exact_model_id=MODEL_ID,
        retrieved_at=OBSERVED_AT,
        catalog_payload=_catalog(model),
        endpoint_records=[endpoint],
        zdr_payload={"data": []},
    )

    route = diagnostic.endpoints[0]
    assert route.effective_reasoning_effort_inventory_source == expected_source
    assert route.effective_reasoning_effort_inventory_state == expected_state
    assert route.effective_supported_reasoning_efforts == expected_efforts
    assert route.effective_high_reasoning_effort_supported is expected_high


def test_endpoint_inventory_rejects_invalid_or_ambiguous_catalog_model_projection() -> None:
    endpoint = _endpoint(tag="provider-alpha")
    invalid_catalogues = (
        _catalog(_model(model_id="beta/beacon-secure")),
        _catalog(_model(), _model()),
        _catalog(_model(model_id="not/a model?"), _model()),
    )

    for catalog_payload in invalid_catalogues:
        with pytest.raises(EndpointInventoryValidationError):
            build_openrouter_endpoint_inventory_diagnostic(
                exact_model_id=MODEL_ID,
                retrieved_at=OBSERVED_AT,
                catalog_payload=catalog_payload,
                endpoint_records=[endpoint],
                zdr_payload={"data": []},
            )


def test_endpoint_inventory_rejects_model_reasoning_without_parameter_support() -> None:
    model = _model(
        parameters=["max_tokens", "response_format", "structured_outputs", "temperature"],
        efforts=["high"],
    )

    with pytest.raises(EndpointInventoryValidationError, match="model catalog record"):
        build_openrouter_endpoint_inventory_diagnostic(
            exact_model_id=MODEL_ID,
            retrieved_at=OBSERVED_AT,
            catalog_payload=_catalog(model),
            endpoint_records=[_endpoint(tag="provider-alpha")],
            zdr_payload={"data": []},
        )


def test_endpoint_inventory_preserves_raw_status_type_for_admission_parity() -> None:
    diagnostic = build_openrouter_endpoint_inventory_diagnostic(
        exact_model_id=MODEL_ID,
        retrieved_at=OBSERVED_AT,
        catalog_payload=_catalog(),
        endpoint_records=[
            _endpoint(tag="numeric-int", status=0),
            _endpoint(tag="numeric-text", status="0", provider_name="Provider Beta"),
        ],
        zdr_payload={"data": []},
    )

    integer_status, textual_status = diagnostic.endpoints
    assert integer_status.operational is True
    assert integer_status.operational_status == 0
    assert type(integer_status.operational_status) is int
    assert textual_status.operational is False
    assert textual_status.operational_status == "0"
    assert type(textual_status.operational_status) is str


def test_endpoint_inventory_deduplicates_equal_tag_and_slug_selector() -> None:
    endpoint = _endpoint(tag="provider-alpha", slug="provider-alpha")

    diagnostic = build_openrouter_endpoint_inventory_diagnostic(
        exact_model_id=MODEL_ID,
        retrieved_at=OBSERVED_AT,
        catalog_payload=_catalog(),
        endpoint_records=[endpoint],
        zdr_payload={"data": []},
    )

    assert diagnostic.endpoints[0].selection_arguments == (f"{MODEL_ID}=provider-alpha",)


def test_endpoint_inventory_omits_ambiguous_aliases_from_successor_arguments() -> None:
    first = _endpoint(tag="shared", slug="alpha")
    second = _endpoint(tag="shared", slug="beta", provider_name="Provider Beta")

    diagnostic = build_openrouter_endpoint_inventory_diagnostic(
        exact_model_id=MODEL_ID,
        retrieved_at=OBSERVED_AT,
        catalog_payload=_catalog(),
        endpoint_records=[first, second],
        zdr_payload={"data": []},
    )

    assert diagnostic.endpoints[0].selection_arguments == (f"{MODEL_ID}=alpha",)
    assert diagnostic.endpoints[1].selection_arguments == (f"{MODEL_ID}=beta",)
    assert all(
        "=shared" not in item
        for route in diagnostic.endpoints
        for item in route.selection_arguments
    )


def test_endpoint_inventory_provider_name_injectivity_is_case_insensitive() -> None:
    diagnostic = build_openrouter_endpoint_inventory_diagnostic(
        exact_model_id=MODEL_ID,
        retrieved_at=OBSERVED_AT,
        catalog_payload=_catalog(),
        endpoint_records=[
            _endpoint(tag="provider-alpha", provider_name="Provider Alpha"),
            _endpoint(tag="provider-beta", provider_name="provider alpha"),
        ],
        zdr_payload={"data": []},
    )

    assert all(endpoint.provider_name_occurrences == 2 for endpoint in diagnostic.endpoints)
    assert all(not endpoint.routing_identity_unambiguous for endpoint in diagnostic.endpoints)
    assert tuple(endpoint.selection_arguments for endpoint in diagnostic.endpoints) == (
        (f"{MODEL_ID}=provider-alpha",),
        (f"{MODEL_ID}=provider-beta",),
    )


def test_endpoint_inventory_replay_rejects_resealed_ambiguous_selection_arguments() -> None:
    diagnostic = build_openrouter_endpoint_inventory_diagnostic(
        exact_model_id=MODEL_ID,
        retrieved_at=OBSERVED_AT,
        catalog_payload=_catalog(),
        endpoint_records=[
            _endpoint(tag="shared", slug="alpha"),
            _endpoint(tag="shared", slug="beta", provider_name="Provider Beta"),
        ],
        zdr_payload={"data": []},
    )
    payload = diagnostic.model_dump(mode="json")
    for endpoint in payload["endpoints"]:
        endpoint["selection_arguments"] = [f"{MODEL_ID}=shared"]
        endpoint["route_addressable"] = True
    _reseal_payload(payload)

    with pytest.raises(ValueError, match="global selection arguments"):
        OpenRouterEndpointInventoryDiagnostic.model_validate_json(json.dumps(payload))


def test_endpoint_inventory_replay_rejects_resealed_operational_contradiction() -> None:
    diagnostic = build_openrouter_endpoint_inventory_diagnostic(
        exact_model_id=MODEL_ID,
        retrieved_at=OBSERVED_AT,
        catalog_payload=_catalog(),
        endpoint_records=[_endpoint(tag="provider-alpha", status=-2)],
        zdr_payload={"data": []},
    )
    payload = diagnostic.model_dump(mode="json")
    payload["endpoints"][0]["operational"] = True
    _reseal_payload(payload)

    with pytest.raises(ValueError, match="operational status"):
        OpenRouterEndpointInventoryDiagnostic.model_validate_json(json.dumps(payload))


def test_endpoint_inventory_replay_rejects_resealed_empty_reasoning_tristate() -> None:
    diagnostic = build_openrouter_endpoint_inventory_diagnostic(
        exact_model_id=MODEL_ID,
        retrieved_at=OBSERVED_AT,
        catalog_payload=_catalog(),
        endpoint_records=[_endpoint(tag="provider-alpha", efforts=[])],
        zdr_payload={"data": []},
    )
    payload = diagnostic.model_dump(mode="json")
    payload["endpoints"][0]["high_reasoning_effort_supported"] = None
    _reseal_payload(payload)

    with pytest.raises(ValueError, match="empty reasoning inventory"):
        OpenRouterEndpointInventoryDiagnostic.model_validate_json(json.dumps(payload))


def test_endpoint_inventory_replay_rejects_resealed_model_projection_tamper() -> None:
    diagnostic = build_openrouter_endpoint_inventory_diagnostic(
        exact_model_id=MODEL_ID,
        retrieved_at=OBSERVED_AT,
        catalog_payload=_catalog(),
        endpoint_records=[_endpoint(tag="provider-alpha", include_reasoning=False)],
        zdr_payload={"data": []},
    )
    payload = diagnostic.model_dump(mode="json")
    payload["model_reasoning_effort_inventory_state"] = "UNAVAILABLE"
    payload["model_reasoning_effort_inventory_present"] = False
    payload["model_supported_reasoning_efforts"] = None
    payload["model_high_reasoning_effort_supported"] = None
    _reseal_payload(payload)

    with pytest.raises(ValueError, match="effective reasoning inventory differs"):
        OpenRouterEndpointInventoryDiagnostic.model_validate_json(json.dumps(payload))


def test_endpoint_inventory_replay_rejects_resealed_effective_projection_tamper() -> None:
    diagnostic = build_openrouter_endpoint_inventory_diagnostic(
        exact_model_id=MODEL_ID,
        retrieved_at=OBSERVED_AT,
        catalog_payload=_catalog(),
        endpoint_records=[_endpoint(tag="provider-alpha", include_reasoning=False)],
        zdr_payload={"data": []},
    )
    payload = diagnostic.model_dump(mode="json")
    route = payload["endpoints"][0]
    route["effective_reasoning_effort_inventory_source"] = "UNAVAILABLE"
    route["effective_reasoning_effort_inventory_state"] = "UNAVAILABLE"
    route["effective_supported_reasoning_efforts"] = None
    route["effective_high_reasoning_effort_supported"] = None
    _reseal_payload(payload)

    with pytest.raises(ValueError, match="effective reasoning inventory differs"):
        OpenRouterEndpointInventoryDiagnostic.model_validate_json(json.dumps(payload))


def test_endpoint_inventory_replay_rejects_resealed_model_output_projection_tamper() -> None:
    diagnostic = build_openrouter_endpoint_inventory_diagnostic(
        exact_model_id=MODEL_ID,
        retrieved_at=OBSERVED_AT,
        catalog_payload=_catalog(),
        endpoint_records=[_endpoint(tag="provider-alpha")],
        zdr_payload={"data": []},
    )
    payload = diagnostic.model_dump(mode="json")
    payload["model_native_structured_output_supported"] = False
    _reseal_payload(payload)

    with pytest.raises(ValueError, match="model inventory native structured-output"):
        OpenRouterEndpointInventoryDiagnostic.model_validate_json(json.dumps(payload))


def test_endpoint_inventory_replay_rejects_resealed_model_parameter_weakening() -> None:
    diagnostic = build_openrouter_endpoint_inventory_diagnostic(
        exact_model_id=MODEL_ID,
        retrieved_at=OBSERVED_AT,
        catalog_payload=_catalog(),
        endpoint_records=[_endpoint(tag="provider-alpha")],
        zdr_payload={"data": []},
    )
    payload = diagnostic.model_dump(mode="json")
    payload["model_supported_parameters"].remove("max_tokens")
    _reseal_payload(payload)

    with pytest.raises(ValueError, match="model inventory parameters are invalid"):
        OpenRouterEndpointInventoryDiagnostic.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    "endpoint_records",
    (
        [_endpoint(tag="provider-alpha", status=True)],
        [_endpoint(tag="provider-alpha", status=2**31)],
        [
            _endpoint(
                tag="provider-alpha",
                parameters=["max_tokens", "max_tokens"],
            )
        ],
        [_endpoint(tag="provider-alpha", efforts=["high", "high"])],
        [_endpoint(tag="provider-alpha", parameters=["max_tokens"], efforts=["high"])],
        [_endpoint(tag="provider-alpha", parameters=["max_tokens"], efforts=[])],
        [{**_endpoint(tag="provider-alpha"), "model_id": "beta/beacon-secure"}],
        [_endpoint(tag="provider-alpha"), _endpoint(tag="provider-alpha")],
    ),
)
def test_endpoint_inventory_rejects_malformed_or_ambiguous_endpoint_metadata(
    endpoint_records: list[dict[str, Any]],
) -> None:
    with pytest.raises(EndpointInventoryValidationError):
        build_openrouter_endpoint_inventory_diagnostic(
            exact_model_id=MODEL_ID,
            retrieved_at=OBSERVED_AT,
            catalog_payload=_catalog(),
            endpoint_records=endpoint_records,
            zdr_payload={"data": []},
        )


def test_endpoint_inventory_joins_zdr_by_complete_bijective_identity() -> None:
    first = _endpoint(tag="shared", slug="provider-alpha/fp8")
    second = _endpoint(
        tag="shared",
        slug="provider-beta/fp8",
        provider_name="Provider Beta",
    )

    diagnostic = build_openrouter_endpoint_inventory_diagnostic(
        exact_model_id=MODEL_ID,
        retrieved_at=OBSERVED_AT,
        catalog_payload=_catalog(),
        endpoint_records=[second, first],
        zdr_payload=_zdr(first),
    )

    assert diagnostic.endpoints[0].zdr_eligible is True
    assert diagnostic.endpoints[1].zdr_eligible is False
    assert diagnostic.endpoints[0].selection_arguments == (f"{MODEL_ID}=provider-alpha/fp8",)
    assert diagnostic.endpoints[1].selection_arguments == (f"{MODEL_ID}=provider-beta/fp8",)


def test_endpoint_inventory_rejects_inconsistent_exact_zdr_facts() -> None:
    endpoint = _endpoint(tag="provider-alpha", slug="provider-alpha/fp8")
    exact = {**endpoint, "model_id": MODEL_ID}

    inconsistent = {
        **exact,
        "provider_name": "Different Provider",
    }
    with pytest.raises(EndpointInventoryValidationError, match="inconsistent"):
        build_openrouter_endpoint_inventory_diagnostic(
            exact_model_id=MODEL_ID,
            retrieved_at=OBSERVED_AT,
            catalog_payload=_catalog(),
            endpoint_records=[endpoint],
            zdr_payload={"data": [inconsistent]},
        )


def test_endpoint_inventory_rejects_zdr_records_without_exact_model_binding() -> None:
    endpoint = _endpoint(tag="provider-alpha")

    for invalid_model_id in (None, "", "not/a model?"):
        raw_zdr = dict(endpoint)
        if invalid_model_id is not None:
            raw_zdr["model_id"] = invalid_model_id
        with pytest.raises(EndpointInventoryValidationError, match="exact model binding"):
            build_openrouter_endpoint_inventory_diagnostic(
                exact_model_id=MODEL_ID,
                retrieved_at=OBSERVED_AT,
                catalog_payload=_catalog(),
                endpoint_records=[endpoint],
                zdr_payload={"data": [raw_zdr]},
            )


def test_endpoint_inventory_rejects_invalid_identity_time_envelope_and_hash_tamper() -> None:
    endpoint = _endpoint(tag="provider-alpha")
    with pytest.raises(ValueError, match="exact non-routed"):
        build_openrouter_endpoint_inventory_diagnostic(
            exact_model_id="alpha/atlas-secure:latest",
            retrieved_at=OBSERVED_AT,
            catalog_payload=_catalog(),
            endpoint_records=[endpoint],
            zdr_payload={"data": []},
        )
    with pytest.raises(EndpointInventoryValidationError, match="whole-second UTC"):
        build_openrouter_endpoint_inventory_diagnostic(
            exact_model_id=MODEL_ID,
            retrieved_at=OBSERVED_AT.replace(microsecond=1),
            catalog_payload=_catalog(),
            endpoint_records=[endpoint],
            zdr_payload={"data": []},
        )
    with pytest.raises(EndpointInventoryValidationError, match="nonempty bounded"):
        build_openrouter_endpoint_inventory_diagnostic(
            exact_model_id=MODEL_ID,
            retrieved_at=OBSERVED_AT,
            catalog_payload=_catalog(),
            endpoint_records=[],
            zdr_payload={"data": []},
        )

    diagnostic = build_openrouter_endpoint_inventory_diagnostic(
        exact_model_id=MODEL_ID,
        retrieved_at=OBSERVED_AT,
        catalog_payload=_catalog(),
        endpoint_records=[endpoint],
        zdr_payload={"data": []},
    )
    offset_payload = diagnostic.model_dump(mode="json")
    offset_payload["retrieved_at"] = datetime(
        2026,
        8,
        30,
        19,
        0,
        tzinfo=timezone(timedelta(hours=1)),
    ).isoformat()
    with pytest.raises(ValueError, match="whole-second UTC"):
        OpenRouterEndpointInventoryDiagnostic.model_validate_json(json.dumps(offset_payload))

    payload = diagnostic.model_dump(mode="python")
    payload["endpoints"][0]["zdr_eligible"] = True
    with pytest.raises(ValueError, match="self-hash"):
        OpenRouterEndpointInventoryDiagnostic.model_validate(payload)
