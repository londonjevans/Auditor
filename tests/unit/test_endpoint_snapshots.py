from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Literal, cast

import pytest
from pydantic import ValidationError

from mmaudit.models.endpoint_snapshots import (
    EndpointSnapshotValidationError,
    OpenRouterConstrainedRouteContext,
    OpenRouterEndpointEvidence,
    OpenRouterEndpointSnapshotEvidence,
    OpenRouterPricingOverrideTier,
    openrouter_pricing_schedule_sha256,
    output_capability_binding_sha256,
    validate_openrouter_endpoint_snapshot,
)
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.price_lexemes import (
    MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
    ZDR_ENDPOINT_PRICE_LEXEME_LAYOUT,
    OpenRouterPriceLexemeLayout,
    captured_openrouter_json_number_raw,
    decode_openrouter_price_metadata_json,
)
from mmaudit.models.reasoning import (
    CANONICAL_REASONING_POLICY_ROLES,
    ReasoningControlProfile,
    ReasoningEffort,
    ReasoningPolicyArtifact,
)
from mmaudit.models.route_constraints import (
    ExactRouteConstraint,
    ExactRoutePricingSchedule,
    ExactRouteRole,
    ProviderPriceCapAlgorithm,
    RoutePredicateDisposition,
    RoutePredicateId,
    RoutePredicateProfile,
    RoutePredicateReason,
)
from mmaudit.orchestration.budgets import EndpointRequestCostBound

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "model_responses"


def _endpoint(
    endpoint_id: str = "approved-provider",
    *,
    use_slug: bool = False,
    provider_name: str = "Approved Provider",
) -> dict[str, Any]:
    identity = {"slug": endpoint_id} if use_slug else {"tag": endpoint_id}
    return {
        **identity,
        "name": "Provider-controlled display name",
        "provider_name": provider_name,
        "status": 0,
        "context_length": 200_000,
        "max_prompt_tokens": 180_000,
        "max_completion_tokens": 20_000,
        "supported_parameters": [
            "response_format",
            "reasoning",
            "max_tokens",
            "temperature",
        ],
        "pricing": {
            "request": "0",
            "prompt": "0.0000030",
            "completion": "0.000015",
            "image": "0",
        },
    }


def _endpoint_payload(*endpoints: dict[str, Any], model: str = "alpha/atlas-secure") -> Any:
    return {
        "data": {
            "id": model,
            "endpoints": list(endpoints or (_endpoint(),)),
        }
    }


def _zdr_payload(*endpoints: dict[str, Any], model: str = "alpha/atlas-secure") -> Any:
    selected = list(endpoints or (_endpoint(),))
    return {
        "data": [
            {
                **copy.deepcopy(endpoint),
                "model_id": model,
            }
            for endpoint in selected
        ]
    }


def _decoded_numeric_price_payload(
    *endpoint_ids: str,
    layout: OpenRouterPriceLexemeLayout,
) -> dict[str, Any]:
    endpoints = [
        _endpoint(endpoint_id, provider_name=f"Provider {index}")
        for index, endpoint_id in enumerate(endpoint_ids)
    ]
    sentinels: list[tuple[str, str]] = []
    for index, endpoint in enumerate(endpoints):
        sentinel = f"__numeric_prompt_{index}__"
        raw_price = f"0.00000{index + 3}"
        endpoint["pricing"]["prompt"] = sentinel
        sentinels.append((sentinel, raw_price))
    envelope = (
        _endpoint_payload(*endpoints)
        if layout == MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT
        else _zdr_payload(*endpoints)
    )
    encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    for sentinel, raw_price in sentinels:
        encoded = encoded.replace(json.dumps(sentinel), raw_price)
    return cast(
        dict[str, Any],
        decode_openrouter_price_metadata_json(encoded.encode(), layout=layout),
    )


def _validate(
    *,
    endpoint_payload: Any | None = None,
    zdr_payload: Any | None = None,
    configured: tuple[str, ...] = ("approved-provider",),
    require_zdr: bool = True,
) -> OpenRouterEndpointSnapshotEvidence:
    endpoint_payload = endpoint_payload or _endpoint_payload()
    zdr_payload = _zdr_payload() if zdr_payload is None and require_zdr else zdr_payload
    return validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=configured,
        provider_policy_mode="only",
        endpoint_payload=endpoint_payload,
        require_zdr=require_zdr,
        zdr_payload=zdr_payload,
    )


def _reasoning_policy(
    *,
    mode: Literal["effort", "disabled"] = "effort",
) -> ReasoningPolicyArtifact:
    control = (
        ReasoningControlProfile.build(
            mode="effort",
            effort="high",
            reserved_reasoning_tokens=4_096,
        )
        if mode == "effort"
        else ReasoningControlProfile.build(mode="disabled", reserved_reasoning_tokens=0)
    )
    return ReasoningPolicyArtifact.build(
        controls_by_role={role: control for role in CANONICAL_REASONING_POLICY_ROLES}
    )


def _constrained_endpoint(
    endpoint_id: str = "approved-provider",
    *,
    use_slug: bool = False,
    provider_name: str = "Approved Provider",
    supported_efforts: tuple[ReasoningEffort, ...] | None = ("high",),
) -> dict[str, Any]:
    endpoint = _endpoint(
        endpoint_id,
        use_slug=use_slug,
        provider_name=provider_name,
    )
    endpoint["supported_parameters"].append("structured_outputs")
    if supported_efforts is not None:
        endpoint["reasoning"] = {"supported_efforts": list(supported_efforts)}
    return endpoint


def _route_bundle(
    *,
    endpoint_id: str = "approved-provider",
    model_efforts: tuple[ReasoningEffort, ...] | None = ("high",),
    observed_policy: ReasoningPolicyArtifact | None = None,
    automatic_fallbacks_allowed: bool = False,
    price_cap_algorithm: ProviderPriceCapAlgorithm = (
        ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1
    ),
) -> tuple[RoutePredicateProfile, ExactRouteConstraint, OpenRouterConstrainedRouteContext]:
    profile_policy = _reasoning_policy()
    role_policy = profile_policy.role_policy_for_request("model_benchmark")
    profile = RoutePredicateProfile.build(
        reasoning_policy_sha256=profile_policy.artifact_sha256,
        reasoning_role_profile_sha256=profile_policy.role_profile.profile_sha256,
        reasoning_role_binding_sha256=role_policy.binding_sha256,
        reasoning_control_profile_sha256=role_policy.control.profile_sha256,
        reserved_reasoning_tokens=4_096,
        minimum_prompt_tokens=100_000,
        required_output_tokens=4_096,
        minimum_context_tokens=120_000,
        price_cap_algorithm=price_cap_algorithm,
    )
    constraint = ExactRouteConstraint.build(
        role=ExactRouteRole.CANDIDATE,
        exact_model_id="alpha/atlas-secure",
        provider_endpoint=endpoint_id,
        profile=profile,
    )
    context = OpenRouterConstrainedRouteContext(
        route_predicate_profile=profile,
        exact_route_constraint=constraint,
        expected_selection_plan_sha256="1" * 64,
        reasoning_policy=observed_policy or profile_policy,
        reasoning_request_role="model_benchmark",
        model_supported_parameters=(
            "max_tokens",
            "reasoning",
            "response_format",
            "structured_outputs",
            "temperature",
        ),
        model_supported_reasoning_efforts=model_efforts,
        automatic_fallbacks_allowed=automatic_fallbacks_allowed,
    )
    return profile, constraint, context


def _validate_constrained(
    endpoint: dict[str, Any],
    *,
    context: OpenRouterConstrainedRouteContext,
    endpoint_id: str = "approved-provider",
    endpoint_payload: Any | None = None,
    reasoning_requested: bool | None = None,
) -> OpenRouterEndpointSnapshotEvidence:
    if reasoning_requested is None:
        reasoning_requested = (
            context.reasoning_policy.role_policy_for_request(
                context.reasoning_request_role
            ).control.mode
            != "disabled"
        )
    return validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=(endpoint_id,),
        provider_policy_mode="only",
        endpoint_payload=endpoint_payload or _endpoint_payload(endpoint),
        require_zdr=True,
        zdr_payload=_zdr_payload(endpoint),
        reasoning_requested=reasoning_requested,
        required_output_mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
        route_constraint_context=context,
    )


def test_valid_snapshot_exposes_exact_cost_proof_inputs() -> None:
    evidence = _validate()

    endpoint = evidence.endpoint("approved-provider")
    assert endpoint.exact_model_id == "alpha/atlas-secure"
    assert endpoint.endpoint_tag == "approved-provider"
    assert endpoint.endpoint_slug is None
    assert endpoint.provider_name == "Approved Provider"
    assert endpoint.operational is True
    assert endpoint.zdr_eligible is True
    assert endpoint.structured_output_parameters == ("response_format",)
    assert endpoint.supported_output_modes == (
        StructuredOutputMode.JSON_OBJECT,
        StructuredOutputMode.VALIDATED_TEXT_JSON,
    )
    assert endpoint.structured_output_mode is StructuredOutputMode.JSON_OBJECT
    assert evidence.supported_output_modes == endpoint.supported_output_modes
    assert evidence.structured_output_mode is StructuredOutputMode.JSON_OBJECT
    assert len(endpoint.output_capability_sha256) == 64
    assert len(evidence.output_capability_sha256) == 64
    assert len(output_capability_binding_sha256(evidence)) == 64
    assert endpoint.max_prompt_tokens_source == "metadata"
    assert endpoint.max_completion_tokens_source == "metadata"
    assert endpoint.pricing == {
        "completion": "0.000015",
        "image": "0",
        "prompt": "0.000003",
        "request": "0",
    }
    assert len(endpoint.pricing_sha256) == 64
    assert len(evidence.endpoint_metadata_sha256) == 64
    assert len(evidence.zdr_metadata_sha256 or "") == 64
    assert len(evidence.snapshot_sha256) == 64
    assert evidence.route_predicate_profile is None
    assert evidence.exact_route_constraint is None
    assert evidence.normalized_route_facts is None
    assert evidence.route_predicate_report is None
    assert "route_predicate_report" not in evidence.model_dump(mode="json")

    bound = EndpointRequestCostBound.from_endpoint_pricing(
        exact_model_id=endpoint.exact_model_id,
        provider_endpoint=endpoint.provider_endpoint,
        request_material="synthetic local review",
        pricing=endpoint.pricing,
        maximum_units={
            "completion": 100,
            "image": 0,
            "prompt": 1_000,
            "request": 1,
        },
    )
    assert bound.maximum_cost_usd > 0
    assert len(bound.pricing_snapshot_sha256) == 64


def test_endpoint_snapshot_is_deterministic_for_semantically_identical_metadata() -> None:
    endpoint_a = _endpoint()
    endpoint_b = copy.deepcopy(endpoint_a)
    endpoint_b["supported_parameters"] = list(reversed(endpoint_b["supported_parameters"]))
    endpoint_b["pricing"] = {
        "completion": "0.0000150",
        "discount": 0,
        "prompt": "0.000003",
        "image": "0.0",
        "request": "0.000",
    }
    endpoint_b["quantization"] = "fp8"
    endpoint_a["untrusted_unknown_field"] = "not retained"
    first = _validate(
        endpoint_payload=_endpoint_payload(endpoint_a),
        zdr_payload=_zdr_payload(endpoint_a),
    )
    second = _validate(
        endpoint_payload=_endpoint_payload(endpoint_b),
        zdr_payload=_zdr_payload(endpoint_b),
    )

    assert first == second
    assert first.snapshot_sha256 == second.snapshot_sha256
    assert OpenRouterEndpointSnapshotEvidence.model_validate_json(first.model_dump_json()) == second
    serialized = json.dumps(first.model_dump(mode="json"), sort_keys=True)
    assert "untrusted_unknown_field" not in serialized
    assert "quantization" not in serialized
    assert "discount" not in serialized
    assert '"name": "Provider-controlled display name"' not in serialized


def test_retained_operational_status_change_is_not_canonicalized_away() -> None:
    numeric_status = _endpoint()
    text_status = copy.deepcopy(numeric_status)
    text_status["status"] = "ACTIVE"

    frozen = _validate(
        endpoint_payload=_endpoint_payload(numeric_status),
        zdr_payload=_zdr_payload(numeric_status),
    )
    live = _validate(
        endpoint_payload=_endpoint_payload(text_status),
        zdr_payload=_zdr_payload(text_status),
    )

    assert frozen.endpoints[0].operational_status == "0"
    assert live.endpoints[0].operational_status == "active"
    assert live != frozen
    assert live.snapshot_sha256 != frozen.snapshot_sha256


def test_output_capability_binding_includes_the_complete_parent_snapshot() -> None:
    baseline_endpoint = _endpoint()
    repriced_endpoint = copy.deepcopy(baseline_endpoint)
    repriced_endpoint["pricing"]["completion"] = "0.000016"
    baseline = _validate(
        endpoint_payload=_endpoint_payload(baseline_endpoint),
        zdr_payload=_zdr_payload(baseline_endpoint),
    )
    repriced = _validate(
        endpoint_payload=_endpoint_payload(repriced_endpoint),
        zdr_payload=_zdr_payload(repriced_endpoint),
    )

    assert baseline.output_capability_sha256 == repriced.output_capability_sha256
    assert baseline.snapshot_sha256 != repriced.snapshot_sha256
    assert output_capability_binding_sha256(baseline) != output_capability_binding_sha256(repriced)


def test_provider_policy_order_is_preserved_and_exactly_covered() -> None:
    first = _endpoint("provider-a")
    second = _endpoint(
        "google-vertex/us-east5",
        use_slug=True,
        provider_name="Google Vertex",
    )
    evidence = validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("google-vertex/us-east5", "provider-a"),
        provider_policy_mode="order",
        endpoint_payload=_endpoint_payload(first, second),
        require_zdr=True,
        zdr_payload=_zdr_payload(second, first),
    )

    assert tuple(item.provider_endpoint for item in evidence.endpoints) == (
        "google-vertex/us-east5",
        "provider-a",
    )
    assert evidence.endpoints[0].endpoint_slug == "google-vertex/us-east5"
    assert evidence.endpoints[0].provider_name == "Google Vertex"
    assert evidence.endpoints[1].endpoint_tag == "provider-a"


def test_wrong_model_binding_and_router_aliases_are_rejected() -> None:
    with pytest.raises(EndpointSnapshotValidationError, match="exact requested model"):
        _validate(endpoint_payload=_endpoint_payload(model="bravo/borealis-secure"))

    endpoint = _endpoint()
    endpoint["model_id"] = "bravo/borealis-secure"
    with pytest.raises(EndpointSnapshotValidationError, match="endpoint record"):
        _validate(endpoint_payload=_endpoint_payload(endpoint))

    with pytest.raises(EndpointSnapshotValidationError, match="router or latest aliases"):
        validate_openrouter_endpoint_snapshot(
            exact_model_id="openrouter/auto",
            configured_provider_endpoints=("approved-provider",),
            provider_policy_mode="only",
            endpoint_payload=_endpoint_payload(model="openrouter/auto"),
            require_zdr=False,
        )


def test_display_name_does_not_satisfy_exact_tag_or_slug_policy() -> None:
    with pytest.raises(EndpointSnapshotValidationError, match="tag or slug is unavailable"):
        _validate(
            endpoint_payload=_endpoint_payload(_endpoint()),
            configured=("Provider-controlled-display-name",),
        )


def test_provider_display_name_is_required_and_bound_across_zdr_metadata() -> None:
    missing = _endpoint()
    missing.pop("provider_name")
    with pytest.raises(EndpointSnapshotValidationError, match="provider display name"):
        _validate(endpoint_payload=_endpoint_payload(missing))

    zdr_endpoint = _endpoint(provider_name="Different Provider Name")
    with pytest.raises(EndpointSnapshotValidationError, match="inconsistent"):
        _validate(zdr_payload=_zdr_payload(zdr_endpoint))


def test_ambiguous_endpoint_identity_is_rejected() -> None:
    with pytest.raises(EndpointSnapshotValidationError, match="tag or slug is ambiguous"):
        _validate(
            endpoint_payload=_endpoint_payload(_endpoint(), _endpoint()),
        )


def test_configured_provider_display_name_must_be_unique_across_exact_model_endpoints() -> None:
    configured = _endpoint(
        "google-vertex/us-east5",
        use_slug=True,
        provider_name="Google Vertex",
    )
    unconfigured = _endpoint(
        "google-vertex/us-central1",
        use_slug=True,
        provider_name="Google Vertex",
    )

    with pytest.raises(EndpointSnapshotValidationError, match="display name is ambiguous"):
        _validate(
            endpoint_payload=_endpoint_payload(configured, unconfigured),
            configured=("google-vertex/us-east5",),
        )


def test_structured_output_capability_can_be_discovered_without_requiring_it() -> None:
    endpoint = _endpoint()
    endpoint["supported_parameters"] = ["max_tokens", "reasoning", "temperature"]

    evidence = validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("approved-provider",),
        provider_policy_mode="only",
        endpoint_payload=_endpoint_payload(endpoint),
        require_zdr=False,
        structured_output_required=False,
    )

    assert evidence.endpoints[0].structured_output_parameters == ()
    assert evidence.endpoints[0].supported_output_modes == (
        StructuredOutputMode.VALIDATED_TEXT_JSON,
    )
    assert evidence.endpoints[0].structured_output_mode is StructuredOutputMode.VALIDATED_TEXT_JSON
    assert evidence.supported_output_modes == (StructuredOutputMode.VALIDATED_TEXT_JSON,)
    assert evidence.structured_output_mode is StructuredOutputMode.VALIDATED_TEXT_JSON
    assert evidence.endpoints[0].required_request_parameters == (
        "max_tokens",
        "temperature",
    )


def test_capability_discovery_defaults_to_validated_text_when_provider_format_is_absent() -> None:
    endpoint = _endpoint()
    endpoint["supported_parameters"] = ["max_tokens", "reasoning", "temperature"]

    evidence = validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("approved-provider",),
        provider_policy_mode="only",
        endpoint_payload=_endpoint_payload(endpoint),
        require_zdr=False,
    )

    assert evidence.structured_output_mode is StructuredOutputMode.VALIDATED_TEXT_JSON


def test_structured_output_remains_required_for_native_schema_requests() -> None:
    endpoint = _endpoint()
    endpoint["supported_parameters"] = ["max_tokens", "reasoning", "temperature"]

    with pytest.raises(
        EndpointSnapshotValidationError,
        match="emitted request parameter support: response_format",
    ):
        validate_openrouter_endpoint_snapshot(
            exact_model_id="alpha/atlas-secure",
            configured_provider_endpoints=("approved-provider",),
            provider_policy_mode="only",
            endpoint_payload=_endpoint_payload(endpoint),
            require_zdr=False,
            structured_output_required=True,
        )


@pytest.mark.parametrize(
    ("parameters", "expected_modes", "expected_mode"),
    [
        (
            [
                "max_tokens",
                "response_format",
                "structured_outputs",
                "temperature",
            ],
            (
                StructuredOutputMode.NATIVE_JSON_SCHEMA,
                StructuredOutputMode.JSON_OBJECT,
                StructuredOutputMode.VALIDATED_TEXT_JSON,
            ),
            StructuredOutputMode.NATIVE_JSON_SCHEMA,
        ),
        (
            ["max_tokens", "response_format", "temperature"],
            (
                StructuredOutputMode.JSON_OBJECT,
                StructuredOutputMode.VALIDATED_TEXT_JSON,
            ),
            StructuredOutputMode.JSON_OBJECT,
        ),
        (
            ["max_tokens", "temperature"],
            (StructuredOutputMode.VALIDATED_TEXT_JSON,),
            StructuredOutputMode.VALIDATED_TEXT_JSON,
        ),
    ],
)
def test_exact_endpoint_preserves_typed_output_modes(
    parameters: list[str],
    expected_modes: tuple[StructuredOutputMode, ...],
    expected_mode: StructuredOutputMode,
) -> None:
    endpoint = _endpoint()
    endpoint["supported_parameters"] = parameters

    evidence = validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("approved-provider",),
        provider_policy_mode="only",
        endpoint_payload=_endpoint_payload(endpoint),
        require_zdr=False,
        structured_output_required=False,
    )

    assert evidence.endpoints[0].supported_output_modes == expected_modes
    assert evidence.endpoints[0].structured_output_mode is expected_mode
    assert evidence.supported_output_modes == expected_modes
    assert evidence.structured_output_mode is expected_mode


def test_multi_endpoint_policy_negotiates_the_strongest_common_output_mode() -> None:
    native = _endpoint("native-provider", provider_name="Native Provider")
    native["supported_parameters"].append("structured_outputs")
    json_object = _endpoint("json-provider", provider_name="JSON Provider")

    evidence = validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("native-provider", "json-provider"),
        provider_policy_mode="order",
        endpoint_payload=_endpoint_payload(native, json_object),
        require_zdr=False,
        structured_output_required=False,
    )

    assert evidence.endpoints[0].structured_output_mode is StructuredOutputMode.NATIVE_JSON_SCHEMA
    assert evidence.endpoints[1].structured_output_mode is StructuredOutputMode.JSON_OBJECT
    assert evidence.supported_output_modes == (
        StructuredOutputMode.JSON_OBJECT,
        StructuredOutputMode.VALIDATED_TEXT_JSON,
    )
    assert evidence.structured_output_mode is StructuredOutputMode.JSON_OBJECT


def test_required_native_schema_mode_rejects_json_object_only_endpoint() -> None:
    endpoint = _endpoint()

    with pytest.raises(
        EndpointSnapshotValidationError,
        match="required structured-output mode",
    ):
        validate_openrouter_endpoint_snapshot(
            exact_model_id="alpha/atlas-secure",
            configured_provider_endpoints=("approved-provider",),
            provider_policy_mode="only",
            endpoint_payload=_endpoint_payload(endpoint),
            require_zdr=False,
            required_output_mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
        )


def test_snapshot_requires_every_parameter_emitted_by_the_request() -> None:
    missing_temperature = _endpoint()
    missing_temperature["supported_parameters"].remove("temperature")
    with pytest.raises(
        EndpointSnapshotValidationError,
        match="emitted request parameter support: temperature",
    ):
        _validate(endpoint_payload=_endpoint_payload(missing_temperature))

    missing_reasoning = _endpoint()
    missing_reasoning["supported_parameters"].remove("reasoning")
    with pytest.raises(
        EndpointSnapshotValidationError,
        match="emitted request parameter support: reasoning",
    ):
        validate_openrouter_endpoint_snapshot(
            exact_model_id="alpha/atlas-secure",
            configured_provider_endpoints=("approved-provider",),
            provider_policy_mode="only",
            endpoint_payload=_endpoint_payload(missing_reasoning),
            require_zdr=False,
            reasoning_requested=True,
        )


@pytest.mark.parametrize("status", [1, -1, True, "degraded", None])
def test_non_operational_or_missing_endpoint_status_is_rejected(status: Any) -> None:
    endpoint = _endpoint()
    endpoint["status"] = status

    with pytest.raises(EndpointSnapshotValidationError, match="operational"):
        _validate(endpoint_payload=_endpoint_payload(endpoint))


@pytest.mark.parametrize(
    ("pricing", "message"),
    [
        ({"prompt": "0.1"}, "omits prompt or completion"),
        ({"prompt": "-0.1", "completion": "0.1"}, "bounded decimal"),
        ({"prompt": "NaN", "completion": "0.1"}, "bounded decimal"),
        ({"prompt": 0.1, "completion": "0.1"}, "exact decimal strings"),
        ({"Prompt": "0.1", "completion": "0.1"}, "omits prompt or completion"),
        (
            {"prompt": "0.1", "completion": "0.1", "unsupported-field": "0"},
            "pricing field is invalid",
        ),
    ],
)
def test_incomplete_or_inexact_pricing_is_rejected(
    pricing: dict[str, Any],
    message: str,
) -> None:
    endpoint = _endpoint()
    endpoint["pricing"] = pricing

    with pytest.raises(EndpointSnapshotValidationError, match=message):
        _validate(endpoint_payload=_endpoint_payload(endpoint))


def test_recorded_xai_pricing_overrides_are_retained_and_self_bound() -> None:
    fixture = json.loads(
        (FIXTURES / "openrouter_tiered_pricing_shape.json").read_text(encoding="utf-8")
    )
    endpoint = _endpoint()
    endpoint["pricing"] = fixture["pricing"]

    snapshot = _validate(
        endpoint_payload=_endpoint_payload(endpoint),
        zdr_payload=_zdr_payload(endpoint),
    )
    evidence = snapshot.endpoint("approved-provider")

    assert evidence.pricing == {
        "completion": "0.0000066",
        "input_cache_read": "0.00000055",
        "input_cache_write": "0",
        "prompt": "0.0000022",
        "web_search": "0.01",
    }
    assert evidence.pricing_overrides == (
        OpenRouterPricingOverrideTier(
            min_prompt_tokens=200_000,
            prices={
                "completion": "0.0000132",
                "input_cache_read": "0.0000011",
                "input_cache_write": "0",
                "prompt": "0.0000044",
            },
        ),
    )
    projection = evidence.tiered_pricing_cost_projection
    assert isinstance(projection, ExactRoutePricingSchedule)
    assert {price.component.value: price.unit_price for price in projection.maximum_pricing} == {
        "completion": "0.0000132",
        "input_cache_read": "0.0000011",
        "input_cache_write": "0",
        "prompt": "0.0000044",
        "web_search": "0.01",
    }
    assert projection.conservative_for_sub_threshold_prompts is True
    assert projection.pricing_schedule_sha256 == evidence.pricing_sha256
    assert evidence.pricing_sha256 == openrouter_pricing_schedule_sha256(
        evidence.pricing,
        evidence.pricing_overrides,
    )
    assert len(evidence.pricing_sha256) == 64
    assert len(evidence.endpoint_snapshot_sha256) == 64
    serialized = evidence.model_dump(mode="json")
    assert serialized["pricing_overrides"] == [
        {
            "min_prompt_tokens": 200_000,
            "prices": {
                "completion": "0.0000132",
                "input_cache_read": "0.0000011",
                "input_cache_write": "0",
                "prompt": "0.0000044",
            },
        }
    ]
    assert "discount" not in json.dumps(serialized, sort_keys=True)


def test_pricing_overrides_use_strict_thresholds_inheritance_and_later_wins() -> None:
    endpoint = _endpoint()
    endpoint["pricing"]["overrides"] = [
        {
            "min_prompt_tokens": 100,
            "prompt": "0.0000060",
        },
        {
            "min_prompt_tokens": 200,
            "completion": "0.0000200",
            "prompt": "0.0000070",
        },
    ]

    evidence = _validate(
        endpoint_payload=_endpoint_payload(endpoint),
        require_zdr=False,
    ).endpoint("approved-provider")

    at_first_boundary = evidence.effective_pricing(100)
    above_first = evidence.effective_pricing(101)
    at_second_boundary = evidence.effective_pricing(200)
    above_second = evidence.effective_pricing(201)
    assert at_first_boundary["prompt"] == "0.000003"
    assert above_first["prompt"] == "0.000006"
    assert above_first["completion"] == "0.000015"
    assert at_second_boundary["prompt"] == "0.000006"
    assert above_second["prompt"] == "0.000007"
    assert above_second["completion"] == "0.00002"
    assert above_second["image"] == "0"
    projection = evidence.tiered_pricing_cost_projection
    assert isinstance(projection, ExactRoutePricingSchedule)
    assert {price.component.value: price.unit_price for price in projection.maximum_pricing} == {
        "completion": "0.00002",
        "image": "0",
        "prompt": "0.000007",
        "request": "0",
    }


@pytest.mark.parametrize(
    ("field", "projection_available"),
    [
        ("audio", False),
        ("completion", True),
        ("input_audio_cache", False),
        ("input_cache_read", False),
        ("input_cache_write", False),
        ("input_cache_write_1h", False),
        ("prompt", True),
    ],
)
def test_pricing_override_retains_every_documented_nested_price_field(
    field: str,
    projection_available: bool,
) -> None:
    endpoint = _endpoint()
    endpoint["pricing"]["overrides"] = [{"min_prompt_tokens": 100, field: "0.000006"}]

    evidence = _validate(
        endpoint_payload=_endpoint_payload(endpoint),
        require_zdr=False,
    ).endpoint("approved-provider")

    assert evidence.pricing_overrides[0].prices == {field: "0.000006"}
    assert evidence.effective_pricing(101)[field] == "0.000006"
    if projection_available:
        assert isinstance(evidence.tiered_pricing_cost_projection, ExactRoutePricingSchedule)
    else:
        assert evidence.tiered_pricing_cost_projection == "unavailable"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (None, "overrides must be a nonempty bounded list"),
        ([], "overrides must be a nonempty bounded list"),
        ({"min_prompt_tokens": 1}, "overrides must be a nonempty bounded list"),
        ([None], "override entry must be a bounded object"),
        ([{}], "override entry must be a bounded object"),
        (
            [{"completion": "0.2", "prompt": "0.1"}],
            "override entry omits min_prompt_tokens",
        ),
        (
            [{"discount": 0, "min_prompt_tokens": 1}],
            "override price field is invalid",
        ),
        (
            [{"discount": 0, "min_prompt_tokens": 1, "prompt": "0.1"}],
            "override price field is invalid",
        ),
    ],
)
def test_malformed_pricing_overrides_are_rejected(overrides: Any, message: str) -> None:
    endpoint = _endpoint()
    endpoint["pricing"]["overrides"] = overrides

    with pytest.raises(EndpointSnapshotValidationError, match=message):
        _validate(endpoint_payload=_endpoint_payload(endpoint), require_zdr=False)


def test_pricing_override_count_is_bounded() -> None:
    endpoint = _endpoint()
    endpoint["pricing"]["overrides"] = [
        {"min_prompt_tokens": threshold, "prompt": "0.1"} for threshold in range(65)
    ]

    with pytest.raises(
        EndpointSnapshotValidationError,
        match="overrides must be a nonempty bounded list",
    ):
        _validate(endpoint_payload=_endpoint_payload(endpoint), require_zdr=False)


@pytest.mark.parametrize("threshold", [True, 1.0, "1", -1, 2**31])
def test_pricing_override_threshold_must_be_an_exact_bounded_integer(
    threshold: Any,
) -> None:
    endpoint = _endpoint()
    endpoint["pricing"]["overrides"] = [{"min_prompt_tokens": threshold, "prompt": "0.1"}]

    with pytest.raises(
        EndpointSnapshotValidationError,
        match="min_prompt_tokens must be an exact bounded nonnegative integer",
    ):
        _validate(endpoint_payload=_endpoint_payload(endpoint), require_zdr=False)


@pytest.mark.parametrize(
    ("thresholds", "message"),
    [
        ((100, 100), "override thresholds are duplicated"),
        ((200, 100), "override thresholds must be strictly increasing"),
    ],
)
def test_pricing_override_thresholds_are_canonical(
    thresholds: tuple[int, int],
    message: str,
) -> None:
    endpoint = _endpoint()
    endpoint["pricing"]["overrides"] = [
        {"min_prompt_tokens": threshold, "prompt": "0.1"} for threshold in thresholds
    ]

    with pytest.raises(EndpointSnapshotValidationError, match=message):
        _validate(endpoint_payload=_endpoint_payload(endpoint), require_zdr=False)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("utc_start", "08:00", "override condition is unsupported: utc_start"),
        ("utc_end", "18:00", "override condition is unsupported: utc_end"),
        ("utc_days", [1, 2, 3], "override condition is unsupported: utc_days"),
        ("overrides", [], "override cannot contain recursive overrides"),
    ],
)
def test_pricing_override_unsupported_conditions_are_rejected(
    field: str,
    value: Any,
    message: str,
) -> None:
    endpoint = _endpoint()
    endpoint["pricing"]["overrides"] = [
        {
            "min_prompt_tokens": 1,
            "prompt": "0.1",
            field: value,
        }
    ]

    with pytest.raises(EndpointSnapshotValidationError, match=message):
        _validate(endpoint_payload=_endpoint_payload(endpoint), require_zdr=False)


@pytest.mark.parametrize("field", ["utc_days", "utc_end", "utc_start"])
def test_time_only_pricing_override_reports_the_unsupported_condition(field: str) -> None:
    endpoint = _endpoint()
    endpoint["pricing"]["overrides"] = [{field: "synthetic-time-condition"}]

    with pytest.raises(
        EndpointSnapshotValidationError,
        match=f"override condition is unsupported: {field}",
    ):
        _validate(endpoint_payload=_endpoint_payload(endpoint), require_zdr=False)


@pytest.mark.parametrize("field", ["utc_days", "utc_end", "utc_start", "usage_tiers"])
def test_durable_pricing_override_cannot_recast_conditions_as_prices(field: str) -> None:
    with pytest.raises(ValidationError, match="invalid price field"):
        OpenRouterPricingOverrideTier(
            min_prompt_tokens=1,
            prices={field: "100"},
        )


def test_pricing_override_rejects_an_unknown_or_ambiguous_price_field() -> None:
    unknown = _endpoint()
    unknown["pricing"]["overrides"] = [{"min_prompt_tokens": 1, "usage_tiers": "0.1"}]
    with pytest.raises(EndpointSnapshotValidationError, match="price field is invalid"):
        _validate(endpoint_payload=_endpoint_payload(unknown), require_zdr=False)

    ambiguous = _endpoint()
    ambiguous["pricing"]["overrides"] = [{"min_prompt_tokens": 1, "prompt": "0.1", "Prompt": "0.2"}]
    with pytest.raises(EndpointSnapshotValidationError, match="fields are ambiguous"):
        _validate(endpoint_payload=_endpoint_payload(ambiguous), require_zdr=False)


def test_pricing_override_entry_width_is_bounded_before_field_interpretation() -> None:
    endpoint = _endpoint()
    endpoint["pricing"]["overrides"] = [
        {
            "min_prompt_tokens": 1,
            **{f"synthetic_price_{index}": "0.1" for index in range(65)},
        }
    ]

    with pytest.raises(EndpointSnapshotValidationError, match="entry must be a bounded object"):
        _validate(endpoint_payload=_endpoint_payload(endpoint), require_zdr=False)


@pytest.mark.parametrize(
    ("price", "message"),
    [
        (None, "field prompt must be a scalar exact decimal string"),
        ([], "field prompt must be a scalar exact decimal string"),
        ({}, "field prompt must be a scalar exact decimal string"),
        (True, "field prompt must be an exact decimal string"),
        (1, "field prompt must be an exact decimal string"),
        (0.1, "field prompt must be an exact decimal string"),
        ("-0.1", "price is not a bounded decimal string"),
        ("NaN", "price is not a bounded decimal string"),
        ("1e-3", "price is not a bounded decimal string"),
        ("01", "price is not a bounded decimal string"),
        ("1000000000000", "price is not a bounded decimal string"),
        (
            "0.1234567890123456789012345678901234567",
            "price is not a bounded decimal string",
        ),
    ],
)
def test_pricing_override_prices_must_be_scalar_exact_decimal_strings(
    price: Any,
    message: str,
) -> None:
    endpoint = _endpoint()
    endpoint["pricing"]["overrides"] = [{"min_prompt_tokens": 1, "prompt": price}]

    with pytest.raises(EndpointSnapshotValidationError, match=message):
        _validate(endpoint_payload=_endpoint_payload(endpoint), require_zdr=False)


def test_unknown_top_level_pricing_collection_has_an_accurate_scalar_error() -> None:
    endpoint = _endpoint()
    endpoint["pricing"]["usage_tiers"] = []

    with pytest.raises(
        EndpointSnapshotValidationError,
        match="pricing field usage_tiers must be a scalar exact decimal string",
    ):
        _validate(endpoint_payload=_endpoint_payload(endpoint), require_zdr=False)


def test_zdr_pricing_overrides_must_match_the_model_endpoint_schedule() -> None:
    endpoint = _endpoint()
    endpoint["pricing"]["overrides"] = [{"min_prompt_tokens": 100, "prompt": "0.000006"}]
    zdr_endpoint = copy.deepcopy(endpoint)
    zdr_endpoint["pricing"]["overrides"][0]["prompt"] = "0.000007"

    with pytest.raises(EndpointSnapshotValidationError, match="snapshots are inconsistent"):
        _validate(
            endpoint_payload=_endpoint_payload(endpoint),
            zdr_payload=_zdr_payload(zdr_endpoint),
        )


def test_tiered_pricing_roundtrip_and_hashes_reject_tampering() -> None:
    endpoint = _endpoint()
    endpoint["pricing"]["overrides"] = [{"min_prompt_tokens": 100, "prompt": "0.000006"}]
    evidence = _validate(
        endpoint_payload=_endpoint_payload(endpoint),
        zdr_payload=_zdr_payload(endpoint),
    )

    assert (
        OpenRouterEndpointSnapshotEvidence.model_validate_json(evidence.model_dump_json())
        == evidence
    )

    payload = evidence.model_dump(mode="json")
    payload["endpoints"][0]["pricing_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="pricing hash is inconsistent"):
        OpenRouterEndpointSnapshotEvidence.model_validate_json(json.dumps(payload))

    payload = evidence.model_dump(mode="json")
    nested = payload["endpoints"][0]
    nested["pricing_overrides"][0]["prices"]["prompt"] = "0.000007"
    tiers = tuple(
        OpenRouterPricingOverrideTier.model_validate(item) for item in nested["pricing_overrides"]
    )
    nested["pricing_sha256"] = openrouter_pricing_schedule_sha256(
        nested["pricing"],
        tiers,
    )
    with pytest.raises(ValidationError, match="pricing projection is inconsistent"):
        OpenRouterEndpointSnapshotEvidence.model_validate_json(json.dumps(payload))

    payload = evidence.model_dump(mode="json")
    maximum = payload["endpoints"][0]["tiered_pricing_cost_projection"]["maximum_pricing"]
    next(item for item in maximum if item["component"] == "prompt")["unit_price"] = "0.000005"
    with pytest.raises(ValidationError, match="schedule maximum is inconsistent"):
        OpenRouterEndpointSnapshotEvidence.model_validate_json(json.dumps(payload))


def test_identical_maximum_different_schedule_cannot_reuse_projection() -> None:
    endpoint = _endpoint()
    endpoint["pricing"]["overrides"] = [{"min_prompt_tokens": 100, "prompt": "0.000006"}]
    evidence = _validate(
        endpoint_payload=_endpoint_payload(endpoint),
        require_zdr=False,
    )
    payload = evidence.model_dump(mode="json")
    nested = payload["endpoints"][0]
    nested["pricing_overrides"][0]["min_prompt_tokens"] = 101
    tiers = tuple(
        OpenRouterPricingOverrideTier.model_validate(item) for item in nested["pricing_overrides"]
    )
    nested["pricing_sha256"] = openrouter_pricing_schedule_sha256(
        nested["pricing"],
        tiers,
    )

    with pytest.raises(ValidationError, match="pricing projection is inconsistent"):
        OpenRouterEndpointSnapshotEvidence.model_validate_json(json.dumps(payload))


def test_durable_endpoint_evidence_rejects_scalarized_overrides_in_base_pricing() -> None:
    evidence = _validate(require_zdr=False).endpoint("approved-provider")
    payload = evidence.model_dump(mode="json")
    payload["pricing"] = dict(sorted({**payload["pricing"], "overrides": "0"}.items()))
    payload["pricing_sha256"] = openrouter_pricing_schedule_sha256(payload["pricing"], ())

    with pytest.raises(ValidationError, match="pricing contains an invalid field"):
        OpenRouterEndpointEvidence.model_validate(payload)


def test_pricing_override_schema_records_all_collection_and_threshold_bounds() -> None:
    schema = OpenRouterEndpointEvidence.model_json_schema()
    overrides = schema["properties"]["pricing_overrides"]
    tier = schema["$defs"]["OpenRouterPricingOverrideTier"]

    assert overrides["minItems"] == 1
    assert overrides["maxItems"] == 64
    assert "default" not in overrides
    assert tier["additionalProperties"] is False
    assert tier["properties"]["min_prompt_tokens"] == {
        "maximum": 2**31 - 1,
        "minimum": 0,
        "title": "Min Prompt Tokens",
        "type": "integer",
    }
    assert tier["properties"]["prices"]["minProperties"] == 1
    assert tier["properties"]["prices"]["maxProperties"] == 64


def test_flat_pricing_evidence_remains_byte_identical_without_overrides() -> None:
    baseline = _validate(require_zdr=False)
    equivalent = _endpoint()
    equivalent["pricing"] = {
        "completion": "0.0000150",
        "discount": 0,
        "image": "0.0",
        "prompt": "0.0000030",
        "request": "0.000",
    }
    canonicalized = _validate(
        endpoint_payload=_endpoint_payload(equivalent),
        require_zdr=False,
    )

    assert canonicalized.model_dump_json() == baseline.model_dump_json()
    assert canonicalized.snapshot_sha256 == baseline.snapshot_sha256
    assert canonicalized.endpoints[0].pricing_sha256 == baseline.endpoints[0].pricing_sha256
    assert (
        canonicalized.endpoints[0].endpoint_snapshot_sha256
        == baseline.endpoints[0].endpoint_snapshot_sha256
    )
    assert "pricing_overrides" not in baseline.endpoints[0].model_dump(mode="json")
    assert "tiered_pricing_cost_projection" not in baseline.endpoints[0].model_dump(mode="json")
    serialized = baseline.model_dump_json().encode("utf-8")
    assert len(serialized) == 1_716
    assert hashlib.sha256(serialized).hexdigest() == (
        "a7417bdb11293293a3c06d17e4b385da8fcbafeb661ae500fa5bf98f5536c41c"
    )
    assert baseline.snapshot_sha256 == (
        "7f34083ebf6de417254aaf857e015481e674a8527ab78674473fed6ce3c4b701"
    )
    assert baseline.endpoints[0].pricing_sha256 == (
        "061fc545aeb7c2d63159a92483091c7ec619656021b95d1de3be4e884e4f310d"
    )
    assert baseline.endpoints[0].endpoint_snapshot_sha256 == (
        "35c7fd1aa9f7741194a038e7b016af7cce3c05af0976d26bf2e7d0fe3ec89c2a"
    )


def test_captured_numeric_price_at_nonzero_endpoint_index_is_accepted() -> None:
    payload = _decoded_numeric_price_payload(
        "first-provider",
        "approved-provider",
        layout=MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
    )

    evidence = _validate(
        endpoint_payload=payload,
        configured=("approved-provider",),
        require_zdr=False,
    )

    assert evidence.endpoint("approved-provider").pricing["prompt"] == "0.000004"


def test_captured_numeric_price_moved_across_endpoint_indices_is_revoked() -> None:
    payload = _decoded_numeric_price_payload(
        "first-provider",
        "second-provider",
        layout=MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
    )
    endpoints = payload["data"]["endpoints"]
    first_pricing = endpoints[0]["pricing"]
    second_pricing = endpoints[1]["pricing"]
    first_token = first_pricing["prompt"]
    second_token = second_pricing["prompt"]
    assert captured_openrouter_json_number_raw(first_token) == "0.000003"

    first_pricing["prompt"] = "0.000003"
    second_pricing["prompt"] = first_token
    with pytest.raises(EndpointSnapshotValidationError):
        _validate(
            endpoint_payload=payload,
            configured=("first-provider", "second-provider"),
            require_zdr=False,
        )

    assert captured_openrouter_json_number_raw(first_token) is None
    first_pricing["prompt"] = first_token
    second_pricing["prompt"] = second_token
    with pytest.raises(EndpointSnapshotValidationError):
        _validate(
            endpoint_payload=payload,
            configured=("first-provider", "second-provider"),
            require_zdr=False,
        )


@pytest.mark.parametrize(
    "source_layout",
    [MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT, ZDR_ENDPOINT_PRICE_LEXEME_LAYOUT],
)
def test_captured_numeric_price_moved_across_endpoint_layouts_is_revoked(
    source_layout: OpenRouterPriceLexemeLayout,
) -> None:
    endpoint_payload = _decoded_numeric_price_payload(
        "approved-provider",
        layout=MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
    )
    zdr_payload = _decoded_numeric_price_payload(
        "approved-provider",
        layout=ZDR_ENDPOINT_PRICE_LEXEME_LAYOUT,
    )
    endpoint_pricing = endpoint_payload["data"]["endpoints"][0]["pricing"]
    zdr_pricing = zdr_payload["data"][0]["pricing"]
    endpoint_token = endpoint_pricing["prompt"]
    zdr_token = zdr_pricing["prompt"]

    if source_layout == MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT:
        moved_token = endpoint_token
        endpoint_pricing["prompt"] = "0.000003"
        zdr_pricing["prompt"] = moved_token
    else:
        moved_token = zdr_token
        endpoint_pricing["prompt"] = moved_token
        zdr_pricing["prompt"] = "0.000003"

    with pytest.raises(EndpointSnapshotValidationError):
        _validate(endpoint_payload=endpoint_payload, zdr_payload=zdr_payload)

    assert captured_openrouter_json_number_raw(moved_token) is None
    endpoint_pricing["prompt"] = endpoint_token
    zdr_pricing["prompt"] = zdr_token
    with pytest.raises(EndpointSnapshotValidationError):
        _validate(endpoint_payload=endpoint_payload, zdr_payload=zdr_payload)


def test_captured_numeric_price_moved_across_fields_is_revoked() -> None:
    payload = _decoded_numeric_price_payload(
        "approved-provider",
        layout=MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT,
    )
    pricing = payload["data"]["endpoints"][0]["pricing"]
    prompt_token = pricing["prompt"]
    completion = pricing["completion"]

    pricing["prompt"] = "0.000003"
    pricing["completion"] = prompt_token
    with pytest.raises(EndpointSnapshotValidationError):
        _validate(endpoint_payload=payload, require_zdr=False)

    assert captured_openrouter_json_number_raw(prompt_token) is None
    pricing["prompt"] = prompt_token
    pricing["completion"] = completion
    with pytest.raises(EndpointSnapshotValidationError):
        _validate(endpoint_payload=payload, require_zdr=False)


def test_zdr_required_policy_rejects_missing_or_wrong_endpoint_evidence() -> None:
    with pytest.raises(EndpointSnapshotValidationError, match="needs a current"):
        validate_openrouter_endpoint_snapshot(
            exact_model_id="alpha/atlas-secure",
            configured_provider_endpoints=("approved-provider",),
            provider_policy_mode="only",
            endpoint_payload=_endpoint_payload(),
            require_zdr=True,
            zdr_payload=None,
        )

    with pytest.raises(EndpointSnapshotValidationError, match="not present"):
        _validate(
            zdr_payload=_zdr_payload(
                _endpoint("different-provider"),
            )
        )


def test_zdr_snapshot_requires_consistent_exact_endpoint_metadata() -> None:
    zdr_endpoint = _endpoint()
    zdr_endpoint["pricing"]["completion"] = "0.000016"

    with pytest.raises(EndpointSnapshotValidationError, match="inconsistent"):
        _validate(zdr_payload=_zdr_payload(zdr_endpoint))


def test_optional_zdr_snapshot_records_unknown_or_false_without_promoting_it() -> None:
    unknown = _validate(require_zdr=False, zdr_payload=None)
    assert unknown.endpoints[0].zdr_eligible is None
    assert unknown.zdr_metadata_sha256 is None

    absent = _validate(
        require_zdr=False,
        zdr_payload=_zdr_payload(_endpoint("different-provider")),
    )
    assert absent.endpoints[0].zdr_eligible is False
    assert absent.zdr_metadata_sha256 is not None


def test_optional_zdr_snapshot_accepts_an_authenticated_empty_catalog() -> None:
    evidence = _validate(require_zdr=False, zdr_payload={"data": []})

    assert evidence.endpoints[0].zdr_eligible is False
    assert evidence.zdr_metadata_sha256 is not None


def test_token_limits_must_be_positive_and_internally_bounded() -> None:
    endpoint = _endpoint()
    endpoint["max_completion_tokens"] = endpoint["context_length"] + 1

    with pytest.raises(EndpointSnapshotValidationError, match="completion limit exceeds"):
        _validate(endpoint_payload=_endpoint_payload(endpoint))


def test_null_live_metadata_limits_use_the_explicit_context_ceiling() -> None:
    endpoint = _endpoint()
    endpoint["max_prompt_tokens"] = None
    endpoint["max_completion_tokens"] = None
    endpoint["pricing"]["discount"] = 0

    evidence = _validate(
        endpoint_payload=_endpoint_payload(endpoint),
        zdr_payload=_zdr_payload(endpoint),
    ).endpoints[0]

    assert evidence.max_prompt_tokens == endpoint["context_length"]
    assert evidence.max_completion_tokens == endpoint["context_length"]
    assert evidence.max_prompt_tokens_source == "context_limit"
    assert evidence.max_completion_tokens_source == "context_limit"
    assert "discount" not in evidence.pricing


@pytest.mark.parametrize("discount", [-0.01, 1, float("inf"), True, []])
def test_invalid_or_cost_increasing_discount_metadata_is_rejected(discount: Any) -> None:
    endpoint = _endpoint()
    endpoint["pricing"]["discount"] = discount

    with pytest.raises(EndpointSnapshotValidationError, match="discount"):
        _validate(endpoint_payload=_endpoint_payload(endpoint))


def test_self_hash_rejects_tampered_serialized_evidence() -> None:
    evidence = _validate()
    payload = evidence.model_dump(mode="json")
    payload["endpoints"][0]["pricing"]["prompt"] = "0.1"

    with pytest.raises(ValidationError, match="pricing hash is inconsistent"):
        OpenRouterEndpointSnapshotEvidence.model_validate(payload)

    payload = evidence.model_dump(mode="json")
    payload["endpoints"][0]["structured_output_mode"] = (
        StructuredOutputMode.VALIDATED_TEXT_JSON.value
    )
    with pytest.raises(ValidationError, match="negotiated endpoint output mode"):
        OpenRouterEndpointSnapshotEvidence.model_validate(payload)

    payload = evidence.model_dump(mode="json")
    payload["output_capability_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="output-capability hash"):
        OpenRouterEndpointSnapshotEvidence.model_validate(payload)


def test_constrained_slug_only_snapshot_embeds_complete_discovery_report() -> None:
    endpoint_id = "approved-provider/fp8"
    endpoint = _constrained_endpoint(endpoint_id, use_slug=True)
    _, _, context = _route_bundle(endpoint_id=endpoint_id)

    evidence = _validate_constrained(
        endpoint,
        context=context,
        endpoint_id=endpoint_id,
    )

    assert evidence.endpoints[0].endpoint_tag is None
    assert evidence.endpoints[0].endpoint_slug == endpoint_id
    assert evidence.normalized_route_facts is not None
    assert evidence.normalized_route_facts.observed_provider_endpoint == endpoint_id
    assert evidence.normalized_route_facts.emitted_request_parameters == (
        "max_tokens",
        "reasoning",
        "response_format",
        "temperature",
    )
    assert evidence.route_predicate_report is not None
    required_results = evidence.route_predicate_report.results[:-5]
    assert all(
        result.disposition is RoutePredicateDisposition.SATISFIED for result in required_results
    )
    assert (
        OpenRouterEndpointSnapshotEvidence.model_validate_json(evidence.model_dump_json())
        == evidence
    )


@pytest.mark.parametrize(
    ("endpoint_id", "selected_provider_name"),
    (
        ("sail-research/fp8", "Sail Research"),
        ("modal/mxfp4", "Modal"),
    ),
)
def test_generic_and_constrained_snapshots_reject_selected_display_name_ambiguity(
    endpoint_id: str,
    selected_provider_name: str,
) -> None:
    selected = _constrained_endpoint(
        endpoint_id,
        use_slug=True,
        provider_name=selected_provider_name,
    )
    duplicate = _constrained_endpoint(
        f"{endpoint_id}-duplicate",
        use_slug=True,
        provider_name=selected_provider_name.swapcase(),
    )
    _, _, context = _route_bundle(endpoint_id=endpoint_id)
    endpoint_payload = _endpoint_payload(selected, duplicate)

    with pytest.raises(EndpointSnapshotValidationError, match="display name is ambiguous"):
        _validate(
            endpoint_payload=endpoint_payload,
            zdr_payload=_zdr_payload(selected),
            configured=(endpoint_id,),
        )
    with pytest.raises(EndpointSnapshotValidationError, match="display name is ambiguous"):
        _validate_constrained(
            selected,
            context=context,
            endpoint_id=endpoint_id,
            endpoint_payload=endpoint_payload,
        )


@pytest.mark.parametrize(
    ("endpoint_id", "selected_provider_name"),
    (
        ("sail-research/fp8", "Sail Research"),
        ("modal/mxfp4", "Modal"),
    ),
)
def test_constrained_snapshot_allows_unrelated_duplicate_provider_display_names(
    endpoint_id: str,
    selected_provider_name: str,
) -> None:
    selected = _constrained_endpoint(
        endpoint_id,
        use_slug=True,
        provider_name=selected_provider_name,
    )
    unrelated = (
        _constrained_endpoint("fireworks/a", provider_name="Fireworks"),
        _constrained_endpoint("fireworks/b", provider_name="fireworks"),
        _constrained_endpoint("fireworks/c", provider_name="FIREWORKS"),
        _constrained_endpoint("alibaba/a", provider_name="Alibaba"),
        _constrained_endpoint("alibaba/b", provider_name="alibaba"),
        _constrained_endpoint("morph/a", provider_name="Morph"),
        _constrained_endpoint("morph/b", provider_name="morph"),
    )
    _, _, context = _route_bundle(endpoint_id=endpoint_id)
    endpoint_payload = _endpoint_payload(selected, *unrelated)

    generic_evidence = _validate(
        endpoint_payload=endpoint_payload,
        zdr_payload=_zdr_payload(selected),
        configured=(endpoint_id,),
    )

    evidence = _validate_constrained(
        selected,
        context=context,
        endpoint_id=endpoint_id,
        endpoint_payload=endpoint_payload,
    )

    assert generic_evidence.endpoints[0].provider_name == selected_provider_name
    assert evidence.normalized_route_facts is not None
    assert evidence.normalized_route_facts.selected_provider_display_name == selected_provider_name
    normalized_inventory = tuple(
        name.casefold() for name in evidence.normalized_route_facts.provider_display_names
    )
    assert normalized_inventory.count("fireworks") == 3
    assert normalized_inventory.count("alibaba") == 2
    assert normalized_inventory.count("morph") == 2
    assert evidence.route_predicate_report is not None
    result = next(
        result
        for result in evidence.route_predicate_report.results
        if result.predicate_id is RoutePredicateId.PROVIDER_DISPLAY_NAME_INJECTIVITY
    )
    assert result.disposition is RoutePredicateDisposition.SATISFIED
    assert result.reason is RoutePredicateReason.SATISFIED


def test_constrained_reasoning_inventory_uses_endpoint_first_and_model_fallback() -> None:
    _, _, context = _route_bundle(model_efforts=("high",))
    fallback_endpoint = _constrained_endpoint(supported_efforts=None)
    fallback = _validate_constrained(fallback_endpoint, context=context)
    assert fallback.normalized_route_facts is not None
    assert fallback.normalized_route_facts.endpoint_supported_reasoning_efforts is None
    assert fallback.normalized_route_facts.model_supported_reasoning_efforts == ("high",)

    empty_endpoint = _constrained_endpoint(supported_efforts=())
    with pytest.raises(
        EndpointSnapshotValidationError,
        match="REASONING_EFFORT_INVENTORY_EMPTY",
    ):
        _validate_constrained(empty_endpoint, context=context)

    _, _, narrow_model_context = _route_bundle(model_efforts=("high",))
    contradictory_endpoint = _constrained_endpoint(supported_efforts=("high", "xhigh"))
    with pytest.raises(
        EndpointSnapshotValidationError,
        match="REASONING_EFFORT_INVENTORY_CONTRADICTORY",
    ):
        _validate_constrained(contradictory_endpoint, context=narrow_model_context)


def test_constrained_snapshot_rejects_reasoning_emission_without_endpoint_support() -> None:
    _, _, context = _route_bundle(model_efforts=("high",))
    endpoint = _constrained_endpoint(supported_efforts=None)
    endpoint["supported_parameters"].remove("reasoning")

    with pytest.raises(
        EndpointSnapshotValidationError,
        match="EMITTED_PARAMETER_SUPPORT_MISMATCH",
    ):
        _validate_constrained(endpoint, context=context)

    with pytest.raises(
        ValidationError,
        match="required request parameters differ from shared emission",
    ):
        _validate_constrained(
            _constrained_endpoint(supported_efforts=None),
            context=context,
            reasoning_requested=False,
        )


def test_constrained_snapshot_rejects_reasoning_emission_without_model_support() -> None:
    _, _, context = _route_bundle(model_efforts=None)
    context = OpenRouterConstrainedRouteContext.model_validate(
        {
            **context.model_dump(mode="python"),
            "model_supported_parameters": tuple(
                parameter
                for parameter in context.model_supported_parameters
                if parameter != "reasoning"
            ),
        }
    )

    with pytest.raises(
        EndpointSnapshotValidationError,
        match="EMITTED_PARAMETER_SUPPORT_MISMATCH",
    ):
        _validate_constrained(_constrained_endpoint(), context=context)


def test_constrained_snapshot_derives_emitted_parameters_from_actual_reasoning_policy() -> None:
    _, _, context = _route_bundle(observed_policy=_reasoning_policy(mode="disabled"))

    with pytest.raises(
        EndpointSnapshotValidationError,
        match="REASONING_NOT_EMITTED",
    ):
        _validate_constrained(_constrained_endpoint(), context=context)


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        ("prompt", "PROMPT_CAPACITY_INSUFFICIENT"),
        ("completion", "OUTPUT_CAPACITY_INSUFFICIENT"),
        ("context", "CONTEXT_CAPACITY_INSUFFICIENT"),
    ),
)
def test_constrained_snapshot_rejects_insufficient_capacity(
    mutation: str,
    reason: str,
) -> None:
    endpoint = _constrained_endpoint()
    if mutation == "prompt":
        endpoint["max_prompt_tokens"] = 99_999
    elif mutation == "completion":
        endpoint["max_completion_tokens"] = 4_095
    else:
        endpoint["context_length"] = 119_999
        endpoint["max_prompt_tokens"] = 100_000
    _, _, context = _route_bundle()

    with pytest.raises(EndpointSnapshotValidationError, match=reason) as exc_info:
        _validate_constrained(endpoint, context=context)
    assert "price-cap projection" not in str(exc_info.value)


@pytest.mark.parametrize("component", ("input_cache_write", "internal_reasoning"))
@pytest.mark.parametrize("price", ("0", "0.000001"))
@pytest.mark.parametrize(
    "algorithm",
    (
        ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1,
        ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2,
    ),
)
def test_constrained_snapshot_names_unexpressible_provider_price_without_raw_metadata(
    component: str,
    price: str,
    algorithm: ProviderPriceCapAlgorithm,
) -> None:
    endpoint = _constrained_endpoint()
    endpoint["name"] = "untrusted-provider-diagnostic-canary"
    endpoint["pricing"][component] = price
    _, _, context = _route_bundle(price_cap_algorithm=algorithm)

    with pytest.raises(
        EndpointSnapshotValidationError,
        match="PRICE_CAP_NOT_EXPRESSIBLE",
    ) as exc_info:
        _validate_constrained(endpoint, context=context)

    message = str(exc_info.value)
    assert "PRICE_CAP_PROOF_UNAVAILABLE" in message
    assert (
        f"price-cap projection [{algorithm.value}]: "
        f"route contains a variable price without a provider cap: {component}"
    ) in message
    assert endpoint["name"] not in message


def test_constrained_snapshot_distinguishes_a_non_dominated_cache_read_price() -> None:
    endpoint = _constrained_endpoint()
    endpoint["pricing"]["input_cache_read"] = "0.000004"
    _, _, context = _route_bundle()

    with pytest.raises(EndpointSnapshotValidationError) as exc_info:
        _validate_constrained(endpoint, context=context)

    message = str(exc_info.value)
    assert "PRICE_CAP_NOT_EXPRESSIBLE" in message
    assert "route cache-read pricing is not prompt dominated" in message
    assert "input_cache_write" not in message


def test_constrained_tiered_price_shape_isolates_the_cache_write_refusal() -> None:
    endpoint = _constrained_endpoint()
    fixture = json.loads((FIXTURES / "openrouter_tiered_pricing_shape.json").read_text())
    endpoint["pricing"] = fixture["pricing"]
    _, _, context = _route_bundle(
        price_cap_algorithm=ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2
    )

    with pytest.raises(EndpointSnapshotValidationError, match="provider cap: input_cache_write"):
        _validate_constrained(endpoint, context=context)

    # A synthetic paired control isolates this blocker; never alter real metadata this way.
    control = copy.deepcopy(endpoint)
    del control["pricing"]["input_cache_write"]
    for tier in control["pricing"]["overrides"]:
        del tier["input_cache_write"]
    snapshot = _validate_constrained(control, context=context)
    facts = snapshot.normalized_route_facts
    assert facts is not None
    assert {
        cap.component.value: cap.value for cap in facts.configured_provider_max_price or ()
    } == {
        "completion": 13.2,
        "prompt": 4.4,
    }


def test_constrained_snapshot_binds_nonzero_web_search_to_zero_request_units() -> None:
    endpoint = _constrained_endpoint()
    endpoint["pricing"]["web_search"] = "0.01"
    profile, _, context = _route_bundle(
        price_cap_algorithm=(ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2)
    )

    snapshot = _validate_constrained(endpoint, context=context)
    assert snapshot.route_predicate_profile == profile
    facts = snapshot.normalized_route_facts
    report = snapshot.route_predicate_report
    assert facts is not None
    assert report is not None
    assert {item.component.value for item in facts.configured_provider_max_price or ()} == {
        "completion",
        "image",
        "prompt",
        "request",
    }
    results = {item.predicate_id: item for item in report.results}
    assert results[RoutePredicateId.PRICE_CAP_EXPRESSIBILITY].disposition is (
        RoutePredicateDisposition.SATISFIED
    )
    assert results[RoutePredicateId.PRICE_CAP_NO_WEAKER].disposition is (
        RoutePredicateDisposition.SATISFIED
    )
    OpenRouterEndpointSnapshotEvidence.model_validate_json(snapshot.model_dump_json(), strict=True)


def test_component_unit_envelope_does_not_exempt_zero_cache_write_price() -> None:
    endpoint = _constrained_endpoint()
    endpoint["pricing"]["input_cache_write"] = "0"
    _, _, context = _route_bundle(
        price_cap_algorithm=(ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2)
    )

    with pytest.raises(
        EndpointSnapshotValidationError,
        match="PRICE_CAP_NOT_EXPRESSIBLE",
    ):
        _validate_constrained(endpoint, context=context)


def test_constrained_snapshot_projects_the_schedule_maximum_across_a_valid_override() -> None:
    endpoint = _constrained_endpoint()
    endpoint["pricing"]["overrides"] = [{"min_prompt_tokens": 100_000, "prompt": "0.000006"}]
    _, _, context = _route_bundle()

    snapshot = _validate_constrained(endpoint, context=context)
    evidence = snapshot.endpoint("approved-provider")
    projection = evidence.tiered_pricing_cost_projection
    assert isinstance(projection, ExactRoutePricingSchedule)
    assert {price.component.value: price.unit_price for price in projection.maximum_pricing} == {
        "completion": "0.000015",
        "image": "0",
        "prompt": "0.000006",
        "request": "0",
    }
    facts = snapshot.normalized_route_facts
    assert facts is not None
    assert facts.pricing_schedule == projection
    assert {
        cap.component.value: cap.value for cap in facts.configured_provider_max_price or ()
    } == {
        "completion": 15.0,
        "image": 0.0,
        "prompt": 6.0,
        "request": 0.0,
    }


def test_constrained_snapshot_fails_closed_for_an_indeterminate_retained_schedule() -> None:
    endpoint = _constrained_endpoint()
    endpoint["pricing"]["overrides"] = [
        {"min_prompt_tokens": 100_000, "input_cache_read": "0.000001"}
    ]
    _, _, context = _route_bundle()

    with pytest.raises(EndpointSnapshotValidationError) as exc_info:
        _validate_constrained(endpoint, context=context)

    message = str(exc_info.value)
    assert "PRICE_CAP_NOT_EXPRESSIBLE" in message
    assert "PRICE_CAP_PROOF_UNAVAILABLE" in message
    assert "PRICE_CAP_MISSING" not in message
    assert "pricing schedule unavailable" in message


def test_constrained_snapshot_rejects_partial_embedded_route_evidence() -> None:
    generic = _validate()
    serialized = generic.model_dump(mode="json")
    serialized["route_predicate_profile"] = _route_bundle()[0].model_dump(mode="json")

    with pytest.raises(ValidationError, match="all present or absent"):
        OpenRouterEndpointSnapshotEvidence.model_validate_json(json.dumps(serialized))
