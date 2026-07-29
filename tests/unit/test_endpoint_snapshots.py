from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.endpoint_snapshots import (
    EndpointSnapshotValidationError,
    OpenRouterEndpointSnapshotEvidence,
    validate_openrouter_endpoint_snapshot,
)
from mmaudit.orchestration.budgets import EndpointRequestCostBound


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
        "prompt": "0.000003",
        "image": "0.0",
        "request": "0.000",
    }
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
    serialized = json.dumps(first.model_dump(mode="json"), sort_keys=True)
    assert "untrusted_unknown_field" not in serialized
    assert '"name": "Provider-controlled display name"' not in serialized


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
    assert evidence.endpoints[0].required_request_parameters == (
        "max_tokens",
        "temperature",
    )


def test_structured_output_remains_required_for_native_schema_requests() -> None:
    endpoint = _endpoint()
    endpoint["supported_parameters"] = ["max_tokens", "reasoning", "temperature"]

    with pytest.raises(
        EndpointSnapshotValidationError,
        match="emitted request parameter support: response_format",
    ):
        _validate(endpoint_payload=_endpoint_payload(endpoint))


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
