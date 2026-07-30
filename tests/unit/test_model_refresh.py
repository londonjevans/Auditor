from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import pytest
from pydantic import ValidationError

import mmaudit.models.refresh as refresh_module
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    CandidateModel,
    CandidateOperationalStatus,
    LineageReviewStatus,
    load_candidate_registry,
    seal_candidate_registry,
    seal_operator_lineage_review,
)
from mmaudit.models.refresh import (
    ATTEMPT_FILENAME,
    DIFF_FILENAME,
    FRESHNESS_FILENAME,
    SNAPSHOT_FILENAME,
    SOURCE_EVIDENCE_FILENAME,
    CatalogModelState,
    ModelDriftKind,
    ModelRefreshAttempt,
    ModelRefreshAttemptStatus,
    ModelRefreshFailureCode,
    ModelRefreshFreshnessState,
    ModelRefreshValidationError,
    PricingComparisonState,
    SelectedModelRoute,
    build_model_refresh_snapshot,
    build_model_refresh_snapshot_from_source,
    build_model_refresh_source_evidence,
    diff_model_refresh,
    evaluate_model_refresh_freshness,
    load_model_refresh_attempt,
    load_model_refresh_diff,
    load_model_refresh_freshness,
    load_model_refresh_snapshot,
    load_model_refresh_source_evidence,
    model_variant_family_key,
    seal_model_refresh_attempt,
    write_model_refresh_failure,
    write_model_refresh_success,
)

NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
MODEL = "alpha/atlas-secure"
ENDPOINT = "approved-provider/fp8"
BASE_PRICING = {"completion": "0.000002", "prompt": "0.000001"}
PARAMETERS = [
    "max_tokens",
    "reasoning",
    "response_format",
    "temperature",
]


def _sha(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _reseal_catalog_model(payload: dict[str, Any]) -> dict[str, Any]:
    for route in payload["routes"]:
        route["route_sha256"] = _sha(
            {key: value for key, value in route.items() if key != "route_sha256"}
        )
    payload["routes"] = sorted(
        payload["routes"],
        key=lambda route: route["provider_endpoint"],
    )
    payload["eligible_provider_endpoints"] = [
        route["provider_endpoint"]
        for route in payload["routes"]
        if route["routing_identity_unambiguous"]
        and route["operational"]
        and route["zdr_eligible"]
        and {"max_tokens", "temperature"}.issubset(route["supported_parameters"])
        and route["pricing_observation"] == "EXACT"
        and {"max_tokens", "temperature"}.issubset(payload["supported_parameters"])
    ]
    payload["state_sha256"] = _sha(
        {key: value for key, value in payload.items() if key != "state_sha256"}
    )
    return payload


def _registry(
    *,
    model_ids: tuple[str, ...] = (MODEL,),
    pricing: dict[str, Any] = BASE_PRICING,
    structured_output_mode: StructuredOutputMode | None = StructuredOutputMode.JSON_OBJECT,
    max_prompt_tokens: int = 91_808,
    max_prompt_tokens_source: Literal["metadata", "context_limit"] = "metadata",
    output_limit: int = 8_192,
    output_limit_source: Literal["metadata", "context_limit"] = "metadata",
) -> Any:
    candidates = []
    for index, model_id in enumerate(sorted(model_ids)):
        endpoint = ENDPOINT if model_id == MODEL else f"provider-{index}/fp8"
        review = seal_operator_lineage_review(
            status=LineageReviewStatus.PENDING,
            reviewed_model_ids=(model_id,),
            rationale="Synthetic lineage remains pending independent review.",
        )
        candidates.append(
            CandidateModel(
                exact_model_id=model_id,
                canonical_model_slug=model_id,
                root_lineage=None,
                lineage_review=review,
                discovery_evidence_sha256=_sha(["discovery", model_id]),
                approved_provider_endpoint=endpoint,
                approved_provider_name=(
                    "Approved Provider" if model_id == MODEL else f"Provider {index}"
                ),
                endpoint_snapshot_sha256=_sha(["endpoint", model_id]),
                output_capability_sha256=(
                    None
                    if structured_output_mode is None
                    else _sha(["output-capability", model_id, structured_output_mode.value])
                ),
                model_metadata_snapshot_sha256=_sha(["metadata", model_id]),
                pricing_snapshot_sha256=_sha(pricing),
                context_size=100_000,
                max_prompt_tokens=(None if structured_output_mode is None else max_prompt_tokens),
                max_prompt_tokens_source=(
                    None if structured_output_mode is None else max_prompt_tokens_source
                ),
                output_limit=output_limit,
                output_limit_source=(
                    None if structured_output_mode is None else output_limit_source
                ),
                structured_output_supported=(
                    True
                    if structured_output_mode is None
                    else structured_output_mode is not StructuredOutputMode.VALIDATED_TEXT_JSON
                ),
                structured_output_mode=structured_output_mode,
                reasoning_supported=True,
                zdr_eligible=True,
                data_collection_deny_eligible=True,
                operational_status=CandidateOperationalStatus.AVAILABLE,
                benchmark_status=CandidateBenchmarkStatus.PENDING,
            )
        )
    return seal_candidate_registry(
        created_at=NOW,
        discovery_run_sha256=_sha(["discovery-run", *model_ids]),
        candidates=tuple(candidates),
    )


def _model(
    model_id: str = MODEL,
    *,
    context: int = 100_000,
    output: int = 8_192,
    parameters: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": model_id,
        "canonical_slug": model_id,
        "context_length": context,
        "top_provider": {
            "context_length": context,
            "max_completion_tokens": output,
        },
        "supported_parameters": list(PARAMETERS if parameters is None else parameters),
    }


def _endpoint(
    model_id: str = MODEL,
    endpoint: str = ENDPOINT,
    *,
    pricing: dict[str, str] = BASE_PRICING,
    context: int = 100_000,
    output: int = 8_192,
    parameters: list[str] | None = None,
    status: int | str = 0,
) -> dict[str, Any]:
    return {
        "model_id": model_id,
        "slug": endpoint,
        "provider_name": ("Approved Provider" if endpoint == ENDPOINT else "Synthetic Provider"),
        "status": status,
        "context_length": context,
        "max_prompt_tokens": context - output,
        "max_completion_tokens": output,
        "supported_parameters": list(PARAMETERS if parameters is None else parameters),
        "pricing": dict(pricing),
    }


def _dual_identity_endpoint(
    *,
    tag: str,
    slug: str,
    provider_name: str,
    model_id: str = MODEL,
) -> dict[str, Any]:
    endpoint = _endpoint(model_id, slug)
    endpoint["tag"] = tag
    endpoint["provider_name"] = provider_name
    return endpoint


def _endpoint_envelope(model_id: str, *endpoints: dict[str, Any]) -> dict[str, Any]:
    return {
        "data": {
            "id": model_id,
            "endpoints": [
                {key: value for key, value in endpoint.items() if key != "model_id"}
                for endpoint in endpoints
            ],
        }
    }


def _snapshot(
    registry: Any,
    *,
    retrieved_at: datetime = NOW,
    models: list[dict[str, Any]] | None = None,
    zdr_endpoints: list[dict[str, Any]] | None = None,
    candidate_endpoints: dict[str, list[dict[str, Any]]] | None = None,
):
    models = list(models if models is not None else [_model()])
    zdr_endpoints = list(zdr_endpoints if zdr_endpoints is not None else [_endpoint()])
    selected = candidate_endpoints or {
        candidate.exact_model_id: [
            _endpoint(
                candidate.exact_model_id,
                candidate.approved_provider_endpoint,
            )
        ]
        for candidate in registry.candidates
    }
    return build_model_refresh_snapshot(
        retrieved_at=retrieved_at,
        catalog_payload={"data": models},
        zdr_payload={"data": zdr_endpoints},
        candidate_registry=registry,
        candidate_endpoint_payloads={
            model_id: _endpoint_envelope(model_id, *endpoints)
            for model_id, endpoints in selected.items()
        },
        authenticated_metadata=True,
    )


def _source(
    registry: Any,
    *,
    retrieved_at: datetime = NOW,
    models: list[dict[str, Any]] | None = None,
    zdr_endpoints: list[dict[str, Any]] | None = None,
    candidate_endpoints: dict[str, list[dict[str, Any]]] | None = None,
):
    models = list(models if models is not None else [_model()])
    zdr_endpoints = list(zdr_endpoints if zdr_endpoints is not None else [_endpoint()])
    selected = candidate_endpoints or {
        candidate.exact_model_id: [
            _endpoint(
                candidate.exact_model_id,
                candidate.approved_provider_endpoint,
            )
        ]
        for candidate in registry.candidates
    }
    return build_model_refresh_source_evidence(
        retrieved_at=retrieved_at,
        catalog_payload={"data": models},
        zdr_payload={"data": zdr_endpoints},
        candidate_registry=registry,
        candidate_endpoint_payloads={
            model_id: _endpoint_envelope(model_id, *endpoints)
            for model_id, endpoints in selected.items()
        },
        authenticated_metadata=True,
    )


def test_refresh_reuses_production_pricing_and_provider_slug_normalization() -> None:
    registry = _registry()
    endpoint = _endpoint(
        pricing={
            "completion": "0.0000020",
            "discount": 0,
            "prompt": "0.0000010",
        }
    )
    endpoint["provider_slug"] = endpoint.pop("slug")

    snapshot = _snapshot(
        registry,
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )

    route = snapshot.models[0].routes[0]
    assert route.provider_endpoint == ENDPOINT
    assert route.endpoint_slug == ENDPOINT
    assert route.pricing == BASE_PRICING
    assert route.zdr_eligible


def test_refresh_reuses_production_token_limit_and_parameter_normalization() -> None:
    registry = _registry()
    endpoint = _endpoint(parameters=list(reversed(PARAMETERS)))
    endpoint["max_prompt_tokens"] = None
    endpoint["max_completion_tokens"] = None
    model = _model(parameters=list(reversed(PARAMETERS)))
    model["top_provider"]["max_completion_tokens"] = None

    snapshot = _snapshot(
        registry,
        models=[model],
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )

    route = snapshot.models[0].routes[0]
    assert route.max_prompt_tokens == 100_000
    assert route.max_prompt_tokens_source == "context_limit"
    assert route.output_limit == 100_000
    assert route.output_limit_source == "context_limit"
    assert route.supported_parameters == tuple(sorted(PARAMETERS))
    assert snapshot.models[0].output_limit == 100_000
    assert snapshot.models[0].output_limit_source == "provider_context"


@pytest.mark.parametrize("surface", ("catalog", "endpoint"))
def test_duplicate_supported_parameters_fail_closed(surface: str) -> None:
    registry = _registry()
    parameters = [*PARAMETERS, "reasoning"]
    model = _model(parameters=parameters if surface == "catalog" else None)
    endpoint = _endpoint(parameters=parameters if surface == "endpoint" else None)

    with pytest.raises(ModelRefreshValidationError, match="supported parameters"):
        _snapshot(
            registry,
            models=[model],
            zdr_endpoints=[endpoint],
            candidate_endpoints={MODEL: [endpoint]},
        )


def test_padded_operational_status_fails_without_changing_casefold_semantics() -> None:
    registry = _registry()
    padded = _endpoint(status=" operational ")
    with pytest.raises(ModelRefreshValidationError, match="operational status"):
        _snapshot(
            registry,
            zdr_endpoints=[padded],
            candidate_endpoints={MODEL: [padded]},
        )

    uppercase = _endpoint(status="OPERATIONAL")
    snapshot = _snapshot(
        registry,
        zdr_endpoints=[uppercase],
        candidate_endpoints={MODEL: [uppercase]},
    )
    assert snapshot.models[0].routes[0].operational
    assert snapshot.models[0].routes[0].operational_status == "operational"


def test_zdr_credit_requires_identical_token_limit_sources() -> None:
    registry = _registry()
    endpoint = _endpoint()
    endpoint["max_prompt_tokens"] = None
    counterpart = _endpoint()
    counterpart["max_prompt_tokens"] = 100_000

    snapshot = _snapshot(
        registry,
        zdr_endpoints=[counterpart],
        candidate_endpoints={MODEL: [endpoint]},
    )

    route = snapshot.models[0].routes[0]
    assert route.max_prompt_tokens == 100_000
    assert route.max_prompt_tokens_source == "context_limit"
    assert route.zdr_eligible is False


def test_shared_route_tags_use_unique_slugs_and_remain_order_invariant() -> None:
    registry = _registry()
    first = _dual_identity_endpoint(
        tag="shared-provider",
        slug=ENDPOINT,
        provider_name="Approved Provider",
    )
    second = _dual_identity_endpoint(
        tag="shared-provider",
        slug="approved-provider/int8",
        provider_name="Secondary Provider",
    )

    forward = _snapshot(
        registry,
        zdr_endpoints=[first, second],
        candidate_endpoints={MODEL: [first, second]},
    )
    reversed_snapshot = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=1),
        zdr_endpoints=[second, first],
        candidate_endpoints={MODEL: [second, first]},
    )

    assert tuple(route.provider_endpoint for route in forward.models[0].routes) == (
        ENDPOINT,
        "approved-provider/int8",
    )
    assert all(route.zdr_eligible for route in forward.models[0].routes)
    assert forward.models == reversed_snapshot.models
    assert forward.semantic_sha256 == reversed_snapshot.semantic_sha256


def test_ambiguous_frozen_route_alias_blocks_without_rejecting_distinct_routes() -> None:
    registry = _registry()
    first = _dual_identity_endpoint(
        tag=ENDPOINT,
        slug="approved-provider/route-a",
        provider_name="Provider A",
    )
    second = _dual_identity_endpoint(
        tag=ENDPOINT,
        slug="approved-provider/route-b",
        provider_name="Provider B",
    )
    current = _snapshot(
        registry,
        zdr_endpoints=[first, second],
        candidate_endpoints={MODEL: [first, second]},
    )

    assert tuple(route.provider_endpoint for route in current.models[0].routes) == (
        "approved-provider/route-a",
        "approved-provider/route-b",
    )
    diff = diff_model_refresh(
        current=current,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )
    assert diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    assert diff.production_block_reasons == (f"{MODEL}={ENDPOINT}",)


def test_zdr_credit_requires_full_identity_and_unambiguous_route_alias() -> None:
    registry = _registry()
    endpoint = _dual_identity_endpoint(
        tag=ENDPOINT,
        slug="approved-provider/route-a",
        provider_name="Approved Provider",
    )
    alias_collision = _dual_identity_endpoint(
        tag="other-provider",
        slug=ENDPOINT,
        provider_name="Other Provider",
    )
    snapshot = _snapshot(
        registry,
        zdr_endpoints=[endpoint, alias_collision],
        candidate_endpoints={MODEL: [endpoint]},
    )

    route = snapshot.models[0].routes[0]
    assert route.provider_endpoint == ENDPOINT
    assert route.zdr_eligible is False


def test_duplicate_provider_name_makes_selected_route_non_routable() -> None:
    registry = _registry()
    selected = _dual_identity_endpoint(
        tag=ENDPOINT,
        slug="approved-provider/route-a",
        provider_name="Approved Provider",
    )
    sibling = _dual_identity_endpoint(
        tag="secondary-provider",
        slug="approved-provider/route-b",
        provider_name="Approved Provider",
    )
    current = _snapshot(
        registry,
        zdr_endpoints=[selected, sibling],
        candidate_endpoints={MODEL: [selected, sibling]},
    )

    route = next(route for route in current.models[0].routes if route.provider_endpoint == ENDPOINT)
    assert route.routing_identity_unambiguous is False
    assert route.discovery_eligible is False
    diff = diff_model_refresh(
        current=current,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )
    assert diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED


def test_route_inventory_without_unique_real_selector_fails_closed() -> None:
    registry = _registry()
    first = _dual_identity_endpoint(
        tag="provider-a",
        slug="provider-b",
        provider_name="Provider A",
    )
    second = _dual_identity_endpoint(
        tag="provider-b",
        slug="provider-a",
        provider_name="Provider B",
    )

    with pytest.raises(ModelRefreshValidationError, match="uniquely addressable"):
        _snapshot(
            registry,
            zdr_endpoints=[first, second],
            candidate_endpoints={MODEL: [first, second]},
        )


def test_equal_tag_and_slug_is_one_valid_route_selector() -> None:
    registry = _registry()
    endpoint = _dual_identity_endpoint(
        tag=ENDPOINT,
        slug=ENDPOINT,
        provider_name="Approved Provider",
    )

    snapshot = _snapshot(
        registry,
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )

    route = snapshot.models[0].routes[0]
    assert route.provider_endpoint == ENDPOINT
    assert route.routing_identity_unambiguous
    assert route.zdr_eligible


@pytest.mark.parametrize(
    "mutation",
    (
        "duplicate_full_identity",
        "ambiguous_selected_alias",
        "forged_provider_name_uniqueness",
    ),
)
def test_resealed_catalog_cannot_forge_route_identity_invariants(mutation: str) -> None:
    registry = _registry()
    first = _dual_identity_endpoint(
        tag="shared-provider",
        slug=ENDPOINT,
        provider_name="Approved Provider",
    )
    second = _dual_identity_endpoint(
        tag="shared-provider",
        slug="approved-provider/int8",
        provider_name="Secondary Provider",
    )
    payload = (
        _snapshot(
            registry,
            zdr_endpoints=[first, second],
            candidate_endpoints={MODEL: [first, second]},
        )
        .models[0]
        .model_dump(mode="json")
    )
    first_route, second_route = payload["routes"]

    if mutation == "duplicate_full_identity":
        second_route["endpoint_tag"] = first_route["endpoint_tag"]
        second_route["endpoint_slug"] = first_route["endpoint_slug"]
        second_route["provider_endpoint"] = "shared-provider"
    elif mutation == "ambiguous_selected_alias":
        second_route["provider_endpoint"] = "shared-provider"
    else:
        second_route["provider_name"] = first_route["provider_name"].swapcase()

    with pytest.raises(ValidationError, match=r"route|identity"):
        CatalogModelState.model_validate(_reseal_catalog_model(payload))


@pytest.mark.parametrize("mutation", ("prompt_source", "effective_output_mode"))
def test_resealed_catalog_cannot_forge_capability_invariants(mutation: str) -> None:
    payload = _snapshot(_registry()).models[0].model_dump(mode="json")
    route = payload["routes"][0]
    if mutation == "prompt_source":
        route["max_prompt_tokens"] = 99_999
        route["max_prompt_tokens_source"] = "context_limit"
    else:
        route["supported_output_modes"] = ["VALIDATED_TEXT_JSON"]
        route["structured_output_mode"] = "VALIDATED_TEXT_JSON"

    with pytest.raises(ValidationError, match=r"prompt|output mode"):
        CatalogModelState.model_validate(_reseal_catalog_model(payload))


def test_diff_after_state_cannot_be_resealed_from_hash_only_baseline() -> None:
    registry = _registry()
    offline = _endpoint(status="offline")
    snapshot = _snapshot(
        registry,
        zdr_endpoints=[offline],
        candidate_endpoints={MODEL: [offline]},
    )
    diff = diff_model_refresh(
        current=snapshot,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
    )
    payload = diff.model_dump(mode="json")
    assert payload["changes"][0]["before"] is not None
    payload["changes"][0]["after"] = payload["changes"][0]["before"]
    payload["changes"][0]["record_sha256"] = _sha(
        {key: value for key, value in payload["changes"][0].items() if key != "record_sha256"}
    )
    payload["diff_sha256"] = _sha(
        {key: value for key, value in payload.items() if key != "diff_sha256"}
    )

    with pytest.raises(ValidationError, match=r"EXACT|pricing|max_prompt_tokens"):
        type(diff).model_validate(payload)


def test_refresh_v1_snapshot_and_diff_versions_are_explicitly_rejected() -> None:
    registry = _registry()
    source = _source(registry)
    snapshot = build_model_refresh_snapshot_from_source(
        source_evidence=source,
        candidate_registry=registry,
    )
    snapshot_payload = snapshot.model_dump(mode="json")
    snapshot_payload["schema_version"] = "1.0"
    with pytest.raises(ValidationError, match=r"2\.0"):
        type(snapshot).model_validate(snapshot_payload)

    diff = diff_model_refresh(
        current=snapshot,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
    )
    diff_payload = diff.model_dump(mode="json")
    diff_payload["schema_version"] = "1.0"
    with pytest.raises(ValidationError, match=r"2\.0"):
        type(diff).model_validate(diff_payload)


def test_full_zdr_inventory_ignores_hash_bound_router_aliases() -> None:
    registry = _registry()
    routed_model = "openrouter/auto"
    routed_endpoint = _endpoint(routed_model, "openrouter/router")
    latest_router = "~openrouter/family-latest"
    latest_endpoint = _endpoint(latest_router, "openrouter/latest-router")

    source = _source(
        registry,
        models=[_model(), _model(routed_model), _model(latest_router)],
        zdr_endpoints=[_endpoint(), routed_endpoint, latest_endpoint],
    )
    snapshot = build_model_refresh_snapshot_from_source(
        source_evidence=source,
        candidate_registry=registry,
    )

    assert snapshot.catalog_model_count == 3
    assert snapshot.excluded_routed_model_ids == (routed_model, latest_router)
    assert tuple(model.exact_model_id for model in snapshot.models) == (MODEL,)
    assert tuple(
        (item.model_id, item.occurrence_count) for item in source.excluded_zdr_routed_models
    ) == ((routed_model, 1), (latest_router, 1))


def test_source_evidence_is_allowlisted_order_invariant_and_replayable() -> None:
    second_model = "bravo/borealis-secure"
    registry = _registry(model_ids=(MODEL, second_model))
    first_model = _model()
    second_catalog = _model(second_model)
    first_endpoint = _endpoint()
    second_endpoint = _endpoint(second_model, "provider-1/fp8")
    canary = "synthetic-unknown-provider-field"
    first_model["description"] = canary
    first_model["top_provider"]["ignored"] = canary
    first_endpoint["ignored"] = canary
    endpoints = {
        MODEL: [first_endpoint],
        second_model: [second_endpoint],
    }

    forward = _source(
        registry,
        models=[first_model, second_catalog],
        zdr_endpoints=[first_endpoint, second_endpoint],
        candidate_endpoints=endpoints,
    )
    reverse = _source(
        registry,
        models=[second_catalog, first_model],
        zdr_endpoints=[second_endpoint, first_endpoint],
        candidate_endpoints=dict(reversed(tuple(endpoints.items()))),
    )
    snapshot = build_model_refresh_snapshot_from_source(
        source_evidence=forward,
        candidate_registry=registry,
    )

    assert forward == reverse
    assert canary not in json.dumps(forward.model_dump(mode="json"), sort_keys=True)
    assert snapshot.source_evidence_sha256 == forward.source_evidence_sha256
    assert snapshot.catalog_snapshot_sha256 == forward.catalog_projection_sha256
    assert snapshot.zdr_snapshot_sha256 == forward.zdr_projection_sha256


def test_source_evidence_preserves_nullable_limit_provenance_and_rejects_reseal() -> None:
    registry = _registry(output_limit=100_000)
    endpoint = _endpoint(output=100_000)
    endpoint["max_prompt_tokens"] = None
    endpoint["max_completion_tokens"] = None
    source = _source(
        registry,
        models=[_model(output=100_000)],
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )
    snapshot = build_model_refresh_snapshot_from_source(
        source_evidence=source,
        candidate_registry=registry,
    )

    assert source.zdr_endpoints[0].max_prompt_tokens is None
    assert source.zdr_endpoints[0].max_completion_tokens is None
    route = snapshot.models[0].routes[0]
    assert route.max_prompt_tokens_source == "context_limit"
    assert route.output_limit_source == "context_limit"

    payload = source.model_dump(mode="json")
    payload["catalog_models"][0]["catalog_context_length"] -= 1
    payload["source_evidence_sha256"] = _sha(
        {key: value for key, value in payload.items() if key != "source_evidence_sha256"}
    )
    with pytest.raises(ValidationError, match="projection hash"):
        type(source).model_validate(payload)


def test_semantic_snapshot_and_diff_are_order_and_time_invariant() -> None:
    second_model = "bravo/borealis-secure"
    registry = _registry(model_ids=(MODEL, second_model))
    first_endpoint = _endpoint()
    second_endpoint = _endpoint(
        second_model,
        "provider-1/fp8",
    )
    endpoints = {
        MODEL: [first_endpoint],
        second_model: [second_endpoint],
    }
    first = _snapshot(
        registry,
        models=[_model(), _model(second_model)],
        zdr_endpoints=[first_endpoint, second_endpoint],
        candidate_endpoints=endpoints,
    )
    second = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=1),
        models=[_model(second_model), _model()],
        zdr_endpoints=[second_endpoint, first_endpoint],
        candidate_endpoints=dict(reversed(tuple(endpoints.items()))),
    )

    assert first.semantic_sha256 == second.semantic_sha256
    assert first.snapshot_sha256 != second.snapshot_sha256
    diff = diff_model_refresh(
        current=second,
        previous=first,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW + timedelta(hours=1),
    )
    assert diff.status is ModelRefreshAttemptStatus.UNCHANGED
    assert diff.semantic_unchanged
    assert diff.changes == ()


def test_diff_classifies_every_required_drift_with_exact_states() -> None:
    withdrawn = "bravo/borealis-secure"
    new_model = "charlie/cirrus-secure"
    registry = _registry(model_ids=(MODEL, withdrawn))
    old_endpoint = _endpoint()
    withdrawn_endpoint = _endpoint(withdrawn, "provider-1/fp8")
    previous = _snapshot(
        registry,
        models=[_model(), _model(withdrawn)],
        zdr_endpoints=[old_endpoint, withdrawn_endpoint],
        candidate_endpoints={
            MODEL: [old_endpoint],
            withdrawn: [withdrawn_endpoint],
        },
    )
    changed_endpoint = _endpoint(
        MODEL,
        "replacement-provider/fp8",
        pricing={"completion": "0.000004", "prompt": "0.000003"},
        context=80_000,
        output=4_096,
        parameters=["max_tokens", "temperature"],
    )
    new_endpoint = _endpoint(
        new_model,
        "new-provider/fp8",
    )
    current = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=1),
        models=[
            _model(
                context=80_000,
                output=4_096,
                parameters=["max_tokens", "temperature"],
            ),
            _model(new_model),
        ],
        zdr_endpoints=[new_endpoint],
        candidate_endpoints={
            MODEL: [changed_endpoint],
            withdrawn: [],
        },
    )

    diff = diff_model_refresh(
        current=current,
        previous=previous,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW + timedelta(hours=1),
    )
    by_model = {record.exact_model_id: record for record in diff.changes}
    changed = by_model[MODEL]
    assert changed.before is not None
    assert changed.after is not None
    assert changed.before.context_limit == 100_000
    assert changed.after.context_limit == 80_000
    assert changed.before.routes[0].pricing == BASE_PRICING
    assert changed.after.routes[0].pricing == {
        "completion": "0.000004",
        "prompt": "0.000003",
    }
    assert set(changed.change_kinds) == {
        ModelDriftKind.CONTEXT_LIMIT_CHANGED,
        ModelDriftKind.ENDPOINT_AVAILABILITY_CHANGED,
        ModelDriftKind.OUTPUT_LIMIT_CHANGED,
        ModelDriftKind.REASONING_SUPPORT_CHANGED,
        ModelDriftKind.STRUCTURED_OUTPUT_SUPPORT_CHANGED,
    }
    assert by_model[withdrawn].change_kinds == (ModelDriftKind.WITHDRAWN_MODEL,)
    assert set(by_model[new_model].change_kinds) == {
        ModelDriftKind.LINEAGE_REVIEW_REQUIRED,
        ModelDriftKind.NEW_ELIGIBLE_MODEL,
    }
    assert by_model[new_model].lineage_review_required


def test_zdr_and_pricing_drift_are_distinct_and_exact() -> None:
    registry = _registry()
    previous = _snapshot(registry)
    repriced = _endpoint(pricing={"completion": "0.000003", "prompt": "0.000002"})
    current = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=1),
        zdr_endpoints=[],
        candidate_endpoints={MODEL: [repriced]},
    )

    diff = diff_model_refresh(
        current=current,
        previous=previous,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW + timedelta(hours=1),
    )
    record = diff.changes[0]
    assert set(record.change_kinds) == {
        ModelDriftKind.PRICING_CHANGED,
        ModelDriftKind.ZDR_ELIGIBILITY_CHANGED,
    }
    assert record.pricing_comparison is PricingComparisonState.EVALUATED
    assert record.before is not None and record.after is not None
    assert record.before.routes[0].zdr_eligible is True
    assert record.after.routes[0].zdr_eligible is False


def test_exact_endpoint_withdrawal_overrides_stale_zdr_inventory_and_blocks() -> None:
    registry = _registry()
    previous = _snapshot(registry)
    current = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=1),
        zdr_endpoints=[_endpoint()],
        candidate_endpoints={MODEL: []},
    )

    assert current.models[0].routes == ()
    diff = diff_model_refresh(
        current=current,
        previous=previous,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW + timedelta(hours=1),
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )

    assert diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    assert diff.changes[0].production_blocking
    assert ModelDriftKind.ENDPOINT_AVAILABILITY_CHANGED in diff.changes[0].change_kinds


@pytest.mark.parametrize(
    "zdr_mutation",
    [
        {"provider_name": "Mismatched Provider"},
        {"tag": ENDPOINT, "slug": "approved-provider/stale-secondary"},
    ],
)
def test_mismatched_zdr_counterpart_cannot_confer_selected_route_eligibility(
    zdr_mutation: dict[str, Any],
) -> None:
    registry = _registry()
    previous = _snapshot(registry)
    endpoint = _endpoint()
    zdr_endpoint = {**endpoint, **zdr_mutation}
    current = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=1),
        zdr_endpoints=[zdr_endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )

    assert current.models[0].routes[0].zdr_eligible is False
    diff = diff_model_refresh(
        current=current,
        previous=previous,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW + timedelta(hours=1),
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )
    assert diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    assert ModelDriftKind.ZDR_ELIGIBILITY_CHANGED in diff.changes[0].change_kinds


def test_selected_route_endpoint_identity_drift_blocks_against_exact_snapshot() -> None:
    registry = _registry()
    previous_endpoint = {
        **_endpoint(),
        "tag": ENDPOINT,
        "slug": "approved-provider/original-secondary",
    }
    current_endpoint = {
        **_endpoint(),
        "tag": ENDPOINT,
        "slug": "approved-provider/replacement-secondary",
    }
    previous = _snapshot(
        registry,
        zdr_endpoints=[previous_endpoint],
        candidate_endpoints={MODEL: [previous_endpoint]},
    )
    current = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=1),
        zdr_endpoints=[current_endpoint],
        candidate_endpoints={MODEL: [current_endpoint]},
    )

    diff = diff_model_refresh(
        current=current,
        previous=previous,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW + timedelta(hours=1),
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )

    assert diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    assert diff.changes[0].production_blocking
    assert ModelDriftKind.ENDPOINT_IDENTITY_CHANGED in diff.changes[0].change_kinds


def test_selected_route_requires_exact_full_endpoint_identity_baseline() -> None:
    registry = _registry()
    endpoint = {
        **_endpoint(),
        "tag": ENDPOINT,
        "slug": "approved-provider/unbound-secondary",
    }
    current = _snapshot(
        registry,
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )

    diff = diff_model_refresh(
        current=current,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )

    assert diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    assert diff.production_block_reasons == (f"{MODEL}={ENDPOINT}",)
    assert diff.changes[0].production_blocking
    assert ModelDriftKind.ENDPOINT_IDENTITY_UNVERIFIED in diff.changes[0].change_kinds
    assert diff.changes[0].after is not None
    observed = diff.changes[0].after.routes[0]
    assert (observed.endpoint_tag, observed.endpoint_slug) == (
        ENDPOINT,
        "approved-provider/unbound-secondary",
    )


@pytest.mark.parametrize(
    ("parameters", "expected_kind"),
    (
        (
            ["max_tokens", "response_format", "temperature"],
            ModelDriftKind.REASONING_SUPPORT_CHANGED,
        ),
        (
            ["json_schema", "max_tokens", "reasoning", "temperature"],
            ModelDriftKind.STRUCTURED_OUTPUT_SUPPORT_CHANGED,
        ),
    ),
)
def test_selected_route_capability_loss_blocks(
    parameters: list[str],
    expected_kind: ModelDriftKind,
) -> None:
    registry = _registry()
    endpoint = _endpoint(parameters=parameters)
    current = _snapshot(
        registry,
        models=[_model(parameters=parameters)],
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )

    route = current.models[0].routes[0]
    if expected_kind is ModelDriftKind.REASONING_SUPPORT_CHANGED:
        assert route.reasoning_supported is False
    else:
        assert route.structured_output_supported is False
    diff = diff_model_refresh(
        current=current,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )

    assert diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    assert diff.production_block_reasons == (f"{MODEL}={ENDPOINT}",)
    assert expected_kind in diff.changes[0].change_kinds


def test_validated_text_route_remains_discovery_eligible_without_response_format() -> None:
    registry = _registry()
    parameters = ["max_tokens", "temperature"]
    endpoint = _endpoint(parameters=parameters)
    snapshot = _snapshot(
        registry,
        models=[_model(parameters=parameters)],
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )

    route = snapshot.models[0].routes[0]
    assert route.structured_output_supported is False
    assert route.discovery_eligible
    assert snapshot.models[0].eligible_provider_endpoints == (ENDPOINT,)


def test_selected_validated_text_candidate_retains_exact_mode_credit() -> None:
    parameters = ["max_tokens", "reasoning", "temperature"]
    registry = _registry(structured_output_mode=StructuredOutputMode.VALIDATED_TEXT_JSON)
    endpoint = _endpoint(parameters=parameters)
    previous = _snapshot(
        registry,
        models=[_model(parameters=parameters)],
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )
    snapshot = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=1),
        models=[_model(parameters=parameters)],
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )

    diff = diff_model_refresh(
        current=snapshot,
        previous=previous,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW + timedelta(hours=1),
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )

    assert snapshot.models[0].routes[0].structured_output_mode is (
        StructuredOutputMode.VALIDATED_TEXT_JSON
    )
    assert diff.status is ModelRefreshAttemptStatus.UNCHANGED
    assert not diff.production_block_reasons


def test_route_parameter_drift_cannot_be_reported_as_semantically_unchanged() -> None:
    registry = _registry()
    previous = _snapshot(registry)
    parameters = [*PARAMETERS, "seed"]
    endpoint = _endpoint(parameters=parameters)
    current = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=1),
        models=[_model(parameters=parameters)],
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )

    diff = diff_model_refresh(
        current=current,
        previous=previous,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW + timedelta(hours=1),
    )

    assert not diff.semantic_unchanged
    assert diff.changes[0].change_kinds == (ModelDriftKind.ENDPOINT_AVAILABILITY_CHANGED,)


@pytest.mark.parametrize(
    ("context", "output"),
    (
        (99_999, 8_192),
        (100_000, 8_191),
    ),
)
def test_selected_route_capacity_loss_blocks(context: int, output: int) -> None:
    registry = _registry()
    endpoint = _endpoint(context=context, output=output)
    current = _snapshot(
        registry,
        models=[_model(context=context, output=output)],
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )

    diff = diff_model_refresh(
        current=current,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )

    assert diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    assert diff.production_block_reasons == (f"{MODEL}={ENDPOINT}",)


def test_selected_route_prompt_capacity_loss_blocks_and_is_classified() -> None:
    registry = _registry()
    endpoint = _endpoint()
    endpoint["max_prompt_tokens"] = 1
    current = _snapshot(
        registry,
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )

    diff = diff_model_refresh(
        current=current,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )

    assert current.models[0].routes[0].max_prompt_tokens == 1
    assert diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    assert ModelDriftKind.CONTEXT_LIMIT_CHANGED in diff.changes[0].change_kinds


def test_exact_prompt_limit_source_drift_is_not_semantically_unchanged() -> None:
    registry = _registry()
    fallback = _endpoint()
    fallback["max_prompt_tokens"] = None
    previous = _snapshot(
        registry,
        zdr_endpoints=[fallback],
        candidate_endpoints={MODEL: [fallback]},
    )
    explicit = _endpoint()
    explicit["max_prompt_tokens"] = 100_000
    current = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=1),
        zdr_endpoints=[explicit],
        candidate_endpoints={MODEL: [explicit]},
    )

    diff = diff_model_refresh(
        current=current,
        previous=previous,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW + timedelta(hours=1),
    )

    assert previous.models[0].routes[0].max_prompt_tokens == 100_000
    assert current.models[0].routes[0].max_prompt_tokens == 100_000
    assert not diff.semantic_unchanged
    assert ModelDriftKind.CONTEXT_LIMIT_CHANGED in diff.changes[0].change_kinds


def test_exact_output_limit_source_drift_is_not_semantically_unchanged() -> None:
    registry = _registry(output_limit=100_000)
    fallback = _endpoint(output=100_000)
    fallback["max_prompt_tokens"] = 100_000
    fallback["max_completion_tokens"] = None
    previous = _snapshot(
        registry,
        models=[_model(output=100_000)],
        zdr_endpoints=[fallback],
        candidate_endpoints={MODEL: [fallback]},
    )
    explicit = _endpoint(output=100_000)
    explicit["max_prompt_tokens"] = 100_000
    current = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=1),
        models=[_model(output=100_000)],
        zdr_endpoints=[explicit],
        candidate_endpoints={MODEL: [explicit]},
    )

    diff = diff_model_refresh(
        current=current,
        previous=previous,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW + timedelta(hours=1),
    )

    assert previous.models[0].routes[0].output_limit == 100_000
    assert current.models[0].routes[0].output_limit == 100_000
    assert not diff.semantic_unchanged
    assert ModelDriftKind.OUTPUT_LIMIT_CHANGED in diff.changes[0].change_kinds


@pytest.mark.parametrize(
    ("limit_kind", "expected_kind"),
    (
        ("prompt", ModelDriftKind.CONTEXT_LIMIT_CHANGED),
        ("output", ModelDriftKind.OUTPUT_LIMIT_CHANGED),
    ),
)
def test_selected_candidate_limit_source_drift_blocks(
    limit_kind: str,
    expected_kind: ModelDriftKind,
) -> None:
    registry = (
        _registry(max_prompt_tokens=100_000, max_prompt_tokens_source="context_limit")
        if limit_kind == "prompt"
        else _registry(output_limit=100_000)
    )
    endpoint = _endpoint(output=100_000) if limit_kind == "output" else _endpoint()
    if limit_kind == "prompt":
        endpoint["max_prompt_tokens"] = 100_000
    else:
        endpoint["max_prompt_tokens"] = 100_000
        endpoint["max_completion_tokens"] = None
    current = _snapshot(
        registry,
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )

    unselected = diff_model_refresh(
        current=current,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
    )
    diff = diff_model_refresh(
        current=current,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )

    assert unselected.status is ModelRefreshAttemptStatus.CHANGED
    assert not unselected.production_block_reasons
    assert diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    assert expected_kind in diff.changes[0].change_kinds


def test_selected_legacy_candidate_without_exact_capability_facts_blocks() -> None:
    registry = _registry(structured_output_mode=None)
    current = _snapshot(registry)

    unselected = diff_model_refresh(
        current=current,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
    )
    selected = diff_model_refresh(
        current=current,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )

    assert unselected.status is not ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    before = selected.changes[0].before
    assert before is not None
    assert before.routes[0].max_prompt_tokens is None
    assert before.routes[0].structured_output_mode is None
    assert selected.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED


def test_selected_native_mode_downgrade_blocks_while_json_upgrade_does_not() -> None:
    native_parameters = [*PARAMETERS, "json_schema"]
    json_endpoint = _endpoint()
    native_endpoint = _endpoint(parameters=native_parameters)

    native_registry = _registry(structured_output_mode=StructuredOutputMode.NATIVE_JSON_SCHEMA)
    downgraded = _snapshot(
        native_registry,
        zdr_endpoints=[json_endpoint],
        candidate_endpoints={MODEL: [json_endpoint]},
    )
    downgrade_diff = diff_model_refresh(
        current=downgraded,
        candidate_registry=native_registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )

    json_registry = _registry(structured_output_mode=StructuredOutputMode.JSON_OBJECT)
    upgraded = _snapshot(
        json_registry,
        retrieved_at=NOW + timedelta(hours=1),
        models=[_model(parameters=native_parameters)],
        zdr_endpoints=[native_endpoint],
        candidate_endpoints={MODEL: [native_endpoint]},
    )
    json_previous = _snapshot(json_registry)
    upgrade_diff = diff_model_refresh(
        current=upgraded,
        previous=json_previous,
        candidate_registry=json_registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW + timedelta(hours=1),
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )

    assert downgrade_diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    assert (
        ModelDriftKind.STRUCTURED_OUTPUT_SUPPORT_CHANGED in downgrade_diff.changes[0].change_kinds
    )
    assert upgrade_diff.status is ModelRefreshAttemptStatus.CHANGED
    assert not upgrade_diff.production_block_reasons


def test_hash_only_native_baseline_does_not_claim_marker_specific_drift() -> None:
    registry = _registry(structured_output_mode=StructuredOutputMode.NATIVE_JSON_SCHEMA)
    parameters = [*PARAMETERS, "structured_outputs"]
    endpoint = _endpoint(parameters=parameters)
    current = _snapshot(
        registry,
        models=[_model(parameters=parameters)],
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )

    diff = diff_model_refresh(
        current=current,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )

    assert current.models[0].routes[0].structured_output_mode is (
        StructuredOutputMode.NATIVE_JSON_SCHEMA
    )
    assert diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    assert diff.production_block_reasons == (f"{MODEL}={ENDPOINT}",)
    assert diff.changes[0].change_kinds == (ModelDriftKind.ENDPOINT_IDENTITY_UNVERIFIED,)


def test_route_output_mode_is_the_model_and_endpoint_intersection() -> None:
    registry = _registry(structured_output_mode=StructuredOutputMode.NATIVE_JSON_SCHEMA)
    endpoint = _endpoint(parameters=[*PARAMETERS, "json_schema"])
    current = _snapshot(
        registry,
        models=[_model(parameters=PARAMETERS)],
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )

    route = current.models[0].routes[0]
    assert route.structured_output_mode is StructuredOutputMode.JSON_OBJECT
    assert StructuredOutputMode.NATIVE_JSON_SCHEMA not in route.supported_output_modes
    diff = diff_model_refresh(
        current=current,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )
    assert diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED


def test_hash_only_baseline_does_not_claim_unknown_catalog_capacity_drift() -> None:
    registry = _registry()
    model = _model(context=99_999, output=8_191)
    model["top_provider"]["context_length"] = 100_000
    endpoint = _endpoint()
    current = _snapshot(
        registry,
        models=[model],
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )

    diff = diff_model_refresh(
        current=current,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )

    assert current.models[0].catalog_context_limit == 99_999
    assert current.models[0].context_limit == 100_000
    assert current.models[0].routes[0].context_limit == 100_000
    assert diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    assert diff.production_block_reasons == (f"{MODEL}={ENDPOINT}",)
    assert diff.changes[0].change_kinds == (ModelDriftKind.ENDPOINT_IDENTITY_UNVERIFIED,)


def test_exact_previous_snapshot_detects_catalog_capacity_drift() -> None:
    registry = _registry()
    previous = _snapshot(registry)
    model = _model(context=99_999, output=8_191)
    model["top_provider"]["context_length"] = 100_000
    endpoint = _endpoint()
    current = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=1),
        models=[model],
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )

    diff = diff_model_refresh(
        current=current,
        previous=previous,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW + timedelta(hours=1),
    )

    assert diff.status is ModelRefreshAttemptStatus.CHANGED
    assert ModelDriftKind.CONTEXT_LIMIT_CHANGED in diff.changes[0].change_kinds
    assert ModelDriftKind.OUTPUT_LIMIT_CHANGED in diff.changes[0].change_kinds


def test_selected_model_withdrawal_cannot_degrade_to_changed_only() -> None:
    replacement_model = "bravo/borealis-secure"
    replacement_endpoint = _endpoint(replacement_model, "replacement-provider/fp8")
    registry = _registry()
    current = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=1),
        models=[_model(replacement_model)],
        zdr_endpoints=[replacement_endpoint],
        candidate_endpoints={MODEL: []},
    )

    diff = diff_model_refresh(
        current=current,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW + timedelta(hours=1),
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )

    assert diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    assert diff.production_block_reasons == (f"{MODEL}={ENDPOINT}",)
    selected_record = next(record for record in diff.changes if record.exact_model_id == MODEL)
    assert selected_record.production_blocking
    assert ModelDriftKind.WITHDRAWN_MODEL in selected_record.change_kinds


@pytest.mark.parametrize(
    ("mutation", "expected_kind"),
    [
        ({"status": "offline"}, ModelDriftKind.ENDPOINT_AVAILABILITY_CHANGED),
        (
            {"supported_parameters": ["reasoning", "response_format"]},
            ModelDriftKind.ENDPOINT_AVAILABILITY_CHANGED,
        ),
        ({"provider_name": "Replacement Provider"}, ModelDriftKind.ENDPOINT_AVAILABILITY_CHANGED),
    ],
)
def test_selected_route_semantic_loss_never_becomes_unchanged(
    mutation: dict[str, Any],
    expected_kind: ModelDriftKind,
) -> None:
    registry = _registry()
    previous = _snapshot(registry)
    changed = {**_endpoint(), **mutation}
    current = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=1),
        zdr_endpoints=[changed],
        candidate_endpoints={MODEL: [changed]},
    )

    diff = diff_model_refresh(
        current=current,
        previous=previous,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW + timedelta(hours=1),
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )

    assert diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    assert diff.changes[0].production_blocking
    assert expected_kind in diff.changes[0].change_kinds


def test_selected_route_must_match_the_frozen_candidate_registry() -> None:
    registry = _registry()
    snapshot = _snapshot(registry)

    with pytest.raises(ModelRefreshValidationError, match="frozen candidate registry"):
        diff_model_refresh(
            current=snapshot,
            candidate_registry=registry,
            pricing_tolerance_fraction="0.05",
            compared_at=NOW,
            selected_routes=(
                SelectedModelRoute(
                    exact_model_id=MODEL,
                    provider_endpoint="unapproved-provider/fp8",
                ),
            ),
        )


def test_diff_rejects_inverted_snapshot_chronology() -> None:
    registry = _registry()
    current = _snapshot(registry)
    future_previous = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=1),
    )

    with pytest.raises(ModelRefreshValidationError, match="newer than the current snapshot"):
        diff_model_refresh(
            current=current,
            previous=future_previous,
            candidate_registry=registry,
            pricing_tolerance_fraction="0.05",
            compared_at=NOW,
        )


def test_diff_requires_comparison_time_to_match_current_snapshot() -> None:
    registry = _registry()
    current = _snapshot(registry)

    with pytest.raises(ModelRefreshValidationError, match="must equal the current snapshot"):
        diff_model_refresh(
            current=current,
            candidate_registry=registry,
            pricing_tolerance_fraction="0.05",
            compared_at=NOW + timedelta(seconds=1),
        )


def test_hash_only_bootstrap_never_fabricates_prior_prices_and_blocks_selection() -> None:
    registry = _registry()
    current = _snapshot(
        registry,
        candidate_endpoints={
            MODEL: [_endpoint(pricing={"completion": "0.000003", "prompt": "0.000002"})]
        },
        zdr_endpoints=[_endpoint(pricing={"completion": "0.000003", "prompt": "0.000002"})],
    )

    diff = diff_model_refresh(
        current=current,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
        selected_routes=(
            SelectedModelRoute(
                exact_model_id=MODEL,
                provider_endpoint=ENDPOINT,
            ),
        ),
    )
    record = diff.changes[0]
    assert record.before is not None
    assert record.before.routes[0].pricing is None
    assert record.pricing_comparison is PricingComparisonState.NOT_EVALUABLE
    assert ModelDriftKind.PRICING_CHANGED in record.change_kinds
    assert record.production_blocking
    assert diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED


def test_pricing_tolerance_uses_exact_decimal_boundary() -> None:
    base = {"completion": "1", "prompt": "1"}
    registry = _registry(pricing=base)
    previous = _snapshot(
        registry,
        candidate_endpoints={MODEL: [_endpoint(pricing=base)]},
        zdr_endpoints=[_endpoint(pricing=base)],
    )
    selected = (SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),)
    boundary = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=1),
        candidate_endpoints={MODEL: [_endpoint(pricing={"completion": "1.05", "prompt": "1.05"})]},
        zdr_endpoints=[_endpoint(pricing={"completion": "1.05", "prompt": "1.05"})],
    )
    boundary_diff = diff_model_refresh(
        current=boundary,
        previous=previous,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW + timedelta(hours=1),
        selected_routes=selected,
    )
    assert boundary_diff.status is ModelRefreshAttemptStatus.CHANGED
    assert boundary_diff.changes[0].pricing_increase_fields == ()

    repeated = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=2),
        candidate_endpoints={MODEL: [_endpoint(pricing={"completion": "1.05", "prompt": "1.05"})]},
        zdr_endpoints=[_endpoint(pricing={"completion": "1.05", "prompt": "1.05"})],
    )
    repeated_diff = diff_model_refresh(
        current=repeated,
        previous=boundary,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW + timedelta(hours=2),
        selected_routes=selected,
    )
    assert repeated_diff.semantic_unchanged
    assert repeated_diff.changes == ()
    assert repeated_diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    assert repeated_diff.production_block_reasons == (f"{MODEL}={ENDPOINT}",)

    beyond = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=3),
        candidate_endpoints={
            MODEL: [_endpoint(pricing={"completion": "1.050000001", "prompt": "1.05"})]
        },
        zdr_endpoints=[_endpoint(pricing={"completion": "1.050000001", "prompt": "1.05"})],
    )
    beyond_diff = diff_model_refresh(
        current=beyond,
        previous=previous,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW + timedelta(hours=3),
        selected_routes=selected,
    )
    assert beyond_diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    assert beyond_diff.changes[0].pricing_increase_fields == (f"{ENDPOINT}:completion",)


def test_canonical_identity_drift_is_classified_and_blocks_selected_route() -> None:
    registry = _registry()
    previous = _snapshot(registry)
    changed_model = _model()
    changed_model["canonical_slug"] = "alpha/atlas-secure-revision"
    current = _snapshot(
        registry,
        retrieved_at=NOW + timedelta(hours=1),
        models=[changed_model],
    )

    diff = diff_model_refresh(
        current=current,
        previous=previous,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW + timedelta(hours=1),
        selected_routes=(SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),),
    )

    assert diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    assert diff.changes[0].production_blocking
    assert ModelDriftKind.MODEL_IDENTITY_CHANGED in diff.changes[0].change_kinds


def test_failure_is_distinct_from_unchanged_and_freshness_blocks_at_hard_age() -> None:
    registry = _registry()
    snapshot = _snapshot(registry)
    diff = diff_model_refresh(
        current=snapshot,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
    )
    unchanged = seal_model_refresh_attempt(
        attempted_at=NOW,
        candidate_registry_sha256=registry.registry_sha256,
        snapshot=snapshot,
        diff=diff,
    )
    failed = seal_model_refresh_attempt(
        attempted_at=NOW,
        candidate_registry_sha256=registry.registry_sha256,
        failure_code=ModelRefreshFailureCode.AUTHENTICATION,
    )

    assert unchanged.status is ModelRefreshAttemptStatus.UNCHANGED
    assert failed.status is ModelRefreshAttemptStatus.FAILED
    assert failed.snapshot_sha256 is None
    assert failed.diff_sha256 is None
    assert failed.attempt_sha256 != unchanged.attempt_sha256

    current = evaluate_model_refresh_freshness(
        observed_at=NOW + timedelta(hours=30),
        snapshot=snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=True,
    )
    stale = evaluate_model_refresh_freshness(
        observed_at=NOW + timedelta(hours=30, seconds=1),
        snapshot=snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=True,
    )
    hard_boundary = evaluate_model_refresh_freshness(
        observed_at=NOW + timedelta(hours=72),
        snapshot=snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=True,
    )
    hard = evaluate_model_refresh_freshness(
        observed_at=NOW + timedelta(hours=72, seconds=1),
        snapshot=snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=True,
    )
    missing = evaluate_model_refresh_freshness(
        observed_at=NOW,
        snapshot=None,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=True,
    )
    assert current.state is ModelRefreshFreshnessState.CURRENT
    assert stale.state is ModelRefreshFreshnessState.STALE
    assert not stale.production_blocked
    assert hard_boundary.state is ModelRefreshFreshnessState.STALE
    assert hard.state is ModelRefreshFreshnessState.HARD_EXPIRED
    assert hard.production_blocked
    assert missing.state is ModelRefreshFreshnessState.NO_SUCCESS
    assert missing.production_blocked


def test_variant_forms_collapse_only_to_review_key_not_lineage_authority() -> None:
    assert model_variant_family_key("alpha/atlas-secure-fast") == MODEL
    assert model_variant_family_key("alpha/atlas-secure:batch") == MODEL
    assert model_variant_family_key(MODEL) == MODEL

    registry = _registry()
    variant = "alpha/atlas-secure-fast"
    variant_endpoint = _endpoint(variant, "variant-provider/fp8")
    current = _snapshot(
        registry,
        models=[_model(), _model(variant)],
        zdr_endpoints=[_endpoint(), variant_endpoint],
    )
    diff = diff_model_refresh(
        current=current,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
    )
    variant_record = next(record for record in diff.changes if record.exact_model_id == variant)
    assert variant_record.lineage_review_required
    assert ModelDriftKind.LINEAGE_REVIEW_REQUIRED in variant_record.change_kinds


def test_artifact_writers_are_private_exact_and_fail_closed_on_tamper(
    tmp_path: Path,
) -> None:
    registry = _registry()
    source = _source(registry)
    snapshot = build_model_refresh_snapshot_from_source(
        source_evidence=source,
        candidate_registry=registry,
    )
    diff = diff_model_refresh(
        current=snapshot,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
    )
    attempt = seal_model_refresh_attempt(
        attempted_at=NOW,
        candidate_registry_sha256=registry.registry_sha256,
        snapshot=snapshot,
        diff=diff,
    )
    freshness = evaluate_model_refresh_freshness(
        observed_at=NOW,
        snapshot=snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=False,
    )
    output = tmp_path / "success"

    write_model_refresh_success(
        output,
        source_evidence=source,
        snapshot=snapshot,
        diff=diff,
        attempt=attempt,
        freshness=freshness,
    )

    assert output.stat().st_mode & 0o777 == 0o700
    assert {path.name for path in output.iterdir()} == {
        SOURCE_EVIDENCE_FILENAME,
        SNAPSHOT_FILENAME,
        DIFF_FILENAME,
        ATTEMPT_FILENAME,
        FRESHNESS_FILENAME,
    }
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in output.iterdir())
    assert load_model_refresh_source_evidence(output / SOURCE_EVIDENCE_FILENAME) == source
    assert load_model_refresh_snapshot(output / SNAPSHOT_FILENAME) == snapshot
    assert load_model_refresh_diff(output / DIFF_FILENAME) == diff
    assert load_model_refresh_attempt(output / ATTEMPT_FILENAME) == attempt
    assert load_model_refresh_freshness(output / FRESHNESS_FILENAME) == freshness
    with pytest.raises(ModelRefreshValidationError, match="fresh"):
        write_model_refresh_success(
            output,
            source_evidence=source,
            snapshot=snapshot,
            diff=diff,
            attempt=attempt,
            freshness=freshness,
        )

    payload = json.loads((output / SNAPSHOT_FILENAME).read_text(encoding="utf-8"))
    payload["semantic_sha256"] = "0" * 64
    (output / SNAPSHOT_FILENAME).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ModelRefreshValidationError, match="strict validation"):
        load_model_refresh_snapshot(output / SNAPSHOT_FILENAME)

    failed = seal_model_refresh_attempt(
        attempted_at=NOW,
        candidate_registry_sha256=registry.registry_sha256,
        failure_code=ModelRefreshFailureCode.NETWORK_TIMEOUT,
    )
    failed_output = tmp_path / "failed"
    write_model_refresh_failure(failed_output, attempt=failed)
    assert [path.name for path in failed_output.iterdir()] == [ATTEMPT_FILENAME]
    assert load_model_refresh_attempt(failed_output / ATTEMPT_FILENAME) == failed

    linked = tmp_path / "linked-attempt.json"
    linked.hardlink_to(failed_output / ATTEMPT_FILENAME)
    with pytest.raises(ModelRefreshValidationError, match="unshared"):
        load_model_refresh_attempt(linked)


def test_success_writer_removes_source_evidence_after_a_later_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _registry()
    source = _source(registry)
    snapshot = build_model_refresh_snapshot_from_source(
        source_evidence=source,
        candidate_registry=registry,
    )
    diff = diff_model_refresh(
        current=snapshot,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
    )
    attempt = seal_model_refresh_attempt(
        attempted_at=NOW,
        candidate_registry_sha256=registry.registry_sha256,
        snapshot=snapshot,
        diff=diff,
    )
    freshness = evaluate_model_refresh_freshness(
        observed_at=NOW,
        snapshot=snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=False,
    )
    original_write = refresh_module._write_private_artifact

    def fail_after_source(path: Path, artifact: Any) -> None:
        if path.name == SNAPSHOT_FILENAME:
            raise OSError("synthetic later-artifact write failure")
        original_write(path, artifact)

    monkeypatch.setattr(refresh_module, "_write_private_artifact", fail_after_source)
    output = tmp_path / "partial-success"
    with pytest.raises(OSError, match="later-artifact"):
        write_model_refresh_success(
            output,
            source_evidence=source,
            snapshot=snapshot,
            diff=diff,
            attempt=attempt,
            freshness=freshness,
        )

    assert not output.exists()


def test_malformed_duplicate_and_tampered_states_fail_closed() -> None:
    registry = _registry()
    with pytest.raises(ModelRefreshValidationError, match="authenticated metadata"):
        build_model_refresh_snapshot(
            retrieved_at=NOW,
            catalog_payload={"data": [_model()]},
            zdr_payload={"data": [_endpoint()]},
            candidate_registry=registry,
            candidate_endpoint_payloads={
                MODEL: _endpoint_envelope(MODEL, _endpoint()),
            },
            authenticated_metadata=False,
        )
    with pytest.raises(ModelRefreshValidationError, match="duplicate model"):
        _snapshot(registry, models=[_model(), _model()])
    with pytest.raises(ModelRefreshValidationError, match="duplicate exact routes"):
        _snapshot(registry, zdr_endpoints=[_endpoint(), _endpoint()])
    duplicate_candidate = _dual_identity_endpoint(
        tag="approved-provider",
        slug=ENDPOINT,
        provider_name="Approved Provider",
    )
    duplicate_candidate_changed = {
        **duplicate_candidate,
        "status": "offline",
    }
    with pytest.raises(ModelRefreshValidationError, match="duplicate exact routes"):
        _snapshot(
            registry,
            zdr_endpoints=[duplicate_candidate],
            candidate_endpoints={
                MODEL: [duplicate_candidate, duplicate_candidate_changed],
            },
        )
    with pytest.raises(ModelRefreshValidationError, match="price"):
        _snapshot(
            registry,
            candidate_endpoints={MODEL: [_endpoint(pricing={"completion": "NaN", "prompt": "1"})]},
            zdr_endpoints=[_endpoint(pricing={"completion": "NaN", "prompt": "1"})],
        )
    mismatched_endpoint = _endpoint_envelope(MODEL, _endpoint())
    mismatched_endpoint["data"]["endpoints"][0]["model_id"] = "bravo/borealis-secure"
    with pytest.raises(ModelRefreshValidationError, match="exact requested model"):
        build_model_refresh_snapshot(
            retrieved_at=NOW,
            catalog_payload={"data": [_model()]},
            zdr_payload={"data": [_endpoint()]},
            candidate_registry=registry,
            candidate_endpoint_payloads={MODEL: mismatched_endpoint},
            authenticated_metadata=True,
        )

    failed = seal_model_refresh_attempt(
        attempted_at=NOW,
        candidate_registry_sha256=registry.registry_sha256,
        failure_code=ModelRefreshFailureCode.MALFORMED_METADATA,
    )
    payload = failed.model_dump(mode="json")
    payload["status"] = ModelRefreshAttemptStatus.UNCHANGED.value
    with pytest.raises(ValidationError, match="successful refresh"):
        ModelRefreshAttempt.model_validate(payload)


def test_committed_candidate_registry_has_hash_only_pricing_baseline() -> None:
    root = Path(__file__).resolve().parents[2]
    registry = load_candidate_registry(root / "config" / "models.candidates.toml")
    endpoint_payloads = {
        candidate.exact_model_id: _endpoint_envelope(
            candidate.exact_model_id,
            _endpoint(
                candidate.exact_model_id,
                candidate.approved_provider_endpoint,
            ),
        )
        for candidate in registry.candidates
    }
    # The assertion is about the immutable input: no exact former prices exist.
    assert registry.candidates
    assert all(candidate.pricing_snapshot_sha256 for candidate in registry.candidates)
    assert all(
        "pricing" not in candidate.model_dump(mode="json") for candidate in registry.candidates
    )
    assert len(endpoint_payloads) == len(registry.candidates)
