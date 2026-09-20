"""Local exact-price and request-envelope regressions; no provider execution."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal, localcontext
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.route_constraints import (
    ExactRoutePriceTier,
    ExactRoutePricingSchedule,
    ProviderPriceCapAlgorithm,
    RouteConstraintError,
    normalize_exact_route_pricing,
    project_provider_price_cap,
)
from mmaudit.models.route_cost_reservations import (
    ExactRouteCostReservation,
    ReservationRateBasis,
    RouteCostReservationError,
    RouteCostReservationPolicy,
    project_route_reservation_provider_caps,
    project_route_reserved_rates,
    require_route_cost_reservation_request,
)
from mmaudit.models.token_planning import EndpointRouteIntersection, RequestTokenPlan
from tests.unit.test_token_planning import _allocations, _plan, _route

FIXTURE = (
    Path(__file__).parents[1] / "fixtures/model_responses/operator_cost_reservation_request.json"
)
BINDINGS = {
    "selection_plan_sha256": "1" * 64,
    "route_predicate_profile_sha256": "2" * 64,
    "route_constraint_sha256": "3" * 64,
    "endpoint_snapshot_sha256": "a" * 64,
}


@pytest.mark.parametrize("precision", (3, 28, 160))
def test_pure_reserved_rate_projection_matches_request_without_inventing_units(
    precision: int,
) -> None:
    inputs = _inputs()
    reservation = ExactRouteCostReservation.build(**inputs)
    with localcontext() as context:
        context.prec = precision
        rates = project_route_reserved_rates(
            policy=reservation.policy,
            pricing=reservation.exact_pricing,
            schedule=reservation.pricing_schedule,
        )
    assert [rate.model_dump(mode="json") for rate in rates] == [
        component.model_dump(mode="json", exclude={"maximum_units"})
        for component in reservation.components
    ]
    assert all("maximum_units" not in rate.model_dump() for rate in rates)
    assert all("request_token_plan" not in rate.model_dump() for rate in rates)


PRICES = {
    "completion": "0.00001",
    "prompt": "0.000001",
    "input_cache_read": "0.0000001",
    "input_cache_write": "0.000002",
    "internal_reasoning": "0.00001",
    "image": "0.1",
    "web_search": "0.01",
    "request": "0.001",
}


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _inputs(
    *,
    pricing: dict[str, str] | None = None,
    schedule: ExactRoutePricingSchedule | None = None,
    request_id: str = "synthetic-request",
    policy: RouteCostReservationPolicy | None = None,
    plan: RequestTokenPlan | None = None,
) -> dict[str, Any]:
    prices = dict(PRICES if pricing is None else pricing)
    exact = normalize_exact_route_pricing(prices)
    caps = project_route_reservation_provider_caps(exact, schedule=schedule)
    current = plan or _plan(
        request_id=request_id,
        role="source_audit",
        route_intersection=EndpointRouteIntersection.build(
            (_route(model="fixture/synthetic-model", endpoint="synthetic-provider"),)
        ),
        allocations=_allocations(source_tokens=1, non_source_tokens_each=1),
        required_output_tokens=4096,
        reserved_reasoning_tokens=4096,
        unknown_completion_accounting=True,
    )
    body = json.loads(FIXTURE.read_text())
    body["max_tokens"] = current.wire_max_tokens or current.requested_completion_tokens
    body["provider"]["max_price"] = {item.component.value: item.value for item in caps}
    return {
        "policy": policy or RouteCostReservationPolicy.build(),
        **BINDINGS,
        "request_material": _canonical(body),
        "request_token_plan": current,
        "pricing": prices,
        "pricing_schedule": schedule,
    }


def _reseal(payload: dict[str, Any], field: str = "reservation_sha256") -> str:
    payload[field] = hashlib.sha256(
        _canonical({key: value for key, value in payload.items() if key != field}).encode()
    ).hexdigest()
    return _canonical(payload)


def test_complete_reservation_is_distinct_from_a_provider_guarantee() -> None:
    inputs = _inputs()
    reservation = ExactRouteCostReservation.build(**inputs)
    assert reservation.policy.operator_decision_id == "OP-COST-2026-09-09"
    assert reservation.policy.provider_enforced_total_ceiling is False
    assert reservation.status == "NONAUTHORIZING_COST_RESERVATION"
    assert set(item.component.value for item in reservation.components) == set(PRICES)
    assert set(item.component.value for item in reservation.provider_capped_subset) == {
        "prompt",
        "completion",
        "image",
        "request",
    }
    assert (
        "expressible" not in reservation.model_dump()
        and "no_weaker" not in reservation.model_dump()
    )
    components = {item.component.value: item for item in reservation.components}
    assert components["input_cache_write"].rate_basis is ReservationRateBasis.OPERATOR_RESERVED
    assert components["input_cache_write"].reserved_unit_price_usd_exact == "0.000004"
    assert components["input_cache_read"].reserved_unit_price_usd_exact == "0.000002"
    assert components["internal_reasoning"].maximum_units == 64_000
    assert components["image"].maximum_units == components["web_search"].maximum_units == 0
    assert components["request"].maximum_units == 1
    assert components["prompt"].maximum_units == len(inputs["request_material"].encode())
    total = sum(
        (
            Decimal(item.reserved_unit_price_usd_exact) * item.maximum_units
            for item in reservation.components
        ),
        Decimal(0),
    )
    assert Decimal(reservation.reserved_cost_usd_exact) >= total
    assert (
        require_route_cost_reservation_request(
            reservation, request_material=inputs["request_material"], **BINDINGS
        )
        == reservation
    )
    assert (
        ExactRouteCostReservation.model_validate_json(reservation.model_dump_json()) == reservation
    )
    assert "non-deployable" not in reservation.model_dump_json()


@pytest.mark.parametrize(
    "algorithm",
    (
        ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1,
        ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2,
    ),
)
def test_existing_provider_cap_algorithms_still_refuse_uncappable_prices(
    algorithm: ProviderPriceCapAlgorithm,
) -> None:
    from mmaudit.models.route_constraints import RoutePriceComponentUnitEnvelope

    envelopes = (
        ()
        if algorithm is ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1
        else (RoutePriceComponentUnitEnvelope.build_web_search_disabled(),)
    )
    with pytest.raises(RouteConstraintError):
        project_provider_price_cap(
            normalize_exact_route_pricing(PRICES),
            algorithm=algorithm,
            price_component_unit_envelopes=envelopes,
        )


@pytest.mark.parametrize(
    "value",
    (
        "0",
        "-0",
        "251",
        "250.000000000000000001",
        "0.0000000000000000001",
        "1.0",
        "1e2",
        "NaN",
        "Infinity",
        " 1",
        1,
        True,
        250.0,
    ),
)
def test_policy_refuses_unbounded_or_inexact_money(value: Any) -> None:
    with pytest.raises(ValueError):
        RouteCostReservationPolicy.build(ledger_ceiling_usd_exact=value)


@pytest.mark.parametrize(
    "field",
    (
        "require_actual_billed_cost",
        "unknown_billing_blocks_new_work",
        "reservation_overrun_blocks_new_work",
        "automatic_ceiling_increase",
        "provider_enforced_total_ceiling",
    ),
)
@pytest.mark.parametrize("value", (0, 1, "true"))
def test_policy_flags_never_coerce_boolean_authority(field: str, value: Any) -> None:
    payload = RouteCostReservationPolicy.build().model_dump(mode="json")
    payload[field] = value
    with pytest.raises(ValidationError):
        RouteCostReservationPolicy.model_validate_json(_reseal(payload, "policy_sha256"))


def test_tier_maxima_preserve_complete_base_and_tier_components() -> None:
    pricing = {"prompt": "0.000001", "completion": "0.00001", "input_cache_write": "0"}
    schedule = ExactRoutePricingSchedule.build(
        base_pricing=normalize_exact_route_pricing(pricing),
        tiers=(
            ExactRoutePriceTier.build(
                min_prompt_tokens=0, pricing={"input_cache_write": "0.000003"}
            ),
            ExactRoutePriceTier.build(
                min_prompt_tokens=100_000,
                pricing={"prompt": "0.00002", "input_cache_write": "0.0001"},
            ),
        ),
    )
    reservation = ExactRouteCostReservation.build(**_inputs(pricing=pricing, schedule=schedule))
    components = {item.component.value: item for item in reservation.components}
    assert components["prompt"].maximum_observed_unit_price_usd_exact == "0.00002"
    assert components["input_cache_write"].reserved_unit_price_usd_exact == "0.0002"
    assert len(reservation.exact_pricing) == len(reservation.components) == 3
    assert reservation.pricing_schedule == schedule


def test_tier_without_complete_base_inventory_remains_unavailable() -> None:
    with pytest.raises(RouteConstraintError, match="component absent from base"):
        ExactRoutePricingSchedule.build(
            base_pricing=normalize_exact_route_pricing({"prompt": "0.001", "completion": "0.001"}),
            tiers=(
                ExactRoutePriceTier.build(min_prompt_tokens=0, pricing={"input_cache_write": "0"}),
            ),
        )


@pytest.mark.parametrize(
    "field",
    (
        "selection_plan_sha256",
        "route_predicate_profile_sha256",
        "route_constraint_sha256",
        "endpoint_snapshot_sha256",
    ),
)
def test_caller_owned_binding_mismatch_refuses(field: str) -> None:
    inputs = _inputs()
    reservation = ExactRouteCostReservation.build(**inputs)
    bindings = {**BINDINGS, field: "f" * 64}
    with pytest.raises(RouteCostReservationError, match="selected route bindings"):
        require_route_cost_reservation_request(
            reservation, request_material=inputs["request_material"], **bindings
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "omit",
        "duplicate",
        "reorder",
        "units",
        "rate",
        "basis",
        "cap",
        "total",
        "snapshot",
        "token_plan",
    ),
)
def test_resealed_inconsistent_reservation_refuses(mutation: str) -> None:
    payload = ExactRouteCostReservation.build(**_inputs()).model_dump(mode="json")
    if mutation == "omit":
        payload["components"].pop()
    elif mutation == "duplicate":
        payload["components"][1] = payload["components"][0]
    elif mutation == "reorder":
        payload["components"].reverse()
    elif mutation == "units":
        payload["components"][0]["maximum_units"] = 0
    elif mutation == "rate":
        payload["components"][0]["reserved_unit_price_usd_exact"] = "0"
    elif mutation == "basis":
        payload["components"][0]["rate_basis"] = "OPERATOR_RESERVED_UNCAPPABLE_RATE"
    elif mutation == "cap":
        payload["provider_capped_subset"][0]["value"] = 0.0
    elif mutation == "total":
        payload["reserved_cost_usd_exact"] = "0.0001"
    elif mutation == "snapshot":
        payload["endpoint_snapshot_sha256"] = "f" * 64
    else:
        payload["request_token_plan"]["reserved_reasoning_tokens"] += 1
    with pytest.raises(ValueError):
        ExactRouteCostReservation.model_validate_json(_reseal(payload))


@pytest.mark.parametrize(
    "mutation",
    (
        "image",
        "tools",
        "plugins",
        "search",
        "fallback",
        "route",
        "cap",
        "wire",
        "reasoning",
        "stream",
        "response",
        "metadata",
        "extra",
    ),
)
def test_request_unit_and_route_envelope_refuses_unsupported_features(mutation: str) -> None:
    inputs = _inputs()
    body = json.loads(inputs["request_material"])
    if mutation == "image":
        body["messages"][1]["content"] = [
            {"type": "image_url", "image_url": {"url": "synthetic-only"}}
        ]
    elif mutation in {"tools", "plugins", "search"}:
        body["web_search" if mutation == "search" else mutation] = []
    elif mutation == "fallback":
        body["provider"]["allow_fallbacks"] = True
    elif mutation == "route":
        body["provider"]["only"] = ["different-synthetic-provider"]
    elif mutation == "cap":
        body["provider"]["max_price"]["prompt"] = 0.0
    elif mutation == "wire":
        body["max_tokens"] += 1
    elif mutation == "reasoning":
        body["reasoning"]["exclude"] = True
    elif mutation == "stream":
        body["stream"] = True
    elif mutation == "response":
        body["response_format"]["json_schema"]["strict"] = False
    elif mutation == "metadata":
        body["metadata"] = {"fixture": []}
    else:
        body["future_chargeable_feature"] = True
    inputs["request_material"] = _canonical(body)
    with pytest.raises(RouteCostReservationError):
        ExactRouteCostReservation.build(**inputs)


@pytest.mark.parametrize(
    "material",
    (
        "{}",
        "null",
        "[]",
        '{"a":1,"a":2}',
        '{"a":NaN}',
        '{"a":Infinity}',
        '{"a":1e999}',
        "\ud800",
        "",
    ),
)
def test_invalid_or_noncanonical_request_bytes_refuse(material: str) -> None:
    inputs = _inputs()
    inputs["request_material"] = material
    with pytest.raises(RouteCostReservationError):
        ExactRouteCostReservation.build(**inputs)


@pytest.mark.parametrize(
    "price",
    ("-1", "NaN", "1e-6", "0.0000000000000000000000000000000000001", "1000000000000", 0.01, True),
)
def test_unknown_or_unbounded_prices_are_not_dropped(price: Any) -> None:
    with pytest.raises(ValueError):
        _inputs(pricing={**PRICES, "input_cache_write": price})
    with pytest.raises(ValueError):
        _inputs(pricing={**PRICES, "unknown_cost_dimension": "0"})


def test_decimal_context_does_not_reduce_reservation() -> None:
    inputs = _inputs()
    expected = ExactRouteCostReservation.build(**inputs)
    with localcontext() as context:
        context.prec = 2
        observed = ExactRouteCostReservation.build(**inputs)
    assert observed == expected


def test_any_positive_sub_ledger_quantum_reserves_upward() -> None:
    tiny = "0." + "0" * 35 + "1"
    reservation = ExactRouteCostReservation.build(
        **_inputs(pricing={"prompt": tiny, "completion": tiny, "input_cache_write": tiny})
    )
    assert reservation.reserved_cost_usd_exact == "0.000000000000000001"


def test_request_ceiling_is_enforced_on_actual_utf8_bytes() -> None:
    inputs = _inputs(policy=RouteCostReservationPolicy.build(maximum_request_bytes=1024))
    body = json.loads(inputs["request_material"])
    body["messages"][1]["content"] = "x" * 1025
    inputs["request_material"] = _canonical(body)
    with pytest.raises(RouteCostReservationError, match="oversized"):
        ExactRouteCostReservation.build(**inputs)


@pytest.mark.parametrize("limit", (1024, 4_000_000, 64_000_000))
def test_actual_request_byte_limit_is_inclusive_and_next_byte_refuses(limit: int) -> None:
    plan = _plan(
        request_id="synthetic-large",
        role="source_audit",
        route_intersection=EndpointRouteIntersection.build(
            (
                _route(
                    model="fixture/synthetic-model",
                    endpoint="synthetic-provider",
                    context_tokens=100_000_000,
                    prompt_tokens=90_000_000,
                ),
            )
        ),
        allocations=_allocations(source_tokens=1, non_source_tokens_each=1),
        required_output_tokens=4096,
        reserved_reasoning_tokens=4096,
        unknown_completion_accounting=True,
    )
    inputs = _inputs(
        policy=RouteCostReservationPolicy.build(maximum_request_bytes=limit),
        plan=plan,
        pricing={
            "prompt": "0.000000001",
            "completion": "0.000000001",
            "input_cache_write": "0.000000001",
        },
    )
    body = json.loads(inputs["request_material"])
    body["messages"][1]["content"] += "x" * (limit - len(inputs["request_material"].encode()))
    inputs["request_material"] = _canonical(body)
    assert len(inputs["request_material"].encode()) == limit
    reservation = ExactRouteCostReservation.build(**inputs)
    assert reservation.request_material_utf8_bytes == limit
    assert (
        next(
            item.maximum_units
            for item in reservation.components
            if item.component.value == "prompt"
        )
        == limit
    )
    body["messages"][1]["content"] += "x"
    inputs["request_material"] = _canonical(body)
    with pytest.raises(RouteCostReservationError, match="oversized"):
        ExactRouteCostReservation.build(**inputs)
