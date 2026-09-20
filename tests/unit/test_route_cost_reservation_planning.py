"""Provider-free task planning must dominate independently derived request costs."""

from __future__ import annotations

import json
from decimal import Decimal, localcontext
from typing import Any

import pytest

import mmaudit.models.openrouter as openrouter_module
import mmaudit.models.route_cost_reservations as reservation_module
import mmaudit.orchestration.budgets as budgets_module
from mmaudit.models.route_constraints import (
    ExactRoutePriceTier,
    ExactRoutePricingSchedule,
    RouteCostReservationPolicy,
    normalize_exact_route_pricing,
)
from mmaudit.models.route_cost_reservations import (
    ExactRouteCostReservation,
    RouteCostReservationPlanningEnvelope,
    route_cost_reservation_pricing_sha256,
)
from mmaudit.orchestration.budgets import (
    EndpointRequestCostBound,
    operator_reservation_planning_cost,
)
from tests.unit.test_route_cost_reservations import BINDINGS, _inputs, _reseal


def _planning_inputs(**kwargs: Any) -> dict[str, Any]:
    request = _inputs(**kwargs)
    plan = request["request_token_plan"]
    return {
        "policy": request["policy"],
        **{key: value for key, value in BINDINGS.items() if key != "endpoint_snapshot_sha256"},
        "route": plan.route_intersection.routes[0],
        "maximum_request_bytes": 16_384,
        "maximum_prompt_tokens": 65_536,
        "maximum_completion_tokens": plan.requested_completion_tokens,
        "pricing": request["pricing"],
        "pricing_schedule": request["pricing_schedule"],
    }


def test_planning_dominates_request_and_retains_the_exact_pricing_identity() -> None:
    inputs = _inputs()
    request = ExactRouteCostReservation.build(**inputs)
    envelope = RouteCostReservationPlanningEnvelope.build(**_planning_inputs())
    bound = EndpointRequestCostBound.from_route_cost_reservation(
        request, request_material=inputs["request_material"], **BINDINGS
    )
    with localcontext() as context:
        context.prec = 6  # Projection must own its decimal arithmetic context.
        total, pricing = operator_reservation_planning_cost(envelope)
    assert total >= bound.maximum_cost_usd
    assert pricing == bound.pricing_snapshot_sha256
    assert route_cost_reservation_pricing_sha256(envelope) == (
        route_cost_reservation_pricing_sha256(request)
    )
    # Existing exact request and stable price fingerprints remain byte-compatible.
    assert request.reservation_sha256 == (
        "7f01f892f46c588197bd7d28cf3e7dc2aa3ef88b6585b2150acadddd3722c529"
    )
    assert route_cost_reservation_pricing_sha256(request) == (
        "e5b7823fb0288ece629ed2401b52d21f8ccc4c6381c7d984a7b8d102485e09a8"
    )
    assert envelope.status == "NONAUTHORIZING_COST_PLANNING"
    assert not {"request_material_sha256", "request_token_plan", "authorizes_dispatch"} & set(
        envelope.model_dump()
    )
    assert envelope.policy.provider_enforced_total_ceiling is False
    assert (
        RouteCostReservationPlanningEnvelope.model_validate_json(envelope.model_dump_json())
        == envelope
    )


@pytest.mark.parametrize(
    "field,value",
    (
        ("maximum_request_bytes", True),
        ("maximum_request_bytes", 0),
        ("maximum_request_bytes", 4_000_001),
        ("maximum_prompt_tokens", 10),
        ("maximum_prompt_tokens", 1_000_000),
        ("maximum_completion_tokens", 64_001),
        ("maximum_completion_tokens", 0),
        ("selection_plan_sha256", ""),
    ),
)
def test_planning_refuses_unbounded_or_invalid_inputs(field: str, value: Any) -> None:
    with pytest.raises(ValueError):
        RouteCostReservationPlanningEnvelope.build(**{**_planning_inputs(), field: value})


@pytest.mark.parametrize("mutation", ("rate", "units", "component", "total", "cap", "request"))
def test_rehashed_planning_cannot_omit_liability_or_impersonate_a_request(mutation: str) -> None:
    envelope = RouteCostReservationPlanningEnvelope.build(**_planning_inputs())
    value = json.loads(envelope.model_dump_json())
    if mutation == "rate":
        value["components"][0]["reserved_unit_price_usd_exact"] = "0"
    elif mutation == "units":
        value["components"][0]["maximum_units"] = 0
    elif mutation == "component":
        value["components"].pop()
    elif mutation == "total":
        value["reserved_cost_usd_exact"] = "0.01"
    elif mutation == "cap":
        value["provider_capped_subset"].pop()
    else:
        value["request_material_sha256"] = "a" * 64
    with pytest.raises(ValueError):
        RouteCostReservationPlanningEnvelope.model_validate_json(_reseal(value, "planning_sha256"))


@pytest.mark.parametrize(
    "field", ("selection_plan_sha256", "route_predicate_profile_sha256", "route_constraint_sha256")
)
def test_planning_cannot_retarget_the_request_pricing_join(field: str) -> None:
    original = RouteCostReservationPlanningEnvelope.build(**_planning_inputs())
    changed = RouteCostReservationPlanningEnvelope.build(**{**_planning_inputs(), field: "f" * 64})
    assert (
        operator_reservation_planning_cost(original)[1]
        != (operator_reservation_planning_cost(changed)[1])
    )


def test_separately_priced_reasoning_uses_full_route_capacity_in_planning() -> None:
    envelope = RouteCostReservationPlanningEnvelope.build(**_planning_inputs())
    components = {item.component.value: item for item in envelope.components}
    assert components["internal_reasoning"].maximum_units == envelope.route.max_completion_tokens
    assert components["internal_reasoning"].maximum_units > envelope.maximum_completion_tokens
    assert components["image"].maximum_units == components["web_search"].maximum_units == 0
    assert components["request"].maximum_units == 1
    assert Decimal(envelope.reserved_cost_usd_exact) > 0


def test_planning_is_not_accepted_as_an_actual_request_reservation() -> None:
    envelope = RouteCostReservationPlanningEnvelope.build(**_planning_inputs())
    with pytest.raises(ValueError):
        EndpointRequestCostBound.from_route_cost_reservation(
            envelope,
            request_material=_inputs()["request_material"],
            **BINDINGS,  # type: ignore[arg-type]
        )


def test_planning_retains_tier_maxima_and_shared_ceiling() -> None:
    pricing = {"prompt": "0.000001", "completion": "0.00001", "input_cache_write": "0"}
    schedule = ExactRoutePricingSchedule.build(
        base_pricing=normalize_exact_route_pricing(pricing),
        tiers=(
            ExactRoutePriceTier.build(
                min_prompt_tokens=100_000, pricing={"input_cache_write": "0.0001"}
            ),
        ),
    )
    inputs = _planning_inputs(pricing=pricing, schedule=schedule)
    envelope = RouteCostReservationPlanningEnvelope.build(**inputs)
    cache = next(c for c in envelope.components if c.component.value == "input_cache_write")
    assert cache.reserved_unit_price_usd_exact == "0.0002"
    assert envelope.pricing_schedule == schedule
    with pytest.raises(ValueError, match="operator ceiling"):
        RouteCostReservationPlanningEnvelope.build(
            **{**inputs, "policy": RouteCostReservationPolicy.build(ledger_ceiling_usd_exact="1")}
        )


@pytest.mark.parametrize(
    "mutation", ("builder", "planning_alias", "planning_module", "validator", "serializer", "code")
)
def test_planning_does_not_open_an_unchecked_runtime_helper(
    mutation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert openrouter_module._openrouter_client_callables_are_pristine()
    if mutation == "builder":
        monkeypatch.setattr(openrouter_module, "_operator_route_planning_envelope", lambda: None)
    elif mutation.startswith("planning"):
        target = openrouter_module if mutation.endswith("alias") else budgets_module
        monkeypatch.setattr(
            target, "operator_reservation_planning_cost", lambda _: (Decimal(0), "")
        )
    elif mutation in {"validator", "serializer"}:
        monkeypatch.setattr(
            reservation_module.RouteCostReservationPlanningEnvelope,
            f"__pydantic_{mutation}__",
            object(),
        )
    else:

        def changed() -> None:
            pass

        monkeypatch.setattr(
            budgets_module.operator_reservation_planning_cost, "__code__", changed.__code__
        )
    assert not openrouter_module._openrouter_client_callables_are_pristine()
