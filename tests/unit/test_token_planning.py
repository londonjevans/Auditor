from __future__ import annotations

import json
from decimal import Decimal

import pytest
from pydantic import ValidationError

from mmaudit.models.token_planning import (
    PROMPT_ALLOCATION_CATEGORIES,
    EndpointRouteIntersection,
    EndpointRouteTokenCapacity,
    PromptAllocationCategory,
    PromptTokenAllocation,
    RequestTokenPlan,
    TokenPlanningError,
    Utf8TokenEstimate,
    build_request_token_plan,
)


def _route(
    *,
    model: str = "alpha/frontier-secure",
    endpoint: str = "approved-provider",
    snapshot_character: str = "a",
    context_tokens: int = 300_000,
    prompt_tokens: int = 280_000,
    completion_tokens: int = 64_000,
) -> EndpointRouteTokenCapacity:
    return EndpointRouteTokenCapacity.build(
        exact_model_id=model,
        provider_endpoint=endpoint,
        endpoint_snapshot_sha256=snapshot_character * 64,
        context_tokens=context_tokens,
        max_prompt_tokens=prompt_tokens,
        max_prompt_tokens_source="metadata",
        max_completion_tokens=completion_tokens,
        max_completion_tokens_source="metadata",
    )


def _allocations(
    *,
    source_tokens: int,
    non_source_tokens_each: int = 100,
    raw_marker: str = "x",
) -> tuple[PromptTokenAllocation, ...]:
    allocations = []
    for category in PROMPT_ALLOCATION_CATEGORIES:
        tokens = (
            source_tokens if category is PromptAllocationCategory.SOURCE else non_source_tokens_each
        )
        allocations.append(
            PromptTokenAllocation.from_text(
                category,
                raw_marker * (tokens * 3),
            )
        )
    return tuple(allocations)


def _plan(
    *,
    request_id: str = "request-1",
    role: str = "source_audit",
    route_intersection: EndpointRouteIntersection | None = None,
    allocations: tuple[PromptTokenAllocation, ...] | None = None,
    required_output_tokens: int = 32_768,
    reserved_reasoning_tokens: int = 8_192,
    context_utilization: Decimal = Decimal("0.75"),
    global_input_token_budget: int = 1_000_000,
    global_output_token_budget: int = 200_000,
    configured_reserved_system_tokens: int = 0,
    configured_reserved_schema_tokens: int = 0,
    configured_reserved_protocol_tokens: int = 0,
    maximum_source_tokens_per_request: int = 200_000,
    context_omission_sha256s: tuple[str, ...] = (),
) -> RequestTokenPlan:
    resolved_allocations = allocations or _allocations(source_tokens=63_000)
    return build_request_token_plan(
        request_id=request_id,
        role=role,
        route_intersection=route_intersection or EndpointRouteIntersection.build((_route(),)),
        allocations=resolved_allocations,
        required_output_tokens=required_output_tokens,
        reserved_reasoning_tokens=reserved_reasoning_tokens,
        global_input_token_budget=global_input_token_budget,
        global_output_token_budget=global_output_token_budget,
        context_utilization=context_utilization,
        configured_reserved_system_tokens=configured_reserved_system_tokens,
        configured_reserved_schema_tokens=configured_reserved_schema_tokens,
        configured_reserved_protocol_tokens=configured_reserved_protocol_tokens,
        maximum_source_tokens_per_request=maximum_source_tokens_per_request,
        context_omission_sha256s=context_omission_sha256s,
        prompt_envelope_byte_upper_bound_tokens=sum(
            allocation.estimate.byte_upper_bound_tokens for allocation in resolved_allocations
        ),
    )


def test_utf8_estimator_records_estimate_upper_bound_and_no_raw_text() -> None:
    raw_text = "synthetic-évidence"

    estimate = Utf8TokenEstimate.from_text(raw_text)

    expected_bytes = len(raw_text.encode("utf-8"))
    assert estimate.utf8_bytes == expected_bytes
    assert estimate.estimated_tokens == (expected_bytes + 2) // 3
    assert estimate.byte_upper_bound_tokens == expected_bytes
    assert raw_text not in estimate.model_dump_json()
    assert Utf8TokenEstimate.from_text("").estimated_tokens == 0
    assert (
        Utf8TokenEstimate.from_measurement(
            content_sha256=estimate.content_sha256,
            utf8_bytes=estimate.utf8_bytes,
        )
        == estimate
    )


def test_high_capacity_route_preserves_32k_output_with_conservative_input_bound() -> None:
    plan = _plan()

    assert plan.required_output_tokens == plan.reserved_output_tokens == 32_768
    assert plan.reserved_reasoning_tokens == 8_192
    assert plan.requested_completion_tokens == 40_960
    assert plan.hard_prompt_tokens == 259_040
    assert plan.usable_prompt_tokens == 194_280
    assert plan.source_budget.maximum_source_tokens_per_request == 191_280
    assert plan.source_budget.planned_source_tokens == 189_000
    assert plan.estimated_prompt_tokens == 64_000
    assert plan.prompt_byte_upper_bound_tokens == 192_000
    assert plan.global_budget.request_input_tokens == 192_000
    assert plan.prompt_byte_upper_bound_tokens <= plan.usable_prompt_tokens
    assert plan.prompt_byte_upper_bound_tokens + plan.requested_completion_tokens <= 300_000


def test_prompt_byte_upper_bound_cannot_exceed_conservative_endpoint_capacity() -> None:
    allocations = _allocations(source_tokens=190_000)

    with pytest.raises(TokenPlanningError, match=r"conservative.*capacity"):
        _plan(allocations=allocations)


def test_mixed_routes_use_lowest_capacity_without_peer_role_division() -> None:
    high = _route()
    low = _route(
        model="alpha/frontier-secure",
        endpoint="compact-provider",
        snapshot_character="b",
        context_tokens=32_768,
        prompt_tokens=24_576,
        completion_tokens=8_192,
    )
    intersection = EndpointRouteIntersection.build((high, low))
    allocations = _allocations(source_tokens=4_700)

    plan = _plan(
        route_intersection=intersection,
        allocations=allocations,
        required_output_tokens=4_096,
        reserved_reasoning_tokens=1_024,
        context_utilization=Decimal("0.70"),
    )

    assert intersection.context_tokens == 32_768
    assert intersection.max_prompt_tokens == 24_576
    assert intersection.max_completion_tokens == 8_192
    assert plan.usable_prompt_tokens == 17_203
    assert plan.source_budget.maximum_source_tokens_per_request == 14_203


def test_required_output_fails_instead_of_clamping_to_mixed_route() -> None:
    low = _route(
        model="alpha/frontier-secure",
        endpoint="compact-provider",
        context_tokens=32_768,
        prompt_tokens=24_576,
        completion_tokens=8_192,
    )
    routes = EndpointRouteIntersection.build((_route(), low))

    with pytest.raises(TokenPlanningError, match="required output exceeds"):
        _plan(
            route_intersection=routes,
            allocations=_allocations(source_tokens=1_000),
            required_output_tokens=32_768,
            reserved_reasoning_tokens=0,
        )


def test_reasoning_and_output_combination_fails_closed() -> None:
    route = _route(context_tokens=100_000, prompt_tokens=90_000, completion_tokens=35_000)

    with pytest.raises(TokenPlanningError, match="output and reasoning exceed"):
        _plan(
            route_intersection=EndpointRouteIntersection.build((route,)),
            allocations=_allocations(source_tokens=1_000),
            required_output_tokens=32_000,
            reserved_reasoning_tokens=8_000,
        )


def test_prompt_plus_completion_cannot_exceed_endpoint_context() -> None:
    route = _route(context_tokens=100_000, prompt_tokens=100_000, completion_tokens=20_000)

    with pytest.raises(
        TokenPlanningError,
        match="conservative prompt bound exceeds the usable endpoint capacity",
    ):
        _plan(
            route_intersection=EndpointRouteIntersection.build((route,)),
            allocations=_allocations(source_tokens=89_000),
            required_output_tokens=20_000,
            reserved_reasoning_tokens=0,
            context_utilization=Decimal("0.75"),
        )


def test_context_utilization_outside_65_to_75_percent_fails() -> None:
    with pytest.raises(TokenPlanningError, match=r"between 0\.65 and 0\.75"):
        _plan(context_utilization=Decimal("0.76"))


def test_configured_non_source_reserves_and_source_cap_are_enforced() -> None:
    def byte_allocations(source_bytes: int) -> tuple[PromptTokenAllocation, ...]:
        return tuple(
            PromptTokenAllocation.from_text(
                category,
                "x" * (source_bytes if category is PromptAllocationCategory.SOURCE else 300),
            )
            for category in PROMPT_ALLOCATION_CATEGORIES
        )

    plan = _plan(
        allocations=byte_allocations(40_000),
        configured_reserved_system_tokens=8_192,
        configured_reserved_schema_tokens=8_192,
        configured_reserved_protocol_tokens=2_048,
        maximum_source_tokens_per_request=50_000,
    )

    assert plan.reserved_system_tokens == 8_192
    assert plan.reserved_schema_tokens == 8_192
    assert plan.reserved_protocol_tokens == 2_048
    assert plan.source_budget.non_source_prompt_tokens == 3_000
    assert plan.source_budget.reserved_non_source_prompt_tokens == 20_532
    assert plan.source_budget.configured_maximum_source_tokens_per_request == 50_000
    assert plan.source_budget.maximum_source_tokens_per_request == 50_000
    assert plan.source_budget.remaining_source_tokens == 10_000
    assert plan.source_budget.unallocated_prompt_tokens == 123_748

    with pytest.raises(TokenPlanningError, match="per-request maximum"):
        _plan(
            allocations=byte_allocations(50_001),
            configured_reserved_system_tokens=8_192,
            configured_reserved_schema_tokens=8_192,
            configured_reserved_protocol_tokens=2_048,
            maximum_source_tokens_per_request=50_000,
        )


def test_route_intersection_rejects_multiple_exact_models() -> None:
    with pytest.raises(TokenPlanningError, match="exactly one model ID"):
        EndpointRouteIntersection.build(
            (
                _route(model="alpha/frontier-secure"),
                _route(
                    model="beta/frontier-secure",
                    endpoint="second-provider",
                    snapshot_character="b",
                ),
            )
        )


def test_context_omission_hashes_are_canonical_and_self_bound() -> None:
    plan = _plan(context_omission_sha256s=("b" * 64, "a" * 64))

    assert plan.context_omission_sha256s == ("a" * 64, "b" * 64)

    with pytest.raises(TokenPlanningError, match="unique"):
        _plan(context_omission_sha256s=("a" * 64, "a" * 64))


def test_global_input_and_output_budgets_fail_closed() -> None:
    allocations = _allocations(source_tokens=1_000)

    with pytest.raises(TokenPlanningError, match="global input token budget"):
        _plan(
            allocations=allocations,
            required_output_tokens=1_000,
            reserved_reasoning_tokens=100,
            global_input_token_budget=1_999,
        )
    with pytest.raises(TokenPlanningError, match="global output token budget"):
        _plan(
            allocations=allocations,
            required_output_tokens=1_000,
            reserved_reasoning_tokens=100,
            global_output_token_budget=1_099,
        )


def test_plan_hash_and_conservation_tampering_are_rejected() -> None:
    plan = _plan()
    hash_tamper = plan.model_dump(mode="python")
    hash_tamper["plan_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="plan_sha256"):
        RequestTokenPlan.model_validate(hash_tamper)

    conservation_tamper = plan.model_dump(mode="python")
    conservation_tamper["estimated_prompt_tokens"] += 1
    with pytest.raises(ValidationError, match="does not conserve"):
        RequestTokenPlan.model_validate(conservation_tamper)


def test_allocation_inventory_must_be_complete_unique_and_sorted() -> None:
    plan = _plan()
    unsorted = plan.model_dump(mode="python")
    unsorted["allocations"] = tuple(reversed(unsorted["allocations"]))

    with pytest.raises(ValidationError, match="complete, unique, and sorted"):
        RequestTokenPlan.model_validate(unsorted)

    duplicated = plan.model_dump(mode="python")
    items = list(duplicated["allocations"])
    items[-1] = items[0]
    duplicated["allocations"] = tuple(items)
    with pytest.raises(ValidationError, match="complete, unique, and sorted"):
        RequestTokenPlan.model_validate(duplicated)


def test_token_plan_serialization_contains_no_raw_prompt_text() -> None:
    raw_marker = "RAW-CONTEXT-CANARY"
    allocations = tuple(
        PromptTokenAllocation.from_text(category, f"{raw_marker}:{category.value}")
        for category in PROMPT_ALLOCATION_CATEGORIES
    )

    plan = _plan(
        allocations=allocations,
        required_output_tokens=1_000,
        reserved_reasoning_tokens=100,
    )
    serialized = plan.model_dump_json()

    assert raw_marker not in serialized
    assert "raw_text" not in serialized
    assert json.loads(serialized)["allocations"][0]["estimate"]["content_sha256"]


def test_request_capacity_is_independent_of_peer_role_count() -> None:
    route = EndpointRouteIntersection.build((_route(),))
    allocations = _allocations(source_tokens=1_000)

    plans = [
        _plan(
            request_id=f"request-{index}",
            role=f"reviewer_{index}",
            route_intersection=route,
            allocations=allocations,
            required_output_tokens=4_096,
            reserved_reasoning_tokens=1_024,
        )
        for index in range(12)
    ]

    assert len({plan.usable_prompt_tokens for plan in plans}) == 1
    assert len({plan.source_budget.maximum_source_tokens_per_request for plan in plans}) == 1
    assert len({plan.plan_sha256 for plan in plans}) == len(plans)


def test_context_derived_limits_must_equal_context_capacity() -> None:
    with pytest.raises(ValidationError, match="context-derived prompt limit"):
        EndpointRouteTokenCapacity.build(
            exact_model_id="alpha/frontier-secure",
            provider_endpoint="approved-provider",
            endpoint_snapshot_sha256="a" * 64,
            context_tokens=100_000,
            max_prompt_tokens=90_000,
            max_prompt_tokens_source="context_limit",
            max_completion_tokens=20_000,
            max_completion_tokens_source="metadata",
        )
