"""Synthetic cost-only admission; no provider, runtime or qualification authority."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

import pytest
from jsonschema import Draft202012Validator

import mmaudit.models.openrouter as openrouter_module
from mmaudit.models.endpoint_snapshots import OpenRouterConstrainedRouteContext
from mmaudit.models.route_constraints import (
    RESERVATION_ROUTE_PREDICATE_IDS,
    ROUTE_PREDICATE_IDS,
    ExactRouteConstraint,
    ProviderPriceCapAlgorithm,
    RouteConstraintError,
    RouteConstraintPurpose,
    RouteCostReservationPolicy,
    RoutePredicateDisposition,
    RoutePredicateId,
    RoutePredicateProfile,
    RoutePredicateReport,
    RoutePredicateRequirementError,
    evaluate_route_predicates,
    normalize_exact_route_pricing,
    project_provider_price_cap,
    project_route_profile_provider_caps,
    require_route_predicates,
)
from mmaudit.orchestration.manifest import canonical_sha256
from tests.unit.test_endpoint_snapshots import (
    _constrained_endpoint,
    _route_bundle,
    _validate_constrained,
)
from tests.unit.test_openrouter_refresh_runtime import _registered_endpoint_pricing
from tests.unit.test_route_constraints import _constraint, _facts, _profile


def _reservation_profile(base: RoutePredicateProfile | None = None) -> RoutePredicateProfile:
    base = base or _profile()
    return RoutePredicateProfile.build(
        reasoning_policy_sha256=base.reasoning_policy_sha256,
        reasoning_role_profile_sha256=base.reasoning_role_profile_sha256,
        reasoning_role_binding_sha256=base.reasoning_role_binding_sha256,
        reasoning_control_profile_sha256=base.reasoning_control_profile_sha256,
        reserved_reasoning_tokens=base.reserved_reasoning_tokens,
        minimum_prompt_tokens=base.minimum_prompt_tokens,
        required_output_tokens=base.required_output_tokens,
        minimum_context_tokens=base.minimum_context_tokens,
        operator_reservation_policy=RouteCostReservationPolicy.build(),
    )


def _reseal(payload: dict[str, Any], key: str) -> str:
    payload[key] = canonical_sha256({k: v for k, v in payload.items() if k != key})
    return json.dumps(payload)


def test_reservation_profile_replaces_only_cost_predicates() -> None:
    legacy = _profile()
    current = _reservation_profile(legacy)
    assert current.schema_version == "1.3"
    assert current.predicate_ids == RESERVATION_ROUTE_PREDICATE_IDS
    assert len(current.predicate_ids) == len(ROUTE_PREDICATE_IDS) == 29
    unchanged = {"schema_version", "predicate_ids", "profile_sha256", "operator_reservation_policy"}
    assert current.model_dump(mode="json", exclude=unchanged) == legacy.model_dump(
        mode="json", exclude=unchanged
    )
    assert "operator_reservation_policy" not in legacy.model_dump(mode="json")
    assert current.operator_reservation_policy is not None
    assert current.operator_reservation_policy.provider_enforced_total_ceiling is False


@pytest.mark.parametrize(
    "component", ["input_cache_read", "input_cache_write", "internal_reasoning", "web_search"]
)
def test_uncappable_prices_use_distinct_predicates_and_keep_runtime_unavailable(
    component: str,
) -> None:
    profile = _reservation_profile()
    constraint = _constraint(profile)
    pricing = normalize_exact_route_pricing(
        {"prompt": "0.000001", "completion": "0.000002", component: "0.000003"}
    )
    report = evaluate_route_predicates(
        profile=profile,
        constraint=constraint,
        facts=_facts(
            profile=profile,
            constraint=constraint,
            exact_pricing=pricing,
            configured_provider_max_price=project_route_profile_provider_caps(profile, pricing),
        ),
    )
    assert report.schema_version == "1.1"
    assert tuple(item.predicate_id for item in report.results) == RESERVATION_ROUTE_PREDICATE_IDS
    assert all(
        item.disposition is RoutePredicateDisposition.SATISFIED for item in report.results[:-2]
    )
    require_route_predicates(report, purpose=RouteConstraintPurpose.NONCREDITING_SMOKE_ADMISSION)
    with pytest.raises(RoutePredicateRequirementError, match="EMPIRICAL_SCHEMA_CONFORMANCE"):
        require_route_predicates(report, purpose=RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION)
    for algorithm in (
        ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1,
        ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2,
    ):
        with pytest.raises(RouteConstraintError):
            project_provider_price_cap(pricing, algorithm=algorithm)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_policy",
        "null_policy",
        "legacy_version",
        "legacy_inventory",
        "weaken_zdr",
        "weaken_reasoning",
        "over_ceiling",
    ],
)
def test_coherently_resealed_profile_cannot_mix_cost_and_security_semantics(mutation: str) -> None:
    payload = _reservation_profile().model_dump(mode="json")
    if mutation == "missing_policy":
        payload.pop("operator_reservation_policy")
    elif mutation == "null_policy":
        payload["operator_reservation_policy"] = None
    elif mutation == "legacy_version":
        payload["schema_version"] = "1.0"
    elif mutation == "legacy_inventory":
        payload["predicate_ids"] = list(ROUTE_PREDICATE_IDS)
    elif mutation == "weaken_zdr":
        payload["require_zdr"] = False
    elif mutation == "weaken_reasoning":
        payload["reasoning_effort"] = "low"
    else:
        policy = payload["operator_reservation_policy"]
        policy["ledger_ceiling_usd_exact"] = "251"
        payload["operator_reservation_policy"] = json.loads(_reseal(policy, "policy_sha256"))
    with pytest.raises(ValueError):
        RoutePredicateProfile.model_validate_json(_reseal(payload, "profile_sha256"))


@pytest.mark.parametrize("mutation", ["version", "inventory"])
def test_resealed_report_cannot_masquerade_as_a_legacy_cap_proof(mutation: str) -> None:
    profile = _reservation_profile()
    report = evaluate_route_predicates(
        profile=profile, constraint=_constraint(profile), facts=_facts(profile=profile)
    )
    payload = report.model_dump(mode="json")
    if mutation == "version":
        payload["schema_version"] = "1.0"
    else:
        payload["results"][22]["predicate_id"] = RoutePredicateId.PRICE_CAP_EXPRESSIBILITY
        payload["results"][23]["predicate_id"] = RoutePredicateId.PRICE_CAP_NO_WEAKER
    with pytest.raises(ValueError):
        RoutePredicateReport.model_validate_json(_reseal(payload, "report_sha256"))


def test_real_endpoint_normalization_embeds_cost_policy_and_retains_uncappable_price() -> None:
    legacy, old_constraint, old_context = _route_bundle()
    profile = _reservation_profile(legacy)
    constraint = ExactRouteConstraint.build(
        role=old_constraint.role,
        exact_model_id=old_constraint.exact_model_id,
        provider_endpoint=old_constraint.provider_endpoint,
        profile=profile,
    )
    context = OpenRouterConstrainedRouteContext.model_validate(
        {
            **old_context.model_dump(mode="python"),
            "route_predicate_profile": profile,
            "exact_route_constraint": constraint,
        }
    )
    endpoint = _constrained_endpoint()
    endpoint["pricing"]["input_cache_write"] = "0.000003"
    snapshot = _validate_constrained(endpoint, context=context)
    assert snapshot.route_predicate_profile == profile
    assert snapshot.normalized_route_facts is not None
    assert "input_cache_write" in {
        price.component.value for price in snapshot.normalized_route_facts.exact_pricing
    }
    assert snapshot.route_predicate_report is not None
    assert snapshot.route_predicate_report.schema_version == "1.1"
    require_route_predicates(
        snapshot.route_predicate_report, purpose=RouteConstraintPurpose.DISCOVERY_PUBLICATION
    )
    assert type(snapshot).model_validate_json(snapshot.model_dump_json()) == snapshot


@pytest.mark.parametrize(
    "updates,predicate",
    [
        ({"observed_model_id": "other/model"}, "EXACT_MODEL_IDENTITY"),
        ({"observed_provider_endpoint": "other-provider"}, "EXACT_PROVIDER_ENDPOINT"),
        ({"provider_identity_inventory_complete": False}, "PROVIDER_DISPLAY_NAME_INJECTIVITY"),
        ({"operational_status": "1"}, "OPERATIONAL_STATUS"),
        ({"zdr_eligible": False}, "ZDR_ELIGIBILITY"),
        (
            {"emitted_request_parameters": ("max_tokens", "response_format", "temperature")},
            "EMITS_REASONING",
        ),
        (
            {
                "model_supported_parameters": (
                    "max_tokens",
                    "reasoning",
                    "response_format",
                    "temperature",
                )
            },
            "MODEL_STRUCTURED_OUTPUT_MARKER",
        ),
        (
            {
                "endpoint_supported_parameters": (
                    "max_tokens",
                    "reasoning",
                    "response_format",
                    "temperature",
                )
            },
            "ENDPOINT_STRUCTURED_OUTPUT_MARKER",
        ),
        (
            {"configured_provider_endpoints": ("provider/fp8", "other-provider")},
            "SINGLETON_EXACT_ROUTE",
        ),
        ({"automatic_fallbacks_allowed": True}, "AUTOMATIC_FALLBACK_DISABLED"),
        ({"reasoning_policy_sha256": "f" * 64}, "REASONING_POLICY_BINDING"),
        ({"reasoning_control_profile_sha256": "f" * 64}, "REASONING_CONTROL_BINDING"),
        ({"reasoning_effort": "low"}, "REASONING_CONTROL_VALUES"),
        (
            {"endpoint_supported_reasoning_efforts": (), "model_supported_reasoning_efforts": ()},
            "REASONING_EFFORT_SUPPORT",
        ),
        ({"max_prompt_tokens": 1024}, "PROMPT_CAPACITY_ENVELOPE"),
        ({"max_completion_tokens": 2048}, "OUTPUT_CAPACITY_ENVELOPE"),
        (
            {"max_prompt_tokens": 8192, "max_completion_tokens": 8192, "context_tokens": 8192},
            "CONTEXT_CAPACITY_ENVELOPE",
        ),
        ({"max_completion_tokens_source": "context_limit"}, "METADATA_COMPLETION_CAPACITY"),
        ({"frozen_live_equivalent": False}, "FROZEN_LIVE_EQUIVALENCE"),
        ({"registry_selection_plan_sha256": "f" * 64}, "REGISTRY_SELECTION_HASH_CUSTODY"),
        ({"registry_constraint_sha256": "f" * 64}, "REGISTRY_CONSTRAINT_HASH_CUSTODY"),
    ],
)
def test_reservation_profile_preserves_non_cost_refusals(
    updates: dict[str, Any], predicate: str
) -> None:
    profile = _reservation_profile()
    report = evaluate_route_predicates(
        profile=profile, constraint=_constraint(profile), facts=_facts(profile=profile, **updates)
    )
    with pytest.raises(RoutePredicateRequirementError, match=predicate):
        require_route_predicates(
            report, purpose=RouteConstraintPurpose.NONCREDITING_SMOKE_ADMISSION
        )


@pytest.mark.parametrize("mutation", ["unavailable", "missing_cap", "wrong_cap"])
def test_cost_metadata_failures_are_required_for_every_purpose(mutation: str) -> None:
    profile = _reservation_profile()
    updates: dict[str, Any] = {"configured_provider_max_price": None}
    if mutation == "unavailable":
        updates["pricing_schedule"] = "unavailable"
    elif mutation == "wrong_cap":
        updates["configured_provider_max_price"] = project_provider_price_cap(
            normalize_exact_route_pricing({"prompt": "0.5", "completion": "0.5"})
        )
    report = evaluate_route_predicates(
        profile=profile, constraint=_constraint(profile), facts=_facts(profile=profile, **updates)
    )
    for purpose in RouteConstraintPurpose:
        with pytest.raises(
            RoutePredicateRequirementError, match=r"RESERVATION_PRICING|PROVIDER_CAPPED_SUBSET"
        ):
            require_route_predicates(report, purpose=purpose)


@pytest.mark.parametrize("is_profile", [False, True])
def test_schema_rejects_coherently_relabelled_cost_inventory(is_profile: bool) -> None:
    profile = _reservation_profile()
    value = (
        profile
        if is_profile
        else evaluate_route_predicates(
            profile=profile, constraint=_constraint(profile), facts=_facts(profile=profile)
        )
    )
    validator = Draft202012Validator(type(value).model_json_schema())
    payload = value.model_dump(mode="json")
    validator.validate(payload)
    payload["schema_version"] = "1.0"
    assert list(validator.iter_errors(payload))


@pytest.mark.parametrize(
    "component", ["input_cache_read", "input_cache_write", "internal_reasoning", "web_search"]
)
def test_registered_prices_retain_uncapped_components_without_legacy_total_proof(
    component: str,
) -> None:
    registered = replace(
        _registered_endpoint_pricing(
            pricing={"prompt": "0.000001", "completion": "0.000002", component: "0.000003"}
        ),
        route_predicate_profile=_reservation_profile(),
    )
    capped = openrouter_module._routing_max_price((registered,))
    assert set(capped) == {"prompt", "completion"}
    assert component in dict(registered.pricing)
    with pytest.raises(
        openrouter_module.OpenRouterCostControlError,
        match="operator reservation cannot be projected as a provider-enforced total ceiling",
    ):
        openrouter_module._provider_capped_cost_bound_pricing(registered, capped)


def test_registered_reservation_policy_refuses_multiple_endpoints() -> None:
    first = replace(
        _registered_endpoint_pricing(pricing={"prompt": "0.000001", "completion": "0.000002"}),
        route_predicate_profile=_reservation_profile(),
    )
    with pytest.raises(openrouter_module.OpenRouterCostControlError, match="one exact route"):
        openrouter_module._routing_max_price(
            (first, replace(first, provider_endpoint="other-provider"))
        )


def test_registered_cost_projector_replacement_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = replace(
        _registered_endpoint_pricing(pricing={"prompt": "0.000001", "completion": "0.000002"}),
        route_predicate_profile=_reservation_profile(),
    )
    monkeypatch.setattr(
        openrouter_module, "project_route_profile_provider_caps", lambda *_args, **_kwargs: ()
    )
    with pytest.raises(openrouter_module.OpenRouterCostControlError, match="projector changed"):
        openrouter_module._routing_max_price((first,))
