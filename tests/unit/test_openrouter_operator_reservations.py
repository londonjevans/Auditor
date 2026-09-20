"""Synthetic request-cost evidence for the explicit operator reservation policy."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

import mmaudit.models.openrouter as openrouter_module
import mmaudit.models.route_cost_reservations as reservations_module
from mmaudit.benchmark.cross_lineage_adjudication import CrossLineageAdjudicationRunKind
from mmaudit.models.authenticated_runner_smoke import build_authenticated_runner_smoke_cost_plan
from mmaudit.models.openrouter import OpenRouterProviderPolicy
from mmaudit.models.reasoning import ReasoningExecutionEvidence
from mmaudit.models.route_constraints import RouteCostReservationPolicy, RoutePredicateProfile
from mmaudit.orchestration.manifest import canonical_sha256
from tests.unit.test_openrouter import _model_discovery_run
from tests.unit.test_openrouter_request_cost_preview import _high_effort_reasoning_policy, _preview


def _reservation_inputs(
    config_factory: Any,
    tmp_path: Path,
    *,
    component: str = "input_cache_write",
    maximum_attempts: int = 1,
    schema_retries: bool = False,
    operator_policy: RouteCostReservationPolicy | None = None,
) -> dict[str, Any]:
    config = config_factory(
        execution={
            "budget_usd": 250,
            "max_model_retries": 0 if schema_retries else maximum_attempts - 1,
            "max_schema_validation_retries": maximum_attempts - 1 if schema_retries else 0,
            "max_requests_per_agent": maximum_attempts,
        }
    )
    reasoning = _high_effort_reasoning_policy()
    role = reasoning.role_policy_for_request("model_benchmark")
    profile = RoutePredicateProfile.build(
        reasoning_policy_sha256=reasoning.artifact_sha256,
        reasoning_role_profile_sha256=reasoning.role_profile.profile_sha256,
        reasoning_role_binding_sha256=role.binding_sha256,
        reasoning_control_profile_sha256=role.control.profile_sha256,
        reserved_reasoning_tokens=4096,
        minimum_prompt_tokens=100_000,
        required_output_tokens=4096,
        minimum_context_tokens=120_000,
        operator_reservation_policy=operator_policy or RouteCostReservationPolicy.build(),
    )
    parameters = ("max_tokens", "reasoning", "response_format", "structured_outputs", "temperature")
    manifest, evidence = _model_discovery_run(
        tmp_path,
        model_supported_parameters=parameters,
        endpoint_supported_parameters=parameters,
        model_reasoning={"supported_efforts": ["high"]},
        endpoint_reasoning_requested=True,
        endpoint_pricing={
            "completion": "0.00001",
            "prompt": "0.000001",
            "request": "0",
            component: "0.000002",
        },
        route_predicate_profile=profile,
        route_reasoning_policy=reasoning,
    )
    return {
        "config": config,
        "manifest": manifest,
        "evidence": evidence,
        "policy": OpenRouterProviderPolicy(only=("approved-provider",), certification=True),
        "reasoning_policy": reasoning,
    }


@pytest.mark.parametrize(
    "component", ("input_cache_read", "input_cache_write", "internal_reasoning", "web_search")
)
def test_reservation_preview_retains_complete_prices_without_a_total_cap_claim(
    config_factory: Any, tmp_path: Path, component: str
) -> None:
    inputs = _reservation_inputs(config_factory, tmp_path, component=component, maximum_attempts=2)
    preview = _preview(**inputs)
    assert preview.schema_version == "1.4"
    assert preview.price_cap_algorithm is None
    reservation = preview.operator_cost_reservation
    assert reservation is not None
    assert reservation.policy.provider_enforced_total_ceiling is False
    assert reservation.selection_plan_sha256 == "1" * 64
    endpoint = inputs["evidence"].endpoint_snapshot
    assert reservation.route_constraint_sha256 == endpoint.exact_route_constraint.constraint_sha256
    assert (
        reservation.route_predicate_profile_sha256
        == endpoint.route_predicate_profile.profile_sha256
    )
    assert reservation.endpoint_snapshot_sha256 == endpoint.endpoints[0].endpoint_snapshot_sha256
    assert component in {item.component.value for item in reservation.exact_pricing}
    assert component not in {item.component.value for item in reservation.provider_capped_subset}
    assert Decimal(preview.maximum_cost_usd_per_attempt_exact) == Decimal(
        reservation.reserved_cost_usd_exact
    )
    assert Decimal(preview.maximum_cost_usd_all_attempts_exact) == 2 * Decimal(
        reservation.reserved_cost_usd_exact
    )
    assert not preview.authorizes_dispatch
    assert not preview.authorizes_budget_reservation
    assert not preview.authorizes_provider_transport
    assert not preview.grants_review_credit and not preview.grants_completion_credit


@pytest.mark.parametrize("current_accounting", (False, True))
def test_missing_provider_observation_has_valid_noncrediting_reasoning_evidence(
    config_factory: Any, tmp_path: Path, current_accounting: bool
) -> None:
    preview = _preview(**_reservation_inputs(config_factory, tmp_path))
    contract = preview.operator_cost_reservation
    assert contract is not None
    plan = contract.request_token_plan
    assert plan.reasoning_plan is not None
    observed = ReasoningExecutionEvidence.build(
        request_plan=plan.reasoning_plan,
        observed_reasoning_tokens=None,
        provider_completion_tokens=None,
        request_token_plan_sha256=plan.plan_sha256,
        request_body_sha256=contract.request_material_sha256,
        accounting_method=plan.token_detail_accounting_method if current_accounting else None,
    )
    assert observed.state == "failed_before_observation"
    assert not observed.observation_available
    assert observed.provider_completion_tokens is None
    assert ReasoningExecutionEvidence.model_validate_json(observed.model_dump_json()) == observed


@pytest.mark.parametrize(
    "mutation",
    (
        "preview_builder",
        "pricing_alias",
        "pricing_module",
        "usage_alias",
        "usage_module",
        "preview_usage",
        "contract_alias",
        "contract_validator",
        "attempt_serializer",
        "preview_validator",
        "rates_alias",
        "rates_module",
        "rate_validator",
        "refresh_attempt_validator",
        "refresh_attempt_serializer",
        "refresh_attempt_mode_validator",
    ),
)
def test_operator_cost_consumers_retain_existing_runtime_custody_guards(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    assert openrouter_module._openrouter_client_callables_are_pristine()
    if mutation == "preview_builder":
        monkeypatch.setattr(openrouter_module, "_operator_route_request_cost_bound", lambda: None)
    elif mutation == "preview_usage":
        monkeypatch.setattr(openrouter_module, "require_operator_cost_preview_usage", lambda: ())
    elif mutation.startswith("rates_"):
        target = reservations_module if mutation.endswith("module") else openrouter_module
        monkeypatch.setattr(target, "project_route_reserved_rates", lambda: ())
    elif mutation == "rate_validator":
        monkeypatch.setattr(
            reservations_module.RouteCostReservationRate, "__pydantic_validator__", object()
        )
    elif mutation.startswith("refresh_attempt_"):
        field = (
            "__pydantic_serializer__"
            if mutation.endswith("serializer")
            else "explicit_cost_mode_fields"
            if mutation.endswith("mode_validator")
            else "__pydantic_validator__"
        )
        monkeypatch.setattr(
            openrouter_module.AuditModelRefreshPricingAttemptEvidence, field, object()
        )
    elif mutation.startswith("pricing"):
        target = reservations_module if mutation.endswith("module") else openrouter_module
        monkeypatch.setattr(target, "route_cost_reservation_pricing_sha256", lambda _: "0" * 64)
    elif mutation.startswith("usage"):
        target = reservations_module if mutation.endswith("module") else openrouter_module
        monkeypatch.setattr(target, "operator_cost_attempts_from_usage", lambda _: ())
    elif mutation == "contract_alias":
        monkeypatch.setattr(openrouter_module, "ExactRouteCostReservation", object)
    elif mutation == "contract_validator":
        monkeypatch.setattr(
            reservations_module.ExactRouteCostReservation, "__pydantic_validator__", object()
        )
    elif mutation == "attempt_serializer":
        monkeypatch.setattr(
            reservations_module.OperatorRouteCostAttemptEvidence,
            "__pydantic_serializer__",
            object(),
        )
    else:
        monkeypatch.setattr(
            openrouter_module.OpenRouterStructuredRequestCostPreview,
            "__pydantic_validator__",
            object(),
        )
    assert not openrouter_module._openrouter_client_callables_are_pristine()


@pytest.mark.parametrize(
    "field,value",
    (
        ("schema_version", "1.3"),
        ("schema_version", "1.2"),
        ("operator_cost_reservation", None),
        ("route_predicate_profile", None),
        ("price_cap_algorithm", "MMAUDIT_OPENROUTER_MAX_PRICE_CEILING_V1"),
        ("maximum_cost_usd_per_attempt_exact", "0.000001"),
        ("maximum_cost_usd_all_attempts_exact", "0.000001"),
        ("maximum_priced_prompt_units", 1),
        ("wire_max_tokens", 1),
        ("endpoint_cost_bound_pricing_sha256", "f" * 64),
        ("endpoint_cost_bound_projection_sha256", "f" * 64),
        ("authorizes_dispatch", True),
        ("grants_review_credit", True),
    ),
)
def test_coherently_rehashed_preview_cannot_change_mode_units_cost_or_authority(
    config_factory: Any,
    tmp_path: Path,
    field: str,
    value: Any,
) -> None:
    preview = _preview(**_reservation_inputs(config_factory, tmp_path))
    values = preview.model_dump(mode="json")
    values[field] = value
    values["preview_sha256"] = canonical_sha256(
        {key: item for key, item in values.items() if key != "preview_sha256"}
    )
    with pytest.raises(ValueError):
        openrouter_module.OpenRouterStructuredRequestCostPreview.model_validate_json(
            json.dumps(values)
        )


def test_operator_preview_stages_smoke_costs_without_execution_or_qualification_authority(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    selection_hash = "1" * 64
    preview = _preview(
        **_reservation_inputs(config_factory, tmp_path),
        logical_request_id=f"authrunner.smoke.r1.candidate.primary:{selection_hash}",
    )
    plan = build_authenticated_runner_smoke_cost_plan(
        smoke_run_index=1,
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
        stage="CANDIDATE",
        case_id="case-df79ea132113b863",
        selection_sha256=selection_hash,
        request_preview=preview,
    )
    assert plan.schema_version == "1.2" and plan.request_preview.schema_version == "1.4"
    assert plan.request_preview.operator_cost_reservation == preview.operator_cost_reservation
    assert not plan.authorizes_dispatch and not plan.qualification_authorized
    assert not plan.calibration_authorized and not plan.authseal_authorized
    assert not plan.release_authorized and not plan.runner_custody_authorized
