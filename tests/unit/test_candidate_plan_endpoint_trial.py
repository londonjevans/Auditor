"""One exact, non-adopting candidate endpoint trial preserves the original policy."""

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

import mmaudit.models.candidate_plan_ancestry as ancestry_module
from mmaudit.models.candidate_plan_ancestry import (
    VerifiedCandidateSelectionPlanAncestry,
    derive_candidate_selection_plan_reactivation,
    resolve_verified_candidate_selection_plan_ancestry,
    validate_candidate_selection_plan_reactivation,
)
from mmaudit.models.candidate_selection import (
    CandidateSelectionPlan,
    CandidateSelectionPlanEndpointTrialBinding,
    authenticated_runner_route_constraint,
    validate_candidate_selection_routes,
)
from mmaudit.models.discovery import DiscoveryCandidateRoute
from mmaudit.models.route_constraints import ExactRouteRole
from mmaudit.orchestration.manifest import canonical_sha256
from scripts.validate_governance_state import validate_current_selection_plan
from tests.unit.test_candidate_plan_cost_transition import _seal
from tests.unit.test_candidate_plan_legacy_cost import _legacy_plan

ROOT = Path(__file__).parents[2]


def _trial(**updates: Any) -> CandidateSelectionPlan:
    options = {
        "candidate_model_id": "deepseek/deepseek-v4-pro-0813",
        "provider_endpoint": "fireworks",
        "candidate_endpoint_trial": True,
    }
    options.update(updates)
    return derive_candidate_selection_plan_reactivation(
        resolve_verified_candidate_selection_plan_ancestry(), **options
    )


def test_fireworks_trial_adds_only_one_candidate_endpoint_without_adoption() -> None:
    active = ROOT / "config/models.selection-plan.json"
    original_bytes = active.read_bytes()
    old, trial = _legacy_plan(), _trial()
    assert trial.schema_version == "1.12"
    assert trial.predecessor_plan_sha256 == old.plan_sha256
    before, after = old.authenticated_runner_selection, trial.authenticated_runner_selection
    assert before is not None and after is not None
    excluded = {"route_constraints", "role_assignment_sha256"}
    assert before.model_dump(exclude=excluded) == after.model_dump(exclude=excluded)
    assert (
        tuple(item for item in after.route_constraints if item.provider_endpoint != "fireworks")
        == before.route_constraints
    )
    added = tuple(item for item in after.route_constraints if item not in before.route_constraints)
    assert len(added) == 1
    assert added[0].role is ExactRouteRole.CANDIDATE
    assert added[0].exact_model_id == before.candidate_model_id
    assert added[0].provider_endpoint == "fireworks"
    for first, second in zip(old.entries, trial.entries, strict=True):
        if first.exact_model_id == before.candidate_model_id:
            assert second.allowed_provider_endpoints == ("fireworks", "together")
            excluded = {"allowed_provider_endpoints", "entry_sha256"}
            assert first.model_dump(exclude=excluded) == second.model_dump(exclude=excluded)
        else:
            assert first == second
    assert old.source_bindings == trial.source_bindings
    assert old.unresolved_requirements == trial.unresolved_requirements
    assert (
        validate_candidate_selection_plan_reactivation(
            resolve_verified_candidate_selection_plan_ancestry(), successor=trial
        )
        == trial
    )
    with pytest.raises(ValueError):
        validate_current_selection_plan(trial)
    assert active.read_bytes() == original_bytes


@pytest.mark.parametrize("endpoint", ("together", "sail-research/fp4", "phala", "other"))
def test_trial_does_not_select_the_next_endpoint_without_its_preceding_result(
    endpoint: str,
) -> None:
    with pytest.raises(ValueError):
        _trial(provider_endpoint=endpoint)


@pytest.mark.parametrize(
    "updates",
    (
        {"candidate_model_id": "moonshotai/kimi-k3"},
        {"primary_judge_provider_endpoint": "together"},
        {"replay_judge_provider_endpoint": "fireworks"},
        {"refresh_endpoint_inventory": True},
        {"reserve_then_reconcile_costs": True},
        {"allow_exact_legacy_uncertainty": True},
        {"candidate_endpoint_trial": 1},
    ),
)
def test_trial_cannot_mix_a_different_model_judge_or_policy_transition(
    updates: dict[str, Any],
) -> None:
    with pytest.raises(ValueError):
        _trial(**updates)


def test_trial_supports_original_singleton_discovery_without_automatic_fallback() -> None:
    trial = _trial()
    route = DiscoveryCandidateRoute(
        exact_model_id="deepseek/deepseek-v4-pro-0813", approved_provider_endpoint="fireworks"
    )
    assert validate_candidate_selection_routes(trial, routes=(route,)) == trial
    profile, constraint = authenticated_runner_route_constraint(
        trial, exact_model_id=route.exact_model_id, provider_endpoint="fireworks"
    )
    assert constraint.role is ExactRouteRole.CANDIDATE
    assert profile.require_singleton_route and not profile.allow_automatic_fallbacks
    together = route.model_copy(update={"approved_provider_endpoint": "together"})
    with pytest.raises(ValueError, match="repeat one exact model ID"):
        validate_candidate_selection_routes(trial, routes=(route, together))
    for endpoint in ("sail-research/fp4", "phala"):
        with pytest.raises(ValueError, match="unlisted endpoint"):
            validate_candidate_selection_routes(
                trial, routes=(route.model_copy(update={"approved_provider_endpoint": endpoint}),)
            )


@pytest.mark.parametrize(
    "mutation",
    (
        "missing_binding",
        "null_binding",
        "old_version",
        "adoption",
        "qualification",
        "seal",
        "durable",
        "wrong_predecessor",
        "output_mode",
        "reasoning",
        "supported_parameters",
    ),
)
def test_schema_and_runtime_reject_trial_scope_changes(mutation: str) -> None:
    payload = _trial().model_dump(mode="json")
    validator = Draft202012Validator(CandidateSelectionPlan.model_json_schema())
    validator.validate(payload)
    binding = payload["operator_endpoint_trial_binding"]
    selection = payload["authenticated_runner_selection"]
    if mutation == "missing_binding":
        payload.pop("operator_endpoint_trial_binding")
    elif mutation == "null_binding":
        payload["operator_endpoint_trial_binding"] = None
    elif mutation == "old_version":
        payload["schema_version"] = "1.11"
    elif mutation in {"adoption", "qualification", "seal", "durable"}:
        binding[
            {
                "adoption": "plan_adoption_authorized",
                "qualification": "qualification_authorized",
                "seal": "seal_publication_authorized",
                "durable": "durable_runner_authorized",
            }[mutation]
        ] = True
    elif mutation == "wrong_predecessor":
        binding["predecessor_raw_sha256"] = "f" * 64
    elif mutation == "output_mode":
        selection["required_output_mode"] = "JSON_OBJECT"
    elif mutation == "reasoning":
        selection["required_reasoning_effort"] = "medium"
    else:
        selection["required_supported_parameters"] = []
    assert list(validator.iter_errors(payload))
    with pytest.raises(ValueError):
        CandidateSelectionPlan.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize("field", ("unresolved_requirements", "source_bindings", "entries"))
def test_coherent_unrelated_changes_cannot_substitute_for_exact_predecessor(field: str) -> None:
    payload = _trial().model_dump(mode="json")
    if field == "unresolved_requirements":
        payload[field] = sorted((*payload[field], "UNRELATED_OPERATOR_CHANGE"))
    elif field == "source_bindings":
        payload[field][0]["content_sha256"] = "f" * 64
        _seal(payload[field][0], "source_binding_sha256")
    else:
        payload[field][0]["advisory_lineage_group"] = "Unrelated"
        payload[field][0]["lineage_group_seed_sha256"] = canonical_sha256(
            {"advisory_lineage_group": "Unrelated", "authority": False}
        )
        _seal(payload[field][0], "entry_sha256")
    _seal(payload, "plan_sha256")
    forged = CandidateSelectionPlan.model_validate_json(json.dumps(payload))
    with pytest.raises(ValueError, match="exact derivation"):
        validate_candidate_selection_plan_reactivation(
            resolve_verified_candidate_selection_plan_ancestry(), successor=forged
        )


@pytest.mark.parametrize(
    "name", ("ENDPOINT_TRIAL_PREDECESSOR_RAW_SHA256", "ENDPOINT_TRIAL_PREDECESSOR_PLAN_SHA256")
)
def test_trial_ancestry_refuses_replaced_predecessor_pins(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    monkeypatch.setattr(ancestry_module, name, "f" * 64)
    with pytest.raises(ValueError, match="boundary changed"):
        derive_candidate_selection_plan_reactivation(
            capability,
            candidate_model_id="deepseek/deepseek-v4-pro-0813",
            provider_endpoint="fireworks",
            candidate_endpoint_trial=True,
        )


def test_trial_ancestry_refuses_replaced_binding_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    monkeypatch.setattr(
        CandidateSelectionPlanEndpointTrialBinding, "__pydantic_validator__", object()
    )
    with pytest.raises(ValueError, match="boundary changed"):
        derive_candidate_selection_plan_reactivation(
            capability,
            candidate_model_id="deepseek/deepseek-v4-pro-0813",
            provider_endpoint="fireworks",
            candidate_endpoint_trial=True,
        )


def test_trial_cannot_be_derived_from_a_data_only_ancestry_capability() -> None:
    forged = object.__new__(VerifiedCandidateSelectionPlanAncestry)
    with pytest.raises(ValueError):
        derive_candidate_selection_plan_reactivation(
            forged,
            candidate_model_id="deepseek/deepseek-v4-pro-0813",
            provider_endpoint="fireworks",
            candidate_endpoint_trial=True,
        )
