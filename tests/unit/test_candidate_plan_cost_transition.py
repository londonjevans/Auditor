"""An operator cost relaxation must retain exact authenticated route ancestry."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

import mmaudit.models.candidate_plan_ancestry as ancestry_module
from mmaudit.models.candidate_plan_ancestry import (
    CandidateSelectionPlanAncestryError,
    VerifiedCandidateSelectionPlanAncestry,
    derive_candidate_selection_plan_reactivation,
    resolve_verified_candidate_selection_plan_ancestry,
    validate_candidate_selection_plan_reactivation,
)
from mmaudit.models.candidate_selection import (
    CandidateSelectionPlan,
    CandidateSelectionPlanCostTransitionBinding,
    load_candidate_selection_plan,
)
from mmaudit.models.route_constraints import ExactRouteRole, RouteCostReservationPolicy
from mmaudit.orchestration.manifest import canonical_sha256
from tests.unit.test_candidate_plan_route_refresh import ROUTES, _refresh

ROOT = Path(__file__).parents[2]


def _cost_plan(
    capability: VerifiedCandidateSelectionPlanAncestry | None = None, **updates: Any
) -> CandidateSelectionPlan:
    values = {
        "candidate_model_id": ROUTES[ExactRouteRole.CANDIDATE][0],
        "provider_endpoint": ROUTES[ExactRouteRole.CANDIDATE][1],
        "refresh_endpoint_inventory": True,
        "primary_judge_provider_endpoint": ROUTES[ExactRouteRole.PRIMARY_JUDGE][1],
        "replay_judge_provider_endpoint": ROUTES[ExactRouteRole.REPLAY_JUDGE][1],
        "reserve_then_reconcile_costs": True,
    }
    values.update(updates)
    return derive_candidate_selection_plan_reactivation(
        capability or resolve_verified_candidate_selection_plan_ancestry(), **values
    )


def _seal(value: dict[str, Any], field: str) -> None:
    value[field] = canonical_sha256({key: item for key, item in value.items() if key != field})


def test_cost_successor_is_opaque_replayed_and_preserves_routes_security_and_active_plan() -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    active = ROOT / "config/models.selection-plan.json"
    before = active.read_bytes()
    predecessor = _refresh(capability)
    assert predecessor == load_candidate_selection_plan(
        ROOT / "tests/fixtures/model_selection/provider-ceiling-plan-v1.9.json"
    )
    successor = _cost_plan(capability)
    assert successor.schema_version == "1.10"
    assert successor.predecessor_plan_sha256 == predecessor.plan_sha256
    assert successor.entries == predecessor.entries
    assert successor.source_bindings == predecessor.source_bindings
    assert successor.unresolved_requirements == predecessor.unresolved_requirements
    assert successor.ancestry_route_transition_binding is None
    binding = successor.operator_cost_transition_binding
    assert binding is not None
    assert binding.operator_decision_id == "OP-COST-2026-09-09"
    assert binding.predecessor_plan_sha256 == predecessor.plan_sha256
    old = predecessor.authenticated_runner_selection
    current = successor.authenticated_runner_selection
    assert old is not None and current is not None
    assert current.distinct_root_lineages_verified is False
    excluded = {"route_predicate_profile", "route_constraints", "role_assignment_sha256"}
    assert current.model_dump(mode="json", exclude=excluded) == old.model_dump(
        mode="json", exclude=excluded
    )
    cost_fields = {
        "schema_version",
        "predicate_ids",
        "operator_reservation_policy",
        "profile_sha256",
    }
    assert current.route_predicate_profile.model_dump(
        mode="json", exclude=cost_fields
    ) == old.route_predicate_profile.model_dump(mode="json", exclude=cost_fields)
    assert (
        validate_candidate_selection_plan_reactivation(capability, successor=successor) == successor
    )
    assert active.read_bytes() == before


@pytest.mark.parametrize(
    "updates",
    [
        {"reserve_then_reconcile_costs": 1},
        {"reserve_then_reconcile_costs": "true"},
        {"refresh_endpoint_inventory": False},
        {"provider_endpoint": "other-provider"},
        {"candidate_model_id": "anthropic/claude-opus-5", "provider_endpoint": "amazon-bedrock"},
        {"primary_judge_provider_endpoint": "other-provider"},
        {"replay_judge_provider_endpoint": "other-provider"},
    ],
)
def test_cost_transition_refuses_nonexplicit_or_different_predecessor(
    updates: dict[str, Any],
) -> None:
    with pytest.raises(ValueError):
        _cost_plan(**updates)


@pytest.mark.parametrize(
    "field",
    [
        "ancestry_evidence_sha256",
        "predecessor_raw_sha256",
        "predecessor_profile_sha256",
        "reservation_policy_sha256",
    ],
)
def test_coherently_resealed_cost_transition_does_not_replace_opaque_custody(field: str) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    payload = _cost_plan(capability).model_dump(mode="json")
    binding = payload["operator_cost_transition_binding"]
    binding[field] = "f" * 64
    _seal(binding, "binding_sha256")
    _seal(payload, "plan_sha256")
    with pytest.raises(ValueError):
        successor = CandidateSelectionPlan.model_validate_json(json.dumps(payload))
        validate_candidate_selection_plan_reactivation(capability, successor=successor)


@pytest.mark.parametrize(
    "mutation", ["missing", "null", "legacy_version", "legacy_profile", "authority"]
)
def test_cost_plan_refuses_schema_downgrades_and_authority(mutation: str) -> None:
    payload = _cost_plan().model_dump(mode="json")
    if mutation == "missing":
        payload.pop("operator_cost_transition_binding")
    elif mutation == "null":
        payload["operator_cost_transition_binding"] = None
    elif mutation == "legacy_version":
        payload["schema_version"] = "1.5"
    elif mutation == "legacy_profile":
        profile = payload["authenticated_runner_selection"]["route_predicate_profile"]
        profile.pop("operator_reservation_policy")
    else:
        payload["operator_cost_transition_binding"]["provider_call_authorized"] = True
    _seal(payload, "plan_sha256")
    with pytest.raises(ValueError):
        CandidateSelectionPlan.model_validate_json(json.dumps(payload))


def test_cost_transition_refuses_forged_capability() -> None:
    with pytest.raises(CandidateSelectionPlanAncestryError):
        _cost_plan(object.__new__(VerifiedCandidateSelectionPlanAncestry))


def test_cost_transition_pins_exact_predecessor_constant(monkeypatch: pytest.MonkeyPatch) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    monkeypatch.setattr(ancestry_module, "COST_PREDECESSOR_RAW_SHA256", "f" * 64)
    with pytest.raises(CandidateSelectionPlanAncestryError, match="boundary changed"):
        _cost_plan(capability)


@pytest.mark.parametrize(
    "field,value",
    [
        ("minimum_prompt_tokens", 60000),
        ("required_output_tokens", 2048),
        ("minimum_context_tokens", 80000),
    ],
)
def test_coherent_security_envelope_change_is_refused_by_opaque_replay(
    field: str, value: int
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    payload = _cost_plan(capability).model_dump(mode="json")
    selection = payload["authenticated_runner_selection"]
    profile = selection["route_predicate_profile"]
    profile[field] = value
    if field == "required_output_tokens":
        profile["required_completion_tokens"] = value + profile["reserved_reasoning_tokens"]
    _seal(profile, "profile_sha256")
    for constraint in selection["route_constraints"]:
        constraint["profile_sha256"] = profile["profile_sha256"]
        _seal(constraint, "constraint_sha256")
    _seal(selection, "role_assignment_sha256")
    binding = payload["operator_cost_transition_binding"]
    binding["replacement_profile_sha256"] = profile["profile_sha256"]
    binding["replacement_constraints"] = selection["route_constraints"]
    _seal(binding, "binding_sha256")
    _seal(payload, "plan_sha256")
    coherent = CandidateSelectionPlan.model_validate_json(json.dumps(payload))
    with pytest.raises(CandidateSelectionPlanAncestryError, match="exact derivation"):
        validate_candidate_selection_plan_reactivation(capability, successor=coherent)


@pytest.mark.parametrize("mutation", ["missing", "null", "legacy"])
def test_schema_requires_the_distinct_cost_ancestry_binding(mutation: str) -> None:
    payload = _cost_plan().model_dump(mode="json")
    validator = Draft202012Validator(CandidateSelectionPlan.model_json_schema())
    validator.validate(payload)
    if mutation == "missing":
        payload.pop("operator_cost_transition_binding")
    elif mutation == "null":
        payload["operator_cost_transition_binding"] = None
    else:
        payload["schema_version"] = "1.5"
    assert list(validator.iter_errors(payload))


@pytest.mark.parametrize(
    "model_type", [CandidateSelectionPlanCostTransitionBinding, RouteCostReservationPolicy]
)
def test_cost_ancestry_refuses_replaced_validation_runtime(
    monkeypatch: pytest.MonkeyPatch, model_type: type[Any]
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    monkeypatch.setattr(model_type, "__pydantic_validator__", object())
    with pytest.raises(CandidateSelectionPlanAncestryError, match="boundary changed"):
        _cost_plan(capability)
