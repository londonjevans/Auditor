"""Exact operator legacy allowance cannot substitute for authenticated cost ancestry."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

import mmaudit.models.candidate_plan_ancestry as ancestry_module
from mmaudit.models.candidate_plan_ancestry import (
    LEGACY_COST_PREDECESSOR_PLAN_SHA256,
    LEGACY_COST_PREDECESSOR_RAW_SHA256,
    CandidateSelectionPlanAncestryError,
    resolve_verified_candidate_selection_plan_ancestry,
    validate_candidate_selection_plan_reactivation,
)
from mmaudit.models.candidate_selection import CandidateSelectionPlan, load_candidate_selection_plan
from mmaudit.models.legacy_cost_allowance import (
    LegacyUncertainCostAllowance,
    LegacyUncertainCostEntry,
)
from mmaudit.reporting.json_report import stable_json
from scripts.validate_governance_state import validate_current_selection_plan
from tests.unit.test_candidate_plan_cost_transition import _cost_plan, _seal

ROOT = Path(__file__).parents[2]


def _legacy_plan(**updates: Any) -> CandidateSelectionPlan:
    return _cost_plan(allow_exact_legacy_uncertainty=True, **updates)


def _reseal_policy(payload: dict[str, Any]) -> CandidateSelectionPlan:
    selection = payload["authenticated_runner_selection"]
    profile = selection["route_predicate_profile"]
    policy = profile["operator_reservation_policy"]
    _seal(policy["legacy_uncertain_allowance"], "allowance_sha256")
    _seal(policy, "policy_sha256")
    _seal(profile, "profile_sha256")
    for constraint in selection["route_constraints"]:
        constraint["profile_sha256"] = profile["profile_sha256"]
        _seal(constraint, "constraint_sha256")
    _seal(selection, "role_assignment_sha256")
    binding = payload["operator_cost_transition_binding"]
    binding["replacement_profile_sha256"] = profile["profile_sha256"]
    binding["replacement_constraints"] = selection["route_constraints"]
    binding["reservation_policy_sha256"] = policy["policy_sha256"]
    _seal(binding, "binding_sha256")
    _seal(payload, "plan_sha256")
    return CandidateSelectionPlan.model_validate_json(json.dumps(payload), strict=True)


def test_exact_legacy_successor_preserves_every_other_policy_route_and_authority() -> None:
    old, new = _cost_plan(), _legacy_plan()
    assert (
        hashlib.sha256(stable_json(old).encode()).hexdigest() == LEGACY_COST_PREDECESSOR_RAW_SHA256
    )
    assert old.plan_sha256 == LEGACY_COST_PREDECESSOR_PLAN_SHA256
    assert new.schema_version == "1.11" and new.predecessor_plan_sha256 == old.plan_sha256
    excluded = {
        "schema_version",
        "predecessor_plan_sha256",
        "operator_cost_transition_binding",
        "authenticated_runner_selection",
        "plan_sha256",
    }
    assert new.model_dump(exclude=excluded) == old.model_dump(exclude=excluded)
    before, after = old.authenticated_runner_selection, new.authenticated_runner_selection
    assert before is not None and after is not None
    excluded = {"route_predicate_profile", "route_constraints", "role_assignment_sha256"}
    assert before.model_dump(exclude=excluded) == after.model_dump(exclude=excluded)
    before_profile, after_profile = before.route_predicate_profile, after.route_predicate_profile
    excluded = {"operator_reservation_policy", "profile_sha256"}
    assert before_profile.model_dump(exclude=excluded) == after_profile.model_dump(exclude=excluded)
    for first, second in zip(before.route_constraints, after.route_constraints, strict=True):
        excluded = {"profile_sha256", "constraint_sha256"}
        assert first.model_dump(exclude=excluded) == second.model_dump(exclude=excluded)
    before_policy = before_profile.operator_reservation_policy
    after_policy = after_profile.operator_reservation_policy
    assert before_policy is not None and after_policy is not None
    excluded = {"schema_version", "policy_sha256", "legacy_uncertain_allowance"}
    assert before_policy.model_dump(exclude=excluded) == after_policy.model_dump(exclude=excluded)
    allowance = after_policy.legacy_uncertain_allowance
    assert allowance is not None
    assert (
        allowance.allowance_sha256
        == "9ddd9264c92d1b9908b6be7f7f70350e0b952852018ea3db7c084e411af3f29d"
    )
    assert after_policy.unknown_billing_blocks_new_work is True
    assert all(
        row.status == "uncertain_accounted" and row.actual_cost_usd is None
        for row in allowance.entries
    )
    assert new.operator_cost_transition_binding is not None
    assert new.operator_cost_transition_binding.operator_decision_id == "OP-COSTLEGACY-2026-09-11"
    validate_current_selection_plan(new)


def test_active_plan_is_exact_authenticated_legacy_successor_without_external_actions() -> None:
    active = ROOT / "config/models.selection-plan.json"
    before = active.read_bytes()
    expected = _legacy_plan()
    assert load_candidate_selection_plan(active) == expected
    assert before == stable_json(expected).encode()
    validate_current_selection_plan(expected)
    assert active.read_bytes() == before


@pytest.mark.parametrize("row_index", (0, 1))
@pytest.mark.parametrize("field", ("request_id", "reservation_id", "created_at", "updated_at"))
def test_coherent_same_prefix_or_historical_identity_substitution_refuses_ancestry(
    row_index: int,
    field: str,
) -> None:
    payload = _legacy_plan().model_dump(mode="json")
    row = payload["authenticated_runner_selection"]["route_predicate_profile"][
        "operator_reservation_policy"
    ]["legacy_uncertain_allowance"]["entries"][row_index]
    row[field] = {
        "request_id": row["request_id"].partition(":")[0] + ":" + "f" * 64,
        "reservation_id": "f" * 32,
        "created_at": "2026-08-01T00:00:00+00:00",
        "updated_at": "2026-08-31T00:00:00+00:00",
    }[field]
    coherent = _reseal_policy(payload)
    with pytest.raises(CandidateSelectionPlanAncestryError, match="exact derivation"):
        validate_candidate_selection_plan_reactivation(
            resolve_verified_candidate_selection_plan_ancestry(),
            successor=coherent,
        )


@pytest.mark.parametrize(
    "field,value", (("minimum_prompt_tokens", 60000), ("maximum_request_bytes", 500000))
)
def test_legacy_allowance_cannot_carry_another_coherently_hashed_policy_change(
    field: str, value: int
) -> None:
    payload = _legacy_plan().model_dump(mode="json")
    profile = payload["authenticated_runner_selection"]["route_predicate_profile"]
    target = profile if field == "minimum_prompt_tokens" else profile["operator_reservation_policy"]
    target[field] = value
    coherent = _reseal_policy(payload)
    with pytest.raises(CandidateSelectionPlanAncestryError, match="exact derivation"):
        validate_current_selection_plan(coherent)


@pytest.mark.parametrize(
    "mutation",
    (
        "old_plan_version",
        "old_binding_version",
        "old_decision",
        "old_policy_version",
        "missing_allowance",
        "null_allowance",
        "third_row",
    ),
)
def test_schema_and_runtime_refuse_legacy_transition_downgrade_or_broadened_allowance(
    mutation: str,
) -> None:
    payload = _legacy_plan().model_dump(mode="json")
    validator = Draft202012Validator(CandidateSelectionPlan.model_json_schema())
    validator.validate(payload)
    binding = payload["operator_cost_transition_binding"]
    policy = payload["authenticated_runner_selection"]["route_predicate_profile"][
        "operator_reservation_policy"
    ]
    if mutation == "old_plan_version":
        payload["schema_version"] = "1.10"
    elif mutation == "old_binding_version":
        binding["schema_version"] = "1.0"
    elif mutation == "old_decision":
        binding["operator_decision_id"] = "OP-COST-2026-09-09"
    elif mutation == "old_policy_version":
        policy["schema_version"] = "1.0"
    elif mutation == "missing_allowance":
        policy.pop("legacy_uncertain_allowance")
    elif mutation == "null_allowance":
        policy["legacy_uncertain_allowance"] = None
    else:
        policy["legacy_uncertain_allowance"]["entries"].append(
            policy["legacy_uncertain_allowance"]["entries"][0]
        )
    assert list(validator.iter_errors(payload))
    with pytest.raises(ValueError):
        CandidateSelectionPlan.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    "updates",
    (
        {"reserve_then_reconcile_costs": False},
        {"refresh_endpoint_inventory": False},
        {"provider_endpoint": "unapproved-provider"},
    ),
)
def test_legacy_allowance_requires_exact_preceding_transitions(updates: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        _legacy_plan(**updates)


@pytest.mark.parametrize("value", (1, "true", None))
def test_legacy_transition_requires_literal_boolean(value: object) -> None:
    with pytest.raises(ValueError, match="must be boolean"):
        _cost_plan(allow_exact_legacy_uncertainty=value)


@pytest.mark.parametrize(
    "name",
    (
        "LEGACY_COST_PREDECESSOR_RAW_SHA256",
        "LEGACY_COST_PREDECESSOR_PLAN_SHA256",
        "_LEGACY_COST_ROWS",
    ),
)
def test_legacy_transition_pins_exact_predecessor_and_approved_metadata(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    monkeypatch.setattr(ancestry_module, name, "f" * 64)
    with pytest.raises(CandidateSelectionPlanAncestryError, match="boundary changed"):
        _cost_plan(capability, allow_exact_legacy_uncertainty=True)


@pytest.mark.parametrize("model_type", (LegacyUncertainCostAllowance, LegacyUncertainCostEntry))
def test_legacy_transition_refuses_replaced_allowance_validation(
    monkeypatch: pytest.MonkeyPatch, model_type: type[Any]
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    monkeypatch.setattr(model_type, "__pydantic_validator__", object())
    with pytest.raises(CandidateSelectionPlanAncestryError, match="boundary changed"):
        _cost_plan(capability, allow_exact_legacy_uncertainty=True)
