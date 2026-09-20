"""Provider-free three-role planning; no metadata or execution authority is supplied."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

import mmaudit.models.candidate_selection as selection_module
from mmaudit.models.candidate_plan_ancestry import (
    CandidateSelectionPlanAncestryError,
    VerifiedCandidateSelectionPlanAncestry,
    candidate_selection_plan_ancestry_projection,
    derive_candidate_selection_plan_reactivation,
    resolve_verified_candidate_selection_plan_ancestry,
    validate_candidate_selection_plan_reactivation,
)
from mmaudit.models.candidate_selection import (
    CandidateSelectionError,
    CandidateSelectionPlan,
    CandidateSelectionPlanRoleRouteTransitionBinding,
    CandidateSelectionRoleRouteRefresh,
    load_candidate_selection_plan,
    seal_authenticated_runner_selection,
    validate_candidate_selection_plan_successor,
)
from mmaudit.models.route_constraints import (
    ExactRouteConstraint,
    ExactRouteRole,
    ProviderPriceCapAlgorithm,
    RoutePredicateProfile,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json

ROOT = Path(__file__).parents[2]
PREDECESSOR = ROOT / "tests/fixtures/model_selection/unavailable-plan-v1.7.json"
ROUTES = {
    ExactRouteRole.CANDIDATE: ("deepseek/deepseek-v4-pro-0813", "together"),
    ExactRouteRole.PRIMARY_JUDGE: ("z-ai/glm-5.2", "deepinfra/fp4"),
    ExactRouteRole.REPLAY_JUDGE: ("moonshotai/kimi-k3", "together"),
}


def _refresh(capability: VerifiedCandidateSelectionPlanAncestry) -> CandidateSelectionPlan:
    return derive_candidate_selection_plan_reactivation(
        capability,
        candidate_model_id=ROUTES[ExactRouteRole.CANDIDATE][0],
        provider_endpoint=ROUTES[ExactRouteRole.CANDIDATE][1],
        refresh_endpoint_inventory=True,
        primary_judge_provider_endpoint=ROUTES[ExactRouteRole.PRIMARY_JUDGE][1],
        replay_judge_provider_endpoint=ROUTES[ExactRouteRole.REPLAY_JUDGE][1],
    )


def test_three_role_refresh_preserves_exact_ancestry_and_security_profile() -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    projection = candidate_selection_plan_ancestry_projection(capability)
    successor = _refresh(capability)
    predecessor = load_candidate_selection_plan(PREDECESSOR)
    unavailable = predecessor.authenticated_runner_unavailability
    assert unavailable is not None
    assert successor.schema_version == "1.9"
    assert successor.predecessor_plan_sha256 == predecessor.plan_sha256
    assert successor.authenticated_runner_unavailability is None
    assert successor.ancestry_transition_binding is None
    binding = successor.ancestry_route_transition_binding
    assert binding is not None
    assert binding.operator_decision_id == "OP-COST-2026-09-09"
    assert binding.ancestry_evidence_sha256 == projection.projection_sha256
    assert (
        binding.unavailable_predecessor_raw_sha256 == projection.unavailable_predecessor_raw_sha256
    )
    assert (
        binding.predecessor_judge_constraint_sha256s == projection.retained_judge_constraint_sha256s
    )
    selection = successor.authenticated_runner_selection
    assert selection is not None
    assert selection.route_predicate_profile == unavailable.route_predicate_profile
    assert selection.route_predicate_profile.price_cap_algorithm is (
        ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1
    )
    assert selection.distinct_root_lineages_verified is False
    assert {
        row.role: (row.exact_model_id, row.provider_endpoint) for row in selection.route_constraints
    } == ROUTES
    assert len(selection.route_constraints) == 3
    assert tuple(row.role for row in binding.route_refreshes) == tuple(ExactRouteRole)
    originals = {entry.exact_model_id: entry for entry in predecessor.entries}
    refreshed = {row.inventory_refresh.exact_model_id: row for row in binding.route_refreshes}
    for entry in successor.entries:
        original = originals[entry.exact_model_id]
        if entry.exact_model_id not in refreshed:
            assert entry == original
            continue
        row = refreshed[entry.exact_model_id]
        assert row.inventory_refresh.predecessor_entry_sha256 == original.entry_sha256
        assert entry.allowed_provider_endpoints == (row.replacement_constraint.provider_endpoint,)
        assert entry.priority_rank == original.priority_rank
        assert entry.advisory_lineage_group == original.advisory_lineage_group
        assert row.inventory_refresh.endpoint_authority is False
    assert successor.source_bindings == predecessor.source_bindings
    for field, value in successor.model_dump(mode="json").items():
        if field.endswith("_authorized") or field == "serialized_authority":
            assert value is False


def test_three_role_refresh_replays_but_cannot_use_ordinary_successor_authority() -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    first = _refresh(capability)
    second = _refresh(capability)
    assert first == second
    loaded = CandidateSelectionPlan.model_validate_json(first.model_dump_json(), strict=True)
    assert validate_candidate_selection_plan_reactivation(capability, successor=loaded) == first
    with pytest.raises(CandidateSelectionError, match="ancestry"):
        validate_candidate_selection_plan_successor(
            predecessor=load_candidate_selection_plan(PREDECESSOR), successor=first
        )


@pytest.mark.parametrize(
    ("model_id", "endpoint", "primary", "replay", "message"),
    (
        ("not/in-the-plan", "together", "deepinfra/fp4", "together", "outside the plan"),
        ("z-ai/glm-5.2", "together", "deepinfra/fp4", "together", "collide with a judge"),
        ("moonshotai/kimi-k3", "together", "deepinfra/fp4", "together", "collide with a judge"),
        ("deepseek/deepseek-v4-pro-0813", "parasail/fp8", "deepinfra/fp4", "together", "revoked"),
        (
            "deepseek/deepseek-v4-pro-20260813",
            "parasail/fp8",
            "deepinfra/fp4",
            "together",
            "outside the plan",
        ),
        ("deepseek/deepseek-v4-pro-0813", "Together", "deepinfra/fp4", "together", "lowercase"),
        (
            "deepseek/deepseek-v4-pro-0813",
            "together",
            "sail-research/fp8",
            "together",
            "previously unlisted",
        ),
        ("deepseek/deepseek-v4-pro-0813", "", "deepinfra/fp4", "together", "endpoint is not exact"),
    ),
)
def test_three_role_refresh_refuses_ineligible_or_implicit_assignments(
    model_id: str, endpoint: str, primary: str, replay: str, message: str
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    with pytest.raises(ValueError, match=message):
        derive_candidate_selection_plan_reactivation(
            capability,
            candidate_model_id=model_id,
            provider_endpoint=endpoint,
            refresh_endpoint_inventory=True,
            primary_judge_provider_endpoint=primary,
            replay_judge_provider_endpoint=replay,
        )


def _reseal(payload: dict[str, Any], hash_key: str) -> None:
    payload[hash_key] = canonical_sha256(
        {key: value for key, value in payload.items() if key != hash_key}
    )


@pytest.mark.parametrize(
    "field",
    (
        "selected_ancestor_raw_sha256",
        "ancestry_evidence_sha256",
        "selected_ancestor_role_assignment_sha256",
        "unavailable_state_sha256",
        "predecessor_judge_constraint_sha256s",
        "predecessor_entry_sha256",
    ),
)
def test_three_role_refresh_rejects_coherently_resealed_custody(field: str) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    payload = _refresh(capability).model_dump(mode="json")
    binding = payload["ancestry_route_transition_binding"]
    if field == "predecessor_judge_constraint_sha256s":
        binding[field] = sorted(["0" * 64, binding[field][1]])
    elif field == "predecessor_entry_sha256":
        refresh = binding["route_refreshes"][0]["inventory_refresh"]
        refresh[field] = "0" * 64
        _reseal(refresh, "refresh_sha256")
    else:
        binding[field] = "0" * 64
    _reseal(binding, "binding_sha256")
    _reseal(payload, "plan_sha256")
    forged = CandidateSelectionPlan.model_validate_json(stable_json(payload), strict=True)
    with pytest.raises(CandidateSelectionPlanAncestryError, match="differs from exact derivation"):
        validate_candidate_selection_plan_reactivation(capability, successor=forged)


@pytest.mark.parametrize("schema_source", ("model", "exported"))
@pytest.mark.parametrize(
    "invalidity",
    (
        "missing_binding",
        "null_binding",
        "missing_selection",
        "null_selection",
        "downgrade",
        "unknown_role",
        "authority",
        "price_upgrade_authority",
        "legacy_binding",
    ),
)
def test_three_role_refresh_schema_and_model_fail_closed(
    invalidity: str, schema_source: str
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    payload = _refresh(capability).model_dump(mode="json")
    schema = (
        CandidateSelectionPlan.model_json_schema()
        if schema_source == "model"
        else json.loads((ROOT / "schemas/candidate_selection_plan.schema.json").read_bytes())
    )
    validator = Draft202012Validator(schema)
    assert validator.is_valid(payload)
    if invalidity in {"missing_binding", "null_binding"}:
        field = "ancestry_route_transition_binding"
        if invalidity == "missing_binding":
            del payload[field]
        else:
            payload[field] = None
    elif invalidity in {"missing_selection", "null_selection"}:
        field = "authenticated_runner_selection"
        if invalidity == "missing_selection":
            del payload[field]
        else:
            payload[field] = None
    elif invalidity == "downgrade":
        payload["schema_version"] = "1.8"
    elif invalidity == "unknown_role":
        payload["ancestry_route_transition_binding"]["route_refreshes"][0]["role"] = "operator"
    elif invalidity == "authority":
        payload["ancestry_route_transition_binding"]["provider_call_authorized"] = True
    elif invalidity == "price_upgrade_authority":
        payload["ancestry_route_transition_binding"]["price_cap_profile_upgrade_authorized"] = True
    else:
        payload["ancestry_transition_binding"] = None
    _reseal(payload, "plan_sha256")
    assert not validator.is_valid(payload)
    with pytest.raises(ValueError):
        CandidateSelectionPlan.model_validate_json(stable_json(payload), strict=True)


@pytest.mark.parametrize(
    "target", (CandidateSelectionPlanRoleRouteTransitionBinding, CandidateSelectionRoleRouteRefresh)
)
def test_three_role_refresh_rejects_changed_model_runtime(
    monkeypatch: pytest.MonkeyPatch, target: type[Any]
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    monkeypatch.setattr(target, "__getattribute__", object.__getattribute__)
    with pytest.raises(CandidateSelectionPlanAncestryError, match="runtime boundary changed"):
        _refresh(capability)


def test_three_role_refresh_rejects_changed_refresh_sealer(monkeypatch: pytest.MonkeyPatch) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    target = selection_module._seal_candidate_selection_endpoint_inventory_refresh
    monkeypatch.setattr(target, "__code__", target.__code__.replace(co_filename="changed.py"))
    with pytest.raises(CandidateSelectionPlanAncestryError, match="runtime boundary changed"):
        _refresh(capability)


def test_three_role_refresh_rejects_serialized_or_forged_capability() -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    forged = object.__new__(VerifiedCandidateSelectionPlanAncestry)
    with pytest.raises(CandidateSelectionPlanAncestryError, match="absent or fork-inherited"):
        _refresh(forged)
    successor = _refresh(capability)
    with pytest.raises(CandidateSelectionPlanAncestryError, match="absent or fork-inherited"):
        validate_candidate_selection_plan_reactivation(forged, successor=successor)


def test_three_role_refresh_cannot_coherently_substitute_a_v2_price_profile() -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    successor = _refresh(capability)
    selection = successor.authenticated_runner_selection
    assert selection is not None
    old = selection.route_predicate_profile
    profile = RoutePredicateProfile.build(
        reasoning_policy_sha256=old.reasoning_policy_sha256,
        reasoning_role_profile_sha256=old.reasoning_role_profile_sha256,
        reasoning_role_binding_sha256=old.reasoning_role_binding_sha256,
        reasoning_control_profile_sha256=old.reasoning_control_profile_sha256,
        reserved_reasoning_tokens=old.reserved_reasoning_tokens,
        minimum_prompt_tokens=old.minimum_prompt_tokens,
        required_output_tokens=old.required_output_tokens,
        minimum_context_tokens=old.minimum_context_tokens,
        price_cap_algorithm=ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2,
    )
    constraints = tuple(
        ExactRouteConstraint.build(
            role=row.role,
            exact_model_id=row.exact_model_id,
            provider_endpoint=row.provider_endpoint,
            profile=profile,
        )
        for row in selection.route_constraints
    )
    rebuilt = seal_authenticated_runner_selection(
        candidate_model_id=selection.candidate_model_id,
        primary_judge_model_id=selection.primary_judge_model_id,
        replay_judge_model_id=selection.replay_judge_model_id,
        route_predicate_profile=profile,
        route_constraints=constraints,
    )
    payload = successor.model_dump(mode="json")
    payload["authenticated_runner_selection"] = rebuilt.model_dump(mode="json")
    binding = payload["ancestry_route_transition_binding"]
    binding["retained_route_predicate_profile_sha256"] = profile.profile_sha256
    for row, constraint in zip(binding["route_refreshes"], constraints, strict=True):
        row["replacement_constraint"] = constraint.model_dump(mode="json")
    _reseal(binding, "binding_sha256")
    _reseal(payload, "plan_sha256")
    for schema in (
        CandidateSelectionPlan.model_json_schema(),
        json.loads((ROOT / "schemas/candidate_selection_plan.schema.json").read_bytes()),
    ):
        assert not Draft202012Validator(schema).is_valid(payload)
    with pytest.raises(ValueError, match="role transition"):
        CandidateSelectionPlan.model_validate_json(stable_json(payload), strict=True)


def test_active_plan_is_the_exact_canonical_derived_transition() -> None:
    import hashlib

    from scripts.validate_governance_state import validate_current_selection_plan
    from tests.unit.test_candidate_plan_cost_transition import _cost_plan

    path = ROOT / "config/models.selection-plan.json"
    content = path.read_bytes()
    plan = load_candidate_selection_plan(path)
    assert plan == _cost_plan(
        resolve_verified_candidate_selection_plan_ancestry(), allow_exact_legacy_uncertainty=True
    )
    assert content == stable_json(plan).encode()
    assert len(content) == 20_016
    assert hashlib.sha256(content).hexdigest() == (
        "7af8d0eeeade437767c965482c563dafa893ce76eee818333fd728daab7cdbb0"
    )
    assert plan.plan_sha256 == "a868db571f4ced1cba9db7aa53d9a6b56b05c99bb465618d445ca940cd73313c"
    validate_current_selection_plan(plan)
    guide = (ROOT / "docs/models/model_selection.md").read_text()
    assert plan.plan_sha256 in guide
    assert hashlib.sha256(content).hexdigest() in guide


def test_current_governance_replays_ancestry_instead_of_accepting_a_resealed_plan() -> None:
    from scripts.validate_governance_state import validate_current_selection_plan

    plan = _refresh(resolve_verified_candidate_selection_plan_ancestry())
    payload = plan.model_dump(mode="json")
    binding = payload["ancestry_route_transition_binding"]
    binding["selected_ancestor_raw_sha256"] = "0" * 64
    _reseal(binding, "binding_sha256")
    _reseal(payload, "plan_sha256")
    coherent = CandidateSelectionPlan.model_validate_json(stable_json(payload), strict=True)
    with pytest.raises(CandidateSelectionPlanAncestryError, match="differs from exact derivation"):
        validate_current_selection_plan(coherent)
