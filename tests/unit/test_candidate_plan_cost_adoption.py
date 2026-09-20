"""Active-plan custody must replay the operator cost transition, not trust its hash."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from mmaudit.models.candidate_plan_ancestry import (
    COST_PREDECESSOR_PLAN_SHA256,
    COST_PREDECESSOR_RAW_SHA256,
    CandidateSelectionPlanAncestryError,
    derive_candidate_selection_plan_reactivation,
    resolve_verified_candidate_selection_plan_ancestry,
)
from mmaudit.models.candidate_selection import CandidateSelectionPlan, load_candidate_selection_plan
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json
from scripts.validate_governance_state import validate_current_selection_plan
from tests.unit.test_candidate_plan_cost_transition import _cost_plan, _seal
from tests.unit.test_candidate_plan_route_refresh import _refresh

ROOT = Path(__file__).parents[2]
PREDECESSOR = ROOT / "tests/fixtures/model_selection/provider-ceiling-plan-v1.9.json"


def test_archived_provider_ceiling_predecessor_is_exact_and_replayable() -> None:
    raw = PREDECESSOR.read_bytes()
    predecessor = load_candidate_selection_plan(PREDECESSOR)
    assert len(raw) == 20_651
    assert hashlib.sha256(raw).hexdigest() == COST_PREDECESSOR_RAW_SHA256
    assert predecessor.plan_sha256 == COST_PREDECESSOR_PLAN_SHA256
    assert raw == stable_json(predecessor).encode()
    assert predecessor == _refresh(resolve_verified_candidate_selection_plan_ancestry())
    validate_current_selection_plan(predecessor)


@pytest.mark.parametrize("version", ("1.7", "1.9", "1.10"))
def test_current_governance_accepts_only_supported_exact_plan_generations(version: str) -> None:
    active = ROOT / "config/models.selection-plan.json"
    before = active.read_bytes()
    plan = (
        _cost_plan()
        if version == "1.10"
        else load_candidate_selection_plan(PREDECESSOR)
        if version == "1.9"
        else load_candidate_selection_plan(
            ROOT / "tests/fixtures/model_selection/unavailable-plan-v1.7.json"
        )
    )
    assert plan.schema_version == version
    validate_current_selection_plan(plan)
    assert active.read_bytes() == before


def coherent_cost_successor_mutation(field: str) -> CandidateSelectionPlan:
    """Build valid nonauthorizing JSON which still cannot substitute for ancestry."""

    payload: dict[str, Any] = _cost_plan().model_dump(mode="json")
    selection = payload["authenticated_runner_selection"]
    binding = payload["operator_cost_transition_binding"]
    if field in {"ancestry_evidence_sha256", "predecessor_raw_sha256"}:
        binding[field] = canonical_sha256({"changed": field, "original": binding[field]})
    else:
        profile = selection["route_predicate_profile"]
        profile[field] = {
            "minimum_prompt_tokens": 60_000,
            "required_output_tokens": 2_048,
            "minimum_context_tokens": 80_000,
        }[field]
        if field == "required_output_tokens":
            profile["required_completion_tokens"] = (
                profile[field] + profile["reserved_reasoning_tokens"]
            )
        _seal(profile, "profile_sha256")
        for constraint in selection["route_constraints"]:
            constraint["profile_sha256"] = profile["profile_sha256"]
            _seal(constraint, "constraint_sha256")
        _seal(selection, "role_assignment_sha256")
        binding["replacement_profile_sha256"] = profile["profile_sha256"]
        binding["replacement_constraints"] = selection["route_constraints"]
    _seal(binding, "binding_sha256")
    _seal(payload, "plan_sha256")
    return CandidateSelectionPlan.model_validate_json(json.dumps(payload), strict=True)


@pytest.mark.parametrize(
    "field",
    (
        "ancestry_evidence_sha256",
        "predecessor_raw_sha256",
        "minimum_prompt_tokens",
        "required_output_tokens",
        "minimum_context_tokens",
    ),
)
def test_current_governance_refuses_coherently_resealed_cost_or_security_custody(
    field: str,
) -> None:
    plan = coherent_cost_successor_mutation(field)
    assert plan.schema_version == "1.10"
    with pytest.raises(CandidateSelectionPlanAncestryError, match="differs from exact derivation"):
        validate_current_selection_plan(plan)


def test_current_governance_does_not_broaden_acceptance_to_other_ancestry_versions() -> None:
    plan = derive_candidate_selection_plan_reactivation(
        resolve_verified_candidate_selection_plan_ancestry(),
        candidate_model_id="anthropic/claude-opus-5",
        provider_endpoint="amazon-bedrock",
    )
    assert plan.schema_version == "1.8"
    with pytest.raises(ValueError, match="retained nonauthorizing V1 custody"):
        validate_current_selection_plan(plan)


def test_cost_successor_changes_only_the_explicit_pair_of_cost_predicates() -> None:
    old = load_candidate_selection_plan(PREDECESSOR).authenticated_runner_selection
    new = _cost_plan().authenticated_runner_selection
    assert old is not None and new is not None
    old_ids = set(old.route_predicate_profile.predicate_ids)
    new_ids = set(new.route_predicate_profile.predicate_ids)
    assert old_ids - new_ids == {"PRICE_CAP_EXPRESSIBILITY", "PRICE_CAP_NO_WEAKER"}
    assert new_ids - old_ids == {"RESERVATION_PRICING_AVAILABLE", "PROVIDER_CAPPED_SUBSET_BOUND"}
    assert len(new_ids & old_ids) == 27
    assert old.distinct_root_lineages_verified is new.distinct_root_lineages_verified is False
