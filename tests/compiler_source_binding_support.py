"""Internally consistent synthetic metadata tampering for original-input refusal tests."""

from __future__ import annotations

from typing import Any, Literal

from mmaudit.benchmark.mutation_discovery import PortfolioMutationDiscovery
from mmaudit.benchmark.mutations import MutationApplicabilityPlan, score_planned_mutation_campaigns
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.orchestration.mutation_pipeline import MutationProjectExecution
from mmaudit.solidity.properties import FoundryPropertyTestMapping
from mmaudit.solidity.property_reachability import CompilerPropertyReachability


def inconsistent_declared_source_map(
    project: MutationProjectExecution, change: Literal["omitted", "map-digest"]
) -> MutationProjectExecution:
    """Keep declarations self-consistent so raw-input reconstruction must detect the lie."""
    plan = project.plan
    assert plan is not None and plan.discovery is not None and plan.property_tests is not None
    mapping = plan.property_tests
    graph = mapping.compiler_reachability
    assert graph is not None

    def alter(raw: dict[str, Any], digest_key: str) -> dict[str, Any]:
        changed = 0
        for source in raw["sources"]:
            bindings = source.get("compiler_source_bindings", [])
            if bindings:
                changed += len(bindings)
                if change == "omitted":
                    source.pop("compiler_source_bindings")
                else:
                    for binding in bindings:
                        binding["transformation"]["boundary_map_sha256"] = "0" * 64
        assert changed
        raw[digest_key] = canonical_sha256({k: v for k, v in raw.items() if k != digest_key})
        return raw

    graph = CompilerPropertyReachability.model_validate(
        alter(graph.model_dump(mode="json"), "reachability_sha256")
    )
    discovery = PortfolioMutationDiscovery.model_validate(
        alter(plan.discovery.model_dump(mode="json"), "discovery_sha256")
    )
    mapping_fields = {
        k: getattr(mapping, k) for k in type(mapping).model_fields if k != "mapping_sha256"
    }
    mapping_fields["compiler_reachability"] = graph
    mapping = FoundryPropertyTestMapping.sealed(**mapping_fields)
    plan_fields = {k: getattr(plan, k) for k in type(plan).model_fields if k != "plan_sha256"}
    plan_fields.update(discovery=discovery, property_tests=mapping)
    changed_plan = MutationApplicabilityPlan.sealed(**plan_fields)
    assert changed_plan != plan
    fields = project.model_dump(mode="python")
    fields.update(
        plan=changed_plan,
        campaigns=[],
        executions=[],
        score=score_planned_mutation_campaigns(
            plan=changed_plan, campaigns=[], minimum_property_kill_score=0.95
        ),
        limitations=["Synthetic inconsistent mapping; no execution or authority claimed."],
    )
    return MutationProjectExecution.model_validate(fields)
