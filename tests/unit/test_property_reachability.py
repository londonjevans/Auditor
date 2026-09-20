"""Compiler-reference scheduling boundaries; synthetic retained source, no execution."""

from __future__ import annotations

import copy
import socket
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any, NoReturn

import pytest

from mmaudit.benchmark.mutation_discovery import _nodes as compiler_nodes
from mmaudit.benchmark.mutations import (
    build_property_bound_inventory_mutation_plan,
    score_planned_mutation_campaigns,
)
from mmaudit.models.schemas import DynamicPropertySpec, PropertyCorpus
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.orchestration.mutation_pipeline import MutationProjectExecution
from mmaudit.orchestration.mutation_reconstruction import reconstruct_mutation_project
from mmaudit.repository.chunking import line_range_hash
from mmaudit.scanners.foundry_inventory_runner import FoundryInventoryRunResult
from mmaudit.solidity import property_reachability as reachability
from mmaudit.solidity.properties import (
    FoundryPropertyTestMapping,
    _corpus,
    bind_compiled_property_tests,
)
from tests.mutation_reconstruction_support import reconstruction_case
from tests.property_reachability_support import (
    FIXTURE,
    SOURCE,
    guard_inputs,
    retained_guard_fixture,
)


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        pytest.fail("compiler-reference mapping attempted external execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)


def graph(**kwargs: Any) -> reachability.CompilerPropertyReachability:
    return reachability.derive_compiler_property_reachability(
        inventory_result=retained_guard_fixture(),
        project_root=".",
        corpus=guard_inputs()[0],
        **kwargs,
    )


def plan(*, legacy: bool = False) -> Any:
    corpus, harnesses = guard_inputs()
    return build_property_bound_inventory_mutation_plan(
        inventory_result=retained_guard_fixture(),
        project_root=".",
        target_paths=(SOURCE,),
        corpus=corpus,
        harnesses=harnesses,
        expected_chain_id=31337,
        repository_id="synthetic",
        approved_executor_sha256="a" * 64,
        approved_isolation_policy_sha256="b" * 64,
        include_compiler_reachability=not legacy,
    )


def with_evidence(corpus: PropertyCorpus, function: str) -> PropertyCorpus:
    text = (FIXTURE / SOURCE).read_text()
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines, 1) if f"function {function}(" in line)
    end = next(i for i in range(start, len(lines) + 1) if lines[i - 1].strip() == "}")
    raw = corpus.properties[0].model_dump(mode="json")
    raw["source_evidence"][0]["location"].update(
        start_line=start,
        end_line=end,
        symbol=function,
        content_hash=line_range_hash(text, start, end),
    )
    digest = DynamicPropertySpec.calculate_hash(raw)
    raw.update(id="prop-" + digest[:24], property_hash=digest)
    return _corpus([DynamicPropertySpec.model_validate(raw)], [])


def reseal_graph(raw: dict[str, Any]) -> reachability.CompilerPropertyReachability:
    value = copy.deepcopy(raw)
    value.pop("reachability_sha256", None)
    value["reachability_sha256"] = reachability._hash(value)
    return reachability.CompilerPropertyReachability.model_validate(value)


def test_original_compiler_declarations_link_nested_helpers_and_modifiers_without_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = retained_guard_fixture()
    corpus, _ = guard_inputs()

    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        pytest.fail("pure compiler-reference graph accessed a path")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    observed = reachability.derive_compiler_property_reachability(
        inventory_result=inventory, project_root=".", corpus=corpus
    )
    names = {p.id: p.property_id for p in corpus.properties}
    assert {names[p.property_id]: len(p.reachable_ids) for p in observed.properties} == {
        "Pause": 4,
        "Fresh": 2,
    }
    assert all(len(p.seed_ids) == 1 and not p.unresolved_ids for p in observed.properties)
    assert any(e.kind == "MODIFIER_INVOCATION" for e in observed.references)
    assert any(e.caller_id == e.target_id for e in observed.references)
    assert observed == reachability.CompilerPropertyReachability.model_validate_json(
        observed.model_dump_json()
    )
    assert (
        observed.execution_validated
        is observed.qualification_eligible
        is observed.path_feasibility_established
        is False
    )


def test_new_planner_challenges_guards_without_dropping_unknown_pairs_or_expanding_targets() -> (
    None
):
    selected = plan()
    old = plan(legacy=True)
    assert len(selected.bindings) == len(selected.non_applicability) == 2
    assert not old.bindings and len(old.non_applicability) == 4
    assert selected.discovery.target_paths == (SOURCE,)
    assert len(selected.kind_accounting) == 11
    assert all(s.path == SOURCE for s in selected.specifications)
    assert old.property_tests.compiler_reachability is None
    assert "compiler_reachability" not in old.property_tests.model_dump(mode="json")
    score = score_planned_mutation_campaigns(
        plan=selected, campaigns=[], minimum_property_kill_score=0.95
    )
    assert len(score.outcomes) == 4 and all(
        o.outcome.value == "inconclusive" for o in score.outcomes
    )
    assert not score.gate_passed


@pytest.mark.parametrize("function", ["externalReference", "virtualReference", "boundedRecursion"])
def test_external_and_virtual_calls_stay_unresolved_while_cycles_are_finite(function: str) -> None:
    corpus = with_evidence(guard_inputs()[0], function)
    result = reachability.derive_compiler_property_reachability(
        inventory_result=retained_guard_fixture(), project_root=".", corpus=corpus
    )
    row = result.properties[0]
    assert len(row.seed_ids) == 1
    if function == "boundedRecursion":
        assert len(row.reachable_ids) == 2 and not row.unresolved_ids
    else:
        assert row.reachable_ids == row.seed_ids and len(row.unresolved_ids) == 1


@pytest.mark.parametrize("case", ["graph", "relations", "seeds"])
def test_graph_and_closure_bounds_refuse_instead_of_truncating(case: str) -> None:
    field = {
        "graph": "maximum_graph_items",
        "relations": "maximum_property_relations",
        "seeds": "maximum_seed_checks",
    }[case]
    with pytest.raises(ValueError, match="bound"):
        graph(limits=reachability.PropertyReachabilityLimits(**{field: 1}))


@pytest.mark.parametrize(
    "field", ["maximum_graph_items", "maximum_property_relations", "maximum_seed_checks"]
)
@pytest.mark.parametrize("value", [0, -1, True, 2_000_000])
def test_invalid_reachability_bounds_refuse(field: str, value: object) -> None:
    values: dict[str, Any] = {field: value}
    with pytest.raises(ValueError):
        reachability.PropertyReachabilityLimits(**values)


@pytest.mark.parametrize(
    "case",
    [
        "duplicate-region",
        "region-identity",
        "missing-target",
        "call-span",
        "call-identity",
        "duplicate-call",
        "build",
        "source",
        "scope",
        "seed",
        "reachable",
        "unresolved",
        "order",
        "authority",
        "feasibility",
    ],
)
def test_resealed_graph_cannot_break_identities_scope_or_complete_closure(case: str) -> None:
    raw = graph().model_dump(mode="json")
    if case == "duplicate-region":
        raw["regions"].insert(0, raw["regions"][0])
    elif case == "region-identity":
        raw["regions"][0]["start_byte"] += 1
    elif case == "missing-target":
        raw["regions"] = [r for r in raw["regions"] if r["id"] != raw["references"][0]["target_id"]]
    elif case in {"call-span", "call-identity"}:
        raw["references"][0]["start_byte"] = 99_999_999
        if case == "call-span":
            raw["references"][0]["id"] = canonical_sha256(
                {k: v for k, v in raw["references"][0].items() if k != "id"}
            )
    elif case == "duplicate-call":
        raw["references"].insert(0, raw["references"][0])
    elif case == "build":
        raw["build_info_sha256s"] = ["f" * 64]
    elif case == "source":
        raw["sources"] = raw["sources"][1:]
    elif case == "scope":
        raw["project_root"] = "outside"
    elif case == "seed":
        raw["properties"][0]["seed_ids"] = ["f" * 64]
    elif case == "reachable":
        raw["properties"][0]["reachable_ids"].pop()
    elif case == "unresolved":
        raw["properties"][0]["unresolved_ids"] = ["f" * 64]
    elif case == "order":
        raw["regions"].reverse()
    elif case == "authority":
        raw["execution_validated"] = True
    else:
        raw["path_feasibility_established"] = True
    with pytest.raises(ValueError):
        reseal_graph(raw)


@pytest.mark.parametrize("case", ["corpus", "inventory", "omit-property", "omit-seed"])
def test_mapping_rejects_resealed_graph_that_disagrees_with_original_property_selection(
    case: str,
) -> None:
    selected = plan()
    mapping = selected.property_tests
    raw = mapping.compiler_reachability.model_dump(mode="json")
    if case == "corpus":
        raw["corpus_hash"] = "f" * 64
    elif case == "inventory":
        raw["inventory_sha256"] = "f" * 64
    elif case == "omit-property":
        raw["properties"].pop()
    else:
        raw["properties"][0].update(seed_ids=[], reachable_ids=[], unresolved_ids=[])
    changed = reseal_graph(raw)
    fields = {k: getattr(mapping, k) for k in type(mapping).model_fields if k != "mapping_sha256"}
    fields["compiler_reachability"] = changed
    with pytest.raises(ValueError):
        FoundryPropertyTestMapping.sealed(**fields)


@pytest.mark.parametrize("case", ["drop-reference", "source-bytes", "forge-bytes", "build-bytes"])
def test_original_compiler_and_restart_replay_reject_changed_retained_declarations(
    tmp_path: Path,
    case: str,
) -> None:
    project, inventory = reconstruction_case(tmp_path)
    assert project.plan is not None and project.plan.property_tests is not None
    if case == "drop-reference":
        mapping = project.plan.property_tests
        assert mapping.compiler_reachability is not None
        raw = mapping.compiler_reachability.model_dump(mode="json")
        # This unvisited edge is internally consistent when removed. Only original input
        # replay can disprove the omission; the graph itself never authenticates an AST.
        seeds = {i for p in raw["properties"] for i in p["reachable_ids"]}
        raw["references"] = [e for e in raw["references"] if e["caller_id"] in seeds]
        fields = {
            k: getattr(mapping, k) for k in type(mapping).model_fields if k != "mapping_sha256"
        }
        fields["compiler_reachability"] = reseal_graph(raw)
        fields_plan = {
            k: getattr(project.plan, k)
            for k in type(project.plan).model_fields
            if k != "plan_sha256"
        }
        fields_plan["property_tests"] = FoundryPropertyTestMapping.sealed(**fields)
        changed_plan = type(project.plan).sealed(**fields_plan)
        assert changed_plan != project.plan
        fields_project = project.model_dump(mode="python")
        fields_project.update(
            plan=changed_plan,
            score=score_planned_mutation_campaigns(
                plan=changed_plan, campaigns=[], minimum_property_kill_score=0.95
            ),
        )
        selected = MutationProjectExecution.model_validate(fields_project)
        with pytest.raises(ValueError, match="full original selection"):
            reconstruct_mutation_project(
                project=selected,
                expected_project_sha256=canonical_sha256(selected.model_dump(mode="json")),
                artifact_root=tmp_path,
            )
    else:
        snapshot = inventory.compiler_inputs[0]
        if case == "source-bytes":
            snapshot = replace(
                snapshot,
                sources=(
                    replace(snapshot.sources[0], content=snapshot.sources[0].content + b" "),
                    *snapshot.sources[1:],
                ),
            )
        elif case == "forge-bytes":
            snapshot = replace(snapshot, forge_list_json=snapshot.forge_list_json + b" ")
        else:
            snapshot = replace(snapshot, build_info_jsons=(snapshot.build_info_jsons[0] + b" ",))
        inventory = replace(inventory, compiler_inputs=(snapshot,))
        with pytest.raises(ValueError):
            reachability.derive_compiler_property_reachability(
                inventory_result=inventory,
                project_root=".",
                corpus=project.plan.property_tests.corpus,
            )


def test_old_direct_only_artifact_reconstruction_does_not_add_graph_metadata(
    tmp_path: Path,
) -> None:
    project, inventory = reconstruction_case(tmp_path)
    assert project.plan is not None and project.plan.property_tests is not None
    original = project.plan
    assert original.property_tests is not None
    selected = build_property_bound_inventory_mutation_plan(
        inventory_result=inventory,
        project_root=".",
        target_paths=("src/LocalAccounting.sol",),
        corpus=original.property_tests.corpus,
        harnesses=original.property_tests.harnesses,
        repository_id=next(iter(original.property_repositories.values())),
        approved_executor_sha256=original.approved_executor_sha256,
        approved_isolation_policy_sha256=original.approved_isolation_policy_sha256,
        include_compiler_reachability=False,
    )
    fields = project.model_dump(mode="python")
    fields.update(
        plan=selected,
        score=score_planned_mutation_campaigns(
            plan=selected, campaigns=[], minimum_property_kill_score=0.95
        ),
    )
    legacy = MutationProjectExecution.model_validate(fields)
    recovered = reconstruct_mutation_project(
        project=legacy,
        expected_project_sha256=canonical_sha256(legacy.model_dump(mode="json")),
        artifact_root=tmp_path,
    )
    assert recovered.plan.model_dump_json() == selected.model_dump_json()
    assert (
        recovered.plan.property_tests is not None
        and recovered.plan.property_tests.compiler_reachability is None
    )


def test_missing_generated_assertion_does_not_gain_a_test_from_reachable_target_source() -> None:
    inventory = retained_guard_fixture()
    corpus, _ = guard_inputs()
    mapping = bind_compiled_property_tests(
        inventory_result=inventory,
        project_root=".",
        corpus=corpus,
        harnesses=[],
        expected_chain_id=31337,
    )
    assert not mapping.tests and len(mapping.unresolved_property_ids) == 2
    assert mapping.compiler_reachability is not None


def test_returned_graph_retains_original_inventory_identity() -> None:
    inventory: FoundryInventoryRunResult = retained_guard_fixture()
    selected = graph()
    assert selected.inventory_sha256 == inventory.evidence.normalized_inventory_sha256
    assert selected.evidence_authority == "COLLECTED_UNATTESTED"
    assert selected.corpus_hash == guard_inputs()[0].corpus_hash


@pytest.mark.parametrize(
    "case",
    [
        "matching",
        "null",
        "boolean",
        "wrong",
        "virtual",
        "wrong-reference",
        "reference-bool",
        "name-mismatch",
        "member-call",
    ],
)
def test_modifier_scope_and_direct_reference_shapes_are_not_inferred_from_names(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    original = graph()

    def supplied_nodes(payload: dict[str, Any], source_maps: Any = None) -> Any:
        # Inject only parsed synthetic AST fields at this pure boundary. This tests
        # interpretation/refusal, never claims the altered AST is a native observation.
        values = copy.deepcopy(compiler_nodes(payload, source_maps))
        for identity, node in list(values.items()):
            raw = dict(node.value)
            if node.kind == "ModifierDefinition" and raw.get("name") == "requireLive":
                if case in {"matching", "null", "boolean", "wrong"}:
                    raw["scope"] = {
                        "matching": node.parent,
                        "null": None,
                        "boolean": True,
                        "wrong": 0,
                    }[case]
                if case == "virtual":
                    raw["virtual"] = True
            if node.kind == "ModifierInvocation" and case in {
                "wrong-reference",
                "reference-bool",
                "name-mismatch",
            }:
                expression = dict(raw["modifierName"])
                if case == "name-mismatch":
                    expression["name"] = "unselectedName"
                else:
                    expression["referencedDeclaration"] = (
                        True if case == "reference-bool" else 9_999_999
                    )
                raw["modifierName"] = expression
            if node.kind == "FunctionCall" and case == "member-call":
                expression = dict(raw.get("expression", {}))
                if expression.get("name") == "_liveCheck":
                    expression["nodeType"] = "MemberAccess"
                    raw["expression"] = expression
            values[identity] = replace(node, value=raw)
        return values

    monkeypatch.setattr(reachability, "_nodes", supplied_nodes)
    if case in {"null", "boolean", "wrong"}:
        with pytest.raises(ValueError, match="declaration scope"):
            graph()
    elif case == "matching":
        assert graph() == original
    else:
        changed = graph()
        names = {p.id: p.property_id for p in guard_inputs()[0].properties}
        pause = next(p for p in changed.properties if names[p.property_id] == "Pause")
        assert len(pause.reachable_ids) < 4 and len(pause.unresolved_ids) == 1
