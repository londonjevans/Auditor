"""Exact generated assertion custody and complete automatic mutation denominators, offline only."""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any, NoReturn

import jsonschema  # type: ignore[import-untyped]
import pytest

from mmaudit.benchmark.mutations import (
    MutationApplicabilityPlan,
    MutationNonApplicabilityReason,
    MutationPropertyOutcome,
    MutationScorecardEvidenceOrigin,
    MutationTestOutcome,
    _score_mutation_outcomes,
    build_property_bound_inventory_mutation_plan,
    score_planned_mutation_campaigns,
)
from mmaudit.models.schemas import (
    AttackerCapabilityPolicy,
    DynamicPropertySpec,
    PropertyCorpus,
    RepositorySuiteInventoryRecord,
)
from mmaudit.solidity.properties import (
    FoundryPropertyTestMapping,
    bind_compiled_property_tests,
    generated_local_property_source,
)
from tests.mutation_inventory_support import inventory_fixture_plan, retained_fixture
from tests.property_mutation_support import (
    SOURCE,
    property_inputs,
    property_plan,
    retained_property_fixture,
)


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> NoReturn:
        pytest.fail("property mapping attempted external execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def _mapping(**changes: Any) -> FoundryPropertyTestMapping:
    corpus, harnesses = property_inputs()
    return bind_compiled_property_tests(
        **dict(
            inventory_result=retained_property_fixture(),
            project_root=".",
            corpus=corpus,
            harnesses=harnesses,
            **changes,
        )
    )


def _reseal(model: Any, **changes: Any) -> Any:
    field = "plan_sha256" if isinstance(model, MutationApplicabilityPlan) else "mapping_sha256"
    values = {k: getattr(model, k) for k in type(model).model_fields if k != field}
    return type(model).sealed(**{**values, **changes})


def _corpus_change(corpus: PropertyCorpus, field: str, value: Any) -> PropertyCorpus:
    raw = corpus.model_dump(mode="json")
    first = raw["properties"][0]
    first[field] = value
    digest = DynamicPropertySpec.calculate_hash(first)
    first.update(id="prop-" + digest[:24], property_hash=digest)
    raw["properties"].sort(key=lambda p: p["id"])
    payload = {
        "schema_version": "1.0",
        "property_hashes": [p["property_hash"] for p in raw["properties"]],
        "limitations": raw["limitations"],
    }
    raw["corpus_hash"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return PropertyCorpus.model_validate(raw)


def test_original_compiler_inputs_bind_complete_generated_assertions_without_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = retained_property_fixture()
    corpus, harnesses = property_inputs()

    def forbidden(*args: object, **kwargs: object) -> NoReturn:
        pytest.fail("in-memory property handoff attempted filesystem access")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    mapping = bind_compiled_property_tests(
        inventory_result=inventory, project_root=".", corpus=corpus, harnesses=harnesses
    )
    assert len(mapping.tests) == 2 and mapping.unresolved_property_ids == []
    assert mapping == FoundryPropertyTestMapping.model_validate_json(mapping.model_dump_json())
    assert not mapping.execution_validated and not mapping.qualification_eligible
    assert mapping.inventory_sha256 == inventory.evidence.normalized_inventory_sha256
    for test in mapping.tests:
        assert test.record in inventory.evidence.projects[0].records


def test_automatic_plan_retains_all_four_pairs_and_unsupported_classes() -> None:
    plan = property_plan(retained_property_fixture())
    assert plan.property_tests is not None and plan.compiler_inventory is not None
    assert len(plan.specifications) == len(plan.bindings) == len(plan.non_applicability) == 2
    assert len(plan.kind_accounting) == 11
    assert all(
        row.reason is MutationNonApplicabilityReason.UNSUPPORTED_PROPERTY_MAPPING
        for row in plan.non_applicability
    )
    assert plan == MutationApplicabilityPlan.model_validate_json(plan.model_dump_json())
    score = score_planned_mutation_campaigns(
        plan=plan, campaigns=[], minimum_property_kill_score=0.95
    )
    assert len(score.outcomes) == 4 and score.mutation_count == 2
    assert all(outcome.outcome is MutationTestOutcome.INCONCLUSIVE for outcome in score.outcomes)
    assert not score.gate_passed


def test_even_process_local_comparison_cannot_drop_unknown_denominator_members() -> None:
    plan = property_plan(retained_property_fixture())
    specs = {spec.id: spec for spec in plan.specifications}
    outcomes = [
        MutationPropertyOutcome(
            property_id=b.property_id,
            mutation_id=b.mutation_id,
            mutation_kind=specs[b.mutation_id].kind,
            outcome=MutationTestOutcome.KILLED,
            evidence_sha256="f" * 64,
        )
        for b in plan.bindings
    ]
    score = _score_mutation_outcomes(
        property_corpus_hash=plan.property_corpus_hash,
        expected_property_ids=list(plan.property_repositories),
        property_repositories=plan.property_repositories,
        outcomes=outcomes,
        minimum_property_kill_score=0.95,
        evidence_origin=MutationScorecardEvidenceOrigin.PROCESS_LOCAL_COMPARISON,
        applicability_plan_sha256=plan.plan_sha256,
        applicability_plan=plan,
    )
    assert len(score.outcomes) == 4 and score.overall_kill_score == 0.5
    assert sum(o.outcome is MutationTestOutcome.INCONCLUSIVE for o in score.outcomes) == 2
    assert not score.gate_passed


@pytest.mark.parametrize("count", [0, 1])
def test_missing_harnesses_remain_unresolved_and_never_use_named_inventory_fallback(
    count: int,
) -> None:
    inventory = retained_property_fixture()
    corpus, harnesses = property_inputs()
    plan = build_property_bound_inventory_mutation_plan(
        inventory_result=inventory,
        project_root=".",
        target_paths=(SOURCE,),
        corpus=corpus,
        harnesses=harnesses[:count],
        repository_id="synthetic",
        approved_executor_sha256="d" * 64,
        approved_isolation_policy_sha256="e" * 64,
    )
    assert plan.property_tests is not None
    assert len(plan.bindings) == count
    assert len(plan.non_applicability) == 4 - count
    assert len(plan.property_tests.unresolved_property_ids) == 2 - count
    assert (
        len(
            score_planned_mutation_campaigns(
                plan=plan, campaigns=[], minimum_property_kill_score=0.95
            ).outcomes
        )
        == 4
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("actors", []),
        ("campaign", {"seed": 2}),
        ("actions", []),
        ("capability_policy", {}),
    ],
)
def test_mutated_typed_property_is_not_trusted(field: str, value: Any) -> None:
    corpus, harnesses = property_inputs()
    mutated = corpus.model_copy(deep=True)
    if field == "campaign":
        value = mutated.properties[0].campaign.model_copy(update={"seed": 2})
    elif field == "capability_policy":
        value = AttackerCapabilityPolicy(attacker_controlled_actors=["alice"])
    object.__setattr__(mutated.properties[0], field, value)
    with pytest.raises(ValueError):
        bind_compiled_property_tests(
            inventory_result=retained_property_fixture(),
            project_root=".",
            corpus=mutated,
            harnesses=harnesses,
        )


@pytest.mark.parametrize("change", ["hash", "path", "range"])
def test_rehashed_property_still_requires_exact_retained_source(change: str) -> None:
    corpus, harnesses = property_inputs()
    evidence = corpus.properties[0].model_dump(mode="json")["source_evidence"]
    location = evidence[0]["location"]
    if change == "hash":
        location["content_hash"] = "f" * 64
    elif change == "path":
        location["path"] = "src/Missing.sol"
    else:
        location["end_line"] = 1_000_000
    corpus = _corpus_change(corpus, "source_evidence", evidence)
    with pytest.raises(ValueError, match="property evidence"):
        bind_compiled_property_tests(
            inventory_result=retained_property_fixture(),
            project_root=".",
            corpus=corpus,
            harnesses=harnesses,
        )


@pytest.mark.parametrize("change", ["predicate", "actor", "campaign", "deployment"])
def test_resealed_harness_or_predicate_drift_refuses(change: str) -> None:
    corpus, harnesses = property_inputs()
    index = next(i for i, h in enumerate(harnesses) if h.name == corpus.properties[0].harness_name)
    harness = harnesses[index].model_copy(deep=True)
    if change == "predicate":
        harness.properties[0].expected_uint = 123
    elif change == "actor":
        harness.actors[0].address = "0x2000000000000000000000000000000000000002"
    elif change == "campaign":
        harness.seed = 2
    else:
        harness.local_deployments[0].source_path = "src/Other.sol"
    harnesses[index] = harness
    with pytest.raises(ValueError, match=r"differs|differ"):
        bind_compiled_property_tests(
            inventory_result=retained_property_fixture(),
            project_root=".",
            corpus=corpus,
            harnesses=harnesses,
        )


def test_duplicate_harness_and_nonlocal_target_are_not_silently_selected() -> None:
    corpus, harnesses = property_inputs()
    result = retained_property_fixture()
    with pytest.raises(ValueError, match="ambiguous"):
        bind_compiled_property_tests(
            inventory_result=result,
            project_root=".",
            corpus=corpus,
            harnesses=[harnesses[0], harnesses[0]],
        )
    nonlocal_harness = harnesses[0].model_copy(update={"local_deployments": []})
    assert generated_local_property_source(nonlocal_harness, project_root=".") is None
    mapping = bind_compiled_property_tests(
        inventory_result=result,
        project_root=".",
        corpus=corpus,
        harnesses=[nonlocal_harness, harnesses[1]],
    )
    assert len(mapping.tests) == len(mapping.unresolved_property_ids) == 1


@pytest.mark.parametrize("path", ['src/Quoted".sol', "src/White space.sol"])
def test_generated_local_imports_cannot_inject_solidity(path: str) -> None:
    _, harnesses = property_inputs()
    harness = harnesses[0].model_copy(deep=True)
    harness.local_deployments[0].source_path = path
    with pytest.raises(ValueError, match="safely rendered"):
        generated_local_property_source(harness, project_root=".")


@pytest.mark.parametrize("change", ["source", "list", "build"])
def test_retained_compiler_input_drift_cannot_be_hidden_as_unresolved(change: str) -> None:
    result = retained_property_fixture()
    snapshot = result.compiler_inputs[0]
    if change == "source":
        source = snapshot.sources[0]
        snapshot = replace(
            snapshot,
            sources=(
                replace(source, content=source.content + b"// drift\n"),
                *snapshot.sources[1:],
            ),
        )
    elif change == "list":
        snapshot = replace(snapshot, forge_list_json=b"{}")
    else:
        snapshot = replace(snapshot, build_info_jsons=(b"{}",))
    result = replace(result, compiler_inputs=(snapshot,))
    corpus, harnesses = property_inputs()
    with pytest.raises(ValueError):
        bind_compiled_property_tests(
            inventory_result=result, project_root=".", corpus=corpus, harnesses=harnesses
        )


@pytest.mark.parametrize(
    "field",
    [
        "test_id",
        "property_id",
        "execution_source_sha256",
        "execution_path",
        "declaration_suite_name",
    ],
)
def test_resealed_mapping_cannot_swap_assertions_or_compiler_identity(field: str) -> None:
    mapping = _mapping()
    test = mapping.tests[0].model_copy(deep=True)
    if field == "test_id":
        test.test_id = mapping.tests[1].test_id
    elif field == "property_id":
        test.property_id = mapping.tests[1].property_id
    else:
        values = {
            k: getattr(test.record, k)
            for k in type(test.record).model_fields
            if k != "record_sha256"
        }
        values[field] = (
            "f" * 64
            if "sha256" in field
            else ("test/Other.t.sol" if field == "execution_path" else "Other")
        )
        test.record = RepositorySuiteInventoryRecord.sealed(**values)
    with pytest.raises(ValueError):
        _reseal(mapping, tests=[test, *mapping.tests[1:]])


@pytest.mark.parametrize(
    "change", ["drop_bound", "drop_gap", "replace_test", "drop_property", "inventory", "corpus"]
)
def test_automatic_plan_resealing_cannot_select_a_smaller_or_swapped_population(
    change: str,
) -> None:
    plan = property_plan(retained_property_fixture())
    updates: dict[str, Any] = {}
    if change == "drop_bound":
        updates["bindings"] = plan.bindings[1:]
    elif change == "drop_gap":
        updates["non_applicability"] = plan.non_applicability[1:]
    elif change == "replace_test":
        updates["bindings"] = [
            plan.bindings[0].model_copy(update={"test_ids": plan.bindings[1].test_ids}),
            plan.bindings[1],
        ]
    elif change == "drop_property":
        updates["property_repositories"] = {next(iter(plan.property_repositories)): "synthetic"}
    elif change == "inventory":
        assert plan.property_tests is not None
        graph = plan.property_tests.compiler_reachability
        assert graph is not None
        graph_values = {
            k: getattr(graph, k) for k in type(graph).model_fields if k != "reachability_sha256"
        }
        graph_values["inventory_sha256"] = "f" * 64
        updates["property_tests"] = _reseal(
            plan.property_tests,
            inventory_sha256="f" * 64,
            compiler_reachability=type(graph).sealed(**graph_values),
            tests=[],
            unresolved_property_ids=list(plan.property_repositories),
        )
    else:
        updates["property_corpus_hash"] = "f" * 64
    with pytest.raises(ValueError):
        _reseal(plan, **updates)


def test_manual_plan_compatibility_does_not_allow_an_empty_denominator() -> None:
    plan = inventory_fixture_plan(retained_fixture())
    assert "property_tests" not in plan.model_dump(mode="json")
    with pytest.raises(ValueError, match="at least one"):
        _reseal(plan, bindings=[])


@pytest.mark.parametrize(
    "change", ["none", "missing_inventory", "missing_discovery", "legacy", "manual_empty"]
)
def test_exported_schema_requires_complete_automatic_mapping_contract(change: str) -> None:
    raw = property_plan(retained_property_fixture()).model_dump(mode="json")
    if change == "missing_inventory":
        raw.pop("compiler_inventory")
    elif change == "missing_discovery":
        raw.pop("discovery")
    elif change == "legacy":
        raw["schema_version"] = "1.1"
    elif change == "manual_empty":
        raw.pop("property_tests")
        raw["bindings"] = []
    schema = json.loads(Path("schemas/mutation_applicability_plan.schema.json").read_bytes())
    validator = jsonschema.Draft202012Validator(schema)
    if change == "none":
        validator.validate(raw)
    else:
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(raw)
