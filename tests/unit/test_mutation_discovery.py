"""Automatic source discovery on synthetic ASTs, with explicit no-credit boundaries."""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
from dataclasses import replace
from typing import Any, NoReturn

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from mmaudit.benchmark.mutation_discovery import (
    PortfolioDiscoveryLimits,
    PortfolioMutationDiscovery,
    discover_portfolio_mutations,
)
from mmaudit.benchmark.mutation_portfolio import (
    SecurityMutationClass,
    mutate_portfolio_source,
    restore_portfolio_source,
)
from mmaudit.benchmark.mutations import MutationApplicabilityPlan, score_planned_mutation_campaigns
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.scanners.foundry_inventory import FoundryInventoryLimits
from scripts.generate_release_schemas import MODELS, rendered_schema
from tests.mutation_discovery_support import (
    all_nodes,
    declared_fixture_plan,
    discover_fixture,
    fixture_inputs,
)
from tests.mutation_portfolio_support import SOURCE_PATH, portfolio_plan


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> NoReturn:
        pytest.fail("pure mutation discovery attempted network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def test_all_eleven_classes_are_automatically_discovered_without_selected_source_spans() -> None:
    result = discover_fixture()
    assert len(result.candidates) == 13
    assert {c.specification.kind for c in result.candidates} == set(SecurityMutationClass)
    assert len(result.source_classes) == 11
    assert all(item.candidate_ids and item.limitation is None for item in result.source_classes)
    assert result.unsupported == ()
    assert not result.property_applicability_established
    assert not result.execution_validated and not result.qualification_eligible
    assert PortfolioMutationDiscovery.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize("kind", list(SecurityMutationClass))
def test_every_automatically_discovered_source_operation_applies_and_restores(
    kind: SecurityMutationClass,
) -> None:
    result = discover_fixture()
    _, sources, _ = fixture_inputs()
    for candidate in result.candidates:
        if candidate.specification.kind is not kind:
            continue
        source = sources[0].content
        mutated, original_span, mutated_span, endings = mutate_portfolio_source(
            source, candidate.specification
        )
        assert original_span != mutated_span
        assert (
            restore_portfolio_source(
                mutated,
                candidate.specification,
                line_endings=endings,
                expected_mutated_span_sha256=hashlib.sha256(mutated_span).hexdigest(),
            )
            == source
        )


@pytest.mark.parametrize(
    "change",
    [
        "hash",
        "same-size-bytes",
        "missing-source",
        "missing-ast",
        "source-id",
        "duplicate-node",
        "span",
        "compiler-error",
        "compiler-version",
        "missing-reference",
    ],
)
def test_compiler_source_and_semantic_evidence_cannot_be_substituted(change: str) -> None:
    payload, sources, compiler_sha = fixture_inputs()
    nodes = all_nodes(payload)
    if change == "hash":
        sources = (replace(sources[0], source_sha256="0" * 64),)
    elif change == "same-size-bytes":
        altered = sources[0].content.replace(b"owner", b"other")
        sources = (
            replace(sources[0], content=altered, source_sha256=hashlib.sha256(altered).hexdigest()),
        )
    elif change == "missing-source":
        sources = ()
    elif change == "missing-ast":
        payload["output"]["sources"][SOURCE_PATH].pop("ast")
    elif change == "source-id":
        payload["output"]["sources"][SOURCE_PATH]["id"] = 99
    elif change == "duplicate-node":
        solidity = [node for node in nodes if "id" in node]
        solidity[-1]["id"] = solidity[-2]["id"]
    elif change == "span":
        payload["output"]["sources"][SOURCE_PATH]["ast"]["src"] = "0:999999:0"
    elif change == "compiler-error":
        payload["output"]["errors"] = [
            {"severity": "error", "message": "synthetic compiler refusal"}
        ]
    elif change == "compiler-version":
        payload["solcVersion"] = "0.8.29"
    elif change == "missing-reference":
        for node in nodes:
            if node.get("nodeType") == "MemberAccess" and node.get("memberName") == "observe":
                node["referencedDeclaration"] = 999999
        result = discover_fixture(build_info_jsons=(json.dumps(payload).encode(),))
        row = next(
            c
            for c in result.source_classes
            if c.kind is SecurityMutationClass.EXTERNAL_CALL_BEFORE_STATE_UPDATE
        )
        assert not row.candidate_ids and row.unsupported_ids and row.limitation
        return
    with pytest.raises(ValueError):
        discover_portfolio_mutations(
            build_info_jsons=(json.dumps(payload).encode(),),
            sources=sources,
            target_paths=(SOURCE_PATH,),
            compiler_version="0.8.30",
            compiler_sha256=compiler_sha,
        )


@pytest.mark.parametrize(
    "role", ["state", "external", "rounding", "call-result", "initializer", "pause"]
)
def test_names_cannot_replace_declaration_relationships(role: str) -> None:
    payload, _, _ = fixture_inputs()
    nodes = all_nodes(payload)
    if role == "state":
        selected = next(
            n
            for n in nodes
            if n.get("nodeType") == "VariableDeclaration" and n.get("name") == "pendingValue"
        )
        selected["stateVariable"] = False
        kind = SecurityMutationClass.EXTERNAL_CALL_BEFORE_STATE_UPDATE
    elif role == "external":
        selected = next(
            n
            for n in nodes
            if n.get("nodeType") == "FunctionDefinition" and n.get("name") == "observe"
        )
        selected["visibility"] = "internal"
        kind = SecurityMutationClass.EXTERNAL_CALL_BEFORE_STATE_UPDATE
    elif role == "rounding":
        selected = next(n for n in nodes if n.get("nodeType") == "EnumDefinition")
        selected["name"] = "UnrelatedChoice"
        kind = SecurityMutationClass.ROUNDING_DIRECTION
    elif role == "call-result":
        selected = next(
            n
            for n in nodes
            if n.get("nodeType") == "FunctionDefinition" and n.get("name") == "accepted"
        )
        selected["visibility"] = "internal"
        kind = SecurityMutationClass.UNCHECKED_RETURN_HANDLING
    else:
        name = "initialized" if role == "initializer" else "paused"
        next(
            n for n in nodes if n.get("nodeType") == "VariableDeclaration" and n.get("name") == name
        )["stateVariable"] = False
        kind = (
            SecurityMutationClass.INITIALIZER_PROTECTION_REMOVAL
            if role == "initializer"
            else SecurityMutationClass.PAUSE_ENFORCEMENT_REMOVAL
        )
    result = discover_fixture(build_info_jsons=(json.dumps(payload).encode(),))
    row = next(c for c in result.source_classes if c.kind is kind)
    assert not row.candidate_ids and row.unsupported_ids and row.limitation


@pytest.mark.parametrize(
    "field,value",
    [
        ("target_paths", ()),
        ("target_paths", (SOURCE_PATH, SOURCE_PATH)),
        ("target_paths", ("../outside.sol",)),
        ("target_paths", [SOURCE_PATH]),
        ("sources", []),
        ("build_info_jsons", []),
    ],
)
def test_explicit_inventory_is_exact_and_immutable(field: str, value: Any) -> None:
    with pytest.raises(ValueError):
        discover_fixture(**{field: value})


@pytest.mark.parametrize(
    "limit", ["candidates", "ast", "source-bytes", "build-bytes", "unsupported"]
)
def test_limits_refuse_instead_of_returning_a_selected_prefix(limit: str) -> None:
    changes: dict[str, Any] = {}
    if limit == "candidates":
        changes["limits"] = PortfolioDiscoveryLimits(maximum_candidates=12)
    elif limit == "ast":
        changes["inventory_limits"] = FoundryInventoryLimits(max_ast_nodes=2)
    elif limit == "source-bytes":
        changes["inventory_limits"] = FoundryInventoryLimits(max_source_bytes=1)
    elif limit == "build-bytes":
        changes["inventory_limits"] = FoundryInventoryLimits(max_build_info_json_bytes=1024)
    else:
        payload, _, _ = fixture_inputs()
        for node in all_nodes(payload):
            if node.get("nodeType") == "VariableDeclaration":
                node["stateVariable"] = False
        changes.update(
            build_info_jsons=(json.dumps(payload).encode(),),
            limits=PortfolioDiscoveryLimits(maximum_unsupported=1),
        )
    with pytest.raises(ValueError):
        discover_fixture(**changes)


def test_plan_consumes_every_discovered_candidate_and_retains_full_discovery_gaps() -> None:
    result = discover_fixture()
    plan = declared_fixture_plan(result)
    assert plan.discovery == result
    assert len(plan.specifications) == 13
    assert len(plan.bindings) + len(plan.non_applicability) == 13 * 11
    assert "discovery" not in portfolio_plan().model_dump(mode="json")
    score = score_planned_mutation_campaigns(
        plan=plan, campaigns=[], minimum_property_kill_score=0.95
    )
    assert not score.gate_passed
    assert len(score.outcomes) == 13


@pytest.mark.parametrize("change", ["candidate", "coverage", "target", "compiler", "flags"])
def test_discovery_cannot_be_resealed_with_hidden_candidates_or_promoted_authority(
    change: str,
) -> None:
    payload = discover_fixture().model_dump(mode="json")
    if change == "candidate":
        payload["candidates"].pop()
    elif change == "coverage":
        payload["source_classes"].pop()
    elif change == "target":
        payload["target_paths"] = ["unselected.sol"]
    elif change == "compiler":
        payload["candidates"][0]["build_info_sha256"] = "0" * 64
    else:
        payload["execution_validated"] = True
    payload["discovery_sha256"] = canonical_sha256(
        {k: v for k, v in payload.items() if k != "discovery_sha256"}
    )
    with pytest.raises(ValueError):
        PortfolioMutationDiscovery.model_validate(payload)


def test_plan_cannot_omit_an_automatically_discovered_candidate() -> None:
    plan = declared_fixture_plan(discover_fixture())
    payload = {field: getattr(plan, field) for field in MutationApplicabilityPlan.model_fields}
    payload["specifications"] = list(plan.specifications)
    payload["specifications"].pop()
    payload.pop("plan_sha256")
    with pytest.raises(ValueError, match="every exact discovered"):
        MutationApplicabilityPlan.sealed(**payload)


def test_nested_project_targets_are_repository_relative_not_root_aliases() -> None:
    result = discover_fixture(project_root="packages/synthetic")
    assert result.target_paths == ("packages/synthetic/" + SOURCE_PATH,)
    assert all(c.specification.path == result.target_paths[0] for c in result.candidates)


@pytest.mark.parametrize("child", [None, {}, [], "synthetic-malformed-expression"])
def test_missing_expression_structure_refuses_instead_of_hiding_one_candidate(child: Any) -> None:
    payload, _, _ = fixture_inputs()
    node = next(
        node for node in all_nodes(payload) if node.get("nodeType") == "ExpressionStatement"
    )
    node["expression"] = child
    with pytest.raises(ValueError, match="shape is malformed"):
        discover_fixture(build_info_jsons=(json.dumps(payload).encode(),))


@pytest.mark.parametrize("category", ["discovery", "compiler"])
def test_constructed_limit_models_do_not_bypass_resource_ceilings(category: str) -> None:
    if category == "discovery":
        limits = PortfolioDiscoveryLimits.model_construct(maximum_candidates=100_001)
        with pytest.raises(ValueError):
            discover_fixture(limits=limits)
    else:
        compiler_limits = FoundryInventoryLimits.model_construct(max_ast_nodes=10_000_001)
        with pytest.raises(ValueError):
            discover_fixture(inventory_limits=compiler_limits)


def test_exported_discovery_schema_preserves_class_denominator_and_no_credit() -> None:
    model = MODELS["portfolio_mutation_discovery.schema.json"]
    schema = json.loads(rendered_schema("portfolio_mutation_discovery.schema.json", model))
    validator = Draft202012Validator(schema)
    result = discover_fixture().model_dump(mode="json")
    validator.validate(result)
    for field in (
        "property_applicability_established",
        "execution_validated",
        "qualification_eligible",
    ):
        assert not validator.is_valid({**result, field: True})
    missing = {**result, "source_classes": result["source_classes"][:-1]}
    assert not validator.is_valid(missing)
    assert not validator.is_valid({**result, "limitations": []})


def test_public_plan_schema_retains_discovery_and_rejects_legacy_promotion() -> None:
    model = MODELS["mutation_applicability_plan.schema.json"]
    validator = Draft202012Validator(
        json.loads(rendered_schema("mutation_applicability_plan.schema.json", model))
    )
    discovery = discover_fixture()
    plan = declared_fixture_plan(discovery)
    validator.validate(plan.model_dump(mode="json"))
    validator.validate(portfolio_plan().model_dump(mode="json"))
    assert not validator.is_valid({**plan.model_dump(mode="json"), "schema_version": "1.1"})


def test_partial_class_discovery_preserves_gaps_in_plan_and_never_passes_without_campaigns() -> (
    None
):
    payload, _, _ = fixture_inputs()
    for node in all_nodes(payload):
        if node.get("nodeType") == "EnumDefinition":
            node["name"] = "UnrelatedChoice"
    discovery = discover_fixture(build_info_jsons=(json.dumps(payload).encode(),))
    plan = declared_fixture_plan(discovery)
    row = next(
        item
        for item in plan.kind_accounting
        if item.kind is SecurityMutationClass.ROUNDING_DIRECTION
    )
    assert row.candidate_count == 0 and row.limitation
    assert plan.discovery == discovery and discovery.unsupported
    assert not score_planned_mutation_campaigns(
        plan=plan, campaigns=[], minimum_property_kill_score=0.95
    ).gate_passed
