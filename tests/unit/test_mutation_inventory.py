"""Retained compiler-input joins and complete plan custody, with no external execution."""

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

from mmaudit.benchmark.foundry_mutation_executor import (
    canonical_foundry_inventory_mutation_test_id,
    canonical_foundry_mutation_test_id,
)
from mmaudit.benchmark.mutation_discovery import PortfolioDiscoveryLimits
from mmaudit.benchmark.mutations import (
    MutationApplicabilityPlan,
    build_inventory_mutation_plan,
    discover_inventory_portfolio_mutations,
    score_planned_mutation_campaigns,
)
from mmaudit.config import SmartContractsConfig
from mmaudit.models.schemas import RepositorySuiteInventoryEvidence, RepositorySuiteInventoryPhase
from mmaudit.scanners.foundry_inventory import FoundrySourceInput
from mmaudit.scanners.foundry_inventory_runner import (
    FoundryInventoryRunResult,
    validated_foundry_compiler_input,
)
from mmaudit.scanners.repository_suite import select_foundry_repository_suite_from_inventory
from tests.mutation_inventory_support import inventory_fixture_plan, retained_fixture
from tests.mutation_portfolio_support import SOURCE_PATH


@pytest.fixture(autouse=True)
def no_network_or_process(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> NoReturn:
        pytest.fail("retained inventory unit control attempted external execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def _discover(result: FoundryInventoryRunResult, **changes: Any) -> Any:
    values = dict(inventory_result=result, project_root=".", target_paths=(SOURCE_PATH,))
    return discover_inventory_portfolio_mutations(**{**values, **changes})


def test_retained_native_snapshot_reconstructs_complete_discovery_and_bound_plan() -> None:
    result = retained_fixture()
    snapshot, evidence = validated_foundry_compiler_input(result, project_root=".")
    assert snapshot == result.compiler_inputs[0] and snapshot is not result.compiler_inputs[0]
    assert evidence == result.evidence and evidence is not result.evidence
    assert "contract PortfolioTargets" not in repr(snapshot)
    plan = inventory_fixture_plan(result)
    assert plan.compiler_inventory == evidence and plan.discovery is not None
    assert len(plan.specifications) == len(plan.bindings) == 13
    assert len(plan.non_applicability) == 130 and len(plan.kind_accounting) == 11
    assert plan.source_repository_sha256 == evidence.repository_sha256
    assert plan.discovery.compiler_sha256 == evidence.compiler_sha256
    assert plan == MutationApplicabilityPlan.model_validate_json(plan.model_dump_json())
    assert not plan.discovery.property_applicability_established
    assert not plan.discovery.execution_validated and not plan.discovery.qualification_eligible
    score = score_planned_mutation_campaigns(
        plan=plan, campaigns=[], minimum_property_kill_score=0.95
    )
    assert not score.gate_passed and len(score.outcomes) == 13


def test_handoff_uses_retained_bytes_without_reopening_original_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = retained_fixture()

    def no_read(*args: object, **kwargs: object) -> NoReturn:
        pytest.fail("retained compiler handoff unexpectedly accessed filesystem")

    monkeypatch.setattr(Path, "read_bytes", no_read)
    monkeypatch.setattr(Path, "read_text", no_read)
    monkeypatch.setattr(Path, "open", no_read)
    discovery, evidence = _discover(result)
    assert len(discovery.candidates) == 13 and evidence == result.evidence


@pytest.mark.parametrize("population", ["inventories", "statement_catalogs", "compiler_inputs"])
def test_missing_project_population_is_not_an_implicit_partial_scope(population: str) -> None:
    changes: dict[str, Any] = {population: ()}
    with pytest.raises(ValueError, match="project counts"):
        replace(retained_fixture(), **changes)


@pytest.mark.parametrize(
    "mutation",
    [
        "forge-bytes",
        "build-bytes",
        "missing-build",
        "duplicate-build",
        "changed-source",
        "changed-source-and-hash",
        "missing-source",
        "extra-source",
        "source-alias",
        "mutable-builds",
        "mutable-sources",
        "mutable-content",
        "parser-limit",
        "parser-limit-forged",
        "source-order",
    ],
)
def test_changed_or_incomplete_snapshot_never_reaches_discovery(mutation: str) -> None:
    result = retained_fixture()
    snapshot = result.compiler_inputs[0]
    changes: dict[str, Any] = {}
    source = snapshot.sources[0]
    if mutation == "forge-bytes":
        changes["forge_list_json"] = snapshot.forge_list_json + b" "
    elif mutation == "build-bytes":
        changes["build_info_jsons"] = (snapshot.build_info_jsons[0] + b" ",)
    elif mutation == "missing-build":
        changes["build_info_jsons"] = ()
    elif mutation == "duplicate-build":
        changes["build_info_jsons"] = snapshot.build_info_jsons * 2
    elif mutation in {"changed-source", "changed-source-and-hash"}:
        raw = source.content + b"\n"
        changes["sources"] = (
            replace(
                source,
                content=raw,
                source_sha256=hashlib.sha256(raw).hexdigest()
                if mutation.endswith("and-hash")
                else source.source_sha256,
            ),
            *snapshot.sources[1:],
        )
    elif mutation == "missing-source":
        changes["sources"] = snapshot.sources[1:]
    elif mutation == "extra-source":
        changes["sources"] = (
            *snapshot.sources,
            FoundrySourceInput("Extra.sol", b"x", hashlib.sha256(b"x").hexdigest()),
        )
    elif mutation == "source-alias":
        changes["sources"] = (replace(source, path="src/../" + source.path), *snapshot.sources[1:])
    elif mutation == "mutable-builds":
        changes["build_info_jsons"] = list(snapshot.build_info_jsons)
    elif mutation == "mutable-sources":
        changes["sources"] = list(snapshot.sources)
    elif mutation == "mutable-content":
        mutable_content: Any = bytearray(source.content)
        changes["sources"] = (
            replace(source, content=mutable_content),
            *snapshot.sources[1:],
        )
    elif mutation == "source-order":
        changes["sources"] = tuple(reversed(snapshot.sources))
    else:
        changes["parser_limits"] = snapshot.parser_limits.model_copy(
            update={
                "max_build_info_json_bytes": 1024 if mutation == "parser-limit" else 999_999_999
            }
        )
    altered = replace(result, compiler_inputs=(replace(snapshot, **changes),))
    with pytest.raises(ValueError):
        _discover(altered)


@pytest.mark.parametrize(
    "mutation", ["catalog", "catalog-source", "parsed-tests", "compiler", "project"]
)
def test_changed_original_inventory_or_catalog_cannot_be_rejoined(mutation: str) -> None:
    result = retained_fixture()
    with pytest.raises(ValueError):
        if mutation == "catalog":
            result = replace(
                result, statement_catalogs=(replace(result.statement_catalogs[0], units=()),)
            )
        elif mutation == "catalog-source":
            catalog = result.statement_catalogs[0]
            unit = catalog.units[0]
            changed = replace(
                unit, sources=(replace(unit.sources[0], content=b"not original"), *unit.sources[1:])
            )
            result = replace(result, statement_catalogs=(replace(catalog, units=(changed,)),))
        elif mutation == "parsed-tests":
            result = replace(
                result, inventories=(result.inventories[0].model_copy(update={"test_count": 1}),)
            )
        elif mutation == "compiler":
            result = replace(
                result, evidence=result.evidence.model_copy(update={"compiler_sha256": "f" * 64})
            )
        else:
            result = replace(
                result,
                compiler_inputs=(
                    replace(result.compiler_inputs[0], project_root="packages/other"),
                ),
            )
        _discover(result)


@pytest.mark.parametrize("root", ["missing", "../", "./", "/", "packages/other"])
def test_project_selection_is_explicit_and_canonical(root: str) -> None:
    with pytest.raises(ValueError, match="project"):
        _discover(retained_fixture(), project_root=root)


@pytest.mark.parametrize(
    "paths", [(), ("missing.sol",), (SOURCE_PATH, SOURCE_PATH), ("../Target.sol",)]
)
def test_target_selection_cannot_fall_back_or_hide_a_missing_source(paths: tuple[str, ...]) -> None:
    with pytest.raises(ValueError):
        _discover(retained_fixture(), target_paths=paths)


def test_post_execution_inventory_is_not_a_baseline() -> None:
    result = retained_fixture()
    evidence = RepositorySuiteInventoryEvidence.sealed(
        **{
            **{
                name: getattr(result.evidence, name)
                for name in type(result.evidence).model_fields
                if name != "inventory_sha256"
            },
            "phase": RepositorySuiteInventoryPhase.POST_EXECUTION,
        }
    )
    with pytest.raises(ValueError, match="pre-execution"):
        _discover(replace(result, evidence=evidence))


def test_discovery_limit_never_returns_a_successful_prefix() -> None:
    with pytest.raises(ValueError, match="bound"):
        _discover(retained_fixture(), limits=PortfolioDiscoveryLimits(maximum_candidates=1))


@pytest.mark.parametrize("change", ["discovery", "source", "compiler", "test", "missing-candidate"])
def test_resealed_plan_cannot_break_inventory_binding(change: str) -> None:
    plan = inventory_fixture_plan(retained_fixture())
    values = {
        name: getattr(plan, name) for name in type(plan).model_fields if name != "plan_sha256"
    }
    if change == "discovery":
        values["discovery"] = None
    elif change == "source":
        values["source_repository_sha256"] = "f" * 64
    elif change == "compiler":
        assert plan.compiler_inventory is not None
        values["compiler_inventory"] = plan.compiler_inventory.model_copy(
            update={"compiler_version": "0.0.0"}
        )
    elif change == "test":
        values["bindings"] = [
            plan.bindings[0].model_copy(update={"test_ids": ["foundry:" + "f" * 64]}),
            *plan.bindings[1:],
        ]
    else:
        values["specifications"] = plan.specifications[:-1]
    with pytest.raises(ValueError):
        MutationApplicabilityPlan.sealed(**values)


def test_inventory_test_ids_match_the_existing_executor_selection() -> None:
    result = retained_fixture()
    evidence = result.evidence
    records = evidence.projects[0].records
    config = SmartContractsConfig.model_validate(
        {
            "repository_suite": {
                "profile": "explicit",
                "foundry_include_paths": ("test/**/*.sol",),
                "foundry_include_tests": ("test*",),
                "hardhat_include_paths": (),
                "hardhat_include_tests": (),
            }
        }
    )
    selection = select_foundry_repository_suite_from_inventory(
        records,
        config,
        repository_sha256=evidence.repository_sha256,
        repository_exclusion_path=".mmaudit",
        inventory_sha256=evidence.normalized_inventory_sha256,
    )
    assert len(selection.tests) == len(records) == 11
    assert {canonical_foundry_mutation_test_id(t) for t in selection.tests} == {
        canonical_foundry_inventory_mutation_test_id(
            r, inventory_sha256=evidence.normalized_inventory_sha256
        )
        for r in records
    }


def test_builder_refuses_missing_applicability_instead_of_selecting_only_easy_candidates() -> None:
    result = retained_fixture()
    plan = inventory_fixture_plan(result)
    with pytest.raises(ValueError, match="every declared"):
        build_inventory_mutation_plan(
            inventory_result=result,
            project_root=".",
            target_paths=(SOURCE_PATH,),
            property_corpus_hash=plan.property_corpus_hash,
            approved_executor_sha256=plan.approved_executor_sha256,
            approved_isolation_policy_sha256=plan.approved_isolation_policy_sha256,
            property_repositories=plan.property_repositories,
            bindings=plan.bindings[:-1],
            non_applicability=plan.non_applicability,
        )


def test_bound_inventory_is_in_serialized_plan_but_raw_inputs_are_not() -> None:
    plan = inventory_fixture_plan(retained_fixture())
    data = json.loads(plan.model_dump_json())
    assert plan.compiler_inventory is not None
    assert (
        data["compiler_inventory"]["inventory_sha256"] == plan.compiler_inventory.inventory_sha256
    )
    assert "build_info_jsons" not in plan.model_dump_json()
    assert "forge_list_json" not in plan.model_dump_json()
    assert "contract PortfolioTargets" not in plan.model_dump_json()


@pytest.mark.parametrize("change", [None, "discovery", "null-discovery", "phase", "version"])
def test_exported_schema_retains_the_compiler_inventory_gate(change: str | None) -> None:
    schema = json.loads(
        (
            Path(__file__).resolve().parents[2] / "schemas/mutation_applicability_plan.schema.json"
        ).read_bytes()
    )
    data = inventory_fixture_plan(retained_fixture()).model_dump(mode="json")
    if change == "discovery":
        del data["discovery"]
    elif change == "null-discovery":
        data["discovery"] = None
    elif change == "phase":
        data["compiler_inventory"]["phase"] = "post_execution"
    elif change == "version":
        data["schema_version"] = "1.1"
    if change is None:
        jsonschema.Draft202012Validator(schema).validate(data)
    else:
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(data)
