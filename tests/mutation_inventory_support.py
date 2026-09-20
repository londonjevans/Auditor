"""Synthetic retained compiler inputs and explicitly declared property mappings, never authority."""

from __future__ import annotations

import json
from pathlib import Path

from mmaudit.benchmark.foundry_mutation_executor import canonical_foundry_inventory_mutation_test_id
from mmaudit.benchmark.mutations import (
    MutationApplicabilityPlan,
    build_inventory_mutation_plan,
    discover_inventory_portfolio_mutations,
)
from mmaudit.models.schemas import RepositorySuiteInventoryEvidence
from mmaudit.scanners.foundry_inventory import (
    FoundryInventoryLimits,
    FoundrySourceInput,
    parse_foundry_compiler_statement_catalog,
    parse_foundry_test_inventory,
)
from mmaudit.scanners.foundry_inventory_runner import (
    FoundryCompilerInputSnapshot,
    FoundryInventoryRunResult,
)
from tests.mutation_discovery_support import declared_fixture_plan
from tests.mutation_portfolio_support import FIXTURE, SOURCE_PATH

RETAINED_FIXTURE = Path(__file__).parent / "fixtures/mutation_inventory"


def retained_fixture() -> FoundryInventoryRunResult:
    """Reconstruct MOCK metadata from a native synthetic inventory; grant no live authority."""

    data = json.loads((RETAINED_FIXTURE / "snapshot.json").read_bytes())
    evidence = RepositorySuiteInventoryEvidence.model_validate(data["evidence"])
    snapshots = tuple(
        FoundryCompilerInputSnapshot(
            project_root=s["project_root"],
            forge_list_json=s["forge_list_json"].encode(),
            build_info_jsons=tuple(raw.encode() for raw in s["build_info_jsons"]),
            sources=tuple(
                FoundrySourceInput(
                    source["path"], (FIXTURE / source["path"]).read_bytes(), source["source_sha256"]
                )
                for source in s["sources"]
            ),
            parser_limits=FoundryInventoryLimits.model_validate(s["parser_limits"]),
        )
        for s in data["snapshots"]
    )
    inventories = []
    catalogs = []
    for snapshot in snapshots:
        inventories.append(
            parse_foundry_test_inventory(
                forge_list_json=snapshot.forge_list_json,
                build_info_jsons=snapshot.build_info_jsons,
                sources=snapshot.sources,
                project_root=snapshot.project_root,
                compiler_version=evidence.compiler_version,
                compiler_sha256=evidence.compiler_sha256,
                limits=snapshot.parser_limits,
            )
        )
        catalogs.append(
            parse_foundry_compiler_statement_catalog(
                build_info_jsons=snapshot.build_info_jsons,
                sources=snapshot.sources,
                project_root=snapshot.project_root,
                compiler_version=evidence.compiler_version,
                compiler_sha256=evidence.compiler_sha256,
                limits=snapshot.parser_limits,
            )
        )
    return FoundryInventoryRunResult(
        inventories=tuple(inventories),
        statement_catalogs=tuple(catalogs),
        evidence=evidence,
        compiler_inputs=snapshots,
        accounted_output_bytes=data["accounted_output_bytes"],
        generated_artifact_bytes=data["generated_artifact_bytes"],
    )


def inventory_fixture_plan(
    result: FoundryInventoryRunResult, source_repository: Path = FIXTURE, *, project_root: str = "."
) -> MutationApplicabilityPlan:
    """Bind existing synthetic assertions explicitly; never infer applicability from names."""

    discovery, inventory = discover_inventory_portfolio_mutations(
        inventory_result=result, project_root=project_root, target_paths=(SOURCE_PATH,)
    )
    declared = declared_fixture_plan(discovery, source_repository)
    project = next(p for p in inventory.projects if p.project_root == project_root)
    test_ids = {
        record.test_name: canonical_foundry_inventory_mutation_test_id(
            record, inventory_sha256=inventory.normalized_inventory_sha256
        )
        for record in project.records
    }
    return build_inventory_mutation_plan(
        inventory_result=result,
        project_root=project_root,
        target_paths=(SOURCE_PATH,),
        property_corpus_hash=declared.property_corpus_hash,
        approved_executor_sha256=declared.approved_executor_sha256,
        approved_isolation_policy_sha256=declared.approved_isolation_policy_sha256,
        property_repositories=declared.property_repositories,
        bindings=[
            b.model_copy(update={"test_ids": [test_ids[t] for t in b.test_ids]})
            for b in declared.bindings
        ],
        non_applicability=declared.non_applicability,
    )
