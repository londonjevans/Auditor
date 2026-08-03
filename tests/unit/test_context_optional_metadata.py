from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from mmaudit.models.schemas import (
    SolidityGraphNode,
    SolidityGraphNodeKind,
    SolidityGraphSet,
    SolidityProjectMetadata,
    SolidityProjectType,
    SolidityProvenance,
    SoliditySymbolIndex,
)
from mmaudit.models.token_planning import ContextOmissionCategory, ContextOmissionReason
from mmaudit.orchestration.context import (
    ContextBuilder,
    _ContextInventorySnapshot,
    render_context,
)
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.repository.mapping import build_repository_map


def _provider_omission_commitment(package) -> str:
    rendered = render_context(package)
    payload = rendered.split("<CONTEXT_OMISSION_COMMITMENT_JSON>\n", 1)[1].split(
        "\n</CONTEXT_OMISSION_COMMITMENT_JSON>",
        1,
    )[0]
    return str(json.loads(payload)["inventory_sha256"])


def _retained_original_map_list_items(original, compacted) -> int:
    retained = 0
    for field_name in (
        "frameworks",
        "manifests",
        "entry_points",
        "api_surfaces",
        "auth_components",
        "data_layers",
        "network_clients",
        "file_handlers",
        "configuration_files",
        "sensitive_processing",
        "security_tests",
        "omitted_files",
    ):
        original_values = Counter(getattr(original, field_name))
        for value in getattr(compacted, field_name):
            if original_values[value]:
                original_values[value] -= 1
                retained += 1
    return retained


def test_context_builder_omits_optional_project_metadata_per_item(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(
        repository={"max_total_context_bytes": 20_000},
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    projects = [
        SolidityProjectMetadata(
            project_type=SolidityProjectType.FOUNDRY,
            project_root=f"synthetic-project-{index}",
            discovery_warnings=["x" * 18_000],
        )
        for index in range(2)
    ]

    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
        solidity_projects=projects,
    ).build("source_audit")

    project_omission = next(
        omission
        for omission in package.omissions
        if omission.category is ContextOmissionCategory.FRAMEWORK
        and omission.reason is ContextOmissionReason.METADATA_BUDGET_EXCLUDED
    )
    assert not package.solidity_projects
    assert package.excerpts
    assert package.bytes_used <= package.byte_budget
    assert project_omission.omitted_item_count == len(projects)


def test_context_builder_counts_one_oversized_logical_construct_once(
    tmp_path: Path,
    config_factory,
) -> None:
    repository = tmp_path / "oversized-logical-construct"
    repository.mkdir()
    (repository / "SyntheticVault.sol").write_text(
        f'contract SyntheticVault {{\n    string constant PAD = "{"x" * 75_000}";\n}}\n',
        encoding="utf-8",
    )
    config = config_factory(
        repository={
            "max_file_bytes": 100_000,
            "max_total_context_bytes": 100_000,
        },
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(repository, config.repository, IgnoreMatcher())

    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    ).build("source_audit")

    logical_omission = next(
        omission
        for omission in package.omissions
        if omission.category is ContextOmissionCategory.SOURCE
        and omission.reason is ContextOmissionReason.LOGICAL_BLOCK_EXCEEDS_LIMIT
    )
    assert not package.excerpts
    assert logical_omission.omitted_item_count == 1


def test_context_builder_classifies_normal_construct_by_remaining_source_budget(
    tmp_path: Path,
    config_factory,
) -> None:
    repository = tmp_path / "remaining-source-budget"
    repository.mkdir()
    for contract_name, marker in (("A", "a"), ("B", "b")):
        (repository / f"{contract_name}.sol").write_text(
            (f'contract {contract_name} {{ string constant PAD = "{marker * 10_500}"; }}\n'),
            encoding="utf-8",
        )
    config = config_factory(
        repository={
            "max_file_bytes": 20_000,
            "max_total_context_bytes": 14_000,
        },
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(repository, config.repository, IgnoreMatcher())

    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    ).build("source_audit")

    assert [excerpt.path for excerpt in package.excerpts] == ["A.sol"]
    assert all(item.size < 48_000 for item in discovery.files)
    source_reasons = {
        omission.reason
        for omission in package.omissions
        if omission.category is ContextOmissionCategory.SOURCE
    }
    assert ContextOmissionReason.SOURCE_BUDGET_EXCLUDED in source_reasons
    assert ContextOmissionReason.LOGICAL_BLOCK_EXCEEDS_LIMIT not in source_reasons


def test_context_builder_degrades_optional_repository_map_lists(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(
        repository={"max_total_context_bytes": 20_000},
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    base_map = build_repository_map(discovery)
    packages = []
    for terminal_marker in ("first", "second"):
        omitted_files = [f"synthetic-omission-{index}-{'y' * 900}" for index in range(99)]
        omitted_files.append(f"terminal-{terminal_marker}-{'z' * 900}")
        repository_map = base_map.model_copy(
            update={
                "frameworks": [f"synthetic-framework-{index}-{'x' * 900}" for index in range(100)],
                "omitted_files": omitted_files,
            }
        )
        package = ContextBuilder(
            discovery=discovery,
            repository_map=repository_map,
            repository_config=config.repository,
            privacy=config.privacy,
            scanner_findings=[],
        ).build("source_audit")
        metadata_omission = next(
            omission
            for omission in package.omissions
            if omission.category is ContextOmissionCategory.METADATA
            and omission.reason is ContextOmissionReason.METADATA_BUDGET_EXCLUDED
        )
        original_list_count = sum(
            len(getattr(repository_map, field_name))
            for field_name in (
                "frameworks",
                "manifests",
                "entry_points",
                "api_surfaces",
                "auth_components",
                "data_layers",
                "network_clients",
                "file_handlers",
                "configuration_files",
                "sensitive_processing",
                "security_tests",
                "omitted_files",
            )
        )
        removed_original_count = (
            len(repository_map.files)
            - len(package.repository_map.files)
            + original_list_count
            - _retained_original_map_list_items(repository_map, package.repository_map)
        )
        assert metadata_omission.omitted_item_count == removed_original_count
        assert package.excerpts
        assert package.bytes_used <= package.byte_budget
        packages.append(package)

    assert packages[0].repository_map == packages[1].repository_map
    assert _provider_omission_commitment(packages[0]) != _provider_omission_commitment(packages[1])


def test_context_builder_commits_compacted_index_source_inventory(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    packages = []
    for terminal_marker in ("first", "second"):
        index = SoliditySymbolIndex(
            projects=[],
            entities=[],
            ast_sources=[f"synthetic-{terminal_marker}.sol"],
        )
        packages.append(
            ContextBuilder(
                discovery=discovery,
                repository_map=build_repository_map(discovery),
                repository_config=config.repository,
                privacy=config.privacy,
                scanner_findings=[],
                solidity_index=index,
            ).build("source_audit")
        )

    framework_omissions = [
        next(
            omission
            for omission in package.omissions
            if omission.category is ContextOmissionCategory.FRAMEWORK
            and omission.reason is ContextOmissionReason.METADATA_BUDGET_EXCLUDED
        )
        for package in packages
    ]
    assert all(omission.omitted_item_count == 1 for omission in framework_omissions)
    assert packages[0].solidity_index == packages[1].solidity_index
    assert _provider_omission_commitment(packages[0]) != _provider_omission_commitment(packages[1])


def test_context_builder_commits_compacted_isolated_graph_nodes(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    packages = []
    for terminal_marker in ("first", "second"):
        graphs = SolidityGraphSet(
            nodes=[
                SolidityGraphNode(
                    id=f"isolated:{terminal_marker}",
                    kind=SolidityGraphNodeKind.UNKNOWN,
                    label=f"isolated {terminal_marker}",
                    path="Synthetic.sol",
                    start_line=1,
                    end_line=1,
                    source_hash="a" * 64,
                    provenance=SolidityProvenance.COMPILER,
                    confidence=1,
                    transformation="synthetic compiler evidence",
                )
            ],
            edges=[],
        )
        packages.append(
            ContextBuilder(
                discovery=discovery,
                repository_map=build_repository_map(discovery),
                repository_config=config.repository,
                privacy=config.privacy,
                scanner_findings=[],
                solidity_graphs=graphs,
            ).build("source_audit")
        )

    graph_omissions = [
        next(
            omission
            for omission in package.omissions
            if omission.category is ContextOmissionCategory.GRAPH
            and omission.reason is ContextOmissionReason.METADATA_BUDGET_EXCLUDED
        )
        for package in packages
    ]
    assert all(omission.omitted_item_count == 1 for omission in graph_omissions)
    assert packages[0].solidity_graphs == packages[1].solidity_graphs
    assert _provider_omission_commitment(packages[0]) != _provider_omission_commitment(packages[1])


def test_context_inventory_snapshot_is_byte_equivalent_to_legacy_hashing(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    index = SoliditySymbolIndex(
        projects=[],
        entities=[],
        ast_sources=["SyntheticOrphan.sol"],
    )
    graphs = SolidityGraphSet(
        nodes=[
            SolidityGraphNode(
                id="isolated:inventory-equivalence",
                kind=SolidityGraphNodeKind.UNKNOWN,
                label="isolated inventory equivalence",
                path="SyntheticOrphan.sol",
                start_line=1,
                end_line=1,
                source_hash="a" * 64,
                provenance=SolidityProvenance.COMPILER,
                confidence=1,
                transformation="synthetic compiler evidence",
            )
        ],
        edges=[],
    )
    builder = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
        solidity_index=index,
        solidity_graphs=graphs,
    )

    cached = builder.build("source_audit")
    assert builder._inventory_snapshot.entries
    builder._inventory_snapshot = _ContextInventorySnapshot.empty()
    uncached = builder.build("source_audit")

    assert cached == uncached
    assert cached.omissions
    assert render_context(cached) == render_context(uncached)
    assert _provider_omission_commitment(cached) == _provider_omission_commitment(uncached)


def test_context_inventory_snapshot_isolated_from_caller_mutation(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    repository_map = build_repository_map(discovery)
    project = SolidityProjectMetadata(
        project_type=SolidityProjectType.FOUNDRY,
        project_root="synthetic-original",
    )
    index = SoliditySymbolIndex(
        projects=[],
        entities=[],
        ast_sources=["SyntheticOriginal.sol"],
    )
    graphs = SolidityGraphSet(
        nodes=[
            SolidityGraphNode(
                id="isolated:owned-snapshot",
                kind=SolidityGraphNodeKind.UNKNOWN,
                label="owned snapshot original",
                path="SyntheticOriginal.sol",
                start_line=1,
                end_line=1,
                source_hash="b" * 64,
                provenance=SolidityProvenance.COMPILER,
                confidence=1,
                transformation="synthetic compiler evidence",
            )
        ],
        edges=[],
    )
    control_map = repository_map.model_copy(deep=True)
    control_project = project.model_copy(deep=True)
    control_index = index.model_copy(deep=True)
    control_graphs = graphs.model_copy(deep=True)
    builder = ContextBuilder(
        discovery=discovery,
        repository_map=repository_map,
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
        solidity_projects=[project],
        solidity_index=index,
        solidity_graphs=graphs,
    )

    repository_map.files[0].size += 1
    project.project_root = "synthetic-mutated"
    index.ast_sources[0] = "SyntheticMutated.sol"
    graphs.nodes[0].label = "owned snapshot mutated"
    exposed_map = builder.repository_map
    exposed_projects = builder.solidity_projects
    exposed_index = builder.solidity_index
    exposed_graphs = builder.solidity_graphs
    exposed_map.files[0].size += 100
    exposed_projects[0].project_root = "synthetic-exposed-mutation"
    assert exposed_index is not None
    exposed_index.ast_sources[0] = "SyntheticExposedMutation.sol"
    assert exposed_graphs is not None
    exposed_graphs.nodes[0].label = "owned snapshot exposed mutation"

    observed = builder.build("source_audit")
    expected = ContextBuilder(
        discovery=discovery,
        repository_map=control_map,
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
        solidity_projects=[control_project],
        solidity_index=control_index,
        solidity_graphs=control_graphs,
    ).build("source_audit")

    assert observed == expected
    assert render_context(observed) == render_context(expected)
    assert _provider_omission_commitment(observed) == _provider_omission_commitment(expected)
