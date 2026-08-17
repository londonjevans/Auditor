from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from mmaudit.artifact_limits import MAX_JSON_ARTIFACT_BYTES
from mmaudit.models.schemas import (
    AnalysisState,
    SolidityGraphEdge,
    SolidityGraphFactKind,
    SolidityGraphKind,
    SolidityGraphNode,
    SolidityGraphNodeKind,
    SolidityGraphOmission,
    SolidityGraphSet,
    SolidityProvenance,
    SolidityStorageEntry,
)
from mmaudit.models.sharding import SolidityShardPolicy
from mmaudit.reporting.json_report import stable_json_bytes, write_json_bounded
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.solidity.coverage import build_solidity_coverage
from mmaudit.solidity.graphs import (
    _GRAPH_PRIORITY,
    _BoundedEdgeCollector,
    _BoundedFactCollector,
    _BoundedWarningCollector,
    _canonical_edge_bytes,
    _node_retention_key,
    _versioned_layout_edges,
    build_solidity_graphs,
)
from mmaudit.solidity.index import build_solidity_index
from mmaudit.solidity.projects import discover_solidity_projects
from mmaudit.solidity.sharding import (
    build_solidity_shard_inventory,
    verify_solidity_shard_inventory,
)

_TEST_GRAPH_LIMIT = 2_000_000


def _fallback_inputs(root: Path, config_factory):
    config = config_factory(
        repository={
            "max_files": 500,
            "max_walk_entries": 2_000,
            "max_file_bytes": 250_000,
            "max_discovery_bytes": 10_000_000,
        }
    )
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    return config, discovery, projects, build


def test_duplicate_contract_names_do_not_cross_link_source_semantics(
    tmp_path: Path,
    config_factory,
) -> None:
    for directory, variable in (("one", "first"), ("two", "second")):
        source = tmp_path / "src" / directory / "Shared.sol"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(
            "// synthetic local fixture\n"
            "pragma solidity ^0.8.20;\n"
            "contract Shared {\n"
            f"    uint256 {variable};\n"
            f"    function update() external {{ {variable} += 1; }}\n"
            "}\n",
            encoding="utf-8",
        )

    _config, discovery, _projects, build = _fallback_inputs(tmp_path, config_factory)
    graphs = build_solidity_graphs(discovery, build)
    entities = {entity.id: entity for entity in build.index.entities}

    dependencies = [
        edge for edge in graphs.edges if edge.graph is SolidityGraphKind.STATE_DEPENDENCY
    ]
    assert dependencies
    assert all(
        entities[edge.source_id].path == entities[edge.target_id].path for edge in dependencies
    )


def test_source_synthetic_nodes_are_scoped_to_their_source_path(
    tmp_path: Path,
    config_factory,
) -> None:
    for directory in ("one", "two"):
        source = tmp_path / "src" / directory / "Shared.sol"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(
            "// synthetic local fixture\n"
            "pragma solidity ^0.8.20;\n"
            "contract Shared {\n"
            "    address token;\n"
            "    function transfer(address recipient, uint256 amount) "
            "external onlyOwner { token.transfer(recipient, amount); }\n"
            "}\n",
            encoding="utf-8",
        )

    _config, discovery, _projects, build = _fallback_inputs(tmp_path, config_factory)
    graphs = build_solidity_graphs(discovery, build)
    transformations = {
        "bounded_source_member_call_target_node",
        "known_asset_transfer_call_regex.asset_node",
        "bounded_source_authorization_role_node",
    }

    for transformation in transformations:
        nodes = [node for node in graphs.nodes if node.transformation == transformation]
        assert len(nodes) == 2
        assert len({node.id for node in nodes}) == 2
        assert {node.path for node in nodes} == {
            "src/one/Shared.sol",
            "src/two/Shared.sol",
        }

    nodes_by_id = {node.id: node for node in graphs.nodes}
    scoped_node_ids = {node.id for node in graphs.nodes if node.transformation in transformations}
    assert all(
        nodes_by_id[edge.target_id].path == edge.path
        for edge in graphs.edges
        if edge.target_id in scoped_node_ids
    )


def _write_scoped_ast_artifact(
    artifact_root: Path,
    source_path: Path,
    relative_path: str,
    artifact_name: str,
) -> None:
    source = source_path.read_text(encoding="utf-8")

    def src(start: int, end: int) -> str:
        return f"{start}:{end - start}:0"

    contract_start = source.index("contract Shared")
    helper_start = source.index("function helper")
    helper_end = source.index("}", helper_start) + 1
    function_start = source.index("function transfer")
    function_end = source.index("\n    }", function_start) + len("\n    }")
    modifier_start = source.index("modifier onlyOwner")
    modifier_end = source.index("\n    }", modifier_start) + len("\n    }")
    transfer_start = source.index("token.transfer", function_start)
    signature_start = source.index("ecrecover", function_start)
    chain_start = source.index("block.chainid", function_start)
    helper_call_start = source.index("helper()", function_start)
    function_body_start = source.index("{", function_start)

    artifact_root.mkdir(parents=True, exist_ok=True)
    (artifact_root / artifact_name).write_text(
        json.dumps(
            {
                "sourceName": relative_path,
                "ast": {
                    "nodeType": "SourceUnit",
                    "src": src(0, len(source)),
                    "nodes": [
                        {
                            "id": 1,
                            "nodeType": "ContractDefinition",
                            "contractKind": "contract",
                            "name": "Shared",
                            "src": src(contract_start, len(source)),
                            "baseContracts": [],
                            "nodes": [
                                {
                                    "id": 2,
                                    "nodeType": "ModifierDefinition",
                                    "name": "onlyOwner",
                                    "src": src(modifier_start, modifier_end),
                                },
                                {
                                    "id": 3,
                                    "nodeType": "FunctionDefinition",
                                    "kind": "function",
                                    "name": "helper",
                                    "visibility": "internal",
                                    "stateMutability": "nonpayable",
                                    "src": src(helper_start, helper_end),
                                    "modifiers": [],
                                    "body": {
                                        "nodeType": "Block",
                                        "src": src(
                                            source.index("{", helper_start),
                                            helper_end,
                                        ),
                                        "statements": [],
                                    },
                                },
                                {
                                    "id": 4,
                                    "nodeType": "FunctionDefinition",
                                    "kind": "function",
                                    "name": "transfer",
                                    "visibility": "external",
                                    "stateMutability": "nonpayable",
                                    "src": src(function_start, function_end),
                                    "modifiers": [
                                        {
                                            "nodeType": "ModifierInvocation",
                                            "src": src(function_start, function_start + 8),
                                            "modifierName": {
                                                "nodeType": "IdentifierPath",
                                                "name": "onlyOwner",
                                                "namePath": "onlyOwner",
                                            },
                                        }
                                    ],
                                    "body": {
                                        "nodeType": "Block",
                                        "src": src(function_body_start, function_end),
                                        "statements": [
                                            {
                                                "nodeType": "FunctionCall",
                                                "src": src(
                                                    helper_call_start,
                                                    helper_call_start + 8,
                                                ),
                                                "expression": {
                                                    "nodeType": "Identifier",
                                                    "name": "helper",
                                                    "src": src(
                                                        helper_call_start,
                                                        helper_call_start + 6,
                                                    ),
                                                },
                                            },
                                            {
                                                "nodeType": "FunctionCall",
                                                "src": src(transfer_start, transfer_start + 14),
                                                "expression": {
                                                    "nodeType": "MemberAccess",
                                                    "memberName": "transfer",
                                                    "src": src(
                                                        transfer_start,
                                                        transfer_start + 14,
                                                    ),
                                                    "expression": {
                                                        "nodeType": "Identifier",
                                                        "name": "token",
                                                        "src": src(
                                                            transfer_start,
                                                            transfer_start + 5,
                                                        ),
                                                    },
                                                },
                                            },
                                            {
                                                "nodeType": "FunctionCall",
                                                "src": src(
                                                    signature_start,
                                                    signature_start + 9,
                                                ),
                                                "expression": {
                                                    "nodeType": "Identifier",
                                                    "name": "ecrecover",
                                                    "src": src(
                                                        signature_start,
                                                        signature_start + 9,
                                                    ),
                                                },
                                            },
                                            {
                                                "nodeType": "MemberAccess",
                                                "memberName": "chainid",
                                                "src": src(chain_start, chain_start + 13),
                                                "expression": {
                                                    "nodeType": "Identifier",
                                                    "name": "block",
                                                    "src": src(chain_start, chain_start + 5),
                                                },
                                            },
                                        ],
                                    },
                                },
                            ],
                        }
                    ],
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_ast_synthetic_nodes_are_scoped_to_their_source_path(
    tmp_path: Path,
    config_factory,
) -> None:
    artifact_root = tmp_path / "artifacts"
    for directory in ("one", "two"):
        relative_path = f"src/{directory}/Shared.sol"
        source = tmp_path / relative_path
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(
            "// synthetic local fixture\n"
            "pragma solidity ^0.8.20;\n"
            "contract Shared {\n"
            "    modifier onlyOwner() { _;\n"
            "    }\n"
            "    function helper() internal { }\n"
            "    function transfer(address token) external onlyOwner {\n"
            "        helper();\n"
            "        token.transfer(address(this), 1);\n"
            "        ecrecover(bytes32(0), 0, bytes32(0), bytes32(0));\n"
            "        uint256 chain = block.chainid;\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        _write_scoped_ast_artifact(
            artifact_root,
            source,
            relative_path,
            f"{directory}.json",
        )

    _config, discovery, projects, _fallback_build = _fallback_inputs(
        tmp_path,
        config_factory,
    )
    build = build_solidity_index(discovery, projects, [artifact_root])
    graphs = build_solidity_graphs(discovery, build)
    assert build.index.ast_sources == ["src/one/Shared.sol", "src/two/Shared.sol"]

    transformations = {
        "modifier_name_privilege_node_classification",
        "known_asset_transfer_call.asset_node",
        "solc_ast_signature_primitive_node",
        "solc_ast_block_chainid_node",
    }
    for transformation in transformations:
        nodes = [node for node in graphs.nodes if node.transformation == transformation]
        assert len(nodes) == 2
        assert len({node.id for node in nodes}) == 2
        assert {node.path for node in nodes} == {
            "src/one/Shared.sol",
            "src/two/Shared.sol",
        }

    entities_by_id = {entity.id: entity for entity in build.index.entities}
    indexed_edges = [
        edge
        for edge in graphs.edges
        if edge.provenance is SolidityProvenance.COMPILER
        and edge.graph in {SolidityGraphKind.INTERNAL_CALL, SolidityGraphKind.MODIFIER}
    ]
    assert len(indexed_edges) == 4
    assert all(
        entities_by_id[edge.source_id].path == entities_by_id[edge.target_id].path
        for edge in indexed_edges
    )


def _compiler_storage_entry(
    *,
    entry_id: str,
    path: str,
    contract_name: str,
    slot: str,
) -> SolidityStorageEntry:
    return SolidityStorageEntry(
        id=entry_id,
        contract_name=contract_name,
        declaring_contract_name=contract_name,
        variable_name="balance",
        type_name="uint256",
        slot=slot,
        offset=0,
        byte_size=32,
        ast_id=1,
        path=path,
        start_line=1,
        end_line=1,
        source_hash="0" * 64,
        provenance=SolidityProvenance.COMPILER,
        confidence=0.95,
        transformation="synthetic_compiler_storage_layout",
    )


def test_versioned_layout_comparisons_are_path_scoped_and_deterministic() -> None:
    entries = [
        _compiler_storage_entry(
            entry_id="one-v1",
            path="src/one/Versions.sol",
            contract_name="LedgerV1",
            slot="0",
        ),
        _compiler_storage_entry(
            entry_id="one-v2",
            path="src/one/Versions.sol",
            contract_name="LedgerV2",
            slot="0",
        ),
        _compiler_storage_entry(
            entry_id="two-v1",
            path="src/two/Versions.sol",
            contract_name="LedgerV1",
            slot="0",
        ),
        _compiler_storage_entry(
            entry_id="two-v2",
            path="src/two/Versions.sol",
            contract_name="LedgerV2",
            slot="1",
        ),
    ]

    first = _versioned_layout_edges(entries)
    second = _versioned_layout_edges(list(reversed(entries)))
    paths_by_id = {entry.id: entry.path for entry in entries}

    assert first == second
    assert len(first) == 2
    assert all(paths_by_id[edge.source_id] == paths_by_id[edge.target_id] for edge in first)
    assert {edge.metadata["source_path"] for edge in first} == {
        "src/one/Versions.sol",
        "src/two/Versions.sol",
    }
    assert {(edge.metadata["source_path"], edge.metadata["compatibility"]) for edge in first} == {
        ("src/one/Versions.sol", "compatible"),
        ("src/two/Versions.sol", "incompatible"),
    }


def test_over_ceiling_candidate_graph_degrades_with_bounded_typed_evidence(
    tmp_path: Path,
    config_factory,
) -> None:
    variable_count = 100
    declarations = "\n".join(
        f"    uint256 private value{index};" for index in range(variable_count)
    )
    updates = "\n".join(f"        value{index} += 1;" for index in range(variable_count))
    source = tmp_path / "src" / "GraphPressure.sol"
    source.parent.mkdir(parents=True)
    source.write_text(
        "// synthetic non-production graph pressure fixture\n"
        "pragma solidity ^0.8.20;\n"
        "contract GraphPressure {\n"
        f"{declarations}\n"
        "    function reconcile() external {\n"
        f"{updates}\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    _config, discovery, projects, build = _fallback_inputs(tmp_path, config_factory)
    graphs = build_solidity_graphs(
        discovery,
        build,
        max_artifact_bytes=_TEST_GRAPH_LIMIT,
    )
    artifact = {"schema_version": "1.0", "graphs": graphs.model_dump(mode="json")}
    artifact_bytes = stable_json_bytes(artifact)
    candidate_canonical_bytes = sum(
        len(_canonical_edge_bytes(edge)) for edge in graphs.edges
    ) + sum(item.omitted_canonical_bytes for item in graphs.edge_omissions)

    assert candidate_canonical_bytes > _TEST_GRAPH_LIMIT
    assert len(artifact_bytes) <= _TEST_GRAPH_LIMIT
    assert graphs.generation_complete is False
    assert graphs.edge_omissions
    assert SolidityGraphKind.STATE_DEPENDENCY not in graphs.analyzed_graphs
    assert sum(item.omitted_count for item in graphs.edge_omissions) > 0
    assert len(graphs.edge_omissions) <= len(SolidityGraphKind)
    assert all(len(item.omitted_sample_sha256s) <= 16 for item in graphs.edge_omissions)

    retained = graphs.coverage
    assert retained[SolidityGraphKind.STATE_DEPENDENCY.value] > 0
    assert retained[SolidityGraphKind.SENSITIVE_REACHABILITY.value] > 0
    assert retained[SolidityGraphKind.INHERITANCE.value] == 0

    artifact_path = tmp_path / "run" / "solidity-graphs.json"
    published_bytes = write_json_bounded(
        artifact_path,
        artifact,
        max_bytes=graphs.artifact_byte_limit,
    )
    assert published_bytes == artifact_path.stat().st_size == len(artifact_bytes)

    policy = SolidityShardPolicy.build()
    shards = build_solidity_shard_inventory(
        discovery,
        build.index,
        graphs,
        policy=policy,
    )
    assert shards.coverage.complete is False
    assert shards.coverage.graph_edges_covered == len(graphs.edges)
    assert shards.coverage.graph_edges_total == len(graphs.edges)
    assert shards.coverage.graph_edge_candidate_occurrences_total == (
        shards.coverage.graph_edge_candidate_occurrences_covered
        + sum(item.omitted_count for item in graphs.edge_omissions)
    )
    verify_solidity_shard_inventory(
        discovery=discovery,
        index=build.index,
        graphs=graphs,
        inventory=shards,
        expected_policy=policy,
    )

    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[],
    )
    assert coverage.graph_analysis_state is AnalysisState.ATTEMPTED_FAILED
    assert coverage.graph_candidate_edge_counts[SolidityGraphKind.STATE_DEPENDENCY.value] == (
        coverage.graph_retained_edge_occurrence_counts[SolidityGraphKind.STATE_DEPENDENCY.value]
        + coverage.graph_omitted_edge_counts[SolidityGraphKind.STATE_DEPENDENCY.value]
    )
    assert coverage.graph_omission_evidence_sha256s == sorted(
        item.evidence_sha256 for item in graphs.edge_omissions
    )


def test_pressure_selection_is_deterministic_and_risk_ordered(
    tmp_path: Path,
    config_factory,
) -> None:
    fixture = Path("tests/fixtures/solidity/realistic_scale/solidity_005k").resolve()
    _config, discovery, _projects, build = _fallback_inputs(fixture, config_factory)

    first = build_solidity_graphs(discovery, build, max_artifact_bytes=_TEST_GRAPH_LIMIT)
    second = build_solidity_graphs(discovery, build, max_artifact_bytes=_TEST_GRAPH_LIMIT)

    assert first == second
    assert first.generation_complete is False
    omitted = {item.graph: item.omitted_count for item in first.edge_omissions}
    assert SolidityGraphKind.PRIVILEGE not in omitted
    assert SolidityGraphKind.ASSET_FLOW not in omitted
    assert omitted[SolidityGraphKind.SENSITIVE_REACHABILITY] > 0
    frontier = _GRAPH_PRIORITY[SolidityGraphKind.SENSITIVE_REACHABILITY]
    assert all(
        first.coverage[kind.value] == 0
        for kind, priority in _GRAPH_PRIORITY.items()
        if priority < frontier
    )
    assert omitted[SolidityGraphKind.EVENT_FLOW] > 0
    assert omitted[SolidityGraphKind.INTERNAL_CALL] > 0


def test_edge_pressure_selection_is_input_order_independent() -> None:
    graph_kinds = (
        SolidityGraphKind.PRIVILEGE,
        SolidityGraphKind.ASSET_FLOW,
        SolidityGraphKind.SENSITIVE_REACHABILITY,
        SolidityGraphKind.STATE_DEPENDENCY,
        SolidityGraphKind.EVENT_FLOW,
    )
    candidates = [
        SolidityGraphEdge(
            graph=kind,
            source_id=f"source:{index}",
            target_id=f"target:{index}",
            label=f"synthetic {kind.value}",
            provenance=SolidityProvenance.COMPILER,
            path="Synthetic.sol",
            start_line=index + 1,
            end_line=index + 1,
            source_hash=hashlib.sha256(kind.value.encode()).hexdigest(),
            confidence=1,
            transformation="synthetic_pressure_order",
        )
        for index, kind in enumerate(graph_kinds)
    ]

    retained: list[list[SolidityGraphEdge]] = []
    for ordered in (candidates, list(reversed(candidates))):
        collector = _BoundedEdgeCollector(1_000_000, max_retained_edges=2)
        collector.extend(ordered)
        collector.discard_below_omission_frontier()
        retained.append(collector.retained_edges())

    assert retained[0] == retained[1]
    assert {edge.graph for edge in retained[0]} == {
        SolidityGraphKind.PRIVILEGE,
        SolidityGraphKind.ASSET_FLOW,
    }
    sensitive_frontier = _GRAPH_PRIORITY[SolidityGraphKind.SENSITIVE_REACHABILITY]
    assert all(_GRAPH_PRIORITY[edge.graph] > sensitive_frontier for edge in retained[0])


def test_duplicate_edges_are_normalized_without_triggering_pressure_frontier() -> None:
    low = SolidityGraphEdge(
        graph=SolidityGraphKind.EVENT_FLOW,
        source_id="source:low",
        target_id="target:low",
        label="synthetic low-risk candidate",
        provenance=SolidityProvenance.COMPILER,
        path="Synthetic.sol",
        start_line=1,
        end_line=1,
        source_hash="1" * 64,
        confidence=1,
        transformation="synthetic_duplicate_pressure",
    )
    high = low.model_copy(
        update={
            "graph": SolidityGraphKind.PRIVILEGE,
            "source_id": "source:high",
            "target_id": "target:high",
            "label": "synthetic high-risk candidate",
            "source_hash": "2" * 64,
        }
    )

    observations = []
    for stream in ((low, high, high), (high, high, low)):
        collector = _BoundedEdgeCollector(1_000_000, max_retained_edges=2)
        collector.extend(stream)
        collector.discard_below_omission_frontier()
        observations.append((collector.retained_edges(), collector.omissions()))

    assert observations[0] == observations[1]
    assert observations[0][0] == [low, high]
    assert observations[0][1] == ()


def test_evicted_duplicate_edges_have_order_independent_occurrence_evidence() -> None:
    low = SolidityGraphEdge(
        graph=SolidityGraphKind.EVENT_FLOW,
        source_id="source:low",
        target_id="target:low",
        label="synthetic low-risk candidate",
        provenance=SolidityProvenance.COMPILER,
        path="Synthetic.sol",
        start_line=1,
        end_line=1,
        source_hash="1" * 64,
        confidence=1,
        transformation="synthetic_evicted_duplicate",
    )
    high = low.model_copy(
        update={
            "graph": SolidityGraphKind.PRIVILEGE,
            "source_id": "source:high",
            "target_id": "target:high",
            "label": "synthetic high-risk candidate",
            "source_hash": "2" * 64,
        }
    )

    observations = []
    for stream in ((low, high, low), (low, low, high)):
        collector = _BoundedEdgeCollector(1_000_000, max_retained_edges=1)
        collector.extend(stream)
        observations.append((collector.retained_edges(), collector.omissions()))

    assert observations[0] == observations[1]
    assert observations[0][0] == [high]
    omission = observations[0][1][0]
    assert omission.graph is SolidityGraphKind.EVENT_FLOW
    assert omission.retained_count == 0
    assert omission.retained_occurrence_count == 0
    assert omission.omitted_count == 2
    assert omission.candidate_count == 2


def test_large_duplicate_edge_variant_enforces_byte_capacity_independent_of_order() -> None:
    small = SolidityGraphEdge(
        graph=SolidityGraphKind.STATE_DEPENDENCY,
        source_id="source:shared",
        target_id="target:shared",
        label="synthetic shared candidate",
        provenance=SolidityProvenance.COMPILER,
        path="Synthetic.sol",
        start_line=1,
        end_line=1,
        source_hash="3" * 64,
        confidence=1,
        transformation="synthetic_duplicate_variant_capacity",
    )
    large = small.model_copy(
        update={
            "provenance": SolidityProvenance.HEURISTIC,
            "confidence": 0.4,
            "metadata": {"padding": "x" * 8_192},
        }
    )
    other = small.model_copy(
        update={
            "source_id": "source:other",
            "target_id": "target:other",
            "label": "synthetic other candidate",
            "source_hash": "4" * 64,
        }
    )
    byte_budget = len(_canonical_edge_bytes(large))

    observations = []
    for stream in ((small, other, large), (large, small, other)):
        collector = _BoundedEdgeCollector(byte_budget, max_retained_edges=2)
        collector.extend(stream)
        observations.append((collector.retained_edges(), collector.omissions()))

    assert observations[0] == observations[1]
    assert len(observations[0][0]) == 1
    omission = observations[0][1][0]
    assert omission.graph is SolidityGraphKind.STATE_DEPENDENCY
    assert omission.candidate_count == 3
    assert omission.retained_occurrence_count + omission.omitted_count == 3


def test_evicted_duplicate_facts_and_variants_have_order_independent_evidence() -> None:
    first = SolidityGraphNode(
        id="candidate:first",
        kind=SolidityGraphNodeKind.ROLE,
        label="shared role",
        path="Synthetic.sol",
        start_line=1,
        end_line=1,
        source_hash="4" * 64,
        provenance=SolidityProvenance.HEURISTIC,
        confidence=0.4,
        transformation="synthetic_evicted_duplicate_fact",
    )
    first_refined = first.model_copy(
        update={"provenance": SolidityProvenance.COMPILER, "confidence": 1.0}
    )
    second = first.model_copy(
        update={
            "id": "candidate:second",
            "label": "second role",
            "source_hash": "5" * 64,
        }
    )

    observations = []
    for stream in ((first, second, first_refined), (first_refined, first, second)):
        collector = _BoundedFactCollector[SolidityGraphNode](
            fact_kind=SolidityGraphFactKind.GRAPH_NODE,
            max_payload_bytes=1_000_000,
            max_records=1,
            priority=_node_retention_key,
        )
        collector.extend(stream)
        observations.append((collector.retained(), collector.omission()))

    assert observations[0] == observations[1]
    omission = observations[0][1]
    assert omission is not None
    assert omission.retained_count == 1
    assert omission.retained_occurrence_count + omission.omitted_count == 3
    assert omission.candidate_count == 3


def test_evicted_duplicate_warnings_are_order_independent_and_samples_stay_bounded() -> None:
    first, second = sorted(
        ("synthetic warning one", "synthetic warning two"),
        key=lambda warning: hashlib.sha256(json.dumps(warning).encode()).hexdigest(),
        reverse=True,
    )
    observations = []
    for stream in ((first, second, first), (first, first, second)):
        collector = _BoundedWarningCollector(max_payload_bytes=1_000_000, max_records=1)
        for warning in stream:
            collector.append(warning)
        observations.append((collector.retained(), collector.omission()))

    assert observations[0] == observations[1]
    omission = observations[0][1]
    assert omission is not None
    assert omission.omitted_count == 2
    assert omission.retained_occurrence_count == 1
    assert omission.candidate_count == 3

    bounded = _BoundedWarningCollector(max_payload_bytes=1_000_000, max_records=1)
    for index in range(40):
        bounded.append(f"synthetic bounded warning {index}")
    bounded_omission = bounded.omission()
    assert bounded_omission is not None
    assert len(bounded_omission.omitted_sample_sha256s) == 16


def test_fixed_endpoint_pins_retain_high_risk_edge_nodes_under_pressure() -> None:
    def node(identifier: str, kind: SolidityGraphNodeKind) -> SolidityGraphNode:
        return SolidityGraphNode(
            id=identifier,
            kind=kind,
            label=identifier,
            path="Synthetic.sol",
            start_line=1,
            end_line=1,
            source_hash=hashlib.sha256(identifier.encode()).hexdigest(),
            provenance=SolidityProvenance.COMPILER,
            confidence=1,
            transformation="synthetic_endpoint_pressure",
        )

    nodes = _BoundedFactCollector[SolidityGraphNode](
        fact_kind=SolidityGraphFactKind.GRAPH_NODE,
        max_payload_bytes=1_000_000,
        max_records=2,
        priority=_node_retention_key,
    )
    edges = _BoundedEdgeCollector(
        1_000_000,
        max_retained_edges=1,
        endpoint_sink=nodes.set_endpoint_priority,
    )
    edge = SolidityGraphEdge(
        graph=SolidityGraphKind.PRIVILEGE,
        source_id="endpoint:function",
        target_id="endpoint:role",
        label="synthetic privileged edge",
        provenance=SolidityProvenance.COMPILER,
        path="Synthetic.sol",
        start_line=1,
        end_line=1,
        source_hash="3" * 64,
        confidence=1,
        transformation="synthetic_endpoint_pressure",
    )
    edges.append(edge)
    nodes.set_endpoint_priorities(edges.endpoint_priorities())
    nodes.extend(
        (
            node("endpoint:role", SolidityGraphNodeKind.ROLE),
            node("isolated:first", SolidityGraphNodeKind.ENTITY),
            node("isolated:second", SolidityGraphNodeKind.ENTITY),
            node("isolated:third", SolidityGraphNodeKind.ENTITY),
            node("endpoint:function", SolidityGraphNodeKind.ENTITY),
            node("isolated:fourth", SolidityGraphNodeKind.ENTITY),
        )
    )

    assert nodes.retained_ids() == {"endpoint:function", "endpoint:role"}
    assert edges.retained_edges() == [edge]
    omission = nodes.omission()
    assert omission is not None
    assert omission.candidate_count == 6
    assert omission.retained_count == 2


def test_storage_order_edge_recovers_late_selected_storage_endpoints(
    tmp_path: Path,
    config_factory,
) -> None:
    source = tmp_path / "StoragePressure.sol"
    source.write_text(
        "// synthetic local storage endpoint pressure fixture\n"
        "pragma solidity ^0.8.20;\n"
        "contract StoragePressure {\n"
        "    uint256 private first;\n"
        "    uint256 private second;\n"
        "    uint256 private third;\n"
        "}\n",
        encoding="utf-8",
    )
    _config, discovery, _projects, build = _fallback_inputs(tmp_path, config_factory)
    policy = SolidityShardPolicy.build(
        max_primary_graph_nodes_per_shard=2,
        max_overlap_graph_nodes_per_shard=2,
        max_primary_graph_edges_per_shard=1,
        max_overlap_graph_edges_per_shard=1,
        max_boundaries_per_shard=1,
        max_total_boundaries=1,
    )

    graphs = build_solidity_graphs(discovery, build, shard_policy=policy)

    assert len(graphs.edges) == 1
    assert graphs.edges[0].graph is SolidityGraphKind.UPGRADE_COMPATIBILITY
    node_ids = {node.id for node in graphs.nodes}
    assert {graphs.edges[0].source_id, graphs.edges[0].target_id} <= node_ids


def test_duplicate_facts_keep_best_record_without_claiming_budget_omission() -> None:
    low = SolidityGraphNode(
        id="shared:node",
        kind=SolidityGraphNodeKind.ROLE,
        label="shared role",
        path="Synthetic.sol",
        start_line=1,
        end_line=1,
        source_hash="4" * 64,
        provenance=SolidityProvenance.HEURISTIC,
        confidence=0.4,
        transformation="synthetic_duplicate_fact",
    )
    high = low.model_copy(update={"provenance": SolidityProvenance.COMPILER, "confidence": 1.0})

    observations = []
    for stream in ((low, high), (high, low)):
        collector = _BoundedFactCollector[SolidityGraphNode](
            fact_kind=SolidityGraphFactKind.GRAPH_NODE,
            max_payload_bytes=1_000_000,
            max_records=1,
            priority=_node_retention_key,
        )
        collector.extend(stream)
        observations.append((collector.retained(), collector.omission()))

    assert observations[0] == observations[1]
    assert observations[0][0] == [high]
    assert observations[0][1] is None


@pytest.mark.parametrize("invalid_limit", [True, 1.5, 1_023, MAX_JSON_ARTIFACT_BYTES + 1])
def test_graph_builder_rejects_invalid_artifact_limits(
    tmp_path: Path,
    config_factory,
    invalid_limit: object,
) -> None:
    _config, discovery, _projects, build = _fallback_inputs(tmp_path, config_factory)

    with pytest.raises(ValueError, match="graph artifact byte ceiling"):
        build_solidity_graphs(
            discovery,
            build,
            max_artifact_bytes=invalid_limit,  # type: ignore[arg-type]
        )


def test_omitted_external_and_asset_edges_remain_in_classification_denominators(
    tmp_path: Path,
    config_factory,
) -> None:
    source = tmp_path / "src" / "Coverage.sol"
    source.parent.mkdir(parents=True)
    source.write_text(
        "// synthetic local coverage fixture\n"
        "pragma solidity ^0.8.20;\n"
        "contract Coverage { function inspect() external {} }\n",
        encoding="utf-8",
    )
    _config, discovery, projects, build = _fallback_inputs(tmp_path, config_factory)
    omitted_counts = {
        SolidityGraphKind.ASSET_FLOW: 3,
        SolidityGraphKind.EXTERNAL_CALL: 2,
    }
    omissions = tuple(
        SolidityGraphOmission.build(
            graph=kind,
            candidate_count=count,
            retained_count=0,
            omitted_count=count,
            omitted_canonical_bytes=count * 320,
            omitted_stream_sha256=hashlib.sha256(kind.value.encode("utf-8")).hexdigest(),
            omitted_sample_sha256s=(hashlib.sha256(f"{kind.value}:0".encode()).hexdigest(),),
        )
        for kind, count in sorted(omitted_counts.items(), key=lambda item: item[0].value)
    )
    graphs = SolidityGraphSet(
        edges=[],
        retained_occurrences=(),
        analyzed_graphs=[kind for kind in SolidityGraphKind if kind not in omitted_counts],
        coverage={kind.value: 0 for kind in SolidityGraphKind},
        generation_complete=False,
        edge_omissions=omissions,
    )

    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[],
    )

    external = coverage.quality_metrics["external_calls_classified"]
    assert (external.numerator, external.denominator, external.population) == (0, 2, 2)
    assert external.percentage == 0
    assert external.failures == [
        "2 candidate external-call edge(s) were omitted before classification"
    ]
    asset = coverage.quality_metrics["asset_flows_classified"]
    assert (asset.numerator, asset.denominator, asset.population) == (0, 3, 3)
    assert asset.percentage == 0
    assert asset.failures == [
        "3 candidate asset-flow edge(s) lack retained complete classification"
    ]
