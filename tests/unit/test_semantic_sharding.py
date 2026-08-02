from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    AuditQualityStatus,
    AuditReport,
    AuditRunStatus,
    MinimumAnalysisFloor,
    RepositoryMap,
    SolidityEntity,
    SolidityGraphEdge,
    SolidityGraphKind,
    SolidityGraphNode,
    SolidityGraphNodeKind,
    SolidityGraphSet,
    SolidityProvenance,
    SolidityStorageEntry,
    SoliditySymbolIndex,
)
from mmaudit.models.sharding import (
    SolidityGraphsArtifact,
    SolidityIndexArtifact,
    SolidityShardInventory,
    SolidityShardOverlapKind,
    SolidityShardPolicy,
    SolidityShardReportBinding,
    SolidityShardRiskSurface,
    SolidityShardsArtifact,
    solidity_shard_semantic_dependency_sha256,
)
from mmaudit.orchestration.manifest import (
    RunEvidenceManifest,
    build_run_evidence_manifest,
    canonical_sha256,
    validate_solidity_shard_artifacts,
    write_run_evidence_manifest,
)
from mmaudit.orchestration.run_status import minimum_analysis_floor_quality_gate
from mmaudit.orchestration.verification import (
    RunVerificationMismatchKind,
    RunVerificationStatus,
    verify_run_evidence,
)
from mmaudit.repository.discovery import DiscoveryResult, discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.repository.mapping import build_repository_map
from mmaudit.solidity.graphs import build_solidity_graphs
from mmaudit.solidity.index import build_solidity_index
from mmaudit.solidity.projects import discover_solidity_projects
from mmaudit.solidity.sharding import (
    SolidityShardingError,
    _graph_set_context_sha256,
    _graph_set_projection_sha256,
    _graph_set_sha256,
    build_solidity_shard_inventory,
    solidity_graph_edge_id,
    verify_solidity_shard_inventory,
    verify_solidity_shard_projection,
)


@dataclass(frozen=True)
class _ShardInputs:
    discovery: DiscoveryResult
    index: SoliditySymbolIndex
    graphs: SolidityGraphSet
    cross_file_edge: SolidityGraphEdge
    source_function: SolidityEntity
    target_function: SolidityEntity
    storage_entry: SolidityStorageEntry


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _reseal_inventory_payload(payload: dict[str, object]) -> None:
    payload["inventory_sha256"] = _canonical_sha256(
        {key: value for key, value in payload.items() if key != "inventory_sha256"}
    )


def _reseal_semantic_shards(payload: dict[str, object]) -> None:
    fact_fields = {
        SolidityShardOverlapKind.ENTITY: "entity_facts",
        SolidityShardOverlapKind.GRAPH_NODE: "graph_node_facts",
        SolidityShardOverlapKind.GRAPH_EDGE: "graph_edge_facts",
        SolidityShardOverlapKind.STORAGE_ENTRY: "storage_facts",
    }
    membership_fields = {
        SolidityShardOverlapKind.ENTITY: ("primary_entity_ids", "overlap_entity_ids"),
        SolidityShardOverlapKind.GRAPH_NODE: (
            "primary_graph_node_ids",
            "overlap_graph_node_ids",
        ),
        SolidityShardOverlapKind.GRAPH_EDGE: (
            "primary_graph_edge_ids",
            "overlap_graph_edge_ids",
        ),
        SolidityShardOverlapKind.STORAGE_ENTRY: (
            "primary_storage_entry_ids",
            "overlap_storage_entry_ids",
        ),
    }
    record_hashes: dict[SolidityShardOverlapKind, dict[str, str]] = {}
    for kind, field_name in fact_fields.items():
        facts = payload[field_name]
        assert isinstance(facts, list)
        record_hashes[kind] = {
            str(item["resource_id"]): str(item["record_sha256"])
            for item in facts
            if isinstance(item, dict)
        }
    boundaries = payload["boundaries"]
    assert isinstance(boundaries, list)
    boundary_hashes = {
        str(item["boundary_id"]): str(item["boundary_sha256"])
        for item in boundaries
        if isinstance(item, dict)
    }
    shards = payload["shards"]
    assert isinstance(shards, list)
    for shard in shards:
        assert isinstance(shard, dict)
        bindings: list[tuple[SolidityShardOverlapKind, str, str]] = []
        for kind, field_names in membership_fields.items():
            for field_name in field_names:
                identifiers = shard[field_name]
                assert isinstance(identifiers, list)
                bindings.extend(
                    (kind, str(resource_id), record_hashes[kind][str(resource_id)])
                    for resource_id in identifiers
                )
        boundary_ids = [
            *shard["inbound_boundary_ids"],
            *shard["outbound_boundary_ids"],
        ]
        shard["semantic_dependency_sha256"] = solidity_shard_semantic_dependency_sha256(
            fact_bindings=bindings,
            boundary_sha256s=[boundary_hashes[str(item)] for item in boundary_ids],
        )
        shard["shard_sha256"] = _canonical_sha256(
            {key: value for key, value in shard.items() if key != "shard_sha256"}
        )
    _reseal_inventory_payload(payload)


def _write_synthetic_project(root: Path) -> None:
    (root / "src").mkdir(parents=True)
    (root / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\ntest = "test"\n',
        encoding="utf-8",
    )
    (root / "src" / "Router.sol").write_text(
        """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

abstract contract Router {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function route(uint256 amount) external {
        require(msg.sender == owner, "synthetic owner only");
        amount;
    }
}
""",
        encoding="utf-8",
    )
    (root / "src" / "Ledger.sol").write_text(
        """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

abstract contract Ledger {
    uint256 public reserve;

    function record(uint256 amount) external {
        reserve += amount;
    }
}
""",
        encoding="utf-8",
    )
    (root / "src" / "Unrelated.sol").write_text(
        """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

abstract contract Unrelated {
    event SyntheticMarker(uint256 value);

    function noop() external pure returns (bool) {
        return true;
    }
}
""",
        encoding="utf-8",
    )


def _entity(index: SoliditySymbolIndex, *, contract: str, name: str) -> SolidityEntity:
    return next(
        item for item in index.entities if item.contract_name == contract and item.name == name
    )


def _shard_inputs(tmp_path: Path, config_factory: Callable[..., object]) -> _ShardInputs:
    root = tmp_path / "semantic-shard-target"
    _write_synthetic_project(root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())  # type: ignore[attr-defined]
    projects = discover_solidity_projects(  # type: ignore[attr-defined]
        discovery,
        config.smart_contracts,  # type: ignore[attr-defined]
    )
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    source_function = _entity(build.index, contract="Router", name="route")
    target_function = _entity(build.index, contract="Ledger", name="record")
    reserve = _entity(build.index, contract="Ledger", name="reserve")

    cross_file_edge = SolidityGraphEdge(
        graph=SolidityGraphKind.INTERNAL_CALL,
        source_id=source_function.id,
        target_id=target_function.id,
        label="synthetic exact cross-file accounting dependency",
        provenance=SolidityProvenance.FALLBACK,
        path=source_function.path,
        start_line=source_function.start_line,
        end_line=source_function.end_line,
        source_hash=source_function.source_hash,
        confidence=0.70,
        transformation="synthetic_local_cross_file_dependency",
        metadata={"resolution": "synthetic_exact_entity_binding"},
    )
    storage_entry = SolidityStorageEntry(
        id="synthetic-ledger-reserve-slot",
        contract_name="Ledger",
        declaring_contract_name="Ledger",
        variable_name="reserve",
        type_name="uint256",
        slot="0",
        offset=0,
        byte_size=32,
        path=reserve.path,
        start_line=reserve.start_line,
        end_line=reserve.end_line,
        source_hash=reserve.source_hash,
        provenance=SolidityProvenance.FALLBACK,
        confidence=0.70,
        transformation="synthetic_local_storage_binding",
    )
    storage_node = SolidityGraphNode(
        id=storage_entry.id,
        kind=SolidityGraphNodeKind.STORAGE_SLOT,
        label="Ledger.reserve@0",
        path=storage_entry.path,
        start_line=storage_entry.start_line,
        end_line=storage_entry.end_line,
        source_hash=storage_entry.source_hash,
        provenance=storage_entry.provenance,
        confidence=storage_entry.confidence,
        transformation="synthetic_local_storage_binding.node",
    )
    coverage = dict(graphs.coverage)
    coverage[SolidityGraphKind.INTERNAL_CALL.value] = (
        coverage.get(SolidityGraphKind.INTERNAL_CALL.value, 0) + 1
    )
    graphs = graphs.model_copy(
        update={
            "nodes": [*graphs.nodes, storage_node],
            "edges": [*graphs.edges, cross_file_edge],
            "storage_layout": [*graphs.storage_layout, storage_entry],
            "coverage": coverage,
        }
    )
    return _ShardInputs(
        discovery=discovery,
        index=build.index,
        graphs=graphs,
        cross_file_edge=cross_file_edge,
        source_function=source_function,
        target_function=target_function,
        storage_entry=storage_entry,
    )


def _inventory(inputs: _ShardInputs) -> SolidityShardInventory:
    return build_solidity_shard_inventory(
        inputs.discovery,
        inputs.index,
        inputs.graphs,
    )


def _report_for_shards(
    *,
    repository: RepositoryMap,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet,
    inventory: SolidityShardInventory | None,
) -> AuditReport:
    return AuditReport(
        schema_version="1.0",
        run_id="semantic-shard-projection-test",
        generated_at=datetime(2026, 8, 2, tzinfo=UTC),
        completed=True,
        incomplete_reasons=[],
        repository=repository,
        configuration_hash="a" * 64,
        model_configuration_hash="b" * 64,
        privacy={"code_egress_enabled": False},
        scanner_runs=[],
        usage=[],
        budget_usd=0,
        accounted_cost_usd=0,
        findings=[],
        rejected_findings=[],
        metadata={
            "solidity": {
                "index_summary": {
                    "entities": len(index.entities),
                    "ast_sources": len(index.ast_sources),
                    "fallback_sources": len(index.fallback_sources),
                },
                "graph_summary": {
                    "edges": len(graphs.edges),
                    "warnings": len(graphs.warnings),
                },
                "shard_summary": (
                    SolidityShardReportBinding.from_inventory(inventory).model_dump(mode="json")
                    if inventory is not None
                    else None
                ),
            }
        },
    )


def _write_shard_artifacts(
    root: Path,
    *,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet,
    inventory: SolidityShardInventory | None,
) -> None:
    root.mkdir(exist_ok=True)
    payloads = {
        "solidity-index.json": SolidityIndexArtifact(index=index).model_dump(mode="json"),
        "solidity-graphs.json": SolidityGraphsArtifact(graphs=graphs).model_dump(mode="json"),
        "solidity-shards.json": SolidityShardsArtifact(inventory=inventory).model_dump(mode="json"),
    }
    for name, payload in payloads.items():
        (root / name).write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )


def test_shard_inventory_is_deterministic_under_input_reordering(
    tmp_path: Path,
    config_factory,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    expected = _inventory(inputs)
    reordered_discovery = replace(
        inputs.discovery,
        files=tuple(reversed(inputs.discovery.files)),
    )
    reordered_index = inputs.index.model_copy(
        update={
            "projects": list(reversed(inputs.index.projects)),
            "entities": list(reversed(inputs.index.entities)),
            "ast_sources": list(reversed(inputs.index.ast_sources)),
            "fallback_sources": list(reversed(inputs.index.fallback_sources)),
            "warnings": list(reversed(inputs.index.warnings)),
        }
    )
    reordered_graphs = inputs.graphs.model_copy(
        update={
            "nodes": list(reversed(inputs.graphs.nodes)),
            "edges": list(reversed(inputs.graphs.edges)),
            "storage_layout": list(reversed(inputs.graphs.storage_layout)),
            "analyzed_graphs": list(reversed(inputs.graphs.analyzed_graphs)),
            "coverage": dict(reversed(tuple(inputs.graphs.coverage.items()))),
            "warnings": list(reversed(inputs.graphs.warnings)),
        }
    )

    observed = build_solidity_shard_inventory(
        reordered_discovery,
        reordered_index,
        reordered_graphs,
    )

    assert observed == expected
    assert observed.inventory_sha256 == expected.inventory_sha256
    assert observed.model_dump(mode="json") == expected.model_dump(mode="json")


def test_shards_exactly_cover_every_primary_source_and_semantic_inventory(
    tmp_path: Path,
    config_factory,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    inventory = _inventory(inputs)
    solidity_files = sorted(
        (item for item in inputs.discovery.files if item.language == "Solidity"),
        key=lambda item: item.relative_path,
    )

    assert [unit.path for unit in inventory.source_units] == [
        item.relative_path for item in solidity_files
    ]
    assert [unit.content_sha256 for unit in inventory.source_units] == [
        item.sha256 for item in solidity_files
    ]
    assert [unit.utf8_bytes for unit in inventory.source_units] == [
        len(item.content.encode("utf-8")) for item in solidity_files
    ]
    assert len({unit.primary_shard_id for unit in inventory.source_units}) == len(solidity_files)
    assert {shard.source_path for shard in inventory.shards} == {
        item.relative_path for item in solidity_files
    }

    expected_entity_ids = tuple(sorted(item.id for item in inputs.index.entities))
    expected_node_ids = tuple(sorted(item.id for item in inputs.graphs.nodes))
    expected_edge_ids = tuple(sorted(solidity_graph_edge_id(item) for item in inputs.graphs.edges))
    expected_storage_ids = tuple(sorted(item.id for item in inputs.graphs.storage_layout))
    assert inventory.entity_ids == expected_entity_ids
    assert inventory.graph_node_ids == expected_node_ids
    assert inventory.graph_edge_ids == expected_edge_ids
    assert inventory.storage_entry_ids == expected_storage_ids
    assert (
        tuple(sorted(item for shard in inventory.shards for item in shard.primary_entity_ids))
        == expected_entity_ids
    )
    assert (
        tuple(sorted(item for shard in inventory.shards for item in shard.primary_graph_node_ids))
        == expected_node_ids
    )
    assert (
        tuple(sorted(item for shard in inventory.shards for item in shard.primary_graph_edge_ids))
        == expected_edge_ids
    )
    assert (
        tuple(
            sorted(item for shard in inventory.shards for item in shard.primary_storage_entry_ids)
        )
        == expected_storage_ids
    )

    assert inventory.coverage.complete is True
    assert inventory.coverage.source_units_covered == len(solidity_files)
    assert inventory.coverage.source_bytes_covered == sum(
        len(item.content.encode("utf-8")) for item in solidity_files
    )
    assert inventory.coverage.entities_covered == len(expected_entity_ids)
    assert inventory.coverage.graph_nodes_covered == len(expected_node_ids)
    assert inventory.coverage.graph_edges_covered == len(expected_edge_ids)
    assert inventory.coverage.storage_entries_covered == len(expected_storage_ids)


def test_cross_file_edge_has_boundary_overlap_and_typed_risk_surfaces(
    tmp_path: Path,
    config_factory,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    inventory = _inventory(inputs)
    edge_id = solidity_graph_edge_id(inputs.cross_file_edge)
    boundary = next(item for item in inventory.boundaries if item.graph_edge_id == edge_id)
    shards_by_id = {item.shard_id: item for item in inventory.shards}
    source_shard = shards_by_id[boundary.source_shard_id]
    target_shard = shards_by_id[boundary.target_shard_id]

    assert source_shard.source_path == inputs.source_function.path
    assert target_shard.source_path == inputs.target_function.path
    assert boundary.boundary_id in source_shard.outbound_boundary_ids
    assert boundary.boundary_id in target_shard.inbound_boundary_ids
    assert edge_id in source_shard.primary_graph_edge_ids
    assert edge_id in target_shard.overlap_graph_edge_ids
    assert inputs.target_function.id in source_shard.overlap_entity_ids
    assert inputs.source_function.id in target_shard.overlap_entity_ids

    overlap_keys = {
        (
            overlap.resource_kind,
            overlap.resource_id,
            overlap.primary_shard_id,
            overlap.consumer_shard_id,
        )
        for overlap in inventory.overlaps
    }
    assert (
        SolidityShardOverlapKind.GRAPH_EDGE,
        edge_id,
        source_shard.shard_id,
        target_shard.shard_id,
    ) in overlap_keys
    assert (
        SolidityShardOverlapKind.ENTITY,
        inputs.target_function.id,
        target_shard.shard_id,
        source_shard.shard_id,
    ) in overlap_keys
    assert (
        SolidityShardOverlapKind.ENTITY,
        inputs.source_function.id,
        source_shard.shard_id,
        target_shard.shard_id,
    ) in overlap_keys

    risk_surfaces = {risk for shard in inventory.shards for risk in shard.risk_surfaces}
    assert SolidityShardRiskSurface.CONTRACTS in risk_surfaces
    assert SolidityShardRiskSurface.CALL_FLOW in risk_surfaces
    assert SolidityShardRiskSurface.STATE_ACCOUNTING in risk_surfaces
    assert inputs.storage_entry.id in target_shard.primary_storage_entry_ids


def test_synthetic_node_path_does_not_invent_a_cross_source_boundary(
    tmp_path: Path,
    config_factory,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    baseline = _inventory(inputs)
    target_contract = inputs.target_function
    synthetic_node = SolidityGraphNode(
        id="synthetic-shared-asset-node",
        kind=SolidityGraphNodeKind.ASSET,
        label="synthetic shared accounting asset",
        path=target_contract.path,
        start_line=target_contract.start_line,
        end_line=target_contract.end_line,
        source_hash=target_contract.source_hash,
        provenance=SolidityProvenance.FALLBACK,
        confidence=0.70,
        transformation="synthetic_local_shared_asset",
    )
    synthetic_edge = SolidityGraphEdge(
        graph=SolidityGraphKind.ASSET_FLOW,
        source_id=inputs.source_function.id,
        target_id=synthetic_node.id,
        label="synthetic shared asset observation",
        provenance=SolidityProvenance.FALLBACK,
        path=inputs.source_function.path,
        start_line=inputs.source_function.start_line,
        end_line=inputs.source_function.end_line,
        source_hash=inputs.source_function.source_hash,
        confidence=0.70,
        transformation="synthetic_local_asset_observation",
        metadata={"operation": "balance_observation"},
    )
    graphs = inputs.graphs.model_copy(
        update={
            "nodes": [*inputs.graphs.nodes, synthetic_node],
            "edges": [*inputs.graphs.edges, synthetic_edge],
            "coverage": {
                **inputs.graphs.coverage,
                SolidityGraphKind.ASSET_FLOW.value: (
                    inputs.graphs.coverage.get(SolidityGraphKind.ASSET_FLOW.value, 0) + 1
                ),
            },
        }
    )

    observed = build_solidity_shard_inventory(inputs.discovery, inputs.index, graphs)

    assert solidity_graph_edge_id(synthetic_edge) not in {
        item.graph_edge_id for item in observed.boundaries
    }
    assert len(observed.boundaries) == len(baseline.boundaries)


def test_sharding_rejects_stale_source_inventory(
    tmp_path: Path,
    config_factory,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    files = list(inputs.discovery.files)
    position = next(index for index, item in enumerate(files) if item.language == "Solidity")
    files[position] = replace(files[position], sha256="0" * 64)
    stale = replace(inputs.discovery, files=tuple(files))

    with pytest.raises(SolidityShardingError, match=r"source.*hash|hash.*source"):
        build_solidity_shard_inventory(stale, inputs.index, inputs.graphs)


@pytest.mark.parametrize("mutation", ["source_hash", "byte_range"])
def test_sharding_rejects_stale_entity_source_ranges(
    tmp_path: Path,
    config_factory,
    mutation: str,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    entities = list(inputs.index.entities)
    position = next(
        index for index, item in enumerate(entities) if item.id == inputs.source_function.id
    )
    updates = {"source_hash": "0" * 64} if mutation == "source_hash" else {"byte_end": 2**31 - 1}
    entities[position] = entities[position].model_copy(update=updates)
    stale_index = inputs.index.model_copy(update={"entities": entities})

    with pytest.raises(SolidityShardingError, match=r"source|range|byte"):
        build_solidity_shard_inventory(inputs.discovery, stale_index, inputs.graphs)


def test_sharding_rejects_a_dangling_graph_endpoint(
    tmp_path: Path,
    config_factory,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    dangling = inputs.cross_file_edge.model_copy(update={"target_id": "missing-graph-node"})
    graphs = inputs.graphs.model_copy(update={"edges": [*inputs.graphs.edges, dangling]})

    with pytest.raises(SolidityShardingError, match=r"endpoint|node|dangling"):
        build_solidity_shard_inventory(inputs.discovery, inputs.index, graphs)


@pytest.mark.parametrize("inventory_kind", ["entity", "node", "edge", "storage"])
def test_sharding_rejects_duplicate_semantic_ids(
    tmp_path: Path,
    config_factory,
    inventory_kind: str,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    index = inputs.index
    graphs = inputs.graphs
    if inventory_kind == "entity":
        index = index.model_copy(update={"entities": [*index.entities, index.entities[0]]})
    elif inventory_kind == "node":
        graphs = graphs.model_copy(update={"nodes": [*graphs.nodes, graphs.nodes[0]]})
    elif inventory_kind == "edge":
        graphs = graphs.model_copy(update={"edges": [*graphs.edges, graphs.edges[0]]})
    else:
        graphs = graphs.model_copy(
            update={"storage_layout": [*graphs.storage_layout, inputs.storage_entry]}
        )

    with pytest.raises(SolidityShardingError, match=r"duplicate|unique"):
        build_solidity_shard_inventory(inputs.discovery, index, graphs)


def test_inventory_schema_rejects_self_hash_tampering(
    tmp_path: Path,
    config_factory,
) -> None:
    inventory = _inventory(_shard_inputs(tmp_path, config_factory))
    payload = inventory.model_dump(mode="json")
    payload["inventory_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="inventory hash"):
        SolidityShardInventory.model_validate(payload)

    payload = inventory.model_dump(mode="json")
    payload["shards"][0]["shard_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="shard hash"):
        SolidityShardInventory.model_validate(payload)


def test_source_larger_than_policy_is_rejected_without_truncation(
    tmp_path: Path,
    config_factory,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    policy = SolidityShardPolicy.build(max_source_bytes_per_shard=4)

    with pytest.raises(SolidityShardingError, match=r"source.*bound|source.*policy"):
        build_solidity_shard_inventory(
            inputs.discovery,
            inputs.index,
            inputs.graphs,
            policy=policy,
        )


@pytest.mark.parametrize("input_kind", ["policy", "index", "graphs"])
def test_sharding_detached_revalidates_model_copy_inputs(
    tmp_path: Path,
    config_factory,
    input_kind: str,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    policy = SolidityShardPolicy.build()
    index = inputs.index
    graphs = inputs.graphs
    if input_kind == "policy":
        policy = policy.model_copy(update={"max_source_bytes_per_shard": 0})
    elif input_kind == "index":
        invalid = inputs.source_function.model_copy(
            update={"byte_start": inputs.source_function.byte_end + 1}
        )
        index = index.model_copy(
            update={
                "entities": [invalid if item.id == invalid.id else item for item in index.entities]
            }
        )
    else:
        node = next(item for item in graphs.nodes if item.id == inputs.source_function.id)
        invalid = node.model_copy(update={"start_line": node.end_line + 1})
        graphs = graphs.model_copy(
            update={"nodes": [invalid if item.id == invalid.id else item for item in graphs.nodes]}
        )

    with pytest.raises(SolidityShardingError, match="detached validation"):
        build_solidity_shard_inventory(
            inputs.discovery,
            index,
            graphs,
            policy=policy,
        )


@pytest.mark.parametrize(
    "omission",
    [
        "src/Missing.sol: exceeds max_file_bytes",
        "repository: max_files reached",
        "repository directory omitted: unsupported path",
        "src/contracts: symlink excluded",
    ],
)
def test_sharding_rejects_an_ambiguous_solidity_source_denominator(
    tmp_path: Path,
    config_factory,
    omission: str,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    incomplete = replace(inputs.discovery, omitted=(*inputs.discovery.omitted, omission))

    with pytest.raises(SolidityShardingError, match=r"coverage.*ambiguous|ambiguous.*coverage"):
        build_solidity_shard_inventory(incomplete, inputs.index, inputs.graphs)


@pytest.mark.parametrize("resource_kind", ["edge", "node"])
def test_sharding_rejects_source_owned_graph_facts_rebound_to_an_unrelated_file(
    tmp_path: Path,
    config_factory,
    resource_kind: str,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    unrelated = _entity(inputs.index, contract="Unrelated", name="noop")
    graphs = inputs.graphs
    if resource_kind == "edge":
        rebound = inputs.cross_file_edge.model_copy(
            update={
                "path": unrelated.path,
                "start_line": unrelated.start_line,
                "end_line": unrelated.end_line,
                "source_hash": unrelated.source_hash,
            }
        )
        graphs = graphs.model_copy(
            update={
                "edges": [
                    rebound if item is inputs.cross_file_edge else item for item in graphs.edges
                ]
            }
        )
    else:
        node = next(item for item in graphs.nodes if item.id == inputs.source_function.id)
        rebound = node.model_copy(
            update={
                "path": unrelated.path,
                "start_line": unrelated.start_line,
                "end_line": unrelated.end_line,
                "source_hash": unrelated.source_hash,
            }
        )
        graphs = graphs.model_copy(
            update={"nodes": [rebound if item.id == rebound.id else item for item in graphs.nodes]}
        )

    with pytest.raises(SolidityShardingError, match="source-owned graph"):
        build_solidity_shard_inventory(inputs.discovery, inputs.index, graphs)


def test_sharding_rejects_a_misclassified_source_owned_graph_node(
    tmp_path: Path,
    config_factory,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    node = next(item for item in inputs.graphs.nodes if item.id == inputs.source_function.id)
    misclassified = node.model_copy(update={"kind": SolidityGraphNodeKind.ASSET})
    graphs = inputs.graphs.model_copy(
        update={
            "nodes": [
                misclassified if item.id == misclassified.id else item
                for item in inputs.graphs.nodes
            ]
        }
    )

    with pytest.raises(SolidityShardingError, match="source-owned graph node"):
        build_solidity_shard_inventory(inputs.discovery, inputs.index, graphs)


def test_inventory_schema_rejects_a_resealed_nested_policy_cap(
    tmp_path: Path,
    config_factory,
) -> None:
    inventory = _inventory(_shard_inputs(tmp_path, config_factory))
    payload = inventory.model_dump(mode="json")
    payload["policy"] = SolidityShardPolicy.build(max_source_bytes_per_shard=4).model_dump(
        mode="json"
    )
    _reseal_inventory_payload(payload)

    with pytest.raises(ValidationError, match="nested policy"):
        SolidityShardInventory.model_validate(payload)


def test_sharding_rejects_an_unsafe_source_path(
    tmp_path: Path,
    config_factory,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    files = list(inputs.discovery.files)
    position = next(index for index, item in enumerate(files) if item.language == "Solidity")
    files[position] = replace(files[position], relative_path="../Unsafe.sol")
    unsafe = replace(inputs.discovery, files=tuple(files))

    with pytest.raises(SolidityShardingError, match="source path is unsafe"):
        build_solidity_shard_inventory(unsafe, inputs.index, inputs.graphs)


def test_source_content_change_preserves_shard_id_but_changes_shard_hash(
    tmp_path: Path,
    config_factory,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    baseline = _inventory(inputs)
    files = list(inputs.discovery.files)
    position = next(
        index for index, item in enumerate(files) if item.relative_path == "src/Router.sol"
    )
    original = files[position]
    changed_content = original.content + "// synthetic defensive review note\n"
    files[position] = replace(
        original,
        content=changed_content,
        size=len(changed_content.encode("utf-8")),
        lines=len(changed_content.splitlines()),
        sha256=hashlib.sha256(changed_content.encode("utf-8")).hexdigest(),
    )
    changed_discovery = replace(inputs.discovery, files=tuple(files))

    changed = build_solidity_shard_inventory(
        changed_discovery,
        inputs.index,
        inputs.graphs,
    )
    baseline_shard = next(
        item for item in baseline.shards if item.source_path == original.relative_path
    )
    changed_shard = next(
        item for item in changed.shards if item.source_path == original.relative_path
    )

    assert changed_shard.shard_id == baseline_shard.shard_id
    assert changed_shard.source_content_sha256 != baseline_shard.source_content_sha256
    assert changed_shard.shard_sha256 != baseline_shard.shard_sha256


def test_exact_comparison_rejects_fully_resealed_source_fact_reassignment(
    tmp_path: Path,
    config_factory,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    inventory = _inventory(inputs)
    contract = next(
        item
        for item in inputs.index.entities
        if item.name == "SyntheticMarker" and item.contract_name == "Unrelated"
    )
    assert all(contract.id not in {edge.source_id, edge.target_id} for edge in inputs.graphs.edges)
    payload = inventory.model_dump(mode="json")
    shards = payload["shards"]
    assert isinstance(shards, list)
    source_shard = next(
        item for item in shards if isinstance(item, dict) and item["source_path"] == contract.path
    )
    target_shard = next(
        item
        for item in shards
        if isinstance(item, dict) and item["source_path"] == "src/Ledger.sol"
    )
    source_shard_id = str(source_shard["shard_id"])
    target_shard_id = str(target_shard["shard_id"])
    source_units = payload["source_units"]
    assert isinstance(source_units, list)
    target_source_unit_id = str(
        next(item for item in source_units if item["path"] == "src/Ledger.sol")["source_unit_id"]
    )
    assert source_shard_id != target_shard_id

    for field_name in ("primary_entity_ids", "primary_graph_node_ids"):
        source_ids = source_shard[field_name]
        target_ids = target_shard[field_name]
        assert isinstance(source_ids, list)
        assert isinstance(target_ids, list)
        source_ids.remove(contract.id)
        target_ids.append(contract.id)
        target_ids.sort()
    entity_facts = payload["entity_facts"]
    node_facts = payload["graph_node_facts"]
    assert isinstance(entity_facts, list)
    assert isinstance(node_facts, list)
    entity_fact = next(item for item in entity_facts if item["resource_id"] == contract.id)
    node_fact = next(item for item in node_facts if item["resource_id"] == contract.id)
    entity_fact["source_unit_id"] = target_source_unit_id
    entity_fact["primary_shard_id"] = target_shard_id
    node_fact["source_unit_id"] = target_source_unit_id
    node_fact["primary_shard_id"] = target_shard_id
    payload["symbol_index_projection_sha256"] = _canonical_sha256(
        {
            "context_sha256": payload["symbol_index_context_sha256"],
            "entity_facts": entity_facts,
        }
    )
    payload["graph_set_projection_sha256"] = _canonical_sha256(
        {
            "context_sha256": payload["graph_set_context_sha256"],
            "node_facts": node_facts,
            "edge_facts": payload["graph_edge_facts"],
            "storage_facts": payload["storage_facts"],
        }
    )
    _reseal_semantic_shards(payload)
    forged = SolidityShardInventory.model_validate(payload)

    assert forged.evidence_authority == "comparison_required"
    with pytest.raises(SolidityShardingError, match="upstream artifacts"):
        verify_solidity_shard_projection(
            index=inputs.index,
            graphs=inputs.graphs,
            inventory=forged,
            expected_policy=SolidityShardPolicy.build(),
            report_binding=SolidityShardReportBinding.from_inventory(forged),
        )
    with pytest.raises(SolidityShardingError, match="exact upstream"):
        verify_solidity_shard_inventory(
            discovery=inputs.discovery,
            index=inputs.index,
            graphs=inputs.graphs,
            inventory=forged,
            expected_policy=SolidityShardPolicy.build(),
        )


def test_exact_comparison_accepts_current_inputs_and_report_binding(
    tmp_path: Path,
    config_factory,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    policy = SolidityShardPolicy.build()
    inventory = build_solidity_shard_inventory(
        inputs.discovery,
        inputs.index,
        inputs.graphs,
        policy=policy,
    )
    binding = SolidityShardReportBinding.from_inventory(inventory)

    result = verify_solidity_shard_inventory(
        discovery=inputs.discovery,
        index=inputs.index,
        graphs=inputs.graphs,
        inventory=inventory,
        expected_policy=policy,
        report_binding=binding,
    )

    assert result.status == "CONSISTENT"
    assert result.evidence_authority == "comparison_only"
    assert result.inventory_sha256 == inventory.inventory_sha256


def test_exact_comparison_rejects_policy_or_report_binding_drift(
    tmp_path: Path,
    config_factory,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    policy = SolidityShardPolicy.build()
    inventory = build_solidity_shard_inventory(
        inputs.discovery,
        inputs.index,
        inputs.graphs,
        policy=policy,
    )

    with pytest.raises(SolidityShardingError, match="expected policy"):
        verify_solidity_shard_inventory(
            discovery=inputs.discovery,
            index=inputs.index,
            graphs=inputs.graphs,
            inventory=inventory,
            expected_policy=SolidityShardPolicy.build(max_total_boundaries=499_999),
        )

    stale_binding = SolidityShardReportBinding.from_inventory(inventory).model_copy(
        update={"boundary_count": len(inventory.boundaries) + 1}
    )
    with pytest.raises(SolidityShardingError, match="report binding"):
        verify_solidity_shard_inventory(
            discovery=inputs.discovery,
            index=inputs.index,
            graphs=inputs.graphs,
            inventory=inventory,
            expected_policy=policy,
            report_binding=stale_binding,
        )


def test_persisted_projection_rejects_resealed_impossible_graph_coverage(
    tmp_path: Path,
    config_factory,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    inventory = _inventory(inputs)
    coverage = dict(inputs.graphs.coverage)
    coverage[SolidityGraphKind.INTERNAL_CALL.value] += 1
    impossible_graphs = SolidityGraphSet.model_validate(
        {
            **inputs.graphs.model_dump(mode="python"),
            "coverage": coverage,
        }
    )
    payload = inventory.model_dump(mode="json")
    payload["graph_set_context_sha256"] = _graph_set_context_sha256(impossible_graphs)
    payload["graph_set_sha256"] = _graph_set_sha256(impossible_graphs)
    payload["graph_set_projection_sha256"] = _graph_set_projection_sha256(
        impossible_graphs,
        node_facts=inventory.graph_node_facts,
        edge_facts=inventory.graph_edge_facts,
        storage_facts=inventory.storage_facts,
    )
    _reseal_inventory_payload(payload)
    resealed_inventory = SolidityShardInventory.model_validate(payload)

    with pytest.raises(SolidityShardingError, match="coverage"):
        verify_solidity_shard_projection(
            index=inputs.index,
            graphs=impossible_graphs,
            inventory=resealed_inventory,
            expected_policy=SolidityShardPolicy.build(),
            report_binding=SolidityShardReportBinding.from_inventory(resealed_inventory),
        )


def test_persisted_shards_reject_report_repository_source_projection_mismatch(
    tmp_path: Path,
    config_factory,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    inventory = _inventory(inputs)
    run_dir = tmp_path / "report-source-projection"
    _write_shard_artifacts(
        run_dir,
        index=inputs.index,
        graphs=inputs.graphs,
        inventory=inventory,
    )
    repository = build_repository_map(inputs.discovery)
    report = _report_for_shards(
        repository=repository,
        index=inputs.index,
        graphs=inputs.graphs,
        inventory=inventory,
    )
    validate_solidity_shard_artifacts(run_dir, report)

    mismatched_files = [
        item.model_copy(update={"sha256": hashlib.sha256(b"different source").hexdigest()})
        if item.path == inputs.source_function.path
        else item
        for item in repository.files
    ]
    mismatched_repository = RepositoryMap.model_validate(
        {
            **repository.model_dump(mode="python"),
            "files": mismatched_files,
        }
    )
    mismatched_report = AuditReport.model_validate(
        {
            **report.model_dump(mode="python"),
            "repository": mismatched_repository,
        }
    )

    with pytest.raises(ValueError, match=r"repository|source"):
        validate_solidity_shard_artifacts(run_dir, mismatched_report)


def test_persisted_shards_reject_null_inventory_with_nonempty_upstream(
    tmp_path: Path,
    config_factory,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    run_dir = tmp_path / "null-shard-inventory"
    _write_shard_artifacts(
        run_dir,
        index=inputs.index,
        graphs=inputs.graphs,
        inventory=None,
    )
    report = _report_for_shards(
        repository=build_repository_map(inputs.discovery),
        index=inputs.index,
        graphs=inputs.graphs,
        inventory=None,
    )

    with pytest.raises(ValueError, match=r"non-empty|incomplete|inventory"):
        validate_solidity_shard_artifacts(run_dir, report)


@pytest.mark.parametrize("projection", ["symbol_index", "graph_set"])
def test_persisted_projection_rejects_fully_resealed_context_and_projection_hash_drift(
    tmp_path: Path,
    config_factory,
    projection: str,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    inventory = _inventory(inputs)
    payload = inventory.model_dump(mode="json")
    drifted_context = hashlib.sha256(f"stale-{projection}-context".encode()).hexdigest()
    if projection == "symbol_index":
        payload["symbol_index_context_sha256"] = drifted_context
        payload["symbol_index_projection_sha256"] = _canonical_sha256(
            {
                "context_sha256": drifted_context,
                "entity_facts": payload["entity_facts"],
            }
        )
    else:
        payload["graph_set_context_sha256"] = drifted_context
        payload["graph_set_projection_sha256"] = _canonical_sha256(
            {
                "context_sha256": drifted_context,
                "node_facts": payload["graph_node_facts"],
                "edge_facts": payload["graph_edge_facts"],
                "storage_facts": payload["storage_facts"],
            }
        )
    _reseal_inventory_payload(payload)
    resealed_inventory = SolidityShardInventory.model_validate(payload)

    with pytest.raises(SolidityShardingError, match="semantic hashes"):
        verify_solidity_shard_projection(
            index=inputs.index,
            graphs=inputs.graphs,
            inventory=resealed_inventory,
            expected_policy=SolidityShardPolicy.build(),
            report_binding=SolidityShardReportBinding.from_inventory(resealed_inventory),
        )


@pytest.mark.parametrize(
    ("summary_name", "count_name"),
    [("index_summary", "entities"), ("graph_summary", "edges")],
)
def test_persisted_shards_reject_stale_report_semantic_summaries(
    tmp_path: Path,
    config_factory,
    summary_name: str,
    count_name: str,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    inventory = _inventory(inputs)
    run_dir = tmp_path / f"stale-{summary_name}"
    _write_shard_artifacts(
        run_dir,
        index=inputs.index,
        graphs=inputs.graphs,
        inventory=inventory,
    )
    report = _report_for_shards(
        repository=build_repository_map(inputs.discovery),
        index=inputs.index,
        graphs=inputs.graphs,
        inventory=inventory,
    )
    solidity_metadata = dict(report.metadata["solidity"])
    stale_summary = dict(solidity_metadata[summary_name])
    stale_summary[count_name] += 1
    solidity_metadata[summary_name] = stale_summary
    stale_report = AuditReport.model_validate(
        {
            **report.model_dump(mode="python"),
            "metadata": {
                **report.metadata,
                "solidity": solidity_metadata,
            },
        }
    )

    with pytest.raises(ValueError, match=r"index report summary|graph report summary"):
        validate_solidity_shard_artifacts(run_dir, stale_report)


@pytest.mark.parametrize(
    ("poisoned_json", "error"),
    [
        (
            '{"schema_version":"1.0","schema_version":"1.0","inventory":null}',
            "duplicate keys",
        ),
        ('{"schema_version":"1.0","inventory":null,"value":NaN}', "non-finite"),
    ],
)
def test_persisted_shard_reader_rejects_ambiguous_or_nonfinite_json(
    tmp_path: Path,
    config_factory,
    poisoned_json: str,
    error: str,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    inventory = _inventory(inputs)
    run_dir = tmp_path / f"strict-json-{error.replace(' ', '-')}"
    _write_shard_artifacts(
        run_dir,
        index=inputs.index,
        graphs=inputs.graphs,
        inventory=inventory,
    )
    (run_dir / "solidity-shards.json").write_text(poisoned_json, encoding="utf-8")
    report = _report_for_shards(
        repository=build_repository_map(inputs.discovery),
        index=inputs.index,
        graphs=inputs.graphs,
        inventory=inventory,
    )

    with pytest.raises(ValueError, match=error):
        validate_solidity_shard_artifacts(run_dir, report)


def test_verify_run_records_manifest_bound_shard_cross_artifact_mismatch(
    tmp_path: Path,
    config_factory,
) -> None:
    from tests.unit.test_manifest import _report, _write_required_artifacts

    config = config_factory()
    inputs = _shard_inputs(tmp_path, config_factory)
    inventory = _inventory(inputs)
    shard_report = _report_for_shards(
        repository=build_repository_map(inputs.discovery),
        index=inputs.index,
        graphs=inputs.graphs,
        inventory=inventory,
    )
    base_report = _report(config)
    report = AuditReport.model_validate(
        {
            **base_report.model_dump(mode="python"),
            "repository": shard_report.repository,
            "metadata": {
                **base_report.metadata,
                "solidity": shard_report.metadata["solidity"],
            },
        }
    )
    run_dir = tmp_path / "manifest-bound-cross-artifact"
    _write_required_artifacts(run_dir, report)
    _write_shard_artifacts(
        run_dir,
        index=inputs.index,
        graphs=inputs.graphs,
        inventory=inventory,
    )
    (run_dir / "benchmark-certificate-verification.json").write_text(
        '{"schema_version":"1.0","status":"current"}\n',
        encoding="utf-8",
    )
    manifest_path = run_dir / "run-evidence-manifest.json"
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
    )
    write_run_evidence_manifest(manifest_path, manifest)
    current = verify_run_evidence(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=inputs.discovery.root,
        config=config,
    )
    assert current.status is RunVerificationStatus.CURRENT

    index_path = run_dir / "solidity-index.json"
    index_payload = json.loads(index_path.read_text(encoding="utf-8"))
    index_payload["index"]["entities"][0]["documentation"] = "stale persisted projection"
    index_path.write_text(
        json.dumps(index_payload, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    index_bytes = index_path.read_bytes()
    resealed_manifest = manifest.model_dump(mode="json")
    index_binding = next(
        item for item in resealed_manifest["artifacts"] if item["path"] == "solidity-index.json"
    )
    index_binding["sha256"] = hashlib.sha256(index_bytes).hexdigest()
    index_binding["size"] = len(index_bytes)
    resealed_manifest["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in resealed_manifest.items() if key != "manifest_sha256"}
    )
    write_run_evidence_manifest(
        manifest_path,
        RunEvidenceManifest.model_validate(resealed_manifest),
    )

    verification = verify_run_evidence(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=inputs.discovery.root,
        config=config,
    )

    assert verification.status is RunVerificationStatus.STALE
    cross_artifact = [
        mismatch
        for mismatch in verification.mismatches
        if mismatch.identifier == "solidity-shards/cross-artifact"
    ]
    assert len(cross_artifact) == 1
    assert cross_artifact[0].kind is RunVerificationMismatchKind.UNVERIFIABLE


def test_current_report_and_verify_run_reject_erased_solidity_metadata_with_shards(
    tmp_path: Path,
    config_factory,
) -> None:
    from tests.unit.test_manifest import _report, _write_required_artifacts

    config = config_factory()
    inputs = _shard_inputs(tmp_path, config_factory)
    inventory = _inventory(inputs)
    shard_report = _report_for_shards(
        repository=build_repository_map(inputs.discovery),
        index=inputs.index,
        graphs=inputs.graphs,
        inventory=inventory,
    )
    limitation = "Synthetic incomplete current report for shard metadata validation."
    floor = MinimumAnalysisFloor(
        run_status=AuditRunStatus.INCOMPLETE,
        source_files_ingested=len(inventory.source_units),
        source_ingestion_succeeded=True,
        solidity_applicable=True,
        qualifying_compilations=0,
        compilation_satisfied=False,
        static_analysis_applicable=True,
        static_analysis_satisfied=False,
        model_review_required=False,
        scanner_only=True,
        model_review_satisfied=True,
        coverage_metric_ids=[],
        coverage_denominators_valid=False,
        surface_analysis_feasible=True,
        minimum_floor_met=False,
        limitations=[limitation],
    )
    base_report = _report(config)
    solidity_metadata = {
        **shard_report.metadata["solidity"],
        "projects": [item.model_dump(mode="json") for item in inputs.index.projects],
        "compilation": [],
    }
    report = AuditReport.model_validate(
        {
            **base_report.model_dump(mode="python"),
            "schema_version": "1.2",
            "completed": False,
            "incomplete_reasons": [limitation],
            "repository": shard_report.repository,
            "quality_status": AuditQualityStatus.INCOMPLETE,
            "run_status": AuditRunStatus.INCOMPLETE,
            "minimum_analysis_floor": floor,
            "quality_gates": [minimum_analysis_floor_quality_gate(floor)],
            "metadata": {
                **base_report.metadata,
                "scanner_only": True,
                "solidity": solidity_metadata,
            },
        }
    )
    manifest_report = AuditReport.model_validate(
        {
            **base_report.model_dump(mode="python"),
            "repository": shard_report.repository,
            "metadata": {
                **base_report.metadata,
                "solidity": shard_report.metadata["solidity"],
            },
        }
    )
    run_dir = tmp_path / "current-report-erased-solidity-metadata"
    _write_required_artifacts(run_dir, manifest_report)
    _write_shard_artifacts(
        run_dir,
        index=inputs.index,
        graphs=inputs.graphs,
        inventory=inventory,
    )
    (run_dir / "benchmark-certificate-verification.json").write_text(
        '{"schema_version":"1.0","status":"current"}\n',
        encoding="utf-8",
    )
    assert {
        "solidity-index.json",
        "solidity-graphs.json",
        "solidity-shards.json",
    } <= {item.name for item in run_dir.iterdir()}
    validate_solidity_shard_artifacts(run_dir, report)
    manifest_path = run_dir / "run-evidence-manifest.json"
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=manifest_report,
        config=config,
    )
    write_run_evidence_manifest(manifest_path, manifest)

    erased_metadata = {key: value for key, value in report.metadata.items() if key != "solidity"}
    erased_report = report.model_copy(update={"metadata": erased_metadata})
    with pytest.raises(ValueError, match="report metadata"):
        validate_solidity_shard_artifacts(run_dir, erased_report)

    (run_dir / "final-findings.json").write_text(
        erased_report.model_dump_json(),
        encoding="utf-8",
    )
    metadata_path = run_dir / "metadata.json"
    metadata_payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata_payload["metadata"] = erased_metadata
    metadata_path.write_text(
        json.dumps(metadata_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    resealed_manifest = manifest.model_dump(mode="json")
    for artifact_name in ("final-findings.json", "metadata.json"):
        artifact_path = run_dir / artifact_name
        artifact_bytes = artifact_path.read_bytes()
        artifact_binding = next(
            item for item in resealed_manifest["artifacts"] if item["path"] == artifact_name
        )
        artifact_binding["sha256"] = hashlib.sha256(artifact_bytes).hexdigest()
        artifact_binding["size"] = len(artifact_bytes)
    resealed_manifest["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in resealed_manifest.items() if key != "manifest_sha256"}
    )
    write_run_evidence_manifest(
        manifest_path,
        RunEvidenceManifest.model_validate(resealed_manifest),
    )

    verification = verify_run_evidence(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=inputs.discovery.root,
        config=config,
    )

    assert verification.status is RunVerificationStatus.STALE
    report_validation = [
        mismatch
        for mismatch in verification.mismatches
        if mismatch.identifier == "report/validation"
    ]
    assert len(report_validation) == 1
    assert report_validation[0].kind is RunVerificationMismatchKind.UNVERIFIABLE


@pytest.mark.parametrize("gap", ["source_provenance", "coverage_counter", "source_node"])
def test_sharding_rejects_incomplete_upstream_denominators(
    tmp_path: Path,
    config_factory,
    gap: str,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    index = inputs.index
    graphs = inputs.graphs
    if gap == "source_provenance":
        if index.ast_sources:
            index = index.model_copy(update={"ast_sources": list(index.ast_sources[1:])})
        else:
            index = index.model_copy(update={"fallback_sources": list(index.fallback_sources[1:])})
    elif gap == "coverage_counter":
        coverage = dict(graphs.coverage)
        coverage[SolidityGraphKind.INTERNAL_CALL.value] += 1
        graphs = graphs.model_copy(update={"coverage": coverage})
    else:
        unused = next(
            item
            for item in index.entities
            if item.name == "SyntheticMarker" and item.contract_name == "Unrelated"
        )
        assert all(unused.id not in {edge.source_id, edge.target_id} for edge in graphs.edges)
        graphs = graphs.model_copy(
            update={"nodes": [node for node in graphs.nodes if node.id != unused.id]}
        )

    with pytest.raises(SolidityShardingError, match=r"provenance|coverage|nodes omit"):
        build_solidity_shard_inventory(inputs.discovery, index, graphs)


def _with_second_cross_file_boundary(inputs: _ShardInputs) -> _ShardInputs:
    second_edge = inputs.cross_file_edge.model_copy(
        update={
            "graph": SolidityGraphKind.STATE_WRITE,
            "target_id": inputs.storage_entry.id,
            "label": "synthetic exact cross-file storage dependency",
            "transformation": "synthetic_local_cross_file_storage_dependency",
        }
    )
    coverage = dict(inputs.graphs.coverage)
    coverage[SolidityGraphKind.STATE_WRITE.value] += 1
    return replace(
        inputs,
        graphs=inputs.graphs.model_copy(
            update={
                "edges": [*inputs.graphs.edges, second_edge],
                "coverage": coverage,
            }
        ),
    )


@pytest.mark.parametrize(
    "policy_update",
    [
        {"max_overlap_graph_nodes_per_shard": 1},
        {"max_boundaries_per_shard": 1},
        {"max_total_boundaries": 1},
        {"max_total_semantic_memberships_per_shard": 1},
    ],
)
def test_sharding_rejects_overlap_boundary_and_total_membership_caps(
    tmp_path: Path,
    config_factory,
    policy_update: dict[str, int],
) -> None:
    inputs = _with_second_cross_file_boundary(_shard_inputs(tmp_path, config_factory))

    with pytest.raises(SolidityShardingError, match="policy"):
        build_solidity_shard_inventory(
            inputs.discovery,
            inputs.index,
            inputs.graphs,
            policy=SolidityShardPolicy.build(**policy_update),
        )


def test_inventory_schema_rejects_resealed_overlap_cap(
    tmp_path: Path,
    config_factory,
) -> None:
    inputs = _with_second_cross_file_boundary(_shard_inputs(tmp_path, config_factory))
    inventory = _inventory(inputs)
    payload = inventory.model_dump(mode="json")
    payload["policy"] = SolidityShardPolicy.build(max_overlap_graph_nodes_per_shard=1).model_dump(
        mode="json"
    )
    _reseal_inventory_payload(payload)

    with pytest.raises(ValidationError, match="nested policy"):
        SolidityShardInventory.model_validate(payload)


@pytest.mark.parametrize("fact_kind", ["entity", "node"])
def test_primary_fact_change_updates_owning_shard_hash(
    tmp_path: Path,
    config_factory,
    fact_kind: str,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    baseline = _inventory(inputs)
    entity = next(
        item
        for item in inputs.index.entities
        if item.name == "SyntheticMarker" and item.contract_name == "Unrelated"
    )
    index = inputs.index
    graphs = inputs.graphs
    if fact_kind == "entity":
        changed = entity.model_copy(update={"documentation": "Synthetic changed primary fact."})
        index = index.model_copy(
            update={
                "entities": [changed if item.id == changed.id else item for item in index.entities]
            }
        )
    else:
        node = next(item for item in graphs.nodes if item.id == entity.id)
        changed = node.model_copy(update={"label": f"{node.label} changed"})
        graphs = graphs.model_copy(
            update={"nodes": [changed if item.id == changed.id else item for item in graphs.nodes]}
        )

    observed = build_solidity_shard_inventory(inputs.discovery, index, graphs)
    baseline_shard = next(item for item in baseline.shards if item.source_path == entity.path)
    observed_shard = next(item for item in observed.shards if item.source_path == entity.path)

    assert baseline_shard.shard_id == observed_shard.shard_id
    assert baseline_shard.shard_sha256 != observed_shard.shard_sha256


@pytest.mark.parametrize("fact_kind", ["entity", "node", "edge", "storage"])
def test_remote_overlap_fact_hash_changes_consumer_shard_hash(
    tmp_path: Path,
    config_factory,
    fact_kind: str,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    boundary_edge = inputs.cross_file_edge
    if fact_kind == "storage":
        boundary_edge = inputs.cross_file_edge.model_copy(
            update={
                "graph": SolidityGraphKind.STATE_WRITE,
                "target_id": inputs.storage_entry.id,
                "label": "synthetic exact cross-file storage dependency",
                "transformation": "synthetic_local_cross_file_storage_dependency",
            }
        )
        coverage = dict(inputs.graphs.coverage)
        coverage[SolidityGraphKind.STATE_WRITE.value] += 1
        inputs = replace(
            inputs,
            graphs=inputs.graphs.model_copy(
                update={
                    "edges": [*inputs.graphs.edges, boundary_edge],
                    "coverage": coverage,
                }
            ),
        )
    baseline = _inventory(inputs)
    baseline_boundary = next(
        item
        for item in baseline.boundaries
        if item.graph_edge_id == solidity_graph_edge_id(boundary_edge)
    )
    consumer_path = inputs.source_function.path
    baseline_consumer = next(
        item for item in baseline.shards if item.shard_id == baseline_boundary.source_shard_id
    )
    assert baseline_consumer.source_path == consumer_path

    index = inputs.index
    graphs = inputs.graphs
    if fact_kind == "entity":
        changed = inputs.target_function.model_copy(
            update={"documentation": "Synthetic changed remote entity fact."}
        )
        index = index.model_copy(
            update={
                "entities": [changed if item.id == changed.id else item for item in index.entities]
            }
        )
        resource_id = changed.id
        fact_field = "entity_facts"
    elif fact_kind == "node":
        node = next(item for item in graphs.nodes if item.id == inputs.target_function.id)
        changed = node.model_copy(update={"label": f"{node.label} changed"})
        graphs = graphs.model_copy(
            update={"nodes": [changed if item.id == changed.id else item for item in graphs.nodes]}
        )
        resource_id = changed.id
        fact_field = "graph_node_facts"
    elif fact_kind == "edge":
        changed = boundary_edge.model_copy(
            update={"metadata": {**boundary_edge.metadata, "changed": True}}
        )
        graphs = graphs.model_copy(
            update={"edges": [changed if item is boundary_edge else item for item in graphs.edges]}
        )
        resource_id = solidity_graph_edge_id(changed)
        fact_field = "graph_edge_facts"
    else:
        changed = inputs.storage_entry.model_copy(update={"type_name": "uint256 synthetic"})
        graphs = graphs.model_copy(
            update={
                "storage_layout": [
                    changed if item.id == changed.id else item for item in graphs.storage_layout
                ]
            }
        )
        resource_id = changed.id
        fact_field = "storage_facts"

    changed_inventory = build_solidity_shard_inventory(inputs.discovery, index, graphs)
    changed_consumer = next(
        item for item in changed_inventory.shards if item.source_path == consumer_path
    )
    baseline_facts = getattr(baseline, fact_field)
    changed_facts = getattr(changed_inventory, fact_field)
    baseline_resource_id = (
        solidity_graph_edge_id(boundary_edge) if fact_kind == "edge" else resource_id
    )
    baseline_fact = next(
        item for item in baseline_facts if item.resource_id == baseline_resource_id
    )
    changed_fact = next(item for item in changed_facts if item.resource_id == resource_id)

    assert baseline_fact.record_sha256 != changed_fact.record_sha256
    assert baseline_consumer.shard_sha256 != changed_consumer.shard_sha256
