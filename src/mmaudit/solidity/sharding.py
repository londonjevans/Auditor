"""Deterministic, fail-closed semantic sharding over Solidity facts."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from mmaudit.models.schemas import (
    RepositoryMap,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphKind,
    SolidityGraphNode,
    SolidityGraphNodeKind,
    SolidityGraphSet,
    SolidityStorageEntry,
    SoliditySymbolIndex,
)
from mmaudit.models.sharding import (
    SoliditySemanticShard,
    SolidityShardBoundary,
    SolidityShardComparisonResult,
    SolidityShardCoverage,
    SolidityShardEntityFact,
    SolidityShardGraphEdgeFact,
    SolidityShardGraphNodeFact,
    SolidityShardInventory,
    SolidityShardOverlap,
    SolidityShardOverlapKind,
    SolidityShardOverlapReason,
    SolidityShardPolicy,
    SolidityShardReportBinding,
    SolidityShardSourceUnit,
    SolidityShardStorageFact,
    solidity_shard_risk_surfaces,
    solidity_shard_semantic_dependency_sha256,
)
from mmaudit.repository.chunking import line_range_hash
from mmaudit.repository.discovery import DiscoveredFile, DiscoveryResult
from mmaudit.repository.ignore import normalize_relative_path


class SolidityShardingError(ValueError):
    """Raised when exact shard coverage cannot be proven from current facts."""


@dataclass(frozen=True)
class _ShardFactProjection:
    entity_owner: dict[str, str]
    storage_owner: dict[str, str]
    node_owner: dict[str, str]
    edge_owner: dict[str, str]
    node_references: dict[str, set[str]]
    entity_facts: tuple[SolidityShardEntityFact, ...]
    storage_facts: tuple[SolidityShardStorageFact, ...]
    graph_node_facts: tuple[SolidityShardGraphNodeFact, ...]
    graph_edge_facts: tuple[SolidityShardGraphEdgeFact, ...]


def verify_solidity_shard_inventory(
    *,
    discovery: DiscoveryResult,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet,
    inventory: SolidityShardInventory,
    expected_policy: SolidityShardPolicy,
    report_binding: SolidityShardReportBinding | None = None,
) -> SolidityShardComparisonResult:
    """Rebuild against exact trusted inputs and compare every normalized shard field."""

    try:
        validated_inventory = SolidityShardInventory.model_validate(
            inventory.model_dump(mode="python")
        )
        validated_policy = SolidityShardPolicy.model_validate(
            expected_policy.model_dump(mode="python")
        )
    except (TypeError, ValueError) as exc:
        raise SolidityShardingError("Solidity shard verification input is invalid") from exc
    if validated_inventory.policy != validated_policy:
        raise SolidityShardingError("Solidity shard inventory differs from the expected policy")
    rebuilt = build_solidity_shard_inventory(
        discovery,
        index,
        graphs,
        policy=validated_policy,
    )
    if rebuilt != validated_inventory:
        raise SolidityShardingError("Solidity shard inventory differs from exact upstream facts")
    if report_binding is not None:
        try:
            validated_binding = SolidityShardReportBinding.model_validate(
                report_binding.model_dump(mode="python")
            )
            validated_binding.require_exact_inventory(validated_inventory)
        except (TypeError, ValueError) as exc:
            raise SolidityShardingError("Solidity shard report binding is inconsistent") from exc
    return SolidityShardComparisonResult(
        policy_sha256=validated_policy.policy_sha256,
        source_inventory_sha256=validated_inventory.source_inventory_sha256,
        symbol_index_sha256=validated_inventory.symbol_index_sha256,
        graph_set_sha256=validated_inventory.graph_set_sha256,
        inventory_sha256=validated_inventory.inventory_sha256,
        shard_count=len(validated_inventory.shards),
        boundary_count=len(validated_inventory.boundaries),
        overlap_count=len(validated_inventory.overlaps),
    )


def verify_solidity_shard_projection(
    *,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet,
    inventory: SolidityShardInventory,
    expected_policy: SolidityShardPolicy,
    report_binding: SolidityShardReportBinding,
) -> SolidityShardComparisonResult:
    """Compare persisted typed index/graph projections without claiming source-range replay."""

    try:
        validated_index = SoliditySymbolIndex.model_validate(index.model_dump(mode="python"))
        validated_graphs = SolidityGraphSet.model_validate(graphs.model_dump(mode="python"))
        validated_inventory = SolidityShardInventory.model_validate(
            inventory.model_dump(mode="python")
        )
        validated_policy = SolidityShardPolicy.model_validate(
            expected_policy.model_dump(mode="python")
        )
        validated_binding = SolidityShardReportBinding.model_validate(
            report_binding.model_dump(mode="python")
        )
    except (TypeError, ValueError) as exc:
        raise SolidityShardingError("persisted Solidity shard evidence is invalid") from exc
    if validated_inventory.policy != validated_policy:
        raise SolidityShardingError("persisted Solidity shard policy differs from expected policy")
    shard_by_path = {
        source.path: source.primary_shard_id for source in validated_inventory.source_units
    }
    entities = tuple(sorted(validated_index.entities, key=lambda item: item.id))
    storage_entries = tuple(sorted(validated_graphs.storage_layout, key=lambda item: item.id))
    nodes = tuple(sorted(validated_graphs.nodes, key=lambda item: item.id))
    edges = tuple(sorted(validated_graphs.edges, key=solidity_graph_edge_id))
    _require_unique_ids((item.id for item in entities), "Solidity entity")
    _require_unique_ids((item.id for item in storage_entries), "Solidity storage entry")
    _require_unique_ids((item.id for item in nodes), "Solidity graph node")
    edge_ids = [solidity_graph_edge_id(item) for item in edges]
    _require_unique_ids(edge_ids, "Solidity graph edge")
    if {entity.id for entity in entities} & {entry.id for entry in storage_entries}:
        raise SolidityShardingError("entity and storage entry identities must be disjoint")
    source_paths = {source.path for source in validated_inventory.source_units}
    _validate_index_source_coverage(validated_index, source_paths)
    _validate_graph_consistency(
        validated_graphs,
        entities=entities,
        storage_entries=storage_entries,
        nodes=nodes,
        edges=edges,
    )
    _validate_persisted_fact_ranges(
        inventory=validated_inventory,
        entities=entities,
        storage_entries=storage_entries,
        nodes=nodes,
        edges=edges,
    )
    projection = _project_shard_facts(
        entities=entities,
        storage_entries=storage_entries,
        nodes=nodes,
        edge_by_id=dict(zip(edge_ids, edges, strict=True)),
        shard_by_path=shard_by_path,
    )
    expected_facts = (
        projection.entity_facts,
        projection.graph_node_facts,
        projection.graph_edge_facts,
        projection.storage_facts,
    )
    observed_facts = (
        validated_inventory.entity_facts,
        validated_inventory.graph_node_facts,
        validated_inventory.graph_edge_facts,
        validated_inventory.storage_facts,
    )
    if observed_facts != expected_facts:
        raise SolidityShardingError("persisted Solidity shard facts differ from upstream artifacts")
    expected_hashes = (
        _symbol_index_context_sha256(validated_index),
        _symbol_index_sha256(validated_index),
        _symbol_index_projection_sha256(validated_index, projection.entity_facts),
        _graph_set_context_sha256(validated_graphs),
        _graph_set_sha256(validated_graphs),
        _graph_set_projection_sha256(
            validated_graphs,
            node_facts=projection.graph_node_facts,
            edge_facts=projection.graph_edge_facts,
            storage_facts=projection.storage_facts,
        ),
    )
    observed_hashes = (
        validated_inventory.symbol_index_context_sha256,
        validated_inventory.symbol_index_sha256,
        validated_inventory.symbol_index_projection_sha256,
        validated_inventory.graph_set_context_sha256,
        validated_inventory.graph_set_sha256,
        validated_inventory.graph_set_projection_sha256,
    )
    if observed_hashes != expected_hashes:
        raise SolidityShardingError("persisted Solidity shard semantic hashes are stale")
    try:
        validated_binding.require_exact_inventory(validated_inventory)
    except ValueError as exc:
        raise SolidityShardingError("persisted Solidity shard report binding is stale") from exc
    return SolidityShardComparisonResult(
        policy_sha256=validated_policy.policy_sha256,
        source_inventory_sha256=validated_inventory.source_inventory_sha256,
        symbol_index_sha256=validated_inventory.symbol_index_sha256,
        graph_set_sha256=validated_inventory.graph_set_sha256,
        inventory_sha256=validated_inventory.inventory_sha256,
        shard_count=len(validated_inventory.shards),
        boundary_count=len(validated_inventory.boundaries),
        overlap_count=len(validated_inventory.overlaps),
    )


def verify_solidity_shard_repository_projection(
    *,
    repository: RepositoryMap,
    inventory: SolidityShardInventory,
) -> None:
    """Bind persisted shard source units to the report's exact Solidity inventory."""

    try:
        validated_repository = RepositoryMap.model_validate(repository.model_dump(mode="python"))
        validated_inventory = SolidityShardInventory.model_validate(
            inventory.model_dump(mode="python")
        )
    except (TypeError, ValueError) as exc:
        raise SolidityShardingError("persisted Solidity repository projection is invalid") from exc
    if validated_repository.git_commit != validated_inventory.git_commit:
        raise SolidityShardingError("persisted Solidity repository commit differs from shards")
    _validate_omitted_solidity_coverage(validated_repository.omitted_files)
    projected: dict[str, tuple[str, int, int, str]] = {}
    for item in validated_repository.files:
        try:
            normalized = normalize_relative_path(item.path)
        except ValueError as exc:
            raise SolidityShardingError("report repository source path is unsafe") from exc
        has_solidity_suffix = PurePosixPath(normalized).suffix.lower() == ".sol"
        declares_solidity = item.language == "Solidity"
        if has_solidity_suffix != declares_solidity:
            raise SolidityShardingError(
                "report repository Solidity membership is inconsistent with its source path"
            )
        if not has_solidity_suffix:
            continue
        if normalized != item.path or normalized in projected:
            raise SolidityShardingError(
                "report repository Solidity source paths must be normalized and unique"
            )
        projected[normalized] = (normalized, item.size, item.lines, item.sha256)
    observed = tuple(sorted(projected.values()))
    expected = tuple(
        sorted(
            (
                item.path,
                item.utf8_bytes,
                item.line_count,
                item.content_sha256,
            )
            for item in validated_inventory.source_units
        )
    )
    if observed != expected:
        raise SolidityShardingError(
            "report repository Solidity source projection differs from shards"
        )


def _canonical_sha256(value: Any) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SolidityShardingError("Solidity shard input is not canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def solidity_graph_edge_id(edge: SolidityGraphEdge) -> str:
    """Return the public stable identity of one complete normalized graph edge."""

    return "edge-" + _canonical_sha256(edge.model_dump(mode="json"))[:32]


def _project_shard_facts(
    *,
    entities: tuple[SolidityEntity, ...],
    storage_entries: tuple[SolidityStorageEntry, ...],
    nodes: tuple[SolidityGraphNode, ...],
    edge_by_id: dict[str, SolidityGraphEdge],
    shard_by_path: dict[str, str],
) -> _ShardFactProjection:
    try:
        entity_owner = {entity.id: shard_by_path[entity.path] for entity in entities}
        storage_owner = {entry.id: shard_by_path[entry.path] for entry in storage_entries}
    except KeyError as exc:
        raise SolidityShardingError("Solidity fact references an unknown source unit") from exc
    source_owned_nodes = {**entity_owner, **storage_owner}
    source_records: dict[str, SolidityEntity | SolidityStorageEntry] = {
        **{entity.id: entity for entity in entities},
        **{entry.id: entry for entry in storage_entries},
    }
    nodes_by_id = {node.id: node for node in nodes}
    if len(nodes_by_id) != len(nodes):
        raise SolidityShardingError("Solidity graph node IDs must be unique")
    for resource_id, source_record in source_records.items():
        node = nodes_by_id.get(resource_id)
        if node is None:
            continue
        if isinstance(source_record, SolidityStorageEntry):
            expected_kind = SolidityGraphNodeKind.STORAGE_SLOT
        elif source_record.kind in {
            SolidityEntityKind.STATE_VARIABLE,
            SolidityEntityKind.IMMUTABLE,
            SolidityEntityKind.CONSTANT,
        }:
            expected_kind = SolidityGraphNodeKind.STATE_VARIABLE
        else:
            expected_kind = SolidityGraphNodeKind.ENTITY
        if (
            node.kind is not expected_kind
            or node.path != source_record.path
            or node.start_line != source_record.start_line
            or node.end_line != source_record.end_line
            or node.source_hash != source_record.source_hash
        ):
            raise SolidityShardingError(
                "source-owned graph node differs from its indexed source record"
            )
    try:
        edge_owner = {edge_id: shard_by_path[edge.path] for edge_id, edge in edge_by_id.items()}
    except KeyError as exc:
        raise SolidityShardingError(
            "Solidity graph edge references an unknown source unit"
        ) from exc
    node_references: dict[str, set[str]] = defaultdict(set)
    for edge_id, edge in edge_by_id.items():
        if edge.source_id not in nodes_by_id or edge.target_id not in nodes_by_id:
            raise SolidityShardingError("Solidity graph edge references an unknown endpoint")
        endpoint_records = [
            record
            for resource_id in (edge.source_id, edge.target_id)
            if (record := source_records.get(resource_id)) is not None
        ]
        if endpoint_records and edge.path not in {record.path for record in endpoint_records}:
            raise SolidityShardingError(
                "source-owned graph edge is bound to an unrelated source path"
            )
        owner = edge_owner[edge_id]
        node_references[edge.source_id].add(owner)
        node_references[edge.target_id].add(owner)
    try:
        node_owner = {
            node.id: (
                source_owned_nodes[node.id]
                if node.id in source_owned_nodes
                else min(node_references[node.id])
                if node_references[node.id]
                else shard_by_path[node.path]
            )
            for node in nodes
        }
    except KeyError as exc:
        raise SolidityShardingError(
            "Solidity graph node references an unknown source unit"
        ) from exc
    entity_facts = tuple(
        SolidityShardEntityFact(
            resource_id=entity.id,
            source_unit_id=_source_unit_id(entity.path),
            primary_shard_id=entity_owner[entity.id],
            entity_kind=entity.kind,
            record_sha256=_record_sha256(entity),
        )
        for entity in entities
    )
    storage_facts = tuple(
        SolidityShardStorageFact(
            resource_id=entry.id,
            source_unit_id=_source_unit_id(entry.path),
            primary_shard_id=storage_owner[entry.id],
            record_sha256=_record_sha256(entry),
        )
        for entry in storage_entries
    )
    graph_node_facts = tuple(
        SolidityShardGraphNodeFact(
            resource_id=node.id,
            source_unit_id=_source_unit_id(node.path),
            primary_shard_id=node_owner[node.id],
            source_owned=node.id in source_owned_nodes,
            record_sha256=_record_sha256(node),
        )
        for node in nodes
    )
    graph_edge_facts = tuple(
        SolidityShardGraphEdgeFact(
            resource_id=edge_id,
            source_unit_id=_source_unit_id(edge.path),
            primary_shard_id=edge_owner[edge_id],
            graph_kind=edge.graph,
            source_node_id=edge.source_id,
            target_node_id=edge.target_id,
            record_sha256=_record_sha256(edge),
        )
        for edge_id, edge in sorted(edge_by_id.items())
    )
    return _ShardFactProjection(
        entity_owner=entity_owner,
        storage_owner=storage_owner,
        node_owner=node_owner,
        edge_owner=edge_owner,
        node_references=dict(node_references),
        entity_facts=entity_facts,
        storage_facts=storage_facts,
        graph_node_facts=graph_node_facts,
        graph_edge_facts=graph_edge_facts,
    )


def build_solidity_shard_inventory(
    discovery: DiscoveryResult,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet,
    policy: SolidityShardPolicy | None = None,
) -> SolidityShardInventory:
    """Build an exact source-primary shard inventory without dropping facts."""

    try:
        effective_policy = SolidityShardPolicy.model_validate(
            (policy or SolidityShardPolicy.build()).model_dump(mode="python")
        )
        index = SoliditySymbolIndex.model_validate(index.model_dump(mode="python"))
        graphs = SolidityGraphSet.model_validate(graphs.model_dump(mode="python"))
    except (TypeError, ValueError) as exc:
        raise SolidityShardingError("Solidity shard inputs failed detached validation") from exc
    _validate_discovery_coverage(discovery)
    files = _validated_solidity_files(discovery)
    if len(files) > effective_policy.max_shards:
        raise SolidityShardingError("Solidity source count exceeds shard policy")

    shard_by_path = {path: _shard_id(path) for path in files}
    entities = _validated_entities(index.entities, files)
    storage_entries = _validated_storage_entries(graphs.storage_layout, files)
    if {entity.id for entity in entities} & {entry.id for entry in storage_entries}:
        raise SolidityShardingError("entity and storage entry identities must be disjoint")
    nodes = _validated_nodes(graphs.nodes, files)
    edges = _validated_edges(graphs.edges, files, nodes)
    _validate_index_coverage(index, files)
    _validate_graph_consistency(
        graphs,
        entities=entities,
        storage_entries=storage_entries,
        nodes=nodes,
        edges=edges,
    )
    edge_by_id = {solidity_graph_edge_id(edge): edge for edge in edges}

    projection = _project_shard_facts(
        entities=entities,
        storage_entries=storage_entries,
        nodes=nodes,
        edge_by_id=edge_by_id,
        shard_by_path=shard_by_path,
    )
    entity_owner = projection.entity_owner
    storage_owner = projection.storage_owner
    node_owner = projection.node_owner
    edge_owner = projection.edge_owner
    node_references = projection.node_references
    entity_facts = projection.entity_facts
    storage_facts = projection.storage_facts
    graph_node_facts = projection.graph_node_facts
    graph_edge_facts = projection.graph_edge_facts
    source_owned_nodes = {**entity_owner, **storage_owner}
    record_hashes = {
        SolidityShardOverlapKind.ENTITY: {
            item.resource_id: item.record_sha256 for item in entity_facts
        },
        SolidityShardOverlapKind.GRAPH_NODE: {
            item.resource_id: item.record_sha256 for item in graph_node_facts
        },
        SolidityShardOverlapKind.GRAPH_EDGE: {
            item.resource_id: item.record_sha256 for item in graph_edge_facts
        },
        SolidityShardOverlapKind.STORAGE_ENTRY: {
            item.resource_id: item.record_sha256 for item in storage_facts
        },
    }

    primary_entities: dict[str, set[str]] = defaultdict(set)
    primary_storage: dict[str, set[str]] = defaultdict(set)
    primary_nodes: dict[str, set[str]] = defaultdict(set)
    primary_edges: dict[str, set[str]] = defaultdict(set)
    overlap_entities: dict[str, set[str]] = defaultdict(set)
    overlap_storage: dict[str, set[str]] = defaultdict(set)
    overlap_nodes: dict[str, set[str]] = defaultdict(set)
    overlap_edges: dict[str, set[str]] = defaultdict(set)
    inbound: dict[str, set[str]] = defaultdict(set)
    outbound: dict[str, set[str]] = defaultdict(set)
    boundary_hashes_by_shard: dict[str, list[str]] = defaultdict(list)
    entity_kinds_by_shard: dict[str, set[SolidityEntityKind]] = defaultdict(set)
    overlap_specs: dict[
        tuple[SolidityShardOverlapKind, str, str, str],
        SolidityShardOverlapReason,
    ] = {}
    overlap_counts: Counter[tuple[str, SolidityShardOverlapKind]] = Counter()

    for entity in entities:
        resource_id = entity.id
        owner = entity_owner[resource_id]
        primary_entities[owner].add(resource_id)
        entity_kinds_by_shard[owner].add(entity.kind)
    for resource_id, owner in storage_owner.items():
        primary_storage[owner].add(resource_id)
    for resource_id, owner in node_owner.items():
        primary_nodes[owner].add(resource_id)
    for resource_id, owner in edge_owner.items():
        primary_edges[owner].add(resource_id)

    for node_id, referring_shards in sorted(node_references.items()):
        if node_id in source_owned_nodes:
            continue
        owner = node_owner[node_id]
        for consumer in sorted(referring_shards - {owner}):
            overlap_nodes[consumer].add(node_id)
            _record_overlap(
                overlap_specs,
                overlap_counts=overlap_counts,
                policy=effective_policy,
                kind=SolidityShardOverlapKind.GRAPH_NODE,
                resource_id=node_id,
                owner=owner,
                consumer=consumer,
                reason=SolidityShardOverlapReason.SHARED_GRAPH_NODE,
            )

    boundaries: list[SolidityShardBoundary] = []
    for edge_id, edge in sorted(edge_by_id.items()):
        source_owner = source_owned_nodes.get(edge.source_id)
        target_owner = source_owned_nodes.get(edge.target_id)
        if source_owner is None or target_owner is None or source_owner == target_owner:
            continue
        boundary = SolidityShardBoundary.build(
            graph_edge_id=edge_id,
            graph_kind=edge.graph,
            source_node_id=edge.source_id,
            target_node_id=edge.target_id,
            source_shard_id=source_owner,
            target_shard_id=target_owner,
        )
        boundaries.append(boundary)
        if len(boundaries) > effective_policy.max_total_boundaries:
            raise SolidityShardingError("Solidity shard boundary inventory exceeds policy")
        outbound[source_owner].add(boundary.boundary_id)
        inbound[target_owner].add(boundary.boundary_id)
        boundary_hashes_by_shard[source_owner].append(boundary.boundary_sha256)
        boundary_hashes_by_shard[target_owner].append(boundary.boundary_sha256)
        if (
            len(inbound[source_owner]) + len(outbound[source_owner])
            > effective_policy.max_boundaries_per_shard
            or len(inbound[target_owner]) + len(outbound[target_owner])
            > effective_policy.max_boundaries_per_shard
        ):
            raise SolidityShardingError("Solidity shard boundary membership exceeds policy")
        for consumer in {source_owner, target_owner} - {edge_owner[edge_id]}:
            overlap_edges[consumer].add(edge_id)
            _record_overlap(
                overlap_specs,
                overlap_counts=overlap_counts,
                policy=effective_policy,
                kind=SolidityShardOverlapKind.GRAPH_EDGE,
                resource_id=edge_id,
                owner=edge_owner[edge_id],
                consumer=consumer,
                reason=SolidityShardOverlapReason.GRAPH_BOUNDARY,
            )
        _add_remote_source_overlap(
            resource_id=edge.target_id,
            owner=target_owner,
            consumer=source_owner,
            entity_owner=entity_owner,
            storage_owner=storage_owner,
            overlap_entities=overlap_entities,
            overlap_storage=overlap_storage,
            overlap_nodes=overlap_nodes,
            overlap_specs=overlap_specs,
            overlap_counts=overlap_counts,
            policy=effective_policy,
        )
        _add_remote_source_overlap(
            resource_id=edge.source_id,
            owner=source_owner,
            consumer=target_owner,
            entity_owner=entity_owner,
            storage_owner=storage_owner,
            overlap_entities=overlap_entities,
            overlap_storage=overlap_storage,
            overlap_nodes=overlap_nodes,
            overlap_specs=overlap_specs,
            overlap_counts=overlap_counts,
            policy=effective_policy,
        )

    shards: list[SoliditySemanticShard] = []
    for path, shard_id in sorted(shard_by_path.items()):
        primary_edge_ids = primary_edges[shard_id]
        overlap_edge_ids = overlap_edges[shard_id]
        shard_edge_kinds = {
            edge_by_id[edge_id].graph for edge_id in primary_edge_ids | overlap_edge_ids
        }
        risks = solidity_shard_risk_surfaces(
            shard_edge_kinds,
            entity_kinds=entity_kinds_by_shard[shard_id],
            has_storage=bool(primary_storage[shard_id] or overlap_storage[shard_id]),
        )
        fact_bindings = [
            (kind, resource_id, record_hashes[kind][resource_id])
            for kind, resource_ids in (
                (SolidityShardOverlapKind.ENTITY, primary_entities[shard_id]),
                (SolidityShardOverlapKind.ENTITY, overlap_entities[shard_id]),
                (SolidityShardOverlapKind.GRAPH_NODE, primary_nodes[shard_id]),
                (SolidityShardOverlapKind.GRAPH_NODE, overlap_nodes[shard_id]),
                (SolidityShardOverlapKind.GRAPH_EDGE, primary_edge_ids),
                (SolidityShardOverlapKind.GRAPH_EDGE, overlap_edge_ids),
                (SolidityShardOverlapKind.STORAGE_ENTRY, primary_storage[shard_id]),
                (SolidityShardOverlapKind.STORAGE_ENTRY, overlap_storage[shard_id]),
            )
            for resource_id in resource_ids
        ]
        boundary_hashes = boundary_hashes_by_shard[shard_id]
        _enforce_shard_caps(
            path=path,
            file=files[path],
            policy=effective_policy,
            entity_count=len(primary_entities[shard_id]),
            node_count=len(primary_nodes[shard_id]),
            edge_count=len(primary_edges[shard_id]),
            storage_count=len(primary_storage[shard_id]),
            overlap_entity_count=len(overlap_entities[shard_id]),
            overlap_node_count=len(overlap_nodes[shard_id]),
            overlap_edge_count=len(overlap_edges[shard_id]),
            overlap_storage_count=len(overlap_storage[shard_id]),
            boundary_count=len(inbound[shard_id]) + len(outbound[shard_id]),
        )
        source_unit_id = _source_unit_id(path)
        shard = SoliditySemanticShard.build(
            source_unit_id=source_unit_id,
            source_path=path,
            source_content_sha256=files[path].sha256,
            primary_entity_ids=tuple(sorted(primary_entities[shard_id])),
            overlap_entity_ids=tuple(sorted(overlap_entities[shard_id])),
            primary_graph_node_ids=tuple(sorted(primary_nodes[shard_id])),
            overlap_graph_node_ids=tuple(sorted(overlap_nodes[shard_id])),
            primary_graph_edge_ids=tuple(sorted(primary_edge_ids)),
            overlap_graph_edge_ids=tuple(sorted(overlap_edge_ids)),
            primary_storage_entry_ids=tuple(sorted(primary_storage[shard_id])),
            overlap_storage_entry_ids=tuple(sorted(overlap_storage[shard_id])),
            semantic_dependency_sha256=solidity_shard_semantic_dependency_sha256(
                fact_bindings=fact_bindings,
                boundary_sha256s=boundary_hashes,
            ),
            inbound_boundary_ids=tuple(sorted(inbound[shard_id])),
            outbound_boundary_ids=tuple(sorted(outbound[shard_id])),
            risk_surfaces=tuple(sorted(risks, key=str)),
        )
        if shard.shard_id != shard_id:
            raise SolidityShardingError("internal Solidity shard identity mismatch")
        shards.append(shard)

    source_units = tuple(
        SolidityShardSourceUnit.build(
            path=path,
            utf8_bytes=file.size,
            line_count=file.lines,
            content_sha256=file.sha256,
            primary_shard_id=shard_by_path[path],
        )
        for path, file in sorted(files.items())
    )
    overlaps = tuple(
        sorted(
            (
                SolidityShardOverlap.build(
                    resource_kind=kind,
                    resource_id=resource_id,
                    primary_shard_id=owner,
                    consumer_shard_id=consumer,
                    reason=reason,
                )
                for (kind, resource_id, owner, consumer), reason in overlap_specs.items()
            ),
            key=lambda item: item.overlap_id,
        )
    )
    sorted_shards = tuple(sorted(shards, key=lambda item: item.shard_id))
    coverage = SolidityShardCoverage(
        source_units_total=len(source_units),
        source_units_covered=len(source_units),
        source_bytes_total=sum(item.utf8_bytes for item in source_units),
        source_bytes_covered=sum(item.utf8_bytes for item in source_units),
        entities_total=len(entities),
        entities_covered=sum(len(shard.primary_entity_ids) for shard in sorted_shards),
        graph_nodes_total=len(nodes),
        graph_nodes_covered=sum(len(shard.primary_graph_node_ids) for shard in sorted_shards),
        graph_edges_total=len(edges),
        graph_edges_covered=sum(len(shard.primary_graph_edge_ids) for shard in sorted_shards),
        storage_entries_total=len(storage_entries),
        storage_entries_covered=sum(
            len(shard.primary_storage_entry_ids) for shard in sorted_shards
        ),
    )
    return SolidityShardInventory.build(
        git_commit=discovery.git_commit,
        policy=effective_policy,
        source_inventory_sha256=_source_inventory_sha256(files.values()),
        symbol_index_context_sha256=_symbol_index_context_sha256(index),
        symbol_index_sha256=_symbol_index_sha256(index),
        symbol_index_projection_sha256=_symbol_index_projection_sha256(index, entity_facts),
        graph_set_context_sha256=_graph_set_context_sha256(graphs),
        graph_set_sha256=_graph_set_sha256(graphs),
        graph_set_projection_sha256=_graph_set_projection_sha256(
            graphs,
            node_facts=graph_node_facts,
            edge_facts=graph_edge_facts,
            storage_facts=storage_facts,
        ),
        source_units=source_units,
        entity_facts=entity_facts,
        graph_node_facts=graph_node_facts,
        graph_edge_facts=graph_edge_facts,
        storage_facts=storage_facts,
        entity_ids=tuple(sorted(entity_owner)),
        graph_node_ids=tuple(sorted(node_owner)),
        graph_edge_ids=tuple(sorted(edge_owner)),
        storage_entry_ids=tuple(sorted(storage_owner)),
        shards=sorted_shards,
        boundaries=tuple(sorted(boundaries, key=lambda item: item.boundary_id)),
        overlaps=overlaps,
        coverage=coverage,
    )


def _validated_solidity_files(discovery: DiscoveryResult) -> dict[str, DiscoveredFile]:
    files: dict[str, DiscoveredFile] = {}
    for file in discovery.files:
        if file.language != "Solidity":
            continue
        try:
            normalized = normalize_relative_path(file.relative_path)
        except ValueError as exc:
            raise SolidityShardingError("Solidity source path is unsafe") from exc
        if normalized != file.relative_path or normalized in files:
            raise SolidityShardingError("Solidity source paths must be normalized and unique")
        encoded = file.content.encode("utf-8")
        if len(encoded) != file.size:
            raise SolidityShardingError(
                f"{file.relative_path}: complete source bytes are unavailable for sharding"
            )
        if hashlib.sha256(encoded).hexdigest() != file.sha256:
            raise SolidityShardingError(f"{file.relative_path}: source hash is stale")
        if len(file.content.splitlines()) != file.lines:
            raise SolidityShardingError(f"{file.relative_path}: source line count is stale")
        files[normalized] = file
    if not files:
        raise SolidityShardingError("semantic Solidity sharding requires a non-empty source set")
    return dict(sorted(files.items()))


def _validate_discovery_coverage(discovery: DiscoveryResult) -> None:
    _validate_omitted_solidity_coverage(discovery.omitted)


def _validate_omitted_solidity_coverage(omissions: Iterable[str]) -> None:
    for omission in omissions:
        lowered = omission.lower()
        omitted_path = omission.split(":", 1)[0].strip().lower()
        suffix = PurePosixPath(omitted_path).suffix.lower()
        dangerous_reason = any(
            token in lowered
            for token in (
                "symlink",
                "cycle",
                "directory",
                "unsupported path",
                "escaped repository",
            )
        )
        provably_non_solidity_file = bool(suffix and suffix != ".sol")
        if omitted_path == "repository" or dangerous_reason or not provably_non_solidity_file:
            raise SolidityShardingError(
                "complete Solidity source coverage is ambiguous because discovery omitted input"
            )


def _validate_index_coverage(
    index: SoliditySymbolIndex,
    files: dict[str, DiscoveredFile],
) -> None:
    _validate_index_source_coverage(index, set(files))


def _validate_index_source_coverage(
    index: SoliditySymbolIndex,
    source_paths: set[str],
) -> None:
    ast_sources = list(index.ast_sources)
    fallback_sources = list(index.fallback_sources)
    if len(ast_sources) != len(set(ast_sources)) or len(fallback_sources) != len(
        set(fallback_sources)
    ):
        raise SolidityShardingError("Solidity index source provenance contains duplicates")
    if set(ast_sources) & set(fallback_sources):
        raise SolidityShardingError("Solidity index source provenance is contradictory")
    if set(ast_sources) | set(fallback_sources) != source_paths:
        raise SolidityShardingError(
            "Solidity index source provenance does not cover every discovered source"
        )


def _validate_persisted_fact_ranges(
    *,
    inventory: SolidityShardInventory,
    entities: tuple[SolidityEntity, ...],
    storage_entries: tuple[SolidityStorageEntry, ...],
    nodes: tuple[SolidityGraphNode, ...],
    edges: tuple[SolidityGraphEdge, ...],
) -> None:
    source_by_path = {item.path: item for item in inventory.source_units}

    def require_line_range(
        *,
        path: str,
        start_line: int,
        end_line: int,
        label: str,
    ) -> SolidityShardSourceUnit:
        source = source_by_path.get(path)
        if source is None:
            raise SolidityShardingError(f"{label} references an unknown source unit")
        if start_line < 1 or end_line < start_line or end_line > source.line_count:
            raise SolidityShardingError(f"{label} has a range outside its source projection")
        return source

    for entity in entities:
        source = require_line_range(
            path=entity.path,
            start_line=entity.start_line,
            end_line=entity.end_line,
            label="persisted Solidity entity",
        )
        if entity.byte_start < 0 or entity.byte_end < entity.byte_start:
            raise SolidityShardingError("persisted Solidity entity byte range is invalid")
        if entity.byte_end > source.utf8_bytes:
            raise SolidityShardingError(
                "persisted Solidity entity byte range exceeds its source projection"
            )
    for entry in storage_entries:
        require_line_range(
            path=entry.path,
            start_line=entry.start_line,
            end_line=entry.end_line,
            label="persisted Solidity storage entry",
        )
    for node in nodes:
        require_line_range(
            path=node.path,
            start_line=node.start_line,
            end_line=node.end_line,
            label="persisted Solidity graph node",
        )
    for edge in edges:
        require_line_range(
            path=edge.path,
            start_line=edge.start_line,
            end_line=edge.end_line,
            label="persisted Solidity graph edge",
        )


def _validate_graph_consistency(
    graphs: SolidityGraphSet,
    *,
    entities: tuple[SolidityEntity, ...],
    storage_entries: tuple[SolidityStorageEntry, ...],
    nodes: tuple[SolidityGraphNode, ...],
    edges: tuple[SolidityGraphEdge, ...],
) -> None:
    analyzed = list(graphs.analyzed_graphs)
    if len(analyzed) != len(set(analyzed)) or set(analyzed) != set(SolidityGraphKind):
        raise SolidityShardingError("Solidity graph analysis-kind inventory is incomplete")
    counts = Counter(edge.graph.value for edge in edges)
    expected_coverage = {
        kind.value: counts.get(kind.value, 0) for kind in sorted(SolidityGraphKind, key=str)
    }
    if graphs.coverage != expected_coverage:
        raise SolidityShardingError("Solidity graph coverage counters differ from graph facts")
    node_ids = {node.id for node in nodes}
    required_source_nodes = {entity.id for entity in entities} | {
        entry.id for entry in storage_entries
    }
    if not required_source_nodes <= node_ids:
        raise SolidityShardingError("Solidity graph nodes omit indexed source-owned facts")


def _validated_entities(
    entities: Iterable[SolidityEntity],
    files: dict[str, DiscoveredFile],
) -> tuple[SolidityEntity, ...]:
    result = tuple(sorted(entities, key=lambda item: item.id))
    _require_unique_ids((item.id for item in result), "Solidity entity")
    for entity in result:
        _validate_range(
            path=entity.path,
            start_line=entity.start_line,
            end_line=entity.end_line,
            source_hash=entity.source_hash,
            files=files,
            label="Solidity entity",
        )
        if entity.byte_end > files[entity.path].size:
            raise SolidityShardingError(f"{entity.id}: entity byte range exceeds current source")
    return result


def _validated_storage_entries(
    entries: Iterable[SolidityStorageEntry],
    files: dict[str, DiscoveredFile],
) -> tuple[SolidityStorageEntry, ...]:
    result = tuple(sorted(entries, key=lambda item: item.id))
    _require_unique_ids((item.id for item in result), "Solidity storage entry")
    for entry in result:
        _validate_range(
            path=entry.path,
            start_line=entry.start_line,
            end_line=entry.end_line,
            source_hash=entry.source_hash,
            files=files,
            label="Solidity storage entry",
        )
    return result


def _validated_nodes(
    nodes: Iterable[SolidityGraphNode],
    files: dict[str, DiscoveredFile],
) -> tuple[SolidityGraphNode, ...]:
    result = tuple(sorted(nodes, key=lambda item: item.id))
    _require_unique_ids((item.id for item in result), "Solidity graph node")
    for node in result:
        _validate_range(
            path=node.path,
            start_line=node.start_line,
            end_line=node.end_line,
            source_hash=node.source_hash,
            files=files,
            label="Solidity graph node",
        )
    return result


def _validated_edges(
    edges: Iterable[SolidityGraphEdge],
    files: dict[str, DiscoveredFile],
    nodes: Iterable[SolidityGraphNode],
) -> tuple[SolidityGraphEdge, ...]:
    result = tuple(sorted(edges, key=solidity_graph_edge_id))
    edge_ids = [solidity_graph_edge_id(item) for item in result]
    _require_unique_ids(edge_ids, "Solidity graph edge")
    node_ids = {node.id for node in nodes}
    for edge in result:
        _validate_range(
            path=edge.path,
            start_line=edge.start_line,
            end_line=edge.end_line,
            source_hash=edge.source_hash,
            files=files,
            label="Solidity graph edge",
        )
        if edge.source_id not in node_ids or edge.target_id not in node_ids:
            raise SolidityShardingError("Solidity graph edge references an unknown endpoint")
    return result


def _validate_range(
    *,
    path: str,
    start_line: int,
    end_line: int,
    source_hash: str,
    files: dict[str, DiscoveredFile],
    label: str,
) -> None:
    file = files.get(path)
    if file is None:
        raise SolidityShardingError(f"{label} references a source outside the shard inventory")
    if start_line < 1 or end_line < start_line or end_line > file.lines:
        raise SolidityShardingError(f"{label} has a range outside current source")
    if line_range_hash(file.content, start_line, end_line) != source_hash:
        raise SolidityShardingError(f"{label} source hash is stale")


def _require_unique_ids(values: Iterable[str], label: str) -> None:
    identifiers = list(values)
    if len(identifiers) != len(set(identifiers)):
        raise SolidityShardingError(f"{label} IDs must be unique")


def _record_overlap(
    overlaps: dict[
        tuple[SolidityShardOverlapKind, str, str, str],
        SolidityShardOverlapReason,
    ],
    *,
    overlap_counts: Counter[tuple[str, SolidityShardOverlapKind]],
    policy: SolidityShardPolicy,
    kind: SolidityShardOverlapKind,
    resource_id: str,
    owner: str,
    consumer: str,
    reason: SolidityShardOverlapReason,
) -> None:
    key = (kind, resource_id, owner, consumer)
    previous = overlaps.get(key)
    if previous is not None and previous is not reason:
        raise SolidityShardingError("Solidity shard overlap has conflicting reasons")
    if previous is None:
        next_total = len(overlaps) + 1
        if next_total > policy.max_total_overlap_records:
            raise SolidityShardingError("Solidity shard overlap inventory exceeds policy")
        count_key = (consumer, kind)
        next_consumer_count = overlap_counts[count_key] + 1
        kind_limit = {
            SolidityShardOverlapKind.ENTITY: policy.max_overlap_entities_per_shard,
            SolidityShardOverlapKind.GRAPH_NODE: policy.max_overlap_graph_nodes_per_shard,
            SolidityShardOverlapKind.GRAPH_EDGE: policy.max_overlap_graph_edges_per_shard,
            SolidityShardOverlapKind.STORAGE_ENTRY: policy.max_overlap_storage_entries_per_shard,
        }[kind]
        if next_consumer_count > kind_limit:
            raise SolidityShardingError("Solidity shard overlap membership exceeds policy")
        overlap_counts[count_key] = next_consumer_count
    overlaps[key] = reason


def _add_remote_source_overlap(
    *,
    resource_id: str,
    owner: str,
    consumer: str,
    entity_owner: dict[str, str],
    storage_owner: dict[str, str],
    overlap_entities: dict[str, set[str]],
    overlap_storage: dict[str, set[str]],
    overlap_nodes: dict[str, set[str]],
    overlap_specs: dict[
        tuple[SolidityShardOverlapKind, str, str, str],
        SolidityShardOverlapReason,
    ],
    overlap_counts: Counter[tuple[str, SolidityShardOverlapKind]],
    policy: SolidityShardPolicy,
) -> None:
    overlap_nodes[consumer].add(resource_id)
    _record_overlap(
        overlap_specs,
        overlap_counts=overlap_counts,
        policy=policy,
        kind=SolidityShardOverlapKind.GRAPH_NODE,
        resource_id=resource_id,
        owner=owner,
        consumer=consumer,
        reason=SolidityShardOverlapReason.GRAPH_BOUNDARY,
    )
    if resource_id in entity_owner:
        overlap_entities[consumer].add(resource_id)
        kind = SolidityShardOverlapKind.ENTITY
    elif resource_id in storage_owner:
        overlap_storage[consumer].add(resource_id)
        kind = SolidityShardOverlapKind.STORAGE_ENTRY
    else:
        raise SolidityShardingError("entity-backed boundary lost source ownership")
    _record_overlap(
        overlap_specs,
        overlap_counts=overlap_counts,
        policy=policy,
        kind=kind,
        resource_id=resource_id,
        owner=owner,
        consumer=consumer,
        reason=SolidityShardOverlapReason.GRAPH_BOUNDARY,
    )


def _enforce_shard_caps(
    *,
    path: str,
    file: DiscoveredFile,
    policy: SolidityShardPolicy,
    entity_count: int,
    node_count: int,
    edge_count: int,
    storage_count: int,
    overlap_entity_count: int,
    overlap_node_count: int,
    overlap_edge_count: int,
    overlap_storage_count: int,
    boundary_count: int,
) -> None:
    total_semantic_memberships = sum(
        (
            entity_count,
            node_count,
            edge_count,
            storage_count,
            overlap_entity_count,
            overlap_node_count,
            overlap_edge_count,
            overlap_storage_count,
        )
    )
    checks = (
        (file.size, policy.max_source_bytes_per_shard, "source bytes"),
        (entity_count, policy.max_primary_entities_per_shard, "primary entities"),
        (node_count, policy.max_primary_graph_nodes_per_shard, "primary graph nodes"),
        (edge_count, policy.max_primary_graph_edges_per_shard, "primary graph edges"),
        (
            storage_count,
            policy.max_primary_storage_entries_per_shard,
            "primary storage entries",
        ),
        (overlap_entity_count, policy.max_overlap_entities_per_shard, "overlap entities"),
        (overlap_node_count, policy.max_overlap_graph_nodes_per_shard, "overlap graph nodes"),
        (overlap_edge_count, policy.max_overlap_graph_edges_per_shard, "overlap graph edges"),
        (
            overlap_storage_count,
            policy.max_overlap_storage_entries_per_shard,
            "overlap storage entries",
        ),
        (boundary_count, policy.max_boundaries_per_shard, "boundaries"),
        (
            total_semantic_memberships,
            policy.max_total_semantic_memberships_per_shard,
            "total semantic memberships",
        ),
    )
    for observed, maximum, label in checks:
        if observed > maximum:
            raise SolidityShardingError(f"{path}: {label} exceed the shard policy")


def _source_unit_id(path: str) -> str:
    return "source-" + _canonical_sha256({"path": path})[:24]


def _shard_id(path: str) -> str:
    source_unit_id = _source_unit_id(path)
    return (
        "shard-" + _canonical_sha256({"source_path": path, "source_unit_id": source_unit_id})[:24]
    )


def _source_inventory_sha256(files: Iterable[DiscoveredFile]) -> str:
    return _canonical_sha256(
        [
            {
                "path": file.relative_path,
                "utf8_bytes": file.size,
                "line_count": file.lines,
                "content_sha256": file.sha256,
            }
            for file in sorted(files, key=lambda item: item.relative_path)
        ]
    )


def _symbol_index_context_sha256(index: SoliditySymbolIndex) -> str:
    return _canonical_sha256(
        {
            "projects": _canonical_models(index.model_dump(mode="json")["projects"]),
            "ast_sources": sorted(index.ast_sources),
            "fallback_sources": sorted(index.fallback_sources),
            "warnings": sorted(index.warnings),
        }
    )


def _symbol_index_sha256(index: SoliditySymbolIndex) -> str:
    payload = index.model_dump(mode="json")
    return _canonical_sha256(
        {
            "projects": _canonical_models(payload["projects"]),
            "entities": sorted(payload["entities"], key=lambda item: item["id"]),
            "ast_sources": sorted(index.ast_sources),
            "fallback_sources": sorted(index.fallback_sources),
            "warnings": sorted(index.warnings),
        }
    )


def _symbol_index_projection_sha256(
    index: SoliditySymbolIndex,
    entity_facts: tuple[SolidityShardEntityFact, ...],
) -> str:
    return _canonical_sha256(
        {
            "context_sha256": _symbol_index_context_sha256(index),
            "entity_facts": [item.model_dump(mode="json") for item in entity_facts],
        }
    )


def _graph_set_context_sha256(graphs: SolidityGraphSet) -> str:
    return _canonical_sha256(
        {
            "analyzed_graphs": sorted(item.value for item in graphs.analyzed_graphs),
            "coverage": dict(sorted(graphs.coverage.items())),
            "warnings": sorted(graphs.warnings),
        }
    )


def _graph_set_sha256(graphs: SolidityGraphSet) -> str:
    payload = graphs.model_dump(mode="json")
    return _canonical_sha256(
        {
            "nodes": sorted(payload["nodes"], key=lambda item: item["id"]),
            "edges": sorted(
                payload["edges"],
                key=lambda item: _canonical_sha256(item),
            ),
            "analyzed_graphs": sorted(item.value for item in graphs.analyzed_graphs),
            "storage_layout": sorted(
                payload["storage_layout"],
                key=lambda item: item["id"],
            ),
            "coverage": dict(sorted(graphs.coverage.items())),
            "warnings": sorted(graphs.warnings),
        }
    )


def _graph_set_projection_sha256(
    graphs: SolidityGraphSet,
    *,
    node_facts: tuple[SolidityShardGraphNodeFact, ...],
    edge_facts: tuple[SolidityShardGraphEdgeFact, ...],
    storage_facts: tuple[SolidityShardStorageFact, ...],
) -> str:
    return _canonical_sha256(
        {
            "context_sha256": _graph_set_context_sha256(graphs),
            "node_facts": [item.model_dump(mode="json") for item in node_facts],
            "edge_facts": [item.model_dump(mode="json") for item in edge_facts],
            "storage_facts": [item.model_dump(mode="json") for item in storage_facts],
        }
    )


def _record_sha256(value: Any) -> str:
    model_dump = getattr(value, "model_dump", None)
    if not callable(model_dump):
        raise SolidityShardingError("Solidity shard fact is not a typed model")
    return _canonical_sha256(model_dump(mode="json"))


def _canonical_models(values: list[Any]) -> list[Any]:
    return sorted(values, key=lambda value: _canonical_sha256(value))
