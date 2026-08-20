"""Bounded Solidity fact retrieval for model context packages."""

from __future__ import annotations

import json
from collections import Counter

from mmaudit.models.schemas import (
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphFactKind,
    SolidityGraphFactOmission,
    SolidityGraphKind,
    SolidityGraphNode,
    SolidityGraphOccurrenceKind,
    SolidityGraphOmission,
    SolidityGraphRetainedOccurrence,
    SolidityGraphSet,
    SolidityStorageEntry,
    SoliditySymbolIndex,
    solidity_graph_occurrence_sha256,
)


def compact_solidity_index(
    index: SoliditySymbolIndex | None,
    *,
    role: str,
    max_entities: int = 500,
    preferred_paths: set[str] | None = None,
    required_entity_ids: set[str] | None = None,
) -> SoliditySymbolIndex | None:
    if index is None:
        if required_entity_ids:
            raise ValueError("required Solidity index entities are unavailable")
        return None
    preferred = preferred_paths or set()
    required = required_entity_ids or set()
    available_ids = {entity.id for entity in index.entities}
    missing = required - available_ids
    if missing:
        raise ValueError("required Solidity index entities are unavailable")
    entities = sorted(
        index.entities,
        key=lambda entity: (
            0 if entity.id in required else 1,
            0 if entity.path in preferred else 1,
            _entity_rank(entity, role),
            entity.path,
            entity.start_line,
        ),
    )
    retained_limit = max(max_entities, len(required))
    selected = entities[:retained_limit]
    omitted = max(0, len(entities) - len(selected))
    warnings = list(index.warnings)
    if omitted:
        warnings.append(f"{omitted} Solidity indexed entities omitted from {role} context")
    selected_paths = {entity.path for entity in selected}
    return index.model_copy(
        update={
            "entities": selected,
            "ast_sources": [path for path in index.ast_sources if path in selected_paths],
            "fallback_sources": [path for path in index.fallback_sources if path in selected_paths],
            "warnings": warnings,
        }
    )


def compact_solidity_graphs(
    graphs: SolidityGraphSet | None,
    *,
    role: str,
    max_edges: int = 700,
    preferred_paths: set[str] | None = None,
    required_edges: tuple[SolidityGraphEdge, ...] = (),
) -> SolidityGraphSet | None:
    if graphs is None:
        if required_edges:
            raise ValueError("required Solidity graph edges are unavailable")
        return None
    preferred = preferred_paths or set()
    required = {_graph_edge_identity(edge) for edge in required_edges}
    available = {_graph_edge_identity(edge) for edge in graphs.edges}
    if not required <= available:
        raise ValueError("required Solidity graph edges are unavailable")
    edges = sorted(
        graphs.edges,
        key=lambda edge: (
            0 if _graph_edge_identity(edge) in required else 1,
            0 if edge.path in preferred else 1,
            _edge_rank(edge, role),
            edge.graph,
            edge.label,
        ),
    )
    retained_limit = max(max_edges, len(required))
    warnings = list(graphs.warnings)
    selected = edges[:retained_limit]
    referenced_ids = {
        identifier for edge in selected for identifier in (edge.source_id, edge.target_id)
    }
    nodes = [node for node in graphs.nodes if node.id in referenced_ids][: retained_limit * 2]
    storage_layout = graphs.storage_layout[:500]
    occurrence_counts = {
        (item.subject_kind, item.subject_sha256): item.occurrence_count
        for item in graphs.retained_occurrences
    }

    def retained_occurrence_count(
        subject_kind: SolidityGraphOccurrenceKind,
        subject: SolidityGraphEdge | SolidityGraphNode | SolidityStorageEntry | str,
    ) -> int:
        return occurrence_counts[
            (subject_kind, solidity_graph_occurrence_sha256(subject_kind, subject))
        ]

    selected_edge_occurrences = {
        solidity_graph_occurrence_sha256(SolidityGraphOccurrenceKind.EDGE, edge): (
            retained_occurrence_count(SolidityGraphOccurrenceKind.EDGE, edge)
        )
        for edge in selected
    }
    selected_counts = Counter(edge.graph for edge in selected)
    selected_occurrence_counts = Counter(
        {
            graph: sum(
                selected_edge_occurrences[
                    solidity_graph_occurrence_sha256(SolidityGraphOccurrenceKind.EDGE, edge)
                ]
                for edge in selected
                if edge.graph is graph
            )
            for graph in SolidityGraphKind
        }
    )
    selected_counts_by_name = Counter(edge.graph.value for edge in selected)
    projected_omissions = tuple(
        SolidityGraphOmission.build(
            graph=omission.graph,
            reason=omission.reason,
            candidate_count=(selected_occurrence_counts[omission.graph] + omission.omitted_count),
            retained_count=selected_counts[omission.graph],
            retained_occurrence_count=selected_occurrence_counts[omission.graph],
            omitted_count=omission.omitted_count,
            omitted_canonical_bytes=omission.omitted_canonical_bytes,
            analytical_omitted_count=omission.analytical_omitted_count,
            analytical_population_sample_sha256s=(omission.analytical_population_sample_sha256s),
            omitted_stream_sha256=omission.omitted_stream_sha256,
            omitted_sample_sha256s=omission.omitted_sample_sha256s,
        )
        for omission in graphs.edge_omissions
    )
    retained_occurrences_by_key: dict[
        tuple[SolidityGraphOccurrenceKind, str], SolidityGraphRetainedOccurrence
    ] = {}

    def retain_occurrence(
        subject_kind: SolidityGraphOccurrenceKind,
        subject: SolidityGraphEdge | SolidityGraphNode | SolidityStorageEntry | str,
    ) -> None:
        subject_sha256 = solidity_graph_occurrence_sha256(subject_kind, subject)
        key = (subject_kind, subject_sha256)
        retained_occurrences_by_key[key] = SolidityGraphRetainedOccurrence(
            subject_kind=subject_kind,
            subject_sha256=subject_sha256,
            occurrence_count=occurrence_counts[key],
        )

    for edge in selected:
        retain_occurrence(SolidityGraphOccurrenceKind.EDGE, edge)
    for node in nodes:
        retain_occurrence(SolidityGraphOccurrenceKind.GRAPH_NODE, node)
    for entry in storage_layout:
        retain_occurrence(SolidityGraphOccurrenceKind.STORAGE_ENTRY, entry)
    for warning in graphs.warnings:
        retain_occurrence(SolidityGraphOccurrenceKind.WARNING, warning)

    if len(edges) > retained_limit:
        context_warning = (
            f"{len(edges) - retained_limit} Solidity graph edges omitted from {role} context"
        )
        warning_sha256 = solidity_graph_occurrence_sha256(
            SolidityGraphOccurrenceKind.WARNING, context_warning
        )
        warning_key = (SolidityGraphOccurrenceKind.WARNING, warning_sha256)
        previous_warning = retained_occurrences_by_key.get(warning_key)
        if previous_warning is None:
            warnings.append(context_warning)
            retained_occurrences_by_key[warning_key] = SolidityGraphRetainedOccurrence(
                subject_kind=SolidityGraphOccurrenceKind.WARNING,
                subject_sha256=warning_sha256,
                occurrence_count=1,
            )
        else:
            retained_occurrences_by_key[warning_key] = previous_warning.model_copy(
                update={"occurrence_count": previous_warning.occurrence_count + 1}
            )

    projected_retained_occurrences = tuple(
        sorted(
            retained_occurrences_by_key.values(),
            key=lambda item: (item.subject_kind.value, item.subject_sha256),
        )
    )
    retained_fact_counts = {
        SolidityGraphFactKind.GRAPH_NODE: len(nodes),
        SolidityGraphFactKind.STORAGE_ENTRY: len(storage_layout),
        SolidityGraphFactKind.WARNING: len(warnings),
    }
    retained_fact_occurrence_counts = Counter(
        {
            item.subject_kind: sum(
                occurrence.occurrence_count
                for occurrence in projected_retained_occurrences
                if occurrence.subject_kind is item.subject_kind
            )
            for item in projected_retained_occurrences
        }
    )
    projected_fact_omissions = tuple(
        SolidityGraphFactOmission.build(
            fact_kind=omission.fact_kind,
            reason=omission.reason,
            candidate_count=(
                retained_fact_occurrence_counts[
                    SolidityGraphOccurrenceKind(omission.fact_kind.value)
                ]
                + omission.omitted_count
            ),
            retained_count=retained_fact_counts[omission.fact_kind],
            retained_occurrence_count=retained_fact_occurrence_counts[
                SolidityGraphOccurrenceKind(omission.fact_kind.value)
            ],
            omitted_count=omission.omitted_count,
            omitted_canonical_bytes=omission.omitted_canonical_bytes,
            omitted_stream_sha256=omission.omitted_stream_sha256,
            omitted_sample_sha256s=omission.omitted_sample_sha256s,
        )
        for omission in graphs.fact_omissions
    )
    coverage_keys = {
        *graphs.coverage,
        *(edge.graph.value for edge in selected),
        *(omission.graph.value for omission in projected_omissions),
    }
    # Producer omissions remain upstream facts; ContextPackage separately records edges
    # removed by this context projection. Rebuild the local retained counters so this
    # projection cannot claim graph facts that its serialized edge inventory does not carry.
    return SolidityGraphSet.model_validate(
        {
            **graphs.model_dump(mode="python"),
            "edges": selected,
            "nodes": nodes,
            "storage_layout": storage_layout,
            "retained_occurrences": projected_retained_occurrences,
            "coverage": {key: selected_counts_by_name.get(key, 0) for key in sorted(coverage_keys)},
            "edge_omissions": projected_omissions,
            "fact_omissions": projected_fact_omissions,
            "warnings": warnings,
        }
    )


def _graph_edge_identity(edge: SolidityGraphEdge) -> str:
    """Return one exact local identity for required-edge retention."""

    return json.dumps(
        edge.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def solidity_preferred_paths(index: SoliditySymbolIndex | None, role: str) -> set[str]:
    if index is None:
        return set()
    return {
        entity.path
        for entity in sorted(index.entities, key=lambda entity: _entity_rank(entity, role))[:300]
    }


def _entity_rank(entity: SolidityEntity, role: str) -> tuple[int, str]:
    role = role.removeprefix("specialist:")
    priority = 50
    if entity.kind in {
        SolidityEntityKind.CONTRACT,
        SolidityEntityKind.INTERFACE,
        SolidityEntityKind.LIBRARY,
    }:
        priority -= 10
    if entity.kind in {
        SolidityEntityKind.FUNCTION,
        SolidityEntityKind.CONSTRUCTOR,
        SolidityEntityKind.MODIFIER,
    }:
        priority -= 20
    if entity.payable:
        priority -= 10
    if entity.visibility in {"public", "external"}:
        priority -= 8
    if role == "business_logic" and any(
        token in entity.name.lower()
        for token in ("claim", "withdraw", "deposit", "stake", "vote", "mint", "burn")
    ):
        priority -= 15
    if role == "configuration" and entity.kind is SolidityEntityKind.CONSTRUCTOR:
        priority -= 15
    if role == "source_audit" and entity.kind is SolidityEntityKind.MODIFIER:
        priority -= 10
    if role in {"access_control", "governance_timelock"} and (
        entity.kind is SolidityEntityKind.MODIFIER
        or any(
            token in entity.name.lower()
            for token in (
                "admin",
                "cancel",
                "execute",
                "govern",
                "owner",
                "pause",
                "proposal",
                "queue",
                "role",
                "timelock",
                "vote",
            )
        )
    ):
        priority -= 18
    if role in {"erc4626_vault", "accounting_invariant"} and any(
        token in entity.name.lower()
        for token in ("asset", "share", "deposit", "withdraw", "redeem", "claim", "reward")
    ):
        priority -= 18
    if role in {"economic_game_theory", "precision_rounding"} and any(
        token in entity.name.lower()
        for token in (
            "asset",
            "borrow",
            "claim",
            "convert",
            "debt",
            "deposit",
            "fee",
            "liquidat",
            "price",
            "redeem",
            "reward",
            "share",
            "swap",
            "withdraw",
        )
    ):
        priority -= 18
    if role == "upgradeability_storage" and any(
        token in entity.name.lower() for token in ("upgrade", "initialize", "implementation")
    ):
        priority -= 20
    if role == "initialization_deployment" and (
        entity.kind is SolidityEntityKind.CONSTRUCTOR
        or any(
            token in entity.name.lower()
            for token in ("initialize", "owner", "admin", "setup", "upgrade")
        )
    ):
        priority -= 20
    if role == "denial_of_service_griefing" and any(
        token in entity.name.lower()
        for token in ("batch", "claim", "execute", "finalize", "liquidate", "queue", "settle")
    ):
        priority -= 16
    if role == "state_machine_lifecycle" and any(
        token in entity.name.lower()
        for token in (
            "state",
            "transition",
            "pause",
            "unpause",
            "finalize",
            "settle",
            "migrate",
            "close",
        )
    ):
        priority -= 20
    if role == "randomness_entropy_commit_reveal" and any(
        token in entity.name.lower()
        for token in (
            "random",
            "entropy",
            "seed",
            "commit",
            "reveal",
            "vrf",
            "winner",
            "draw",
            "select",
        )
    ):
        priority -= 20
    if role == "cross_chain_bridge" and any(
        token in entity.name.lower()
        for token in (
            "bridge",
            "callback",
            "dispatch",
            "fulfill",
            "message",
            "relay",
        )
    ):
        priority -= 20
    if role == "invariant_review" and (
        entity.kind
        in {
            SolidityEntityKind.STATE_VARIABLE,
            SolidityEntityKind.IMMUTABLE,
            SolidityEntityKind.CONSTANT,
        }
        or any(
            token in entity.name.lower()
            for token in (
                "asset",
                "balance",
                "borrow",
                "claim",
                "collateral",
                "debt",
                "deposit",
                "fee",
                "index",
                "initialize",
                "mint",
                "oracle",
                "reward",
                "share",
                "supply",
                "upgrade",
                "withdraw",
            )
        )
    ):
        priority -= 22
    return (priority, entity.id)


def _edge_rank(edge: SolidityGraphEdge, role: str) -> tuple[int, str]:
    role = role.removeprefix("specialist:")
    priority = 50
    if edge.graph == "inheritance":
        priority -= 12
    if edge.graph == "modifier":
        priority -= 15
    if role == "source_audit" and edge.graph == "internal_call":
        priority -= 12
    if role == "source_audit" and edge.graph in {
        "external_call",
        "low_level_call",
        "delegatecall",
        "reentrancy",
        "sensitive_reachability",
    }:
        priority -= 22
    if role == "business_logic" and edge.graph in {
        "asset_flow",
        "dependency",
        "state_dependency",
        "oracle_dependency",
    }:
        priority -= 22
    if role == "configuration" and edge.graph in {
        "proxy",
        "storage_layout",
        "upgrade_compatibility",
        "privilege",
    }:
        priority -= 22
    specialist_graphs = {
        "access_control": {
            "privilege",
            "governance",
            "modifier",
            "sensitive_reachability",
        },
        "reentrancy_control_flow": {
            "reentrancy",
            "external_call",
            "low_level_call",
            "state_write",
        },
        "oracle_price_manipulation": {
            "oracle_dependency",
            "offchain_dependency",
            "dependency",
            "asset_flow",
            "external_call",
        },
        "accounting_invariant": {"asset_flow", "state_dependency", "state_write"},
        "token_standard": {
            "asset_flow",
            "external_call",
            "state_write",
            "signature_replay",
        },
        "erc4626_vault": {
            "asset_flow",
            "oracle_dependency",
            "state_dependency",
            "state_read",
            "state_write",
        },
        "amm_dex_liquidity": {"asset_flow", "oracle_dependency", "external_call"},
        "lending_liquidation": {
            "asset_flow",
            "oracle_dependency",
            "state_dependency",
            "state_write",
        },
        "economic_game_theory": {
            "asset_flow",
            "oracle_dependency",
            "state_dependency",
            "sensitive_reachability",
        },
        "signature_permit_replay": {
            "signature_replay",
            "state_read",
            "state_write",
            "external_call",
        },
        "formal_methods_property": {
            "event_state",
            "signature_replay",
            "state_dependency",
            "storage_layout",
        },
        "state_machine_lifecycle": {
            "state_dependency",
            "state_read",
            "state_write",
            "event_state",
            "event_flow",
            "initializer",
            "governance",
            "sensitive_reachability",
        },
        "randomness_entropy_commit_reveal": {
            "dependency",
            "offchain_dependency",
            "oracle_dependency",
            "state_dependency",
            "state_read",
            "state_write",
            "event_state",
            "sensitive_reachability",
        },
        "upgradeability_storage": {
            "proxy",
            "delegatecall",
            "storage_layout",
            "upgrade_compatibility",
            "initializer",
        },
        "initialization_deployment": {
            "initializer",
            "proxy",
            "privilege",
            "storage_layout",
            "upgrade_compatibility",
        },
        "governance_timelock": {
            "governance",
            "privilege",
            "modifier",
            "state_dependency",
            "sensitive_reachability",
        },
        "denial_of_service_griefing": {
            "external_call",
            "low_level_call",
            "state_dependency",
            "sensitive_reachability",
        },
        "precision_rounding": {
            "asset_flow",
            "state_dependency",
            "state_read",
            "state_write",
        },
        "mev_ordering": {
            "asset_flow",
            "external_call",
            "oracle_dependency",
            "sensitive_reachability",
        },
        "cross_chain_bridge": {
            "asset_flow",
            "cross_chain",
            "delegatecall",
            "dependency",
            "event_flow",
            "external_call",
            "offchain_dependency",
            "signature_replay",
        },
        "dependency_supply_chain": {
            "dependency",
            "external_call",
            "delegatecall",
            "offchain_dependency",
            "oracle_dependency",
            "proxy",
        },
        "invariant_review": {
            "asset_flow",
            "cross_chain",
            "dependency",
            "event_flow",
            "governance",
            "offchain_dependency",
            "state_dependency",
            "state_read",
            "state_write",
            "privilege",
            "oracle_dependency",
            "storage_layout",
            "initializer",
            "event_state",
            "signature_replay",
        },
    }
    if edge.graph in specialist_graphs.get(role, set()):
        priority -= 25
    if role == "reentrancy_control_flow" and edge.graph == "reentrancy":
        priority -= 12
        if edge.metadata.get("unsafe_transition_candidate") is True:
            priority -= 4
    if (
        role in {"access_control", "governance_timelock"}
        and edge.graph == "privilege"
        and edge.metadata.get("control_resolution") == "unknown"
    ):
        priority -= 8
    if (
        role in {"oracle_price_manipulation", "dependency_supply_chain"}
        and edge.graph in {"dependency", "oracle_dependency"}
        and (
            edge.metadata.get("dependency_resolution") == "unknown_target"
            or edge.metadata.get("freshness_validation") == "unknown"
        )
    ):
        priority -= 6
    if role == "oracle_price_manipulation" and edge.graph == "oracle_dependency":
        priority -= 8
    if role == "governance_timelock" and edge.graph == "governance":
        priority -= 8
    if role == "cross_chain_bridge" and edge.graph in {
        "cross_chain",
        "event_flow",
        "offchain_dependency",
    }:
        priority -= 8
    if (
        role
        in {
            "token_standard",
            "erc4626_vault",
            "amm_dex_liquidity",
            "lending_liquidation",
            "economic_game_theory",
            "mev_ordering",
            "cross_chain_bridge",
        }
        and edge.graph == "asset_flow"
    ):
        priority -= 8
    return (priority, edge.source_id)
