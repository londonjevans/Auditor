"""Bounded Solidity fact retrieval for model context packages."""

from __future__ import annotations

from mmaudit.models.schemas import (
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphSet,
    SoliditySymbolIndex,
)


def compact_solidity_index(
    index: SoliditySymbolIndex | None,
    *,
    role: str,
    max_entities: int = 500,
    preferred_paths: set[str] | None = None,
) -> SoliditySymbolIndex | None:
    if index is None:
        return None
    preferred = preferred_paths or set()
    entities = sorted(
        index.entities,
        key=lambda entity: (
            0 if entity.path in preferred else 1,
            _entity_rank(entity, role),
            entity.path,
            entity.start_line,
        ),
    )
    omitted = max(0, len(entities) - max_entities)
    warnings = list(index.warnings)
    if omitted:
        warnings.append(f"{omitted} Solidity indexed entities omitted from {role} context")
    selected_paths = {entity.path for entity in entities[:max_entities]}
    return index.model_copy(
        update={
            "entities": entities[:max_entities],
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
) -> SolidityGraphSet | None:
    if graphs is None:
        return None
    preferred = preferred_paths or set()
    edges = sorted(
        graphs.edges,
        key=lambda edge: (
            0 if edge.path in preferred else 1,
            _edge_rank(edge, role),
            edge.graph,
            edge.label,
        ),
    )
    warnings = list(graphs.warnings)
    if len(edges) > max_edges:
        warnings.append(
            f"{len(edges) - max_edges} Solidity graph edges omitted from {role} context"
        )
    selected = edges[:max_edges]
    referenced_ids = {
        identifier for edge in selected for identifier in (edge.source_id, edge.target_id)
    }
    nodes = [node for node in graphs.nodes if node.id in referenced_ids][: max_edges * 2]
    return graphs.model_copy(
        update={
            "edges": selected,
            "nodes": nodes,
            "storage_layout": graphs.storage_layout[:500],
            "warnings": warnings,
        }
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
