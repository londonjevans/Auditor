"""Bounded Solidity fact retrieval for model context packages."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Literal, Self, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

from mmaudit.models.retrieval import (
    SOLIDITY_RETRIEVAL_MAX_EXCHANGES,
    SOLIDITY_RETRIEVAL_SUBJECT_ID_MAX_LENGTH,
    SolidityRetrievalEntity,
    SolidityRetrievalEntityKind,
    SolidityRetrievalExchange,
    SolidityRetrievalOmission,
    SolidityRetrievalOperation,
    SolidityRetrievalReason,
    SolidityRetrievalRecord,
    SolidityRetrievalRequest,
    SolidityRetrievalRequestBatch,
    SolidityRetrievalResult,
    SolidityRetrievalRolePolicy,
    SolidityRetrievalStatus,
    SolidityRetrievalTranscript,
    solidity_retrieval_records_utf8_bytes,
    solidity_retrieval_transcript_utf8_bytes,
    validated_solidity_retrieval_subject_id,
)
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
    StrictModel,
    solidity_graph_occurrence_sha256,
)
from mmaudit.models.token_planning import UTF8_BYTES_PER_ESTIMATED_TOKEN
from mmaudit.repository.ignore import normalize_relative_path


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


# The retrieval protocol is deliberately isolated from the context-compaction helpers above.
# Its corpus builder may inspect original source bytes transiently, but only safe redacted ranges
# and hash-only source bindings survive in the returned model.

_RETRIEVAL_MAX_SOURCE_FILES = 100_000
_RETRIEVAL_MAX_SOURCE_BYTES = 500_000_000
_RETRIEVAL_MAX_ENTITIES = 1_000_000
_RETRIEVAL_MAX_RELATIONS = 2_000_000

if {kind.value for kind in SolidityRetrievalEntityKind} != {
    kind.value for kind in SolidityEntityKind
}:
    raise RuntimeError("provider-visible retrieval entity kinds differ from the Solidity index")


def _canonical_json_bytes(value: Any, *, ensure_ascii: bool = True) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=ensure_ascii,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _model_sha256(model: StrictModel, *, hash_field: str) -> str:
    return _canonical_sha256(model.model_dump(mode="json", exclude={hash_field}))


def _sealed_model_values(
    model_type: type[StrictModel],
    values: dict[str, Any],
    *,
    hash_field: str,
) -> dict[str, Any]:
    if hash_field in values:
        raise ValueError(f"{hash_field} is derived and cannot be supplied")
    provisional_values: dict[str, Any] = {**values, hash_field: "0" * 64}
    provisional = model_type.model_construct(**provisional_values)
    payload = provisional.model_dump(mode="json", exclude={hash_field})
    return {**values, hash_field: _canonical_sha256(payload)}


def _validated_retrieval_path(value: str) -> str:
    normalized = normalize_relative_path(value)
    if normalized != value or normalized in {"", "."}:
        raise ValueError("retrieval source path must be normalized and relative")
    if PurePosixPath(value).suffix.lower() != ".sol":
        raise ValueError("retrieval source path must identify a Solidity source")
    return value


def _source_line_count(content: str) -> int:
    return len(content.splitlines(keepends=True))


def _exact_source_range(content: str, start_line: int, end_line: int) -> str:
    lines = content.splitlines(keepends=True)
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise ValueError("indexed source range lies outside its exact source")
    return "".join(lines[start_line - 1 : end_line])


class _FrozenRetrievalModel(StrictModel):
    """Strict immutable base for retrieval evidence and engine state."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SolidityRetrievalAccessStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    REDACTED_OR_SECRET = "REDACTED_OR_SECRET"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


class SolidityRetrievalGraphStatus(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"


class SolidityRetrievalScopeMode(StrEnum):
    ALL_INDEXED_PATHS = "ALL_INDEXED_PATHS"
    PATH_ALLOWLIST = "PATH_ALLOWLIST"


class SolidityRetrievalSecretInterval(_FrozenRetrievalModel):
    """Line-only secret taint; secret match text is intentionally absent."""

    path: str = Field(min_length=1, max_length=4_096)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)

    @field_validator("path")
    @classmethod
    def path_is_safe(cls, value: str) -> str:
        return _validated_retrieval_path(value)

    @model_validator(mode="after")
    def interval_is_ordered(self) -> Self:
        if self.end_line < self.start_line:
            raise ValueError("secret-tainted interval is reversed")
        return self


class SolidityRetrievalScope(_FrozenRetrievalModel):
    """Canonical effective path scope for one retrieval corpus."""

    schema_version: Literal["1.0"] = "1.0"
    mode: SolidityRetrievalScopeMode
    source_path_count: int = Field(ge=0, le=_RETRIEVAL_MAX_SOURCE_FILES)
    source_paths_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    allowed_paths: tuple[str, ...] = Field(max_length=_RETRIEVAL_MAX_SOURCE_FILES)
    scope_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(
        cls,
        *,
        source_paths: Sequence[str],
        allowed_paths: Sequence[str] | set[str] | frozenset[str] | None = None,
    ) -> Self:
        canonical_sources = tuple(sorted(_validated_retrieval_path(path) for path in source_paths))
        if len(canonical_sources) != len(set(canonical_sources)):
            raise ValueError("retrieval source paths must be unique")
        if allowed_paths is None:
            mode = SolidityRetrievalScopeMode.ALL_INDEXED_PATHS
            canonical_allowed = canonical_sources
        else:
            mode = SolidityRetrievalScopeMode.PATH_ALLOWLIST
            canonical_allowed = tuple(
                sorted(_validated_retrieval_path(path) for path in allowed_paths)
            )
            if len(canonical_allowed) != len(set(canonical_allowed)):
                raise ValueError("retrieval allowed paths must be unique")
            if not set(canonical_allowed) <= set(canonical_sources):
                raise ValueError("retrieval allowed paths must exist in the source mapping")
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "mode": mode,
            "source_path_count": len(canonical_sources),
            "source_paths_sha256": _canonical_sha256(canonical_sources),
            "allowed_paths": canonical_allowed,
        }
        return cls.model_validate(_sealed_model_values(cls, values, hash_field="scope_sha256"))

    @field_validator("allowed_paths")
    @classmethod
    def allowed_paths_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("retrieval allowed paths must be unique and canonically ordered")
        for path in value:
            _validated_retrieval_path(path)
        return value

    @model_validator(mode="after")
    def scope_hash_is_exact(self) -> Self:
        if len(self.allowed_paths) > self.source_path_count:
            raise ValueError("retrieval scope contains more paths than its source inventory")
        if self.scope_sha256 != _model_sha256(self, hash_field="scope_sha256"):
            raise ValueError("retrieval scope hash is inconsistent")
        return self


class SolidityRetrievalSourceBinding(_FrozenRetrievalModel):
    """Content-free binding to exact original/redacted source inputs and line taint."""

    path: str = Field(min_length=1, max_length=4_096)
    original_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    redacted_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    original_utf8_bytes: int = Field(ge=0, le=_RETRIEVAL_MAX_SOURCE_BYTES)
    redacted_utf8_bytes: int = Field(ge=0, le=_RETRIEVAL_MAX_SOURCE_BYTES)
    line_count: int = Field(ge=0, le=2**31 - 1)
    secret_interval_count: int = Field(ge=0, le=2**31 - 1)
    secret_intervals_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("path")
    @classmethod
    def path_is_safe(cls, value: str) -> str:
        return _validated_retrieval_path(value)


class SolidityRetrievalSubjectAccess(_FrozenRetrievalModel):
    """Opaque indexed-subject access decision; no source or secret text is retained."""

    subject_id: str = Field(
        min_length=1,
        max_length=SOLIDITY_RETRIEVAL_SUBJECT_ID_MAX_LENGTH,
    )
    status: SolidityRetrievalAccessStatus

    @field_validator("subject_id")
    @classmethod
    def subject_id_is_safe(cls, value: str) -> str:
        return validated_solidity_retrieval_subject_id(value)


class SolidityRetrievalRelation(_FrozenRetrievalModel):
    """Metadata-free graph relation retained only for the two allowed listing operations."""

    graph: Literal[SolidityGraphKind.INTERNAL_CALL, SolidityGraphKind.STATE_WRITE]
    source_subject_id: str = Field(
        min_length=1,
        max_length=SOLIDITY_RETRIEVAL_SUBJECT_ID_MAX_LENGTH,
    )
    target_subject_id: str = Field(
        min_length=1,
        max_length=SOLIDITY_RETRIEVAL_SUBJECT_ID_MAX_LENGTH,
    )

    @field_validator("source_subject_id", "target_subject_id")
    @classmethod
    def subject_ids_are_safe(cls, value: str) -> str:
        return validated_solidity_retrieval_subject_id(value)


class SolidityRetrievalGraphAvailability(_FrozenRetrievalModel):
    """Exact completeness state for one supported relation graph."""

    graph: Literal[SolidityGraphKind.INTERNAL_CALL, SolidityGraphKind.STATE_WRITE]
    status: SolidityRetrievalGraphStatus
    omitted_edge_count: int = Field(ge=0, le=2**63 - 1)

    @model_validator(mode="after")
    def omission_count_matches_status(self) -> Self:
        if (self.status is SolidityRetrievalGraphStatus.PARTIAL) is not bool(
            self.omitted_edge_count
        ):
            raise ValueError("retrieval graph status differs from typed upstream omissions")
        return self


class SolidityRetrievalCorpus(_FrozenRetrievalModel):
    """Self-hashed safe corpus; original sources and secret match values are never stored."""

    schema_version: Literal["1.0"] = "1.0"
    scope: SolidityRetrievalScope
    source_bindings: tuple[SolidityRetrievalSourceBinding, ...] = Field(
        max_length=_RETRIEVAL_MAX_SOURCE_FILES
    )
    withheld_path_count: int = Field(ge=0, le=_RETRIEVAL_MAX_SOURCE_FILES)
    withheld_paths_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    symbol_index_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    symbol_index_entity_count: int = Field(ge=0, le=_RETRIEVAL_MAX_ENTITIES)
    graph_set_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    subject_access: tuple[SolidityRetrievalSubjectAccess, ...] = Field(
        max_length=_RETRIEVAL_MAX_ENTITIES
    )
    entities: tuple[SolidityRetrievalEntity, ...] = Field(max_length=_RETRIEVAL_MAX_ENTITIES)
    indexed_ranges: tuple[SolidityRetrievalRecord, ...] = Field(max_length=_RETRIEVAL_MAX_ENTITIES)
    relations: tuple[SolidityRetrievalRelation, ...] = Field(max_length=_RETRIEVAL_MAX_RELATIONS)
    graph_availability: tuple[SolidityRetrievalGraphAvailability, ...] = Field(
        min_length=2,
        max_length=2,
    )
    corpus_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(
        cls,
        *,
        original_sources: Mapping[str, str],
        redacted_sources: Mapping[str, str],
        secret_tainted_intervals: Sequence[SolidityRetrievalSecretInterval],
        index: SoliditySymbolIndex,
        graphs: SolidityGraphSet | None,
        allowed_paths: Sequence[str] | set[str] | frozenset[str] | None = None,
        withheld_paths: Sequence[str] | set[str] | frozenset[str] = (),
    ) -> Self:
        return cast(
            Self,
            _build_solidity_retrieval_corpus(
                original_sources=original_sources,
                redacted_sources=redacted_sources,
                secret_tainted_intervals=secret_tainted_intervals,
                index=index,
                graphs=graphs,
                allowed_paths=allowed_paths,
                withheld_paths=withheld_paths,
            ),
        )

    @model_validator(mode="after")
    def canonical_memberships_and_hash_are_exact(self) -> Self:
        source_paths = tuple(binding.path for binding in self.source_bindings)
        if source_paths != tuple(sorted(set(source_paths))):
            raise ValueError("retrieval source bindings must be unique and canonical")
        if self.scope.source_path_count != len(
            source_paths
        ) or self.scope.source_paths_sha256 != _canonical_sha256(source_paths):
            raise ValueError("retrieval scope differs from corpus source bindings")
        if self.withheld_path_count == 0 and self.withheld_paths_sha256 != _canonical_sha256(()):
            raise ValueError("empty withheld retrieval inventory has an inconsistent commitment")
        access_ids = tuple(item.subject_id for item in self.subject_access)
        entity_ids = tuple(item.subject_id for item in self.entities)
        range_ids = tuple(item.entity.subject_id for item in self.indexed_ranges)
        if access_ids != tuple(sorted(set(access_ids))):
            raise ValueError("retrieval subject access must be unique and canonical")
        if entity_ids != tuple(sorted(set(entity_ids))) or range_ids != tuple(
            sorted(set(range_ids))
        ):
            raise ValueError("retrieval safe entities and ranges must be unique and canonical")
        available_ids = tuple(
            item.subject_id
            for item in self.subject_access
            if item.status is SolidityRetrievalAccessStatus.AVAILABLE
        )
        if entity_ids != available_ids or range_ids != available_ids:
            raise ValueError("retrieval safe records differ from subject access decisions")
        entity_by_id = {entity.subject_id: entity for entity in self.entities}
        if any(
            record.entity != entity_by_id[record.entity.subject_id] or record.content is None
            for record in self.indexed_ranges
        ):
            raise ValueError("retrieval indexed ranges differ from safe entity projections")
        relation_keys = tuple(
            (item.graph.value, item.target_subject_id, item.source_subject_id)
            for item in self.relations
        )
        if relation_keys != tuple(sorted(set(relation_keys))):
            raise ValueError("retrieval relations must be unique and canonical")
        graph_keys = tuple(item.graph.value for item in self.graph_availability)
        expected_graph_keys = tuple(
            sorted(
                (
                    SolidityGraphKind.INTERNAL_CALL.value,
                    SolidityGraphKind.STATE_WRITE.value,
                )
            )
        )
        if graph_keys != expected_graph_keys:
            raise ValueError("retrieval graph availability must cover the fixed graph vocabulary")
        if self.symbol_index_entity_count != len(self.subject_access):
            raise ValueError("retrieval index count differs from its subject access inventory")
        if self.graph_set_sha256 is None and (
            self.relations
            or any(
                item.status is not SolidityRetrievalGraphStatus.UNAVAILABLE
                for item in self.graph_availability
            )
        ):
            raise ValueError("retrieval graph facts exist without a bound graph set")
        if self.corpus_sha256 != _model_sha256(self, hash_field="corpus_sha256"):
            raise ValueError("retrieval corpus hash is inconsistent")
        return self


def _validated_source_mapping(
    sources: Mapping[str, str],
    *,
    label: str,
) -> dict[str, str]:
    if len(sources) > _RETRIEVAL_MAX_SOURCE_FILES:
        raise ValueError(f"{label} exceeds the retrieval source-file cap")
    validated: dict[str, str] = {}
    total_bytes = 0
    for path, content in sources.items():
        if type(path) is not str or type(content) is not str:
            raise TypeError(f"{label} must map exact strings to exact strings")
        canonical_path = _validated_retrieval_path(path)
        if canonical_path in validated:
            raise ValueError(f"{label} contains duplicate normalized paths")
        total_bytes += len(content.encode("utf-8"))
        if total_bytes > _RETRIEVAL_MAX_SOURCE_BYTES:
            raise ValueError(f"{label} exceeds the retrieval source-byte cap")
        validated[canonical_path] = content
    return {path: validated[path] for path in sorted(validated)}


def _validated_secret_intervals(
    intervals: Sequence[SolidityRetrievalSecretInterval],
    *,
    sources: Mapping[str, str],
) -> tuple[SolidityRetrievalSecretInterval, ...]:
    validated: list[SolidityRetrievalSecretInterval] = []
    for interval in intervals:
        if not isinstance(interval, SolidityRetrievalSecretInterval):
            raise TypeError("secret-tainted ranges must be typed retrieval intervals")
        exact = SolidityRetrievalSecretInterval.model_validate(interval.model_dump(mode="python"))
        content = sources.get(exact.path)
        if content is None:
            raise ValueError("secret-tainted interval refers to an unknown source path")
        if exact.end_line > _source_line_count(content):
            raise ValueError("secret-tainted interval lies outside its exact source")
        validated.append(exact)
    return tuple(sorted(validated, key=lambda item: (item.path, item.start_line, item.end_line)))


def _entity_intersects_secret_interval(
    entity: SolidityEntity,
    intervals: Sequence[SolidityRetrievalSecretInterval],
) -> bool:
    return any(
        interval.path == entity.path
        and interval.start_line <= entity.end_line
        and entity.start_line <= interval.end_line
        for interval in intervals
    )


def _safe_entity_projection(entity: SolidityEntity) -> SolidityRetrievalEntity:
    return SolidityRetrievalEntity(
        subject_id=entity.id,
        kind=SolidityRetrievalEntityKind(entity.kind.value),
        name=entity.name,
        # A child range can be clean while its enclosing declaration is tainted.
        # Do not project the parent spelling across the retrieval boundary.
        contract_name=None,
        path=entity.path,
        start_line=entity.start_line,
        end_line=entity.end_line,
        source_hash=entity.source_hash,
        visibility=entity.visibility,
        mutability=entity.mutability,
        payable=entity.payable,
    )


def _retrieval_graph_availability(
    graphs: SolidityGraphSet | None,
    graph: Literal[SolidityGraphKind.INTERNAL_CALL, SolidityGraphKind.STATE_WRITE],
) -> SolidityRetrievalGraphAvailability:
    if graphs is None:
        return SolidityRetrievalGraphAvailability(
            graph=graph,
            status=SolidityRetrievalGraphStatus.UNAVAILABLE,
            omitted_edge_count=0,
        )
    omitted_count = sum(
        omission.omitted_count for omission in graphs.edge_omissions if omission.graph is graph
    )
    if omitted_count:
        status = SolidityRetrievalGraphStatus.PARTIAL
    elif graph in graphs.analyzed_graphs:
        status = SolidityRetrievalGraphStatus.COMPLETE
    else:
        status = SolidityRetrievalGraphStatus.UNAVAILABLE
    return SolidityRetrievalGraphAvailability(
        graph=graph,
        status=status,
        omitted_edge_count=omitted_count,
    )


def _validated_withheld_paths(
    paths: Sequence[str] | set[str] | frozenset[str],
    *,
    safe_source_paths: set[str],
) -> tuple[str, ...]:
    if len(paths) > _RETRIEVAL_MAX_SOURCE_FILES:
        raise ValueError("withheld retrieval paths exceed the source-file cap")
    canonical = tuple(sorted(_validated_retrieval_path(path) for path in paths))
    if len(canonical) != len(set(canonical)):
        raise ValueError("withheld retrieval paths must be unique")
    if set(canonical) & safe_source_paths:
        raise ValueError("withheld retrieval paths must be absent from safe source mappings")
    return canonical


def _build_solidity_retrieval_corpus(
    *,
    original_sources: Mapping[str, str],
    redacted_sources: Mapping[str, str],
    secret_tainted_intervals: Sequence[SolidityRetrievalSecretInterval],
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet | None,
    allowed_paths: Sequence[str] | set[str] | frozenset[str] | None,
    withheld_paths: Sequence[str] | set[str] | frozenset[str],
) -> SolidityRetrievalCorpus:
    originals = _validated_source_mapping(original_sources, label="original source mapping")
    redacted = _validated_source_mapping(redacted_sources, label="redacted source mapping")
    if originals.keys() != redacted.keys():
        raise ValueError("original and redacted retrieval source mappings must have exact paths")
    canonical_withheld_paths = _validated_withheld_paths(
        withheld_paths,
        safe_source_paths=set(originals),
    )
    withheld_path_set = set(canonical_withheld_paths)
    for path in originals:
        if _source_line_count(originals[path]) != _source_line_count(redacted[path]):
            raise ValueError("redaction must preserve exact source line boundaries")

    intervals = _validated_secret_intervals(
        secret_tainted_intervals,
        sources=originals,
    )
    intervals_by_path: dict[str, list[SolidityRetrievalSecretInterval]] = {
        path: [] for path in originals
    }
    for interval in intervals:
        intervals_by_path[interval.path].append(interval)

    scope = SolidityRetrievalScope.build(
        source_paths=tuple(originals),
        allowed_paths=allowed_paths,
    )
    allowed_path_set = set(scope.allowed_paths)
    source_bindings = tuple(
        SolidityRetrievalSourceBinding(
            path=path,
            original_sha256=hashlib.sha256(originals[path].encode("utf-8")).hexdigest(),
            redacted_sha256=hashlib.sha256(redacted[path].encode("utf-8")).hexdigest(),
            original_utf8_bytes=len(originals[path].encode("utf-8")),
            redacted_utf8_bytes=len(redacted[path].encode("utf-8")),
            line_count=_source_line_count(originals[path]),
            secret_interval_count=len(intervals_by_path[path]),
            secret_intervals_sha256=_canonical_sha256(
                tuple(interval.model_dump(mode="json") for interval in intervals_by_path[path])
            ),
        )
        for path in originals
    )

    if not isinstance(index, SoliditySymbolIndex):
        raise TypeError("retrieval corpus requires a typed Solidity symbol index")
    validated_index = SoliditySymbolIndex.model_validate(index.model_dump(mode="python"))
    if len(validated_index.entities) > _RETRIEVAL_MAX_ENTITIES:
        raise ValueError("Solidity symbol index exceeds the retrieval entity cap")
    entity_ids = tuple(entity.id for entity in validated_index.entities)
    if len(entity_ids) != len(set(entity_ids)):
        raise ValueError("Solidity retrieval entity IDs must be unique")

    access_records: list[SolidityRetrievalSubjectAccess] = []
    safe_entities: list[SolidityRetrievalEntity] = []
    safe_ranges: list[SolidityRetrievalRecord] = []
    for entity in sorted(validated_index.entities, key=lambda item: item.id):
        if entity.path in withheld_path_set:
            access_records.append(
                SolidityRetrievalSubjectAccess(
                    subject_id=entity.id,
                    status=SolidityRetrievalAccessStatus.REDACTED_OR_SECRET,
                )
            )
            continue
        original_content = originals.get(entity.path)
        redacted_content = redacted.get(entity.path)
        if original_content is None or redacted_content is None:
            raise ValueError("indexed entity path is absent from exact source mappings")
        original_range = _exact_source_range(
            original_content,
            entity.start_line,
            entity.end_line,
        )
        if hashlib.sha256(original_range.encode("utf-8")).hexdigest() != entity.source_hash:
            raise ValueError("indexed entity range hash differs from exact original source")
        redacted_range = _exact_source_range(
            redacted_content,
            entity.start_line,
            entity.end_line,
        )
        if _entity_intersects_secret_interval(entity, intervals_by_path[entity.path]) or (
            hashlib.sha256(redacted_range.encode("utf-8")).hexdigest() != entity.source_hash
        ):
            access_status = SolidityRetrievalAccessStatus.REDACTED_OR_SECRET
        elif entity.path not in allowed_path_set:
            access_status = SolidityRetrievalAccessStatus.OUT_OF_SCOPE
        else:
            access_status = SolidityRetrievalAccessStatus.AVAILABLE
        access_records.append(
            SolidityRetrievalSubjectAccess(subject_id=entity.id, status=access_status)
        )
        if access_status is not SolidityRetrievalAccessStatus.AVAILABLE:
            continue
        projection = _safe_entity_projection(entity)
        safe_entities.append(projection)
        safe_ranges.append(SolidityRetrievalRecord(entity=projection, content=redacted_range))

    validated_graphs: SolidityGraphSet | None
    if graphs is None:
        validated_graphs = None
    else:
        validated_graphs = SolidityGraphSet.model_validate(graphs.model_dump(mode="python"))
    supported_graphs = (SolidityGraphKind.INTERNAL_CALL, SolidityGraphKind.STATE_WRITE)
    relations = tuple(
        SolidityRetrievalRelation(
            graph=cast(
                Literal[SolidityGraphKind.INTERNAL_CALL, SolidityGraphKind.STATE_WRITE],
                edge.graph,
            ),
            source_subject_id=edge.source_id,
            target_subject_id=edge.target_id,
        )
        for edge in sorted(
            (
                edge
                for edge in (() if validated_graphs is None else validated_graphs.edges)
                if edge.graph in supported_graphs
            ),
            key=lambda item: (item.graph.value, item.target_id, item.source_id),
        )
    )
    canonical_relations = tuple(
        sorted(
            set(relations),
            key=lambda item: (item.graph.value, item.target_subject_id, item.source_subject_id),
        )
    )
    if len(canonical_relations) > _RETRIEVAL_MAX_RELATIONS:
        raise ValueError("Solidity graph set exceeds the retrieval relation cap")
    graph_availability = tuple(
        sorted(
            (
                _retrieval_graph_availability(validated_graphs, SolidityGraphKind.INTERNAL_CALL),
                _retrieval_graph_availability(validated_graphs, SolidityGraphKind.STATE_WRITE),
            ),
            key=lambda item: item.graph.value,
        )
    )
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "scope": scope,
        "source_bindings": source_bindings,
        "withheld_path_count": len(canonical_withheld_paths),
        "withheld_paths_sha256": _canonical_sha256(canonical_withheld_paths),
        "symbol_index_sha256": _canonical_sha256(validated_index.model_dump(mode="json")),
        "symbol_index_entity_count": len(validated_index.entities),
        "graph_set_sha256": (
            None
            if validated_graphs is None
            else _canonical_sha256(validated_graphs.model_dump(mode="json"))
        ),
        "subject_access": tuple(access_records),
        "entities": tuple(safe_entities),
        "indexed_ranges": tuple(safe_ranges),
        "relations": canonical_relations,
        "graph_availability": graph_availability,
    }
    return SolidityRetrievalCorpus.model_validate(
        _sealed_model_values(SolidityRetrievalCorpus, values, hash_field="corpus_sha256")
    )


def build_solidity_retrieval_corpus(
    *,
    original_sources: Mapping[str, str],
    redacted_sources: Mapping[str, str],
    secret_tainted_intervals: Sequence[SolidityRetrievalSecretInterval],
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet | None,
    allowed_paths: Sequence[str] | set[str] | frozenset[str] | None = None,
    withheld_paths: Sequence[str] | set[str] | frozenset[str] = (),
) -> SolidityRetrievalCorpus:
    """Build a deterministic safe corpus without retaining original source mappings."""

    return _build_solidity_retrieval_corpus(
        original_sources=original_sources,
        redacted_sources=redacted_sources,
        secret_tainted_intervals=secret_tainted_intervals,
        index=index,
        graphs=graphs,
        allowed_paths=allowed_paths,
        withheld_paths=withheld_paths,
    )


def start_solidity_retrieval_transcript(
    *,
    corpus: SolidityRetrievalCorpus,
    policy: SolidityRetrievalRolePolicy,
) -> SolidityRetrievalTranscript:
    """Start an empty transcript bound to one exact safe corpus and role policy."""

    validated_corpus = SolidityRetrievalCorpus.model_validate(corpus.model_dump(mode="python"))
    validated_policy = SolidityRetrievalRolePolicy.model_validate(policy.model_dump(mode="python"))
    return SolidityRetrievalTranscript.build(
        role=validated_policy.role,
        policy_sha256=validated_policy.policy_sha256,
        corpus_sha256=validated_corpus.corpus_sha256,
    )


def _omissions_from_counts(
    counts: Mapping[SolidityRetrievalReason, int],
) -> tuple[SolidityRetrievalOmission, ...]:
    return tuple(
        SolidityRetrievalOmission(reason=reason, count=count)
        for reason, count in sorted(counts.items(), key=lambda item: item[0].value)
        if count
    )


def _subject_refusal_reason(
    corpus: SolidityRetrievalCorpus,
    subject_id: str,
) -> SolidityRetrievalReason | None:
    access = next(
        (item.status for item in corpus.subject_access if item.subject_id == subject_id),
        None,
    )
    if access is None:
        return SolidityRetrievalReason.UNINDEXED_SUBJECT
    if access is SolidityRetrievalAccessStatus.REDACTED_OR_SECRET:
        return SolidityRetrievalReason.REDACTED_OR_SECRET_SUBJECT
    if access is SolidityRetrievalAccessStatus.OUT_OF_SCOPE:
        return SolidityRetrievalReason.OUT_OF_SCOPE_SUBJECT
    return None


def _related_omission_reason(
    access: SolidityRetrievalAccessStatus | None,
) -> SolidityRetrievalReason:
    if access is None:
        return SolidityRetrievalReason.RELATED_UNINDEXED
    if access is SolidityRetrievalAccessStatus.REDACTED_OR_SECRET:
        return SolidityRetrievalReason.RELATED_REDACTED_OR_SECRET
    if access is SolidityRetrievalAccessStatus.OUT_OF_SCOPE:
        return SolidityRetrievalReason.RELATED_OUT_OF_SCOPE
    raise ValueError("available related subject cannot be classified as omitted")


def _graph_for_operation(
    operation: SolidityRetrievalOperation,
) -> Literal[SolidityGraphKind.INTERNAL_CALL, SolidityGraphKind.STATE_WRITE]:
    if operation is SolidityRetrievalOperation.LIST_CALLERS:
        return SolidityGraphKind.INTERNAL_CALL
    if operation is SolidityRetrievalOperation.LIST_STATE_WRITERS:
        return SolidityGraphKind.STATE_WRITE
    raise ValueError("non-graph retrieval operation has no graph kind")


def _candidate_records_and_omissions(
    *,
    corpus: SolidityRetrievalCorpus,
    request: SolidityRetrievalRequest,
) -> tuple[
    SolidityRetrievalStatus,
    tuple[SolidityRetrievalRecord, ...],
    tuple[SolidityRetrievalOmission, ...],
]:
    refusal_reason = _subject_refusal_reason(corpus, request.subject_id)
    if refusal_reason is not None:
        return (
            SolidityRetrievalStatus.REFUSED,
            (),
            (SolidityRetrievalOmission(reason=refusal_reason, count=1),),
        )

    entities = {entity.subject_id: entity for entity in corpus.entities}
    ranges = {record.entity.subject_id: record for record in corpus.indexed_ranges}
    if request.operation is SolidityRetrievalOperation.RESOLVE_ENTITY:
        return (
            SolidityRetrievalStatus.COMPLETE,
            (SolidityRetrievalRecord(entity=entities[request.subject_id]),),
            (),
        )
    if request.operation is SolidityRetrievalOperation.FETCH_INDEXED_RANGE:
        return (SolidityRetrievalStatus.COMPLETE, (ranges[request.subject_id],), ())

    graph = _graph_for_operation(request.operation)
    graph_state = next(item for item in corpus.graph_availability if item.graph is graph)
    if graph_state.status is SolidityRetrievalGraphStatus.UNAVAILABLE:
        return (
            SolidityRetrievalStatus.UNAVAILABLE,
            (),
            (
                SolidityRetrievalOmission(
                    reason=SolidityRetrievalReason.GRAPH_UNAVAILABLE,
                    count=1,
                ),
            ),
        )

    related_ids = tuple(
        sorted(
            {
                relation.source_subject_id
                for relation in corpus.relations
                if relation.graph is graph and relation.target_subject_id == request.subject_id
            }
        )
    )
    access_by_id = {item.subject_id: item.status for item in corpus.subject_access}
    records: list[SolidityRetrievalRecord] = []
    omission_counts: Counter[SolidityRetrievalReason] = Counter()
    for related_id in related_ids:
        access = access_by_id.get(related_id)
        if access is not SolidityRetrievalAccessStatus.AVAILABLE:
            omission_counts[_related_omission_reason(access)] += 1
            continue
        entity = entities.get(related_id)
        if entity is None:
            omission_counts[SolidityRetrievalReason.RELATED_UNINDEXED] += 1
            continue
        records.append(SolidityRetrievalRecord(entity=entity))
    if graph_state.status is SolidityRetrievalGraphStatus.PARTIAL:
        omission_counts[SolidityRetrievalReason.UPSTREAM_GRAPH_OMISSION] += (
            graph_state.omitted_edge_count
        )
    omissions = _omissions_from_counts(omission_counts)
    status = SolidityRetrievalStatus.PARTIAL if omissions else SolidityRetrievalStatus.COMPLETE
    return (status, tuple(records), omissions)


def _bounded_retrieval_result(
    *,
    request: SolidityRetrievalRequest,
    status: SolidityRetrievalStatus,
    candidate_records: Sequence[SolidityRetrievalRecord],
    omissions: Sequence[SolidityRetrievalOmission],
    transcript: SolidityRetrievalTranscript,
    policy: SolidityRetrievalRolePolicy,
) -> SolidityRetrievalResult:
    if status not in {SolidityRetrievalStatus.COMPLETE, SolidityRetrievalStatus.PARTIAL}:
        return SolidityRetrievalResult.build(
            request=request,
            status=status,
            omissions=omissions,
        )

    selected: list[SolidityRetrievalRecord] = []
    selected_bytes = 0
    limit_reason: SolidityRetrievalReason | None = None
    for record in candidate_records:
        if len(selected) >= policy.maximum_results_per_request:
            limit_reason = SolidityRetrievalReason.RESULT_ITEM_LIMIT
            break
        record_bytes = solidity_retrieval_records_utf8_bytes((record,))
        proposed_bytes = selected_bytes + record_bytes
        proposed_tokens = (
            proposed_bytes + UTF8_BYTES_PER_ESTIMATED_TOKEN - 1
        ) // UTF8_BYTES_PER_ESTIMATED_TOKEN
        if proposed_bytes > policy.maximum_result_utf8_bytes:
            limit_reason = SolidityRetrievalReason.RESULT_UTF8_LIMIT
            break
        if (
            transcript.total_result_utf8_bytes + proposed_bytes
            > policy.maximum_total_result_utf8_bytes
        ):
            limit_reason = SolidityRetrievalReason.TOTAL_RESULT_UTF8_BUDGET
            break
        if (
            transcript.total_estimated_result_tokens + proposed_tokens
            > policy.maximum_total_result_tokens
        ):
            limit_reason = SolidityRetrievalReason.TOTAL_RESULT_TOKEN_BUDGET
            break
        selected.append(record)
        selected_bytes = proposed_bytes

    omission_counts: Counter[SolidityRetrievalReason] = Counter(
        {omission.reason: omission.count for omission in omissions}
    )
    if limit_reason is not None:
        omission_counts[limit_reason] += len(candidate_records) - len(selected)
    bounded_omissions = _omissions_from_counts(omission_counts)
    if candidate_records and not selected:
        bounded_status = SolidityRetrievalStatus.EXHAUSTED
    elif len(selected) < len(candidate_records) or bounded_omissions:
        bounded_status = SolidityRetrievalStatus.PARTIAL
    else:
        bounded_status = status
    return SolidityRetrievalResult.build(
        request=request,
        status=bounded_status,
        records=selected,
        omissions=bounded_omissions,
    )


def _transcript_envelope_exhaustion_reason(
    transcript: SolidityRetrievalTranscript,
    policy: SolidityRetrievalRolePolicy,
) -> SolidityRetrievalReason | None:
    transcript_utf8_bytes = solidity_retrieval_transcript_utf8_bytes(transcript)
    if transcript_utf8_bytes > policy.maximum_transcript_utf8_bytes:
        return SolidityRetrievalReason.TRANSCRIPT_UTF8_BUDGET
    transcript_tokens = (
        transcript_utf8_bytes + UTF8_BYTES_PER_ESTIMATED_TOKEN - 1
    ) // UTF8_BYTES_PER_ESTIMATED_TOKEN
    if transcript_tokens > policy.maximum_transcript_tokens:
        return SolidityRetrievalReason.TRANSCRIPT_TOKEN_BUDGET
    return None


def _append_retrieval_exchange(
    *,
    transcript: SolidityRetrievalTranscript,
    request: SolidityRetrievalRequest,
    result: SolidityRetrievalResult,
    accepted_request: bool,
) -> SolidityRetrievalTranscript:
    previous_exchange_sha256 = (
        None if not transcript.exchanges else transcript.exchanges[-1].exchange_sha256
    )
    exchange = SolidityRetrievalExchange.build(
        sequence=len(transcript.exchanges) + 1,
        previous_exchange_sha256=previous_exchange_sha256,
        request=request,
        result=result,
    )
    return SolidityRetrievalTranscript.build(
        role=transcript.role,
        policy_sha256=transcript.policy_sha256,
        corpus_sha256=transcript.corpus_sha256,
        exchanges=(*transcript.exchanges, exchange),
        accepted_request_count=transcript.accepted_request_count + int(accepted_request),
    )


def execute_solidity_retrieval(
    *,
    corpus: SolidityRetrievalCorpus,
    policy: SolidityRetrievalRolePolicy,
    transcript: SolidityRetrievalTranscript,
    request: SolidityRetrievalRequest,
) -> SolidityRetrievalTranscript:
    """Execute one pure lookup and append its result, never raising for budget exhaustion."""

    validated_corpus = SolidityRetrievalCorpus.model_validate(corpus.model_dump(mode="python"))
    validated_policy = SolidityRetrievalRolePolicy.model_validate(policy.model_dump(mode="python"))
    validated_transcript = SolidityRetrievalTranscript.model_validate(
        transcript.model_dump(mode="python")
    )
    validated_request = SolidityRetrievalRequest.model_validate(request.model_dump(mode="python"))
    if (
        validated_transcript.role != validated_policy.role
        or validated_transcript.policy_sha256 != validated_policy.policy_sha256
        or validated_transcript.corpus_sha256 != validated_corpus.corpus_sha256
    ):
        raise ValueError("retrieval transcript is bound to a different corpus or role policy")
    if len(validated_transcript.exchanges) >= SOLIDITY_RETRIEVAL_MAX_EXCHANGES:
        raise ValueError("retrieval transcript reached the hard wire-batch exchange cap")

    accepted_request = True
    if validated_transcript.retrieval_exhausted:
        accepted_request = False
        result = SolidityRetrievalResult.build(
            request=validated_request,
            status=SolidityRetrievalStatus.EXHAUSTED,
            omissions=(
                SolidityRetrievalOmission(
                    reason=SolidityRetrievalReason.RETRIEVAL_ALREADY_EXHAUSTED,
                    count=1,
                ),
            ),
        )
    elif validated_transcript.accepted_request_count >= validated_policy.maximum_requests:
        accepted_request = False
        result = SolidityRetrievalResult.build(
            request=validated_request,
            status=SolidityRetrievalStatus.EXHAUSTED,
            omissions=(
                SolidityRetrievalOmission(
                    reason=SolidityRetrievalReason.REQUEST_COUNT_BUDGET,
                    count=1,
                ),
            ),
        )
    else:
        status, candidate_records, omissions = _candidate_records_and_omissions(
            corpus=validated_corpus,
            request=validated_request,
        )
        result = _bounded_retrieval_result(
            request=validated_request,
            status=status,
            candidate_records=candidate_records,
            omissions=omissions,
            transcript=validated_transcript,
            policy=validated_policy,
        )

    candidate = _append_retrieval_exchange(
        transcript=validated_transcript,
        request=validated_request,
        result=result,
        accepted_request=accepted_request,
    )
    envelope_reason = _transcript_envelope_exhaustion_reason(candidate, validated_policy)
    if envelope_reason is None:
        return candidate
    if result.status is SolidityRetrievalStatus.EXHAUSTED:
        raise ValueError("fixed retrieval transcript envelope cannot record terminal exhaustion")
    exhausted_result = SolidityRetrievalResult.build(
        request=validated_request,
        status=SolidityRetrievalStatus.EXHAUSTED,
        omissions=(SolidityRetrievalOmission(reason=envelope_reason, count=1),),
    )
    exhausted = _append_retrieval_exchange(
        transcript=validated_transcript,
        request=validated_request,
        result=exhausted_result,
        accepted_request=accepted_request,
    )
    if _transcript_envelope_exhaustion_reason(exhausted, validated_policy) is not None:
        raise ValueError("fixed retrieval transcript envelope cannot record typed exhaustion")
    return exhausted


def execute_solidity_retrieval_batch(
    *,
    corpus: SolidityRetrievalCorpus,
    policy: SolidityRetrievalRolePolicy,
    transcript: SolidityRetrievalTranscript,
    batch: SolidityRetrievalRequestBatch,
) -> SolidityRetrievalTranscript:
    """Host-hash and record every intent in one validated zero-to-eight wire batch."""

    validated_batch = SolidityRetrievalRequestBatch.model_validate(batch.model_dump(mode="python"))
    validated_transcript = SolidityRetrievalTranscript.model_validate(
        transcript.model_dump(mode="python")
    )
    if (
        len(validated_transcript.exchanges) + len(validated_batch.requests)
        > SOLIDITY_RETRIEVAL_MAX_EXCHANGES
    ):
        raise ValueError("retrieval wire batch exceeds the remaining transcript exchange cap")
    current = validated_transcript
    for request in validated_batch.to_host_requests():
        current = execute_solidity_retrieval(
            corpus=corpus,
            policy=policy,
            transcript=current,
            request=request,
        )
    if not validated_batch.requests:
        expected = start_solidity_retrieval_transcript(corpus=corpus, policy=policy)
        if (
            current.role != expected.role
            or current.policy_sha256 != expected.policy_sha256
            or current.corpus_sha256 != expected.corpus_sha256
        ):
            raise ValueError("retrieval transcript is bound to a different corpus or role policy")
    return current


def validate_solidity_retrieval_replay(
    *,
    corpus: SolidityRetrievalCorpus,
    policy: SolidityRetrievalRolePolicy,
    transcript: SolidityRetrievalTranscript,
    expected_transcript_sha256: str | None = None,
) -> SolidityRetrievalTranscript:
    """Re-execute every lookup and reject hash, chain, binding, or semantic tampering."""

    validated_corpus = SolidityRetrievalCorpus.model_validate(corpus.model_dump(mode="python"))
    validated_policy = SolidityRetrievalRolePolicy.model_validate(policy.model_dump(mode="python"))
    validated_transcript = SolidityRetrievalTranscript.model_validate(
        transcript.model_dump(mode="python")
    )
    if (
        expected_transcript_sha256 is not None
        and validated_transcript.transcript_sha256 != expected_transcript_sha256
    ):
        raise ValueError("retrieval transcript differs from its external replay commitment")
    replayed = start_solidity_retrieval_transcript(
        corpus=validated_corpus,
        policy=validated_policy,
    )
    for expected_exchange in validated_transcript.exchanges:
        prior_count = len(replayed.exchanges)
        replayed = execute_solidity_retrieval(
            corpus=validated_corpus,
            policy=validated_policy,
            transcript=replayed,
            request=expected_exchange.request,
        )
        if len(replayed.exchanges) != prior_count + 1:
            raise ValueError("retrieval transcript contains exchanges after terminal exhaustion")
        if replayed.exchanges[-1] != expected_exchange:
            raise ValueError("retrieval replay differs from the recorded exchange")
    if replayed != validated_transcript:
        raise ValueError("retrieval replay differs from the recorded transcript")
    return replayed
