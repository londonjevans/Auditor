"""Typed evidence for deterministic Solidity semantic shard inventories."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Literal, Self, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

from mmaudit.models.schemas import (
    SolidityEntityKind,
    SolidityGraphKind,
    SolidityGraphSet,
    SoliditySymbolIndex,
    StrictModel,
)
from mmaudit.repository.ignore import normalize_relative_path

SHARD_ALGORITHM_VERSION = "mmaudit.solidity-file-shards.v1"
_RESOURCE_ID_MAX_LENGTH = 4_096


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _model_sha256(model: StrictModel, *, exclude: set[str]) -> str:
    return _canonical_sha256(model.model_dump(mode="json", exclude=exclude))


def _validated_solidity_source_path(value: str, *, label: str) -> str:
    try:
        normalized = normalize_relative_path(value)
    except ValueError as exc:
        raise ValueError(f"{label} is unsafe") from exc
    if normalized != value:
        raise ValueError(f"{label} must be normalized")
    if PurePosixPath(value).suffix.lower() != ".sol":
        raise ValueError(f"{label} must identify a Solidity source")
    return value


def solidity_shard_semantic_dependency_sha256(
    *,
    fact_bindings: Iterable[tuple[SolidityShardOverlapKind, str, str]],
    boundary_sha256s: Iterable[str],
) -> str:
    """Bind a shard hash to all retained facts and its boundary records."""

    return _canonical_sha256(
        {
            "fact_bindings": [
                {
                    "kind": kind.value,
                    "resource_id": resource_id,
                    "record_sha256": record_sha256,
                }
                for kind, resource_id, record_sha256 in sorted(
                    fact_bindings,
                    key=lambda item: (item[0].value, item[1], item[2]),
                )
            ],
            "boundary_sha256s": sorted(boundary_sha256s),
        }
    )


class SolidityShardRiskSurface(StrEnum):
    """Closed deterministic risk taxonomy projected from existing graph facts."""

    CONTRACTS = "contracts"
    CALL_FLOW = "call_flow"
    STATE_ACCOUNTING = "state_accounting"
    INHERITANCE_UPGRADE = "inheritance_upgrade"
    ASSET_FLOW = "asset_flow"
    AUTHORITY_GOVERNANCE = "authority_governance"
    ORACLE_DEPENDENCY = "oracle_dependency"
    INITIALIZATION = "initialization"
    CROSS_CHAIN_MESSAGING = "cross_chain_messaging"
    SIGNATURE_REPLAY = "signature_replay"
    REENTRANCY = "reentrancy"
    EXTERNAL_DEPENDENCY = "external_dependency"


_RISK_CALL_GRAPHS = {
    SolidityGraphKind.INTERNAL_CALL,
    SolidityGraphKind.EXTERNAL_CALL,
    SolidityGraphKind.LOW_LEVEL_CALL,
    SolidityGraphKind.DELEGATECALL,
    SolidityGraphKind.CONTRACT_CREATION,
}
_RISK_STATE_GRAPHS = {
    SolidityGraphKind.STATE_READ,
    SolidityGraphKind.STATE_WRITE,
    SolidityGraphKind.STATE_DEPENDENCY,
    SolidityGraphKind.STATE_GROWTH,
    SolidityGraphKind.STORAGE_LAYOUT,
    SolidityGraphKind.UPGRADE_COMPATIBILITY,
    SolidityGraphKind.ASSET_FLOW,
    SolidityGraphKind.EVENT_STATE,
}
_RISK_UPGRADE_GRAPHS = {
    SolidityGraphKind.INHERITANCE,
    SolidityGraphKind.PROXY,
    SolidityGraphKind.DELEGATECALL,
    SolidityGraphKind.STORAGE_LAYOUT,
    SolidityGraphKind.UPGRADE_COMPATIBILITY,
}
_RISK_AUTHORITY_GRAPHS = {
    SolidityGraphKind.MODIFIER,
    SolidityGraphKind.PRIVILEGE,
    SolidityGraphKind.GOVERNANCE,
    SolidityGraphKind.SENSITIVE_REACHABILITY,
}
_RISK_INITIALIZATION_GRAPHS = {
    SolidityGraphKind.INITIALIZER,
    SolidityGraphKind.CONTRACT_CREATION,
}
_RISK_CROSS_CHAIN_GRAPHS = {
    SolidityGraphKind.CROSS_CHAIN,
    SolidityGraphKind.EVENT_FLOW,
    SolidityGraphKind.EVENT_STATE,
    SolidityGraphKind.OFFCHAIN_DEPENDENCY,
}
_RISK_EXTERNAL_GRAPHS = {
    SolidityGraphKind.EXTERNAL_CALL,
    SolidityGraphKind.LOW_LEVEL_CALL,
    SolidityGraphKind.DELEGATECALL,
    SolidityGraphKind.DEPENDENCY,
    SolidityGraphKind.ORACLE_DEPENDENCY,
    SolidityGraphKind.OFFCHAIN_DEPENDENCY,
}


def solidity_shard_risk_surfaces(
    graph_kinds: set[SolidityGraphKind],
    *,
    entity_kinds: set[SolidityEntityKind],
    has_storage: bool,
) -> set[SolidityShardRiskSurface]:
    """Derive the exact closed shard risk set from retained deterministic facts."""

    risks = {SolidityShardRiskSurface.CONTRACTS}
    if graph_kinds & _RISK_CALL_GRAPHS:
        risks.add(SolidityShardRiskSurface.CALL_FLOW)
    if graph_kinds & _RISK_STATE_GRAPHS or has_storage:
        risks.add(SolidityShardRiskSurface.STATE_ACCOUNTING)
    if graph_kinds & _RISK_UPGRADE_GRAPHS or has_storage:
        risks.add(SolidityShardRiskSurface.INHERITANCE_UPGRADE)
    if SolidityGraphKind.ASSET_FLOW in graph_kinds:
        risks.add(SolidityShardRiskSurface.ASSET_FLOW)
    if graph_kinds & _RISK_AUTHORITY_GRAPHS:
        risks.add(SolidityShardRiskSurface.AUTHORITY_GOVERNANCE)
    if SolidityGraphKind.ORACLE_DEPENDENCY in graph_kinds:
        risks.add(SolidityShardRiskSurface.ORACLE_DEPENDENCY)
    if graph_kinds & _RISK_INITIALIZATION_GRAPHS or SolidityEntityKind.CONSTRUCTOR in entity_kinds:
        risks.add(SolidityShardRiskSurface.INITIALIZATION)
    if graph_kinds & _RISK_CROSS_CHAIN_GRAPHS:
        risks.add(SolidityShardRiskSurface.CROSS_CHAIN_MESSAGING)
    if SolidityGraphKind.SIGNATURE_REPLAY in graph_kinds:
        risks.add(SolidityShardRiskSurface.SIGNATURE_REPLAY)
    if SolidityGraphKind.REENTRANCY in graph_kinds:
        risks.add(SolidityShardRiskSurface.REENTRANCY)
    if graph_kinds & _RISK_EXTERNAL_GRAPHS:
        risks.add(SolidityShardRiskSurface.EXTERNAL_DEPENDENCY)
    return risks


if set(SolidityGraphKind) != (
    _RISK_CALL_GRAPHS
    | _RISK_STATE_GRAPHS
    | _RISK_UPGRADE_GRAPHS
    | _RISK_AUTHORITY_GRAPHS
    | _RISK_INITIALIZATION_GRAPHS
    | _RISK_CROSS_CHAIN_GRAPHS
    | _RISK_EXTERNAL_GRAPHS
    | {
        SolidityGraphKind.ASSET_FLOW,
        SolidityGraphKind.ORACLE_DEPENDENCY,
        SolidityGraphKind.SIGNATURE_REPLAY,
        SolidityGraphKind.REENTRANCY,
    }
):
    raise RuntimeError("Solidity shard risk mapping is incomplete")


class SolidityShardOverlapKind(StrEnum):
    ENTITY = "entity"
    GRAPH_NODE = "graph_node"
    GRAPH_EDGE = "graph_edge"
    STORAGE_ENTRY = "storage_entry"


class SolidityShardOverlapReason(StrEnum):
    GRAPH_BOUNDARY = "graph_boundary"
    SHARED_GRAPH_NODE = "shared_graph_node"


class SolidityShardPolicy(StrictModel):
    """Fixed-cap, self-hashed policy used to construct a shard inventory."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    algorithm_version: Literal["mmaudit.solidity-file-shards.v1"] = (
        "mmaudit.solidity-file-shards.v1"
    )
    max_shards: int = Field(default=10_000, ge=1, le=100_000)
    max_source_bytes_per_shard: int = Field(default=250_000, ge=4, le=10_000_000)
    max_primary_entities_per_shard: int = Field(default=20_000, ge=1, le=100_000)
    max_primary_graph_nodes_per_shard: int = Field(default=50_000, ge=1, le=250_000)
    max_primary_graph_edges_per_shard: int = Field(default=100_000, ge=1, le=500_000)
    max_primary_storage_entries_per_shard: int = Field(default=20_000, ge=1, le=100_000)
    max_overlap_entities_per_shard: int = Field(default=20_000, ge=1, le=100_000)
    max_overlap_graph_nodes_per_shard: int = Field(default=50_000, ge=1, le=250_000)
    max_overlap_graph_edges_per_shard: int = Field(default=100_000, ge=1, le=500_000)
    max_overlap_storage_entries_per_shard: int = Field(default=20_000, ge=1, le=100_000)
    max_boundaries_per_shard: int = Field(default=100_000, ge=1, le=500_000)
    max_total_semantic_memberships_per_shard: int = Field(
        default=250_000,
        ge=1,
        le=1_000_000,
    )
    max_total_overlap_records: int = Field(default=2_000_000, ge=1, le=5_000_000)
    max_total_boundaries: int = Field(default=500_000, ge=1, le=1_000_000)
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(cls, **updates: int) -> SolidityShardPolicy:
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "algorithm_version": "mmaudit.solidity-file-shards.v1",
            "max_shards": 10_000,
            "max_source_bytes_per_shard": 250_000,
            "max_primary_entities_per_shard": 20_000,
            "max_primary_graph_nodes_per_shard": 50_000,
            "max_primary_graph_edges_per_shard": 100_000,
            "max_primary_storage_entries_per_shard": 20_000,
            "max_overlap_entities_per_shard": 20_000,
            "max_overlap_graph_nodes_per_shard": 50_000,
            "max_overlap_graph_edges_per_shard": 100_000,
            "max_overlap_storage_entries_per_shard": 20_000,
            "max_boundaries_per_shard": 100_000,
            "max_total_semantic_memberships_per_shard": 250_000,
            "max_total_overlap_records": 2_000_000,
            "max_total_boundaries": 500_000,
        }
        values.update(updates)
        return cls(**values, policy_sha256=_canonical_sha256(values))

    @model_validator(mode="after")
    def policy_hash_is_exact(self) -> Self:
        if self.policy_sha256 != _model_sha256(self, exclude={"policy_sha256"}):
            raise ValueError("Solidity shard policy hash does not match its typed fields")
        return self


class SolidityShardSourceUnit(StrictModel):
    """One exact Solidity source file, primary-owned by exactly one shard."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_unit_id: str = Field(pattern=r"^source-[0-9a-f]{24}$")
    path: str = Field(min_length=1, max_length=4_096)
    utf8_bytes: int = Field(ge=0)
    line_count: int = Field(ge=0)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    primary_shard_id: str = Field(pattern=r"^shard-[0-9a-f]{24}$")
    unit_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("path")
    @classmethod
    def path_is_normalized_relative(cls, value: str) -> str:
        return _validated_solidity_source_path(value, label="Solidity shard source path")

    @classmethod
    def build(
        cls,
        *,
        path: str,
        utf8_bytes: int,
        line_count: int,
        content_sha256: str,
        primary_shard_id: str,
    ) -> SolidityShardSourceUnit:
        source_unit_id = "source-" + _canonical_sha256({"path": path})[:24]
        values = {
            "source_unit_id": source_unit_id,
            "path": path,
            "utf8_bytes": utf8_bytes,
            "line_count": line_count,
            "content_sha256": content_sha256,
            "primary_shard_id": primary_shard_id,
        }
        return cls(**values, unit_sha256=_canonical_sha256(values))

    @model_validator(mode="after")
    def identity_and_hash_are_exact(self) -> Self:
        expected_id = "source-" + _canonical_sha256({"path": self.path})[:24]
        if self.source_unit_id != expected_id:
            raise ValueError("Solidity source-unit ID is not derived from its path")
        if self.unit_sha256 != _model_sha256(self, exclude={"unit_sha256"}):
            raise ValueError("Solidity source-unit hash does not match its typed fields")
        return self


class SolidityShardEntityFact(StrictModel):
    """Hash-only source-index fact sufficient to validate shard ownership."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: str = Field(min_length=1, max_length=_RESOURCE_ID_MAX_LENGTH)
    source_unit_id: str = Field(pattern=r"^source-[0-9a-f]{24}$")
    primary_shard_id: str = Field(pattern=r"^shard-[0-9a-f]{24}$")
    entity_kind: SolidityEntityKind
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SolidityShardGraphNodeFact(StrictModel):
    """Hash-only graph-node fact with explicit source-ownership classification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: str = Field(min_length=1, max_length=_RESOURCE_ID_MAX_LENGTH)
    source_unit_id: str = Field(pattern=r"^source-[0-9a-f]{24}$")
    primary_shard_id: str = Field(pattern=r"^shard-[0-9a-f]{24}$")
    source_owned: bool
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SolidityShardGraphEdgeFact(StrictModel):
    """Hash-only edge projection that makes boundaries and risk derivable."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: str = Field(pattern=r"^edge-[0-9a-f]{32}$")
    source_unit_id: str = Field(pattern=r"^source-[0-9a-f]{24}$")
    primary_shard_id: str = Field(pattern=r"^shard-[0-9a-f]{24}$")
    graph_kind: SolidityGraphKind
    source_node_id: str = Field(min_length=1, max_length=_RESOURCE_ID_MAX_LENGTH)
    target_node_id: str = Field(min_length=1, max_length=_RESOURCE_ID_MAX_LENGTH)
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def edge_id_is_record_hash_prefix(self) -> Self:
        if self.resource_id != "edge-" + self.record_sha256[:32]:
            raise ValueError("Solidity shard graph-edge ID must derive from its record hash")
        return self


class SolidityShardStorageFact(StrictModel):
    """Hash-only storage-layout fact sufficient to validate shard ownership."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: str = Field(min_length=1, max_length=_RESOURCE_ID_MAX_LENGTH)
    source_unit_id: str = Field(pattern=r"^source-[0-9a-f]{24}$")
    primary_shard_id: str = Field(pattern=r"^shard-[0-9a-f]{24}$")
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SolidityShardBoundary(StrictModel):
    """One entity-backed graph edge crossing two primary source shards."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    boundary_id: str = Field(pattern=r"^boundary-[0-9a-f]{24}$")
    graph_edge_id: str = Field(pattern=r"^edge-[0-9a-f]{32}$")
    graph_kind: SolidityGraphKind
    source_node_id: str = Field(min_length=1, max_length=_RESOURCE_ID_MAX_LENGTH)
    target_node_id: str = Field(min_length=1, max_length=_RESOURCE_ID_MAX_LENGTH)
    source_shard_id: str = Field(pattern=r"^shard-[0-9a-f]{24}$")
    target_shard_id: str = Field(pattern=r"^shard-[0-9a-f]{24}$")
    boundary_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(
        cls,
        *,
        graph_edge_id: str,
        graph_kind: SolidityGraphKind,
        source_node_id: str,
        target_node_id: str,
        source_shard_id: str,
        target_shard_id: str,
    ) -> SolidityShardBoundary:
        anchor = {
            "graph_edge_id": graph_edge_id,
            "source_shard_id": source_shard_id,
            "target_shard_id": target_shard_id,
        }
        values = {
            "boundary_id": "boundary-" + _canonical_sha256(anchor)[:24],
            "graph_edge_id": graph_edge_id,
            "graph_kind": graph_kind,
            "source_node_id": source_node_id,
            "target_node_id": target_node_id,
            "source_shard_id": source_shard_id,
            "target_shard_id": target_shard_id,
        }
        return cls(**values, boundary_sha256=_canonical_sha256(_json_values(values)))

    @model_validator(mode="after")
    def boundary_is_canonical_and_hashed(self) -> Self:
        if self.source_shard_id == self.target_shard_id:
            raise ValueError("Solidity shard boundary must cross distinct shards")
        anchor = {
            "graph_edge_id": self.graph_edge_id,
            "source_shard_id": self.source_shard_id,
            "target_shard_id": self.target_shard_id,
        }
        if self.boundary_id != "boundary-" + _canonical_sha256(anchor)[:24]:
            raise ValueError("Solidity shard boundary ID is not derived from its edge and shards")
        if self.boundary_sha256 != _model_sha256(self, exclude={"boundary_sha256"}):
            raise ValueError("Solidity shard boundary hash does not match its typed fields")
        return self


class SolidityShardOverlap(StrictModel):
    """Explicit non-primary membership of one semantic resource."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    overlap_id: str = Field(pattern=r"^overlap-[0-9a-f]{24}$")
    resource_kind: SolidityShardOverlapKind
    resource_id: str = Field(min_length=1, max_length=_RESOURCE_ID_MAX_LENGTH)
    primary_shard_id: str = Field(pattern=r"^shard-[0-9a-f]{24}$")
    consumer_shard_id: str = Field(pattern=r"^shard-[0-9a-f]{24}$")
    reason: SolidityShardOverlapReason
    overlap_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(
        cls,
        *,
        resource_kind: SolidityShardOverlapKind,
        resource_id: str,
        primary_shard_id: str,
        consumer_shard_id: str,
        reason: SolidityShardOverlapReason,
    ) -> SolidityShardOverlap:
        values = {
            "resource_kind": resource_kind,
            "resource_id": resource_id,
            "primary_shard_id": primary_shard_id,
            "consumer_shard_id": consumer_shard_id,
            "reason": reason,
        }
        serialized = _json_values(values)
        return cls(
            overlap_id="overlap-" + _canonical_sha256(serialized)[:24],
            **values,
            overlap_sha256=_canonical_sha256(serialized),
        )

    @model_validator(mode="after")
    def overlap_is_canonical_and_hashed(self) -> Self:
        if self.primary_shard_id == self.consumer_shard_id:
            raise ValueError("Solidity shard overlap must name a distinct consumer")
        payload = self.model_dump(
            mode="json",
            exclude={"overlap_id", "overlap_sha256"},
        )
        expected = _canonical_sha256(payload)
        if self.overlap_id != "overlap-" + expected[:24]:
            raise ValueError("Solidity shard overlap ID does not match its typed fields")
        if self.overlap_sha256 != expected:
            raise ValueError("Solidity shard overlap hash does not match its typed fields")
        return self


class SoliditySemanticShard(StrictModel):
    """One source-primary shard plus exact graph-boundary overlap."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    shard_id: str = Field(pattern=r"^shard-[0-9a-f]{24}$")
    source_unit_id: str = Field(pattern=r"^source-[0-9a-f]{24}$")
    source_path: str = Field(min_length=1, max_length=4_096)
    source_content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    primary_entity_ids: tuple[str, ...] = ()
    overlap_entity_ids: tuple[str, ...] = ()
    primary_graph_node_ids: tuple[str, ...] = ()
    overlap_graph_node_ids: tuple[str, ...] = ()
    primary_graph_edge_ids: tuple[str, ...] = ()
    overlap_graph_edge_ids: tuple[str, ...] = ()
    primary_storage_entry_ids: tuple[str, ...] = ()
    overlap_storage_entry_ids: tuple[str, ...] = ()
    semantic_dependency_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    inbound_boundary_ids: tuple[str, ...] = ()
    outbound_boundary_ids: tuple[str, ...] = ()
    risk_surfaces: tuple[SolidityShardRiskSurface, ...] = Field(min_length=1)
    shard_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("source_path")
    @classmethod
    def source_path_is_normalized_relative(cls, value: str) -> str:
        return _validated_solidity_source_path(value, label="Solidity semantic shard source path")

    @classmethod
    def build(cls, **values: Any) -> SoliditySemanticShard:
        source_path = str(values["source_path"])
        source_unit_id = str(values["source_unit_id"])
        shard_id = (
            "shard-"
            + _canonical_sha256({"source_path": source_path, "source_unit_id": source_unit_id})[:24]
        )
        body = {"shard_id": shard_id, **values}
        return cls(**body, shard_sha256=_canonical_sha256(_json_values(body)))

    @model_validator(mode="after")
    def shard_is_canonical_complete_and_hashed(self) -> Self:
        expected_id = (
            "shard-"
            + _canonical_sha256(
                {"source_path": self.source_path, "source_unit_id": self.source_unit_id}
            )[:24]
        )
        if self.shard_id != expected_id:
            raise ValueError("Solidity shard ID is not derived from its stable source anchor")
        tuple_fields = (
            "primary_entity_ids",
            "overlap_entity_ids",
            "primary_graph_node_ids",
            "overlap_graph_node_ids",
            "primary_graph_edge_ids",
            "overlap_graph_edge_ids",
            "primary_storage_entry_ids",
            "overlap_storage_entry_ids",
            "inbound_boundary_ids",
            "outbound_boundary_ids",
        )
        for field_name in tuple_fields:
            values = getattr(self, field_name)
            if values != tuple(sorted(set(values))):
                raise ValueError(f"{field_name} must be unique and canonically sorted")
        if set(self.primary_entity_ids) & set(self.overlap_entity_ids):
            raise ValueError("primary and overlap entity memberships must be disjoint")
        if set(self.primary_graph_node_ids) & set(self.overlap_graph_node_ids):
            raise ValueError("primary and overlap node memberships must be disjoint")
        if set(self.primary_graph_edge_ids) & set(self.overlap_graph_edge_ids):
            raise ValueError("primary and overlap edge memberships must be disjoint")
        if set(self.primary_storage_entry_ids) & set(self.overlap_storage_entry_ids):
            raise ValueError("primary and overlap storage memberships must be disjoint")
        if self.risk_surfaces != tuple(sorted(set(self.risk_surfaces), key=str)):
            raise ValueError("Solidity shard risk surfaces must be unique and sorted")
        if SolidityShardRiskSurface.CONTRACTS not in self.risk_surfaces:
            raise ValueError("every Solidity shard must retain the contract risk surface")
        if self.shard_sha256 != _model_sha256(self, exclude={"shard_sha256"}):
            raise ValueError("Solidity shard hash does not match its typed fields")
        return self


class SolidityShardCoverage(StrictModel):
    """Non-vacuous exact-denominator coverage summary for one inventory."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    complete: Literal[True] = True
    source_units_total: int = Field(gt=0)
    source_units_covered: int = Field(gt=0)
    source_bytes_total: int = Field(ge=0)
    source_bytes_covered: int = Field(ge=0)
    entities_total: int = Field(ge=0)
    entities_covered: int = Field(ge=0)
    graph_nodes_total: int = Field(ge=0)
    graph_nodes_covered: int = Field(ge=0)
    graph_edges_total: int = Field(ge=0)
    graph_edges_covered: int = Field(ge=0)
    storage_entries_total: int = Field(ge=0)
    storage_entries_covered: int = Field(ge=0)

    @model_validator(mode="after")
    def all_denominators_are_exact(self) -> Self:
        pairs = (
            (self.source_units_covered, self.source_units_total),
            (self.source_bytes_covered, self.source_bytes_total),
            (self.entities_covered, self.entities_total),
            (self.graph_nodes_covered, self.graph_nodes_total),
            (self.graph_edges_covered, self.graph_edges_total),
            (self.storage_entries_covered, self.storage_entries_total),
        )
        if any(covered != total for covered, total in pairs):
            raise ValueError("Solidity shard coverage cannot claim complete with a gap")
        return self


class SolidityShardInventory(StrictModel):
    """Structurally validated shard inventory requiring exact upstream comparison."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    algorithm_version: Literal["mmaudit.solidity-file-shards.v1"] = (
        "mmaudit.solidity-file-shards.v1"
    )
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    git_commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
    policy: SolidityShardPolicy
    source_inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    symbol_index_context_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    symbol_index_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    symbol_index_projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_set_context_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_set_projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_units: tuple[SolidityShardSourceUnit, ...] = Field(min_length=1)
    entity_facts: tuple[SolidityShardEntityFact, ...] = ()
    graph_node_facts: tuple[SolidityShardGraphNodeFact, ...] = ()
    graph_edge_facts: tuple[SolidityShardGraphEdgeFact, ...] = ()
    storage_facts: tuple[SolidityShardStorageFact, ...] = ()
    entity_ids: tuple[str, ...] = ()
    graph_node_ids: tuple[str, ...] = ()
    graph_edge_ids: tuple[str, ...] = ()
    storage_entry_ids: tuple[str, ...] = ()
    shards: tuple[SoliditySemanticShard, ...] = Field(min_length=1)
    boundaries: tuple[SolidityShardBoundary, ...] = ()
    overlaps: tuple[SolidityShardOverlap, ...] = ()
    coverage: SolidityShardCoverage
    inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(cls, **values: Any) -> SolidityShardInventory:
        body = {
            "schema_version": "1.0",
            "algorithm_version": "mmaudit.solidity-file-shards.v1",
            "evidence_authority": "comparison_required",
            **values,
        }
        return cls(**body, inventory_sha256=_canonical_sha256(_json_values(body)))

    @model_validator(mode="after")
    def inventory_is_exact_and_hashed(self) -> Self:
        self._require_canonical_inventories()
        self._require_fact_commitments()
        shards = {shard.shard_id: shard for shard in self.shards}
        if len(shards) != len(self.shards):
            raise ValueError("Solidity shard IDs must be unique")
        if len(shards) > self.policy.max_shards:
            raise ValueError("Solidity shard count exceeds its bound policy")
        source_owner = {item.source_unit_id: item.primary_shard_id for item in self.source_units}
        if len(source_owner) != len(self.source_units):
            raise ValueError("Solidity source-unit IDs must be unique")
        if len({item.path for item in self.source_units}) != len(self.source_units):
            raise ValueError("Solidity source-unit paths must be unique")
        if len(self.source_units) != len(self.shards):
            raise ValueError("Solidity source units and primary shards must have equal counts")
        if set(source_owner.values()) != set(shards):
            raise ValueError("every shard must primary-own exactly one Solidity source unit")
        source_projection = [
            {
                "path": item.path,
                "utf8_bytes": item.utf8_bytes,
                "line_count": item.line_count,
                "content_sha256": item.content_sha256,
            }
            for item in self.source_units
        ]
        if self.source_inventory_sha256 != _canonical_sha256(source_projection):
            raise ValueError("Solidity source inventory hash does not match its source units")
        for item in self.source_units:
            shard = shards.get(item.primary_shard_id)
            if shard is None or shard.source_unit_id != item.source_unit_id:
                raise ValueError("Solidity source-unit ownership is inconsistent")
            if shard.source_path != item.path:
                raise ValueError("Solidity source path differs between source unit and shard")
            if shard.source_content_sha256 != item.content_sha256:
                raise ValueError("Solidity shard content hash differs from its source unit")
        self._require_primary_coverage(shards)
        self._require_policy_caps(shards)
        self._require_overlap_evidence(shards)
        self._require_boundary_evidence(shards)
        self._require_exact_semantics(shards, source_owner=source_owner)
        expected_coverage = SolidityShardCoverage(
            source_units_total=len(self.source_units),
            source_units_covered=len(source_owner),
            source_bytes_total=sum(item.utf8_bytes for item in self.source_units),
            source_bytes_covered=sum(item.utf8_bytes for item in self.source_units),
            entities_total=len(self.entity_ids),
            entities_covered=sum(len(shard.primary_entity_ids) for shard in self.shards),
            graph_nodes_total=len(self.graph_node_ids),
            graph_nodes_covered=sum(len(shard.primary_graph_node_ids) for shard in self.shards),
            graph_edges_total=len(self.graph_edge_ids),
            graph_edges_covered=sum(len(shard.primary_graph_edge_ids) for shard in self.shards),
            storage_entries_total=len(self.storage_entry_ids),
            storage_entries_covered=sum(
                len(shard.primary_storage_entry_ids) for shard in self.shards
            ),
        )
        if self.coverage != expected_coverage:
            raise ValueError("Solidity shard coverage is not derived from exact memberships")
        if self.inventory_sha256 != _model_sha256(self, exclude={"inventory_sha256"}):
            raise ValueError("Solidity shard inventory hash does not match its typed fields")
        return self

    def _require_canonical_inventories(self) -> None:
        id_fields = ("entity_ids", "graph_node_ids", "graph_edge_ids", "storage_entry_ids")
        for field_name in id_fields:
            values = getattr(self, field_name)
            if values != tuple(sorted(set(values))):
                raise ValueError(f"{field_name} must be unique and canonically sorted")
        if self.source_units != tuple(sorted(self.source_units, key=lambda item: item.path)):
            raise ValueError("Solidity source units must be sorted by path")
        for field_name in (
            "entity_facts",
            "graph_node_facts",
            "graph_edge_facts",
            "storage_facts",
        ):
            facts = getattr(self, field_name)
            if facts != tuple(sorted(facts, key=lambda item: item.resource_id)):
                raise ValueError(f"{field_name} must be sorted by resource ID")
            identifiers = [item.resource_id for item in facts]
            if len(identifiers) != len(set(identifiers)):
                raise ValueError(f"{field_name} resource IDs must be unique")
        if self.shards != tuple(sorted(self.shards, key=lambda item: item.shard_id)):
            raise ValueError("Solidity shards must be sorted by ID")
        if self.boundaries != tuple(sorted(self.boundaries, key=lambda item: item.boundary_id)):
            raise ValueError("Solidity shard boundaries must be sorted by ID")
        if self.overlaps != tuple(sorted(self.overlaps, key=lambda item: item.overlap_id)):
            raise ValueError("Solidity shard overlaps must be sorted by ID")
        for values, label in (
            (self.boundaries, "boundary"),
            (self.overlaps, "overlap"),
        ):
            identifiers = [getattr(item, f"{label}_id") for item in values]
            if len(identifiers) != len(set(identifiers)):
                raise ValueError(f"Solidity shard {label} IDs must be unique")

    def _require_fact_commitments(self) -> None:
        fact_sets = (
            (self.entity_facts, self.entity_ids, "entity"),
            (self.graph_node_facts, self.graph_node_ids, "graph node"),
            (self.graph_edge_facts, self.graph_edge_ids, "graph edge"),
            (self.storage_facts, self.storage_entry_ids, "storage"),
        )
        for facts, identifiers, label in fact_sets:
            if tuple(item.resource_id for item in facts) != identifiers:
                raise ValueError(f"Solidity shard {label} facts differ from their ID inventory")
        expected_index_sha256 = _canonical_sha256(
            {
                "context_sha256": self.symbol_index_context_sha256,
                "entity_facts": [item.model_dump(mode="json") for item in self.entity_facts],
            }
        )
        if self.symbol_index_projection_sha256 != expected_index_sha256:
            raise ValueError("Solidity symbol-index projection differs from its fact commitments")
        expected_graph_sha256 = _canonical_sha256(
            {
                "context_sha256": self.graph_set_context_sha256,
                "node_facts": [item.model_dump(mode="json") for item in self.graph_node_facts],
                "edge_facts": [item.model_dump(mode="json") for item in self.graph_edge_facts],
                "storage_facts": [item.model_dump(mode="json") for item in self.storage_facts],
            }
        )
        if self.graph_set_projection_sha256 != expected_graph_sha256:
            raise ValueError("Solidity graph-set projection differs from its fact commitments")

    def _require_primary_coverage(self, shards: dict[str, SoliditySemanticShard]) -> None:
        inventories = (
            (self.entity_ids, "primary_entity_ids", "entity"),
            (self.graph_node_ids, "primary_graph_node_ids", "graph node"),
            (self.graph_edge_ids, "primary_graph_edge_ids", "graph edge"),
            (self.storage_entry_ids, "primary_storage_entry_ids", "storage entry"),
        )
        for expected, field_name, label in inventories:
            memberships = [item for shard in shards.values() for item in getattr(shard, field_name)]
            if tuple(sorted(memberships)) != expected:
                raise ValueError(
                    f"Solidity shard primary {label} coverage is incomplete or duplicated"
                )

    def _require_policy_caps(self, shards: dict[str, SoliditySemanticShard]) -> None:
        if len(self.overlaps) > self.policy.max_total_overlap_records:
            raise ValueError("Solidity shard overlap inventory exceeds its global policy")
        if len(self.boundaries) > self.policy.max_total_boundaries:
            raise ValueError("Solidity shard boundary inventory exceeds its global policy")
        sources_by_shard = {item.primary_shard_id: item for item in self.source_units}
        for shard_id, shard in shards.items():
            source = sources_by_shard[shard_id]
            checks = (
                (source.utf8_bytes, self.policy.max_source_bytes_per_shard),
                (len(shard.primary_entity_ids), self.policy.max_primary_entities_per_shard),
                (
                    len(shard.primary_graph_node_ids),
                    self.policy.max_primary_graph_nodes_per_shard,
                ),
                (
                    len(shard.primary_graph_edge_ids),
                    self.policy.max_primary_graph_edges_per_shard,
                ),
                (
                    len(shard.primary_storage_entry_ids),
                    self.policy.max_primary_storage_entries_per_shard,
                ),
                (len(shard.overlap_entity_ids), self.policy.max_overlap_entities_per_shard),
                (
                    len(shard.overlap_graph_node_ids),
                    self.policy.max_overlap_graph_nodes_per_shard,
                ),
                (
                    len(shard.overlap_graph_edge_ids),
                    self.policy.max_overlap_graph_edges_per_shard,
                ),
                (
                    len(shard.overlap_storage_entry_ids),
                    self.policy.max_overlap_storage_entries_per_shard,
                ),
                (
                    len(shard.inbound_boundary_ids) + len(shard.outbound_boundary_ids),
                    self.policy.max_boundaries_per_shard,
                ),
                (
                    sum(
                        len(getattr(shard, field_name))
                        for field_name in (
                            "primary_entity_ids",
                            "overlap_entity_ids",
                            "primary_graph_node_ids",
                            "overlap_graph_node_ids",
                            "primary_graph_edge_ids",
                            "overlap_graph_edge_ids",
                            "primary_storage_entry_ids",
                            "overlap_storage_entry_ids",
                        )
                    ),
                    self.policy.max_total_semantic_memberships_per_shard,
                ),
            )
            if any(observed > maximum for observed, maximum in checks):
                raise ValueError("Solidity shard membership exceeds its nested policy")

    def _require_overlap_evidence(self, shards: dict[str, SoliditySemanticShard]) -> None:
        valid_ids = {
            SolidityShardOverlapKind.ENTITY: set(self.entity_ids),
            SolidityShardOverlapKind.GRAPH_NODE: set(self.graph_node_ids),
            SolidityShardOverlapKind.GRAPH_EDGE: set(self.graph_edge_ids),
            SolidityShardOverlapKind.STORAGE_ENTRY: set(self.storage_entry_ids),
        }
        owners_by_kind = {
            SolidityShardOverlapKind.ENTITY: {
                item.resource_id: item.primary_shard_id for item in self.entity_facts
            },
            SolidityShardOverlapKind.GRAPH_NODE: {
                item.resource_id: item.primary_shard_id for item in self.graph_node_facts
            },
            SolidityShardOverlapKind.GRAPH_EDGE: {
                item.resource_id: item.primary_shard_id for item in self.graph_edge_facts
            },
            SolidityShardOverlapKind.STORAGE_ENTRY: {
                item.resource_id: item.primary_shard_id for item in self.storage_facts
            },
        }
        overlap_fields = {
            SolidityShardOverlapKind.ENTITY: "overlap_entity_ids",
            SolidityShardOverlapKind.GRAPH_NODE: "overlap_graph_node_ids",
            SolidityShardOverlapKind.GRAPH_EDGE: "overlap_graph_edge_ids",
            SolidityShardOverlapKind.STORAGE_ENTRY: "overlap_storage_entry_ids",
        }
        expected_memberships: set[tuple[SolidityShardOverlapKind, str, str, str]] = set()
        source_owned_node_ids = {
            item.resource_id for item in self.graph_node_facts if item.source_owned
        }
        for kind, field_name in overlap_fields.items():
            for shard in shards.values():
                for resource_id in getattr(shard, field_name):
                    owner = owners_by_kind[kind].get(resource_id)
                    if owner is None:
                        raise ValueError("overlap resource must have exactly one primary owner")
                    expected_memberships.add((kind, resource_id, owner, shard.shard_id))
        observed_memberships: set[tuple[SolidityShardOverlapKind, str, str, str]] = set()
        for overlap in self.overlaps:
            if overlap.resource_id not in valid_ids[overlap.resource_kind]:
                raise ValueError("Solidity shard overlap references an unknown resource")
            if overlap.primary_shard_id not in shards or overlap.consumer_shard_id not in shards:
                raise ValueError("Solidity shard overlap references an unknown shard")
            if overlap.resource_kind is SolidityShardOverlapKind.GRAPH_NODE:
                expected_reason = (
                    SolidityShardOverlapReason.GRAPH_BOUNDARY
                    if overlap.resource_id in source_owned_node_ids
                    else SolidityShardOverlapReason.SHARED_GRAPH_NODE
                )
            else:
                expected_reason = SolidityShardOverlapReason.GRAPH_BOUNDARY
            if overlap.reason is not expected_reason:
                raise ValueError("Solidity shard overlap reason is inconsistent with its resource")
            observed_memberships.add(
                (
                    overlap.resource_kind,
                    overlap.resource_id,
                    overlap.primary_shard_id,
                    overlap.consumer_shard_id,
                )
            )
        if observed_memberships != expected_memberships or len(observed_memberships) != len(
            self.overlaps
        ):
            raise ValueError("Solidity shard overlap evidence is incomplete or duplicated")

    def _require_boundary_evidence(self, shards: dict[str, SoliditySemanticShard]) -> None:
        boundary_ids = {boundary.boundary_id for boundary in self.boundaries}
        expected_inbound: dict[str, set[str]] = {shard_id: set() for shard_id in shards}
        expected_outbound: dict[str, set[str]] = {shard_id: set() for shard_id in shards}
        for boundary in self.boundaries:
            expected_outbound.setdefault(boundary.source_shard_id, set()).add(boundary.boundary_id)
            expected_inbound.setdefault(boundary.target_shard_id, set()).add(boundary.boundary_id)
        for shard_id, shard in shards.items():
            if set(shard.inbound_boundary_ids) != expected_inbound[shard_id]:
                raise ValueError("Solidity shard inbound boundary membership is not exact")
            if set(shard.outbound_boundary_ids) != expected_outbound[shard_id]:
                raise ValueError("Solidity shard outbound boundary membership is not exact")
        if {item for values in expected_inbound.values() for item in values} != boundary_ids:
            raise ValueError("Solidity shard inbound boundary inventory is incomplete")
        if {item for values in expected_outbound.values() for item in values} != boundary_ids:
            raise ValueError("Solidity shard outbound boundary inventory is incomplete")
        for boundary in self.boundaries:
            source_shard = shards.get(boundary.source_shard_id)
            target_shard = shards.get(boundary.target_shard_id)
            if source_shard is None or target_shard is None:
                raise ValueError("Solidity shard boundary references an unknown shard")
            if boundary.boundary_id not in source_shard.outbound_boundary_ids:
                raise ValueError("Solidity shard boundary is missing its outbound membership")
            if boundary.boundary_id not in target_shard.inbound_boundary_ids:
                raise ValueError("Solidity shard boundary is missing its inbound membership")
            source_edges = set(source_shard.primary_graph_edge_ids) | set(
                source_shard.overlap_graph_edge_ids
            )
            target_edges = set(target_shard.primary_graph_edge_ids) | set(
                target_shard.overlap_graph_edge_ids
            )
            if (
                boundary.graph_edge_id not in source_edges
                or boundary.graph_edge_id not in target_edges
            ):
                raise ValueError("Solidity shard boundary edge is absent from one endpoint shard")

    def _require_exact_semantics(
        self,
        shards: dict[str, SoliditySemanticShard],
        *,
        source_owner: dict[str, str],
    ) -> None:
        entity_facts = {item.resource_id: item for item in self.entity_facts}
        node_facts = {item.resource_id: item for item in self.graph_node_facts}
        edge_facts = {item.resource_id: item for item in self.graph_edge_facts}
        storage_facts = {item.resource_id: item for item in self.storage_facts}
        if set(entity_facts) & set(storage_facts):
            raise ValueError("Solidity entity and storage fact identities must be disjoint")
        source_bindings = [
            (item.source_unit_id, item.primary_shard_id) for item in self.entity_facts
        ]
        source_bindings.extend(
            (item.source_unit_id, item.primary_shard_id) for item in self.graph_edge_facts
        )
        source_bindings.extend(
            (item.source_unit_id, item.primary_shard_id) for item in self.storage_facts
        )
        for source_unit_id, primary_shard_id in source_bindings:
            expected_owner = source_owner.get(source_unit_id)
            if expected_owner is None or primary_shard_id != expected_owner:
                raise ValueError("Solidity shard fact is rebound from its source unit")
        for facts, primary_field in (
            (entity_facts, "primary_entity_ids"),
            (node_facts, "primary_graph_node_ids"),
            (edge_facts, "primary_graph_edge_ids"),
            (storage_facts, "primary_storage_entry_ids"),
        ):
            for resource_id, fact in facts.items():
                owner = shards.get(fact.primary_shard_id)
                if owner is None or resource_id not in getattr(owner, primary_field):
                    raise ValueError("Solidity shard fact primary ownership is inconsistent")
        source_fact_owners = {
            **{resource_id: fact.primary_shard_id for resource_id, fact in entity_facts.items()},
            **{resource_id: fact.primary_shard_id for resource_id, fact in storage_facts.items()},
        }
        for node_id, node in node_facts.items():
            source_shard_id = source_owner.get(node.source_unit_id)
            if source_shard_id is None:
                raise ValueError("Solidity graph-node fact references an unknown source unit")
            expected_source_owned = node_id in source_fact_owners
            if node.source_owned is not expected_source_owned:
                raise ValueError("Solidity graph-node source ownership classification is false")
            if expected_source_owned:
                source_fact = entity_facts.get(node_id) or storage_facts.get(node_id)
                if (
                    node.primary_shard_id != source_fact_owners[node_id]
                    or source_fact is None
                    or node.source_unit_id != source_fact.source_unit_id
                ):
                    raise ValueError("Solidity source-owned graph node has a different source")
        for edge in edge_facts.values():
            if edge.source_node_id not in node_facts or edge.target_node_id not in node_facts:
                raise ValueError("Solidity graph-edge fact references an unknown node")
            if edge.primary_shard_id not in shards:
                raise ValueError("Solidity graph-edge fact references an unknown primary shard")

        expected_boundaries: set[tuple[str, SolidityGraphKind, str, str, str, str]] = set()
        for edge in edge_facts.values():
            source_node_fact = node_facts[edge.source_node_id]
            target_node_fact = node_facts[edge.target_node_id]
            if not source_node_fact.source_owned or not target_node_fact.source_owned:
                continue
            if source_node_fact.primary_shard_id == target_node_fact.primary_shard_id:
                continue
            expected_boundaries.add(
                (
                    edge.resource_id,
                    edge.graph_kind,
                    edge.source_node_id,
                    edge.target_node_id,
                    source_node_fact.primary_shard_id,
                    target_node_fact.primary_shard_id,
                )
            )
        observed_boundaries = {
            (
                item.graph_edge_id,
                item.graph_kind,
                item.source_node_id,
                item.target_node_id,
                item.source_shard_id,
                item.target_shard_id,
            )
            for item in self.boundaries
        }
        if observed_boundaries != expected_boundaries or len(observed_boundaries) != len(
            self.boundaries
        ):
            raise ValueError("Solidity shard boundaries differ from graph-edge facts")

        expected_overlaps: set[
            tuple[
                SolidityShardOverlapKind,
                str,
                str,
                str,
                SolidityShardOverlapReason,
            ]
        ] = set()

        def add_overlap(
            kind: SolidityShardOverlapKind,
            resource_id: str,
            owner: str,
            consumer: str,
            reason: SolidityShardOverlapReason,
        ) -> None:
            if owner != consumer:
                expected_overlaps.add((kind, resource_id, owner, consumer, reason))

        node_referring_shards: dict[str, set[str]] = {node_id: set() for node_id in node_facts}
        for edge in edge_facts.values():
            node_referring_shards[edge.source_node_id].add(edge.primary_shard_id)
            node_referring_shards[edge.target_node_id].add(edge.primary_shard_id)
        for node_id, referring_shards in node_referring_shards.items():
            node = node_facts[node_id]
            if node.source_owned:
                continue
            expected_owner = (
                min(referring_shards) if referring_shards else source_owner[node.source_unit_id]
            )
            if node.primary_shard_id != expected_owner:
                raise ValueError("shared Solidity graph node has a non-canonical primary shard")
            for consumer in referring_shards - {node.primary_shard_id}:
                add_overlap(
                    SolidityShardOverlapKind.GRAPH_NODE,
                    node_id,
                    node.primary_shard_id,
                    consumer,
                    SolidityShardOverlapReason.SHARED_GRAPH_NODE,
                )
        for edge in edge_facts.values():
            source_node_fact = node_facts[edge.source_node_id]
            target_node_fact = node_facts[edge.target_node_id]
            if (
                not source_node_fact.source_owned
                or not target_node_fact.source_owned
                or source_node_fact.primary_shard_id == target_node_fact.primary_shard_id
            ):
                continue
            for consumer in {
                source_node_fact.primary_shard_id,
                target_node_fact.primary_shard_id,
            }:
                add_overlap(
                    SolidityShardOverlapKind.GRAPH_EDGE,
                    edge.resource_id,
                    edge.primary_shard_id,
                    consumer,
                    SolidityShardOverlapReason.GRAPH_BOUNDARY,
                )
            for node_id, owner_shard_id, consumer_shard_id in (
                (
                    edge.target_node_id,
                    target_node_fact.primary_shard_id,
                    source_node_fact.primary_shard_id,
                ),
                (
                    edge.source_node_id,
                    source_node_fact.primary_shard_id,
                    target_node_fact.primary_shard_id,
                ),
            ):
                add_overlap(
                    SolidityShardOverlapKind.GRAPH_NODE,
                    node_id,
                    owner_shard_id,
                    consumer_shard_id,
                    SolidityShardOverlapReason.GRAPH_BOUNDARY,
                )
                kind = (
                    SolidityShardOverlapKind.ENTITY
                    if node_id in entity_facts
                    else SolidityShardOverlapKind.STORAGE_ENTRY
                )
                add_overlap(
                    kind,
                    node_id,
                    owner_shard_id,
                    consumer_shard_id,
                    SolidityShardOverlapReason.GRAPH_BOUNDARY,
                )
        observed_overlaps = {
            (
                item.resource_kind,
                item.resource_id,
                item.primary_shard_id,
                item.consumer_shard_id,
                item.reason,
            )
            for item in self.overlaps
        }
        if observed_overlaps != expected_overlaps or len(observed_overlaps) != len(self.overlaps):
            raise ValueError("Solidity shard overlaps differ from exact graph semantics")

        record_hashes = {
            SolidityShardOverlapKind.ENTITY: {
                item.resource_id: item.record_sha256 for item in self.entity_facts
            },
            SolidityShardOverlapKind.GRAPH_NODE: {
                item.resource_id: item.record_sha256 for item in self.graph_node_facts
            },
            SolidityShardOverlapKind.GRAPH_EDGE: {
                item.resource_id: item.record_sha256 for item in self.graph_edge_facts
            },
            SolidityShardOverlapKind.STORAGE_ENTRY: {
                item.resource_id: item.record_sha256 for item in self.storage_facts
            },
        }
        boundaries_by_id = {item.boundary_id: item for item in self.boundaries}
        for shard in shards.values():
            fact_bindings = [
                (
                    kind,
                    resource_id,
                    record_hashes[kind][resource_id],
                )
                for kind, field_name in (
                    (SolidityShardOverlapKind.ENTITY, "primary_entity_ids"),
                    (SolidityShardOverlapKind.ENTITY, "overlap_entity_ids"),
                    (SolidityShardOverlapKind.GRAPH_NODE, "primary_graph_node_ids"),
                    (SolidityShardOverlapKind.GRAPH_NODE, "overlap_graph_node_ids"),
                    (SolidityShardOverlapKind.GRAPH_EDGE, "primary_graph_edge_ids"),
                    (SolidityShardOverlapKind.GRAPH_EDGE, "overlap_graph_edge_ids"),
                    (SolidityShardOverlapKind.STORAGE_ENTRY, "primary_storage_entry_ids"),
                    (SolidityShardOverlapKind.STORAGE_ENTRY, "overlap_storage_entry_ids"),
                )
                for resource_id in getattr(shard, field_name)
            ]
            boundary_hashes = [
                boundaries_by_id[boundary_id].boundary_sha256
                for boundary_id in (
                    *shard.inbound_boundary_ids,
                    *shard.outbound_boundary_ids,
                )
            ]
            expected_dependency_sha256 = solidity_shard_semantic_dependency_sha256(
                fact_bindings=fact_bindings,
                boundary_sha256s=boundary_hashes,
            )
            if shard.semantic_dependency_sha256 != expected_dependency_sha256:
                raise ValueError("Solidity shard semantic dependency hash is stale")
            edge_ids = set(shard.primary_graph_edge_ids) | set(shard.overlap_graph_edge_ids)
            graph_kinds = {edge_facts[edge_id].graph_kind for edge_id in edge_ids}
            entity_kinds = {
                entity_facts[entity_id].entity_kind for entity_id in shard.primary_entity_ids
            }
            has_storage = bool(shard.primary_storage_entry_ids or shard.overlap_storage_entry_ids)
            expected_risks = tuple(
                sorted(
                    solidity_shard_risk_surfaces(
                        graph_kinds,
                        entity_kinds=entity_kinds,
                        has_storage=has_storage,
                    ),
                    key=str,
                )
            )
            if shard.risk_surfaces != expected_risks:
                raise ValueError("Solidity shard risk surfaces differ from exact retained facts")


class SolidityShardsArtifact(StrictModel):
    """Typed envelope matching the emitted ``solidity-shards.json`` artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    inventory: SolidityShardInventory | None


class SolidityIndexArtifact(StrictModel):
    """Typed envelope matching the emitted ``solidity-index.json`` artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    index: SoliditySymbolIndex | None


class SolidityGraphsArtifact(StrictModel):
    """Typed envelope matching the emitted ``solidity-graphs.json`` artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    graphs: SolidityGraphSet | None


class SolidityShardReportBinding(StrictModel):
    """Report projection that remains non-authoritative until exact comparison."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    symbol_index_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    symbol_index_projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_set_projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    shard_count: int = Field(gt=0)
    boundary_count: int = Field(ge=0)
    overlap_count: int = Field(ge=0)
    coverage: SolidityShardCoverage

    @classmethod
    def from_inventory(cls, inventory: SolidityShardInventory) -> SolidityShardReportBinding:
        validated = SolidityShardInventory.model_validate(inventory.model_dump(mode="python"))
        return cls(
            policy_sha256=validated.policy.policy_sha256,
            source_inventory_sha256=validated.source_inventory_sha256,
            symbol_index_sha256=validated.symbol_index_sha256,
            symbol_index_projection_sha256=validated.symbol_index_projection_sha256,
            graph_set_sha256=validated.graph_set_sha256,
            graph_set_projection_sha256=validated.graph_set_projection_sha256,
            inventory_sha256=validated.inventory_sha256,
            shard_count=len(validated.shards),
            boundary_count=len(validated.boundaries),
            overlap_count=len(validated.overlaps),
            coverage=validated.coverage,
        )

    def require_exact_inventory(self, inventory: SolidityShardInventory) -> None:
        if self != type(self).from_inventory(inventory):
            raise ValueError("Solidity shard report binding differs from its inventory")


class SolidityShardComparisonResult(StrictModel):
    """Ephemeral exact-comparison result; serialization is never origin authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["CONSISTENT"] = "CONSISTENT"
    evidence_authority: Literal["comparison_only"] = "comparison_only"
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    symbol_index_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    shard_count: int = Field(gt=0)
    boundary_count: int = Field(ge=0)
    overlap_count: int = Field(ge=0)


def _json_values(values: dict[str, Any]) -> dict[str, Any]:
    """Normalize enums and tuples through Pydantic-compatible JSON semantics."""

    return cast(
        dict[str, Any],
        json.loads(json.dumps(values, default=_json_default, allow_nan=False)),
    )


def _json_default(value: Any) -> Any:
    if isinstance(value, StrictModel):
        return value.model_dump(mode="json")
    if isinstance(value, StrEnum):
        return value.value
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")
