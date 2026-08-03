"""Role-specific, redacted, bounded context packages."""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter, deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from itertools import chain
from types import MappingProxyType
from typing import Any

from pydantic_core import PydanticSerializationError

from mmaudit.config import PrivacyConfig, RepositoryConfig
from mmaudit.models.schemas import (
    ContextExcerpt,
    ContextPackage,
    EconomicSimulationPlan,
    EvidenceStrength,
    FormalToolRun,
    InvariantExecutionResult,
    InvariantSuite,
    Location,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewRequest,
    RepositoryMap,
    ScannerFinding,
    SolidityCompilationResult,
    SolidityCoverage,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphSet,
    SolidityProjectMetadata,
    SoliditySymbolIndex,
    ThreatModel,
)
from mmaudit.models.token_planning import (
    CONTEXT_OMISSION_GROUP_CAP,
    UTF8_BYTES_PER_ESTIMATED_TOKEN,
    ContextOmissionAccumulator,
    ContextOmissionCategory,
    ContextOmissionItem,
    ContextOmissionNoticeLevel,
    ContextOmissionReason,
)
from mmaudit.orchestration.model_coverage import (
    build_model_surface_requests,
    model_review_edge_subject_id,
)
from mmaudit.repository.chunking import chunk_text, excerpt_proves_location, line_range_hash
from mmaudit.repository.discovery import DiscoveredFile, DiscoveryResult
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.redaction import SecretSafetyError, detect_secrets, redact_text
from mmaudit.solidity.retrieval import (
    compact_solidity_graphs,
    compact_solidity_index,
    solidity_preferred_paths,
)


class ContextBudgetError(RuntimeError):
    """Raised when even metadata cannot fit an explicit context allocation."""


class ContextBoundaryError(ContextBudgetError, ValueError):
    """Raised when a supplied context package fails detached boundary validation."""


@dataclass(frozen=True, slots=True)
class ContextCategoryMeasurement:
    """Hash/count projection for one provider-visible context category."""

    content_sha256: str
    utf8_bytes: int


@dataclass(frozen=True, slots=True)
class _RequiredModelSurfaceFacts:
    """Exact deterministic facts that a supplied review request cannot lose."""

    entity_ids: frozenset[str]
    graph_edges: tuple[SolidityGraphEdge, ...]
    graph_node_ids: frozenset[str]
    source_locations: tuple[Location, ...]
    source_paths: frozenset[str]
    source_file_identities: tuple[tuple[str, int, int, str], ...] = ()


_MAX_PROVIDER_OMISSION_NOTICE_BYTES = 4_096
_MAX_PROVIDER_OMISSION_COMMITMENT_GROWTH_BYTES = len(str(CONTEXT_OMISSION_GROUP_CAP)) - len("0")


@dataclass(frozen=True, slots=True)
class _BoundInventoryIdentity:
    """One legacy inventory digest bound to its owned source field and ordinal."""

    field: str
    ordinal: int
    identity_sha256: str


def _scanner_context_payload(findings: Iterable[ScannerFinding]) -> list[dict[str, Any]]:
    """Serialize stable scanner evidence without runtime-observation timestamps.

    Source-location validation timestamps remain available in the private scanner
    artifact, but they are incidental to the provider's security reasoning.  If
    included here, an otherwise exact scheduler resume would produce a different
    prompt solely because the same location was revalidated later.
    """

    payloads: list[dict[str, Any]] = []
    for finding in findings:
        payload = finding.model_dump(mode="json")
        if finding.evidence_strength is EvidenceStrength.NONE:
            payload.pop("evidence_strength", None)
        metadata = payload.get("metadata")
        if isinstance(metadata, dict):
            location_validation = metadata.get("location_validation")
            if isinstance(location_validation, list):
                for validation in location_validation:
                    if isinstance(validation, dict):
                        validation.pop("validated_at", None)
        payloads.append(payload)
    return payloads


def _inventory_item_sha256(item: Any) -> str:
    """Return a stable hash for one trusted inventory item without retaining its body."""

    if isinstance(item, _BoundInventoryIdentity):
        return item.identity_sha256
    model_dump = getattr(item, "model_dump", None)
    payload = model_dump(mode="json") if callable(model_dump) else item
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class _ContextInventorySnapshot:
    """Immutable precomputed identities for builder-owned context inventory.

    Field and ordinal bind every cached identity to the captured inventory. They
    deliberately do not alter ``identity_sha256``: that digest remains exactly
    the value emitted by the pre-cache omission algorithm.
    """

    entries: tuple[_BoundInventoryIdentity, ...]
    _raw_by_object_id: Mapping[int, str]
    _bound_by_field_and_object_id: Mapping[tuple[str, int], _BoundInventoryIdentity]

    @classmethod
    def empty(cls) -> _ContextInventorySnapshot:
        """Return an immutable uncached snapshot for equivalence validation."""

        return cls(
            entries=(),
            _raw_by_object_id=MappingProxyType({}),
            _bound_by_field_and_object_id=MappingProxyType({}),
        )

    @classmethod
    def capture(
        cls,
        *,
        repository_map: RepositoryMap,
        scanner_findings: Iterable[ScannerFinding],
        solidity_projects: Iterable[SolidityProjectMetadata],
        solidity_compilations: Iterable[SolidityCompilationResult],
        solidity_index: SoliditySymbolIndex | None,
        solidity_graphs: SolidityGraphSet | None,
        solidity_invariants: InvariantSuite | None,
        invariant_executions: Iterable[InvariantExecutionResult],
        economic_simulations: Iterable[EconomicSimulationPlan],
        formal_runs: Iterable[FormalToolRun],
        solidity_coverage: SolidityCoverage | None,
    ) -> _ContextInventorySnapshot:
        raw_by_object_id: dict[int, str] = {}
        bound_by_field_and_object_id: dict[tuple[str, int], _BoundInventoryIdentity] = {}
        entries: list[_BoundInventoryIdentity] = []

        def raw_identity(item: Any) -> str:
            object_id = id(item)
            identity_sha256 = raw_by_object_id.get(object_id)
            if identity_sha256 is None:
                identity_sha256 = _inventory_item_sha256(item)
                raw_by_object_id[object_id] = identity_sha256
            return identity_sha256

        def bind(
            field: str,
            items: Iterable[Any],
            *,
            provider_field: str | None = None,
            map_value: bool = False,
            identity_projection: Callable[[Any], Any] | None = None,
        ) -> None:
            for ordinal, item in enumerate(items):
                if identity_projection is None:
                    item_sha256 = raw_identity(item)
                else:
                    object_id = id(item)
                    cached_item_sha256 = raw_by_object_id.get(object_id)
                    if cached_item_sha256 is None:
                        cached_item_sha256 = _inventory_item_sha256(identity_projection(item))
                        raw_by_object_id[object_id] = cached_item_sha256
                    item_sha256 = cached_item_sha256
                if provider_field is None:
                    identity_sha256 = item_sha256
                elif map_value:
                    identity_sha256 = _inventory_item_sha256(
                        {"field": provider_field, "value": item}
                    )
                else:
                    identity_sha256 = _inventory_item_sha256(
                        {"field": provider_field, "item_sha256": item_sha256}
                    )
                entry = _BoundInventoryIdentity(
                    field=field,
                    ordinal=ordinal,
                    identity_sha256=identity_sha256,
                )
                key = (field, id(item))
                existing = bound_by_field_and_object_id.setdefault(key, entry)
                if existing.identity_sha256 != identity_sha256:
                    raise ContextBudgetError("owned context inventory identity is inconsistent")
                entries.append(entry)

        bind("repository_map.files", repository_map.files)
        for field_name in _REPOSITORY_MAP_LIST_FIELDS:
            bind(
                f"repository_map.{field_name}",
                getattr(repository_map, field_name),
                provider_field=field_name,
                map_value=True,
            )
        bind(
            "repository_map.omitted_files",
            repository_map.omitted_files,
            provider_field="omitted_files",
            map_value=True,
        )
        bind(
            "scanner_findings",
            scanner_findings,
            identity_projection=lambda finding: _scanner_context_payload((finding,))[0],
        )
        bind("solidity_projects", solidity_projects)
        bind("solidity_compilations", solidity_compilations)
        bind("invariant_executions", invariant_executions)
        bind("economic_simulations", economic_simulations)
        bind("formal_runs", formal_runs)
        if solidity_invariants is not None:
            bind("solidity_invariants", (solidity_invariants,))
        if solidity_coverage is not None:
            bind("solidity_coverage", (solidity_coverage,))
        if solidity_index is not None:
            for field_name in (
                "projects",
                "entities",
                "ast_sources",
                "fallback_sources",
                "warnings",
            ):
                bind(
                    f"solidity_index.{field_name}",
                    getattr(solidity_index, field_name),
                    provider_field=field_name,
                )
        if solidity_graphs is not None:
            for field_name in (
                "nodes",
                "edges",
                "storage_layout",
                "analyzed_graphs",
                "warnings",
            ):
                bind(
                    f"solidity_graphs.{field_name}",
                    getattr(solidity_graphs, field_name),
                    provider_field=field_name,
                )
        return cls(
            entries=tuple(entries),
            _raw_by_object_id=MappingProxyType(raw_by_object_id),
            _bound_by_field_and_object_id=MappingProxyType(bound_by_field_and_object_id),
        )

    def item_sha256(self, item: Any) -> str:
        """Return a captured raw identity or the exact legacy fallback digest."""

        if isinstance(item, _BoundInventoryIdentity):
            return item.identity_sha256
        cached = self._raw_by_object_id.get(id(item))
        if cached is not None:
            return cached
        return _inventory_item_sha256(item)

    def bound_identity(self, field: str, item: Any) -> _BoundInventoryIdentity | None:
        """Resolve an owned field item without serializing it again."""

        return self._bound_by_field_and_object_id.get((field, id(item)))


def _tagged_inventory(
    field_name: str,
    items: Iterable[Any],
    *,
    binding_field: str,
    snapshot: _ContextInventorySnapshot | None = None,
) -> Iterable[dict[str, str] | _BoundInventoryIdentity]:
    """Project one provider-visible collection into field-bound hash-only identities."""

    for item in items:
        if snapshot is not None:
            cached = snapshot.bound_identity(binding_field, item)
            if cached is not None:
                yield cached
                continue
        yield {
            "field": field_name,
            "item_sha256": _inventory_item_sha256(item),
        }


def _solidity_index_compaction_inventory(
    index: SoliditySymbolIndex | None,
    *,
    snapshot: _ContextInventorySnapshot | None = None,
) -> Iterable[dict[str, str] | _BoundInventoryIdentity]:
    """Return index items that deterministic compaction can remove progressively."""

    if index is None:
        return
    yield from _tagged_inventory(
        "entities",
        index.entities,
        binding_field="solidity_index.entities",
        snapshot=snapshot,
    )
    yield from _tagged_inventory(
        "ast_sources",
        index.ast_sources,
        binding_field="solidity_index.ast_sources",
        snapshot=snapshot,
    )
    yield from _tagged_inventory(
        "fallback_sources",
        index.fallback_sources,
        binding_field="solidity_index.fallback_sources",
        snapshot=snapshot,
    )


def _retained_solidity_index_inventory(
    index: SoliditySymbolIndex,
    *,
    original: SoliditySymbolIndex,
    snapshot: _ContextInventorySnapshot | None = None,
) -> Iterable[dict[str, str] | _BoundInventoryIdentity]:
    """Return original index items still present in one compact candidate.

    Compaction appends a synthetic warning describing its own reduction. That
    transient summary was never part of the input inventory and must not be
    counted as omitted when a later candidate replaces it.
    """

    yield from _tagged_inventory(
        "projects",
        index.projects,
        binding_field="solidity_index.projects",
        snapshot=snapshot,
    )
    yield from _solidity_index_compaction_inventory(index, snapshot=snapshot)
    yield from _tagged_inventory(
        "warnings",
        index.warnings[: len(original.warnings)],
        binding_field="solidity_index.warnings",
        snapshot=snapshot,
    )


def _solidity_graph_compaction_inventory(
    graphs: SolidityGraphSet | None,
    *,
    snapshot: _ContextInventorySnapshot | None = None,
) -> Iterable[dict[str, str] | _BoundInventoryIdentity]:
    """Return graph items that deterministic compaction can remove progressively."""

    if graphs is None:
        return
    yield from _tagged_inventory(
        "nodes",
        graphs.nodes,
        binding_field="solidity_graphs.nodes",
        snapshot=snapshot,
    )
    yield from _tagged_inventory(
        "edges",
        graphs.edges,
        binding_field="solidity_graphs.edges",
        snapshot=snapshot,
    )
    yield from _tagged_inventory(
        "storage_layout",
        graphs.storage_layout,
        binding_field="solidity_graphs.storage_layout",
        snapshot=snapshot,
    )


def _retained_solidity_graph_inventory(
    graphs: SolidityGraphSet,
    *,
    original: SolidityGraphSet,
    snapshot: _ContextInventorySnapshot | None = None,
) -> Iterable[dict[str, str] | _BoundInventoryIdentity]:
    """Return every original graph item retained in one compact candidate."""

    yield from _solidity_graph_compaction_inventory(graphs, snapshot=snapshot)
    yield from _tagged_inventory(
        "analyzed_graphs",
        graphs.analyzed_graphs,
        binding_field="solidity_graphs.analyzed_graphs",
        snapshot=snapshot,
    )
    yield from _tagged_inventory(
        "coverage",
        (
            {
                "name": name,
                "count": count,
            }
            for name, count in sorted(graphs.coverage.items())
        ),
        binding_field="solidity_graphs.coverage",
        snapshot=snapshot,
    )
    yield from _tagged_inventory(
        "warnings",
        graphs.warnings[: len(original.warnings)],
        binding_field="solidity_graphs.warnings",
        snapshot=snapshot,
    )


def _add_context_omission(
    inventory: dict[
        tuple[ContextOmissionCategory, ContextOmissionReason],
        ContextOmissionAccumulator,
    ],
    *,
    category: ContextOmissionCategory,
    reason: ContextOmissionReason,
    identity: Any,
) -> None:
    """Bind one omission to deterministic identity while retaining hash-only evidence."""

    identity_payload = {
        "category": category.value,
        "reason": reason.value,
        "identity": identity,
    }
    omitted_item_sha256 = hashlib.sha256(
        json.dumps(
            identity_payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    key = (category, reason)
    accumulator = inventory.get(key)
    if accumulator is None:
        accumulator = ContextOmissionAccumulator(
            category=category,
            reason=reason,
        )
        inventory[key] = accumulator
    accumulator.add(omitted_item_sha256)


def _canonical_context_omissions(
    inventory: dict[
        tuple[ContextOmissionCategory, ContextOmissionReason],
        ContextOmissionAccumulator,
    ],
) -> list[ContextOmissionItem]:
    if len(inventory) > CONTEXT_OMISSION_GROUP_CAP:
        raise ContextBudgetError("context omission group inventory exceeds its fixed cap")
    return [
        accumulator.build()
        for (_category, _reason), accumulator in sorted(
            inventory.items(),
            key=lambda item: (item[0][0].value, item[0][1].value),
        )
    ]


_ROLE_CATEGORY_WEIGHTS: dict[str, dict[str, int]] = {
    "threat_model": {
        "api": 8,
        "auth": 9,
        "network": 7,
        "sensitive": 8,
        "business_logic": 6,
        "configuration": 4,
        "changed": 5,
        "smart_contract": 9,
        "evm_auth": 9,
        "evm_external_call": 8,
        "evm_upgrade": 8,
        "evm_value": 8,
        "evm_signature": 7,
        "evm_oracle": 7,
    },
    "source_audit": {
        "api": 8,
        "auth": 9,
        "data": 8,
        "file": 8,
        "network": 9,
        "serialization": 9,
        "command": 10,
        "sensitive": 7,
        "changed": 8,
        "test": 3,
        "smart_contract": 10,
        "evm_auth": 9,
        "evm_external_call": 10,
        "evm_upgrade": 9,
        "evm_value": 9,
        "evm_signature": 8,
        "evm_storage": 7,
    },
    "business_logic": {
        "business_logic": 10,
        "api": 7,
        "auth": 8,
        "data": 6,
        "changed": 8,
        "test": 5,
        "smart_contract": 9,
        "evm_value": 10,
        "evm_token": 8,
        "evm_oracle": 7,
        "evm_storage": 7,
    },
    "configuration": {
        "configuration": 10,
        "dependency": 10,
        "sensitive": 7,
        "network": 5,
        "changed": 6,
        "smart_contract": 6,
        "evm_upgrade": 9,
        "evm_oracle": 8,
        "evm_signature": 6,
    },
    "verifier": {
        "auth": 9,
        "api": 8,
        "data": 8,
        "test": 8,
        "changed": 7,
        "source": 3,
        "smart_contract": 8,
        "evm_auth": 9,
        "evm_external_call": 8,
        "evm_upgrade": 8,
        "evm_value": 8,
    },
    "judge": {
        "auth": 5,
        "api": 5,
        "data": 5,
        "configuration": 5,
        "test": 5,
        "changed": 6,
        "smart_contract": 7,
    },
}

_SPECIALIST_CATEGORY_WEIGHTS: dict[str, dict[str, int]] = {
    "access_control": {"evm_auth": 12, "auth": 10, "evm_upgrade": 7, "smart_contract": 8},
    "reentrancy_control_flow": {
        "evm_external_call": 12,
        "evm_value": 10,
        "evm_storage": 9,
        "smart_contract": 8,
    },
    "economic_game_theory": {
        "evm_value": 12,
        "evm_oracle": 10,
        "business_logic": 10,
        "evm_external_call": 8,
    },
    "oracle_price_manipulation": {
        "evm_oracle": 12,
        "evm_value": 10,
        "evm_external_call": 8,
    },
    "accounting_invariant": {"evm_value": 12, "evm_storage": 10, "business_logic": 9},
    "token_standard": {"evm_token": 12, "evm_value": 10, "evm_external_call": 8},
    "erc4626_vault": {"evm_value": 12, "evm_token": 10, "evm_storage": 9},
    "amm_dex_liquidity": {"evm_value": 12, "evm_oracle": 9, "evm_external_call": 10},
    "lending_liquidation": {"evm_value": 12, "evm_oracle": 10, "evm_storage": 9},
    "governance_timelock": {"evm_auth": 11, "evm_upgrade": 10, "business_logic": 9},
    "upgradeability_storage": {"evm_upgrade": 12, "evm_storage": 12, "evm_auth": 9},
    "initialization_deployment": {
        "evm_upgrade": 12,
        "evm_auth": 10,
        "configuration": 9,
        "smart_contract": 8,
    },
    "signature_permit_replay": {"evm_signature": 12, "evm_auth": 8, "evm_storage": 7},
    "mev_ordering": {"evm_value": 12, "evm_oracle": 9, "business_logic": 10},
    "denial_of_service_griefing": {
        "evm_external_call": 11,
        "business_logic": 10,
        "evm_storage": 8,
    },
    "precision_rounding": {"evm_value": 12, "evm_storage": 9, "business_logic": 8},
    "cross_chain_bridge": {"evm_signature": 10, "evm_value": 10, "evm_external_call": 9},
    "dependency_supply_chain": {
        "dependency": 12,
        "configuration": 11,
        "evm_upgrade": 7,
        "smart_contract": 5,
    },
    "formal_methods_property": {"evm_storage": 10, "evm_auth": 9, "evm_value": 9},
    "false_negative_hunter": {"smart_contract": 10, "changed": 8, "test": 5},
    "invariant_review": {
        "evm_storage": 12,
        "evm_value": 12,
        "evm_auth": 10,
        "evm_token": 9,
        "evm_oracle": 9,
        "smart_contract": 8,
    },
    "test_generation": {
        "smart_contract": 12,
        "test": 11,
        "evm_external_call": 10,
        "evm_value": 10,
    },
    "exploit_reproduction_planner": {
        "smart_contract": 12,
        "evm_external_call": 11,
        "evm_value": 11,
        "evm_auth": 10,
    },
    "falsifier": {
        "smart_contract": 12,
        "test": 10,
        "evm_auth": 10,
        "evm_value": 10,
    },
    "report_quality": {
        "smart_contract": 8,
        "changed": 8,
        "test": 8,
        "configuration": 8,
        "dependency": 8,
    },
}


def _role_weights(role: str) -> dict[str, int]:
    specialist = role.removeprefix("specialist:")
    return _ROLE_CATEGORY_WEIGHTS.get(
        role,
        _SPECIALIST_CATEGORY_WEIGHTS.get(specialist, {}),
    )


def _score(file: DiscoveredFile, role: str) -> tuple[int, str]:
    weights = _role_weights(role)
    score = sum(weights.get(category, 1) for category in file.categories)
    return (-score, file.relative_path)


_REPOSITORY_MAP_LIST_FIELDS = (
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
)


def _repository_map_list_inventory(
    repository_map: RepositoryMap,
    *,
    snapshot: _ContextInventorySnapshot | None = None,
) -> Iterable[dict[str, str] | _BoundInventoryIdentity]:
    for field_name in _REPOSITORY_MAP_LIST_FIELDS:
        for value in getattr(repository_map, field_name):
            if snapshot is not None:
                cached = snapshot.bound_identity(f"repository_map.{field_name}", value)
                if cached is not None:
                    yield cached
                    continue
            yield {"field": field_name, "value": value}
    for value in repository_map.omitted_files:
        if snapshot is not None:
            cached = snapshot.bound_identity("repository_map.omitted_files", value)
            if cached is not None:
                yield cached
                continue
        yield {"field": "omitted_files", "value": value}


@dataclass(frozen=True, slots=True)
class _RepositoryMapCompaction:
    """Provider map plus the retained inventory originating in its input map."""

    repository_map: RepositoryMap
    original_list_inventory: tuple[dict[str, str], ...]


def _compact_map(
    repository_map: RepositoryMap,
    role: str,
    max_files: int = 300,
    *,
    max_list_items: int = 100,
    preferred_paths: set[str] | None = None,
) -> _RepositoryMapCompaction:
    retained_paths = preferred_paths or set()
    sorted_files = sorted(
        repository_map.files,
        key=lambda file: (
            file.path not in retained_paths,
            -sum(_role_weights(role).get(category, 1) for category in file.categories),
            file.path,
        ),
    )
    retained_limit = max(
        max_files,
        sum(file.path in retained_paths for file in sorted_files),
    )
    selected_files = sorted_files[:retained_limit]
    list_limit = max(0, min(100, max_list_items))
    omitted = list(repository_map.omitted_files[:list_limit])
    if len(sorted_files) > len(selected_files) and list_limit > 0:
        omitted.append(
            f"repository map: {len(sorted_files) - len(selected_files)} file entries omitted"
        )
    compacted = repository_map.model_copy(
        update={
            "files": selected_files,
            "omitted_files": omitted,
            **{
                field_name: getattr(repository_map, field_name)[:list_limit]
                for field_name in _REPOSITORY_MAP_LIST_FIELDS
            },
        }
    )
    original_list_inventory = tuple(
        {
            "field": field_name,
            "value": value,
        }
        for field_name in _REPOSITORY_MAP_LIST_FIELDS
        for value in getattr(repository_map, field_name)[:list_limit]
    ) + tuple(
        {"field": "omitted_files", "value": value}
        for value in repository_map.omitted_files[:list_limit]
    )
    return _RepositoryMapCompaction(
        repository_map=compacted,
        original_list_inventory=original_list_inventory,
    )


_ENTITY_BACKED_MODEL_SURFACE_KINDS = frozenset(
    {
        ModelReviewSurfaceKind.CONTRACT,
        ModelReviewSurfaceKind.ENTRY_POINT,
        ModelReviewSurfaceKind.INTERNAL_FUNCTION,
        ModelReviewSurfaceKind.PRIVILEGE_FUNCTION,
        ModelReviewSurfaceKind.ASSET_FUNCTION,
        ModelReviewSurfaceKind.STATE,
    }
)


def _model_surface_entity_location(entity: SolidityEntity) -> Location:
    return Location(
        path=entity.path,
        start_line=entity.start_line,
        end_line=entity.end_line,
        symbol=entity.signature or entity.name,
        content_hash=entity.source_hash,
    )


def _model_surface_edge_location(edge: SolidityGraphEdge) -> Location:
    return Location(
        path=edge.path,
        start_line=edge.start_line,
        end_line=edge.end_line,
        content_hash=edge.source_hash,
    )


def _deterministic_entry_path(
    source_id: str,
    *,
    entities_by_id: Mapping[str, SolidityEntity],
    graphs: SolidityGraphSet,
) -> tuple[SolidityGraphEdge, ...]:
    """Return one stable shortest typed entry-to-source path, or fail closed."""

    entry_ids = tuple(
        sorted(
            entity.id
            for entity in entities_by_id.values()
            if entity.kind in {SolidityEntityKind.FUNCTION, SolidityEntityKind.CONSTRUCTOR}
            and (
                entity.kind is SolidityEntityKind.CONSTRUCTOR
                or entity.visibility in {"public", "external"}
            )
        )
    )
    if source_id in entry_ids:
        return ()
    outgoing: dict[str, list[SolidityGraphEdge]] = {}
    for edge in graphs.edges:
        if edge.source_id not in entities_by_id or edge.target_id not in entities_by_id:
            continue
        outgoing.setdefault(edge.source_id, []).append(edge)
    for edges in outgoing.values():
        edges.sort(key=model_review_edge_subject_id)

    pending = deque(entry_ids)
    predecessor: dict[str, tuple[str, SolidityGraphEdge] | None] = {
        entry_id: None for entry_id in entry_ids
    }
    while pending:
        current = pending.popleft()
        for edge in outgoing.get(current, ()):
            if edge.target_id in predecessor:
                continue
            predecessor[edge.target_id] = (current, edge)
            if edge.target_id == source_id:
                pending.clear()
                break
            pending.append(edge.target_id)
    if source_id not in predecessor:
        raise ContextBudgetError(
            "requested call surface lacks a deterministic public entry-to-source path"
        )

    path: list[SolidityGraphEdge] = []
    cursor = source_id
    previous_edge = predecessor[cursor]
    while previous_edge is not None:
        previous, edge = previous_edge
        path.append(edge)
        cursor = previous
        previous_edge = predecessor[cursor]
    return tuple(reversed(path))


def _required_model_surface_facts(
    requests: Iterable[ModelSurfaceReviewRequest],
    *,
    index: SoliditySymbolIndex | None,
    graphs: SolidityGraphSet | None,
) -> _RequiredModelSurfaceFacts:
    """Resolve exact typed facts before optional inventory can be compacted."""

    selected_requests = tuple(requests)
    source_paths = frozenset(
        location.path for request in selected_requests for location in request.allowed_locations
    )
    if not selected_requests:
        return _RequiredModelSurfaceFacts(
            entity_ids=frozenset(),
            graph_edges=(),
            graph_node_ids=frozenset(),
            source_locations=(),
            source_paths=source_paths,
        )

    entities_by_id = {entity.id: entity for entity in index.entities} if index else {}
    entity_ids: set[str] = set()
    required_edges: dict[str, SolidityGraphEdge] = {}
    graph_node_ids: set[str] = set()
    graph_nodes = {node.id for node in graphs.nodes} if graphs else set()
    source_locations: dict[tuple[str, int, int, str | None, str | None], Location] = {}

    def require_entity(entity_id: str) -> None:
        entity = entities_by_id.get(entity_id)
        if entity is None:
            return
        entity_ids.add(entity_id)
        location = _model_surface_entity_location(entity)
        source_locations[
            (
                location.path,
                location.start_line,
                location.end_line,
                location.symbol,
                location.content_hash,
            )
        ] = location

    def require_edge(edge: SolidityGraphEdge) -> None:
        required_edges[model_review_edge_subject_id(edge)] = edge
        require_entity(edge.source_id)
        if edge.target_id in entities_by_id:
            # The edge and its graph node carry the terminal identity. Keep the
            # target entity in typed metadata, but do not force unrelated target
            # source bytes into a shard whose requested terminal is the edge.
            entity_ids.add(edge.target_id)
        entity_endpoint_ids = {
            identifier
            for identifier in (edge.source_id, edge.target_id)
            if identifier in entities_by_id
        }
        if not entity_endpoint_ids <= graph_nodes:
            raise ContextBudgetError(
                "requested call reachability path lacks an exact entity graph node"
            )
        graph_node_ids.update(
            identifier
            for identifier in (edge.source_id, edge.target_id)
            if identifier in graph_nodes
        )
        location = _model_surface_edge_location(edge)
        source_locations[
            (
                location.path,
                location.start_line,
                location.end_line,
                location.symbol,
                location.content_hash,
            )
        ] = location

    for entity_id in tuple(entity_ids):
        require_entity(entity_id)
    for request in selected_requests:
        for location in request.allowed_locations:
            source_locations[
                (
                    location.path,
                    location.start_line,
                    location.end_line,
                    location.symbol,
                    location.content_hash,
                )
            ] = location

    for request in selected_requests:
        if request.kind in _ENTITY_BACKED_MODEL_SURFACE_KINDS:
            if index is None or request.subject_id not in entities_by_id:
                raise ContextBudgetError(
                    f"requested model surface {request.surface_id} lacks its exact index entity"
                )
            require_entity(request.subject_id)
        if request.kind is not ModelReviewSurfaceKind.CALL:
            continue
        if index is None or graphs is None:
            raise ContextBudgetError(
                f"requested call surface {request.surface_id} lacks typed index or graph facts"
            )
        matching_edges = tuple(
            edge
            for edge in graphs.edges
            if model_review_edge_subject_id(edge) == request.subject_id
        )
        if len(matching_edges) != 1:
            raise ContextBudgetError(
                f"requested call surface {request.surface_id} does not resolve one exact graph edge"
            )
        edge = matching_edges[0]
        if not any(
            location.path == edge.path
            and location.start_line == edge.start_line
            and location.end_line == edge.end_line
            and location.content_hash == edge.source_hash
            for location in request.allowed_locations
        ):
            raise ContextBudgetError(
                f"requested call surface {request.surface_id} lacks its exact edge location hash"
            )
        if edge.source_id not in entities_by_id:
            raise ContextBudgetError(
                f"requested call surface {request.surface_id} lacks its exact source entity"
            )
        for reachability_edge in _deterministic_entry_path(
            edge.source_id,
            entities_by_id=entities_by_id,
            graphs=graphs,
        ):
            require_edge(reachability_edge)
        require_edge(edge)

    ordered_source_locations = tuple(
        sorted(
            source_locations.values(),
            key=lambda location: (
                location.path,
                location.start_line,
                location.end_line,
                location.symbol or "",
                location.content_hash or "",
            ),
        )
    )

    return _RequiredModelSurfaceFacts(
        entity_ids=frozenset(entity_ids),
        graph_edges=tuple(required_edges[key] for key in sorted(required_edges)),
        graph_node_ids=frozenset(graph_node_ids),
        source_locations=ordered_source_locations,
        source_paths=frozenset(location.path for location in ordered_source_locations),
    )


def _require_requested_source_inventory(
    locations: Iterable[Location],
    *,
    safe_files: Iterable[DiscoveredFile],
) -> tuple[tuple[str, int, int, str], ...]:
    """Reject stale or unavailable requested locations before context allocation."""

    sources = {item.relative_path: item for item in safe_files}
    identities: dict[str, tuple[str, int, int, str]] = {}
    for location in locations:
        source = sources.get(location.path)
        if source is None:
            raise ContextBudgetError("requested model surface lacks safe source evidence")
        if location.content_hash is not None and location.content_hash != line_range_hash(
            source.content,
            location.start_line,
            location.end_line,
        ):
            raise ContextBudgetError("requested model surface has a stale source hash")
        encoded = source.content.encode("utf-8")
        identities[source.relative_path] = (
            source.relative_path,
            len(encoded),
            len(source.content.splitlines()),
            hashlib.sha256(encoded).hexdigest(),
        )
    return tuple(identities[path] for path in sorted(identities))


def _require_model_surface_fact_custody(
    package: ContextPackage,
    *,
    required: _RequiredModelSurfaceFacts,
) -> None:
    """Enforce exact deterministic and source custody immediately before transport."""

    retained_entities = (
        {entity.id for entity in package.solidity_index.entities}
        if package.solidity_index
        else set()
    )
    if not required.entity_ids <= retained_entities:
        raise ContextBudgetError("context compaction omitted a required model-surface entity")
    retained_edge_subjects = (
        {model_review_edge_subject_id(edge) for edge in package.solidity_graphs.edges}
        if package.solidity_graphs
        else set()
    )
    required_edge_subjects = {model_review_edge_subject_id(edge) for edge in required.graph_edges}
    if not required_edge_subjects <= retained_edge_subjects:
        raise ContextBudgetError("context compaction omitted a required model-surface graph edge")
    retained_node_ids = (
        {node.id for node in package.solidity_graphs.nodes} if package.solidity_graphs else set()
    )
    if not required.graph_node_ids <= retained_node_ids:
        raise ContextBudgetError("context compaction omitted a required model-surface graph node")

    map_records_by_path: dict[str, list[Any]] = {}
    for item in package.repository_map.files:
        map_records_by_path.setdefault(item.path, []).append(item)
    for identity in required.source_file_identities:
        records = map_records_by_path.get(identity[0], [])
        if (
            len(records) != 1
            or (
                records[0].path,
                records[0].size,
                records[0].lines,
                records[0].sha256,
            )
            != identity
        ):
            raise ContextBudgetError(
                "context compaction omitted a required model-surface source identity"
            )
    for location in required.source_locations:
        location_proven = any(
            excerpt_proves_location(excerpt, location)
            if location.content_hash is not None
            else (
                excerpt.path == location.path
                and excerpt.start_line <= location.start_line
                and excerpt.end_line >= location.end_line
            )
            for excerpt in package.excerpts
        )
        if not location_proven:
            raise ContextBudgetError(
                "context compaction omitted a required model-surface source range"
            )
    _require_source_file_review_custody(package)


def _require_source_file_review_custody(package: ContextPackage) -> None:
    """Require exact whole-file map and excerpt evidence before provider spend."""

    for request in package.requested_model_surfaces:
        if request.kind is not ModelReviewSurfaceKind.SOURCE_FILE:
            continue
        if len(request.allowed_locations) != 1:
            raise ContextBudgetError("source-file review lacks one exact whole-file location")
        location = request.allowed_locations[0]
        records = tuple(item for item in package.repository_map.files if item.path == location.path)
        if len(records) != 1:
            raise ContextBudgetError("source-file review lacks one repository source identity")
        source = records[0]
        expected_end_line = max(1, source.lines)
        if (
            location.start_line != 1
            or location.end_line != expected_end_line
            or location.content_hash != source.sha256
        ):
            raise ContextBudgetError("source-file review location differs from repository identity")
        if not any(
            excerpt.path == source.path
            and excerpt.start_line == 1
            and excerpt.end_line == expected_end_line
            and not excerpt.omitted_before
            and not excerpt.omitted_after
            and len(excerpt.content.encode("utf-8")) == source.size
            and excerpt.content_hash == source.sha256
            and hashlib.sha256(excerpt.content.encode("utf-8")).hexdigest() == source.sha256
            for excerpt in package.excerpts
        ):
            raise ContextBudgetError("source-file review lacks exact whole-file excerpt bytes")


class ContextBuilder:
    """Prepare all potential source locally before any model request is possible."""

    def __init__(
        self,
        *,
        discovery: DiscoveryResult,
        repository_map: RepositoryMap,
        repository_config: RepositoryConfig,
        privacy: PrivacyConfig,
        scanner_findings: list[ScannerFinding],
        scanner_secret_paths: set[str] | None = None,
        solidity_projects: list[SolidityProjectMetadata] | None = None,
        solidity_compilations: list[SolidityCompilationResult] | None = None,
        solidity_index: SoliditySymbolIndex | None = None,
        solidity_graphs: SolidityGraphSet | None = None,
        solidity_invariants: InvariantSuite | None = None,
        invariant_executions: list[InvariantExecutionResult] | None = None,
        economic_simulations: list[EconomicSimulationPlan] | None = None,
        formal_runs: list[FormalToolRun] | None = None,
        solidity_coverage: SolidityCoverage | None = None,
        planned_packages: int = 6,
        maximum_source_tokens_per_request: int = 200_000,
    ) -> None:
        self.discovery = discovery
        self.repository_config = repository_config
        self.privacy = privacy
        self._scanner_secret_paths = {
            *(scanner_secret_paths or set()),
            *(
                location.path
                for finding in scanner_findings
                if finding.scanner == "gitleaks" or finding.metadata.get("class") == "secret"
                for location in finding.locations
            ),
        }
        if self._scanner_secret_paths and privacy.fail_on_detected_secret:
            raise SecretSafetyError(
                "deterministic scanner detected a potential secret in model-eligible source; "
                "model egress blocked"
            )
        self._safe_files = self._redact_every_file(discovery.files)
        safe_paths = {item.relative_path for item in self._safe_files}
        self._repository_map = self._safe_repository_map(
            repository_map,
            safe_paths,
        ).model_copy(deep=True)
        self._scanner_findings = [
            finding.model_copy(deep=True)
            for finding in self._redact_scanner_findings(
                scanner_findings,
                safe_paths,
            )
        ]
        self._solidity_projects = [
            project.model_copy(deep=True) for project in (solidity_projects or ())
        ]
        self._solidity_compilations = [
            compilation.model_copy(deep=True) for compilation in (solidity_compilations or ())
        ]
        self._solidity_index = solidity_index.model_copy(deep=True) if solidity_index else None
        self._solidity_graphs = solidity_graphs.model_copy(deep=True) if solidity_graphs else None
        self._solidity_invariants = (
            solidity_invariants.model_copy(deep=True) if solidity_invariants else None
        )
        self._invariant_executions = [
            execution.model_copy(deep=True) for execution in (invariant_executions or ())
        ]
        self._economic_simulations = [
            simulation.model_copy(deep=True) for simulation in (economic_simulations or ())
        ]
        self._formal_runs = [run.model_copy(deep=True) for run in (formal_runs or ())]
        self._solidity_coverage = (
            solidity_coverage.model_copy(deep=True) if solidity_coverage else None
        )
        self._inventory_snapshot = _ContextInventorySnapshot.capture(
            repository_map=self._repository_map,
            scanner_findings=self._scanner_findings,
            solidity_projects=self._solidity_projects,
            solidity_compilations=self._solidity_compilations,
            solidity_index=self._solidity_index,
            solidity_graphs=self._solidity_graphs,
            solidity_invariants=self._solidity_invariants,
            invariant_executions=self._invariant_executions,
            economic_simulations=self._economic_simulations,
            formal_runs=self._formal_runs,
            solidity_coverage=self._solidity_coverage,
        )
        self.planned_packages = max(1, planned_packages)
        if (
            isinstance(maximum_source_tokens_per_request, bool)
            or maximum_source_tokens_per_request <= 0
        ):
            raise ContextBudgetError("maximum source token budget must be positive")
        self.maximum_source_tokens_per_request = maximum_source_tokens_per_request

    @property
    def repository_map(self) -> RepositoryMap:
        """Return a detached view; builder-owned cached inventory is never exposed."""

        return self._repository_map.model_copy(deep=True)

    @property
    def scanner_findings(self) -> list[ScannerFinding]:
        return [finding.model_copy(deep=True) for finding in self._scanner_findings]

    @property
    def solidity_projects(self) -> list[SolidityProjectMetadata]:
        return [project.model_copy(deep=True) for project in self._solidity_projects]

    @property
    def solidity_compilations(self) -> list[SolidityCompilationResult]:
        return [compilation.model_copy(deep=True) for compilation in self._solidity_compilations]

    @property
    def solidity_index(self) -> SoliditySymbolIndex | None:
        return self._solidity_index.model_copy(deep=True) if self._solidity_index else None

    @property
    def solidity_graphs(self) -> SolidityGraphSet | None:
        return self._solidity_graphs.model_copy(deep=True) if self._solidity_graphs else None

    @property
    def solidity_invariants(self) -> InvariantSuite | None:
        return (
            self._solidity_invariants.model_copy(deep=True) if self._solidity_invariants else None
        )

    @property
    def invariant_executions(self) -> list[InvariantExecutionResult]:
        return [execution.model_copy(deep=True) for execution in self._invariant_executions]

    @property
    def economic_simulations(self) -> list[EconomicSimulationPlan]:
        return [simulation.model_copy(deep=True) for simulation in self._economic_simulations]

    @property
    def formal_runs(self) -> list[FormalToolRun]:
        return [run.model_copy(deep=True) for run in self._formal_runs]

    @property
    def solidity_coverage(self) -> SolidityCoverage | None:
        return self._solidity_coverage.model_copy(deep=True) if self._solidity_coverage else None

    def _redact_every_file(self, files: Iterable[DiscoveredFile]) -> tuple[DiscoveredFile, ...]:
        safe: list[DiscoveredFile] = []
        for item in files:
            if item.relative_path in self._scanner_secret_paths:
                continue
            path_matches = detect_secrets(item.relative_path)
            if any(match.confidence == "high" for match in path_matches):
                redact_text(
                    item.relative_path,
                    fail_on_detected_secret=self.privacy.fail_on_detected_secret,
                    redact=False,
                )
            if path_matches:
                continue
            redacted, _matches = redact_text(
                item.content,
                fail_on_detected_secret=self.privacy.fail_on_detected_secret,
                redact=self.privacy.redact_secrets,
            )
            safe.append(replace(item, content=redacted, size=len(redacted.encode())))
        return tuple(safe)

    def _safe_repository_map(
        self,
        repository_map: RepositoryMap,
        safe_paths: set[str],
    ) -> RepositoryMap:
        path_fields = (
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
        )
        updates: dict[str, Any] = {
            field: [path for path in getattr(repository_map, field) if path in safe_paths]
            for field in path_fields
        }
        updates["files"] = [file for file in repository_map.files if file.path in safe_paths]
        updates["root_name"] = self._redact_string(repository_map.root_name)
        updates["changed_since"] = (
            self._redact_string(repository_map.changed_since)
            if repository_map.changed_since
            else None
        )
        updates["omitted_files"] = [
            self._redact_string(value) for value in repository_map.omitted_files
        ]
        omitted_path_count = len(repository_map.files) - len(updates["files"])
        if omitted_path_count:
            updates["omitted_files"].append(
                f"{omitted_path_count} file(s) withheld by local secret safeguards"
            )
        return repository_map.model_copy(update=updates)

    def _redact_scanner_findings(
        self,
        scanner_findings: list[ScannerFinding],
        safe_paths: set[str],
    ) -> list[ScannerFinding]:
        safe: list[ScannerFinding] = []
        for finding in scanner_findings:
            locations = [location for location in finding.locations if location.path in safe_paths]
            if not locations:
                continue
            safe.append(
                finding.model_copy(
                    update={
                        "rule_id": self._redact_string(finding.rule_id),
                        "title": self._redact_string(finding.title),
                        "message": self._redact_string(finding.message),
                        "locations": locations,
                        "metadata": self._redact_value(finding.metadata),
                    }
                )
            )
        return safe

    def _redact_string(self, value: str) -> str:
        redacted, _matches = redact_text(
            value,
            fail_on_detected_secret=self.privacy.fail_on_detected_secret,
            redact=self.privacy.redact_secrets,
        )
        return redacted

    def _redact_value(
        self,
        value: Any,
        *,
        _active_containers: set[int] | None = None,
        _depth: int = 0,
    ) -> Any:
        """Return only deterministic JSON-compatible scanner metadata.

        Scanner findings are untrusted tool output. Pydantic's ``Any`` metadata
        values may otherwise retain opaque Python objects until prompt
        serialization, where they can escape the typed context-failure path.
        Unsupported, cyclic, non-finite, and excessively nested values are
        represented as JSON ``null`` without retaining object representations.
        """

        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, str):
            redacted = self._redact_string(value)
            return redacted.encode("utf-8", errors="replace").decode("utf-8")
        if isinstance(value, int):
            return value if -(2**63) <= value <= 2**63 - 1 else None
        if isinstance(value, float):
            return value if math.isfinite(value) else None
        if _depth >= 32:
            return None
        active_containers = _active_containers if _active_containers is not None else set()
        if isinstance(value, (list, tuple)):
            identity = id(value)
            if identity in active_containers:
                return None
            active_containers.add(identity)
            try:
                return [
                    self._redact_value(
                        item,
                        _active_containers=active_containers,
                        _depth=_depth + 1,
                    )
                    for item in value
                ]
            finally:
                active_containers.remove(identity)
        if isinstance(value, dict):
            identity = id(value)
            if identity in active_containers:
                return None
            active_containers.add(identity)
            try:
                return {
                    self._redact_string(key)
                    .encode("utf-8", errors="replace")
                    .decode("utf-8"): self._redact_value(
                        item,
                        _active_containers=active_containers,
                        _depth=_depth + 1,
                    )
                    for key, item in value.items()
                    if isinstance(key, str)
                }
            finally:
                active_containers.remove(identity)
        return None

    @property
    def remaining_bytes(self) -> int:
        """Return the per-package serialization ceiling kept for compatibility."""

        return self.repository_config.max_total_context_bytes

    def build(
        self,
        role: str,
        *,
        threat_model: ThreatModel | None = None,
        requested_budget: int | None = None,
        preferred_paths: set[str] | None = None,
        allowed_source_paths: set[str] | None = None,
        requested_model_surfaces: list[ModelSurfaceReviewRequest] | None = None,
        request_model_surface_reviews: bool = False,
    ) -> ContextPackage:
        """Allocate one independently bounded package."""

        if request_model_surface_reviews and requested_model_surfaces is not None:
            raise ContextBudgetError("model surface requests cannot be both derived and supplied")
        scoped_safe_files = self._safe_files
        scope_excluded_files: list[DiscoveredFile] = []
        if allowed_source_paths is not None:
            if not allowed_source_paths:
                raise ContextBudgetError("shard source allowlist cannot be empty")
            try:
                normalized_allowed_paths = {
                    normalize_relative_path(path) for path in allowed_source_paths
                }
            except ValueError as exc:
                raise ContextBudgetError("shard source allowlist contains an unsafe path") from exc
            if normalized_allowed_paths != allowed_source_paths:
                raise ContextBudgetError("shard source allowlist paths must be normalized")
            available_paths = {item.relative_path for item in self._safe_files}
            unknown_paths = normalized_allowed_paths - available_paths
            if unknown_paths:
                raise ContextBudgetError(
                    "shard source allowlist contains a path outside the safe discovery inventory"
                )
            scoped_safe_files = tuple(
                item for item in self._safe_files if item.relative_path in normalized_allowed_paths
            )
            scope_excluded_files = [
                item
                for item in self._safe_files
                if item.relative_path not in normalized_allowed_paths
            ]
        # The source limit is an estimated-token planning ceiling, while the
        # package budget covers source plus deterministic metadata. The provider
        # planner independently reserves the full UTF-8 byte upper bound before
        # transport, so allowing the deterministic byte/3 estimate here cannot
        # overrun an endpoint.
        source_byte_ceiling = min(
            2**31 - 1,
            self.maximum_source_tokens_per_request * UTF8_BYTES_PER_ESTIMATED_TOKEN,
        )
        default_share = self.repository_config.max_total_context_bytes
        budget = min(
            default_share if requested_budget is None else requested_budget,
            self.repository_config.max_total_context_bytes,
        )
        if budget <= 0:
            raise ContextBudgetError("repository context package budget is invalid")
        omissions: dict[
            tuple[ContextOmissionCategory, ContextOmissionReason],
            ContextOmissionAccumulator,
        ] = {}

        def omit(
            category: ContextOmissionCategory,
            reason: ContextOmissionReason,
            identity: Any,
        ) -> None:
            _add_context_omission(
                omissions,
                category=category,
                reason=reason,
                identity=identity,
            )

        def omit_inventory_reduction(
            category: ContextOmissionCategory,
            *,
            kind: str,
            before: Iterable[Any],
            after: Iterable[Any],
        ) -> None:
            retained = Counter(self._inventory_snapshot.item_sha256(item) for item in after)
            for item in before:
                item_sha256 = self._inventory_snapshot.item_sha256(item)
                if retained[item_sha256] > 0:
                    retained[item_sha256] -= 1
                    continue
                omit(
                    category,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    {
                        "kind": kind,
                        "item_sha256": item_sha256,
                    },
                )

        def omit_inventory_items(
            category: ContextOmissionCategory,
            *,
            reason: ContextOmissionReason = ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
            kind: str,
            items: Iterable[Any],
        ) -> None:
            """Stream one exact omission event per removed inventory item."""

            for item in items:
                omit(
                    category,
                    reason,
                    {
                        "kind": kind,
                        "item_sha256": self._inventory_snapshot.item_sha256(item),
                    },
                )

        def omit_remaining_source_files(
            current: DiscoveredFile,
            remaining: Iterable[DiscoveredFile],
            *,
            cause: str,
        ) -> None:
            """Commit the unprocessed source suffix without retaining a second inventory."""

            for excluded_item in chain((current,), remaining):
                encoded = excluded_item.content.encode("utf-8")
                omit(
                    ContextOmissionCategory.SOURCE,
                    ContextOmissionReason.SOURCE_BUDGET_EXCLUDED,
                    {
                        "kind": "source_inventory_item_excluded",
                        "cause": cause,
                        "item": {
                            "path_sha256": hashlib.sha256(
                                excluded_item.relative_path.encode("utf-8")
                            ).hexdigest(),
                            "content_sha256": hashlib.sha256(encoded).hexdigest(),
                            "utf8_bytes": len(encoded),
                        },
                    },
                )

        file_limit = min(300, len(self._repository_map.files))
        map_list_limit = 100
        scanner_limit = min(200, len(self._scanner_findings))
        entity_limit = 500
        graph_edge_limit = 700
        include_solidity_index = self._solidity_index is not None
        include_solidity_graphs = self._solidity_graphs is not None
        included_threat_model = threat_model
        included_solidity_projects = list(self._solidity_projects)
        included_solidity_compilations = list(self._solidity_compilations)
        selected_model_surfaces = list(requested_model_surfaces or [])
        if request_model_surface_reviews:
            selected_model_surfaces = build_model_surface_requests(
                index=self._solidity_index,
                graphs=self._solidity_graphs,
                invariants=self._solidity_invariants,
                economic_simulations=self._economic_simulations,
            )
        required_surface_facts = _required_model_surface_facts(
            selected_model_surfaces,
            index=self._solidity_index,
            graphs=self._solidity_graphs,
        )
        required_surface_facts = replace(
            required_surface_facts,
            source_file_identities=_require_requested_source_inventory(
                required_surface_facts.source_locations,
                safe_files=self._safe_files,
            ),
        )
        review_request_mode = bool(selected_model_surfaces) or request_model_surface_reviews
        included_solidity_invariants = None if review_request_mode else self._solidity_invariants
        included_invariant_executions = (
            [] if review_request_mode else list(self._invariant_executions)
        )
        included_economic_simulations = (
            [] if review_request_mode else list(self._economic_simulations)
        )
        included_formal_runs = [] if review_request_mode else list(self._formal_runs)
        included_solidity_coverage = None if review_request_mode else self._solidity_coverage
        initial_compaction_recorded = False
        deterministic_preferred_paths = set(preferred_paths or set())
        deterministic_preferred_paths.update(
            location.path
            for request in selected_model_surfaces
            for location in request.allowed_locations
        )
        deterministic_preferred_paths.update(required_surface_facts.source_paths)
        if allowed_source_paths is not None and not deterministic_preferred_paths <= set(
            allowed_source_paths
        ):
            outside_paths = sorted(deterministic_preferred_paths - set(allowed_source_paths))
            raise ContextBudgetError(
                "requested or preferred source lies outside the shard source allowlist: "
                + ", ".join(outside_paths[:8])
                + (" (additional paths omitted)" if len(outside_paths) > 8 else "")
            )
        for excluded_item in scope_excluded_files:
            encoded = excluded_item.content.encode("utf-8")
            omit(
                ContextOmissionCategory.SOURCE,
                ContextOmissionReason.SHARD_SCOPE_WITHHELD,
                {
                    "kind": "source_inventory_item_outside_shard_scope",
                    "item": {
                        "path_sha256": hashlib.sha256(
                            excluded_item.relative_path.encode("utf-8")
                        ).hexdigest(),
                        "content_sha256": hashlib.sha256(encoded).hexdigest(),
                        "utf8_bytes": len(encoded),
                    },
                },
            )
        available_source_bytes = min(
            source_byte_ceiling,
            sum(len(item.content.encode("utf-8")) for item in scoped_safe_files),
        )
        source_serialization_capacity = min(
            max(0, budget - 1),
            available_source_bytes + (8_192 if available_source_bytes else 0),
        )
        minimum_source_reserve = min(8_192, source_serialization_capacity)
        source_reserve = min(
            max(0, budget - 1),
            source_serialization_capacity,
            max(minimum_source_reserve, (budget * 65) // 100),
        )
        metadata_ceiling = max(1, budget - source_reserve)
        if review_request_mode:
            if self._solidity_invariants is not None:
                omit_inventory_items(
                    ContextOmissionCategory.METADATA,
                    reason=ContextOmissionReason.REVIEW_CONTRACT_WITHHELD,
                    kind="review_contract_solidity_invariants_withheld",
                    items=(self._solidity_invariants,),
                )
            omit_inventory_items(
                ContextOmissionCategory.METADATA,
                reason=ContextOmissionReason.REVIEW_CONTRACT_WITHHELD,
                kind="review_contract_invariant_execution_withheld",
                items=self._invariant_executions,
            )
            omit_inventory_items(
                ContextOmissionCategory.METADATA,
                reason=ContextOmissionReason.REVIEW_CONTRACT_WITHHELD,
                kind="review_contract_economic_simulation_withheld",
                items=self._economic_simulations,
            )
            omit_inventory_items(
                ContextOmissionCategory.METADATA,
                reason=ContextOmissionReason.REVIEW_CONTRACT_WITHHELD,
                kind="review_contract_formal_run_withheld",
                items=self._formal_runs,
            )
            if self._solidity_coverage is not None:
                omit_inventory_items(
                    ContextOmissionCategory.METADATA,
                    reason=ContextOmissionReason.REVIEW_CONTRACT_WITHHELD,
                    kind="review_contract_solidity_coverage_withheld",
                    items=(self._solidity_coverage,),
                )
        minimum_compact_limit = 8 if review_request_mode else 32
        preserve_invariant_index = role.removeprefix("specialist:") == "invariant_review"
        while True:
            compact_map_result = _compact_map(
                self._repository_map,
                role,
                max_files=file_limit,
                max_list_items=map_list_limit,
                preferred_paths=deterministic_preferred_paths,
            )
            compact_map = compact_map_result.repository_map
            selected_scanners = self._scanner_findings[:scanner_limit]
            compact_index = compact_solidity_index(
                self._solidity_index if include_solidity_index else None,
                role=role,
                max_entities=entity_limit,
                preferred_paths=deterministic_preferred_paths,
                required_entity_ids=set(required_surface_facts.entity_ids),
            )
            compact_graphs = compact_solidity_graphs(
                self._solidity_graphs if include_solidity_graphs else None,
                role=role,
                max_edges=graph_edge_limit,
                preferred_paths=deterministic_preferred_paths,
                required_edges=required_surface_facts.graph_edges,
            )
            if not initial_compaction_recorded:
                omit_inventory_reduction(
                    ContextOmissionCategory.METADATA,
                    kind="initial_repository_map_file_excluded",
                    before=self._repository_map.files,
                    after=compact_map.files,
                )
                omit_inventory_reduction(
                    ContextOmissionCategory.METADATA,
                    kind="initial_repository_map_list_item_excluded",
                    before=_repository_map_list_inventory(
                        self._repository_map,
                        snapshot=self._inventory_snapshot,
                    ),
                    after=compact_map_result.original_list_inventory,
                )
                omit_inventory_reduction(
                    ContextOmissionCategory.SCANNER,
                    kind="initial_scanner_finding_excluded",
                    before=self._scanner_findings,
                    after=selected_scanners,
                )
                omit_inventory_reduction(
                    ContextOmissionCategory.FRAMEWORK,
                    kind="initial_solidity_index_item_excluded",
                    before=_solidity_index_compaction_inventory(
                        self._solidity_index,
                        snapshot=self._inventory_snapshot,
                    ),
                    after=_solidity_index_compaction_inventory(
                        compact_index,
                        snapshot=self._inventory_snapshot,
                    ),
                )
                omit_inventory_reduction(
                    ContextOmissionCategory.GRAPH,
                    kind="initial_solidity_graph_item_excluded",
                    before=_solidity_graph_compaction_inventory(
                        self._solidity_graphs,
                        snapshot=self._inventory_snapshot,
                    ),
                    after=_solidity_graph_compaction_inventory(
                        compact_graphs,
                        snapshot=self._inventory_snapshot,
                    ),
                )
                initial_compaction_recorded = True
            base_package = ContextPackage(
                role=role,
                byte_budget=budget,
                bytes_used=0,
                configured_maximum_source_tokens_per_request=(
                    self.maximum_source_tokens_per_request
                ),
                effective_source_byte_ceiling=min(source_byte_ceiling, budget),
                repository_map=compact_map,
                scanner_findings=selected_scanners,
                excerpts=[],
                requested_model_surfaces=selected_model_surfaces,
                threat_model=included_threat_model,
                solidity_projects=included_solidity_projects,
                solidity_compilations=included_solidity_compilations,
                solidity_index=compact_index,
                solidity_graphs=compact_graphs,
                solidity_invariants=(None if review_request_mode else included_solidity_invariants),
                invariant_executions=([] if review_request_mode else included_invariant_executions),
                economic_simulations=([] if review_request_mode else included_economic_simulations),
                formal_runs=[] if review_request_mode else included_formal_runs,
                solidity_coverage=(None if review_request_mode else included_solidity_coverage),
                omissions=_canonical_context_omissions(omissions),
            )
            base_bytes = len(render_context(base_package).encode("utf-8"))
            if base_bytes <= metadata_ceiling:
                break
            if (
                compact_graphs is not None
                and compact_graphs.edges
                and graph_edge_limit > minimum_compact_limit
            ):
                next_limit = max(minimum_compact_limit, graph_edge_limit // 2)
                next_graphs = compact_solidity_graphs(
                    self._solidity_graphs,
                    role=role,
                    max_edges=next_limit,
                    preferred_paths=deterministic_preferred_paths,
                    required_edges=required_surface_facts.graph_edges,
                )
                graph_edge_limit = next_limit
                if compact_graphs == next_graphs:
                    continue
                omit_inventory_reduction(
                    ContextOmissionCategory.GRAPH,
                    kind="solidity_graph_item_excluded",
                    before=_solidity_graph_compaction_inventory(
                        compact_graphs,
                        snapshot=self._inventory_snapshot,
                    ),
                    after=_solidity_graph_compaction_inventory(
                        next_graphs,
                        snapshot=self._inventory_snapshot,
                    ),
                )
            elif include_solidity_graphs and not required_surface_facts.graph_edges:
                include_solidity_graphs = False
                if compact_graphs is None:
                    continue
                original_graphs = self._solidity_graphs
                if original_graphs is None:
                    raise ContextBudgetError("Solidity graph compaction state is inconsistent")
                omit_inventory_items(
                    ContextOmissionCategory.GRAPH,
                    kind="solidity_graph_item_excluded",
                    items=_retained_solidity_graph_inventory(
                        compact_graphs,
                        original=original_graphs,
                        snapshot=self._inventory_snapshot,
                    ),
                )
            elif preserve_invariant_index and included_formal_runs:
                before_formal_runs = included_formal_runs
                included_formal_runs = []
                omit_inventory_items(
                    ContextOmissionCategory.INVARIANT,
                    kind="formal_run_excluded",
                    items=before_formal_runs,
                )
            elif preserve_invariant_index and included_economic_simulations:
                before_economic_simulations = included_economic_simulations
                included_economic_simulations = []
                omit_inventory_items(
                    ContextOmissionCategory.INVARIANT,
                    kind="economic_simulation_excluded",
                    items=before_economic_simulations,
                )
            elif preserve_invariant_index and included_invariant_executions:
                before_invariant_executions = included_invariant_executions
                included_invariant_executions = []
                omit_inventory_items(
                    ContextOmissionCategory.INVARIANT,
                    kind="invariant_execution_excluded",
                    items=before_invariant_executions,
                )
            elif preserve_invariant_index and included_solidity_coverage is not None:
                before_solidity_coverage = included_solidity_coverage
                included_solidity_coverage = None
                omit_inventory_items(
                    ContextOmissionCategory.FRAMEWORK,
                    kind="solidity_coverage_excluded",
                    items=(before_solidity_coverage,),
                )
            elif preserve_invariant_index and included_solidity_compilations:
                before_solidity_compilations = included_solidity_compilations
                included_solidity_compilations = []
                omit_inventory_items(
                    ContextOmissionCategory.FRAMEWORK,
                    kind="solidity_compilation_excluded",
                    items=before_solidity_compilations,
                )
            elif preserve_invariant_index and included_solidity_projects:
                before_solidity_projects = included_solidity_projects
                included_solidity_projects = []
                omit_inventory_items(
                    ContextOmissionCategory.FRAMEWORK,
                    kind="solidity_project_excluded",
                    items=before_solidity_projects,
                )
            elif (
                compact_index is not None
                and compact_index.entities
                and entity_limit > minimum_compact_limit
            ):
                next_limit = max(minimum_compact_limit, entity_limit // 2)
                next_index = compact_solidity_index(
                    self._solidity_index,
                    role=role,
                    max_entities=next_limit,
                    preferred_paths=deterministic_preferred_paths,
                    required_entity_ids=set(required_surface_facts.entity_ids),
                )
                entity_limit = next_limit
                if compact_index == next_index:
                    continue
                omit_inventory_reduction(
                    ContextOmissionCategory.FRAMEWORK,
                    kind="solidity_index_item_excluded",
                    before=_solidity_index_compaction_inventory(
                        compact_index,
                        snapshot=self._inventory_snapshot,
                    ),
                    after=_solidity_index_compaction_inventory(
                        next_index,
                        snapshot=self._inventory_snapshot,
                    ),
                )
            elif include_solidity_index and not required_surface_facts.entity_ids:
                include_solidity_index = False
                if compact_index is None:
                    continue
                original_index = self._solidity_index
                if original_index is None:
                    raise ContextBudgetError("Solidity index compaction state is inconsistent")
                omit_inventory_items(
                    ContextOmissionCategory.FRAMEWORK,
                    kind="solidity_index_item_excluded",
                    items=_retained_solidity_index_inventory(
                        compact_index,
                        original=original_index,
                        snapshot=self._inventory_snapshot,
                    ),
                )
            elif included_formal_runs:
                before_formal_runs = included_formal_runs
                included_formal_runs = []
                omit_inventory_items(
                    ContextOmissionCategory.INVARIANT,
                    kind="formal_run_excluded",
                    items=before_formal_runs,
                )
            elif included_economic_simulations:
                before_economic_simulations = included_economic_simulations
                included_economic_simulations = []
                omit_inventory_items(
                    ContextOmissionCategory.INVARIANT,
                    kind="economic_simulation_excluded",
                    items=before_economic_simulations,
                )
            elif included_invariant_executions:
                before_invariant_executions = included_invariant_executions
                included_invariant_executions = []
                omit_inventory_items(
                    ContextOmissionCategory.INVARIANT,
                    kind="invariant_execution_excluded",
                    items=before_invariant_executions,
                )
            elif included_solidity_invariants is not None:
                before_solidity_invariants = included_solidity_invariants
                included_solidity_invariants = None
                omit_inventory_items(
                    ContextOmissionCategory.INVARIANT,
                    kind="solidity_invariant_suite_excluded",
                    items=(before_solidity_invariants,),
                )
            elif included_solidity_coverage is not None:
                before_solidity_coverage = included_solidity_coverage
                included_solidity_coverage = None
                omit_inventory_items(
                    ContextOmissionCategory.FRAMEWORK,
                    kind="solidity_coverage_excluded",
                    items=(before_solidity_coverage,),
                )
            elif included_solidity_compilations:
                before_solidity_compilations = included_solidity_compilations
                included_solidity_compilations = []
                omit_inventory_items(
                    ContextOmissionCategory.FRAMEWORK,
                    kind="solidity_compilation_excluded",
                    items=before_solidity_compilations,
                )
            elif included_solidity_projects:
                before_solidity_projects = included_solidity_projects
                included_solidity_projects = []
                omit_inventory_items(
                    ContextOmissionCategory.FRAMEWORK,
                    kind="solidity_project_excluded",
                    items=before_solidity_projects,
                )
            elif scanner_limit:
                next_limit = scanner_limit // 2
                next_scanners = self._scanner_findings[:next_limit]
                scanner_limit = next_limit
                if selected_scanners == next_scanners:
                    continue
                omit_inventory_reduction(
                    ContextOmissionCategory.SCANNER,
                    kind="scanner_finding_excluded",
                    before=selected_scanners,
                    after=next_scanners,
                )
            elif file_limit:
                next_limit = file_limit // 2
                next_map_result = _compact_map(
                    self._repository_map,
                    role,
                    max_files=next_limit,
                    max_list_items=map_list_limit,
                    preferred_paths=deterministic_preferred_paths,
                )
                next_map = next_map_result.repository_map
                file_limit = next_limit
                if compact_map == next_map:
                    continue
                omit_inventory_reduction(
                    ContextOmissionCategory.METADATA,
                    kind="repository_map_file_excluded",
                    before=compact_map.files,
                    after=next_map.files,
                )
            elif map_list_limit:
                next_list_limit = map_list_limit // 2
                next_map_result = _compact_map(
                    self._repository_map,
                    role,
                    max_files=file_limit,
                    max_list_items=next_list_limit,
                    preferred_paths=deterministic_preferred_paths,
                )
                next_map = next_map_result.repository_map
                map_list_limit = next_list_limit
                if compact_map == next_map:
                    continue
                omit_inventory_reduction(
                    ContextOmissionCategory.METADATA,
                    kind="repository_map_list_item_excluded",
                    before=compact_map_result.original_list_inventory,
                    after=next_map_result.original_list_inventory,
                )
            elif included_threat_model is not None:
                before_threat_model = included_threat_model
                included_threat_model = None
                omit_inventory_items(
                    ContextOmissionCategory.METADATA,
                    kind="threat_model_excluded",
                    items=(before_threat_model,),
                )
            elif base_bytes <= budget:
                omit(
                    ContextOmissionCategory.METADATA,
                    ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                    {
                        "kind": "metadata_source_reserve_conflict",
                        "metadata_sha256": hashlib.sha256(
                            render_context(base_package).encode("utf-8")
                        ).hexdigest(),
                        "metadata_bytes": base_bytes,
                        "metadata_ceiling": metadata_ceiling,
                        "source_reserve": source_reserve,
                    },
                )
                break
            else:
                if required_surface_facts.source_locations:
                    raise ContextBudgetError(
                        f"required model-surface facts for role {role} exceed its "
                        f"{budget}-byte allocation"
                    )
                raise ContextBudgetError(
                    f"minimum metadata for role {role} exceeds its {budget}-byte allocation"
                )
        excerpt_budget = min(
            source_byte_ceiling,
            max(0, budget - base_bytes),
        )
        used = base_bytes
        source_used = 0
        excerpts: list[ContextExcerpt] = []
        preferred_paths = deterministic_preferred_paths | solidity_preferred_paths(
            self._solidity_index,
            role,
        )
        ranked = sorted(
            scoped_safe_files,
            key=lambda item: (
                0 if item.relative_path in preferred_paths else 1,
                *_score(item, role),
            ),
        )
        ranked_iterator = iter(ranked)
        for item in ranked_iterator:
            if used >= budget:
                omit_remaining_source_files(
                    item,
                    ranked_iterator,
                    cause="context_byte_budget",
                )
                break
            remaining_source_bytes = excerpt_budget - source_used
            if remaining_source_bytes <= 0:
                omit_remaining_source_files(
                    item,
                    ranked_iterator,
                    cause="source_token_budget",
                )
                break
            remaining_rendered_bytes = max(
                0,
                budget - used - _MAX_PROVIDER_OMISSION_COMMITMENT_GROWTH_BYTES,
            )
            if remaining_rendered_bytes <= 0:
                omit_remaining_source_files(
                    item,
                    ranked_iterator,
                    cause="serialized_context_budget",
                )
                break
            result = chunk_text(
                path=item.relative_path,
                content=item.content,
                categories=item.categories,
                # Logical construct classification is independent of the
                # remaining package allocation. Returned constructs that do not
                # fit are classified below as source-budget omissions.
                max_chunk_bytes=48_000,
            )
            chunk_omission_reason = ContextOmissionReason.LOGICAL_BLOCK_EXCEEDS_LIMIT
            if len(result.excerpts) == 1 and result.excerpts[0].content == item.content:
                whole_excerpt = result.excerpts[0]
                whole_source_bytes = len(whole_excerpt.content.encode("utf-8"))
                whole_rendered_bytes = _rendered_excerpt_byte_delta(whole_excerpt)
                if (
                    whole_source_bytes > remaining_source_bytes
                    or whole_rendered_bytes > remaining_rendered_bytes
                ):
                    # A normal-size file is initially represented as one whole
                    # excerpt. Re-enter logical boundary discovery only to
                    # retain smaller complete constructs; any second-pass
                    # exclusion is caused by remaining capacity, never by the
                    # stable 48,000-byte construct limit.
                    result = chunk_text(
                        path=item.relative_path,
                        content=item.content,
                        categories=item.categories,
                        max_chunk_bytes=max(
                            1,
                            min(remaining_source_bytes, remaining_rendered_bytes),
                        ),
                    )
                    chunk_omission_reason = ContextOmissionReason.SOURCE_BUDGET_EXCLUDED
            for descriptor in result.omissions:
                omit(
                    ContextOmissionCategory.SOURCE,
                    chunk_omission_reason,
                    {
                        "kind": (
                            "logical_block_excluded"
                            if chunk_omission_reason
                            is ContextOmissionReason.LOGICAL_BLOCK_EXCEEDS_LIMIT
                            else "source_construct_excluded"
                        ),
                        "path_sha256": hashlib.sha256(
                            item.relative_path.encode("utf-8")
                        ).hexdigest(),
                        "source_sha256": hashlib.sha256(item.content.encode("utf-8")).hexdigest(),
                        "descriptor_sha256": hashlib.sha256(descriptor.encode("utf-8")).hexdigest(),
                    },
                )
            for excerpt in result.excerpts:
                size = len(excerpt.content.encode("utf-8"))
                rendered_delta = _rendered_excerpt_byte_delta(excerpt)
                remaining_rendered_bytes = max(
                    0,
                    budget - used - _MAX_PROVIDER_OMISSION_COMMITMENT_GROWTH_BYTES,
                )
                remaining_source_bytes = max(0, excerpt_budget - source_used)
                if size > remaining_source_bytes or rendered_delta > remaining_rendered_bytes:
                    omit(
                        ContextOmissionCategory.SOURCE,
                        ContextOmissionReason.SOURCE_BUDGET_EXCLUDED,
                        {
                            "kind": "source_excerpt_excluded",
                            "path_sha256": hashlib.sha256(excerpt.path.encode("utf-8")).hexdigest(),
                            "start_line": excerpt.start_line,
                            "end_line": excerpt.end_line,
                            "content_sha256": excerpt.content_hash,
                            "utf8_bytes": size,
                            "rendered_bytes": rendered_delta,
                            "available_source_bytes": remaining_source_bytes,
                            "available_rendered_bytes": remaining_rendered_bytes,
                        },
                    )
                    continue
                excerpts.append(excerpt)
                used += rendered_delta
                source_used += size
        package = ContextPackage(
            role=role,
            byte_budget=budget,
            bytes_used=0,
            configured_maximum_source_tokens_per_request=(self.maximum_source_tokens_per_request),
            effective_source_byte_ceiling=excerpt_budget,
            repository_map=compact_map,
            scanner_findings=selected_scanners,
            excerpts=excerpts,
            requested_model_surfaces=selected_model_surfaces,
            threat_model=included_threat_model,
            solidity_projects=included_solidity_projects,
            solidity_compilations=included_solidity_compilations,
            solidity_index=compact_solidity_index(
                self._solidity_index if include_solidity_index else None,
                role=role,
                max_entities=entity_limit,
                preferred_paths=deterministic_preferred_paths,
                required_entity_ids=set(required_surface_facts.entity_ids),
            ),
            solidity_graphs=compact_solidity_graphs(
                self._solidity_graphs if include_solidity_graphs else None,
                role=role,
                max_edges=graph_edge_limit,
                preferred_paths=deterministic_preferred_paths,
                required_edges=required_surface_facts.graph_edges,
            ),
            solidity_invariants=(None if review_request_mode else included_solidity_invariants),
            invariant_executions=([] if review_request_mode else included_invariant_executions),
            economic_simulations=([] if review_request_mode else included_economic_simulations),
            formal_runs=[] if review_request_mode else included_formal_runs,
            solidity_coverage=(None if review_request_mode else included_solidity_coverage),
            omission_notice_level=(
                ContextOmissionNoticeLevel.COUNTS_BY_GROUP
                if omissions
                else ContextOmissionNoticeLevel.MANIFEST_ONLY
            ),
            omissions=_canonical_context_omissions(omissions),
        )
        actual_bytes = len(render_context(package).encode())
        for next_notice_level in (
            ContextOmissionNoticeLevel.TOTALS_ONLY,
            ContextOmissionNoticeLevel.MANIFEST_ONLY,
        ):
            if actual_bytes <= budget:
                break
            if package.omission_notice_level is ContextOmissionNoticeLevel.MANIFEST_ONLY:
                break
            package = package.model_copy(update={"omission_notice_level": next_notice_level})
            actual_bytes = len(render_context(package).encode())
        while package.excerpts and actual_bytes > budget:
            removed = package.excerpts[-1]
            omit(
                ContextOmissionCategory.SOURCE,
                ContextOmissionReason.SERIALIZED_BUDGET_EXCLUDED,
                {
                    "kind": "source_excerpt_excluded",
                    "path_sha256": hashlib.sha256(removed.path.encode("utf-8")).hexdigest(),
                    "start_line": removed.start_line,
                    "end_line": removed.end_line,
                    "content_sha256": removed.content_hash,
                    "utf8_bytes": len(removed.content.encode("utf-8")),
                    "serialized_bytes_before": actual_bytes,
                    "serialized_budget": budget,
                },
            )
            package = package.model_copy(
                update={
                    "excerpts": package.excerpts[:-1],
                    "omissions": _canonical_context_omissions(omissions),
                }
            )
            actual_bytes = len(render_context(package).encode())
        if actual_bytes > budget:
            raise ContextBudgetError(
                f"serialized metadata for role {role} exceeds its {budget}-byte allocation"
            )
        package = package.model_copy(update={"bytes_used": actual_bytes})
        if package.requested_model_surfaces and not package.excerpts:
            raise ContextBudgetError(
                f"model surface review context for role {role} omitted all source evidence"
            )
        _require_model_surface_fact_custody(package, required=required_surface_facts)
        return package


def context_hash_index(packages: Iterable[ContextPackage]) -> dict[tuple[str, int, int], str]:
    result: dict[tuple[str, int, int], str] = {}
    for package in packages:
        sealed = revalidate_context_package(package)
        for file in sealed.repository_map.files:
            result[(file.path, 0, 0)] = file.sha256
        for excerpt in sealed.excerpts:
            result[(excerpt.path, excerpt.start_line, excerpt.end_line)] = excerpt.content_hash
    return result


def _provider_omission_notice(package: ContextPackage) -> str | None:
    """Return a bounded limitation notice without provider-visible forensic digests."""

    if (
        not package.omissions
        or package.omission_notice_level is ContextOmissionNoticeLevel.MANIFEST_ONLY
    ):
        return None
    omitted_item_count = sum(item.omitted_item_count for item in package.omissions)
    sampled_item_count = sum(len(item.sampled_item_sha256s) for item in package.omissions)
    totals_payload: dict[str, Any] = {
        "schema_version": "1.0",
        "detail_level": ContextOmissionNoticeLevel.TOTALS_ONLY.value,
        "omission_group_count": len(package.omissions),
        "omitted_item_count": omitted_item_count,
        "retained_forensic_sample_count": sampled_item_count,
        "forensic_samples_truncated": any(item.samples_truncated for item in package.omissions),
        "forensic_inventory": "HOST_MANIFEST_ONLY",
    }
    payload = totals_payload
    if package.omission_notice_level is ContextOmissionNoticeLevel.COUNTS_BY_GROUP:
        payload = {
            **totals_payload,
            "detail_level": ContextOmissionNoticeLevel.COUNTS_BY_GROUP.value,
            "groups": [
                {
                    "category": item.category.value,
                    "reason": item.reason.value,
                    "omitted_item_count": item.omitted_item_count,
                    "retained_forensic_sample_count": len(item.sampled_item_sha256s),
                    "forensic_samples_truncated": item.samples_truncated,
                }
                for item in package.omissions
            ],
        }
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    if len(serialized.encode("utf-8")) <= _MAX_PROVIDER_OMISSION_NOTICE_BYTES:
        return serialized
    serialized = json.dumps(
        totals_payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    if len(serialized.encode("utf-8")) <= _MAX_PROVIDER_OMISSION_NOTICE_BYTES:
        return serialized
    return None


def _provider_omission_commitment(package: ContextPackage) -> str:
    """Bind host-only omission evidence into the prompt with constant-size overhead."""

    inventory_payload = {
        "schema_version": "1.0",
        "omission_group_count": len(package.omissions),
        "omission_evidence_sha256s": [item.evidence_sha256 for item in package.omissions],
    }
    inventory_sha256 = hashlib.sha256(
        json.dumps(
            inventory_payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return json.dumps(
        {
            "schema_version": "1.0",
            "commitment_method": "MMAUDIT_CONTEXT_OMISSION_EVIDENCE_SHA256_V1",
            "omission_group_count": len(package.omissions),
            "inventory_sha256": inventory_sha256,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _rendered_excerpt_parts(excerpt: ContextExcerpt) -> list[str]:
    metadata = json.dumps(
        {
            "path": excerpt.path,
            "start_line": excerpt.start_line,
            "end_line": excerpt.end_line,
            "content_sha256": excerpt.content_hash,
        },
        sort_keys=True,
    )
    sentinel = f"MMAUDIT-UNTRUSTED-{excerpt.content_hash.upper()}"
    return [
        "<REPOSITORY_EXCERPT_METADATA_JSON>",
        metadata,
        "</REPOSITORY_EXCERPT_METADATA_JSON>",
        f"-----BEGIN {sentinel}-----",
        excerpt.content,
        f"-----END {sentinel}-----",
    ]


def _rendered_excerpt_byte_delta(excerpt: ContextExcerpt) -> int:
    """Return exact bytes added when one excerpt is appended to non-empty context."""

    parts = _rendered_excerpt_parts(excerpt)
    return sum(len(part.encode("utf-8")) for part in parts) + len(parts)


def render_context(package: ContextPackage) -> str:
    """Serialize with explicit source delimiters and metadata outside bodies."""

    parts = [
        "<REPOSITORY_MAP_JSON>",
        json.dumps(package.repository_map.model_dump(mode="json"), sort_keys=True),
        "</REPOSITORY_MAP_JSON>",
        "<NORMALIZED_SCANNER_EVIDENCE_JSON>",
        json.dumps(
            _scanner_context_payload(package.scanner_findings),
            sort_keys=True,
        ),
        "</NORMALIZED_SCANNER_EVIDENCE_JSON>",
        "<TRUSTED_MODEL_SURFACE_REQUESTS_JSON>",
        json.dumps(
            [request.model_dump(mode="json") for request in package.requested_model_surfaces],
            sort_keys=True,
        ),
        "</TRUSTED_MODEL_SURFACE_REQUESTS_JSON>",
        "<CONTEXT_OMISSION_COMMITMENT_JSON>",
        _provider_omission_commitment(package),
        "</CONTEXT_OMISSION_COMMITMENT_JSON>",
    ]
    if package.threat_model is not None:
        parts.extend(
            [
                "<THREAT_MODEL_JSON>",
                json.dumps(package.threat_model.model_dump(mode="json"), sort_keys=True),
                "</THREAT_MODEL_JSON>",
            ]
        )
    solidity_payload = {
        "projects": [project.model_dump(mode="json") for project in package.solidity_projects],
        "compilations": [
            result.model_dump(mode="json") for result in package.solidity_compilations
        ],
        "symbol_index": (
            package.solidity_index.model_dump(mode="json") if package.solidity_index else None
        ),
        "graphs": package.solidity_graphs.model_dump(mode="json")
        if package.solidity_graphs
        else None,
        "invariants": (
            package.solidity_invariants.model_dump(mode="json")
            if package.solidity_invariants
            else None
        ),
        "invariant_executions": [
            result.model_dump(mode="json") for result in package.invariant_executions
        ],
        "economic_simulations": [
            plan.model_dump(mode="json") for plan in package.economic_simulations
        ],
        "formal_runs": [run.model_dump(mode="json") for run in package.formal_runs],
        "coverage": package.solidity_coverage.model_dump(mode="json")
        if package.solidity_coverage
        else None,
    }
    if any(value for value in solidity_payload.values()):
        parts.extend(
            [
                "<DETERMINISTIC_SOLIDITY_FACTS_JSON>",
                json.dumps(solidity_payload, sort_keys=True),
                "</DETERMINISTIC_SOLIDITY_FACTS_JSON>",
            ]
        )
    for excerpt in package.excerpts:
        parts.extend(_rendered_excerpt_parts(excerpt))
    omission_notice = _provider_omission_notice(package)
    if omission_notice is not None:
        parts.extend(
            [
                "<CONTEXT_LIMITATIONS_JSON>",
                omission_notice,
                "</CONTEXT_LIMITATIONS_JSON>",
            ]
        )
    return "\n".join(parts)


def revalidate_context_package(package: ContextPackage) -> ContextPackage:
    """Return a detached package only when its declared bounds match exact rendering.

    Context packages are frozen at the top level, but several nested source models
    intentionally remain reusable elsewhere in the pipeline. Boundary consumers
    therefore must not trust an already-instantiated package or its mutable nested
    references. Reconstructing from plain data re-runs every nested validator and
    detaches the returned evidence from the caller's object graph.
    """

    if not isinstance(package, ContextPackage):
        raise ContextBoundaryError("context boundary requires a typed context package")
    try:
        sealed = ContextPackage.model_validate(package.model_dump(mode="python"))
        rendered_bytes = len(render_context(sealed).encode("utf-8"))
        source_bytes = sum(len(excerpt.content.encode("utf-8")) for excerpt in sealed.excerpts)
    except (
        AttributeError,
        OverflowError,
        PydanticSerializationError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise ContextBoundaryError("context package failed detached boundary validation") from exc
    if sealed.bytes_used != rendered_bytes:
        raise ContextBoundaryError("declared context bytes differ from exact rendered UTF-8 bytes")
    if rendered_bytes > sealed.byte_budget:
        raise ContextBoundaryError("rendered context-package bytes exceed its byte budget")
    if source_bytes > sealed.effective_source_byte_ceiling:
        raise ContextBoundaryError(
            "rendered context-package source exceeds its effective source byte ceiling"
        )
    return sealed


def revalidate_model_surface_context_package(package: ContextPackage) -> ContextPackage:
    """Re-seal and rederive provider-bound model-surface custody from package bytes."""

    sealed = revalidate_context_package(package)
    if not sealed.requested_model_surfaces:
        return sealed
    try:
        required = _required_model_surface_facts(
            sealed.requested_model_surfaces,
            index=sealed.solidity_index,
            graphs=sealed.solidity_graphs,
        )
        repository_files_by_path: dict[str, list[Any]] = {}
        for item in sealed.repository_map.files:
            repository_files_by_path.setdefault(item.path, []).append(item)
        if any(len(repository_files_by_path.get(path, ())) != 1 for path in required.source_paths):
            raise ContextBudgetError(
                "provider context lacks one exact model-surface source identity"
            )
        repository_files = {path: records[0] for path, records in repository_files_by_path.items()}
        if not required.source_paths <= set(repository_files):
            raise ContextBudgetError(
                "provider context omitted a required model-surface source identity"
            )
        required = replace(
            required,
            source_file_identities=tuple(
                (
                    repository_files[path].path,
                    repository_files[path].size,
                    repository_files[path].lines,
                    repository_files[path].sha256,
                )
                for path in sorted(required.source_paths)
            ),
        )
        _require_model_surface_fact_custody(sealed, required=required)
    except ContextBudgetError as exc:
        raise ContextBoundaryError(
            "provider context failed exact model-surface custody validation"
        ) from exc
    return sealed


def context_json_escape_overhead_tokens(package: ContextPackage) -> int:
    """Return exact JSON-string escaping overhead for the rendered context.

    OpenRouter transports the user message inside JSON. This local measurement
    accounts for quotes, control characters, backslashes, and non-ASCII source
    without retaining a second serialized copy in runtime evidence.
    """

    sealed = revalidate_context_package(package)
    rendered = render_context(sealed)
    raw_bytes = len(rendered.encode("utf-8"))
    encoded_string = json.dumps(
        rendered,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    escaped_bytes = len(encoded_string) - 2
    if escaped_bytes < raw_bytes:
        raise ContextBudgetError("context JSON escaping measurement is inconsistent")
    return escaped_bytes - raw_bytes


def context_category_byte_counts(package: ContextPackage) -> dict[str, int]:
    """Account rendered context bytes without persisting source or prompt material."""

    package = revalidate_context_package(package)
    rendered_bytes = len(render_context(package).encode("utf-8"))
    source_bytes = sum(len(excerpt.content.encode("utf-8")) for excerpt in package.excerpts)
    scanner_bytes = len(
        json.dumps(
            _scanner_context_payload(package.scanner_findings),
            sort_keys=True,
        ).encode("utf-8")
    )
    framework_payload = {
        "projects": [project.model_dump(mode="json") for project in package.solidity_projects],
        "compilations": [
            result.model_dump(mode="json") for result in package.solidity_compilations
        ],
        "symbol_index": (
            package.solidity_index.model_dump(mode="json") if package.solidity_index else None
        ),
        "coverage": (
            package.solidity_coverage.model_dump(mode="json") if package.solidity_coverage else None
        ),
    }
    graph_payload = (
        package.solidity_graphs.model_dump(mode="json") if package.solidity_graphs else None
    )
    invariant_payload = {
        "invariants": (
            package.solidity_invariants.model_dump(mode="json")
            if package.solidity_invariants
            else None
        ),
        "invariant_executions": [
            result.model_dump(mode="json") for result in package.invariant_executions
        ],
        "economic_simulations": [
            plan.model_dump(mode="json") for plan in package.economic_simulations
        ],
        "formal_runs": [run.model_dump(mode="json") for run in package.formal_runs],
    }

    def payload_bytes(value: Any) -> int:
        if value is None or value == [] or value == {}:
            return 0
        return len(json.dumps(value, sort_keys=True).encode("utf-8"))

    framework_bytes = payload_bytes(framework_payload) if any(framework_payload.values()) else 0
    graph_bytes = payload_bytes(graph_payload)
    invariant_bytes = payload_bytes(invariant_payload) if any(invariant_payload.values()) else 0
    accounted = source_bytes + scanner_bytes + framework_bytes + graph_bytes + invariant_bytes
    if accounted > rendered_bytes:
        raise ContextBudgetError("context category accounting exceeds rendered context")
    return {
        "framework": framework_bytes,
        "graph": graph_bytes,
        "invariant": invariant_bytes,
        "metadata": rendered_bytes - accounted,
        "prior_audit": 0,
        "scanner": scanner_bytes,
        "source": source_bytes,
        "workflow": 0,
    }


def context_category_measurements(
    package: ContextPackage,
) -> dict[str, ContextCategoryMeasurement]:
    """Bind category byte counts to actual local semantic context projections."""

    package = revalidate_context_package(package)
    counts = context_category_byte_counts(package)
    rendered_sha256 = hashlib.sha256(render_context(package).encode("utf-8")).hexdigest()
    scanner_projection = json.dumps(
        _scanner_context_payload(package.scanner_findings),
        sort_keys=True,
    )
    framework_projection = json.dumps(
        {
            "projects": [project.model_dump(mode="json") for project in package.solidity_projects],
            "compilations": [
                result.model_dump(mode="json") for result in package.solidity_compilations
            ],
            "symbol_index": (
                package.solidity_index.model_dump(mode="json") if package.solidity_index else None
            ),
            "coverage": (
                package.solidity_coverage.model_dump(mode="json")
                if package.solidity_coverage
                else None
            ),
        },
        sort_keys=True,
    )
    graph_projection = json.dumps(
        package.solidity_graphs.model_dump(mode="json") if package.solidity_graphs else None,
        sort_keys=True,
    )
    invariant_projection = json.dumps(
        {
            "invariants": (
                package.solidity_invariants.model_dump(mode="json")
                if package.solidity_invariants
                else None
            ),
            "invariant_executions": [
                result.model_dump(mode="json") for result in package.invariant_executions
            ],
            "economic_simulations": [
                plan.model_dump(mode="json") for plan in package.economic_simulations
            ],
            "formal_runs": [run.model_dump(mode="json") for run in package.formal_runs],
        },
        sort_keys=True,
    )
    source_projection = json.dumps(
        [
            {
                "path": excerpt.path,
                "start_line": excerpt.start_line,
                "end_line": excerpt.end_line,
                "content_sha256": excerpt.content_hash,
                "utf8_bytes": len(excerpt.content.encode("utf-8")),
            }
            for excerpt in package.excerpts
        ],
        sort_keys=True,
    )
    projections = {
        "framework": framework_projection,
        "graph": graph_projection,
        "invariant": invariant_projection,
        "prior_audit": "",
        "scanner": scanner_projection,
        "source": source_projection,
        "workflow": "",
    }
    projection_hashes = {
        category: hashlib.sha256(value.encode("utf-8")).hexdigest()
        for category, value in projections.items()
    }
    metadata_projection = json.dumps(
        {
            "rendered_context_sha256": rendered_sha256,
            "category_byte_counts": counts,
            "semantic_projection_sha256s": projection_hashes,
        },
        sort_keys=True,
    )
    projection_hashes["metadata"] = hashlib.sha256(metadata_projection.encode("utf-8")).hexdigest()
    return {
        category: ContextCategoryMeasurement(
            content_sha256=projection_hashes[category],
            utf8_bytes=utf8_bytes,
        )
        for category, utf8_bytes in counts.items()
    }
