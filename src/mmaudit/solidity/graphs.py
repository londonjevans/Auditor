"""Deterministic Solidity semantic graph construction.

Compiler AST facts are preferred.  Source heuristics supplement incomplete AST
artifacts, but are explicitly marked ``heuristic`` and never promoted to
compiler evidence.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import re
from bisect import bisect_right
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from functools import lru_cache
from itertools import groupby, islice, pairwise, product
from typing import Any, Protocol

from mmaudit.artifact_limits import MAX_JSON_ARTIFACT_BYTES
from mmaudit.models.schemas import (
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphFactKind,
    SolidityGraphFactOmission,
    SolidityGraphKind,
    SolidityGraphNode,
    SolidityGraphNodeKind,
    SolidityGraphOccurrenceKind,
    SolidityGraphOmission,
    SolidityGraphRetainedOccurrence,
    SolidityGraphSet,
    SolidityProvenance,
    SolidityStorageEntry,
    solidity_graph_edge_logical_key,
    solidity_graph_occurrence_sha256,
)
from mmaudit.models.sharding import SolidityShardPolicy
from mmaudit.reporting.json_report import stable_json_bytes
from mmaudit.repository.discovery import DiscoveredFile, DiscoveryResult
from mmaudit.solidity.index import AstDocument, SolidityIndexBuild, _parse_src_components

_LOW_LEVEL_MEMBERS = {"call", "staticcall", "delegatecall", "callcode", "send", "transfer"}
_TOKEN_FLOW_MEMBERS = {
    "transfer",
    "transferFrom",
    "safeTransferFrom",
    "safeBatchTransferFrom",
    "mint",
    "_mint",
    "burn",
    "_burn",
    "deposit",
    "withdraw",
    "redeem",
    "claim",
    "claimRewards",
    "harvest",
    "liquidate",
    "repay",
    "borrow",
    "reward",
    "distributeReward",
    "accrueReward",
}
_TOKEN_OBSERVATION_MEMBERS = {"balanceOf", "totalAssets", "totalSupply"}
_ASSET_MEMBERS = _TOKEN_FLOW_MEMBERS | _TOKEN_OBSERVATION_MEMBERS
_ORACLE_MEMBERS = {
    "decimals",
    "latestAnswer",
    "latestPrice",
    "latestRoundData",
    "getPrice",
    "price",
    "spotPrice",
    "consult",
    "observe",
    "slot0",
    "getReserves",
    "exchangeRate",
    "getRate",
    "sequencerUp",
}
_MESSAGE_MEMBERS = {
    "sendMessage",
    "dispatch",
    "publishMessage",
    "relayMessage",
    "processMessage",
    "receiveMessage",
    "bridgeMessage",
}
_CALLBACK_MEMBERS = {
    "onCreditReceived",
    "onTokenTransfer",
    "tokensReceived",
    "onERC721Received",
    "onERC1155Received",
    "onERC1155BatchReceived",
}
_OUTBOUND_MESSAGE_TOKENS = (
    "sendmessage",
    "dispatch",
    "publishmessage",
    "bridgemessage",
    "requestmessage",
)
_INBOUND_MESSAGE_TOKENS = (
    "receivemessage",
    "relaymessage",
    "processmessage",
    "executemessage",
    "finalizemessage",
    "lzreceive",
    "ccipreceive",
    "handlemessage",
)
_OFFCHAIN_EVENT_TOKENS = (
    "message",
    "dispatch",
    "bridge",
    "relay",
    "request",
    "query",
)
_SIGNATURE_PRIMITIVES = {
    "ecrecover",
    "recover",
    "tryRecover",
    "isValidSignature",
    "_hashTypedDataV4",
    "hashTypedDataV4",
}
_SIGNATURE_DOMAIN_TOKENS = (
    "chainid",
    "domainseparator",
    "nonces",
    "nonce",
    "deadline",
    "expiry",
    "salt",
)
_PRIVILEGED_TOKENS = {
    "admin",
    "owner",
    "governor",
    "guardian",
    "operator",
    "pauser",
    "upgrader",
    "timelock",
    "multisig",
    "role",
    "auth",
}
_SENSITIVE_FUNCTION_TOKENS = {
    "upgrade",
    "admin",
    "owner",
    "role",
    "pause",
    "unpause",
    "mint",
    "burn",
    "withdraw",
    "rescue",
    "sweep",
    "drain",
    "oracle",
    "fee",
    "treasury",
    "strategy",
    "implementation",
    "delegate",
    "emergency",
}
_GOVERNANCE_STAGE_TOKENS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("proposal", ("propose", "proposal")),
    ("vote", ("castvote", "vote")),
    ("queue", ("queue", "schedule")),
    ("execute", ("execute",)),
    ("cancel", ("cancel", "veto")),
)
_GOVERNANCE_CONTEXT_TOKENS = (
    "govern",
    "timelock",
    "proposal",
    "quorum",
    "voting",
)
_PROXY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("transparent", re.compile(r"\bTransparentUpgradeableProxy\b|\bProxyAdmin\b")),
    ("uups", re.compile(r"\bUUPSUpgradeable\b|\b_authorizeUpgrade\b")),
    ("beacon", re.compile(r"\bBeaconProxy\b|\bUpgradeableBeacon\b|\bbeacon\b", re.I)),
    ("diamond", re.compile(r"\bdiamondCut\b|\bfacetAddress\b|\bEIP[- ]?2535\b", re.I)),
    (
        "minimal_proxy",
        re.compile(r"\bClones\b|\bcloneDeterministic\b|363d3d373d3d3d363d73", re.I),
    ),
    ("custom_delegatecall", re.compile(r"\.delegatecall\s*\(")),
)
_PROXY_SLOT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "implementation",
        re.compile(
            r"\bIMPLEMENTATION_SLOT\b|"
            r"360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
            re.I,
        ),
    ),
    ("admin", re.compile(r"\bADMIN_SLOT\b", re.I)),
    ("beacon", re.compile(r"\bBEACON_SLOT\b", re.I)),
    ("rollback", re.compile(r"\bROLLBACK_SLOT\b", re.I)),
)

_GRAPH_SELECTION_ALGORITHM = "mmaudit.semantic-graph-risk-order.v1"
_OMISSION_SAMPLE_LIMIT = 16
# Graph facts are also projected into the bounded shard artifact.  Reserving only
# one fifth of the graph envelope for edge payload leaves deterministic room for
# endpoint nodes, source-owned facts, typed omission evidence, and the downstream
# projection without relying on optimistic average record sizes.
_EDGE_BUDGET_NUMERATOR = 1
_EDGE_BUDGET_DENOMINATOR = 5
_MAX_CARTESIAN_EDGE_RECORDS = 250_000
_GRAPH_PRIORITY: dict[SolidityGraphKind, int] = {
    # The first four classes are the operator-mandated pressure order.
    SolidityGraphKind.PRIVILEGE: 500,
    SolidityGraphKind.ASSET_FLOW: 490,
    SolidityGraphKind.SENSITIVE_REACHABILITY: 480,
    SolidityGraphKind.STATE_DEPENDENCY: 470,
    SolidityGraphKind.REENTRANCY: 460,
    SolidityGraphKind.DELEGATECALL: 450,
    SolidityGraphKind.LOW_LEVEL_CALL: 440,
    SolidityGraphKind.ORACLE_DEPENDENCY: 430,
    SolidityGraphKind.SIGNATURE_REPLAY: 420,
    SolidityGraphKind.INITIALIZER: 410,
    SolidityGraphKind.UPGRADE_COMPATIBILITY: 400,
    SolidityGraphKind.PROXY: 390,
    SolidityGraphKind.GOVERNANCE: 380,
    SolidityGraphKind.CROSS_CHAIN: 370,
    SolidityGraphKind.EXTERNAL_CALL: 360,
    SolidityGraphKind.CONTRACT_CREATION: 350,
    SolidityGraphKind.STATE_WRITE: 340,
    SolidityGraphKind.STATE_GROWTH: 330,
    SolidityGraphKind.MODIFIER: 320,
    SolidityGraphKind.DEPENDENCY: 310,
    SolidityGraphKind.OFFCHAIN_DEPENDENCY: 300,
    SolidityGraphKind.EVENT_STATE: 290,
    SolidityGraphKind.STORAGE_LAYOUT: 280,
    SolidityGraphKind.INTERNAL_CALL: 200,
    SolidityGraphKind.STATE_READ: 190,
    SolidityGraphKind.EVENT_FLOW: 180,
    SolidityGraphKind.INHERITANCE: 170,
}
_NODE_KIND_PRIORITY: dict[SolidityGraphNodeKind, int] = {
    # Indexed entities are the source/target backbone for every graph class.
    SolidityGraphNodeKind.ENTITY: 510,
    SolidityGraphNodeKind.ROLE: 500,
    SolidityGraphNodeKind.ASSET: 490,
    SolidityGraphNodeKind.STATE_VARIABLE: 480,
    SolidityGraphNodeKind.UNKNOWN: 470,
    SolidityGraphNodeKind.ORACLE: 460,
    SolidityGraphNodeKind.GOVERNANCE: 450,
    SolidityGraphNodeKind.MESSAGE: 440,
    SolidityGraphNodeKind.PROXY: 430,
    SolidityGraphNodeKind.STORAGE_SLOT: 420,
    SolidityGraphNodeKind.EXTERNAL_TARGET: 410,
    SolidityGraphNodeKind.OFFCHAIN_ACTOR: 400,
    SolidityGraphNodeKind.SIGNATURE_DOMAIN: 390,
}


class _EdgeSink(Protocol):
    def append(self, edge: SolidityGraphEdge) -> None: ...

    def extend(self, edges: Iterable[SolidityGraphEdge]) -> None: ...

    def record_analytical_omission(
        self,
        *,
        graph: SolidityGraphKind,
        omitted_count: int,
        derivation: dict[str, Any],
    ) -> None: ...


class _NodeSink(Protocol):
    def append(self, node: SolidityGraphNode) -> None: ...

    def extend(self, nodes: Iterable[SolidityGraphNode]) -> None: ...


class _WarningSink(Protocol):
    def append(self, warning: str) -> None: ...


class _DiscardingEdgeSink:
    """Consume graph producer calls without retaining or accounting edge evidence."""

    def append(self, edge: SolidityGraphEdge) -> None:
        del edge

    def extend(self, edges: Iterable[SolidityGraphEdge]) -> None:
        del edges

    def record_analytical_omission(
        self,
        *,
        graph: SolidityGraphKind,
        omitted_count: int,
        derivation: dict[str, Any],
    ) -> None:
        del graph, omitted_count, derivation


class _DiscardingNodeSink:
    """Skip node construction side effects during the edge-selection pass."""

    def append(self, node: SolidityGraphNode) -> None:
        del node

    def extend(self, nodes: Iterable[SolidityGraphNode]) -> None:
        del nodes


class _DiscardingWarningSink:
    def append(self, warning: str) -> None:
        del warning


def _canonical_edge_bytes(edge: SolidityGraphEdge) -> bytes:
    return json.dumps(
        edge.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


@lru_cache(maxsize=64)
def _source_coordinates(content: str) -> tuple[bytes, tuple[int, ...]]:
    """Cache immutable UTF-8 bytes and line starts for bounded source-range work."""

    encoded = content.encode("utf-8")
    starts = [0]
    cursor = 0
    while True:
        newline = encoded.find(b"\n", cursor)
        if newline < 0:
            break
        cursor = newline + 1
        starts.append(cursor)
    return encoded, tuple(starts)


def _line_range_hash(content: str, start_line: int, end_line: int) -> str:
    """Hash an inclusive line range without repeatedly splitting the source."""

    encoded, starts = _source_coordinates(content)
    start_index = max(0, start_line - 1)
    if start_index >= len(starts):
        return hashlib.sha256(b"").hexdigest()
    start = starts[start_index]
    end = starts[end_line] if end_line < len(starts) else len(encoded)
    return hashlib.sha256(encoded[start:end]).hexdigest()


def _edge_key(
    edge: SolidityGraphEdge,
) -> tuple[str, str, str, str, str, int, int, int | None]:
    return solidity_graph_edge_logical_key(edge)


def _edge_retention_key(edge: SolidityGraphEdge, digest: str) -> tuple[int, int, int, int, int]:
    """Return a stable key where larger values have greater defensive value."""

    unsafe = str(edge.metadata.get("compatibility", "")).casefold() in {
        "incompatible",
        "unsafe",
    } or str(edge.metadata.get("control_resolution", "")).casefold() in {
        "unknown",
        "unresolved",
    }
    provenance = {
        SolidityProvenance.COMPILER: 4,
        SolidityProvenance.STATIC_TOOL: 3,
        SolidityProvenance.HEURISTIC: 2,
        SolidityProvenance.FALLBACK: 1,
        SolidityProvenance.MODEL_SUGGESTED: 0,
    }[edge.provenance]
    # A lower canonical digest wins the final deterministic tie-break.
    digest_tiebreak = -(int(digest, 16))
    return (
        _GRAPH_PRIORITY[edge.graph],
        int(unsafe),
        provenance,
        int(edge.confidence * 1_000_000),
        digest_tiebreak,
    )


def _edge_selection_key(
    edge: SolidityGraphEdge,
    key: tuple[str, str, str, str, str, int, int, int | None],
) -> tuple[int, int, int, int, int]:
    """Rank a logical edge independently from whichever evidence variant arrives first."""

    key_digest = hashlib.sha256(
        json.dumps(key, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    return (_GRAPH_PRIORITY[edge.graph], 0, 0, 0, -int(key_digest, 16))


def _node_retention_key(node: SolidityGraphNode, digest: str) -> tuple[int, int, int]:
    """Return deterministic defensive value for one non-edge graph node."""

    return (
        _NODE_KIND_PRIORITY[node.kind],
        int(node.confidence * 1_000_000),
        -int(digest, 16),
    )


def _maximum_retained_edges_for_sharding(policy: SolidityShardPolicy) -> int:
    """Return a global edge ceiling that cannot overflow any per-shard graph cap.

    A retained edge can contribute one primary and one overlap edge membership,
    two primary and two overlap node memberships, and one boundary membership to
    a shard.  The global cap is deliberately conservative: even if every retained
    edge touches the same source unit, the resulting projection remains within
    the exact policy used downstream.
    """

    non_graph_memberships = sum(
        (
            policy.max_primary_entities_per_shard,
            policy.max_overlap_entities_per_shard,
            policy.max_primary_storage_entries_per_shard,
            policy.max_overlap_storage_entries_per_shard,
        )
    )
    graph_membership_capacity = max(
        0,
        policy.max_total_semantic_memberships_per_shard - non_graph_memberships,
    )
    return min(
        policy.max_primary_graph_edges_per_shard,
        policy.max_overlap_graph_edges_per_shard,
        policy.max_primary_graph_nodes_per_shard // 2,
        policy.max_overlap_graph_nodes_per_shard // 2,
        policy.max_boundaries_per_shard,
        policy.max_total_boundaries,
        graph_membership_capacity // 6,
    )


@dataclass(slots=True)
class _OccurrenceAggregate:
    """Commutative evidence for candidate occurrences represented by one retained key."""

    count: int
    canonical_bytes: int
    digest_xor: int
    digest_sum: int
    sample_digests: list[str]

    @classmethod
    def from_candidate(cls, size: int, digest: str) -> _OccurrenceAggregate:
        digest_int = int(digest, 16)
        return cls(
            count=1,
            canonical_bytes=size,
            digest_xor=digest_int,
            digest_sum=digest_int,
            sample_digests=[digest],
        )

    def add_candidate(self, size: int, digest: str) -> None:
        self.count += 1
        self.canonical_bytes += size
        digest_int = int(digest, 16)
        self.digest_xor ^= digest_int
        self.digest_sum = (self.digest_sum + digest_int) % (1 << 256)
        _merge_digest_samples(self.sample_digests, (digest,))


def _merge_digest_samples(target: list[str], additions: Iterable[str]) -> None:
    target[:] = sorted(set(target) | set(additions))[:_OMISSION_SAMPLE_LIMIT]


@dataclass(slots=True)
class _FactRecord[FactT: (SolidityGraphNode, SolidityStorageEntry)]:
    fact: FactT
    size: int
    digest: str
    variant_priority: tuple[int, int, int]
    selection_priority: tuple[int, ...]
    sequence: int
    occurrences: _OccurrenceAggregate


class _BoundedFactCollector[FactT: (SolidityGraphNode, SolidityStorageEntry)]:
    """Keep a deterministic top population of non-edge graph facts."""

    def __init__(
        self,
        *,
        fact_kind: SolidityGraphFactKind,
        max_payload_bytes: int,
        max_records: int,
        priority: Callable[[FactT, str], tuple[int, int, int]],
    ) -> None:
        self.fact_kind = fact_kind
        self.max_payload_bytes = max(0, max_payload_bytes)
        self.max_records = max(0, max_records)
        self._priority: Callable[[FactT, str], tuple[int, int, int]] = priority
        self._by_id: dict[str, _FactRecord[FactT]] = {}
        self._heap: list[tuple[tuple[int, ...], int, str]] = []
        self._sequence = 0
        self._endpoint_priorities: dict[str, tuple[int, int, int, int, int]] = {}
        self._maximum_candidate_bytes = 0
        self._omitted_count = 0
        self._omitted_bytes = 0
        self._omitted_xor = 0
        self._omitted_sum = 0
        self._omitted_samples: list[str] = []

    def append(self, fact: FactT) -> None:
        encoded = json.dumps(
            fact.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        size = len(encoded)
        digest = hashlib.sha256(encoded).hexdigest()
        self._maximum_candidate_bytes = max(self._maximum_candidate_bytes, size)
        variant_priority = self._priority(fact, digest)
        previous = self._by_id.get(fact.id)
        if previous is not None:
            previous.occurrences.add_candidate(size, digest)
            if variant_priority > previous.variant_priority:
                previous.fact = fact
                previous.size = size
                previous.digest = digest
                previous.variant_priority = variant_priority
            self._enforce_retention_limit()
            return

        # Keep at most one staged record beyond the exact capacity. Several graph
        # producers emit a synthetic endpoint immediately before its edge; the edge
        # callback can therefore pin that endpoint before the next fact forces eviction.
        self._enforce_retention_limit()
        fact_priority = self._effective_priority(fact.id)
        self._sequence += 1
        record = _FactRecord(
            fact=fact,
            size=size,
            digest=digest,
            variant_priority=variant_priority,
            selection_priority=fact_priority,
            sequence=self._sequence,
            occurrences=_OccurrenceAggregate.from_candidate(size, digest),
        )
        self._by_id[fact.id] = record
        heapq.heappush(self._heap, (fact_priority, self._sequence, fact.id))
        self._compact_heap_if_needed()

    def set_endpoint_priority(
        self,
        fact_id: str,
        edge_priority: tuple[int, int, int, int, int] | None,
    ) -> None:
        """Set the exact current defensive value of one retained-edge endpoint."""

        previous_pin = self._endpoint_priorities.get(fact_id)
        if previous_pin == edge_priority:
            return
        if edge_priority is None:
            self._endpoint_priorities.pop(fact_id, None)
        else:
            self._endpoint_priorities[fact_id] = edge_priority
        record = self._by_id.get(fact_id)
        if record is None:
            return
        updated_priority = self._effective_priority(fact_id)
        self._sequence += 1
        record.selection_priority = updated_priority
        record.sequence = self._sequence
        heapq.heappush(self._heap, (updated_priority, self._sequence, fact_id))
        self._compact_heap_if_needed()

    def set_endpoint_priorities(
        self,
        priorities: dict[str, tuple[int, int, int, int, int]],
    ) -> None:
        """Replace transient pins with the exact final retained-edge endpoint set."""

        self._endpoint_priorities = dict(priorities)
        self._heap = []
        for fact_id, record in sorted(self._by_id.items()):
            effective = self._effective_priority(fact_id)
            self._sequence += 1
            record.selection_priority = effective
            record.sequence = self._sequence
            heapq.heappush(self._heap, (effective, self._sequence, fact_id))
        self._enforce_retention_limit()

    def extend(self, facts: Iterable[FactT]) -> None:
        for fact in facts:
            self.append(fact)

    def retained(self) -> list[FactT]:
        self._enforce_retention_limit()
        return [record.fact for _fact_id, record in sorted(self._by_id.items())]

    def retained_ids(self) -> set[str]:
        self._enforce_retention_limit()
        return set(self._by_id)

    def retained_occurrences(self) -> tuple[SolidityGraphRetainedOccurrence, ...]:
        """Return exact occurrence counts for the currently retained normalized facts."""

        self._enforce_retention_limit()
        subject_kind = SolidityGraphOccurrenceKind(self.fact_kind.value)
        return tuple(
            SolidityGraphRetainedOccurrence(
                subject_kind=subject_kind,
                subject_sha256=solidity_graph_occurrence_sha256(subject_kind, record.fact),
                occurrence_count=record.occurrences.count,
            )
            for fact_id, record in sorted(self._by_id.items())
        )

    def discard_bytes(self, minimum_bytes: int) -> int:
        self._enforce_retention_limit()
        discarded = 0
        while discarded < minimum_bytes and self._by_id:
            omitted = self._pop_lowest()
            if omitted is None:
                continue
            self._record_omission(omitted)
            discarded += omitted.size
        return discarded

    def discard_ids(self, fact_ids: set[str]) -> int:
        self._enforce_retention_limit()
        discarded = 0
        for fact_id in sorted(fact_ids & self._by_id.keys()):
            omitted = self._by_id.pop(fact_id)
            self._record_omission(omitted)
            discarded += omitted.size
        return discarded

    def omission(self) -> SolidityGraphFactOmission | None:
        self._enforce_retention_limit()
        if self._omitted_count == 0:
            return None
        retained_occurrence_count = sum(record.occurrences.count for record in self._by_id.values())
        return SolidityGraphFactOmission.build(
            fact_kind=self.fact_kind,
            candidate_count=retained_occurrence_count + self._omitted_count,
            retained_count=len(self._by_id),
            retained_occurrence_count=retained_occurrence_count,
            omitted_count=self._omitted_count,
            omitted_canonical_bytes=self._omitted_bytes,
            omitted_stream_sha256=hashlib.sha256(
                (f"{self._omitted_count}:{self._omitted_xor:064x}:{self._omitted_sum:064x}").encode(
                    "ascii"
                )
            ).hexdigest(),
            omitted_sample_sha256s=tuple(self._omitted_samples),
        )

    def _effective_priority(self, fact_id: str) -> tuple[int, ...]:
        edge_priority = self._endpoint_priorities.get(fact_id)
        resolved_edge_priority: tuple[int, int, int, int, int] = (
            edge_priority if edge_priority is not None else (0, 0, 0, 0, 0)
        )
        identity_tiebreak = -int(
            hashlib.sha256(f"{self.fact_kind.value}\0{fact_id}".encode()).hexdigest(),
            16,
        )
        return (
            int(edge_priority is not None),
            *resolved_edge_priority,
            identity_tiebreak,
        )

    def _capacity(self) -> int:
        byte_capacity = (
            self.max_payload_bytes // self._maximum_candidate_bytes
            if self._maximum_candidate_bytes
            else 0
        )
        return min(self.max_records, byte_capacity)

    def _enforce_retention_limit(self) -> None:
        capacity = self._capacity()
        while len(self._by_id) > capacity:
            omitted = self._pop_lowest()
            if omitted is None:
                break
            self._record_omission(omitted)
        self._compact_heap_if_needed()

    def _compact_heap_if_needed(self) -> None:
        if len(self._heap) <= len(self._by_id) * 2 + 1_024:
            return
        self._heap = [
            (record.selection_priority, record.sequence, fact_id)
            for fact_id, record in self._by_id.items()
        ]
        heapq.heapify(self._heap)

    def _pop_lowest(
        self,
    ) -> _FactRecord[FactT] | None:
        while self._heap:
            _priority, sequence, omitted_id = heapq.heappop(self._heap)
            omitted = self._by_id.get(omitted_id)
            if omitted is None or omitted.sequence != sequence:
                continue
            del self._by_id[omitted_id]
            return omitted
        return None

    def _record_omission(self, record: _FactRecord[FactT]) -> None:
        occurrences = record.occurrences
        self._omitted_count += occurrences.count
        self._omitted_bytes += occurrences.canonical_bytes
        self._omitted_xor ^= occurrences.digest_xor
        self._omitted_sum = (self._omitted_sum + occurrences.digest_sum) % (1 << 256)
        _merge_digest_samples(self._omitted_samples, occurrences.sample_digests)


@dataclass(slots=True)
class _WarningRecord:
    warning: str
    size: int
    occurrences: _OccurrenceAggregate


class _BoundedWarningCollector:
    """Bound diagnostic strings and expose typed evidence when records are dropped."""

    def __init__(self, *, max_payload_bytes: int, max_records: int = 256) -> None:
        self.max_payload_bytes = max(0, max_payload_bytes)
        self.max_records = max_records
        self._by_digest: dict[str, _WarningRecord] = {}
        self._omitted_count = 0
        self._omitted_bytes = 0
        self._omitted_xor = 0
        self._omitted_sum = 0
        self._omitted_samples: list[str] = []

    def append(self, warning: str) -> None:
        encoded = json.dumps(warning, ensure_ascii=False).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        previous = self._by_digest.get(digest)
        if previous is not None:
            previous.occurrences.add_candidate(len(encoded), digest)
            return
        self._by_digest[digest] = _WarningRecord(
            warning=warning,
            size=len(encoded),
            occurrences=_OccurrenceAggregate.from_candidate(len(encoded), digest),
        )
        while (
            len(self._by_digest) > self.max_records
            or sum(item.size for item in self._by_digest.values()) > self.max_payload_bytes
        ):
            omitted_digest = max(self._by_digest)
            omitted = self._by_digest.pop(omitted_digest)
            self._record_omission(omitted)

    def retained(self) -> list[str]:
        return sorted(item.warning for item in self._by_digest.values())

    def retained_occurrences(self) -> tuple[SolidityGraphRetainedOccurrence, ...]:
        """Return exact occurrence counts for the retained normalized warnings."""

        return tuple(
            SolidityGraphRetainedOccurrence(
                subject_kind=SolidityGraphOccurrenceKind.WARNING,
                subject_sha256=solidity_graph_occurrence_sha256(
                    SolidityGraphOccurrenceKind.WARNING, record.warning
                ),
                occurrence_count=record.occurrences.count,
            )
            for _digest, record in sorted(self._by_digest.items())
        )

    def omission(self) -> SolidityGraphFactOmission | None:
        if self._omitted_count == 0:
            return None
        retained_occurrence_count = sum(
            record.occurrences.count for record in self._by_digest.values()
        )
        return SolidityGraphFactOmission.build(
            fact_kind=SolidityGraphFactKind.WARNING,
            candidate_count=retained_occurrence_count + self._omitted_count,
            retained_count=len(self._by_digest),
            retained_occurrence_count=retained_occurrence_count,
            omitted_count=self._omitted_count,
            omitted_canonical_bytes=self._omitted_bytes,
            omitted_stream_sha256=hashlib.sha256(
                (f"{self._omitted_count}:{self._omitted_xor:064x}:{self._omitted_sum:064x}").encode(
                    "ascii"
                )
            ).hexdigest(),
            omitted_sample_sha256s=tuple(self._omitted_samples),
        )

    def _record_omission(self, record: _WarningRecord) -> None:
        occurrences = record.occurrences
        self._omitted_count += occurrences.count
        self._omitted_bytes += occurrences.canonical_bytes
        self._omitted_xor ^= occurrences.digest_xor
        self._omitted_sum = (self._omitted_sum + occurrences.digest_sum) % (1 << 256)
        _merge_digest_samples(self._omitted_samples, occurrences.sample_digests)


@dataclass(slots=True)
class _EdgeRecord:
    edge: SolidityGraphEdge
    size: int
    digest: str
    variant_priority: tuple[int, int, int, int, int]
    selection_priority: tuple[int, int, int, int, int]
    sequence: int
    occurrences: _OccurrenceAggregate


class _BoundedEdgeCollector:
    """Retain a deterministic risk-ordered edge set under a fixed memory budget."""

    def __init__(
        self,
        max_payload_bytes: int,
        *,
        max_retained_edges: int,
        endpoint_sink: (Callable[[str, tuple[int, int, int, int, int] | None], None] | None) = None,
    ) -> None:
        self.max_payload_bytes = max(0, max_payload_bytes)
        self.max_retained_edges = max(0, max_retained_edges)
        self._endpoint_sink = endpoint_sink
        self._endpoint_priority_counts: defaultdict[
            str,
            Counter[tuple[int, int, int, int, int]],
        ] = defaultdict(Counter)
        self._by_key: dict[
            tuple[str, str, str, str, str, int, int, int | None],
            _EdgeRecord,
        ] = {}
        self._heap: list[
            tuple[
                tuple[int, int, int, int, int],
                int,
                tuple[str, str, str, str, str, int, int, int | None],
            ]
        ] = []
        self._sequence = 0
        self._retained_bytes = 0
        self._maximum_candidate_bytes = 0
        self._omitted_count: Counter[SolidityGraphKind] = Counter()
        self._omitted_bytes: Counter[SolidityGraphKind] = Counter()
        self._omitted_xor: defaultdict[SolidityGraphKind, int] = defaultdict(int)
        self._omitted_sum: defaultdict[SolidityGraphKind, int] = defaultdict(int)
        self._omitted_samples: defaultdict[SolidityGraphKind, list[str]] = defaultdict(list)
        self._analytical_omitted_count: Counter[SolidityGraphKind] = Counter()
        self._analytical_population_hashes: defaultdict[SolidityGraphKind, list[str]] = defaultdict(
            list
        )
        self._analytical_xor: defaultdict[SolidityGraphKind, int] = defaultdict(int)
        self._analytical_sum: defaultdict[SolidityGraphKind, int] = defaultdict(int)

    def append(self, edge: SolidityGraphEdge) -> None:
        encoded = _canonical_edge_bytes(edge)
        size = len(encoded)
        self._maximum_candidate_bytes = max(self._maximum_candidate_bytes, size)
        digest = hashlib.sha256(encoded).hexdigest()
        key = _edge_key(edge)
        variant_priority = _edge_retention_key(edge, digest)
        previous = self._by_key.get(key)
        if previous is not None:
            previous.occurrences.add_candidate(size, digest)
            if variant_priority > previous.variant_priority:
                self._retained_bytes += size - previous.size
                previous.edge = edge
                previous.size = size
                previous.digest = digest
                previous.variant_priority = variant_priority
            self._enforce_retention_limit()
            return

        selection_priority = _edge_selection_key(edge, key)
        self._sequence += 1
        sequence = self._sequence
        self._by_key[key] = _EdgeRecord(
            edge=edge,
            size=size,
            digest=digest,
            variant_priority=variant_priority,
            selection_priority=selection_priority,
            sequence=sequence,
            occurrences=_OccurrenceAggregate.from_candidate(size, digest),
        )
        self._retained_bytes += size
        self._add_endpoint_bindings(edge, selection_priority)
        heapq.heappush(self._heap, (selection_priority, sequence, key))
        self._enforce_retention_limit()
        if len(self._heap) > len(self._by_key) * 2 + 1_024:
            self._heap = [
                (record.selection_priority, record.sequence, retained_key)
                for retained_key, record in self._by_key.items()
            ]
            heapq.heapify(self._heap)

    def extend(self, edges: Iterable[SolidityGraphEdge]) -> None:
        for edge in edges:
            self.append(edge)

    def record_analytical_omission(
        self,
        *,
        graph: SolidityGraphKind,
        omitted_count: int,
        derivation: dict[str, Any],
    ) -> None:
        """Record an exact skipped population without constructing each edge object."""

        if omitted_count <= 0:
            return
        payload = {
            "algorithm": _GRAPH_SELECTION_ALGORITHM,
            "graph": graph.value,
            "omitted_count": omitted_count,
            "derivation": derivation,
        }
        digest = hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        hashes = self._analytical_population_hashes[graph]
        if digest not in hashes:
            hashes.append(digest)
            hashes.sort()
            del hashes[_OMISSION_SAMPLE_LIMIT:]
        digest_int = int(digest, 16)
        self._analytical_xor[graph] ^= digest_int
        self._analytical_sum[graph] = (self._analytical_sum[graph] + digest_int) % (1 << 256)
        self._analytical_omitted_count[graph] += omitted_count
        self._omitted_count[graph] += omitted_count

    def discard_below_omission_frontier(self) -> None:
        """Never retain a lower-risk graph kind after a higher-risk kind was omitted."""

        if not self._omitted_count:
            return
        frontier = max(_GRAPH_PRIORITY[graph] for graph in self._omitted_count)
        keys = [
            key
            for key, record in self._by_key.items()
            if _GRAPH_PRIORITY[record.edge.graph] < frontier
        ]
        for key in sorted(keys):
            record = self._by_key.pop(key)
            self._retained_bytes -= record.size
            self._remove_endpoint_bindings(record.edge, record.selection_priority)
            self._record_omission(record)

    def discard_bytes(self, minimum_bytes: int) -> int:
        discarded = 0
        while discarded < minimum_bytes and self._by_key:
            record = self._pop_lowest()
            if record is None:
                break
            self._record_omission(record)
            discarded += record.size
        return discarded

    def discard_edges_with_missing_nodes(self, node_ids: set[str]) -> None:
        missing = [
            key
            for key, record in self._by_key.items()
            if record.edge.source_id not in node_ids or record.edge.target_id not in node_ids
        ]
        for key in sorted(missing):
            record = self._by_key.pop(key)
            self._retained_bytes -= record.size
            self._remove_endpoint_bindings(record.edge, record.selection_priority)
            self._record_omission(record)

    def retained_edges(self) -> list[SolidityGraphEdge]:
        return sorted(
            (record.edge for record in self._by_key.values()),
            key=lambda edge: (
                edge.graph.value,
                edge.source_id,
                edge.target_id,
                edge.path,
                edge.start_line,
                edge.end_line,
                _int_or_none(edge.metadata.get("occurrence_relative_start")) or -1,
                edge.label,
            ),
        )

    def retained_occurrences(self) -> tuple[SolidityGraphRetainedOccurrence, ...]:
        """Return exact occurrence counts for the retained normalized edge keys."""

        occurrences = (
            SolidityGraphRetainedOccurrence(
                subject_kind=SolidityGraphOccurrenceKind.EDGE,
                subject_sha256=solidity_graph_occurrence_sha256(
                    SolidityGraphOccurrenceKind.EDGE, record.edge
                ),
                occurrence_count=record.occurrences.count,
            )
            for record in self._by_key.values()
        )
        return tuple(
            sorted(
                occurrences,
                key=lambda item: (item.subject_kind.value, item.subject_sha256),
            )
        )

    def endpoint_priorities(self) -> dict[str, tuple[int, int, int, int, int]]:
        """Return exact maximum retained-edge priority for every endpoint."""

        return {
            endpoint: max(counts)
            for endpoint, counts in self._endpoint_priority_counts.items()
            if counts
        }

    def omissions(self) -> tuple[SolidityGraphOmission, ...]:
        retained = Counter(edge.graph for edge in self.retained_edges())
        retained_occurrences: Counter[SolidityGraphKind] = Counter()
        for record in self._by_key.values():
            retained_occurrences[record.edge.graph] += record.occurrences.count
        omissions: list[SolidityGraphOmission] = []
        for graph in sorted(self._omitted_count, key=lambda item: item.value):
            omitted_count = self._omitted_count[graph]
            if omitted_count <= 0:
                continue
            commitment_payload = (
                f"{omitted_count}:{self._omitted_xor[graph]:064x}:"
                f"{self._omitted_sum[graph]:064x}:"
                f"{self._analytical_xor[graph]:064x}:"
                f"{self._analytical_sum[graph]:064x}"
            )
            omissions.append(
                SolidityGraphOmission.build(
                    graph=graph,
                    candidate_count=retained_occurrences[graph] + omitted_count,
                    retained_count=retained[graph],
                    retained_occurrence_count=retained_occurrences[graph],
                    omitted_count=omitted_count,
                    omitted_canonical_bytes=self._omitted_bytes[graph],
                    analytical_omitted_count=self._analytical_omitted_count[graph],
                    analytical_population_sample_sha256s=tuple(
                        self._analytical_population_hashes[graph]
                    ),
                    omitted_stream_sha256=hashlib.sha256(
                        commitment_payload.encode("ascii")
                    ).hexdigest(),
                    omitted_sample_sha256s=tuple(sorted(self._omitted_samples[graph])),
                )
            )
        return tuple(omissions)

    def _enforce_retention_limit(self) -> None:
        byte_capacity = (
            self.max_payload_bytes // self._maximum_candidate_bytes
            if self._maximum_candidate_bytes
            else 0
        )
        capacity = min(self.max_retained_edges, byte_capacity)
        while len(self._by_key) > capacity:
            record = self._pop_lowest()
            if record is None:
                break
            self._record_omission(record)

    def _pop_lowest(self) -> _EdgeRecord | None:
        while self._heap:
            _priority, sequence, key = heapq.heappop(self._heap)
            current = self._by_key.get(key)
            if current is None or current.sequence != sequence:
                continue
            record = self._by_key.pop(key)
            self._retained_bytes -= record.size
            self._remove_endpoint_bindings(record.edge, record.selection_priority)
            return record
        return None

    def _add_endpoint_bindings(
        self,
        edge: SolidityGraphEdge,
        priority: tuple[int, int, int, int, int],
    ) -> None:
        for endpoint in {edge.source_id, edge.target_id}:
            counts = self._endpoint_priority_counts[endpoint]
            counts[priority] += 1
            if self._endpoint_sink is not None:
                self._endpoint_sink(endpoint, max(counts))

    def _remove_endpoint_bindings(
        self,
        edge: SolidityGraphEdge,
        priority: tuple[int, int, int, int, int],
    ) -> None:
        for endpoint in {edge.source_id, edge.target_id}:
            counts = self._endpoint_priority_counts[endpoint]
            counts[priority] -= 1
            if counts[priority] <= 0:
                del counts[priority]
            if counts:
                current = max(counts)
            else:
                del self._endpoint_priority_counts[endpoint]
                current = None
            if self._endpoint_sink is not None:
                self._endpoint_sink(endpoint, current)

    def _record_omission(self, record: _EdgeRecord) -> None:
        graph = record.edge.graph
        occurrences = record.occurrences
        self._omitted_count[graph] += occurrences.count
        self._omitted_bytes[graph] += occurrences.canonical_bytes
        self._omitted_xor[graph] ^= occurrences.digest_xor
        self._omitted_sum[graph] = (self._omitted_sum[graph] + occurrences.digest_sum) % (1 << 256)
        _merge_digest_samples(self._omitted_samples[graph], occurrences.sample_digests)


def _bounded_state_dependency_pairs(
    read_ids: Iterable[str],
    write_ids: Iterable[str],
    *,
    edge_sink: _EdgeSink | None,
    path: str,
    function_id: str,
    transformation: str,
) -> Iterable[tuple[str, str]]:
    """Yield a bounded canonical state-product and account for the skipped population."""

    reads = tuple(sorted(set(read_ids)))
    writes = tuple(sorted(set(write_ids)))
    total = len(reads) * len(writes)
    limit = total if edge_sink is None else min(total, _MAX_CARTESIAN_EDGE_RECORDS)
    if edge_sink is not None and total > limit:
        edge_sink.record_analytical_omission(
            graph=SolidityGraphKind.STATE_DEPENDENCY,
            omitted_count=total - limit,
            derivation={
                "transformation": transformation,
                "path": path,
                "function_id": function_id,
                "read_count": len(reads),
                "write_count": len(writes),
                "read_ids_sha256": hashlib.sha256("\n".join(reads).encode("utf-8")).hexdigest(),
                "write_ids_sha256": hashlib.sha256("\n".join(writes).encode("utf-8")).hexdigest(),
                "enumerated_prefix_count": limit,
            },
        )
    return islice(product(reads, writes), limit)


def build_solidity_graphs(
    discovery: DiscoveryResult,
    build: SolidityIndexBuild,
    *,
    max_artifact_bytes: int = MAX_JSON_ARTIFACT_BYTES,
    shard_policy: SolidityShardPolicy | None = None,
) -> SolidityGraphSet:
    """Build a risk-ordered semantic graph that cannot exceed its artifact ceiling."""

    if (
        type(max_artifact_bytes) is not int
        or max_artifact_bytes < 1_024
        or max_artifact_bytes > MAX_JSON_ARTIFACT_BYTES
    ):
        raise ValueError(
            f"graph artifact byte ceiling must be in [1024, {MAX_JSON_ARTIFACT_BYTES}]"
        )

    effective_shard_policy = SolidityShardPolicy.model_validate(
        (shard_policy or SolidityShardPolicy.build()).model_dump(mode="python")
    )
    files = {item.relative_path: item for item in discovery.files if item.language == "Solidity"}
    node_collector = _BoundedFactCollector[SolidityGraphNode](
        fact_kind=SolidityGraphFactKind.GRAPH_NODE,
        max_payload_bytes=max_artifact_bytes * 2 // 5,
        max_records=min(
            effective_shard_policy.max_primary_graph_nodes_per_shard,
            effective_shard_policy.max_overlap_graph_nodes_per_shard,
        ),
        priority=_node_retention_key,
    )
    edge_budget = max_artifact_bytes * _EDGE_BUDGET_NUMERATOR // _EDGE_BUDGET_DENOMINATOR
    edges = _BoundedEdgeCollector(
        edge_budget,
        max_retained_edges=_maximum_retained_edges_for_sharding(effective_shard_policy),
        endpoint_sink=node_collector.set_endpoint_priority,
    )
    warnings = _BoundedWarningCollector(max_payload_bytes=max(1_024, max_artifact_bytes // 100))
    storage_collector = _BoundedFactCollector[SolidityStorageEntry](
        fact_kind=SolidityGraphFactKind.STORAGE_ENTRY,
        max_payload_bytes=max_artifact_bytes // 10,
        max_records=min(
            effective_shard_policy.max_primary_storage_entries_per_shard,
            effective_shard_policy.max_overlap_storage_entries_per_shard,
        ),
        priority=lambda entry, digest: (
            1 if entry.provenance is SolidityProvenance.COMPILER else 0,
            int(entry.confidence * 1_000_000),
            -int(digest, 16),
        ),
    )
    discarding_nodes = _DiscardingNodeSink()
    for document in build.ast_documents:
        file = files.get(document.source_path)
        if file is None:
            warnings.append(f"{document.source_path}: graph AST source was not discovered")
            continue
        ast_edges, _ast_nodes = _ast_edges(
            document,
            file,
            build,
            warnings,
            edge_sink=edges,
            node_sink=discarding_nodes,
        )
        edges.extend(ast_edges)

    _heuristic_edges, _heuristic_nodes = _source_semantic_edges(
        files,
        build.index.entities,
        edge_sink=edges,
        node_sink=discarding_nodes,
    )
    _storage_layout_entries, storage_edges, _storage_nodes = _storage_layout(
        files,
        build.index.entities,
        build.storage_layout,
        edge_sink=edges,
        node_sink=discarding_nodes,
        storage_sink=storage_collector,
    )
    edges.extend(storage_edges)
    proxy_edges, _proxy_nodes = _proxy_edges(
        files,
        build.index.entities,
        edge_sink=edges,
        node_sink=discarding_nodes,
    )
    edges.extend(proxy_edges)

    edges.discard_below_omission_frontier()
    node_collector.set_endpoint_priorities(edges.endpoint_priorities())

    # Replay only node producers after edge selection so endpoint pins are immutable
    # throughout fact retention. The sinks suppress duplicate edge/warning accounting.
    replay_edges = _DiscardingEdgeSink()
    replay_warnings = _DiscardingWarningSink()
    for document in build.ast_documents:
        file = files.get(document.source_path)
        if file is None:
            continue
        _ast_edges(
            document,
            file,
            build,
            replay_warnings,
            edge_sink=replay_edges,
            node_sink=node_collector,
        )
    _source_semantic_edges(
        files,
        build.index.entities,
        edge_sink=replay_edges,
        node_sink=node_collector,
    )
    _storage_layout(
        files,
        build.index.entities,
        build.storage_layout,
        edge_sink=replay_edges,
        node_sink=node_collector,
        storage_sink=storage_collector,
        populate_storage=False,
    )
    _proxy_edges(
        files,
        build.index.entities,
        edge_sink=replay_edges,
        node_sink=node_collector,
    )
    node_collector.extend(_entity_node(entity) for entity in build.index.entities)
    edges.discard_edges_with_missing_nodes(node_collector.retained_ids())
    edges.discard_below_omission_frontier()
    node_collector.set_endpoint_priorities(edges.endpoint_priorities())

    limit_warning_added = False

    def ensure_limit_warning() -> None:
        nonlocal limit_warning_added
        if limit_warning_added:
            return
        if not (
            edges.omissions()
            or node_collector.omission()
            or storage_collector.omission()
            or warnings.omission()
        ):
            return
        warnings.append(
            "semantic graph artifact reached a bounded generation limit; typed "
            "risk-ordered omissions are recorded"
        )
        limit_warning_added = True

    def materialize() -> SolidityGraphSet:
        ensure_limit_warning()
        retained_edges = edges.retained_edges()
        retained_nodes = node_collector.retained()
        retained_storage = storage_collector.retained()
        retained_warnings = warnings.retained()
        retained_occurrences = tuple(
            sorted(
                (
                    *edges.retained_occurrences(),
                    *node_collector.retained_occurrences(),
                    *storage_collector.retained_occurrences(),
                    *warnings.retained_occurrences(),
                ),
                key=lambda item: (item.subject_kind.value, item.subject_sha256),
            )
        )
        coverage = Counter(edge.graph.value for edge in retained_edges)
        omissions = edges.omissions()
        fact_omissions = tuple(
            sorted(
                (
                    omission
                    for omission in (
                        node_collector.omission(),
                        storage_collector.omission(),
                        warnings.omission(),
                    )
                    if omission is not None
                ),
                key=lambda item: item.fact_kind.value,
            )
        )
        omitted_kinds = {item.graph for item in omissions}
        analyzed = [kind for kind in SolidityGraphKind if kind not in omitted_kinds]
        return SolidityGraphSet(
            nodes=retained_nodes,
            edges=retained_edges,
            storage_layout=retained_storage,
            retained_occurrences=retained_occurrences,
            analyzed_graphs=analyzed,
            coverage={kind.value: coverage.get(kind.value, 0) for kind in SolidityGraphKind},
            warnings=retained_warnings,
            generation_complete=not omissions and not fact_omissions,
            artifact_byte_limit=max_artifact_bytes,
            selection_algorithm=_GRAPH_SELECTION_ALGORITHM,
            edge_omissions=omissions,
            fact_omissions=fact_omissions,
        )

    graph_set = materialize()
    encoded_size = len(
        stable_json_bytes(
            {
                "schema_version": "1.0",
                "graphs": graph_set.model_dump(mode="json"),
            }
        )
    )
    while encoded_size > max_artifact_bytes:
        excess = encoded_size - max_artifact_bytes
        endpoint_ids = {
            identifier
            for edge in edges.retained_edges()
            for identifier in (edge.source_id, edge.target_id)
        }
        discarded = node_collector.discard_ids(node_collector.retained_ids() - endpoint_ids)
        if discarded == 0:
            discarded = storage_collector.discard_bytes(max(1_024, excess * 2))
        if discarded == 0:
            discarded = edges.discard_bytes(max(1_024, excess * 2))
        if discarded == 0:
            discarded = node_collector.discard_bytes(max(1_024, excess * 2))
            edges.discard_edges_with_missing_nodes(node_collector.retained_ids())
        if discarded == 0:
            raise ValueError("minimum typed semantic graph envelope exceeds its byte ceiling")
        edges.discard_below_omission_frontier()
        graph_set = materialize()
        encoded_size = len(
            stable_json_bytes(
                {
                    "schema_version": "1.0",
                    "graphs": graph_set.model_dump(mode="json"),
                }
            )
        )
    return graph_set


def summarize_asset_flows(graphs: SolidityGraphSet | None) -> dict[str, dict[str, int]]:
    """Summarize separately classified asset operations and source/sink directions."""

    edges = (
        [edge for edge in graphs.edges if edge.graph is SolidityGraphKind.ASSET_FLOW]
        if graphs is not None
        else []
    )
    operations = Counter(str(edge.metadata.get("operation", "unknown")) for edge in edges)
    directions = Counter(str(edge.metadata.get("flow_direction", "unknown")) for edge in edges)
    return {
        "operations": dict(sorted(operations.items())),
        "directions": dict(sorted(directions.items())),
    }


def summarize_control_dependencies(
    graphs: SolidityGraphSet | None,
) -> dict[str, dict[str, int]]:
    """Summarize resolved and explicitly unknown control/dependency facts."""

    edges = graphs.edges if graphs is not None else []
    controls = Counter(
        str(edge.metadata.get("control_resolution", "unknown"))
        for edge in edges
        if edge.graph is SolidityGraphKind.PRIVILEGE
    )
    governance = Counter(
        str(edge.metadata.get("stage", "unknown"))
        for edge in edges
        if edge.graph is SolidityGraphKind.GOVERNANCE
    )
    dependencies = Counter(
        str(edge.metadata.get("dependency_resolution", "unknown"))
        for edge in edges
        if edge.graph is SolidityGraphKind.DEPENDENCY
    )
    oracle_freshness = Counter(
        str(edge.metadata.get("freshness_validation", "unknown"))
        for edge in edges
        if edge.graph is SolidityGraphKind.ORACLE_DEPENDENCY
    )
    return {
        "controls": dict(sorted(controls.items())),
        "governance": dict(sorted(governance.items())),
        "dependencies": dict(sorted(dependencies.items())),
        "oracle_freshness": dict(sorted(oracle_freshness.items())),
    }


def _ast_edges(
    document: AstDocument,
    file: DiscoveredFile,
    build: SolidityIndexBuild,
    warnings: _WarningSink,
    *,
    edge_sink: _EdgeSink | None = None,
    node_sink: _NodeSink | None = None,
) -> tuple[list[SolidityGraphEdge], list[SolidityGraphNode]]:
    local_edges: list[SolidityGraphEdge] = []
    local_nodes: list[SolidityGraphNode] = []
    edges: list[SolidityGraphEdge] | _EdgeSink = local_edges if edge_sink is None else edge_sink
    nodes: list[SolidityGraphNode] | _NodeSink = local_nodes if node_sink is None else node_sink
    for contract in document.ast.get("nodes", []):
        if not isinstance(contract, dict) or contract.get("nodeType") != "ContractDefinition":
            continue
        contract_name = str(contract.get("name", ""))
        contract_id = _entity_id_for_node(document.source_path, contract, build)
        if contract_id is None:
            continue
        for base in contract.get("baseContracts", []) or []:
            if not isinstance(base, dict):
                continue
            base_node = base.get("baseName")
            base_name = _name_from_ast(base_node)
            declaration = (
                _int_or_none(base_node.get("referencedDeclaration"))
                if isinstance(base_node, dict)
                else None
            )
            target_id = (
                build.ast_entity_ids.get((file.relative_path, declaration))
                if declaration is not None
                else None
            ) or _named_entity_id(
                build.index.entities,
                path=file.relative_path,
                contract_name=None,
                name=base_name,
                kinds=frozenset(
                    {
                        SolidityEntityKind.CONTRACT,
                        SolidityEntityKind.INTERFACE,
                        SolidityEntityKind.LIBRARY,
                    }
                ),
            )
            if target_id is None:
                warnings.append(f"{contract_name}: inherited base {base_name} was not indexed")
                continue
            edges.append(
                _ast_edge(
                    graph=SolidityGraphKind.INHERITANCE,
                    source_id=contract_id,
                    target_id=target_id,
                    label=f"{contract_name} inherits {base_name}",
                    file=file,
                    node=base,
                    transformation="solc_ast.ContractDefinition.baseContracts",
                )
            )
        for child in contract.get("nodes", []) or []:
            if not isinstance(child, dict) or child.get("nodeType") != "FunctionDefinition":
                continue
            function_id = _entity_id_for_node(document.source_path, child, build)
            if function_id is None:
                continue
            modifier_edges, modifier_nodes = _modifier_edges(
                file,
                contract_name,
                function_id,
                child,
                build,
                warnings,
            )
            edges.extend(modifier_edges)
            nodes.extend(modifier_nodes)
            body = child.get("body")
            function_edges, function_nodes = _ast_function_edges(
                file=file,
                contract_name=contract_name,
                function_id=function_id,
                function_node=child,
                body=body,
                build=build,
                edge_sink=edge_sink,
            )
            edges.extend(function_edges)
            nodes.extend(function_nodes)
    return local_edges, local_nodes


def _modifier_edges(
    file: DiscoveredFile,
    contract_name: str,
    function_id: str,
    child: dict[str, Any],
    build: SolidityIndexBuild,
    warnings: _WarningSink,
) -> tuple[list[SolidityGraphEdge], list[SolidityGraphNode]]:
    edges: list[SolidityGraphEdge] = []
    nodes: list[SolidityGraphNode] = []
    for modifier in child.get("modifiers", []) or []:
        if not isinstance(modifier, dict):
            continue
        modifier_node = modifier.get("modifierName")
        modifier_name = _name_from_ast(modifier_node)
        declaration = (
            _int_or_none(modifier_node.get("referencedDeclaration"))
            if isinstance(modifier_node, dict)
            else None
        )
        target_id = (
            build.ast_entity_ids.get((file.relative_path, declaration))
            if declaration is not None
            else None
        ) or _named_entity_id(
            build.index.entities,
            path=file.relative_path,
            contract_name=contract_name,
            name=modifier_name,
            kinds=frozenset({SolidityEntityKind.MODIFIER}),
        )
        if target_id is None:
            warnings.append(
                f"{contract_name}.{child.get('name') or child.get('kind')}: "
                f"modifier {modifier_name} was not indexed"
            )
            target_id = _synthetic_id(
                "unknown-modifier",
                file.relative_path,
                contract_name,
                str(child.get("name") or child.get("kind")),
                modifier_name,
            )
            unknown_metadata = {
                "control": modifier_name or "unknown modifier",
                "control_resolution": "unknown",
                "control_kind": "unresolved_modifier",
                "reason": "modifier declaration was not indexed",
            }
            nodes.append(
                _synthetic_node(
                    target_id,
                    SolidityGraphNodeKind.UNKNOWN,
                    modifier_name or "unknown modifier",
                    file,
                    modifier,
                    SolidityProvenance.COMPILER,
                    0.8,
                    unknown_metadata,
                    transformation="unresolved_modifier_invocation_node",
                )
            )
            edges.append(
                _ast_edge(
                    graph=SolidityGraphKind.MODIFIER,
                    source_id=function_id,
                    target_id=target_id,
                    label=f"applies unresolved modifier {modifier_name or 'unknown'}",
                    file=file,
                    node=modifier,
                    transformation="solc_ast.FunctionDefinition.modifiers.unresolved",
                    confidence=0.8,
                    metadata=unknown_metadata,
                )
            )
            if _looks_privileged(modifier_name):
                edges.append(
                    _ast_edge(
                        graph=SolidityGraphKind.PRIVILEGE,
                        source_id=function_id,
                        target_id=target_id,
                        label=f"privilege control {modifier_name} remains unresolved",
                        file=file,
                        node=modifier,
                        transformation="unresolved_privilege_modifier_classification",
                        confidence=0.65,
                        metadata=unknown_metadata,
                    )
                )
            continue
        control_metadata = {
            "control": modifier_name,
            "control_resolution": "resolved",
            "control_kind": "indexed_modifier",
            "governance_control": _looks_governance(modifier_name),
        }
        edges.append(
            _ast_edge(
                graph=SolidityGraphKind.MODIFIER,
                source_id=function_id,
                target_id=target_id,
                label=f"applies {modifier_name}",
                file=file,
                node=modifier,
                transformation="solc_ast.FunctionDefinition.modifiers",
                metadata=control_metadata,
            )
        )
        if _looks_privileged(modifier_name):
            role_id = _synthetic_id(
                "role",
                file.relative_path,
                contract_name,
                modifier_name,
            )
            nodes.append(
                _synthetic_node(
                    role_id,
                    SolidityGraphNodeKind.ROLE,
                    modifier_name,
                    file,
                    modifier,
                    SolidityProvenance.COMPILER,
                    0.9,
                    {
                        "contract": contract_name,
                        "source": "modifier",
                        **control_metadata,
                    },
                    transformation="modifier_name_privilege_node_classification",
                )
            )
            edges.append(
                _ast_edge(
                    graph=SolidityGraphKind.PRIVILEGE,
                    source_id=function_id,
                    target_id=role_id,
                    label=f"requires role/control {modifier_name}",
                    file=file,
                    node=modifier,
                    transformation="modifier_name_privilege_classification",
                    confidence=0.9,
                    metadata=control_metadata,
                )
            )
    return edges, nodes


def _ast_function_edges(
    *,
    file: DiscoveredFile,
    contract_name: str,
    function_id: str,
    function_node: dict[str, Any],
    body: Any,
    build: SolidityIndexBuild,
    edge_sink: _EdgeSink | None = None,
) -> tuple[list[SolidityGraphEdge], list[SolidityGraphNode]]:
    local_edges: list[SolidityGraphEdge] = []
    edges: list[SolidityGraphEdge] | _EdgeSink = local_edges if edge_sink is None else edge_sink
    nodes: list[SolidityGraphNode] = []
    function_entity = _entity_by_id(build.index.entities, function_id)
    function_source = (
        _entity_source(file.content, function_entity) if function_entity is not None else ""
    )
    state_variables = {
        ast_id: entity_id
        for (path, ast_id), entity_id in build.ast_entity_ids.items()
        if path == file.relative_path
        and (entity := _entity_by_id(build.index.entities, entity_id)) is not None
        and entity.kind
        in {
            SolidityEntityKind.STATE_VARIABLE,
            SolidityEntityKind.IMMUTABLE,
            SolidityEntityKind.CONSTANT,
        }
    }
    writes = _ast_state_writes(body, state_variables)
    all_state_refs = _ast_state_references(body, state_variables)
    reads = [
        (node, variable_id)
        for node, variable_id in all_state_refs
        if not any(
            node is write_node and not reads_previous for write_node, _, _, reads_previous in writes
        )
    ]
    for node, variable_id in reads:
        variable = _entity_by_id(build.index.entities, variable_id)
        if variable is None:
            continue
        edges.append(
            _ast_edge(
                graph=SolidityGraphKind.STATE_READ,
                source_id=function_id,
                target_id=variable_id,
                label=f"reads state {variable.name}",
                file=file,
                node=node,
                transformation="solc_ast.Identifier.referencedDeclaration",
                metadata={
                    "access": "read",
                    "read_modify_write": any(
                        node is write_node and variable_id == write_id and reads_previous
                        for write_node, write_id, _, reads_previous in writes
                    ),
                },
            )
        )
    for node, variable_id, operator, reads_previous in writes:
        variable = _entity_by_id(build.index.entities, variable_id)
        if variable is None:
            continue
        edges.append(
            _ast_edge(
                graph=SolidityGraphKind.STATE_WRITE,
                source_id=function_id,
                target_id=variable_id,
                label=f"writes state {variable.name}",
                file=file,
                node=node,
                transformation="solc_ast.Assignment.leftHandSide",
                metadata={
                    "access": "write",
                    "operator": operator,
                    "write_semantics": ("read_modify_write" if reads_previous else "overwrite"),
                },
            )
        )
    read_ids = {variable_id for _, variable_id in reads}
    write_ids = {variable_id for _, variable_id, _, _ in writes}
    for read_id, write_id in _bounded_state_dependency_pairs(
        read_ids,
        write_ids,
        edge_sink=edge_sink,
        path=file.relative_path,
        function_id=function_id,
        transformation="function_state_read_write_dependency",
    ):
        edges.append(
            _ast_edge(
                graph=SolidityGraphKind.STATE_DEPENDENCY,
                source_id=read_id,
                target_id=write_id,
                label=f"{function_node.get('name') or function_node.get('kind')} derives a write",
                file=file,
                node=function_node,
                transformation="function_state_read_write_dependency",
                confidence=0.9,
                metadata={"function_id": function_id},
            )
        )

    event_edges = _ast_event_state_edges(
        file=file,
        function_id=function_id,
        body=body,
        write_ids=write_ids,
        build=build,
        edge_sink=edge_sink,
    )
    edges.extend(event_edges)
    signature_edges, signature_nodes = _ast_signature_edges(
        file=file,
        function_id=function_id,
        body=body,
        state_references=all_state_refs,
        build=build,
    )
    edges.extend(signature_edges)
    nodes.extend(signature_nodes)

    guard_candidates = _ast_reentrancy_guard_candidates(function_node)
    external_calls: list[tuple[int, str, dict[str, Any]]] = []
    sensitive_targets = set(write_ids)
    for call in _nodes_of_type(body, "FunctionCall"):
        expression = call.get("expression", {})
        if not isinstance(expression, dict):
            continue
        if expression.get("nodeType") == "Identifier":
            call_name = str(expression.get("name", ""))
            declaration = _int_or_none(expression.get("referencedDeclaration"))
            target_id = (
                build.ast_entity_ids.get((file.relative_path, declaration))
                if declaration is not None
                else None
            ) or _named_entity_id(
                build.index.entities,
                path=file.relative_path,
                contract_name=contract_name,
                name=call_name,
                kinds=frozenset(
                    {
                        SolidityEntityKind.FUNCTION,
                        SolidityEntityKind.CONSTRUCTOR,
                    }
                ),
            )
            if target_id is not None:
                edges.append(
                    _ast_edge(
                        graph=SolidityGraphKind.INTERNAL_CALL,
                        source_id=function_id,
                        target_id=target_id,
                        label=f"calls {call_name}",
                        file=file,
                        node=call,
                        transformation="solc_ast.FunctionCall.Identifier",
                        metadata={
                            "call_kind": SolidityGraphKind.INTERNAL_CALL.value,
                            "resolution": (
                                "referenced_declaration"
                                if declaration is not None
                                else "contract_name"
                            ),
                        },
                    )
                )
            continue
        if expression.get("nodeType") == "NewExpression":
            target_label = _expression_label(expression.get("typeName")) or "contract"
            target_id = _synthetic_id(
                "creation",
                file.relative_path,
                contract_name,
                target_label,
            )
            nodes.append(
                _synthetic_node(
                    target_id,
                    SolidityGraphNodeKind.EXTERNAL_TARGET,
                    target_label,
                    file,
                    call,
                    SolidityProvenance.COMPILER,
                    0.95,
                    {"operation": "contract_creation"},
                    transformation="solc_ast.NewExpression.target_node",
                )
            )
            edges.append(
                _ast_edge(
                    graph=SolidityGraphKind.CONTRACT_CREATION,
                    source_id=function_id,
                    target_id=target_id,
                    label=f"creates {target_label}",
                    file=file,
                    node=call,
                    transformation="solc_ast.NewExpression",
                )
            )
            continue
        if expression.get("nodeType") != "MemberAccess":
            continue
        member = str(expression.get("memberName", ""))
        target_label = _expression_label(expression.get("expression")) or "external"
        if member in {"push", "pop", "length"}:
            continue
        target_id = _synthetic_id(
            "external",
            file.relative_path,
            contract_name,
            target_label,
            member,
        )
        target_kind = (
            SolidityGraphNodeKind.ORACLE
            if member in _ORACLE_MEMBERS or _looks_oracle(target_label)
            else SolidityGraphNodeKind.EXTERNAL_TARGET
        )
        nodes.append(
            _synthetic_node(
                target_id,
                target_kind,
                f"{target_label}.{member}",
                file,
                call,
                SolidityProvenance.COMPILER,
                0.9,
                {
                    "target": target_label,
                    "member": member,
                    "call_kind": "target",
                },
                transformation="solc_ast.FunctionCall.MemberAccess.target_node",
            )
        )
        graph = (
            SolidityGraphKind.DELEGATECALL
            if member in {"delegatecall", "callcode"}
            else (
                SolidityGraphKind.LOW_LEVEL_CALL
                if member in _LOW_LEVEL_MEMBERS
                else SolidityGraphKind.EXTERNAL_CALL
            )
        )
        edges.append(
            _ast_edge(
                graph=graph,
                source_id=function_id,
                target_id=target_id,
                label=f"{member} on {target_label}",
                file=file,
                node=call,
                transformation="solc_ast.FunctionCall.MemberAccess",
                metadata={
                    "member": member,
                    "target": target_label,
                    "call_kind": graph.value,
                },
            )
        )
        if graph in {SolidityGraphKind.DELEGATECALL, SolidityGraphKind.LOW_LEVEL_CALL}:
            sensitive_targets.add(target_id)
        dependency_metadata = _dependency_metadata(
            member,
            target_label,
            resolution="compiler_expression_reference",
        )
        edges.append(
            _ast_edge(
                graph=SolidityGraphKind.DEPENDENCY,
                source_id=function_id,
                target_id=target_id,
                label=f"depends on external member {target_label}.{member}",
                file=file,
                node=call,
                transformation="solc_ast.FunctionCall.MemberAccess.dependency",
                confidence=0.9,
                metadata=dependency_metadata,
            )
        )
        external_calls.append((_src_start(call), target_id, call))
        if member in _ASSET_MEMBERS:
            asset_id = _synthetic_id(
                "asset",
                file.relative_path,
                target_label,
                member,
            )
            nodes.append(
                _synthetic_node(
                    asset_id,
                    SolidityGraphNodeKind.ASSET,
                    _asset_label(member, target_label),
                    file,
                    call,
                    SolidityProvenance.COMPILER,
                    0.85,
                    _asset_flow_metadata(member, target_label),
                    transformation="known_asset_transfer_call.asset_node",
                )
            )
            edges.append(
                _ast_edge(
                    graph=SolidityGraphKind.ASSET_FLOW,
                    source_id=function_id,
                    target_id=asset_id,
                    label=_asset_flow_label(member, target_label),
                    file=file,
                    node=call,
                    transformation="known_asset_transfer_call",
                    confidence=0.85,
                    metadata=_asset_flow_metadata(member, target_label),
                )
            )
            sensitive_targets.add(asset_id)
        if member in _ORACLE_MEMBERS or _looks_oracle(target_label):
            oracle_metadata = {
                **dependency_metadata,
                **_oracle_validation_metadata(function_source),
            }
            edges.append(
                _ast_edge(
                    graph=SolidityGraphKind.ORACLE_DEPENDENCY,
                    source_id=function_id,
                    target_id=target_id,
                    label=f"depends on oracle/source {target_label}.{member}",
                    file=file,
                    node=call,
                    transformation="known_oracle_interface_call",
                    confidence=0.85,
                    metadata=oracle_metadata,
                )
            )
    for write_node, variable_id, _, _ in writes:
        write_offset = _src_start(write_node)
        for call_offset, call_target, call_node in external_calls:
            if call_offset >= 0 and write_offset > call_offset:
                call_expression = call_node.get("expression", {})
                callback_member = (
                    str(call_expression.get("memberName", ""))
                    if isinstance(call_expression, dict)
                    else ""
                )
                callback_target = (
                    _expression_label(call_expression.get("expression")) or "external"
                    if isinstance(call_expression, dict)
                    else "external"
                )
                affected_state = _entity_by_id(build.index.entities, variable_id)
                control = (
                    "named_reentrancy_guard_present"
                    if guard_candidates
                    else "no_named_reentrancy_guard"
                )
                edges.append(
                    _ast_sequence_edge(
                        graph=SolidityGraphKind.REENTRANCY,
                        source_id=call_target,
                        target_id=variable_id,
                        label=(
                            "state write follows external interaction with named guard"
                            if guard_candidates
                            else "unguarded state write follows external interaction"
                        ),
                        file=file,
                        first_node=call_node,
                        last_node=write_node,
                        transformation="source_order_external_call_before_state_write",
                        confidence=0.9,
                        metadata={
                            "function_id": function_id,
                            "control_classification": control,
                            "guard_candidates": guard_candidates,
                            "unsafe_transition_candidate": not guard_candidates,
                            "interaction_byte_start": call_offset,
                            "state_write_byte_start": write_offset,
                            "callback_reachability": (
                                "present"
                                if function_node.get("visibility") in {"public", "external"}
                                else "unknown"
                            ),
                            "callback_kind": (
                                "explicit_receiver_hook"
                                if callback_member in _CALLBACK_MEMBERS
                                else "external_interaction"
                            ),
                            "callback_target": callback_target,
                            "callback_member": callback_member,
                            "affected_state_id": variable_id,
                            "affected_state_name": (
                                affected_state.name if affected_state is not None else "unknown"
                            ),
                            "entrypoint_signature": (
                                function_entity.signature if function_entity is not None else None
                            ),
                        },
                    )
                )
    if function_node.get("visibility") in {"public", "external"}:
        for target_id in sorted(sensitive_targets):
            edges.append(
                _ast_edge(
                    graph=SolidityGraphKind.SENSITIVE_REACHABILITY,
                    source_id=function_id,
                    target_id=target_id,
                    label="public entry point reaches a sensitive sink",
                    file=file,
                    node=function_node,
                    transformation="entry_point_sensitive_sink_projection",
                    confidence=0.9,
                )
            )
    return local_edges, nodes


def _ast_event_state_edges(
    *,
    file: DiscoveredFile,
    function_id: str,
    body: Any,
    write_ids: set[str],
    build: SolidityIndexBuild,
    edge_sink: _EdgeSink | None = None,
) -> list[SolidityGraphEdge]:
    """Project compiler-resolved event emissions onto state written by the function."""

    local_edges: list[SolidityGraphEdge] = []
    edges: list[SolidityGraphEdge] | _EdgeSink = local_edges if edge_sink is None else edge_sink
    for emission in _nodes_of_type(body, "EmitStatement"):
        event_call = emission.get("eventCall")
        expression = event_call.get("expression") if isinstance(event_call, dict) else None
        declaration = (
            _int_or_none(expression.get("referencedDeclaration"))
            if isinstance(expression, dict)
            else None
        )
        event_id = (
            build.ast_entity_ids.get((file.relative_path, declaration))
            if declaration is not None
            else None
        )
        event = _entity_by_id(build.index.entities, event_id) if event_id else None
        if event is None or event.kind is not SolidityEntityKind.EVENT:
            continue
        edges.append(
            _ast_edge(
                graph=SolidityGraphKind.EVENT_FLOW,
                source_id=function_id,
                target_id=event.id,
                label=f"emits event {event.name}",
                file=file,
                node=emission,
                transformation="solc_ast.EmitStatement.event_flow",
                confidence=0.95,
                metadata={
                    "event": event.name,
                    "event_resolution": "referenced_declaration",
                },
            )
        )
        for variable_id in sorted(write_ids):
            variable = _entity_by_id(build.index.entities, variable_id)
            if variable is None:
                continue
            edges.append(
                _ast_edge(
                    graph=SolidityGraphKind.EVENT_STATE,
                    source_id=event.id,
                    target_id=variable.id,
                    label=f"event {event.name} accompanies write to {variable.name}",
                    file=file,
                    node=emission,
                    transformation="solc_ast.EmitStatement_to_function_state_writes",
                    confidence=0.9,
                    metadata={"function_id": function_id},
                )
            )
    return local_edges


def _ast_signature_edges(
    *,
    file: DiscoveredFile,
    function_id: str,
    body: Any,
    state_references: list[tuple[dict[str, Any], str]],
    build: SolidityIndexBuild,
) -> tuple[list[SolidityGraphEdge], list[SolidityGraphNode]]:
    """Record signature primitives and replay-domain inputs without judging safety."""

    edges: list[SolidityGraphEdge] = []
    nodes: list[SolidityGraphNode] = []
    for reference, variable_id in state_references:
        variable = _entity_by_id(build.index.entities, variable_id)
        if variable is None:
            continue
        aspect = _signature_domain_aspect(variable.name)
        if aspect is None:
            continue
        edges.append(
            _ast_edge(
                graph=SolidityGraphKind.SIGNATURE_REPLAY,
                source_id=function_id,
                target_id=variable.id,
                label=f"references replay/domain state {variable.name}",
                file=file,
                node=reference,
                transformation="solc_ast_signature_domain_state_reference",
                confidence=0.95,
                metadata={"aspect": aspect, "state_variable": variable.name},
            )
        )

    for call in _nodes_of_type(body, "FunctionCall"):
        expression = call.get("expression")
        if not isinstance(expression, dict):
            continue
        primitive = ""
        if expression.get("nodeType") == "Identifier":
            primitive = str(expression.get("name", ""))
        elif expression.get("nodeType") == "MemberAccess":
            primitive = str(expression.get("memberName", ""))
        if primitive not in _SIGNATURE_PRIMITIVES:
            continue
        target_id = _synthetic_id("signature", file.relative_path, primitive)
        nodes.append(
            _synthetic_node(
                target_id,
                SolidityGraphNodeKind.SIGNATURE_DOMAIN,
                primitive,
                file,
                call,
                SolidityProvenance.COMPILER,
                0.95,
                {"aspect": "signature_primitive", "primitive": primitive},
                transformation="solc_ast_signature_primitive_node",
            )
        )
        edges.append(
            _ast_edge(
                graph=SolidityGraphKind.SIGNATURE_REPLAY,
                source_id=function_id,
                target_id=target_id,
                label=f"uses signature primitive {primitive}",
                file=file,
                node=call,
                transformation="solc_ast_signature_primitive_call",
                confidence=0.95,
                metadata={"aspect": "signature_primitive", "primitive": primitive},
            )
        )

    for member in _nodes_of_type(body, "MemberAccess"):
        member_name = str(member.get("memberName", ""))
        if member_name != "chainid":
            continue
        target_id = _synthetic_id(
            "signature-domain",
            file.relative_path,
            "chainid",
        )
        nodes.append(
            _synthetic_node(
                target_id,
                SolidityGraphNodeKind.SIGNATURE_DOMAIN,
                "block.chainid",
                file,
                member,
                SolidityProvenance.COMPILER,
                0.95,
                {"aspect": "chain_id"},
                transformation="solc_ast_block_chainid_node",
            )
        )
        edges.append(
            _ast_edge(
                graph=SolidityGraphKind.SIGNATURE_REPLAY,
                source_id=function_id,
                target_id=target_id,
                label="binds logic to block.chainid",
                file=file,
                node=member,
                transformation="solc_ast_block_chainid_member",
                confidence=0.95,
                metadata={"aspect": "chain_id"},
            )
        )
    return edges, nodes


def _source_signature_edges(
    function: SolidityEntity,
    source: str,
    file: DiscoveredFile,
    referenced_state: list[SolidityEntity],
    confidence: float,
) -> tuple[list[SolidityGraphEdge], list[SolidityGraphNode]]:
    """Fallback signature/replay facts, explicitly marked as heuristic."""

    edges: list[SolidityGraphEdge] = []
    nodes: list[SolidityGraphNode] = []
    for variable in referenced_state:
        aspect = _signature_domain_aspect(variable.name)
        if aspect is None:
            continue
        edges.append(
            _source_edge(
                SolidityGraphKind.SIGNATURE_REPLAY,
                function,
                variable.id,
                f"heuristic replay/domain state reference {variable.name}",
                file,
                "bounded_source_signature_state_pattern",
                confidence,
                metadata={"aspect": aspect, "state_variable": variable.name},
            )
        )

    patterns: tuple[tuple[str, str, str], ...] = (
        (
            "signature_primitive",
            "signature primitive",
            r"\b(?:ecrecover|ECDSA\s*\.\s*(?:recover|tryRecover)|"
            r"isValidSignature|_?hashTypedDataV4)\b",
        ),
        ("chain_id", "chain ID domain input", r"\b(?:block\s*\.\s*chainid|chainid\s*\(\s*\))"),
        ("contract_domain", "verifying contract domain input", r"\baddress\s*\(\s*this\s*\)"),
        (
            "nonce_or_deadline",
            "nonce/deadline replay input",
            r"\b(?:nonces?|deadline|expiry|DOMAIN_SEPARATOR|domainSeparator)\b",
        ),
    )
    for aspect, label, pattern in patterns:
        if not re.search(pattern, source, re.I):
            continue
        target_id = _synthetic_id(
            "signature-domain",
            function.path,
            function.id,
            aspect,
        )
        nodes.append(
            _entity_range_node(
                target_id,
                SolidityGraphNodeKind.SIGNATURE_DOMAIN,
                label,
                function,
                SolidityProvenance.HEURISTIC,
                min(confidence, 0.5),
                {"aspect": aspect},
                transformation="bounded_source_signature_domain_node",
            )
        )
        edges.append(
            _source_edge(
                SolidityGraphKind.SIGNATURE_REPLAY,
                function,
                target_id,
                f"heuristic {label}",
                file,
                "bounded_source_signature_domain_pattern",
                min(confidence, 0.5),
                metadata={"aspect": aspect},
            )
        )
    return edges, nodes


def _source_semantic_edges(
    files: dict[str, DiscoveredFile],
    entities: list[SolidityEntity],
    *,
    edge_sink: _EdgeSink | None = None,
    node_sink: _NodeSink | None = None,
) -> tuple[list[SolidityGraphEdge], list[SolidityGraphNode]]:
    """Supplement incomplete compiler artifacts and all fallback parser entities."""

    local_edges: list[SolidityGraphEdge] = []
    local_nodes: list[SolidityGraphNode] = []
    edges: list[SolidityGraphEdge] | _EdgeSink = local_edges if edge_sink is None else edge_sink
    nodes: list[SolidityGraphNode] | _NodeSink = local_nodes if node_sink is None else node_sink
    functions = [
        entity
        for entity in entities
        if entity.kind in {SolidityEntityKind.FUNCTION, SolidityEntityKind.CONSTRUCTOR}
    ]
    contract_keys = {
        (entity.path, entity.contract_name)
        for entity in entities
        if entity.contract_name is not None
    }
    state_by_contract = {
        contract_key: [
            entity
            for entity in entities
            if (entity.path, entity.contract_name) == contract_key and _is_state(entity)
        ]
        for contract_key in sorted(contract_keys)
    }
    functions_by_contract = {
        contract_key: [
            entity for entity in functions if (entity.path, entity.contract_name) == contract_key
        ]
        for contract_key in sorted(contract_keys)
    }
    events_by_contract = {
        contract_key: [
            entity
            for entity in entities
            if (entity.path, entity.contract_name) == contract_key
            and entity.kind is SolidityEntityKind.EVENT
        ]
        for contract_key in sorted(contract_keys)
    }
    for function in functions:
        file = files.get(function.path)
        if file is None:
            continue
        source = _entity_source(file.content, function)
        provenance = SolidityProvenance.HEURISTIC
        confidence = 0.55 if function.provenance is SolidityProvenance.COMPILER else 0.4
        contract_label = function.contract_name or ""
        contract_key = (function.path, contract_label)
        role_labels = _roles_from_source(function, source)
        governance_stage = _governance_stage(function, source)
        if governance_stage is not None:
            governance_id = _synthetic_id(
                "governance",
                function.path,
                contract_label,
                governance_stage,
            )
            governance_metadata = {
                "stage": governance_stage,
                "authorization_control": (
                    "present"
                    if any(
                        _control_metadata(role)["control_resolution"] == "resolved"
                        for role in role_labels
                    )
                    else "unknown"
                ),
                "delay_control": _governance_delay_control(governance_stage, source),
                "classification": "bounded_governance_source_pattern",
            }
            nodes.append(
                _entity_range_node(
                    governance_id,
                    SolidityGraphNodeKind.GOVERNANCE,
                    f"{contract_label or 'contract'} {governance_stage}",
                    function,
                    provenance,
                    confidence,
                    governance_metadata,
                    transformation="bounded_source_governance_stage_node",
                )
            )
            edges.append(
                _source_edge(
                    SolidityGraphKind.GOVERNANCE,
                    function,
                    governance_id,
                    f"governance stage {governance_stage}",
                    file,
                    "bounded_source_governance_stage_classification",
                    confidence,
                    metadata=governance_metadata,
                )
            )
        operation = _function_asset_operation(function.name)
        if operation is not None:
            operation_edges, operation_nodes = _function_asset_edges(
                function,
                file,
                operation,
                confidence=min(0.7, confidence + 0.15),
            )
            edges.extend(operation_edges)
            nodes.extend(operation_nodes)
        for target in functions_by_contract.get(contract_key, []):
            if target.id == function.id:
                continue
            if re.search(rf"(?<![.\w]){re.escape(target.name)}\s*\(", source):
                edges.append(
                    _source_edge(
                        SolidityGraphKind.INTERNAL_CALL,
                        function,
                        target.id,
                        f"heuristic call to {target.name}",
                        file,
                        "bounded_source_function_call_regex",
                        confidence,
                    )
                )
        state_reads: set[str] = set()
        state_writes: set[str] = set()
        for variable in state_by_contract.get(contract_key, []):
            references = list(re.finditer(rf"\b{re.escape(variable.name)}\b", source))
            if not references:
                continue
            growth_match = re.search(
                rf"\b{re.escape(variable.name)}\s*\.\s*push\s*\(",
                source,
            )
            if growth_match is not None:
                growth_metadata = _state_growth_metadata(
                    function,
                    variable,
                    source,
                    file.content,
                )
                state_writes.add(variable.id)
                edges.append(
                    _source_occurrence_edge(
                        SolidityGraphKind.STATE_GROWTH,
                        function,
                        variable.id,
                        f"state collection growth through {variable.name}.push",
                        file,
                        "bounded_source_array_push_growth",
                        confidence,
                        relative_start=growth_match.start(),
                        relative_end=growth_match.end(),
                        metadata=growth_metadata,
                    )
                )
            write_match = re.search(
                rf"\b{re.escape(variable.name)}(?:\s*\[[^\]]+\])?\s*"
                r"(?P<operator>\+\+|--|\+=|-=|\*=|/=|%=|\|=|&=|\^=|<<=|>>=|=)",
                source,
            )
            reads_previous = bool(
                write_match is not None
                and (write_match.group("operator") != "=" or len(references) > 1)
            )
            if write_match is not None:
                state_writes.add(variable.id)
                edges.append(
                    _source_edge(
                        SolidityGraphKind.STATE_WRITE,
                        function,
                        variable.id,
                        f"heuristic write to state {variable.name}",
                        file,
                        "bounded_source_state_assignment_regex",
                        confidence,
                        metadata={
                            "access": "write",
                            "operator": write_match.group("operator"),
                            "write_semantics": (
                                "read_modify_write" if reads_previous else "overwrite"
                            ),
                        },
                    )
                )
            if write_match is None or reads_previous:
                state_reads.add(variable.id)
                edges.append(
                    _source_edge(
                        SolidityGraphKind.STATE_READ,
                        function,
                        variable.id,
                        f"heuristic read of state {variable.name}",
                        file,
                        "bounded_source_state_reference_regex",
                        confidence,
                        metadata={
                            "access": "read",
                            "read_modify_write": reads_previous,
                        },
                    )
                )
        for read_id, write_id in _bounded_state_dependency_pairs(
            state_reads,
            state_writes,
            edge_sink=edge_sink,
            path=file.relative_path,
            function_id=function.id,
            transformation="bounded_source_function_state_projection",
        ):
            edges.append(
                _source_edge(
                    SolidityGraphKind.STATE_DEPENDENCY,
                    function,
                    write_id,
                    "heuristic state read/write dependency",
                    file,
                    "bounded_source_function_state_projection",
                    confidence,
                    source_id=read_id,
                )
            )
        for event in events_by_contract.get(contract_key, []):
            event_matches = list(re.finditer(rf"\bemit\s+{re.escape(event.name)}\s*\(", source))
            for event_match in event_matches:
                edges.append(
                    _source_occurrence_edge(
                        SolidityGraphKind.EVENT_FLOW,
                        function,
                        event.id,
                        f"heuristic emission of event {event.name}",
                        file,
                        "bounded_source_event_emission_regex",
                        confidence,
                        relative_start=event_match.start(),
                        relative_end=event_match.end(),
                        metadata={
                            "event": event.name,
                            "event_resolution": "indexed_source_declaration",
                        },
                    )
                )
                for variable_id in sorted(state_writes):
                    edges.append(
                        _source_occurrence_edge(
                            SolidityGraphKind.EVENT_STATE,
                            function,
                            variable_id,
                            f"event {event.name} accompanies a state write",
                            file,
                            "bounded_source_emit_state_write_projection",
                            confidence,
                            relative_start=event_match.start(),
                            relative_end=event_match.end(),
                            source_id=event.id,
                            metadata={
                                "function_id": function.id,
                                "event_resolution": "indexed_source_declaration",
                            },
                        )
                    )
                if _looks_offchain_event(event.name):
                    offchain_id = _synthetic_id(
                        "offchain-event-consumer",
                        function.path,
                        contract_label,
                        event.name,
                    )
                    offchain_metadata = _offchain_event_metadata(event.name)
                    nodes.append(
                        _entity_range_node(
                            offchain_id,
                            SolidityGraphNodeKind.OFFCHAIN_ACTOR,
                            f"off-chain consumer of {event.name}",
                            function,
                            provenance,
                            confidence,
                            offchain_metadata,
                            transformation="bounded_source_offchain_event_consumer_node",
                        )
                    )
                    edges.append(
                        _source_occurrence_edge(
                            SolidityGraphKind.OFFCHAIN_DEPENDENCY,
                            function,
                            offchain_id,
                            f"event {event.name} may require an off-chain consumer",
                            file,
                            "bounded_source_offchain_event_dependency",
                            confidence,
                            relative_start=event_match.start(),
                            relative_end=event_match.end(),
                            source_id=event.id,
                            metadata=offchain_metadata,
                        )
                    )
        signature_edges, signature_nodes = _source_signature_edges(
            function,
            source,
            file,
            [
                variable
                for variable in state_by_contract.get(contract_key, [])
                if variable.id in state_reads
            ],
            confidence,
        )
        edges.extend(signature_edges)
        nodes.extend(signature_nodes)
        call_matches = list(
            re.finditer(
                r"\b(?P<target>[A-Za-z_][A-Za-z0-9_.\[\]]*)\s*\.\s*"
                r"(?P<member>delegatecall|callcode|staticcall|call|send|transfer|"
                r"safeTransferFrom|safeBatchTransferFrom|transferFrom|mint|burn|"
                r"deposit|withdraw|redeem|claim|claimRewards|harvest|liquidate|"
                r"repay|borrow|reward|distributeReward|accrueReward|balanceOf|"
                r"totalAssets|totalSupply|latestPrice|latestRoundData|spotPrice|"
                r"getPrice|consult|observe|slot0|getReserves|sendMessage|dispatch|"
                r"publishMessage|relayMessage|processMessage|receiveMessage|"
                r"bridgeMessage|onCreditReceived|onTokenTransfer|tokensReceived|"
                r"onERC721Received|onERC1155Received|onERC1155BatchReceived)"
                r"\s*(?:\{[^}]*\})?\s*\(",
                source,
            )
        )
        external_calls: list[tuple[re.Match[str], str, SolidityGraphNode]] = []
        message_member_seen = False
        for match in call_matches:
            target_label = match.group("target")
            member = match.group("member")
            target_id = _synthetic_id(
                "external",
                function.path,
                function.contract_name or "",
                target_label,
                member,
            )
            node_kind = (
                SolidityGraphNodeKind.ORACLE
                if member in _ORACLE_MEMBERS or _looks_oracle(target_label)
                else SolidityGraphNodeKind.EXTERNAL_TARGET
            )
            target_node = _entity_range_node(
                target_id,
                node_kind,
                f"{target_label}.{member}",
                function,
                provenance,
                confidence,
                {
                    "target": target_label,
                    "member": member,
                    "call_kind": "target",
                },
                transformation="bounded_source_member_call_target_node",
            )
            nodes.append(target_node)
            graph = (
                SolidityGraphKind.DELEGATECALL
                if member in {"delegatecall", "callcode"}
                else (
                    SolidityGraphKind.LOW_LEVEL_CALL
                    if member in _LOW_LEVEL_MEMBERS
                    else SolidityGraphKind.EXTERNAL_CALL
                )
            )
            edges.append(
                _source_occurrence_edge(
                    graph,
                    function,
                    target_id,
                    f"heuristic {member} on {target_label}",
                    file,
                    "bounded_source_member_call_regex",
                    confidence,
                    relative_start=match.start(),
                    relative_end=match.end(),
                    metadata={
                        "target": target_label,
                        "member": member,
                        "call_kind": graph.value,
                    },
                )
            )
            dependency_metadata = _dependency_metadata(
                member,
                target_label,
                resolution="source_reference_only",
            )
            edges.append(
                _source_occurrence_edge(
                    SolidityGraphKind.DEPENDENCY,
                    function,
                    target_id,
                    f"heuristic dependency on {target_label}.{member}",
                    file,
                    "bounded_source_member_dependency_regex",
                    confidence,
                    relative_start=match.start(),
                    relative_end=match.end(),
                    metadata=dependency_metadata,
                )
            )
            external_calls.append((match, target_id, target_node))
            if member in _ASSET_MEMBERS:
                asset_id = _synthetic_id(
                    "asset",
                    function.path,
                    target_label,
                    member,
                )
                nodes.append(
                    _entity_range_node(
                        asset_id,
                        SolidityGraphNodeKind.ASSET,
                        _asset_label(member, target_label),
                        function,
                        provenance,
                        confidence,
                        _asset_flow_metadata(member, target_label),
                        transformation="known_asset_transfer_call_regex.asset_node",
                    )
                )
                edges.append(
                    _source_occurrence_edge(
                        SolidityGraphKind.ASSET_FLOW,
                        function,
                        asset_id,
                        _asset_flow_label(member, target_label),
                        file,
                        "known_asset_transfer_call_regex",
                        confidence,
                        relative_start=match.start(),
                        relative_end=match.end(),
                        metadata=_asset_flow_metadata(member, target_label),
                    )
                )
            if member in _ORACLE_MEMBERS or _looks_oracle(target_label):
                oracle_metadata = {
                    **dependency_metadata,
                    **_oracle_validation_metadata(source),
                }
                edges.append(
                    _source_occurrence_edge(
                        SolidityGraphKind.ORACLE_DEPENDENCY,
                        function,
                        target_id,
                        f"heuristic oracle dependency {target_label}.{member}",
                        file,
                        "known_oracle_call_regex",
                        confidence,
                        relative_start=match.start(),
                        relative_end=match.end(),
                        metadata=oracle_metadata,
                    )
                )
            if member in _MESSAGE_MEMBERS:
                message_member_seen = True
                direction = _message_direction(member) or "unknown"
                message_id = _synthetic_id(
                    "cross-chain-message",
                    function.path,
                    contract_label,
                    function.id,
                    target_label,
                    member,
                )
                message_metadata = _message_assumption_metadata(
                    function,
                    source,
                    direction=direction,
                    operation=member,
                )
                nodes.append(
                    _entity_range_node(
                        message_id,
                        SolidityGraphNodeKind.MESSAGE,
                        f"{direction} message via {target_label}.{member}",
                        function,
                        provenance,
                        confidence,
                        message_metadata,
                        transformation="bounded_source_message_call_node",
                    )
                )
                edges.append(
                    _source_occurrence_edge(
                        SolidityGraphKind.CROSS_CHAIN,
                        function,
                        message_id,
                        f"heuristic {direction} cross-chain message {member}",
                        file,
                        "bounded_source_cross_chain_member_call",
                        confidence,
                        relative_start=match.start(),
                        relative_end=match.end(),
                        metadata=message_metadata,
                    )
                )
        if not message_member_seen:
            entry_direction = _message_direction(function.name)
            if entry_direction is not None:
                message_id = _synthetic_id(
                    "cross-chain-message",
                    function.path,
                    contract_label,
                    function.id,
                    entry_direction,
                )
                message_metadata = _message_assumption_metadata(
                    function,
                    source,
                    direction=entry_direction,
                    operation=function.name,
                )
                nodes.append(
                    _entity_range_node(
                        message_id,
                        SolidityGraphNodeKind.MESSAGE,
                        f"{entry_direction} message entry {function.name}",
                        function,
                        provenance,
                        confidence,
                        message_metadata,
                        transformation="bounded_source_message_entry_node",
                    )
                )
                edges.append(
                    _source_edge(
                        SolidityGraphKind.CROSS_CHAIN,
                        function,
                        message_id,
                        f"heuristic {entry_direction} cross-chain message entry",
                        file,
                        "bounded_source_cross_chain_function_name",
                        confidence,
                        metadata=message_metadata,
                    )
                )
        callback_kind = _offchain_callback_kind(function.name)
        if callback_kind is not None:
            offchain_id = _synthetic_id(
                "offchain-callback",
                function.path,
                contract_label,
                function.id,
                callback_kind,
            )
            callback_metadata = {
                "dependency_kind": callback_kind,
                "authentication_resolution": ("present" if role_labels else "unknown"),
                "delivery_assumption": "unknown",
                "ordering_assumption": "unknown",
                "classification": "bounded_source_callback_name",
                "deterministic_fact": False,
            }
            nodes.append(
                _entity_range_node(
                    offchain_id,
                    SolidityGraphNodeKind.OFFCHAIN_ACTOR,
                    f"off-chain callback dependency {function.name}",
                    function,
                    provenance,
                    confidence,
                    callback_metadata,
                    transformation="bounded_source_offchain_callback_node",
                )
            )
            edges.append(
                _source_edge(
                    SolidityGraphKind.OFFCHAIN_DEPENDENCY,
                    function,
                    offchain_id,
                    f"heuristic off-chain callback {function.name}",
                    file,
                    "bounded_source_offchain_callback_classification",
                    confidence,
                    metadata=callback_metadata,
                )
            )
        if external_calls and state_writes:
            last_call, call_target, _call_target_node = max(
                external_calls,
                key=lambda item: item[0].start(),
            )
            guard_candidates = _source_reentrancy_guard_candidates(source)
            for variable_id in sorted(state_writes):
                found_variable = _entity_by_id(entities, variable_id)
                write_match = (
                    re.search(
                        rf"\b{re.escape(found_variable.name)}(?:\s*\[[^\]]+\])?\s*"
                        r"(?:=|\+=|-=|\*=|/=|\+\+|--)",
                        source[last_call.end() :],
                    )
                    if found_variable
                    else None
                )
                if write_match is not None:
                    write_end = last_call.end() + write_match.end()
                    control = (
                        "named_reentrancy_guard_present"
                        if guard_candidates
                        else "no_named_reentrancy_guard"
                    )
                    edges.append(
                        _source_sequence_edge(
                            source=function,
                            source_id=call_target,
                            target_id=variable_id,
                            label=(
                                "heuristic state write follows external interaction "
                                "with named guard"
                                if guard_candidates
                                else "heuristic unguarded state write follows external interaction"
                            ),
                            file=file,
                            relative_start=last_call.start(),
                            relative_end=write_end,
                            confidence=min(confidence, 0.5),
                            metadata={
                                "function_id": function.id,
                                "control_classification": control,
                                "guard_candidates": guard_candidates,
                                "unsafe_transition_candidate": not guard_candidates,
                                "interaction_relative_start": last_call.start(),
                                "state_write_relative_start": (
                                    last_call.end() + write_match.start()
                                ),
                                "callback_reachability": (
                                    "present"
                                    if function.visibility in {"public", "external"}
                                    else "unknown"
                                ),
                                "callback_kind": (
                                    "explicit_receiver_hook"
                                    if last_call.group("member") in _CALLBACK_MEMBERS
                                    else "external_interaction"
                                ),
                                "callback_target": last_call.group("target"),
                                "callback_member": last_call.group("member"),
                                "affected_state_id": variable_id,
                                "affected_state_name": (
                                    found_variable.name if found_variable is not None else "unknown"
                                ),
                                "entrypoint_signature": function.signature,
                            },
                        )
                    )
        for role in sorted(role_labels):
            role_id = _synthetic_id(
                "role",
                function.path,
                function.contract_name or "",
                role,
            )
            control_metadata = _control_metadata(role)
            node_kind = (
                SolidityGraphNodeKind.UNKNOWN
                if control_metadata["control_resolution"] == "unknown"
                else SolidityGraphNodeKind.ROLE
            )
            nodes.append(
                _entity_range_node(
                    role_id,
                    node_kind,
                    role,
                    function,
                    provenance,
                    confidence,
                    {
                        "source": "source_control_pattern",
                        **control_metadata,
                    },
                    transformation="bounded_source_authorization_role_node",
                )
            )
            edges.append(
                _source_edge(
                    SolidityGraphKind.PRIVILEGE,
                    function,
                    role_id,
                    f"heuristic authorization control {role}",
                    file,
                    "bounded_source_authorization_pattern",
                    confidence,
                    metadata=control_metadata,
                )
            )
        if function.visibility in {"public", "external"} and (
            state_writes
            or call_matches
            or any(token in function.name.lower() for token in _SENSITIVE_FUNCTION_TOKENS)
        ):
            sink_id = min(state_writes) if state_writes else function.id
            edges.append(
                _source_edge(
                    SolidityGraphKind.SENSITIVE_REACHABILITY,
                    function,
                    sink_id,
                    "public entry point reaches a heuristic sensitive operation",
                    file,
                    "entry_point_sensitive_name_or_operation_projection",
                    confidence,
                )
            )
    return local_edges, local_nodes


def _proxy_edges(
    files: dict[str, DiscoveredFile],
    entities: list[SolidityEntity],
    *,
    edge_sink: _EdgeSink | None = None,
    node_sink: _NodeSink | None = None,
) -> tuple[list[SolidityGraphEdge], list[SolidityGraphNode]]:
    local_edges: list[SolidityGraphEdge] = []
    local_nodes: list[SolidityGraphNode] = []
    edges: list[SolidityGraphEdge] | _EdgeSink = local_edges if edge_sink is None else edge_sink
    nodes: list[SolidityGraphNode] | _NodeSink = local_nodes if node_sink is None else node_sink
    contracts = [
        entity
        for entity in entities
        if entity.kind
        in {
            SolidityEntityKind.CONTRACT,
            SolidityEntityKind.INTERFACE,
            SolidityEntityKind.LIBRARY,
        }
    ]
    functions_by_contract = {
        (contract.path, contract.name): [
            entity
            for entity in entities
            if entity.path == contract.path
            and entity.contract_name == contract.name
            and entity.kind in {SolidityEntityKind.FUNCTION, SolidityEntityKind.CONSTRUCTOR}
        ]
        for contract in contracts
    }
    for contract in contracts:
        file = files.get(contract.path)
        if file is None:
            continue
        source = _entity_source(file.content, contract)
        contract_functions = functions_by_contract.get((contract.path, contract.name), [])
        for function in contract_functions:
            lowered = function.name.casefold()
            function_source = _entity_source(file.content, function)
            if "initialize" in lowered:
                initializer_metadata = {
                    "guard_resolution": _initializer_guard_resolution(function_source),
                    "initializer_kind": (
                        "reinitializer" if "reinitialize" in lowered else "initializer"
                    ),
                }
                edges.append(
                    _source_edge(
                        SolidityGraphKind.INITIALIZER,
                        function,
                        contract.id,
                        f"initializer path {function.name}",
                        file,
                        "function_name_initializer_classification",
                        0.65,
                        metadata=initializer_metadata,
                    )
                )
            if "upgrade" in lowered or "implementation" in lowered:
                edges.append(
                    _source_edge(
                        SolidityGraphKind.PROXY,
                        function,
                        contract.id,
                        f"upgrade/implementation control {function.name}",
                        file,
                        "function_name_upgrade_classification",
                        0.65,
                        metadata={
                            "surface": "upgrade_or_implementation",
                            "authorization_resolution": (
                                "present"
                                if any(
                                    _control_metadata(role)["control_resolution"] == "resolved"
                                    for role in _roles_from_source(function, function_source)
                                )
                                else "unknown"
                            ),
                        },
                    )
                )
        patterns = [name for name, pattern in _PROXY_PATTERNS if pattern.search(source)]
        slot_kinds = [
            slot_kind
            for slot_kind, slot_pattern in _PROXY_SLOT_PATTERNS
            if slot_pattern.search(source)
        ]
        delegates = re.search(r"\b(?:delegatecall|callcode)\s*\(", source) is not None
        if (
            not patterns
            and "proxy" not in contract.name.casefold()
            and not slot_kinds
            and not delegates
        ):
            continue
        if not patterns:
            patterns = ["name_based_proxy"]
        for pattern in patterns:
            proxy_id = _synthetic_id("proxy", contract.id, pattern)
            nodes.append(
                _entity_range_node(
                    proxy_id,
                    SolidityGraphNodeKind.PROXY,
                    f"{contract.name}:{pattern}",
                    contract,
                    SolidityProvenance.HEURISTIC,
                    0.65,
                    {"pattern": pattern},
                    transformation="bounded_proxy_pattern_node",
                )
            )
            edges.append(
                _source_edge(
                    SolidityGraphKind.PROXY,
                    contract,
                    proxy_id,
                    f"detected {pattern} proxy pattern",
                    file,
                    "bounded_proxy_pattern_classification",
                    0.65,
                    metadata={
                        "pattern": pattern,
                        "evidence_resolution": "source_pattern",
                    },
                )
            )
        if delegates:
            delegate_target = _synthetic_id("delegate-target", contract.id)
            nodes.append(
                _entity_range_node(
                    delegate_target,
                    SolidityGraphNodeKind.EXTERNAL_TARGET,
                    "runtime implementation target",
                    contract,
                    SolidityProvenance.HEURISTIC,
                    0.55,
                    {"operation": "delegatecall"},
                    transformation="bounded_source_delegatecall_target_node",
                )
            )
            edges.append(
                _source_edge(
                    SolidityGraphKind.DELEGATECALL,
                    contract,
                    delegate_target,
                    "proxy delegates to runtime implementation",
                    file,
                    "bounded_source_delegatecall_pattern",
                    0.55,
                )
            )
        for slot_kind in slot_kinds:
            slot_id = _synthetic_id("slot", contract.id, slot_kind)
            slot_metadata = {
                "unstructured": True,
                "slot_kind": slot_kind,
                "evidence_resolution": "source_symbol_or_known_constant",
            }
            nodes.append(
                _entity_range_node(
                    slot_id,
                    SolidityGraphNodeKind.STORAGE_SLOT,
                    f"{slot_kind} proxy slot",
                    contract,
                    SolidityProvenance.HEURISTIC,
                    0.7,
                    slot_metadata,
                    transformation="known_eip1967_slot_node",
                )
            )
            edges.append(
                _source_edge(
                    SolidityGraphKind.STORAGE_LAYOUT,
                    contract,
                    slot_id,
                    f"uses an unstructured {slot_kind} proxy slot",
                    file,
                    "known_eip1967_slot_pattern",
                    0.7,
                    metadata=slot_metadata,
                )
            )
    return local_edges, local_nodes


def _storage_layout(
    files: dict[str, DiscoveredFile],
    entities: list[SolidityEntity],
    compiler_layout: list[SolidityStorageEntry],
    *,
    edge_sink: _EdgeSink | None = None,
    node_sink: _NodeSink | None = None,
    storage_sink: _BoundedFactCollector[SolidityStorageEntry] | None = None,
    populate_storage: bool = True,
) -> tuple[list[SolidityStorageEntry], list[SolidityGraphEdge], list[SolidityGraphNode]]:
    """Use compiler layouts and fill missing contracts with marked heuristics."""

    local_entries: list[SolidityStorageEntry] = []
    entry_sink: list[SolidityStorageEntry] | _BoundedFactCollector[SolidityStorageEntry] = (
        local_entries if storage_sink is None else storage_sink
    )
    local_edges: list[SolidityGraphEdge] = []
    local_nodes: list[SolidityGraphNode] = []
    edges: list[SolidityGraphEdge] | _EdgeSink = local_edges if edge_sink is None else edge_sink
    nodes: list[SolidityGraphNode] | _NodeSink = local_nodes if node_sink is None else node_sink
    by_contract: dict[tuple[str, str], list[SolidityEntity]] = {}
    for entity in entities:
        if entity.contract_name and _is_state(entity):
            by_contract.setdefault((entity.path, entity.contract_name), []).append(entity)
    contract_ids = {
        (entity.path, entity.name): entity.id
        for entity in entities
        if entity.kind
        in {
            SolidityEntityKind.CONTRACT,
            SolidityEntityKind.INTERFACE,
            SolidityEntityKind.LIBRARY,
        }
    }
    compiler_by_contract: defaultdict[tuple[str, str], list[SolidityStorageEntry]] = defaultdict(
        list
    )
    for compiler_entry in compiler_layout:
        compiler_by_contract[(compiler_entry.path, compiler_entry.contract_name)].append(
            compiler_entry
        )
    compiler_contracts = set(compiler_by_contract)

    def fallback_entries() -> Iterable[SolidityStorageEntry]:
        for (contract_path, contract_name), variables in sorted(by_contract.items()):
            if (contract_path, contract_name) in compiler_contracts:
                continue
            for slot, variable in enumerate(
                sorted(variables, key=lambda item: (item.path, item.start_line, item.id))
            ):
                file = files.get(variable.path)
                if file is None:
                    continue
                yield SolidityStorageEntry(
                    id=_synthetic_id(
                        "storage",
                        contract_path,
                        contract_name,
                        variable.name,
                        str(slot),
                    ),
                    contract_name=contract_name,
                    declaring_contract_name=contract_name,
                    variable_name=variable.name,
                    type_name=_state_type_from_source(file.content, variable),
                    slot=str(slot),
                    offset=0,
                    byte_size=None,
                    path=variable.path,
                    start_line=variable.start_line,
                    end_line=variable.end_line,
                    source_hash=variable.source_hash,
                    provenance=SolidityProvenance.HEURISTIC,
                    confidence=0.35,
                    transformation="source_order_storage_layout_fallback",
                )

    # Feed the bounded storage collector directly. The fallback iterator is replayable,
    # so derived graph facts can still be streamed without retaining the candidate objects.
    if populate_storage:
        entry_sink.extend(compiler_layout)
        entry_sink.extend(fallback_entries())
        entries = local_entries if storage_sink is None else storage_sink.retained()
    else:
        entries = []

    def emit_entry(entry: SolidityStorageEntry) -> None:
        contract_id = contract_ids.get((entry.path, entry.contract_name))
        if contract_id is None:
            return
        compiler_backed = entry.provenance is SolidityProvenance.COMPILER
        edges.append(
            SolidityGraphEdge(
                graph=SolidityGraphKind.STORAGE_LAYOUT,
                source_id=contract_id,
                target_id=entry.id,
                label=(
                    f"compiler storage slot {entry.slot}:{entry.offset}"
                    if compiler_backed
                    else f"estimated storage order {entry.slot}"
                ),
                provenance=entry.provenance,
                path=entry.path,
                start_line=entry.start_line,
                end_line=entry.end_line,
                source_hash=entry.source_hash,
                confidence=entry.confidence,
                transformation=(
                    "solc_storageLayout"
                    if compiler_backed
                    else "source_order_storage_layout_fallback"
                ),
                metadata=(
                    {
                        "type": entry.type_name,
                        "slot": entry.slot,
                        "offset": entry.offset,
                        "byte_size": entry.byte_size,
                        "declaring_contract": entry.declaring_contract_name,
                        "layout_resolution": "compiler",
                    }
                    if compiler_backed
                    else {
                        "layout_resolution": "unknown_estimate",
                        "estimated": True,
                    }
                ),
            )
        )

    for compiler_entry in compiler_layout:
        emit_entry(compiler_entry)
    for fallback_entry in fallback_entries():
        emit_entry(fallback_entry)

    def emit_order_edges(
        contract_name: str,
        contract_entries: Iterable[SolidityStorageEntry],
    ) -> None:
        ordered = sorted(
            contract_entries,
            key=lambda item: (_slot_number(item.slot), item.offset, item.variable_name, item.id),
        )
        for left, right in pairwise(ordered):
            both_compiler = (
                left.provenance is SolidityProvenance.COMPILER
                and right.provenance is SolidityProvenance.COMPILER
            )
            same_slot = left.slot == right.slot
            overlap = _storage_entries_overlap(left, right)
            end_line = right.end_line if right.path == left.path else left.end_line
            file = files.get(left.path)
            source_hash = (
                _line_range_hash(file.content, left.start_line, end_line)
                if file is not None
                else left.source_hash
            )
            edges.append(
                SolidityGraphEdge(
                    graph=SolidityGraphKind.UPGRADE_COMPATIBILITY,
                    source_id=left.id,
                    target_id=right.id,
                    label=(
                        f"{contract_name} storage order "
                        f"{left.slot}:{left.offset} before {right.slot}:{right.offset}"
                    ),
                    provenance=(
                        SolidityProvenance.COMPILER
                        if both_compiler
                        else SolidityProvenance.HEURISTIC
                    ),
                    path=left.path,
                    start_line=left.start_line,
                    end_line=end_line,
                    source_hash=source_hash,
                    confidence=min(left.confidence, right.confidence),
                    transformation=(
                        "compiler_storage_order_projection"
                        if both_compiler
                        else "fallback_storage_order_projection"
                    ),
                    metadata={
                        "left_type": left.type_name,
                        "right_type": right.type_name,
                        "same_slot": same_slot,
                        "packed": same_slot and not overlap,
                        "storage_gap": "__gap" in {left.variable_name, right.variable_name},
                        "collision": overlap,
                        "layout_resolution": ("compiler" if both_compiler else "unknown_estimate"),
                        "compatibility": "observed_order" if both_compiler else "unknown",
                    },
                )
            )

    for (_contract_path, contract_name), contract_entries in sorted(compiler_by_contract.items()):
        emit_order_edges(contract_name, contract_entries)
    for (_contract_path, contract_name), fallback_contract_entries in groupby(
        fallback_entries(),
        key=lambda item: (item.path, item.contract_name),
    ):
        emit_order_edges(contract_name, fallback_contract_entries)
    edges.extend(_versioned_layout_edges(compiler_layout, edge_sink=edge_sink))
    # Storage-order and version-comparison edges are emitted after direct layout edges
    # and carry higher risk. Replay the node facts only after all those edges have
    # established the bounded final endpoint priorities.
    nodes.extend(_storage_entry_node(entry) for entry in compiler_layout)
    nodes.extend(_storage_entry_node(entry) for entry in fallback_entries())
    return entries, local_edges, local_nodes


def _initializer_guard_resolution(source: str) -> str:
    signature = source.split("{", 1)[0].casefold()
    if re.search(r"\b(?:re)?initializer\b", signature):
        return "named_guard"
    normalized = source.casefold().replace("_", "")
    if "require" in normalized and "initialized" in normalized:
        return "inline_state_guard"
    return "unknown"


def _storage_entries_overlap(
    left: SolidityStorageEntry,
    right: SolidityStorageEntry,
) -> bool:
    if left.slot != right.slot:
        return False
    if left.byte_size is None or right.byte_size is None:
        return left.offset == right.offset
    left_end = left.offset + left.byte_size
    right_end = right.offset + right.byte_size
    return left.offset < right_end and right.offset < left_end


def _versioned_layout_edges(
    entries: list[SolidityStorageEntry],
    *,
    edge_sink: _EdgeSink | None = None,
) -> list[SolidityGraphEdge]:
    families: dict[
        tuple[str, str],
        dict[int, dict[str, list[SolidityStorageEntry]]],
    ] = {}
    for entry in entries:
        if entry.provenance is not SolidityProvenance.COMPILER:
            continue
        version = _layout_version(entry.contract_name)
        if version is None:
            continue
        family, number = version
        families.setdefault((entry.path, family), {}).setdefault(number, {}).setdefault(
            entry.contract_name,
            [],
        ).append(entry)

    local_edges: list[SolidityGraphEdge] = []
    edges: list[SolidityGraphEdge] | _EdgeSink = local_edges if edge_sink is None else edge_sink
    for (source_path, family), versions in sorted(families.items()):
        for current_version in sorted(versions):
            earlier_versions = [version for version in versions if version < current_version]
            if not earlier_versions:
                continue
            prior_version = max(earlier_versions)
            for prior_contract, prior_entries in sorted(versions[prior_version].items()):
                for current_contract, current_entries in sorted(versions[current_version].items()):
                    edges.extend(
                        _compare_versioned_layouts(
                            family=family,
                            source_path=source_path,
                            prior_contract=prior_contract,
                            prior_version=prior_version,
                            prior_entries=sorted(
                                prior_entries,
                                key=lambda item: (
                                    _slot_number(item.slot),
                                    item.offset,
                                    item.variable_name,
                                    item.id,
                                ),
                            ),
                            current_contract=current_contract,
                            current_version=current_version,
                            current_entries=sorted(
                                current_entries,
                                key=lambda item: (
                                    _slot_number(item.slot),
                                    item.offset,
                                    item.variable_name,
                                    item.id,
                                ),
                            ),
                        )
                    )
    return local_edges


def _compare_versioned_layouts(
    *,
    family: str,
    source_path: str,
    prior_contract: str,
    prior_version: int,
    prior_entries: list[SolidityStorageEntry],
    current_contract: str,
    current_version: int,
    current_entries: list[SolidityStorageEntry],
) -> Iterator[SolidityGraphEdge]:
    prior_by_name = {entry.variable_name: entry for entry in prior_entries}
    current_by_name = {entry.variable_name: entry for entry in current_entries}
    common_metadata = {
        "comparison": "versioned_layout",
        "family": family,
        "source_path": source_path,
        "from_contract": prior_contract,
        "from_version": prior_version,
        "to_contract": current_contract,
        "to_version": current_version,
        "layout_resolution": "compiler",
    }

    for variable_name in sorted(prior_by_name.keys() & current_by_name.keys()):
        prior = prior_by_name[variable_name]
        current = current_by_name[variable_name]
        if variable_name == "__gap":
            compatible = _compatible_gap_change(prior, current)
            change_kind = "storage_gap"
        else:
            compatible = (
                prior.slot == current.slot
                and prior.offset == current.offset
                and prior.type_name == current.type_name
            )
            change_kind = "stable_variable"
        yield _layout_comparison_edge(
            prior,
            current,
            label=(f"{family} {variable_name} layout v{prior_version} to v{current_version}"),
            metadata={
                **common_metadata,
                "variable": variable_name,
                "change_kind": change_kind,
                "slot_changed": prior.slot != current.slot,
                "offset_changed": prior.offset != current.offset,
                "type_changed": prior.type_name != current.type_name,
                "compatibility": "compatible" if compatible else "incompatible",
            },
        )

    prior_gap = prior_by_name.get("__gap")
    prior_anchor = prior_gap or max(
        prior_entries,
        key=lambda entry: (_slot_number(entry.slot), entry.offset, entry.variable_name),
    )
    prior_max_end = max(
        (span[1] for entry in prior_entries if (span := _storage_slot_span(entry)) is not None),
        default=None,
    )
    prior_gap_span = _storage_slot_span(prior_gap) if prior_gap is not None else None
    for variable_name in sorted(current_by_name.keys() - prior_by_name.keys()):
        current = current_by_name[variable_name]
        current_span = _storage_slot_span(current)
        consumes_gap = bool(
            prior_gap_span is not None
            and current_span is not None
            and prior_gap_span[0] <= current_span[0] < prior_gap_span[1]
        )
        appended = bool(
            prior_max_end is not None
            and current_span is not None
            and current_span[0] >= prior_max_end
        )
        compatible = consumes_gap or appended
        yield _layout_comparison_edge(
            prior_anchor,
            current,
            label=(f"{family} new variable {variable_name} v{prior_version} to v{current_version}"),
            metadata={
                **common_metadata,
                "variable": variable_name,
                "change_kind": "new_variable",
                "storage_gap_consumption": consumes_gap,
                "append_only": appended,
                "compatibility": "compatible" if compatible else "incompatible",
            },
        )


def _layout_comparison_edge(
    prior: SolidityStorageEntry,
    current: SolidityStorageEntry,
    *,
    label: str,
    metadata: dict[str, Any],
) -> SolidityGraphEdge:
    return SolidityGraphEdge(
        graph=SolidityGraphKind.UPGRADE_COMPATIBILITY,
        source_id=prior.id,
        target_id=current.id,
        label=label,
        provenance=SolidityProvenance.COMPILER,
        path=current.path,
        start_line=current.start_line,
        end_line=current.end_line,
        source_hash=current.source_hash,
        confidence=min(prior.confidence, current.confidence),
        transformation="compiler_storage_layout_version_comparison",
        metadata=metadata,
    )


def _compatible_gap_change(
    prior: SolidityStorageEntry,
    current: SolidityStorageEntry,
) -> bool:
    prior_span = _storage_slot_span(prior)
    current_span = _storage_slot_span(current)
    return bool(
        prior_span is not None
        and current_span is not None
        and current_span[0] >= prior_span[0]
        and current_span[1] == prior_span[1]
    )


def _storage_slot_span(entry: SolidityStorageEntry | None) -> tuple[int, int] | None:
    if entry is None:
        return None
    try:
        start = int(entry.slot, 0)
    except ValueError:
        return None
    byte_size = entry.byte_size
    if byte_size is None:
        array_size = re.search(r"\[(?P<count>\d+)\]", entry.type_name)
        byte_size = int(array_size.group("count")) * 32 if array_size else 32
    slots = max(1, (entry.offset + byte_size + 31) // 32)
    return start, start + slots


def _layout_version(contract_name: str) -> tuple[str, int] | None:
    match = re.fullmatch(
        r"(?P<family>.+?)(?:Implementation)?V(?P<version>\d+)(?:Safe|Unsafe)?",
        contract_name,
        re.I,
    )
    if match is None:
        return None
    return match.group("family"), int(match.group("version"))


def _slot_number(value: str) -> tuple[int, str]:
    try:
        return (int(value, 0), "")
    except ValueError:
        return (2**256 - 1, value)


def _ast_state_writes(
    node: Any,
    state_variables: dict[int, str],
) -> list[tuple[dict[str, Any], str, str, bool]]:
    writes: list[tuple[dict[str, Any], str, str, bool]] = []
    for assignment in [
        *_nodes_of_type(node, "Assignment"),
        *_nodes_of_type(node, "UnaryOperation"),
    ]:
        target = (
            assignment.get("leftHandSide")
            if assignment.get("nodeType") == "Assignment"
            else assignment.get("subExpression")
        )
        operator = str(
            assignment.get(
                "operator",
                "=" if assignment.get("nodeType") == "Assignment" else "",
            )
        )
        reads_previous = operator in {
            "+=",
            "-=",
            "*=",
            "/=",
            "%=",
            "|=",
            "&=",
            "^=",
            "<<=",
            ">>=",
            "++",
            "--",
        }
        for reference in _identifier_nodes(target):
            declaration = _int_or_none(reference.get("referencedDeclaration"))
            if declaration is not None and declaration in state_variables:
                writes.append(
                    (
                        reference,
                        state_variables[declaration],
                        operator or "unary",
                        reads_previous,
                    )
                )
    return writes


def _ast_state_references(
    node: Any,
    state_variables: dict[int, str],
) -> list[tuple[dict[str, Any], str]]:
    references: list[tuple[dict[str, Any], str]] = []
    for reference in _identifier_nodes(node):
        declaration = _int_or_none(reference.get("referencedDeclaration"))
        if declaration is not None and declaration in state_variables:
            references.append((reference, state_variables[declaration]))
    return references


def _nodes_of_type(node: Any, node_type: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(node, dict):
        if node.get("nodeType") == node_type:
            found.append(node)
        for value in node.values():
            found.extend(_nodes_of_type(value, node_type))
    elif isinstance(node, list):
        for item in node:
            found.extend(_nodes_of_type(item, node_type))
    return found


def _identifier_nodes(node: Any) -> list[dict[str, Any]]:
    return [
        item
        for kind in ("Identifier", "MemberAccess", "IndexAccess")
        for item in _nodes_of_type(node, kind)
    ]


def _ast_edge(
    *,
    graph: SolidityGraphKind,
    source_id: str,
    target_id: str,
    label: str,
    file: DiscoveredFile,
    node: dict[str, Any],
    transformation: str,
    confidence: float = 0.95,
    metadata: dict[str, Any] | None = None,
) -> SolidityGraphEdge:
    start_line, end_line = _line_range(file.content, str(node.get("src", "")))
    return SolidityGraphEdge(
        graph=graph,
        source_id=source_id,
        target_id=target_id,
        label=label,
        provenance=SolidityProvenance.COMPILER,
        path=file.relative_path,
        start_line=start_line,
        end_line=end_line,
        source_hash=_line_range_hash(file.content, start_line, end_line),
        confidence=confidence,
        transformation=transformation,
        metadata=metadata or {},
    )


def _ast_sequence_edge(
    *,
    graph: SolidityGraphKind,
    source_id: str,
    target_id: str,
    label: str,
    file: DiscoveredFile,
    first_node: dict[str, Any],
    last_node: dict[str, Any],
    transformation: str,
    confidence: float,
    metadata: dict[str, Any],
) -> SolidityGraphEdge:
    start_line, _ = _line_range(file.content, str(first_node.get("src", "")))
    _, end_line = _line_range(file.content, str(last_node.get("src", "")))
    end_line = max(start_line, end_line)
    return SolidityGraphEdge(
        graph=graph,
        source_id=source_id,
        target_id=target_id,
        label=label,
        provenance=SolidityProvenance.COMPILER,
        path=file.relative_path,
        start_line=start_line,
        end_line=end_line,
        source_hash=_line_range_hash(file.content, start_line, end_line),
        confidence=confidence,
        transformation=transformation,
        metadata=metadata,
    )


def _source_edge(
    graph: SolidityGraphKind,
    source: SolidityEntity,
    target_id: str,
    label: str,
    file: DiscoveredFile,
    transformation: str,
    confidence: float,
    *,
    source_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SolidityGraphEdge:
    return SolidityGraphEdge(
        graph=graph,
        source_id=source_id or source.id,
        target_id=target_id,
        label=label,
        provenance=SolidityProvenance.HEURISTIC,
        path=source.path,
        start_line=source.start_line,
        end_line=source.end_line,
        source_hash=_line_range_hash(file.content, source.start_line, source.end_line),
        confidence=confidence,
        transformation=transformation,
        metadata=metadata or {},
    )


def _source_occurrence_edge(
    graph: SolidityGraphKind,
    source: SolidityEntity,
    target_id: str,
    label: str,
    file: DiscoveredFile,
    transformation: str,
    confidence: float,
    *,
    relative_start: int,
    relative_end: int,
    source_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SolidityGraphEdge:
    """Bind a fallback edge to one bounded source occurrence within an entity."""

    entity_source = _entity_source(file.content, source)
    bounded_start = max(0, min(relative_start, len(entity_source)))
    bounded_end = max(bounded_start, min(relative_end, len(entity_source)))
    start_line = source.start_line + entity_source[:bounded_start].count("\n")
    end_line = source.start_line + entity_source[:bounded_end].count("\n")
    occurrence_metadata: dict[str, Any] = {
        "occurrence_relative_start": bounded_start,
        "occurrence_relative_end": bounded_end,
        **(metadata or {}),
    }
    return SolidityGraphEdge(
        graph=graph,
        source_id=source_id or source.id,
        target_id=target_id,
        label=label,
        provenance=SolidityProvenance.HEURISTIC,
        path=source.path,
        start_line=start_line,
        end_line=max(start_line, end_line),
        source_hash=_line_range_hash(file.content, start_line, max(start_line, end_line)),
        confidence=confidence,
        transformation=transformation,
        metadata=occurrence_metadata,
    )


def _source_sequence_edge(
    *,
    source: SolidityEntity,
    source_id: str,
    target_id: str,
    label: str,
    file: DiscoveredFile,
    relative_start: int,
    relative_end: int,
    confidence: float,
    metadata: dict[str, Any],
) -> SolidityGraphEdge:
    function_source = _entity_source(file.content, source)
    bounded_start = max(0, min(relative_start, len(function_source)))
    bounded_end = max(bounded_start, min(relative_end, len(function_source)))
    start_line = source.start_line + function_source[:bounded_start].count("\n")
    end_line = source.start_line + function_source[:bounded_end].count("\n")
    return SolidityGraphEdge(
        graph=SolidityGraphKind.REENTRANCY,
        source_id=source_id,
        target_id=target_id,
        label=label,
        provenance=SolidityProvenance.HEURISTIC,
        path=source.path,
        start_line=start_line,
        end_line=max(start_line, end_line),
        source_hash=_line_range_hash(file.content, start_line, max(start_line, end_line)),
        confidence=confidence,
        transformation="bounded_source_ordering_regex",
        metadata=metadata,
    )


def _entity_node(entity: SolidityEntity) -> SolidityGraphNode:
    kind = (
        SolidityGraphNodeKind.STATE_VARIABLE if _is_state(entity) else SolidityGraphNodeKind.ENTITY
    )
    return SolidityGraphNode(
        id=entity.id,
        kind=kind,
        label=(f"{entity.contract_name}.{entity.name}" if entity.contract_name else entity.name),
        path=entity.path,
        start_line=entity.start_line,
        end_line=entity.end_line,
        source_hash=entity.source_hash,
        provenance=entity.provenance,
        confidence=entity.confidence,
        transformation=entity.transformation,
        metadata={"entity_kind": entity.kind.value},
    )


def _storage_entry_node(entry: SolidityStorageEntry) -> SolidityGraphNode:
    estimated = entry.provenance is not SolidityProvenance.COMPILER
    return SolidityGraphNode(
        id=entry.id,
        kind=SolidityGraphNodeKind.STORAGE_SLOT,
        label=(
            f"{entry.contract_name}.{entry.variable_name}@slot?{entry.slot}"
            if estimated
            else f"{entry.contract_name}.{entry.variable_name}@{entry.slot}:{entry.offset}"
        ),
        path=entry.path,
        start_line=entry.start_line,
        end_line=entry.end_line,
        source_hash=entry.source_hash,
        provenance=entry.provenance,
        confidence=entry.confidence,
        transformation=(f"{entry.transformation}.node" if estimated else entry.transformation),
        metadata={
            "slot": entry.slot,
            "offset": entry.offset,
            "type": entry.type_name,
            "byte_size": entry.byte_size,
            "declaring_contract": entry.declaring_contract_name,
            "ast_id": entry.ast_id,
            "estimated": estimated,
            "layout_resolution": "unknown_estimate" if estimated else "compiler",
        },
    )


def _synthetic_node(
    node_id: str,
    kind: SolidityGraphNodeKind,
    label: str,
    file: DiscoveredFile,
    node: dict[str, Any],
    provenance: SolidityProvenance,
    confidence: float,
    metadata: dict[str, Any],
    *,
    transformation: str,
) -> SolidityGraphNode:
    start_line, end_line = _line_range(file.content, str(node.get("src", "")))
    return SolidityGraphNode(
        id=node_id,
        kind=kind,
        label=label,
        path=file.relative_path,
        start_line=start_line,
        end_line=end_line,
        source_hash=_line_range_hash(file.content, start_line, end_line),
        provenance=provenance,
        confidence=confidence,
        transformation=transformation,
        metadata=metadata,
    )


def _entity_range_node(
    node_id: str,
    kind: SolidityGraphNodeKind,
    label: str,
    entity: SolidityEntity,
    provenance: SolidityProvenance,
    confidence: float,
    metadata: dict[str, Any],
    *,
    transformation: str,
) -> SolidityGraphNode:
    return SolidityGraphNode(
        id=node_id,
        kind=kind,
        label=label,
        path=entity.path,
        start_line=entity.start_line,
        end_line=entity.end_line,
        source_hash=entity.source_hash,
        provenance=provenance,
        confidence=confidence,
        transformation=transformation,
        metadata=metadata,
    )


def _line_range(content: str, src: str) -> tuple[int, int]:
    """Convert a valid half-open compiler byte span to an inclusive line range."""

    parsed = _parse_src_components(src)
    if parsed is None:
        raise ValueError("compiler source range is malformed")
    start, length, source_id = parsed
    encoded, starts = _source_coordinates(content)
    end = start + length
    if source_id < 0 or start < 0 or length < 0 or start >= len(encoded) or end > len(encoded):
        raise ValueError("compiler source range is outside the source bytes")
    start_line = bisect_right(starts, start)
    end_position = start if length == 0 else end - 1
    end_line = bisect_right(starts, end_position)
    return start_line, max(start_line, end_line)


def _src_start(node: dict[str, Any]) -> int:
    try:
        return int(str(node.get("src", "")).split(":", 1)[0])
    except ValueError:
        return -1


def _expression_label(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    if value.get("name"):
        return str(value["name"])
    if value.get("namePath"):
        return str(value["namePath"])
    if value.get("memberName"):
        base = _expression_label(value.get("expression"))
        return f"{base}.{value['memberName']}".strip(".")
    if value.get("typeName"):
        return _expression_label(value["typeName"])
    if value.get("typeDescriptions", {}).get("typeString"):
        return str(value["typeDescriptions"]["typeString"])
    return str(value.get("nodeType", ""))


def _name_from_ast(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("namePath", "name"):
            if value.get(key):
                return str(value[key]).rsplit(".", 1)[-1]
        if value.get("referencedDeclaration"):
            return str(value["referencedDeclaration"])
    return str(value or "")


def _entity_id_for_node(
    source_path: str,
    node: dict[str, Any],
    build: SolidityIndexBuild,
) -> str | None:
    ast_id = _int_or_none(node.get("id"))
    return build.ast_entity_ids.get((source_path, ast_id)) if ast_id is not None else None


def _named_entity_id(
    entities: list[SolidityEntity],
    *,
    path: str,
    contract_name: str | None,
    name: str,
    kinds: frozenset[SolidityEntityKind],
) -> str | None:
    """Resolve an AST name without coalescing same-named symbols across paths."""

    candidates = [entity for entity in entities if entity.kind in kinds and entity.name == name]
    path_matches = [
        entity
        for entity in candidates
        if entity.path == path and entity.contract_name == contract_name
    ]
    if len(path_matches) == 1:
        return path_matches[0].id

    contract_matches = [entity for entity in candidates if entity.contract_name == contract_name]
    if len(contract_matches) == 1:
        return contract_matches[0].id
    if len(candidates) == 1:
        return candidates[0].id
    return None


def _entity_by_id(
    entities: list[SolidityEntity],
    entity_id: str,
) -> SolidityEntity | None:
    return next((entity for entity in entities if entity.id == entity_id), None)


def _entity_source(content: str, entity: SolidityEntity) -> str:
    lines = content.splitlines(keepends=True)
    return "".join(lines[entity.start_line - 1 : entity.end_line])


def _roles_from_source(function: SolidityEntity, source: str) -> set[str]:
    roles = {
        match.group(0)
        for match in re.finditer(
            r"\bonly[A-Za-z0-9_]*|\brequires?Role\b|\bhasRole\b|\bmsg\.sender\s*==\s*"
            r"(?:owner|admin|governor|guardian|timelock|[A-Za-z_][A-Za-z0-9_]*Multisig)",
            source,
            re.I,
        )
    }
    roles.update(
        match.group("role")
        for match in re.finditer(
            r"\b(?:onlyRole|hasRole)\s*\(\s*(?P<role>[A-Za-z_][A-Za-z0-9_]*)",
            source,
        )
    )
    if not roles and any(token in function.name.lower() for token in _SENSITIVE_FUNCTION_TOKENS):
        roles.add("privileged_surface_unclassified")
    return roles


def _control_metadata(role: str) -> dict[str, Any]:
    if role == "privileged_surface_unclassified":
        return {
            "control": role,
            "control_resolution": "unknown",
            "control_kind": "unresolved_sensitive_surface",
            "governance_control": False,
            "reason": "no source-local authorization control was classified",
        }
    lowered = role.casefold()
    if "msg.sender" in lowered:
        control_kind = "inline_sender_check"
    elif lowered.startswith("only"):
        control_kind = "named_modifier"
    elif "role" in lowered:
        control_kind = "access_control_role"
    else:
        control_kind = "source_control_pattern"
    return {
        "control": role,
        "control_resolution": "resolved",
        "control_kind": control_kind,
        "governance_control": _looks_governance(role),
    }


def _governance_stage(function: SolidityEntity, source: str) -> str | None:
    name = function.name.casefold().replace("_", "")
    context = f"{function.contract_name or ''} {source}".casefold()
    has_governance_context = any(token in context for token in _GOVERNANCE_CONTEXT_TOKENS)
    for stage, tokens in _GOVERNANCE_STAGE_TOKENS:
        if any(token in name for token in tokens) and (
            has_governance_context or stage in {"proposal", "vote"}
        ):
            return stage
    return None


def _governance_delay_control(stage: str, source: str) -> str:
    if stage not in {"queue", "execute"}:
        return "not_applicable"
    guarded = (
        " ".join(
            re.findall(
                r"\brequire\s*\((.*?)\)\s*;",
                source,
                flags=re.IGNORECASE | re.DOTALL,
            )
        )
        .casefold()
        .replace("_", "")
    )
    has_clock = "block.timestamp" in guarded or "block.number" in guarded
    has_delay_state = any(
        token in guarded for token in ("delay", "eta", "readyat", "schedule", "timelock", "minwait")
    )
    return "present" if has_clock and has_delay_state else "unknown"


def _message_direction(value: str) -> str | None:
    normalized = value.casefold().replace("_", "")
    if any(token in normalized for token in _OUTBOUND_MESSAGE_TOKENS):
        return "outbound"
    if any(token in normalized for token in _INBOUND_MESSAGE_TOKENS):
        return "inbound"
    return None


def _message_assumption_metadata(
    function: SolidityEntity,
    source: str,
    *,
    direction: str,
    operation: str,
) -> dict[str, Any]:
    guarded = (
        " ".join(
            re.findall(
                r"\brequire\s*\((.*?)\)\s*;",
                source,
                flags=re.IGNORECASE | re.DOTALL,
            )
        )
        .casefold()
        .replace("_", "")
    )
    authentication_terms = (
        "sourcechain",
        "srcchain",
        "sourcesender",
        "originsender",
        "trustedremote",
        "trustedmessenger",
        "authorizedrelayer",
        "messenger",
    )
    replay_terms = (
        "processed",
        "consumed",
        "messageid",
        "messagenonce",
    )
    ordering_terms = (
        "nextnonce",
        "expectednonce",
        "sequencenumber",
        "messagenonce",
    )
    finality_terms = (
        "confirmations",
        "minconfirmations",
        "finalitydelay",
        "finalizedblock",
    )
    return {
        "direction": direction,
        "operation": operation,
        "function_id": function.id,
        "authentication_evidence": (
            "present" if any(term in guarded for term in authentication_terms) else "unknown"
        ),
        "replay_protection_evidence": (
            "present" if any(term in guarded for term in replay_terms) else "unknown"
        ),
        "ordering_evidence": (
            "present" if any(term in guarded for term in ordering_terms) else "unknown"
        ),
        "finality_evidence": (
            "present" if any(term in guarded for term in finality_terms) else "unknown"
        ),
        "classification": "heuristic_source_pattern",
        "deterministic_fact": False,
    }


def _looks_offchain_event(event_name: str) -> bool:
    lowered = event_name.casefold()
    return any(token in lowered for token in _OFFCHAIN_EVENT_TOKENS)


def _offchain_event_metadata(event_name: str) -> dict[str, Any]:
    lowered = event_name.casefold()
    dependency_kind = (
        "relayer_or_message_consumer"
        if any(token in lowered for token in ("message", "bridge", "dispatch", "relay"))
        else "request_or_query_consumer"
    )
    return {
        "event": event_name,
        "dependency_kind": dependency_kind,
        "delivery_assumption": "unknown",
        "ordering_assumption": "unknown",
        "consumer_resolution": "unknown",
        "classification": "heuristic_event_name",
        "deterministic_fact": False,
    }


def _offchain_callback_kind(function_name: str) -> str | None:
    normalized = function_name.casefold().replace("_", "")
    if any(token in normalized for token in ("fulfill", "callback", "report")):
        return "oracle_or_request_fulfillment"
    if "relay" in normalized:
        return "relayer_callback"
    return None


def _ast_reentrancy_guard_candidates(function_node: dict[str, Any]) -> list[str]:
    candidates = [
        _name_from_ast(modifier.get("modifierName"))
        for modifier in function_node.get("modifiers", []) or []
        if isinstance(modifier, dict)
    ]
    return sorted({name for name in candidates if _looks_reentrancy_guard(name)})


def _source_reentrancy_guard_candidates(source: str) -> list[str]:
    signature = source.split("{", 1)[0]
    names = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", signature)
    return sorted({name for name in names if _looks_reentrancy_guard(name)})


def _looks_reentrancy_guard(value: str) -> bool:
    normalized = re.sub(r"[^a-z]", "", value.casefold())
    return "nonreentrant" in normalized or "reentrancyguard" in normalized


def _state_growth_metadata(
    function: SolidityEntity,
    variable: SolidityEntity,
    source: str,
    file_source: str,
) -> dict[str, Any]:
    guard = re.search(
        rf"\brequire\s*\(\s*{re.escape(variable.name)}\s*\.\s*length\s*"
        r"(?P<operator><|<=)\s*(?P<bound>[A-Za-z_][A-Za-z0-9_]*|[0-9]+)",
        source,
    )
    bound_value: int | None = None
    if guard is not None:
        bound = guard.group("bound")
        if bound.isdigit():
            bound_value = int(bound)
        else:
            declaration = re.search(
                rf"\buint(?:256)?\s+(?:(?:public|private|internal)\s+)?"
                rf"constant\s+{re.escape(bound)}\s*=\s*(?P<value>[0-9]+)\s*;",
                file_source,
            )
            if declaration is not None:
                bound_value = int(declaration.group("value"))
    threshold = (
        bound_value + (1 if guard is not None and guard.group("operator") == "<=" else 0)
        if bound_value is not None
        else None
    )
    return {
        "operation": "array_push",
        "entrypoint_visibility": function.visibility or "unknown",
        "entrypoint_signature": function.signature,
        "state_variable_id": variable.id,
        "state_variable_name": variable.name,
        "growth_limit_resolution": "present" if threshold is not None else "unknown",
        "growth_threshold": threshold,
        "guard_expression": guard.group(0)[:200] if guard is not None else None,
        "classification": "bounded_source_array_push",
        "deterministic_fact": False,
    }


def _looks_privileged(value: str) -> bool:
    lowered = value.lower()
    return any(token in lowered for token in _PRIVILEGED_TOKENS)


def _looks_governance(value: str) -> bool:
    lowered = value.casefold()
    return any(
        token in lowered
        for token in (
            *_GOVERNANCE_CONTEXT_TOKENS,
            "proposer",
            "executor",
            "voter",
        )
    )


def _looks_oracle(value: str) -> bool:
    lowered = value.lower()
    return any(token in lowered for token in ("oracle", "feed", "price", "twap", "sequencer"))


def _dependency_metadata(
    member: str,
    target: str,
    *,
    resolution: str,
) -> dict[str, str]:
    unresolved_target = target.casefold() in {"", "external", "unknown"}
    return {
        "target": target or "unknown",
        "member": member,
        "dependency_kind": (
            "cross_chain_messenger"
            if member in _MESSAGE_MEMBERS
            else (
                "oracle"
                if member in _ORACLE_MEMBERS or _looks_oracle(target)
                else "external_contract"
            )
        ),
        "dependency_resolution": "unknown_target" if unresolved_target else resolution,
    }


def _oracle_validation_metadata(source: str) -> dict[str, str]:
    normalized = source.casefold().replace("_", "")
    guarded = (
        " ".join(
            re.findall(
                r"\brequire\s*\((.*?)\)\s*;",
                source,
                flags=re.IGNORECASE | re.DOTALL,
            )
        )
        .casefold()
        .replace("_", "")
    )
    freshness_terms = (
        "updatedat",
        "latesttimestamp",
        "heartbeat",
        "maxage",
        "stale",
        "answeredInRound".casefold(),
    )
    has_freshness_value = any(term in normalized for term in freshness_terms)
    has_clock_or_round = any(
        term in normalized
        for term in ("block.timestamp", "block.number", "roundid", "answeredInRound".casefold())
    )
    configured_scale = "decimals" in normalized
    configured_sequencer = any(
        term in normalized for term in ("sequencerup", "sequenceravailable", "issequencerup")
    )
    has_freshness_guard = (
        has_freshness_value
        and has_clock_or_round
        and all(term in guarded for term in ("updatedat", "block.timestamp"))
    )
    has_scale_guard = configured_scale and "decimals" in guarded
    has_availability_guard = any(
        re.search(rf"\b{term}\b\s*(?:>|!=)\s*0", guarded) for term in ("answer", "price")
    )
    has_sequencer_guard = configured_sequencer and any(
        term in guarded for term in ("sequencerup", "sequenceravailable", "issequencerup")
    )
    return {
        "oracle_guard_configuration": (
            "configured" if configured_scale and configured_sequencer else "unknown"
        ),
        "freshness_validation": "present" if has_freshness_guard else "unknown",
        "scale_validation": "present" if has_scale_guard else "unknown",
        "availability_validation": "present" if has_availability_guard else "unknown",
        "sequencer_validation": "present" if has_sequencer_guard else "unknown",
    }


def _signature_domain_aspect(value: str) -> str | None:
    lowered = value.casefold().replace("_", "")
    for token in _SIGNATURE_DOMAIN_TOKENS:
        normalized = token.casefold().replace("_", "")
        if normalized in lowered:
            return token
    return None


def _asset_label(member: str, target: str) -> str:
    operation = _asset_operation(member)
    if operation == "balance_observation":
        return f"observed asset accounting via {target}.{member}"
    if member in {"transfer", "send"} and target in {"payable", "address", "msg.sender"}:
        return "native ETH"
    return f"asset via {target}.{member}"


def _asset_flow_label(member: str, target: str) -> str:
    operation = _asset_operation(member)
    direction = _asset_flow_direction(member)
    return f"{direction} {operation} through {target}.{member}"


def _asset_flow_metadata(member: str, target: str) -> dict[str, str]:
    direction = _asset_flow_direction(member)
    return {
        "target": target,
        "member": member,
        "operation": _asset_operation(member),
        "flow_direction": direction,
        "endpoint_kind": direction,
        "asset_standard": _asset_standard(member, target),
        "classification": "member_call",
    }


def _asset_flow_direction(member: str) -> str:
    operation = _asset_operation(member)
    if operation in {"mint", "deposit", "reward", "borrow", "donation"}:
        return "source"
    if operation in {"burn", "withdraw", "redeem", "claim", "liquidation", "repay"}:
        return "sink"
    if operation == "balance_observation":
        return "observation"
    return "transfer"


def _asset_standard(member: str, target: str) -> str:
    normalized_target = target.lower()
    if member in {"transfer", "send"} and target in {"payable", "address", "msg.sender"}:
        return "native_eth"
    if member == "safeBatchTransferFrom":
        return "erc1155"
    if member == "safeTransferFrom":
        return "erc721_or_erc1155"
    if member in _TOKEN_OBSERVATION_MEMBERS:
        return "token_or_protocol_accounting"
    if member in {"transfer", "transferFrom", "mint", "_mint", "burn", "_burn"}:
        if any(token in normalized_target for token in ("asset", "token", "erc20")):
            return "erc20_like"
        return "token_like"
    if member in {
        "deposit",
        "withdraw",
        "redeem",
        "claim",
        "claimRewards",
        "harvest",
        "liquidate",
        "repay",
        "borrow",
        "reward",
        "distributeReward",
        "accrueReward",
    }:
        return "protocol_accounting"
    return "unknown"


def _asset_operation(value: str) -> str:
    normalized = value.casefold().replace("_", "")
    aliases = {
        "mint": "mint",
        "burn": "burn",
        "deposit": "deposit",
        "stake": "deposit",
        "supply": "deposit",
        "contribute": "deposit",
        "withdraw": "withdraw",
        "unstake": "withdraw",
        "redeem": "redeem",
        "reward": "reward",
        "distributereward": "reward",
        "accruereward": "reward",
        "claim": "claim",
        "claimrewards": "claim",
        "harvest": "claim",
        "liquidate": "liquidation",
        "liquidation": "liquidation",
        "repay": "repay",
        "borrow": "borrow",
        "donate": "donation",
        "transfer": "transfer",
        "transferfrom": "transfer",
        "safetransferfrom": "transfer",
        "safebatchtransferfrom": "transfer",
        "send": "transfer",
        "balanceof": "balance_observation",
        "totalassets": "balance_observation",
        "totalsupply": "balance_observation",
        "balanceobservation": "balance_observation",
    }
    return aliases.get(normalized, "unknown")


def _function_asset_operation(name: str) -> str | None:
    operation = _asset_operation(name)
    return operation if operation != "unknown" else None


def _function_asset_edges(
    function: SolidityEntity,
    file: DiscoveredFile,
    operation: str,
    *,
    confidence: float,
) -> tuple[list[SolidityGraphEdge], list[SolidityGraphNode]]:
    direction = _asset_flow_direction(operation)
    target_id = _synthetic_id(
        "asset-operation",
        function.path,
        function.id,
        operation,
    )
    metadata = {
        "target": function.contract_name or "contract",
        "member": function.name,
        "operation": operation,
        "flow_direction": direction,
        "endpoint_kind": direction,
        "asset_standard": "protocol_accounting",
        "classification": "function_name",
    }
    node = _entity_range_node(
        target_id,
        SolidityGraphNodeKind.ASSET,
        f"{operation} {direction} at {function.contract_name or 'contract'}.{function.name}",
        function,
        SolidityProvenance.HEURISTIC,
        confidence,
        metadata,
        transformation="function_name_asset_operation_node",
    )
    edge = _source_edge(
        SolidityGraphKind.ASSET_FLOW,
        function,
        target_id,
        f"{direction} {operation} boundary {function.name}",
        file,
        "function_name_asset_operation_classification",
        confidence,
        metadata=metadata,
    )
    return [edge], [node]


def _state_type_from_source(content: str, entity: SolidityEntity) -> str:
    source = _entity_source(content, entity)
    prefix = source.split(entity.name, 1)[0].strip()
    return prefix[-160:] or "unknown"


def _is_state(entity: SolidityEntity) -> bool:
    return entity.kind in {
        SolidityEntityKind.STATE_VARIABLE,
        SolidityEntityKind.IMMUTABLE,
        SolidityEntityKind.CONSTANT,
    }


def _synthetic_id(*parts: str) -> str:
    payload = "\0".join(parts)
    return "graph-" + hashlib.sha256(payload.encode()).hexdigest()[:20]


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _unique_edges(edges: list[SolidityGraphEdge]) -> list[SolidityGraphEdge]:
    by_key: dict[tuple[str, str, str, str, str, int, int, int | None], SolidityGraphEdge] = {}
    for edge in edges:
        key = _edge_key(edge)
        previous = by_key.get(key)
        if previous is None or edge.confidence > previous.confidence:
            by_key[key] = edge
    return sorted(
        by_key.values(),
        key=lambda edge: (
            edge.graph.value,
            edge.source_id,
            edge.target_id,
            edge.path,
            edge.start_line,
            edge.end_line,
            _int_or_none(edge.metadata.get("occurrence_relative_start")) or -1,
            edge.label,
        ),
    )


def _unique_nodes(nodes: list[SolidityGraphNode]) -> list[SolidityGraphNode]:
    by_id: dict[str, SolidityGraphNode] = {}
    for node in nodes:
        previous = by_id.get(node.id)
        if previous is None or node.confidence > previous.confidence:
            by_id[node.id] = node
    return sorted(by_id.values(), key=lambda node: (node.kind.value, node.id))
