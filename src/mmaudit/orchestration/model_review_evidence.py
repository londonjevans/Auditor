"""Fail-closed sealing for explicit, surface-specific model review evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from mmaudit.constants import SPECIALIST_INVESTIGATOR_ROLES
from mmaudit.models.openrouter import StructuredCompletion, strict_json_schema
from mmaudit.models.schemas import (
    CandidateReviewBatch,
    ContextExcerpt,
    ContextPackage,
    Location,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewCitation,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphNode,
    SolidityGraphSet,
    SoliditySymbolIndex,
)
from mmaudit.models.usage import is_creditable_usage_record

_BASE_REVIEW_ROLES = frozenset({"source_audit", "business_logic", "configuration"})
_SPECIALIST_REVIEW_ROLES = frozenset(f"specialist:{role}" for role in SPECIALIST_INVESTIGATOR_ROLES)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
_DIRECT_ENTRY_SURFACES = frozenset(
    {
        ModelReviewSurfaceKind.ENTRY_POINT,
        ModelReviewSurfaceKind.PRIVILEGE_FUNCTION,
        ModelReviewSurfaceKind.ASSET_FUNCTION,
    }
)
_FUNCTION_KINDS = frozenset(
    {
        SolidityEntityKind.FUNCTION,
        SolidityEntityKind.CONSTRUCTOR,
    }
)
_GENERIC_OBSERVATION_PHRASES = frozenset(
    {
        "explicitly considered this supplied surface",
        "inspected for its state effects",
        "reviewed against its state effects",
        "the cited transition was evaluated",
        "the supplied surface was reviewed",
        "the named invariant was reviewed",
    }
)
_BEHAVIOR_TERMS = frozenset(
    {
        "assign",
        "burn",
        "call",
        "check",
        "compare",
        "decrement",
        "emit",
        "increment",
        "mint",
        "read",
        "record",
        "return",
        "revert",
        "transfer",
        "update",
        "validate",
        "write",
    }
)
_SECURITY_TERMS = frozenset(
    {
        "account",
        "asset",
        "authorization",
        "balance",
        "conservation",
        "integrity",
        "invariant",
        "loss",
        "oracle",
        "overflow",
        "privilege",
        "reentrancy",
        "replay",
        "round",
        "state",
        "storage",
    }
)
_ANCHOR_STOPWORDS = frozenset(
    {
        "assess",
        "authorization",
        "behavior",
        "contract",
        "declared",
        "function",
        "invariant",
        "preservation",
        "preserve",
        "protocol",
        "security",
        "state",
        "surface",
        "transition",
        "uint",
        "uint256",
    }
)


@dataclass(frozen=True, slots=True)
class _DeterministicReviewGraph:
    """Trusted citation identities and adjacency derived from compiler artifacts."""

    citation_tokens: dict[tuple[str, int, int, str, str], frozenset[str]]
    symbol_tokens: dict[str, frozenset[str]]
    identity_symbol_tokens: dict[str, frozenset[str]]
    entry_tokens: frozenset[str]
    adjacency: frozenset[tuple[str, str]]
    entities_by_id: dict[str, SolidityEntity]
    edge_tokens_by_subject: dict[str, str]
    token_locations: dict[str, tuple[Location, ...]]


class ModelReviewEvidenceError(ValueError):
    """Raised when model-authored review evidence cannot be safely credited."""


def seal_model_surface_review_artifact(
    context: ContextPackage,
    completion: StructuredCompletion[CandidateReviewBatch],
    *,
    rendered_user_context: str,
) -> ModelSurfaceReviewArtifact | None:
    """Validate and hash-link one completed response to its exact requested surfaces."""

    # Imported lazily because context construction imports the surface inventory.
    from mmaudit.orchestration.context import (
        ContextBudgetError,
        revalidate_context_package,
    )

    try:
        context = revalidate_context_package(context)
    except ContextBudgetError as exc:
        raise ModelReviewEvidenceError(
            "model surface evidence context failed exact boundary validation"
        ) from exc
    if context.role not in _BASE_REVIEW_ROLES | _SPECIALIST_REVIEW_ROLES:
        raise ModelReviewEvidenceError(
            "model surface evidence was produced by a non-investigator role"
        )
    if not isinstance(completion.value, CandidateReviewBatch):
        raise ModelReviewEvidenceError(
            "model surface evidence did not use the candidate review schema"
        )

    usage = completion.usage_record
    if usage.role != context.role:
        raise ModelReviewEvidenceError(
            "model surface evidence usage role differs from the request context"
        )
    if not is_creditable_usage_record(usage):
        raise ModelReviewEvidenceError(
            "model surface evidence requires a completed creditable structured request"
        )
    if usage.schema_sha256 != _canonical_sha256(strict_json_schema(CandidateReviewBatch)):
        raise ModelReviewEvidenceError(
            "model surface evidence response schema hash is inconsistent"
        )
    if usage.validated_response_sha256 != _canonical_sha256(
        completion.value.model_dump(mode="json")
    ):
        raise ModelReviewEvidenceError(
            "model surface evidence validated response hash is inconsistent"
        )
    rendered_context_sha256 = hashlib.sha256(rendered_user_context.encode()).hexdigest()
    if rendered_context_sha256 != model_review_context_sha256(context):
        raise ModelReviewEvidenceError(
            "model surface evidence context differs from the rendered provider request"
        )
    if usage.user_prompt_sha256 != rendered_context_sha256:
        raise ModelReviewEvidenceError(
            "model surface evidence context hash differs from provider request evidence"
        )

    requests = tuple(context.requested_model_surfaces)
    requested_ids = tuple(request.surface_id for request in requests)
    if requested_ids != tuple(sorted(set(requested_ids))):
        raise ModelReviewEvidenceError("requested model surface IDs must be unique and sorted")

    records = tuple(completion.value.surface_reviews)
    record_ids = tuple(record.surface_id for record in records)
    if record_ids != tuple(sorted(set(record_ids))):
        raise ModelReviewEvidenceError("model surface review records must be unique and sorted")
    if record_ids != requested_ids:
        raise ModelReviewEvidenceError(
            "model surface review records do not exactly cover the requested surfaces"
        )
    if not requests:
        return None

    request_by_id = {request.surface_id: request for request in requests}
    for record in records:
        request = request_by_id[record.surface_id]
        validate_model_surface_review_record(
            request,
            record,
            expected_role=context.role,
            index=context.solidity_index,
            graphs=context.solidity_graphs,
        )
        excerpt_failures = model_surface_review_excerpt_validation_failures(
            context=context,
            request=request,
            record=record,
        )
        if excerpt_failures:
            raise ModelReviewEvidenceError(excerpt_failures[0])

    if (
        usage.response_sha256 is None
        or usage.validated_response_sha256 is None
        or usage.schema_sha256 is None
    ):
        raise ModelReviewEvidenceError("model surface evidence request hashes are incomplete")
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "request_id": usage.request_id,
        "review_role": context.role,
        "requested_surface_ids": list(requested_ids),
        "requested_surface_ids_sha256": _canonical_sha256(list(requested_ids)),
        "requested_surface_manifest_sha256": (
            ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(requests)
        ),
        "rendered_context_sha256": rendered_context_sha256,
        "prompt_sha256": usage.prompt_sha256,
        "response_sha256": usage.response_sha256,
        "validated_response_sha256": usage.validated_response_sha256,
        "response_schema_sha256": usage.schema_sha256,
        "records": [record.model_dump(mode="json") for record in records],
    }
    payload["artifact_sha256"] = ModelSurfaceReviewArtifact.calculate_artifact_sha256(payload)
    try:
        artifact = ModelSurfaceReviewArtifact.model_validate(payload)
        artifact.require_exact_requested_surface_manifest(requests)
    except ValueError as exc:
        raise ModelReviewEvidenceError("model surface evidence artifact binding failed") from exc
    return artifact


def model_review_context_sha256(context: ContextPackage) -> str:
    """Hash the exact deterministic user-context rendering without retaining its content."""

    # Imported lazily because context construction imports the surface inventory.
    from mmaudit.orchestration.context import (
        render_context,
        revalidate_context_package,
    )

    sealed = revalidate_context_package(context)
    return hashlib.sha256(render_context(sealed).encode()).hexdigest()


def validate_model_surface_review_record(
    request: ModelSurfaceReviewRequest,
    record: ModelSurfaceReviewRecord,
    expected_role: str,
    *,
    index: SoliditySymbolIndex | None = None,
    graphs: SolidityGraphSet | None = None,
) -> None:
    """Revalidate one sealed record against a deterministic inventory descriptor."""

    failures = model_surface_review_record_validation_failures(
        request=request,
        record=record,
        expected_role=expected_role,
        index=index,
        graphs=graphs,
    )
    if failures:
        raise ModelReviewEvidenceError(failures[0])


def model_surface_review_record_validation_failures(
    request: ModelSurfaceReviewRequest,
    record: ModelSurfaceReviewRecord,
    expected_role: str,
    *,
    index: SoliditySymbolIndex | None,
    graphs: SolidityGraphSet | None,
) -> tuple[str, ...]:
    """Return deterministic no-credit reasons for one provider-authored record."""

    failures: list[str] = []
    if expected_role not in _BASE_REVIEW_ROLES | _SPECIALIST_REVIEW_ROLES:
        failures.append("model surface evidence was produced by a non-investigator role")
        return tuple(failures)
    try:
        _validate_record_metadata(
            request=request,
            record=record,
            expected_role=expected_role,
        )
    except ModelReviewEvidenceError as exc:
        failures.append(str(exc))
    citation = record.citation
    if citation.location is not None:
        try:
            _validate_location_descriptor(request=request, location=citation.location)
        except ModelReviewEvidenceError as exc:
            failures.append(str(exc))
    if citation.symbol is not None and citation.symbol not in request.allowed_symbols:
        failures.append(f"model surface {request.surface_id} cited an unrequested symbol")

    if record.status not in {
        ModelSurfaceReviewStatus.CANDIDATE,
        ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
    }:
        return tuple(dict.fromkeys(failures))
    if index is None:
        failures.append(
            f"model surface {request.surface_id} lacks a deterministic Solidity symbol index"
        )
        return tuple(dict.fromkeys(failures))

    deterministic_graph = _build_deterministic_review_graph(index=index, graphs=graphs)
    failures.extend(
        _substantive_observation_failures(
            request=request,
            record=record,
            graph=deterministic_graph,
        )
    )
    failures.extend(
        _reachability_failures(
            request=request,
            record=record,
            graph=deterministic_graph,
        )
    )
    return tuple(dict.fromkeys(failures))


def _validate_record_metadata(
    *,
    request: ModelSurfaceReviewRequest,
    record: ModelSurfaceReviewRecord,
    expected_role: str,
) -> None:
    if record.surface_id != request.surface_id:
        raise ModelReviewEvidenceError("model surface record ID is inconsistent")
    if record.review_role != expected_role:
        raise ModelReviewEvidenceError(
            f"model surface {request.surface_id} review role is inconsistent"
        )
    if record.contract != request.contract:
        raise ModelReviewEvidenceError(
            f"model surface {request.surface_id} contract is inconsistent"
        )
    if record.function_or_state_surface != request.function_or_state_surface:
        raise ModelReviewEvidenceError(
            f"model surface {request.surface_id} function or state metadata is inconsistent"
        )
    if record.invariant_considered != request.invariant_considered:
        raise ModelReviewEvidenceError(
            f"model surface {request.surface_id} invariant metadata is inconsistent"
        )


def _validate_location_descriptor(
    *,
    request: ModelSurfaceReviewRequest,
    location: Location,
) -> None:
    if location.content_hash is None or _SHA256.fullmatch(location.content_hash) is None:
        raise ModelReviewEvidenceError(
            f"model surface {request.surface_id} location lacks an exact source hash"
        )
    if location not in request.allowed_locations:
        raise ModelReviewEvidenceError(
            f"model surface {request.surface_id} cited an unrequested source location"
        )


def _validate_location_source(
    *,
    context: ContextPackage,
    request: ModelSurfaceReviewRequest,
    location: Location,
) -> None:
    if not any(_excerpt_proves_location(excerpt, location) for excerpt in context.excerpts):
        raise ModelReviewEvidenceError(
            f"model surface {request.surface_id} source location hash was not proven by context"
        )


def model_surface_review_excerpt_validation_failures(
    *,
    context: ContextPackage,
    request: ModelSurfaceReviewRequest,
    record: ModelSurfaceReviewRecord,
) -> tuple[str, ...]:
    """Require every creditable citation to resolve to source bytes supplied to the model."""

    if record.status not in {
        ModelSurfaceReviewStatus.CANDIDATE,
        ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
    }:
        return ()
    if context.solidity_index is None:
        return (f"model surface {request.surface_id} lacks a deterministic Solidity symbol index",)
    if not context.excerpts:
        return (f"model surface {request.surface_id} source evidence was omitted from context",)

    graph = _build_deterministic_review_graph(
        index=context.solidity_index,
        graphs=context.solidity_graphs,
    )
    citations: list[tuple[str, ModelSurfaceReviewCitation]] = [
        ("review citation", record.citation),
        *(
            (f"observation {position} citation", observation.citation)
            for position, observation in enumerate(record.evidence_observations)
        ),
    ]
    if record.reachability is not None:
        citations.append(("reachability entry point", record.reachability.entry_point))
        citations.extend(
            (f"reachability path node {position}", citation)
            for position, citation in enumerate(record.reachability.path)
        )

    failures: list[str] = []
    for label, citation in citations:
        locations = _resolved_citation_locations(citation, graph=graph)
        if len(locations) != 1:
            failures.append(
                f"model surface {request.surface_id} {label} did not resolve to "
                "one exact deterministic source range"
            )
            continue
        if not any(_excerpt_proves_location(excerpt, locations[0]) for excerpt in context.excerpts):
            failures.append(
                f"model surface {request.surface_id} {label} source range hash "
                "was not proven by supplied context bytes"
            )
    return tuple(dict.fromkeys(failures))


def _excerpt_proves_location(excerpt: ContextExcerpt, location: Location) -> bool:
    if (
        excerpt.path != location.path
        or excerpt.start_line > location.start_line
        or location.end_line > excerpt.end_line
        or hashlib.sha256(excerpt.content.encode()).hexdigest() != excerpt.content_hash
    ):
        return False
    relative_start = location.start_line - excerpt.start_line
    relative_end = location.end_line - excerpt.start_line + 1
    lines = excerpt.content.splitlines(keepends=True)
    if relative_end > len(lines):
        return False
    observed_hash = hashlib.sha256("".join(lines[relative_start:relative_end]).encode()).hexdigest()
    return observed_hash == location.content_hash


def _build_deterministic_review_graph(
    *,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet | None,
) -> _DeterministicReviewGraph:
    location_tokens: dict[tuple[str, int, int, str, str], set[str]] = {}
    token_locations: dict[str, dict[tuple[str, int, int, str], Location]] = {}
    symbol_tokens: dict[str, set[str]] = {}
    identity_symbol_tokens: dict[str, set[str]] = {}
    entities_by_id = {entity.id: entity for entity in index.entities}

    def register_location(location: Location, token: str) -> None:
        location_tokens.setdefault(_location_key(location), set()).add(token)
        token_locations.setdefault(token, {})[_source_location_key(location)] = location

    def register_symbol(
        symbol: str | None,
        token: str,
        *,
        identity: bool = False,
    ) -> None:
        if symbol:
            normalized = _normalized_symbol(symbol)
            symbol_tokens.setdefault(normalized, set()).add(token)
            if identity:
                identity_symbol_tokens.setdefault(normalized, set()).add(token)

    for entity in index.entities:
        token = _identity_token(entity.id)
        register_location(_entity_location(entity), token)
        register_symbol(entity.id, token, identity=True)
        register_symbol(entity.name, token, identity=True)
        register_symbol(entity.signature, token, identity=True)

    edges = tuple(graphs.edges) if graphs is not None else ()
    nodes = tuple(graphs.nodes) if graphs is not None else ()
    for node in nodes:
        token = _identity_token(node.id)
        register_location(_node_location(node), token)
        register_symbol(node.id, token, identity=True)
        register_symbol(node.label, token)

    adjacency: set[tuple[str, str]] = set()
    edge_tokens_by_subject: dict[str, str] = {}
    for edge in edges:
        source_token = _identity_token(edge.source_id)
        target_token = _identity_token(edge.target_id)
        edge_token = _edge_token(edge)
        register_location(_edge_location(edge), edge_token)
        source = entities_by_id.get(edge.source_id)
        for symbol in (
            edge.source_id,
            edge.target_id,
            edge.label,
            source.name if source is not None else None,
            source.signature if source is not None else None,
        ):
            register_symbol(symbol, edge_token)
        adjacency.update(
            {
                (source_token, target_token),
                (source_token, edge_token),
                (edge_token, target_token),
            }
        )
        edge_tokens_by_subject[_edge_subject_id(edge)] = edge_token

    contract_tokens = {
        entity.name: _identity_token(entity.id)
        for entity in index.entities
        if entity.kind
        in {
            SolidityEntityKind.CONTRACT,
            SolidityEntityKind.INTERFACE,
            SolidityEntityKind.LIBRARY,
        }
    }
    for entity in index.entities:
        if entity.kind not in _FUNCTION_KINDS or not entity.contract_name:
            continue
        contract_token = contract_tokens.get(entity.contract_name)
        if contract_token is not None:
            adjacency.add((_identity_token(entity.id), contract_token))

    entry_tokens = frozenset(
        _identity_token(entity.id)
        for entity in index.entities
        if entity.kind in _FUNCTION_KINDS
        and (
            entity.kind is SolidityEntityKind.CONSTRUCTOR
            or entity.visibility in {"public", "external"}
        )
    )
    return _DeterministicReviewGraph(
        citation_tokens={key: frozenset(tokens) for key, tokens in location_tokens.items()},
        symbol_tokens={key: frozenset(tokens) for key, tokens in symbol_tokens.items()},
        identity_symbol_tokens={
            key: frozenset(tokens) for key, tokens in identity_symbol_tokens.items()
        },
        entry_tokens=entry_tokens,
        adjacency=frozenset(adjacency),
        entities_by_id=entities_by_id,
        edge_tokens_by_subject=edge_tokens_by_subject,
        token_locations={
            token: tuple(locations[key] for key in sorted(locations))
            for token, locations in token_locations.items()
        },
    )


def _substantive_observation_failures(
    *,
    request: ModelSurfaceReviewRequest,
    record: ModelSurfaceReviewRecord,
    graph: _DeterministicReviewGraph,
) -> list[str]:
    failures: list[str] = []
    request_anchor_tokens = _request_anchor_tokens(request)
    invariant_tokens = _meaningful_tokens(request.invariant_considered)
    request_texts = {
        _normalized_text(request.contract),
        _normalized_text(request.function_or_state_surface),
        _normalized_text(request.invariant_considered),
    }
    for index, observation in enumerate(record.evidence_observations):
        citation_tokens = _resolve_citation(observation.citation, graph=graph)
        if not citation_tokens and not _citation_matches_request(
            observation.citation,
            request=request,
        ):
            failures.append(
                f"model surface {request.surface_id} observation {index} "
                "did not cite deterministic source or surface evidence"
            )
        observed = _normalized_text(observation.observed_behavior)
        relevance = _normalized_text(observation.security_relevance)
        if (
            observed in request_texts
            or relevance in request_texts
            or _is_near_copy(
                observation.observed_behavior,
                request.invariant_considered,
            )
            or _is_near_copy(
                observation.security_relevance,
                request.invariant_considered,
            )
        ):
            failures.append(
                f"model surface {request.surface_id} observation {index} copied request text"
            )
        if observed == relevance:
            failures.append(
                f"model surface {request.surface_id} observation {index} "
                "repeated one generic statement"
            )
        combined = f"{observed} {relevance}"
        if any(phrase in combined for phrase in _GENERIC_OBSERVATION_PHRASES):
            failures.append(
                f"model surface {request.surface_id} observation {index} used generic boilerplate"
            )
        observed_tokens = _meaningful_tokens(observation.observed_behavior)
        relevance_tokens = _meaningful_tokens(observation.security_relevance)
        if not observed_tokens & request_anchor_tokens:
            failures.append(
                f"model surface {request.surface_id} observation {index} "
                "did not name a surface-specific source anchor"
            )
        if not _contains_term_family(observed_tokens, _BEHAVIOR_TERMS):
            failures.append(
                f"model surface {request.surface_id} observation {index} "
                "did not state a concrete source behavior"
            )
        if not relevance_tokens & invariant_tokens:
            failures.append(
                f"model surface {request.surface_id} observation {index} "
                "did not connect to the requested invariant"
            )
        if not relevance_tokens & request_anchor_tokens:
            failures.append(
                f"model surface {request.surface_id} observation {index} "
                "did not connect the security consequence to the reviewed surface"
            )
        if not _contains_term_family(relevance_tokens, _SECURITY_TERMS):
            failures.append(
                f"model surface {request.surface_id} observation {index} "
                "did not state a concrete security consequence"
            )
    return failures


def _reachability_failures(
    *,
    request: ModelSurfaceReviewRequest,
    record: ModelSurfaceReviewRecord,
    graph: _DeterministicReviewGraph,
) -> list[str]:
    reachability = record.reachability
    if reachability is None:
        return [f"model surface {request.surface_id} omitted reachability evidence"]
    entry_candidates = _resolve_citation(reachability.entry_point, graph=graph)
    entry_tokens = entry_candidates & graph.entry_tokens
    if len(entry_tokens) != 1:
        return [
            f"model surface {request.surface_id} reachability entry point "
            "was not one exact known public, external, or constructor entry point"
        ]

    resolved_path: list[frozenset[str]] = []
    for position, citation in enumerate(reachability.path):
        tokens = _resolve_citation(citation, graph=graph)
        if position == len(reachability.path) - 1 and _citation_matches_request(
            citation,
            request=request,
        ):
            terminal_token = _surface_terminal_token(request, graph=graph)
            if terminal_token is not None:
                tokens = tokens | frozenset({terminal_token})
        if not tokens:
            return [
                f"model surface {request.surface_id} reachability path node {position} "
                "lacked deterministic source or graph identity"
            ]
        resolved_path.append(tokens)

    if not resolved_path or not (resolved_path[0] & entry_tokens):
        return [
            f"model surface {request.surface_id} reachability path did not begin "
            "at its exact known entry point"
        ]
    terminal_tokens = _expected_surface_tokens(
        request,
        record=record,
        graph=graph,
    )
    if not terminal_tokens or not (resolved_path[-1] & terminal_tokens):
        return [
            f"model surface {request.surface_id} reachability path did not terminate "
            "at the exact deterministic surface"
        ]

    if len(resolved_path) == 1:
        if request.kind not in _DIRECT_ENTRY_SURFACES or not (
            resolved_path[0] & terminal_tokens & graph.entry_tokens
        ):
            return [
                f"model surface {request.surface_id} used an unsupported self-to-self "
                "reachability path"
            ]
        return []

    frontier = resolved_path[0] & entry_tokens
    for position, tokens in enumerate(resolved_path[1:], start=1):
        advancing_tokens = tokens - frontier
        if not advancing_tokens:
            return [
                f"model surface {request.surface_id} reachability path node {position} "
                "repeated the preceding deterministic surface"
            ]
        next_frontier = frozenset(
            target
            for source in frontier
            for target in advancing_tokens
            if (source, target) in graph.adjacency
        )
        if not next_frontier:
            return [
                f"model surface {request.surface_id} reachability path node {position} "
                "was not adjacent in the deterministic graph"
            ]
        frontier = next_frontier
    return []


def _resolve_citation(
    citation: ModelSurfaceReviewCitation,
    *,
    graph: _DeterministicReviewGraph,
) -> frozenset[str]:
    location_tokens: frozenset[str] | None = None
    if citation.location is not None:
        location_tokens = graph.citation_tokens.get(_location_key(citation.location), frozenset())
    symbol_tokens: frozenset[str] | None = None
    if citation.symbol is not None:
        normalized = _normalized_symbol(citation.symbol)
        identity_tokens = graph.identity_symbol_tokens.get(normalized, frozenset())
        symbol_tokens = (
            identity_tokens
            if len(identity_tokens) == 1
            else graph.symbol_tokens.get(normalized, frozenset())
        )
    if location_tokens is not None and symbol_tokens is not None:
        return location_tokens & symbol_tokens
    if location_tokens is not None:
        return location_tokens
    return symbol_tokens or frozenset()


def _resolved_citation_locations(
    citation: ModelSurfaceReviewCitation,
    *,
    graph: _DeterministicReviewGraph,
) -> tuple[Location, ...]:
    locations: dict[tuple[str, int, int, str], Location] = {}
    for token in _resolve_citation(citation, graph=graph):
        for location in graph.token_locations.get(token, ()):
            if citation.location is not None and _source_location_key(
                citation.location
            ) != _source_location_key(location):
                continue
            locations[_source_location_key(location)] = location
    return tuple(locations[key] for key in sorted(locations))


def _expected_surface_tokens(
    request: ModelSurfaceReviewRequest,
    *,
    record: ModelSurfaceReviewRecord,
    graph: _DeterministicReviewGraph,
) -> frozenset[str]:
    entity = graph.entities_by_id.get(request.subject_id)
    if entity is not None:
        return frozenset({_identity_token(entity.id)})
    edge_token = graph.edge_tokens_by_subject.get(request.subject_id)
    if edge_token is not None:
        return frozenset({edge_token})
    if (
        request.kind is ModelReviewSurfaceKind.INVARIANT and request.subject_id.startswith("inv:")
    ) or (
        request.kind is ModelReviewSurfaceKind.TEMPLATE
        and request.subject_id.startswith(
            (
                "invariant-template:",
                "economic-template:",
            )
        )
    ):
        return _resolve_citation(record.citation, graph=graph)
    return frozenset()


def _surface_terminal_token(
    request: ModelSurfaceReviewRequest,
    *,
    graph: _DeterministicReviewGraph,
) -> str | None:
    entity = graph.entities_by_id.get(request.subject_id)
    if entity is not None:
        return _identity_token(entity.id)
    return graph.edge_tokens_by_subject.get(request.subject_id)


def _citation_matches_request(
    citation: ModelSurfaceReviewCitation,
    *,
    request: ModelSurfaceReviewRequest,
) -> bool:
    if citation.location is not None and citation.location not in request.allowed_locations:
        return False
    if citation.symbol is not None and citation.symbol not in request.allowed_symbols:
        return False
    return citation.location is not None or citation.symbol is not None


def _request_anchor_tokens(request: ModelSurfaceReviewRequest) -> frozenset[str]:
    tokens: set[str] = set()
    for value in (
        request.contract,
        request.function_or_state_surface,
        request.subject_id,
        *request.allowed_symbols,
    ):
        tokens.update(_meaningful_tokens(value))
    return frozenset(tokens - _ANCHOR_STOPWORDS)


def _meaningful_tokens(value: str) -> frozenset[str]:
    expanded = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", value)
    return frozenset(token.casefold() for token in _WORD.findall(expanded) if len(token) >= 3)


def _contains_term_family(tokens: frozenset[str], terms: frozenset[str]) -> bool:
    return any(
        token.startswith(term) or term.startswith(token) for token in tokens for term in terms
    )


def _normalized_text(value: str) -> str:
    return " ".join(_WORD.findall(value.casefold()))


def _is_near_copy(candidate: str, source: str) -> bool:
    candidate_tokens = _meaningful_tokens(candidate)
    source_tokens = _meaningful_tokens(source)
    if len(source_tokens) < 4:
        return False
    return (
        len(candidate_tokens & source_tokens) / len(source_tokens) >= 0.85
        and len(candidate_tokens - source_tokens) <= 3
    )


def _normalized_symbol(value: str) -> str:
    return " ".join(value.strip().casefold().split())


def _identity_token(identifier: str) -> str:
    return f"id:{identifier}"


def _edge_subject_id(edge: SolidityGraphEdge) -> str:
    return f"graph-edge:{_edge_digest(edge)}"


def _edge_token(edge: SolidityGraphEdge) -> str:
    return f"edge:{_edge_digest(edge)}"


def _edge_digest(edge: SolidityGraphEdge) -> str:
    payload = {
        "graph": edge.graph.value,
        "source_id": edge.source_id,
        "target_id": edge.target_id,
        "label": edge.label,
        "path": edge.path,
        "start_line": edge.start_line,
        "end_line": edge.end_line,
        "source_hash": edge.source_hash,
        "metadata": edge.metadata,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _entity_location(entity: SolidityEntity) -> Location:
    return Location(
        path=entity.path,
        start_line=entity.start_line,
        end_line=entity.end_line,
        symbol=entity.signature or entity.name,
        content_hash=entity.source_hash,
    )


def _node_location(node: SolidityGraphNode) -> Location:
    return Location(
        path=node.path,
        start_line=node.start_line,
        end_line=node.end_line,
        content_hash=node.source_hash,
    )


def _edge_location(edge: SolidityGraphEdge) -> Location:
    return Location(
        path=edge.path,
        start_line=edge.start_line,
        end_line=edge.end_line,
        content_hash=edge.source_hash,
    )


def _location_key(location: Location) -> tuple[str, int, int, str, str]:
    return (
        location.path,
        location.start_line,
        location.end_line,
        location.symbol or "",
        location.content_hash or "",
    )


def _source_location_key(location: Location) -> tuple[str, int, int, str]:
    return (
        location.path,
        location.start_line,
        location.end_line,
        location.content_hash or "",
    )


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()


__all__ = [
    "ModelReviewEvidenceError",
    "model_review_context_sha256",
    "model_surface_review_excerpt_validation_failures",
    "model_surface_review_record_validation_failures",
    "seal_model_surface_review_artifact",
    "validate_model_surface_review_record",
]
