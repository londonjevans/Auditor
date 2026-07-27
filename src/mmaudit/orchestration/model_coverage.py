"""Deterministic per-surface accounting for successful model review contexts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from mmaudit.config import AuditConfig, model_lineage_index
from mmaudit.models.schemas import (
    AnalysisState,
    ContextPackage,
    CoverageMetric,
    CoverageProvenance,
    EconomicSimulationPlan,
    InvariantSuite,
    Location,
    ModelReviewCoverage,
    ModelReviewSurface,
    ModelReviewSurfaceKind,
    QualityGateResult,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphKind,
    SolidityGraphSet,
    SoliditySymbolIndex,
    UsageRecord,
)

_CALL_GRAPHS = frozenset(
    {
        SolidityGraphKind.INTERNAL_CALL,
        SolidityGraphKind.EXTERNAL_CALL,
        SolidityGraphKind.LOW_LEVEL_CALL,
        SolidityGraphKind.DELEGATECALL,
        SolidityGraphKind.CONTRACT_CREATION,
    }
)
_CRITICAL_CALL_GRAPHS = frozenset(
    {
        SolidityGraphKind.EXTERNAL_CALL,
        SolidityGraphKind.LOW_LEVEL_CALL,
        SolidityGraphKind.DELEGATECALL,
    }
)
_STATE_KINDS = frozenset(
    {
        SolidityEntityKind.STATE_VARIABLE,
        SolidityEntityKind.IMMUTABLE,
        SolidityEntityKind.CONSTANT,
    }
)
_CONTRACT_KINDS = frozenset(
    {
        SolidityEntityKind.CONTRACT,
        SolidityEntityKind.INTERFACE,
        SolidityEntityKind.LIBRARY,
    }
)
_FUNCTION_KINDS = frozenset(
    {
        SolidityEntityKind.FUNCTION,
        SolidityEntityKind.CONSTRUCTOR,
    }
)


@dataclass(frozen=True)
class _SurfaceSeed:
    kind: ModelReviewSurfaceKind
    subject_id: str
    label: str
    critical: bool
    locations: tuple[Location, ...]
    required_tokens: frozenset[str]


@dataclass(frozen=True)
class _ReviewContext:
    role: str
    root_lineage: str | None
    tokens: frozenset[str]


def build_model_review_coverage(
    config: AuditConfig,
    *,
    usage_records: list[UsageRecord],
    contexts: list[ContextPackage],
    index: SoliditySymbolIndex | None,
    graphs: SolidityGraphSet | None,
    invariants: InvariantSuite | None,
    economic_simulations: list[EconomicSimulationPlan],
    minimum_critical_root_lineages: int = 2,
) -> ModelReviewCoverage:
    """Measure exact deterministic surfaces present in successful model requests."""

    limitations: set[str] = set()
    if index is None:
        limitations.add(
            "Solidity symbol index was unavailable; model surface coverage was not analyzed"
        )
    review_contexts = _successful_review_contexts(
        config,
        usage_records=usage_records,
        contexts=contexts,
        limitations=limitations,
    )
    seeds = (
        _surface_inventory(
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=economic_simulations,
        )
        if index is not None
        else []
    )
    surfaces = sorted(
        (_materialize_surface(seed, review_contexts) for seed in seeds),
        key=lambda surface: surface.surface_id,
    )
    applicable = index is not None
    overall = _coverage_metric(
        numerator=sum(surface.reviewed for surface in surfaces),
        surfaces=surfaces,
        applicable=applicable,
        detail="deterministic surfaces present in at least one successful registered-model context",
    )
    by_kind = {
        kind: _coverage_metric(
            numerator=sum(surface.reviewed for surface in surfaces if surface.kind is kind),
            surfaces=[surface for surface in surfaces if surface.kind is kind],
            applicable=applicable,
            detail=f"{kind.value} surfaces present in successful registered-model contexts",
        )
        for kind in ModelReviewSurfaceKind
    }
    critical_surfaces = [surface for surface in surfaces if surface.critical]
    critical_numerator = sum(
        surface.reviewed and len(surface.root_lineages) >= minimum_critical_root_lineages
        for surface in critical_surfaces
    )
    critical = _coverage_metric(
        numerator=critical_numerator,
        surfaces=critical_surfaces,
        applicable=applicable,
        detail=(
            "critical surfaces reviewed by at least "
            f"{minimum_critical_root_lineages} independent immutable root lineages"
        ),
        minimum_root_lineages=minimum_critical_root_lineages,
    )
    return ModelReviewCoverage(
        applicable=applicable,
        minimum_critical_root_lineages=minimum_critical_root_lineages,
        surfaces=surfaces,
        overall=overall,
        by_kind=by_kind,
        critical=critical,
        critical_gate_passed=critical.numerator == critical.denominator,
        limitations=sorted(limitations),
    )


def model_review_critical_surface_gate(
    coverage: ModelReviewCoverage | None,
    *,
    required: bool,
) -> QualityGateResult:
    """Evaluate the independent critical-surface denominator."""

    if coverage is None:
        return QualityGateResult(
            gate="critical_model_surface_review",
            required=required,
            passed=False,
            detail="per-surface model review coverage was not produced",
            state=AnalysisState.NOT_ANALYZED,
            artifacts=[],
        )
    metric = coverage.critical
    if not coverage.applicable:
        return QualityGateResult(
            gate="critical_model_surface_review",
            required=required,
            passed=False,
            detail=coverage.limitations[0]
            if coverage.limitations
            else "coverage was not applicable",
            state=AnalysisState.NOT_ANALYZED,
            artifacts=["model-review-coverage.json"],
        )
    return QualityGateResult(
        gate="critical_model_surface_review",
        required=required,
        passed=coverage.critical_gate_passed,
        detail=(
            f"{metric.numerator}/{metric.denominator} critical surface(s) reviewed by at least "
            f"{coverage.minimum_critical_root_lineages} independent root lineages"
        ),
        state=metric.state,
        artifacts=["model-review-coverage.json"],
    )


def _successful_review_contexts(
    config: AuditConfig,
    *,
    usage_records: list[UsageRecord],
    contexts: list[ContextPackage],
    limitations: set[str],
) -> list[_ReviewContext]:
    lineage_by_model = model_lineage_index(config)
    results: list[_ReviewContext] = []
    successful = [record for record in usage_records if record.status == "success"]
    for package in contexts:
        tokens = _context_tokens(package)
        for record in successful:
            if not _usage_matches_context(record.role, package.role):
                continue
            returned_model = (record.returned_model or record.requested_model).lower()
            lineage = lineage_by_model.get(returned_model)
            if lineage is None:
                limitations.add(
                    f"successful usage role {record.role} returned an unregistered model; "
                    "its review was not credited to an immutable root lineage"
                )
            results.append(
                _ReviewContext(
                    role=record.role,
                    root_lineage=lineage.root_lineage if lineage is not None else None,
                    tokens=tokens,
                )
            )
    return results


def _usage_matches_context(usage_role: str, context_role: str) -> bool:
    return (
        usage_role == context_role
        or usage_role.startswith(f"{context_role}:")
        or (context_role == "specialist:falsifier" and usage_role == "falsifier")
    )


def _context_tokens(package: ContextPackage) -> frozenset[str]:
    tokens: set[str] = set()
    if package.solidity_index is not None:
        for entity in package.solidity_index.entities:
            tokens.add(_entity_token(entity.id))
            if entity.kind in _CONTRACT_KINDS:
                tokens.add(_contract_token(entity.path, entity.name))
            if entity.contract_name:
                tokens.add(_contract_token(entity.path, entity.contract_name))
    if package.solidity_graphs is not None:
        for edge in package.solidity_graphs.edges:
            tokens.add(_edge_token(edge))
            tokens.add(_graph_source_token(edge.graph, edge.source_id))
    if package.solidity_invariants is not None:
        for invariant in package.solidity_invariants.invariants:
            tokens.add(_invariant_token(invariant.id))
            if invariant.template is not None:
                tokens.add(_template_token("invariant", invariant.template.value))
    for plan in package.economic_simulations:
        if plan.applicable:
            tokens.add(_template_token("economic", plan.kind.value))
    return frozenset(tokens)


def _surface_inventory(
    *,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet | None,
    invariants: InvariantSuite | None,
    economic_simulations: list[EconomicSimulationPlan],
) -> list[_SurfaceSeed]:
    entities_by_id = {entity.id: entity for entity in index.entities}
    edges = list(graphs.edges) if graphs is not None else []
    privilege_sources = _edge_sources(edges, SolidityGraphKind.PRIVILEGE)
    asset_sources = _edge_sources(edges, SolidityGraphKind.ASSET_FLOW)
    sensitive_sources = _edge_sources(edges, SolidityGraphKind.SENSITIVE_REACHABILITY)
    invariant_entity_ids = {
        entity_id
        for invariant in (invariants.invariants if invariants is not None else [])
        for entity_id in invariant.entity_ids
    }
    critical_function_ids = (
        privilege_sources | asset_sources | sensitive_sources | invariant_entity_ids
    )
    critical_state_ids = {
        edge.target_id
        for edge in edges
        if edge.graph
        in {
            SolidityGraphKind.STATE_READ,
            SolidityGraphKind.STATE_WRITE,
            SolidityGraphKind.STATE_DEPENDENCY,
        }
        and edge.source_id in critical_function_ids
    }
    if invariants is not None:
        invariant_state_names = {
            name for invariant in invariants.invariants for name in invariant.state_variables
        }
        critical_state_ids.update(
            entity.id
            for entity in index.entities
            if entity.kind in _STATE_KINDS and entity.name in invariant_state_names
        )
    critical_contracts = {
        (entity.path, entity.contract_name)
        for entity in index.entities
        if entity.id in critical_function_ids and entity.contract_name
    }
    seeds: list[_SurfaceSeed] = []
    for entity in index.entities:
        location = (_entity_location(entity),)
        if entity.kind in _CONTRACT_KINDS:
            seeds.append(
                _SurfaceSeed(
                    kind=ModelReviewSurfaceKind.CONTRACT,
                    subject_id=entity.id,
                    label=entity.name,
                    critical=(entity.path, entity.name) in critical_contracts,
                    locations=location,
                    required_tokens=frozenset({_contract_token(entity.path, entity.name)}),
                )
            )
        if entity.kind in _FUNCTION_KINDS and (
            entity.kind is SolidityEntityKind.CONSTRUCTOR
            or entity.visibility in {"public", "external"}
        ):
            seeds.append(
                _entity_surface(
                    ModelReviewSurfaceKind.ENTRY_POINT,
                    entity,
                    critical=entity.id in critical_function_ids,
                )
            )
        if entity.id in privilege_sources:
            seeds.append(
                _entity_surface(
                    ModelReviewSurfaceKind.PRIVILEGE_FUNCTION,
                    entity,
                    critical=True,
                    graph=SolidityGraphKind.PRIVILEGE,
                )
            )
        if entity.id in asset_sources:
            seeds.append(
                _entity_surface(
                    ModelReviewSurfaceKind.ASSET_FUNCTION,
                    entity,
                    critical=True,
                    graph=SolidityGraphKind.ASSET_FLOW,
                )
            )
        if entity.kind in _STATE_KINDS:
            seeds.append(
                _entity_surface(
                    ModelReviewSurfaceKind.STATE,
                    entity,
                    critical=entity.id in critical_state_ids,
                )
            )
    for edge in edges:
        if edge.graph not in _CALL_GRAPHS:
            continue
        source = entities_by_id.get(edge.source_id)
        source_label = source.signature or source.name if source is not None else edge.source_id
        seeds.append(
            _SurfaceSeed(
                kind=ModelReviewSurfaceKind.CALL,
                subject_id=_edge_subject_id(edge),
                label=f"{source_label} -> {edge.label}",
                critical=edge.graph in _CRITICAL_CALL_GRAPHS
                or edge.source_id in critical_function_ids,
                locations=(_edge_location(edge),),
                required_tokens=frozenset({_edge_token(edge)}),
            )
        )
    if invariants is not None:
        for invariant in invariants.invariants:
            seeds.append(
                _SurfaceSeed(
                    kind=ModelReviewSurfaceKind.INVARIANT,
                    subject_id=invariant.id,
                    label=invariant.title,
                    critical=True,
                    locations=tuple(_sorted_locations(invariant.locations)),
                    required_tokens=frozenset({_invariant_token(invariant.id)}),
                )
            )
        invariant_templates = sorted(
            {
                invariant.template.value
                for invariant in invariants.invariants
                if invariant.template is not None
            }
        )
        for template in invariant_templates:
            seeds.append(
                _SurfaceSeed(
                    kind=ModelReviewSurfaceKind.TEMPLATE,
                    subject_id=f"invariant-template:{template}",
                    label=f"Invariant template: {template}",
                    critical=True,
                    locations=(),
                    required_tokens=frozenset({_template_token("invariant", template)}),
                )
            )
    for template in sorted({plan.kind.value for plan in economic_simulations if plan.applicable}):
        template_plans = [
            plan for plan in economic_simulations if plan.applicable and plan.kind.value == template
        ]
        seeds.append(
            _SurfaceSeed(
                kind=ModelReviewSurfaceKind.TEMPLATE,
                subject_id=f"economic-template:{template}",
                label=f"Economic template: {template}",
                critical=True,
                locations=tuple(
                    _sorted_locations(
                        [location for plan in template_plans for location in plan.source_locations]
                    )
                ),
                required_tokens=frozenset({_template_token("economic", template)}),
            )
        )
    return seeds


def _entity_surface(
    kind: ModelReviewSurfaceKind,
    entity: SolidityEntity,
    *,
    critical: bool,
    graph: SolidityGraphKind | None = None,
) -> _SurfaceSeed:
    tokens = {_entity_token(entity.id)}
    if graph is not None:
        tokens.add(_graph_source_token(graph, entity.id))
    return _SurfaceSeed(
        kind=kind,
        subject_id=entity.id,
        label=entity.signature or entity.name,
        critical=critical,
        locations=(_entity_location(entity),),
        required_tokens=frozenset(tokens),
    )


def _materialize_surface(
    seed: _SurfaceSeed,
    review_contexts: list[_ReviewContext],
) -> ModelReviewSurface:
    matched = [context for context in review_contexts if seed.required_tokens <= context.tokens]
    roles = sorted({context.role for context in matched})
    root_lineages = sorted(
        {context.root_lineage for context in matched if context.root_lineage is not None}
    )
    return ModelReviewSurface(
        surface_id=_surface_id(seed.kind, seed.subject_id),
        kind=seed.kind,
        subject_id=seed.subject_id,
        label=seed.label,
        critical=seed.critical,
        locations=list(seed.locations),
        reviewer_roles=roles,
        root_lineages=root_lineages,
        reviewed=bool(roles and root_lineages),
    )


def _coverage_metric(
    *,
    numerator: int,
    surfaces: list[ModelReviewSurface],
    applicable: bool,
    detail: str,
    minimum_root_lineages: int | None = None,
) -> CoverageMetric:
    denominator = len(surfaces)
    if denominator:
        if minimum_root_lineages is None:
            uncovered = [surface for surface in surfaces if not surface.reviewed]
        else:
            uncovered = [
                surface
                for surface in surfaces
                if not surface.reviewed or len(surface.root_lineages) < minimum_root_lineages
            ]
        failures = [
            (f"{surface.surface_id} has {len(surface.root_lineages)} registered root lineage(s)")
            for surface in uncovered[:100]
        ]
        not_applicable_evidence: list[str] = []
    elif applicable:
        failures = []
        not_applicable_evidence = ["no deterministic surfaces of this category were discovered"]
    else:
        failures = ["Solidity symbol index was unavailable"]
        not_applicable_evidence = []
    return CoverageMetric(
        numerator=numerator,
        denominator=denominator,
        population=denominator,
        percentage=round((numerator / denominator) * 100, 4) if denominator else None,
        exclusions=[],
        not_applicable_evidence=not_applicable_evidence,
        confidence=1,
        provenance=[CoverageProvenance.MODEL_CONTEXT],
        failures=failures,
        state=AnalysisState.MODEL_ONLY if applicable else AnalysisState.NOT_ANALYZED,
        detail=detail,
    )


def _edge_sources(
    edges: list[SolidityGraphEdge],
    graph: SolidityGraphKind,
) -> set[str]:
    return {edge.source_id for edge in edges if edge.graph is graph}


def _surface_id(kind: ModelReviewSurfaceKind, subject_id: str) -> str:
    digest = hashlib.sha256(f"{kind.value}\0{subject_id}".encode()).hexdigest()
    return f"model-surface:{digest}"


def _entity_token(entity_id: str) -> str:
    return f"entity:{entity_id}"


def _contract_token(path: str, name: str) -> str:
    return f"contract:{path}:{name}"


def _graph_source_token(graph: SolidityGraphKind, source_id: str) -> str:
    return f"graph-source:{graph.value}:{source_id}"


def _invariant_token(invariant_id: str) -> str:
    return f"invariant:{invariant_id}"


def _template_token(template_type: str, template: str) -> str:
    return f"template:{template_type}:{template}"


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


def _edge_location(edge: SolidityGraphEdge) -> Location:
    return Location(
        path=edge.path,
        start_line=edge.start_line,
        end_line=edge.end_line,
        content_hash=edge.source_hash,
    )


def _sorted_locations(locations: list[Location]) -> list[Location]:
    unique = {
        (
            location.path,
            location.start_line,
            location.end_line,
            location.symbol,
            location.content_hash,
        ): location
        for location in locations
    }
    return [
        unique[key]
        for key in sorted(
            unique,
            key=lambda item: (
                item[0],
                item[1],
                item[2],
                item[3] or "",
                item[4] or "",
            ),
        )
    ]
