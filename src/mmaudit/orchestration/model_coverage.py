"""Deterministic per-surface accounting for explicit model review responses."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import PurePosixPath

from mmaudit.config import AuditConfig, ModelLineageConfig, model_lineage_index
from mmaudit.constants import SPECIALIST_INVESTIGATOR_ROLES
from mmaudit.models.schemas import (
    AnalysisState,
    AuditedSuiteCoverage,
    AuditProfile,
    ContextPackage,
    CoverageMetric,
    CoverageProvenance,
    EconomicSimulationPlan,
    ExecutionEvidenceKind,
    InvariantSpec,
    InvariantSuite,
    Location,
    ModelReviewCoverage,
    ModelReviewEvidenceReference,
    ModelReviewSurface,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewPriority,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
    QualityGateResult,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphKind,
    SolidityGraphSet,
    SolidityProvenance,
    SoliditySymbolIndex,
    UsageRecord,
)
from mmaudit.models.usage import is_creditable_usage_record
from mmaudit.orchestration.model_review_evidence import (
    model_review_context_sha256,
    model_surface_review_excerpt_validation_failures,
    model_surface_review_record_validation_failures,
)
from mmaudit.repository.chunking import line_range_hash
from mmaudit.solidity.coverage import (
    bind_economic_plan_to_audited_entities,
    bind_invariant_to_audited_entities,
    critical_graph_edge_is_exact,
    exact_test_entity_ids,
    partition_audited_source_entities,
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
    contract: str
    allowed_symbols: tuple[str, ...]
    invariant_considered: str


_BASE_REVIEW_ROLES = frozenset({"source_audit", "business_logic", "configuration"})
_SPECIALIST_REVIEW_ROLES = frozenset(f"specialist:{role}" for role in SPECIALIST_INVESTIGATOR_ROLES)
_COVERAGE_GAP_HUNTER_ROLE = "specialist:false_negative_hunter"
_CREDITABLE_REVIEW_STATUSES = frozenset(
    {
        ModelSurfaceReviewStatus.CANDIDATE,
        ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
    }
)
_FORENSIC_LIMITATION_LABELS = {
    "duplicate_artifact": "duplicate model-review artifacts were not credited",
    "invalid_context": "model-review requests used an invalid context package",
    "unknown_surfaces": "model-review artifacts referenced unknown surfaces",
    "unregistered_model": "model-review requests used an unregistered model",
    "unapproved_lineage": "model-review requests used an unapproved lineage",
}


def _record_forensic_limitation(
    inventory: dict[str, set[str]],
    *,
    category: str,
    identity: str,
) -> None:
    """Retain exact failure cardinality without overflowing the public summary schema."""

    if category not in _FORENSIC_LIMITATION_LABELS:
        raise ValueError("unknown forensic limitation category")
    inventory.setdefault(category, set()).add(identity)


def _forensic_limitation_summaries(inventory: dict[str, set[str]]) -> tuple[str, ...]:
    """Commit sorted failure identities in deterministic bounded public summaries."""

    summaries: list[str] = []
    for category, identities in sorted(inventory.items()):
        normalized = tuple(sorted(identities))
        identity_set_sha256 = hashlib.sha256(
            json.dumps(
                {"category": category, "identities": normalized},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        summaries.append(
            f"{_FORENSIC_LIMITATION_LABELS[category]}; "
            f"affected_identity_count={len(normalized)}; "
            f"affected_identity_set_sha256={identity_set_sha256}"
        )
    return tuple(summaries)


def build_model_review_coverage(
    config: AuditConfig,
    *,
    usage_records: list[UsageRecord],
    review_artifacts: list[ModelSurfaceReviewArtifact],
    review_contexts_by_request: dict[str, list[ContextPackage]],
    index: SoliditySymbolIndex | None,
    graphs: SolidityGraphSet | None,
    invariants: InvariantSuite | None,
    economic_simulations: list[EconomicSimulationPlan],
    minimum_critical_root_lineages: int = 3,
    audited_suite_coverage: AuditedSuiteCoverage | None = None,
    source_contents_by_path: dict[str, str] | None = None,
) -> ModelReviewCoverage:
    """Credit only explicit, validated per-surface response records."""

    source_contents_by_path = _copy_source_contents(source_contents_by_path)
    index, graphs, invariants, economic_simulations = _reconstruct_surface_inputs(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=economic_simulations,
    )
    audited_suite_coverage = _reconstruct_audited_suite_coverage(audited_suite_coverage)
    limitations: set[str] = set()
    if index is None:
        limitations.add(
            "Solidity symbol index was unavailable; model surface coverage was not analyzed"
        )
    audited_source_classification_complete = (
        audited_suite_coverage is None or audited_suite_coverage.source_classification_complete
    )
    audited_critical_classification_complete = audited_suite_coverage is not None and (
        audited_suite_coverage.critical_classification_complete
        and _critical_classification_inputs_complete(
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=economic_simulations,
            source_contents_by_path=source_contents_by_path,
        )
    )
    if audited_suite_coverage is None:
        limitations.add(
            "audited-suite coverage was unavailable; critical model-review classification "
            "was not analyzed"
        )
    elif not audited_source_classification_complete:
        limitations.update(audited_suite_coverage.limitations)
        limitations.add(
            "audited-suite source classification was incomplete; "
            "model surface coverage was not analyzed"
        )
    elif audited_suite_coverage is not None and not audited_critical_classification_complete:
        limitations.update(audited_suite_coverage.limitations)
        limitations.add(
            "audited-suite critical classification was incomplete; critical model-review "
            "completion was not analyzed and exact coverage gaps remain conservatively elevated"
        )
    source_partition = (
        partition_audited_source_entities(index=index, projects=index.projects)
        if index is not None
        else None
    )
    if source_partition is not None and not source_partition.classification_complete:
        limitations.update(source_partition.limitations)
    seeds = (
        _surface_inventory(
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=economic_simulations,
            source_contents_by_path=source_contents_by_path,
        )
        if (
            index is not None
            and source_partition is not None
            and source_partition.classification_complete
            and audited_source_classification_complete
        )
        else []
    )
    seeds = _with_audited_suite_criticality(seeds, audited_suite_coverage)
    requests = _requests_from_seeds(
        seeds,
        coverage_gap_ids_by_entity=(
            _validated_coverage_gap_ids_by_entity(
                index=index,
                graphs=graphs,
                invariants=invariants,
                economic_simulations=economic_simulations,
                seeds=seeds,
                audited_suite_coverage=audited_suite_coverage,
                source_contents_by_path=source_contents_by_path,
            )
            if audited_suite_coverage is not None
            else {}
        ),
    )
    references = _review_evidence_references(
        config,
        requests=requests,
        usage_records=usage_records,
        review_artifacts=review_artifacts,
        review_contexts_by_request=review_contexts_by_request,
        index=index,
        graphs=graphs,
        limitations=limitations,
    )
    surfaces = sorted(
        (
            _materialize_surface(
                seed,
                references=references.get(_surface_id(seed.kind, seed.subject_id), []),
            )
            for seed in seeds
        ),
        key=lambda surface: surface.surface_id,
    )
    applicable = (
        index is not None
        and source_partition is not None
        and source_partition.classification_complete
        and audited_source_classification_complete
    )
    inapplicable_reason = (
        "Solidity symbol index was unavailable"
        if index is None
        else next(
            iter(sorted(limitations)),
            "audited-source classification was incomplete",
        )
    )
    overall = _coverage_metric(
        numerator=sum(surface.reviewed for surface in surfaces),
        surfaces=surfaces,
        applicable=applicable,
        detail="deterministic surfaces with at least one validated substantive model response",
        inapplicable_reason=inapplicable_reason,
    )
    by_kind = {
        kind: _coverage_metric(
            numerator=sum(surface.reviewed for surface in surfaces if surface.kind is kind),
            surfaces=[surface for surface in surfaces if surface.kind is kind],
            applicable=applicable,
            detail=f"{kind.value} surfaces with validated substantive model responses",
            inapplicable_reason=inapplicable_reason,
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
        applicable=applicable and audited_critical_classification_complete,
        detail=(
            "critical surfaces reviewed by at least "
            f"{minimum_critical_root_lineages} independent immutable root lineages"
        ),
        minimum_root_lineages=minimum_critical_root_lineages,
        inapplicable_reason=inapplicable_reason,
    )
    return ModelReviewCoverage(
        applicable=applicable,
        critical_classification_complete=audited_critical_classification_complete,
        minimum_critical_root_lineages=minimum_critical_root_lineages,
        surfaces=surfaces,
        overall=overall,
        by_kind=by_kind,
        critical=critical,
        critical_gate_passed=(
            applicable
            and audited_critical_classification_complete
            and critical.denominator > 0
            and critical.numerator == critical.denominator
        ),
        limitations=sorted(limitations),
    )


def build_model_surface_requests(
    *,
    index: SoliditySymbolIndex | None,
    graphs: SolidityGraphSet | None,
    invariants: InvariantSuite | None,
    economic_simulations: list[EconomicSimulationPlan],
    audited_suite_coverage: AuditedSuiteCoverage | None = None,
    source_contents_by_path: dict[str, str] | None = None,
) -> list[ModelSurfaceReviewRequest]:
    """Build the stable, deterministic request descriptors used by model reviewers."""

    source_contents_by_path = _copy_source_contents(source_contents_by_path)
    index, graphs, invariants, economic_simulations = _reconstruct_surface_inputs(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=economic_simulations,
    )
    audited_suite_coverage = _reconstruct_audited_suite_coverage(audited_suite_coverage)
    if index is None:
        if audited_suite_coverage is not None and audited_suite_coverage.gaps:
            raise ValueError(
                "audited-suite coverage gaps require a Solidity symbol index for exact binding"
            )
        return []
    source_partition = partition_audited_source_entities(index=index, projects=index.projects)
    if not source_partition.classification_complete:
        return []
    if (
        audited_suite_coverage is not None
        and not audited_suite_coverage.source_classification_complete
    ):
        return []
    seeds = _surface_inventory(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=economic_simulations,
        source_contents_by_path=source_contents_by_path,
    )
    seeds = _with_audited_suite_criticality(seeds, audited_suite_coverage)
    return _requests_from_seeds(
        seeds,
        coverage_gap_ids_by_entity=(
            _validated_coverage_gap_ids_by_entity(
                index=index,
                graphs=graphs,
                invariants=invariants,
                economic_simulations=economic_simulations,
                seeds=seeds,
                audited_suite_coverage=audited_suite_coverage,
                source_contents_by_path=source_contents_by_path,
            )
            if audited_suite_coverage is not None
            else {}
        ),
    )


def build_semantic_shard_source_review_request(
    *,
    index: SoliditySymbolIndex,
    source_path: str,
    source_content: str,
    source_sha256: str,
) -> ModelSurfaceReviewRequest:
    """Build one exact semantic review surface omitted from audited-source coverage.

    Solidity tests and other non-audited Solidity inputs can still form semantic
    scheduler shards. They are intentionally absent from the product coverage
    denominator, but a blind source-audit request must still name a typed Solidity
    entity rather than receiving only a whole-file disposition. This helper derives
    that supplemental request solely from a validated compiler/fallback index and
    the exact current source bytes.
    """

    validated_index = SoliditySymbolIndex.model_validate(index.model_dump(mode="python"))
    path = PurePosixPath(source_path)
    if (
        not source_path
        or path.is_absolute()
        or path.as_posix() != source_path
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("semantic source review path must be normalized and relative")
    encoded = source_content.encode("utf-8")
    if hashlib.sha256(encoded).hexdigest() != source_sha256:
        raise ValueError("semantic source review bytes differ from the exact source hash")

    ast_backed = source_path in validated_index.ast_sources
    fallback_backed = source_path in validated_index.fallback_sources
    if ast_backed == fallback_backed:
        raise ValueError("semantic source review requires one exact index provenance")
    expected_provenance = SolidityProvenance.COMPILER if ast_backed else SolidityProvenance.FALLBACK
    entities = sorted(
        (entity for entity in validated_index.entities if entity.path == source_path),
        key=lambda entity: (entity.start_line, entity.end_line, entity.id),
    )
    if not entities:
        raise ValueError("semantic source review lacks a typed Solidity entity")

    source_lines = source_content.splitlines(keepends=True)
    for entity in entities:
        if (
            entity.provenance is not expected_provenance
            or entity.end_line > len(source_lines)
            or entity.byte_end > len(encoded)
            or line_range_hash(source_content, entity.start_line, entity.end_line)
            != entity.source_hash
        ):
            raise ValueError("semantic source review index differs from current source bytes")

    reviewable = [
        entity
        for entity in entities
        if entity.kind in _CONTRACT_KINDS | _FUNCTION_KINDS | _STATE_KINDS
    ]
    if not reviewable:
        raise ValueError("semantic source review lacks a reviewable Solidity entity")
    kind_order = {
        **{kind: 0 for kind in _CONTRACT_KINDS},
        **{kind: 1 for kind in _FUNCTION_KINDS},
        **{kind: 2 for kind in _STATE_KINDS},
    }
    entity = min(
        reviewable,
        key=lambda item: (kind_order[item.kind], item.start_line, item.end_line, item.id),
    )
    if entity.kind in _CONTRACT_KINDS:
        return _requests_from_seeds(
            [
                _SurfaceSeed(
                    kind=ModelReviewSurfaceKind.CONTRACT,
                    subject_id=entity.id,
                    label=entity.name,
                    critical=False,
                    locations=(_entity_location(entity),),
                    contract=entity.name,
                    allowed_symbols=tuple(sorted({entity.id, entity.name})),
                    invariant_considered=(
                        f"Assess declared security invariants across contract {entity.name}."
                    ),
                )
            ]
        )[0]
    if entity.kind in _FUNCTION_KINDS:
        request_kind = (
            ModelReviewSurfaceKind.ENTRY_POINT
            if entity.kind is SolidityEntityKind.CONSTRUCTOR
            or entity.visibility in {"public", "external"}
            else ModelReviewSurfaceKind.INTERNAL_FUNCTION
        )
        return _requests_from_seeds([_entity_surface(request_kind, entity, critical=False)])[0]
    return _requests_from_seeds(
        [_entity_surface(ModelReviewSurfaceKind.STATE, entity, critical=False)]
    )[0]


def plan_model_surface_review_assignments(
    config: AuditConfig,
    requests: list[ModelSurfaceReviewRequest],
    *,
    index: SoliditySymbolIndex | None,
    graphs: SolidityGraphSet | None,
    invariants: InvariantSuite | None,
    economic_simulations: list[EconomicSimulationPlan],
    audited_suite_coverage: AuditedSuiteCoverage | None = None,
    minimum_critical_root_lineages: int = 3,
    source_contents_by_path: dict[str, str] | None = None,
) -> dict[str, list[ModelSurfaceReviewRequest]]:
    """Distribute explicit review requests without treating aliases as independence.

    Critical surfaces are assigned to distinct registered and operator-approved
    root lineages. Non-critical surfaces receive one deterministic assignment.
    Missing independent lineages leave the surface under-assigned so the
    downstream coverage gate fails closed.
    """

    source_contents_by_path = _copy_source_contents(source_contents_by_path)
    requests = _require_authoritative_request_inventory(
        requests,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=economic_simulations,
        audited_suite_coverage=audited_suite_coverage,
        source_contents_by_path=source_contents_by_path,
    )
    roles = _scheduled_model_surface_review_roles(config)
    lineage_by_model = model_lineage_index(config)
    approved_lineages = set(config.privacy.approved_model_lineages)
    candidates: list[tuple[str, str]] = []
    for role in sorted(roles):
        configured = _configured_models_for_role(config, role)
        if not configured:
            continue
        primary = (
            config.models.role(role).primary
            if role in _BASE_REVIEW_ROLES
            else config.models.specialists[role.removeprefix("specialist:")].primary
        )
        lineage = lineage_by_model.get(primary.lower())
        if lineage is None:
            continue
        if lineage.root_lineage not in approved_lineages:
            continue
        candidates.append((role, lineage.root_lineage))

    assignments: dict[str, list[ModelSurfaceReviewRequest]] = {role: [] for role in sorted(roles)}
    for request in sorted(requests, key=lambda item: item.surface_id):
        if (
            request.priority is ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP
            and not request.critical
        ):
            raise ValueError("coverage-gap priority is valid only for critical model surfaces")
        target = minimum_critical_root_lineages if request.critical else 1
        if not candidates:
            continue
        offset = int(request.surface_id.removeprefix("model-surface:")[:16], 16) % len(candidates)
        ordered_candidates = candidates[offset:] + candidates[:offset]
        selected_lineages: set[str] = set()
        if request.priority is ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP:
            hunter = next(
                (
                    (role, root_lineage)
                    for role, root_lineage in candidates
                    if role == _COVERAGE_GAP_HUNTER_ROLE
                ),
                None,
            )
            if hunter is not None:
                hunter_role, hunter_lineage = hunter
                assignments[hunter_role].append(request)
                selected_lineages.add(hunter_lineage)
        for role, root_lineage in ordered_candidates:
            if len(selected_lineages) >= target:
                break
            if root_lineage in selected_lineages:
                continue
            assignments[role].append(request)
            selected_lineages.add(root_lineage)
            if len(selected_lineages) == target:
                break
    return {
        role: sorted(role_requests, key=lambda item: item.surface_id)
        for role, role_requests in assignments.items()
    }


def model_surface_assignment_feasibility_gate(
    config: AuditConfig,
    *,
    index: SoliditySymbolIndex | None,
    graphs: SolidityGraphSet | None,
    invariants: InvariantSuite | None,
    economic_simulations: list[EconomicSimulationPlan],
    audited_suite_coverage: AuditedSuiteCoverage | None,
    requests: list[ModelSurfaceReviewRequest],
    assignments: dict[str, list[ModelSurfaceReviewRequest]],
    required: bool,
    minimum_critical_root_lineages: int = 3,
    source_contents_by_path: dict[str, str] | None = None,
) -> QualityGateResult:
    """Prove the planned surface assignments are feasible before provider spend.

    Only distinct, operator-approved root lineages resolved from a configured
    review role's registered primary model count. Aliases therefore cannot add
    independence, and fallback models cannot make a primary assignment feasible.
    """

    if minimum_critical_root_lineages < 1:
        raise ValueError("critical surface feasibility requires at least one root lineage")
    source_contents_by_path = _copy_source_contents(source_contents_by_path)
    gate = "model_surface_assignment_feasibility"
    if index is None:
        return QualityGateResult(
            gate=gate,
            required=required,
            passed=False,
            detail="Solidity symbol index was unavailable; assignment feasibility is unknown",
            state=AnalysisState.NOT_ANALYZED,
        )
    try:
        index, graphs, invariants, economic_simulations = _reconstruct_surface_inputs(
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=economic_simulations,
        )
        audited_suite_coverage = _reconstruct_audited_suite_coverage(audited_suite_coverage)
    except ValueError as exc:
        return QualityGateResult(
            gate=gate,
            required=required,
            passed=False,
            detail=f"model-surface classification evidence failed validation: {exc}",
            state=AnalysisState.ATTEMPTED_FAILED,
        )
    assert index is not None
    if audited_suite_coverage is None:
        return QualityGateResult(
            gate=gate,
            required=required,
            passed=False,
            detail=(
                "audited-suite coverage was unavailable; assignment feasibility cannot "
                "prove the critical-surface denominator"
            ),
            state=AnalysisState.NOT_ANALYZED,
        )
    if (
        not audited_suite_coverage.source_classification_complete
        or not audited_suite_coverage.critical_classification_complete
        or not _critical_classification_inputs_complete(
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=economic_simulations,
            source_contents_by_path=source_contents_by_path,
        )
    ):
        return QualityGateResult(
            gate=gate,
            required=required,
            passed=False,
            detail=(
                "audited-suite critical classification was incomplete or lacked exact "
                "graph, invariant, economic, and source-partition evidence"
            ),
            state=AnalysisState.NOT_ANALYZED,
        )
    try:
        requests = _require_authoritative_request_inventory(
            requests,
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=economic_simulations,
            audited_suite_coverage=audited_suite_coverage,
            source_contents_by_path=source_contents_by_path,
        )
    except ValueError as exc:
        return QualityGateResult(
            gate=gate,
            required=required,
            passed=False,
            detail=f"model-surface inventory failed authoritative revalidation: {exc}",
            state=AnalysisState.ATTEMPTED_FAILED,
        )
    if not requests:
        return QualityGateResult(
            gate=gate,
            required=required,
            passed=False,
            detail=(
                "Solidity analysis was applicable but the deterministic model-surface "
                "inventory was empty (0/0)"
            ),
            state=AnalysisState.ATTEMPTED_FAILED,
        )

    requests_by_id = {request.surface_id: request for request in requests}
    duplicate_inventory_ids = len(requests_by_id) != len(requests)
    assigned_lineages: dict[str, set[str]] = {surface_id: set() for surface_id in requests_by_id}
    invalid_assignments: set[str] = set()
    lineage_by_model = model_lineage_index(config)
    approved_lineages = set(config.privacy.approved_model_lineages)
    scheduled_roles = set(_scheduled_model_surface_review_roles(config))
    coverage_gap_hunter_lineage = (
        _approved_registered_primary_lineage(
            config,
            _COVERAGE_GAP_HUNTER_ROLE,
            lineage_by_model=lineage_by_model,
            approved_lineages=approved_lineages,
        )
        if _COVERAGE_GAP_HUNTER_ROLE in scheduled_roles
        else None
    )
    hunter_request_counts: dict[str, int] = {}

    seen_role_surfaces: set[tuple[str, str]] = set()
    for role, role_requests in sorted(assignments.items()):
        role_is_scheduled = role in scheduled_roles
        if not role_is_scheduled:
            invalid_assignments.add(f"{role}:unscheduled-role")
        root_lineage = (
            _approved_registered_primary_lineage(
                config,
                role,
                lineage_by_model=lineage_by_model,
                approved_lineages=approved_lineages,
            )
            if role_is_scheduled
            else None
        )
        for assigned_request in role_requests:
            role_surface = (role, assigned_request.surface_id)
            if role_surface in seen_role_surfaces:
                invalid_assignments.add(f"{role}:duplicate-surface:{assigned_request.surface_id}")
                continue
            seen_role_surfaces.add(role_surface)
            if role == _COVERAGE_GAP_HUNTER_ROLE:
                hunter_request_counts[assigned_request.surface_id] = (
                    hunter_request_counts.get(assigned_request.surface_id, 0) + 1
                )
            inventory_request = requests_by_id.get(assigned_request.surface_id)
            if inventory_request is None:
                invalid_assignments.add(f"{role}:unknown-surface:{assigned_request.surface_id}")
                continue
            if assigned_request != inventory_request:
                invalid_assignments.add(f"{role}:mismatched-surface:{assigned_request.surface_id}")
                continue
            if root_lineage is None:
                if role_is_scheduled:
                    invalid_assignments.add(
                        f"{role}:unapproved-or-unregistered-primary:{assigned_request.surface_id}"
                    )
                continue
            assigned_lineages[assigned_request.surface_id].add(root_lineage)

    underassigned = [
        (
            request.surface_id,
            len(assigned_lineages[request.surface_id]),
            minimum_critical_root_lineages if request.critical else 1,
        )
        for request in sorted(requests, key=lambda item: item.surface_id)
        if len(assigned_lineages[request.surface_id])
        < (minimum_critical_root_lineages if request.critical else 1)
    ]
    missing_priority_assignments = [
        request.surface_id
        for request in sorted(requests, key=lambda item: item.surface_id)
        if (
            coverage_gap_hunter_lineage is not None
            and request.priority is ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP
            and hunter_request_counts.get(request.surface_id, 0) != 1
        )
    ]
    passed = (
        not duplicate_inventory_ids
        and not invalid_assignments
        and not underassigned
        and not missing_priority_assignments
    )
    return QualityGateResult(
        gate=gate,
        required=required,
        passed=passed,
        detail=(
            f"surfaces={len(requests)}; "
            f"critical={sum(request.critical for request in requests)}; "
            f"noncritical={sum(not request.critical for request in requests)}; "
            f"underassigned={len(underassigned)}; "
            f"invalid_assignments={len(invalid_assignments)}; "
            f"missing_priority_assignments={len(missing_priority_assignments)}; "
            f"coverage_gap_hunter_available={int(coverage_gap_hunter_lineage is not None)}; "
            f"duplicate_inventory_ids={int(duplicate_inventory_ids)}; "
            "required_distinct_primary_root_lineages="
            f"critical:{minimum_critical_root_lineages},noncritical:1"
        ),
        state=AnalysisState.DETERMINISTIC if passed else AnalysisState.ATTEMPTED_FAILED,
    )


def _scheduled_model_surface_review_roles(config: AuditConfig) -> tuple[str, ...]:
    """Return only investigator roles the pipeline executes for the selected profile."""

    specialists = (
        (
            f"specialist:{role}"
            for role in SPECIALIST_INVESTIGATOR_ROLES
            if role in config.models.specialists
        )
        if config.profile in {AuditProfile.DEEP, AuditProfile.MAXIMUM_ASSURANCE}
        else ()
    )
    return tuple(sorted((*_BASE_REVIEW_ROLES, *specialists)))


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
    if not coverage.critical_classification_complete:
        return QualityGateResult(
            gate="critical_model_surface_review",
            required=required,
            passed=False,
            detail=(
                coverage.limitations[0]
                if coverage.limitations
                else "critical-surface classification was incomplete"
            ),
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


def _requests_from_seeds(
    seeds: list[_SurfaceSeed],
    *,
    coverage_gap_ids_by_entity: dict[str, tuple[str, ...]] | None = None,
) -> list[ModelSurfaceReviewRequest]:
    gap_ids_by_entity = coverage_gap_ids_by_entity or {}
    requests = [
        ModelSurfaceReviewRequest(
            surface_id=_surface_id(seed.kind, seed.subject_id),
            kind=seed.kind,
            subject_id=seed.subject_id,
            contract=seed.contract,
            function_or_state_surface=seed.label,
            critical=seed.critical,
            allowed_locations=tuple(_sorted_locations(list(seed.locations))),
            allowed_symbols=seed.allowed_symbols,
            invariant_considered=seed.invariant_considered,
            priority=(
                ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP
                if gap_ids_by_entity.get(seed.subject_id)
                else ModelSurfaceReviewPriority.STANDARD
            ),
            coverage_gap_ids=gap_ids_by_entity.get(seed.subject_id, ()),
        )
        for seed in seeds
    ]
    return sorted(requests, key=lambda request: request.surface_id)


def _with_audited_suite_criticality(
    seeds: list[_SurfaceSeed],
    coverage: AuditedSuiteCoverage | None,
) -> list[_SurfaceSeed]:
    """Conservatively retain exact source criticality from audited-suite coverage."""

    if coverage is None or coverage.critical_classification_complete:
        return seeds
    conservative_source_entity_ids = {surface.entity_id for surface in coverage.surfaces}
    return [
        (
            replace(seed, critical=True)
            if seed.subject_id in conservative_source_entity_ids and not seed.critical
            else seed
        )
        for seed in seeds
    ]


def _review_evidence_references(
    config: AuditConfig,
    *,
    requests: list[ModelSurfaceReviewRequest],
    usage_records: list[UsageRecord],
    review_artifacts: list[ModelSurfaceReviewArtifact],
    review_contexts_by_request: dict[str, list[ContextPackage]],
    index: SoliditySymbolIndex | None,
    graphs: SolidityGraphSet | None,
    limitations: set[str],
) -> dict[str, list[ModelReviewEvidenceReference]]:
    requests_by_id = {request.surface_id: request for request in requests}
    usage_by_request: dict[str, list[UsageRecord]] = {}
    for usage_record in usage_records:
        usage_by_request.setdefault(usage_record.request_id, []).append(usage_record)
    lineage_by_model = model_lineage_index(config)
    require_certification = config.profile is AuditProfile.MAXIMUM_ASSURANCE
    references: dict[str, list[ModelReviewEvidenceReference]] = {}
    forensic_limitations: dict[str, set[str]] = {}
    artifact_counts: dict[str, int] = {}
    for artifact in review_artifacts:
        artifact_counts[artifact.artifact_sha256] = (
            artifact_counts.get(artifact.artifact_sha256, 0) + 1
        )

    processed_artifacts: set[str] = set()
    for artifact in review_artifacts:
        duplicate_artifact = artifact_counts[artifact.artifact_sha256] > 1
        if artifact.artifact_sha256 in processed_artifacts:
            continue
        processed_artifacts.add(artifact.artifact_sha256)
        if duplicate_artifact:
            _record_forensic_limitation(
                forensic_limitations,
                category="duplicate_artifact",
                identity=artifact.artifact_sha256,
            )

        reasons: list[str] = []
        if duplicate_artifact:
            reasons.append("duplicate model-review artifact")

        usages = usage_by_request.get(artifact.request_id, [])
        usage = usages[0] if len(usages) == 1 else None
        if not usages:
            reasons.append("no usage record matched the artifact request")
        elif len(usages) != 1:
            reasons.append("artifact request did not join exactly one usage record")

        contexts = review_contexts_by_request.get(artifact.request_id, [])
        context = contexts[0] if len(contexts) == 1 else None
        if not contexts:
            reasons.append("no source review context matched the artifact request")
        elif len(contexts) != 1:
            reasons.append("artifact request did not join exactly one source review context")
        elif context is not None:
            # Imported lazily because context construction imports this module.
            from mmaudit.orchestration.context import (
                ContextBudgetError,
                revalidate_context_package,
            )

            try:
                context = revalidate_context_package(context)
            except ContextBudgetError:
                context = None
                reasons.append("source review context failed exact boundary validation")
                _record_forensic_limitation(
                    forensic_limitations,
                    category="invalid_context",
                    identity=artifact.request_id,
                )

        artifact_requests: list[ModelSurfaceReviewRequest] = []
        unknown_surface_ids = [
            surface_id
            for surface_id in artifact.requested_surface_ids
            if surface_id not in requests_by_id
        ]
        if unknown_surface_ids:
            reasons.append("artifact requested surfaces outside the deterministic inventory")
            _record_forensic_limitation(
                forensic_limitations,
                category="unknown_surfaces",
                identity=artifact.artifact_sha256,
            )
        else:
            artifact_requests = [
                requests_by_id[surface_id] for surface_id in artifact.requested_surface_ids
            ]
            try:
                artifact.require_exact_requested_surface_manifest(artifact_requests)
            except ValueError:
                reasons.append("artifact requested-surface manifest hash was inconsistent")

        if context is not None:
            if artifact.rendered_context_sha256 != model_review_context_sha256(context):
                reasons.append(
                    "source review context hash differed from the rendered provider request"
                )
            if context.role != artifact.review_role:
                reasons.append("source review context role differed from the artifact role")
            if tuple(context.requested_model_surfaces) != tuple(artifact_requests):
                reasons.append("source review context surfaces differed from the artifact manifest")
            if not _context_symbol_index_is_subset(context.solidity_index, index):
                reasons.append(
                    "source review context symbol index was not an exact inventory subset"
                )
            if not _context_graphs_are_subset(context.solidity_graphs, graphs):
                reasons.append("source review context graphs were not an exact inventory subset")

        expected_artifact_hash = ModelSurfaceReviewArtifact.calculate_artifact_sha256(
            artifact.model_dump(mode="json")
        )
        if expected_artifact_hash != artifact.artifact_sha256:
            reasons.append("artifact hash was inconsistent")
        if artifact.review_role not in _BASE_REVIEW_ROLES | _SPECIALIST_REVIEW_ROLES:
            reasons.append("artifact role was not an allowed investigator role")

        requested_model: str | None = None
        actual_model: str | None = None
        root_lineage: str | None = None
        if usage is not None:
            requested_model = usage.requested_model
            actual_model = usage.actual_model
            if artifact.review_role != usage.role:
                reasons.append("artifact role differed from its usage record")
            if artifact.prompt_sha256 != usage.prompt_sha256:
                reasons.append("artifact prompt hash differed from its usage record")
            if artifact.rendered_context_sha256 != usage.user_prompt_sha256:
                reasons.append("artifact context hash differed from its usage record")
            if artifact.response_sha256 != usage.response_sha256:
                reasons.append("artifact response hash differed from its usage record")
            if artifact.validated_response_sha256 != usage.validated_response_sha256:
                reasons.append("artifact validated-response hash differed from its usage record")
            if artifact.response_schema_sha256 != usage.schema_sha256:
                reasons.append("artifact schema hash differed from its usage record")
            if not is_creditable_usage_record(
                usage,
                require_real=True,
                require_certification=require_certification,
            ):
                if usage.execution_evidence is not ExecutionEvidenceKind.REAL:
                    reasons.append("model usage was not REAL")
                    limitations.add(
                        "mock model usage was excluded from substantive model-review coverage"
                    )
                elif require_certification:
                    reasons.append("maximum-assurance model usage lacked certification evidence")
                else:
                    reasons.append("model usage was not creditable")
            configured_models = _configured_models_for_role(config, artifact.review_role)
            if usage.requested_model not in configured_models:
                reasons.append("requested model was not configured for the review role")
            lineage = lineage_by_model.get(usage.requested_model.lower())
            if lineage is None:
                reasons.append("requested model had no registered immutable lineage")
                _record_forensic_limitation(
                    forensic_limitations,
                    category="unregistered_model",
                    identity=usage.request_id,
                )
            else:
                root_lineage = lineage.root_lineage
                approved_lineages = set(config.privacy.approved_model_lineages)
                if lineage.root_lineage not in approved_lineages:
                    reasons.append("requested model lineage lacked operator approval")
                    _record_forensic_limitation(
                        forensic_limitations,
                        category="unapproved_lineage",
                        identity=usage.request_id,
                    )

        for record in artifact.records:
            request = requests_by_id.get(record.surface_id)
            if request is None:
                continue
            record_reasons = [*reasons]
            record_reasons.extend(
                _record_validation_failures(
                    request,
                    record,
                    expected_role=artifact.review_role,
                    index=index,
                    graphs=graphs,
                )
            )
            if context is not None:
                record_reasons.extend(
                    model_surface_review_excerpt_validation_failures(
                        context=context,
                        request=request,
                        record=record,
                    )
                )
            if record.status not in _CREDITABLE_REVIEW_STATUSES:
                record_reasons.append(
                    f"{record.status.value} is explicit no-credit review evidence"
                )
            credited = not record_reasons and record.status in _CREDITABLE_REVIEW_STATUSES
            reference = ModelReviewEvidenceReference(
                surface_id=record.surface_id,
                request_id=artifact.request_id,
                artifact_sha256=artifact.artifact_sha256,
                requested_model=requested_model,
                model=actual_model,
                review_role=artifact.review_role,
                status=record.status,
                root_lineage=root_lineage,
                credited=credited,
                reason=(
                    "credited: explicit per-surface response passed independent validation"
                    if credited
                    else "; ".join(sorted(set(record_reasons)))
                ),
            )
            references.setdefault(record.surface_id, []).append(reference)

    limitations.update(_forensic_limitation_summaries(forensic_limitations))

    for surface_references in references.values():
        surface_references.sort(
            key=lambda item: (
                item.request_id,
                item.artifact_sha256,
                item.surface_id,
                item.review_role,
                item.status.value,
            )
        )
    return references


def _context_symbol_index_is_subset(
    context_index: SoliditySymbolIndex | None,
    evaluated_index: SoliditySymbolIndex | None,
) -> bool:
    if context_index is None:
        return False
    if evaluated_index is None:
        return False
    return all(entity in evaluated_index.entities for entity in context_index.entities)


def _context_graphs_are_subset(
    context_graphs: SolidityGraphSet | None,
    evaluated_graphs: SolidityGraphSet | None,
) -> bool:
    if context_graphs is None:
        return True
    if evaluated_graphs is None:
        return False
    return all(node in evaluated_graphs.nodes for node in context_graphs.nodes) and all(
        edge in evaluated_graphs.edges for edge in context_graphs.edges
    )


def _configured_models_for_role(config: AuditConfig, role: str) -> frozenset[str]:
    if role in _BASE_REVIEW_ROLES:
        role_config = config.models.role(role)
        return frozenset((role_config.primary, *role_config.fallbacks))
    if not role.startswith("specialist:"):
        return frozenset()
    specialist_config = config.models.specialists.get(role.removeprefix("specialist:"))
    if specialist_config is None:
        return frozenset()
    return frozenset((specialist_config.primary, *specialist_config.fallbacks))


def _approved_registered_primary_lineage(
    config: AuditConfig,
    role: str,
    *,
    lineage_by_model: dict[str, ModelLineageConfig],
    approved_lineages: set[str],
) -> str | None:
    if role in _BASE_REVIEW_ROLES:
        primary = config.models.role(role).primary
    elif role.startswith("specialist:"):
        specialist = config.models.specialists.get(role.removeprefix("specialist:"))
        if specialist is None:
            return None
        primary = specialist.primary
    else:
        return None
    lineage = lineage_by_model.get(primary.lower())
    if lineage is None or lineage.root_lineage not in approved_lineages:
        return None
    return lineage.root_lineage


def _record_validation_failures(
    request: ModelSurfaceReviewRequest,
    record: ModelSurfaceReviewRecord,
    *,
    expected_role: str,
    index: SoliditySymbolIndex | None,
    graphs: SolidityGraphSet | None,
) -> list[str]:
    # Artifacts are already schema-validated, but all deterministic joins are
    # repeated here so serialized evidence cannot self-authorize coverage.
    failures: list[str] = []
    if record.surface_id != request.surface_id:
        failures.append("record surface ID differed from the deterministic request")
    if record.contract != request.contract:
        failures.append("record contract differed from the deterministic request")
    if record.function_or_state_surface != request.function_or_state_surface:
        failures.append("record surface label differed from the deterministic request")
    if record.invariant_considered != request.invariant_considered:
        failures.append("record invariant instruction differed from the deterministic request")
    if record.review_role != expected_role:
        failures.append("record review role differed from the containing artifact")
    citation = record.citation
    if citation.location is not None and citation.location not in request.allowed_locations:
        failures.append("record cited a location outside the deterministic request")
    if citation.symbol is not None and citation.symbol not in request.allowed_symbols:
        failures.append("record cited a symbol outside the deterministic request")
    failures.extend(
        model_surface_review_record_validation_failures(
            request,
            record,
            expected_role,
            index=index,
            graphs=graphs,
        )
    )
    return failures


def _reconstruct_audited_suite_coverage(
    coverage: AuditedSuiteCoverage | None,
) -> AuditedSuiteCoverage | None:
    """Revalidate mutable nested evidence at each public orchestration boundary."""

    if coverage is None:
        return None
    return AuditedSuiteCoverage.model_validate(coverage.model_dump(mode="python"))


def _copy_source_contents(
    source_contents_by_path: dict[str, str] | None,
) -> dict[str, str] | None:
    """Copy ephemeral current-source evidence without placing it in typed artifacts."""

    if source_contents_by_path is None:
        return None
    if any(
        not isinstance(path, str) or not isinstance(content, str)
        for path, content in source_contents_by_path.items()
    ):
        raise ValueError("current-source evidence must map string paths to string contents")
    return dict(sorted(source_contents_by_path.items()))


def _reconstruct_surface_inputs(
    *,
    index: SoliditySymbolIndex | None,
    graphs: SolidityGraphSet | None,
    invariants: InvariantSuite | None,
    economic_simulations: list[EconomicSimulationPlan],
) -> tuple[
    SoliditySymbolIndex | None,
    SolidityGraphSet | None,
    InvariantSuite | None,
    list[EconomicSimulationPlan],
]:
    """Revalidate every mutable deterministic input before deriving paid work."""

    return (
        (
            SoliditySymbolIndex.model_validate(index.model_dump(mode="python"))
            if index is not None
            else None
        ),
        (
            SolidityGraphSet.model_validate(graphs.model_dump(mode="python"))
            if graphs is not None
            else None
        ),
        (
            InvariantSuite.model_validate(invariants.model_dump(mode="python"))
            if invariants is not None
            else None
        ),
        [
            EconomicSimulationPlan.model_validate(plan.model_dump(mode="python"))
            for plan in economic_simulations
        ],
    )


def _require_authoritative_request_inventory(
    requests: list[ModelSurfaceReviewRequest],
    *,
    index: SoliditySymbolIndex | None,
    graphs: SolidityGraphSet | None,
    invariants: InvariantSuite | None,
    economic_simulations: list[EconomicSimulationPlan],
    audited_suite_coverage: AuditedSuiteCoverage | None,
    source_contents_by_path: dict[str, str] | None,
) -> list[ModelSurfaceReviewRequest]:
    """Reject caller-authored scheduling facts by rebuilding the host inventory."""

    reconstructed = [
        ModelSurfaceReviewRequest.model_validate(request.model_dump(mode="python"))
        for request in requests
    ]
    authoritative = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=economic_simulations,
        audited_suite_coverage=audited_suite_coverage,
        source_contents_by_path=source_contents_by_path,
    )
    if reconstructed != authoritative:
        raise ValueError(
            "supplied model-surface requests differ from the authoritative source inventory"
        )
    return authoritative


def _validated_coverage_gap_ids_by_entity(
    *,
    index: SoliditySymbolIndex | None,
    graphs: SolidityGraphSet | None,
    invariants: InvariantSuite | None,
    economic_simulations: list[EconomicSimulationPlan],
    seeds: list[_SurfaceSeed],
    audited_suite_coverage: AuditedSuiteCoverage | None,
    source_contents_by_path: dict[str, str] | None,
) -> dict[str, tuple[str, ...]]:
    if audited_suite_coverage is None:
        return {}
    if not audited_suite_coverage.source_classification_complete:
        return {}
    if index is None:
        raise ValueError(
            "audited-suite coverage gaps require a Solidity symbol index for exact binding"
        )
    if audited_suite_coverage.critical_classification_complete and not (
        _critical_classification_inputs_complete(
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=economic_simulations,
            source_contents_by_path=source_contents_by_path,
        )
    ):
        raise ValueError(
            "audited-suite coverage claims complete critical classification without "
            "complete graph, invariant, economic, and exact source-binding evidence"
        )

    entities_by_id = {entity.id: entity for entity in index.entities}
    partition = partition_audited_source_entities(index=index, projects=index.projects)
    if not partition.classification_complete:
        raise ValueError("audited-suite coverage requires complete audited-source classification")
    expected_entity_ids = {
        *partition.contract_entity_ids,
        *partition.function_entity_ids,
    }
    surfaces_by_id = {surface.entity_id: surface for surface in audited_suite_coverage.surfaces}
    if set(surfaces_by_id) != expected_entity_ids:
        raise ValueError(
            "audited-suite coverage surface population differs from the audited-source partition"
        )
    surfaced_subject_ids = {seed.subject_id for seed in seeds}
    critical_subject_ids = {seed.subject_id for seed in seeds if seed.critical}
    for entity_id in sorted(expected_entity_ids):
        entity = entities_by_id[entity_id]
        surface = surfaces_by_id[entity_id]
        expected_contract = entity.contract_name or (
            entity.name if entity.kind in _CONTRACT_KINDS else "protocol"
        )
        if (
            surface.entity_kind is not entity.kind
            or surface.contract_name != expected_contract
            or surface.location != _entity_location(entity)
            or surface.critical != (entity_id in critical_subject_ids)
        ):
            raise ValueError(
                "audited-suite coverage surface identity or criticality differs from "
                f"the authoritative inventory: {entity_id}"
            )
    if not audited_suite_coverage.gaps:
        return {}
    gap_ids_by_entity: dict[str, list[str]] = {}
    for gap in audited_suite_coverage.gaps:
        gap_entity = entities_by_id.get(gap.entity_id)
        if gap_entity is None or gap.entity_id not in surfaced_subject_ids:
            raise ValueError(
                f"audited-suite coverage gap references unknown audited surface {gap.entity_id}"
            )
        if gap_entity.kind is not gap.entity_kind:
            raise ValueError(
                f"audited-suite coverage gap kind differs from indexed entity {gap.entity_id}"
            )
        if _entity_location(gap_entity) != gap.location:
            raise ValueError(
                f"audited-suite coverage gap location/hash differs from index {gap.entity_id}"
            )
        if gap.entity_id not in critical_subject_ids:
            raise ValueError(
                f"audited-suite coverage gap is not independently critical {gap.entity_id}"
            )
        gap_ids_by_entity.setdefault(gap.entity_id, []).append(gap.gap_id)
    return {
        entity_id: tuple(sorted(gap_ids))
        for entity_id, gap_ids in sorted(gap_ids_by_entity.items())
    }


def _critical_classification_inputs_complete(
    *,
    index: SoliditySymbolIndex | None,
    graphs: SolidityGraphSet | None,
    invariants: InvariantSuite | None,
    economic_simulations: list[EconomicSimulationPlan],
    source_contents_by_path: dict[str, str] | None,
) -> bool:
    if index is None or graphs is None or invariants is None:
        return False
    partition = partition_audited_source_entities(index=index, projects=index.projects)
    if not partition.classification_complete:
        return False
    required_graphs = {
        SolidityGraphKind.PRIVILEGE,
        SolidityGraphKind.ASSET_FLOW,
        SolidityGraphKind.SENSITIVE_REACHABILITY,
    }
    entities_by_id = {entity.id: entity for entity in index.entities}
    audited_contract_ids = set(partition.contract_entity_ids)
    audited_function_ids = set(partition.function_entity_ids)
    audited_contract_keys = {
        (entities_by_id[entity_id].path, entities_by_id[entity_id].name)
        for entity_id in audited_contract_ids
    }
    audited_state_ids = {
        entity.id
        for entity in index.entities
        if entity.kind in _STATE_KINDS
        and entity.contract_name is not None
        and (entity.path, entity.contract_name) in audited_contract_keys
    }
    audited_entity_ids = audited_contract_ids | audited_function_ids | audited_state_ids
    test_entity_ids = exact_test_entity_ids(index=index, projects=index.projects)
    test_function_ids = {
        entity.id
        for entity in index.entities
        if entity.id in test_entity_ids
        and entity.kind
        in {
            SolidityEntityKind.FUNCTION,
            SolidityEntityKind.CONSTRUCTOR,
        }
    }
    invariant_bindings = [
        (
            invariant,
            bind_invariant_to_audited_entities(
                invariant=invariant,
                entities=index.entities,
                audited_entity_ids=audited_entity_ids,
                exact_test_entity_ids=test_entity_ids,
                source_contents_by_path=source_contents_by_path,
            ),
        )
        for invariant in invariants.invariants
    ]
    invariant_binding_incomplete = any(binding.invalid for _, binding in invariant_bindings)
    invariant_bindings_by_id = {invariant.id: binding for invariant, binding in invariant_bindings}
    economic_binding_incomplete = any(
        bind_economic_plan_to_audited_entities(
            plan=plan,
            entities=index.entities,
            audited_entity_ids=audited_entity_ids,
            exact_test_entity_ids=test_entity_ids,
            invariant_bindings_by_id=invariant_bindings_by_id,
            source_contents_by_path=source_contents_by_path,
        ).invalid
        for plan in economic_simulations
    )
    critical_graph_edges = [edge for edge in graphs.edges if edge.graph in required_graphs]
    graph_binding_incomplete = any(
        (
            edge.source_id not in audited_function_ids | test_function_ids
            or not critical_graph_edge_is_exact(
                edge,
                entities_by_id=entities_by_id,
                audited_function_ids=(
                    audited_function_ids
                    if edge.source_id in audited_function_ids
                    else test_function_ids
                ),
                source_contents_by_path=source_contents_by_path,
            )
        )
        for edge in critical_graph_edges
    )
    return (
        required_graphs <= set(graphs.analyzed_graphs)
        and not graph_binding_incomplete
        and not invariant_binding_incomplete
        and not economic_binding_incomplete
    )


def _surface_inventory(
    *,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet | None,
    invariants: InvariantSuite | None,
    economic_simulations: list[EconomicSimulationPlan],
    source_contents_by_path: dict[str, str] | None,
) -> list[_SurfaceSeed]:
    entities_by_id = {entity.id: entity for entity in index.entities}
    partition = partition_audited_source_entities(index=index, projects=index.projects)
    if not partition.classification_complete:
        return []
    audited_contract_ids = set(partition.contract_entity_ids)
    audited_function_ids = set(partition.function_entity_ids)
    audited_contract_keys = {
        (entity.path, entity.name) for entity in index.entities if entity.id in audited_contract_ids
    }
    audited_contract_keys.update(
        (entity.path, entity.contract_name)
        for entity in index.entities
        if entity.id in audited_function_ids and entity.contract_name is not None
    )
    audited_state_ids = {
        entity.id
        for entity in index.entities
        if entity.kind in _STATE_KINDS
        and entity.contract_name is not None
        and (entity.path, entity.contract_name) in audited_contract_keys
    }
    audited_entity_ids = audited_contract_ids | audited_function_ids | audited_state_ids
    test_entity_ids = exact_test_entity_ids(index=index, projects=index.projects)
    edges = [
        edge
        for edge in (graphs.edges if graphs is not None else [])
        if edge.source_id in audited_function_ids
        and edge.path == entities_by_id[edge.source_id].path
        and entities_by_id[edge.source_id].start_line <= edge.start_line
        and edge.end_line <= entities_by_id[edge.source_id].end_line
        and (edge.target_id not in entities_by_id or edge.target_id in audited_entity_ids)
        and (
            source_contents_by_path is None
            or critical_graph_edge_is_exact(
                edge,
                entities_by_id=entities_by_id,
                audited_function_ids=audited_function_ids,
                source_contents_by_path=source_contents_by_path,
            )
        )
    ]
    invariant_bindings = [
        (
            invariant,
            bind_invariant_to_audited_entities(
                invariant=invariant,
                entities=index.entities,
                audited_entity_ids=audited_entity_ids,
                exact_test_entity_ids=test_entity_ids,
                source_contents_by_path=source_contents_by_path,
            ),
        )
        for invariant in (invariants.invariants if invariants is not None else [])
    ]
    audited_invariants = [invariant for invariant, binding in invariant_bindings if binding.audited]
    invariant_bindings_by_id = {invariant.id: binding for invariant, binding in invariant_bindings}
    audited_economic_bindings = [
        (
            plan,
            bind_economic_plan_to_audited_entities(
                plan=plan,
                entities=index.entities,
                audited_entity_ids=audited_entity_ids,
                exact_test_entity_ids=test_entity_ids,
                invariant_bindings_by_id=invariant_bindings_by_id,
                source_contents_by_path=source_contents_by_path,
            ),
        )
        for plan in economic_simulations
    ]
    audited_economic_entity_ids = {
        entity_id
        for _, binding in audited_economic_bindings
        if binding.audited
        for entity_id in binding.entity_ids
    }
    privilege_sources = _edge_sources(edges, SolidityGraphKind.PRIVILEGE)
    asset_sources = _edge_sources(edges, SolidityGraphKind.ASSET_FLOW)
    sensitive_sources = _edge_sources(edges, SolidityGraphKind.SENSITIVE_REACHABILITY)
    invariant_entity_ids = {
        entity_id
        for _, binding in invariant_bindings
        if binding.audited
        for entity_id in binding.entity_ids
    }
    critical_function_ids = (
        privilege_sources
        | asset_sources
        | sensitive_sources
        | (invariant_entity_ids & audited_function_ids)
        | (audited_economic_entity_ids & audited_function_ids)
    )
    critical_state_ids = (
        (invariant_entity_ids | audited_economic_entity_ids) & audited_state_ids
    ) | {
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
    if audited_invariants:
        invariant_state_names = {
            name for invariant in audited_invariants for name in invariant.state_variables
        }
        critical_state_ids.update(
            entity.id
            for entity in index.entities
            if entity.id in audited_state_ids and entity.name in invariant_state_names
        )
    audited_contract_ids_by_key = {
        (entities_by_id[entity_id].path, entities_by_id[entity_id].name): entity_id
        for entity_id in audited_contract_ids
    }
    critical_contract_ids = (
        invariant_entity_ids | audited_economic_entity_ids
    ) & audited_contract_ids
    for entity_id in critical_function_ids | critical_state_ids:
        entity = entities_by_id[entity_id]
        if entity.contract_name is None:
            continue
        contract_id = audited_contract_ids_by_key.get((entity.path, entity.contract_name))
        if contract_id is not None:
            critical_contract_ids.add(contract_id)
    seeds: list[_SurfaceSeed] = []
    for entity in index.entities:
        if entity.kind in _CONTRACT_KINDS and entity.id not in audited_contract_ids:
            continue
        if entity.kind in _FUNCTION_KINDS and entity.id not in audited_function_ids:
            continue
        if entity.kind in _STATE_KINDS and entity.id not in audited_state_ids:
            continue
        location = (_entity_location(entity),)
        if entity.kind in _CONTRACT_KINDS:
            seeds.append(
                _SurfaceSeed(
                    kind=ModelReviewSurfaceKind.CONTRACT,
                    subject_id=entity.id,
                    label=entity.name,
                    critical=entity.id in critical_contract_ids,
                    locations=location,
                    contract=entity.name,
                    allowed_symbols=tuple(sorted({entity.id, entity.name})),
                    invariant_considered=(
                        f"Assess declared security invariants across contract {entity.name}."
                    ),
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
        if entity.kind is SolidityEntityKind.FUNCTION and entity.visibility not in {
            "public",
            "external",
        }:
            seeds.append(
                _entity_surface(
                    ModelReviewSurfaceKind.INTERNAL_FUNCTION,
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
                contract=(
                    source.contract_name
                    if source is not None and source.contract_name
                    else "protocol"
                ),
                allowed_symbols=tuple(
                    sorted(
                        {
                            symbol
                            for symbol in (
                                source.signature if source is not None else None,
                                source.name if source is not None else None,
                                edge.source_id,
                            )
                            if symbol
                        }
                    )
                ),
                invariant_considered=(
                    f"Assess state, authorization, and asset invariants across "
                    f"{edge.graph.value} call {source_label}."
                ),
            )
        )
    if audited_invariants:
        for invariant in audited_invariants:
            seeds.append(
                _SurfaceSeed(
                    kind=ModelReviewSurfaceKind.INVARIANT,
                    subject_id=invariant.id,
                    label=invariant.title,
                    critical=True,
                    locations=tuple(_sorted_locations(invariant.locations)),
                    contract=_invariant_contract(invariant, entities_by_id),
                    allowed_symbols=tuple(
                        sorted(
                            {
                                invariant.id,
                                *invariant.entity_ids,
                                *invariant.functions,
                                *invariant.state_variables,
                            }
                        )
                    ),
                    invariant_considered=invariant.description,
                )
            )
        invariant_templates = sorted(
            {
                invariant.template.value
                for invariant in audited_invariants
                if invariant.template is not None
            }
        )
        for template in invariant_templates:
            template_invariants = [
                invariant
                for invariant in audited_invariants
                if invariant.template is not None and invariant.template.value == template
            ]
            seeds.append(
                _SurfaceSeed(
                    kind=ModelReviewSurfaceKind.TEMPLATE,
                    subject_id=f"invariant-template:{template}",
                    label=f"Invariant template: {template}",
                    critical=True,
                    locations=tuple(
                        _sorted_locations(
                            [
                                location
                                for invariant in template_invariants
                                for location in invariant.locations
                            ]
                        )
                    ),
                    contract=_shared_invariant_contract(
                        template_invariants,
                        entities_by_id,
                    ),
                    allowed_symbols=tuple(
                        sorted(
                            {
                                f"invariant-template:{template}",
                                *(
                                    entity_id
                                    for invariant in template_invariants
                                    for entity_id in invariant.entity_ids
                                ),
                                *(
                                    function
                                    for invariant in template_invariants
                                    for function in invariant.functions
                                ),
                                *(
                                    state_variable
                                    for invariant in template_invariants
                                    for state_variable in invariant.state_variables
                                ),
                            }
                        )
                    ),
                    invariant_considered=(f"Assess preservation of invariant template {template}."),
                )
            )
    audited_economic_simulations = [
        plan for plan, binding in audited_economic_bindings if binding.audited
    ]
    for template in sorted({plan.kind.value for plan in audited_economic_simulations}):
        template_plans = [
            plan for plan in audited_economic_simulations if plan.kind.value == template
        ]
        linked_invariant_ids = {
            invariant_id for plan in template_plans for invariant_id in plan.invariant_ids
        }
        linked_invariants = [
            invariant for invariant in audited_invariants if invariant.id in linked_invariant_ids
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
                contract="protocol",
                allowed_symbols=tuple(
                    sorted(
                        {
                            f"economic-template:{template}",
                            *linked_invariant_ids,
                            *(
                                entity_id
                                for invariant in linked_invariants
                                for entity_id in invariant.entity_ids
                            ),
                            *(
                                function
                                for invariant in linked_invariants
                                for function in invariant.functions
                            ),
                            *(
                                state_variable
                                for invariant in linked_invariants
                                for state_variable in invariant.state_variables
                            ),
                        }
                    )
                ),
                invariant_considered=(
                    f"Assess applicability and preservation of economic template {template}."
                ),
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
    graph_instruction = f" and {graph.value} behavior" if graph is not None else ""
    return _SurfaceSeed(
        kind=kind,
        subject_id=entity.id,
        label=entity.signature or entity.name,
        critical=critical,
        locations=(_entity_location(entity),),
        contract=entity.contract_name or "protocol",
        allowed_symbols=tuple(
            sorted({entity.id, entity.name, *(item for item in (entity.signature,) if item)})
        ),
        invariant_considered=(
            f"Assess authorization, state, and asset invariants{graph_instruction} for "
            f"{entity.signature or entity.name}."
        ),
    )


def _materialize_surface(
    seed: _SurfaceSeed,
    *,
    references: list[ModelReviewEvidenceReference],
) -> ModelReviewSurface:
    return ModelReviewSurface(
        surface_id=_surface_id(seed.kind, seed.subject_id),
        kind=seed.kind,
        subject_id=seed.subject_id,
        label=seed.label,
        critical=seed.critical,
        locations=list(seed.locations),
        evidence_references=references,
    )


def _coverage_metric(
    *,
    numerator: int,
    surfaces: list[ModelReviewSurface],
    applicable: bool,
    detail: str,
    minimum_root_lineages: int | None = None,
    inapplicable_reason: str = "Solidity symbol index was unavailable",
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
        failures = [inapplicable_reason]
        not_applicable_evidence = []
    return CoverageMetric(
        numerator=numerator,
        denominator=denominator,
        population=denominator,
        percentage=round((numerator / denominator) * 100, 4) if denominator else None,
        exclusions=[],
        not_applicable_evidence=not_applicable_evidence,
        confidence=1,
        provenance=[CoverageProvenance.MODEL_REVIEW],
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


def _edge_subject_id(edge: SolidityGraphEdge) -> str:
    return f"graph-edge:{_edge_digest(edge)}"


def model_review_edge_subject_id(edge: SolidityGraphEdge) -> str:
    """Return the stable public model-review subject for one normalized graph edge."""

    return _edge_subject_id(edge)


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


def _invariant_contract(
    invariant: InvariantSpec,
    entities_by_id: dict[str, SolidityEntity],
) -> str:
    contracts = sorted(
        {
            entity.contract_name
            for entity_id in invariant.entity_ids
            for entity in (entities_by_id.get(entity_id),)
            if entity is not None and entity.contract_name
        }
    )
    return contracts[0] if len(contracts) == 1 else "protocol"


def _shared_invariant_contract(
    invariants: list[InvariantSpec],
    entities_by_id: dict[str, SolidityEntity],
) -> str:
    contracts = {
        contract
        for invariant in invariants
        for contract in (_invariant_contract(invariant, entities_by_id),)
        if contract != "protocol"
    }
    return next(iter(contracts)) if len(contracts) == 1 else "protocol"
