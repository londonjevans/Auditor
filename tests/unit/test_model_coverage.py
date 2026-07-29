from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime

from mmaudit.config import AuditConfig
from mmaudit.models.schemas import (
    ContextExcerpt,
    ContextPackage,
    ExecutionEvidenceKind,
    InvariantCategory,
    InvariantSpec,
    InvariantSuite,
    InvariantTemplate,
    Location,
    ModelRequestValidationStatus,
    ModelReviewCoverage,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewCitation,
    ModelSurfaceReviewEvidenceObservation,
    ModelSurfaceReviewReachability,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
    RepositoryMap,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphKind,
    SolidityGraphSet,
    SolidityProjectMetadata,
    SolidityProjectType,
    SolidityProvenance,
    SoliditySymbolIndex,
    UsageRecord,
)
from mmaudit.models.token_planning import (
    ContextOmissionCategory,
    ContextOmissionItem,
    ContextOmissionReason,
)
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.model_coverage import (
    build_model_review_coverage,
    build_model_surface_requests,
    model_review_critical_surface_gate,
    plan_model_surface_review_assignments,
)
from tests.identity_fixtures import (
    bind_synthetic_usage_identity,
    reattest_synthetic_real_usage,
)

_PATH = "src/Vault.sol"
_SOURCE = "".join(f"// synthetic source line {line}\n" for line in range(1, 31))


def _source_hash(start_line: int, end_line: int) -> str:
    lines = _SOURCE.splitlines(keepends=True)
    return hashlib.sha256("".join(lines[start_line - 1 : end_line]).encode()).hexdigest()


def _entity(
    entity_id: str,
    kind: SolidityEntityKind,
    name: str,
    line: int,
    *,
    contract_name: str | None = "Vault",
    visibility: str | None = None,
    signature: str | None = None,
) -> SolidityEntity:
    return SolidityEntity(
        id=entity_id,
        kind=kind,
        name=name,
        contract_name=contract_name,
        path=_PATH,
        start_line=line,
        end_line=line + 1,
        byte_start=line,
        byte_end=line + 1,
        source_hash=_source_hash(line, line + 1),
        provenance=SolidityProvenance.COMPILER,
        confidence=1,
        transformation="synthetic_model_coverage_test",
        visibility=visibility,
        signature=signature,
    )


def _edge(
    graph: SolidityGraphKind,
    source_id: str,
    target_id: str,
    label: str,
    line: int,
) -> SolidityGraphEdge:
    return SolidityGraphEdge(
        graph=graph,
        source_id=source_id,
        target_id=target_id,
        label=label,
        provenance=SolidityProvenance.COMPILER,
        path=_PATH,
        start_line=line,
        end_line=line,
        source_hash=_source_hash(line, line),
        confidence=1,
        transformation="synthetic_model_coverage_test",
    )


def _inventory() -> tuple[SoliditySymbolIndex, SolidityGraphSet, InvariantSuite]:
    index = SoliditySymbolIndex(
        projects=[
            SolidityProjectMetadata(
                project_type=SolidityProjectType.FOUNDRY,
                project_root=".",
                source_directories=["src"],
            )
        ],
        entities=[
            _entity(
                "contract:Vault",
                SolidityEntityKind.CONTRACT,
                "Vault",
                1,
                contract_name=None,
            ),
            _entity(
                "function:Vault.deposit",
                SolidityEntityKind.FUNCTION,
                "deposit",
                10,
                visibility="external",
                signature="deposit(uint256)",
            ),
            _entity(
                "function:Vault.adminSet",
                SolidityEntityKind.FUNCTION,
                "adminSet",
                20,
                visibility="public",
                signature="adminSet(uint256)",
            ),
            _entity(
                "state:Vault.totalAssets",
                SolidityEntityKind.STATE_VARIABLE,
                "totalAssets",
                5,
            ),
        ],
        ast_sources=["src/Vault.sol"],
    )
    graphs = SolidityGraphSet(
        edges=[
            _edge(
                SolidityGraphKind.ASSET_FLOW,
                "function:Vault.deposit",
                "asset:synthetic",
                "observed asset inflow",
                11,
            ),
            _edge(
                SolidityGraphKind.PRIVILEGE,
                "function:Vault.adminSet",
                "role:admin",
                "administrator guarded transition",
                21,
            ),
            _edge(
                SolidityGraphKind.EXTERNAL_CALL,
                "function:Vault.deposit",
                "external:token",
                "bounded synthetic token call",
                12,
            ),
            _edge(
                SolidityGraphKind.STATE_WRITE,
                "function:Vault.deposit",
                "state:Vault.totalAssets",
                "writes totalAssets",
                13,
            ),
        ]
    )
    invariants = InvariantSuite(
        invariants=[
            InvariantSpec(
                id="inv:observed-assets",
                title="Observed assets back accounting",
                category=InvariantCategory.ACCOUNTING,
                description="Recorded accounting cannot exceed locally observed assets.",
                template=InvariantTemplate.OBSERVED_ASSET_ACCOUNTING,
                locations=[
                    Location(
                        path=_PATH,
                        start_line=10,
                        end_line=14,
                        content_hash=_source_hash(10, 14),
                    )
                ],
                entity_ids=["function:Vault.deposit"],
                state_variables=["totalAssets"],
                functions=["deposit(uint256)"],
                provenance=SolidityProvenance.COMPILER,
                confidence=1,
                template_available=True,
                evidence_hash="b" * 64,
            )
        ],
        templates_available_count=1,
    )
    return index, graphs, invariants


def _usage(
    role: str,
    model_id: str,
    request_id: str,
    *,
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.REAL,
) -> UsageRecord:
    started_at = datetime.now(UTC)
    generation_id = f"generation-{request_id}"
    schema_sha256 = "e" * 64
    return bind_synthetic_usage_identity(
        UsageRecord(
            request_id=request_id,
            role=role,
            execution_evidence=execution_evidence,
            requested_model=model_id,
            returned_model=model_id,
            actual_model=model_id,
            provider="approved-provider",
            model_family=model_id.split("/", 1)[0],
            timestamp=started_at,
            prompt_tokens=100,
            completion_tokens=20,
            total_tokens=120,
            reported_cost_usd=0.01,
            accounted_cost_usd=0.01,
            routing={
                "generation_id": generation_id,
                "selected_model": model_id,
                "canonical_model": model_id,
                "selected_provider_endpoint": "approved-provider",
                "selected_provider_name": "approved-provider",
                "router_strategy": "direct",
                "finish_reason": "stop",
                "schema_sha256": schema_sha256,
                "router_metadata_sha256": "f" * 64,
                "provider_policy_sha256": "0" * 64,
                "validation_status": "valid",
                "zdr_requested": True,
                "data_collection": "deny",
                "repair_used": False,
                "repair_request": False,
                "request_started_at": started_at.isoformat(),
                "request_ended_at": started_at.isoformat(),
                "latency_ms": 0,
            },
            prompt_sha256="c" * 64,
            response_sha256="d" * 64,
            validated_response_sha256="f" * 64,
            request_body_sha256="a" * 64,
            schema_sha256=schema_sha256,
            openrouter_generation_id=generation_id,
            configured_provider_endpoints=["approved-provider"],
            actual_provider_endpoint="approved-provider",
            started_at=started_at,
            ended_at=started_at,
            latency_ms=0,
            finish_reason="stop",
            retry_count=0,
            validation_status=ModelRequestValidationStatus.VALID,
            status="success",
            attempts=1,
        )
    )


def _record(
    request: ModelSurfaceReviewRequest,
    role: str,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet,
    *,
    status: ModelSurfaceReviewStatus = ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
) -> ModelSurfaceReviewRecord:
    entities = {entity.id: entity for entity in index.entities}
    subject = entities.get(request.subject_id)
    entry = next(
        entity
        for entity in index.entities
        if entity.kind is SolidityEntityKind.FUNCTION
        and entity.visibility in {"public", "external"}
        and entity.name == "deposit"
    )
    entry_citation = _entity_citation(entry)
    if subject is not None and subject.kind is SolidityEntityKind.FUNCTION:
        citation = _entity_citation(subject)
        path = (citation,)
    elif subject is not None and subject.kind in {
        SolidityEntityKind.CONTRACT,
        SolidityEntityKind.STATE_VARIABLE,
    }:
        citation = _entity_citation(subject)
        path = (entry_citation, citation)
    elif request.kind is ModelReviewSurfaceKind.CALL:
        citation = ModelSurfaceReviewCitation(location=request.allowed_locations[0])
        path = (entry_citation, citation)
    else:
        state = entities["state:Vault.totalAssets"]
        citation = ModelSurfaceReviewCitation(symbol=state.name)
        path = (entry_citation, citation)
    anchor = citation.symbol or request.contract
    return ModelSurfaceReviewRecord(
        surface_id=request.surface_id,
        contract=request.contract,
        function_or_state_surface=request.function_or_state_surface,
        review_role=role,
        status=status,
        rationale="The named invariant and reachable state transition were reviewed.",
        citation=citation,
        invariant_considered=request.invariant_considered,
        evidence_observations=(
            ModelSurfaceReviewEvidenceObservation(
                citation=citation,
                observed_behavior=f"{anchor} writes or checks its deterministic source state.",
                security_relevance=(
                    f"{anchor} preserves the requested asset or authorization invariant."
                ),
            ),
        ),
        reachability=ModelSurfaceReviewReachability(
            entry_point=path[0],
            path=path,
            actor_or_caller="authorized synthetic caller",
            preconditions=(),
        ),
        assumptions=(),
        confidence=0.9,
    )


def _entity_citation(entity: SolidityEntity) -> ModelSurfaceReviewCitation:
    return ModelSurfaceReviewCitation(
        location=Location(
            path=entity.path,
            start_line=entity.start_line,
            end_line=entity.end_line,
            symbol=entity.signature or entity.name,
            content_hash=entity.source_hash,
        ),
        symbol=entity.signature or entity.name,
    )


def _artifact(
    requests: list[ModelSurfaceReviewRequest],
    usage: UsageRecord,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet,
    *,
    status: ModelSurfaceReviewStatus = ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
    manifest_sha256: str | None = None,
    context: ContextPackage | None = None,
) -> ModelSurfaceReviewArtifact:
    records = tuple(
        _record(
            request,
            usage.role,
            index,
            graphs,
            status=status,
        )
        for request in requests
    )
    ids = tuple(request.surface_id for request in requests)
    review_context = context or _review_context(requests, usage, index, graphs)
    payload = {
        "schema_version": "1.0",
        "request_id": usage.request_id,
        "review_role": usage.role,
        "requested_surface_ids": list(ids),
        "requested_surface_ids_sha256": hashlib.sha256(
            json.dumps(
                list(ids),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        ).hexdigest(),
        "requested_surface_manifest_sha256": manifest_sha256
        or ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(requests),
        "rendered_context_sha256": hashlib.sha256(
            render_context(review_context).encode()
        ).hexdigest(),
        "prompt_sha256": usage.prompt_sha256,
        "response_sha256": usage.response_sha256,
        "validated_response_sha256": usage.validated_response_sha256,
        "response_schema_sha256": usage.schema_sha256,
        "records": [record.model_dump(mode="json") for record in records],
    }
    payload["artifact_sha256"] = ModelSurfaceReviewArtifact.calculate_artifact_sha256(payload)
    return ModelSurfaceReviewArtifact.model_validate(payload)


def _replace_artifact_record(
    artifact: ModelSurfaceReviewArtifact,
    record: ModelSurfaceReviewRecord,
) -> ModelSurfaceReviewArtifact:
    payload = artifact.model_dump(mode="json")
    payload["records"] = [record.model_dump(mode="json")]
    payload["artifact_sha256"] = ModelSurfaceReviewArtifact.calculate_artifact_sha256(payload)
    return ModelSurfaceReviewArtifact.model_validate(payload)


def _review_context(
    requests: list[ModelSurfaceReviewRequest],
    usage: UsageRecord,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet,
    *,
    excerpts: list[ContextExcerpt] | None = None,
) -> ContextPackage:
    source_excerpt = ContextExcerpt(
        path=_PATH,
        start_line=1,
        end_line=len(_SOURCE.splitlines()),
        content_hash=hashlib.sha256(_SOURCE.encode()).hexdigest(),
        content=_SOURCE,
    )
    selected_excerpts = [source_excerpt] if excerpts is None else excerpts
    return ContextPackage(
        role=usage.role,
        byte_budget=100_000,
        bytes_used=sum(len(excerpt.content.encode()) for excerpt in selected_excerpts),
        repository_map=RepositoryMap(
            root_name="synthetic-model-coverage",
            languages={"Solidity": 1},
            frameworks=[],
            manifests=[],
            entry_points=[],
            api_surfaces=[],
            auth_components=[],
            data_layers=[],
            network_clients=[],
            file_handlers=[],
            configuration_files=[],
            sensitive_processing=[],
            security_tests=[],
            files=[],
        ),
        scanner_findings=[],
        excerpts=selected_excerpts,
        requested_model_surfaces=requests,
        solidity_index=index,
        solidity_graphs=graphs,
    )


def _review_contexts(
    requests: list[ModelSurfaceReviewRequest],
    usages: list[UsageRecord],
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet,
) -> dict[str, list[ContextPackage]]:
    result: dict[str, list[ContextPackage]] = {}
    for usage in usages:
        context = _review_context(requests, usage, index, graphs)
        _bind_usage_to_context(usage, context)
        result[usage.request_id] = [context]
    return result


def _bind_usage_to_context(usage: UsageRecord, context: ContextPackage) -> None:
    usage.user_prompt_sha256 = hashlib.sha256(render_context(context).encode()).hexdigest()
    reattest_synthetic_real_usage(usage)


def _requests() -> tuple[
    SoliditySymbolIndex,
    SolidityGraphSet,
    InvariantSuite,
    list[ModelSurfaceReviewRequest],
]:
    index, graphs, invariants = _inventory()
    requests = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )
    return index, graphs, invariants, requests


def test_surface_requests_cover_full_deterministic_inventory() -> None:
    _, _, _, requests = _requests()

    assert len(requests) == 9
    assert requests == sorted(requests, key=lambda request: request.surface_id)
    assert set(request.kind for request in requests) == set(ModelReviewSurfaceKind)
    assert all(
        request.contract
        and request.function_or_state_surface
        and (request.allowed_locations or request.allowed_symbols)
        and request.invariant_considered
        for request in requests
    )


def test_surface_request_plan_distributes_critical_surfaces_across_lineages(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    _, _, _, requests = _requests()

    assignments = plan_model_surface_review_assignments(config, requests)

    assigned_roles = {
        request.surface_id: [
            role for role, role_requests in assignments.items() if request in role_requests
        ]
        for request in requests
    }
    assert all(
        len(assigned_roles[request.surface_id]) == (3 if request.critical else 1)
        for request in requests
    )
    assert all(
        role_requests == sorted(role_requests, key=lambda item: item.surface_id)
        for role_requests in assignments.values()
    )


def test_surface_request_plan_excludes_unapproved_lineage(
    config_factory: Callable[..., AuditConfig],
) -> None:
    base = config_factory()
    excluded = next(
        entry.root_lineage
        for entry in base.models.registry
        if entry.canonical_model_id == base.models.configuration.primary
    )
    approved = tuple(
        lineage for lineage in base.privacy.approved_model_lineages if lineage != excluded
    )
    config = base.model_copy(
        update={"privacy": base.privacy.model_copy(update={"approved_model_lineages": approved})}
    )
    _, _, _, requests = _requests()

    assignments = plan_model_surface_review_assignments(config, requests)

    for request in requests:
        assigned = sum(request in role_requests for role_requests in assignments.values())
        assert assigned == (2 if request.critical else 1)


def test_context_delivery_or_successful_usage_without_response_earns_no_credit(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, _ = _requests()
    usage = _usage("source_audit", config.models.source_audit.primary, "request-context-only")

    coverage = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[],
        review_contexts_by_request={},
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    assert coverage.overall.denominator == 9
    assert coverage.overall.numerator == 0
    assert all(not surface.evidence_references for surface in coverage.surfaces)
    assert not coverage.critical_gate_passed


def test_three_independent_response_lineages_cover_critical_surfaces(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    usages = [
        _usage("source_audit", config.models.source_audit.primary, "request-1"),
        _usage("business_logic", config.models.business_logic.primary, "request-2"),
        _usage("configuration", config.models.configuration.primary, "request-3"),
    ]

    coverage = build_model_review_coverage(
        config,
        usage_records=usages,
        review_artifacts=[_artifact(requests, usage, index, graphs) for usage in usages],
        review_contexts_by_request=_review_contexts(requests, usages, index, graphs),
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    assert coverage.overall.numerator == coverage.overall.denominator == 9
    assert coverage.critical.numerator == coverage.critical.denominator == 9
    assert coverage.critical_gate_passed
    assert all(len(surface.root_lineages) == 3 for surface in coverage.surfaces)
    assert all(len(surface.evidence_references) == 3 for surface in coverage.surfaces)
    assert ModelReviewCoverage.model_validate_json(coverage.model_dump_json()) == coverage


def test_direct_entry_and_graph_adjacent_state_records_receive_credit(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    selected = sorted(
        (
            next(
                request
                for request in requests
                if request.kind is ModelReviewSurfaceKind.ENTRY_POINT
            ),
            next(request for request in requests if request.kind is ModelReviewSurfaceKind.STATE),
        ),
        key=lambda request: request.surface_id,
    )
    usage = _usage("source_audit", config.models.source_audit.primary, "request-direct-state")

    coverage = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[_artifact(selected, usage, index, graphs)],
        review_contexts_by_request=_review_contexts(selected, [usage], index, graphs),
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    by_id = {surface.surface_id: surface for surface in coverage.surfaces}
    assert all(by_id[request.surface_id].reviewed for request in selected)


def test_compact_source_context_inventory_subset_receives_credit(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    selected = sorted(
        (
            next(
                request
                for request in requests
                if request.kind is ModelReviewSurfaceKind.ENTRY_POINT
                and request.function_or_state_surface == "deposit(uint256)"
            ),
            next(request for request in requests if request.kind is ModelReviewSurfaceKind.STATE),
        ),
        key=lambda request: request.surface_id,
    )
    usage = _usage("source_audit", config.models.source_audit.primary, "request-compact-context")
    context = _review_context(selected, usage, index, graphs)
    compact_index = index.model_copy(
        update={
            "entities": [
                entity
                for entity in index.entities
                if entity.id in {"function:Vault.deposit", "state:Vault.totalAssets"}
            ]
        }
    )
    compact_graphs = graphs.model_copy(
        update={
            "edges": [edge for edge in graphs.edges if edge.graph is SolidityGraphKind.STATE_WRITE]
        }
    )
    context = context.model_copy(
        update={
            "solidity_index": compact_index,
            "solidity_graphs": compact_graphs,
        }
    )
    _bind_usage_to_context(usage, context)

    coverage = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[_artifact(selected, usage, index, graphs, context=context)],
        review_contexts_by_request={usage.request_id: [context]},
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    by_id = {surface.surface_id: surface for surface in coverage.surfaces}
    assert all(by_id[request.surface_id].reviewed for request in selected)


def test_missing_or_duplicate_source_context_cannot_authorize_coverage(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    request = next(
        request for request in requests if request.kind is ModelReviewSurfaceKind.ENTRY_POINT
    )
    usage = _usage("source_audit", config.models.source_audit.primary, "request-context-join")
    artifact = _artifact([request], usage, index, graphs)
    context = _review_context([request], usage, index, graphs)
    _bind_usage_to_context(usage, context)

    missing = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[artifact],
        review_contexts_by_request={},
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )
    duplicate = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[artifact],
        review_contexts_by_request={usage.request_id: [context, context]},
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    missing_surface = next(
        surface for surface in missing.surfaces if surface.surface_id == request.surface_id
    )
    duplicate_surface = next(
        surface for surface in duplicate.surfaces if surface.surface_id == request.surface_id
    )
    assert not missing_surface.reviewed
    assert "no source review context matched" in missing_surface.evidence_references[0].reason
    assert not duplicate_surface.reviewed
    assert (
        "did not join exactly one source review context"
        in duplicate_surface.evidence_references[0].reason
    )


def test_post_hoc_context_substitution_cannot_authorize_coverage(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    request = next(
        request for request in requests if request.kind is ModelReviewSurfaceKind.ENTRY_POINT
    )
    usage = _usage("source_audit", config.models.source_audit.primary, "request-context-binding")
    original_context = _review_context([request], usage, index, graphs)
    _bind_usage_to_context(usage, original_context)
    artifact = _artifact(
        [request],
        usage,
        index,
        graphs,
        context=original_context,
    )
    substituted_context = original_context.model_copy(
        update={
            "omissions": [
                ContextOmissionItem.build(
                    category=ContextOmissionCategory.CONTEXT_PACKAGE,
                    reason=ContextOmissionReason.CONTEXT_BUDGET_EXCLUDED,
                    omitted_item_sha256=hashlib.sha256(
                        b"post-hoc context differs from the provider request"
                    ).hexdigest(),
                )
            ]
        }
    )

    coverage = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[artifact],
        review_contexts_by_request={usage.request_id: [substituted_context]},
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    surface = next(
        surface for surface in coverage.surfaces if surface.surface_id == request.surface_id
    )
    assert not surface.reviewed
    assert (
        "context hash differed from the rendered provider request"
        in surface.evidence_references[0].reason
    )


def test_serialized_generic_state_self_loop_cannot_self_authorize_coverage(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    state_request = next(
        request for request in requests if request.kind is ModelReviewSurfaceKind.STATE
    )
    usage = _usage("source_audit", config.models.source_audit.primary, "request-generic-loop")
    artifact = _artifact([state_request], usage, index, graphs)
    valid = artifact.records[0]
    assert valid.reachability is not None
    generic_observation = valid.evidence_observations[0].model_copy(
        update={
            "observed_behavior": (
                "The synthetic source surface was inspected for its state effects."
            ),
            "security_relevance": (
                "Those effects determine whether the supplied invariant is preserved."
            ),
        }
    )
    generic_loop = valid.model_copy(
        update={
            "evidence_observations": (generic_observation,),
            "reachability": valid.reachability.model_copy(
                update={
                    "entry_point": valid.citation,
                    "path": (valid.citation,),
                }
            ),
        }
    )
    artifact = _replace_artifact_record(artifact, generic_loop)

    coverage = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[artifact],
        review_contexts_by_request=_review_contexts(
            [state_request],
            [usage],
            index,
            graphs,
        ),
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    state_surface = next(
        surface for surface in coverage.surfaces if surface.surface_id == state_request.surface_id
    )
    assert not state_surface.reviewed
    assert len(state_surface.evidence_references) == 1
    reason = state_surface.evidence_references[0].reason
    assert "generic boilerplate" in reason
    assert "exact known" in reason


def test_serialized_record_role_mismatch_cannot_self_authorize_coverage(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    request = next(
        request for request in requests if request.kind is ModelReviewSurfaceKind.ENTRY_POINT
    )
    usage = _usage("source_audit", config.models.source_audit.primary, "request-record-role")
    artifact = _artifact([request], usage, index, graphs)
    mismatched = artifact.records[0].model_copy(update={"review_role": "business_logic"})
    payload = artifact.model_dump(mode="json")
    payload["records"] = [mismatched.model_dump(mode="json")]
    tampered = artifact.model_copy(
        update={
            "records": (mismatched,),
            "artifact_sha256": ModelSurfaceReviewArtifact.calculate_artifact_sha256(payload),
        }
    )

    coverage = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[tampered],
        review_contexts_by_request=_review_contexts([request], [usage], index, graphs),
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    surface = next(
        surface for surface in coverage.surfaces if surface.surface_id == request.surface_id
    )
    assert not surface.reviewed
    assert "record review role differed" in surface.evidence_references[0].reason


def test_mock_and_unregistered_models_are_retained_as_no_credit(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    mock = _usage(
        "source_audit",
        config.models.source_audit.primary,
        "request-mock",
        execution_evidence=ExecutionEvidenceKind.MOCK,
    )
    unknown = _usage("source_audit", "unknown/unqualified", "request-unknown")

    coverage = build_model_review_coverage(
        config,
        usage_records=[mock, unknown],
        review_artifacts=[
            _artifact(requests, mock, index, graphs),
            _artifact(requests, unknown, index, graphs),
        ],
        review_contexts_by_request=_review_contexts(
            requests,
            [mock, unknown],
            index,
            graphs,
        ),
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    assert coverage.overall.numerator == 0
    assert all(len(surface.evidence_references) == 2 for surface in coverage.surfaces)
    assert all(
        all(not reference.credited for reference in surface.evidence_references)
        for surface in coverage.surfaces
    )
    assert any("mock model usage was excluded" in item for item in coverage.limitations)
    assert any("unregistered model" in item for item in coverage.limitations)


def test_same_lineage_aliases_do_not_inflate_independence(
    config_factory: Callable[..., AuditConfig],
) -> None:
    base = config_factory()
    source = base.models.source_audit.primary
    alias = "mirror/borealis-secure"
    registry = [
        entry.model_copy(update={"aliases": (alias,)})
        if entry.canonical_model_id == source
        else entry
        for entry in base.models.registry
    ]
    config = base.model_copy(
        update={
            "models": base.models.model_copy(
                update={
                    "registry": tuple(registry),
                    "source_audit": base.models.source_audit.model_copy(
                        update={"fallbacks": [alias]}
                    ),
                }
            )
        }
    )
    index, graphs, invariants, requests = _requests()
    usages = [
        _usage("source_audit", source, "request-canonical"),
        _usage("source_audit", alias, "request-alias"),
    ]
    coverage = build_model_review_coverage(
        config,
        usage_records=usages,
        review_artifacts=[_artifact(requests, usage, index, graphs) for usage in usages],
        review_contexts_by_request=_review_contexts(requests, usages, index, graphs),
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    assert coverage.overall.numerator == coverage.overall.denominator
    assert all(len(surface.root_lineages) == 1 for surface in coverage.surfaces)
    assert coverage.critical.numerator == 0
    assert not coverage.critical_gate_passed


def test_request_manifest_or_response_hash_splice_is_not_credited(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    usage = _usage("source_audit", config.models.source_audit.primary, "request-splice")
    artifact = _artifact(
        requests,
        usage,
        index,
        graphs,
        manifest_sha256="9" * 64,
    )
    coverage = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[artifact],
        review_contexts_by_request=_review_contexts(requests, [usage], index, graphs),
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    assert coverage.overall.numerator == 0
    assert all(
        "manifest hash was inconsistent" in surface.evidence_references[0].reason
        for surface in coverage.surfaces
    )


def test_inconclusive_and_not_reviewed_records_are_explicit_no_credit(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    usages = [
        _usage("source_audit", config.models.source_audit.primary, "request-inconclusive"),
        _usage("business_logic", config.models.business_logic.primary, "request-not-reviewed"),
    ]
    artifacts = [
        _artifact(
            requests,
            usages[0],
            index,
            graphs,
            status=ModelSurfaceReviewStatus.INCONCLUSIVE,
        ),
        _artifact(
            requests,
            usages[1],
            index,
            graphs,
            status=ModelSurfaceReviewStatus.NOT_REVIEWED,
        ),
    ]
    coverage = build_model_review_coverage(
        config,
        usage_records=usages,
        review_artifacts=artifacts,
        review_contexts_by_request=_review_contexts(requests, usages, index, graphs),
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    assert coverage.overall.numerator == 0
    assert {reference.status for reference in coverage.surfaces[0].evidence_references} == {
        ModelSurfaceReviewStatus.INCONCLUSIVE,
        ModelSurfaceReviewStatus.NOT_REVIEWED,
    }


def test_role_mismatch_is_not_credited_and_gate_fails(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    usage = _usage("source_audit", config.models.source_audit.primary, "request-role")
    artifact = _artifact(
        requests,
        usage,
        index,
        graphs,
    ).model_copy(update={"review_role": "verifier"})
    coverage = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[artifact],
        review_contexts_by_request=_review_contexts(requests, [usage], index, graphs),
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    assert coverage.overall.numerator == 0
    assert all(
        "not an allowed investigator role" in surface.evidence_references[0].reason
        for surface in coverage.surfaces
    )
    gate = model_review_critical_surface_gate(coverage, required=True)
    assert gate.required and not gate.passed
