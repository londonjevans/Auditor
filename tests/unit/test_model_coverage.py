from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from mmaudit.config import AuditConfig
from mmaudit.models.schemas import (
    AnalysisState,
    AuditedSuiteAssertionStatus,
    AuditedSuiteCoverage,
    AuditedSuiteCoverageGap,
    AuditedSuiteCoverageGapKind,
    AuditedSuiteStatementStatus,
    AuditedSuiteSurfaceCoverage,
    AuditProfile,
    ContextExcerpt,
    ContextPackage,
    CoverageMetric,
    CoverageProvenance,
    EconomicSimulationKind,
    EconomicSimulationPlan,
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
    ModelSurfaceReviewPriority,
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
    model_surface_assignment_feasibility_gate,
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
    end_line: int | None = None,
) -> SolidityGraphEdge:
    bounded_end = line if end_line is None else end_line
    return SolidityGraphEdge(
        graph=graph,
        source_id=source_id,
        target_id=target_id,
        label=label,
        provenance=SolidityProvenance.COMPILER,
        path=_PATH,
        start_line=line,
        end_line=bounded_end,
        source_hash=_source_hash(line, bounded_end),
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
                10,
                11,
            ),
            _edge(
                SolidityGraphKind.PRIVILEGE,
                "function:Vault.adminSet",
                "role:admin",
                "administrator guarded transition",
                20,
                21,
            ),
            _edge(
                SolidityGraphKind.EXTERNAL_CALL,
                "function:Vault.deposit",
                "external:token",
                "bounded synthetic token call",
                10,
                11,
            ),
            _edge(
                SolidityGraphKind.STATE_WRITE,
                "function:Vault.deposit",
                "state:Vault.totalAssets",
                "writes totalAssets",
                10,
                11,
            ),
        ],
        analyzed_graphs=[
            SolidityGraphKind.PRIVILEGE,
            SolidityGraphKind.ASSET_FLOW,
            SolidityGraphKind.SENSITIVE_REACHABILITY,
        ],
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
                        end_line=11,
                        symbol="deposit(uint256)",
                        content_hash=_source_hash(10, 11),
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


def _audited_gap_coverage(
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet,
    invariants: InvariantSuite,
    *,
    force_critical_ids: set[str] | None = None,
) -> AuditedSuiteCoverage:
    entity_kinds = {
        SolidityEntityKind.CONTRACT,
        SolidityEntityKind.INTERFACE,
        SolidityEntityKind.LIBRARY,
        SolidityEntityKind.FUNCTION,
        SolidityEntityKind.CONSTRUCTOR,
    }
    entities = sorted(
        (entity for entity in index.entities if entity.kind in entity_kinds),
        key=lambda entity: entity.id,
    )
    base_requests = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )
    critical_ids = {request.subject_id for request in base_requests if request.critical} | (
        force_critical_ids or set()
    )
    surfaces: list[AuditedSuiteSurfaceCoverage] = []
    gaps: list[AuditedSuiteCoverageGap] = []
    for entity in entities:
        location = Location(
            path=entity.path,
            start_line=entity.start_line,
            end_line=entity.end_line,
            symbol=entity.signature or entity.name,
            content_hash=entity.source_hash,
        )
        critical = entity.id in critical_ids
        surfaces.append(
            AuditedSuiteSurfaceCoverage(
                entity_id=entity.id,
                entity_kind=entity.kind,
                contract_name=entity.contract_name or entity.name,
                location=location,
                critical=critical,
                statement_status=AuditedSuiteStatementStatus.NOT_ANALYZED,
                assertion_status=AuditedSuiteAssertionStatus.NOT_ANALYZED,
            )
        )
        if critical:
            gap_kind = AuditedSuiteCoverageGapKind.ASSERTION_NOT_ANALYZED
            gaps.append(
                AuditedSuiteCoverageGap(
                    gap_id=AuditedSuiteCoverageGap.calculate_gap_id(entity.id, gap_kind),
                    entity_id=entity.id,
                    entity_kind=entity.kind,
                    location=location,
                    kind=gap_kind,
                    assertion_status=AuditedSuiteAssertionStatus.NOT_ANALYZED,
                    detail=(
                        "The audited repository suite has no assertion-strength evidence "
                        "for this surface."
                    ),
                )
            )

    contract_count = sum(
        surface.entity_kind
        in {
            SolidityEntityKind.CONTRACT,
            SolidityEntityKind.INTERFACE,
            SolidityEntityKind.LIBRARY,
        }
        for surface in surfaces
    )
    function_count = sum(
        surface.entity_kind
        in {
            SolidityEntityKind.FUNCTION,
            SolidityEntityKind.CONSTRUCTOR,
        }
        for surface in surfaces
    )
    critical_surface_count = len(gaps)

    def uncovered_metric(denominator: int, detail: str) -> CoverageMetric:
        return CoverageMetric(
            numerator=0,
            denominator=denominator,
            population=denominator,
            percentage=0 if denominator else None,
            exclusions=[],
            not_applicable_evidence=(
                ["no exact surface exists in this focused fixture"] if not denominator else []
            ),
            confidence=1,
            provenance=[CoverageProvenance.RUNTIME],
            failures=(["the exact surfaces lack runtime coverage evidence"] if denominator else []),
            state=AnalysisState.NOT_ANALYZED,
            detail=detail,
        )

    return AuditedSuiteCoverage(
        contract_statement_coverage=uncovered_metric(
            contract_count,
            "Focused audited-suite contract coverage fixture.",
        ),
        function_statement_coverage=uncovered_metric(
            function_count,
            "Focused audited-suite function coverage fixture.",
        ),
        critical_function_assertion_coverage=uncovered_metric(
            critical_surface_count,
            "Focused audited-suite assertion coverage fixture.",
        ),
        surfaces=surfaces,
        gaps=sorted(gaps, key=lambda gap: (gap.entity_id, gap.kind.value)),
        source_classification_complete=True,
        critical_classification_complete=True,
    )


def _with_false_negative_hunter(config: AuditConfig) -> AuditConfig:
    models = config.models.model_copy(
        update={
            "specialists": {
                **config.models.specialists,
                "false_negative_hunter": config.models.threat_model,
            }
        }
    )
    return config.model_copy(update={"models": models})


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
    package = ContextPackage(
        role=usage.role,
        byte_budget=100_000,
        bytes_used=0,
        configured_maximum_source_tokens_per_request=200_000,
        effective_source_byte_ceiling=100_000,
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
    return _with_exact_context_bytes(package)


def _with_exact_context_bytes(context: ContextPackage) -> ContextPackage:
    return context.model_copy(update={"bytes_used": len(render_context(context).encode("utf-8"))})


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


def _requests_with_audited_coverage() -> tuple[
    SoliditySymbolIndex,
    SolidityGraphSet,
    InvariantSuite,
    AuditedSuiteCoverage,
    list[ModelSurfaceReviewRequest],
]:
    index, graphs, invariants = _inventory()
    audited_suite = _audited_gap_coverage(index, graphs, invariants)
    requests = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )
    return index, graphs, invariants, audited_suite, requests


def test_surface_requests_cover_full_deterministic_inventory() -> None:
    _, _, _, requests = _requests()

    assert len(requests) == 9
    assert requests == sorted(requests, key=lambda request: request.surface_id)
    assert set(request.kind for request in requests) == (
        set(ModelReviewSurfaceKind) - {ModelReviewSurfaceKind.INTERNAL_FUNCTION}
    )
    assert all(
        request.contract
        and request.function_or_state_surface
        and (request.allowed_locations or request.allowed_symbols)
        and request.invariant_considered
        for request in requests
    )


def test_exact_critical_gap_elevates_only_its_surfaces_without_changing_ids() -> None:
    index, graphs, invariants = _inventory()
    audited_suite = _audited_gap_coverage(index, graphs, invariants)
    baseline = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )
    prioritized = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )

    assert [request.surface_id for request in prioritized] == [
        request.surface_id for request in baseline
    ]
    elevated = [
        request
        for request in prioritized
        if request.priority is ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP
    ]
    assert {request.kind for request in elevated} == {
        ModelReviewSurfaceKind.CONTRACT,
        ModelReviewSurfaceKind.ENTRY_POINT,
        ModelReviewSurfaceKind.PRIVILEGE_FUNCTION,
        ModelReviewSurfaceKind.ASSET_FUNCTION,
    }
    assert {request.subject_id for request in elevated} == {
        "contract:Vault",
        "function:Vault.adminSet",
        "function:Vault.deposit",
    }
    gap_ids_by_entity = {gap.entity_id: (gap.gap_id,) for gap in audited_suite.gaps}
    assert all(
        request.coverage_gap_ids == gap_ids_by_entity[request.subject_id] for request in elevated
    )
    assert all(
        request.priority is ModelSurfaceReviewPriority.STANDARD and not request.coverage_gap_ids
        for request in prioritized
        if request.subject_id not in gap_ids_by_entity
    )


def test_invariant_only_internal_function_receives_an_elevated_review_surface() -> None:
    index, graphs, invariants = _inventory()
    internal = _entity(
        "function:Vault.internalInvariant",
        SolidityEntityKind.FUNCTION,
        "internalInvariant",
        30,
        visibility="internal",
        signature="internalInvariant()",
    )
    index = index.model_copy(update={"entities": [*index.entities, internal]})
    invariant = InvariantSpec(
        id="inv:internal-transition",
        title="Internal transition preserves accounting",
        category=InvariantCategory.ACCOUNTING,
        description="The internal transition preserves the declared accounting boundary.",
        locations=[
            Location(
                path=internal.path,
                start_line=internal.start_line,
                end_line=internal.end_line,
                symbol=internal.signature,
                content_hash=internal.source_hash,
            )
        ],
        entity_ids=[internal.id],
        functions=[internal.signature or internal.name],
        provenance=SolidityProvenance.COMPILER,
        confidence=1,
        template_available=False,
        evidence_hash="c" * 64,
    )
    invariants = invariants.model_copy(update={"invariants": [*invariants.invariants, invariant]})
    audited_suite = _audited_gap_coverage(index, graphs, invariants)

    requests = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )

    internal_requests = [request for request in requests if request.subject_id == internal.id]
    assert len(internal_requests) == 1
    assert internal_requests[0].kind is ModelReviewSurfaceKind.INTERNAL_FUNCTION
    assert internal_requests[0].critical
    assert internal_requests[0].priority is ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP
    assert internal_requests[0].coverage_gap_ids


def test_direct_and_location_bound_invariants_make_exact_contract_surfaces_critical(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, _ = _inventory()
    contract = next(entity for entity in index.entities if entity.id == "contract:Vault")
    admin = next(entity for entity in index.entities if entity.id == "function:Vault.adminSet")
    state = next(entity for entity in index.entities if entity.id == "state:Vault.totalAssets")
    graphs = graphs.model_copy(
        update={
            "edges": [edge for edge in graphs.edges if edge.graph is SolidityGraphKind.STATE_WRITE]
        }
    )

    def invariant(
        invariant_id: str,
        *,
        entity_ids: list[str],
        location: Location,
    ) -> InvariantSpec:
        return InvariantSpec(
            id=invariant_id,
            title=f"Exact binding for {invariant_id}",
            category=InvariantCategory.STATE_MACHINE,
            description="The exact audited contract and state transition remain consistent.",
            locations=[location],
            entity_ids=entity_ids,
            state_variables=[state.name],
            functions=[admin.signature or admin.name],
            provenance=SolidityProvenance.COMPILER,
            confidence=1,
            template_available=False,
            evidence_hash=hashlib.sha256(invariant_id.encode()).hexdigest(),
        )

    invariants = InvariantSuite(
        invariants=[
            invariant(
                "inv:direct-contract",
                entity_ids=[contract.id],
                location=_entity_citation(contract).location,
            ),
            invariant(
                "inv:direct-state",
                entity_ids=[state.id],
                location=_entity_citation(state).location,
            ),
            invariant(
                "inv:location-function",
                entity_ids=[],
                location=_entity_citation(admin).location,
            ),
        ]
    )
    audited_suite = _audited_gap_coverage(index, graphs, invariants)
    requests = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )
    contract_request = next(
        request
        for request in requests
        if request.kind is ModelReviewSurfaceKind.CONTRACT and request.subject_id == contract.id
    )
    state_request = next(
        request
        for request in requests
        if request.kind is ModelReviewSurfaceKind.STATE and request.subject_id == state.id
    )
    location_request = next(
        request
        for request in requests
        if request.kind is ModelReviewSurfaceKind.ENTRY_POINT and request.subject_id == admin.id
    )
    assert contract_request.critical
    assert state_request.critical
    assert location_request.critical

    usages = [
        _usage("source_audit", config.models.source_audit.primary, "request-contract-1"),
        _usage("business_logic", config.models.business_logic.primary, "request-contract-2"),
        _usage("configuration", config.models.configuration.primary, "request-contract-3"),
    ]
    one_lineage = build_model_review_coverage(
        config,
        usage_records=usages[:1],
        review_artifacts=[_artifact(requests, usages[0], index, graphs)],
        review_contexts_by_request=_review_contexts(requests, usages[:1], index, graphs),
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )
    one_contract = next(
        surface
        for surface in one_lineage.surfaces
        if surface.surface_id == contract_request.surface_id
    )
    assert len(one_contract.root_lineages) == 1
    assert not one_lineage.critical_gate_passed

    three_lineages = build_model_review_coverage(
        config,
        usage_records=usages,
        review_artifacts=[_artifact(requests, usage, index, graphs) for usage in usages],
        review_contexts_by_request=_review_contexts(requests, usages, index, graphs),
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )
    assert three_lineages.critical_gate_passed


def test_coverage_gap_priority_rejects_wrong_location_hash_and_unknown_entity() -> None:
    index, graphs, invariants = _inventory()
    admin = next(entity for entity in index.entities if entity.id == "function:Vault.adminSet")
    wrong_location = admin.model_copy(
        update={
            "start_line": admin.start_line + 1,
            "end_line": admin.end_line + 1,
        }
    )
    wrong_hash = admin.model_copy(update={"source_hash": "f" * 64})
    unknown = admin.model_copy(update={"id": "function:Vault.unknown"})

    for forged_entity in (wrong_location, wrong_hash, unknown):
        forged_entities = [
            forged_entity if entity.id == admin.id else entity for entity in index.entities
        ]
        forged_index = index.model_copy(update={"entities": forged_entities})
        with pytest.raises(ValueError, match="audited-suite coverage"):
            build_model_surface_requests(
                index=index,
                graphs=graphs,
                invariants=invariants,
                economic_simulations=[],
                audited_suite_coverage=_audited_gap_coverage(
                    forged_index,
                    graphs,
                    invariants,
                    force_critical_ids={forged_entity.id},
                ),
            )


def test_coverage_gap_priority_rejects_noncritical_and_mutated_typed_evidence(
    config_factory: Callable[..., AuditConfig],
) -> None:
    index, graphs, invariants = _inventory()
    ordinary = _entity(
        "function:Vault.viewValue",
        SolidityEntityKind.FUNCTION,
        "viewValue",
        24,
        visibility="external",
        signature="viewValue()",
    )
    extended_index = index.model_copy(update={"entities": [*index.entities, ordinary]})
    with pytest.raises(ValueError, match="identity or criticality"):
        build_model_surface_requests(
            index=extended_index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            audited_suite_coverage=_audited_gap_coverage(
                extended_index,
                graphs,
                invariants,
                force_critical_ids={ordinary.id},
            ),
        )

    mutated = _audited_gap_coverage(index, graphs, invariants)
    object.__setattr__(mutated.gaps[0], "gap_id", "audited-suite-gap:" + ("f" * 64))
    with pytest.raises(ValueError, match="coverage gap ID"):
        build_model_review_coverage(
            config_factory(),
            usage_records=[],
            review_artifacts=[],
            review_contexts_by_request={},
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            audited_suite_coverage=mutated,
        )


def test_partial_audited_suite_population_cannot_authorize_review_priority() -> None:
    index, graphs, invariants = _inventory()
    partial_index = index.model_copy(
        update={
            "entities": [
                entity for entity in index.entities if entity.id != "function:Vault.adminSet"
            ]
        }
    )
    partial_coverage = _audited_gap_coverage(partial_index, graphs, invariants)

    with pytest.raises(ValueError, match="surface population"):
        build_model_surface_requests(
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            audited_suite_coverage=partial_coverage,
        )


def test_planner_and_gate_reject_caller_authored_priority_and_criticality(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _with_false_negative_hunter(config_factory(profile=AuditProfile.DEEP))
    index, graphs, invariants = _inventory()
    audited_suite = _audited_gap_coverage(index, graphs, invariants)
    requests = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )
    target_index = next(position for position, request in enumerate(requests) if request.critical)
    target = requests[target_index]
    forged_gap_request = ModelSurfaceReviewRequest.model_validate(
        {
            **target.model_dump(mode="python"),
            "priority": ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP,
            "coverage_gap_ids": ("audited-suite-gap:" + ("f" * 64),),
        }
    )
    downgraded_request = target.model_copy(update={"critical": False})

    for forged_request in (forged_gap_request, downgraded_request):
        forged_requests = list(requests)
        forged_requests[target_index] = forged_request
        with pytest.raises(ValueError, match="authoritative source inventory"):
            plan_model_surface_review_assignments(
                config,
                forged_requests,
                index=index,
                graphs=graphs,
                invariants=invariants,
                economic_simulations=[],
                audited_suite_coverage=audited_suite,
            )
        gate = model_surface_assignment_feasibility_gate(
            config,
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            audited_suite_coverage=audited_suite,
            requests=forged_requests,
            assignments={"source_audit": forged_requests},
            required=True,
        )
        assert not gate.passed
        assert "failed authoritative revalidation" in gate.detail


def test_test_harness_entities_edges_and_invariants_never_enter_surface_denominator(
    config_factory: Callable[..., AuditConfig],
) -> None:
    index, graphs, invariants = _inventory()
    project = index.projects[0].model_copy(update={"test_directories": ["test"]})
    harness_contract = SolidityEntity(
        id="contract:VaultHarness",
        kind=SolidityEntityKind.CONTRACT,
        name="VaultHarness",
        path="test/VaultHarness.t.sol",
        start_line=1,
        end_line=20,
        byte_start=0,
        byte_end=20,
        source_hash="1" * 64,
        provenance=SolidityProvenance.COMPILER,
        confidence=1,
        transformation="synthetic_model_coverage_test",
    )
    harness_function = SolidityEntity(
        id="function:VaultHarness.exercise",
        kind=SolidityEntityKind.FUNCTION,
        name="exercise",
        contract_name="VaultHarness",
        path="test/VaultHarness.t.sol",
        start_line=5,
        end_line=8,
        byte_start=5,
        byte_end=8,
        source_hash="2" * 64,
        provenance=SolidityProvenance.COMPILER,
        confidence=1,
        transformation="synthetic_model_coverage_test",
        visibility="external",
        signature="exercise()",
    )
    harness_edge = SolidityGraphEdge(
        graph=SolidityGraphKind.EXTERNAL_CALL,
        source_id=harness_function.id,
        target_id="external:fixture",
        label="test-only external call",
        provenance=SolidityProvenance.COMPILER,
        path=harness_function.path,
        start_line=6,
        end_line=6,
        source_hash="3" * 64,
        confidence=1,
        transformation="synthetic_model_coverage_test",
    )
    source_id_spoofed_test_edge = harness_edge.model_copy(
        update={
            "source_id": "function:Vault.deposit",
            "label": "test-only edge spoofing a source entity ID",
        }
    )
    harness_invariant = InvariantSpec(
        id="inv:test-harness-only",
        title="Test harness helper behavior",
        category=InvariantCategory.STATE_MACHINE,
        description="Test-only helper state is never part of the audited-source denominator.",
        locations=[
            Location(
                path=harness_function.path,
                start_line=5,
                end_line=8,
                content_hash=harness_function.source_hash,
            )
        ],
        entity_ids=[harness_function.id],
        functions=[harness_function.signature or harness_function.name],
        provenance=SolidityProvenance.COMPILER,
        confidence=1,
        template_available=False,
        evidence_hash="4" * 64,
    )
    extended_index = index.model_copy(
        update={
            "projects": [project],
            "entities": [*index.entities, harness_contract, harness_function],
        }
    )
    extended_graphs = graphs.model_copy(
        update={"edges": [*graphs.edges, harness_edge, source_id_spoofed_test_edge]}
    )
    extended_invariants = invariants.model_copy(
        update={"invariants": [*invariants.invariants, harness_invariant]}
    )

    requests = build_model_surface_requests(
        index=extended_index,
        graphs=extended_graphs,
        invariants=extended_invariants,
        economic_simulations=[],
    )

    assert len(requests) == 9
    assert all(
        request.subject_id not in {harness_contract.id, harness_function.id} for request in requests
    )
    assert all(request.subject_id != harness_invariant.id for request in requests)
    assert all(
        location.path != harness_function.path
        for request in requests
        for location in request.allowed_locations
    )
    assert all(
        "test-only external call" not in request.function_or_state_surface for request in requests
    )
    assert all(
        "test-only edge spoofing" not in request.function_or_state_surface for request in requests
    )
    coverage = build_model_review_coverage(
        config_factory(),
        usage_records=[],
        review_artifacts=[],
        review_contexts_by_request={},
        index=extended_index,
        graphs=extended_graphs,
        invariants=extended_invariants,
        economic_simulations=[],
    )
    assert coverage.applicable
    assert coverage.overall.denominator == 9


def test_incomplete_source_classification_fails_request_preflight_and_coverage(
    config_factory: Callable[..., AuditConfig],
) -> None:
    index, graphs, invariants = _inventory()
    unclassified = index.model_copy(update={"projects": []})

    requests = build_model_surface_requests(
        index=unclassified,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )
    coverage = build_model_review_coverage(
        config_factory(),
        usage_records=[],
        review_artifacts=[],
        review_contexts_by_request={},
        index=unclassified,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    assert requests == []
    assert not coverage.applicable
    assert coverage.overall.denominator == 0
    assert coverage.overall.failures
    assert any("source classification incomplete" in item for item in coverage.limitations)
    assert not model_review_critical_surface_gate(coverage, required=True).passed


def test_public_model_coverage_paths_reject_incomplete_critical_classification_inputs(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants = _inventory()
    audited_suite = _audited_gap_coverage(index, graphs, invariants)
    valid_requests = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )
    assignments = plan_model_surface_review_assignments(
        config,
        valid_requests,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )
    partial_edge = next(
        edge
        for edge in graphs.edges
        if edge.graph
        in {
            SolidityGraphKind.PRIVILEGE,
            SolidityGraphKind.ASSET_FLOW,
            SolidityGraphKind.SENSITIVE_REACHABILITY,
        }
    )
    partial_graphs = graphs.model_copy(
        update={
            "edges": [
                edge.model_copy(
                    update={
                        "end_line": edge.start_line,
                        "source_hash": _source_hash(edge.start_line, edge.start_line),
                    }
                )
                if edge == partial_edge
                else edge
                for edge in graphs.edges
            ]
        }
    )
    source_contents_by_path = {_PATH: _SOURCE}
    source_bound_requests = build_model_surface_requests(
        index=index,
        graphs=partial_graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        source_contents_by_path=source_contents_by_path,
    )
    source_bound_assignments = plan_model_surface_review_assignments(
        config,
        source_bound_requests,
        index=index,
        graphs=partial_graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        source_contents_by_path=source_contents_by_path,
    )
    source_bound_coverage = build_model_review_coverage(
        config,
        usage_records=[],
        review_artifacts=[],
        review_contexts_by_request={},
        index=index,
        graphs=partial_graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        source_contents_by_path=source_contents_by_path,
    )
    source_bound_gate = model_surface_assignment_feasibility_gate(
        config,
        index=index,
        graphs=partial_graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        requests=source_bound_requests,
        assignments=source_bound_assignments,
        required=True,
        source_contents_by_path=source_contents_by_path,
    )
    assert source_bound_requests == valid_requests
    assert source_bound_coverage.critical_classification_complete
    assert source_bound_gate.passed
    assert _SOURCE not in source_bound_coverage.model_dump_json()

    with pytest.raises(ValueError, match="claims complete"):
        build_model_surface_requests(
            index=index,
            graphs=partial_graphs,
            invariants=invariants,
            economic_simulations=[],
            audited_suite_coverage=audited_suite,
            source_contents_by_path={
                _PATH: _SOURCE.replace("synthetic source line 10", "stale source line 10")
            },
        )
    stale_source_gate = model_surface_assignment_feasibility_gate(
        config,
        index=index,
        graphs=partial_graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        requests=source_bound_requests,
        assignments=source_bound_assignments,
        required=True,
        source_contents_by_path={
            _PATH: _SOURCE.replace("synthetic source line 10", "stale source line 10")
        },
    )
    assert not stale_source_gate.passed
    assert stale_source_gate.state is AnalysisState.NOT_ANALYZED
    missing_kind_graphs = graphs.model_copy(
        update={
            "analyzed_graphs": [
                kind for kind in graphs.analyzed_graphs if kind is not SolidityGraphKind.PRIVILEGE
            ]
        }
    )
    unbound_invariant = InvariantSpec(
        id="inv:unbound-symbolic",
        title="Unbound symbolic invariant",
        category=InvariantCategory.STATE_MACHINE,
        description="A symbolic name alone cannot identify exact current source.",
        functions=["deposit(uint256)"],
        provenance=SolidityProvenance.COMPILER,
        confidence=1,
        evidence_hash="4" * 64,
    )
    unbound_economic = EconomicSimulationPlan(
        kind=EconomicSimulationKind.SHARE_PRICE,
        applicable=True,
        rationale="Synthetic applicable plan without an exact audited-source binding.",
    )
    cases: list[
        tuple[
            str,
            SolidityGraphSet | None,
            InvariantSuite | None,
            list[EconomicSimulationPlan],
        ]
    ] = [
        ("missing graphs", None, invariants, []),
        ("missing invariants", graphs, None, []),
        ("missing required graph kind", missing_kind_graphs, invariants, []),
        ("unverifiable partial graph range", partial_graphs, invariants, []),
        (
            "unbound symbolic invariant",
            graphs,
            InvariantSuite(invariants=[unbound_invariant]),
            [],
        ),
        ("unbound applicable economic plan", graphs, invariants, [unbound_economic]),
    ]

    for label, case_graphs, case_invariants, economic_simulations in cases:
        with pytest.raises(ValueError, match="claims complete"):
            build_model_review_coverage(
                config,
                usage_records=[],
                review_artifacts=[],
                review_contexts_by_request={},
                index=index,
                graphs=case_graphs,
                invariants=case_invariants,
                economic_simulations=economic_simulations,
                audited_suite_coverage=audited_suite,
            )
        gate = model_surface_assignment_feasibility_gate(
            config,
            index=index,
            graphs=case_graphs,
            invariants=case_invariants,
            economic_simulations=economic_simulations,
            audited_suite_coverage=audited_suite,
            requests=valid_requests,
            assignments=assignments,
            required=True,
        )
        assert not gate.passed, label
        assert gate.state is AnalysisState.NOT_ANALYZED, label


def test_incomplete_typed_audited_suite_coverage_fails_priority_preflight(
    config_factory: Callable[..., AuditConfig],
) -> None:
    index, graphs, invariants = _inventory()
    payload = _audited_gap_coverage(index, graphs, invariants).model_dump(mode="python")
    payload.update(
        {
            "source_classification_complete": False,
            "critical_classification_complete": False,
            "limitations": [
                "critical classification incomplete: synthetic missing graph evidence",
                "source classification incomplete: synthetic missing project metadata",
            ],
        }
    )
    incomplete = AuditedSuiteCoverage.model_validate(payload)

    requests = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=incomplete,
    )
    coverage = build_model_review_coverage(
        config_factory(),
        usage_records=[],
        review_artifacts=[],
        review_contexts_by_request={},
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=incomplete,
    )
    assignments = plan_model_surface_review_assignments(
        config_factory(),
        requests,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=incomplete,
    )
    gate = model_surface_assignment_feasibility_gate(
        config_factory(),
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=incomplete,
        requests=requests,
        assignments=assignments,
        required=True,
    )

    assert requests == []
    assert assignments
    assert all(not role_requests for role_requests in assignments.values())
    assert not coverage.applicable
    assert coverage.overall.denominator == 0
    assert any("classification was incomplete" in item for item in coverage.limitations)
    assert not gate.passed
    assert "critical classification was incomplete" in gate.detail


def test_incomplete_critical_classification_preserves_base_review_but_fails_critical_gate(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants = _inventory()
    payload = _audited_gap_coverage(index, graphs, invariants).model_dump(mode="python")
    payload.update(
        {
            "critical_classification_complete": False,
            "limitations": [
                "critical classification incomplete: synthetic invariant binding mismatch"
            ],
        }
    )
    incomplete = AuditedSuiteCoverage.model_validate(payload)

    requests = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=incomplete,
    )
    coverage = build_model_review_coverage(
        config,
        usage_records=[],
        review_artifacts=[],
        review_contexts_by_request={},
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=incomplete,
    )
    assignments = plan_model_surface_review_assignments(
        config,
        requests,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=incomplete,
    )
    gate = model_surface_assignment_feasibility_gate(
        config,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=incomplete,
        requests=requests,
        assignments=assignments,
        required=True,
    )

    assert requests
    assert any(
        request.priority is ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP for request in requests
    )
    assert any(request.coverage_gap_ids for request in requests)
    assert not gate.passed
    assert gate.state is AnalysisState.NOT_ANALYZED
    assert coverage.applicable
    assert not coverage.critical_classification_complete
    assert coverage.overall.denominator == len(requests)
    assert coverage.critical.state is AnalysisState.NOT_ANALYZED
    assert not model_review_critical_surface_gate(coverage, required=True).passed


def test_incomplete_critical_classification_cannot_shrink_conservative_source_priority() -> None:
    index, graphs, invariants = _inventory()
    payload = _audited_gap_coverage(index, graphs, invariants).model_dump(mode="python")
    payload.update(
        {
            "critical_classification_complete": False,
            "limitations": [
                "critical classification incomplete: synthetic caller removed critical flags"
            ],
            "surfaces": [{**surface, "critical": False} for surface in payload["surfaces"]],
            "gaps": [],
            "critical_function_assertion_coverage": CoverageMetric(
                numerator=0,
                denominator=0,
                population=0,
                percentage=None,
                exclusions=[],
                not_applicable_evidence=[],
                confidence=1,
                provenance=[CoverageProvenance.RUNTIME],
                failures=["critical source population is caller-authored and incomplete"],
                state=AnalysisState.NOT_ANALYZED,
                detail="Synthetic malformed conservative denominator.",
            ),
        }
    )
    incomplete = AuditedSuiteCoverage.model_validate(payload)

    with pytest.raises(ValueError, match="criticality differs"):
        build_model_surface_requests(
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            audited_suite_coverage=incomplete,
        )


def test_elevated_gap_routes_to_available_hunter_and_preserves_lineage_floor(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _with_false_negative_hunter(config_factory(profile=AuditProfile.DEEP))
    index, graphs, invariants = _inventory()
    audited_suite = _audited_gap_coverage(index, graphs, invariants)
    requests = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )
    assignments = plan_model_surface_review_assignments(
        config,
        requests,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )
    elevated = [
        request
        for request in requests
        if request.priority is ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP
    ]

    assert elevated
    assert all(request in assignments["specialist:false_negative_hunter"] for request in elevated)
    assert all(
        role_requests == sorted(role_requests, key=lambda request: request.surface_id)
        for role_requests in assignments.values()
    )
    assert all(
        sum(request in role_requests for role_requests in assignments.values()) == 3
        for request in elevated
    )
    gate = model_surface_assignment_feasibility_gate(
        config,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        requests=requests,
        assignments=assignments,
        required=True,
    )
    assert gate.passed
    assert "missing_priority_assignments=0" in gate.detail
    assert "coverage_gap_hunter_available=1" in gate.detail


def test_standard_profile_routes_elevated_gaps_only_to_scheduled_base_roles(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _with_false_negative_hunter(config_factory(profile=AuditProfile.STANDARD))
    index, graphs, invariants = _inventory()
    audited_suite = _audited_gap_coverage(index, graphs, invariants)
    requests = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )
    assignments = plan_model_surface_review_assignments(
        config,
        requests,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        minimum_critical_root_lineages=1,
    )
    elevated = [
        request
        for request in requests
        if request.priority is ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP
    ]

    assert elevated
    assert set(assignments) == {"business_logic", "configuration", "source_audit"}
    assert all(
        any(request in role_requests for role_requests in assignments.values())
        for request in elevated
    )
    gate = model_surface_assignment_feasibility_gate(
        config,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        requests=requests,
        assignments=assignments,
        required=True,
        minimum_critical_root_lineages=1,
    )
    assert gate.passed
    assert "coverage_gap_hunter_available=0" in gate.detail


def test_standard_feasibility_rejects_injected_unscheduled_hunter(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _with_false_negative_hunter(config_factory(profile=AuditProfile.STANDARD))
    index, graphs, invariants = _inventory()
    audited_suite = _audited_gap_coverage(index, graphs, invariants)
    requests = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )
    assignments = plan_model_surface_review_assignments(
        config,
        requests,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        minimum_critical_root_lineages=1,
    )
    elevated = next(
        request
        for request in requests
        if request.priority is ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP
    )
    scheduled_role = next(
        role for role, role_requests in assignments.items() if elevated in role_requests
    )
    assignments[scheduled_role] = [
        request for request in assignments[scheduled_role] if request != elevated
    ]
    assignments["specialist:false_negative_hunter"] = [elevated]

    gate = model_surface_assignment_feasibility_gate(
        config,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        requests=requests,
        assignments=assignments,
        required=True,
        minimum_critical_root_lineages=1,
    )

    assert not gate.passed
    assert gate.state is AnalysisState.ATTEMPTED_FAILED
    assert "underassigned=1" in gate.detail
    assert "invalid_assignments=1" in gate.detail
    assert "coverage_gap_hunter_available=0" in gate.detail


def test_feasibility_requires_available_hunter_but_not_unavailable_hunter(
    config_factory: Callable[..., AuditConfig],
) -> None:
    index, graphs, invariants = _inventory()
    audited_suite = _audited_gap_coverage(index, graphs, invariants)
    requests = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )
    elevated = next(
        request
        for request in requests
        if request.priority is ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP
    )

    configured = _with_false_negative_hunter(config_factory(profile=AuditProfile.DEEP))
    assignments = plan_model_surface_review_assignments(
        configured,
        requests,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )
    assignments["specialist:false_negative_hunter"] = [
        request
        for request in assignments["specialist:false_negative_hunter"]
        if request != elevated
    ]
    replacement_role = next(
        role
        for role in ("business_logic", "configuration", "source_audit")
        if elevated not in assignments[role]
    )
    assignments[replacement_role].append(elevated)
    assignments[replacement_role].sort(key=lambda request: request.surface_id)
    missing_hunter = model_surface_assignment_feasibility_gate(
        configured,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        requests=requests,
        assignments=assignments,
        required=True,
    )
    assert not missing_hunter.passed
    assert "underassigned=0" in missing_hunter.detail
    assert "missing_priority_assignments=1" in missing_hunter.detail

    unavailable = config_factory()
    ordinary_assignments = plan_model_surface_review_assignments(
        unavailable,
        requests,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )
    unavailable_gate = model_surface_assignment_feasibility_gate(
        unavailable,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        requests=requests,
        assignments=ordinary_assignments,
        required=True,
    )
    assert unavailable_gate.passed
    assert "coverage_gap_hunter_available=0" in unavailable_gate.detail


def test_surface_request_plan_distributes_critical_surfaces_across_lineages(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()

    assignments = plan_model_surface_review_assignments(
        config,
        requests,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

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
    index, graphs, invariants, requests = _requests()

    assignments = plan_model_surface_review_assignments(
        config,
        requests,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    for request in requests:
        assigned = sum(request in role_requests for role_requests in assignments.values())
        assert assigned == (2 if request.critical else 1)


def test_surface_assignment_feasibility_passes_with_distinct_approved_primaries(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, audited_suite, requests = _requests_with_audited_coverage()
    assignments = plan_model_surface_review_assignments(
        config,
        requests,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )

    gate = model_surface_assignment_feasibility_gate(
        config,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        requests=requests,
        assignments=assignments,
        required=True,
    )

    assert gate.required
    assert gate.passed
    assert gate.state is AnalysisState.DETERMINISTIC
    assert "underassigned=0" in gate.detail
    assert "required_distinct_primary_root_lineages=critical:3,noncritical:1" in gate.detail


def test_surface_assignment_feasibility_rejects_revoked_lineage_approval(
    config_factory: Callable[..., AuditConfig],
) -> None:
    base = config_factory()
    index, graphs, invariants, audited_suite, requests = _requests_with_audited_coverage()
    assignments = plan_model_surface_review_assignments(
        base,
        requests,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )
    revoked = next(
        entry.root_lineage
        for entry in base.models.registry
        if entry.canonical_model_id == base.models.configuration.primary
    )
    config = base.model_copy(
        update={
            "privacy": base.privacy.model_copy(
                update={
                    "approved_model_lineages": tuple(
                        lineage
                        for lineage in base.privacy.approved_model_lineages
                        if lineage != revoked
                    )
                }
            )
        }
    )

    gate = model_surface_assignment_feasibility_gate(
        config,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        requests=requests,
        assignments=assignments,
        required=True,
    )

    assert not gate.passed
    assert gate.state is AnalysisState.ATTEMPTED_FAILED
    assert "invalid_assignments=0" not in gate.detail


def test_surface_assignment_feasibility_rejects_an_underassigned_surface(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, audited_suite, requests = _requests_with_audited_coverage()
    assignments = plan_model_surface_review_assignments(
        config,
        requests,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )
    critical_request = next(request for request in requests if request.critical)
    assigned_role = next(
        role for role, role_requests in assignments.items() if critical_request in role_requests
    )
    assignments[assigned_role] = [
        request for request in assignments[assigned_role] if request != critical_request
    ]

    gate = model_surface_assignment_feasibility_gate(
        config,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        requests=requests,
        assignments=assignments,
        required=True,
    )

    assert not gate.passed
    assert gate.state is AnalysisState.ATTEMPTED_FAILED
    assert "underassigned=1" in gate.detail


def test_surface_assignment_feasibility_uses_the_selected_lineage_floor(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, audited_suite, requests = _requests_with_audited_coverage()
    assignments = plan_model_surface_review_assignments(
        config,
        requests,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )
    critical_request = next(request for request in requests if request.critical)
    assigned_roles = sorted(
        role for role, role_requests in assignments.items() if critical_request in role_requests
    )
    for role in assigned_roles[1:]:
        assignments[role] = [
            request for request in assignments[role] if request != critical_request
        ]

    maximum_gate = model_surface_assignment_feasibility_gate(
        config,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        requests=requests,
        assignments=assignments,
        required=True,
    )
    lower_profile_gate = model_surface_assignment_feasibility_gate(
        config,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        requests=requests,
        assignments=assignments,
        required=True,
        minimum_critical_root_lineages=1,
    )

    assert not maximum_gate.passed
    assert lower_profile_gate.passed
    assert "critical:1,noncritical:1" in lower_profile_gate.detail


def test_surface_assignment_feasibility_rejects_empty_applicable_inventory(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, _ = _requests()
    empty_index = index.model_copy(update={"entities": []})
    empty_assignments = plan_model_surface_review_assignments(
        config,
        [],
        index=empty_index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    gate = model_surface_assignment_feasibility_gate(
        config,
        index=empty_index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=None,
        requests=[],
        assignments=empty_assignments,
        required=True,
    )

    assert not gate.passed
    assert gate.state is AnalysisState.NOT_ANALYZED
    assert "audited-suite coverage was unavailable" in gate.detail


def test_surface_assignment_feasibility_rejects_missing_solidity_index_when_required(
    config_factory: Callable[..., AuditConfig],
) -> None:
    gate = model_surface_assignment_feasibility_gate(
        config_factory(),
        index=None,
        graphs=None,
        invariants=None,
        economic_simulations=[],
        audited_suite_coverage=None,
        requests=[],
        assignments={},
        required=True,
    )

    assert gate.required
    assert not gate.passed
    assert gate.state is AnalysisState.NOT_ANALYZED
    assert "symbol index was unavailable" in gate.detail


def test_surface_assignment_feasibility_deduplicates_aliases_of_the_same_lineage(
    config_factory: Callable[..., AuditConfig],
) -> None:
    base = config_factory()
    data = base.model_dump(mode="python")
    source_primary = data["models"]["source_audit"]["primary"]
    source_entry = next(
        entry
        for entry in data["models"]["registry"]
        if entry["canonical_model_id"] == source_primary
    )
    source_alias = "alias/borealis-secure"
    source_entry["aliases"] = (source_alias,)
    data["models"]["configuration"]["primary"] = source_alias
    config = AuditConfig.model_validate(data)
    index, graphs, invariants, audited_suite, requests = _requests_with_audited_coverage()
    assignments = {
        "business_logic": list(requests),
        "configuration": list(requests),
        "source_audit": list(requests),
    }

    gate = model_surface_assignment_feasibility_gate(
        config,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        requests=requests,
        assignments=assignments,
        required=True,
    )

    assert not gate.passed
    assert gate.state is AnalysisState.ATTEMPTED_FAILED
    assert "underassigned=" in gate.detail


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
    assert coverage.applicable
    assert not coverage.critical_classification_complete
    assert coverage.critical.state is AnalysisState.NOT_ANALYZED
    assert not coverage.critical_gate_passed
    assert not model_review_critical_surface_gate(coverage, required=True).passed


def test_model_review_schema_requires_explicit_critical_classification(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, _ = _requests()
    coverage = build_model_review_coverage(
        config,
        usage_records=[],
        review_artifacts=[],
        review_contexts_by_request={},
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )
    payload = coverage.model_dump(mode="json")
    payload.pop("critical_classification_complete")

    with pytest.raises(ValidationError, match="critical_classification_complete"):
        ModelReviewCoverage.model_validate(payload)


def test_three_independent_response_lineages_cover_critical_surfaces(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, audited_suite, requests = _requests_with_audited_coverage()
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
        audited_suite_coverage=audited_suite,
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
    context = _with_exact_context_bytes(
        context.model_copy(
            update={
                "solidity_index": compact_index,
                "solidity_graphs": compact_graphs,
            }
        )
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
    substituted_context = _with_exact_context_bytes(
        original_context.model_copy(
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


def test_nested_context_mutation_cannot_authorize_coverage(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    request = next(
        request for request in requests if request.kind is ModelReviewSurfaceKind.ENTRY_POINT
    )
    usage = _usage("source_audit", config.models.source_audit.primary, "request-mutated-context")
    context = _review_context([request], usage, index, graphs)
    _bind_usage_to_context(usage, context)
    artifact = _artifact([request], usage, index, graphs, context=context)
    context.repository_map.frameworks.append("SyntheticNestedMutation")

    coverage = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[artifact],
        review_contexts_by_request={usage.request_id: [context]},
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    surface = next(
        surface for surface in coverage.surfaces if surface.surface_id == request.surface_id
    )
    assert not surface.reviewed
    assert "failed exact boundary validation" in surface.evidence_references[0].reason
    assert any("invalid context package" in limitation for limitation in coverage.limitations)


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


def test_registered_unapproved_model_is_retained_as_no_credit(
    config_factory: Callable[..., AuditConfig],
) -> None:
    base = config_factory()
    revoked = next(
        entry.root_lineage
        for entry in base.models.registry
        if entry.canonical_model_id == base.models.source_audit.primary
    )
    config = base.model_copy(
        update={
            "privacy": base.privacy.model_copy(
                update={
                    "approved_model_lineages": tuple(
                        lineage
                        for lineage in base.privacy.approved_model_lineages
                        if lineage != revoked
                    )
                }
            )
        }
    )
    index, graphs, invariants, requests = _requests()
    request = next(
        request for request in requests if request.kind is ModelReviewSurfaceKind.ENTRY_POINT
    )
    usage = _usage("source_audit", config.models.source_audit.primary, "request-unapproved")

    coverage = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[_artifact([request], usage, index, graphs)],
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
    assert not surface.evidence_references[0].credited
    assert "lineage lacked operator approval" in surface.evidence_references[0].reason
    assert any("used an unapproved lineage" in item for item in coverage.limitations)


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
