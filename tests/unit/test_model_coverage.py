from __future__ import annotations

import hashlib
import json
import os
import pickle
from collections.abc import Callable
from copy import copy, deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import ValidationError

import mmaudit.models.openrouter as openrouter_module
import mmaudit.orchestration.manifest as manifest_module
import mmaudit.orchestration.model_review_authority as model_review_authority_module
import mmaudit.orchestration.pipeline as pipeline_module
import mmaudit.orchestration.scheduler as scheduler_module
from mmaudit.config import AuditConfig, model_lineage_index
from mmaudit.models.coverage_planning import (
    ModelSurfaceRiskTier,
    build_model_surface_coverage_plan,
    classify_model_surface_risk,
)
from mmaudit.models.scheduler import (
    SchedulerArtifact,
    SchedulerPassKind,
    SchedulerPassPlan,
    SchedulerPassStatus,
    SchedulerScope,
    SchedulerTaskEventKind,
    SchedulerTaskKind,
    SchedulerTaskPlan,
    SchedulerTaskResult,
    SchedulerTerminalStatus,
    SchedulerTruncationRecoveryPromotionDisposition,
)
from mmaudit.models.schemas import (
    AnalysisState,
    AuditedSuiteAssertionStatus,
    AuditedSuiteCoverage,
    AuditedSuiteCoverageGap,
    AuditedSuiteCoverageGapKind,
    AuditedSuiteStatementStatus,
    AuditedSuiteSurfaceCoverage,
    AuditProfile,
    CandidateReviewBatch,
    ContextExcerpt,
    ContextPackage,
    ContextRequestEvidence,
    CoverageMetric,
    CoverageProvenance,
    EconomicSimulationKind,
    EconomicSimulationPlan,
    ExecutionEvidenceKind,
    InvariantCategory,
    InvariantSpec,
    InvariantSuite,
    InvariantTemplate,
    KnownIssueCriticality,
    KnownIssueTaxonomy,
    KnownIssueTaxonomyItem,
    Location,
    MinimumFloorRecoveryModelUsageBinding,
    ModelIdentityStrength,
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
    ProtocolProfileKind,
    RepositoryFile,
    RepositoryMap,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphKind,
    SolidityGraphNode,
    SolidityGraphNodeKind,
    SolidityGraphOccurrenceKind,
    SolidityGraphOmission,
    SolidityGraphRetainedOccurrence,
    SolidityGraphSet,
    SolidityProjectMetadata,
    SolidityProjectType,
    SolidityProvenance,
    SoliditySymbolIndex,
    SpecialistAcceptedOutcome,
    SpecialistAcceptedOutcomeKind,
    UsageRecord,
    solidity_graph_occurrence_sha256,
)
from mmaudit.models.token_planning import (
    ContextOmissionCategory,
    ContextOmissionItem,
    ContextOmissionReason,
)
from mmaudit.models.truncation import (
    CandidateReviewTruncatedEnvelopeEvidence,
    CandidateReviewTruncationProjection,
    candidate_review_frame_wire_schema_sha256,
    frame_candidate_review_batch,
    normalize_candidate_review_document,
    seal_candidate_review_truncated_envelope_evidence,
)
from mmaudit.models.truncation_closure import (
    _INVARIANT_ROUTING_KEYS,
    TruncationRecoveredRecursiveSurfaceReviewArtifact,
    TruncationRecoveredSurfaceReviewArtifact,
    TruncationSurfaceOriginKind,
)
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryClosureStatus,
    SchedulerTruncationRecoveryFamilyPromotion,
    SchedulerTruncationRecoveryRequestedSurfaceManifest,
)
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.model_coverage import (
    ModelReviewPreDispatchAuthorization,
    build_model_review_coverage,
    build_model_review_pre_dispatch_authorizations,
    build_model_surface_requests,
    build_semantic_shard_source_review_request,
    model_review_critical_surface_gate,
    model_surface_assignment_feasibility_gate,
    plan_model_surface_review_assignments,
)
from mmaudit.orchestration.model_review_evidence import (
    model_surface_context_source_custody,
    model_surface_review_record_validation_failures,
)
from mmaudit.orchestration.scheduler import (
    SchedulerJournal,
    open_scheduler_journal_for_verification,
    require_model_review_pre_dispatch_authorization,
    require_verified_promoted_recursive_truncation_recovery_surface_coverage,
    require_verified_promoted_truncation_recovery_surface_coverage,
)
from mmaudit.orchestration.scheduler_runtime import PipelineScheduler
from mmaudit.orchestration.truncation_recovery_evidence import (
    VerifiedPromotedRecursiveTruncationRecoverySurfaceCoverage,
    VerifiedPromotedTruncationRecoverySurfaceCoverage,
    VerifiedRecursiveTruncationRecoveryTree,
    VerifiedTruncationRecoveryClosure,
    build_truncation_recovery_child_context,
    verify_recursive_truncation_recovery_tree,
    verify_truncation_recovery_closure,
)
from mmaudit.solidity.invariants import detect_protocol_profiles
from mmaudit.solidity.taxonomy import (
    LoadedKnownIssueTaxonomy,
    build_known_issue_taxonomy_coverage,
)
from tests.fake_openrouter import (
    _maximum_assurance_candidates,
    _request_scoped_candidate_id,
    _requested_surface_covers_path,
)
from tests.identity_fixtures import (
    bind_synthetic_usage_identity,
    reattest_synthetic_real_usage,
    rebind_synthetic_token_plan,
)
from tests.scheduler_support import (
    bind_scheduler_test_usage_to_audit_selection,
    build_scheduler_test_model_payload,
    build_scheduler_test_model_surface_review_custody,
    build_scheduler_test_real_usage,
    build_scheduler_test_usage,
    scheduler_test_delivered_source_descriptor_sha256s,
    scheduler_test_model_surface_review_request_manifest_sha256,
    scheduler_test_response_schema_sha256,
)
from tests.unit.test_scheduler_journal import (
    _bindings as _scheduler_bindings,
)
from tests.unit.test_scheduler_journal import (
    _inventory as _scheduler_inventory,
)
from tests.unit.test_scheduler_journal import (
    _privacy_custody as _scheduler_privacy_custody,
)
from tests.unit.test_scheduler_journal import (
    create_scheduler_journal as _create_test_scheduler_journal,
)
from tests.unit.test_scheduler_truncation_promotion_integration import (
    _bind_child_to_parent_invariant as _bind_promoted_child_to_parent_invariant,
)
from tests.unit.test_scheduler_truncation_promotion_integration import (
    _one_shard_bindings as _promoted_surface_bindings,
)
from tests.unit.test_scheduler_truncation_promotion_integration import (
    _plan as _scheduler_test_plan,
)
from tests.unit.test_scheduler_truncation_promotion_integration import (
    _recovery_plan as _promoted_recovery_plan,
)
from tests.unit.test_truncation_recovery_journal import (
    _nested_plan_for_typed_truncated_child as _promoted_nested_recovery_plan,
)
from tests.unit.test_truncation_recovery_journal import (
    _projection as _promoted_truncation_projection,
)
from tests.unit.test_truncation_recovery_journal import (
    _success_custody as _promoted_child_success_custody,
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


def _edge_occurrences(
    edges: list[SolidityGraphEdge],
) -> tuple[SolidityGraphRetainedOccurrence, ...]:
    return tuple(
        sorted(
            (
                SolidityGraphRetainedOccurrence(
                    subject_kind=SolidityGraphOccurrenceKind.EDGE,
                    subject_sha256=solidity_graph_occurrence_sha256(
                        SolidityGraphOccurrenceKind.EDGE,
                        edge,
                    ),
                    occurrence_count=1,
                )
                for edge in edges
            ),
            key=lambda item: (item.subject_kind.value, item.subject_sha256),
        )
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
    edges = [
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
    ]
    graphs = SolidityGraphSet(
        edges=edges,
        retained_occurrences=_edge_occurrences(edges),
        analyzed_graphs=[
            SolidityGraphKind.PRIVILEGE,
            SolidityGraphKind.ASSET_FLOW,
            SolidityGraphKind.SENSITIVE_REACHABILITY,
        ],
    )
    invariants = InvariantSuite(
        invariants=[
            InvariantSpec(
                id="inv-00000000000000000001",
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
                    ),
                    Location(
                        path=_PATH,
                        start_line=5,
                        end_line=6,
                        symbol="totalAssets",
                        content_hash=_source_hash(5, 6),
                    ),
                ],
                entity_ids=["function:Vault.deposit", "state:Vault.totalAssets"],
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
    schema_sha256: str = "e" * 64,
) -> UsageRecord:
    started_at = datetime.now(UTC)
    generation_id = f"generation-{request_id}"
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
    security_relevance = (
        (
            f"{anchor} authorization controls address the source linked defensive class "
            "and its requested security invariant."
        )
        if request.kind is ModelReviewSurfaceKind.KNOWN_ISSUE_CLASS
        else f"{anchor} preserves the requested asset or authorization invariant."
    )
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
                security_relevance=security_relevance,
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


def _semantically_invalid_record(
    record: ModelSurfaceReviewRecord,
) -> ModelSurfaceReviewRecord:
    """Retain schema shape while replacing source semantics with boilerplate and a self-loop."""

    observation = record.evidence_observations[0].model_copy(
        update={
            "observed_behavior": "Explicitly considered this supplied surface.",
            "security_relevance": "Explicitly considered this supplied surface.",
        }
    )
    assert record.reachability is not None
    reachability = record.reachability.model_copy(
        update={
            "entry_point": record.citation,
            "path": (record.citation,),
        }
    )
    return record.model_copy(
        update={
            "rationale": "Explicitly considered this supplied surface.",
            "evidence_observations": (observation,),
            "reachability": reachability,
        }
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
        _with_context_request_evidence(usage, context, request_role=usage.role)
        result[usage.request_id] = [context]
    return result


@dataclass(frozen=True, slots=True)
class _AuthorizedOrdinaryReviewEvidence:
    usage_records: tuple[UsageRecord, ...]
    artifacts: tuple[ModelSurfaceReviewArtifact, ...]
    contexts_by_request: dict[str, list[ContextPackage]]
    authorizations: tuple[ModelReviewPreDispatchAuthorization, ...]
    journal: SchedulerJournal
    temporary_root: TemporaryDirectory[str]

    def close(self) -> None:
        self.journal.close()
        self.temporary_root.cleanup()

    def __enter__(self) -> _AuthorizedOrdinaryReviewEvidence:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()


def _require_authorization_after_fork(
    authorization: ModelReviewPreDispatchAuthorization,
    write_descriptor: int,
) -> None:
    """Report whether a fork inherited invalid process-local credit authority."""

    try:
        require_model_review_pre_dispatch_authorization(authorization)
    except ValueError:
        result = b"rejected"
    except BaseException:
        result = b"error"
    else:
        result = b"accepted"
    try:
        os.write(write_descriptor, result)
    finally:
        os.close(write_descriptor)


def _authorized_ordinary_review_evidence(
    config: AuditConfig,
    *,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet,
    requests: list[ModelSurfaceReviewRequest],
    reviewers: tuple[tuple[str, str], ...],
    contexts: tuple[ContextPackage, ...] | None = None,
    before_dispatch: Callable[[SchedulerJournal], None] | None = None,
) -> _AuthorizedOrdinaryReviewEvidence:
    """Dispatch synthetic local tasks before constructing their matching review evidence."""

    if not reviewers:
        raise ValueError("synthetic review authority requires at least one reviewer")
    lineage_by_model = model_lineage_index(config)
    provisional_contexts = contexts or tuple(
        _review_context(
            requests,
            _usage(role, model_id, f"pre-dispatch-context-{ordinal}"),
            index,
            graphs,
        )
        for ordinal, (role, model_id) in enumerate(reviewers)
    )
    if len(provisional_contexts) != len(reviewers):
        raise ValueError("synthetic review contexts differ from reviewer inventory")
    manifest_sha256 = ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(
        requests
    )
    temporary_root = TemporaryDirectory(prefix="mmaudit-model-review-authority-")
    inventory = _scheduler_inventory()
    journal = _create_test_scheduler_journal(
        Path(temporary_root.name) / "journal",
        bindings=_scheduler_bindings(),
        shard_inventory=inventory,
        privacy_evidence_custody=_scheduler_privacy_custody(
            source_sha256=inventory.source_tree_sha256
        ),
    )
    try:
        orientation_plan = journal.seal_pass_plan(
            _scheduler_test_plan(journal, SchedulerPassKind.ORIENTATION)
        )
        orientation_task = orientation_plan.tasks[0]
        orientation_activation = journal.activate_task(
            orientation_task.task_id,
            actual_input_sha256=orientation_task.input_sha256,
            system_prompt_sha256=orientation_task.system_prompt_sha256,
            user_prompt_sha256="3" * 64,
            provider_prompt_sha256="4" * 64,
            response_schema_sha256=orientation_task.response_schema_sha256,
            delivered_source_descriptor_sha256s=(
                scheduler_test_delivered_source_descriptor_sha256s(
                    orientation_plan,
                    orientation_task,
                )
            ),
        )
        journal.mark_dispatched(orientation_task.task_id)
        orientation_payload = build_scheduler_test_model_payload(
            orientation_plan,
            orientation_task,
        )
        orientation_usage = build_scheduler_test_usage(
            orientation_task,
            orientation_activation,
            seed="ordinary-authority-orientation",
            validated_output=orientation_payload,
            privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
        )
        orientation_output = journal.persist_output(
            orientation_task.task_id,
            orientation_payload,
            usage_record=orientation_usage,
        )
        journal.record_terminal(
            SchedulerTaskResult.build(
                plan=orientation_plan,
                task=orientation_task,
                activation=orientation_activation,
                terminal_status=SchedulerTerminalStatus.SUCCEEDED,
                terminal_evidence_sha256=(orientation_usage.validated_response_sha256 or "0" * 64),
                output=orientation_output,
            )
        )
        assert journal.seal_pass_result(SchedulerPassKind.ORIENTATION).status is (
            SchedulerPassStatus.COMPLETE
        )
        tasks: list[SchedulerTaskPlan] = []
        reviewer_context_by_key: dict[str, ContextPackage] = {}
        shard_ids = tuple(shard.shard_id for shard in journal.manifest.shard_inventory.shards)
        for ordinal, ((role, model_id), context) in enumerate(
            zip(reviewers, provisional_contexts, strict=True)
        ):
            lineage = lineage_by_model.get(model_id.lower())
            if lineage is None:
                raise ValueError("synthetic review model lacks configured lineage")
            task_key = f"ordinary-review-authority-{ordinal}"
            reviewer_context_by_key[task_key] = context
            tasks.append(
                SchedulerTaskPlan.build(
                    manifest=journal.manifest,
                    pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
                    scope=(
                        SchedulerScope.global_scope()
                        if manifest_module._WHOLE_PROTOCOL_REVIEW_ROLE_RE.fullmatch(role)
                        is not None
                        else SchedulerScope.single_shard(shard_ids[0])
                    ),
                    task_kind=SchedulerTaskKind.MODEL_REQUEST,
                    task_key=task_key,
                    role=role,
                    requested_model=model_id,
                    root_lineage=lineage.root_lineage,
                    input_sha256=hashlib.sha256(f"ordinary-input-{ordinal}".encode()).hexdigest(),
                    prompt_sha256=hashlib.sha256(
                        f"ordinary-prompt-recipe-{ordinal}".encode()
                    ).hexdigest(),
                    system_prompt_sha256=hashlib.sha256(
                        f"ordinary-system-{ordinal}".encode()
                    ).hexdigest(),
                    normalizer_sha256=hashlib.sha256(
                        f"ordinary-normalizer-{ordinal}".encode()
                    ).hexdigest(),
                    response_schema_sha256=candidate_review_frame_wire_schema_sha256(),
                    model_surface_review_request_manifest_sha256=manifest_sha256,
                )
            )
        covered_source_shards = {
            task.scope.shard_ids[0]
            for task in tasks
            if task.role == "source_audit" and task.scope.shard_ids
        }
        supporting_model = config.models.source_audit.primary
        supporting_lineage = lineage_by_model.get(supporting_model.lower())
        if supporting_lineage is None:
            raise ValueError("synthetic source-audit support lacks configured lineage")
        for ordinal, shard_id in enumerate(
            shard_id for shard_id in shard_ids if shard_id not in covered_source_shards
        ):
            task_key = f"ordinary-review-authority-support-{ordinal}"
            reviewer_context_by_key[task_key] = provisional_contexts[0]
            tasks.append(
                SchedulerTaskPlan.build(
                    manifest=journal.manifest,
                    pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
                    scope=SchedulerScope.single_shard(shard_id),
                    task_kind=SchedulerTaskKind.MODEL_REQUEST,
                    task_key=task_key,
                    role="source_audit",
                    requested_model=supporting_model,
                    root_lineage=supporting_lineage.root_lineage,
                    input_sha256=hashlib.sha256(
                        f"ordinary-support-input-{ordinal}".encode()
                    ).hexdigest(),
                    prompt_sha256=hashlib.sha256(
                        f"ordinary-support-prompt-recipe-{ordinal}".encode()
                    ).hexdigest(),
                    system_prompt_sha256=hashlib.sha256(
                        f"ordinary-support-system-{ordinal}".encode()
                    ).hexdigest(),
                    normalizer_sha256=hashlib.sha256(
                        f"ordinary-support-normalizer-{ordinal}".encode()
                    ).hexdigest(),
                    response_schema_sha256=candidate_review_frame_wire_schema_sha256(),
                    model_surface_review_request_manifest_sha256=manifest_sha256,
                )
            )
        plan = journal.seal_pass_plan(
            SchedulerPassPlan.build(
                manifest=journal.manifest,
                pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
                dependencies=journal.next_dependencies,
                tasks=tasks,
            )
        )
        tasks_by_key = {task.task_key: task for task in plan.tasks}
        ordered_tasks = tuple(
            tasks_by_key[f"ordinary-review-authority-{ordinal}"]
            for ordinal in range(len(reviewers))
        )
        for task in plan.tasks:
            context = reviewer_context_by_key[task.task_key]
            rendered_sha256 = hashlib.sha256(render_context(context).encode()).hexdigest()
            journal.activate_task(
                task.task_id,
                actual_input_sha256=rendered_sha256,
                system_prompt_sha256=task.system_prompt_sha256,
                user_prompt_sha256=rendered_sha256,
                provider_prompt_sha256="c" * 64,
                response_schema_sha256=task.response_schema_sha256,
                delivered_source_descriptor_sha256s=(
                    scheduler_test_delivered_source_descriptor_sha256s(plan, task)
                ),
            )
        if before_dispatch is not None:
            before_dispatch(journal)
        for task in plan.tasks:
            journal.mark_dispatched(task.task_id)
        reviewer_request_ids = {task.logical_request_id for task in ordered_tasks}
        authorizations = tuple(
            authorization
            for authorization in build_model_review_pre_dispatch_authorizations(journal)
            if require_model_review_pre_dispatch_authorization(authorization).request_id
            in reviewer_request_ids
        )
        if len(authorizations) != len(ordered_tasks):
            raise ValueError("synthetic review dispatch lacked exact live authority")
        usages: list[UsageRecord] = []
        artifacts: list[ModelSurfaceReviewArtifact] = []
        contexts_by_request: dict[str, list[ContextPackage]] = {}
        for task, (role, model_id), context in zip(
            ordered_tasks,
            reviewers,
            provisional_contexts,
            strict=True,
        ):
            usage = _usage(
                role,
                model_id,
                task.logical_request_id,
                schema_sha256=task.response_schema_sha256,
            )
            _bind_usage_to_context(usage, context)
            _with_context_request_evidence(usage, context, request_role=role)
            usages.append(usage)
            artifacts.append(_artifact(requests, usage, index, graphs, context=context))
            contexts_by_request[usage.request_id] = [context]
        return _AuthorizedOrdinaryReviewEvidence(
            usage_records=tuple(usages),
            artifacts=tuple(artifacts),
            contexts_by_request=contexts_by_request,
            authorizations=authorizations,
            journal=journal,
            temporary_root=temporary_root,
        )
    except BaseException:
        journal.close()
        temporary_root.cleanup()
        raise


def _bind_usage_to_context(usage: UsageRecord, context: ContextPackage) -> None:
    usage.user_prompt_sha256 = hashlib.sha256(render_context(context).encode()).hexdigest()
    reattest_synthetic_real_usage(usage)


def _with_context_request_evidence(
    usage: UsageRecord,
    context: ContextPackage,
    *,
    request_role: str,
) -> UsageRecord:
    """Bind synthetic usage to the exact rendered context presented to its request."""

    rendered_context = render_context(context)
    requested_surface_manifest_sha256, source_location_proof_sha256s = (
        model_surface_context_source_custody(context)
    )
    context_evidence = ContextRequestEvidence.build(
        request_id=usage.request_id,
        request_role=request_role,
        context_role=context.role,
        byte_budget=context.byte_budget,
        declared_bytes_used=context.bytes_used,
        rendered_bytes=len(rendered_context.encode()),
        source_bytes=sum(len(item.content.encode()) for item in context.excerpts),
        configured_maximum_source_tokens_per_request=(
            context.configured_maximum_source_tokens_per_request
        ),
        effective_source_byte_ceiling=context.effective_source_byte_ceiling,
        rendered_sha256=hashlib.sha256(rendered_context.encode()).hexdigest(),
        requested_surface_manifest_sha256=requested_surface_manifest_sha256,
        source_location_proof_sha256s=source_location_proof_sha256s,
    )
    usage.routing = {
        **usage.routing,
        "context_request_evidence": context_evidence.model_dump(mode="json"),
        "context_request_evidence_sha256": context_evidence.evidence_sha256,
    }
    return reattest_synthetic_real_usage(usage)


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


def test_ordinary_review_authority_is_absent_until_live_dispatch(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, _invariants, requests = _requests()
    observed_before_dispatch = False

    def assert_absent_before_dispatch(journal: SchedulerJournal) -> None:
        nonlocal observed_before_dispatch
        assert build_model_review_pre_dispatch_authorizations(journal) == ()
        observed_before_dispatch = True

    with _authorized_ordinary_review_evidence(
        config,
        index=index,
        graphs=graphs,
        requests=requests[:1],
        reviewers=(("source_audit", config.models.source_audit.primary),),
        before_dispatch=assert_absent_before_dispatch,
    ) as evidence:
        assert observed_before_dispatch
        assert len(evidence.authorizations) == 1
        binding = require_model_review_pre_dispatch_authorization(evidence.authorizations[0])
        assert binding.request_id == evidence.usage_records[0].request_id


def test_ordinary_review_authority_is_one_shot_and_returns_detached_binding(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, _invariants, requests = _requests()
    with _authorized_ordinary_review_evidence(
        config,
        index=index,
        graphs=graphs,
        requests=requests[:1],
        reviewers=(("source_audit", config.models.source_audit.primary),),
    ) as evidence:
        authorization = evidence.authorizations[0]
        binding = require_model_review_pre_dispatch_authorization(authorization)
        object.__setattr__(binding, "request_id", "forged-detached-request")
        retained = require_model_review_pre_dispatch_authorization(authorization)
        assert retained.request_id == evidence.usage_records[0].request_id

        assert not hasattr(
            model_review_authority_module,
            "_issue_model_review_pre_dispatch_authorization",
        )
        assert not hasattr(
            scheduler_module,
            "_issue_model_review_pre_dispatch_authorization",
        )

        forged = object.__new__(ModelReviewPreDispatchAuthorization)
        with pytest.raises(ValueError, match="was not issued live"):
            require_model_review_pre_dispatch_authorization(forged)


@pytest.mark.parametrize(
    "mutation",
    (
        "activation_system_prompt",
        "activation_delivered_sources",
        "task_input",
        "task_prompt",
        "task_normalizer",
        "task_scope",
        "dispatch_pass_plan_id",
        "dispatch_pass_plan_sha256",
    ),
)
def test_ordinary_review_authority_rejects_unsealed_retained_state_drift(
    config_factory: Callable[..., AuditConfig],
    mutation: str,
) -> None:
    config = config_factory()
    index, graphs, _invariants, requests = _requests()
    with _authorized_ordinary_review_evidence(
        config,
        index=index,
        graphs=graphs,
        requests=requests[:1],
        reviewers=(("source_audit", config.models.source_audit.primary),),
    ) as evidence:
        authorization = evidence.authorizations[0]
        binding = require_model_review_pre_dispatch_authorization(authorization)
        plan = next(
            plan
            for plan in evidence.journal.plans
            if any(task.task_id == binding.task_id for task in plan.tasks)
        )
        task = next(task for task in plan.tasks if task.task_id == binding.task_id)
        activation = next(
            item for item in evidence.journal.activations if item.task_id == binding.task_id
        )
        dispatch = next(
            item
            for item in evidence.journal.events
            if item.task_id == binding.task_id and item.kind is SchedulerTaskEventKind.DISPATCHED
        )
        if mutation == "activation_system_prompt":
            object.__setattr__(activation, "system_prompt_sha256", "e" * 64)
        elif mutation == "activation_delivered_sources":
            object.__setattr__(activation, "delivered_source_descriptor_sha256s", ())
        elif mutation == "task_input":
            object.__setattr__(task, "input_sha256", "e" * 64)
        elif mutation == "task_prompt":
            object.__setattr__(task, "prompt_sha256", "e" * 64)
        elif mutation == "task_normalizer":
            object.__setattr__(task, "normalizer_sha256", "e" * 64)
        elif mutation == "task_scope":
            object.__setattr__(task, "scope", SchedulerScope.global_scope())
        elif mutation == "dispatch_pass_plan_id":
            object.__setattr__(dispatch, "pass_plan_id", "scheduler-plan-" + "e" * 64)
        else:
            object.__setattr__(dispatch, "pass_plan_sha256", "e" * 64)

        with pytest.raises(ValueError, match="no longer live"):
            require_model_review_pre_dispatch_authorization(authorization)


def test_ordinary_review_authority_survives_append_only_later_transitions(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, _invariants, requests = _requests()
    with _authorized_ordinary_review_evidence(
        config,
        index=index,
        graphs=graphs,
        requests=requests[:1],
        reviewers=(("business_logic", config.models.business_logic.primary),),
    ) as evidence:
        authorization = evidence.authorizations[0]
        binding = require_model_review_pre_dispatch_authorization(authorization)
        plan = evidence.journal.plans[-1]
        task = next(item for item in plan.tasks if item.task_id == binding.task_id)
        activations = {
            activation.task_id: activation for activation in evidence.journal.activations
        }
        activation = activations[task.task_id]
        context = evidence.contexts_by_request[task.logical_request_id][0]
        payload = CandidateReviewBatch(
            findings=[],
            surface_reviews=tuple(
                _record(request, task.role, index, graphs) for request in requests[:1]
            ),
        )
        framed_payload = frame_candidate_review_batch(payload)
        normalized_payload, normalization = normalize_candidate_review_document(
            framed_payload,
            request_id=task.logical_request_id,
        )
        assert normalized_payload == payload
        usage = build_scheduler_test_usage(
            task,
            activation,
            seed="ordinary-authority-later-output",
            validated_output=framed_payload,
            privacy_evidence_custody=evidence.journal.manifest.privacy_evidence_custody,
        )
        _with_context_request_evidence(usage, context, request_role=task.role)
        base_artifact = _artifact(
            requests[:1],
            usage,
            index,
            graphs,
            context=context,
        )
        artifact_payload = base_artifact.model_dump(mode="json")
        artifact_payload.update(
            {
                "schema_version": "1.1",
                "normalized_response_sha256": normalization.normalized_batch_sha256,
                "normalization_evidence": normalization.model_dump(mode="json"),
                "normalized_response": payload.model_dump(mode="json"),
            }
        )
        artifact_payload["artifact_sha256"] = ModelSurfaceReviewArtifact.calculate_artifact_sha256(
            artifact_payload
        )
        surface_artifact = ModelSurfaceReviewArtifact.model_validate(artifact_payload)
        output = evidence.journal.persist_output(
            task.task_id,
            payload,
            usage_record=usage,
            model_surface_review_requests=requests[:1],
            model_surface_review_artifact=surface_artifact,
            normalization_evidence=normalization,
        )
        assert require_model_review_pre_dispatch_authorization(authorization) == binding
        evidence.journal.record_terminal(
            SchedulerTaskResult.build(
                plan=plan,
                task=task,
                activation=activation,
                terminal_status=SchedulerTerminalStatus.SUCCEEDED,
                terminal_evidence_sha256=usage.validated_response_sha256 or "0" * 64,
                output=output,
            )
        )
        assert require_model_review_pre_dispatch_authorization(authorization) == binding
        for sibling in plan.tasks:
            if sibling is task:
                continue
            evidence.journal.record_terminal(
                SchedulerTaskResult.build(
                    plan=plan,
                    task=sibling,
                    activation=activations[sibling.task_id],
                    terminal_status=SchedulerTerminalStatus.FAILED,
                    terminal_evidence_sha256=hashlib.sha256(
                        f"terminal-{sibling.task_id}".encode()
                    ).hexdigest(),
                )
            )
        evidence.journal.seal_pass_result(SchedulerPassKind.BLIND_SHARD_REVIEW)
        assert require_model_review_pre_dispatch_authorization(authorization) == binding


@pytest.mark.parametrize(
    ("artifact_kind", "mutation"),
    tuple(
        (artifact_kind, mutation)
        for artifact_kind in ("pass_plan", "activation", "dispatch_event", "checkpoint")
        for mutation in ("unlink", "replace_same_bytes", "change_bytes")
    ),
)
def test_ordinary_review_authority_rejects_bound_durable_artifact_drift(
    config_factory: Callable[..., AuditConfig],
    artifact_kind: str,
    mutation: str,
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    with _authorized_ordinary_review_evidence(
        config,
        index=index,
        graphs=graphs,
        requests=requests[:1],
        reviewers=(("source_audit", config.models.source_audit.primary),),
    ) as evidence:
        authorization = evidence.authorizations[0]
        binding = require_model_review_pre_dispatch_authorization(authorization)
        plan_ordinal, _plan = next(
            (ordinal, plan)
            for ordinal, plan in enumerate(evidence.journal.plans)
            if any(task.task_id == binding.task_id for task in plan.tasks)
        )
        activation = next(
            item for item in evidence.journal.activations if item.task_id == binding.task_id
        )
        dispatch = next(
            item
            for item in evidence.journal.events
            if item.task_id == binding.task_id and item.kind is SchedulerTaskEventKind.DISPATCHED
        )
        paths = {
            "pass_plan": evidence.journal.path
            / "pass-plans"
            / f"pass-{plan_ordinal + 1:02d}-plan.json",
            "activation": evidence.journal.path
            / "activations"
            / f"{activation.task_id}-{activation.activation_sha256}.json",
            "dispatch_event": evidence.journal.path
            / "events"
            / f"event-{dispatch.event_index:08d}.json",
            "checkpoint": evidence.journal.path / "journal-head-checkpoint.json",
        }
        target = paths[artifact_kind]
        original = target.read_bytes()
        if mutation == "unlink":
            target.unlink()
        elif mutation == "replace_same_bytes":
            replacement = target.with_name(f".{target.name}.replacement")
            replacement.write_bytes(original)
            replacement.chmod(0o600)
            os.replace(replacement, target)
        else:
            target.write_bytes(original + b" ")

        with pytest.raises(ValueError, match="no longer live"):
            require_model_review_pre_dispatch_authorization(authorization)
        with pytest.raises(ValueError, match="no longer live"):
            build_model_review_coverage(
                config,
                usage_records=list(evidence.usage_records),
                review_artifacts=list(evidence.artifacts),
                review_contexts_by_request=evidence.contexts_by_request,
                index=index,
                graphs=graphs,
                invariants=invariants,
                economic_simulations=[],
                ordinary_review_authorizations=evidence.authorizations,
            )


def test_ordinary_review_credit_requires_live_pre_dispatch_authority(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    with _authorized_ordinary_review_evidence(
        config,
        index=index,
        graphs=graphs,
        requests=requests[:1],
        reviewers=(("source_audit", config.models.source_audit.primary),),
    ) as evidence:
        unbound = build_model_review_coverage(
            config,
            usage_records=list(evidence.usage_records),
            review_artifacts=list(evidence.artifacts),
            review_contexts_by_request=evidence.contexts_by_request,
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
        )
        authorized = build_model_review_coverage(
            config,
            usage_records=list(evidence.usage_records),
            review_artifacts=list(evidence.artifacts),
            review_contexts_by_request=evidence.contexts_by_request,
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            ordinary_review_authorizations=evidence.authorizations,
        )

    assert not any(
        reference.credited
        for surface in unbound.surfaces
        for reference in surface.evidence_references
    )
    assert any(
        reference.credited
        for surface in authorized.surfaces
        for reference in surface.evidence_references
    )


def test_ordinary_review_authority_rejects_copy_pickle_replace_and_fork(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, _invariants, requests = _requests()
    with _authorized_ordinary_review_evidence(
        config,
        index=index,
        graphs=graphs,
        requests=requests[:1],
        reviewers=(("source_audit", config.models.source_audit.primary),),
    ) as evidence:
        authorization = evidence.authorizations[0]
        with pytest.raises(TypeError, match="cannot be copied"):
            copy(authorization)
        with pytest.raises(TypeError, match="cannot be copied"):
            deepcopy(authorization)
        with pytest.raises(TypeError, match="cannot be serialized"):
            pickle.dumps(authorization)
        with pytest.raises(TypeError):
            replace(authorization)

        if not hasattr(os, "fork"):
            pytest.skip("process-local fork custody requires os.fork")
        read_descriptor, write_descriptor = os.pipe()
        child_pid = os.fork()
        if child_pid == 0:  # pragma: no cover - asserted through the parent-side pipe
            os.close(read_descriptor)
            _require_authorization_after_fork(authorization, write_descriptor)
            os._exit(0)
        os.close(write_descriptor)
        try:
            fork_result = os.read(read_descriptor, 32)
        finally:
            os.close(read_descriptor)
        waited_pid, status = os.waitpid(child_pid, 0)
        assert waited_pid == child_pid
        assert os.waitstatus_to_exitcode(status) == 0
        assert fork_result == b"rejected"


@pytest.mark.parametrize("terminalize", (False, True), ids=("dispatched", "terminal"))
def test_reopened_dispatched_or_terminal_journal_cannot_reissue_ordinary_review_authority(
    config_factory: Callable[..., AuditConfig],
    terminalize: bool,
) -> None:
    config = config_factory()
    index, graphs, _invariants, requests = _requests()
    with _authorized_ordinary_review_evidence(
        config,
        index=index,
        graphs=graphs,
        requests=requests[:1],
        reviewers=(("source_audit", config.models.source_audit.primary),),
    ) as evidence:
        journal = evidence.journal
        authorization = evidence.authorizations[0]
        if terminalize:
            plan = journal.plans[-1]
            activations_by_task = {
                activation.task_id: activation for activation in journal.activations
            }
            for task in plan.tasks:
                journal.record_terminal(
                    SchedulerTaskResult.build(
                        plan=plan,
                        task=task,
                        activation=activations_by_task[task.task_id],
                        terminal_status=SchedulerTerminalStatus.FAILED,
                        terminal_evidence_sha256=hashlib.sha256(
                            f"terminal-{task.task_id}".encode()
                        ).hexdigest(),
                    )
                )
        journal_path = journal.path
        manifest = journal.manifest
        journal.close()
        with pytest.raises(ValueError, match="no longer live"):
            require_model_review_pre_dispatch_authorization(authorization)
        reopened = open_scheduler_journal_for_verification(
            journal_path,
            expected_bindings=manifest.bindings,
            expected_shard_inventory=manifest.shard_inventory,
            expected_cost_ledger_baseline=manifest.cost_ledger_baseline,
            expected_privacy_evidence_custody=manifest.privacy_evidence_custody,
            expected_terminal_report_authority_required=(
                manifest.terminal_report_authority_required
            ),
            expected_terminal_evidence_authority_required=(
                manifest.terminal_evidence_authority_required
            ),
        )
        try:
            assert build_model_review_pre_dispatch_authorizations(reopened) == ()
        finally:
            reopened.close()


def _known_issue_item(
    item_id: str,
    profile: ProtocolProfileKind,
    *,
    criticality: KnownIssueCriticality = KnownIssueCriticality.CRITICAL,
) -> KnownIssueTaxonomyItem:
    payload = {
        "item_id": item_id,
        "title": f"Synthetic defensive class {item_id}",
        "category": "synthetic_review",
        "criticality": criticality,
        "applicable_protocol_profiles": [profile],
        "defensive_question": (f"Confirm source-linked controls for defensive class {item_id}."),
        "economic_template": None,
    }
    item_sha256 = KnownIssueTaxonomyItem.calculate_item_sha256(payload)
    return KnownIssueTaxonomyItem(
        **payload,
        item_sha256=item_sha256,
        review_surface_subject_id=f"known-issue:{item_id}:{item_sha256}",
    )


def _known_issue_taxonomy(*items: KnownIssueTaxonomyItem) -> KnownIssueTaxonomy:
    payload = {
        "schema_version": "1.0",
        "taxonomy_version": "1.0",
        "purpose": "defensive_failure_mode_coverage",
        "finding_authority": False,
        "items": [
            item.model_dump(mode="json") for item in sorted(items, key=lambda item: item.item_id)
        ],
    }
    return KnownIssueTaxonomy(
        **payload,
        corpus_sha256=KnownIssueTaxonomy.calculate_corpus_sha256(payload),
    )


@dataclass(frozen=True, slots=True)
class _PromotedParentSurfaceFixture:
    journal: SchedulerJournal
    family_id: str
    closure_capability: VerifiedTruncationRecoveryClosure
    surface_capability: VerifiedPromotedTruncationRecoverySurfaceCoverage
    promotion: SchedulerTruncationRecoveryFamilyPromotion
    scheduler_artifact: SchedulerArtifact
    structural_artifact: TruncationRecoveredSurfaceReviewArtifact
    requests: tuple[ModelSurfaceReviewRequest, ...]
    records: tuple[ModelSurfaceReviewRecord, ...]
    parent_usage: UsageRecord
    child_usages: tuple[UsageRecord, ...]
    parent_context: ContextPackage
    child_contexts: tuple[ContextPackage, ...]
    child_artifacts: tuple[ModelSurfaceReviewArtifact, ...]
    child_specialist_outcomes: tuple[SpecialistAcceptedOutcome, ...] = ()
    scheduler_live_usages: tuple[UsageRecord, ...] = ()


@dataclass(frozen=True, slots=True)
class _PromotedRecursiveParentSurfaceFixture:
    """One exact journal-owned full-tree promotion for consumer regressions."""

    journal: SchedulerJournal
    family_id: str
    tree_capability: VerifiedRecursiveTruncationRecoveryTree
    surface_capability: VerifiedPromotedRecursiveTruncationRecoverySurfaceCoverage
    promotion: SchedulerTruncationRecoveryFamilyPromotion
    scheduler_artifact: SchedulerArtifact
    structural_artifact: TruncationRecoveredRecursiveSurfaceReviewArtifact
    requests: tuple[ModelSurfaceReviewRequest, ...]
    records: tuple[ModelSurfaceReviewRecord, ...]
    parent_usage: UsageRecord
    bridge_usage: UsageRecord
    leaf_usages: tuple[UsageRecord, UsageRecord, UsageRecord]
    parent_context: ContextPackage
    bridge_context: ContextPackage
    leaf_contexts: tuple[ContextPackage, ContextPackage, ContextPackage]
    leaf_artifacts: tuple[
        ModelSurfaceReviewArtifact,
        ModelSurfaceReviewArtifact,
        ModelSurfaceReviewArtifact,
    ]
    scheduler_live_usages: tuple[UsageRecord, ...] = ()


def _promoted_parent_truncation(
    *,
    journal: SchedulerJournal,
    task: Any,
    activation: Any,
    context: ContextPackage,
    projection: CandidateReviewTruncationProjection,
    full_batch: CandidateReviewBatch,
    include_scheduler_test_refresh_pricing: bool,
) -> tuple[CandidateReviewTruncatedEnvelopeEvidence, UsageRecord]:
    base = build_scheduler_test_real_usage(
        task,
        activation,
        seed="promotion-parent",
        validated_output=frame_candidate_review_batch(full_batch),
        cost_usd_exact="0.04",
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
        audit_model_selection=journal.manifest.bindings.audit_model_selection,
        audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
        audit_model_refresh_pricing=journal.manifest.bindings.audit_model_refresh_pricing,
        include_audit_model_refresh_pricing=include_scheduler_test_refresh_pricing,
    )
    assert base.openrouter_generation_id is not None
    assert base.returned_model is not None
    assert base.actual_model is not None
    assert base.provider is not None
    assert base.actual_provider_endpoint is not None
    router_metadata_sha256 = base.routing.get("router_metadata_sha256")
    assert isinstance(router_metadata_sha256, str)
    envelope = seal_candidate_review_truncated_envelope_evidence(
        logical_request_id=task.logical_request_id,
        generation_id=base.openrouter_generation_id,
        generation_header_id=base.openrouter_generation_id,
        requested_model=base.requested_model,
        returned_model=base.returned_model,
        selected_model=base.actual_model,
        response_provider_identity=base.provider,
        selected_provider_endpoint=base.actual_provider_endpoint,
        selected_provider_identity="synthetic-provider",
        selected_provider_name=base.provider,
        router_metadata_sha256=router_metadata_sha256,
        finish_reason=projection.finish_reason,
        native_finish_reason=projection.native_finish_reason,
        wire_schema_sha256=projection.wire_schema_sha256,
        response_sha256=projection.original_response_sha256,
    )
    rendered_context = render_context(context)
    requested_surface_manifest_sha256, source_location_proof_sha256s = (
        model_surface_context_source_custody(context)
    )
    context_evidence = ContextRequestEvidence.build(
        request_id=task.logical_request_id,
        request_role=task.role,
        context_role=context.role,
        byte_budget=context.byte_budget,
        declared_bytes_used=context.bytes_used,
        rendered_bytes=len(rendered_context.encode()),
        source_bytes=sum(len(item.content.encode()) for item in context.excerpts),
        configured_maximum_source_tokens_per_request=(
            context.configured_maximum_source_tokens_per_request
        ),
        effective_source_byte_ceiling=context.effective_source_byte_ceiling,
        rendered_sha256=hashlib.sha256(rendered_context.encode()).hexdigest(),
        requested_surface_manifest_sha256=requested_surface_manifest_sha256,
        source_location_proof_sha256s=source_location_proof_sha256s,
    )
    routing = {
        **base.routing,
        "generation_id": envelope.generation_id,
        "generation_header_id": envelope.generation_header_id,
        "provider": envelope.selected_provider_name,
        "router_metadata_sha256": envelope.router_metadata_sha256,
        "finish_reason": envelope.finish_reason,
        "native_finish_reason": envelope.native_finish_reason,
        "schema_sha256": envelope.wire_schema_sha256,
        "validation_status": ModelRequestValidationStatus.TRUNCATED.value,
        "context_request_evidence": context_evidence.model_dump(mode="json"),
        "context_request_evidence_sha256": context_evidence.evidence_sha256,
        **openrouter_module._candidate_review_truncated_envelope_routing(envelope),
        **openrouter_module._candidate_review_truncation_projection_routing(projection),
    }
    usage = reattest_synthetic_real_usage(
        base.model_copy(
            update={
                "response_sha256": projection.original_response_sha256,
                "validated_response_sha256": None,
                "finish_reason": projection.finish_reason,
                "validation_status": ModelRequestValidationStatus.TRUNCATED,
                "identity_strength": ModelIdentityStrength.UNBOUND,
                "model_family": "synthetic-recovery-lineage",
                "status": "rejected_truncated_response",
                "provider_error_classification": "truncated_response",
                "routing": routing,
            }
        )
    )
    return envelope, usage


def _promoted_bridge_truncation(
    *,
    journal: SchedulerJournal,
    child: Any,
    activation: Any,
    context: ContextPackage,
    surface_manifest: SchedulerTruncationRecoveryRequestedSurfaceManifest,
    records: tuple[ModelSurfaceReviewRecord, ...],
    parent_usage: UsageRecord,
    parent_role: str,
    parent_model_id: str,
    include_scheduler_test_refresh_pricing: bool,
    transform: Callable[[UsageRecord], UsageRecord],
) -> tuple[
    UsageRecord,
    CandidateReviewTruncatedEnvelopeEvidence,
    CandidateReviewTruncationProjection,
]:
    """Turn one valid synthetic child attempt into exact zero-retained REAL custody."""

    base, _normalization, _batch, _requests, _artifact = _promoted_child_success_custody(
        child=child,
        activation=activation,
        surface_manifest=surface_manifest,
        surfaces=records,
        execution_evidence=ExecutionEvidenceKind.REAL,
        request_role=parent_role,
        exact_model_id=parent_model_id,
    )
    if include_scheduler_test_refresh_pricing:
        base = _bind_promoted_child_to_parent_invariant(
            base,
            journal=journal,
            parent_usage=parent_usage,
        )
    else:
        audit_selection = journal.manifest.bindings.audit_model_selection
        assert audit_selection is not None
        base = bind_scheduler_test_usage_to_audit_selection(base, audit_selection)
        bridge_routing = dict(base.routing)
        for key in _INVARIANT_ROUTING_KEYS:
            bridge_routing.pop(key, None)
            if key in parent_usage.routing:
                bridge_routing[key] = parent_usage.routing[key]
        base = base.model_copy(update={"routing": bridge_routing})

    records_by_id = {record.surface_id: record for record in records}
    bridge_records = tuple(records_by_id[surface_id] for surface_id in child.surface_ids)
    projection = _promoted_truncation_projection(bridge_records, retained_count=0)
    assert base.openrouter_generation_id is not None
    assert base.returned_model is not None
    assert base.actual_model is not None
    assert base.provider is not None
    assert base.actual_provider_endpoint is not None
    router_metadata_sha256 = base.routing.get("router_metadata_sha256")
    assert isinstance(router_metadata_sha256, str)
    envelope = seal_candidate_review_truncated_envelope_evidence(
        logical_request_id=child.child_logical_request_id,
        generation_id=base.openrouter_generation_id,
        generation_header_id=base.openrouter_generation_id,
        requested_model=base.requested_model,
        returned_model=base.returned_model,
        selected_model=base.actual_model,
        response_provider_identity=base.provider,
        selected_provider_endpoint=base.actual_provider_endpoint,
        selected_provider_identity="synthetic-provider",
        selected_provider_name=base.provider,
        router_metadata_sha256=router_metadata_sha256,
        finish_reason=projection.finish_reason,
        native_finish_reason=projection.native_finish_reason,
        wire_schema_sha256=projection.wire_schema_sha256,
        response_sha256=projection.original_response_sha256,
    )
    rendered_context = render_context(context)
    requested_surface_manifest_sha256, source_location_proof_sha256s = (
        model_surface_context_source_custody(context)
    )
    context_evidence = ContextRequestEvidence.build(
        request_id=base.request_id,
        request_role=parent_role,
        context_role=context.role,
        byte_budget=context.byte_budget,
        declared_bytes_used=context.bytes_used,
        rendered_bytes=len(rendered_context.encode()),
        source_bytes=sum(len(item.content.encode()) for item in context.excerpts),
        configured_maximum_source_tokens_per_request=(
            context.configured_maximum_source_tokens_per_request
        ),
        effective_source_byte_ceiling=context.effective_source_byte_ceiling,
        rendered_sha256=hashlib.sha256(rendered_context.encode()).hexdigest(),
        requested_surface_manifest_sha256=requested_surface_manifest_sha256,
        source_location_proof_sha256s=source_location_proof_sha256s,
    )
    routing = {
        **base.routing,
        "generation_id": envelope.generation_id,
        "generation_header_id": envelope.generation_header_id,
        "provider": envelope.selected_provider_name,
        "router_metadata_sha256": envelope.router_metadata_sha256,
        "finish_reason": envelope.finish_reason,
        "native_finish_reason": envelope.native_finish_reason,
        "schema_sha256": envelope.wire_schema_sha256,
        "validation_status": ModelRequestValidationStatus.TRUNCATED.value,
        "context_request_evidence": context_evidence.model_dump(mode="json"),
        "context_request_evidence_sha256": context_evidence.evidence_sha256,
        **openrouter_module._candidate_review_truncated_envelope_routing(envelope),
        **openrouter_module._candidate_review_truncation_projection_routing(projection),
    }
    usage = reattest_synthetic_real_usage(
        base.model_copy(
            update={
                "response_sha256": projection.original_response_sha256,
                "validated_response_sha256": None,
                "finish_reason": projection.finish_reason,
                "validation_status": ModelRequestValidationStatus.TRUNCATED,
                "identity_strength": ModelIdentityStrength.UNBOUND,
                "status": "rejected_truncated_response",
                "provider_error_classification": "truncated_response",
                "routing": routing,
            }
        )
    )
    return transform(usage), envelope, projection


def _build_promoted_parent_surface_fixture(
    journal: SchedulerJournal,
    *,
    requests: tuple[ModelSurfaceReviewRequest, ...],
    records: tuple[ModelSurfaceReviewRecord, ...],
    parent_context: ContextPackage,
    parent_model_id: str,
    parent_root_lineage: str,
    orientation_model_id: str | None = None,
    orientation_root_lineage: str | None = None,
    usage_transform: Callable[[UsageRecord], UsageRecord] | None = None,
    include_scheduler_test_refresh_pricing: bool = True,
    parent_role: str = "source_audit",
    specialist_role: str | None = None,
    supporting_source_model_id: str | None = None,
    supporting_source_root_lineage: str | None = None,
    recursive: bool = False,
    direct_parent_retained_count: int = 1,
    recursive_parent_retained_count: int = 0,
) -> _PromotedParentSurfaceFixture | _PromotedRecursiveParentSurfaceFixture:
    """Issue one real journal-owned retained-parent surface capability for consumers."""

    if tuple(parent_context.requested_model_surfaces) != requests:
        raise ValueError("promoted surface fixture context differs from its requests")
    if tuple(record.surface_id for record in records) != tuple(
        request.surface_id for request in requests
    ):
        raise ValueError("promoted surface fixture records differ from its requests")
    selected_orientation_model = orientation_model_id or parent_model_id
    selected_orientation_root = orientation_root_lineage or parent_root_lineage
    transform = usage_transform or (lambda usage: usage)
    whole_protocol_parent = (
        manifest_module._WHOLE_PROTOCOL_REVIEW_ROLE_RE.fullmatch(parent_role) is not None
    )
    generic_parent_role = parent_role == "source_audit" or whole_protocol_parent
    if (specialist_role is None) != generic_parent_role:
        raise ValueError("promoted surface specialist role mode is inconsistent")
    if specialist_role is not None and (
        parent_role != f"specialist:{specialist_role}"
        or supporting_source_model_id is None
        or supporting_source_root_lineage is None
    ):
        raise ValueError("promoted specialist surface fixture lacks source-review support")
    if whole_protocol_parent and (
        supporting_source_model_id is None or supporting_source_root_lineage is None
    ):
        raise ValueError("whole-protocol promotion fixture lacks source-review support")
    if recursive and specialist_role is not None:
        raise ValueError("recursive promotion fixture admits only generic recovery leaves")
    planner = PipelineScheduler(journal)

    orientation_task = planner.model_task(
        pass_kind=SchedulerPassKind.ORIENTATION,
        scope=SchedulerScope.global_scope(),
        task_key="promoted-surface-orientation",
        role="threat_model",
        requested_model=selected_orientation_model,
        root_lineage=selected_orientation_root,
        system_prompt_sha256=hashlib.sha256(b"promoted-surface-orientation-system").hexdigest(),
        response_schema_sha256=scheduler_test_response_schema_sha256(
            SchedulerPassKind.ORIENTATION,
            "threat_model",
        ),
    )
    orientation_plan = planner.prepare_pass(
        SchedulerPassKind.ORIENTATION,
        (orientation_task,),
    )
    orientation_activation = journal.activate_task(
        orientation_task.task_id,
        actual_input_sha256=orientation_task.input_sha256,
        system_prompt_sha256=orientation_task.system_prompt_sha256,
        user_prompt_sha256=hashlib.sha256(b"promoted-surface-orientation-user").hexdigest(),
        provider_prompt_sha256=hashlib.sha256(b"promoted-surface-orientation-provider").hexdigest(),
        response_schema_sha256=orientation_task.response_schema_sha256,
        delivered_source_descriptor_sha256s=(
            scheduler_test_delivered_source_descriptor_sha256s(
                orientation_plan,
                orientation_task,
            )
        ),
    )
    journal.mark_dispatched(orientation_task.task_id)
    orientation_payload = build_scheduler_test_model_payload(
        orientation_plan,
        orientation_task,
    )
    orientation_usage = transform(
        build_scheduler_test_real_usage(
            orientation_task,
            orientation_activation,
            seed="promoted-surface-orientation",
            validated_output=orientation_payload,
            privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
            audit_model_selection=journal.manifest.bindings.audit_model_selection,
            audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
            audit_model_refresh_pricing=(journal.manifest.bindings.audit_model_refresh_pricing),
            include_audit_model_refresh_pricing=include_scheduler_test_refresh_pricing,
        )
    )
    orientation_output = journal.persist_output(
        orientation_task.task_id,
        orientation_payload,
        usage_record=orientation_usage,
    )
    journal.record_terminal(
        SchedulerTaskResult.build(
            plan=orientation_plan,
            task=orientation_task,
            activation=orientation_activation,
            terminal_status=SchedulerTerminalStatus.SUCCEEDED,
            terminal_evidence_sha256=orientation_usage.validated_response_sha256 or "0" * 64,
            output=orientation_output,
        )
    )
    assert journal.seal_pass_result(SchedulerPassKind.ORIENTATION).status is (
        SchedulerPassStatus.COMPLETE
    )

    planner = PipelineScheduler(journal)
    projection = _promoted_truncation_projection(
        records,
        retained_count=(
            recursive_parent_retained_count if recursive else direct_parent_retained_count
        ),
    )
    surface_manifest = SchedulerTruncationRecoveryRequestedSurfaceManifest.build(requests)
    blind_task = planner.model_task(
        pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
        scope=(
            SchedulerScope.global_scope()
            if manifest_module._WHOLE_PROTOCOL_REVIEW_ROLE_RE.fullmatch(parent_role) is not None
            else SchedulerScope.single_shard(journal.manifest.shard_inventory.shards[0].shard_id)
        ),
        task_key=f"promoted-retained-parent-{parent_role}",
        role=parent_role,
        requested_model=parent_model_id,
        root_lineage=parent_root_lineage,
        system_prompt_sha256=hashlib.sha256(b"promoted-retained-parent-system").hexdigest(),
        response_schema_sha256=candidate_review_frame_wire_schema_sha256(),
        model_surface_review_request_manifest_sha256=(
            surface_manifest.requested_surface_manifest_sha256
        ),
    )
    supporting_source_task = (
        planner.model_task(
            pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
            scope=SchedulerScope.single_shard(journal.manifest.shard_inventory.shards[0].shard_id),
            task_key="promoted-retained-parent-source-audit",
            role="source_audit",
            requested_model=cast(str, supporting_source_model_id),
            root_lineage=cast(str, supporting_source_root_lineage),
            system_prompt_sha256=hashlib.sha256(
                b"promoted-retained-supporting-source-system"
            ).hexdigest(),
            response_schema_sha256=candidate_review_frame_wire_schema_sha256(),
            model_surface_review_request_manifest_sha256=(
                scheduler_test_model_surface_review_request_manifest_sha256(
                    manifest=journal.manifest,
                    pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
                    scope=SchedulerScope.single_shard(
                        journal.manifest.shard_inventory.shards[0].shard_id
                    ),
                    task_key="promoted-retained-parent-source-audit",
                    role="source_audit",
                )
            ),
        )
        if specialist_role is not None or whole_protocol_parent
        else None
    )
    blind_plan = planner.prepare_pass(
        SchedulerPassKind.BLIND_SHARD_REVIEW,
        (blind_task,) if supporting_source_task is None else (supporting_source_task, blind_task),
    )
    supporting_usage: UsageRecord | None = None
    if supporting_source_task is not None:
        supporting_prompt_sha256 = hashlib.sha256(
            b"promoted-retained-supporting-source-user"
        ).hexdigest()
        supporting_activation = journal.activate_task(
            supporting_source_task.task_id,
            actual_input_sha256=supporting_prompt_sha256,
            system_prompt_sha256=supporting_source_task.system_prompt_sha256,
            user_prompt_sha256=supporting_prompt_sha256,
            provider_prompt_sha256=hashlib.sha256(
                b"promoted-retained-supporting-source-provider"
            ).hexdigest(),
            response_schema_sha256=supporting_source_task.response_schema_sha256,
            delivered_source_descriptor_sha256s=(
                scheduler_test_delivered_source_descriptor_sha256s(
                    blind_plan,
                    supporting_source_task,
                )
            ),
        )
        journal.mark_dispatched(supporting_source_task.task_id)
        supporting_payload = CandidateReviewBatch.model_validate(
            build_scheduler_test_model_payload(
                blind_plan,
                supporting_source_task,
            )
        )
        supporting_document = frame_candidate_review_batch(supporting_payload)
        normalized_supporting_payload, supporting_normalization = (
            normalize_candidate_review_document(
                supporting_document,
                request_id=supporting_source_task.logical_request_id,
            )
        )
        assert normalized_supporting_payload == supporting_payload
        supporting_usage = transform(
            build_scheduler_test_real_usage(
                supporting_source_task,
                supporting_activation,
                seed="promoted-retained-supporting-source",
                validated_output=supporting_document,
                privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
                audit_model_selection=journal.manifest.bindings.audit_model_selection,
                audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
                audit_model_refresh_pricing=(journal.manifest.bindings.audit_model_refresh_pricing),
                include_audit_model_refresh_pricing=(include_scheduler_test_refresh_pricing),
            )
        )
        supporting_surface_requests, supporting_surface_artifact = (
            build_scheduler_test_model_surface_review_custody(
                blind_plan,
                supporting_source_task,
                supporting_activation,
                supporting_usage,
                supporting_payload,
                normalization_evidence=supporting_normalization,
            )
        )
        assert supporting_surface_artifact is not None
        supporting_output = journal.persist_output(
            supporting_source_task.task_id,
            supporting_payload,
            usage_record=supporting_usage,
            model_surface_review_requests=supporting_surface_requests,
            model_surface_review_artifact=supporting_surface_artifact,
            normalization_evidence=supporting_normalization,
        )
        journal.record_terminal(
            SchedulerTaskResult.build(
                plan=blind_plan,
                task=supporting_source_task,
                activation=supporting_activation,
                terminal_status=SchedulerTerminalStatus.SUCCEEDED,
                terminal_evidence_sha256=(supporting_usage.validated_response_sha256 or "0" * 64),
                output=supporting_output,
            )
        )
    parent_prompt_sha256 = hashlib.sha256(render_context(parent_context).encode()).hexdigest()
    parent_activation = journal.activate_task(
        blind_task.task_id,
        actual_input_sha256=parent_prompt_sha256,
        system_prompt_sha256=blind_task.system_prompt_sha256,
        user_prompt_sha256=parent_prompt_sha256,
        provider_prompt_sha256=hashlib.sha256(b"promoted-retained-parent-provider").hexdigest(),
        response_schema_sha256=blind_task.response_schema_sha256,
        delivered_source_descriptor_sha256s=(
            scheduler_test_delivered_source_descriptor_sha256s(blind_plan, blind_task)
        ),
    )
    journal.mark_dispatched(blind_task.task_id)
    envelope, parent_usage = _promoted_parent_truncation(
        journal=journal,
        task=blind_task,
        activation=parent_activation,
        context=parent_context,
        projection=projection,
        full_batch=CandidateReviewBatch(findings=(), surface_reviews=records),
        include_scheduler_test_refresh_pricing=include_scheduler_test_refresh_pricing,
    )
    parent_usage = transform(parent_usage)
    parent_attempt = journal.persist_truncated_provider_attempt(
        blind_task.task_id,
        parent_usage,
        truncated_envelope_evidence=envelope,
        truncation_projection=projection,
    )
    original_result = SchedulerTaskResult.build(
        plan=blind_plan,
        task=blind_task,
        activation=parent_activation,
        terminal_status=SchedulerTerminalStatus.TRUNCATED,
        terminal_evidence_sha256=projection.evidence_sha256,
    )
    journal.record_terminal(original_result)
    recovery_plan = _promoted_recovery_plan(
        journal=journal,
        pass_plan=blind_plan,
        task=blind_task,
        activation=parent_activation,
        attempt=parent_attempt,
        projection=projection,
        manifest=surface_manifest,
        parent_usage=parent_usage,
    )
    family = journal.open_truncation_recovery_family(
        recovery_plan=recovery_plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    child_results = []
    child_usages = []
    child_contexts = []
    child_artifacts = []
    child_specialist_outcomes = []
    bridge_child = recovery_plan.children[0] if recursive else None
    bridge_activation = None
    bridge_result = None
    bridge_usage = None
    bridge_context = None
    bridge_projection = None
    for child in recovery_plan.children:
        child_context = build_truncation_recovery_child_context(
            parent_context=parent_context,
            child=child,
        )
        child_prompt_sha256 = hashlib.sha256(render_context(child_context).encode()).hexdigest()
        child_activation = journal.activate_truncation_recovery_child(
            child.child_task_id,
            actual_input_sha256=child_prompt_sha256,
            system_prompt_sha256=blind_task.system_prompt_sha256,
            user_prompt_sha256=child_prompt_sha256,
            provider_prompt_sha256=hashlib.sha256(
                f"promoted-child-provider:{child.child_task_id}".encode()
            ).hexdigest(),
            response_schema_sha256=candidate_review_frame_wire_schema_sha256(),
        )
        journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
        if child is bridge_child:
            bridge_usage, bridge_envelope, bridge_projection = _promoted_bridge_truncation(
                journal=journal,
                child=child,
                activation=child_activation,
                context=child_context,
                surface_manifest=surface_manifest,
                records=records,
                parent_usage=parent_usage,
                parent_role=parent_role,
                parent_model_id=parent_model_id,
                include_scheduler_test_refresh_pricing=(include_scheduler_test_refresh_pricing),
                transform=transform,
            )
            bridge_result = journal.record_truncation_recovery_child_truncated(
                child.child_task_id,
                failed_usage_record=bridge_usage,
                truncated_envelope_evidence=bridge_envelope,
                truncation_projection=bridge_projection,
            )
            bridge_activation = child_activation
            bridge_context = child_context
            child_results.append(bridge_result)
            continue
        child_usage, normalization, batch, child_requests, child_artifact = (
            _promoted_child_success_custody(
                child=child,
                activation=child_activation,
                surface_manifest=surface_manifest,
                surfaces=records,
                execution_evidence=ExecutionEvidenceKind.REAL,
                request_role=parent_role,
                exact_model_id=parent_model_id,
            )
        )
        if include_scheduler_test_refresh_pricing:
            child_usage = _bind_promoted_child_to_parent_invariant(
                child_usage,
                journal=journal,
                parent_usage=parent_usage,
            )
        else:
            audit_selection = journal.manifest.bindings.audit_model_selection
            assert audit_selection is not None
            child_usage = bind_scheduler_test_usage_to_audit_selection(
                child_usage,
                audit_selection,
            )
            child_routing = dict(child_usage.routing)
            for key in _INVARIANT_ROUTING_KEYS:
                child_routing.pop(key, None)
                if key in parent_usage.routing:
                    child_routing[key] = parent_usage.routing[key]
            child_usage = child_usage.model_copy(update={"routing": child_routing})
        child_usage = _with_context_request_evidence(
            child_usage,
            child_context,
            request_role=parent_role,
        )
        child_usage = transform(child_usage)
        child_specialist_outcome = None
        if specialist_role is not None:
            context_request_evidence_sha256 = child_usage.routing.get(
                "context_request_evidence_sha256"
            )
            assert isinstance(context_request_evidence_sha256, str)
            assert child_usage.validated_response_sha256 is not None
            child_specialist_outcome = SpecialistAcceptedOutcome.build(
                request_id=child_usage.request_id,
                specialist_role=specialist_role,
                request_role=parent_role,
                outcome_kind=SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW,
                validated_response_sha256=child_usage.validated_response_sha256,
                context_request_evidence_sha256=context_request_evidence_sha256,
                requested_surface_count=len(child_requests),
                surface_review_artifact_sha256=child_artifact.artifact_sha256,
            )
        child_result = journal.record_truncation_recovery_child_success(
            child.child_task_id,
            usage_record=child_usage,
            normalization_evidence=normalization,
            normalized_batch=batch,
            requested_surface_requests=child_requests,
            output_artifact=child_artifact,
            specialist_accepted_outcome=child_specialist_outcome,
        )
        child_results.append(child_result)
        child_usages.append(child_usage)
        child_contexts.append(child_context)
        child_artifacts.append(child_artifact)
        if child_specialist_outcome is not None:
            child_specialist_outcomes.append(child_specialist_outcome)

    if recursive:
        assert bridge_child is not None
        assert bridge_activation is not None
        assert bridge_result is not None
        assert bridge_usage is not None
        assert bridge_context is not None
        assert bridge_projection is not None
        direct_results = tuple(result for result in child_results if result is not bridge_result)
        assert len(direct_results) == 1
        nested_plan = _promoted_nested_recovery_plan(
            root=family,
            root_plan=recovery_plan,
            child=bridge_child,
            activation=bridge_activation,
            result=bridge_result,
            projection=bridge_projection,
            other_direct_results=direct_results,
        )
        nested_family = journal.open_truncation_recovery_family(
            recovery_plan=nested_plan,
            truncation_projection=bridge_projection,
            requested_surface_manifest=surface_manifest,
        )
        nested_results = []
        for nested_child in nested_plan.children:
            nested_context = build_truncation_recovery_child_context(
                parent_context=bridge_context,
                child=nested_child,
            )
            nested_prompt_sha256 = hashlib.sha256(
                render_context(nested_context).encode()
            ).hexdigest()
            nested_activation = journal.activate_truncation_recovery_child(
                nested_child.child_task_id,
                actual_input_sha256=nested_prompt_sha256,
                system_prompt_sha256=blind_task.system_prompt_sha256,
                user_prompt_sha256=nested_prompt_sha256,
                provider_prompt_sha256=hashlib.sha256(
                    f"promoted-nested-provider:{nested_child.child_task_id}".encode()
                ).hexdigest(),
                response_schema_sha256=candidate_review_frame_wire_schema_sha256(),
            )
            journal.mark_truncation_recovery_child_dispatched(nested_child.child_task_id)
            (
                nested_usage,
                nested_normalization,
                nested_batch,
                nested_requests,
                nested_artifact,
            ) = _promoted_child_success_custody(
                child=nested_child,
                activation=nested_activation,
                surface_manifest=surface_manifest,
                surfaces=records,
                execution_evidence=ExecutionEvidenceKind.REAL,
                request_role=parent_role,
                exact_model_id=parent_model_id,
            )
            if include_scheduler_test_refresh_pricing:
                nested_usage = _bind_promoted_child_to_parent_invariant(
                    nested_usage,
                    journal=journal,
                    parent_usage=parent_usage,
                )
            else:
                audit_selection = journal.manifest.bindings.audit_model_selection
                assert audit_selection is not None
                nested_usage = bind_scheduler_test_usage_to_audit_selection(
                    nested_usage,
                    audit_selection,
                )
                nested_routing = dict(nested_usage.routing)
                for key in _INVARIANT_ROUTING_KEYS:
                    nested_routing.pop(key, None)
                    if key in parent_usage.routing:
                        nested_routing[key] = parent_usage.routing[key]
                nested_usage = nested_usage.model_copy(update={"routing": nested_routing})
            nested_usage = _with_context_request_evidence(
                nested_usage,
                nested_context,
                request_role=parent_role,
            )
            nested_usage = transform(nested_usage)
            nested_result = journal.record_truncation_recovery_child_success(
                nested_child.child_task_id,
                usage_record=nested_usage,
                normalization_evidence=nested_normalization,
                normalized_batch=nested_batch,
                requested_surface_requests=nested_requests,
                output_artifact=nested_artifact,
            )
            nested_results.append(nested_result)
            child_usages.append(nested_usage)
            child_contexts.append(nested_context)
            child_artifacts.append(nested_artifact)

        nested_closure = journal.seal_truncation_recovery_family(nested_family.family_id)
        assert nested_closure.closure_status is (
            SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
        )
        root_closure = journal.seal_truncation_recovery_family(family.family_id)
        assert root_closure.closure_status is (
            SchedulerTruncationRecoveryClosureStatus.RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING
        )
        tree_capability, recursive_artifact = verify_recursive_truncation_recovery_tree(
            root_family=family,
            nested_family=nested_family,
            root_closure=root_closure,
            nested_closure=nested_closure,
            root_child_results=child_results,
            nested_child_results=nested_results,
            parent_usage_record=parent_usage,
            bridge_usage_record=bridge_usage,
            leaf_usage_records=child_usages,
            parent_context=parent_context,
            bridge_context=bridge_context,
            leaf_contexts=child_contexts,
            requests=requests,
        )
        promotion = journal.promote_truncation_recovery_family(
            family.family_id,
            tree_capability,
        )
        recursive_surface_capability = (
            journal.issue_promoted_recursive_truncation_recovery_surface_coverage(
                family.family_id,
                tree_capability,
            )
        )
        blind_result = journal.seal_pass_result(SchedulerPassKind.BLIND_SHARD_REVIEW)
        assert blind_result.status is SchedulerPassStatus.COMPLETE
        scheduler_artifact = journal.artifact()
        assert len(child_usages) == len(child_contexts) == len(child_artifacts) == 3
        return _PromotedRecursiveParentSurfaceFixture(
            journal=journal,
            family_id=family.family_id,
            tree_capability=tree_capability,
            surface_capability=recursive_surface_capability,
            promotion=promotion,
            scheduler_artifact=scheduler_artifact,
            structural_artifact=recursive_artifact,
            requests=requests,
            records=records,
            parent_usage=parent_usage,
            bridge_usage=bridge_usage,
            leaf_usages=cast(
                tuple[UsageRecord, UsageRecord, UsageRecord],
                tuple(child_usages),
            ),
            parent_context=parent_context,
            bridge_context=bridge_context,
            leaf_contexts=cast(
                tuple[ContextPackage, ContextPackage, ContextPackage],
                tuple(child_contexts),
            ),
            leaf_artifacts=cast(
                tuple[
                    ModelSurfaceReviewArtifact,
                    ModelSurfaceReviewArtifact,
                    ModelSurfaceReviewArtifact,
                ],
                tuple(child_artifacts),
            ),
            scheduler_live_usages=(
                orientation_usage,
                parent_usage,
                bridge_usage,
                *child_usages,
            ),
        )

    closure = journal.seal_truncation_recovery_family(family.family_id)
    assert closure.closure_status is SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
    closure_capability, structural_artifact = verify_truncation_recovery_closure(
        family=family,
        closure=closure,
        child_results=child_results,
        parent_usage_record=parent_usage,
        child_usage_records=child_usages,
        parent_context=parent_context,
        child_contexts=child_contexts,
        requests=requests,
    )
    promotion = journal.promote_truncation_recovery_family(
        family.family_id,
        closure_capability,
    )
    surface_capability = journal.issue_promoted_truncation_recovery_surface_coverage(
        family.family_id,
        closure_capability,
    )
    blind_result = journal.seal_pass_result(SchedulerPassKind.BLIND_SHARD_REVIEW)
    assert blind_result.status is SchedulerPassStatus.COMPLETE
    scheduler_artifact = journal.artifact()
    scheduler_live_usages: tuple[UsageRecord, ...] = ()
    if supporting_source_task is not None:
        assert supporting_usage is not None
        scheduler_live_usages = (
            orientation_usage,
            supporting_usage,
            parent_usage,
            *child_usages,
        )
    return _PromotedParentSurfaceFixture(
        journal=journal,
        family_id=family.family_id,
        closure_capability=closure_capability,
        surface_capability=surface_capability,
        promotion=promotion,
        scheduler_artifact=scheduler_artifact,
        structural_artifact=structural_artifact,
        requests=requests,
        records=records,
        parent_usage=parent_usage,
        child_usages=tuple(child_usages),
        parent_context=parent_context,
        child_contexts=tuple(child_contexts),
        child_artifacts=tuple(child_artifacts),
        child_specialist_outcomes=tuple(child_specialist_outcomes),
        scheduler_live_usages=scheduler_live_usages,
    )


def _build_promoted_recursive_parent_surface_fixture(
    journal: SchedulerJournal,
    **kwargs: Any,
) -> _PromotedRecursiveParentSurfaceFixture:
    """Reusable exact journal-owned recursive promotion fixture."""

    fixture = _build_promoted_parent_surface_fixture(
        journal,
        recursive=True,
        **kwargs,
    )
    assert isinstance(fixture, _PromotedRecursiveParentSurfaceFixture)
    return fixture


def test_surface_requests_cover_full_deterministic_inventory() -> None:
    _, _, _, requests = _requests()

    assert len(requests) == 9
    assert requests == sorted(requests, key=lambda request: request.surface_id)
    assert set(request.kind for request in requests) == (
        set(ModelReviewSurfaceKind)
        - {
            ModelReviewSurfaceKind.INTERNAL_FUNCTION,
            ModelReviewSurfaceKind.KNOWN_ISSUE_CLASS,
            ModelReviewSurfaceKind.SOURCE_FILE,
        }
    )
    assert all(
        request.contract
        and request.function_or_state_surface
        and (request.allowed_locations or request.allowed_symbols)
        and request.invariant_considered
        for request in requests
    )


def test_applicable_known_issue_adds_hash_bound_critical_surface(config_factory) -> None:
    index, graphs, legacy_invariants = _inventory()
    assessment = detect_protocol_profiles(index, graphs, {_PATH: _SOURCE})
    invariants = InvariantSuite.model_validate(
        {
            **legacy_invariants.model_dump(mode="python"),
            "protocol_profiles": [profile.value for profile in assessment.detected_profiles],
            "protocol_profile_assessment": assessment.model_dump(mode="python"),
        }
    )
    general = _known_issue_item("KI-GENERAL", ProtocolProfileKind.SOLIDITY_GENERAL)
    unknown_oracle = _known_issue_item("KI-ORACLE", ProtocolProfileKind.ORACLE_CONSUMER)
    taxonomy = _known_issue_taxonomy(general, unknown_oracle)

    requests = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        known_issue_taxonomy=taxonomy,
        source_contents_by_path={_PATH: _SOURCE},
    )
    taxonomy_requests = [
        request for request in requests if request.kind is ModelReviewSurfaceKind.KNOWN_ISSUE_CLASS
    ]

    assert len(taxonomy_requests) == 1
    request = taxonomy_requests[0]
    assert request.subject_id == general.review_surface_subject_id
    assert request.invariant_considered == general.defensive_question
    assert request.critical
    assert request.allowed_locations
    assert classify_model_surface_risk(request) is ModelSurfaceRiskTier.T0
    assert unknown_oracle.review_surface_subject_id not in {item.subject_id for item in requests}

    coverage = build_model_review_coverage(
        config_factory(),
        usage_records=[],
        review_artifacts=[],
        review_contexts_by_request={},
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        known_issue_taxonomy=taxonomy,
        source_contents_by_path={_PATH: _SOURCE},
    )
    taxonomy_surfaces = [
        surface
        for surface in coverage.surfaces
        if surface.kind is ModelReviewSurfaceKind.KNOWN_ISSUE_CLASS
    ]
    assert [surface.subject_id for surface in taxonomy_surfaces] == [
        general.review_surface_subject_id
    ]
    assert not taxonomy_surfaces[0].reviewed


def test_content_bound_known_issue_surface_can_earn_exact_review_credit(config_factory) -> None:
    config = config_factory()
    index, graphs, legacy_invariants = _inventory()
    assessment = detect_protocol_profiles(index, graphs, {_PATH: _SOURCE})
    invariants = InvariantSuite.model_validate(
        {
            **legacy_invariants.model_dump(mode="python"),
            "protocol_profiles": [profile.value for profile in assessment.detected_profiles],
            "protocol_profile_assessment": assessment.model_dump(mode="python"),
        }
    )
    item = _known_issue_item("KI-GENERAL", ProtocolProfileKind.SOLIDITY_GENERAL)
    taxonomy = _known_issue_taxonomy(item)
    requests = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        known_issue_taxonomy=taxonomy,
        source_contents_by_path={_PATH: _SOURCE},
    )
    request = next(
        request for request in requests if request.kind is ModelReviewSurfaceKind.KNOWN_ISSUE_CLASS
    )
    with _authorized_ordinary_review_evidence(
        config,
        index=index,
        graphs=graphs,
        requests=[request],
        reviewers=(("source_audit", config.models.source_audit.primary),),
    ) as evidence:
        coverage = build_model_review_coverage(
            config,
            usage_records=list(evidence.usage_records),
            review_artifacts=list(evidence.artifacts),
            review_contexts_by_request=evidence.contexts_by_request,
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            known_issue_taxonomy=taxonomy,
            source_contents_by_path={_PATH: _SOURCE},
            ordinary_review_authorizations=evidence.authorizations,
        )

    surface = next(
        surface for surface in coverage.surfaces if surface.surface_id == request.surface_id
    )
    assert surface.reviewed
    assert surface.evidence_references[0].credited
    taxonomy_coverage = build_known_issue_taxonomy_coverage(
        LoadedKnownIssueTaxonomy(
            corpus=taxonomy,
            raw_bytes=b"",
            raw_sha256="f" * 64,
        ),
        invariants=invariants,
        model_review_coverage=coverage,
    )
    assert taxonomy_coverage.dispositions[0].disposition.value == "REVIEWED"
    assert taxonomy_coverage.dispositions[0].reviewed_surface_ids == [request.surface_id]


def test_applicable_noncritical_known_issue_remains_mandatory_t0_surface(
    config_factory,
) -> None:
    index, graphs, legacy_invariants = _inventory()
    assessment = detect_protocol_profiles(index, graphs, {_PATH: _SOURCE})
    invariants = InvariantSuite.model_validate(
        {
            **legacy_invariants.model_dump(mode="python"),
            "protocol_profiles": [profile.value for profile in assessment.detected_profiles],
            "protocol_profile_assessment": assessment.model_dump(mode="python"),
        }
    )
    item = _known_issue_item(
        "KI-NONCRITICAL",
        ProtocolProfileKind.SOLIDITY_GENERAL,
        criticality=KnownIssueCriticality.NON_CRITICAL,
    )

    requests = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        known_issue_taxonomy=_known_issue_taxonomy(item),
        source_contents_by_path={_PATH: _SOURCE},
    )
    request = next(
        request for request in requests if request.kind is ModelReviewSurfaceKind.KNOWN_ISSUE_CLASS
    )

    assert request.subject_id == item.review_surface_subject_id
    assert request.critical
    assert classify_model_surface_risk(request) is ModelSurfaceRiskTier.T0
    plan = build_model_surface_coverage_plan(
        requests,
        (),
        surface_scope_by_id={
            surface.surface_id: "scope:synthetic-taxonomy" for surface in requests
        },
    )
    requirement = next(
        requirement
        for requirement in plan.requirements
        if requirement.surface_id == request.surface_id
    )
    assert requirement.risk_tier is ModelSurfaceRiskTier.T0


def test_semantic_shard_request_uses_exact_fallback_parser_entity_custody() -> None:
    path = "test/audit/AuditHarness.t.sol"
    source = "contract AuditHarness {\n    function check() external {}\n}\n"
    source_sha256 = hashlib.sha256(source.encode()).hexdigest()
    index = SoliditySymbolIndex(
        projects=[
            SolidityProjectMetadata(
                project_type=SolidityProjectType.FOUNDRY,
                project_root=".",
                source_directories=["src"],
                test_directories=["test"],
            )
        ],
        entities=[
            SolidityEntity(
                id="contract:AuditHarness",
                kind=SolidityEntityKind.CONTRACT,
                name="AuditHarness",
                contract_name=None,
                path=path,
                start_line=1,
                end_line=3,
                byte_start=0,
                byte_end=len(source.encode()),
                source_hash=source_sha256,
                provenance=SolidityProvenance.FALLBACK,
                confidence=0.55,
                transformation="synthetic_fallback_parser",
            )
        ],
        fallback_sources=[path],
    )

    request = build_semantic_shard_source_review_request(
        index=index,
        source_path=path,
        source_content=source,
        source_sha256=source_sha256,
    )

    assert request.kind is ModelReviewSurfaceKind.CONTRACT
    assert request.subject_id == "contract:AuditHarness"
    assert request.allowed_locations == (
        Location(
            path=path,
            start_line=1,
            end_line=3,
            symbol="AuditHarness",
            content_hash=source_sha256,
        ),
    )


def test_semantic_shard_request_rejects_source_drift() -> None:
    path = "test/audit/AuditHarness.t.sol"
    source = "contract AuditHarness {}\n"
    source_sha256 = hashlib.sha256(source.encode()).hexdigest()
    entity = SolidityEntity(
        id="contract:AuditHarness",
        kind=SolidityEntityKind.CONTRACT,
        name="AuditHarness",
        path=path,
        start_line=1,
        end_line=1,
        byte_start=0,
        byte_end=len(source.encode()),
        source_hash=source_sha256,
        provenance=SolidityProvenance.FALLBACK,
        confidence=0.55,
        transformation="synthetic_fallback_parser",
    )
    project = SolidityProjectMetadata(
        project_type=SolidityProjectType.FOUNDRY,
        project_root=".",
        test_directories=["test"],
    )

    with pytest.raises(ValueError, match="exact source hash"):
        build_semantic_shard_source_review_request(
            index=SoliditySymbolIndex(
                projects=[project],
                entities=[entity],
                fallback_sources=[path],
            ),
            source_path=path,
            source_content=source + "// drift\n",
            source_sha256=source_sha256,
        )


@pytest.mark.parametrize(
    ("ast_backed", "fallback_backed", "entity_provenance", "expected_message"),
    [
        (False, False, SolidityProvenance.FALLBACK, "exact index provenance"),
        (True, True, SolidityProvenance.FALLBACK, "exact index provenance"),
        (False, True, SolidityProvenance.COMPILER, "index differs from current source bytes"),
    ],
)
def test_semantic_shard_request_rejects_missing_ambiguous_or_wrong_provenance(
    ast_backed: bool,
    fallback_backed: bool,
    entity_provenance: SolidityProvenance,
    expected_message: str,
) -> None:
    path = "test/audit/AuditHarness.t.sol"
    source = "contract AuditHarness {}\n"
    source_sha256 = hashlib.sha256(source.encode()).hexdigest()
    entity = SolidityEntity(
        id="contract:AuditHarness",
        kind=SolidityEntityKind.CONTRACT,
        name="AuditHarness",
        path=path,
        start_line=1,
        end_line=1,
        byte_start=0,
        byte_end=len(source.encode()),
        source_hash=source_sha256,
        provenance=entity_provenance,
        confidence=0.55,
        transformation="synthetic_fallback_parser",
    )
    project = SolidityProjectMetadata(
        project_type=SolidityProjectType.FOUNDRY,
        project_root=".",
        test_directories=["test"],
    )

    with pytest.raises(ValueError, match=expected_message):
        build_semantic_shard_source_review_request(
            index=SoliditySymbolIndex(
                projects=[project],
                entities=[entity],
                ast_sources=[path] if ast_backed else [],
                fallback_sources=[path] if fallback_backed else [],
            ),
            source_path=path,
            source_content=source,
            source_sha256=source_sha256,
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
        id="inv-00000000000000000002",
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
            "edges": [edge for edge in graphs.edges if edge.graph is SolidityGraphKind.STATE_WRITE],
            "retained_occurrences": _edge_occurrences(
                [edge for edge in graphs.edges if edge.graph is SolidityGraphKind.STATE_WRITE]
            ),
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
                "inv-00000000000000000003",
                entity_ids=[contract.id, state.id],
                location=_entity_citation(contract).location,
            ),
            invariant(
                "inv-00000000000000000004",
                entity_ids=[state.id],
                location=_entity_citation(state).location,
            ),
            invariant(
                "inv-00000000000000000005",
                entity_ids=[state.id],
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

    with _authorized_ordinary_review_evidence(
        config,
        index=index,
        graphs=graphs,
        requests=requests,
        reviewers=(
            ("source_audit", config.models.source_audit.primary),
            ("business_logic", config.models.business_logic.primary),
            ("configuration", config.models.configuration.primary),
        ),
    ) as evidence:
        first_request_id = evidence.usage_records[0].request_id
        one_lineage = build_model_review_coverage(
            config,
            usage_records=[evidence.usage_records[0]],
            review_artifacts=[evidence.artifacts[0]],
            review_contexts_by_request={
                first_request_id: evidence.contexts_by_request[first_request_id]
            },
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            audited_suite_coverage=audited_suite,
            ordinary_review_authorizations=(evidence.authorizations[0],),
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
            usage_records=list(evidence.usage_records),
            review_artifacts=list(evidence.artifacts),
            review_contexts_by_request=evidence.contexts_by_request,
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            audited_suite_coverage=audited_suite,
            ordinary_review_authorizations=evidence.authorizations,
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
        id="inv-00000000000000000006",
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
    extended_edges = [*graphs.edges, harness_edge, source_id_spoofed_test_edge]
    extended_graphs = graphs.model_copy(
        update={
            "edges": extended_edges,
            "retained_occurrences": _edge_occurrences(extended_edges),
        }
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
    partial_edges = [
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
    partial_graphs = graphs.model_copy(
        update={
            "edges": partial_edges,
            "retained_occurrences": _edge_occurrences(partial_edges),
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
        id="inv-00000000000000000007",
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


def test_omitted_external_call_cannot_shrink_complete_surface_inventory(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants = _inventory()
    audited_suite = _audited_gap_coverage(index, graphs, invariants)
    complete_requests = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
    )
    retained_edges = [
        edge for edge in graphs.edges if edge.graph is not SolidityGraphKind.EXTERNAL_CALL
    ]
    omission = SolidityGraphOmission.build(
        graph=SolidityGraphKind.EXTERNAL_CALL,
        candidate_count=1,
        retained_count=0,
        omitted_count=1,
        omitted_canonical_bytes=320,
        omitted_stream_sha256=hashlib.sha256(b"synthetic omitted external call").hexdigest(),
        omitted_sample_sha256s=(
            hashlib.sha256(b"synthetic omitted external call sample").hexdigest(),
        ),
    )
    partial_graphs = SolidityGraphSet.model_validate(
        {
            **graphs.model_dump(mode="python"),
            "edges": retained_edges,
            "retained_occurrences": _edge_occurrences(retained_edges),
            "coverage": {
                **graphs.coverage,
                SolidityGraphKind.EXTERNAL_CALL.value: 0,
            },
            "generation_complete": False,
            "edge_omissions": (omission,),
        }
    )
    partial_requests = build_model_surface_requests(
        index=index,
        graphs=partial_graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    assert len(partial_requests) == len(complete_requests) - 1
    assert all(request.kind is not ModelReviewSurfaceKind.CALL for request in partial_requests)
    with pytest.raises(ValueError, match="claims complete"):
        build_model_surface_requests(
            index=index,
            graphs=partial_graphs,
            invariants=invariants,
            economic_simulations=[],
            audited_suite_coverage=audited_suite,
        )
    with pytest.raises(ValueError, match="claims complete"):
        build_model_review_coverage(
            config,
            usage_records=[],
            review_artifacts=[],
            review_contexts_by_request={},
            index=index,
            graphs=partial_graphs,
            invariants=invariants,
            economic_simulations=[],
            audited_suite_coverage=audited_suite,
        )

    gate = model_surface_assignment_feasibility_gate(
        config,
        index=index,
        graphs=partial_graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        requests=partial_requests,
        assignments={},
        required=True,
    )

    assert not gate.passed
    assert gate.state is AnalysisState.NOT_ANALYZED
    assert "critical classification was incomplete" in gate.detail


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


@pytest.mark.parametrize("include_known_surface", [False, True])
def test_supplemental_surface_artifacts_cannot_inflate_or_receive_product_coverage_credit(
    config_factory: Callable[..., AuditConfig],
    include_known_surface: bool,
) -> None:
    config = config_factory()
    index, graphs, invariants, authoritative_requests = _requests()
    known = next(
        request
        for request in authoritative_requests
        if request.kind is ModelReviewSurfaceKind.ENTRY_POINT
    )
    supplemental_subject = "function:SupplementalAuditHarness.check"
    supplemental = ModelSurfaceReviewRequest.model_validate(
        {
            **known.model_dump(mode="python"),
            "surface_id": ModelSurfaceReviewRequest.calculate_surface_id(
                known.kind,
                supplemental_subject,
            ),
            "subject_id": supplemental_subject,
            "contract": "SupplementalAuditHarness",
            "function_or_state_surface": "check()",
            "critical": False,
        }
    )
    requested = sorted(
        [supplemental, *([known] if include_known_surface else [])],
        key=lambda request: request.surface_id,
    )
    usage = _usage(
        "source_audit",
        config.models.source_audit.primary,
        f"request-supplemental-{'mixed' if include_known_surface else 'only'}",
    )
    contexts = _review_contexts(requested, [usage], index, graphs)

    baseline = build_model_review_coverage(
        config,
        usage_records=[],
        review_artifacts=[],
        review_contexts_by_request={},
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )
    coverage = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[_artifact(requested, usage, index, graphs)],
        review_contexts_by_request=contexts,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    authoritative_ids = {request.surface_id for request in authoritative_requests}
    assert coverage.overall.denominator == baseline.overall.denominator
    assert coverage.overall.numerator == baseline.overall.numerator == 0
    assert {surface.surface_id for surface in coverage.surfaces} == authoritative_ids
    assert supplemental.surface_id not in authoritative_ids
    assert any("referenced unknown surfaces" in item for item in coverage.limitations)
    if include_known_surface:
        known_surface = next(
            surface for surface in coverage.surfaces if surface.surface_id == known.surface_id
        )
        assert len(known_surface.evidence_references) == 1
        assert not known_surface.evidence_references[0].credited
        assert "outside the deterministic inventory" in known_surface.evidence_references[0].reason
    else:
        assert all(not surface.evidence_references for surface in coverage.surfaces)


def test_supplemental_surface_failures_are_bounded_without_hiding_accounting(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, authoritative_requests = _requests()
    known = next(
        request
        for request in authoritative_requests
        if request.kind is ModelReviewSurfaceKind.ENTRY_POINT
    )
    supplemental_subject = "function:SupplementalAuditHarness.check"
    supplemental = ModelSurfaceReviewRequest.model_validate(
        {
            **known.model_dump(mode="python"),
            "surface_id": ModelSurfaceReviewRequest.calculate_surface_id(
                known.kind,
                supplemental_subject,
            ),
            "subject_id": supplemental_subject,
            "contract": "SupplementalAuditHarness",
            "function_or_state_surface": "check()",
            "critical": False,
        }
    )
    usages = [
        _usage(
            "source_audit",
            config.models.source_audit.primary,
            f"request-supplemental-overflow-{ordinal:03d}",
        )
        for ordinal in range(101)
    ]
    contexts = _review_contexts([supplemental], usages, index, graphs)
    artifacts = [_artifact([supplemental], usage, index, graphs) for usage in usages]

    baseline = build_model_review_coverage(
        config,
        usage_records=[],
        review_artifacts=[],
        review_contexts_by_request={},
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )
    coverage = build_model_review_coverage(
        config,
        usage_records=usages,
        review_artifacts=artifacts,
        review_contexts_by_request=contexts,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    artifact_identities = tuple(sorted(artifact.artifact_sha256 for artifact in artifacts))
    identity_set_sha256 = hashlib.sha256(
        json.dumps(
            {"category": "unknown_surfaces", "identities": artifact_identities},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    expected_summary = (
        "model-review artifacts referenced unknown surfaces; "
        "affected_identity_count=101; "
        f"affected_identity_set_sha256={identity_set_sha256}"
    )

    assert coverage.overall == baseline.overall
    assert coverage.by_kind == baseline.by_kind
    assert coverage.critical == baseline.critical
    assert len(coverage.limitations) <= 100
    assert expected_summary in coverage.limitations
    assert sum("referenced unknown surfaces" in item for item in coverage.limitations) == 1
    assert all(not surface.evidence_references for surface in coverage.surfaces)


@pytest.mark.parametrize(
    ("mutated_kind", "mutated_content_hash", "expected"),
    [
        (None, None, True),
        (ModelReviewSurfaceKind.SOURCE_FILE.value, None, False),
        (None, "0" * 64, False),
    ],
)
def test_synthetic_path_gate_requires_exact_typed_index_location(
    mutated_kind: str | None,
    mutated_content_hash: str | None,
    expected: bool,
) -> None:
    index, _, _, requests = _requests()
    request = next(
        request for request in requests if request.kind is ModelReviewSurfaceKind.ENTRY_POINT
    )
    request_payload = request.model_dump(mode="json")
    if mutated_kind is not None:
        request_payload["kind"] = mutated_kind
    if mutated_content_hash is not None:
        request_payload["allowed_locations"][0]["content_hash"] = mutated_content_hash
    prompt = "\n".join(
        [
            "<TRUSTED_MODEL_SURFACE_REQUESTS_JSON>",
            json.dumps([request_payload], sort_keys=True),
            "</TRUSTED_MODEL_SURFACE_REQUESTS_JSON>",
            "<DETERMINISTIC_SOLIDITY_FACTS_JSON>",
            json.dumps({"symbol_index": index.model_dump(mode="json")}, sort_keys=True),
            "</DETERMINISTIC_SOLIDITY_FACTS_JSON>",
        ]
    )

    assert _requested_surface_covers_path(prompt, _PATH) is expected


def test_synthetic_candidate_identity_is_bound_to_request_and_exact_delivered_excerpt() -> None:
    index, _, _, requests = _requests()
    entry_request = next(
        request for request in requests if request.kind is ModelReviewSurfaceKind.ENTRY_POINT
    )
    state_request = next(
        request for request in requests if request.kind is ModelReviewSurfaceKind.STATE
    )

    excerpt_content = "".join(_SOURCE.splitlines(keepends=True)[18:23])

    def prompt_for(
        request: ModelSurfaceReviewRequest,
        *,
        path: str = _PATH,
        content: str = excerpt_content,
        requested_surface_path: str | None = None,
    ) -> str:
        start_line = 19
        end_line = start_line + len(content.splitlines()) - 1
        content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        sentinel = f"MMAUDIT-UNTRUSTED-{content_sha256.upper()}"
        request_payload = request.model_dump(mode="json")
        if requested_surface_path is not None:
            request_payload["allowed_locations"][0]["path"] = requested_surface_path
        return "\n".join(
            [
                "<TRUSTED_MODEL_SURFACE_REQUESTS_JSON>",
                json.dumps([request_payload], sort_keys=True),
                "</TRUSTED_MODEL_SURFACE_REQUESTS_JSON>",
                "<DETERMINISTIC_SOLIDITY_FACTS_JSON>",
                json.dumps({"symbol_index": index.model_dump(mode="json")}, sort_keys=True),
                "</DETERMINISTIC_SOLIDITY_FACTS_JSON>",
                "<REPOSITORY_EXCERPT_METADATA_JSON>",
                json.dumps(
                    {
                        "path": path,
                        "start_line": start_line,
                        "end_line": end_line,
                        "content_sha256": content_sha256,
                    },
                    sort_keys=True,
                ),
                "</REPOSITORY_EXCERPT_METADATA_JSON>",
                f"-----BEGIN {sentinel}-----",
                content,
                f"-----END {sentinel}-----",
            ]
        )

    entry_prompt = prompt_for(entry_request)
    entry_candidate_id = _request_scoped_candidate_id(
        "specialist-access",
        entry_prompt,
        _PATH,
        20,
        22,
        logical_request_id="scheduler-request-a",
    )

    assert entry_candidate_id is not None
    assert entry_candidate_id == _request_scoped_candidate_id(
        "specialist-access",
        entry_prompt,
        _PATH,
        20,
        22,
        logical_request_id="scheduler-request-a",
    )
    assert entry_candidate_id == _request_scoped_candidate_id(
        "specialist-access",
        prompt_for(state_request, requested_surface_path="src/Dependency.sol"),
        _PATH,
        20,
        22,
        logical_request_id="scheduler-request-a",
    )
    assert entry_candidate_id != _request_scoped_candidate_id(
        "specialist-access",
        entry_prompt,
        _PATH,
        20,
        22,
        logical_request_id="scheduler-request-b",
    )
    changed_excerpt = "".join(
        _SOURCE.replace("line 20", "line XX").splitlines(keepends=True)[18:23]
    )
    assert entry_candidate_id != _request_scoped_candidate_id(
        "specialist-access",
        prompt_for(state_request, content=changed_excerpt),
        _PATH,
        20,
        22,
        logical_request_id="scheduler-request-a",
    )
    assert (
        _request_scoped_candidate_id(
            "specialist-access",
            entry_prompt,
            "src/OutsideScope.sol",
            20,
            22,
            logical_request_id="scheduler-request-a",
        )
        is None
    )
    assert (
        _request_scoped_candidate_id(
            "specialist-access",
            prompt_for(entry_request, path="src/OutsideScope.sol"),
            _PATH,
            20,
            22,
            logical_request_id="scheduler-request-a",
        )
        is None
    )
    assert (
        _request_scoped_candidate_id(
            "specialist-access",
            entry_prompt,
            _PATH,
            18,
            22,
            logical_request_id="scheduler-request-a",
        )
        is None
    )


def test_maximum_assurance_fixture_candidates_follow_exact_delivered_source() -> None:
    source = "\n".join(
        (
            "    function drain(address payable recipient) external {",
            "        recipient.transfer(address(this).balance);",
            "    }",
        )
    )
    source_sha256 = hashlib.sha256(source.encode()).hexdigest()
    sentinel = f"MMAUDIT-UNTRUSTED-{source_sha256.upper()}"
    prompt = "\n".join(
        (
            "<REPOSITORY_EXCERPT_METADATA_JSON>",
            json.dumps(
                {
                    "path": "src/AccessVault.sol",
                    "start_line": 12,
                    "end_line": 14,
                    "content_sha256": source_sha256,
                },
                sort_keys=True,
            ),
            "</REPOSITORY_EXCERPT_METADATA_JSON>",
            f"-----BEGIN {sentinel}-----",
            source,
            f"-----END {sentinel}-----",
        )
    )

    findings = _maximum_assurance_candidates(
        prompt,
        logical_request_id=f"scheduler-request-{'a' * 64}",
        role="source_audit",
        include_vulnerabilities=True,
        include_safe_control=False,
    )

    assert len(findings) == 1
    assert findings[0]["locations"][0]["path"] == "src/AccessVault.sol"
    assert findings[0]["role"] == "source_audit"
    assert findings[0]["evidence"][0]["source"] == "source_audit"
    assert (
        _maximum_assurance_candidates(
            "no source excerpt",
            logical_request_id=f"scheduler-request-{'b' * 64}",
            role="source_audit",
            include_vulnerabilities=True,
            include_safe_control=False,
        )
        == []
    )


def test_synthetic_candidate_identity_rejects_tampered_delivered_excerpt() -> None:
    content = "line one\nline two\n"
    content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
    sentinel = f"MMAUDIT-UNTRUSTED-{content_sha256.upper()}"
    prompt = "\n".join(
        [
            "<REPOSITORY_EXCERPT_METADATA_JSON>",
            json.dumps(
                {
                    "path": _PATH,
                    "start_line": 1,
                    "end_line": 2,
                    "content_sha256": content_sha256,
                },
                sort_keys=True,
            ),
            "</REPOSITORY_EXCERPT_METADATA_JSON>",
            f"-----BEGIN {sentinel}-----",
            f"{content}tampered",
            f"-----END {sentinel}-----",
        ]
    )

    with pytest.raises(AssertionError, match="hash differs"):
        _request_scoped_candidate_id(
            "specialist-access",
            prompt,
            _PATH,
            1,
            2,
            logical_request_id="scheduler-request-a",
        )


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
    with _authorized_ordinary_review_evidence(
        config,
        index=index,
        graphs=graphs,
        requests=requests,
        reviewers=(
            ("source_audit", config.models.source_audit.primary),
            ("business_logic", config.models.business_logic.primary),
            ("configuration", config.models.configuration.primary),
        ),
    ) as evidence:
        coverage = build_model_review_coverage(
            config,
            usage_records=list(evidence.usage_records),
            review_artifacts=list(evidence.artifacts),
            review_contexts_by_request=evidence.contexts_by_request,
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            audited_suite_coverage=audited_suite,
            ordinary_review_authorizations=evidence.authorizations,
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
    with _authorized_ordinary_review_evidence(
        config,
        index=index,
        graphs=graphs,
        requests=selected,
        reviewers=(("source_audit", config.models.source_audit.primary),),
    ) as evidence:
        coverage = build_model_review_coverage(
            config,
            usage_records=list(evidence.usage_records),
            review_artifacts=list(evidence.artifacts),
            review_contexts_by_request=evidence.contexts_by_request,
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            ordinary_review_authorizations=evidence.authorizations,
        )

    by_id = {surface.surface_id: surface for surface in coverage.surfaces}
    assert all(by_id[request.surface_id].reviewed for request in selected)


def test_recovery_surface_usage_requires_exact_external_request_limit_coordinates(
    config_factory: Callable[..., AuditConfig],
) -> None:
    from tests.unit.test_usage import _with_request_limit_inventory

    config = config_factory()
    index, graphs, invariants, requests = _requests()
    selected = [
        next(request for request in requests if request.kind is ModelReviewSurfaceKind.ENTRY_POINT)
    ]
    request_id = "scheduler-recovery-request-" + "a" * 64
    request_limit_scope = "scheduler-request-" + "b" * 64
    provisional = _usage(
        "source_audit",
        config.models.source_audit.primary,
        request_id,
    )
    contexts = _review_contexts(selected, [provisional], index, graphs)
    planned = rebind_synthetic_token_plan(provisional)
    usage = reattest_synthetic_real_usage(
        _with_request_limit_inventory(
            planned,
            request_limit_scope=request_limit_scope,
            request_limit_count_before=1,
        )
    )
    artifact = _artifact(
        selected,
        usage,
        index,
        graphs,
        context=contexts[request_id][0],
    )

    missing = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[artifact],
        review_contexts_by_request=contexts,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )
    exact = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[artifact],
        review_contexts_by_request=contexts,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        recovery_usage_coordinates=((request_id, request_limit_scope, 1),),
    )
    missing_surface = next(
        surface for surface in missing.surfaces if surface.surface_id == selected[0].surface_id
    )
    exact_surface = next(
        surface for surface in exact.surfaces if surface.surface_id == selected[0].surface_id
    )
    assert not missing_surface.reviewed
    assert not exact_surface.reviewed
    assert (
        "lacked exact journal-derived pre-dispatch authorization"
        in exact_surface.evidence_references[0].reason
    )
    with pytest.raises(ValueError, match="unique and sorted"):
        build_model_review_coverage(
            config,
            usage_records=[usage],
            review_artifacts=[artifact],
            review_contexts_by_request=contexts,
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            recovery_usage_coordinates=(
                (request_id, request_limit_scope, 1),
                (request_id, request_limit_scope, 1),
            ),
        )


def _config_with_promoted_surface_model(
    config: AuditConfig,
    model_id: str,
) -> AuditConfig:
    canonical = config.models.source_audit.primary
    registry = tuple(
        entry.model_copy(update={"aliases": tuple(sorted({*entry.aliases, model_id}))})
        if entry.canonical_model_id == canonical
        else entry
        for entry in config.models.registry
    )
    source_audit = config.models.source_audit.model_copy(
        update={"fallbacks": tuple(sorted({*config.models.source_audit.fallbacks, model_id}))}
    )
    return config.model_copy(
        update={
            "models": config.models.model_copy(
                update={"registry": registry, "source_audit": source_audit}
            )
        }
    )


def _config_with_promoted_surface_manifest_lineage(
    config: AuditConfig,
    model_id: str,
) -> AuditConfig:
    configured = _config_with_promoted_surface_model(config, model_id)
    root_lineage = "sha256:" + hashlib.sha256(model_id.encode()).hexdigest()
    registry = tuple(
        entry.model_copy(update={"root_lineage": root_lineage})
        if entry.canonical_model_id == configured.models.source_audit.primary
        else entry
        for entry in configured.models.registry
    )
    return configured.model_copy(
        update={
            "models": configured.models.model_copy(update={"registry": registry}),
            "privacy": configured.privacy.model_copy(
                update={
                    "approved_model_lineages": tuple(
                        sorted({*configured.privacy.approved_model_lineages, root_lineage})
                    )
                }
            ),
        }
    )


def _config_with_registry_only_promoted_surface_model(
    config: AuditConfig,
    model_id: str,
) -> AuditConfig:
    configured = _config_with_promoted_surface_manifest_lineage(config, model_id)
    source_audit = configured.models.source_audit.model_copy(
        update={
            "fallbacks": tuple(
                fallback
                for fallback in configured.models.source_audit.fallbacks
                if fallback != model_id
            )
        }
    )
    return configured.model_copy(
        update={"models": configured.models.model_copy(update={"source_audit": source_audit})}
    )


def _with_provider_visible_registry_alias(
    config: AuditConfig,
    *,
    requested_model: str,
    alias: str,
    same_root: bool,
) -> AuditConfig:
    """Register one synthetic provider alias on the requested or a distinct lineage."""

    requested_entry = next(
        entry for entry in config.models.registry if requested_model in entry.model_ids()
    )
    target_entry = (
        requested_entry
        if same_root
        else next(
            entry
            for entry in config.models.registry
            if entry.root_lineage != requested_entry.root_lineage
        )
    )
    registry = tuple(
        entry.model_copy(update={"aliases": tuple(sorted({*entry.aliases, alias}))})
        if entry is target_entry
        else entry
        for entry in config.models.registry
    )
    return config.model_copy(
        update={
            "models": config.models.model_copy(update={"registry": registry}),
            "privacy": config.privacy.model_copy(
                update={
                    "approved_model_lineages": tuple(
                        sorted(
                            {
                                *config.privacy.approved_model_lineages,
                                target_entry.root_lineage,
                            }
                        )
                    )
                }
            ),
        }
    )


def _with_provider_visible_model_alias(usage: UsageRecord, alias: str) -> UsageRecord:
    """Rebind a synthetic completion whose provider-visible identity is one alias."""

    return bind_synthetic_usage_identity(
        usage.model_copy(
            update={
                "returned_model": alias,
                "actual_model": alias,
                "routing": {
                    **usage.routing,
                    "selected_model": alias,
                    "canonical_model": alias,
                    "accepted_model_aliases": sorted({usage.requested_model, alias}),
                },
            }
        )
    )


def _promoted_surface_inputs() -> tuple[
    SoliditySymbolIndex,
    SolidityGraphSet,
    InvariantSuite,
    AuditedSuiteCoverage,
    tuple[ModelSurfaceReviewRequest, ...],
]:
    index, base_graphs, invariants = _inventory()
    nodes = tuple(
        SolidityGraphNode(
            id=entity.id,
            kind=SolidityGraphNodeKind.ENTITY,
            label=entity.signature or entity.name,
            path=entity.path,
            start_line=entity.start_line,
            end_line=entity.end_line,
            source_hash=entity.source_hash,
            provenance=entity.provenance,
            confidence=entity.confidence,
            transformation="promoted_surface_exact_entity_node",
        )
        for entity in index.entities
    )
    retained_occurrences = tuple(
        sorted(
            (
                *_edge_occurrences(list(base_graphs.edges)),
                *(
                    SolidityGraphRetainedOccurrence(
                        subject_kind=SolidityGraphOccurrenceKind.GRAPH_NODE,
                        subject_sha256=solidity_graph_occurrence_sha256(
                            SolidityGraphOccurrenceKind.GRAPH_NODE,
                            node,
                        ),
                        occurrence_count=1,
                    )
                    for node in nodes
                ),
            ),
            key=lambda item: (item.subject_kind.value, item.subject_sha256),
        )
    )
    graphs = base_graphs.model_copy(
        update={
            "nodes": list(nodes),
            "retained_occurrences": retained_occurrences,
            "analyzed_graphs": list(
                sorted(
                    {
                        *base_graphs.analyzed_graphs,
                        *(edge.graph for edge in base_graphs.edges),
                    },
                    key=lambda item: item.value,
                )
            ),
        }
    )
    audited_suite = _audited_gap_coverage(index, graphs, invariants)
    requests = tuple(
        build_model_surface_requests(
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            audited_suite_coverage=audited_suite,
        )
    )
    return index, graphs, invariants, audited_suite, requests


def _promoted_surface_context(
    requests: tuple[ModelSurfaceReviewRequest, ...],
    usage: UsageRecord,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet,
) -> ContextPackage:
    context = _review_context(list(requests), usage, index, graphs)
    repository_map = context.repository_map.model_copy(
        update={
            "files": [
                RepositoryFile(
                    path=_PATH,
                    size=len(_SOURCE.encode()),
                    lines=len(_SOURCE.splitlines()),
                    sha256=hashlib.sha256(_SOURCE.encode()).hexdigest(),
                    language="Solidity",
                )
            ]
        }
    )
    return _with_exact_context_bytes(context.model_copy(update={"repository_map": repository_map}))


def _coverage_from_promoted_surface_fixture(
    config: AuditConfig,
    fixture: _PromotedParentSurfaceFixture,
    *,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet,
    invariants: InvariantSuite,
    audited_suite_coverage: AuditedSuiteCoverage,
    review_artifacts: list[ModelSurfaceReviewArtifact] | None = None,
    ordinary_review_authorizations: tuple[ModelReviewPreDispatchAuthorization, ...] = (),
    include_promoted_surface_coverage: bool = True,
) -> ModelReviewCoverage:
    recovery_coordinates = tuple(
        (
            request.logical_request_id,
            request.request_limit_scope,
            request.request_limit_count_before,
        )
        for request in fixture.scheduler_artifact.recovery_model_requests
    )
    return build_model_review_coverage(
        config,
        usage_records=[fixture.parent_usage, *fixture.child_usages],
        review_artifacts=(
            list(fixture.child_artifacts) if review_artifacts is None else review_artifacts
        ),
        review_contexts_by_request={
            fixture.parent_usage.request_id: [fixture.parent_context],
            **{
                usage.request_id: [context]
                for usage, context in zip(
                    fixture.child_usages,
                    fixture.child_contexts,
                    strict=True,
                )
            },
        },
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        minimum_critical_root_lineages=2,
        audited_suite_coverage=audited_suite_coverage,
        source_contents_by_path={_PATH: _SOURCE},
        recovery_usage_coordinates=recovery_coordinates,
        promoted_recovery_surface_coverages=(
            (fixture.surface_capability,) if include_promoted_surface_coverage else ()
        ),
        ordinary_review_authorizations=ordinary_review_authorizations,
    )


def _basic_promoted_surface_fixture(
    root: Path,
    *,
    requests: tuple[ModelSurfaceReviewRequest, ...],
    records: tuple[ModelSurfaceReviewRecord, ...],
    context: ContextPackage,
    parent_role: str = "source_audit",
    usage_transform: Callable[[UsageRecord], UsageRecord] | None = None,
) -> _PromotedParentSurfaceFixture:
    inventory = _scheduler_inventory(one_shard=True)
    journal = _create_test_scheduler_journal(
        root,
        bindings=_promoted_surface_bindings(),
        shard_inventory=inventory,
        privacy_evidence_custody=_scheduler_privacy_custody(
            source_sha256=inventory.source_tree_sha256
        ),
    )
    return _build_promoted_parent_surface_fixture(
        journal,
        requests=requests,
        records=records,
        parent_context=context,
        parent_model_id="synthetic/auditor-v1",
        parent_root_lineage="sha256:" + hashlib.sha256(b"synthetic/auditor-v1").hexdigest(),
        parent_role=parent_role,
        usage_transform=usage_transform,
        supporting_source_model_id=(
            "synthetic/auditor-v1"
            if manifest_module._WHOLE_PROTOCOL_REVIEW_ROLE_RE.fullmatch(parent_role) is not None
            else None
        ),
        supporting_source_root_lineage=(
            "sha256:" + hashlib.sha256(b"synthetic/auditor-v1").hexdigest()
            if manifest_module._WHOLE_PROTOCOL_REVIEW_ROLE_RE.fullmatch(parent_role) is not None
            else None
        ),
    )


def _basic_promoted_recursive_surface_fixture(
    root: Path,
    *,
    requests: tuple[ModelSurfaceReviewRequest, ...],
    records: tuple[ModelSurfaceReviewRecord, ...],
    context: ContextPackage,
    parent_retained_count: int = 0,
    usage_transform: Callable[[UsageRecord], UsageRecord] | None = None,
) -> _PromotedRecursiveParentSurfaceFixture:
    inventory = _scheduler_inventory(one_shard=True)
    journal = _create_test_scheduler_journal(
        root,
        bindings=_promoted_surface_bindings(),
        shard_inventory=inventory,
        privacy_evidence_custody=_scheduler_privacy_custody(
            source_sha256=inventory.source_tree_sha256
        ),
    )
    return _build_promoted_recursive_parent_surface_fixture(
        journal,
        requests=requests,
        records=records,
        parent_context=context,
        parent_model_id="synthetic/auditor-v1",
        parent_root_lineage="sha256:" + hashlib.sha256(b"synthetic/auditor-v1").hexdigest(),
        recursive_parent_retained_count=parent_retained_count,
        usage_transform=usage_transform,
    )


def _coverage_from_promoted_recursive_surface_fixture(
    config: AuditConfig,
    fixture: _PromotedRecursiveParentSurfaceFixture,
    *,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet,
    invariants: InvariantSuite,
    audited_suite_coverage: AuditedSuiteCoverage,
    capabilities: tuple[VerifiedPromotedRecursiveTruncationRecoverySurfaceCoverage, ...]
    | None = None,
    usage_records: list[UsageRecord] | None = None,
    review_artifacts: list[ModelSurfaceReviewArtifact] | None = None,
    review_contexts_by_request: dict[str, list[ContextPackage]] | None = None,
) -> ModelReviewCoverage:
    recovery_coordinates = tuple(
        (
            request.logical_request_id,
            request.request_limit_scope,
            request.request_limit_count_before,
        )
        for request in fixture.scheduler_artifact.recovery_model_requests
        if request.terminal_status is SchedulerTerminalStatus.SUCCEEDED
    )
    exact_contexts = {
        fixture.parent_usage.request_id: [fixture.parent_context],
        fixture.bridge_usage.request_id: [fixture.bridge_context],
        **{
            usage.request_id: [context]
            for usage, context in zip(
                fixture.leaf_usages,
                fixture.leaf_contexts,
                strict=True,
            )
        },
    }
    return build_model_review_coverage(
        config,
        usage_records=(
            [fixture.parent_usage, fixture.bridge_usage, *fixture.leaf_usages]
            if usage_records is None
            else usage_records
        ),
        review_artifacts=(
            list(fixture.leaf_artifacts) if review_artifacts is None else review_artifacts
        ),
        review_contexts_by_request=(
            exact_contexts if review_contexts_by_request is None else review_contexts_by_request
        ),
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        minimum_critical_root_lineages=2,
        audited_suite_coverage=audited_suite_coverage,
        source_contents_by_path={_PATH: _SOURCE},
        recovery_usage_coordinates=recovery_coordinates,
        promoted_recursive_recovery_surface_coverages=(
            (fixture.surface_capability,) if capabilities is None else capabilities
        ),
    )


def _manifest_model_review_inventories(
    fixture: _PromotedParentSurfaceFixture | _PromotedRecursiveParentSurfaceFixture,
    snapshot: Any,
) -> tuple[Any, Any]:
    """Build the exact private inventories emitted for one promoted fixture."""

    context_authorities = {fixture.parent_usage.request_id: [fixture.parent_context]}
    if isinstance(fixture, _PromotedRecursiveParentSurfaceFixture):
        context_authorities[fixture.bridge_usage.request_id] = [fixture.bridge_context]
        context_authorities.update(
            {
                usage.request_id: [context]
                for usage, context in zip(
                    fixture.leaf_usages,
                    fixture.leaf_contexts,
                    strict=True,
                )
            }
        )
    else:
        context_authorities.update(
            {
                usage.request_id: [context]
                for usage, context in zip(
                    fixture.child_usages,
                    fixture.child_contexts,
                    strict=True,
                )
            }
        )
    raw_inventory = manifest_module.build_model_review_artifact_inventory(
        artifacts=tuple(
            authority.artifact
            for authority in manifest_module._retained_model_surface_review_authorities(snapshot)
        ),
        review_contexts_by_request=context_authorities,
    )
    if isinstance(fixture.structural_artifact, TruncationRecoveredRecursiveSurfaceReviewArtifact):
        promoted_entry = manifest_module._RecursivePromotedModelReviewArtifact(
            promotion_entry_sha256=fixture.promotion.entry_sha256,
            recovered_output_artifact_sha256=(
                fixture.promotion.recovered_output.output_artifact_sha256
            ),
            recursive_tree=True,
            artifact=fixture.structural_artifact,
        )
        schema_version = "1.1"
    else:
        promoted_entry = manifest_module._DirectPromotedModelReviewArtifact(
            promotion_entry_sha256=fixture.promotion.entry_sha256,
            recovered_output_artifact_sha256=(
                fixture.promotion.recovered_output.output_artifact_sha256
            ),
            artifact=fixture.structural_artifact,
        )
        schema_version = "1.0"
    promoted_inventory = manifest_module._PromotedModelReviewArtifactInventory(
        schema_version=schema_version,
        promotions=(promoted_entry,),
    )
    return raw_inventory, promoted_inventory


def _fresh_manifest_replay_value(model: Any) -> Any:
    """Round-trip a strict model to remove all process-local authority."""

    return type(model).model_validate_json(model.model_dump_json())


def _open_promoted_fixture_for_verification(
    fixture: _PromotedParentSurfaceFixture | _PromotedRecursiveParentSurfaceFixture,
) -> SchedulerJournal:
    artifact = fixture.scheduler_artifact
    manifest = artifact.summary.manifest
    journal_path = fixture.journal.path
    fixture.journal.close()
    return open_scheduler_journal_for_verification(
        journal_path,
        expected_bindings=manifest.bindings,
        expected_shard_inventory=manifest.shard_inventory,
        expected_cost_ledger_baseline=manifest.cost_ledger_baseline,
        expected_privacy_evidence_custody=manifest.privacy_evidence_custody,
        expected_terminal_report_authority_required=manifest.terminal_report_authority_required,
        expected_terminal_evidence_authority_required=(
            manifest.terminal_evidence_authority_required
        ),
    )


def _validate_promoted_fixture_manifest_replay(
    *,
    config: AuditConfig,
    coverage: ModelReviewCoverage,
    fixture: _PromotedParentSurfaceFixture | _PromotedRecursiveParentSurfaceFixture,
    detached: bool,
    journal: SchedulerJournal | None = None,
    inventory: Any | None = None,
    promoted_inventory: Any | None = None,
    index: SoliditySymbolIndex | None = None,
    graphs: SolidityGraphSet | None = None,
) -> tuple[Any, Any]:
    snapshot = manifest_module._scheduler_report_authority_snapshot(
        fixture.journal if journal is None else journal
    )
    exact_inventory, exact_promoted_inventory = _manifest_model_review_inventories(
        fixture,
        snapshot,
    )
    selected_inventory = exact_inventory if inventory is None else inventory
    selected_promoted_inventory = (
        exact_promoted_inventory if promoted_inventory is None else promoted_inventory
    )
    manifest_module._validate_model_review_artifact_inventory_against_scheduler(
        report=cast(Any, SimpleNamespace(model_review_coverage=coverage)),
        inventory=selected_inventory,
        snapshot=snapshot,
        config=config,
        promoted_inventory=selected_promoted_inventory,
        detached=detached,
        index=fixture.parent_context.solidity_index if index is None else index,
        graphs=fixture.parent_context.solidity_graphs if graphs is None else graphs,
        runtime_journal=(None if detached else (fixture.journal if journal is None else journal)),
    )
    return exact_inventory, exact_promoted_inventory


@pytest.mark.parametrize("recursive", (False, True))
def test_pipeline_recovery_credit_requires_private_leaf_authority_after_reopen(
    tmp_path: Path,
    recursive: bool,
) -> None:
    model_id = "synthetic/auditor-v1"
    index, graphs, _invariants, _audited_suite, requests = _promoted_surface_inputs()
    context = _promoted_surface_context(
        requests,
        _usage("source_audit", model_id, f"pipeline-private-authority-{recursive}"),
        index,
        graphs,
    )
    records = tuple(_record(request, "source_audit", index, graphs) for request in requests)
    fixture = (
        _basic_promoted_recursive_surface_fixture(
            tmp_path / "recursive-pipeline-private-authority",
            requests=requests,
            records=records,
            context=context,
            parent_retained_count=1,
        )
        if recursive
        else _basic_promoted_surface_fixture(
            tmp_path / "direct-pipeline-private-authority",
            requests=requests,
            records=records,
            context=context,
        )
    )
    direct_capabilities: tuple[VerifiedPromotedTruncationRecoverySurfaceCoverage, ...]
    recursive_capabilities: tuple[VerifiedPromotedRecursiveTruncationRecoverySurfaceCoverage, ...]
    if isinstance(fixture, _PromotedRecursiveParentSurfaceFixture):
        direct_capabilities = ()
        recursive_capabilities = (fixture.surface_capability,)
        expected_leaf_ids = {usage.request_id for usage in fixture.leaf_usages}
        excluded_ids = {fixture.parent_usage.request_id, fixture.bridge_usage.request_id}
    else:
        direct_capabilities = (fixture.surface_capability,)
        recursive_capabilities = ()
        expected_leaf_ids = {usage.request_id for usage in fixture.child_usages}
        excluded_ids = {fixture.parent_usage.request_id}
    authorities = pipeline_module._require_current_promoted_recovery_leaf_authorities(
        direct_capabilities=direct_capabilities,
        recursive_capabilities=recursive_capabilities,
    )

    assert {authority.request_id for authority in authorities} == expected_leaf_ids
    assert not ({authority.request_id for authority in authorities} & excluded_ids)
    snapshot = manifest_module._scheduler_report_authority_snapshot(fixture.journal)
    _raw_inventory, promoted_inventory = _manifest_model_review_inventories(fixture, snapshot)
    fresh_promoted_inventory = _fresh_manifest_replay_value(promoted_inventory)
    assert (
        set(manifest_module._promoted_model_review_leaf_usage_inventory(fresh_promoted_inventory))
        == expected_leaf_ids
    )

    recovery_requests = fixture.scheduler_artifact.recovery_model_requests
    assert recovery_requests
    selected = pipeline_module._require_promoted_recovery_leaf_requests(
        authorities=authorities,
        recovery_requests=recovery_requests,
    )
    assert {request.logical_request_id for request in selected} == expected_leaf_ids
    recovery_usages = (
        (fixture.bridge_usage, *fixture.leaf_usages)
        if isinstance(fixture, _PromotedRecursiveParentSurfaceFixture)
        else fixture.child_usages
    )
    successful_ids = {usage.request_id for usage in recovery_usages}
    assert {
        usage.request_id
        for usage in pipeline_module._minimum_floor_creditable_usage_records(
            usage_records=recovery_usages,
            successful_request_ids=successful_ids,
            all_recovery_requests=recovery_requests,
            promoted_recovery_leaf_requests=selected,
        )
    } == expected_leaf_ids

    exact_leaf_usage = next(
        usage for usage in recovery_usages if usage.request_id == min(expected_leaf_ids)
    )
    drifted_leaf_usage = exact_leaf_usage.model_copy(
        update={"openrouter_generation_id": "forged-generation"}
    )
    with pytest.raises(
        ValueError,
        match="promoted recovery usage differs from exact scheduler comparison evidence",
    ):
        pipeline_module._minimum_floor_creditable_usage_records(
            usage_records=(drifted_leaf_usage,),
            successful_request_ids={drifted_leaf_usage.request_id},
            all_recovery_requests=recovery_requests,
            promoted_recovery_leaf_requests=selected,
        )

    first_leaf_id = min(expected_leaf_ids)
    missing_promotion = tuple(
        request.model_copy(update={"promotion_entry_sha256": None})
        if request.logical_request_id == first_leaf_id
        else request
        for request in recovery_requests
    )
    with pytest.raises(ValueError, match="differs from scheduler comparison evidence"):
        pipeline_module._require_promoted_recovery_leaf_requests(
            authorities=authorities,
            recovery_requests=missing_promotion,
        )

    assert {
        authority.request_id
        for authority in pipeline_module._require_current_promoted_recovery_leaf_authorities(
            direct_capabilities=direct_capabilities,
            recursive_capabilities=recursive_capabilities,
        )
    } == expected_leaf_ids

    reopened = _open_promoted_fixture_for_verification(fixture)
    try:
        reopened_requests = reopened.artifact().recovery_model_requests
        assert reopened_requests == recovery_requests
        assert all(request.promotion_entry_sha256 is not None for request in reopened_requests)
        with pytest.raises(ValueError):
            pipeline_module._require_current_promoted_recovery_leaf_authorities(
                direct_capabilities=direct_capabilities,
                recursive_capabilities=recursive_capabilities,
            )
        reopened_authorities = pipeline_module._require_current_promoted_recovery_leaf_authorities(
            direct_capabilities=(reopened.promoted_truncation_recovery_surface_coverages),
            recursive_capabilities=(
                reopened.promoted_recursive_truncation_recovery_surface_coverages
            ),
        )
        assert reopened_authorities == ()

        # Durable promotion markers and public recovery rows are comparison-only.
        assert (
            pipeline_module._require_promoted_recovery_leaf_requests(
                authorities=reopened_authorities,
                recovery_requests=reopened_requests,
            )
            == ()
        )
        assert (
            pipeline_module._minimum_floor_creditable_usage_records(
                usage_records=recovery_usages,
                successful_request_ids=successful_ids,
                all_recovery_requests=reopened_requests,
                promoted_recovery_leaf_requests=(),
            )
            == []
        )
    finally:
        reopened.close()


@pytest.mark.parametrize("recursive", (False, True))
def test_manifest_recovery_floor_requires_exact_live_promoted_leaf_capabilities(
    tmp_path: Path,
    recursive: bool,
) -> None:
    model_id = "synthetic/auditor-v1"
    index, graphs, _invariants, _audited_suite, requests = _promoted_surface_inputs()
    context = _promoted_surface_context(
        requests,
        _usage("source_audit", model_id, f"manifest-floor-live-{recursive}"),
        index,
        graphs,
    )
    records = tuple(_record(request, "source_audit", index, graphs) for request in requests)
    fixture = (
        _basic_promoted_recursive_surface_fixture(
            tmp_path / "recursive-manifest-floor-live",
            requests=requests,
            records=records,
            context=context,
            parent_retained_count=1,
        )
        if recursive
        else _basic_promoted_surface_fixture(
            tmp_path / "direct-manifest-floor-live",
            requests=requests,
            records=records,
            context=context,
        )
    )
    snapshot = manifest_module._scheduler_report_authority_snapshot(fixture.journal)
    _raw_inventory, promoted_inventory = _manifest_model_review_inventories(fixture, snapshot)
    serialized_leaf_inventory = manifest_module._promoted_model_review_leaf_usage_inventory(
        promoted_inventory
    )
    recovery_requests = {
        request.logical_request_id: request
        for request in fixture.scheduler_artifact.recovery_model_requests
    }
    leaf_usages = (
        fixture.leaf_usages
        if isinstance(fixture, _PromotedRecursiveParentSurfaceFixture)
        else fixture.child_usages
    )
    bindings = tuple(
        MinimumFloorRecoveryModelUsageBinding.build(
            usage_record=usage,
            request_limit_scope=recovery_requests[usage.request_id].request_limit_scope,
            request_limit_count_before=(
                recovery_requests[usage.request_id].request_limit_count_before
            ),
            scheduler_request_evidence_sha256=(
                recovery_requests[usage.request_id].request_evidence_sha256
            ),
        )
        for usage in sorted(leaf_usages, key=lambda item: item.request_id)
    )

    live_leaf_inventory = manifest_module._live_promoted_model_review_leaf_usage_inventory(
        fixture.journal
    )
    assert set(live_leaf_inventory) == {usage.request_id for usage in leaf_usages}
    assert len(live_leaf_inventory) == (3 if recursive else 2)
    assert fixture.parent_usage.request_id not in live_leaf_inventory
    if isinstance(fixture, _PromotedRecursiveParentSurfaceFixture):
        assert fixture.bridge_usage.request_id not in live_leaf_inventory
        assert all(
            authority.promotion_disposition
            is SchedulerTruncationRecoveryPromotionDisposition.SUCCESSFUL_LEAF
            for authority in live_leaf_inventory.values()
        )
    else:
        assert all(
            authority.promotion_disposition is None for authority in live_leaf_inventory.values()
        )
    manifest_module._validate_minimum_floor_recovery_usage_bindings(
        bindings=bindings,
        serialized_leaf_inventory=serialized_leaf_inventory,
        recovery_model_requests=recovery_requests,
        runtime_journal=fixture.journal,
    )

    with pytest.raises(ValueError, match="lacks exact live scheduler authority"):
        manifest_module._validate_minimum_floor_recovery_usage_bindings(
            bindings=bindings,
            serialized_leaf_inventory=serialized_leaf_inventory,
            recovery_model_requests=recovery_requests,
            runtime_journal=None,
        )
    with pytest.raises(ValueError, match="lacks exact live scheduler authority"):
        manifest_module._live_promoted_model_review_leaf_usage_inventory(
            cast(
                Any,
                SimpleNamespace(
                    promoted_truncation_recovery_surface_coverages=(
                        fixture.journal.promoted_truncation_recovery_surface_coverages
                    ),
                    promoted_recursive_truncation_recovery_surface_coverages=(
                        fixture.journal.promoted_recursive_truncation_recovery_surface_coverages
                    ),
                ),
            )
        )
    with pytest.raises(ValueError, match="repeats a request identity"):
        manifest_module._validate_minimum_floor_recovery_usage_bindings(
            bindings=(bindings[0], *bindings),
            serialized_leaf_inventory=serialized_leaf_inventory,
            recovery_model_requests=recovery_requests,
            runtime_journal=fixture.journal,
        )

    first_request_id = min(serialized_leaf_inventory)
    first_request = recovery_requests[first_request_id]
    wrong_disposition = (
        None if recursive else SchedulerTruncationRecoveryPromotionDisposition.SUCCESSFUL_LEAF
    )
    request_mutations = (
        {"promotion_disposition": wrong_disposition},
        {"terminal_status": SchedulerTerminalStatus.FAILED},
        {"usage_record_sha256": "f" * 64},
        {"promotion_entry_sha256": "e" * 64},
        {"role": "business_logic"},
        {"requested_model": "synthetic/unapproved-v1"},
        {"request_limit_scope": "scheduler-request-" + "d" * 64},
        {"request_limit_count_before": first_request.request_limit_count_before + 1},
    )
    for update in request_mutations:
        with pytest.raises(ValueError, match="exact live promoted scheduler evidence"):
            manifest_module._validate_minimum_floor_recovery_usage_bindings(
                bindings=bindings,
                serialized_leaf_inventory=serialized_leaf_inventory,
                recovery_model_requests={
                    **recovery_requests,
                    first_request_id: first_request.model_copy(update=update),
                },
                runtime_journal=fixture.journal,
            )

    first_binding = next(binding for binding in bindings if binding.request_id == first_request_id)
    for update in (
        {"role": "business_logic"},
        {"request_limit_scope": "scheduler-request-" + "c" * 64},
        {"request_limit_count_before": first_binding.request_limit_count_before + 1},
        {"usage_record_sha256": "b" * 64},
        {"scheduler_request_evidence_sha256": "a" * 64},
    ):
        mutated_bindings = tuple(
            binding.model_copy(update=update) if binding is first_binding else binding
            for binding in bindings
        )
        with pytest.raises(ValueError, match="exact live promoted scheduler evidence"):
            manifest_module._validate_minimum_floor_recovery_usage_bindings(
                bindings=mutated_bindings,
                serialized_leaf_inventory=serialized_leaf_inventory,
                recovery_model_requests=recovery_requests,
                runtime_journal=fixture.journal,
            )

    with pytest.raises(ValueError, match="exact live promoted scheduler evidence"):
        manifest_module._validate_minimum_floor_recovery_usage_bindings(
            bindings=bindings,
            serialized_leaf_inventory=serialized_leaf_inventory,
            recovery_model_requests={
                request_id: request
                for request_id, request in recovery_requests.items()
                if request_id != first_request_id
            },
            runtime_journal=fixture.journal,
        )

    reopened = _open_promoted_fixture_for_verification(fixture)
    try:
        with pytest.raises(ValueError, match="differs from live promoted capabilities"):
            manifest_module._validate_minimum_floor_recovery_usage_bindings(
                bindings=bindings,
                serialized_leaf_inventory=serialized_leaf_inventory,
                recovery_model_requests=recovery_requests,
                runtime_journal=reopened,
            )
    finally:
        reopened.close()


def _ordinary_model_review_snapshot(
    *,
    requests: tuple[ModelSurfaceReviewRequest, ...],
    artifact: ModelSurfaceReviewArtifact,
    usage: UsageRecord,
    pre_dispatch_requests: tuple[ModelSurfaceReviewRequest, ...] | None = None,
    pre_dispatch_rendered_context_sha256: str | None = None,
    include_pre_dispatch_authority: bool = True,
) -> Any:
    """Build the minimal detached scheduler projection consumed by raw-review replay."""

    output = SimpleNamespace(
        model_surface_review_artifact=artifact,
        model_completion_evidence=SimpleNamespace(usage_record=usage),
        model_surface_review_requests=requests,
        payload=CandidateReviewBatch(
            findings=[],
            surface_reviews=artifact.records,
        ).model_dump(mode="json"),
    )
    authoritative_requests = requests if pre_dispatch_requests is None else pre_dispatch_requests
    task = SimpleNamespace(
        logical_request_id=artifact.request_id,
        role=artifact.review_role,
        model_surface_review_request_manifest_sha256=(
            ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(
                authoritative_requests
            )
        ),
    )
    activation = SimpleNamespace(
        user_prompt_sha256=(
            artifact.rendered_context_sha256
            if pre_dispatch_rendered_context_sha256 is None
            else pre_dispatch_rendered_context_sha256
        ),
        provider_prompt_sha256=artifact.prompt_sha256,
        response_schema_sha256=artifact.response_schema_sha256,
    )
    snapshot = SimpleNamespace(
        outputs_by_task_id={"ordinary-model-review": output},
        journal=SimpleNamespace(truncation_recovery_entries=()),
    )
    if include_pre_dispatch_authority:
        snapshot.tasks_by_task_id = {"ordinary-model-review": task}
        snapshot.activations_by_task_id = {"ordinary-model-review": activation}
    else:
        snapshot.tasks_by_task_id = None
        snapshot.activations_by_task_id = None
    return snapshot


def _ordinary_model_review_inventory(
    artifact: ModelSurfaceReviewArtifact,
    context: ContextPackage,
) -> Any:
    """Retain one exact private context authority beside an ordinary raw artifact."""

    return manifest_module.build_model_review_artifact_inventory(
        artifacts=(artifact,),
        review_contexts_by_request={artifact.request_id: [context]},
    )


def _forge_detached_credited_surface(
    coverage: ModelReviewCoverage,
    artifact: ModelSurfaceReviewArtifact,
) -> Any:
    """Flip one typed raw reference to credited while retaining a canonical surface shape."""

    surface = next(
        item
        for item in coverage.surfaces
        if any(
            reference.artifact_sha256 == artifact.artifact_sha256
            for reference in item.evidence_references
        )
    )
    reference = next(
        item
        for item in surface.evidence_references
        if item.artifact_sha256 == artifact.artifact_sha256
    )
    assert not reference.credited
    payload = surface.model_dump(mode="json")
    payload["evidence_references"] = [
        {
            **reference.model_dump(mode="json"),
            "credited": True,
            "reason": "credited: forged detached raw-review custody",
        }
    ]
    for derived_field in ("reviewer_roles", "root_lineages", "reviewed"):
        payload.pop(derived_field)
    return type(surface).model_validate(payload)


def test_ordinary_model_review_replay_uses_runtime_authority_live_and_structure_detached(
    config_factory: Callable[..., AuditConfig],
) -> None:
    model_id = "synthetic/auditor-v1"
    role = "whole_protocol_review:0"
    config = _config_with_promoted_surface_manifest_lineage(config_factory(), model_id)
    registry_only_config = _config_with_registry_only_promoted_surface_model(
        config_factory(),
        model_id,
    )
    usage = _usage(role, model_id, "ordinary-replay")
    live_authority = manifest_module._RetainedModelSurfaceReviewAuthority(
        artifact=cast(Any, None),
        requests=(),
        usage=usage,
    )
    assert manifest_module._ordinary_model_review_usage_is_creditable(
        live_authority,
        detached=False,
        require_certification=False,
    )

    serialized_usage = UsageRecord.model_validate_json(usage.model_dump_json())
    detached_authority = manifest_module._RetainedModelSurfaceReviewAuthority(
        artifact=cast(Any, None),
        requests=(),
        usage=serialized_usage,
    )
    assert not manifest_module._ordinary_model_review_usage_is_creditable(
        detached_authority,
        detached=False,
        require_certification=False,
    )
    assert manifest_module._ordinary_model_review_usage_is_creditable(
        detached_authority,
        detached=True,
        require_certification=False,
    )
    assert manifest_module._usage_has_configured_approved_model_custody(
        config,
        serialized_usage,
    )
    assert not manifest_module._usage_has_configured_approved_model_custody(
        registry_only_config,
        serialized_usage,
    )
    configured_lineage = next(
        entry.root_lineage for entry in config.models.registry if model_id in entry.model_ids()
    )
    scheduler_request = cast(
        Any,
        SimpleNamespace(
            logical_request_id=serialized_usage.request_id,
            requested_model=model_id,
            root_lineage=configured_lineage,
        ),
    )
    assert manifest_module._scheduler_usage_is_creditable(
        usage=serialized_usage,
        request=scheduler_request,
        config=config,
    )
    assert not manifest_module._scheduler_usage_is_creditable(
        usage=serialized_usage,
        request=scheduler_request,
        config=registry_only_config,
    )
    for invalid_role in (
        "whole_protocol_review:00",
        "whole_protocol_review:10000",
        "whole_protocol_review:+1",
    ):
        assert not manifest_module._usage_has_configured_approved_model_custody(
            config,
            serialized_usage.model_copy(update={"role": invalid_role}),
        )
    assert not manifest_module._ordinary_model_review_usage_is_creditable(
        detached_authority,
        detached=True,
        require_certification=True,
    )

    mock_usage = _usage(
        role,
        model_id,
        "ordinary-mock-replay",
        execution_evidence=ExecutionEvidenceKind.MOCK,
    )
    mock_authority = manifest_module._RetainedModelSurfaceReviewAuthority(
        artifact=cast(Any, None),
        requests=(),
        usage=UsageRecord.model_validate_json(mock_usage.model_dump_json()),
    )
    assert not manifest_module._ordinary_model_review_usage_is_creditable(
        mock_authority,
        detached=True,
        require_certification=False,
    )


def test_whole_protocol_raw_credit_requires_indexed_source_context_live_and_detached(
    config_factory: Callable[..., AuditConfig],
) -> None:
    model_id = "synthetic/auditor-v1"
    role = "whole_protocol_review:0"
    config = _config_with_promoted_surface_manifest_lineage(config_factory(), model_id)
    index, graphs, invariants, audited_suite, requests = _requests_with_audited_coverage()
    base_context = _review_context(
        requests,
        _usage("whole_protocol_review", model_id, "whole-protocol-base-context"),
        index,
        graphs,
    )

    with _authorized_ordinary_review_evidence(
        config,
        index=index,
        graphs=graphs,
        requests=requests,
        reviewers=((role, model_id),),
        contexts=(base_context,),
    ) as evidence:
        legitimate_usage = evidence.usage_records[0]
        legitimate_artifact = evidence.artifacts[0]
        legitimate_coverage = build_model_review_coverage(
            config,
            usage_records=[legitimate_usage],
            review_artifacts=[legitimate_artifact],
            review_contexts_by_request=evidence.contexts_by_request,
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            audited_suite_coverage=audited_suite,
            source_contents_by_path={_PATH: _SOURCE},
            ordinary_review_authorizations=evidence.authorizations,
        )
    legitimate_references = [
        reference
        for surface in legitimate_coverage.surfaces
        for reference in surface.evidence_references
        if reference.artifact_sha256 == legitimate_artifact.artifact_sha256
    ]
    assert legitimate_references
    assert all(reference.credited for reference in legitimate_references)

    fresh_usage = UsageRecord.model_validate_json(legitimate_usage.model_dump_json())
    fresh_artifact = ModelSurfaceReviewArtifact.model_validate_json(
        legitimate_artifact.model_dump_json()
    )
    fresh_requests = tuple(
        ModelSurfaceReviewRequest.model_validate_json(request.model_dump_json())
        for request in requests
    )
    fresh_inventory = _ordinary_model_review_inventory(fresh_artifact, base_context)
    fresh_coverage = _fresh_manifest_replay_value(legitimate_coverage)
    fresh_snapshot = _ordinary_model_review_snapshot(
        requests=fresh_requests,
        artifact=fresh_artifact,
        usage=fresh_usage,
    )
    credited_surfaces = [
        surface
        for surface in fresh_coverage.surfaces
        if any(
            reference.credited and reference.artifact_sha256 == fresh_artifact.artifact_sha256
            for reference in surface.evidence_references
        )
    ]
    assert len(credited_surfaces) >= 2
    first_surface, later_surface = credited_surfaces[:2]
    assert len(first_surface.evidence_references) == 1
    assert len(later_surface.evidence_references) == 1

    # Every credited reference must replay before the terminal live-authority gate.
    with pytest.raises(ValueError, match="lacks live pre-dispatch runtime authority"):
        manifest_module._validate_model_review_artifact_inventory_against_scheduler(
            report=cast(
                Any,
                SimpleNamespace(
                    model_review_coverage=SimpleNamespace(surfaces=[first_surface, later_surface])
                ),
            ),
            inventory=fresh_inventory,
            snapshot=fresh_snapshot,
            config=config,
            detached=True,
            index=index,
            graphs=graphs,
        )
    later_payload = later_surface.model_dump(mode="json")
    later_payload["evidence_references"][0]["request_id"] = "forged-later-credited-reference"
    for derived_field in ("reviewer_roles", "root_lineages", "reviewed"):
        later_payload.pop(derived_field)
    forged_later_surface = type(later_surface).model_validate(later_payload)
    with pytest.raises(ValueError, match="contradicts exact scheduler artifact custody"):
        manifest_module._validate_model_review_artifact_inventory_against_scheduler(
            report=cast(
                Any,
                SimpleNamespace(
                    model_review_coverage=SimpleNamespace(
                        surfaces=[first_surface, forged_later_surface]
                    )
                ),
            ),
            inventory=fresh_inventory,
            snapshot=fresh_snapshot,
            config=config,
            detached=True,
            index=index,
            graphs=graphs,
        )
    with pytest.raises(ValueError, match="lacks live pre-dispatch runtime authority"):
        manifest_module._validate_model_review_artifact_inventory_against_scheduler(
            report=cast(
                Any,
                SimpleNamespace(model_review_coverage=fresh_coverage),
            ),
            inventory=fresh_inventory,
            snapshot=fresh_snapshot,
            config=config,
            detached=True,
            index=index,
            graphs=graphs,
        )
    with pytest.raises(ValueError, match="contradicts exact scheduler artifact custody"):
        manifest_module._validate_model_review_artifact_inventory_against_scheduler(
            report=cast(
                Any,
                SimpleNamespace(
                    model_review_coverage=_fresh_manifest_replay_value(legitimate_coverage)
                ),
            ),
            inventory=fresh_inventory,
            snapshot=_ordinary_model_review_snapshot(
                requests=fresh_requests,
                artifact=fresh_artifact,
                usage=fresh_usage,
                include_pre_dispatch_authority=False,
            ),
            config=config,
            detached=True,
            index=index,
            graphs=graphs,
        )

    unbound_usage = _usage(role, model_id, "whole-protocol-indexed-unbound")
    _bind_usage_to_context(unbound_usage, base_context)
    unbound_artifact = _artifact(
        requests,
        unbound_usage,
        index,
        graphs,
        context=base_context,
    )
    unbound_coverage = build_model_review_coverage(
        config,
        usage_records=[unbound_usage],
        review_artifacts=[unbound_artifact],
        review_contexts_by_request={unbound_usage.request_id: [base_context]},
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        source_contents_by_path={_PATH: _SOURCE},
    )
    unbound_surface = next(
        surface
        for surface in unbound_coverage.surfaces
        if any(
            reference.artifact_sha256 == unbound_artifact.artifact_sha256
            for reference in surface.evidence_references
        )
    )
    unbound_reference = next(
        reference
        for reference in unbound_surface.evidence_references
        if reference.artifact_sha256 == unbound_artifact.artifact_sha256
    )
    assert not unbound_reference.credited
    forged_surface_payload = unbound_surface.model_dump(mode="json")
    forged_surface_payload["evidence_references"] = [
        {
            **unbound_reference.model_dump(mode="json"),
            "credited": True,
            "reason": "credited: forged detached whole-protocol custody",
        }
    ]
    for derived_field in ("reviewer_roles", "root_lineages", "reviewed"):
        forged_surface_payload.pop(derived_field)
    forged_surface = type(unbound_surface).model_validate(forged_surface_payload)

    detached_unbound_usage = UsageRecord.model_validate_json(unbound_usage.model_dump_json())
    detached_unbound_artifact = ModelSurfaceReviewArtifact.model_validate_json(
        unbound_artifact.model_dump_json()
    )
    with pytest.raises(ValueError, match="contradicts exact scheduler artifact custody"):
        manifest_module._validate_model_review_artifact_inventory_against_scheduler(
            report=cast(
                Any,
                SimpleNamespace(model_review_coverage=SimpleNamespace(surfaces=[forged_surface])),
            ),
            inventory=_ordinary_model_review_inventory(
                detached_unbound_artifact,
                base_context,
            ),
            snapshot=_ordinary_model_review_snapshot(
                requests=fresh_requests,
                artifact=detached_unbound_artifact,
                usage=detached_unbound_usage,
            ),
            config=config,
            detached=True,
            index=index,
            graphs=graphs,
        )


@pytest.mark.parametrize(
    ("alias_registration", "expected_credit"),
    (
        ("same_root", True),
        ("unregistered", False),
        ("cross_lineage", False),
    ),
)
def test_model_review_provider_alias_requires_one_registered_approved_lineage_live_and_detached(
    config_factory: Callable[..., AuditConfig],
    alias_registration: str,
    expected_credit: bool,
) -> None:
    model_id = "synthetic/auditor-v1"
    alias = f"synthetic/{alias_registration}-provider-alias"
    role = "whole_protocol_review:0"
    config = _config_with_promoted_surface_manifest_lineage(config_factory(), model_id)
    if alias_registration != "unregistered":
        config = _with_provider_visible_registry_alias(
            config,
            requested_model=model_id,
            alias=alias,
            same_root=alias_registration == "same_root",
        )
    index, graphs, invariants, audited_suite, requests = _requests_with_audited_coverage()
    selected_requests = requests[:1]
    context = _review_context(
        selected_requests,
        _usage("whole_protocol_review", model_id, f"{alias_registration}-alias-context"),
        index,
        graphs,
    )
    with _authorized_ordinary_review_evidence(
        config,
        index=index,
        graphs=graphs,
        requests=selected_requests,
        reviewers=((role, model_id),),
        contexts=(context,),
    ) as evidence:
        usage = _with_provider_visible_model_alias(evidence.usage_records[0], alias)
        artifact = _artifact(selected_requests, usage, index, graphs, context=context)
        coverage = build_model_review_coverage(
            config,
            usage_records=[usage],
            review_artifacts=[artifact],
            review_contexts_by_request={usage.request_id: [context]},
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            audited_suite_coverage=audited_suite,
            source_contents_by_path={_PATH: _SOURCE},
            ordinary_review_authorizations=evidence.authorizations,
        )
    reference = next(
        reference
        for surface in coverage.surfaces
        for reference in surface.evidence_references
        if reference.artifact_sha256 == artifact.artifact_sha256
    )
    assert reference.credited is expected_credit

    fresh_usage = UsageRecord.model_validate_json(usage.model_dump_json())
    fresh_artifact = ModelSurfaceReviewArtifact.model_validate_json(artifact.model_dump_json())
    fresh_requests = tuple(
        ModelSurfaceReviewRequest.model_validate_json(request.model_dump_json())
        for request in selected_requests
    )
    fresh_inventory = _ordinary_model_review_inventory(fresh_artifact, context)
    detached_authority = manifest_module._RetainedModelSurfaceReviewAuthority(
        artifact=fresh_artifact,
        requests=fresh_requests,
        usage=fresh_usage,
    )
    assert manifest_module._ordinary_model_review_usage_is_creditable(
        detached_authority,
        detached=True,
        require_certification=False,
    )
    detached_surface = (
        _fresh_manifest_replay_value(coverage).surfaces
        if expected_credit
        else [_forge_detached_credited_surface(coverage, artifact)]
    )

    def validate() -> None:
        manifest_module._validate_model_review_artifact_inventory_against_scheduler(
            report=cast(
                Any,
                SimpleNamespace(model_review_coverage=SimpleNamespace(surfaces=detached_surface)),
            ),
            inventory=fresh_inventory,
            snapshot=_ordinary_model_review_snapshot(
                requests=fresh_requests,
                artifact=fresh_artifact,
                usage=fresh_usage,
            ),
            config=config,
            detached=True,
            index=index,
            graphs=graphs,
        )

    with pytest.raises(
        ValueError,
        match=(
            r"lacks live pre-dispatch runtime authority|contradicts exact scheduler artifact custody"
        ),
    ):
        validate()


def test_detached_whole_protocol_rejects_coherent_surface_inventory_substitution(
    config_factory: Callable[..., AuditConfig],
) -> None:
    model_id = "synthetic/auditor-v1"
    role = "whole_protocol_review:0"
    config = _config_with_promoted_surface_manifest_lineage(config_factory(), model_id)
    index, graphs, invariants, audited_suite, requests = _requests_with_audited_coverage()
    context_requests = requests[:1]
    substituted_requests = requests[1:2]
    context = _review_context(
        context_requests,
        _usage("whole_protocol_review", model_id, "surface-substitution-context"),
        index,
        graphs,
    )
    with _authorized_ordinary_review_evidence(
        config,
        index=index,
        graphs=graphs,
        requests=context_requests,
        reviewers=((role, model_id),),
        contexts=(context,),
    ) as evidence:
        usage = evidence.usage_records[0]
        legitimate_artifact = evidence.artifacts[0]
        legitimate_coverage = build_model_review_coverage(
            config,
            usage_records=[usage],
            review_artifacts=[legitimate_artifact],
            review_contexts_by_request=evidence.contexts_by_request,
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            audited_suite_coverage=audited_suite,
            source_contents_by_path={_PATH: _SOURCE},
            ordinary_review_authorizations=evidence.authorizations,
        )
        assert any(
            reference.credited
            for surface in legitimate_coverage.surfaces
            for reference in surface.evidence_references
            if reference.artifact_sha256 == legitimate_artifact.artifact_sha256
        )

        substituted_artifact = _artifact(
            substituted_requests,
            usage,
            index,
            graphs,
            context=context,
        )
        substituted_coverage = build_model_review_coverage(
            config,
            usage_records=[usage],
            review_artifacts=[substituted_artifact],
            review_contexts_by_request={usage.request_id: [context]},
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            audited_suite_coverage=audited_suite,
            source_contents_by_path={_PATH: _SOURCE},
            ordinary_review_authorizations=evidence.authorizations,
        )
        assert not any(
            reference.credited
            for surface in substituted_coverage.surfaces
            for reference in surface.evidence_references
            if reference.artifact_sha256 == substituted_artifact.artifact_sha256
        )
    forged_surface = _forge_detached_credited_surface(
        substituted_coverage,
        substituted_artifact,
    )
    fresh_usage = UsageRecord.model_validate_json(usage.model_dump_json())
    fresh_artifact = ModelSurfaceReviewArtifact.model_validate_json(
        substituted_artifact.model_dump_json()
    )
    fresh_requests = tuple(
        ModelSurfaceReviewRequest.model_validate_json(request.model_dump_json())
        for request in substituted_requests
    )
    with pytest.raises(ValueError, match="contradicts exact scheduler artifact custody"):
        manifest_module._validate_model_review_artifact_inventory_against_scheduler(
            report=cast(
                Any,
                SimpleNamespace(model_review_coverage=SimpleNamespace(surfaces=[forged_surface])),
            ),
            inventory=_ordinary_model_review_inventory(fresh_artifact, context),
            snapshot=_ordinary_model_review_snapshot(
                requests=fresh_requests,
                artifact=fresh_artifact,
                usage=fresh_usage,
            ),
            config=config,
            detached=True,
            index=index,
            graphs=graphs,
        )


def test_detached_whole_protocol_rejects_coherent_context_reseal_against_retained_authority(
    config_factory: Callable[..., AuditConfig],
) -> None:
    model_id = "synthetic/auditor-v1"
    role = "whole_protocol_review:0"
    config = _config_with_promoted_surface_manifest_lineage(config_factory(), model_id)
    index, graphs, invariants, audited_suite, requests = _requests_with_audited_coverage()
    actual_requests = requests[:1]
    forged_requests = requests[1:2]
    actual_context = _review_context(
        actual_requests,
        _usage("whole_protocol_review", model_id, "retained-actual-context"),
        index,
        graphs,
    )
    forged_context = _review_context(
        forged_requests,
        _usage("whole_protocol_review", model_id, "resealed-forged-context"),
        index,
        graphs,
    )
    missing_graphs_context = _with_exact_context_bytes(
        actual_context.model_copy(update={"solidity_graphs": None})
    )
    missing_graphs_usage = _usage(role, model_id, "retained-missing-graphs")
    _bind_usage_to_context(missing_graphs_usage, missing_graphs_context)
    missing_graphs_usage = _with_context_request_evidence(
        missing_graphs_usage,
        missing_graphs_context,
        request_role=role,
    )
    assert any(
        "graphs" in failure
        for failure in manifest_module.model_surface_retained_context_custody_failures(
            context=missing_graphs_context,
            usage=missing_graphs_usage,
            requests=tuple(actual_requests),
            request_id=missing_graphs_usage.request_id,
            review_role=role,
            context_role=missing_graphs_context.role,
            rendered_context_sha256=missing_graphs_usage.user_prompt_sha256 or "",
            requested_surface_manifest_sha256=(
                ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(
                    actual_requests
                )
            ),
            index=index,
            graphs=graphs,
        )
    )

    actual_usage = _usage(role, model_id, "coherent-context-reseal")
    _bind_usage_to_context(actual_usage, actual_context)
    actual_usage = _with_context_request_evidence(
        actual_usage,
        actual_context,
        request_role=role,
    )
    forged_usage = UsageRecord.model_validate_json(actual_usage.model_dump_json())
    _bind_usage_to_context(forged_usage, forged_context)
    forged_usage = _with_context_request_evidence(
        forged_usage,
        forged_context,
        request_role=role,
    )
    forged_artifact = _artifact(
        forged_requests,
        forged_usage,
        index,
        graphs,
        context=forged_context,
    )
    live_coverage = build_model_review_coverage(
        config,
        usage_records=[forged_usage],
        review_artifacts=[forged_artifact],
        review_contexts_by_request={forged_usage.request_id: [actual_context]},
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        source_contents_by_path={_PATH: _SOURCE},
    )
    live_reference = next(
        reference
        for surface in live_coverage.surfaces
        for reference in surface.evidence_references
        if reference.artifact_sha256 == forged_artifact.artifact_sha256
    )
    assert not live_reference.credited

    fresh_usage = UsageRecord.model_validate_json(forged_usage.model_dump_json())
    fresh_artifact = ModelSurfaceReviewArtifact.model_validate_json(
        forged_artifact.model_dump_json()
    )
    fresh_requests = tuple(
        ModelSurfaceReviewRequest.model_validate_json(request.model_dump_json())
        for request in forged_requests
    )
    retained_inventory = _ordinary_model_review_inventory(fresh_artifact, actual_context)
    with pytest.raises(ValueError, match="contradicts exact scheduler artifact custody"):
        manifest_module._validate_model_review_artifact_inventory_against_scheduler(
            report=cast(
                Any,
                SimpleNamespace(
                    model_review_coverage=SimpleNamespace(
                        surfaces=[
                            _forge_detached_credited_surface(
                                live_coverage,
                                forged_artifact,
                            )
                        ]
                    )
                ),
            ),
            inventory=_fresh_manifest_replay_value(retained_inventory),
            snapshot=_ordinary_model_review_snapshot(
                requests=fresh_requests,
                artifact=fresh_artifact,
                usage=fresh_usage,
            ),
            config=config,
            detached=True,
            index=index,
            graphs=graphs,
        )

    # A coherently resealed late inventory must not replace the surface/context
    # authority already committed by the scheduler before provider dispatch.
    resealed_inventory = _ordinary_model_review_inventory(fresh_artifact, forged_context)
    with pytest.raises(ValueError, match="contradicts exact scheduler artifact custody"):
        manifest_module._validate_model_review_artifact_inventory_against_scheduler(
            report=cast(
                Any,
                SimpleNamespace(
                    model_review_coverage=SimpleNamespace(
                        surfaces=[
                            _forge_detached_credited_surface(
                                live_coverage,
                                forged_artifact,
                            )
                        ]
                    )
                ),
            ),
            inventory=_fresh_manifest_replay_value(resealed_inventory),
            snapshot=_ordinary_model_review_snapshot(
                requests=fresh_requests,
                artifact=fresh_artifact,
                usage=fresh_usage,
                pre_dispatch_requests=tuple(actual_requests),
                pre_dispatch_rendered_context_sha256=(
                    hashlib.sha256(render_context(actual_context).encode()).hexdigest()
                ),
            ),
            config=config,
            detached=True,
            index=index,
            graphs=graphs,
        )


def test_detached_raw_replay_rejects_semantically_invalid_record(
    config_factory: Callable[..., AuditConfig],
) -> None:
    model_id = "synthetic/auditor-v1"
    role = "whole_protocol_review:0"
    config = _config_with_promoted_surface_manifest_lineage(config_factory(), model_id)
    index, graphs, invariants, audited_suite, requests = _requests_with_audited_coverage()
    selected_requests = requests[:1]
    context = _review_context(
        selected_requests,
        _usage("whole_protocol_review", model_id, "semantic-replay-context"),
        index,
        graphs,
    )
    usage = _usage(role, model_id, "semantic-replay-invalid")
    _bind_usage_to_context(usage, context)
    usage = _with_context_request_evidence(usage, context, request_role=role)
    artifact = _artifact(selected_requests, usage, index, graphs, context=context)
    invalid_artifact = _replace_artifact_record(
        artifact,
        _semantically_invalid_record(artifact.records[0]),
    )
    coverage = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[invalid_artifact],
        review_contexts_by_request={usage.request_id: [context]},
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        source_contents_by_path={_PATH: _SOURCE},
    )
    invalid_reference = next(
        reference
        for surface in coverage.surfaces
        for reference in surface.evidence_references
        if reference.artifact_sha256 == invalid_artifact.artifact_sha256
    )
    assert not invalid_reference.credited
    assert len(invalid_reference.reason) <= 1_000
    forged_surface = _forge_detached_credited_surface(coverage, invalid_artifact)
    fresh_usage = UsageRecord.model_validate_json(usage.model_dump_json())
    fresh_artifact = ModelSurfaceReviewArtifact.model_validate_json(
        invalid_artifact.model_dump_json()
    )
    fresh_requests = tuple(
        ModelSurfaceReviewRequest.model_validate_json(request.model_dump_json())
        for request in selected_requests
    )
    with pytest.raises(ValueError, match="contradicts exact scheduler artifact custody"):
        manifest_module._validate_model_review_artifact_inventory_against_scheduler(
            report=cast(
                Any,
                SimpleNamespace(model_review_coverage=SimpleNamespace(surfaces=[forged_surface])),
            ),
            inventory=_ordinary_model_review_inventory(fresh_artifact, context),
            snapshot=_ordinary_model_review_snapshot(
                requests=fresh_requests,
                artifact=fresh_artifact,
                usage=fresh_usage,
            ),
            config=config,
            detached=True,
            index=index,
            graphs=graphs,
        )


def test_detached_base_role_rejects_coherent_surface_context_substitution(
    config_factory: Callable[..., AuditConfig],
) -> None:
    model_id = "synthetic/auditor-v1"
    role = "source_audit"
    config = _config_with_promoted_surface_manifest_lineage(config_factory(), model_id)
    index, graphs, invariants, audited_suite, requests = _requests_with_audited_coverage()
    context_requests = requests[:1]
    substituted_requests = requests[1:2]
    context = _review_context(
        context_requests,
        _usage(role, model_id, "base-role-surface-substitution-context"),
        index,
        graphs,
    )
    usage = _usage(role, model_id, "base-role-surface-substitution")
    _bind_usage_to_context(usage, context)
    usage = _with_context_request_evidence(usage, context, request_role=role)
    artifact = _artifact(substituted_requests, usage, index, graphs, context=context)
    coverage = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[artifact],
        review_contexts_by_request={usage.request_id: [context]},
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        source_contents_by_path={_PATH: _SOURCE},
    )
    forged_surface = _forge_detached_credited_surface(coverage, artifact)
    fresh_usage = UsageRecord.model_validate_json(usage.model_dump_json())
    fresh_artifact = ModelSurfaceReviewArtifact.model_validate_json(artifact.model_dump_json())
    fresh_requests = tuple(
        ModelSurfaceReviewRequest.model_validate_json(request.model_dump_json())
        for request in substituted_requests
    )
    with pytest.raises(ValueError, match="contradicts exact scheduler artifact custody"):
        manifest_module._validate_model_review_artifact_inventory_against_scheduler(
            report=cast(
                Any,
                SimpleNamespace(model_review_coverage=SimpleNamespace(surfaces=[forged_surface])),
            ),
            inventory=_ordinary_model_review_inventory(fresh_artifact, context),
            snapshot=_ordinary_model_review_snapshot(
                requests=fresh_requests,
                artifact=fresh_artifact,
                usage=fresh_usage,
            ),
            config=config,
            detached=True,
            index=index,
            graphs=graphs,
        )


def test_detached_base_role_rejects_missing_provider_visible_source_proofs(
    config_factory: Callable[..., AuditConfig],
) -> None:
    model_id = "synthetic/auditor-v1"
    role = "source_audit"
    config = _config_with_promoted_surface_manifest_lineage(config_factory(), model_id)
    index, graphs, invariants, audited_suite, requests = _requests_with_audited_coverage()
    selected_requests = requests[:1]
    context = _review_context(
        selected_requests,
        _usage(role, model_id, "base-role-source-omission-context"),
        index,
        graphs,
        excerpts=[],
    )
    usage = _usage(role, model_id, "base-role-source-omission")
    _bind_usage_to_context(usage, context)
    _with_context_request_evidence(usage, context, request_role=role)
    artifact = _artifact(selected_requests, usage, index, graphs, context=context)
    coverage = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[artifact],
        review_contexts_by_request={usage.request_id: [context]},
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited_suite,
        source_contents_by_path={_PATH: _SOURCE},
    )
    reference = next(
        reference
        for surface in coverage.surfaces
        for reference in surface.evidence_references
        if reference.artifact_sha256 == artifact.artifact_sha256
    )
    assert not reference.credited
    forged_surface = _forge_detached_credited_surface(coverage, artifact)
    fresh_usage = UsageRecord.model_validate_json(usage.model_dump_json())
    fresh_artifact = ModelSurfaceReviewArtifact.model_validate_json(artifact.model_dump_json())
    fresh_requests = tuple(
        ModelSurfaceReviewRequest.model_validate_json(request.model_dump_json())
        for request in selected_requests
    )
    with pytest.raises(ValueError, match="contradicts exact scheduler artifact custody"):
        manifest_module._validate_model_review_artifact_inventory_against_scheduler(
            report=cast(
                Any,
                SimpleNamespace(model_review_coverage=SimpleNamespace(surfaces=[forged_surface])),
            ),
            inventory=_ordinary_model_review_inventory(fresh_artifact, context),
            snapshot=_ordinary_model_review_snapshot(
                requests=fresh_requests,
                artifact=fresh_artifact,
                usage=fresh_usage,
            ),
            config=config,
            detached=True,
            index=index,
            graphs=graphs,
        )


def test_promoted_parent_surface_credits_only_parent_origin_while_children_stay_ordinary(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
) -> None:
    model_id = "synthetic/auditor-v1"
    config = _config_with_promoted_surface_manifest_lineage(config_factory(), model_id)
    index, graphs, invariants, audited_suite, requests = _promoted_surface_inputs()
    context_usage = _usage("source_audit", model_id, "promoted-context-only")
    context = _promoted_surface_context(requests, context_usage, index, graphs)
    records = tuple(_record(request, "source_audit", index, graphs) for request in requests)
    fixture = _basic_promoted_surface_fixture(
        tmp_path / "promoted-parent-credit",
        requests=requests,
        records=records,
        context=context,
    )

    coverage = _coverage_from_promoted_surface_fixture(
        config,
        fixture,
        index=index,
        graphs=graphs,
        invariants=invariants,
        audited_suite_coverage=audited_suite,
    )
    projection = require_verified_promoted_truncation_recovery_surface_coverage(
        fixture.surface_capability
    )
    assert projection.parent_usage_record is fixture.parent_usage
    assert all(
        projected is expected
        for projected, expected in zip(
            projection.child_usage_records,
            fixture.child_usages,
            strict=True,
        )
    )
    parent_origin = next(
        origin
        for origin in projection.artifact.origins
        if origin.origin_kind is TruncationSurfaceOriginKind.PARENT_PROVISIONAL
    )
    surfaces_by_id = {surface.surface_id: surface for surface in coverage.surfaces}
    parent_reference = surfaces_by_id[parent_origin.surface_id].evidence_references
    child_artifacts_by_surface = {
        record.surface_id: artifact
        for artifact in fixture.child_artifacts
        for record in artifact.records
    }

    assert coverage.overall.numerator == coverage.overall.denominator == len(requests)
    assert len(parent_reference) == 1
    assert parent_reference[0].credited
    assert parent_reference[0].request_id == fixture.parent_usage.request_id
    assert parent_reference[0].artifact_sha256 == projection.artifact.artifact_sha256
    assert all(
        artifact.request_id != fixture.parent_usage.request_id
        for artifact in fixture.child_artifacts
    )
    assert set(child_artifacts_by_surface) == set(surfaces_by_id) - {parent_origin.surface_id}
    for surface_id, artifact in child_artifacts_by_surface.items():
        references = surfaces_by_id[surface_id].evidence_references
        assert len(references) == 1
        assert references[0].credited
        assert references[0].artifact_sha256 == artifact.artifact_sha256
        assert references[0].request_id == artifact.request_id
        assert references[0].artifact_sha256 != projection.artifact.artifact_sha256
    fixture.journal.close()


def test_recovery_children_cannot_use_public_ordinary_authority_without_promotion(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
) -> None:
    model_id = "synthetic/auditor-v1"
    config = _config_with_promoted_surface_manifest_lineage(config_factory(), model_id)
    index, graphs, invariants, audited_suite, requests = _promoted_surface_inputs()
    context_usage = _usage("source_audit", model_id, "promoted-public-authority-context")
    context = _promoted_surface_context(requests, context_usage, index, graphs)
    records = tuple(_record(request, "source_audit", index, graphs) for request in requests)
    fixture = _basic_promoted_surface_fixture(
        tmp_path / "promoted-public-authority",
        requests=requests,
        records=records,
        context=context,
    )

    public_authorizations = build_model_review_pre_dispatch_authorizations(fixture.journal)
    public_bindings = tuple(
        require_model_review_pre_dispatch_authorization(authorization)
        for authorization in public_authorizations
    )
    assert len(public_bindings) == 1
    assert public_bindings[0].request_id == fixture.parent_usage.request_id
    assert not public_bindings[0].request_id.startswith("scheduler-recovery-request-")
    assert not public_bindings[0].task_id.startswith("scheduler-recovery-task-")

    coverage = _coverage_from_promoted_surface_fixture(
        config,
        fixture,
        index=index,
        graphs=graphs,
        invariants=invariants,
        audited_suite_coverage=audited_suite,
        ordinary_review_authorizations=public_authorizations,
        include_promoted_surface_coverage=False,
    )
    child_request_ids = {usage.request_id for usage in fixture.child_usages}
    child_references = tuple(
        reference
        for surface in coverage.surfaces
        for reference in surface.evidence_references
        if reference.request_id in child_request_ids
    )
    assert child_references
    assert not any(reference.credited for reference in child_references)
    assert coverage.overall.numerator == 0
    fixture.journal.close()


def test_promoted_parent_manifest_replay_survives_fresh_deserialization_and_rejects_tamper(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
) -> None:
    model_id = "synthetic/auditor-v1"
    role = "whole_protocol_review:0"
    config = _config_with_promoted_surface_manifest_lineage(config_factory(), model_id)
    registry_only_config = _config_with_registry_only_promoted_surface_model(
        config_factory(),
        model_id,
    )
    index, graphs, invariants, audited_suite, requests = _promoted_surface_inputs()
    context = _promoted_surface_context(
        requests,
        _usage("whole_protocol_review", model_id, "promoted-manifest-context"),
        index,
        graphs,
    )
    records = tuple(_record(request, role, index, graphs) for request in requests)
    fixture = _basic_promoted_surface_fixture(
        tmp_path / "promoted-manifest-replay",
        requests=requests,
        records=records,
        context=context,
        parent_role=role,
    )
    coverage = _coverage_from_promoted_surface_fixture(
        config,
        fixture,
        index=index,
        graphs=graphs,
        invariants=invariants,
        audited_suite_coverage=audited_suite,
    )

    live_snapshot = manifest_module._scheduler_report_authority_snapshot(fixture.journal)
    live_parent_attempt = next(
        attempt
        for attempt in live_snapshot.journal.provider_attempts
        if attempt.task_id == fixture.promotion.parent_task_id
    )
    assert manifest_module._promoted_parent_usage_is_accountable(
        live_parent_attempt.usage_record,
        require_certification=False,
    )
    assert manifest_module._usage_has_configured_approved_model_custody(
        config,
        fixture.structural_artifact.parent.usage_record,
    )

    raw_inventory, promoted_inventory = _validate_promoted_fixture_manifest_replay(
        config=config,
        coverage=coverage,
        fixture=fixture,
        detached=False,
    )
    parent_surface_id = next(
        origin.surface_id
        for origin in fixture.structural_artifact.origins
        if origin.origin_kind is TruncationSurfaceOriginKind.PARENT_PROVISIONAL
    )
    parent_reference = next(
        reference
        for surface in coverage.surfaces
        if surface.surface_id == parent_surface_id
        for reference in surface.evidence_references
        if reference.credited
    )
    assert parent_reference.artifact_sha256 == fixture.structural_artifact.artifact_sha256

    fresh_coverage = _fresh_manifest_replay_value(coverage)
    fresh_raw_inventory = _fresh_manifest_replay_value(raw_inventory)
    fresh_promoted_inventory = _fresh_manifest_replay_value(promoted_inventory)
    reopened = _open_promoted_fixture_for_verification(fixture)
    try:
        with pytest.raises(ValueError, match="lacks live pre-dispatch runtime authority"):
            _validate_promoted_fixture_manifest_replay(
                config=config,
                coverage=fresh_coverage,
                fixture=fixture,
                journal=reopened,
                detached=True,
                inventory=fresh_raw_inventory,
                promoted_inventory=fresh_promoted_inventory,
            )
        with pytest.raises(ValueError, match="lacks exact REAL model custody"):
            _validate_promoted_fixture_manifest_replay(
                config=registry_only_config,
                coverage=fresh_coverage,
                fixture=fixture,
                journal=reopened,
                detached=True,
                inventory=fresh_raw_inventory,
                promoted_inventory=fresh_promoted_inventory,
            )

        promotion_entry = fresh_promoted_inventory.promotions[0]
        tampered_promotion = promotion_entry.model_copy(
            update={"recovered_output_artifact_sha256": "f" * 64}
        )
        tampered_inventory = fresh_promoted_inventory.model_copy(
            update={"promotions": (tampered_promotion,)}
        )
        with pytest.raises(ValueError, match="parent promotion custody"):
            _validate_promoted_fixture_manifest_replay(
                config=config,
                coverage=fresh_coverage,
                fixture=fixture,
                journal=reopened,
                detached=True,
                inventory=fresh_raw_inventory,
                promoted_inventory=tampered_inventory,
            )

        parent_surface = next(
            surface
            for surface in fresh_coverage.surfaces
            if surface.surface_id == parent_surface_id
        )
        forged_reference = parent_surface.evidence_references[0].model_copy(
            update={"root_lineage": "sha256:" + "f" * 64}
        )
        forged_surface = parent_surface.model_copy(
            update={"evidence_references": [forged_reference]}
        )
        forged_coverage = fresh_coverage.model_copy(
            update={
                "surfaces": [
                    forged_surface if surface.surface_id == parent_surface_id else surface
                    for surface in fresh_coverage.surfaces
                ]
            }
        )
        with pytest.raises(ValueError, match="contradicts exact scheduler artifact custody"):
            _validate_promoted_fixture_manifest_replay(
                config=config,
                coverage=forged_coverage,
                fixture=fixture,
                journal=reopened,
                detached=True,
                inventory=fresh_raw_inventory,
                promoted_inventory=fresh_promoted_inventory,
            )
    finally:
        reopened.close()


def test_promoted_parent_substitution_cannot_earn_live_or_detached_credit(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
) -> None:
    model_id = "synthetic/auditor-v1"
    config = _config_with_promoted_surface_manifest_lineage(config_factory(), model_id)
    index, graphs, invariants, audited_suite, requests = _promoted_surface_inputs()
    context = _promoted_surface_context(
        requests,
        _usage("source_audit", model_id, "substituted-parent-context"),
        index,
        graphs,
    )
    records = tuple(_record(request, "source_audit", index, graphs) for request in requests)

    def mark_truncated_usage_substituted(usage: UsageRecord) -> UsageRecord:
        if usage.status != "rejected_truncated_response":
            return usage
        return reattest_synthetic_real_usage(
            usage.model_copy(update={"substitution_detected": True})
        )

    fixture = _basic_promoted_surface_fixture(
        tmp_path / "substituted-promoted-parent",
        requests=requests,
        records=records,
        context=context,
        usage_transform=mark_truncated_usage_substituted,
    )
    exact_parent_usage = fixture.parent_usage.model_copy(update={"substitution_detected": False})
    assert manifest_module._promoted_parent_usage_is_accountable(
        exact_parent_usage,
        require_certification=False,
    )
    for drifted_parent_usage in (
        exact_parent_usage.model_copy(update={"requested_model": "synthetic/request-drift"}),
        exact_parent_usage.model_copy(update={"returned_model": "synthetic/return-drift"}),
        exact_parent_usage.model_copy(update={"actual_model": "synthetic/actual-drift"}),
        exact_parent_usage.model_copy(
            update={
                "routing": {
                    **exact_parent_usage.routing,
                    "selected_model": "synthetic/selection-drift",
                }
            }
        ),
    ):
        assert not manifest_module._promoted_parent_usage_is_accountable(
            drifted_parent_usage,
            require_certification=False,
        )
    coverage = _coverage_from_promoted_surface_fixture(
        config,
        fixture,
        index=index,
        graphs=graphs,
        invariants=invariants,
        audited_suite_coverage=audited_suite,
    )
    parent_surface_ids = {
        origin.surface_id
        for origin in fixture.structural_artifact.origins
        if origin.origin_kind is TruncationSurfaceOriginKind.PARENT_PROVISIONAL
    }
    parent_references = [
        reference
        for surface in coverage.surfaces
        if surface.surface_id in parent_surface_ids
        for reference in surface.evidence_references
        if reference.artifact_sha256 == fixture.structural_artifact.artifact_sha256
    ]
    assert parent_references
    assert not any(reference.credited for reference in parent_references)

    snapshot = manifest_module._scheduler_report_authority_snapshot(fixture.journal)
    raw_inventory, promoted_inventory = _manifest_model_review_inventories(fixture, snapshot)
    with pytest.raises(ValueError, match="parent lacks exact REAL model custody"):
        _validate_promoted_fixture_manifest_replay(
            config=config,
            coverage=coverage,
            fixture=fixture,
            detached=False,
            inventory=raw_inventory,
            promoted_inventory=promoted_inventory,
        )

    fresh_coverage = _fresh_manifest_replay_value(coverage)
    fresh_raw_inventory = _fresh_manifest_replay_value(raw_inventory)
    fresh_promoted_inventory = _fresh_manifest_replay_value(promoted_inventory)
    reopened = _open_promoted_fixture_for_verification(fixture)
    try:
        with pytest.raises(ValueError, match="parent lacks exact REAL model custody"):
            _validate_promoted_fixture_manifest_replay(
                config=config,
                coverage=fresh_coverage,
                fixture=fixture,
                journal=reopened,
                detached=True,
                inventory=fresh_raw_inventory,
                promoted_inventory=fresh_promoted_inventory,
            )
    finally:
        reopened.close()


def test_promoted_parent_surface_rejects_missing_forged_serialized_and_swapped_custody(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
) -> None:
    model_id = "synthetic/auditor-v1"
    config = _config_with_promoted_surface_manifest_lineage(config_factory(), model_id)
    index, graphs, invariants, audited_suite, requests = _promoted_surface_inputs()
    context_usage = _usage("source_audit", model_id, "promoted-negative-context-only")
    context = _promoted_surface_context(requests, context_usage, index, graphs)
    records = tuple(_record(request, "source_audit", index, graphs) for request in requests)
    exact = _basic_promoted_surface_fixture(
        tmp_path / "promoted-negative-exact",
        requests=requests,
        records=records,
        context=context,
    )
    swapped = _basic_promoted_surface_fixture(
        tmp_path / "promoted-negative-swapped",
        requests=requests,
        records=records,
        context=context,
    )
    parent_surface_id = next(
        origin.surface_id
        for origin in exact.structural_artifact.origins
        if origin.origin_kind is TruncationSurfaceOriginKind.PARENT_PROVISIONAL
    )

    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(exact.surface_capability)
    exact_projection = require_verified_promoted_truncation_recovery_surface_coverage(
        exact.surface_capability
    )
    exact_coverage = _coverage_from_promoted_surface_fixture(
        config,
        exact,
        index=index,
        graphs=graphs,
        invariants=invariants,
        audited_suite_coverage=audited_suite,
    )
    exact_parent_surface = next(
        surface for surface in exact_coverage.surfaces if surface.surface_id == parent_surface_id
    )
    assert exact_parent_surface.reviewed
    assert exact_projection.parent_usage_record is exact.parent_usage

    missing_child_artifact = _coverage_from_promoted_surface_fixture(
        config,
        exact,
        index=index,
        graphs=graphs,
        invariants=invariants,
        audited_suite_coverage=audited_suite,
        review_artifacts=list(exact.child_artifacts[1:]),
    )
    missing_child_parent_surface = next(
        surface
        for surface in missing_child_artifact.surfaces
        if surface.surface_id == parent_surface_id
    )
    assert not missing_child_parent_surface.reviewed
    assert not any(
        reference.credited for reference in missing_child_parent_surface.evidence_references
    )

    forged = object.__new__(VerifiedPromotedTruncationRecoverySurfaceCoverage)
    serialized_projection = json.loads(
        require_verified_promoted_truncation_recovery_surface_coverage(
            exact.surface_capability
        ).artifact.model_dump_json()
    )
    recovery_coordinates = tuple(
        (
            request.logical_request_id,
            request.request_limit_scope,
            request.request_limit_count_before,
        )
        for request in exact.scheduler_artifact.recovery_model_requests
    )

    def coverage_with(
        capabilities: tuple[Any, ...],
    ) -> ModelReviewCoverage:
        return build_model_review_coverage(
            config,
            usage_records=[exact.parent_usage, *exact.child_usages],
            review_artifacts=list(exact.child_artifacts),
            review_contexts_by_request={
                exact.parent_usage.request_id: [exact.parent_context],
                **{
                    usage.request_id: [context]
                    for usage, context in zip(
                        exact.child_usages,
                        exact.child_contexts,
                        strict=True,
                    )
                },
            },
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            minimum_critical_root_lineages=2,
            audited_suite_coverage=audited_suite,
            source_contents_by_path={_PATH: _SOURCE},
            recovery_usage_coordinates=recovery_coordinates,
            promoted_recovery_surface_coverages=capabilities,
        )

    for forged_capabilities in (
        (forged,),
        (cast(Any, serialized_projection),),
    ):
        with pytest.raises(ValueError, match="promoted recovery capability is absent"):
            coverage_with(forged_capabilities)

    for nonauthorizing_capabilities in ((), (swapped.surface_capability,)):
        coverage = coverage_with(nonauthorizing_capabilities)
        parent_surface = next(
            surface for surface in coverage.surfaces if surface.surface_id == parent_surface_id
        )
        assert not parent_surface.reviewed
        assert not any(reference.credited for reference in parent_surface.evidence_references)

    exact.journal.close()
    swapped.journal.close()


def test_promoted_zero_retained_recursive_surface_credits_only_three_ordinary_leaves(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
) -> None:
    model_id = "synthetic/auditor-v1"
    config = _config_with_promoted_surface_model(config_factory(), model_id)
    index, graphs, invariants, audited_suite, requests = _promoted_surface_inputs()
    context_usage = _usage("source_audit", model_id, "recursive-promoted-context-only")
    context = _promoted_surface_context(requests, context_usage, index, graphs)
    records = tuple(_record(request, "source_audit", index, graphs) for request in requests)
    fixture = _basic_promoted_recursive_surface_fixture(
        tmp_path / "promoted-recursive-credit",
        requests=requests,
        records=records,
        context=context,
    )

    coverage = _coverage_from_promoted_recursive_surface_fixture(
        config,
        fixture,
        index=index,
        graphs=graphs,
        invariants=invariants,
        audited_suite_coverage=audited_suite,
    )
    projection = require_verified_promoted_recursive_truncation_recovery_surface_coverage(
        fixture.surface_capability
    )
    assert projection.parent_usage_record is fixture.parent_usage
    assert projection.bridge_usage_record is fixture.bridge_usage
    assert all(
        projected is expected
        for projected, expected in zip(
            projection.leaf_usage_records,
            fixture.leaf_usages,
            strict=True,
        )
    )
    surfaces_by_id = {surface.surface_id: surface for surface in coverage.surfaces}
    leaf_artifacts_by_surface = {
        record.surface_id: artifact
        for artifact in fixture.leaf_artifacts
        for record in artifact.records
    }

    assert not projection.artifact.parent.projection.surface_reviews
    assert not any(
        origin.origin_kind is TruncationSurfaceOriginKind.PARENT_PROVISIONAL
        for origin in projection.artifact.origins
    )
    assert coverage.overall.numerator == coverage.overall.denominator == len(requests)
    assert set(leaf_artifacts_by_surface) == set(surfaces_by_id)
    for surface_id, artifact in leaf_artifacts_by_surface.items():
        references = surfaces_by_id[surface_id].evidence_references
        assert len(references) == 1
        assert references[0].credited
        assert references[0].request_id == artifact.request_id
        assert references[0].artifact_sha256 == artifact.artifact_sha256
        assert references[0].artifact_sha256 != projection.artifact.artifact_sha256
    assert all(
        reference.request_id
        not in {fixture.parent_usage.request_id, fixture.bridge_usage.request_id}
        and reference.artifact_sha256 != projection.artifact.artifact_sha256
        for surface in coverage.surfaces
        for reference in surface.evidence_references
    )
    fixture.journal.close()


def test_recursive_promoted_parent_manifest_replay_joins_bridge_and_rejects_tamper(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
) -> None:
    model_id = "synthetic/auditor-v1"
    config = _config_with_promoted_surface_manifest_lineage(config_factory(), model_id)
    index, graphs, invariants, audited_suite, requests = _promoted_surface_inputs()
    context = _promoted_surface_context(
        requests,
        _usage("source_audit", model_id, "recursive-manifest-context"),
        index,
        graphs,
    )
    records = tuple(_record(request, "source_audit", index, graphs) for request in requests)
    fixture = _basic_promoted_recursive_surface_fixture(
        tmp_path / "recursive-promoted-manifest-replay",
        requests=requests,
        records=records,
        context=context,
        parent_retained_count=1,
    )
    coverage = _coverage_from_promoted_recursive_surface_fixture(
        config,
        fixture,
        index=index,
        graphs=graphs,
        invariants=invariants,
        audited_suite_coverage=audited_suite,
    )

    raw_inventory, promoted_inventory = _validate_promoted_fixture_manifest_replay(
        config=config,
        coverage=coverage,
        fixture=fixture,
        detached=False,
    )
    parent_surface_id = next(
        origin.surface_id
        for origin in fixture.structural_artifact.origins
        if origin.origin_kind is TruncationSurfaceOriginKind.PARENT_PROVISIONAL
    )
    assert any(
        reference.credited
        and reference.artifact_sha256 == fixture.structural_artifact.artifact_sha256
        for surface in coverage.surfaces
        if surface.surface_id == parent_surface_id
        for reference in surface.evidence_references
    )

    fresh_coverage = _fresh_manifest_replay_value(coverage)
    fresh_raw_inventory = _fresh_manifest_replay_value(raw_inventory)
    fresh_promoted_inventory = _fresh_manifest_replay_value(promoted_inventory)
    reopened = _open_promoted_fixture_for_verification(fixture)
    try:
        with pytest.raises(ValueError, match="lacks live pre-dispatch runtime authority"):
            _validate_promoted_fixture_manifest_replay(
                config=config,
                coverage=fresh_coverage,
                fixture=fixture,
                journal=reopened,
                detached=True,
                inventory=fresh_raw_inventory,
                promoted_inventory=fresh_promoted_inventory,
            )

        promotion_entry = fresh_promoted_inventory.promotions[0]
        tampered_bridge = promotion_entry.artifact.bridge.model_copy(
            update={"usage_record_sha256": "f" * 64}
        )
        tampered_artifact = promotion_entry.artifact.model_copy(update={"bridge": tampered_bridge})
        tampered_promotion = promotion_entry.model_copy(update={"artifact": tampered_artifact})
        tampered_inventory = fresh_promoted_inventory.model_copy(
            update={"promotions": (tampered_promotion,)}
        )
        with pytest.raises(ValueError, match="bridge custody"):
            _validate_promoted_fixture_manifest_replay(
                config=config,
                coverage=fresh_coverage,
                fixture=fixture,
                journal=reopened,
                detached=True,
                inventory=fresh_raw_inventory,
                promoted_inventory=tampered_inventory,
            )
    finally:
        reopened.close()


@pytest.mark.parametrize("recursive", (False, True))
def test_detached_promoted_parent_replays_semantic_authority(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
    recursive: bool,
) -> None:
    model_id = "synthetic/auditor-v1"
    config = _config_with_promoted_surface_manifest_lineage(config_factory(), model_id)
    index, graphs, invariants, audited_suite, requests = _promoted_surface_inputs()
    context = _promoted_surface_context(
        requests,
        _usage("source_audit", model_id, f"promoted-semantic-{recursive}-context"),
        index,
        graphs,
    )
    records = tuple(_record(request, "source_audit", index, graphs) for request in requests)
    fixture = (
        _basic_promoted_recursive_surface_fixture(
            tmp_path / "recursive-promoted-semantic-replay",
            requests=requests,
            records=records,
            context=context,
            parent_retained_count=1,
        )
        if recursive
        else _basic_promoted_surface_fixture(
            tmp_path / "direct-promoted-semantic-replay",
            requests=requests,
            records=records,
            context=context,
        )
    )
    parent_surface_id = next(
        origin.surface_id
        for origin in fixture.structural_artifact.origins
        if origin.origin_kind is TruncationSurfaceOriginKind.PARENT_PROVISIONAL
    )
    semantic_index = SoliditySymbolIndex.model_validate(
        {
            **index.model_dump(mode="python"),
            "entities": [
                entity.model_copy(
                    update={
                        "source_hash": hashlib.sha256(
                            f"detached-semantic-drift:{entity.id}".encode()
                        ).hexdigest()
                    }
                )
                for entity in index.entities
            ],
        }
    )
    coverage = (
        _coverage_from_promoted_recursive_surface_fixture(
            config,
            cast(_PromotedRecursiveParentSurfaceFixture, fixture),
            index=index,
            graphs=graphs,
            invariants=invariants,
            audited_suite_coverage=audited_suite,
        )
        if recursive
        else _coverage_from_promoted_surface_fixture(
            config,
            cast(_PromotedParentSurfaceFixture, fixture),
            index=index,
            graphs=graphs,
            invariants=invariants,
            audited_suite_coverage=audited_suite,
        )
    )
    parent_reference = next(
        reference
        for surface in coverage.surfaces
        if surface.surface_id == parent_surface_id
        for reference in surface.evidence_references
        if reference.artifact_sha256 == fixture.structural_artifact.artifact_sha256
    )
    assert parent_reference.credited
    fresh_coverage = _fresh_manifest_replay_value(coverage)
    snapshot = manifest_module._scheduler_report_authority_snapshot(fixture.journal)
    raw_inventory, promoted_inventory = _manifest_model_review_inventories(
        fixture,
        snapshot,
    )
    fresh_raw_inventory = _fresh_manifest_replay_value(raw_inventory)
    fresh_promoted_inventory = _fresh_manifest_replay_value(promoted_inventory)
    reopened = _open_promoted_fixture_for_verification(fixture)
    try:
        with pytest.raises(
            ValueError,
            match="contradicts exact scheduler artifact custody",
        ):
            _validate_promoted_fixture_manifest_replay(
                config=config,
                coverage=fresh_coverage,
                fixture=fixture,
                journal=reopened,
                detached=True,
                inventory=fresh_raw_inventory,
                promoted_inventory=fresh_promoted_inventory,
                index=semantic_index,
            )
    finally:
        reopened.close()


@pytest.mark.parametrize("recursive", (False, True))
def test_detached_promoted_parent_rejects_context_reseal_against_retained_authority(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
    recursive: bool,
) -> None:
    model_id = "synthetic/auditor-v1"
    config = _config_with_promoted_surface_manifest_lineage(config_factory(), model_id)
    index, graphs, invariants, audited_suite, requests = _promoted_surface_inputs()
    forged_context = _promoted_surface_context(
        requests,
        _usage("source_audit", model_id, f"promoted-reseal-{recursive}-forged"),
        index,
        graphs,
    )
    actual_context = _promoted_surface_context(
        requests[:1],
        _usage("source_audit", model_id, f"promoted-reseal-{recursive}-actual"),
        index,
        graphs,
    )
    records = tuple(_record(request, "source_audit", index, graphs) for request in requests)
    fixture = (
        _basic_promoted_recursive_surface_fixture(
            tmp_path / "recursive-promoted-context-reseal",
            requests=requests,
            records=records,
            context=forged_context,
            parent_retained_count=1,
        )
        if recursive
        else _basic_promoted_surface_fixture(
            tmp_path / "direct-promoted-context-reseal",
            requests=requests,
            records=records,
            context=forged_context,
        )
    )
    coverage = (
        _coverage_from_promoted_recursive_surface_fixture(
            config,
            cast(_PromotedRecursiveParentSurfaceFixture, fixture),
            index=index,
            graphs=graphs,
            invariants=invariants,
            audited_suite_coverage=audited_suite,
        )
        if recursive
        else _coverage_from_promoted_surface_fixture(
            config,
            cast(_PromotedParentSurfaceFixture, fixture),
            index=index,
            graphs=graphs,
            invariants=invariants,
            audited_suite_coverage=audited_suite,
        )
    )
    parent_surface_id = next(
        origin.surface_id
        for origin in fixture.structural_artifact.origins
        if origin.origin_kind is TruncationSurfaceOriginKind.PARENT_PROVISIONAL
    )
    assert any(
        reference.credited
        for surface in coverage.surfaces
        if surface.surface_id == parent_surface_id
        for reference in surface.evidence_references
        if reference.artifact_sha256 == fixture.structural_artifact.artifact_sha256
    )

    snapshot = manifest_module._scheduler_report_authority_snapshot(fixture.journal)
    raw_inventory, promoted_inventory = _manifest_model_review_inventories(fixture, snapshot)
    retained_context_inventory = raw_inventory.model_copy(
        update={
            "context_authorities": tuple(
                authority.model_copy(update={"context": actual_context})
                if authority.request_id == fixture.parent_usage.request_id
                else authority
                for authority in raw_inventory.context_authorities
            )
        }
    )
    pre_dispatch_tasks = dict(snapshot.tasks_by_task_id or {})
    pre_dispatch_task = pre_dispatch_tasks[fixture.promotion.parent_task_id]
    pre_dispatch_tasks[fixture.promotion.parent_task_id] = SimpleNamespace(
        logical_request_id=fixture.parent_usage.request_id,
        role=pre_dispatch_task.role,
        model_surface_review_request_manifest_sha256=(
            ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(
                tuple(actual_context.requested_model_surfaces)
            )
        ),
    )
    pre_dispatch_activations = dict(snapshot.activations_by_task_id or {})
    pre_dispatch_activations[fixture.promotion.parent_task_id] = SimpleNamespace(
        user_prompt_sha256=hashlib.sha256(render_context(actual_context).encode()).hexdigest(),
        provider_prompt_sha256=fixture.parent_usage.prompt_sha256,
        response_schema_sha256=fixture.parent_usage.schema_sha256,
    )
    pre_dispatch_snapshot = manifest_module._SchedulerReportAuthoritySnapshot(
        journal=snapshot.journal,
        outputs_by_task_id=snapshot.outputs_by_task_id,
        pass_results_by_kind=snapshot.pass_results_by_kind,
        tasks_by_task_id=pre_dispatch_tasks,
        activations_by_task_id=pre_dispatch_activations,
    )
    with pytest.raises(
        ValueError,
        match="contradicts exact scheduler artifact custody",
    ):
        manifest_module._validate_model_review_artifact_inventory_against_scheduler(
            report=cast(Any, SimpleNamespace(model_review_coverage=coverage)),
            inventory=raw_inventory,
            snapshot=pre_dispatch_snapshot,
            config=config,
            promoted_inventory=promoted_inventory,
            detached=True,
            index=index,
            graphs=graphs,
        )
    reopened = _open_promoted_fixture_for_verification(fixture)
    try:
        with pytest.raises(
            ValueError,
            match="contradicts exact scheduler artifact custody",
        ):
            _validate_promoted_fixture_manifest_replay(
                config=config,
                coverage=_fresh_manifest_replay_value(coverage),
                fixture=fixture,
                journal=reopened,
                detached=True,
                inventory=_fresh_manifest_replay_value(retained_context_inventory),
                promoted_inventory=_fresh_manifest_replay_value(promoted_inventory),
                index=index,
                graphs=graphs,
            )
    finally:
        reopened.close()


def test_recursive_promoted_fallback_cannot_earn_live_or_detached_parent_credit(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
) -> None:
    model_id = "synthetic/auditor-v1"
    config = _config_with_promoted_surface_manifest_lineage(config_factory(), model_id)
    index, graphs, invariants, audited_suite, requests = _promoted_surface_inputs()
    context = _promoted_surface_context(
        requests,
        _usage("source_audit", model_id, "fallback-recursive-parent-context"),
        index,
        graphs,
    )
    records = tuple(_record(request, "source_audit", index, graphs) for request in requests)

    def mark_truncated_usage_as_fallback(usage: UsageRecord) -> UsageRecord:
        if usage.status != "rejected_truncated_response":
            return usage
        return reattest_synthetic_real_usage(
            usage.model_copy(
                update={
                    "fallback_used": True,
                    "routing": {
                        **usage.routing,
                        "provider_fallback_used": True,
                    },
                }
            )
        )

    fixture = _basic_promoted_recursive_surface_fixture(
        tmp_path / "fallback-recursive-promoted-parent",
        requests=requests,
        records=records,
        context=context,
        parent_retained_count=1,
        usage_transform=mark_truncated_usage_as_fallback,
    )
    coverage = _coverage_from_promoted_recursive_surface_fixture(
        config,
        fixture,
        index=index,
        graphs=graphs,
        invariants=invariants,
        audited_suite_coverage=audited_suite,
    )
    parent_surface_ids = {
        origin.surface_id
        for origin in fixture.structural_artifact.origins
        if origin.origin_kind is TruncationSurfaceOriginKind.PARENT_PROVISIONAL
    }
    parent_references = [
        reference
        for surface in coverage.surfaces
        if surface.surface_id in parent_surface_ids
        for reference in surface.evidence_references
        if reference.artifact_sha256 == fixture.structural_artifact.artifact_sha256
    ]
    assert parent_references
    assert not any(reference.credited for reference in parent_references)

    snapshot = manifest_module._scheduler_report_authority_snapshot(fixture.journal)
    raw_inventory, promoted_inventory = _manifest_model_review_inventories(fixture, snapshot)
    with pytest.raises(ValueError, match="parent lacks exact REAL model custody"):
        _validate_promoted_fixture_manifest_replay(
            config=config,
            coverage=coverage,
            fixture=fixture,
            detached=False,
            inventory=raw_inventory,
            promoted_inventory=promoted_inventory,
        )

    fresh_coverage = _fresh_manifest_replay_value(coverage)
    fresh_raw_inventory = _fresh_manifest_replay_value(raw_inventory)
    fresh_promoted_inventory = _fresh_manifest_replay_value(promoted_inventory)
    reopened = _open_promoted_fixture_for_verification(fixture)
    try:
        with pytest.raises(ValueError, match="parent lacks exact REAL model custody"):
            _validate_promoted_fixture_manifest_replay(
                config=config,
                coverage=fresh_coverage,
                fixture=fixture,
                journal=reopened,
                detached=True,
                inventory=fresh_raw_inventory,
                promoted_inventory=fresh_promoted_inventory,
            )
    finally:
        reopened.close()


def test_promoted_recursive_surface_rejects_missing_bridge_and_leaf_custody(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
) -> None:
    model_id = "synthetic/auditor-v1"
    config = _config_with_promoted_surface_model(config_factory(), model_id)
    index, graphs, invariants, audited_suite, requests = _promoted_surface_inputs()
    context_usage = _usage("source_audit", model_id, "recursive-negative-context-only")
    context = _promoted_surface_context(requests, context_usage, index, graphs)
    records = tuple(_record(request, "source_audit", index, graphs) for request in requests)
    fixture = _basic_promoted_recursive_surface_fixture(
        tmp_path / "promoted-recursive-negative",
        requests=requests,
        records=records,
        context=context,
    )
    assert not fixture.structural_artifact.parent.projection.surface_reviews
    exact_contexts = {
        fixture.parent_usage.request_id: [fixture.parent_context],
        fixture.bridge_usage.request_id: [fixture.bridge_context],
        **{
            usage.request_id: [context]
            for usage, context in zip(
                fixture.leaf_usages,
                fixture.leaf_contexts,
                strict=True,
            )
        },
    }
    forged = object.__new__(VerifiedPromotedRecursiveTruncationRecoverySurfaceCoverage)
    serialized_bridge = UsageRecord.model_validate_json(fixture.bridge_usage.model_dump_json())
    invalid_live_custody_variants = (
        {
            "usage_records": [fixture.parent_usage, *fixture.leaf_usages],
        },
        {
            "usage_records": [
                fixture.parent_usage,
                serialized_bridge,
                *fixture.leaf_usages,
            ],
        },
        {
            "review_artifacts": list(fixture.leaf_artifacts[1:]),
        },
        {
            "review_contexts_by_request": {
                **exact_contexts,
                fixture.bridge_usage.request_id: [],
            },
        },
        {
            "review_contexts_by_request": {
                **exact_contexts,
                fixture.leaf_usages[0].request_id: [fixture.leaf_contexts[1]],
                fixture.leaf_usages[1].request_id: [fixture.leaf_contexts[0]],
            },
        },
    )
    invalid_limitation = (
        "promoted recursive zero-retained tree failed exact live custody; "
        "its leaf partition was not accepted as promoted recovery evidence"
    )
    for variant in invalid_live_custody_variants:
        coverage = _coverage_from_promoted_recursive_surface_fixture(
            config,
            fixture,
            index=index,
            graphs=graphs,
            invariants=invariants,
            audited_suite_coverage=audited_suite,
            **variant,  # type: ignore[arg-type]
        )
        assert invalid_limitation in coverage.limitations
        assert all(
            reference.artifact_sha256 != fixture.structural_artifact.artifact_sha256
            for surface in coverage.surfaces
            for reference in surface.evidence_references
        )

    without_capability = _coverage_from_promoted_recursive_surface_fixture(
        config,
        fixture,
        index=index,
        graphs=graphs,
        invariants=invariants,
        audited_suite_coverage=audited_suite,
        capabilities=(),
    )
    assert all(
        reference.artifact_sha256 != fixture.structural_artifact.artifact_sha256
        for surface in without_capability.surfaces
        for reference in surface.evidence_references
    )
    with pytest.raises(ValueError, match="promoted recovery capability is absent"):
        _coverage_from_promoted_recursive_surface_fixture(
            config,
            fixture,
            index=index,
            graphs=graphs,
            invariants=invariants,
            audited_suite_coverage=audited_suite,
            capabilities=(forged,),
        )

    fixture.journal.close()


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
    context = _review_context(
        selected,
        _usage("source_audit", config.models.source_audit.primary, "compact-context-seed"),
        index,
        graphs,
    )
    compact_index = index.model_copy(
        update={
            "entities": [
                entity
                for entity in index.entities
                if entity.id in {"function:Vault.deposit", "state:Vault.totalAssets"}
            ]
        }
    )
    compact_edges = [edge for edge in graphs.edges if edge.graph is SolidityGraphKind.STATE_WRITE]
    compact_graphs = graphs.model_copy(
        update={
            "edges": compact_edges,
            "retained_occurrences": _edge_occurrences(compact_edges),
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
    with _authorized_ordinary_review_evidence(
        config,
        index=index,
        graphs=graphs,
        requests=selected,
        reviewers=(("source_audit", config.models.source_audit.primary),),
        contexts=(context,),
    ) as evidence:
        coverage = build_model_review_coverage(
            config,
            usage_records=list(evidence.usage_records),
            review_artifacts=list(evidence.artifacts),
            review_contexts_by_request=evidence.contexts_by_request,
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            ordinary_review_authorizations=evidence.authorizations,
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
    _with_context_request_evidence(usage, context, request_role=usage.role)

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
    _with_context_request_evidence(usage, original_context, request_role=usage.role)
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
    _with_context_request_evidence(usage, context, request_role=usage.role)
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
    semantic_failures = model_surface_review_record_validation_failures(
        state_request,
        generic_loop,
        "source_audit",
        index=index,
        graphs=graphs,
    )
    assert any("generic boilerplate" in failure for failure in semantic_failures)
    assert any("exact known" in failure for failure in semantic_failures)

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
    assert "failure_count=" in reason
    assert "full_failure_set_sha256=" in reason
    assert len(reason) <= 1_000


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
    with _authorized_ordinary_review_evidence(
        config,
        index=index,
        graphs=graphs,
        requests=requests,
        reviewers=(("source_audit", source), ("source_audit", alias)),
    ) as evidence:
        coverage = build_model_review_coverage(
            config,
            usage_records=list(evidence.usage_records),
            review_artifacts=list(evidence.artifacts),
            review_contexts_by_request=evidence.contexts_by_request,
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            ordinary_review_authorizations=evidence.authorizations,
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
