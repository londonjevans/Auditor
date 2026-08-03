from __future__ import annotations

import hashlib
import json
import pickle
from dataclasses import replace
from datetime import UTC, datetime

import pytest

import tests.scheduler_support as scheduler_support
from mmaudit.agents.specialists import SPECIALIST_ROLE_REGISTRY, canonical_specialist_role
from mmaudit.benchmark.certificate import (
    BenchmarkCertificateVerification,
    CertificateVerificationOrigin,
    CertificateVerificationStatus,
    FileBackedBenchmarkVerificationEvidence,
)
from mmaudit.config import (
    AuditConfig,
    SmartContractsConfig,
    model_lineage_index,
    validate_model_independence,
)
from mmaudit.constants import (
    ALL_SPECIALIST_ROLES,
    SPECIALIST_INVESTIGATOR_ROLES,
)
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.qualification import (
    QualifiedReasoningRoleBinding,
    VerifiedProductionQualification,
    VerifiedTierAModelQualification,
)
from mmaudit.models.reasoning import (
    ReasoningControlProfile,
    ReasoningExecutionEvidence,
    ReasoningPolicyArtifact,
    ReasoningRequestPlanEvidence,
    resolve_reasoning_request_role,
)
from mmaudit.models.scheduler import (
    SchedulerBindings,
    SchedulerCampaignManifest,
    SchedulerCostLedgerBaseline,
    SchedulerPassKind,
    SchedulerPassPlan,
    SchedulerPrivacyEvidenceCustody,
    SchedulerScope,
    SchedulerShardDescriptor,
    SchedulerShardInventory,
    SchedulerSourceDescriptor,
    SchedulerTaskActivation,
    SchedulerTaskKind,
    SchedulerTaskOutput,
    SchedulerTaskPlan,
)
from mmaudit.models.schemas import (
    AnalysisState,
    AuditProfile,
    AuditQualityStatus,
    AuditReport,
    AuditScope,
    AuditScopeAssessment,
    CandidateReproductionResolution,
    CompilationStatus,
    ContextExecutionEvidence,
    ContextRequestEvidence,
    CoverageMetric,
    CoverageProvenance,
    EconomicSimulationKind,
    EconomicSimulationPlan,
    EvidenceStrength,
    ExecutionEvidenceKind,
    FormalCampaignBounds,
    FormalCampaignObservation,
    FormalDependencyProvenance,
    FormalEvidence,
    FormalPropertyBinding,
    FormalResultKind,
    FormalToolRun,
    FormalToolStatus,
    FoundryTestExecutionSummary,
    InvariantCampaignCoverage,
    InvariantCategory,
    InvariantExecutionAttemptEvidence,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    InvariantSpec,
    InvariantSuite,
    InvariantTemplate,
    Location,
    MaximumAssuranceStatus,
    ModelRequestValidationStatus,
    ModelReviewCoverage,
    ModelReviewEvidenceReference,
    ModelReviewSurface,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewCitation,
    ModelSurfaceReviewEvidenceObservation,
    ModelSurfaceReviewReachability,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
    RepositoryCodeExecutionState,
    RepositoryMap,
    RepositorySuiteExecutionPolicy,
    RepositorySuiteFramework,
    RepositorySuiteInventoryArtifact,
    RepositorySuiteInventoryEvidence,
    RepositorySuiteInventoryKind,
    RepositorySuiteInventoryPhase,
    RepositorySuiteInventoryRecord,
    RepositorySuiteProjectInventoryEvidence,
    RepositorySuiteSelection,
    RepositorySuiteTestDescriptor,
    RepositoryTestExecution,
    RepositoryTestExecutionStatus,
    RepositoryTestKind,
    ReproductionIntegrityAssessment,
    ReproductionIntegrityCheck,
    ReproductionIntegrityCheckKind,
    ReproductionIntegrityStatus,
    ReproductionMinimizationEvidence,
    ReproductionResolutionKind,
    ReproductionResult,
    ReproductionSettlementEvidence,
    ReproductionSettlementStatus,
    ReproductionState,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
    ScopeComponent,
    ScopeComponentEvidence,
    ScopeEvidenceStatus,
    Severity,
    SolidityCompilationResult,
    SolidityCoverage,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphSet,
    SolidityProjectMetadata,
    SolidityProjectType,
    SolidityProvenance,
    SoliditySymbolIndex,
    SpecialistAcceptedOutcome,
    SpecialistAcceptedOutcomeKind,
    SpecialistExecutionRecord,
    SpecialistExecutionStatus,
    TransactionOrderingCapability,
    UsageRecord,
)
from mmaudit.models.usage import (
    candidate_falsifier_role,
    is_creditable_usage_record,
    request_token_plan_from_usage,
)
from mmaudit.orchestration.assurance import (
    FULL_SEMANTIC_GRAPHS,
    AssuranceRuntime,
    MaximumAssuranceContract,
    ProviderSessionProvenance,
    _is_real_model_usage,
    _issue_provider_session_provenance,
    is_qualifying_real_foundry_portfolio,
    is_qualifying_real_scanner_run,
)
from mmaudit.orchestration.budgets import AtomicRequestLimitReservationEvidence
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.orchestration.replay import (
    OfflineReplay,
    OfflineReplayComponent,
    OfflineReplayStatus,
    ReplayComponentKind,
    ReplayComponentStatus,
)
from mmaudit.orchestration.scheduler_runtime import build_scheduler_bindings
from mmaudit.reporting.markdown import render_markdown
from mmaudit.reporting.sarif import generate_sarif
from mmaudit.traceability import (
    ImplementationStatus,
    MaximumAssuranceTraceability,
    TraceabilityRequirement,
    build_traceability_matrix,
)
from tests.identity_fixtures import (
    bind_synthetic_usage_identity,
    reattest_synthetic_real_usage,
    rebind_synthetic_token_plan,
)
from tests.output_evidence_fixtures import synthetic_structured_output_routing
from tests.qualification_support import (
    bind_usage_to_qualification as _bind_base_usage_to_qualification,
)
from tests.qualification_support import (
    synthetic_production_qualification as _synthetic_production_qualification,
)
from tests.scheduler_support import (
    CompleteSchedulerFixture,
    SchedulerFixtureModelTask,
    build_complete_scheduler_artifact,
    build_complete_scheduler_fixture,
)


def _bind_usage_to_qualification(
    record: UsageRecord,
    qualification: VerifiedProductionQualification,
    now: datetime,
) -> UsageRecord:
    bound = _bind_base_usage_to_qualification(record, qualification, now)
    model = qualification.model_for(record.requested_model, now=now)
    rebound = bound.model_copy(
        update={
            "routing": {
                **bound.routing,
                "qualified_exact_model_id": model.exact_model_id,
                "qualified_canonical_model_slug": model.canonical_model_slug,
                "qualified_root_lineage": model.root_lineage,
                "qualified_provider_endpoint": model.approved_provider_endpoint,
                "qualified_provider_name": model.approved_provider_name,
                "qualified_endpoint_snapshot_sha256": model.endpoint_snapshot_sha256,
                "qualified_output_capability_sha256": model.output_capability_sha256,
                "qualified_structured_output_mode": model.structured_output_mode.value,
                "qualified_model_metadata_snapshot_sha256": (model.model_metadata_snapshot_sha256),
                "qualified_pricing_snapshot_sha256": model.pricing_snapshot_sha256,
                "qualified_roles": list(model.approved_roles),
                "qualification_verified_at": qualification.verified_at.isoformat(),
                "qualification_expires_at": model.expires_at.isoformat(),
                "endpoint_snapshot_sha256": model.endpoint_snapshot_sha256,
                "output_capability_sha256": model.output_capability_sha256,
                "endpoint_pricing_sha256": model.pricing_snapshot_sha256,
                "model_metadata_snapshot_sha256": model.model_metadata_snapshot_sha256,
            }
        }
    )
    output_bound = _with_output_evidence(
        rebound,
        endpoint_snapshot_sha256=model.endpoint_snapshot_sha256,
        output_capability_sha256=model.output_capability_sha256,
        mode=model.structured_output_mode,
    )
    binding = _reasoning_binding_for_usage(output_bound, model)
    policy = _reasoning_policy_for_model(model)
    assert policy.artifact_sha256 == binding.reasoning_policy_artifact_sha256
    plan = ReasoningRequestPlanEvidence.build(
        request_role=output_bound.role,
        policy=policy,
        endpoint_capability_sha256=binding.endpoint_reasoning_capability_sha256,
        qualification_binding_sha256=binding.binding_sha256,
    )
    active = plan.control_profile.mode != "disabled" and not (
        plan.control_profile.mode == "effort" and plan.control_profile.effort == "none"
    )
    return _with_reasoning_plan(
        output_bound,
        plan,
        observed_reasoning_tokens=1 if active else 0,
    )


def _reasoning_policy_for_model(
    model: VerifiedTierAModelQualification,
) -> ReasoningPolicyArtifact:
    controls_by_role: dict[str, ReasoningControlProfile] = {}
    for candidate in model.reasoning_bindings:
        prior = controls_by_role.setdefault(
            candidate.configured_policy_role,
            candidate.control_profile,
        )
        assert prior == candidate.control_profile
    return ReasoningPolicyArtifact.build(controls_by_role=controls_by_role)


def _reasoning_binding_for_usage(
    record: UsageRecord,
    model: VerifiedTierAModelQualification,
) -> QualifiedReasoningRoleBinding:
    resolution = resolve_reasoning_request_role(record.role)
    bindings = tuple(
        binding
        for binding in model.reasoning_bindings
        if binding.qualified_role == resolution.qualification_role
        and binding.configured_policy_role == resolution.configured_policy_role
    )
    assert len(bindings) == 1
    return bindings[0]


def _with_reasoning_plan(
    record: UsageRecord,
    plan: ReasoningRequestPlanEvidence,
    *,
    observed_reasoning_tokens: int | None,
) -> UsageRecord:
    routing = dict(record.routing)
    for field in (
        "request_token_plan",
        "request_token_plan_sha256",
        "atomic_token_reservations",
        "atomic_token_reservation_sha256s",
        "atomic_token_reservation",
        "atomic_token_reservation_sha256",
    ):
        routing.pop(field, None)
    bound = bind_synthetic_usage_identity(
        record.model_copy(
            update={
                "routing": routing,
                "reasoning_evidence": None,
                "reasoning_tokens": 0,
            }
        ),
        reasoning_plan=plan,
        observed_reasoning_tokens=(
            observed_reasoning_tokens if observed_reasoning_tokens is not None else 0
        ),
    )
    if observed_reasoning_tokens is not None:
        return bound
    assert bound.request_body_sha256 is not None
    token_plan_sha256 = bound.routing["request_token_plan_sha256"]
    assert isinstance(token_plan_sha256, str)
    unavailable = ReasoningExecutionEvidence.build(
        request_plan=plan,
        observed_reasoning_tokens=None,
        provider_completion_tokens=bound.completion_tokens,
        request_token_plan_sha256=token_plan_sha256,
        request_body_sha256=bound.request_body_sha256,
    )
    return reattest_synthetic_real_usage(
        bound.model_copy(
            update={
                "reasoning_evidence": unavailable,
                "reasoning_tokens": 0,
            }
        )
    )


def _with_output_evidence(
    record: UsageRecord,
    *,
    endpoint_snapshot_sha256: str,
    output_capability_sha256: str,
    mode: StructuredOutputMode,
) -> UsageRecord:
    assert record.actual_provider_endpoint is not None
    assert record.request_body_sha256 is not None
    assert record.schema_sha256 is not None
    assert record.response_sha256 is not None
    assert record.validated_response_sha256 is not None
    provider_policy_sha256 = record.routing["provider_policy_sha256"]
    routing = {
        **record.routing,
        "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
        "output_capability_sha256": output_capability_sha256,
        "structured_output": synthetic_structured_output_routing(
            configured_provider_endpoints=tuple(record.configured_provider_endpoints),
            selected_provider_endpoint=record.actual_provider_endpoint,
            endpoint_snapshot_sha256=endpoint_snapshot_sha256,
            output_capability_sha256=output_capability_sha256,
            prompt_sha256=record.prompt_sha256,
            request_body_sha256=record.request_body_sha256,
            provider_policy_sha256=provider_policy_sha256,
            schema_sha256=record.schema_sha256,
            original_response_sha256=record.response_sha256,
            validated_response_sha256=record.validated_response_sha256,
            mode=mode,
        ),
    }
    updated = record.model_copy(update={"routing": routing})
    reasoning = updated.reasoning_evidence
    if reasoning is not None and reasoning.request_plan.resolution.request_role == updated.role:
        return _with_reasoning_plan(
            updated,
            reasoning.request_plan,
            observed_reasoning_tokens=reasoning.observed_reasoning_tokens,
        )
    return bind_synthetic_usage_identity(
        rebind_synthetic_token_plan(
            updated.model_copy(
                update={
                    "reasoning_evidence": None,
                    "reasoning_tokens": 0,
                }
            )
        )
    )


def _specialists(*, families: int = 8) -> dict[str, dict[str, object]]:
    return {
        role: {
            "primary": f"specialist-{index % families}/model-{index % families}",
            "fallbacks": [],
            "quality_tier": "high",
            "capabilities": ["structured_json", "security_reasoning", "solidity"],
        }
        for index, role in enumerate(ALL_SPECIALIST_ROLES)
    }


def _maximum_config(
    config_factory,
    *,
    allow_downgrade: bool = False,
    families: int = 8,
    reasoning: dict[str, object] | None = None,
):
    specialists = _specialists(families=families)
    if families >= 3:
        specialists["falsifier"]["fallbacks"] = [
            "specialist-0/model-0",
            "specialist-1/model-1",
        ]
    models: dict[str, object] = {"specialists": specialists}
    if reasoning is not None:
        models["reasoning"] = reasoning
    return config_factory(
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        maximum_assurance={"allow_downgrade": allow_downgrade},
        models=models,
        smart_contracts={
            "solc_version": "0.8.30",
            "solc_sha256": "6" * 64,
        },
        reproduction={
            "expected_chain_id": 31_337,
            "pinned_block_number": 42,
        },
        scanners={
            "slither": {
                "version": "0.11.5",
                "sha256": "3" * 64,
            },
            "foundry_fork": {
                "version": "1.3.2",
                "sha256": "5" * 64,
            },
        },
        formal={
            "echidna_version": "1.0.0",
            "echidna_sha256": hashlib.sha256(b"echidna:executable").hexdigest(),
            "medusa_version": "1.0.0",
            "medusa_sha256": hashlib.sha256(b"medusa:executable").hexdigest(),
            "halmos_version": "1.0.0",
            "halmos_sha256": hashlib.sha256(b"halmos:executable").hexdigest(),
            "halmos_solver_version": "4.15.0",
            "halmos_solver_sha256": "e" * 64,
            "certora": {
                "enabled": True,
                "cli_version": "1.0.0",
                "cli_sha256": hashlib.sha256(b"certora:executable").hexdigest(),
                "source": "src/Vault.sol",
                "contract": "Vault",
                "specification": "certora/Vault.spec",
            },
        },
    ).effective()


def _model_metric(numerator: int, denominator: int, detail: str) -> CoverageMetric:
    return CoverageMetric(
        numerator=numerator,
        denominator=denominator,
        population=denominator,
        percentage=round((numerator / denominator) * 100, 4) if denominator else None,
        exclusions=[],
        not_applicable_evidence=([] if denominator else ["no synthetic surfaces of this category"]),
        confidence=1,
        provenance=[CoverageProvenance.MODEL_REVIEW],
        failures=[],
        state=AnalysisState.MODEL_ONLY,
        detail=detail,
    )


def _complete_model_coverage(
    usage_records: list[UsageRecord],
    scheduler_fixture: CompleteSchedulerFixture | None = None,
) -> tuple[ModelReviewCoverage, list[ModelSurfaceReviewArtifact]]:
    if scheduler_fixture is not None:
        artifacts = list(scheduler_fixture.model_surface_review_artifacts)
        references: list[ModelReviewEvidenceReference] = []
        surface_id: str | None = None
        location: Location | None = None
        source_path: str | None = None
        for role in ("business_logic", "configuration", "source_audit"):
            usage = next(record for record in usage_records if record.role == role)
            artifact = next(item for item in artifacts if item.request_id == usage.request_id)
            assert len(artifact.records) == 1
            review_record = artifact.records[0]
            assert review_record.citation.location is not None
            surface_id = surface_id or review_record.surface_id
            location = location or review_record.citation.location
            source_path = source_path or review_record.contract
            assert review_record.surface_id == surface_id
            references.append(
                ModelReviewEvidenceReference(
                    surface_id=review_record.surface_id,
                    request_id=usage.request_id,
                    artifact_sha256=artifact.artifact_sha256,
                    requested_model=usage.requested_model,
                    model=usage.actual_model,
                    review_role=role,
                    status=review_record.status,
                    root_lineage=str(usage.routing["qualified_root_lineage"]),
                    credited=True,
                    reason="credited: exact scheduler-bound synthetic response evidence",
                )
            )
        assert surface_id is not None and location is not None and source_path is not None
        references.sort(
            key=lambda item: (
                item.request_id,
                item.artifact_sha256,
                item.surface_id,
                item.review_role,
                item.status.value,
            )
        )
        surface = ModelReviewSurface(
            surface_id=surface_id,
            kind=ModelReviewSurfaceKind.SOURCE_FILE,
            subject_id=f"source:{source_path}",
            label=source_path,
            critical=True,
            locations=[location],
            evidence_references=references,
        )
        coverage = ModelReviewCoverage(
            applicable=True,
            critical_classification_complete=True,
            minimum_critical_root_lineages=3,
            surfaces=[surface],
            overall=_model_metric(1, 1, "synthetic scheduler-bound overall model coverage"),
            by_kind={
                kind: _model_metric(
                    1 if kind is ModelReviewSurfaceKind.SOURCE_FILE else 0,
                    1 if kind is ModelReviewSurfaceKind.SOURCE_FILE else 0,
                    f"synthetic {kind.value} model coverage",
                )
                for kind in ModelReviewSurfaceKind
            },
            critical=_model_metric(1, 1, "synthetic scheduler-bound critical model coverage"),
            critical_gate_passed=True,
        )
        return coverage, artifacts

    location = Location(
        path="src/Vault.sol",
        start_line=1,
        end_line=5,
        content_hash="a" * 64,
    )
    request = ModelSurfaceReviewRequest(
        surface_id=ModelSurfaceReviewRequest.calculate_surface_id(
            ModelReviewSurfaceKind.CONTRACT,
            "contract:Vault",
        ),
        kind=ModelReviewSurfaceKind.CONTRACT,
        subject_id="contract:Vault",
        contract="Vault",
        function_or_state_surface="Vault",
        critical=True,
        allowed_locations=(location,),
        allowed_symbols=("Vault",),
        invariant_considered="Assess declared security invariants across contract Vault.",
    )
    references: list[ModelReviewEvidenceReference] = []
    artifacts: list[ModelSurfaceReviewArtifact] = []
    for role in ("business_logic", "configuration", "source_audit"):
        usage = next(record for record in usage_records if record.role == role)
        citation = ModelSurfaceReviewCitation(location=location, symbol="Vault")
        record = ModelSurfaceReviewRecord(
            surface_id=request.surface_id,
            contract=request.contract,
            function_or_state_surface=request.function_or_state_surface,
            review_role=role,
            status=ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
            rationale="Synthetic substantive review found no invariant violation.",
            citation=citation,
            invariant_considered=request.invariant_considered,
            evidence_observations=(
                ModelSurfaceReviewEvidenceObservation(
                    citation=citation,
                    observed_behavior="The cited contract surface was checked for state transitions.",
                    security_relevance="The observed transitions preserve the declared contract invariant.",
                ),
            ),
            reachability=ModelSurfaceReviewReachability(
                entry_point=citation,
                path=(citation,),
                actor_or_caller="synthetic contract caller",
                preconditions=(),
            ),
            assumptions=(),
            confidence=1,
        )
        artifact_payload = {
            "schema_version": "1.0",
            "request_id": usage.request_id,
            "review_role": role,
            "requested_surface_ids": [request.surface_id],
            "requested_surface_ids_sha256": canonical_sha256([request.surface_id]),
            "requested_surface_manifest_sha256": (
                ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256([request])
            ),
            "rendered_context_sha256": "0" * 64,
            "prompt_sha256": usage.prompt_sha256,
            "response_sha256": usage.response_sha256,
            "validated_response_sha256": usage.validated_response_sha256,
            "response_schema_sha256": usage.schema_sha256,
            "records": [record.model_dump(mode="json")],
        }
        artifact_payload["artifact_sha256"] = ModelSurfaceReviewArtifact.calculate_artifact_sha256(
            artifact_payload
        )
        artifact = ModelSurfaceReviewArtifact.model_validate(artifact_payload)
        artifacts.append(artifact)
        references.append(
            ModelReviewEvidenceReference(
                surface_id=request.surface_id,
                request_id=usage.request_id,
                artifact_sha256=artifact.artifact_sha256,
                requested_model=usage.requested_model,
                model=usage.actual_model,
                review_role=role,
                status=record.status,
                root_lineage=(
                    "sha256:"
                    + hashlib.sha256(f"lineage:{usage.requested_model}".encode()).hexdigest()
                ),
                credited=True,
                reason="credited: synthetic response evidence passed validation",
            )
        )
    references.sort(
        key=lambda item: (
            item.request_id,
            item.artifact_sha256,
            item.surface_id,
            item.review_role,
            item.status.value,
        )
    )
    surface = ModelReviewSurface(
        surface_id=request.surface_id,
        kind=ModelReviewSurfaceKind.CONTRACT,
        subject_id="contract:Vault",
        label="Vault",
        critical=True,
        locations=[location],
        evidence_references=references,
    )
    coverage = ModelReviewCoverage(
        applicable=True,
        critical_classification_complete=True,
        minimum_critical_root_lineages=3,
        surfaces=[surface],
        overall=_model_metric(1, 1, "synthetic complete overall model coverage"),
        by_kind={
            kind: _model_metric(
                1 if kind is ModelReviewSurfaceKind.CONTRACT else 0,
                1 if kind is ModelReviewSurfaceKind.CONTRACT else 0,
                f"synthetic {kind.value} model coverage",
            )
            for kind in ModelReviewSurfaceKind
        },
        critical=_model_metric(1, 1, "synthetic complete critical model coverage"),
        critical_gate_passed=True,
    )
    return coverage, artifacts


def _complete_specialist_execution_records(
    usage_records: list[UsageRecord],
    accepted_outcomes: tuple[SpecialistAcceptedOutcome, ...] = (),
) -> list[SpecialistExecutionRecord]:
    accepted_by_request = {outcome.request_id: outcome for outcome in accepted_outcomes}
    assert len(accepted_by_request) == len(accepted_outcomes)
    records: list[SpecialistExecutionRecord] = []
    for role in ALL_SPECIALIST_ROLES:
        usage = next(
            record for record in usage_records if canonical_specialist_role(record.role) == role
        )
        context = ContextRequestEvidence.model_validate(usage.routing["context_request_evidence"])
        retained_context = ContextExecutionEvidence.model_validate(
            context.model_dump(
                mode="python",
                include={
                    "context_role",
                    "byte_budget",
                    "declared_bytes_used",
                    "rendered_bytes",
                    "source_bytes",
                    "configured_maximum_source_tokens_per_request",
                    "effective_source_byte_ceiling",
                    "rendered_sha256",
                },
            )
        )
        outcome = accepted_by_request.get(usage.request_id)
        if outcome is None:
            outcome_kind = (
                SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW
                if role in SPECIALIST_INVESTIGATOR_ROLES
                else {
                    "invariant_review": SpecialistAcceptedOutcomeKind.INVARIANT_REVIEW,
                    "test_generation": SpecialistAcceptedOutcomeKind.TEST_GENERATION,
                    "exploit_reproduction_planner": (SpecialistAcceptedOutcomeKind.TEST_GENERATION),
                    "falsifier": SpecialistAcceptedOutcomeKind.FALSIFICATION,
                    "report_quality": SpecialistAcceptedOutcomeKind.REPORT_QUALITY,
                }[role]
            )
            assert usage.validated_response_sha256 is not None
            outcome = SpecialistAcceptedOutcome.build(
                request_id=usage.request_id,
                specialist_role=role,
                request_role=usage.role,
                outcome_kind=outcome_kind,
                validated_response_sha256=usage.validated_response_sha256,
                context_request_evidence_sha256=context.evidence_sha256,
                requested_surface_count=(1 if role in SPECIALIST_INVESTIGATOR_ROLES else 0),
                surface_review_artifact_sha256=(
                    hashlib.sha256(f"specialist-surface:{role}".encode()).hexdigest()
                    if role in SPECIALIST_INVESTIGATOR_ROLES
                    else None
                ),
            )
        definition = SPECIALIST_ROLE_REGISTRY[role]
        records.append(
            SpecialistExecutionRecord(
                role=role,
                role_kind=definition.role_kind,
                responsibility=definition.mission,
                response_schema=definition.response_schema,
                schema_name=definition.effective_schema_name(),
                configured=True,
                execution_evidence=usage.execution_evidence,
                context_limit_bytes=context.byte_budget,
                context_budget_bytes=context.byte_budget,
                context_bytes_used=context.rendered_bytes,
                contexts=(retained_context,),
                request_contexts=(context,),
                accepted_outcomes=(outcome,),
                request_roles=[usage.role],
                successful_request_ids=(usage.request_id,),
                successful_requests=1,
                source_review_creditable_requests=(
                    1 if role in SPECIALIST_INVESTIGATOR_ROLES else 0
                ),
                status=SpecialistExecutionStatus.COMPLETED,
            )
        )
    return records


def _complete_assurance_scheduler_fixture(
    config: AuditConfig,
    qualification: VerifiedProductionQualification,
    now: datetime,
) -> CompleteSchedulerFixture:
    source = SchedulerSourceDescriptor.build(
        path="src/Vault.sol",
        sha256="a" * 64,
        size=1,
    )
    shard = SchedulerShardDescriptor.semantic(
        shard_id="shard-" + ("1" * 24),
        semantic_shard_sha256=hashlib.sha256(b"assurance:semantic-shard").hexdigest(),
        sources=(source,),
    )
    inventory = SchedulerShardInventory.build(
        semantic_inventory_sha256=hashlib.sha256(b"assurance:semantic-shard-inventory").hexdigest(),
        shards=(shard,),
    )
    cost_baseline = SchedulerCostLedgerBaseline.build(
        cap_usd_exact="250",
        spent_usd_exact="0",
        active_reserved_usd_exact="0",
        entries=(),
        ledger_identity_sha256=hashlib.sha256(
            b"assurance:operator-cost-ledger-identity"
        ).hexdigest(),
        ledger_snapshot_sha256=hashlib.sha256(b"assurance:pre-campaign-cost-ledger").hexdigest(),
    )
    provenance_sha256 = hashlib.sha256(b"assurance:privacy-provenance").hexdigest()
    privacy_custody = SchedulerPrivacyEvidenceCustody.build(
        source_sha256=inventory.source_tree_sha256,
        source_provenance_size=128,
        source_provenance_artifact_sha256=hashlib.sha256(
            b"assurance:privacy-provenance-bytes"
        ).hexdigest(),
        source_provenance_evidence_sha256=provenance_sha256,
        effective_policy_size=256,
        effective_policy_artifact_sha256=hashlib.sha256(
            b"assurance:privacy-policy-bytes"
        ).hexdigest(),
        effective_policy_evidence_sha256=hashlib.sha256(b"assurance:privacy-policy").hexdigest(),
        policy_source_provenance_sha256=provenance_sha256,
    )
    bindings = build_scheduler_bindings(
        config=config,
        shard_inventory=inventory,
        qualification=qualification,
        analysis_input_sha256=hashlib.sha256(b"assurance:analysis-input").hexdigest(),
        cost_ledger_baseline=cost_baseline,
        privacy_evidence_custody=privacy_custody,
    )
    manifest = SchedulerCampaignManifest.build(
        bindings=bindings,
        shard_inventory=inventory,
        cost_ledger_baseline=cost_baseline,
        privacy_evidence_custody=privacy_custody,
    )

    def assignment(role: str, scope: SchedulerScope, *, task_key: str) -> SchedulerFixtureModelTask:
        if role.startswith("whole_protocol_review:"):
            index = int(role.rsplit(":", 1)[1])
            model_id = f"specialist-{index}/model-{index}"
        elif (specialist_role := canonical_specialist_role(role)) is not None:
            model_id = config.models.role(specialist_role).primary
        else:
            model_id = config.models.role(role).primary
        return SchedulerFixtureModelTask(
            task_key=task_key,
            role=role,
            requested_model=model_id,
            root_lineage=qualification.model_for(model_id, now=now).root_lineage,
            scope=scope,
        )

    single_shard = SchedulerScope.single_shard(shard.shard_id)
    blind_tasks = [
        assignment("business_logic", single_shard, task_key="blind-business-logic"),
        assignment("configuration", single_shard, task_key="blind-configuration"),
        *[
            assignment(
                f"specialist:{role}",
                single_shard,
                task_key=f"blind-specialist-{role}",
            )
            for role in SPECIALIST_INVESTIGATOR_ROLES
        ],
        *[
            assignment(
                f"whole_protocol_review:{index}",
                SchedulerScope.global_scope(),
                task_key=f"blind-whole-protocol-{index}",
            )
            for index in range(4)
        ],
    ]

    def later_assignment(
        role: str,
        pass_kind: SchedulerPassKind,
        *,
        task_key: str,
        candidate_ids: tuple[str, ...] = (),
    ) -> SchedulerFixtureModelTask:
        base = assignment(role, SchedulerScope.global_scope(), task_key=task_key)
        return SchedulerFixtureModelTask(
            task_key=base.task_key,
            role=base.role,
            requested_model=base.requested_model,
            root_lineage=base.root_lineage,
            scope=base.scope,
            pass_kind=pass_kind,
            candidate_ids=candidate_ids,
        )

    candidate_ids = ("candidate-critical",)
    model_tasks = (
        later_assignment(
            "specialist:invariant_review",
            SchedulerPassKind.CROSS_SHARD_INTEGRATION,
            task_key="integration-invariant-review",
        ),
        later_assignment(
            "specialist:test_generation:exploit_test",
            SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
            task_key="validation-test-generation",
            candidate_ids=candidate_ids,
        ),
        later_assignment(
            "specialist:exploit_reproduction_planner:exploit_test",
            SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
            task_key="validation-reproduction-planner",
            candidate_ids=candidate_ids,
        ),
        later_assignment(
            "specialist:falsifier",
            SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
            task_key="validation-specialist-falsifier",
            candidate_ids=candidate_ids,
        ),
        later_assignment(
            "judge",
            SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT,
            task_key="judgment-evidence-cap",
            candidate_ids=candidate_ids,
        ),
        later_assignment(
            "specialist:report_quality",
            SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT,
            task_key="judgment-report-quality",
            candidate_ids=candidate_ids,
        ),
    )

    def resolve_model_assignment(
        pass_kind: SchedulerPassKind,
        task_key: str,
        role: str,
    ) -> tuple[str, str]:
        del pass_kind
        if role.startswith("candidate_falsifier:"):
            fallback_index = 0 if task_key.endswith(":1") else 1
            model_id = config.models.role("falsifier").fallbacks[fallback_index]
        elif role == "candidate_falsifier":
            fallback_index = 0 if task_key.endswith("-1") else 1
            model_id = config.models.role("falsifier").fallbacks[fallback_index]
        elif role.startswith("whole_protocol_review:"):
            index = int(role.rsplit(":", 1)[1])
            model_id = f"specialist-{index}/model-{index}"
        elif (specialist_role := canonical_specialist_role(role)) is not None:
            model_id = config.models.role(specialist_role).primary
        else:
            model_id = config.models.role(role).primary
        return model_id, qualification.model_for(model_id, now=now).root_lineage

    def bind_usage(
        _task: object,
        _activation: object,
        record: UsageRecord,
    ) -> UsageRecord:
        model = qualification.model_for(record.requested_model, now=now)
        request_limit_fields = {
            "atomic_request_limit_reservations",
            "atomic_request_limit_reservation_sha256s",
            "atomic_request_limit_reservation",
            "atomic_request_limit_reservation_sha256",
        }
        routing = {
            key: value for key, value in record.routing.items() if key not in request_limit_fields
        }
        prepared = record.model_copy(
            update={
                "provider": model.approved_provider_name,
                "configured_provider_endpoints": [model.approved_provider_endpoint],
                "actual_provider_endpoint": model.approved_provider_endpoint,
                "routing": {
                    **routing,
                    "certification_request": True,
                    "selected_provider_endpoint": model.approved_provider_endpoint,
                    "selected_provider_name": model.approved_provider_name,
                },
            }
        )
        bound = _bind_usage_to_qualification(prepared, qualification, now)
        token_plan = request_token_plan_from_usage(bound)
        assert token_plan is not None
        request_limit = AtomicRequestLimitReservationEvidence.build(
            request_id=bound.request_id,
            exact_model_id=bound.requested_model,
            role=bound.role,
            request_token_plan_sha256=token_plan.plan_sha256,
            request_limit_scope=bound.request_id,
            request_limit_count_before=0,
            request_limit_maximum=100,
        )
        return reattest_synthetic_real_usage(
            bound.model_copy(
                update={
                    "routing": {
                        **bound.routing,
                        "atomic_request_limit_reservations": [
                            request_limit.model_dump(mode="json")
                        ],
                        "atomic_request_limit_reservation_sha256s": [request_limit.evidence_sha256],
                        "atomic_request_limit_reservation": request_limit.model_dump(mode="json"),
                        "atomic_request_limit_reservation_sha256": request_limit.evidence_sha256,
                    }
                }
            )
        )

    return build_complete_scheduler_fixture(
        seed="maximum-assurance-runtime",
        manifest=manifest,
        real_usage=True,
        blind_model_tasks=blind_tasks,
        model_tasks=model_tasks,
        model_assignment_resolver=resolve_model_assignment,
        usage_transform=bind_usage,
    )


def _complete_scope_assessment() -> AuditScopeAssessment:
    return AuditScopeAssessment(
        requested=AuditScope.FULL_PROTOCOL,
        achieved=AuditScope.FULL_PROTOCOL,
        gate_required=True,
        complete=True,
        components=[
            ScopeComponentEvidence(
                component=component,
                required=True,
                status=ScopeEvidenceStatus.ANALYZED,
                analyzed_paths=[f"scope/{component.value}.txt"],
                detail="synthetic analyzed scope evidence",
            )
            for component in sorted(ScopeComponent, key=lambda item: item.value)
        ],
        missing_required_components=[],
    )


def _real_formal_run(
    tool: str,
    *,
    proof: bool = False,
    observe_properties: bool = True,
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.REAL,
    isolation_backend: str = "sandbox-exec",
) -> FormalToolRun:
    executable_sha256 = hashlib.sha256(f"{tool}:executable".encode()).hexdigest()
    stdout_sha256 = hashlib.sha256(f"{tool}:stdout".encode()).hexdigest()
    stderr_sha256 = hashlib.sha256(f"{tool}:stderr".encode()).hexdigest()
    result_sha256 = hashlib.sha256(f"{tool}:result".encode()).hexdigest()
    command = [tool, "--bounded", "--offline"]
    property_corpus_hash = "d" * 64
    property_id = "prop-" + ("1" * 24)
    property_hash = "1" * 64
    executed_property_ids = [property_id]
    observed_property_ids = list(executed_property_ids) if observe_properties else []
    evidence = [
        FormalEvidence(
            tool=tool,
            property_id=property_id,
            property_description="synthetic typed execution observation",
            status=FormalToolStatus.SUCCESS,
            result_kind=FormalResultKind.PROOF if proof else FormalResultKind.NONE,
            artifact_paths=[f"private/formal/{tool}/result.json"],
            confidence=1,
        )
    ]
    run = FormalToolRun(
        tool=tool,
        execution_evidence=execution_evidence,
        version="1.0.0",
        executable_sha256=executable_sha256,
        isolation_backend=isolation_backend,
        isolation_attestation_sha256="7" * 64,
        dependencies=(
            [
                FormalDependencyProvenance(
                    name="z3",
                    version="4.15.0",
                    executable_sha256="e" * 64,
                )
            ]
            if tool == "halmos"
            else []
        ),
        status=FormalToolStatus.SUCCESS,
        command=command,
        duration_seconds=1,
        evidence=evidence,
        coverage={
            "indexed_sources": 1,
            "properties": 1,
        },
        property_corpus_hash=property_corpus_hash,
        property_corpus_property_ids=[property_id],
        translated_property_bindings=[
            FormalPropertyBinding(
                generated_property_id="GeneratedProperty",
                corpus_property_id=property_id,
                property_hash=property_hash,
            )
        ],
        campaign_seed=7 if tool in {"echidna", "medusa", "halmos"} else None,
        configured_campaign=FormalCampaignBounds(runs=256, depth=32),
        observed_campaign=(
            FormalCampaignObservation(paths=64)
            if tool == "halmos"
            else (
                FormalCampaignObservation(runs=256, calls=8_192, depth=32)
                if tool in {"echidna", "medusa"}
                else FormalCampaignObservation(iterations=32, depth=32)
            )
        ),
        translated_properties=len(executed_property_ids),
        executed_property_ids=executed_property_ids,
        observed_property_ids=observed_property_ids,
        specification_artifacts=(["private/formal/certora/specification.spec"] if proof else []),
        vacuity_artifacts=(["private/formal/certora/vacuity.json"] if proof else []),
        stdout_path=f"private/formal/{tool}/stdout.txt",
        stderr_path=f"private/formal/{tool}/stderr.txt",
        result_path=f"private/formal/{tool}/result.json",
        process_exit_code=0,
        stdout_sha256=stdout_sha256,
        stderr_sha256=stderr_sha256,
        result_sha256=result_sha256,
        stdout_bytes=100,
        stderr_bytes=1,
        result_bytes=100,
        machine_output_validated=True,
    )
    return run.model_copy(
        update={"execution_observation_sha256": run.expected_execution_observation_sha256()}
    )


def _real_model_usage(now: datetime) -> list[UsageRecord]:
    def specialist_request_role(role: str) -> str:
        suffix = (
            ":exploit_test" if role in {"test_generation", "exploit_reproduction_planner"} else ""
        )
        return f"specialist:{role}{suffix}"

    roles = sorted(
        {
            "threat_model",
            "source_audit",
            "business_logic",
            "configuration",
            "verifier",
            "judge",
            "falsifier",
            *(f"whole_protocol_review:{index}" for index in range(4)),
            *(specialist_request_role(role) for role in ALL_SPECIALIST_ROLES),
        }
    )
    base_models = {
        "threat_model": "alpha/atlas-secure",
        "source_audit": "bravo/borealis-secure",
        "business_logic": "charlie/cirrus-secure",
        "configuration": "delta/denali-secure",
        "verifier": "echo/equinox-secure",
        "judge": "foxtrot/fjord-secure",
        "whole_protocol_review:0": "specialist-0/model-0",
        "whole_protocol_review:1": "specialist-1/model-1",
        "whole_protocol_review:2": "specialist-2/model-2",
        "whole_protocol_review:3": "specialist-3/model-3",
    }
    specialist_models = {
        specialist_request_role(role): f"specialist-{index % 8}/model-{index % 8}"
        for index, role in enumerate(ALL_SPECIALIST_ROLES)
    }
    specialist_models.update(
        {
            role: f"specialist-{index % 8}/model-{index % 8}"
            for index, role in enumerate(ALL_SPECIALIST_ROLES)
        }
    )
    role_models = {**base_models, **specialist_models}
    records = [
        bind_synthetic_usage_identity(
            UsageRecord(
                request_id=f"request-{index:02d}",
                role=role,
                execution_evidence=ExecutionEvidenceKind.REAL,
                requested_model=(model_id := role_models[role]),
                returned_model=model_id,
                actual_model=model_id,
                provider="approved-provider",
                model_family=model_id,
                timestamp=now,
                prompt_tokens=100,
                completion_tokens=100,
                total_tokens=200,
                reported_cost_usd=0.01,
                accounted_cost_usd=0.01,
                routing={
                    "generation_id": f"generation-{index:02d}",
                    "selected_model": model_id,
                    "canonical_model": model_id,
                    "selected_provider_endpoint": "approved-provider",
                    "selected_provider_name": "approved-provider",
                    "router_strategy": "direct",
                    "router_attempt": 1,
                    "router_attempt_count": 1,
                    "router_pipeline": [],
                    "finish_reason": "stop",
                    "schema_sha256": "d" * 64,
                    "router_metadata_sha256": "e" * 64,
                    "provider_policy_sha256": "f" * 64,
                    "provider_fallbacks_allowed": False,
                    "certification_request": True,
                    "endpoint_snapshot_sha256": "1" * 64,
                    "endpoint_pricing_sha256": "2" * 64,
                    "catalog_identity_binding_sha256": canonical_sha256(
                        {
                            "canonical_slug": model_id,
                            "id": model_id,
                        }
                    ),
                    "catalog_snapshot_sha256": "3" * 64,
                    "discovery_provenance_sha256": "4" * 64,
                    "discovery_evidence_sha256": "5" * 64,
                    "validation_status": "valid",
                    "zdr_requested": True,
                    "data_collection": "deny",
                    "repair_used": False,
                    "repair_request": False,
                    "request_started_at": now.isoformat(),
                    "request_ended_at": now.isoformat(),
                    "latency_ms": 0,
                },
                prompt_sha256=hashlib.sha256(f"{role}:prompt".encode()).hexdigest(),
                response_sha256=hashlib.sha256(f"{role}:response".encode()).hexdigest(),
                validated_response_sha256=hashlib.sha256(
                    f"{role}:validated-response".encode()
                ).hexdigest(),
                request_body_sha256=hashlib.sha256(f"{role}:request".encode()).hexdigest(),
                schema_sha256="d" * 64,
                openrouter_generation_id=f"generation-{index:02d}",
                configured_provider_endpoints=["approved-provider"],
                actual_provider_endpoint="approved-provider",
                started_at=now,
                ended_at=now,
                latency_ms=0,
                finish_reason="stop",
                retry_count=0,
                validation_status=ModelRequestValidationStatus.VALID,
                status="success",
                attempts=1,
            )
        )
        for index, role in enumerate(roles)
    ]
    source_bound_records: list[UsageRecord] = []
    for record in records:
        if record.role.startswith("whole_protocol_review:"):
            context_role = "whole_protocol_review"
        elif record.role.startswith("specialist:"):
            context_role = ":".join(record.role.split(":")[:2])
        elif record.role == "falsifier":
            context_role = "verifier"
        else:
            context_role = record.role
        try:
            context_evidence = ContextRequestEvidence.build(
                request_id=record.request_id,
                request_role=record.role,
                context_role=context_role,
                byte_budget=1_000,
                declared_bytes_used=128,
                rendered_bytes=128,
                source_bytes=64,
                configured_maximum_source_tokens_per_request=1_000,
                effective_source_byte_ceiling=64,
                rendered_sha256=hashlib.sha256(
                    f"{record.request_id}:whole-protocol-context".encode()
                ).hexdigest(),
            )
        except ValueError:
            source_bound_records.append(record)
            continue
        source_bound_records.append(
            record.model_copy(
                update={
                    "user_prompt_sha256": context_evidence.rendered_sha256,
                    "routing": {
                        **record.routing,
                        "context_request_evidence": context_evidence.model_dump(mode="json"),
                        "context_request_evidence_sha256": (context_evidence.evidence_sha256),
                    },
                }
            )
        )
    return [
        _with_output_evidence(
            record,
            endpoint_snapshot_sha256=record.routing["endpoint_snapshot_sha256"],
            output_capability_sha256=hashlib.sha256(
                f"output-capability:{record.requested_model}".encode()
            ).hexdigest(),
            mode=StructuredOutputMode.JSON_OBJECT,
        )
        for record in source_bound_records
    ]


def _real_offline_replay(
    *,
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.REAL,
    isolation_backend: str = "sandbox-exec",
    kinds: set[ReplayComponentKind] | None = None,
) -> OfflineReplay:
    component_identities = (
        [
            (ReplayComponentKind.SCANNER, "foundry_fork"),
            (ReplayComponentKind.SCANNER, "slither"),
            (ReplayComponentKind.SAVED_TEST, "inv-economic/DonationInflation"),
        ]
        if kinds is None
        else [
            (kind, f"{kind.value}-evidence") for kind in sorted(kinds, key=lambda item: item.value)
        ]
    )
    component_identities = sorted(
        component_identities,
        key=lambda item: (item[0].value, item[1]),
    )
    applicable_kinds = {kind for kind, _identifier in component_identities}
    components = [
        OfflineReplayComponent(
            kind=kind,
            identifier=identifier,
            status=ReplayComponentStatus.MATCHED,
            executed=True,
            execution_evidence=execution_evidence,
            isolation_backend=isolation_backend,
            isolation_attestation_sha256="7" * 64,
            expected_state="matched",
            observed_state="matched",
            expected_sha256=hashlib.sha256(kind.value.encode()).hexdigest(),
            observed_sha256=hashlib.sha256(kind.value.encode()).hexdigest(),
        )
        for kind, identifier in component_identities
    ]
    payload = {
        "schema_version": "1.0",
        "generated_by": "mmaudit",
        "status": OfflineReplayStatus.REPLAYED,
        "run_id": "synthetic-assurance-run",
        "manifest_sha256": "1" * 64,
        "run_verification_sha256": "2" * 64,
        "model_provider_contacted": False,
        "remote_network_policy": "denied",
        "loopback_policy": "local_only",
        "components": [component.model_dump(mode="json") for component in components],
        "applicable_kinds": [
            kind.value for kind in sorted(applicable_kinds, key=lambda item: item.value)
        ],
        "missing_kinds": [],
    }
    payload["replay_sha256"] = canonical_sha256(payload)
    return OfflineReplay.model_validate(payload)


def _real_foundry_scanner(
    now: datetime,
    config: AuditConfig | None = None,
) -> ScannerRun:
    smart_contracts = config.smart_contracts if config is not None else SmartContractsConfig()
    chain_id = (
        config.reproduction.expected_chain_id
        if config is not None and config.reproduction.expected_chain_id is not None
        else 31_337
    )
    block_number = (
        config.reproduction.pinned_block_number
        if config is not None and config.reproduction.pinned_block_number is not None
        else 42
    )
    records = tuple(
        sorted(
            (
                RepositorySuiteInventoryRecord.sealed(
                    project_root=".",
                    execution_path="test/audit/Portfolio.t.sol",
                    execution_suite_name="PortfolioTest",
                    test_name=test_name,
                    execution_signature=f"{test_name}()",
                    execution_source_sha256="8" * 64,
                    execution_start_line=line,
                    execution_end_line=line,
                    execution_contract_ast_id=100,
                    declaration_path="test/audit/Portfolio.t.sol",
                    declaration_suite_name="PortfolioTest",
                    declaration_signature=f"{test_name}()",
                    declaration_source_sha256="8" * 64,
                    declaration_start_line=line,
                    declaration_end_line=line,
                    declaration_contract_ast_id=100,
                    declaration_function_ast_id=100 + line,
                    build_info_sha256="a" * 64,
                )
                for line, test_name in enumerate(
                    ("testUnit", "testFuzz_Portfolio", "invariant_Portfolio"),
                    start=1,
                )
            ),
            key=lambda item: item.canonical_key,
        )
    )
    artifact = RepositorySuiteInventoryArtifact(
        name="portfolio-build-info.json",
        sha256="a" * 64,
        normalized_sha256="a" * 64,
        bytes=1_000,
    )
    normalized_inventory_sha256 = canonical_sha256(
        sorted(record.record_sha256 for record in records)
    )
    project_inventory = RepositorySuiteProjectInventoryEvidence.sealed(
        project_root=".",
        command_sha256="b" * 64,
        stdout_sha256="c" * 64,
        stdout_bytes=100,
        stderr_sha256="d" * 64,
        stderr_bytes=0,
        build_info_artifacts=(artifact,),
        build_info_bundle_sha256=canonical_sha256([artifact.model_dump(mode="json")]),
        normalized_build_info_bundle_sha256=canonical_sha256([artifact.normalized_sha256]),
        parser_inventory_sha256="f" * 64,
        records=records,
        normalized_inventory_sha256=normalized_inventory_sha256,
    )
    inventory_common = {
        "framework": RepositorySuiteFramework.FOUNDRY,
        "repository_sha256": "9" * 64,
        "configuration_sha256": smart_contracts.repository_suite.stable_hash(),
        "tool_version": "forge 1.3.2",
        "tool_sha256": "5" * 64,
        "compiler_version": "solc 0.8.30",
        "compiler_sha256": smart_contracts.solc_sha256 or ("6" * 64),
        "isolation_backend": "sandbox-exec",
        "isolation_attestation_sha256": "7" * 64,
        "execution_evidence": ExecutionEvidenceKind.REAL,
        "repository_code_execution": RepositoryCodeExecutionState.ISOLATED,
        "projects": (project_inventory,),
        "project_bundle_sha256": canonical_sha256([project_inventory.project_inventory_sha256]),
        "normalized_inventory_sha256": normalized_inventory_sha256,
        "inventory_record_count": len(records),
        "safety_claim": False,
    }
    inventory = RepositorySuiteInventoryEvidence.sealed(
        phase=RepositorySuiteInventoryPhase.PRE_EXECUTION,
        **inventory_common,
    )
    post_inventory = RepositorySuiteInventoryEvidence.sealed(
        phase=RepositorySuiteInventoryPhase.POST_EXECUTION,
        **inventory_common,
    )
    descriptors = tuple(
        RepositorySuiteTestDescriptor.sealed(
            framework=RepositorySuiteFramework.FOUNDRY,
            project_root=record.project_root,
            path=record.execution_path,
            suite_name=record.execution_suite_name,
            test_name=record.test_name,
            source_sha256=record.execution_source_sha256,
            start_line=record.execution_start_line,
            end_line=record.execution_end_line,
            inventory_sha256=inventory.normalized_inventory_sha256,
            inventory_record_sha256=record.record_sha256,
            execution_contract_ast_id=record.execution_contract_ast_id,
            declaration_path=record.declaration_path,
            declaration_suite_name=record.declaration_suite_name,
            declaration_signature=record.declaration_signature,
            declaration_source_sha256=record.declaration_source_sha256,
            declaration_start_line=record.declaration_start_line,
            declaration_end_line=record.declaration_end_line,
            declaration_contract_ast_id=record.declaration_contract_ast_id,
            declaration_function_ast_id=record.declaration_function_ast_id,
        )
        for record in records
    )
    selection = RepositorySuiteSelection.sealed(
        profile="legacy_audit",
        repository_sha256="9" * 64,
        repository_exclusion_path=".mmaudit",
        configuration_sha256=smart_contracts.repository_suite.stable_hash(),
        candidate_file_count=1,
        candidate_test_count=3,
        selected_file_count=1,
        selected_test_count=3,
        omitted_file_count=0,
        omitted_test_count=0,
        limit_reached=False,
        inventory_kind=RepositorySuiteInventoryKind.ISOLATED_FOUNDRY_BUILD_INFO,
        inventory_sha256=inventory.normalized_inventory_sha256,
        tests=descriptors,
        safety_claim=False,
    )
    scanner_timeout = config.execution.scanner_timeout_seconds if config is not None else 2
    total_timeout = min(
        scanner_timeout,
        smart_contracts.max_fork_probe_seconds,
        smart_contracts.repository_suite.total_timeout_seconds,
    )
    execution_policy = RepositorySuiteExecutionPolicy.sealed(
        selection_sha256=selection.selection_sha256,
        selection_configuration_sha256=selection.configuration_sha256,
        chain_id=chain_id,
        block_number=block_number,
        block_hash="0x" + ("a" * 64),
        tool_version="forge 1.3.2",
        tool_sha256="5" * 64,
        compiler_version="solc 0.8.30",
        compiler_sha256=smart_contracts.solc_sha256 or ("6" * 64),
        isolation_backend="sandbox-exec",
        isolation_attestation_sha256="7" * 64,
        fuzz_seed=smart_contracts.repository_suite.fuzz_seed,
        fuzz_runs=smart_contracts.foundry_fuzz_runs,
        invariant_runs=smart_contracts.foundry_invariant_runs,
        per_test_timeout_seconds=min(
            total_timeout,
            smart_contracts.repository_suite.per_test_timeout_seconds,
        ),
        total_timeout_seconds=total_timeout,
        max_output_bytes_per_test=(smart_contracts.repository_suite.max_output_bytes_per_test),
        max_total_output_bytes=smart_contracts.repository_suite.max_total_output_bytes,
    )
    executions = [
        RepositoryTestExecution.sealed(
            selection_sha256=selection.selection_sha256,
            descriptor_sha256=descriptor.descriptor_sha256,
            inventory_sha256=inventory.inventory_sha256,
            post_inventory_sha256=post_inventory.inventory_sha256,
            inventory_record_sha256=descriptor.inventory_record_sha256,
            framework=descriptor.framework,
            project_root=descriptor.project_root,
            path=descriptor.path,
            suite_name=descriptor.suite_name,
            test_name=descriptor.test_name,
            chain_id=chain_id,
            block_number=block_number,
            block_hash="0x" + ("a" * 64),
            fuzz_seed=smart_contracts.repository_suite.fuzz_seed,
            test_kind=(
                RepositoryTestKind.FUZZ
                if descriptor.test_name.startswith("testFuzz")
                else (
                    RepositoryTestKind.INVARIANT
                    if descriptor.test_name.startswith("invariant")
                    else RepositoryTestKind.UNIT
                )
            ),
            fuzz_cases=256 if descriptor.test_name.startswith("testFuzz") else 0,
            invariant_runs=256 if descriptor.test_name.startswith("invariant") else 0,
            invariant_calls=8192 if descriptor.test_name.startswith("invariant") else 0,
            status=RepositoryTestExecutionStatus.PASSED,
            terminal_detail=None,
            duration_seconds=0.1,
            command_sha256=hashlib.sha256(f"command:{descriptor.test_name}".encode()).hexdigest(),
            output_sha256=hashlib.sha256(f"output:{descriptor.test_name}".encode()).hexdigest(),
            output_bytes=100,
            machine_result_sha256=hashlib.sha256(
                f"machine-result:{descriptor.test_name}".encode()
            ).hexdigest(),
            process_exit_code=0,
            machine_output_validated=True,
            execution_evidence=ExecutionEvidenceKind.REAL,
            repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
            isolation_backend="sandbox-exec",
            isolation_attestation_sha256="7" * 64,
            compiler_version="solc 0.8.30",
            compiler_sha256=smart_contracts.solc_sha256 or ("6" * 64),
            execution_policy_sha256=execution_policy.policy_sha256,
            safety_claim=False,
        )
        for descriptor in descriptors
    ]
    run = ScannerRun(
        scanner="foundry_fork",
        status=ScannerStatus.SUCCESS,
        execution_evidence=ExecutionEvidenceKind.REAL,
        version="forge 1.3.2",
        executable_sha256="5" * 64,
        command=["forge", "test", "--offline", "--json"],
        started_at=now,
        finished_at=now,
        duration_seconds=1,
        raw_output_path="private/scanner-output/foundry-fork.json",
        raw_output_sha256="6" * 64,
        raw_output_bytes=1_000,
        process_exit_code=0,
        isolation_backend="sandbox-exec",
        isolation_attestation_sha256="7" * 64,
        machine_output_validated=True,
        foundry_summary=FoundryTestExecutionSummary(
            unit_tests=1,
            fuzz_tests=1,
            invariant_tests=1,
            passed_tests=3,
            failed_tests=0,
            skipped_tests=0,
            fuzz_cases=256,
            invariant_runs=256,
            invariant_calls=8_192,
        ),
        repository_suite_selection=selection,
        repository_suite_inventory=inventory,
        repository_suite_post_inventory=post_inventory,
        repository_suite_execution_policy=execution_policy,
        repository_test_executions=executions,
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
    )
    return ScannerRun.model_validate(
        {
            **run.model_dump(mode="json"),
            "execution_observation_sha256": run.expected_execution_observation_sha256(),
        }
    )


def _static_source_foundry_scanner(run: ScannerRun) -> ScannerRun:
    selection = run.repository_suite_selection
    execution_policy = run.repository_suite_execution_policy
    assert selection is not None
    assert execution_policy is not None
    descriptors = tuple(
        RepositorySuiteTestDescriptor.sealed(
            framework=descriptor.framework,
            project_root=descriptor.project_root,
            path=descriptor.path,
            suite_name=descriptor.suite_name,
            test_name=descriptor.test_name,
            source_sha256=descriptor.source_sha256,
            start_line=descriptor.start_line,
            end_line=descriptor.end_line,
        )
        for descriptor in selection.tests
    )
    static_selection = RepositorySuiteSelection.sealed(
        profile=selection.profile,
        repository_sha256=selection.repository_sha256,
        repository_exclusion_path=selection.repository_exclusion_path,
        configuration_sha256=selection.configuration_sha256,
        candidate_file_count=selection.candidate_file_count,
        candidate_test_count=selection.candidate_test_count,
        selected_file_count=selection.selected_file_count,
        selected_test_count=selection.selected_test_count,
        omitted_file_count=selection.omitted_file_count,
        omitted_test_count=selection.omitted_test_count,
        limit_reached=selection.limit_reached,
        tests=descriptors,
        safety_claim=False,
    )
    static_policy = RepositorySuiteExecutionPolicy.sealed(
        **execution_policy.model_dump(
            mode="python",
            exclude={
                "policy_sha256",
                "selection_sha256",
                "selection_configuration_sha256",
            },
        ),
        selection_sha256=static_selection.selection_sha256,
        selection_configuration_sha256=static_selection.configuration_sha256,
    )
    prior_by_key = {
        execution.canonical_key: execution for execution in run.repository_test_executions
    }
    executions = [
        RepositoryTestExecution.sealed(
            **prior_by_key[descriptor.canonical_key].model_dump(
                mode="python",
                exclude={
                    "execution_sha256",
                    "selection_sha256",
                    "descriptor_sha256",
                    "inventory_sha256",
                    "post_inventory_sha256",
                    "inventory_record_sha256",
                    "execution_policy_sha256",
                },
            ),
            selection_sha256=static_selection.selection_sha256,
            descriptor_sha256=descriptor.descriptor_sha256,
            execution_policy_sha256=static_policy.policy_sha256,
        )
        for descriptor in descriptors
    ]
    candidate = run.model_copy(
        update={
            "repository_suite_selection": static_selection,
            "repository_suite_inventory": None,
            "repository_suite_post_inventory": None,
            "repository_suite_execution_policy": static_policy,
            "repository_test_executions": executions,
            "execution_observation_sha256": None,
        }
    )
    return ScannerRun.model_validate(
        {
            **candidate.model_dump(mode="json"),
            "execution_observation_sha256": candidate.expected_execution_observation_sha256(),
        }
    )


def _foundry_scanner_with_post_build_info_drift(run: ScannerRun) -> ScannerRun:
    post_inventory = run.repository_suite_post_inventory
    assert post_inventory is not None
    project = post_inventory.projects[0]
    drifted_artifact = project.build_info_artifacts[0].model_copy(
        update={
            "name": "extra-build-info.json",
            "sha256": "e" * 64,
            "normalized_sha256": "e" * 64,
        }
    )
    build_info_artifacts = tuple(
        sorted(
            (*project.build_info_artifacts, drifted_artifact),
            key=lambda artifact: (artifact.name, artifact.sha256, artifact.bytes),
        )
    )
    drifted_project = RepositorySuiteProjectInventoryEvidence.sealed(
        **project.model_dump(
            mode="python",
            exclude={
                "project_inventory_sha256",
                "build_info_artifacts",
                "build_info_bundle_sha256",
                "normalized_build_info_bundle_sha256",
                "records",
            },
        ),
        build_info_artifacts=build_info_artifacts,
        build_info_bundle_sha256=canonical_sha256(
            [artifact.model_dump(mode="json") for artifact in build_info_artifacts]
        ),
        normalized_build_info_bundle_sha256=canonical_sha256(
            sorted(artifact.normalized_sha256 for artifact in build_info_artifacts)
        ),
        records=project.records,
    )
    drifted_post = RepositorySuiteInventoryEvidence.sealed(
        **post_inventory.model_dump(
            mode="python",
            exclude={
                "inventory_sha256",
                "projects",
                "project_bundle_sha256",
            },
        ),
        projects=(drifted_project,),
        project_bundle_sha256=canonical_sha256([drifted_project.project_inventory_sha256]),
    )
    executions = [
        RepositoryTestExecution.sealed(
            **execution.model_dump(
                mode="python",
                exclude={"execution_sha256", "post_inventory_sha256"},
            ),
            post_inventory_sha256=drifted_post.normalized_inventory_sha256,
        )
        for execution in run.repository_test_executions
    ]
    candidate = run.model_copy(
        update={
            "repository_suite_post_inventory": drifted_post,
            "repository_test_executions": executions,
            "execution_observation_sha256": None,
        }
    )
    return candidate.model_copy(
        update={"execution_observation_sha256": candidate.expected_execution_observation_sha256()}
    )


def _reseal_foundry_inventory(
    inventory: RepositorySuiteInventoryEvidence,
    **updates: object,
) -> RepositorySuiteInventoryEvidence:
    payload = inventory.model_dump(mode="python", exclude={"inventory_sha256"})
    payload["projects"] = inventory.projects
    payload.update(updates)
    return RepositorySuiteInventoryEvidence.sealed(**payload)


def _reseal_scanner_observation(run: ScannerRun, **updates: object) -> ScannerRun:
    candidate = run.model_copy(
        update={
            **updates,
            "execution_observation_sha256": None,
        }
    )
    return candidate.model_copy(
        update={"execution_observation_sha256": candidate.expected_execution_observation_sha256()}
    )


def _real_slither_scanner(now: datetime) -> ScannerRun:
    run = ScannerRun(
        scanner="slither",
        status=ScannerStatus.SUCCESS,
        execution_evidence=ExecutionEvidenceKind.REAL,
        version="slither 0.11.5",
        executable_sha256="3" * 64,
        command=["slither", ".", "--json", "-"],
        started_at=now,
        finished_at=now,
        duration_seconds=0,
        raw_output_path="private/scanner-output/slither/slither.json",
        raw_output_sha256="4" * 64,
        raw_output_bytes=100,
        process_exit_code=0,
        isolation_backend="sandbox-exec",
        isolation_attestation_sha256="7" * 64,
        machine_output_validated=True,
    )
    return ScannerRun.model_validate(
        {
            **run.model_dump(mode="json"),
            "execution_observation_sha256": run.expected_execution_observation_sha256(),
        }
    )


def _complete_runtime(config: AuditConfig | None = None) -> AssuranceRuntime:
    now = datetime.now(UTC).replace(microsecond=0)
    qualification = _synthetic_production_qualification(config, now) if config is not None else None
    scheduler_fixture = (
        _complete_assurance_scheduler_fixture(config, qualification, now)
        if config is not None and qualification is not None
        else None
    )
    model_usage = (
        list(scheduler_fixture.usage_records)
        if scheduler_fixture is not None
        else _real_model_usage(now)
    )
    model_review_coverage, model_surface_review_artifacts = _complete_model_coverage(
        model_usage,
        scheduler_fixture,
    )
    project = SolidityProjectMetadata(
        project_type=SolidityProjectType.FOUNDRY,
        project_root=".",
        source_directories=["src"],
    )
    invariant = InvariantSpec(
        id="inv-economic",
        title="Economic invariant",
        category=InvariantCategory.ECONOMIC,
        description="Synthetic invariant used to satisfy contract gate coverage.",
        template=InvariantTemplate.DONATION_INFLATION_RESISTANCE,
        locations=[
            Location(
                path="src/Vault.sol",
                start_line=1,
                end_line=5,
                content_hash="a" * 64,
            )
        ],
        provenance=SolidityProvenance.HEURISTIC,
        confidence=0.9,
        template_available=True,
        executable=True,
        evidence_hash="b" * 64,
    )
    runtime = AssuranceRuntime(
        scheduler_artifact=(
            scheduler_fixture.artifact
            if scheduler_fixture is not None
            else build_complete_scheduler_artifact()
        ),
        expected_scheduler_bindings=(
            scheduler_fixture.manifest.bindings if scheduler_fixture is not None else None
        ),
        expected_scheduler_analysis_input_sha256=(
            scheduler_fixture.manifest.bindings.analysis_input_sha256
            if scheduler_fixture is not None
            else None
        ),
        expected_scheduler_shard_inventory=(
            scheduler_fixture.manifest.shard_inventory if scheduler_fixture is not None else None
        ),
        expected_scheduler_cost_ledger_baseline=(
            scheduler_fixture.manifest.cost_ledger_baseline
            if scheduler_fixture is not None
            else None
        ),
        repository_execution_sha256="9" * 64,
        projects=[project],
        compilations=[
            SolidityCompilationResult(
                status=CompilationStatus.SUCCESS,
                framework=SolidityProjectType.FOUNDRY,
                project_root=".",
                contracts_compiled=["Vault"],
                ast_available=True,
            )
        ],
        index=SoliditySymbolIndex(
            projects=[project],
            entities=[
                SolidityEntity(
                    id="contract:Vault",
                    kind=SolidityEntityKind.CONTRACT,
                    name="Vault",
                    path="src/Vault.sol",
                    start_line=1,
                    end_line=5,
                    byte_start=0,
                    byte_end=1,
                    source_hash="a" * 64,
                    provenance=SolidityProvenance.COMPILER,
                    confidence=1,
                    transformation="synthetic_test_entity",
                )
            ],
            ast_sources=["src/Vault.sol"],
        ),
        graphs=SolidityGraphSet(edges=[], analyzed_graphs=list(FULL_SEMANTIC_GRAPHS)),
        scanners=[_real_slither_scanner(now), _real_foundry_scanner(now, config)],
        invariants=InvariantSuite(
            invariants=[invariant],
            templates_available_count=1,
            executable_count=1,
        ),
        expected_invariant_harnesses={
            (
                invariant.id,
                "DonationInflation",
                "9" * 64,
            )
        },
        invariant_executions=[
            InvariantExecutionResult(
                invariant_id=invariant.id,
                harness_name="DonationInflation",
                harness_spec_sha256="9" * 64,
                status=InvariantExecutionStatus.PASSED,
                execution_evidence=ExecutionEvidenceKind.REAL,
                executable_sha256="5" * 64,
                source_sha256="8" * 64,
                compiler_version="solc 0.8.30",
                compiler_sha256="6" * 64,
                command=["forge", "test", "--offline", "--match-test", "invariant_"],
                runs=256,
                depth=32,
                seed=7,
                economic_template=EconomicSimulationKind.ERC4626_DONATION,
                attempts=2,
                successful_attempts=2,
                replay_confirmed=True,
                attempt_evidence=[
                    InvariantExecutionAttemptEvidence(
                        attempt=attempt,
                        status=InvariantExecutionStatus.PASSED,
                        source_sha256="8" * 64,
                        fresh_workspace=True,
                        stdout_sha256=hashlib.sha256(
                            f"invariant:{attempt}:stdout".encode()
                        ).hexdigest(),
                        stderr_sha256=hashlib.sha256(
                            f"invariant:{attempt}:stderr".encode()
                        ).hexdigest(),
                        stdout_path=f"private/invariants/attempt-{attempt}/stdout.txt",
                        stderr_path=f"private/invariants/attempt-{attempt}/stderr.txt",
                        process_exit_code=0,
                        machine_output_validated=True,
                        campaign_runs=256,
                        campaign_calls=8_192,
                    )
                    for attempt in (1, 2)
                ],
                campaign_coverage=InvariantCampaignCoverage(
                    declared_action_functions=["deposit"],
                    observed_action_functions=["deposit"],
                    declared_state_properties=["conservation"],
                    observed_state_properties=["conservation"],
                    sequence_depth_bound=32,
                    observed_sequence_lengths=[1],
                    attempts_consistent=True,
                    observed_campaign_runs=256,
                    observed_campaign_calls=8_192,
                ),
                stdout_path="private/invariants/stdout.txt",
                stderr_path="private/invariants/stderr.txt",
                isolation_backend="sandbox-exec",
                isolation_attestation_sha256="7" * 64,
            )
        ],
        economic_simulations=[
            EconomicSimulationPlan(
                kind=EconomicSimulationKind.ERC4626_DONATION,
                applicable=True,
                rationale="synthetic",
                invariant_ids=[invariant.id],
                typed_harness_available=True,
                execution_required=True,
            )
        ],
        formal_runs=[
            _real_formal_run("echidna"),
            _real_formal_run("medusa"),
            _real_formal_run("halmos"),
            _real_formal_run("certora", proof=True),
        ],
        property_corpus_sha256="d" * 64,
        property_corpus_property_ids={"prop-" + ("1" * 24)},
        property_corpus_property_hashes={"prop-" + ("1" * 24): "1" * 64},
        model_roles_completed={
            "threat_model",
            "source_audit",
            "business_logic",
            "configuration",
        },
        specialist_roles_completed=set(SPECIALIST_INVESTIGATOR_ROLES),
        auxiliary_roles_completed={
            "invariant_review",
            "test_generation",
            "exploit_reproduction_planner",
            "falsifier",
            "report_quality",
        },
        specialist_execution_records=_complete_specialist_execution_records(
            model_usage,
            tuple(
                output.specialist_accepted_outcome
                for output in scheduler_fixture.outputs
                if output.specialist_accepted_outcome is not None
            )
            if scheduler_fixture is not None
            else (),
        ),
        verifier_completed=True,
        falsifier_completed=True,
        judge_completed=True,
        coverage=SolidityCoverage(projects_discovered=1),
        model_review_coverage=model_review_coverage,
        model_surface_review_artifacts=model_surface_review_artifacts,
        model_usage=model_usage,
        production_qualification=qualification,
        provider_session=_issue_provider_session_provenance(
            execution_evidence=ExecutionEvidenceKind.REAL,
            pipeline_owned=True,
            trusted_concrete_client=True,
            usage_evidence_consistent=True,
        ),
        offline_replay=_real_offline_replay(),
        replay_run_id="synthetic-assurance-run",
        replay_manifest_sha256="1" * 64,
        replay_verification_sha256="2" * 64,
        benchmark_verification=_current_benchmark_verification(),
        benchmark_repository_git_commit="b" * 40,
        scope_assessment=_complete_scope_assessment(),
        isolation_available=True,
        artifacts={
            "solidity-projects.json",
            "solidity-compilation.json",
            "solidity-index.json",
            "solidity-graphs.json",
            "scanner-results.json",
            "solidity-invariants.json",
            "invariant-review.json",
            "invariant-execution-results.json",
            "economic-simulation-plan.json",
            "reproduction-results.json",
            "solidity-coverage.json",
            "formal-results.json",
            "cross-examination.json",
            "specialist-execution.json",
            "model-review-coverage.json",
            "offline-replay.json",
            "benchmark-certificate-verification.json",
            "scope-assessment.json",
            "scheduler-state.json",
            "maximum_assurance_traceability.json",
        },
        traceability=_implemented_traceability(),
    )
    invariant_result = runtime.invariant_executions[0]
    runtime.invariant_executions[0] = InvariantExecutionResult.model_validate(
        {
            **invariant_result.model_dump(mode="json"),
            "execution_observation_sha256": (
                invariant_result.expected_execution_observation_sha256()
            ),
        }
    )
    if qualification is not None:
        candidate_role_prefix = candidate_falsifier_role("candidate-critical", 1).rsplit(":", 1)[0]
        runtime = replace(
            runtime,
            artifacts={*runtime.artifacts, "model-qualification-runtime.json"},
            eligible_high_critical_ids={"candidate-critical"},
            documented_infeasible_ids={"candidate-critical"},
            candidate_falsifier_request_ids={
                "candidate-critical": {
                    record.request_id
                    for record in runtime.model_usage
                    if record.role.startswith(candidate_role_prefix + ":")
                }
            },
        )
    return runtime


def _implemented_traceability() -> MaximumAssuranceTraceability:
    return MaximumAssuranceTraceability(
        last_verified_commit="synthetic-test",
        requirements=[
            TraceabilityRequirement(
                requirement_id="MA-SYNTHETIC-READY",
                description="Synthetic fully implemented assurance dependency.",
                implementation_status=ImplementationStatus.IMPLEMENTED,
                implementation_paths=["src/mmaudit/orchestration/assurance.py"],
                unit_tests=["tests/unit/test_assurance.py"],
                runtime_artifacts=["maximum_assurance_traceability.json"],
                required_for_complete=True,
                last_verified_commit="synthetic-test",
            )
        ],
    )


def _current_benchmark_verification(
    *,
    profile: AuditProfile = AuditProfile.MAXIMUM_ASSURANCE,
) -> BenchmarkCertificateVerification:
    payload = {
        "schema_version": "1.0",
        "certificate_sha256": "a" * 64,
        "status": CertificateVerificationStatus.CURRENT,
        "observed_repository_git_commit": "b" * 40,
        "observed_bindings_sha256": "c" * 64,
        "mismatches": [],
        "origin": CertificateVerificationOrigin.FILE_BACKED,
        "file_backed_evidence": FileBackedBenchmarkVerificationEvidence(
            certificate_loaded=True,
            certificate_file_sha256="d" * 64,
            benchmark_report_loaded=True,
            benchmark_report_file_sha256="e" * 64,
            benchmark_name="Synthetic maximum-assurance benchmark",
            benchmark_profile=profile,
            benchmark_report_status="passed",
            benchmark_report_gate_count=1,
            benchmark_reports_expected=1,
            benchmark_reports_loaded=1,
        ).model_dump(mode="json"),
    }
    payload["verification_sha256"] = canonical_sha256(payload)
    return BenchmarkCertificateVerification.model_validate(payload)


def _in_memory_benchmark_verification() -> BenchmarkCertificateVerification:
    payload = {
        "schema_version": "1.0",
        "certificate_sha256": "a" * 64,
        "status": CertificateVerificationStatus.CURRENT,
        "observed_repository_git_commit": "b" * 40,
        "observed_bindings_sha256": "c" * 64,
        "mismatches": [],
    }
    payload["verification_sha256"] = canonical_sha256(payload)
    return BenchmarkCertificateVerification.model_validate(payload)


def _verified_reproduction_integrity() -> ReproductionIntegrityAssessment:
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "status": ReproductionIntegrityStatus.VERIFIED,
        "repository_sha256": "a" * 64,
        "targets": [],
        "reachability": [],
        "settlement": ReproductionSettlementEvidence(
            status=ReproductionSettlementStatus.ASSERTIONS_SATISFIED,
            assertions_sha256="b" * 64,
            assertion_count=1,
            verified_attempts=1,
        ).model_dump(mode="json"),
        "minimization": ReproductionMinimizationEvidence(
            original_step_ids=["SyntheticStep"],
            retained_step_ids=["SyntheticStep"],
            strategy="single_step_trivial",
            proven_minimal=True,
        ).model_dump(mode="json"),
        "checks": [
            ReproductionIntegrityCheck(
                check=check,
                passed=True,
                detail="synthetic integrity evidence",
                evidence_sha256=canonical_sha256({"check": check.value}),
            ).model_dump(mode="json")
            for check in ReproductionIntegrityCheckKind
        ],
    }
    payload["integrity_sha256"] = canonical_sha256(payload)
    return ReproductionIntegrityAssessment.model_validate(payload)


def test_maximum_assurance_rejects_missing_model_families(config_factory) -> None:
    repeated_specialists = {
        role: {
            "primary": "alpha/atlas-secure",
            "fallbacks": [],
            "quality_tier": "high",
            "capabilities": ["structured_json", "security_reasoning", "solidity"],
        }
        for role in ALL_SPECIALIST_ROLES
    }
    config = config_factory(
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        models={"specialists": repeated_specialists},
    ).effective()
    errors = validate_model_independence(config)
    assert any("independent analysis model families" in error for error in errors)
    assert any("unique high-quality model slots" in error for error in errors)


def test_maximum_assurance_complete_requires_all_runtime_clauses(config_factory) -> None:
    config = _maximum_config(config_factory)
    assessment = MaximumAssuranceContract(config).evaluate(_complete_runtime(config))
    assert assessment.status is MaximumAssuranceStatus.COMPLETE, [
        (requirement.engine, requirement.detail)
        for requirement in assessment.requirements
        if not requirement.passed
    ]
    assert not assessment.downgraded
    assert all(
        requirement.passed for requirement in assessment.requirements if requirement.required
    )
    certified_ensemble = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "certified_model_ensemble"
    )
    assert "candidate falsifier lineages=minimum=2/2 across 1 candidate(s)" in (
        certified_ensemble.detail
    )


def test_maximum_assurance_rejects_missing_scheduler_artifact(config_factory) -> None:
    config = _maximum_config(config_factory)
    assessment = MaximumAssuranceContract(config).evaluate(
        replace(_complete_runtime(config), scheduler_artifact=None)
    )

    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )
    assert not scheduler.passed
    assert scheduler.state is AnalysisState.NOT_ANALYZED
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


@pytest.mark.parametrize(
    ("field", "detail"),
    [
        ("expected_scheduler_bindings", "trusted runtime scheduler bindings were not supplied"),
        (
            "expected_scheduler_analysis_input_sha256",
            "trusted runtime scheduler analysis-input binding was not supplied",
        ),
        (
            "expected_scheduler_shard_inventory",
            "trusted runtime scheduler shard inventory was not supplied",
        ),
        (
            "expected_scheduler_cost_ledger_baseline",
            "trusted runtime scheduler cost-ledger baseline was not supplied",
        ),
    ],
)
def test_maximum_assurance_rejects_missing_trusted_scheduler_inputs(
    config_factory,
    field: str,
    detail: str,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    assessment = MaximumAssuranceContract(config).evaluate(replace(runtime, **{field: None}))
    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )

    assert not scheduler.passed
    assert detail in scheduler.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_maximum_assurance_rejects_wrong_scheduler_binding(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    binding = runtime.expected_scheduler_bindings
    assert binding is not None
    wrong = SchedulerBindings.build(
        source_sha256=binding.source_sha256,
        analysis_input_sha256=binding.analysis_input_sha256,
        effective_config_sha256=binding.effective_config_sha256,
        shard_inventory_sha256=binding.shard_inventory_sha256,
        model_selection_sha256=binding.model_selection_sha256,
        qualification_sha256=binding.qualification_sha256,
        prompt_set_sha256=binding.prompt_set_sha256,
        schema_set_sha256=binding.schema_set_sha256,
        tool_policy_sha256=hashlib.sha256(b"wrong scheduler tool policy").hexdigest(),
        cost_ledger_baseline_sha256=binding.cost_ledger_baseline_sha256,
        privacy_evidence_custody_sha256=binding.privacy_evidence_custody_sha256,
    )
    assessment = MaximumAssuranceContract(config).evaluate(
        replace(runtime, expected_scheduler_bindings=wrong)
    )
    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )

    assert not scheduler.passed
    assert "artifact bindings differ from trusted runtime bindings" in scheduler.detail
    assert "bindings differ from current configuration" in scheduler.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_maximum_assurance_rejects_wrong_scheduler_analysis_input_binding(
    config_factory,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    assert runtime.expected_scheduler_analysis_input_sha256 is not None
    assessment = MaximumAssuranceContract(config).evaluate(
        replace(runtime, expected_scheduler_analysis_input_sha256="f" * 64)
    )
    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )

    assert not scheduler.passed
    assert (
        "bindings differ from the trusted pre-scheduler analysis-input digest" in scheduler.detail
    )
    assert "bindings differ from current configuration" in scheduler.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_maximum_assurance_rejects_wrong_scheduler_cost_ledger_baseline(
    config_factory,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    baseline = runtime.expected_scheduler_cost_ledger_baseline
    assert baseline is not None
    wrong = SchedulerCostLedgerBaseline.build(
        cap_usd_exact=baseline.cap_usd_exact,
        spent_usd_exact=baseline.spent_usd_exact,
        active_reserved_usd_exact=baseline.active_reserved_usd_exact,
        entries=baseline.entries,
        ledger_identity_sha256=baseline.ledger_identity_sha256,
        ledger_snapshot_sha256=hashlib.sha256(b"wrong scheduler ledger snapshot").hexdigest(),
    )
    assessment = MaximumAssuranceContract(config).evaluate(
        replace(runtime, expected_scheduler_cost_ledger_baseline=wrong)
    )
    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )

    assert not scheduler.passed
    assert "cost-ledger baseline differs from trusted runtime baseline" in scheduler.detail
    assert "bindings differ from current configuration" in scheduler.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_maximum_assurance_rejects_wrong_scheduler_shard_inventory(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    wrong_inventory = build_complete_scheduler_artifact(
        seed="wrong-assurance-inventory"
    ).summary.manifest.shard_inventory
    assert wrong_inventory != runtime.expected_scheduler_shard_inventory
    assessment = MaximumAssuranceContract(config).evaluate(
        replace(runtime, expected_scheduler_shard_inventory=wrong_inventory)
    )
    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )

    assert not scheduler.passed
    assert "differs from trusted runtime inventory" in scheduler.detail
    assert "lacks exact global whole-protocol source delivery" in scheduler.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_maximum_assurance_rejects_extra_unscheduled_provider_usage(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    original = runtime.model_usage[0]
    extra = original.model_copy(update={"request_id": "unscheduled-provider-request"})
    assessment = MaximumAssuranceContract(config).evaluate(
        replace(runtime, model_usage=[*runtime.model_usage, extra])
    )
    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )

    assert not scheduler.passed
    assert "differs from the scheduler request inventory" in scheduler.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_maximum_assurance_rejects_mock_scheduler_usage(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    original = runtime.model_usage[0]
    mocked = original.model_copy(update={"execution_evidence": ExecutionEvidenceKind.MOCK})
    assessment = MaximumAssuranceContract(config).evaluate(
        replace(
            runtime,
            model_usage=[
                mocked if record.request_id == original.request_id else record
                for record in runtime.model_usage
            ],
        )
    )
    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )

    assert not scheduler.passed
    assert "lacks real creditable usage" in scheduler.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_maximum_assurance_rejects_unqualified_real_scheduler_usage(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    original = runtime.model_usage[0]
    routing = {
        key: value for key, value in original.routing.items() if not key.startswith("qualified_")
    }
    unqualified = reattest_synthetic_real_usage(original.model_copy(update={"routing": routing}))
    assert is_creditable_usage_record(unqualified, require_real=True)
    assessment = MaximumAssuranceContract(config).evaluate(
        replace(
            runtime,
            model_usage=[
                unqualified if record.request_id == original.request_id else record
                for record in runtime.model_usage
            ],
        )
    )
    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )

    assert not scheduler.passed
    assert "lacks current qualified certification-grade" in scheduler.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_maximum_assurance_rejects_scheduler_context_hash_mismatch(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    original = next(record for record in runtime.model_usage if record.role == "threat_model")
    context = ContextRequestEvidence.model_validate(original.routing["context_request_evidence"])
    changed_context = ContextRequestEvidence.build(
        request_id=context.request_id,
        request_role=context.request_role,
        context_role=context.context_role,
        byte_budget=context.byte_budget,
        declared_bytes_used=context.declared_bytes_used,
        rendered_bytes=context.rendered_bytes,
        source_bytes=context.source_bytes,
        configured_maximum_source_tokens_per_request=(
            context.configured_maximum_source_tokens_per_request
        ),
        effective_source_byte_ceiling=context.effective_source_byte_ceiling,
        rendered_sha256=hashlib.sha256(b"different retained scheduler context").hexdigest(),
    )
    changed = reattest_synthetic_real_usage(
        original.model_copy(
            update={
                "routing": {
                    **original.routing,
                    "context_request_evidence": changed_context.model_dump(mode="json"),
                    "context_request_evidence_sha256": changed_context.evidence_sha256,
                }
            }
        )
    )
    assert is_creditable_usage_record(changed, require_real=True)
    assessment = MaximumAssuranceContract(config).evaluate(
        replace(
            runtime,
            model_usage=[
                changed if record.request_id == original.request_id else record
                for record in runtime.model_usage
            ],
        )
    )
    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )

    assert not scheduler.passed
    assert "differs from exact provider evidence" in scheduler.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_maximum_assurance_rejects_scheduler_usage_record_hash_mismatch(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    original = next(record for record in runtime.model_usage if record.role == "threat_model")
    changed = reattest_synthetic_real_usage(
        original.model_copy(
            update={
                "routing": {
                    **original.routing,
                    "synthetic_runtime_observation": "different scheduler usage evidence",
                }
            }
        )
    )
    assert is_creditable_usage_record(changed, require_real=True)
    assessment = MaximumAssuranceContract(config).evaluate(
        replace(
            runtime,
            model_usage=[
                changed if record.request_id == original.request_id else record
                for record in runtime.model_usage
            ],
        )
    )
    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )

    assert not scheduler.passed
    assert "differs from exact provider evidence" in scheduler.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_declared_specialist_roles_without_execution_records_never_receive_credit(
    config_factory,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    assessment = MaximumAssuranceContract(config).evaluate(
        replace(runtime, specialist_execution_records=[])
    )

    evidence = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "specialist_execution_evidence"
    )
    multi_agent = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "multi_agent_review"
    )
    assert not evidence.passed
    assert "differs from accepted outcomes" in evidence.detail
    assert not multi_agent.passed
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_real_specialist_usage_without_host_accepted_outcome_never_receives_credit(
    config_factory,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    original = next(
        record for record in runtime.specialist_execution_records if record.role == "access_control"
    )
    no_outcome = SpecialistExecutionRecord(
        role=original.role,
        role_kind=original.role_kind,
        responsibility=original.responsibility,
        response_schema=original.response_schema,
        schema_name=original.schema_name,
        configured=True,
        execution_evidence=ExecutionEvidenceKind.UNVERIFIED,
        context_limit_bytes=original.context_limit_bytes,
        status=SpecialistExecutionStatus.NOT_SCHEDULED,
    )
    records = [
        no_outcome if record.role == original.role else record
        for record in runtime.specialist_execution_records
    ]
    assessment = MaximumAssuranceContract(config).evaluate(
        replace(runtime, specialist_execution_records=records)
    )

    evidence = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "specialist_execution_evidence"
    )
    multi_agent = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "multi_agent_review"
    )
    assert not evidence.passed
    assert "declared investigator completion differs" in evidence.detail
    assert not multi_agent.passed
    assert "access_control" in multi_agent.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_mock_completed_specialist_is_descriptive_but_never_receives_assurance_credit(
    config_factory,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    original = next(
        record for record in runtime.specialist_execution_records if record.role == "access_control"
    )
    mock_completed = original.model_copy(update={"execution_evidence": ExecutionEvidenceKind.MOCK})
    records = [
        mock_completed if record.role == original.role else record
        for record in runtime.specialist_execution_records
    ]

    assert mock_completed.status is SpecialistExecutionStatus.COMPLETED
    assessment = MaximumAssuranceContract(config).evaluate(
        replace(runtime, specialist_execution_records=records)
    )
    evidence = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "specialist_execution_evidence"
    )
    multi_agent = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "multi_agent_review"
    )

    assert not evidence.passed
    assert "declared investigator completion differs" in evidence.detail
    assert not multi_agent.passed
    assert "access_control" in multi_agent.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_scheduler_rejects_specialist_outcome_for_another_validated_response(
    config_factory,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    original = next(
        record for record in runtime.specialist_execution_records if record.role == "access_control"
    )
    assert len(original.accepted_outcomes) == 1
    outcome = original.accepted_outcomes[0]
    mismatched_outcome = SpecialistAcceptedOutcome.build(
        request_id=outcome.request_id,
        specialist_role=outcome.specialist_role,
        request_role=outcome.request_role,
        outcome_kind=outcome.outcome_kind,
        validated_response_sha256=hashlib.sha256(
            b"unrelated validated specialist response"
        ).hexdigest(),
        context_request_evidence_sha256=outcome.context_request_evidence_sha256,
        requested_surface_count=outcome.requested_surface_count,
        surface_review_artifact_sha256=outcome.surface_review_artifact_sha256,
    )
    changed_record = SpecialistExecutionRecord.model_validate(
        original.model_copy(update={"accepted_outcomes": (mismatched_outcome,)}).model_dump(
            mode="python"
        )
    )
    assessment = MaximumAssuranceContract(config).evaluate(
        replace(
            runtime,
            specialist_execution_records=[
                changed_record if record.role == original.role else record
                for record in runtime.specialist_execution_records
            ],
        )
    )
    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )

    assert not scheduler.passed
    assert "differs from its exact host-accepted outcome" in scheduler.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_maximum_assurance_rejects_generic_blind_specialist_payload_with_declared_outcome(
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_payload = scheduler_support.build_scheduler_test_model_payload
    original_outcome = scheduler_support._scheduler_test_specialist_outcome

    def generic_specialist_payload(
        plan: SchedulerPassPlan,
        task: SchedulerTaskPlan,
    ) -> object:
        if task.role == "specialist:access_control":
            return {"unvalidated_generic_summary": True}
        return original_payload(plan, task)

    def declared_specialist_outcome(
        task: SchedulerTaskPlan,
        usage: UsageRecord | None,
        payload: object,
        surface_review_artifact: ModelSurfaceReviewArtifact | None,
    ) -> SpecialistAcceptedOutcome | None:
        if task.role != "specialist:access_control":
            return original_outcome(task, usage, payload, surface_review_artifact)
        assert usage is not None
        assert usage.validated_response_sha256 is not None
        context = ContextRequestEvidence.model_validate(usage.routing["context_request_evidence"])
        return SpecialistAcceptedOutcome.build(
            request_id=usage.request_id,
            specialist_role="access_control",
            request_role=usage.role,
            outcome_kind=SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW,
            validated_response_sha256=usage.validated_response_sha256,
            context_request_evidence_sha256=context.evidence_sha256,
            requested_surface_count=1,
            surface_review_artifact_sha256=hashlib.sha256(
                b"nonexistent-specialist-review-artifact"
            ).hexdigest(),
        )

    monkeypatch.setattr(
        scheduler_support,
        "build_scheduler_test_model_payload",
        generic_specialist_payload,
    )
    monkeypatch.setattr(
        scheduler_support,
        "_scheduler_test_specialist_outcome",
        declared_specialist_outcome,
    )
    config = _maximum_config(config_factory)
    try:
        runtime = _complete_runtime(config)
    except ValueError as exc:
        assert any(
            marker in str(exc).lower()
            for marker in ("specialist", "candidatereviewbatch", "surface")
        )
        return

    assessment = MaximumAssuranceContract(config).evaluate(runtime)
    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )
    assert not scheduler.passed
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_maximum_assurance_rejects_generic_auxiliary_specialist_payload(
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_payload = scheduler_support.build_scheduler_test_model_payload

    def generic_specialist_payload(
        plan: SchedulerPassPlan,
        task: SchedulerTaskPlan,
    ) -> object:
        if task.role == "specialist:invariant_review":
            return {"unvalidated_generic_summary": True}
        return original_payload(plan, task)

    monkeypatch.setattr(
        scheduler_support,
        "build_scheduler_test_model_payload",
        generic_specialist_payload,
    )
    config = _maximum_config(config_factory)
    try:
        runtime = _complete_runtime(config)
    except ValueError as exc:
        assert "specialist" in str(exc).lower()
        return

    assessment = MaximumAssuranceContract(config).evaluate(runtime)
    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )
    assert not scheduler.passed
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_maximum_assurance_rejects_generic_orientation_payload(
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_payload = scheduler_support.build_scheduler_test_model_payload

    def generic_orientation_payload(
        plan: SchedulerPassPlan,
        task: SchedulerTaskPlan,
    ) -> object:
        if task.pass_kind is SchedulerPassKind.ORIENTATION:
            return {"unvalidated_generic_summary": True}
        return original_payload(plan, task)

    monkeypatch.setattr(
        scheduler_support,
        "build_scheduler_test_model_payload",
        generic_orientation_payload,
    )
    config = _maximum_config(config_factory)
    try:
        runtime = _complete_runtime(config)
    except ValueError as exc:
        assert any(
            marker in str(exc).lower()
            for marker in ("orientation", "threat", "scheduler task output")
        )
        return

    assessment = MaximumAssuranceContract(config).evaluate(runtime)
    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )
    assert not scheduler.passed
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


@pytest.mark.parametrize(
    "host_role",
    ("host:finding_reducer", "host:evidence_cap_judgment"),
)
def test_maximum_assurance_rejects_generic_host_pass_payload(
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
    host_role: str,
) -> None:
    original_build = SchedulerTaskOutput.build

    def generic_host_output(
        cls: type[SchedulerTaskOutput],
        *,
        plan: SchedulerPassPlan,
        task: SchedulerTaskPlan,
        activation: SchedulerTaskActivation,
        payload: object,
        usage_record: UsageRecord | None = None,
        specialist_accepted_outcome: SpecialistAcceptedOutcome | None = None,
        normalizer_sha256: str | None = None,
        **extra: object,
    ) -> SchedulerTaskOutput:
        del cls
        if task.task_kind is SchedulerTaskKind.HOST_COMPUTATION and task.role == host_role:
            payload = {"unvalidated_generic_summary": True}
        return original_build(
            plan=plan,
            task=task,
            activation=activation,
            payload=payload,
            usage_record=usage_record,
            specialist_accepted_outcome=specialist_accepted_outcome,
            normalizer_sha256=normalizer_sha256,
            **extra,
        )

    monkeypatch.setattr(SchedulerTaskOutput, "build", classmethod(generic_host_output))
    config = _maximum_config(config_factory)
    try:
        runtime = _complete_runtime(config)
    except ValueError as exc:
        assert any(
            marker in str(exc).lower()
            for marker in ("host", "reduction", "judgment", "scheduler task output")
        )
        return

    assessment = MaximumAssuranceContract(config).evaluate(runtime)
    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )
    assert not scheduler.passed
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_maximum_assurance_rejects_nonexistent_specialist_surface_artifact(
    config_factory,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    access_control = next(
        record for record in runtime.specialist_execution_records if record.role == "access_control"
    )
    assert len(access_control.accepted_outcomes) == 1
    accepted = access_control.accepted_outcomes[0]
    assert accepted.surface_review_artifact_sha256 is not None

    assessment = MaximumAssuranceContract(config).evaluate(
        replace(
            runtime,
            model_surface_review_artifacts=[
                artifact
                for artifact in runtime.model_surface_review_artifacts
                if artifact.request_id != accepted.request_id
            ],
        )
    )
    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )

    assert not scheduler.passed
    assert (
        "runtime model-surface artifacts differ from scheduler request custody" in scheduler.detail
    )
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


@pytest.mark.parametrize(
    "tampered_field",
    ("requested_surface_manifest_sha256", "rendered_context_sha256"),
)
def test_scheduler_rejects_runtime_surface_artifact_binding_tamper(
    config_factory,
    tampered_field: str,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    original = runtime.model_surface_review_artifacts[0]
    payload = original.model_dump(mode="json")
    payload[tampered_field] = hashlib.sha256(
        f"tampered scheduler surface {tampered_field}".encode()
    ).hexdigest()
    payload["artifact_sha256"] = ModelSurfaceReviewArtifact.calculate_artifact_sha256(payload)
    tampered = ModelSurfaceReviewArtifact.model_validate(payload)

    assessment = MaximumAssuranceContract(config).evaluate(
        replace(
            runtime,
            model_surface_review_artifacts=[
                tampered if artifact.request_id == original.request_id else artifact
                for artifact in runtime.model_surface_review_artifacts
            ],
        )
    )
    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )

    assert not scheduler.passed
    assert "differs from exact runtime model-surface artifact" in scheduler.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_scheduler_rejects_duplicate_runtime_surface_artifact(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    duplicate = runtime.model_surface_review_artifacts[0]

    assessment = MaximumAssuranceContract(config).evaluate(
        replace(
            runtime,
            model_surface_review_artifacts=[
                *runtime.model_surface_review_artifacts,
                duplicate,
            ],
        )
    )
    scheduler = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "seven_pass_scheduler"
    )

    assert not scheduler.passed
    assert (
        "runtime model-surface artifacts differ from scheduler request custody" in scheduler.detail
    )
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_certified_ensemble_requires_twenty_four_specialist_responsibilities(
    config_factory,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    reduced_usage = [
        record
        for record in runtime.model_usage
        if record.role
        not in {
            "specialist:access_control",
            "specialist:reentrancy_control_flow",
        }
    ]

    assessment = MaximumAssuranceContract(config).evaluate(
        replace(runtime, model_usage=reduced_usage)
    )
    ensemble = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "certified_model_ensemble"
    )

    assert not ensemble.passed
    assert "specialist responsibilities=23/24" in ensemble.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_certified_ensemble_requires_four_whole_protocol_lineages(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    reduced_usage = [
        record for record in runtime.model_usage if record.role != "whole_protocol_review:3"
    ]

    assessment = MaximumAssuranceContract(config).evaluate(
        replace(runtime, model_usage=reduced_usage)
    )
    ensemble = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "certified_model_ensemble"
    )

    assert not ensemble.passed
    assert "whole-protocol lineages=3/4" in ensemble.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


@pytest.mark.parametrize(
    "invalid_binding",
    ["missing_user_prompt_sha256", "mismatched_user_prompt_sha256"],
)
def test_certified_ensemble_requires_exact_whole_protocol_prompt_binding(
    config_factory,
    invalid_binding: str,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    original = next(
        record for record in runtime.model_usage if record.role == "whole_protocol_review:3"
    )
    assert original.user_prompt_sha256 is not None
    user_prompt_sha256 = None if invalid_binding == "missing_user_prompt_sha256" else "f" * 64
    invalid = reattest_synthetic_real_usage(
        original.model_copy(update={"user_prompt_sha256": user_prompt_sha256})
    )
    invalid_usage = [
        invalid if record.request_id == original.request_id else record
        for record in runtime.model_usage
    ]

    assessment = MaximumAssuranceContract(config).evaluate(
        replace(runtime, model_usage=invalid_usage)
    )
    ensemble = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "certified_model_ensemble"
    )

    assert not ensemble.passed
    assert "whole-protocol lineages=3/4" in ensemble.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_certified_ensemble_requires_response_backed_critical_surface_lineages(
    config_factory,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    reduced_usage = [record for record in runtime.model_usage if record.role != "source_audit"]

    assessment = MaximumAssuranceContract(config).evaluate(
        replace(runtime, model_usage=reduced_usage)
    )
    ensemble = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "certified_model_ensemble"
    )

    assert not ensemble.passed
    assert "critical surfaces=0 with minimum lineages=0/3" in ensemble.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_zero_critical_surface_denominator_cannot_pass_maximum_assurance(
    config_factory,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    assert runtime.model_review_coverage is not None
    coverage_payload = runtime.model_review_coverage.model_dump(mode="json")
    coverage_payload["surfaces"][0]["critical"] = False
    coverage_payload["critical"] = _model_metric(
        0,
        0,
        "synthetic empty critical-surface denominator",
    ).model_dump(mode="json")
    coverage_payload["critical_gate_passed"] = False
    coverage = ModelReviewCoverage.model_validate(coverage_payload)

    assessment = MaximumAssuranceContract(config).evaluate(
        replace(runtime, model_review_coverage=coverage)
    )
    clauses = {requirement.engine: requirement for requirement in assessment.requirements}

    assert not clauses["critical_model_surface_review"].passed
    assert "denominator is zero" in clauses["critical_model_surface_review"].detail
    assert not clauses["certified_model_ensemble"].passed
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_provider_session_provenance_cannot_be_constructed_or_serialized() -> None:
    with pytest.raises(TypeError, match="only be issued by the pipeline"):
        ProviderSessionProvenance()

    capability = _issue_provider_session_provenance(
        execution_evidence=ExecutionEvidenceKind.REAL,
        pipeline_owned=True,
        trusted_concrete_client=True,
        usage_evidence_consistent=True,
    )
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(capability)


def test_forged_provider_session_without_private_issuer_cannot_receive_real_credit(
    config_factory,
) -> None:
    forged = object.__new__(ProviderSessionProvenance)
    object.__setattr__(forged, "_issuer", object())
    object.__setattr__(forged, "execution_evidence", ExecutionEvidenceKind.REAL)
    object.__setattr__(forged, "pipeline_owned", True)
    object.__setattr__(forged, "trusted_concrete_client", True)
    object.__setattr__(forged, "usage_evidence_consistent", True)
    config = _maximum_config(config_factory)

    assessment = MaximumAssuranceContract(config).evaluate(
        replace(_complete_runtime(config), provider_session=forged)
    )

    clauses = {requirement.engine: requirement for requirement in assessment.requirements}
    assert not clauses["real_provider_session_provenance"].passed
    assert not clauses["real_model_execution"].passed
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


@pytest.mark.parametrize(
    "provider_session",
    [
        None,
        _issue_provider_session_provenance(
            execution_evidence=ExecutionEvidenceKind.MOCK,
            pipeline_owned=False,
            trusted_concrete_client=True,
            usage_evidence_consistent=True,
        ),
        _issue_provider_session_provenance(
            execution_evidence=ExecutionEvidenceKind.REAL,
            pipeline_owned=False,
            trusted_concrete_client=True,
            usage_evidence_consistent=True,
        ),
        _issue_provider_session_provenance(
            execution_evidence=ExecutionEvidenceKind.REAL,
            pipeline_owned=True,
            trusted_concrete_client=False,
            usage_evidence_consistent=True,
        ),
        _issue_provider_session_provenance(
            execution_evidence=ExecutionEvidenceKind.REAL,
            pipeline_owned=True,
            trusted_concrete_client=True,
            usage_evidence_consistent=False,
        ),
    ],
    ids=["missing", "mock", "injected-real", "non-concrete", "usage-mismatch"],
)
def test_real_model_credit_requires_owned_provider_session_provenance(
    config_factory,
    provider_session: ProviderSessionProvenance | None,
) -> None:
    config = _maximum_config(config_factory)
    runtime = replace(_complete_runtime(config), provider_session=provider_session)

    assessment = MaximumAssuranceContract(config).evaluate(runtime)

    clauses = {requirement.engine: requirement for requirement in assessment.requirements}
    assert not clauses["real_provider_session_provenance"].passed
    assert not clauses["real_model_execution"].passed
    assert not clauses["qualified_model_selection_execution"].passed
    assert not clauses["critical_model_surface_review"].passed
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_shape_only_model_quality_cannot_satisfy_runtime_qualification(config_factory) -> None:
    config = _maximum_config(config_factory)

    assessment = MaximumAssuranceContract(config).evaluate(_complete_runtime())

    qualification = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "production_model_qualification"
    )
    real_models = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "real_model_execution"
    )
    assert not qualification.passed
    assert not real_models.passed
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_assurance_revalidates_root_approval_for_credited_surface_reviews(
    config_factory,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    lineage = model_lineage_index(config)[config.models.source_audit.primary.lower()].root_lineage
    config = config.model_copy(
        update={
            "privacy": config.privacy.model_copy(
                update={
                    "approved_model_lineages": tuple(
                        approved
                        for approved in config.privacy.approved_model_lineages
                        if approved != lineage
                    )
                }
            )
        }
    )

    assessment = MaximumAssuranceContract(config).evaluate(runtime)

    critical_review = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "critical_model_surface_review"
    )
    assert not critical_review.passed
    assert "not backed by matching certification-grade" in critical_review.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


@pytest.mark.parametrize(
    "missing_hash",
    [
        "qualification_artifact_sha256",
        "qualification_verification_sha256",
        "production_selection_sha256",
        "selection_verification_sha256",
        "qualification_result_sha256",
    ],
)
def test_each_missing_usage_qualification_join_revokes_surface_credit(
    config_factory,
    missing_hash: str,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    usage: list[UsageRecord] = []
    for record in runtime.model_usage:
        if record.role == "source_audit":
            routing = dict(record.routing)
            routing.pop(missing_hash)
            record = record.model_copy(update={"routing": routing})
        usage.append(record)

    assessment = MaximumAssuranceContract(config).evaluate(replace(runtime, model_usage=usage))

    critical_review = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "critical_model_surface_review"
    )
    assert not critical_review.passed
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_public_qualification_hashes_without_reasoning_evidence_receive_no_credit(
    config_factory,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    original = next(record for record in runtime.model_usage if record.role == "source_audit")
    unbound = bind_synthetic_usage_identity(
        rebind_synthetic_token_plan(
            original.model_copy(
                update={
                    "reasoning_evidence": None,
                    "reasoning_tokens": 0,
                }
            )
        )
    )
    assert not is_creditable_usage_record(
        unbound,
        require_real=True,
        require_certification=True,
    )
    assert not _is_real_model_usage(
        unbound,
        config,
        qualification=runtime.production_qualification,
        provider_session=runtime.provider_session,
    )

    assessment = MaximumAssuranceContract(config).evaluate(
        replace(
            runtime,
            model_usage=[
                unbound if record.request_id == original.request_id else record
                for record in runtime.model_usage
            ],
        )
    )

    critical_review = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "critical_model_surface_review"
    )
    assert not critical_review.passed
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


@pytest.mark.parametrize(
    "fault",
    [
        "policy_artifact",
        "role_policy_and_control",
        "endpoint_capability",
        "qualification_binding",
        "wrong_role_pair_binding",
        "other_model_binding",
    ],
)
def test_reasoning_authority_mismatch_revokes_runtime_credit(
    config_factory,
    fault: str,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    qualification = runtime.production_qualification
    assert qualification is not None
    original = next(record for record in runtime.model_usage if record.role == "source_audit")
    model = qualification.model_for(
        original.requested_model,
        now=datetime.now(UTC).replace(microsecond=0),
    )
    binding = _reasoning_binding_for_usage(original, model)
    policy = _reasoning_policy_for_model(model)
    request_role = original.role
    endpoint_capability_sha256 = binding.endpoint_reasoning_capability_sha256
    qualification_binding_sha256 = binding.binding_sha256

    if fault == "policy_artifact":
        controls = {item.role: item.control for item in policy.policies}
        unrelated_role = next(role for role in controls if role != binding.configured_policy_role)
        controls[unrelated_role] = ReasoningControlProfile.build(
            mode="effort",
            effort="none",
            reserved_reasoning_tokens=0,
        )
        policy = ReasoningPolicyArtifact.build(controls_by_role=controls)
    elif fault == "role_policy_and_control":
        controls = {item.role: item.control for item in policy.policies}
        controls[binding.configured_policy_role] = ReasoningControlProfile.build(
            mode="effort",
            effort="none",
            reserved_reasoning_tokens=0,
        )
        policy = ReasoningPolicyArtifact.build(controls_by_role=controls)
    elif fault == "endpoint_capability":
        endpoint_capability_sha256 = "f" * 64
    elif fault == "qualification_binding":
        qualification_binding_sha256 = "f" * 64
    elif fault == "wrong_role_pair_binding":
        original = next(
            record
            for record in runtime.model_usage
            if record.role.startswith("candidate_falsifier:")
        )
        model = qualification.model_for(
            original.requested_model,
            now=datetime.now(UTC).replace(microsecond=0),
        )
        policy = _reasoning_policy_for_model(model)
        resolution = resolve_reasoning_request_role(original.role)
        wrong_binding = next(
            candidate
            for candidate in model.reasoning_bindings
            if candidate.qualified_role == resolution.qualification_role
            and candidate.configured_policy_role != resolution.configured_policy_role
        )
        request_role = original.role
        endpoint_capability_sha256 = wrong_binding.endpoint_reasoning_capability_sha256
        qualification_binding_sha256 = wrong_binding.binding_sha256
    else:
        other_model = next(
            candidate
            for candidate in qualification.models
            if candidate.exact_model_id != model.exact_model_id
        )
        other_binding = _reasoning_binding_for_usage(original, other_model)
        endpoint_capability_sha256 = other_binding.endpoint_reasoning_capability_sha256
        qualification_binding_sha256 = other_binding.binding_sha256

    plan = ReasoningRequestPlanEvidence.build(
        request_role=request_role,
        policy=policy,
        endpoint_capability_sha256=endpoint_capability_sha256,
        qualification_binding_sha256=qualification_binding_sha256,
    )
    mismatched = _with_reasoning_plan(
        original,
        plan,
        observed_reasoning_tokens=0,
    )
    assert not is_creditable_usage_record(
        mismatched,
        require_real=True,
        require_certification=True,
    )
    assert not _is_real_model_usage(
        mismatched,
        config,
        qualification=qualification,
        provider_session=runtime.provider_session,
    )

    assessment = MaximumAssuranceContract(config).evaluate(
        replace(
            runtime,
            model_usage=[
                mismatched if record.request_id == original.request_id else record
                for record in runtime.model_usage
            ],
        )
    )

    if fault != "wrong_role_pair_binding":
        selection_execution = next(
            requirement
            for requirement in assessment.requirements
            if requirement.engine == "qualified_model_selection_execution"
        )
        assert not selection_execution.passed
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


@pytest.mark.parametrize("observed_reasoning_tokens", [0, None])
def test_active_reasoning_without_positive_observation_receives_no_runtime_credit(
    config_factory,
    observed_reasoning_tokens: int | None,
) -> None:
    config = _maximum_config(
        config_factory,
        reasoning={
            "effort": "high",
            "reserved_tokens": 8,
        },
    )
    runtime = _complete_runtime(config)
    assert (
        MaximumAssuranceContract(config).evaluate(runtime).status is MaximumAssuranceStatus.COMPLETE
    )
    original = next(record for record in runtime.model_usage if record.role == "source_audit")
    assert original.reasoning_evidence is not None
    invalid = _with_reasoning_plan(
        original,
        original.reasoning_evidence.request_plan,
        observed_reasoning_tokens=observed_reasoning_tokens,
    )
    assert not _is_real_model_usage(
        invalid,
        config,
        qualification=runtime.production_qualification,
        provider_session=runtime.provider_session,
    )

    assessment = MaximumAssuranceContract(config).evaluate(
        replace(
            runtime,
            model_usage=[
                invalid if record.request_id == original.request_id else record
                for record in runtime.model_usage
            ],
        )
    )

    selection_execution = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "qualified_model_selection_execution"
    )
    assert not selection_execution.passed
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


@pytest.mark.parametrize(
    "fault",
    [
        "canonical_model",
        "qualified_exact_model_id",
        "qualified_canonical_model_slug",
        "qualified_root_lineage",
        "qualified_provider_endpoint",
        "qualified_provider_name",
        "qualified_endpoint_snapshot_sha256",
        "qualified_model_metadata_snapshot_sha256",
        "qualified_pricing_snapshot_sha256",
        "qualified_roles",
        "qualification_verified_at",
        "qualification_expires_at",
        "endpoint_snapshot_sha256",
        "endpoint_pricing_sha256",
        "model_metadata_snapshot_sha256",
    ],
)
def test_mismatched_qualified_usage_projection_revokes_runtime_credit(
    config_factory,
    fault: str,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    qualification = runtime.production_qualification
    assert qualification is not None
    usage: list[UsageRecord] = []
    for record in runtime.model_usage:
        if record.role != "source_audit":
            usage.append(record)
            continue
        routing = dict(record.routing)
        if fault == "canonical_model":
            requested_author = record.requested_model.split("/", 1)[0]
            mismatched_canonical = f"{requested_author}/canonical-mismatch"
            routing.update(
                {
                    "selected_model": mismatched_canonical,
                    "canonical_model": mismatched_canonical,
                    "catalog_identity_binding_sha256": canonical_sha256(
                        {
                            "canonical_slug": mismatched_canonical,
                            "id": record.requested_model,
                        }
                    ),
                }
            )
            record = record.model_copy(
                update={
                    "actual_model": mismatched_canonical,
                    "returned_model": mismatched_canonical,
                    "routing": routing,
                }
            )
        else:
            mismatched_values: dict[str, object] = {
                "qualified_exact_model_id": "synthetic/unqualified",
                "qualified_canonical_model_slug": "synthetic/unqualified-canonical",
                "qualified_root_lineage": f"sha256:{'f' * 64}",
                "qualified_provider_endpoint": "unqualified-provider",
                "qualified_provider_name": "Unqualified Provider",
                "qualified_endpoint_snapshot_sha256": "a" * 64,
                "qualified_model_metadata_snapshot_sha256": "b" * 64,
                "qualified_pricing_snapshot_sha256": "c" * 64,
                "qualified_roles": [],
                "qualification_verified_at": "2000-01-01T00:00:00+00:00",
                "qualification_expires_at": "2000-01-02T00:00:00+00:00",
                "endpoint_snapshot_sha256": "d" * 64,
                "endpoint_pricing_sha256": "e" * 64,
                "model_metadata_snapshot_sha256": "f" * 64,
            }
            routing[fault] = mismatched_values[fault]
            record = record.model_copy(update={"routing": routing})
        raw_structured_output = record.routing["structured_output"]
        assert isinstance(raw_structured_output, dict)
        endpoint_snapshot_sha256 = record.routing["endpoint_snapshot_sha256"]
        output_capability_sha256 = record.routing["output_capability_sha256"]
        assert isinstance(endpoint_snapshot_sha256, str)
        assert isinstance(output_capability_sha256, str)
        record = _with_output_evidence(
            record,
            endpoint_snapshot_sha256=endpoint_snapshot_sha256,
            output_capability_sha256=output_capability_sha256,
            mode=StructuredOutputMode(raw_structured_output["requested_mode"]),
        )
        if fault == "endpoint_snapshot_sha256":
            assert not is_creditable_usage_record(
                record,
                require_real=True,
                require_certification=True,
            )
        else:
            assert is_creditable_usage_record(
                record,
                require_real=True,
                require_certification=True,
            )
        usage.append(record)

    assessment = MaximumAssuranceContract(config).evaluate(replace(runtime, model_usage=usage))

    selection_execution = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "qualified_model_selection_execution"
    )
    assert not selection_execution.passed
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_every_selected_tier_a_model_requires_successful_real_usage(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    omitted_model = config.models.verifier.primary
    partial_usage = [
        record for record in runtime.model_usage if record.requested_model != omitted_model
    ]
    assert partial_usage

    assessment = MaximumAssuranceContract(config).evaluate(
        replace(runtime, model_usage=partial_usage)
    )

    qualification = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "production_model_qualification"
    )
    selection_execution = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "qualified_model_selection_execution"
    )
    certified_ensemble = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "certified_model_ensemble"
    )
    assert qualification.passed
    assert not selection_execution.passed
    assert not certified_ensemble.passed
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_unrelated_real_requests_cannot_back_mock_model_surface_coverage(
    config_factory,
) -> None:
    runtime = _complete_runtime()
    runtime = replace(
        runtime,
        model_usage=[
            (
                record.model_copy(update={"execution_evidence": ExecutionEvidenceKind.MOCK})
                if record.role in {"business_logic", "source_audit"}
                else record
            )
            for record in runtime.model_usage
        ],
    )

    assessment = MaximumAssuranceContract(_maximum_config(config_factory)).evaluate(runtime)
    gate = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "critical_model_surface_review"
    )

    assert not gate.passed
    assert "not backed by matching certification-grade" in gate.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_context_and_aggregate_fields_alone_cannot_back_model_surface_coverage(
    config_factory,
) -> None:
    runtime = _complete_runtime()
    coverage = runtime.model_review_coverage
    assert coverage is not None
    asserted_surface = coverage.surfaces[0].model_copy(update={"evidence_references": []})
    asserted_coverage = coverage.model_copy(update={"surfaces": [asserted_surface]})
    assert asserted_coverage.critical_gate_passed
    assert asserted_surface.reviewed

    assessment = MaximumAssuranceContract(_maximum_config(config_factory)).evaluate(
        replace(
            runtime,
            model_review_coverage=asserted_coverage,
            model_surface_review_artifacts=[],
        )
    )
    gate = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "critical_model_surface_review"
    )

    assert not gate.passed
    assert "not backed by matching certification-grade" in gate.detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_model_surface_coverage_rejects_sealed_artifact_usage_hash_mismatch(
    config_factory,
) -> None:
    runtime = _complete_runtime()
    coverage = runtime.model_review_coverage
    assert coverage is not None
    original = runtime.model_surface_review_artifacts[0]
    payload = original.model_dump(mode="json")
    payload["prompt_sha256"] = "f" * 64
    payload["artifact_sha256"] = ModelSurfaceReviewArtifact.calculate_artifact_sha256(payload)
    mismatched = ModelSurfaceReviewArtifact.model_validate(payload)
    updated_references = [
        (
            reference.model_copy(update={"artifact_sha256": mismatched.artifact_sha256})
            if reference.request_id == original.request_id
            else reference
        )
        for reference in coverage.surfaces[0].evidence_references
    ]
    updated_surface = coverage.surfaces[0].model_copy(
        update={"evidence_references": updated_references}
    )
    updated_coverage = coverage.model_copy(update={"surfaces": [updated_surface]})
    updated_artifacts = [
        mismatched if artifact.request_id == original.request_id else artifact
        for artifact in runtime.model_surface_review_artifacts
    ]

    assessment = MaximumAssuranceContract(_maximum_config(config_factory)).evaluate(
        replace(
            runtime,
            model_review_coverage=updated_coverage,
            model_surface_review_artifacts=updated_artifacts,
        )
    )
    gate = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "critical_model_surface_review"
    )

    assert not gate.passed
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_model_surface_coverage_requires_exactly_one_usage_and_artifact(
    config_factory,
) -> None:
    runtime = _complete_runtime()
    referenced_request = runtime.model_surface_review_artifacts[0].request_id
    usage = next(
        record for record in runtime.model_usage if record.request_id == referenced_request
    )
    duplicate_usage_runtime = replace(
        runtime,
        model_usage=[*runtime.model_usage, usage],
    )
    duplicate_artifact_runtime = replace(
        runtime,
        model_surface_review_artifacts=[
            *runtime.model_surface_review_artifacts,
            runtime.model_surface_review_artifacts[0],
        ],
    )

    for ambiguous_runtime in (duplicate_usage_runtime, duplicate_artifact_runtime):
        assessment = MaximumAssuranceContract(_maximum_config(config_factory)).evaluate(
            ambiguous_runtime
        )
        gate = next(
            requirement
            for requirement in assessment.requirements
            if requirement.engine == "critical_model_surface_review"
        )
        assert not gate.passed
        assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_foundry_negative_regression_is_conclusive_engine_execution(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    foundry = next(run for run in runtime.scanners if run.scanner == "foundry_fork")
    assert foundry.foundry_summary is not None
    assert foundry.repository_suite_selection is not None
    prior_execution = foundry.repository_test_executions[0]
    execution_payload = prior_execution.model_dump(
        mode="python",
        exclude={"execution_sha256"},
    )
    execution_payload.update(
        {
            "status": RepositoryTestExecutionStatus.ASSERTION_FAILED,
            "terminal_detail": "Synthetic assertion failed",
            "process_exit_code": 1,
        }
    )
    failed_execution = RepositoryTestExecution.sealed(**execution_payload)
    executions = [failed_execution, *foundry.repository_test_executions[1:]]
    descriptor = next(
        item
        for item in foundry.repository_suite_selection.tests
        if item.descriptor_sha256 == failed_execution.descriptor_sha256
    )
    finding = ScannerFinding(
        scanner="foundry_fork",
        rule_id="repository-fork-test-failure",
        title="Synthetic pinned-fork test failure",
        severity=Severity.HIGH,
        message="Synthetic assertion failed",
        locations=[
            Location(
                path=descriptor.path,
                start_line=descriptor.start_line,
                end_line=descriptor.end_line,
            )
        ],
        metadata={
            "repository_test_execution_sha256": failed_execution.execution_sha256,
        },
        evidence_strength=EvidenceStrength.DETERMINISTIC_ANALYZER,
        fingerprint="f" * 64,
    )
    updated = foundry.model_copy(
        update={
            "process_exit_code": 1,
            "findings": [finding],
            "repository_test_executions": executions,
            "foundry_summary": foundry.foundry_summary.model_copy(
                update={"passed_tests": 2, "failed_tests": 1}
            ),
            "execution_observation_sha256": None,
        }
    )
    updated = ScannerRun.model_validate(
        {
            **updated.model_dump(mode="json"),
            "execution_observation_sha256": updated.expected_execution_observation_sha256(),
        }
    )
    runtime.scanners[runtime.scanners.index(foundry)] = updated

    assessment = MaximumAssuranceContract(config).evaluate(runtime)

    gate = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "foundry_unit_property_invariant_execution"
    )
    assert gate.passed
    assert assessment.status is MaximumAssuranceStatus.COMPLETE


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("economic_template", EconomicSimulationKind.ROUNDING),
        (
            "required_transaction_ordering",
            TransactionOrderingCapability.SAME_BLOCK,
        ),
        ("harness_spec_sha256", "0" * 64),
        ("compiler_version", "solc 0.8.29"),
    ],
)
def test_invariant_observation_binds_assurance_consumed_identity_and_economic_fields(
    field: str,
    value: object,
) -> None:
    result = _complete_runtime().invariant_executions[0]
    assert result.execution_observation_sha256 is not None

    changed = result.model_copy(update={field: value})

    assert changed.expected_execution_observation_sha256() != result.execution_observation_sha256


@pytest.mark.parametrize(
    ("case", "failed_clause"),
    [
        pytest.param(
            "legacy_empty_success",
            "foundry_unit_property_invariant_execution",
            id="legacy_empty_success",
        ),
        pytest.param(
            "missing_slither",
            "slither_execution",
            id="required_slither_missing",
        ),
        pytest.param(
            "missing_foundry",
            "foundry_unit_property_invariant_execution",
            id="foundry_missing",
        ),
        pytest.param(
            "missing_slither_pin",
            "slither_execution",
            id="slither_without_trust_pin",
        ),
        pytest.param(
            "missing_slither_observation",
            "slither_execution",
            id="slither_execution_observation_missing",
        ),
        pytest.param(
            "unvalidated_slither_output",
            "slither_execution",
            id="slither_machine_envelope_unvalidated",
        ),
        pytest.param(
            "tampered_slither_backend",
            "slither_execution",
            id="slither_backend_not_bound_to_observation",
        ),
        pytest.param(
            "mismatched_foundry_pin",
            "foundry_unit_property_invariant_execution",
            id="foundry_with_wrong_trust_pin",
        ),
        pytest.param(
            "zero_foundry_unit",
            "foundry_unit_property_invariant_execution",
            id="foundry_zero_unit",
        ),
        pytest.param(
            "missing_foundry_observation",
            "foundry_unit_property_invariant_execution",
            id="foundry_execution_observation_missing",
        ),
        pytest.param(
            "tampered_foundry_observation",
            "foundry_unit_property_invariant_execution",
            id="foundry_execution_observation_tampered",
        ),
        pytest.param(
            "unvalidated_foundry_output",
            "foundry_unit_property_invariant_execution",
            id="foundry_machine_envelope_unvalidated",
        ),
        pytest.param(
            "missing_foundry_attestation",
            "foundry_unit_property_invariant_execution",
            id="foundry_isolation_attestation_missing",
        ),
        pytest.param(
            "rootless_foundry_unattested",
            "foundry_unit_property_invariant_execution",
            id="rootless_binary_identity_unattested",
        ),
        pytest.param(
            "empty_invariant_coverage",
            "stateful_invariant_execution",
            id="empty_declared_invariant_coverage_is_not_execution",
        ),
        pytest.param(
            "inconsistent_invariant_coverage",
            "stateful_invariant_execution",
            id="inconsistent_invariant_attempts_are_not_execution",
        ),
        pytest.param(
            "missing_invariant_result",
            "stateful_invariant_execution",
            id="missing_expected_invariant_execution",
        ),
        pytest.param(
            "duplicate_invariant_result",
            "stateful_invariant_execution",
            id="duplicate_invariant_execution",
        ),
        pytest.param(
            "wrong_invariant_harness_hash",
            "stateful_invariant_execution",
            id="wrong_invariant_harness_identity",
        ),
        pytest.param(
            "empty_observed_invariant_actions",
            "stateful_invariant_execution",
            id="declared_actions_without_observed_calls",
        ),
        pytest.param(
            "missing_invariant_attestation",
            "stateful_invariant_execution",
            id="invariant_isolation_attestation_missing",
        ),
        pytest.param(
            "missing_economic_plan",
            "protocol_economic_simulation",
            id="deterministic_economic_applicability_omitted",
        ),
        pytest.param("missing_echidna", "required_formal_tool:echidna"),
        pytest.param("missing_medusa", "required_formal_tool:medusa"),
        pytest.param("missing_halmos", "required_formal_tool:halmos"),
        pytest.param(
            "duplicate_echidna",
            "required_formal_tool:echidna",
            id="ambiguous_duplicate_engine",
        ),
        pytest.param(
            "mock_echidna",
            "required_formal_tool:echidna",
            id="mock_engine_is_not_real",
        ),
        pytest.param(
            "missing_medusa_pin",
            "required_formal_tool:medusa",
            id="medusa_without_trust_pin",
        ),
        pytest.param(
            "wrong_halmos_solver_pin",
            "required_formal_tool:halmos",
            id="halmos_with_wrong_solver_pin",
        ),
        pytest.param(
            "translation_only_echidna",
            "required_formal_tool:echidna",
            id="planned_property_ids_are_not_execution",
        ),
        pytest.param(
            "mismatched_echidna_corpus",
            "required_formal_tool:echidna",
            id="property_engine_uses_another_corpus",
        ),
        pytest.param(
            "mismatched_echidna_property_hash",
            "required_formal_tool:echidna",
            id="truncated_property_id_cannot_hide_content_drift",
        ),
        pytest.param(
            "partial_echidna_campaign",
            "required_formal_tool:echidna",
            id="configured_campaign_was_not_completed",
        ),
        pytest.param(
            "missing_echidna_attestation",
            "required_formal_tool:echidna",
            id="formal_isolation_attestation_missing",
        ),
        pytest.param(
            "formal_only_unavailable",
            "formal_proof_engine",
            id="formal_only_unavailable_record",
        ),
        pytest.param(
            "empty_formal_proof",
            "formal_proof_engine",
            id="empty_success_is_not_proof",
        ),
        pytest.param(
            "zero_property_formal_proof",
            "formal_proof_engine",
            id="zero_property_proof_is_vacuous",
        ),
        pytest.param(
            "mismatched_formal_evidence_id",
            "formal_proof_engine",
            id="proof_evidence_must_bind_executed_property",
        ),
        pytest.param(
            "missing_offline_replay",
            "isolated_replay_execution",
            id="missing_isolated_replay",
        ),
        pytest.param(
            "mock_offline_replay",
            "isolated_replay_execution",
            id="mock_replay_is_not_real",
        ),
        pytest.param(
            "wrong_replay_run",
            "isolated_replay_execution",
            id="replay_from_another_run_is_not_real",
        ),
        pytest.param(
            "wrong_replay_manifest",
            "isolated_replay_execution",
            id="replay_from_another_manifest_is_not_real",
        ),
        pytest.param(
            "wrong_replay_verification",
            "isolated_replay_execution",
            id="replay_without_current_verification_is_not_real",
        ),
        pytest.param(
            "scanner_only_replay",
            "isolated_replay_execution",
            id="replay_applicability_is_not_self_declared",
        ),
        pytest.param(
            "missing_replay_member",
            "isolated_replay_execution",
            id="replay_must_cover_exact_component_inventory",
        ),
        pytest.param(
            "missing_replay_attestation",
            "isolated_replay_execution",
            id="replay_isolation_attestation_missing",
        ),
        pytest.param(
            "missing_model_usage",
            "real_model_execution",
            id="role_sets_are_not_model_execution",
        ),
        pytest.param(
            "mock_model_usage",
            "real_model_execution",
            id="mock_models_are_not_real_reviews",
        ),
        pytest.param(
            "non_certification_model_usage",
            "real_model_execution",
            id="ordinary_real_calls_are_not_certification_evidence",
        ),
        pytest.param(
            "unconfigured_model_usage",
            "real_model_execution",
            id="unconfigured_models_are_not_real_reviews",
        ),
        pytest.param(
            "missing_benchmark",
            "benchmark_regression_gate",
            id="missing_benchmark_default",
        ),
        pytest.param(
            "in_memory_benchmark",
            "benchmark_regression_gate",
            id="declared_current_benchmark_is_not_file_backed",
        ),
        pytest.param(
            "standard_benchmark",
            "benchmark_regression_gate",
            id="standard_profile_benchmark_is_not_maximum_assurance",
        ),
        pytest.param(
            "wrong_benchmark_commit",
            "benchmark_regression_gate",
            id="benchmark_from_another_commit_is_not_current",
        ),
    ],
)
def test_exact_maximum_assurance_portfolio_fails_closed(
    config_factory,
    case: str,
    failed_clause: str,
) -> None:
    runtime = _complete_runtime()
    config = _maximum_config(config_factory)
    if case == "legacy_empty_success":
        now = datetime.now(UTC)
        runtime = replace(
            runtime,
            scanners=[
                ScannerRun(
                    scanner="slither",
                    status=ScannerStatus.SUCCESS,
                    started_at=now,
                    finished_at=now,
                    duration_seconds=0,
                )
            ],
            invariant_executions=[
                InvariantExecutionResult(
                    invariant_id="inv-economic",
                    harness_name="DonationInflation",
                    status=InvariantExecutionStatus.PASSED,
                )
            ],
            formal_runs=[
                FormalToolRun(
                    tool="solc-smtchecker",
                    status=FormalToolStatus.SUCCESS,
                )
            ],
            model_usage=[],
            offline_replay=None,
            benchmark_verification=None,
        )
    elif case == "missing_slither":
        runtime = replace(
            runtime,
            scanners=[run for run in runtime.scanners if run.scanner != "slither"],
        )
    elif case == "missing_foundry":
        runtime = replace(
            runtime,
            scanners=[run for run in runtime.scanners if run.scanner != "foundry_fork"],
        )
    elif case == "missing_slither_pin":
        config = config.model_copy(
            update={
                "scanners": config.scanners.model_copy(
                    update={
                        "slither": config.scanners.slither.model_copy(
                            update={"version": None, "sha256": None}
                        )
                    }
                )
            }
        )
    elif case in {
        "missing_slither_observation",
        "unvalidated_slither_output",
        "tampered_slither_backend",
    }:
        run = next(run for run in runtime.scanners if run.scanner == "slither")
        update: dict[str, object]
        if case == "missing_slither_observation":
            update = {"execution_observation_sha256": None}
        elif case == "unvalidated_slither_output":
            update = {"machine_output_validated": False}
        else:
            update = {"isolation_backend": "rootless-container"}
        runtime.scanners[runtime.scanners.index(run)] = run.model_copy(update=update)
    elif case == "mismatched_foundry_pin":
        config = config.model_copy(
            update={
                "scanners": config.scanners.model_copy(
                    update={
                        "foundry_fork": config.scanners.foundry_fork.model_copy(
                            update={"sha256": "0" * 64}
                        )
                    }
                )
            }
        )
    elif case == "zero_foundry_unit":
        run = next(run for run in runtime.scanners if run.scanner == "foundry_fork")
        runtime.scanners[runtime.scanners.index(run)] = run.model_copy(
            update={
                "foundry_summary": FoundryTestExecutionSummary(
                    unit_tests=0,
                    fuzz_tests=1,
                    invariant_tests=1,
                    passed_tests=2,
                    failed_tests=0,
                    skipped_tests=0,
                    fuzz_cases=256,
                    invariant_runs=256,
                    invariant_calls=8_192,
                )
            }
        )
    elif case == "missing_foundry_observation":
        run = next(run for run in runtime.scanners if run.scanner == "foundry_fork")
        runtime.scanners[runtime.scanners.index(run)] = run.model_copy(
            update={"execution_observation_sha256": None}
        )
    elif case == "tampered_foundry_observation":
        run = next(run for run in runtime.scanners if run.scanner == "foundry_fork")
        runtime.scanners[runtime.scanners.index(run)] = run.model_copy(
            update={"raw_output_bytes": run.raw_output_bytes + 1}
        )
    elif case in {"unvalidated_foundry_output", "missing_foundry_attestation"}:
        run_index = next(
            index for index, item in enumerate(runtime.scanners) if item.scanner == "foundry_fork"
        )
        run = runtime.scanners[run_index]
        run = run.model_copy(
            update={
                (
                    "machine_output_validated"
                    if case == "unvalidated_foundry_output"
                    else "isolation_attestation_sha256"
                ): False if case == "unvalidated_foundry_output" else None,
                "execution_observation_sha256": None,
            }
        )
        runtime.scanners[run_index] = run.model_copy(
            update={"execution_observation_sha256": run.expected_execution_observation_sha256()}
        )
    elif case == "rootless_foundry_unattested":
        run = next(run for run in runtime.scanners if run.scanner == "foundry_fork")
        runtime.scanners[runtime.scanners.index(run)] = run.model_copy(
            update={"isolation_backend": "rootless-container"}
        )
    elif case in {"empty_invariant_coverage", "inconsistent_invariant_coverage"}:
        run = runtime.invariant_executions[0]
        coverage = run.campaign_coverage
        assert coverage is not None
        replacement = (
            InvariantCampaignCoverage(
                declared_action_functions=[],
                observed_action_functions=[],
                declared_state_properties=[],
                observed_state_properties=[],
                sequence_depth_bound=run.depth,
                observed_sequence_lengths=[],
                attempts_consistent=False,
            )
            if case == "empty_invariant_coverage"
            else coverage.model_copy(update={"attempts_consistent": False})
        )
        runtime = replace(
            runtime,
            invariant_executions=[run.model_copy(update={"campaign_coverage": replacement})],
        )
    elif case == "missing_invariant_result":
        runtime = replace(runtime, invariant_executions=[])
    elif case == "duplicate_invariant_result":
        runtime.invariant_executions.append(runtime.invariant_executions[0])
    elif case == "wrong_invariant_harness_hash":
        run = runtime.invariant_executions[0].model_copy(update={"harness_spec_sha256": "0" * 64})
        runtime = replace(
            runtime,
            invariant_executions=[
                run.model_copy(
                    update={
                        "execution_observation_sha256": (
                            run.expected_execution_observation_sha256()
                        )
                    }
                )
            ],
        )
    elif case == "empty_observed_invariant_actions":
        run = runtime.invariant_executions[0]
        coverage = run.campaign_coverage
        assert coverage is not None
        run = run.model_copy(
            update={
                "campaign_coverage": coverage.model_copy(update={"observed_action_functions": []})
            }
        )
        runtime = replace(
            runtime,
            invariant_executions=[
                run.model_copy(
                    update={
                        "execution_observation_sha256": (
                            run.expected_execution_observation_sha256()
                        )
                    }
                )
            ],
        )
    elif case == "missing_invariant_attestation":
        run = runtime.invariant_executions[0].model_copy(
            update={
                "isolation_attestation_sha256": None,
                "execution_observation_sha256": None,
            }
        )
        runtime = replace(
            runtime,
            invariant_executions=[
                run.model_copy(
                    update={
                        "execution_observation_sha256": (
                            run.expected_execution_observation_sha256()
                        )
                    }
                )
            ],
        )
    elif case == "missing_economic_plan":
        runtime = replace(runtime, economic_simulations=[])
    elif case.startswith("missing_") and case.removeprefix("missing_") in {
        "echidna",
        "medusa",
        "halmos",
    }:
        tool = case.removeprefix("missing_")
        runtime = replace(
            runtime,
            formal_runs=[run for run in runtime.formal_runs if run.tool != tool],
        )
    elif case == "duplicate_echidna":
        runtime.formal_runs.append(_real_formal_run("echidna"))
    elif case == "mock_echidna":
        runtime = replace(
            runtime,
            formal_runs=[
                (
                    _real_formal_run(
                        "echidna",
                        execution_evidence=ExecutionEvidenceKind.MOCK,
                    )
                    if run.tool == "echidna"
                    else run
                )
                for run in runtime.formal_runs
            ],
        )
    elif case == "missing_medusa_pin":
        config = config.model_copy(
            update={
                "formal": config.formal.model_copy(
                    update={"medusa_version": None, "medusa_sha256": None}
                )
            }
        )
    elif case == "wrong_halmos_solver_pin":
        config = config.model_copy(
            update={"formal": config.formal.model_copy(update={"halmos_solver_sha256": "0" * 64})}
        )
    elif case == "translation_only_echidna":
        runtime = replace(
            runtime,
            formal_runs=[
                (
                    _real_formal_run("echidna", observe_properties=False)
                    if run.tool == "echidna"
                    else run
                )
                for run in runtime.formal_runs
            ],
        )
    elif case == "mismatched_echidna_corpus":
        runtime = replace(
            runtime,
            formal_runs=[
                (
                    run.model_copy(
                        update={
                            "property_corpus_hash": "e" * 64,
                            "execution_observation_sha256": None,
                        }
                    )
                    if run.tool == "echidna"
                    else run
                )
                for run in runtime.formal_runs
            ],
        )
        echidna = next(run for run in runtime.formal_runs if run.tool == "echidna")
        runtime.formal_runs[runtime.formal_runs.index(echidna)] = echidna.model_copy(
            update={"execution_observation_sha256": echidna.expected_execution_observation_sha256()}
        )
    elif case in {
        "mismatched_echidna_property_hash",
        "partial_echidna_campaign",
        "missing_echidna_attestation",
    }:
        echidna_index = next(
            index for index, item in enumerate(runtime.formal_runs) if item.tool == "echidna"
        )
        echidna = runtime.formal_runs[echidna_index]
        updates: dict[str, object] = {"execution_observation_sha256": None}
        if case == "mismatched_echidna_property_hash":
            binding = echidna.translated_property_bindings[0].model_copy(
                update={"property_hash": ("1" * 24) + ("2" * 40)}
            )
            updates["translated_property_bindings"] = [binding]
        elif case == "partial_echidna_campaign":
            updates["observed_campaign"] = FormalCampaignObservation(runs=1, calls=1, depth=1)
        else:
            updates["isolation_attestation_sha256"] = None
        echidna = echidna.model_copy(update=updates)
        runtime.formal_runs[echidna_index] = echidna.model_copy(
            update={"execution_observation_sha256": echidna.expected_execution_observation_sha256()}
        )
    elif case == "formal_only_unavailable":
        runtime = replace(
            runtime,
            formal_runs=[
                FormalToolRun(
                    tool="certora",
                    status=FormalToolStatus.UNAVAILABLE,
                )
            ],
        )
    elif case == "empty_formal_proof":
        runtime = replace(
            runtime,
            formal_runs=[
                (run.model_copy(update={"evidence": []}) if run.tool == "certora" else run)
                for run in runtime.formal_runs
            ],
        )
    elif case == "zero_property_formal_proof":
        runtime = replace(
            runtime,
            formal_runs=[
                (
                    run.model_copy(
                        update={
                            "translated_properties": 0,
                            "executed_property_ids": [],
                            "observed_property_ids": [],
                            "translated_property_bindings": [],
                            "execution_observation_sha256": None,
                        }
                    )
                    if run.tool == "certora"
                    else run
                )
                for run in runtime.formal_runs
            ],
        )
        certora = next(run for run in runtime.formal_runs if run.tool == "certora")
        runtime.formal_runs[runtime.formal_runs.index(certora)] = certora.model_copy(
            update={"execution_observation_sha256": certora.expected_execution_observation_sha256()}
        )
    elif case == "mismatched_formal_evidence_id":
        certora_index = next(
            index for index, item in enumerate(runtime.formal_runs) if item.tool == "certora"
        )
        certora = runtime.formal_runs[certora_index]
        certora = certora.model_copy(
            update={
                "evidence": [
                    certora.evidence[0].model_copy(update={"property_id": "prop-" + ("2" * 24)})
                ],
                "execution_observation_sha256": None,
            }
        )
        runtime.formal_runs[certora_index] = certora.model_copy(
            update={"execution_observation_sha256": certora.expected_execution_observation_sha256()}
        )
    elif case == "missing_offline_replay":
        runtime = replace(runtime, offline_replay=None)
    elif case == "mock_offline_replay":
        runtime = replace(
            runtime,
            offline_replay=_real_offline_replay(execution_evidence=ExecutionEvidenceKind.MOCK),
        )
    elif case == "wrong_replay_run":
        runtime = replace(runtime, replay_run_id="another-run")
    elif case == "wrong_replay_manifest":
        runtime = replace(runtime, replay_manifest_sha256="3" * 64)
    elif case == "wrong_replay_verification":
        runtime = replace(runtime, replay_verification_sha256="4" * 64)
    elif case == "scanner_only_replay":
        runtime = replace(
            runtime,
            offline_replay=_real_offline_replay(kinds={ReplayComponentKind.SCANNER}),
        )
    elif case in {"missing_replay_member", "missing_replay_attestation"}:
        replay = runtime.offline_replay
        assert replay is not None
        components = list(replay.components)
        if case == "missing_replay_member":
            components = [
                component for component in components if component.identifier != "slither"
            ]
        else:
            components[0] = components[0].model_copy(update={"isolation_attestation_sha256": None})
        payload = replay.model_dump(mode="json", exclude={"replay_sha256"})
        payload["components"] = [component.model_dump(mode="json") for component in components]
        payload["replay_sha256"] = canonical_sha256(payload)
        runtime = replace(runtime, offline_replay=OfflineReplay.model_validate(payload))
    elif case == "missing_model_usage":
        runtime = replace(runtime, model_usage=[])
    elif case == "mock_model_usage":
        runtime = replace(
            runtime,
            model_usage=[
                record.model_copy(update={"execution_evidence": ExecutionEvidenceKind.MOCK})
                for record in runtime.model_usage
            ],
        )
    elif case == "non_certification_model_usage":
        runtime = replace(
            runtime,
            model_usage=[
                record.model_copy(
                    update={
                        "routing": {
                            **record.routing,
                            "certification_request": False,
                        }
                    }
                )
                for record in runtime.model_usage
            ],
        )
    elif case == "unconfigured_model_usage":
        runtime = replace(
            runtime,
            model_usage=[
                record.model_copy(
                    update={
                        "requested_model": "unregistered/unqualified",
                        "returned_model": "unregistered/unqualified",
                    }
                )
                for record in runtime.model_usage
            ],
        )
    elif case == "missing_benchmark":
        runtime = replace(runtime, benchmark_verification=None)
    elif case == "in_memory_benchmark":
        runtime = replace(
            runtime,
            benchmark_verification=_in_memory_benchmark_verification(),
        )
    elif case == "standard_benchmark":
        runtime = replace(
            runtime,
            benchmark_verification=_current_benchmark_verification(
                profile=AuditProfile.STANDARD,
            ),
        )
    elif case == "wrong_benchmark_commit":
        runtime = replace(runtime, benchmark_repository_git_commit="c" * 40)
    else:  # pragma: no cover - guarded by the parameter table
        raise AssertionError(f"unknown assurance portfolio case: {case}")

    assessment = MaximumAssuranceContract(config).evaluate(runtime)
    clause = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == failed_clause
    )

    assert assessment.status is not MaximumAssuranceStatus.COMPLETE
    assert not clause.passed
    assert clause.blocking


@pytest.mark.parametrize("tool", ["echidna", "medusa", "halmos"])
@pytest.mark.parametrize(
    "status",
    [
        FormalToolStatus.UNAVAILABLE,
        FormalToolStatus.SKIPPED,
        FormalToolStatus.FAILED,
        FormalToolStatus.TIMED_OUT,
        FormalToolStatus.INCONCLUSIVE,
    ],
)
def test_non_successful_property_engine_records_never_satisfy_portfolio(
    config_factory,
    tool: str,
    status: FormalToolStatus,
) -> None:
    runtime = _complete_runtime()
    runtime = replace(
        runtime,
        formal_runs=[
            run.model_copy(update={"status": status}) if run.tool == tool else run
            for run in runtime.formal_runs
        ],
    )

    assessment = MaximumAssuranceContract(_maximum_config(config_factory)).evaluate(runtime)
    clause = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == f"required_formal_tool:{tool}"
    )

    assert assessment.status is not MaximumAssuranceStatus.COMPLETE
    assert not clause.passed
    assert clause.blocking


@pytest.mark.parametrize(
    "status",
    [
        ScannerStatus.UNAVAILABLE,
        ScannerStatus.SKIPPED,
        ScannerStatus.FAILED,
        ScannerStatus.TIMED_OUT,
    ],
)
def test_non_successful_foundry_portfolio_never_satisfies_maximum_assurance(
    config_factory,
    status: ScannerStatus,
) -> None:
    runtime = _complete_runtime()
    foundry = next(run for run in runtime.scanners if run.scanner == "foundry_fork")
    runtime.scanners[runtime.scanners.index(foundry)] = foundry.model_copy(
        update={"status": status}
    )

    assessment = MaximumAssuranceContract(_maximum_config(config_factory)).evaluate(runtime)
    clause = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "foundry_unit_property_invariant_execution"
    )

    assert assessment.status is not MaximumAssuranceStatus.COMPLETE
    assert not clause.passed
    assert clause.blocking


@pytest.mark.parametrize(
    "case",
    [
        pytest.param("static_source", id="static_source_inventory_is_not_compiler_evidence"),
        pytest.param("missing_post", id="missing_post_execution_inventory"),
        pytest.param("drifted_post", id="post_execution_build_info_drift"),
    ],
)
def test_real_foundry_qualification_requires_stable_compiler_inventory(
    config_factory,
    case: str,
) -> None:
    config = _maximum_config(config_factory)
    foundry = _real_foundry_scanner(datetime.now(UTC), config)
    assert is_qualifying_real_foundry_portfolio(
        foundry,
        config,
        expected_repository_sha256="9" * 64,
    )

    if case == "static_source":
        changed = _static_source_foundry_scanner(foundry)
    elif case == "missing_post":
        changed = foundry.model_copy(
            update={
                "repository_suite_post_inventory": None,
                "execution_observation_sha256": None,
            }
        )
        changed = changed.model_copy(
            update={"execution_observation_sha256": changed.expected_execution_observation_sha256()}
        )
    else:
        changed = _foundry_scanner_with_post_build_info_drift(foundry)

    assert not is_qualifying_real_foundry_portfolio(
        changed,
        config,
        expected_repository_sha256="9" * 64,
    )


def test_real_foundry_qualification_accepts_exact_pre_scope_legacy_digest(
    config_factory,
) -> None:
    config = _maximum_config(config_factory)
    current = _real_foundry_scanner(datetime.now(UTC), config)
    payload = current.model_dump(mode="json")
    payload.pop("repository_test_fork_rpc_scopes", None)
    payload["execution_observation_sha256"] = current.expected_legacy_execution_observation_sha256()

    legacy = ScannerRun.model_validate_json(json.dumps(payload, sort_keys=True))

    assert legacy.execution_observation_sha256_is_valid()
    assert is_qualifying_real_scanner_run(legacy)
    assert is_qualifying_real_foundry_portfolio(
        legacy,
        config,
        expected_repository_sha256="9" * 64,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("repository_sha256", "1" * 64, id="repository"),
        pytest.param("configuration_sha256", "2" * 64, id="configuration"),
        pytest.param("tool_version", "forge 9.9.9", id="tool_version"),
        pytest.param("tool_sha256", "3" * 64, id="tool_hash"),
        pytest.param("compiler_version", "solc 9.9.9", id="compiler_version"),
        pytest.param("compiler_sha256", "4" * 64, id="compiler_hash"),
        pytest.param("isolation_backend", "bubblewrap", id="isolation_backend"),
        pytest.param(
            "isolation_attestation_sha256",
            "6" * 64,
            id="isolation_attestation",
        ),
    ],
)
def test_real_foundry_qualification_revalidates_inventory_identity_bindings(
    config_factory,
    field: str,
    value: object,
) -> None:
    config = _maximum_config(config_factory)
    foundry = _real_foundry_scanner(datetime.now(UTC), config)
    inventory = foundry.repository_suite_inventory
    post_inventory = foundry.repository_suite_post_inventory
    assert inventory is not None
    assert post_inventory is not None
    assert is_qualifying_real_foundry_portfolio(
        foundry,
        config,
        expected_repository_sha256="9" * 64,
    )

    changed = _reseal_scanner_observation(
        foundry,
        repository_suite_inventory=_reseal_foundry_inventory(
            inventory,
            **{field: value},
        ),
        repository_suite_post_inventory=_reseal_foundry_inventory(
            post_inventory,
            **{field: value},
        ),
    )

    assert not is_qualifying_real_foundry_portfolio(
        changed,
        config,
        expected_repository_sha256="9" * 64,
    )


def test_real_foundry_qualification_resolves_each_execution_inventory_record(
    config_factory,
) -> None:
    config = _maximum_config(config_factory)
    foundry = _real_foundry_scanner(datetime.now(UTC), config)
    executions = list(foundry.repository_test_executions)
    first = executions[0]
    executions[0] = RepositoryTestExecution.sealed(
        **first.model_dump(
            mode="python",
            exclude={"execution_sha256", "inventory_record_sha256"},
        ),
        inventory_record_sha256="e" * 64,
    )
    changed = _reseal_scanner_observation(
        foundry,
        repository_test_executions=executions,
    )
    assert changed.execution_observation_sha256 == (changed.expected_execution_observation_sha256())

    assert not is_qualifying_real_foundry_portfolio(
        changed,
        config,
        expected_repository_sha256="9" * 64,
    )


def test_real_foundry_qualification_requires_current_repository_identity(
    config_factory,
) -> None:
    config = _maximum_config(config_factory)
    foundry = _real_foundry_scanner(datetime.now(UTC), config)

    assert not is_qualifying_real_foundry_portfolio(
        foundry,
        config,
        expected_repository_sha256="1" * 64,
    )


def test_real_foundry_qualification_requires_the_configured_tool_pin(
    config_factory,
) -> None:
    config = _maximum_config(config_factory)
    foundry = _real_foundry_scanner(datetime.now(UTC), config)
    changed_config = config.model_copy(
        update={
            "scanners": config.scanners.model_copy(
                update={
                    "foundry_fork": config.scanners.foundry_fork.model_copy(
                        update={"version": "9.9.9"}
                    )
                }
            )
        }
    )

    assert not is_qualifying_real_foundry_portfolio(
        foundry,
        changed_config,
        expected_repository_sha256="9" * 64,
    )


def test_real_foundry_qualification_binds_selection_profile_to_configuration(
    config_factory,
) -> None:
    config = _maximum_config(config_factory)
    foundry = _real_foundry_scanner(datetime.now(UTC), config)
    selection = foundry.repository_suite_selection
    execution_policy = foundry.repository_suite_execution_policy
    assert selection is not None
    assert execution_policy is not None
    selection_payload = selection.model_dump(
        mode="python",
        exclude={"selection_sha256", "profile"},
    )
    selection_payload["tests"] = selection.tests
    changed_selection = RepositorySuiteSelection.sealed(
        **selection_payload,
        profile="explicit",
    )
    policy_payload = execution_policy.model_dump(
        mode="python",
        exclude={"policy_sha256", "selection_sha256"},
    )
    changed_policy = RepositorySuiteExecutionPolicy.sealed(
        **policy_payload,
        selection_sha256=changed_selection.selection_sha256,
    )
    changed_executions = [
        RepositoryTestExecution.sealed(
            **execution.model_dump(
                mode="python",
                exclude={
                    "execution_sha256",
                    "selection_sha256",
                    "execution_policy_sha256",
                },
            ),
            selection_sha256=changed_selection.selection_sha256,
            execution_policy_sha256=changed_policy.policy_sha256,
        )
        for execution in foundry.repository_test_executions
    ]
    changed = _reseal_scanner_observation(
        foundry,
        repository_suite_selection=changed_selection,
        repository_suite_execution_policy=changed_policy,
        repository_test_executions=changed_executions,
    )
    ScannerRun.model_validate(changed.model_dump(mode="json"))

    assert not is_qualifying_real_foundry_portfolio(
        changed,
        config,
        expected_repository_sha256="9" * 64,
    )


@pytest.mark.parametrize(
    ("kind", "field"),
    [
        pytest.param(RepositoryTestKind.FUZZ, "fuzz_cases", id="fuzz"),
        pytest.param(RepositoryTestKind.INVARIANT, "invariant_runs", id="invariant"),
    ],
)
def test_real_foundry_qualification_requires_configured_campaign_strength(
    config_factory,
    kind: RepositoryTestKind,
    field: str,
) -> None:
    config = _maximum_config(config_factory)
    foundry = _real_foundry_scanner(datetime.now(UTC), config)
    executions = list(foundry.repository_test_executions)
    index = next(index for index, execution in enumerate(executions) if execution.test_kind is kind)
    execution = executions[index]
    executions[index] = RepositoryTestExecution.sealed(
        **execution.model_dump(
            mode="python",
            exclude={"execution_sha256", field},
        ),
        **{field: 1},
    )
    summary = foundry.foundry_summary
    assert summary is not None
    changed = _reseal_scanner_observation(
        foundry,
        foundry_summary=summary.model_copy(update={field: 1}),
        repository_test_executions=executions,
    )

    assert not is_qualifying_real_foundry_portfolio(
        changed,
        config,
        expected_repository_sha256="9" * 64,
    )


@pytest.mark.parametrize("scope", ["suite", "test"])
def test_real_foundry_qualification_rejects_execution_past_declared_deadline(
    config_factory,
    scope: str,
) -> None:
    config = _maximum_config(config_factory)
    foundry = _real_foundry_scanner(datetime.now(UTC), config)
    policy = foundry.repository_suite_execution_policy
    assert policy is not None
    if scope == "suite":
        changed = _reseal_scanner_observation(
            foundry,
            duration_seconds=policy.total_timeout_seconds + 0.001,
        )
    else:
        executions = list(foundry.repository_test_executions)
        first = executions[0]
        executions[0] = RepositoryTestExecution.sealed(
            **first.model_dump(
                mode="python",
                exclude={"execution_sha256", "duration_seconds"},
            ),
            duration_seconds=policy.per_test_timeout_seconds + 0.001,
        )
        changed = _reseal_scanner_observation(
            foundry,
            repository_test_executions=executions,
        )

    assert not is_qualifying_real_foundry_portfolio(
        changed,
        config,
        expected_repository_sha256="9" * 64,
    )


@pytest.mark.parametrize(
    ("mutation", "failed_clause"),
    [
        pytest.param(
            "property_empty_evidence",
            "required_formal_tool:echidna",
        ),
        pytest.param(
            "property_empty_output",
            "required_formal_tool:echidna",
        ),
        pytest.param(
            "property_unisolated",
            "required_formal_tool:echidna",
        ),
        pytest.param(
            "invariant_zero_attempts",
            "stateful_invariant_execution",
        ),
        pytest.param(
            "invariant_mock",
            "stateful_invariant_execution",
        ),
        pytest.param(
            "invariant_unisolated",
            "stateful_invariant_execution",
        ),
    ],
)
def test_empty_mock_or_unisolated_dynamic_evidence_fails_closed(
    config_factory,
    mutation: str,
    failed_clause: str,
) -> None:
    runtime = _complete_runtime()
    if mutation.startswith("property_"):
        echidna = next(run for run in runtime.formal_runs if run.tool == "echidna")
        if mutation == "property_empty_evidence":
            changed = echidna.model_copy(update={"evidence": []})
        elif mutation == "property_empty_output":
            changed = echidna.model_copy(
                update={
                    "stdout_bytes": 0,
                    "stderr_bytes": 0,
                    "result_bytes": 0,
                }
            )
        else:
            changed = _real_formal_run(
                "echidna",
                isolation_backend="unisolated",
            )
        runtime = replace(
            runtime,
            formal_runs=[changed if run.tool == "echidna" else run for run in runtime.formal_runs],
        )
    else:
        invariant = runtime.invariant_executions[0]
        if mutation == "invariant_zero_attempts":
            changed_invariant = InvariantExecutionResult(
                invariant_id=invariant.invariant_id,
                harness_name=invariant.harness_name,
                status=InvariantExecutionStatus.PASSED,
            )
        elif mutation == "invariant_mock":
            changed_invariant = invariant.model_copy(
                update={"execution_evidence": ExecutionEvidenceKind.MOCK}
            )
        else:
            changed_invariant = invariant.model_copy(update={"isolation_backend": "unisolated"})
        runtime = replace(runtime, invariant_executions=[changed_invariant])

    assessment = MaximumAssuranceContract(_maximum_config(config_factory)).evaluate(runtime)
    clause = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == failed_clause
    )

    assert assessment.status is not MaximumAssuranceStatus.COMPLETE
    assert not clause.passed
    assert clause.blocking


@pytest.mark.parametrize(
    ("status", "expected_state", "expected_assessment"),
    [
        pytest.param(
            CompilationStatus.FAILED,
            AnalysisState.ATTEMPTED_FAILED,
            MaximumAssuranceStatus.INCONCLUSIVE,
            id="compilation_failed",
        ),
        pytest.param(
            CompilationStatus.TIMED_OUT,
            AnalysisState.ATTEMPTED_FAILED,
            MaximumAssuranceStatus.INCONCLUSIVE,
            id="compilation_timed_out",
        ),
        pytest.param(
            CompilationStatus.SKIPPED,
            AnalysisState.NOT_ANALYZED,
            MaximumAssuranceStatus.FAILED,
            id="compilation_skipped",
        ),
        pytest.param(
            CompilationStatus.UNAVAILABLE,
            AnalysisState.NOT_ANALYZED,
            MaximumAssuranceStatus.FAILED,
            id="compilation_unavailable",
        ),
    ],
)
def test_non_successful_compilation_never_satisfies_maximum_assurance(
    config_factory,
    status: CompilationStatus,
    expected_state: AnalysisState,
    expected_assessment: MaximumAssuranceStatus,
) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    runtime.compilations[0] = runtime.compilations[0].model_copy(
        update={
            "status": status,
            "ast_available": False,
            "contracts_compiled": [],
        }
    )

    assessment = MaximumAssuranceContract(config).evaluate(runtime)
    gate = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "compilation"
    )

    assert assessment.status is expected_assessment
    assert not gate.passed
    assert gate.blocking
    assert gate.state is expected_state
    assert status.value in gate.detail


@pytest.mark.parametrize(
    ("updates", "expected_detail"),
    [
        pytest.param(
            {"ast_available": False},
            "compiler AST unavailable",
            id="successful_status_without_ast",
        ),
        pytest.param(
            {"contracts_compiled": []},
            "no compiled contracts",
            id="successful_status_without_compiled_contracts",
        ),
    ],
)
def test_success_status_without_compiler_evidence_fails_compilation_clause(
    config_factory,
    updates: dict[str, object],
    expected_detail: str,
) -> None:
    runtime = _complete_runtime()
    runtime.compilations[0] = runtime.compilations[0].model_copy(update=updates)

    assessment = MaximumAssuranceContract(_maximum_config(config_factory)).evaluate(runtime)
    gate = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "compilation"
    )

    assert assessment.status is MaximumAssuranceStatus.INCONCLUSIVE
    assert not gate.passed
    assert gate.state is AnalysisState.ATTEMPTED_FAILED
    assert expected_detail in gate.detail


def test_partial_multi_project_compilation_fails_closed(config_factory) -> None:
    runtime = _complete_runtime()
    runtime.projects.append(
        SolidityProjectMetadata(
            project_type=SolidityProjectType.HARDHAT,
            project_root="packages/secondary",
            source_directories=["contracts"],
        )
    )

    assessment = MaximumAssuranceContract(_maximum_config(config_factory)).evaluate(runtime)
    gate = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "compilation"
    )

    assert assessment.status is MaximumAssuranceStatus.INCONCLUSIVE
    assert not gate.passed
    assert "packages/secondary (hardhat)" in gate.detail


def test_fallback_parser_only_index_never_satisfies_ast_clause(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    assert runtime.index is not None
    runtime = replace(
        runtime,
        index=runtime.index.model_copy(
            update={
                "ast_sources": [],
                "fallback_sources": ["src/Vault.sol"],
            }
        ),
    )

    assessment = MaximumAssuranceContract(config).evaluate(runtime)
    gate = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "ast_backed_index"
    )

    assert assessment.status is MaximumAssuranceStatus.FAILED
    assert not gate.passed
    assert gate.state is AnalysisState.FALLBACK_PARSER
    assert "fallback-parsed sources" in gate.detail


def test_benchmark_gate_requires_current_typed_verification_and_artifact(
    config_factory,
) -> None:
    config = config_factory(
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        maximum_assurance={"benchmark_gate": True},
        models={"specialists": _specialists()},
    ).effective()
    contract = MaximumAssuranceContract(config)
    base_runtime = _complete_runtime()
    absent = contract.evaluate(
        replace(
            base_runtime,
            benchmark_verification=None,
            artifacts=base_runtime.artifacts - {"benchmark-certificate-verification.json"},
        )
    )
    absent_gate = next(
        requirement
        for requirement in absent.requirements
        if requirement.engine == "benchmark_regression_gate"
    )
    current = contract.evaluate(
        replace(
            base_runtime,
            benchmark_verification=_current_benchmark_verification(),
            artifacts={
                *base_runtime.artifacts,
                "benchmark-certificate-verification.json",
            },
        )
    )
    current_gate = next(
        requirement
        for requirement in current.requirements
        if requirement.engine == "benchmark_regression_gate"
    )

    assert absent_gate.required
    assert not absent_gate.passed
    assert absent_gate.state is AnalysisState.NOT_ANALYZED
    assert current_gate.passed
    assert current_gate.state is AnalysisState.DETERMINISTIC
    assert current_gate.artifacts == ["benchmark-certificate-verification.json"]


def test_missing_traceability_fails_without_downgrade(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = replace(_complete_runtime(config), traceability=None)
    assessment = MaximumAssuranceContract(config).evaluate(runtime)
    gate = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "requirements_traceability"
    )
    assert assessment.status is MaximumAssuranceStatus.FAILED
    assert not gate.passed


def test_missing_full_protocol_scope_blocks_maximum_assurance(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    assessment = MaximumAssuranceContract(config).evaluate(
        replace(
            runtime,
            scope_assessment=None,
            artifacts=runtime.artifacts - {"scope-assessment.json"},
        )
    )
    gate = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "full_protocol_scope"
    )
    assert assessment.status is MaximumAssuranceStatus.FAILED
    assert not gate.passed
    assert gate.artifacts == []


def test_incomplete_required_traceability_is_failed_or_explicitly_downgraded(
    config_factory,
) -> None:
    for status in (
        ImplementationStatus.PARTIALLY_IMPLEMENTED,
        ImplementationStatus.UNAVAILABLE,
        ImplementationStatus.UNIMPLEMENTED,
    ):
        traceability = MaximumAssuranceTraceability(
            last_verified_commit="synthetic-test",
            requirements=[
                TraceabilityRequirement(
                    requirement_id="MA-SYNTHETIC-GAP",
                    description="Synthetic blocking dependency.",
                    implementation_status=status,
                    required_for_complete=True,
                    downgrade_reason="synthetic capability is incomplete",
                    last_verified_commit="synthetic-test",
                )
            ],
        )
        failed_config = _maximum_config(config_factory)
        failed_runtime = replace(
            _complete_runtime(failed_config),
            traceability=traceability,
        )
        failed = MaximumAssuranceContract(failed_config).evaluate(failed_runtime)
        assert failed.status is MaximumAssuranceStatus.FAILED
        gap = next(
            requirement
            for requirement in failed.requirements
            if requirement.engine == "traceability:ma-synthetic-gap"
        )
        assert not gap.passed
        assert status.value in gap.detail

        downgraded_config = _maximum_config(config_factory, allow_downgrade=True)
        downgraded_runtime = replace(
            _complete_runtime(downgraded_config),
            traceability=traceability,
        )
        downgraded = MaximumAssuranceContract(downgraded_config).evaluate(downgraded_runtime)
        assert downgraded.status is MaximumAssuranceStatus.DOWNGRADED
        assert downgraded.downgraded
        assert any(status.value in reason for reason in downgraded.downgrade_reasons)


def test_incomplete_nonblocking_traceability_does_not_block(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = replace(
        _complete_runtime(config),
        traceability=MaximumAssuranceTraceability(
            last_verified_commit="synthetic-test",
            requirements=[
                TraceabilityRequirement(
                    requirement_id="MA-SYNTHETIC-OPTIONAL",
                    description="Synthetic nonblocking evaluation.",
                    implementation_status=ImplementationStatus.UNAVAILABLE,
                    required_for_complete=False,
                    downgrade_reason="independent evaluation has not been run",
                    last_verified_commit="synthetic-test",
                )
            ],
        ),
    )
    assessment = MaximumAssuranceContract(config).evaluate(runtime)
    assert assessment.status is MaximumAssuranceStatus.COMPLETE
    assert not any(
        requirement.engine == "traceability:ma-synthetic-optional"
        for requirement in assessment.requirements
    )


def test_current_required_traceability_gaps_all_block_complete(config_factory) -> None:
    config = _maximum_config(config_factory)
    matrix = build_traceability_matrix("synthetic-test")
    runtime = replace(_complete_runtime(config), traceability=matrix)
    assessment = MaximumAssuranceContract(config).evaluate(runtime)
    expected = {
        f"traceability:{item.requirement_id.lower()}"
        for item in matrix.requirements
        if item.required_for_complete
        and item.implementation_status is not ImplementationStatus.IMPLEMENTED
    }
    failed = {
        requirement.engine
        for requirement in assessment.requirements
        if requirement.required and not requirement.passed
    }
    assert assessment.status is MaximumAssuranceStatus.FAILED
    assert expected
    assert expected <= failed


def test_maximum_assurance_reports_untyped_economic_templates(config_factory) -> None:
    config = _maximum_config(config_factory)
    runtime = _complete_runtime(config)
    runtime.economic_simulations.append(
        EconomicSimulationPlan(
            kind=EconomicSimulationKind.FLASH_ORACLE,
            applicable=True,
            rationale="synthetic unimplemented template",
            execution_required=True,
            typed_harness_available=False,
        )
    )

    assessment = MaximumAssuranceContract(config).evaluate(runtime)

    assert assessment.status is MaximumAssuranceStatus.FAILED
    economic = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "protocol_economic_simulation"
    )
    assert not economic.passed
    assert "lack deterministic typed harness support" in economic.detail


def test_maximum_assurance_preflight_requires_isolation(config_factory) -> None:
    config = _maximum_config(config_factory)
    requirements = MaximumAssuranceContract(config).configuration_requirements(
        isolation_available=False,
        scanner_only=False,
    )
    isolation = next(
        requirement
        for requirement in requirements
        if requirement.engine == "hardened_dynamic_isolation"
    )
    assert isolation.required
    assert not isolation.passed
    assert isolation.blocking


def test_maximum_assurance_requires_every_narrow_specialist(config_factory) -> None:
    specialists = _specialists()
    specialists.pop("precision_rounding")
    config = config_factory(
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        models={"specialists": specialists},
    ).effective()
    requirements = MaximumAssuranceContract(config).configuration_requirements(
        isolation_available=True,
        scanner_only=False,
    )
    coverage = next(
        requirement
        for requirement in requirements
        if requirement.engine == "specialist_role_coverage"
    )
    assert not coverage.passed
    assert "precision_rounding" in coverage.detail
    assert len(SPECIALIST_INVESTIGATOR_ROLES) >= 20
    assert set(SPECIALIST_ROLE_REGISTRY) == set(ALL_SPECIALIST_ROLES)
    assert len({definition.mission for definition in SPECIALIST_ROLE_REGISTRY.values()}) == len(
        SPECIALIST_ROLE_REGISTRY
    )
    assert len(
        {definition.effective_schema_name() for definition in SPECIALIST_ROLE_REGISTRY.values()}
    ) == len(SPECIALIST_ROLE_REGISTRY)
    assert all(
        definition.required_checks and definition.context_priorities
        for definition in SPECIALIST_ROLE_REGISTRY.values()
    )


def test_critical_reproduction_impossibility_requires_a_reason(config_factory) -> None:
    config = _maximum_config(config_factory)
    contract = MaximumAssuranceContract(config)
    unexplained = contract.evaluate(
        AssuranceRuntime(
            eligible_high_critical_ids={"critical-1"},
            feasible_high_critical_ids=set(),
            documented_infeasible_ids=set(),
            isolation_available=True,
        )
    )
    gate = next(
        requirement
        for requirement in unexplained.requirements
        if requirement.engine == "critical_high_reproduction"
    )
    assert not gate.passed
    assert "lacked a reason" in gate.detail

    explained = contract.evaluate(
        AssuranceRuntime(
            eligible_high_critical_ids={"critical-1"},
            feasible_high_critical_ids=set(),
            documented_infeasible_ids={"critical-1"},
            isolation_available=True,
        )
    )
    explained_gate = next(
        requirement
        for requirement in explained.requirements
        if requirement.engine == "critical_high_reproduction"
    )
    assert explained_gate.passed


@pytest.mark.parametrize("include_inconclusive_resolution", [False, True])
def test_failed_reproduction_attempt_never_satisfies_maximum_assurance(
    config_factory,
    include_inconclusive_resolution: bool,
) -> None:
    candidate_id = "critical-failed-reproduction"
    runtime = replace(
        _complete_runtime(),
        eligible_high_critical_ids={candidate_id},
        feasible_high_critical_ids={candidate_id},
        reproduction_results=[
            ReproductionResult(
                candidate_id=candidate_id,
                test_name="test_failed_reproduction",
                state=ReproductionState.NOT_REPRODUCED,
                specification_sha256="a" * 64,
                attempts=1,
                successful_attempts=0,
            )
        ],
        reproduction_resolutions=(
            [
                CandidateReproductionResolution(
                    candidate_id=candidate_id,
                    kind=ReproductionResolutionKind.INCONCLUSIVE,
                    detail="attempt completed without a qualifying terminal outcome",
                )
            ]
            if include_inconclusive_resolution
            else []
        ),
    )

    assessment = MaximumAssuranceContract(_maximum_config(config_factory)).evaluate(runtime)
    gate = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "critical_high_reproduction"
    )

    assert assessment.status is MaximumAssuranceStatus.INCONCLUSIVE
    assert not gate.passed
    assert gate.state is AnalysisState.ATTEMPTED_FAILED
    assert "remain unresolved" in gate.detail


def test_integrity_bound_reproduction_resolution_satisfies_candidate_clause(
    config_factory,
) -> None:
    candidate_id = "critical-resolved"
    integrity = _verified_reproduction_integrity()
    runtime = replace(
        _complete_runtime(),
        eligible_high_critical_ids={candidate_id},
        feasible_high_critical_ids={candidate_id},
        reproduction_results=[
            ReproductionResult(
                candidate_id=candidate_id,
                test_name="test_resolved_reproduction",
                state=ReproductionState.REPRODUCED,
                specification_sha256="a" * 64,
                attempts=1,
                successful_attempts=1,
                integrity=integrity,
            )
        ],
        reproduction_resolutions=[
            CandidateReproductionResolution(
                candidate_id=candidate_id,
                kind=ReproductionResolutionKind.REPRODUCED,
                evidence_refs=[f"reproduction:{integrity.integrity_sha256}"],
                detail="synthetic integrity-bound qualifying resolution",
            )
        ],
        falsifier_completed=True,
    )

    assessment = MaximumAssuranceContract(_maximum_config(config_factory)).evaluate(runtime)
    gate = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "critical_high_reproduction"
    )

    assert gate.passed
    assert gate.state is AnalysisState.REPRODUCED


def test_unbound_reproduced_resolution_fails_closed(config_factory) -> None:
    candidate_id = "critical-unbound-resolution"
    runtime = replace(
        _complete_runtime(),
        eligible_high_critical_ids={candidate_id},
        feasible_high_critical_ids={candidate_id},
        reproduction_results=[],
        reproduction_resolutions=[
            CandidateReproductionResolution(
                candidate_id=candidate_id,
                kind=ReproductionResolutionKind.REPRODUCED,
                evidence_refs=["reproduction:" + ("a" * 64)],
                detail="synthetic stale derived resolution",
            )
        ],
    )

    assessment = MaximumAssuranceContract(_maximum_config(config_factory)).evaluate(runtime)
    gate = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "critical_high_reproduction"
    )

    assert assessment.status is MaximumAssuranceStatus.INCONCLUSIVE
    assert not gate.passed
    assert "not bound to qualifying raw runtime evidence" in gate.detail


def test_duplicate_candidate_resolutions_fail_closed(config_factory) -> None:
    candidate_id = "critical-duplicate-resolution"
    resolution = CandidateReproductionResolution(
        candidate_id=candidate_id,
        kind=ReproductionResolutionKind.REPRODUCED,
        evidence_refs=["runtime-evidence:" + ("a" * 64)],
        detail="synthetic duplicated resolution",
    )
    runtime = replace(
        _complete_runtime(),
        eligible_high_critical_ids={candidate_id},
        feasible_high_critical_ids={candidate_id},
        reproduction_resolutions=[resolution, resolution],
    )

    assessment = MaximumAssuranceContract(_maximum_config(config_factory)).evaluate(runtime)
    gate = next(
        requirement
        for requirement in assessment.requirements
        if requirement.engine == "critical_high_reproduction"
    )

    assert not gate.passed
    assert "ambiguous resolutions" in gate.detail


def test_high_critical_cross_examination_requires_two_lineages(config_factory) -> None:
    config = _maximum_config(config_factory)
    contract = MaximumAssuranceContract(config)
    complete_runtime = _complete_runtime(config)
    qualification = complete_runtime.production_qualification
    assert qualification is not None
    candidate_id = "candidate-critical"
    falsifier_request_ids = complete_runtime.candidate_falsifier_request_ids[candidate_id]
    assert len(falsifier_request_ids) == 2
    falsifier_usage = [
        record
        for record in complete_runtime.model_usage
        if record.request_id in falsifier_request_ids
    ]
    assert len(falsifier_usage) == 2
    assert (
        len(
            {
                qualification.model_for(
                    record.requested_model,
                    now=qualification.verified_at,
                ).root_lineage
                for record in falsifier_usage
            }
        )
        == 2
    )
    one_lineage = contract.evaluate(
        replace(
            complete_runtime,
            eligible_high_critical_ids={candidate_id},
            falsifier_completed=True,
            candidate_falsifier_request_ids={
                candidate_id: {falsifier_usage[0].request_id},
            },
        )
    )
    one_lineage_gate = next(
        requirement
        for requirement in one_lineage.requirements
        if requirement.engine == "independent_falsifier"
    )
    assert not one_lineage_gate.passed

    two_lineages = contract.evaluate(complete_runtime)
    two_lineage_gate = next(
        requirement
        for requirement in two_lineages.requirements
        if requirement.engine == "independent_falsifier"
    )
    assert two_lineage_gate.passed


def test_candidate_falsifier_requests_cannot_be_reused_across_candidates(
    config_factory,
) -> None:
    config = _maximum_config(config_factory)
    contract = MaximumAssuranceContract(config)
    lineage_by_model = model_lineage_index(config)
    complete_runtime = _complete_runtime(config)
    qualification = complete_runtime.production_qualification
    assert qualification is not None
    template = complete_runtime.model_usage[0]
    falsifier_models = [
        config.models.verifier.primary,
        config.models.judge.primary,
    ]
    falsifier_usage: list[UsageRecord] = []
    for reviewer_index, model_id in enumerate(falsifier_models, start=1):
        generation_id = f"generation-per-candidate-{reviewer_index}"
        usage = template.model_copy(
            update={
                "request_id": f"request-per-candidate-{reviewer_index}",
                "role": candidate_falsifier_role(
                    "critical-1",
                    reviewer_index,
                ),
                "requested_model": model_id,
                "returned_model": model_id,
                "actual_model": model_id,
                "model_family": model_id,
                "openrouter_generation_id": generation_id,
                "routing": {
                    **template.routing,
                    "generation_id": generation_id,
                    "selected_model": model_id,
                    "canonical_model": model_id,
                    "catalog_identity_binding_sha256": canonical_sha256(
                        {
                            "canonical_slug": model_id,
                            "id": model_id,
                        }
                    ),
                },
            }
        )
        falsifier_usage.append(
            _bind_usage_to_qualification(
                usage,
                qualification,
                qualification.verified_at,
            )
        )
    assert (
        len({lineage_by_model[model_id.lower()].root_lineage for model_id in falsifier_models}) == 2
    )
    assessment = contract.evaluate(
        replace(
            complete_runtime,
            eligible_high_critical_ids={"critical-1", "critical-2"},
            falsifier_completed=True,
            candidate_falsifier_request_ids={
                candidate_id: {record.request_id for record in falsifier_usage}
                for candidate_id in ("critical-1", "critical-2")
            },
            model_usage=[*complete_runtime.model_usage, *falsifier_usage],
        )
    )
    clauses = {requirement.engine: requirement for requirement in assessment.requirements}

    assert not clauses["independent_falsifier"].passed
    assert not clauses["certified_model_ensemble"].passed
    assert "minimum 0 independent" in clauses["independent_falsifier"].detail
    assert assessment.status is not MaximumAssuranceStatus.COMPLETE


def test_downgrade_is_visible_in_markdown_json_and_sarif(config_factory) -> None:
    config = _maximum_config(config_factory, allow_downgrade=True)
    assessment = MaximumAssuranceContract(config).evaluate(
        AssuranceRuntime(isolation_available=False, scanner_only=True)
    )
    assert assessment.status is MaximumAssuranceStatus.DOWNGRADED
    report = AuditReport(
        schema_version="1.0",
        run_id="assurance-test",
        generated_at=datetime.now(UTC),
        completed=True,
        incomplete_reasons=[],
        repository=RepositoryMap(
            root_name="synthetic",
            languages={"Solidity": 1},
            frameworks=["Foundry"],
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
        configuration_hash="a" * 64,
        model_configuration_hash="b" * 64,
        privacy={"code_egress_enabled": False},
        scanner_runs=[],
        usage=[],
        budget_usd=1,
        accounted_cost_usd=0,
        findings=[],
        rejected_findings=[],
        audit_profile=AuditProfile.MAXIMUM_ASSURANCE,
        quality_status=AuditQualityStatus.COMPLETED_WITH_LIMITATIONS,
        maximum_assurance=assessment,
    )
    markdown = render_markdown(report)
    assert "DOWNGRADED" in markdown
    assert "must not be represented as maximum assurance" in markdown
    payload = json.loads(report.model_dump_json())
    assert payload["maximum_assurance"]["status"] == "DOWNGRADED"
    sarif = generate_sarif([], maximum_assurance=assessment)
    run = sarif["runs"][0]
    assert run["properties"]["maximumAssurance"]["status"] == "DOWNGRADED"
    assert run["invocations"][0]["properties"]["downgraded"] is True
