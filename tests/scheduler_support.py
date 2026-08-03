"""Synthetic builders for exact seven-pass scheduler evidence in tests only."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from pydantic import BaseModel

from mmaudit.models.openrouter import strict_json_schema
from mmaudit.models.scheduler import (
    SCHEDULER_ANALYSIS_INPUT_LABELS,
    SCHEDULER_PASS_ORDER,
    SchedulerAnalysisInputDescriptor,
    SchedulerAnalysisInputInventory,
    SchedulerArtifact,
    SchedulerBindings,
    SchedulerCampaignManifest,
    SchedulerCampaignSummary,
    SchedulerCandidateWorkset,
    SchedulerCrossShardIntegrationOutput,
    SchedulerEvidenceCapJudgmentOutput,
    SchedulerFindingReductionCandidate,
    SchedulerFindingReductionGroup,
    SchedulerFindingReductionOutput,
    SchedulerFindingReductionValidation,
    SchedulerJournalEvidence,
    SchedulerPassDependency,
    SchedulerPassKind,
    SchedulerPassPlan,
    SchedulerPassResult,
    SchedulerPrivacyEvidenceCustody,
    SchedulerReportBinding,
    SchedulerReproductionHostOutput,
    SchedulerScope,
    SchedulerShardDescriptor,
    SchedulerShardInventory,
    SchedulerSourceDescriptor,
    SchedulerTaskActivation,
    SchedulerTaskEvent,
    SchedulerTaskEventKind,
    SchedulerTaskKind,
    SchedulerTaskOutput,
    SchedulerTaskPlan,
    SchedulerTaskResult,
    SchedulerTerminalStatus,
    build_scheduler_model_request_evidence,
    scheduler_canonical_sha256,
    scheduler_role_requires_specialist_accepted_outcome,
)
from mmaudit.models.schemas import (
    CandidateCrossExaminationResponse,
    CandidateCrossExaminationResponseDecision,
    CandidateReviewBatch,
    ContextRequestEvidence,
    ExecutionEvidenceKind,
    FalsificationBatch,
    FalsificationDecision,
    FalsificationVerdict,
    FindingStatus,
    GeneratedFoundryTestBatch,
    InvariantReviewBatch,
    JudgeDecision,
    JudgeDecisionBatch,
    Location,
    ModelRequestValidationStatus,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewCitation,
    ModelSurfaceReviewEvidenceObservation,
    ModelSurfaceReviewReachability,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
    ReportQualityReview,
    Severity,
    SpecialistAcceptedOutcome,
    SpecialistAcceptedOutcomeKind,
    ThreatBoundary,
    ThreatModel,
    UsageRecord,
    VerificationBatch,
    VerificationDecision,
    VerificationTest,
    VerificationVerdict,
)
from mmaudit.models.usage import request_token_plan_from_usage
from mmaudit.orchestration.budgets import AtomicRequestLimitReservationEvidence
from tests.identity_fixtures import (
    bind_synthetic_usage_identity,
    reattest_synthetic_real_usage,
)


@dataclass(frozen=True)
class CompleteSchedulerFixture:
    """All private and public evidence for one synthetic COMPLETE campaign."""

    manifest: SchedulerCampaignManifest
    plans: tuple[SchedulerPassPlan, ...]
    activations: tuple[SchedulerTaskActivation, ...]
    outputs: tuple[SchedulerTaskOutput, ...]
    task_results: tuple[SchedulerTaskResult, ...]
    pass_results: tuple[SchedulerPassResult, ...]
    events: tuple[SchedulerTaskEvent, ...]
    summary: SchedulerCampaignSummary
    journal_evidence: SchedulerJournalEvidence
    artifact: SchedulerArtifact
    report_binding: SchedulerReportBinding
    usage_records: tuple[UsageRecord, ...]
    context_request_evidence: tuple[ContextRequestEvidence, ...]
    model_surface_review_requests: tuple[ModelSurfaceReviewRequest, ...]
    model_surface_review_artifacts: tuple[ModelSurfaceReviewArtifact, ...]


@dataclass(frozen=True)
class SchedulerFixtureModelTask:
    """One exact pass-specific model request used by assurance fixtures."""

    task_key: str
    role: str
    requested_model: str
    root_lineage: str
    scope: SchedulerScope
    pass_kind: SchedulerPassKind = SchedulerPassKind.BLIND_SHARD_REVIEW
    candidate_ids: tuple[str, ...] = ()


SchedulerFixtureUsageTransform = Callable[
    [SchedulerTaskPlan, SchedulerTaskActivation, UsageRecord], UsageRecord
]
SchedulerFixtureModelAssignmentResolver = Callable[[SchedulerPassKind, str, str], tuple[str, str]]


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def scheduler_test_analysis_input_inventory(seed: str) -> SchedulerAnalysisInputInventory:
    """Build complete hash-only scheduler input custody for synthetic campaigns."""

    return SchedulerAnalysisInputInventory.build(
        SchedulerAnalysisInputDescriptor.build(
            label=label,
            type_name="SyntheticProjection",
            value={"seed": seed, "label": label},
        )
        for label in SCHEDULER_ANALYSIS_INPUT_LABELS
    )


def scheduler_test_model_fields(seed: str) -> dict[str, str]:
    """Return explicit synthetic system-prompt and normalizer commitments."""

    return {
        "system_prompt_sha256": _sha256(f"{seed}:effective-system-prompt"),
        "normalizer_sha256": _sha256(f"{seed}:normalizer"),
    }


def scheduler_test_response_schema_sha256(
    pass_kind: SchedulerPassKind,
    role: str,
) -> str:
    """Return the exact closed response-schema digest authorized for one scheduler role."""

    response_model: type[BaseModel]
    if pass_kind is SchedulerPassKind.ORIENTATION and role == "threat_model":
        response_model = ThreatModel
    elif pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW or (
        pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION and role == "business_logic"
    ):
        response_model = CandidateReviewBatch
    elif (
        pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
        and role == "specialist:invariant_review"
    ):
        response_model = InvariantReviewBatch
    elif pass_kind is SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION:
        response_model = CandidateCrossExaminationResponse
    elif pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION and role in {
        "verifier",
        "candidate_falsifier",
    }:
        response_model = VerificationBatch
    elif pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION and role in {
        "falsifier",
        "specialist:falsifier",
    }:
        response_model = FalsificationBatch
    elif (
        pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
        and role.startswith("specialist:")
        and role.endswith(":exploit_test")
    ):
        response_model = GeneratedFoundryTestBatch
    elif pass_kind is SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT and role == "judge":
        response_model = JudgeDecisionBatch
    elif (
        pass_kind is SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT
        and role == "specialist:report_quality"
    ):
        response_model = ReportQualityReview
    else:
        raise ValueError(f"synthetic scheduler role lacks a response contract: {role}")
    return scheduler_canonical_sha256(strict_json_schema(response_model))


def scheduler_test_delivered_source_descriptor_sha256s(
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
) -> tuple[str, ...]:
    """Return exact scoped full-source delivery identities for a synthetic task."""

    requires_exact_delivery = task.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW or (
        task.pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
        and task.role == "business_logic"
    )
    if not requires_exact_delivery:
        return ()
    scoped = set(plan.manifest.shard_ids) if not task.scope.shard_ids else set(task.scope.shard_ids)
    return tuple(
        sorted(
            source.source_descriptor_sha256
            for shard in plan.manifest.shard_inventory.shards
            if shard.shard_id in scoped
            for source in shard.sources
        )
    )


def build_scheduler_test_host_payload(
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
    *,
    candidate_ids: Sequence[str] = (),
) -> BaseModel:
    """Return a minimal internally consistent payload for one closed host contract."""

    candidates = tuple(sorted(set(candidate_ids)))
    candidate_hashes = {
        candidate_id: scheduler_canonical_sha256({"candidate_id": candidate_id})
        for candidate_id in candidates
    }
    if task.role == "host:finding_reducer":
        groups = tuple(
            SchedulerFindingReductionGroup(
                group_id=f"group:{candidate_id}",
                candidate_ids=(candidate_id,),
                canonical_candidate_id=candidate_id,
                valid_candidate_ids=(candidate_id,),
                invalid_candidate_ids=(),
            )
            for candidate_id in candidates
        )
        values: dict[str, object] = {
            "schema_version": "1.0",
            "algorithm": "mmaudit.deterministic-finding-reduction.v1",
            "blind_candidate_ids": candidates,
            "execution_candidate_ids": (),
            "candidate_ids": candidates,
            "candidate_payload_sha256s": candidate_hashes,
            "candidate_records": tuple(
                SchedulerFindingReductionCandidate(
                    candidate_id=candidate_id,
                    candidate_sha256=candidate_hashes[candidate_id],
                    location_validation=SchedulerFindingReductionValidation(
                        valid=True,
                        content_hash=None,
                        errors=(),
                    ),
                )
                for candidate_id in candidates
            ),
            "groups": groups,
            "canonical_candidate_ids": candidates,
        }
        values["reduction_sha256"] = scheduler_canonical_sha256(values)
        return SchedulerFindingReductionOutput.model_validate(values)
    if task.role == "host:cross_shard_integrator":
        semantic_inventory_sha256 = plan.manifest.shard_inventory.semantic_inventory_sha256
        values = {
            "schema_version": "1.0",
            "algorithm": "mmaudit.cross-shard-integration.v1",
            "status": (
                "REVIEWED_NO_CROSS_SHARD_RELATIONSHIPS"
                if semantic_inventory_sha256 is not None
                else "NOT_APPLICABLE_NO_SEMANTIC_INVENTORY"
            ),
            "semantic_inventory_sha256": semantic_inventory_sha256,
            "candidate_ids": candidates,
            "candidate_payload_sha256s": candidate_hashes,
            "shard_ids": plan.manifest.shard_ids,
            "semantic_relationship_ids": (),
            "boundary_review_artifact_sha256s": (),
            "invariant_review_present": any(
                model_task.task_kind is SchedulerTaskKind.MODEL_REQUEST
                and model_task.role == "specialist:invariant_review"
                for model_task in plan.tasks
            ),
            "high_critical_candidate_ids": candidates,
            "validation_candidate_ids": candidates,
            "relationships": (),
            "decisions": (),
            "invariant_review_decision_ids": (),
        }
        values["integration_sha256"] = scheduler_canonical_sha256(values)
        return SchedulerCrossShardIntegrationOutput.model_validate(values)
    if task.role == "host:reproduction":
        eligible = (
            plan.candidate_workset.selected_candidate_ids
            if plan.candidate_workset is not None
            else candidates
        )
        return SchedulerReproductionHostOutput(
            eligible_candidate_ids=eligible,
            generated_test_ids=tuple(f"{candidate_id}:synthetic-test" for candidate_id in eligible),
            reproduction_result_ids=tuple(
                f"{candidate_id}:synthetic-test" for candidate_id in eligible
            ),
            falsification_decisions=0,
        )
    if task.role == "host:evidence_cap_judgment":
        group_ids = tuple(
            sorted(
                candidate_id
                for model_task in plan.tasks
                if model_task.task_kind is SchedulerTaskKind.MODEL_REQUEST
                and model_task.role == "judge"
                for candidate_id in model_task.candidate_ids
            )
        )
        return SchedulerEvidenceCapJudgmentOutput(
            group_ids=group_ids,
            judge_decision_ids=group_ids,
            final_finding_ids=group_ids,
            rejected_finding_ids=(),
        )
    raise ValueError(f"synthetic scheduler host role lacks a contract: {task.role}")


def scheduler_test_host_activation_input_sha256(
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
    *,
    candidate_ids: Sequence[str] = (),
) -> str:
    """Return the exact activated-input hash required by a typed synthetic host output."""

    payload = build_scheduler_test_host_payload(plan, task, candidate_ids=candidate_ids)
    if isinstance(payload, SchedulerFindingReductionOutput):
        activation_input: object = {
            "blind_candidate_ids": list(payload.blind_candidate_ids),
            "execution_candidate_ids": list(payload.execution_candidate_ids),
            "candidate_payload_sha256s": payload.candidate_payload_sha256s,
        }
    elif isinstance(payload, SchedulerCrossShardIntegrationOutput):
        activation_input = {
            "candidate_ids": list(payload.candidate_ids),
            "candidate_payload_sha256s": payload.candidate_payload_sha256s,
            "semantic_inventory_sha256": payload.semantic_inventory_sha256,
            "shard_ids": list(payload.shard_ids),
            "semantic_relationship_ids": list(payload.semantic_relationship_ids),
            "semantic_relationships": [
                item.model_dump(mode="json") for item in payload.relationships
            ],
            "boundary_review_artifact_sha256s": list(payload.boundary_review_artifact_sha256s),
            "invariant_review_present": payload.invariant_review_present,
            "high_critical_candidate_ids": list(payload.high_critical_candidate_ids),
            "validation_candidate_ids": list(payload.validation_candidate_ids),
        }
    else:
        activation_input = payload.model_dump(mode="json")
    return scheduler_canonical_sha256(activation_input)


def _context_role_for_request(role: str) -> str:
    if role.startswith("whole_protocol_review:"):
        return "whole_protocol_review"
    if role.startswith("candidate_falsifier:"):
        return "candidate_cross_examination"
    if role == "falsifier":
        return "verifier"
    if role.endswith(":exploit_test") and role.startswith("specialist:"):
        configured_role = role.removeprefix("specialist:").removesuffix(":exploit_test")
        if configured_role in {"test_generation", "exploit_reproduction_planner"}:
            return f"specialist:{configured_role}"
        return configured_role
    return role


def build_scheduler_test_usage(
    task: SchedulerTaskPlan,
    activation: SchedulerTaskActivation,
    *,
    seed: str = "scheduler-test-usage",
    validated_output: object,
    privacy_evidence_custody: SchedulerPrivacyEvidenceCustody | None = None,
) -> UsageRecord:
    """Build redacted typed local provider evidence for scheduler unit tests."""

    assert task.requested_model is not None
    assert activation.user_prompt_sha256 is not None
    assert activation.provider_prompt_sha256 is not None
    assert activation.response_schema_sha256 is not None
    rendered_context_sha256 = (
        _sha256(f"{seed}:rendered-context:{task.task_id}")
        if task.pass_kind
        in {
            SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
            SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
        }
        else activation.user_prompt_sha256
    )
    context = ContextRequestEvidence.build(
        request_id=task.logical_request_id,
        request_role=task.role,
        context_role=_context_role_for_request(task.role),
        byte_budget=1_024,
        declared_bytes_used=64,
        rendered_bytes=64,
        source_bytes=32,
        configured_maximum_source_tokens_per_request=256,
        effective_source_byte_ceiling=256,
        rendered_sha256=rendered_context_sha256,
    )
    started_at = datetime(2025, 1, 1, tzinfo=UTC)
    privacy_routing: dict[str, object] = {}
    if privacy_evidence_custody is not None:
        privacy_routing = {
            "privacy_profile": "STRICT_ZDR",
            "privacy_authorization": "STRICT_ZDR_ENFORCED",
            "effective_privacy_policy_sha256": (
                privacy_evidence_custody.effective_policy_evidence_sha256
            ),
            "privacy_source_sha256": privacy_evidence_custody.source_sha256,
            "privacy_source_provenance_sha256": (
                privacy_evidence_custody.source_provenance_evidence_sha256
            ),
            "privacy_source_classification": "PRIVATE_OPERATOR_SOURCE",
            "privacy_consent_file_sha256": None,
            "privacy_consent_sha256": None,
            "privacy_consent_expires_at": None,
            "privacy_endpoint_policy_class": "ZDR",
        }
    return UsageRecord(
        request_id=task.logical_request_id,
        role=task.role,
        execution_evidence=ExecutionEvidenceKind.MOCK,
        requested_model=task.requested_model,
        returned_model=task.requested_model,
        actual_model=task.requested_model,
        provider="Synthetic Provider",
        model_family=task.requested_model,
        timestamp=started_at,
        prompt_tokens=10,
        completion_tokens=5,
        total_tokens=15,
        reported_cost_usd=0,
        accounted_cost_usd=0,
        routing={
            "context_request_evidence": context.model_dump(mode="json"),
            "context_request_evidence_sha256": context.evidence_sha256,
            "qualified_root_lineage": task.root_lineage,
            **privacy_routing,
        },
        prompt_sha256=activation.provider_prompt_sha256,
        user_prompt_sha256=activation.user_prompt_sha256,
        response_sha256=_sha256(f"{seed}:raw:{task.task_id}"),
        validated_response_sha256=scheduler_canonical_sha256(validated_output),
        request_body_sha256=_sha256(f"{seed}:request:{task.task_id}"),
        schema_sha256=activation.response_schema_sha256,
        openrouter_generation_id=f"synthetic-{task.task_id[-16:]}",
        configured_provider_endpoints=["synthetic-provider"],
        actual_provider_endpoint="synthetic-provider",
        started_at=started_at,
        ended_at=started_at + timedelta(milliseconds=1),
        latency_ms=1,
        finish_reason="stop",
        retry_count=0,
        validation_status=ModelRequestValidationStatus.VALID,
        status="success",
        attempts=1,
    )


def build_scheduler_test_real_usage(
    task: SchedulerTaskPlan,
    activation: SchedulerTaskActivation,
    *,
    seed: str = "scheduler-test-real-usage",
    validated_output: object,
    cost_usd_exact: str = "0",
    privacy_evidence_custody: SchedulerPrivacyEvidenceCustody | None = None,
) -> UsageRecord:
    """Build runtime-attested but wholly synthetic REAL-shaped scheduler evidence."""

    provisional = build_scheduler_test_usage(
        task,
        activation,
        seed=seed,
        validated_output=validated_output,
        privacy_evidence_custody=privacy_evidence_custody,
    )
    assert provisional.started_at is not None
    assert provisional.ended_at is not None
    exact_cost = Decimal(cost_usd_exact)
    routing = {
        **provisional.routing,
        "generation_id": provisional.openrouter_generation_id,
        "selected_model": task.requested_model,
        "canonical_model": task.requested_model,
        "selected_provider_name": provisional.provider,
        "selected_provider_endpoint": provisional.actual_provider_endpoint,
        "router_strategy": "direct",
        "router_attempt": 1,
        "router_attempt_count": 1,
        "router_pipeline": [],
        "finish_reason": "stop",
        "schema_sha256": provisional.schema_sha256,
        "router_metadata_sha256": _sha256(f"{seed}:router-metadata"),
        "provider_policy_sha256": _sha256(f"{seed}:provider-policy"),
        "endpoint_snapshot_sha256": _sha256(f"{seed}:endpoint-snapshot"),
        "output_capability_sha256": _sha256(f"{seed}:output-capability"),
        "provider_fallbacks_allowed": False,
        "certification_request": False,
        "validation_status": "valid",
        "zdr_requested": True,
        "data_collection": "deny",
        "repair_used": False,
        "repair_request": False,
        "request_started_at": provisional.started_at.isoformat(),
        "request_ended_at": provisional.ended_at.isoformat(),
        "latency_ms": provisional.latency_ms,
    }
    bound = bind_synthetic_usage_identity(
        provisional.model_copy(
            update={
                "execution_evidence": ExecutionEvidenceKind.REAL,
                "reported_cost_usd": float(exact_cost),
                "reported_cost_usd_exact": cost_usd_exact,
                "accounted_cost_usd": float(exact_cost),
                "accounted_cost_usd_exact": cost_usd_exact,
                "routing": routing,
            }
        )
    )
    plan = request_token_plan_from_usage(bound)
    assert plan is not None
    request_limit = AtomicRequestLimitReservationEvidence.build(
        request_id=bound.request_id,
        exact_model_id=bound.requested_model,
        role=bound.role,
        request_token_plan_sha256=plan.plan_sha256,
        request_limit_scope=bound.request_id,
        request_limit_count_before=0,
        request_limit_maximum=10,
    )
    return reattest_synthetic_real_usage(
        bound.model_copy(
            update={
                "routing": {
                    **bound.routing,
                    "atomic_request_limit_reservations": [request_limit.model_dump(mode="json")],
                    "atomic_request_limit_reservation_sha256s": [request_limit.evidence_sha256],
                    "atomic_request_limit_reservation": request_limit.model_dump(mode="json"),
                    "atomic_request_limit_reservation_sha256": request_limit.evidence_sha256,
                }
            }
        )
    )


def scheduler_test_model_surface_review_requests(
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
) -> tuple[ModelSurfaceReviewRequest, ...]:
    """Build the exact deterministic review surfaces supplied to a candidate-review task."""

    scoped_shards = (
        set(plan.manifest.shard_ids) if not task.scope.shard_ids else set(task.scope.shard_ids)
    )
    sources = tuple(
        source
        for shard in plan.manifest.shard_inventory.shards
        if shard.shard_id in scoped_shards
        for source in shard.sources
    )
    if task.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW:
        requests = tuple(
            ModelSurfaceReviewRequest(
                surface_id=ModelSurfaceReviewRequest.calculate_surface_id(
                    ModelReviewSurfaceKind.SOURCE_FILE,
                    f"source:{source.path}",
                ),
                kind=ModelReviewSurfaceKind.SOURCE_FILE,
                subject_id=f"source:{source.path}",
                contract=source.path,
                function_or_state_surface="synthetic file surface",
                critical=True,
                allowed_locations=(Location(path=source.path, start_line=1, end_line=1),),
                invariant_considered="Synthetic state transitions remain within scope.",
            )
            for source in sources
        )
    elif (
        task.pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
        and task.role == "business_logic"
    ):
        if not sources:
            raise ValueError("synthetic boundary review requires one scoped source")
        subject_id = f"cross-shard:{task.task_key}"
        source = sources[0]
        request = ModelSurfaceReviewRequest(
            surface_id=ModelSurfaceReviewRequest.calculate_surface_id(
                ModelReviewSurfaceKind.INVARIANT,
                subject_id,
            ),
            kind=ModelReviewSurfaceKind.INVARIANT,
            subject_id=subject_id,
            contract=source.path,
            function_or_state_surface="synthetic cross-shard boundary",
            critical=True,
            allowed_locations=(Location(path=source.path, start_line=1, end_line=1),),
            invariant_considered="Cross-shard state and accounting remain coherent.",
        )
        if task.candidate_ids != (request.surface_id,):
            raise ValueError("synthetic boundary task differs from its deterministic surface")
        requests = (request,)
    else:
        return ()
    return tuple(sorted(requests, key=lambda item: item.surface_id))


def _blind_candidate_review_batch(
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
) -> CandidateReviewBatch:
    requests = scheduler_test_model_surface_review_requests(plan, task)
    records: list[ModelSurfaceReviewRecord] = []
    for request in requests:
        citation = ModelSurfaceReviewCitation(
            location=request.allowed_locations[0],
        )
        records.append(
            ModelSurfaceReviewRecord(
                surface_id=request.surface_id,
                contract=request.contract,
                function_or_state_surface=request.function_or_state_surface,
                review_role=task.role,
                status=ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
                rationale="Synthetic substantive review found no unsafe condition.",
                citation=citation,
                invariant_considered=request.invariant_considered,
                evidence_observations=(
                    ModelSurfaceReviewEvidenceObservation(
                        citation=citation,
                        observed_behavior="Synthetic source behavior was inspected locally.",
                        security_relevance="The local source surface is explicitly accounted for.",
                    ),
                ),
                reachability=ModelSurfaceReviewReachability(
                    entry_point=citation,
                    path=(citation,),
                    actor_or_caller="synthetic local caller",
                    preconditions=(),
                ),
                assumptions=(),
                confidence=1,
            )
        )
    return CandidateReviewBatch(
        findings=[],
        surface_reviews=tuple(sorted(records, key=lambda item: item.surface_id)),
    )


def _boundary_candidate_review_batch(
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
) -> CandidateReviewBatch:
    request = scheduler_test_model_surface_review_requests(plan, task)[0]
    citation = ModelSurfaceReviewCitation(
        location=request.allowed_locations[0],
    )
    record = ModelSurfaceReviewRecord(
        surface_id=request.surface_id,
        contract=request.contract,
        function_or_state_surface=request.function_or_state_surface,
        review_role=task.role,
        status=ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
        rationale="Synthetic boundary review found no unsafe state transition.",
        citation=citation,
        invariant_considered=request.invariant_considered,
        evidence_observations=(
            ModelSurfaceReviewEvidenceObservation(
                citation=citation,
                observed_behavior="Synthetic cross-shard boundary behavior was inspected.",
                security_relevance="The requested boundary has an explicit disposition.",
            ),
        ),
        reachability=ModelSurfaceReviewReachability(
            entry_point=citation,
            path=(citation,),
            actor_or_caller="synthetic local caller",
            preconditions=(),
        ),
        assumptions=(),
        confidence=1,
    )
    return CandidateReviewBatch(findings=[], surface_reviews=(record,))


def build_scheduler_test_model_surface_review_custody(
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
    activation: SchedulerTaskActivation,
    usage: UsageRecord | None,
    payload: object,
) -> tuple[tuple[ModelSurfaceReviewRequest, ...], ModelSurfaceReviewArtifact | None]:
    """Bind a typed candidate-review response to its exact deterministic request manifest."""

    requests = scheduler_test_model_surface_review_requests(plan, task)
    if not requests:
        return (), None
    if usage is None or usage.response_sha256 is None or usage.validated_response_sha256 is None:
        raise ValueError("synthetic surface-review custody requires provider response hashes")
    if usage.schema_sha256 is None or activation.provider_prompt_sha256 is None:
        raise ValueError("synthetic surface-review custody requires prompt and schema hashes")
    batch = CandidateReviewBatch.model_validate(payload).require_exact_surface_set(
        tuple(request.surface_id for request in requests)
    )
    context = ContextRequestEvidence.model_validate(usage.routing["context_request_evidence"])
    requested_ids = tuple(request.surface_id for request in requests)
    requested_ids_sha256 = hashlib.sha256(
        json.dumps(
            list(requested_ids),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()
    artifact_payload: dict[str, object] = {
        "schema_version": "1.0",
        "request_id": task.logical_request_id,
        "review_role": task.role,
        "requested_surface_ids": requested_ids,
        "requested_surface_ids_sha256": requested_ids_sha256,
        "requested_surface_manifest_sha256": (
            ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(requests)
        ),
        "rendered_context_sha256": context.rendered_sha256,
        "prompt_sha256": activation.provider_prompt_sha256,
        "response_sha256": usage.response_sha256,
        "validated_response_sha256": usage.validated_response_sha256,
        "response_schema_sha256": usage.schema_sha256,
        "records": [record.model_dump(mode="json") for record in batch.surface_reviews],
    }
    artifact_payload["artifact_sha256"] = ModelSurfaceReviewArtifact.calculate_artifact_sha256(
        artifact_payload
    )
    return requests, ModelSurfaceReviewArtifact.model_validate(artifact_payload)


def build_scheduler_test_model_payload(
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
) -> object:
    """Return a minimal output satisfying the task's explicit review contract."""

    if task.pass_kind is SchedulerPassKind.ORIENTATION and task.role == "threat_model":
        return ThreatModel(
            assets=["synthetic protocol state"],
            trust_boundaries=[
                ThreatBoundary(
                    name="synthetic local boundary",
                    description="Only disposable local fixture state is in scope.",
                )
            ],
            attacker_controlled_inputs=["synthetic local input"],
            identities_and_roles=["synthetic caller"],
            sensitive_data=[],
            external_integrations=[],
            attack_surfaces=["synthetic function surface"],
            missing_controls=[],
            review_targets=["synthetic invariant"],
        )
    if task.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW:
        return _blind_candidate_review_batch(plan, task)
    if (
        task.pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
        and task.role == "business_logic"
    ):
        return _boundary_candidate_review_batch(plan, task)
    if task.pass_kind is SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION:
        return CandidateCrossExaminationResponse(
            decisions=[
                CandidateCrossExaminationResponseDecision(
                    candidate_ref="candidate-0001",
                    verdict="supported",
                    rationale="Synthetic candidate decision retained for scheduler validation.",
                )
                for _candidate_id in task.candidate_ids
            ]
        )
    if task.pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION and task.role in {
        "verifier",
        "candidate_falsifier",
    }:
        return VerificationBatch(
            decisions=[
                VerificationDecision(
                    candidate_id=candidate_id,
                    verdict=VerificationVerdict.VERIFIED,
                    rationale="Synthetic verifier decision.",
                    source_to_sink="synthetic source to sink",
                    reachability="synthetic reachable path",
                    authentication="synthetic authentication assumption",
                    privilege_requirements="none",
                    environmental_assumptions=[],
                    guards_and_controls=[],
                    false_positive_conditions=[],
                    safe_verification_test=VerificationTest(
                        description="Synthetic local verification only."
                    ),
                    confidence=1,
                )
                for candidate_id in task.candidate_ids
            ]
        )
    if task.pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION and task.role in {
        "falsifier",
        "specialist:falsifier",
    }:
        return FalsificationBatch(
            decisions=[
                FalsificationDecision(
                    candidate_id=candidate_id,
                    test_name="synthetic_local_regression",
                    verdict=FalsificationVerdict.ACCEPTED,
                    test_matches_claim=True,
                    assumptions_validated=True,
                    rationale="Synthetic falsifier decision.",
                )
                for candidate_id in task.candidate_ids
            ]
        )
    if task.role == "specialist:invariant_review":
        return InvariantReviewBatch(decisions=[], proposals=[])
    if task.role.startswith("specialist:") and task.role.endswith(":exploit_test"):
        return GeneratedFoundryTestBatch(tests=[])
    if task.pass_kind is SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT and task.role == "judge":
        return JudgeDecisionBatch(
            decisions=[
                JudgeDecision(
                    group_id=group_id,
                    status=FindingStatus.NEEDS_REVIEW,
                    severity=Severity.MEDIUM,
                    confidence=0.5,
                    rationale="Synthetic evidence-capped judgment.",
                )
                for group_id in task.candidate_ids
            ]
        )
    if task.role == "specialist:report_quality":
        return ReportQualityReview(
            passed=True,
            rationale="Synthetic report evidence is internally consistent.",
        )
    return {"synthetic": True, "task_id": task.task_id}


def _scheduler_test_specialist_outcome(
    task: SchedulerTaskPlan,
    usage: UsageRecord | None,
    payload: object,
    surface_review_artifact: ModelSurfaceReviewArtifact | None,
) -> SpecialistAcceptedOutcome | None:
    if not scheduler_role_requires_specialist_accepted_outcome(task.role):
        return None
    if usage is None or usage.validated_response_sha256 is None:
        raise ValueError("synthetic specialist completion requires exact provider usage")
    context = ContextRequestEvidence.model_validate(usage.routing["context_request_evidence"])
    specialist_role = task.role.split(":", 2)[1]
    requested_surface_count = 0
    surface_review_artifact_sha256 = None
    if task.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW:
        outcome_kind = SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW
        batch = CandidateReviewBatch.model_validate(payload)
        requested_surface_count = len(batch.surface_reviews)
        if surface_review_artifact is None:
            raise ValueError("synthetic specialist review requires exact surface artifact")
        surface_review_artifact_sha256 = surface_review_artifact.artifact_sha256
    else:
        outcome_kind = {
            "invariant_review": SpecialistAcceptedOutcomeKind.INVARIANT_REVIEW,
            "test_generation": SpecialistAcceptedOutcomeKind.TEST_GENERATION,
            "exploit_reproduction_planner": SpecialistAcceptedOutcomeKind.TEST_GENERATION,
            "falsifier": SpecialistAcceptedOutcomeKind.FALSIFICATION,
            "report_quality": SpecialistAcceptedOutcomeKind.REPORT_QUALITY,
        }[specialist_role]
    return SpecialistAcceptedOutcome.build(
        request_id=usage.request_id,
        specialist_role=specialist_role,
        request_role=usage.role,
        outcome_kind=outcome_kind,
        validated_response_sha256=usage.validated_response_sha256,
        context_request_evidence_sha256=context.evidence_sha256,
        requested_surface_count=requested_surface_count,
        surface_review_artifact_sha256=surface_review_artifact_sha256,
    )


def _synthetic_manifest(seed: str) -> SchedulerCampaignManifest:
    solidity_content = f"{seed}:Synthetic.sol".encode()
    notes_content = f"{seed}:NOTES.md".encode()
    solidity = SchedulerSourceDescriptor.build(
        path="src/Synthetic.sol",
        sha256=hashlib.sha256(solidity_content).hexdigest(),
        size=len(solidity_content),
    )
    notes = SchedulerSourceDescriptor.build(
        path="NOTES.md",
        sha256=hashlib.sha256(notes_content).hexdigest(),
        size=len(notes_content),
    )
    semantic = SchedulerShardDescriptor.semantic(
        shard_id="shard-000000000000000000000001",
        semantic_shard_sha256=_sha256(f"{seed}:semantic-shard"),
        sources=(solidity,),
    )
    pseudo = SchedulerShardDescriptor.repository_pseudo(sources=(notes,))
    inventory = SchedulerShardInventory.build(
        semantic_inventory_sha256=_sha256(f"{seed}:semantic-inventory"),
        shards=(pseudo, semantic),
    )
    analysis_inputs = scheduler_test_analysis_input_inventory(seed)
    privacy_custody = SchedulerPrivacyEvidenceCustody.build(
        source_sha256=inventory.source_tree_sha256,
        source_provenance_size=128,
        source_provenance_artifact_sha256=_sha256(f"{seed}:privacy-provenance-bytes"),
        source_provenance_evidence_sha256=_sha256(f"{seed}:privacy-provenance"),
        effective_policy_size=256,
        effective_policy_artifact_sha256=_sha256(f"{seed}:privacy-policy-bytes"),
        effective_policy_evidence_sha256=_sha256(f"{seed}:privacy-policy"),
        policy_source_provenance_sha256=_sha256(f"{seed}:privacy-provenance"),
    )
    bindings = SchedulerBindings.build(
        source_sha256=inventory.source_tree_sha256,
        analysis_input_sha256=analysis_inputs.analysis_input_sha256,
        effective_config_sha256=_sha256(f"{seed}:config"),
        shard_inventory_sha256=inventory.inventory_sha256,
        model_selection_sha256=_sha256(f"{seed}:models"),
        qualification_sha256=_sha256(f"{seed}:qualification"),
        prompt_set_sha256=_sha256(f"{seed}:prompts"),
        schema_set_sha256=_sha256(f"{seed}:schemas"),
        tool_policy_sha256=_sha256(f"{seed}:tools"),
        privacy_evidence_custody_sha256=privacy_custody.custody_sha256,
    )
    return SchedulerCampaignManifest.build(
        bindings=bindings,
        shard_inventory=inventory,
        privacy_evidence_custody=privacy_custody,
    )


def _task_plans(
    manifest: SchedulerCampaignManifest,
    pass_kind: SchedulerPassKind,
    seed: str,
    candidate_workset: SchedulerCandidateWorkset | None = None,
    blind_model_tasks: Sequence[SchedulerFixtureModelTask] = (),
    model_tasks: Sequence[SchedulerFixtureModelTask] = (),
    model_assignment_resolver: SchedulerFixtureModelAssignmentResolver | None = None,
) -> tuple[SchedulerTaskPlan, ...]:
    descriptors: list[
        tuple[
            str,
            str,
            SchedulerTaskKind,
            SchedulerScope,
            tuple[str, ...],
            str | None,
            str | None,
        ]
    ] = []
    if pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW:
        descriptors.extend(
            (
                f"blind:{shard_id}",
                "source_audit",
                SchedulerTaskKind.MODEL_REQUEST,
                SchedulerScope.single_shard(shard_id),
                (),
                None,
                None,
            )
            for shard_id in manifest.shard_ids
        )
    elif pass_kind is SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION:
        assert candidate_workset is not None
        descriptors.extend(
            (
                f"cross:{candidate_id}:{reviewer_index}",
                (
                    "candidate_falsifier:"
                    + hashlib.sha256(candidate_id.encode()).hexdigest()
                    + f":reviewer_{reviewer_index}"
                ),
                SchedulerTaskKind.MODEL_REQUEST,
                SchedulerScope.global_scope(),
                (candidate_id,),
                None,
                None,
            )
            for candidate_id in candidate_workset.selected_candidate_ids
            for reviewer_index in (1, 2)
        )
    elif pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION:
        assert candidate_workset is not None
        descriptors.extend(
            (
                (
                    "validation:verifier",
                    "verifier",
                    SchedulerTaskKind.MODEL_REQUEST,
                    SchedulerScope.global_scope(),
                    candidate_workset.selected_candidate_ids,
                    None,
                    None,
                ),
                (
                    "validation:candidate-falsifier-1",
                    "candidate_falsifier",
                    SchedulerTaskKind.MODEL_REQUEST,
                    SchedulerScope.global_scope(),
                    candidate_workset.selected_candidate_ids,
                    None,
                    None,
                ),
                (
                    "validation:candidate-falsifier-2",
                    "candidate_falsifier",
                    SchedulerTaskKind.MODEL_REQUEST,
                    SchedulerScope.global_scope(),
                    candidate_workset.selected_candidate_ids,
                    None,
                    None,
                ),
            )
        )
    else:
        role, task_kind = {
            SchedulerPassKind.ORIENTATION: ("threat_model", SchedulerTaskKind.MODEL_REQUEST),
            SchedulerPassKind.FINDING_REDUCTION: (
                "host:finding_reducer",
                SchedulerTaskKind.HOST_COMPUTATION,
            ),
            SchedulerPassKind.CROSS_SHARD_INTEGRATION: (
                "host:cross_shard_integrator",
                SchedulerTaskKind.HOST_COMPUTATION,
            ),
            SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT: (
                "host:evidence_cap_judgment",
                SchedulerTaskKind.HOST_COMPUTATION,
            ),
        }[pass_kind]
        descriptors.append(
            (
                pass_kind.value,
                role,
                task_kind,
                SchedulerScope.global_scope(),
                (),
                None,
                None,
            )
        )

    descriptors.extend(
        (
            assignment.task_key,
            assignment.role,
            SchedulerTaskKind.MODEL_REQUEST,
            assignment.scope,
            assignment.candidate_ids,
            assignment.requested_model,
            assignment.root_lineage,
        )
        for assignment in (*blind_model_tasks, *model_tasks)
        if assignment.pass_kind is pass_kind
    )

    tasks: list[SchedulerTaskPlan] = []
    for (
        task_key,
        role,
        task_kind,
        scope,
        candidate_ids,
        requested_model,
        root_lineage,
    ) in descriptors:
        if task_kind is SchedulerTaskKind.MODEL_REQUEST:
            if model_assignment_resolver is not None:
                requested_model, root_lineage = model_assignment_resolver(
                    pass_kind,
                    task_key,
                    role,
                )
            else:
                requested_model = requested_model or "synthetic/auditor-v1"
                root_lineage = root_lineage or "sha256:" + _sha256(f"{seed}:lineage:{task_key}")
        tasks.append(
            SchedulerTaskPlan.build(
                manifest=manifest,
                pass_kind=pass_kind,
                scope=scope,
                task_kind=task_kind,
                task_key=task_key,
                role=role,
                requested_model=requested_model,
                root_lineage=root_lineage,
                candidate_ids=candidate_ids,
                input_sha256=_sha256(f"{seed}:recipe-input:{task_key}"),
                prompt_sha256=_sha256(f"{seed}:recipe-prompt:{task_key}"),
                response_schema_sha256=(
                    scheduler_test_response_schema_sha256(pass_kind, role)
                    if task_kind is SchedulerTaskKind.MODEL_REQUEST
                    else _sha256(f"{seed}:schema:{task_key}")
                ),
                **(
                    scheduler_test_model_fields(f"{seed}:{task_key}")
                    if task_kind is SchedulerTaskKind.MODEL_REQUEST
                    else {}
                ),
            )
        )
    return tuple(tasks)


def build_complete_scheduler_fixture(
    *,
    seed: str = "complete-scheduler",
    manifest: SchedulerCampaignManifest | None = None,
    analysis_input_inventory: SchedulerAnalysisInputInventory | None = None,
    real_usage: bool = False,
    blind_model_tasks: Sequence[SchedulerFixtureModelTask] = (),
    model_tasks: Sequence[SchedulerFixtureModelTask] = (),
    model_assignment_resolver: SchedulerFixtureModelAssignmentResolver | None = None,
    usage_transform: SchedulerFixtureUsageTransform | None = None,
) -> CompleteSchedulerFixture:
    """Build one deterministic, local-only COMPLETE scheduler evidence graph."""

    exact_analysis_inputs = analysis_input_inventory or scheduler_test_analysis_input_inventory(
        seed
    )
    exact_manifest = manifest or _synthetic_manifest(seed)
    if exact_manifest.bindings.analysis_input_sha256 != exact_analysis_inputs.analysis_input_sha256:
        bindings = exact_manifest.bindings
        exact_bindings = SchedulerBindings.build(
            source_sha256=bindings.source_sha256,
            analysis_input_sha256=exact_analysis_inputs.analysis_input_sha256,
            effective_config_sha256=bindings.effective_config_sha256,
            shard_inventory_sha256=bindings.shard_inventory_sha256,
            model_selection_sha256=bindings.model_selection_sha256,
            qualification_sha256=bindings.qualification_sha256,
            prompt_set_sha256=bindings.prompt_set_sha256,
            schema_set_sha256=bindings.schema_set_sha256,
            tool_policy_sha256=bindings.tool_policy_sha256,
            cost_ledger_baseline_sha256=bindings.cost_ledger_baseline_sha256,
            privacy_evidence_custody_sha256=bindings.privacy_evidence_custody_sha256,
        )
        exact_manifest = SchedulerCampaignManifest.build(
            bindings=exact_bindings,
            shard_inventory=exact_manifest.shard_inventory,
            cost_ledger_baseline=exact_manifest.cost_ledger_baseline,
            privacy_evidence_custody=exact_manifest.privacy_evidence_custody,
        )
    plans: list[SchedulerPassPlan] = []
    activations: list[SchedulerTaskActivation] = []
    outputs: list[SchedulerTaskOutput] = []
    task_results: list[SchedulerTaskResult] = []
    pass_results: list[SchedulerPassResult] = []
    recorded_usage: list[UsageRecord] = []
    recorded_surface_requests: list[ModelSurfaceReviewRequest] = []
    recorded_surface_artifacts: list[ModelSurfaceReviewArtifact] = []

    for pass_kind in SCHEDULER_PASS_ORDER:
        candidate_workset = None
        if pass_kind in {
            SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
            SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
        }:
            source_pass = next(
                result
                for result in pass_results
                if result.plan.pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
            )
            source_result = next(
                result
                for result in source_pass.task_results
                if next(
                    task for task in source_pass.plan.tasks if task.task_id == result.task_id
                ).role
                == "host:cross_shard_integrator"
            )
            source_output = next(
                output for output in outputs if output.task_id == source_result.task_id
            )
            candidate_workset = SchedulerCandidateWorkset.build(
                pass_kind=pass_kind,
                source_pass_result=source_pass,
                source_result=source_result,
                source_output=source_output,
            )
        plan = SchedulerPassPlan.build(
            manifest=exact_manifest,
            pass_kind=pass_kind,
            dependencies=tuple(
                SchedulerPassDependency.from_result(result) for result in pass_results
            ),
            tasks=_task_plans(
                exact_manifest,
                pass_kind,
                seed,
                candidate_workset,
                blind_model_tasks,
                model_tasks,
                model_assignment_resolver,
            ),
            candidate_workset=candidate_workset,
        )
        plans.append(plan)
        current_results: list[SchedulerTaskResult] = []
        for task in plan.tasks:
            provider_hashes: dict[str, str] = {}
            if task.task_kind is SchedulerTaskKind.MODEL_REQUEST:
                assert task.system_prompt_sha256 is not None
                assert task.response_schema_sha256 is not None
                provider_hashes = {
                    "system_prompt_sha256": task.system_prompt_sha256,
                    "user_prompt_sha256": _sha256(f"{seed}:user:{task.task_id}"),
                    "provider_prompt_sha256": _sha256(f"{seed}:provider:{task.task_id}"),
                    "response_schema_sha256": task.response_schema_sha256,
                }
            host_candidate_ids = ("candidate-critical",)
            actual_input_sha256 = (
                scheduler_test_host_activation_input_sha256(
                    plan,
                    task,
                    candidate_ids=host_candidate_ids,
                )
                if task.task_kind is SchedulerTaskKind.HOST_COMPUTATION
                else _sha256(f"{seed}:input:{task.task_id}")
            )
            activation = SchedulerTaskActivation.build(
                plan=plan,
                task=task,
                actual_input_sha256=actual_input_sha256,
                delivered_source_descriptor_sha256s=(
                    scheduler_test_delivered_source_descriptor_sha256s(plan, task)
                ),
                **provider_hashes,
            )
            activations.append(activation)
            payload: object
            usage = None
            if task.task_kind is SchedulerTaskKind.MODEL_REQUEST:
                payload = build_scheduler_test_model_payload(plan, task)
                usage_builder = (
                    build_scheduler_test_real_usage if real_usage else build_scheduler_test_usage
                )
                usage = usage_builder(
                    task,
                    activation,
                    seed=seed,
                    validated_output=payload,
                    privacy_evidence_custody=exact_manifest.privacy_evidence_custody,
                )
                if usage_transform is not None:
                    transformed_usage = usage_transform(task, activation, usage)
                    usage = UsageRecord.model_validate(transformed_usage.model_dump(mode="python"))
                    if transformed_usage.execution_evidence is ExecutionEvidenceKind.REAL:
                        usage = reattest_synthetic_real_usage(usage)
                recorded_usage.append(usage)
            elif task.task_kind is SchedulerTaskKind.HOST_COMPUTATION:
                payload = build_scheduler_test_host_payload(
                    plan,
                    task,
                    candidate_ids=host_candidate_ids,
                )
            else:
                payload = {"synthetic": True, "task_id": task.task_id}
            surface_requests, surface_artifact = (
                build_scheduler_test_model_surface_review_custody(
                    plan,
                    task,
                    activation,
                    usage,
                    payload,
                )
                if task.task_kind is SchedulerTaskKind.MODEL_REQUEST
                else ((), None)
            )
            recorded_surface_requests.extend(surface_requests)
            if surface_artifact is not None:
                recorded_surface_artifacts.append(surface_artifact)
            output = SchedulerTaskOutput.build(
                plan=plan,
                task=task,
                activation=activation,
                payload=payload,
                usage_record=usage,
                specialist_accepted_outcome=_scheduler_test_specialist_outcome(
                    task,
                    usage,
                    payload,
                    surface_artifact,
                ),
                model_surface_review_requests=surface_requests,
                model_surface_review_artifact=surface_artifact,
            )
            outputs.append(output)
            result = SchedulerTaskResult.build(
                plan=plan,
                task=task,
                activation=activation,
                terminal_status=SchedulerTerminalStatus.SUCCEEDED,
                terminal_evidence_sha256=(
                    usage.validated_response_sha256
                    if usage is not None and usage.validated_response_sha256 is not None
                    else _sha256(f"{seed}:terminal:{task.task_id}")
                ),
                output=output,
            )
            task_results.append(result)
            current_results.append(result)
        pass_results.append(SchedulerPassResult.build(plan=plan, task_results=current_results))

    events: list[SchedulerTaskEvent] = []
    activation_by_task = {item.task_id: item for item in activations}
    result_by_task = {item.task_id: item for item in task_results}
    for plan in plans:
        for task in plan.tasks:
            previous = events[-1] if events else None
            planned = SchedulerTaskEvent.build(
                plan=plan,
                task=task,
                kind=SchedulerTaskEventKind.PLANNED,
                event_index=len(events),
                previous_event=previous,
            )
            events.append(planned)
            activation = activation_by_task[task.task_id]
            activated = SchedulerTaskEvent.build(
                plan=plan,
                task=task,
                kind=SchedulerTaskEventKind.ACTIVATED,
                event_index=len(events),
                previous_event=events[-1],
                prior_task_event=planned,
                activation=activation,
            )
            events.append(activated)
            dispatched = SchedulerTaskEvent.build(
                plan=plan,
                task=task,
                kind=SchedulerTaskEventKind.DISPATCHED,
                event_index=len(events),
                previous_event=events[-1],
                prior_task_event=activated,
                activation=activation,
                request_id=task.logical_request_id,
            )
            events.append(dispatched)
            events.append(
                SchedulerTaskEvent.build(
                    plan=plan,
                    task=task,
                    kind=SchedulerTaskEventKind.TERMINAL,
                    event_index=len(events),
                    previous_event=events[-1],
                    prior_task_event=dispatched,
                    activation=activation,
                    request_id=task.logical_request_id,
                    result=result_by_task[task.task_id],
                )
            )

    exact_pass_results = tuple(pass_results)
    summary = SchedulerCampaignSummary.build(
        manifest=exact_manifest,
        pass_results=exact_pass_results,
    )
    model_requests = build_scheduler_model_request_evidence(
        plans=plans,
        activations=activations,
        task_results=task_results,
    )
    journal_evidence = SchedulerJournalEvidence.build(
        manifest=exact_manifest,
        analysis_input_inventory=exact_analysis_inputs,
        summary=summary,
        plans=plans,
        model_requests=model_requests,
        activations=activations,
        outputs=outputs,
        task_results=task_results,
        result_observations=task_results,
        events=events,
    )
    artifact = SchedulerArtifact.build(
        summary=summary,
        journal_evidence=journal_evidence,
        model_requests=model_requests,
    )
    report_binding = SchedulerReportBinding.from_artifact(artifact)
    usage_records = tuple(recorded_usage)
    context_request_evidence = tuple(
        ContextRequestEvidence.model_validate(record.routing["context_request_evidence"])
        for record in usage_records
    )
    return CompleteSchedulerFixture(
        manifest=exact_manifest,
        plans=tuple(plans),
        activations=tuple(activations),
        outputs=tuple(outputs),
        task_results=tuple(task_results),
        pass_results=exact_pass_results,
        events=tuple(events),
        summary=summary,
        journal_evidence=journal_evidence,
        artifact=artifact,
        report_binding=report_binding,
        usage_records=usage_records,
        context_request_evidence=context_request_evidence,
        model_surface_review_requests=tuple(recorded_surface_requests),
        model_surface_review_artifacts=tuple(recorded_surface_artifacts),
    )


def build_complete_scheduler_artifact(
    *,
    seed: str = "complete-scheduler",
    manifest: SchedulerCampaignManifest | None = None,
) -> SchedulerArtifact:
    """Return only the public artifact for callers that do not need private evidence."""

    return build_complete_scheduler_fixture(seed=seed, manifest=manifest).artifact
