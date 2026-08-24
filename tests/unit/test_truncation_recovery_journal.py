"""Durable scheduler custody tests for typed truncation-recovery families."""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from itertools import repeat
from pathlib import Path

import pytest

from mmaudit.models.scheduler import (
    SchedulerCampaignManifest,
    SchedulerJournalEvidence,
    SchedulerModelRequestEvidence,
    SchedulerPassKind,
    SchedulerPassPlan,
    SchedulerProviderAttemptEvidence,
    SchedulerTaskPlan,
    SchedulerTaskResult,
    SchedulerTerminalStatus,
    build_scheduler_truncation_recovery_model_request_evidence,
    scheduler_canonical_sha256,
)
from mmaudit.models.schemas import (
    CandidateReviewBatch,
    ContextRequestEvidence,
    ExecutionEvidenceKind,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
    SpecialistAcceptedOutcome,
    SpecialistAcceptedOutcomeKind,
    UsageRecord,
)
from mmaudit.models.truncation import (
    CandidateReviewChannelState,
    CandidateReviewNormalizationEvidence,
    CandidateReviewTruncatedEnvelopeEvidence,
    CandidateReviewTruncationProjection,
    candidate_review_frame_wire_schema_sha256,
    frame_candidate_review_batch,
    normalize_candidate_review_document,
    project_truncated_candidate_review_prefix,
    seal_candidate_review_truncated_envelope_evidence,
)
from mmaudit.models.truncation_recovery import (
    TruncationRecoveryChannel,
    TruncationRecoveryChannelBinding,
    TruncationRecoveryChannelState,
    TruncationRecoveryChildPlan,
    TruncationRecoveryParentBinding,
    TruncationRecoveryPlan,
    TruncationRecoveryResourceBudget,
    plan_truncation_recovery,
)
from mmaudit.models.truncation_recovery_journal import (
    SCHEDULER_TRUNCATION_RECOVERY_ENTRY_TYPES,
    SCHEDULER_TRUNCATION_RECOVERY_MAX_ENTRIES,
    SCHEDULER_TRUNCATION_RECOVERY_MAX_FAMILIES,
    SchedulerTruncationRecoveryChildActivation,
    SchedulerTruncationRecoveryChildDispatch,
    SchedulerTruncationRecoveryChildPreflightResult,
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryClosureStatus,
    SchedulerTruncationRecoveryEntry,
    SchedulerTruncationRecoveryEntryKind,
    SchedulerTruncationRecoveryFamilyClosure,
    SchedulerTruncationRecoveryFamilyRoot,
    SchedulerTruncationRecoveryParentKind,
    SchedulerTruncationRecoveryRequestedSurfaceManifest,
    SchedulerTruncationRecoveryTerminalStatus,
    rebuild_truncation_recovery_parent_from_projection,
    validate_truncation_recovery_entry_chain,
)
from mmaudit.models.usage import is_recovery_creditable_usage_record
from mmaudit.orchestration import scheduler as scheduler_module
from mmaudit.orchestration.budgets import AtomicRequestLimitReservationEvidence, BudgetManager
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.scheduler import SchedulerJournal
from mmaudit.orchestration.scheduler_runtime import scheduler_response_normalizer_sha256
from mmaudit.reporting.json_report import stable_json
from tests.identity_fixtures import (
    bind_synthetic_usage_identity,
    reattest_synthetic_real_usage,
    synthetic_token_plan_routing,
)
from tests.scheduler_support import (
    build_scheduler_test_model_payload,
    build_scheduler_test_real_usage,
    scheduler_test_delivered_source_descriptor_sha256s,
)
from tests.unit.test_scheduler_journal import (
    _bindings,
    _inventory,
    _plan,
    create_scheduler_journal,
    open_scheduler_journal_for_verification,
    resume_scheduler_journal,
)
from tests.unit.test_truncation import _frame_json, _frames, _surface


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _requested_surfaces() -> tuple[
    SchedulerTruncationRecoveryRequestedSurfaceManifest,
    tuple[ModelSurfaceReviewRecord, ...],
]:
    pairs: list[tuple[ModelSurfaceReviewRequest, ModelSurfaceReviewRecord]] = []
    for index in range(4):
        subject_id = f"synthetic-root-surface-{index}"
        request = ModelSurfaceReviewRequest(
            surface_id=ModelSurfaceReviewRequest.calculate_surface_id(
                ModelReviewSurfaceKind.ENTRY_POINT,
                subject_id,
            ),
            kind=ModelReviewSurfaceKind.ENTRY_POINT,
            subject_id=subject_id,
            contract="SyntheticVault",
            function_or_state_surface=f"surface-{index}",
            critical=False,
            allowed_symbols=(f"surface-{index}",),
            invariant_considered="Synthetic state remains within its declared local bound.",
        )
        base = _surface(f"root-{index}")
        record = ModelSurfaceReviewRecord.model_validate(
            {
                **base.model_dump(mode="python"),
                "surface_id": request.surface_id,
                "review_role": "source_audit",
                "function_or_state_surface": request.function_or_state_surface,
            }
        )
        pairs.append((request, record))
    ordered = tuple(sorted(pairs, key=lambda pair: pair[0].surface_id))
    manifest = SchedulerTruncationRecoveryRequestedSurfaceManifest.build(
        request for request, _record in ordered
    )
    return manifest, tuple(record for _request, record in ordered)


def _projection(
    surfaces: tuple[ModelSurfaceReviewRecord, ...],
    *,
    retained_count: int,
) -> CandidateReviewTruncationProjection:
    frames = _frames((), surfaces)
    accepted_frame_count = 2 + retained_count
    accepted = ",".join(_frame_json(frame) for frame in frames[:accepted_frame_count])
    sequence = accepted_frame_count
    partial = (
        '{"schema_version":"1.0","sequence":'
        + str(sequence)
        + ',"phase":"SURFACE_REVIEW","record":{"surface_id":"partial-tail'
    )
    content = '{"frames":[' + accepted + "," + partial
    return project_truncated_candidate_review_prefix(
        content,
        finish_reason="stop",
        native_finish_reason="max_tokens",
    )


def _channel_state(state: CandidateReviewChannelState) -> TruncationRecoveryChannelState:
    if state is CandidateReviewChannelState.COMPLETE:
        return TruncationRecoveryChannelState.COMPLETE
    if state is CandidateReviewChannelState.INVALID:
        return TruncationRecoveryChannelState.INVALID
    return TruncationRecoveryChannelState.INCOMPLETE


def _placeholder_channels(
    projection: CandidateReviewTruncationProjection,
    *,
    wrong_findings_state: bool = False,
) -> tuple[TruncationRecoveryChannelBinding, ...]:
    findings_state = _channel_state(projection.findings_state)
    if wrong_findings_state:
        findings_state = TruncationRecoveryChannelState.INVALID
    return (
        TruncationRecoveryChannelBinding.build(
            channel=TruncationRecoveryChannel.COVERAGE,
            state=_channel_state(projection.surface_reviews_state),
            retained_record_count=len(projection.surface_reviews),
            retained_inventory_sha256=_digest("placeholder-coverage"),
        ),
        TruncationRecoveryChannelBinding.build(
            channel=TruncationRecoveryChannel.FINDINGS,
            state=findings_state,
            retained_record_count=len(projection.findings),
            retained_inventory_sha256=_digest("placeholder-findings"),
        ),
        TruncationRecoveryChannelBinding.build(
            channel=TruncationRecoveryChannel.SUMMARY,
            state=_channel_state(projection.summary_state),
            retained_record_count=(
                1 if projection.summary_state is CandidateReviewChannelState.COMPLETE else 0
            ),
            retained_inventory_sha256=_digest("placeholder-summary"),
        ),
    )


def _resources(
    *,
    recovery_requests_consumed: int,
    accounted_before: str = "0",
    attempts_before: int = 0,
    tokens_before: int = 0,
    parent_attempts: int = 1,
    parent_tokens: int = 5,
    parent_cost: str = "0",
) -> TruncationRecoveryResourceBudget:
    return TruncationRecoveryResourceBudget.build(
        campaign_cap_usd_exact="250",
        accounted_usd_before_parent_exact=accounted_before,
        parent_accounted_cost_usd_exact=parent_cost,
        child_reserved_usd_exact="0.1",
        recovery_requests_consumed=recovery_requests_consumed,
        provider_attempts_before_parent=attempts_before,
        parent_provider_attempts=parent_attempts,
        child_provider_attempts=1,
        completion_tokens_before_parent=tokens_before,
        parent_completion_tokens=parent_tokens,
        child_completion_tokens=100,
    )


def _complete_recovery_orientation(journal: SchedulerJournal) -> None:
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    activation = journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
        delivered_source_descriptor_sha256s=(
            scheduler_test_delivered_source_descriptor_sha256s(plan, task)
        ),
    )
    journal.mark_dispatched(task.task_id)
    payload = build_scheduler_test_model_payload(plan, task)
    real_usage = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=payload,
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
        audit_model_selection=journal.manifest.bindings.audit_model_selection,
        audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
        audit_model_refresh_pricing=journal.manifest.bindings.audit_model_refresh_pricing,
    )
    usage = UsageRecord.model_validate(
        {
            **real_usage.model_dump(mode="python"),
            "execution_evidence": ExecutionEvidenceKind.MOCK,
            "identity_strength": ModelIdentityStrength.UNBOUND,
        }
    )
    output = journal.persist_output(task.task_id, payload, usage_record=usage)
    journal.record_terminal(
        SchedulerTaskResult.build(
            plan=plan,
            task=task,
            activation=activation,
            terminal_status=SchedulerTerminalStatus.SUCCEEDED,
            terminal_evidence_sha256=usage.validated_response_sha256 or "0" * 64,
            output=output,
        )
    )
    journal.seal_pass_result(SchedulerPassKind.ORIENTATION)


def _root_plan(
    journal: SchedulerJournal,
    *,
    projection: CandidateReviewTruncationProjection,
    surface_manifest: SchedulerTruncationRecoveryRequestedSurfaceManifest,
    wrong_findings_state: bool = False,
) -> TruncationRecoveryPlan:
    parent_result = next(
        result
        for result in journal.task_results
        if result.terminal_status is SchedulerTerminalStatus.TRUNCATED
    )
    pass_plan = next(
        item
        for item in journal.plans
        if any(task.task_id == parent_result.task_id for task in item.tasks)
    )
    task = next(task for task in pass_plan.tasks if task.task_id == parent_result.task_id)
    activation = next(item for item in journal.activations if item.task_id == parent_result.task_id)
    attempt = next(
        item for item in journal.provider_attempts if item.task_id == parent_result.task_id
    )
    prior_usage = tuple(
        record
        for record in journal.retained_provider_usage_records
        if record.request_id != attempt.usage_record.request_id
    )
    claimed = TruncationRecoveryParentBinding.build(
        campaign_id=journal.manifest.campaign_id,
        pass_plan_id=pass_plan.pass_plan_id,
        parent_task_id=task.task_id,
        parent_logical_request_id=task.logical_request_id,
        parent_task_plan_sha256=task.task_plan_sha256,
        parent_activation_sha256=activation.activation_sha256,
        provider_attempt_evidence_sha256=attempt.attempt_evidence_sha256,
        truncation_projection_sha256=projection.evidence_sha256,
        requested_surface_manifest_sha256=(surface_manifest.requested_surface_manifest_sha256),
        requested_surface_ids=surface_manifest.requested_surface_ids,
        retained_surface_ids=tuple(item.surface_id for item in projection.surface_reviews),
        channel_bindings=_placeholder_channels(
            projection,
            wrong_findings_state=wrong_findings_state,
        ),
    )
    parent = (
        claimed
        if wrong_findings_state
        else rebuild_truncation_recovery_parent_from_projection(
            claimed_parent=claimed,
            projection=projection,
        )
    )
    return plan_truncation_recovery(
        parent=parent,
        resources=_resources(
            recovery_requests_consumed=0,
            accounted_before=format(
                sum(
                    (Decimal(record.accounted_cost_usd_exact or "0") for record in prior_usage),
                    start=Decimal("0"),
                ),
                "f",
            ),
            attempts_before=sum(record.attempts for record in prior_usage),
            tokens_before=sum(record.completion_tokens for record in prior_usage),
            parent_attempts=attempt.usage_record.attempts,
            parent_tokens=attempt.usage_record.completion_tokens,
            parent_cost=attempt.usage_record.accounted_cost_usd_exact or "0",
        ),
    )


def _journal_with_truncated_parent(
    path: Path,
    *,
    exact_truncation_usage: bool = True,
    typed_parent_attempt: bool = False,
    request_limit_maximum: int = 10,
    retain_validated_hash: bool = False,
    wrong_truncation_status: bool = False,
    parent_cost_usd_exact: str = "0",
    parent_role: str | None = None,
) -> tuple[
    SchedulerJournal,
    TruncationRecoveryPlan,
    CandidateReviewTruncationProjection,
    tuple[ModelSurfaceReviewRecord, ...],
    SchedulerTruncationRecoveryRequestedSurfaceManifest,
]:
    bindings = _bindings()
    journal = create_scheduler_journal(
        path,
        bindings=bindings,
        shard_inventory=_inventory(),
    )
    _complete_recovery_orientation(journal)
    surface_manifest, surfaces = _requested_surfaces()
    if parent_role is not None:
        surfaces = tuple(
            ModelSurfaceReviewRecord.model_validate(
                {**record.model_dump(mode="python"), "review_role": parent_role}
            )
            for record in surfaces
        )
    projection = _projection(surfaces, retained_count=1)
    base_plan = _plan(journal, SchedulerPassKind.BLIND_SHARD_REVIEW, task_count=2)
    base_task = base_plan.tasks[0]
    specialist_tasks: tuple[SchedulerTaskPlan, ...] = ()
    if parent_role is not None:
        specialist_tasks = tuple(
            SchedulerTaskPlan.build(
                manifest=journal.manifest,
                pass_kind=item.pass_kind,
                scope=item.scope,
                task_kind=item.task_kind,
                task_key=item.task_key,
                role=parent_role,
                input_sha256=item.input_sha256,
                prompt_sha256=item.prompt_sha256,
                response_schema_sha256=(
                    projection.wire_schema_sha256 if index == 0 else item.response_schema_sha256
                ),
                system_prompt_sha256=item.system_prompt_sha256,
                normalizer_sha256=(
                    scheduler_response_normalizer_sha256(projection.wire_schema_sha256)
                    if index == 0
                    else item.normalizer_sha256
                ),
                requested_model=item.requested_model,
                root_lineage=item.root_lineage,
                candidate_ids=item.candidate_ids,
            )
            for index, item in enumerate(base_plan.tasks)
        )
        task = specialist_tasks[0]
        planned_tasks = (*base_plan.tasks, *specialist_tasks)
    else:
        task = SchedulerTaskPlan.build(
            manifest=journal.manifest,
            pass_kind=base_task.pass_kind,
            scope=base_task.scope,
            task_kind=base_task.task_kind,
            task_key=base_task.task_key,
            role=base_task.role,
            input_sha256=base_task.input_sha256,
            prompt_sha256=base_task.prompt_sha256,
            response_schema_sha256=projection.wire_schema_sha256,
            system_prompt_sha256=base_task.system_prompt_sha256,
            normalizer_sha256=scheduler_response_normalizer_sha256(projection.wire_schema_sha256),
            requested_model=base_task.requested_model,
            root_lineage=base_task.root_lineage,
            candidate_ids=base_task.candidate_ids,
        )
        planned_tasks = (task, *base_plan.tasks[1:])
    target_task_id = task.task_id
    plan = journal.seal_pass_plan(
        SchedulerPassPlan.build(
            manifest=journal.manifest,
            pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
            dependencies=journal.next_dependencies,
            tasks=planned_tasks,
        )
    )
    task = next(item for item in plan.tasks if item.task_id == target_task_id)
    activation = journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
        delivered_source_descriptor_sha256s=(
            scheduler_test_delivered_source_descriptor_sha256s(plan, task)
        ),
    )
    journal.mark_dispatched(task.task_id)
    usage = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=build_scheduler_test_model_payload(plan, task),
        cost_usd_exact=parent_cost_usd_exact,
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
    )
    original_request_limit = AtomicRequestLimitReservationEvidence.model_validate(
        usage.routing["atomic_request_limit_reservation"]
    )
    request_limit = AtomicRequestLimitReservationEvidence.build(
        request_id=original_request_limit.request_id,
        exact_model_id=original_request_limit.exact_model_id,
        role=original_request_limit.role,
        request_token_plan_sha256=original_request_limit.request_token_plan_sha256,
        request_limit_scope=original_request_limit.request_limit_scope,
        request_limit_count_before=original_request_limit.request_limit_count_before,
        request_limit_maximum=request_limit_maximum,
    )
    request_limit_routing = {
        **usage.routing,
        "atomic_request_limit_reservations": [request_limit.model_dump(mode="json")],
        "atomic_request_limit_reservation_sha256s": [request_limit.evidence_sha256],
        "atomic_request_limit_reservation": request_limit.model_dump(mode="json"),
        "atomic_request_limit_reservation_sha256": request_limit.evidence_sha256,
    }
    envelope: CandidateReviewTruncatedEnvelopeEvidence | None = None
    typed_routing = request_limit_routing
    if typed_parent_attempt:
        assert usage.openrouter_generation_id is not None
        assert usage.returned_model is not None
        assert usage.actual_model is not None
        assert usage.provider is not None
        assert usage.actual_provider_endpoint is not None
        router_metadata_sha256 = usage.routing.get("router_metadata_sha256")
        assert isinstance(router_metadata_sha256, str)
        envelope = seal_candidate_review_truncated_envelope_evidence(
            logical_request_id=task.logical_request_id,
            generation_id=usage.openrouter_generation_id,
            generation_header_id=usage.openrouter_generation_id,
            requested_model=usage.requested_model,
            returned_model=usage.returned_model,
            selected_model=usage.actual_model,
            response_provider_identity=usage.provider,
            selected_provider_endpoint=usage.actual_provider_endpoint,
            selected_provider_identity="synthetic-provider",
            selected_provider_name=usage.provider,
            router_metadata_sha256=router_metadata_sha256,
            finish_reason=projection.finish_reason,
            native_finish_reason=projection.native_finish_reason,
            wire_schema_sha256=projection.wire_schema_sha256,
            response_sha256=projection.original_response_sha256,
        )
        typed_routing = {
            **request_limit_routing,
            "generation_id": envelope.generation_id,
            "generation_header_id": envelope.generation_header_id,
            "provider": envelope.selected_provider_name,
            "router_metadata_sha256": envelope.router_metadata_sha256,
            "finish_reason": envelope.finish_reason,
            "native_finish_reason": envelope.native_finish_reason,
            "schema_sha256": envelope.wire_schema_sha256,
            "candidate_review_truncated_envelope_evidence": envelope.model_dump(mode="json"),
            "candidate_review_truncated_envelope_sha256": envelope.evidence_sha256,
            **_truncation_projection_routing(projection),
        }
    retained_usage = (
        UsageRecord.model_validate(
            {
                **usage.model_dump(mode="python"),
                "response_sha256": projection.original_response_sha256,
                "validated_response_sha256": (
                    usage.validated_response_sha256 if retain_validated_hash else None
                ),
                "finish_reason": (
                    projection.finish_reason if typed_parent_attempt else "max_tokens"
                ),
                "validation_status": ModelRequestValidationStatus.TRUNCATED,
                "identity_strength": ModelIdentityStrength.UNBOUND,
                "execution_evidence": ExecutionEvidenceKind.MOCK,
                "status": (
                    "wrong_truncation_status"
                    if wrong_truncation_status
                    else "rejected_truncated_response"
                ),
                "routing": {
                    **typed_routing,
                    "finish_reason": (
                        projection.finish_reason if typed_parent_attempt else "max_tokens"
                    ),
                    "validation_status": "truncated",
                },
            }
        )
        if exact_truncation_usage
        else UsageRecord.model_validate(
            {
                **usage.model_dump(mode="python"),
                "identity_strength": ModelIdentityStrength.UNBOUND,
                "execution_evidence": ExecutionEvidenceKind.MOCK,
                "routing": request_limit_routing,
            }
        )
    )
    if envelope is None:
        journal.persist_provider_attempt(task.task_id, retained_usage)
    else:
        journal.persist_truncated_provider_attempt(
            task.task_id,
            retained_usage,
            truncated_envelope_evidence=envelope,
            truncation_projection=projection,
        )
    journal.record_terminal(
        SchedulerTaskResult.build(
            plan=plan,
            task=task,
            activation=activation,
            terminal_status=SchedulerTerminalStatus.TRUNCATED,
            terminal_evidence_sha256=projection.evidence_sha256,
        )
    )
    recovery_plan = _root_plan(
        journal,
        projection=projection,
        surface_manifest=surface_manifest,
    )
    return journal, recovery_plan, projection, surfaces, surface_manifest


def _activate_child(
    journal: SchedulerJournal,
    child_task_id: str,
) -> SchedulerTruncationRecoveryChildActivation:
    return journal.activate_truncation_recovery_child(
        child_task_id,
        actual_input_sha256=_digest(f"input:{child_task_id}"),
        system_prompt_sha256=_digest(f"system:{child_task_id}"),
        user_prompt_sha256=_digest(f"user:{child_task_id}"),
        provider_prompt_sha256=_digest(f"provider:{child_task_id}"),
        response_schema_sha256=candidate_review_frame_wire_schema_sha256(),
    )


def _truncation_projection_routing(
    projection: CandidateReviewTruncationProjection,
) -> dict[str, object]:
    return {
        "candidate_review_truncation_projection_sha256": projection.evidence_sha256,
        "candidate_review_truncation_termination": projection.termination.value,
        "candidate_review_truncation_findings_state": projection.findings_state.value,
        "candidate_review_truncation_surface_reviews_state": (
            projection.surface_reviews_state.value
        ),
        "candidate_review_truncation_summary_state": projection.summary_state.value,
        "candidate_review_truncation_stream_integrity_valid": projection.stream_integrity_valid,
        "candidate_review_truncation_document_complete": projection.document_complete,
        "candidate_review_truncation_declared_finding_count": projection.declared_finding_count,
        "candidate_review_truncation_declared_surface_review_count": (
            projection.declared_surface_review_count
        ),
        "candidate_review_truncation_observed_frame_count": projection.observed_frame_count,
        "candidate_review_truncation_observed_finding_frame_count": (
            projection.observed_finding_frame_count
        ),
        "candidate_review_truncation_observed_surface_review_frame_count": (
            projection.observed_surface_review_frame_count
        ),
        "candidate_review_truncation_accepted_frame_count": len(projection.accepted_frames),
        "candidate_review_truncation_accepted_finding_count": (projection.accepted_finding_count),
        "candidate_review_truncation_accepted_surface_review_count": (
            projection.accepted_surface_review_count
        ),
        "candidate_review_truncation_invalid_frame_count": projection.invalid_frame_count,
        "candidate_review_truncation_credit_eligible": False,
        "candidate_review_truncation_authority_eligible": False,
    }


def _typed_usage(
    *,
    activation: SchedulerTruncationRecoveryChildActivation,
    validation_status: ModelRequestValidationStatus,
    status: str,
    response_sha256: str,
    validated_response_sha256: str | None,
    finish_reason: str,
    native_finish_reason: str | None,
    completion_tokens: int = 10,
    cost_usd_exact: str = "0.05",
    schema_sha256: str | None = None,
    request_limit_scope: str | None = None,
    request_limit_count_before: int | None = None,
    request_limit_maximum: int | None = None,
    envelope: CandidateReviewTruncatedEnvelopeEvidence | None = None,
    projection: CandidateReviewTruncationProjection | None = None,
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.MOCK,
    request_role: str | None = None,
    exact_model_id: str | None = None,
) -> UsageRecord:
    assert activation.request_role is not None
    assert activation.requested_model is not None
    role = request_role or activation.request_role
    model_id = exact_model_id or activation.requested_model
    provider_name = "Synthetic Provider"
    provider_endpoint = "synthetic-provider/endpoint"
    generation_id = f"generation-{activation.child_task_id[-32:]}"
    router_metadata_sha256 = _digest(f"router:{activation.child_task_id}")
    exact_schema = schema_sha256 or activation.response_schema_sha256
    instant = datetime(2026, 8, 18, tzinfo=UTC)
    context = ContextRequestEvidence.build(
        request_id=activation.child_logical_request_id,
        request_role=role,
        context_role=role,
        byte_budget=64,
        declared_bytes_used=32,
        rendered_bytes=32,
        source_bytes=16,
        configured_maximum_source_tokens_per_request=64,
        effective_source_byte_ceiling=64,
        rendered_sha256=activation.user_prompt_sha256,
    )
    routing: dict[str, object] = {
        "generation_id": generation_id,
        "generation_header_id": generation_id,
        "provider": provider_name,
        "selected_model": model_id,
        "selected_provider_endpoint": provider_endpoint,
        "selected_provider_identity": "synthetic-provider",
        "selected_provider_name": provider_name,
        "canonical_model": model_id,
        "router_strategy": "direct",
        "router_attempt": 1,
        "router_attempt_count": 1,
        "router_pipeline": [],
        "router_metadata_sha256": router_metadata_sha256,
        "provider_policy_sha256": _digest(f"provider-policy:{activation.child_task_id}"),
        "endpoint_snapshot_sha256": _digest(f"endpoint:{activation.child_task_id}"),
        "output_capability_sha256": _digest(f"output:{activation.child_task_id}"),
        "provider_fallbacks_allowed": False,
        "provider_fallback_used": False,
        "host_model_fallback_used": False,
        "certification_request": False,
        "finish_reason": finish_reason,
        "native_finish_reason": native_finish_reason,
        "schema_sha256": exact_schema,
        "validation_status": validation_status.value,
        "zdr_requested": True,
        "data_collection": "deny",
        "repair_used": False,
        "repair_request": False,
        "request_started_at": instant.isoformat(),
        "request_ended_at": instant.isoformat(),
        "latency_ms": 0,
        "context_request_evidence": context.model_dump(mode="json"),
        "context_request_evidence_sha256": context.evidence_sha256,
    }
    if envelope is not None:
        routing.update(
            {
                "candidate_review_truncated_envelope_evidence": envelope.model_dump(mode="json"),
                "candidate_review_truncated_envelope_sha256": envelope.evidence_sha256,
            }
        )
    if projection is not None:
        routing.update(_truncation_projection_routing(projection))
    base = UsageRecord(
        request_id=activation.child_logical_request_id,
        role=role,
        execution_evidence=execution_evidence,
        requested_model=model_id,
        returned_model=model_id,
        actual_model=model_id,
        provider=provider_name,
        model_family="synthetic-recovery-lineage",
        timestamp=instant,
        prompt_tokens=5,
        completion_tokens=completion_tokens,
        total_tokens=5 + completion_tokens,
        reported_cost_usd=float(cost_usd_exact),
        accounted_cost_usd=float(cost_usd_exact),
        reported_cost_usd_exact=cost_usd_exact,
        accounted_cost_usd_exact=cost_usd_exact,
        routing=routing,
        prompt_sha256=activation.provider_prompt_sha256,
        user_prompt_sha256=activation.user_prompt_sha256,
        response_sha256=response_sha256,
        validated_response_sha256=validated_response_sha256,
        request_body_sha256=activation.actual_input_sha256,
        schema_sha256=exact_schema,
        openrouter_generation_id=generation_id,
        configured_provider_endpoints=[provider_endpoint],
        actual_provider_endpoint=provider_endpoint,
        started_at=instant,
        ended_at=instant,
        latency_ms=0,
        finish_reason=finish_reason,
        reasoning_tokens=0,
        reasoning_evidence=None,
        cached_tokens=0,
        retry_count=0,
        provider_error_classification=None,
        validation_status=validation_status,
        identity_strength=ModelIdentityStrength.UNBOUND,
        fallback_used=False,
        substitution_detected=False,
        status=status,
        attempts=1,
    )
    routed = (
        bind_synthetic_usage_identity(base)
        if validation_status is ModelRequestValidationStatus.VALID
        else base.model_copy(update={"routing": synthetic_token_plan_routing(base, routing)})
    )
    token_routing = routed.routing
    token_plan_sha256 = token_routing["request_token_plan_sha256"]
    assert isinstance(token_plan_sha256, str)
    reservation = AtomicRequestLimitReservationEvidence.build(
        request_id=routed.request_id,
        exact_model_id=routed.requested_model,
        role=routed.role,
        request_token_plan_sha256=token_plan_sha256,
        request_limit_scope=request_limit_scope or activation.request_limit_id,
        request_limit_count_before=(
            activation.request_limit_count_before_child
            if request_limit_count_before is None
            else request_limit_count_before
        ),
        request_limit_maximum=(
            activation.request_limit_maximum
            if request_limit_maximum is None
            else request_limit_maximum
        ),
    )
    finalized = UsageRecord.model_validate(
        {
            **routed.model_dump(mode="python"),
            "routing": {
                **token_routing,
                "atomic_request_limit_reservations": [reservation.model_dump(mode="json")],
                "atomic_request_limit_reservation_sha256s": [reservation.evidence_sha256],
                "atomic_request_limit_reservation": reservation.model_dump(mode="json"),
                "atomic_request_limit_reservation_sha256": reservation.evidence_sha256,
            },
        }
    )
    return reattest_synthetic_real_usage(finalized)


def _surface_ids_sha256(surface_ids: tuple[str, ...]) -> str:
    return hashlib.sha256(
        json.dumps(
            list(surface_ids),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _success_custody(
    *,
    child: TruncationRecoveryChildPlan,
    activation: SchedulerTruncationRecoveryChildActivation,
    surface_manifest: SchedulerTruncationRecoveryRequestedSurfaceManifest,
    surfaces: tuple[ModelSurfaceReviewRecord, ...],
    cost_usd_exact: str = "0.05",
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.MOCK,
    request_role: str | None = None,
    exact_model_id: str | None = None,
) -> tuple[
    UsageRecord,
    CandidateReviewNormalizationEvidence,
    CandidateReviewBatch,
    tuple[ModelSurfaceReviewRequest, ...],
    ModelSurfaceReviewArtifact,
]:
    requests_by_id = {request.surface_id: request for request in surface_manifest.requests}
    records_by_id = {
        record.surface_id: (
            ModelSurfaceReviewRecord.model_validate(
                {**record.model_dump(mode="python"), "review_role": request_role}
            )
            if request_role is not None
            else record
        )
        for record in surfaces
    }
    requests = tuple(requests_by_id[surface_id] for surface_id in child.surface_ids)
    batch = CandidateReviewBatch(
        findings=[],
        surface_reviews=tuple(records_by_id[surface_id] for surface_id in child.surface_ids),
    )
    normalized_batch, normalization = normalize_candidate_review_document(
        frame_candidate_review_batch(batch),
        request_id=child.child_logical_request_id,
    )
    usage = _typed_usage(
        activation=activation,
        validation_status=ModelRequestValidationStatus.VALID,
        status="success",
        response_sha256=_digest(f"success-response:{child.child_task_id}"),
        validated_response_sha256=normalization.wire_validated_response_sha256,
        finish_reason="stop",
        native_finish_reason=None,
        cost_usd_exact=cost_usd_exact,
        execution_evidence=execution_evidence,
        request_role=request_role,
        exact_model_id=exact_model_id,
    )
    artifact_values: dict[str, object] = {
        "schema_version": "1.1",
        "request_id": child.child_logical_request_id,
        "review_role": usage.role,
        "requested_surface_ids": child.surface_ids,
        "requested_surface_ids_sha256": _surface_ids_sha256(child.surface_ids),
        "requested_surface_manifest_sha256": (
            ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(requests)
        ),
        "rendered_context_sha256": activation.user_prompt_sha256,
        "prompt_sha256": activation.provider_prompt_sha256,
        "response_sha256": usage.response_sha256,
        "validated_response_sha256": usage.validated_response_sha256,
        "response_schema_sha256": activation.response_schema_sha256,
        "normalized_response_sha256": normalization.normalized_batch_sha256,
        "normalization_evidence": normalization.model_dump(mode="json"),
        "normalized_response": normalized_batch.model_dump(mode="json"),
        "records": [record.model_dump(mode="json") for record in normalized_batch.surface_reviews],
    }
    artifact_values["artifact_sha256"] = ModelSurfaceReviewArtifact.calculate_artifact_sha256(
        artifact_values
    )
    artifact = ModelSurfaceReviewArtifact.model_validate(artifact_values)
    return usage, normalization, normalized_batch, requests, artifact


def _truncated_custody(
    *,
    child: TruncationRecoveryChildPlan,
    activation: SchedulerTruncationRecoveryChildActivation,
    surfaces: tuple[ModelSurfaceReviewRecord, ...],
) -> tuple[
    UsageRecord,
    CandidateReviewTruncatedEnvelopeEvidence,
    CandidateReviewTruncationProjection,
]:
    records_by_id = {record.surface_id: record for record in surfaces}
    child_records = tuple(records_by_id[surface_id] for surface_id in child.surface_ids)
    projection = _projection(child_records, retained_count=0)
    assert activation.requested_model is not None
    model_id = activation.requested_model
    provider_name = "Synthetic Provider"
    provider_endpoint = "synthetic-provider/endpoint"
    generation_id = f"generation-{activation.child_task_id[-32:]}"
    envelope = seal_candidate_review_truncated_envelope_evidence(
        logical_request_id=child.child_logical_request_id,
        generation_id=generation_id,
        generation_header_id=generation_id,
        requested_model=model_id,
        returned_model=model_id,
        selected_model=model_id,
        response_provider_identity="synthetic-provider",
        selected_provider_endpoint=provider_endpoint,
        selected_provider_identity="synthetic-provider",
        selected_provider_name=provider_name,
        router_metadata_sha256=_digest(f"router:{activation.child_task_id}"),
        finish_reason=projection.finish_reason,
        native_finish_reason=projection.native_finish_reason,
        wire_schema_sha256=projection.wire_schema_sha256,
        response_sha256=projection.original_response_sha256,
    )
    usage = _typed_usage(
        activation=activation,
        validation_status=ModelRequestValidationStatus.TRUNCATED,
        status="rejected_truncated_response",
        response_sha256=projection.original_response_sha256,
        validated_response_sha256=None,
        finish_reason=projection.finish_reason,
        native_finish_reason=projection.native_finish_reason,
        envelope=envelope,
        projection=projection,
    )
    return usage, envelope, projection


def _nested_plan_for_typed_truncated_child(
    *,
    root: SchedulerTruncationRecoveryFamilyRoot,
    root_plan: TruncationRecoveryPlan,
    child: TruncationRecoveryChildPlan,
    activation: SchedulerTruncationRecoveryChildActivation,
    result: SchedulerTruncationRecoveryChildResult,
    projection: CandidateReviewTruncationProjection,
    other_direct_results: tuple[SchedulerTruncationRecoveryChildResult, ...],
    unresolved_direct_children: tuple[TruncationRecoveryChildPlan, ...] = (),
) -> TruncationRecoveryPlan:
    assert result.provider_attempt_evidence_sha256 is not None
    claimed = TruncationRecoveryParentBinding.build(
        campaign_id=child.campaign_id,
        pass_plan_id=child.pass_plan_id,
        parent_task_id=child.child_task_id,
        parent_logical_request_id=child.child_logical_request_id,
        parent_task_plan_sha256=child.child_plan_sha256,
        parent_activation_sha256=activation.entry_sha256,
        provider_attempt_evidence_sha256=result.provider_attempt_evidence_sha256,
        truncation_projection_sha256=projection.evidence_sha256,
        requested_surface_manifest_sha256=child.requested_surface_manifest_sha256,
        requested_surface_ids=child.surface_ids,
        retained_surface_ids=(),
        channel_bindings=_placeholder_channels(projection),
        current_depth=child.depth,
        parent_path=child.path,
    )
    parent = rebuild_truncation_recovery_parent_from_projection(
        claimed_parent=claimed,
        projection=projection,
    )
    prior_cost = (
        Decimal(root_plan.resources.accounted_usd_before_parent_exact)
        + Decimal(root_plan.resources.parent_accounted_cost_usd_exact)
        + sum(
            (Decimal(item.accounted_cost_usd_exact) for item in other_direct_results),
            start=Decimal("0"),
        )
        + sum(
            (Decimal(item.reserved_usd_exact) for item in unresolved_direct_children),
            start=Decimal("0"),
        )
    )
    prior_cost_text = format(prior_cost, "f")
    if "." in prior_cost_text:
        prior_cost_text = prior_cost_text.rstrip("0").rstrip(".")
    resources = TruncationRecoveryResourceBudget.build(
        campaign_cap_usd_exact=root_plan.resources.campaign_cap_usd_exact,
        accounted_usd_before_parent_exact=prior_cost_text,
        parent_accounted_cost_usd_exact=result.accounted_cost_usd_exact,
        child_reserved_usd_exact=root_plan.resources.child_reserved_usd_exact,
        recovery_requests_consumed=root.request_count_after_family,
        provider_attempts_before_parent=(
            root_plan.resources.provider_attempts_before_parent
            + root_plan.resources.parent_provider_attempts
            + sum(item.accounted_provider_attempts for item in other_direct_results)
            + sum(item.reserved_provider_attempts for item in unresolved_direct_children)
        ),
        parent_provider_attempts=result.accounted_provider_attempts,
        child_provider_attempts=root_plan.resources.child_provider_attempts,
        completion_tokens_before_parent=(
            root_plan.resources.completion_tokens_before_parent
            + root_plan.resources.parent_completion_tokens
            + sum(item.accounted_completion_tokens for item in other_direct_results)
            + sum(item.reserved_completion_tokens for item in unresolved_direct_children)
        ),
        parent_completion_tokens=result.accounted_completion_tokens,
        child_completion_tokens=root_plan.resources.child_completion_tokens,
    )
    return plan_truncation_recovery(parent=parent, resources=resources)


@dataclass(frozen=True)
class _RecursivePublicProjectionBase:
    manifest: SchedulerCampaignManifest
    model_requests: tuple[SchedulerModelRequestEvidence, ...]
    provider_attempts: tuple[SchedulerProviderAttemptEvidence, ...]
    entries: tuple[SchedulerTruncationRecoveryEntry, ...]
    root_family: SchedulerTruncationRecoveryFamilyRoot
    nested_family: SchedulerTruncationRecoveryFamilyRoot
    truncated_child: TruncationRecoveryChildPlan
    successful_child: TruncationRecoveryChildPlan
    truncated_result: SchedulerTruncationRecoveryChildResult
    successful_result: SchedulerTruncationRecoveryChildResult
    nested_child: TruncationRecoveryChildPlan
    nested_activation: SchedulerTruncationRecoveryChildActivation
    nested_result: SchedulerTruncationRecoveryChildResult
    nested_closure: SchedulerTruncationRecoveryFamilyClosure
    root_closure: SchedulerTruncationRecoveryFamilyClosure
    wrong_pass_plan_id: str


def _recursive_public_projection_base(path: Path) -> _RecursivePublicProjectionBase:
    journal, plan, projection, surfaces, surface_manifest = _journal_with_truncated_parent(
        path,
        request_limit_maximum=5,
        typed_parent_attempt=True,
    )
    root = journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    truncated_child, successful_child = plan.children
    truncated_activation = _activate_child(journal, truncated_child.child_task_id)
    journal.mark_truncation_recovery_child_dispatched(truncated_child.child_task_id)
    failed_usage, envelope, nested_projection = _truncated_custody(
        child=truncated_child,
        activation=truncated_activation,
        surfaces=surfaces,
    )
    truncated_result = journal.record_truncation_recovery_child_truncated(
        truncated_child.child_task_id,
        failed_usage_record=failed_usage,
        truncated_envelope_evidence=envelope,
        truncation_projection=nested_projection,
    )

    successful_activation = _activate_child(journal, successful_child.child_task_id)
    journal.mark_truncation_recovery_child_dispatched(successful_child.child_task_id)
    successful_custody = _success_custody(
        child=successful_child,
        activation=successful_activation,
        surface_manifest=surface_manifest,
        surfaces=surfaces,
    )
    successful_result = journal.record_truncation_recovery_child_success(
        successful_child.child_task_id,
        usage_record=successful_custody[0],
        normalization_evidence=successful_custody[1],
        normalized_batch=successful_custody[2],
        requested_surface_requests=successful_custody[3],
        output_artifact=successful_custody[4],
    )
    nested_plan = _nested_plan_for_typed_truncated_child(
        root=root,
        root_plan=plan,
        child=truncated_child,
        activation=truncated_activation,
        result=truncated_result,
        projection=nested_projection,
        other_direct_results=(successful_result,),
    )
    nested_family = journal.open_truncation_recovery_family(
        recovery_plan=nested_plan,
        truncation_projection=nested_projection,
        requested_surface_manifest=surface_manifest,
    )
    nested_activations: list[SchedulerTruncationRecoveryChildActivation] = []
    nested_results: list[SchedulerTruncationRecoveryChildResult] = []
    for child in nested_plan.children:
        activation = _activate_child(journal, child.child_task_id)
        nested_activations.append(activation)
        journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
        custody = _success_custody(
            child=child,
            activation=activation,
            surface_manifest=surface_manifest,
            surfaces=surfaces,
        )
        nested_results.append(
            journal.record_truncation_recovery_child_success(
                child.child_task_id,
                usage_record=custody[0],
                normalization_evidence=custody[1],
                normalized_batch=custody[2],
                requested_surface_requests=custody[3],
                output_artifact=custody[4],
            )
        )
    nested_closure = journal.seal_truncation_recovery_family(nested_family.family_id)
    root_closure = journal.seal_truncation_recovery_family(root.family_id)
    model_requests = journal.model_requests
    provider_attempts = journal.provider_attempts
    entries = journal.truncation_recovery_entries
    assert (
        len(
            build_scheduler_truncation_recovery_model_request_evidence(
                manifest=journal.manifest,
                model_requests=model_requests,
                truncation_recovery_entries=entries,
                provider_attempts=provider_attempts,
            )
        )
        == 4
    )
    base = _RecursivePublicProjectionBase(
        manifest=journal.manifest,
        model_requests=model_requests,
        provider_attempts=provider_attempts,
        entries=entries,
        root_family=root,
        nested_family=nested_family,
        truncated_child=truncated_child,
        successful_child=successful_child,
        truncated_result=truncated_result,
        successful_result=successful_result,
        nested_child=nested_plan.children[0],
        nested_activation=nested_activations[0],
        nested_result=nested_results[0],
        nested_closure=nested_closure,
        root_closure=root_closure,
        wrong_pass_plan_id=journal.plans[0].pass_plan_id,
    )
    journal.close()
    return base


def _reseal_recovery_chain(
    entries: tuple[SchedulerTruncationRecoveryEntry, ...],
) -> tuple[SchedulerTruncationRecoveryEntry, ...]:
    resealed: list[SchedulerTruncationRecoveryEntry] = []
    previous_entry_sha256: str | None = None
    for entry_index, entry in enumerate(entries):
        payload = entry.model_dump(mode="json")
        payload["entry_index"] = entry_index
        payload["previous_entry_sha256"] = previous_entry_sha256
        payload["entry_sha256"] = _canonical_payload_sha256(
            {key: value for key, value in payload.items() if key != "entry_sha256"}
        )
        entry_type = SCHEDULER_TRUNCATION_RECOVERY_ENTRY_TYPES[
            SchedulerTruncationRecoveryEntryKind(payload["entry_kind"])
        ]
        frozen = entry_type.model_validate_json(
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            strict=True,
        )
        resealed.append(frozen)
        previous_entry_sha256 = frozen.entry_sha256
    return tuple(resealed)


def _replace_recovery_entry(
    entries: tuple[SchedulerTruncationRecoveryEntry, ...],
    *,
    original: SchedulerTruncationRecoveryEntry,
    replacement: SchedulerTruncationRecoveryEntry,
) -> tuple[SchedulerTruncationRecoveryEntry, ...]:
    return tuple(replacement if entry == original else entry for entry in entries)


def _open_dispatched_child(
    path: Path,
    *,
    parent_cost_usd_exact: str = "0",
    parent_role: str | None = None,
) -> tuple[
    SchedulerJournal,
    TruncationRecoveryChildPlan,
    SchedulerTruncationRecoveryChildActivation,
    SchedulerTruncationRecoveryChildDispatch,
    tuple[ModelSurfaceReviewRecord, ...],
    SchedulerTruncationRecoveryRequestedSurfaceManifest,
]:
    journal, plan, projection, surfaces, surface_manifest = _journal_with_truncated_parent(
        path,
        parent_cost_usd_exact=parent_cost_usd_exact,
        parent_role=parent_role,
    )
    journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    child = plan.children[0]
    activation = _activate_child(journal, child.child_task_id)
    dispatch = journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
    return journal, child, activation, dispatch, surfaces, surface_manifest


def _specialist_success_outcome(
    *,
    usage: UsageRecord,
    requests: tuple[ModelSurfaceReviewRequest, ...],
    artifact: ModelSurfaceReviewArtifact,
) -> SpecialistAcceptedOutcome:
    context_sha256 = usage.routing.get("context_request_evidence_sha256")
    assert isinstance(context_sha256, str)
    assert usage.validated_response_sha256 is not None
    return SpecialistAcceptedOutcome.build(
        request_id=usage.request_id,
        specialist_role=usage.role.removeprefix("specialist:"),
        request_role=usage.role,
        outcome_kind=SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW,
        validated_response_sha256=usage.validated_response_sha256,
        context_request_evidence_sha256=context_sha256,
        requested_surface_count=len(requests),
        surface_review_artifact_sha256=artifact.artifact_sha256,
    )


def _replace_recovery_request_limit(
    usage: UsageRecord,
    *,
    activation: SchedulerTruncationRecoveryChildActivation,
    request_limit_scope: str | None = None,
    request_limit_count_before: int | None = None,
    request_limit_maximum: int | None = None,
) -> UsageRecord:
    token_plan_sha256 = usage.routing["request_token_plan_sha256"]
    assert isinstance(token_plan_sha256, str)
    reservation = AtomicRequestLimitReservationEvidence.build(
        request_id=usage.request_id,
        exact_model_id=usage.requested_model,
        role=usage.role,
        request_token_plan_sha256=token_plan_sha256,
        request_limit_scope=request_limit_scope or activation.request_limit_id,
        request_limit_count_before=(
            activation.request_limit_count_before_child
            if request_limit_count_before is None
            else request_limit_count_before
        ),
        request_limit_maximum=(
            activation.request_limit_maximum
            if request_limit_maximum is None
            else request_limit_maximum
        ),
    )
    return UsageRecord.model_validate(
        {
            **usage.model_dump(mode="python"),
            "routing": {
                **usage.routing,
                "atomic_request_limit_reservations": [reservation.model_dump(mode="json")],
                "atomic_request_limit_reservation_sha256s": [reservation.evidence_sha256],
                "atomic_request_limit_reservation": reservation.model_dump(mode="json"),
                "atomic_request_limit_reservation_sha256": reservation.evidence_sha256,
            },
        }
    )


def _canonical_payload_sha256(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _reseal_result_payload(payload: dict[str, object]) -> dict[str, object]:
    resealed = dict(payload)
    resealed["entry_sha256"] = _canonical_payload_sha256(
        {key: value for key, value in resealed.items() if key != "entry_sha256"}
    )
    return resealed


def test_family_root_rebuilds_typed_projection_without_mutating_pass_inventory(
    tmp_path: Path,
) -> None:
    journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(
        tmp_path / "projection-root"
    )
    frozen_task_ids = tuple(task.task_id for item in journal.plans for task in item.tasks)

    wrong_plan = _root_plan(
        journal,
        projection=projection,
        surface_manifest=surface_manifest,
        wrong_findings_state=True,
    )
    with pytest.raises(ValueError, match="inconsistent"):
        journal.open_truncation_recovery_family(
            recovery_plan=wrong_plan,
            truncation_projection=projection,
            requested_surface_manifest=surface_manifest,
        )
    assert journal.truncation_recovery_entries == ()

    family = journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )

    assert family.truncation_projection == projection
    assert family.recovery_plan.parent == rebuild_truncation_recovery_parent_from_projection(
        claimed_parent=family.recovery_plan.parent,
        projection=projection,
    )
    assert tuple(task.task_id for item in journal.plans for task in item.tasks) == frozen_task_ids
    assert family.request_limit_id == plan.parent.parent_logical_request_id
    assert family.request_limit_binding.parent_request_limit_count_after == 1
    assert family.request_limit_binding.request_limit_maximum == 10
    assert family.request_limit_count_before_family == 1
    assert family.request_limit_count_after_family == 3
    assert family.provider_dispatch_authorized is False
    assert family.review_credit_authorized is False
    assert family.coverage_credit_authorized is False
    assert family.completion_authorized is False
    assert family.release_authorized is False

    journal.close()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("campaign_cap_usd_exact", "249"),
        ("accounted_usd_before_parent_exact", "0.01"),
        ("parent_accounted_cost_usd_exact", "0.01"),
        ("recovery_requests_consumed", 1),
        ("provider_attempts_before_parent", 2),
        ("parent_provider_attempts", 2),
        ("completion_tokens_before_parent", 1),
        ("parent_completion_tokens", 4),
    ),
)
def test_family_root_rejects_each_resealed_resource_scalar_not_in_durable_accounting(
    tmp_path: Path,
    field: str,
    value: str | int,
) -> None:
    journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(
        tmp_path / f"resource-drift-{field}"
    )
    resources = plan.resources
    resource_values: dict[str, str | int] = {
        "campaign_cap_usd_exact": resources.campaign_cap_usd_exact,
        "accounted_usd_before_parent_exact": resources.accounted_usd_before_parent_exact,
        "parent_accounted_cost_usd_exact": resources.parent_accounted_cost_usd_exact,
        "child_reserved_usd_exact": resources.child_reserved_usd_exact,
        "recovery_requests_consumed": resources.recovery_requests_consumed,
        "provider_attempts_before_parent": resources.provider_attempts_before_parent,
        "parent_provider_attempts": resources.parent_provider_attempts,
        "child_provider_attempts": resources.child_provider_attempts,
        "completion_tokens_before_parent": resources.completion_tokens_before_parent,
        "parent_completion_tokens": resources.parent_completion_tokens,
        "child_completion_tokens": resources.child_completion_tokens,
    }
    resource_values[field] = value
    drifted_resources = TruncationRecoveryResourceBudget.build(
        campaign_cap_usd_exact=str(resource_values["campaign_cap_usd_exact"]),
        accounted_usd_before_parent_exact=str(resource_values["accounted_usd_before_parent_exact"]),
        parent_accounted_cost_usd_exact=str(resource_values["parent_accounted_cost_usd_exact"]),
        child_reserved_usd_exact=str(resource_values["child_reserved_usd_exact"]),
        recovery_requests_consumed=int(resource_values["recovery_requests_consumed"]),
        provider_attempts_before_parent=int(resource_values["provider_attempts_before_parent"]),
        parent_provider_attempts=int(resource_values["parent_provider_attempts"]),
        child_provider_attempts=int(resource_values["child_provider_attempts"]),
        completion_tokens_before_parent=int(resource_values["completion_tokens_before_parent"]),
        parent_completion_tokens=int(resource_values["parent_completion_tokens"]),
        child_completion_tokens=int(resource_values["child_completion_tokens"]),
    )
    drifted_plan = plan_truncation_recovery(
        parent=plan.parent,
        resources=drifted_resources,
    )

    with pytest.raises(
        ValueError,
        match=r"resources differ from durable accounting|family root is inconsistent",
    ):
        journal.open_truncation_recovery_family(
            recovery_plan=drifted_plan,
            truncation_projection=projection,
            requested_surface_manifest=surface_manifest,
        )
    assert journal.truncation_recovery_entries == ()
    journal.close()


def test_activation_only_replays_but_dispatched_child_becomes_uncertain(
    tmp_path: Path,
) -> None:
    path = tmp_path / "crash-boundaries"
    journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(path)
    journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    child = plan.children[0]
    _activate_child(journal, child.child_task_id)
    activation_evidence = journal.journal_evidence
    journal.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=activation_evidence,
    )
    assert resumed.dispatchable_truncation_recovery_child_ids == (child.child_task_id,)
    resumed.mark_truncation_recovery_child_dispatched(child.child_task_id)
    dispatch_evidence = resumed.journal_evidence
    resumed.close()

    recovered = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=dispatch_evidence,
    )
    assert recovered.dispatchable_truncation_recovery_child_ids == ()
    assert recovered.uncertain_truncation_recovery_child_ids == (child.child_task_id,)
    result = recovered._truncation_recovery_indexes.results[child.child_task_id]
    assert result.accounted_provider_attempts == child.reserved_provider_attempts
    assert result.accounted_completion_tokens == child.reserved_completion_tokens
    assert result.accounted_cost_usd_exact == child.reserved_usd_exact
    recovered_evidence = recovered.journal_evidence
    recovered_entries = recovered.truncation_recovery_entries
    assert recovered.local_journal_head_checkpoint == recovered_evidence
    with pytest.raises(ValueError, match="activated recovery child"):
        recovered.mark_truncation_recovery_child_dispatched(child.child_task_id)
    recovered.close()

    replayed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    assert replayed.truncation_recovery_entries == recovered_entries
    assert replayed.journal_evidence == recovered_evidence
    assert replayed.local_journal_head_checkpoint == recovered_evidence
    assert replayed.uncertain_truncation_recovery_child_ids == (child.child_task_id,)
    replayed.close()


@pytest.mark.parametrize("suffix_kind", ("preflight", "dispatch", "runtime_result", "closure"))
def test_local_head_checkpoint_rejects_each_deleted_recovery_suffix_before_recovery(
    tmp_path: Path,
    suffix_kind: str,
) -> None:
    path = tmp_path / f"deleted-{suffix_kind}-suffix"
    journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(path)
    family = journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    first_child = plan.children[0]
    _activate_child(journal, first_child.child_task_id)
    if suffix_kind == "preflight":
        journal.record_truncation_recovery_child_preflight_result(
            first_child.child_task_id,
            terminal_status=SchedulerTruncationRecoveryTerminalStatus.FAILED,
            terminal_evidence_sha256=_digest("deleted-preflight"),
        )
    elif suffix_kind in {"dispatch", "runtime_result"}:
        dispatch = journal.mark_truncation_recovery_child_dispatched(first_child.child_task_id)
        if suffix_kind == "runtime_result":
            journal.record_truncation_recovery_child_result(
                SchedulerTruncationRecoveryChildResult.build_runtime(
                    child=first_child,
                    dispatch=dispatch,
                    terminal_status=SchedulerTruncationRecoveryTerminalStatus.FAILED,
                    terminal_evidence_sha256=_digest("deleted-runtime-result"),
                    provider_attempt_evidence_sha256=_digest("deleted-runtime-attempt"),
                    accounted_provider_attempts=first_child.reserved_provider_attempts,
                    accounted_completion_tokens=first_child.reserved_completion_tokens,
                    accounted_cost_usd_exact=first_child.reserved_usd_exact,
                    entry_index=len(journal.truncation_recovery_entries),
                    previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
                )
            )
    else:
        journal.record_truncation_recovery_child_preflight_result(
            first_child.child_task_id,
            terminal_status=SchedulerTruncationRecoveryTerminalStatus.FAILED,
            terminal_evidence_sha256=_digest("closure-first-child"),
        )
        for child in plan.children[1:]:
            _activate_child(journal, child.child_task_id)
            journal.record_truncation_recovery_child_preflight_result(
                child.child_task_id,
                terminal_status=SchedulerTruncationRecoveryTerminalStatus.INVALID,
                terminal_evidence_sha256=_digest(f"closure:{child.child_task_id}"),
            )
        journal.seal_truncation_recovery_family(family.family_id)

    checkpoint = journal.local_journal_head_checkpoint
    assert checkpoint == journal.journal_evidence
    assert (path / "journal-head-checkpoint.json").is_file()
    recovery_files = sorted((path / "truncation-recovery").iterdir())
    expected_remaining_count = len(recovery_files) - 1
    journal.close()
    recovery_files[-1].unlink()

    with pytest.raises(ValueError, match="local journal-head checkpoint does not match"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )
    assert len(tuple((path / "truncation-recovery").iterdir())) == expected_remaining_count


def test_artifact_checkpoint_gap_fails_closed_instead_of_recovering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "checkpoint-gap"
    journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(path)
    journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    child = plan.children[0]
    _activate_child(journal, child.child_task_id)

    def fail_before_checkpoint_replace(
        _parent_descriptor: int,
        _leaf: str,
        _content: bytes,
    ) -> None:
        raise ValueError("synthetic checkpoint replacement interruption")

    monkeypatch.setattr(
        scheduler_module,
        "_replace_private_file",
        fail_before_checkpoint_replace,
    )
    with pytest.raises(ValueError, match="synthetic checkpoint replacement interruption"):
        journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
    journal.close()

    with pytest.raises(ValueError, match="local journal-head checkpoint does not match"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )


def test_family_root_rejects_success_usage_paired_with_a_truncated_result(
    tmp_path: Path,
) -> None:
    journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(
        tmp_path / "success-usage-parent",
        exact_truncation_usage=False,
    )
    retained_usage = journal.provider_attempts[0].usage_record
    assert retained_usage.validated_response_sha256 is not None
    assert retained_usage.status == "success"

    with pytest.raises(ValueError, match="truncated parent task"):
        journal.open_truncation_recovery_family(
            recovery_plan=plan,
            truncation_projection=projection,
            requested_surface_manifest=surface_manifest,
        )
    assert journal.truncation_recovery_entries == ()
    journal.close()


@pytest.mark.parametrize(
    ("retain_validated_hash", "wrong_truncation_status"),
    ((True, False), (False, True)),
)
def test_family_root_rejects_each_impossible_truncated_usage_shape(
    tmp_path: Path,
    *,
    retain_validated_hash: bool,
    wrong_truncation_status: bool,
) -> None:
    journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(
        tmp_path / f"invalid-truncated-parent-{retain_validated_hash}-{wrong_truncation_status}",
        retain_validated_hash=retain_validated_hash,
        wrong_truncation_status=wrong_truncation_status,
    )

    with pytest.raises(ValueError, match="truncated parent task"):
        journal.open_truncation_recovery_family(
            recovery_plan=plan,
            truncation_projection=projection,
            requested_surface_manifest=surface_manifest,
        )
    assert journal.truncation_recovery_entries == ()
    journal.close()


def test_nested_family_rejects_legacy_truncated_parent_before_mutation(
    tmp_path: Path,
) -> None:
    journal, plan, projection, surfaces, surface_manifest = _journal_with_truncated_parent(
        tmp_path / "recursive-family"
    )
    root = journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    child = next(item for item in plan.children if len(item.surface_ids) == 2)
    activation = _activate_child(journal, child.child_task_id)
    dispatch = journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
    by_id = {item.surface_id: item for item in surfaces}
    nested_surfaces = tuple(by_id[surface_id] for surface_id in child.surface_ids)
    nested_projection = _projection(nested_surfaces, retained_count=0)
    attempt_sha256 = _digest("nested-provider-attempt")
    result = SchedulerTruncationRecoveryChildResult.build_runtime(
        child=child,
        dispatch=dispatch,
        terminal_status=SchedulerTruncationRecoveryTerminalStatus.TRUNCATED,
        terminal_evidence_sha256=nested_projection.evidence_sha256,
        provider_attempt_evidence_sha256=attempt_sha256,
        accounted_provider_attempts=child.reserved_provider_attempts,
        accounted_completion_tokens=child.reserved_completion_tokens,
        accounted_cost_usd_exact=child.reserved_usd_exact,
        truncation_projection=nested_projection,
        entry_index=len(journal.truncation_recovery_entries),
        previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
    )
    journal.record_truncation_recovery_child_result(result)
    claimed_nested = TruncationRecoveryParentBinding.build(
        campaign_id=child.campaign_id,
        pass_plan_id=child.pass_plan_id,
        parent_task_id=child.child_task_id,
        parent_logical_request_id=child.child_logical_request_id,
        parent_task_plan_sha256=child.child_plan_sha256,
        parent_activation_sha256=activation.entry_sha256,
        provider_attempt_evidence_sha256=attempt_sha256,
        truncation_projection_sha256=nested_projection.evidence_sha256,
        requested_surface_manifest_sha256=child.requested_surface_manifest_sha256,
        requested_surface_ids=child.surface_ids,
        retained_surface_ids=(),
        channel_bindings=_placeholder_channels(nested_projection),
        current_depth=child.depth,
        parent_path=child.path,
    )
    nested_parent = rebuild_truncation_recovery_parent_from_projection(
        claimed_parent=claimed_nested,
        projection=nested_projection,
    )
    nested_plan = plan_truncation_recovery(
        parent=nested_parent,
        resources=_resources(
            recovery_requests_consumed=root.request_count_after_family,
            accounted_before=child.reserved_usd_exact,
            attempts_before=2,
            tokens_before=105,
            parent_tokens=child.reserved_completion_tokens,
            parent_cost=child.reserved_usd_exact,
        ),
    )

    before = journal.truncation_recovery_entries
    plans_before = journal.plans
    with pytest.raises(ValueError, match="differs from its truncated child"):
        journal.open_truncation_recovery_family(
            recovery_plan=nested_plan,
            truncation_projection=nested_projection,
            requested_surface_manifest=surface_manifest,
        )

    assert journal.truncation_recovery_entries == before
    assert journal.truncation_recovery_families == (root,)
    assert journal.plans == plans_before
    journal.close()


def test_nested_family_requires_other_root_child_typed_success_before_mutation(
    tmp_path: Path,
) -> None:
    journal, plan, projection, surfaces, surface_manifest = _journal_with_truncated_parent(
        tmp_path / "recursive-family-unfinished-sibling",
        request_limit_maximum=5,
    )
    root = journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    truncated_child, unfinished_child = plan.children
    activation = _activate_child(journal, truncated_child.child_task_id)
    journal.mark_truncation_recovery_child_dispatched(truncated_child.child_task_id)
    failed_usage, envelope, nested_projection = _truncated_custody(
        child=truncated_child,
        activation=activation,
        surfaces=surfaces,
    )
    result = journal.record_truncation_recovery_child_truncated(
        truncated_child.child_task_id,
        failed_usage_record=failed_usage,
        truncated_envelope_evidence=envelope,
        truncation_projection=nested_projection,
    )
    nested_plan = _nested_plan_for_typed_truncated_child(
        root=root,
        root_plan=plan,
        child=truncated_child,
        activation=activation,
        result=result,
        projection=nested_projection,
        other_direct_results=(),
        unresolved_direct_children=(unfinished_child,),
    )

    before = journal.truncation_recovery_entries
    with pytest.raises(ValueError, match="differs from its truncated child"):
        journal.open_truncation_recovery_family(
            recovery_plan=nested_plan,
            truncation_projection=nested_projection,
            requested_surface_manifest=surface_manifest,
        )
    assert journal.truncation_recovery_entries == before
    assert journal.truncation_recovery_families == (root,)
    journal.close()


def test_nested_family_rejects_specialist_root_before_mutation(tmp_path: Path) -> None:
    journal, plan, projection, surfaces, surface_manifest = _journal_with_truncated_parent(
        tmp_path / "recursive-family-specialist",
        request_limit_maximum=5,
        parent_role="specialist:access_control",
    )
    root = journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    truncated_child, direct_child = plan.children
    truncated_activation = _activate_child(journal, truncated_child.child_task_id)
    journal.mark_truncation_recovery_child_dispatched(truncated_child.child_task_id)
    failed_usage, envelope, nested_projection = _truncated_custody(
        child=truncated_child,
        activation=truncated_activation,
        surfaces=surfaces,
    )
    truncated_result = journal.record_truncation_recovery_child_truncated(
        truncated_child.child_task_id,
        failed_usage_record=failed_usage,
        truncated_envelope_evidence=envelope,
        truncation_projection=nested_projection,
    )

    direct_activation = _activate_child(journal, direct_child.child_task_id)
    journal.mark_truncation_recovery_child_dispatched(direct_child.child_task_id)
    direct_custody = _success_custody(
        child=direct_child,
        activation=direct_activation,
        surface_manifest=surface_manifest,
        surfaces=surfaces,
    )
    outcome = _specialist_success_outcome(
        usage=direct_custody[0],
        requests=direct_custody[3],
        artifact=direct_custody[4],
    )
    direct_result = journal.record_truncation_recovery_child_success(
        direct_child.child_task_id,
        usage_record=direct_custody[0],
        normalization_evidence=direct_custody[1],
        normalized_batch=direct_custody[2],
        requested_surface_requests=direct_custody[3],
        output_artifact=direct_custody[4],
        specialist_accepted_outcome=outcome,
    )
    assert direct_result.schema_version == "1.2"
    nested_plan = _nested_plan_for_typed_truncated_child(
        root=root,
        root_plan=plan,
        child=truncated_child,
        activation=truncated_activation,
        result=truncated_result,
        projection=nested_projection,
        other_direct_results=(direct_result,),
    )

    before = journal.truncation_recovery_entries
    with pytest.raises(ValueError, match="differs from its truncated child"):
        journal.open_truncation_recovery_family(
            recovery_plan=nested_plan,
            truncation_projection=nested_projection,
            requested_surface_manifest=surface_manifest,
        )
    assert journal.truncation_recovery_entries == before
    assert journal.truncation_recovery_families == (root,)
    journal.close()


def test_one_generic_typed_truncated_child_closes_one_depth_two_family(
    tmp_path: Path,
) -> None:
    path = tmp_path / "one-level-recursive-family"
    journal, plan, projection, surfaces, surface_manifest = _journal_with_truncated_parent(
        path,
        request_limit_maximum=5,
        typed_parent_attempt=True,
    )
    root = journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    truncated_child, direct_child = plan.children

    truncated_activation = _activate_child(journal, truncated_child.child_task_id)
    journal.mark_truncation_recovery_child_dispatched(truncated_child.child_task_id)
    failed_usage, envelope, nested_projection = _truncated_custody(
        child=truncated_child,
        activation=truncated_activation,
        surfaces=surfaces,
    )
    assert nested_projection.findings_state is CandidateReviewChannelState.COMPLETE
    assert nested_projection.surface_reviews == ()
    truncated_result = journal.record_truncation_recovery_child_truncated(
        truncated_child.child_task_id,
        failed_usage_record=failed_usage,
        truncated_envelope_evidence=envelope,
        truncation_projection=nested_projection,
    )
    assert truncated_result.schema_version == "1.1"
    assert truncated_result.retained_surface_ids == ()

    direct_activation = _activate_child(journal, direct_child.child_task_id)
    journal.mark_truncation_recovery_child_dispatched(direct_child.child_task_id)
    direct_custody = _success_custody(
        child=direct_child,
        activation=direct_activation,
        surface_manifest=surface_manifest,
        surfaces=surfaces,
    )
    direct_result = journal.record_truncation_recovery_child_success(
        direct_child.child_task_id,
        usage_record=direct_custody[0],
        normalization_evidence=direct_custody[1],
        normalized_batch=direct_custody[2],
        requested_surface_requests=direct_custody[3],
        output_artifact=direct_custody[4],
    )

    nested_plan = _nested_plan_for_typed_truncated_child(
        root=root,
        root_plan=plan,
        child=truncated_child,
        activation=truncated_activation,
        result=truncated_result,
        projection=nested_projection,
        other_direct_results=(direct_result,),
    )
    nested_family = journal.open_truncation_recovery_family(
        recovery_plan=nested_plan,
        truncation_projection=nested_projection,
        requested_surface_manifest=surface_manifest,
    )
    assert nested_family.parent_family_id == root.family_id
    assert nested_plan.parent.current_depth == 1
    assert nested_plan.parent.parent_path == truncated_child.path
    assert all(child.parent_depth == 1 and child.depth == 2 for child in nested_plan.children)

    nested_results: list[SchedulerTruncationRecoveryChildResult] = []
    for grandchild in nested_plan.children:
        activation = _activate_child(journal, grandchild.child_task_id)
        journal.mark_truncation_recovery_child_dispatched(grandchild.child_task_id)
        custody = _success_custody(
            child=grandchild,
            activation=activation,
            surface_manifest=surface_manifest,
            surfaces=surfaces,
        )
        nested_results.append(
            journal.record_truncation_recovery_child_success(
                grandchild.child_task_id,
                usage_record=custody[0],
                normalization_evidence=custody[1],
                normalized_batch=custody[2],
                requested_surface_requests=custody[3],
                output_artifact=custody[4],
            )
        )

    nested_closure = journal.seal_truncation_recovery_family(nested_family.family_id)
    assert nested_closure.schema_version == "1.1"
    assert nested_closure.closure_status is SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
    assert nested_closure.nested_family_closure_sha256s == ()
    assert nested_closure.child_result_sha256s == tuple(
        result.entry_sha256 for result in nested_results
    )
    assert nested_closure.covered_unfinished_surface_ids == truncated_child.surface_ids

    root_closure = journal.seal_truncation_recovery_family(root.family_id)
    assert root_closure.schema_version == "1.2"
    assert (
        root_closure.closure_status
        is SchedulerTruncationRecoveryClosureStatus.RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING
    )
    assert root_closure.child_result_sha256s == (
        truncated_result.entry_sha256,
        direct_result.entry_sha256,
    )
    assert root_closure.nested_family_closure_sha256s == (nested_closure.entry_sha256,)
    assert root_closure.covered_unfinished_surface_ids == plan.parent.unfinished_surface_ids
    assert root_closure.closure_id == "scheduler-recovery-closure-" + scheduler_canonical_sha256(
        {
            "domain": "mmaudit.scheduler.truncation-recovery-closure.v2",
            "family_id": root.family_id,
            "family_root_sha256": root.entry_sha256,
            "child_result_sha256s": root_closure.child_result_sha256s,
            "nested_family_closure_sha256s": (nested_closure.entry_sha256,),
            "covered_unfinished_surface_ids": plan.parent.unfinished_surface_ids,
            "closure_status": root_closure.closure_status,
        }
    )
    assert root_closure.coverage_credit_authorized is False
    assert root_closure.completion_authorized is False
    activations = tuple(
        entry
        for entry in journal.truncation_recovery_entries
        if isinstance(entry, SchedulerTruncationRecoveryChildActivation)
    )
    assert tuple(item.global_request_ordinal for item in activations) == (1, 2, 3, 4)
    assert tuple(item.request_limit_count_before_child for item in activations) == (1, 2, 3, 4)

    public_requests = journal.recovery_model_requests
    expected_results = (truncated_result, direct_result, *nested_results)
    expected_request_ids = tuple(
        sorted(result.child_logical_request_id for result in expected_results)
    )
    expected_result_hashes = {result.entry_sha256 for result in expected_results}
    assert len(public_requests) == 4
    assert tuple(item.logical_request_id for item in public_requests) == expected_request_ids
    assert len({item.logical_request_id for item in public_requests}) == 4
    assert {item.child_result_entry_sha256 for item in public_requests} == (expected_result_hashes)
    assert all(item.promotion_entry_sha256 is None for item in public_requests)
    assert all(item.review_credit_authorized is False for item in public_requests)
    assert all(item.coverage_credit_authorized is False for item in public_requests)
    assert journal.artifact().recovery_model_requests == public_requests

    entries_before_forged_promotion = journal.truncation_recovery_entries
    with pytest.raises(ValueError, match=r"direct v1\.1 closure"):
        journal.promote_truncation_recovery_family(
            root.family_id,
            root_closure,  # type: ignore[arg-type]
        )
    assert journal.truncation_recovery_entries == entries_before_forged_promotion

    evidence = journal.journal_evidence
    journal.close()
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=evidence,
    )
    assert resumed._truncation_recovery_indexes.closures[root.family_id] == root_closure
    assert resumed._truncation_recovery_indexes.closures[nested_family.family_id] == nested_closure
    assert resumed.recovery_model_requests == public_requests
    assert resumed.artifact().recovery_model_requests == public_requests
    resumed.close()


@pytest.fixture(scope="module")
def recursive_public_projection_base(
    tmp_path_factory: pytest.TempPathFactory,
) -> _RecursivePublicProjectionBase:
    return _recursive_public_projection_base(
        tmp_path_factory.mktemp("recursive-public-projection") / "journal"
    )


def _assert_recursive_public_projection_rejected(
    base: _RecursivePublicProjectionBase,
    entries: tuple[SchedulerTruncationRecoveryEntry, ...],
) -> None:
    with pytest.raises(ValueError):
        build_scheduler_truncation_recovery_model_request_evidence(
            manifest=base.manifest,
            model_requests=base.model_requests,
            truncation_recovery_entries=entries,
            provider_attempts=base.provider_attempts,
        )


def test_recursive_public_projection_rejects_missing_dispatch(
    recursive_public_projection_base: _RecursivePublicProjectionBase,
) -> None:
    base = recursive_public_projection_base
    entries = tuple(
        entry
        for entry in base.entries
        if not (
            isinstance(entry, SchedulerTruncationRecoveryChildDispatch)
            and entry.entry_sha256 == base.nested_result.dispatch_sha256
        )
    )
    assert len(entries) == len(base.entries) - 1
    _assert_recursive_public_projection_rejected(base, _reseal_recovery_chain(entries))


def test_recursive_public_projection_rejects_nested_family_before_root_terminals(
    recursive_public_projection_base: _RecursivePublicProjectionBase,
) -> None:
    base = recursive_public_projection_base
    nested = next(
        entry
        for entry in base.entries
        if isinstance(entry, SchedulerTruncationRecoveryFamilyRoot)
        and entry.family_id == base.nested_family.family_id
    )
    without_nested = tuple(entry for entry in base.entries if entry != nested)
    reordered = (without_nested[0], nested, *without_nested[1:])
    assert nested.entry_index > max(
        result.entry_index for result in (base.truncated_result, base.successful_result)
    )
    forged = _reseal_recovery_chain(reordered)
    assert forged[1].entry_kind is SchedulerTruncationRecoveryEntryKind.FAMILY_ROOT
    _assert_recursive_public_projection_rejected(base, forged)


def _forged_nested_family(
    base: _RecursivePublicProjectionBase,
    *,
    association: str,
) -> SchedulerTruncationRecoveryFamilyRoot:
    original = base.nested_family
    parent = original.recovery_plan.parent
    recovery_plan = original.recovery_plan
    requested_surface_manifest = original.requested_surface_manifest
    parent_terminal_result_sha256 = original.parent_terminal_result_sha256
    if association == "terminal_result":
        parent_terminal_result_sha256 = base.successful_result.entry_sha256
    else:
        pass_plan_id = parent.pass_plan_id
        parent_path = parent.parent_path
        requested_surface_ids = parent.requested_surface_ids
        if association == "pass_plan":
            pass_plan_id = base.wrong_pass_plan_id
        elif association == "path":
            parent_path = "1" if parent.parent_path == "0" else "0"
        elif association == "surfaces":
            requested_surface_manifest = SchedulerTruncationRecoveryRequestedSurfaceManifest.build(
                request
                for request in original.requested_surface_manifest.requests
                if request.surface_id in set(parent.requested_surface_ids)
            )
        else:
            raise AssertionError(f"unknown nested association mutation: {association}")
        claimed = TruncationRecoveryParentBinding.build(
            campaign_id=parent.campaign_id,
            pass_plan_id=pass_plan_id,
            parent_task_id=parent.parent_task_id,
            parent_logical_request_id=parent.parent_logical_request_id,
            parent_task_plan_sha256=parent.parent_task_plan_sha256,
            parent_activation_sha256=parent.parent_activation_sha256,
            provider_attempt_evidence_sha256=parent.provider_attempt_evidence_sha256,
            truncation_projection_sha256=parent.truncation_projection_sha256,
            requested_surface_manifest_sha256=(
                requested_surface_manifest.requested_surface_manifest_sha256
            ),
            requested_surface_ids=requested_surface_ids,
            retained_surface_ids=(),
            channel_bindings=parent.channel_bindings,
            current_depth=parent.current_depth,
            parent_path=parent_path,
        )
        forged_parent = rebuild_truncation_recovery_parent_from_projection(
            claimed_parent=claimed,
            projection=original.truncation_projection,
        )
        recovery_plan = plan_truncation_recovery(
            parent=forged_parent,
            resources=original.recovery_plan.resources,
        )
    return SchedulerTruncationRecoveryFamilyRoot.build(
        request_limit_binding=original.request_limit_binding,
        family_index=original.family_index,
        parent_kind=SchedulerTruncationRecoveryParentKind.RECOVERY_CHILD,
        parent_family_id=base.root_family.family_id,
        parent_terminal_result_sha256=parent_terminal_result_sha256,
        requested_surface_manifest=requested_surface_manifest,
        truncation_projection=original.truncation_projection,
        recovery_plan=recovery_plan,
        request_count_before_family=original.request_count_before_family,
        request_limit_count_before_family=original.request_limit_count_before_family,
        entry_index=original.entry_index,
        previous_entry_sha256=original.previous_entry_sha256,
    )


@pytest.mark.parametrize(
    "association",
    ("pass_plan", "path", "surfaces", "terminal_result"),
)
def test_recursive_public_projection_rejects_wrong_nested_parent_association(
    recursive_public_projection_base: _RecursivePublicProjectionBase,
    association: str,
) -> None:
    base = recursive_public_projection_base
    forged_family = _forged_nested_family(base, association=association)
    replaced = _replace_recovery_entry(
        base.entries,
        original=base.nested_family,
        replacement=forged_family,
    )
    assert replaced != base.entries
    _assert_recursive_public_projection_rejected(base, _reseal_recovery_chain(replaced))


@pytest.mark.parametrize("duplicate_kind", ("runtime", "preflight"))
def test_recursive_public_projection_rejects_duplicate_terminal_for_one_child(
    recursive_public_projection_base: _RecursivePublicProjectionBase,
    duplicate_kind: str,
) -> None:
    base = recursive_public_projection_base
    duplicate: SchedulerTruncationRecoveryEntry
    if duplicate_kind == "runtime":
        duplicate = base.nested_result
    else:
        duplicate = SchedulerTruncationRecoveryChildPreflightResult.build(
            child=base.nested_child,
            activation=base.nested_activation,
            terminal_status=SchedulerTruncationRecoveryTerminalStatus.FAILED,
            terminal_evidence_sha256=_digest("forged-preflight-plus-runtime"),
            entry_index=len(base.entries),
            previous_entry_sha256=base.entries[-1].entry_sha256,
        )
    forged = _reseal_recovery_chain((*base.entries, duplicate))
    _assert_recursive_public_projection_rejected(base, forged)


def test_recursive_public_projection_rejects_second_nested_family_for_same_child(
    recursive_public_projection_base: _RecursivePublicProjectionBase,
) -> None:
    base = recursive_public_projection_base
    forged = _reseal_recovery_chain((*base.entries, base.nested_family))
    _assert_recursive_public_projection_rejected(base, forged)


def test_recursive_public_projection_rejects_wrong_derived_root_closure_coverage(
    recursive_public_projection_base: _RecursivePublicProjectionBase,
) -> None:
    base = recursive_public_projection_base
    forged_closure = SchedulerTruncationRecoveryFamilyClosure.build(
        family=base.root_family,
        closure_status=base.root_closure.closure_status,
        child_result_sha256s=base.root_closure.child_result_sha256s,
        nested_family_closure_sha256s=base.root_closure.nested_family_closure_sha256s,
        covered_unfinished_surface_ids=(base.root_closure.covered_unfinished_surface_ids[:-1]),
        entry_index=base.root_closure.entry_index,
        previous_entry_sha256=base.root_closure.previous_entry_sha256,
    )
    forged = _replace_recovery_entry(
        base.entries,
        original=base.root_closure,
        replacement=forged_closure,
    )
    assert validate_truncation_recovery_entry_chain(forged) == forged
    _assert_recursive_public_projection_rejected(base, forged)


@pytest.mark.parametrize("counter", ("family_index", "request_count", "request_limit"))
def test_recursive_public_projection_rejects_nested_family_counter_reset(
    recursive_public_projection_base: _RecursivePublicProjectionBase,
    counter: str,
) -> None:
    base = recursive_public_projection_base
    original = base.nested_family
    recovery_plan = original.recovery_plan
    family_index = original.family_index
    request_count_before_family = original.request_count_before_family
    request_limit_count_before_family = original.request_limit_count_before_family
    if counter == "family_index":
        family_index = base.root_family.family_index
    elif counter == "request_limit":
        request_limit_count_before_family = base.root_family.request_limit_count_before_family
    elif counter == "request_count":
        resources = original.recovery_plan.resources
        recovery_plan = plan_truncation_recovery(
            parent=original.recovery_plan.parent,
            resources=TruncationRecoveryResourceBudget.build(
                campaign_cap_usd_exact=resources.campaign_cap_usd_exact,
                accounted_usd_before_parent_exact=resources.accounted_usd_before_parent_exact,
                parent_accounted_cost_usd_exact=resources.parent_accounted_cost_usd_exact,
                child_reserved_usd_exact=resources.child_reserved_usd_exact,
                recovery_requests_consumed=0,
                provider_attempts_before_parent=resources.provider_attempts_before_parent,
                parent_provider_attempts=resources.parent_provider_attempts,
                child_provider_attempts=resources.child_provider_attempts,
                completion_tokens_before_parent=resources.completion_tokens_before_parent,
                parent_completion_tokens=resources.parent_completion_tokens,
                child_completion_tokens=resources.child_completion_tokens,
            ),
        )
        request_count_before_family = 0
    else:
        raise AssertionError(f"unknown nested counter mutation: {counter}")
    forged_family = SchedulerTruncationRecoveryFamilyRoot.build(
        request_limit_binding=original.request_limit_binding,
        family_index=family_index,
        parent_kind=original.parent_kind,
        parent_family_id=original.parent_family_id,
        parent_terminal_result_sha256=original.parent_terminal_result_sha256,
        requested_surface_manifest=original.requested_surface_manifest,
        truncation_projection=original.truncation_projection,
        recovery_plan=recovery_plan,
        request_count_before_family=request_count_before_family,
        request_limit_count_before_family=request_limit_count_before_family,
        entry_index=original.entry_index,
        previous_entry_sha256=original.previous_entry_sha256,
    )
    forged = _replace_recovery_entry(
        base.entries,
        original=original,
        replacement=forged_family,
    )
    _assert_recursive_public_projection_rejected(base, _reseal_recovery_chain(forged))


def test_lower_parent_request_limit_cannot_be_relaxed_by_recovery_cap(tmp_path: Path) -> None:
    journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(
        tmp_path / "low-parent-request-limit",
        request_limit_maximum=2,
    )

    with pytest.raises(ValueError, match=r"request_limit_count_after_family|request limit"):
        journal.open_truncation_recovery_family(
            recovery_plan=plan,
            truncation_projection=projection,
            requested_surface_manifest=surface_manifest,
        )
    assert journal.truncation_recovery_entries == ()
    journal.close()


def test_typed_success_retains_exact_non_authorizing_custody_and_reloads(
    tmp_path: Path,
) -> None:
    path = tmp_path / "typed-success"
    journal, child, activation, _dispatch, surfaces, surface_manifest = _open_dispatched_child(path)
    usage, normalization, batch, requests, artifact = _success_custody(
        child=child,
        activation=activation,
        surface_manifest=surface_manifest,
        surfaces=surfaces,
        cost_usd_exact="0.050000000000000000",
    )
    result = journal.record_truncation_recovery_child_success(
        child.child_task_id,
        usage_record=usage,
        normalization_evidence=normalization,
        normalized_batch=batch,
        requested_surface_requests=requests,
        output_artifact=artifact,
    )

    assert result.schema_version == "1.1"
    assert result.runtime_usage_record is usage
    assert result.runtime_normalization_evidence == normalization
    assert result.runtime_normalized_batch == batch
    assert result.runtime_requested_surface_requests == requests
    assert result.runtime_output_artifact == artifact
    assert result.accounted_provider_attempts == 1
    assert result.accounted_completion_tokens == usage.completion_tokens
    assert usage.accounted_cost_usd_exact == "0.050000000000000000"
    assert result.accounted_cost_usd_exact == "0.05"
    assert result.provider_dispatch_authorized is False
    assert result.review_credit_authorized is False
    assert result.coverage_credit_authorized is False
    recovery_requests = journal.recovery_model_requests
    assert len(recovery_requests) == 1
    recovery_request = recovery_requests[0]
    assert recovery_request.logical_request_id == usage.request_id
    assert recovery_request.terminal_status is SchedulerTerminalStatus.SUCCEEDED
    assert recovery_request.promotion_entry_sha256 is None
    assert recovery_request.runtime_completion_evidence_sha256 is not None
    assert recovery_request.validated_response_sha256 is not None
    assert recovery_request.normalization_evidence_sha256 is not None
    assert recovery_request.output_artifact_sha256 is not None
    assert journal.artifact().recovery_model_requests == recovery_requests
    assert result.completion_authorized is False
    assert result.release_authorized is False
    assert (
        SchedulerTruncationRecoveryChildResult.model_validate_json(
            result.model_dump_json(),
            strict=True,
        )
        == result
    )
    evidence = journal.journal_evidence
    journal.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=evidence,
    )
    assert resumed._truncation_recovery_indexes.results[child.child_task_id] == result
    assert resumed.local_journal_head_checkpoint == resumed.journal_evidence
    resumed.close()


def test_specialist_typed_success_requires_durable_outcome_and_projects_only_its_hash(
    tmp_path: Path,
) -> None:
    path = tmp_path / "typed-specialist-success"
    journal, child, activation, _dispatch, surfaces, surface_manifest = _open_dispatched_child(
        path,
        parent_role="specialist:access_control",
    )
    usage, normalization, batch, requests, artifact = _success_custody(
        child=child,
        activation=activation,
        surface_manifest=surface_manifest,
        surfaces=surfaces,
    )
    entries_before = journal.truncation_recovery_entries
    with pytest.raises(ValueError, match="lacks an accepted outcome"):
        journal.record_truncation_recovery_child_success(
            child.child_task_id,
            usage_record=usage,
            normalization_evidence=normalization,
            normalized_batch=batch,
            requested_surface_requests=requests,
            output_artifact=artifact,
        )
    assert journal.truncation_recovery_entries == entries_before

    outcome = _specialist_success_outcome(usage=usage, requests=requests, artifact=artifact)
    result = journal.record_truncation_recovery_child_success(
        child.child_task_id,
        usage_record=usage,
        normalization_evidence=normalization,
        normalized_batch=batch,
        requested_surface_requests=requests,
        output_artifact=artifact,
        specialist_accepted_outcome=outcome,
    )
    assert result.schema_version == "1.2"
    assert result.runtime_specialist_accepted_outcome == outcome
    assert result.runtime_specialist_accepted_outcome_sha256 == outcome.evidence_sha256
    public_request = journal.recovery_model_requests[0]
    assert public_request.schema_version == "1.1"
    assert public_request.specialist_accepted_outcome_sha256 == outcome.evidence_sha256
    assert public_request.review_credit_authorized is False
    assert "runtime_specialist_accepted_outcome" not in public_request.model_dump_json()

    detached_result = SchedulerTruncationRecoveryChildResult.model_validate_json(
        result.model_dump_json(),
        strict=True,
    )
    assert detached_result == result
    with pytest.raises(ValueError, match="live construction API"):
        journal.record_truncation_recovery_child_result(detached_result)

    stripped_payload = json.loads(result.model_dump_json())
    stripped_payload["schema_version"] = "1.1"
    stripped_payload.pop("runtime_specialist_accepted_outcome")
    stripped_payload.pop("runtime_specialist_accepted_outcome_sha256")
    stripped_payload["entry_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in stripped_payload.items() if key != "entry_sha256"}
    )
    with pytest.raises(ValueError, match="lacks an accepted outcome"):
        SchedulerTruncationRecoveryChildResult.model_validate_json(
            json.dumps(stripped_payload),
            strict=True,
        )

    evidence = journal.journal_evidence
    journal.close()
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=evidence,
    )
    assert resumed._truncation_recovery_indexes.results[child.child_task_id] == result
    assert (
        resumed.recovery_model_requests[0].specialist_accepted_outcome_sha256
        == outcome.evidence_sha256
    )
    resumed.close()


def test_specialist_typed_success_rejects_an_outcome_from_another_recovery_child(
    tmp_path: Path,
) -> None:
    journal, plan, projection, surfaces, surface_manifest = _journal_with_truncated_parent(
        tmp_path / "typed-specialist-swapped-outcome",
        parent_role="specialist:access_control",
    )
    journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    first_child, second_child = plan.children
    first_activation = _activate_child(journal, first_child.child_task_id)
    journal.mark_truncation_recovery_child_dispatched(first_child.child_task_id)
    second_activation = _activate_child(journal, second_child.child_task_id)
    journal.mark_truncation_recovery_child_dispatched(second_child.child_task_id)
    first_custody = _success_custody(
        child=first_child,
        activation=first_activation,
        surface_manifest=surface_manifest,
        surfaces=surfaces,
    )
    second_custody = _success_custody(
        child=second_child,
        activation=second_activation,
        surface_manifest=surface_manifest,
        surfaces=surfaces,
    )
    second_outcome = _specialist_success_outcome(
        usage=second_custody[0],
        requests=second_custody[3],
        artifact=second_custody[4],
    )
    entries_before = journal.truncation_recovery_entries
    with pytest.raises(ValueError, match="accepted outcome custody"):
        journal.record_truncation_recovery_child_success(
            first_child.child_task_id,
            usage_record=first_custody[0],
            normalization_evidence=first_custody[1],
            normalized_batch=first_custody[2],
            requested_surface_requests=first_custody[3],
            output_artifact=first_custody[4],
            specialist_accepted_outcome=second_outcome,
        )
    assert journal.truncation_recovery_entries == entries_before
    journal.close()


def test_typed_success_requires_owned_real_usage_before_detached_custody(
    tmp_path: Path,
) -> None:
    journal, child, activation, _dispatch, surfaces, surface_manifest = _open_dispatched_child(
        tmp_path / "typed-real-ownership"
    )
    usage, normalization, batch, requests, artifact = _success_custody(
        child=child,
        activation=activation,
        surface_manifest=surface_manifest,
        surfaces=surfaces,
        execution_evidence=ExecutionEvidenceKind.REAL,
    )
    serialized_clone = UsageRecord.model_validate_json(usage.model_dump_json())
    with pytest.raises(ValueError, match="owned creditable"):
        journal.record_truncation_recovery_child_success(
            child.child_task_id,
            usage_record=serialized_clone,
            normalization_evidence=normalization,
            normalized_batch=batch,
            requested_surface_requests=requests,
            output_artifact=artifact,
        )
    result = journal.record_truncation_recovery_child_success(
        child.child_task_id,
        usage_record=usage,
        normalization_evidence=normalization,
        normalized_batch=batch,
        requested_surface_requests=requests,
        output_artifact=artifact,
    )
    assert result.runtime_usage_record is usage
    assert result.runtime_usage_record.execution_evidence is ExecutionEvidenceKind.REAL
    detached_result = SchedulerTruncationRecoveryChildResult.model_validate_json(
        result.model_dump_json(),
        strict=True,
    )
    with pytest.raises(ValueError, match="live construction API"):
        journal.record_truncation_recovery_child_result(detached_result)
    journal.close()


@pytest.mark.parametrize(
    ("request_role", "exact_model_id"),
    (
        ("independent_reviewer", None),
        (None, "synthetic/different-recovery-model-v1"),
    ),
)
def test_typed_success_rejects_coherent_route_different_from_parent_activation(
    tmp_path: Path,
    request_role: str | None,
    exact_model_id: str | None,
) -> None:
    journal, child, activation, dispatch, surfaces, surface_manifest = _open_dispatched_child(
        tmp_path / f"typed-route-{_digest(request_role or exact_model_id or 'missing')}"
    )
    usage, normalization, batch, requests, artifact = _success_custody(
        child=child,
        activation=activation,
        surface_manifest=surface_manifest,
        surfaces=surfaces,
        request_role=request_role,
        exact_model_id=exact_model_id,
    )
    with pytest.raises(ValueError, match=r"activation|request"):
        SchedulerTruncationRecoveryChildResult.build_typed_success(
            child=child,
            activation=activation,
            dispatch=dispatch,
            usage_record=usage,
            normalization_evidence=normalization,
            normalized_batch=batch,
            requested_surface_requests=requests,
            output_artifact=artifact,
            entry_index=len(journal.truncation_recovery_entries),
            previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
        )
    journal.close()


def test_typed_truncation_retains_exact_failed_usage_envelope_projection_and_reloads(
    tmp_path: Path,
) -> None:
    path = tmp_path / "typed-truncated"
    journal, child, activation, _dispatch, surfaces, _surface_manifest = _open_dispatched_child(
        path
    )
    usage, envelope, projection = _truncated_custody(
        child=child,
        activation=activation,
        surfaces=surfaces,
    )
    result = journal.record_truncation_recovery_child_truncated(
        child.child_task_id,
        failed_usage_record=usage,
        truncated_envelope_evidence=envelope,
        truncation_projection=projection,
    )

    assert result.schema_version == "1.1"
    assert result.runtime_usage_record is usage
    assert result.runtime_truncated_envelope_evidence == envelope
    assert result.truncation_projection == projection
    assert result.runtime_completion_evidence_sha256 is None
    assert result.runtime_output_artifact is None
    assert result.completed_surface_ids == ()
    assert result.review_credit_authorized is False
    assert result.coverage_credit_authorized is False
    recovery_requests = journal.recovery_model_requests
    assert len(recovery_requests) == 1
    recovery_request = recovery_requests[0]
    assert recovery_request.logical_request_id == usage.request_id
    assert recovery_request.terminal_status is SchedulerTerminalStatus.TRUNCATED
    assert recovery_request.promotion_entry_sha256 is None
    assert recovery_request.runtime_completion_evidence_sha256 is None
    assert recovery_request.validated_response_sha256 is None
    assert recovery_request.normalization_evidence_sha256 is None
    assert recovery_request.output_artifact_sha256 is None
    assert journal.artifact().recovery_model_requests == recovery_requests
    assert (
        SchedulerTruncationRecoveryChildResult.model_validate_json(
            result.model_dump_json(),
            strict=True,
        )
        == result
    )
    evidence = journal.journal_evidence
    journal.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=evidence,
    )
    assert resumed._truncation_recovery_indexes.results[child.child_task_id] == result
    resumed.close()


def test_all_direct_live_typed_successes_close_exact_coverage_without_credit(
    tmp_path: Path,
) -> None:
    journal, plan, projection, surfaces, surface_manifest = _journal_with_truncated_parent(
        tmp_path / "typed-direct-coverage-closure"
    )
    family = journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    results: list[SchedulerTruncationRecoveryChildResult] = []
    for child in plan.children:
        activation = _activate_child(journal, child.child_task_id)
        journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
        usage, normalization, batch, requests, artifact = _success_custody(
            child=child,
            activation=activation,
            surface_manifest=surface_manifest,
            surfaces=surfaces,
        )
        results.append(
            journal.record_truncation_recovery_child_success(
                child.child_task_id,
                usage_record=usage,
                normalization_evidence=normalization,
                normalized_batch=batch,
                requested_surface_requests=requests,
                output_artifact=artifact,
            )
        )

    closure = journal.seal_truncation_recovery_family(family.family_id)
    assert closure.schema_version == "1.1"
    assert closure.closure_status is SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
    assert closure.child_result_sha256s == tuple(result.entry_sha256 for result in results)
    assert closure.nested_family_closure_sha256s == ()
    assert (
        closure.covered_unfinished_surface_ids == family.recovery_plan.parent.unfinished_surface_ids
    )
    assert closure.closure_id == "scheduler-recovery-closure-" + scheduler_canonical_sha256(
        {
            "domain": "mmaudit.scheduler.truncation-recovery-closure.v1",
            "family_id": family.family_id,
            "family_root_sha256": family.entry_sha256,
            "child_result_sha256s": closure.child_result_sha256s,
            "nested_family_closure_sha256s": (),
            "covered_unfinished_surface_ids": (family.recovery_plan.parent.unfinished_surface_ids),
            "closure_status": closure.closure_status,
        }
    )
    assert closure.review_credit_authorized is False
    assert closure.coverage_credit_authorized is False
    assert closure.completion_authorized is False
    journal.close()


@pytest.mark.asyncio
async def test_resume_restores_mixed_main_and_real_recovery_usage_with_shared_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "typed-recovery-usage-resume"
    journal, child, activation, _dispatch, surfaces, surface_manifest = _open_dispatched_child(
        path,
        parent_cost_usd_exact="0.01",
    )
    usage, normalization, batch, requests, artifact = _success_custody(
        child=child,
        activation=activation,
        surface_manifest=surface_manifest,
        surfaces=surfaces,
        execution_evidence=ExecutionEvidenceKind.REAL,
    )
    journal.record_truncation_recovery_child_success(
        child.child_task_id,
        usage_record=usage,
        normalization_evidence=normalization,
        normalized_batch=batch,
        requested_surface_requests=requests,
        output_artifact=artifact,
    )
    expected_shared_count_before = journal.truncation_recovery_families[
        0
    ].request_limit_binding.parent_request_limit_reservation.request_limit_count_before
    durable_records = journal.restorable_usage_records
    ledger = AtomicCostLedger.initialize(
        tmp_path / "typed-recovery-cost.json", cap_usd=Decimal("1")
    )
    expected_spent = Decimal(0)
    for record in durable_records:
        assert record.accounted_cost_usd_exact is not None
        accounted = Decimal(record.accounted_cost_usd_exact)
        reservation = ledger.reserve(record.request_id, max(accounted, Decimal("0.01")))
        reported = (
            Decimal(record.reported_cost_usd_exact)
            if record.reported_cost_usd_exact is not None
            else None
        )
        ledger.reconcile(reservation, reported)
        expected_spent += accounted
    budget = BudgetManager(
        total_usd=1,
        max_output_tokens=1_000,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=activation.request_limit_maximum,
        atomic_ledger=ledger,
        global_input_token_budget=1_000_000,
        global_output_token_budget=100_000,
    )
    evidence = journal.journal_evidence
    journal.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=evidence,
    )
    resumed_request_ids = {record.request_id for record in resumed.restorable_usage_records}
    assert resumed_request_ids == {record.request_id for record in durable_records}
    assert {activation.request_limit_id, child.child_logical_request_id} <= resumed_request_ids
    captured: dict[str, object] = {}
    original_issue = scheduler_module._issue_trusted_budget_recovery_scope

    def capture_issue(records: tuple[UsageRecord, ...], **kwargs: object) -> object:
        captured.update(kwargs)
        return original_issue(records, **kwargs)

    monkeypatch.setattr(
        scheduler_module,
        "_issue_trusted_budget_recovery_scope",
        capture_issue,
    )
    recovered, budget_scope = resumed.claim_restorable_usage_for_budget_recovery(
        atomic_ledger=ledger
    )
    recovered_by_id = {record.request_id: record for record in recovered}
    recovered_child = recovered_by_id[child.child_logical_request_id]
    assert is_recovery_creditable_usage_record(
        recovered_child,
        request_limit_scope=activation.request_limit_id,
        request_limit_count_before=activation.request_limit_count_before_child,
        require_real=True,
    )
    assert captured["shared_request_limit_roots"] == (
        (activation.request_limit_id, expected_shared_count_before),
    )
    await budget.restore_recovered_usage(recovered, recovery_scope=budget_scope)
    assert budget.spent_usd_exact == expected_spent
    assert not budget.recovery_required
    resumed.close()


def test_reload_rejects_resealed_typed_result_with_omitted_usage(tmp_path: Path) -> None:
    path = tmp_path / "typed-result-omitted-usage"
    journal, child, activation, _dispatch, surfaces, surface_manifest = _open_dispatched_child(path)
    usage, normalization, batch, requests, artifact = _success_custody(
        child=child,
        activation=activation,
        surface_manifest=surface_manifest,
        surfaces=surfaces,
    )
    journal.record_truncation_recovery_child_success(
        child.child_task_id,
        usage_record=usage,
        normalization_evidence=normalization,
        normalized_batch=batch,
        requested_surface_requests=requests,
        output_artifact=artifact,
    )
    journal.close()

    result_path = sorted((path / "truncation-recovery").iterdir())[-1]
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    payload.pop("runtime_usage_record")
    result_path.write_text(
        stable_json(_reseal_result_payload(payload)),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="scheduler truncation recovery entry is invalid"):
        open_scheduler_journal_for_verification(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )


@pytest.mark.parametrize(
    "omitted_field",
    (
        "runtime_activation",
        "runtime_request_limit_reservation",
        "runtime_usage_record",
        "runtime_normalization_evidence",
        "runtime_normalized_batch",
        "runtime_requested_surface_requests",
        "runtime_output_artifact",
    ),
)
def test_typed_success_rejects_each_omitted_nested_custody_field_after_reseal(
    tmp_path: Path,
    omitted_field: str,
) -> None:
    journal, child, activation, dispatch, surfaces, surface_manifest = _open_dispatched_child(
        tmp_path / f"typed-omitted-{omitted_field}"
    )
    usage, normalization, batch, requests, artifact = _success_custody(
        child=child,
        activation=activation,
        surface_manifest=surface_manifest,
        surfaces=surfaces,
    )
    result = SchedulerTruncationRecoveryChildResult.build_typed_success(
        child=child,
        activation=activation,
        dispatch=dispatch,
        usage_record=usage,
        normalization_evidence=normalization,
        normalized_batch=batch,
        requested_surface_requests=requests,
        output_artifact=artifact,
        entry_index=len(journal.truncation_recovery_entries),
        previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
    )
    payload = result.model_dump(mode="json")
    payload.pop(omitted_field)
    with pytest.raises(ValueError, match=r"typed|successful"):
        SchedulerTruncationRecoveryChildResult.model_validate_json(
            json.dumps(_reseal_result_payload(payload)),
            strict=True,
        )
    journal.close()


def test_typed_success_rejects_a_swapped_child_artifact_and_unbounded_request_iterable(
    tmp_path: Path,
) -> None:
    journal, child, activation, dispatch, surfaces, surface_manifest = _open_dispatched_child(
        tmp_path / "typed-swapped-artifact"
    )
    usage, normalization, batch, requests, artifact = _success_custody(
        child=child,
        activation=activation,
        surface_manifest=surface_manifest,
        surfaces=surfaces,
    )
    family = journal.truncation_recovery_families[0]
    other_child = family.recovery_plan.children[1]
    other_activation = _activate_child(journal, other_child.child_task_id)
    _other_usage, _other_normalization, _other_batch, _other_requests, other_artifact = (
        _success_custody(
            child=other_child,
            activation=other_activation,
            surface_manifest=surface_manifest,
            surfaces=surfaces,
        )
    )

    with pytest.raises(ValueError, match=r"successful typed|wire-to-artifact"):
        SchedulerTruncationRecoveryChildResult.build_typed_success(
            child=child,
            activation=activation,
            dispatch=dispatch,
            usage_record=usage,
            normalization_evidence=normalization,
            normalized_batch=batch,
            requested_surface_requests=requests,
            output_artifact=other_artifact,
            entry_index=len(journal.truncation_recovery_entries),
            previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
        )
    with pytest.raises(ValueError, match="exceeds its item limit"):
        SchedulerTruncationRecoveryChildResult.build_typed_success(
            child=child,
            activation=activation,
            dispatch=dispatch,
            usage_record=usage,
            normalization_evidence=normalization,
            normalized_batch=batch,
            requested_surface_requests=repeat(requests[0]),
            output_artifact=artifact,
            entry_index=len(journal.truncation_recovery_entries),
            previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
        )
    journal.close()


@pytest.mark.parametrize("drift", ("root", "count", "maximum"))
def test_typed_success_rejects_each_shared_request_limit_coordinate_drift(
    tmp_path: Path,
    drift: str,
) -> None:
    journal, child, activation, dispatch, surfaces, surface_manifest = _open_dispatched_child(
        tmp_path / f"typed-limit-{drift}"
    )
    usage, normalization, batch, requests, artifact = _success_custody(
        child=child,
        activation=activation,
        surface_manifest=surface_manifest,
        surfaces=surfaces,
    )
    changed_usage = _replace_recovery_request_limit(
        usage,
        activation=activation,
        request_limit_scope=(
            f"scheduler-request-{_digest('wrong-recovery-root')}" if drift == "root" else None
        ),
        request_limit_count_before=(
            activation.request_limit_count_before_child + 1 if drift == "count" else None
        ),
        request_limit_maximum=(
            activation.request_limit_maximum + 1 if drift == "maximum" else None
        ),
    )
    with pytest.raises(ValueError, match=r"request-limit|creditable"):
        SchedulerTruncationRecoveryChildResult.build_typed_success(
            child=child,
            activation=activation,
            dispatch=dispatch,
            usage_record=changed_usage,
            normalization_evidence=normalization,
            normalized_batch=batch,
            requested_surface_requests=requests,
            output_artifact=artifact,
            entry_index=len(journal.truncation_recovery_entries),
            previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
        )
    journal.close()


def test_typed_success_rejects_cost_and_schema_beyond_its_exact_plan(
    tmp_path: Path,
) -> None:
    journal, child, activation, dispatch, surfaces, surface_manifest = _open_dispatched_child(
        tmp_path / "typed-cost-schema"
    )
    over_cost_usage, normalization, batch, requests, over_cost_artifact = _success_custody(
        child=child,
        activation=activation,
        surface_manifest=surface_manifest,
        surfaces=surfaces,
        cost_usd_exact="0.2",
    )
    with pytest.raises(ValueError, match="exceeds its child reservation"):
        SchedulerTruncationRecoveryChildResult.build_typed_success(
            child=child,
            activation=activation,
            dispatch=dispatch,
            usage_record=over_cost_usage,
            normalization_evidence=normalization,
            normalized_batch=batch,
            requested_surface_requests=requests,
            output_artifact=over_cost_artifact,
            entry_index=len(journal.truncation_recovery_entries),
            previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
        )

    usage, normalization, batch, requests, artifact = _success_custody(
        child=child,
        activation=activation,
        surface_manifest=surface_manifest,
        surfaces=surfaces,
    )
    wrong_schema = _digest("wrong-recovery-wire-schema")
    changed_usage = UsageRecord.model_validate(
        {
            **usage.model_dump(mode="python"),
            "schema_sha256": wrong_schema,
            "routing": {**usage.routing, "schema_sha256": wrong_schema},
        }
    )
    with pytest.raises(ValueError, match=r"activation|request|creditable"):
        SchedulerTruncationRecoveryChildResult.build_typed_success(
            child=child,
            activation=activation,
            dispatch=dispatch,
            usage_record=changed_usage,
            normalization_evidence=normalization,
            normalized_batch=batch,
            requested_surface_requests=requests,
            output_artifact=artifact,
            entry_index=len(journal.truncation_recovery_entries),
            previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
        )
    journal.close()


def test_typed_truncation_rejects_swapped_envelope_identity(tmp_path: Path) -> None:
    journal, child, activation, dispatch, surfaces, _surface_manifest = _open_dispatched_child(
        tmp_path / "typed-truncated-swap"
    )
    usage, envelope, projection = _truncated_custody(
        child=child,
        activation=activation,
        surfaces=surfaces,
    )
    swapped = seal_candidate_review_truncated_envelope_evidence(
        logical_request_id=envelope.logical_request_id,
        generation_id=envelope.generation_id,
        generation_header_id=envelope.generation_header_id,
        requested_model=envelope.requested_model,
        returned_model="synthetic/swapped-model-v1",
        selected_model=envelope.selected_model,
        response_provider_identity=envelope.response_provider_identity,
        selected_provider_endpoint=envelope.selected_provider_endpoint,
        selected_provider_identity=envelope.selected_provider_identity,
        selected_provider_name=envelope.selected_provider_name,
        router_metadata_sha256=envelope.router_metadata_sha256,
        finish_reason=envelope.finish_reason,
        native_finish_reason=envelope.native_finish_reason,
        wire_schema_sha256=envelope.wire_schema_sha256,
        response_sha256=envelope.response_sha256,
    )
    with pytest.raises(ValueError, match="truncated typed recovery child custody"):
        SchedulerTruncationRecoveryChildResult.build_typed_truncated(
            child=child,
            activation=activation,
            dispatch=dispatch,
            failed_usage_record=usage,
            truncated_envelope_evidence=swapped,
            truncation_projection=projection,
            entry_index=len(journal.truncation_recovery_entries),
            previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
        )
    journal.close()


def test_legacy_hash_only_result_reloads_as_full_reservation_without_typed_custody(
    tmp_path: Path,
) -> None:
    journal, child, _activation, dispatch, _surfaces, _surface_manifest = _open_dispatched_child(
        tmp_path / "legacy-v1-reload"
    )
    legacy = SchedulerTruncationRecoveryChildResult.build_runtime(
        child=child,
        dispatch=dispatch,
        terminal_status=SchedulerTruncationRecoveryTerminalStatus.FAILED,
        terminal_evidence_sha256=_digest("legacy-terminal"),
        provider_attempt_evidence_sha256=_digest("legacy-attempt"),
        accounted_provider_attempts=child.reserved_provider_attempts,
        accounted_completion_tokens=child.reserved_completion_tokens,
        accounted_cost_usd_exact=child.reserved_usd_exact,
        entry_index=len(journal.truncation_recovery_entries),
        previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
    )
    replayed = SchedulerTruncationRecoveryChildResult.model_validate_json(
        legacy.model_dump_json(),
        strict=True,
    )
    assert replayed == legacy
    assert replayed.schema_version == "1.0"
    assert replayed.runtime_usage_record is None
    assert replayed.runtime_output_artifact is None
    assert replayed.accounted_provider_attempts == child.reserved_provider_attempts
    assert replayed.accounted_completion_tokens == child.reserved_completion_tokens
    assert replayed.accounted_cost_usd_exact == child.reserved_usd_exact
    assert replayed.completion_authorized is False
    journal.close()


def test_activation_preflight_failure_is_zero_cost_terminal_and_never_redispatched(
    tmp_path: Path,
) -> None:
    path = tmp_path / "preflight-terminal"
    journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(path)
    family = journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    for index, child in enumerate(plan.children):
        activation = _activate_child(journal, child.child_task_id)
        assert activation.request_limit_count_before_child == 1 + index
        result = journal.record_truncation_recovery_child_preflight_result(
            child.child_task_id,
            terminal_status=(
                SchedulerTruncationRecoveryTerminalStatus.FAILED
                if index == 0
                else SchedulerTruncationRecoveryTerminalStatus.INVALID
            ),
            terminal_evidence_sha256=_digest(f"preflight:{child.child_task_id}"),
        )
        assert result.activation_sha256 == activation.entry_sha256
        assert result.accounted_provider_attempts == 0
        assert result.accounted_completion_tokens == 0
        assert result.accounted_cost_usd_exact == "0"
        assert result.provider_attempt_evidence_sha256 is None
        with pytest.raises(ValueError, match="activated recovery child"):
            journal.mark_truncation_recovery_child_dispatched(child.child_task_id)

    closure = journal.seal_truncation_recovery_family(family.family_id)
    assert closure.closure_status is SchedulerTruncationRecoveryClosureStatus.INCOMPLETE
    evidence = journal.journal_evidence
    journal.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=evidence,
    )
    assert resumed.dispatchable_truncation_recovery_child_ids == ()
    assert resumed.uncertain_truncation_recovery_child_ids == ()
    resumed.close()


def test_dispatched_child_without_provider_accounting_is_uncertain_not_zero_cost(
    tmp_path: Path,
) -> None:
    journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(
        tmp_path / "dispatched-accounting"
    )
    journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    child = plan.children[0]
    _activate_child(journal, child.child_task_id)
    dispatch = journal.mark_truncation_recovery_child_dispatched(child.child_task_id)

    with pytest.raises(ValueError, match="conservatively fully accounted"):
        SchedulerTruncationRecoveryChildResult.build_runtime(
            child=child,
            dispatch=dispatch,
            terminal_status=SchedulerTruncationRecoveryTerminalStatus.FAILED,
            terminal_evidence_sha256=_digest("unaccounted-dispatched-failure"),
            provider_attempt_evidence_sha256=None,
            accounted_provider_attempts=0,
            accounted_completion_tokens=0,
            accounted_cost_usd_exact="0",
            entry_index=len(journal.truncation_recovery_entries),
            previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
        )

    uncertain = SchedulerTruncationRecoveryChildResult.build_uncertain(
        child=child,
        dispatch=dispatch,
        entry_index=len(journal.truncation_recovery_entries),
        previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
    )
    journal.record_truncation_recovery_child_result(uncertain)
    assert uncertain.terminal_status is SchedulerTruncationRecoveryTerminalStatus.UNCERTAIN
    assert uncertain.accounted_provider_attempts == child.reserved_provider_attempts
    assert uncertain.accounted_completion_tokens == child.reserved_completion_tokens
    assert uncertain.accounted_cost_usd_exact == child.reserved_usd_exact
    journal.close()


def test_hash_only_success_cannot_satisfy_a_recovery_family_closure(tmp_path: Path) -> None:
    journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(
        tmp_path / "hash-only-success"
    )
    family = journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    for index, child in enumerate(plan.children):
        _activate_child(journal, child.child_task_id)
        dispatch = journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
        terminal_status = (
            SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
            if index == 0
            else SchedulerTruncationRecoveryTerminalStatus.FAILED
        )
        journal.record_truncation_recovery_child_result(
            SchedulerTruncationRecoveryChildResult.build_runtime(
                child=child,
                dispatch=dispatch,
                terminal_status=terminal_status,
                terminal_evidence_sha256=_digest(f"terminal:{child.child_task_id}"),
                provider_attempt_evidence_sha256=_digest(f"attempt:{child.child_task_id}"),
                runtime_completion_evidence_sha256=(_digest("completion") if index == 0 else None),
                runtime_usage_record_sha256=_digest("usage") if index == 0 else None,
                runtime_output_artifact_sha256=_digest("output") if index == 0 else None,
                accounted_provider_attempts=child.reserved_provider_attempts,
                accounted_completion_tokens=child.reserved_completion_tokens,
                accounted_cost_usd_exact=child.reserved_usd_exact,
                entry_index=len(journal.truncation_recovery_entries),
                previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
            )
        )

    with pytest.raises(ValueError, match="exact typed runtime child completion custody"):
        journal.seal_truncation_recovery_family(family.family_id)
    assert all(
        entry.completion_authorized is False for entry in journal.truncation_recovery_entries
    )
    journal.close()


def test_closure_and_main_evidence_detect_replay_tamper_and_suffix_omission(
    tmp_path: Path,
) -> None:
    path = tmp_path / "evidence-source"
    journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(path)
    family = journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    with pytest.raises(ValueError, match="unfinished child"):
        journal.seal_truncation_recovery_family(family.family_id)
    for child in plan.children:
        _activate_child(journal, child.child_task_id)
        dispatch = journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
        with pytest.raises(ValueError, match="exceeds reserved resources"):
            SchedulerTruncationRecoveryChildResult.build_runtime(
                child=child,
                dispatch=dispatch,
                terminal_status=SchedulerTruncationRecoveryTerminalStatus.FAILED,
                terminal_evidence_sha256=_digest(f"over-budget:{child.child_task_id}"),
                provider_attempt_evidence_sha256=_digest(f"attempt:{child.child_task_id}"),
                accounted_provider_attempts=1,
                accounted_completion_tokens=10,
                accounted_cost_usd_exact="0.2",
                entry_index=len(journal.truncation_recovery_entries),
                previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
            )
        journal.record_truncation_recovery_child_result(
            SchedulerTruncationRecoveryChildResult.build_runtime(
                child=child,
                dispatch=dispatch,
                terminal_status=SchedulerTruncationRecoveryTerminalStatus.FAILED,
                terminal_evidence_sha256=_digest(f"terminal:{child.child_task_id}"),
                provider_attempt_evidence_sha256=_digest(f"attempt:{child.child_task_id}"),
                accounted_provider_attempts=child.reserved_provider_attempts,
                accounted_completion_tokens=child.reserved_completion_tokens,
                accounted_cost_usd_exact=child.reserved_usd_exact,
                entry_index=len(journal.truncation_recovery_entries),
                previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
            )
        )
    closure = journal.seal_truncation_recovery_family(family.family_id)
    assert closure.closure_status is SchedulerTruncationRecoveryClosureStatus.INCOMPLETE
    assert closure.completion_authorized is False
    assert closure.coverage_credit_authorized is False
    evidence = journal.journal_evidence
    assert evidence.truncation_recovery_entry_count == len(journal.truncation_recovery_entries)
    assert evidence.truncation_recovery_chain_head_sha256 == closure.entry_sha256
    journal.close()

    omitted = tmp_path / "omitted"
    shutil.copytree(path, omitted)
    sorted((omitted / "truncation-recovery").iterdir())[-1].unlink()
    with pytest.raises(ValueError, match=r"journal-head checkpoint|journal evidence"):
        open_scheduler_journal_for_verification(
            omitted,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=evidence,
        )

    replayed = tmp_path / "replayed"
    shutil.copytree(path, replayed)
    first = sorted((replayed / "truncation-recovery").iterdir())[0]
    shutil.copy2(first, first.with_name("entry-99999999-replayed.json"))
    with pytest.raises(ValueError, match=r"filename|filenames|invalid"):
        open_scheduler_journal_for_verification(
            replayed,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )

    tampered = evidence.model_dump(mode="json")
    hashes = tuple(reversed(evidence.truncation_recovery_entry_sha256s))
    tampered["truncation_recovery_entry_sha256s"] = hashes
    tampered["truncation_recovery_chain_head_sha256"] = hashes[-1]
    tampered["evidence_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in tampered.items() if key != "evidence_sha256"}
    )
    resealed = SchedulerJournalEvidence.model_validate(tampered)
    with pytest.raises(ValueError, match="journal evidence does not match"):
        open_scheduler_journal_for_verification(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=resealed,
        )

    entry_path = sorted((path / "truncation-recovery").iterdir())[0]
    raw = json.loads(entry_path.read_text(encoding="utf-8"))
    raw["provider_dispatch_authorized"] = True
    entry_path.write_text(stable_json(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid"):
        open_scheduler_journal_for_verification(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )


def test_recovery_chain_and_directory_enumeration_are_tightly_bounded(
    tmp_path: Path,
) -> None:
    assert SCHEDULER_TRUNCATION_RECOVERY_MAX_FAMILIES == 16
    assert SCHEDULER_TRUNCATION_RECOVERY_MAX_ENTRIES == 144
    journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(
        tmp_path / "bounded-chain"
    )
    family = journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    with pytest.raises(ValueError, match="exceeds its item limit"):
        validate_truncation_recovery_entry_chain(repeat(family))
    with pytest.raises(ValueError, match="exceeds its item limit"):
        SchedulerTruncationRecoveryRequestedSurfaceManifest.build(
            repeat(surface_manifest.requests[0])
        )
    journal.close()

    oversized = tmp_path / "oversized-directory"
    empty = create_scheduler_journal(
        oversized,
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    empty.close()
    recovery_directory = oversized / "truncation-recovery"
    for index in range(SCHEDULER_TRUNCATION_RECOVERY_MAX_ENTRIES + 1):
        (recovery_directory / f"entry-{index:08d}-synthetic.json").write_text(
            "{}",
            encoding="utf-8",
        )
    with pytest.raises(ValueError, match="exceeds its exact entry bound"):
        open_scheduler_journal_for_verification(
            oversized,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )


def test_live_recovery_journal_retains_exclusive_concurrent_custody(tmp_path: Path) -> None:
    path = tmp_path / "exclusive-custody"
    journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(path)
    journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    with pytest.raises(ValueError, match=r"live.*custody"):
        open_scheduler_journal_for_verification(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )
    journal.close()
