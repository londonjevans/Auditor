"""Comparison-boundary tests for truncation-recovery surface evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import pickle
from dataclasses import dataclass
from decimal import Decimal

import pytest

import mmaudit.orchestration.truncation_recovery_evidence as recovery_evidence
from mmaudit.models.schemas import (
    CandidateFinding,
    CandidateReviewBatch,
    ContextPackage,
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    ModelSurfaceReviewRequest,
    UsageRecord,
)
from mmaudit.models.truncation import (
    CandidateReviewFramePhase,
    CandidateReviewTruncatedEnvelopeEvidence,
    CandidateReviewTruncationProjection,
    candidate_review_frame_wire_schema_sha256,
    frame_candidate_review_batch,
    normalize_candidate_review_document,
    project_truncated_candidate_review_prefix,
    seal_candidate_review_truncated_envelope_evidence,
)
from mmaudit.models.truncation_closure import (
    TruncationRecoveredRecursiveSurfaceReviewArtifact,
    TruncationRecoveredSurfaceReviewArtifact,
)
from mmaudit.models.truncation_recovery import (
    TruncationRecoveryChannel,
    TruncationRecoveryChannelState,
    TruncationRecoveryChildPlan,
    TruncationRecoveryParentBinding,
    TruncationRecoveryResourceBudget,
    plan_truncation_recovery,
)
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildActivation,
    SchedulerTruncationRecoveryChildDispatch,
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryClosureStatus,
    SchedulerTruncationRecoveryFamilyClosure,
    SchedulerTruncationRecoveryFamilyRoot,
    SchedulerTruncationRecoveryParentKind,
    SchedulerTruncationRecoveryRequestedSurfaceManifest,
    SchedulerTruncationRecoveryRequestLimitBinding,
    SchedulerTruncationRecoveryTerminalStatus,
    rebuild_truncation_recovery_parent_from_projection,
)
from mmaudit.models.usage import atomic_request_limit_reservations_from_usage
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.truncation_recovery_evidence import (
    TruncationRecoveryChildInput,
    TruncationRecoveryEvidenceError,
    VerifiedRecursiveTruncationRecoveryTree,
    VerifiedTruncationRecoveryClosure,
    build_truncation_recovery_child_context,
    model_surface_analysis_context_sha256,
    require_verified_recursive_truncation_recovery_tree,
    require_verified_recursive_truncation_recovery_tree_projection,
    require_verified_truncation_recovery_closure,
    require_verified_truncation_recovery_closure_projection,
    seal_truncation_recovery_surface_evidence,
    verify_recursive_truncation_recovery_tree,
    verify_truncation_recovery_closure,
)
from tests.identity_fixtures import (
    bind_synthetic_usage_identity,
    reattest_synthetic_real_usage,
)
from tests.unit.test_truncation import _candidate
from tests.unit.test_truncation_closure import (
    _artifact,
    _channel_binding,
    _context,
    _record,
    _requests,
    _usage,
    _with_request_limit,
    _with_truncation_custody,
    build_closure_fixture,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class _TypedClosureFixture:
    family: SchedulerTruncationRecoveryFamilyRoot
    closure: SchedulerTruncationRecoveryFamilyClosure
    results: tuple[SchedulerTruncationRecoveryChildResult, ...]
    dispatches: tuple[SchedulerTruncationRecoveryChildDispatch, ...]
    parent_usage: UsageRecord
    child_usages: tuple[UsageRecord, ...]
    parent_context: ContextPackage
    child_contexts: tuple[ContextPackage, ...]
    requests: tuple[ModelSurfaceReviewRequest, ...]


@dataclass(frozen=True, slots=True)
class _RecursiveTreeFixture:
    root_family: SchedulerTruncationRecoveryFamilyRoot
    nested_family: SchedulerTruncationRecoveryFamilyRoot
    root_closure: SchedulerTruncationRecoveryFamilyClosure
    nested_closure: SchedulerTruncationRecoveryFamilyClosure
    root_results: tuple[
        SchedulerTruncationRecoveryChildResult,
        SchedulerTruncationRecoveryChildResult,
    ]
    nested_results: tuple[
        SchedulerTruncationRecoveryChildResult,
        SchedulerTruncationRecoveryChildResult,
    ]
    parent_usage: UsageRecord
    bridge_usage: UsageRecord
    leaf_usages: tuple[UsageRecord, UsageRecord, UsageRecord]
    parent_context: ContextPackage
    bridge_context: ContextPackage
    leaf_contexts: tuple[ContextPackage, ContextPackage, ContextPackage]
    requests: tuple[ModelSurfaceReviewRequest, ...]


def _truncated_projection(
    requests: tuple[ModelSurfaceReviewRequest, ...],
    *,
    retained_count: int,
    findings: tuple[CandidateFinding, ...] = (),
) -> tuple[CandidateReviewTruncationProjection, str]:
    records = tuple(_record(request) for request in requests)
    document = frame_candidate_review_batch(
        CandidateReviewBatch(findings=findings, surface_reviews=records)
    )
    first_surface_index = next(
        index
        for index, frame in enumerate(document.frames)
        if frame.phase is CandidateReviewFramePhase.SURFACE_REVIEW
    )
    accepted_count = first_surface_index + retained_count
    accepted = ",".join(
        json.dumps(
            frame.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        for frame in document.frames[:accepted_count]
    )
    partial = (
        '{"schema_version":"1.0","sequence":'
        + str(accepted_count)
        + ',"phase":"SURFACE_REVIEW","record":{"surface_id":"partial-tail'
    )
    content = '{"frames":[' + accepted + "," + partial
    return (
        project_truncated_candidate_review_prefix(
            content,
            finish_reason="length",
            native_finish_reason=None,
        ),
        hashlib.sha256(content.encode()).hexdigest(),
    )


def _truncated_envelope(
    usage: UsageRecord,
    projection: CandidateReviewTruncationProjection,
) -> CandidateReviewTruncatedEnvelopeEvidence:
    assert usage.openrouter_generation_id is not None
    assert usage.returned_model is not None
    assert usage.actual_model is not None
    assert usage.provider is not None
    assert usage.actual_provider_endpoint is not None
    provider_identity = usage.routing.get("selected_provider_identity")
    router_metadata_sha256 = usage.routing.get("router_metadata_sha256")
    assert isinstance(provider_identity, str)
    assert isinstance(router_metadata_sha256, str)
    return seal_candidate_review_truncated_envelope_evidence(
        logical_request_id=usage.request_id,
        generation_id=usage.openrouter_generation_id,
        generation_header_id=usage.openrouter_generation_id,
        requested_model=usage.requested_model,
        returned_model=usage.returned_model,
        selected_model=usage.actual_model,
        response_provider_identity=provider_identity,
        selected_provider_endpoint=usage.actual_provider_endpoint,
        selected_provider_identity=provider_identity,
        selected_provider_name=usage.provider,
        router_metadata_sha256=router_metadata_sha256,
        finish_reason=projection.finish_reason,
        native_finish_reason=projection.native_finish_reason,
        wire_schema_sha256=projection.wire_schema_sha256,
        response_sha256=projection.original_response_sha256,
    )


def _real_accountable(usage: UsageRecord) -> UsageRecord:
    return reattest_synthetic_real_usage(
        UsageRecord.model_validate(
            {
                **usage.model_dump(mode="python"),
                "execution_evidence": ExecutionEvidenceKind.REAL,
            }
        )
    )


def _real_creditable(usage: UsageRecord) -> UsageRecord:
    return bind_synthetic_usage_identity(
        UsageRecord.model_validate(
            {
                **usage.model_dump(mode="python"),
                "execution_evidence": ExecutionEvidenceKind.REAL,
            }
        )
    )


def _recursive_tree_fixture() -> _RecursiveTreeFixture:
    """Build the exact five-request live tree shared by recursive consumer tests."""

    requests = _requests()
    parent_context = _context(requests)
    root_projection, root_response_sha256 = _truncated_projection(
        requests,
        retained_count=1,
    )
    parent_request_id = "scheduler-request-" + _digest("recursive-parent-request")
    parent_usage = _with_request_limit(
        _usage(
            context=parent_context,
            request_id=parent_request_id,
            generation_id="generation-recursive-parent",
            response_sha256=root_response_sha256,
            validated_response_sha256=None,
            status="rejected_truncated_response",
            finish_reason="length",
            validation_status=ModelRequestValidationStatus.TRUNCATED,
            cost="0.4",
            completion_tokens=20,
        )
    )
    parent_envelope = _truncated_envelope(parent_usage, root_projection)
    parent_usage = _real_accountable(
        _with_truncation_custody(
            parent_usage,
            envelope=parent_envelope,
            projection=root_projection,
        )
    )
    parent_reservations = atomic_request_limit_reservations_from_usage(parent_usage)
    assert len(parent_reservations) == 1
    manifest = SchedulerTruncationRecoveryRequestedSurfaceManifest.build(requests)

    parent_task_id = "scheduler-task-" + _digest("recursive-parent-task")
    parent_activation_sha256 = _digest("recursive-parent-activation")
    parent_provider_attempt_sha256 = _digest("recursive-parent-provider-attempt")
    claimed_root_parent = TruncationRecoveryParentBinding.build(
        campaign_id="scheduler-campaign-" + _digest("recursive-campaign"),
        pass_plan_id="scheduler-plan-" + _digest("recursive-pass-plan"),
        parent_task_id=parent_task_id,
        parent_logical_request_id=parent_request_id,
        parent_task_plan_sha256=_digest("recursive-parent-task-plan"),
        parent_activation_sha256=parent_activation_sha256,
        provider_attempt_evidence_sha256=parent_provider_attempt_sha256,
        truncation_projection_sha256=root_projection.evidence_sha256,
        requested_surface_manifest_sha256=manifest.requested_surface_manifest_sha256,
        requested_surface_ids=manifest.requested_surface_ids,
        retained_surface_ids=tuple(record.surface_id for record in root_projection.surface_reviews),
        channel_bindings=(
            _channel_binding(
                TruncationRecoveryChannel.COVERAGE,
                TruncationRecoveryChannelState.INCOMPLETE,
                len(root_projection.surface_reviews),
            ),
            _channel_binding(
                TruncationRecoveryChannel.FINDINGS,
                TruncationRecoveryChannelState.COMPLETE,
                len(root_projection.findings),
            ),
            _channel_binding(
                TruncationRecoveryChannel.SUMMARY,
                TruncationRecoveryChannelState.INCOMPLETE,
                0,
            ),
        ),
    )
    root_parent = rebuild_truncation_recovery_parent_from_projection(
        claimed_parent=claimed_root_parent,
        projection=root_projection,
    )
    root_resources = TruncationRecoveryResourceBudget.build(
        campaign_cap_usd_exact="250",
        accounted_usd_before_parent_exact="1",
        parent_accounted_cost_usd_exact="0.4",
        child_reserved_usd_exact="0.1",
        recovery_requests_consumed=0,
        provider_attempts_before_parent=0,
        parent_provider_attempts=1,
        child_provider_attempts=1,
        completion_tokens_before_parent=0,
        parent_completion_tokens=20,
        child_completion_tokens=100,
    )
    root_plan = plan_truncation_recovery(parent=root_parent, resources=root_resources)
    bridge_plan = next(child for child in root_plan.children if len(child.surface_ids) == 2)
    direct_plan = next(child for child in root_plan.children if child != bridge_plan)
    request_limit_binding = SchedulerTruncationRecoveryRequestLimitBinding.build(
        campaign_id=root_parent.campaign_id,
        manifest_sha256=_digest("recursive-journal-manifest"),
        request_limit_id=parent_request_id,
        policy=root_plan.policy,
        parent_request_limit_reservation=parent_reservations[0],
    )
    root_family = SchedulerTruncationRecoveryFamilyRoot.build(
        request_limit_binding=request_limit_binding,
        family_index=0,
        parent_kind=SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK,
        parent_family_id=None,
        parent_terminal_result_sha256=_digest("recursive-parent-terminal"),
        requested_surface_manifest=manifest,
        truncation_projection=root_projection,
        recovery_plan=root_plan,
        request_count_before_family=0,
        request_limit_count_before_family=1,
        entry_index=0,
        previous_entry_sha256=None,
    )

    requests_by_id = {request.surface_id: request for request in requests}
    records_by_id = {request.surface_id: _record(request) for request in requests}
    bridge_context = build_truncation_recovery_child_context(
        parent_context=parent_context,
        child=bridge_plan,
    )
    direct_context = build_truncation_recovery_child_context(
        parent_context=parent_context,
        child=direct_plan,
    )

    def activation_for(
        *,
        family: SchedulerTruncationRecoveryFamilyRoot,
        child: TruncationRecoveryChildPlan,
        context: ContextPackage,
        entry_index: int,
        previous_entry_sha256: str,
    ) -> SchedulerTruncationRecoveryChildActivation:
        return SchedulerTruncationRecoveryChildActivation.build(
            family=family,
            child=child,
            actual_input_sha256=_digest("body:" + child.child_logical_request_id),
            system_prompt_sha256=_digest("recursive-system:" + child.child_task_id),
            user_prompt_sha256=hashlib.sha256(render_context(context).encode()).hexdigest(),
            provider_prompt_sha256=_digest("provider-prompt"),
            response_schema_sha256=candidate_review_frame_wire_schema_sha256(),
            entry_index=entry_index,
            previous_entry_sha256=previous_entry_sha256,
        )

    def success_result(
        *,
        family: SchedulerTruncationRecoveryFamilyRoot,
        child: TruncationRecoveryChildPlan,
        context: ContextPackage,
        entry_index: int,
        previous_entry_sha256: str,
    ) -> tuple[
        SchedulerTruncationRecoveryChildResult,
        UsageRecord,
        str,
    ]:
        activation = activation_for(
            family=family,
            child=child,
            context=context,
            entry_index=entry_index,
            previous_entry_sha256=previous_entry_sha256,
        )
        dispatch = SchedulerTruncationRecoveryChildDispatch.build(
            activation=activation,
            entry_index=entry_index + 1,
            previous_entry_sha256=activation.entry_sha256,
        )
        child_requests = tuple(requests_by_id[item] for item in child.surface_ids)
        batch = CandidateReviewBatch(
            findings=(),
            surface_reviews=tuple(records_by_id[item] for item in child.surface_ids),
        )
        normalized_batch, normalization = normalize_candidate_review_document(
            frame_candidate_review_batch(batch),
            request_id=child.child_logical_request_id,
        )
        usage = _real_creditable(
            _with_request_limit(
                _usage(
                    context=context,
                    request_id=child.child_logical_request_id,
                    generation_id="generation-" + child.child_task_id[-24:],
                    response_sha256=_digest("recursive-response:" + child.child_task_id),
                    validated_response_sha256=(normalization.wire_validated_response_sha256),
                    status="success",
                    finish_reason="stop",
                    validation_status=ModelRequestValidationStatus.VALID,
                    cost="0.05",
                    completion_tokens=25,
                ),
                request_limit_scope=parent_request_id,
                request_limit_count_before=activation.request_limit_count_before_child,
            )
        )
        artifact = _artifact(
            context,
            normalized_batch,
            usage,
            normalization,
            request_limit_scope=parent_request_id,
            request_limit_count_before=activation.request_limit_count_before_child,
        )
        result = SchedulerTruncationRecoveryChildResult.build_typed_success(
            child=child,
            activation=activation,
            dispatch=dispatch,
            usage_record=usage,
            normalization_evidence=normalization,
            normalized_batch=normalized_batch,
            requested_surface_requests=child_requests,
            output_artifact=artifact,
            entry_index=entry_index + 2,
            previous_entry_sha256=dispatch.entry_sha256,
        )
        return result, usage, result.entry_sha256

    root_results_by_plan: dict[str, SchedulerTruncationRecoveryChildResult] = {}
    previous_entry_sha256 = root_family.entry_sha256
    entry_index = 1
    bridge_projection: CandidateReviewTruncationProjection | None = None
    bridge_usage: UsageRecord | None = None
    direct_usage: UsageRecord | None = None
    for child in root_plan.children:
        context = bridge_context if child == bridge_plan else direct_context
        if child == bridge_plan:
            activation = activation_for(
                family=root_family,
                child=child,
                context=context,
                entry_index=entry_index,
                previous_entry_sha256=previous_entry_sha256,
            )
            dispatch = SchedulerTruncationRecoveryChildDispatch.build(
                activation=activation,
                entry_index=entry_index + 1,
                previous_entry_sha256=activation.entry_sha256,
            )
            child_requests = tuple(requests_by_id[item] for item in child.surface_ids)
            bridge_projection, bridge_response_sha256 = _truncated_projection(
                child_requests,
                retained_count=0,
                findings=(_candidate("recursive-bridge-candidate"),),
            )
            raw_bridge_usage = _usage(
                context=context,
                request_id=child.child_logical_request_id,
                generation_id="generation-recursive-bridge",
                response_sha256=bridge_response_sha256,
                validated_response_sha256=None,
                status="rejected_truncated_response",
                finish_reason="length",
                validation_status=ModelRequestValidationStatus.TRUNCATED,
                cost="0.05",
                completion_tokens=20,
            )
            provisional_bridge_usage = _with_request_limit(
                UsageRecord.model_validate(
                    {
                        **raw_bridge_usage.model_dump(mode="python"),
                        "routing": {
                            **raw_bridge_usage.routing,
                            "provider": raw_bridge_usage.provider,
                        },
                    }
                ),
                request_limit_scope=parent_request_id,
                request_limit_count_before=activation.request_limit_count_before_child,
            )
            bridge_envelope = _truncated_envelope(
                provisional_bridge_usage,
                bridge_projection,
            )
            bridge_usage = _real_accountable(
                _with_truncation_custody(
                    provisional_bridge_usage,
                    envelope=bridge_envelope,
                    projection=bridge_projection,
                )
            )
            result = SchedulerTruncationRecoveryChildResult.build_typed_truncated(
                child=child,
                activation=activation,
                dispatch=dispatch,
                failed_usage_record=bridge_usage,
                truncated_envelope_evidence=bridge_envelope,
                truncation_projection=bridge_projection,
                entry_index=entry_index + 2,
                previous_entry_sha256=dispatch.entry_sha256,
            )
        else:
            result, direct_usage, _ = success_result(
                family=root_family,
                child=child,
                context=context,
                entry_index=entry_index,
                previous_entry_sha256=previous_entry_sha256,
            )
        root_results_by_plan[child.child_plan_sha256] = result
        previous_entry_sha256 = result.entry_sha256
        entry_index += 3
    assert bridge_projection is not None
    assert bridge_usage is not None
    assert direct_usage is not None
    root_results = tuple(
        root_results_by_plan[child.child_plan_sha256] for child in root_plan.children
    )
    root_result_pair = (root_results[0], root_results[1])
    bridge_result = root_results_by_plan[bridge_plan.child_plan_sha256]
    direct_result = root_results_by_plan[direct_plan.child_plan_sha256]
    assert bridge_result.runtime_activation is not None
    assert bridge_result.provider_attempt_evidence_sha256 is not None

    claimed_nested_parent = TruncationRecoveryParentBinding.build(
        campaign_id=root_parent.campaign_id,
        pass_plan_id=root_parent.pass_plan_id,
        parent_task_id=bridge_plan.child_task_id,
        parent_logical_request_id=bridge_plan.child_logical_request_id,
        parent_task_plan_sha256=bridge_plan.child_plan_sha256,
        parent_activation_sha256=bridge_result.runtime_activation.entry_sha256,
        provider_attempt_evidence_sha256=bridge_result.provider_attempt_evidence_sha256,
        truncation_projection_sha256=bridge_projection.evidence_sha256,
        requested_surface_manifest_sha256=manifest.requested_surface_manifest_sha256,
        requested_surface_ids=bridge_plan.surface_ids,
        retained_surface_ids=(),
        channel_bindings=(
            _channel_binding(
                TruncationRecoveryChannel.COVERAGE,
                TruncationRecoveryChannelState.INCOMPLETE,
                0,
            ),
            _channel_binding(
                TruncationRecoveryChannel.FINDINGS,
                TruncationRecoveryChannelState.COMPLETE,
                len(bridge_projection.findings),
            ),
            _channel_binding(
                TruncationRecoveryChannel.SUMMARY,
                TruncationRecoveryChannelState.INCOMPLETE,
                0,
            ),
        ),
        current_depth=bridge_plan.depth,
        parent_path=bridge_plan.path,
    )
    nested_parent = rebuild_truncation_recovery_parent_from_projection(
        claimed_parent=claimed_nested_parent,
        projection=bridge_projection,
    )
    nested_before = (
        Decimal(root_resources.accounted_usd_before_parent_exact)
        + Decimal(root_resources.parent_accounted_cost_usd_exact)
        + Decimal(direct_result.accounted_cost_usd_exact)
    )
    nested_resources = TruncationRecoveryResourceBudget.build(
        campaign_cap_usd_exact=root_resources.campaign_cap_usd_exact,
        accounted_usd_before_parent_exact=format(nested_before, "f"),
        parent_accounted_cost_usd_exact=bridge_result.accounted_cost_usd_exact,
        child_reserved_usd_exact=root_resources.child_reserved_usd_exact,
        recovery_requests_consumed=2,
        provider_attempts_before_parent=(
            root_resources.provider_attempts_before_parent
            + root_resources.parent_provider_attempts
            + direct_result.accounted_provider_attempts
        ),
        parent_provider_attempts=bridge_result.accounted_provider_attempts,
        child_provider_attempts=root_resources.child_provider_attempts,
        completion_tokens_before_parent=(
            root_resources.completion_tokens_before_parent
            + root_resources.parent_completion_tokens
            + direct_result.accounted_completion_tokens
        ),
        parent_completion_tokens=bridge_result.accounted_completion_tokens,
        child_completion_tokens=root_resources.child_completion_tokens,
    )
    nested_plan = plan_truncation_recovery(
        parent=nested_parent,
        resources=nested_resources,
    )
    nested_family = SchedulerTruncationRecoveryFamilyRoot.build(
        request_limit_binding=request_limit_binding,
        family_index=1,
        parent_kind=SchedulerTruncationRecoveryParentKind.RECOVERY_CHILD,
        parent_family_id=root_family.family_id,
        parent_terminal_result_sha256=bridge_result.entry_sha256,
        requested_surface_manifest=manifest,
        truncation_projection=bridge_projection,
        recovery_plan=nested_plan,
        request_count_before_family=root_family.request_count_after_family,
        request_limit_count_before_family=root_family.request_limit_count_after_family,
        entry_index=entry_index,
        previous_entry_sha256=previous_entry_sha256,
    )
    previous_entry_sha256 = nested_family.entry_sha256
    entry_index += 1

    nested_results_list: list[SchedulerTruncationRecoveryChildResult] = []
    nested_usages: list[UsageRecord] = []
    nested_contexts: list[ContextPackage] = []
    for child in nested_plan.children:
        context = build_truncation_recovery_child_context(
            parent_context=bridge_context,
            child=child,
        )
        result, usage, previous_entry_sha256 = success_result(
            family=nested_family,
            child=child,
            context=context,
            entry_index=entry_index,
            previous_entry_sha256=previous_entry_sha256,
        )
        nested_results_list.append(result)
        nested_usages.append(usage)
        nested_contexts.append(context)
        entry_index += 3
    nested_result_pair = (nested_results_list[0], nested_results_list[1])
    nested_closure = SchedulerTruncationRecoveryFamilyClosure.build(
        family=nested_family,
        closure_status=SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED,
        child_result_sha256s=(result.entry_sha256 for result in nested_result_pair),
        nested_family_closure_sha256s=(),
        covered_unfinished_surface_ids=nested_plan.parent.unfinished_surface_ids,
        entry_index=entry_index,
        previous_entry_sha256=previous_entry_sha256,
    )
    entry_index += 1
    root_closure = SchedulerTruncationRecoveryFamilyClosure.build(
        family=root_family,
        closure_status=(
            SchedulerTruncationRecoveryClosureStatus.RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING
        ),
        child_result_sha256s=(result.entry_sha256 for result in root_result_pair),
        nested_family_closure_sha256s=(nested_closure.entry_sha256,),
        covered_unfinished_surface_ids=root_plan.parent.unfinished_surface_ids,
        entry_index=entry_index,
        previous_entry_sha256=nested_closure.entry_sha256,
    )
    return _RecursiveTreeFixture(
        root_family=root_family,
        nested_family=nested_family,
        root_closure=root_closure,
        nested_closure=nested_closure,
        root_results=root_result_pair,
        nested_results=nested_result_pair,
        parent_usage=parent_usage,
        bridge_usage=bridge_usage,
        leaf_usages=(direct_usage, nested_usages[0], nested_usages[1]),
        parent_context=parent_context,
        bridge_context=bridge_context,
        leaf_contexts=(direct_context, nested_contexts[0], nested_contexts[1]),
        requests=requests,
    )


def _typed_closure_fixture() -> _TypedClosureFixture:
    comparison, parent_context, child_contexts = build_closure_fixture()
    parent_usage = reattest_synthetic_real_usage(
        UsageRecord.model_validate(
            {
                **comparison.parent.usage_record.model_dump(mode="python"),
                "execution_evidence": ExecutionEvidenceKind.REAL,
            }
        )
    )
    child_usages = tuple(
        bind_synthetic_usage_identity(
            UsageRecord.model_validate(
                {
                    **child.usage_record.model_dump(mode="python"),
                    "execution_evidence": ExecutionEvidenceKind.REAL,
                }
            )
        )
        for child in comparison.children
    )
    parent_reservations = atomic_request_limit_reservations_from_usage(parent_usage)
    assert len(parent_reservations) == 1
    manifest = SchedulerTruncationRecoveryRequestedSurfaceManifest.build(comparison.requests)
    binding = SchedulerTruncationRecoveryRequestLimitBinding.build(
        campaign_id=comparison.campaign_id,
        manifest_sha256=_digest("typed-closure-journal-manifest"),
        request_limit_id=parent_usage.request_id,
        policy=comparison.recovery_plan.policy,
        parent_request_limit_reservation=parent_reservations[0],
    )
    family = SchedulerTruncationRecoveryFamilyRoot.build(
        request_limit_binding=binding,
        family_index=0,
        parent_kind=SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK,
        parent_family_id=None,
        parent_terminal_result_sha256=_digest("typed-closure-parent-terminal"),
        requested_surface_manifest=manifest,
        truncation_projection=comparison.parent.projection,
        recovery_plan=comparison.recovery_plan,
        request_count_before_family=0,
        request_limit_count_before_family=1,
        entry_index=0,
        previous_entry_sha256=None,
    )
    results: list[SchedulerTruncationRecoveryChildResult] = []
    dispatches: list[SchedulerTruncationRecoveryChildDispatch] = []
    previous_entry_sha256 = family.entry_sha256
    entry_index = 1
    for child_plan, child, usage in zip(
        family.recovery_plan.children,
        comparison.children,
        child_usages,
        strict=True,
    ):
        assert usage.request_body_sha256 is not None
        assert usage.user_prompt_sha256 is not None
        assert usage.schema_sha256 is not None
        activation = SchedulerTruncationRecoveryChildActivation.build(
            family=family,
            child=child_plan,
            actual_input_sha256=usage.request_body_sha256,
            system_prompt_sha256=_digest(f"typed-closure-system:{child_plan.child_task_id}"),
            user_prompt_sha256=usage.user_prompt_sha256,
            provider_prompt_sha256=usage.prompt_sha256,
            response_schema_sha256=usage.schema_sha256,
            entry_index=entry_index,
            previous_entry_sha256=previous_entry_sha256,
        )
        dispatch = SchedulerTruncationRecoveryChildDispatch.build(
            activation=activation,
            entry_index=entry_index + 1,
            previous_entry_sha256=activation.entry_sha256,
        )
        result = SchedulerTruncationRecoveryChildResult.build_typed_success(
            child=child_plan,
            activation=activation,
            dispatch=dispatch,
            usage_record=usage,
            normalization_evidence=child.normalization,
            normalized_batch=child.normalized_batch,
            requested_surface_requests=child.requests,
            output_artifact=child.surface_artifact,
            entry_index=entry_index + 2,
            previous_entry_sha256=dispatch.entry_sha256,
        )
        dispatches.append(dispatch)
        results.append(result)
        previous_entry_sha256 = result.entry_sha256
        entry_index += 3
    closure = SchedulerTruncationRecoveryFamilyClosure.build(
        family=family,
        closure_status=SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED,
        child_result_sha256s=(result.entry_sha256 for result in results),
        nested_family_closure_sha256s=(),
        covered_unfinished_surface_ids=family.recovery_plan.parent.unfinished_surface_ids,
        entry_index=entry_index,
        previous_entry_sha256=previous_entry_sha256,
    )
    return _TypedClosureFixture(
        family=family,
        closure=closure,
        results=tuple(results),
        dispatches=tuple(dispatches),
        parent_usage=parent_usage,
        child_usages=child_usages,
        parent_context=parent_context,
        child_contexts=child_contexts,
        requests=comparison.requests,
    )


def _verify_typed_fixture(
    fixture: _TypedClosureFixture,
) -> tuple[VerifiedTruncationRecoveryClosure, TruncationRecoveredSurfaceReviewArtifact]:
    return verify_truncation_recovery_closure(
        family=fixture.family,
        closure=fixture.closure,
        child_results=fixture.results,
        parent_usage_record=fixture.parent_usage,
        child_usage_records=fixture.child_usages,
        parent_context=fixture.parent_context,
        child_contexts=fixture.child_contexts,
        requests=fixture.requests,
    )


def _verify_recursive_fixture(
    fixture: _RecursiveTreeFixture,
) -> tuple[
    VerifiedRecursiveTruncationRecoveryTree,
    TruncationRecoveredRecursiveSurfaceReviewArtifact,
]:
    return verify_recursive_truncation_recovery_tree(
        root_family=fixture.root_family,
        nested_family=fixture.nested_family,
        root_closure=fixture.root_closure,
        nested_closure=fixture.nested_closure,
        root_child_results=fixture.root_results,
        nested_child_results=fixture.nested_results,
        parent_usage_record=fixture.parent_usage,
        bridge_usage_record=fixture.bridge_usage,
        leaf_usage_records=fixture.leaf_usages,
        parent_context=fixture.parent_context,
        bridge_context=fixture.bridge_context,
        leaf_contexts=fixture.leaf_contexts,
        requests=fixture.requests,
    )


def _seal_fixture() -> TruncationRecoveredSurfaceReviewArtifact:
    closure, parent_context, child_contexts = build_closure_fixture()
    return seal_truncation_recovery_surface_evidence(
        recovery_plan=closure.recovery_plan,
        requests=closure.requests,
        parent=closure.parent,
        parent_context=parent_context,
        children=tuple(
            TruncationRecoveryChildInput(completion=completion, context=context)
            for completion, context in zip(
                closure.children,
                child_contexts,
                strict=True,
            )
        ),
    )


def test_live_predicates_produce_only_noncreditable_surface_comparison() -> None:
    artifact = _seal_fixture()

    assert artifact.structural_outcome == "EXACT_SURFACE_PARTITION_VALIDATED"
    assert artifact.surface_set_structurally_closed
    assert not artifact.scheduler_custody_verified
    assert not artifact.scheduler_surface_closure_eligible
    assert not artifact.surface_review_credit_eligible
    assert not artifact.review_credit_authorized
    assert not artifact.completion_authorized
    assert not artifact.candidate_credit_eligible
    assert "usage_record" not in type(artifact).model_fields


def test_exact_recursive_tree_issues_five_request_live_capability() -> None:
    fixture = _recursive_tree_fixture()
    capability, initial = _verify_recursive_fixture(fixture)
    projection = require_verified_recursive_truncation_recovery_tree_projection(capability)
    replayed = require_verified_recursive_truncation_recovery_tree(capability, initial)

    assert projection.artifact == replayed == initial
    assert projection.artifact is not initial
    assert projection.direct_child_result_sha256s == tuple(
        result.entry_sha256 for result in fixture.root_results
    )
    assert projection.nested_child_result_sha256s == tuple(
        result.entry_sha256 for result in fixture.nested_results
    )
    assert projection.promoted_leaf_result_sha256s == (
        next(
            result.entry_sha256
            for result in fixture.root_results
            if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
        ),
        *(result.entry_sha256 for result in fixture.nested_results),
    )
    assert projection.superseded_bridge_result_sha256 == next(
        result.entry_sha256
        for result in fixture.root_results
        if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED
    )
    assert len(projection.scanner_fingerprints_by_request) == 5
    assert tuple(item[0] for item in projection.scanner_fingerprints_by_request) == tuple(
        sorted(
            (
                fixture.parent_usage.request_id,
                fixture.bridge_usage.request_id,
                *(usage.request_id for usage in fixture.leaf_usages),
            )
        )
    )
    assert initial.bridge.projection.surface_reviews == ()
    assert len(initial.bridge.projection.findings) == 1
    assert len(initial.children) == 3
    assert tuple(record.surface_id for record in initial.records) == tuple(
        request.surface_id for request in fixture.requests
    )
    assert not initial.scheduler_custody_verified
    assert not initial.surface_review_credit_eligible
    assert not initial.candidate_credit_eligible
    assert not initial.completion_authorized


def test_recursive_tree_capability_is_opaque_and_exact_order_bound() -> None:
    fixture = _recursive_tree_fixture()
    capability, artifact = _verify_recursive_fixture(fixture)
    with pytest.raises(TypeError):
        VerifiedRecursiveTruncationRecoveryTree()
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError, match=r"cannot be copied|cannot be serialized"):
            operation(capability)
    with pytest.raises(TruncationRecoveryEvidenceError, match="absent or forged"):
        require_verified_recursive_truncation_recovery_tree(
            object.__new__(VerifiedRecursiveTruncationRecoveryTree),
            artifact,
        )
    with pytest.raises(TruncationRecoveryEvidenceError):
        verify_recursive_truncation_recovery_tree(
            root_family=fixture.root_family,
            nested_family=fixture.nested_family,
            root_closure=fixture.root_closure,
            nested_closure=fixture.nested_closure,
            root_child_results=fixture.root_results,
            nested_child_results=tuple(reversed(fixture.nested_results)),
            parent_usage_record=fixture.parent_usage,
            bridge_usage_record=fixture.bridge_usage,
            leaf_usage_records=fixture.leaf_usages,
            parent_context=fixture.parent_context,
            bridge_context=fixture.bridge_context,
            leaf_contexts=fixture.leaf_contexts,
            requests=fixture.requests,
        )


@pytest.mark.parametrize("clone_kind", ["parent", "bridge", "leaf"])
def test_recursive_tree_rejects_serialized_live_usage_clone(clone_kind: str) -> None:
    fixture = _recursive_tree_fixture()
    parent_usage = fixture.parent_usage
    bridge_usage = fixture.bridge_usage
    leaf_usages = fixture.leaf_usages
    if clone_kind == "parent":
        parent_usage = UsageRecord.model_validate_json(parent_usage.model_dump_json())
    elif clone_kind == "bridge":
        bridge_usage = UsageRecord.model_validate_json(bridge_usage.model_dump_json())
    else:
        leaf_usages = (
            UsageRecord.model_validate_json(leaf_usages[0].model_dump_json()),
            leaf_usages[1],
            leaf_usages[2],
        )
    with pytest.raises(TruncationRecoveryEvidenceError, match="live re-attested"):
        verify_recursive_truncation_recovery_tree(
            root_family=fixture.root_family,
            nested_family=fixture.nested_family,
            root_closure=fixture.root_closure,
            nested_closure=fixture.nested_closure,
            root_child_results=fixture.root_results,
            nested_child_results=fixture.nested_results,
            parent_usage_record=parent_usage,
            bridge_usage_record=bridge_usage,
            leaf_usage_records=leaf_usages,
            parent_context=fixture.parent_context,
            bridge_context=fixture.bridge_context,
            leaf_contexts=fixture.leaf_contexts,
            requests=fixture.requests,
        )


def test_capability_is_unconstructible_noncopyable_and_registry_bound() -> None:
    fixture = _typed_closure_fixture()
    capability, artifact = _verify_typed_fixture(fixture)
    with pytest.raises(TypeError):
        VerifiedTruncationRecoveryClosure()
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError, match=r"cannot be copied|cannot be serialized"):
            operation(capability)

    forged = object.__new__(VerifiedTruncationRecoveryClosure)
    with pytest.raises(TruncationRecoveryEvidenceError, match="absent or forged"):
        require_verified_truncation_recovery_closure(forged, artifact)

    class ForgedSubclass(VerifiedTruncationRecoveryClosure):
        pass

    with pytest.raises(TruncationRecoveryEvidenceError, match="absent or forged"):
        require_verified_truncation_recovery_closure(
            object.__new__(ForgedSubclass),
            artifact,
        )
    with pytest.raises(TruncationRecoveryEvidenceError, match="absent or forged"):
        require_verified_truncation_recovery_closure(object(), artifact)  # type: ignore[arg-type]


def test_direct_typed_success_family_issues_only_fresh_non_authorizing_artifacts() -> None:
    fixture = _typed_closure_fixture()
    capability, initial = _verify_typed_fixture(fixture)

    first = require_verified_truncation_recovery_closure(capability, initial)
    second = require_verified_truncation_recovery_closure(capability)
    projection = require_verified_truncation_recovery_closure_projection(capability)
    second_projection = require_verified_truncation_recovery_closure_projection(capability)

    assert first == second == initial
    assert first is not initial
    assert second is not first
    assert first.parent.projection.findings == fixture.family.truncation_projection.findings
    assert first.records == initial.records
    assert not first.scheduler_custody_verified
    assert not first.scheduler_surface_closure_eligible
    assert not first.surface_review_credit_eligible
    assert not first.candidate_credit_eligible
    assert not first.review_credit_authorized
    assert not first.completion_authorized
    assert not first.release_authorized
    expected_fingerprints = (_digest("truncation-closure-scanner-fingerprint"),)
    expected_request_ids = tuple(
        sorted(
            (
                fixture.parent_usage.request_id,
                *(usage.request_id for usage in fixture.child_usages),
            )
        )
    )
    assert projection.artifact == initial
    assert tuple(item[0] for item in projection.scanner_fingerprints_by_request) == (
        expected_request_ids
    )
    assert all(
        fingerprints == expected_fingerprints
        for _request_id, fingerprints in projection.scanner_fingerprints_by_request
    )
    assert second_projection == projection
    assert second_projection is not projection
    assert second_projection.artifact is not projection.artifact
    durable_payload = projection.artifact.model_dump(mode="json")
    assert "scanner_fingerprints_by_request" not in durable_payload
    assert "parent_context" not in durable_payload
    assert "child_contexts" not in durable_payload


@pytest.mark.parametrize("clone_kind", ["parent", "child"])
def test_serialized_real_usage_clone_cannot_issue_live_closure(clone_kind: str) -> None:
    fixture = _typed_closure_fixture()
    parent_usage = fixture.parent_usage
    child_usages = fixture.child_usages
    if clone_kind == "parent":
        parent_usage = UsageRecord.model_validate_json(parent_usage.model_dump_json())
    else:
        child_usages = (
            UsageRecord.model_validate_json(child_usages[0].model_dump_json()),
            child_usages[1],
        )

    with pytest.raises(TruncationRecoveryEvidenceError, match="live re-attested"):
        verify_truncation_recovery_closure(
            family=fixture.family,
            closure=fixture.closure,
            child_results=fixture.results,
            parent_usage_record=parent_usage,
            child_usage_records=child_usages,
            parent_context=fixture.parent_context,
            child_contexts=fixture.child_contexts,
            requests=fixture.requests,
        )


def test_module_predicate_reassignment_cannot_admit_detached_real_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _typed_closure_fixture()
    detached_parent = UsageRecord.model_validate_json(fixture.parent_usage.model_dump_json())
    monkeypatch.setattr(
        recovery_evidence,
        "is_accountable_usage_record",
        lambda _usage, **_requirements: True,
    )
    monkeypatch.setattr(
        recovery_evidence,
        "is_recovery_creditable_usage_record",
        lambda _usage, **_requirements: True,
    )

    with pytest.raises(TruncationRecoveryEvidenceError, match="live re-attested"):
        verify_truncation_recovery_closure(
            family=fixture.family,
            closure=fixture.closure,
            child_results=fixture.results,
            parent_usage_record=detached_parent,
            child_usage_records=fixture.child_usages,
            parent_context=fixture.parent_context,
            child_contexts=fixture.child_contexts,
            requests=fixture.requests,
        )


@pytest.mark.parametrize("swap_kind", ["results", "usage", "contexts"])
def test_direct_child_swap_cannot_issue_live_closure(swap_kind: str) -> None:
    fixture = _typed_closure_fixture()
    results = fixture.results
    child_usages = fixture.child_usages
    child_contexts = fixture.child_contexts
    if swap_kind == "results":
        results = tuple(reversed(results))
    elif swap_kind == "usage":
        child_usages = tuple(reversed(child_usages))
    else:
        child_contexts = tuple(reversed(child_contexts))

    with pytest.raises(TruncationRecoveryEvidenceError):
        verify_truncation_recovery_closure(
            family=fixture.family,
            closure=fixture.closure,
            child_results=results,
            parent_usage_record=fixture.parent_usage,
            child_usage_records=child_usages,
            parent_context=fixture.parent_context,
            child_contexts=child_contexts,
            requests=fixture.requests,
        )


def test_v11_closed_family_rejects_mixed_legacy_hash_only_child() -> None:
    fixture = _typed_closure_fixture()
    child = fixture.family.recovery_plan.children[0]
    legacy = SchedulerTruncationRecoveryChildResult.build_runtime(
        child=child,
        dispatch=fixture.dispatches[0],
        terminal_status=SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED,
        terminal_evidence_sha256=_digest("legacy-completion"),
        provider_attempt_evidence_sha256=_digest("legacy-provider-attempt"),
        accounted_provider_attempts=child.reserved_provider_attempts,
        accounted_completion_tokens=child.reserved_completion_tokens,
        accounted_cost_usd_exact=child.reserved_usd_exact,
        runtime_completion_evidence_sha256=_digest("legacy-runtime-completion"),
        runtime_usage_record_sha256=_digest("legacy-usage"),
        runtime_output_artifact_sha256=_digest("legacy-output"),
        entry_index=fixture.results[0].entry_index,
        previous_entry_sha256=fixture.results[0].previous_entry_sha256,
    )
    results = (legacy, fixture.results[1])
    closure = SchedulerTruncationRecoveryFamilyClosure.build(
        family=fixture.family,
        closure_status=SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED,
        child_result_sha256s=(result.entry_sha256 for result in results),
        nested_family_closure_sha256s=(),
        covered_unfinished_surface_ids=(fixture.family.recovery_plan.parent.unfinished_surface_ids),
        entry_index=fixture.closure.entry_index,
        previous_entry_sha256=fixture.closure.previous_entry_sha256,
    )

    with pytest.raises(TruncationRecoveryEvidenceError, match="mixed or non-success"):
        verify_truncation_recovery_closure(
            family=fixture.family,
            closure=closure,
            child_results=results,
            parent_usage_record=fixture.parent_usage,
            child_usage_records=fixture.child_usages,
            parent_context=fixture.parent_context,
            child_contexts=fixture.child_contexts,
            requests=fixture.requests,
        )


def test_returned_artifact_and_live_usage_mutation_cannot_change_closure_state() -> None:
    fixture = _typed_closure_fixture()
    capability, artifact = _verify_typed_fixture(fixture)
    expected_sha256 = artifact.artifact_sha256
    projection = require_verified_truncation_recovery_closure_projection(capability)
    expected_scanner_projection = projection.scanner_fingerprints_by_request
    object.__setattr__(projection, "scanner_fingerprints_by_request", ())
    object.__setattr__(artifact, "artifact_sha256", "0" * 64)

    with pytest.raises(TruncationRecoveryEvidenceError, match="differs"):
        require_verified_truncation_recovery_closure(capability, artifact)
    assert require_verified_truncation_recovery_closure(capability).artifact_sha256 == (
        expected_sha256
    )
    assert (
        require_verified_truncation_recovery_closure_projection(
            capability
        ).scanner_fingerprints_by_request
        == expected_scanner_projection
    )

    object.__setattr__(fixture.child_usages[0], "status", "mutated")
    with pytest.raises(TruncationRecoveryEvidenceError):
        require_verified_truncation_recovery_closure(capability)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork is unavailable")
def test_verified_closure_cannot_cross_a_process_fork() -> None:
    capability, _artifact = _verify_typed_fixture(_typed_closure_fixture())
    child = os.fork()
    if child == 0:  # pragma: no cover - asserted through the child exit status
        status = 1
        try:
            require_verified_truncation_recovery_closure(capability)
        except TruncationRecoveryEvidenceError as exc:
            if "process fork" in str(exc):
                status = 0
        os._exit(status)
    _, wait_status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(wait_status) == 0


def test_swapped_child_context_cannot_seal() -> None:
    closure, parent_context, child_contexts = build_closure_fixture()
    assert len(closure.children) == len(child_contexts) == 2

    with pytest.raises(TruncationRecoveryEvidenceError):
        seal_truncation_recovery_surface_evidence(
            recovery_plan=closure.recovery_plan,
            requests=closure.requests,
            parent=closure.parent,
            parent_context=parent_context,
            children=(
                TruncationRecoveryChildInput(
                    completion=closure.children[0],
                    context=child_contexts[1],
                ),
                TruncationRecoveryChildInput(
                    completion=closure.children[1],
                    context=child_contexts[0],
                ),
            ),
        )


def test_child_control_budget_drift_cannot_seal() -> None:
    closure, parent_context, child_contexts = build_closure_fixture()
    drifted = child_contexts[0].model_copy(
        update={"byte_budget": child_contexts[0].byte_budget + 1},
        deep=True,
    )

    with pytest.raises(TruncationRecoveryEvidenceError, match="drifted"):
        seal_truncation_recovery_surface_evidence(
            recovery_plan=closure.recovery_plan,
            requests=closure.requests,
            parent=closure.parent,
            parent_context=parent_context,
            children=(
                TruncationRecoveryChildInput(
                    completion=closure.children[0],
                    context=drifted,
                ),
                TruncationRecoveryChildInput(
                    completion=closure.children[1],
                    context=child_contexts[1],
                ),
            ),
        )


def test_child_context_is_exact_strict_shard_of_parent_analysis() -> None:
    closure, parent_context, expected_child_contexts = build_closure_fixture()

    derived = tuple(
        build_truncation_recovery_child_context(parent_context=parent_context, child=child)
        for child in closure.recovery_plan.children
    )

    assert derived == expected_child_contexts
    assert all(
        tuple(request.surface_id for request in context.requested_model_surfaces)
        == child.surface_ids
        for child, context in zip(closure.recovery_plan.children, derived, strict=True)
    )
    assert {
        model_surface_analysis_context_sha256(context) for context in (parent_context, *derived)
    } == {model_surface_analysis_context_sha256(parent_context)}


def test_child_context_rejects_surface_outside_exact_parent_inventory() -> None:
    closure, parent_context, _child_contexts = build_closure_fixture()
    child = closure.recovery_plan.children[0]
    narrowed_parent = parent_context.model_copy(
        update={
            "requested_model_surfaces": tuple(
                request
                for request in closure.requests
                if request.surface_id not in child.surface_ids
            )
        },
        deep=True,
    )
    narrowed_parent = narrowed_parent.model_copy(
        update={"bytes_used": len(render_context(narrowed_parent).encode("utf-8"))},
        deep=True,
    )

    with pytest.raises(TruncationRecoveryEvidenceError, match="unknown parent surface"):
        build_truncation_recovery_child_context(
            parent_context=narrowed_parent,
            child=child,
        )


def test_child_context_revalidates_the_child_plan_before_derivation() -> None:
    closure, parent_context, _child_contexts = build_closure_fixture()
    child = closure.recovery_plan.children[0].model_copy(deep=True)
    object.__setattr__(child, "surface_ids", closure.recovery_plan.children[1].surface_ids)

    with pytest.raises(TruncationRecoveryEvidenceError, match="exact boundary"):
        build_truncation_recovery_child_context(
            parent_context=parent_context,
            child=child,
        )


@pytest.mark.parametrize("custody_check", ["parent", "child"])
def test_live_usage_predicate_failure_never_produces_comparison_evidence(
    monkeypatch: pytest.MonkeyPatch,
    custody_check: str,
) -> None:
    closure, parent_context, child_contexts = build_closure_fixture()
    children = tuple(
        TruncationRecoveryChildInput(completion=completion, context=context)
        for completion, context in zip(closure.children, child_contexts, strict=True)
    )
    if custody_check == "parent":
        monkeypatch.setattr(recovery_evidence, "is_accountable_usage_record", lambda _usage: False)
    else:
        monkeypatch.setattr(
            recovery_evidence,
            "is_recovery_creditable_usage_record",
            lambda _usage, **_coordinates: False,
        )

    with pytest.raises(TruncationRecoveryEvidenceError):
        seal_truncation_recovery_surface_evidence(
            recovery_plan=closure.recovery_plan,
            requests=closure.requests,
            parent=closure.parent,
            parent_context=parent_context,
            children=children,
        )
