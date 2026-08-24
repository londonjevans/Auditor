"""End-to-end journal regression for opaque truncation-recovery promotion."""

from __future__ import annotations

import hashlib
import json
import pickle
from decimal import Decimal
from pathlib import Path

import pytest

import mmaudit.models.openrouter as openrouter_module
import mmaudit.orchestration.scheduler as scheduler_module
from mmaudit.models.scheduler import (
    SchedulerBindings,
    SchedulerPassKind,
    SchedulerPassStatus,
    SchedulerScope,
    SchedulerTaskResult,
    SchedulerTerminalStatus,
    SchedulerTruncationRecoveryPromotionDisposition,
)
from mmaudit.models.schemas import (
    CandidateReviewBatch,
    ContextPackage,
    ExecutionEvidenceKind,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
    UsageRecord,
)
from mmaudit.models.truncation import (
    CandidateReviewTruncatedEnvelopeEvidence,
    CandidateReviewTruncationProjection,
    candidate_review_frame_wire_schema_sha256,
    frame_candidate_review_batch,
    seal_candidate_review_truncated_envelope_evidence,
)
from mmaudit.models.truncation_closure import (
    _INVARIANT_ROUTING_KEYS,
    TruncationSurfaceOriginKind,
)
from mmaudit.models.truncation_recovery import (
    TruncationRecoveryParentBinding,
    plan_truncation_recovery,
)
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryClosureStatus,
    SchedulerTruncationRecoveryEntryKind,
    SchedulerTruncationRecoveryFamilyClosure,
    SchedulerTruncationRecoveryRequestedSurfaceManifest,
    SchedulerTruncationRecoveryTerminalStatus,
    rebuild_truncation_recovery_parent_from_projection,
)
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.scheduler_runtime import PipelineScheduler
from mmaudit.orchestration.truncation_recovery_evidence import (
    VerifiedPromotedRecursiveTruncationRecoverySurfaceCoverage,
    VerifiedPromotedTruncationRecoverySurfaceCoverage,
    VerifiedRecursiveTruncationRecoveryTree,
    VerifiedTruncationRecoveryClosure,
    build_truncation_recovery_child_context,
    require_verified_promoted_recursive_truncation_recovery_surface_coverage,
    require_verified_promoted_truncation_recovery_surface_coverage,
    verify_recursive_truncation_recovery_tree,
    verify_truncation_recovery_closure,
)
from tests.identity_fixtures import reattest_synthetic_real_usage
from tests.output_evidence_fixtures import synthetic_structured_output_routing
from tests.scheduler_support import (
    bind_scheduler_test_usage_to_audit_model_refresh,
    bind_scheduler_test_usage_to_audit_model_refresh_pricing,
    bind_scheduler_test_usage_to_audit_selection,
    build_scheduler_test_audit_model_refresh_binding,
    build_scheduler_test_audit_model_refresh_pricing_binding,
    build_scheduler_test_audit_model_selection_binding,
    build_scheduler_test_model_payload,
    build_scheduler_test_real_usage,
    scheduler_test_delivered_source_descriptor_sha256s,
    scheduler_test_host_activation_input_sha256,
)
from tests.unit.test_scheduler_journal import (
    SHARDS,
    _analysis_inventory,
    _bindings,
    _inventory,
    _plan,
    _privacy_custody,
    create_scheduler_journal,
    resume_scheduler_journal,
)
from tests.unit.test_truncation_closure import (
    _context,
    _context_evidence,
    _record,
    _requests,
)
from tests.unit.test_truncation_recovery_journal import (
    _nested_plan_for_typed_truncated_child,
    _placeholder_channels,
    _projection,
    _resources,
    _success_custody,
    _truncated_custody,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _one_shard_bindings() -> SchedulerBindings:
    inventory = _inventory(one_shard=True)
    base = _bindings()
    audit_selection = build_scheduler_test_audit_model_selection_binding(
        source_sha256=inventory.source_tree_sha256,
        selected_routes=(
            (
                "synthetic/auditor-v1",
                "sha256:" + hashlib.sha256(b"synthetic/auditor-v1").hexdigest(),
                "Synthetic Provider",
                "synthetic-provider/endpoint",
            ),
        ),
    )
    audit_refresh = build_scheduler_test_audit_model_refresh_binding(audit_selection)
    audit_pricing = build_scheduler_test_audit_model_refresh_pricing_binding(
        audit_selection,
        audit_refresh,
    )
    return SchedulerBindings.build(
        source_sha256=inventory.source_tree_sha256,
        analysis_input_sha256=_analysis_inventory().analysis_input_sha256,
        effective_config_sha256=base.effective_config_sha256,
        shard_inventory_sha256=inventory.inventory_sha256,
        model_selection_sha256=base.model_selection_sha256,
        qualification_sha256=base.qualification_sha256,
        prompt_set_sha256=base.prompt_set_sha256,
        schema_set_sha256=base.schema_set_sha256,
        tool_policy_sha256=base.tool_policy_sha256,
        privacy_evidence_custody_sha256=_privacy_custody(
            source_sha256=inventory.source_tree_sha256
        ).custody_sha256,
        audit_model_selection=audit_selection,
        audit_model_refresh=audit_refresh,
        audit_model_refresh_pricing=audit_pricing,
    )


def _complete_real_orientation(journal: object) -> None:
    from mmaudit.orchestration.scheduler import SchedulerJournal

    assert isinstance(journal, SchedulerJournal)
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    activation = journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="3" * 64,
        provider_prompt_sha256="4" * 64,
        response_schema_sha256=task.response_schema_sha256,
        delivered_source_descriptor_sha256s=(
            scheduler_test_delivered_source_descriptor_sha256s(plan, task)
        ),
    )
    journal.mark_dispatched(task.task_id)
    payload = build_scheduler_test_model_payload(plan, task)
    usage = build_scheduler_test_real_usage(
        task,
        activation,
        seed="promotion-orientation",
        validated_output=payload,
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
        audit_model_selection=journal.manifest.bindings.audit_model_selection,
        audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
        audit_model_refresh_pricing=journal.manifest.bindings.audit_model_refresh_pricing,
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
    assert journal.seal_pass_result(SchedulerPassKind.ORIENTATION).status is (
        SchedulerPassStatus.COMPLETE
    )


def _typed_parent_truncation(
    *,
    journal: object,
    task: object,
    activation: object,
    context: ContextPackage,
    projection: CandidateReviewTruncationProjection,
    full_batch: CandidateReviewBatch,
) -> tuple[CandidateReviewTruncatedEnvelopeEvidence, UsageRecord]:
    # These imports stay local so the helper's deliberately narrow structural types
    # remain obvious at the test boundary.
    from mmaudit.models.scheduler import SchedulerTaskActivation, SchedulerTaskPlan
    from mmaudit.orchestration.scheduler import SchedulerJournal

    assert isinstance(journal, SchedulerJournal)
    assert isinstance(task, SchedulerTaskPlan)
    assert isinstance(activation, SchedulerTaskActivation)
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
    context_evidence = _context_evidence(context, task.logical_request_id)
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


def _bind_child_to_parent_invariant(
    usage: UsageRecord,
    *,
    journal: object,
    parent_usage: UsageRecord,
) -> UsageRecord:
    from mmaudit.orchestration.scheduler import SchedulerJournal

    assert isinstance(journal, SchedulerJournal)
    selection = journal.manifest.bindings.audit_model_selection
    refresh = journal.manifest.bindings.audit_model_refresh
    pricing = journal.manifest.bindings.audit_model_refresh_pricing
    assert selection is not None and refresh is not None and pricing is not None
    bound = bind_scheduler_test_usage_to_audit_selection(usage, selection)
    bound = bind_scheduler_test_usage_to_audit_model_refresh(bound, selection, refresh)
    bound = bind_scheduler_test_usage_to_audit_model_refresh_pricing(
        bound,
        selection,
        refresh,
        pricing,
    )
    routing = dict(bound.routing)
    for key in _INVARIANT_ROUTING_KEYS:
        routing.pop(key, None)
        if key in parent_usage.routing:
            routing[key] = parent_usage.routing[key]
    endpoint_snapshot_sha256 = routing.get("endpoint_snapshot_sha256")
    output_capability_sha256 = routing.get("output_capability_sha256")
    provider_policy_sha256 = routing.get("provider_policy_sha256")
    assert isinstance(endpoint_snapshot_sha256, str)
    assert isinstance(output_capability_sha256, str)
    assert isinstance(provider_policy_sha256, str)
    assert bound.actual_provider_endpoint is not None
    assert bound.prompt_sha256 is not None
    assert bound.request_body_sha256 is not None
    assert bound.schema_sha256 is not None
    assert bound.response_sha256 is not None
    assert bound.validated_response_sha256 is not None
    routing["structured_output"] = synthetic_structured_output_routing(
        configured_provider_endpoints=tuple(bound.configured_provider_endpoints),
        selected_provider_endpoint=bound.actual_provider_endpoint,
        endpoint_snapshot_sha256=endpoint_snapshot_sha256,
        output_capability_sha256=output_capability_sha256,
        prompt_sha256=bound.prompt_sha256,
        request_body_sha256=bound.request_body_sha256,
        provider_policy_sha256=provider_policy_sha256,
        schema_sha256=bound.schema_sha256,
        original_response_sha256=bound.response_sha256,
        validated_response_sha256=bound.validated_response_sha256,
    )
    return reattest_synthetic_real_usage(
        bound.model_copy(
            update={
                "model_family": parent_usage.model_family,
                "routing": routing,
            }
        )
    )


def _bind_bridge_to_parent_invariant(
    usage: UsageRecord,
    *,
    journal: object,
    parent_usage: UsageRecord,
) -> UsageRecord:
    """Align a truncated recovery bridge without granting successful-use credit."""

    from mmaudit.orchestration.scheduler import SchedulerJournal

    assert isinstance(journal, SchedulerJournal)
    selection = journal.manifest.bindings.audit_model_selection
    refresh = journal.manifest.bindings.audit_model_refresh
    pricing = journal.manifest.bindings.audit_model_refresh_pricing
    assert selection is not None and refresh is not None and pricing is not None
    bound = bind_scheduler_test_usage_to_audit_selection(usage, selection)
    bound = bind_scheduler_test_usage_to_audit_model_refresh(bound, selection, refresh)
    bound = bind_scheduler_test_usage_to_audit_model_refresh_pricing(
        bound,
        selection,
        refresh,
        pricing,
    )
    routing = dict(bound.routing)
    for key in _INVARIANT_ROUTING_KEYS:
        routing.pop(key, None)
        if key in parent_usage.routing:
            routing[key] = parent_usage.routing[key]
    rebound = bound.model_copy(
        update={
            "model_family": parent_usage.model_family,
            "routing": routing,
        }
    )
    return reattest_synthetic_real_usage(rebound)


def _recovery_plan(
    *,
    journal: object,
    pass_plan: object,
    task: object,
    activation: object,
    attempt: object,
    projection: CandidateReviewTruncationProjection,
    manifest: SchedulerTruncationRecoveryRequestedSurfaceManifest,
    parent_usage: UsageRecord,
) -> object:
    from mmaudit.models.scheduler import (
        SchedulerPassPlan,
        SchedulerProviderAttemptEvidence,
        SchedulerTaskActivation,
        SchedulerTaskPlan,
    )
    from mmaudit.models.truncation_recovery import TruncationRecoveryPlan
    from mmaudit.orchestration.scheduler import SchedulerJournal

    assert isinstance(journal, SchedulerJournal)
    assert isinstance(pass_plan, SchedulerPassPlan)
    assert isinstance(task, SchedulerTaskPlan)
    assert isinstance(activation, SchedulerTaskActivation)
    assert isinstance(attempt, SchedulerProviderAttemptEvidence)
    claimed = TruncationRecoveryParentBinding.build(
        campaign_id=journal.manifest.campaign_id,
        pass_plan_id=pass_plan.pass_plan_id,
        parent_task_id=task.task_id,
        parent_logical_request_id=task.logical_request_id,
        parent_task_plan_sha256=task.task_plan_sha256,
        parent_activation_sha256=activation.activation_sha256,
        provider_attempt_evidence_sha256=attempt.attempt_evidence_sha256,
        truncation_projection_sha256=projection.evidence_sha256,
        requested_surface_manifest_sha256=manifest.requested_surface_manifest_sha256,
        requested_surface_ids=manifest.requested_surface_ids,
        retained_surface_ids=tuple(item.surface_id for item in projection.surface_reviews),
        channel_bindings=_placeholder_channels(projection),
    )
    parent = rebuild_truncation_recovery_parent_from_projection(
        claimed_parent=claimed,
        projection=projection,
    )
    prior_usages = tuple(
        item
        for item in journal.structurally_successful_review_usage_records
        if item.request_id != parent_usage.request_id
    )
    prior_cost = sum(
        (Decimal(item.accounted_cost_usd_exact or "0") for item in prior_usages),
        start=Decimal("0"),
    )
    plan = plan_truncation_recovery(
        parent=parent,
        resources=_resources(
            recovery_requests_consumed=0,
            accounted_before=format(prior_cost, "f"),
            attempts_before=sum(item.attempts for item in prior_usages),
            tokens_before=sum(item.completion_tokens for item in prior_usages),
            parent_attempts=parent_usage.attempts,
            parent_tokens=parent_usage.completion_tokens,
            parent_cost=parent_usage.accounted_cost_usd_exact or "0",
        ),
    )
    assert isinstance(plan, TruncationRecoveryPlan)
    return plan


def test_live_closure_promotes_truncated_blind_task_and_replays_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "promoted-recovery"
    bindings = _one_shard_bindings()
    inventory = _inventory(one_shard=True)
    journal = create_scheduler_journal(
        path,
        bindings=bindings,
        shard_inventory=inventory,
        privacy_evidence_custody=_privacy_custody(source_sha256=inventory.source_tree_sha256),
    )
    _complete_real_orientation(journal)

    requests: tuple[ModelSurfaceReviewRequest, ...] = _requests()
    records: tuple[ModelSurfaceReviewRecord, ...] = tuple(_record(item) for item in requests)
    parent_context = _context(requests)
    projection = _projection(records, retained_count=1)
    assert projection.findings_state.value == "COMPLETE"
    assert len(projection.surface_reviews) == 1
    surface_manifest = SchedulerTruncationRecoveryRequestedSurfaceManifest.build(requests)

    planner = PipelineScheduler(journal)
    audit_selection = journal.manifest.bindings.audit_model_selection
    assert audit_selection is not None
    model_id = audit_selection.selected_model_ids[0]
    blind_task = planner.model_task(
        pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
        scope=SchedulerScope.single_shard(SHARDS[0]),
        task_key="promotion-source-audit",
        role="source_audit",
        requested_model=model_id,
        root_lineage=audit_selection.route_for(model_id).root_lineage,
        system_prompt_sha256="a" * 64,
        response_schema_sha256=candidate_review_frame_wire_schema_sha256(),
    )
    blind_plan = planner.prepare_pass(SchedulerPassKind.BLIND_SHARD_REVIEW, (blind_task,))
    parent_context_sha256 = hashlib.sha256(render_context(parent_context).encode()).hexdigest()
    parent_activation = journal.activate_task(
        blind_task.task_id,
        actual_input_sha256=blind_task.input_sha256,
        system_prompt_sha256=blind_task.system_prompt_sha256,
        user_prompt_sha256=parent_context_sha256,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=blind_task.response_schema_sha256,
        delivered_source_descriptor_sha256s=(
            scheduler_test_delivered_source_descriptor_sha256s(blind_plan, blind_task)
        ),
    )
    journal.mark_dispatched(blind_task.task_id)
    full_batch = CandidateReviewBatch(findings=(), surface_reviews=records)
    envelope, parent_usage = _typed_parent_truncation(
        journal=journal,
        task=blind_task,
        activation=parent_activation,
        context=parent_context,
        projection=projection,
        full_batch=full_batch,
    )
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
    assert all(output.task_id != blind_task.task_id for output in journal.outputs)

    recovery_plan = _recovery_plan(
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
    retained_surface_ids = tuple(item.surface_id for item in projection.surface_reviews)
    assert recovery_plan.parent.retained_surface_ids == retained_surface_ids
    assert set(recovery_plan.parent.unfinished_surface_ids) == (
        set(recovery_plan.parent.requested_surface_ids) - set(retained_surface_ids)
    )
    child_surface_ids = tuple(
        surface_id for child in recovery_plan.children for surface_id in child.surface_ids
    )
    assert len(child_surface_ids) == len(set(child_surface_ids))
    assert set(child_surface_ids) == set(recovery_plan.parent.unfinished_surface_ids)
    assert not set(child_surface_ids).intersection(retained_surface_ids)
    child_results = []
    child_usages = []
    child_contexts = []
    for child in recovery_plan.children:
        child_context = build_truncation_recovery_child_context(
            parent_context=parent_context,
            child=child,
        )
        child_contexts.append(child_context)
        child_activation = journal.activate_truncation_recovery_child(
            child.child_task_id,
            actual_input_sha256=_digest(f"input:{child.child_task_id}"),
            system_prompt_sha256=_digest(f"system:{child.child_task_id}"),
            user_prompt_sha256=hashlib.sha256(render_context(child_context).encode()).hexdigest(),
            provider_prompt_sha256=_digest(f"provider:{child.child_task_id}"),
            response_schema_sha256=candidate_review_frame_wire_schema_sha256(),
        )
        journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
        usage, normalization, batch, child_requests, artifact = _success_custody(
            child=child,
            activation=child_activation,
            surface_manifest=surface_manifest,
            surfaces=records,
            execution_evidence=ExecutionEvidenceKind.REAL,
        )
        usage = _bind_child_to_parent_invariant(
            usage,
            journal=journal,
            parent_usage=parent_usage,
        )
        child_usages.append(usage)
        child_result = journal.record_truncation_recovery_child_success(
            child.child_task_id,
            usage_record=usage,
            normalization_evidence=normalization,
            normalized_batch=batch,
            requested_surface_requests=child_requests,
            output_artifact=artifact,
        )
        assert child_result.runtime_usage_record is usage
        child_results.append(child_result)

    unpromoted_requests = journal.recovery_model_requests
    assert len(unpromoted_requests) == 2
    assert all(item.promotion_entry_sha256 is None for item in unpromoted_requests)
    assert {item.logical_request_id for item in unpromoted_requests} == {
        item.request_id for item in child_usages
    }
    assert journal.artifact().recovery_model_requests == unpromoted_requests
    assert not {
        item.request_id for item in journal.structurally_successful_review_usage_records
    }.intersection(item.request_id for item in child_usages)

    closure = journal.seal_truncation_recovery_family(family.family_id)
    assert closure.closure_status is SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
    capability, structural_artifact = verify_truncation_recovery_closure(
        family=family,
        closure=closure,
        child_results=child_results,
        parent_usage_record=parent_usage,
        child_usage_records=child_usages,
        parent_context=parent_context,
        child_contexts=child_contexts,
        requests=requests,
    )
    assert structural_artifact.surface_set_structurally_closed
    assert structural_artifact.records == records
    assert [origin.origin_kind for origin in structural_artifact.origins].count(
        TruncationSurfaceOriginKind.PARENT_PROVISIONAL
    ) == 1
    with pytest.raises(ValueError, match="live closure custody"):
        journal.promote_truncation_recovery_family(
            family.family_id,
            object.__new__(VerifiedTruncationRecoveryClosure),
        )
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(capability)

    unpromoted_recovery_files = {
        item.name: item.read_bytes() for item in (path / "truncation-recovery").glob("*.json")
    }
    unpromoted_entries = journal.truncation_recovery_entries
    unpromoted_checkpoint = (path / "journal-head-checkpoint.json").read_bytes()
    with pytest.raises(ValueError, match="live or promotable recovery work"):
        journal.seal_pass_result(SchedulerPassKind.BLIND_SHARD_REVIEW)
    assert journal.truncation_recovery_entries == unpromoted_entries
    assert {
        item.name: item.read_bytes() for item in (path / "truncation-recovery").glob("*.json")
    } == unpromoted_recovery_files
    assert (path / "journal-head-checkpoint.json").read_bytes() == unpromoted_checkpoint

    promotion = journal.promote_truncation_recovery_family(family.family_id, capability)
    assert promotion.entry_kind is SchedulerTruncationRecoveryEntryKind.FAMILY_PROMOTED
    assert promotion.original_truncated_result_sha256 == original_result.result_sha256
    assert promotion.recovered_output.recovered_batch.surface_reviews == records
    surface_coverage = journal.issue_promoted_truncation_recovery_surface_coverage(
        family.family_id,
        capability,
    )
    assert type(surface_coverage) is VerifiedPromotedTruncationRecoverySurfaceCoverage
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(surface_coverage)
    fresh_surface_projection = require_verified_promoted_truncation_recovery_surface_coverage(
        surface_coverage
    )
    replayed_surface_projection = require_verified_promoted_truncation_recovery_surface_coverage(
        surface_coverage
    )
    assert replayed_surface_projection == fresh_surface_projection
    assert replayed_surface_projection is not fresh_surface_projection
    assert replayed_surface_projection.artifact is not fresh_surface_projection.artifact
    assert fresh_surface_projection.promotion_entry_sha256 == promotion.entry_sha256
    assert fresh_surface_projection.recovered_output_artifact_sha256 == (
        promotion.recovered_output.output_artifact_sha256
    )
    assert fresh_surface_projection.artifact.records == records
    blind_result = journal.seal_pass_result(SchedulerPassKind.BLIND_SHARD_REVIEW)
    assert blind_result.status is SchedulerPassStatus.COMPLETE
    assert blind_result.task_results == (original_result,)
    assert blind_result.task_results[0].terminal_status is SchedulerTerminalStatus.TRUNCATED
    assert all(output.task_id != blind_task.task_id for output in journal.outputs)
    assert len(blind_result.recovery_promotion_bindings) == 1
    public_binding = blind_result.recovery_promotion_bindings[0]
    assert public_binding.parent_task_id == blind_task.task_id
    assert public_binding.original_truncated_result_sha256 == original_result.result_sha256
    assert public_binding.promotion_entry_sha256 == promotion.entry_sha256
    assert (
        public_binding.recovered_output_artifact_sha256
        == promotion.recovered_output.output_artifact_sha256
    )
    promoted_requests = journal.recovery_model_requests
    assert len(promoted_requests) == 2
    assert {item.promotion_entry_sha256 for item in promoted_requests} == {promotion.entry_sha256}
    assert {item.child_result_entry_sha256 for item in promoted_requests} == set(
        public_binding.direct_child_result_sha256s
    )
    assert journal.artifact().recovery_model_requests == promoted_requests
    recovery_public_json = journal.artifact().model_dump_json()
    assert "runtime_usage_record" not in recovery_public_json
    assert "runtime_normalized_batch" not in recovery_public_json
    assert 'context_request_evidence"' not in recovery_public_json
    assert {
        item.request_id for item in journal.structurally_successful_review_usage_records
    }.issuperset(item.request_id for item in child_usages)
    assert {item.request_id for item in journal.restorable_review_usage_records}.issuperset(
        item.request_id for item in child_usages
    )
    public_json = json.dumps(blind_result.model_dump(mode="json"), sort_keys=True)
    assert "recovered_batch" not in public_json
    assert "scanner_fingerprints_by_request" not in public_json

    durable_paths = tuple(
        sorted(
            (
                *(path / "truncation-recovery").glob("*.json"),
                *(path / "pass-results").glob("*.json"),
            )
        )
    )
    durable_bytes = {item.relative_to(path): item.read_bytes() for item in durable_paths}
    evidence = journal.journal_evidence
    planner.close()
    monkeypatch.setattr(
        scheduler_module,
        "_validate_live_scheduler_model_refresh",
        lambda **_values: (True, True),
    )
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=bindings,
        expected_shard_inventory=inventory,
        expected_journal_evidence=evidence,
    )
    assert {item.relative_to(path): item.read_bytes() for item in durable_paths} == durable_bytes
    assert resumed.pass_results[-1] == blind_result
    assert resumed.artifact().recovery_model_requests == promoted_requests
    assert (
        resumed.pass_results[-1].recovery_promotion_bindings
        == blind_result.recovery_promotion_bindings
    )
    recovered_usage_by_request_id = {
        item.request_id: item for item in resumed.claim_restorable_usage_records()
    }
    resumed_families = resumed.truncation_recovery_families
    assert len(resumed_families) == 1
    resumed_family = resumed_families[0]
    resumed_entries = resumed.truncation_recovery_entries
    resumed_closures = tuple(
        item
        for item in resumed_entries
        if isinstance(item, SchedulerTruncationRecoveryFamilyClosure)
        and item.family_id == resumed_family.family_id
    )
    assert len(resumed_closures) == 1
    resumed_closure = resumed_closures[0]
    resumed_child_results = tuple(
        next(
            item
            for item in resumed_entries
            if isinstance(item, SchedulerTruncationRecoveryChildResult)
            and item.child_task_id == child.child_task_id
        )
        for child in resumed_family.recovery_plan.children
    )
    resumed_child_contexts = tuple(
        build_truncation_recovery_child_context(
            parent_context=parent_context,
            child=child,
        )
        for child in resumed_family.recovery_plan.children
    )
    resumed_closure_capability, resumed_structural_artifact = verify_truncation_recovery_closure(
        family=resumed_family,
        closure=resumed_closure,
        child_results=resumed_child_results,
        parent_usage_record=recovered_usage_by_request_id[blind_task.logical_request_id],
        child_usage_records=tuple(
            recovered_usage_by_request_id[child.child_logical_request_id]
            for child in resumed_family.recovery_plan.children
        ),
        parent_context=parent_context,
        child_contexts=resumed_child_contexts,
        requests=requests,
    )
    assert resumed_structural_artifact == structural_artifact
    resumed_surface_coverage = resumed.issue_promoted_truncation_recovery_surface_coverage(
        resumed_family.family_id,
        resumed_closure_capability,
    )
    assert type(resumed_surface_coverage) is VerifiedPromotedTruncationRecoverySurfaceCoverage
    resumed_surface_projection = require_verified_promoted_truncation_recovery_surface_coverage(
        resumed_surface_coverage
    )
    assert resumed_surface_projection == fresh_surface_projection

    later_plan = resumed.seal_pass_plan(_plan(resumed, SchedulerPassKind.FINDING_REDUCTION))
    later_task = later_plan.tasks[0]
    later_activation = resumed.activate_task(
        later_task.task_id,
        actual_input_sha256=scheduler_test_host_activation_input_sha256(
            later_plan,
            later_task,
        ),
    )
    assert later_activation.task_id == later_task.task_id
    assert resumed.truncation_recovery_entries[-1] == promotion
    assert resumed.pass_results[-1].status is SchedulerPassStatus.COMPLETE
    # Terminal authority freezes every append, but downstream coverage/report
    # construction must still be able to replay the already-issued live token.
    monkeypatch.setattr(resumed, "_terminal_report_authority", object())
    assert (
        require_verified_promoted_truncation_recovery_surface_coverage(resumed_surface_coverage)
        == fresh_surface_projection
    )
    with pytest.raises(ValueError, match="frozen by its terminal report authority"):
        resumed.open_truncation_recovery_family(
            recovery_plan=resumed_family.recovery_plan,
            truncation_projection=projection,
            requested_surface_manifest=surface_manifest,
        )
    resumed.close()


def test_live_recursive_tree_promotes_only_three_leaves_and_replays_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "promoted-recursive-recovery"
    bindings = _one_shard_bindings()
    inventory = _inventory(one_shard=True)
    journal = create_scheduler_journal(
        path,
        bindings=bindings,
        shard_inventory=inventory,
        privacy_evidence_custody=_privacy_custody(source_sha256=inventory.source_tree_sha256),
    )
    _complete_real_orientation(journal)

    requests: tuple[ModelSurfaceReviewRequest, ...] = _requests()
    records: tuple[ModelSurfaceReviewRecord, ...] = tuple(_record(item) for item in requests)
    parent_context = _context(requests)
    projection = _projection(records, retained_count=1)
    assert projection.findings_state.value == "COMPLETE"
    surface_manifest = SchedulerTruncationRecoveryRequestedSurfaceManifest.build(requests)

    planner = PipelineScheduler(journal)
    audit_selection = journal.manifest.bindings.audit_model_selection
    assert audit_selection is not None
    model_id = audit_selection.selected_model_ids[0]
    blind_task = planner.model_task(
        pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
        scope=SchedulerScope.single_shard(SHARDS[0]),
        task_key="recursive-promotion-source-audit",
        role="source_audit",
        requested_model=model_id,
        root_lineage=audit_selection.route_for(model_id).root_lineage,
        system_prompt_sha256="a" * 64,
        response_schema_sha256=candidate_review_frame_wire_schema_sha256(),
    )
    blind_plan = planner.prepare_pass(SchedulerPassKind.BLIND_SHARD_REVIEW, (blind_task,))
    parent_activation = journal.activate_task(
        blind_task.task_id,
        actual_input_sha256=blind_task.input_sha256,
        system_prompt_sha256=blind_task.system_prompt_sha256,
        user_prompt_sha256=hashlib.sha256(render_context(parent_context).encode()).hexdigest(),
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=blind_task.response_schema_sha256,
        delivered_source_descriptor_sha256s=(
            scheduler_test_delivered_source_descriptor_sha256s(blind_plan, blind_task)
        ),
    )
    journal.mark_dispatched(blind_task.task_id)
    envelope, parent_usage = _typed_parent_truncation(
        journal=journal,
        task=blind_task,
        activation=parent_activation,
        context=parent_context,
        projection=projection,
        full_batch=CandidateReviewBatch(findings=(), surface_reviews=records),
    )
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
    root_plan = _recovery_plan(
        journal=journal,
        pass_plan=blind_plan,
        task=blind_task,
        activation=parent_activation,
        attempt=parent_attempt,
        projection=projection,
        manifest=surface_manifest,
        parent_usage=parent_usage,
    )
    root_family = journal.open_truncation_recovery_family(
        recovery_plan=root_plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    bridge_child = max(root_plan.children, key=lambda child: len(child.surface_ids))
    direct_leaf_child = next(child for child in root_plan.children if child != bridge_child)
    assert len(bridge_child.surface_ids) == 2

    root_results_by_child: dict[str, SchedulerTruncationRecoveryChildResult] = {}
    root_contexts_by_child: dict[str, ContextPackage] = {}
    leaf_usages_by_child: dict[str, UsageRecord] = {}
    bridge_usage: UsageRecord | None = None
    bridge_projection: CandidateReviewTruncationProjection | None = None
    bridge_activation = None
    for child in root_plan.children:
        child_context = build_truncation_recovery_child_context(
            parent_context=parent_context,
            child=child,
        )
        root_contexts_by_child[child.child_task_id] = child_context
        activation = journal.activate_truncation_recovery_child(
            child.child_task_id,
            actual_input_sha256=_digest(f"input:{child.child_task_id}"),
            system_prompt_sha256=_digest(f"system:{child.child_task_id}"),
            user_prompt_sha256=hashlib.sha256(render_context(child_context).encode()).hexdigest(),
            provider_prompt_sha256=_digest(f"provider:{child.child_task_id}"),
            response_schema_sha256=candidate_review_frame_wire_schema_sha256(),
        )
        journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
        if child == bridge_child:
            failed_usage, child_envelope, child_projection = _truncated_custody(
                child=child,
                activation=activation,
                surfaces=records,
            )
            failed_usage = _bind_bridge_to_parent_invariant(
                failed_usage.model_copy(update={"execution_evidence": ExecutionEvidenceKind.REAL}),
                journal=journal,
                parent_usage=parent_usage,
            )
            bridge_usage = failed_usage
            bridge_projection = child_projection
            bridge_activation = activation
            root_results_by_child[child.child_task_id] = (
                journal.record_truncation_recovery_child_truncated(
                    child.child_task_id,
                    failed_usage_record=failed_usage,
                    truncated_envelope_evidence=child_envelope,
                    truncation_projection=child_projection,
                )
            )
        else:
            usage, normalization, batch, child_requests, artifact = _success_custody(
                child=child,
                activation=activation,
                surface_manifest=surface_manifest,
                surfaces=records,
                execution_evidence=ExecutionEvidenceKind.REAL,
            )
            usage = _bind_child_to_parent_invariant(
                usage,
                journal=journal,
                parent_usage=parent_usage,
            )
            leaf_usages_by_child[child.child_task_id] = usage
            root_results_by_child[child.child_task_id] = (
                journal.record_truncation_recovery_child_success(
                    child.child_task_id,
                    usage_record=usage,
                    normalization_evidence=normalization,
                    normalized_batch=batch,
                    requested_surface_requests=child_requests,
                    output_artifact=artifact,
                )
            )
    assert bridge_usage is not None
    assert bridge_projection is not None
    assert bridge_activation is not None
    bridge_result = root_results_by_child[bridge_child.child_task_id]
    direct_leaf_result = root_results_by_child[direct_leaf_child.child_task_id]
    nested_plan = _nested_plan_for_typed_truncated_child(
        root=root_family,
        root_plan=root_plan,
        child=bridge_child,
        activation=bridge_activation,
        result=bridge_result,
        projection=bridge_projection,
        other_direct_results=(direct_leaf_result,),
    )
    nested_family = journal.open_truncation_recovery_family(
        recovery_plan=nested_plan,
        truncation_projection=bridge_projection,
        requested_surface_manifest=surface_manifest,
    )
    bridge_context = root_contexts_by_child[bridge_child.child_task_id]
    nested_results: list[SchedulerTruncationRecoveryChildResult] = []
    nested_contexts: list[ContextPackage] = []
    for child in nested_plan.children:
        child_context = build_truncation_recovery_child_context(
            parent_context=bridge_context,
            child=child,
        )
        nested_contexts.append(child_context)
        activation = journal.activate_truncation_recovery_child(
            child.child_task_id,
            actual_input_sha256=_digest(f"input:{child.child_task_id}"),
            system_prompt_sha256=_digest(f"system:{child.child_task_id}"),
            user_prompt_sha256=hashlib.sha256(render_context(child_context).encode()).hexdigest(),
            provider_prompt_sha256=_digest(f"provider:{child.child_task_id}"),
            response_schema_sha256=candidate_review_frame_wire_schema_sha256(),
        )
        journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
        usage, normalization, batch, child_requests, artifact = _success_custody(
            child=child,
            activation=activation,
            surface_manifest=surface_manifest,
            surfaces=records,
            execution_evidence=ExecutionEvidenceKind.REAL,
        )
        usage = _bind_child_to_parent_invariant(
            usage,
            journal=journal,
            parent_usage=parent_usage,
        )
        leaf_usages_by_child[child.child_task_id] = usage
        nested_results.append(
            journal.record_truncation_recovery_child_success(
                child.child_task_id,
                usage_record=usage,
                normalization_evidence=normalization,
                normalized_batch=batch,
                requested_surface_requests=child_requests,
                output_artifact=artifact,
            )
        )

    nested_closure = journal.seal_truncation_recovery_family(nested_family.family_id)
    root_closure = journal.seal_truncation_recovery_family(root_family.family_id)
    assert nested_closure.closure_status is SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
    assert (
        root_closure.closure_status
        is SchedulerTruncationRecoveryClosureStatus.RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING
    )
    root_results = tuple(root_results_by_child[child.child_task_id] for child in root_plan.children)
    leaf_usages = (
        leaf_usages_by_child[direct_leaf_child.child_task_id],
        *(leaf_usages_by_child[child.child_task_id] for child in nested_plan.children),
    )
    leaf_contexts = (
        root_contexts_by_child[direct_leaf_child.child_task_id],
        *nested_contexts,
    )
    capability, structural_artifact = verify_recursive_truncation_recovery_tree(
        root_family=root_family,
        nested_family=nested_family,
        root_closure=root_closure,
        nested_closure=nested_closure,
        root_child_results=root_results,
        nested_child_results=nested_results,
        parent_usage_record=parent_usage,
        bridge_usage_record=bridge_usage,
        leaf_usage_records=leaf_usages,
        parent_context=parent_context,
        bridge_context=bridge_context,
        leaf_contexts=leaf_contexts,
        requests=requests,
    )
    assert structural_artifact.records == records
    with pytest.raises(ValueError, match="live closure custody"):
        journal.promote_truncation_recovery_family(
            root_family.family_id,
            object.__new__(VerifiedRecursiveTruncationRecoveryTree),
        )
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(capability)

    promotion = journal.promote_truncation_recovery_family(
        root_family.family_id,
        capability,
    )
    assert promotion.schema_version == "1.1"
    assert promotion.recovered_output.schema_version == "1.1"
    assert promotion.superseded_bridge_result_sha256 == bridge_result.entry_sha256
    assert promotion.promoted_leaf_result_sha256s == (
        direct_leaf_result.entry_sha256,
        *(result.entry_sha256 for result in nested_results),
    )
    surface_coverage = journal.issue_promoted_recursive_truncation_recovery_surface_coverage(
        root_family.family_id,
        capability,
    )
    assert type(surface_coverage) is VerifiedPromotedRecursiveTruncationRecoverySurfaceCoverage
    fresh_projection = require_verified_promoted_recursive_truncation_recovery_surface_coverage(
        surface_coverage
    )
    assert fresh_projection.artifact == structural_artifact
    assert fresh_projection.bridge_usage_record is bridge_usage
    assert fresh_projection.leaf_usage_records == leaf_usages

    public_requests = journal.recovery_model_requests
    assert len(public_requests) == 4
    assert {request.promotion_entry_sha256 for request in public_requests} == {
        promotion.entry_sha256
    }
    bridge_requests = tuple(
        request
        for request in public_requests
        if request.promotion_disposition
        is SchedulerTruncationRecoveryPromotionDisposition.SUPERSEDED_TRUNCATED_BRIDGE
    )
    leaf_requests = tuple(
        request
        for request in public_requests
        if request.promotion_disposition
        is SchedulerTruncationRecoveryPromotionDisposition.SUCCESSFUL_LEAF
    )
    assert len(bridge_requests) == 1
    assert bridge_requests[0].child_result_entry_sha256 == bridge_result.entry_sha256
    assert len(leaf_requests) == 3
    assert tuple(sorted(request.global_request_ordinal for request in public_requests)) == (
        1,
        2,
        3,
        4,
    )
    successful_recovery_ids = {
        record.request_id for record in journal.structurally_successful_review_usage_records
    }
    assert {usage.request_id for usage in leaf_usages} <= successful_recovery_ids
    assert bridge_usage.request_id not in successful_recovery_ids

    blind_result = journal.seal_pass_result(SchedulerPassKind.BLIND_SHARD_REVIEW)
    assert blind_result.status is SchedulerPassStatus.COMPLETE
    assert len(blind_result.recovery_promotion_bindings) == 1
    assert blind_result.recovery_promotion_bindings[0].promotion_entry_sha256 == (
        promotion.entry_sha256
    )
    evidence = journal.journal_evidence
    durable_entries = journal.truncation_recovery_entries
    planner.close()
    monkeypatch.setattr(
        scheduler_module,
        "_validate_live_scheduler_model_refresh",
        lambda **_values: (True, True),
    )
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=bindings,
        expected_shard_inventory=inventory,
        expected_journal_evidence=evidence,
    )
    assert resumed.truncation_recovery_entries == durable_entries
    recovered_usage = {item.request_id: item for item in resumed.claim_restorable_usage_records()}
    resumed_families = resumed.truncation_recovery_families
    resumed_root = next(item for item in resumed_families if item.parent_family_id is None)
    resumed_nested = next(item for item in resumed_families if item.parent_family_id is not None)
    resumed_closures = {
        item.family_id: item
        for item in resumed.truncation_recovery_entries
        if isinstance(item, SchedulerTruncationRecoveryFamilyClosure)
    }
    resumed_results = {
        item.child_task_id: item
        for item in resumed.truncation_recovery_entries
        if isinstance(item, SchedulerTruncationRecoveryChildResult)
    }
    resumed_root_results = tuple(
        resumed_results[child.child_task_id] for child in resumed_root.recovery_plan.children
    )
    resumed_nested_results = tuple(
        resumed_results[child.child_task_id] for child in resumed_nested.recovery_plan.children
    )
    resumed_root_contexts = tuple(
        build_truncation_recovery_child_context(parent_context=parent_context, child=child)
        for child in resumed_root.recovery_plan.children
    )
    resumed_bridge_index = next(
        index
        for index, result in enumerate(resumed_root_results)
        if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED
    )
    resumed_direct_index = 1 - resumed_bridge_index
    resumed_bridge_context = resumed_root_contexts[resumed_bridge_index]
    resumed_nested_contexts = tuple(
        build_truncation_recovery_child_context(
            parent_context=resumed_bridge_context,
            child=child,
        )
        for child in resumed_nested.recovery_plan.children
    )
    resumed_tree_capability, resumed_artifact = verify_recursive_truncation_recovery_tree(
        root_family=resumed_root,
        nested_family=resumed_nested,
        root_closure=resumed_closures[resumed_root.family_id],
        nested_closure=resumed_closures[resumed_nested.family_id],
        root_child_results=resumed_root_results,
        nested_child_results=resumed_nested_results,
        parent_usage_record=recovered_usage[parent_usage.request_id],
        bridge_usage_record=recovered_usage[bridge_usage.request_id],
        leaf_usage_records=(
            recovered_usage[resumed_root_results[resumed_direct_index].child_logical_request_id],
            *(
                recovered_usage[result.child_logical_request_id]
                for result in resumed_nested_results
            ),
        ),
        parent_context=parent_context,
        bridge_context=resumed_bridge_context,
        leaf_contexts=(
            resumed_root_contexts[resumed_direct_index],
            *resumed_nested_contexts,
        ),
        requests=requests,
    )
    assert resumed_artifact == structural_artifact
    resumed_surface_coverage = (
        resumed.issue_promoted_recursive_truncation_recovery_surface_coverage(
            resumed_root.family_id,
            resumed_tree_capability,
        )
    )
    assert (
        require_verified_promoted_recursive_truncation_recovery_surface_coverage(
            resumed_surface_coverage
        )
        == fresh_projection
    )
    resumed.close()
