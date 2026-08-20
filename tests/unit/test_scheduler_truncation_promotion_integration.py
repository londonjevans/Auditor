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
from mmaudit.models.truncation_closure import _INVARIANT_ROUTING_KEYS
from mmaudit.models.truncation_recovery import (
    TruncationRecoveryParentBinding,
    plan_truncation_recovery,
)
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryClosureStatus,
    SchedulerTruncationRecoveryEntryKind,
    SchedulerTruncationRecoveryRequestedSurfaceManifest,
    rebuild_truncation_recovery_parent_from_projection,
)
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.scheduler_runtime import PipelineScheduler
from mmaudit.orchestration.truncation_recovery_evidence import (
    VerifiedTruncationRecoveryClosure,
    build_truncation_recovery_child_context,
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
    _placeholder_channels,
    _projection,
    _resources,
    _success_custody,
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
    projection = _projection(records, retained_count=0)
    assert projection.findings_state.value == "COMPLETE"
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
    resumed.close()
