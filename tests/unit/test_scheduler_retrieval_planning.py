from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from mmaudit.models.openrouter import DeliveredSourceDescriptor, ModelRequestPrivacyBinding
from mmaudit.models.retrieval import (
    SolidityRetrievalEntity,
    SolidityRetrievalEntityKind,
    SolidityRetrievalExchange,
    SolidityRetrievalIntent,
    SolidityRetrievalOmission,
    SolidityRetrievalOperation,
    SolidityRetrievalReason,
    SolidityRetrievalRecord,
    SolidityRetrievalRequest,
    SolidityRetrievalRequestBatch,
    SolidityRetrievalResult,
    SolidityRetrievalRoleBudgetPlan,
    SolidityRetrievalRolePolicy,
    SolidityRetrievalStatus,
    SolidityRetrievalTranscript,
)
from mmaudit.models.scheduler import (
    SchedulerActivationStatus,
    SchedulerArtifact,
    SchedulerBindings,
    SchedulerCampaignManifest,
    SchedulerModelRequestEvidence,
    SchedulerPassKind,
    SchedulerPassPlan,
    SchedulerPassResult,
    SchedulerPassStatus,
    SchedulerReportBinding,
    SchedulerRetrievalBinding,
    SchedulerTaskActivation,
    SchedulerTaskKind,
    SchedulerTaskOutput,
    SchedulerTaskPlan,
    SchedulerTaskPurpose,
    SchedulerTaskResult,
    SchedulerTerminalStatus,
    scheduler_auxiliary_response_schema_hashes_for_algorithm,
    scheduler_auxiliary_response_schema_inventory_for_algorithm,
    scheduler_auxiliary_response_schema_set_sha256_for_algorithm,
    scheduler_canonical_sha256,
    scheduler_response_schema_inventory_for_algorithm,
    scheduler_response_schema_set_sha256_for_algorithm,
    scheduler_response_schema_sha256,
)
from mmaudit.models.schemas import ContextRequestEvidence, ExecutionEvidenceKind, UsageRecord
from mmaudit.models.usage import is_creditable_usage_record
from mmaudit.orchestration.scheduler import (
    SchedulerJournal,
    create_scheduler_journal,
    resume_scheduler_journal,
)
from mmaudit.orchestration.scheduler_runtime import PipelineScheduler
from tests.scheduler_support import (
    build_complete_scheduler_fixture,
    build_scheduler_test_model_payload,
    build_scheduler_test_model_surface_review_custody,
    build_scheduler_test_real_usage,
    build_scheduler_test_usage,
    scheduler_test_analysis_input_inventory,
    scheduler_test_delivered_source_descriptor_sha256s,
    scheduler_test_model_surface_review_requests,
)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _legacy_manifest(manifest: SchedulerCampaignManifest) -> SchedulerCampaignManifest:
    bindings_body = manifest.bindings.model_dump(mode="json", exclude={"bindings_sha256"})
    bindings_body["algorithm_version"] = "mmaudit.seven-pass-scheduler.v1"
    bindings = SchedulerBindings.model_validate(
        {
            **bindings_body,
            "bindings_sha256": scheduler_canonical_sha256(bindings_body),
        }
    )
    manifest_body = manifest.model_dump(
        mode="json",
        exclude={"campaign_id", "manifest_sha256"},
    )
    manifest_body["algorithm_version"] = "mmaudit.seven-pass-scheduler.v1"
    manifest_body["bindings"] = bindings.model_dump(mode="json")
    campaign_id = "scheduler-campaign-" + scheduler_canonical_sha256(manifest_body)
    bound_body = {**manifest_body, "campaign_id": campaign_id}
    return SchedulerCampaignManifest.model_validate(
        {
            **bound_body,
            "manifest_sha256": scheduler_canonical_sha256(bound_body),
        }
    )


def _retrieval_plan(
    seed: str,
    *,
    manifest: SchedulerCampaignManifest | None = None,
) -> tuple[SchedulerPassPlan, SchedulerTaskPlan, SchedulerTaskPlan]:
    fixture = build_complete_scheduler_fixture(seed=seed, manifest=manifest)
    original = next(
        plan for plan in fixture.plans if plan.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
    )
    parent = next(task for task in original.tasks if task.role == "source_audit")
    child = SchedulerTaskPlan.build(
        manifest=original.manifest,
        pass_kind=original.pass_kind,
        scope=parent.scope,
        task_kind=SchedulerTaskKind.MODEL_REQUEST,
        purpose=SchedulerTaskPurpose.RETRIEVAL_PLANNING,
        parent_task_id=parent.task_id,
        task_key="retrieval-planning",
        role=parent.role,
        requested_model=parent.requested_model,
        root_lineage=parent.root_lineage,
        candidate_ids=parent.candidate_ids,
        model_surface_review_request_manifest_sha256=(
            parent.model_surface_review_request_manifest_sha256
        ),
        input_sha256=_sha256(f"{seed}:retrieval-input"),
        prompt_sha256=_sha256(f"{seed}:retrieval-prompt"),
        system_prompt_sha256=_sha256(f"{seed}:retrieval-system"),
        response_schema_sha256=scheduler_response_schema_sha256(SolidityRetrievalRequestBatch),
    )
    plan = SchedulerPassPlan.build(
        manifest=original.manifest,
        pass_kind=original.pass_kind,
        dependencies=original.dependencies,
        tasks=(*original.tasks, child),
    )
    return plan, parent, child


def _activation(
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
    *,
    seed: str,
    retrieval_result: SchedulerTaskResult | None = None,
) -> SchedulerTaskActivation:
    return SchedulerTaskActivation.build(
        plan=plan,
        task=task,
        actual_input_sha256=_sha256(f"{seed}:actual-input"),
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256=_sha256(f"{seed}:user-prompt"),
        provider_prompt_sha256=_sha256(f"{seed}:provider-prompt"),
        response_schema_sha256=task.response_schema_sha256,
        delivered_source_descriptor_sha256s=(
            scheduler_test_delivered_source_descriptor_sha256s(plan, task)
        ),
        retrieval_planning_result=retrieval_result,
    )


def _usage_with_retrieval_planning_context(
    usage: UsageRecord,
    *,
    policy: SolidityRetrievalRolePolicy,
    corpus_sha256: str,
) -> UsageRecord:
    original = ContextRequestEvidence.model_validate(usage.routing["context_request_evidence"])
    context = ContextRequestEvidence.build(
        request_id=original.request_id,
        request_role=original.request_role,
        context_role=original.context_role,
        byte_budget=original.byte_budget,
        declared_bytes_used=original.declared_bytes_used,
        rendered_bytes=original.rendered_bytes,
        source_bytes=original.source_bytes,
        configured_maximum_source_tokens_per_request=(
            original.configured_maximum_source_tokens_per_request
        ),
        effective_source_byte_ceiling=original.effective_source_byte_ceiling,
        rendered_sha256=original.rendered_sha256,
        requested_surface_manifest_sha256=original.requested_surface_manifest_sha256,
        source_location_proof_sha256s=original.source_location_proof_sha256s,
        retrieval_policy=policy,
        retrieval_corpus_sha256=corpus_sha256,
    )
    routing = {
        **usage.routing,
        "context_request_evidence": context.model_dump(mode="json"),
        "context_request_evidence_sha256": context.evidence_sha256,
    }
    return UsageRecord.model_validate({**usage.model_dump(mode="python"), "routing": routing})


def _successful_planner(
    plan: SchedulerPassPlan,
    child: SchedulerTaskPlan,
    *,
    seed: str,
    corpus_sha256: str,
    intent: SolidityRetrievalIntent | None = None,
    bind_retrieval_context: bool = True,
    planning_policy: SolidityRetrievalRolePolicy | None = None,
) -> tuple[
    SchedulerTaskActivation,
    SchedulerTaskOutput,
    SchedulerTaskResult,
    SolidityRetrievalIntent,
]:
    activation = _activation(plan, child, seed=seed)
    selected_intent = intent or SolidityRetrievalIntent(
        operation=SolidityRetrievalOperation.RESOLVE_ENTITY,
        subject_id="entity:synthetic",
    )
    batch = SolidityRetrievalRequestBatch(requests=(selected_intent,))
    usage = build_scheduler_test_usage(
        child,
        activation,
        seed=seed,
        validated_output=batch,
        privacy_evidence_custody=plan.manifest.privacy_evidence_custody,
    )
    if bind_retrieval_context:
        assert child.parent_task_id is not None
        allocation = plan.retrieval_role_budget_allocation_for_task(child.parent_task_id)
        usage = _usage_with_retrieval_planning_context(
            usage,
            policy=planning_policy or allocation.policy,
            corpus_sha256=corpus_sha256,
        )
    output = SchedulerTaskOutput.build(
        plan=plan,
        task=child,
        activation=activation,
        payload=batch,
        usage_record=usage,
    )
    assert usage.validated_response_sha256 is not None
    result = SchedulerTaskResult.build(
        plan=plan,
        task=child,
        activation=activation,
        terminal_status=SchedulerTerminalStatus.SUCCEEDED,
        terminal_evidence_sha256=usage.validated_response_sha256,
        output=output,
    )
    return activation, output, result, selected_intent


def _transcript(
    *,
    role: str,
    intent: SolidityRetrievalIntent,
    seed: str,
) -> tuple[SolidityRetrievalRolePolicy, SolidityRetrievalTranscript]:
    policy = SolidityRetrievalRolePolicy.build(role=role)
    request = SolidityRetrievalRequest.from_intent(intent)
    result = SolidityRetrievalResult.build(
        request=request,
        status=SolidityRetrievalStatus.REFUSED,
        omissions=(
            SolidityRetrievalOmission(
                reason=SolidityRetrievalReason.UNINDEXED_SUBJECT,
                count=1,
            ),
        ),
    )
    exchange = SolidityRetrievalExchange.build(
        sequence=1,
        previous_exchange_sha256=None,
        request=request,
        result=result,
    )
    transcript = SolidityRetrievalTranscript.build(
        role=role,
        policy_sha256=policy.policy_sha256,
        corpus_sha256=_sha256(f"{seed}:corpus"),
        exchanges=(exchange,),
        accepted_request_count=1,
    )
    return policy, transcript


def _usage_with_retrieval_context(
    usage: UsageRecord,
    *,
    policy: SolidityRetrievalRolePolicy,
    transcript: SolidityRetrievalTranscript,
) -> UsageRecord:
    original = ContextRequestEvidence.model_validate(usage.routing["context_request_evidence"])
    context = ContextRequestEvidence.build(
        request_id=original.request_id,
        request_role=original.request_role,
        context_role=original.context_role,
        byte_budget=original.byte_budget,
        declared_bytes_used=original.declared_bytes_used,
        rendered_bytes=original.rendered_bytes,
        source_bytes=original.source_bytes,
        configured_maximum_source_tokens_per_request=(
            original.configured_maximum_source_tokens_per_request
        ),
        effective_source_byte_ceiling=original.effective_source_byte_ceiling,
        rendered_sha256=original.rendered_sha256,
        requested_surface_manifest_sha256=original.requested_surface_manifest_sha256,
        source_location_proof_sha256s=original.source_location_proof_sha256s,
        retrieval_policy=policy,
        retrieval_corpus_sha256=transcript.corpus_sha256,
        retrieval_transcript=transcript,
    )
    routing = {
        **usage.routing,
        "context_request_evidence": context.model_dump(mode="json"),
        "context_request_evidence_sha256": context.evidence_sha256,
    }
    return UsageRecord.model_validate({**usage.model_dump(mode="python"), "routing": routing})


def _successful_primary(
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
    activation: SchedulerTaskActivation,
    *,
    seed: str,
    retrieval_binding: SchedulerRetrievalBinding | None = None,
    retrieval_policy: SolidityRetrievalRolePolicy | None = None,
    retrieval_transcript: SolidityRetrievalTranscript | None = None,
    project_retrieval_context: bool | None = None,
) -> tuple[SchedulerTaskOutput, SchedulerTaskResult]:
    payload = build_scheduler_test_model_payload(plan, task)
    requests = scheduler_test_model_surface_review_requests(plan, task)
    usage = build_scheduler_test_usage(
        task,
        activation,
        seed=seed,
        validated_output=payload,
        privacy_evidence_custody=plan.manifest.privacy_evidence_custody,
        model_surface_review_requests=requests,
    )
    project_context = (
        retrieval_binding is not None
        and not retrieval_binding.transcript.single_shot_fallback_required
        if project_retrieval_context is None
        else project_retrieval_context
    )
    if project_context:
        assert retrieval_policy is not None and retrieval_transcript is not None
        usage = _usage_with_retrieval_context(
            usage,
            policy=retrieval_policy,
            transcript=retrieval_transcript,
        )
    requests, artifact = build_scheduler_test_model_surface_review_custody(
        plan,
        task,
        activation,
        usage,
        payload,
    )
    output = SchedulerTaskOutput.build(
        plan=plan,
        task=task,
        activation=activation,
        payload=payload,
        usage_record=usage,
        model_surface_review_requests=requests,
        model_surface_review_artifact=artifact,
        retrieval_binding=retrieval_binding,
    )
    assert usage.validated_response_sha256 is not None
    result = SchedulerTaskResult.build(
        plan=plan,
        task=task,
        activation=activation,
        terminal_status=SchedulerTerminalStatus.SUCCEEDED,
        terminal_evidence_sha256=usage.validated_response_sha256,
        output=output,
    )
    return output, result


def _other_primary_results(
    plan: SchedulerPassPlan,
    parent: SchedulerTaskPlan,
    *,
    seed: str,
) -> tuple[SchedulerTaskResult, ...]:
    results: list[SchedulerTaskResult] = []
    for index, task in enumerate(
        task
        for task in plan.tasks
        if task.purpose is SchedulerTaskPurpose.PRIMARY and task.task_id != parent.task_id
    ):
        activation = _activation(plan, task, seed=f"{seed}:{index}")
        _output, result = _successful_primary(
            plan,
            task,
            activation,
            seed=f"{seed}:{index}",
        )
        results.append(result)
    return tuple(results)


def _privacy_binding(plan: SchedulerPassPlan) -> ModelRequestPrivacyBinding:
    custody = plan.manifest.privacy_evidence_custody
    assert custody is not None
    return ModelRequestPrivacyBinding(
        source_sha256=custody.source_sha256,
        effective_policy_sha256=custody.effective_policy_evidence_sha256,
        source_provenance_sha256=custody.source_provenance_evidence_sha256,
    )


def _delivered_sources(
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
) -> tuple[DeliveredSourceDescriptor, ...]:
    required = set(scheduler_test_delivered_source_descriptor_sha256s(plan, task))
    return tuple(
        sorted(
            (
                DeliveredSourceDescriptor(path=source.path, sha256=source.sha256, size=source.size)
                for shard in plan.manifest.shard_inventory.shards
                for source in shard.sources
                if source.source_descriptor_sha256 in required
            ),
            key=lambda item: item.path,
        )
    )


def _replay_fixture_orientation(
    runtime: PipelineScheduler,
    *,
    seed: str,
    manifest: SchedulerCampaignManifest,
) -> PipelineScheduler:
    fixture = build_complete_scheduler_fixture(seed=seed, manifest=manifest)
    plan = fixture.plans[0]
    runtime.journal.seal_pass_plan(plan)
    for task in plan.tasks:
        activation = next(item for item in fixture.activations if item.task_id == task.task_id)
        persisted_activation = runtime.journal.activate_task(
            task.task_id,
            actual_input_sha256=activation.actual_input_sha256,
            system_prompt_sha256=activation.system_prompt_sha256,
            user_prompt_sha256=activation.user_prompt_sha256,
            provider_prompt_sha256=activation.provider_prompt_sha256,
            response_schema_sha256=activation.response_schema_sha256,
            delivered_source_descriptor_sha256s=(activation.delivered_source_descriptor_sha256s),
            upstream_task_result_sha256s=activation.upstream_task_result_sha256s,
        )
        assert persisted_activation == activation
        runtime.journal.mark_dispatched(task.task_id)
        output = next(item for item in fixture.outputs if item.task_id == task.task_id)
        completion = output.model_completion_evidence
        persisted_output = runtime.journal.persist_output(
            task.task_id,
            output.payload,
            usage_record=completion.usage_record if completion is not None else None,
            specialist_accepted_outcome=output.specialist_accepted_outcome,
            model_surface_review_requests=output.model_surface_review_requests,
            model_surface_review_artifact=output.model_surface_review_artifact,
            accepted_candidates=output.accepted_candidates,
            normalization_evidence=(
                completion.normalization_evidence if completion is not None else None
            ),
        )
        assert persisted_output == output
        result = next(item for item in fixture.task_results if item.task_id == task.task_id)
        runtime.journal.record_terminal(result)
    assert runtime.journal.seal_pass_result(plan.pass_kind) == fixture.pass_results[0]
    return PipelineScheduler(runtime.journal)


def _ready_model_task(
    runtime: PipelineScheduler,
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
    *,
    seed: str,
) -> SchedulerTaskActivation:
    assert task.requested_model is not None
    assert task.system_prompt_sha256 is not None
    user_prompt_sha256 = _sha256(f"{seed}:user")
    runtime.request_ready(
        logical_request_id=task.logical_request_id,
        role=task.role,
        requested_model=task.requested_model,
        prompt_sha256=_sha256(f"{seed}:provider"),
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256=user_prompt_sha256,
        schema_sha256=task.response_schema_sha256,
        delivered_sources=_delivered_sources(plan, task),
        privacy_binding=_privacy_binding(plan),
    )
    activation = next(item for item in runtime.journal.activations if item.task_id == task.task_id)
    runtime.request_dispatched(logical_request_id=task.logical_request_id)
    return activation


def _record_ordinary_primary(
    runtime: PipelineScheduler,
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
    *,
    seed: str,
) -> SchedulerTaskResult:
    activation = _ready_model_task(runtime, plan, task, seed=seed)
    payload = build_scheduler_test_model_payload(plan, task)
    planned_requests = scheduler_test_model_surface_review_requests(plan, task)
    usage = build_scheduler_test_real_usage(
        task,
        activation,
        seed=seed,
        validated_output=payload,
        privacy_evidence_custody=plan.manifest.privacy_evidence_custody,
        model_surface_review_requests=planned_requests,
    ).model_copy(
        update={"execution_evidence": ExecutionEvidenceKind.MOCK},
    )
    requests, artifact = build_scheduler_test_model_surface_review_custody(
        plan,
        task,
        activation,
        usage,
        payload,
    )
    return runtime.record_model_success(
        task,
        output_value=payload,
        usage_records=[usage],
        model_surface_review_requests=requests,
        model_surface_review_artifact=artifact,
    )


def _runtime_retrieval_campaign(
    path: Path,
    *,
    seed: str,
    mode: str,
    fail_primary: bool = False,
) -> tuple[
    PipelineScheduler,
    SchedulerPassPlan,
    SchedulerTaskPlan,
    SchedulerRetrievalBinding,
]:
    fixture = build_complete_scheduler_fixture(seed=seed)
    manifest = fixture.manifest
    journal = create_scheduler_journal(
        path,
        bindings=manifest.bindings,
        analysis_input_inventory=scheduler_test_analysis_input_inventory(seed),
        shard_inventory=manifest.shard_inventory,
        privacy_evidence_custody=manifest.privacy_evidence_custody,
    )
    runtime = PipelineScheduler(journal)
    runtime = _replay_fixture_orientation(runtime, seed=seed, manifest=manifest)
    plan, primary, planner = _retrieval_plan(seed, manifest=manifest)
    runtime.prepare_pass(plan.pass_kind, plan.tasks)

    planner_activation = _ready_model_task(runtime, plan, planner, seed=f"{seed}:planner")
    policy = plan.retrieval_role_budget_allocation_for_task(primary.task_id).policy
    corpus_sha256 = _sha256(f"{seed}:corpus")
    intent = SolidityRetrievalIntent(
        operation=SolidityRetrievalOperation.RESOLVE_ENTITY,
        subject_id="entity:synthetic",
    )
    batch = SolidityRetrievalRequestBatch(requests=() if mode == "empty" else (intent,))
    planner_usage = build_scheduler_test_real_usage(
        planner,
        planner_activation,
        seed=f"{seed}:planner",
        validated_output=batch,
        privacy_evidence_custody=plan.manifest.privacy_evidence_custody,
    ).model_copy(
        update={"execution_evidence": ExecutionEvidenceKind.MOCK},
    )
    planner_usage = _usage_with_retrieval_planning_context(
        planner_usage,
        policy=policy,
        corpus_sha256=corpus_sha256,
    )
    planner_result = runtime.record_model_success(
        planner,
        output_value=batch,
        usage_records=[planner_usage],
    )
    assert planner_result.terminal_status is SchedulerTerminalStatus.SUCCEEDED
    runtime.set_upstream_results(primary, (planner_result,))

    if mode == "empty":
        transcript = SolidityRetrievalTranscript.build(
            role=primary.role,
            policy_sha256=policy.policy_sha256,
            corpus_sha256=corpus_sha256,
        )
    elif mode == "exhausted":
        request = SolidityRetrievalRequest.from_intent(intent)
        exhausted_result = SolidityRetrievalResult.build(
            request=request,
            status=SolidityRetrievalStatus.EXHAUSTED,
            omissions=(
                SolidityRetrievalOmission(
                    reason=SolidityRetrievalReason.REQUEST_COUNT_BUDGET,
                    count=1,
                ),
            ),
        )
        exchange = SolidityRetrievalExchange.build(
            sequence=1,
            previous_exchange_sha256=None,
            request=request,
            result=exhausted_result,
        )
        transcript = SolidityRetrievalTranscript.build(
            role=primary.role,
            policy_sha256=policy.policy_sha256,
            corpus_sha256=corpus_sha256,
            exchanges=(exchange,),
            accepted_request_count=0,
        )
    else:
        _ignored_policy, transcript = _transcript(
            role=primary.role,
            intent=intent,
            seed=seed,
        )
        policy = _ignored_policy
    binding = runtime.build_retrieval_binding(
        primary_task=primary,
        planner_task=planner,
        transcript=transcript,
    )
    primary_activation = _ready_model_task(runtime, plan, primary, seed=f"{seed}:primary")
    assert primary_activation.upstream_task_result_sha256s == (planner_result.result_sha256,)

    if fail_primary:
        primary_result = runtime.record_failure(
            primary,
            ValueError("synthetic primary failure after retrieval"),
        )
        assert primary_result.terminal_status is SchedulerTerminalStatus.FAILED
    else:
        payload = build_scheduler_test_model_payload(plan, primary)
        planned_requests = scheduler_test_model_surface_review_requests(plan, primary)
        primary_usage = build_scheduler_test_real_usage(
            primary,
            primary_activation,
            seed=f"{seed}:primary",
            validated_output=payload,
            privacy_evidence_custody=plan.manifest.privacy_evidence_custody,
            model_surface_review_requests=planned_requests,
        ).model_copy(
            update={"execution_evidence": ExecutionEvidenceKind.MOCK},
        )
        if not transcript.single_shot_fallback_required:
            primary_usage = _usage_with_retrieval_context(
                primary_usage,
                policy=policy,
                transcript=transcript,
            )
        requests, artifact = build_scheduler_test_model_surface_review_custody(
            plan,
            primary,
            primary_activation,
            primary_usage,
            payload,
        )
        primary_result = runtime.record_model_success(
            primary,
            output_value=payload,
            usage_records=[primary_usage],
            model_surface_review_requests=requests,
            model_surface_review_artifact=artifact,
            retrieval_binding=binding,
        )
        assert primary_result.terminal_status is SchedulerTerminalStatus.SUCCEEDED

    for other in plan.tasks:
        if other.task_id not in {planner.task_id, primary.task_id}:
            result = _record_ordinary_primary(
                runtime,
                plan,
                other,
                seed=f"{seed}:other:{other.task_id}",
            )
            assert result.terminal_status is SchedulerTerminalStatus.SUCCEEDED
    runtime.seal_pass_result()
    return runtime, plan, primary, binding


def _resume_retrieval_runtime(
    path: Path,
    *,
    plan: SchedulerPassPlan,
    seed: str,
) -> PipelineScheduler:
    return PipelineScheduler(
        resume_scheduler_journal(
            path,
            expected_bindings=plan.manifest.bindings,
            expected_analysis_input_inventory=scheduler_test_analysis_input_inventory(seed),
            expected_shard_inventory=plan.manifest.shard_inventory,
            expected_terminal_report_authority_required=False,
        )
    )


def test_retrieval_child_is_v11_in_detached_registry_without_schema_set_drift() -> None:
    plan, parent, child = _retrieval_plan("retrieval-plan-shape")
    rebuilt_primary = SchedulerTaskPlan.build(
        manifest=plan.manifest,
        pass_kind=parent.pass_kind,
        scope=parent.scope,
        task_kind=parent.task_kind,
        purpose=SchedulerTaskPurpose.PRIMARY,
        task_key=parent.task_key,
        role=parent.role,
        requested_model=parent.requested_model,
        root_lineage=parent.root_lineage,
        candidate_ids=parent.candidate_ids,
        model_surface_review_request_manifest_sha256=(
            parent.model_surface_review_request_manifest_sha256
        ),
        input_sha256=parent.input_sha256,
        prompt_sha256=parent.prompt_sha256,
        system_prompt_sha256=parent.system_prompt_sha256,
        normalizer_sha256=parent.normalizer_sha256,
        response_schema_sha256=parent.response_schema_sha256,
    )

    assert parent.schema_version == "1.0"
    assert rebuilt_primary.model_dump_json() == parent.model_dump_json()
    assert rebuilt_primary.task_plan_sha256 == parent.task_plan_sha256
    assert "purpose" not in parent.model_dump(mode="json")
    assert "parent_task_id" not in parent.model_dump(mode="json")
    assert child.schema_version == "1.1"
    assert child.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
    assert child.parent_task_id == parent.task_id
    assert child.task_id != parent.task_id
    assert child.logical_request_id != parent.logical_request_id
    assert child.normalizer_sha256 is None
    assert child.response_schema_sha256 == scheduler_response_schema_sha256(
        SolidityRetrievalRequestBatch
    )
    assert plan.schema_version == "1.1"
    assert len(plan.retrieval_role_budget_plans) == 1
    role_budget = plan.retrieval_role_budget_plan_for_task(parent.task_id)
    allocation = plan.retrieval_role_budget_allocation_for_task(parent.task_id)
    assert role_budget.role == parent.role
    assert role_budget.allocations == (allocation,)
    assert allocation.policy.policy_sha256 == role_budget.ceiling.policy_sha256
    assert (
        scheduler_response_schema_set_sha256_for_algorithm(
            algorithm_version="mmaudit.seven-pass-scheduler.v1"
        )
        == "c913ab94fab7fc3eafaaaa83686047bb83786a66b893eb2ebf78a364326bf7b7"
    )
    assert (
        scheduler_response_schema_set_sha256_for_algorithm(
            algorithm_version="mmaudit.seven-pass-scheduler.v2"
        )
        == "cd19136893b9caca1054ce45dcf05e555ba078e960aeaa7d4e7672f7b04f839a"
    )
    retrieval_model_type = "mmaudit.models.retrieval.SolidityRetrievalRequestBatch"
    assert retrieval_model_type not in {
        item["model_type"]
        for item in scheduler_response_schema_inventory_for_algorithm(
            algorithm_version="mmaudit.seven-pass-scheduler.v1"
        )
    }
    assert retrieval_model_type not in {
        item["model_type"]
        for item in scheduler_response_schema_inventory_for_algorithm(
            algorithm_version="mmaudit.seven-pass-scheduler.v2"
        )
    }
    assert (
        scheduler_auxiliary_response_schema_inventory_for_algorithm(
            algorithm_version="mmaudit.seven-pass-scheduler.v1"
        )
        == ()
    )
    assert scheduler_response_schema_sha256(SolidityRetrievalRequestBatch) in (
        scheduler_auxiliary_response_schema_hashes_for_algorithm(
            algorithm_version="mmaudit.seven-pass-scheduler.v2"
        )
    )
    assert {
        item["model_type"]
        for item in scheduler_auxiliary_response_schema_inventory_for_algorithm(
            algorithm_version="mmaudit.seven-pass-scheduler.v2"
        )
    } == {retrieval_model_type}
    assert (
        scheduler_auxiliary_response_schema_set_sha256_for_algorithm(
            algorithm_version="mmaudit.seven-pass-scheduler.v2"
        )
        == "7d1b86ed39c47dbda316a40b4cf9277010e7dbb7328bfaadb411a661deba9041"
    )

    orphan = SchedulerTaskPlan.build(
        manifest=plan.manifest,
        pass_kind=plan.pass_kind,
        scope=parent.scope,
        task_kind=SchedulerTaskKind.MODEL_REQUEST,
        purpose=SchedulerTaskPurpose.RETRIEVAL_PLANNING,
        parent_task_id="scheduler-task-" + ("0" * 64),
        task_key="orphan-retrieval",
        role=parent.role,
        requested_model=parent.requested_model,
        root_lineage=parent.root_lineage,
        candidate_ids=parent.candidate_ids,
        model_surface_review_request_manifest_sha256=(
            parent.model_surface_review_request_manifest_sha256
        ),
        input_sha256=_sha256("orphan-input"),
        prompt_sha256=_sha256("orphan-prompt"),
        system_prompt_sha256=_sha256("orphan-system"),
        response_schema_sha256=scheduler_response_schema_sha256(SolidityRetrievalRequestBatch),
    )
    with pytest.raises(ValueError, match="exact primary parent"):
        SchedulerPassPlan.build(
            manifest=plan.manifest,
            pass_kind=plan.pass_kind,
            dependencies=plan.dependencies,
            tasks=(
                *(task for task in plan.tasks if task.purpose is SchedulerTaskPurpose.PRIMARY),
                orphan,
            ),
        )

    with pytest.raises(ValueError, match="retrieval-planning task shape"):
        SchedulerTaskPlan.build(
            manifest=_legacy_manifest(plan.manifest),
            pass_kind=plan.pass_kind,
            scope=parent.scope,
            task_kind=SchedulerTaskKind.MODEL_REQUEST,
            purpose=SchedulerTaskPurpose.RETRIEVAL_PLANNING,
            parent_task_id=parent.task_id,
            task_key="legacy-retrieval",
            role=parent.role,
            requested_model=parent.requested_model,
            root_lineage=parent.root_lineage,
            candidate_ids=parent.candidate_ids,
            model_surface_review_request_manifest_sha256=(
                parent.model_surface_review_request_manifest_sha256
            ),
            input_sha256=_sha256("legacy-retrieval-input"),
            prompt_sha256=_sha256("legacy-retrieval-prompt"),
            system_prompt_sha256=_sha256("legacy-retrieval-system"),
            response_schema_sha256=scheduler_response_schema_sha256(SolidityRetrievalRequestBatch),
        )


def test_pass_plan_statically_caps_six_concurrent_retrieval_primaries() -> None:
    seed = "retrieval-role-budget-six"
    fixture = build_complete_scheduler_fixture(seed=seed)
    original = next(
        plan for plan in fixture.plans if plan.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
    )
    template = next(task for task in original.tasks if task.role == "source_audit")
    primaries = [template]
    for index in range(5):
        primaries.append(
            SchedulerTaskPlan.build(
                manifest=original.manifest,
                pass_kind=original.pass_kind,
                scope=template.scope,
                task_kind=SchedulerTaskKind.MODEL_REQUEST,
                task_key=f"retrieval-budget-primary-{index}",
                role=template.role,
                requested_model=template.requested_model,
                root_lineage=template.root_lineage,
                candidate_ids=template.candidate_ids,
                model_surface_review_request_manifest_sha256=(
                    template.model_surface_review_request_manifest_sha256
                ),
                input_sha256=_sha256(f"{seed}:primary-input:{index}"),
                prompt_sha256=_sha256(f"{seed}:primary-prompt:{index}"),
                system_prompt_sha256=template.system_prompt_sha256,
                normalizer_sha256=template.normalizer_sha256,
                response_schema_sha256=template.response_schema_sha256,
            )
        )
    children = tuple(
        SchedulerTaskPlan.build(
            manifest=original.manifest,
            pass_kind=original.pass_kind,
            scope=primary.scope,
            task_kind=SchedulerTaskKind.MODEL_REQUEST,
            purpose=SchedulerTaskPurpose.RETRIEVAL_PLANNING,
            parent_task_id=primary.task_id,
            task_key=f"retrieval-budget-child-{index}",
            role=primary.role,
            requested_model=primary.requested_model,
            root_lineage=primary.root_lineage,
            candidate_ids=primary.candidate_ids,
            model_surface_review_request_manifest_sha256=(
                primary.model_surface_review_request_manifest_sha256
            ),
            input_sha256=_sha256(f"{seed}:child-input:{index}"),
            prompt_sha256=_sha256(f"{seed}:child-prompt:{index}"),
            system_prompt_sha256=_sha256(f"{seed}:child-system:{index}"),
            response_schema_sha256=scheduler_response_schema_sha256(SolidityRetrievalRequestBatch),
        )
        for index, primary in enumerate(primaries)
    )
    plan = SchedulerPassPlan.build(
        manifest=original.manifest,
        pass_kind=original.pass_kind,
        dependencies=original.dependencies,
        tasks=(*original.tasks, *primaries[1:], *children),
    )
    budget = plan.retrieval_role_budget_plans[0]

    assert budget.role == "source_audit"
    assert len(budget.allocations) == 6
    assert budget.allocated_maximum_requests == 4
    assert budget.allocated_maximum_total_result_utf8_bytes == 16_384
    assert budget.allocated_maximum_total_result_tokens == 5_462
    assert sum(allocation.policy.maximum_requests == 0 for allocation in budget.allocations) == 2
    assert (
        sum(allocation.policy.maximum_total_result_utf8_bytes for allocation in budget.allocations)
        == 16_384
    )
    assert (
        sum(allocation.policy.maximum_total_result_tokens for allocation in budget.allocations)
        == 5_462
    )

    drifted_budget = SolidityRetrievalRoleBudgetPlan.build(
        role="source_audit",
        primary_task_ids=tuple(primary.task_id for primary in primaries[:-1]),
    )
    drifted_plan = plan.model_copy(
        update={"retrieval_role_budget_plans": (drifted_budget,)},
    )
    with pytest.raises(ValueError, match="exact child inventory"):
        SchedulerPassPlan.model_validate(drifted_plan.model_dump(mode="python"))


def test_generated_public_scheduler_schema_exposes_only_hash_only_retrieval_custody() -> None:
    artifact_schema = SchedulerArtifact.model_json_schema()
    definitions = artifact_schema["$defs"]
    public_request = definitions["SchedulerModelRequestEvidence"]["properties"]
    retrieval_custody = definitions["SchedulerRetrievalCustody"]["properties"]
    report_binding = SchedulerReportBinding.model_json_schema()["properties"]

    assert public_request["purpose"]["$ref"].endswith("/SchedulerTaskPurpose")
    assert "parent_task_id" in public_request
    assert public_request["retrieval_custody"]["anyOf"][0] == {
        "$ref": "#/$defs/SchedulerRetrievalCustody"
    }
    assert "transcript" not in retrieval_custody
    assert "request_sha256s" in retrieval_custody
    assert "result_sha256s" in retrieval_custody
    assert "exchange_sha256s" in retrieval_custody
    assert "role_budget_plan_sha256" in retrieval_custody
    assert "role_budget_allocation_sha256" in retrieval_custody
    assert "retrieval_planning_task_count" in report_binding
    assert "retrieval_planning_non_success_count" in report_binding


def test_successful_planner_transcript_projects_hash_only_public_custody() -> None:
    plan, parent, child = _retrieval_plan("retrieval-success")
    _child_activation, child_output, child_result, intent = _successful_planner(
        plan,
        child,
        seed="retrieval-success:child",
        corpus_sha256=_sha256("retrieval-success:corpus"),
    )
    with pytest.raises(ValueError, match="retrieval-child result"):
        _activation(plan, parent, seed="retrieval-success:missing")
    primary_activation = _activation(
        plan,
        parent,
        seed="retrieval-success:primary",
        retrieval_result=child_result,
    )
    assert primary_activation.upstream_task_result_sha256s == (child_result.result_sha256,)
    policy, transcript = _transcript(
        role=parent.role,
        intent=intent,
        seed="retrieval-success",
    )
    empty_transcript = SolidityRetrievalTranscript.build(
        role=parent.role,
        policy_sha256=policy.policy_sha256,
        corpus_sha256=transcript.corpus_sha256,
    )
    with pytest.raises(ValueError, match="planner request batch"):
        SchedulerRetrievalBinding.build(
            plan=plan,
            primary_task=parent,
            primary_activation=primary_activation,
            planner_task=child,
            planner_output=child_output,
            planner_result=child_result,
            transcript=empty_transcript,
        )
    drifted_policy = SolidityRetrievalRolePolicy.build(
        role=parent.role,
        maximum_requests=1,
    )
    drifted_transcript = SolidityRetrievalTranscript.build(
        role=parent.role,
        policy_sha256=drifted_policy.policy_sha256,
        corpus_sha256=transcript.corpus_sha256,
        exchanges=transcript.exchanges,
        accepted_request_count=transcript.accepted_request_count,
    )
    with pytest.raises(ValueError, match="planner lifecycle"):
        SchedulerRetrievalBinding.build(
            plan=plan,
            primary_task=parent,
            primary_activation=primary_activation,
            planner_task=child,
            planner_output=child_output,
            planner_result=child_result,
            transcript=drifted_transcript,
        )
    binding = SchedulerRetrievalBinding.build(
        plan=plan,
        primary_task=parent,
        primary_activation=primary_activation,
        planner_task=child,
        planner_output=child_output,
        planner_result=child_result,
        transcript=transcript,
    )
    primary_output, primary_result = _successful_primary(
        plan,
        parent,
        primary_activation,
        seed="retrieval-success:primary",
        retrieval_binding=binding,
        retrieval_policy=policy,
        retrieval_transcript=transcript,
    )
    public = SchedulerModelRequestEvidence.build(
        plan=plan,
        task=parent,
        activation=primary_activation,
        result=primary_result,
    )

    assert child_output.model_completion_evidence is not None
    assert child_output.model_completion_evidence.normalizer_sha256 is None
    planner_context = child_output.model_completion_evidence.context_request_evidence
    assert planner_context.schema_version == "1.1"
    assert planner_context.retrieval_policy_sha256 == policy.policy_sha256
    assert planner_context.retrieval_corpus_sha256 == transcript.corpus_sha256
    assert planner_context.retrieval_transcript_sha256 is None
    assert child_output.specialist_accepted_outcome is None
    assert child_output.model_surface_review_artifact is None
    assert child_output.reviewed_source_descriptor_sha256s == ()
    assert child_output.reviewed_candidate_ids == ()
    assert child_output.accepted_candidates == ()
    assert primary_output.schema_version == "1.3"
    assert primary_output.retrieval_binding == binding
    assert primary_result.schema_version == "1.1"
    assert public.schema_version == "1.1"
    assert public.retrieval_custody == primary_result.retrieval_custody
    assert public.retrieval_custody is not None
    assert public.retrieval_custody.transcript_sha256 == transcript.transcript_sha256
    allocation = plan.retrieval_role_budget_allocation_for_task(parent.task_id)
    role_budget = plan.retrieval_role_budget_plan_for_task(parent.task_id)
    assert binding.role_budget_plan_sha256 == role_budget.plan_sha256
    assert binding.role_budget_allocation_sha256 == allocation.allocation_sha256
    assert public.retrieval_custody.role_budget_plan_sha256 == role_budget.plan_sha256
    assert public.retrieval_custody.role_budget_allocation_sha256 == allocation.allocation_sha256
    assert public.retrieval_custody.request_sha256s == (
        transcript.exchanges[0].request.request_sha256,
    )
    assert "transcript" not in public.model_dump(mode="json")["retrieval_custody"]

    pass_result = SchedulerPassResult.build(
        plan=plan,
        task_results=(
            child_result,
            primary_result,
            *_other_primary_results(plan, parent, seed="retrieval-success:other"),
        ),
    )
    assert pass_result.status is SchedulerPassStatus.COMPLETE


def test_pre_activation_rejects_transcript_with_planner_context_corpus_drift() -> None:
    plan, parent, child = _retrieval_plan("retrieval-corpus-drift")
    _activation_item, child_output, child_result, intent = _successful_planner(
        plan,
        child,
        seed="retrieval-corpus-drift:child",
        corpus_sha256=_sha256("retrieval-corpus-drift:planned-corpus"),
    )
    _policy, transcript = _transcript(
        role=parent.role,
        intent=intent,
        seed="retrieval-corpus-drift:executed-corpus",
    )

    with pytest.raises(ValueError, match="planner lifecycle"):
        SchedulerRetrievalBinding.build_pre_activation(
            plan=plan,
            primary_task=parent,
            planner_task=child,
            planner_output=child_output,
            planner_result=child_result,
            transcript=transcript,
        )


def test_pre_activation_rejects_legacy_planner_context_without_retrieval_binding() -> None:
    plan, parent, child = _retrieval_plan("retrieval-legacy-planner-context")
    _activation_item, child_output, child_result, intent = _successful_planner(
        plan,
        child,
        seed="retrieval-legacy-planner-context:child",
        corpus_sha256=_sha256("retrieval-legacy-planner-context:corpus"),
        bind_retrieval_context=False,
    )
    _policy, transcript = _transcript(
        role=parent.role,
        intent=intent,
        seed="retrieval-legacy-planner-context",
    )
    assert child_output.model_completion_evidence is not None
    assert child_output.model_completion_evidence.context_request_evidence.schema_version == "1.0"

    with pytest.raises(ValueError, match="planner lifecycle"):
        SchedulerRetrievalBinding.build_pre_activation(
            plan=plan,
            primary_task=parent,
            planner_task=child,
            planner_output=child_output,
            planner_result=child_result,
            transcript=transcript,
        )


def test_pre_activation_rejects_planner_context_policy_drift() -> None:
    plan, parent, child = _retrieval_plan("retrieval-planner-policy-drift")
    corpus_sha256 = _sha256("retrieval-planner-policy-drift:corpus")
    drifted_policy = SolidityRetrievalRolePolicy.build(
        role=parent.role,
        maximum_requests=1,
    )
    _activation_item, child_output, child_result, intent = _successful_planner(
        plan,
        child,
        seed="retrieval-planner-policy-drift:child",
        corpus_sha256=corpus_sha256,
        planning_policy=drifted_policy,
    )
    allocation = plan.retrieval_role_budget_allocation_for_task(parent.task_id)
    _ignored_policy, provisional = _transcript(
        role=parent.role,
        intent=intent,
        seed="retrieval-planner-policy-drift",
    )
    transcript = SolidityRetrievalTranscript.build(
        role=parent.role,
        policy_sha256=allocation.policy.policy_sha256,
        corpus_sha256=corpus_sha256,
        exchanges=provisional.exchanges,
        accepted_request_count=provisional.accepted_request_count,
    )

    with pytest.raises(ValueError, match="planner lifecycle"):
        SchedulerRetrievalBinding.build_pre_activation(
            plan=plan,
            primary_task=parent,
            planner_task=child,
            planner_output=child_output,
            planner_result=child_result,
            transcript=transcript,
        )


def test_pre_activation_rejects_resealed_transcript_exceeding_role_policy() -> None:
    plan, parent, child = _retrieval_plan("retrieval-policy-overrun")
    corpus_sha256 = _sha256("retrieval-policy-overrun:corpus")
    intent = SolidityRetrievalIntent(
        operation=SolidityRetrievalOperation.FETCH_INDEXED_RANGE,
        subject_id="entity:oversized",
    )
    _activation_item, child_output, child_result, _intent = _successful_planner(
        plan,
        child,
        seed="retrieval-policy-overrun:child",
        corpus_sha256=corpus_sha256,
        intent=intent,
    )
    policy = plan.retrieval_role_budget_allocation_for_task(parent.task_id).policy
    request = SolidityRetrievalRequest.from_intent(intent)
    content = "x" * (policy.maximum_result_utf8_bytes + 1)
    entity = SolidityRetrievalEntity(
        subject_id=intent.subject_id,
        kind=SolidityRetrievalEntityKind.CONTRACT,
        name="SyntheticOversized",
        path="src/SyntheticOversized.sol",
        start_line=1,
        end_line=1,
        source_hash=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        payable=False,
    )
    result = SolidityRetrievalResult.build(
        request=request,
        status=SolidityRetrievalStatus.COMPLETE,
        records=(SolidityRetrievalRecord(entity=entity, content=content),),
    )
    assert result.result_utf8_bytes > policy.maximum_result_utf8_bytes
    exchange = SolidityRetrievalExchange.build(
        sequence=1,
        previous_exchange_sha256=None,
        request=request,
        result=result,
    )
    transcript = SolidityRetrievalTranscript.build(
        role=parent.role,
        policy_sha256=policy.policy_sha256,
        corpus_sha256=corpus_sha256,
        exchanges=(exchange,),
        accepted_request_count=1,
    )

    with pytest.raises(ValueError, match="exceeds its exact role policy"):
        SchedulerRetrievalBinding.build_pre_activation(
            plan=plan,
            primary_task=parent,
            planner_task=child,
            planner_output=child_output,
            planner_result=child_result,
            transcript=transcript,
        )


def test_empty_non_exhausted_transcript_requires_unchanged_single_shot_context() -> None:
    plan, parent, child = _retrieval_plan("retrieval-empty")
    child_activation = _activation(plan, child, seed="retrieval-empty:child")
    batch = SolidityRetrievalRequestBatch(requests=())
    child_usage = build_scheduler_test_usage(
        child,
        child_activation,
        seed="retrieval-empty:child",
        validated_output=batch,
        privacy_evidence_custody=plan.manifest.privacy_evidence_custody,
    )
    policy = plan.retrieval_role_budget_allocation_for_task(parent.task_id).policy
    corpus_sha256 = _sha256("retrieval-empty:corpus")
    child_usage = _usage_with_retrieval_planning_context(
        child_usage,
        policy=policy,
        corpus_sha256=corpus_sha256,
    )
    child_output = SchedulerTaskOutput.build(
        plan=plan,
        task=child,
        activation=child_activation,
        payload=batch,
        usage_record=child_usage,
    )
    assert child_usage.validated_response_sha256 is not None
    child_result = SchedulerTaskResult.build(
        plan=plan,
        task=child,
        activation=child_activation,
        terminal_status=SchedulerTerminalStatus.SUCCEEDED,
        terminal_evidence_sha256=child_usage.validated_response_sha256,
        output=child_output,
    )
    primary_activation = _activation(
        plan,
        parent,
        seed="retrieval-empty:primary",
        retrieval_result=child_result,
    )
    transcript = SolidityRetrievalTranscript.build(
        role=parent.role,
        policy_sha256=policy.policy_sha256,
        corpus_sha256=corpus_sha256,
    )
    binding = SchedulerRetrievalBinding.build(
        plan=plan,
        primary_task=parent,
        primary_activation=primary_activation,
        planner_task=child,
        planner_output=child_output,
        planner_result=child_result,
        transcript=transcript,
    )
    primary_output, _primary_result = _successful_primary(
        plan,
        parent,
        primary_activation,
        seed="retrieval-empty:primary",
        retrieval_binding=binding,
        retrieval_policy=policy,
        retrieval_transcript=transcript,
    )
    assert primary_output.model_completion_evidence is not None
    context = primary_output.model_completion_evidence.context_request_evidence
    assert context.schema_version == "1.0"
    assert context.retrieval_transcript_sha256 is None
    assert context.retrieval_request_sha256s == ()

    with pytest.raises(ValueError, match="unchanged single-shot context"):
        _successful_primary(
            plan,
            parent,
            primary_activation,
            seed="retrieval-empty:invalid-context",
            retrieval_binding=binding,
            retrieval_policy=policy,
            retrieval_transcript=transcript,
            project_retrieval_context=True,
        )


def test_failed_planner_is_retained_but_does_not_override_primary_success() -> None:
    plan, parent, child = _retrieval_plan("retrieval-fallback")
    child_result = SchedulerTaskResult.build_preflight_failure(
        plan=plan,
        task=child,
        terminal_status=SchedulerTerminalStatus.FAILED,
        terminal_evidence_sha256=_sha256("retrieval-fallback:failure"),
    )
    primary_activation = _activation(
        plan,
        parent,
        seed="retrieval-fallback:primary",
        retrieval_result=child_result,
    )
    primary_output, primary_result = _successful_primary(
        plan,
        parent,
        primary_activation,
        seed="retrieval-fallback:primary",
    )
    assert primary_output.retrieval_binding is None
    assert primary_result.retrieval_custody is None

    all_results = (
        child_result,
        primary_result,
        *_other_primary_results(plan, parent, seed="retrieval-fallback:other"),
    )
    pass_result = SchedulerPassResult.build(plan=plan, task_results=all_results)
    assert pass_result.status is SchedulerPassStatus.COMPLETE
    retained_child = next(
        result for result in pass_result.task_results if result.task_id == child.task_id
    )
    assert retained_child.terminal_status is SchedulerTerminalStatus.FAILED
    with pytest.raises(ValueError, match="exact task plan"):
        SchedulerPassResult.build(
            plan=plan,
            task_results=tuple(result for result in all_results if result.task_id != child.task_id),
        )


def test_planner_usage_is_accounted_but_excluded_from_review_credit() -> None:
    plan, primary, planner = _retrieval_plan("retrieval-usage-credit")
    planner_activation, _planner_output, planner_result, _intent = _successful_planner(
        plan,
        planner,
        seed="retrieval-usage-credit:planner",
        corpus_sha256=_sha256("retrieval-usage-credit:corpus"),
    )
    planner_batch = SolidityRetrievalRequestBatch(
        requests=(
            SolidityRetrievalIntent(
                operation=SolidityRetrievalOperation.RESOLVE_ENTITY,
                subject_id="entity:synthetic",
            ),
        )
    )
    planner_usage = build_scheduler_test_real_usage(
        planner,
        planner_activation,
        seed="retrieval-usage-credit:planner",
        validated_output=planner_batch,
        privacy_evidence_custody=plan.manifest.privacy_evidence_custody,
    )
    primary_activation = _activation(
        plan,
        primary,
        seed="retrieval-usage-credit:primary",
        retrieval_result=planner_result,
    )
    primary_payload = build_scheduler_test_model_payload(plan, primary)
    primary_usage = build_scheduler_test_real_usage(
        primary,
        primary_activation,
        seed="retrieval-usage-credit:primary",
        validated_output=primary_payload,
        privacy_evidence_custody=plan.manifest.privacy_evidence_custody,
        model_surface_review_requests=scheduler_test_model_surface_review_requests(
            plan,
            primary,
        ),
    )
    assert is_creditable_usage_record(planner_usage, require_real=True)
    assert is_creditable_usage_record(primary_usage, require_real=True)

    outputs = (
        SimpleNamespace(
            task_id=planner.task_id,
            model_completion_evidence=SimpleNamespace(usage_record=planner_usage),
        ),
        SimpleNamespace(
            task_id=primary.task_id,
            model_completion_evidence=SimpleNamespace(usage_record=primary_usage),
        ),
    )
    projection = SimpleNamespace(
        plans=(plan,),
        task_results=(
            SimpleNamespace(
                task_id=planner.task_id,
                terminal_status=SchedulerTerminalStatus.SUCCEEDED,
            ),
            SimpleNamespace(
                task_id=primary.task_id,
                terminal_status=SchedulerTerminalStatus.SUCCEEDED,
            ),
        ),
        _retained_outputs=lambda: outputs,
        _retained_main_provider_usage_records=lambda: (planner_usage, primary_usage),
        _retained_typed_recovery_usage=lambda: ((), (), ()),
        _promoted_typed_recovery_usage=lambda: (),
    )
    retained_getter = SchedulerJournal.retained_provider_usage_records.fget
    structural_getter = SchedulerJournal.structurally_successful_review_usage_records.fget
    restorable_getter = SchedulerJournal.restorable_review_usage_records.fget
    assert retained_getter is not None
    assert structural_getter is not None
    assert restorable_getter is not None

    retained = retained_getter(projection)  # type: ignore[arg-type]
    structural = structural_getter(projection)  # type: ignore[arg-type]
    restorable = restorable_getter(projection)  # type: ignore[arg-type]

    assert {record.request_id for record in retained} == {
        planner.logical_request_id,
        primary.logical_request_id,
    }
    assert tuple(record.request_id for record in structural) == (primary.logical_request_id,)
    assert tuple(record.request_id for record in restorable) == (primary.logical_request_id,)


def test_exhausted_transcript_requires_unchanged_single_shot_context() -> None:
    plan, parent, child = _retrieval_plan("retrieval-exhausted")
    _child_activation, child_output, child_result, intent = _successful_planner(
        plan,
        child,
        seed="retrieval-exhausted:child",
        corpus_sha256=_sha256("retrieval-exhausted:corpus"),
    )
    primary_activation = _activation(
        plan,
        parent,
        seed="retrieval-exhausted:primary",
        retrieval_result=child_result,
    )
    policy = SolidityRetrievalRolePolicy.build(role=parent.role)
    request = SolidityRetrievalRequest.from_intent(intent)
    exhausted_result = SolidityRetrievalResult.build(
        request=request,
        status=SolidityRetrievalStatus.EXHAUSTED,
        omissions=(
            SolidityRetrievalOmission(
                reason=SolidityRetrievalReason.REQUEST_COUNT_BUDGET,
                count=1,
            ),
        ),
    )
    exchange = SolidityRetrievalExchange.build(
        sequence=1,
        previous_exchange_sha256=None,
        request=request,
        result=exhausted_result,
    )
    transcript = SolidityRetrievalTranscript.build(
        role=parent.role,
        policy_sha256=policy.policy_sha256,
        corpus_sha256=_sha256("retrieval-exhausted:corpus"),
        exchanges=(exchange,),
        accepted_request_count=0,
    )
    binding = SchedulerRetrievalBinding.build(
        plan=plan,
        primary_task=parent,
        primary_activation=primary_activation,
        planner_task=child,
        planner_output=child_output,
        planner_result=child_result,
        transcript=transcript,
    )

    primary_output, primary_result = _successful_primary(
        plan,
        parent,
        primary_activation,
        seed="retrieval-exhausted:primary",
        retrieval_binding=binding,
    )
    assert primary_output.retrieval_binding == binding
    assert primary_result.retrieval_custody is not None
    assert primary_result.retrieval_custody.single_shot_fallback_required
    assert primary_output.model_completion_evidence is not None
    context = primary_output.model_completion_evidence.context_request_evidence
    assert context.schema_version == "1.0"
    assert context.retrieval_policy_sha256 is None
    assert context.retrieval_request_sha256s == ()

    with pytest.raises(ValueError, match="unchanged single-shot context"):
        _successful_primary(
            plan,
            parent,
            primary_activation,
            seed="retrieval-exhausted:invalid-context",
            retrieval_binding=binding,
            retrieval_policy=policy,
            retrieval_transcript=transcript,
            project_retrieval_context=True,
        )


@pytest.mark.parametrize("mode", ["success", "empty", "exhausted"])
def test_runtime_persists_and_recovers_exact_private_retrieval_binding(
    tmp_path: Path,
    mode: str,
) -> None:
    seed = f"retrieval-runtime:{mode}"
    path = tmp_path / mode
    runtime, plan, primary, binding = _runtime_retrieval_campaign(
        path,
        seed=seed,
        mode=mode,
    )
    runtime.close()

    resumed = _resume_retrieval_runtime(
        path,
        plan=plan,
        seed=seed,
    )
    pass_result = resumed.completed_pass_result(plan.pass_kind, plan.tasks)
    assert pass_result is not None
    recovered = resumed.completed_retrieval_binding_for_task(pass_result, primary)
    public_artifact = resumed.journal.artifact()
    planner_task = next(
        task for task in plan.tasks if task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
    )
    public_planner = next(
        request
        for request in public_artifact.model_requests
        if request.task_id == planner_task.task_id
    )

    assert recovered == binding
    assert recovered is not binding
    assert recovered.transcript.transcript_sha256 == binding.transcript.transcript_sha256
    assert public_planner.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
    assert public_planner.parent_task_id == primary.task_id
    assert public_planner.activation_status is SchedulerActivationStatus.ACTIVATED
    assert public_planner.terminal_status is SchedulerTerminalStatus.SUCCEEDED
    assert public_planner.retrieval_custody is None
    assert "transcript" not in json.dumps(public_planner.model_dump(mode="json"))
    if mode == "empty":
        assert recovered.transcript.exchanges == ()
        assert recovered.transcript.retrieval_exhausted is False
        assert recovered.transcript.single_shot_fallback_required
        result = resumed.completed_result_for_task(pass_result, primary)
        assert result.retrieval_custody is not None
        assert result.retrieval_custody.retrieval_exhausted is False
        assert result.retrieval_custody.single_shot_fallback_required
    elif mode == "exhausted":
        assert recovered.transcript.single_shot_fallback_required
        result = resumed.completed_result_for_task(pass_result, primary)
        assert result.retrieval_custody is not None
        assert result.retrieval_custody.single_shot_fallback_required
    resumed.close()


def test_public_artifact_retains_local_retrieval_failure_without_private_payload(
    tmp_path: Path,
) -> None:
    seed = "retrieval-runtime:local-failure"
    path = tmp_path / "local-failure"
    fixture = build_complete_scheduler_fixture(seed=seed)
    manifest = fixture.manifest
    runtime = PipelineScheduler(
        create_scheduler_journal(
            path,
            bindings=manifest.bindings,
            analysis_input_inventory=scheduler_test_analysis_input_inventory(seed),
            shard_inventory=manifest.shard_inventory,
            privacy_evidence_custody=manifest.privacy_evidence_custody,
        )
    )
    runtime = _replay_fixture_orientation(runtime, seed=seed, manifest=manifest)
    plan, primary, planner = _retrieval_plan(seed, manifest=manifest)
    runtime.prepare_pass(plan.pass_kind, plan.tasks)

    planner_result = runtime.record_failure(
        planner,
        error=ValueError("synthetic local retrieval planning failure"),
    )
    assert planner_result.result_origin.value == "LOCAL_PREFLIGHT"
    runtime.set_upstream_results(primary, (planner_result,))
    assert (
        _record_ordinary_primary(
            runtime,
            plan,
            primary,
            seed=f"{seed}:primary",
        ).terminal_status
        is SchedulerTerminalStatus.SUCCEEDED
    )
    for other in plan.tasks:
        if other.task_id not in {planner.task_id, primary.task_id}:
            assert (
                _record_ordinary_primary(
                    runtime,
                    plan,
                    other,
                    seed=f"{seed}:other:{other.task_id}",
                ).terminal_status
                is SchedulerTerminalStatus.SUCCEEDED
            )
    runtime.seal_pass_result()

    artifact = runtime.journal.artifact()
    public_planner = next(
        request for request in artifact.model_requests if request.task_id == planner.task_id
    )
    report_binding = SchedulerReportBinding.from_artifact(artifact)

    assert public_planner.schema_version == "1.1"
    assert public_planner.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
    assert public_planner.parent_task_id == primary.task_id
    assert public_planner.activation_status is SchedulerActivationStatus.PREFLIGHT_FAILED
    assert public_planner.terminal_status is SchedulerTerminalStatus.FAILED
    assert public_planner.response_schema_sha256 is None
    assert public_planner.retrieval_custody is None
    assert "transcript" not in json.dumps(public_planner.model_dump(mode="json"))
    assert report_binding.schema_version == "1.1"
    assert report_binding.retrieval_planning_task_count == 1
    assert report_binding.retrieval_planning_preflight_failure_count == 1
    assert report_binding.retrieval_planning_non_success_count == 1
    runtime.close()


def test_failed_primary_retains_private_transcript_and_public_hash_custody(
    tmp_path: Path,
) -> None:
    seed = "retrieval-runtime:failed-primary"
    path = tmp_path / "failed-primary"
    runtime, plan, primary, binding = _runtime_retrieval_campaign(
        path,
        seed=seed,
        mode="success",
        fail_primary=True,
    )
    pass_result = runtime.completed_pass_result(plan.pass_kind, plan.tasks)
    assert pass_result is not None
    failed = runtime.completed_result_for_task(pass_result, primary)
    public_request = next(
        request
        for request in runtime.journal.artifact().model_requests
        if request.task_id == primary.task_id
    )

    assert failed.terminal_status is SchedulerTerminalStatus.FAILED
    assert failed.output_artifact_sha256 is None
    assert failed.retrieval_custody is not None
    assert failed.retrieval_custody.transcript_sha256 == binding.transcript.transcript_sha256
    assert public_request.retrieval_custody == failed.retrieval_custody
    assert not any(output.task_id == primary.task_id for output in runtime.journal.outputs)
    assert len(tuple((path / "retrieval-bindings").glob(f"{primary.task_id}-*.json"))) == 1
    public_json = json.dumps(public_request.model_dump(mode="json"))
    assert '"exchanges"' not in public_json
    assert "entity:synthetic" not in public_json
    runtime.close()

    resumed = _resume_retrieval_runtime(path, plan=plan, seed=seed)
    resumed_pass = resumed.completed_pass_result(plan.pass_kind, plan.tasks)
    assert resumed_pass is not None
    assert resumed.completed_retrieval_binding_for_task(resumed_pass, primary) == binding
    resumed.close()


def test_resume_rejects_tampered_private_retrieval_transcript(tmp_path: Path) -> None:
    seed = "retrieval-runtime:tamper"
    path = tmp_path / "tamper"
    runtime, plan, primary, _binding = _runtime_retrieval_campaign(
        path,
        seed=seed,
        mode="success",
    )
    runtime.close()

    retrieval_binding_path = next((path / "retrieval-bindings").glob(f"{primary.task_id}-*.json"))
    payload = json.loads(retrieval_binding_path.read_text())
    payload["transcript"]["corpus_sha256"] = "f" * 64
    retrieval_binding_path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        _resume_retrieval_runtime(
            path,
            plan=plan,
            seed=seed,
        )
