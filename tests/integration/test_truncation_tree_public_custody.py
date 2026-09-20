"""Original local journals with interleaved synthetic roots; never provider qualification."""

from __future__ import annotations

import hashlib
from decimal import Decimal
from pathlib import Path
from typing import Any

from mmaudit.models.scheduler import (
    SchedulerPassKind,
    SchedulerPassStatus,
    SchedulerScope,
    SchedulerTaskResult,
    SchedulerTerminalStatus,
)
from mmaudit.models.schemas import CandidateReviewBatch, ExecutionEvidenceKind
from mmaudit.models.truncation import candidate_review_frame_wire_schema_sha256
from mmaudit.models.truncation_recovery import plan_truncation_recovery
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryRequestedSurfaceManifest,
    SchedulerTruncationRecoveryTerminalStatus,
)
from mmaudit.orchestration.truncation_tree_evidence import verify_truncation_recovery_full_tree
from mmaudit.orchestration.truncation_tree_promotion import (
    issue_promoted_full_tree_surface_coverage,
    promote_truncation_recovery_full_tree,
    require_promoted_full_tree_surface_coverage,
)
from tests.unit import test_truncation_tree_evidence as f
from tests.unit.test_truncation_recovery_journal import _resources


def test_interleaved_original_roots_replay_without_contiguous_ordinal_assumptions(
    tmp_path: Path,
) -> None:
    inventory = f._inventory(one_shard=True)
    journal = f.create_scheduler_journal(
        tmp_path / "interleaved",
        bindings=f._one_shard_bindings(),
        shard_inventory=inventory,
        privacy_evidence_custody=f._privacy_custody(source_sha256=inventory.source_tree_sha256),
    )
    try:
        f._complete_costed_orientation(journal)
        requests = f._requests(7)
        records = tuple(f._record(request) for request in requests)
        context = f._context(requests, source_count=7)
        manifest = SchedulerTruncationRecoveryRequestedSurfaceManifest.build(requests)
        planner = f.PipelineScheduler(journal)
        selection = journal.manifest.bindings.audit_model_selection
        assert selection is not None
        model = selection.selected_model_ids[0]
        tasks = tuple(
            planner.model_task(
                pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
                scope=SchedulerScope.single_shard(f.SHARDS[0]),
                task_key=f"interleaved-local-root-{index}",
                role="source_audit",
                requested_model=model,
                root_lineage=selection.route_for(model).root_lineage,
                system_prompt_sha256="a" * 64,
                response_schema_sha256=candidate_review_frame_wire_schema_sha256(),
                model_surface_review_request_manifest_sha256=manifest.requested_surface_manifest_sha256,
            )
            for index in range(2)
        )
        plan = planner.prepare_pass(SchedulerPassKind.BLIND_SHARD_REVIEW, tasks)
        parents: list[tuple[Any, Any, Any, Any, Any]] = []
        for task in plan.tasks:
            digest = hashlib.sha256(f.render_context(context).encode()).hexdigest()
            activation = journal.activate_task(
                task.task_id,
                actual_input_sha256=digest,
                system_prompt_sha256=task.system_prompt_sha256,
                user_prompt_sha256=digest,
                provider_prompt_sha256="2" * 64,
                response_schema_sha256=task.response_schema_sha256,
                delivered_source_descriptor_sha256s=f.scheduler_test_delivered_source_descriptor_sha256s(
                    plan, task
                ),
            )
            journal.mark_dispatched(task.task_id)
            projection = f._projection(records, retained_count=1)
            envelope, usage = f._typed_parent_truncation(
                journal=journal,
                task=task,
                activation=activation,
                context=context,
                projection=projection,
                full_batch=CandidateReviewBatch(findings=(), surface_reviews=records),
            )
            attempt = journal.persist_truncated_provider_attempt(
                task.task_id,
                usage,
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
            parents.append((task, activation, attempt, usage, projection))

        def exact_resources(parent_usage: Any) -> Any:
            prior = tuple(
                usage
                for usage in journal._retained_main_provider_usage_records()
                if usage.request_id != parent_usage.request_id
            )
            # Undispatched siblings remain reservations, not zero-cost omissions.
            costs = [Decimal(usage.accounted_cost_usd_exact or "0") for usage in prior]
            attempts = sum(usage.attempts for usage in prior)
            tokens = sum(usage.completion_tokens for usage in prior)
            for family in journal.truncation_recovery_families:
                for child in family.recovery_plan.children:
                    if child.child_logical_request_id == parent_usage.request_id:
                        continue
                    result = journal._truncation_recovery_indexes.results.get(child.child_task_id)
                    costs.append(
                        Decimal(
                            result.accounted_cost_usd_exact
                            if result is not None
                            else child.reserved_usd_exact
                        )
                    )
                    attempts += (
                        result.accounted_provider_attempts
                        if result is not None
                        else child.reserved_provider_attempts
                    )
                    tokens += (
                        result.accounted_completion_tokens
                        if result is not None
                        else child.reserved_completion_tokens
                    )
            return _resources(
                recovery_requests_consumed=sum(
                    len(family.recovery_plan.children)
                    for family in journal.truncation_recovery_families
                ),
                accounted_before=format(
                    sum(costs, Decimal("0")),
                    "f",
                ),
                attempts_before=attempts,
                tokens_before=tokens,
                parent_attempts=parent_usage.attempts,
                parent_tokens=parent_usage.completion_tokens,
                parent_cost=parent_usage.accounted_cost_usd_exact or "0",
            )

        roots = []
        for task, activation, attempt, usage, projection in parents:
            base = f._recovery_plan(
                journal=journal,
                pass_plan=plan,
                task=task,
                activation=activation,
                attempt=attempt,
                projection=projection,
                manifest=manifest,
                parent_usage=usage,
            )
            root_plan = plan_truncation_recovery(
                parent=base.parent, resources=exact_resources(usage)
            )
            roots.append(
                journal.open_truncation_recovery_family(
                    recovery_plan=root_plan,
                    truncation_projection=projection,
                    requested_surface_manifest=manifest,
                )
            )

        def finish(
            family: Any,
            parent_context: Any,
            root_usage: Any,
            usages: list[Any],
            contexts: list[Any],
        ) -> None:
            results = {}
            child_contexts = {}
            for child in family.recovery_plan.children:
                child_context = f.build_truncation_recovery_child_context(
                    parent_context=parent_context, child=child
                )
                child_contexts[child.child_task_id] = child_context
                digest = hashlib.sha256(f.render_context(child_context).encode()).hexdigest()
                activation = journal.activate_truncation_recovery_child(
                    child.child_task_id,
                    actual_input_sha256=digest,
                    system_prompt_sha256="a" * 64,
                    user_prompt_sha256=digest,
                    provider_prompt_sha256=hashlib.sha256(child.child_task_id.encode()).hexdigest(),
                    response_schema_sha256=candidate_review_frame_wire_schema_sha256(),
                )
                journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
                if child.depth == 1:
                    usage, envelope, projection = f._truncated_custody(
                        child=child, activation=activation, surfaces=records, retained_count=1
                    )
                    usage = f._bind_bridge_to_parent_invariant(
                        usage.model_copy(update={"execution_evidence": ExecutionEvidenceKind.REAL}),
                        journal=journal,
                        parent_usage=root_usage,
                    )
                    result = journal.record_truncation_recovery_child_truncated(
                        child.child_task_id,
                        failed_usage_record=usage,
                        truncated_envelope_evidence=envelope,
                        truncation_projection=projection,
                    )
                else:
                    usage, normalization, batch, child_requests, artifact = f._success_custody(
                        child=child,
                        activation=activation,
                        surface_manifest=manifest,
                        surfaces=records,
                        execution_evidence=ExecutionEvidenceKind.REAL,
                    )
                    usage = f._bind_child_to_parent_invariant(
                        usage, journal=journal, parent_usage=root_usage
                    )
                    result = journal.record_truncation_recovery_child_success(
                        child.child_task_id,
                        usage_record=usage,
                        normalization_evidence=normalization,
                        normalized_batch=batch,
                        requested_surface_requests=child_requests,
                        output_artifact=artifact,
                    )
                results[child.child_task_id] = result
                usages.append(usage)
                contexts.append(child_context)
            for child in family.recovery_plan.children:
                result = results[child.child_task_id]
                if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED:
                    base = f._nested_plan(journal, family, child, result)
                    nested_plan = plan_truncation_recovery(
                        parent=base.parent, resources=exact_resources(result.runtime_usage_record)
                    )
                    nested = journal.open_truncation_recovery_family(
                        recovery_plan=nested_plan,
                        truncation_projection=result.truncation_projection,
                        requested_surface_manifest=manifest,
                    )
                    finish(
                        nested, child_contexts[child.child_task_id], root_usage, usages, contexts
                    )
            journal.seal_truncation_recovery_family(family.family_id)

        tokens = []
        for root, (_task, _activation, _attempt, usage, _projection) in zip(
            roots, parents, strict=True
        ):
            usages: list[Any] = []
            contexts: list[Any] = []
            finish(root, context, usage, usages, contexts)
            source, artifact = verify_truncation_recovery_full_tree(
                journal=journal,
                root_family_id=root.family_id,
                parent_usage_record=usage,
                child_usage_records=tuple(usages),
                parent_context=context,
                child_contexts=tuple(contexts),
            )
            assert Decimal(artifact.accounting.other_accounted_cost_usd_exact) >= Decimal("0.05")
            private, _promotion = promote_truncation_recovery_full_tree(
                journal=journal, capability=source
            )
            tokens.append(issue_promoted_full_tree_surface_coverage(private))
        assert (
            journal.seal_pass_result(SchedulerPassKind.BLIND_SHARD_REVIEW).status
            is SchedulerPassStatus.COMPLETE
        )
        public = journal.artifact()
        assert len(public.recovery_model_requests) == 12
        ordinals_by_root = []
        for token in tokens:
            projection = require_promoted_full_tree_surface_coverage(token)
            requests_for_root = tuple(
                request
                for request in public.recovery_model_requests
                if request.promotion_entry_sha256 == projection.promotion_entry_sha256
            )
            assert projection.matches_requests(requests_for_root)
            ordinals = sorted(request.global_request_ordinal for request in requests_for_root)
            assert ordinals != list(range(ordinals[0], ordinals[0] + len(ordinals)))
            ordinals_by_root.append(set(ordinals))
        assert not ordinals_by_root[0] & ordinals_by_root[1]
        assert ordinals_by_root[0] | ordinals_by_root[1] == set(range(1, 13))
    finally:
        journal.close()
