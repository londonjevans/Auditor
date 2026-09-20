"""Synthetic seven-pass recovery acceptance; never evidence of a real provider audit."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mmaudit.agents.specialists import build_specialist_execution_records
from mmaudit.config import AuditConfig
from mmaudit.constants import SPECIALIST_INVESTIGATOR_ROLES
from mmaudit.models.candidate_review_stamping import stamp_candidate_review_findings
from mmaudit.models.registry import ModelRegistry
from mmaudit.models.scheduler import (
    SchedulerCandidateWorkset,
    SchedulerPassKind,
    SchedulerPassPlan,
    SchedulerPassStatus,
    SchedulerTaskKind,
    SchedulerTaskPlan,
    SchedulerTaskResult,
    SchedulerTerminalStatus,
    scheduler_role_requires_specialist_accepted_outcome,
)
from mmaudit.models.schemas import (
    CandidateReviewBatch,
    ExecutionEvidenceKind,
    UsageRecord,
)
from mmaudit.models.truncation import (
    candidate_review_frame_wire_schema_sha256,
    frame_candidate_review_batch,
    normalize_candidate_review_document,
)
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryRequestedSurfaceManifest,
    SchedulerTruncationRecoveryTerminalStatus,
)
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.model_coverage import (
    build_model_review_coverage,
    build_model_review_pre_dispatch_authorizations,
)
from mmaudit.orchestration.truncation_recovery_evidence import (
    build_truncation_recovery_child_context,
)
from mmaudit.orchestration.truncation_tree_evidence import verify_truncation_recovery_full_tree
from mmaudit.orchestration.truncation_tree_promotion import (
    issue_promoted_full_tree_surface_coverage,
    promote_truncation_recovery_full_tree,
    require_promoted_full_tree_surface_coverage,
)
from tests import scheduler_support as scheduler
from tests.truncation_tree_manifest_support import (
    ReviewPrivacyFixture,
    ReviewSourceFixture,
    build_review_privacy_fixture,
    build_review_source_fixture,
    file_review_record,
    review_artifact_for_batch,
)
from tests.truncation_tree_request_support import (
    CONFIGURED_RUN_TOKEN_CAPACITY,
    configured_child_resource_limits,
)
from tests.truncation_tree_run_support import OriginalRunAccounting
from tests.unit import test_assurance as assurance
from tests.unit import test_model_coverage as surfaces
from tests.unit.test_generic_truncation_tree import _nested_plan
from tests.unit.test_truncation_recovery_journal import _specialist_success_outcome


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass(frozen=True)
class CompleteTreeAssuranceFixture:
    """Own one disposable journal and every original usage used by its consumers."""

    journal: Any
    runtime: Any
    coverage_arguments: dict[str, Any]
    capability: Any
    projection: Any
    authorities: Any
    source: ReviewSourceFixture
    privacy: ReviewPrivacyFixture
    candidate_report: Any = None
    run_accounting: OriginalRunAccounting | None = None

    def close(self) -> None:
        self.journal.close()


def _surface_task(
    task: SchedulerTaskPlan, manifest: Any, surface_manifest: Any, *, framed: bool = True
) -> SchedulerTaskPlan:
    return SchedulerTaskPlan.build(
        manifest=manifest,
        pass_kind=task.pass_kind,
        scope=task.scope,
        task_kind=task.task_kind,
        task_key=task.task_key,
        role=task.role,
        input_sha256=task.input_sha256,
        prompt_sha256=task.prompt_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        normalizer_sha256=task.normalizer_sha256,
        requested_model=task.requested_model,
        root_lineage=task.root_lineage,
        candidate_ids=task.candidate_ids,
        response_schema_sha256=(
            candidate_review_frame_wire_schema_sha256() if framed else task.response_schema_sha256
        ),
        model_surface_review_request_manifest_sha256=(
            surface_manifest.requested_surface_manifest_sha256
        ),
    )


def _record_original_truncation(
    journal: Any,
    plan: Any,
    task: Any,
    activation: Any,
    context: Any,
    records: Any,
    authorities: Any,
    findings: tuple[Any, ...] = (),
    accounting: OriginalRunAccounting | None = None,
) -> tuple[Any, Any, Any]:
    """Record the terminal main attempt before any recovery family is admitted."""

    projection = surfaces._promoted_truncation_projection(
        records, retained_count=1, findings=findings
    )
    envelope, parent = surfaces._promoted_parent_truncation(
        journal=journal,
        task=task,
        activation=activation,
        context=context,
        projection=projection,
        full_batch=CandidateReviewBatch(findings=findings, surface_reviews=records),
        include_scheduler_test_refresh_pricing=False,
    )
    parent = assurance._bind_promoted_assurance_usage(parent, authorities)
    if accounting is not None:
        parent = accounting.prepare(parent, authorities.refresh_runtime, context=context)
        accounting.dispatch(journal, task.task_id, parent)
        accounting.finish(parent)
    attempt = journal.persist_truncated_provider_attempt(
        task.task_id,
        parent,
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
    return parent, attempt, projection


def _recover_original_tree(
    journal: Any,
    plan: Any,
    task: Any,
    activation: Any,
    context: Any,
    requests: Any,
    records: Any,
    authorities: Any,
    recorded_parent: tuple[Any, Any, Any],
    findings: tuple[Any, ...] = (),
    accounting: OriginalRunAccounting | None = None,
) -> tuple[Any, list[UsageRecord], dict[str, list[Any]]]:
    """Mirror pipeline quiescence before reserving and recovering either branch."""

    def transform(usage: UsageRecord) -> UsageRecord:
        return assurance._bind_promoted_assurance_usage(usage, authorities)

    parent, attempt, projection = recorded_parent
    assert {task.task_id for task in plan.tasks} <= {
        result.task_id for result in journal.task_results
    }
    manifest = SchedulerTruncationRecoveryRequestedSurfaceManifest.build(requests)
    recovery_plan = surfaces._promoted_recovery_plan(
        journal=journal,
        pass_plan=plan,
        task=task,
        activation=activation,
        attempt=attempt,
        projection=projection,
        manifest=manifest,
        parent_usage=parent,
        child_resource_limits=(
            configured_child_resource_limits(authorities.refresh_runtime)
            if accounting is not None and accounting.configured_requests
            else None
        ),
    )
    root = journal.open_truncation_recovery_family(
        recovery_plan=recovery_plan,
        truncation_projection=projection,
        requested_surface_manifest=manifest,
    )
    usages: list[UsageRecord] = []
    contexts: list[Any] = []

    def finish(family: Any, parent_context: Any) -> None:
        results: dict[str, Any] = {}
        child_contexts: dict[str, Any] = {}
        for child in family.recovery_plan.children:
            child_context = build_truncation_recovery_child_context(
                parent_context=parent_context, child=child
            )
            child_contexts[child.child_task_id] = child_context
            digest = _sha(render_context(child_context))
            child_activation = journal.activate_truncation_recovery_child(
                child.child_task_id,
                actual_input_sha256=digest,
                system_prompt_sha256=task.system_prompt_sha256,
                user_prompt_sha256=digest,
                provider_prompt_sha256=_sha(child.child_task_id),
                response_schema_sha256=task.response_schema_sha256,
            )
            if accounting is None:
                journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
            if child.path in {"0", "1"}:
                usage, child_envelope, child_projection = surfaces._promoted_bridge_truncation(
                    journal=journal,
                    child=child,
                    activation=child_activation,
                    context=child_context,
                    surface_manifest=manifest,
                    records=records,
                    parent_usage=parent,
                    parent_role=task.role,
                    parent_model_id=task.requested_model,
                    include_scheduler_test_refresh_pricing=False,
                    transform=transform,
                    retained_count=1,
                    findings=findings,
                )
                if accounting is not None:
                    usage = accounting.prepare(
                        usage,
                        authorities.refresh_runtime,
                        recovery_activation=child_activation,
                        context=child_context,
                    )
                    accounting.dispatch(journal, child.child_task_id, usage, recovery=True)
                    accounting.finish(usage)
                result = journal.record_truncation_recovery_child_truncated(
                    child.child_task_id,
                    failed_usage_record=usage,
                    truncated_envelope_evidence=child_envelope,
                    truncation_projection=child_projection,
                )
            else:
                usage, normalization, batch, child_requests, artifact = (
                    surfaces._promoted_child_success_custody(
                        child=child,
                        activation=child_activation,
                        surface_manifest=manifest,
                        surfaces=records,
                        execution_evidence=ExecutionEvidenceKind.REAL,
                        request_role=task.role,
                        exact_model_id=task.requested_model,
                        findings=findings,
                    )
                )
                routing = dict(usage.routing)
                for key in surfaces._INVARIANT_ROUTING_KEYS:
                    routing.pop(key, None)
                    if key in parent.routing:
                        routing[key] = parent.routing[key]
                usage = usage.model_copy(update={"routing": routing})
                usage = surfaces._with_context_request_evidence(
                    usage, child_context, request_role=task.role
                )
                usage = transform(usage)
                if accounting is not None:
                    usage = accounting.prepare(
                        usage,
                        authorities.refresh_runtime,
                        recovery_activation=child_activation,
                        context=child_context,
                    )
                    accounting.dispatch(journal, child.child_task_id, usage, recovery=True)
                    accounting.finish(usage)
                result = journal.record_truncation_recovery_child_success(
                    child.child_task_id,
                    usage_record=usage,
                    normalization_evidence=normalization,
                    normalized_batch=batch,
                    requested_surface_requests=child_requests,
                    output_artifact=artifact,
                    specialist_accepted_outcome=(
                        _specialist_success_outcome(
                            usage=usage, requests=child_requests, artifact=artifact
                        )
                        if scheduler_role_requires_specialist_accepted_outcome(task.role)
                        else None
                    ),
                )
            usages.append(usage)
            contexts.append(child_context)
            results[child.child_task_id] = result
        for child in family.recovery_plan.children:
            result = results[child.child_task_id]
            if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED:
                nested = journal.open_truncation_recovery_family(
                    recovery_plan=_nested_plan(journal, family, child, result),
                    truncation_projection=result.truncation_projection,
                    requested_surface_manifest=manifest,
                )
                finish(nested, child_contexts[child.child_task_id])
        journal.seal_truncation_recovery_family(family.family_id)

    finish(root, context)
    source, _ = verify_truncation_recovery_full_tree(
        journal=journal,
        root_family_id=root.family_id,
        parent_usage_record=parent,
        child_usage_records=tuple(usages),
        parent_context=context,
        child_contexts=tuple(contexts),
    )
    private, _ = promote_truncation_recovery_full_tree(journal=journal, capability=source)
    capability = issue_promoted_full_tree_surface_coverage(private)
    return (
        capability,
        [parent, *usages],
        {parent.request_id: [context]}
        | {usage.request_id: [ctx] for usage, ctx in zip(usages, contexts, strict=True)},
    )


def build_complete_tree_assurance_fixture(
    config: AuditConfig,
    root: Path,
    *,
    candidate_report: bool = False,
    run_manifest: bool = False,
    configured_requests: bool = False,
    recovery_role: str = "source_audit",
) -> CompleteTreeAssuranceFixture:
    """Build a full original campaign with synthetic authorities and two truncated branches."""

    if recovery_role not in {"source_audit"} | {
        f"specialist:{role}" for role in SPECIALIST_INVESTIGATOR_ROLES
    }:
        raise ValueError("synthetic recovery role must be an exact known investigator")
    surface_roles = {"source_audit", "business_logic", "configuration", recovery_role}
    source = build_review_source_fixture()
    assert root.name == "scheduler-journal" and root.parent.name == "private"
    if run_manifest and not candidate_report:
        raise ValueError("full run manifest fixture requires original candidate/report custody")
    if configured_requests and not run_manifest:
        raise ValueError("configured requests require original run accounting and invocation")
    accounting = (
        OriginalRunAccounting(
            root.parent.parent.with_name(root.parent.parent.name + "-cost"),
            configured_requests=configured_requests,
        )
        if run_manifest
        else None
    )
    now = datetime.now(UTC).replace(microsecond=0)
    privacy = build_review_privacy_fixture(config, source, root.parent.parent, now=now)
    report_state = None
    if candidate_report:
        from tests.truncation_tree_report_support import TreeCandidateReportState

        report_state = TreeCandidateReportState(
            config, source, privacy, include_invocation=run_manifest
        )
    authorities = assurance._assurance_policy_selection(
        config,
        now,
        source_inventory=source.scheduler_shards,
        token_capacity=CONFIGURED_RUN_TOKEN_CAPACITY if configured_requests else None,
    )
    if candidate_report:
        configured = ModelRegistry.validate_production_qualification(
            config, authorities.qualification, now=now
        )
        assert configured.valid, configured.errors
    base = assurance.AssuranceRuntime(
        index=source.index,
        graphs=source.graphs,
        invariants=source.invariants,
        production_qualification=authorities.qualification,
        audit_model_selection_evidence=authorities.evidence_bundle,
        verified_audit_model_selection=authorities.capability,
        audit_model_refresh_evidence=authorities.refresh_runtime.evidence,
        audit_model_refresh_guard=authorities.refresh_runtime.guard,
        audit_model_refresh_pricing_evidence=authorities.refresh_runtime.pricing_evidence,
        audit_model_refresh_pricing_authority=authorities.refresh_runtime.pricing_authority,
        provider_session=assurance._issue_provider_session_provenance(
            execution_evidence=ExecutionEvidenceKind.REAL,
            pipeline_owned=True,
            trusted_concrete_client=True,
            usage_evidence_consistent=True,
        ),
    )
    template = assurance._complete_assurance_scheduler_fixture(
        config,
        authorities.qualification,
        authorities.evidence_bundle,
        authorities.refresh_runtime,
        authorities.refresh_runtime.verified_at,
        source_inventory=source.scheduler_shards,
        analysis_input_inventory=source.analysis_inputs,
        privacy_evidence_custody=privacy.custody,
        candidate_falsifier_models=(
            ("specialist-0/model-0", "specialist-1/model-1") if candidate_report else None
        ),
        original_cost_baseline=accounting.baseline if accounting is not None else None,
    )
    manifest = template.manifest
    # Provision the standard disposable run/private parent before the unchanged
    # journal factory enforces physical, unlinked parent-directory custody.
    root.parent.mkdir(mode=0o700, exist_ok=True)
    journal = assurance.create_scheduler_journal(
        root,
        bindings=manifest.bindings,
        analysis_input_inventory=source.analysis_inputs,
        shard_inventory=manifest.shard_inventory,
        cost_ledger_baseline=manifest.cost_ledger_baseline,
        privacy_evidence_custody=manifest.privacy_evidence_custody,
        audit_model_refresh_evidence=base.audit_model_refresh_evidence,
        audit_model_refresh_guard=base.audit_model_refresh_guard,
        audit_model_refresh_pricing_evidence=base.audit_model_refresh_pricing_evidence,
        audit_model_refresh_pricing_authority=base.audit_model_refresh_pricing_authority,
        production_qualification=base.production_qualification,
        audit_model_selection=base.verified_audit_model_selection,
    )
    try:
        index, graphs, invariants, suite, requests = (
            source.index,
            source.graphs,
            source.invariants,
            source.suite,
            source.rich_requests,
        )
        surface_manifest = SchedulerTruncationRecoveryRequestedSurfaceManifest.build(requests)
        file_manifest = SchedulerTruncationRecoveryRequestedSurfaceManifest.build(
            source.file_requests
        )
        usages: list[UsageRecord] = []
        artifacts: list[Any] = []
        contexts: dict[str, list[Any]] = {}
        if report_state is not None:
            report_state.contexts = contexts
        capability = None
        for original_plan in template.plans:
            kind = original_plan.pass_kind
            pending_recovery: tuple[Any, ...] | None = None
            workset = None
            if original_plan.candidate_workset is not None:
                source_pass = next(
                    item
                    for item in journal.pass_results
                    if item.plan.pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
                )
                source_task = next(
                    task
                    for task in source_pass.plan.tasks
                    if task.role == "host:cross_shard_integrator"
                )
                source_result = next(
                    result
                    for result in source_pass.task_results
                    if result.task_id == source_task.task_id
                )
                source_output = next(
                    output for output in journal.outputs if output.task_id == source_task.task_id
                )
                workset = SchedulerCandidateWorkset.build(
                    pass_kind=kind,
                    source_pass_result=source_pass,
                    source_result=source_result,
                    source_output=source_output,
                )
            tasks = tuple(
                _surface_task(
                    task,
                    manifest,
                    surface_manifest if task.role in surface_roles else file_manifest,
                    framed=task.role in surface_roles,
                )
                if kind is SchedulerPassKind.BLIND_SHARD_REVIEW
                else task
                for task in original_plan.tasks
            )
            if report_state is not None:
                tasks = report_state.tasks(journal, original_plan, tasks, workset)
            plan = journal.seal_pass_plan(
                SchedulerPassPlan.build(
                    manifest=manifest,
                    pass_kind=kind,
                    dependencies=journal.next_dependencies,
                    tasks=tasks,
                    candidate_workset=workset,
                )
            )
            # Original host inputs must follow the model outputs they consume.
            ordered_tasks = (
                sorted(
                    plan.tasks,
                    key=lambda task: task.task_kind is SchedulerTaskKind.HOST_COMPUTATION,
                )
                if report_state is not None
                else plan.tasks
            )
            for task in ordered_tasks:
                is_surface = (
                    kind is SchedulerPassKind.BLIND_SHARD_REVIEW and task.role in surface_roles
                )
                context = None
                records: tuple[Any, ...] = ()
                model = task.task_kind is SchedulerTaskKind.MODEL_REQUEST
                is_review = kind is SchedulerPassKind.BLIND_SHARD_REVIEW and model
                review_requests = (
                    requests if is_surface else source.file_requests if is_review else ()
                )
                if model:
                    context = surfaces._promoted_surface_context(
                        review_requests,
                        surfaces._usage(task.role, task.requested_model, "full-assurance-context"),
                        index,
                        graphs,
                    )
                    context = surfaces._with_exact_context_bytes(
                        context.model_copy(
                            update={"role": scheduler._context_role_for_request(task.role)}
                        )
                    )
                    records = tuple(
                        surfaces._record(r, task.role, index, graphs)
                        if is_surface
                        else file_review_record(r, task.role)
                        for r in review_requests
                    )
                host_payload = None
                if not model and report_state is not None:
                    host_payload, host_input = report_state.host_payload(journal, plan, task)
                actual = (
                    _sha(render_context(context))
                    if context is not None
                    else _sha(task.task_id)
                    if model
                    else host_input
                    if report_state is not None
                    else scheduler.scheduler_test_host_activation_input_sha256(
                        plan, task, candidate_ids=("candidate-critical",)
                    )
                )
                activation = journal.activate_task(
                    task.task_id,
                    actual_input_sha256=actual,
                    delivered_source_descriptor_sha256s=(
                        scheduler.scheduler_test_delivered_source_descriptor_sha256s(plan, task)
                    ),
                    **(
                        dict(
                            system_prompt_sha256=task.system_prompt_sha256,
                            user_prompt_sha256=actual,
                            provider_prompt_sha256=_sha("provider:" + task.task_id),
                            response_schema_sha256=task.response_schema_sha256,
                        )
                        if model
                        else {}
                    ),
                )
                if accounting is None or not model:
                    journal.mark_dispatched(task.task_id)
                if is_surface and task.role == recovery_role:
                    recorded_parent = _record_original_truncation(
                        journal,
                        plan,
                        task,
                        activation,
                        context,
                        records,
                        authorities,
                        report_state.raw_findings if report_state is not None else (),
                        accounting,
                    )
                    assert pending_recovery is None
                    pending_recovery = (
                        journal,
                        plan,
                        task,
                        activation,
                        context,
                        requests,
                        records,
                        authorities,
                        recorded_parent,
                        report_state.raw_findings if report_state is not None else (),
                        accounting,
                    )
                    usages.append(recorded_parent[0])
                    contexts[recorded_parent[0].request_id] = [context]
                    continue
                usage = None
                surface_artifact = None
                normalization = None
                requested: tuple[Any, ...] = ()
                if model:
                    payload = (
                        CandidateReviewBatch(
                            findings=(
                                report_state.raw_findings
                                if report_state is not None and is_surface
                                else ()
                            ),
                            surface_reviews=records,
                        )
                        if is_review
                        else scheduler.build_scheduler_test_model_payload(plan, task)
                    )
                    requested = review_requests
                    wire_payload = payload
                    if is_surface:
                        wire_payload = frame_candidate_review_batch(payload)
                        normalized, normalization = normalize_candidate_review_document(
                            wire_payload, request_id=task.logical_request_id
                        )
                        assert normalized == payload
                    usage = scheduler.build_scheduler_test_real_usage(
                        task,
                        activation,
                        seed="full-tree-assurance",
                        validated_output=wire_payload,
                        privacy_evidence_custody=manifest.privacy_evidence_custody,
                        audit_model_selection=manifest.bindings.audit_model_selection,
                        audit_model_refresh=manifest.bindings.audit_model_refresh,
                        audit_model_refresh_pricing=manifest.bindings.audit_model_refresh_pricing,
                        include_audit_model_refresh_pricing=False,
                        model_surface_review_requests=requested,
                    )
                    if context is not None:
                        usage = surfaces._with_context_request_evidence(
                            usage, context, request_role=task.role
                        )
                    usage = assurance._bind_promoted_assurance_usage(usage, authorities)
                    if accounting is not None:
                        usage = accounting.prepare(
                            usage, authorities.refresh_runtime, context=context
                        )
                        accounting.dispatch(journal, task.task_id, usage)
                        accounting.finish(usage)
                    usages.append(usage)
                    assert context is not None
                    contexts[usage.request_id] = [context]
                    if is_review:
                        assert isinstance(payload, CandidateReviewBatch)
                        surface_artifact = review_artifact_for_batch(
                            requests=review_requests,
                            usage=usage,
                            context=context,
                            batch=payload,
                            normalization=normalization,
                        )
                    else:
                        requested, surface_artifact = (
                            scheduler.build_scheduler_test_model_surface_review_custody(
                                plan, task, activation, usage, payload
                            )
                        )
                    if surface_artifact is not None:
                        artifacts.append(surface_artifact)
                else:
                    payload = (
                        host_payload
                        if report_state is not None
                        else scheduler.build_scheduler_test_host_payload(
                            plan, task, candidate_ids=("candidate-critical",)
                        )
                    )
                output = journal.persist_output(
                    task.task_id,
                    payload,
                    usage_record=usage,
                    accepted_candidates=(
                        stamp_candidate_review_findings(
                            request_role=task.role,
                            usage_record=usage,
                            trusted_scanner_fingerprints=(),
                            raw_findings=payload.findings,
                        )
                        if report_state is not None
                        and isinstance(payload, CandidateReviewBatch)
                        and usage is not None
                        else ()
                    ),
                    specialist_accepted_outcome=scheduler._scheduler_test_specialist_outcome(
                        task, usage, payload, surface_artifact
                    ),
                    model_surface_review_requests=requested,
                    model_surface_review_artifact=surface_artifact,
                    normalization_evidence=normalization,
                )
                journal.record_terminal(
                    SchedulerTaskResult.build(
                        plan=plan,
                        task=task,
                        activation=activation,
                        terminal_status=SchedulerTerminalStatus.SUCCEEDED,
                        terminal_evidence_sha256=(
                            usage.validated_response_sha256 if usage else _sha(task.task_id)
                        ),
                        output=output,
                    )
                )
            if pending_recovery is not None:
                capability, tree_usages, tree_contexts = _recover_original_tree(*pending_recovery)
                usages.extend(tree_usages[1:])
                contexts.update(tree_contexts)
                projection = require_promoted_full_tree_surface_coverage(capability)
                artifacts.extend(child.surface_artifact for child in projection.artifact.children)
            assert journal.seal_pass_result(kind).status is SchedulerPassStatus.COMPLETE
        assert capability is not None
        public = journal.artifact()
        projection = require_promoted_full_tree_surface_coverage(capability)
        arguments = dict(
            usage_records=usages,
            review_artifacts=artifacts,
            review_contexts_by_request=contexts,
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            minimum_critical_root_lineages=3,
            audited_suite_coverage=suite,
            source_contents_by_path=source.sources,
            recovery_usage_coordinates=tuple(
                (r.logical_request_id, r.request_limit_scope, r.request_limit_count_before)
                for r in public.recovery_model_requests
                if r.output_artifact_sha256 is not None
            ),
            promoted_recursive_recovery_surface_coverages=(capability,),
            ordinary_review_authorizations=build_model_review_pre_dispatch_authorizations(journal),
        )
        coverage = build_model_review_coverage(config, **arguments)
        original_outcomes = tuple(
            output.specialist_accepted_outcome
            for output in journal.outputs
            if output.specialist_accepted_outcome is not None
        )
        if recovery_role != "source_audit":
            original_outcomes += tuple(
                result.runtime_specialist_accepted_outcome
                for result in journal.truncation_recovery_entries
                if isinstance(result, SchedulerTruncationRecoveryChildResult)
                and result.runtime_specialist_accepted_outcome is not None
            )
            # Mirror the host's verified recursive aggregate exclusion only in its role report.
            # The runtime usage inventory below still retains every original failed liability.
            aggregate_ids = {
                projection.parent_usage_record.request_id,
                *(usage.request_id for usage in projection.bridge_usage_records),
            }
            specialist_records = build_specialist_execution_records(
                config,
                usage_records=[usage for usage in usages if usage.request_id not in aggregate_ids],
                contexts=[context for values in contexts.values() for context in values],
                accepted_outcomes=original_outcomes,
                structurally_successful_request_ids={
                    usage.request_id
                    for usage in journal.structurally_successful_review_usage_records
                    if usage.request_id not in aggregate_ids
                },
                recovery_usage_coordinates=arguments["recovery_usage_coordinates"],
            )
        else:
            specialist_records = assurance._complete_specialist_execution_records(
                usages, original_outcomes
            )
        runtime = replace(
            base,
            scheduler_artifact=public,
            expected_scheduler_bindings=manifest.bindings,
            expected_scheduler_analysis_input_sha256=manifest.bindings.analysis_input_sha256,
            expected_scheduler_shard_inventory=manifest.shard_inventory,
            expected_scheduler_cost_ledger_baseline=manifest.cost_ledger_baseline,
            model_usage=usages,
            model_surface_review_artifacts=artifacts,
            model_review_coverage=coverage,
            promoted_recursive_recovery_surface_coverages=[capability],
            specialist_execution_records=specialist_records,
        )
        return CompleteTreeAssuranceFixture(
            journal,
            runtime,
            arguments,
            capability,
            projection,
            authorities,
            source,
            privacy,
            report_state,
            accounting,
        )
    except BaseException:
        journal.close()
        raise
