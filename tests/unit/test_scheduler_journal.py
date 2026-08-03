from __future__ import annotations

import hashlib
import json
import shutil
import stat
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

import mmaudit.orchestration.scheduler as scheduler_module
from mmaudit.models.openrouter import (
    DeliveredSourceDescriptor,
    ModelRequestPrivacyBinding,
    OpenRouterSchemaError,
)
from mmaudit.models.scheduler import (
    SCHEDULER_ANALYSIS_INPUT_LABELS,
    SCHEDULER_PASS_ORDER,
    SchedulerAbsenceReason,
    SchedulerAnalysisInputDescriptor,
    SchedulerAnalysisInputInventory,
    SchedulerBindings,
    SchedulerCampaignStatus,
    SchedulerCandidateWorkset,
    SchedulerConditionalAbsence,
    SchedulerJournalEvidence,
    SchedulerPassKind,
    SchedulerPassPlan,
    SchedulerPassResult,
    SchedulerPassStatus,
    SchedulerPrivacyEvidenceCustody,
    SchedulerScope,
    SchedulerShardDescriptor,
    SchedulerShardInventory,
    SchedulerSourceDescriptor,
    SchedulerTaskActivation,
    SchedulerTaskEventKind,
    SchedulerTaskKind,
    SchedulerTaskOutput,
    SchedulerTaskPlan,
    SchedulerTaskResult,
    SchedulerTerminalStatus,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    Severity,
    ThreatModel,
    UsageRecord,
)
from mmaudit.models.usage import (
    is_accountable_usage_record,
    is_creditable_usage_record,
    is_structurally_accountable_usage_record,
)
from mmaudit.orchestration.budgets import (
    BudgetExhaustedError,
    BudgetManager,
    BudgetReservationStateError,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.scheduler import (
    SchedulerJournal,
)
from mmaudit.orchestration.scheduler import (
    create_scheduler_journal as _create_scheduler_journal,
)
from mmaudit.orchestration.scheduler import (
    open_scheduler_journal_for_verification as _open_scheduler_journal_for_verification,
)
from mmaudit.orchestration.scheduler import (
    resume_scheduler_journal as _resume_scheduler_journal,
)
from mmaudit.orchestration.scheduler_runtime import (
    PipelineScheduler,
    build_scheduler_cost_ledger_baseline,
    scheduler_response_schema_registry,
)
from mmaudit.release_io import write_json_evidence
from tests.identity_fixtures import reattest_synthetic_real_usage
from tests.scheduler_support import (
    build_scheduler_test_host_payload,
    build_scheduler_test_model_payload,
    build_scheduler_test_model_surface_review_custody,
    build_scheduler_test_real_usage,
    build_scheduler_test_usage,
    scheduler_test_delivered_source_descriptor_sha256s,
    scheduler_test_host_activation_input_sha256,
    scheduler_test_model_fields,
    scheduler_test_response_schema_sha256,
)

SHARDS = (
    "shard-" + "1" * 24,
    "shard-" + "2" * 24,
)


_MODEL_ROLES = {
    SchedulerPassKind.ORIENTATION: "threat_model",
    SchedulerPassKind.BLIND_SHARD_REVIEW: "source_audit",
    SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION: "adversarial_reviewer",
    SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION: "falsifier",
}

_HOST_ROLES = {
    SchedulerPassKind.FINDING_REDUCTION: "host:finding_reducer",
    SchedulerPassKind.CROSS_SHARD_INTEGRATION: "host:cross_shard_integrator",
    SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT: "host:evidence_cap_judgment",
}


def _privacy_custody(
    *,
    source_sha256: str | None = None,
) -> SchedulerPrivacyEvidenceCustody:
    return SchedulerPrivacyEvidenceCustody.build(
        source_sha256=source_sha256 or _inventory().source_tree_sha256,
        source_provenance_size=128,
        source_provenance_artifact_sha256="a" * 64,
        source_provenance_evidence_sha256="b" * 64,
        effective_policy_size=256,
        effective_policy_artifact_sha256="c" * 64,
        effective_policy_evidence_sha256="d" * 64,
        policy_source_provenance_sha256="b" * 64,
    )


def _inventory(*, one_shard: bool = False) -> SchedulerShardInventory:
    shards = tuple(
        SchedulerShardDescriptor.semantic(
            shard_id=shard_id,
            semantic_shard_sha256=f"{index + 1:x}" * 64,
            sources=(
                SchedulerSourceDescriptor.build(
                    path=f"src/Fixture{index}.sol",
                    sha256=f"{index + 3:x}" * 64,
                    size=100 + index,
                ),
            ),
        )
        for index, shard_id in enumerate(SHARDS[: 1 if one_shard else len(SHARDS)])
    )
    return SchedulerShardInventory.build(
        semantic_inventory_sha256="a" * 64,
        shards=shards,
    )


def _analysis_inventory(*, changed_label: str | None = None) -> SchedulerAnalysisInputInventory:
    return SchedulerAnalysisInputInventory.build(
        SchedulerAnalysisInputDescriptor.build(
            label=label,
            type_name="SyntheticProjection",
            value={"label": label, "changed": label == changed_label},
        )
        for label in SCHEDULER_ANALYSIS_INPUT_LABELS
    )


def _bindings(
    *,
    changed: str | None = None,
    cost_ledger_baseline_sha256: str | None = None,
) -> SchedulerBindings:
    inventory = _inventory()
    values = {
        "source_sha256": inventory.source_tree_sha256,
        "analysis_input_sha256": _analysis_inventory().analysis_input_sha256,
        "effective_config_sha256": "2" * 64,
        "shard_inventory_sha256": inventory.inventory_sha256,
        "model_selection_sha256": "4" * 64,
        "qualification_sha256": "5" * 64,
        "prompt_set_sha256": "6" * 64,
        "schema_set_sha256": "7" * 64,
        "tool_policy_sha256": "8" * 64,
        "privacy_evidence_custody_sha256": _privacy_custody(
            source_sha256=inventory.source_tree_sha256
        ).custody_sha256,
    }
    if changed is not None:
        values[changed] = "f" * 64
    if cost_ledger_baseline_sha256 is not None:
        values["cost_ledger_baseline_sha256"] = cost_ledger_baseline_sha256
    return SchedulerBindings.build(**values)


def _bindings_without_privacy_custody() -> SchedulerBindings:
    bindings = _bindings()
    return SchedulerBindings.build(
        source_sha256=bindings.source_sha256,
        analysis_input_sha256=bindings.analysis_input_sha256,
        effective_config_sha256=bindings.effective_config_sha256,
        shard_inventory_sha256=bindings.shard_inventory_sha256,
        model_selection_sha256=bindings.model_selection_sha256,
        qualification_sha256=bindings.qualification_sha256,
        prompt_set_sha256=bindings.prompt_set_sha256,
        schema_set_sha256=bindings.schema_set_sha256,
        tool_policy_sha256=bindings.tool_policy_sha256,
        cost_ledger_baseline_sha256=bindings.cost_ledger_baseline_sha256,
    )


def create_scheduler_journal(
    path: Path,
    *,
    bindings: SchedulerBindings,
    shard_inventory: SchedulerShardInventory,
    **kwargs: Any,
) -> SchedulerJournal:
    kwargs.setdefault("privacy_evidence_custody", _privacy_custody())
    return _create_scheduler_journal(
        path,
        bindings=bindings,
        analysis_input_inventory=_analysis_inventory(),
        shard_inventory=shard_inventory,
        **kwargs,
    )


def resume_scheduler_journal(
    path: Path,
    *,
    expected_bindings: SchedulerBindings,
    expected_shard_inventory: SchedulerShardInventory,
    **kwargs: Any,
) -> SchedulerJournal:
    return _resume_scheduler_journal(
        path,
        expected_bindings=expected_bindings,
        expected_analysis_input_inventory=_analysis_inventory(),
        expected_shard_inventory=expected_shard_inventory,
        **kwargs,
    )


def open_scheduler_journal_for_verification(
    path: Path,
    *,
    expected_bindings: SchedulerBindings,
    expected_shard_inventory: SchedulerShardInventory,
    **kwargs: Any,
) -> SchedulerJournal:
    kwargs.setdefault("expected_privacy_evidence_custody", _privacy_custody())
    return _open_scheduler_journal_for_verification(
        path,
        expected_bindings=expected_bindings,
        expected_analysis_input_inventory=_analysis_inventory(),
        expected_shard_inventory=expected_shard_inventory,
        **kwargs,
    )


def _task(
    journal: SchedulerJournal,
    pass_kind: SchedulerPassKind,
    *,
    key: str = "task-0",
    task_kind: SchedulerTaskKind | None = None,
    shard_id: str | None = None,
    role: str | None = None,
    candidate_ids: tuple[str, ...] = (),
) -> SchedulerTaskPlan:
    resolved_kind = task_kind or (
        SchedulerTaskKind.MODEL_REQUEST
        if pass_kind in _MODEL_ROLES
        else SchedulerTaskKind.HOST_COMPUTATION
    )
    if resolved_kind is SchedulerTaskKind.EMPTY_COMPLETION:
        resolved_role = "host:conditional_absence"
    elif resolved_kind is SchedulerTaskKind.MODEL_REQUEST:
        resolved_role = role or _MODEL_ROLES[pass_kind]
    else:
        resolved_role = role or _HOST_ROLES.get(pass_kind, "host:computation")
    return SchedulerTaskPlan.build(
        manifest=journal.manifest,
        pass_kind=pass_kind,
        scope=(
            SchedulerScope.single_shard(shard_id)
            if shard_id is not None
            else SchedulerScope.global_scope()
        ),
        task_kind=resolved_kind,
        task_key=key,
        role=resolved_role,
        requested_model=(
            "synthetic/auditor-v1" if resolved_kind is SchedulerTaskKind.MODEL_REQUEST else None
        ),
        root_lineage=(
            "sha256:" + hashlib.sha256(key.encode()).hexdigest()
            if resolved_kind is SchedulerTaskKind.MODEL_REQUEST
            else None
        ),
        candidate_ids=candidate_ids,
        input_sha256="9" * 64,
        prompt_sha256="a" * 64,
        response_schema_sha256=(
            scheduler_test_response_schema_sha256(pass_kind, resolved_role)
            if resolved_kind is SchedulerTaskKind.MODEL_REQUEST
            else "b" * 64
        ),
        **(
            scheduler_test_model_fields(f"journal:{key}")
            if resolved_kind is SchedulerTaskKind.MODEL_REQUEST
            else {}
        ),
    )


def _plan(
    journal: SchedulerJournal,
    pass_kind: SchedulerPassKind,
    *,
    task_kind: SchedulerTaskKind | None = None,
    task_count: int = 1,
) -> SchedulerPassPlan:
    candidate_workset = None
    if pass_kind in {
        SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
        SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
    }:
        source_pass = next(
            result
            for result in journal.pass_results
            if result.plan.pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
        )
        source_result = next(
            result
            for result in source_pass.task_results
            if next(task for task in source_pass.plan.tasks if task.task_id == result.task_id).role
            == "host:cross_shard_integrator"
        )
        source_output = next(
            output for output in journal.outputs if output.task_id == source_result.task_id
        )
        candidate_workset = SchedulerCandidateWorkset.build(
            pass_kind=pass_kind,
            source_pass_result=source_pass,
            source_result=source_result,
            source_output=source_output,
        )
    if task_kind is SchedulerTaskKind.EMPTY_COMPLETION:
        tasks = (
            _task(
                journal,
                pass_kind,
                key="task-empty",
                task_kind=task_kind,
            ),
        )
    elif pass_kind is SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION:
        assert candidate_workset is not None
        tasks = tuple(
            _task(
                journal,
                pass_kind,
                key=f"cross-{candidate_id}-{reviewer_index}",
                role=(
                    "candidate_falsifier:"
                    + hashlib.sha256(candidate_id.encode()).hexdigest()
                    + f":reviewer_{reviewer_index}"
                ),
                candidate_ids=(candidate_id,),
            )
            for candidate_id in candidate_workset.selected_candidate_ids
            for reviewer_index in (1, 2)
        )
    elif pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION:
        assert candidate_workset is not None
        tasks = (
            _task(
                journal,
                pass_kind,
                key="validation-verifier",
                role="verifier",
                candidate_ids=candidate_workset.selected_candidate_ids,
            ),
            _task(
                journal,
                pass_kind,
                key="validation-candidate-falsifier-1",
                role="candidate_falsifier",
                candidate_ids=candidate_workset.selected_candidate_ids,
            ),
            _task(
                journal,
                pass_kind,
                key="validation-candidate-falsifier-2",
                role="candidate_falsifier",
                candidate_ids=candidate_workset.selected_candidate_ids,
            ),
        )
    else:
        tasks = tuple(
            _task(
                journal,
                pass_kind,
                key=f"task-{index}",
                task_kind=task_kind,
                shard_id=(
                    SHARDS[index] if pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW else None
                ),
            )
            for index in range(task_count)
        )
    conditional_absence = None
    if task_kind is SchedulerTaskKind.EMPTY_COMPLETION:
        reason = {
            SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION: (
                SchedulerAbsenceReason.NO_HIGH_CRITICAL_CANDIDATES
            ),
            SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION: (
                SchedulerAbsenceReason.NO_VALIDATION_CANDIDATES
            ),
        }[pass_kind]
        conditional_absence = SchedulerConditionalAbsence.build(
            reason=reason,
            candidate_workset=candidate_workset,
        )
    return SchedulerPassPlan.build(
        manifest=journal.manifest,
        pass_kind=pass_kind,
        dependencies=journal.next_dependencies,
        tasks=tasks,
        candidate_workset=candidate_workset,
        conditional_absence=conditional_absence,
    )


def _large_blind_plan(
    journal: SchedulerJournal,
    *,
    whole_protocol_review_count: int,
) -> SchedulerPassPlan:
    tasks = tuple(
        _task(
            journal,
            SchedulerPassKind.BLIND_SHARD_REVIEW,
            key=f"large-source-{index}",
            shard_id=shard_id,
            role="source_audit",
        )
        for index, shard_id in enumerate(SHARDS)
    ) + tuple(
        _task(
            journal,
            SchedulerPassKind.BLIND_SHARD_REVIEW,
            key=f"large-whole-protocol-{index}",
            role=f"whole_protocol_review:{index}",
        )
        for index in range(whole_protocol_review_count)
    )
    return SchedulerPassPlan.build(
        manifest=journal.manifest,
        pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
        dependencies=journal.next_dependencies,
        tasks=tasks,
    )


def _seal_failed_preflight_pass(
    journal: SchedulerJournal,
    plan: SchedulerPassPlan,
) -> SchedulerPassResult:
    sealed = journal.seal_pass_plan(plan)
    for task in sealed.tasks:
        journal.record_preflight_failure(
            SchedulerTaskResult.build_preflight_failure(
                plan=sealed,
                task=task,
                terminal_status=SchedulerTerminalStatus.FAILED,
                terminal_evidence_sha256="d" * 64,
            )
        )
    return journal.seal_pass_result(sealed.pass_kind)


def _complete_pass(
    journal: SchedulerJournal,
    pass_kind: SchedulerPassKind,
    *,
    task_kind: SchedulerTaskKind | None = None,
    terminal_status: SchedulerTerminalStatus = SchedulerTerminalStatus.SUCCEEDED,
    candidate_ids: tuple[str, ...] = ("candidate-critical",),
) -> None:
    plan = journal.seal_pass_plan(
        _plan(
            journal,
            pass_kind,
            task_kind=task_kind,
            task_count=(len(SHARDS) if pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW else 1),
        ),
    )
    for task in plan.tasks:
        activation = journal.activate_task(
            task.task_id,
            actual_input_sha256=(
                scheduler_test_host_activation_input_sha256(
                    plan,
                    task,
                    candidate_ids=candidate_ids,
                )
                if task.task_kind is SchedulerTaskKind.HOST_COMPUTATION
                else task.input_sha256
            ),
            system_prompt_sha256=(
                task.system_prompt_sha256
                if task.task_kind is SchedulerTaskKind.MODEL_REQUEST
                else None
            ),
            user_prompt_sha256=(
                "1" * 64 if task.task_kind is SchedulerTaskKind.MODEL_REQUEST else None
            ),
            provider_prompt_sha256=(
                "2" * 64 if task.task_kind is SchedulerTaskKind.MODEL_REQUEST else None
            ),
            response_schema_sha256=(
                task.response_schema_sha256
                if task.task_kind is SchedulerTaskKind.MODEL_REQUEST
                else None
            ),
            delivered_source_descriptor_sha256s=(
                scheduler_test_delivered_source_descriptor_sha256s(plan, task)
            ),
            upstream_task_result_sha256s=(
                (plan.candidate_workset.source_result_sha256,)
                if task.task_kind is SchedulerTaskKind.EMPTY_COMPLETION
                and plan.candidate_workset is not None
                else ()
            ),
        )
        dispatched = journal.mark_dispatched(task.task_id)
        assert dispatched.request_id == task.logical_request_id
        output = None
        usage = None
        surface_requests = ()
        surface_artifact = None
        if terminal_status is SchedulerTerminalStatus.SUCCEEDED:
            if task.task_kind is SchedulerTaskKind.MODEL_REQUEST:
                payload = build_scheduler_test_model_payload(plan, task)
                usage = build_scheduler_test_usage(
                    task,
                    activation,
                    validated_output=payload,
                )
                surface_requests, surface_artifact = (
                    build_scheduler_test_model_surface_review_custody(
                        plan,
                        task,
                        activation,
                        usage,
                        payload,
                    )
                )
            elif task.task_kind is SchedulerTaskKind.HOST_COMPUTATION:
                payload = build_scheduler_test_host_payload(
                    plan,
                    task,
                    candidate_ids=candidate_ids,
                )
            else:
                payload = {"completed": True, "task_id": task.task_id}
            output = journal.persist_output(
                task.task_id,
                payload,
                usage_record=usage,
                model_surface_review_requests=surface_requests,
                model_surface_review_artifact=surface_artifact,
            )
        result = SchedulerTaskResult.build(
            plan=plan,
            task=task,
            activation=activation,
            terminal_status=terminal_status,
            terminal_evidence_sha256=(
                usage.validated_response_sha256
                if usage is not None and usage.validated_response_sha256 is not None
                else "c" * 64
            ),
            output=output,
        )
        terminal = journal.record_terminal(result)
        assert terminal.task_result_sha256 == result.result_sha256
    journal.seal_pass_result(pass_kind)


def test_all_seven_exact_passes_derive_complete_campaign(tmp_path: Path) -> None:
    journal = create_scheduler_journal(
        tmp_path / "journal",
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    assert {item.name for item in journal.path.iterdir()} == {
        ".scheduler.lock",
        "activations",
        "analysis-input-inventory.json",
        "events",
        "manifest.json",
        "pass-plans",
        "pass-results",
        "provider-attempts",
        "task-outputs",
        "task-results",
    }

    for pass_kind in SCHEDULER_PASS_ORDER:
        _complete_pass(journal, pass_kind)

    summary = journal.require_complete()
    assert summary.status is SchedulerCampaignStatus.COMPLETE
    assert summary.completed_passes == SCHEDULER_PASS_ORDER
    assert len(journal.pass_results) == 7
    assert len(journal.events) == 44
    evidence = journal.journal_evidence
    assert isinstance(evidence, SchedulerJournalEvidence)
    assert evidence.pass_plan_count == 7
    assert evidence.pass_result_count == 7
    assert evidence.task_plan_count == 11
    assert evidence.model_request_count == 8
    assert evidence.task_activation_count == 11
    assert evidence.task_output_count == 11
    assert evidence.task_result_count == 11
    assert evidence.result_observation_count == 11
    assert evidence.event_count == 44
    assert evidence.terminal_event_chain_head_sha256 == journal.events[-1].event_sha256
    histories: dict[str, list[SchedulerTaskEventKind]] = {}
    for event in journal.events:
        histories.setdefault(event.task_id, []).append(event.kind)
    assert set(tuple(history) for history in histories.values()) == {
        (
            SchedulerTaskEventKind.PLANNED,
            SchedulerTaskEventKind.ACTIVATED,
            SchedulerTaskEventKind.DISPATCHED,
            SchedulerTaskEventKind.TERMINAL,
        )
    }
    artifact = journal.artifact()
    assert artifact.summary == summary
    assert artifact.journal_evidence == evidence
    for candidate in journal.path.rglob("*"):
        mode = stat.S_IMODE(candidate.lstat().st_mode)
        assert mode == (0o700 if candidate.is_dir() else 0o600)
    journal.close()


def test_current_terminal_authority_is_write_once_resume_exact_and_downgrade_resistant(
    tmp_path: Path,
) -> None:
    path = tmp_path / "current-terminal-authority"
    journal = create_scheduler_journal(
        path,
        bindings=_bindings(),
        shard_inventory=_inventory(),
        require_terminal_report_authority=True,
    )
    assert journal.manifest.schema_version == "1.2"
    assert journal.manifest.terminal_report_authority_required
    assert journal.manifest.terminal_evidence_authority_required
    _seal_failed_preflight_pass(
        journal,
        _plan(journal, SchedulerPassKind.ORIENTATION),
    )
    authority = journal.seal_terminal_report_authority(
        severity_threshold=Severity.MEDIUM,
        candidates=(),
        final_findings=(),
        rejected_findings=(),
        filtered_findings=(),
        report_quality_review=None,
        verification_decisions=(),
        cross_examination_decisions=(),
        falsification_decisions=(),
        reproduction_results=(),
        reproduction_resolutions=(),
    )
    assert (
        journal.seal_terminal_report_authority(
            severity_threshold=Severity.MEDIUM,
            candidates=(),
            final_findings=(),
            rejected_findings=(),
            filtered_findings=(),
            report_quality_review=None,
            verification_decisions=(),
            cross_examination_decisions=(),
            falsification_decisions=(),
            reproduction_results=(),
            reproduction_resolutions=(),
        )
        == authority
    )
    evidence = journal.journal_evidence
    artifact = journal.artifact()
    assert evidence.schema_version == "1.1"
    assert artifact.schema_version == "1.1"
    assert evidence.terminal_report_authority_sha256 == authority.authority_sha256
    with pytest.raises(ValueError, match="differs from durable evidence"):
        journal.seal_terminal_report_authority(
            severity_threshold=Severity.HIGH,
            candidates=(),
            final_findings=(),
            rejected_findings=(),
            filtered_findings=(),
            report_quality_review=None,
            verification_decisions=(),
            cross_examination_decisions=(),
            falsification_decisions=(),
            reproduction_results=(),
            reproduction_resolutions=(),
        )
    journal.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_terminal_report_authority_required=True,
    )
    assert resumed.terminal_report_authority == authority
    assert (
        resumed.seal_terminal_report_authority(
            severity_threshold=Severity.MEDIUM,
            candidates=(),
            final_findings=(),
            rejected_findings=(),
            filtered_findings=(),
            report_quality_review=None,
            verification_decisions=(),
            cross_examination_decisions=(),
            falsification_decisions=(),
            reproduction_results=(),
            reproduction_resolutions=(),
        )
        == authority
    )
    resumed.close()

    (path / "terminal-report-authority.json").unlink()
    missing = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_terminal_report_authority_required=True,
    )
    with pytest.raises(ValueError, match="terminal-authority mode"):
        missing.artifact()
    missing.close()


def test_current_unsealed_crash_window_remains_resumable(tmp_path: Path) -> None:
    path = tmp_path / "current-unsealed-resume"
    journal = create_scheduler_journal(
        path,
        bindings=_bindings(),
        shard_inventory=_inventory(),
        require_terminal_report_authority=True,
    )
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    journal.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_terminal_report_authority_required=True,
    )
    assert resumed.terminal_report_authority is None
    assert resumed.resumable_task_ids == tuple(task.task_id for task in plan.tasks)
    resumed.close()


def test_large_indexed_journal_matches_full_readback_reconstruction(tmp_path: Path) -> None:
    path = tmp_path / "large-journal"
    journal = create_scheduler_journal(
        path,
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    _complete_pass(journal, SchedulerPassKind.ORIENTATION)
    pass_result = _seal_failed_preflight_pass(
        journal,
        _large_blind_plan(journal, whole_protocol_review_count=128),
    )
    expected_plans = journal.plans
    expected_events = journal.events
    expected_results = journal.task_results
    expected_evidence = journal.journal_evidence
    journal.close()

    verified = open_scheduler_journal_for_verification(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    assert verified.plans == expected_plans
    assert verified.events == expected_events
    assert verified.task_results == expected_results
    assert verified.pass_results[-1] == pass_result
    assert verified.journal_evidence == expected_evidence
    verified.close()


def test_large_journal_full_readback_rejects_middle_event_chain_tamper(tmp_path: Path) -> None:
    path = tmp_path / "large-tamper"
    journal = create_scheduler_journal(
        path,
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    _complete_pass(journal, SchedulerPassKind.ORIENTATION)
    _seal_failed_preflight_pass(
        journal,
        _large_blind_plan(journal, whole_protocol_review_count=32),
    )
    middle_event = journal.events[len(journal.events) // 2]
    journal.close()
    (path / "events" / f"event-{middle_event.event_index:08d}.json").unlink()

    with pytest.raises(ValueError, match="contiguous exact journal"):
        open_scheduler_journal_for_verification(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )


def test_require_complete_reconstructs_full_live_artifact_inventory(tmp_path: Path) -> None:
    path = tmp_path / "live-complete-tamper"
    journal = create_scheduler_journal(
        path,
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    for pass_kind in SCHEDULER_PASS_ORDER:
        _complete_pass(journal, pass_kind)
    (path / "pass-results" / "pass-07-result.json").unlink()

    with pytest.raises(ValueError):
        journal.require_complete()
    journal.close()


def _corrupt_retained_artifact(path: Path, *, same_name_replacement: bool) -> None:
    corrupted = b"{}\n"
    if same_name_replacement:
        replacement = path.with_name(f".{path.name}.replacement")
        replacement.write_bytes(corrupted)
        replacement.chmod(0o600)
        replacement.replace(path)
    else:
        path.write_bytes(corrupted)
        path.chmod(0o600)


@pytest.mark.parametrize("same_name_replacement", [False, True], ids=["in-place", "replacement"])
@pytest.mark.parametrize("artifact_kind", ["middle-event", "task-result", "pass-result"])
def test_live_full_validation_rejects_retained_artifact_byte_drift(
    tmp_path: Path,
    artifact_kind: str,
    same_name_replacement: bool,
) -> None:
    path = tmp_path / f"{artifact_kind}-{same_name_replacement}"
    journal = create_scheduler_journal(
        path,
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    for pass_kind in SCHEDULER_PASS_ORDER:
        _complete_pass(journal, pass_kind)
    if artifact_kind == "middle-event":
        candidates = sorted((path / "events").iterdir())
        target = candidates[len(candidates) // 2]
    elif artifact_kind == "task-result":
        candidates = sorted((path / "task-results").iterdir())
        target = candidates[len(candidates) // 2]
    else:
        target = path / "pass-results" / "pass-04-result.json"
    _corrupt_retained_artifact(target, same_name_replacement=same_name_replacement)

    with pytest.raises(ValueError):
        journal.require_complete()
    with pytest.raises(ValueError):
        journal.artifact()
    journal.close()


def test_live_full_validation_rejects_replacement_after_an_earlier_artifact_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "cross-file-replacement"
    journal = create_scheduler_journal(
        path,
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    for pass_kind in SCHEDULER_PASS_ORDER:
        _complete_pass(journal, pass_kind)
    earlier_event = path / "events" / "event-00000010.json"
    original_read_model = scheduler_module._read_model
    replaced = False

    def replace_event_after_later_read(
        root_descriptor: int,
        directory_descriptors: dict[str, int],
        relative: str,
        model_type: Any,
    ) -> Any:
        nonlocal replaced
        model = original_read_model(
            root_descriptor,
            directory_descriptors,
            relative,
            model_type,
        )
        if not replaced and relative.startswith("task-results/"):
            replacement = earlier_event.with_name(f".{earlier_event.name}.replacement")
            replacement.write_bytes(earlier_event.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(earlier_event)
            replaced = True
        return model

    monkeypatch.setattr(scheduler_module, "_read_model", replace_event_after_later_read)

    with pytest.raises(ValueError, match="changed during full reconstruction"):
        journal.require_complete()
    assert replaced
    journal.close()


def test_artifact_rejects_replacement_between_summary_and_journal_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "artifact-summary-window"
    journal = create_scheduler_journal(
        path,
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    for pass_kind in SCHEDULER_PASS_ORDER:
        _complete_pass(journal, pass_kind)
    original_summary = SchedulerJournal.summary.fget
    assert original_summary is not None
    replaced = False

    def summary_then_replace(self: SchedulerJournal) -> Any:
        nonlocal replaced
        summary = original_summary(self)
        if self is journal and not replaced:
            target = path / "pass-results" / "pass-04-result.json"
            replacement = target.with_name(f".{target.name}.replacement")
            replacement.write_bytes(target.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(target)
            replaced = True
        return summary

    monkeypatch.setattr(SchedulerJournal, "summary", property(summary_then_replace))

    with pytest.raises(ValueError, match="changed during validated projection"):
        journal.artifact()
    assert replaced
    journal.close()


@pytest.mark.parametrize("mutation", ["delete", "tamper"])
def test_pipeline_scheduler_final_boundaries_delegate_to_durable_validation(
    tmp_path: Path,
    mutation: str,
) -> None:
    path = tmp_path / mutation
    journal = create_scheduler_journal(
        path,
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    for pass_kind in SCHEDULER_PASS_ORDER:
        _complete_pass(journal, pass_kind)
    runtime = PipelineScheduler(journal)
    if mutation == "delete":
        (path / "pass-results" / "pass-07-result.json").unlink()
    else:
        events = sorted((path / "events").iterdir())
        _corrupt_retained_artifact(
            events[len(events) // 2],
            same_name_replacement=False,
        )

    for final_boundary in (
        runtime.require_complete,
        runtime.artifact,
        runtime.report_binding,
    ):
        with pytest.raises(ValueError):
            final_boundary()
    runtime.close()


def test_model_plan_cannot_be_sealed_without_exact_privacy_custody(tmp_path: Path) -> None:
    path = tmp_path / "absent-privacy-custody"
    journal = _create_scheduler_journal(
        path,
        bindings=_bindings_without_privacy_custody(),
        analysis_input_inventory=_analysis_inventory(),
        shard_inventory=_inventory(),
    )
    plan = _plan(journal, SchedulerPassKind.ORIENTATION)

    with pytest.raises(ValueError, match="lacks exact pre-dispatch privacy custody"):
        journal.seal_pass_plan(plan)

    assert journal.plans == ()
    assert journal.events == ()
    assert not any((path / "pass-plans").iterdir())
    journal.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("validation_status", "status", "classification", "error", "terminal_status"),
    (
        (
            ModelRequestValidationStatus.PROVIDER_ERROR,
            "provider_error",
            "timeout",
            TimeoutError("synthetic provider timeout"),
            SchedulerTerminalStatus.FAILED,
        ),
        (
            ModelRequestValidationStatus.PROVIDER_ERROR,
            "provider_error",
            "rate_limit",
            RuntimeError("synthetic provider rate limit"),
            SchedulerTerminalStatus.FAILED,
        ),
        (
            ModelRequestValidationStatus.INVALID_RESPONSE,
            "invalid_response",
            "schema_validation",
            OpenRouterSchemaError("synthetic invalid response"),
            SchedulerTerminalStatus.INVALID,
        ),
    ),
)
async def test_failed_paid_attempt_survives_resume_without_review_credit_or_double_charge(
    tmp_path: Path,
    validation_status: ModelRequestValidationStatus,
    status: str,
    classification: str,
    error: BaseException,
    terminal_status: SchedulerTerminalStatus,
) -> None:
    exact_cost = Decimal("0.125")
    path = tmp_path / classification
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    activation = journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
    )
    journal.mark_dispatched(task.task_id)
    payload = build_scheduler_test_model_payload(plan, task)
    successful_usage = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=payload,
        cost_usd_exact=str(exact_cost),
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
    )
    failed_usage = reattest_synthetic_real_usage(
        successful_usage.model_copy(
            update={
                "identity_strength": ModelIdentityStrength.UNBOUND,
                "provider_error_classification": classification,
                "status": status,
                "validation_status": validation_status,
            }
        )
    )
    assert is_accountable_usage_record(failed_usage, require_real=True)
    assert not is_creditable_usage_record(failed_usage, require_real=True)

    ledger = AtomicCostLedger.initialize(
        tmp_path / f"{classification}-cost.json",
        cap_usd=Decimal("1"),
    )
    reservation = ledger.reserve(failed_usage.request_id, Decimal("0.25"))
    ledger.reconcile(reservation, exact_cost)
    before_resume = ledger.snapshot()
    runtime = PipelineScheduler(journal)
    result = runtime.record_failure(task, error, usage_records=(failed_usage,))

    assert result.terminal_status is terminal_status
    assert len(journal.provider_attempts) == 1
    attempt = journal.provider_attempts[0]
    assert result.terminal_evidence_sha256 == attempt.attempt_evidence_sha256
    assert journal.outputs == ()
    assert journal.structurally_successful_review_usage_records == ()
    assert journal.restorable_review_usage_records == ()
    public = journal.artifact().journal_evidence
    assert public.provider_attempt_count == 1
    assert public.provider_attempt_evidence_sha256s == (attempt.attempt_evidence_sha256,)
    serialized_public = journal.artifact().model_dump_json()
    assert "provider_error_classification" not in serialized_public
    assert failed_usage.accounted_cost_usd_exact not in serialized_public
    runtime.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    serialized = resumed.restorable_usage_records
    assert len(serialized) == 1
    assert is_structurally_accountable_usage_record(serialized[0], require_real=True)
    assert not is_accountable_usage_record(serialized[0], require_real=True)
    assert resumed.restorable_context_request_evidence == (
        resumed.provider_attempts[0].context_request_evidence,
    )
    restored, recovery_scope = resumed.claim_restorable_usage_for_budget_recovery(
        atomic_ledger=ledger
    )
    assert len(restored) == 1
    assert is_accountable_usage_record(restored[0], require_real=True)
    assert not is_creditable_usage_record(restored[0], require_real=True)
    budget = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
    )
    await budget.restore_recovered_usage(restored, recovery_scope=recovery_scope)
    assert budget.spent_usd_exact == exact_cost
    assert ledger.snapshot() == before_resume
    resumed.close()


def test_post_transport_privacy_mismatch_is_accounted_but_never_credited(
    tmp_path: Path,
) -> None:
    journal = create_scheduler_journal(
        tmp_path / "privacy-mismatch",
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    activation = journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
    )
    journal.mark_dispatched(task.task_id)
    payload = build_scheduler_test_model_payload(plan, task)
    exact_usage = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=payload,
        cost_usd_exact="0.125",
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
    )
    mismatched_usage = reattest_synthetic_real_usage(
        exact_usage.model_copy(
            update={
                "routing": {
                    **exact_usage.routing,
                    "effective_privacy_policy_sha256": "f" * 64,
                }
            }
        )
    )
    assert is_creditable_usage_record(mismatched_usage, require_real=True)
    runtime = PipelineScheduler(journal)

    result = runtime.record_model_success(
        task,
        output_value=payload,
        usage_records=[mismatched_usage],
    )

    assert result.terminal_status is SchedulerTerminalStatus.UNBOUND
    assert journal.outputs == ()
    assert len(journal.provider_attempts) == 1
    assert journal.provider_attempts[0].usage_record.request_id == task.logical_request_id
    assert journal.structurally_successful_review_usage_records == ()
    assert journal.restorable_review_usage_records == ()
    runtime.close()


def test_success_requires_private_output_and_reconstructs_typed_payload(tmp_path: Path) -> None:
    journal = create_scheduler_journal(
        tmp_path / "journal",
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    activation = journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
    )
    assert isinstance(activation, SchedulerTaskActivation)
    journal.mark_dispatched(task.task_id)
    with pytest.raises(ValueError, match="lacks provider completion evidence"):
        SchedulerTaskResult.build(
            plan=plan,
            task=task,
            activation=activation,
            terminal_status=SchedulerTerminalStatus.SUCCEEDED,
            terminal_evidence_sha256="d" * 64,
        )
    payload = build_scheduler_test_model_payload(plan, task)
    usage = build_scheduler_test_usage(task, activation, validated_output=payload)
    output = journal.persist_output(task.task_id, payload, usage_record=usage)
    assert isinstance(output, SchedulerTaskOutput)
    typed = journal.reconstruct_output(task.task_id, ThreatModel)
    assert typed == payload
    journal.close()


def test_resume_repairs_activation_file_crash_window(tmp_path: Path) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    activation = journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
    )
    activated_event = journal.events[-1]
    journal.close()
    (path / "events" / f"event-{activated_event.event_index:08d}.json").unlink()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    assert resumed.activations == (activation,)
    assert resumed.events[-1] == activated_event
    assert resumed.dispatchable_task_ids == (task.task_id,)
    resumed.close()


@pytest.mark.asyncio
async def test_resume_re_attests_exact_real_usage_once_but_serialized_copy_cannot(
    tmp_path: Path,
) -> None:
    exact_cost = Decimal("0.123456789012345678")
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    activation = journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
    )
    journal.mark_dispatched(task.task_id)
    payload = build_scheduler_test_model_payload(plan, task)
    runtime_usage = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=payload,
        cost_usd_exact=str(exact_cost),
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
    )
    assert is_creditable_usage_record(runtime_usage, require_real=True)
    output = journal.persist_output(task.task_id, payload, usage_record=runtime_usage)
    journal.record_terminal(
        SchedulerTaskResult.build(
            plan=plan,
            task=task,
            activation=activation,
            terminal_status=SchedulerTerminalStatus.SUCCEEDED,
            terminal_evidence_sha256=runtime_usage.validated_response_sha256,
            output=output,
        )
    )
    journal.close()

    cost_ledger = AtomicCostLedger.initialize(
        tmp_path / "model-cost-ledger.json",
        cap_usd=Decimal("1"),
    )
    cost_reservation = cost_ledger.reserve(runtime_usage.request_id, Decimal("0.13"))
    cost_ledger.reconcile(cost_reservation, exact_cost)
    budget = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=cost_ledger,
        global_input_token_budget=1_000,
        global_output_token_budget=1_000,
    )
    assert budget.recovery_required
    with pytest.raises(BudgetReservationStateError, match="exact usage recovery"):
        await budget.reserve("blocked-before-recovery", "review", "prompt")

    verification = open_scheduler_journal_for_verification(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    with pytest.raises(ValueError, match="read-only"):
        verification.claim_restorable_usage_records()
    verification.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    serialized = resumed.restorable_usage_records
    assert len(serialized) == 1
    assert not is_creditable_usage_record(serialized[0], require_real=True)
    forged = UsageRecord.model_validate(serialized[0].model_dump(mode="json"))
    assert not is_creditable_usage_record(forged, require_real=True)
    restored, budget_scope = resumed.claim_restorable_usage_for_budget_recovery()
    assert len(restored) == 1
    assert is_creditable_usage_record(restored[0], require_real=True)
    before_cost = cost_ledger.snapshot()
    await budget.restore_recovered_usage(restored, recovery_scope=budget_scope)
    assert not budget.recovery_required
    assert budget.spent_input_tokens == restored[0].prompt_tokens
    assert budget.spent_output_tokens == restored[0].completion_tokens
    assert budget.spent_usd_exact == exact_cost
    assert cost_ledger.snapshot() == before_cost
    with pytest.raises(BudgetReservationStateError, match="not required or already ran"):
        await budget.restore_recovered_usage(restored, recovery_scope=budget_scope)
    with pytest.raises(ValueError, match="lacks usage recovery authority"):
        resumed.claim_restorable_usage_records()
    resumed.close()


def test_resume_recovery_authority_never_promotes_mock_usage_to_real(tmp_path: Path) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    activation = journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
    )
    journal.mark_dispatched(task.task_id)
    payload = build_scheduler_test_model_payload(plan, task)
    mock_usage = build_scheduler_test_usage(task, activation, validated_output=payload)
    assert mock_usage.execution_evidence is ExecutionEvidenceKind.MOCK
    output = journal.persist_output(task.task_id, payload, usage_record=mock_usage)
    journal.record_terminal(
        SchedulerTaskResult.build(
            plan=plan,
            task=task,
            activation=activation,
            terminal_status=SchedulerTerminalStatus.SUCCEEDED,
            terminal_evidence_sha256=mock_usage.validated_response_sha256 or "0" * 64,
            output=output,
        )
    )
    journal.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    serialized = resumed.restorable_usage_records
    assert len(serialized) == 1
    assert serialized[0].execution_evidence is ExecutionEvidenceKind.MOCK
    assert not is_creditable_usage_record(serialized[0], require_real=True)
    descriptive = resumed.structurally_successful_review_usage_records
    assert len(descriptive) == 1
    assert descriptive[0].request_id == mock_usage.request_id
    assert descriptive[0].execution_evidence is ExecutionEvidenceKind.MOCK
    assert resumed.restorable_review_usage_records == ()

    recovered = resumed.claim_restorable_usage_records()
    assert len(recovered) == 1
    assert recovered[0].execution_evidence is ExecutionEvidenceKind.MOCK
    assert not is_creditable_usage_record(recovered[0], require_real=True)
    with pytest.raises(ValueError, match="lacks usage recovery authority"):
        resumed.claim_restorable_usage_records()
    resumed.close()


def test_preflight_failure_closes_without_activation_or_dispatch(tmp_path: Path) -> None:
    journal = create_scheduler_journal(
        tmp_path / "journal",
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    result = SchedulerTaskResult.build_preflight_failure(
        plan=plan,
        task=task,
        terminal_status=SchedulerTerminalStatus.FAILED,
        terminal_evidence_sha256="d" * 64,
    )
    journal.record_preflight_failure(result)
    assert journal.activations == ()
    assert journal.outputs == ()
    assert tuple(event.kind for event in journal.events) == (
        SchedulerTaskEventKind.PLANNED,
        SchedulerTaskEventKind.PREFLIGHT_TERMINAL,
    )
    assert (
        journal.seal_pass_result(SchedulerPassKind.ORIENTATION).status is SchedulerPassStatus.FAILED
    )
    journal.close()


@pytest.mark.asyncio
async def test_resume_adopts_activated_cost_reservation_and_dispatches_same_task_once(
    tmp_path: Path,
) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
    )
    ledger = AtomicCostLedger.initialize(tmp_path / "cost.json", cap_usd=Decimal("1"))
    initial_budget = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
    )
    initial_reservation = await initial_budget.reserve(
        task.logical_request_id,
        task.role,
        "prompt",
        exact_model_id=task.requested_model,
    )
    assert initial_reservation.persistent is not None
    budget = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
    )
    journal.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    records, recovery_scope = resumed.claim_restorable_usage_for_budget_recovery(
        atomic_ledger=ledger
    )
    assert records == ()
    await budget.restore_recovered_usage(records, recovery_scope=recovery_scope)
    assert not budget.recovery_required
    assert ledger.snapshot().entries[0].status is CostEntryStatus.RESERVED
    task_events = tuple(event.kind for event in resumed.events if event.task_id == task.task_id)
    assert SchedulerTaskEventKind.DISPATCHED not in task_events
    assert task_events[-1] is SchedulerTaskEventKind.ACTIVATED
    assert task.task_id in resumed.dispatchable_task_ids
    adopted = await budget.reserve(
        task.logical_request_id,
        task.role,
        "prompt",
        exact_model_id=task.requested_model,
    )
    assert adopted.persistent == initial_reservation.persistent
    resumed.mark_dispatched(task.task_id)
    await budget.reconcile(adopted, Decimal("0"))
    assert ledger.snapshot().entries[0].status is CostEntryStatus.RECONCILED
    resumed.close()


@pytest.mark.asyncio
async def test_resume_accounts_full_dispatched_reservation_once_and_never_retries(
    tmp_path: Path,
) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
    )
    journal.mark_dispatched(task.task_id)
    ledger = AtomicCostLedger.initialize(tmp_path / "cost.json", cap_usd=Decimal("1"))
    ledger.reserve(task.logical_request_id, Decimal("0.25"))
    budget = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
        global_input_token_budget=100,
        global_output_token_budget=200,
    )
    journal.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    assert resumed.task_results[0].terminal_status is SchedulerTerminalStatus.UNCERTAIN
    records, recovery_scope = resumed.claim_restorable_usage_for_budget_recovery(
        atomic_ledger=ledger
    )
    assert records == ()
    await budget.restore_recovered_usage(records, recovery_scope=recovery_scope)
    assert not budget.recovery_required
    assert budget.spent_usd_exact == Decimal("0.25")
    assert budget.spent_input_tokens == 100
    assert budget.spent_output_tokens == 200
    snapshot = ledger.snapshot()
    assert snapshot.spent_usd == Decimal("0.25")
    assert snapshot.entries[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert ledger.snapshot().spent_usd == Decimal("0.25")
    assert task.task_id not in resumed.resumable_task_ids
    resumed.close()


def test_resume_rejects_pre_dispatch_retry_reservation_without_dispatch_evidence(
    tmp_path: Path,
) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
    )
    ledger = AtomicCostLedger.initialize(tmp_path / "cost.json", cap_usd=Decimal("1"))
    ledger.reserve(f"{task.logical_request_id}:attempt:2", Decimal("0.20"))
    journal.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    with pytest.raises(ValueError, match="pre-send retry reservation lacks exact dispatch"):
        resumed.claim_restorable_usage_for_budget_recovery(atomic_ledger=ledger)
    snapshot = ledger.snapshot()
    assert snapshot.entries[0].status is CostEntryStatus.RESERVED
    assert snapshot.active_reserved_usd == Decimal("0.20")
    resumed.close()


@pytest.mark.parametrize(
    ("case", "expected_error"),
    (
        ("noncontiguous", "provider-attempt ordinals are not contiguous"),
        ("unfinalized_prior", "prior retry attempt lacks accounted uncertainty"),
    ),
)
def test_resume_rejects_tampered_dispatched_retry_inventory_before_mutation(
    tmp_path: Path,
    case: str,
    expected_error: str,
) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
    )
    journal.mark_dispatched(task.task_id)
    ledger = AtomicCostLedger.initialize(tmp_path / "cost.json", cap_usd=Decimal("1"))
    first = ledger.reserve(task.logical_request_id, Decimal("0.10"))
    if case == "noncontiguous":
        ledger.reconcile(first, None)
        retry_ordinal = 3
    else:
        retry_ordinal = 2
    ledger.reserve(
        f"{task.logical_request_id}:attempt:{retry_ordinal}",
        Decimal("0.20"),
    )
    before = ledger.snapshot()
    journal.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    with pytest.raises(ValueError, match=expected_error):
        resumed.claim_restorable_usage_for_budget_recovery(atomic_ledger=ledger)
    assert ledger.snapshot() == before
    resumed.close()


@pytest.mark.asyncio
async def test_resume_accounts_multiple_dispatched_attempts_once_per_logical_request(
    tmp_path: Path,
) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
    )
    journal.mark_dispatched(task.task_id)
    ledger = AtomicCostLedger.initialize(tmp_path / "cost.json", cap_usd=Decimal("1"))
    first = ledger.reserve(task.logical_request_id, Decimal("0.10"))
    ledger.reconcile(first, None)
    ledger.reserve(f"{task.logical_request_id}:attempt:2", Decimal("0.20"))
    journal.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    budget = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
    )
    records, recovery_scope = resumed.claim_restorable_usage_for_budget_recovery(
        atomic_ledger=ledger
    )
    await budget.restore_recovered_usage(records, recovery_scope=recovery_scope)
    first_recovery = ledger.snapshot()
    assert budget.spent_usd_exact == Decimal("0.30")
    assert first_recovery.spent_usd == Decimal("0.30")
    assert first_recovery.active_reserved_usd == 0
    assert [entry.status for entry in first_recovery.entries] == [
        CostEntryStatus.UNCERTAIN_ACCOUNTED,
        CostEntryStatus.UNCERTAIN_ACCOUNTED,
    ]
    assert task.task_id not in resumed.resumable_task_ids
    resumed.close()

    resumed_again = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    second_budget = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
    )
    records, recovery_scope = resumed_again.claim_restorable_usage_for_budget_recovery(
        atomic_ledger=ledger
    )
    await second_budget.restore_recovered_usage(records, recovery_scope=recovery_scope)
    assert second_budget.spent_usd_exact == Decimal("0.30")
    assert ledger.snapshot() == first_recovery
    resumed_again.close()


@pytest.mark.asyncio
async def test_campaign_baseline_excludes_preexisting_spend_from_scoped_recovery(
    tmp_path: Path,
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "cost.json", cap_usd=Decimal("1"))
    prior = ledger.reserve("prior-campaign-request", Decimal("0.10"))
    ledger.reconcile(prior, Decimal("0.10"))
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    bindings = _bindings(cost_ledger_baseline_sha256=baseline.baseline_sha256)
    journal = create_scheduler_journal(
        tmp_path / "journal",
        bindings=bindings,
        shard_inventory=_inventory(),
        cost_ledger_baseline=baseline,
    )
    budget = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
    )
    records, recovery_scope = journal.claim_restorable_usage_for_budget_recovery(
        atomic_ledger=ledger
    )
    await budget.restore_recovered_usage(records, recovery_scope=recovery_scope)

    assert budget.spent_usd_exact == Decimal("0.10")
    assert budget.spent_model_usd("synthetic/auditor-v1") == 0
    assert not budget.recovery_required
    journal.close()


def test_scheduler_cost_baseline_is_stable_and_does_not_serialize_ledger_paths(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "operator-private-ledger-name.json"
    ledger = AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("1"))
    reservation = ledger.reserve("prior-request", Decimal("0.10"))
    ledger.reconcile(reservation, Decimal("0.05"))

    baseline = build_scheduler_cost_ledger_baseline(ledger)
    reopened = AtomicCostLedger.open_existing(ledger_path, cap_usd=Decimal("1"))
    reopened_baseline = build_scheduler_cost_ledger_baseline(reopened)
    serialized = baseline.model_dump_json()

    assert reopened_baseline == baseline
    assert ledger_path.as_posix() not in serialized
    assert ledger.lock_path.as_posix() not in serialized
    assert ledger_path.name not in serialized


@pytest.mark.asyncio
async def test_resume_reads_bound_baseline_and_recovers_only_campaign_delta(
    tmp_path: Path,
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "cost.json", cap_usd=Decimal("1"))
    prior = ledger.reserve("prior-campaign-request", Decimal("0.10"))
    ledger.reconcile(prior, Decimal("0.10"))
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    bindings = _bindings(cost_ledger_baseline_sha256=baseline.baseline_sha256)
    path = tmp_path / "journal"
    journal = create_scheduler_journal(
        path,
        bindings=bindings,
        shard_inventory=_inventory(),
        cost_ledger_baseline=baseline,
    )
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
    )
    journal.mark_dispatched(task.task_id)
    ledger.reserve(task.logical_request_id, Decimal("0.25"))
    journal.close()

    wrong_ledger = AtomicCostLedger.initialize(
        tmp_path / "wrong-cost.json",
        cap_usd=Decimal("1"),
    )
    with pytest.raises(ValueError, match="identity differs"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            atomic_ledger=wrong_ledger,
        )
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        atomic_ledger=ledger,
    )
    budget = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
    )
    records, recovery_scope = resumed.claim_restorable_usage_for_budget_recovery(
        atomic_ledger=ledger
    )
    await budget.restore_recovered_usage(records, recovery_scope=recovery_scope)

    assert budget.spent_usd_exact == Decimal("0.35")
    assert budget.spent_model_usd(task.requested_model or "") == Decimal("0.25")
    assert ledger.snapshot().entries[-1].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    resumed.close()


@pytest.mark.parametrize(
    "error",
    (
        BudgetExhaustedError("synthetic token-plan budget failure"),
        ValueError("synthetic provider reservation failure"),
    ),
)
def test_activated_provider_preflight_failure_is_terminal_without_dispatch(
    tmp_path: Path,
    error: BaseException,
) -> None:
    runtime = PipelineScheduler.create(
        tmp_path / "journal",
        bindings=_bindings(),
        analysis_input_inventory=_analysis_inventory(),
        shard_inventory=_inventory(),
        privacy_evidence_custody=_privacy_custody(),
    )
    task = _task(runtime.journal, SchedulerPassKind.ORIENTATION)
    runtime.seal_pass(SchedulerPassKind.ORIENTATION, (task,))
    runtime.journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
    )
    runtime._activations[task.task_id] = runtime.journal.activations[0]

    result = runtime.record_failure(task, error)

    assert result.terminal_status in {
        SchedulerTerminalStatus.FAILED,
        SchedulerTerminalStatus.INCONCLUSIVE,
    }
    assert tuple(event.kind for event in runtime.journal.events) == (
        SchedulerTaskEventKind.PLANNED,
        SchedulerTaskEventKind.ACTIVATED,
        SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
    )
    assert all(
        event.kind is not SchedulerTaskEventKind.DISPATCHED for event in runtime.journal.events
    )
    assert runtime.journal.resumable_task_ids == ()
    assert runtime.seal_pass_result().status in {
        SchedulerPassStatus.FAILED,
        SchedulerPassStatus.INCONCLUSIVE,
    }
    runtime.close()


def test_provider_delivery_requires_exact_audited_path_hash_and_size(tmp_path: Path) -> None:
    runtime = PipelineScheduler.create(
        tmp_path / "journal",
        bindings=_bindings(),
        analysis_input_inventory=_analysis_inventory(),
        shard_inventory=_inventory(),
        privacy_evidence_custody=_privacy_custody(),
    )
    schema_sha256 = next(
        item["schema_sha256"]
        for item in scheduler_response_schema_registry()
        if item["model_type"].endswith("ThreatModel")
    )
    task = runtime.model_task(
        pass_kind=SchedulerPassKind.ORIENTATION,
        scope=SchedulerScope.global_scope(),
        task_key="exact-source-delivery",
        role="threat_model",
        requested_model="synthetic/auditor-v1",
        root_lineage="sha256:" + "1" * 64,
        system_prompt_sha256="2" * 64,
        response_schema_sha256=schema_sha256,
    )
    runtime.seal_pass(SchedulerPassKind.ORIENTATION, (task,))
    source = runtime.journal.manifest.shard_inventory.shards[0].sources[0]
    wrong = DeliveredSourceDescriptor(
        path=source.path,
        sha256="f" * 64,
        size=source.size,
    )
    request = {
        "logical_request_id": task.logical_request_id,
        "role": task.role,
        "requested_model": task.requested_model,
        "prompt_sha256": "3" * 64,
        "system_prompt_sha256": task.system_prompt_sha256,
        "user_prompt_sha256": "4" * 64,
        "schema_sha256": task.response_schema_sha256,
    }
    custody = runtime.journal.manifest.privacy_evidence_custody
    assert custody is not None
    exact_privacy = ModelRequestPrivacyBinding(
        source_sha256=custody.source_sha256,
        effective_policy_sha256=custody.effective_policy_evidence_sha256,
        source_provenance_sha256=custody.source_provenance_evidence_sha256,
    )
    with pytest.raises(OpenRouterSchemaError, match="differs from audited source bytes"):
        runtime.request_ready(
            **request,
            delivered_sources=(wrong,),
            privacy_binding=exact_privacy,
        )
    assert runtime.journal.activations == ()

    exact = DeliveredSourceDescriptor(path=source.path, sha256=source.sha256, size=source.size)
    wrong_privacy = ModelRequestPrivacyBinding(
        source_sha256=custody.source_sha256,
        effective_policy_sha256="f" * 64,
        source_provenance_sha256=custody.source_provenance_evidence_sha256,
    )
    with pytest.raises(OpenRouterSchemaError, match="privacy authority differs"):
        runtime.request_ready(
            **request,
            delivered_sources=(exact,),
            privacy_binding=wrong_privacy,
        )
    assert runtime.journal.activations == ()

    runtime.request_ready(
        **request,
        delivered_sources=(exact,),
        privacy_binding=exact_privacy,
    )
    assert runtime.journal.activations[0].delivered_source_descriptor_sha256s == (
        source.source_descriptor_sha256,
    )
    runtime.close()


def test_explicit_empty_task_is_terminal_evidence_not_zero_task_pass(tmp_path: Path) -> None:
    journal = create_scheduler_journal(
        tmp_path / "journal",
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    for pass_kind in SCHEDULER_PASS_ORDER[:4]:
        _complete_pass(
            journal,
            pass_kind,
            candidate_ids=(
                ()
                if pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
                else ("candidate-critical",)
            ),
        )
    _complete_pass(
        journal,
        SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
        task_kind=SchedulerTaskKind.EMPTY_COMPLETION,
        terminal_status=SchedulerTerminalStatus.EXPLICIT_EMPTY,
    )

    assert journal.pass_results[-1].status is SchedulerPassStatus.COMPLETE
    assert len(journal.pass_results[-1].plan.tasks) == 1
    assert (
        journal.pass_results[-1].task_results[0].terminal_status
        is SchedulerTerminalStatus.EXPLICIT_EMPTY
    )
    journal.close()


def test_incomplete_or_failed_pass_cannot_appear_complete_or_advance(tmp_path: Path) -> None:
    journal = create_scheduler_journal(
        tmp_path / "journal",
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    with pytest.raises(ValueError, match="not complete"):
        journal.require_complete()
    with pytest.raises(ValueError, match="unfinished"):
        journal.seal_pass_result(SchedulerPassKind.ORIENTATION)

    task = plan.tasks[0]
    activation = journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
    )
    journal.mark_dispatched(task.task_id)
    journal.record_terminal(
        SchedulerTaskResult.build(
            plan=plan,
            task=task,
            activation=activation,
            terminal_status=SchedulerTerminalStatus.FAILED,
            terminal_evidence_sha256="e" * 64,
        )
    )
    result = journal.seal_pass_result(SchedulerPassKind.ORIENTATION)
    assert result.status is SchedulerPassStatus.FAILED
    next_plan = _plan(journal, SchedulerPassKind.BLIND_SHARD_REVIEW, task_count=2)
    with pytest.raises(ValueError, match="non-complete"):
        journal.seal_pass_plan(next_plan)
    assert journal.summary.status is SchedulerCampaignStatus.FAILED
    journal.close()


def test_resume_only_returns_never_dispatched_tasks(tmp_path: Path) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task_id = plan.tasks[0].task_id
    journal.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    assert resumed.resumable_task_ids == (task_id,)
    assert resumed.uncertain_task_ids == ()
    resumed.close()


def test_dispatched_without_terminal_becomes_uncertain_and_is_not_retried(
    tmp_path: Path,
) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
    )
    journal.mark_dispatched(task.task_id)
    journal.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    assert resumed.resumable_task_ids == ()
    assert resumed.uncertain_task_ids == (task.task_id,)
    assert resumed.events[-1].kind is SchedulerTaskEventKind.TERMINAL
    assert resumed.task_results[-1].terminal_status is SchedulerTerminalStatus.UNCERTAIN
    with pytest.raises(ValueError, match="only an activated"):
        resumed.mark_dispatched(task.task_id)
    result = resumed.seal_pass_result(SchedulerPassKind.ORIENTATION)
    assert result.status is SchedulerPassStatus.INCOMPLETE
    assert resumed.summary.status is SchedulerCampaignStatus.INCOMPLETE
    resumed.close()


def test_resume_repairs_only_missing_planned_suffix_after_sealed_blind_plan(
    tmp_path: Path,
) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    _complete_pass(journal, SchedulerPassKind.ORIENTATION)
    blind = journal.seal_pass_plan(
        _plan(journal, SchedulerPassKind.BLIND_SHARD_REVIEW, task_count=2)
    )
    assert blind.blind_plan_barrier_sha256 is not None
    last_event = journal.events[-1]
    assert last_event.task_id == blind.tasks[-1].task_id
    journal.close()
    (path / "events" / f"event-{last_event.event_index:08d}.json").unlink()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    assert resumed.events[-1] == last_event
    assert resumed.resumable_task_ids == tuple(sorted(task.task_id for task in blind.tasks))
    with pytest.raises(ValueError, match="exact campaign order"):
        resumed.seal_pass_plan(blind)
    resumed.close()


def test_result_without_terminal_event_is_retained_but_never_credited(
    tmp_path: Path,
) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    activation = journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
    )
    journal.mark_dispatched(task.task_id)
    payload = build_scheduler_test_model_payload(plan, task)
    usage = build_scheduler_test_usage(task, activation, validated_output=payload)
    output = journal.persist_output(task.task_id, payload, usage_record=usage)
    result = SchedulerTaskResult.build(
        plan=plan,
        task=task,
        activation=activation,
        terminal_status=SchedulerTerminalStatus.SUCCEEDED,
        terminal_evidence_sha256=usage.validated_response_sha256,
        output=output,
    )
    write_json_evidence(
        evidence_root=path,
        relative_path=f"task-results/{task.task_id}-{result.result_sha256}.json",
        value=result,
    )
    journal.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    assert len(resumed.result_observations) == 2
    assert result in resumed.result_observations
    assert resumed.task_results[0].terminal_status is SchedulerTerminalStatus.UNCERTAIN
    assert resumed.events[-1].kind is SchedulerTaskEventKind.TERMINAL
    assert resumed.uncertain_task_ids == (task.task_id,)
    resumed.close()


def test_output_without_terminal_result_is_retained_and_dispatch_is_uncertain(
    tmp_path: Path,
) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    activation = journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
    )
    journal.mark_dispatched(task.task_id)
    payload = build_scheduler_test_model_payload(plan, task)
    usage = build_scheduler_test_usage(task, activation, validated_output=payload)
    output = journal.persist_output(task.task_id, payload, usage_record=usage)
    journal.close()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    assert resumed.outputs == (output,)
    assert resumed.load_output(task.task_id) == output.payload
    assert resumed.task_results[0].terminal_status is SchedulerTerminalStatus.UNCERTAIN
    assert resumed.uncertain_task_ids == (task.task_id,)
    assert resumed.resumable_task_ids == ()
    assert resumed.artifact().journal_evidence.task_output_count == 1
    assert resumed.artifact().journal_evidence.succeeded_count == 0
    resumed.close()


def test_resume_repairs_preflight_result_file_crash_window(tmp_path: Path) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    result = SchedulerTaskResult.build_preflight_failure(
        plan=plan,
        task=task,
        terminal_status=SchedulerTerminalStatus.INCONCLUSIVE,
        terminal_evidence_sha256="d" * 64,
    )
    terminal = journal.record_preflight_failure(result)
    journal.close()
    (path / "events" / f"event-{terminal.event_index:08d}.json").unlink()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    assert resumed.events[-1] == terminal
    assert resumed.task_results == (result,)
    assert resumed.activations == ()
    resumed.close()


@pytest.mark.parametrize("directory", ["activations", "task-outputs", "task-results"])
def test_resume_rejects_deleted_linked_runtime_evidence(
    tmp_path: Path,
    directory: str,
) -> None:
    path = tmp_path / directory
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    _complete_pass(journal, SchedulerPassKind.ORIENTATION)
    journal.close()
    next((path / directory).iterdir()).unlink()

    with pytest.raises(ValueError):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )


@pytest.mark.parametrize(
    ("directory", "field"),
    [
        ("activations", "actual_input_sha256"),
        ("task-outputs", "payload"),
        ("task-results", "terminal_evidence_sha256"),
    ],
)
def test_resume_rejects_tampered_runtime_evidence(
    tmp_path: Path,
    directory: str,
    field: str,
) -> None:
    path = tmp_path / directory
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    _complete_pass(journal, SchedulerPassKind.ORIENTATION)
    journal.close()
    artifact_path = next((path / directory).iterdir())
    value = json.loads(artifact_path.read_text(encoding="utf-8"))
    value[field] = {"tampered": True} if field == "payload" else "0" * 64
    artifact_path.write_text(
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    artifact_path.chmod(0o600)

    with pytest.raises(ValueError):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )


@pytest.mark.parametrize("directory", ["activations", "task-outputs", "task-results"])
def test_resume_rejects_duplicate_runtime_evidence(
    tmp_path: Path,
    directory: str,
) -> None:
    path = tmp_path / directory
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    _complete_pass(journal, SchedulerPassKind.ORIENTATION)
    journal.close()
    original = next((path / directory).iterdir())
    duplicate = path / directory / "duplicate.json"
    duplicate.write_bytes(original.read_bytes())
    duplicate.chmod(0o600)

    with pytest.raises(ValueError):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )


def test_resume_rejects_deleted_terminal_event_linked_by_pass_result(tmp_path: Path) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    _complete_pass(journal, SchedulerPassKind.ORIENTATION)
    terminal = journal.events[-1]
    journal.close()
    (path / "events" / f"event-{terminal.event_index:08d}.json").unlink()

    with pytest.raises(ValueError):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )


def test_deleted_tail_pass_result_cannot_preserve_complete_status(tmp_path: Path) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    for pass_kind in SCHEDULER_PASS_ORDER:
        _complete_pass(journal, pass_kind)
    assert journal.require_complete().status is SchedulerCampaignStatus.COMPLETE
    journal.close()
    (path / "pass-results" / "pass-07-result.json").unlink()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    with pytest.raises(ValueError, match="not complete"):
        resumed.require_complete()
    assert resumed.artifact().summary.status is SchedulerCampaignStatus.INCOMPLETE
    resumed.close()


def test_concurrent_live_custody_is_rejected_without_releasing_owner(tmp_path: Path) -> None:
    path = tmp_path / "journal"
    owner = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    with pytest.raises(ValueError, match="live in-process custody"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )
    plan = owner.seal_pass_plan(_plan(owner, SchedulerPassKind.ORIENTATION))
    assert owner.resumable_task_ids == (plan.tasks[0].task_id,)
    owner.close()


@pytest.mark.parametrize(
    "changed",
    [
        "source_sha256",
        "effective_config_sha256",
        "shard_inventory_sha256",
        "model_selection_sha256",
        "qualification_sha256",
        "prompt_set_sha256",
        "schema_set_sha256",
        "tool_policy_sha256",
    ],
)
def test_resume_rejects_every_immutable_binding_drift(tmp_path: Path, changed: str) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    journal.close()

    with pytest.raises(ValueError, match="bindings or shard inventory"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(changed=changed),
            expected_shard_inventory=_inventory(),
        )


def test_resume_rejects_shard_inventory_drift(tmp_path: Path) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    journal.close()

    with pytest.raises(ValueError, match="bindings or shard inventory"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(one_shard=True),
        )


def test_resume_rejects_manifest_tamper_and_unmanifested_artifacts(tmp_path: Path) -> None:
    tampered = tmp_path / "tampered"
    journal = create_scheduler_journal(
        tampered,
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    journal.close()
    manifest_path = tampered / "manifest.json"
    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    value["bindings"]["source_sha256"] = "f" * 64
    manifest_path.write_text(json.dumps(value), encoding="utf-8")
    manifest_path.chmod(0o600)
    with pytest.raises(ValueError):
        resume_scheduler_journal(
            tampered,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )

    extra = tmp_path / "extra"
    journal = create_scheduler_journal(extra, bindings=_bindings(), shard_inventory=_inventory())
    journal.close()
    (extra / "events" / "unmanifested.json").write_text("{}", encoding="utf-8")
    (extra / "events" / "unmanifested.json").chmod(0o600)
    with pytest.raises(ValueError, match=r"contiguous exact journal|unmanifested"):
        resume_scheduler_journal(
            extra,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )


def test_resume_rejects_symlinked_or_shared_evidence(tmp_path: Path) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    journal.close()
    event_path = path / "events" / "event-00000000.json"
    outside = tmp_path / "outside.json"
    outside.write_bytes(event_path.read_bytes())
    outside.chmod(0o600)
    event_path.unlink()
    try:
        event_path.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")

    with pytest.raises(ValueError):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )


def test_resume_root_swap_after_open_cannot_redirect_custody(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    journal.close()
    original = scheduler_module._acquire_custody_lock
    swapped = False

    def swap_before_lock(root_descriptor: int, *, create: bool) -> int:
        nonlocal swapped
        if not swapped:
            retained = tmp_path / "retained-journal"
            path.rename(retained)
            shutil.copytree(retained, path)
            swapped = True
        return original(root_descriptor, create=create)

    monkeypatch.setattr(scheduler_module, "_acquire_custody_lock", swap_before_lock)
    with pytest.raises(ValueError, match="root changed during live custody"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )
    assert swapped


def test_resume_child_swap_cannot_redirect_descriptor_held_listing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    journal.close()
    original = scheduler_module._load_state
    swapped = False

    def swap_before_listing(
        root_descriptor: int,
        directory_descriptors: Any,
        manifest: Any,
    ) -> Any:
        nonlocal swapped
        if not swapped:
            (path / "events").rename(tmp_path / "retained-events")
            (path / "events").mkdir(mode=0o700)
            swapped = True
        return original(root_descriptor, directory_descriptors, manifest)

    monkeypatch.setattr(scheduler_module, "_load_state", swap_before_listing)
    with pytest.raises(ValueError, match="directories must remain"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )
    assert swapped
    assert not any((path / "events").iterdir())
    assert {item.name for item in (tmp_path / "retained-events").iterdir()} == {
        "event-00000000.json"
    }


@pytest.mark.parametrize("swap_child", [False, True])
def test_live_root_and_child_swaps_never_receive_descriptor_held_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    swap_child: bool,
) -> None:
    path = tmp_path / ("child" if swap_child else "root")
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    plan = _plan(journal, SchedulerPassKind.ORIENTATION)
    original = scheduler_module._write_model
    swapped = False

    def swap_before_write(
        root_descriptor: int,
        directory_descriptors: dict[str, int],
        relative: str,
        model: Any,
    ) -> None:
        nonlocal swapped
        if not swapped:
            if swap_child:
                retained = path / "retained-pass-plans"
                (path / "pass-plans").rename(retained)
                (path / "pass-plans").mkdir(mode=0o700)
            else:
                retained = path.with_name("retained-root")
                path.rename(retained)
                shutil.copytree(retained, path)
            swapped = True
        original(root_descriptor, directory_descriptors, relative, model)

    monkeypatch.setattr(scheduler_module, "_write_model", swap_before_write)
    with pytest.raises(
        ValueError,
        match=r"root changed|directories must remain|unmanifested root",
    ):
        journal.seal_pass_plan(plan)
    assert swapped
    assert not any((path / "pass-plans").iterdir())
    retained_plans = (
        path / "retained-pass-plans"
        if swap_child
        else path.with_name("retained-root") / "pass-plans"
    )
    assert {item.name for item in retained_plans.iterdir()} == {"pass-01-plan.json"}
    journal.close()
