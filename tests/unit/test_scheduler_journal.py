from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pickle
import shutil
import stat
import threading
from collections.abc import Iterator
from copy import copy, deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, NoReturn

import pytest

import mmaudit.orchestration.scheduler as scheduler_module
from mmaudit.models.openrouter import (
    DeliveredSourceDescriptor,
    ModelRequestPrivacyBinding,
    OpenRouterSchemaError,
)
from mmaudit.models.refresh_runtime import (
    AuditModelRefreshPricingRouteEvidence,
    AuditModelRefreshRouteEvidence,
)
from mmaudit.models.scheduler import (
    SCHEDULER_ANALYSIS_INPUT_LABELS,
    SCHEDULER_PASS_ORDER,
    SchedulerAbsenceReason,
    SchedulerAnalysisInputDescriptor,
    SchedulerAnalysisInputInventory,
    SchedulerAuditModelRefreshBinding,
    SchedulerAuditModelRefreshPricingBinding,
    SchedulerAuditModelRefreshPricingRouteBinding,
    SchedulerAuditModelRefreshRouteBinding,
    SchedulerBindings,
    SchedulerCampaignStatus,
    SchedulerCampaignSummary,
    SchedulerCandidateWorkset,
    SchedulerConditionalAbsence,
    SchedulerJournalEvidence,
    SchedulerModelCompletionEvidence,
    SchedulerPassKind,
    SchedulerPassPlan,
    SchedulerPassResult,
    SchedulerPassStatus,
    SchedulerPrivacyEvidenceCustody,
    SchedulerProviderAttemptEvidence,
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
    scheduler_canonical_sha256,
)
from mmaudit.models.schemas import (
    AuditModelRefreshPricingAttemptEvidence,
    CandidateReviewBatch,
    ExecutionEvidenceKind,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    Severity,
    ThreatModel,
    UsageRecord,
)
from mmaudit.models.truncation import (
    CandidateReviewNormalizationEvidence,
    candidate_review_frame_wire_schema_sha256,
    frame_candidate_review_batch,
    normalize_candidate_review_document,
)
from mmaudit.models.usage import (
    is_accountable_usage_record,
    is_creditable_usage_record,
    is_structurally_accountable_usage_record,
)
from mmaudit.orchestration.budgets import (
    AtomicRequestLimitReservationEvidence,
    AtomicTokenReservationEvidence,
    BudgetExhaustedError,
    BudgetManager,
    BudgetReservationStateError,
    _issue_trusted_request_limit_scope,
)
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntryStatus,
    ReleaseReason,
    cost_entry_sha256,
)
from mmaudit.orchestration.model_review_authority import (
    ModelReviewPreDispatchAuthorization as ExactModelReviewPreDispatchAuthorization,
)
from mmaudit.orchestration.model_review_authority import (
    ModelReviewPreDispatchBinding as ExactModelReviewPreDispatchBinding,
)
from mmaudit.orchestration.scheduler import (
    SchedulerJournal,
    require_model_review_pre_dispatch_authorization,
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
    build_scheduler_bindings,
    build_scheduler_cost_ledger_baseline,
    scheduler_response_normalizer_sha256,
    scheduler_response_schema_registry,
)
from mmaudit.release_io import write_json_evidence
from mmaudit.reporting.json_report import stable_json
from tests.identity_fixtures import reattest_synthetic_real_usage
from tests.refresh_runtime_support import synthetic_refresh_runtime
from tests.scheduler_support import (
    build_scheduler_test_audit_model_refresh_binding,
    build_scheduler_test_audit_model_refresh_pricing_binding,
    build_scheduler_test_audit_model_selection_binding,
    build_scheduler_test_host_payload,
    build_scheduler_test_model_payload,
    build_scheduler_test_model_surface_review_custody,
    build_scheduler_test_real_usage,
    build_scheduler_test_usage,
    scheduler_test_delivered_source_descriptor_sha256s,
    scheduler_test_host_activation_input_sha256,
    scheduler_test_model_fields,
    scheduler_test_model_surface_review_request_manifest_sha256,
    scheduler_test_response_schema_sha256,
)

SHARDS = (
    "shard-" + "1" * 24,
    "shard-" + "2" * 24,
)


def _journal_private_file_snapshot(
    path: Path,
) -> dict[str, tuple[bytes, int, int, int, int]]:
    """Capture exact bytes and link identity for fail-before-mutation assertions."""

    snapshot: dict[str, tuple[bytes, int, int, int, int]] = {}
    for candidate in sorted(path.rglob("*")):
        metadata = candidate.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            continue
        snapshot[candidate.relative_to(path).as_posix()] = (
            candidate.read_bytes(),
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_nlink,
            stat.S_IMODE(metadata.st_mode),
        )
    return snapshot


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
    with_audit_policy: bool = False,
    audit_policy_seed: str = "scheduler-journal-policy",
    audit_model_refresh_expires_at: datetime | None = None,
) -> SchedulerBindings:
    inventory = _inventory()
    audit_selection = (
        build_scheduler_test_audit_model_selection_binding(
            source_sha256=inventory.source_tree_sha256,
            selected_routes=(
                (
                    "synthetic/auditor-v1",
                    "sha256:" + hashlib.sha256(b"synthetic/auditor-v1").hexdigest(),
                    "Synthetic Provider",
                    "synthetic-provider",
                ),
            ),
            seed=audit_policy_seed,
        )
        if with_audit_policy
        else None
    )
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
    if audit_selection is not None:
        values["audit_model_selection"] = audit_selection
        audit_refresh = build_scheduler_test_audit_model_refresh_binding(
            audit_selection,
            seed=f"{audit_policy_seed}:refresh",
            expires_at=audit_model_refresh_expires_at,
        )
        values["audit_model_refresh"] = audit_refresh
        values["audit_model_refresh_pricing"] = (
            build_scheduler_test_audit_model_refresh_pricing_binding(
                audit_selection,
                audit_refresh,
            )
        )
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
        audit_model_selection=bindings.audit_model_selection,
        audit_model_refresh=bindings.audit_model_refresh,
    )


def _refresh_only_bindings() -> SchedulerBindings:
    bindings = _bindings(with_audit_policy=True)
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
        privacy_evidence_custody_sha256=bindings.privacy_evidence_custody_sha256,
        audit_model_selection=bindings.audit_model_selection,
        audit_model_refresh=bindings.audit_model_refresh,
    )


def create_scheduler_journal(
    path: Path,
    *,
    bindings: SchedulerBindings,
    shard_inventory: SchedulerShardInventory,
    **kwargs: Any,
) -> SchedulerJournal:
    kwargs.setdefault("privacy_evidence_custody", _privacy_custody())
    original_validator = scheduler_module._validate_live_scheduler_model_refresh
    synthetic_pricing = (
        bindings.audit_model_refresh_pricing is not None
        and "audit_model_refresh_pricing_authority" not in kwargs
    )
    if synthetic_pricing:
        # Model-graph tests use deliberately non-authorizing hash fixtures. The
        # production live-authority boundary is exercised through PipelineScheduler
        # directly below; bypass it only while constructing these local journals.
        scheduler_module._validate_live_scheduler_model_refresh = lambda **_values: (
            True,
            True,
        )
    try:
        return _create_scheduler_journal(
            path,
            bindings=bindings,
            analysis_input_inventory=_analysis_inventory(),
            shard_inventory=shard_inventory,
            **kwargs,
        )
    finally:
        scheduler_module._validate_live_scheduler_model_refresh = original_validator


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


def test_legacy_scheduler_journal_is_verification_only_not_mutably_resumable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.unit.test_scheduler_models import (
        _legacy_analysis_inventory,
        _legacy_manifest,
    )

    manifest = _legacy_manifest("mutable-resume-policy")
    analysis_inputs = _legacy_analysis_inventory()
    summary = SchedulerCampaignSummary.build(manifest=manifest, pass_results=())
    checkpoint = SchedulerJournalEvidence.build(
        manifest=manifest,
        analysis_input_inventory=analysis_inputs,
        summary=summary,
        plans=(),
        model_requests=(),
        activations=(),
        outputs=(),
        provider_attempts=(),
        task_results=(),
        result_observations=(),
        events=(),
    )
    path = tmp_path / "legacy-verification-only"
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    for directory in scheduler_module._CONTROL_DIRECTORIES:
        child = path / directory
        child.mkdir(mode=0o700)
        child.chmod(0o700)
    lock_path = path / scheduler_module._LOCK_FILENAME
    lock_path.touch(mode=0o600)
    lock_path.chmod(0o600)
    for filename, value in (
        (scheduler_module._MANIFEST_FILENAME, manifest),
        (scheduler_module._ANALYSIS_INPUT_INVENTORY_FILENAME, analysis_inputs),
        (scheduler_module._JOURNAL_HEAD_CHECKPOINT_FILENAME, checkpoint),
    ):
        artifact_path = path / filename
        artifact_path.write_text(stable_json(value), encoding="utf-8")
        artifact_path.chmod(0o600)

    with monkeypatch.context() as resume_guard:
        resume_guard.setattr(
            scheduler_module,
            "_validate_live_scheduler_model_refresh",
            lambda **_kwargs: pytest.fail("legacy resume reached live refresh validation"),
        )
        resume_guard.setattr(
            scheduler_module,
            "_open_private_root",
            lambda _path: pytest.fail("legacy resume opened mutable journal custody"),
        )
        with pytest.raises(
            ValueError,
            match="verification/replay-only and cannot be resumed mutably",
        ):
            _resume_scheduler_journal(
                path,
                expected_bindings=manifest.bindings,
                expected_analysis_input_inventory=analysis_inputs,
                expected_shard_inventory=manifest.shard_inventory,
            )

    verified = _open_scheduler_journal_for_verification(
        path,
        expected_bindings=manifest.bindings,
        expected_analysis_input_inventory=analysis_inputs,
        expected_shard_inventory=manifest.shard_inventory,
        expected_privacy_evidence_custody=manifest.privacy_evidence_custody,
        expected_journal_evidence=checkpoint,
    )
    assert verified.manifest == manifest
    verified.close()


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
    scope = (
        SchedulerScope.single_shard(shard_id)
        if shard_id is not None
        else SchedulerScope.global_scope()
    )
    candidate_review_contract = resolved_kind is SchedulerTaskKind.MODEL_REQUEST and (
        pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
        or (
            pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
            and resolved_role == "business_logic"
        )
    )
    return SchedulerTaskPlan.build(
        manifest=journal.manifest,
        pass_kind=pass_kind,
        scope=scope,
        task_kind=resolved_kind,
        task_key=key,
        role=resolved_role,
        requested_model=(
            "synthetic/auditor-v1" if resolved_kind is SchedulerTaskKind.MODEL_REQUEST else None
        ),
        root_lineage=(
            (
                journal.manifest.bindings.audit_model_selection.route_for(
                    "synthetic/auditor-v1"
                ).root_lineage
                if journal.manifest.bindings.audit_model_selection is not None
                else "sha256:" + hashlib.sha256(key.encode()).hexdigest()
            )
            if resolved_kind is SchedulerTaskKind.MODEL_REQUEST
            else None
        ),
        candidate_ids=candidate_ids,
        model_surface_review_request_manifest_sha256=(
            scheduler_test_model_surface_review_request_manifest_sha256(
                manifest=journal.manifest,
                pass_kind=pass_kind,
                scope=scope,
                task_key=key,
                role=resolved_role,
                candidate_ids=candidate_ids,
            )
            if candidate_review_contract
            else None
        ),
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
                key="independent-verifier",
                role="verifier",
                candidate_ids=candidate_workset.selected_candidate_ids,
            ),
            _task(
                journal,
                pass_kind,
                key="candidate-falsifier-1",
                role="candidate_falsifier",
                candidate_ids=candidate_workset.selected_candidate_ids,
            ),
            _task(
                journal,
                pass_kind,
                key="candidate-falsifier-2",
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
                else (
                    "1" * 64
                    if task.task_kind is SchedulerTaskKind.MODEL_REQUEST
                    else task.input_sha256
                )
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
        "journal-head-checkpoint.json",
        "manifest.json",
        "pass-plans",
        "pass-results",
        "provider-attempts",
        "retrieval-bindings",
        "task-outputs",
        "task-results",
        "truncation-recovery",
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
    review_bindings = tuple(
        require_model_review_pre_dispatch_authorization(authorization)
        for authorization in journal.model_review_pre_dispatch_authorizations
    )
    expected_review_tasks = tuple(
        task
        for plan in journal.plans
        if plan.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
        for task in plan.tasks
    )
    assert {(binding.task_id, binding.request_id) for binding in review_bindings} == {
        (task.task_id, task.logical_request_id) for task in expected_review_tasks
    }
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


def test_dispatch_uses_lexically_captured_review_authority_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert not hasattr(scheduler_module, "_requires_model_review_pre_dispatch_authority")
    blind_journal = create_scheduler_journal(
        tmp_path / "captured-blind",
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    _complete_pass(blind_journal, SchedulerPassKind.ORIENTATION)
    blind_plan = blind_journal.seal_pass_plan(
        _plan(
            blind_journal,
            SchedulerPassKind.BLIND_SHARD_REVIEW,
            task_count=len(SHARDS),
        )
    )
    blind_task = blind_plan.tasks[0]
    rendered_sha256 = "1" * 64
    blind_journal.activate_task(
        blind_task.task_id,
        actual_input_sha256=rendered_sha256,
        system_prompt_sha256=blind_task.system_prompt_sha256,
        user_prompt_sha256=rendered_sha256,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=blind_task.response_schema_sha256,
        delivered_source_descriptor_sha256s=(
            scheduler_test_delivered_source_descriptor_sha256s(blind_plan, blind_task)
        ),
    )
    monkeypatch.setattr(
        scheduler_module,
        "_requires_model_review_pre_dispatch_authority",
        lambda *_args: False,
        raising=False,
    )
    blind_dispatch = blind_journal.mark_dispatched(blind_task.task_id)
    blind_bindings = tuple(
        require_model_review_pre_dispatch_authorization(authorization)
        for authorization in blind_journal.model_review_pre_dispatch_authorizations
    )
    assert len(blind_bindings) == 1
    assert (
        blind_bindings[0].task_id,
        blind_bindings[0].request_id,
        blind_bindings[0].dispatched_event_sha256,
    ) == (
        blind_task.task_id,
        blind_task.logical_request_id,
        blind_dispatch.event_sha256,
    )
    blind_journal.close()

    orientation_journal = create_scheduler_journal(
        tmp_path / "captured-orientation",
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    orientation_plan = orientation_journal.seal_pass_plan(
        _plan(orientation_journal, SchedulerPassKind.ORIENTATION)
    )
    orientation_task = orientation_plan.tasks[0]
    orientation_journal.activate_task(
        orientation_task.task_id,
        actual_input_sha256=rendered_sha256,
        system_prompt_sha256=orientation_task.system_prompt_sha256,
        user_prompt_sha256=rendered_sha256,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=orientation_task.response_schema_sha256,
        delivered_source_descriptor_sha256s=(
            scheduler_test_delivered_source_descriptor_sha256s(
                orientation_plan,
                orientation_task,
            )
        ),
    )
    monkeypatch.setattr(
        scheduler_module,
        "_requires_model_review_pre_dispatch_authority",
        lambda *_args: True,
    )
    orientation_journal.mark_dispatched(orientation_task.task_id)
    assert orientation_journal.model_review_pre_dispatch_authorizations == ()
    orientation_journal.close()


def test_mutable_authority_type_aliases_cannot_replace_ordinary_dispatch_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExplodingBinding:
        def __init__(self, **_kwargs: object) -> None:
            pytest.fail("mutable binding alias constructed during ordinary dispatch")

    class ExplodingAuthorization(tuple[object, ...]):
        pass

    journal = create_scheduler_journal(
        tmp_path / "captured-authority-types",
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    _complete_pass(journal, SchedulerPassKind.ORIENTATION)
    plan = journal.seal_pass_plan(
        _plan(
            journal,
            SchedulerPassKind.BLIND_SHARD_REVIEW,
            task_count=len(SHARDS),
        )
    )
    task = plan.tasks[0]
    rendered_sha256 = "1" * 64
    provider_prompt_sha256 = "2" * 64
    activation = journal.activate_task(
        task.task_id,
        actual_input_sha256=rendered_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256=rendered_sha256,
        provider_prompt_sha256=provider_prompt_sha256,
        response_schema_sha256=task.response_schema_sha256,
        delivered_source_descriptor_sha256s=(
            scheduler_test_delivered_source_descriptor_sha256s(plan, task)
        ),
    )
    monkeypatch.setattr(
        scheduler_module,
        "SchedulerModelReviewPreDispatchBinding",
        ExplodingBinding,
    )
    monkeypatch.setattr(
        scheduler_module,
        "SchedulerModelReviewPreDispatchAuthorization",
        ExplodingAuthorization,
    )

    dispatched = journal.mark_dispatched(task.task_id)
    authorizations = journal.model_review_pre_dispatch_authorizations
    assert len(authorizations) == 1
    authorization = authorizations[0]
    assert type(authorization) is ExactModelReviewPreDispatchAuthorization
    binding = require_model_review_pre_dispatch_authorization(authorization)
    assert type(binding) is ExactModelReviewPreDispatchBinding
    assert task.requested_model is not None
    assert task.root_lineage is not None
    assert task.model_surface_review_request_manifest_sha256 is not None
    assert task.response_schema_sha256 is not None
    assert binding == ExactModelReviewPreDispatchBinding(
        request_id=task.logical_request_id,
        task_id=task.task_id,
        review_role=task.role,
        requested_model=task.requested_model,
        root_lineage=task.root_lineage,
        requested_surface_manifest_sha256=(task.model_surface_review_request_manifest_sha256),
        rendered_context_sha256=rendered_sha256,
        provider_prompt_sha256=provider_prompt_sha256,
        response_schema_sha256=task.response_schema_sha256,
        task_plan_sha256=task.task_plan_sha256,
        activation_sha256=activation.activation_sha256,
        dispatched_event_sha256=dispatched.event_sha256,
    )
    journal.close()


@pytest.mark.parametrize(
    ("field_name", "mutated_value"),
    (
        ("pass_kind", SchedulerPassKind.ORIENTATION),
        ("role", "configuration"),
    ),
)
def test_mutated_review_eligibility_cannot_append_a_dispatch(
    tmp_path: Path,
    field_name: str,
    mutated_value: object,
) -> None:
    journal = create_scheduler_journal(
        tmp_path / f"mutated-eligibility-{field_name}",
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    _complete_pass(journal, SchedulerPassKind.ORIENTATION)
    plan = journal.seal_pass_plan(
        _plan(
            journal,
            SchedulerPassKind.BLIND_SHARD_REVIEW,
            task_count=len(SHARDS),
        )
    )
    task = plan.tasks[0]
    rendered_sha256 = "1" * 64
    journal.activate_task(
        task.task_id,
        actual_input_sha256=rendered_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256=rendered_sha256,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
        delivered_source_descriptor_sha256s=(
            scheduler_test_delivered_source_descriptor_sha256s(plan, task)
        ),
    )
    event_count = len(journal.events)
    original_value = getattr(task, field_name)
    object.__setattr__(task, field_name, mutated_value)
    try:
        with pytest.raises(ValueError, match="eligibility state is not canonically sealed"):
            journal.mark_dispatched(task.task_id)
    finally:
        object.__setattr__(task, field_name, original_value)
    assert len(journal.events) == event_count
    assert journal.model_review_pre_dispatch_authorizations == ()
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
    with pytest.raises(ValueError, match="local journal-head checkpoint does not match"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            expected_terminal_report_authority_required=True,
        )


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


def test_incremental_checkpoint_is_byte_identical_at_every_task_lifecycle_prefix(
    tmp_path: Path,
) -> None:
    journal = create_scheduler_journal(
        tmp_path / "lifecycle-checkpoint",
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )

    def require_exact_checkpoint() -> None:
        assert journal.local_journal_head_checkpoint == journal.journal_evidence

    require_exact_checkpoint()
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    require_exact_checkpoint()
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
    require_exact_checkpoint()
    journal.mark_dispatched(task.task_id)
    require_exact_checkpoint()
    payload = build_scheduler_test_model_payload(plan, task)
    usage = build_scheduler_test_usage(task, activation, validated_output=payload)
    surface_requests, surface_artifact = build_scheduler_test_model_surface_review_custody(
        plan,
        task,
        activation,
        usage,
        payload,
    )
    output = journal.persist_output(
        task.task_id,
        payload,
        usage_record=usage,
        model_surface_review_requests=surface_requests,
        model_surface_review_artifact=surface_artifact,
    )
    require_exact_checkpoint()
    journal.record_terminal(
        SchedulerTaskResult.build(
            plan=plan,
            task=task,
            activation=activation,
            terminal_status=SchedulerTerminalStatus.SUCCEEDED,
            terminal_evidence_sha256=usage.validated_response_sha256,
            output=output,
        )
    )
    require_exact_checkpoint()
    journal.seal_pass_result(plan.pass_kind)
    require_exact_checkpoint()
    journal.close()


@pytest.mark.parametrize(
    "stage",
    ["plan", "activation", "dispatch", "output", "result", "pass-result"],
)
@pytest.mark.parametrize("crash_point", ["refresh-entry", "pending-fsync"])
def test_one_public_mutator_transition_resumes_from_exact_predecessor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    crash_point: str,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    path = tmp_path / f"{stage}-{crash_point}"
    journal = create_scheduler_journal(
        path,
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    plan: SchedulerPassPlan | None = None
    task: SchedulerTaskPlan | None = None
    activation: SchedulerTaskActivation | None = None
    operation: Any
    if stage == "plan":

        def operation() -> object:
            return journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))

    else:
        plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
        task = plan.tasks[0]
        if stage in {"activation", "dispatch", "output"}:
            activation_values = {
                "actual_input_sha256": task.input_sha256,
                "system_prompt_sha256": task.system_prompt_sha256,
                "user_prompt_sha256": "1" * 64,
                "provider_prompt_sha256": "2" * 64,
                "response_schema_sha256": task.response_schema_sha256,
            }
            if stage == "activation":

                def operation() -> object:
                    return journal.activate_task(task.task_id, **activation_values)

            else:
                activation = journal.activate_task(task.task_id, **activation_values)
                if stage == "dispatch":

                    def operation() -> object:
                        return journal.mark_dispatched(task.task_id)

                else:
                    journal.mark_dispatched(task.task_id)
                    payload = build_scheduler_test_model_payload(plan, task)
                    usage = build_scheduler_test_usage(
                        task,
                        activation,
                        validated_output=payload,
                    )

                    def operation() -> object:
                        return journal.persist_output(
                            task.task_id,
                            payload,
                            usage_record=usage,
                        )

        elif stage == "result":
            result = SchedulerTaskResult.build_preflight_failure(
                plan=plan,
                task=task,
                terminal_status=SchedulerTerminalStatus.FAILED,
                terminal_evidence_sha256="d" * 64,
            )

            def operation() -> object:
                return journal.record_preflight_failure(result)

        else:
            journal.record_preflight_failure(
                SchedulerTaskResult.build_preflight_failure(
                    plan=plan,
                    task=task,
                    terminal_status=SchedulerTerminalStatus.FAILED,
                    terminal_evidence_sha256="d" * 64,
                )
            )

            def operation() -> object:
                return journal.seal_pass_result(plan.pass_kind)

    predecessor = journal.journal_evidence
    checkpoint_before = (path / "journal-head-checkpoint.json").read_bytes()
    if crash_point == "refresh-entry":

        def crash_before_refresh() -> NoReturn:
            raise SimulatedProcessDeath

        monkeypatch.setattr(journal, "_refresh_journal_head_checkpoint", crash_before_refresh)
    else:
        original_write = scheduler_module._write_fresh_private_file

        def crash_after_pending_fsync(
            parent_descriptor: int,
            leaf: str,
            content: bytes,
        ) -> None:
            original_write(parent_descriptor, leaf, content)
            if leaf == scheduler_module._JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME:
                raise SimulatedProcessDeath

        monkeypatch.setattr(
            scheduler_module,
            "_write_fresh_private_file",
            crash_after_pending_fsync,
        )
    with pytest.raises(SimulatedProcessDeath):
        operation()
    journal.close()
    monkeypatch.undo()

    assert (path / "journal-head-checkpoint.json").read_bytes() == checkpoint_before
    assert (path / scheduler_module._JOURNAL_TRANSITION_PREDECESSOR_FILENAME).is_file()
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=predecessor,
    )
    assert resumed.local_journal_head_checkpoint == resumed.journal_evidence
    assert not (path / scheduler_module._JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME).exists()
    assert not (path / scheduler_module._JOURNAL_TRANSITION_PREDECESSOR_FILENAME).exists()
    if stage == "dispatch":
        assert resumed.uncertain_task_ids == (task.task_id,)
    elif stage == "output":
        assert resumed.task_results[0].terminal_status is SchedulerTerminalStatus.SUCCEEDED
        assert (
            resumed.task_results[0].output_artifact_sha256
            == resumed.outputs[0].output_artifact_sha256
        )
    elif stage == "result":
        assert resumed.task_results[0].terminal_status is SchedulerTerminalStatus.FAILED
    elif stage == "pass-result":
        assert len(resumed.pass_results) == 1
    resumed.close()

    replayed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    assert replayed.local_journal_head_checkpoint == replayed.journal_evidence
    replayed.close()


def test_host_output_publication_crash_recovers_exact_success_idempotently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    path = tmp_path / "host-output-publication"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    _complete_pass(journal, SchedulerPassKind.ORIENTATION)
    _complete_pass(journal, SchedulerPassKind.BLIND_SHARD_REVIEW)
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.FINDING_REDUCTION))
    task = plan.tasks[0]
    journal.activate_task(
        task.task_id,
        actual_input_sha256=scheduler_test_host_activation_input_sha256(
            plan,
            task,
            candidate_ids=("candidate-critical",),
        ),
    )
    journal.mark_dispatched(task.task_id)
    predecessor = journal.journal_evidence
    payload = build_scheduler_test_host_payload(
        plan,
        task,
        candidate_ids=("candidate-critical",),
    )

    def crash_before_refresh() -> NoReturn:
        raise SimulatedProcessDeath

    monkeypatch.setattr(journal, "_refresh_journal_head_checkpoint", crash_before_refresh)
    with pytest.raises(SimulatedProcessDeath):
        journal.persist_output(task.task_id, payload)
    journal.close()
    monkeypatch.undo()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=predecessor,
    )
    recovered_result = next(
        result for result in resumed.task_results if result.task_id == task.task_id
    )
    recovered_output = next(output for output in resumed.outputs if output.task_id == task.task_id)
    assert recovered_result.terminal_status is SchedulerTerminalStatus.SUCCEEDED
    assert recovered_output.output_sha256 == scheduler_canonical_sha256(payload)
    assert recovered_result.terminal_evidence_sha256 == scheduler_canonical_sha256(
        {
            "classification": "host_computation_completed",
            "output_sha256": recovered_output.output_sha256,
        }
    )
    recovered = resumed.journal_evidence
    resumed.close()

    replayed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=recovered,
    )
    assert replayed.journal_evidence == recovered
    replayed.close()


@pytest.mark.parametrize("stage", ["plan", "activation", "result"])
def test_multi_file_transition_resumes_between_immutable_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    path = tmp_path / f"between-{stage}"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    if stage == "plan":
        plan = _plan(journal, SchedulerPassKind.ORIENTATION)

        def operation() -> object:
            return journal.seal_pass_plan(plan)

    else:
        plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
        task = plan.tasks[0]
        if stage == "activation":

            def operation() -> object:
                return journal.activate_task(
                    task.task_id,
                    actual_input_sha256=task.input_sha256,
                    system_prompt_sha256=task.system_prompt_sha256,
                    user_prompt_sha256="1" * 64,
                    provider_prompt_sha256="2" * 64,
                    response_schema_sha256=task.response_schema_sha256,
                )

        else:
            result = SchedulerTaskResult.build_preflight_failure(
                plan=plan,
                task=task,
                terminal_status=SchedulerTerminalStatus.FAILED,
                terminal_evidence_sha256="d" * 64,
            )

            def operation() -> object:
                return journal.record_preflight_failure(result)

    predecessor = journal.journal_evidence
    original_write_model = scheduler_module._write_model
    durable_writes = 0

    def crash_before_second_artifact(*args: Any, **kwargs: Any) -> None:
        nonlocal durable_writes
        durable_writes += 1
        if durable_writes == 2:
            raise SimulatedProcessDeath
        original_write_model(*args, **kwargs)

    monkeypatch.setattr(scheduler_module, "_write_model", crash_before_second_artifact)
    with pytest.raises(SimulatedProcessDeath):
        operation()
    journal.close()
    monkeypatch.undo()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=predecessor,
    )
    assert resumed.local_journal_head_checkpoint == resumed.journal_evidence
    if stage == "plan":
        assert tuple(item.kind for item in resumed.events) == (SchedulerTaskEventKind.PLANNED,)
    elif stage == "activation":
        assert tuple(item.kind for item in resumed.events)[-1] is SchedulerTaskEventKind.ACTIVATED
    else:
        assert tuple(item.kind for item in resumed.events)[-1] is (
            SchedulerTaskEventKind.PREFLIGHT_TERMINAL
        )
    resumed.close()


def test_resume_rejects_forged_multi_transition_pending_checkpoint(
    tmp_path: Path,
) -> None:
    path = tmp_path / "multi-transition-pending"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    predecessor = journal.journal_evidence
    predecessor_bytes = stable_json(predecessor).encode("utf-8")
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
    current_bytes = stable_json(journal.journal_evidence).encode("utf-8")
    journal.close()

    checkpoint_path = path / "journal-head-checkpoint.json"
    predecessor_path = path / scheduler_module._JOURNAL_TRANSITION_PREDECESSOR_FILENAME
    pending_path = path / scheduler_module._JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME
    checkpoint_path.write_bytes(predecessor_bytes)
    predecessor_path.write_bytes(predecessor_bytes)
    pending_path.write_bytes(current_bytes)
    predecessor_path.chmod(0o600)
    pending_path.chmod(0o600)

    with pytest.raises(ValueError, match="local journal-head checkpoint does not match"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=predecessor,
        )
    assert checkpoint_path.read_bytes() == predecessor_bytes
    assert predecessor_path.read_bytes() == predecessor_bytes
    assert pending_path.read_bytes() == current_bytes


def test_immutable_publication_never_replaces_a_racing_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "no-replace-race"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    original_link = os.link
    target_leaf = "pass-01-plan.json"
    sentinel = b"synthetic racing target"

    def create_target_before_link(source: Any, target: Any, **kwargs: Any) -> None:
        if target == target_leaf:
            target_descriptor = os.open(
                target_leaf,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=kwargs["dst_dir_fd"],
            )
            try:
                os.fchmod(target_descriptor, 0o600)
                os.write(target_descriptor, sentinel)
                os.fsync(target_descriptor)
            finally:
                os.close(target_descriptor)
            os.fsync(kwargs["dst_dir_fd"])
        original_link(source, target, **kwargs)

    monkeypatch.setattr(os, "link", create_target_before_link)
    with pytest.raises(ValueError, match="could not be published safely"):
        journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    monkeypatch.undo()

    assert (path / "pass-plans" / target_leaf).read_bytes() == sentinel
    assert not (
        path / "pass-plans" / scheduler_module._immutable_write_temp_leaf(target_leaf)
    ).exists()
    journal.close()


def test_published_immutable_temp_pair_is_finalized_and_recovered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    path = tmp_path / "published-pair"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    predecessor = journal.journal_evidence
    target_leaf = "pass-01-plan.json"
    temporary_leaf = scheduler_module._immutable_write_temp_leaf(target_leaf)
    original_unlink = os.unlink

    def crash_before_temp_unlink(candidate: Any, **kwargs: Any) -> None:
        if candidate == temporary_leaf:
            raise SimulatedProcessDeath
        original_unlink(candidate, **kwargs)

    monkeypatch.setattr(os, "unlink", crash_before_temp_unlink)
    with pytest.raises(SimulatedProcessDeath):
        journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    journal.close()
    monkeypatch.undo()

    target_path = path / "pass-plans" / target_leaf
    temporary_path = path / "pass-plans" / temporary_leaf
    assert target_path.stat().st_ino == temporary_path.stat().st_ino
    assert target_path.stat().st_nlink == 2
    paired_bytes = target_path.read_bytes()
    donor = create_scheduler_journal(
        tmp_path / "published-pair-donor",
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    donor.seal_pass_plan(_plan(donor, SchedulerPassKind.ORIENTATION))
    wrong_expected = donor.journal_evidence
    donor.close()
    with pytest.raises(ValueError, match="resume journal evidence does not match"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=wrong_expected,
        )
    assert target_path.read_bytes() == paired_bytes
    assert temporary_path.read_bytes() == paired_bytes
    assert target_path.stat().st_ino == temporary_path.stat().st_ino
    assert target_path.stat().st_nlink == 2

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=predecessor,
    )
    assert not temporary_path.exists()
    assert target_path.stat().st_nlink == 1
    assert len(resumed.plans) == 1
    assert resumed.local_journal_head_checkpoint == resumed.journal_evidence
    resumed.close()


def test_checkpoint_replacement_before_predecessor_cleanup_resumes_exactly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    path = tmp_path / "checkpoint-replaced"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    predecessor = journal.journal_evidence
    original_unlink = scheduler_module._unlink_exact_private_file

    def crash_before_predecessor_cleanup(
        parent_descriptor: int,
        leaf: str,
        content: bytes,
    ) -> None:
        if leaf == scheduler_module._JOURNAL_TRANSITION_PREDECESSOR_FILENAME:
            raise SimulatedProcessDeath
        original_unlink(parent_descriptor, leaf, content)

    monkeypatch.setattr(
        scheduler_module,
        "_unlink_exact_private_file",
        crash_before_predecessor_cleanup,
    )
    with pytest.raises(SimulatedProcessDeath):
        journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    journal.close()
    monkeypatch.undo()

    assert (path / scheduler_module._JOURNAL_TRANSITION_PREDECESSOR_FILENAME).is_file()
    assert (
        SchedulerJournalEvidence.model_validate_json(
            (path / "journal-head-checkpoint.json").read_bytes()
        ).pass_plan_count
        == 1
    )
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=predecessor,
    )
    assert resumed.local_journal_head_checkpoint == resumed.journal_evidence
    assert not (path / scheduler_module._JOURNAL_TRANSITION_PREDECESSOR_FILENAME).exists()
    resumed.close()


@pytest.mark.parametrize("recovery_crash_point", ["event-publication", "checkpoint-pending"])
def test_plan_missing_event_recovery_survives_a_second_process_death(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    recovery_crash_point: str,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    path = tmp_path / f"plan-recovery-{recovery_crash_point}"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    predecessor = journal.journal_evidence
    original_write_model = scheduler_module._write_model
    writes = 0

    def crash_before_planned_event(*args: Any, **kwargs: Any) -> None:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise SimulatedProcessDeath
        original_write_model(*args, **kwargs)

    monkeypatch.setattr(scheduler_module, "_write_model", crash_before_planned_event)
    with pytest.raises(SimulatedProcessDeath):
        journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    journal.close()
    monkeypatch.undo()

    original_publish = scheduler_module._write_fresh_private_file

    def crash_during_recovery(parent_descriptor: int, leaf: str, content: bytes) -> None:
        original_publish(parent_descriptor, leaf, content)
        if (recovery_crash_point == "event-publication" and leaf == "event-00000000.json") or (
            recovery_crash_point == "checkpoint-pending"
            and leaf == scheduler_module._JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME
        ):
            raise SimulatedProcessDeath

    monkeypatch.setattr(
        scheduler_module,
        "_write_fresh_private_file",
        crash_during_recovery,
    )
    with pytest.raises(SimulatedProcessDeath):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=predecessor,
        )
    monkeypatch.undo()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=predecessor,
    )
    assert tuple(item.kind for item in resumed.events) == (SchedulerTaskEventKind.PLANNED,)
    recovered = resumed.journal_evidence
    resumed.close()
    replayed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=recovered,
    )
    assert replayed.journal_evidence == recovered
    replayed.close()


@pytest.mark.parametrize("retained_runtime", ["output", "attempt"])
@pytest.mark.parametrize("recovery_crash_point", ["result-publication", "checkpoint-pending"])
def test_derived_terminal_recovery_survives_a_second_process_death(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    retained_runtime: str,
    recovery_crash_point: str,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    path = tmp_path / f"{retained_runtime}-recovery-{recovery_crash_point}"
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
    if retained_runtime == "output":
        usage = build_scheduler_test_usage(task, activation, validated_output=payload)
        journal.persist_output(task.task_id, payload, usage_record=usage)
    else:
        journal.persist_provider_attempt(
            task.task_id,
            _failed_accountable_mock_usage(
                plan,
                task,
                activation,
                reported_cost_usd_exact=None,
                accounted_cost_usd_exact="0",
            ),
        )
    predecessor = journal.journal_evidence
    journal.close()

    original_publish = scheduler_module._write_fresh_private_file

    def crash_during_recovery(parent_descriptor: int, leaf: str, content: bytes) -> None:
        original_publish(parent_descriptor, leaf, content)
        if (
            recovery_crash_point == "result-publication" and leaf.startswith(f"{task.task_id}-")
        ) or (
            recovery_crash_point == "checkpoint-pending"
            and leaf == scheduler_module._JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME
        ):
            raise SimulatedProcessDeath

    monkeypatch.setattr(
        scheduler_module,
        "_write_fresh_private_file",
        crash_during_recovery,
    )
    with pytest.raises(SimulatedProcessDeath):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=predecessor,
        )
    monkeypatch.undo()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=predecessor,
    )
    expected_status = (
        SchedulerTerminalStatus.SUCCEEDED
        if retained_runtime == "output"
        else SchedulerTerminalStatus.UNCERTAIN
    )
    assert resumed.task_results[0].terminal_status is expected_status
    assert resumed.local_journal_head_checkpoint == resumed.journal_evidence
    recovered = resumed.journal_evidence
    resumed.close()
    replayed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=recovered,
    )
    assert replayed.journal_evidence == recovered
    replayed.close()


@pytest.mark.parametrize("second_crash", ["result-publication", "checkpoint-pending"])
def test_uncheckpointed_dispatch_survives_a_second_recovery_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    second_crash: str,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    path = tmp_path / f"dispatch-recovery-{second_crash}"
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
    predecessor = journal.journal_evidence

    def crash_before_dispatch_checkpoint() -> NoReturn:
        raise SimulatedProcessDeath

    monkeypatch.setattr(
        journal,
        "_refresh_journal_head_checkpoint",
        crash_before_dispatch_checkpoint,
    )
    with pytest.raises(SimulatedProcessDeath):
        journal.mark_dispatched(task.task_id)
    journal.close()
    monkeypatch.undo()

    original_publish = scheduler_module._write_fresh_private_file

    def crash_during_recovered_terminal(
        parent_descriptor: int,
        leaf: str,
        content: bytes,
    ) -> None:
        original_publish(parent_descriptor, leaf, content)
        if (second_crash == "result-publication" and leaf.startswith(f"{task.task_id}-")) or (
            second_crash == "checkpoint-pending"
            and leaf == scheduler_module._JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME
            and SchedulerJournalEvidence.model_validate_json(content).uncertain_count == 1
        ):
            raise SimulatedProcessDeath

    monkeypatch.setattr(
        scheduler_module,
        "_write_fresh_private_file",
        crash_during_recovered_terminal,
    )
    with pytest.raises(SimulatedProcessDeath):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=predecessor,
        )
    monkeypatch.undo()

    phase_snapshot = _journal_private_file_snapshot(path)
    with pytest.raises(ValueError, match="resume journal evidence does not match"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=predecessor,
        )
    assert _journal_private_file_snapshot(path) == phase_snapshot

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    assert resumed.task_results[0].terminal_status is SchedulerTerminalStatus.UNCERTAIN
    recovered = resumed.journal_evidence
    resumed.close()
    replayed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=recovered,
    )
    assert replayed.journal_evidence == recovered
    replayed.close()


@pytest.mark.parametrize(
    ("terminal_status", "checkpointed_attempt"),
    (
        (SchedulerTerminalStatus.FAILED, False),
        (SchedulerTerminalStatus.FAILED, True),
        (SchedulerTerminalStatus.INVALID, False),
        (SchedulerTerminalStatus.INVALID, True),
        (SchedulerTerminalStatus.UNBOUND, False),
        (SchedulerTerminalStatus.UNBOUND, True),
        (SchedulerTerminalStatus.INCONCLUSIVE, False),
        (SchedulerTerminalStatus.INCONCLUSIVE, True),
        (SchedulerTerminalStatus.EXPLICIT_EMPTY, False),
    ),
)
def test_terminal_observation_crash_replays_exact_result_instead_of_uncertain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    checkpointed_attempt: bool,
    terminal_status: SchedulerTerminalStatus,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    path = tmp_path / f"terminal-prefix-{checkpointed_attempt}-{terminal_status.value}"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    if terminal_status is SchedulerTerminalStatus.EXPLICIT_EMPTY:
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
        plan = journal.seal_pass_plan(
            _plan(
                journal,
                SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
                task_kind=SchedulerTaskKind.EMPTY_COMPLETION,
            )
        )
    else:
        plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    activation = journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=(
            task.system_prompt_sha256 if task.task_kind is SchedulerTaskKind.MODEL_REQUEST else None
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
    journal.mark_dispatched(task.task_id)
    if checkpointed_attempt:
        journal.persist_provider_attempt(
            task.task_id,
            _failed_accountable_mock_usage(
                plan,
                task,
                activation,
                reported_cost_usd_exact=None,
                accounted_cost_usd_exact="0",
            ),
        )
    predecessor = journal.journal_evidence
    expected_result = SchedulerTaskResult.build(
        plan=plan,
        task=task,
        activation=activation,
        terminal_status=terminal_status,
        terminal_evidence_sha256=scheduler_canonical_sha256(
            {
                "classification": "synthetic_terminal_prefix",
                "terminal_status": terminal_status.value,
            }
        ),
    )

    def crash_before_terminal_event(**_values: Any) -> NoReturn:
        raise SimulatedProcessDeath

    monkeypatch.setattr(journal, "_append_event", crash_before_terminal_event)
    with pytest.raises(SimulatedProcessDeath):
        journal.record_terminal(expected_result)
    assert tuple(item for item in journal.result_observations if item.task_id == task.task_id) == (
        expected_result,
    )
    assert tuple(item for item in journal.task_results if item.task_id == task.task_id) == ()
    journal.close()
    monkeypatch.undo()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=predecessor,
    )
    assert tuple(item for item in resumed.task_results if item.task_id == task.task_id) == (
        expected_result,
    )
    assert tuple(item for item in resumed.result_observations if item.task_id == task.task_id) == (
        expected_result,
    )
    assert resumed.events[-1].kind is SchedulerTaskEventKind.TERMINAL
    assert resumed.events[-1].task_result_sha256 == expected_result.result_sha256
    recovered = resumed.journal_evidence
    resumed.close()

    replayed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=recovered,
    )
    assert replayed.journal_evidence == recovered
    assert tuple(item for item in replayed.task_results if item.task_id == task.task_id) == (
        expected_result,
    )
    replayed.close()


@pytest.mark.parametrize("second_crash", ["result-publication", "checkpoint-pending"])
def test_uncheckpointed_provider_attempt_survives_a_second_recovery_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    second_crash: str,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    path = tmp_path / f"attempt-recovery-{second_crash}"
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
    dispatch = journal.mark_dispatched(task.task_id)
    predecessor = journal.journal_evidence

    def crash_before_attempt_checkpoint() -> NoReturn:
        raise SimulatedProcessDeath

    monkeypatch.setattr(
        journal,
        "_refresh_journal_head_checkpoint",
        crash_before_attempt_checkpoint,
    )
    with pytest.raises(SimulatedProcessDeath):
        journal.persist_provider_attempt(
            task.task_id,
            _failed_accountable_mock_usage(
                plan,
                task,
                activation,
                reported_cost_usd_exact=None,
                accounted_cost_usd_exact="0",
            ),
        )
    journal.close()
    monkeypatch.undo()

    original_publish = scheduler_module._write_fresh_private_file

    def crash_during_recovered_terminal(
        parent_descriptor: int,
        leaf: str,
        content: bytes,
    ) -> None:
        original_publish(parent_descriptor, leaf, content)
        if (second_crash == "result-publication" and leaf.startswith(f"{task.task_id}-")) or (
            second_crash == "checkpoint-pending"
            and leaf == scheduler_module._JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME
            and SchedulerJournalEvidence.model_validate_json(content).uncertain_count == 1
        ):
            raise SimulatedProcessDeath

    monkeypatch.setattr(
        scheduler_module,
        "_write_fresh_private_file",
        crash_during_recovered_terminal,
    )
    with pytest.raises(SimulatedProcessDeath):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=predecessor,
        )
    monkeypatch.undo()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    assert resumed.task_results[0].terminal_status is SchedulerTerminalStatus.UNCERTAIN
    assert resumed.task_results[0].terminal_evidence_sha256 == scheduler_canonical_sha256(
        {
            "classification": "dispatch_without_terminal",
            "dispatch_event_sha256": dispatch.event_sha256,
        }
    )
    recovered = resumed.journal_evidence
    resumed.close()
    replayed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=recovered,
    )
    assert replayed.journal_evidence == recovered
    replayed.close()


def test_uncheckpointed_provider_attempt_rejects_an_arbitrary_terminal_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    path = tmp_path / "attempt-arbitrary-terminal"
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
    predecessor = journal.journal_evidence

    def crash_before_checkpoint() -> NoReturn:
        raise SimulatedProcessDeath

    monkeypatch.setattr(journal, "_refresh_journal_head_checkpoint", crash_before_checkpoint)
    with pytest.raises(SimulatedProcessDeath):
        journal.persist_provider_attempt(
            task.task_id,
            _failed_accountable_mock_usage(
                plan,
                task,
                activation,
                reported_cost_usd_exact=None,
                accounted_cost_usd_exact="0",
            ),
        )
    arbitrary = SchedulerTaskResult.build(
        plan=plan,
        task=task,
        activation=activation,
        terminal_status=SchedulerTerminalStatus.FAILED,
        terminal_evidence_sha256="f" * 64,
    )
    with pytest.raises(SimulatedProcessDeath):
        journal.record_terminal(arbitrary)
    journal.close()
    monkeypatch.undo()

    before = _journal_private_file_snapshot(path)
    with pytest.raises(ValueError, match="checkpoint does not match durable journal evidence"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=predecessor,
        )
    assert _journal_private_file_snapshot(path) == before


@pytest.mark.parametrize("artifact_kind", ["result", "output", "attempt"])
def test_terminal_checkpoint_rejects_fresh_same_task_runtime_evidence(
    tmp_path: Path,
    artifact_kind: str,
) -> None:
    path = tmp_path / f"terminal-plus-{artifact_kind}"
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
    dispatch = journal.mark_dispatched(task.task_id)
    canonical = SchedulerTaskResult.build(
        plan=plan,
        task=task,
        activation=activation,
        terminal_status=SchedulerTerminalStatus.UNCERTAIN,
        terminal_evidence_sha256=scheduler_canonical_sha256(
            {
                "classification": "dispatch_without_terminal",
                "dispatch_event_sha256": dispatch.event_sha256,
            }
        ),
    )
    journal.record_terminal(canonical)
    predecessor = journal.journal_evidence
    if artifact_kind == "result":
        unreachable_result = SchedulerTaskResult.build(
            plan=plan,
            task=task,
            activation=activation,
            terminal_status=SchedulerTerminalStatus.FAILED,
            terminal_evidence_sha256="f" * 64,
        )
        scheduler_module._write_model(
            journal._root_descriptor,
            journal._directory_descriptors,
            scheduler_module._task_result_path(unreachable_result),
            unreachable_result,
        )
        journal._retain_result_observation(unreachable_result)
    elif artifact_kind == "output":
        payload = build_scheduler_test_model_payload(plan, task)
        unreachable_output = SchedulerTaskOutput.build(
            plan=plan,
            task=task,
            activation=activation,
            payload=payload,
            usage_record=build_scheduler_test_usage(
                task,
                activation,
                validated_output=payload,
            ),
        )
        scheduler_module._write_model(
            journal._root_descriptor,
            journal._directory_descriptors,
            scheduler_module._task_output_path(unreachable_output),
            unreachable_output,
        )
        journal._retain_output(unreachable_output)
    else:
        unreachable_attempt = SchedulerProviderAttemptEvidence.build(
            task=task,
            activation=activation,
            usage_record=_failed_accountable_mock_usage(
                plan,
                task,
                activation,
                reported_cost_usd_exact=None,
                accounted_cost_usd_exact="0",
            ),
            audit_model_selection=journal.manifest.bindings.audit_model_selection,
            audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
            audit_model_refresh_pricing=(journal.manifest.bindings.audit_model_refresh_pricing),
        )
        scheduler_module._write_model(
            journal._root_descriptor,
            journal._directory_descriptors,
            scheduler_module._provider_attempt_path(unreachable_attempt),
            unreachable_attempt,
        )
        journal._retain_provider_attempt(unreachable_attempt)
    journal.close()

    before = _journal_private_file_snapshot(path)
    with pytest.raises(ValueError, match="checkpoint does not match durable journal evidence"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=predecessor,
        )
    assert _journal_private_file_snapshot(path) == before


def test_partial_immutable_temp_is_cleaned_only_after_expected_predecessor_join(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    path = tmp_path / "partial-immutable"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    predecessor = journal.journal_evidence
    target_leaf = "pass-01-plan.json"
    temporary_leaf = scheduler_module._immutable_write_temp_leaf(target_leaf)
    original_write = scheduler_module._write_exclusive_private_file

    def leave_partial_temp(parent_descriptor: int, leaf: str, content: bytes) -> None:
        if leaf != temporary_leaf:
            original_write(parent_descriptor, leaf, content)
            return
        descriptor = os.open(
            leaf,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=parent_descriptor,
        )
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, content[:11])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_descriptor)
        raise SimulatedProcessDeath

    monkeypatch.setattr(
        scheduler_module,
        "_write_exclusive_private_file",
        leave_partial_temp,
    )
    with pytest.raises(SimulatedProcessDeath):
        journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    journal.close()
    monkeypatch.undo()

    temporary_path = path / "pass-plans" / temporary_leaf
    assert temporary_path.read_bytes()
    assert not (path / "pass-plans" / target_leaf).exists()
    donor = create_scheduler_journal(
        tmp_path / "donor",
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    donor.seal_pass_plan(_plan(donor, SchedulerPassKind.ORIENTATION))
    wrong_expected = donor.journal_evidence
    donor.close()
    with pytest.raises(ValueError, match="resume journal evidence does not match"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=wrong_expected,
        )
    assert temporary_path.is_file()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=predecessor,
    )
    assert not temporary_path.exists()
    assert resumed.plans == ()
    sealed = resumed.seal_pass_plan(_plan(resumed, SchedulerPassKind.ORIENTATION))
    assert (path / "pass-plans" / target_leaf).read_bytes() == stable_json(sealed).encode("utf-8")
    resumed.close()


def test_partial_checkpoint_staging_temp_recovers_exact_plan_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    path = tmp_path / "partial-checkpoint-staging"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    predecessor = journal.journal_evidence
    checkpoint_temp = scheduler_module._immutable_write_temp_leaf(
        scheduler_module._JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME
    )
    original_write = scheduler_module._write_exclusive_private_file

    def leave_partial_checkpoint(parent_descriptor: int, leaf: str, content: bytes) -> None:
        if leaf != checkpoint_temp:
            original_write(parent_descriptor, leaf, content)
            return
        descriptor = os.open(
            leaf,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=parent_descriptor,
        )
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, content[:17])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_descriptor)
        raise SimulatedProcessDeath

    monkeypatch.setattr(
        scheduler_module,
        "_write_exclusive_private_file",
        leave_partial_checkpoint,
    )
    with pytest.raises(SimulatedProcessDeath):
        journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    journal.close()
    monkeypatch.undo()

    checkpoint_temp_path = path / checkpoint_temp
    assert checkpoint_temp_path.is_file()
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=predecessor,
    )
    assert len(resumed.plans) == 1
    assert resumed.local_journal_head_checkpoint == resumed.journal_evidence
    assert not checkpoint_temp_path.exists()
    assert not (path / scheduler_module._JOURNAL_TRANSITION_PREDECESSOR_FILENAME).exists()
    resumed.close()


def test_returned_output_payload_cannot_mutate_retained_checkpoint_state(
    tmp_path: Path,
) -> None:
    journal = create_scheduler_journal(
        tmp_path / "detached-output",
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
        delivered_source_descriptor_sha256s=(
            scheduler_test_delivered_source_descriptor_sha256s(plan, task)
        ),
    )
    journal.mark_dispatched(task.task_id)
    payload = build_scheduler_test_model_payload(plan, task)
    usage = build_scheduler_test_usage(task, activation, validated_output=payload)
    surface_requests, surface_artifact = build_scheduler_test_model_surface_review_custody(
        plan,
        task,
        activation,
        usage,
        payload,
    )
    output = journal.persist_output(
        task.task_id,
        payload,
        usage_record=usage,
        model_surface_review_requests=surface_requests,
        model_surface_review_artifact=surface_artifact,
    )
    durable_payload = journal.load_output(task.task_id)
    returned_payload = output.payload
    assert isinstance(returned_payload, dict)
    returned_assets = returned_payload["assets"]
    assert isinstance(returned_assets, list)
    returned_assets.append("caller-owned mutation")

    exposed_payload = journal.outputs[0].payload
    assert isinstance(exposed_payload, dict)
    exposed_assets = exposed_payload["assets"]
    assert isinstance(exposed_assets, list)
    exposed_assets.append("outward-property mutation")

    journal.record_terminal(
        SchedulerTaskResult.build(
            plan=plan,
            task=task,
            activation=activation,
            terminal_status=SchedulerTerminalStatus.SUCCEEDED,
            terminal_evidence_sha256=usage.validated_response_sha256,
            output=output,
        )
    )
    assert journal.load_output(task.task_id) == durable_payload
    assert journal.local_journal_head_checkpoint == journal.journal_evidence
    journal.close()


def test_returned_pass_result_indexes_cannot_mutate_retained_checkpoint_state(
    tmp_path: Path,
) -> None:
    journal = create_scheduler_journal(
        tmp_path / "detached-pass-result",
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    returned = _seal_failed_preflight_pass(
        journal,
        _plan(journal, SchedulerPassKind.ORIENTATION),
    )
    returned.plan._tasks_by_id.clear()

    exposed = journal.pass_results[0]
    exposed.plan._tasks_by_id.clear()

    retained = journal.pass_results[0]
    assert retained.plan.has_exact_task(retained.plan.tasks[0])
    assert journal.local_journal_head_checkpoint == journal.journal_evidence
    journal.close()


def test_task_transition_checkpoint_does_not_reload_full_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = create_scheduler_journal(
        tmp_path / "incremental-transition",
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    original_load_state = scheduler_module._load_state
    load_calls = 0

    def counted_load_state(*args: Any, **kwargs: Any) -> Any:
        nonlocal load_calls
        load_calls += 1
        return original_load_state(*args, **kwargs)

    monkeypatch.setattr(scheduler_module, "_load_state", counted_load_state)
    task = plan.tasks[0]
    journal.record_preflight_failure(
        SchedulerTaskResult.build_preflight_failure(
            plan=plan,
            task=task,
            terminal_status=SchedulerTerminalStatus.FAILED,
            terminal_evidence_sha256="d" * 64,
        )
    )
    assert load_calls == 0
    assert journal.local_journal_head_checkpoint == journal.journal_evidence
    assert load_calls == 1
    journal.close()


@pytest.mark.parametrize(
    "mutation",
    ["same-inode", "replacement", "delete", "extra"],
)
def test_active_transition_rejects_retained_artifact_tamper_before_checkpoint_advance(
    tmp_path: Path,
    mutation: str,
) -> None:
    path = tmp_path / f"active-tamper-{mutation}"
    journal = create_scheduler_journal(
        path,
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    checkpoint_path = path / "journal-head-checkpoint.json"
    checkpoint_before = checkpoint_path.read_bytes()
    target = path / "events" / "event-00000000.json"
    if mutation == "same-inode":
        metadata = target.stat()
        content = bytearray(target.read_bytes())
        marker = b'"event_sha256": "'
        offset = content.index(marker) + len(marker)
        content[offset] = ord("0") if content[offset] != ord("0") else ord("1")
        target.write_bytes(content)
        os.utime(
            target,
            ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
        )
    elif mutation == "replacement":
        replacement = target.with_name(".event-replacement")
        replacement.write_bytes(target.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(target)
    elif mutation == "delete":
        target.unlink()
    else:
        extra = path / "events" / "unmanifested.json"
        extra.write_text("{}\n", encoding="utf-8")
        extra.chmod(0o600)

    task = plan.tasks[0]
    with pytest.raises(ValueError, match=r"retained artifact|unmanifested"):
        journal.record_preflight_failure(
            SchedulerTaskResult.build_preflight_failure(
                plan=plan,
                task=task,
                terminal_status=SchedulerTerminalStatus.FAILED,
                terminal_evidence_sha256="d" * 64,
            )
        )
    assert checkpoint_path.read_bytes() == checkpoint_before
    journal.close()


def test_active_transition_rejects_replacement_during_fast_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "active-projection-race"
    journal = create_scheduler_journal(
        path,
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    checkpoint_path = path / "journal-head-checkpoint.json"
    checkpoint_before = checkpoint_path.read_bytes()
    target = path / "events" / "event-00000000.json"
    original_projection = SchedulerJournal._build_retained_journal_evidence
    replaced = False

    def project_then_replace(self: SchedulerJournal) -> SchedulerJournalEvidence:
        nonlocal replaced
        evidence = original_projection(self)
        if self is journal and not replaced:
            replacement = target.with_name(".event-race-replacement")
            replacement.write_bytes(target.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(target)
            replaced = True
        return evidence

    monkeypatch.setattr(
        SchedulerJournal,
        "_build_retained_journal_evidence",
        project_then_replace,
    )
    task = plan.tasks[0]
    with pytest.raises(ValueError, match="changed during checkpoint projection"):
        journal.record_preflight_failure(
            SchedulerTaskResult.build_preflight_failure(
                plan=plan,
                task=task,
                terminal_status=SchedulerTerminalStatus.FAILED,
                terminal_evidence_sha256="d" * 64,
            )
        )
    assert replaced
    assert checkpoint_path.read_bytes() == checkpoint_before
    journal.close()


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
        **kwargs: Any,
    ) -> Any:
        nonlocal replaced
        model = original_read_model(
            root_descriptor,
            directory_descriptors,
            relative,
            model_type,
            **kwargs,
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
async def test_failed_paid_attempt_survives_structural_resume_without_runtime_authority(
    tmp_path: Path,
    validation_status: ModelRequestValidationStatus,
    status: str,
    classification: str,
    error: BaseException,
    terminal_status: SchedulerTerminalStatus,
) -> None:
    exact_cost = Decimal("0.125")
    path = tmp_path / classification
    journal = create_scheduler_journal(
        path,
        bindings=_bindings(with_audit_policy=True),
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
    successful_usage = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=payload,
        cost_usd_exact=str(exact_cost),
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
        audit_model_selection=journal.manifest.bindings.audit_model_selection,
        audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
        audit_model_refresh_pricing=(journal.manifest.bindings.audit_model_refresh_pricing),
    )
    failed_usage = reattest_synthetic_real_usage(
        successful_usage.model_copy(
            update={
                "identity_strength": ModelIdentityStrength.UNBOUND,
                "provider": (
                    None
                    if classification in {"timeout", "rate_limit"}
                    else successful_usage.provider
                ),
                "actual_provider_endpoint": (
                    None
                    if classification in {"timeout", "rate_limit"}
                    else successful_usage.actual_provider_endpoint
                ),
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
    assert attempt.audit_policy_selection_binding_sha256 is not None
    assert attempt.audit_model_refresh_binding_sha256 is not None
    assert attempt.audit_model_refresh_pricing_binding_sha256 is not None
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

    with pytest.raises(ValueError, match="requires live model-refresh authority"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(with_audit_policy=True),
            expected_shard_inventory=_inventory(),
        )
    verification = open_scheduler_journal_for_verification(
        path,
        expected_bindings=_bindings(with_audit_policy=True),
        expected_shard_inventory=_inventory(),
    )
    serialized = verification.restorable_usage_records
    assert len(serialized) == 1
    assert is_structurally_accountable_usage_record(serialized[0], require_real=True)
    assert verification.restorable_context_request_evidence == (
        verification.provider_attempts[0].context_request_evidence,
    )
    with pytest.raises(ValueError, match="read-only"):
        verification.claim_restorable_usage_for_budget_recovery(atomic_ledger=ledger)
    assert ledger.snapshot() == before_resume
    verification.close()


def test_failed_paid_provider_attempt_rejects_missing_audit_policy_custody(
    tmp_path: Path,
) -> None:
    journal = create_scheduler_journal(
        tmp_path / "missing-attempt-policy",
        bindings=_bindings(with_audit_policy=True),
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
    usage = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=payload,
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
    )
    failed_usage = reattest_synthetic_real_usage(
        usage.model_copy(
            update={
                "identity_strength": ModelIdentityStrength.UNBOUND,
                "provider_error_classification": "timeout",
                "status": "provider_error",
                "validation_status": ModelRequestValidationStatus.PROVIDER_ERROR,
            }
        )
    )

    with pytest.raises(ValueError, match="lacks audit policy selection evidence"):
        journal.persist_provider_attempt(task.task_id, failed_usage)
    assert journal.provider_attempts == ()
    journal.close()


def test_refresh_only_legacy_binding_cannot_persist_or_recover_real_usage(
    tmp_path: Path,
) -> None:
    path = tmp_path / "refresh-only-real-usage"
    bindings = _refresh_only_bindings()
    journal = create_scheduler_journal(
        path,
        bindings=bindings,
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
    usage = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=payload,
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
        audit_model_selection=bindings.audit_model_selection,
        audit_model_refresh=bindings.audit_model_refresh,
        include_audit_model_refresh_pricing=False,
    )

    with pytest.raises(ValueError, match="lacks refreshed-price evidence"):
        journal.persist_output(task.task_id, payload, usage_record=usage)
    with pytest.raises(ValueError, match="lacks refreshed-price evidence"):
        journal.persist_provider_attempt(task.task_id, usage)
    assert journal.outputs == ()
    assert journal.provider_attempts == ()
    journal.close()

    with pytest.raises(ValueError, match="requires live model-refresh authority"):
        resume_scheduler_journal(
            path,
            expected_bindings=bindings,
            expected_shard_inventory=_inventory(),
        )


def test_scheduler_bindings_reject_resealed_pricing_selection_capability_drift() -> None:
    bindings = _bindings(with_audit_policy=True)
    pricing = bindings.audit_model_refresh_pricing
    assert pricing is not None
    pricing_values = pricing.model_dump(mode="python", exclude={"binding_sha256"})
    pricing_values["audit_selection_capability_sha256"] = "f" * 64
    resealed_pricing = SchedulerAuditModelRefreshPricingBinding.model_validate(
        {
            **pricing_values,
            "binding_sha256": scheduler_canonical_sha256(pricing_values),
        }
    )
    binding_values = bindings.model_dump(mode="python", exclude={"bindings_sha256"})
    binding_values["audit_model_refresh_pricing"] = resealed_pricing

    with pytest.raises(
        ValueError,
        match="pricing differs from exact refresh and selection custody",
    ):
        SchedulerBindings.model_validate(
            {
                **binding_values,
                "bindings_sha256": scheduler_canonical_sha256(binding_values),
            }
        )


def test_resume_rejects_coherently_swapped_provider_attempt_audit_selection(
    tmp_path: Path,
) -> None:
    path = tmp_path / "swapped-attempt-policy"
    original_bindings = _bindings(
        with_audit_policy=True,
        audit_policy_seed="scheduler-attempt-original",
    )
    journal = create_scheduler_journal(
        path,
        bindings=original_bindings,
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
    original_usage = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=payload,
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
        audit_model_selection=journal.manifest.bindings.audit_model_selection,
        audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
    )
    original_failed_usage = reattest_synthetic_real_usage(
        original_usage.model_copy(
            update={
                "identity_strength": ModelIdentityStrength.UNBOUND,
                "provider_error_classification": "timeout",
                "status": "provider_error",
                "validation_status": ModelRequestValidationStatus.PROVIDER_ERROR,
            }
        )
    )
    PipelineScheduler(journal).record_failure(
        task,
        TimeoutError("synthetic provider timeout"),
        usage_records=(original_failed_usage,),
    )
    campaign = journal.manifest
    journal.close()

    swapped_selection = build_scheduler_test_audit_model_selection_binding(
        source_sha256=campaign.bindings.source_sha256,
        selected_routes=(
            (
                task.requested_model or "",
                task.root_lineage or "",
                "Synthetic Provider",
                "synthetic-provider",
            ),
        ),
        seed="scheduler-attempt-swapped",
    )
    swapped_refresh = build_scheduler_test_audit_model_refresh_binding(
        swapped_selection,
        seed="scheduler-attempt-swapped:refresh",
    )
    swapped_pricing = build_scheduler_test_audit_model_refresh_pricing_binding(
        swapped_selection,
        swapped_refresh,
    )
    swapped_usage = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=payload,
        privacy_evidence_custody=campaign.privacy_evidence_custody,
        audit_model_selection=swapped_selection,
        audit_model_refresh=swapped_refresh,
        audit_model_refresh_pricing=swapped_pricing,
    )
    swapped_failed_usage = reattest_synthetic_real_usage(
        swapped_usage.model_copy(
            update={
                "identity_strength": ModelIdentityStrength.UNBOUND,
                "provider_error_classification": "timeout",
                "status": "provider_error",
                "validation_status": ModelRequestValidationStatus.PROVIDER_ERROR,
            }
        )
    )
    swapped_attempt = SchedulerProviderAttemptEvidence.build(
        task=task,
        activation=activation,
        usage_record=swapped_failed_usage,
        audit_model_selection=swapped_selection,
        audit_model_refresh=swapped_refresh,
        audit_model_refresh_pricing=swapped_pricing,
    )
    attempt_path = next((path / "provider-attempts").glob("*.json"))
    attempt_path.write_text(stable_json(swapped_attempt), encoding="utf-8")
    attempt_path.rename(
        attempt_path.with_name(
            f"{swapped_attempt.task_id}-{swapped_attempt.attempt_evidence_sha256}.json"
        )
    )

    with pytest.raises(ValueError, match="differs from audit policy selection"):
        open_scheduler_journal_for_verification(
            path,
            expected_bindings=original_bindings,
            expected_shard_inventory=_inventory(),
        )


def test_resume_rejects_coherently_resealed_failed_attempt_with_unbound_refresh_route(
    tmp_path: Path,
) -> None:
    path = tmp_path / "resealed-attempt-refresh-route"
    bindings = _bindings(with_audit_policy=True)
    journal = create_scheduler_journal(
        path,
        bindings=bindings,
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
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
        audit_model_selection=bindings.audit_model_selection,
        audit_model_refresh=bindings.audit_model_refresh,
    )
    exact_failed_usage = reattest_synthetic_real_usage(
        exact_usage.model_copy(
            update={
                "identity_strength": ModelIdentityStrength.UNBOUND,
                "provider_error_classification": "timeout",
                "status": "provider_error",
                "validation_status": ModelRequestValidationStatus.PROVIDER_ERROR,
            }
        )
    )
    journal.persist_provider_attempt(task.task_id, exact_failed_usage)
    journal.close()

    assert bindings.audit_model_refresh is not None
    assert bindings.audit_model_refresh_pricing is not None
    assert bindings.audit_model_selection is not None
    resealed_usage, resealed_refresh, resealed_pricing = _reseal_refresh_route_and_binding(
        exact_failed_usage,
        bindings.audit_model_refresh,
        bindings.audit_model_refresh_pricing,
    )
    resealed_attempt = SchedulerProviderAttemptEvidence.build(
        task=task,
        activation=activation,
        usage_record=resealed_usage,
        audit_model_selection=bindings.audit_model_selection,
        audit_model_refresh=resealed_refresh,
        audit_model_refresh_pricing=resealed_pricing,
    )
    attempt_path = next((path / "provider-attempts").glob("*.json"))
    attempt_path.write_text(stable_json(resealed_attempt), encoding="utf-8")
    attempt_path.rename(
        attempt_path.with_name(
            f"{resealed_attempt.task_id}-{resealed_attempt.attempt_evidence_sha256}.json"
        )
    )

    with pytest.raises(ValueError, match="current model refresh"):
        open_scheduler_journal_for_verification(
            path,
            expected_bindings=bindings,
            expected_shard_inventory=_inventory(),
        )


def test_resume_rejects_coherently_resealed_success_with_swapped_refresh(
    tmp_path: Path,
) -> None:
    path = tmp_path / "swapped-completion-refresh"
    bindings = _bindings(
        with_audit_policy=True,
        audit_policy_seed="scheduler-completion-original",
    )
    journal = create_scheduler_journal(
        path,
        bindings=bindings,
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
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
        audit_model_selection=bindings.audit_model_selection,
        audit_model_refresh=bindings.audit_model_refresh,
    )
    output = journal.persist_output(task.task_id, payload, usage_record=exact_usage)
    journal.close()

    audit_selection = bindings.audit_model_selection
    assert audit_selection is not None
    swapped_refresh = build_scheduler_test_audit_model_refresh_binding(
        audit_selection,
        seed="scheduler-completion-swapped:refresh",
    )
    swapped_pricing = build_scheduler_test_audit_model_refresh_pricing_binding(
        audit_selection,
        swapped_refresh,
    )
    swapped_usage = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=payload,
        privacy_evidence_custody=plan.manifest.privacy_evidence_custody,
        audit_model_selection=audit_selection,
        audit_model_refresh=swapped_refresh,
        audit_model_refresh_pricing=swapped_pricing,
    )
    assert task.normalizer_sha256 is not None
    swapped_completion = SchedulerModelCompletionEvidence.build(
        task=task,
        activation=activation,
        usage_record=swapped_usage,
        privacy_evidence_custody=plan.manifest.privacy_evidence_custody,
        audit_model_selection=audit_selection,
        audit_model_refresh=swapped_refresh,
        audit_model_refresh_pricing=swapped_pricing,
        normalizer_sha256=task.normalizer_sha256,
        normalized_output_sha256=output.output_sha256,
    )
    output_values = output.model_dump(mode="python", exclude={"output_artifact_sha256"})
    output_values["model_completion_evidence"] = swapped_completion
    swapped_output = SchedulerTaskOutput.model_validate(
        {
            **output_values,
            "output_artifact_sha256": scheduler_canonical_sha256(output_values),
        }
    )
    output_path = next((path / "task-outputs").glob("*.json"))
    output_path.write_text(stable_json(swapped_output), encoding="utf-8")
    output_path.rename(
        output_path.with_name(
            f"{swapped_output.task_id}-{swapped_output.output_artifact_sha256}.json"
        )
    )

    with pytest.raises(ValueError, match="current model refresh"):
        open_scheduler_journal_for_verification(
            path,
            expected_bindings=bindings,
            expected_shard_inventory=_inventory(),
        )


def _reseal_refresh_route_and_binding(
    usage: UsageRecord,
    binding: SchedulerAuditModelRefreshBinding,
    pricing_binding: SchedulerAuditModelRefreshPricingBinding,
) -> tuple[
    UsageRecord,
    SchedulerAuditModelRefreshBinding,
    SchedulerAuditModelRefreshPricingBinding,
]:
    raw_route = usage.routing.get("audit_model_refresh_route_evidence")
    route = AuditModelRefreshRouteEvidence.model_validate_json(json.dumps(raw_route))
    route_values = route.model_dump(mode="python", exclude={"route_evidence_sha256"})
    route_values["endpoint_snapshot_sha256"] = "f" * 64
    resealed_route = AuditModelRefreshRouteEvidence.model_validate(
        {
            **route_values,
            "route_evidence_sha256": scheduler_canonical_sha256(route_values),
        }
    )
    raw_pricing_route = usage.routing.get("audit_model_refresh_pricing_route_evidence")
    pricing_route = AuditModelRefreshPricingRouteEvidence.model_validate_json(
        json.dumps(raw_pricing_route)
    )
    pricing_route_values = pricing_route.model_dump(
        mode="python",
        exclude={"route_evidence_sha256"},
    )
    pricing_route_values["refresh_route_evidence_sha256"] = resealed_route.route_evidence_sha256
    resealed_pricing_route = AuditModelRefreshPricingRouteEvidence.model_validate(
        {
            **pricing_route_values,
            "route_evidence_sha256": scheduler_canonical_sha256(pricing_route_values),
        }
    )
    raw_attempts = usage.routing.get("audit_model_refresh_pricing_attempts")
    assert isinstance(raw_attempts, list)
    resealed_attempts = []
    for raw_attempt in raw_attempts:
        attempt = AuditModelRefreshPricingAttemptEvidence.model_validate_json(
            json.dumps(raw_attempt)
        )
        attempt_values = attempt.model_dump(mode="python", exclude={"evidence_sha256"})
        attempt_values["refresh_route_evidence_sha256"] = resealed_route.route_evidence_sha256
        attempt_values["pricing_route_evidence_sha256"] = (
            resealed_pricing_route.route_evidence_sha256
        )
        resealed_attempts.append(
            AuditModelRefreshPricingAttemptEvidence.model_validate(
                {
                    **attempt_values,
                    "evidence_sha256": scheduler_canonical_sha256(attempt_values),
                }
            )
        )
    final_attempt = resealed_attempts[-1]
    resealed_usage = reattest_synthetic_real_usage(
        usage.model_copy(
            update={
                "routing": {
                    **usage.routing,
                    "audit_model_refresh_route_evidence": resealed_route.model_dump(mode="json"),
                    "audit_model_refresh_route_evidence_sha256": (
                        resealed_route.route_evidence_sha256
                    ),
                    "audit_model_refresh_pricing_route_evidence": (
                        resealed_pricing_route.model_dump(mode="json")
                    ),
                    "audit_model_refresh_pricing_route_evidence_sha256": (
                        resealed_pricing_route.route_evidence_sha256
                    ),
                    "audit_model_refresh_pricing_attempts": [
                        attempt.model_dump(mode="json") for attempt in resealed_attempts
                    ],
                    "audit_model_refresh_pricing_attempt_sha256s": [
                        attempt.evidence_sha256 for attempt in resealed_attempts
                    ],
                    "audit_model_refresh_pricing_attempt": final_attempt.model_dump(mode="json"),
                    "audit_model_refresh_pricing_attempt_sha256": (final_attempt.evidence_sha256),
                }
            }
        )
    )
    binding_values = binding.model_dump(mode="python", exclude={"binding_sha256"})
    binding_values["audit_routes"] = (
        SchedulerAuditModelRefreshRouteBinding(
            exact_model_id=resealed_route.exact_model_id,
            route_evidence_sha256=resealed_route.route_evidence_sha256,
        ),
    )
    resealed_binding = SchedulerAuditModelRefreshBinding.model_validate(
        {
            **binding_values,
            "binding_sha256": scheduler_canonical_sha256(binding_values),
        }
    )
    pricing_binding_values = pricing_binding.model_dump(
        mode="python",
        exclude={"binding_sha256"},
    )
    pricing_binding_values["audit_routes"] = (
        SchedulerAuditModelRefreshPricingRouteBinding(
            exact_model_id=resealed_pricing_route.exact_model_id,
            approved_provider_endpoint=resealed_pricing_route.approved_provider_endpoint,
            pricing_route_evidence_sha256=resealed_pricing_route.route_evidence_sha256,
            refresh_route_evidence_sha256=resealed_route.route_evidence_sha256,
            qualified_pricing_snapshot_sha256=(
                resealed_pricing_route.qualified_pricing_snapshot_sha256
            ),
            baseline_pricing_sha256=resealed_pricing_route.baseline_pricing_sha256,
            current_pricing_sha256=resealed_pricing_route.current_pricing_sha256,
        ),
    )
    resealed_pricing_binding = SchedulerAuditModelRefreshPricingBinding.model_validate(
        {
            **pricing_binding_values,
            "binding_sha256": scheduler_canonical_sha256(pricing_binding_values),
        }
    )
    return resealed_usage, resealed_binding, resealed_pricing_binding


def test_resume_rejects_coherently_resealed_success_with_unbound_refresh_route(
    tmp_path: Path,
) -> None:
    path = tmp_path / "resealed-completion-refresh-route"
    bindings = _bindings(with_audit_policy=True)
    journal = create_scheduler_journal(
        path,
        bindings=bindings,
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
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
        audit_model_selection=bindings.audit_model_selection,
        audit_model_refresh=bindings.audit_model_refresh,
    )
    output = journal.persist_output(task.task_id, payload, usage_record=exact_usage)
    journal.close()

    assert bindings.audit_model_refresh is not None
    assert bindings.audit_model_refresh_pricing is not None
    assert bindings.audit_model_selection is not None
    resealed_usage, resealed_refresh, resealed_pricing = _reseal_refresh_route_and_binding(
        exact_usage,
        bindings.audit_model_refresh,
        bindings.audit_model_refresh_pricing,
    )
    assert task.normalizer_sha256 is not None
    resealed_completion = SchedulerModelCompletionEvidence.build(
        task=task,
        activation=activation,
        usage_record=resealed_usage,
        privacy_evidence_custody=plan.manifest.privacy_evidence_custody,
        audit_model_selection=bindings.audit_model_selection,
        audit_model_refresh=resealed_refresh,
        audit_model_refresh_pricing=resealed_pricing,
        normalizer_sha256=task.normalizer_sha256,
        normalized_output_sha256=output.output_sha256,
    )
    output_values = output.model_dump(mode="python", exclude={"output_artifact_sha256"})
    output_values["model_completion_evidence"] = resealed_completion
    resealed_output = SchedulerTaskOutput.model_validate(
        {
            **output_values,
            "output_artifact_sha256": scheduler_canonical_sha256(output_values),
        }
    )
    output_path = next((path / "task-outputs").glob("*.json"))
    output_path.write_text(stable_json(resealed_output), encoding="utf-8")
    output_path.rename(
        output_path.with_name(
            f"{resealed_output.task_id}-{resealed_output.output_artifact_sha256}.json"
        )
    )

    with pytest.raises(ValueError, match="current model refresh"):
        open_scheduler_journal_for_verification(
            path,
            expected_bindings=bindings,
            expected_shard_inventory=_inventory(),
        )


def test_post_transport_privacy_mismatch_is_accounted_but_never_credited(
    tmp_path: Path,
) -> None:
    journal = create_scheduler_journal(
        tmp_path / "privacy-mismatch",
        bindings=_bindings(with_audit_policy=True),
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
        audit_model_selection=journal.manifest.bindings.audit_model_selection,
        audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
        audit_model_refresh_pricing=(journal.manifest.bindings.audit_model_refresh_pricing),
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


def _framed_candidate_review_fixture(path: Path) -> dict[str, Any]:
    bindings = _bindings(with_audit_policy=True)
    inventory = _inventory()
    journal = create_scheduler_journal(
        path,
        bindings=bindings,
        shard_inventory=inventory,
    )
    orientation_plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    orientation_task = orientation_plan.tasks[0]
    orientation_activation = journal.activate_task(
        orientation_task.task_id,
        actual_input_sha256=orientation_task.input_sha256,
        system_prompt_sha256=orientation_task.system_prompt_sha256,
        user_prompt_sha256="3" * 64,
        provider_prompt_sha256="4" * 64,
        response_schema_sha256=orientation_task.response_schema_sha256,
    )
    journal.mark_dispatched(orientation_task.task_id)
    orientation_payload = build_scheduler_test_model_payload(
        orientation_plan,
        orientation_task,
    )
    orientation_usage = build_scheduler_test_real_usage(
        orientation_task,
        orientation_activation,
        validated_output=orientation_payload,
        cost_usd_exact="0.125",
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
        audit_model_selection=journal.manifest.bindings.audit_model_selection,
        audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
        audit_model_refresh_pricing=(journal.manifest.bindings.audit_model_refresh_pricing),
    )
    orientation_output = journal.persist_output(
        orientation_task.task_id,
        orientation_payload,
        usage_record=orientation_usage,
    )
    orientation_result = SchedulerTaskResult.build(
        plan=orientation_plan,
        task=orientation_task,
        activation=orientation_activation,
        terminal_status=SchedulerTerminalStatus.SUCCEEDED,
        terminal_evidence_sha256=orientation_usage.validated_response_sha256 or "0" * 64,
        output=orientation_output,
    )
    journal.record_terminal(orientation_result)
    journal.seal_pass_result(SchedulerPassKind.ORIENTATION)
    planner = PipelineScheduler(journal)
    wire_schema_sha256 = candidate_review_frame_wire_schema_sha256()
    audit_selection = journal.manifest.bindings.audit_model_selection
    assert audit_selection is not None
    selected_root_lineage = audit_selection.route_for("synthetic/auditor-v1").root_lineage
    tasks = tuple(
        planner.model_task(
            pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
            scope=SchedulerScope.single_shard(shard_id),
            task_key=f"framed-source-audit-{shard_id}",
            role="source_audit",
            requested_model="synthetic/auditor-v1",
            root_lineage=selected_root_lineage,
            system_prompt_sha256="a" * 64,
            response_schema_sha256=wire_schema_sha256,
            model_surface_review_request_manifest_sha256=(
                scheduler_test_model_surface_review_request_manifest_sha256(
                    manifest=journal.manifest,
                    pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
                    scope=SchedulerScope.single_shard(shard_id),
                    task_key=f"framed-source-audit-{shard_id}",
                    role="source_audit",
                )
            ),
        )
        for shard_id in SHARDS
    )
    task = tasks[0]
    assert task.normalizer_sha256 == scheduler_response_normalizer_sha256(wire_schema_sha256)
    plan = planner.prepare_pass(SchedulerPassKind.BLIND_SHARD_REVIEW, tasks)
    activation = journal.activate_task(
        task.task_id,
        actual_input_sha256="1" * 64,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=wire_schema_sha256,
        delivered_source_descriptor_sha256s=(
            scheduler_test_delivered_source_descriptor_sha256s(plan, task)
        ),
    )
    journal.mark_dispatched(task.task_id)
    payload = CandidateReviewBatch.model_validate(build_scheduler_test_model_payload(plan, task))
    document = frame_candidate_review_batch(payload)
    normalized, normalization = normalize_candidate_review_document(
        document,
        request_id=task.logical_request_id,
    )
    assert normalized == payload
    usage = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=document,
        cost_usd_exact="0.125",
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
        audit_model_selection=journal.manifest.bindings.audit_model_selection,
        audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
        audit_model_refresh_pricing=(journal.manifest.bindings.audit_model_refresh_pricing),
    )
    surface_requests, surface_artifact = build_scheduler_test_model_surface_review_custody(
        plan,
        task,
        activation,
        usage,
        payload,
        normalization_evidence=normalization,
    )
    assert surface_artifact is not None
    assert surface_artifact.schema_version == "1.1"
    return {
        "bindings": bindings,
        "inventory": inventory,
        "journal": journal,
        "runtime": PipelineScheduler(journal),
        "plan": plan,
        "task": task,
        "payload": payload,
        "usage": usage,
        "normalization": normalization,
        "surface_requests": surface_requests,
        "surface_artifact": surface_artifact,
    }


def _record_framed_candidate_review(
    fixture: dict[str, Any],
    *,
    normalization: CandidateReviewNormalizationEvidence | None,
) -> SchedulerTaskResult:
    runtime = fixture["runtime"]
    assert isinstance(runtime, PipelineScheduler)
    task = fixture["task"]
    assert isinstance(task, SchedulerTaskPlan)
    usage = fixture["usage"]
    assert isinstance(usage, UsageRecord)
    return runtime.record_model_success(
        task,
        output_value=fixture["payload"],
        usage_records=[usage],
        model_surface_review_requests=fixture["surface_requests"],
        model_surface_review_artifact=fixture["surface_artifact"],
        normalization_evidence=normalization,
    )


def test_framed_candidate_review_completion_survives_exact_journal_reload(
    tmp_path: Path,
) -> None:
    path = tmp_path / "framed-candidate-review"
    fixture = _framed_candidate_review_fixture(path)
    normalization = fixture["normalization"]
    assert isinstance(normalization, CandidateReviewNormalizationEvidence)

    result = _record_framed_candidate_review(fixture, normalization=normalization)

    assert result.terminal_status is SchedulerTerminalStatus.SUCCEEDED
    runtime = fixture["runtime"]
    assert isinstance(runtime, PipelineScheduler)
    runtime.close()
    verified = open_scheduler_journal_for_verification(
        path,
        expected_bindings=fixture["bindings"],
        expected_shard_inventory=fixture["inventory"],
    )
    task = fixture["task"]
    assert isinstance(task, SchedulerTaskPlan)
    output = next(item for item in verified.outputs if item.task_id == task.task_id)
    completion = output.model_completion_evidence
    assert completion is not None
    assert completion.schema_version == "1.1"
    assert completion.normalization_evidence == normalization
    assert completion.validated_response_sha256 == normalization.wire_validated_response_sha256
    assert completion.normalized_output_sha256 == normalization.normalized_batch_sha256
    assert completion.validated_response_sha256 != completion.normalized_output_sha256
    assert output.model_surface_review_artifact is not None
    assert output.model_surface_review_artifact.normalization_evidence == normalization
    assert verified.reconstruct_output(task.task_id, CandidateReviewBatch) == fixture["payload"]
    verified.close()


def test_legacy_direct_batch_candidate_review_remains_reload_compatible(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-candidate-review"
    bindings = _bindings()
    inventory = _inventory()
    journal = create_scheduler_journal(
        path,
        bindings=bindings,
        shard_inventory=inventory,
    )
    _complete_pass(journal, SchedulerPassKind.ORIENTATION)
    _complete_pass(journal, SchedulerPassKind.BLIND_SHARD_REVIEW)
    legacy_outputs = tuple(
        output
        for output in journal.outputs
        if output.model_completion_evidence is not None
        and output.model_completion_evidence.response_schema_sha256
        == scheduler_test_response_schema_sha256(
            SchedulerPassKind.BLIND_SHARD_REVIEW,
            "source_audit",
        )
    )
    assert len(legacy_outputs) == len(SHARDS)
    assert all(
        output.model_completion_evidence is not None
        and output.model_completion_evidence.schema_version == "1.0"
        and output.model_completion_evidence.normalization_evidence is None
        for output in legacy_outputs
    )
    journal.close()

    verified = open_scheduler_journal_for_verification(
        path,
        expected_bindings=bindings,
        expected_shard_inventory=inventory,
    )
    assert {
        output.output_artifact_sha256
        for output in verified.outputs
        if output.model_completion_evidence is not None
        and output.model_completion_evidence.response_schema_sha256
        == scheduler_test_response_schema_sha256(
            SchedulerPassKind.BLIND_SHARD_REVIEW,
            "source_audit",
        )
    } == {output.output_artifact_sha256 for output in legacy_outputs}
    verified.close()


def test_new_pipeline_candidate_review_task_rejects_legacy_batch_wire_schema(
    tmp_path: Path,
) -> None:
    runtime = PipelineScheduler.create(
        tmp_path / "new-candidate-task",
        bindings=_bindings(),
        analysis_input_inventory=_analysis_inventory(),
        shard_inventory=_inventory(),
        privacy_evidence_custody=_privacy_custody(),
    )

    with pytest.raises(ValueError, match="exact framed wire schema"):
        runtime.model_task(
            pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
            scope=SchedulerScope.single_shard(SHARDS[0]),
            task_key="legacy-wire-is-for-replay-only",
            role="source_audit",
            requested_model="synthetic/auditor-v1",
            root_lineage="sha256:" + "1" * 64,
            system_prompt_sha256="2" * 64,
            response_schema_sha256=scheduler_test_response_schema_sha256(
                SchedulerPassKind.BLIND_SHARD_REVIEW,
                "source_audit",
            ),
            model_surface_review_request_manifest_sha256="f" * 64,
        )
    runtime.close()


@pytest.mark.parametrize("tamper", ("omitted", "swapped", "coherently_resealed"))
def test_framed_candidate_review_rejects_missing_or_false_normalization_custody(
    tmp_path: Path,
    tamper: str,
) -> None:
    fixture = _framed_candidate_review_fixture(tmp_path / tamper)
    normalization = fixture["normalization"]
    assert isinstance(normalization, CandidateReviewNormalizationEvidence)
    supplied: CandidateReviewNormalizationEvidence | None
    if tamper == "omitted":
        supplied = None
    elif tamper == "swapped":
        payload = fixture["payload"]
        assert isinstance(payload, CandidateReviewBatch)
        _normalized, supplied = normalize_candidate_review_document(
            frame_candidate_review_batch(payload),
            request_id="scheduler-request-" + "f" * 64,
        )
    else:
        resealed = normalization.model_dump(mode="json")
        resealed["normalized_batch_sha256"] = "f" * 64
        resealed["evidence_sha256"] = scheduler_canonical_sha256(
            {key: value for key, value in resealed.items() if key != "evidence_sha256"}
        )
        supplied = CandidateReviewNormalizationEvidence.model_validate(resealed)

    result = _record_framed_candidate_review(fixture, normalization=supplied)

    assert result.terminal_status is SchedulerTerminalStatus.INVALID
    journal = fixture["journal"]
    assert isinstance(journal, SchedulerJournal)
    task = fixture["task"]
    assert isinstance(task, SchedulerTaskPlan)
    assert all(output.task_id != task.task_id for output in journal.outputs)
    assert len(journal.provider_attempts) == 1
    runtime = fixture["runtime"]
    assert isinstance(runtime, PipelineScheduler)
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


def test_paid_real_success_rejects_stripped_audit_policy_routing(tmp_path: Path) -> None:
    journal = create_scheduler_journal(
        tmp_path / "policy-stripped",
        bindings=_bindings(with_audit_policy=True),
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
    stripped = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=payload,
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
    )

    with pytest.raises(ValueError, match="lacks audit policy selection evidence"):
        journal.persist_output(task.task_id, payload, usage_record=stripped)
    journal.close()


@pytest.mark.parametrize(
    "routing_field",
    (
        "audit_model_refresh_technical_route_set_sha256",
        "audit_model_refresh_guard_capability_sha256",
    ),
)
def test_paid_real_success_rejects_swapped_refresh_binding_hash(
    tmp_path: Path,
    routing_field: str,
) -> None:
    journal = create_scheduler_journal(
        tmp_path / "refresh-technical-route-swapped",
        bindings=_bindings(with_audit_policy=True),
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
    exact = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=payload,
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
        audit_model_selection=journal.manifest.bindings.audit_model_selection,
        audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
    )
    swapped = reattest_synthetic_real_usage(
        exact.model_copy(
            update={
                "routing": {
                    **exact.routing,
                    routing_field: "f" * 64,
                }
            }
        )
    )

    with pytest.raises(ValueError, match="differs from current model refresh"):
        journal.persist_output(task.task_id, payload, usage_record=swapped)
    assert journal.outputs == ()
    journal.close()


def test_paid_real_success_rejects_use_before_refresh_verification(
    tmp_path: Path,
) -> None:
    journal = create_scheduler_journal(
        tmp_path / "refresh-use-before-verification",
        bindings=_bindings(with_audit_policy=True),
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
    exact = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=payload,
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
        audit_model_selection=journal.manifest.bindings.audit_model_selection,
        audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
    )
    started_at = datetime(2019, 12, 31, 23, 59, 59, tzinfo=UTC)
    ended_at = started_at + timedelta(milliseconds=1)
    predates_verification = reattest_synthetic_real_usage(
        exact.model_copy(
            update={
                "started_at": started_at,
                "ended_at": ended_at,
                "routing": {
                    **exact.routing,
                    "request_started_at": started_at.isoformat(),
                    "request_ended_at": ended_at.isoformat(),
                },
            }
        )
    )

    with pytest.raises(ValueError, match="differs from current model refresh"):
        journal.persist_output(task.task_id, payload, usage_record=predates_verification)
    assert journal.outputs == ()
    journal.close()


def test_paid_real_completion_may_finish_after_refresh_expiry_if_dispatch_was_current(
    tmp_path: Path,
) -> None:
    started_at = datetime(2025, 1, 1, tzinfo=UTC)
    refresh_expires_at = started_at + timedelta(seconds=1)
    journal = create_scheduler_journal(
        tmp_path / "refresh-expires-during-request",
        bindings=_bindings(
            with_audit_policy=True,
            audit_model_refresh_expires_at=refresh_expires_at,
        ),
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
    exact = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=payload,
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
        audit_model_selection=journal.manifest.bindings.audit_model_selection,
        audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
    )
    ended_at = refresh_expires_at + timedelta(seconds=1)
    completed_after_expiry = reattest_synthetic_real_usage(
        exact.model_copy(
            update={
                "ended_at": ended_at,
                "latency_ms": 2_000,
                "routing": {
                    **exact.routing,
                    "request_ended_at": ended_at.isoformat(),
                    "latency_ms": 2_000,
                },
            }
        )
    )

    output = journal.persist_output(
        task.task_id,
        payload,
        usage_record=completed_after_expiry,
    )

    assert output.model_completion_evidence is not None
    assert output.model_completion_evidence.audit_model_refresh_expires_at == refresh_expires_at
    journal.close()


def test_resume_rejects_activation_event_rollback_against_local_head(tmp_path: Path) -> None:
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
    activated_event = journal.events[-1]
    journal.close()
    (path / "events" / f"event-{activated_event.event_index:08d}.json").unlink()

    with pytest.raises(ValueError):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )


def test_resume_rejects_swapped_audit_policy_selection_bundle(tmp_path: Path) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(
        path,
        bindings=_bindings(
            with_audit_policy=True,
            audit_policy_seed="scheduler-policy-original",
        ),
        shard_inventory=_inventory(),
    )
    journal.close()

    with pytest.raises(ValueError, match="bindings or shard inventory do not match"):
        open_scheduler_journal_for_verification(
            path,
            expected_bindings=_bindings(
                with_audit_policy=True,
                audit_policy_seed="scheduler-policy-swapped",
            ),
            expected_shard_inventory=_inventory(),
        )


@pytest.mark.asyncio
async def test_structural_refresh_resume_cannot_re_attest_real_usage(
    tmp_path: Path,
) -> None:
    exact_cost = Decimal("0.123456789012345678")
    path = tmp_path / "journal"
    journal = create_scheduler_journal(
        path,
        bindings=_bindings(with_audit_policy=True),
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
    runtime_usage = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=payload,
        cost_usd_exact=str(exact_cost),
        privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
        audit_model_selection=journal.manifest.bindings.audit_model_selection,
        audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
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
        expected_bindings=_bindings(with_audit_policy=True),
        expected_shard_inventory=_inventory(),
    )
    serialized = verification.restorable_usage_records
    assert len(serialized) == 1
    assert not is_creditable_usage_record(serialized[0], require_real=True)
    forged = UsageRecord.model_validate(serialized[0].model_dump(mode="json"))
    assert not is_creditable_usage_record(forged, require_real=True)
    with pytest.raises(ValueError, match="read-only"):
        verification.claim_restorable_usage_records()
    verification.close()

    before_cost = cost_ledger.snapshot()
    with pytest.raises(ValueError, match="requires live model-refresh authority"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(with_audit_policy=True),
            expected_shard_inventory=_inventory(),
        )
    assert budget.recovery_required
    assert cost_ledger.snapshot() == before_cost


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


def _failed_accountable_mock_usage(
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
    activation: SchedulerTaskActivation,
    *,
    reported_cost_usd_exact: str | None,
    accounted_cost_usd_exact: str,
    attempts: int = 1,
    released_before_send: bool = False,
) -> UsageRecord:
    """Build synthetic failed-attempt accounting with an exact atomic inventory."""

    payload = build_scheduler_test_model_payload(plan, task)
    base = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=payload,
        cost_usd_exact=accounted_cost_usd_exact,
    )
    routing = dict(base.routing)
    if attempts == 2:
        first_token = AtomicTokenReservationEvidence.model_validate(
            routing["atomic_token_reservation"]
        )
        second_token = AtomicTokenReservationEvidence.build(
            request_id=f"{task.logical_request_id}:attempt:2",
            exact_model_id=first_token.exact_model_id,
            role=first_token.role,
            request_token_plan_sha256=first_token.request_token_plan_sha256,
            planned_prompt_tokens=first_token.planned_prompt_tokens,
            planned_visible_output_tokens=first_token.planned_visible_output_tokens,
            planned_reasoning_tokens=first_token.planned_reasoning_tokens,
            planned_completion_tokens=first_token.planned_completion_tokens,
            global_input_token_limit=first_token.global_input_token_limit,
            global_output_token_limit=first_token.global_output_token_limit,
            spent_input_tokens_before=first_token.planned_prompt_tokens,
            reserved_input_tokens_before=0,
            spent_output_tokens_before=first_token.planned_completion_tokens,
            reserved_output_tokens_before=0,
        )
        first_request = AtomicRequestLimitReservationEvidence.model_validate(
            routing["atomic_request_limit_reservation"]
        )
        second_request = AtomicRequestLimitReservationEvidence.build(
            request_id=second_token.request_id,
            exact_model_id=first_request.exact_model_id,
            role=first_request.role,
            request_token_plan_sha256=first_request.request_token_plan_sha256,
            request_limit_scope=first_request.request_limit_scope,
            request_limit_count_before=1,
            request_limit_maximum=first_request.request_limit_maximum,
        )
        routing.update(
            {
                "atomic_token_reservations": [
                    first_token.model_dump(mode="json"),
                    second_token.model_dump(mode="json"),
                ],
                "atomic_token_reservation_sha256s": [
                    first_token.evidence_sha256,
                    second_token.evidence_sha256,
                ],
                "atomic_token_reservation": second_token.model_dump(mode="json"),
                "atomic_token_reservation_sha256": second_token.evidence_sha256,
                "atomic_request_limit_reservations": [
                    first_request.model_dump(mode="json"),
                    second_request.model_dump(mode="json"),
                ],
                "atomic_request_limit_reservation_sha256s": [
                    first_request.evidence_sha256,
                    second_request.evidence_sha256,
                ],
                "atomic_request_limit_reservation": second_request.model_dump(mode="json"),
                "atomic_request_limit_reservation_sha256": second_request.evidence_sha256,
            }
        )
    failure_updates: dict[str, object] = {
        "execution_evidence": ExecutionEvidenceKind.MOCK,
        "reported_cost_usd": (
            float(Decimal(reported_cost_usd_exact)) if reported_cost_usd_exact is not None else None
        ),
        "reported_cost_usd_exact": reported_cost_usd_exact,
        "accounted_cost_usd": float(Decimal(accounted_cost_usd_exact)),
        "accounted_cost_usd_exact": accounted_cost_usd_exact,
        "routing": routing,
        "identity_strength": ModelIdentityStrength.UNBOUND,
        "provider_error_classification": "timeout",
        "validation_status": ModelRequestValidationStatus.PROVIDER_ERROR,
        "status": "provider_error",
        "attempts": attempts,
        "retry_count": attempts - 1,
    }
    if released_before_send:
        failure_updates.update(
            {
                "returned_model": None,
                "actual_model": None,
                "provider": None,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "cached_tokens": 0,
                "reasoning_tokens": 0,
                "reasoning_evidence": None,
                "token_detail_accounting_evidence": None,
                "response_sha256": None,
                "validated_response_sha256": None,
                "openrouter_generation_id": None,
                "actual_provider_endpoint": None,
                "finish_reason": None,
            }
        )
    record = UsageRecord.model_validate(
        base.model_copy(update=failure_updates).model_dump(mode="python")
    )
    assert is_structurally_accountable_usage_record(record)
    return record


def _persist_failed_provider_attempt(
    journal: SchedulerJournal,
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
    activation: SchedulerTaskActivation,
    usage: UsageRecord,
    *,
    terminal_evidence_sha256: str | None = None,
) -> None:
    attempt = journal.persist_provider_attempt(task.task_id, usage)
    journal.record_terminal(
        SchedulerTaskResult.build(
            plan=plan,
            task=task,
            activation=activation,
            terminal_status=SchedulerTerminalStatus.FAILED,
            terminal_evidence_sha256=(terminal_evidence_sha256 or attempt.attempt_evidence_sha256),
        )
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("initial_ledger_state", "reported_cost", "accounted_cost", "expected_status"),
    (
        ("uncertain", None, "0.25", CostEntryStatus.UNCERTAIN_ACCOUNTED),
        ("reserved_unknown", None, "0.25", CostEntryStatus.UNCERTAIN_ACCOUNTED),
        ("reserved_reported", "0.125", "0.125", CostEntryStatus.RECONCILED),
    ),
)
async def test_resume_restores_terminal_failed_retained_attempt_from_exact_ledger_state(
    tmp_path: Path,
    initial_ledger_state: str,
    reported_cost: str | None,
    accounted_cost: str,
    expected_status: CostEntryStatus,
) -> None:
    path = tmp_path / initial_ledger_state
    journal = create_scheduler_journal(
        path,
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
    usage = _failed_accountable_mock_usage(
        plan,
        task,
        activation,
        reported_cost_usd_exact=reported_cost,
        accounted_cost_usd_exact=accounted_cost,
    )
    _persist_failed_provider_attempt(journal, plan, task, activation, usage)
    journal.close()

    ledger = AtomicCostLedger.initialize(
        tmp_path / f"{initial_ledger_state}.json", cap_usd=Decimal("1")
    )
    reservation = ledger.reserve(task.logical_request_id, Decimal("0.25"))
    if initial_ledger_state == "uncertain":
        ledger.reconcile(reservation, None)
    budget = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
        global_input_token_budget=1_000_000,
        global_output_token_budget=100_000,
    )
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    assert resumed.task_results[0].terminal_status is SchedulerTerminalStatus.FAILED

    records, recovery_scope = resumed.claim_restorable_usage_for_budget_recovery(
        atomic_ledger=ledger
    )
    assert records == (usage,)
    await budget.restore_recovered_usage(records, recovery_scope=recovery_scope)

    entry = ledger.snapshot().entries[0]
    assert entry.status is expected_status
    assert entry.accounted_cost_usd == Decimal(accounted_cost)
    assert budget.spent_usd_exact == Decimal(accounted_cost)
    assert budget.spent_model_usd(task.requested_model or "") == Decimal(accounted_cost)
    resumed.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "release_reason",
    (
        ReleaseReason.FAILED_BEFORE_SEND,
        ReleaseReason.CANCELLED_BEFORE_SEND,
    ),
)
async def test_resume_restores_zero_cost_released_retained_attempt(
    tmp_path: Path,
    release_reason: ReleaseReason,
) -> None:
    path = tmp_path / release_reason.value
    journal = create_scheduler_journal(
        path,
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
    usage = _failed_accountable_mock_usage(
        plan,
        task,
        activation,
        reported_cost_usd_exact=None,
        accounted_cost_usd_exact="0",
        released_before_send=True,
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / f"{release_reason.value}.json",
        cap_usd=Decimal("1"),
    )
    reservation = ledger.reserve(task.logical_request_id, Decimal("0.25"))
    released = ledger.release(reservation, reason=release_reason)
    _persist_failed_provider_attempt(
        journal,
        plan,
        task,
        activation,
        usage,
        terminal_evidence_sha256=cost_entry_sha256(released),
    )
    journal.close()

    budget = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
        global_input_token_budget=1_000_000,
        global_output_token_budget=100_000,
    )
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )

    records, recovery_scope = resumed.claim_restorable_usage_for_budget_recovery(
        atomic_ledger=ledger
    )
    await budget.restore_recovered_usage(records, recovery_scope=recovery_scope)

    assert records == (usage,)
    assert budget.spent_usd_exact == 0
    assert budget.spent_input_tokens == 0
    assert budget.spent_output_tokens == 0
    retry = await budget.reserve(
        f"{task.logical_request_id}:attempt:2",
        task.role,
        "x",
        exact_model_id=task.requested_model,
        planned_prompt_tokens=1,
        planned_visible_output_tokens=1,
        planned_reasoning_tokens=0,
        planned_completion_tokens=1,
        request_token_plan_sha256="3" * 64,
        request_limit_scope=_issue_trusted_request_limit_scope(task.logical_request_id),
    )
    assert retry.request_limit_reservation_evidence is not None
    assert retry.request_limit_reservation_evidence.request_limit_count_before == 1
    await budget.release(retry)
    resumed.close()


@pytest.mark.asyncio
async def test_resume_restores_uncertain_prefix_with_zero_cost_released_tail(
    tmp_path: Path,
) -> None:
    path = tmp_path / "uncertain-released-tail"
    journal = create_scheduler_journal(
        path,
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
    usage = _failed_accountable_mock_usage(
        plan,
        task,
        activation,
        reported_cost_usd_exact=None,
        accounted_cost_usd_exact="0.10",
        attempts=2,
        released_before_send=True,
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "uncertain-released-tail.json",
        cap_usd=Decimal("1"),
    )
    first = ledger.reserve(task.logical_request_id, Decimal("0.10"))
    ledger.reconcile(first, None)
    tail = ledger.reserve(f"{task.logical_request_id}:attempt:2", Decimal("0.20"))
    released = ledger.release(tail, reason=ReleaseReason.FAILED_BEFORE_SEND)
    _persist_failed_provider_attempt(
        journal,
        plan,
        task,
        activation,
        usage,
        terminal_evidence_sha256=cost_entry_sha256(released),
    )
    journal.close()

    budget = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
        global_input_token_budget=1_000_000,
        global_output_token_budget=100_000,
    )
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )

    records, recovery_scope = resumed.claim_restorable_usage_for_budget_recovery(
        atomic_ledger=ledger
    )
    await budget.restore_recovered_usage(records, recovery_scope=recovery_scope)

    first_token = AtomicTokenReservationEvidence.model_validate(
        usage.routing["atomic_token_reservations"][0]
    )
    assert budget.spent_usd_exact == Decimal("0.10")
    assert budget.spent_input_tokens == first_token.planned_prompt_tokens
    assert budget.spent_output_tokens == first_token.planned_completion_tokens
    retry = await budget.reserve(
        f"{task.logical_request_id}:attempt:3",
        task.role,
        "x",
        exact_model_id=task.requested_model,
        planned_prompt_tokens=1,
        planned_visible_output_tokens=1,
        planned_reasoning_tokens=0,
        planned_completion_tokens=1,
        request_token_plan_sha256="4" * 64,
        request_limit_scope=_issue_trusted_request_limit_scope(task.logical_request_id),
    )
    assert retry.request_limit_reservation_evidence is not None
    assert retry.request_limit_reservation_evidence.request_limit_count_before == 2
    await budget.release(retry)
    resumed.close()


def test_retained_usage_rejects_nonfinal_released_attempt_before_mutation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "nonfinal-released"
    journal = create_scheduler_journal(
        path,
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
    usage = _failed_accountable_mock_usage(
        plan,
        task,
        activation,
        reported_cost_usd_exact=None,
        accounted_cost_usd_exact="0.20",
        attempts=2,
        released_before_send=True,
    )
    _persist_failed_provider_attempt(journal, plan, task, activation, usage)
    journal.close()

    ledger_path = tmp_path / "nonfinal-released.json"
    ledger = AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("1"))
    first = ledger.reserve(task.logical_request_id, Decimal("0.10"))
    ledger.release(first, reason=ReleaseReason.FAILED_BEFORE_SEND)
    tail = ledger.reserve(f"{task.logical_request_id}:attempt:2", Decimal("0.20"))
    ledger.reconcile(tail, None)
    before_snapshot = ledger.snapshot()
    before_bytes = ledger_path.read_bytes()
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )

    with pytest.raises(ValueError, match="lacks an exact uncertain retry prefix"):
        resumed.claim_restorable_usage_for_budget_recovery(atomic_ledger=ledger)
    assert ledger.snapshot() == before_snapshot
    assert ledger_path.read_bytes() == before_bytes
    resumed.close()


@pytest.mark.parametrize(
    "entry_change",
    ("wrong_reason", "actual_cost", "accounted_cost"),
)
def test_released_retained_attempt_requires_exact_zero_cost_lifecycle(
    tmp_path: Path,
    entry_change: str,
) -> None:
    journal = create_scheduler_journal(
        tmp_path / entry_change,
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
    usage = _failed_accountable_mock_usage(
        plan,
        task,
        activation,
        reported_cost_usd_exact=None,
        accounted_cost_usd_exact="0",
        released_before_send=True,
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / f"{entry_change}.json",
        cap_usd=Decimal("1"),
    )
    reservation = ledger.reserve(task.logical_request_id, Decimal("0.25"))
    ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)
    entry = ledger.snapshot().entries[0]
    if entry_change == "wrong_reason":
        forged = replace(entry, release_reason=None)
    elif entry_change == "actual_cost":
        forged = replace(entry, actual_cost_usd=Decimal("0.01"))
    else:
        forged = replace(entry, accounted_cost_usd=Decimal("0.01"))

    with pytest.raises(ValueError, match="release lacks exact pre-send custody"):
        scheduler_module._retained_main_usage_cost_recovery_plan(
            records=(usage,),
            tasks_by_request={task.logical_request_id: task},
            ledger_entries=(forged,),
        )
    journal.close()


@pytest.mark.asyncio
async def test_resume_restores_multi_attempt_usage_and_reconciles_only_retained_reserved_tail(
    tmp_path: Path,
) -> None:
    path = tmp_path / "retained-retry"
    journal = create_scheduler_journal(
        path,
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
    usage = _failed_accountable_mock_usage(
        plan,
        task,
        activation,
        reported_cost_usd_exact="0.125",
        accounted_cost_usd_exact="0.225",
        attempts=2,
    )
    _persist_failed_provider_attempt(journal, plan, task, activation, usage)
    journal.close()

    ledger = AtomicCostLedger.initialize(tmp_path / "retained-retry.json", cap_usd=Decimal("1"))
    first = ledger.reserve(task.logical_request_id, Decimal("0.10"))
    ledger.reconcile(first, None)
    ledger.reserve(f"{task.logical_request_id}:attempt:2", Decimal("0.20"))
    budget = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
        global_input_token_budget=1_000_000,
        global_output_token_budget=100_000,
    )
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )

    records, recovery_scope = resumed.claim_restorable_usage_for_budget_recovery(
        atomic_ledger=ledger
    )
    await budget.restore_recovered_usage(records, recovery_scope=recovery_scope)

    assert records == (usage,)
    assert [entry.status for entry in ledger.snapshot().entries] == [
        CostEntryStatus.UNCERTAIN_ACCOUNTED,
        CostEntryStatus.RECONCILED,
    ]
    assert ledger.snapshot().entries[1].actual_cost_usd == Decimal("0.125")
    assert budget.spent_usd_exact == Decimal("0.225")
    resumed.close()


@pytest.mark.parametrize(
    ("case", "reported_cost", "accounted_cost", "expected_error"),
    (
        ("accounting_mismatch", None, "0.20", "accounting differs from its ledger"),
        ("reservation_overrun", "0.30", "0.30", "reported cost exceeds its reservation"),
    ),
)
def test_retained_attempt_cost_mismatch_fails_before_ledger_mutation(
    tmp_path: Path,
    case: str,
    reported_cost: str | None,
    accounted_cost: str,
    expected_error: str,
) -> None:
    path = tmp_path / case
    journal = create_scheduler_journal(
        path,
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
    usage = _failed_accountable_mock_usage(
        plan,
        task,
        activation,
        reported_cost_usd_exact=reported_cost,
        accounted_cost_usd_exact=accounted_cost,
    )
    _persist_failed_provider_attempt(journal, plan, task, activation, usage)
    journal.close()

    ledger_path = tmp_path / f"{case}.json"
    ledger = AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("1"))
    reservation = ledger.reserve(task.logical_request_id, Decimal("0.25"))
    if case == "accounting_mismatch":
        ledger.reconcile(reservation, None)
    before_snapshot = ledger.snapshot()
    before_bytes = ledger_path.read_bytes()
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )

    with pytest.raises(ValueError, match=expected_error):
        resumed.claim_restorable_usage_for_budget_recovery(atomic_ledger=ledger)
    assert ledger.snapshot() == before_snapshot
    assert ledger_path.read_bytes() == before_bytes
    resumed.close()


def test_retained_attempt_cannot_hide_an_extra_active_retry_entry(tmp_path: Path) -> None:
    path = tmp_path / "extra-retry"
    journal = create_scheduler_journal(
        path,
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
    usage = _failed_accountable_mock_usage(
        plan,
        task,
        activation,
        reported_cost_usd_exact=None,
        accounted_cost_usd_exact="0.25",
    )
    _persist_failed_provider_attempt(journal, plan, task, activation, usage)
    journal.close()

    ledger_path = tmp_path / "extra-retry.json"
    ledger = AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("1"))
    first = ledger.reserve(task.logical_request_id, Decimal("0.25"))
    ledger.reconcile(first, None)
    ledger.reserve(f"{task.logical_request_id}:attempt:2", Decimal("0.20"))
    before_snapshot = ledger.snapshot()
    before_bytes = ledger_path.read_bytes()
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )

    with pytest.raises(ValueError, match="complete ledger attempt inventory"):
        resumed.claim_restorable_usage_for_budget_recovery(atomic_ledger=ledger)
    assert ledger.snapshot() == before_snapshot
    assert ledger_path.read_bytes() == before_bytes
    resumed.close()


def test_terminal_failure_without_retained_usage_cannot_claim_accounted_uncertainty(
    tmp_path: Path,
) -> None:
    path = tmp_path / "failed-without-usage"
    journal = create_scheduler_journal(
        path,
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
    journal.record_terminal(
        SchedulerTaskResult.build(
            plan=plan,
            task=task,
            activation=activation,
            terminal_status=SchedulerTerminalStatus.FAILED,
            terminal_evidence_sha256="d" * 64,
        )
    )
    journal.close()

    ledger_path = tmp_path / "failed-without-usage.json"
    ledger = AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("1"))
    reservation = ledger.reserve(task.logical_request_id, Decimal("0.25"))
    ledger.reconcile(reservation, None)
    before_snapshot = ledger.snapshot()
    before_bytes = ledger_path.read_bytes()
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )

    with pytest.raises(ValueError, match="differs from its scheduler terminal"):
        resumed.claim_restorable_usage_for_budget_recovery(atomic_ledger=ledger)
    assert ledger.snapshot() == before_snapshot
    assert ledger_path.read_bytes() == before_bytes
    resumed.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "journal_state",
    (
        "activated",
        "activated_terminal",
        "dispatched",
        "dispatched_terminal",
    ),
)
async def test_no_usage_released_attempt_terminalizes_and_restores_idempotently(
    tmp_path: Path,
    journal_state: str,
) -> None:
    path = tmp_path / journal_state
    journal = create_scheduler_journal(
        path,
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
    if journal_state.startswith("dispatched"):
        journal.mark_dispatched(task.task_id)
    ledger = AtomicCostLedger.initialize(
        tmp_path / f"{journal_state}.json",
        cap_usd=Decimal("1"),
    )
    reservation = ledger.reserve(task.logical_request_id, Decimal("0.25"))
    released = ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)
    expected_result = SchedulerTaskResult.build(
        plan=plan,
        task=task,
        activation=activation,
        terminal_status=SchedulerTerminalStatus.FAILED,
        terminal_evidence_sha256=cost_entry_sha256(released),
    )
    if journal_state == "activated_terminal":
        journal.record_activated_preflight_failure(expected_result)
    elif journal_state == "dispatched_terminal":
        journal.record_terminal(expected_result)
    journal.close()
    ledger_bytes = ledger.path.read_bytes()

    observed_result: SchedulerTaskResult | None = None
    observed_events: tuple[SchedulerTaskEventKind, ...] | None = None
    for _resume_ordinal in range(2):
        resumed = resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            atomic_ledger=ledger,
        )
        assert resumed.task_results == (expected_result,)
        assert task.task_id not in resumed.dispatchable_task_ids
        task_events = tuple(event.kind for event in resumed.events if event.task_id == task.task_id)
        assert task_events[-1] is (
            SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL
            if journal_state.startswith("activated")
            else SchedulerTaskEventKind.TERMINAL
        )
        if observed_result is None:
            observed_result = resumed.task_results[0]
            observed_events = task_events
        else:
            assert resumed.task_results[0] == observed_result
            assert task_events == observed_events

        budget = BudgetManager(
            total_usd=1,
            max_output_tokens=10,
            conservative_usd_per_million_tokens=1,
            max_requests_per_agent=10,
            atomic_ledger=ledger,
            global_input_token_budget=100,
            global_output_token_budget=200,
        )
        records, recovery_scope = resumed.claim_restorable_usage_for_budget_recovery(
            atomic_ledger=ledger
        )
        assert records == ()
        await budget.restore_recovered_usage(records, recovery_scope=recovery_scope)
        assert budget.spent_usd_exact == 0
        assert budget.spent_input_tokens == 0
        assert budget.spent_output_tokens == 0
        assert budget._request_limit_counts[("scheduled_task", task.logical_request_id)] == 1
        assert ledger.path.read_bytes() == ledger_bytes
        resumed.close()


@pytest.mark.asyncio
async def test_live_activated_released_usage_is_retained_and_restored(
    tmp_path: Path,
) -> None:
    ledger = AtomicCostLedger.initialize(
        tmp_path / "live-release-ledger.json", cap_usd=Decimal("1")
    )
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    bindings = _bindings(cost_ledger_baseline_sha256=baseline.baseline_sha256)
    runtime = PipelineScheduler.create(
        tmp_path / "live-release-journal",
        bindings=bindings,
        analysis_input_inventory=_analysis_inventory(),
        shard_inventory=_inventory(),
        cost_ledger_baseline=baseline,
        privacy_evidence_custody=_privacy_custody(),
    )
    task = _task(runtime.journal, SchedulerPassKind.ORIENTATION)
    plan = runtime.seal_pass(SchedulerPassKind.ORIENTATION, (task,))
    activation = runtime.journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=task.response_schema_sha256,
    )
    runtime._activations[task.task_id] = activation
    usage = _failed_accountable_mock_usage(
        plan,
        task,
        activation,
        reported_cost_usd_exact=None,
        accounted_cost_usd_exact="0",
        released_before_send=True,
    )
    reservation = ledger.reserve(task.logical_request_id, Decimal("0.25"))
    released = ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)

    result = runtime.record_failure(
        task,
        RuntimeError("synthetic pre-send host failure"),
        usage_records=(usage,),
        atomic_ledger=ledger,
    )

    assert result.terminal_status is SchedulerTerminalStatus.FAILED
    assert result.terminal_evidence_sha256 == cost_entry_sha256(released)
    assert runtime.journal.retained_provider_usage_records == (usage,)
    assert tuple(event.kind for event in runtime.journal.events)[-1] is (
        SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL
    )
    runtime.close()

    resumed = PipelineScheduler.resume(
        tmp_path / "live-release-journal",
        bindings=bindings,
        analysis_input_inventory=_analysis_inventory(),
        shard_inventory=_inventory(),
        atomic_ledger=ledger,
    )
    records, recovery_scope = resumed.journal.claim_restorable_usage_for_budget_recovery(
        atomic_ledger=ledger
    )
    budget = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
        global_input_token_budget=100,
        global_output_token_budget=200,
    )
    await budget.restore_recovered_usage(records, recovery_scope=recovery_scope)
    assert records == (usage,)
    assert budget.spent_usd_exact == 0
    assert budget.spent_input_tokens == 0
    assert budget.spent_output_tokens == 0
    assert budget._request_limit_counts[("scheduled_task", task.logical_request_id)] == 1
    resumed.close()


def test_live_activated_release_crash_after_attempt_checkpoint_terminalizes_on_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = AtomicCostLedger.initialize(
        tmp_path / "attempt-crash-ledger.json", cap_usd=Decimal("1")
    )
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    bindings = _bindings(cost_ledger_baseline_sha256=baseline.baseline_sha256)
    journal = create_scheduler_journal(
        tmp_path / "attempt-crash-journal",
        bindings=bindings,
        shard_inventory=_inventory(),
        cost_ledger_baseline=baseline,
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
    usage = _failed_accountable_mock_usage(
        plan,
        task,
        activation,
        reported_cost_usd_exact=None,
        accounted_cost_usd_exact="0",
        released_before_send=True,
    )
    reservation = ledger.reserve(task.logical_request_id, Decimal("0.25"))
    released = ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)

    def crash_before_terminal(_result: SchedulerTaskResult) -> NoReturn:
        raise RuntimeError("synthetic crash after provider-attempt checkpoint")

    monkeypatch.setattr(journal, "record_activated_preflight_failure", crash_before_terminal)
    with pytest.raises(RuntimeError, match="after provider-attempt checkpoint"):
        journal.record_released_provider_failure(
            task.task_id,
            usage_records=(usage,),
            atomic_ledger=ledger,
        )
    assert journal.retained_provider_usage_records == (usage,)
    assert tuple(event.kind for event in journal.events)[-1] is SchedulerTaskEventKind.ACTIVATED
    journal.close()

    resumed = resume_scheduler_journal(
        tmp_path / "attempt-crash-journal",
        expected_bindings=bindings,
        expected_shard_inventory=_inventory(),
        atomic_ledger=ledger,
    )
    assert resumed.task_results[0].terminal_status is SchedulerTerminalStatus.FAILED
    assert resumed.task_results[0].terminal_evidence_sha256 == cost_entry_sha256(released)
    assert tuple(event.kind for event in resumed.events)[-1] is (
        SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL
    )
    resumed.close()


@pytest.mark.parametrize("dispatched", [False, True])
def test_live_release_crash_before_attempt_checkpoint_terminalizes_on_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    dispatched: bool,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    ledger = AtomicCostLedger.initialize(
        tmp_path / "attempt-checkpoint-crash-ledger.json",
        cap_usd=Decimal("1"),
    )
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    bindings = _bindings(cost_ledger_baseline_sha256=baseline.baseline_sha256)
    journal = create_scheduler_journal(
        tmp_path / "attempt-checkpoint-crash-journal",
        bindings=bindings,
        shard_inventory=_inventory(),
        cost_ledger_baseline=baseline,
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
    if dispatched:
        journal.mark_dispatched(task.task_id)
    usage = _failed_accountable_mock_usage(
        plan,
        task,
        activation,
        reported_cost_usd_exact=None,
        accounted_cost_usd_exact="0",
        released_before_send=True,
    )
    reservation = ledger.reserve(task.logical_request_id, Decimal("0.25"))
    released = ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)

    def crash_before_attempt_checkpoint() -> NoReturn:
        raise SimulatedProcessDeath

    monkeypatch.setattr(
        journal,
        "_refresh_journal_head_checkpoint",
        crash_before_attempt_checkpoint,
    )
    with pytest.raises(SimulatedProcessDeath):
        journal.record_released_provider_failure(
            task.task_id,
            usage_records=(usage,),
            atomic_ledger=ledger,
        )
    assert journal.retained_provider_usage_records == (usage,)
    assert tuple(event.kind for event in journal.events)[-1] is (
        SchedulerTaskEventKind.DISPATCHED if dispatched else SchedulerTaskEventKind.ACTIVATED
    )
    journal.close()

    resumed = resume_scheduler_journal(
        tmp_path / "attempt-checkpoint-crash-journal",
        expected_bindings=bindings,
        expected_shard_inventory=_inventory(),
        atomic_ledger=ledger,
    )
    assert resumed.task_results[0].terminal_status is SchedulerTerminalStatus.FAILED
    assert resumed.task_results[0].terminal_evidence_sha256 == cost_entry_sha256(released)
    assert tuple(event.kind for event in resumed.events)[-1] is (
        SchedulerTaskEventKind.TERMINAL
        if dispatched
        else SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL
    )
    resumed.close()


@pytest.mark.parametrize("dispatched", [False, True])
@pytest.mark.parametrize("second_crash", ["result-publication", "checkpoint-pending"])
def test_uncheckpointed_live_release_survives_a_second_recovery_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    dispatched: bool,
    second_crash: str,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    ledger = AtomicCostLedger.initialize(
        tmp_path / f"released-twice-{dispatched}-{second_crash}-ledger.json",
        cap_usd=Decimal("1"),
    )
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    bindings = _bindings(cost_ledger_baseline_sha256=baseline.baseline_sha256)
    journal_path = tmp_path / f"released-twice-{dispatched}-{second_crash}-journal"
    journal = create_scheduler_journal(
        journal_path,
        bindings=bindings,
        shard_inventory=_inventory(),
        cost_ledger_baseline=baseline,
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
    if dispatched:
        journal.mark_dispatched(task.task_id)
    predecessor = journal.journal_evidence
    usage = _failed_accountable_mock_usage(
        plan,
        task,
        activation,
        reported_cost_usd_exact=None,
        accounted_cost_usd_exact="0",
        released_before_send=True,
    )
    reservation = ledger.reserve(task.logical_request_id, Decimal("0.25"))
    released = ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)

    def crash_before_attempt_checkpoint() -> NoReturn:
        raise SimulatedProcessDeath

    monkeypatch.setattr(
        journal,
        "_refresh_journal_head_checkpoint",
        crash_before_attempt_checkpoint,
    )
    with pytest.raises(SimulatedProcessDeath):
        journal.record_released_provider_failure(
            task.task_id,
            usage_records=(usage,),
            atomic_ledger=ledger,
        )
    journal.close()
    monkeypatch.undo()

    original_publish = scheduler_module._write_fresh_private_file

    def crash_during_recovered_terminal(
        parent_descriptor: int,
        leaf: str,
        content: bytes,
    ) -> None:
        original_publish(parent_descriptor, leaf, content)
        if (second_crash == "result-publication" and leaf.startswith(f"{task.task_id}-")) or (
            second_crash == "checkpoint-pending"
            and leaf == scheduler_module._JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME
            and SchedulerJournalEvidence.model_validate_json(content).task_result_count == 1
        ):
            raise SimulatedProcessDeath

    monkeypatch.setattr(
        scheduler_module,
        "_write_fresh_private_file",
        crash_during_recovered_terminal,
    )
    with pytest.raises(SimulatedProcessDeath):
        resume_scheduler_journal(
            journal_path,
            expected_bindings=bindings,
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=predecessor,
            atomic_ledger=ledger,
        )
    monkeypatch.undo()

    phase_snapshot = _journal_private_file_snapshot(journal_path)
    ledger_bytes = ledger.path.read_bytes()
    with pytest.raises(ValueError, match="resume journal evidence does not match"):
        resume_scheduler_journal(
            journal_path,
            expected_bindings=bindings,
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=predecessor,
            atomic_ledger=ledger,
        )
    assert _journal_private_file_snapshot(journal_path) == phase_snapshot
    assert ledger.path.read_bytes() == ledger_bytes

    resumed = resume_scheduler_journal(
        journal_path,
        expected_bindings=bindings,
        expected_shard_inventory=_inventory(),
        atomic_ledger=ledger,
    )
    assert resumed.task_results[0].terminal_evidence_sha256 == cost_entry_sha256(released)
    assert tuple(item.kind for item in resumed.events)[-1] is (
        SchedulerTaskEventKind.TERMINAL
        if dispatched
        else SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL
    )
    recovered = resumed.journal_evidence
    resumed.close()
    replayed = resume_scheduler_journal(
        journal_path,
        expected_bindings=bindings,
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=recovered,
        atomic_ledger=ledger,
    )
    assert replayed.journal_evidence == recovered
    replayed.close()


@pytest.mark.parametrize("dispatched", [False, True])
@pytest.mark.parametrize("tamper_pending", [False, True])
def test_live_release_pending_checkpoint_is_adopted_only_after_exact_resume_join(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    dispatched: bool,
    tamper_pending: bool,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    ledger = AtomicCostLedger.initialize(
        tmp_path / "pending-checkpoint-ledger.json",
        cap_usd=Decimal("1"),
    )
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    bindings = _bindings(cost_ledger_baseline_sha256=baseline.baseline_sha256)
    journal_path = tmp_path / "pending-checkpoint-journal"
    journal = create_scheduler_journal(
        journal_path,
        bindings=bindings,
        shard_inventory=_inventory(),
        cost_ledger_baseline=baseline,
    )
    wrong_expected = journal.journal_evidence
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
    if dispatched:
        journal.mark_dispatched(task.task_id)
    expected = journal.journal_evidence
    checkpoint_path = journal_path / "journal-head-checkpoint.json"
    checkpoint_before = checkpoint_path.read_bytes()
    usage = _failed_accountable_mock_usage(
        plan,
        task,
        activation,
        reported_cost_usd_exact=None,
        accounted_cost_usd_exact="0",
        released_before_send=True,
    )
    reservation = ledger.reserve(task.logical_request_id, Decimal("0.25"))
    released = ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)
    ledger_before = ledger.path.read_bytes()
    original_write = scheduler_module._write_fresh_private_file

    def crash_after_pending_fsync(
        parent_descriptor: int,
        leaf: str,
        content: bytes,
    ) -> None:
        original_write(parent_descriptor, leaf, content)
        if leaf == scheduler_module._JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME:
            raise SimulatedProcessDeath

    monkeypatch.setattr(
        scheduler_module,
        "_write_fresh_private_file",
        crash_after_pending_fsync,
    )
    with pytest.raises(SimulatedProcessDeath):
        journal.record_released_provider_failure(
            task.task_id,
            usage_records=(usage,),
            atomic_ledger=ledger,
        )
    journal.close()
    monkeypatch.setattr(
        scheduler_module,
        "_write_fresh_private_file",
        original_write,
    )
    pending_path = journal_path / scheduler_module._JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME
    assert pending_path.is_file()

    with pytest.raises(ValueError, match="resume journal evidence does not match"):
        resume_scheduler_journal(
            journal_path,
            expected_bindings=bindings,
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=wrong_expected,
            atomic_ledger=ledger,
        )
    assert pending_path.is_file()
    assert checkpoint_path.read_bytes() == checkpoint_before
    assert ledger.path.read_bytes() == ledger_before

    if tamper_pending:
        pending_path.write_bytes(b"{}")
        with pytest.raises(ValueError, match="artifact is invalid"):
            resume_scheduler_journal(
                journal_path,
                expected_bindings=bindings,
                expected_shard_inventory=_inventory(),
                expected_journal_evidence=expected,
                atomic_ledger=ledger,
            )
        assert pending_path.read_bytes() == b"{}"
        assert checkpoint_path.read_bytes() == checkpoint_before
        assert ledger.path.read_bytes() == ledger_before
        return

    for _resume_ordinal in range(2):
        resumed = resume_scheduler_journal(
            journal_path,
            expected_bindings=bindings,
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=expected if _resume_ordinal == 0 else None,
            atomic_ledger=ledger,
        )
        assert resumed.task_results[0].terminal_status is SchedulerTerminalStatus.FAILED
        assert resumed.task_results[0].terminal_evidence_sha256 == cost_entry_sha256(released)
        assert tuple(event.kind for event in resumed.events)[-1] is (
            SchedulerTaskEventKind.TERMINAL
            if dispatched
            else SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL
        )
        assert not pending_path.exists()
        assert ledger.path.read_bytes() == ledger_before
        resumed.close()


@pytest.mark.parametrize("dispatched", [False, True])
@pytest.mark.parametrize("crash_stage", ["result", "terminal_checkpoint"])
def test_live_release_terminal_suffix_crashes_resume_exact_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    dispatched: bool,
    crash_stage: str,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    ledger = AtomicCostLedger.initialize(
        tmp_path / "terminal-checkpoint-crash-ledger.json",
        cap_usd=Decimal("1"),
    )
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    bindings = _bindings(cost_ledger_baseline_sha256=baseline.baseline_sha256)
    journal = create_scheduler_journal(
        tmp_path / "terminal-checkpoint-crash-journal",
        bindings=bindings,
        shard_inventory=_inventory(),
        cost_ledger_baseline=baseline,
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
    if dispatched:
        journal.mark_dispatched(task.task_id)
    usage = _failed_accountable_mock_usage(
        plan,
        task,
        activation,
        reported_cost_usd_exact=None,
        accounted_cost_usd_exact="0",
        released_before_send=True,
    )
    reservation = ledger.reserve(task.logical_request_id, Decimal("0.25"))
    released = ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)
    if crash_stage == "result":

        def crash_before_terminal_event(**_values: Any) -> NoReturn:
            raise SimulatedProcessDeath

        monkeypatch.setattr(journal, "_append_event", crash_before_terminal_event)
    else:
        original_refresh = journal._refresh_journal_head_checkpoint
        refresh_calls = 0

        def crash_before_terminal_checkpoint() -> SchedulerJournalEvidence:
            nonlocal refresh_calls
            refresh_calls += 1
            if refresh_calls == 2:
                raise SimulatedProcessDeath
            return original_refresh()

        monkeypatch.setattr(
            journal,
            "_refresh_journal_head_checkpoint",
            crash_before_terminal_checkpoint,
        )
    with pytest.raises(SimulatedProcessDeath):
        journal.record_released_provider_failure(
            task.task_id,
            usage_records=(usage,),
            atomic_ledger=ledger,
        )
    assert journal.result_observations[0].terminal_evidence_sha256 == cost_entry_sha256(released)
    if crash_stage == "result":
        assert journal.task_results == ()
        assert tuple(event.kind for event in journal.events)[-1] is (
            SchedulerTaskEventKind.DISPATCHED if dispatched else SchedulerTaskEventKind.ACTIVATED
        )
    else:
        assert journal.task_results[0].terminal_evidence_sha256 == cost_entry_sha256(released)
        assert tuple(event.kind for event in journal.events)[-1] is (
            SchedulerTaskEventKind.TERMINAL
            if dispatched
            else SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL
        )
    journal.close()

    resumed = resume_scheduler_journal(
        tmp_path / "terminal-checkpoint-crash-journal",
        expected_bindings=bindings,
        expected_shard_inventory=_inventory(),
        atomic_ledger=ledger,
    )
    assert resumed.task_results[0].terminal_status is SchedulerTerminalStatus.FAILED
    assert resumed.task_results[0].terminal_evidence_sha256 == cost_entry_sha256(released)
    assert tuple(event.kind for event in resumed.events)[-1] is (
        SchedulerTaskEventKind.TERMINAL
        if dispatched
        else SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL
    )
    resumed.close()


@pytest.mark.asyncio
async def test_no_usage_uncertain_prefix_and_released_tail_restore_exactly_once(
    tmp_path: Path,
) -> None:
    path = tmp_path / "uncertain-released-no-usage"
    journal = create_scheduler_journal(
        path,
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
    ledger = AtomicCostLedger.initialize(
        tmp_path / "uncertain-released-no-usage.json",
        cap_usd=Decimal("1"),
    )
    first = ledger.reserve(task.logical_request_id, Decimal("0.10"))
    ledger.reconcile(first, None)
    tail = ledger.reserve(f"{task.logical_request_id}:attempt:2", Decimal("0.20"))
    released = ledger.release(tail, reason=ReleaseReason.FAILED_BEFORE_SEND)
    expected_result = SchedulerTaskResult.build(
        plan=plan,
        task=task,
        activation=activation,
        terminal_status=SchedulerTerminalStatus.FAILED,
        terminal_evidence_sha256=cost_entry_sha256(released),
    )
    journal.close()
    ledger_bytes = ledger.path.read_bytes()

    for _resume_ordinal in range(2):
        resumed = resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            atomic_ledger=ledger,
        )
        assert resumed.task_results == (expected_result,)
        budget = BudgetManager(
            total_usd=1,
            max_output_tokens=10,
            conservative_usd_per_million_tokens=1,
            max_requests_per_agent=10,
            atomic_ledger=ledger,
            global_input_token_budget=100,
            global_output_token_budget=200,
        )
        records, recovery_scope = resumed.claim_restorable_usage_for_budget_recovery(
            atomic_ledger=ledger
        )
        await budget.restore_recovered_usage(records, recovery_scope=recovery_scope)
        assert budget.spent_usd_exact == Decimal("0.10")
        assert budget.spent_input_tokens == 100
        assert budget.spent_output_tokens == 200
        assert budget._request_limit_counts[("scheduled_task", task.logical_request_id)] == 2
        assert ledger.path.read_bytes() == ledger_bytes
        resumed.close()


def test_no_usage_released_attempt_rejects_wrong_terminal_hash_before_mutation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "wrong-released-terminal"
    journal = create_scheduler_journal(
        path,
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
    ledger = AtomicCostLedger.initialize(
        tmp_path / "wrong-released-terminal.json",
        cap_usd=Decimal("1"),
    )
    reservation = ledger.reserve(task.logical_request_id, Decimal("0.25"))
    ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)
    journal.record_activated_preflight_failure(
        SchedulerTaskResult.build(
            plan=plan,
            task=task,
            activation=activation,
            terminal_status=SchedulerTerminalStatus.FAILED,
            terminal_evidence_sha256="d" * 64,
        )
    )
    journal.close()
    before_snapshot = ledger.snapshot()
    before_bytes = ledger.path.read_bytes()

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        atomic_ledger=ledger,
    )
    with pytest.raises(ValueError, match="differs from its scheduler terminal"):
        resumed.claim_restorable_usage_for_budget_recovery(atomic_ledger=ledger)
    assert ledger.snapshot() == before_snapshot
    assert ledger.path.read_bytes() == before_bytes
    resumed.close()


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
    ledger = AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("20"))
    reservation = ledger.reserve("prior-request", Decimal("0.10"))
    ledger.reconcile(reservation, Decimal("0.05"))

    baseline = build_scheduler_cost_ledger_baseline(ledger)
    reopened = AtomicCostLedger.open_existing(ledger_path, cap_usd=Decimal("20"))
    reopened_baseline = build_scheduler_cost_ledger_baseline(reopened)
    serialized = baseline.model_dump_json()

    assert reopened_baseline == baseline
    assert baseline.cap_usd_exact == "20"
    assert baseline.spent_usd_exact == "0.05"
    assert baseline.active_reserved_usd_exact == "0"
    assert scheduler_module._canonical_recovery_usd_sum(("20.000000000000",)) == "20"
    assert ledger_path.as_posix() not in serialized
    assert ledger.lock_path.as_posix() not in serialized
    assert ledger_path.name not in serialized


def test_scheduler_recovery_cost_sum_bounds_a_lying_iterable() -> None:
    class LyingCosts:
        def __init__(self) -> None:
            self.consumed = 0

        def __len__(self) -> int:
            return 0

        def __iter__(self) -> Iterator[str]:
            while True:
                self.consumed += 1
                yield "0"

    values = LyingCosts()
    with pytest.raises(ValueError, match="cost evidence exceeds its item limit"):
        scheduler_module._canonical_recovery_usd_sum(values)
    assert values.consumed == scheduler_module._TRUNCATION_RECOVERY_COST_COMPONENT_LIMIT + 1


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


def test_pipeline_scheduler_requires_live_refresh_guard_on_create_and_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = _inventory()
    analysis_inventory = _analysis_inventory()
    privacy_custody = _privacy_custody(source_sha256=inventory.source_tree_sha256)
    refresh = synthetic_refresh_runtime(
        tmp_path / "refresh-authority",
        source_sha256_override=inventory.source_tree_sha256,
    )
    bindings = build_scheduler_bindings(
        config=refresh.config,
        shard_inventory=inventory,
        qualification=refresh.technical_qualification,
        analysis_input_sha256=analysis_inventory.analysis_input_sha256,
        privacy_evidence_custody=privacy_custody,
        audit_model_selection_evidence=refresh.audit_selection_evidence,
        audit_model_refresh_evidence=refresh.evidence,
    )
    assert bindings.audit_model_refresh is not None
    assert bindings.audit_model_refresh.guard_capability_sha256 == refresh.guard.capability_sha256
    journal_path = tmp_path / "journal"

    with pytest.raises(ValueError, match="must be one exact atomic pair"):
        PipelineScheduler.create(
            journal_path,
            bindings=bindings,
            analysis_input_inventory=analysis_inventory,
            shard_inventory=inventory,
            privacy_evidence_custody=privacy_custody,
            audit_model_refresh_evidence=refresh.evidence,
        )
    with pytest.raises(ValueError, match="requires live model-refresh authority"):
        PipelineScheduler.create(
            journal_path,
            bindings=bindings,
            analysis_input_inventory=analysis_inventory,
            shard_inventory=inventory,
            privacy_evidence_custody=privacy_custody,
        )
    assert not journal_path.exists()

    monkeypatch.setattr(
        scheduler_module,
        "_scheduler_wall_clock",
        lambda: refresh.verified_at,
    )
    scheduler = PipelineScheduler.create(
        journal_path,
        bindings=bindings,
        analysis_input_inventory=analysis_inventory,
        shard_inventory=inventory,
        privacy_evidence_custody=privacy_custody,
        audit_model_refresh_evidence=refresh.evidence,
        audit_model_refresh_guard=refresh.guard,
        production_qualification=refresh.technical_qualification,
        audit_model_selection=refresh.audit_selection,
    )
    scheduler.close()

    serialized = (journal_path / "manifest.json").read_text(encoding="utf-8")
    assert refresh.evidence.evidence_sha256 in serialized
    assert refresh.guard.capability_sha256 in serialized
    assert '"audit_model_refresh_guard":' not in serialized

    with pytest.raises(ValueError, match="requires live model-refresh authority"):
        PipelineScheduler.resume(
            journal_path,
            bindings=bindings,
            analysis_input_inventory=analysis_inventory,
            shard_inventory=inventory,
        )
    resumed = PipelineScheduler.resume(
        journal_path,
        bindings=bindings,
        analysis_input_inventory=analysis_inventory,
        shard_inventory=inventory,
        audit_model_refresh_evidence=refresh.evidence,
        audit_model_refresh_guard=refresh.guard,
        production_qualification=refresh.technical_qualification,
        audit_model_selection=refresh.audit_selection,
    )
    with pytest.raises(ValueError, match="lacks live model-refresh recovery authority"):
        resumed.journal.claim_restorable_usage_records()
    resumed.close()


def test_pricing_bound_recovery_rechecks_actual_wall_clock_before_ledger_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = _inventory()
    analysis_inventory = _analysis_inventory()
    privacy_custody = _privacy_custody(source_sha256=inventory.source_tree_sha256)
    refresh = synthetic_refresh_runtime(
        tmp_path / "pricing-recovery-authority",
        source_sha256_override=inventory.source_tree_sha256,
    )
    ledger_path = tmp_path / "pricing-recovery-cost.json"
    ledger = AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("1"))
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    bindings = build_scheduler_bindings(
        config=refresh.config,
        shard_inventory=inventory,
        qualification=refresh.technical_qualification,
        analysis_input_sha256=analysis_inventory.analysis_input_sha256,
        cost_ledger_baseline=baseline,
        privacy_evidence_custody=privacy_custody,
        audit_model_selection_evidence=refresh.audit_selection_evidence,
        audit_model_refresh_evidence=refresh.evidence,
        audit_model_refresh_pricing_evidence=refresh.pricing_evidence,
    )
    assert bindings.audit_model_selection is not None
    selected = bindings.audit_model_selection.selected_routes[0]
    journal_path = tmp_path / "pricing-recovery-journal"
    monkeypatch.setattr(scheduler_module, "_scheduler_wall_clock", lambda: refresh.verified_at)
    journal = _create_scheduler_journal(
        journal_path,
        bindings=bindings,
        analysis_input_inventory=analysis_inventory,
        shard_inventory=inventory,
        cost_ledger_baseline=baseline,
        privacy_evidence_custody=privacy_custody,
        audit_model_refresh_evidence=refresh.evidence,
        audit_model_refresh_guard=refresh.guard,
        audit_model_refresh_pricing_evidence=refresh.pricing_evidence,
        audit_model_refresh_pricing_authority=refresh.pricing_authority,
        production_qualification=refresh.technical_qualification,
        audit_model_selection=refresh.audit_selection,
    )
    task = SchedulerTaskPlan.build(
        manifest=journal.manifest,
        pass_kind=SchedulerPassKind.ORIENTATION,
        scope=SchedulerScope.global_scope(),
        task_kind=SchedulerTaskKind.MODEL_REQUEST,
        task_key="pricing-expiry-recovery",
        role="threat_model",
        requested_model=selected.exact_model_id,
        root_lineage=selected.root_lineage,
        candidate_ids=(),
        input_sha256="9" * 64,
        prompt_sha256="a" * 64,
        response_schema_sha256=scheduler_test_response_schema_sha256(
            SchedulerPassKind.ORIENTATION,
            "threat_model",
        ),
        **scheduler_test_model_fields("pricing-expiry-recovery"),
    )
    plan = journal.seal_pass_plan(
        SchedulerPassPlan.build(
            manifest=journal.manifest,
            pass_kind=SchedulerPassKind.ORIENTATION,
            dependencies=journal.next_dependencies,
            tasks=(task,),
        )
    )
    sealed_task = plan.tasks[0]
    journal.activate_task(
        sealed_task.task_id,
        actual_input_sha256=sealed_task.input_sha256,
        system_prompt_sha256=sealed_task.system_prompt_sha256,
        user_prompt_sha256="1" * 64,
        provider_prompt_sha256="2" * 64,
        response_schema_sha256=sealed_task.response_schema_sha256,
    )
    journal.mark_dispatched(sealed_task.task_id)
    ledger.reserve(sealed_task.logical_request_id, Decimal("0.25"))
    journal.close()

    resumed = _resume_scheduler_journal(
        journal_path,
        expected_bindings=bindings,
        expected_analysis_input_inventory=analysis_inventory,
        expected_shard_inventory=inventory,
        expected_cost_ledger_baseline=baseline,
        atomic_ledger=ledger,
        audit_model_refresh_evidence=refresh.evidence,
        audit_model_refresh_guard=refresh.guard,
        audit_model_refresh_pricing_evidence=refresh.pricing_evidence,
        audit_model_refresh_pricing_authority=refresh.pricing_authority,
        production_qualification=refresh.technical_qualification,
        audit_model_selection=refresh.audit_selection,
    )
    before_snapshot = ledger.snapshot()
    before_bytes = ledger_path.read_bytes()
    monkeypatch.setattr(
        scheduler_module,
        "_scheduler_wall_clock",
        lambda: refresh.pricing_evidence.expires_at,
    )

    with pytest.raises(ValueError, match="recovery authority is expired"):
        resumed.recover_active_cost_reservations(ledger)
    assert ledger.snapshot() == before_snapshot
    assert ledger_path.read_bytes() == before_bytes
    with pytest.raises(ValueError, match="recovery authority is expired"):
        resumed.claim_restorable_usage_for_budget_recovery(atomic_ledger=ledger)
    assert ledger.snapshot() == before_snapshot
    assert ledger_path.read_bytes() == before_bytes
    resumed.close()


def test_refresh_bound_raw_resume_refuses_before_active_ledger_mutation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "refresh-raw-resume"
    bindings = _bindings(with_audit_policy=True)
    journal = create_scheduler_journal(
        path,
        bindings=bindings,
        shard_inventory=_inventory(),
    )
    journal.close()
    ledger = AtomicCostLedger.initialize(
        tmp_path / "active-refresh-ledger.json",
        cap_usd=Decimal("1"),
    )
    ledger.reserve("synthetic-auditor-v1-attempt-1", Decimal("0.25"))
    before = ledger.snapshot()

    with pytest.raises(ValueError, match="requires live model-refresh authority"):
        resume_scheduler_journal(
            path,
            expected_bindings=bindings,
            expected_shard_inventory=_inventory(),
            atomic_ledger=ledger,
        )

    assert ledger.snapshot() == before


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


def test_resume_rejects_missing_planned_suffix_against_local_head(
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

    with pytest.raises(ValueError):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )


def test_result_without_checkpoint_update_fails_closed_before_recovery(
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

    with pytest.raises(ValueError, match="local journal-head checkpoint does not match"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )


def test_output_without_terminal_result_recovers_deterministic_success(
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
    assert resumed.task_results[0].terminal_status is SchedulerTerminalStatus.SUCCEEDED
    assert resumed.task_results[0].terminal_evidence_sha256 == usage.validated_response_sha256
    assert resumed.uncertain_task_ids == ()
    assert resumed.resumable_task_ids == ()
    assert resumed.artifact().journal_evidence.task_output_count == 1
    assert resumed.artifact().journal_evidence.succeeded_count == 1
    resumed.close()


def test_resume_rejects_preflight_event_rollback_against_local_head(tmp_path: Path) -> None:
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

    with pytest.raises(ValueError, match="local journal-head checkpoint does not match"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )


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


def test_deleted_tail_pass_result_fails_closed_against_local_head(tmp_path: Path) -> None:
    path = tmp_path / "journal"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    for pass_kind in SCHEDULER_PASS_ORDER:
        _complete_pass(journal, pass_kind)
    assert journal.require_complete().status is SchedulerCampaignStatus.COMPLETE
    journal.close()
    (path / "pass-results" / "pass-07-result.json").unlink()

    with pytest.raises(ValueError, match="local journal-head checkpoint does not match"):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )


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


def test_exact_journal_owner_rejects_copy_pickle_and_object_new_clone(tmp_path: Path) -> None:
    path = tmp_path / "journal-owner"
    owner = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())

    with pytest.raises(TypeError, match="cannot be copied"):
        copy(owner)
    with pytest.raises(TypeError, match="cannot be copied"):
        deepcopy(owner)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(owner)

    clone = object.__new__(SchedulerJournal)
    vars(clone).update(vars(owner))
    before = _journal_private_file_snapshot(path)
    with pytest.raises(ValueError, match="exact process-local custody owner"):
        clone.close()
    with pytest.raises(ValueError, match="exact process-local custody owner"):
        clone.seal_pass_plan(_plan(owner, SchedulerPassKind.ORIENTATION))
    assert _journal_private_file_snapshot(path) == before

    plan = owner.seal_pass_plan(_plan(owner, SchedulerPassKind.ORIENTATION))
    assert owner.resumable_task_ids == (plan.tasks[0].task_id,)
    owner.close()
    owner.close()


def test_scheduler_journal_direct_constructor_and_generic_permit_are_absent() -> None:
    assert not hasattr(scheduler_module, "_reserve_live_custody")
    assert not hasattr(scheduler_module, "_bind_live_journal_owner")
    assert not hasattr(scheduler_module, "_admit_scheduler_journal_opening")

    with pytest.raises(TypeError, match="authenticated openers"):
        SchedulerJournal()
    raw = object.__new__(SchedulerJournal)
    with pytest.raises(TypeError, match="authenticated openers"):
        SchedulerJournal.__init__(raw)


def test_opening_and_live_custody_reject_unlocked_exact_lock_file_descriptor(
    tmp_path: Path,
) -> None:
    path = tmp_path / "unlocked-lock"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    metadata = scheduler_module._assert_exact_live_journal_owner(journal)
    unlocked = os.open(
        ".scheduler.lock",
        os.O_RDWR | getattr(os, "O_CLOEXEC", 0),
        dir_fd=metadata.root_descriptor,
    )
    try:
        with pytest.raises(ValueError, match="exact owner"):
            scheduler_module._assert_opening_descriptor_custody(
                replace(metadata, lock_descriptor=unlocked)
            )
    finally:
        os.close(unlocked)
        journal.close()

    unlocked_path = tmp_path / "unlock-after-open"
    unlocked_owner = create_scheduler_journal(
        unlocked_path,
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    plan = _plan(unlocked_owner, SchedulerPassKind.ORIENTATION)
    live_metadata = scheduler_module._assert_exact_live_journal_owner(unlocked_owner)
    before = _journal_private_file_snapshot(unlocked_path)
    fcntl.flock(live_metadata.lock_descriptor, fcntl.LOCK_UN)
    with pytest.raises(ValueError, match="lock descriptor is not held"):
        unlocked_owner.seal_pass_plan(plan)
    assert _journal_private_file_snapshot(unlocked_path) == before
    unlocked_owner.close()


def test_verification_opening_mode_cannot_be_flipped_writable(tmp_path: Path) -> None:
    path = tmp_path / "verification-mode"
    created = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    created.close()
    verifier = open_scheduler_journal_for_verification(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    plan = _plan(verifier, SchedulerPassKind.ORIENTATION)
    before = _journal_private_file_snapshot(path)
    object.__setattr__(verifier, "_read_only", False)
    with pytest.raises(ValueError, match="instance fields differ from frozen custody"):
        verifier.seal_pass_plan(plan)
    assert _journal_private_file_snapshot(path) == before
    verifier.close()


def test_copied_root_cannot_construct_or_rewrap_a_live_owner(tmp_path: Path) -> None:
    source = tmp_path / "source-journal"
    copied = tmp_path / "copied-journal"
    created = create_scheduler_journal(source, bindings=_bindings(), shard_inventory=_inventory())
    created.close()
    shutil.copytree(source, copied)

    with pytest.raises(TypeError, match="authenticated openers"):
        SchedulerJournal(path=copied)

    verifier = open_scheduler_journal_for_verification(
        copied,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    clone = object.__new__(SchedulerJournal)
    vars(clone).update(vars(verifier))
    before = _journal_private_file_snapshot(copied)
    with pytest.raises(ValueError, match="exact process-local custody owner"):
        clone.close()
    assert _journal_private_file_snapshot(copied) == before
    verifier.close()


def test_exact_journal_close_is_thread_safe_and_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "thread-close"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    barrier = threading.Barrier(3)
    failures: list[BaseException] = []

    def close_once() -> None:
        barrier.wait()
        try:
            journal.close()
        except BaseException as exc:  # pragma: no cover - asserted by the parent thread
            failures.append(exc)

    threads = [threading.Thread(target=close_once) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert failures == []
    journal.close()

    reopened = open_scheduler_journal_for_verification(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
    )
    reopened.close()


def test_custody_metadata_and_cleanup_claim_are_detached_and_exact(tmp_path: Path) -> None:
    path = tmp_path / "detached-custody"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    metadata = scheduler_module._assert_exact_live_journal_owner(journal)
    object.__setattr__(metadata, "root_descriptor", -1)
    object.__setattr__(metadata, "read_only", True)

    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    assert journal.resumable_task_ids == (plan.tasks[0].task_id,)

    claim = scheduler_module._claim_live_journal_close(journal)
    assert claim is not None
    exact_token = claim.token
    object.__setattr__(claim, "token", object())
    with pytest.raises(ValueError, match="cleanup claim is absent or forged"):
        scheduler_module._resolve_journal_cleanup(claim)
    object.__setattr__(claim, "token", exact_token)
    scheduler_module._cleanup_journal_claim(claim)
    journal.close()


def test_close_cleanup_uncertainty_is_orphaned_and_never_reclaimed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "orphaned-close"
    journal = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    original_flock = fcntl.flock
    raised = False

    def unlock_then_report_uncertainty(descriptor: int, operation: int) -> None:
        nonlocal raised
        original_flock(descriptor, operation)
        if operation == fcntl.LOCK_UN and not raised:
            raised = True
            raise OSError("synthetic post-unlock uncertainty")

    with monkeypatch.context() as patch:
        patch.setattr(fcntl, "flock", unlock_then_report_uncertainty)
        with pytest.raises(ValueError, match="cleanup failed closed"):
            journal.close()

    with pytest.raises(ValueError, match="cleanup is orphaned"):
        journal.close()
    with pytest.raises(ValueError, match="live in-process custody"):
        open_scheduler_journal_for_verification(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
        )


def test_fork_cannot_close_or_rereserve_inherited_root_but_can_create_fresh_root(
    tmp_path: Path,
) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("process-local fork custody requires os.fork")
    path = tmp_path / "parent-journal"
    fresh_path = tmp_path / "child-fresh-journal"
    owner = create_scheduler_journal(path, bindings=_bindings(), shard_inventory=_inventory())
    read_descriptor, write_descriptor = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - asserted through the parent-side pipe
        os.close(read_descriptor)
        outcomes: list[str] = []
        try:
            owner.close()
        except ValueError:
            outcomes.append("close-rejected")
        try:
            resume_scheduler_journal(
                path,
                expected_bindings=_bindings(),
                expected_shard_inventory=_inventory(),
            )
        except ValueError:
            outcomes.append("reserve-rejected")
        try:
            fresh = create_scheduler_journal(
                fresh_path,
                bindings=_bindings(),
                shard_inventory=_inventory(),
            )
            fresh.close()
        except BaseException:
            outcomes.append("fresh-failed")
        else:
            outcomes.append("fresh-created")
        os.write(write_descriptor, ",".join(outcomes).encode())
        os.close(write_descriptor)
        os._exit(0)
    os.close(write_descriptor)
    try:
        result = os.read(read_descriptor, 128)
    finally:
        os.close(read_descriptor)
    waited_pid, status = os.waitpid(child_pid, 0)
    assert waited_pid == child_pid
    assert os.waitstatus_to_exitcode(status) == 0
    assert result == b"close-rejected,reserve-rejected,fresh-created"

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
    original = scheduler_module._assert_root_path_identity
    swapped = False

    def swap_before_identity_check(
        opened_path: Path,
        root_descriptor: int,
        expected: tuple[int, int, int],
    ) -> None:
        nonlocal swapped
        if not swapped:
            retained = tmp_path / "retained-journal"
            path.rename(retained)
            shutil.copytree(retained, path)
            swapped = True
        original(opened_path, root_descriptor, expected)

    monkeypatch.setattr(
        scheduler_module,
        "_assert_root_path_identity",
        swap_before_identity_check,
    )
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
        **kwargs: Any,
    ) -> Any:
        nonlocal swapped
        if not swapped:
            (path / "events").rename(tmp_path / "retained-events")
            (path / "events").mkdir(mode=0o700)
            swapped = True
        return original(root_descriptor, directory_descriptors, manifest, **kwargs)

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
        match=(
            r"root changed|directories must remain|unmanifested root|"
            r"opening control-directory descriptor changed"
        ),
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
