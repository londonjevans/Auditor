"""Focused runtime-observer tests for bounded truncation-recovery children."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

import pytest

from mmaudit.models.openrouter import (
    DeliveredSourceDescriptor,
    ModelRequestPrivacyBinding,
    OpenRouterSchemaError,
)
from mmaudit.models.scheduler import (
    SchedulerBindings,
    SchedulerPassKind,
    SchedulerPassPlan,
    SchedulerShardDescriptor,
    SchedulerShardInventory,
    SchedulerSourceDescriptor,
    SchedulerTaskPlan,
    SchedulerTaskResult,
    SchedulerTerminalStatus,
)
from mmaudit.models.schemas import (
    ContextPackage,
    ExecutionEvidenceKind,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    ModelSurfaceReviewStatus,
    UsageRecord,
)
from mmaudit.models.truncation import candidate_review_frame_wire_schema_sha256
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildActivation,
    SchedulerTruncationRecoveryChildPreflightResult,
    SchedulerTruncationRecoveryRequestedSurfaceManifest,
    SchedulerTruncationRecoveryTerminalStatus,
)
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.scheduler_runtime import (
    PipelineScheduler,
    scheduler_response_normalizer_sha256,
)
from tests.scheduler_support import (
    build_scheduler_test_model_payload,
    build_scheduler_test_real_usage,
)
from tests.unit.test_scheduler_journal import (
    _bindings,
    _plan,
    _privacy_custody,
    create_scheduler_journal,
    resume_scheduler_journal,
)
from tests.unit.test_truncation_closure import (
    _context,
    _requests,
    _truncated_projection,
)
from tests.unit.test_truncation_recovery_journal import (
    _complete_recovery_orientation,
    _root_plan,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class _RuntimeFixture:
    runtime: PipelineScheduler
    bindings: SchedulerBindings
    shard_inventory: SchedulerShardInventory
    privacy_binding: ModelRequestPrivacyBinding | None
    parent_context: ContextPackage
    family_id: str
    child_task_ids: tuple[str, ...]


class _ReadyValues(TypedDict):
    logical_request_id: str
    role: str
    requested_model: str
    prompt_sha256: str
    system_prompt_sha256: str
    user_prompt_sha256: str
    schema_sha256: str
    delivered_sources: tuple[DeliveredSourceDescriptor, ...]
    privacy_binding: ModelRequestPrivacyBinding


def _runtime_fixture(path: Path) -> _RuntimeFixture:
    requests = _requests()
    base_parent_context = _context(requests)
    provisional_parent_context = base_parent_context.model_copy(update={"role": "source_audit"})
    parent_context = provisional_parent_context.model_copy(
        update={"bytes_used": len(render_context(provisional_parent_context).encode("utf-8"))}
    )
    projection, _response_sha256 = _truncated_projection(
        requests,
        record_status=ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
    )
    sources = tuple(
        SchedulerSourceDescriptor.build(
            path=item.path,
            sha256=item.sha256,
            size=item.size,
        )
        for item in parent_context.repository_map.files
    )
    shard_inventory = SchedulerShardInventory.build(
        semantic_inventory_sha256=_digest("runtime-recovery-semantic-inventory"),
        shards=(
            SchedulerShardDescriptor.semantic(
                shard_id="shard-" + "1" * 24,
                semantic_shard_sha256=_digest("runtime-recovery-shard"),
                sources=sources,
            ),
        ),
    )
    custody = _privacy_custody(source_sha256=shard_inventory.source_tree_sha256)
    base_bindings = _bindings()
    bindings = SchedulerBindings.build(
        source_sha256=shard_inventory.source_tree_sha256,
        analysis_input_sha256=base_bindings.analysis_input_sha256,
        effective_config_sha256=base_bindings.effective_config_sha256,
        shard_inventory_sha256=shard_inventory.inventory_sha256,
        model_selection_sha256=base_bindings.model_selection_sha256,
        qualification_sha256=base_bindings.qualification_sha256,
        prompt_set_sha256=base_bindings.prompt_set_sha256,
        schema_set_sha256=base_bindings.schema_set_sha256,
        tool_policy_sha256=base_bindings.tool_policy_sha256,
        privacy_evidence_custody_sha256=custody.custody_sha256,
    )
    journal = create_scheduler_journal(
        path,
        bindings=bindings,
        shard_inventory=shard_inventory,
        privacy_evidence_custody=custody,
    )
    _complete_recovery_orientation(journal)
    base_plan = _plan(journal, SchedulerPassKind.BLIND_SHARD_REVIEW)
    base_task = base_plan.tasks[0]
    wire_schema_sha256 = candidate_review_frame_wire_schema_sha256()
    task = SchedulerTaskPlan.build(
        manifest=journal.manifest,
        pass_kind=base_task.pass_kind,
        scope=base_task.scope,
        task_kind=base_task.task_kind,
        task_key=base_task.task_key,
        role=base_task.role,
        requested_model=base_task.requested_model,
        root_lineage=base_task.root_lineage,
        candidate_ids=base_task.candidate_ids,
        input_sha256=base_task.input_sha256,
        prompt_sha256=base_task.prompt_sha256,
        system_prompt_sha256=base_task.system_prompt_sha256,
        normalizer_sha256=scheduler_response_normalizer_sha256(wire_schema_sha256),
        response_schema_sha256=wire_schema_sha256,
    )
    plan = journal.seal_pass_plan(
        SchedulerPassPlan.build(
            manifest=journal.manifest,
            pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
            dependencies=journal.next_dependencies,
            tasks=(task,),
        )
    )
    task = plan.tasks[0]
    parent_user_prompt_sha256 = hashlib.sha256(
        render_context(parent_context).encode("utf-8")
    ).hexdigest()
    activation = journal.activate_task(
        task.task_id,
        actual_input_sha256=parent_user_prompt_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256=parent_user_prompt_sha256,
        provider_prompt_sha256=_digest("runtime-recovery-parent-provider-prompt"),
        response_schema_sha256=wire_schema_sha256,
        delivered_source_descriptor_sha256s=tuple(
            source.source_descriptor_sha256 for source in sources
        ),
    )
    journal.mark_dispatched(task.task_id)
    usage = build_scheduler_test_real_usage(
        task,
        activation,
        validated_output=build_scheduler_test_model_payload(plan, task),
        privacy_evidence_custody=custody,
    )
    truncated_usage = UsageRecord.model_validate(
        {
            **usage.model_dump(mode="python"),
            "response_sha256": projection.original_response_sha256,
            "validated_response_sha256": None,
            "finish_reason": "max_tokens",
            "validation_status": ModelRequestValidationStatus.TRUNCATED,
            "identity_strength": ModelIdentityStrength.UNBOUND,
            "execution_evidence": ExecutionEvidenceKind.MOCK,
            "status": "rejected_truncated_response",
            "routing": {
                **usage.routing,
                "finish_reason": "max_tokens",
                "validation_status": "truncated",
            },
        }
    )
    journal.persist_provider_attempt(task.task_id, truncated_usage)
    journal.record_terminal(
        SchedulerTaskResult.build(
            plan=plan,
            task=task,
            activation=activation,
            terminal_status=SchedulerTerminalStatus.TRUNCATED,
            terminal_evidence_sha256=projection.evidence_sha256,
        )
    )
    surface_manifest = SchedulerTruncationRecoveryRequestedSurfaceManifest.build(requests)
    recovery_plan = _root_plan(
        journal,
        projection=projection,
        surface_manifest=surface_manifest,
    )
    family = journal.open_truncation_recovery_family(
        recovery_plan=recovery_plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    privacy_binding = ModelRequestPrivacyBinding(
        source_sha256=custody.source_sha256,
        effective_policy_sha256=custody.effective_policy_evidence_sha256,
        source_provenance_sha256=custody.source_provenance_evidence_sha256,
    )
    return _RuntimeFixture(
        runtime=PipelineScheduler(journal),
        bindings=bindings,
        shard_inventory=shard_inventory,
        privacy_binding=privacy_binding,
        parent_context=parent_context,
        family_id=family.family_id,
        child_task_ids=tuple(child.child_task_id for child in recovery_plan.children),
    )


def _ready_values(fixture: _RuntimeFixture, child_task_id: str) -> _ReadyValues:
    prepared = fixture.runtime.prepare_truncation_recovery_child(
        child_task_id,
        parent_context=fixture.parent_context,
    )
    return {
        "logical_request_id": prepared.logical_request_id,
        "role": prepared.role,
        "requested_model": prepared.requested_model,
        "prompt_sha256": _digest(f"provider-prompt:{child_task_id}"),
        "system_prompt_sha256": prepared.system_prompt_sha256,
        "user_prompt_sha256": prepared.user_prompt_sha256,
        "schema_sha256": prepared.response_schema_sha256,
        "delivered_sources": prepared.delivered_sources,
        "privacy_binding": fixture.privacy_binding,
    }


def test_recovery_request_drift_is_no_call_and_preflight_terminal_is_zero_cost(
    tmp_path: Path,
) -> None:
    fixture = _runtime_fixture(tmp_path / "preflight")
    child_task_id = fixture.child_task_ids[0]
    provisional_parent = fixture.parent_context.model_copy(
        update={"requested_model_surfaces": (fixture.parent_context.requested_model_surfaces[:-1])}
    )
    drifted_parent = provisional_parent.model_copy(
        update={"bytes_used": len(render_context(provisional_parent).encode("utf-8"))}
    )
    with pytest.raises(OpenRouterSchemaError, match="surface manifest"):
        fixture.runtime.prepare_truncation_recovery_child(
            child_task_id,
            parent_context=drifted_parent,
        )
    values = _ready_values(fixture, child_task_id)
    drifted_user = values.copy()
    drifted_user["user_prompt_sha256"] = _digest("drifted-child-context")
    drifted_sources = values.copy()
    drifted_sources["delivered_sources"] = ()
    drifted_privacy = values.copy()
    drifted_privacy["privacy_binding"] = None
    for drifted_values in (drifted_user, drifted_sources, drifted_privacy):
        with pytest.raises(OpenRouterSchemaError):
            fixture.runtime.request_ready(**drifted_values)
    assert not any(
        isinstance(entry, SchedulerTruncationRecoveryChildActivation)
        for entry in fixture.runtime.journal.truncation_recovery_entries
    )

    fixture.runtime.request_ready(**values)
    result = fixture.runtime.record_truncation_recovery_child_preflight_result(
        logical_request_id=values["logical_request_id"],
        terminal_status=SchedulerTruncationRecoveryTerminalStatus.INVALID,
        terminal_evidence_sha256=_digest("local-preflight-drift"),
    )
    assert isinstance(result, SchedulerTruncationRecoveryChildPreflightResult)
    assert result.accounted_provider_attempts == 0
    assert result.accounted_completion_tokens == 0
    assert result.accounted_cost_usd_exact == "0"
    assert not any(
        entry.entry_kind.value == "CHILD_DISPATCHED"
        for entry in fixture.runtime.journal.truncation_recovery_entries
    )
    fixture.runtime.close()


def test_recovery_request_uses_exact_parent_root_scope_and_child_count(tmp_path: Path) -> None:
    fixture = _runtime_fixture(tmp_path / "shared-root")
    child_task_id = fixture.child_task_ids[0]
    values = _ready_values(fixture, child_task_id)
    prepared = fixture.runtime.prepared_truncation_recovery_request(
        logical_request_id=values["logical_request_id"],
    )
    family = fixture.runtime.journal.truncation_recovery_families[0]
    assert prepared.request_limit_scope == family.request_limit_id
    assert prepared.request_limit_scope == family.recovery_plan.parent.parent_logical_request_id
    assert prepared.request_limit_count_before == family.request_limit_count_before_family

    scope = fixture.runtime.request_ready(**values)
    assert scope is not None
    assert scope.identifier == prepared.request_limit_scope
    activation = next(
        entry
        for entry in fixture.runtime.journal.truncation_recovery_entries
        if isinstance(entry, SchedulerTruncationRecoveryChildActivation)
    )
    assert activation.request_limit_count_before_child == prepared.request_limit_count_before
    assert activation.request_limit_count_after_child == prepared.request_limit_count_before + 1
    with pytest.raises(OpenRouterSchemaError, match="one truncation-recovery child"):
        fixture.runtime.prepare_truncation_recovery_child(
            fixture.child_task_ids[1],
            parent_context=fixture.parent_context,
        )
    fixture.runtime.request_dispatched(logical_request_id=prepared.logical_request_id)
    with pytest.raises(ValueError, match="only one activated recovery child"):
        fixture.runtime.request_dispatched(logical_request_id=prepared.logical_request_id)
    fixture.runtime.close()


def test_resumed_prepared_child_is_serializable_and_not_activated_twice(tmp_path: Path) -> None:
    path = tmp_path / "resume"
    fixture = _runtime_fixture(path)
    child_task_id = fixture.child_task_ids[0]
    values = _ready_values(fixture, child_task_id)
    fixture.runtime.request_ready(**values)
    activation = next(
        entry
        for entry in fixture.runtime.journal.truncation_recovery_entries
        if isinstance(entry, SchedulerTruncationRecoveryChildActivation)
    )
    assert (
        SchedulerTruncationRecoveryChildActivation.model_validate_json(
            activation.model_dump_json(),
            strict=True,
        )
        == activation
    )
    evidence = fixture.runtime.journal.journal_evidence
    entry_count = len(fixture.runtime.journal.truncation_recovery_entries)
    fixture.runtime.close()

    resumed_journal = resume_scheduler_journal(
        path,
        expected_bindings=fixture.bindings,
        expected_shard_inventory=fixture.shard_inventory,
        expected_journal_evidence=evidence,
    )
    resumed = PipelineScheduler(resumed_journal)
    prepared = resumed.prepare_truncation_recovery_child(
        child_task_id,
        parent_context=fixture.parent_context,
    )
    resumed.request_ready(**values)
    assert len(resumed.journal.truncation_recovery_entries) == entry_count
    assert (
        prepared.request_limit_scope
        == resumed.journal.truncation_recovery_families[0].request_limit_id
    )
    resumed.close()
