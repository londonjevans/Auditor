"""Synthetic original-live tree verification; no provider or audit credit is exercised."""

from __future__ import annotations

import copy
import hashlib
import json
import pickle
from collections.abc import Iterator
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from mmaudit.models.scheduler import (
    SchedulerPassKind,
    SchedulerPassStatus,
    SchedulerScope,
    SchedulerTaskResult,
    SchedulerTerminalStatus,
    scheduler_role_requires_specialist_accepted_outcome,
)
from mmaudit.models.schemas import (
    CandidateReviewBatch,
    ContextPackage,
    ExecutionEvidenceKind,
    UsageRecord,
)
from mmaudit.models.truncation import candidate_review_frame_wire_schema_sha256
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryFamilyPromotion,
    SchedulerTruncationRecoveryFamilyRoot,
    SchedulerTruncationRecoveryRequestedSurfaceManifest,
    SchedulerTruncationRecoveryTerminalStatus,
)
from mmaudit.models.truncation_tree import TruncationRecoveredTreeArtifact
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.scheduler import SchedulerJournal
from mmaudit.orchestration.scheduler_runtime import PipelineScheduler
from mmaudit.orchestration.truncation_recovery_evidence import (
    build_truncation_recovery_child_context,
)
from mmaudit.orchestration.truncation_tree_evidence import (
    VerifiedTruncationRecoveryFullTree,
    require_verified_truncation_recovery_full_tree,
    verify_truncation_recovery_full_tree,
)
from tests.scheduler_support import (
    build_scheduler_test_model_payload,
    build_scheduler_test_real_usage,
    scheduler_test_delivered_source_descriptor_sha256s,
)
from tests.unit.test_generic_truncation_tree import _nested_plan
from tests.unit.test_scheduler_journal import (
    SHARDS,
    _inventory,
    _plan,
    _privacy_custody,
    create_scheduler_journal,
)
from tests.unit.test_scheduler_truncation_promotion_integration import (
    _bind_bridge_to_parent_invariant,
    _bind_child_to_parent_invariant,
    _one_shard_bindings,
    _recovery_plan,
    _typed_parent_truncation,
)
from tests.unit.test_truncation_closure import _context, _record, _requests
from tests.unit.test_truncation_recovery_journal import (
    _projection,
    _specialist_success_outcome,
    _success_custody,
    _truncated_custody,
)


@dataclass(frozen=True)
class LiveTreeFixture:
    journal: SchedulerJournal
    root_family_id: str
    parent_usage: UsageRecord
    usages: tuple[UsageRecord, ...]
    parent_context: ContextPackage
    contexts: tuple[ContextPackage, ...]

    def arguments(self) -> dict[str, Any]:
        return {
            "journal": self.journal,
            "root_family_id": self.root_family_id,
            "parent_usage_record": self.parent_usage,
            "child_usage_records": self.usages,
            "parent_context": self.parent_context,
            "child_contexts": self.contexts,
        }


def _complete_costed_orientation(journal: SchedulerJournal) -> None:
    """Retain a nonzero unrelated main-request liability in the original journal."""

    plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
    task = plan.tasks[0]
    activation = journal.activate_task(
        task.task_id,
        actual_input_sha256=task.input_sha256,
        system_prompt_sha256=task.system_prompt_sha256,
        user_prompt_sha256="3" * 64,
        provider_prompt_sha256="4" * 64,
        response_schema_sha256=task.response_schema_sha256,
        delivered_source_descriptor_sha256s=scheduler_test_delivered_source_descriptor_sha256s(
            plan, task
        ),
    )
    journal.mark_dispatched(task.task_id)
    payload = build_scheduler_test_model_payload(plan, task)
    usage = build_scheduler_test_real_usage(
        task,
        activation,
        seed="full-tree-prior-cost",
        validated_output=payload,
        cost_usd_exact="0.01",
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
    assert (
        journal.seal_pass_result(SchedulerPassKind.ORIENTATION).status
        is SchedulerPassStatus.COMPLETE
    )


def build_live_tree(
    path: Path,
    *,
    source_count: int = 17,
    truncated_paths: frozenset[str] = frozenset({"0", "00", "000"}),
    retained_count: int = 0,
    request_role: str = "source_audit",
) -> LiveTreeFixture:
    """Exercise original journal/usage owners with inert, locally generated source evidence."""

    inventory = _inventory(one_shard=True)
    journal = create_scheduler_journal(
        path,
        bindings=_one_shard_bindings(),
        shard_inventory=inventory,
        privacy_evidence_custody=_privacy_custody(source_sha256=inventory.source_tree_sha256),
    )
    try:
        _complete_costed_orientation(journal)
        requests = _requests(source_count)
        records = tuple(_record(r, review_role=request_role) for r in requests)
        context = _context(requests, source_count=source_count, role=request_role)
        projection = _projection(records, retained_count=1)
        manifest = SchedulerTruncationRecoveryRequestedSurfaceManifest.build(requests)
        planner = PipelineScheduler(journal)
        selection = journal.manifest.bindings.audit_model_selection
        assert selection is not None
        model = selection.selected_model_ids[0]
        task = planner.model_task(
            pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
            scope=SchedulerScope.single_shard(SHARDS[0]),
            task_key="full-tree-local-verification",
            role=request_role,
            requested_model=model,
            root_lineage=selection.route_for(model).root_lineage,
            system_prompt_sha256="a" * 64,
            response_schema_sha256=candidate_review_frame_wire_schema_sha256(),
            model_surface_review_request_manifest_sha256=manifest.requested_surface_manifest_sha256,
        )
        tasks = (task,)
        if request_role != "source_audit":
            # Preserve the mandatory base audit without claiming it was executed.
            source_task = planner.model_task(
                pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
                scope=SchedulerScope.single_shard(SHARDS[0]),
                task_key="full-tree-base-source-audit",
                role="source_audit",
                requested_model=model,
                root_lineage=selection.route_for(model).root_lineage,
                system_prompt_sha256="a" * 64,
                response_schema_sha256=candidate_review_frame_wire_schema_sha256(),
                model_surface_review_request_manifest_sha256=(
                    manifest.requested_surface_manifest_sha256
                ),
            )
            tasks = (*tasks, source_task)
        plan = planner.prepare_pass(SchedulerPassKind.BLIND_SHARD_REVIEW, tasks)
        context_sha256 = hashlib.sha256(render_context(context).encode()).hexdigest()
        activation = journal.activate_task(
            task.task_id,
            actual_input_sha256=context_sha256,
            system_prompt_sha256=task.system_prompt_sha256,
            user_prompt_sha256=context_sha256,
            provider_prompt_sha256="2" * 64,
            response_schema_sha256=task.response_schema_sha256,
            delivered_source_descriptor_sha256s=scheduler_test_delivered_source_descriptor_sha256s(
                plan, task
            ),
        )
        journal.mark_dispatched(task.task_id)
        envelope, parent_usage = _typed_parent_truncation(
            journal=journal,
            task=task,
            activation=activation,
            context=context,
            projection=projection,
            full_batch=CandidateReviewBatch(findings=(), surface_reviews=records),
        )
        attempt = journal.persist_truncated_provider_attempt(
            task.task_id,
            parent_usage,
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
        recovery_plan = _recovery_plan(
            journal=journal,
            pass_plan=plan,
            task=task,
            activation=activation,
            attempt=attempt,
            projection=projection,
            manifest=manifest,
            parent_usage=parent_usage,
        )
        root = journal.open_truncation_recovery_family(
            recovery_plan=recovery_plan,
            truncation_projection=projection,
            requested_surface_manifest=manifest,
        )
        ordered_usages: list[UsageRecord] = []
        ordered_contexts: list[ContextPackage] = []

        def finish(
            family: SchedulerTruncationRecoveryFamilyRoot, parent_context: ContextPackage
        ) -> None:
            results: dict[str, SchedulerTruncationRecoveryChildResult] = {}
            contexts: dict[str, ContextPackage] = {}
            for child in family.recovery_plan.children:
                child_context = build_truncation_recovery_child_context(
                    parent_context=parent_context, child=child
                )
                contexts[child.child_task_id] = child_context
                child_sha256 = hashlib.sha256(render_context(child_context).encode()).hexdigest()
                child_activation = journal.activate_truncation_recovery_child(
                    child.child_task_id,
                    actual_input_sha256=child_sha256,
                    system_prompt_sha256=task.system_prompt_sha256,
                    user_prompt_sha256=child_sha256,
                    provider_prompt_sha256=hashlib.sha256(child.child_task_id.encode()).hexdigest(),
                    response_schema_sha256=task.response_schema_sha256,
                )
                journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
                if child.path in truncated_paths:
                    assert len(child.surface_ids) >= retained_count + 2
                    usage, child_envelope, child_projection = _truncated_custody(
                        child=child,
                        activation=child_activation,
                        surfaces=records,
                        retained_count=retained_count,
                    )
                    usage = _bind_bridge_to_parent_invariant(
                        usage.model_copy(update={"execution_evidence": ExecutionEvidenceKind.REAL}),
                        journal=journal,
                        parent_usage=parent_usage,
                    )
                    result = journal.record_truncation_recovery_child_truncated(
                        child.child_task_id,
                        failed_usage_record=usage,
                        truncated_envelope_evidence=child_envelope,
                        truncation_projection=child_projection,
                    )
                else:
                    usage, normalization, batch, child_requests, artifact = _success_custody(
                        child=child,
                        activation=child_activation,
                        surface_manifest=manifest,
                        surfaces=records,
                        execution_evidence=ExecutionEvidenceKind.REAL,
                    )
                    usage = _bind_child_to_parent_invariant(
                        usage, journal=journal, parent_usage=parent_usage
                    )
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
                            if scheduler_role_requires_specialist_accepted_outcome(request_role)
                            else None
                        ),
                    )
                results[child.child_task_id] = result
                ordered_usages.append(usage)
                ordered_contexts.append(child_context)
            for child in family.recovery_plan.children:
                result = results[child.child_task_id]
                if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED:
                    assert result.truncation_projection is not None
                    nested = journal.open_truncation_recovery_family(
                        recovery_plan=_nested_plan(journal, family, child, result),
                        truncation_projection=result.truncation_projection,
                        requested_surface_manifest=manifest,
                    )
                    finish(nested, contexts[child.child_task_id])
            journal.seal_truncation_recovery_family(family.family_id)

        finish(root, context)
        return LiveTreeFixture(
            journal,
            root.family_id,
            parent_usage,
            tuple(ordered_usages),
            context,
            tuple(ordered_contexts),
        )
    except BaseException:
        journal.close()
        raise


@pytest.fixture(scope="module")
def live_tree(tmp_path_factory: pytest.TempPathFactory) -> Iterator[LiveTreeFixture]:
    fixture = build_live_tree(tmp_path_factory.mktemp("full-live-tree") / "journal")
    try:
        yield fixture
    finally:
        fixture.journal.close()


@pytest.fixture(scope="module")
def verified_tree(
    live_tree: LiveTreeFixture,
) -> tuple[VerifiedTruncationRecoveryFullTree, TruncationRecoveredTreeArtifact]:
    return verify_truncation_recovery_full_tree(**live_tree.arguments())


def test_depth_four_verifies_every_original_branch_without_promotion(
    live_tree: LiveTreeFixture, verified_tree: tuple[Any, Any]
) -> None:
    token, artifact = verified_tree
    projection = require_verified_truncation_recovery_full_tree(token)
    assert projection.journal is live_tree.journal
    assert projection.parent_usage_record is live_tree.parent_usage
    assert all(
        a is b for a, b in zip(projection.child_usage_records, live_tree.usages, strict=True)
    )
    assert artifact == projection.artifact
    assert len(artifact.bridges) == 3 and len(artifact.leaves) == 5
    assert max(c.child_plan.depth for c in artifact.leaves) == 4
    assert tuple(b.schema_version for b in artifact.bridges) == ("1.0", "1.2", "1.2")
    assert len(artifact.records) == 17
    assert artifact.accounting.provider_request_count == 9
    assert artifact.accounting.tree_accounted_cost_usd_exact == "0.44"
    assert Decimal(artifact.accounting.other_accounted_cost_usd_exact) > 0
    assert artifact.accounting.parent_cost_refunded is False
    assert artifact.surface_review_credit_eligible is False
    assert artifact.candidate_credit_eligible is False
    assert artifact.scheduler_custody_verified is False
    assert not any(
        isinstance(e, SchedulerTruncationRecoveryFamilyPromotion)
        for e in live_tree.journal.truncation_recovery_entries
    )
    with pytest.raises(ValueError):
        live_tree.journal.promote_truncation_recovery_family(live_tree.root_family_id, token)


@pytest.mark.parametrize("which", ["parent", "bridge", "leaf"])
def test_decoded_usage_cannot_replace_original_live_custody(
    live_tree: LiveTreeFixture, which: str
) -> None:
    arguments = live_tree.arguments()
    if which == "parent":
        arguments["parent_usage_record"] = UsageRecord.model_validate_json(
            live_tree.parent_usage.model_dump_json()
        )
    else:
        usages = list(live_tree.usages)
        index = 0 if which == "bridge" else 1
        usages[index] = UsageRecord.model_validate_json(usages[index].model_dump_json())
        arguments["child_usage_records"] = usages
    with pytest.raises(ValueError, match=r"live.*custody"):
        verify_truncation_recovery_full_tree(**arguments)


@pytest.mark.parametrize(
    "which", ["usage_order", "context_order", "missing_leaf", "duplicate_leaf", "foreign_owner"]
)
def test_original_tree_inventory_cannot_be_substituted(
    live_tree: LiveTreeFixture, which: str
) -> None:
    arguments = live_tree.arguments()
    if which == "usage_order":
        arguments["child_usage_records"] = tuple(reversed(live_tree.usages))
    elif which == "context_order":
        arguments["child_contexts"] = tuple(reversed(live_tree.contexts))
    elif which == "missing_leaf":
        arguments["child_usage_records"] = live_tree.usages[:-1]
    elif which == "duplicate_leaf":
        arguments["child_usage_records"] = (*live_tree.usages[:-1], live_tree.usages[1])
    else:
        forged = object.__new__(SchedulerJournal)
        forged.__dict__.update(live_tree.journal.__dict__)
        arguments["journal"] = forged
    with pytest.raises(ValueError):
        verify_truncation_recovery_full_tree(**arguments)


@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_token_cannot_be_copied_or_serialized(
    verified_tree: tuple[Any, Any], operation: Any
) -> None:
    with pytest.raises(TypeError, match="cannot be"):
        operation(verified_tree[0])


def test_constructed_token_and_decoded_artifact_are_not_authority(
    verified_tree: tuple[Any, Any],
) -> None:
    with pytest.raises(TypeError, match="constructed"):
        VerifiedTruncationRecoveryFullTree()
    decoded = TruncationRecoveredTreeArtifact.model_validate_json(
        verified_tree[1].model_dump_json(), strict=True
    )
    assert decoded == verified_tree[1]
    for forged in (object.__new__(VerifiedTruncationRecoveryFullTree), decoded):
        with pytest.raises(ValueError, match="absent or forged"):
            require_verified_truncation_recovery_full_tree(forged)


@pytest.mark.parametrize(
    "field", ["main_usage_records", "origins", "bridges", "recovery_prefix", "leaves"]
)
def test_serialized_tree_cannot_omit_prefix_or_origins(
    verified_tree: tuple[Any, Any], field: str
) -> None:
    raw = json.loads(verified_tree[1].model_dump_json())
    raw[field] = raw[field][1:]
    with pytest.raises(ValueError):
        TruncationRecoveredTreeArtifact.model_validate_json(json.dumps(raw), strict=True)


def test_returned_mutable_comparison_alias_does_not_change_private_capture(
    verified_tree: tuple[Any, Any],
) -> None:
    token, _ = verified_tree
    projection = require_verified_truncation_recovery_full_tree(token)
    projection.artifact.parent.usage_record.routing["synthetic_comparison_mutation"] = True
    fresh = require_verified_truncation_recovery_full_tree(token)
    assert "synthetic_comparison_mutation" not in fresh.artifact.parent.usage_record.routing
    assert "synthetic_comparison_mutation" not in fresh.parent_usage_record.routing


def test_two_truncated_branches_preserve_each_retained_record(tmp_path: Path) -> None:
    fixture = build_live_tree(
        tmp_path / "retained-branches",
        source_count=10,
        truncated_paths=frozenset({"0", "1"}),
        retained_count=1,
    )
    try:
        token, artifact = verify_truncation_recovery_full_tree(**fixture.arguments())
        assert require_verified_truncation_recovery_full_tree(token).artifact == artifact
        assert len(artifact.bridges) == 2 and len(artifact.leaves) == 4
        assert all(len(b.retained_surface_ids) == 1 for b in artifact.bridges)
        assert len(artifact.records) == 10
        assert len({o.surface_id for o in artifact.origins}) == 10
        for bridge in artifact.bridges:
            origins = tuple(
                o for o in artifact.origins if o.request_id == bridge.usage_record.request_id
            )
            assert tuple(o.surface_id for o in origins) == bridge.retained_surface_ids
        assert not any(
            isinstance(e, SchedulerTruncationRecoveryFamilyPromotion)
            for e in fixture.journal.truncation_recovery_entries
        )
    finally:
        fixture.journal.close()
