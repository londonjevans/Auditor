"""Original-file channel retention never turns incomplete findings into audit credit."""

from __future__ import annotations

from decimal import Decimal
from functools import partial
from pathlib import Path

import pytest

from mmaudit.models.truncation import CandidateReviewChannelState
from mmaudit.models.truncation_recovery import (
    TruncationRecoveryChannel,
    TruncationRecoveryDisposition,
)
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryClosureStatus,
    SchedulerTruncationRecoveryEntryKind,
)
from mmaudit.orchestration.scheduler import SchedulerJournal
from mmaudit.reporting.json_report import stable_json
from tests.channel_retention_support import VALID_FINDING_IDS, channel_projection
from tests.unit import test_truncation_recovery_journal as support
from tests.unit.test_scheduler_journal import (
    _bindings,
    _inventory,
    _journal_private_file_snapshot,
    resume_scheduler_journal,
)


def _assert_no_recovery_credit(journal: SchedulerJournal, parent_task_id: str) -> None:
    assert journal.recovered_candidate_review_output_for_task(parent_task_id) is None
    assert all(
        entry.entry_kind is not SchedulerTruncationRecoveryEntryKind.FAMILY_PROMOTED
        for entry in journal.truncation_recovery_entries
    )
    for request in journal.recovery_model_requests:
        assert request.promotion_entry_sha256 is None
        assert not request.review_credit_authorized
        assert not request.coverage_credit_authorized


def _assert_original_resume_preserves_channels(journal: SchedulerJournal, path: Path) -> None:
    evidence = journal.journal_evidence
    entries = tuple(
        stable_json(entry.model_dump(mode="json")) for entry in journal.truncation_recovery_entries
    )
    usage = tuple(
        stable_json(record.model_dump(mode="json"))
        for record in journal.retained_provider_usage_records
    )
    public = tuple(
        stable_json(request.model_dump(mode="json")) for request in journal.recovery_model_requests
    )
    snapshot = _journal_private_file_snapshot(path)
    journal.close()
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=evidence,
    )
    try:
        assert (
            tuple(
                stable_json(entry.model_dump(mode="json"))
                for entry in resumed.truncation_recovery_entries
            )
            == entries
        )
        assert (
            tuple(
                stable_json(record.model_dump(mode="json"))
                for record in resumed.retained_provider_usage_records
            )
            == usage
        )
        assert (
            tuple(
                stable_json(request.model_dump(mode="json"))
                for request in resumed.recovery_model_requests
            )
            == public
        )
        assert not resumed.dispatchable_truncation_recovery_child_ids
        assert _journal_private_file_snapshot(path) == snapshot
    finally:
        resumed.close()
    assert _journal_private_file_snapshot(path) == snapshot


@pytest.mark.parametrize(
    "state", [CandidateReviewChannelState.OPEN, CandidateReviewChannelState.INVALID]
)
def test_original_root_retains_valid_findings_after_independent_coverage_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: CandidateReviewChannelState,
) -> None:
    path = tmp_path / "root-channel-retention"
    with monkeypatch.context() as patch:
        patch.setattr(support, "_projection", partial(channel_projection, state=state))
        journal, plan, projection, records, manifest = support._journal_with_truncated_parent(
            path, typed_parent_attempt=True, source_count=7, parent_cost_usd_exact="0.02"
        )
    try:
        assert plan.disposition is TruncationRecoveryDisposition.PLANNED
        assert plan.irreducible_channels == (TruncationRecoveryChannel.FINDINGS,)
        assert plan.non_authorizing_incomplete_channels == (TruncationRecoveryChannel.SUMMARY,)
        root = journal.open_truncation_recovery_family(
            recovery_plan=plan,
            truncation_projection=projection,
            requested_surface_manifest=manifest,
        )
        before = root.model_dump_json()
        results: list[SchedulerTruncationRecoveryChildResult] = []
        for child in plan.children:
            activation = support._activate_child(journal, child.child_task_id)
            journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
            usage, normalization, batch, requests, artifact = support._success_custody(
                child=child, activation=activation, surface_manifest=manifest, surfaces=records
            )
            results.append(
                journal.record_truncation_recovery_child_success(
                    child.child_task_id,
                    usage_record=usage,
                    normalization_evidence=normalization,
                    normalized_batch=batch,
                    requested_surface_requests=requests,
                    output_artifact=artifact,
                )
            )
        closure = journal.seal_truncation_recovery_family(root.family_id)
        assert closure.closure_status is SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
        assert closure.covered_unfinished_surface_ids == plan.parent.unfinished_surface_ids
        assert set(closure.covered_unfinished_surface_ids).isdisjoint(
            plan.parent.retained_surface_ids
        )
        assert set(closure.covered_unfinished_surface_ids) | set(
            plan.parent.retained_surface_ids
        ) == set(manifest.requested_surface_ids)
        assert journal.truncation_recovery_families[0].model_dump_json() == before
        assert (
            tuple(item.candidate_id for item in root.truncation_projection.findings)
            == VALID_FINDING_IDS
        )
        assert root.truncation_projection.findings_state is state
        assert Decimal(plan.resources.parent_accounted_cost_usd_exact) == Decimal("0.02")
        assert sum(
            (Decimal(result.accounted_cost_usd_exact) for result in results), Decimal(0)
        ) == Decimal("0.10")
        assert not closure.completion_authorized
        assert not closure.review_credit_authorized
        _assert_no_recovery_credit(journal, plan.parent.parent_task_id)
        _assert_original_resume_preserves_channels(journal, path)
    finally:
        journal.close()


@pytest.mark.parametrize(
    "state", [CandidateReviewChannelState.OPEN, CandidateReviewChannelState.INVALID]
)
def test_original_nested_refusal_preserves_findings_coverage_and_all_failed_costs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: CandidateReviewChannelState,
) -> None:
    path = tmp_path / "nested-channel-retention"
    journal, plan, projection, records, manifest = support._journal_with_truncated_parent(
        path, typed_parent_attempt=True, source_count=7, parent_cost_usd_exact="0.02"
    )
    try:
        root = journal.open_truncation_recovery_family(
            recovery_plan=plan,
            truncation_projection=projection,
            requested_surface_manifest=manifest,
        )
        bridge, leaf = plan.children
        activation = support._activate_child(journal, bridge.child_task_id)
        journal.mark_truncation_recovery_child_dispatched(bridge.child_task_id)
        with monkeypatch.context() as patch:
            patch.setattr(support, "_projection", partial(channel_projection, state=state))
            failed_usage, envelope, failed_projection = support._truncated_custody(
                child=bridge, activation=activation, surfaces=records, retained_count=1
            )
        bridge_result = journal.record_truncation_recovery_child_truncated(
            bridge.child_task_id,
            failed_usage_record=failed_usage,
            truncated_envelope_evidence=envelope,
            truncation_projection=failed_projection,
        )
        leaf_activation = support._activate_child(journal, leaf.child_task_id)
        journal.mark_truncation_recovery_child_dispatched(leaf.child_task_id)
        usage, normalization, batch, requests, artifact = support._success_custody(
            child=leaf, activation=leaf_activation, surface_manifest=manifest, surfaces=records
        )
        leaf_result = journal.record_truncation_recovery_child_success(
            leaf.child_task_id,
            usage_record=usage,
            normalization_evidence=normalization,
            normalized_batch=batch,
            requested_surface_requests=requests,
            output_artifact=artifact,
        )
        nested_plan = support._nested_plan_for_typed_truncated_child(
            root=root,
            root_plan=plan,
            child=bridge,
            activation=activation,
            result=bridge_result,
            projection=failed_projection,
            other_direct_results=(leaf_result,),
        )
        assert nested_plan.disposition is TruncationRecoveryDisposition.PLANNED
        assert nested_plan.irreducible_channels == (TruncationRecoveryChannel.FINDINGS,)
        assert (
            nested_plan.covered_unfinished_surface_ids == nested_plan.parent.unfinished_surface_ids
        )
        before = _journal_private_file_snapshot(path)
        with pytest.raises(
            ValueError, match="nested scheduler recovery root differs from its truncated child"
        ) as refused:
            journal.open_truncation_recovery_family(
                recovery_plan=nested_plan,
                truncation_projection=failed_projection,
                requested_surface_manifest=manifest,
            )
        assert isinstance(refused.value.__cause__, ValueError)
        assert str(refused.value.__cause__) == (
            "scheduler recovery ancestry differs from its truncated parent child"
        )
        assert _journal_private_file_snapshot(path) == before
        assert journal.truncation_recovery_families == (root,)
        assert bridge_result.truncation_projection == failed_projection
        assert tuple(item.candidate_id for item in failed_projection.findings) == VALID_FINDING_IDS
        assert bridge_result.runtime_output_artifact is None
        assert bridge_result.runtime_specialist_accepted_outcome is None
        assert Decimal(bridge_result.accounted_cost_usd_exact) == Decimal("0.05")
        assert Decimal(leaf_result.accounted_cost_usd_exact) == Decimal("0.05")
        closure = journal.seal_truncation_recovery_family(root.family_id)
        assert closure.closure_status is SchedulerTruncationRecoveryClosureStatus.INCOMPLETE
        assert not closure.completion_authorized
        _assert_no_recovery_credit(journal, plan.parent.parent_task_id)
        _assert_original_resume_preserves_channels(journal, path)
    finally:
        journal.close()
