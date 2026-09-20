"""Synthetic file-backed specialist ancestry keeps original custody and never promotes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildActivation,
    SchedulerTruncationRecoveryClosureStatus,
    SchedulerTruncationRecoveryFamilyPromotion,
)
from mmaudit.models.truncation_tree import (
    _generic_truncation_recovery_tree_inventory,
    truncation_recovery_tree_inventory,
)
from mmaudit.orchestration.scheduler import _truncation_recovery_entry_path
from tests.unit.test_scheduler_journal import (
    _bindings,
    _inventory,
    _journal_private_file_snapshot,
    resume_scheduler_journal,
)
from tests.unit.test_specialist_truncation_ancestry import build_specialist_ancestry
from tests.unit.test_truncation_recovery_journal import (
    _activate_child,
    _specialist_success_outcome,
    _success_custody,
)


@pytest.mark.parametrize("retained_count", [0, 1])
def test_nested_specialist_journal_closes_and_replays_without_authority(
    tmp_path: Path, retained_count: int
) -> None:
    path = tmp_path / "synthetic-specialist-journal"
    fixture = build_specialist_ancestry(path, retained_count=retained_count)
    journal = fixture.journal
    try:
        assert len(fixture.bridge.retained_surface_ids) == retained_count
        assert fixture.bridge.completed_surface_ids == ()
        assert fixture.bridge.runtime_specialist_accepted_outcome is None
        for child in fixture.nested.recovery_plan.children:
            activation = _activate_child(journal, child.child_task_id)
            journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
            custody = _success_custody(
                child=child,
                activation=activation,
                surface_manifest=fixture.surface_manifest,
                surfaces=fixture.surfaces,
            )
            args = {
                "usage_record": custody[0],
                "normalization_evidence": custody[1],
                "normalized_batch": custody[2],
                "requested_surface_requests": custody[3],
                "output_artifact": custody[4],
            }
            before = _journal_private_file_snapshot(path)
            # Invariant: no absent or sibling outcome may finish this specialist child.
            for substituted in (None, fixture.sibling.runtime_specialist_accepted_outcome):
                with pytest.raises(ValueError):
                    journal.record_truncation_recovery_child_success(
                        child.child_task_id,
                        **args,  # type: ignore[arg-type]
                        specialist_accepted_outcome=substituted,
                    )
                assert _journal_private_file_snapshot(path) == before
            outcome = _specialist_success_outcome(
                usage=custody[0], requests=custody[3], artifact=custody[4]
            )
            result = journal.record_truncation_recovery_child_success(
                child.child_task_id,
                **args,  # type: ignore[arg-type]
                specialist_accepted_outcome=outcome,
            )
            assert result.schema_version == "1.2"
            assert result.runtime_specialist_accepted_outcome == outcome
            assert result.runtime_specialist_accepted_outcome_sha256 == outcome.evidence_sha256
            assert result.runtime_usage_record is not None
            assert result.runtime_usage_record.execution_evidence is ExecutionEvidenceKind.MOCK
        nested_closure = journal.seal_truncation_recovery_family(fixture.nested.family_id)
        root_closure = journal.seal_truncation_recovery_family(fixture.root.family_id)
        assert (
            nested_closure.closure_status
            is SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
        )
        assert root_closure.closure_status is (
            SchedulerTruncationRecoveryClosureStatus.RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING
        )
        assert root_closure.covered_unfinished_surface_ids == (
            fixture.root.recovery_plan.parent.unfinished_surface_ids
        )
        assert not root_closure.coverage_credit_authorized
        assert not root_closure.completion_authorized
        entries = journal.truncation_recovery_entries
        activations = [
            entry
            for entry in entries
            if isinstance(entry, SchedulerTruncationRecoveryChildActivation)
        ]
        assert [item.request_limit_count_before_child for item in activations] == [1, 2, 3, 4]
        assert {item.request_role for item in activations} == {"specialist:access_control"}
        assert {item.request_limit_id for item in activations} == {fixture.root.request_limit_id}
        assert not any(
            isinstance(item, SchedulerTruncationRecoveryFamilyPromotion) for item in entries
        )
        tree = truncation_recovery_tree_inventory(entries, root_family_id=fixture.root.family_id)
        assert tree.families == (fixture.root, fixture.nested)
        assert len(tree.results) == 4
        assert (
            sum(result.runtime_specialist_accepted_outcome is not None for result in tree.results)
            == 3
        )
        # Structural membership does not enable generic-only verification or promotion.
        with pytest.raises(ValueError, match="generic typed child custody"):
            _generic_truncation_recovery_tree_inventory(
                entries, root_family_id=fixture.root.family_id
            )
        before = _journal_private_file_snapshot(path)
        with pytest.raises(ValueError, match="live closure custody"):
            journal.promote_truncation_recovery_family(
                fixture.root.family_id,
                root_closure,  # type: ignore[arg-type]
            )
        assert _journal_private_file_snapshot(path) == before
        requests = journal.recovery_model_requests
        assert len(requests) == 4
        assert all(not item.review_credit_authorized for item in requests)
        assert all(not item.coverage_credit_authorized for item in requests)
        evidence = journal.journal_evidence
    finally:
        journal.close()
    before = _journal_private_file_snapshot(path)
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=evidence,
    )
    try:
        assert resumed.truncation_recovery_entries == entries
        assert (
            truncation_recovery_tree_inventory(
                resumed.truncation_recovery_entries, root_family_id=fixture.root.family_id
            )
            == tree
        )
        assert resumed.recovery_model_requests == requests
        assert resumed.artifact().recovery_model_requests == requests
        assert not resumed.dispatchable_truncation_recovery_child_ids
        assert _journal_private_file_snapshot(path) == before
    finally:
        resumed.close()


def test_missing_durable_specialist_outcome_refuses_replay_without_repair(tmp_path: Path) -> None:
    path = tmp_path / "synthetic-corrupted-specialist-journal"
    fixture = build_specialist_ancestry(path)
    evidence = fixture.journal.journal_evidence
    target = path / _truncation_recovery_entry_path(fixture.sibling)
    fixture.journal.close()
    value = json.loads(target.read_text())
    value["runtime_specialist_accepted_outcome"] = None
    target.write_text(json.dumps(value) + "\n")
    before = _journal_private_file_snapshot(path)
    with pytest.raises(ValueError):
        resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=evidence,
        )
    assert _journal_private_file_snapshot(path) == before
