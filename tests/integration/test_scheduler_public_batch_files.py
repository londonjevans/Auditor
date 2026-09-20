"""Original synthetic file custody survives call-local public inventory reuse."""

from __future__ import annotations

from pathlib import Path

from mmaudit.models.scheduler import SchedulerTruncationRecoveryModelRequestEvidence
from mmaudit.orchestration.scheduler import resume_scheduler_journal
from tests.unit.test_generic_truncation_tree import _build_tree
from tests.unit.test_scheduler_journal import (
    _bindings,
    _inventory,
    _journal_private_file_snapshot,
)
from tests.unit.test_scheduler_public_batch import _standalone_arguments
from tests.unit.test_scheduler_reconstruction import reconstruction_calls


def test_original_public_inventory_bytes_survive_file_resume_without_redispatch(
    tmp_path: Path,
) -> None:
    path = tmp_path / "synthetic-public-batch-journal"
    journal, refusals = _build_tree(path, source_count=3)
    try:
        assert refusals == ()
        strict = tuple(
            SchedulerTruncationRecoveryModelRequestEvidence.build(**arguments)
            for arguments in _standalone_arguments(journal)
        )
        expected = tuple(sorted(strict, key=lambda item: item.logical_request_id))
        entries = journal.truncation_recovery_entries
        evidence = journal.journal_evidence
        analysis_inputs = journal.analysis_input_inventory
        files = _journal_private_file_snapshot(path)
        with reconstruction_calls() as calls:
            actual = journal.recovery_model_requests
        assert calls["validate_truncation_recovery_entry_chain"] == 1
        assert tuple(item.model_dump_json() for item in actual) == tuple(
            item.model_dump_json() for item in expected
        )
        assert _journal_private_file_snapshot(path) == files
    finally:
        journal.close()
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_analysis_input_inventory=analysis_inputs,
        expected_journal_evidence=evidence,
    )
    try:
        assert resumed.truncation_recovery_entries == entries
        assert resumed.journal_evidence == evidence
        for _ in range(2):
            with reconstruction_calls() as calls:
                actual = resumed.recovery_model_requests
            assert calls["validate_truncation_recovery_entry_chain"] == 1
            assert actual == expected
            assert tuple(item.model_dump_json() for item in actual) == tuple(
                item.model_dump_json() for item in expected
            )
            assert all(not item.review_credit_authorized for item in actual)
            assert all(not item.coverage_credit_authorized for item in actual)
            assert all(not item.release_authorized for item in actual)
        assert resumed.dispatchable_truncation_recovery_child_ids == ()
        assert resumed.uncertain_truncation_recovery_child_ids == ()
        assert _journal_private_file_snapshot(path) == files
    finally:
        resumed.close()
