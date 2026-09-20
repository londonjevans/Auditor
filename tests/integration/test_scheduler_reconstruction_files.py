"""Original synthetic journals retain exact append, file-race and replay custody."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from mmaudit.orchestration import scheduler as scheduler_module
from mmaudit.orchestration.scheduler import resume_scheduler_journal
from tests.unit.test_scheduler_journal import (
    _bindings,
    _inventory,
    _journal_private_file_snapshot,
)
from tests.unit.test_scheduler_reconstruction import reconstruction_calls
from tests.unit.test_truncation_recovery_journal import (
    _activate_child,
    _journal_with_truncated_parent,
    _success_custody,
)


def test_recovery_append_reuses_one_fresh_load_and_original_files_replay(
    tmp_path: Path,
) -> None:
    path = tmp_path / "synthetic-reconstruction-journal"
    journal, plan, projection, surfaces, manifest = _journal_with_truncated_parent(
        path, typed_parent_attempt=True, source_count=3
    )
    try:
        family = journal.open_truncation_recovery_family(
            recovery_plan=plan,
            truncation_projection=projection,
            requested_surface_manifest=manifest,
        )
        before = _journal_private_file_snapshot(path)
        with reconstruction_calls() as calls:
            first_activation = _activate_child(journal, plan.children[0].child_task_id)
        assert calls["_append_truncation_recovery_entry"] == 1
        assert calls["_load_state"] == 1
        assert calls["_derive_scheduler_journal_indexes"] == 1
        # One prospective validation before writing, one full file-derived replay after.
        assert calls["_derive_truncation_recovery_indexes"] == 2
        after = _journal_private_file_snapshot(path)
        assert all(
            after[name] == value
            for name, value in before.items()
            if name != "journal-head-checkpoint.json"
        )
        assert journal.local_journal_head_checkpoint == journal.journal_evidence
        for index, child in enumerate(plan.children):
            activation = (
                first_activation if index == 0 else _activate_child(journal, child.child_task_id)
            )
            journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
            usage, normalization, batch, requests, artifact = _success_custody(
                child=child, activation=activation, surface_manifest=manifest, surfaces=surfaces
            )
            journal.record_truncation_recovery_child_success(
                child.child_task_id,
                usage_record=usage,
                normalization_evidence=normalization,
                normalized_batch=batch,
                requested_surface_requests=requests,
                output_artifact=artifact,
            )
        journal.seal_truncation_recovery_family(family.family_id)
        evidence = journal.journal_evidence
        entries = journal.truncation_recovery_entries
        requests_before = journal.recovery_model_requests
        assert len(requests_before) == 2
        assert all(not request.review_credit_authorized for request in requests_before)
        files = _journal_private_file_snapshot(path)
        analysis_inputs = journal.analysis_input_inventory
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
        assert resumed.recovery_model_requests == requests_before
        assert resumed.dispatchable_truncation_recovery_child_ids == ()
        assert resumed.uncertain_truncation_recovery_child_ids == ()
        assert _journal_private_file_snapshot(path) == files
    finally:
        resumed.close()


@pytest.mark.parametrize("target_kind", ("event", "recovery"))
@pytest.mark.parametrize("mutation", ("same_inode", "replacement", "restore_bytes_and_mtime"))
def test_post_append_load_detects_durable_race_before_checkpoint_advances(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_kind: str,
    mutation: str,
) -> None:
    path = tmp_path / "synthetic-reconstruction-race"
    journal, plan, projection, _surfaces, manifest = _journal_with_truncated_parent(
        path, typed_parent_attempt=True, source_count=3
    )
    try:
        root = journal.open_truncation_recovery_family(
            recovery_plan=plan,
            truncation_projection=projection,
            requested_surface_manifest=manifest,
        )
        target = path / (
            "events/event-00000000.json"
            if target_kind == "event"
            else scheduler_module._truncation_recovery_entry_path(root)
        )
        original_bytes = target.read_bytes()
        original_stat = target.stat()
        checkpoint = (path / "journal-head-checkpoint.json").read_bytes()
        original_load = scheduler_module._load_state
        raced = False

        def race_after_load(*args: Any, **kwargs: Any) -> Any:
            nonlocal raced
            loaded = original_load(*args, **kwargs)
            assert not raced
            raced = True
            if mutation == "replacement":
                replacement = tmp_path / "synthetic-replacement.json"
                replacement.write_bytes(original_bytes)
                replacement.chmod(0o600)
                replacement.replace(target)
            else:
                target.write_bytes(original_bytes + b" ")
                if mutation == "restore_bytes_and_mtime":
                    target.write_bytes(original_bytes)
                os.utime(target, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            return loaded

        monkeypatch.setattr(scheduler_module, "_load_state", race_after_load)
        # Invariant: loading valid bytes cannot authorize a checkpoint over later changes.
        with pytest.raises(ValueError, match="durable evidence changed during full reconstruction"):
            _activate_child(journal, plan.children[0].child_task_id)
        assert raced
        assert (path / "journal-head-checkpoint.json").read_bytes() == checkpoint
    finally:
        journal.close()
