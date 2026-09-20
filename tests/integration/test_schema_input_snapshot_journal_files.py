"""Input-snapshot dependency drift cannot alter original custody or grant fresh work."""

from __future__ import annotations

from typing import Any

import pytest

import mmaudit.models.truncation as protocol
from mmaudit.orchestration import scheduler as scheduler_module
from mmaudit.orchestration.provisional_findings import build_provisional_finding_inventory
from mmaudit.orchestration.scheduler import SchedulerJournal
from tests.integration.test_schema_remapping_journal_files import (
    original_recovery_journal as original_recovery_journal,
)
from tests.integration.test_truncation_tree_manifest_files import (
    no_provider_or_operator_secrets as no_provider_or_operator_secrets,
)
from tests.unit.test_scheduler_journal import _journal_private_file_snapshot


@pytest.mark.parametrize("stage", ("before_load", "after_load"))
@pytest.mark.parametrize("target", ("input_guard", "itemgetter"))
def test_original_custody_rechecks_consumed_snapshot_dependencies(
    original_recovery_journal: SchedulerJournal,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    target: str,
) -> None:
    journal = original_recovery_journal
    evidence, artifact = journal.journal_evidence, journal.artifact()
    inventory = build_provisional_finding_inventory(journal, scheduler_artifact=artifact)
    assert inventory is not None and inventory.retained_finding_count == 1
    exported = inventory.model_dump_json()
    files = _journal_private_file_snapshot(journal.path)
    entries = tuple(row.model_dump_json() for row in journal.truncation_recovery_entries)
    consumed = target == "input_guard" or "itemgetter" in (
        protocol._candidate_review_schema_input_guard.__code__.co_names
    )
    with monkeypatch.context() as patch:

        def mutate() -> None:
            if target == "input_guard":
                patch.setattr(protocol, "_candidate_review_schema_input_guard", lambda _: None)
            else:
                patch.setattr(protocol, "itemgetter", object(), raising=False)

        if stage == "before_load":
            mutate()
        else:
            original_load = scheduler_module._load_state

            def mutate_after_load(*args: Any, **kwargs: Any) -> Any:
                result = original_load(*args, **kwargs)
                mutate()
                return result

            patch.setattr(scheduler_module, "_load_state", mutate_after_load)
        # Named invariant: a prior load cannot authorize a changed consumed dependency.
        # An unused reference-side name has no effect and grants no additional credit.
        if consumed:
            with pytest.raises(ValueError):
                _ = journal.journal_evidence
        else:
            assert journal.journal_evidence == evidence
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    assert _journal_private_file_snapshot(journal.path) == files
    assert journal.journal_evidence == evidence and journal.artifact() == artifact
    assert tuple(row.model_dump_json() for row in journal.truncation_recovery_entries) == entries
    restored = build_provisional_finding_inventory(journal, scheduler_artifact=artifact)
    assert restored is not None and restored.model_dump_json() == exported
    assert not journal.dispatchable_truncation_recovery_child_ids
    assert _journal_private_file_snapshot(journal.path) == files
