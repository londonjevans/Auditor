"""Hash-copy dependency changes cannot mutate original journals or grant resumed credit."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic.json_schema import GenerateJsonSchema

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
from tests.unit.test_truncation_schema_copy import (
    _mutate_selected_sort,
)
from tests.unit.test_truncation_schema_copy import (
    selected_schema_generator as selected_schema_generator,
)


@pytest.mark.parametrize("stage", ("before_load", "after_load"))
@pytest.mark.parametrize("mutation", ("rebind", "code"))
def test_original_files_exports_and_no_dispatch_survive_hash_copy_dependency_refusal(
    selected_schema_generator: type[GenerateJsonSchema],
    original_recovery_journal: SchedulerJournal,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    mutation: str,
) -> None:
    journal = original_recovery_journal
    evidence, artifact = journal.journal_evidence, journal.artifact()
    inventory = build_provisional_finding_inventory(journal, scheduler_artifact=artifact)
    assert inventory is not None and inventory.retained_finding_count == 1
    exported = inventory.model_dump_json()
    files = _journal_private_file_snapshot(journal.path)
    entries = tuple(row.model_dump_json() for row in journal.truncation_recovery_entries)
    with monkeypatch.context() as patch:

        def mutate() -> None:
            _mutate_selected_sort(patch, selected_schema_generator, mutation)

        if stage == "before_load":
            mutate()
        else:
            original_load = scheduler_module._load_state

            def mutate_after_load(*args: Any, **kwargs: Any) -> Any:
                result = original_load(*args, **kwargs)
                mutate()
                return result

            patch.setattr(scheduler_module, "_load_state", mutate_after_load)
        # Named invariant: original custody cannot authorize changed copy/sort dependencies.
        with pytest.raises(ValueError):
            _ = journal.journal_evidence
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    assert _journal_private_file_snapshot(journal.path) == files
    assert journal.journal_evidence == evidence and journal.artifact() == artifact
    assert tuple(row.model_dump_json() for row in journal.truncation_recovery_entries) == entries
    restored = build_provisional_finding_inventory(journal, scheduler_artifact=artifact)
    assert restored is not None and restored.model_dump_json() == exported
    assert not journal.dispatchable_truncation_recovery_child_ids
    assert _journal_private_file_snapshot(journal.path) == files
