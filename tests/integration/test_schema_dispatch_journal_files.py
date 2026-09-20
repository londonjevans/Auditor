"""Original recovery files cannot gain credit through changed schema dispatch machinery."""

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


@pytest.mark.parametrize("stage", ("before_load", "after_load"))
@pytest.mark.parametrize("target", ("selector", "dispatcher", "mode"))
def test_original_custody_rejects_dispatch_drift_without_changing_files_costs_or_export(
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
    with monkeypatch.context() as patch:

        def mutate() -> None:
            if target == "selector":
                patch.setattr(protocol, "_candidate_review_direct_schema_dispatch", lambda _: None)
            elif target == "dispatcher":
                patch.setattr(
                    protocol._CandidateReviewJsonSchemaGenerator,
                    "generate_inner",
                    GenerateJsonSchema.generate_inner,
                )
            else:
                descriptor = vars(GenerateJsonSchema)["mode"]
                patch.setattr(GenerateJsonSchema, "mode", property(descriptor.fget))

        if stage == "before_load":
            mutate()
        else:
            original_load = scheduler_module._load_state

            def mutate_after_load(*args: Any, **kwargs: Any) -> Any:
                result = original_load(*args, **kwargs)
                mutate()
                return result

            patch.setattr(scheduler_module, "_load_state", mutate_after_load)
        # Named invariant: prior full loading cannot authorize changed renderers or mutate custody.
        with pytest.raises(ValueError):
            _ = journal.journal_evidence
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    assert _journal_private_file_snapshot(journal.path) == files
    assert journal.journal_evidence == evidence
    assert tuple(row.model_dump_json() for row in journal.truncation_recovery_entries) == entries
    restored = build_provisional_finding_inventory(journal, scheduler_artifact=artifact)
    assert restored is not None and restored.model_dump_json() == exported
    assert not journal.dispatchable_truncation_recovery_child_ids
    assert _journal_private_file_snapshot(journal.path) == files
