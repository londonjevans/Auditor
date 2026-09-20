"""Original file custody must survive rejection of altered fresh-schema machinery."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic.json_schema import GenerateJsonSchema

import mmaudit.models.truncation as protocol
from mmaudit.orchestration import scheduler as scheduler_module
from mmaudit.orchestration.provisional_findings import build_provisional_finding_inventory
from mmaudit.orchestration.scheduler import SchedulerJournal
from tests.integration.test_truncation_tree_manifest_files import (
    no_provider_or_operator_secrets as no_provider_or_operator_secrets,
)
from tests.scheduler_scaling_support import (
    _nonempty_original_projection,
    load_scaling_cases,
    measure_original_tree,
)
from tests.unit.test_generic_truncation_tree import _build_tree
from tests.unit.test_scheduler_journal import _journal_private_file_snapshot


@pytest.fixture
def original_recovery_journal(tmp_path: Path) -> Iterator[SchedulerJournal]:
    with _nonempty_original_projection():
        journal, refusals = _build_tree(
            tmp_path / "original-schema-remapping-journal", source_count=3, request_limit=33
        )
    try:
        assert refusals == ()
        yield journal
    finally:
        journal.close()


@pytest.mark.parametrize("stage", ("before_load", "after_load"))
@pytest.mark.parametrize("target", ("helper", "generator_override", "limit"))
def test_original_files_and_noncrediting_export_survive_remapping_drift_refusal(
    original_recovery_journal: SchedulerJournal,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    target: str,
) -> None:
    journal = original_recovery_journal
    evidence, artifact = journal.journal_evidence, journal.artifact()
    inventory = build_provisional_finding_inventory(journal, scheduler_artifact=artifact)
    assert inventory is not None and inventory.retained_finding_count == 1
    original_inventory = inventory.model_dump_json()
    original_files = _journal_private_file_snapshot(journal.path)
    original_entries = tuple(row.model_dump_json() for row in journal.truncation_recovery_entries)
    with monkeypatch.context() as patch:

        def fallback(*_args: Any, **_kwargs: Any) -> None:
            return None

        def mutate() -> None:
            if target == "helper":
                patch.setattr(protocol, "_collision_free_schema_remapping", fallback)
            elif target == "generator_override":
                patch.setattr(
                    protocol._CandidateReviewJsonSchemaGenerator,
                    "generate_definitions",
                    GenerateJsonSchema.generate_definitions,
                )
            else:
                patch.setattr(protocol, "_SCHEMA_REMAPPING_MAX_DEFINITIONS", 255)

        if stage == "before_load":
            mutate()
        else:
            original_load = scheduler_module._load_state

            def mutate_after_load(*args: Any, **kwargs: Any) -> Any:
                result = original_load(*args, **kwargs)
                mutate()
                return result

            patch.setattr(scheduler_module, "_load_state", mutate_after_load)
        # Invariant: a previous full load cannot authorize altered schema machinery.
        with pytest.raises(ValueError):
            _ = journal.journal_evidence
    assert protocol.candidate_review_protocol_implementation_is_pristine()
    assert _journal_private_file_snapshot(journal.path) == original_files
    assert journal.journal_evidence == evidence
    assert (
        tuple(row.model_dump_json() for row in journal.truncation_recovery_entries)
        == original_entries
    )
    restored = build_provisional_finding_inventory(journal, scheduler_artifact=artifact)
    assert restored is not None and restored.model_dump_json() == original_inventory
    assert not journal.dispatchable_truncation_recovery_child_ids
    assert _journal_private_file_snapshot(journal.path) == original_files


def test_fresh_remapping_keeps_exact_original_nonempty_export_and_resume(tmp_path: Path) -> None:
    result = measure_original_tree(load_scaling_cases()[0], tmp_path, samples=1, profile=False)
    assert result["provisional_findings"] == 1
    assert result["original_files_unchanged"] is True
    assert result["original_costs_and_request_ordinals_unchanged"] is True
    assert result["accounted_child_cost_usd"] == "0.10"
    assert result["new_resume_dispatches"] == result["provider_calls"] == 0
    assert result["promotion_or_completion_credit"] is False
    assert len(result["phases"]) == 5
