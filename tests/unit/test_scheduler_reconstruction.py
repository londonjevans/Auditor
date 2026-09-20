"""Fresh full reconstruction reuses its own indexes without caching authority."""

from __future__ import annotations

import cProfile
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from types import CodeType
from typing import Any

import pytest

from mmaudit.models import truncation as protocol
from mmaudit.models.schemas import Location
from mmaudit.orchestration import scheduler as scheduler_module
from mmaudit.orchestration.scheduler import SchedulerJournal
from tests.unit.test_generic_truncation_tree import _build_tree
from tests.unit.test_scheduler_journal import _journal_private_file_snapshot


@contextmanager
def reconstruction_calls() -> Iterator[Counter[str]]:
    """Observe calls without replacing any journal or schema-integrity implementation."""

    counts: Counter[str] = Counter()
    profiler = cProfile.Profile()
    profiler.enable()
    try:
        yield counts
    finally:
        profiler.disable()
        for entry in profiler.getstats():
            if isinstance(entry.code, CodeType) and "/mmaudit/" in entry.code.co_filename:
                counts[entry.code.co_name] += entry.callcount


@pytest.fixture(scope="module")
def completed_recovery_journal(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[SchedulerJournal]:
    journal, refusals = _build_tree(
        tmp_path_factory.mktemp("same-load-reconstruction") / "journal", source_count=3
    )
    try:
        assert refusals == ()
        yield journal
    finally:
        journal.close()


def test_each_full_projection_derives_indexes_once_without_cross_call_cache(
    completed_recovery_journal: SchedulerJournal,
) -> None:
    journal = completed_recovery_journal
    expected = journal.local_journal_head_checkpoint
    for _ in range(2):
        with reconstruction_calls() as calls:
            observed = journal.journal_evidence
        assert observed == expected
        assert calls["_load_state"] == 1
        assert calls["_validate_loaded_state"] == 1
        assert calls["_derive_scheduler_journal_indexes"] == 1
        assert calls["_derive_truncation_recovery_indexes"] == 1
        # Every projection still re-reads evidence and freshly checks mutable schemas.
        assert calls["_candidate_review_schema_inventory_sha256"] > 0
        assert calls["_observe_durable_artifacts"] >= 2


@pytest.mark.parametrize("stage", ("before_load", "after_load"))
@pytest.mark.parametrize(
    "mutation",
    (
        "retained_event",
        "retained_recovery_entry",
        "main_index_membership",
        "main_index_value",
        "recovery_index_membership",
        "recovery_index_counter",
    ),
)
def test_fresh_indexes_and_files_still_detect_retained_memory_mutation(
    completed_recovery_journal: SchedulerJournal,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    mutation: str,
) -> None:
    journal = completed_recovery_journal
    expected = journal.journal_evidence
    files = _journal_private_file_snapshot(journal.path)
    with monkeypatch.context() as patch:

        def mutate() -> None:
            if mutation == "retained_event":
                event = journal._events[0].model_copy(update={"event_sha256": "f" * 64})
                patch.setattr(journal, "_events", [event, *journal._events[1:]])
            elif mutation == "retained_recovery_entry":
                patch.setattr(
                    journal,
                    "_truncation_recovery_entries",
                    journal._truncation_recovery_entries[:-1],
                )
            elif mutation == "main_index_membership":
                patch.setattr(journal._indexes, "event_ids", set())
            elif mutation == "main_index_value":
                task_id = next(iter(journal._indexes.event_histories))
                patch.setitem(journal._indexes.event_histories, task_id, [])
            elif mutation == "recovery_index_membership":
                patch.setattr(journal._truncation_recovery_indexes, "results", {})
            else:
                patch.setattr(journal._truncation_recovery_indexes, "recovery_requests_consumed", 0)

        if stage == "before_load":
            mutate()
        else:
            original_load = scheduler_module._load_state

            def mutate_after_load(*args: Any, **kwargs: Any) -> Any:
                reconstructed = original_load(*args, **kwargs)
                mutate()
                return reconstructed

            patch.setattr(scheduler_module, "_load_state", mutate_after_load)
        match = (
            "retained state differs from durable journal evidence"
            if mutation.startswith("retained_")
            else "indexes differ from full reconstruction"
        )
        # Invariant: no stale or caller-mutated value/index can project durable authority.
        with pytest.raises(ValueError, match=match):
            _ = journal.journal_evidence
    assert _journal_private_file_snapshot(journal.path) == files
    assert journal.journal_evidence == expected


@pytest.mark.parametrize("stage", ("before_load", "after_load"))
@pytest.mark.parametrize("target", ("direct", "transitive", "core_constraint"))
def test_prior_full_load_does_not_authorize_later_schema_drift(
    completed_recovery_journal: SchedulerJournal,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    stage: str,
) -> None:
    journal = completed_recovery_journal
    expected = journal.journal_evidence
    before = _journal_private_file_snapshot(journal.path)
    with monkeypatch.context() as patch:

        def mutate() -> None:
            if target == "core_constraint":
                core = protocol.CandidateReviewBeginFrame.__pydantic_core_schema__
                patch.setitem(core["schema"]["fields"]["finding_count"]["schema"], "ge", 99)
            else:
                model = protocol.CandidateFinding if target == "direct" else Location
                patch.setitem(
                    model.model_config, "title", "Synthetic changed reconstruction schema"
                )

        if stage == "before_load":
            mutate()
        else:
            original_load = scheduler_module._load_state

            def mutate_after_load(*args: Any, **kwargs: Any) -> Any:
                reconstructed = original_load(*args, **kwargs)
                mutate()
                return reconstructed

            patch.setattr(scheduler_module, "_load_state", mutate_after_load)
        with pytest.raises(ValueError):
            journal._validate_state()
    assert _journal_private_file_snapshot(journal.path) == before
    assert journal.journal_evidence == expected
