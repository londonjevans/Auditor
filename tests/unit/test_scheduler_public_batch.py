"""One public inventory call may reuse a fresh chain, never stale usage or authority."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import pytest
from pydantic import BaseModel
from pydantic.json_schema import GenerateJsonSchema

from mmaudit.models import scheduler as scheduler_models
from mmaudit.models import truncation as protocol
from mmaudit.models.scheduler import SchedulerTruncationRecoveryModelRequestEvidence
from mmaudit.models.schemas import Location, UsageRecord
from mmaudit.models.truncation_recovery_journal import (
    SCHEDULER_TRUNCATION_RECOVERY_MAX_ENTRIES,
    SchedulerTruncationRecoveryChildActivation,
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryFamilyRoot,
)
from mmaudit.orchestration.scheduler import SchedulerJournal
from tests.unit.test_generic_truncation_tree import _build_tree
from tests.unit.test_scheduler_journal import _journal_private_file_snapshot
from tests.unit.test_scheduler_reconstruction import reconstruction_calls


@pytest.fixture(scope="module")
def public_batch_journal(tmp_path_factory: pytest.TempPathFactory) -> Iterator[SchedulerJournal]:
    journal, refusals = _build_tree(
        tmp_path_factory.mktemp("public-inventory-batch") / "journal", source_count=3
    )
    try:
        assert refusals == ()
        yield journal
    finally:
        journal.close()


def test_public_inventory_validates_common_chain_once_per_call(
    public_batch_journal: SchedulerJournal,
) -> None:
    journal = public_batch_journal
    expected = journal.recovery_model_requests
    files = _journal_private_file_snapshot(journal.path)
    assert len(expected) == 2
    for _ in range(2):
        with reconstruction_calls() as calls:
            observed = journal.recovery_model_requests
        assert observed == expected
        assert tuple(item.model_dump_json() for item in observed) == tuple(
            item.model_dump_json() for item in expected
        )
        assert calls["validate_truncation_recovery_entry_chain"] == 1
        assert calls["_candidate_review_schema_inventory_sha256"] > 0
        assert all(not item.review_credit_authorized for item in observed)
        assert all(not item.coverage_credit_authorized for item in observed)
    assert _journal_private_file_snapshot(journal.path) == files


def _standalone_arguments(journal: SchedulerJournal) -> tuple[dict[str, Any], ...]:
    entries = journal.truncation_recovery_entries
    families = {
        item.family_id: item
        for item in entries
        if isinstance(item, SchedulerTruncationRecoveryFamilyRoot)
    }
    activations = {
        item.entry_sha256: item
        for item in entries
        if isinstance(item, SchedulerTruncationRecoveryChildActivation)
    }
    parents = {item.task_id: item for item in journal.model_requests}
    attempts = {item.task_id: item for item in journal.provider_attempts}
    arguments: list[dict[str, Any]] = []
    for result in entries:
        if not isinstance(result, SchedulerTruncationRecoveryChildResult):
            continue
        family = families[result.family_id]
        assert family.parent_family_id is None
        task_id = family.recovery_plan.parent.parent_task_id
        arguments.append(
            {
                "manifest": journal.manifest,
                "parent_request": parents[task_id],
                "parent_attempt": attempts[task_id],
                "family": family,
                "root_family": family,
                "promotion": None,
                "activation": activations[result.activation_sha256],
                "result": result,
                "recovery_entries": entries,
            }
        )
    return tuple(arguments)


def test_standalone_builder_stays_strict_and_matches_batch_bytes(
    public_batch_journal: SchedulerJournal,
) -> None:
    arguments = _standalone_arguments(public_batch_journal)
    with reconstruction_calls() as calls:
        strict = tuple(
            SchedulerTruncationRecoveryModelRequestEvidence.build(**item) for item in arguments
        )
    assert calls["validate_truncation_recovery_entry_chain"] == 2
    expected = tuple(sorted(strict, key=lambda item: item.logical_request_id))
    observed = public_batch_journal.recovery_model_requests
    assert tuple(item.model_dump_json() for item in observed) == tuple(
        item.model_dump_json() for item in expected
    )
    for item in arguments:
        with pytest.raises(ValueError):
            SchedulerTruncationRecoveryModelRequestEvidence.build(
                **{**item, "recovery_entries": item["recovery_entries"][1:]}
            )


@pytest.mark.parametrize("stage", ("before_first", "before_second", "after_last"))
@pytest.mark.parametrize("mutation", ("entry_value", "usage_value", "usage_identity"))
def test_call_local_chain_rejects_entry_and_live_usage_changes(
    public_batch_journal: SchedulerJournal,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    mutation: str,
) -> None:
    journal = public_batch_journal
    expected = journal.recovery_model_requests
    files = _journal_private_file_snapshot(journal.path)
    original = SchedulerTruncationRecoveryModelRequestEvidence._build_with_entry_validator
    calls = 0
    restorations: list[Callable[[], None]] = []
    with monkeypatch.context() as patch:

        def mutate(arguments: dict[str, Any]) -> None:
            entries = arguments["recovery_entries"]
            target = next(
                item for item in entries if isinstance(item, SchedulerTruncationRecoveryChildResult)
            )
            usage = target.runtime_usage_record
            assert usage is not None
            if mutation == "usage_value":
                patch.setitem(usage.routing, "synthetic_public_batch_mutation", "changed")
            elif mutation == "usage_identity":
                replacement = UsageRecord.model_validate(usage.model_dump(mode="python"))
                assert replacement == usage and replacement is not usage
                object.__setattr__(target, "runtime_usage_record", replacement)
                restorations.append(
                    lambda: object.__setattr__(target, "runtime_usage_record", usage)
                )
            else:
                entry = entries[0]
                old_index = entry.entry_index
                object.__setattr__(entry, "entry_index", old_index + 1)
                restorations.append(lambda: object.__setattr__(entry, "entry_index", old_index))

        def intercept(cls: type[Any], **arguments: Any) -> Any:
            nonlocal calls
            calls += 1
            if (stage == "before_first" and calls == 1) or (
                stage == "before_second" and calls == 2
            ):
                mutate(arguments)
            result = original(**arguments)
            if stage == "after_last" and calls == 2:
                mutate(arguments)
            return result

        patch.setattr(
            SchedulerTruncationRecoveryModelRequestEvidence,
            "_build_with_entry_validator",
            classmethod(intercept),
        )
        try:
            with pytest.raises(ValueError):
                _ = journal.recovery_model_requests
        finally:
            for restore in reversed(restorations):
                restore()
    assert calls >= 1
    assert _journal_private_file_snapshot(journal.path) == files
    assert journal.recovery_model_requests == expected


@pytest.mark.parametrize("stage", ("before_first", "before_second", "after_last"))
@pytest.mark.parametrize(
    "mutation", ("direct", "transitive", "core_constraint", "callback", "keyword_default")
)
def test_call_local_reuse_rejects_fresh_schema_and_callback_drift(
    public_batch_journal: SchedulerJournal,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    mutation: str,
) -> None:
    journal = public_batch_journal
    expected = journal.recovery_model_requests
    files = _journal_private_file_snapshot(journal.path)
    original = SchedulerTruncationRecoveryModelRequestEvidence._build_with_entry_validator
    calls = 0
    with monkeypatch.context() as patch:

        def changed(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("changed schema callback must not be invoked")

        def mutate() -> None:
            if mutation == "core_constraint":
                core = protocol.CandidateReviewBeginFrame.__pydantic_core_schema__
                patch.setitem(core["schema"]["fields"]["finding_count"]["schema"], "ge", 99)
            elif mutation == "callback":
                patch.setattr(GenerateJsonSchema.generate, "__code__", changed.__code__)
            elif mutation == "keyword_default":
                renderer = BaseModel.model_json_schema.__func__
                assert renderer.__kwdefaults__ is not None
                patch.setitem(renderer.__kwdefaults__, "union_format", "primitive_type_array")
            else:
                model = protocol.CandidateFinding if mutation == "direct" else Location
                patch.setitem(model.model_config, "title", "Synthetic changed public batch schema")

        def intercept(cls: type[Any], **arguments: Any) -> Any:
            nonlocal calls
            calls += 1
            if (stage == "before_first" and calls == 1) or (
                stage == "before_second" and calls == 2
            ):
                mutate()
            result = original(**arguments)
            if stage == "after_last" and calls == 2:
                mutate()
            return result

        patch.setattr(
            SchedulerTruncationRecoveryModelRequestEvidence,
            "_build_with_entry_validator",
            classmethod(intercept),
        )
        with pytest.raises(ValueError):
            _ = journal.recovery_model_requests
    assert calls >= 1
    assert _journal_private_file_snapshot(journal.path) == files
    assert journal.recovery_model_requests == expected


def test_checked_chain_is_call_local_not_a_public_skip_option(
    public_batch_journal: SchedulerJournal,
) -> None:
    import inspect

    signature = inspect.signature(SchedulerTruncationRecoveryModelRequestEvidence.build)
    assert "entry_validator" not in signature.parameters
    assert "checked_entries" not in signature.parameters
    entries = public_batch_journal.truncation_recovery_entries
    first = scheduler_models._CheckedPublicRecoveryEntries.from_validated(entries)
    assert first.validate(entries) is entries
    with pytest.raises(ValueError, match="this call's checked chain"):
        first.validate(tuple(list(entries)))


@pytest.mark.parametrize("mutation", ("entry_value", "usage_value"))
def test_changed_input_is_rejected_before_any_batch_reuse(
    public_batch_journal: SchedulerJournal,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    journal = public_batch_journal
    expected = journal.recovery_model_requests
    entries = journal.truncation_recovery_entries
    files = _journal_private_file_snapshot(journal.path)
    if mutation == "entry_value":
        entries = (entries[0].model_copy(update={"entry_index": 1}), *entries[1:])
    with monkeypatch.context() as patch:
        if mutation == "usage_value":
            result = next(
                item for item in entries if isinstance(item, SchedulerTruncationRecoveryChildResult)
            )
            assert result.runtime_usage_record is not None
            patch.setitem(result.runtime_usage_record.routing, "synthetic_before_batch", "changed")
        with pytest.raises(ValueError):
            scheduler_models.build_scheduler_truncation_recovery_model_request_evidence(
                manifest=journal.manifest,
                model_requests=journal.model_requests,
                provider_attempts=journal.provider_attempts,
                truncation_recovery_entries=entries,
            )
    assert _journal_private_file_snapshot(journal.path) == files
    assert journal.recovery_model_requests == expected


def test_public_inventory_consumes_one_shot_input_only_once(
    public_batch_journal: SchedulerJournal,
) -> None:
    journal = public_batch_journal
    entries = journal.truncation_recovery_entries
    iterations = 0

    class SinglePass:
        def __iter__(self) -> Iterator[Any]:
            nonlocal iterations
            iterations += 1
            assert iterations == 1
            yield from entries

    actual = scheduler_models.build_scheduler_truncation_recovery_model_request_evidence(
        manifest=journal.manifest,
        model_requests=journal.model_requests,
        provider_attempts=journal.provider_attempts,
        truncation_recovery_entries=SinglePass(),
    )
    assert actual == journal.recovery_model_requests
    assert iterations == 1


def test_public_inventory_keeps_original_iteration_ceiling(
    public_batch_journal: SchedulerJournal,
) -> None:
    journal = public_batch_journal
    entry = journal.truncation_recovery_entries[0]
    emitted = 0

    class LyingSize:
        def __len__(self) -> int:
            return 0

        def __iter__(self) -> Iterator[Any]:
            nonlocal emitted
            for _ in range(SCHEDULER_TRUNCATION_RECOVERY_MAX_ENTRIES + 2):
                emitted += 1
                yield entry

    with pytest.raises(ValueError, match="journal entries exceeds its item limit"):
        scheduler_models.build_scheduler_truncation_recovery_model_request_evidence(
            manifest=journal.manifest,
            model_requests=journal.model_requests,
            provider_attempts=journal.provider_attempts,
            truncation_recovery_entries=LyingSize(),
        )
    assert emitted == SCHEDULER_TRUNCATION_RECOVERY_MAX_ENTRIES + 1


def test_empty_inventory_preserves_the_original_empty_result(
    public_batch_journal: SchedulerJournal,
) -> None:
    assert (
        scheduler_models.build_scheduler_truncation_recovery_model_request_evidence(
            manifest=public_batch_journal.manifest,
            model_requests=(),
            provider_attempts=(),
            truncation_recovery_entries=(),
        )
        == ()
    )
