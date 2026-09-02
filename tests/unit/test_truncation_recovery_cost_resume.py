"""Crash-safe cost and request-limit recovery for dispatched recovery children."""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest

import mmaudit.orchestration.scheduler as scheduler_module
from mmaudit.models.schemas import ModelRequestValidationStatus, UsageRecord
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildActivation,
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryResultOrigin,
    SchedulerTruncationRecoveryTerminalStatus,
)
from mmaudit.models.usage import (
    atomic_request_limit_reservations_from_usage,
    is_structurally_recovery_accountable_usage_record,
)
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntryStatus,
    ReleaseReason,
    cost_entry_sha256,
)
from mmaudit.orchestration.scheduler import SchedulerJournal
from tests.unit.test_budgets import _shared_recovery_usage
from tests.unit.test_scheduler_journal import _bindings, _inventory, resume_scheduler_journal
from tests.unit.test_truncation_recovery_journal import (
    _activate_child,
    _journal_with_truncated_parent,
    _open_dispatched_child,
    _typed_usage,
)


def _ledger_with_retained_usage(
    path: Path,
    journal: SchedulerJournal,
    *,
    ledger: AtomicCostLedger | None = None,
) -> AtomicCostLedger:
    selected = ledger or AtomicCostLedger.initialize(path, cap_usd=Decimal("1"))
    for record in journal.retained_provider_usage_records:
        assert record.accounted_cost_usd_exact is not None
        accounted = Decimal(record.accounted_cost_usd_exact)
        reservation = selected.reserve(record.request_id, max(accounted, Decimal("0.01")))
        reported = (
            Decimal(record.reported_cost_usd_exact)
            if record.reported_cost_usd_exact is not None
            else None
        )
        selected.reconcile(reservation, reported)
    return selected


def _released_recovery_usage(
    activation: SchedulerTruncationRecoveryChildActivation,
) -> UsageRecord:
    base = _typed_usage(
        activation=activation,
        validation_status=ModelRequestValidationStatus.PROVIDER_ERROR,
        status="provider_error",
        response_sha256=None,
        validated_response_sha256=None,
        finish_reason=None,
        native_finish_reason=None,
        completion_tokens=0,
        cost_usd_exact="0",
    )
    released = UsageRecord.model_validate(
        base.model_copy(
            update={
                "returned_model": None,
                "actual_model": None,
                "provider": None,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "reported_cost_usd": None,
                "reported_cost_usd_exact": None,
                "openrouter_generation_id": None,
                "actual_provider_endpoint": None,
                "reasoning_tokens": 0,
                "reasoning_evidence": None,
                "token_detail_accounting_evidence": None,
                "cached_tokens": 0,
                "provider_error_classification": "timeout",
            }
        ).model_dump(mode="python")
    )
    assert is_structurally_recovery_accountable_usage_record(
        released,
        request_limit_scope=activation.request_limit_id,
        request_limit_count_before=activation.request_limit_count_before_child,
    )
    return released


def test_scheduler_budget_recovery_hands_off_two_exact_disjoint_root_coordinates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    roots = ("family-a-request", "family-b-request")
    records = tuple(_shared_recovery_usage(root, root_scope=root, count_before=0) for root in roots)
    families = {
        f"family-{index}": SimpleNamespace(
            request_limit_id=root,
            request_limit_binding=SimpleNamespace(
                parent_request_limit_reservation=(
                    atomic_request_limit_reservations_from_usage(record)[-1]
                )
            ),
        )
        for index, (root, record) in enumerate(zip(roots, records, strict=True))
    }
    journal = object.__new__(SchedulerJournal)
    journal._truncation_recovery_indexes = SimpleNamespace(families=families)  # type: ignore[assignment]
    monkeypatch.setattr(journal, "_retained_typed_recovery_usage", lambda: ((), (), roots))
    monkeypatch.setattr(journal, "_retained_main_provider_usage_records", lambda: records)
    monkeypatch.setattr(journal, "claim_restorable_usage_records", lambda: records)
    journal.manifest = SimpleNamespace(cost_ledger_baseline=None)  # type: ignore[assignment]
    issued = object()
    captured: dict[str, object] = {}

    def capture_issue(
        issued_records: tuple[object, ...],
        **kwargs: object,
    ) -> object:
        assert issued_records == records
        captured.update(kwargs)
        return issued

    monkeypatch.setattr(scheduler_module, "_issue_trusted_budget_recovery_scope", capture_issue)

    recovered, recovery_scope = journal.claim_restorable_usage_for_budget_recovery()

    assert recovered == records
    assert recovery_scope is issued
    assert captured["shared_request_limit_roots"] == (
        ("family-a-request", 0),
        ("family-b-request", 0),
    )


@pytest.mark.asyncio
async def test_dispatched_recovery_child_is_accounted_and_never_redispatched(
    tmp_path: Path,
) -> None:
    journal_path = tmp_path / "journal"
    journal, child, activation, _dispatch, _surfaces, _surface_manifest = _open_dispatched_child(
        journal_path, parent_cost_usd_exact="0.01"
    )
    main_usage = journal.retained_provider_usage_records
    parent_usage = next(
        record for record in main_usage if record.request_id == activation.request_limit_id
    )
    assert parent_usage.accounted_cost_usd_exact == "0.01"

    ledger = AtomicCostLedger.initialize(tmp_path / "cost-ledger.json", cap_usd=Decimal("1"))
    for record in main_usage:
        assert record.accounted_cost_usd_exact is not None
        accounted = Decimal(record.accounted_cost_usd_exact)
        reservation = ledger.reserve(record.request_id, max(accounted, Decimal("0.01")))
        reported = (
            Decimal(record.reported_cost_usd_exact)
            if record.reported_cost_usd_exact is not None
            else None
        )
        ledger.reconcile(reservation, reported)
    ledger.reserve(child.child_logical_request_id, Decimal("0.10"))
    expected_journal = journal.journal_evidence
    journal.close()

    resumed = resume_scheduler_journal(
        journal_path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_journal_evidence=expected_journal,
    )
    result = next(
        item
        for item in resumed.truncation_recovery_entries
        if isinstance(item, SchedulerTruncationRecoveryChildResult)
    )
    assert result.result_origin is SchedulerTruncationRecoveryResultOrigin.CRASH_RECOVERY
    assert result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.UNCERTAIN

    records, recovery_scope = resumed.claim_restorable_usage_for_budget_recovery(
        atomic_ledger=ledger
    )
    child_entry = next(
        entry
        for entry in ledger.snapshot().entries
        if entry.request_id == child.child_logical_request_id
    )
    assert child_entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert child_entry.accounted_cost_usd == Decimal("0.10")

    budget = BudgetManager(
        total_usd=1,
        max_output_tokens=1_000,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=activation.request_limit_maximum,
        atomic_ledger=ledger,
        global_input_token_budget=1_000_000,
        global_output_token_budget=100_000,
    )
    await budget.restore_recovered_usage(records, recovery_scope=recovery_scope)

    assert budget.spent_usd_exact == Decimal("0.11")
    assert not budget.recovery_required
    assert resumed.dispatchable_truncation_recovery_child_ids == ()
    resumed.close()


@pytest.mark.asyncio
async def test_dispatched_recovery_child_release_is_zero_cost_and_idempotent(
    tmp_path: Path,
) -> None:
    journal_path = tmp_path / "released-journal"
    journal, child, activation, _dispatch, _surfaces, _surface_manifest = _open_dispatched_child(
        journal_path, parent_cost_usd_exact="0.01"
    )
    parent_usage = next(
        record
        for record in journal.retained_provider_usage_records
        if record.request_id == activation.request_limit_id
    )
    ledger = _ledger_with_retained_usage(tmp_path / "released-ledger.json", journal)
    reservation = ledger.reserve(child.child_logical_request_id, Decimal("0.10"))
    released = ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)
    expected = journal.journal_evidence
    journal.close()

    for resume_index in range(2):
        resumed = resume_scheduler_journal(
            journal_path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=expected if resume_index == 0 else None,
            atomic_ledger=ledger,
        )
        result = next(
            item
            for item in resumed.truncation_recovery_entries
            if isinstance(item, SchedulerTruncationRecoveryChildResult)
        )
        assert result.schema_version == "1.3"
        assert result.result_origin is SchedulerTruncationRecoveryResultOrigin.CRASH_RECOVERY
        assert result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.FAILED
        assert result.dispatch_id is not None
        assert result.released_cost_entry_sha256 == cost_entry_sha256(released)
        assert result.accounted_provider_attempts == 1
        assert result.accounted_completion_tokens == 0
        assert result.accounted_cost_usd_exact == "0"
        assert result.runtime_usage_record is None

        records, recovery_scope = resumed.claim_restorable_usage_for_budget_recovery(
            atomic_ledger=ledger
        )
        budget = BudgetManager(
            total_usd=1,
            max_output_tokens=1_000,
            conservative_usd_per_million_tokens=1,
            max_requests_per_agent=activation.request_limit_maximum,
            atomic_ledger=ledger,
            global_input_token_budget=1_000_000,
            global_output_token_budget=100_000,
        )
        await budget.restore_recovered_usage(records, recovery_scope=recovery_scope)

        assert parent_usage in records
        assert child.child_logical_request_id not in {record.request_id for record in records}
        assert budget.spent_usd_exact == Decimal("0.01")
        assert budget.spent_output_tokens == sum(record.completion_tokens for record in records)
        assert budget._request_limit_counts[("scheduled_task", activation.request_limit_id)] == 2
        assert resumed.dispatchable_truncation_recovery_child_ids == ()
        resumed.close()


@pytest.mark.asyncio
async def test_activated_recovery_child_release_is_terminalized_without_dispatch(
    tmp_path: Path,
) -> None:
    journal_path = tmp_path / "activated-release-journal"
    journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(
        journal_path,
        parent_cost_usd_exact="0.01",
    )
    journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    child = plan.children[0]
    activation = _activate_child(journal, child.child_task_id)
    ledger = _ledger_with_retained_usage(tmp_path / "activated-release-ledger.json", journal)
    reservation = ledger.reserve(child.child_logical_request_id, Decimal("0.10"))
    released = ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)
    journal.close()

    resumed = resume_scheduler_journal(
        journal_path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        atomic_ledger=ledger,
    )
    result = next(
        item
        for item in resumed.truncation_recovery_entries
        if isinstance(item, SchedulerTruncationRecoveryChildResult)
    )
    assert result.schema_version == "1.3"
    assert result.dispatch_id is None
    assert result.dispatch_sha256 is None
    assert result.released_cost_entry_sha256 == cost_entry_sha256(released)
    assert result.accounted_provider_attempts == 1
    assert result.accounted_completion_tokens == 0
    assert resumed.dispatchable_truncation_recovery_child_ids == ()

    records, recovery_scope = resumed.claim_restorable_usage_for_budget_recovery(
        atomic_ledger=ledger
    )
    budget = BudgetManager(
        total_usd=1,
        max_output_tokens=1_000,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=activation.request_limit_maximum,
        atomic_ledger=ledger,
        global_input_token_budget=1_000_000,
        global_output_token_budget=100_000,
    )
    await budget.restore_recovered_usage(records, recovery_scope=recovery_scope)
    assert budget.spent_usd_exact == Decimal("0.01")
    assert budget._request_limit_counts[("scheduled_task", activation.request_limit_id)] == 2
    resumed.close()


def test_runtime_released_child_result_retains_exact_failed_usage(tmp_path: Path) -> None:
    journal, child, activation, dispatch, _surfaces, _surface_manifest = _open_dispatched_child(
        tmp_path / "runtime-release-model",
        parent_cost_usd_exact="0.01",
    )
    failed_usage = _released_recovery_usage(activation)
    result = SchedulerTruncationRecoveryChildResult.build_released_pre_send(
        child=child,
        activation=activation,
        dispatch=dispatch,
        terminal_evidence_sha256="a" * 64,
        release_reason=ReleaseReason.FAILED_BEFORE_SEND.value,
        accounted_prefix_attempts=0,
        accounted_prefix_cost_usd_exact="0",
        failed_usage_record=failed_usage,
        result_origin=SchedulerTruncationRecoveryResultOrigin.RUNTIME,
        entry_index=len(journal.truncation_recovery_entries),
        previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
    )

    assert result.schema_version == "1.3"
    assert result.runtime_usage_record == failed_usage
    assert result.runtime_usage_record_sha256 is not None
    assert result.accounted_provider_attempts == 1
    assert result.accounted_completion_tokens == 0
    assert result.accounted_cost_usd_exact == "0"
    assert result.completed_surface_ids == ()
    assert result.retained_surface_ids == ()
    journal.close()


@pytest.mark.parametrize("dispatched", [False, True])
@pytest.mark.parametrize("pending_checkpoint", [False, True])
def test_live_released_child_crash_before_checkpoint_resumes_exact_suffix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    dispatched: bool,
    pending_checkpoint: bool,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    ledger = AtomicCostLedger.initialize(
        tmp_path / "child-checkpoint-ledger.json",
        cap_usd=Decimal("1"),
    )
    journal_path = tmp_path / "child-checkpoint-journal"
    if dispatched:
        journal, child, activation, _dispatch, _surfaces, _surface_manifest = (
            _open_dispatched_child(
                journal_path,
                parent_cost_usd_exact="0.01",
                atomic_ledger=ledger,
            )
        )
    else:
        journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(
            journal_path,
            parent_cost_usd_exact="0.01",
            atomic_ledger=ledger,
        )
        journal.open_truncation_recovery_family(
            recovery_plan=plan,
            truncation_projection=projection,
            requested_surface_manifest=surface_manifest,
        )
        child = plan.children[0]
        activation = _activate_child(journal, child.child_task_id)
    bindings = journal.manifest.bindings
    _ledger_with_retained_usage(
        tmp_path / "unused-ledger-path.json",
        journal,
        ledger=ledger,
    )
    reservation = ledger.reserve(child.child_logical_request_id, Decimal("0.10"))
    released = ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)
    failed_usage = _released_recovery_usage(activation)
    expected = journal.journal_evidence

    def crash_before_checkpoint() -> None:
        raise SimulatedProcessDeath

    original_write = scheduler_module._write_fresh_private_file

    def crash_after_pending_fsync(
        parent_descriptor: int,
        leaf: str,
        content: bytes,
    ) -> None:
        original_write(parent_descriptor, leaf, content)
        if leaf == scheduler_module._JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME:
            raise SimulatedProcessDeath

    if pending_checkpoint:
        monkeypatch.setattr(
            scheduler_module,
            "_write_fresh_private_file",
            crash_after_pending_fsync,
        )
    else:
        monkeypatch.setattr(
            journal,
            "_refresh_journal_head_checkpoint",
            crash_before_checkpoint,
        )
    with pytest.raises(SimulatedProcessDeath):
        journal.record_truncation_recovery_child_released_failure(
            child.child_task_id,
            failed_usage_record=failed_usage,
            atomic_ledger=ledger,
        )
    if pending_checkpoint:
        monkeypatch.setattr(
            scheduler_module,
            "_write_fresh_private_file",
            original_write,
        )
    staged = journal.truncation_recovery_entries[-1]
    assert isinstance(staged, SchedulerTruncationRecoveryChildResult)
    assert staged.schema_version == "1.3"
    assert staged.released_cost_entry_sha256 == cost_entry_sha256(released)
    assert (staged.dispatch_id is not None) is dispatched
    journal.close()

    observed_result: SchedulerTruncationRecoveryChildResult | None = None
    for _resume_ordinal in range(2):
        resumed = resume_scheduler_journal(
            journal_path,
            expected_bindings=bindings,
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=expected if _resume_ordinal == 0 else None,
            atomic_ledger=ledger,
        )
        result = next(
            entry
            for entry in resumed.truncation_recovery_entries
            if isinstance(entry, SchedulerTruncationRecoveryChildResult)
            and entry.child_task_id == child.child_task_id
        )
        assert result == staged
        assert result.runtime_usage_record == failed_usage
        assert resumed.dispatchable_truncation_recovery_child_ids == ()
        if observed_result is not None:
            assert result == observed_result
        assert not (
            journal_path / scheduler_module._JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME
        ).exists()
        observed_result = result
        resumed.close()


def test_resume_rejects_multiple_released_child_suffixes_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    ledger = AtomicCostLedger.initialize(
        tmp_path / "multiple-child-suffix-ledger.json",
        cap_usd=Decimal("1"),
    )
    journal_path = tmp_path / "multiple-child-suffix-journal"
    journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(
        journal_path,
        parent_cost_usd_exact="0.01",
        atomic_ledger=ledger,
    )
    journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    children = plan.children[:2]
    activations = tuple(_activate_child(journal, child.child_task_id) for child in children)
    _ledger_with_retained_usage(
        tmp_path / "unused-multiple-child-ledger.json",
        journal,
        ledger=ledger,
    )

    def crash_before_checkpoint() -> None:
        raise SimulatedProcessDeath

    monkeypatch.setattr(journal, "_refresh_journal_head_checkpoint", crash_before_checkpoint)
    for ordinal, (child, activation) in enumerate(
        zip(children, activations, strict=True),
    ):
        reservation = ledger.reserve(child.child_logical_request_id, Decimal("0.10"))
        ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)
        expected_error: type[BaseException] = SimulatedProcessDeath if ordinal == 0 else ValueError
        expected_match = (
            None if ordinal == 0 else "scheduler recovery snapshot changed after private custody"
        )
        with pytest.raises(expected_error, match=expected_match):
            journal.record_truncation_recovery_child_released_failure(
                child.child_task_id,
                failed_usage_record=_released_recovery_usage(activation),
                atomic_ledger=ledger,
            )
    bindings = journal.manifest.bindings
    journal.close()
    ledger_before = ledger.path.read_bytes()

    with pytest.raises(ValueError, match="checkpoint does not match"):
        resume_scheduler_journal(
            journal_path,
            expected_bindings=bindings,
            expected_shard_inventory=_inventory(),
            atomic_ledger=ledger,
        )

    assert ledger.path.read_bytes() == ledger_before


def test_resume_rejects_forged_released_child_suffix_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    ledger = AtomicCostLedger.initialize(
        tmp_path / "forged-child-suffix-ledger.json",
        cap_usd=Decimal("1"),
    )
    journal_path = tmp_path / "forged-child-suffix-journal"
    journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(
        journal_path,
        parent_cost_usd_exact="0.01",
        atomic_ledger=ledger,
    )
    journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    child = plan.children[0]
    activation = _activate_child(journal, child.child_task_id)
    _ledger_with_retained_usage(
        tmp_path / "unused-forged-child-ledger.json",
        journal,
        ledger=ledger,
    )
    reservation = ledger.reserve(child.child_logical_request_id, Decimal("0.10"))
    ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)
    forged = SchedulerTruncationRecoveryChildResult.build_released_pre_send(
        child=child,
        activation=activation,
        dispatch=None,
        terminal_evidence_sha256="f" * 64,
        release_reason=ReleaseReason.FAILED_BEFORE_SEND.value,
        accounted_prefix_attempts=0,
        accounted_prefix_cost_usd_exact="0",
        failed_usage_record=_released_recovery_usage(activation),
        result_origin=SchedulerTruncationRecoveryResultOrigin.RUNTIME,
        entry_index=len(journal.truncation_recovery_entries),
        previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
    )

    def crash_before_checkpoint() -> None:
        raise SimulatedProcessDeath

    monkeypatch.setattr(journal, "_refresh_journal_head_checkpoint", crash_before_checkpoint)
    with pytest.raises(SimulatedProcessDeath):
        journal._append_truncation_recovery_entry(forged)
    bindings = journal.manifest.bindings
    journal.close()
    ledger_before = ledger.path.read_bytes()

    with pytest.raises(ValueError, match="checkpoint does not match"):
        resume_scheduler_journal(
            journal_path,
            expected_bindings=bindings,
            expected_shard_inventory=_inventory(),
            atomic_ledger=ledger,
        )

    assert ledger.path.read_bytes() == ledger_before
