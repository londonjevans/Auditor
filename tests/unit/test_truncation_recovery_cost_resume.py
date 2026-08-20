"""Crash-safe cost and request-limit recovery for dispatched recovery children."""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest

import mmaudit.orchestration.scheduler as scheduler_module
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryResultOrigin,
    SchedulerTruncationRecoveryTerminalStatus,
)
from mmaudit.models.usage import atomic_request_limit_reservations_from_usage
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.scheduler import SchedulerJournal
from tests.unit.test_budgets import _shared_recovery_usage
from tests.unit.test_scheduler_journal import _bindings, _inventory, resume_scheduler_journal
from tests.unit.test_truncation_recovery_journal import _open_dispatched_child


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
