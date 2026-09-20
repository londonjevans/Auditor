"""Pure synthetic closed-bill joins do not grant runtime or provider authority."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest

from mmaudit.models.authenticated_runner import (
    AuthenticatedCrossLineageLedgerEntryEvidence,
    AuthenticatedCrossLineageLedgerIntervalEvidence,
)
from mmaudit.models.authenticated_runner_smoke import _require_operator_cost_ledger_join
from mmaudit.models.route_cost_reservations import (
    ExactRouteCostReservation,
    OperatorRouteCostAttemptEvidence,
    RouteCostReservationPolicy,
)
from mmaudit.orchestration.cost_ledger import CostEntry, CostEntryStatus, cost_entry_sha256
from tests.unit.test_route_cost_reservations import _inputs


def _closed_pair(*, ceiling: str = "250") -> tuple[Any, Any]:
    inputs = _inputs()
    inputs["policy"] = RouteCostReservationPolicy.build(ledger_ceiling_usd_exact=ceiling)
    contract = ExactRouteCostReservation.build(**inputs)
    moment = datetime(2026, 1, 1, tzinfo=UTC)
    base = CostEntry(
        request_id=contract.request_token_plan.request_id,
        reservation_id="1" * 32,
        status=CostEntryStatus.RECONCILED,
        reserved_usd=Decimal(contract.reserved_cost_usd_exact),
        actual_cost_usd=Decimal("0.01"),
        accounted_cost_usd=Decimal("0.01"),
        release_reason=None,
        created_at=moment,
        updated_at=moment,
    )
    second = replace(base, request_id=f"{base.request_id}:attempt:2", reservation_id="2" * 32)
    attempts = tuple(
        OperatorRouteCostAttemptEvidence.from_entry(
            reservation=contract, attempt_index=index, entry=entry
        )
        for index, entry in enumerate((base, second), start=1)
    )
    interval = AuthenticatedCrossLineageLedgerIntervalEvidence(
        ledger_identity_sha256="1" * 64,
        initial_snapshot_sha256="2" * 64,
        final_snapshot_sha256="3" * 64,
        initial_spent_usd="0",
        interval_spent_usd="0.02",
        final_spent_usd="0.02",
        entries=tuple(
            AuthenticatedCrossLineageLedgerEntryEvidence(
                request_id=entry.request_id,
                entry_sha256=cost_entry_sha256(entry),
                reserved_usd=contract.reserved_cost_usd_exact,
                actual_cost_usd="0.01",
            )
            for entry in (base, second)
        ),
    )
    return attempts, interval


def test_closed_ledger_joins_every_retry_attempt() -> None:
    attempts, interval = _closed_pair()
    _require_operator_cost_ledger_join(attempts, interval)
    assert len(attempts) == len(interval.entries) == 2


def test_equal_aggregate_cannot_replace_two_individual_bills() -> None:
    attempts, interval = _closed_pair()
    changed = interval.model_copy(
        update={
            "entries": (
                interval.entries[0].model_copy(update={"actual_cost_usd": "0.015"}),
                interval.entries[1].model_copy(update={"actual_cost_usd": "0.005"}),
            )
        }
    )
    changed = AuthenticatedCrossLineageLedgerIntervalEvidence.model_validate_json(
        changed.model_dump_json()
    )
    assert changed.interval_spent_usd == interval.interval_spent_usd
    with pytest.raises(ValueError, match="exact closed ledger entry"):
        _require_operator_cost_ledger_join(attempts, changed)


@pytest.mark.parametrize("mutation", ("first_hash", "second_hash", "missing_retry", "swap_hashes"))
def test_closed_ledger_join_checks_every_entry_identity(mutation: str) -> None:
    attempts, interval = _closed_pair()
    entries = list(interval.entries)
    if mutation == "missing_retry":
        entries = entries[:1]
    elif mutation == "swap_hashes":
        entries = [
            entry.model_copy(update={"entry_sha256": entries[1 - index].entry_sha256})
            for index, entry in enumerate(entries)
        ]
    else:
        index = 0 if mutation == "first_hash" else 1
        entries[index] = entries[index].model_copy(update={"entry_sha256": "f" * 64})
    changed = interval.model_copy(
        update={
            "entries": tuple(entries),
            "interval_spent_usd": "0.01" if len(entries) == 1 else "0.02",
            "final_spent_usd": "0.01" if len(entries) == 1 else "0.02",
        }
    )
    changed = AuthenticatedCrossLineageLedgerIntervalEvidence.model_validate_json(
        changed.model_dump_json()
    )
    with pytest.raises(ValueError, match="exact closed ledger entry"):
        _require_operator_cost_ledger_join(attempts, changed)


def test_different_fixed_ledger_ceiling_refuses() -> None:
    attempts, interval = _closed_pair(ceiling="249")
    with pytest.raises(ValueError, match="ceiling differs"):
        _require_operator_cost_ledger_join(attempts, interval)
