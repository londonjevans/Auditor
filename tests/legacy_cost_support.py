"""Synthetic local historical rows; never read or modify the operator's real ledger."""

from datetime import UTC, datetime
from decimal import Decimal

import pytest

from mmaudit.models.legacy_cost_allowance import (
    LegacyUncertainCostAllowance,
    LegacyUncertainCostEntry,
)
from mmaudit.orchestration import cost_ledger
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntry


def allowance_for_entries(
    entries: tuple[CostEntry, ...],
) -> LegacyUncertainCostAllowance:
    values = tuple(
        LegacyUncertainCostEntry(
            request_id=entry.request_id,
            reservation_id=entry.reservation_id,
            created_at=entry.created_at.isoformat(),
            updated_at=entry.updated_at.isoformat(),
            reserved_usd_exact=str(entry.reserved_usd),
            accounted_cost_usd_exact=str(entry.accounted_cost_usd),
        )
        for entry in sorted(entries, key=lambda item: item.request_id)
    )
    assert len(values) == 2
    return LegacyUncertainCostAllowance.build((values[0], values[1]))


def seed_legacy_uncertainty(
    ledger: AtomicCostLedger, monkeypatch: pytest.MonkeyPatch
) -> LegacyUncertainCostAllowance:
    for name, cost, day in (
        ("authrunner.smoke.r2.candidate.primary", "0.05225616", 23),
        ("authrunner.smoke.r17.judge.replay", "0.18105", 24),
    ):
        with monkeypatch.context() as patch:
            now = datetime(2026, 8, day, 12, tzinfo=UTC)
            patch.setattr(cost_ledger, "_timestamp", lambda observed=now: observed)
            reservation = ledger.reserve(f"{name}:{'1' * 64}", Decimal(cost))
            ledger.commit_for_transport(reservation)
            ledger.reconcile(reservation, None)
    return allowance_for_entries(
        tuple(
            entry
            for entry in ledger.snapshot().entries
            if entry.request_id.startswith("authrunner.")
        )
    )
