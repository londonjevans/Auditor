"""Unknown billing is a typed stop, not exhausted capacity or settled cost."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path

import pytest
import typer

import mmaudit.cli as cli_module
from mmaudit.constants import ExitCode
from mmaudit.orchestration.budgets import BudgetExhaustedError, BudgetPriorBillingUnknownError
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostBudgetExceededError,
    CostEntryStatus,
    CostPriorBillingUnknownError,
    PortfolioAttemptSlot,
)


@pytest.mark.parametrize("reopen", (False, True))
@pytest.mark.parametrize("operation", ("reserve", "claim", "adopt", "commit"))
def test_unknown_history_refuses_without_changing_any_liability(
    tmp_path: Path, reopen: bool, operation: str
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic.json", cap_usd=Decimal("250"))
    prior = ledger.reserve("synthetic-prior", Decimal("0.25"))
    pending = ledger.reserve("synthetic-pending", Decimal("0.01"))
    hold = ledger.reserve_portfolio(
        "a" * 64, (PortfolioAttemptSlot("synthetic-slot", Decimal("0.01")),)
    )
    ledger.commit_for_transport(prior)
    ledger.reconcile(prior, None)
    if reopen:
        ledger = AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("250"))
    retained = ledger.path.read_bytes()
    with pytest.raises(CostPriorBillingUnknownError, match=r"^UNKNOWN_PRIOR_BILLING:"):
        if operation == "reserve":
            ledger.reserve("synthetic-next", Decimal("0.01"), require_known_prior_costs=True)
        elif operation == "claim":
            ledger.claim_portfolio_slot(
                hold, "synthetic-slot", Decimal("0.01"), require_known_prior_costs=True
            )
        elif operation == "adopt":
            ledger.active_reservation(pending.request_id, require_known_prior_costs=True)
        else:
            ledger.commit_for_transport(pending, require_known_prior_costs=True)
    assert ledger.path.read_bytes() == retained
    assert ledger.snapshot().remaining_usd > Decimal("249")
    assert ledger.active_reservation(pending.request_id) == pending
    assert ledger.snapshot().entries[1].status is CostEntryStatus.UNCERTAIN_ACCOUNTED


@pytest.mark.parametrize("actual", ("0", "0.01"))
def test_only_recorded_actual_billing_clears_unknown_history(tmp_path: Path, actual: str) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic.json", cap_usd=Decimal("250"))
    prior = ledger.reserve("synthetic-prior", Decimal("0.25"))
    ledger.commit_for_transport(prior)
    ledger.reconcile(prior, None)
    with pytest.raises(CostPriorBillingUnknownError):
        ledger.reserve("synthetic-next", Decimal("0.01"), require_known_prior_costs=True)
    # Synthetic bill supplied by this fixture, never an estimate promoted to actual.
    billed = ledger.reconcile(prior, Decimal(actual))
    assert billed.actual_cost_usd == billed.accounted_cost_usd == Decimal(actual)
    assert billed.reserved_usd == Decimal("0.25")
    assert billed.reservation_id == prior.reservation_id
    assert ledger.reserve("synthetic-next", Decimal("0.01"), require_known_prior_costs=True)


def test_exhausted_capacity_is_not_an_unknown_billing_refusal(tmp_path: Path) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic.json", cap_usd=Decimal("250"))
    prior = ledger.reserve("synthetic-prior", Decimal("250"))
    ledger.reconcile(prior, Decimal("250"))
    retained = ledger.path.read_bytes()
    with pytest.raises(CostBudgetExceededError) as caught:
        ledger.reserve("synthetic-next", Decimal("0.01"), require_known_prior_costs=True)
    assert type(caught.value) is CostBudgetExceededError
    assert "UNKNOWN_PRIOR_BILLING" not in str(caught.value)
    assert ledger.path.read_bytes() == retained


@pytest.mark.parametrize(
    "error",
    (
        BudgetPriorBillingUnknownError("UNKNOWN_PRIOR_BILLING: unknown billing blocks new work"),
        CostPriorBillingUnknownError("UNKNOWN_PRIOR_BILLING: unknown billing blocks transport"),
        BudgetExhaustedError("request exceeds the remaining global input-token budget"),
        CostBudgetExceededError("cost-ledger ceiling blocks further transport"),
    ),
)
def test_expected_cost_stops_exit_cleanly(
    error: RuntimeError, capsys: pytest.CaptureFixture
) -> None:
    async def refuse() -> None:
        raise error

    with ThreadPoolExecutor(max_workers=1) as executor, pytest.raises(typer.Exit) as caught:
        executor.submit(cli_module._run_async_cli, refuse).result(timeout=30)
    assert caught.value.exit_code == ExitCode.CONFIGURATION
    output = " ".join(capsys.readouterr().out.split())
    assert f"mmaudit failed safely: {error}" in output
    assert "Traceback" not in output
    assert isinstance(error, cli_module.SecretlessErrors)


def test_unexpected_runtime_errors_are_not_hidden() -> None:
    error = RuntimeError("synthetic unexpected defect")

    async def refuse() -> None:
        raise error

    with ThreadPoolExecutor(max_workers=1) as executor, pytest.raises(RuntimeError) as caught:
        executor.submit(cli_module._run_async_cli, refuse).result(timeout=30)
    assert caught.value is error
    assert not isinstance(error, cli_module.SecretlessErrors)
